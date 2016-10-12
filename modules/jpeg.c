// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Extract various things from JPEG & JPEG-LS files.
// Extract comments from J2C files.
// Extract embedded JPEG files from arbitrary files.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_jpeg);
DE_DECLARE_MODULE(de_module_j2c);
DE_DECLARE_MODULE(de_module_jpegscan);

typedef struct localctx_struct {
	dbuf *iccprofile_file;
	dbuf *hdr_residual_file;
	int is_jpegls;
	int is_j2c;
	int image_count;
} lctx;

static void do_icc_profile_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte b1, b2;

	if(data_size<2) return; // bogus data
	b1 = de_getbyte(pos);
	b2 = de_getbyte(pos+1);
	de_dbg(c, "icc profile segment at %d datasize=%d part %d of %d\n", (int)pos, (int)(data_size-2), b1, b2);

	if(!d->iccprofile_file) {
		d->iccprofile_file = dbuf_create_output_file(c, "icc", NULL, DE_CREATEFLAG_IS_AUX);
	}
	dbuf_copy(c->infile, pos+2, data_size-2, d->iccprofile_file);

	if(b1==b2) {
		// If this is the final piece of the ICC profile, close the file.
		// That way, if for some reason there's another profile in the file, we'll put
		// it in a separate file.
		dbuf_close(d->iccprofile_file);
		d->iccprofile_file = NULL;
	}
}

// Extract JPEG-HDR residual images.
// Note: This code is based on reverse engineering, and may not be correct.
static void do_jpeghdr_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size,
	int is_ext)
{
	if(is_ext) {
		de_dbg(c, "JPEG-HDR residual image continuation, pos=%d size=%d\n",
			(int)pos, (int)data_size);
	}
	else {
		de_dbg(c, "JPEG-HDR residual image start, pos=%d size=%d\n",
			(int)pos, (int)data_size);

		// Close any previous file
		if(d->hdr_residual_file) {
			dbuf_close(d->hdr_residual_file);
			d->hdr_residual_file = NULL;
		}

		// Make sure it looks like an embedded JPEG file
		if(dbuf_memcmp(c->infile, pos, "\xff\xd8", 2)) {
			de_dbg(c, "unexpected HDR format\n");
			return;
		}

		d->hdr_residual_file = dbuf_create_output_file(c, "residual.jpg", NULL, DE_CREATEFLAG_IS_AUX);
	}

	if(!d->hdr_residual_file) return;
	dbuf_copy(c->infile, pos, data_size, d->hdr_residual_file);
}

static void do_jfif_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte ver_h, ver_l;
	de_byte units;
	const char *units_name;
	de_int64 xdens, ydens;

	if(data_size<9) return;
	ver_h = de_getbyte(pos);
	ver_l = de_getbyte(pos+1);
	de_dbg(c, "JFIF version: %d.%02d\n", (int)ver_h, (int)ver_l);
	units = de_getbyte(pos+2);
	xdens = de_getui16be(pos+3);
	ydens = de_getui16be(pos+5);
	if(units==1) units_name="dpi";
	else if(units==2) units_name="dots/cm";
	else units_name="(unspecified units)";
	de_dbg(c, "density: %dx%d %s\n", (int)xdens, (int)ydens, units_name);
}

static void do_jfxx_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte t;

	de_dbg(c, "jfxx segment at %d datasize=%d\n", (int)pos, (int)data_size);
	if(data_size<2) return;

	// The first byte indicates the type of thumbnail.
	t = de_getbyte(pos);

	if(t==16) { // thumbnail coded using JPEG
		// TODO: JPEG-formatted thumbnails are forbidden from containing JFIF segments.
		// They essentially inherit them from their parent.
		// So, maybe, when we extract a thumbnail, we should insert an artificial JFIF
		// segment into it. We currently don't do that.
		// (However, this is not at all important.)
		dbuf_create_file_from_slice(c->infile, pos+1, data_size-1, "jfxxthumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void do_adobeapp14_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte transform;
	const char *tname;

	if(data_size<7) return;
	transform = de_getbyte(pos+6);
	if(transform==0) tname="RGB or CMYK";
	else if(transform==1) tname="YCbCr";
	else if(transform==2) tname="YCCK";
	else tname="unknown";
	de_dbg(c, "color transform: %d (%s)\n", (int)transform, tname);
}

static void do_mpf_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_dbg(c, "MPF data at %d, size=%d\n", (int)pos, (int)data_size);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "tiff", "M", c->infile, pos, data_size);
	de_dbg_indent(c, -1);
}

// ITU-T Rec. T.86 says nothing about canonicalizing the APP ID, but in
// practice, some apps are sloppy about capitalization, and trailing spaces.
static void normalize_app_id(const char *app_id_orig, char *app_id_normalized,
	size_t app_id_normalized_len)
{
	de_int64 id_strlen;
	de_int64 i;

	de_strlcpy(app_id_normalized, app_id_orig, app_id_normalized_len);
	id_strlen = (de_int64)de_strlen(app_id_normalized);

	// Strip trailing spaces.
	while(id_strlen>0 && app_id_normalized[id_strlen-1]==' ') {
		app_id_normalized[id_strlen-1] = '\0';
		id_strlen--;
	}

	for(i=0; i<id_strlen; i++) {
		if(app_id_normalized[i]>='a' && app_id_normalized[i]<='z') {
			app_id_normalized[i] -= 32;
		}
	}
}

// seg_size is the data size, excluding the marker and length fields.
static void do_app_segment(deark *c, lctx *d, de_byte seg_type,
	de_int64 seg_data_pos, de_int64 seg_data_size)
{
#define MAX_APP_ID_LEN 256
	char app_id_orig[MAX_APP_ID_LEN];
	char app_id_normalized[MAX_APP_ID_LEN];
	char app_id_printable[MAX_APP_ID_LEN];
	de_int64 app_id_orig_strlen;
	de_int64 app_id_orig_size;
	de_int64 payload_pos;
	de_int64 payload_size;

	de_dbg_indent(c, 1);
	if(seg_data_size<3) goto done;

	// Read the first few bytes of the segment, so we can tell what kind of segment it is.
	if(seg_data_size+1 < (de_int64)sizeof(app_id_orig))
		dbuf_read_sz(c->infile, seg_data_pos, app_id_orig, (size_t)(seg_data_size+1));
	else
		dbuf_read_sz(c->infile, seg_data_pos, app_id_orig, sizeof(app_id_orig));

	// APP ID is the string before the first NUL byte.
	// app_id_orig_size includes the NUL byte
	app_id_orig_strlen = (de_int64)de_strlen(app_id_orig);
	app_id_orig_size = app_id_orig_strlen + 1;

	de_bytes_to_printable_sz((const de_byte*)app_id_orig, app_id_orig_strlen,
		app_id_printable, sizeof(app_id_printable), 0, DE_ENCODING_ASCII);

	de_dbg(c, "app id: \"%s\"\n", app_id_printable);

	normalize_app_id(app_id_orig, app_id_normalized, sizeof(app_id_normalized));

	// The payload data size is usually everything after the first NUL byte.
	payload_pos = seg_data_pos + app_id_orig_size;
	payload_size = seg_data_size - app_id_orig_size;
	if(payload_size<1) goto done;

	if(seg_type==0xe0 && !de_strcmp(app_id_normalized, "JFIF")) {
		do_jfif_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xe0 && !de_strcmp(app_id_normalized, "JFXX")) {
		do_jfxx_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xee && app_id_orig_strlen>=5 && !de_memcmp(app_id_normalized, "ADOBE", 5)) {
		// libjpeg implies that the "Adobe" string is *not* NUL-terminated. That the byte
		// that is usually 0 is actually the high byte of a version number.
		do_adobeapp14_segment(c, d, seg_data_pos+5, seg_data_size-5);
	}
	else if(seg_type==0xe1 && !de_strcmp(app_id_normalized, "EXIF")) {
		// Note that Exif has an additional padding byte after the APP ID NUL terminator.
		de_dbg(c, "Exif data at %d, size=%d\n", (int)(payload_pos+1), (int)(payload_size-1));
		de_dbg_indent(c, 1);
		de_fmtutil_handle_exif(c, payload_pos+1, payload_size-1);
		de_dbg_indent(c, -1);
	}
	else if(seg_type==0xe2 && !de_strcmp(app_id_normalized, "ICC_PROFILE")) {
		do_icc_profile_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xed && !de_strcmp(app_id_normalized, "PHOTOSHOP 3.0")) {
		de_dbg(c, "photoshop data at %d, size=%d\n", (int)(payload_pos), (int)(payload_size));
		de_dbg_indent(c, 1);
		de_fmtutil_handle_photoshop_rsrc(c, payload_pos, payload_size);
		de_dbg_indent(c, -1);
	}
	else if(seg_type==0xe1 && !de_strcmp(app_id_normalized, "HTTP://NS.ADOBE.COM/XAP/1.0/")) {
		de_dbg(c, "XMP data at %d, size=%d\n", (int)(payload_pos), (int)(payload_size));
		dbuf_create_file_from_slice(c->infile, payload_pos, payload_size, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(seg_type==0xeb && app_id_orig_strlen>=10 && !de_memcmp(app_id_normalized, "HDR_RI VER", 10)) {
		do_jpeghdr_segment(c, d, payload_pos, payload_size, 0);
	}
	else if(seg_type==0xeb && app_id_orig_strlen>=10 && !de_memcmp(app_id_normalized, "HDR_RI EXT", 10)) {
		do_jpeghdr_segment(c, d, payload_pos, payload_size, 1);
	}
	else if(seg_type==0xe2 && !de_strcmp(app_id_normalized, "MPF")) {
		do_mpf_segment(c, d, payload_pos, payload_size);
	}

done:
	de_dbg_indent(c, -1);
}

static void do_sof_segment(deark *c, lctx *d, de_byte seg_type,
	de_int64 pos, de_int64 data_size)
{
	de_int64 w, h;
	de_byte b;
	de_int64 ncomp;
	de_int64 i;
	const char *attr_lossy = "DCT";
	const char *attr_cmpr = "huffman";
	const char *attr_progr = "non-progr.";
	const char *attr_hier = "non-hier.";

	if(data_size<6) return;
	de_dbg_indent(c, 1);

	if(seg_type>=0xc1 && seg_type<=0xcf && (seg_type%4)!=0) {
		if((seg_type%4)==3) attr_lossy="lossless";
		if(seg_type%16>=9) attr_cmpr="arithmetic";
		if((seg_type%4)==2) attr_progr="progressive";
		if((seg_type%8)>=5) attr_hier="hierarchical";
		de_dbg(c, "image type: %s, %s, %s, %s\n",
			attr_lossy, attr_cmpr, attr_progr, attr_hier);
	}
	else if(seg_type==0xc0) {
		de_dbg(c, "image type: baseline (%s, %s, %s, %s)\n",
			attr_lossy, attr_cmpr, attr_progr, attr_hier);
	}
	else if(seg_type==0xf7) {
		de_dbg(c, "image type: JPEG-LS\n");
	}

	b = de_getbyte(pos);
	de_dbg(c, "precision: %d\n", (int)b);
	h = de_getui16be(pos+1);
	w = de_getui16be(pos+3);
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);
	ncomp = (de_int64)de_getbyte(pos+5);
	de_dbg(c, "number of components: %d\n", (int)ncomp);

	// per-component data
	if(data_size<6+3*ncomp) goto done;
	for(i=0; i<ncomp; i++) {
		de_byte comp_id;
		de_int64 sf1, sf2;
		de_byte qtid;
		comp_id = de_getbyte(pos+6+3*i+0);
		b = de_getbyte(pos+6+3*i+1);
		sf1 = (de_int64)(b>>4);
		sf2 = (de_int64)(b&0x0f);
		qtid = de_getbyte(pos+6+3*i+2);
		de_dbg(c, "cmp #%d: id=%d sampling=%dx%d quant_table=Q%d\n",
			(int)i, (int)comp_id, (int)sf1, (int)sf2, (int)qtid);
	}

done:
	de_dbg_indent(c, -1);
}
static void do_dri_segment(deark *c, lctx *d,
	de_int64 pos, de_int64 data_size)
{
	de_int64 ri;
	if(data_size!=2) return;
	de_dbg_indent(c, 1);
	ri = de_getui16be(pos);
	de_dbg(c, "restart interval: %d\n", (int)ri);
	de_dbg_indent(c, -1);
}

static void do_dht_segment(deark *c, lctx *d,
	de_int64 pos1, de_int64 data_size)
{
	de_int64 pos;
	de_byte b;
	de_byte table_class;
	de_byte table_id;
	de_int64 num_huff_codes;
	de_int64 k;

	de_dbg_indent(c, 1);

	pos = pos1;

	while(1) {
		if(pos >= pos1+data_size) goto done;

		b = de_getbyte(pos);
		table_class = b>>4;
		table_id = b&0x0f;
		de_dbg(c, "table: %s%d, at %d\n", table_class==0?"DC":"AC",
			(int)table_id, (int)pos);

		num_huff_codes = 0;
		for(k=0; k<16; k++) {
			num_huff_codes += (de_int64)de_getbyte(pos+1+k);
		}

		pos += 1 + 16 + num_huff_codes;
	}

done:
	de_dbg_indent(c, -1);
}

// DAC = Define arithmetic coding conditioning
static void do_dac_segment(deark *c, lctx *d,
	de_int64 pos1, de_int64 data_size)
{
	de_int64 ntables;
	de_int64 i;
	de_byte b;
	de_byte cs;
	de_byte table_class;
	de_byte table_id;

	de_dbg_indent(c, 1);
	ntables = data_size/2;
	for(i=0; i<ntables; i++) {
		b = de_getbyte(pos1+i*2);
		table_class = b>>4;
		table_id = b&0x0f;
		de_dbg(c, "table: %s%u\n", table_class==0?"DC":"AC",
			(unsigned int)table_id);
		cs = de_getbyte(pos1+i*2+1);
		de_dbg_indent(c, 1);
		de_dbg(c, "conditioning value: %d\n", (int)cs);
		de_dbg_indent(c, -1);
	}
	de_dbg_indent(c, -1);
}

static void do_dqt_segment(deark *c, lctx *d,
	de_int64 pos1, de_int64 data_size)
{
	de_int64 pos;
	de_byte b;
	de_byte precision_code;
	de_byte table_id;
	de_int64 qsize;
	const char *s;

	de_dbg_indent(c, 1);

	pos = pos1;

	while(1) {
		if(pos >= pos1+data_size) goto done;

		b = de_getbyte(pos);
		precision_code = b>>4;
		table_id = b&0x0f;
		if(precision_code==0) {
			s="8-bit";
			qsize = 64;
		}
		else if(precision_code==1) {
			s="16-bit";
			qsize = 128;
		}
		else {
			s="?";
			qsize = 0;
		}
		de_dbg(c, "table: Q%d, at %d\n", table_id, (int)pos);

		de_dbg_indent(c, 1);
		de_dbg(c, "precision: %d (%s)\n", (int)precision_code, s);
		de_dbg_indent(c, -1);

		if(qsize==0) goto done;

		pos += 1 + qsize;
	}

done:
	de_dbg_indent(c, -1);
}

#define DE_MAX_DBG_CHARS 500

static void handle_comment(deark *c, lctx *d, de_int64 pos, de_int64 comment_size,
   int encoding)
{
	de_ucstring *s = NULL;
	int write_to_file;

	// If c->extract_level>=2, write the comment to a file;
	// otherwise if we have debugging output, write (at least part of) it
	// to the debug output;
	// otherwise do nothing.

	if(c->extract_level<2 && c->debug_level<1) return;
	if(comment_size<1) return;

	write_to_file = (c->extract_level>=2);

	if(write_to_file && encoding==DE_ENCODING_UNKNOWN) {
		// If we don't know the encoding, dump the raw bytes to a file.
		dbuf_create_file_from_slice(c->infile, pos, comment_size, "comment.txt",
			NULL, DE_CREATEFLAG_IS_AUX);
		goto done;
	}

	if(encoding==DE_ENCODING_UNKNOWN) {
		// In this case, we're printing the comment in the debug info.
		// If we don't know the encoding, pretend it's ASCII.
		encoding=DE_ENCODING_ASCII;
	}

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, comment_size, s, 0, encoding);

	if(write_to_file) {
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}
	else {
		de_dbg(c, "comment: \"%s\"\n", ucstring_get_printable_sz_n(s, DE_MAX_DBG_CHARS));
	}

done:
	ucstring_destroy(s);
}

static void do_com_segment(deark *c, lctx *d,
	de_int64 pos, de_int64 data_size)
{
	de_dbg_indent(c, 1);
	// Note that a JPEG COM-segment comment is an arbitrary sequence of bytes, so
	// there's no way to know what text encoding it uses, or even whether it is text.
	handle_comment(c, d, pos, data_size, DE_ENCODING_UNKNOWN);
	de_dbg_indent(c, -1);
}

static void do_cme_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_int64 reg_val;
	de_byte *buf = NULL;
	de_int64 comment_pos;
	de_int64 comment_size;
	const char *name;

	de_dbg_indent(c, 1);
	if(data_size<2) goto done;

	reg_val = de_getui16be(pos);
	switch(reg_val) {
	case 0: name="binary"; break;
	case 1: name="text"; break;
	default: name="?";
	}
	de_dbg(c, "comment/extension type: %d (%s)\n", (int)reg_val, name);

	comment_pos = pos+2;
	comment_size = data_size-2;

	if(reg_val==1) {
		handle_comment(c, d, comment_pos, comment_size, DE_ENCODING_LATIN1);
	}

done:
	de_free(c, buf);
	de_dbg_indent(c, -1);
}

static void do_sos_segment(deark *c, lctx *d,
	de_int64 pos, de_int64 data_size)
{
	de_int64 ncomp;
	de_int64 i;
	de_byte cs;
	de_byte b;
	de_byte ss, se, ax;
	de_byte actable, dctable;

	de_dbg_indent(c, 1);
	if(data_size<1) goto done;

	ncomp = (de_int64)de_getbyte(pos);
	de_dbg(c, "number of components in scan: %d\n", (int)ncomp);
	if(data_size < 4 + 2*ncomp) goto done;

	for(i=0; i<ncomp; i++) {
		cs = de_getbyte(pos+1+i*2);
		de_dbg(c, "component #%d id: %d\n", (int)i, (int)cs);
		de_dbg_indent(c, 1);
		b = de_getbyte(pos+1+i*2+1);
		dctable = b>>4;
		actable = b&0x0f;
		de_dbg(c, "tables to use: DC%d, AC%d\n", (int)dctable, (int)actable);
		de_dbg_indent(c, -1);
	}

	ss = de_getbyte(pos+1+ncomp*2);
	se = de_getbyte(pos+1+ncomp*2+1);
	ax = de_getbyte(pos+1+ncomp*2+2);
	de_dbg(c, "spectral selection start/end: %d, %d\n", (int)ss, (int)se);
	de_dbg(c, "successive approx. bit pos high/low: %u, %u\n",
		(unsigned int)(ax>>4), (unsigned int)(ax&0x0f));

done:
	de_dbg_indent(c, -1);
}

struct marker_info {
	char name[12];
#define FLAG_NO_DATA 0x01
#define FLAG_IS_SOF  0x02
#define FLAG_IS_APP  0x04
	unsigned int flags;
};

// Caller allocates mi
static int get_marker_info(deark *c, lctx *d, de_byte seg_type,
	struct marker_info *mi)
{
	const char *name = NULL;

	de_memset(mi, 0, sizeof(struct marker_info));

	// TODO: Figure out exactly which J2C markers have parameters.
	switch(seg_type) {
	case 0x01: name = "TEM"; mi->flags |= FLAG_NO_DATA; break;
	case 0x4f:
		if(d->is_j2c) {
			name = "SOC"; mi->flags |= FLAG_NO_DATA; break;
		}
		break;
	case 0x51: name = "SIZ"; break;
	case 0x52: name = "COD"; break;
	case 0x53: name = "COC"; break;
	case 0x55: name = "TLM"; break;
	case 0x57: name = "PLM"; break;
	case 0x58: name = "PLT"; break;
	case 0x5c: name = "QCD"; break;
	case 0x5d: name = "QCC"; break;
	case 0x5e: name = "RGN"; break;
	case 0x5f: name = "POD"; break;
	case 0x60: name = "PPM"; break;
	case 0x61: name = "PPT"; break;
	case 0x64: name = "CME"; break;
	case 0x90: name = "SOT"; break;
	case 0x91: name = "SOP"; break;
	case 0x92:
		if(d->is_j2c) {
			name = "EPH";
			mi->flags |= FLAG_NO_DATA;
		}
		break;
	case 0x93:
		if(d->is_j2c) {
			name = "SOD";
			mi->flags |= FLAG_NO_DATA;
		}
		break;
	case 0xc4: name = "DHT"; break;
	case 0xc8: name = "JPG"; mi->flags |= FLAG_IS_SOF; break;
	case 0xcc: name = "DAC"; break;
	case 0xd8: name = "SOI"; mi->flags |= FLAG_NO_DATA; break;
	case 0xd9:
		if(d->is_j2c) name = "EOC";
		else name = "EOI";
		mi->flags |= FLAG_NO_DATA;
		break;
	case 0xda: name = "SOS"; break;
	case 0xdb: name = "DQT"; break;
	case 0xdc: name = "DNL"; break;
	case 0xdd: name = "DRI"; break;
	case 0xde: name = "DHP"; break;
	case 0xdf: name = "EXP"; break;
	case 0xf7:
		d->is_jpegls = 1;
		mi->flags |= FLAG_IS_SOF;
		name = "SOF55";
		break;
	case 0xf8:
		if(d->is_jpegls) {
			name = "LSE";
		}
		break;
	case 0xfe: name = "COM"; break;
	}

	if(d->is_j2c && (seg_type>=0x30 && seg_type<=0x3f)) {
		mi->flags |= FLAG_NO_DATA;
	}

	if(name) {
		de_strlcpy(mi->name, name, sizeof(mi->name));
		goto done;
	}

	// Handle some pattern-based markers.
	if(seg_type>=0xe0 && seg_type<=0xef) {
		de_snprintf(mi->name, sizeof(mi->name), "APP%d", (int)(seg_type-0xe0));
		mi->flags |= FLAG_IS_APP;
		goto done;
	}

	if(seg_type>=0xc0 && seg_type<=0xcf) {
		de_snprintf(mi->name, sizeof(mi->name), "SOF%d", (int)(seg_type-0xc0));
		mi->flags |= FLAG_IS_SOF;
		goto done;
	}

	if(seg_type>=0xd0 && seg_type<=0xd7) {
		de_snprintf(mi->name, sizeof(mi->name), "RST%d", (int)(seg_type-0xd0));
		mi->flags |= FLAG_NO_DATA;
		goto done;
	}

	if(seg_type>=0xf0 && seg_type<=0xfd) {
		de_snprintf(mi->name, sizeof(mi->name), "JPG%d", (int)(seg_type-0xf0));
		goto done;
	}

	de_strlcpy(mi->name, "???", sizeof(mi->name));
	return 0;

done:
	return 1;
}

static void do_segment(deark *c, lctx *d, de_byte seg_type,
	const struct marker_info *mi,
	de_int64 payload_pos, de_int64 payload_size)
{
	de_dbg(c, "segment %s (0x%02x) at %d, data_len=%d\n",
		mi->name, (unsigned int)seg_type, (int)(payload_pos-4), (int)payload_size);

	if(mi->flags & FLAG_IS_APP) {
		do_app_segment(c, d, seg_type, payload_pos, payload_size);
	}
	else if(mi->flags & FLAG_IS_SOF) {
		do_sof_segment(c, d, seg_type, payload_pos, payload_size);
	}
	else if(seg_type==0xda) {
		do_sos_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xdd) {
		do_dri_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xc4) {
		do_dht_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xcc) {
		do_dac_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xdb) {
		do_dqt_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xfe) {
		do_com_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0x64 && d->is_j2c) {
		do_cme_segment(c, d, payload_pos, payload_size);
	}
}

// TODO: This is very similar to detect_jpeg_len().
// Maybe they should be consolidated.
static int do_read_scan_data(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_byte b0, b1;
	struct marker_info mi;

	*bytes_consumed = c->infile->len - pos1; // default
	de_dbg(c, "scan data at %d\n", (int)pos1);

	de_dbg_indent(c, 1);

	while(1) {
		if(pos >= c->infile->len) goto done;
		b0 = de_getbyte(pos++);
		if(b0==0xff) {
			b1 = de_getbyte(pos++);
			if(b1==0x00) {
				; // an escaped 0xff
			}
			else if(d->is_jpegls && b1<0x80) {
				// In JPEG-LS, 0xff bytes are not escaped if they're followed by a
				// a byte less than 0x80.
				;
			}
			else if(d->is_j2c && b1<0x90) {
				// In J2c, 0xff bytes are not escaped if they're followed by a
				// a byte less than 0x90.
				;
			}
			else if(b1>=0xd0 && b1<=0xd7) { // an RSTn marker
				if(c->debug_level>=2) {
					get_marker_info(c, d, b1, &mi);
					de_dbg2(c, "marker %s (0x%02x) at %d\n", mi.name, (unsigned int)b1, (int)(pos-2));
				}
			}
			else if(b1==0xff) { // a "fill byte" (are they allowed here?)
				pos--;
			}
			else {
				// A marker that is not part of the scan.
				// Subtract the bytes consumed by it, and stop.
				pos -= 2;
				*bytes_consumed = pos - pos1;
				de_dbg(c, "end of scan data found at %d (len=%d)\n", (int)pos, (int)*bytes_consumed);
				break;
			}
		}
	}

done:
	de_dbg_indent(c, -1);
	return 1;
}

static void do_jpeg_internal(deark *c, lctx *d)
{
	de_byte b;
	de_int64 pos;
	de_int64 seg_size;
	de_byte seg_type;
	int found_marker;
	struct marker_info mi;
	de_int64 scan_byte_count;

	pos = 0;
	found_marker = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte(pos);
		pos++;
		if(b==0xff) {
			found_marker = 1;
			continue;
		}

		if(!found_marker) {
			// Not an 0xff byte, and not preceded by an 0xff byte. Just ignore it.
			continue;
		}

		found_marker = 0; // Reset this flag.

		if(b==0x00) {
			continue; // Escaped 0xff
		}

		seg_type = b;
		get_marker_info(c, d, seg_type, &mi);

		if(mi.flags & FLAG_NO_DATA) {
			de_dbg(c, "marker %s (0x%02x) at %d\n", mi.name, (unsigned int)seg_type,
				(int)(pos-2));

			if(seg_type==0xd8 && !d->is_j2c) {
				// Count the number of SOI segments
				d->image_count++;
			}

			if(d->is_j2c && seg_type==0x93) {
				// SOD (JPEG 2000 marker sort of like SOS)
				if(!do_read_scan_data(c, d, pos, &scan_byte_count)) {
					break;
				}
				pos += scan_byte_count;
			}

			continue;
		}

		// If we get here, we're reading a segment that has a size field.
		seg_size = de_getui16be(pos);
		if(pos<2) break; // bogus size

		do_segment(c, d, seg_type, &mi, pos+2, seg_size-2);

		pos += seg_size;

		if(seg_type==0xda && !d->is_j2c) {
			// If we read an SOS segment, now read the untagged image data that
			// should follow it.
			if(!do_read_scan_data(c, d, pos, &scan_byte_count)) {
				break;
			}
			pos += scan_byte_count;
		}
	}

	dbuf_close(d->iccprofile_file);
	dbuf_close(d->hdr_residual_file);

	if(d->image_count>1) {
		// For Multi-Picture Format (.mpo) and similar.
		de_msg(c, "Note: This file seems to contain %d JPEG files. "
			"Use \"-m jpegscan\" to extract them.\n", d->image_count);
	}
}

static void de_run_jpeg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	do_jpeg_internal(c, d);
	de_free(c, d);
}

typedef struct scanctx_struct {
	de_int64 len;
	int is_jpegls;
} scanctx;

static int detect_jpeg_len(deark *c, scanctx *d, de_int64 pos1, de_int64 len)
{
	de_byte b0, b1;
	de_int64 pos;
	de_int64 seg_size;
	int in_scan = 0;
	int found_sof = 0;
	int found_scan = 0;

	d->len = 0;
	d->is_jpegls = 0;
	pos = pos1;

	while(1) {
		if(pos>=pos1+len)
			break;
		b0 = de_getbyte(pos);

		if(b0!=0xff) {
			pos++;
			continue;
		}

		// Peek at the next byte (after this 0xff byte).
		b1 = de_getbyte(pos+1);

		if(b1==0xff) {
			// A "fill byte", not a marker.
			pos++;
			continue;
		}
		else if(b1==0x00 || (d->is_jpegls && b1<0x80 && in_scan)) {
			// An escape sequence, not a marker.
			pos+=2;
			continue;
		}
		else if(b1==0xd9) { // EOI. That's what we're looking for.
			if(!found_sof || !found_scan) return 0;
			pos+=2;
			d->len = pos-pos1;
			return 1;
		}
		else if(b1==0xf7) {
			de_dbg(c, "Looks like a JPEG-LS file.\n");
			found_sof = 1;
			d->is_jpegls = 1;
		}
		else if(b1>=0xc0 && b1<=0xcf && b1!=0xc4 && b1!=0xc8 && b1!=0xcc) {
			found_sof = 1;
		}

		if(b1==0xda) { // SOS - Start of scan
			if(!found_sof) return 0;
			found_scan = 1;
			in_scan = 1;
		}
		else if(b1>=0xd0 && b1<=0xd7) {
			// RSTn markers don't change the in_scan state.
			;
		}
		else {
			in_scan = 0;
		}

		if((b1>=0xd0 && b1<=0xda) || b1==0x01) {
			// Markers that have no content.
			pos+=2;
			continue;
		}

		// Everything else should be a marker segment, with a length field.
		seg_size = de_getui16be(pos+2);
		if(seg_size<2) break; // bogus size

		pos += seg_size+2;
	}

	return 0;
}

static void de_run_jpegscan(deark *c, de_module_params *mparams)
{
	de_int64 pos = 0;
	de_int64 foundpos = 0;
	scanctx *d = NULL;
	int ret;

	d = de_malloc(c, sizeof(*d));

	while(1) {
		if(pos >= c->infile->len) break;

		ret = dbuf_search(c->infile, (const de_byte*)"\xff\xd8\xff", 3,
			pos, c->infile->len-pos, &foundpos);
		if(!ret) break; // No more JPEGs in file.

		de_dbg(c, "Found possible JPEG file at %d\n", (int)foundpos);

		pos = foundpos;

		if(detect_jpeg_len(c, d, pos, c->infile->len-pos)) {
			de_dbg(c, "length=%d\n", (int)d->len);
			dbuf_create_file_from_slice(c->infile, pos, d->len,
				d->is_jpegls ? "jls" : "jpg", NULL, 0);
			pos += d->len;
		}
		else {
			de_dbg(c, "Doesn't seem to be a valid JPEG.\n");
			pos++;
		}
	}

	de_free(c, d);
}

static int de_identify_jpeg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xff\xd8\xff", 3)) {
		return 100;
	}
	return 0;
}

void de_module_jpeg(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpeg";
	mi->desc = "JPEG image (resources only)";
	mi->run_fn = de_run_jpeg;
	mi->identify_fn = de_identify_jpeg;
}

void de_module_jpegscan(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpegscan";
	mi->desc = "Extract embedded JPEG images from arbitrary files";
	mi->run_fn = de_run_jpegscan;
	mi->identify_fn = de_identify_none;
}

//////////// JPEG 2000 codestream ////////////
//
// This is in jpeg.c, not jpeg2000.c, because (for our purposes) the format is
// very much like JPEG.

static void de_run_j2c(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->is_j2c = 1;
	do_jpeg_internal(c, d);
	de_free(c, d);
}

static int de_identify_j2c(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xff\x4f\xff\x51", 4))
		return 100;
	return 0;
}

void de_module_j2c(deark *c, struct deark_module_info *mi)
{
	mi->id = "j2c";
	mi->desc = "JPEG 2000 codestream";
	mi->run_fn = de_run_j2c;
	mi->identify_fn = de_identify_j2c;
}
