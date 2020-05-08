// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Extract various things from JPEG & JPEG-LS files.
// Extract embedded JPEG files from arbitrary files.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_jpeg);
DE_DECLARE_MODULE(de_module_jpegscan);

struct fpxr_entity_struct {
	size_t index;
	struct de_stringreaderdata *name_srd;
	dbuf *stream;
	i64 stream_size;
	int is_storage;
	int done_flag;
};

struct fpxr_data_struct {
	size_t num_entities;
	struct fpxr_entity_struct *entities;
};

typedef struct localctx_struct {
	u8 is_jpegls;

	u8 has_jfif_seg, has_jfif_thumb, has_jfxx_seg;
	u8 has_exif_seg, has_exif_gps, has_spiff_seg, has_mpf_seg, has_afcp;
	u8 exif_before_jfif;
	u8 has_psd, has_iptc, has_xmp, has_xmp_ext, has_iccprofile, has_flashpix;
	u8 is_baseline, is_progressive, is_lossless, is_arithmetic, is_hierarchical;
	u8 is_jpeghdr, is_jpegxt, is_mpo, is_jps;
	u8 has_restart_markers;
	u8 precision;
	u8 has_adobeapp14;
	u8 color_transform; // valid if(has_adobeapp14)
	u8 has_revcolorxform;
	u8 exif_cosited;
	int scan_count;

	u8 found_soi;
	u8 found_sof;
	i64 ncomp;

	u8 jfif_ver_h, jfif_ver_l; // valid if(has_jfif_seg)
	u32 exif_orientation; // valid if != 0, and(has_exif_seg)
	u32 exif_version_as_uint32; // valid if != 0, and(has_exif_seg)
	dbuf *iccprofile_file;
	dbuf *hdr_residual_file;

	int extxmp_found;
	int extxmp_warned_flag; // Have we warned about multiple extxmp digests?
	int extxmp_error_flag;
	dbuf *extxmp_membuf;
	u8 extxmp_digest[32];
	i64 extxmp_total_len;

	int is_subsampled;
	de_ucstring *sampling_code;

	struct fpxr_data_struct *fpxr_data;
} lctx;

struct marker_info;

typedef void (*handler_fn_type)(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos, i64 data_size);

#define FLAG_JPEG_COMPAT   0x0001
#define FLAG_JPEGLS_COMPAT 0x0002
#define FLAG_NO_DATA       0x0100
#define FLAG_IS_SOF        0x0200

struct marker_info {
	u8 seg_type;
	unsigned int flags;
	char shortname[12];
	char longname[80];
	handler_fn_type hfn;
};

// Static info about markers/segments.
struct marker_info1 {
	u8 seg_type;
	unsigned int flags;
	const char *shortname;
	const char *longname;
	handler_fn_type hfn;
};

static void do_icc_profile_segment(deark *c, lctx *d, i64 pos, i64 data_size)
{
	u8 b1, b2;

	if(data_size<2) return; // bogus data
	b1 = de_getbyte(pos);
	b2 = de_getbyte(pos+1);
	de_dbg(c, "icc profile segment at %d datasize=%d part %d of %d", (int)pos, (int)(data_size-2), b1, b2);

	if(!d->iccprofile_file) {
		d->has_iccprofile = 1;
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
static void do_jpeghdr_segment(deark *c, lctx *d, i64 pos1,
	i64 data_size1, int is_ext)
{
	int ret;
	i64 pos = 0;
	i64 data_size;

	// Payload should begin after the first NUL byte. Search for it.
	ret = dbuf_search_byte(c->infile, 0x00, pos1, data_size1, &pos);
	if(!ret) {
		de_warn(c, "Bad or unsupported JPEG-HDR data");
		return;
	}
	pos++;
	data_size = pos1+data_size1 - pos;

	if(is_ext) {
		de_dbg(c, "JPEG-HDR residual image continuation, pos=%d size=%d",
			(int)pos, (int)data_size);
	}
	else {
		de_dbg(c, "JPEG-HDR residual image start, pos=%d size=%d",
			(int)pos, (int)data_size);

		// Close any previous file
		if(d->hdr_residual_file) {
			dbuf_close(d->hdr_residual_file);
			d->hdr_residual_file = NULL;
		}

		// Make sure it looks like an embedded JPEG file
		if(dbuf_memcmp(c->infile, pos, "\xff\xd8", 2)) {
			de_warn(c, "Bad or unsupported JPEG-HDR format");
			return;
		}

		d->hdr_residual_file = dbuf_create_output_file(c, "residual.jpg", NULL, DE_CREATEFLAG_IS_AUX);
	}

	if(!d->hdr_residual_file) return;
	dbuf_copy(c->infile, pos, data_size, d->hdr_residual_file);
}

static void do_jpegxt_segment(deark *c, lctx *d, i64 pos,
	i64 data_size)
{
	i64 n;
	if(data_size<14) return;
	n = de_getu16be(pos);
	de_dbg(c, "enumerator: %u", (unsigned int)n);
	n = de_getu32be(pos+2);
	de_dbg(c, "seq number: %u", (unsigned int)n);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "bmff", "T", c->infile, pos+6, data_size-6);
	de_dbg_indent(c, -1);
}

// Decode an uncompressed JFIF thumbnail.
// This code has not been properly tested, because I can't find any files in
// the wild that have these kinds of thumbnails.
static void extract_unc_jfif_thumbnail(deark *c, lctx *d,
	i64 pos1, i64 len, i64 w, i64 h, int has_pal,
	const char *token)
{
	i64 i, j;
	i64 pos = pos1;
	de_bitmap *img = NULL;
	u32 clr;
	i64 rowspan;

	img = de_bitmap_create(c, w, h, 3);

	if(has_pal) {
		u32 pal[256];
		de_read_palette_rgb(c->infile, pos, 256, 3, pal, 256, 0);
		pos += 768;
		de_convert_image_paletted(c->infile, pos, 8, w, pal, img, 0);
	}
	else {
		rowspan = 3*w;
		for(j=0; j<h; j++) {
			for(i=0; i<w; i++) {
				clr = dbuf_getRGB(c->infile, pos + j*rowspan + i*3, 0);
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
		}
	}

	de_bitmap_write_to_file(img, token, DE_CREATEFLAG_IS_AUX);

	de_bitmap_destroy(img);
}

static void do_jfif_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	u8 units;
	const char *units_name;
	i64 xdens, ydens;
	i64 tn_w, tn_h;

	d->has_jfif_seg = 1;
	if(data_size<9) return;
	d->jfif_ver_h = de_getbyte(pos);
	d->jfif_ver_l = de_getbyte(pos+1);
	de_dbg(c, "JFIF version: %d.%02d", (int)d->jfif_ver_h, (int)d->jfif_ver_l);
	units = de_getbyte(pos+2);
	xdens = de_getu16be(pos+3);
	ydens = de_getu16be(pos+5);
	if(units==1) units_name="dpi";
	else if(units==2) units_name="dots/cm";
	else units_name="(unspecified)";
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d, units=%s", (int)xdens, (int)ydens, units_name);

	tn_w = (i64)de_getbyte(pos+7);
	tn_h = (i64)de_getbyte(pos+8);
	de_dbg(c, "thumbnail dimensions: %d"DE_CHAR_TIMES"%d", (int)tn_w, (int)tn_h);
	if(tn_w>0 && tn_h>0 && data_size>9) {
		d->has_jfif_thumb = 1;
		if(tn_w*tn_h*3 != data_size-9) {
			de_warn(c, "Expected %d bytes of JFIF thumbnail image data at %d, found %d",
				(int)(tn_w*tn_h*3), (int)(pos+9), (int)(data_size-9));
		}
		extract_unc_jfif_thumbnail(c, d, pos+9, data_size-9, tn_w, tn_h,
			0, "jfifthumb");
	}
}

static void do_jfxx_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	u8 t;

	d->has_jfxx_seg = 1;
	de_dbg(c, "JFXX segment at %d datasize=%d", (int)pos, (int)data_size);
	if(data_size<1) return;

	t = de_getbyte(pos);
	de_dbg(c, "thumbnail type: 0x%02x", (unsigned int)t);

	if(t==0x10) { // thumbnail coded using JPEG
		// TODO: JPEG-formatted thumbnails are forbidden from containing JFIF segments.
		// They essentially inherit them from their parent.
		// So, maybe, when we extract a thumbnail, we should insert an artificial JFIF
		// segment into it. We currently don't do that.
		// (However, this is not at all important.)
		dbuf_create_file_from_slice(c->infile, pos+1, data_size-1, "jfxxthumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(t==0x11 || t==0x13) {
		i64 tn_w, tn_h;

		if(data_size<3) return;
		tn_w = (i64)de_getbyte(pos+1);
		tn_h = (i64)de_getbyte(pos+2);
		de_dbg(c, "JFXX thumbnail dimensions: %d"DE_CHAR_TIMES"%d", (int)tn_w, (int)tn_h);
		extract_unc_jfif_thumbnail(c, d, pos+3, data_size-3, tn_w, tn_h,
			(t==0x11)?1:0, "jfxxthumb");
	}
}

static void do_adobeapp14_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	const char *tname;

	if(data_size<7) return;
	d->has_adobeapp14 = 1;
	d->color_transform = de_getbyte(pos+6);
	if(d->color_transform==0) tname="RGB or CMYK";
	else if(d->color_transform==1) tname="YCbCr";
	else if(d->color_transform==2) tname="YCCK";
	else tname="unknown";
	de_dbg(c, "color transform: %d (%s)", (int)d->color_transform, tname);
}

static void do_exif_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	u32 exifflags = 0;
	u32 exiforientation = 0;
	u32 exifversion = 0;

	if(data_size<8) return;
	// Note that Exif has an additional padding byte after the APP ID NUL terminator.
	de_dbg(c, "Exif data at %d, size=%d", (int)pos, (int)data_size);
	d->has_exif_seg = 1;
	if(!d->has_jfif_seg) {
		d->exif_before_jfif = 1;
	}
	de_dbg_indent(c, 1);
	de_fmtutil_handle_exif2(c, pos, data_size,
		&exifflags, &exiforientation, &exifversion);
	if(exifflags&0x08)
		d->has_exif_gps = 1;
	if(exifflags&0x10)
		d->exif_cosited = 1;
	if(exifflags&0x20)
		d->exif_orientation = exiforientation;
	if(exifflags&0x40)
		d->exif_version_as_uint32 = exifversion;
	de_dbg_indent(c, -1);
}

static void do_photoshop_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	struct de_module_out_params oparams;

	de_zeromem(&oparams, sizeof(struct de_module_out_params));
	// TODO: Can Photoshop resources span multiple JPEG segments? I have
	// a file in which that seems to be the case.
	de_dbg(c, "photoshop data at %d, size=%d", (int)pos, (int)data_size);
	d->has_psd = 1;
	de_dbg_indent(c, 1);
	de_fmtutil_handle_photoshop_rsrc2(c, c->infile, pos, data_size, 0x0, &oparams);
	if(oparams.flags&0x02)
		d->has_iptc = 1;
	de_dbg_indent(c, -1);
}

static void do_mpf_segment(deark *c, lctx *d,
	i64 pos, i64 data_size)
{
	de_module_params *mparams = NULL;

	d->has_mpf_seg = 1;
	de_dbg(c, "MPF data at %d, size=%d", (int)pos, (int)data_size);
	de_dbg_indent(c, 1);

	mparams = de_malloc(c, sizeof(de_module_params));

	mparams->in_params.codes = "M";
	mparams->in_params.flags |= 0x01;
	mparams->in_params.offset_in_parent = pos;
	mparams->in_params.parent_dbuf = c->infile;

	de_run_module_by_id_on_slice(c, "tiff", mparams, c->infile, pos, data_size);

	if(mparams->out_params.flags & 0x80) {
		if(mparams->out_params.uint3 > 1) {
			// We want to set the is_mpo flag if there is an MPEntry tag which
			// says there is more than one non-thumbnail image.
			// This is so we can declare the format to be "JPEG/MPO".
			d->is_mpo = 1;
		}
	}

	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void do_jps_segment(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 blk_len;
	u32 st_descr;
	de_ucstring *flags_str = NULL;
	de_ucstring *comment = NULL;
	unsigned int mtype;

	// Descriptor block
	if(len<8) goto done;
	blk_len = de_getu16be_p(&pos);
	if(blk_len<4) goto done;
	st_descr = (u32)de_getu32be(pos);

	flags_str = ucstring_create(c);
	mtype = (unsigned int)(st_descr&0x000000ff);
	switch(mtype) {
	case 0: ucstring_append_flags_item(flags_str, "MONOSCOPIC_IMAGE"); break;
	case 1: ucstring_append_flags_item(flags_str, "STEREOSCOPIC_IMAGE"); break;
	}
	if(mtype==0) {
		switch((st_descr&0x0000ff00)>>8) {
		case 0: ucstring_append_flags_item(flags_str, "EYE_BOTH"); break;
		case 1: ucstring_append_flags_item(flags_str, "EYE_LEFT"); break;
		case 2: ucstring_append_flags_item(flags_str, "EYE_RIGHT"); break;
		}
	}
	else if(mtype==1) {
		switch((st_descr&0x0000ff00)>>8) {
		case 1: ucstring_append_flags_item(flags_str, "LAYOUT_INTERLEAVED"); break;
		case 2: ucstring_append_flags_item(flags_str, "LAYOUT_SIDEBYSIDE"); break;
		case 3: ucstring_append_flags_item(flags_str, "LAYOUT_OVERUNDER"); break;
		case 4: ucstring_append_flags_item(flags_str, "LAYOUT_ANAGLYPH"); break;
		}
	}
	ucstring_append_flags_item(flags_str, (st_descr&0x00010000)?"half-height":"full-height");
	ucstring_append_flags_item(flags_str, (st_descr&0x00020000)?"half-width":"full-width");
	// TODO: FIELD ORDER BIT
	// TODO: SEPARATION

	de_dbg(c, "stereoscopic descriptor: 0x%08x (%s)", (unsigned int)st_descr,
		ucstring_getpsz(flags_str));
	pos += blk_len;

	// Comment block
	if(pos1+len-pos<2) goto done;
	blk_len = de_getu16be_p(&pos);
	if(pos+blk_len > pos1+len) goto done;
	comment = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, blk_len, DE_DBG_MAX_STRLEN, comment,
				0, DE_ENCODING_ASCII);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz(comment));

done:
	ucstring_destroy(flags_str);
	ucstring_destroy(comment);
}

static void do_arot_segment(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 nvals;

	if(len<8) goto done;
	nvals = de_getu32be(pos);
	de_dbg(c, "number of values: %u", (unsigned int)nvals);

done:
	;
}

static void do_xmp_extension_segment(deark *c, lctx *d,
	i64 pos1, i64 data_size)
{
	i64 thisseg_full_extxmp_len;
	i64 segment_offset;
	u8 thisseg_digest_raw[32];
	de_ucstring *digest_str = NULL;
	i64 pos = pos1;
	i64 dlen;
	int is_first_segment = 0;

	de_dbg(c, "extended XMP segment, dpos=%d, dlen=%d", (int)pos1, (int)(data_size));
	de_dbg_indent(c, 1);
	if(d->extxmp_error_flag) goto done;

	de_read(thisseg_digest_raw, pos, 32);
	pos += 32;
	digest_str = ucstring_create(c);
	ucstring_append_bytes(digest_str, thisseg_digest_raw, 32, 0, DE_ENCODING_ASCII);
	de_dbg(c, "digest: \"%s\"", ucstring_getpsz(digest_str));

	if(d->extxmp_found && de_memcmp(thisseg_digest_raw, d->extxmp_digest, 32)) {
		// We only care about the extended XMP segments whose digest matches that
		// indicated in the main XMP segment. Unfortunately, we don't know what that
		// is, because we don't parse XMP. We'll just hope that the first extended
		// XMP segment has the correct digest.
		if(!d->extxmp_warned_flag) {
			de_warn(c, "Multiple extended XMP blocks found. All but the first will be ignored.");
			d->extxmp_warned_flag = 1;
		}
		goto done;
	}

	if(!d->extxmp_found) {
		is_first_segment = 1;
		d->extxmp_found = 1;
		de_memcpy(d->extxmp_digest, thisseg_digest_raw, 32);
	}

	thisseg_full_extxmp_len = de_getu32be_p(&pos);
	if(is_first_segment) {
		d->extxmp_total_len = thisseg_full_extxmp_len;
	}
	de_dbg(c, "full ext. XMP length: %d", (int)thisseg_full_extxmp_len);
	if(thisseg_full_extxmp_len != d->extxmp_total_len) {
		de_warn(c, "Inconsistent extended XMP block lengths");
		d->extxmp_error_flag = 1;
		goto done;
	}

	if(d->extxmp_total_len > 10000000) {
		de_warn(c, "Extended XMP block too large");
		d->extxmp_error_flag = 1;
		goto done;
	}

	segment_offset = de_getu32be_p(&pos);
	de_dbg(c, "offset of this segment: %d", (int)segment_offset);

	dlen = data_size - (pos-pos1);
	de_dbg(c, "[%d bytes of ext. XMP data at %d]", (int)dlen, (int)pos);

	if(segment_offset + dlen > d->extxmp_total_len) {
		de_warn(c, "Extended XMP segment too long");
		d->extxmp_error_flag = 1;
		goto done;
	}

	if(!d->extxmp_membuf) {
		d->extxmp_membuf = dbuf_create_membuf(c, d->extxmp_total_len, 0x1);
	}
	dbuf_copy_at(c->infile, pos, dlen, d->extxmp_membuf, segment_offset);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(digest_str);
}

static void destroy_fpxr_data(deark *c, lctx *d)
{
	size_t k;
	if(!d->fpxr_data) return;

	for(k=0; k<d->fpxr_data->num_entities; k++) {
		if(d->fpxr_data->entities[k].name_srd) {
			de_destroy_stringreaderdata(c, d->fpxr_data->entities[k].name_srd);
			d->fpxr_data->entities[k].name_srd = NULL;
		}

		dbuf_close(d->fpxr_data->entities[k].stream);
		d->fpxr_data->entities[k].stream = NULL;
	}

	de_free(c, d->fpxr_data->entities);
	de_free(c, d->fpxr_data);
	d->fpxr_data = NULL;
}

static void do_fpxr_olepropset_stream(deark *c, lctx *d, struct fpxr_entity_struct *fe)
{
	de_dbg(c, "decoding Flashpix stream %d (OLE property set)", (int)fe->index);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "olepropset", NULL, fe->stream, 0, fe->stream->len);
	de_dbg_indent(c, -1);
}

static void do_fpxr_fujifilm_preview(deark *c, lctx *d, struct fpxr_entity_struct *fe)
{
	if(fe->stream->len < 100) return;
	if(dbuf_memcmp(fe->stream, 47, "\xff\xd8\xff", 3)) return;
	dbuf_create_file_from_slice(fe->stream, 47, fe->stream->len-47, "fujipreview.jpg",
		NULL, DE_CREATEFLAG_IS_AUX);
}

static int ucstring_contains_char(de_ucstring *s, i32 ch)
{
	i64 k;

	if(!s) return 0;
	for(k=0; k<s->len; k++) {
		if(s->str[k]==ch) return 1;
	}
	return 0;
}

// Called after we've saved all of a stream's data.
static void finalize_fpxr_stream(deark *c, lctx *d, struct fpxr_entity_struct *fe)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	de_ucstring *name2 = NULL;

	if(!fe || !fe->stream) goto done;
	if(fe->done_flag || fe->is_storage) goto done;

	if(fe->stream->len != fe->stream_size) {
		de_warn(c, "Expected FPXR stream #%u to have %"I64_FMT" bytes, found %"I64_FMT,
			(unsigned int)fe->index, fe->stream_size, fe->stream->len);
	}

	// Process some known streams
	if(fe->name_srd) {
		if(fe->name_srd->sz_utf8 && !de_strcmp(fe->name_srd->sz_utf8, "/FUJIFILM/Preview")) {
			do_fpxr_fujifilm_preview(c, d, fe);
		}

		// The FlashPix spec says "Names in an IStorage that begin with the
		// value '\0x05' are reserved exclusively for the storage of property
		// sets."
		//
		// It probably means the last *component* of the name begins with 0x05.
		// 0x05 shouldn't appear anywhere else, I think, so I'll just search
		// the whole string for it.
		if(ucstring_contains_char(fe->name_srd->str, 0x05)) {
			do_fpxr_olepropset_stream(c, d, fe);
		}
	}

	if(c->extract_level<2) goto done;

	fi = de_finfo_create(c);

	name2 = ucstring_create(c);
	if(fe->name_srd) {
		ucstring_append_ucstring(name2, fe->name_srd->str);
	}
	if(name2->len>0) {
		ucstring_append_char(name2, '.');
	}
	ucstring_append_sz(name2, "fpxr.bin", DE_ENCODING_UTF8);
	de_finfo_set_name_from_ucstring(c, fi, name2, 0);

	outf = dbuf_create_output_file(c, NULL, fi, DE_CREATEFLAG_IS_AUX);
	dbuf_copy(fe->stream, 0, fe->stream->len, outf);

done:
	if(fe && fe->stream) {
		dbuf_close(fe->stream);
		fe->stream = NULL;
	}
	if(fe) {
		fe->done_flag = 1;
	}
	ucstring_destroy(name2);
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

// Clean up incomplete FPXR streams.
// This function shouldn't be necessary, but I've seen some streams that don't
// have their full expected length, even though they seem to contain useful data.
// If we didn't do this, we would never process short streams at all.
static void finalize_all_fpxr_streams(deark *c, lctx *d)
{
	size_t k;

	if(!d->fpxr_data) return;

	for(k=0; k<d->fpxr_data->num_entities; k++) {
		struct fpxr_entity_struct *fe = &d->fpxr_data->entities[k];
		if(fe->stream) {
			finalize_fpxr_stream(c, d, fe);
		}
	}
	destroy_fpxr_data(c, d);
}

static void append_fpxr_stream_data(deark *c, lctx *d, size_t stream_idx,
	i64 pos, i64 len)
{
	struct fpxr_entity_struct *fe = NULL;

	if(!d->fpxr_data) return;
	if(stream_idx > d->fpxr_data->num_entities) return;
	fe = &d->fpxr_data->entities[stream_idx];
	if(fe->done_flag) return;

	// TODO: More validation could be done here.
	// We're just assuming the FPXR chunks are correctly formed, and in the
	// right order.
	// Note that the chunk size (len) is a calculated value, and is constrained
	// to the size of a JPEG segment (64KB). So it should be okay to trust it.

	// If we haven't done it yet, create a membuf for this stream.
	if(!fe->stream) {
		fe->stream = dbuf_create_membuf(c, len, 0);
	}

	// Save the stream data to the membuf.
	// We make a copy of the stream, because it could be split up into chunks,
	// *and* we might want to parse it.
	dbuf_copy(c->infile, pos, len, fe->stream);

	if(fe->stream->len >= fe->stream_size) {
		finalize_fpxr_stream(c, d, fe);
	}
}

static void do_fpxr_segment(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	size_t k;
	i64 nbytesleft;
	int saved_indent_level;
	u8 ver;
	u8 segtype;
	const char *name;

	de_dbg_indent_save(c, &saved_indent_level);
	if(len<2) goto done;
	ver = de_getbyte_p(&pos);

	de_dbg(c, "version: %u", (unsigned int)ver);
	segtype = de_getbyte_p(&pos);
	switch(segtype) {
	case 1: name = "contents list"; break;
	case 2: name = "stream data"; break;
	default: name = "?";
	}
	de_dbg(c, "segment type: %u (%s)", (unsigned int)segtype, name);

	if(segtype==1) { // contents list
		// Initialize our saved fpxr data
		destroy_fpxr_data(c, d);
		d->fpxr_data = de_malloc(c, sizeof(struct fpxr_data_struct));

		if(len<4) goto done;

		d->fpxr_data->num_entities = (size_t)de_getu16be_p(&pos);
		de_dbg(c, "interoperability count: %u", (unsigned int)d->fpxr_data->num_entities);
		d->fpxr_data->entities = de_mallocarray(c, d->fpxr_data->num_entities, sizeof(struct fpxr_entity_struct));

		for(k=0; k<d->fpxr_data->num_entities; k++) {
			i64 bytes_consumed = 0;
			struct fpxr_entity_struct *fe;
			i64 esize;
			u8 defval;
			u8 clsid_buf[16];
			char clsid_string[50];

			if(pos>=pos1+len) goto done;
			fe = &d->fpxr_data->entities[k];
			fe->index = k;
			de_dbg(c, "entity[%d] at %d", (int)k, (int)pos);
			de_dbg_indent(c, 1);

			esize = de_getu32be_p(&pos);
			if(esize==0xffffffffLL) {
				fe->is_storage = 1;
			}
			de_dbg(c, "entity type: %s", fe->is_storage?"storage":"stream");
			if(!fe->is_storage) {
				de_dbg(c, "stream size: %u", (unsigned int)esize);
				fe->stream_size = esize;
			}

			defval = de_getbyte_p(&pos);
			de_dbg(c, "default value: 0x%02x", (unsigned int)defval);

			nbytesleft = pos1+len-pos;
			if(!dbuf_get_utf16_NULterm_len(c->infile, pos, nbytesleft, &bytes_consumed)) goto done;
			fe->name_srd = dbuf_read_string(c->infile, pos, bytes_consumed-2, bytes_consumed-2,
				DE_CONVFLAG_WANT_UTF8, DE_ENCODING_UTF16LE);
			de_dbg(c, "entity name: \"%s\"", ucstring_getpsz_d(fe->name_srd->str));
			pos += bytes_consumed;

			if(fe->is_storage) { // read Entity class ID
				de_read(clsid_buf, pos, 16);
				pos += 16;
				de_fmtutil_guid_to_uuid(clsid_buf);
				de_fmtutil_render_uuid(c, clsid_buf, clsid_string, sizeof(clsid_string));
				de_dbg(c, "class id: {%s}", clsid_string);
			}
			de_dbg_indent(c, -1);
		}
	}
	else if(segtype==2) { // stream data
		size_t stream_idx;
		i64 stream_offset;

		if(len<6) goto done;

		stream_idx = (size_t)de_getu16be_p(&pos);
		de_dbg(c, "index to contents list: %d", (int)stream_idx);

		// The Exif spec (2.31) says this field is at offset 0x0C, but I'm
		// assuming that's a clerical error that should be 0x0D.
		stream_offset = de_getu32be_p(&pos);
		de_dbg(c, "offset to flashpix stream: %u", (unsigned int)stream_offset);

		nbytesleft = pos1+len-pos;
		if(nbytesleft>0) {
			de_dbg(c, "[%d bytes of flashpix stream data, at %d]", (int)nbytesleft, (int)pos);
		}
		append_fpxr_stream_data(c, d, stream_idx, pos, nbytesleft);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_ducky_stringblock(deark *c, lctx *d,
	i64 pos1, i64 len, const char *name)
{
	i64 pos = pos1;
	i64 nchars;
	de_ucstring *s = NULL;

	if(len<4) goto done;
	nchars = de_getu32be_p(&pos);
	if(nchars*2 > len-4) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, nchars*2, DE_DBG_MAX_STRLEN, s,
		0, DE_ENCODING_UTF16BE);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
done:
	ucstring_destroy(s);
}

static void do_ducky_segment(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	u32 blktype;
	i64 blklen;
	i64 n;

	while(1) {
		blktype = (u32)de_getu16be_p(&pos);
		if(blktype==0) break;
		if(pos+2 > pos1+len) break;
		blklen = de_getu16be_p(&pos);
		if(pos+blklen > pos1+len) break;
		switch(blktype) {
		case 1:
			if(blklen==4) {
				n = de_getu32be(pos);
				de_dbg(c, "quality: %d", (int)n);
			}
			break;
		case 2:
			do_ducky_stringblock(c, d, pos, blklen, "comment");
			break;
		case 3:
			do_ducky_stringblock(c, d, pos, blklen, "copyright");
			break;
		}
		pos += blklen;
	}
}

static void do_meta_segment(deark *c, lctx *d, i64 pos1, i64 len)
{
	if(len<1) return;

	de_dbg(c, "\"Meta\" data at %d, size=%d", (int)(pos1+1), (int)(len-1));
	de_dbg_indent(c, 1);
	// TODO: The 3rd param below should probably represent some sort of TIFF
	// tag "namespace".
	de_run_module_by_id_on_slice2(c, "tiff", NULL, c->infile, pos1+1, len-1);
	de_dbg_indent(c, -1);
}


// ITU-T Rec. T.86 says nothing about canonicalizing the APP ID, but in
// practice, some apps are sloppy about capitalization, and trailing spaces.
static void normalize_app_id(const char *app_id_orig, char *app_id_normalized,
	size_t app_id_normalized_len)
{
	i64 id_strlen;
	i64 i;

	de_strlcpy(app_id_normalized, app_id_orig, app_id_normalized_len);
	id_strlen = (i64)de_strlen(app_id_normalized);

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

#define APPSEGTYPE_UNKNOWN        0
#define APPSEGTYPE_JFIF           2
#define APPSEGTYPE_JFXX           3
#define APPSEGTYPE_SPIFF          5
#define APPSEGTYPE_EXIF           6
#define APPSEGTYPE_FPXR           7
#define APPSEGTYPE_ADOBEAPP14     9
#define APPSEGTYPE_ICC_PROFILE    10
#define APPSEGTYPE_PHOTOSHOP      11
#define APPSEGTYPE_DUCKY          12
#define APPSEGTYPE_XMP            14
#define APPSEGTYPE_XMP_EXTENSION  15
#define APPSEGTYPE_JPEGXT         20
#define APPSEGTYPE_MPF            21
#define APPSEGTYPE_JPS            22
#define APPSEGTYPE_HDR_RI_VER     24
#define APPSEGTYPE_HDR_RI_EXT     25
#define APPSEGTYPE_META           26
#define APPSEGTYPE_AROT           27
#define APPSEGTYPE_MSRGBA         100
#define APPSEGTYPE_RBSWAP         101

struct app_id_info_struct {
	int app_id_found;
	int appsegtype;
	i64 payload_pos;
	de_ucstring *app_id_str; // valid if(app_id_found)
	const char *app_type_name;
};

#define MAX_APP_ID_LEN 80
struct app_id_decode_struct {
	// In:
	u8 raw_bytes[MAX_APP_ID_LEN];
	i64 nraw_bytes;

	// Out:
	char app_id_orig[MAX_APP_ID_LEN];
	char app_id_normalized[MAX_APP_ID_LEN];
	i64 app_id_orig_strlen;
	int has_app_id;
};

// Caller allocates ad, and initializes the "In" fields.
static void decode_app_id(struct app_id_decode_struct *ad)
{
	i64 k;

	if(ad->nraw_bytes<2) return;
	if(ad->raw_bytes[0]<32 || ad->raw_bytes[0]>126) return;

	// Might have an app id.
	for(k=0; k<ad->nraw_bytes; k++) {
		if(ad->raw_bytes[k]==0) {
			ad->has_app_id = 1;
			ad->app_id_orig_strlen = k;
			break;
		}
	}

	if(ad->has_app_id) {
		// We'll assume this is an app id
		de_strlcpy(ad->app_id_orig, (const char*)ad->raw_bytes, sizeof(ad->app_id_orig));
		normalize_app_id(ad->app_id_orig, ad->app_id_normalized, sizeof(ad->app_id_normalized));
	}
}

// Caller allocates app_id_info, and initializes it to all 0.
// Caller must free ->app_id_str.
static void detect_app_seg_type(deark *c, lctx *d, const struct marker_info *mi,
	i64 seg_data_pos, i64 seg_data_size, struct app_id_info_struct *app_id_info)
{
	i64 sig_size = 0;
	i64 payload_size;
	u8 seg_type = mi->seg_type;
	struct app_id_decode_struct ad;

	de_zeromem(&ad, sizeof(struct app_id_decode_struct));

	// defaults:
	app_id_info->app_id_found = 0;
	app_id_info->appsegtype = APPSEGTYPE_UNKNOWN;
	app_id_info->app_type_name = "?";

	ad.nraw_bytes = (i64)sizeof(ad.raw_bytes);
	if(ad.nraw_bytes>seg_data_size)
		ad.nraw_bytes = seg_data_size;
	if(ad.nraw_bytes<2) goto done;
	de_read(ad.raw_bytes, seg_data_pos, ad.nraw_bytes-1);

	decode_app_id(&ad);

	if(ad.has_app_id) {
		app_id_info->app_id_str = ucstring_create(c);
		ucstring_append_bytes(app_id_info->app_id_str, (const u8*)ad.app_id_orig, ad.app_id_orig_strlen, 0,
			DE_ENCODING_ASCII);
	}

	if(seg_type==0xe1 && ad.nraw_bytes>20 && ad.has_app_id && !de_strcmp(ad.app_id_orig, "XMP")) {
		// Ugly hack. I've seen a fair number of files in which the first four
		// bytes of the "http://ns.adobe.com/xap/1.0/" signature seem to have
		// been corrupted, and replaced with "XMP\0".
		struct app_id_decode_struct ad2;

		de_zeromem(&ad2, sizeof(struct app_id_decode_struct));
		de_memcpy(ad2.raw_bytes, ad.raw_bytes, (size_t)ad.nraw_bytes);
		ad2.nraw_bytes = ad.nraw_bytes;
		// Try to patch the app ID, decode it, and see what happens.
		de_memcpy(ad2.raw_bytes, (const u8*)"http", 4);

		decode_app_id(&ad2);

		// If that seemed to work, replace the old "normalized" ID with the patched one.
		if(ad2.has_app_id) {
			de_strlcpy(ad.app_id_normalized, ad2.app_id_normalized, sizeof(ad.app_id_normalized));
			// Need to update orig_strlen, so we can find the payload data position.
			// (ad.app_id_orig can stay the same.)
			ad.app_id_orig_strlen = ad2.app_id_orig_strlen;
		}
	}

	if(ad.has_app_id) {
		app_id_info->app_id_found = 1;
		sig_size = ad.app_id_orig_strlen + 1;
	}

	payload_size = seg_data_size - sig_size;
	if(payload_size<0) goto done;

	if(seg_type==0xe0 && !de_strcmp(ad.app_id_normalized, "JFIF")) {
		app_id_info->appsegtype = APPSEGTYPE_JFIF;
		app_id_info->app_type_name = "JFIF";
	}
	else if(seg_type==0xe0 && !de_strcmp(ad.app_id_normalized, "JFXX")) {
		app_id_info->appsegtype = APPSEGTYPE_JFXX;
		app_id_info->app_type_name = "JFIF-JFXX";
	}
	else if(seg_type==0xee && ad.nraw_bytes>=5 && !de_strncmp((const char*)ad.raw_bytes, "Adobe", 5)) {
		app_id_info->appsegtype = APPSEGTYPE_ADOBEAPP14;
		app_id_info->app_type_name = "AdobeAPP14";
		sig_size = 5;
	}
	else if(seg_type==0xec && ad.nraw_bytes>=5 && !de_strncmp((const char*)ad.raw_bytes, "Ducky", 5)) {
		app_id_info->appsegtype = APPSEGTYPE_DUCKY;
		app_id_info->app_type_name = "Ducky";
		sig_size = 5;
	}
	else if(seg_type==0xe1 && seg_data_size>=6 && !de_strcmp(ad.app_id_normalized, "EXIF")) {
		app_id_info->appsegtype = APPSEGTYPE_EXIF;
		app_id_info->app_type_name = "Exif";
		// We arbitrarily consider the "padding byte" to be part of the signature.
		sig_size = 6;
	}
	else if((seg_type==0xe1 || seg_type==0xe3) && ad.nraw_bytes>=14 &&
		!de_memcmp(ad.raw_bytes, "Meta\0\0", 6) &&
		(ad.raw_bytes[6]=='I' || ad.raw_bytes[6]=='M'))
	{
		// This seems to be some Kodak imitation of an Exif segment.
		// ExifTool says APP3, but all I've seen is APP1.
		app_id_info->appsegtype = APPSEGTYPE_META;
		app_id_info->app_type_name = "Meta";
	}
	else if(seg_type==0xe2 && !de_strcmp(ad.app_id_normalized, "ICC_PROFILE")) {
		app_id_info->appsegtype = APPSEGTYPE_ICC_PROFILE;
		app_id_info->app_type_name = "ICC profile";
	}
	else if(seg_type==0xe2 && !de_strcmp(ad.app_id_normalized, "FPXR")) {
		app_id_info->appsegtype = APPSEGTYPE_FPXR;
		app_id_info->app_type_name = "Exif Flashpix Ready";
	}
	else if(seg_type==0xe8 && !de_strcmp(ad.app_id_normalized, "SPIFF")) {
		app_id_info->appsegtype = APPSEGTYPE_SPIFF;
		app_id_info->app_type_name = "SPIFF";
	}
	else if(seg_type==0xed && !de_strcmp(ad.app_id_normalized, "PHOTOSHOP 3.0")) {
		app_id_info->appsegtype = APPSEGTYPE_PHOTOSHOP;
		app_id_info->app_type_name = "Photoshop resources";
	}
	else if(seg_type==0xe1 && !de_strcmp(ad.app_id_normalized, "HTTP://NS.ADOBE.COM/XAP/1.0/")) {
		app_id_info->appsegtype = APPSEGTYPE_XMP;
		app_id_info->app_type_name = "XMP";
	}
	else if(seg_type==0xe1 && ad.nraw_bytes>=32 && !de_memcmp(ad.raw_bytes, "<?xpacket begin=", 16)) {
		// I have a few files like this, that are missing the XMP signature.
		app_id_info->appsegtype = APPSEGTYPE_XMP;
		app_id_info->app_type_name = "XMP";
		sig_size = 0;
	}
	else if(seg_type==0xe1 && !de_strcmp(ad.app_id_normalized, "HTTP://NS.ADOBE.COM/XMP/EXTENSION/")) {
		app_id_info->appsegtype = APPSEGTYPE_XMP_EXTENSION;
		app_id_info->app_type_name = "XMP extension";
	}
	else if(seg_type==0xeb && ad.nraw_bytes>=10 && !de_strncmp((const char*)ad.raw_bytes, "HDR_RI ver", 10)) {
		app_id_info->appsegtype = APPSEGTYPE_HDR_RI_VER;
		app_id_info->app_type_name = "JPEG-HDR Ver";
	}
	else if(seg_type==0xeb && ad.nraw_bytes>=10 && !de_strncmp((const char*)ad.raw_bytes, "HDR_RI ext", 10)) {
		app_id_info->appsegtype = APPSEGTYPE_HDR_RI_EXT;
		app_id_info->app_type_name = "JPEG-HDR Ext";
	}
	else if(seg_type==0xeb && ad.nraw_bytes>=2 && !de_strncmp((const char*)ad.raw_bytes, "JP", 2)) {
		app_id_info->appsegtype = APPSEGTYPE_JPEGXT;
		app_id_info->app_type_name = "JPEG XT";
		sig_size = 2;
	}
	else if(seg_type==0xe2 && !de_strcmp(ad.app_id_normalized, "MPF")) {
		app_id_info->appsegtype = APPSEGTYPE_MPF;
		app_id_info->app_type_name = "Multi-Picture Format";
	}
	else if(seg_type==0xe3 && ad.nraw_bytes>=8 && !de_strncmp((const char*)ad.raw_bytes, "_JPSJPS_", 8)) {
		// This signature is not NUL terminated.
		app_id_info->appsegtype = APPSEGTYPE_JPS;
		app_id_info->app_type_name = "JPS";
		sig_size = 8;
	}
	else if(seg_type==0xea && seg_data_size>=6 && !de_strcmp(ad.app_id_normalized, "AROT")) {
		app_id_info->appsegtype = APPSEGTYPE_AROT;
		app_id_info->app_type_name = "Apple absolute rotational angle delta";
		// Guessing that there's a "padding byte" that's part of the signature.
		sig_size = 6;
	}
	else if(seg_type==0xe1 && !de_strcmp(ad.app_id_orig, "Deark_MSRGBA")) {
		app_id_info->appsegtype = APPSEGTYPE_MSRGBA;
		app_id_info->app_type_name = "RGBA JPEG headers from Thumbs.db";
	}
	else if(seg_type==0xe1 && !de_strcmp(ad.app_id_orig, "Deark_RB_swap")) {
		app_id_info->appsegtype = APPSEGTYPE_RBSWAP;
		app_id_info->app_type_name = "Flag for swapped red/blue";
	}

done:
	app_id_info->payload_pos = seg_data_pos + sig_size;
}

// seg_size is the data size, excluding the marker and length fields.
static void handler_app(deark *c, lctx *d,
	const struct marker_info *mi, i64 seg_data_pos, i64 seg_data_size)
{
	int appsegtype;
	i64 payload_pos;
	i64 payload_size;
	struct app_id_info_struct app_id_info;

	de_zeromem(&app_id_info, sizeof(struct app_id_info_struct));

	detect_app_seg_type(c, d, mi, seg_data_pos, seg_data_size, &app_id_info);
	appsegtype = app_id_info.appsegtype;
	payload_pos = app_id_info.payload_pos;
	if(app_id_info.app_id_found) {
		de_dbg(c, "app id: \"%s\", identified as: %s", ucstring_getpsz(app_id_info.app_id_str),
			app_id_info.app_type_name);
	}
	else {
		de_dbg(c, "app id: (not found), identified as: %s", app_id_info.app_type_name);
	}

	payload_size = seg_data_pos + seg_data_size - payload_pos;
	if(payload_size<0) goto done;

	switch(appsegtype) {
	case APPSEGTYPE_JFIF:
		do_jfif_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_JFXX:
		do_jfxx_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_ADOBEAPP14:
		do_adobeapp14_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_EXIF:
		do_exif_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_META:
		do_meta_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_ICC_PROFILE:
		do_icc_profile_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_FPXR:
		d->has_flashpix = 1;
		do_fpxr_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_SPIFF:
		d->has_spiff_seg = 1;
		break;
	case APPSEGTYPE_PHOTOSHOP:
		do_photoshop_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_DUCKY:
		do_ducky_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_XMP:
		de_dbg(c, "XMP data at %d, size=%d", (int)(payload_pos), (int)(payload_size));
		d->has_xmp = 1;
		dbuf_create_file_from_slice(c->infile, payload_pos, payload_size, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
		break;
	case APPSEGTYPE_XMP_EXTENSION:
		d->has_xmp_ext = 1;
		do_xmp_extension_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_HDR_RI_VER:
		d->is_jpeghdr = 1;
		do_jpeghdr_segment(c, d, seg_data_pos, seg_data_size, 0);
		break;
	case APPSEGTYPE_HDR_RI_EXT:
		do_jpeghdr_segment(c, d, seg_data_pos, seg_data_size, 1);
		break;
	case APPSEGTYPE_JPEGXT:
		d->is_jpegxt = 1;
		do_jpegxt_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_MPF:
		do_mpf_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_JPS:
		d->is_jps = 1;
		do_jps_segment(c, d, payload_pos, payload_size);
		break;
	case APPSEGTYPE_AROT:
		do_arot_segment(c, d, payload_pos, payload_size);
		break;
	default:
		if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, seg_data_pos, seg_data_size, 256, "segment data", 0x1);
		}
		break;
	}

done:
	if(app_id_info.app_id_str) {
		ucstring_destroy(app_id_info.app_id_str);
	}
}

static void handler_jpg8(deark *c, lctx *d,
	const struct marker_info *mi, i64 seg_data_pos, i64 seg_data_size)
{
	u8 id;
	const char *name = "?";

	if(seg_data_size<1) return;
	id = de_getbyte(seg_data_pos);
	if(id==0x0d) {
		d->has_revcolorxform = 1;
		name="inverse color transform specification";
	}
	de_dbg(c, "id: 0x%02x (%s)", (unsigned int)id, name);
}

static void declare_jpeg_fmt(deark *c, lctx *d, u8 seg_type)
{
	const char *name = "JPEG (other)";

	// The declared format is only an executive summary of the kind of JPEG.
	// It does not come close to covering all possible combinations of attributes.
	// (The "summary:" line goes a bit further.)
	if(d->is_jpegls) { name = "JPEG-LS"; }
	else if(d->is_mpo) { name = "JPEG/MPO"; }
	else if(d->is_jps) { name = "JPEG/JPS"; }
	else if(d->is_jpegxt) { name = "JPEG/JPEG_XT"; }
	else if(d->is_jpeghdr) { name = "JPEG-HDR"; }
	else if(d->is_lossless) { name = "JPEG/lossless"; }
	else if(d->has_jfif_seg && d->has_exif_seg) { name = "JPEG/JFIF+Exif"; }
	else if(d->has_jfif_seg) { name = "JPEG/JFIF"; }
	else if(d->has_exif_seg) { name = "JPEG/Exif"; }
	de_declare_fmt(c, name);
}

static void handler_sof(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos, i64 data_size)
{
	i64 w, h;
	u8 b;
	i64 i;
	const char *attr_lossy = "DCT";
	const char *attr_cmpr = "huffman";
	const char *attr_progr = "non-progr.";
	const char *attr_hier = "non-hier.";
	u8 seg_type = mi->seg_type;

	if(data_size<6) return;

	if(d->fpxr_data) {
		finalize_all_fpxr_streams(c, d);
	}

	if(seg_type>=0xc1 && seg_type<=0xcf && (seg_type%4)!=0) {
		if((seg_type%4)==3) { d->is_lossless=1; attr_lossy="lossless"; }
		if(seg_type%16>=9) { d->is_arithmetic=1; attr_cmpr="arithmetic"; }
		if((seg_type%4)==2) { d->is_progressive=1; attr_progr="progressive"; }
		if((seg_type%8)>=5) { d->is_hierarchical=1; attr_hier="hierarchical"; }
		de_dbg(c, "image type: %s, %s, %s, %s",
			attr_lossy, attr_cmpr, attr_progr, attr_hier);
	}
	else if(seg_type==0xc0) {
		d->is_baseline = 1;
		de_dbg(c, "image type: baseline (%s, %s, %s, %s)",
			attr_lossy, attr_cmpr, attr_progr, attr_hier);
	}
	else if(seg_type==0xf7) {
		de_dbg(c, "image type: JPEG-LS");
	}

	// By now we have hopefully collected the info we need to decide what JPEG
	// format we're dealing with.
	declare_jpeg_fmt(c, d, seg_type);

	d->precision = de_getbyte(pos);
	de_dbg(c, "precision: %d", (int)d->precision);
	h = de_getu16be(pos+1);
	w = de_getu16be(pos+3);
	de_dbg_dimensions(c, w, h);
	d->ncomp = (i64)de_getbyte(pos+5);
	de_dbg(c, "number of components: %d", (int)d->ncomp);

	// per-component data
	if(data_size<6+3*d->ncomp) goto done;
	for(i=0; i<d->ncomp; i++) {
		u8 comp_id;
		i64 sf1, sf2;
		u8 qtid;
		comp_id = de_getbyte(pos+6+3*i+0);
		b = de_getbyte(pos+6+3*i+1);
		sf1 = (i64)(b>>4);
		sf2 = (i64)(b&0x0f);
		if(sf1!=1 || sf2!=1) d->is_subsampled = 1;
		ucstring_printf(d->sampling_code, DE_ENCODING_LATIN1, "%d%d", (int)sf1, (int)sf2);
		qtid = de_getbyte(pos+6+3*i+2);
		de_dbg(c, "cmp #%d: id=%d sampling=%d"DE_CHAR_TIMES"%d quant_table=Q%d",
			(int)i, (int)comp_id, (int)sf1, (int)sf2, (int)qtid);
	}

done:
	;
}

static void handler_dri(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos, i64 data_size)
{
	i64 ri;
	if(data_size!=2) return;
	ri = de_getu16be(pos);
	de_dbg(c, "restart interval: %d", (int)ri);
	if(ri!=0) d->has_restart_markers = 1;
}

static void dump_htable_data(deark *c, lctx *d, const u8 *codecounts)
{
	i64 k;
	de_ucstring *s = NULL;

	if(c->debug_level<2) return;

	s = ucstring_create(c);
	for(k=0; k<16; k++) {
		ucstring_printf(s, DE_ENCODING_LATIN1, " %3u",
			(unsigned int)codecounts[k]);
		if(k%8==7) { // end of a debug line
			de_dbg(c, "number of codes of len[%d-%2d]:%s",
				(int)(k-7+1), (int)(k+1),
				ucstring_getpsz(s));
			ucstring_empty(s);
		}
	}
	ucstring_destroy(s);
}

static void handler_dht(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos1, i64 data_size)
{
	i64 pos = pos1;
	u8 b;
	u8 table_class;
	u8 table_id;
	i64 num_huff_codes;
	i64 k;
	u8 codecounts[16];

	while(1) {
		if(pos >= pos1+data_size) goto done;

		b = de_getbyte(pos);
		table_class = b>>4;
		table_id = b&0x0f;
		de_dbg(c, "table: %s%d, at %d", table_class==0?"DC":"AC",
			(int)table_id, (int)pos);

		de_read(codecounts, pos+1, 16);
		num_huff_codes = 0;
		for(k=0; k<16; k++) {
			num_huff_codes += (i64)codecounts[k];
		}
		de_dbg_indent(c, 1);
		dump_htable_data(c, d, codecounts);
		de_dbg(c, "number of codes: %d", (int)num_huff_codes);
		de_dbg_indent(c, -1);
		pos += 1 + 16 + num_huff_codes;
	}

done:
	;
}

// DAC = Define arithmetic coding conditioning
static void handler_dac(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos1, i64 data_size)
{
	i64 ntables;
	i64 i;
	u8 b;
	u8 cs;
	u8 table_class;
	u8 table_id;

	ntables = data_size/2;
	for(i=0; i<ntables; i++) {
		b = de_getbyte(pos1+i*2);
		table_class = b>>4;
		table_id = b&0x0f;
		de_dbg(c, "table: %s%u", table_class==0?"DC":"AC",
			(unsigned int)table_id);
		cs = de_getbyte(pos1+i*2+1);
		de_dbg_indent(c, 1);
		de_dbg(c, "conditioning value: %d", (int)cs);
		de_dbg_indent(c, -1);
	}
}

static void dump_qtable_data(deark *c, lctx *d, i64 pos, u8 precision_code)
{
	u8 qbuf[64];
	i64 k;
	de_ucstring *s = NULL;
	static const u8 zigzag[64] = {
		 0, 1, 5, 6,14,15,27,28,
		 2, 4, 7,13,16,26,29,42,
		 3, 8,12,17,25,30,41,43,
		 9,11,18,24,31,40,44,53,
		10,19,23,32,39,45,52,54,
		20,22,33,38,46,51,55,60,
		21,34,37,47,50,56,59,61,
		35,36,48,49,57,58,62,63
	};

	if(c->debug_level<2) return;
	if(precision_code!=0) return;

	de_read(qbuf, pos, 64);
	s = ucstring_create(c);
	for(k=0; k<64; k++) {
		ucstring_printf(s, DE_ENCODING_LATIN1, " %3u",
			(unsigned int)qbuf[(unsigned int)zigzag[k]]);
		if(k%8==7) { // end of a debug line
			de_dbg(c, "data:%s", ucstring_getpsz(s));
			ucstring_empty(s);
		}
	}
	ucstring_destroy(s);
}

static void handler_dqt(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos1, i64 data_size)
{
	i64 pos = pos1;
	u8 b;
	u8 precision_code;
	u8 table_id;
	i64 qsize;
	const char *s;

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
		de_dbg(c, "table: Q%d, at %d", table_id, (int)pos);

		de_dbg_indent(c, 1);
		de_dbg(c, "precision: %d (%s)", (int)precision_code, s);
		dump_qtable_data(c, d, pos+1, precision_code);
		de_dbg_indent(c, -1);

		if(qsize==0) goto done;

		pos += 1 + qsize;
	}

done:
	;
}

static void handle_comment(deark *c, lctx *d, i64 pos, i64 comment_size,
   de_encoding encoding_base)
{
	de_ucstring *s = NULL;
	de_ext_encoding encoding_ext;
	int write_to_file;

	// If c->extract_level>=2, write the comment to a file;
	// otherwise if we have debugging output, write (at least part of) it
	// to the debug output;
	// otherwise do nothing.

	if(c->extract_level<2 && c->debug_level<1) return;
	if(comment_size<1) return;

	write_to_file = (c->extract_level>=2);

	if(write_to_file && encoding_base==DE_ENCODING_UNKNOWN) {
		// If we don't know the encoding, dump the raw bytes to a file.
		dbuf_create_file_from_slice(c->infile, pos, comment_size, "comment.txt",
			NULL, DE_CREATEFLAG_IS_AUX);
		goto done;
	}

	if(encoding_base==DE_ENCODING_UNKNOWN) {
		// In this case, we're printing the comment in the debug info.
		// If we don't know the encoding, pretend it's ASCII-like.
		encoding_ext = DE_EXTENC_MAKE(DE_ENCODING_ASCII, DE_ENCSUBTYPE_PRINTABLE);
	}
	else {
		encoding_ext = encoding_base;
	}

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, comment_size, s, 0, encoding_ext);

	if(write_to_file) {
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}
	else {
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));
	}

done:
	ucstring_destroy(s);
}

static void handler_com(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos, i64 data_size)
{
	// Note that a JPEG COM-segment comment is an arbitrary sequence of bytes, so
	// there's no way to know what text encoding it uses, or even whether it is text.
	// We'll use the user's "-inenc" encoding, or DE_ENCODING_UNKNOWN by default.
	handle_comment(c, d, pos, data_size, c->input_encoding);
}

static void handler_sos(deark *c, lctx *d,
	const struct marker_info *mi, i64 pos, i64 data_size)
{
	i64 ncomp;
	i64 i;
	u8 cs;
	u8 b;
	u8 ss, se, ax;
	u8 actable, dctable;

	if(data_size<1) goto done;

	d->scan_count++;
	ncomp = (i64)de_getbyte(pos);
	de_dbg(c, "number of components in scan: %d", (int)ncomp);
	if(data_size < 4 + 2*ncomp) goto done;

	for(i=0; i<ncomp; i++) {
		cs = de_getbyte(pos+1+i*2);
		de_dbg(c, "component #%d id: %d", (int)i, (int)cs);
		de_dbg_indent(c, 1);
		b = de_getbyte(pos+1+i*2+1);
		dctable = b>>4;
		actable = b&0x0f;
		de_dbg(c, "tables to use: DC%d, AC%d", (int)dctable, (int)actable);
		de_dbg_indent(c, -1);
	}

	ss = de_getbyte(pos+1+ncomp*2);
	se = de_getbyte(pos+1+ncomp*2+1);
	ax = de_getbyte(pos+1+ncomp*2+2);
	de_dbg(c, "spectral selection start/end: %d, %d", (int)ss, (int)se);
	de_dbg(c, "successive approx. bit pos high/low: %u, %u",
		(unsigned int)(ax>>4), (unsigned int)(ax&0x0f));

done:
	;
}

static const struct marker_info1 marker_info1_arr[] = {
	{0x01, 0x0101, "TEM", NULL, NULL},
	{0xc4, 0x0001, "DHT", "Define Huffman table", handler_dht},
	{0xc8, 0x0201, "JPG", NULL, handler_sof},
	{0xcc, 0x0001, "DAC", "Define arithmetic coding conditioning", handler_dac},
	{0xd8, 0x0103, "SOI", "Start of image", NULL},
	{0xd9, 0x0103, "EOI", "End of image", NULL},
	{0xda, 0x0003, "SOS", "Start of scan", handler_sos},
	{0xdb, 0x0001, "DQT", "Define quantization table", handler_dqt},
	{0xdc, 0x0001, "DNL", "Define number of lines", NULL},
	{0xdd, 0x0003, "DRI", "Define restart interval", handler_dri},
	{0xde, 0x0001, "DHP", "Define hierarchical progression", NULL},
	{0xdf, 0x0001, "EXP", "Expand reference component", NULL},
	{0xf7, 0x0202, "SOF55", "JPEG-LS start of frame", handler_sof},
	{0xf8, 0x0001, "JPG8", NULL, handler_jpg8},
	{0xf8, 0x0002, "LSE", "JPEG-LS preset parameters", NULL},
	{0xfe, 0x0003, "COM", "Comment", handler_com}
};

// Caller allocates mi
static int get_marker_info(deark *c, lctx *d, u8 seg_type,
	struct marker_info *mi)
{
	i64 k;

	de_zeromem(mi, sizeof(struct marker_info));
	mi->seg_type = seg_type;

	// First, try to find the segment type in the static marker info.
	for(k=0; k<(i64)DE_ARRAYCOUNT(marker_info1_arr); k++) {
		const struct marker_info1 *mi1 = &marker_info1_arr[k];

		if(!d->is_jpegls && !(mi1->flags&FLAG_JPEG_COMPAT)) continue;
		if(d->is_jpegls && !(mi1->flags&FLAG_JPEGLS_COMPAT)) continue;

		if(mi1->seg_type == seg_type) {
			mi->flags = mi1->flags;
			mi->hfn = mi1->hfn;
			de_strlcpy(mi->shortname, mi1->shortname, sizeof(mi->shortname));
			if(mi1->longname) {
				de_snprintf(mi->longname, sizeof(mi->longname), "%s: %s",
					mi1->shortname, mi1->longname);
			}
			goto done;
		}
	}

	// Handle some pattern-based markers.

	if(seg_type>=0xe0 && seg_type<=0xef) {
		de_snprintf(mi->shortname, sizeof(mi->shortname), "APP%d", (int)(seg_type-0xe0));
		mi->hfn = handler_app;
		goto done;
	}

	if(seg_type>=0xc0 && seg_type<=0xcf) {
		de_snprintf(mi->shortname, sizeof(mi->shortname), "SOF%d", (int)(seg_type-0xc0));
		de_snprintf(mi->longname, sizeof(mi->longname), "%s: Start of frame", mi->shortname);
		mi->flags |= FLAG_IS_SOF;
		mi->hfn = handler_sof;
		goto done;
	}

	if(seg_type>=0xd0 && seg_type<=0xd7) {
		int rstn = (int)(seg_type-0xd0);
		de_snprintf(mi->shortname, sizeof(mi->shortname), "RST%d", rstn);
		de_snprintf(mi->longname, sizeof(mi->longname), "%s: Restart with mod 8 count %d",
			mi->shortname, rstn);
		mi->flags |= FLAG_NO_DATA;
		goto done;
	}

	if(seg_type>=0xf0 && seg_type<=0xfd) {
		de_snprintf(mi->shortname, sizeof(mi->shortname), "JPG%d", (int)(seg_type-0xf0));
		goto done;
	}

	de_strlcpy(mi->shortname, "???", sizeof(mi->shortname));
	de_strlcpy(mi->longname, "???", sizeof(mi->longname));
	return 0;

done:
	if(!mi->longname[0]) {
		// If no longname was set, use the shortname
		de_strlcpy(mi->longname, mi->shortname, sizeof(mi->longname));
	}
	return 1;
}

static void do_segment(deark *c, lctx *d, const struct marker_info *mi,
	i64 payload_pos, i64 payload_size)
{
	de_dbg(c, "segment 0x%02x (%s) at %d, dpos=%d, dlen=%d",
		(unsigned int)mi->seg_type, mi->longname, (int)(payload_pos-4),
		(int)payload_pos, (int)payload_size);

	if(mi->hfn) {
		// If a handler function is available, use it.
		de_dbg_indent(c, 1);
		mi->hfn(c, d, mi, payload_pos, payload_size);
		de_dbg_indent(c, -1);
	}
}

// TODO: This is very similar to detect_jpeg_len().
// Maybe they should be consolidated.
static int do_read_scan_data(deark *c, lctx *d,
	i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	u8 b0, b1;
	struct marker_info mi;

	*bytes_consumed = c->infile->len - pos1; // default
	de_dbg(c, "scan data at %d", (int)pos1);

	de_dbg_indent(c, 1);

	while(1) {
		if(pos >= c->infile->len) goto done;
		b0 = de_getbyte_p(&pos);
		if(b0==0xff) {
			b1 = de_getbyte_p(&pos);
			if(b1==0x00) {
				; // an escaped 0xff
			}
			else if(d->is_jpegls && b1<0x80) {
				// In JPEG-LS, 0xff bytes are not escaped if they're followed by a
				// a byte less than 0x80.
				;
			}
			else if(b1>=0xd0 && b1<=0xd7) { // an RSTn marker
				if(c->debug_level>=2) {
					get_marker_info(c, d, b1, &mi);
					de_dbg2(c, "marker 0x%02x (%s) at %d", (unsigned int)b1,
						mi.longname, (int)(pos-2));
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
				de_dbg(c, "end of scan data found at %d (len=%d)", (int)pos, (int)*bytes_consumed);
				break;
			}
		}
	}

done:
	de_dbg_indent(c, -1);
	return 1;
}

// Caller supplies s[5].
static void exif_version_to_string(u32 v, char *s)
{
	s[0] = de_byte_to_printable_char((u8)((v>>24)&0xff));
	s[1] = de_byte_to_printable_char((u8)((v>>16)&0xff));
	s[2] = de_byte_to_printable_char((u8)((v>>8)&0xff));
	s[3] = de_byte_to_printable_char((u8)(v&0xff));
	s[4] = '\0';
}

// Print a summary line indicating the main characteristics of this image.
static void print_summary(deark *c, lctx *d)
{
	de_ucstring *summary = NULL;

	if(d->is_jpegls) goto done;
	if(!d->found_sof) goto done;
	if(!d->found_soi) goto done;

	summary = ucstring_create(c);

	if(d->is_baseline) ucstring_append_sz(summary, " baseline", DE_ENCODING_LATIN1);
	if(d->is_lossless) ucstring_append_sz(summary, " lossless", DE_ENCODING_LATIN1);
	if(d->is_progressive) ucstring_append_sz(summary, " progressive", DE_ENCODING_LATIN1);
	if(d->is_arithmetic) ucstring_append_sz(summary, " arithmetic", DE_ENCODING_LATIN1);
	if(d->is_hierarchical) ucstring_append_sz(summary, " hierarchical", DE_ENCODING_LATIN1);
	ucstring_printf(summary, DE_ENCODING_LATIN1, " cmpts=%d", (int)d->ncomp);
	if(d->is_subsampled) {
		// The subsampling type code printed here is not the standard way to denote
		// subsampling, but the standard notation is incomprehensible, and doesn't
		// cover all the possible cases.
		ucstring_printf(summary, DE_ENCODING_UTF8, " subsampling=%s",
			ucstring_getpsz(d->sampling_code));
	}
	ucstring_printf(summary, DE_ENCODING_LATIN1, " bits=%d", (int)d->precision);

	if(d->has_restart_markers) ucstring_append_sz(summary, " rst", DE_ENCODING_LATIN1);
	if(d->has_jfif_seg) {
		ucstring_printf(summary, DE_ENCODING_LATIN1, " JFIF=%u.%02u",
			(unsigned int)d->jfif_ver_h, (unsigned int)d->jfif_ver_l);
	}
	if(d->has_spiff_seg) ucstring_append_sz(summary, " SPIFF", DE_ENCODING_LATIN1);
	if(d->has_exif_seg) {
		ucstring_append_sz(summary, " Exif", DE_ENCODING_LATIN1);
		if(d->exif_version_as_uint32!=0) {
			char tmps[5];
			exif_version_to_string(d->exif_version_as_uint32, tmps);
			ucstring_printf(summary, DE_ENCODING_LATIN1, "=%s", tmps);
		}
	}
	if(d->has_adobeapp14)
		ucstring_printf(summary, DE_ENCODING_LATIN1, " colorxform=%d", (int)d->color_transform);
	if(d->has_revcolorxform) ucstring_append_sz(summary, " rev-colorxform", DE_ENCODING_LATIN1);

	if(d->has_jfif_thumb) ucstring_append_sz(summary, " JFIFthumbnail", DE_ENCODING_LATIN1);
	if(d->has_jfxx_seg) ucstring_append_sz(summary, " JFXX", DE_ENCODING_LATIN1);
	if(d->has_flashpix) ucstring_append_sz(summary, " FlashPix", DE_ENCODING_LATIN1);
	if(d->is_jpeghdr) ucstring_append_sz(summary, " HDR", DE_ENCODING_LATIN1);
	if(d->is_jpegxt) ucstring_append_sz(summary, " XT", DE_ENCODING_LATIN1);
	if(d->has_mpf_seg) ucstring_append_sz(summary, " MPO", DE_ENCODING_LATIN1);
	if(d->is_jps) ucstring_append_sz(summary, " JPS", DE_ENCODING_LATIN1);
	if(d->has_iccprofile) ucstring_append_sz(summary, " ICC", DE_ENCODING_LATIN1);
	if(d->has_xmp) ucstring_append_sz(summary, " XMP", DE_ENCODING_LATIN1);
	if(d->has_xmp_ext) ucstring_append_sz(summary, " XMPext", DE_ENCODING_LATIN1);
	if(d->has_psd) ucstring_append_sz(summary, " PSD", DE_ENCODING_LATIN1);
	if(d->has_iptc) ucstring_append_sz(summary, " IPTC", DE_ENCODING_LATIN1);
	if(d->has_exif_gps) ucstring_append_sz(summary, " GPS", DE_ENCODING_LATIN1);
	if(d->has_afcp) ucstring_append_sz(summary, " AFCP", DE_ENCODING_LATIN1);

	if(d->scan_count!=1) ucstring_printf(summary, DE_ENCODING_LATIN1, " scans=%d", d->scan_count);

	de_dbg(c, "summary:%s", ucstring_getpsz(summary));

done:
	ucstring_destroy(summary);
}

static void do_post_sof_stuff(deark *c, lctx *d)
{
	if(d->is_jpegls) return;

	if(d->has_jfif_seg && d->has_exif_seg && !d->exif_before_jfif &&
		(d->jfif_ver_h==1 && (d->jfif_ver_l==1 || d->jfif_ver_l==2)))
	{
		if(d->exif_orientation>1) {
			de_dbg(c, "Note: Image has an ambiguous orientation: JFIF says "
				"%s; Exif says %s",
				de_fmtutil_tiff_orientation_name(1),
				de_fmtutil_tiff_orientation_name((i64)d->exif_orientation));
		}

		if(d->exif_cosited && d->is_subsampled && d->ncomp>1) {
			de_dbg(c, "Note: Image has an ambiguous subsampling position: JFIF says "
				"centered; Exif says cosited");
		}

		// TODO: Another thing we could check for is a significant conflict in
		// the JFIF and Exif density settings.
	}
}

// Tasks to do at the end of normal JPEG data (after we've found the EOI marker,
// or an unexpected end of file).
// This does not handle data that might exist after the EOI; that might still
// be read later.
static void do_at_end_of_jpeg(deark *c, lctx *d)
{
	dbuf_close(d->iccprofile_file);
	d->iccprofile_file = NULL;
	dbuf_close(d->hdr_residual_file);
	d->hdr_residual_file = NULL;
	destroy_fpxr_data(c, d);

	if(d->extxmp_membuf && !d->extxmp_error_flag) {
		dbuf *tmpdbuf = NULL;
		tmpdbuf = dbuf_create_output_file(c, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_copy(d->extxmp_membuf, 0, d->extxmp_total_len, tmpdbuf);
		dbuf_close(tmpdbuf);
	}
	dbuf_close(d->extxmp_membuf);
	d->extxmp_membuf = NULL;
}

static void do_destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	ucstring_destroy(d->sampling_code);
	de_free(c, d);
}

// Process a single JPEG image (through the EOI marker).
// Returns nonzero if EOI was found.
static int do_jpeg_stream(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	u8 b;
	i64 pos = pos1;
	i64 seg_size;
	u8 seg_type;
	int found_marker;
	struct marker_info mi;
	i64 scan_byte_count;
	int sof_count = 0;
	int retval = 0;

	d->sampling_code = ucstring_create(c);

	found_marker = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte_p(&pos);
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

		if(seg_type==0xf7 && !d->found_sof) {
			d->is_jpegls = 1;
		}

		get_marker_info(c, d, seg_type, &mi);

		if(mi.flags & FLAG_IS_SOF) {
			d->found_sof = 1;
		}

		if(mi.flags & FLAG_NO_DATA) {
			de_dbg(c, "marker 0x%02x (%s) at %d", (unsigned int)seg_type,
				mi.longname, (int)(pos-2));

			if(seg_type==0xd9) { // EOI
				retval = 1;
				goto done;
			}

			if(seg_type==0xd8 && !d->found_soi) {
				d->found_soi = 1;
			}

			continue;
		}

		// If we get here, we're reading a segment that has a size field.
		seg_size = de_getu16be(pos);
		if(pos<2) break; // bogus size

		do_segment(c, d, &mi, pos+2, seg_size-2);

		pos += seg_size;

		if(mi.flags & FLAG_IS_SOF) {
			if(sof_count==0) {
				do_post_sof_stuff(c, d);
			}
			sof_count++;
		}

		if(seg_type==0xda) {
			// If we read an SOS segment, now read the untagged image data that
			// should follow it.
			if(!do_read_scan_data(c, d, pos, &scan_byte_count)) {
				break;
			}
			pos += scan_byte_count;
		}
	}

done:
	do_at_end_of_jpeg(c, d);
	*bytes_consumed = pos - pos1;
	return retval;
}

static void do_afcp_segment(deark *c, lctx *d, i64 endpos)
{
	d->has_afcp = 1;
	de_dbg(c, "AFCP segment found at end of file");

	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "afcp", NULL, c->infile, 0, endpos);
	de_dbg_indent(c, -1);
}

static void de_run_jpeg(deark *c, de_module_params *mparams)
{
	i64 pos;
	i64 bytes_consumed;
	int retval_stream = 0;
	i64 foundpos;
	i64 extra_bytes_at_eof;
	i64 nbytes_to_scan;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	bytes_consumed = 0;
	retval_stream = do_jpeg_stream(c, d, pos, &bytes_consumed);
	if(!retval_stream) goto done;
	pos += bytes_consumed;

	if(bytes_consumed<1) goto done;
	if(pos >= c->infile->len) goto done;

	if(c->module_nesting_level>1) goto done;
	extra_bytes_at_eof = c->infile->len - pos;
	if(extra_bytes_at_eof<4) goto done;

	if(extra_bytes_at_eof>=24) {
		u8 tbuf[12];

		de_read(tbuf, c->infile->len-12, sizeof(tbuf));
		if(tbuf[0]=='A' && tbuf[1]=='X' && tbuf[2]=='S' &&
			(tbuf[3]=='!' || tbuf[3]=='*'))
		{
			do_afcp_segment(c, d, c->infile->len);
			goto done;
		}
	}

	if(d->has_mpf_seg) {
		// In this case, it is normal for there to be multiple JPEG streams,
		// and we should have already extracted the extras.
		goto done;
	}

	nbytes_to_scan = de_min_int(extra_bytes_at_eof, 512);
	if(dbuf_search(c->infile, (const u8*)"\xff\xd8\xff", 3, pos,
		nbytes_to_scan, &foundpos))
	{
		de_info(c, "Note: This file might contain multiple JPEG images. "
			"Use \"-m jpegscan\" to extract them.");
		goto done;
	}

	if(dbuf_is_all_zeroes(c->infile, pos, extra_bytes_at_eof)) goto done;

	de_info(c, "Note: %"I64_FMT" bytes of unidentified data found at end "
		"of file (starting at %"I64_FMT").", extra_bytes_at_eof, pos);

done:
	if(d) {
		if(retval_stream) {
			print_summary(c, d);
		}
		do_destroy_lctx(c, d);
	}
}

typedef struct scanctx_struct {
	i64 len;
	u8 is_jpegls;
} scanctx;

static int detect_jpeg_len(deark *c, scanctx *d, i64 pos1, i64 len)
{
	u8 b0, b1;
	i64 pos;
	i64 seg_size;
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
			de_dbg(c, "Looks like a JPEG-LS file.");
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
		seg_size = de_getu16be(pos+2);
		if(seg_size<2) break; // bogus size

		pos += seg_size+2;
	}

	return 0;
}

static void de_run_jpegscan(deark *c, de_module_params *mparams)
{
	i64 pos = 0;
	i64 foundpos = 0;
	scanctx *d = NULL;
	int ret;

	d = de_malloc(c, sizeof(*d));

	while(1) {
		if(pos >= c->infile->len) break;

		ret = dbuf_search(c->infile, (const u8*)"\xff\xd8\xff", 3,
			pos, c->infile->len-pos, &foundpos);
		if(!ret) break; // No more JPEGs in file.

		de_dbg(c, "Found possible JPEG file at %d", (int)foundpos);

		pos = foundpos;

		if(detect_jpeg_len(c, d, pos, c->infile->len-pos)) {
			de_dbg(c, "length=%d", (int)d->len);
			dbuf_create_file_from_slice(c->infile, pos, d->len,
				d->is_jpegls ? "jls" : "jpg", NULL, 0);
			pos += d->len;
		}
		else {
			de_dbg(c, "Doesn't seem to be a valid JPEG.");
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
	mi->desc = "JPEG image";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_jpeg;
	mi->identify_fn = de_identify_jpeg;
}

void de_module_jpegscan(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpegscan";
	mi->desc = "Extract embedded JPEG images from arbitrary files";
	mi->run_fn = de_run_jpegscan;
}
