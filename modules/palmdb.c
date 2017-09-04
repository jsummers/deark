// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm Database (PDB)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_palmdb);
DE_DECLARE_MODULE(de_module_palmbitmap);

#define CODE_Tbmp 0x54626d70U
#define CODE_View 0x56696577U
#define CODE_appl 0x6170706cU
#define CODE_clpr 0x636c7072U
#define CODE_lnch 0x6c6e6368U
#define CODE_pqa  0x70716120U
#define CODE_tAIB 0x74414942U
#define CODE_vIMG 0x76494d47U

// Our compression code scheme is an extension of the standard BitmapType codes.
// Codes 0x100 and higher are not standard.
#define CMPR_SCANLINE 0
#define CMPR_RLE      1
#define CMPR_PACKBITS 2
#define CMPR_NONE     0xff
#define CMPR_IMGVIEWER 0x100

struct rec_data_struct {
	de_uint32 offset;
};

struct rec_list_struct {
	de_int64 num_recs;
	struct rec_data_struct *rec_data;
};

struct img_gen_info {
	de_int64 w, h;
	de_int64 bitsperpixel;
	de_int64 rowbytes;
	de_finfo *fi;
	unsigned int createflags;
};

typedef struct localctx_struct {
#define FMT_PDB 0
#define FMT_PQA 1
#define FMT_PRC 2
	int file_fmt;
	const char *fmt_shortname;
	de_int64 rec_size; // bytes per record
	struct de_fourcc dtype4cc;
	struct de_fourcc creator4cc;
	de_int64 appinfo_offs;
	de_int64 sortinfo_offs;
	struct rec_list_struct rec_list;
} lctx;

static void handle_palm_timestamp(deark *c, lctx *d, de_int64 pos, const char *name)
{
	struct de_timestamp ts;
	char timestamp_buf[64];
	de_int64 ts_int;

	ts_int = de_getui32be(pos);
	if(ts_int==0) {
		de_dbg(c, "%s: 0 (not set)\n", name);
		return;
	}

	de_dbg(c, "%s: ...\n", name);
	de_dbg_indent(c, 1);

	// I've seen three different ways to interpret this 32-bit timestamp, and
	// I don't know how to guess the correct one.

	de_unix_time_to_timestamp(ts_int - 2082844800, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "... if Mac-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);

	ts_int = de_geti32be(pos);
	if(ts_int>0) { // Assume dates before 1970 are wrong
		de_unix_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0x1);
		de_dbg(c, "... if Unix-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	ts_int = de_getui32le(pos);
	if(ts_int>2082844800) {
		de_unix_time_to_timestamp(ts_int - 2082844800, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Mac-LE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	de_dbg_indent(c, -1);
}

static int do_read_header(deark *c, lctx *d)
{
	de_int64 pos1 = 0;
	de_ucstring *dname = NULL;
	de_uint32 attribs;
	de_uint32 version;
	de_int64 x;

	de_dbg(c, "header at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	dname = ucstring_create(c);
	// TODO: What exactly is the encoding?
	dbuf_read_to_ucstring(c->infile, pos1, 32, dname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(dname));

	attribs = (de_uint32)de_getui16be(pos1+32);
	de_dbg(c, "attributes: 0x%04x\n", (unsigned int)attribs);

	version = (de_uint32)de_getui16be(pos1+34);
	de_dbg(c, "version: 0x%04x\n", (unsigned int)version);

	handle_palm_timestamp(c, d, pos1+36, "create date");
	handle_palm_timestamp(c, d, pos1+40, "mod date");
	handle_palm_timestamp(c, d, pos1+44, "backup date");

	x = de_getui32be(pos1+48);
	de_dbg(c, "mod number: %d\n", (int)x);
	d->appinfo_offs = de_getui32be(pos1+52);
	de_dbg(c, "app info pos: %d\n", (int)d->appinfo_offs);
	d->sortinfo_offs = de_getui32be(pos1+56);
	de_dbg(c, "sort info pos: %d\n", (int)d->sortinfo_offs);

	dbuf_read_fourcc(c->infile, pos1+60, &d->dtype4cc, 0);
	de_dbg(c, "type: \"%s\"\n", d->dtype4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos1+64, &d->creator4cc, 0);
	de_dbg(c, "creator: \"%s\"\n", d->creator4cc.id_printable);

	if(d->dtype4cc.id==CODE_appl) {
		d->file_fmt = FMT_PRC;
		d->fmt_shortname = "PRC";
		de_declare_fmt(c, "Palm PRC");
	}
	else if(d->dtype4cc.id==CODE_pqa && d->creator4cc.id==CODE_clpr) {
		d->file_fmt = FMT_PQA;
		d->fmt_shortname = "PQA";
		de_declare_fmt(c, "Palm PQA");
	}
	else {
		d->file_fmt = FMT_PDB;
		d->fmt_shortname = "PDB";
		de_declare_fmt(c, "Palm PDB");
	}

	x = de_getui32be(68);
	de_dbg(c, "uniqueIDseed: %d\n", (int)x);

	de_dbg_indent(c, -1);
	ucstring_destroy(dname);
	return 1;
}

static de_int64 calc_rec_len(deark *c, lctx *d, de_int64 rec_idx)
{
	de_int64 len;
	if(rec_idx+1 < d->rec_list.num_recs) {
		len = (de_int64)(d->rec_list.rec_data[rec_idx+1].offset - d->rec_list.rec_data[rec_idx].offset);
	}
	else {
		len = c->infile->len - (de_int64)d->rec_list.rec_data[rec_idx].offset;
	}
	return len;
}

static void extract_item(deark *c, lctx *d, de_int64 data_offs, de_int64 data_len,
	const char *ext, unsigned int createflags)
{
	de_finfo *fi = NULL;

	if(c->extract_level<2) goto done;
	if(data_offs<0 || data_len<0) goto done;
	if(data_offs+data_len > c->infile->len) goto done;
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, ext, DE_ENCODING_ASCII);
	dbuf_create_file_from_slice(c->infile, data_offs, data_len, NULL, fi, createflags);
done:
	de_finfo_destroy(c, fi);
}

static int do_decompress_imgview_image(deark *c, lctx *d, dbuf *inf,
	de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	de_int64 pos = pos1;
	de_byte b1, b2;
	de_int64 count;

	while(pos < pos1+len) {
		b1 = dbuf_getbyte(inf, pos++);
		if(b1>128) {
			count = (de_int64)b1-127;
			b2 = dbuf_getbyte(inf, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else {
			count = (de_int64)b1+1;
			dbuf_copy(inf, pos, count, unc_pixels);
			pos += count;
		}
	}
	return 1;
}

static int do_decompress_scanline_compression(deark *c, lctx *d, dbuf *inf,
	de_int64 pos1, de_int64 len, dbuf *unc_pixels, struct img_gen_info *igi)
{
	de_int64 srcpos = pos1;
	de_int64 j;
	de_int64 blocknum;
	de_int64 blocksperrow;
	de_byte bf;
	de_byte dstb;
	unsigned int k;
	de_int64 x;

	blocksperrow = (igi->rowbytes+7)/8;

	x = dbuf_getui16be(inf, srcpos);
	// TODO: Find documentation for this field, and maybe do something with it.
	// It apparently includes the 2 bytes for itself.
	de_dbg2(c, "cmpr len: %d\n", (int)x);
	srcpos += 2;

	for(j=0; j<igi->h; j++) {
		de_int64 bytes_written_this_row = 0;

		for(blocknum=0; blocknum<blocksperrow; blocknum++) {
			// For each byte-per-row, we expect a lead byte, which is a
			// bitfield that tells us which of the next 8 bytes are stored
			// in the file, versus being copied from the previous row.
			bf = dbuf_getbyte(inf, srcpos++);
			for(k=0; k<8; k++) {
				if(bytes_written_this_row>=igi->rowbytes) break;

				if(bf&(1<<(7-k))) {
					// byte is present
					dstb = dbuf_getbyte(inf, srcpos++);
				}
				else {
					// copy from previous row
					dstb = dbuf_getbyte(unc_pixels, unc_pixels->len - igi->rowbytes);
				}
				dbuf_writebyte(unc_pixels, dstb);

				bytes_written_this_row++;
			}
		}
	}

	return 1;
}

static void do_generate_unc_image(deark *c, lctx *d, dbuf *unc_pixels,
	struct img_gen_info *igi)
{
	de_int64 i, j;
	de_byte b;
	struct deark_bitmap *img = NULL;

	if(igi->bitsperpixel==1) {
		de_convert_and_write_image_bilevel(unc_pixels, 0, igi->w, igi->h, igi->rowbytes,
			DE_CVTF_WHITEISZERO, igi->fi, igi->createflags);
		goto done;
	}

	img = de_bitmap_create(c, igi->w, igi->h, 1);

	for(j=0; j<igi->h; j++) {
		for(i=0; i<igi->w; i++) {
			b = de_get_bits_symbol(unc_pixels, igi->bitsperpixel, igi->rowbytes*j, i);
			b = 255 - de_sample_nbit_to_8bit(igi->bitsperpixel, (unsigned int)b);
			de_bitmap_setpixel_gray(img, i, j, b);
		}
	}

	de_bitmap_write_to_file_finfo(img, igi->fi, igi->createflags);

done:
	de_bitmap_destroy(img);
}

// A wrapper that decompresses the image if necessary, then calls do_generate_unc_image().
// TODO: This function signature is a mess.
static void do_generate_image(deark *c, lctx *d,
	dbuf *inf, de_int64 pos, de_int64 len, unsigned int cmpr_type,
	struct img_gen_info *igi)
{
	dbuf *unc_pixels = NULL;
	de_int64 expected_num_uncmpr_image_bytes;

	expected_num_uncmpr_image_bytes = igi->rowbytes*igi->h;

	if(cmpr_type==CMPR_NONE) {
		if(expected_num_uncmpr_image_bytes > len) {
			de_warn(c, "Not enough data for image\n");
		}
		unc_pixels = dbuf_open_input_subfile(inf, pos, len);
	}
	else {
		unc_pixels = dbuf_create_membuf(c, expected_num_uncmpr_image_bytes, 1);

		if(cmpr_type==CMPR_IMGVIEWER) {
			do_decompress_imgview_image(c, d, inf, pos, len, unc_pixels);
		}
		else if(cmpr_type==CMPR_SCANLINE) {
			do_decompress_scanline_compression(c, d, inf, pos, len, unc_pixels, igi);
		}
		else {
			de_err(c, "Unsupported compression type: %u\n", cmpr_type);
			goto done;
		}

		// TODO: The byte counts in this message are not very accurate.
		de_dbg(c, "decompressed %d bytes to %d bytes\n", (int)len,
			(int)unc_pixels->len);
	}

	do_generate_unc_image(c, d, unc_pixels, igi);

done:
	dbuf_close(unc_pixels);
}

static const char *get_cmpr_type_name(unsigned int cmpr_type)
{
	const char *name;

	switch(cmpr_type) {
	case 0: name = "ScanLine"; break;
	case 1: name = "RLE"; break;
	case 2: name = "PackBits"; break;
	case 0xff: name = "none"; break;
	default: name = "?"; break;
	}
	return name;
}

static void do_palm_BitmapType_internal(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	const char *token, unsigned int createflags,
	de_int64 *pnextbitmapoffset)
{
	de_int64 x;
	de_int64 pos;
	de_uint32 bitmapflags;
	de_byte pixelsize_raw;
	de_byte bitmapversion;
	de_int64 headersize;
	de_int64 nextbitmapoffs = 0;
	unsigned int cmpr_type;
	struct img_gen_info *igi = NULL;

	igi = de_malloc(c, sizeof(struct img_gen_info));
	igi->createflags = createflags;

	de_dbg(c, "BitmapType at %d, len<=%d\n", (int)pos1, (int)len);
	de_dbg_indent(c, 1);

	// Look ahead to get the version
	bitmapversion = de_getbyte(pos1+9);
	de_dbg(c, "bitmap version: %d\n", (int)bitmapversion);

	if(bitmapversion>3) {
		// Note that V3 allows the high bit of the version field to
		// be set (to mean little-endian), but we don't support that.
		de_err(c, "Unsupported bitmap version: %d\n", (int)bitmapversion);
		goto done;
	}

	igi->w = de_geti16be(pos1);
	igi->h = de_geti16be(pos1+2);
	de_dbg(c, "dimensions: %dx%d\n", (int)igi->w, (int)igi->h);
	if(!de_good_image_dimensions(c, igi->w, igi->h)) goto done;

	igi->rowbytes = de_getui16be(pos1+4);
	de_dbg(c, "rowBytes: %d\n", (int)igi->rowbytes);

	bitmapflags = (de_uint32)de_getui16be(pos1+6);
	de_dbg(c, "bitmap flags: 0x%04x\n", (unsigned int)bitmapflags);

	if(bitmapversion>=1) {
		pixelsize_raw = de_getbyte(pos1+8);
		de_dbg(c, "pixelSize: %d\n", (int)pixelsize_raw);
	}
	else {
		pixelsize_raw = 0;
	}
	if(pixelsize_raw==0) igi->bitsperpixel = 1;
	else igi->bitsperpixel = (de_int64)pixelsize_raw;

	if(bitmapversion==1 || bitmapversion==2) {
		x = de_getui16be(pos1+10);
		nextbitmapoffs = 4*x;
		de_dbg(c, "nextDepthOffset: %d (%d bytes)\n", (int)x, (int)nextbitmapoffs);
	}

	if(bitmapversion<3) {
		headersize = 16;
	}
	else {
		headersize = (de_int64)de_getbyte(pos1+10);
		de_dbg(c, "header size: %d\n", (int)headersize);
	}

	// [11] TODO: pixelFormat (V3)
	// [12] TODO: transp. idx. (V2)

	if(bitmapflags&0x8000) {
		if(bitmapversion>=2) {
			cmpr_type = (unsigned int)de_getbyte(pos1+13);
			de_dbg(c, "compression type field: 0x%02x\n", cmpr_type);
		}
		else {
			// V1 & V2 have no cmpr_type field, but can still be compressed.
			cmpr_type = CMPR_SCANLINE;
		}
	}
	else {
		cmpr_type = CMPR_NONE;
	}

	if((bitmapflags&0x8000) && (bitmapversion>=2)) {
		de_dbg(c, "compression type: %s (0x%02x)\n", get_cmpr_type_name(cmpr_type), cmpr_type);
	}
	else {
		de_dbg(c, "compression type: %s (based on flags)\n", get_cmpr_type_name(cmpr_type));
	}

	// TODO: [14] density (V3)
	// TODO: [16] transparentValue (V3)

	if(bitmapversion==3 && headersize>=24) {
		// Documented as the "number of bytes to the next bitmap", but it doesn't
		// say where it is measured *from*. I'll assume it's the same logic as
		// the "nextDepthOffset" field.
		nextbitmapoffs = de_getui32be(pos1+20);
		de_dbg(c, "nextBitmapOffset: %u (bytes)\n", (unsigned int)nextbitmapoffs);
	}

	pos = pos1 + headersize;
	if(pos >= pos1+len) goto done;

	if(bitmapversion>=1 && (bitmapflags&0x4000)) {
		de_err(c, "Bitmaps with a color table are not supported\n");
		goto done;
	}

	if(bitmapversion>=2 && (bitmapflags&0x2000)) {
		de_warn(c, "Transparency is not supported\n");
	}

	if(bitmapversion>=3 && (bitmapflags&0x0400)) {
		de_err(c, "RGB color is not supported\n");
		goto done;
	}

	if(igi->bitsperpixel!=1 && igi->bitsperpixel!=2 && igi->bitsperpixel!=4 && igi->bitsperpixel!=8) {
		de_err(c, "Unsupported bits/pixel: %d\n", (int)igi->bitsperpixel);
		goto done;
	}

	igi->fi = de_finfo_create(c);
	if(token) {
		de_finfo_set_name_from_sz(c, igi->fi, token, DE_ENCODING_UTF8);
	}

	do_generate_image(c, d, c->infile, pos, pos1+len-pos, cmpr_type, igi);

done:
	*pnextbitmapoffset = nextbitmapoffs;
	de_dbg_indent(c, -1);
	if(igi) {
		de_finfo_destroy(c, igi->fi);
		de_free(c, igi);
	}
}

static void do_palm_BitmapType(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	const char *token, unsigned int createflags)
{
	de_int64 nextbitmapoffs = 0;
	de_int64 pos = pos1;

	while(1) {
		if(pos > pos1+len-16) {
			de_err(c, "Bitmap exceeds its bounds\n");
			break;
		}
		do_palm_BitmapType_internal(c, d, pos, pos1+len-pos, token, createflags, &nextbitmapoffs);
		if(nextbitmapoffs<=0) break;
		pos += nextbitmapoffs;
	}
}

static void do_imgview_image(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_byte imgver;
	de_byte imgtype;
	unsigned int cmpr_meth;
	de_int64 x0, x1;
	de_int64 pos = pos1;
	de_int64 num_raw_image_bytes;
	de_ucstring *iname = NULL;
	struct img_gen_info *igi = NULL;

	igi = de_malloc(c, sizeof(struct img_gen_info));

	de_dbg(c, "image record at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	iname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 32, iname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(iname));
	// TODO: Use this in the filename?
	pos += 32;

	imgver = de_getbyte(pos++);
	de_dbg(c, "version: 0x%02x\n", (unsigned int)imgver);
	cmpr_meth = (unsigned int)(imgver&0x07);
	de_dbg_indent(c, 1);
	de_dbg(c, "compression method: %u\n", cmpr_meth);
	de_dbg_indent(c, -1);

	imgtype = de_getbyte(pos++);
	de_dbg(c, "type: 0x%02x\n", (unsigned int)imgtype);
	de_dbg_indent(c, 1);
	switch(imgtype) {
	case 0: igi->bitsperpixel = 2; break;
	case 2: igi->bitsperpixel = 4; break;
	default: igi->bitsperpixel = 1;
	}
	de_dbg(c, "bits/pixel: %d\n", (int)igi->bitsperpixel);
	de_dbg_indent(c, -1);

	pos += 4; // reserved
	pos += 4; // note

	x0 = de_getui16be(pos);
	pos += 2;
	x1 = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "last: (%d,%d)\n", (int)x0, (int)x1);

	pos += 4; // reserved

	x0 = de_getui16be(pos);
	pos += 2;
	x1 = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "anchor: (%d,%d)\n", (int)x0, (int)x1);

	igi->w = de_getui16be(pos);
	pos += 2;
	igi->h = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "dimensions: %dx%d\n", (int)igi->w, (int)igi->h);
	if(!de_good_image_dimensions(c, igi->w, igi->h)) goto done;

	igi->rowbytes = (igi->w*igi->bitsperpixel + 7)/8;
	num_raw_image_bytes = pos1+len-pos;

	do_generate_image(c, d, c->infile, pos, num_raw_image_bytes,
		(cmpr_meth==0)?CMPR_NONE:CMPR_IMGVIEWER, igi);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(iname);
	if(igi) {
		de_free(c, igi);
	}
}

static void do_imgview_text(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;

	if(len<1) return;

	// (I'm pretty much just guessing the format of this record.)
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);

	// TODO: Decide when to write the text record to a file.
	// Problem is that we're already using -a to mean "write all raw records to files".
	{
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}

	ucstring_destroy(s);
}

// For PDB or PQA format
static int do_read_pdb_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_int64 data_offs;
	de_byte attribs;
	de_uint32 id;
	de_int64 data_len;

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	data_offs = (int)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);

	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	if(d->file_fmt==FMT_PDB) {
		const char *idname = NULL;
		char tmpstr[80];

		attribs = de_getbyte(pos1+4);
		de_dbg(c, "attributes: 0x%02x\n", (unsigned int)attribs);

		id = (de_getbyte(pos1+5)<<16) |
			(de_getbyte(pos1+6)<<8) |
			(de_getbyte(pos1+7));

		if(d->dtype4cc.id==CODE_vIMG && d->creator4cc.id==CODE_View) {
			if(id==0x6f8000) idname = "image record";
			else if(id==0x6f8001) idname = "text record";
			else idname = "?";
		}
		if(idname)
			de_snprintf(tmpstr, sizeof(tmpstr), " (%s)", idname);
		else
			tmpstr[0] = '\0';

		de_dbg(c, "id: %u (0x%06x)%s\n", (unsigned int)id, (unsigned int)id, tmpstr);

		if(d->dtype4cc.id==CODE_vIMG && d->creator4cc.id==CODE_View) {
			if(id==0x6f8000) do_imgview_image(c, d, data_offs, data_len);
			else if(id==0x6f8001) do_imgview_text(c, d, data_offs, data_len);
		}
	}

	extract_item(c, d, data_offs, data_len, "bin", 0);

	de_dbg_indent(c, -1);
	return 1;
}

static int do_read_prc_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_uint32 id;
	struct de_fourcc name4cc;
	de_int64 data_offs;
	de_int64 data_len;
	const char *ext1 = "bin";
	char extfull[80];

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos1, &name4cc, 0);
	de_dbg(c, "name: \"%s\"\n", name4cc.id_printable);

	id = (de_uint32)de_getui16be(pos1+4);
	de_dbg(c, "id: %d\n", (int)id);

	data_offs = (de_int64)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);
	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	switch(name4cc.id) {
	case CODE_Tbmp:
	case CODE_tAIB:
		ext1 = "palm";
		do_palm_BitmapType(c, d, data_offs, data_len,
			name4cc.id_printable, 0);
		break;
	}

	de_snprintf(extfull, sizeof(extfull), "%s.%s", name4cc.id_printable, ext1);
	extract_item(c, d, data_offs, data_len, extfull, 0);

	de_dbg_indent(c, -1);
	return 1;
}

// Allocates and populates the d->rec_data array.
// Tests for sanity, and returns 0 if there is a problem.
static int do_prescan_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	if(d->rec_list.num_recs<1) return 1;
	// num_recs is untrusted, but it is a 16-bit int that can be at most 65535.
	d->rec_list.rec_data = de_malloc(c, sizeof(struct rec_data_struct)*d->rec_list.num_recs);
	for(i=0; i<d->rec_list.num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			d->rec_list.rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i + 6);
		}
		else {
			d->rec_list.rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i);
		}

		// Record data must not start beyond the end of file.
		if((de_int64)d->rec_list.rec_data[i].offset > c->infile->len) {
			de_err(c, "Record %d (at %d) starts after end of file (%d)\n",
				(int)i, (int)d->rec_list.rec_data[i].offset, (int)c->infile->len);
			return 0;
		}

		// Record data must not start before the previous record's data.
		if(i>0) {
			if(d->rec_list.rec_data[i].offset < d->rec_list.rec_data[i-1].offset) {
				de_err(c, "Record %d (at %d) starts before previous record (at %d)\n",
					(int)i, (int)d->rec_list.rec_data[i].offset, (int)d->rec_list.rec_data[i-1].offset);
				return 0;
			}
		}
	}
	return 1;
}

// Read "Palm Database record list", and the data it refers to
static int do_read_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;
	de_int64 x;
	int retval = 0;

	de_dbg(c, "%s record list at %d\n", d->fmt_shortname, (int)pos1);
	de_dbg_indent(c, 1);

	// 6-byte header

	x = de_getui32be(pos1);
	de_dbg(c, "nextRecordListID: %d\n", (int)x);
	if(x!=0) {
		de_warn(c, "This file contains multiple record lists, which is not supported.\n");
	}

	d->rec_list.num_recs = de_getui16be(pos1+4);
	de_dbg(c, "number of records: %d\n", (int)d->rec_list.num_recs);

	/////

	if(d->file_fmt==FMT_PRC) d->rec_size = 10;
	else d->rec_size = 8;

	if(!do_prescan_records(c, d, pos1+6)) goto done;

	for(i=0; i<d->rec_list.num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			if(!do_read_prc_record(c, d, i, pos1+6+d->rec_size*i))
				goto done;
		}
		else {
			if(!do_read_pdb_record(c, d, i, pos1+6+d->rec_size*i))
				goto done;
		}
	}
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_pqa_app_info_block(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_uint32 sig;
	de_uint32 ux;
	de_ucstring *s = NULL;
	de_int64 pos = pos1;

	sig = (de_uint32)de_getui32be(pos);
	if(sig!=CODE_lnch) return; // Apparently not a PQA appinfo block
	de_dbg(c, "PQA sig: 0x%08x\n", (unsigned int)sig);
	pos += 4;

	ux = (de_uint32)de_getui16be(pos);
	de_dbg(c, "hdrVersion: 0x%04x\n", (unsigned int)ux);
	pos += 2;
	ux = (de_uint32)de_getui16be(pos);
	de_dbg(c, "encVersion: 0x%04x\n", (unsigned int)ux);
	pos += 2;

	s = ucstring_create(c);

	ux = (de_uint32)de_getui16be(pos);
	pos += 2;
	dbuf_read_to_ucstring_n(c->infile, pos, ux*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "verStr: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_empty(s);
	pos += 2*ux;

	ux = (de_uint32)de_getui16be(pos);
	pos += 2;
	dbuf_read_to_ucstring_n(c->infile, pos, ux*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "pqaTitle: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_empty(s);
	pos += 2*ux;

	de_dbg(c, "icon\n");
	de_dbg_indent(c, 1);
	ux = (de_uint32)de_getui16be(pos); // iconWords (length prefix)
	pos += 2;
	do_palm_BitmapType(c, d, pos, 2*ux, "icon", DE_CREATEFLAG_IS_AUX);
	extract_item(c, d, pos, 2*ux, "icon.palm", DE_CREATEFLAG_IS_AUX);
	pos += 2*ux;
	de_dbg_indent(c, -1);

	de_dbg(c, "smIcon\n");
	de_dbg_indent(c, 1);
	ux = (de_uint32)de_getui16be(pos); // smIconWords
	pos += 2;
	do_palm_BitmapType(c, d, pos, 2*ux, "smicon", DE_CREATEFLAG_IS_AUX);
	extract_item(c, d, pos, 2*ux, "smicon.palm", DE_CREATEFLAG_IS_AUX);
	pos += 2*ux;
	de_dbg_indent(c, -1);

	ucstring_destroy(s);
}

static void do_app_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->appinfo_offs==0) return;
	de_dbg(c, "app info block at %d\n", (int)d->appinfo_offs);

	de_dbg_indent(c, 1);
	if(d->sortinfo_offs) {
		len = d->sortinfo_offs - d->appinfo_offs;
	}
	else if(d->rec_list.num_recs>0) {
		len = (de_int64)d->rec_list.rec_data[0].offset - d->appinfo_offs;
	}
	else {
		len = c->infile->len - d->appinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		// TODO: Decide exactly when to extract this, and when to decode it.
		extract_item(c, d, d->appinfo_offs, len, "appinfo.bin", DE_CREATEFLAG_IS_AUX);

		if(d->file_fmt==FMT_PQA) {
			do_pqa_app_info_block(c, d, d->appinfo_offs, len);
		}
	}

	de_dbg_indent(c, -1);
}

static void do_sort_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->sortinfo_offs==0) return;
	de_dbg(c, "sort info block at %d\n", (int)d->sortinfo_offs);

	de_dbg_indent(c, 1);
	if(d->rec_list.num_recs>0) {
		len = (de_int64)d->rec_list.rec_data[0].offset - d->sortinfo_offs;
	}
	else {
		len = c->infile->len - d->sortinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		extract_item(c, d, d->sortinfo_offs, len, "sortinfo.bin", DE_CREATEFLAG_IS_AUX);
	}

	de_dbg_indent(c, -1);
}

static void free_lctx(deark *c, lctx *d)
{
	if(d) {
		de_free(c, d->rec_list.rec_data);
		de_free(c, d);
	}
}

static void de_run_palmdb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	if(!do_read_header(c, d)) goto done;
	if(!do_read_records(c, d, 72)) goto done;
	do_app_info_block(c, d);
	do_sort_info_block(c, d);

done:
	free_lctx(c, d);
}

static int de_identify_palmdb(deark *c)
{
	int has_ext = 0;
	de_byte id[8];
	static const char *exts[] = {"pdb", "prc", "pqa", "mobi"};
	static const char *ids[] = {"vIMGView", "TEXtREAd", "pqa clpr", "BOOKMOBI"};
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}
	if(!has_ext) return 0;

	de_read(id, 60, 8);

	if(!de_memcmp(id, "appl", 4)) return 100;

	for(k=0; k<DE_ITEMS_IN_ARRAY(ids); k++) {
		if(!de_memcmp(id, ids[k], 8)) return 100;
	}

	// TODO: More work is needed here.
	return 0;
}

void de_module_palmdb(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmdb";
	mi->desc = "Palm OS PDB, PRC, PQA";
	mi->run_fn = de_run_palmdb;
	mi->identify_fn = de_identify_palmdb;
}

static void de_run_palmbitmap(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	do_palm_BitmapType(c, d, 0, c->infile->len, NULL, 0);

	free_lctx(c, d);
}

void de_module_palmbitmap(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmbitmap";
	mi->desc = "Palm BitmapType";
	mi->run_fn = de_run_palmbitmap;
	mi->identify_fn = de_identify_none;
}
