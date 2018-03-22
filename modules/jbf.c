// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PaintShop Pro Browser Cache (JBF) (pspbrwse.jbf)

// This module was developed with the help of information from
// jbfinspect.c (https://github.com/0x09/jbfinspect), which says:
//     "The author disclaims all copyright on this code."

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_jbf);

struct page_ctx {
	de_finfo *fi;
	de_ucstring *fname;
	const char *thumbnail_ext;
};

typedef struct localctx_struct {
	unsigned int ver_major;
	unsigned int ver_minor;
	unsigned int ver_combined;
	de_int64 image_count;
} lctx;

static const de_uint32 v1pal[256] = {
	0x000000,0xffffff,0xff0000,0x00fe00,0x0000fe,0xffff00,0xff00ff,0x00ffff,
	0x0f0f0f,0x171717,0x1f1f1f,0x272727,0x383838,0x404040,0x484848,0x4f4f4f,
	0x606060,0x686868,0x707070,0x808080,0x979797,0xa0a0a0,0xb0b0b0,0xb8b8b8,
	0xbfbfbf,0xc8c8c8,0xd9d9d9,0xe0e0e0,0xe8e8e8,0xf0f0f0,0xc00000,0x170606,
	0x270506,0x400b0b,0x500f0f,0x681717,0x801717,0x981b1b,0xa01f20,0xb82324,
	0xc82728,0xe02b2b,0xf12f2f,0xff4040,0xfe5050,0xff6060,0xff706f,0xff807f,
	0xff9898,0xffa0a0,0xffb0b0,0xfec0c0,0xffd0d0,0xffe0e0,0xfff0f0,0x00c000,
	0x061705,0x062705,0x0a400b,0x0f500f,0x176717,0x177f17,0x1b971b,0x1fa020,
	0x24b724,0x27c827,0x2ce02b,0x30f02f,0x40ff40,0x50ff50,0x60ff60,0x70ff70,
	0x80ff80,0x98ff98,0x9fffa0,0xb0ffb0,0xc0fec0,0xd0fed1,0xe0ffe1,0xf0fff0,
	0x0000c0,0x060617,0x050628,0x0a0b3f,0x0f0e4f,0x171768,0x171780,0x1c1b98,
	0x2020a0,0x2324b8,0x2728c8,0x2b2be0,0x2f2ff0,0x4040ff,0x5050ff,0x605fff,
	0x6f70ff,0x8080ff,0x9797fe,0x9fa0ff,0xb0afff,0xc0c0ff,0xd0d0ff,0xe0e0fe,
	0xf0f0ff,0xc0c100,0x171706,0x282705,0x40400b,0x4f500f,0x686717,0x808017,
	0x97981b,0xa0a01f,0xb8b824,0xc8c827,0xe1e02b,0xf0f030,0xffff3f,0xffff50,
	0xfeff60,0xffff6f,0xffff80,0xffff98,0xfffea0,0xfefeb1,0xffffc0,0xffffd0,
	0xfeffe0,0xfffff0,0xc000c0,0x170517,0x270527,0x400a3f,0x500f50,0x681768,
	0x80177f,0x981b98,0xa01f9f,0xb823b8,0xc927c8,0xe02be1,0xf02ff1,0xff40fe,
	0xff50fe,0xff5fff,0xff70ff,0xff7fff,0xfe98ff,0xfea0ff,0xffb0ff,0xffc0ff,
	0xffcffe,0xffdfff,0xfff0ff,0x00c0c0,0x062727,0x0a4040,0x0f4f50,0x186868,
	0x178080,0x1b9898,0x1fa0a0,0x23b8b8,0x27c8c8,0x2ce0df,0x30f0f0,0x40ffff,
	0x4fffff,0x60ffff,0x70fffe,0x80fffe,0x97fffe,0xa0ffff,0xafffff,0xc1ffff,
	0xcfffff,0xf1ffff,0x170f05,0x271705,0x401f0a,0x50270f,0x673817,0x804017,
	0x98481b,0xa0501f,0xb86023,0xc86828,0xe0702b,0xf0802f,0xf88840,0xf49850,
	0xf49760,0xf8a070,0xf8b080,0xf8b898,0xf9bea0,0xfac8b1,0xffd9c0,0xffe0d0,
	0xffe8e0,0xfff0f0,0x28170f,0x402317,0x4f2f1f,0x674028,0x7f4830,0x985438,
	0x9f6040,0xb86c48,0xc88050,0xd9845c,0xe09768,0xdf9c73,0xe4a880,0xe8b797,
	0xe9c098,0xefcca4,0xefd8b0,0xf8e4bc,0xf9f0c8,0xf8f8d4,0xfff4e1,0xfff7f0,
	0x50507f,0x5f5f88,0x686897,0x706f98,0x8080a0,0x8888b0,0x9798be,0x9898c8,
	0xa0a0d9,0xb0b0e0,0xb8b8e8,0x50804f,0x5f8760,0x679868,0x6f9870,0x7fa080,
	0x88b087,0x98be98,0x98c898,0xa0d89f,0xb0e1b0,0xb8e8b8,0x007ff0,0x00f080,
	0x7f00f0,0x78f000,0xf18000,0xf00080,0xc10037,0xa89080,0x606848,0x887860
};

static int do_read_header(deark *c, lctx *d, de_int64 pos)
{
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 15;
	d->ver_major = (unsigned int)de_getui16be(pos);
	d->ver_minor = (unsigned int)de_getui16be(pos+2);
	d->ver_combined = (d->ver_major<<16) | d->ver_minor;
	de_dbg(c, "format version: %u.%u", d->ver_major, d->ver_minor);
	pos+=4;

	if(d->ver_major<1 || d->ver_major>2) {
		de_err(c, "Unsupported JBF format version: %u.%u", d->ver_major, d->ver_minor);
		goto done;
	}
	if(d->ver_major==1 && (d->ver_minor==2 || d->ver_minor>3)) {
		de_warn(c, "Unrecognized JBF format version (%u.%u). File may not be "
			"decoded correctly.", d->ver_major, d->ver_minor);
	}

	d->image_count = de_getui32le(pos);
	de_dbg(c, "image count: %d", (int)d->image_count);
	pos+=4;
	if(!de_good_image_count(c, d->image_count)) goto done;

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static const char *get_type_name(unsigned int filetype_code)
{
	const char *nm = "unknown";

	switch(filetype_code) {
	// There are many more PSP file types. These are just some common ones.
	case 0x00: nm="none"; break;
	case 0x01: nm="BMP"; break;
	case 0x0a: nm="GIF"; break;
	case 0x11: nm="JPEG"; break;
	case 0x18: nm="PCX"; break;
	case 0x1c: nm="PNG"; break;
	case 0x1f: nm="PSP"; break;
	case 0x23: nm="TGA"; break;
	case 0x24: nm="TIFF"; break;
	}
	return nm;
}

static int read_filename(deark *c, lctx *d, struct page_ctx *pg, de_int64 pos1, de_int64 *bytes_consumed)
{
	int retval = 0;
	de_int64 pos = pos1;
	de_ucstring *fname_orig = NULL;

	fname_orig = ucstring_create(c);

	if(d->ver_combined>=0x010001) { // v1.1+
		de_int64 fnlen;
		fnlen = de_getui32le(pos);
		de_dbg(c, "original filename len: %d", (int)fnlen);
		pos += 4;
		if(fnlen>1000) {
			de_err(c, "Bad filename length");
			goto done;
		}

		// I don't think there's any way to know the encoding of the filename.
		// WINDOWS1252 is just a guess.
		dbuf_read_to_ucstring(c->infile, pos, fnlen, fname_orig, 0, DE_ENCODING_WINDOWS1252);
		pos += fnlen;
	}
	else { // v1.0
		// File always has 13 bytes reserved for the filename.
		// The name is up to 12 bytes long, terminated by 0x00.
		dbuf_read_to_ucstring(c->infile, pos, 12, fname_orig, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_WINDOWS1252);
		pos += 13;
	}

	de_dbg(c, "original filename: \"%s\"", ucstring_getpsz(fname_orig));

	if(c->filenames_from_file) {
		pg->fname = ucstring_clone(fname_orig);
		ucstring_append_sz(pg->fname, ".thumb.", DE_ENCODING_ASCII);
		if(d->ver_major>=2)
			ucstring_append_sz(pg->fname, "jpg", DE_ENCODING_ASCII);
		else
			ucstring_append_sz(pg->fname, "bmp", DE_ENCODING_ASCII);
		de_finfo_set_name_from_ucstring(c, pg->fi, pg->fname);
		pg->fi->original_filename_flag = 1;
	}
	else {
		if(d->ver_major>=2)
			pg->thumbnail_ext = "jpg";
		else
			pg->thumbnail_ext = "bmp";
	}

	retval = 1;
done:
	ucstring_destroy(fname_orig);
	*bytes_consumed = pos - pos1;
	return retval;
}

static void read_FILETIME(deark *c, lctx *d, struct page_ctx *pg, de_int64 pos)
{
	de_int64 ft;
	char timestamp_buf[64];

	ft = de_geti64le(pos);
	de_FILETIME_to_timestamp(ft, &pg->fi->mod_time);
	de_timestamp_to_string(&pg->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static void read_unix_time(deark *c, lctx *d, struct page_ctx *pg, de_int64 pos)
{
	de_int64 ut;
	char timestamp_buf[64];

	ut = de_geti32le(pos);
	de_unix_time_to_timestamp(ut, &pg->fi->mod_time);
	de_timestamp_to_string(&pg->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static int read_bitmap_v1(deark *c, lctx *d, struct page_ctx *pg, de_int64 pos1, de_int64 *bytes_consumed)
{
	struct de_bmpinfo bi;
	int retval = 0;
	dbuf *outf = NULL;
	de_int64 pos = pos1;
	de_int64 k;
	de_int64 count;
	de_int64 dec_bytes = 0;

	de_dbg(c, "bitmap at %d", (int)pos);
	de_dbg_indent(c, 1);

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, pos, c->infile->len-pos, 0)) {
		de_err(c, "Invalid bitmap");
		goto done;
	}

	if(bi.infohdrsize != 40) {
		de_err(c, "Unexpected BMP format");
		goto done;
	}

	outf = dbuf_create_output_file(c, pg->thumbnail_ext, pg->fi, 0);
	// Manufacture a BMP fileheader
	de_fmtutil_generate_bmpfileheader(c, outf, &bi, 0);

	// Copy the BITMAPINFOHEADER
	dbuf_copy(c->infile, pos, bi.infohdrsize, outf);

	// Write the standard palette
	for(k=0; k<256; k++) {
		dbuf_writebyte(outf, (de_byte)DE_COLOR_B(v1pal[k]));
		dbuf_writebyte(outf, (de_byte)DE_COLOR_G(v1pal[k]));
		dbuf_writebyte(outf, (de_byte)DE_COLOR_R(v1pal[k]));
		dbuf_writebyte(outf, 0);
	}

	pos += bi.infohdrsize;

	// Decompress the image
	while(1) {
		de_byte b0, b1;

		// Stop if we reach the end of the input file.
		if(pos >= c->infile->len) break;

		// Stop if we decompressed the expected number of bytes
		if(dec_bytes >= bi.foreground_size) break;

		b0 = de_getbyte(pos++);

		if(d->ver_minor>=3) {
			if(b0>0x80) { // a compressed run
				count = (de_int64)(b0-0x80);
				b1 = de_getbyte(pos++);
				dbuf_write_run(outf, b1, count);
				dec_bytes += count;
			}
			else { // uncompressed run
				count = (de_int64)b0;
				dbuf_copy(c->infile, pos, count, outf);
				pos += count;
				dec_bytes += count;
			}
		}
		else {
			if(b0>0xc0) { // a compressed run
				count = (de_int64)(b0-0xc0);
				b1 = de_getbyte(pos++);
				dbuf_write_run(outf, b1, count);
				dec_bytes += count;
			}
			else { // literal byte
				count = 1;
				dbuf_writebyte(outf, b0);
				dec_bytes += 1;
			}
		}
	}

	retval = 1;
done:
	dbuf_close(outf);
	*bytes_consumed = pos - pos1;
	de_dbg_indent(c, -1);
	return retval;
}

static int do_one_thumbnail(deark *c, lctx *d, de_int64 pos1, de_int64 imgidx, de_int64 *bytes_consumed)
{
	de_int64 payload_len;
	int retval = 0;
	de_int64 pos = pos1;
	unsigned int filetype_code;
	de_int64 file_size;
	de_int64 x;
	de_int64 tn_w, tn_h;
	struct page_ctx *pg = NULL;
	de_int64 fn_field_size = 0;

	de_dbg(c, "image #%d at %d", (int)imgidx, (int)pos1);
	de_dbg_indent(c, 1);

	pg = de_malloc(c, sizeof(struct page_ctx));

	pg->fi = de_finfo_create(c);

	if(!read_filename(c, d, pg, pos, &fn_field_size)) {
		goto done;
	}
	pos += fn_field_size;

	if(d->ver_major==2) {
		read_FILETIME(c, d, pg, pos);
		pos += 8;
	}

	if(d->ver_major==2) {
		// The original file type (not the format of the thumbnail)
		filetype_code = (unsigned int)de_getui32le(pos);
		de_dbg(c, "original file type: 0x%02x (%s)", filetype_code, get_type_name(filetype_code));
		pos += 4; // filetype code
	}
	else if(d->ver_major==1 && d->ver_minor<3) {
		pos += 4; // TODO: FOURCC
	}

	tn_w = de_getui16le(pos);
	pos += 4;
	tn_h = de_getui16le(pos);
	pos += 4;
	de_dbg(c, "original dimensions: %d"DE_CHAR_TIMES"%d", (int)tn_w, (int)tn_h);

	pos += 4; // color depth

	if(d->ver_major==2) {
		pos += 4; // (uncompressed size?)
	}

	file_size = de_getui32le(pos);
	de_dbg(c, "original file size: %u", (unsigned int)file_size);
	pos += 4;

	if(d->ver_major==1) {
		read_unix_time(c, d, pg, pos);
		pos += 4;

		pos += 4; // TODO: image index
	}

	if(d->ver_major==2) {
		// first 4 bytes of 12-byte "thumbnail signature"
		x = de_getui32le(pos);
		pos += 4;
		if(x==0) { // truncated entry
			de_dbg(c, "thumbnail not present");
			retval = 1;
			goto done;
		}

		pos += 8; // remaining 8 byte of signature

		payload_len = de_getui32le(pos);
		de_dbg(c, "payload len: %u", (unsigned int)payload_len);
		pos += 4;

		if(pos + payload_len > c->infile->len) {
			de_err(c, "Bad payload length (%u) or unsupported format", (unsigned int)payload_len);
			goto done;
		}

		dbuf_create_file_from_slice(c->infile, pos, payload_len, pg->thumbnail_ext, pg->fi, 0);
		pos += payload_len;
	}
	else { // ver_major==1
		de_int64 thumbnail_size;
		if(!read_bitmap_v1(c, d, pg, pos, &thumbnail_size)) {
			goto done;
		}
		pos += thumbnail_size;
	}

	retval = 1;
done:
	*bytes_consumed = pos - pos1;
	de_finfo_destroy(c, pg->fi);
	ucstring_destroy(pg->fname);
	de_free(c, pg);
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_jbf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos = 0;
	de_int64 bytes_consumed;
	de_int64 count = 0;

	d = de_malloc(c, sizeof(lctx));
	if(!do_read_header(c, d, pos)) goto done;
	pos += 1024;

	count = 0;
	while(1) {
		if(count>=d->image_count) break;
		if(pos>=c->infile->len) goto done;

		bytes_consumed = 0;
		if(!do_one_thumbnail(c, d, pos, count, &bytes_consumed)) {
			goto done;
		}
		if(bytes_consumed<1) goto done;
		pos += bytes_consumed;
		count++;
	}

done:
	de_free(c, d);
}

static int de_identify_jbf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "JASC BROWS FILE", 15))
		return 100;
	return 0;
}

void de_module_jbf(deark *c, struct deark_module_info *mi)
{
	mi->id = "jbf";
	mi->desc = "PaintShop Pro Browser Cache (pspbrwse.jbf)";
	mi->run_fn = de_run_jbf;
	mi->identify_fn = de_identify_jbf;
}
