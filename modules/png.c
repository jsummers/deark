// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PNG and related formats

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_png);

#define PNGID_IDAT 0x49444154
#define PNGID_IHDR 0x49484452U
#define PNGID_gAMA 0x67414d41U
#define PNGID_iCCP 0x69434350
#define PNGID_iTXt 0x69545874
#define PNGID_pHYs 0x70485973U
#define PNGID_tEXt 0x74455874
#define PNGID_tIME 0x74494d45U
#define PNGID_zTXt 0x7a545874

typedef struct localctx_struct {
#define DE_PNGFMT_PNG 1
#define DE_PNGFMT_JNG 2
#define DE_PNGFMT_MNG 3
	int fmt;
} lctx;

struct text_chunk_ctx {
	int is_xmp;
};

#define FIELD_KEYWORD  1
#define FIELD_LANG     2
#define FIELD_XKEYWORD 3
#define FIELD_MAIN     4

// Read and process the keyword, language, translated keyword, or main text
// field of a tEXt/zTXt/iTXt chunk.
// 'bytes_consumed' does not include the NUL separator/terminator.
static int do_text_field(deark *c, lctx *d,
	struct text_chunk_ctx *tcc,
	int which_field,
	dbuf *srcdbuf, de_int64 pos, de_int64 bytes_avail,
	int is_nul_terminated, int is_compressed, int encoding,
	de_int64 *bytes_consumed)
{
	dbuf *tmpdbuf = NULL;
	de_ucstring *value_s = NULL;
	dbuf *value_dbuf = NULL; // Uncompressed value. A pointer to either src_dbuf, or tmpdbuf.
	de_int64 value_pos, value_len; // Position in value_dbuf.
	const char *name;
	int retval = 0;

	*bytes_consumed = 0;

	if(bytes_avail<0) return 0;

	if(is_compressed) {
		// Decompress to a membuf
		tmpdbuf = dbuf_create_membuf(c, 0, 0);
		if(!de_uncompress_zlib(srcdbuf, pos, bytes_avail, tmpdbuf)) {
			goto done;
		}
		value_dbuf = tmpdbuf;
		value_pos = 0;
		value_len = tmpdbuf->len;
	}
	else {
		de_int64 foundpos;

		if(is_nul_terminated) {
			if(!dbuf_search_byte(srcdbuf, 0x00, pos, bytes_avail, &foundpos)) {
				goto done;
			}
			value_len = foundpos - pos;
		}
		else {
			value_len = bytes_avail;
		}

		value_dbuf = srcdbuf;
		value_pos = pos;
		*bytes_consumed = value_len;
	}

	if(which_field==FIELD_KEYWORD) {
		// This is a bit of a hack. If there are any other special keywords we need
		// to look for, we should do something better.
		if(value_len==17 && !dbuf_memcmp(value_dbuf, value_pos, "XML:com.adobe.xmp", 17)) {
			tcc->is_xmp = 1;
		}
	}

	if(which_field==FIELD_MAIN && tcc->is_xmp) {
		dbuf_create_file_from_slice(value_dbuf, value_pos, value_len, "xmp",
			NULL, DE_CREATEFLAG_IS_AUX);
		retval = 1;
		goto done;
	}

	// Read the value into a ucstring, for easy printing.
	value_s = ucstring_create(c);
	dbuf_read_to_ucstring_n(value_dbuf, value_pos, value_len, 300, value_s, 0, encoding);

	switch(which_field) {
	case FIELD_KEYWORD: name="keyword"; break;
	case FIELD_LANG: name="language"; break;
	case FIELD_XKEYWORD: name="translated keyword"; break;
	default: name="text";
	}

	de_dbg(c, "%s: \"%s\"\n", name, ucstring_get_printable_sz(value_s));
	retval = 1;

done:
	ucstring_destroy(value_s);
	dbuf_close(tmpdbuf);
	return retval;
}

static void do_png_text(deark *c, lctx *d, de_uint32 chunk_id, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 field_bytes_consumed;
	int is_compressed = 0;
	int encoding;
	int ret;
	struct text_chunk_ctx tcc;

	de_memset(&tcc, 0, sizeof(struct text_chunk_ctx));

	endpos = pos1+len;
	pos = pos1;

	// Keyword
	ret = do_text_field(c, d, &tcc, FIELD_KEYWORD, c->infile, pos, endpos-pos,
		1, 0, DE_ENCODING_LATIN1, &field_bytes_consumed);
	if(!ret) goto done;
	pos += field_bytes_consumed;
	pos += 1;

	// Compression flag
	if(chunk_id==PNGID_iTXt) {
		is_compressed = (int)de_getbyte(pos++);
		de_dbg(c, "compression flag: %d\n", (int)is_compressed);
	}
	else if(chunk_id==PNGID_zTXt) {
		is_compressed = 1;
	}

	// Compression method
	if(chunk_id==PNGID_zTXt || chunk_id==PNGID_iTXt) {
		de_byte cmpr_method;
		cmpr_method = de_getbyte(pos++);
		if(is_compressed && cmpr_method!=0) {
			de_warn(c, "Unsupported text compression type: %d\n", (int)cmpr_method);
			goto done;
		}
	}

	if(chunk_id==PNGID_iTXt) {
		// Language tag
		ret = do_text_field(c, d, &tcc, FIELD_LANG, c->infile, pos, endpos-pos,
			1, 0, DE_ENCODING_ASCII, &field_bytes_consumed);
		if(!ret) goto done;
		pos += field_bytes_consumed;
		pos += 1;

		// Translated keyword
		ret = do_text_field(c, d, &tcc, FIELD_XKEYWORD, c->infile, pos, endpos-pos,
			1, 0, DE_ENCODING_UTF8, &field_bytes_consumed);
		if(!ret) goto done;
		pos += field_bytes_consumed;
		pos += 1;
	}

	if(chunk_id==PNGID_iTXt)
		encoding = DE_ENCODING_UTF8;
	else
		encoding = DE_ENCODING_LATIN1;

	do_text_field(c, d, &tcc, FIELD_MAIN, c->infile, pos, endpos-pos,
		0, is_compressed, encoding, &field_bytes_consumed);

done:
	;
}

static void do_png_IHDR(deark *c, de_int64 pos, de_int64 len)
{
	de_int64 w, h;
	de_byte n;
	const char *name;

	if(len<13) return;
	w = de_getui32be(pos);
	h = de_getui32be(pos+4);
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);

	n = de_getbyte(pos+8);
	de_dbg(c, "depth: %d bits/sample\n", (int)n);

	n = de_getbyte(pos+9);
	switch(n) {
	case 0: name="grayscale"; break;
	case 2: name="truecolor"; break;
	case 3: name="palette"; break;
	case 4: name="grayscale+alpha"; break;
	case 6: name="truecolor+alpha"; break;
	default: name="?";
	}
	de_dbg(c, "color type: %d (%s)\n", (int)n, name);

	n = de_getbyte(pos+12);
	de_dbg(c, "interlaced: %d\n", (int)n);
}

static void do_png_gAMA(deark *c, de_int64 pos, de_int64 len)
{
	de_int64 n;
	n = de_getui32be(pos);
	de_dbg(c, "image gamma: %.5f\n", (double)n / 100000.0);
}

static void do_png_pHYs(deark *c, de_int64 pos, de_int64 len)
{
	de_int64 dx, dy;
	de_byte u;
	const char *name;

	dx = de_getui32be(pos);
	dy = de_getui32be(pos+4);
	de_dbg(c, "density: %dx%d\n", (int)dx, (int)dy);
	u = de_getbyte(pos+8);
	switch(u) {
	case 0: name="unspecified"; break;
	case 1: name="per meter"; break;
	default: name="?";
	}
	de_dbg(c, "units: %d (%s)\n", (int)u, name);
}

static void do_png_tIME(deark *c, de_int64 pos, de_int64 len)
{
	de_int64 yr;
	de_byte mo, da, hr, mi, se;
	struct de_timestamp ts;
	char timestamp_buf[64];

	yr = de_getui16be(pos);
	mo = de_getbyte(pos+2);
	da = de_getbyte(pos+3);
	hr = de_getbyte(pos+4);
	mi = de_getbyte(pos+5);
	se = de_getbyte(pos+6);

	de_make_timestamp(&ts, yr, mo, da, hr, mi, (double)se);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %s\n", timestamp_buf);
}

static void do_png_iccp(deark *c, de_int64 pos, de_int64 len)
{
	de_byte prof_name[81];
	de_int64 prof_name_len;
	de_byte cmpr_type;
	dbuf *f = NULL;
	de_finfo *fi = NULL;

	de_read(prof_name, pos, 80); // One of the next 80 bytes should be a NUL.
	prof_name[80] = '\0';
	prof_name_len = de_strlen((const char*)prof_name);
	if(prof_name_len > 79) return;

	if(prof_name_len>=5) {
		// If the name already ends in ".icc", chop it off so that we don't end
		// up with a double ".icc.icc" file extension.
		if(de_sz_has_ext((const char*)prof_name, "icc")) {
			prof_name[prof_name_len-4] = '\0';
		}
	}

	cmpr_type = de_getbyte(pos + prof_name_len + 1);
	if(cmpr_type!=0) return;

	fi = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_sz(c, fi, (const char*)prof_name, DE_ENCODING_LATIN1);
	f = dbuf_create_output_file(c, "icc", fi, DE_CREATEFLAG_IS_AUX);
	de_uncompress_zlib(c->infile, pos + prof_name_len + 2,
		len - (prof_name_len + 2), f);
	dbuf_close(f);
	de_finfo_destroy(c, fi);
}

static int do_identify_png_internal(deark *c)
{
	de_byte buf[8];
	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_PNG;
	if(!de_memcmp(buf, "\x8b\x4a\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_JNG;
	if(!de_memcmp(buf, "\x8a\x4d\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_MNG;
	return 0;
}

static void de_run_png(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 chunk_data_len;
	de_int32 prev_chunk_id = 0;
	int suppress_idat_dbg = 0;
	struct de_fourcc chunk4cc;

	d = de_malloc(c, sizeof(lctx));

	d->fmt = do_identify_png_internal(c);
	switch(d->fmt) {
	case DE_PNGFMT_PNG: de_declare_fmt(c, "PNG"); break;
	case DE_PNGFMT_JNG: de_declare_fmt(c, "JNG"); break;
	case DE_PNGFMT_MNG: de_declare_fmt(c, "MNG"); break;
	}

	pos = 8;
	while(pos < c->infile->len) {
		chunk_data_len = de_getui32be(pos);
		if(pos + 8 + chunk_data_len + 4 > c->infile->len) break;
		dbuf_read_fourcc(c->infile, pos+4, &chunk4cc, 0);

		if(chunk4cc.id==PNGID_IDAT && suppress_idat_dbg) {
			;
		}
		else if(chunk4cc.id==PNGID_IDAT && prev_chunk_id==PNGID_IDAT && c->debug_level<2) {
			de_dbg(c, "(more IDAT chunks follow)\n");
			suppress_idat_dbg = 1;
		}
		else {
			de_dbg(c, "chunk '%s' at %d dpos=%d dlen=%d\n", chunk4cc.id_printable, (int)pos,
				(int)(pos+8), (int)chunk_data_len);
			if(chunk4cc.id!=PNGID_IDAT) suppress_idat_dbg = 0;
		}

		de_dbg_indent(c, 1);
		switch(chunk4cc.id) {
		case PNGID_IHDR:
			do_png_IHDR(c, pos+8, chunk_data_len);
			break;
		case PNGID_gAMA:
			do_png_gAMA(c, pos+8, chunk_data_len);
			break;
		case PNGID_pHYs:
			do_png_pHYs(c, pos+8, chunk_data_len);
			break;
		case PNGID_tIME:
			do_png_tIME(c, pos+8, chunk_data_len);
			break;
		case PNGID_iCCP:
			do_png_iccp(c, pos+8, chunk_data_len);
			break;
		case PNGID_tEXt:
		case PNGID_zTXt:
		case PNGID_iTXt:
			do_png_text(c, d, chunk4cc.id, pos+8, chunk_data_len);
			break;
		}
		de_dbg_indent(c, -1);
		pos += 8 + chunk_data_len + 4;
		prev_chunk_id = chunk4cc.id;
	}

	de_free(c, d);
}

static int de_identify_png(deark *c)
{
	int x;
	x = do_identify_png_internal(c);
	if(x!=0) return 100;
	return 0;
}

void de_module_png(deark *c, struct deark_module_info *mi)
{
	mi->id = "png";
	mi->desc = "PNG image (resources only)";
	mi->run_fn = de_run_png;
	mi->identify_fn = de_identify_png;
}

