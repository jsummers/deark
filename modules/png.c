// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PNG and related formats

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_png);

#define PNGID_CgBI 0x43674249U
#define PNGID_IDAT 0x49444154U
#define PNGID_IHDR 0x49484452U
#define PNGID_PLTE 0x504c5445U
#define PNGID_bKGD 0x624b4744U
#define PNGID_cHRM 0x6348524dU
#define PNGID_eXIf 0x65584966U
#define PNGID_gAMA 0x67414d41U
#define PNGID_hIST 0x68495354U
#define PNGID_iCCP 0x69434350U
#define PNGID_iTXt 0x69545874U
#define PNGID_pHYs 0x70485973U
#define PNGID_sBIT 0x73424954U
#define PNGID_sPLT 0x73504c54U
#define PNGID_sRGB 0x73524742U
#define PNGID_tEXt 0x74455874U
#define PNGID_tIME 0x74494d45U
#define PNGID_tRNS 0x74524e53U
#define PNGID_zTXt 0x7a545874U

typedef struct localctx_struct {
#define DE_PNGFMT_PNG 1
#define DE_PNGFMT_JNG 2
#define DE_PNGFMT_MNG 3
	int fmt;
	int is_CgBI;
	de_byte color_type;
} lctx;

struct text_chunk_ctx {
	int is_xmp;
};

#define FIELD_KEYWORD  1
#define FIELD_LANG     2
#define FIELD_XKEYWORD 3
#define FIELD_MAIN     4

struct chunk_type_info_struct;

typedef void (*chunk_decoder_fn)(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 dlen);

struct chunk_type_info_struct {
	de_uint32 id;
	de_uint32 flags;
	const char *name;
	chunk_decoder_fn decoder_fn;
};

// An internal function that does the main work of do_text_field().
static int do_unc_text_field(deark *c, lctx *d,
	struct text_chunk_ctx *tcc, int which_field,
	dbuf *srcdbuf, de_int64 pos, de_int64 bytes_avail,
	int is_nul_terminated, int encoding, de_int64 *bytes_consumed)
{
	const char *name;
	int retval = 0;
	struct de_stringreaderdata *srd = NULL;

	*bytes_consumed = 0;
	if(bytes_avail<0) return 0;

	if(which_field==FIELD_MAIN && tcc->is_xmp) {
		// The main field is never NUL terminated, so we can do this right away.
		dbuf_create_file_from_slice(srcdbuf, pos, bytes_avail, "xmp",
			NULL, DE_CREATEFLAG_IS_AUX);
		retval = 1;
		goto done;
	}

	if(is_nul_terminated) {
		srd = dbuf_read_string(srcdbuf, pos, bytes_avail, DE_DBG_MAX_STRLEN,
			DE_CONVFLAG_STOP_AT_NUL, encoding);

		if(!srd->found_nul) goto done;
		*bytes_consumed = srd->bytes_consumed - 1;
	}
	else {
		de_int64 bytes_to_scan;

		*bytes_consumed = bytes_avail;

		bytes_to_scan = bytes_avail;
		if(bytes_to_scan>DE_DBG_MAX_STRLEN) bytes_to_scan = DE_DBG_MAX_STRLEN;
		srd = dbuf_read_string(srcdbuf, pos, bytes_to_scan, bytes_to_scan, 0, encoding);
	}

	if(which_field==FIELD_KEYWORD) {
		// This is a bit of a hack. If there are any other special keywords we need
		// to look for, we should do something better.
		if(!de_strcmp((const char*)srd->sz, "XML:com.adobe.xmp")) {
			tcc->is_xmp = 1;
		}
	}

	switch(which_field) {
	case FIELD_KEYWORD: name="keyword"; break;
	case FIELD_LANG: name="language"; break;
	case FIELD_XKEYWORD: name="translated keyword"; break;
	default: name="text";
	}

	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(srd->str));
	retval = 1;

done:
	de_destroy_stringreaderdata(c, srd);
	return retval;
}

// Read and process the keyword, language, translated keyword, or main text
// field of a tEXt/zTXt/iTXt chunk.
// 'bytes_consumed' does not include the NUL separator/terminator.
// This is a wrapper that first decompresses the field if necessary.
static int do_text_field(deark *c, lctx *d,
	struct text_chunk_ctx *tcc, int which_field,
	de_int64 pos, de_int64 bytes_avail,
	int is_nul_terminated, int is_compressed, int encoding,
	de_int64 *bytes_consumed)
{
	dbuf *tmpdbuf = NULL;
	int retval = 0;
	de_int64 bytes_consumed2;

	if(!is_compressed) {
		retval = do_unc_text_field(c, d, tcc,
			which_field, c->infile, pos, bytes_avail,
			is_nul_terminated, encoding, bytes_consumed);
		goto done;
	}

	// Decompress to a membuf, then call do_unc_text_field() with that membuf.
	// Note that a compressed field cannot be NUL-terminated.
	*bytes_consumed = bytes_avail;

	tmpdbuf = dbuf_create_membuf(c, 0, 0);
	if(!de_uncompress_zlib(c->infile, pos, bytes_avail, tmpdbuf)) {
		goto done;
	}

	retval = do_unc_text_field(c, d, tcc,
		which_field, tmpdbuf, 0, tmpdbuf->len,
		0, encoding, &bytes_consumed2);

done:
	dbuf_close(tmpdbuf);
	return retval;
}

static void do_png_text(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos1, de_int64 len)
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
	ret = do_text_field(c, d, &tcc, FIELD_KEYWORD, pos, endpos-pos,
		1, 0, DE_ENCODING_LATIN1, &field_bytes_consumed);
	if(!ret) goto done;
	pos += field_bytes_consumed;
	pos += 1;

	// Compression flag
	if(chunk4cc->id==PNGID_iTXt) {
		is_compressed = (int)de_getbyte(pos++);
		de_dbg(c, "compression flag: %d", (int)is_compressed);
	}
	else if(chunk4cc->id==PNGID_zTXt) {
		is_compressed = 1;
	}

	// Compression method
	if(chunk4cc->id==PNGID_zTXt || chunk4cc->id==PNGID_iTXt) {
		de_byte cmpr_method;
		cmpr_method = de_getbyte(pos++);
		if(is_compressed && cmpr_method!=0) {
			de_warn(c, "Unsupported text compression type: %d", (int)cmpr_method);
			goto done;
		}
	}

	if(chunk4cc->id==PNGID_iTXt) {
		// Language tag
		ret = do_text_field(c, d, &tcc, FIELD_LANG, pos, endpos-pos,
			1, 0, DE_ENCODING_ASCII, &field_bytes_consumed);
		if(!ret) goto done;
		pos += field_bytes_consumed;
		pos += 1;

		// Translated keyword
		ret = do_text_field(c, d, &tcc, FIELD_XKEYWORD, pos, endpos-pos,
			1, 0, DE_ENCODING_UTF8, &field_bytes_consumed);
		if(!ret) goto done;
		pos += field_bytes_consumed;
		pos += 1;
	}

	if(chunk4cc->id==PNGID_iTXt)
		encoding = DE_ENCODING_UTF8;
	else
		encoding = DE_ENCODING_LATIN1;

	do_text_field(c, d, &tcc, FIELD_MAIN, pos, endpos-pos,
		0, is_compressed, encoding, &field_bytes_consumed);

done:
	;
}

static void do_png_CgBI(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	d->is_CgBI = 1;
}

static void do_png_IHDR(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 w, h;
	de_byte n;
	const char *name;

	if(len<13) return;
	w = de_getui32be(pos);
	h = de_getui32be(pos+4);
	de_dbg_dimensions(c, w, h);

	n = de_getbyte(pos+8);
	de_dbg(c, "depth: %d bits/sample", (int)n);

	d->color_type = de_getbyte(pos+9);
	switch(d->color_type) {
	case 0: name="grayscale"; break;
	case 2: name="truecolor"; break;
	case 3: name="palette"; break;
	case 4: name="grayscale+alpha"; break;
	case 6: name="truecolor+alpha"; break;
	default: name="?";
	}
	de_dbg(c, "color type: %d (%s)", (int)d->color_type, name);

	n = de_getbyte(pos+12);
	de_dbg(c, "interlaced: %d", (int)n);
}

static void do_png_PLTE(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	// pal is a dummy variable, since we don't need to keep the palette.
	// TODO: Maybe de_read_palette_rgb shouldn't require the palette to be returned.
	de_uint32 pal[256];
	de_int64 nentries;

	nentries = len/3;
	de_dbg(c, "num palette entries: %d", (int)nentries);
	de_read_palette_rgb(c->infile, pos, nentries, 3, pal, DE_ITEMS_IN_ARRAY(pal), 0);
}

static void do_png_sPLT(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos1, de_int64 len)
{
	struct de_stringreaderdata *srd = NULL;
	de_int64 pos = pos1;
	de_int64 nbytes_to_scan;
	de_byte depth;
	de_int64 nentries;
	de_int64 stride;
	de_int64 i;

	nbytes_to_scan = len;
	if(nbytes_to_scan>80) nbytes_to_scan=80;
	srd = dbuf_read_string(c->infile, pos, nbytes_to_scan, 79, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_LATIN1);
	if(!srd->found_nul) goto done;
	de_dbg(c, "palette name: \"%s\"", ucstring_getpsz(srd->str));
	pos += srd->bytes_consumed;

	if(pos >= pos1+len) goto done;
	depth = de_getbyte(pos++);
	de_dbg(c, "depth: %d", (int)depth);
	if(depth!=8 && depth!=16) goto done;

	stride = (depth==8) ? 6 : 10;
	nentries = (pos1+len-pos)/stride;
	de_dbg(c, "number of entries: %d", (int)nentries);

	if(c->debug_level<2) goto done;
	for(i=0; i<nentries; i++) {
		unsigned int cr, cg, cb, ca, cf;
		if(depth==8) {
			cr = (unsigned int)de_getbyte(pos);
			cg = (unsigned int)de_getbyte(pos+1);
			cb = (unsigned int)de_getbyte(pos+2);
			ca = (unsigned int)de_getbyte(pos+3);
			cf = (unsigned int)de_getui16be(pos+4);
			de_dbg2(c, "pal[%3d] = (%3u,%3u,%3u,A=%u) F=%u",
				(int)i, cr, cg, cb, ca, cf);
		}
		else {
			cr = (unsigned int)de_getui16be(pos);
			cg = (unsigned int)de_getui16be(pos+2);
			cb = (unsigned int)de_getui16be(pos+4);
			ca = (unsigned int)de_getui16be(pos+6);
			cf = (unsigned int)de_getui16be(pos+8);
			de_dbg2(c, "pal[%3d] = (%5u,%5u,%5u,A=%u) F=%u",
				(int)i, cr, cg, cb, ca, cf);
		}
		pos += stride;
	}

done:
	de_destroy_stringreaderdata(c, srd);
}

static void do_png_tRNS(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 r, g, b;

	if(d->color_type==0) {
		if(len<2) return;
		r = de_getui16be(pos);
		de_dbg(c, "transparent color gray shade: %d", (int)r);
	}
	else if(d->color_type==2) {
		if(len<6) return;
		r = de_getui16be(pos);
		g = de_getui16be(pos+2);
		b = de_getui16be(pos+4);
		de_dbg(c, "transparent color: (%d,%d,%d)", (int)r, (int)g, (int)b);
	}
	else if(d->color_type==3) {
		de_int64 i;
		de_byte a;

		de_dbg(c, "number of alpha values: %d", (int)len);
		if(c->debug_level<2) return;
		for(i=0; i<len && i<256; i++) {
			a = de_getbyte(pos+i);
			de_dbg2(c, "alpha[%3d] = %d", (int)i, (int)a);
		}
	}
}

static void do_png_hIST(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 i;
	de_int64 v;
	de_int64 nentries = len/2;

	de_dbg(c, "number of histogram values: %d", (int)nentries);
	if(c->debug_level<2) return;
	for(i=0; i<nentries; i++) {
		v = de_getui16be(pos+i*2);
		de_dbg2(c, "freq[%3d] = %d", (int)i, (int)v);
	}
}

static void do_png_bKGD(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 r, g, b;
	de_byte idx;

	if(d->color_type==0 || d->color_type==4) {
		if(len<2) return;
		r = de_getui16be(pos);
		de_dbg(c, "%s gray shade: %d", cti->name, (int)r);
	}
	else if(d->color_type==2 || d->color_type==6) {
		if(len<6) return;
		r = de_getui16be(pos);
		g = de_getui16be(pos+2);
		b = de_getui16be(pos+4);
		de_dbg(c, "%s: (%d,%d,%d)", cti->name, (int)r, (int)g, (int)b);
	}
	else if(d->color_type==3) {
		if(len<1) return;
		idx = de_getbyte(pos);
		de_dbg(c, "%s palette index: %d", cti->name, (int)idx);
	}
}

static void do_png_gAMA(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 n;
	n = de_getui32be(pos);
	de_dbg(c, "image gamma: %.5f", (double)n / 100000.0);
}

static void do_png_pHYs(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 dx, dy;
	de_byte u;
	const char *name;

	dx = de_getui32be(pos);
	dy = de_getui32be(pos+4);
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d", (int)dx, (int)dy);
	u = de_getbyte(pos+8);
	switch(u) {
	case 0: name="unspecified"; break;
	case 1: name="per meter"; break;
	default: name="?";
	}
	de_dbg(c, "units: %d (%s)", (int)u, name);
}

static void do_png_sBIT(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	const char *sbname[4];
	de_int64 i;

	sbname[0] = "red";
	sbname[1] = "green";
	sbname[2] = "blue";
	sbname[3] = "alpha";
	if(d->color_type==0 || d->color_type==4) {
		sbname[0] = "gray";
		sbname[1] = "alpha";
	}

	for(i=0; i<4 && i<len; i++) {
		de_byte n;
		n = de_getbyte(pos+i);
		de_dbg(c, "significant %s bits: %d", sbname[i], (int)n);
	}
}

static void do_png_tIME(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
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

	de_make_timestamp(&ts, yr, mo, da, hr, mi, (double)se, 0);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static void do_png_cHRM(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_int64 n[8];
	double nd[8];
	size_t i;

	if(len<32) return;
	for(i=0; i<8; i++) {
		n[i] = de_getui32be(pos+4*i);
		nd[i] = ((double)n[i])/100000.0;
	}
	de_dbg(c, "white point: (%1.5f, %1.5f)", nd[0], nd[1]);
	de_dbg(c, "red        : (%1.5f, %1.5f)", nd[2], nd[3]);
	de_dbg(c, "green      : (%1.5f, %1.5f)", nd[4], nd[5]);
	de_dbg(c, "blue       : (%1.5f, %1.5f)", nd[6], nd[7]);
}

static void do_png_sRGB(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	de_byte intent;
	const char *name;

	if(len<1) return;
	intent = de_getbyte(pos);
	switch(intent) {
	case 0: name="perceptual"; break;
	case 1: name="relative"; break;
	case 2: name="saturation"; break;
	case 3: name="absolute"; break;
	default: name="?";
	}
	de_dbg(c, "rendering intent: %d (%s)", (int)intent, name);
}

static void do_png_iccp(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
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
	if(d->is_CgBI) {
		de_int64 bytes_consumed = 0;
		de_uncompress_deflate(c->infile, pos + prof_name_len + 2,
			len - (prof_name_len + 2), f, &bytes_consumed);
	}
	else {
		de_uncompress_zlib(c->infile, pos + prof_name_len + 2,
			len - (prof_name_len + 2), f);
	}
	dbuf_close(f);
	de_finfo_destroy(c, fi);
}

static void do_png_eXIf(deark *c, lctx *d,
	const struct de_fourcc *chunk4cc, const struct chunk_type_info_struct *cti,
	de_int64 pos, de_int64 len)
{
	if(len>=6 && !dbuf_memcmp(c->infile, pos, "Exif\0", 5)) {
		// Some versions of the PNG-Exif proposal had the Exif data starting with
		// an "Exif\0\0" identifier, and some files were created in this format.
		// So we'll support it.
		de_dbg(c, "[skipping JPEG app ID]");
		pos += 6;
		len -= 6;
	}
	if(len<8) return;

	de_fmtutil_handle_exif(c, pos, len);
}

static const struct chunk_type_info_struct chunk_type_info_arr[] = {
	{ PNGID_CgBI, 0, NULL, do_png_CgBI },
	{ PNGID_IHDR, 0, NULL, do_png_IHDR },
	{ PNGID_PLTE, 0, "palette", do_png_PLTE },
	{ PNGID_bKGD, 0, "background color", do_png_bKGD },
	{ PNGID_cHRM, 0, "chromaticities", do_png_cHRM },
	{ PNGID_eXIf, 0, NULL, do_png_eXIf },
	{ PNGID_gAMA, 0, "image gamma", do_png_gAMA },
	{ PNGID_hIST, 0, "histogram", do_png_hIST },
	{ PNGID_iCCP, 0, "ICC profile", do_png_iccp },
	{ PNGID_iTXt, 0, NULL, do_png_text },
	{ PNGID_pHYs, 0, "physical pixel size", do_png_pHYs },
	{ PNGID_sBIT, 0, "significant bits", do_png_sBIT },
	{ PNGID_sPLT, 0, "suggested palette", do_png_sPLT },
	{ PNGID_sRGB, 0, NULL, do_png_sRGB },
	{ PNGID_tEXt, 0, NULL, do_png_text },
	{ PNGID_tIME, 0, "last-modification time", do_png_tIME },
	{ PNGID_tRNS, 0, "transparency info", do_png_tRNS },
	{ PNGID_zTXt, 0, NULL, do_png_text }
};

static const struct chunk_type_info_struct *get_chunk_type_info(de_uint32 id)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(chunk_type_info_arr); i++) {
		if(id == chunk_type_info_arr[i].id) {
			return &chunk_type_info_arr[i];
		}
	}
	return NULL;
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
	const struct chunk_type_info_struct *cti;

	d = de_malloc(c, sizeof(lctx));

	d->fmt = do_identify_png_internal(c);
	switch(d->fmt) {
	case DE_PNGFMT_PNG: de_declare_fmt(c, "PNG"); break;
	case DE_PNGFMT_JNG: de_declare_fmt(c, "JNG"); break;
	case DE_PNGFMT_MNG: de_declare_fmt(c, "MNG"); break;
	}

	pos = 8;
	while(pos < c->infile->len) {
		de_uint32 crc;
		char nbuf[80];

		chunk_data_len = de_getui32be(pos);
		if(pos + 8 + chunk_data_len + 4 > c->infile->len) break;
		dbuf_read_fourcc(c->infile, pos+4, &chunk4cc, 0);

		cti = get_chunk_type_info(chunk4cc.id);

		if(chunk4cc.id==PNGID_IDAT && suppress_idat_dbg) {
			;
		}
		else if(chunk4cc.id==PNGID_IDAT && prev_chunk_id==PNGID_IDAT && c->debug_level<2) {
			de_dbg(c, "(more IDAT chunks follow)");
			suppress_idat_dbg = 1;
		}
		else {
			if(cti && cti->name) {
				de_snprintf(nbuf, sizeof(nbuf), " (%s)", cti->name);
			}
			else {
				de_strlcpy(nbuf, "", sizeof(nbuf));
			}

			de_dbg(c, "chunk '%s'%s at %d dpos=%d dlen=%d",
				chunk4cc.id_printable, nbuf,
				(int)pos, (int)(pos+8), (int)chunk_data_len);
			if(chunk4cc.id!=PNGID_IDAT) suppress_idat_dbg = 0;
		}

		pos += 8;

		de_dbg_indent(c, 1);
		if(cti && cti->decoder_fn) {
			cti->decoder_fn(c, d, &chunk4cc, cti, pos, chunk_data_len);
		}
		pos += chunk_data_len;

		crc = (de_uint32)de_getui32be(pos);
		de_dbg2(c, "crc32 (reported): 0x%08x", (unsigned int)crc);
		pos += 4;

		de_dbg_indent(c, -1);

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
	mi->desc = "PNG image";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_png;
	mi->identify_fn = de_identify_png;
}

