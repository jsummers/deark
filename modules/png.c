// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PNG and related formats

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_png);

#define CODE_CgBI 0x43674249U
#define CODE_IDAT 0x49444154U
#define CODE_IEND 0x49454e44U
#define CODE_IHDR 0x49484452U
#define CODE_PLTE 0x504c5445U
#define CODE_acTL 0x6163544cU
#define CODE_bKGD 0x624b4744U
#define CODE_cHRM 0x6348524dU
#define CODE_caNv 0x63614e76U
#define CODE_eXIf 0x65584966U
#define CODE_exIf 0x65784966U
#define CODE_fcTL 0x6663544cU
#define CODE_fdAT 0x66644154U
#define CODE_gAMA 0x67414d41U
#define CODE_hIST 0x68495354U
#define CODE_iCCP 0x69434350U
#define CODE_iTXt 0x69545874U
#define CODE_orNT 0x6f724e54U
#define CODE_pHYs 0x70485973U
#define CODE_sBIT 0x73424954U
#define CODE_sPLT 0x73504c54U
#define CODE_sRGB 0x73524742U
#define CODE_tEXt 0x74455874U
#define CODE_tIME 0x74494d45U
#define CODE_tRNS 0x74524e53U
#define CODE_zTXt 0x7a545874U

#define CODE_BACK 0x4241434bU
#define CODE_BASI 0x42415349U
#define CODE_CLIP 0x434c4950U
#define CODE_CLON 0x434c4f4eU
#define CODE_DBYK 0x4442594bU
#define CODE_DEFI 0x44454649U
#define CODE_DHDR 0x44484452U
#define CODE_DISC 0x44495343U
#define CODE_DROP 0x44524f50U
#define CODE_ENDL 0x454e444cU
#define CODE_FRAM 0x4652414dU
#define CODE_IJNG 0x494a4e47U
#define CODE_IPNG 0x49504e47U
#define CODE_JDAA 0x4a444141U
#define CODE_JDAT 0x4a444154U
#define CODE_JHDR 0x4a484452U
#define CODE_JSEP 0x4a534550U
#define CODE_LOOP 0x4c4f4f50U
#define CODE_MAGN 0x4d41474eU
#define CODE_MEND 0x4d454e44U
#define CODE_MHDR 0x4d484452U
#define CODE_MOVE 0x4d4f5645U
#define CODE_ORDR 0x4f524452U
#define CODE_PAST 0x50415354U
#define CODE_PPLT 0x50504c54U
#define CODE_PROM 0x50524f4dU
#define CODE_SAVE 0x53415645U
#define CODE_SEEK 0x5345454bU
#define CODE_SHOW 0x53484f57U
#define CODE_TERM 0x5445524dU
#define CODE_eXPI 0x65585049U
#define CODE_fPRI 0x66505249U
#define CODE_nEED 0x6e454544U
#define CODE_pHYg 0x70485967U

typedef struct localctx_struct {
#define DE_PNGFMT_PNG 1
#define DE_PNGFMT_JNG 2
#define DE_PNGFMT_MNG 3
	int fmt;
	int is_CgBI;
	u8 color_type;
	const char *fmt_name;
} lctx;

struct text_chunk_ctx {
	int suppress_debugstr;
	int is_xmp;
	int is_im_generic_profile; // ImageMagick-style generic "Raw profile type"
#define PROFILETYPE_8BIM 1
#define PROFILETYPE_IPTC 2
#define PROFILETYPE_XMP  3
#define PROFILETYPE_ICC  4
	int im_generic_profile_type;
	const char *im_generic_profile_type_name;
};

#define FIELD_KEYWORD  1
#define FIELD_LANG     2
#define FIELD_XKEYWORD 3
#define FIELD_MAIN     4

struct chunk_type_info_struct;
struct handler_params;

typedef void (*chunk_handler_fn)(deark *c, lctx *d, struct handler_params *hp);

struct chunk_type_info_struct {
	u32 id;
	// The low 8 bits of flags are reserved, and should be to 0xff.
	// They may someday be used to, for example, make MNG-only chunk table entries.
	u32 flags;
	const char *name;
	chunk_handler_fn handler_fn;
};

struct handler_params {
	i64 dpos;
	i64 dlen;
	const struct de_fourcc *chunk4cc;
	const struct chunk_type_info_struct *cti;
};

static void handler_hexdump(deark *c, lctx *d, struct handler_params *hp)
{
	de_dbg_hexdump(c, c->infile, hp->dpos, hp->dlen, 256, NULL, 0x1);
}

static void on_im_generic_profile_keyword(deark *c, lctx *d,
	struct text_chunk_ctx *tcc, struct de_stringreaderdata *srd)
{
	char typestr[32];

	tcc->is_im_generic_profile = 1;
	tcc->im_generic_profile_type = 0;
	tcc->im_generic_profile_type_name = NULL;
	tcc->suppress_debugstr = 1;

	de_bytes_to_printable_sz((const u8*)(srd->sz+17), de_strlen(srd->sz+17),
		typestr, sizeof(typestr), 0, DE_ENCODING_ASCII);

	if(!de_strcmp(typestr, "8bim")) {
		tcc->im_generic_profile_type = PROFILETYPE_8BIM;
		tcc->im_generic_profile_type_name = "Photoshop";
	}
	else if(!de_strcmp(typestr, "iptc")) {
		tcc->im_generic_profile_type = PROFILETYPE_IPTC;
		tcc->im_generic_profile_type_name = "IPTC";
	}
	else if(!de_strcmp(typestr, "xmp")) {
		tcc->im_generic_profile_type = PROFILETYPE_XMP;
		tcc->im_generic_profile_type_name = "XMP";
	}
	else if(!de_strcmp(typestr, "icc")) {
		tcc->im_generic_profile_type = PROFILETYPE_ICC;
		tcc->im_generic_profile_type_name = "ICC";
	}
	else {
		if(c->extract_level<2) {
			tcc->suppress_debugstr = 0;
		}
	}
}

// Generic (ImageMagick?) profile. Hex-encoded, with three header lines.
static void on_im_generic_profile_main(deark *c, lctx *d,
	struct text_chunk_ctx *tcc, dbuf *inf, i64 pos1, i64 len)
{
	int k;
	i64 pos = pos1;
	i64 dlen;
	int dump_to_file = 0;
	int decode_to_membuf = 0;
	const char *ext = NULL;

	// Skip the first three lines
	for(k=0; k<3; k++) {
		int ret;
		i64 foundpos = 0;
		ret = dbuf_search_byte(inf, 0x0a, pos, pos1+len-pos, &foundpos);
		if(!ret) goto done;
		pos = foundpos+1;
	}
	dlen = pos1+len-pos;

	if(tcc->im_generic_profile_type==PROFILETYPE_XMP) {
		dump_to_file = 1;
		ext = "xmp";
	}
	else if(tcc->im_generic_profile_type==PROFILETYPE_8BIM) {
		decode_to_membuf = 1;
	}
	else if(tcc->im_generic_profile_type==PROFILETYPE_IPTC) {
		if(c->extract_level>=2) {
			dump_to_file = 1;
			ext = "iptc";
		}
		else {
			decode_to_membuf = 1;
		}
	}
	else if(tcc->im_generic_profile_type==PROFILETYPE_ICC) {
		dump_to_file = 1;
		ext = "icc";
	}
	else {
		if(c->extract_level>=2) {
			dump_to_file = 1;
			ext = "profile.bin";
		}
	}

	if(dump_to_file) {
		dbuf *outf;
		outf = dbuf_create_output_file(c, ext?ext:"bin", NULL, DE_CREATEFLAG_IS_AUX);
		de_decode_base16(c, inf, pos, dlen, outf, 0);
		dbuf_close(outf);
	}

	if(decode_to_membuf) {
		dbuf *tmpf;

		tmpf = dbuf_create_membuf(c, 0, 0);
		de_decode_base16(c, inf, pos, dlen, tmpf, 0);

		if(tcc->im_generic_profile_type==PROFILETYPE_8BIM) {
			de_fmtutil_handle_photoshop_rsrc(c, tmpf, 0, tmpf->len, 0x0);
		}
		else if(tcc->im_generic_profile_type==PROFILETYPE_IPTC) {
			de_fmtutil_handle_iptc(c, tmpf, 0, tmpf->len, 0x0);
		}

		dbuf_close(tmpf);
	}

done:
	;
}

// An internal function that does the main work of do_text_field().
// TODO: Clean up the text field processing code. It's gotten too messy.
static int do_unc_text_field(deark *c, lctx *d,
	struct text_chunk_ctx *tcc, int which_field,
	dbuf *srcdbuf, i64 pos, i64 bytes_avail,
	int is_nul_terminated, de_encoding encoding, i64 *bytes_consumed)
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
		i64 bytes_to_scan;

		*bytes_consumed = bytes_avail;

		bytes_to_scan = bytes_avail;
		if(bytes_to_scan>DE_DBG_MAX_STRLEN) bytes_to_scan = DE_DBG_MAX_STRLEN;
		srd = dbuf_read_string(srcdbuf, pos, bytes_to_scan, bytes_to_scan, 0, encoding);
	}

	if(which_field==FIELD_KEYWORD) {
		if(!de_strcmp(srd->sz, "XML:com.adobe.xmp")) {
			tcc->is_xmp = 1;
		}
	}

	switch(which_field) {
	case FIELD_KEYWORD: name="keyword"; break;
	case FIELD_LANG: name="language"; break;
	case FIELD_XKEYWORD: name="translated keyword"; break;
	default: name="text";
	}

	if(which_field==FIELD_MAIN && tcc->is_im_generic_profile) {
		de_dbg(c, "generic profile type: %s",
			tcc->im_generic_profile_type_name?tcc->im_generic_profile_type_name:"?");
	}

	if(!(which_field==FIELD_MAIN && tcc->suppress_debugstr)) {
		de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(srd->str));
	}
	retval = 1;

	if(which_field==FIELD_KEYWORD) {
		if(!de_strncmp(srd->sz, "Raw profile type ", 17)) {
			on_im_generic_profile_keyword(c, d, tcc, srd);
		}
	}

	if(which_field==FIELD_MAIN && tcc->is_im_generic_profile) {
		de_dbg_indent(c, 1);
		on_im_generic_profile_main(c, d, tcc, srcdbuf, pos, bytes_avail);
		de_dbg_indent(c, -1);
		goto done;
	}

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
	i64 pos, i64 bytes_avail,
	int is_nul_terminated, int is_compressed, de_encoding encoding,
	i64 *bytes_consumed)
{
	dbuf *tmpdbuf = NULL;
	int retval = 0;
	i64 bytes_consumed2;

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
	if(!de_decompress_deflate(c->infile, pos, bytes_avail, tmpdbuf, 0, NULL,
		d->is_CgBI ? 0 : DE_DEFLATEFLAG_ISZLIB))
	{
		goto done;
	}

	retval = do_unc_text_field(c, d, tcc,
		which_field, tmpdbuf, 0, tmpdbuf->len,
		0, encoding, &bytes_consumed2);

done:
	dbuf_close(tmpdbuf);
	return retval;
}

static void handler_text(deark *c, lctx *d, struct handler_params *hp)
{
	i64 pos;
	i64 endpos;
	i64 field_bytes_consumed;
	int is_compressed = 0;
	de_encoding encoding;
	int ret;
	struct text_chunk_ctx tcc;

	de_zeromem(&tcc, sizeof(struct text_chunk_ctx));

	endpos = hp->dpos+hp->dlen;
	pos = hp->dpos;

	// Keyword
	ret = do_text_field(c, d, &tcc, FIELD_KEYWORD, pos, endpos-pos,
		1, 0, DE_ENCODING_LATIN1, &field_bytes_consumed);
	if(!ret) goto done;
	pos += field_bytes_consumed;
	pos += 1;

	// Compression flag
	if(hp->chunk4cc->id==CODE_iTXt) {
		is_compressed = (int)de_getbyte(pos++);
		de_dbg(c, "compression flag: %d", (int)is_compressed);
	}
	else if(hp->chunk4cc->id==CODE_zTXt) {
		is_compressed = 1;
	}

	// Compression method
	if(hp->chunk4cc->id==CODE_zTXt || hp->chunk4cc->id==CODE_iTXt) {
		u8 cmpr_method;
		cmpr_method = de_getbyte(pos++);
		if(is_compressed && cmpr_method!=0) {
			de_warn(c, "Unsupported text compression type: %d", (int)cmpr_method);
			goto done;
		}
	}

	if(hp->chunk4cc->id==CODE_iTXt) {
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

	if(hp->chunk4cc->id==CODE_iTXt)
		encoding = DE_ENCODING_UTF8;
	else
		encoding = DE_ENCODING_LATIN1;

	do_text_field(c, d, &tcc, FIELD_MAIN, pos, endpos-pos,
		0, is_compressed, encoding, &field_bytes_consumed);

done:
	;
}

static void handler_CgBI(deark *c, lctx *d, struct handler_params *hp)
{
	d->is_CgBI = 1;
}

static void handler_IHDR(deark *c, lctx *d, struct handler_params *hp)
{
	i64 w, h;
	u8 n;
	const char *name;

	if(hp->dlen<13) return;
	w = de_getu32be(hp->dpos);
	h = de_getu32be(hp->dpos+4);
	de_dbg_dimensions(c, w, h);

	n = de_getbyte(hp->dpos+8);
	de_dbg(c, "depth: %d bits/sample", (int)n);

	d->color_type = de_getbyte(hp->dpos+9);
	switch(d->color_type) {
	case 0: name="grayscale"; break;
	case 2: name="truecolor"; break;
	case 3: name="palette"; break;
	case 4: name="grayscale+alpha"; break;
	case 6: name="truecolor+alpha"; break;
	default: name="?";
	}
	de_dbg(c, "color type: %d (%s)", (int)d->color_type, name);

	n = de_getbyte(hp->dpos+12);
	de_dbg(c, "interlaced: %d", (int)n);
}

static void handler_PLTE(deark *c, lctx *d, struct handler_params *hp)
{
	// pal is a dummy variable, since we don't need to keep the palette.
	// TODO: Maybe de_read_palette_rgb shouldn't require the palette to be returned.
	u32 pal[256];
	i64 nentries;

	nentries = hp->dlen/3;
	de_dbg(c, "num palette entries: %d", (int)nentries);
	de_read_palette_rgb(c->infile, hp->dpos, nentries, 3, pal, DE_ITEMS_IN_ARRAY(pal), 0);
}

static void handler_sPLT(deark *c, lctx *d, struct handler_params *hp)
{
	struct de_stringreaderdata *srd = NULL;
	i64 pos = hp->dpos;
	i64 nbytes_to_scan;
	u8 depth;
	i64 nentries;
	i64 stride;
	i64 i;

	nbytes_to_scan = hp->dlen;
	if(nbytes_to_scan>80) nbytes_to_scan=80;
	srd = dbuf_read_string(c->infile, pos, nbytes_to_scan, 79, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_LATIN1);
	if(!srd->found_nul) goto done;
	de_dbg(c, "palette name: \"%s\"", ucstring_getpsz(srd->str));
	pos += srd->bytes_consumed;

	if(pos >= hp->dpos+hp->dlen) goto done;
	depth = de_getbyte(pos++);
	de_dbg(c, "depth: %d", (int)depth);
	if(depth!=8 && depth!=16) goto done;

	stride = (depth==8) ? 6 : 10;
	nentries = (hp->dpos+hp->dlen-pos)/stride;
	de_dbg(c, "number of entries: %d", (int)nentries);

	if(c->debug_level<2) goto done;
	for(i=0; i<nentries; i++) {
		unsigned int cr, cg, cb, ca, cf;
		if(depth==8) {
			cr = (unsigned int)de_getbyte(pos);
			cg = (unsigned int)de_getbyte(pos+1);
			cb = (unsigned int)de_getbyte(pos+2);
			ca = (unsigned int)de_getbyte(pos+3);
			cf = (unsigned int)de_getu16be(pos+4);
			de_dbg2(c, "pal[%3d] = (%3u,%3u,%3u,A=%u) F=%u",
				(int)i, cr, cg, cb, ca, cf);
		}
		else {
			cr = (unsigned int)de_getu16be(pos);
			cg = (unsigned int)de_getu16be(pos+2);
			cb = (unsigned int)de_getu16be(pos+4);
			ca = (unsigned int)de_getu16be(pos+6);
			cf = (unsigned int)de_getu16be(pos+8);
			de_dbg2(c, "pal[%3d] = (%5u,%5u,%5u,A=%u) F=%u",
				(int)i, cr, cg, cb, ca, cf);
		}
		pos += stride;
	}

done:
	de_destroy_stringreaderdata(c, srd);
}

static void handler_tRNS(deark *c, lctx *d, struct handler_params *hp)
{
	i64 r, g, b;

	if(d->color_type==0) {
		if(hp->dlen<2) return;
		r = de_getu16be(hp->dpos);
		de_dbg(c, "transparent color gray shade: %d", (int)r);
	}
	else if(d->color_type==2) {
		if(hp->dlen<6) return;
		r = de_getu16be(hp->dpos);
		g = de_getu16be(hp->dpos+2);
		b = de_getu16be(hp->dpos+4);
		de_dbg(c, "transparent color: (%d,%d,%d)", (int)r, (int)g, (int)b);
	}
	else if(d->color_type==3) {
		i64 i;
		u8 a;

		de_dbg(c, "number of alpha values: %d", (int)hp->dlen);
		if(c->debug_level<2) return;
		for(i=0; i<hp->dlen && i<256; i++) {
			a = de_getbyte(hp->dpos+i);
			de_dbg2(c, "alpha[%3d] = %d", (int)i, (int)a);
		}
	}
}

static void handler_hIST(deark *c, lctx *d, struct handler_params *hp)
{
	i64 i;
	i64 v;
	i64 nentries = hp->dlen/2;

	de_dbg(c, "number of histogram values: %d", (int)nentries);
	if(c->debug_level<2) return;
	for(i=0; i<nentries; i++) {
		v = de_getu16be(hp->dpos+i*2);
		de_dbg2(c, "freq[%3d] = %d", (int)i, (int)v);
	}
}

static void handler_bKGD(deark *c, lctx *d, struct handler_params *hp)
{
	i64 r, g, b;
	u8 idx;

	if(d->color_type==0 || d->color_type==4) {
		if(hp->dlen<2) return;
		r = de_getu16be(hp->dpos);
		de_dbg(c, "%s gray shade: %d", hp->cti->name, (int)r);
	}
	else if(d->color_type==2 || d->color_type==6) {
		if(hp->dlen<6) return;
		r = de_getu16be(hp->dpos);
		g = de_getu16be(hp->dpos+2);
		b = de_getu16be(hp->dpos+4);
		de_dbg(c, "%s: (%d,%d,%d)", hp->cti->name, (int)r, (int)g, (int)b);
	}
	else if(d->color_type==3) {
		if(hp->dlen<1) return;
		idx = de_getbyte(hp->dpos);
		de_dbg(c, "%s palette index: %d", hp->cti->name, (int)idx);
	}
}

static void handler_gAMA(deark *c, lctx *d, struct handler_params *hp)
{
	i64 n;
	n = de_getu32be(hp->dpos);
	de_dbg(c, "image gamma: %.5f", (double)n / 100000.0);
}

static void handler_pHYs(deark *c, lctx *d, struct handler_params *hp)
{
	i64 dx, dy;
	u8 u;
	const char *name;

	dx = de_getu32be(hp->dpos);
	dy = de_getu32be(hp->dpos+4);
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d", (int)dx, (int)dy);
	u = de_getbyte(hp->dpos+8);
	switch(u) {
	case 0: name="unspecified"; break;
	case 1: name="per meter"; break;
	default: name="?";
	}
	de_dbg(c, "units: %d (%s)", (int)u, name);
}

static void handler_sBIT(deark *c, lctx *d, struct handler_params *hp)
{
	const char *sbname[4];
	i64 i;

	sbname[0] = "red";
	sbname[1] = "green";
	sbname[2] = "blue";
	sbname[3] = "alpha";
	if(d->color_type==0 || d->color_type==4) {
		sbname[0] = "gray";
		sbname[1] = "alpha";
	}

	for(i=0; i<4 && i<hp->dlen; i++) {
		u8 n;
		n = de_getbyte(hp->dpos+i);
		de_dbg(c, "significant %s bits: %d", sbname[i], (int)n);
	}
}

static void handler_tIME(deark *c, lctx *d, struct handler_params *hp)
{
	i64 yr;
	u8 mo, da, hr, mi, se;
	struct de_timestamp ts;
	char timestamp_buf[64];

	yr = de_getu16be(hp->dpos);
	mo = de_getbyte(hp->dpos+2);
	da = de_getbyte(hp->dpos+3);
	hr = de_getbyte(hp->dpos+4);
	mi = de_getbyte(hp->dpos+5);
	se = de_getbyte(hp->dpos+6);

	de_make_timestamp(&ts, yr, mo, da, hr, mi, se);
	ts.tzcode = DE_TZCODE_UTC;
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static void handler_cHRM(deark *c, lctx *d, struct handler_params *hp)
{
	i64 n[8];
	double nd[8];
	size_t i;

	if(hp->dlen<32) return;
	for(i=0; i<8; i++) {
		n[i] = de_getu32be(hp->dpos+4*(i64)i);
		nd[i] = ((double)n[i])/100000.0;
	}
	de_dbg(c, "white point: (%1.5f, %1.5f)", nd[0], nd[1]);
	de_dbg(c, "red        : (%1.5f, %1.5f)", nd[2], nd[3]);
	de_dbg(c, "green      : (%1.5f, %1.5f)", nd[4], nd[5]);
	de_dbg(c, "blue       : (%1.5f, %1.5f)", nd[6], nd[7]);
}

static void handler_sRGB(deark *c, lctx *d, struct handler_params *hp)
{
	u8 intent;
	const char *name;

	if(hp->dlen<1) return;
	intent = de_getbyte(hp->dpos);
	switch(intent) {
	case 0: name="perceptual"; break;
	case 1: name="relative"; break;
	case 2: name="saturation"; break;
	case 3: name="absolute"; break;
	default: name="?";
	}
	de_dbg(c, "rendering intent: %d (%s)", (int)intent, name);
}

static void handler_iccp(deark *c, lctx *d, struct handler_params *hp)
{
	u8 cmpr_type;
	dbuf *f = NULL;
	struct de_stringreaderdata *prof_name_srd = NULL;
	de_finfo *fi = NULL;
	char prof_name2[100];
	size_t prof_name2_strlen;
	i64 pos = hp->dpos;

	prof_name_srd = dbuf_read_string(c->infile, pos, 80, 80,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	if(!prof_name_srd->found_nul) goto done;
	de_dbg(c, "profile name: \"%s\"", ucstring_getpsz_d(prof_name_srd->str));
	pos += prof_name_srd->bytes_consumed;

	// Our working copy, to use as part of the filename.
	de_strlcpy(prof_name2, prof_name_srd->sz, sizeof(prof_name2));
	if(!de_strcasecmp(prof_name2, "icc") ||
		!de_strcasecmp(prof_name2, "icc profile"))
	{
		prof_name2[0] = '\0'; // Ignore generic name.
	}

	prof_name2_strlen = de_strlen(prof_name2);
	if(prof_name2_strlen>=5) {
		if(de_sz_has_ext(prof_name2, "icc")) {
			// If the name already ends in ".icc", chop it off so that we don't end
			// up with a double ".icc.icc" file extension.
			prof_name2[prof_name2_strlen-4] = '\0';
		}
	}

	cmpr_type = de_getbyte_p(&pos);
	if(cmpr_type!=0) return;

	fi = de_finfo_create(c);
	if(c->filenames_from_file && prof_name2[0])
		de_finfo_set_name_from_sz(c, fi, prof_name2, 0, DE_ENCODING_LATIN1);
	f = dbuf_create_output_file(c, "icc", fi, DE_CREATEFLAG_IS_AUX);
	de_decompress_deflate(c->infile, pos, hp->dlen - pos, f, 0, NULL,
		d->is_CgBI ? 0 : DE_DEFLATEFLAG_ISZLIB);

done:
	dbuf_close(f);
	de_finfo_destroy(c, fi);
	de_destroy_stringreaderdata(c, prof_name_srd);
}

static void handler_eXIf(deark *c, lctx *d, struct handler_params *hp)
{
	i64 pos = hp->dpos;
	i64 len = hp->dlen;

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

static void handler_caNv(deark *c, lctx *d, struct handler_params *hp)
{
	i64 x0, x1;

	if(hp->dlen<16) return;
	x0 = de_geti32be(hp->dpos);
	x1 = de_geti32be(hp->dpos+4);
	de_dbg(c, "caNv dimensions: %dx%d", (int)x0, (int)x1);
	x0 = de_geti32be(hp->dpos+8);
	x1 = de_geti32be(hp->dpos+12);
	de_dbg(c, "caNv position: %d,%d", (int)x0, (int)x1);
}

static void handler_orNT(deark *c, lctx *d, struct handler_params *hp)
{
	u8 n;
	if(hp->dlen!=1) return;
	n = de_getbyte(hp->dpos);
	de_dbg(c, "orientation: %d (%s)", (int)n, de_fmtutil_tiff_orientation_name((i64)n));
}

static void do_APNG_seqno(deark *c, lctx *d, i64 pos)
{
	unsigned int n;
	n = (unsigned int)de_getu32be(pos);
	de_dbg(c, "seq. number: %u", n);
}

static void handler_acTL(deark *c, lctx *d, struct handler_params *hp)
{
	unsigned int n;
	i64 pos = hp->dpos;

	if(hp->dlen<8) return;
	n = (unsigned int)de_getu32be_p(&pos);
	de_dbg(c, "num frames: %u", n);
	n = (unsigned int)de_getu32be_p(&pos);
	de_dbg(c, "num plays: %u%s", n, (n==0)?" (infinite)":"");
}

static const char *get_apng_disp_name(u8 t)
{
	switch(t) {
	case 0: return "none"; break;
	case 1: return "background"; break;
	case 2: return "previous"; break;
	}
	return "?";
}

static const char *get_apng_blend_name(u8 t)
{
	switch(t) {
	case 0: return "source"; break;
	case 1: return "over"; break;
	}
	return "?";
}

static void handler_fcTL(deark *c, lctx *d, struct handler_params *hp)
{
	i64 n1, n2;
	i64 pos = hp->dpos;
	u8 b;

	if(hp->dlen<26) return;
	do_APNG_seqno(c, d, pos);
	pos += 4;
	n1 = de_getu32be_p(&pos);
	n2 = de_getu32be_p(&pos);
	de_dbg_dimensions(c, n1, n2);
	n1 = de_getu32be_p(&pos);
	n2 = de_getu32be_p(&pos);
	de_dbg(c, "offset: (%u, %u)", (unsigned int)n1, (unsigned int)n2);
	n1 = de_getu16be_p(&pos);
	n2 = de_getu16be_p(&pos);
	de_dbg(c, "delay: %d/%d seconds", (int)n1, (int)n2);
	b = de_getbyte_p(&pos);
	de_dbg(c, "disposal type: %u (%s)", (unsigned int)b, get_apng_disp_name(b));
	b = de_getbyte_p(&pos);
	de_dbg(c, "blend type: %u (%s)", (unsigned int)b, get_apng_blend_name(b));
}

static void handler_fdAT(deark *c, lctx *d, struct handler_params *hp)
{
	if(hp->dlen<4) return;
	do_APNG_seqno(c, d, hp->dpos);
}

static const struct chunk_type_info_struct chunk_type_info_arr[] = {
	{ CODE_CgBI, 0x00ff, NULL, handler_CgBI },
	{ CODE_IDAT, 0x00ff, NULL, NULL },
	{ CODE_IEND, 0x00ff, NULL, NULL },
	{ CODE_IHDR, 0x00ff, NULL, handler_IHDR },
	{ CODE_PLTE, 0x00ff, "palette", handler_PLTE },
	{ CODE_bKGD, 0x00ff, "background color", handler_bKGD },
	{ CODE_acTL, 0x00ff, "APNG animation control", handler_acTL },
	{ CODE_cHRM, 0x00ff, "chromaticities", handler_cHRM },
	{ CODE_caNv, 0x00ff, "virtual canvas info", handler_caNv },
	{ CODE_eXIf, 0x00ff, NULL, handler_eXIf },
	{ CODE_exIf, 0x00ff, NULL, handler_eXIf },
	{ CODE_fcTL, 0x00ff, "APNG frame control", handler_fcTL },
	{ CODE_fdAT, 0x00ff, "APNG frame data", handler_fdAT },
	{ CODE_gAMA, 0x00ff, "image gamma", handler_gAMA },
	{ CODE_hIST, 0x00ff, "histogram", handler_hIST },
	{ CODE_iCCP, 0x00ff, "ICC profile", handler_iccp },
	{ CODE_iTXt, 0x00ff, NULL, handler_text },
	{ CODE_orNT, 0x00ff, NULL, handler_orNT },
	{ CODE_pHYs, 0x00ff, "physical pixel size", handler_pHYs },
	{ CODE_sBIT, 0x00ff, "significant bits", handler_sBIT },
	{ CODE_sPLT, 0x00ff, "suggested palette", handler_sPLT },
	{ CODE_sRGB, 0x00ff, NULL, handler_sRGB },
	{ CODE_tEXt, 0x00ff, NULL, handler_text },
	{ CODE_tIME, 0x00ff, "last-modification time", handler_tIME },
	{ CODE_tRNS, 0x00ff, "transparency info", handler_tRNS },
	{ CODE_zTXt, 0x00ff, NULL, handler_text },

	{ CODE_BACK, 0x0004, NULL, NULL },
	{ CODE_BASI, 0x0004, "parent object", NULL },
	{ CODE_CLIP, 0x0004, NULL, NULL },
	{ CODE_CLON, 0x0004, NULL, NULL },
	{ CODE_DBYK, 0x0004, NULL, NULL },
	{ CODE_DEFI, 0x0004, NULL, NULL },
	{ CODE_DHDR, 0x0004, "delta-PNG header", NULL },
	{ CODE_DISC, 0x0004, NULL, NULL },
	{ CODE_DROP, 0x0004, NULL, NULL },
	{ CODE_ENDL, 0x0004, NULL, NULL },
	{ CODE_FRAM, 0x0004, NULL, NULL },
	{ CODE_IJNG, 0x0004, NULL, NULL },
	{ CODE_IPNG, 0x0004, NULL, NULL },
	{ CODE_JDAA, 0x00ff, "JNG JPEG-encoded alpha data", NULL },
	{ CODE_JDAT, 0x00ff, "JNG image data", NULL },
	{ CODE_JHDR, 0x00ff, "JNG header", NULL },
	{ CODE_JSEP, 0x00ff, "8-bit/12-bit image separator", NULL },
	{ CODE_LOOP, 0x0004, NULL, NULL },
	{ CODE_MAGN, 0x0004, NULL, NULL },
	{ CODE_MEND, 0x0004, "end of MNG datastream", NULL },
	{ CODE_MHDR, 0x0004, "MNG header", NULL },
	{ CODE_MOVE, 0x0004, NULL, NULL },
	{ CODE_ORDR, 0x0004, NULL, NULL },
	{ CODE_PAST, 0x0004, NULL, NULL },
	{ CODE_PPLT, 0x0004, NULL, NULL },
	{ CODE_PROM, 0x0004, NULL, NULL },
	{ CODE_SAVE, 0x0004, NULL, NULL },
	{ CODE_SEEK, 0x0004, NULL, NULL },
	{ CODE_SHOW, 0x0004, NULL, NULL },
	{ CODE_TERM, 0x0004, NULL, NULL },
	{ CODE_eXPI, 0x0004, NULL, NULL },
	{ CODE_fPRI, 0x0004, NULL, NULL },
	{ CODE_nEED, 0x0004, NULL, NULL },
	{ CODE_pHYg, 0x0004, NULL, NULL }
};

static const struct chunk_type_info_struct *get_chunk_type_info(u32 id)
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
	u8 buf[8];
	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_PNG;
	if(!de_memcmp(buf, "\x8b\x4a\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_JNG;
	if(!de_memcmp(buf, "\x8a\x4d\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_MNG;
	return 0;
}

static void de_run_png(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i32 prev_chunk_id = 0;
	int suppress_idat_dbg = 0;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "signature at %d", 0);
	de_dbg_indent(c, 1);
	d->fmt = do_identify_png_internal(c);
	switch(d->fmt) {
	case DE_PNGFMT_PNG: d->fmt_name = "PNG"; break;
	case DE_PNGFMT_JNG: d->fmt_name = "JNG"; break;
	case DE_PNGFMT_MNG: d->fmt_name = "MNG"; break;
	default: d->fmt_name = "?";
	}
	de_dbg(c, "format: %s", d->fmt_name);
	if(d->fmt>0) {
		de_declare_fmt(c, d->fmt_name);
	}
	de_dbg_indent(c, -1);

	pos = 8;
	while(pos < c->infile->len) {
		struct de_fourcc chunk4cc;
		struct handler_params hp;
		u32 crc;
		char nbuf[80];

		de_zeromem(&hp, sizeof(struct handler_params));

		hp.dlen = de_getu32be(pos);
		if(pos + 8 + hp.dlen + 4 > c->infile->len) break;
		dbuf_read_fourcc(c->infile, pos+4, &chunk4cc, 4, 0x0);

		hp.cti = get_chunk_type_info(chunk4cc.id);

		if(chunk4cc.id==CODE_IDAT && suppress_idat_dbg) {
			;
		}
		else if(chunk4cc.id==CODE_IDAT && prev_chunk_id==CODE_IDAT && c->debug_level<2) {
			de_dbg(c, "(more IDAT chunks follow)");
			suppress_idat_dbg = 1;
		}
		else {
			if(hp.cti) {
				if(hp.cti->name) {
					de_snprintf(nbuf, sizeof(nbuf), " (%s)", hp.cti->name);
				}
				else {
					de_strlcpy(nbuf, "", sizeof(nbuf));
				}
			}
			else {
				de_strlcpy(nbuf, " (?)", sizeof(nbuf));
			}

			de_dbg(c, "chunk '%s'%s at %d dpos=%d dlen=%d",
				chunk4cc.id_dbgstr, nbuf,
				(int)pos, (int)(pos+8), (int)hp.dlen);
			if(chunk4cc.id!=CODE_IDAT) suppress_idat_dbg = 0;
		}

		pos += 8;

		de_dbg_indent(c, 1);

		hp.dpos = pos;
		hp.chunk4cc = &chunk4cc;

		if(hp.cti) {
			if(hp.cti->handler_fn) {
				hp.cti->handler_fn(c, d, &hp);
			}
		}
		else {
			if(c->debug_level>=2) {
				handler_hexdump(c, d, &hp);
			}
		}
		pos += hp.dlen;

		crc = (u32)de_getu32be(pos);
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

