// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// IFF (Interchange File Format)
// MIDI

// Note that the IFF parser is actually implemented in fmtutil-iff.c, not here.
// This module uses fmtutil to support unknown IFF formats, and IFF formats
// for which we have very little format-specific logic.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_iff);
DE_DECLARE_MODULE(de_module_midi);
DE_DECLARE_MODULE(de_module_rgfx);
DE_DECLARE_MODULE(de_module_pic_cat_sp);
DE_DECLARE_MODULE(de_module_tplt_cat_sp);

#define FMT_FORM   1
#define FMT_FOR4   4
#define FMT_DJVU   10

#define CODE_8SVX  0x38535658U
#define CODE_AIFF  0x41494646U
#define CODE_ANNO  0x414e4e4fU
#define CODE_AT_T  0x41542654U
#define CODE_BODY  0x424f4459U
#define CODE_CAT   0x43415420U
#define CODE_CAT4  0x43415434U
#define CODE_COMT  0x434f4d54U
#define CODE_FOR4  0x464f5234U
#define CODE_FORM  0x464f524dU
#define CODE_ID3   0x49443320U
#define CODE_ILBM  0x494c424dU
#define CODE_INFO  0x494e464fU
#define CODE_LIS4  0x4c495334U
#define CODE_LIST  0x4c495354U
#define CODE_MThd  0x4d546864U
#define CODE_NAME  0x4e414d45U
#define CODE_XPKF  0x58504b46U
#define CODE_YAFA  0x59414641U

typedef struct localctx_struct {
	int fmt; // FMT_*
	u8 decode_hint; // 0=prefer extracting to decoding
	u8 yafa_XPK;
} lctx;

static void do_text_chunk(deark *c, struct de_iffctx *ictx, const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	// TODO: Sometimes this text is clearly not ASCII, but I've never seen
	// a file with a "CSET" chunk, and I don't know how else I would know
	// the character encoding.
	dbuf_read_to_ucstring_n(c->infile,
		ictx->chunkctx->dpos, ictx->chunkctx->dlen, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_id3_chunk(deark *c, struct de_iffctx *ictx)
{
	if(dbuf_memcmp(ictx->f, ictx->chunkctx->dpos, "ID3", 3)) {
		return;
	}
	de_dbg(c, "ID3v2 data at %"I64_FMT", len=%"I64_FMT, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "id3", "I", ictx->f,
		ictx->chunkctx->dpos, ictx->chunkctx->dlen);
	de_dbg_indent(c, -1);
}

static void do_aiff_comt_chunk(deark *c, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;
	i64 endpos = ictx->chunkctx->dpos + ictx->chunkctx->dlen;
	i64 ncomments;
	i64 i;
	de_ucstring *s = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	ncomments = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "num comments: %d", (int)ncomments);
	s = ucstring_create(c);
	for(i=0; i<ncomments; i++) {
		i64 textlen;

		if(pos+8 >= endpos) goto done;
		de_dbg(c, "comment at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		pos += 4; // timestamp
		pos += 2; // MarkerID
		textlen = dbuf_getu16be_p(ictx->f, &pos);
		if(pos+textlen > endpos) goto done;
		ucstring_empty(s);
		dbuf_read_to_ucstring_n(ictx->f, pos, textlen, 1000, s, 0, DE_ENCODING_ASCII);
		de_dbg(c, "text: \"%s\"", ucstring_getpsz_d(s));
		pos += de_pad_to_2(textlen);
		de_dbg_indent(c, -1);
	}

done:
	ucstring_destroy(s);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_YAFA_INFO(deark *c, lctx *d, struct de_iffctx *ictx)
{
	i64 x1, x2;
	i64 pos = ictx->chunkctx->dpos;
	const char *name;

	if(ictx->chunkctx->dlen<14) goto done;

	x1 = dbuf_getu16be_p(ictx->f, &pos);
	x2 = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg_dimensions(c, x1, x2);
	pos += 2; // depth
	pos += 2; // speed
	x1 = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "frames: %u", (UI)x1);

	x1 = dbuf_getu16be_p(ictx->f, &pos);
	switch(x1) {
	case 0: name="planar"; break;
	case 1: name="planar XPK"; d->yafa_XPK=1; break;
	case 3: name="chunky 8bit XPK"; d->yafa_XPK=1; break;
	case 4: name="chunky 8bit"; break;
	default: name="?";
	}
	de_dbg(c, "frame type: %u (%s)", (UI)x1, name);

	ictx->handled = 1;
done:
	;
}

static void do_XPK_data_chunk(deark *c, struct de_iffctx *ictx, const char *label)
{
	struct de_fourcc tmp4cc;

	if(ictx->chunkctx->dlen<12) goto done;
	if((UI)dbuf_getu32be(ictx->f, ictx->chunkctx->dpos) != CODE_XPKF) goto done;
	dbuf_read_fourcc(ictx->f, ictx->chunkctx->dpos+8, &tmp4cc, 4, 0);
	de_dbg(c, "%s: XPK '%s'", label, tmp4cc.id_dbgstr);
	ictx->handled = 1;
done:
	;
}

// Not a standard IFF ANNO chunk.
static void do_YAFA_ANNO(deark *c, struct de_iffctx *ictx)
{
	i64 tlen;
	i64 pos = ictx->chunkctx->dpos;
	de_ucstring *s = NULL;

	ictx->handled = 1;
	if(ictx->chunkctx->dlen<4) goto done;
	tlen = dbuf_getu32be_p(ictx->f, &pos);
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(ictx->f, pos, tlen, DE_DBG_MAX_STRLEN, s, 0, ictx->input_encoding);
	ucstring_strip_trailing_NUL(s);
	de_dbg(c, "annotation: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
}

static void do_YAFA_chunk(deark *c, lctx *d, struct de_iffctx *ictx)
{
	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANNO:
		do_YAFA_ANNO(c, ictx);
		break;
	case CODE_BODY:
		if(d->yafa_XPK) {
			do_XPK_data_chunk(c, ictx, "cmpr method of 1st frame");
		}
		break;
	case CODE_INFO:
		do_YAFA_INFO(c, d, ictx);
		break;
	}
}

static int is_container_chunk(deark *c, lctx *d, u32 ct)
{
	if(d->fmt==FMT_FOR4) {
		if(ct==CODE_FOR4 || ct==CODE_LIS4 || ct==CODE_CAT4) return 1;
	}
	else {
		if(ct==CODE_FORM || ct==CODE_LIST || ct==CODE_CAT) return 1;
	}
	return 0;
}

static void extract_iff_item(deark *c, lctx *d, struct de_iffctx *ictx, const char *ext)
{
	i64 pos, len;

	pos = ictx->chunkctx->pos;
	// chunkctx->len isn't set correctly yet.
	// (TODO: That's probably something that could be improved.)
	len = 8 + de_pad_to_n(ictx->chunkctx->dlen, ictx->alignment);
	if(pos+len >= ictx->f->len+100) return;
	dbuf_create_file_from_slice(ictx->f, pos, len, ext, NULL, 0);
}

static int my_std_container_start_fn(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->level>0 && d->decode_hint==0 && ictx->chunkctx->parent) {
		if(ictx->chunkctx->parent->chunk4cc.id==CODE_CAT) {
			if(ictx->curr_container_fmt4cc.id==CODE_FORM) {
				// TODO: Extract more formats.
				if(ictx->curr_container_contentstype4cc.id==CODE_ILBM) {
					extract_iff_item(c, d, ictx, "ilbm");
					return 0; // = Stop processing this container
				}
			}
		}
	}

	if(ictx->level==0 &&
		ictx->curr_container_fmt4cc.id==CODE_FORM &&
		ictx->main_fmt4cc.id==CODE_FORM)
	{
		const char *fmtname = NULL;

		switch(ictx->main_contentstype4cc.id) {
		case CODE_8SVX: fmtname = "8SVX"; break;
		case CODE_AIFF: fmtname = "AIFF"; break;
		case CODE_YAFA: fmtname = "YAFA"; break;
		}

		if(fmtname) {
			de_declare_fmt(c, fmtname);
		}
	}

	return 1;
}

static int my_iff_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;

	ictx->is_std_container = is_container_chunk(c, d, ictx->chunkctx->chunk4cc.id);
	if(ictx->is_std_container) goto done;

	if(ictx->main_contentstype4cc.id==CODE_8SVX) {
		switch(ictx->chunkctx->chunk4cc.id) {
		case CODE_NAME:
			// In 8SVX, the NAME chunk means "voice name". In other types
			// of files, it presumably means some other sort of name.
			do_text_chunk(c, ictx, "voice name");
			ictx->handled = 1;
			break;
		}
	}
	else if(ictx->main_contentstype4cc.id==CODE_AIFF) {
		switch(ictx->chunkctx->chunk4cc.id) {
		case CODE_COMT:
			do_aiff_comt_chunk(c, ictx);
			ictx->handled = 1;
			break;
		case CODE_ID3:
			do_id3_chunk(c, ictx);
			ictx->handled = 1;
			break;
		}
	}
	else if(ictx->main_contentstype4cc.id==CODE_YAFA) {
		do_YAFA_chunk(c, d, ictx);
	}

done:
	return 1;
}

static int identify_internal(deark *c, int *pconfidence)
{
	UI n1, n2, n4;

	n1 = (UI)de_getu32be(0);
	n2 = (UI)de_getu32be(4);

	if(n1==CODE_AT_T && n2==CODE_FORM) {
		*pconfidence = 100;
		return FMT_DJVU;
	}

	if(n1==CODE_FOR4) {
		*pconfidence = 25;
		return FMT_FOR4;
	}

	// Try to screen out plain text files.
	if(n2>=0x20202020U && c->infile->len<0x20000000) goto done_nomatch;

	if(n1==CODE_FORM) {
		// Must use a lower confidence than other IFF-like formats
		// (ilbm, anim, cdi_imag, nsl, ...).
		*pconfidence = 9;
		return FMT_FORM;
	}

	if(n1==CODE_CAT) {
		n4 = (UI)de_getu32be(12);
		if(n4==CODE_FORM) {
			*pconfidence = 19;
			return FMT_FORM;
		}
		*pconfidence = 9;
		return FMT_FORM;
	}

	// TODO: LIST. (The problem is that the only LIST files I've found don't seem
	// to conform to the spec.)

done_nomatch:
	*pconfidence = 0;
	return 0;
}

static void de_run_iff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *s;
	i64 pos;
	int confidence = 0;

	d = de_malloc(c, sizeof(lctx));

	ictx = fmtutil_create_iff_decoder(c);
	ictx->has_standard_iff_chunks = 1;
	ictx->alignment = 2; // default

	d->fmt = identify_internal(c, &confidence);

	if(d->fmt==FMT_FOR4) {
		ictx->alignment = 4;
	}

	d->decode_hint = (u8)de_get_ext_option_bool(c, "iff:decode", 0);
	s = de_get_ext_option(c, "iff:align");
	if(s) {
		ictx->alignment = de_atoi(s);
	}

	if(d->fmt==FMT_DJVU) {
		de_declare_fmt(c, "DjVu");
		pos = 4;
	}
	else {
		pos = 0;
	}

	ictx->userdata = (void*)d;
	ictx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	ictx->handle_chunk_fn = my_iff_chunk_handler;
	ictx->on_std_container_start_fn = my_std_container_start_fn;
	ictx->f = c->infile;

	fmtutil_read_iff_format(ictx, pos, c->infile->len - pos);

	fmtutil_destroy_iff_decoder(ictx);
	de_free(c, d);
}

static int de_identify_iff(deark *c)
{
	int confidence = 0;
	int fmt;

	fmt = identify_internal(c, &confidence);
	if(fmt!=0) {
		return confidence;
	}
	return 0;
}

static void de_help_iff(deark *c)
{
	de_msg(c, "-opt iff:decode=1 : Prefer to decode instead of extract");
	de_msg(c, "-opt iff:align=<n> : Assume chunks are padded to an n-byte boundary");
}
void de_module_iff(deark *c, struct deark_module_info *mi)
{
	mi->id = "iff";
	mi->desc = "IFF (Interchange File Format)";
	mi->run_fn = de_run_iff;
	mi->identify_fn = de_identify_iff;
	mi->help_fn = de_help_iff;
}

///// MIDI /////
// MIDI is not IFF, but it's close enough.

static void do_midi_MThd(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	i64 format_field, ntrks_field, division_field;

	if(chunkctx->dlen<6) return;
	ictx->handled = 1;
	format_field = dbuf_getu16be(ictx->f, chunkctx->dpos);
	de_dbg(c, "format: %d", (int)format_field);
	ntrks_field = dbuf_getu16be(ictx->f, chunkctx->dpos+2);
	de_dbg(c, "ntrks: %d", (int)ntrks_field);
	division_field = dbuf_getu16be(ictx->f, chunkctx->dpos+4);
	de_dbg(c, "division: %d", (int)division_field);
}

static int my_midi_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_MThd:
		do_midi_MThd(c, ictx, ictx->chunkctx);
		break;
	}

	return 1;
}

static void de_run_midi(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	ictx = fmtutil_create_iff_decoder(c);
	ictx->alignment = 1;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_midi_chunk_handler;
	ictx->f = c->infile;

	fmtutil_read_iff_format(ictx, 0, c->infile->len);

	fmtutil_destroy_iff_decoder(ictx);
	de_free(c, d);
}

static int de_identify_midi(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "MThd", 4)) {
		return 100;
	}
	return 0;
}

void de_module_midi(deark *c, struct deark_module_info *mi)
{
	mi->id = "midi";
	mi->desc = "MIDI audio";
	mi->run_fn = de_run_midi;
	mi->identify_fn = de_identify_midi;
}

// **************************************************************************
// RGFX (Amiga graphics format)
// **************************************************************************
// TODO: RGFX should probably be moved to another file.

#define CODE_RBOD 0x52424f44U
#define CODE_RCOL 0x52434f4cU
#define CODE_RGFX 0x52474658U
#define CODE_RGHD 0x52474844U
#define CODE_RSCM 0x5253434dU

// (a.k.a. "RMBT..."; suspect a typo in the rgfx.h file)
#define RBMT_BYTECHUNKY8   0x1
#define RBMT_3BYTERGB24    0x2

struct rgfx_ctx {
	u8 errflag;
	u8 need_errmsg;
	u8 found_RGHD;
	u8 found_RCOL;
	u8 found_RBOD;
	u32 rgfx_cmpr_meth;
	i64 width;
	i64 height;
	UI bitmaptype;
	UI viewmode;
	i64 depth;
	i64 pixelbits;
	i64 rowspan;
	dbuf *unc_image;
	de_color pal[256];
};

static void do_RGFX_decompress(deark *c, struct rgfx_ctx *d,
	struct de_iffctx *ictx)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg(c, "[decompressing]");
	de_dbg_indent(c, 1);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = ictx->f;
	dcmpri.pos = ictx->chunkctx->dpos;
	dcmpri.len = ictx->chunkctx->dlen;
	dcmpro.f = d->unc_image;

	if(d->rgfx_cmpr_meth==1) {
		fmtutil_xpk_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	}
	else {
		de_dfilter_set_errorf(c, &dres, NULL, "Unsupported compression method");
	}

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		d->errflag = 1;
		goto done;
	}

done:
	de_dbg_indent(c, -1);
}

static void do_RGFX_RBOD(deark *c, struct rgfx_ctx *d, struct de_iffctx *ictx)
{
	int saved_indent_level;
	int bypp = 0;
	de_bitmap *img = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->found_RBOD) goto done;
	d->found_RBOD = 1;

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	if(d->rgfx_cmpr_meth==0) {
		d->unc_image = dbuf_open_input_subfile(ictx->f, ictx->chunkctx->dpos,
			ictx->chunkctx->dlen);
	}
	else {
		d->unc_image = dbuf_create_membuf(c, 0, 0);
		do_RGFX_decompress(c, d, ictx);
	}
	if(d->errflag) goto done;

	if(d->bitmaptype==RBMT_BYTECHUNKY8 && d->depth==8 && d->pixelbits==8 && d->found_RCOL) {
		bypp = 3;
	}
	else if(d->bitmaptype==RBMT_3BYTERGB24 && d->depth==24 && d->pixelbits==24) {
		bypp = 3;
	}

	if(bypp==0) {
		de_err(c, "Unsupported image type");
		goto done;
	}

	img = de_bitmap_create(c, d->width,  d->height, bypp);

	if(d->depth==8) {
		de_convert_image_paletted(d->unc_image, 0, 8, d->rowspan, d->pal, img, 0);
	}
	else if(d->depth==24) {
		de_convert_image_rgb(d->unc_image, 0, d->rowspan, 3, img, 0);
	}
	else {
		goto done;
	}

	de_bitmap_write_to_fileOLD(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_RGFX_RCOL(deark *c, struct rgfx_ctx *d, struct de_iffctx *ictx)
{
	i64 num_entries;
	i64 pos;
	i64 len;

	d->found_RCOL = 1;

	pos = ictx->chunkctx->dpos;
	len = ictx->chunkctx->dlen;
	if(len==776) { // ???
		pos += 8;
		len -= 8;
	}

	num_entries = len / 3;
	if(num_entries>256) num_entries = 256;
	de_read_simple_palette(c, ictx->f, pos, num_entries, 3,
		d->pal, 256, DE_RDPALTYPE_24BIT, 0);
}

static void do_RGFX_RSCM(deark *c, struct rgfx_ctx *d, struct de_iffctx *ictx)
{
	if(ictx->chunkctx->dlen<4) goto done;
	d->viewmode = (UI)dbuf_getu32be(ictx->f, ictx->chunkctx->dpos);
	// Relevant: https://wiki.amigaos.net/wiki/Display_Database
	de_dbg(c, "ViewMode: 0x%08x", d->viewmode);
done:
	;
}

static void do_RGFX_RGHD(deark *c, struct rgfx_ctx *d, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;
	const char *name;

	if(ictx->chunkctx->dlen<52) goto done;
	pos += 8;
	d->width = dbuf_getu32be_p(ictx->f, &pos);
	d->height = dbuf_getu32be_p(ictx->f, &pos);
	de_dbg_dimensions(c, d->width, d->height);
	pos += 8;
	d->depth = dbuf_getu32be_p(ictx->f, &pos);
	de_dbg(c, "depth: %u", (UI)d->depth);
	d->pixelbits = dbuf_getu32be_p(ictx->f, &pos);
	de_dbg(c, "PixelBits: %u", (UI)d->pixelbits);
	d->rowspan = dbuf_getu32be_p(ictx->f, &pos);
	de_dbg(c, "bytes/line: %u", (UI)d->rowspan);
	d->rgfx_cmpr_meth = (u32)dbuf_getu32be_p(ictx->f, &pos);
	switch(d->rgfx_cmpr_meth) {
	case 0: name="uncompressed"; break;
	case 1: name="XPK"; break;
	case 2: name="ZIP"; break;
	default: name = "?";
	}
	de_dbg(c, "cmpr method: %u (%s)", (UI)d->rgfx_cmpr_meth, name);
	pos += 8; // TODO: aspect
	d->bitmaptype = (UI)dbuf_getu32be_p(ictx->f, &pos);
	de_dbg(c, "BitMapType: 0x%08x", d->bitmaptype);

	d->found_RGHD = 1;
done:
	;
}

static int my_rgfx_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct rgfx_ctx *d = (struct rgfx_ctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		ictx->is_std_container = 1;
		goto done;
	}

	if(ictx->level != 1) goto done;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_RBOD:
		do_RGFX_RBOD(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_RCOL:
		do_RGFX_RCOL(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_RGHD:
		do_RGFX_RGHD(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_RSCM:
		do_RGFX_RSCM(c, d, ictx);
		ictx->handled = 1;
		break;
	}

done:
	if(d->errflag) return 0;
	return 1;
}

static void de_run_rgfx(deark *c, de_module_params *mparams)
{
	struct rgfx_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	de_declare_fmt(c, "IFF-RGFX");
	d = de_malloc(c, sizeof(struct rgfx_ctx));

	ictx = fmtutil_create_iff_decoder(c);
	ictx->alignment = 2;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_rgfx_chunk_handler;
	ictx->f = c->infile;

	fmtutil_read_iff_format(ictx, 0, c->infile->len);

	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Unsupported or bad RGFX file");
		}
		dbuf_close(d->unc_image);
		de_free(c, d);
	}
}

static int de_identify_rgfx(deark *c)
{
	if((u32)de_getu32be(8)!=CODE_RGFX) return 0;
	if((u32)de_getu32be(0)!=CODE_FORM) return 0;
	return 100;
}

void de_module_rgfx(deark *c, struct deark_module_info *mi)
{
	mi->id = "rgfx";
	mi->desc = "RGFX graphics";
	mi->run_fn = de_run_rgfx;
	mi->identify_fn = de_identify_rgfx;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// Spinnaker Picture Catalog (.CAT)
// **************************************************************************

#define CODE_CLIP 0x434c4950U
#define CODE_DIB  0x44494220U
#define CODE_FNAM 0x464e414dU
#define CODE_PATH 0x50415448U
#define CODE_TPLT 0x54504c54U
#define CODE_XXXX 0x58585858U

struct spcat_ctx {
	u8 fmtcode;
	de_ucstring *tmpstr;
	de_ucstring *fname;
};

static void do_spcat_INFO(deark *c, struct spcat_ctx *d, struct de_iffctx *ictx)
{
	if(ictx->chunkctx->dlen<21) goto done;
	ucstring_empty(d->fname);
	dbuf_read_to_ucstring(ictx->f, ictx->chunkctx->dpos, 12, d->fname,
		DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(d->fname));
	// TODO: There's more data in this chunk. Possibly there's a timestamp,
	// but if so, I wasn't able to decode it.
done:
	;
}

static void do_spcat_FNAM(deark *c, struct spcat_ctx *d, struct de_iffctx *ictx)
{
	if(ictx->chunkctx->dlen<1 || ictx->chunkctx->dlen>32) goto done;
	ucstring_empty(d->fname);
	dbuf_read_to_ucstring(ictx->f, ictx->chunkctx->dpos,
		ictx->chunkctx->dlen, d->fname,
		DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	ucstring_strip_trailing_spaces(d->fname);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->fname));
done:
	;
}

static void do_spcat_PATH(deark *c, struct spcat_ctx *d, struct de_iffctx *ictx)
{
	struct de_iffchunkctx *cctx = ictx->chunkctx;

	if(cctx->dlen<1 || cctx->dlen>260) goto done;
	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(ictx->f, ictx->chunkctx->dpos, cctx->dlen, d->tmpstr,
		DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(d->tmpstr));
done:
	;
}

static void do_spcat_DIB(deark *c, struct spcat_ctx *d, struct de_iffctx *ictx)
{
	de_finfo *fi = NULL;
	UI bmihlen;
	de_module_params *mparams = NULL;
	struct de_iffchunkctx *cctx = ictx->chunkctx;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(cctx->dlen<=40) goto done;
	bmihlen = (UI)dbuf_getu32le(ictx->f, cctx->dpos);
	if(bmihlen!=40) goto done;
	fi = de_finfo_create(c);

	if(!c->filenames_from_file) {
		ucstring_empty(d->fname);
	}

	if(ictx->curr_container_contentstype4cc.id == CODE_XXXX) {
		// Possibly the "XXXX" codes mark deleted items, but until I have
		// some good evidence of that, I'll just put "xxxx" in the name.
		if(ucstring_isnonempty(d->fname)) {
			ucstring_append_char(d->fname, '.');
		}
		ucstring_append_sz(d->fname, "xxxx", DE_ENCODING_LATIN1);
	}

	if(ucstring_isnonempty(d->fname)) {
		de_finfo_set_name_from_ucstring(c, fi, d->fname, 0);
	}

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.flags = 0x1;
	mparams->in_params.fi = fi;
	de_run_module_by_id_on_slice(c, "dib", mparams, ictx->f,
		cctx->dpos, cctx->dlen);
done:
	de_free(c, mparams);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int spcat_std_container_start_fn(struct de_iffctx *ictx)
{
	struct spcat_ctx *d = (struct spcat_ctx*)ictx->userdata;

	ucstring_empty(d->fname);
	return 1;
}

static int spcat_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct spcat_ctx *d = (struct spcat_ctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_CAT:
		ictx->is_std_container = 1;
		goto done;
	case CODE_FORM:
		ictx->is_std_container = 1;
		goto done;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_INFO:
		do_spcat_INFO(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_PATH:
		do_spcat_PATH(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_FNAM:
		do_spcat_FNAM(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_DIB:
		do_spcat_DIB(c, d, ictx);
		ictx->handled = 1;
		break;
	}

done:
	return 1;
}

static void run_pic_cat_sp(deark *c, de_module_params *mparams, u8 fmtcode)
{
	struct spcat_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(struct spcat_ctx));
	d->fmtcode = fmtcode;

	ictx = fmtutil_create_iff_decoder(c);
	ictx->alignment = 2;
	ictx->is_le = 1;
	ictx->userdata = (void*)d;
	ictx->input_encoding = de_get_input_encoding(c, NULL,
		DE_ENCODING_WINDOWS1252);
	ictx->handle_chunk_fn = spcat_chunk_handler;
	ictx->on_std_container_start_fn = spcat_std_container_start_fn;
	ictx->f = c->infile;
	d->tmpstr = ucstring_create(c);
	d->fname = ucstring_create(c);

	fmtutil_read_iff_format(ictx, 0, c->infile->len);

	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		ucstring_destroy(d->tmpstr);
		ucstring_destroy(d->fname);
		de_free(c, d);
	}
}

static void de_run_pic_cat_sp(deark *c, de_module_params *mparams)
{
	de_declare_fmt(c, "Spinnaker Picture Catalog");
	run_pic_cat_sp(c, mparams, 0);
}

static int de_identify_pic_cat_sp(deark *c)
{
	UI n;

	if((u32)de_getu32be(8)!=CODE_CLIP) return 0;
	if((u32)de_getu32be(0)!=CODE_CAT) return 0;
	n = (UI)de_getu32le(4);
	if(n > c->infile->len) return 0;
	if((u32)de_getu32be(12)!=CODE_FORM) return 0;
	return 80;
}

void de_module_pic_cat_sp(deark *c, struct deark_module_info *mi)
{
	mi->id = "pic_cat_sp";
	mi->desc = "Picture Catalog (Spinnaker)";
	mi->run_fn = de_run_pic_cat_sp;
	mi->identify_fn = de_identify_pic_cat_sp;
}

// **************************************************************************
// Spinnaker Template Catalog (.CAT)
// **************************************************************************

static void de_run_tplt_cat_sp(deark *c, de_module_params *mparams)
{
	de_declare_fmt(c, "Spinnaker Template Catalog");
	run_pic_cat_sp(c, mparams, 1);
}

static int de_identify_tplt_cat_sp(deark *c)
{
	UI n;

	if((u32)de_getu32be(8)!=CODE_TPLT) return 0;
	if((u32)de_getu32be(0)!=CODE_CAT) return 0;
	n = (UI)de_getu32le(4);
	if(n > c->infile->len) return 0;
	if((u32)de_getu32be(12)!=CODE_FORM) return 0;
	return 80;
}

void de_module_tplt_cat_sp(deark *c, struct deark_module_info *mi)
{
	mi->id = "tplt_cat_sp";
	mi->desc = "Template Catalog (Spinnaker)";
	mi->run_fn = de_run_tplt_cat_sp;
	mi->identify_fn = de_identify_tplt_cat_sp;
}
