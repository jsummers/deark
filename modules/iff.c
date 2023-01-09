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
#define CODE_INFO  0x494e464fU
#define CODE_LIS4  0x4c495334U
#define CODE_LIST  0x4c495354U
#define CODE_MThd  0x4d546864U
#define CODE_NAME  0x4e414d45U
#define CODE_RBOD  0x52424f44U
#define CODE_RGFX  0x52474658U
#define CODE_RGHD  0x52474844U
#define CODE_XPKF  0x58504b46U
#define CODE_YAFA  0x59414641U

typedef struct localctx_struct {
	int fmt; // FMT_*
	u32 rgfx_cmpr_meth;
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

static void do_RGFX_RGHD(deark *c, lctx *d, struct de_iffctx *ictx)
{
	i64 x1, x2;
	i64 pos = ictx->chunkctx->dpos;
	const char *name;

	if(ictx->chunkctx->dlen<52) goto done;
	pos += 8;
	x1 = dbuf_getu32be_p(ictx->f, &pos);
	x2 = dbuf_getu32be_p(ictx->f, &pos);
	de_dbg_dimensions(c, x1, x2);
	pos += 20;
	d->rgfx_cmpr_meth = (u32)dbuf_getu32be_p(ictx->f, &pos);
	switch(d->rgfx_cmpr_meth) {
	case 0: name="uncompressed"; break;
	case 1: name="XPK"; break;
	case 2: name="ZIP"; break;
	default: name = "?";
	}
	de_dbg(c, "cmpr method: %u (%s)", (UI)d->rgfx_cmpr_meth, name);
	ictx->handled = 1;
done:
	;
}

static void do_RGFX_chunk(deark *c, lctx *d, struct de_iffctx *ictx)
{
	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_RBOD:
		if(d->rgfx_cmpr_meth==1) {
			// Documentation implies that chunk might start with "XPKXPKF", but
			// actual files start more sensibly, with "XPKF".
			do_XPK_data_chunk(c, ictx, "cmpr method");
		}
		break;
	case CODE_RGHD:
		do_RGFX_RGHD(c, d, ictx);
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

static int my_std_container_start_fn(struct de_iffctx *ictx)
{
	deark *c = ictx->c;

	if(ictx->level==0 &&
		ictx->curr_container_fmt4cc.id==CODE_FORM &&
		ictx->main_fmt4cc.id==CODE_FORM)
	{
		const char *fmtname = NULL;

		switch(ictx->main_contentstype4cc.id) {
		case CODE_8SVX: fmtname = "8SVX"; break;
		case CODE_AIFF: fmtname = "AIFF"; break;
		case CODE_YAFA: fmtname = "YAFA"; break;
		case CODE_RGFX: fmtname = "IFF-RGFX"; break;
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
	else if(ictx->main_contentstype4cc.id==CODE_RGFX) {
		do_RGFX_chunk(c, d, ictx);
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
	// TODO: LIST, CAT formats?
	return 0;
}

static void de_help_iff(deark *c)
{
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
