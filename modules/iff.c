// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// IFF (Interchange File Format)
// MIDI

// Note that the IFF parser is actually implemented in fmtutil.c, not here.
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
#define CODE_CAT   0x43415420U
#define CODE_CAT4  0x43415434U
#define CODE_FOR4  0x464f5234U
#define CODE_FORM  0x464f524dU
#define CODE_LIS4  0x4c495334U
#define CODE_LIST  0x4c495354U
#define CODE_MThd  0x4d546864U
#define CODE_NAME  0x4e414d45U

typedef struct localctx_struct {
	int fmt; // FMT_*
} lctx;

static void do_text_chunk(deark *c, struct de_iffctx *ictx, const char *name)
{
	de_ucstring *s = NULL;

	ictx->handled = 1;
	s = ucstring_create(c);
	// TODO: Sometimes this text is clearly not ASCII, but I've never seen
	// a file with a "CSET" chunk, and I don't know how else I would know
	// the character encoding.
	dbuf_read_to_ucstring_n(c->infile,
		ictx->chunkctx->chunk_dpos, ictx->chunkctx->chunk_dlen, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static int is_container_chunk(deark *c, lctx *d, de_uint32 ct)
{
	if(d->fmt==FMT_FOR4) {
		if(ct==CODE_FOR4 || ct==CODE_LIS4 || ct==CODE_CAT4) return 1;
	}
	else {
		if(ct==CODE_FORM || ct==CODE_LIST || ct==CODE_CAT) return 1;
	}
	return 0;
}

static int my_iff_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	ictx->is_std_container = is_container_chunk(c, d, ictx->chunkctx->chunk4cc.id);
	if(ictx->is_std_container) goto done;

	if(ictx->main_contentstype4cc.id==CODE_8SVX) {
		switch(ictx->chunkctx->chunk4cc.id) {
		case CODE_NAME:
			// In 8SVX, the NAME chunk means "voice name". In other types
			// of files, it presumably means some other sort of name.
			do_text_chunk(c, ictx, "voice name");
			break;
		}
	}

done:
	return 1;
}

static int identify_internal(deark *c, int *confidence)
{
	de_byte buf[8];

	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, (const de_byte*)"FORM", 4)) {
		if(confidence) *confidence = 9;
		return FMT_FORM;
	}
	if(!de_memcmp(buf, (const de_byte*)"FOR4", 4)) {
		if(confidence) *confidence = 25;
		return FMT_FOR4;
	}
	if(!de_memcmp(buf, (const de_byte*)"AT&TFORM", 8)) {
		if(confidence) *confidence = 100;
		return FMT_DJVU;
	}

	if(confidence) *confidence = 0;
	return 0;
}

static void de_run_iff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *s;
	de_int64 pos;


	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->alignment = 2; // default

	d->fmt = identify_internal(c, NULL);

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
	ictx->handle_chunk_fn = my_iff_chunk_handler;
	ictx->f = c->infile;

	de_fmtutil_read_iff_format(c, ictx, pos, c->infile->len - pos);

	de_free(c, ictx);
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
	de_int64 format_field, ntrks_field, division_field;

	if(chunkctx->chunk_dlen<6) return;
	format_field = dbuf_getui16be(ictx->f, chunkctx->chunk_dpos);
	de_dbg(c, "format: %d", (int)format_field);
	ntrks_field = dbuf_getui16be(ictx->f, chunkctx->chunk_dpos+2);
	de_dbg(c, "ntrks: %d", (int)ntrks_field);
	division_field = dbuf_getui16be(ictx->f, chunkctx->chunk_dpos+4);
	de_dbg(c, "division: %d", (int)division_field);
}

static int my_midi_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_MThd:
		do_midi_MThd(c, ictx, ictx->chunkctx);
		break;
	}
	ictx->handled = 1;
	return 1;
}

static void de_run_midi(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	de_msg(c, "Note: MIDI files can be parsed, but no files can be extracted from them.");
	d = de_malloc(c, sizeof(lctx));

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->alignment = 1;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_midi_chunk_handler;
	ictx->f = c->infile;

	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	de_free(c, ictx);
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
	mi->flags |= DE_MODFLAG_HIDDEN;
}
