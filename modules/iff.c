// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// IFF (Interchange File Format)

// TODO: This module might eventually become general enough that it
// can share most of its code with other modules that parse IFF-like
// formats (ilbm, amigaicon, nokia, riff).

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_iff);

#define FMT_FORM   1
#define FMT_FOR4   4
#define FMT_DJVU   10

#define CODE_CAT   0x43415420U
#define CODE_CAT4  0x43415434U
#define CODE_FOR4  0x464f5234U
#define CODE_FORM  0x464f524dU
#define CODE_LIS4  0x4c495334U
#define CODE_LIST  0x4c495354U

typedef struct localctx_struct {
	int fmt; // FMT_*
} lctx;

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

	ictx->is_std_container = is_container_chunk(c, d, ictx->chunk4cc.id);
	return 1;
}

static int identify_internal(deark *c)
{
	de_byte buf[8];

	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, (const de_byte*)"FORM", 4)) {
		return FMT_FORM;
	}
	if(!de_memcmp(buf, (const de_byte*)"FOR4", 4)) {
		return FMT_FOR4;
	}
	if(!de_memcmp(buf, (const de_byte*)"AT&TFORM", 8)) {
		return FMT_DJVU;
	}

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

	d->fmt = identify_internal(c);

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
	int fmt = identify_internal(c);
	if(fmt==FMT_DJVU) {
		return 100;
	}
	if(fmt!=0) {
		return 9;
	}
	// TODO: LIST, CAT formats?
	return 0;
}

static void de_help_iff(deark *c)
{
	de_msg(c, "-opt iff:align=<n> : Assume chunks are padded to an n-byte boundary\n");
}
void de_module_iff(deark *c, struct deark_module_info *mi)
{
	mi->id = "iff";
	mi->desc = "IFF (Interchange File Format)";
	mi->run_fn = de_run_iff;
	mi->identify_fn = de_identify_iff;
	mi->help_fn = de_help_iff;
}
