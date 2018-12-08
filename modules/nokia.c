// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Various Nokia phone image formats

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_nol);
DE_DECLARE_MODULE(de_module_ngg);
DE_DECLARE_MODULE(de_module_npm);
DE_DECLARE_MODULE(de_module_nlm);
DE_DECLARE_MODULE(de_module_nsl);

typedef struct localctx_struct {
	i64 w, h;
	int done_flag;
} lctx;

// **************************************************************************
// Nokia Operator Logo (NOL)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void nol_ngg_read_bitmap(deark *c, lctx *d, i64 pos)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 n;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			n = de_getbyte(pos);
			pos++;
			de_bitmap_setpixel_gray(img, i, j, n=='0' ? 255 : 0);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void de_run_nol(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->w = de_getu16le(10);
	d->h = de_getu16le(12);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	nol_ngg_read_bitmap(c, d, 20);
done:
	de_free(c, d);
}

static int de_identify_nol(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "NOL", 3)) return 80;
	return 0;
}

void de_module_nol(deark *c, struct deark_module_info *mi)
{
	mi->id = "nol";
	mi->desc = "Nokia Operator Logo";
	mi->run_fn = de_run_nol;
	mi->identify_fn = de_identify_nol;
}

// **************************************************************************
// Nokia Group Graphic (NGG)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void de_run_ngg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->w = de_getu16le(6);
	d->h = de_getu16le(8);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	nol_ngg_read_bitmap(c, d, 16);
done:
	de_free(c, d);
}

static int de_identify_ngg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "NGG", 3)) return 80;
	return 0;
}

void de_module_ngg(deark *c, struct deark_module_info *mi)
{
	mi->id = "ngg";
	mi->desc = "Nokia Group Graphic";
	mi->run_fn = de_run_ngg;
	mi->identify_fn = de_identify_ngg;
}

// **************************************************************************
// Nokia Picture Message (NPM)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void npm_nlm_read_bitmap(deark *c, lctx *d, i64 pos)
{
	de_convert_and_write_image_bilevel(c->infile, pos, d->w, d->h, (d->w+7)/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

static void de_run_npm(deark *c, de_module_params *mparams)
{
	i64 txt_len;
	i64 pos;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	pos = 4;
	txt_len = (i64)de_getbyte(pos);
	pos += txt_len;
	if(txt_len>0) de_dbg(c, "text length: %d", (int)txt_len);
	// TODO: Maybe write the text to a file.

	pos += 2;

	d->w = (i64)de_getbyte(pos);
	pos += 1;
	d->h = (i64)de_getbyte(pos);
	pos += 1;
	de_dbg_dimensions(c, d->w, d->h);

	pos += 3;
	npm_nlm_read_bitmap(c, d, pos);

	de_free(c, d);
}

static int de_identify_npm(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "NPM", 3)) return 80;
	return 0;
}

void de_module_npm(deark *c, struct deark_module_info *mi)
{
	mi->id = "npm";
	mi->desc = "Nokia Picture Message";
	mi->run_fn = de_run_npm;
	mi->identify_fn = de_identify_npm;
}

// **************************************************************************
// Nokia Logo Manager bitmap (NLM)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void de_run_nlm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u8 imgtype;
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	imgtype = de_getbyte(5);
	switch(imgtype) {
	case 0: s="Operator logo"; break;
	case 1: s="Caller logo"; break;
	case 2: s="Startup logo"; break;
	case 3: s="Picture image logo"; break;
	default: s="unknown";
	}
	de_dbg(c, "image type: %d (%s)", (int)imgtype, s);

	d->w = (i64)de_getbyte(7);
	d->h = (i64)de_getbyte(8);
	de_dbg_dimensions(c, d->w, d->h);

	npm_nlm_read_bitmap(c, d, 10);

	de_free(c, d);
}

static int de_identify_nlm(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "NLM ", 4)) return 80;
	return 0;
}

void de_module_nlm(deark *c, struct deark_module_info *mi)
{
	mi->id = "nlm";
	mi->desc = "Nokia Logo Manager bitmap";
	mi->run_fn = de_run_nlm;
	mi->identify_fn = de_identify_nlm;
}

// **************************************************************************
// Nokia Startup Logo (NSL)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************


static void nsl_read_bitmap(deark *c, lctx *d, i64 pos, i64 len)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 x;

	de_dbg(c, "bitmap at %d, len=%d", (int)pos, (int)len);
	d->done_flag = 1;

	if(len!=504) {
		de_err(c, "Unsupported NSL version (bitmap size=%d)", (int)len);
		goto done;
	}

	d->w = 84;
	d->h = 48;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			x = de_getbyte(pos + (j/8)*d->w + i);
			x = x & (1<<(j%8));
			if(x==0)
				de_bitmap_setpixel_gray(img, i, j, 255);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

#define CODE_FORM  0x464f524dU
#define CODE_NSLD  0x4e534c44U

static int my_nsl_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->chunkctx->chunk4cc.id == CODE_FORM) {
		ictx->is_raw_container = 1;
		return 1;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_NSLD:
		if(ictx->level==1 && !d->done_flag) {
			nsl_read_bitmap(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		}
		break;
	}

	ictx->handled = 1;
	return 1;
}

static void de_run_nsl(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_nsl_chunk_handler;
	ictx->f = c->infile;
	ictx->sizeof_len = 2;

	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_nsl(deark *c)
{
	i64 x;

	// NSL uses a variant of IFF, which is not so easy to identify.
	// (TODO: Write an IFF format detector.)

	if(dbuf_memcmp(c->infile, 0, "FORM", 4)) return 0;

	x = de_getu16be(4);
	if(x+6 != c->infile->len) return 0;

	if(de_input_file_has_ext(c, "nsl")) {
		return 100;
	}
	return 10;
}

void de_module_nsl(deark *c, struct deark_module_info *mi)
{
	mi->id = "nsl";
	mi->desc = "Nokia Startup Logo";
	mi->run_fn = de_run_nsl;
	mi->identify_fn = de_identify_nsl;
}
