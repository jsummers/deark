// This file is part of Deark.
// Copyright (C) 2017-2020 Jason Summers
// See the file COPYING for terms of use.

// IFF-ANIM animation format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_anim);

#define CODE_ANHD  0x414e4844U
#define CODE_FORM  0x464f524dU

typedef struct animctx_struct {
	int reserved;
} animctx;

static void do_anim_anhd(deark *c, animctx *d, i64 pos, i64 len)
{
	u8 op;
	i64 tmp;

	if(len<24) return;

	op = de_getbyte(pos++);
	de_dbg(c, "operation: %d", (int)op);

	pos++; // Mask
	pos+=2; // w
	pos+=2; // h
	pos+=2; // x
	pos+=2; // y
	pos+=4; // abstime

	tmp = de_getu32be(pos); // reltime
	de_dbg(c, "reltime: %.5f sec", ((double)tmp)/60.0);
	pos+=4;

	pos++; // interleave
	pos++; // pad0

	// bits
	if(op==4 || op==5) {
		tmp = de_getu32be(pos);
		de_dbg(c, "flags: 0x%08u", (unsigned int)tmp);
	}
	//pos+=4;
}

static int my_anim_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	int quitflag = 0;
	int saved_indent_level;
	animctx *d = (animctx*)ictx->userdata;

	de_dbg_indent_save(c, &saved_indent_level);

	// Pretend we can handle all nonstandard chunks
	if(!de_fmtutil_is_standard_iff_chunk(c, ictx, ictx->chunkctx->chunk4cc.id)) {
		ictx->handled = 1;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANHD:
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_FORM:
		if(ictx->level>1) break;
		ictx->is_std_container = 1;
		break;
	}

	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	animctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(animctx));
	de_declare_fmt(c, "ANIM");

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_anim_chunk_handler;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_anim(deark *c)
{
	u8 buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "FORM", 4)) {
		if(!de_memcmp(&buf[8], "ANIM", 4)) return 100;
	}
	return 0;
}

void de_module_anim(deark *c, struct deark_module_info *mi)
{
	mi->id = "anim";
	mi->desc = "IFF-ANIM animation";
	mi->run_fn = de_run_anim;
	mi->identify_fn = de_identify_anim;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
