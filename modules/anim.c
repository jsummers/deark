// This file is part of Deark.
// Copyright (C) 2017-2020 Jason Summers
// See the file COPYING for terms of use.

// IFF-ANIM animation format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_anim);

// TODO: This code might eventually replace the current ilbm module.
// Until then, expect a lot of duplicated code.

#define CODE_ANHD  0x414e4844U
#define CODE_FORM  0x464f524dU
#define CODE_ILBM  0x494c424dU

#define ANIM_OP_XOR 1

struct frame_ctx {
	int frame_idx;
	u8 op;
};

typedef struct localctx_struct {
	int error_flag;
	int num_frames_started;
	int num_frames_finished;
	struct frame_ctx *frctx; // Non-NULL means we're inside a frame
} lctx;

static const char *anim_get_op_name(u8 op)
{
	const char *name = NULL;

	switch(op) {
	case 0: name="direct"; break;
	case ANIM_OP_XOR: name="XOR"; break;
	case 2: name="long delta"; break;
	case 3: name="short delta"; break;
	case 4: name="short/long delta"; break;
	case 5: name="byte vert. delta"; break;
	case 7: name="short/long vert. delta"; break;
	}
	return name?name:"?";
}

static void anim_destroy_current_frame(deark *c, lctx *d)
{
	if(!d->frctx) return;
	de_free(c, d->frctx);
	d->frctx = NULL;
}

static void do_anim_anhd(deark *c, lctx *d, i64 pos, i64 len)
{
	u8 ileave;
	i64 tmp;
	struct frame_ctx *frctx = d->frctx;

	if(!frctx) return;
	if(len<24) return;

	frctx->op = de_getbyte(pos++);
	de_dbg(c, "operation: %d (%s)", (int)frctx->op, anim_get_op_name(frctx->op));

	if(frctx->op==ANIM_OP_XOR) {
		pos++; // Mask
		pos += 2; // w
		pos += 2; // h
		pos += 2; // x
		pos += 2; // y
	}
	else {
		pos += 9;
	}
	pos+=4; // abstime

	tmp = de_getu32be(pos); // reltime
	de_dbg(c, "reltime: %.5f sec", ((double)tmp)/60.0);
	pos+=4;

	ileave = de_getbyte_p(&pos); // interleave
	de_dbg(c, "interleave: %d", (int)ileave);
	if(ileave != 0) {
		d->error_flag = 1;
	}

	pos++; // pad0

	// bits
	if(frctx->op==4 || frctx->op==5) {
		tmp = de_getu32be(pos);
		de_dbg(c, "flags: 0x%08u", (unsigned int)tmp);
	}
	//pos+=4;
}

static void anim_on_frame_begin(deark *c, lctx *d)
{
	if(d->frctx) return;
	d->num_frames_started++;
	d->frctx = de_malloc(c, sizeof(struct frame_ctx));
	d->frctx->frame_idx = d->num_frames_finished;
	de_dbg(c, "[frame #%d begin]", d->frctx->frame_idx);
}

static void anim_on_frame_end(deark *c, lctx *d)
{
	if(!d->frctx) return;
	de_dbg(c, "[frame #%d end]", d->frctx->frame_idx);
	anim_destroy_current_frame(c, d);
	d->num_frames_finished++;
}

static int my_anim_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	int quitflag = 0;
	int saved_indent_level;
	lctx *d = (lctx*)ictx->userdata;

	de_dbg_indent_save(c, &saved_indent_level);

	// Pretend we can handle all nonstandard chunks
	if(!de_fmtutil_is_standard_iff_chunk(c, ictx, ictx->chunkctx->chunk4cc.id)) {
		ictx->handled = 1;
	}

	if(!d->frctx && ictx->level==2 && ictx->curr_container_contentstype4cc.id==CODE_ILBM) {
		anim_on_frame_begin(c, d);
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANHD:
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_FORM:
		if(ictx->level>1) break;
		if(d->frctx && ictx->level==1) {
			anim_on_frame_end(c, d);
		}
		ictx->is_std_container = 1;
		break;
	}

	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_declare_fmt(c, "ANIM");

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_anim_chunk_handler;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);
	de_free(c, ictx);

	if(d->frctx) {
		anim_on_frame_end(c, d);
	}
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
