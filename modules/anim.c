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

#define CODE_ANHD 0x414e4844U
#define CODE_ANIM 0x414e494dU
#define CODE_BMHD 0x424d4844U
#define CODE_BODY 0x424f4459U
#define CODE_CAMG 0x43414d47U
#define CODE_CMAP 0x434d4150U
#define CODE_CRNG 0x43524e47U
#define CODE_DLTA 0x444c5441U
#define CODE_DPI  0x44504920U
#define CODE_DRNG 0x44524e47U
#define CODE_FORM 0x464f524dU
#define CODE_GRAB 0x47524142U
#define CODE_ILBM 0x494c424dU
#define CODE_TINY 0x54494e59U

#define ANIM_OP_XOR 1

struct img_info {
	i64 width, height;
	//i64 planes_total;
	//i64 rowspan;
	//i64 planespan;
	//i64 bits_per_row_per_plane;
	u8 masking_code;
	//u8 has_hotspot;
	//int hotspot_x, hotspot_y;
	//int is_thumb;
	//const char *filename_token;
};

struct frame_ctx {
	int frame_idx;
	u8 op;
	u8 compression;
	i64 planes;
	i64 transparent_color;
	i64 x_aspect, y_aspect;

	// This struct is for image attributes that might be different in
	// thumbnail images vs. the main image.
	struct img_info main_img;
};

typedef struct localctx_struct {
	int FORM_level; // nesting level of the frames' FORM chunks
	int errflag;
	int num_frames_started;
	int num_frames_finished;
	struct frame_ctx *frctx; // Non-NULL means we're inside a frame
	u8 found_bmhd;
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

static int do_bmhd(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int retval = 0;
	const char *masking_name;
	struct frame_ctx *frctx = d->frctx;

	if(!frctx) goto done;
	if(len<20) {
		de_err(c, "Bad BMHD chunk");
		goto done;
	}

	d->found_bmhd = 1;
	frctx->main_img.width = de_getu16be_p(&pos);
	frctx->main_img.height = de_getu16be_p(&pos);
	de_dbg_dimensions(c, frctx->main_img.width, frctx->main_img.height);
	pos += 4;
	frctx->planes = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)frctx->planes);
	frctx->main_img.masking_code = de_getbyte_p(&pos);
	switch(frctx->main_img.masking_code) {
	case 0: masking_name = "no transparency"; break;
	case 1: masking_name = "1-bit transparency mask"; break;
	case 2: masking_name = "color-key transparency"; break;
	case 3: masking_name = "lasso"; break;
	default: masking_name = "unknown"; break;
	}

	frctx->compression = de_getbyte_p(&pos);
	de_dbg(c, "compression: %d", (int)frctx->compression);

	pos++;
	frctx->transparent_color = de_getu16be_p(&pos);
	de_dbg(c, "masking: %d (%s)", (int)frctx->main_img.masking_code, masking_name);
	if(frctx->main_img.masking_code==2 || frctx->main_img.masking_code==3) {
		de_dbg(c, " color key: %d", (int)frctx->transparent_color);
	}

	frctx->x_aspect = (i64)de_getbyte_p(&pos);
	frctx->y_aspect = (i64)de_getbyte_p(&pos);
	de_dbg(c, "apect ratio: %d, %d", (int)frctx->x_aspect, (int)frctx->y_aspect);

	retval = 1;
done:
	return retval;
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
		d->errflag = 1;
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

	if(!d->frctx && (ictx->level==d->FORM_level+1) && ictx->curr_container_contentstype4cc.id==CODE_ILBM) {
		anim_on_frame_begin(c, d);
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		if(ictx->level>d->FORM_level) break;
		if(d->frctx && ictx->level==d->FORM_level) {
			anim_on_frame_end(c, d);
		}
		ictx->is_std_container = 1;
		break;

	case CODE_BMHD:
		if(!d->frctx) goto done;
		if(!do_bmhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen)) {
			d->errflag = 1;
			goto done;
		}
		break;

	case CODE_ANHD:
		if(!d->frctx) goto done;
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static int my_preprocess_ilbm_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANHD: name="animation header"; break;
	case CODE_BMHD: name="bitmap header"; break;
	case CODE_BODY: name="image data"; break;
	case CODE_CAMG: name="Amiga viewport mode"; break;
	case CODE_CMAP: name="color map"; break;
	case CODE_CRNG: name="color register range info"; break;
	case CODE_DLTA: name="delta-compressed data"; break;
	case CODE_DPI : name="dots/inch"; break;
	case CODE_DRNG: name="color cycle"; break;
	case CODE_GRAB: name="hotspot"; break;
	case CODE_TINY: name="thumbnail"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	else {
		de_fmtutil_default_iff_chunk_identify(c, ictx);
	}
	return 1;
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	u32 id;
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) {
		de_err(c, "Not an IFF file");
		goto done;
	}
	id = (u32)de_getu32be(8);
	switch(id) {
	case CODE_ANIM:
		d->FORM_level = 1;
		break;
	case CODE_ILBM:
		d->FORM_level = 0;
		break;
	default:
		de_err(c, "Not a supported IFF format");
		goto done;
	}

	if(id==CODE_ANIM) {
		de_declare_fmt(c, "IFF-ANIM");
	}

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_anim_chunk_handler;
	ictx->preprocess_chunk_fn = my_preprocess_ilbm_chunk_fn;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

done:
	de_free(c, ictx);
	if(d) {
		if(d->frctx) {
			anim_on_frame_end(c, d);
		}
		de_free(c, d);
	}
}

static int de_identify_anim(deark *c)
{
	u32 id;

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) return 0;
	id = (u32)de_getu32be(8);
	if(id==CODE_ANIM) return 100;
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
