// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// REKO cardset

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_reko);

#define MINCARDS       52
#define MAXCARDS       68
#define MINCARDWIDTH   64
#define MAXCARDWIDTH   100
#define MINCARDHEIGHT  100
#define MAXCARDHEIGHT  150

#define RKFMT_RKP16   1
#define RKFMT_RKP8    2

typedef struct localctx_reko {
	UI fmt; // RKFMT_*
	u8 fatalerrflag;
	u8 need_errmsg;
	i64 bodysize;
	i64 cardsize;
	i64 w, h;
	UI depth;
	i64 numcards;
	i64 hdrsize;
	i64 pal_nbytes;
	de_color pal[256];
} lctx;

static void read_header_pc(deark *c, lctx *d)
{
	i64 pos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 8;

	d->bodysize = de_getu32le_p(&pos);
	de_dbg(c, "body size: %"I64_FMT, d->bodysize);
	d->cardsize = de_getu32le_p(&pos);
	de_dbg(c, "card size: %"I64_FMT, d->cardsize);
	d->w = de_getu16le_p(&pos);
	d->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	d->depth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "depth: %u", d->depth);
	d->numcards = (i64)de_getbyte_p(&pos);
	de_dbg(c, "num cards: %"I64_FMT, d->numcards);
	d->hdrsize = pos;

	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_image_pc8(deark *c, lctx *d, de_bitmap *img, i64 pos1)
{
	i64 pos = pos1;
	size_t k;

	de_dbg(c, "palette at %"I64_FMT, pos);
	de_zeromem(d->pal, sizeof(d->pal));
	for(k=0; k<256; k++) {
		u32 clr_raw;

		clr_raw = (u32)de_getu16le_p(&pos);
		d->pal[k] = de_rgb555_to_888(clr_raw);

	}
	de_dbg(c, "image at %"I64_FMT, pos);
	de_convert_image_paletted(c->infile, pos, 8, d->w, d->pal, img, 0);
}

static void read_image_pc16(deark *c, lctx *d, de_bitmap *img, i64 pos1)
{
	i64 i,j;
	i64 pos = pos1;

	de_dbg(c, "image at %"I64_FMT, pos);
	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			u32 clr_raw;
			de_color clr;

			clr_raw = (u32)de_getu16le_p(&pos);
			clr = de_rgb555_to_888(clr_raw);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void reko_main(deark *c, lctx *d)
{
	i64 pos = d->hdrsize;
	int saved_indent_level;
	i64 cardidx;
	i64 expected_cardsize;
	i64 expected_bodysize;
	de_bitmap *cardimg = NULL;
	de_bitmap *canvas = NULL;
	i64 canvas_cols, canvas_rows;
	i64 canvas_w, canvas_h;
	i64 cxpos_maincards, cypos_maincards;
	i64 cxpos_extracards, cypos_extracards;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "cards at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	if((d->depth!=8 && d->depth!=16) ||
		d->numcards<MINCARDS || d->numcards>MAXCARDS ||
		d->w<MINCARDWIDTH || d->w>MAXCARDWIDTH ||
		d->h<MINCARDHEIGHT || d->h>MAXCARDHEIGHT)
	{
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	expected_cardsize = d->w * d->h * (d->depth/8);
	if(d->cardsize != expected_cardsize) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->depth==8) {
		d->pal_nbytes = 512;
	}
	else {
		d->pal_nbytes = 0;
	}

	expected_bodysize = (4+d->pal_nbytes+d->cardsize) * d->numcards;
	if(d->bodysize != expected_bodysize) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
	if(pos + d->bodysize > c->infile->len) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	canvas_cols = 13;
	canvas_rows = d->numcards % 13;

	cxpos_maincards = 0;
	cypos_maincards = 0;
	cxpos_extracards = 0;
	cypos_extracards = 4;

#define REKO_BORDER 2
	canvas_w = canvas_cols*(d->w+REKO_BORDER)-REKO_BORDER;
	canvas_h = canvas_rows*(d->h+REKO_BORDER)-REKO_BORDER;
	canvas = de_bitmap_create(c, canvas_w, canvas_h, 4);

	cardimg = de_bitmap_create(c, d->w, d->h, 3);

	for(cardidx=0; cardidx<d->numcards; cardidx++) {
		u8 is_main_card;
		i64 cw_raw, ch_raw;
		i64 dstcxpos, dstcypos;
		i64 dstxpos, dstypos;

		de_dbg(c, "card #%"I64_FMT" at %"I64_FMT, cardidx, pos);
		de_dbg_indent(c, 1);
		cw_raw = de_getu16le_p(&pos);
		ch_raw = de_getu16le_p(&pos);
		if((cw_raw+1 != d->w) || (ch_raw+1 != d->h)) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		de_bitmap_rect(cardimg, 0, 0, d->w, d->h, DE_STOCKCOLOR_BLACK, 0);
		if(d->depth==8) {
			read_image_pc8(c, d, cardimg, pos);
		}
		else {
			read_image_pc16(c, d, cardimg, pos);
		}
		pos += d->pal_nbytes;
		pos += d->cardsize;

		is_main_card = (cardidx>=1 && cardidx<=52);
		if(is_main_card) {
			dstcxpos = cxpos_maincards;
			dstcypos = cypos_maincards;
			cypos_maincards++;
			if(cypos_maincards>=4) {
				cypos_maincards = 0;
				cxpos_maincards++;
			}
		}
		else {
			dstcxpos = cxpos_extracards;
			dstcypos = cypos_extracards;
			cxpos_extracards++;
			if(cxpos_extracards>=13) {
				cxpos_extracards = 0;
				cypos_extracards++;
			}
		}
		dstxpos = dstcxpos*(d->w+REKO_BORDER);
		dstypos = dstcypos*(d->h+REKO_BORDER);
		de_bitmap_copy_rect(cardimg, canvas, 0, 0, d->w, d->h, dstxpos, dstypos, 0);
		de_dbg_indent(c, -1);
	}

	de_bitmap_write_to_file(canvas, NULL, 0);

done:
	de_bitmap_destroy(cardimg);
	de_bitmap_destroy(canvas);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_reko(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u8 b;

	d = de_malloc(c, sizeof(lctx));
	b = de_getbyte(0);
	if(b=='P') {
		UI id2;

		id2 = (UI)de_getu16be(6);
		if(id2==0x0000) {
			d->fmt = RKFMT_RKP16;
		}
		else if(id2==0x4420) {
			d->fmt = RKFMT_RKP8;
		}
	}

	if(d->fmt==0) {
		de_err(c, "Unsupported REKO version");
		goto done;
	}

	read_header_pc(c, d);
	if(d->fatalerrflag) goto done;
	reko_main(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported file");
		}
		de_free(c, d);
	}
}

static int de_identify_reko(deark *c)
{
#if 0
	if(!dbuf_memcmp(c->infile, 0, (const void*)"REKO", 4)) {
		return 75;
	}
#endif
	if(!dbuf_memcmp(c->infile, 0, (const void*)"PCREKO", 6)) {
		return 85;
	}
	return 0;
}

void de_module_reko(deark *c, struct deark_module_info *mi)
{
	mi->id = "reko";
	mi->desc = "REKO cardset";
	mi->run_fn = de_run_reko;
	mi->identify_fn = de_identify_reko;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
