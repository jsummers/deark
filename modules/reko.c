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
#define RKFMT_AMIGA   10

typedef struct localctx_reko {
	u8 fmt; // RKFMT_*
	u8 is_pc;
	u8 fatalerrflag;
	u8 need_errmsg;
	u8 suppress_size_warnings;
	i64 bodysize;
	i64 cardsize;
	i64 w, h;
	i64 amiga_row_stride, amiga_plane_stride;
	UI depth_pixel;
	UI depth_color;
	UI camg_mode;
	u8 ham_flag;
	i64 numcards;
	i64 hdrsize;
	i64 globalpal_nbytes;
	i64 localpal_nbytes;
	de_color pal[256];
} lctx;

static void read_header_amiga(deark *c, lctx *d)
{
	i64 pos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 4;

	d->bodysize = de_getu32be_p(&pos);
	de_dbg(c, "body size: %"I64_FMT, d->bodysize);
	d->cardsize = de_getu32be_p(&pos);
	de_dbg(c, "card size: %"I64_FMT, d->cardsize);
	d->h = de_getu16be_p(&pos);
	d->w = de_getu16be_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	if(d->w != 88) {
		de_warn(c, "Unexpected width %d; assuming it should be 88", (int)d->w);
		d->w = 88;
		d->suppress_size_warnings = 1;
	}
	d->camg_mode = (UI)de_getu32be_p(&pos);
	de_dbg(c, "CAMG mode: 0x%08x", d->camg_mode);
	if(d->camg_mode & 0x0800) d->ham_flag = 1;
	de_dbg_indent(c, 1);
	de_dbg(c, "HAM: %u", (UI)d->ham_flag);
	de_dbg_indent(c, -1);
	d->depth_pixel = (UI)de_getbyte_p(&pos);
	de_dbg(c, "depth: %u", d->depth_pixel);
	d->numcards = (i64)de_getbyte_p(&pos);
	de_dbg(c, "num cards: %"I64_FMT, d->numcards);
	d->hdrsize = pos;

	if(d->depth_pixel<1 || d->depth_pixel>8) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	d->depth_color = d->depth_pixel;
	if(d->ham_flag) {
		if(d->depth_pixel!=6 && d->depth_pixel!=8) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		d->depth_color -= 2;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_palette_amiga(deark *c, lctx *d)
{
	i64 pos;
	i64 numentries;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = d->hdrsize;
	de_dbg(c, "global palette at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	numentries = 1LL<<d->depth_color;
	d->globalpal_nbytes = numentries*3;
	de_read_simple_palette(c, c->infile, pos, numentries, 3, d->pal, 256,
		DE_RDPALTYPE_24BIT, DE_RDPALFLAG_NOHEADER);
	de_dbg_indent_restore(c, saved_indent_level);
}

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
	d->depth_pixel = (UI)de_getbyte_p(&pos);
	de_dbg(c, "depth: %u", d->depth_pixel);
	d->depth_color = d->depth_pixel;
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
		// TODO: dbg info
	}
	de_dbg(c, "image at %"I64_FMT, pos);
	de_convert_image_paletted(c->infile, pos, 8, d->w, d->pal, img, 0);
}

// TODO?: Make this a library function, and consolidate with the ILBM functions.
static void convert_image_planar_HAM(dbuf *f, i64 fpos, i64 nplanes,
	i64 row_stride, i64 plane_stride, const de_color *pal, de_bitmap *img)
{
	i64 ypos;
	u8 pbit[8];
	i64 units_per_row; // num bytes per row per plane that we will process
	UI pixshift1;

	de_zeromem(pbit, sizeof(pbit));
	if(nplanes==6) {
		pixshift1 = 4;
	}
	else if(nplanes==8) {
		pixshift1 = 2;
	}
	else goto done;

	units_per_row = (img->width + 7)/8;

	for(ypos=0; ypos<img->height; ypos++) {
		i64 n;
		u8 cr, cg, cb;

		cr = DE_COLOR_R(pal[0]) >> pixshift1;
		cg = DE_COLOR_G(pal[0]) >> pixshift1;
		cb = DE_COLOR_B(pal[0]) >> pixshift1;

		// Read 8 bits from each plane, then rearrange to make 8 output pixels.
		for(n=0; n<units_per_row; n++) {
			UI k;
			UI pn;
			u8 b;
			i64 xpos;

			for(pn=0; pn<(UI)nplanes; pn++) {
				b = dbuf_getbyte(f, fpos + ypos*row_stride + pn*plane_stride + n);
				pbit[pn] = b;
			}

			for(k=0; k<8; k++) {
				de_color clr;
				u8 pixval;
				u8 pixval_code;
				u8 pixval_color;
				u8 cr2, cg2, cb2;

				pixval = 0;
				for(pn=0; pn<(UI)nplanes; pn++) {
					if((pbit[pn] & (1U<<(7-k)))!=0) {
						pixval |= 1U<<pn;
					}
				}

				if(nplanes==6) {
					pixval_code = pixval >> 4;
					pixval_color = pixval & 0x0f;
				}
				else {
					pixval_code = pixval >> 6;
					pixval_color = pixval & 0x3f;
				}

				switch(pixval_code) {
				case 0x1: // Modify blue value
					cb = pixval_color;
					break;
				case 0x2: // Modify red value
					cr = pixval_color;
					break;
				case 0x3: // Modify green value
					cg = pixval_color;
					break;
				default: // 0: Use colormap value
					clr = pal[(UI)pixval_color];
					cr = DE_COLOR_R(clr) >> pixshift1;
					cg = DE_COLOR_G(clr) >> pixshift1;
					cb = DE_COLOR_B(clr) >> pixshift1;
					break;
				}

				if(nplanes==6) {
					cr2 = (cr<<4) | cr;
					cg2 = (cr<<4) | cr;
					cb2 = (cr<<4) | cr;
				}
				else {
					cr2 = (cr<<2) | (cr>>4);
					cg2 = (cg<<2) | (cg>>4);
					cb2 = (cb<<2) | (cb>>4);
				}
				xpos = n*8 + (i64)k;
				de_bitmap_setpixel_rgba(img, xpos, ypos, DE_MAKE_RGB(cr2, cg2, cb2));
			}
		}
	}

done:
	;
}

static void read_image_amiga(deark *c, lctx *d, de_bitmap *img, i64 pos1)
{
	if(d->ham_flag) {
		convert_image_planar_HAM(c->infile, pos1, d->depth_pixel,
			d->amiga_row_stride, d->amiga_plane_stride, d->pal, img);
	}
	else {
		de_convert_image_paletted_planar(c->infile, pos1, d->depth_pixel,
			d->amiga_row_stride, d->amiga_plane_stride, d->pal, img, 0x02);
	}
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
	i64 pos;
	int saved_indent_level;
	i64 cardidx;
	i64 expected_cardsize;
	de_bitmap *cardimg = NULL;
	de_bitmap *canvas = NULL;
	i64 canvas_cols, canvas_rows;
	i64 canvas_w, canvas_h;
	i64 cxpos_maincards, cypos_maincards;
	i64 cxpos_extracards, cypos_extracards;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = d->hdrsize + d->globalpal_nbytes;
	de_dbg(c, "cards at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	if(d->is_pc) {
		if(d->depth_pixel!=8 && d->depth_pixel!=16) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
	}

	if(d->numcards<MINCARDS || d->numcards>MAXCARDS ||
		d->w<MINCARDWIDTH || d->w>MAXCARDWIDTH ||
		d->h<MINCARDHEIGHT || d->h>MAXCARDHEIGHT)
	{
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->is_pc) {
		expected_cardsize = d->w * d->h * (d->depth_pixel/8);
	}
	else {
		i64 bytes_per_row_per_plane;

		// We expect the width to be a multiple of 8. Other widths are not
		// supported.
		bytes_per_row_per_plane = (d->w)/8;
		d->amiga_plane_stride = bytes_per_row_per_plane;
		d->amiga_row_stride = bytes_per_row_per_plane * d->depth_pixel;
		expected_cardsize = (d->w * d->h * d->depth_pixel)/8;
	}

	if(d->cardsize!=expected_cardsize && !d->suppress_size_warnings) {
		de_warn(c, "Reported cardsize is %"I64_FMT"; expected %"I64_FMT,
			d->cardsize, expected_cardsize);
		d->suppress_size_warnings = 1;
	}

	d->localpal_nbytes = 0;
	if(d->is_pc) {
		if(d->depth_pixel==8) {
			d->localpal_nbytes = 512;
		}
	}

	canvas_cols = 13;
	canvas_rows = (d->numcards+12) / 13;
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
		if(d->is_pc) {
			cw_raw = de_getu16le_p(&pos);
			ch_raw = de_getu16le_p(&pos);
			if((cw_raw+1 != d->w) || (ch_raw+1 != d->h)) {
				d->fatalerrflag = 1;
				d->need_errmsg = 1;
				goto done;
			}
		}

		de_bitmap_rect(cardimg, 0, 0, d->w, d->h, DE_STOCKCOLOR_BLACK, 0);
		if(d->is_pc) {
			if(d->depth_pixel==8) {
				read_image_pc8(c, d, cardimg, pos);
			}
			else {
				read_image_pc16(c, d, cardimg, pos);
			}
		}
		else {
			read_image_amiga(c, d, cardimg, pos);
		}
		pos += d->localpal_nbytes;
		pos += d->cardsize;

		if(d->is_pc) {
			is_main_card = (cardidx>=1 && cardidx<=52);
		}
		else {
			is_main_card = (cardidx>=3 && cardidx<=54);
		}

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

static u8 reko_fmt_from_sig(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, (const void*)"REKO", 4)) {
		return RKFMT_AMIGA;
	}
	if(!de_memcmp(buf, (const void*)"PCREKO", 6)) {
		if(buf[6]=='D' && buf[7]==0x20) return RKFMT_RKP8;
		if(buf[6]==0 && buf[7]==0) return RKFMT_RKP16;
	}
	return 0;
}

static void de_run_reko(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = reko_fmt_from_sig(c);

	if(d->fmt==0) {
		de_err(c, "Unsupported REKO version");
		goto done;
	}

	if(d->fmt==RKFMT_RKP8 || d->fmt==RKFMT_RKP16) {
		d->is_pc = 1;
	}
	de_dbg(c, "platform: %s", (d->is_pc ? "pc" : "amiga"));

	if(d->is_pc) {
		read_header_pc(c, d);
	}
	else {
		read_header_amiga(c, d);
	}
	if(d->fatalerrflag) goto done;

	if(!d->is_pc) {
		read_palette_amiga(c, d);
	}
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
	u8 fmt;

	fmt = reko_fmt_from_sig(c);
	if(fmt!=0) return 70;
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
