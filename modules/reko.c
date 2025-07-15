// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// REKO cardset, etc.

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_reko);
DE_DECLARE_MODULE(de_module_wizsolitaire);

//----------------------------------------------------
// REKO cardset

#define MAXCARDS       80
#define MINCARDWIDTH   64
#define MAXCARDWIDTH   100
#define MINCARDHEIGHT  100
#define MAXCARDHEIGHT  150

#define RKFMT_AMIGA   1
#define RKFMT_RKP8    4
#define RKFMT_RKP16   5
#define RKFMT_RKP24   6

typedef struct localctx_reko {
	u8 fmt; // RKFMT_*
	u8 is_pc;
	u8 fatalerrflag;
	u8 need_errmsg;
	u8 suppress_size_warnings;
	u8 combine_images;
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
	i64 idx_of_first_main_card;
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
	if(d->w==96 && d->depth_pixel==4) {
		; // Hack. Found a file that's really like this.
	}
	else if(d->w>88 && d->w<=96) {
		de_warn(c, "Unexpected width %d; assuming it should be 88", (int)d->w);
		d->w = 88;
		d->suppress_size_warnings = 1;
	}

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

// TODO?: Support for RKP 24 is quick and dirty.
static void read_header_rkp24(deark *c, lctx *d)
{
	i64 pos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 8;

	d->cardsize = de_getu32le_p(&pos);
	de_dbg(c, "card size: %"I64_FMT, d->cardsize);
	d->bodysize = de_getu32le_p(&pos);
	de_dbg(c, "body size: %"I64_FMT, d->bodysize);
	d->w = de_getu32le_p(&pos);
	d->h = de_getu32le_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	d->depth_pixel = (UI)de_getu32le_p(&pos);
	de_dbg(c, "depth: %u", d->depth_pixel);
	d->depth_color = d->depth_pixel;
	d->numcards = (i64)de_getu32le_p(&pos);
	de_dbg(c, "num cards: %"I64_FMT, d->numcards);
	d->hdrsize = 1104;

	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_image_pc8(deark *c, lctx *d, de_bitmap *img, i64 pos1)
{
	i64 pos = pos1;
	size_t k;
	char tmps[64];

	de_dbg(c, "palette at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	de_zeromem(d->pal, sizeof(d->pal));
	for(k=0; k<256; k++) {
		u32 clr_raw;

		clr_raw = (u32)de_getu16le_p(&pos);
		d->pal[k] = de_rgb555_to_888(clr_raw);
		if(c->debug_level>=2) {
			de_snprintf(tmps, sizeof(tmps), "0x%04x "DE_CHAR_RIGHTARROW" ", (UI)clr_raw);
			de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
		}
	}
	de_dbg_indent(c, -1);

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
					cg2 = (cg<<4) | cg;
					cb2 = (cb<<4) | cb;
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

static void set_reko_card_filename(deark *c, i64 idx_of_first_main_card,
	i64 cardidx, de_finfo *fi)
{
	static const char *cnames = "a23456789tjqk";
	static const char *snames = "cdhs";
	char nbuf[16];

	if(cardidx>=idx_of_first_main_card && cardidx<idx_of_first_main_card+52) {
		nbuf[0] = cnames[(cardidx-idx_of_first_main_card)/4];
		nbuf[1] = snames[(cardidx-idx_of_first_main_card)%4];
		nbuf[2] = '\0';
	}
	else if(cardidx==0) {
		de_strlcpy(nbuf, "back", sizeof(nbuf));
	}
	else {
		de_strlcpy(nbuf, "other", sizeof(nbuf));
	}

	de_finfo_set_name_from_sz(c, fi, nbuf, 0, DE_ENCODING_LATIN1);
}

static void reko_main_rkp24(deark *c, lctx *d)
{
	i64 pos;
	int saved_indent_level;
	i64 cardidx;
	u8 jpeg_fmt = 0;
	const char *ext;
	de_finfo *fi = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = d->hdrsize;
	de_dbg(c, "cards at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	fi = de_finfo_create(c);

	if(d->cardsize==0) {
		jpeg_fmt = 1;
		ext = "jpg";
	}
	else {
		ext = "bmp";
	}

	if(d->numcards<1 || d->numcards>MAXCARDS) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	for(cardidx=0; cardidx<d->numcards; cardidx++) {
		i64 extract_pos = 0;
		i64 nbytes_to_extract = 0;
		i64 this_cardsize = 0;
		dbuf *outf;

		de_dbg(c, "card #%"I64_FMT" at %"I64_FMT, cardidx, pos);
		de_dbg_indent(c, 1);

		if(jpeg_fmt) {
			extract_pos = pos+4;
			if(de_getu16be(extract_pos) != 0xffd8) {
				d->fatalerrflag = 1;
				d->need_errmsg = 1;
				goto done;
			}
			nbytes_to_extract = de_getu32le(pos);
			this_cardsize = 4+nbytes_to_extract;
		}
		else {
			if(de_getu16be(pos) != 0x424d) {
				d->fatalerrflag = 1;
				d->need_errmsg = 1;
				goto done;
			}
			extract_pos = pos;
			nbytes_to_extract = d->cardsize;
			this_cardsize = d->cardsize;
		}

		if(extract_pos+nbytes_to_extract > c->infile->len) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		set_reko_card_filename(c, d->idx_of_first_main_card, cardidx, fi);
		outf = dbuf_create_output_file(c, ext, fi, 0);
		dbuf_copy(c->infile, extract_pos, nbytes_to_extract, outf);
		dbuf_close(outf);

		pos += this_cardsize;
		de_dbg_indent(c, -1);
	}

done:
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void reko_main(deark *c, lctx *d)
{
	int saved_indent_level;
	i64 cardidx;
	i64 expected_cardsize;
	i64 full_cardsize;
	de_bitmap *cardimg = NULL;
	de_bitmap *canvas = NULL;
	de_finfo *fi = NULL;
	i64 cards_pos;
	i64 localhdrsize = 0;
	i64 canvas_cols, canvas_rows;
	i64 canvas_w, canvas_h;
	i64 cxpos_maincards, cypos_maincards;
	i64 cxpos_extracards, cypos_extracards;

	de_dbg_indent_save(c, &saved_indent_level);
	cards_pos = d->hdrsize + d->globalpal_nbytes;
	de_dbg(c, "cards at %"I64_FMT, cards_pos);
	de_dbg_indent(c, 1);

	fi = de_finfo_create(c);

	if(d->is_pc) {
		if(d->depth_pixel!=8 && d->depth_pixel!=16) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
	}

	if(d->numcards<1 || d->numcards>MAXCARDS ||
		d->w<MINCARDWIDTH || d->w>MAXCARDWIDTH ||
		d->h<MINCARDHEIGHT || d->h>MAXCARDHEIGHT)
	{
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->numcards < d->idx_of_first_main_card+52) {
		de_warn(c, "Expected at least %"I64_FMT" cards; only found %"I64_FMT,
			d->idx_of_first_main_card+52, d->numcards);
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
		localhdrsize = 4;
		if(d->depth_pixel==8) {
			d->localpal_nbytes = 512;
		}
	}
	full_cardsize = localhdrsize + d->localpal_nbytes + d->cardsize;

	canvas_cols = 13;
	canvas_rows = (d->numcards+12) / 13;
	// There has to be at least 1 extra card, so we need at least 5 rows.
	if(canvas_rows<5) canvas_rows = 5;
	cxpos_maincards = 0;
	cypos_maincards = 0;
	cxpos_extracards = 0;
	cypos_extracards = 4;

#define REKO_BORDER 2
	canvas_w = canvas_cols*(d->w+REKO_BORDER)-REKO_BORDER;
	canvas_h = canvas_rows*(d->h+REKO_BORDER)-REKO_BORDER;
	if(d->combine_images) {
		canvas = de_bitmap_create(c, canvas_w, canvas_h, 4);
	}

	cardimg = de_bitmap_create(c, d->w, d->h, 3);

	for(cardidx=0; cardidx<d->numcards; cardidx++) {
		u8 is_main_card;
		i64 dstcxpos, dstcypos;
		i64 dstxpos, dstypos;
		i64 thiscardpos;

		thiscardpos = cards_pos + cardidx*full_cardsize;
		de_dbg(c, "card #%"I64_FMT" at %"I64_FMT, cardidx, thiscardpos);
		de_dbg_indent(c, 1);

		if(d->is_pc && !d->fatalerrflag && (thiscardpos+localhdrsize <= c->infile->len)) {
			i64 cw_raw, ch_raw;

			cw_raw = de_getu16le(thiscardpos);
			ch_raw = de_getu16le(thiscardpos+2);
			if((cw_raw+1 != d->w) || (ch_raw+1 != d->h)) {
				de_err(c, "Card #%d: Bad card header", (int)cardidx);
				d->fatalerrflag = 1;
				// (But keep going.)
			}
		}

		de_bitmap_rect(cardimg, 0, 0, d->w, d->h, DE_STOCKCOLOR_BLACK, 0);

		if(d->fatalerrflag) {
			;
		}
		else if(d->is_pc) {
			if(d->depth_pixel==8) {
				read_image_pc8(c, d, cardimg, thiscardpos+localhdrsize);
			}
			else {
				read_image_pc16(c, d, cardimg, thiscardpos+localhdrsize);
			}
		}
		else {
			read_image_amiga(c, d, cardimg, thiscardpos);
		}

		is_main_card = (cardidx>=d->idx_of_first_main_card &&
			cardidx<(d->idx_of_first_main_card+52));
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
		if(canvas) {
			de_bitmap_copy_rect(cardimg, canvas, 0, 0, d->w, d->h, dstxpos, dstypos, 0);
		}
		else {
			set_reko_card_filename(c, d->idx_of_first_main_card, cardidx, fi);
			de_bitmap_write_to_file_finfo(cardimg, fi, 0);
		}

		if(!d->fatalerrflag && (thiscardpos+full_cardsize > c->infile->len)) {
			de_err(c, "Premature end of file");
			d->fatalerrflag = 1;
			// (But keep going, so we draw the full image template.)
		}

		if(d->fatalerrflag && !canvas) goto done;

		de_dbg_indent(c, -1);
	}

	if(canvas) {
		de_bitmap_write_to_file(canvas, NULL, 0);
	}

done:
	de_bitmap_destroy(cardimg);
	de_bitmap_destroy(canvas);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static u8 reko_fmt_from_sig(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, (const void*)"REKO", 4)) {
		// Just to screen out text files, I think we can assume the high byte
		// of the cardsize field is 0.
		if(de_getbyte(8) == 0) {
			return RKFMT_AMIGA;
		}
	}
	if(!de_memcmp(buf, (const void*)"PCREKO", 6)) {
		if(buf[6]=='D' && buf[7]==0x20) return RKFMT_RKP8;
		if(buf[6]==0 && buf[7]==0) return RKFMT_RKP16;
	}
	if(!de_memcmp(buf, (const void*)"PCRKP\0", 6)) {
		return RKFMT_RKP24;
	}
	return 0;
}

static void de_run_reko(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *fmtname;

	d = de_malloc(c, sizeof(lctx));
	d->combine_images = (u8)de_get_ext_option_bool(c, "reko:combine", 1);

	d->fmt = reko_fmt_from_sig(c);
	if(d->fmt==0) {
		de_err(c, "Unsupported REKO version");
		goto done;
	}
	if(d->fmt==RKFMT_RKP8) fmtname = "RKP 8";
	else if(d->fmt==RKFMT_RKP16) fmtname = "RKP 16";
	else if(d->fmt==RKFMT_RKP24) fmtname = "RKP 24";
	else fmtname = "Amiga";
	de_declare_fmtf(c, "REKO cardset (%s)", fmtname);

	if(d->fmt==RKFMT_RKP8 || d->fmt==RKFMT_RKP16 || d->fmt==RKFMT_RKP24) {
		d->is_pc = 1;
	}

	if(d->is_pc) {
		d->idx_of_first_main_card = 1;
	}
	else {
		d->idx_of_first_main_card = 3;
	}

	if(d->fmt==RKFMT_RKP24) {
		read_header_rkp24(c, d);
	}
	else if(d->is_pc) {
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
	if(d->fmt==RKFMT_RKP24) {
		reko_main_rkp24(c, d);
	}
	else {
		reko_main(c, d);
	}

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

static void de_help_reko(deark *c)
{
	de_msg(c, "-opt reko:combine=0 : Always write each card to its own file");
}

void de_module_reko(deark *c, struct deark_module_info *mi)
{
	mi->id = "reko";
	mi->desc = "REKO cardset";
	mi->run_fn = de_run_reko;
	mi->identify_fn = de_identify_reko;
	mi->help_fn = de_help_reko;
}

//----------------------------------------------------
// Wiz Solitaire deck

static void set_wizsol_card_filename(deark *c, i64 cardidx, u8 cardval,
	u8 cardsuit, de_finfo *fi)
{
	static const char *cnames = "a23456789tjqk";
	static const char *snames = "cdhs";
	char nbuf[16];

	if(cardval>=1 && cardval<=13 && cardsuit<=3) {
		nbuf[0] = cnames[(UI)cardval-1];
		nbuf[1] = snames[(UI)cardsuit];
		nbuf[2] = '\0';
	}
	else if(cardidx==0) {
		de_strlcpy(nbuf, "back", sizeof(nbuf));
	}
	else {
		de_strlcpy(nbuf, "other", sizeof(nbuf));
	}

	de_finfo_set_name_from_sz(c, fi, nbuf, 0, DE_ENCODING_LATIN1);
}

static void de_run_wizsolitaire(deark *c, de_module_params *mparams)
{
	i64 cardidx = 0;
	u8 errflag = 0;
	u8 need_errmsg = 0;
	i64 pos;
	de_finfo *fi = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = 20;
	fi = de_finfo_create(c);
	while(1) {
		i64 extralen;
		i64 imglen;
		u8 cardval, cardsuit;

		if(cardidx>72) {
			errflag = 1;
			need_errmsg = 1;
			goto done;
		}
		if(pos+18 > c->infile->len) goto done;
		de_dbg(c, "card #%"I64_FMT" at %"I64_FMT, cardidx, pos);
		de_dbg_indent(c, 1);

		// Card headers start with 00 00 00 00, except the 54th which starts
		// with 04 00 00 00 00 00 00 00.
		// I don't know how to interpret this. But the 04 does not seem to be the
		// number of extra cards, so I'm assuming it's the number of extra bytes
		// in the header.
		extralen = de_getu32le_p(&pos);
		de_dbg(c, "len1: %"I64_FMT, extralen);
		pos += extralen;
		pos += 8;
		cardval = de_getbyte_p(&pos);
		cardsuit = de_getbyte_p(&pos);
		imglen = de_getu32le_p(&pos);
		de_dbg(c, "img len: %"I64_FMT, imglen);
		if(imglen==0) {
			de_dbg(c, "[eof marker]");
			goto done;
		}

		de_dbg(c, "suit %u card %u", (UI)cardsuit, (UI)cardval);

		if(imglen<32 || pos+imglen>c->infile->len) {
			errflag = 1;
			need_errmsg = 1;
			goto done;
		}
		if(dbuf_memcmp(c->infile, pos, (const void*)"\xff\xd8\xff", 3)) {
			de_err(c, "Expected image not found at %"I64_FMT, pos);
			errflag = 1;
			goto done;
		}
		set_wizsol_card_filename(c, cardidx, cardval, cardsuit, fi);
		dbuf_create_file_from_slice(c->infile, pos, imglen, "jpg", fi, 0);
		pos += imglen;
		de_dbg_indent(c, -1);
		cardidx++;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(!errflag) {
		de_dbg(c, "number of cards: %"I64_FMT, cardidx);
		if(cardidx<53 && !errflag) {
			de_warn(c, "Expected at least 53 cards, found %"I64_FMT, cardidx);
		}
	}
	if(need_errmsg) {
		de_err(c, "Bad or unsupported file");
	}
	de_finfo_destroy(c, fi);
}

static int de_identify_wizsolitaire(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, (const void*)"WizSolitaireDeck", 16)) {
		return 100;
	}
	return 0;
}

void de_module_wizsolitaire(deark *c, struct deark_module_info *mi)
{
	mi->id = "wizsolitaire";
	mi->desc = "Wiz Solitaire deck";
	mi->run_fn = de_run_wizsolitaire;
	mi->identify_fn = de_identify_wizsolitaire;
}
