// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// IBM Storyboard .PIC/.CAP
// - Old "EP_CAP" format
// - Some newer formats may be partially supported.

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_storyboard);

struct storyboard_ctx {
	de_encoding input_encoding;
	u8 mode;
	u8 is_text;
	u8 need_errmsg;
	i64 bpp; // bits per pixel
	i64 width, height;
	i64 rowspan;
	i64 width_in_chars, height_in_chars;
	i64 max_unc_size;
	i64 attribs_pos;
	i64 img_endpos;

	i64 nstrips_per_plane;
	i64 planespan;

	de_color pal[256];
	de_color paltmp[256];
};

static int decompress_oldfmt(deark *c, struct storyboard_ctx *d, i64 pos1,
	dbuf *outf)
{
	i64 pos = pos1;
	i64 nbytes_written = 0;
	i64 img_seg_size;
	int found_attribs = 0;
	int element_count = 0;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "compressed data segment at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	img_seg_size = de_getu16le_p(&pos);
	d->img_endpos = pos + img_seg_size;
	de_dbg(c, "segment size: %"I64_FMT" (ends at %"I64_FMT")", img_seg_size, d->img_endpos);
	if(img_seg_size<2) {
		d->need_errmsg = 1;
		goto done;
	}

	while(1) {
		UI n;
		i64 count;

		if(nbytes_written >= d->max_unc_size) break;
		if(pos >= c->infile->len) break;

		n = (UI)de_getu16le_p(&pos);
		if(n == 0x0000) { // Seems to be a special stop/separator code
			element_count++;
			if(element_count==1 && d->is_text) {
				// End of foreground, start of attributes.
				// Kind of a hack, but it's easiest just to decompress everything
				// in one go.
				dbuf_flush(outf);
				d->attribs_pos = outf->len;
				found_attribs = 1;
			}
			else {
				break;
			}
		}
		else if(n < 0x8000) {
			count = (i64)n;
			dbuf_copy(c->infile, pos, count, outf);
			pos += count;
			nbytes_written += count;
		}
		else {
			u8 v;

			count = (i64)(n-0x8000);
			v = de_getbyte_p(&pos);
			dbuf_write_run(outf, v, count);
			nbytes_written += count;
		}
	}

	if(d->is_text && !found_attribs) {
		d->need_errmsg = 1;
	}
	else {
		retval = 1;
	}
	de_dbg(c, "decompressed to %"I64_FMT" bytes", nbytes_written);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_oldfmt_text_main(deark *c, struct storyboard_ctx *d, dbuf *unc_data,
	struct de_char_context *charctx)
{
	i64 i, j;
	u8 ccode, acode;
	u8 fgcol, bgcol;
	struct de_char_screen *screen;
	struct de_encconv_state es;

	charctx->nscreens = 1;
	charctx->screens = de_mallocarray(c, charctx->nscreens, sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];
	screen->width = d->width_in_chars;
	screen->height = d->height_in_chars;
	screen->cell_rows = de_mallocarray(c, d->height_in_chars, sizeof(struct de_char_cell*));
	de_encconv_init(&es, d->input_encoding);

	for(j=0; j<d->height_in_chars; j++) {
		screen->cell_rows[j] = de_mallocarray(c, d->width_in_chars, sizeof(struct de_char_cell));

		for(i=0; i<d->width_in_chars; i++) {
			ccode = dbuf_getbyte(unc_data, j*d->width_in_chars + i);
			acode = dbuf_getbyte(unc_data, d->attribs_pos + j*d->width_in_chars + i);

			fgcol = (acode & 0x0f);
			bgcol = acode >> 4;

			screen->cell_rows[j][i].fgcol = (u32)fgcol;
			screen->cell_rows[j][i].bgcol = (u32)bgcol;
			screen->cell_rows[j][i].codepoint = (i32)ccode;
			screen->cell_rows[j][i].codepoint_unicode = de_char_to_unicode_ex((i32)ccode, &es);
		}
	}

	de_char_output_to_file(c, charctx);
}

static void do_oldfmt_text(deark *c, struct storyboard_ctx *d, i64 pos)
{
	dbuf *unc_data = NULL;
	struct de_char_context *charctx = NULL;

	if(d->mode != 3) goto done;
	d->max_unc_size = 65536;

	unc_data = dbuf_create_membuf(c, 4000, 0);
	dbuf_enable_wbuffer(unc_data);

	if(!decompress_oldfmt(c, d, pos, unc_data)) goto done;
	dbuf_flush(unc_data);

	// Not sure how to figure out the dimensions. The files in the distribution
	// seem to contain this information, but the ones I capture myself contain
	// nonsense. (Maybe mode=3 implies 80x25, so we could just assume that.)
	if(d->rowspan>=80 && d->rowspan<=400 && d->height>=20 && d->height<=100 &&
		(d->rowspan*d->height == unc_data->len))
	{
		d->width_in_chars = d->rowspan/2;
		d->height_in_chars = d->height;
	}
	else {
		d->width_in_chars = 80;
		d->height_in_chars = 25;
	}

	charctx = de_create_charctx(c, 0);
	de_char_decide_output_format(c, charctx);
	de_copy_std_palette(DE_PALID_PC16, 0, 0, 16, charctx->pal, 16, 0);
	do_oldfmt_text_main(c, d, unc_data, charctx);

done:
	if(charctx) {
		de_free_charctx_screens(c, charctx);
		de_destroy_charctx(c, charctx);
	}
	dbuf_close(unc_data);
}

static void do_oldfmt_image(deark *c, struct storyboard_ctx *d, i64 pos)
{
	dbuf *unc_data = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;

	d->max_unc_size = d->height * d->rowspan;
	d->width = d->rowspan * (8/d->bpp);
	de_dbg_dimensions(c, d->width, d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}

	unc_data = dbuf_create_membuf(c, d->max_unc_size, 0x1);
	dbuf_enable_wbuffer(unc_data);

	if(!decompress_oldfmt(c, d, pos, unc_data)) goto done;
	dbuf_flush(unc_data);

	fi = de_finfo_create(c);

	if(d->mode == 0x06) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 12.0;
		fi->density.ydens = 5.0;
		d->pal[0] = DE_STOCKCOLOR_BLACK;
		d->pal[1] = DE_STOCKCOLOR_WHITE;
	}
	else { // assuming mode = 0x04
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 6.0;
		fi->density.ydens = 5.0;
		// TODO? In PC Storyboard 1.0 Picture Maker, images can be displayed using
		// different CGA palettes (F3/F4 keys). But that information is not stored
		// in the file.
		// Maybe we should have a command-line option to select the palette.
		// Also, maybe we should have a CGA composite color mode.
		de_copy_std_palette(DE_PALID_CGA, 3, 0, 4, d->pal, 4, 0);
	}

	img = de_bitmap_create(c, d->width, d->height, ((d->bpp==1)?1:3));
	de_convert_image_paletted(unc_data, 0, d->bpp, d->rowspan, d->pal, img, 0);
	de_bitmap_write_to_file_finfo(img, fi, 0);

	dbuf_close(unc_data);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
done:
	;
}

static void de_run_storyboard_oldfmt(deark *c, struct storyboard_ctx *d,
	de_module_params *mparams)
{
	i64 pos;

	pos = 6;
	if(de_getbyte_p(&pos) != 0) {
		d->need_errmsg = 1;
		goto done;
	}

	d->mode = de_getbyte_p(&pos);
	de_dbg(c, "mode: %u", (UI)d->mode);
	pos += 3; // ?

	d->rowspan = de_getu16le_p(&pos);
	de_dbg(c, "bytes per row: %u", (UI)d->rowspan);
	d->height = de_getu16le_p(&pos);
	de_dbg(c, "height: %u", (UI)d->height);

	switch(d->mode) {
	case 3:
		d->is_text = 1;
		break;
	case 4:
		d->bpp = 2;
		break;
	case 6:
		d->bpp = 1;
		break;
	default:
		de_err(c, "Unsupported screen mode: %u", (UI)d->mode);
		goto done;
	}

	if(d->is_text) {
		do_oldfmt_text(c, d, pos);
	}
	else {
		do_oldfmt_image(c, d, pos);
	}
	// TODO: Is it possible for a file to contain multiple images?

done:
	;
}

static void do_decompress_newfmt(deark *c, struct storyboard_ctx *d,
	dbuf *outf)
{
	i64 pos = 2048;
	i64 endpos = c->infile->len;

	while(1) {
		i64 count;
		u8 b, b2;

		if(pos>=endpos) break;

		b = de_getbyte_p(&pos);
		count = (i64)(b & 0x7f);
		if(b & 0x80) { // compressed run
			b2 = de_getbyte_p(&pos);
			dbuf_write_run(outf, b2, count);
		}
		else { // uncompressed run
			dbuf_copy(c->infile, pos, count, outf);
			pos += count;
		}
	}
}

static void do_newfmt_render_planar(deark *c, struct storyboard_ctx *d,
	dbuf *unc_data, de_bitmap *img)
{
	i64 n;
#define SBPIC_MAXPLANES 4
	u8 pbit[SBPIC_MAXPLANES];

	de_zeromem(pbit, sizeof(pbit));

	for(n=0; n<d->planespan; n++) {
		UI k;
		UI pn;
		i64 xpos, ypos;

		for(pn=0; pn<(UI)d->bpp; pn++) {
			pbit[pn] = dbuf_getbyte(unc_data, pn*d->planespan + n);
		}

		ypos = n%d->height;
		for(k=0; k<8; k++) {
			UI palent;

			xpos = 8*(n/d->height) + (i64)(7-k);
			palent = 0;
			for(pn=0; pn<(UI)d->bpp; pn++) {
				if((pbit[pn] & (1U<<k))!=0) {
					palent |= 1U<<pn;
				}
			}

			de_bitmap_setpixel_rgb(img, xpos, ypos, d->pal[palent]);
		}
	}
}

static void do_storyboard_main(deark *c, struct storyboard_ctx *d)
{
	dbuf *unc_data = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	i64 max_unc_size;
	UI i;
	char tmps[32];
	// I can't figure out how the image bits are mapped to palette indices.
	// These maps make no sense to me, but it's one way to do it.
	static const u8 palmap_cga[4] = { 3, 1, 2, 0 };
	static const u8 palmap_ega[16] = {
		0, 11,  6,  4, 13, 15,  2, 9, 8,  3, 14, 12,  5,  7, 10, 1 };
	static const u8 palmap_16[16] = {
		0, 11, 13, 15,  6,  4,  2, 9, 8,  3,  5,  7, 14, 12, 10, 1 };

	if(d->bpp==2) {
		de_copy_std_palette(DE_PALID_CGA, 3, 0, 4, d->paltmp, 4, 0);
		for(i=0; i<4; i++) {
			d->pal[i] = d->paltmp[(UI)palmap_cga[i]];
		}
	}
	else if(d->bpp==4) {
		for(i=0; i<16; i++) {
			int idx;

			idx = (int)de_getbyte(13+(i64)i);
			if(idx==6 && d->height==200) {
				// ?? hack - dark yellow vs. brown issue
				d->paltmp[i] = de_get_std_palette_entry(DE_PALID_EGA64, 0, 20);
			}//
			else {
				d->paltmp[i] = de_get_std_palette_entry(DE_PALID_EGA64, 0, idx);
			}
			de_snprintf(tmps, sizeof(tmps), "%2d ", (int)idx);
			de_dbg_pal_entry2(c, i, d->paltmp[i], tmps, NULL, NULL);
		}
		for(i=0; i<16; i++) {
			if(d->height==200) {
				d->pal[i] = d->paltmp[(UI)palmap_16[i]];
			}
			else {
				d->pal[i] = d->paltmp[(UI)palmap_ega[i]];
			}
		}
	}

	if(d->bpp<8) {
		d->nstrips_per_plane = de_pad_to_n(d->width, 8) / 8;
		d->planespan = d->nstrips_per_plane * d->height;
		max_unc_size = d->planespan*d->bpp;
	}
	else {
		max_unc_size = d->width * d->height * (d->bpp/8);
	}

	unc_data = dbuf_create_membuf(c, max_unc_size, 0x1);
	dbuf_enable_wbuffer(unc_data);

	do_decompress_newfmt(c, d, unc_data);
	dbuf_flush(unc_data);

	fi = de_finfo_create(c);
	img = de_bitmap_create(c, d->width, d->height, 3);

	do_newfmt_render_planar(c, d, unc_data, img);

	if(d->width==320 && d->height==200) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 6.0;
		fi->density.ydens = 5.0;
	}
	else if(d->width==640 && d->height!=480) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 480.0;
		fi->density.ydens = (double)d->height;
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);

	dbuf_close(unc_data);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

// Support for "new" format is highly experimental. I don't know what most of
// the first 2048 bytes in the file are for.
static void de_run_storyboard_newfmt(deark *c, struct storyboard_ctx *d,
	de_module_params *mparams)
{
	u8 hdrbytes[4];

	dbuf_read(c->infile, hdrbytes, 0, sizeof(hdrbytes));
	if(hdrbytes[1]==0x84 && hdrbytes[3]==0x08) {
		d->width = 320;
		d->height = 200;
		d->bpp = 2;
		do_storyboard_main(c, d);
	}
	else if(hdrbytes[1]==0x84 && hdrbytes[3]==0x01) {
		d->width = 640;
		d->height = 200;
		d->bpp = 4;
		do_storyboard_main(c, d);
	}
	else if(hdrbytes[1]==0x84 && hdrbytes[3]==0x03) {
		d->width = 640;
		d->height = 350;
		d->bpp = 4;
		do_storyboard_main(c, d);
	}
	else if(hdrbytes[1]==0x84 && hdrbytes[3]==0x07) {
		d->width = 640;
		d->height = 480;
		d->bpp = 4;
		do_storyboard_main(c, d);
	}
	else {
		de_err(c, "Not a supported Storyboard format");
	}
}

static void de_run_storyboard(deark *c, de_module_params *mparams)
{
	struct storyboard_ctx *d = NULL;
	u8 b;

	d = de_malloc(c, sizeof(struct storyboard_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	b = de_getbyte(2);
	if(b=='_') {
		de_run_storyboard_oldfmt(c, d, mparams);
	}
	else if(b==0xc1) {
		de_run_storyboard_newfmt(c, d, mparams);
	}
	else {
		d->need_errmsg = 1;
	}

	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported Storyboard image");
		}
		de_free(c, d);
	}
}

static int de_identify_storyboard(deark *c)
{
	u8 b[6];

	de_read(b, 0, sizeof(b));

	if(!de_memcmp(b, (const void*)"EP_CAP", 6)) {
		return 100;
	}

	if(c->infile->len<2048) return 0;
	if(b[2]==0xc1 && b[0]==0x00) {
		if(b[1]==0x84) {
			if(b[3]==0x01 || b[3]==0x03 || b[3]==0x07 || b[3]==0x08) {
				return 80;
			}
		}
		else if(b[1]==0x85 || b[2]==0x86) {
			// We don't support these 256-color modes yet, so it doesn't
			// matter much if we identify them.
			return 7;
		}
	}
	return 0;
}

void de_module_storyboard(deark *c, struct deark_module_info *mi)
{
	mi->id = "storyboard";
	mi->desc = "Storyboard PIC/CAP";
	mi->run_fn = de_run_storyboard;
	mi->identify_fn = de_identify_storyboard;
}
