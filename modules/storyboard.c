// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// IBM Storyboard .PIC/.CAP, old "EP_CAP" format

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
	de_color pal[256];
};

static int decompress_storyboard(deark *c, struct storyboard_ctx *d, i64 pos1,
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

static void do_text_main(deark *c, struct storyboard_ctx *d, dbuf *unc_data, struct de_char_context *charctx)
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

static void do_text(deark *c, struct storyboard_ctx *d, i64 pos)
{
	dbuf *unc_data = NULL;
	struct de_char_context *charctx = NULL;
	int k;

	if(d->mode != 3) goto done;
	d->max_unc_size = 65536;

	unc_data = dbuf_create_membuf(c, 4000, 0);
	dbuf_enable_wbuffer(unc_data);

	if(!decompress_storyboard(c, d, pos, unc_data)) goto done;
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

	for(k=0; k<16; k++) {
		charctx->pal[k] = de_palette_pc16(k);
	}

	do_text_main(c, d, unc_data, charctx);

done:
	if(charctx) {
		de_free_charctx_screens(c, charctx);
		de_destroy_charctx(c, charctx);
	}
	dbuf_close(unc_data);
}

static void do_image(deark *c, struct storyboard_ctx *d, i64 pos)
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

	if(!decompress_storyboard(c, d, pos, unc_data)) goto done;
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
		int i;

		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 6.0;
		fi->density.ydens = 5.0;
		// TODO? In PC Storyboard 1.0 Picture Maker, images can be displayed using
		// different CGA palettes (F3/F4 keys). But that information is not stored
		// in the file.
		// Maybe we should have a command-line option to select the palette.
		// Also, maybe we should have a CGA composite color mode.
		for(i=0; i<4; i++) {
			d->pal[i] = de_palette_pcpaint_cga4(3, (int)i);
		}
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

static void de_run_storyboard(deark *c, de_module_params *mparams)
{
	struct storyboard_ctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(struct storyboard_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

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
		do_text(c, d, pos);
	}
	else {
		do_image(c, d, pos);
	}
	// TODO: Is it possible for a file to contain multiple images?

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported Storyboard image");
		}
		de_free(c, d);
	}
}

static int de_identify_storyboard(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "EP_CAP", 6)) {
		return 100;
	}
	return 0;
}

void de_module_storyboard(deark *c, struct deark_module_info *mi)
{
	mi->id = "storyboard";
	mi->desc = "Storyboard PIC/CAP (old format)";
	mi->run_fn = de_run_storyboard;
	mi->identify_fn = de_identify_storyboard;
}
