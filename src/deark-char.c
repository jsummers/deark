// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-char.c
//
// Functions related to character graphics.

#include "deark-config.h"
#include "deark-private.h"

struct charextractx {
	de_byte vga_9col_mode; // Flag: Render an extra column, like VGA does
	de_byte used_underline;
	de_byte used_blink;
	de_byte used_fgcol[16];
	de_byte used_bgcol[16];
	struct de_bitmap_font *standard_font;
	struct de_bitmap_font *font_to_use;

	de_int64 char_width_in_pixels;
	de_int64 char_height_in_pixels;
};

// Frees a charctx struct that has been allocated in a particular way.
// Does not free charctx->font.
// Does not free the ucstring fields.
void de_free_charctx(deark *c, struct de_char_context *charctx)
{
	de_int64 pgnum;
	de_int64 j;

	if(charctx) {
		if(charctx->screens) {
			for(pgnum=0; pgnum<charctx->nscreens; pgnum++) {
				if(charctx->screens[pgnum]) {
					if(charctx->screens[pgnum]->cell_rows) {
						for(j=0; j<charctx->screens[pgnum]->height; j++) {
							de_free(c, charctx->screens[pgnum]->cell_rows[j]);
						}
						de_free(c, charctx->screens[pgnum]->cell_rows);
					}
					de_free(c, charctx->screens[pgnum]);
				}
			}
			de_free(c, charctx->screens);
		}
		de_free(c, charctx);
	}
}

static void do_prescan_screen(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct de_char_screen *screen)
{
	const struct de_char_cell *cell;
	int i, j;
	de_byte cell_fgcol_actual;

	for(j=0; j<screen->height; j++) {
		for(i=0; i<screen->width; i++) {
			if(!screen->cell_rows || !screen->cell_rows[j]) continue;
			cell = &screen->cell_rows[j][i];
			if(!cell) continue;

			cell_fgcol_actual = cell->fgcol;
			if(cell->bold) cell_fgcol_actual |= 0x08;

			if(cell->fgcol<16) ectx->used_fgcol[(unsigned int)cell_fgcol_actual] = 1;
			if(cell->bgcol<16) ectx->used_bgcol[(unsigned int)cell->bgcol] = 1;
			if(cell->underline) ectx->used_underline = 1;
			if(cell->blink) ectx->used_blink = 1;
		}
	}
}

static void do_output_html_screen(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct de_char_screen *screen, dbuf *ofile)
{
	const struct de_char_cell *cell;
	struct de_char_cell blank_cell;
	int i, j;
	de_int32 n;
	int span_count = 0;
	int need_newline = 0;
	de_byte active_fgcol = 0;
	de_byte active_bgcol = 0;
	de_byte active_underline = 0;
	de_byte active_blink = 0;
	de_byte cell_fgcol_actual;

	// In case a cell is missing, we'll use this one:
	de_memset(&blank_cell, 0, sizeof(struct de_char_cell));
	blank_cell.codepoint = 32;
	blank_cell.codepoint_unicode = 32;

	dbuf_fputs(ofile, "<table style=\"margin-left:auto;margin-right:auto\"><tr>\n<td>");
	dbuf_fputs(ofile, "<pre>");
	for(j=0; j<screen->height; j++) {
		for(i=0; i<screen->width; i++) {
			if(!screen->cell_rows || !screen->cell_rows[j]) {
				cell = &blank_cell;
			}
			else {
				cell = &screen->cell_rows[j][i];
				if(!cell) cell = &blank_cell;
			}

			cell_fgcol_actual = cell->fgcol;
			if(cell->bold) cell_fgcol_actual |= 0x08;

			if(span_count==0 || cell_fgcol_actual!=active_fgcol || cell->bgcol!=active_bgcol ||
				cell->underline!=active_underline || cell->blink!=active_blink)
			{
				while(span_count>0) {
					dbuf_fprintf(ofile, "</span>");
					span_count--;
				}

				if(need_newline) {
					dbuf_fputs(ofile, "\n");
					need_newline = 0;
				}

				dbuf_fputs(ofile, "<span class=\"");

				// Classes for foreground and background colors
				dbuf_fprintf(ofile, "f%c", de_get_hexchar(cell_fgcol_actual));
				dbuf_fprintf(ofile, " b%c", de_get_hexchar(cell->bgcol));

				// Other attributes
				if(cell->underline) dbuf_fputs(ofile, " u");
				if(cell->blink) dbuf_fputs(ofile, " blink");

				dbuf_fputs(ofile, "\">");

				span_count++;
				active_fgcol = cell_fgcol_actual;
				active_bgcol = cell->bgcol;
				active_underline = cell->underline;
				active_blink = cell->blink;
			}

			n = cell->codepoint_unicode;
			if(n==0x00) n=0x20;
			if(n<0x20) n='?';

			if(need_newline) {
				dbuf_fputs(ofile, "\n");
				need_newline = 0;
			}

			de_write_codepoint_to_html(c, ofile, n);
		}

		// Defer emitting a newline, so that we have more control over where
		// to put it. We prefer to put it after "</span>".
		need_newline = 1;
	}

	while(span_count>0) {
		dbuf_fprintf(ofile, "</span>");
		span_count--;
	}

	dbuf_fputs(ofile, "</pre>");
	dbuf_fputs(ofile, "</td>\n</tr></table>\n");
}

static void output_css_color_block(deark *c, dbuf *ofile, de_uint32 *pal,
	const char *selectorprefix, const char *prop, const de_byte *used_flags)
{
	char tmpbuf[16];
	int i;

	for(i=0; i<16; i++) {
		if(!used_flags[i]) continue;
		de_color_to_css(pal[i], tmpbuf, sizeof(tmpbuf));
		dbuf_fprintf(ofile, " %s%c { %s: %s }\n", selectorprefix, de_get_hexchar(i),
			prop, tmpbuf);
	}
}

static void write_ucstring_to_html(deark *c, de_ucstring *s, dbuf *f)
{
	de_int64 i;
	int prev_space = 0;
	de_int32 ch;

	for(i=0; i<s->len; i++) {
		ch = s->str[i];

		// Don't let HTML collapse consecutive spaces
		if(ch==0x20) {
			if(prev_space) {
				ch = 0xa0; // nbsp
			}
			prev_space = 1;
		}
		else {
			prev_space = 0;
		}

		de_write_codepoint_to_html(c, f, ch);
	}
}

static void do_output_html_header(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, dbuf *ofile)
{
	int has_metadata;

	has_metadata = charctx->title || charctx->artist || charctx->organization ||
		charctx->creation_date;
	if(c->write_bom && !c->ascii_html) dbuf_write_uchar_as_utf8(ofile, 0xfeff);
	dbuf_fputs(ofile, "<!DOCTYPE html>\n");
	dbuf_fputs(ofile, "<html>\n");
	dbuf_fputs(ofile, "<head>\n");
	if(!c->ascii_html) dbuf_fputs(ofile, "<meta charset=\"UTF-8\">\n");
	dbuf_fputs(ofile, "<title>");
	if(charctx->title) {
		write_ucstring_to_html(c, charctx->title, ofile);
	}
	dbuf_fputs(ofile, "</title>\n");

	dbuf_fputs(ofile, "<style type=\"text/css\">\n");

	dbuf_fputs(ofile, " body { background-color: #222; background-image: url(\"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEUgICAoKCidji3LAAAAMUlE"
		"QVQI12NgaGBgPMDA/ICB/QMD/w8G+T8M9v8Y6v8z/P8PIoFsoAhQHCgLVMN4AACOoBFvDLHV4QAA"
		"AABJRU5ErkJggg==\") }\n");

	if(has_metadata) {
		// Styles for header name and value
		dbuf_fputs(ofile, " .hn { color: #aaa; text-align:right; padding-right:0.5em }\n");
		dbuf_fputs(ofile, " .hv { color: #fff }\n");
	}

	output_css_color_block(c, ofile, charctx->pal, ".f", "color", &ectx->used_fgcol[0]);
	output_css_color_block(c, ofile, charctx->pal, ".b", "background-color", &ectx->used_bgcol[0]);

	if(ectx->used_underline) {
		dbuf_fputs(ofile, " .u { text-decoration: underline }\n");
	}

	if(ectx->used_blink) {
		dbuf_fputs(ofile, " .blink {\n"
			"  animation: blink 1s steps(1) infinite;\n"
			"  -webkit-animation: blink 1s steps(1) infinite }\n"
			" @keyframes blink { 50% { color: transparent } }\n"
			" @-webkit-keyframes blink { 50% { color: transparent } }\n");
	}
	dbuf_fputs(ofile, "</style>\n");

	dbuf_fputs(ofile, "</head>\n");
	dbuf_fputs(ofile, "<body>\n");

	if(has_metadata) {
		dbuf_fputs(ofile, "<table>");
		if(charctx->title) {
			dbuf_fputs(ofile, "<tr><td class=hn>Title: </td><td class=hv>");
			write_ucstring_to_html(c, charctx->title, ofile);
			dbuf_fputs(ofile, "</td></tr>\n");
		}
		if(charctx->artist) {
			dbuf_fputs(ofile, "<tr><td class=hn>Artist: </td><td class=hv>");
			write_ucstring_to_html(c, charctx->artist, ofile);
			dbuf_fputs(ofile, "</td></tr>\n");
		}
		if(charctx->organization) {
			dbuf_fputs(ofile, "<tr><td class=hn>Organization: </td><td class=hv>");
			write_ucstring_to_html(c, charctx->organization, ofile);
			dbuf_fputs(ofile, "</td></tr>\n");
		}
		if(charctx->creation_date) {
			dbuf_fputs(ofile, "<tr><td class=hn>Date: </td><td class=hv>");
			write_ucstring_to_html(c, charctx->creation_date, ofile);
			dbuf_fputs(ofile, "</td></tr>\n");
		}
		dbuf_fputs(ofile, "</table>\n");
	}
}

static void do_output_html_footer(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, dbuf *ofile)
{
	dbuf_fputs(ofile, "</body>\n</html>\n");
}

static void de_char_output_to_html_file(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx)
{
	de_int64 i;
	dbuf *ofile = NULL;

	if(charctx->font) {
		de_warn(c, "This file uses a custom font, which is not supported with "
			"HTML output. Use \"-opt char:output=image\" for image output.\n");
	}

	ofile = dbuf_create_output_file(c, "html", NULL);

	do_output_html_header(c, charctx, ectx, ofile);
	for(i=0; i<charctx->nscreens; i++) {
		do_output_html_screen(c, charctx, ectx, charctx->screens[i], ofile);
	}
	do_output_html_footer(c, charctx, ectx, ofile);

	dbuf_close(ofile);
}

static void do_render_character(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct deark_bitmap *img,
	de_int64 xpos, de_int64 ypos,
	de_uint32 codepoint, de_byte fgcol_idx, de_byte bgcol_idx)
{
	de_int64 xpos_in_pix, ypos_in_pix;
	de_uint32 fgcol, bgcol;
	unsigned int flags;

	xpos_in_pix = xpos * ectx->char_width_in_pixels;
	ypos_in_pix = ypos * ectx->char_height_in_pixels;

	fgcol = charctx->pal[(unsigned int)fgcol_idx];
	bgcol = charctx->pal[(unsigned int)bgcol_idx];

	flags = 0;
	if(ectx->vga_9col_mode) flags |= DE_PAINTFLAG_VGA9COL;

	de_font_paint_character_idx(c, img, ectx->font_to_use, (de_int64)codepoint,
		xpos_in_pix, ypos_in_pix, fgcol, bgcol, flags);
}

static void set_density(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct deark_bitmap *img)
{
	// FIXME: This is quick and dirty. Need to put more thought into how to
	// figure out the pixel density.

	if(charctx->no_density) return;

	if(ectx->char_height_in_pixels==16 && ectx->char_width_in_pixels==8) {
		// Assume the intended display is 640x400.
		img->density_code = DE_DENSITY_UNK_UNITS;
		img->xdens = 480.0;
		img->ydens = 400.0;
	}
	else if(ectx->char_height_in_pixels==16 && ectx->char_width_in_pixels==9) {
		// Assume the intended display is 720x400.
		img->density_code = DE_DENSITY_UNK_UNITS;
		img->xdens = 540.0;
		img->ydens = 400.0;
	}
}

static void de_char_output_screen_to_image_file(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct de_char_screen *screen)
{
	de_int64 screen_width_in_pixels, screen_height_in_pixels;
	struct deark_bitmap *img = NULL;
	int i, j;
	const struct de_char_cell *cell;
	de_byte cell_fgcol_actual;

	screen_width_in_pixels = screen->width * ectx->char_width_in_pixels;
	screen_height_in_pixels = screen->height * ectx->char_height_in_pixels;

	if(!de_good_image_dimensions(c, screen_width_in_pixels, screen_height_in_pixels)) goto done;

	img = de_bitmap_create(c, screen_width_in_pixels, screen_height_in_pixels, 3);

	set_density(c, charctx, ectx, img);

	for(j=0; j<screen->height; j++) {
		for(i=0; i<screen->width; i++) {
			if(!screen->cell_rows[j]) continue;
			cell = &screen->cell_rows[j][i];
			if(!cell) continue;

			cell_fgcol_actual = cell->fgcol;
			if(cell->bold) cell_fgcol_actual |= 0x08;

			do_render_character(c, charctx, ectx, img, i, j,
				cell->codepoint, cell_fgcol_actual, cell->bgcol);
		}
	}

	de_bitmap_write_to_file(img, NULL);
done:
	de_bitmap_destroy(img);
}

static void do_create_standard_font(deark *c, struct charextractx *ectx)
{
	de_int64 i;
	struct de_bitmap_font *font;
	const de_byte *vga_font_data;

	font = de_malloc(c, sizeof(struct de_bitmap_font));
	ectx->standard_font = font;

	vga_font_data = de_get_vga_font_ptr();

	font->num_chars = 256;
	font->nominal_width = 8;
	font->nominal_height = 16;

	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].codepoint = (de_int32)i;
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = 1;
		font->char_array[i].bitmap = (de_byte*)&vga_font_data[i*16];
	}
}

static void de_char_output_to_image_files(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx)
{
	de_int64 i;

	if(ectx->used_underline) {
		// TODO: Support underline.
		de_warn(c, "This file uses underlined characters, which are not supported with "
			"image output.\n");
	}

	if(ectx->used_blink) {
		if(charctx->font) {
			// We have no way to support both a custom font and blinking characters
			// at the same time.
			de_warn(c, "This file uses blinking characters, which are not supported.\n");
		}
		else {
			de_warn(c, "This file uses blinking characters, which are not supported with "
				"image output. Use \"-opt char:output=html\" for HTML output.\n");
		}
	}

	if(charctx->font) {
		ectx->font_to_use = charctx->font;
	}
	else {
		do_create_standard_font(c, ectx);
		ectx->font_to_use = ectx->standard_font;
	}

	if(ectx->vga_9col_mode)
		ectx->char_width_in_pixels = 9;
	else
		ectx->char_width_in_pixels = ectx->font_to_use->nominal_width;

	ectx->char_height_in_pixels = ectx->font_to_use->nominal_height;

	for(i=0; i<charctx->nscreens; i++) {
		de_char_output_screen_to_image_file(c, charctx, ectx, charctx->screens[i]);
	}

	if(ectx->standard_font) {
		de_free(c, ectx->standard_font->char_array);
		de_free(c, ectx->standard_font);
	}
}

void de_char_output_to_file(deark *c, struct de_char_context *charctx)
{
	de_int64 i;
	int outfmt = 0;
	const char *s;
	struct charextractx *ectx = NULL;

	ectx = de_malloc(c, sizeof(struct charextractx));

	if(charctx->prefer_image_output)
		outfmt = 1;

	s = de_get_ext_option(c, "char:output");
	if(s) {
		if(!de_strcmp(s, "html")) {
			outfmt = 0;
		}
		else if(!de_strcmp(s, "image")) {
			outfmt = 1;
		}
	}

	s = de_get_ext_option(c, "char:charwidth");
	if(s) {
		if(de_atoi(s)>=9) {
			ectx->vga_9col_mode = 1;
		}
	}

	for(i=0; i<charctx->nscreens; i++) {
		do_prescan_screen(c, charctx, ectx, charctx->screens[i]);
	}

	switch(outfmt) {
	case 1:
		de_char_output_to_image_files(c, charctx, ectx);
		break;
	default:
		de_char_output_to_html_file(c, charctx, ectx);
	}

	de_free(c, ectx);
}
