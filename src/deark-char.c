// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-char.c
//
// Functions related to character graphics.

#include "deark-config.h"
#include "deark-private.h"

struct screen_stats {
	de_uint32 fgcol_count[16];
	de_uint32 bgcol_count[16];
	de_uint32 most_used_fgcol;
	de_uint32 most_used_bgcol;
};

struct charextractx {
	de_byte vga_9col_mode; // Flag: Render an extra column, like VGA does
	de_byte uses_custom_font;
	de_byte used_underline;
	de_byte used_strikethru;
	de_byte used_blink;
	de_byte used_24bitcolor;
	de_byte used_fgcol[16];
	de_byte used_bgcol[16];
	struct de_bitmap_font *standard_font;
	struct de_bitmap_font *font_to_use;

	de_int64 char_width_in_pixels;
	de_int64 char_height_in_pixels;

	struct screen_stats *scrstats; // pointer to array of struct screen_stats
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
	struct charextractx *ectx, de_int64 screen_idx)
{
	const struct de_char_cell *cell;
	int i, j;
	struct de_char_screen *screen;
	de_uint32 highest_fgcol_count;
	de_uint32 highest_bgcol_count;

	screen = charctx->screens[screen_idx];

	for(j=0; j<screen->height; j++) {
		for(i=0; i<screen->width; i++) {
			if(!screen->cell_rows || !screen->cell_rows[j]) continue;
			cell = &screen->cell_rows[j][i];
			if(!cell) continue;

			if(DE_IS_PAL_COLOR(cell->fgcol)) {
				ectx->used_fgcol[cell->fgcol] = 1;
				ectx->scrstats[screen_idx].fgcol_count[cell->fgcol]++;
			}
			else {
				ectx->used_24bitcolor = 1;
			}
			if(DE_IS_PAL_COLOR(cell->bgcol)) {
				ectx->used_bgcol[cell->bgcol] = 1;
				ectx->scrstats[screen_idx].bgcol_count[cell->bgcol]++;
			}
			else {
				ectx->used_24bitcolor = 1;
			}
			if(cell->underline) ectx->used_underline = 1;
			if(cell->strikethru) ectx->used_strikethru = 1;
			if(cell->blink) ectx->used_blink = 1;
		}
	}

	// Find the most-used foreground and background (palette) colors
	highest_fgcol_count = ectx->scrstats[screen_idx].fgcol_count[0];
	highest_bgcol_count = ectx->scrstats[screen_idx].bgcol_count[0];
	ectx->scrstats->most_used_fgcol = 0;
	ectx->scrstats->most_used_bgcol = 0;

	for(i=1; i<16; i++) {
		if(ectx->scrstats[screen_idx].fgcol_count[i] > highest_fgcol_count) {
			highest_fgcol_count = ectx->scrstats[screen_idx].fgcol_count[i];
			ectx->scrstats->most_used_fgcol = (de_uint32)i;
		}
		if(ectx->scrstats[screen_idx].bgcol_count[i] > highest_bgcol_count) {
			highest_bgcol_count = ectx->scrstats[screen_idx].bgcol_count[i];
			ectx->scrstats->most_used_bgcol = (de_uint32)i;
		}
	}
}

struct span_info {
	de_uint32 fgcol, bgcol;
	de_byte underline;
	de_byte strikethru;
	de_byte blink;
	de_byte is_suppressed;
};

// This may modify sp->is_suppressed.
static void span_open(deark *c, dbuf *ofile, struct span_info *sp,
	const struct screen_stats *scrstats)
{
	int need_fgcol_attr, need_bgcol_attr;
	int need_underline, need_strikethru, need_blink;
	int attrindex = 0;
	int attrcount;
	int fgcol_is_24bit, bgcol_is_24bit;
	int need_style = 0;

	fgcol_is_24bit = !DE_IS_PAL_COLOR(sp->fgcol);
	bgcol_is_24bit = !DE_IS_PAL_COLOR(sp->bgcol);

	need_fgcol_attr = !scrstats || sp->fgcol!=scrstats->most_used_fgcol;
	need_bgcol_attr = !scrstats || sp->bgcol!=scrstats->most_used_bgcol;
	if(fgcol_is_24bit) { need_fgcol_attr=0; need_style=1; }
	if(bgcol_is_24bit) { need_bgcol_attr=0; need_style=1; }
	need_underline = (sp->underline!=0);
	need_strikethru = (sp->strikethru!=0);
	need_blink = (sp->blink!=0);

	attrcount = need_fgcol_attr + need_bgcol_attr + need_underline +
		need_strikethru + need_blink;
	if(attrcount==0 && !need_style) {
		sp->is_suppressed = 1;
		return;
	}

	sp->is_suppressed = 0;

	dbuf_fputs(ofile, "<span");

	if(attrcount==0)
		goto no_class;

	dbuf_fputs(ofile, " class=");
	if(attrcount>1) // Don't need quotes if there's only one attribute
		dbuf_fputs(ofile, "\"");

	// Classes for foreground and background colors

	if(need_fgcol_attr) {
		dbuf_fprintf(ofile, "f%c", de_get_hexchar(sp->fgcol));
		attrindex++;
	}

	if(need_bgcol_attr) {
		if(attrindex) dbuf_fputs(ofile, " ");
		dbuf_fprintf(ofile, "b%c", de_get_hexchar(sp->bgcol));
		attrindex++;
	}

	// Other attributes

	if(sp->underline) {
		if(attrindex) dbuf_fputs(ofile, " ");
		dbuf_fputs(ofile, "u");
		attrindex++;
	}
	if(sp->strikethru) {
		if(attrindex) dbuf_fputs(ofile, " ");
		dbuf_fputs(ofile, "s");
		attrindex++;
	}
	if(sp->blink) {
		if(attrindex) dbuf_fputs(ofile, " ");
		dbuf_fputs(ofile, "blink");
		attrindex++;
	}

	if(attrcount>1)
		dbuf_fputs(ofile, "\"");

no_class:
	if(fgcol_is_24bit || bgcol_is_24bit) {
		char tmpbuf[16];

		dbuf_fputs(ofile, " style=\"");
		if(fgcol_is_24bit) {
			de_color_to_css(sp->fgcol, tmpbuf, sizeof(tmpbuf));
			dbuf_fprintf(ofile, "color:%s", tmpbuf);
		}

		if(bgcol_is_24bit) {
			if(fgcol_is_24bit)
				dbuf_fputs(ofile, ";");
			de_color_to_css(sp->bgcol, tmpbuf, sizeof(tmpbuf));
			dbuf_fprintf(ofile, "background-color:%s", tmpbuf);
		}
		dbuf_fputs(ofile, "\"");
	}

	dbuf_fputs(ofile, ">");
	return;
}

static void span_close(deark *c, dbuf *ofile, struct span_info *sp)
{
	if(sp->is_suppressed) return;
	dbuf_fprintf(ofile, "</span>");
}

static void do_output_html_screen(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, de_int64 screen_idx, dbuf *ofile)
{
	const struct de_char_cell *cell;
	struct de_char_cell blank_cell;
	struct de_char_screen *screen;
	int i, j;
	de_int32 n;
	int in_span = 0;
	int need_newline = 0;
	de_uint32 active_fgcol = 0;
	de_uint32 active_bgcol = 0;
	de_byte active_underline = 0;
	de_byte active_strikethru = 0;
	de_byte active_blink = 0;
	int is_blank_char;
	struct span_info default_span;
	struct span_info cur_span;

	de_memset(&default_span, 0, sizeof(struct span_info));
	de_memset(&cur_span, 0, sizeof(struct span_info));

	screen = charctx->screens[screen_idx];

	// In case a cell is missing, we'll use this one:
	de_memset(&blank_cell, 0, sizeof(struct de_char_cell));
	blank_cell.codepoint = 32;
	blank_cell.codepoint_unicode = 32;

	dbuf_fputs(ofile, "<table class=mt><tr>\n<td>");
	dbuf_fputs(ofile, "<pre>");

	// Containing <span> with default colors.
	default_span.fgcol = ectx->scrstats[screen_idx].most_used_fgcol;
	default_span.bgcol = ectx->scrstats[screen_idx].most_used_bgcol;
	span_open(c, ofile, &default_span, NULL);

	for(j=0; j<screen->height; j++) {
		for(i=0; i<screen->width; i++) {
			if(!screen->cell_rows || !screen->cell_rows[j]) {
				cell = &blank_cell;
			}
			else {
				cell = &screen->cell_rows[j][i];
				if(!cell) cell = &blank_cell;
			}

			n = cell->codepoint_unicode;

			if((cell->size_flags&DE_PAINTFLAG_RIGHTHALF) ||
				(cell->size_flags&DE_PAINTFLAG_BOTTOMHALF))
			{
				// We don't support double-size characters with HTML output.
				// Make the left / bottom parts of the cell blank so we don't
				// duplicate the foreground character.
				n = 0x20;
			}

			if(n==0x00) n=0x20;
			if(n<0x20) n='?';
			is_blank_char = (n==0x20 || n==0xa0) &&
				!cell->underline && !cell->strikethru;

			// Optimization: If this is a blank character, ignore a foreground color
			// mismatch, because it won't be visible anyway. (Many other similar
			// optimizations are also possible, but that could get very complex.)
			if(in_span==0 ||
				(cell->fgcol!=active_fgcol && !is_blank_char) ||
				cell->bgcol!=active_bgcol ||
				cell->underline!=active_underline ||
				cell->strikethru!=active_strikethru ||
				cell->blink!=active_blink)
			{
				if(in_span) {
					span_close(c, ofile, &cur_span);
					in_span=0;
				}

				if(need_newline) {
					dbuf_fputs(ofile, "\n");
					need_newline = 0;
				}

				cur_span.fgcol = cell->fgcol;
				cur_span.bgcol = cell->bgcol;
				cur_span.underline = cell->underline;
				cur_span.strikethru = cell->strikethru;
				cur_span.blink = cell->blink;
				span_open(c, ofile, &cur_span, &ectx->scrstats[screen_idx]);

				in_span=1;
				active_fgcol = cell->fgcol;
				active_bgcol = cell->bgcol;
				active_underline = cell->underline;
				active_strikethru = cell->strikethru;
				active_blink = cell->blink;
			}

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

	if(in_span) {
		span_close(c, ofile, &cur_span);
	}

	// Close containing <span>
	span_close(c, ofile, &default_span);

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

static void write_ucstring_to_html(deark *c, const de_ucstring *s, dbuf *f)
{
	de_int64 i;
	int prev_space = 0;
	de_int32 ch;

	if(!s) return;

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

static void print_header_item(deark *c, dbuf *ofile, const char *name_rawhtml, const de_ucstring *value)
{
	int k;

	dbuf_fputs(ofile, "<td class=htc>");
	if(value && value->len>0) {
		dbuf_fprintf(ofile, "<span class=hn>%s:&nbsp; </span><span class=hv>", name_rawhtml);
		write_ucstring_to_html(c, value, ofile);
		dbuf_fputs(ofile, "</span>");
	}
	else {
		// Placeholder
		for(k=0; k<20; k++) {
			de_write_codepoint_to_html(c, ofile, 0x00a0); // nbsp
		}
	}
	dbuf_fputs(ofile, "</td>\n");
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
	dbuf_fprintf(ofile, "<meta charset=\"%s\">\n", c->ascii_html?"US-ASCII":"UTF-8");
	dbuf_fputs(ofile, "<title>");
	write_ucstring_to_html(c, charctx->title, ofile);
	dbuf_fputs(ofile, "</title>\n");

	dbuf_fputs(ofile, "<style type=\"text/css\">\n");

	dbuf_fputs(ofile, " body { background-color: #222; background-image: url(\"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEUgICAoKCidji3LAAAAMUlE"
		"QVQI12NgaGBgPMDA/ICB/QMD/w8G+T8M9v8Y6v8z/P8PIoFsoAhQHCgLVMN4AACOoBFvDLHV4QAA"
		"AABJRU5ErkJggg==\") }\n");

	// The table for the main graphics
	dbuf_fputs(ofile, " .mt { margin-left: auto; margin-right: auto }\n");

	if(has_metadata) {
		// Styles for header name and value
		dbuf_fputs(ofile, " .htt { width: 100%; border-collapse: collapse; background-color: #034 }\n");
		dbuf_fputs(ofile, " .htc { border: 2px solid #056; text-align: center }\n");
		dbuf_fputs(ofile, " .hn { color: #aaa; font-style: italic }\n");
		dbuf_fputs(ofile, " .hv { color: #fff }\n");
	}

	output_css_color_block(c, ofile, charctx->pal, ".f", "color", &ectx->used_fgcol[0]);
	output_css_color_block(c, ofile, charctx->pal, ".b", "background-color", &ectx->used_bgcol[0]);

	if(ectx->used_underline) {
		dbuf_fputs(ofile, " .u { text-decoration: underline }\n");
	}
	if(ectx->used_strikethru) {
		dbuf_fputs(ofile, " .s { text-decoration: line-through }\n");
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
		dbuf_fputs(ofile, "<table class=htt><tr>\n");
		print_header_item(c, ofile, "Title", charctx->title);
		print_header_item(c, ofile, "Organization", charctx->organization);
		print_header_item(c, ofile, "Artist", charctx->artist);
		print_header_item(c, ofile, "Date", charctx->creation_date);
		dbuf_fputs(ofile, "</tr></table>\n");
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

	if(charctx->font && !charctx->suppress_custom_font_warning) {
		de_warn(c, "This file uses a custom font, which is not supported with "
			"HTML output.\n");
	}

	if(ectx->used_24bitcolor) {
		de_msg(c, "Note: This file uses 24-bit colors, which are supported but "
			"not optimized. The HTML file may be very large.\n");
	}

	ofile = dbuf_create_output_file(c, "html", NULL);

	do_output_html_header(c, charctx, ectx, ofile);
	for(i=0; i<charctx->nscreens; i++) {
		do_output_html_screen(c, charctx, ectx, i, ofile);
	}
	do_output_html_footer(c, charctx, ectx, ofile);

	dbuf_close(ofile);
}

static void do_render_character(deark *c, struct de_char_context *charctx,
	struct charextractx *ectx, struct deark_bitmap *img,
	de_int64 xpos, de_int64 ypos,
	de_int32 codepoint, int codepoint_is_unicode,
	de_uint32 fgcol, de_uint32 bgcol,
	unsigned int extra_flags)
{
	de_int64 xpos_in_pix, ypos_in_pix;
	de_uint32 fgcol_rgb, bgcol_rgb;
	unsigned int flags;

	xpos_in_pix = xpos * ectx->char_width_in_pixels;
	ypos_in_pix = ypos * ectx->char_height_in_pixels;

	if(DE_IS_PAL_COLOR(fgcol))
		fgcol_rgb = charctx->pal[fgcol];
	else
		fgcol_rgb = fgcol;
	if(DE_IS_PAL_COLOR(bgcol))
		bgcol_rgb = charctx->pal[bgcol];
	else
		bgcol_rgb = bgcol;

	flags = extra_flags;
	if(ectx->vga_9col_mode) flags |= DE_PAINTFLAG_VGA9COL;

	if(codepoint_is_unicode) {
		de_font_paint_character_cp(c, img, ectx->font_to_use, codepoint,
			xpos_in_pix, ypos_in_pix, fgcol_rgb, bgcol_rgb, flags);
	}
	else {
		de_font_paint_character_idx(c, img, ectx->font_to_use, (de_int64)codepoint,
			xpos_in_pix, ypos_in_pix, fgcol_rgb, bgcol_rgb, flags);
	}
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
	unsigned int flags;

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

			flags = cell->size_flags;

			do_render_character(c, charctx, ectx, img, i, j,
				ectx->uses_custom_font ? cell->codepoint : cell->codepoint_unicode,
				ectx->uses_custom_font ? 0 : 1,
				cell->fgcol, cell->bgcol, flags);

			// TODO: It might be better to draw our own underline and/or
			// strikethru marks, rather than relying on font glyphs that
			// might be customized or otherwise sub-optimal.
			if(cell->underline) {
				do_render_character(c, charctx, ectx, img, i, j,
					0x5f, 1, cell->fgcol, cell->bgcol, flags|DE_PAINTFLAG_TRNSBKGD);
			}
			if(cell->strikethru) {
				do_render_character(c, charctx, ectx, img, i, j,
					0x2d, 1, cell->fgcol, cell->bgcol, flags|DE_PAINTFLAG_TRNSBKGD);
			}
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
	font->has_unicode_codepoints = 1;

	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].codepoint = (de_int32)i;
		font->char_array[i].codepoint_unicode = de_char_to_unicode(c, (de_int32)i, DE_ENCODING_CP437_G);
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

	if(ectx->used_blink) {
		de_warn(c, "This file uses blinking characters, which are not supported with "
			"image output.\n");
	}

	if(charctx->font) {
		ectx->uses_custom_font = 1;
		ectx->font_to_use = charctx->font;
	}
	else {
		ectx->uses_custom_font = 0;
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
	int n;
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

	if(charctx->prefer_9col_mode) {
		ectx->vga_9col_mode = 1;
	}

	s = de_get_ext_option(c, "char:charwidth");
	if(s) {
		n = de_atoi(s);
		if(n>=9) {
			ectx->vga_9col_mode = 1;
		}
		else if(n>=1) {
			ectx->vga_9col_mode = 0;
		}
	}

	ectx->scrstats = de_malloc(c, charctx->nscreens * sizeof(struct screen_stats));

	for(i=0; i<charctx->nscreens; i++) {
		do_prescan_screen(c, charctx, ectx, i);
	}

	switch(outfmt) {
	case 1:
		de_char_output_to_image_files(c, charctx, ectx);
		break;
	default:
		de_char_output_to_html_file(c, charctx, ectx);
	}

	if(ectx) {
		de_free(c, ectx->scrstats);
	}
	de_free(c, ectx);
}
