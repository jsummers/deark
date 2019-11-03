// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-font.c
//
// Functions related to fonts.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

static int is_valid_char(struct de_bitmap_font_char *ch)
{
	if(!ch) return 0;
	if(!ch->bitmap) return 0;
	if(ch->width<1 || ch->height<1) return 0;
	return 1;
}

struct de_bitmap_font *de_create_bitmap_font(deark *c)
{
	struct de_bitmap_font *font;
	font = de_malloc(c, sizeof(struct de_bitmap_font));
	font->index_of_replacement_char = -1;
	return font;
}

void de_destroy_bitmap_font(deark *c, struct de_bitmap_font *font)
{
	de_free(c, font);
}

static void paint_character_internal(deark *c, de_bitmap *img,
	struct de_bitmap_font_char *ch,
	i64 xpos, i64 ypos, u32 fgcol, unsigned int flags)
{
	i64 i, j;
	i64 num_x_pixels_to_paint;
	int vga9col_flag = 0;

	num_x_pixels_to_paint = (i64)ch->width;
	if((flags&DE_PAINTFLAG_VGA9COL) && ch->width==8) {
		vga9col_flag = 1;
		num_x_pixels_to_paint = 9;
	}

	for(j=0; j<ch->height; j++) {
		i64 j_src;

		j_src = j;
		if(flags&DE_PAINTFLAG_TOPHALF) {
			j_src = j/2;
		}
		else if(flags&DE_PAINTFLAG_BOTTOMHALF) {
			j_src = (ch->height+j)/2;
		}

		for(i=0; i<num_x_pixels_to_paint; i++) {
			i64 i_src; // -1 = No source position
			int is_fg = 0;
			u8 x;

			i_src = i;
			if(flags&DE_PAINTFLAG_LEFTHALF) {
				i_src = i/2;
			}
			else if(flags&DE_PAINTFLAG_RIGHTHALF) {
				i_src = (num_x_pixels_to_paint+i)/2;
			}

			if(i_src==8 && vga9col_flag) {
				// Manufacture a column 8.
				if(ch->codepoint_nonunicode>=0xb0 && ch->codepoint_nonunicode<=0xdf) {
					i_src = 7; // Make this pixel a duplicate of the one in col #7.
				}
				else {
					i_src = -1; // Make this pixel a background pixel.
				}
			}

			if(i_src>=0 && i_src<ch->width) {
				x = ch->bitmap[j_src*ch->rowspan + i_src/8];
				if(x & (1<<(7-i_src%8))) {
					is_fg = 1;
				}
			}

			if(is_fg) {
				u32 clr = fgcol;

				de_bitmap_setpixel_rgba(img, xpos+i, ypos+j, clr);
			}
		}
	}
}

// Paint a character at the given index in the given font, to the given bitmap.
void de_font_paint_character_idx(deark *c, de_bitmap *img,
	struct de_bitmap_font *font, i64 char_idx,
	i64 xpos, i64 ypos, u32 fgcol, u32 bgcol,
	unsigned int flags)
{
	struct de_bitmap_font_char *ch;

	if(char_idx<0 || char_idx>=font->num_chars) return;
	ch = &font->char_array[char_idx];
	if(!is_valid_char(ch)) return;
	if(ch->width > font->nominal_width) return;
	if(ch->height > font->nominal_height) return;

	// Paint a "canvas" for the char, if needed.

	// If the "extraspace" feature is used, paint an additional canvas of
	// a different color.
	if(!(flags&DE_PAINTFLAG_TRNSBKGD) && (ch->extraspace_l || ch->extraspace_r)) {
		i64 canvas_x, canvas_y;
		i64 canvas_w, canvas_h;

		canvas_x = xpos;
		canvas_y = ypos+ch->v_offset;
		canvas_w = (i64)ch->extraspace_l + (i64)ch->width + (i64)ch->extraspace_r;
		canvas_h = ch->height;
		// (We don't need to support both the "extraspace" and the VGA9COL
		// feature at the same time.)

		de_bitmap_rect(img, canvas_x, canvas_y,
			canvas_w, canvas_h, DE_MAKE_RGB(192,255,192), 0);
	}

	// Paint the canvas for the main part of the character.
	if(!(flags&DE_PAINTFLAG_TRNSBKGD)) {
		i64 canvas_x, canvas_y;
		i64 canvas_w, canvas_h;

		canvas_x = xpos + ch->extraspace_l;
		canvas_y = ypos+ch->v_offset;
		canvas_w = ch->width;
		if((flags&DE_PAINTFLAG_VGA9COL) && ch->width==8) {
			canvas_w++;
		}
		canvas_h = ch->height;

		de_bitmap_rect(img, canvas_x, canvas_y,
			canvas_w, canvas_h, bgcol, 0);
	}

	paint_character_internal(c, img, ch,
		ch->extraspace_l + xpos, ch->v_offset + ypos, fgcol, flags);
}

// Given a codepoint, returns the character index in the font.
// 'codepoint' is expected to be a Unicode codepoint. If the font does not
// have Unicode codepoints, the non-Unicode codepoint will be used instead.
// Returns -1 if not found.
static i64 get_char_idx_by_cp(deark *c, struct de_bitmap_font *font, i32 codepoint)
{
	i64 i;

	// TODO: Sometimes, a font has multiple characters that map to the same
	// codepoint. We should have a way to find the *best* such character,
	// which might not be the first one.

	for(i=0; i<font->num_chars; i++) {
		if(font->has_unicode_codepoints) {
			if(font->char_array[i].codepoint_unicode == codepoint)
				return i;
		}
		else {
			if(font->char_array[i].codepoint_nonunicode == codepoint)
				return i;
		}
	}
	return -1;
}

// 'codepoint' is expected to be a Unicode codepoint. If the font does not
// have Unicode codepoints, the non-Unicode codepoint will be used instead.
void de_font_paint_character_cp(deark *c, de_bitmap *img,
	struct de_bitmap_font *font, i32 codepoint,
	i64 xpos, i64 ypos, u32 fgcol, u32 bgcol, unsigned int flags)
{
	i64 char_idx;

	char_idx = get_char_idx_by_cp(c, font, codepoint);
	if(char_idx<0) {
		if(font->index_of_replacement_char>=0) {
			char_idx = font->index_of_replacement_char;
		}
	}
	if(char_idx<0) {
		char_idx = get_char_idx_by_cp(c, font, '?');
	}
	if(char_idx<0 || char_idx>=font->num_chars) {
		return;
	}
	de_font_paint_character_idx(c, img, font, char_idx, xpos, ypos, fgcol, bgcol, flags);
}

struct dfont_char_data {
	i32 codepoint_unicode;
	u8 bitmap[7];
};

static const struct dfont_char_data dfont_data[16] = {
	{48, {0x30,0x48,0x48,0x48,0x48,0x48,0x30}}, // 0
	{49, {0x10,0x30,0x10,0x10,0x10,0x10,0x38}}, // 1
	{50, {0x70,0x08,0x08,0x30,0x40,0x40,0x78}}, // 2
	{51, {0x70,0x08,0x08,0x30,0x08,0x08,0x70}}, // 3
	{52, {0x48,0x48,0x48,0x78,0x08,0x08,0x08}}, // 4
	{53, {0x78,0x40,0x40,0x70,0x08,0x08,0x70}}, // 5
	{54, {0x38,0x40,0x40,0x70,0x48,0x48,0x30}}, // 6
	{55, {0x78,0x08,0x08,0x10,0x10,0x10,0x10}}, // 7
	{56, {0x30,0x48,0x48,0x30,0x48,0x48,0x30}}, // 8
	{57, {0x30,0x48,0x48,0x38,0x08,0x08,0x70}}, // 9
	{65, {0x30,0x48,0x48,0x78,0x48,0x48,0x48}}, // A
	{66, {0x70,0x48,0x48,0x70,0x48,0x48,0x70}}, // B
	{67, {0x30,0x48,0x40,0x40,0x40,0x48,0x30}}, // C
	{68, {0x70,0x58,0x48,0x48,0x48,0x58,0x70}}, // D
	{69, {0x78,0x40,0x40,0x70,0x40,0x40,0x78}}, // E
	{70, {0x78,0x40,0x40,0x70,0x40,0x40,0x40}}  // F
};

static struct de_bitmap_font *make_digit_font(deark *c)
{
	struct de_bitmap_font *dfont = NULL;
	i64 i;

	dfont = de_create_bitmap_font(c);
	dfont->num_chars = 16;
	dfont->nominal_width = 6;
	dfont->nominal_height = 7;
	dfont->has_unicode_codepoints = 1;
	dfont->char_array = de_mallocarray(c, dfont->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<dfont->num_chars; i++) {
		dfont->char_array[i].codepoint_unicode = dfont_data[i].codepoint_unicode;
		dfont->char_array[i].width = dfont->nominal_width;
		dfont->char_array[i].height = dfont->nominal_height;
		dfont->char_array[i].rowspan = 1;
		dfont->char_array[i].bitmap = (u8*)dfont_data[i].bitmap;
	}

	return dfont;
}

struct font_render_ctx {
	struct de_bitmap_font *font;
	i32 min_codepoint; // currently unused
	i32 max_codepoint;
	i64 num_valid_chars;
	int render_as_unicode;

	// Array of the actual codepoints we will use when dumping the font
	// to an image. Size is font->num_chars.
	i32 *codepoint_tmp;
};

#define DNFLAG_HEX            0x1
#define DNFLAG_LEADING_ZEROES 0x2
#define DNFLAG_HCENTER        0x4

// (xpos,ypos) is the lower-right corner
//   (or the bottom-center, if hcenter==1).
static void draw_number(deark *c, de_bitmap *img,
	struct de_bitmap_font *dfont, i64 n, i64 xpos1, i64 ypos1,
	unsigned int flags)
{
	char buf[32];
	i64 len;
	i64 i;
	i64 xpos_start;
	i64 xpos, ypos;

	if(flags & DNFLAG_HEX) {
		if(flags & DNFLAG_LEADING_ZEROES)
			de_snprintf(buf, sizeof(buf), "%04X", (unsigned int)n);
		else
			de_snprintf(buf, sizeof(buf), "%X", (unsigned int)n);
	}
	else {
		de_snprintf(buf, sizeof(buf), "%u", (unsigned int)n);
	}
	len = (i64)de_strlen(buf);

	if(flags & DNFLAG_HCENTER)
		xpos_start = xpos1-(dfont->nominal_width*len)/2;
	else
		xpos_start = xpos1-dfont->nominal_width*len;

	// Make sure number doesn't go beyond the image
	if(xpos_start + dfont->nominal_width*len > img->width) {
		xpos_start = img->width - dfont->nominal_width*len;
	}

	for(i=len-1; i>=0; i--) {
		xpos = xpos_start + dfont->nominal_width*i;
		ypos = ypos1-dfont->nominal_height;
		de_font_paint_character_cp(c, img, dfont, buf[i], xpos, ypos,
			DE_MAKE_GRAY(255), 0, DE_PAINTFLAG_TRNSBKGD);
	}
}

static void get_min_max_codepoint(struct font_render_ctx *fctx)
{
	i64 i;

	fctx->min_codepoint = 0x10ffff;
	fctx->max_codepoint = 0;
	fctx->num_valid_chars = 0;

	for(i=0; i<fctx->font->num_chars; i++) {
		if(!is_valid_char(&fctx->font->char_array[i])) continue;
		if(fctx->codepoint_tmp[i] == DE_CODEPOINT_INVALID) continue;
		fctx->num_valid_chars++;
		if(fctx->codepoint_tmp[i] < fctx->min_codepoint)
			fctx->min_codepoint = fctx->codepoint_tmp[i];
		if(fctx->codepoint_tmp[i] > fctx->max_codepoint)
			fctx->max_codepoint = fctx->codepoint_tmp[i];
	}
}

// Put the actual codepont to use in the font->char_array[].codepoint_tmp field.
static void fixup_codepoints(deark *c, struct font_render_ctx *fctx)
{
	i64 i;
	i32 c1;
	i64 num_uncoded_chars = 0;
	u8 *used_codepoint_map = NULL;
	u8 codepoint_already_used;

	if(!fctx->render_as_unicode) {
		for(i=0; i<fctx->font->num_chars; i++) {
			fctx->codepoint_tmp[i] = fctx->font->char_array[i].codepoint_nonunicode;
		}
		goto done;
	}

	// An array of bits to remember if we've seen a codepoint before (BMP only).
	// A character with a duplicate codepoint will be moved to another
	// location, so that it doesn't get painted over the previous one.
	used_codepoint_map = de_malloc(c, 65536/8);

	for(i=0; i<fctx->font->num_chars; i++) {
		if(!is_valid_char(&fctx->font->char_array[i])) continue;
		c1 = fctx->font->char_array[i].codepoint_unicode;

		codepoint_already_used = 0;
		if(c1>=0 && c1<65536) {
			// Check if we've seen this codepoint before.
			codepoint_already_used = used_codepoint_map[c1/8] & (1<<(c1%8));

			// Remember that we've seen this codepoint.
			used_codepoint_map[c1/8] |= 1<<(c1%8);
		}

		if(codepoint_already_used || c1==DE_CODEPOINT_INVALID) {
			if(codepoint_already_used) {
				de_dbg2(c, "moving duplicate codepoint U+%04x at index %d to private use area",
					(unsigned int)c1, (int)i);
			}
			// Move uncoded characters to a Private Use area.
			// (Supplementary Private Use Area-A = U+F0000 - U+FFFFD)
			if(DE_CODEPOINT_MOVED + num_uncoded_chars <= DE_CODEPOINT_MOVED_MAX) {
				fctx->codepoint_tmp[i] = (i32)(DE_CODEPOINT_MOVED + num_uncoded_chars);
				num_uncoded_chars++;
			}
		}
		else {
			fctx->codepoint_tmp[i] = c1;
		}
	}

done:
	de_free(c, used_codepoint_map);
}

struct row_info_struct {
	u8 is_visible;
	i64 display_pos;
};

struct col_info_struct {
	i64 display_width;
	i64 display_pos;
};

static void checkerboard_bkgd(de_bitmap *img, i64 xpos, i64 ypos, i64 w, i64 h)
{
	i64 ii, jj;

	for(jj=0; jj<h; jj++) {
		for(ii=0; ii<w; ii++) {
			de_bitmap_setpixel_gray(img, xpos+ii, ypos+jj, (ii/2+jj/2)%2 ? 176 : 192);
		}
	}
}

void de_font_bitmap_font_to_image(deark *c, struct de_bitmap_font *font1, de_finfo *fi,
	unsigned int createflags)
{
	struct font_render_ctx *fctx = NULL;
	i64 i, j, k;
	de_bitmap *img = NULL;
	i64 xpos, ypos;
	i64 img_leftmargin, img_topmargin;
	i64 img_rightmargin, img_bottommargin;
	i64 img_vpixelsperchar;
	i64 img_width, img_height;
	i64 num_table_rows_to_display;
	i64 num_table_rows_total;
	i64 last_valid_row;
	struct de_bitmap_font *dfont = NULL;
	i64 chars_per_row = 32;
	const char *s;
	struct row_info_struct *row_info = NULL;
	struct col_info_struct *col_info = NULL;
	int unicode_req = 0;
	i64 label_stride;
	i64 rownum, colnum;
	i64 curpos;
	unsigned int dnflags;

	fctx = de_malloc(c, sizeof(struct font_render_ctx));
	fctx->font = font1;

	if(fctx->font->num_chars<1) goto done;
	if(fctx->font->num_chars>17*65536) goto done;
	if(fctx->font->nominal_width>512 || fctx->font->nominal_height>512) {
		de_err(c, "Font size too big (%d"DE_CHAR_TIMES"%d). Not supported.",
			(int)fctx->font->nominal_width, (int)fctx->font->nominal_height);
		goto done;
	}

	// -1 = "no preference"
	unicode_req = de_get_ext_option_bool(c, "font:tounicode", -1);

	if(unicode_req==0 &&
		(fctx->font->has_nonunicode_codepoints || !fctx->font->has_unicode_codepoints))
	{
		; // Render as nonunicode.
	}
	else if(fctx->font->has_unicode_codepoints &&
		(unicode_req>0 || fctx->font->prefer_unicode || !fctx->font->has_nonunicode_codepoints))
	{
		fctx->render_as_unicode = 1;
	}

	s = de_get_ext_option(c, "font:charsperrow");
	if(s) {
		chars_per_row = de_atoi64(s);
		if(chars_per_row<1) chars_per_row=1;
	}

	dfont = make_digit_font(c);

	fctx->codepoint_tmp = de_mallocarray(c, fctx->font->num_chars, sizeof(i32));
	fixup_codepoints(c, fctx);

	get_min_max_codepoint(fctx);
	if(fctx->num_valid_chars<1) goto done;
	num_table_rows_total = fctx->max_codepoint/chars_per_row+1;

	// TODO: Clean up these margin calculations, and make it more general.
	if(fctx->render_as_unicode) {
		img_leftmargin = (i64)dfont->nominal_width * 5 + 6;
	}
	else {
		if(fctx->max_codepoint >= 1000)
			img_leftmargin = (i64)dfont->nominal_width * 5 + 6;
		else
			img_leftmargin = (i64)dfont->nominal_width * 3 + 6;
	}
	img_topmargin = (i64)dfont->nominal_height + 6;
	img_rightmargin = 1;
	img_bottommargin = 1;

	// Scan the characters, and record relevant information.
	row_info = de_mallocarray(c, num_table_rows_total, sizeof(struct row_info_struct));
	col_info = de_mallocarray(c, chars_per_row, sizeof(struct col_info_struct));
	for(i=0; i<chars_per_row; i++) {
#define MIN_CHAR_CELL_WIDTH 5
		col_info[i].display_width = MIN_CHAR_CELL_WIDTH;
	}

	for(k=0; k<fctx->font->num_chars; k++) {
		i64 char_display_width;

		if(fctx->codepoint_tmp[k] == DE_CODEPOINT_INVALID) continue;
		if(!is_valid_char(&fctx->font->char_array[k])) continue;
		rownum = fctx->codepoint_tmp[k] / chars_per_row;
		colnum = fctx->codepoint_tmp[k] % chars_per_row;
		if(rownum<0 || rownum>=num_table_rows_total) {
			de_err(c, "internal: bad rownum");
			de_fatalerror(c);
		}

		// Remember that there is at least one valid character in this character's row.
		row_info[rownum].is_visible = 1;

		// Track the maximum width of any character in this character's column.
		char_display_width = (i64)fctx->font->char_array[k].width +
				(i64)fctx->font->char_array[k].extraspace_l +
				(i64)fctx->font->char_array[k].extraspace_r;
		if(char_display_width > col_info[colnum].display_width) {
			col_info[colnum].display_width = char_display_width;
		}
	}

	img_vpixelsperchar = (i64)fctx->font->nominal_height + 1;

	// Figure out how many rows are used, and where to draw them.
	num_table_rows_to_display = 0;
	last_valid_row = -1;
	curpos = img_topmargin;
	for(j=0; j<num_table_rows_total; j++) {
		if(!row_info[j].is_visible) continue;

		// If we skipped one or more rows, leave some extra vertical space.
		if(num_table_rows_to_display>0 && !row_info[j-1].is_visible) curpos+=3;

		last_valid_row = j;
		row_info[j].display_pos = curpos;
		curpos += img_vpixelsperchar;
		num_table_rows_to_display++;
	}
	if(num_table_rows_to_display<1) goto done;

	// Figure out the positions of the columns.
	curpos = img_leftmargin;
	for(i=0; i<chars_per_row; i++) {
		col_info[i].display_pos = curpos;
		curpos += col_info[i].display_width + 1;
	}

	img_width = col_info[chars_per_row-1].display_pos +
		col_info[chars_per_row-1].display_width + img_rightmargin;
	img_height = row_info[last_valid_row].display_pos +
		img_vpixelsperchar -1 + img_bottommargin;

	img = de_bitmap_create(c, img_width, img_height, 3);

	// Clear the image
	de_bitmap_rect(img, 0, 0, img->width, img->height, DE_MAKE_RGB(32,32,144), 0);

	// Draw/clear the cell backgrounds
	for(j=0; j<num_table_rows_total; j++) {
		if(!row_info[j].is_visible) continue;
		ypos = row_info[j].display_pos;

		for(i=0; i<chars_per_row; i++) {
			xpos = col_info[i].display_pos;
			de_bitmap_rect(img, xpos, ypos,
				col_info[i].display_width, img_vpixelsperchar-1,
				DE_MAKE_RGB(112,112,160), 0);
		}
	}

	// Draw the labels in the top margin.

	// TODO: Better label spacing logic.
	if(fctx->font->nominal_width <= 12)
		label_stride = 2;
	else
		label_stride = 1;

	for(i=0; i<chars_per_row; i++) {
		if(i%label_stride != 0) continue;
		xpos = col_info[i].display_pos + col_info[i].display_width/2;
		ypos = img_topmargin - 3;

		dnflags = DNFLAG_HCENTER;
		if(fctx->render_as_unicode) dnflags |= DNFLAG_HEX;

		draw_number(c, img, dfont, i, xpos, ypos, dnflags);
	}

	// Draw the labels in the left margin.
	for(j=0; j<num_table_rows_total; j++) {
		if(!row_info[j].is_visible) continue;
		xpos = img_leftmargin - 3;
		ypos = row_info[j].display_pos + (img_vpixelsperchar + dfont->nominal_height + 1)/2;

		dnflags = 0;
		if(fctx->render_as_unicode) dnflags |= DNFLAG_HEX | DNFLAG_LEADING_ZEROES;

		draw_number(c, img, dfont, j*chars_per_row, xpos, ypos, dnflags);
	}

	// Render the glyphs.
	for(k=0; k<fctx->font->num_chars; k++) {
		if(fctx->codepoint_tmp[k] == DE_CODEPOINT_INVALID) continue;
		if(!is_valid_char(&fctx->font->char_array[k])) continue;

		rownum = fctx->codepoint_tmp[k] / chars_per_row;
		colnum = fctx->codepoint_tmp[k] % chars_per_row;
		if(rownum<0 || rownum>=num_table_rows_total) {
			de_err(c, "internal: bad rownum");
			de_fatalerror(c);
		}

		xpos = col_info[colnum].display_pos;
		ypos = row_info[rownum].display_pos;

		checkerboard_bkgd(img, xpos, ypos,
			col_info[colnum].display_width, img_vpixelsperchar-1);

		de_font_paint_character_idx(c, img, fctx->font, k, xpos, ypos,
			DE_STOCKCOLOR_BLACK, DE_STOCKCOLOR_WHITE, 0);
	}

	de_bitmap_write_to_file_finfo(img, fi, createflags);

done:
	if(dfont) {
		de_free(c, dfont->char_array);
		de_destroy_bitmap_font(c, dfont);
	}
	de_bitmap_destroy(img);
	de_free(c, row_info);
	de_free(c, col_info);
	if(fctx) {
		de_free(c, fctx->codepoint_tmp);
		de_free(c, fctx);
	}
}

// Do we recognize the font as a standard VGA CP437 font?
// This function is quick and dirty. Ideally we would:
// * look at each character, instead or requiring the whole font to be identical
// * recognize fonts with other character sets
int de_font_is_standard_vga_font(deark *c, u32 crc)
{
	switch(crc) {
	case 0x2c3cf7d2U: // e.g.: ndh - Ada.xb
	case 0x3c0aa3eeU: // https://commons.wikimedia.org/w/index.php?title=File:Codepage-437.png&oldid=153353189
	case 0x71e15998U: // Used in many XBIN files.
	case 0xb6133c6eU: // blocktronics_baud_dudes/k1-strax.xb (8x14)
	case 0xb7cb6e5cU: // e.g.: T1-XBIN.XB
		return 1;
	}
	return 0;
}
