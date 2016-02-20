// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-font.c
//
// Functions related to fonts.

#include "deark-config.h"
#include "deark-private.h"

static int is_valid_char(struct de_bitmap_font_char *ch)
{
	if(!ch) return 0;
	if(!ch->bitmap) return 0;
	if(ch->width<1 || ch->height<1) return 0;
	return 1;
}

void de_font_paint_character_idx(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int64 char_idx,
	de_int64 xpos, de_int64 ypos, de_uint32 fgcol, de_uint32 bgcol,
	unsigned int flags)
{
	de_int64 i, j;
	de_int64 i_src, j_src;
	de_byte x;
	int fg;
	de_uint32 clr;
	struct de_bitmap_font_char *ch;

	if(char_idx<0 || char_idx>=font->num_chars) return;
	ch = &font->char_array[char_idx];
	if(!is_valid_char(ch)) return;
	if(ch->width > font->nominal_width) return;
	if(ch->height > font->nominal_height) return;

	for(j=0; j<ch->height; j++) {
		j_src = j;
		if(flags&DE_PAINTFLAG_TOPHALF) {
			j_src = j/2;
		}
		else if(flags&DE_PAINTFLAG_BOTTOMHALF) {
			j_src = (ch->height+j)/2;
		}

		for(i=0; i<ch->width; i++) {
			i_src = i;
			if(flags&DE_PAINTFLAG_LEFTHALF) {
				i_src = i/2;
			}
			else if(flags&DE_PAINTFLAG_RIGHTHALF) {
				i_src = (ch->width+i)/2;
			}

			x = ch->bitmap[j_src*ch->rowspan + i_src/8];
			fg = (x & (1<<(7-i_src%8))) ? 1 : 0;
			clr = fg ? fgcol : bgcol;
			if(fg || !(flags&DE_PAINTFLAG_TRNSBKGD))
				de_bitmap_setpixel_rgba(img, xpos+i, ypos+j, clr);

			// Manufacture a 9th column, if requested.
			// FIXME: 9 column mode interacts poorly with double-width characters.
			if((flags&DE_PAINTFLAG_VGA9COL) && i==7) {
				// Depending on the codepoint, the 9th column is either
				// the same as the 8th column, or is the background color.
				if(ch->codepoint<0xb0 || ch->codepoint>0xdf) {
					fg = 0;
					clr = bgcol;
				}
				if(fg || !(flags&DE_PAINTFLAG_TRNSBKGD))
					de_bitmap_setpixel_rgba(img, xpos+i+1, ypos+j, clr);
			}
		}
	}
}

// Given a codepoint, returns the character index in the font.
// Returns -1 if not found.
static de_int64 get_char_idx_by_cp(deark *c, struct de_bitmap_font *font, de_int32 codepoint)
{
	de_int64 i;

	for(i=0; i<font->num_chars; i++) {
		if(font->has_unicode_codepoints) {
			if(font->char_array[i].codepoint_unicode == codepoint)
				return i;
		}
		else {
			if(font->char_array[i].codepoint == codepoint)
				return i;
		}
	}
	return -1;
}

void de_font_paint_character_cp(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int32 codepoint,
	de_int64 xpos, de_int64 ypos, de_uint32 fgcol, de_uint32 bgcol, unsigned int flags)
{
	de_int64 char_idx;

	char_idx = get_char_idx_by_cp(c, font, codepoint);
	if(char_idx<0) {
		// TODO: Paint a better error character
		char_idx = get_char_idx_by_cp(c, font, '?');
	}
	if(char_idx<0) {
		return;
	}
	de_font_paint_character_idx(c, img, font, char_idx, xpos, ypos, fgcol, bgcol, flags);
}

struct dfont_char_data {
	de_int32 codepoint;
	de_byte bitmap[7];
};

static const struct dfont_char_data dfont_data[16] = {
	{48, {0xf0,0x90,0x90,0x90,0x90,0x90,0xf0}}, // 0
	{49, {0x10,0x10,0x10,0x10,0x10,0x10,0x10}}, // 1
	{50, {0xf0,0x10,0x10,0xf0,0x80,0x80,0xf0}}, // 2
	{51, {0xf0,0x10,0x10,0xf0,0x10,0x10,0xf0}}, // 3
	{52, {0x90,0x90,0x90,0xf0,0x10,0x10,0x10}}, // 4
	{53, {0xf0,0x80,0x80,0xf0,0x10,0x10,0xf0}}, // 5
	{54, {0xf0,0x80,0x80,0xf0,0x90,0x90,0xf0}}, // 6
	{55, {0xf0,0x10,0x10,0x10,0x10,0x10,0x10}}, // 7
	{56, {0xf0,0x90,0x90,0xf0,0x90,0x90,0xf0}}, // 8
	{57, {0xf0,0x90,0x90,0xf0,0x10,0x10,0xf0}}, // 9
	{65, {0x60,0x90,0x90,0xf0,0x90,0x90,0x90}}, // A
	{66, {0xe0,0x90,0x90,0xe0,0x90,0x90,0xe0}}, // B
	{67, {0x60,0x90,0x80,0x80,0x80,0x90,0x60}}, // C
	{68, {0xe0,0x90,0x90,0x90,0x90,0x90,0xe0}}, // D
	{69, {0xf0,0x80,0x80,0xe0,0x80,0x80,0xf0}}, // E
	{70, {0xf0,0x80,0x80,0xe0,0x80,0x80,0x80}}  // F
};

static struct de_bitmap_font *make_digit_font(deark *c)
{
	struct de_bitmap_font *dfont = NULL;
	de_int64 i;

	dfont = de_malloc(c, sizeof(struct de_bitmap_font));
	dfont->num_chars = 16;
	dfont->nominal_width = 6;
	dfont->nominal_height = 7;
	dfont->char_array = de_malloc(c, dfont->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<dfont->num_chars; i++) {
		dfont->char_array[i].codepoint = dfont_data[i].codepoint;
		dfont->char_array[i].width = dfont->nominal_width;
		dfont->char_array[i].height = dfont->nominal_height;
		dfont->char_array[i].rowspan = 1;
		dfont->char_array[i].bitmap = (de_byte*)dfont_data[i].bitmap;
	}

	return dfont;
}

// (xpos,ypos) is the lower-right corner.
static void draw_number(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *dfont, de_int64 n, de_int64 xpos, de_int64 ypos,
	int hex, int leading_zeroes)
{
	char buf[32];
	de_int64 len;
	de_int64 i;

	if(hex) {
		if(leading_zeroes)
			de_snprintf(buf, sizeof(buf), "%04X", (unsigned int)n);
		else
			de_snprintf(buf, sizeof(buf), "%X", (unsigned int)n);
	}
	else {
		de_snprintf(buf, sizeof(buf), "%u", (unsigned int)n);
	}
	len = (de_int64)de_strlen(buf);

	for(i=len-1; i>=0; i--) {
		de_font_paint_character_cp(c, img, dfont, buf[i],
			xpos-dfont->nominal_width*(len-i), ypos-dfont->nominal_height,
			DE_MAKE_GRAY(255), 0, DE_PAINTFLAG_TRNSBKGD);
	}
}

static void get_min_max_codepoint(struct de_bitmap_font *font,
	de_int32 *mincp, de_int32 *maxcp, de_int64 *num_valid_chars)
{
	de_int64 i;

	*mincp = 0x10ffff;
	*maxcp = 0;
	*num_valid_chars = 0;

	for(i=0; i<font->num_chars; i++) {
		if(!is_valid_char(&font->char_array[i])) continue;
		(*num_valid_chars)++;
		if(font->char_array[i].codepoint_tmp < *mincp)
			*mincp = font->char_array[i].codepoint_tmp;
		if(font->char_array[i].codepoint_tmp > *maxcp)
			*maxcp = font->char_array[i].codepoint_tmp;
	}
}

// Put the actual codepont to use in the font->char_array[].codepoint_tmp field.
static void fixup_codepoints(deark *c, struct de_bitmap_font *font, int render_as_unicode)
{
	de_int64 i;
	de_int32 c1;
	de_int64 num_uncoded_chars = 0;

	for(i=0; i<font->num_chars; i++) {
		if(render_as_unicode)
			c1 = font->char_array[i].codepoint_unicode;
		else
			c1 = font->char_array[i].codepoint;

		if(render_as_unicode && !font->is_unicode && c1==0xfffd) {
			// Move uncoded characters to the Private Use area.
			font->char_array[i].codepoint_tmp = (de_int32)(0xee00 + num_uncoded_chars);
			num_uncoded_chars++;
		}
		else {
			font->char_array[i].codepoint_tmp = c1;
		}
	}
}

struct row_info_struct {
	de_byte is_visible;
	de_int64 display_index; // Number of rows displayed above this one
};

struct col_info_struct {
	de_int64 display_width;
	de_int64 display_pos_in_pixels;
};

void de_font_bitmap_font_to_image(deark *c, struct de_bitmap_font *font, de_finfo *fi)
{
	de_int64 i, j, k;
	struct deark_bitmap *img = NULL;
	de_int64 xpos, ypos;
	de_int64 img_leftmargin, img_topmargin;
	de_int64 img_rightmargin, img_bottommargin;
	de_int64 img_vpixelsperchar;
	de_int64 img_width, img_height;
	de_int64 img_fieldheight;
	de_int64 num_table_rows_total;
	de_int64 num_table_rows_rendered;
	de_int32 min_codepoint, max_codepoint;
	de_int64 num_valid_chars;
	struct de_bitmap_font *dfont = NULL;
	de_int64 chars_per_row = 32;
	const char *s;
	struct row_info_struct *row_info = NULL;
	struct col_info_struct *col_info = NULL;
	int unicode_req = 0;
	int render_as_unicode = 0;
	de_int64 label_stride;
	de_int64 rownum, colnum;
	de_int64 curpos;

	if(font->num_chars<1) goto done;
	if(font->nominal_width>128 || font->nominal_height>128) {
		de_err(c, "Font size too big. Not supported.\n");
		goto done;
	}

	s = de_get_ext_option(c, "font:tounicode");
	if(s) {
		unicode_req = de_atoi(s);
	}

	if(font->is_unicode || (font->has_unicode_codepoints && unicode_req)) {
		render_as_unicode = 1;
	}

	s = de_get_ext_option(c, "font:charsperrow");
	if(s) {
		chars_per_row = de_atoi64(s);
		if(chars_per_row<1) chars_per_row=1;
	}

	dfont = make_digit_font(c);

	if(render_as_unicode)
		img_leftmargin = dfont->nominal_width * 4 + 6;
	else
		img_leftmargin = dfont->nominal_width * 3 + 6;
	img_topmargin = dfont->nominal_height + 6;
	img_rightmargin = 1;
	img_bottommargin = 1;

	fixup_codepoints(c, font, render_as_unicode);

	get_min_max_codepoint(font, &min_codepoint, &max_codepoint, &num_valid_chars);
	if(num_valid_chars<1) goto done;
	num_table_rows_total = max_codepoint/chars_per_row+1;

	// Scan the characters, and record relevant information.
	row_info = de_malloc(c, num_table_rows_total*sizeof(struct row_info_struct));
	col_info = de_malloc(c, chars_per_row*sizeof(struct col_info_struct));
	for(i=0; i<chars_per_row; i++) {
#define MIN_CHAR_CELL_WIDTH 5
		col_info[i].display_width = MIN_CHAR_CELL_WIDTH;
	}

	for(k=0; k<font->num_chars; k++) {
		if(!is_valid_char(&font->char_array[k])) continue;
		rownum = font->char_array[k].codepoint_tmp / chars_per_row;
		colnum = font->char_array[k].codepoint_tmp % chars_per_row;

		// Remember that there is at least one valid character in this character's row.
		row_info[rownum].is_visible = 1;

		// Track the maximum width of any character in this character's column.
		if(font->char_array[k].width > col_info[colnum].display_width) {
			col_info[colnum].display_width = font->char_array[k].width;
		}
	}

	// Figure out how many rows are used, and where to draw them.
	num_table_rows_rendered = 0;
	for(i=0; i<num_table_rows_total; i++) {
		if(row_info[i].is_visible) {
			row_info[i].display_index = num_table_rows_rendered;
			num_table_rows_rendered++;
		}
	}
	if(num_table_rows_rendered<1) goto done;

	// Figure out the positions of the columns.
	curpos = img_leftmargin;
	for(i=0; i<chars_per_row; i++) {
		col_info[i].display_pos_in_pixels = curpos;
		curpos += col_info[i].display_width + 1;
	}

	img_vpixelsperchar = font->nominal_height + 1;
	img_fieldheight = num_table_rows_rendered * img_vpixelsperchar -1;
	img_width = col_info[chars_per_row-1].display_pos_in_pixels +
		col_info[chars_per_row-1].display_width + img_rightmargin;
	img_height = img_topmargin + img_fieldheight + img_bottommargin;

	img = de_bitmap_create(c, img_width, img_height, 1);

	// Clear the image
	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			de_bitmap_setpixel_gray(img, i, j, 128);
		}
	}

	// Draw/clear the cell backgrounds
	for(j=0; j<num_table_rows_total; j++) {
		if(!row_info[j].is_visible) continue;
		ypos = img_topmargin + (row_info[j].display_index)*img_vpixelsperchar;

		for(i=0; i<chars_per_row; i++) {
			de_int64 ii, jj;

			xpos = col_info[i].display_pos_in_pixels;
			for(jj=0; jj<img_vpixelsperchar-1; jj++) {
				for(ii=0; ii<col_info[i].display_width; ii++) {
					de_bitmap_setpixel_gray(img, xpos+ii, ypos+jj, 192);
				}
			}
		}
	}

	// Draw the labels in the top margin.

	// TODO: Better label spacing logic.
	if(font->nominal_width <= 12)
		label_stride = 2;
	else
		label_stride = 1;

	for(i=0; i<chars_per_row; i++) {
		if(i%label_stride != 0) continue;
		xpos = col_info[i].display_pos_in_pixels + col_info[i].display_width + 1;
		ypos = img_topmargin - 3;
		draw_number(c, img, dfont, i, xpos, ypos, render_as_unicode?1:0, 0);
	}

	// Draw the labels in the left margin.
	for(j=0; j<num_table_rows_total; j++) {
		if(!row_info[j].is_visible) continue;
		xpos = img_leftmargin - 2;
		ypos = img_topmargin + (row_info[j].display_index+1)*img_vpixelsperchar - 2;
		draw_number(c, img, dfont, j*chars_per_row, xpos, ypos,
			render_as_unicode?1:0, render_as_unicode?1:0);
	}

	// Render the glyphs.
	for(k=0; k<font->num_chars; k++) {
		rownum = font->char_array[k].codepoint_tmp / chars_per_row;
		colnum = font->char_array[k].codepoint_tmp % chars_per_row;

		xpos = col_info[colnum].display_pos_in_pixels;
		ypos = img_topmargin + (row_info[rownum].display_index) * img_vpixelsperchar;

		de_font_paint_character_idx(c, img, font, k, xpos, ypos,
			DE_STOCKCOLOR_BLACK, DE_STOCKCOLOR_WHITE, 0);
	}

	de_bitmap_write_to_file_finfo(img, fi);

done:
	if(dfont) {
		de_free(c, dfont->char_array);
		de_free(c, dfont);
	}
	de_bitmap_destroy(img);
	de_free(c, row_info);
	de_free(c, col_info);
}

// Do we recognize the font as a standard VGA CP437 font?
// This function is quick and dirty. Ideally we would:
// * look at each character, instead or requiring the whole font to be identical
// * recognize fonts with other character sets
int de_font_is_standard_vga_font(deark *c, de_uint32 crc)
{
	switch(crc) {
	case 0x2c3cf7d2U: // e.g.: ndh - Ada.xb
	case 0x3c0aa3eeU: // https://commons.wikimedia.org/w/index.php?title=File:Codepage-437.png&oldid=153353189
	case 0x71e15998U: // Used in many XBIN files.
	case 0xb7cb6e5cU: // e.g.: T1-XBIN.XB
		return 1;
	}
	return 0;
}
