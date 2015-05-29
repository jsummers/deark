// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// This file is for format-specific functions that are used by multiple modules.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"

// Gathers information about a DIB.
// If DE_BMPINFO_HAS_FILEHEADER flag is set, pos points to the BITMAPFILEHEADER.
// Otherwise, it points to the BITMAPINFOHEADER.
// Caller allocates bi.
// Returns 0 if BMP is invalid.
int de_fmtutil_get_bmpinfo(deark *c, dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags)
{
	de_int64 fhs; // file header size
	de_int64 bmih_pos;

	de_memset(bi, 0, sizeof(struct de_bmpinfo));

	fhs = (flags & DE_BMPINFO_HAS_FILEHEADER) ? 14 : 0;

	if(fhs+len < 16) return 0;

	if(fhs) {
		if(flags & DE_BMPINFO_HAS_HOTSPOT) {
			bi->hotspot_x = dbuf_getui16le(f, pos+6);
			bi->hotspot_y = dbuf_getui16le(f, pos+8);
			de_dbg(c, "hotspot: (%d,%d)\n", (int)bi->hotspot_x, (int)bi->hotspot_y);
		}

		bi->bitsoffset = dbuf_getui32le(f, pos+10);
		de_dbg(c, "bits offset: %d\n", (int)bi->bitsoffset);
	}

	bmih_pos = pos + fhs;

	bi->infohdrsize = dbuf_getui32le(f, bmih_pos);

	if(bi->infohdrsize==0x474e5089 && (flags & DE_BMPINFO_ICO_FORMAT)) {
		// We don't examine PNG-formatted icons, but we can identify them.
		bi->infohdrsize = 0;
		bi->file_format = DE_BMPINFO_FMT_PNG;
		return 1;
	}

	de_dbg(c, "info header size: %d\n", (int)bi->infohdrsize);

	if(bi->infohdrsize==12) {
		bi->bytes_per_pal_entry = 3;
		bi->width = dbuf_getui16le(f, bmih_pos+4);
		bi->height = dbuf_getui16le(f, bmih_pos+6);
		bi->bitcount = dbuf_getui16le(f, bmih_pos+10);
	}
	else if(bi->infohdrsize>=16 && bi->infohdrsize<=124) {
		bi->bytes_per_pal_entry = 4;
		bi->width = dbuf_getui32le(f, bmih_pos+4);
		bi->height = dbuf_getui32le(f, bmih_pos+8);
		if(bi->height<0) {
			bi->is_topdown = 1;
			bi->height = -bi->height;
		}
		bi->bitcount = dbuf_getui16le(f, bmih_pos+14);
		if(bi->infohdrsize>=20) {
			bi->compression_field = dbuf_getui32le(f, bmih_pos+16);
		}
		if(bi->infohdrsize>=36) {
			bi->pal_entries = dbuf_getui32le(f, bmih_pos+32);
		}
	}
	else {
		return 0;
	}

	if(flags & DE_BMPINFO_ICO_FORMAT) bi->height /= 2;

	if(bi->bitcount>=1 && bi->bitcount<=8) {
		if(bi->pal_entries==0) {
			bi->pal_entries = (de_int64)(1<<(unsigned int)bi->bitcount);
		}
		// I think the NumColors field (in icons) is supposed to be the maximum number of
		// colors implied by the bit depth, not the number of colors in the palette.
		bi->num_colors = (de_int64)(1<<(unsigned int)bi->bitcount);
	}
	else {
		// An arbitrary value. All that matters is that it's >=256.
		bi->num_colors = 16777216;
	}

	de_dbg(c, "image size: %dx%d\n", (int)bi->width, (int)bi->height);
	de_dbg(c, "bit count: %d\n", (int)bi->bitcount);
	de_dbg(c, "palette entries: %d\n", (int)bi->pal_entries);

	bi->pal_bytes = bi->bytes_per_pal_entry*bi->pal_entries;
	bi->size_of_headers_and_pal = fhs + bi->infohdrsize + bi->pal_bytes;
	if(bi->compression_field==3) {
		bi->size_of_headers_and_pal += 12; // BITFIELDS
	}

	if(bi->compression_field==0) {
		// Try to figure out the true size of the resource, minus any padding.

		bi->rowspan = ((bi->bitcount*bi->width +31)/32)*4;
		bi->foreground_size = bi->rowspan * bi->height;

		if(flags & DE_BMPINFO_ICO_FORMAT) {
			bi->mask_rowspan = ((bi->width +31)/32)*4;
			bi->mask_size = bi->mask_rowspan * bi->height;
		}
		else {
			bi->mask_size = 0;
		}

		bi->total_size = bi->size_of_headers_and_pal + bi->foreground_size + bi->mask_size;
	}
	else {
		// Don't try to figure out the true size of compressed or other unusual images.
		bi->total_size = len;
	}

	return 1;
}

void de_fmtutil_handle_exif(deark *c, de_int64 pos, de_int64 len)
{
	dbuf *old_ifile;

	if(c->extract_level>=2) {
		// Writing raw Exif data isn't very useful, but do so if requested.
		dbuf_create_file_from_slice(c->infile, pos, len, "exif.tif", NULL);

		// Caller will have to reprocess the Exif file to extract anything from it.
		return;
	}

	old_ifile = c->infile;

	c->infile = dbuf_open_input_subfile(old_ifile, pos, len);
	de_run_module_by_id(c, "tiff", "E");
	dbuf_close(c->infile);

	c->infile = old_ifile;
}

void de_fmtutil_handle_photoshop_rsrc(deark *c, de_int64 pos, de_int64 len)
{
	dbuf *old_ifile;

	old_ifile = c->infile;

	c->infile = dbuf_open_input_subfile(old_ifile, pos, len);
	de_run_module_by_id(c, "psd", "R");
	dbuf_close(c->infile);

	c->infile = old_ifile;
}

// Returns 0 on failure (currently impossible).
int de_fmtutil_uncompress_packbits(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (de_int64)b;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
		// Else b==128. No-op.
		// TODO: Some (but not most) ILBM specs say that code 128 is used to
		// mark the end of compressed data, so maybe there should be options to
		// tell us what to do when code 128 is encountered.
	}

	return 1;
}

void de_fmtutil_paint_character_idx(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int64 char_idx,
	de_int64 xpos, de_int64 ypos, de_int32 fgcol, de_int32 bgcol,
	unsigned int flags)
{
	de_int64 i, j;
	de_byte x;
	int fg;
	de_int32 clr;
	struct de_bitmap_font_char *ch;

	if(char_idx<0 || char_idx>=font->num_chars) return;
	ch = &font->char_array[char_idx];
	if(!ch) return;
	if(ch->width > font->nominal_width) return;
	if(ch->height > font->nominal_height) return;

	for(j=0; j<ch->height; j++) {
		for(i=0; i<ch->width; i++) {
			x = ch->bitmap[j*ch->rowspan + i/8];
			fg = (x & (1<<(7-i%8))) ? 1 : 0;
			clr = fg ? fgcol : bgcol;
			if(fg || !(flags&DE_PAINTFLAG_TRNSBKGD))
				de_bitmap_setpixel_rgba(img, xpos+i, ypos+j, clr);

			// Manufacture a 9th column, if requested.
			if(font->vga_9col_mode && i==7) {
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
		if(font->char_array[i].codepoint == codepoint)
			return i;
	}
	return -1;
}

void de_fmtutil_paint_character_cp(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int32 codepoint,
	de_int64 xpos, de_int64 ypos, de_int32 fgcol, de_int32 bgcol, unsigned int flags)
{
	de_int64 char_idx;

	char_idx = get_char_idx_by_cp(c, font, codepoint);
	if(char_idx<0) return;
	de_fmtutil_paint_character_idx(c, img, font, char_idx, xpos, ypos, fgcol, bgcol, flags);
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
	struct de_bitmap_font *dfont, de_int64 n, de_int64 xpos, de_int64 ypos, int hex)
{
	char buf[32];
	de_int64 len;
	de_int64 i;

	if(hex)
		de_snprintf(buf, sizeof(buf), "%X", (unsigned int)n);
	else
		de_snprintf(buf, sizeof(buf), "%u", (unsigned int)n);
	len = (de_int64)de_strlen(buf);

	for(i=len-1; i>=0; i--) {
		de_fmtutil_paint_character_cp(c, img, dfont, buf[i],
			xpos-dfont->nominal_width*(len-i), ypos-dfont->nominal_height,
			DE_MAKE_GRAY(255), 0, DE_PAINTFLAG_TRNSBKGD);
	}
}

static void get_min_max_codepoint(struct de_bitmap_font *font, de_int32 *mincp, de_int32 *maxcp)
{
	de_int64 i;

	*mincp = 0x10ffff;
	*maxcp = 0;

	for(i=0; i<font->num_chars; i++) {
		if(font->char_array[i].codepoint < *mincp)
			*mincp = font->char_array[i].codepoint;
		if(font->char_array[i].codepoint > *maxcp)
			*maxcp = font->char_array[i].codepoint;
	}
}

void de_fmtutil_bitmap_font_to_image(deark *c, struct de_bitmap_font *font, de_finfo *fi)
{
	de_int64 i, j;
	de_byte clr;
	struct deark_bitmap *img = NULL;
	de_int64 xpos, ypos;
	de_int64 img_leftmargin, img_topmargin;
	de_int64 img_rightmargin, img_bottommargin;
	de_int64 img_hpixelsperchar, img_vpixelsperchar;
	de_int64 img_width, img_height;
	de_int64 img_fieldwidth, img_fieldheight;
	de_int64 num_table_rows_total;
	de_int64 num_table_rows_rendered;
	de_int32 min_codepoint, max_codepoint;
	struct de_bitmap_font *dfont = NULL;
	de_int64 chars_per_row = 32;
	const char *s;
	de_byte *row_flags = NULL;
	de_int64 *row_display_pos = NULL;

	if(font->num_chars<1) goto done;
	if(font->nominal_width>128 || font->nominal_height>128) {
		de_err(c, "Font size too big. Not supported.\n");
		goto done;
	}

	s = de_get_ext_option(c, "font:charsperrow");
	if(s) {
		chars_per_row = de_atoi64(s);
		if(chars_per_row<1) chars_per_row=1;
	}

	dfont = make_digit_font(c);

	if(font->is_unicode)
		img_leftmargin = dfont->nominal_width * 4 + 6;
	else
		img_leftmargin = dfont->nominal_width * 3 + 6;
	img_topmargin = dfont->nominal_height + 6;
	img_rightmargin = 1;
	img_bottommargin = 1;

	get_min_max_codepoint(font, &min_codepoint, &max_codepoint);
	num_table_rows_total = max_codepoint/chars_per_row+1;

	// Flag each row that has a character that exists in this font.
	row_flags = de_malloc(c, num_table_rows_total*sizeof(de_byte));
	for(i=0; i<font->num_chars; i++) {
		de_int64 rownum;
		rownum = font->char_array[i].codepoint / chars_per_row;
		row_flags[rownum] = 1;
	}
	// Figure out how many rows are used, and where to draw them.
	row_display_pos = de_malloc(c, num_table_rows_total*sizeof(de_int64));
	num_table_rows_rendered = 0;
	for(i=0; i<num_table_rows_total; i++) {
		if(row_flags[i]) {
			row_display_pos[i] = num_table_rows_rendered;
			num_table_rows_rendered++;
		}
	}
	if(num_table_rows_rendered<1) goto done;

	img_hpixelsperchar = font->nominal_width + 1;
	img_vpixelsperchar = font->nominal_height + 1;
	// TODO: Ideally, we should probably skip over any rows that have no valid
	// characters.
	img_fieldwidth = chars_per_row * img_hpixelsperchar -1;
	img_fieldheight = num_table_rows_rendered * img_vpixelsperchar -1;
	img_width = img_leftmargin + img_fieldwidth + img_rightmargin;
	img_height = img_topmargin + img_fieldheight + img_bottommargin;

	img = de_bitmap_create(c, img_width, img_height, 1);

	// Clear image and draw the grid.
	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			if(i<img_leftmargin || i>img_leftmargin+img_fieldwidth ||
				j<img_topmargin || j>img_topmargin+img_fieldheight)
			{
				clr = 128;
			}
			else if((i+1-img_leftmargin)%img_hpixelsperchar==0 ||
				(j+1-img_topmargin)%img_vpixelsperchar==0)
			{
				clr = 128;
			}
			else {
				clr = 192;
			}
			de_bitmap_setpixel_gray(img, i, j, clr);
		}
	}

	// Draw the labels in the top margin.
	// TODO: Don't draw the numbers too close together.
	for(i=0; i<chars_per_row; i++) {
		xpos = img_leftmargin + (i+1)*img_hpixelsperchar;
		ypos = img_topmargin - 3;
		draw_number(c, img, dfont, i, xpos, ypos, font->is_unicode?1:0);
	}

	// Draw the labels in the left margin.
	for(i=0; i<num_table_rows_total; i++) {
		if(row_flags[i]==0) continue;
		xpos = img_leftmargin - 2;
		ypos = img_topmargin + (row_display_pos[i]+1)*img_vpixelsperchar - 2;
		draw_number(c, img, dfont, i*chars_per_row, xpos, ypos, font->is_unicode?1:0);
	}

	// Render the glyphs.
	for(i=0; i<font->num_chars; i++) {
		xpos = img_leftmargin + (font->char_array[i].codepoint%chars_per_row) * img_hpixelsperchar;
		ypos = img_topmargin + (row_display_pos[font->char_array[i].codepoint/chars_per_row]) * img_vpixelsperchar;
		de_fmtutil_paint_character_idx(c, img, font, i, xpos, ypos,
			DE_MAKE_GRAY(0), DE_MAKE_GRAY(255), 0);
	}

	de_bitmap_write_to_file_finfo(img, fi);

done:
	if(dfont) {
		de_free(c, dfont->char_array);
		de_free(c, dfont);
	}
	de_bitmap_destroy(img);
	de_free(c, row_flags);
	de_free(c, row_display_pos);
}
