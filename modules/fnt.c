// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 fnt_version;
	de_int64 nominal_char_width;
	de_int64 char_height;
	de_int64 hdrsize;
	de_int64 char_table_size;

	de_byte first_char;
	de_byte last_char;
	de_int64 num_chars_indexed;
	de_int64 num_chars_stored;

	de_int64 char_entry_size;
	de_int64 detected_max_width;

	de_int64 img_leftmargin;
	de_int64 img_topmargin;
	de_int64 img_hpixelsperchar;
	de_int64 img_vpixelsperchar;
} lctx;

static void do_render_char(deark *c, lctx *d, struct deark_bitmap *img,
	de_int64 char_idx, de_int64 char_width, de_int64 char_offset)
{
	de_int64 xpos, ypos;
	de_int64 num_tiles;
	de_int64 tile;
	de_int64 row;
	de_int64 k;
	de_int64 tile_width;
	de_byte x;

	if(char_width>d->nominal_char_width) return;

	xpos = d->img_leftmargin + (char_idx%16) * d->img_hpixelsperchar;
	ypos = d->img_topmargin + (char_idx/16) * d->img_vpixelsperchar;

	num_tiles = (char_width+7)/8;

	for(tile=0; tile<num_tiles; tile++) {

		if(tile==num_tiles-1 && char_width%8) {
			tile_width = char_width%8;
		}
		else {
			tile_width = 8;
		}

		for(row=0; row<d->char_height; row++) {
			for(k=0; k<tile_width; k++) {
				x = de_get_bits_symbol(c->infile, 1, char_offset+tile*d->char_height+row, k);
				de_bitmap_setpixel_gray(img, xpos+tile*8+k, ypos+row, x?0:255);
			}
		}
	}
}

// Find the widest character.
static void do_prescan_chars(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 pos;
	de_int64 char_width;

	for(i=0; i<d->num_chars_indexed; i++) {
		pos = d->hdrsize + d->char_entry_size*i;
		char_width = de_getui16le(pos);

		if(char_width > d->detected_max_width) {
			d->detected_max_width = char_width;
		}
	}
	de_dbg(c, "detected max width: %d\n", (int)d->detected_max_width);
}

static void do_make_image(deark *c, lctx *d)
{
	de_int64 i, j;
	de_int64 pos;
	de_int64 char_width;
	de_int64 char_offset;
	de_int64 img_width, img_height;
	de_byte clr;
	struct deark_bitmap *img = NULL;

	if(d->nominal_char_width>128 || d->char_height>128) {
		de_err(c, "Font size too big. Not supported.\n");
		goto done;
	}

	d->img_leftmargin = 0;
	d->img_topmargin = 0;
	d->img_hpixelsperchar = d->nominal_char_width + 1;
	d->img_vpixelsperchar = d->char_height + 1;
	img_width = d->img_leftmargin + 16 * d->img_hpixelsperchar;
	img_height = d->img_topmargin + 16 * d->img_vpixelsperchar;

	img = de_bitmap_create(c, img_width, img_height, 1);

	// Clear image and draw the grid.
	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			if(i>=d->img_leftmargin-1 && j>=d->img_topmargin-1 &&
				((i+1-d->img_leftmargin)%d->img_hpixelsperchar==0 ||
				(j+1-d->img_topmargin)%d->img_vpixelsperchar==0))
			{
				clr = 128;
			}
			else {
				clr = 192;
			}
			de_bitmap_setpixel_gray(img, i, j, clr);
		}
	}

	for(i=0; i<d->num_chars_indexed; i++) {
		pos = d->hdrsize + d->char_entry_size*i;
		char_width = de_getui16le(pos);
		if(d->char_entry_size==6)
			char_offset = de_getui32le(pos+2);
		else
			char_offset = de_getui16le(pos+2);
		de_dbg2(c, "char[%d] width=%d offset=%d\n", (int)(d->first_char + i), (int)char_width, (int)char_offset);

		do_render_char(c, d, img, d->first_char + i, char_width, char_offset);
	}

	de_bitmap_write_to_file(img, NULL);
done:
	de_bitmap_destroy(img);
}

static void do_read_header(deark *c, lctx *d)
{
	de_int64 dfType;
	de_byte dfCharSet;
	de_int64 dfPixWidth;
	de_int64 dfPixHeight;
	de_int64 dfMaxWidth;
	int is_vector = 0;

	d->fnt_version = de_getui16le(0);
	de_dbg(c, "dfVersion: 0x%04x\n", (int)d->fnt_version);

	if(d->fnt_version==0x0300)
		d->hdrsize = 148;
	else
		d->hdrsize = 118;

	dfType = de_getui16le(66);
	de_dbg(c, "dfType: 0x%04x\n", (int)dfType);

	is_vector = (dfType&0x1)?1:0;
	de_dbg(c, "Font type: %s\n", is_vector?"vector":"bitmap");
	if(is_vector) {
		de_err(c, "This is a vector font. Not supported.\n");
		return;
	}

	dfPixWidth = de_getui16le(86);
	de_dbg(c, "dfPixWidth: %d\n", (int)dfPixWidth);
	dfPixHeight = de_getui16le(88);
	de_dbg(c, "dfPixHeight: %d\n", (int)dfPixHeight);

	dfCharSet = de_getbyte(85);
	de_dbg(c, "charset: 0x%02x\n", (int)dfCharSet);

	dfMaxWidth = de_getui16le(93);
	de_dbg(c, "dfMaxWidth: %d\n", (int)dfMaxWidth);

	if(dfPixWidth!=dfMaxWidth && dfPixWidth!=0) {
		de_warn(c, "dfMaxWidth (%d) does not equal dfPixWidth (%d)\n",
			(int)dfMaxWidth, (int)dfPixWidth);
	}

	d->first_char = de_getbyte(95);
	d->last_char = de_getbyte(96);
	de_dbg(c, "first char: %d, last char: %d\n", (int)d->first_char, (int)d->last_char);

	d->num_chars_indexed = (de_int64)d->last_char - d->first_char + 1;
	d->num_chars_stored = d->num_chars_indexed + 1;

	if(d->fnt_version==0x0300) {
		d->char_entry_size = 6;
	}
	else {
		d->char_entry_size = 4;
	}

	d->char_table_size = d->char_entry_size * d->num_chars_stored;

	do_prescan_chars(c, d);

	if(d->detected_max_width < dfMaxWidth) {
		// dfMaxWidth setting is larger than necessary.
		d->nominal_char_width = d->detected_max_width;
	}
	else {
		d->nominal_char_width = dfMaxWidth;
	}
	d->char_height = dfPixHeight;

	do_make_image(c, d);
}

static void de_run_fnt(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In fnt module\n");
	d = de_malloc(c, sizeof(lctx));
	do_read_header(c, d);
	de_free(c, d);
}

static int de_identify_fnt(deark *c)
{
	de_int64 ver;

	// TODO: Better format detection.
	if(de_input_file_has_ext(c, "fnt")) {
		ver = de_getui16le(0);
		if(ver==0x0200 || ver==0x0300)
			return 10;
	}
	return 0;
}

void de_module_fnt(deark *c, struct deark_module_info *mi)
{
	mi->id = "fnt";
	mi->run_fn = de_run_fnt;
	mi->identify_fn = de_identify_fnt;
}
