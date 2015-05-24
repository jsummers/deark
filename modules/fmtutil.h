// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

struct de_bmpinfo {
#define DE_BMPINFO_FMT_BMP 0
#define DE_BMPINFO_FMT_PNG 1
	int file_format;

	de_int64 hotspot_x, hotspot_y;
	de_int64 bitsoffset; // Literal value from FILEHEADER
	de_int64 infohdrsize;
	de_int64 width;
	de_int64 height;
	de_int64 bitcount;
	de_int64 compression_field;

	de_int64 bytes_per_pal_entry;
	de_int64 pal_entries;
	de_int64 num_colors; // For use in ICO/CUR file headers.
	de_int64 rowspan;

	de_int64 foreground_size;
	de_int64 mask_rowspan;
	de_int64 mask_size;

	de_int64 pal_bytes; // Size of palette in bytes
	de_int64 size_of_headers_and_pal; // Relative offset to bitmap (bitsoffset might be absolute)
	de_int64 total_size;

	int is_topdown;
};

#define DE_BMPINFO_HAS_FILEHEADER 0x1
#define DE_BMPINFO_ICO_FORMAT     0x2
#define DE_BMPINFO_HAS_HOTSPOT    0x4

int de_fmtutil_get_bmpinfo(deark *c,  dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags);

void de_fmtutil_handle_exif(deark *c, de_int64 pos, de_int64 len);

void de_fmtutil_handle_photoshop_rsrc(deark *c, de_int64 pos, de_int64 len);

int de_fmtutil_uncompress_packbits(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels);


struct de_bitmap_font_char {
	de_int32 codepoint;
	int width, height;
	de_int64 rowspan;
	de_byte *bitmap;
};

struct de_bitmap_font {
	int nominal_width, nominal_height;
	int vga_9col_mode; // Flag: Render an extra column, like VGA does
	de_int64 num_chars;
	struct de_bitmap_font_char *char_array;
};

void de_fmtutil_paint_character(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int64 char_idx,
	de_int64 xpos, de_int64 ypos, de_int32 fgcol, de_int32 bgcol);

void de_fmtutil_bitmap_font_to_image(deark *c, struct de_bitmap_font *font, de_finfo *fi);
