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
	dbuf *unc_pixels, de_int64 *cmpr_bytes_consumed);

struct de_SAUCE_info {
	de_ucstring *title;
	de_ucstring *artist;
	de_ucstring *organization;
	de_ucstring *creation_date;
	de_int64 original_file_size;
	de_byte data_type;
	de_byte file_type;
	de_int64 width_in_chars; // 0 if unknown
	de_int64 number_of_lines; // Reported value. May be incorrect.
};

int de_read_SAUCE(deark *c, dbuf *f, de_int64 pos, struct de_SAUCE_info *si);
