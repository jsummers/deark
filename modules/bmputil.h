// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

struct de_bmpinfo {
	de_int64 width;
	de_int64 height;
	de_int64 num_colors; // For use in ICO/CUR file headers.
	de_int64 size_of_headers; // Offset to bitmap
	de_int64 total_size;

#define DE_BMPINFO_FMT_BMP 0
#define DE_BMPINFO_FMT_PNG 1
	int file_format;
};

#define DE_BMPINFO_HAS_FILEHEADER 0x1
#define DE_BMPINFO_ICO_FORMAT     0x2

int de_bmputil_get_bmpinfo(dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags);
