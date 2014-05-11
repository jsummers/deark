// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>
#include "bmputil.h"

// Gathers information about a DIB.
// pos points to the beginning of the BITMAPINFOHEADER.
// Caller allocates bi.
// Returns 0 if BMP is invalid.
int de_bmputil_get_bmpinfo(dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags)
{
	de_int64 infohdrsize;
	de_int64 bitcount;
	de_int64 compression = 0;
	de_int64 pal_entries = 0;
	de_int64 foreground_rowspan, mask_rowspan;
	de_int64 foreground_size, mask_size;
	de_int64 bytes_per_pal_entry;

	de_memset(bi, 0, sizeof(struct de_bmpinfo));

	if(len<16) return 0;
	infohdrsize = dbuf_getui32le(f, pos);

	if(infohdrsize==0x474e5089 && (flags & DE_BMPINFO_ICO_FORMAT)) {
		// We don't examine PNG-formatted icons, but we can identify them.
		bi->file_format = DE_BMPINFO_FMT_PNG;
		return 1;
	}
	else if(infohdrsize==12) {
		bytes_per_pal_entry = 3;
		bi->width = dbuf_getui16le(f, pos+4);
		bi->height = dbuf_getui16le(f, pos+6);
		bitcount = dbuf_getui16le(f, pos+10);
	}
	else if(infohdrsize>=16 && infohdrsize<=124) {
		bytes_per_pal_entry = 4;
		bi->width = dbuf_getui32le(f, pos+4);
		bi->height = dbuf_getui32le(f, pos+8);
		if(bi->height<0) bi->height = -bi->height;
		bitcount = dbuf_getui16le(f, pos+14);
		if(infohdrsize>=20) {
			compression = dbuf_getui32le(f, pos+16);
		}
		if(infohdrsize>=36) {
			pal_entries = dbuf_getui32le(f, pos+32);
		}
	}
	else {
		return 0;
	}

	if(flags & DE_BMPINFO_ICO_FORMAT) bi->height /= 2;

	if(bitcount>=1 && bitcount<=8) {
		if(pal_entries==0) {
			pal_entries = (de_int64)(1<<(unsigned int)bitcount);
		}
		// I think the NumColors field is supposed to be the maximum number of
		// colors implied by the bit depth, not the number of colors in the
		// palette.
		bi->num_colors = (de_int64)(1<<(unsigned int)bitcount);
	}
	else {
		// An arbitrary value. All that matters is that it's >=256.
		bi->num_colors = 16777216;
	}

	bi->size_of_headers = infohdrsize + bytes_per_pal_entry*pal_entries;
	if(compression==3) {
		bi->size_of_headers += 12; // BITFIELDS
	}

	if(compression==0) {
		// Try to figure out the true size of the resource, minus any padding.

		foreground_rowspan = ((bitcount*bi->width +31)/32)*4;
		foreground_size = foreground_rowspan * bi->height;

		if(flags & DE_BMPINFO_ICO_FORMAT) {
			mask_rowspan = ((bi->width +31)/32)*4;
			mask_size = mask_rowspan * bi->height;
		}
		else {
			mask_size = 0;
		}

		bi->total_size = bi->size_of_headers + foreground_size + mask_size;
	}
	else {
		// Don't try to figure out the true size of compressed or other unusual images.
		bi->total_size = len;
	}

	return 1;
}
