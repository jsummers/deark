// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

// Atari Prism Paint (.pnt)

typedef struct localctx_struct {
	de_int64 pal_size;
	de_int64 width, height;
	de_int64 bits_per_pixel;
	de_int64 compression;
	de_int64 pic_data_size;
	de_uint32 pal[256];
} lctx;

static de_byte samp1000to255(de_int64 n)
{
	if(n>=1000) return 255;
	if(n<=0) return 0;
	return (de_byte)(0.5+(((double)n)*(255.0/1000.0)));
}

// A color value of N does not necessarily refer to Nth color in the palette.
// Some of them are mixed up. Aparently this is called "VDI order".
// This table may not be completely correct.
static unsigned int map_pal(de_int64 bpp, unsigned int v)
{
	switch(v) {
		case 1: return 2;
		case 2: return 3;
		case 3: return 6;
		case 5: return 7;
		case 6: return 5;
		case 7: return 8;
		case 8: return 9;
		case 9: return 10;
		case 10: return 11;
		case 11: return 14; 
		case 13: return 15;
		case 14: return 13;
		case 15: return bpp==8 ? 255 : 1;
		case 255: return 1;
	}
	return v;
}

static void do_read_palette(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 r1, g1, b1;
	de_byte r, g, b;

	for(i=0; i<d->pal_size; i++) {
		r1 = de_getui16be(128+6*i+0);
		g1 = de_getui16be(128+6*i+2);
		b1 = de_getui16be(128+6*i+4);
		r = samp1000to255(r1);
		g = samp1000to255(g1);
		b = samp1000to255(b1);
		de_dbg2(c, "pal#%3d (%5d,%5d,%5d) (%3d,%3d,%3d)\n", (int)i, (int)r1, (int)g1, (int)b1,
			(int)r, (int)g, (int)b);
		if(i>255) continue;
		d->pal[i] = DE_MAKE_RGB(r,g,b); 
	}
}

static void do_image(deark *c, lctx *d, dbuf *unc_pixels)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 plane;
	de_int64 rowspan;
	de_byte b;
	unsigned int v;
	de_int64 planespan;

	img = de_bitmap_create(c, d->width, d->height, 3);

	planespan = 2*((d->width+15)/16);
	rowspan = planespan*d->bits_per_pixel;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			v = 0;

			for(plane=0; plane<d->bits_per_pixel; plane++) {
				if(d->compression==0) {
					// This may not be correct, but it at least works for 8-bit images
					// whose width is a nice round number.
					b = de_get_bits_symbol(unc_pixels, 1, j*rowspan + 2*plane + (i-i%16), i%16);
				}
				else {
					b = de_get_bits_symbol(unc_pixels, 1, j*rowspan + plane*planespan, i);
				}
				if(b) v |= 1<<plane;
			}

			if(v>255) v=255;
			de_bitmap_setpixel_rgb(img, i, j, d->pal[map_pal(d->bits_per_pixel, v)]);
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void de_run_prismpaint(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pixels_start;
	dbuf *unc_pixels = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->pal_size = de_getui16be(6);
	d->width = de_getui16be(8);
	d->height = de_getui16be(10);
	de_dbg(c, "pal_size: %d, dimensions: %dx%d\n", (int)d->pal_size,
		(int)d->width, (int)d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	d->bits_per_pixel = de_getui16be(12);
	d->compression = de_getui16be(14);
	de_dbg(c, "bits/pixel: %d, compression: %d\n", (int)d->bits_per_pixel,
		(int)d->compression);

	d->pic_data_size = de_getui32be(16);
	de_dbg(c, "reported (uncompressed) picture data size: %d\n", (int)d->pic_data_size);

	if(d->bits_per_pixel!=4 && d->bits_per_pixel!=8) {
		de_err(c, "Unsupported bits/pixel (%d)\n", (int)d->bits_per_pixel);
		goto done;
	}
	if(d->compression!=0 && d->compression!=1) {
		de_err(c, "Unsupported compression (%d)\n", (int)d->compression);
		goto done;
	}

	do_read_palette(c, d);

	pixels_start = 128 + 2*3*d->pal_size;
	de_dbg(c, "pixel data starts at %d\n", (int)pixels_start);
	if(pixels_start >= c->infile->len) goto done;

	if(d->compression==0) {
		unc_pixels = dbuf_open_input_subfile(c->infile, pixels_start,
			c->infile->len - pixels_start);
	}
	else {
		// TODO: Calculate the initial size more accurately.
		unc_pixels = dbuf_create_membuf(c, d->width*d->height);
		//dbuf_set_max_length(unc_pixels, ...);

		de_fmtutil_uncompress_packbits(c->infile, pixels_start, c->infile->len - pixels_start, unc_pixels);
		de_dbg(c, "uncompressed to %d bytes\n", (int)unc_pixels->len);
	}

	do_image(c, d, unc_pixels);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_prismpaint(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PNT\x00", 4))
		return 100;
	return 0;
}

void de_module_prismpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "prismpaint";
	mi->run_fn = de_run_prismpaint;
	mi->identify_fn = de_identify_prismpaint;
}
