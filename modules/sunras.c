// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Sun Raster image format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_sunras);

typedef struct localctx_struct {
	de_int64 width, height;
	de_int64 depth;

#define RT_OLD          0
#define RT_STANDARD     1
#define RT_BYTE_ENCODED 2
#define RT_FORMAT_RGB   3
#define RT_FORMAT_TIFF  4
#define RT_FORMAT_IFF   5
	de_int64 imgtype;

	de_int64 imglen;

#define RMT_NONE        0
#define RMT_EQUAL_RGB   1
#define RMT_RAW         2
	de_int64 maptype;

	de_int64 maplen;

	int is_paletted;
	int is_grayscale;

	de_uint32 pal[256];
} lctx;

static void do_read_palette(deark *c, lctx *d, de_int64 pos)
{
	de_int64 num_entries;
	de_int64 num_entries_to_read;
	de_int64 k;
	de_byte r, g, b;

	num_entries = d->maplen/3;
	num_entries_to_read = num_entries;
	if(num_entries_to_read>256) num_entries_to_read = 256;

	for(k=0; k<num_entries_to_read; k++) {
		r = de_getbyte(pos + k);
		g = de_getbyte(pos+num_entries + k);
		b = de_getbyte(pos+num_entries*2 + k);
		d->pal[k] = DE_MAKE_RGB(r, g, b);
		de_dbg_pal_entry(c, k, d->pal[k]);
	}
}

static void do_image(deark *c, lctx *d, dbuf *unc_pixels)
{
	struct deark_bitmap *img = NULL;
	de_uint32 clr;
	de_byte b;
	de_int64 i, j;
	de_int64 rowspan;
	de_int64 src_bypp, dst_bypp;

	if(d->depth!=1 && d->depth!=4 && d->depth!=8 && d->depth!=24 && d->depth!=32) {
		de_err(c, "Bit depth %d not supported\n", (int)d->depth);
		goto done;
	}
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	if(d->imgtype!=RT_STANDARD) goto done;

	src_bypp = d->depth/8;

	if(d->is_paletted) {
		dst_bypp = 3;
	}
	else if(d->is_grayscale) {
		dst_bypp = 1;
	}
	else {
		dst_bypp = 3;
	}

	img = de_bitmap_create(c, d->width, d->height, (int)dst_bypp);
	rowspan = (((d->width * d->depth)+15)/16)*2;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			if(d->is_paletted || d->is_grayscale) {
				b = de_get_bits_symbol(unc_pixels, d->depth, rowspan*j, i);
				clr = d->pal[(unsigned int)b];
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
			else if(d->depth==24 || d->depth==32) {
				clr = dbuf_getRGB(unc_pixels, rowspan*j+i*src_bypp, DE_GETRGBFLAG_BGR);
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static void read_header(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->width = de_getui32be(pos+4);
	d->height = de_getui32be(pos+8);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	d->depth = de_getui32be(pos+12);
	de_dbg(c, "depth: %d\n", (int)d->depth);

	d->imglen = de_getui32be(pos+16);
	d->imgtype = de_getui32be(pos+20);
	de_dbg(c, "image type=%d, len=%d\n", (int)d->imgtype, (int)d->imglen);

	d->maptype = de_getui32be(pos+24);
	d->maplen = de_getui32be(pos+28);
	de_dbg(c, "map type=%d, len=%d\n", (int)d->maptype, (int)d->maplen);

	de_dbg_indent(c, -1);
}

static void de_run_sunras(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *unc_pixels = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	read_header(c, d, pos);
	pos += 32;

	if(d->maptype==RMT_EQUAL_RGB) {
		d->is_paletted = 1;
		do_read_palette(c, d, pos);
	}
	else if(d->maptype==RMT_NONE && d->depth<=8) {
		d->is_grayscale = 1;
		de_make_grayscale_palette(d->pal, ((de_int64)1)<<d->depth, d->depth==1 ? 1 : 0);
	}
	pos += d->maplen;

	if(pos+d->imglen > c->infile->len) {
		de_err(c, "Unexpected end of file\n");
		goto done;
	}

	if(d->imgtype!=RT_STANDARD) {
		de_err(c, "This type of image (%d) is not supported\n", (int)d->imgtype);
		goto done;
	}

	unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
	do_image(c, d, unc_pixels);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_sunras(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x59\xa6\x6a\x95", 4))
		return 100;
	return 0;
}

void de_module_sunras(deark *c, struct deark_module_info *mi)
{
	mi->id = "sunras";
	mi->desc = "Sun Raster";
	mi->run_fn = de_run_sunras;
	mi->identify_fn = de_identify_sunras;
}
