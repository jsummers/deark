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
	int is_compressed;
	int is_rgb_order;

	de_int64 imglen;

#define RMT_NONE        0
#define RMT_EQUAL_RGB   1
#define RMT_RAW         2
	de_int64 maptype;

	de_int64 maplen;

	de_int64 rowspan;
	de_int64 unc_pixels_size;
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
	de_bitmap *img = NULL;
	de_uint32 clr;
	de_byte b;
	de_int64 i, j;
	de_int64 src_bypp, dst_bypp;
	unsigned int getrgbflags;

	if(d->depth!=1 && d->depth!=4 && d->depth!=8 && d->depth!=24 && d->depth!=32) {
		de_err(c, "Bit depth %d not supported", (int)d->depth);
		goto done;
	}
	if(d->depth==32) {
		// Some apps think the extra channel comes first (e.g. xBGR); others
		// think it comes last (BGRx).
		// Some apps think the extra channel is for alpha; others think it is
		// unused.
		// Some apps think the color channels are always in BGR order; others
		// think the order is RGB for RT_FORMAT_RGB format.
		de_warn(c, "32-bit Sun Raster files are not portable");
	}
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

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

	if(d->is_rgb_order) {
		getrgbflags = 0;
	}
	else {
		getrgbflags = DE_GETRGBFLAG_BGR;
	}

	img = de_bitmap_create(c, d->width, d->height, (int)dst_bypp);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			if(d->is_paletted || d->is_grayscale) {
				b = de_get_bits_symbol(unc_pixels, d->depth, d->rowspan*j, i);
				clr = d->pal[(unsigned int)b];
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
			else if(d->depth==24 || d->depth==32) {
				clr = dbuf_getRGB(unc_pixels, d->rowspan*j+i*src_bypp, getrgbflags);
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static const char *get_image_type_name(de_int64 t)
{
	const char *name;

	switch(t) {
	case RT_OLD: name="old"; break;
	case RT_STANDARD: name="standard"; break;
	case RT_BYTE_ENCODED: name="RLE"; break;
	case RT_FORMAT_RGB: name="RGB"; break;
	case RT_FORMAT_TIFF: name="TIFF"; break;
	case RT_FORMAT_IFF: name="IFF"; break;
	case 0xffff: name="experimental"; break;
	default: name="?";
	}
	return name;
}

static const char *get_map_type_name(de_int64 t)
{
	const char *name;

	switch(t) {
	case RMT_NONE: name="NONE"; break;
	case RMT_EQUAL_RGB: name="EQUAL_RGB"; break;
	case RMT_RAW: name="RAW"; break;
	default: name="?";
	}
	return name;
}

static void read_header(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->width = de_getui32be(pos+4);
	d->height = de_getui32be(pos+8);
	de_dbg_dimensions(c, d->width, d->height);

	d->depth = de_getui32be(pos+12);
	de_dbg(c, "depth: %d", (int)d->depth);

	d->imglen = de_getui32be(pos+16);
	d->imgtype = de_getui32be(pos+20);
	de_dbg(c, "image type=%d (%s), len=%d", (int)d->imgtype,
		get_image_type_name(d->imgtype), (int)d->imglen);
	if(d->imgtype==RT_BYTE_ENCODED) {
		d->is_compressed = 1;
	}
	if(d->imgtype==RT_FORMAT_RGB) {
		d->is_rgb_order = 1;
	}

	d->maptype = de_getui32be(pos+24);
	d->maplen = de_getui32be(pos+28);
	de_dbg(c, "map type=%d (%s), len=%d", (int)d->maptype,
		get_map_type_name(d->maptype), (int)d->maplen);

	de_dbg_indent(c, -1);
}

static void do_uncompress_image(deark *c, lctx *d, de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	de_int64 pos = pos1;

	while(1) {
		de_byte b0, b1, b2;

		// Stop if we reach the end of the input file.
		if(pos >= c->infile->len) break;

		b0 = de_getbyte(pos++);
		if(b0==0x80) {
			b1 = de_getbyte(pos++);
			if(b1==0x00) { // An escaped 0x80 byte
				dbuf_writebyte(unc_pixels, 0x80);
			}
			else { // A compressed run
				b2 = de_getbyte(pos++);
				dbuf_write_run(unc_pixels, b2, (de_int64)b1+1);
			}
		}
		else { // An uncompressed byte
			dbuf_writebyte(unc_pixels, b0);
		}
	}
}

static void de_run_sunras(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *unc_pixels = NULL;
	de_int64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	read_header(c, d, pos);
	pos += 32;

	if(pos >= c->infile->len) goto done;

	if(d->maplen > 0)
		de_dbg(c, "colormap at %d", (int)pos);

	de_dbg_indent(c, 1);

	if(d->maptype==RMT_EQUAL_RGB) {
		if(d->depth<=8) {
			d->is_paletted = 1;
			do_read_palette(c, d, pos);
		}
		else {
			de_err(c, "This type of image is not supported");
			goto done;
		}
	}
	else if(d->maptype==RMT_NONE) {
		if(d->depth<=8) {
			d->is_grayscale = 1;
			de_make_grayscale_palette(d->pal, ((de_int64)1)<<d->depth, d->depth==1 ? 1 : 0);
		}
	}
	else {
		// TODO: Support RMT_RAW
		de_err(c, "Colormap type (%d) is not supported", (int)d->maptype);
		goto done;
	}
	pos += d->maplen;
	de_dbg_indent(c, -1);

	if(pos >= c->infile->len) goto done;
	de_dbg(c, "image data at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->rowspan = (((d->width * d->depth)+15)/16)*2;
	d->unc_pixels_size = d->rowspan * d->height;

	if(d->imgtype>5) {
		de_err(c, "This type of image (%d) is not supported", (int)d->imgtype);
		goto done;
	}

	if((d->imgtype==RT_STANDARD || d->imgtype==RT_FORMAT_RGB) && d->imglen!=d->unc_pixels_size) {
		de_warn(c, "Inconsistent image length: reported=%d, calculated=%d",
			(int)d->imglen, (int)d->unc_pixels_size);
	}

	if(d->is_compressed) {
		unc_pixels = dbuf_create_membuf(c, d->unc_pixels_size, 0x1);
		do_uncompress_image(c, d, pos, c->infile->len - pos, unc_pixels);
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
	}

	do_image(c, d, unc_pixels);
	de_dbg_indent(c, -1);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
	de_dbg_indent_restore(c, saved_indent_level);
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
