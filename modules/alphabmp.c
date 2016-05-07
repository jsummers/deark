// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Alpha Microsystems BMP

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_alphabmp);

typedef struct localctx_struct {
	de_int64 w, h;
	de_int64 bpp;
	unsigned int has_palette;
	unsigned int palette_is_hls;
	de_int64 compression;
	de_int64 num_pal_entries;
	de_uint32 pal[256];
} lctx;

static int do_read_palette(deark *c, lctx *d, de_int64 pos, de_int64 *pal_nbytes)
{
	de_dbg(c, "Palette at %d\n", (int)pos);

	d->num_pal_entries = de_getui16le(pos) + 1;
	de_dbg(c, "Number of palette colors: %d\n", (int)d->num_pal_entries);
	if(d->palette_is_hls)
		*pal_nbytes = 2 + d->num_pal_entries * 6;
	else
		*pal_nbytes = 2 + d->num_pal_entries * 3;
	if(d->palette_is_hls) return 1;

	de_read_palette_rgb(c->infile, pos+2, d->num_pal_entries, 3, d->pal, 256, 0);
	return 1;
}

static void do_bitmap(deark *c, lctx *d, dbuf *unc_pixels)
{
	de_int64 i, j;
	de_int64 rowspan;
	de_uint32 clr;
	struct deark_bitmap *img = NULL;
	de_byte b;

	rowspan = (d->w * d->bpp +7)/8;

	img = de_bitmap_create(c, d->w, d->h, 3);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			if(d->bpp<=8) {
				b = de_get_bits_symbol(unc_pixels, d->bpp, j*rowspan, i);
				clr = d->pal[(unsigned int)b];
			}
			else {
				clr = dbuf_getRGB(unc_pixels, j*rowspan + i*3, 0);
			}
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
}

static int do_uncompress_image(deark *c, lctx *d, de_int64 pos, dbuf *unc_pixels)
{
	de_int64 bytes_in_this_line;
	de_int64 j;
	int ret;

	de_dbg(c, "Decompressing bitmap\n");

	// Each line is compressed independently, using PackBits.

	for(j=0; j<d->h; j++) {
		bytes_in_this_line = de_getui16le(pos);
		pos += 2;
		ret = de_fmtutil_uncompress_packbits(c->infile, pos, bytes_in_this_line,
			unc_pixels, NULL);
		if(!ret) return 0;
		pos += bytes_in_this_line;
	}
	return 1;
}

static void de_run_alphabmp(deark *c, de_module_params *mparams)
{
	unsigned int flags;
	lctx *d = NULL;
	de_int64 pos;
	de_int64 palsize;
	dbuf *unc_pixels = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_declare_fmt(c, "Alpha Microsystems BMP");

	pos = 10;

	de_dbg(c, "Bitmap image definition block at %d\n", (int)pos);

	d->w = de_getui16le(pos);
	d->h = de_getui16le(pos+2);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	d->bpp = de_getui16le(pos+4);
	de_dbg(c, "bits/pixel: %d\n", (int)d->bpp);

	flags = (unsigned int)de_getui16le(pos+6);
	d->has_palette = flags & 0x01;
	d->palette_is_hls = (flags>>1) & 0x01;
	de_dbg(c, "has-palette: %d\n", (int)d->has_palette);
	if(d->has_palette)
		de_dbg(c, "palette-is-HLS: %d\n", (int)d->palette_is_hls);

	d->compression = de_getui16le(pos+8);
	de_dbg(c, "compression: %d\n", (int)d->compression);

	pos += 70;

	if(d->has_palette) {
		if(d->palette_is_hls && d->bpp<=8) {
			de_err(c, "HLS palettes are not supported\n");
			goto done;
		}
		if(!do_read_palette(c, d, pos, &palsize)) goto done;
		pos += palsize;
	}
	else if(d->bpp<=8) {
		de_err(c, "Paletted images without an embedded palette are not supported\n");
		goto done;
	}

	de_dbg(c, "Bitmap at %d\n", (int)pos);

	if(d->compression) {
		unc_pixels = dbuf_create_membuf(c, 32768, 0);
		if(!do_uncompress_image(c, d, pos, unc_pixels)) goto done;
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
	}

	if(d->bpp!=1 && d->bpp!=4 && d->bpp!=8 && d->bpp!=24) {
		de_err(c, "%d bits/pixel is not supported\n", (int)d->bpp);
		goto done;
	}

	do_bitmap(c, d, unc_pixels);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_alphabmp(deark *c)
{
	de_int64 flg;

	if(!de_input_file_has_ext(c, "bmp")) return 0;

	flg = de_getui16le(0);
	if(flg==0xffff || flg==0xfffe) {
		return 60;
	}
	return 0;
}

void de_module_alphabmp(deark *c, struct deark_module_info *mi)
{
	mi->id = "alphabmp";
	mi->desc = "Alpha Microsystems BMP";
	mi->run_fn = de_run_alphabmp;
	mi->identify_fn = de_identify_alphabmp;
}
