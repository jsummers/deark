// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// PCX (PC Paintbrush)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_byte version;
	de_byte encoding;
	de_int64 bits;
	de_int64 bits_per_pixel;
	de_int64 margin_l, margin_t, margin_r, margin_b;
	de_int64 planes;
	de_int64 rowspan_raw;
	de_int64 rowspan;
	de_byte palette_info;
	de_int64 width, height;
	int has_vga_pal;
	dbuf *unc_pixels;
	de_uint32 pal[256];
} lctx;

static int do_read_header(deark *c, lctx *d)
{
	int retval = 0;
	de_int64 k;

	d->version = de_getbyte(1);
	d->encoding = de_getbyte(2);
	d->bits = (de_int64)de_getbyte(3); // Bits per pixel per plane
	d->margin_l = (de_int64)de_getui16le(4);
	d->margin_t = (de_int64)de_getui16le(6);
	d->margin_r = (de_int64)de_getui16le(8);
	d->margin_b = (de_int64)de_getui16le(10);

	// 16-color EGA palette. Note that this might get overwritten by the
	// VGA palette.
	if(d->version==2 || d->version>=4) {
		for(k=0; k<16; k++) {
			d->pal[k] = dbuf_getRGB(c->infile, 16 + 3*k, 0);
		}
	}

	d->planes = (de_int64)de_getbyte(0x41);
	d->rowspan_raw = (de_int64)de_getui16le(0x42);
	d->palette_info = de_getbyte(0x44);

	de_dbg(c, "version: %d, encoding: %d, bits: %d\n", (int)d->version,
		(int)d->encoding, (int)d->bits);
	de_dbg(c, "margins: %d, %d, %d, %d\n", (int)d->margin_l, (int)d->margin_t,
		(int)d->margin_r, (int)d->margin_b);
	de_dbg(c, "planes: %d, bytes/line: %d, palette_info: %d\n", (int)d->planes,
		(int)d->rowspan_raw, (int)d->palette_info);

	d->width = d->margin_r - d->margin_l +1;
	d->height = d->margin_b - d->margin_t +1;
	de_dbg(c, "calculated dimensions: %dx%d\n", (int)d->width, (int)d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	d->rowspan = d->rowspan_raw * d->planes;
	de_dbg(c, "calculated bytes/row: %d\n", (int)d->rowspan);

	d->bits_per_pixel = d->bits * d->planes;

	if(d->encoding != 1) {
		de_err(c, "Unsupported encoding: %d\n", (int)d->encoding);
		goto done;
	}

	// Enumerate the valid PCX image types.
	if( (d->planes==1 && d->bits==1) ||
		/* (d->planes==1 && d->bits==2) ||   TODO: CGA mode */
		(d->planes==3 && d->bits==1) ||
		(d->planes==4 && d->bits==1) ||
		(d->planes==1 && d->bits==8) ||
		(d->planes==3 && d->bits==8) )
	{
		;
	}
	else {
		de_err(c, "Unsupported image type (bits=%d, planes=%d)\n",
			(int)d->bits, (int)d->planes);
		goto done;
	}

	// Sanity check
	if(d->rowspan > d->width * 3 + 100) {
		de_err(c, "Bad bytes/line (%d)\n", (int)d->rowspan_raw);
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static void do_read_vga_palette(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 k;

	if(d->version<5) return;
	if(d->bits_per_pixel==1) return;
	if(d->bits_per_pixel>8) return;
	pos = c->infile->len - 769;
	if(pos<128) return;

	if(de_getbyte(pos) != 0x0c) {
		if(d->bits_per_pixel>4) {
			de_warn(c, "Expected VGA palette was not found\n");
		}
		return;
	}

	// version is 5
	// number of colors is >2 and <256
	// VGA palette is present
	// EGA palette is not all black

	de_dbg(c, "Reading VGA palette at %d\n", (int)pos);
	d->has_vga_pal = 1;
	pos++;
	for(k=0; k<256; k++) {
		d->pal[k] = dbuf_getRGB(c->infile, pos + 3*k, 0);
	}
}

static int do_uncompress(deark *c, lctx *d)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 k;
	de_int64 expected_bytes;
	de_int64 endpos;

	pos = 128;

	expected_bytes = d->rowspan * d->height;
	d->unc_pixels = dbuf_create_membuf(c, expected_bytes);

	endpos = c->infile->len;
	if(d->has_vga_pal) {
		// The last 769 bytes of this file are reserved for the palette.
		// Don't try to decoded them as pixels.
		endpos -= 769;
	}

	while(1) {
		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		if(d->unc_pixels->len >= expected_bytes) {
			break; // Reached the end of the image
		}
		b = de_getbyte(pos++);

		if(b>=0xc0) {
			count = (de_int64)(b&0x3f);
			b2 = de_getbyte(pos++);

			for(k=0; k<count; k++) {
				dbuf_writebyte(d->unc_pixels, b2);
			}
		}
		else {
			dbuf_writebyte(d->unc_pixels, b);
		}
	}

	if(d->unc_pixels->len < expected_bytes) {
		de_warn(c, "Expected %d bytes of image data, but only found %d\n",
			(int)expected_bytes, (int)d->unc_pixels->len);
	}

	return 1;
}

static void do_bitmap_1bpp(deark *c, lctx *d)
{
	// Apparently, bilevel PCX images do not use a palette and are always black
	// and white.
	// The paletted algorithm would work (if we did something about the palette)
	// but this special case is easy and efficient.
	de_convert_and_write_image_bilevel(d->unc_pixels, 0,
		d->width, d->height, d->rowspan, 0, NULL);
}

static void do_bitmap_paletted(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 plane;
	de_byte b;
	unsigned int palent;

	img = de_bitmap_create(c, d->width, d->height, 3);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			palent = 0;
			for(plane=0; plane<d->planes; plane++) {
				b = de_get_bits_symbol(d->unc_pixels, (int)d->bits,
					j*d->rowspan + plane*d->rowspan_raw, i);
				palent |= b<<(plane*d->bits);
			}
			if(palent>255) palent=0; // Should be impossible.
			de_bitmap_setpixel_rgb(img, i, j, d->pal[palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_bitmap_24bpp(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 plane;
	de_byte rgb[3];

	img = de_bitmap_create(c, d->width, d->height, 3);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			//palent = 0;
			for(plane=0; plane<3; plane++) {
				rgb[plane] = dbuf_getbyte(d->unc_pixels, j*d->rowspan + plane*d->rowspan_raw +i);
			}
			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(rgb[0], rgb[1], rgb[2]));
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_bitmap(deark *c, lctx *d)
{
	if(d->bits_per_pixel==1) {
		do_bitmap_1bpp(c, d);
	}
	else if(d->bits_per_pixel<=8) {
		do_bitmap_paletted(c, d);
	}
	else if(d->bits_per_pixel==24) {
		do_bitmap_24bpp(c, d);
	}
	else {
		de_err(c, "Unsupported bits/pixel: %d\n", (int)d->bits_per_pixel);
	}
}

static void do_palette_stuff(deark *c, lctx *d)
{
	de_int64 k;
	de_uint32 clr;

	if((d->version==0 || d->version==3) && d->bits_per_pixel>2) {
		// Use default EGA palette
		for(k=0; k<16; k++) {
			clr = de_palette_pc16((int)k);
			// Have to swap red/blue. Don't know why.
			d->pal[k] = DE_MAKE_RGB(DE_COLOR_B(clr), DE_COLOR_G(clr), DE_COLOR_R(clr));
		}
	}
	// TODO: Default CGA palette

	do_read_vga_palette(c, d);
}

static void de_run_pcx(deark *c, const char *params)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_read_header(c, d)) {
		goto done;
	}

	do_palette_stuff(c, d);

	if(!do_uncompress(c, d)) {
		goto done;
	}

	do_bitmap(c, d);

done:
	dbuf_close(d->unc_pixels);
	de_free(c, d);
}

static int de_identify_pcx(deark *c)
{
	de_byte buf[8];

	de_read(buf, 0, 8);
	if(buf[0]==0x0a && (buf[1]==0 || buf[1]==2 || buf[1]==3
		|| buf[1]==4 || buf[1]==5))
	{
		if(de_input_file_has_ext(c, "pcx"))
			return 100;

		return 10;
	}
	return 0;
}

void de_module_pcx(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcx";
	mi->run_fn = de_run_pcx;
	mi->identify_fn = de_identify_pcx;
}
