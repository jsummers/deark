// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Jovian Logic VI (.vi)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_jovianvi);

typedef struct localctx_struct {
	u8 imgtype;
	u8 pal_code;
	i64 w, h;
	i64 bitdepth;
	i64 bits_alloc;
	i64 rowspan;
	i64 palpos;
	i64 bitspos;
	i64 pal_first_entry_idx;
	i64 num_pal_colors;
	u32 pal[256];
} lctx;

static void do_read_palette(deark *c, lctx *d)
{
	i64 k, z;
	i64 idx;
	u8 b1[3];
	u8 b2[3];

	de_dbg(c, "palette at %d", (int)d->palpos);
	de_dbg_indent(c, 1);

	for(k=0; k<d->num_pal_colors; k++) {
		idx = d->pal_first_entry_idx + k;
		if(idx > 255) break;

		de_read(b1, d->palpos + 3*k, 3);
		for(z=0; z<3; z++) {
			if(d->pal_code==0) {
				b2[z] = de_scale_63_to_255(b1[z]); // 6-bit palette samples
			}
			else {
				b2[z] = b1[z]; // 8-bit palette samples
			}
		}

		d->pal[idx] = DE_MAKE_RGB(b2[0],b2[1],b2[2]);

		if(d->pal_code==0) {
			char tmps[64];
			de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
				(int)b1[0], (int)b1[1], (int)b1[2]);
			de_dbg_pal_entry2(c, k, d->pal[idx], tmps, NULL, NULL);
		}
		else {
			de_dbg_pal_entry(c, k, d->pal[idx]);
		}
	}

	de_dbg_indent(c, -1);
}

static void do_convert_grayscale(deark *c, lctx *d, de_bitmap *img)
{
	int i, j;
	u8 v;

	if(d->bitdepth==1) {
		de_convert_image_bilevel(c->infile, d->bitspos, d->rowspan, img, 0);
		goto done;
	}

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			v = de_get_bits_symbol(c->infile, d->bits_alloc, d->bitspos + j*d->rowspan, i);
			if(d->bitdepth==4) v *= 17;
			else if(d->bitdepth==6) {
				if(v<=63) v = de_scale_63_to_255(v);
				else v=0;
			}
			de_bitmap_setpixel_gray(img, i, j, v);
		}
	}

done:
	;
}

static void do_convert_rgb(deark *c, lctx *d, de_bitmap *img)
{
	i64 i, j;
	u32 clr;
	u8 b0, b1;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			if(d->bitdepth==16) {
				b0 = de_getbyte(d->bitspos + j*d->rowspan + i*2);
				b1 = de_getbyte(d->bitspos + j*d->rowspan + i*2 + 1);
				clr = (((u32)b1)<<8) | b0;
				clr = de_rgb565_to_888(clr);
			}
			else {
				clr = dbuf_getRGB(c->infile, d->bitspos+j*d->rowspan+i*3, 0);
			}
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void de_run_jovianvi(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_bitmap *img = NULL;
	int has_palette = 0;
	int is_grayscale = 0;
	const char *imgtypename;

	// Warning: This decoder is based on reverse engineering, and may be
	// incorrect or incomplete.

	d = de_malloc(c, sizeof(lctx));

	d->imgtype = de_getbyte(2);
	de_dbg(c, "image type: 0x%02x", (unsigned int)d->imgtype);

	switch(d->imgtype) {
	case 0x10:
		d->bitdepth = 16;
		break;
	case 0x11:
		d->bitdepth = 24;
		break;
	case 0x20:
		d->bitdepth = 4;
		is_grayscale = 1;
		break;
	case 0x21:
		d->bitdepth = 6;
		is_grayscale = 1;
		break;
	case 0x22:
		d->bitdepth = 8;
		is_grayscale = 1;
		break;
	case 0x23:
		d->bitdepth = 1;
		is_grayscale = 1;
		break;
	case 0x30:
		d->bitdepth = 8;
		has_palette = 1;
		break;
	case 0x31:
		d->bitdepth = 4;
		has_palette = 1;
		break;
	default:
		de_err(c, "Unknown VI image type: 0x%02x", (unsigned int)d->imgtype);
		goto done;
	}

	if(d->bitdepth==6)
		d->bits_alloc = 8;
	else
		d->bits_alloc = d->bitdepth;

	de_dbg_indent(c, 1);

	if(is_grayscale) imgtypename="grayscale";
	else if(has_palette) imgtypename="palette color";
	else imgtypename="RGB";
	de_dbg(c, "%d bits/pixel, %s", (int)d->bitdepth, imgtypename);
	de_dbg_indent(c, -1);
	if(is_grayscale && (d->bitdepth!=1 && d->bitdepth!=4 && d->bitdepth!=6 && d->bitdepth!=8)) {
		de_err(c, "This type of VI image is not supported");
		goto done;
	}

	d->w = de_getu16le(3);
	d->h = de_getu16le(5);
	de_dbg_dimensions(c, d->w, d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;


	if(has_palette) {
		d->pal_code = de_getbyte(9);
		de_dbg(c, "palette code: 0x%02x", (unsigned int)d->pal_code);

		d->pal_first_entry_idx = (i64)de_getbyte(10);
		d->num_pal_colors =  (i64)de_getbyte(11);
		if(d->num_pal_colors==0)
			d->num_pal_colors = 256;
		de_dbg(c, "index of first palette color: %d", (int)d->pal_first_entry_idx);
		de_dbg(c, "number of palette colors: %d", (int)d->num_pal_colors);
	}

	d->palpos = de_getu16le(12);
	d->bitspos = de_getu16le(14);

	// Read palette, if applicable
	if(has_palette) {
		do_read_palette(c, d);
	}

	// Convert the image
	de_dbg(c, "bitmap at %d", (int)d->bitspos);
	d->rowspan = (d->w*d->bits_alloc + 7)/8;
	img = de_bitmap_create(c, d->w, d->h, is_grayscale?1:3);
	if(has_palette) {
		de_convert_image_paletted(c->infile, d->bitspos, d->bitdepth, d->rowspan, d->pal, img, 0);
	}
	else if(is_grayscale) {
		do_convert_grayscale(c, d, img);
	}
	else {
		do_convert_rgb(c, d, img);
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_free(c, d);
}

static int de_identify_jovianvi(deark *c)
{
	u8 t;

	if(dbuf_memcmp(c->infile, 0, "VI", 2)) return 0;
	t = de_getbyte(2);
	if((t>=0x10 && t<=0x11) ||
		(t>=0x20 && t<=0x23) ||
		(t>=0x30 && t<=0x31))
	{
		return 100;
	}
	return 0;
}

void de_module_jovianvi(deark *c, struct deark_module_info *mi)
{
	mi->id = "jovianvi";
	mi->desc = "Jovian Logic VI";
	mi->run_fn = de_run_jovianvi;
	mi->identify_fn = de_identify_jovianvi;
}
