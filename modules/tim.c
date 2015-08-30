// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Playstation .TIM image format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	unsigned int bpp_code;
	unsigned int palette_flag;
	de_int64 bpp;
	de_int64 width, height;
	de_uint32 pal[256];
} lctx;

static void do_read_palette(deark *c, lctx *d, de_int64 pos, de_int64 ncolors)
{
	de_int64 k;
	de_uint32 n1, n2;

	for(k=0; k<ncolors && k<256; k++) {
		n1 = (de_uint32)de_getui16le(pos + 2*k);
		n2 = de_bgr555_to_888(n1);
		de_dbg(c, "pal[%3d] = %04x (%3d,%3d,%3d)\n", (int)k, n1,
			(int)DE_COLOR_R(n2), (int)DE_COLOR_G(n2), (int)DE_COLOR_B(n2));
		d->pal[k] = n2;
	}
}

static void do_pal8(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 clut_size;
	de_int64 ncolors_per_clut;
	de_int64 num_cluts;
	de_int64 second_header_blk_pos;
	de_int64 img_data_size_field;
	de_int64 width_field;
	de_int64 rowspan;
	de_int64 i, j;
	de_int64 pos;
	de_byte b;

	if(!d->palette_flag) {
		de_err(c, "8-bit images without a palette aren't supported\n");
		goto done;
	}

	clut_size = de_getui32le(8);

	ncolors_per_clut = de_getui16le(16);
	num_cluts = de_getui16le(18);

	de_dbg(c, "clut 'size': %d\n", (int)clut_size);
	de_dbg(c, "colors per clut: %d\n", (int)ncolors_per_clut);
	de_dbg(c, "num cluts: %d\n", (int)num_cluts);

	do_read_palette(c, d, 20, ncolors_per_clut);

	second_header_blk_pos = 20 + num_cluts*ncolors_per_clut*2;
	de_dbg(c, "second header block at %d\n", (int)second_header_blk_pos);
	img_data_size_field = de_getui32le(second_header_blk_pos);
	de_dbg(c, "image data size field: %d\n", (int)img_data_size_field);
	width_field = de_getui16le(second_header_blk_pos+8);
	d->width = 2*width_field;
	d->height = de_getui16le(second_header_blk_pos+10);
	de_dbg(c, "width field: %d (width=%d)\n", (int)width_field, (int)d->width);
	de_dbg(c, "height: %d\n", (int)d->height);

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	img = de_bitmap_create(c, d->width, d->height, 3);

	pos = second_header_blk_pos + 12;
	rowspan = d->width;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			b = de_getbyte(pos + j*rowspan + i);
			de_bitmap_setpixel_rgb(img, i, j, d->pal[(unsigned int)b]);
		}
	}

	de_bitmap_write_to_file(img, NULL);
done:
	de_bitmap_destroy(img);
}

static void de_run_tim(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	unsigned int tim_type;

	d = de_malloc(c, sizeof(lctx));

	tim_type = (unsigned int)de_getui32le(4);
	d->bpp_code = tim_type & 0x07;
	d->palette_flag = (tim_type>>3)&0x01;

	de_dbg(c, "TIM type: %08x\n", tim_type);

	switch(d->bpp_code) {
	case 0: d->bpp = 4; break;
	case 1: d->bpp = 8; break;
	case 2: d->bpp = 16; break;
	case 3: d->bpp = 24; break;
	case 4:
		de_err(c, "Mixed Format not supported\n");
		goto done;
	default:
		de_err(c, "Unknown bits/pixel code (%u)\n", d->bpp_code);
		goto done;
	}

	de_dbg(c, "bits/pixel: %d, has-palette: %u\n", (int)d->bpp, d->palette_flag);


	switch(d->bpp) {
	case 8:
		do_pal8(c, d);
		break;
	default:
		de_err(c, "Unsupported bits/pixel (%d)\n", (int)d->bpp);
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_tim(deark *c)
{
	de_int64 x;

	if(dbuf_memcmp(c->infile, 0, "\x10\x00\x00\x00", 4))
		return 0;

	x = de_getui32le(4);
	if(x<=3 || x==8 || x==9) {
		if(de_input_file_has_ext(c, "tim")) return 100;
		return 15;
	}
	return 0;
}

void de_module_tim(deark *c, struct deark_module_info *mi)
{
	mi->id = "tim";
	mi->run_fn = de_run_tim;
	mi->identify_fn = de_identify_tim;

	// Probably works for 8-bits/pixel, but I'm not convinced.
	mi->flags |= DE_MODFLAG_NONWORKING;
}
