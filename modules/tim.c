// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Playstation .TIM image format
// (Limited support. Probably works for 8-bits/pixel.)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_tim);

typedef struct localctx_struct {
	unsigned int bpp_code;
	unsigned int palette_flag;
	i64 bpp;
	i64 width, height;
	u32 pal[256];
} lctx;

static void do_read_palette(deark *c, lctx *d, i64 pos, i64 ncolors)
{
	i64 k;
	u32 n1, n2;
	char tmps[32];

	de_dbg(c, "CLUT block at %d", (int)pos);
	de_dbg_indent(c, 1);

	for(k=0; k<ncolors && k<256; k++) {
		n1 = (u32)de_getu16le(pos + 2*k);
		n2 = de_bgr555_to_888(n1);
		de_snprintf(tmps, sizeof(tmps), "0x%04x "DE_CHAR_RIGHTARROW" ", (unsigned int)n1);
		de_dbg_pal_entry2(c, k, n2, tmps, NULL, NULL);
		d->pal[k] = n2;
	}

	de_dbg_indent(c, -1);
}

static void do_pal8(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 clut_size;
	i64 ncolors_per_clut;
	i64 num_cluts;
	i64 second_header_blk_pos;
	i64 img_data_size_field;
	i64 width_field;
	i64 rowspan;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg_indent(c, 1); // still in the first header block

	if(!d->palette_flag) {
		de_err(c, "8-bit images without a palette aren't supported");
		goto done;
	}

	clut_size = de_getu32le(8);

	ncolors_per_clut = de_getu16le(16);
	num_cluts = de_getu16le(18);

	de_dbg(c, "clut 'size': %d", (int)clut_size);
	de_dbg(c, "colors per clut: %d", (int)ncolors_per_clut);
	de_dbg(c, "num cluts: %d", (int)num_cluts);
	de_dbg_indent(c, -1); // end of first header block

	do_read_palette(c, d, 20, ncolors_per_clut);

	second_header_blk_pos = 20 + num_cluts*ncolors_per_clut*2;
	de_dbg(c, "second header block at %d", (int)second_header_blk_pos);
	de_dbg_indent(c, 1);
	img_data_size_field = de_getu32le(second_header_blk_pos);
	de_dbg(c, "image data size field: %d", (int)img_data_size_field);
	width_field = de_getu16le(second_header_blk_pos+8);
	d->width = 2*width_field;
	d->height = de_getu16le(second_header_blk_pos+10);
	de_dbg(c, "width field: %d (width=%d)", (int)width_field, (int)d->width);
	de_dbg(c, "height: %d", (int)d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	de_dbg_indent(c, -1);

	img = de_bitmap_create(c, d->width, d->height, 3);

	pos = second_header_blk_pos + 12;
	de_dbg(c, "image data block at %d", (int)pos);
	rowspan = d->width;

	de_convert_image_paletted(c->infile, pos,
		8, rowspan, d->pal, img, 0);

	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_bitmap_destroy(img);
}

static void de_run_tim(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	unsigned int tim_type;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "first header block at %d", 0);
	de_dbg_indent(c, 1);

	tim_type = (unsigned int)de_getu32le(4);
	d->bpp_code = tim_type & 0x07;
	d->palette_flag = (tim_type>>3)&0x01;

	de_dbg(c, "TIM type: 0x%08x", tim_type);
	de_dbg_indent(c, 1);

	switch(d->bpp_code) {
	case 0: d->bpp = 4; break;
	case 1: d->bpp = 8; break;
	case 2: d->bpp = 16; break;
	case 3: d->bpp = 24; break;
	case 4:
		de_err(c, "Mixed Format not supported");
		goto done;
	default:
		de_err(c, "Unknown bits/pixel code (%u)", d->bpp_code);
		goto done;
	}

	de_dbg(c, "bits/pixel: %d, has-palette: %u", (int)d->bpp, d->palette_flag);

	de_dbg_indent(c, -1); // end of TIM type field

	// Hack: Unindent as if the first header block were complete.
	// But it probably isn't. We'll re-indent if needed.
	de_dbg_indent(c, -1);

	switch(d->bpp) {
	case 8:
		do_pal8(c, d);
		break;
	default:
		de_err(c, "Unsupported bits/pixel (%d)", (int)d->bpp);
		goto done;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, d);
}

static int de_identify_tim(deark *c)
{
	i64 x;

	if(dbuf_memcmp(c->infile, 0, "\x10\x00\x00\x00", 4))
		return 0;

	x = de_getu32le(4);
	if(x<=3 || x==8 || x==9) {
		if(de_input_file_has_ext(c, "tim")) return 100;
		return 15;
	}
	return 0;
}

void de_module_tim(deark *c, struct deark_module_info *mi)
{
	mi->id = "tim";
	mi->desc = "PlayStation graphics";
	mi->run_fn = de_run_tim;
	mi->identify_fn = de_identify_tim;
}
