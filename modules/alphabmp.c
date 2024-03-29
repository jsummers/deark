// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Alpha Microsystems BMP

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_alphabmp);

typedef struct localctx_struct {
	i64 npwidth, h;
	i64 pdwidth;
	i64 bpp;
	unsigned int has_palette;
	unsigned int palette_is_hls;
	i64 compression;
	i64 num_pal_entries;
	u32 pal[256];
} lctx;

static int do_read_palette(deark *c, lctx *d, i64 pos, i64 *pal_nbytes)
{
	de_dbg(c, "palette at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->num_pal_entries = de_getu16le(pos) + 1;
	de_dbg(c, "number of palette colors: %d", (int)d->num_pal_entries);
	if(d->palette_is_hls)
		*pal_nbytes = 2 + d->num_pal_entries * 6;
	else
		*pal_nbytes = 2 + d->num_pal_entries * 3;
	if(d->palette_is_hls) goto done;

	de_read_palette_rgb(c->infile, pos+2, d->num_pal_entries, 3, d->pal, 256, 0);
done:
	de_dbg_indent(c, -1);
	return 1;
}

static void do_bitmap(deark *c, lctx *d, dbuf *unc_pixels)
{
	i64 rowspan;
	i64 bits_per_row;
	de_bitmap *img = NULL;

	bits_per_row = de_pad_to_n(d->npwidth * d->bpp, 8);
	rowspan = bits_per_row/8;
	d->pdwidth = bits_per_row / d->bpp;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->h, 3);

	if(d->bpp<=8) {
		de_convert_image_paletted(unc_pixels, 0, d->bpp, rowspan, d->pal, img, 0);
	}
	else {
		de_convert_image_rgb(unc_pixels, 0, rowspan, 3, img, 0);
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

	de_bitmap_destroy(img);
}

static int do_uncompress_image(deark *c, lctx *d, i64 pos1, dbuf *unc_pixels)
{
	i64 bytes_in_this_line;
	i64 pos = pos1;
	i64 j;
	struct de_dfilter_ctx *dfctx = NULL;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg(c, "decompressing bitmap");

	// Each line is compressed independently, using PackBits.
	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);
	dcmpro.f = unc_pixels;
	dfctx = de_dfilter_create(c, dfilter_packbits_codec, NULL, &dcmpro, &dres);

	for(j=0; j<d->h; j++) {
		bytes_in_this_line = de_getu16le(pos);
		pos += 2;
		de_dfilter_addslice(dfctx, c->infile, pos, bytes_in_this_line);
		de_dfilter_command(dfctx, DE_DFILTER_COMMAND_SOFTRESET, 0);
		pos += bytes_in_this_line;
	}

	de_dfilter_finish(dfctx);
	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		return 0;
	}

	de_dbg(c, "decompressed %d bytes to %d bytes", (int)(pos-pos1),
		(int)unc_pixels->len);

	de_dfilter_destroy(dfctx);
	return 1;
}

static void de_run_alphabmp(deark *c, de_module_params *mparams)
{
	unsigned int flags;
	lctx *d = NULL;
	i64 pos;
	i64 palsize;
	dbuf *unc_pixels = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d = de_malloc(c, sizeof(lctx));
	de_declare_fmt(c, "Alpha Microsystems BMP");

	pos = 10;

	de_dbg(c, "bitmap image definition block at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->npwidth = de_getu16le(pos);
	d->h = de_getu16le(pos+2);
	de_dbg_dimensions(c, d->npwidth, d->h);
	if(!de_good_image_dimensions(c, d->npwidth, d->h)) goto done;

	d->bpp = de_getu16le(pos+4);
	de_dbg(c, "bits/pixel: %d", (int)d->bpp);

	flags = (unsigned int)de_getu16le(pos+6);
	d->has_palette = flags & 0x01;
	d->palette_is_hls = (flags>>1) & 0x01;
	de_dbg(c, "has-palette: %d", (int)d->has_palette);
	if(d->has_palette)
		de_dbg(c, "palette-is-HLS: %d", (int)d->palette_is_hls);

	d->compression = de_getu16le(pos+8);
	de_dbg(c, "compression: %d", (int)d->compression);
	de_dbg_indent(c, -1);

	pos += 70;

	if(d->has_palette) {
		if(d->palette_is_hls && d->bpp<=8) {
			de_err(c, "HLS palettes are not supported");
			goto done;
		}
		if(!do_read_palette(c, d, pos, &palsize)) goto done;
		pos += palsize;
	}
	else if(d->bpp<=8) {
		de_err(c, "Paletted images without an embedded palette are not supported");
		goto done;
	}

	de_dbg(c, "bitmap at %d", (int)pos);
	de_dbg_indent(c, 1);

	if(d->compression) {
		unc_pixels = dbuf_create_membuf(c, 32768, 0);
		if(!do_uncompress_image(c, d, pos, unc_pixels)) goto done;
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
	}

	if(d->bpp!=1 && d->bpp!=4 && d->bpp!=8 && d->bpp!=24) {
		de_err(c, "%d bits/pixel is not supported", (int)d->bpp);
		goto done;
	}

	do_bitmap(c, d, unc_pixels);
	de_dbg_indent(c, -1);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_alphabmp(deark *c)
{
	i64 flg;

	if(!de_input_file_has_ext(c, "bmp")) return 0;

	flg = de_getu16le(0);
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
