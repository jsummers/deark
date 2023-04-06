// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// ColoRIX

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_colorix);

struct colorix_ctx {
	u8 paltype;
	u8 stgtype;
	u8 imgtype;
	u8 is_compressed;
	u8 is_encrypted;
	u8 has_extension_block;
	i64 width, height;
	de_color pal[256];
};

static int do_colorix_decompress(deark *c, struct colorix_ctx *d, i64 pos1,
	dbuf *unc_pixels)
{
	int retval = 0;

	de_err(c, "Compression not supported");
	return retval;
}

static void do_colorix_image(deark *c, struct colorix_ctx *d, i64 pos1)
{
	de_bitmap *img = NULL;
	dbuf *unc_pixels = 0;

	de_dbg(c, "image at %"I64_FMT, pos1);
	img = de_bitmap_create(c, d->width, d->height, 3);

	if(d->is_compressed) {
		unc_pixels = dbuf_create_membuf(c, 0, 0);
		if(!do_colorix_decompress(c, d, pos1, unc_pixels)) {
			goto done;
		}
		de_convert_image_paletted(unc_pixels, pos1, 8, d->width, d->pal, img, 0);
	}
	else {
		de_convert_image_paletted(c->infile, pos1, 8, d->width, d->pal, img, 0);
	}
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
}

static void de_run_colorix(deark *c, de_module_params *mparams)
{
	i64 pos;
	struct colorix_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct colorix_ctx));
	pos = 4;
	d->width = de_getu16le_p(&pos);
	d->height = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->width, d->height);

	d->paltype = de_getbyte_p(&pos);
	de_dbg(c, "palette type: 0x%02x", (UI)d->paltype);
	if(d->paltype!=0xaf) {
		de_err(c, "Unsupported palette type: 0x%02x", (UI)d->paltype);
	}

	d->stgtype = de_getbyte_p(&pos);
	de_dbg(c, "storage type: 0x%02x", (UI)d->stgtype);

	if(d->stgtype & 0x80) d->is_compressed = 1;
	if(d->stgtype & 0x40) d->has_extension_block = 1;
	if(d->stgtype & 0x20) d->is_encrypted = 1;
	d->imgtype = d->stgtype & 0x0f; // I guess?

	if(d->imgtype != 0x00) {
		de_err(c, "Unsupported image type: 0x%02x", (UI)d->stgtype);
		goto done;
	}

	if(d->is_encrypted) {
		de_err(c, "Encrypted files not supported");
		goto done;
	}
	if(d->has_extension_block) {
		// TODO: We could tolerate this.
		de_err(c, "Extension blocks not supported");
		goto done;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	de_read_simple_palette(c, c->infile, pos, 256, 3, d->pal, 256, DE_RDPALTYPE_VGA18BIT, 0);
	pos += 768;
	do_colorix_image(c, d, pos);

done:
	de_free(c, d);
}

static int de_identify_colorix(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"RIX3", 4)) {
		return 0;
	}
	return 95;
}

void de_module_colorix(deark *c, struct deark_module_info *mi)
{
	mi->id = "colorix";
	mi->desc = "ColoRIX";
	mi->run_fn = de_run_colorix;
	mi->identify_fn = de_identify_colorix;
}
