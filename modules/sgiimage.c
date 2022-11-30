// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// SGI image / RGB / IRIS

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_sgiimage);

struct sgiimage_offsettab_entry {
	u32 pos;
	u32 len;
};

struct sgiimage_ctx {
	u8 storage_fmt;
	UI bytes_per_sample;
	UI dimension_code;
	u32 colormap_id;
	i64 width;
	i64 height;
	i64 num_channels;

	i64 rowspan;
	i64 num_scanlines;
	i64 total_unc_size;
};

static void sgiimage_decode_image(deark *c, struct sgiimage_ctx *d,
	dbuf *inf, i64 pos1, de_bitmap *img)
{
	i64 pos = pos1;
	i64 pn;
	i64 i, j;

	for(pn=0; pn<d->num_channels; pn++) {
		for(j=0; j<d->height; j++) {
			for(i=0; i<d->width; i++) {
				de_colorsample b;

				b = dbuf_getbyte_p(inf, &pos);
				// TODO: Handle PIXMIN, PIXMAX
				if(d->num_channels==1) {
					de_bitmap_setpixel_gray(img, i, j, b);
				}
				else {
					de_bitmap_setsample(img, i, j, pn, b);
				}
			}
		}
	}
}
static void sgiimage_decompress_rle_scanline(deark *c,
	struct sgiimage_ctx *d, i64 pos1, i64 len,
	dbuf *unc_pixels)
{
	i64 curpos;
	i64 endpos;
	i64 num_dcmpr_bytes = 0;

	curpos = pos1;
	endpos = pos1 + len;

	while(1) {
		UI b;
		i64 count;

		if(curpos >= endpos) break; // end of input
		if(num_dcmpr_bytes >= d->rowspan) break; // sufficient output

		b = de_getbyte_p(&curpos);
		count = (i64)(b & 0x7f);
		if(count==0) break;
		if(b >= 0x80) { // noncompressed run
			dbuf_copy(c->infile, curpos, count, unc_pixels);
			curpos += count;
		}
		else { // RLE run
			u8 b2;

			b2 = de_getbyte_p(&curpos);
			dbuf_write_run(unc_pixels, b2, count);
		}
		num_dcmpr_bytes += count;
	}
}

static void sgiimage_decompress_rle(deark *c, struct sgiimage_ctx *d,
	dbuf *unc_pixels)
{
	struct sgiimage_offsettab_entry *offsettab = NULL;
	i64 i;
	i64 pos;

	offsettab = de_mallocarray(c, d->num_scanlines,
		sizeof(struct sgiimage_offsettab_entry));

	pos = 512;
	de_dbg(c, "scanline table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "offsets at %"I64_FMT, pos);
	for(i=0; i<d->num_scanlines; i++) {
		offsettab[i].pos = (u32)de_getu32be_p(&pos);
	}
	de_dbg(c, "lengths at %"I64_FMT, pos);
	for(i=0; i<d->num_scanlines; i++) {
		offsettab[i].len = (u32)de_getu32be_p(&pos);
	}
	de_dbg(c, "table end: %"I64_FMT, pos);

	if(c->debug_level>=2) {
		for(i=0; i<d->num_scanlines; i++) {
			de_dbg2(c, "scanline[%"I64_FMT"]: offs=%u len=%u", i,
				(UI)offsettab[i].pos, (UI)offsettab[i].len);
		}
	}
	de_dbg_indent(c, -1);

	for(i=0; i<d->num_scanlines; i++) {
		i64 expected_ulen;

		sgiimage_decompress_rle_scanline(c, d,
			(i64)offsettab[i].pos, (i64)offsettab[i].len,
			unc_pixels);

		expected_ulen = (i+1) * d->rowspan;
		if(dbuf_get_length(unc_pixels) != expected_ulen) {
			dbuf_truncate(unc_pixels, expected_ulen);
		}
	}

	dbuf_flush(unc_pixels);
	de_free(c, offsettab);
}

static void do_sgiimage_image(deark *c, struct sgiimage_ctx *d)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	img = de_bitmap_create(c, d->width, d->height, (int)d->num_channels);

	d->rowspan = d->width * d->bytes_per_sample;
	d->num_scanlines = d->height * d->num_channels;
	d->total_unc_size = d->num_scanlines * d->rowspan;

	if(d->storage_fmt==0) { // Uncompressed
		sgiimage_decode_image(c, d, c->infile, 512, img);
	}
	else {
		unc_pixels = dbuf_create_membuf(c, d->total_unc_size, 0);
		dbuf_enable_wbuffer(unc_pixels);
		sgiimage_decompress_rle(c, d, unc_pixels);
		sgiimage_decode_image(c, d, unc_pixels, 0, img);
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);

done:
	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
}

static void de_run_sgiimage(deark *c, de_module_params *mparams)
{
	struct sgiimage_ctx *d = NULL;
	i64 pos;
	int ok;

	d = de_malloc(c, sizeof(struct sgiimage_ctx));

	pos = 2;
	d->storage_fmt = de_getbyte_p(&pos);
	de_dbg(c, "compression: %u", (UI)d->storage_fmt);

	d->bytes_per_sample = (UI)de_getbyte_p(&pos);
	de_dbg(c, "bytes/sample: %u", d->bytes_per_sample);

	d->dimension_code = (UI)de_getu16be_p(&pos);
	de_dbg(c, "dimension code: %u", d->dimension_code);

	d->width = de_getu16be_p(&pos);
	d->height = de_getu16be_p(&pos);
	de_dbg_dimensions(c, d->width, d->height);

	d->num_channels = de_getu16be_p(&pos); // a.k.a. ZSIZE
	de_dbg(c, "num channels: %u", (UI)d->num_channels);

	pos += 8; // PIXMIN, PIXMAX
	pos += 4; // unused
	pos += 80; // name (TODO)

	d->colormap_id = (u32)de_getu32be_p(&pos);
	de_dbg(c, "colormap code: %u", (UI)d->colormap_id);

	// We support these image types:
	//
	// dim.code     num.chan.  colormap_id
	// (DIMENSION)  (ZSIZE)    (COLORMAP)
	// =========    =========  ===========
	//  2           1          0           = grayscale
	//  3           3          0           = RGB
	//  3           4          0           = RGBA

	ok = 0;
	if(d->storage_fmt>1) {
		;
	}
	else if(d->bytes_per_sample!=1) {
		; // TODO: Support 16 bits/sample
	}
	else if(d->colormap_id!=0) {
		;
	}
	else if((d->dimension_code==2 && d->num_channels==1) ||
		(d->dimension_code==3 && d->num_channels==3) ||
		(d->dimension_code==3 && d->num_channels==4))
	{
		ok = 1;
	}

	if(!ok) {
		de_err(c, "This type of SGI image is not supported");
		goto done;
	}

	do_sgiimage_image(c, d);

done:
	de_free(c, d);
}

static int de_identify_sgiimage(deark *c)
{
	UI n;

	if(c->infile->len<513) return 0;

	n = (UI)de_getu16be(0); // MAGIC
	if(n!=474) return 0;

	n = (UI)de_getbyte(2); // "STORAGE"
	if(n>1) return 0;

	n = (UI)de_getbyte(3); // "BPC"
	if(n<1 && n>2) return 0;

	n = (UI)de_getu16be(4); // "DIMENSION"
	if(n<1 || n>3) return 0;

	return 60;
}

void de_module_sgiimage(deark *c, struct deark_module_info *mi)
{
	mi->id = "sgiimage";
	mi->desc = "SGI image";
	mi->run_fn = de_run_sgiimage;
	mi->identify_fn = de_identify_sgiimage;
}
