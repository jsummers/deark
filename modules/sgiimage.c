// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// SGI image / RGB / IRIS

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_sgiimage);

#define CMI_NORMAL       0
#define CMI_RGB332       1
#define CMI_PALETTED     2
#define CMI_PALETTE_ONLY 3

struct sgiimage_offsettab_entry {
	u32 pos;
	u32 len;
};

struct sgiimage_ctx {
	de_encoding input_encoding;
	u8 storage_fmt;
	UI bytes_per_sample;
	UI dimension_count;
	u32 pix_min, pix_max;
	u32 colormap_id; // CMI_*
	i64 width;
	i64 height;
	i64 num_channels;

	u8 is_grayscale;
	u8 has_alpha;
	u8 warned_bad_offset;
	i64 rowspan;
	i64 num_scanlines;
	i64 total_unc_size;
	de_ucstring *name;
};

static const char *get_cmprtype_name(u8 n)
{
	const char *name = NULL;

	switch(n) {
	case 0: name = "none"; break;
	case 1: name = "RLE"; break;
	}
	return name?name:"?";
}

static const char *get_cmi_name(u32 n)
{
	const char *name = NULL;

	switch(n) {
	case CMI_NORMAL: name = "normal image"; break;
	case CMI_RGB332: name = "RGB332"; break;
	case CMI_PALETTED: name = "paletted"; break;
	case CMI_PALETTE_ONLY: name = "palette only"; break;
	}
	return name?name:"?";
}

static UI sgiimage_getsample_p(struct sgiimage_ctx *d, dbuf *f, i64 *ppos)
{
	UI s;

	if(d->bytes_per_sample==2) {
		s = (UI)dbuf_getu16be_p(f, ppos);
	}
	else {
		s = dbuf_getbyte_p(f, ppos);
	}
	return s;
}

static void sgiimage_decode_image(deark *c, struct sgiimage_ctx *d,
	dbuf *inf, i64 pos1, de_bitmap *img, de_bitmap *imglo)
{
	i64 pos = pos1;
	i64 pn;
	i64 i, j;

	for(pn=0; pn<d->num_channels; pn++) {
		i64 samplenum;

		if(d->has_alpha && pn==(d->num_channels-1))
			samplenum = 3;
		else
			samplenum = pn;

		for(j=0; j<d->height; j++) {
			for(i=0; i<d->width; i++) {
				UI s;

				s = sgiimage_getsample_p(d, inf, &pos);

				if(imglo) {
					de_bitmap_setsample(img, i, j, samplenum, (de_colorsample)(s>>8));
					de_bitmap_setsample(imglo, i, j, samplenum, (s&0xff));
				}
				else {
					de_bitmap_setsample(img, i, j, samplenum, (de_colorsample)s);
				}
			}
		}
	}
}

static void sgiimage_decompress_rle_scanline(deark *c,
	struct sgiimage_ctx *d, i64 scanline_num, i64 pos1, i64 len,
	dbuf *unc_pixels)
{
	i64 curpos;
	i64 endpos;
	i64 num_dcmpr_bytes = 0;

	curpos = pos1;
	endpos = pos1 + len;

	// Some files seem to set the offset to 0 for a nonexistent alpha channel.
	if(pos1 < 20) {
		if(!d->warned_bad_offset) {
			de_warn(c, "Bad offset at scanline %"I64_FMT": %"I64_FMT,
				scanline_num, pos1);
			d->warned_bad_offset = 1;
		}
		goto done;
	}

	while(1) {
		UI n;
		i64 count;

		if(curpos >= endpos) break; // end of input
		if(num_dcmpr_bytes >= d->rowspan) break; // sufficient output

		n = sgiimage_getsample_p(d, c->infile, &curpos);
		count = (i64)(n & 0x7f);
		if(count==0) break;
		if(n & 0x80) { // noncompressed run
			dbuf_copy(c->infile, curpos, count*d->bytes_per_sample, unc_pixels);
			curpos += count*d->bytes_per_sample;
		}
		else { // RLE run
			UI n2;

			n2 = sgiimage_getsample_p(d, c->infile, &curpos);
			if(d->bytes_per_sample==2) {
				i64 k2;

				for(k2=0; k2<count; k2++) {
					dbuf_writeu16be(unc_pixels, (i64)n2);
				}
			}
			else {
				dbuf_write_run(unc_pixels, (u8)n2, count);
			}
		}
		num_dcmpr_bytes += count*d->bytes_per_sample;
	}

done:
	;
}

static void sgiimage_decompress_rle(deark *c, struct sgiimage_ctx *d,
	dbuf *unc_pixels)
{
	struct sgiimage_offsettab_entry *offsettab = NULL;
	i64 i;
	i64 pos;
	i64 first_alpha_scanline;

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

	if(d->has_alpha) {
		first_alpha_scanline = d->height * (d->num_channels-1);
	}
	else {
		first_alpha_scanline = d->num_scanlines;
	}

	for(i=0; i<d->num_scanlines; i++) {
		i64 expected_ulen;
		i64 actual_ulen;

		sgiimage_decompress_rle_scanline(c, d, i,
			(i64)offsettab[i].pos, (i64)offsettab[i].len, unc_pixels);

		expected_ulen = (i+1) * d->rowspan;
		actual_ulen = dbuf_get_length(unc_pixels);
		if(actual_ulen != expected_ulen) {
			if((actual_ulen < expected_ulen) && i>=first_alpha_scanline) {
				// If we didn't decompress enough bytes, don't default to 0 (invisible)
				// if this is the alpha channel.
				dbuf_write_run(unc_pixels, 0xff, expected_ulen - actual_ulen);
			}
			else {
				dbuf_truncate(unc_pixels, expected_ulen);
			}
		}
	}

	dbuf_flush(unc_pixels);
	de_free(c, offsettab);
}

static void do_sgiimage_image(deark *c, struct sgiimage_ctx *d)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_bitmap *imglo = NULL;

	d->is_grayscale = (d->num_channels<=2);
	d->has_alpha = (d->num_channels==2 || d->num_channels==4);

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	if(d->pix_max>0 && (
		(d->bytes_per_sample==1 && d->pix_max<24) ||
		(d->bytes_per_sample==2 && d->pix_max<24*256)))
	{
		// If pix_max is to be believed, this image likely needs its brightness
		// adjusted.
		de_warn(c, "This image might need special processing (not supported).");
	}

	img = de_bitmap_create(c, d->width, d->height, (int)d->num_channels);
	if(d->bytes_per_sample==2) {
		imglo = de_bitmap_create(c, d->width, d->height, (int)d->num_channels);
	}

	d->rowspan = d->width * d->bytes_per_sample;
	d->num_scanlines = d->height * d->num_channels;
	d->total_unc_size = d->num_scanlines * d->rowspan;

	if(d->storage_fmt==0) { // Uncompressed
		sgiimage_decode_image(c, d, c->infile, 512, img, imglo);
	}
	else {
		unc_pixels = dbuf_create_membuf(c, d->total_unc_size, 0);
		dbuf_enable_wbuffer(unc_pixels);
		sgiimage_decompress_rle(c, d, unc_pixels);
		sgiimage_decode_image(c, d, unc_pixels, 0, img, imglo);
	}

	// Remove the alpha channel if it seems bad
	if(!imglo) {
		de_bitmap_optimize_alpha(img, 0x4 | 0x2);
	}

	de_bitmap16_write_to_file_finfo(img, imglo, NULL, DE_CREATEFLAG_FLIP_IMAGE |
		DE_CREATEFLAG_OPT_IMAGE);

done:
	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
	de_bitmap_destroy(imglo);
}

static void de_run_sgiimage(deark *c, de_module_params *mparams)
{
	struct sgiimage_ctx *d = NULL;
	i64 pos;
	UI min_dim_count_expected;
	int need_errmsg = 0;

	d = de_malloc(c, sizeof(struct sgiimage_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	pos = 2;
	d->storage_fmt = de_getbyte_p(&pos);
	de_dbg(c, "compression: %u (%s)", (UI)d->storage_fmt,
		get_cmprtype_name(d->storage_fmt));

	d->bytes_per_sample = (UI)de_getbyte_p(&pos);
	de_dbg(c, "bytes/sample: %u", d->bytes_per_sample);

	d->dimension_count = (UI)de_getu16be_p(&pos);
	de_dbg(c, "dimension count: %u", d->dimension_count);

	d->width = de_getu16be_p(&pos);
	de_dbg(c, "x-size: %"I64_FMT, d->width);
	d->height = de_getu16be_p(&pos);
	de_dbg(c, "y-size: %"I64_FMT, d->height);
	d->num_channels = de_getu16be_p(&pos);
	de_dbg(c, "z-size: %u", (UI)d->num_channels);

	d->pix_min = (u32)de_getu32be_p(&pos);
	d->pix_max = (u32)de_getu32be_p(&pos);
	de_dbg(c, "pix min, max: %u, %u", (UI)d->pix_min, (UI)d->pix_max);
	// TODO?: Support normalizing the image brightness/contrast.
	// Unfortunately, the spec is ambiguous about the meaning of these fields,
	// and there's no simple logic that would always do the right thing.

	pos += 4; // unused

	d->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 80, d->name, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->name));
	pos += 80;

	d->colormap_id = (u32)de_getu32be_p(&pos);
	de_dbg(c, "colormap code: %u (%s)", (UI)d->colormap_id,
		get_cmi_name(d->colormap_id));

	if(d->storage_fmt>1) {
		need_errmsg = 1;
		goto done;
	}

	if(d->colormap_id!=CMI_NORMAL) {
		// TODO: Support other image types?
		need_errmsg = 1;
		goto done;
	}

	if(d->bytes_per_sample!=1 && d->bytes_per_sample!=2) {
		need_errmsg = 1;
		goto done;
	}

	// We're hoping that unused fields will be set to 0 or 1.
	if(d->width==0) d->width = 1;
	if(d->height==0) d->height = 1;
	if(d->num_channels==0) d->num_channels = 1;

	if(d->num_channels>1) min_dim_count_expected = 3;
	else if(d->height>1) min_dim_count_expected = 2;
	else min_dim_count_expected = 1;

	if(d->dimension_count<min_dim_count_expected || d->dimension_count>3) {
		de_warn(c, "Likely bad dimension count (is %u, assuming it should be %u)",
			d->dimension_count, min_dim_count_expected);
	}
	// Note that, other than for the above warning, we ignore dimension_count.
	// The x-size, y-size, z-size fields seem to be more reliable than it is.

	if(d->num_channels<1 || d->num_channels>4) {
		need_errmsg = 1;
		goto done;
	}

	do_sgiimage_image(c, d);

done:
	if(need_errmsg) {
		de_err(c, "This type of SGI image is not supported");
	}
	if(d) {
		ucstring_destroy(d->name);
		de_free(c, d);
	}
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
	if(n<1 || n>2) return 0;

	n = (UI)de_getu16be(4); // "DIMENSION"
	// Only 1-3 are legal, but we allow 0-4 because this field is confusing
	// and underspecified.
	if(n>4) return 0;

	n = (UI)de_getu16be(10); // "ZSIZE"
	// Allow 0 because this field may be unused for some image types.
	if(n>4) return 0;

	return 60;
}

void de_module_sgiimage(deark *c, struct deark_module_info *mi)
{
	mi->id = "sgiimage";
	mi->desc = "SGI image";
	mi->run_fn = de_run_sgiimage;
	mi->identify_fn = de_identify_sgiimage;
}
