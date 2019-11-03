// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// PrintPartner .GPH

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pp_gph);

struct page_ctx {
	i64 width, height;
	i64 width_raw;
	u8 cmpr_type;
	de_ucstring *imgname;
};

typedef struct localctx_struct {
	int reserved;
} lctx;

static void do_write_image_frombitmap(deark *c, lctx *d, struct page_ctx *pg,
	de_bitmap *img)
{
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = 2;
	fi->density.ydens = 1;

	if(c->filenames_from_file && pg->imgname && (pg->imgname->len > 0)) {
		de_finfo_set_name_from_ucstring(c, fi, pg->imgname, 0);
	}
	de_bitmap_write_to_file_finfo(img, fi, 0);
	de_finfo_destroy(c, fi);
}

static void do_write_image_fromuncpixels(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *unc_pixels)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, pg->width, pg->height, 1);
	de_convert_image_bilevel(unc_pixels, 0, pg->width_raw, img, DE_CVTF_WHITEISZERO);
	do_write_image_frombitmap(c, d, pg, img);
	de_bitmap_destroy(img);
}

// Decode the pixels of an uncompressed image
static void do_image_cmpr1(deark *c, lctx *d, struct page_ctx *pg, i64 pos1,
	i64 *bytes_consumed)
{
	dbuf *unc_pixels = NULL;

	*bytes_consumed = pg->width_raw*pg->height;
	unc_pixels = dbuf_open_input_subfile(c->infile, pos1,
		pg->width_raw*pg->height);
	do_write_image_fromuncpixels(c, d, pg, unc_pixels);
	dbuf_close(unc_pixels);
}

// A simple byte-oriented RLE scheme.
static void do_image_cmpr2(deark *c, lctx *d, struct page_ctx *pg, i64 pos1,
	i64 *bytes_consumed)
{
	i64 cmpr_len;
	i64 pos = pos1;
	dbuf *unc_pixels = NULL;

	cmpr_len = de_getu16le(pos);
	de_dbg(c, "cmpr data len: %d bytes", (int)cmpr_len);
	pos += 2;
	*bytes_consumed = 2 + cmpr_len;

	unc_pixels = dbuf_create_membuf(c, pg->width_raw*pg->height, 0x1);

	while(1) {
		i64 count;
		u8 b, b2;

		if(pos >= pos1+2+cmpr_len) break;
		b = de_getbyte(pos++);
		count = (i64)(b & 0x7f);
		if(b & 0x80) { // compressed run
			b2 = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // uncompressed run
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}

	do_write_image_fromuncpixels(c, d, pg, unc_pixels);
	dbuf_close(unc_pixels);
}

// A simple pixel-oriented RLE scheme. Each nibble represents a run of 1 to 7
// white or black pixels.
// It is unknown how run lengths of 0 are handled.
static void do_image_cmpr3(deark *c, lctx *d, struct page_ctx *pg, i64 pos1,
	i64 *bytes_consumed)
{
	de_bitmap *img = NULL;
	i64 pos = pos1;
	i64 nibble_count;
	i64 nibble_idx;
	i64 pixel_idx;
	u8 b;

	img = de_bitmap_create(c, pg->width, pg->height, 1);

	// Start with an all-white image:
	de_bitmap_rect(img, 0, 0, pg->width, pg->height, DE_STOCKCOLOR_WHITE, 0);

	nibble_count = de_getu16le(pos);
	de_dbg(c, "cmpr data len: %d nibbles", (int)nibble_count);
	pos += 2;

	*bytes_consumed = 2 + (nibble_count+1)/2;

	b = 0;
	pixel_idx = 0;
	for(nibble_idx=0; nibble_idx<nibble_count; nibble_idx++) {
		i64 count;
		int isblack;
		u8 nibble_val;
		i64 k;

		if((nibble_idx&0x1) == 0) {
			b = de_getbyte(pos++);
			nibble_val = b>>4;
		}
		else {
			nibble_val = b&0x0f;
		}

		count = (i64)(nibble_val&0x7);
		isblack = (nibble_val>=8);

		for(k=0; k<count; k++) {
			if(isblack)
				de_bitmap_setpixel_gray(img, pixel_idx%pg->width, pixel_idx/pg->width, 0x00);
			pixel_idx++;
		}
	}

	do_write_image_frombitmap(c, d, pg, img);
	de_bitmap_destroy(img);
}

static int do_one_image(deark *c, lctx *d, i64 pos1, int img_idx, i64 *bytes_consumed)
{
	i64 namelen;
	i64 pos = pos1;
	i64 bytes_consumed2 = 0;
	int retval = 0;

	struct page_ctx *pg = NULL;

	pg = de_malloc(c, sizeof(struct page_ctx));

	de_dbg(c, "image #%d at %d", img_idx, (int)pos1);
	de_dbg_indent(c, 1);
	namelen = (i64)de_getbyte(pos++);
	if(namelen>20) {
		de_err(c, "Invalid image");
		goto done;
	}

	pg->imgname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, namelen, pg->imgname, 0, DE_ENCODING_ASCII);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(pg->imgname));
	pos += 20;

	pg->cmpr_type = (i64)de_getbyte(pos++);
	de_dbg(c, "cmpr type: %d", (int)pg->cmpr_type);
	pg->height = (i64)de_getbyte(pos++);
	pg->width_raw = (i64)de_getbyte(pos++);
	pg->width = pg->width_raw*8;
	de_dbg_dimensions(c, pg->width, pg->height);

	if(pg->cmpr_type==1) {
		do_image_cmpr1(c, d, pg, pos, &bytes_consumed2);
		pos += bytes_consumed2;
	}
	else if(pg->cmpr_type==2) {
		do_image_cmpr2(c, d, pg, pos, &bytes_consumed2);
		pos += bytes_consumed2;
	}
	else if(pg->cmpr_type==3) {
		do_image_cmpr3(c, d, pg, pos, &bytes_consumed2);
		pos += bytes_consumed2;
	}
	else {
		de_err(c, "Unsupported compression type: %d", (int)pg->cmpr_type);
		goto done;
	}

	*bytes_consumed = pos - pos1;
	retval = 1;
done:
	de_dbg_indent(c, -1);
	if(pg) {
		ucstring_destroy(pg->imgname);
		de_free(c, pg);
	}
	return retval;
}

static void de_run_pp_gph(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 bytes_consumed;
	int img_idx = 0;
	u8 *bufptr;
	u8 buf[256];

	d = de_malloc(c, sizeof(lctx));

	de_read(buf, 0, sizeof(buf)-1);
	buf[sizeof(buf)-1] = '\0';
	bufptr = (u8*)de_strchr((const char*)buf, 0x1a);
	if(!bufptr) {
		de_err(c, "This doesn't look like a valid .GPH file");
		goto done;
	}

	pos = (bufptr - buf);
	de_dbg(c, "end of header found at %d", (int)pos);

	pos++;

	while(1) {
		if(pos > (c->infile->len - 24)) break;
		bytes_consumed = 0;
		if(!do_one_image(c, d, pos, img_idx, &bytes_consumed)) goto done;
		if(bytes_consumed<1) goto done;
		pos += bytes_consumed;
		img_idx++;
	}

done:
	de_free(c, d);
}

static int de_identify_pp_gph(deark *c)
{
	if(!de_input_file_has_ext(c, "gph")) return 0;

	if(!dbuf_memcmp(c->infile, 0, "PrintPartner", 12)) {
		return 100;
	}
	return 0;
}

void de_module_pp_gph(deark *c, struct deark_module_info *mi)
{
	mi->id = "pp_gph";
	mi->desc = "PrintPartner .GPH";
	mi->run_fn = de_run_pp_gph;
	mi->identify_fn = de_identify_pp_gph;
}
