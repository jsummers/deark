// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Zoner BMI bitmap image

// Warning: This code is not based on any written specifications, so it may be
// wrong or misleading. Read it at your own risk.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_bmi);

struct table_item {
	unsigned int tag_num;
	de_int64 tag_offs;
};

struct imageinfo {
	de_int64 w, h;
	unsigned int palmode;
	de_int64 bpp;
	de_int64 num_pal_entries;
	de_uint32 pal[256];
};

typedef struct localctx_struct {
	int input_encoding;
	de_int64 fixed_header_size;
	de_int64 num_table_items;
	struct table_item *table;
	struct imageinfo globalimg;
} lctx;

static void read_palette(deark *c, lctx *d, struct imageinfo *ii, de_int64 pos1)
{
	if(ii->num_pal_entries<1) return;
	de_dbg(c, "palette at %"INT64_FMT", %d entries", pos1, (int)ii->num_pal_entries);
	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, pos1, ii->num_pal_entries, 4,
		ii->pal, 256, DE_GETRGBFLAG_BGR);
	de_dbg_indent(c, -1);
}

// Read the fixed part of the header
static int do_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos1);
	de_dbg_indent(c, 1);

	pos += 9; // signature

	d->globalimg.w = de_getui16le_p(&pos);
	d->globalimg.h = de_getui16le_p(&pos);
	de_dbg_dimensions(c, d->globalimg.w, d->globalimg.h);

	d->globalimg.palmode = (unsigned int)de_getui16le_p(&pos);
	de_dbg(c, "palette mode: %u", d->globalimg.palmode);

	d->globalimg.bpp = de_getui16le_p(&pos);
	de_dbg(c, "bits/pixel: %d", (int)d->globalimg.bpp);

	if(d->globalimg.palmode && d->globalimg.bpp>=1 && d->globalimg.bpp<=8) {
		d->globalimg.num_pal_entries = (de_int64)(1U<<((unsigned int)d->globalimg.bpp));
	}

	pos += 2;

	d->num_table_items = de_getui16le_p(&pos);
	if(d->num_table_items>100) goto done;

	d->fixed_header_size = pos - pos1;
	retval = 1;

done:
	if(!retval) {
		de_err(c, "Error reading header");
	}
	de_dbg_indent(c, -1);
	return retval;
}

static int do_read_table(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 k;

	de_dbg(c, "table at %d, %d items", (int)pos1, (int)d->num_table_items);
	d->table = de_malloc(c, d->num_table_items*sizeof(struct table_item));

	de_dbg_indent(c, 1);

	for(k=0; k<d->num_table_items; k++) {
		d->table[k].tag_num = (unsigned int)de_getui16le_p(&pos);
		d->table[k].tag_offs = de_getui32le_p(&pos);
		de_dbg(c, "item[%d]: tag=0x%x, offset=%"INT64_FMT, (int)k,
			d->table[k].tag_num, d->table[k].tag_offs);
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void do_bitmap(deark *c, lctx *d, de_int64 pos1)
{
	int saved_indent_level;
	de_int64 pos = pos1;
	de_int64 unc_data_size;
	de_int64 max_uncmpr_block_size;
	de_int64 i, j;
	de_int64 rowspan;
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	struct imageinfo ii;
	const de_uint32 *pal_to_use = d->globalimg.pal;

	de_memset(&ii, 0, sizeof(struct imageinfo));

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "bitmap at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);
	ii.w = de_getui16le_p(&pos);
	ii.h = de_getui16le_p(&pos);
	de_dbg_dimensions(c, ii.w, ii.h);

	ii.bpp = de_getui16le_p(&pos);
	de_dbg(c, "bits/pixel: %d", (int)ii.bpp);

	ii.palmode = (unsigned int)de_getui16le_p(&pos);
	de_dbg(c, "palette mode: %u", ii.palmode);

	if(ii.palmode) {
		pal_to_use = ii.pal;
	}

	if(ii.palmode && ii.bpp>=1 && ii.bpp<=8) {
		ii.num_pal_entries = (de_int64)(1U<<((unsigned int)ii.bpp));
	}

	pos += 2;

	unc_data_size = de_getui32le_p(&pos);
	de_dbg(c, "uncmpr data size: %"INT64_FMT, unc_data_size);
	if(unc_data_size>DE_MAX_FILE_SIZE) goto done;

	max_uncmpr_block_size = de_getui16le_p(&pos);
	de_dbg(c, "max uncmpr block size: %d", (int)max_uncmpr_block_size);

	if(ii.num_pal_entries>0) {
		read_palette(c, d, &ii, pos);
		pos += 4*ii.num_pal_entries;
	}

	if(!de_good_image_dimensions(c, ii.w, ii.h)) goto done;
	if(ii.bpp!=24 && ii.bpp!=8 && ii.bpp!=4 && ii.bpp!=1) {
		de_err(c, "Unsupported image type");
		goto done;
	}

	unc_pixels = dbuf_create_membuf(c, unc_data_size, 1);

	while(1) {
		de_int64 blen;

		if(unc_pixels->len >= unc_data_size) break;
		if(pos >= c->infile->len) goto done;

		de_dbg(c, "block at %d", (int)pos);
		de_dbg_indent(c, 1);
		blen = de_getui16le_p(&pos);
		de_dbg(c, "block len: %d", (int)blen);
		pos++;
		if(pos+blen > c->infile->len) goto done;
		if(blen>max_uncmpr_block_size) goto done;

		if(!de_uncompress_zlib(c->infile, pos, blen, unc_pixels)) goto done;
		de_dbg_indent(c, -1);

		pos += blen;
	}

	img = de_bitmap_create(c, ii.w, ii.h, 3);
	rowspan = de_pad_to_n(ii.w*ii.bpp, 32)/8;

	for(j=0; j<ii.h; j++) {
		for(i=0; i<ii.w; i++) {
			if(ii.bpp==24) {
				de_uint32 clr;
				clr = dbuf_getRGB(unc_pixels, j*rowspan+i*3, DE_GETRGBFLAG_BGR);
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
			else {
				de_byte b;
				b = de_get_bits_symbol(unc_pixels, ii.bpp, j*rowspan, i);
				de_bitmap_setpixel_rgb(img, i, j, pal_to_use[(unsigned int)b]);
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_bitmaps(deark *c, lctx *d)
{
	de_int64 k;

	for(k=0; k<d->num_table_items; k++) {
		if(d->table[k].tag_num==0x0001) {
			do_bitmap(c, d, d->table[k].tag_offs);
		}
	}
}

static void do_comment(deark *c, lctx *d, de_int64 idx, de_int64 pos1)
{
	de_ucstring *s = NULL;
	de_int64 cmt_len;
	de_int64 pos = pos1;

	pos += 2;
	cmt_len = de_getui32le_p(&pos);
	pos += 2;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, cmt_len, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "comment (item[%d]): \"%s\"", (int)idx, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comments(deark *c, lctx *d)
{
	de_int64 k;

	for(k=0; k<d->num_table_items; k++) {
		if(d->table[k].tag_num==0x0003) {
			do_comment(c, d, k, d->table[k].tag_offs);
		}
	}
}

static void de_run_bmi(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos = 0;

	d = de_malloc(c, sizeof(lctx));

	if(c->input_encoding==DE_ENCODING_UNKNOWN)
		d->input_encoding = DE_ENCODING_WINDOWS1252;
	else
		d->input_encoding = c->input_encoding;

	if(!do_header(c, d, pos)) goto done;
	pos += d->fixed_header_size;

	if(d->globalimg.num_pal_entries>0) {
		read_palette(c, d, &d->globalimg, pos);
		pos += 4*d->globalimg.num_pal_entries;
	}

	if(!do_read_table(c, d, pos)) goto done;
	do_comments(c, d);
	do_bitmaps(c, d);

done:
	if(d) {
		de_free(c, d->table);
		de_free(c, d);
	}
}

static int de_identify_bmi(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "ZonerBMIa", 9))
		return 100;
	return 0;
}

void de_module_bmi(deark *c, struct deark_module_info *mi)
{
	mi->id = "bmi";
	mi->desc = "Zoner BMI bitmap";
	mi->run_fn = de_run_bmi;
	mi->identify_fn = de_identify_bmi;
}
