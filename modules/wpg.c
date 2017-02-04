// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// WordPerfect Graphics

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wpg);

typedef struct localctx_struct {
	de_int64 start_of_data;
	de_byte ver_major, ver_minor;
	int has_pal;
	de_uint32 pal[256];
} lctx;

static int do_read_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	pos += 4; // FileId

	d->start_of_data = de_getui32le(pos);
	de_dbg(c, "start of data: %u\n", (unsigned int)d->start_of_data);
	pos += 4;

	pos++; // ProductType
	pos++; // FileType

	d->ver_major = de_getbyte(pos++);
	d->ver_minor = de_getbyte(pos++);
	de_dbg(c, "version: %d.%d\n", (int)d->ver_major, (int)d->ver_minor);

	de_dbg_indent(c, -1);
	return 1;
}

typedef void (*record_handler_fn)(deark *c, lctx *d, de_byte rectype, de_int64 dpos,
	de_int64 dlen);

struct wpg_rectype_info {
	de_byte rectype;
	const char *name;
	record_handler_fn fn;
};

static int do_uncompress_rle(deark *c, lctx *d, dbuf *f, de_int64 pos1, de_int64 len,
	de_int64 rowspan, dbuf *unc_pixels)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;
	de_int64 k;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b==0x00) { // repeat scanline
			de_int64 src_line_pos;

			count = dbuf_getbyte(f, pos++);

			// Make 'count' more copies of the previous scanline
			src_line_pos = unc_pixels->len - rowspan;
			for(k=0; k<count; k++) {
				// (It is allowed to copy from a membuf to itself.)
				dbuf_copy(unc_pixels, src_line_pos, rowspan, unc_pixels);
			}
		}
		else if(b<=0x7f) { // uncompressed run
			count = (de_int64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
		else if(b==0x80) { // Special 0xff compression
			count = (de_int64)dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, 0xff, count);
		}
		else { // byte RLE compression
			count = (de_int64)(b&0x7f);
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
	}

	return 1;
}

static void handler_bitmap(deark *c, lctx *d, de_byte rectype, de_int64 dpos1, de_int64 dlen)
{
	de_int64 w, h;
	de_int64 xdens, ydens;
	de_int64 bpp;
	de_int64 pos = dpos1;
	de_int64 rowspan;
	int is_bilevel;
	dbuf *unc_pixels = NULL;
	struct deark_bitmap *img = NULL;

	if(rectype==0x14)
		pos += 10;

	w = de_getui16le(pos);
	pos += 2;
	h = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);

	bpp = de_getui16le(pos);
	de_dbg(c, "bits/pixel: %d\n", (int)bpp);
	pos += 2;

	xdens = de_getui16le(pos);
	pos += 2;
	ydens = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "density: %dx%d dpi\n", (int)xdens, (int)ydens);

	if(bpp!=1 && bpp!=2 && bpp!=4 && bpp!=8) {
		de_err(c, "Unsupported bitmap depth: %d\n", (int)bpp);
		goto done;
	}
	if(!de_good_image_dimensions(c, w, h)) goto done;

	// Evidence suggests the palette is to be ignored if bpp==1.
	// (Or maybe you're supposed to use pal[0] and pal[15]?)
	is_bilevel = (bpp==1);

	rowspan = (bpp * w + 7)/8;

	unc_pixels = dbuf_create_membuf(c, h*rowspan, 0x1);

	if(!do_uncompress_rle(c, d, c->infile, pos, dpos1+dlen-pos, rowspan, unc_pixels)) {
		goto done;
	}

	img = de_bitmap_create(c, w, h, is_bilevel?1:3);

	if(xdens>0 && ydens>0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = (double)xdens;
		img->ydens = (double)ydens;
	}

	if(is_bilevel) {
		de_convert_image_bilevel(unc_pixels, 0, rowspan, img, 0);
	}
	else {
		if(!d->has_pal) {
			// TODO: Figure out what the default palette is.
			de_err(c, "Paletted images with no palette are not supported\n");
		}
		de_convert_image_paletted(unc_pixels, 0, bpp, rowspan, d->pal, img, 0);
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
}

static void handler_colormap(deark *c, lctx *d, de_byte rectype, de_int64 dpos1, de_int64 dlen)
{
	de_int64 start_index;
	de_int64 num_entries;
	de_int64 pos = dpos1;

	d->has_pal = 1;
	start_index = de_getui16le(pos);
	de_dbg(c, "start index: %d\n", (int)start_index);
	pos += 2;

	num_entries = de_getui16le(pos);
	de_dbg(c, "num entries: %d\n", (int)num_entries);
	pos += 2;

	if(start_index+num_entries>256) start_index = 256 - num_entries;
	if(start_index<0 || start_index+num_entries>256) return;

	de_read_palette_rgb(c->infile, pos, num_entries, 3, &d->pal[start_index], 256, 0);
}

static const struct wpg_rectype_info wmf_rectype_info_arr[] = {
	{ 0x01, "Fill attributes", NULL },
	{ 0x02, "Line attributes", NULL },
	{ 0x03, "Marker attributes", NULL },
	{ 0x04, "Polymarker", NULL },
	{ 0x05, "Line", NULL },
	{ 0x06, "Polyline", NULL },
	{ 0x07, "Rectangle", NULL },
	{ 0x08, "Polygon", NULL },
	{ 0x09, "Ellipse", NULL },
	{ 0x0b, "Bitmap, Type 1", handler_bitmap },
	{ 0x0c, "Graphics text, Type 1", NULL },
	{ 0x0d, "Graphics text attributes", NULL },
	{ 0x0e, "Color map", handler_colormap },
	{ 0x0f, "Start of WPG data", NULL },
	{ 0x10, "End of WPG data", NULL },
	{ 0x11, "PostScript data, Type 1", NULL },
	{ 0x12, "Output attributes", NULL },
	{ 0x13, "Curved polyline", NULL },
	{ 0x14, "Bitmap, Type 2", handler_bitmap },
	{ 0x15, "Start figure", NULL },
	{ 0x16, "Start chart", NULL },
	{ 0x17, "PlanPerfect data", NULL },
	{ 0x18, "Graphics text, Type 2", NULL },
	{ 0x19, "Start of WPG data, Type 2", NULL },
	{ 0x1a, "Graphics text, Type 3", NULL },
	{ 0x1b, "PostScript data, Type 2", NULL }
};

static const struct wpg_rectype_info *find_wpg_rectype_info(de_byte rectype)
{
	de_int64 i;
	for(i=0; i<(de_int64)DE_ITEMS_IN_ARRAY(wmf_rectype_info_arr); i++) {
		if(wmf_rectype_info_arr[i].rectype == rectype) {
			return &wmf_rectype_info_arr[i];
		}
	}
	return NULL;
}

static int do_record(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_byte rectype;
	de_int64 rec_dlen;
	int retval = 0;
	const char *name;
	const struct wpg_rectype_info *wri;

	rectype = de_getbyte(pos++);
	wri = find_wpg_rectype_info(rectype);
	if(wri) name = wri->name;
	else name="?";
	de_dbg(c, "record type 0x%02x (%s) at %d\n", (unsigned int)rectype, name, (int)pos1);
	de_dbg_indent(c, 1);

	rec_dlen = (de_int64)de_getbyte(pos++);

	// As far as I can tell, the variable-length integer works as follows.
	// An integer uses either 1, 3, or 5 bytes.

	// number = d c b a  (d = most-significant bits, ...)
	//  value           byte0    byte1    byte2    byte3    byte4
	//  --------------  -------- -------- -------- -------- --------
	//  (0-32767)     : 11111111 aaaaaaaa 0bbbbbbb
	//  (0-2147483647): 11111111 cccccccc 1ddddddd aaaaaaaa bbbbbbbb
	//  (0-254)       : aaaaaaaa [where the a's are not 1s]

	if(rec_dlen==0xff) {
		// Not an 8-bit value. Could be 16-bit or 32-bit.
		rec_dlen = de_getui16le(pos);
		pos += 2;

		if(rec_dlen & 0x8000) { // A 32-bit value
			de_int64 n;

			n = de_getui16le(pos);
			pos += 2;
			rec_dlen = ((rec_dlen&0x7fff)<<16) | n;
		}
	}

	de_dbg(c, "rec dpos=%d, dlen=[%d]%d\n", (int)pos, (int)(pos-(pos1+1)), (int)rec_dlen);

	if(wri && wri->fn) {
		wri->fn(c, d, rectype, pos, rec_dlen);
	}

	*bytes_consumed = (pos-pos1) + rec_dlen;
	retval = 1;

	de_dbg_indent(c, -1);
	return retval;
}

static int do_record_area(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "record area at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	while(1) {
		de_int64 bytes_consumed = 0;
		int ret;

		if(pos >= c->infile->len) break;

		ret = do_record(c, d, pos, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;

		pos += bytes_consumed;
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_wpg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_read_header(c, d, pos)) goto done;
	pos = d->start_of_data;

	if(!do_record_area(c, d, pos)) goto done;

done:
	de_free(c, d);
}

static int de_identify_wpg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xff\x57\x50\x43", 4))
		return 100;
	return 0;
}

void de_module_wpg(deark *c, struct deark_module_info *mi)
{
	mi->id = "wpg";
	mi->desc = "WordPerfect Graphics";
	mi->run_fn = de_run_wpg;
	mi->identify_fn = de_identify_wpg;
}
