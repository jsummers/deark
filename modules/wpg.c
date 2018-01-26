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
	int opt_fixpal;
	int has_pal;
	de_uint32 pal[256];

	// Fields used only by the "summary" debug line:
	de_int64 num_pal_entries; // 0 if no palette
	int start_wpg_data_record_ver; // Highest "Start of WPG data" record type
	int bitmap_record_ver; // Highest "Bitmap" record type
	de_int64 bitmap_count;
	de_int64 bpp_of_first_bitmap;
	de_int64 width_of_first_bitmap;
	de_int64 height_of_first_bitmap;
} lctx;

static int do_read_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 4; // FileId

	d->start_of_data = de_getui32le(pos);
	de_dbg(c, "start of data: %u", (unsigned int)d->start_of_data);
	pos += 4;

	pos++; // ProductType
	pos++; // FileType

	d->ver_major = de_getbyte(pos++);
	d->ver_minor = de_getbyte(pos++);
	de_dbg(c, "version: %d.%d", (int)d->ver_major, (int)d->ver_minor);

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

// Make a copy of the global palette, possibly adjusting it in some way.
// Caller supplies finalpal[256].
static void get_final_palette(deark *c, lctx *d, de_uint32 *finalpal, de_int64 bpp)
{
	de_int64 k;
	de_byte cr, cg, cb;
	int has_3plusbitpal = 0;
	int has_5plusbitpal = 0;
	int has_nonblack_color = 0;
	int fixpal2_flag = 0;
	int fixpal4_flag = 0;

	if(bpp==2 && !d->has_pal) {
		// I'm not sure what I'm supposed to do here. The first 4 colors of
		// the default palette do not really constitute a usable 4-color
		// palette.
		// The images of this type that I've seen look correct if I use a
		// particular CGA palette. So...
		de_warn(c, "4-color image with no palette. Using a CGA palette.");
		for(k=0; k<4; k++) {
			finalpal[k] = de_palette_pcpaint_cga4(2, (int)k);
		}
		return;
	}

	for(k=0; k<256; k++) {
		finalpal[k] = d->pal[k];

		if(d->opt_fixpal && bpp==4 && k<16) {
			cr = DE_COLOR_R(d->pal[k]);
			cg = DE_COLOR_G(d->pal[k]);
			cb = DE_COLOR_B(d->pal[k]);

			if((cr&0x0f)!=0 || (cg&0x0f)!=0 || (cb&0x0f)!=0) {
				has_5plusbitpal = 1;
			}
			if((cr&0x3f)!=0 || (cg&0x3f)!=0 || (cb&0x3f)!=0) {
				has_3plusbitpal = 1;
			}

			if(cr || cg || cb) {
				has_nonblack_color = 1;
			}
		}
	}

	if(d->opt_fixpal && bpp==4 && !has_3plusbitpal && has_nonblack_color) {
		de_dbg(c, "Palette seems to have 2 bits of precision. Rescaling palette.");
		fixpal2_flag = 1;
	}
	else if(d->opt_fixpal && bpp==4 && !has_5plusbitpal && has_nonblack_color) {
		de_dbg(c, "Palette seems to have 4 bits of precision. Rescaling palette.");
		fixpal4_flag = 1;
	}

	if(fixpal2_flag) {
		for(k=0; k<16; k++) {
			cr = DE_COLOR_R(finalpal[k]);
			cg = DE_COLOR_G(finalpal[k]);
			cb = DE_COLOR_B(finalpal[k]);
			cr = 85*(cr>>6);
			cg = 85*(cg>>6);
			cb = 85*(cb>>6);
			finalpal[k] = DE_MAKE_RGB(cr, cg, cb);
		}
	}
	else if(fixpal4_flag) {
		for(k=0; k<16; k++) {
			cr = DE_COLOR_R(finalpal[k]);
			cg = DE_COLOR_G(finalpal[k]);
			cb = DE_COLOR_B(finalpal[k]);
			cr = 17*(cr>>4);
			cg = 17*(cg>>4);
			cb = 17*(cb>>4);
			finalpal[k] = DE_MAKE_RGB(cr, cg, cb);
		}
	}
}

static void handler_bitmap(deark *c, lctx *d, de_byte rectype, de_int64 dpos1, de_int64 dlen)
{
	de_int64 w, h;
	de_int64 xdens, ydens;
	de_int64 bpp;
	de_int64 pos = dpos1;
	de_int64 rowspan;
	int is_bilevel;
	int is_grayscale;
	int output_bypp;
	int record_version;
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_uint32 finalpal[256];

	d->bitmap_count++;

	if(rectype==0x14) {
		record_version = 2;
		pos += 10;
	}
	else {
		record_version = 1;
	}

	// Keep track of the highest bitmap record version found.
	if(record_version > d->bitmap_record_ver) {
		d->bitmap_record_ver = record_version;
	}

	w = de_getui16le(pos);
	pos += 2;
	h = de_getui16le(pos);
	pos += 2;
	de_dbg_dimensions(c, w, h);

	bpp = de_getui16le(pos);
	de_dbg(c, "bits/pixel: %d", (int)bpp);
	pos += 2;

	xdens = de_getui16le(pos);
	pos += 2;
	ydens = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d dpi", (int)xdens, (int)ydens);

	if(d->bitmap_count==1) {
		d->bpp_of_first_bitmap = bpp;
		d->width_of_first_bitmap = w;
		d->height_of_first_bitmap = h;
	}

	if(bpp!=1 && bpp!=2 && bpp!=4 && bpp!=8) {
		de_err(c, "Unsupported bitmap depth: %d", (int)bpp);
		goto done;
	}
	if(!de_good_image_dimensions(c, w, h)) goto done;

	// Evidence suggests the palette is to be ignored if bpp==1.
	// (Or maybe you're supposed to use pal[0] and pal[15]?)
	is_bilevel = (bpp==1);

	if(is_bilevel) {
		is_grayscale = 1;
	}
	else {
		get_final_palette(c, d, finalpal, bpp);
		is_grayscale = de_is_grayscale_palette(finalpal, (de_int64)1<<bpp);
	}

	if(is_bilevel || is_grayscale)
		output_bypp = 1;
	else
		output_bypp = 3;

	rowspan = (bpp * w + 7)/8;

	unc_pixels = dbuf_create_membuf(c, h*rowspan, 0x1);

	if(!do_uncompress_rle(c, d, c->infile, pos, dpos1+dlen-pos, rowspan, unc_pixels)) {
		goto done;
	}

	img = de_bitmap_create(c, w, h, output_bypp);

	if(xdens>0 && ydens>0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = (double)xdens;
		img->ydens = (double)ydens;
	}

	if(is_bilevel) {
		de_convert_image_bilevel(unc_pixels, 0, rowspan, img, 0);
	}
	else {
		if(!d->has_pal && bpp!=2) {
			// TODO: Figure out what the default palette is.
			de_err(c, "Paletted images with no palette are not supported");
			goto done;
		}

		de_convert_image_paletted(unc_pixels, 0, bpp, rowspan, finalpal, img, 0);
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
	de_dbg(c, "start index: %d", (int)start_index);
	pos += 2;

	num_entries = de_getui16le(pos);
	de_dbg(c, "num entries: %d", (int)num_entries);
	pos += 2;

	if(start_index+num_entries>256) num_entries = 256 - start_index;
	if(start_index<0 || start_index+num_entries>256) return;

	if(num_entries > d->num_pal_entries) {
		d->num_pal_entries = num_entries;
	}

	de_read_palette_rgb(c->infile, pos, num_entries, 3, &d->pal[start_index],
		256-start_index, 0);
}

static void handler_start_of_wpg_data(deark *c, lctx *d, de_byte rectype, de_int64 dpos1, de_int64 dlen)
{
	int record_version;

	if(rectype==0x19) {
		record_version = 2;
	}
	else {
		record_version = 1;
	}

	// Keep track of the highest record version found.
	if(record_version > d->start_wpg_data_record_ver) {
		d->start_wpg_data_record_ver = record_version;
	}
}

static const struct wpg_rectype_info wpg_rectype_info_arr[] = {
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
	{ 0x0f, "Start of WPG data", handler_start_of_wpg_data },
	{ 0x10, "End of WPG data", NULL },
	{ 0x11, "PostScript data, Type 1", NULL },
	{ 0x12, "Output attributes", NULL },
	{ 0x13, "Curved polyline", NULL },
	{ 0x14, "Bitmap, Type 2", handler_bitmap },
	{ 0x15, "Start figure", NULL },
	{ 0x16, "Start chart", NULL },
	{ 0x17, "PlanPerfect data", NULL },
	{ 0x18, "Graphics text, Type 2", NULL },
	{ 0x19, "Start of WPG data, Type 2", handler_start_of_wpg_data },
	{ 0x1a, "Graphics text, Type 3", NULL },
	{ 0x1b, "PostScript data, Type 2", NULL }
};

static const struct wpg_rectype_info *find_wpg_rectype_info(de_byte rectype)
{
	de_int64 i;
	for(i=0; i<(de_int64)DE_ITEMS_IN_ARRAY(wpg_rectype_info_arr); i++) {
		if(wpg_rectype_info_arr[i].rectype == rectype) {
			return &wpg_rectype_info_arr[i];
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
	de_dbg(c, "record type 0x%02x (%s) at %d", (unsigned int)rectype, name, (int)pos1);
	de_dbg_indent(c, 1);

	rec_dlen = (de_int64)de_getbyte(pos++);

	// As far as I can tell, the variable-length integer works as follows.
	// An integer uses either 1, 3, or 5 bytes.

	// number = d c b a  (d = most-significant bits, ...)
	//  value           byte0    byte1    byte2    byte3    byte4
	//  --------------  -------- -------- -------- -------- --------
	//  (0-32767)     : 11111111 aaaaaaaa 0bbbbbbb
	//  (0-2147483647): 11111111 cccccccc 1ddddddd aaaaaaaa bbbbbbbb
	//  (0-254)       : aaaaaaaa [where the a's are not all 1's]

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

	de_dbg(c, "rec dpos=%d, dlen=[%d]%d", (int)pos, (int)(pos-(pos1+1)), (int)rec_dlen);

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
	de_dbg(c, "record area at %d", (int)pos);
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

static void do_set_default_palette(deark *c, lctx *d)
{
	int k;

	if(d->ver_major>1) return; // TODO: v2 files have a different palette

	for(k=0; k<256; k++) {
		d->pal[k] = de_palette_vga256(k);
	}
}

static void de_run_wpg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->opt_fixpal = 1;
	s = de_get_ext_option(c, "wpg:fixpal");
	if(s) d->opt_fixpal = de_atoi(s);

	pos = 0;
	if(!do_read_header(c, d, pos)) goto done;
	pos = d->start_of_data;

	do_set_default_palette(c, d);

	if(!do_record_area(c, d, pos)) goto done;

	// This debug line is mainly to help find interesting WPG files.
	de_dbg(c, "summary: ver=%d.%d dataver=%d pal=%d bitmaps=%d "
		"bitmapver=%d bpp=%d dimensions=%d"DE_CHAR_TIMES"%d",
		(int)d->ver_major, (int)d->ver_minor, d->start_wpg_data_record_ver,
		(int)d->num_pal_entries,
		(int)d->bitmap_count, d->bitmap_record_ver,
		(int)d->bpp_of_first_bitmap,
		(int)d->width_of_first_bitmap, (int)d->height_of_first_bitmap);

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
