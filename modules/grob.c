// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// "GROB" image format for HP48/49 calculators.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_grob);

typedef struct localctx_struct {
	i64 w, h_phys;
	i64 bytes_consumed;
	i64 num_planes;
	int grayscale_lsb; // Does the plane of least-significant bits come first?
} lctx;

static void grob_read_binary_bitmap(deark *c, lctx *d, dbuf *inf, i64 pos)
{
	i64 h_logical;
	i64 i, j;
	i64 plane;
	i64 rowspan;
	u8 b;
	unsigned int v;
	u8 v2;
	de_bitmap *img = NULL;

	if(d->num_planes<=1) {
		de_convert_and_write_image_bilevel(inf, pos, d->w, d->h_phys, (d->w+7)/8,
			DE_CVTF_WHITEISZERO|DE_CVTF_LSBFIRST, NULL, 0);
		return;
	}

	if((d->h_phys % d->num_planes) != 0) {
		de_warn(c, "Number of rows is not divisible by number of planes. The grob:planes "
			"setting is probably not correct.");
	}
	h_logical = d->h_phys/d->num_planes;

	if(!de_good_image_dimensions(c, d->w, h_logical))
		goto done;

	de_dbg(c, "logical dimensions: %d"DE_CHAR_TIMES"%d", (int)d->w, (int)h_logical);

	rowspan = (d->w+7)/8;
	img = de_bitmap_create(c, d->w, h_logical, 1);

	for(j=0; j<h_logical; j++) {
		for(i=0; i<d->w; i++) {
			v = 0;
			for(plane=0; plane<d->num_planes; plane++) {
				b = de_get_bits_symbol_lsb(inf, 1,
					pos+rowspan*(h_logical*(i64)plane+j), i);
				if(d->grayscale_lsb)
					v |= b<<(unsigned int)plane;
				else
					v = (v<<1)|b;
			}
			v2 = 255-de_sample_nbit_to_8bit(d->num_planes, v);
			de_bitmap_setpixel_gray(img, i, j, v2);
		}
	}

	de_bitmap_write_to_file_finfo(img, NULL, 0);
done:
	de_bitmap_destroy(img);
}

static void de_run_grob_binary(deark *c, lctx *d)
{
	u8 hdr[18];
	i64 obj_id;
	i64 length;

	de_declare_fmt(c, "HP GROB, binary encoded");

	de_read(hdr, 0, 18);

	// Next 4 fields are packed 20-bit integers, 2.5 bytes each.

	obj_id = (hdr[10]&0x0f)<<16 | hdr[9]<<8 | hdr[8];
	length = hdr[12]<<12 | hdr[11]<<4 | hdr[10]>>4;
	de_dbg(c, "object id: 0x%05x", (unsigned int)obj_id);
	if(obj_id != 0x02b1e) {
		de_warn(c, "Unexpected object identifier (0x%05x, expected 0x02b1e)", (unsigned int)obj_id);
	}
	de_dbg(c, "object length in nibbles: %d", (int)length);

	d->h_phys = (hdr[15]&0x0f)<<16 | hdr[14]<<8 | hdr[13];
	d->w = hdr[17]<<12 | hdr[16]<<4 | hdr[15]>>4;
	de_dbg(c, "%sdimensions: %d"DE_CHAR_TIMES"%d", (d->num_planes==1)?"":"physical ",
		(int)d->w, (int)d->h_phys);

	grob_read_binary_bitmap(c, d, c->infile, 18);
}

// On return, sets d->bytes_consumed
static void grob_text_1_image(deark *c, lctx *d, i64 pos1)
{
	i64 data_start;
	u8 x;
	u8 b0, b1;
	i64 pos;
	dbuf *bin_bmp = NULL; // Binary version of the bitmap

	pos = pos1;

	d->w = 0;
	d->h_phys = 0;

	// We assume the GROB text format starts with
	// "GROB" <zero or more spaces> <width> <one or more spaces>
	// <height> <one or more spaces> <data>.

	// TODO: This parser is pretty clumsy.

	pos += 4; // Skip over "GROB"

	while(de_getbyte(pos)==' ')
		pos++;
	while((x=de_getbyte(pos))!=' ') {
		d->w = d->w*10 + (x-'0');
		pos++;
	}

	while(de_getbyte(pos)==' ')
		pos++;
	while((x=de_getbyte(pos))!=' ') {
		d->h_phys = d->h_phys*10 + (x-'0');
		pos++;
	}

	while(de_getbyte(pos)==' ')
		pos++;
	data_start = pos;

	de_dbg(c, "%sdimensions: %d"DE_CHAR_TIMES"%d", (d->num_planes==1)?"":"physical ",
		(int)d->w, (int)d->h_phys);

	// FIXME: This should really be testing the logical height, not the
	// physical height.
	if(!de_good_image_dimensions(c, d->w, d->h_phys))
		goto done;

	// Decode the quasi-hex-encoded data into a memory buffer, then use the
	// same decoder as for binary format.

	bin_bmp = dbuf_create_membuf(c, d->h_phys * (d->w+7)/8, 0);

	pos = data_start;
	while(pos < c->infile->len) {
		b0 = de_getbyte(pos);
		b1 = de_getbyte(pos+1);
		if(b0<48 || b1<48) {
			// Apparently, we've reached the end of the bitmap data.
			break;
		}

		pos+=2;

		x = de_decode_hex_digit(b0,NULL) | (de_decode_hex_digit(b1,NULL)<<4);
		dbuf_writebyte(bin_bmp, x);
	}

	d->bytes_consumed = pos - pos1;

	grob_read_binary_bitmap(c, d, bin_bmp, 0);

done:
	dbuf_close(bin_bmp);
}

static void de_run_grob_text(deark *c, lctx *d)
{
	i64 pos;
	i64 img_pos = 0;
	int ret;
	i64 img_count = 0;

	de_declare_fmt(c, "HP GROB, text encoded");

	// Though some text GROB files begin with "GROB", we also want to support files
	// that have "%%HP" headers, and other files that have one or more GROB data objects
	// embedded in them.

	pos = 0;

	while(pos < c->infile->len) {
		// TODO: Ideally, we should be more careful about what we search for.
		// Maybe we should make sure "GROB" is the first nonwhitespace on the line,
		// but even that isn't enough.

		ret = dbuf_search(c->infile, (const u8*)"GROB", 4, pos, c->infile->len-pos, &img_pos);
		if(!ret) {
			// No more images in this file.
			break;
		}

		de_dbg(c, "GROB format found at %d", (int)img_pos);

		img_count++;
		if(!de_good_image_count(c, img_count)) break;
		grob_text_1_image(c, d, img_pos);

		if(d->bytes_consumed<1) break;
		pos = img_pos + d->bytes_consumed;
	}

	if(img_count==0) {
		de_err(c, "Unknown or unsupported GROB format");
	}
}

static void de_run_grob(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u8 buf[4];
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	s = de_get_ext_option(c, "grob:planes");
	if(s) {
		d->num_planes = de_atoi64(s);
	}
	if(d->num_planes<1) d->num_planes=1;
	if(d->num_planes>8) {
		de_err(c, "Unsupported grob:planes option");
		goto done;
	}

	s = de_get_ext_option(c, "grob:planeorder");
	if(s && s[0]=='l') {
		d->grayscale_lsb = 1;
	}

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "HPHP", 4)) {
		de_run_grob_binary(c, d);
	}
	else {
		de_run_grob_text(c, d);
	}

done:
	de_free(c, d);
}

static int de_identify_grob(deark *c)
{
	u8 buf[10];
	de_read(buf, 0, 10);

	if(buf[0]=='H' && buf[1]=='P' && buf[2]=='H' && buf[3]=='P' &&
		buf[4]=='4' && (buf[5]=='8' || buf[5]=='9') &&
		buf[8]==0x1e && buf[9]==0x2b)
	{
			return 100;
	}

	if(buf[0]=='G' && buf[1]=='R' && buf[2]=='O' && buf[3]=='B') {
		return 90;
	}

	return 0;
}

static void de_help_grob(deark *c)
{
	de_msg(c, "-opt grob:planes=<n> : Treat image as grayscale");
	de_msg(c, "-opt grob:planeorder=l : Least-significant plane comes first");
}

void de_module_grob(deark *c, struct deark_module_info *mi)
{
	mi->id = "grob";
	mi->desc = "GROB - HP48/49 calculator image";
	mi->run_fn = de_run_grob;
	mi->identify_fn = de_identify_grob;
	mi->help_fn = de_help_grob;
}
