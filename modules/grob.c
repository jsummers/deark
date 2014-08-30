// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// "GROB" image format for HP48/49 calculators.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int w, h;
	de_int64 bytes_consumed;
} lctx;


static void grob_read_binary_bitmap(deark *c, lctx *d, dbuf *inf, de_int64 pos)
{
	de_int64 j;
	de_int64 src_rowspan;
	struct deark_bitmap *img = NULL;

	if(!de_good_image_dimensions(c, d->w, d->h))
		return;

	img = de_bitmap_create(c, d->w, d->h, 1);
	src_rowspan = (d->w+7)/8;

	for(j=0; j<d->h; j++) {
		de_convert_row_bilevel(inf, pos+j*src_rowspan, img, j,
			DE_CVTR_WHITEISZERO|DE_CVTR_LSBFIRST);
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void de_run_grob_binary(deark *c, lctx *d)
{
	de_byte hdr[18];

	de_declare_fmt(c, "HP GROB, binary encoded");

	de_read(hdr, 0, 18);

	// Height and Width are 20-bit integers, 2.5 bytes each.
	d->h = (hdr[15]&0x0f)<<16 | hdr[14]<<8 | hdr[13];
	d->w = hdr[17]<<12 | hdr[16]<<4 | hdr[15]>>4;
	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	grob_read_binary_bitmap(c, d, c->infile, 18);
}

// On return, sets d->bytes_consumed
static void grob_text_1_image(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 data_start;
	de_byte x;
	de_byte b0, b1;
	de_int64 pos;
	dbuf *bin_bmp = NULL; // Binary version of the bitmap

	pos = pos1;

	d->w = 0;
	d->h = 0;

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
		d->h = d->h*10 + (x-'0');
		pos++;
	}

	while(de_getbyte(pos)==' ')
		pos++;
	data_start = pos;

	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	if(!de_good_image_dimensions(c, d->w, d->h))
		goto done;

	// Decode the quasi-hex-encoded data into a memory buffer, then use the
	// same decoder as for binary format.

	bin_bmp = dbuf_create_membuf(c, d->h * (d->w+7)/8);

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
	de_int64 pos;
	de_int64 img_pos = 0;
	int ret;
	int img_count = 0;

	de_declare_fmt(c, "HP GROB, text encoded");

	// Though some text GROB files begin with "GROB", we also want to support files
	// that have "%%HP" headers, and other files that have one or more GROB data objects
	// embedded in them.

	pos = 0;

	while(pos < c->infile->len) {
		// TODO: Ideally, we should be more careful about what we search for.
		// Maybe we should make sure "GROB" is the first nonwhitespace on the line,
		// but even that isn't enough.

		ret = dbuf_search(c->infile, (const de_byte*)"GROB", 4, pos, c->infile->len-pos, &img_pos);
		if(!ret) {
			// No more images in this file.
			break;
		}

		de_dbg(c, "GROB format found at %d\n", (int)img_pos);

		img_count++;
		grob_text_1_image(c, d, img_pos);

		if(d->bytes_consumed<1) break;
		pos = img_pos + d->bytes_consumed;
	}

	if(img_count==0) {
		de_err(c, "Unknown or unsupported GROB format\n");
	}
}

static void de_run_grob(deark *c, const char *params)
{
	lctx *d = NULL;
	de_byte buf[4];

	de_dbg(c, "In grob module\n");

	d = de_malloc(c, sizeof(lctx));

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "HPHP", 4)) {
		de_run_grob_binary(c, d);
	}
	else {
		de_run_grob_text(c, d);
	}

	de_free(c, d);
}

static int de_identify_grob(deark *c)
{
	de_byte buf[10];
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

void de_module_grob(deark *c, struct deark_module_info *mi)
{
	mi->id = "grob";
	mi->run_fn = de_run_grob;
	mi->identify_fn = de_identify_grob;
}
