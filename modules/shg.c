// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Segmented Hypergraphics (SHG) and Multiple Resolution Bitmap (MRB)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 signature;

	de_int64 shg_startpos;
	de_int64 num_pictures;

	de_byte picture_type;
	de_byte packing_method;
} lctx;

// "compressed unsigned short" - a variable-length integer format
static de_int64 get_cus(dbuf *f, de_int64 *pos)
{
	de_int64 x1, x2;
	x1 = (de_int64)dbuf_getbyte(f, *pos);
	*pos += 1;
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 128 times the value of
	// the next byte.
	x2 = (de_int64)dbuf_getbyte(f, *pos);
	*pos += 1;
	return (x1>>1) | (x2<<7);
}

// "compressed unsigned long" - a variable-length integer format
static de_int64 get_cul(dbuf *f, de_int64 *pos)
{
	de_int64 x1, x2;
	x1 = dbuf_getui16le(f, *pos);
	*pos += 2;
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 32768 times the value of
	// the next two bytes.
	x2 = dbuf_getui16le(f, *pos);
	*pos += 2;
	return (x1>>1) | (x2<<15);
}

static void do_uncompress_rle(deark *c, lctx *d, dbuf *unc_pixels,
	de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_byte b;
	de_int64 count;

	de_dbg(c, "uncompressing RLE data\n");
	endpos = pos1 + len;
	pos = pos1;
	while(pos<endpos) {
		b = de_getbyte(pos);
		pos++;
		if(b&0x80) {
			// uncompressed run
			count = (de_int64)(b&0x7f);
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
		else {
			// compressed run
			count = (de_int64)b;
			b = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, b, count);
		}
	}
}

static de_int64 per_inch_to_per_meter(de_int64 dpi)
{
	return (de_int64)(0.5 + (100.0/2.54)*(double)dpi);
}

static int do_dib(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 xdpi, ydpi;
	de_int64 planes;
	de_int64 bitcount;
	de_int64 width, height;
	de_int64 colors_used;
	de_int64 colors_important;
	de_int64 compressed_size;
	de_int64 hotspot_size;
	de_int64 compressed_offset;
	de_int64 hotspot_offset;
	de_int64 pos;
	de_int64 pal_offset;
	de_int64 pal_size_in_colors;
	de_int64 pal_size_in_bytes;
	de_int64 image_size;
	dbuf *unc_pixels = NULL;
	dbuf *outf = NULL;
	int retval = 1;

	if(d->picture_type==5) {
		// TODO: Support this
		de_err(c, "DDB image format is not supported\n");
		goto done;
	}

	pos = pos1 + 2;

	xdpi = get_cul(c->infile, &pos);
	ydpi = get_cul(c->infile, &pos);
	de_dbg(c, "dpi: %dx%d\n", (int)xdpi, (int)ydpi);

	planes = get_cus(c->infile, &pos);
	bitcount = get_cus(c->infile, &pos);
	width = get_cul(c->infile, &pos);
	height = get_cul(c->infile, &pos);
	de_dbg(c, "planes=%d, bitcount=%d, dimensions=%dx%d\n", (int)planes,
		(int)bitcount, (int)width, (int)height);

	colors_used = get_cul(c->infile, &pos);
	colors_important = get_cul(c->infile, &pos);
	de_dbg(c, "colors used=%d, important=%d\n", (int)colors_used,
		(int)colors_important);

	compressed_size = get_cul(c->infile, &pos);
	hotspot_size = get_cul(c->infile, &pos);
	compressed_offset = de_getui32le(pos);
	pos+=4;
	compressed_offset += pos1;
	hotspot_offset = de_getui32le(pos);
	pos+=4;
	hotspot_offset += pos1;
	de_dbg(c, "bits offset=%d, size=%d\n", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d\n", (int)hotspot_offset,
		(int)hotspot_size);

	if(bitcount!=1 && bitcount!=4 && bitcount!=8 && bitcount!=24) {
		de_err(c, "Unsupported bit count: %d\n", (int)bitcount);
		goto done;
	}

	if(planes!=1) {
		de_err(c, "Unsupported planes: %d\n", (int)planes);
		goto done;
	}

	if(!de_good_image_dimensions(c, width, height)) goto done;

	if(compressed_offset + compressed_size > c->infile->len) {
		de_err(c, "Image goes beyond end of file\n");
		goto done;
	}

	pal_offset = pos;

	if(bitcount>8) {
		pal_size_in_colors = 0;
	}
	else if(colors_used==0) {
		pal_size_in_colors = ((de_int64)1)<<bitcount;
	}
	else {
		pal_size_in_colors = colors_used;
		if(pal_size_in_colors<1 || pal_size_in_colors>(((de_int64)1)<<bitcount)) {
			goto done;
		}
	}

	pal_size_in_bytes = 4*pal_size_in_colors;

	image_size = height * (((width*bitcount +31)/32)*4);

	if(d->packing_method==0) { // Uncompressed
		unc_pixels = dbuf_open_input_subfile(c->infile,
			compressed_offset, compressed_size);
	}
	else if(d->packing_method==1) { // RLE
		unc_pixels = dbuf_create_membuf(c, image_size);
		dbuf_set_max_length(unc_pixels, image_size);
		do_uncompress_rle(c, d, unc_pixels, compressed_offset, compressed_size);

		if(unc_pixels->len < image_size) {
			de_warn(c, "Expected %d bytes after decompression, only got %d\n",
				(int)image_size, (int)unc_pixels->len);
		}
	}
	else if(d->packing_method==2 || d->packing_method==3) {
		de_err(c, "LZ77 compression is not supported\n");
		goto done;
	}
	else {
		de_err(c, "Unsupported compression type: %d\n", (int)d->packing_method);
		goto done;
	}

	outf = dbuf_create_output_file(c, "bmp", NULL);

	// Write fileheader
	dbuf_write(outf, (const de_byte*)"BM", 2);
	dbuf_writeui32le(outf, 14 + 40 + pal_size_in_bytes + image_size);
	dbuf_write_zeroes(outf, 4);
	dbuf_writeui32le(outf, 14 + 40 + pal_size_in_bytes);

	// Write infoheader
	dbuf_writeui32le(outf, 40);
	dbuf_writeui32le(outf, width);
	dbuf_writeui32le(outf, height);
	dbuf_writeui16le(outf, planes);
	dbuf_writeui16le(outf, bitcount);
	dbuf_writeui32le(outf, 0); // compression
	dbuf_writeui32le(outf, 0); // SizeImage
	dbuf_writeui32le(outf, per_inch_to_per_meter(xdpi));
	dbuf_writeui32le(outf, per_inch_to_per_meter(ydpi));
	dbuf_writeui32le(outf, colors_used);
	dbuf_writeui32le(outf, colors_important);

	// Write color table
	dbuf_copy(c->infile, pal_offset, pal_size_in_bytes, outf);

	// Write pixels
	dbuf_copy(unc_pixels, 0, image_size, outf);

	retval = 1;
done:
	dbuf_close(unc_pixels);
	dbuf_close(outf);
	return retval;
}

static int do_wmf(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos;
	de_int64 mapping_mode;
	de_int64 width, height;
	de_int64 decompressed_size;
	de_int64 compressed_size;
	de_int64 hotspot_size;
	de_int64 compressed_offset;
	de_int64 hotspot_offset;
	dbuf *outf = NULL;
	int retval = 0;

	pos = pos1 + 2;

	mapping_mode = get_cus(c->infile, &pos);
	width = de_getui16le(pos);
	pos+=2;
	height = de_getui16le(pos);
	pos+=2;
	de_dbg(c, "mapping mode: %d, nominal dimensions: %dx%d\n",
		(int)mapping_mode, (int)width, (int)height);
	decompressed_size = get_cul(c->infile, &pos);
	compressed_size = get_cul(c->infile, &pos);
	hotspot_size = get_cul(c->infile, &pos);
	compressed_offset = de_getui32le(pos);
	pos+=4;
	compressed_offset += pos1;
	hotspot_offset = de_getui32le(pos);
	pos+=4;
	hotspot_offset += pos1;

	de_dbg(c, "wmf offset=%d, size=%d\n", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d\n", (int)hotspot_offset,
		(int)hotspot_size);
	if(compressed_offset+compressed_size>c->infile->len) {
		de_err(c, "WMF data goes beyond end of file\n");
		goto done;
	}

	outf = dbuf_create_output_file(c, "wmf", 0);
	do_uncompress_rle(c, d, outf, compressed_offset, compressed_size);

	if(outf->len != decompressed_size) {
		de_warn(c, "Expected %d bytes after decompression, got %d\n",
			(int)decompressed_size, (int)outf->len);
	}

	retval = 1;
done:
	dbuf_close(outf);
	return retval;
}

static int do_picture(deark *c, lctx *d, de_int64 pic_index)
{
	de_int64 pic_offset;

	int retval = 0;

	de_dbg(c, "picture #%d\n", (int)pic_index);
	de_dbg_indent(c, 1);

	pic_offset = de_getui32le(d->shg_startpos + 4 + 4*pic_index);
	pic_offset += d->shg_startpos;
	de_dbg(c, "picture data at %d\n", (int)pic_offset);
	if(pic_offset >= c->infile->len) {
		goto done;
	}

	d->picture_type = de_getbyte(pic_offset);
	d->packing_method = de_getbyte(pic_offset+1);

	de_dbg(c, "picture type: %d\n", (int)d->picture_type);
	de_dbg(c, "packing method: %d\n", (int)d->packing_method);

	if(d->picture_type==5 || d->picture_type==6) { // DDB or DIB
		do_dib(c, d, pic_offset);
	}
	else if(d->picture_type==8) { // WMF
		do_wmf(c, d, pic_offset);
	}
	else {
		de_warn(c, "Unsupported picture type: %d\n", (int)d->picture_type);
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_shg(deark *c, lctx *d)
{
	de_int64 k;

	d->num_pictures = de_getui16le(d->shg_startpos+2);
	de_dbg(c, "number of pictures in file: %d\n", (int)d->num_pictures);
	if(d->num_pictures>DE_MAX_IMAGES_PER_FILE) {
		goto done;
	}

	for(k=0; k<d->num_pictures; k++) {
		if(!do_picture(c, d, k)) {
			goto done;
		}
	}

done:
	;
}

static void de_run_shg(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In shg module\n");

	d = de_malloc(c, sizeof(lctx));

	d->shg_startpos = 0;
	d->signature = de_getui16le(d->shg_startpos);
	if(d->signature==0x506c) {
		de_declare_fmt(c, "SHG");
	}
	else if(d->signature==0x706c) {
		de_declare_fmt(c, "MRB");
	}
	else {
		de_warn(c, "This is probably not an SHG/MRB file.\n");
	}

	do_shg(c, d);

	de_free(c, d);
}

static int de_identify_shg(deark *c)
{
	de_byte buf[2];
	de_read(buf, 0, 2);
	if(buf[0]==0x6c && (buf[1]==0x50 || buf[1]==0x70)) {
		return 50;
	}
	return 0;
}

void de_module_shg(deark *c, struct deark_module_info *mi)
{
	mi->id = "shg";
	mi->run_fn = de_run_shg;
	mi->identify_fn = de_identify_shg;
}
