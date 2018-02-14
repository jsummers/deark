// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Segmented Hypergraphics (SHG) and Multiple Resolution Bitmap (MRB)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_shg);

typedef struct localctx_struct {
	de_int64 signature;

	de_int64 shg_startpos;
	de_int64 num_pictures;

	de_byte picture_type;
	de_byte packing_method;
} lctx;

// This is very similar to the mscompress SZDD algorithm, but
// gratuitously different.
// If expected_output_len is 0, it will be ignored.
static void do_uncompress_lz77(deark *c,
	dbuf *inf, de_int64 pos1, de_int64 input_len,
	dbuf *outf, de_int64 expected_output_len)
{
	de_int64 pos = pos1;
	de_byte *window = NULL;
	unsigned int wpos;
	de_int64 nbytes_read;

	window = de_malloc(c, 4096);
	wpos = 4096 - 16;
	de_memset(window, 0x20, 4096);

	while(1) {
		unsigned int control;
		unsigned int cbit;

		if(pos >= (pos1+input_len)) break; // Out of input data

		control = (unsigned int)dbuf_getbyte(inf, pos++);

		for(cbit=0x01; cbit&0xff; cbit<<=1) {
			if(!(control & cbit)) { // literal
				de_byte b;
				b = dbuf_getbyte(inf, pos++);
				dbuf_writebyte(outf, b);
				if(expected_output_len>0 && outf->len>=expected_output_len) goto unc_done;
				window[wpos] = b;
				wpos++; wpos &= 4095;
			}
			else { // match
				unsigned int matchpos;
				unsigned int matchlen;
				matchpos = (unsigned int)dbuf_getui16le(inf, pos);
				pos+=2;
				matchlen = ((matchpos>>12) & 0x0f) + 3;
				matchpos = wpos-(matchpos&4095)-1;
				matchpos &= 4095;
				while(matchlen--) {
					dbuf_writebyte(outf, window[matchpos]);
					if(expected_output_len>0 && outf->len>=expected_output_len) goto unc_done;
					window[wpos] = window[matchpos];
					wpos++; wpos &= 4095;
					matchpos++; matchpos &= 4095;
				}
			}
		}
	}

unc_done:
	nbytes_read = pos-pos1;
	de_dbg(c, "uncompressed %d bytes to %d bytes",
		(int)nbytes_read, (int)outf->len);

	if(expected_output_len>0 && outf->len!=expected_output_len) {
		de_warn(c, "Expected %d output bytes, got %d",
			(int)expected_output_len, (int)outf->len);
	}

	de_free(c, window);
}

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

static void do_uncompress_rle(deark *c, lctx *d,
	dbuf *inf, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels)
{
	de_int64 pos;
	de_int64 endpos;
	de_byte b;
	de_int64 count;

	de_dbg(c, "uncompressing RLE data");
	endpos = pos1 + len;
	pos = pos1;
	while(pos<endpos) {
		b = dbuf_getbyte(inf, pos);
		pos++;
		if(b&0x80) {
			// uncompressed run
			count = (de_int64)(b&0x7f);
			dbuf_copy(inf, pos, count, unc_pixels);
			pos += count;
		}
		else {
			// compressed run
			count = (de_int64)b;
			b = dbuf_getbyte(inf, pos);
			pos++;
			dbuf_write_run(unc_pixels, b, count);
		}
	}
}

static int do_uncompress_picture_data(deark *c, lctx *d,
	de_int64 compressed_offset, de_int64 compressed_size,
	dbuf *pixels_final, de_int64 final_image_size)
{
	dbuf *pixels_tmp = NULL;
	int retval = 0;

	if(d->packing_method>3) {
		de_err(c, "Unsupported compression type: %d", (int)d->packing_method);
		goto done;
	}

	pixels_tmp = dbuf_create_membuf(c, 0, 0);

	// Copy the pixels to a membuf, then run zero or more decompression
	// algorithms on them using a temporary membuf.
	// This is not very efficient, but it keeps the code simple.
	dbuf_copy(c->infile, compressed_offset, compressed_size, pixels_final);

	if(d->packing_method==2 || d->packing_method==3) {
		de_dbg(c, "doing LZ77 decompression");
		dbuf_copy(pixels_final, 0, pixels_final->len, pixels_tmp);
		dbuf_truncate(pixels_final, 0);

		// If packing_method==2, then this is the last decompression algorithm,
		// so we know how many output bytes to expect.
		do_uncompress_lz77(c, pixels_tmp, 0, pixels_tmp->len,
			pixels_final, d->packing_method==2 ? final_image_size : 0);
		dbuf_truncate(pixels_tmp, 0);
	}

	if(d->packing_method==1 || d->packing_method==3) {
		de_dbg(c, "doing RLE decompression");
		dbuf_copy(pixels_final, 0, pixels_final->len, pixels_tmp);
		dbuf_truncate(pixels_final, 0);
		do_uncompress_rle(c, d, pixels_tmp, 0, pixels_tmp->len, pixels_final);
		dbuf_truncate(pixels_tmp, 0);

		if(pixels_final->len < final_image_size) {
			de_warn(c, "Expected %d bytes after decompression, only got %d",
				(int)final_image_size, (int)pixels_final->len);
		}
	}

	retval = 1;

done:
	dbuf_close(pixels_tmp);
	return retval;
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
	de_int64 final_image_size;
	dbuf *pixels_final = NULL;
	struct de_bmpinfo bi;
	dbuf *outf = NULL;
	int retval = 0;

	if(d->picture_type==5) {
		// TODO: Support this
		de_err(c, "DDB image format is not supported");
		goto done;
	}

	pos = pos1 + 2;

	xdpi = get_cul(c->infile, &pos);
	ydpi = get_cul(c->infile, &pos);
	de_dbg(c, "dpi: %d"DE_CHAR_TIMES"%d", (int)xdpi, (int)ydpi);
	if(xdpi<10 || ydpi<10 || xdpi>30000 || ydpi>30000) {
		xdpi = 0;
		ydpi = 0;
	}

	planes = get_cus(c->infile, &pos);
	bitcount = get_cus(c->infile, &pos);
	width = get_cul(c->infile, &pos);
	height = get_cul(c->infile, &pos);
	de_dbg(c, "planes=%d, bitcount=%d, dimensions=%d"DE_CHAR_TIMES"%d", (int)planes,
		(int)bitcount, (int)width, (int)height);

	colors_used = get_cul(c->infile, &pos);
	colors_important = get_cul(c->infile, &pos);
	de_dbg(c, "colors used=%d, important=%d", (int)colors_used,
		(int)colors_important);

	compressed_size = get_cul(c->infile, &pos);
	hotspot_size = get_cul(c->infile, &pos);
	compressed_offset = de_getui32le(pos);
	pos+=4;
	compressed_offset += pos1;
	hotspot_offset = de_getui32le(pos);
	pos+=4;
	hotspot_offset += pos1;
	de_dbg(c, "bits offset=%d, size=%d", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d", (int)hotspot_offset,
		(int)hotspot_size);

	if(bitcount!=1 && bitcount!=4 && bitcount!=8 && bitcount!=24) {
		de_err(c, "Unsupported bit count: %d", (int)bitcount);
		goto done;
	}

	if(planes!=1) {
		de_err(c, "Unsupported planes: %d", (int)planes);
		goto done;
	}

	if(!de_good_image_dimensions(c, width, height)) goto done;

	if(compressed_offset + compressed_size > c->infile->len) {
		de_err(c, "Image goes beyond end of file");
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

	final_image_size = height * (((width*bitcount +31)/32)*4);

	pixels_final = dbuf_create_membuf(c, 0, 0);
	if(!do_uncompress_picture_data(c, d,
		compressed_offset, compressed_size,
		pixels_final, final_image_size))
	{
		goto done;
	}

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// Write fileheader
	de_memset(&bi, 0, sizeof(struct de_bmpinfo));
	bi.size_of_headers_and_pal = 40 + pal_size_in_bytes;
	bi.total_size = bi.size_of_headers_and_pal + final_image_size;
	de_fmtutil_generate_bmpfileheader(c, outf, &bi, 0);

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
	dbuf_copy(pixels_final, 0, final_image_size, outf);

	retval = 1;
done:
	dbuf_close(outf);
	dbuf_close(pixels_final);
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
	dbuf *pixels_final = NULL;
	dbuf *outf = NULL;
	int retval = 0;

	pos = pos1 + 2;

	mapping_mode = get_cus(c->infile, &pos);
	width = de_getui16le(pos);
	pos+=2;
	height = de_getui16le(pos);
	pos+=2;
	de_dbg(c, "mapping mode: %d, nominal dimensions: %d"DE_CHAR_TIMES"%d",
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

	de_dbg(c, "wmf offset=%d, size=%d", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d", (int)hotspot_offset,
		(int)hotspot_size);
	if(compressed_offset+compressed_size>c->infile->len) {
		de_err(c, "WMF data goes beyond end of file");
		goto done;
	}

	pixels_final = dbuf_create_membuf(c, decompressed_size, 0x1);
	if(!do_uncompress_picture_data(c, d, compressed_offset, compressed_size,
		pixels_final, decompressed_size))
	{
		goto done;
	}

	if(pixels_final->len != decompressed_size) {
		de_warn(c, "Expected %d bytes after decompression, got %d",
			(int)decompressed_size, (int)outf->len);
	}

	outf = dbuf_create_output_file(c, "wmf", NULL, 0);
	dbuf_copy(pixels_final, 0, pixels_final->len, outf);

	retval = 1;
done:
	dbuf_close(outf);
	dbuf_close(pixels_final);
	return retval;
}

static int do_picture(deark *c, lctx *d, de_int64 pic_index)
{
	de_int64 pic_offset;
	const char *ptname;

	int retval = 0;

	de_dbg(c, "picture #%d", (int)pic_index);
	de_dbg_indent(c, 1);

	pic_offset = de_getui32le(d->shg_startpos + 4 + 4*pic_index);
	pic_offset += d->shg_startpos;
	de_dbg(c, "picture data at %d", (int)pic_offset);
	if(pic_offset >= c->infile->len) {
		goto done;
	}

	d->picture_type = de_getbyte(pic_offset);
	d->packing_method = de_getbyte(pic_offset+1);

	switch(d->picture_type) {
	case 5: ptname="DDB"; break;
	case 6: ptname="DIB"; break;
	case 8: ptname="metafile"; break;
	default: ptname="?";
	}
	de_dbg(c, "picture type: %d (%s)", (int)d->picture_type, ptname);
	de_dbg(c, "packing method: %d", (int)d->packing_method);

	if(d->picture_type==5 || d->picture_type==6) { // DDB or DIB
		do_dib(c, d, pic_offset);
	}
	else if(d->picture_type==8) { // WMF
		do_wmf(c, d, pic_offset);
	}
	else {
		de_warn(c, "Unsupported picture type: %d", (int)d->picture_type);
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
	de_dbg(c, "number of pictures in file: %d", (int)d->num_pictures);
	if(!de_good_image_count(c, d->num_pictures)) {
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

static void de_run_shg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

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
		de_warn(c, "This is probably not an SHG/MRB file.");
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
	mi->desc = "SHG (Segmented Hypergraphics), MRB (Multiple Resolution Bitmap)";
	mi->run_fn = de_run_shg;
	mi->identify_fn = de_identify_shg;
}
