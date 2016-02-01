// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-bitmap.c
//
// Functions related to bitmaps and struct deark_bitmap.

#include "deark-config.h"
#include "deark-private.h"

int de_good_image_dimensions_noerr(deark *c, de_int64 w, de_int64 h)
{
	if(w<1 || h<1 || w>c->max_image_dimension || h>c->max_image_dimension) {
		return 0;
	}
	return 1;
}

int de_good_image_dimensions(deark *c, de_int64 w, de_int64 h)
{
	if(!de_good_image_dimensions_noerr(c, w, h)) {
		de_err(c, "Bad or unsupported image dimensions (%dx%d)\n",
			(int)w, (int)h);
		return 0;
	}
	return 1;
}

int de_is_grayscale_palette(const de_uint32 *pal, de_int64 num_entries)
{
	de_int64 k;
	de_byte cr;

	for(k=0; k<num_entries; k++) {
		cr = DE_COLOR_R(pal[k]);
		if(cr != DE_COLOR_G(pal[k])) return 0;
		if(cr != DE_COLOR_B(pal[k])) return 0;
	}
	return 1;
}

static void de_bitmap_alloc_pixels(struct deark_bitmap *img)
{
	if(img->bitmap) {
		de_free(img->c, img->bitmap);
	}

	if(!de_good_image_dimensions(img->c, img->width, img->height)) {
		// This function is not allowed to fail. If something goes wrong, create
		// a dummy image, and set invalid_image_flag.
		img->invalid_image_flag = 1;

		img->width = 1;
		img->height = 1;
	}

	img->bitmap_size = (img->width*img->bytes_per_pixel) * img->height;
	img->bitmap = de_malloc(img->c, img->bitmap_size);
}

void de_bitmap_write_to_file(struct deark_bitmap *img, const char *token)
{
	dbuf *f;
	char buf[80];

	if(!img) return;
	if(img->invalid_image_flag) return;

	if(token==NULL || token[0]=='\0') {
		de_strlcpy(buf, "png", sizeof(buf));
	}
	else {
		de_snprintf(buf, sizeof(buf), "%s.png", token);
	}

	if(!img->bitmap) de_bitmap_alloc_pixels(img);

	f = dbuf_create_output_file(img->c, buf, NULL);
	de_write_png(img->c, img, f);
	dbuf_close(f);
}

void de_bitmap_write_to_file_finfo(struct deark_bitmap *img, de_finfo *fi)
{
	const char *token = NULL;
	if(fi && fi->file_name) {
		token = fi->file_name;
	}
	de_bitmap_write_to_file(img, token);
}

// samplenum 0=Red, 1=Green, 2=Blue, 3=Alpha
void de_bitmap_setsample(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_int64 samplenum, de_byte v)
{
	de_int64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(x<0 || y<0 || x>=img->width || y>=img->height) return;
	if(samplenum<0 || samplenum>3) return;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	switch(img->bytes_per_pixel) {
	case 1: // gray
		if(samplenum<3) {
			img->bitmap[pos] = v;
		}
		break;
	case 2: // gray+alpha
		if(samplenum==3) {
			img->bitmap[pos+1] = v;
		}
		else {
			img->bitmap[pos] = v;
		}
		break;
	case 3: // RGB
		if(samplenum<3) {
			img->bitmap[pos+samplenum] = v;
		}
		break;
	case 4: // RGBA
		img->bitmap[pos+samplenum] = v;
		break;
	}
}

void de_bitmap_setpixel_gray(struct deark_bitmap *img, de_int64 x, de_int64 y, de_byte v)
{
	de_int64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(x<0 || y<0 || x>=img->width || y>=img->height) return;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	img->bitmap[pos] = v;
	switch(img->bytes_per_pixel) {
	case 2: // gray+alpha
		img->bitmap[pos+1] = 255;
		break;
	case 3: // RGB
		img->bitmap[pos+1] = v;
		img->bitmap[pos+2] = v;
		break;
	case 4: // RGBA
		img->bitmap[pos+1] = v;
		img->bitmap[pos+2] = v;
		img->bitmap[pos+3] = 255;
		break;
	}
}

// TODO: Decide if this should just be an alias of setpixel_rgb, or if it will
// force colors to be opaque.
void de_bitmap_setpixel_rgb(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color)
{
	de_bitmap_setpixel_rgba(img, x, y, color);
}

void de_bitmap_setpixel_rgba(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color)
{
	de_int64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(x<0 || y<0 || x>=img->width || y>=img->height) return;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	switch(img->bytes_per_pixel) {
	case 4:
		img->bitmap[pos]   = DE_COLOR_R(color);
		img->bitmap[pos+1] = DE_COLOR_G(color);
		img->bitmap[pos+2] = DE_COLOR_B(color);
		img->bitmap[pos+3] = DE_COLOR_A(color);
		break;
	case 3:
		img->bitmap[pos]   = DE_COLOR_R(color);
		img->bitmap[pos+1] = DE_COLOR_G(color);
		img->bitmap[pos+2] = DE_COLOR_B(color);
		break;
	case 2:
		img->bitmap[pos]   = DE_COLOR_G(color);
		img->bitmap[pos+1] = DE_COLOR_A(color);
		break;
	case 1:
		// TODO: We could do real grayscale conversion, but for now we
		// assume this won't happen, or that if it does the color given to
		// us is a gray shade.
		img->bitmap[pos]   = DE_COLOR_G(color);
		break;
	}
}

de_uint32 de_bitmap_getpixel(struct deark_bitmap *img, de_int64 x, de_int64 y)
{
	de_int64 pos;

	if(!img) return 0;
	if(!img->bitmap) return 0;
	if(x<0 || y<0 || x>=img->width || y>=img->height) return 0;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	switch(img->bytes_per_pixel) {
	case 4:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos+1],
			img->bitmap[pos+2], img->bitmap[pos+3]);
	case 3:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos+1],
			img->bitmap[pos+2], 0xff);
		break;
	case 2:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos],
			img->bitmap[pos], img->bitmap[pos+1]);
		break;
	case 1:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos],
			img->bitmap[pos], 0xff);
		break;
	}
	return 0;
}

struct deark_bitmap *de_bitmap_create_noinit(deark *c)
{
	struct deark_bitmap *img;
	img = de_malloc(c, sizeof(struct deark_bitmap));
	img->c = c;
	return img;
}

struct deark_bitmap *de_bitmap_create(deark *c, de_int64 width, de_int64 height, int bypp)
{
	struct deark_bitmap *img;
	img = de_bitmap_create_noinit(c);
	img->width = width;
	img->height = height;
	img->bytes_per_pixel = bypp;
	//img->rowspan = img->width * img->bytes_per_pixel;
	return img;
}

void de_bitmap_destroy(struct deark_bitmap *b)
{
	if(b) {
		deark *c = b->c;
		if(b->bitmap) de_free(c, b->bitmap);
		de_free(c, b);
	}
}

de_byte de_get_bits_symbol(dbuf *f, de_int64 bps, de_int64 rowstart, de_int64 index)
{
	de_int64 byte_offset;
	de_byte b;
	de_byte x = 0;

	switch(bps) {
	case 1:
		byte_offset = rowstart + index/8;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (7 - index%8)) & 0x01;
		break;
	case 2:
		byte_offset = rowstart + index/4;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (2 * (3 - index%4))) & 0x03;
		break;
	case 4:
		byte_offset = rowstart + index/2;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (4 * (1 - index%2))) & 0x0f;
		break;
	case 8:
		byte_offset = rowstart + index;
		x = dbuf_getbyte(f, byte_offset);
	}
	return x;
}

// Like de_get_bits_symbol, but with LSB-first bit order
de_byte de_get_bits_symbol_lsb(dbuf *f, de_int64 bps, de_int64 rowstart, de_int64 index)
{
	de_int64 byte_offset;
	de_byte b;
	de_byte x = 0;

	switch(bps) {
	case 1:
		byte_offset = rowstart + index/8;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (index%8)) & 0x01;
		break;
	case 2:
		byte_offset = rowstart + index/4;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (2 * (index%4))) & 0x03;
		break;
	case 4:
		byte_offset = rowstart + index/2;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (4 * (index%2))) & 0x0f;
		break;
	case 8:
		byte_offset = rowstart + index;
		x = dbuf_getbyte(f, byte_offset);
	}
	return x;
}

// Read a symbol (up to 8 bits) that starts at an arbitrary bit position.
// It may span (two) bytes.
de_byte de_get_bits_symbol2(dbuf *f, int nbits, de_int64 bytepos, de_int64 bitpos)
{
	de_byte b0, b1;
	int bits_in_first_byte;
	int bits_in_second_byte;

	bits_in_first_byte = 8-(bitpos%8);

	b0 = dbuf_getbyte(f, bytepos + bitpos/8);

	if(bits_in_first_byte<8) {
		b0 &= (0xff >> (8-bits_in_first_byte)); // Zero out insignificant bits
	}

	if(bits_in_first_byte == nbits) {
		// First byte has all the bits
		return b0;
	}
	else if(bits_in_first_byte >= nbits) {
		// First byte has all the bits
		return b0 >> (bits_in_first_byte - nbits);
	}

	bits_in_second_byte = nbits - bits_in_first_byte;
	b1 = dbuf_getbyte(f, bytepos + bitpos/8 +1);

	return (b0<<bits_in_second_byte) | (b1>>(8-bits_in_second_byte));
}

void de_convert_row_bilevel(dbuf *f, de_int64 fpos, struct deark_bitmap *img,
	de_int64 rownum, unsigned int flags)
{
	de_int64 i;
	de_byte x;
	de_byte b;
	de_byte black, white;

	if(flags & DE_CVTF_WHITEISZERO) {
		white = 0; black = 255;
	}
	else {
		black = 0; white = 255;
	}

	for(i=0; i<img->width; i++) {
		b = dbuf_getbyte(f, fpos + i/8);
		if(flags & DE_CVTF_LSBFIRST)
			x = (b >> (i%8)) & 0x01;
		else
			x = (b >> (7 - i%8)) & 0x01;
		de_bitmap_setpixel_gray(img, i, rownum, x ? white : black);
	}
}

void de_convert_image_bilevel(dbuf *f, de_int64 fpos, de_int64 rowspan,
	struct deark_bitmap *img, unsigned int flags)
{
	de_int64 j;

	for(j=0; j<img->height; j++) {
		de_convert_row_bilevel(f, fpos+j*rowspan, img, j, flags);
	}
}

void de_convert_and_write_image_bilevel(dbuf *f, de_int64 fpos,
	de_int64 width, de_int64 height, de_int64 rowspan, unsigned int flags,
	de_finfo *fi)
{
	struct deark_bitmap *img = NULL;
	deark *c = f->c;

	if(!de_good_image_dimensions(c, width, height)) return;

	img = de_bitmap_create(c, width, height, 1);
	de_convert_image_bilevel(f, fpos, rowspan, img, flags);
	de_bitmap_write_to_file_finfo(img, fi);
	de_bitmap_destroy(img);
}

void de_bitmap_apply_mask(struct deark_bitmap *fg, struct deark_bitmap *mask,
	unsigned int flags)
{
	de_int64 i, j;
	de_uint32 clr;
	de_byte a;

	for(j=0; j<fg->height && j<mask->height; j++) {
		for(i=0; i<fg->width && i<mask->width; i++) {
			clr = de_bitmap_getpixel(mask, i, j);
			a = DE_COLOR_K(clr);
			if(flags&DE_BITMAPFLAG_WHITEISTRNS)
				a = 0xff-a;
			de_bitmap_setsample(fg, i, j, 3, a);
		}
	}
}
