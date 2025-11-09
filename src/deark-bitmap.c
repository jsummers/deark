// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-bitmap.c
//
// Functions related to bitmaps and de_bitmap.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

int de_good_image_dimensions_noerr(deark *c, i64 w, i64 h)
{
	if(w<1 || h<1 || w>c->max_image_dimension || h>c->max_image_dimension) {
		return 0;
	}
	return 1;
}

int de_good_image_dimensions(deark *c, i64 w, i64 h)
{
	if(!de_good_image_dimensions_noerr(c, w, h)) {
		de_err(c, "Bad or unsupported image dimensions (%d"DE_CHAR_TIMES"%d)",
			(int)w, (int)h);
		return 0;
	}
	return 1;
}

#define MAX_INTERNAL_IMAGE_DIMENSION 10000

// flags: 0x1: Emit an error message for a bad non-internal image.
int de_bitmap_good_dimensions(de_bitmap *img, UI flags)
{
	if(img->is_internal) {
		// Images for internal use, that aren't going to be written to a file,
		// should not respect the "-maxdim" setting from the user.
		//
		// Note - The is_internal flag should only be used for images with
		// a fixed size, that does not depend on width/height fields in the
		// input file.
		if(img->width<1 || img->width>MAX_INTERNAL_IMAGE_DIMENSION ||
			img->height<1 || img->height>MAX_INTERNAL_IMAGE_DIMENSION)
		{
			de_internal_err_nonfatal(img->c, "Bad temp bitmap size");
			return 0;
		}
	}
	else if(flags & 0x1) {
		if(!de_good_image_dimensions(img->c, img->width, img->height)) {
			return 0;
		}
	}
	else {
		if(!de_good_image_dimensions_noerr(img->c, img->width, img->height)) {
			return 0;
		}
	}
	return 1;
}

#define DE_MAX_IMAGES_PER_FILE 10000

// This is meant as a sanity check for fields that indicate how many images
// are in a file.
// TODO: It is not used very consistently, and should probably be re-thought
// or removed.
int de_good_image_count(deark *c, i64 n)
{
	i64 maximages;

	maximages = DE_MAX_IMAGES_PER_FILE;
	if(c->max_output_files>DE_MAX_IMAGES_PER_FILE) {
		maximages = c->max_output_files;
	}

	if(n<0 || n>maximages) {
		de_err(c, "Bad or unsupported number of images (%d)", (int)n);
		return 0;
	}
	return 1;
}

int de_is_grayscale_palette(const de_color *pal, i64 num_entries)
{
	i64 k;
	de_colorsample cr;

	for(k=0; k<num_entries; k++) {
		cr = DE_COLOR_R(pal[k]);
		if(cr != DE_COLOR_G(pal[k])) return 0;
		if(cr != DE_COLOR_B(pal[k])) return 0;
	}
	return 1;
}

static void de_bitmap_free_pixels(de_bitmap *b)
{
	if(b) {
		deark *c = b->c;

		if(b->bitmap) {
			de_free(c, b->bitmap);
			b->bitmap = NULL;
		}
		b->bitmap_size = 0;
	}
}

static void de_bitmap_alloc_pixels(de_bitmap *img)
{
	if(img->bitmap) {
		de_bitmap_free_pixels(img);
	}

	if(!de_bitmap_good_dimensions(img, 0x1)) {
		// This function is not allowed to fail. If something goes wrong, create
		// a dummy image, and set invalid_image_flag.
		img->invalid_image_flag = 1;

		img->width = 1;
		img->height = 1;
	}

	img->bitmap_size = (img->width*img->bytes_per_pixel) * img->height;
	img->bitmap = de_malloc(img->c, img->bitmap_size);
}

struct image_scan_opt_data {
	u8 has_color;
	u8 has_trns;
	u8 has_visible_pixels;
	// bilevel means every pixel is black or white, and opaque.
	u8 is_nonbilevel;
	u8 has_only_invis_black_pixels;
	u8 has_only_invis_white_pixels;
	de_bitmap *optimg;
};

// Scan the image's pixels, and report whether any are transparent, etc.
// Caller initializes optctx.
static void scan_image(de_bitmap *img, struct image_scan_opt_data *optctx)
{
	i64 i, j;
	de_color clr;
	de_colorsample a, r, g, b;

	if(img->bytes_per_pixel==1) { // Special case
		optctx->has_visible_pixels = 1;

		for(j=0; j<img->height; j++) {
			for(i=0; i<img->width; i++) {
				clr = de_bitmap_getpixel(img, i, j);
				r = DE_COLOR_K(clr);
				if(r!=0 && r!=255) {
					optctx->is_nonbilevel = 1;
					return;
				}
			}
		}
		return;
	}

	optctx->has_only_invis_black_pixels = 1;
	optctx->has_only_invis_white_pixels = 1;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			clr = de_bitmap_getpixel(img, i, j);
			// TODO: Optimize these tests. We check for too many things we
			// already know the answer to.
			a = DE_COLOR_A(clr);
			r = DE_COLOR_R(clr);
			g = DE_COLOR_G(clr);
			b = DE_COLOR_B(clr);

			if(!optctx->has_visible_pixels && a==0) {
				if(optctx->has_only_invis_black_pixels) {
					if(r || g || b) {
						optctx->has_only_invis_black_pixels = 0;
					}
				}
				if(optctx->has_only_invis_white_pixels) {
					if((r!=0xff) || (g!=0xff) || (b!=0xff)) {
						optctx->has_only_invis_white_pixels = 0;
					}
				}
			}

			if(!optctx->has_visible_pixels && a!=0) {
				optctx->has_visible_pixels = 1;
				optctx->has_only_invis_black_pixels = 0;
				optctx->has_only_invis_white_pixels = 0;
			}
			if(!optctx->has_trns && a<255) {
				optctx->has_trns = 1;
				optctx->is_nonbilevel = 1;
			}
			if(!optctx->has_color && img->bytes_per_pixel>=3 &&
				(g!=r || b!=r))
			{
				// This doesn't test for "&& a!=0". It *could*, but our (undocumented)
				// behavior is to try not to change the underlying color of invisible
				// pixels.
				// If we *were* going to do that, it would be more logical, and better
				// for compression, to change the underlying color to black, instead
				// of ultimately writing what amounts to garbage (probably just the
				// red channel would survive).
				optctx->has_color = 1;
				optctx->is_nonbilevel = 1;
			}

			if(!optctx->is_nonbilevel && (r!=0 && r!=255)) {
				// Only need to test one of the color samples. The has_color and
				// has_trns tests will take care of the rest.
				optctx->is_nonbilevel = 1;
			}
		}

		// After each row, test whether we've learned everything we can learn
		// about this image.
		if(img->bytes_per_pixel==2) {
			if(optctx->has_trns && optctx->has_visible_pixels) return;
		}
		else if(img->bytes_per_pixel==3) {
			if(optctx->has_color) return;
		}
		else { // bypp==4
			if(optctx->has_color && optctx->has_trns && optctx->has_visible_pixels) return;
		}
	}
}

static de_bitmap *de_bitmap_create_noinit(deark *c);

// Clone an existing bitmap's metadata, but don't allocate the new pixels.
// The caller can then change the bytes_per_pixel if desired.
static de_bitmap *de_bitmap_clone_noalloc(de_bitmap *img1)
{
	de_bitmap *img2;

	img2 = de_bitmap_create_noinit(img1->c);
	de_memcpy(img2, img1, sizeof(de_bitmap));
	img2->bitmap = NULL;
	img2->bitmap_size = 0;
	return img2;
}

static de_bitmap *de_bitmap_clone(de_bitmap *img1)
{
	de_bitmap *img2;
	i64 nbytes_to_copy;

	img2 = de_bitmap_clone_noalloc(img1);
	de_bitmap_alloc_pixels(img2);
	nbytes_to_copy = de_min_int(img2->bitmap_size, img1->bitmap_size);
	de_memcpy(img2->bitmap, img1->bitmap, (size_t)nbytes_to_copy);
	return img2;
}

// Caller initializes optctx.
// Returns:
//   optctx->optimg: NULL if no optimized image was produced.
//     Caller must free if non-NULL.
static void get_optimized_image(de_bitmap *img1, struct image_scan_opt_data *optctx)
{
	int opt_bytes_per_pixel;

	scan_image(img1, optctx);

	if(!optctx->is_nonbilevel) {
		// We don't optimize this type of image here. It will be handled
		// by the PNG encoder.
		return;
	}

	opt_bytes_per_pixel = optctx->has_color ? 3 : 1;
	if(optctx->has_trns) opt_bytes_per_pixel++;

	if(opt_bytes_per_pixel>=img1->bytes_per_pixel) {
		return;
	}

	optctx->optimg = de_bitmap_clone_noalloc(img1);
	optctx->optimg->bytes_per_pixel = opt_bytes_per_pixel;
	de_bitmap_copy_rect(img1, optctx->optimg, 0, 0, img1->width, img1->height, 0, 0, 0);
}

static int valid_imglo(de_bitmap *img, de_bitmap *imglo)
{
	if(imglo->invalid_image_flag) return 0;
	if(img->bytes_per_pixel != imglo->bytes_per_pixel) return 0;
	if(img->width != imglo->width) return 0;
	if(img->height != imglo->height) return 0;
	return 1;
}

static int bitmap16_low_bits_important(de_bitmap *imghi, de_bitmap *imglo)
{
	i64 i, j;

	for(j=0; j<imghi->height; j++) {
		for(i=0; i<imghi->width; i++) {
			de_color c1, c2;

			c1 = de_bitmap_getpixel(imghi, i, j);
			c2 = de_bitmap_getpixel(imglo, i, j);
			if(c1 != c2) return 1;
		}
	}
	return 0;
}

static UI bitmap_createflags_old2new(UI oldcreateflags)
{
	UI newcreateflags;

	if(oldcreateflags & DE_CREATEFLAG_OPT_IMAGE) {
		newcreateflags = oldcreateflags - DE_CREATEFLAG_OPT_IMAGE;
	}
	else {
		newcreateflags = oldcreateflags | DE_CREATEFLAG_NOOPT_IMAGE;
	}
	return newcreateflags;
}

// When calling this function, the "name" data associated with fi, if set, should
// be set to something like a filename, but *without* a final ".png" extension.
// Image-specific createflags:
//  - DE_CREATEFLAG_NOOPT_IMAGE
//  - DE_CREATEFLAG_OPT_IMAGE (Usually ignored, but overrides NOOPT)
//  - DE_CREATEFLAG_IS_BWIMG - Declares that image is bi-level B&W.
//  - DE_CREATEFLAG_FLIP_IMAGE
//     Write the rows in reverse order ("bottom-up"). This affects only the pixels,
//     not the finfo metadata (e.g. hotspot). It's equivalent to flipping the image
//     immediately before writing it, then flipping it back immediately after.
// imglo: If non-NULL, contains the low 8 bits of each sample, and a 16 bits/sample
//     output image will potentially be written. (This is obviously a hack, but
//     it's not worth doing anything more for such a rarely used feature.)
void de_bitmap16_write_to_file_finfo(de_bitmap *img, de_bitmap *imglo,
	de_finfo *fi, UI createflags)
{
	deark *c;
	struct image_scan_opt_data optctx;
	struct de_write_image_params wp;

	if(!img) return;
	c = img->c;
	if(img->invalid_image_flag) return;
	de_zeromem(&optctx, sizeof(struct image_scan_opt_data));

	if(!(createflags&DE_CREATEFLAG_NOOPT_IMAGE)) {
		createflags |= DE_CREATEFLAG_OPT_IMAGE;
	}

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(imglo) {
		if(!imglo->bitmap) de_bitmap_alloc_pixels(imglo);
		if(!valid_imglo(img, imglo)) return;
	}

	de_zeromem(&wp, sizeof(struct de_write_image_params));
	wp.createflags = createflags;

	if(imglo && (createflags & DE_CREATEFLAG_OPT_IMAGE)) {
		// If the high and low bytes are the same in every sample, we don't need
		// the low byte.
		if(!bitmap16_low_bits_important(img, imglo)) {
			imglo = NULL;
		}
	}

	if(imglo) {
		; // The routines below don't support 16-bit images
	}
	else if(createflags & DE_CREATEFLAG_IS_BWIMG) {
		// The BWIMG flag/optimization has to be handled in a different way than the
		// other optimizations, because our de_bitmap object does not support a
		// 1 bit/pixel image type.
		wp.flags2 |= 0x1;
	}
	else if(createflags & DE_CREATEFLAG_OPT_IMAGE) {
		// This is the default, but our optimization routine
		// isn't very efficient, so it can be disabled.
		get_optimized_image(img, &optctx);
		if(optctx.optimg) {
			de_dbg3(c, "reducing image depth (%d->%d)", img->bytes_per_pixel,
				optctx.optimg->bytes_per_pixel);
		}
		if(!optctx.is_nonbilevel) {
			de_dbg3(c, "reducing to bilevel (from %d samples)", img->bytes_per_pixel);
			wp.flags2 |= 0x1;
		}
	}

	if(fi && fi->linear_colorpace) {
		wp.flags2 |= 0x2;
	}

	wp.f = dbuf_create_output_file(c, "png", fi, createflags);
	if(optctx.optimg) {
		wp.img = optctx.optimg;
	}
	else {
		wp.img = img;
		wp.imglo = imglo;
	}
	de_write_png(c, &wp);
	dbuf_close(wp.f);

	if(optctx.optimg) de_bitmap_destroy(optctx.optimg);
}

void de_bitmap_write_to_file_finfo(de_bitmap *img, de_finfo *fi,
	UI createflags)
{
	de_bitmap16_write_to_file_finfo(img, NULL, fi, createflags);
}

// "token" - A (UTF-8) filename component, like "output.000.<token>.png".
//   It can be NULL.
void de_bitmap_write_to_file(de_bitmap *img, const char *token,
	UI createflags)
{
	deark *c = img->c;

	if(token && token[0]) {
		de_finfo *tmpfi = de_finfo_create(c);
		de_finfo_set_name_from_sz(c, tmpfi, token, 0, DE_ENCODING_UTF8);
		de_bitmap_write_to_file_finfo(img, tmpfi, createflags);
		de_finfo_destroy(c, tmpfi);
	}
	else {
		de_bitmap_write_to_file_finfo(img, NULL, createflags);
	}
}

void de_bitmap_write_to_file_finfoOLD(de_bitmap *img, de_finfo *fi,
	UI oldcreateflags)
{
	de_bitmap16_write_to_file_finfo(img, NULL, fi, bitmap_createflags_old2new(oldcreateflags));
}

void de_bitmap_write_to_fileOLD(de_bitmap *img, const char *token,
	UI oldcreateflags)
{
	de_bitmap_write_to_file(img, token, bitmap_createflags_old2new(oldcreateflags));
}

// samplenum 0=Red, 1=Green, 2=Blue, 3=Alpha
// If img is grayscale or grayscale+alpha, samplenum 0=Gray.
void de_bitmap_setsample(de_bitmap *img, i64 x, i64 y,
	i64 samplenum, de_colorsample v)
{
	i64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(!img->bitmap) return;
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

void de_bitmap_setpixel_gray(de_bitmap *img, i64 x, i64 y, de_colorsample v)
{
	i64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(!img->bitmap) return;
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

// TODO: Decide if this should just be an alias of setpixel_rgba, or if it will
// force colors to be opaque.
void de_bitmap_setpixel_rgb(de_bitmap *img, i64 x, i64 y,
	de_color color)
{
	de_bitmap_setpixel_rgba(img, x, y, color);
}

void de_bitmap_setpixel_rgba(de_bitmap *img, i64 x, i64 y,
	de_color color)
{
	i64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(!img->bitmap) return;
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

de_color de_bitmap_getpixel(de_bitmap *img, i64 x, i64 y)
{
	i64 pos;

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

static de_bitmap *de_bitmap_create_noinit(deark *c)
{
	de_bitmap *img;
	img = de_malloc(c, sizeof(de_bitmap));
	img->c = c;
	return img;
}

de_bitmap *de_bitmap_create(deark *c, i64 width, i64 height, int bypp)
{
	de_bitmap *img;
	img = de_bitmap_create_noinit(c);
	img->width = width;
	img->unpadded_width = width;
	img->height = height;
	img->bytes_per_pixel = bypp;
	//img->rowspan = img->width * img->bytes_per_pixel;
	return img;
}

de_bitmap *de_bitmap_create2(deark *c, i64 npwidth, i64 pdwidth, i64 height, int bypp)
{
	de_bitmap *img;

	if(pdwidth<npwidth) pdwidth = npwidth;

	img = de_bitmap_create(c, pdwidth, height, bypp);

	if(npwidth>0 && npwidth<img->width) {
		img->unpadded_width = npwidth;
	}

	return img;
}

void de_bitmap_destroy(de_bitmap *b)
{
	if(b) {
		deark *c = b->c;

		de_bitmap_free_pixels(b);
		de_free(c, b);
	}
}

u8 de_get_bits_symbol(dbuf *f, i64 bps, i64 rowstart, i64 index)
{
	i64 byte_offset;
	u8 b;
	u8 x = 0;

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
u8 de_get_bits_symbol_lsb(dbuf *f, i64 bps, i64 rowstart, i64 index)
{
	i64 byte_offset;
	u8 b;
	u8 x = 0;

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
// TODO: Delete this function, if it's not being used.
u8 de_get_bits_symbol2(dbuf *f, int nbits, i64 bytepos, i64 bitpos)
{
	u8 b0, b1;
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

// DE_CVTF_ONLYWHITE = Don't paint the black pixels (presumably because
//   they are already black). Use with caution if the format supports transparency.
void de_unpack_pixels_bilevel_from_byte(de_bitmap *img, i64 xpos, i64 ypos,
	u8 val, UI npixels, unsigned int flags)
{
	UI i;
	u8 xv;

	if(npixels>8) return;
	xv = (flags & DE_CVTF_WHITEISZERO) ? 0xff : 0x00;

	for(i=0; i<npixels; i++) {
		u8 x;

		if(flags & DE_CVTF_LSBFIRST) {
			x = (val & 0x01) ? 0xff : 0x00;
			val >>= 1;
		}
		else {
			x = (val & 0x80) ? 0xff : 0x00;
			val <<= 1;
		}

		x ^= xv;
		if(x==0x00 && (flags & DE_CVTF_ONLYWHITE)) continue;
		de_bitmap_setpixel_gray(img, xpos+(i64)i, ypos, x);
	}
}

// Generalization of de_convert_row_bilevel(), to support just part of a row.
void de_convert_pixels_bilevel(dbuf *f, i64 pos1, de_bitmap *img,
	i64 xpos1, i64 ypos, i64 npixels, unsigned int flags)
{
	i64 pos = pos1;
	i64 xpos = xpos1;
	i64 npixels_remaining = npixels;
	i64 npixels_this_time;

	while(npixels_remaining>0) {
		u8 b;

		b = dbuf_getbyte_p(f, &pos);
		npixels_this_time = de_min_int(npixels_remaining, 8);
		de_unpack_pixels_bilevel_from_byte(img, xpos, ypos, b,
			(UI)npixels_this_time, flags);
		npixels_remaining -= npixels_this_time;
		xpos += 8;
	}
}

void de_convert_row_bilevel(dbuf *f, i64 fpos, de_bitmap *img,
	i64 rownum, unsigned int flags)
{
	de_convert_pixels_bilevel(f, fpos, img, 0, rownum, img->width, flags);
}

void de_convert_image_bilevel(dbuf *f, i64 fpos, i64 rowspan,
	de_bitmap *img, unsigned int flags)
{
	i64 j;

	for(j=0; j<img->height; j++) {
		de_convert_row_bilevel(f, fpos+j*rowspan, img, j, flags);
	}
}

// TODO: Review everything using this function, and convert to ..._bilevel2()
// when appropriate.
// Maybe remove/rename this function.
void de_convert_and_write_image_bilevel(dbuf *f, i64 fpos,
	i64 width, i64 height, i64 rowspan, unsigned int cvtflags,
	de_finfo *fi, unsigned int createflags)
{
	de_bitmap *img = NULL;
	deark *c = f->c;

	if(!de_good_image_dimensions(c, width, height)) return;

	img = de_bitmap_create(c, width, height, 1);
	de_convert_image_bilevel(f, fpos, rowspan, img, cvtflags);
	de_bitmap_write_to_file_finfo(img, fi, createflags | DE_CREATEFLAG_IS_BWIMG);
	de_bitmap_destroy(img);
}

// This function automatically handles padding pixels, for the -padpix option.
// This means the "rowspan" param cannot be used to do clever things --
// there cannot be any data between the rows, other than padding bits.
void de_convert_and_write_image_bilevel2(dbuf *f, i64 fpos,
	i64 width, i64 height, i64 rowspan, unsigned int cvtflags,
	de_finfo *fi, unsigned int createflags)
{
	de_bitmap *img = NULL;
	deark *c = f->c;

	if(!de_good_image_dimensions(c, width, height)) return;
	img = de_bitmap_create2(c, width, rowspan*8, height, 1);
	de_convert_image_bilevel(f, fpos, rowspan, img, cvtflags);
	de_bitmap_write_to_file_finfo(img, fi, createflags | DE_CREATEFLAG_IS_BWIMG);
	de_bitmap_destroy(img);
}

// Read a palette of 24-bit RGB colors.
// flags = flags used by dbuf_getRGB()
void de_read_palette_rgb(dbuf *f,
	i64 fpos, i64 num_entries, i64 entryspan,
	de_color *pal, i64 ncolors_in_pal,
	unsigned int flags)
{
	i64 k;

	if(num_entries > ncolors_in_pal) num_entries = ncolors_in_pal;
	for(k=0; k<num_entries; k++) {
		pal[k] = dbuf_getRGB(f, fpos + k*entryspan, flags);
		de_dbg_pal_entry(f->c, k, pal[k]);
	}
}

// Can be used if:
//  - First palette index is "0".
//  - You don't need to detect invalid colors or other errors.
//  - You don't need an indication of the transparent "color key".
//  - You don't need any annotations like "[unused]".
//  - No other unusual features needed.
// If DE_RDPALFLAG_INITPAL is used, exactly 'ncolors_to_save' colors will be
// written to pal[].
// Otherwise, the min of (ncolors_to_read, ncolors_to_save) will be written to pal[].
void de_read_simple_palette(deark *c, dbuf *f, i64 fpos,
	i64 ncolors_to_read, i64 entryspan,
	de_color *pal, i64 ncolors_to_save, UI paltype, UI flags)
{
	i64 k;
	i64 i;
	i64 pos = fpos;
	UI clr1 = 0;
	u8 samp1[3];
	u8 samp2[3];
	char tmps[64];

	if(flags & DE_RDPALFLAG_INITPAL) {
		de_zeromem(pal, (size_t)ncolors_to_save*sizeof(de_color));
	}

	if(!(flags & DE_RDPALFLAG_NOHEADER)) {
		de_dbg(c, "palette at %"I64_FMT, fpos);
		de_dbg_indent(c, 1);
	}

	if(ncolors_to_save > ncolors_to_read) {
		ncolors_to_save = ncolors_to_read;
	}

	for(k=0; k<ncolors_to_read; k++) {
		de_color clr;

		pos = fpos + k*entryspan;
		if(pos >= f->len) {
			if(k < ncolors_to_save) {
				pal[k] = 0;
				continue;
			}
			goto done;
		}

		switch(paltype) {
		case DE_RDPALTYPE_24BIT:
		case DE_RDPALTYPE_VGA18BIT:
			for(i=0; i<3; i++) {
				samp1[i] = dbuf_getbyte(f, pos+i);
			}
			break;
		case DE_RDPALTYPE_AMIGA12BIT:
			clr1 = (UI)dbuf_getu16be(f, pos);
			samp1[0] = (u8)((clr1>>8)&0x0f);
			samp1[1] = (u8)((clr1>>4)&0x0f);
			samp1[2] = (u8)(clr1&0x0f);
			break;
		default:
			for(i=0; i<3; i++) {
				samp1[i] = 0;
			}
		}

		if(flags & DE_RDPALFLAG_BGR) {
			u8 tmpsamp;
			tmpsamp = samp1[0];
			samp1[0] = samp1[2];
			samp1[2] = tmpsamp;
		}

		switch(paltype) {
		case DE_RDPALTYPE_VGA18BIT:
			for(i=0; i<3; i++) {
				samp2[i] = de_scale_63_to_255(samp1[i] & 0x3f);
			}
			break;
		case DE_RDPALTYPE_AMIGA12BIT:
			for(i=0; i<3; i++) {
				samp2[i] = 17 * samp1[i];
			}
			break;
		default:
			for(i=0; i<3; i++) {
				samp2[i] = samp1[i];
			}
			break;
		}

		clr = DE_MAKE_RGB(samp2[0], samp2[1], samp2[2]);

		switch(paltype) {
		case DE_RDPALTYPE_VGA18BIT:
			de_snprintf(tmps, sizeof(tmps), "(%2u,%2u,%2u) "DE_CHAR_RIGHTARROW" ",
				(UI)samp1[0], (UI)samp1[1], (UI)samp1[2]);
			de_dbg_pal_entry2(c, k, clr, tmps, NULL, NULL);
			break;
		case DE_RDPALTYPE_AMIGA12BIT:
			de_snprintf(tmps, sizeof(tmps), "0x%04x "DE_CHAR_RIGHTARROW" ", clr1);
			de_dbg_pal_entry2(c, k, clr, tmps, NULL, NULL);
			break;
		default:
			de_dbg_pal_entry(c, k, clr);
			break;
		}

		if(k < ncolors_to_save) {
			pal[k] = clr;
		}
	}

done:
	if(!(flags & DE_RDPALFLAG_NOHEADER)) {
		de_dbg_indent(c, -1);
	}
}

// flags:
//  0x01 = lsb bit order
void de_convert_image_paletted(dbuf *f, i64 fpos,
	i64 bpp, i64 rowspan, const de_color *pal,
	de_bitmap *img, unsigned int flags)
{
	i64 i, j;
	unsigned int palent;
	u8 mask;

	if(bpp!=1 && bpp!=2 && bpp!=4 && bpp!=8) return;
	if(!de_bitmap_good_dimensions(img, 0)) return;

	mask = (1U<<(UI)bpp)-1;

	for(j=0; j<img->height; j++) {
		i64 pos = fpos + j*rowspan;

		i = 0;

		while(1) {
			UI nbits_avail;
			u8 b = 0;

			b = dbuf_getbyte_p(f, &pos);
			nbits_avail = 8;

			while(nbits_avail >= (UI)bpp) {
				nbits_avail -= (UI)bpp;
				if(flags & 0x1) {
					palent = b & mask;
					b >>= (UI)bpp;
				}
				else {
					palent = (b >> nbits_avail) & mask;
				}
				de_bitmap_setpixel_rgba(img, i++, j, pal[palent]);
				if(i>=img->width) goto nextrow;
			}
		}
	nextrow:
		;
	}
}

// Decode some planar paletted images.
// Rows and planes must be byte-aligned.
// All image data must be in the same dbuf.
// row_stride = Dist. in bytes from first byte of row 0 plane 0 to first byte of row 1 plane 0
// plane_stride = Dist. in bytes from first byte of row 0 plane 0 to first byte of row 0 plane 1
// Note: row_stride may be smaller, or larger, than plane_stride.
// Note: nplanes = bits/pixel
// flags:
//  0x01 = lsb bit order
//  0x02 = lsb plane order
void de_convert_image_paletted_planar(dbuf *f, i64 fpos, i64 nplanes,
	i64 row_stride, i64 plane_stride, const de_color *pal, de_bitmap *img, UI flags)
{
	i64 ypos;
	u8 bit_order_is_lsb = 0;
	u8 plane_order_is_lsb = 0;
	u8 pbit[8]; // [0] is for bits from the least-significant plane, etc.
	i64 units_per_row; // num bytes per row per plane that we will process

	if(nplanes<1 || nplanes>8) goto done;
	de_zeromem(pbit, sizeof(pbit));

	if(flags & 0x01) bit_order_is_lsb = 1;
	if(flags & 0x02) plane_order_is_lsb = 1;
	units_per_row = (img->width + 7)/8;

	for(ypos=0; ypos<img->height; ypos++) {
		i64 n;

		// Read 8 bits from each plane, then rearrange them to make 8
		// output pixels.
		for(n=0; n<units_per_row; n++) {
			UI k;
			UI pn;
			u8 b;
			i64 xpos;

			for(pn=0; pn<(UI)nplanes; pn++) {
				b = dbuf_getbyte(f, fpos + ypos*row_stride + pn*plane_stride + n);
				if(plane_order_is_lsb) {
					pbit[pn] = b;
				}
				else {
					pbit[(UI)nplanes-1-pn] = b;
				}
			}

			for(k=0; k<8; k++) {
				UI palent;

				palent = 0;
				for(pn=0; pn<(UI)nplanes; pn++) {
					if((pbit[pn] & (1U<<k))!=0) {
						palent |= 1U<<pn;
					}
				}

				if(bit_order_is_lsb) {
					xpos = n*8 + (i64)k;
				}
				else {
					xpos = n*8 + (i64)(7-k);
				}
				de_bitmap_setpixel_rgba(img, xpos, ypos, pal[palent]);
			}
		}
	}

done:
	;
}

void de_convert_image_rgb(dbuf *f, i64 fpos,
	i64 rowspan, i64 pixelspan, de_bitmap *img, unsigned int flags)
{
	i64 i, j;
	de_color clr;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			clr = dbuf_getRGB(f, fpos + j*rowspan + i*pixelspan, flags);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

// Turn padding pixels into real pixels.
static void de_bitmap_apply_padding(de_bitmap *img)
{
	if(img->unpadded_width != img->width) {
		img->unpadded_width = img->width;
	}
}

// TODO: This function could be made more efficient.
void de_bitmap_flip(de_bitmap *img)
{
	i64 i, j;
	i64 nr;

	nr = img->height/2;

	for(j=0; j<nr; j++) {
		i64 row1, row2;

		row1 = j;
		row2 = img->height-1-j;

		for(i=0; i<img->width; i++) {
			de_color tmp1, tmp2;

			tmp1 = de_bitmap_getpixel(img, i, row1);
			tmp2 = de_bitmap_getpixel(img, i, row2);
			if(tmp1==tmp2) continue;
			de_bitmap_setpixel_rgba(img, i, row2, tmp1);
			de_bitmap_setpixel_rgba(img, i, row1, tmp2);
		}
	}
}

// Not recommended for use with padded bitmaps (e.g. those created with
// de_bitmap_create2()). We don't support padding pixels on the left, so we can't
// truly mirror such an image. Current behavior is to turn padding pixels into
// real pixels.
void de_bitmap_mirror(de_bitmap *img)
{
	i64 i, j;
	i64 nc;

	de_bitmap_apply_padding(img);
	nc = img->width/2;

	for(j=0; j<img->height; j++) {
		for(i=0; i<nc; i++) {
			i64 col1, col2;
			de_color tmp1, tmp2;

			col1 = i;
			col2 = img->width-1-i;

			tmp1 = de_bitmap_getpixel(img, col1, j);
			tmp2 = de_bitmap_getpixel(img, col2, j);
			if(tmp1==tmp2) continue;
			de_bitmap_setpixel_rgba(img, col2, j, tmp1);
			de_bitmap_setpixel_rgba(img, col1, j, tmp2);
		}
	}
}

// Transpose (flip over the line y=x) a square bitmap.
static void bitmap_transpose_square(de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<img->height; j++) {
		for(i=0; i<j; i++) {
			de_color tmp1, tmp2;

			tmp1 = de_bitmap_getpixel(img, i, j);
			tmp2 = de_bitmap_getpixel(img, j, i);
			if(tmp1==tmp2) continue;
			de_bitmap_setpixel_rgba(img, j, i, tmp1);
			de_bitmap_setpixel_rgba(img, i, j, tmp2);
		}
	}
}

// Transpose (flip over the line y=x) a bitmap.
// Not recommended for use with padded bitmaps (e.g. those created with
// de_bitmap_create2()).
void de_bitmap_transpose(de_bitmap *img)
{
	i64 i, j;
	de_bitmap *imgtmp = NULL;

	de_bitmap_apply_padding(img);

	if(img->width == img->height) {
		bitmap_transpose_square(img);
		goto done;
	}

	imgtmp = de_bitmap_clone(img);

	de_bitmap_free_pixels(img);
	img->width = imgtmp->height;
	img->unpadded_width = imgtmp->height;
	img->height = imgtmp->width;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			de_color tmp1;

			tmp1 = de_bitmap_getpixel(imgtmp, j, i);
			de_bitmap_setpixel_rgba(img, i, j, tmp1);
		}
	}

done:
	if(imgtmp) de_bitmap_destroy(imgtmp);
}

// Paint a solid, solid-color rectangle onto an image.
// (Pixels will be replaced, not merged.)
void de_bitmap_rect(de_bitmap *img,
	i64 xpos, i64 ypos, i64 width, i64 height,
	de_color clr, unsigned int flags)
{
	i64 i, j;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			de_bitmap_setpixel_rgba(img, xpos+i, ypos+j, clr);
		}
	}
}

// Paint or copy (all or part of) srcimg onto dstimg.
// If srcimg and dstimg are the same image, the source and destination
// rectangles must not overlap.
// Flags supported:
//   DE_BITMAPFLAG_MERGE - Merge transparent pixels (partially supported)
void de_bitmap_copy_rect(de_bitmap *srcimg, de_bitmap *dstimg,
	i64 srcxpos, i64 srcypos, i64 width, i64 height,
	i64 dstxpos, i64 dstypos, unsigned int flags)
{
	i64 i, j;
	de_color dst_clr, src_clr, clr;
	de_colorsample src_a;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			src_clr = de_bitmap_getpixel(srcimg, srcxpos+i, srcypos+j);
			if(!(flags&DE_BITMAPFLAG_MERGE)) {
				clr = src_clr;
			}
			else {
				src_a = DE_COLOR_A(src_clr);
				if(src_a>0) {
					// TODO: Support partial transparency (of both foreground and
					// background, ideally)
					clr = src_clr;
				}
				else {
					dst_clr = de_bitmap_getpixel(dstimg, dstxpos+i, dstypos+j);
					clr = dst_clr;
				}
			}
			de_bitmap_setpixel_rgba(dstimg, dstxpos+i, dstypos+j, clr);
		}
	}
}

void de_bitmap_apply_mask(de_bitmap *fg, de_bitmap *mask,
	unsigned int flags)
{
	i64 i, j;
	de_color clr;
	de_colorsample a;

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

void de_bitmap_remove_alpha(de_bitmap *img)
{
	i64 i, j;
	i64 k;

	if(img->bytes_per_pixel!=2 && img->bytes_per_pixel!=4) return;

	// Note that the format conversion is done in-place. The extra memory used
	// by the alpha channel is not de-allocated.
	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			for(k=0; k<(i64)img->bytes_per_pixel-1; k++) {
				img->bitmap[(j*img->width+i)*((i64)img->bytes_per_pixel-1) + k] =
					img->bitmap[(j*img->width+i)*(img->bytes_per_pixel) + k];
			}
		}
	}

	img->bytes_per_pixel--;
}

// Note: This function's features overlap with the DE_CREATEFLAG_OPT_IMAGE
//  flag supported by de_bitmap_write_to_file().
// If the image is 100% opaque, remove the alpha channel.
// Otherwise do nothing.
// flags:
//  0x1: Make 100% invisible images 100% opaque (always)
//  0x2: Warn if an invisible image was made opaque
//  0x4: Make 100% invisible images 100% opaque, unless the image seems
//       sufficiently "boring".
void de_bitmap_optimize_alpha(de_bitmap *img, unsigned int flags)
{
	struct image_scan_opt_data optctx;

	if(img->bytes_per_pixel!=2 && img->bytes_per_pixel!=4) return;

	de_zeromem(&optctx, sizeof(struct image_scan_opt_data));
	scan_image(img, &optctx);

	if((flags&0x4) && !optctx.has_visible_pixels &&
		(optctx.has_only_invis_black_pixels || optctx.has_only_invis_white_pixels))
	{
		// No visible pixels, but the image is boring enough that it may be by
		// design, so don't remove the alpha channel.
		return;
	}

	if(optctx.has_trns && !optctx.has_visible_pixels && (flags&(0x1|0x4))) {
		if(flags&0x2) {
			de_warn(img->c, "Invisible image detected. Ignoring transparency.");
		}
	}
	else if(optctx.has_trns) {
		return;
	}

	// No meaningful transparency found.
	de_dbg3(img->c, "Removing alpha channel from image");

	de_bitmap_remove_alpha(img);
}

// flag 0x1: white-is-min
void de_make_grayscale_palette(de_color *pal, i64 num_entries, unsigned int flags)
{
	i64 k;
	u8 b;

	for(k=0; k<num_entries; k++) {
		b = (u8)(0.5+ (double)k * (255.0 / (double)(num_entries-1)));
		if(flags&0x1) b = 255-b;
		pal[k] = DE_MAKE_GRAY(b);
	}
}

de_colorsample de_unpremultiply_alpha_samp(de_colorsample cval, de_colorsample a)
{
	if(a==0xff) {
		return cval;
	}
	if(a==0 || cval==0) {
		return 0;
	}
	if(cval>=a) {
		return 0xff;
	}
	return (de_colorsample)(0.5 + (double)cval / ((double)a/255.0));
}

de_color de_unpremultiply_alpha_clr(de_color clr)
{
	de_colorsample r, g, b, a;

	r = DE_COLOR_R(clr);
	g = DE_COLOR_G(clr);
	b = DE_COLOR_B(clr);
	a = DE_COLOR_A(clr);
	r = de_unpremultiply_alpha_samp(r, a);
	g = de_unpremultiply_alpha_samp(g, a);
	b = de_unpremultiply_alpha_samp(b, a);
	return DE_MAKE_RGBA(r, g, b, a);
}
