// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

#define TGA_CMPR_UNKNOWN 0
#define TGA_CMPR_NONE    1
#define TGA_CMPR_RLE     2

typedef struct localctx_struct {
	de_int64 id_field_len;
	de_byte color_map_type;
	de_byte img_type;
	de_int64 width, height;
	de_int64 pixel_depth;
	de_byte image_descriptor;
	de_int64 num_attribute_bits;
	de_byte top_down;
	int has_signature;
	int cmpr_type;
	dbuf *unc_pixels;
	de_int64 img_size_in_bytes;
	de_int64 bytes_per_pixel;
} lctx;

static void setup_img(deark *c, lctx *d, struct deark_bitmap *img)
{
	img->flipped = !d->top_down;
}

static void do_decode_gray(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte b;
	de_int64 rowspan;

	if(d->pixel_depth!=8) {
		de_err(c, "Unsupported bit depth (%d)\n", (int)d->pixel_depth);
		goto done;
	}
	if(d->num_attribute_bits>0) goto done;

	rowspan = d->width;

	img = de_bitmap_create(c, d->width, d->height, 1);
	setup_img(c, d, img);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			b = dbuf_getbyte(d->unc_pixels, j*rowspan + i);
			de_bitmap_setpixel_gray(img, i, j, b);
		}
	}

done:
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_decode_rgb(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_uint32 clr;
	de_int64 rowspan;
	de_int64 bytes_per_pixel;

	if(d->pixel_depth==24) {
		bytes_per_pixel = 3;
	}
	else if(d->pixel_depth==32) {
		bytes_per_pixel = 4;
	}
	else {
		de_err(c, "Unsupported bit depth (%d)\n", (int)d->pixel_depth);
		goto done;
	}
	if(d->num_attribute_bits>0) goto done;

	rowspan = d->width*bytes_per_pixel;

	img = de_bitmap_create(c, d->width, d->height, 3);
	setup_img(c, d, img);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			clr = dbuf_getRGB(d->unc_pixels, j*rowspan + i*bytes_per_pixel, DE_GETRGBFLAG_BGR);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

done:
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static int do_decode_rle(deark *c, lctx *d, de_int64 pos)
{
	de_byte b;
	de_int64 count;
	de_int64 k;
	de_byte buf[8];

	while(1) {
		if(pos >= c->infile->len) break;
		if(d->unc_pixels->len >= d->img_size_in_bytes) break;

		b = de_getbyte(pos);
		pos++;

		if(b & 0x80) { // RLE block
			count = (de_int64)(b - 0x80) + 1;
			de_read(buf, pos, d->bytes_per_pixel);
			pos += d->bytes_per_pixel;
			for(k=0; k<count; k++) {
				dbuf_write(d->unc_pixels, buf, d->bytes_per_pixel);
			}
		}
		else { // uncompressed block
			count = (de_int64)(b) + 1;
			dbuf_copy(c->infile, pos, count * d->bytes_per_pixel, d->unc_pixels);
			pos += count * d->bytes_per_pixel;
		}
	}

	return 1;
}

static int has_signature(deark *c)
{
	if(c->infile->len<18) return 0;
	if(!dbuf_memcmp(c->infile, c->infile->len-18, "TRUEVISION-XFILE.\0", 18)) {
		return 1;
	}
	return 0;
}

static void de_run_tga(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	const char *cmpr_name = NULL;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	d->has_signature = has_signature(c);
	de_dbg(c, "has v2 signature: %d\n", d->has_signature);

	d->id_field_len = (de_int64)de_getbyte(0);
	d->color_map_type = de_getbyte(1);
	d->img_type = de_getbyte(2);
	de_dbg(c, "image type code: %d\n", (int)d->img_type);

	switch(d->img_type) {
	case 1: case 2: case 3:
		d->cmpr_type = TGA_CMPR_NONE;
		cmpr_name = "none";
		break;
	case 9: case 10: case 11:
		d->cmpr_type = TGA_CMPR_RLE;
		cmpr_name = "RLE";
		break;
	default:
		d->cmpr_type = TGA_CMPR_UNKNOWN;
		cmpr_name = "unknown";
	}
	de_dbg_indent(c, 1);
	de_dbg(c, "compression: %s\n", cmpr_name);
	de_dbg_indent(c, -1);

	d->width = de_getui16le(12);
	d->height = de_getui16le(14);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	d->pixel_depth = (de_int64)de_getbyte(16);
	de_dbg(c, "pixel depth: %d\n", (int)d->pixel_depth);
	d->image_descriptor = de_getbyte(17);
	de_dbg(c, "descriptor: 0x%02x\n", (unsigned int)d->image_descriptor);

	de_dbg_indent(c, 1);
	d->num_attribute_bits = (de_int64)(d->image_descriptor & 0x0f);
	de_dbg(c, "number of attribute bits: %d\n", (int)d->num_attribute_bits);

	// Note: There is conflicting information about whether bit 4 is part of the
	// "origin code", or if it consists only of bit 5. But it doesn't really matter.
	d->top_down = (d->image_descriptor>>5)&0x01;
	de_dbg(c, "top-down flag: %d\n", (int)d->top_down);
	de_dbg_indent(c, -1);

	if(d->num_attribute_bits!=0) {
		de_err(c, "Transparent TGA images are not supported.\n");
		goto done;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	pos += 18;

	if(d->id_field_len>0) {
		de_dbg(c, "image ID at %d (len=%d)\n", (int)pos, (int)d->id_field_len);
		pos += d->id_field_len;
	}

	if(d->color_map_type!=0) {
		de_dbg(c, "color map at %d\n", (int)pos);
		de_err(c, "TGA images with a color map are not supported.\n");
		goto done;
	}

	de_dbg(c, "bitmap at %d\n", (int)pos);

	d->bytes_per_pixel = ((d->pixel_depth+7)/8);
	d->img_size_in_bytes = d->height * d->width * d->bytes_per_pixel;

	if(d->cmpr_type==TGA_CMPR_RLE) {
		d->unc_pixels = dbuf_create_membuf(c, d->img_size_in_bytes);
		dbuf_set_max_length(d->unc_pixels, d->img_size_in_bytes);
		if(!do_decode_rle(c, d, pos)) goto done;
	}
	else if(d->cmpr_type==TGA_CMPR_NONE) {
		d->unc_pixels = dbuf_open_input_subfile(c->infile, pos, d->img_size_in_bytes);
	}
	else {
		de_err(c, "Unsupported compression type (%s)\n", cmpr_name);
		goto done;
	}

	switch(d->img_type) {
	case 2: case 10:
		do_decode_rgb(c, d);
		break;
	case 3: case 11:
		do_decode_gray(c, d);
		break;
	default:
		de_err(c, "This TGA image type (%d) is not supported.\n", (int)d->img_type);
		goto done;
	}

done:
	dbuf_close(d->unc_pixels);
	de_free(c, d);
}

static int de_identify_tga(deark *c)
{
	// TODO: Better identification
	if(de_input_file_has_ext(c, "tga")) {
		if(has_signature(c)) {
			return 100;
		}
		return 10;
	}
	return 0;
}

void de_module_tga(deark *c, struct deark_module_info *mi)
{
	mi->id = "tga";
	mi->run_fn = de_run_tga;
	mi->identify_fn = de_identify_tga;
}
