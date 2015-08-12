// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

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
} lctx;

static void do_decode_rgb(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_uint32 clr;
	de_int64 rowspan;

	if(d->pixel_depth!=24) {
		de_err(c, "Unsupported bit depth (%d)\n", (int)d->pixel_depth);
		goto done;
	}

	rowspan = d->width*3;

	img = de_bitmap_create(c, d->width, d->height, 3);
	img->flipped = !d->top_down;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			clr = dbuf_getRGB(c->infile, pos + j*rowspan + i*3, DE_GETRGBFLAG_BGR);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

done:
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
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

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	d->has_signature = has_signature(c);
	de_dbg(c, "has v2 signature: %d\n", d->has_signature);

	d->id_field_len = (de_int64)de_getbyte(0);
	d->color_map_type = de_getbyte(1);
	d->img_type = de_getbyte(2);
	de_dbg(c, "image type code: %d\n", (int)d->img_type);

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

	if(d->img_type!=2) {
		de_err(c, "This TGA image type (%d) is not supported.\n", (int)d->img_type);
		goto done;
	}

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

	switch(d->img_type) {
	case 2:
		do_decode_rgb(c, d, pos);
		break;
	}

done:
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
