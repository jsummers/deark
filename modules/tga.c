// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	de_int64 id_field_len;
	de_byte color_map_type;
	de_byte img_type;
	de_int64 cmap_start;
	de_int64 cmap_length;
	de_int64 cmap_depth;
	de_int64 width, height;
	de_int64 pixel_depth;
	de_byte image_descriptor;
	de_int64 num_attribute_bits;
	de_byte attributes_type;
	de_byte top_down, right_to_left;
	int has_signature;
#define TGA_CMPR_UNKNOWN 0
#define TGA_CMPR_NONE    1
#define TGA_CMPR_RLE     2
	int cmpr_type;
#define TGA_CLRTYPE_UNKNOWN   0
#define TGA_CLRTYPE_PALETTE   1
#define TGA_CLRTYPE_TRUECOLOR 2
#define TGA_CLRTYPE_GRAYSCALE 3
	int color_type;
	dbuf *unc_pixels;
	de_int64 img_size_in_bytes;
	de_int64 bytes_per_pixel;
	de_int64 bytes_per_pal_entry;
	de_int64 pal_size_in_bytes;
	de_int64 aspect_ratio_num, aspect_ratio_den;
	de_uint32 pal[256];
} lctx;

static void do_decode_image(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 i_adj, j_adj;
	de_byte b;
	de_uint32 clr;
	de_int64 rowspan;
	int output_bypp;

	rowspan = d->width*d->bytes_per_pixel;

	if(d->color_type==TGA_CLRTYPE_GRAYSCALE)
		output_bypp=1;
	else
		output_bypp=3;

	img = de_bitmap_create(c, d->width, d->height, output_bypp);

	for(j=0; j<d->height; j++) {
		if(d->top_down)
			j_adj = j;
		else
			j_adj = d->height-1-j;

		for(i=0; i<d->width; i++) {
			if(d->right_to_left)
				i_adj = d->width-1-i;
			else
				i_adj = i;

			if(d->color_type==TGA_CLRTYPE_TRUECOLOR && (d->pixel_depth==15 || d->pixel_depth==16)) {
				clr = (de_uint32)dbuf_getui16le(d->unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				clr = de_rgb555_to_888(clr);
				de_bitmap_setpixel_rgb(img, i_adj, j_adj, clr);
			}
			else if(d->color_type==TGA_CLRTYPE_TRUECOLOR) {
				clr = dbuf_getRGB(d->unc_pixels, j*rowspan + i*d->bytes_per_pixel, DE_GETRGBFLAG_BGR);
				de_bitmap_setpixel_rgb(img, i_adj, j_adj, clr);
			}
			else if(d->color_type==TGA_CLRTYPE_GRAYSCALE) {
				b = dbuf_getbyte(d->unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				de_bitmap_setpixel_gray(img, i_adj, j_adj, b);
			}
			else if(d->color_type==TGA_CLRTYPE_PALETTE) {
				b = dbuf_getbyte(d->unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				de_bitmap_setpixel_rgb(img, i_adj, j_adj, d->pal[(unsigned int)b]);
			}
		}
	}

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

static int do_read_palette(deark *c, lctx *d, de_int64 pos)
{
	de_int64 i;
	de_int64 idx;

	if(d->color_type != TGA_CLRTYPE_PALETTE) {
		return 1; // don't care about the palette
	}

	if(d->cmap_depth != 24) {
		de_err(c, "Palettes with depth=%d are not supported.\n", (int)d->cmap_depth);
		return 0;
	}
	if(d->pixel_depth != 8) {
		de_err(c, "Paletted images with depth=%d are not supported.\n", (int)d->pixel_depth);
		return 0;
	}

	for(i=0; i<d->cmap_length; i++) {
		idx = d->cmap_start + i;
		if(idx<0 || idx>255) continue;
		d->pal[idx] = dbuf_getRGB(c->infile, pos + i*d->bytes_per_pal_entry, DE_GETRGBFLAG_BGR);
		de_dbg2(c, "pal[%3d] = (%3d,%3d,%3d)\n", (int)idx,
			(int)DE_COLOR_R(d->pal[idx]), (int)DE_COLOR_G(d->pal[idx]),
			(int)DE_COLOR_B(d->pal[idx]));
	}
	return 1;
}

static void do_read_extension_area(deark *c, lctx *d, de_int64 pos)
{
	de_int64 ext_area_size;
	de_int64 thumbnail_offset;

	de_dbg(c, "extension area at %d\n", (int)pos);

	de_dbg_indent(c, 1);
	ext_area_size = de_getui16le(pos);
	de_dbg(c, "extension area size: %d\n", (int)ext_area_size);
	if(ext_area_size<495) goto done;

	// TODO: Retain the aspect ratio. (Need sample files. Nobody seems to use this field.)
	d->aspect_ratio_num = de_getui16le(pos+474);
	d->aspect_ratio_den = de_getui16le(pos+476);
	de_dbg(c, "aspect ratio: %d/%d\n", (int)d->aspect_ratio_num, (int)d->aspect_ratio_den);

	thumbnail_offset = de_getui32le(pos+486);
	de_dbg(c, "thumbnail image offset: %d\n", (int)thumbnail_offset);

	d->attributes_type = de_getbyte(pos+494);
	de_dbg(c, "attributes type: %d\n", (int)d->attributes_type);
done:
	de_dbg_indent(c, -1);
}

static void do_read_developer_area(deark *c, lctx *d, de_int64 pos)
{
	de_int64 num_tags;
	de_int64 i;
	de_int64 tag_id, tag_data_pos, tag_data_size;

	de_dbg(c, "developer area at %d\n", (int)pos);

	de_dbg_indent(c, 1);
	num_tags = de_getui16le(pos);
	de_dbg(c, "number of tags: %d\n", (int)num_tags);
	for(i=0; i<num_tags; i++) {
		if(i>=200) break;
		tag_id = de_getui16le(pos + 2 + 10*i);
		tag_data_pos = de_getui32le(pos + 2 + 10*i + 2);
		tag_data_size = de_getui32le(pos + 2 + 10*i + 6);
		de_dbg(c, "tag #%d: id=%d, pos=%d, size=%d\n", (int)i, (int)tag_id,
			(int)tag_data_pos, (int)tag_data_size);

		if(tag_id==20) {
			// Tag 20 seems to contain Photoshop resources, though this is unconfirmed.
			de_dbg_indent(c, 1);
			de_fmtutil_handle_photoshop_rsrc(c, tag_data_pos, tag_data_size);
			de_dbg_indent(c, -1);
		}
	}
	de_dbg_indent(c, -1);
}

static void do_read_footer(deark *c, lctx *d)
{
	de_int64 footerpos;
	de_int64 ext_offset, dev_offset;

	footerpos = c->infile->len - 26;
	de_dbg(c, "v2 footer at %d\n", (int)footerpos);
	ext_offset = de_getui32le(footerpos);
	de_dbg(c, "extension area offset: %d\n", (int)ext_offset);
	dev_offset = de_getui32le(footerpos+4);
	de_dbg(c, "developer area offset: %d\n", (int)dev_offset);

	if(ext_offset!=0) {
		do_read_extension_area(c, d, ext_offset);
	}

	if(dev_offset!=0) {
		do_read_developer_area(c, d, dev_offset);
	}
}

static int has_signature(deark *c)
{
	if(c->infile->len<18+26) return 0;
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
	const char *clrtype_name = NULL;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	d->has_signature = has_signature(c);
	de_dbg(c, "has v2 signature: %d\n", d->has_signature);

	d->id_field_len = (de_int64)de_getbyte(0);
	d->color_map_type = de_getbyte(1);
	d->img_type = de_getbyte(2);
	de_dbg(c, "image type code: %d\n", (int)d->img_type);

	switch(d->img_type) {
	case 1: case 9:
	case 32: case 33:
		d->color_type = TGA_CLRTYPE_PALETTE;
		clrtype_name = "palette";
		break;
	case 2: case 10:
		d->color_type = TGA_CLRTYPE_TRUECOLOR;
		clrtype_name = "truecolor";
		break;
	case 3: case 11:
		d->color_type = TGA_CLRTYPE_GRAYSCALE;
		clrtype_name = "grayscale";
		break;
	default:
		d->color_type = TGA_CLRTYPE_UNKNOWN;
		clrtype_name = "unknown";
	}

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
	de_dbg(c, "color type: %s\n", clrtype_name);
	de_dbg(c, "compression: %s\n", cmpr_name);
	de_dbg_indent(c, -1);

	if(d->color_map_type != 0) {
		d->cmap_start = de_getui16le(3);
		d->cmap_length = de_getui16le(5);
		d->cmap_depth = (de_int64)de_getbyte(7);
		de_dbg(c, "color map start: %d, len: %d, depth: %d\n", (int)d->cmap_start,
			(int)d->cmap_length, (int)d->cmap_depth);
	}

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

	d->right_to_left = (d->image_descriptor>>4)&0x01;
	d->top_down = (d->image_descriptor>>5)&0x01;
	de_dbg(c, "right-to-left flag: %d\n", (int)d->right_to_left);
	de_dbg(c, "top-down flag: %d\n", (int)d->top_down);
	de_dbg_indent(c, -1);

	if(d->has_signature) {
		do_read_footer(c, d);
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	pos += 18;

	if(d->id_field_len>0) {
		de_dbg(c, "image ID at %d (len=%d)\n", (int)pos, (int)d->id_field_len);
		pos += d->id_field_len;
	}

	if(d->color_map_type!=0) {
		d->bytes_per_pal_entry = (d->cmap_depth+7)/8;
		d->pal_size_in_bytes = d->cmap_length * d->bytes_per_pal_entry;
		de_dbg(c, "color map at %d (%d colors, %d bytes)\n", (int)pos,
			(int)d->cmap_length, (int)d->pal_size_in_bytes);

		if(!do_read_palette(c, d, pos)) goto done;

		pos += d->pal_size_in_bytes;
	}

	de_dbg(c, "bitmap at %d\n", (int)pos);

	d->bytes_per_pixel = ((d->pixel_depth+7)/8);
	d->img_size_in_bytes = d->height * d->width * d->bytes_per_pixel;

	if(d->color_type!=TGA_CLRTYPE_PALETTE && d->color_type!=TGA_CLRTYPE_TRUECOLOR &&
		d->color_type!=TGA_CLRTYPE_GRAYSCALE)
	{
		de_err(c, "Unsupported color type (%d: %s)\n", (int)d->color_type, clrtype_name);
		goto done;
	}

	if( (d->color_type==TGA_CLRTYPE_PALETTE && d->pixel_depth==8) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==15) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==16) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==24) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==32) ||
		(d->color_type==TGA_CLRTYPE_GRAYSCALE && d->pixel_depth==8) )
	{
		;
	}
	else {
		de_err(c, "Unsupported TGA image type (%s, depth=%d)\n", clrtype_name,
			(int)d->pixel_depth);
		goto done;
	}

	if(d->num_attribute_bits!=0 || d->attributes_type!=0 || d->pixel_depth==32) {
		// I'm giving up on TGA transparency, for now.
		// The specification is inadequate. To the extent that it is documented,
		// actual TGA files and TGA viewers both violate the spec, in different ways.
		de_warn(c, "This image might have transparency, which is not supported.\n");
	}

	if(d->cmpr_type==TGA_CMPR_RLE) {
		d->unc_pixels = dbuf_create_membuf(c, d->img_size_in_bytes);
		dbuf_set_max_length(d->unc_pixels, d->img_size_in_bytes);
		if(!do_decode_rle(c, d, pos)) goto done;
	}
	else if(d->cmpr_type==TGA_CMPR_NONE) {
		d->unc_pixels = dbuf_open_input_subfile(c->infile, pos, d->img_size_in_bytes);
	}
	else {
		de_err(c, "Unsupported compression type (%d, %s)\n", (int)d->cmpr_type, cmpr_name);
		goto done;
	}

	do_decode_image(c, d);

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
