// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// EPOC MBM, EPOC Sketch, EPOC AIF

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_epocimage);

static const u32 supplpal[40] = {
	0x111111,0x222222,0x444444,0x555555,0x777777,
	0x110000,0x220000,0x440000,0x550000,0x770000,
	0x001100,0x002200,0x004400,0x005500,0x007700,
	0x000011,0x000022,0x000044,0x000055,0x000077,
	0x000088,0x0000aa,0x0000bb,0x0000dd,0x0000ee,
	0x008800,0x00aa00,0x00bb00,0x00dd00,0x00ee00,
	0x880000,0xaa0000,0xbb0000,0xdd0000,0xee0000,
	0x888888,0xaaaaaa,0xbbbbbb,0xdddddd,0xeeeeee
};

static u32 getpal256(int k)
{
	int x;
	u8 r, g, b;

	if(k<0 || k>255) return 0;

	// The first and last 108 entries together make up the simple palette once
	// known as the "web safe" palette. The middle 40 entries are
	// supplementary grayscale and red/green/blue shades.

	if(k>=108 && k<148) {
		return supplpal[k-108];
	}

	x = k<108 ? k : k-40;
	r = (x%6)*0x33;
	g = ((x%36)/6)*0x33;
	b = (u8)((x/36)*0x33);

	return DE_MAKE_RGB(r,g,b);
}

// I believe this is the correct palette (or at least *a* correct palette),
// though it has some differences from the one in the Psiconv documentation.
static const u32 pal16[16] = {
	0x000000,0x555555,0x800000,0x808000,0x008000,0xff0000,0xffff00,0x00ff00,
	0xff00ff,0x0000ff,0x00ffff,0x800080,0x000080,0x008080,0xaaaaaa,0xffffff
};

struct page_ctx {
	i64 width, height;
	i64 color_type;
	i64 bits_per_pixel;
};

typedef struct localctx_struct {
	i64 paint_data_section_size;
	int warned_exp;

	i64 jumptable_offset;
	i64 section_table_offset;
} lctx;

static de_bitmap *do_create_image(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *unc_pixels, int is_mask)
{
	de_bitmap *img = NULL;
	i64 i, j;
	i64 src_rowspan;
	u8 b;
	u8 cr;
	u32 n;
	u32 clr;

	img = de_bitmap_create(c, pg->width, pg->height, pg->color_type ? 3 : 1);

	img->orig_colortype = (int)pg->color_type;
	img->orig_bitdepth = (int)pg->bits_per_pixel;

	if(pg->bits_per_pixel==24) {
		// 24-bit images seem to be 12-byte aligned
		src_rowspan = ((pg->bits_per_pixel*pg->width +95)/96)*12;
	}
	else if(pg->bits_per_pixel==12) {
		// Our decompression algorithm expands RLE12 to an RGB24 format.
		// Apparently, rows with an odd number of pixels have one pixel of
		// padding, which at this stage is 3 bytes.
		src_rowspan = 3*pg->width;
		if(pg->width%2) src_rowspan += 3;
	}
	else {
		// Rows are 4-byte aligned
		src_rowspan = ((pg->bits_per_pixel*pg->width +31)/32)*4;
	}

	for(j=0; j<pg->height; j++) {
		for(i=0; i<pg->width; i++) {
			switch(pg->bits_per_pixel) {
			case 1:
				b = de_get_bits_symbol_lsb(unc_pixels, pg->bits_per_pixel, j*src_rowspan, i);
				de_bitmap_setpixel_gray(img, i, j, b*255);
				break;
			case 2:
				b = de_get_bits_symbol_lsb(unc_pixels, pg->bits_per_pixel, j*src_rowspan, i);
				de_bitmap_setpixel_gray(img, i, j, b*85);
				break;
			case 4:
				b = de_get_bits_symbol_lsb(unc_pixels, pg->bits_per_pixel, j*src_rowspan, i);
				if(pg->color_type)
					de_bitmap_setpixel_rgb(img, i, j, pal16[(unsigned int)b]);
				else
					de_bitmap_setpixel_gray(img, i, j, b*17);
				break;
			case 8:
				b = dbuf_getbyte(unc_pixels, j*src_rowspan + i);
				if(pg->color_type) {
					de_bitmap_setpixel_rgb(img, i, j, getpal256((unsigned int)b));
				}
				else {
					// I have no 8-bit grayscale samples, so I don't know if this is
					// correct, or valid.
					de_bitmap_setpixel_gray(img, i, j, b);
				}
				break;
			case 16:
				n = (u32)dbuf_getu16le(unc_pixels, j*src_rowspan + i*2);
				if(is_mask) {
					cr = (u8)(n>>8);
					clr = DE_MAKE_RGB(cr, cr, cr);
				}
				else {
					clr = de_rgb565_to_888(n);
				}
				de_bitmap_setpixel_rgb(img, i, j, clr);
				break;
			case 12:
			case 24:
				clr = dbuf_getRGB(unc_pixels, j*src_rowspan + i*3, 0);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				break;
			}
		}
	}
	return img;
}

static void do_rle8(deark *c, lctx *d, dbuf *unc_pixels,
	i64 pos1, i64 len)
{
	u8 b0, b1;
	i64 pos;
	i64 count;

	pos = pos1;
	while(pos<pos1+len) {
		b0 = de_getbyte(pos);
		pos++;

		if(b0<=0x7f) {
			// Next byte should be repeated b0+1 times.
			count = 1+(i64)b0;
			b1 = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, b1, count);
		}
		else {
			// 256-b0 bytes of uncompressed data.
			count = 256-(i64)b0;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}
}

static void do_rle12(deark *c, lctx *d, dbuf *unc_pixels,
	i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 count;
	i64 k;
	unsigned int n;
	u8 v[3];

	while(pos<pos1+len) {
		n = (unsigned int)de_getu16le_p(&pos);
		count = 1+(i64)((n&0xf000)>>12);
		v[0] = (u8)((n&0x0f00)>>8);
		v[1] = (u8)((n&0x00f0)>>4);
		v[2] = (u8)(n&0x000f);
		v[0] *= 17;
		v[1] *= 17;
		v[2] *= 17;
		for(k=0; k<count; k++) {
			dbuf_write(unc_pixels, v, 3);
		}
	}
}

static void do_rle16_24(deark *c, lctx *d, dbuf *unc_pixels,
	i64 pos1, i64 len, i64 bytes_per_pixel)
{
	i64 i;
	i64 k;
	u8 b0;
	i64 pos;
	i64 count;
	u8 v[3];

	pos = pos1;
	while(pos<pos1+len) {
		b0 = de_getbyte(pos);
		pos++;

		if(b0<=0x7f) {
			// Next pixel should be repeated b0+1 times.
			count = 1+(i64)b0;
			for(k=0; k<bytes_per_pixel; k++) {
				v[k] = de_getbyte(pos++);
			}
			for(i=0; i<count; i++) {
				dbuf_write(unc_pixels, v, bytes_per_pixel);
			}
		}
		else {
			// 256-b0 pixels of uncompressed data.
			count = 256-(i64)b0;
			dbuf_copy(c->infile, pos, count*bytes_per_pixel, unc_pixels);
			pos += count*bytes_per_pixel;
		}
	}
}

static const char *get_cmpr_type_name(i64 t)
{
	const char *s = NULL;
	switch(t) {
	case 0: s="none"; break;
	case 1: s="RLE8"; break;
	case 2: s="RLE12"; break;
	case 3: s="RLE16"; break;
	case 4: s="RLE24"; break;
	}
	return s?s:"?";
}

// Sets d->paint_data_section_size.
// Returns a bitmap.
static de_bitmap *do_read_paint_data_section(deark *c, lctx *d,
	i64 pos1, int is_mask)
{
	i64 pixel_data_offset;
	i64 pos;
	dbuf *unc_pixels = NULL;
	i64 compression_type;
	i64 cmpr_pixels_size;
	de_bitmap *img = NULL;
	struct page_ctx *pg = NULL;

	pg = de_malloc(c, sizeof(struct page_ctx));
	pos = pos1;
	de_dbg(c, "paint data section at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->paint_data_section_size = de_getu32le(pos);
	de_dbg(c, "paint data section size: %d", (int)d->paint_data_section_size);

	// offset within "paint data section"
	pixel_data_offset = de_getu32le(pos+4);
	de_dbg(c, "pixel data offset: %d", (int)pixel_data_offset);

	pg->width = de_getu16le(pos+8);
	pg->height = de_getu16le(pos+12);
	de_dbg(c, "picture dimensions: %d"DE_CHAR_TIMES"%d", (int)pg->width, (int)pg->height);

	pg->bits_per_pixel = de_getu32le(pos+24);
	de_dbg(c, "bits/pixel: %d", (int)pg->bits_per_pixel);

	pg->color_type = de_getu32le(pos+28);
	// 0=grayscale  1=color
	de_dbg(c, "color type: %d", (int)pg->color_type);

	compression_type = de_getu32le(pos+36);
	// 0=uncompressed  1=8-bit RLE  2=12-bit RLE  3=16-bit RLE  4=24-bit RLE
	de_dbg(c, "compression type: %d (%s)", (int)compression_type,
		get_cmpr_type_name(compression_type));

	if(pg->color_type==0) {
		if(pg->bits_per_pixel!=1 && pg->bits_per_pixel!=2 && pg->bits_per_pixel!=4 &&
			pg->bits_per_pixel!=8)
		{
			de_err(c, "Unsupported bits/pixel (%d) for grayscale image", (int)pg->bits_per_pixel);
			goto done;
		}
	}
	else {
		if(pg->bits_per_pixel!=4 && pg->bits_per_pixel!=8 && pg->bits_per_pixel!=12 &&
			pg->bits_per_pixel!=16 && pg->bits_per_pixel!=24)
		{
			de_err(c, "Unsupported bits/pixel (%d) for color image", (int)pg->bits_per_pixel);
			goto done;
		}
		if(pg->bits_per_pixel==12 && compression_type!=2) {
			de_err(c, "12 bits/pixel images are not supported with this compression type (%d)",
				(int)compression_type);
		}
		if(pg->bits_per_pixel==16 && !d->warned_exp) {
			de_warn(c, "Support for this type of 16-bit image is experimental, and may not be correct.");
			d->warned_exp = 1;
		}
	}

	pos += 40;
	cmpr_pixels_size = d->paint_data_section_size-40;
	de_dbg(c, "pixel data at %d", (int)pos);

	switch(compression_type) {
	case 0: // uncompressed
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
		break;
	case 1: // RLE8
		unc_pixels = dbuf_create_membuf(c, 16384, 0);
		do_rle8(c, d, unc_pixels, pos, cmpr_pixels_size);
		break;
	case 2: // RLE12
		unc_pixels = dbuf_create_membuf(c, 16384, 0);
		do_rle12(c, d, unc_pixels, pos, cmpr_pixels_size);
		break;
	case 3: // RLE16
		unc_pixels = dbuf_create_membuf(c, 16384, 0);
		do_rle16_24(c, d, unc_pixels, pos, cmpr_pixels_size, 2);
		break;
	case 4: // RLE24
		unc_pixels = dbuf_create_membuf(c, 16384, 0);
		do_rle16_24(c, d, unc_pixels, pos, cmpr_pixels_size, 3);
		break;
	default:
		de_err(c, "Unsupported compression type: %d", (int)compression_type);
		goto done;
	}

	img = do_create_image(c, d, pg, unc_pixels, is_mask);

done:
	if(unc_pixels) dbuf_close(unc_pixels);
	de_dbg_indent(c, -1);
	de_free(c, pg);
	return img;
}

// Writes the image to a file.
// Sets d->paint_data_section_size.
static void do_read_and_write_paint_data_section(deark *c, lctx *d, i64 pos1)
{
	de_bitmap *img = NULL;

	img = do_read_paint_data_section(c, d, pos1, 0);
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_combine_and_write_images(deark *c, lctx *d,
	de_bitmap *fg_img, de_bitmap *mask_img)
{
	de_bitmap *img = NULL; // The combined image
	i64 i, j;
	u32 clr;
	u8 a;

	if(!fg_img) goto done;
	if(!mask_img) {
		de_bitmap_write_to_file(fg_img, NULL, 0);
		goto done;
	}

	// Create a new image (which supports transparency).
	img = de_bitmap_create(c, fg_img->width, fg_img->height, fg_img->bytes_per_pixel<=2 ? 2 : 4);

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			clr = de_bitmap_getpixel(fg_img, i, j);

			if(i<mask_img->width && j<mask_img->height) {
				a = DE_COLOR_G(de_bitmap_getpixel(mask_img, i, j));
				if(mask_img->orig_colortype==0 && mask_img->orig_bitdepth==8) {
					a = 255-a;
				}
			}
			else {
				// Apparently, some masks are smaller than the image, and undefined
				// pixels should be transparent.
				a = 0xff;
			}

			// White is background, black is foreground.
			if(a==0xff) {
				clr = DE_MAKE_RGBA(255,128,255,0);
			}
			else if(a!=0) {
				// Make this pixel transparent or partly transparent.
				clr = DE_SET_ALPHA(clr, 255-a);
			}
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static void do_sketch_section(deark *c, lctx *d, i64 pos1)
{
	i64 pos;
	i64 paint_data_section_start;
	i64 s_s_w, s_s_h;
	i64 x1, x2;

	pos = pos1;

	// 18-byte header
	de_dbg(c, "sketch section at %d", (int)pos);
	de_dbg_indent(c, 1);

	s_s_w = de_getu16le(pos);
	s_s_h = de_getu16le(pos+2);
	de_dbg(c, "sketch section dimensions: %d"DE_CHAR_TIMES"%d", (int)s_s_w, (int)s_s_h);

	pos += 18;

	// The image itself
	paint_data_section_start = pos;
	do_read_and_write_paint_data_section(c, d, paint_data_section_start);

	// Some data follows the image, but it doesn't seem to be important,
	// so we don't have to read it before calling
	// do_read_and_write_paint_data_section() to convert the image.

	pos = paint_data_section_start + d->paint_data_section_size;
	x1 = de_getu16le(pos);
	x2 = de_getu16le(pos+2);
	de_dbg(c, "magnification: %d"DE_CHAR_TIMES"%d", (int)x1, (int)x2);
	x1 = de_getu32le(pos+4);
	x2 = de_getu32le(pos+8);
	de_dbg(c, "left, right cut: %d, %d", (int)x1, (int)x2);
	x1 = de_getu32le(pos+12);
	x2 = de_getu32le(pos+16);
	de_dbg(c, "top, bottom cut: %d, %d", (int)x1, (int)x2);

	de_dbg_indent(c, -1);
}

static void do_epocsketch_section_table_entry(deark *c, lctx *d,
	i64 entry_index, i64 pos)
{
	i64 section_id;
	i64 section_loc;

	section_id = de_getu32le(pos);
	section_loc = de_getu32le(pos+4);
	de_dbg(c, "section #%d: id=0x%08x, pos=%d", (int)entry_index,
		(unsigned int)section_id, (int)section_loc);
	de_dbg_indent(c, 1);
	if(section_id==0x1000007d) {
		do_sketch_section(c, d, section_loc);
	}
	de_dbg_indent(c, -1);
}

static void do_epocsketch_section_table(deark *c, lctx *d, i64 pos)
{
	u8 section_table_size_code;
	int num_sections;
	i64 i;

	// Section table section
	de_dbg(c, "section table at %d", (int)pos);
	de_dbg_indent(c, 1);

	section_table_size_code = de_getbyte(pos);
	// The Section Table is a single "BListL" object. A BlistL starts with a byte
	// indicating the remaining size in 4-byte Longs. Each entry in the table is 8
	// bytes, so divide by 2 to get the number of entries.
	num_sections = ((int)section_table_size_code)/2;

	de_dbg(c, "section table size: %d (%d entries)", (int)section_table_size_code,
		(int)num_sections);
	pos++;

	for(i=0; i<num_sections; i++) {
		do_epocsketch_section_table_entry(c, d, i, pos+8*i);
	}
	de_dbg_indent(c, -1);
}

static void do_epocsketch_header(deark *c, lctx *d, i64 pos)
{
	de_dbg(c, "header section at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->section_table_offset = de_getu32le(pos+16);
	de_dbg(c, "section table offset: %d", (int)d->section_table_offset);
	de_dbg_indent(c, -1);
}

static void de_run_epocsketch(deark *c, lctx *d)
{
	do_epocsketch_header(c, d, 0);
	do_epocsketch_section_table(c, d, d->section_table_offset);
}

static void de_run_epocaif(deark *c, lctx *d)
{
	i64 table_offset;
	i64 pos;
	i64 i;
	i64 caption_count_code;
	i64 num_images;
	i64 first_image_pos;
	i64 img_pos;
	de_bitmap *fg_img = NULL;
	de_bitmap *mask_img = NULL;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);
	table_offset = de_getu32le(16);
	de_dbg(c, "table offset: %d", (int)table_offset);
	de_dbg_indent(c, -1);

	pos = table_offset;
	de_dbg(c, "table at %d", (int)pos);
	de_dbg_indent(c, 1);
	// The first byte seems to be 2 times the number of captions.
	caption_count_code = de_getbyte(pos);
	de_dbg(c, "caption count code(?): %d", (int)caption_count_code);
	pos++;

	// Next, there are 3*caption_count_code partially-unknown bytes
	// (we know that this includes the position of the captions).
	pos += 3*caption_count_code;

	num_images = de_getbyte(pos);
	de_dbg(c, "bitmap count(?): %d", (int)num_images);
	pos++;

	first_image_pos = de_getu32le(pos);
	de_dbg(c, "offset of first bitmap: %d", (int)first_image_pos);

	de_dbg_indent(c, -1);

	// Unfortunately, I don't know what the remaining data in the file is for.
	// (I'm working without specs.) Maybe it indicates which image is a
	// transparency mask for which other image, or something.
	// For now, I'll assume that every second image is the transparency mask for
	// the previous image.

	img_pos = first_image_pos;
	i = 0;
	while(i<num_images) {
		de_dbg(c, "image #%d", (int)(i/2));
		de_dbg_indent(c, 1);

		de_dbg(c, "foreground bitmap at %d", (int)img_pos);
		de_dbg_indent(c, 1);
		fg_img = do_read_paint_data_section(c, d, img_pos, 0);
		if(d->paint_data_section_size<=0) break;
		img_pos += d->paint_data_section_size;
		i++;
		de_dbg_indent(c, -1);

		if(i<num_images) {
			de_dbg(c, "mask bitmap at %d", (int)img_pos);
			de_dbg_indent(c, 1);
			mask_img = do_read_paint_data_section(c, d, img_pos, 1);
			if(d->paint_data_section_size<=0) break;
			img_pos += d->paint_data_section_size;
			i++;
			de_dbg_indent(c, -1);
		}

		do_combine_and_write_images(c, d, fg_img, mask_img);
		de_bitmap_destroy(fg_img);
		fg_img = NULL;
		de_bitmap_destroy(mask_img);
		mask_img = NULL;
		de_dbg_indent(c, -1);
	}

	de_bitmap_destroy(fg_img);
	de_bitmap_destroy(mask_img);
}

static void do_epocmbm_jumptable_entry(deark *c, lctx *d, i64 entry_index,
	i64 pos)
{
	i64 img_pos;

	img_pos = de_getu32le(pos);
	de_dbg(c, "image #%d, pos=%d", (int)entry_index, (int)pos);
	de_dbg_indent(c, 1);
	do_read_and_write_paint_data_section(c, d, img_pos);
	de_dbg_indent(c, -1);
}

static void do_epocmbm_jumptable(deark *c, lctx *d, i64 pos)
{
	i64 num_images;
	i64 i;

	de_dbg(c, "MBM jumptable at %d", (int)pos);
	de_dbg_indent(c, 1);

	num_images = de_getu32le(pos);
	de_dbg(c, "number of images: %d", (int)num_images);
	if(!de_good_image_count(c, num_images)) {
		de_err(c, "Too many images");
		goto done;
	}

	for(i=0; i<num_images; i++) {
		do_epocmbm_jumptable_entry(c, d, i, pos + 4 + 4*i);
	}

done:
	de_dbg_indent(c, -1);
}

static void do_epocmbm_header(deark *c, lctx *d, i64 pos)
{
	de_dbg(c, "header section at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->jumptable_offset = de_getu32le(pos+16);
	de_dbg(c, "MBM jumptable offset: %d", (int)d->jumptable_offset);
	de_dbg_indent(c, -1);
}

static void de_run_epocmbm(deark *c, lctx *d)
{
	do_epocmbm_header(c, d, 0);
	do_epocmbm_jumptable(c, d, d->jumptable_offset);
}

#define DE_PFMT_MBM     1
#define DE_PFMT_EXPORTED_MBM 2
#define DE_PFMT_SKETCH  3
#define DE_PFMT_AIF     4

static int de_identify_epocimage_internal(deark *c)
{
	u8 b[12];
	de_read(b, 0, 12);

	if(!de_memcmp(b, "\x37\x00\x00\x10\x42\x00\x00\x10", 8)) {
		return DE_PFMT_MBM; // EPOC MBM
	}
	if(!de_memcmp(b, "\x37\x00\x00\x10\x8a\x00\x00\x10", 8)) {
		return DE_PFMT_EXPORTED_MBM; // EPOC exported MBM
	}
	if(!de_memcmp(b, "\x37\x00\x00\x10\x6D\x00\x00\x10\x7D\x00\x00\x10", 12)) {
		return DE_PFMT_SKETCH; // EPOC Sketch
	}
	if(!de_memcmp(b, "\x37\x00\x00\x10\x6a\x00\x00\x10", 8)) {
		return DE_PFMT_AIF; // EPOC AIF
	}
	if(!de_memcmp(b, "\x37\x00\x00\x10\x38\x3a\x00\x10", 8)) {
		return DE_PFMT_AIF;
	}
	//if(!de_memcmp(b, "\x32\xb0\x1f\x10\x00\x00\x00\x00", 8)) {
	//	return DE_PFMT_?;
	//}
	return 0;
}

static void de_run_epocimage(deark *c, de_module_params *mparams)
{
	int fmt;
	lctx *d = NULL;

	fmt = de_identify_epocimage_internal(c);

	d = de_malloc(c, sizeof(lctx));

	switch(fmt) {
	case DE_PFMT_SKETCH:
		de_declare_fmt(c, "EPOC Sketch");
		de_run_epocsketch(c, d);
		break;
	case DE_PFMT_MBM:
		de_declare_fmt(c, "EPOC MBM");
		de_run_epocmbm(c, d);
		break;
	case DE_PFMT_EXPORTED_MBM:
		de_declare_fmt(c, "EPOC Exported MBM");
		de_run_epocmbm(c, d);
		break;
	case DE_PFMT_AIF:
		de_declare_fmt(c, "EPOC AIF");
		de_run_epocaif(c, d);
		break;
	default:
		de_err(c, "Internal: Unidentified format");
	}

	de_free(c, d);
}

static int de_identify_epocimage(deark *c)
{
	int fmt;

	fmt = de_identify_epocimage_internal(c);
	return (fmt>0) ? 100 : 0;
}

void de_module_epocimage(deark *c, struct deark_module_info *mi)
{
	mi->id = "epocimage";
	mi->desc = "EPOC MBM (a.k.a. Symbian Multibitmap), EPOC Sketch, EPOC AIF";
	mi->run_fn = de_run_epocimage;
	mi->identify_fn = de_identify_epocimage;
}
