// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// EPOC MBM, EPOC Sketch, EPOC AIF

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_epocimage);

#define DE_PFMT_MBM           1
#define DE_PFMT_EXPORTED_MBM  2
#define DE_PFMT_SKETCH        3
#define DE_PFMT_AIF           4

// Corresponds to a Paint Data Section
struct phys_image_ctx {
	i64 width, height;
	i64 color_type;
	i64 bits_per_pixel;
	int is_mask;
	i64 src_rowspan;
	de_bitmap *img;
	i64 paint_data_section_size;
	de_color pal[256];
};

typedef struct localctx_struct {
	int fmt;
	i64 last_paint_data_section_size;
	int warned_exp;

	i64 jumptable_offset;
	i64 section_table_offset;
	u8 have_stdpal256;
	de_color stdpal256[256];
} lctx;

static const de_color supplpal[40] = {
	0xff111111U,0xff222222U,0xff444444U,0xff555555U,0xff777777U,
	0xff110000U,0xff220000U,0xff440000U,0xff550000U,0xff770000U,
	0xff001100U,0xff002200U,0xff004400U,0xff005500U,0xff007700U,
	0xff000011U,0xff000022U,0xff000044U,0xff000055U,0xff000077U,
	0xff000088U,0xff0000aaU,0xff0000bbU,0xff0000ddU,0xff0000eeU,
	0xff008800U,0xff00aa00U,0xff00bb00U,0xff00dd00U,0xff00ee00U,
	0xff880000U,0xffaa0000U,0xffbb0000U,0xffdd0000U,0xffee0000U,
	0xff888888U,0xffaaaaaaU,0xffbbbbbbU,0xffddddddU,0xffeeeeeeU
};

static de_color getpal256(UI k)
{
	UI x;
	u8 r, g, b;

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

static void populate_stdpal256(lctx *d)
{
	UI k;

	if(d->have_stdpal256) return;
	d->have_stdpal256 = 1;

	for(k=0; k<256; k++) {
		d->stdpal256[k] = getpal256(k);
	}
}

// I believe this is the correct palette (or at least *a* correct palette),
// though it has some differences from the one in the Psiconv documentation.
static const de_color g_stdpal16[16] = {
	0xff000000U,0xff555555U,0xff800000U,0xff808000U,0xff008000U,0xffff0000U,0xffffff00U,0xff00ff00U,
	0xffff00ffU,0xff0000ffU,0xff00ffffU,0xff800080U,0xff000080U,0xff008080U,0xffaaaaaaU,0xffffffffU
};

static void destroy_phys_image(deark *c, struct phys_image_ctx *pi)
{
	if(!pi) return;
	if(pi->img) {
		de_bitmap_destroy(pi->img);
	}
	de_free(c, pi);
}

static void decode_image_16bit(deark *c, lctx *d, struct phys_image_ctx *pi,
	dbuf *unc_pixels, de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<pi->height; j++) {
		for(i=0; i<pi->width; i++) {
			u8 cr;
			u32 n;
			de_color clr;

			n = (u32)dbuf_getu16le(unc_pixels, j*pi->src_rowspan + i*2);
			if(pi->is_mask) {
				cr = (u8)(n>>8);
				clr = DE_MAKE_RGB(cr, cr, cr);
			}
			else {
				clr = de_rgb565_to_888(n);
			}
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

// Returns an image in pi->img
static void do_read_phys_image(deark *c, lctx *d, struct phys_image_ctx *pi,
	dbuf *unc_pixels)
{
	de_bitmap *img = NULL;
	i64 pdwidth;
	int bypp;

	if(pi->img) goto done;
	pdwidth = pi->width;

	if(pi->bits_per_pixel==24) {
		// 24-bit images seem to be 12-byte aligned
		pi->src_rowspan = ((pi->bits_per_pixel*pi->width +95)/96)*12;
	}
	else if(pi->bits_per_pixel==12) {
		// Our decompression algorithm expands RLE12 to an RGB24 format.
		// Apparently, rows with an odd number of pixels have one pixel of
		// padding, which at this stage is 3 bytes.
		pi->src_rowspan = 3*pi->width;
		if(pi->width%2) pi->src_rowspan += 3;
	}
	else {
		i64 bits_per_row;
		// Rows are 4-byte aligned

		bits_per_row = de_pad_to_n(pi->bits_per_pixel*pi->width, 32);
		pi->src_rowspan = bits_per_row / 8;
		pdwidth = bits_per_row / pi->bits_per_pixel;
	}

	bypp = pi->color_type ? 3 : 1;
	img = de_bitmap_create2(c, pi->width, pdwidth, pi->height, bypp);
	pi->img = img;

	if(pi->bits_per_pixel==1 || pi->bits_per_pixel==2 || pi->bits_per_pixel==4 ||
		pi->bits_per_pixel==8)
	{
		if(pi->bits_per_pixel==4 && pi->color_type) {
			de_memcpy(pi->pal, g_stdpal16, sizeof(g_stdpal16));
		}
		else if(pi->bits_per_pixel==8 && pi->color_type) {
			populate_stdpal256(d);
			de_memcpy(pi->pal, d->stdpal256, sizeof(d->stdpal256));
		}
		else {
			// I have no 8-bit grayscale sample files, so I don't know if this is
			// correct for them.
			de_make_grayscale_palette(pi->pal, 1LL<<pi->bits_per_pixel, 0);
		}

		de_convert_image_paletted(unc_pixels, 0, pi->bits_per_pixel, pi->src_rowspan,
			pi->pal, img, 0x1);
	}
	else if(pi->bits_per_pixel==12 || pi->bits_per_pixel==24) {
		de_convert_image_rgb(unc_pixels, 0, pi->src_rowspan, 3, img, 0);
	}
	else if(pi->bits_per_pixel==16) {
		decode_image_16bit(c, d, pi, unc_pixels, img);
	}

done:
	;
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
// Caller creates pi, and sets pi->is_mask.
// Returns a bitmap in pi->img, if successful
static void do_read_paint_data_section(deark *c, lctx *d,
	struct phys_image_ctx *pi, i64 pos1)
{
	i64 pixel_data_offset;
	i64 pos;
	dbuf *unc_pixels = NULL;
	i64 compression_type;
	i64 cmpr_pixels_size;

	pos = pos1;
	de_dbg(c, "paint data section at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pi->paint_data_section_size = de_getu32le(pos);
	de_dbg(c, "paint data section size: %"I64_FMT, pi->paint_data_section_size);

	// offset within "paint data section"
	pixel_data_offset = de_getu32le(pos+4);
	de_dbg(c, "pixel data offset: %"I64_FMT, pixel_data_offset);

	pi->width = de_getu16le(pos+8);
	pi->height = de_getu16le(pos+12);
	de_dbg(c, "picture dimensions: %d"DE_CHAR_TIMES"%d", (int)pi->width, (int)pi->height);

	pi->bits_per_pixel = de_getu32le(pos+24);
	de_dbg(c, "bits/pixel: %d", (int)pi->bits_per_pixel);

	pi->color_type = de_getu32le(pos+28);
	// 0=grayscale  1=color
	de_dbg(c, "color type: %d", (int)pi->color_type);

	compression_type = de_getu32le(pos+36);
	// 0=uncompressed  1=8-bit RLE  2=12-bit RLE  3=16-bit RLE  4=24-bit RLE
	de_dbg(c, "compression type: %d (%s)", (int)compression_type,
		get_cmpr_type_name(compression_type));

	if(pi->color_type==0) {
		if(pi->bits_per_pixel!=1 && pi->bits_per_pixel!=2 && pi->bits_per_pixel!=4 &&
			pi->bits_per_pixel!=8)
		{
			de_err(c, "Unsupported bits/pixel (%d) for grayscale image", (int)pi->bits_per_pixel);
			goto done;
		}
	}
	else {
		if(pi->bits_per_pixel!=4 && pi->bits_per_pixel!=8 && pi->bits_per_pixel!=12 &&
			pi->bits_per_pixel!=16 && pi->bits_per_pixel!=24)
		{
			de_err(c, "Unsupported bits/pixel (%d) for color image", (int)pi->bits_per_pixel);
			goto done;
		}
		if(pi->bits_per_pixel==12 && compression_type!=2) {
			de_err(c, "12 bits/pixel images are not supported with this compression type (%d)",
				(int)compression_type);
		}
		if(pi->bits_per_pixel==16 && !d->warned_exp) {
			de_warn(c, "Support for this type of 16-bit image is experimental, and may not be correct.");
			d->warned_exp = 1;
		}
	}

	pos += 40;
	cmpr_pixels_size = pi->paint_data_section_size-40;
	de_dbg(c, "pixel data at %"I64_FMT, pos);

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

	do_read_phys_image(c, d, pi, unc_pixels);

done:
	if(unc_pixels) dbuf_close(unc_pixels);
	de_dbg_indent(c, -1);
}

// Writes the image to a file.
// Sets d->last_paint_data_section_size.
static void do_read_and_write_paint_data_section(deark *c, lctx *d, i64 pos1)
{
	struct phys_image_ctx *pi = NULL;

	pi = de_malloc(c, sizeof(struct phys_image_ctx));
	pi->is_mask = 0;
	do_read_paint_data_section(c, d, pi, pos1);
	if(pi->img) {
		de_bitmap_write_to_file(pi->img, NULL, 0);
	}
	d->last_paint_data_section_size = pi->paint_data_section_size;
	destroy_phys_image(c, pi);
}

static void do_combine_and_write_images(deark *c, lctx *d,
	struct phys_image_ctx *pi_fg, struct phys_image_ctx *pi_mask)
{
	de_bitmap *fg_img;
	de_bitmap *mask_img;
	de_bitmap *img = NULL; // The combined image
	i64 i, j;

	if(!pi_fg || !pi_fg->img) goto done;
	if(!pi_mask || !pi_mask->img) {
		de_bitmap_write_to_file(pi_fg->img, NULL, 0);
		goto done;
	}

	fg_img = pi_fg->img;
	mask_img = pi_mask->img;

	// Create a new image (which supports transparency).
	img = de_bitmap_create2(c, fg_img->unpadded_width, fg_img->width, fg_img->height,
		(fg_img->bytes_per_pixel<=2 ? 2 : 4));

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			de_color clr;
			de_colorsample a;

			clr = de_bitmap_getpixel(fg_img, i, j);

			if(i>=fg_img->unpadded_width) {
				// Make all padding pixels opaque. (We don't preserve the mask's padding pixels.)
				a = 0;
			}
			else if(i<mask_img->unpadded_width && j<mask_img->height) {
				de_color clrm;
				i64 a1;

				clrm = de_bitmap_getpixel(mask_img, i, j);

				// Some masks have colors that are not quite grayscale.
				// Guess we'll use the average of the sample values.
				a1 = (i64)DE_COLOR_R(clrm) + (i64)DE_COLOR_G(clrm) + (i64)DE_COLOR_B(clrm);
				a = de_scale_n_to_255(255*3, a1);

				if(pi_mask->color_type==0 && pi_mask->bits_per_pixel==8) {
					a = 255-a;
				}
			}
			else {
				// Apparently, some masks are smaller than the image, and undefined
				// pixels should be transparent.
				a = 0xff;
			}

			de_bitmap_setpixel_rgba(img, i, j, DE_SET_ALPHA(clr, 255-a));
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
	de_dbg(c, "sketch section at %"I64_FMT, pos);
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

	pos = paint_data_section_start + d->last_paint_data_section_size;
	x1 = de_getu16le(pos);
	x2 = de_getu16le(pos+2);
	de_dbg(c, "magnification: %u"DE_CHAR_TIMES"%u", (UI)x1, (UI)x2);
	x1 = de_getu32le(pos+4);
	x2 = de_getu32le(pos+8);
	de_dbg(c, "left, right cut: %u, %u", (UI)x1, (UI)x2);
	x1 = de_getu32le(pos+12);
	x2 = de_getu32le(pos+16);
	de_dbg(c, "top, bottom cut: %u, %u", (UI)x1, (UI)x2);

	de_dbg_indent(c, -1);
}

static void do_epocsketch_section_table_entry(deark *c, lctx *d,
	i64 entry_index, i64 pos)
{
	i64 section_id;
	i64 section_loc;

	section_id = de_getu32le(pos);
	section_loc = de_getu32le(pos+4);
	de_dbg(c, "section #%d: id=0x%08x, pos=%"I64_FMT, (int)entry_index,
		(UI)section_id, section_loc);
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
	de_dbg(c, "section table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	section_table_size_code = de_getbyte(pos);
	// The Section Table is a single "BListL" object. A BlistL starts with a byte
	// indicating the remaining size in 4-byte Longs. Each entry in the table is 8
	// bytes, so divide by 2 to get the number of entries.
	num_sections = ((int)section_table_size_code)/2;

	de_dbg(c, "section table size: %u (%d entries)", (UI)section_table_size_code,
		(int)num_sections);
	pos++;

	for(i=0; i<num_sections; i++) {
		do_epocsketch_section_table_entry(c, d, i, pos+8*i);
	}
	de_dbg_indent(c, -1);
}

static void do_epocsketch_header(deark *c, lctx *d, i64 pos)
{
	de_dbg(c, "header section at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	d->section_table_offset = de_getu32le(pos+16);
	de_dbg(c, "section table offset: %"I64_FMT, d->section_table_offset);
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
	struct phys_image_ctx *pi_fg = NULL;
	struct phys_image_ctx *pi_mask = NULL;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);
	table_offset = de_getu32le(16);
	de_dbg(c, "table offset: %"I64_FMT, table_offset);
	de_dbg_indent(c, -1);

	pos = table_offset;
	de_dbg(c, "table at %"I64_FMT, pos);
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
	de_dbg(c, "offset of first bitmap: %"I64_FMT, first_image_pos);

	de_dbg_indent(c, -1);

	// Unfortunately, I don't know what the remaining data in the file is for.
	// (I'm working without specs.) Maybe it indicates which image is a
	// transparency mask for which other image, or something.
	// For now, I'll assume that every second image is the transparency mask for
	// the previous image.

	img_pos = first_image_pos;
	i = 0;
	while(i<num_images) {
		if(pi_fg) {
			destroy_phys_image(c, pi_fg);
			pi_fg = NULL;
		}
		if(pi_mask) {
			destroy_phys_image(c, pi_mask);
			pi_mask = NULL;
		}

		de_dbg(c, "image #%d", (int)(i/2));
		de_dbg_indent(c, 1);

		de_dbg(c, "foreground bitmap at %"I64_FMT, img_pos);
		de_dbg_indent(c, 1);
		pi_fg = de_malloc(c, sizeof(struct phys_image_ctx));
		pi_fg->is_mask = 0;
		do_read_paint_data_section(c, d, pi_fg, img_pos);
		if(pi_fg->paint_data_section_size<=0) break;
		img_pos += pi_fg->paint_data_section_size;
		i++;
		de_dbg_indent(c, -1);

		if(i<num_images) {
			de_dbg(c, "mask bitmap at %"I64_FMT, img_pos);
			de_dbg_indent(c, 1);
			pi_mask = de_malloc(c, sizeof(struct phys_image_ctx));
			pi_mask->is_mask = 1;
			do_read_paint_data_section(c, d, pi_mask, img_pos);
			if(pi_mask->paint_data_section_size<=0) break;
			img_pos += pi_mask->paint_data_section_size;
			i++;
			de_dbg_indent(c, -1);
		}

		do_combine_and_write_images(c, d, pi_fg, pi_mask);
		de_dbg_indent(c, -1);
	}

	destroy_phys_image(c, pi_fg);
	destroy_phys_image(c, pi_mask);
}

static void do_epocmbm_jumptable_entry(deark *c, lctx *d, i64 entry_index,
	i64 pos)
{
	i64 img_pos;

	img_pos = de_getu32le(pos);
	de_dbg(c, "image #%d, pos=%"I64_FMT, (int)entry_index, pos);
	de_dbg_indent(c, 1);
	do_read_and_write_paint_data_section(c, d, img_pos);
	de_dbg_indent(c, -1);
}

static void do_epocmbm_jumptable(deark *c, lctx *d, i64 pos)
{
	i64 num_images;
	i64 i;

	de_dbg(c, "MBM jumptable at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	num_images = de_getu32le(pos);
	de_dbg(c, "number of images: %"I64_FMT, num_images);
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
	de_dbg(c, "header section at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	d->jumptable_offset = de_getu32le(pos+16);
	de_dbg(c, "MBM jumptable offset: %"I64_FMT, d->jumptable_offset);
	de_dbg_indent(c, -1);
}

static void de_run_epocmbm(deark *c, lctx *d)
{
	do_epocmbm_header(c, d, 0);
	do_epocmbm_jumptable(c, d, d->jumptable_offset);
}

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
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = de_identify_epocimage_internal(c);

	switch(d->fmt) {
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
		de_internal_err_nonfatal(c, "Unidentified format");
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
	mi->desc = "EPOC/Symbian MBM, Sketch, AIF";
	mi->run_fn = de_run_epocimage;
	mi->identify_fn = de_identify_epocimage;
}
