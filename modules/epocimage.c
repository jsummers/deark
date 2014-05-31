// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

static const de_uint32 pal256[256] = {
	0x000000,0x330000,0x660000,0x990000,0xcc0000,0xff0000,0x003300,0x333300,
	0x663300,0x993300,0xcc3300,0xff3300,0x006600,0x336600,0x666600,0x996600,
	0xcc6600,0xff6600,0x009900,0x339900,0x669900,0x999900,0xcc9900,0xff9900,
	0x00cc00,0x33cc00,0x66cc00,0x99cc00,0xcccc00,0xffcc00,0x00ff00,0x33ff00,
	0x66ff00,0x99ff00,0xccff00,0xffff00,0x000033,0x330033,0x660033,0x990033,
	0xcc0033,0xff0033,0x003333,0x333333,0x663333,0x993333,0xcc3333,0xff3333,
	0x006633,0x336633,0x666633,0x996633,0xcc6633,0xff6633,0x009933,0x339933,
	0x669933,0x999933,0xcc9933,0xff9933,0x00cc33,0x33cc33,0x66cc33,0x99cc33,
	0xcccc33,0xffcc33,0x00ff33,0x33ff33,0x66ff33,0x99ff33,0xccff33,0xffff33,
	0x000066,0x330066,0x660066,0x990066,0xcc0066,0xff0066,0x003366,0x333366,
	0x663366,0x993366,0xcc3366,0xff3366,0x006666,0x336666,0x666666,0x996666,
	0xcc6666,0xff6666,0x009966,0x339966,0x669966,0x999966,0xcc9966,0xff9966,
	0x00cc66,0x33cc66,0x66cc66,0x99cc66,0xcccc66,0xffcc66,0x00ff66,0x33ff66,
	0x66ff66,0x99ff66,0xccff66,0xffff66,0x111111,0x222222,0x444444,0x555555,
	0x777777,0x110000,0x220000,0x440000,0x550000,0x770000,0x001100,0x002200,
	0x004400,0x005500,0x007700,0x000011,0x000022,0x000044,0x000055,0x000077,
	0x000088,0x0000aa,0x0000bb,0x0000dd,0x0000ee,0x008800,0x00aa00,0x00bb00,
	0x00dd00,0x00ee00,0x880000,0xaa0000,0xbb0000,0xdd0000,0xee0000,0x888888,
	0xaaaaaa,0xbbbbbb,0xdddddd,0xeeeeee,0x000099,0x330099,0x660099,0x990099,
	0xcc0099,0xff0099,0x003399,0x333399,0x663399,0x993399,0xcc3399,0xff3399,
	0x006699,0x336699,0x666699,0x996699,0xcc6699,0xff6699,0x009999,0x339999,
	0x669999,0x999999,0xcc9999,0xff9999,0x00cc99,0x33cc99,0x66cc99,0x99cc99,
	0xcccc99,0xffcc99,0x00ff99,0x33ff99,0x66ff99,0x99ff99,0xccff99,0xffff99,
	0x0000cc,0x3300cc,0x6600cc,0x9900cc,0xcc00cc,0xff00cc,0x0033cc,0x3333cc,
	0x6633cc,0x9933cc,0xcc33cc,0xff33cc,0x0066cc,0x3366cc,0x6666cc,0x9966cc,
	0xcc66cc,0xff66cc,0x0099cc,0x3399cc,0x6699cc,0x9999cc,0xcc99cc,0xff99cc,
	0x00cccc,0x33cccc,0x66cccc,0x99cccc,0xcccccc,0xffcccc,0x00ffcc,0x33ffcc,
	0x66ffcc,0x99ffcc,0xccffcc,0xffffcc,0x0000ff,0x3300ff,0x6600ff,0x9900ff,
	0xcc00ff,0xff00ff,0x0033ff,0x3333ff,0x6633ff,0x9933ff,0xcc33ff,0xff33ff,
	0x0066ff,0x3366ff,0x6666ff,0x9966ff,0xcc66ff,0xff66ff,0x0099ff,0x3399ff,
	0x6699ff,0x9999ff,0xcc99ff,0xff99ff,0x00ccff,0x33ccff,0x66ccff,0x99ccff,
	0xccccff,0xffccff,0x00ffff,0x33ffff,0x66ffff,0x99ffff,0xccffff,0xffffff
};

static const de_uint32 pal16[16] = {
	0x000000,0x555555,0x800000,0x808000,0x008000,0xff0000,0x00ff00,0xffff00,
	0xff00ff,0x00ff00,0x00ffff,0x800080,0x000080,0x008080,0xaaaaaa,0xffffff
};

typedef struct localctx_struct {
	de_int64 width, height;
	de_int64 color_type;
	de_int64 bits_per_pixel;
	de_int64 paint_data_section_size;
	int warned_exp;
} lctx;

static de_uint32 rgb565to888(de_uint32 n)
{
	de_byte cr, cg, cb;
	cr = (de_byte)(n>>11);
	cg = (de_byte)((n>>5)&0x3f);
	cb = (de_byte)(n&0x1f);
	cr = (de_byte)(0.5+((double)cr)*(255.0/31.0));
	cg = (de_byte)(0.5+((double)cg)*(255.0/63.0));
	cb = (de_byte)(0.5+((double)cb)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

static struct deark_bitmap *do_create_image(deark *c, lctx *d, dbuf *unc_pixels, int is_mask)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 src_rowspan;
	de_byte b;
	de_int64 i_adj;
	de_byte cr;
	de_uint32 n;
	de_uint32 clr;
	de_byte v[3];

	img = de_bitmap_create(c, d->width, d->height, d->color_type ? 3 : 1);

	img->orig_colortype = (int)d->color_type;
	img->orig_bitdepth = (int)d->bits_per_pixel;

	if(d->bits_per_pixel==24) {
		// 24-bit images seem to be 12-byte aligned
		src_rowspan = ((d->bits_per_pixel*d->width +95)/96)*12;
	}
	else {
		// Rows are 4-byte aligned
		src_rowspan = ((d->bits_per_pixel*d->width +31)/32)*4;
	}

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			// Pixels within a byte are apparently packed in "little bit endian" order:
			// the leftmost pixel uses the least significant bits, etc.
			// This is unusual, and de_get_bits_symbol() doesn't handle it.
			switch(d->bits_per_pixel) {
			case 2:
				i_adj = (i-i%4) + (3-i%4);
				b = de_get_bits_symbol(unc_pixels, (int)d->bits_per_pixel, j*src_rowspan, i_adj);
				de_bitmap_setpixel_gray(img, i, j, b*85);
				break;
			case 4:
				i_adj = (i-i%2) + (1-i%2);
				b = de_get_bits_symbol(unc_pixels, (int)d->bits_per_pixel, j*src_rowspan, i_adj);
				if(d->color_type)
					de_bitmap_setpixel_rgb(img, i, j, pal16[(unsigned int)b]);
				else
					de_bitmap_setpixel_gray(img, i, j, b*17);
				break;
			case 8:
				b = dbuf_getbyte(unc_pixels, j*src_rowspan + i);
				if(d->color_type) {
					de_bitmap_setpixel_rgb(img, i, j, pal256[(unsigned int)b]);
				}
				else {
					// I have no 8-bit grayscale samples, so I don't know if this is
					// correct, or valid.
					de_bitmap_setpixel_gray(img, i, j, b);
				}
				break;
			case 16:
				n = (de_uint32)dbuf_getui16le(unc_pixels, j*src_rowspan + i*2);
				if(is_mask) {
					cr = (de_byte)(n>>8);
					clr = DE_MAKE_RGB(cr, cr, cr);
				}
				else {
					clr = rgb565to888(n);
				}
				de_bitmap_setpixel_rgb(img, i, j, clr);
				break;
			case 24:
				v[0] = dbuf_getbyte(unc_pixels, j*src_rowspan + i*3);
				v[1] = dbuf_getbyte(unc_pixels, j*src_rowspan + i*3+1);
				v[2] = dbuf_getbyte(unc_pixels, j*src_rowspan + i*3+2);
				clr = DE_MAKE_RGB(v[0], v[1], v[2]);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				break;
			}
		}
	}
	return img;
}

static void do_rle8(deark *c, lctx *d, dbuf *unc_pixels,
	de_int64 pos1, de_int64 len)
{
	de_int64 i;
	de_byte b0, b1;
	de_int64 pos;
	de_int64 count;

	pos = pos1;
	while(pos<pos1+len) {
		b0 = de_getbyte(pos);
		pos++;

		if(b0<=0x7f) {
			// Next byte should be repeated b0+1 times.
			count = 1+(de_int64)b0;
			b1 = de_getbyte(pos);
			pos++;
			for(i=0; i<count; i++) {
				dbuf_write(unc_pixels, &b1, 1);
			}
		}
		else {
			// 256-b0 bytes of uncompressed data.
			count = 256-(de_int64)b0;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}
}

static void do_rle16_24(deark *c, lctx *d, dbuf *unc_pixels,
	de_int64 pos1, de_int64 len, de_int64 bytes_per_pixel)
{
	de_int64 i;
	de_int64 k;
	de_byte b0;
	de_int64 pos;
	de_int64 count;
	de_byte v[3];

	pos = pos1;
	while(pos<pos1+len) {
		b0 = de_getbyte(pos);
		pos++;

		if(b0<=0x7f) {
			// Next pixel should be repeated b0+1 times.
			count = 1+(de_int64)b0;
			for(k=0; k<bytes_per_pixel; k++) {
				v[k] = de_getbyte(pos++);
			}
			for(i=0; i<count; i++) {
				dbuf_write(unc_pixels, v, bytes_per_pixel);
			}
		}
		else {
			// 256-b0 pixels of uncompressed data.
			count = 256-(de_int64)b0;
			dbuf_copy(c->infile, pos, count*bytes_per_pixel, unc_pixels);
			pos += count*bytes_per_pixel;
		}
	}
}

// Sets d->paint_data_section_size.
// Returns a bitmap.
static struct deark_bitmap *do_read_paint_data_section(deark *c, lctx *d,
	de_int64 pos1, int is_mask)
{
	de_int64 pixel_data_offset;
	de_int64 pos;
	dbuf *unc_pixels = NULL;
	de_int64 compression_type;
	de_int64 cmpr_pixels_size;
	struct deark_bitmap *img = NULL;

	pos = pos1;
	de_dbg(c, "paint data section at: %d\n", (int)pos1);

	d->paint_data_section_size = de_getui32le(pos);
	de_dbg(c, "paint data section size: %d\n", (int)d->paint_data_section_size);

	// offset within "paint data section"
	pixel_data_offset = de_getui32le(pos+4);
	de_dbg(c, "pixel data offset: %d\n", (int)pixel_data_offset);

	d->width = de_getui16le(pos+8);
	d->height = de_getui16le(pos+12);
	de_dbg(c, "picture dimensions: %dx%d\n", (int)d->width, (int)d->height);

	d->bits_per_pixel = de_getui32le(pos+24);
	de_dbg(c, "bits/pixel: %d\n", (int)d->bits_per_pixel);

	d->color_type = de_getui32le(pos+28);
	// 0=grayscale  1=color
	de_dbg(c, "color type: %d\n", (int)d->color_type);

	compression_type = de_getui32le(pos+36);
	// 0=uncompressed  1=8-bit RLE  2=12-bit RLE  3=16-bit RLE  4=24-bit RLE
	de_dbg(c, "compression type: %d\n", (int)compression_type);

	if(d->color_type==0) {
		if(d->bits_per_pixel!=2 && d->bits_per_pixel!=4 && d->bits_per_pixel!=8) {
			de_err(c, "Unsupported bits/pixel (%d) for grayscale image\n", (int)d->bits_per_pixel);
			goto done;
		}
	}
	else {
		if(d->bits_per_pixel!=4 && d->bits_per_pixel!=8 && d->bits_per_pixel!=16 &&
			d->bits_per_pixel!=24)
		{
			de_err(c, "Unsupported bits/pixel (%d) for color image\n", (int)d->bits_per_pixel);
			goto done;
		}
		if(d->bits_per_pixel==16 && !d->warned_exp) {
			de_warn(c, "Support for this type of 16-bit image is experimental, and may not be correct.\n");
			d->warned_exp = 1;
		}
	}

	pos += 40;
	cmpr_pixels_size = d->paint_data_section_size-40;
	de_dbg(c, "pixel data at: %d\n", (int)pos);

	switch(compression_type) {
	case 0: // uncompressed
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
		break;
	case 1: // RLE8
		unc_pixels = dbuf_create_membuf(c, 16384);
		do_rle8(c, d, unc_pixels, pos, cmpr_pixels_size);
		break;
	case 3: // RLE16
		unc_pixels = dbuf_create_membuf(c, 16384);
		do_rle16_24(c, d, unc_pixels, pos, cmpr_pixels_size, 2);
		break;
	case 4: // RLE24
		unc_pixels = dbuf_create_membuf(c, 16384);
		do_rle16_24(c, d, unc_pixels, pos, cmpr_pixels_size, 3);
		break;

		// TODO: RLE12 (2)

	default:
		de_err(c, "Unsupported compression type: %d\n", (int)compression_type);
		goto done;
	}

	img = do_create_image(c, d, unc_pixels, is_mask);

done:
	if(unc_pixels) dbuf_close(unc_pixels);
	return img;
}

// Writes the image to a file.
// Sets d->paint_data_section_size.
static void do_read_and_write_paint_data_section(deark *c, lctx *d, de_int64 pos1)
{
	struct deark_bitmap *img = NULL;

	img = do_read_paint_data_section(c, d, pos1, 0);
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_combine_and_write_images(deark *c, lctx *d,
	struct deark_bitmap *fg_img, struct deark_bitmap *mask_img)
{
	struct deark_bitmap *img = NULL; // The combined image
	de_int64 i, j;
	de_uint32 clr;
	de_byte a;

	if(!fg_img) goto done;
	if(!mask_img) {
		de_bitmap_write_to_file(fg_img, NULL);
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
	de_bitmap_write_to_file(img, NULL);

done:
	de_bitmap_destroy(img);
}

static void do_sketch_section(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos;
	de_int64 paint_data_section_start;
	de_int64 s_s_w, s_s_h;
	de_int64 x1, x2;

	pos = pos1;

	// 18-byte header
	de_dbg(c, "sketch section at %d\n", (int)pos);
	s_s_w = de_getui16le(pos);
	s_s_h = de_getui16le(pos+2);
	de_dbg(c, "sketch section dimensions: %dx%d\n", (int)s_s_w, (int)s_s_h);

	pos += 18;

	// The image itself
	paint_data_section_start = pos;
	do_read_and_write_paint_data_section(c, d, paint_data_section_start);

	// Some data follows the image, but it doesn't seem to be important,
	// so we don't have to read it before calling
	// do_read_and_write_paint_data_section() to convert the image.

	pos = paint_data_section_start + d->paint_data_section_size;
	x1 = de_getui16le(pos);
	x2 = de_getui16le(pos+2);
	de_dbg(c, "magnification: %dx%d\n", (int)x1, (int)x2);
	x1 = de_getui32le(pos+4);
	x2 = de_getui32le(pos+8);
	de_dbg(c, "left, right cut: %d, %d\n", (int)x1, (int)x2);
	x1 = de_getui32le(pos+12);
	x2 = de_getui32le(pos+16);
	de_dbg(c, "top, bottom cut: %d, %d\n", (int)x1, (int)x2);
}

static void de_run_epocsketch(deark *c, lctx *d)
{
	de_int64 section_table_offset;
	de_byte unknown_section_table_byte;
	de_int64 pos;
	int num_sections;
	de_int64 section_id;
	de_int64 section_loc;
	de_int64 i;

	de_dbg(c, "EPOC Sketch format\n");

	section_table_offset = de_getui32le(16);
	de_dbg(c, "section table offset: %d\n", (int)section_table_offset);

	// Section table section
	pos = section_table_offset;
	unknown_section_table_byte = de_getbyte(pos);
	de_dbg(c, "first byte of section table: %d\n", (int)unknown_section_table_byte);
	pos++;

	num_sections = ((int)unknown_section_table_byte)/2; // guess
	for(i=0; i<num_sections; i++) {
		section_id = de_getui32le(pos+8*i);
		section_loc = de_getui32le(pos+8*i+4);
		de_dbg(c, "section id: 0x%08x at %d\n", (unsigned int)section_id, (int)section_loc);
		if(section_id==0x1000007d) {
			do_sketch_section(c, d, section_loc);
		}
	}
}

static void de_run_epocaif(deark *c, lctx *d)
{
	de_int64 table_offset;
	de_int64 pos;
	de_int64 i;
	de_int64 caption_count_code;
	de_int64 num_images;
	de_int64 first_image_pos;
	de_int64 img_pos;
	struct deark_bitmap *fg_img = NULL;
	struct deark_bitmap *mask_img = NULL;

	de_dbg(c, "EPOC AIF format\n");

	table_offset = de_getui32le(16);
	de_dbg(c, "table offset: %d\n", (int)table_offset);

	pos = table_offset;

	// The first byte seems to be 2 times the number of captions.
	caption_count_code = de_getbyte(pos);
	de_dbg(c, "caption count code(?): %d\n", (int)caption_count_code);
	pos++;

	// Next, there are 3*caption_count_code partially-unknown bytes
	// (we know that this includes the position of the captions).
	pos += 3*caption_count_code;

	num_images = de_getbyte(pos);
	de_dbg(c, "image count(?): %d\n", (int)num_images);
	pos++;

	first_image_pos = de_getui32le(pos);
	de_dbg(c, "offset of first image: %d\n", (int)first_image_pos);

	// Unfortunately, I don't know what the remaining data in the file is for.
	// (I'm working without specs.) Maybe it indicates which image is a
	// transparency mask for which other image, or something.
	// For now, I'll assume that every second image is the transparency mask for
	// the previous image.

	img_pos = first_image_pos;
	i = 0;
	while(i<num_images) {
		de_dbg(c, "foreground image at %d\n", (int)img_pos);
		de_bitmap_destroy(fg_img);
		fg_img = do_read_paint_data_section(c, d, img_pos, 0);
		if(d->paint_data_section_size<=0) break;
		img_pos += d->paint_data_section_size;
		i++;

		if(i<num_images) {
			de_dbg(c, "mask image at %d\n", (int)img_pos);
			de_bitmap_destroy(mask_img);
			mask_img = do_read_paint_data_section(c, d, img_pos, 1);
			if(d->paint_data_section_size<=0) break;
			img_pos += d->paint_data_section_size;
			i++;
		}

		do_combine_and_write_images(c, d, fg_img, mask_img);
	}

	de_bitmap_destroy(fg_img);
	de_bitmap_destroy(mask_img);
}

static void de_run_epocmbm(deark *c, lctx *d)
{
	de_int64 image_table_offset;
	de_int64 num_images;
	de_int64 i;
	de_int64 img_pos;

	de_dbg(c, "EPOC MBM format\n");

	image_table_offset = de_getui32le(16);
	de_dbg(c, "image table offset: %d\n", (int)image_table_offset);

	num_images = de_getui32le(image_table_offset);
	de_dbg(c, "number of images: %d\n", (int)num_images);
	if(num_images>DE_MAX_IMAGES_PER_FILE) {
		de_err(c, "Too many images\n");
		goto done;
	}

	for(i=0; i<num_images; i++) {
		img_pos = de_getui32le(image_table_offset + 4 + 4*i);
		de_dbg(c, "image at %d\n", (int)img_pos);
		do_read_and_write_paint_data_section(c, d, img_pos);
	}

done:
	;
}

#define DE_PFMT_MBM     1
#define DE_PFMT_EXPORTED_MBM 2
#define DE_PFMT_SKETCH  3
#define DE_PFMT_AIF     4

static int de_identify_epocimage_internal(deark *c)
{
	de_byte b[12];
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

static void de_run_epocimage(deark *c, const char *params)
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
		de_err(c, "Internal: Unidentified format\n");
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
	mi->run_fn = de_run_epocimage;
	mi->identify_fn = de_identify_epocimage;
}
