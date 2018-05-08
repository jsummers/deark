// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// icns - Apple Icon Image format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_icns);

static const de_uint32 pal16[16] = {
	0xffffff,0xfcf305,0xff6402,0xdd0806,0xf20884,0x4600a5,0x0000d4,0x02abea,
	0x1fb714,0x006411,0x562c05,0x90713a,0xc0c0c0,0x808080,0x404040,0x000000
};

#define IMGTYPE_EMBEDDED_FILE   1
#define IMGTYPE_MASK            2
#define IMGTYPE_IMAGE           3
#define IMGTYPE_IMAGE_AND_MASK  4

struct image_type_info {
	de_uint32 code;
	int width;
	int height;
	int bpp; // bits per pixel. 0 = unspecified
	int image_type; // IMGTYPE_*
};
static const struct image_type_info image_type_info_arr[] = {
	{ 0x69636d23, 16,   12,   1,  IMGTYPE_IMAGE_AND_MASK }, // icm#
	{ 0x69637323, 16,   16,   1,  IMGTYPE_IMAGE_AND_MASK }, // ics#
	{ 0x49434e23, 32,   32,   1,  IMGTYPE_IMAGE_AND_MASK }, // ICN#
	{ 0x69636823, 48,   48,   1,  IMGTYPE_IMAGE_AND_MASK }, // ich#

	{ 0x49434f4e, 32,   32,   1,  IMGTYPE_IMAGE }, // ICON
	{ 0x69636d34, 16,   12,   4,  IMGTYPE_IMAGE }, // icm4
	{ 0x69637334, 16,   16,   4,  IMGTYPE_IMAGE }, // ics4
	{ 0x69636c34, 32,   32,   4,  IMGTYPE_IMAGE }, // icl4
	{ 0x69636834, 48,   48,   4,  IMGTYPE_IMAGE }, // ich4
	{ 0x69636d38, 16,   12,   8,  IMGTYPE_IMAGE }, // icm8
	{ 0x69637338, 16,   16,   8,  IMGTYPE_IMAGE }, // ics8
	{ 0x69636c38, 32,   32,   8,  IMGTYPE_IMAGE }, // icl8
	{ 0x69636838, 48,   48,   8,  IMGTYPE_IMAGE }, // ich8
	{ 0x69733332, 16,   16,   24, IMGTYPE_IMAGE }, // is32
	{ 0x696c3332, 32,   32,   24, IMGTYPE_IMAGE }, // il32
	{ 0x69683332, 48,   48,   24, IMGTYPE_IMAGE }, // ih32
	{ 0x69743332, 128,  128,  24, IMGTYPE_IMAGE }, // it32

	{ 0x73386d6b, 16,   16,   8,  IMGTYPE_MASK }, // s8mk
	{ 0x6c386d6b, 32,   32,   8,  IMGTYPE_MASK }, // l8mk
	{ 0x68386d6b, 48,   48,   8,  IMGTYPE_MASK }, // h8mk
	{ 0x74386d6b, 128,  128,  8,  IMGTYPE_MASK }, // t8mk

	{ 0x69637034, 16,   16,   0,  IMGTYPE_EMBEDDED_FILE }, // icp4
	{ 0x69637035, 32,   32,   0,  IMGTYPE_EMBEDDED_FILE }, // icp5
	{ 0x69637036, 64,   64,   0,  IMGTYPE_EMBEDDED_FILE }, // icp6
	{ 0x69633037, 128,  128,  0,  IMGTYPE_EMBEDDED_FILE }, // ic07
	{ 0x69633038, 256,  256,  0,  IMGTYPE_EMBEDDED_FILE }, // ic08
	{ 0x69633039, 512,  512,  0,  IMGTYPE_EMBEDDED_FILE }, // ic09
	{ 0x69633130, 1024, 1024, 0,  IMGTYPE_EMBEDDED_FILE }, // ic10
	{ 0x69633131, 32,   32,   0,  IMGTYPE_EMBEDDED_FILE }, // ic11
	{ 0x69633132, 64,   64,   0,  IMGTYPE_EMBEDDED_FILE }, // ic12
	{ 0x69633133, 256,  256,  0,  IMGTYPE_EMBEDDED_FILE }, // ic13
	{ 0x69633134, 512,  512,  0,  IMGTYPE_EMBEDDED_FILE }, // ic14

	{ 0x544f4320, 0,    0,    0,  0 }, // 'TOC '
	{ 0x69636e56, 0,    0,    0,  0 }, // icnV
	{ 0, 0, 0, 0, 0 }
};

struct page_ctx {
	int image_num;
	de_int64 image_pos;
	de_int64 image_len;
	de_int64 mask_pos; //  (0 = not found)
	de_int64 mask_rowspan;
	de_int64 rowspan;
	const struct image_type_info *type_info;
	struct de_fourcc code4cc;
	char filename_token[32];
};

typedef struct localctx_struct {
	de_int64 file_size;

	// File offsets of mask images (0 = not present)
	de_int64 mkpos_16_12_1;
	de_int64 mkpos_16_16_1;
	de_int64 mkpos_32_32_1;
	de_int64 mkpos_48_48_1;
	de_int64 mkpos_16_16_8;
	de_int64 mkpos_32_32_8;
	de_int64 mkpos_48_48_8;
	de_int64 mkpos_128_128_8;
} lctx;

static const de_uint32 supplpal256[41] = {
	0xee0000,0xdd0000,0xbb0000,0xaa0000,0x880000,
	0x770000,0x550000,0x440000,0x220000,0x110000,
	0x00ee00,0x00dd00,0x00bb00,0x00aa00,0x008800,
	0x007700,0x005500,0x004400,0x002200,0x001100,
	0x0000ee,0x0000dd,0x0000bb,0x0000aa,0x000088,
	0x000077,0x000055,0x000044,0x000022,0x000011,
	0xeeeeee,0xdddddd,0xbbbbbb,0xaaaaaa,0x888888,
	0x777777,0x555555,0x444444,0x222222,0x111111,0x000000
};

static de_uint32 getpal256(int k)
{
	de_byte r, g, b;

	if(k<0 || k>255) return 0;
	if(k<=214) {
		// The first 215 palette entries follow a simple pattern.
		r = (de_byte)((5-k/36)*0x33);
		g = (5-(k%36)/6)*0x33;
		b = (5-k%6)*0x33;
		return DE_MAKE_RGB(r,g,b);
	}

	return supplpal256[k-215];
}

static void do_decode_1_4_8bit(deark *c, lctx *d, struct page_ctx *pg)
{
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_byte a, b;
	de_byte x;
	de_int32 fgcol;

	img = de_bitmap_create(c, pg->type_info->width, pg->type_info->height, 4);

	for(j=0; j<pg->type_info->height; j++) {
		for(i=0; i<pg->type_info->width; i++) {
			// Foreground
			b = de_get_bits_symbol(c->infile, pg->type_info->bpp, pg->image_pos + pg->rowspan*j, i);

			if(pg->type_info->bpp==8) {
				fgcol = getpal256((int)b);
			}
			else if(pg->type_info->bpp==4) {
				fgcol = pal16[(unsigned int)b];
			}
			else {
				fgcol = b ? 0x0000000 : 0xffffff;
			}

			// Opacity
			if(pg->mask_pos) {
				x = de_get_bits_symbol(c->infile, 1, pg->mask_pos + pg->mask_rowspan*j, i);
				a = x ? 0xff : 0x00;
			}
			else {
				a = 0xff;
			}
			de_bitmap_setpixel_rgba(img, i, j, DE_SET_ALPHA(fgcol, a));
		}
	}

	de_bitmap_write_to_file(img, pg->filename_token, 0);
	de_bitmap_destroy(img);
}

static void do_uncompress_24(deark *c, lctx *d, struct page_ctx *pg, dbuf *unc_pixels,
	de_int64 skip)
{
	de_int64 pos;
	de_byte b;
	de_int64 count;
	de_byte n;

	pos = pg->image_pos;
	if(skip) pos+=4;

	while(1) {
		if(pos >= pg->image_pos + pg->image_len) break;

		b = de_getbyte(pos);
		pos++;
		if(b>=128) {
			// Compressed run
			count = (de_int64)b - 125;
			n = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, n, count);
		}
		else {
			// An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}
}

static void do_decode_24bit(deark *c, lctx *d, struct page_ctx *pg)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_byte cr, cg, cb, ca;
	de_int64 w, h;
	de_int64 skip;

	w = pg->type_info->width;
	h = pg->type_info->height;

	// TODO: Try to support uncompressed 24-bit images, assuming they exist.

	// Apparently, some 'it32' icons begin with four extra 0x00 bytes.
	// Skip over the first four bytes if they are 0x00.
	// (I don't know the reason for these bytes, but this is the same
	// logic libicns uses.)
	skip = 0;
	if(pg->code4cc.id==0x69743332) { // 'it32' (128x128)
		if(!dbuf_memcmp(c->infile, pg->image_pos, "\0\0\0\0", 4)) {
			skip = 4;
		}
	}

	unc_pixels = dbuf_create_membuf(c, w*h*3, 1);
	do_uncompress_24(c, d, pg, unc_pixels, skip);

	img = de_bitmap_create(c, w, h, 4);

	for(j=0; j<pg->type_info->height; j++) {
		for(i=0; i<pg->type_info->width; i++) {
			cr = dbuf_getbyte(unc_pixels, j*w + i);
			cg = dbuf_getbyte(unc_pixels, (h+j)*w + i);
			cb = dbuf_getbyte(unc_pixels, (2*h+j)*w + i);
			if(pg->mask_pos)
				ca = de_getbyte(pg->mask_pos + j*w + i);
			else
				ca = 0xff;
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(cr,cg,cb,ca));
		}
	}

	de_bitmap_write_to_file(img, pg->filename_token, 0);
	de_bitmap_destroy(img);
	if(unc_pixels) dbuf_close(unc_pixels);
}

static void do_extract_png_or_jp2(deark *c, lctx *d, struct page_ctx *pg)
{
	de_byte buf[8];
	de_finfo *fi = NULL;

	de_dbg(c, "Trying to extract file at %d", (int)pg->image_pos);

	// Detect the format
	de_read(buf, pg->image_pos, sizeof(buf));

	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, pg->filename_token, DE_ENCODING_ASCII);

	if(buf[4]=='j' && buf[5]=='P') {
		dbuf_create_file_from_slice(c->infile, pg->image_pos, pg->image_len, "jp2", fi, 0);
	}
	else if(buf[0]==0x89 && buf[1]==0x50) {
		dbuf_create_file_from_slice(c->infile, pg->image_pos, pg->image_len, "png", fi, 0);
	}
	else {
		de_err(c, "(Image #%d) Unidentified file format", pg->image_num);
	}

	de_finfo_destroy(c, fi);
}

// Sets pg->mask_pos and pg->mask_rowspan.
// Assumes image_type is IMAGE or IMAGE_AND_MASK.
static void find_mask(deark *c, lctx *d, struct page_ctx *pg)
{
	const struct image_type_info *t;
	t = pg->type_info;

	// As far as I can determine, icons with 8 or fewer bits/pixel always use the
	// 1-bit mask. Note that 1-bit masks cannot appear by themselves, and always
	// follow a 1-bit image. So if there is an 8- or 4-bit image, there must
	// always be a 1-bit image of the same dimensions.

	if(t->bpp<=8) {
		pg->mask_rowspan = (t->width + 7)/8;
	}
	else {
		pg->mask_rowspan = t->width;
	}

	if(t->code==0x49434f4e) { // 'ICON'
		// I'm assuming this format doesn't have a mask.
		return;
	}

	if(t->width==16 && t->height==12 && t->bpp<=8) {
		pg->mask_pos = d->mkpos_16_12_1;
	}
	else if(t->width==16 && t->height==16 && t->bpp<=8) {
		pg->mask_pos = d->mkpos_16_16_1;
	}
	else if(t->width==32 && t->bpp<=8) {
		pg->mask_pos = d->mkpos_32_32_1;
	}
	else if(t->width==48 && t->bpp<=8) {
		pg->mask_pos = d->mkpos_48_48_1;
	}
	else if(t->width==16 && t->bpp>=24) {
		pg->mask_pos = d->mkpos_16_16_8;
	}
	else if(t->width==32 && t->bpp>=24) {
		pg->mask_pos = d->mkpos_32_32_8;
	}
	else if(t->width==48 && t->bpp>=24) {
		pg->mask_pos = d->mkpos_48_48_8;
	}
	else if(t->width==128 && t->bpp>=24) {
		pg->mask_pos = d->mkpos_128_128_8;
	}
}

static void do_icon(deark *c, lctx *d, struct page_ctx *pg)
{
	de_int64 expected_image_size;
	int is_compressed;

	if(!pg->type_info) return; // Shouldn't happen.

	de_strlcpy(pg->filename_token, "", sizeof(pg->filename_token));

	if(pg->type_info->image_type==IMGTYPE_MASK) {
		de_dbg(c, "transparency mask");
		return;
	}

	if(pg->type_info->image_type==IMGTYPE_EMBEDDED_FILE) {
		de_snprintf(pg->filename_token, sizeof(pg->filename_token), "%dx%d",
			(int)pg->type_info->width, (int)pg->type_info->height);
		do_extract_png_or_jp2(c, d, pg);
		return;
	}

	if(pg->type_info->image_type!=IMGTYPE_IMAGE &&
		pg->type_info->image_type!=IMGTYPE_IMAGE_AND_MASK)
	{
		return;
	}

	// At this point we know it's a regular image (or an image+mask)

	// Note - This pg->rowspan is arguably incorrect for 24-bit images, since
	// rows aren't stored contiguously.
	pg->rowspan = ((pg->type_info->bpp * pg->type_info->width)+7)/8;

	expected_image_size = pg->rowspan * pg->type_info->height;
	if(pg->type_info->image_type==IMGTYPE_IMAGE_AND_MASK) {
		expected_image_size *= 2;
	}

	is_compressed = (pg->type_info->bpp==24) ? 1 : 0;

	if(!is_compressed) {
		if(pg->image_len < expected_image_size) {
			de_err(c, "(Image #%d) Premature end of image (expected %d bytes, found %d)",
				pg->image_num, (int)expected_image_size, (int)pg->image_len);
			return;
		}
		if(pg->image_len > expected_image_size) {
			de_warn(c, "(Image #%d) Extra image data found (expected %d bytes, found %d)",
				pg->image_num, (int)expected_image_size, (int)pg->image_len);
		}
	}

	find_mask(c, d, pg);

	de_snprintf(pg->filename_token, sizeof(pg->filename_token), "%dx%dx%d",
		(int)pg->type_info->width, (int)pg->type_info->height, (int)pg->type_info->bpp);

	de_dbg(c, "image dimensions: %d"DE_CHAR_TIMES"%d, bpp: %d",
		pg->type_info->width, pg->type_info->height, pg->type_info->bpp);

	if(pg->type_info->bpp==1 || pg->type_info->bpp==4 || pg->type_info->bpp==8) {
		do_decode_1_4_8bit(c, d, pg);
		return;
	}
	else if(pg->type_info->bpp==24) {
		do_decode_24bit(c, d, pg);
		return;
	}

	de_warn(c, "(Image #%d) Image type '%s' is not supported", pg->image_num, pg->code4cc.id_sanitized_sz);
}

static void de_run_icns_pass(deark *c, lctx *d, int pass)
{
	de_int64 i;
	de_int64 segment_pos;
	struct page_ctx *pg = NULL;
	int image_count;

	segment_pos = 8;
	image_count = 0;

	while(1) {
		de_int64 segment_len;

		if(pg) { de_free(c, pg); pg=NULL; }

		if(segment_pos+8 > d->file_size) break;

		pg = de_malloc(c, sizeof(struct page_ctx));
		pg->image_num = image_count;

		dbuf_read_fourcc(c->infile, segment_pos, &pg->code4cc, 4, 0x0);

		segment_len = de_getui32be(segment_pos+4);

		pg->image_pos = segment_pos + 8;
		pg->image_len = segment_len - 8;

		if(pass==2) {
			de_dbg(c, "image #%d, type '%s', at %d, size=%d", pg->image_num, pg->code4cc.id_dbgstr,
				(int)pg->image_pos, (int)pg->image_len);
		}
		if(segment_len<8 || segment_pos+segment_len > d->file_size) {
			if(pass==2) {
				de_err(c, "Invalid length for segment '%s' (%u)", pg->code4cc.id_sanitized_sz,
					(unsigned int)segment_len);
			}
			break;
		}

		if(pass==2) {
			// Find this type code in the image_type_info array
			pg->type_info = NULL;
			for(i=0; image_type_info_arr[i].code!=0; i++) {
				if(image_type_info_arr[i].code==pg->code4cc.id) {
					pg->type_info = &image_type_info_arr[i];
					break;
				}
			}
			if(!pg->type_info) {
				de_warn(c, "(Image #%d) Unknown image type '%s'", pg->image_num, pg->code4cc.id_sanitized_sz);
			}
		}

		if(pass==1) {
			switch(pg->code4cc.id) {
			case 0x69636d23: // icm# 16x12x1
				d->mkpos_16_16_1 = pg->image_pos + (16*12)/8;
				break;
			case 0x69637323: // ics# 16x16x1
				d->mkpos_16_16_1 = pg->image_pos + 16*16/8;
				break;
			case 0x49434e23: // ICN# 32x32x1
				d->mkpos_32_32_1 = pg->image_pos + 32*32/8;
				break;
			case 0x69636823: // ich# 48x48x1
				d->mkpos_48_48_1 = pg->image_pos + 48*48/8;
				break;
			case 0x73386d6b: // s8mk 16x16x8
				d->mkpos_16_16_8 = pg->image_pos;
				break;
			case 0x6c386d6b: // l8mk 32x32x8
				d->mkpos_32_32_8 = pg->image_pos;
				break;
			case 0x68386d6b: // h8mk 48x48x8
				d->mkpos_48_48_8 = pg->image_pos;
				break;
			case 0x74386d6b: // t8mk 128x128x8
				d->mkpos_128_128_8 = pg->image_pos;
				break;
			}
		}
		else if(pass==2) {
			de_dbg_indent(c, 1);
			do_icon(c, d, pg);
			de_dbg_indent(c, -1);
		}

		image_count++;
		segment_pos += segment_len;
	}

	if(pg) de_free(c, pg);
}

static void de_run_icns(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->file_size = de_getui32be(4);
	de_dbg(c, "reported file size: %d", (int)d->file_size);
	if(d->file_size > c->infile->len) d->file_size = c->infile->len;

	de_dbg(c, "pass 1: recording mask locations");
	de_run_icns_pass(c, d, 1);
	de_dbg(c, "pass 2: decoding/extracting icons");
	de_run_icns_pass(c, d, 2);

	de_free(c, d);
}

static int de_identify_icns(deark *c)
{
	de_int64 fsize;

	if(dbuf_memcmp(c->infile, 0, "icns", 4)) return 0;

	fsize = de_getui32be(4);
	if(fsize == c->infile->len) return 100;
	return 20;
}

void de_module_icns(deark *c, struct deark_module_info *mi)
{
	mi->id = "icns";
	mi->desc = "Macintosh icon";
	mi->run_fn = de_run_icns;
	mi->identify_fn = de_identify_icns;
}
