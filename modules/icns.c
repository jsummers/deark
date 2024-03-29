// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// icns - Apple Icon Image format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_icns);

static const de_color g_stdpal16[16] = {
	0xffffffffU,0xfffcf305U,0xffff6402U,0xffdd0806U,0xfff20884U,0xff4600a5U,0xff0000d4U,0xff02abeaU,
	0xff1fb714U,0xff006411U,0xff562c05U,0xff90713aU,0xffc0c0c0U,0xff808080U,0xff404040U,0xff000000U
};

#define IMGTYPE_EMBEDDED_FILE   1 // JP2 or PNG
#define IMGTYPE_MASK            2
#define IMGTYPE_IMAGE           3
#define IMGTYPE_IMAGE_AND_MASK  4
#define IMGTYPE_ARGB_ETC        5 // ARGB or JP2 or PNG

enum content_enum {
	CONTENT_UNSET=0,
	CONTENT_UNKNOWN,
	CONTENT_PNG,
	CONTENT_JP2,
	CONTENT_J2C,
	CONTENT_ARGB
};

struct image_type_info {
	u32 code;
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
	{ 0x73623234, 24,   24,   0,  IMGTYPE_EMBEDDED_FILE }, // sb24
	{ 0x69637342, 36,   36,   0,  IMGTYPE_EMBEDDED_FILE }, // icsB
	{ 0x53423234, 48,   48,   0,  IMGTYPE_EMBEDDED_FILE }, // SB24

	{ 0x69633034, 16,   16,   0,  IMGTYPE_ARGB_ETC }, // ic04
	{ 0x69633035, 32,   32,   0,  IMGTYPE_ARGB_ETC }, // ic05
	{ 0x69637362, 18,   18,   0,  IMGTYPE_ARGB_ETC }, // icsb

	{ 0x544f4320, 0,    0,    0,  0 }, // 'TOC '
	{ 0x69636e56, 0,    0,    0,  0 }  // icnV
};

struct mask_wrapper {
	i64 segment_pos;
	u8 used_flag;
	de_bitmap *img;
};

struct page_ctx {
	int image_num;
	i64 segment_pos;
	i64 image_pos;
	i64 image_len;
	struct mask_wrapper *mask_ref; // (pointer to a d->mask field; do not free)
	i64 rowspan;
	const struct image_type_info *type_info;
	struct de_fourcc code4cc;
	enum content_enum content_type; // Used when code4cc is insufficient
	char filename_token[32];
	de_color pal[256];
};

#define MASKTYPEID_16_12_1    0
#define MASKTYPEID_16_16_1    1
#define MASKTYPEID_32_32_1    2
#define MASKTYPEID_48_48_1    3
#define MASKTYPEID_16_16_8    4
#define MASKTYPEID_32_32_8    5
#define MASKTYPEID_48_48_8    6
#define MASKTYPEID_128_128_8  7
#define NUM_MASKTYPES 8

typedef struct localctx_struct {
	i64 file_size;
	u8 opt_mask1;
	u8 opt_mask8;
	u8 opt_mask24;
	struct mask_wrapper mask[NUM_MASKTYPES];
	u8 have_stdpal256;
	de_color stdpal256[256];
} lctx;

static const de_color supplpal256[41] = {
	0xffee0000U,0xffdd0000U,0xffbb0000U,0xffaa0000U,0xff880000U,
	0xff770000U,0xff550000U,0xff440000U,0xff220000U,0xff110000U,
	0xff00ee00U,0xff00dd00U,0xff00bb00U,0xff00aa00U,0xff008800U,
	0xff007700U,0xff005500U,0xff004400U,0xff002200U,0xff001100U,
	0xff0000eeU,0xff0000ddU,0xff0000bbU,0xff0000aaU,0xff000088U,
	0xff000077U,0xff000055U,0xff000044U,0xff000022U,0xff000011U,
	0xffeeeeeeU,0xffddddddU,0xffbbbbbbU,0xffaaaaaaU,0xff888888U,
	0xff777777U,0xff555555U,0xff444444U,0xff222222U,0xff111111U,0xff000000U
};

static de_color getpal256(int k)
{
	u8 r, g, b;

	if(k<0 || k>255) return 0;
	if(k<=214) {
		// The first 215 palette entries follow a simple pattern.
		r = (u8)((5-k/36)*0x33);
		g = (5-(k%36)/6)*0x33;
		b = (5-k%6)*0x33;
		return DE_MAKE_RGB(r,g,b);
	}

	return supplpal256[k-215];
}

static void populate_stdpal256(lctx *d)
{
	int k;

	if(d->have_stdpal256) return;
	d->have_stdpal256 = 1;

	for(k=0; k<256; k++) {
		d->stdpal256[k] = getpal256(k);
	}
}

static void do_decode_1_4_8bit(deark *c, lctx *d, struct page_ctx *pg)
{
	de_bitmap *img = NULL;
	int bypp;

	bypp = (pg->type_info->bpp==1)?2:4;
	img = de_bitmap_create(c, pg->type_info->width, pg->type_info->height, bypp);

	if(pg->type_info->bpp==8) {
		populate_stdpal256(d);
		de_memcpy(pg->pal, d->stdpal256, sizeof(d->stdpal256));
	}
	else if(pg->type_info->bpp==4) {
		de_memcpy(pg->pal, g_stdpal16, sizeof(g_stdpal16));
	}
	else { // 1
		pg->pal[0] = DE_STOCKCOLOR_WHITE;
		pg->pal[1] = DE_STOCKCOLOR_BLACK;
	}

	de_convert_image_paletted(c->infile, pg->image_pos, pg->type_info->bpp, pg->rowspan,
		pg->pal, img, 0);

	if(pg->mask_ref && pg->mask_ref->img) {
		de_bitmap_apply_mask(img, pg->mask_ref->img, 0);
	}

	de_bitmap_write_to_file(img, pg->filename_token, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void do_uncompress_24(deark *c, lctx *d, struct page_ctx *pg, dbuf *unc_pixels,
	i64 skip)
{
	i64 pos;
	u8 b;
	i64 count;
	u8 n;

	pos = pg->image_pos;
	if(skip) pos+=4;

	while(1) {
		if(pos >= pg->image_pos + pg->image_len) break;

		b = de_getbyte(pos);
		pos++;
		if(b>=128) {
			// Compressed run
			count = (i64)b - 125;
			n = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, n, count);
		}
		else {
			// An uncompressed run
			count = 1 + (i64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}
}

static void read_image_plane(deark *c, lctx *d,
	dbuf *unc_pixels, i64 plane, de_bitmap *img, i64 samplenum)
{
	i64 i, j;
	i64 w, h;

	w = img->width;
	h = img->height;

	for(j=0; j<h; j++) {
		for(i=0; i<w; i++) {
			u8 v;

			v = dbuf_getbyte(unc_pixels, (plane*h+j)*w + i);
			de_bitmap_setsample(img, i, j, samplenum, v);
		}
	}
}

static void do_decode_24bit(deark *c, lctx *d, struct page_ctx *pg)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	i64 w, h;
	i64 skip;

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

	de_bitmap_rect(img, 0, 0, w, h, DE_STOCKCOLOR_BLACK, 0);
	read_image_plane(c, d, unc_pixels, 0, img, 0);
	read_image_plane(c, d, unc_pixels, 1, img, 1);
	read_image_plane(c, d, unc_pixels, 2, img, 2);

	if(pg->mask_ref && pg->mask_ref->img) {
		de_bitmap_apply_mask(img, pg->mask_ref->img, 0);
	}

	de_bitmap_write_to_file(img, pg->filename_token, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
	if(unc_pixels) dbuf_close(unc_pixels);
}

// Sets pg->content_type
static void identify_content(deark *c, lctx *d, struct page_ctx *pg)
{
	u8 buf[8];

	if(pg->content_type!=CONTENT_UNSET) return;

	// Read the first few bytes
	de_read(buf, pg->image_pos, sizeof(buf));

	if(buf[4]=='j' && buf[5]=='P') {
		pg->content_type = CONTENT_JP2;
	}
	else if(buf[0]==0xff && buf[1]==0x4f && buf[2]==0xff && buf[3]==0x51) {
		pg->content_type = CONTENT_J2C;
	}
	else if(buf[0]==0x89 && buf[1]==0x50) {
		pg->content_type = CONTENT_PNG;
	}
	else if(buf[0]=='A' && buf[1]=='R' && buf[2]=='G' && buf[3]=='B') {
		pg->content_type = CONTENT_ARGB;
	}
	else {
		pg->content_type = CONTENT_UNKNOWN;
	}
}

// Call this only after the PNG or JP2 format has been identified.
static void do_extract_png_or_jp2(deark *c, lctx *d, struct page_ctx *pg)
{
	de_finfo *fi = NULL;
	const char *ext;

	if(pg->content_type==CONTENT_JP2) {
		ext = "jp2";
	}
	else if(pg->content_type==CONTENT_J2C) {
		ext = "j2c";
	}
	else if(pg->content_type==CONTENT_PNG) {
		ext = "png";
	}
	else {
		goto done;
	}

	fi = de_finfo_create(c);

	de_snprintf(pg->filename_token, sizeof(pg->filename_token), "%dx%d",
		(int)pg->type_info->width, (int)pg->type_info->height);
	de_finfo_set_name_from_sz(c, fi, pg->filename_token, 0, DE_ENCODING_ASCII);

	dbuf_create_file_from_slice(c->infile, pg->image_pos, pg->image_len, ext, fi, 0);

done:
	de_finfo_destroy(c, fi);
}

static void do_argb(deark *c, lctx *d, struct page_ctx *pg)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	i64 w, h;

	w = pg->type_info->width;
	h = pg->type_info->height;

	unc_pixels = dbuf_create_membuf(c, w*h*4, 1);
	do_uncompress_24(c, d, pg, unc_pixels, 4);

	img = de_bitmap_create(c, w, h, 4);

	read_image_plane(c, d, unc_pixels, 0, img, 3);
	read_image_plane(c, d, unc_pixels, 1, img, 0);
	read_image_plane(c, d, unc_pixels, 2, img, 1);
	read_image_plane(c, d, unc_pixels, 3, img, 2);

	de_snprintf(pg->filename_token, sizeof(pg->filename_token), "%dx%dx32",
		(int)w, (int)h);

	de_bitmap_write_to_file(img, pg->filename_token, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
	if(unc_pixels) dbuf_close(unc_pixels);
}

static void do_argb_png_or_jp2(deark *c, lctx *d, struct page_ctx *pg)
{
	identify_content(c, d, pg);

	if(pg->type_info->image_type==IMGTYPE_ARGB_ETC && pg->content_type==CONTENT_ARGB) {
		do_argb(c, d, pg);
		return;
	}

	de_dbg(c, "Trying to extract file at %"I64_FMT, pg->image_pos);

	if(pg->content_type==CONTENT_JP2 || pg->content_type==CONTENT_J2C ||
		pg->content_type==CONTENT_PNG)
	{
		do_extract_png_or_jp2(c, d, pg);
		return;
	}

	de_err(c, "(Image #%d) Unidentified file format", pg->image_num);
}

// Assumes image_type is IMAGE or IMAGE_AND_MASK.
static struct mask_wrapper *find_mask(deark *c, lctx *d, struct page_ctx *pg)
{
	struct mask_wrapper *mw = NULL;
	struct mask_wrapper *mw1 = NULL;
	struct mask_wrapper *mw8 = NULL;
	const struct image_type_info *t;
	int found_mask = 0;
	u8 opt;

	t = pg->type_info;

	// TODO: What is the correct way to match masks to images?

	if(t->code==0x49434f4e) { // 'ICON'
		// I'm assuming this format doesn't have a mask.
		return NULL;
	}

	if(t->width==16 && t->height==12 && t->bpp<=8) {
		mw1 = &d->mask[MASKTYPEID_16_12_1];
		goto afterdiscovery;
	}
	if(t->width==16 && t->height==16) {
		mw1 = &d->mask[MASKTYPEID_16_16_1];
		mw8 = &d->mask[MASKTYPEID_16_16_8];
		goto afterdiscovery;
	}
	if(t->width==32) {
		mw1 = &d->mask[MASKTYPEID_32_32_1];
		mw8 = &d->mask[MASKTYPEID_32_32_8];
		goto afterdiscovery;
	}
	if(t->width==48) {
		mw1 = &d->mask[MASKTYPEID_48_48_1];
		mw8 = &d->mask[MASKTYPEID_48_48_8];
		goto afterdiscovery;
	}
	if(t->width==128) {
		mw8 = &d->mask[MASKTYPEID_128_128_8];
		goto afterdiscovery;
	}

afterdiscovery:
	if(t->bpp==1) {
		opt = d->opt_mask1;
	}
	else if(t->bpp<=8) {
		opt = d->opt_mask8;
	}
	else {
		opt = d->opt_mask24;
	}

	if(opt==1) {
		mw = mw1;
	}
	else if(opt==8) {
		mw = mw8;
	}
	else if(opt==18) {
		if(mw1 && mw1->img) mw = mw1;
		else mw = mw8;
	}
	else if(opt==81) {
		if(mw8 && mw8->img) mw = mw8;
		else mw = mw1;
	}

	found_mask = (mw && mw->img);
	if(!found_mask) goto notfound;

	if(t->image_type==IMGTYPE_IMAGE_AND_MASK && mw==mw1) {
		// Sanity check. This could fail if there are multiple icons of
		// the same type.
		if(pg->segment_pos != mw->segment_pos) {
			goto notfound;
		}
	}

	mw->used_flag = 1;
	de_dbg(c, "[using mask at %"I64_FMT"]", mw->segment_pos);
	return mw;

notfound:
	de_dbg(c, "[no mask found for icon at %"I64_FMT"]", pg->segment_pos);
	return NULL;
}

static void convert_image_gray8(dbuf *f, i64 fpos, i64 rowspan, de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			u8 n;

			n = dbuf_getbyte(f, fpos+j*rowspan+i);
			de_bitmap_setpixel_gray(img, i, j, n);
		}
	}
}

static void do_read_mask(deark *c, lctx *d, struct page_ctx *pg, int masktype_id,
	int depth, i64 w, i64 h)
{
	de_bitmap *img;
	i64 rowspan;
	i64 mask_offset;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(depth==1) {
		rowspan = (w+7)/8;
		mask_offset = rowspan*h;
	}
	else {
		rowspan = w;
		mask_offset = 0;
	}

	de_dbg(c, "mask(%d"DE_CHAR_TIMES"%d,%d) segment at %"I64_FMT", mask at %"I64_FMT"+%"I64_FMT,
		(int)w, (int)h, depth, pg->segment_pos, pg->image_pos, mask_offset);
	de_dbg_indent(c, 1);

	if(d->mask[masktype_id].img) {
		de_dbg(c, "duplicate mask type %u", (UI)masktype_id);
		de_bitmap_destroy(d->mask[masktype_id].img);
	}
	d->mask[masktype_id].img = de_bitmap_create(c, w, h, 1);
	d->mask[masktype_id].segment_pos = pg->segment_pos;
	img = d->mask[masktype_id].img;

	if(depth==1) {
		de_convert_image_bilevel(c->infile, pg->image_pos+mask_offset, rowspan, img, 0);
	}
	else {
		convert_image_gray8(c->infile, pg->image_pos+mask_offset, rowspan, img);
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_icon(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 expected_image_size;
	int is_compressed;

	if(!pg->type_info) return; // Shouldn't happen.

	de_strlcpy(pg->filename_token, "", sizeof(pg->filename_token));

	if(pg->type_info->image_type==IMGTYPE_MASK) {
		de_dbg(c, "[transparency mask]");
		return;
	}

	if(pg->type_info->image_type==IMGTYPE_EMBEDDED_FILE ||
		pg->type_info->image_type==IMGTYPE_ARGB_ETC)
	{
		do_argb_png_or_jp2(c, d, pg);
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

	pg->mask_ref = find_mask(c, d, pg);

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
	i64 segment_pos;
	struct page_ctx *pg = NULL;
	int image_count;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	segment_pos = 8;
	image_count = 0;

	while(1) {
		i64 segment_len;

		if(pg) { de_free(c, pg); pg=NULL; }

		if(segment_pos+8 > d->file_size) break;

		pg = de_malloc(c, sizeof(struct page_ctx));
		pg->segment_pos = segment_pos;
		pg->image_num = image_count;

		dbuf_read_fourcc(c->infile, segment_pos, &pg->code4cc, 4, 0x0);

		segment_len = de_getu32be(segment_pos+4);

		pg->image_pos = segment_pos + 8;
		pg->image_len = segment_len - 8;

		if(pass==2) {
			de_dbg(c, "image #%d, type '%s', segment at %"I64_FMT", image at %"I64_FMT", size=%"I64_FMT,
				pg->image_num, pg->code4cc.id_dbgstr,
				pg->segment_pos, pg->image_pos, pg->image_len);
		}
		de_dbg_indent(c, 1);

		if(segment_len<8 || segment_pos+segment_len > d->file_size) {
			if(pass==2) {
				de_err(c, "Invalid length for segment '%s' (%u)", pg->code4cc.id_sanitized_sz,
					(unsigned int)segment_len);
			}
			break;
		}

		if(segment_len==8) {
			if(pass==2) {
				de_dbg(c, "[empty icon]");
			}
			goto next_icon;
		}

		if(pass==2) {
			size_t i;

			// Find this type code in the image_type_info array
			pg->type_info = NULL;
			for(i=0; i<DE_ARRAYCOUNT(image_type_info_arr); i++) {
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
			de_dbg_indent(c, -1);
			switch(pg->code4cc.id) {
			case 0x69636d23: // icm# 16x12x1
				do_read_mask(c, d, pg, MASKTYPEID_16_12_1, 1, 16, 12);
				break;
			case 0x69637323: // ics# 16x16x1
				do_read_mask(c, d, pg, MASKTYPEID_16_16_1, 1, 16, 16);
				break;
			case 0x49434e23: // ICN# 32x32x1
				do_read_mask(c, d, pg, MASKTYPEID_32_32_1, 1, 32, 32);
				break;
			case 0x69636823: // ich# 48x48x1
				do_read_mask(c, d, pg, MASKTYPEID_48_48_1, 1, 48, 48);
				break;
			case 0x73386d6b: // s8mk 16x16x8
				do_read_mask(c, d, pg, MASKTYPEID_16_16_8, 8, 16, 16);
				break;
			case 0x6c386d6b: // l8mk 32x32x8
				do_read_mask(c, d, pg, MASKTYPEID_32_32_8, 8, 32, 32);
				break;
			case 0x68386d6b: // h8mk 48x48x8
				do_read_mask(c, d, pg, MASKTYPEID_48_48_8, 8, 48, 48);
				break;
			case 0x74386d6b: // t8mk 128x128x8
				do_read_mask(c, d, pg, MASKTYPEID_128_128_8, 8, 128, 128);
				break;
			}
			de_dbg_indent(c, 1);
		}
		else if(pass==2) {
			do_icon(c, d, pg);
		}

next_icon:
		image_count++;
		segment_pos += segment_len;
		de_dbg_indent(c, -1);
	}

	if(pg) de_free(c, pg);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_icns(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	// (If these options are undocumented, it's because they're still in
	// development/testing.)
	// 81 = Use 8-bit mask if present, otherwise 1-bit mask
	// 18 = Use 1-bit mask if present, otherwise 8-bit mask
	// 8 = Use 8-bit mask only
	// 1 = Use 1-bit mask only
	// 0 = No transparency
	//
	// TODO: Maybe set opt_mask1 = 81
	d->opt_mask1 = 1; // Setting for (most) 1bpp icons
	d->opt_mask8 = 81; // Setting for 4 and 8bpp icons
	d->opt_mask24 = 81; // Setting for 24bpp icons
	s = de_get_ext_option(c, "icns:mask1");
	if(s) {
		d->opt_mask1 = (u8)de_atoi(s);
	}
	s = de_get_ext_option(c, "icns:mask8");
	if(s) {
		d->opt_mask8 = (u8)de_atoi(s);
	}
	s = de_get_ext_option(c, "icns:mask24");
	if(s) {
		d->opt_mask24 = (u8)de_atoi(s);
	}

	d->file_size = de_getu32be(4);
	de_dbg(c, "reported file size: %d", (int)d->file_size);
	if(d->file_size > c->infile->len) d->file_size = c->infile->len;

	de_dbg(c, "pass 1: reading masks");
	de_dbg_indent(c, 1);
	de_run_icns_pass(c, d, 1);
	de_dbg_indent(c, -1);
	de_dbg(c, "pass 2: decoding/extracting icons");
	de_dbg_indent(c, 1);
	de_run_icns_pass(c, d, 2);
	de_dbg_indent(c, -1);

	if(d) {
		int i;

		for(i=0; i<NUM_MASKTYPES; i++) {
			if(d->mask[i].img) {
				if(!d->mask[i].used_flag) {
					de_dbg(c, "[mask at %"I64_FMT" was not used]", d->mask[i].segment_pos);
				}
				de_bitmap_destroy(d->mask[i].img);
				d->mask[i].img = NULL;
			}
		}
		de_free(c, d);
	}
}

static int de_identify_icns(deark *c)
{
	i64 fsize;

	if(dbuf_memcmp(c->infile, 0, "icns", 4)) return 0;

	fsize = de_getu32be(4);
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
