// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Psion PIC

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_psionpic);

struct plane_info_struct {
	i64 width, height;
	i64 image_pos; // absolute position in file
	i64 image_size_in_bytes;
	i64 rowspan;
	u32 crc_reported;
};

typedef struct localctx_struct {
	i64 num_planes;
	int bw;
	struct plane_info_struct *plane_info; // Array of plane_info_structs
	struct de_crcobj *crco;
} lctx;

static void check_crc(deark *c, lctx *d, struct plane_info_struct *pi)
{
	u32 crc_calc;

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, pi->image_pos, pi->image_size_in_bytes);
	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calc);
	if(crc_calc != pi->crc_reported) {
		de_warn(c, "CRC check failed: Expected 0x%04x, got 0x%04x",
			(UI)pi->crc_reported, (UI)crc_calc);
	}
}

static void do_read_plane_info(deark *c, lctx *d, struct plane_info_struct *pi, i64 pos1)
{
	i64 image_relative_pos;
	i64 pos = pos1;

	de_zeromem(pi, sizeof(struct plane_info_struct));
	pi->crc_reported = (u32)de_getu16le_p(&pos);
	pi->width = de_getu16le_p(&pos);
	pi->height = de_getu16le_p(&pos);
	pi->image_size_in_bytes = de_getu16le_p(&pos);
	image_relative_pos = de_getu32le_p(&pos);

	pi->image_pos = pos1 + 12 + image_relative_pos;
	pi->rowspan = ((pi->width+15)/16)*2; // 2-byte alignment

	de_dbg(c, "bitmap descriptor at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_dbg(c, "image pos: %"I64_FMT, pi->image_pos);
	de_dbg(c, "image len: %"I64_FMT, pi->image_size_in_bytes);
	de_dbg_dimensions(c, pi->width, pi->height);
	de_dbg(c, "crc (reported): 0x%04x", (UI)pi->crc_reported);
	check_crc(c, d, pi);
	de_dbg_indent(c, -1);
}

static void do_bitmap_1plane(deark *c, lctx *d, i64 plane_num)
{
	struct plane_info_struct *pi = &d->plane_info[plane_num];

	de_dbg(c, "making a bilevel image from plane %d", (int)plane_num);

	de_convert_and_write_image_bilevel2(c->infile, pi->image_pos, pi->width, pi->height,
		pi->rowspan, DE_CVTF_WHITEISZERO|DE_CVTF_LSBFIRST, NULL, 0);
}

static void do_bitmap_2planes(deark *c, lctx *d, i64 pn1, i64 pn2)
{
	de_bitmap *img = NULL;
	i64 planespan;
	// AFAIK, all relevant devices support only 3 colors. Two of the four codes
	// map to black. We'll make the two blacks slightly different, just to avoid
	// losing information.
	static const de_color pal[4] = { 0xffffffff, 0xff808080U, 0xff010101U, 0xff000000U };

	de_dbg(c, "making a grayscale image from planes %d and %d", (int)pn1, (int)pn2);

	// TODO: Support -padpix (need samples with width not a multiple of 16)
	img = de_bitmap_create(c, d->plane_info[pn1].width, d->plane_info[pn1].height, 1);

	planespan = d->plane_info[1].image_pos - d->plane_info[0].image_pos;
	de_convert_image_paletted_planar(c->infile, d->plane_info[0].image_pos, 2,
		d->plane_info[0].rowspan, planespan, pal, img, 0x1);
	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
}

static int could_be_2bit(lctx *d, int startpos)
{
	i64 i;
	if( (d->num_planes - startpos)%2 != 0) {
		// Not an even number of bitmaps.
		return 0;
	}
	for(i=startpos; i<d->num_planes; i+=2) {
		if(d->plane_info[i].width!=d->plane_info[i+1].width ||
			d->plane_info[i].height!=d->plane_info[i+1].height)
		{
			// Bitmaps aren't the same size.
			return 0;
		}
	}
	return 1;
}

#define PPIC_FMT_1_1  1
#define PPIC_FMT_1_2  2
#define PPIC_FMT_2_2  3

// This detection logic is just a wild guess. Copy it at your own risk.
static int detect_format(deark *c, lctx *d)
{
	if(d->bw)
		return PPIC_FMT_1_1;

	if(d->num_planes>=3 &&
		d->plane_info[0].width==24 && d->plane_info[0].height==24 &&
		d->plane_info[1].width==48 && d->plane_info[1].height==48 &&
		could_be_2bit(d, 1))
	{
		return PPIC_FMT_1_2;
	}

	if(d->num_planes>=1 &&
		d->plane_info[0].width==24 && d->plane_info[0].height==24)
	{
		return PPIC_FMT_1_1;
	}

	if(d->num_planes>=2 && could_be_2bit(d, 0)) {
		return PPIC_FMT_2_2;
	}

	return PPIC_FMT_1_1;
}

static void de_run_psionpic(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 i;
	int format;
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	s = de_get_ext_option(c, "psionpic:bw");
	if(s) {
		d->bw = 1;
	}

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);

	d->num_planes = de_getu16le(6);
	de_dbg(c, "number of planes/bitmaps: %d", (int)d->num_planes);

	// After the 8-byte header are [num_images] 12-byte bitmap descriptors.
	d->plane_info = de_mallocarray(c, d->num_planes, sizeof(struct plane_info_struct));
	for(i=0; i<d->num_planes; i++) {
		do_read_plane_info(c, d, &d->plane_info[i], 8+12*i);
	}

	// The PIC format seems like it was intended to store an arbitrary
	// number of bilevel images, but some of them are clearly planes that
	// are intended to be combined to form an image. I don't know for sure
	// how I'm supposed to do that.

	format = detect_format(c, d);

	switch(format) {
	case PPIC_FMT_2_2:
		for(i=0; i+1<d->num_planes; i+=2) {
			do_bitmap_2planes(c, d, i, i+1);
		}
		break;
	case PPIC_FMT_1_2:
		do_bitmap_1plane(c, d, 0);
		for(i=1; i+1<d->num_planes; i+=2) {
			do_bitmap_2planes(c, d, i, i+1);
		}
		break;
	default:
		for(i=0; i<d->num_planes; i++) {
			do_bitmap_1plane(c, d, i);
		}
	}

	de_crcobj_destroy(d->crco);
	de_free(c, d->plane_info);
	de_free(c, d);
}

static int de_identify_psionpic(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PIC\xdc\x30\x30", 6))
		return 100;
	return 0;
}

static void de_help_psionpic(deark *c)
{
	de_msg(c, "-opt psionpic:bw : Do not try to detect grayscale images");
}

void de_module_psionpic(deark *c, struct deark_module_info *mi)
{
	mi->id = "psionpic";
	mi->desc = "Psion PIC, a.k.a. EPOC PIC";
	mi->run_fn = de_run_psionpic;
	mi->identify_fn = de_identify_psionpic;
	mi->help_fn = de_help_psionpic;
}
