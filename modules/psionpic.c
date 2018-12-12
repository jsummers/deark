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
	i64 rowspan;
};

typedef struct localctx_struct {
	i64 num_planes;
	int bw;
	struct plane_info_struct *plane_info; // Array of plane_info_structs
} lctx;

static void do_read_plane_info(deark *c, lctx *d, struct plane_info_struct *pi, i64 pos)
{
	i64 image_relative_pos;
	i64 image_size_in_bytes;

	de_zeromem(pi, sizeof(struct plane_info_struct));
	pi->width = de_getu16le(pos+2);
	pi->height = de_getu16le(pos+4);
	image_size_in_bytes = de_getu16le(pos+6);
	image_relative_pos = de_getu32le(pos+8);
	pi->image_pos = pos + 12 + image_relative_pos;
	pi->rowspan = ((pi->width+15)/16)*2; // 2-byte alignment

	de_dbg(c, "bitmap: descriptor at %d, image at %d (size %d)",
		(int)pos, (int)pi->image_pos, (int)image_size_in_bytes);
	de_dbg_dimensions(c, pi->width, pi->height);
}

static void do_bitmap_1plane(deark *c, lctx *d, i64 plane_num)
{
	struct plane_info_struct *pi = &d->plane_info[plane_num];

	de_dbg(c, "making a bilevel image from plane %d", (int)plane_num);

	de_convert_and_write_image_bilevel(c->infile, pi->image_pos, pi->width, pi->height,
		pi->rowspan, DE_CVTF_WHITEISZERO|DE_CVTF_LSBFIRST, NULL, 0);
}

static void do_bitmap_2planes(deark *c, lctx *d, i64 pn1, i64 pn2)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 n0, n1;

	de_dbg(c, "making a grayscale image from planes %d and %d", (int)pn1, (int)pn2);

	img = de_bitmap_create(c, d->plane_info[pn1].width, d->plane_info[pn1].height, 1);

	for(j=0; j<d->plane_info[pn1].height; j++) {
		for(i=0; i<d->plane_info[pn1].width; i++) {
			n0 = de_get_bits_symbol_lsb(c->infile, 1, d->plane_info[pn1].image_pos + j*d->plane_info[pn1].rowspan, i);
			n1 = de_get_bits_symbol_lsb(c->infile, 1, d->plane_info[pn2].image_pos + j*d->plane_info[pn2].rowspan, i);
			de_bitmap_setpixel_gray(img, i, j, (3-(n0*2+n1))*85);
		}
	}
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
