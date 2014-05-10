// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// psionpic module

#include <deark-config.h>
#include <deark-modules.h>

struct plane_info_struct {
	de_int64 width, height;
	de_int64 image_pos; // absolute position in file
	de_int64 rowspan;
};

typedef struct localctx_struct {
	de_int64 num_planes;
	int bw;
	struct plane_info_struct *plane_info; // Array of plane_info_structs
} lctx;

static void do_read_plane_info(deark *c, lctx *d, struct plane_info_struct *pi, de_int64 pos)
{
	de_int64 image_relative_pos;
	de_int64 image_size_in_bytes;

	de_memset(pi, 0, sizeof(struct plane_info_struct));
	pi->width = de_getui16le(pos+2);
	pi->height = de_getui16le(pos+4);
	image_size_in_bytes = de_getui16le(pos+6);
	image_relative_pos = de_getui32le(pos+8);
	pi->image_pos = pos + 12 + image_relative_pos;
	pi->rowspan = ((pi->width+15)/16)*2; // 2-byte alignment

	de_dbg(c, "bitmap: descriptor at %d, image at %d (size %d)\n",
		(int)pos, (int)pi->image_pos, (int)image_size_in_bytes);
	de_dbg(c, "dimensions: %dx%d\n", (int)pi->width,
		(int)pi->height);
}

static void do_bitmap_1plane(deark *c, lctx *d, de_int64 plane_num)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n;
	struct plane_info_struct *pi = &d->plane_info[plane_num];

	de_dbg(c, "making a bilevel image from plane %d\n", (int)plane_num);

	img = de_bitmap_create(c, pi->width, pi->height, 1);

	for(j=0; j<pi->height; j++) {
		for(i=0; i<pi->width; i++) {
			n = de_getbyte(pi->image_pos + j*pi->rowspan + i/8);
			n = (n>>(i%8))&0x1; // least-significant bit is leftmost
			de_bitmap_setpixel_gray(img, i, j, n ? 0 : 255);
		}
	}
	de_bitmap_write_to_file(img, NULL);

	de_bitmap_destroy(img);
}

static void do_bitmap_2planes(deark *c, lctx *d, de_int64 pn1, de_int64 pn2)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n0, n1;

	de_dbg(c, "making a grayscale image from planes %d and %d\n", (int)pn1, (int)pn2);

	img = de_bitmap_create(c, d->plane_info[pn1].width, d->plane_info[pn1].height, 1);

	for(j=0; j<d->plane_info[pn1].height; j++) {
		for(i=0; i<d->plane_info[pn1].width; i++) {
			n0 = de_getbyte(d->plane_info[pn1].image_pos + j*d->plane_info[pn1].rowspan + i/8);
			n0 = (n0>>(i%8))&0x1;
			n1 = de_getbyte(d->plane_info[pn2].image_pos + j*d->plane_info[pn2].rowspan + i/8);
			n1 = (n1>>(i%8))&0x1;
			de_bitmap_setpixel_gray(img, i, j, (3-(n0*2+n1))*85);
		}
	}
	de_bitmap_write_to_file(img, NULL);

	de_bitmap_destroy(img);
}

static int could_be_2bit(lctx *d, int startpos)
{
	de_int64 i;
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

static void de_run_psionpic(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 i;
	int format;
	const char *s;

	de_dbg(c, "In psionpic module\n");
	d = de_malloc(c, sizeof(lctx));

	s = de_get_option(c, "psionpic:bw");
	if(s) {
		d->bw = 1;
	}

	d->num_planes = de_getui16le(6);
	de_dbg(c, "number of planes/bitmaps: %d\n", (int)d->num_planes);

	// After the 8-byte header are [num_images] 12-byte bitmap descriptors.
	d->plane_info = de_malloc(c, d->num_planes * sizeof(struct plane_info_struct));
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
	de_byte b[6];
	de_read(b, 0, 6);
	if(!de_memcmp(b, "PIC\xdc\x30\x30", 6))
		return 100;
	return 0;
}

void de_module_psionpic(deark *c, struct deark_module_info *mi)
{
	mi->id = "psionpic";
	mi->run_fn = de_run_psionpic;
	mi->identify_fn = de_identify_psionpic;
}
