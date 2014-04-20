// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// psionpic module

#include <deark-config.h>
#include <deark-modules.h>

#define MAX_PLANES 2

struct plane_info_struct {
	de_int64 width, height;
	de_int64 image_pos; // absolute position in file
	de_int64 rowspan;
};

typedef struct localctx_struct {
	de_int64 num_planes;
	struct plane_info_struct plane_info[MAX_PLANES];
} lctx;

static void do_read_plane_info(deark *c, lctx *d, de_int64 plane, de_int64 pos)
{
	de_int64 image_relative_pos;
	de_int64 image_size_in_bytes;
	struct plane_info_struct *pi = &d->plane_info[plane];

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

static void do_bitmap_1plane(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n;
	struct plane_info_struct *pi = &d->plane_info[0];

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

static void do_bitmap_2planes(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n0, n1;

	img = de_bitmap_create(c, d->plane_info[0].width, d->plane_info[0].height, 1);

	for(j=0; j<d->plane_info[0].height; j++) {
		for(i=0; i<d->plane_info[0].width; i++) {
			n0 = de_getbyte(d->plane_info[0].image_pos + j*d->plane_info[0].rowspan + i/8);
			n0 = (n0>>(i%8))&0x1;
			n1 = de_getbyte(d->plane_info[1].image_pos + j*d->plane_info[1].rowspan + i/8);
			n1 = (n1>>(i%8))&0x1;
			de_bitmap_setpixel_gray(img, i, j, (3-(n0*2+n1))*85);
		}
	}
	de_bitmap_write_to_file(img, NULL);

	de_bitmap_destroy(img);
}

static void de_run_psionpic(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 i;

	de_dbg(c, "In psionpic module\n");
	d = de_malloc(c, sizeof(lctx));

	d->num_planes = de_getui16le(6);
	de_dbg(c, "number of planes/bitmaps: %d\n", (int)d->num_planes);
	if(d->num_planes<1 || d->num_planes>MAX_PLANES) {
		de_err(c, "Don't know how to handle files with %d planes/bitmaps\n", (int)d->num_planes);
		goto done;
	}

	// The PIC format seems like it was intended to store an arbitrary
	// number of bilevel images, but i've only seen two types of files:
	// * Files with a single bilevel image
	// * Files with two bilevel images of the same size, that are obviously
	//   intended to be interpreted as planes of a 2-bit grayscale image.
	// For now, those are the only two types of files supported.

	// After the 8-byte header are [num_images] 12-byte bitmap descriptors.
	for(i=0; i<d->num_planes; i++) {
		do_read_plane_info(c, d, i, 8+12*i);
	}

	switch(d->num_planes) {
	case 1:
		do_bitmap_1plane(c, d);
		break;
	case 2:
		do_bitmap_2planes(c, d);
		break;
	}

done:
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
