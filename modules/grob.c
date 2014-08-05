// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int w, h;
} lctx;


static void grob_read_bitmap(deark *c, lctx *d, de_int64 pos)
{
	de_int64 j;
	de_int64 src_rowspan;
	struct deark_bitmap *img = NULL;

	if(!de_good_image_dimensions(c, d->w, d->h))
		return;

	img = de_bitmap_create(c, d->w, d->h, 1);
	src_rowspan = (d->w+7)/8;

	for(j=0; j<d->h; j++) {
		de_convert_row_bilevel(c->infile, pos+j*src_rowspan, img, j,
			DE_CVTR_WHITEISZERO|DE_CVTR_LSBFIRST);
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void de_run_grob(deark *c, const char *params)
{
	lctx *d = NULL;
	de_byte hdr[18];

	de_dbg(c, "In grob module\n");

	d = de_malloc(c, sizeof(lctx));

	de_read(hdr, 0, 18);

	// Height and Width are 20-bit integers, 2.5 bytes each.
	d->h = (hdr[15]&0x0f)<<16 | hdr[14]<<8 | hdr[13];
	d->w = hdr[17]<<12 | hdr[16]<<4 | hdr[15]>>4;
	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	grob_read_bitmap(c, d, 18);

	de_free(c, d);
}

static int de_identify_grob(deark *c)
{
	de_byte buf[10];
	de_read(buf, 0, 10);

	if(buf[0]=='H' && buf[1]=='P' && buf[2]=='H' && buf[3]=='P' &&
		buf[4]=='4' && (buf[5]=='8' || buf[5]=='9') &&
		buf[8]==0x1e && buf[9]==0x2b) {
			return 100;
	}
	return 0;
}

void de_module_grob(deark *c, struct deark_module_info *mi)
{
	mi->id = "grob";
	mi->run_fn = de_run_grob;
	mi->identify_fn = de_identify_grob;
}
