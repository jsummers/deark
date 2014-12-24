// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Microsoft Paint

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int ver; // 1 or 2
	de_int64 width, height;
	dbuf *rowbuf;
} lctx;

static void do_ver1(deark *c, lctx *d)
{
	de_int64 src_rowspan;

	// TODO: Are version-1 MSP files padded this way?
	// (Maybe the width is always a multiple of 8, so it doesn't matter.)
	src_rowspan = (d->width+7)/8;

	de_convert_and_write_image_bilevel(c->infile, 32,
		d->width, d->height, src_rowspan, 0, NULL);
}

static void do_decompress_scanline(deark *c, lctx *d, struct deark_bitmap *img,
   de_int64 rownum, de_int64 rowoffset, de_int64 bytes_in_row)
{
	de_int64 i;
	de_byte runtype;
	de_int64 runcount;
	de_byte value;

	de_dbg2(c, "decompressing row %d\n", (int)rownum);

	if(!d->rowbuf) {
		d->rowbuf = dbuf_create_membuf(c, (d->width+7)/8);
		dbuf_set_max_length(d->rowbuf, (d->width+7)/8);
	}

	dbuf_empty(d->rowbuf);

	// Read the compressed data byte by byte
	i = 0;
	while(i<bytes_in_row) {
		runtype = de_getbyte(rowoffset+i);
		i++;
		if(runtype==0x00) {
			runcount = (de_int64)de_getbyte(rowoffset+i);
			i++;
			value = de_getbyte(rowoffset+i);
			i++;
			// write value runcount times
			de_dbg2(c, "compressed, %d bytes of %d\n", (int)runcount, value);
			dbuf_write_run(d->rowbuf, value, runcount);
		}
		else {
			runcount = (de_int64)runtype;
			de_dbg2(c, "%d bytes uncompressed\n", (int)runcount);
			dbuf_copy(c->infile, rowoffset+i, runcount, d->rowbuf);
			i+=runcount;
		}
	}

	de_convert_row_bilevel(d->rowbuf, 0, img, rownum, 0);
}

static void do_ver2(deark *c, lctx *d)
{
	de_int64 j;
	de_int64 *rowoffset;
	de_int64 *rowsize;
	struct deark_bitmap *img = NULL;

	rowoffset = de_malloc(c, d->height * sizeof(de_int64));
	rowsize = de_malloc(c, d->height * sizeof(de_int64));

	// Read the scanline map, and record the row sizes.
	for(j=0; j<d->height; j++) {
		rowsize[j] = de_getui16le(32+2*j);
	}

	// Calculate the position, in the file, of each row.
	for(j=0; j<d->height; j++) {
		if(j==0)
			rowoffset[j] = 32 + 2*d->height;
		else
			rowoffset[j] = rowoffset[j-1] + rowsize[j-1];
		de_dbg2(c, "row %d offset=%d size=%d\n", (int)j, (int)rowoffset[j], (int)rowsize[j]);
	}

	img = de_bitmap_create(c, d->width, d->height, 1);

	for(j=0; j<d->height; j++) {
		do_decompress_scanline(c, d, img, j, rowoffset[j], rowsize[j]);
	}

	de_bitmap_write_to_file(img, NULL);

	de_free(c, rowsize);
	de_free(c, rowoffset);
	dbuf_close(d->rowbuf);
	d->rowbuf = NULL;
	de_bitmap_destroy(img);
}

static void de_run_msp(deark *c, const char *params)
{
	lctx *d;

	de_dbg(c, "In msp module\n");

	d = de_malloc(c, sizeof(lctx));

	d->ver = de_getbyte(0) == 0x4c ? 2 : 1;
	de_dbg(c, "MSP version %d\n", (int)d->ver);

	d->width = de_getui16le(4);
	d->height = de_getui16le(6);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	if(d->ver==1) {
		de_declare_fmt(c, "MS Paint v1");
		do_ver1(c, d);
	}
	else {
		de_declare_fmt(c, "MS Paint v2");
		do_ver2(c, d);
	}

	de_free(c, d);
}

static int de_identify_msp(deark *c)
{
	de_byte b[4];
	de_read(b, 0, 4);

	if(b[0]==0x44 && b[1]==0x61 && b[2]==0x6e && b[3]==0x4d)
		return 100;
	if(b[0]==0x4c && b[1]==0x69 && b[2]==0x6e && b[3]==0x53)
		return 100;
	return 0;
}

void de_module_msp(deark *c, struct deark_module_info *mi)
{
	mi->id = "msp";
	mi->run_fn = de_run_msp;
	mi->identify_fn = de_identify_msp;
}
