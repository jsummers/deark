// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int ver; // 1 or 2
	struct deark_bitmap *img;
	dbuf *rowbuf;
} lctx;

static void do_ver1(deark *c, lctx *d)
{
	de_int64 j;
	de_int64 src_rowspan;

	// TODO: Are version-1 MSP files padded this way?
	// (Maybe the width is always a multiple of 8, so it doesn't matter.)
	src_rowspan = (d->img->width+7)/8;

	for(j=0; j<d->img->height; j++) {
		de_convert_row_bilevel(c->infile, 32+j*src_rowspan, d->img, j, 0);
	}
}

static void do_decompress_scanline(deark *c, lctx *d, de_int64 rownum,
   de_int64 rowoffset, de_int64 bytes_in_row)
{
	de_int64 i;
	int k;
	de_byte runtype;
	int runcount;
	de_byte value;

	de_dbg2(c, "decompressing row %d\n", (int)rownum);

	if(!d->rowbuf) {
		d->rowbuf = dbuf_create_membuf(c, (d->img->width+63)/8);
	}

	dbuf_empty(d->rowbuf);

	// Read the compressed data byte by byte
	i = 0;
	while(i<bytes_in_row) {
		runtype = de_getbyte(rowoffset+i);
		i++;
		if(runtype==0x00) {
			runcount = (int)de_getbyte(rowoffset+i);
			i++;
			value = de_getbyte(rowoffset+i);
			i++;
			// write value runcount times
			de_dbg2(c, "compressed, %d bytes of %d\n", runcount, value);
			for(k=0; k<runcount; k++) {
				dbuf_write(d->rowbuf, &value, 1);
			}
		}
		else {
			runcount = (int)runtype;
			de_dbg2(c, "%d bytes uncompressed\n", runcount);
			dbuf_copy(c->infile, rowoffset+i, runcount, d->rowbuf);
			i+=runcount;
		}
		// TODO: sanity check for over-long lines
	}

	de_convert_row_bilevel(d->rowbuf, 0, d->img, rownum, 0);
}

static void do_ver2(deark *c, lctx *d)
{
	de_int64 j;
	de_int64 *rowoffset;
	de_int64 *rowsize;

	rowoffset = de_malloc(c, d->img->height * sizeof(de_int64));
	rowsize = de_malloc(c, d->img->height * sizeof(de_int64));

	// Read the scanline map, and record the row sizes.
	for(j=0; j<d->img->height; j++) {
		rowsize[j] = de_getui16le(32+2*j);
	}

	// Calculate the position, in the file, of each row.
	for(j=0; j<d->img->height; j++) {
		if(j==0)
			rowoffset[j] = 32 + 2*d->img->height;
		else
			rowoffset[j] = rowoffset[j-1] + rowsize[j-1];
		de_dbg2(c, "row %d offset=%d size=%d\n", (int)j, (int)rowoffset[j], (int)rowsize[j]);
	}

	for(j=0; j<d->img->height; j++) {
		do_decompress_scanline(c, d, j, rowoffset[j], rowsize[j]);
	}

	de_free(c, rowsize);
	de_free(c, rowoffset);
}

static void de_run_msp(deark *c, const char *params)
{
	lctx *d;

	de_dbg(c, "In msp module\n");

	d = de_malloc(c, sizeof(lctx));
	d->img = de_bitmap_create_noinit(c);

	d->ver = de_getbyte(0) == 0x4c ? 2 : 1;
	de_dbg(c, "MSP version %d\n", (int)d->ver);

	d->img->width = de_getui16le(4);
	d->img->height = de_getui16le(6);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->img->width, (int)d->img->height);
	d->img->bytes_per_pixel = 1;

	if(d->ver==1) {
		do_ver1(c, d);
	}
	else {
		do_ver2(c, d);
	}

	de_bitmap_write_to_file(d->img, NULL);

	de_bitmap_destroy(d->img);
	dbuf_close(d->rowbuf);
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
