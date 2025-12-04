// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Paint

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_msp);

typedef struct localctx_struct {
	int ver; // 1 or 2
	i64 width, height;
	dbuf *rowbuf;
} lctx;

static void do_ver1(deark *c, lctx *d)
{
	i64 src_rowspan;

	// TODO: Are version-1 MSP files padded this way?
	// (Maybe the width is always a multiple of 8, so it doesn't matter.)
	src_rowspan = (d->width+7)/8;

	de_convert_and_write_image_bilevel(c->infile, 32,
		d->width, d->height, src_rowspan, 0, NULL, 0);
}

static void do_decompress_scanline(deark *c, lctx *d, de_bitmap *img,
	i64 rownum, i64 rowoffset, i64 bytes_in_row)
{
	i64 i;
	u8 runtype;
	i64 runcount;
	u8 value;

	de_dbg2(c, "decompressing row %d", (int)rownum);

	if(!d->rowbuf) {
		d->rowbuf = dbuf_create_membuf(c, (d->width+7)/8, 1);
	}

	dbuf_empty(d->rowbuf);

	// Read the compressed data byte by byte
	i = 0;
	while(i<bytes_in_row) {
		runtype = de_getbyte(rowoffset+i);
		i++;
		if(runtype==0x00) {
			runcount = (i64)de_getbyte(rowoffset+i);
			i++;
			value = de_getbyte(rowoffset+i);
			i++;
			// write value runcount times
			de_dbg2(c, "compressed, %d bytes of %d", (int)runcount, value);
			dbuf_write_run(d->rowbuf, value, runcount);
		}
		else {
			runcount = (i64)runtype;
			de_dbg2(c, "%d bytes uncompressed", (int)runcount);
			dbuf_copy(c->infile, rowoffset+i, runcount, d->rowbuf);
			i+=runcount;
		}
	}

	de_convert_row_bilevel(d->rowbuf, 0, img, rownum, 0);
}

static void do_ver2(deark *c, lctx *d)
{
	i64 j;
	i64 *rowoffset;
	i64 *rowsize;
	de_bitmap *img = NULL;

	rowoffset = de_mallocarray(c, d->height, sizeof(i64));
	rowsize = de_mallocarray(c, d->height, sizeof(i64));

	// Read the scanline map, and record the row sizes.
	for(j=0; j<d->height; j++) {
		rowsize[j] = de_getu16le(32+2*j);
	}

	// Calculate the position, in the file, of each row.
	for(j=0; j<d->height; j++) {
		if(j==0)
			rowoffset[j] = 32 + 2*d->height;
		else
			rowoffset[j] = rowoffset[j-1] + rowsize[j-1];
		de_dbg2(c, "row %d offset=%d size=%d", (int)j, (int)rowoffset[j], (int)rowsize[j]);
	}

	img = de_bitmap_create(c, d->width, d->height, 1);

	for(j=0; j<d->height; j++) {
		do_decompress_scanline(c, d, img, j, rowoffset[j], rowsize[j]);
	}

	de_bitmap_write_to_file(img, NULL, 0);

	de_free(c, rowsize);
	de_free(c, rowoffset);
	dbuf_close(d->rowbuf);
	d->rowbuf = NULL;
	de_bitmap_destroy(img);
}

static void de_run_msp(deark *c, de_module_params *mparams)
{
	lctx *d;

	d = de_malloc(c, sizeof(lctx));

	d->ver = de_getbyte(0) == 0x4c ? 2 : 1;
	de_dbg(c, "version: %d", d->ver);
	de_declare_fmtf(c, "MS Paint v%d", d->ver);

	d->width = de_getu16le(4);
	d->height = de_getu16le(6);
	de_dbg_dimensions(c, d->width, d->height);

	if(d->ver==1) {
		do_ver1(c, d);
	}
	else {
		do_ver2(c, d);
	}

	de_free(c, d);
}

static int de_identify_msp(deark *c)
{
	u8 b[4];
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
	mi->desc = "Microsoft Paint image";
	mi->run_fn = de_run_msp;
	mi->identify_fn = de_identify_msp;
}
