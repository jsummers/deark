// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// This file is for miscellaneous formats that are easy to support.
// Combining them in one file speeds up compilation and development time.

#include <deark-config.h>
#include <deark-modules.h>

// **************************************************************************
// "copy" module
//
// This is a trivial module that makes a copy of the input file.
// **************************************************************************

static int de_identify_copy(deark *c)
{
	return 0;
}

static void de_run_copy(deark *c, const char *params)
{
	de_dbg(c, "In copy module\n");

	dbuf_create_file_from_slice(c->infile, 0, c->infile->len, "bin", NULL);
}

void de_module_copy(deark *c, struct deark_module_info *mi)
{
	mi->id = "copy";
	mi->run_fn = de_run_copy;
	mi->identify_fn = de_identify_copy;
}

// **************************************************************************
// HP 100LX / HP 200LX .ICN icon format
// **************************************************************************

static void de_run_hpicn(deark *c, const char *params)
{
	struct deark_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 src_rowspan;
	de_int64 j;

	de_dbg(c, "In hpicn module\n");

	width = de_getui16le(4);
	height = de_getui16le(6);

	img = de_bitmap_create(c, width, height, 1);
	src_rowspan = (width+7)/8;

	for(j=0; j<height; j++) {
		de_convert_row_bilevel(c->infile, 8+j*src_rowspan, img, j, 1);
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static int de_identify_hpicn(deark *c)
{
	de_byte b[8];
	de_read(b, 0, 8);
	if(!de_memcmp(b, "\x01\x00\x01\x00\x2c\x00\x20\x00", 8))
		return 100;
	if(!de_memcmp(b, "\x01\x00\x01\x00", 4))
		return 60;
	return 0;
}

void de_module_hpicn(deark *c, struct deark_module_info *mi)
{
	mi->id = "hpicn";
	mi->run_fn = de_run_hpicn;
	mi->identify_fn = de_identify_hpicn;
}
