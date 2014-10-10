// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 w, h;
#define DE_FMT_TI92  1
#define DE_FMT_TI89  2
#define DE_FMT_TI92P 3
	int fmt;
} lctx;

static int identify_internal(deark *c)
{
	de_byte buf[8];

	de_read(buf, 0, 8);
	if(!de_memcmp(buf, "**TI92**", 8)) return DE_FMT_TI92;
	if(!de_memcmp(buf, "**TI89**", 8)) return DE_FMT_TI89;
	if(!de_memcmp(buf, "**TI92P*", 8)) return DE_FMT_TI92P;
	return 0;
}

static int do_bitmap(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 j;
	de_int64 rowspan;
	int retval = 0;

	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);
	rowspan = (d->w+7)/8;

	if(pos+rowspan*d->h > c->infile->len) {
		de_err(c, "File too small. This is probably not a TI bitmap file.\n");
		goto done;
	}
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		de_convert_row_bilevel(c->infile, pos+j*rowspan, img, j, DE_CVTR_WHITEISZERO);
	}

	de_bitmap_write_to_file(img, NULL);
	retval = 1;
done:
	de_bitmap_destroy(img);
	return retval;
}

static int do_ti92_picture_var(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x;

	de_dbg(c, "picture at %d\n", (int)pos);
	pos+=4;

	x = de_getui16be(pos);
	de_dbg(c, "picture size: %d\n", (int)x);
	d->h = de_getui16be(pos+2);
	d->w = de_getui16be(pos+4);
	return do_bitmap(c, d, pos+6);
}

static void do_ti92_var_table_entry(deark *c, lctx *d, de_int64 pos)
{
	de_int64 data_offset;
	de_byte type_id;

	de_dbg(c, "var table entry at %d\n", (int)pos);
	data_offset = de_getui32le(pos);

	type_id = de_getbyte(pos+12);
	de_dbg(c, "var type: 0x%02x\n", (unsigned int)type_id);
	if(type_id!=0x10) {
		// Not a picture
		return;
	}
	de_dbg(c, "data offset: %d\n", (int)data_offset);
	do_ti92_picture_var(c, d, data_offset);
}

static void do_ti92(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 numvars;
	de_int64 x;
	de_int64 i;

	// 0-7: signature
	// 8-9: 0x01 0x00
	// 10-17: default folder name
	// 18-57: comment

	numvars = de_getui16le(58);
	de_dbg(c, "number of variables/folders: %d\n", (int)numvars);
	if(numvars>DE_MAX_IMAGES_PER_FILE) goto done;

	pos = 60;
	for(i=0; i<numvars; i++) {
		do_ti92_var_table_entry(c, d, pos);
		pos+=16;
	}

	// Data section
	x = de_getui32le(pos);
	de_dbg(c, "reported file size: %d\n", (int)x);

done:
	;
}

static void de_run_tivariable(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In tivariable module\n");
	d = de_malloc(c, sizeof(lctx));
	d->fmt = identify_internal(c);
	switch(d->fmt) {
	case DE_FMT_TI92:
		de_declare_fmt(c, "TI92 variable file");
		break;
	case DE_FMT_TI89:
		de_declare_fmt(c, "TI89 variable file");
		break;
	case DE_FMT_TI92P:
		de_declare_fmt(c, "TI92P variable file");
		break;
	}

	do_ti92(c, d);
	de_free(c, d);
}

static int de_identify_tivariable(deark *c)
{
	if(identify_internal(c)!=0) return 100;
	return 0;
}

void de_module_tivariable(deark *c, struct deark_module_info *mi)
{
	mi->id = "tivariable";
	mi->run_fn = de_run_tivariable;
	mi->identify_fn = de_identify_tivariable;
}
