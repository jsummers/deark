// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// QTIF (QuickTime Image)

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	int idat_found;
	de_int64 idat_pos;
	de_int64 idat_size;

	int idsc_found;
	de_int64 idsc_size;
	de_int64 idat_data_size; // "Data size" reported in idsc (0=unknown)
	de_byte cmpr_type[4];
	char cmpr_type_printable[8];

	de_int64 width, height;
	de_int64 bitdepth;
	de_int64 palette_id;
	double hres, vres;
} lctx;

static double read_fixed(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

static int do_read_idsc(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	int retval = 0;

	if(len<8) goto done;

	d->idsc_found = 1;

	d->idsc_size = de_getui32be(pos);
	de_dbg(c, "idsc size: %d\n", (int)d->idsc_size);

	de_read(d->cmpr_type, pos+4, 4);
	de_make_printable_ascii(d->cmpr_type, 4, d->cmpr_type_printable,
		sizeof(d->cmpr_type_printable), 0);
	de_dbg(c, "compression type: \"%s\"\n", d->cmpr_type_printable);

	if(len<86) goto done;
	if(d->idsc_size<86) goto done;

	d->width = de_getui16be(pos+32);
	d->height = de_getui16be(pos+34);
	d->hres = read_fixed(c->infile, pos+36);
	d->vres = read_fixed(c->infile, pos+40);
	de_dbg(c, "dpi: %.2fx%.2f\n", d->hres, d->vres);
	d->idat_data_size = de_getui32be(pos+44);
	de_dbg(c, "reported data size: %d\n", (int)d->idat_data_size);
	if(d->idat_data_size>c->infile->len) d->idat_data_size=0;
	d->bitdepth = de_getui16be(pos+82);
	d->palette_id = de_getui16be(pos+84);
	de_dbg(c, "dimensions: %dx%d, bitdepth: %d, palette: %d\n", (int)d->width,
		(int)d->height, (int)d->bitdepth, (int)d->palette_id);
	retval = 1;
done:
	return retval;
}

static void do_decode_raw(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_int64 rowspan;
	de_uint32 clr;

	if(d->bitdepth != 32) {
		de_err(c, "Unsupported bit depth for raw image (%d)\n", (int)d->bitdepth);
		goto done;
	}
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	img = de_bitmap_create(c, d->width, d->height, 3);

	img->density_code = DE_DENSITY_DPI;
	img->xdens = d->hres;
	img->ydens = d->vres;

	// Warning: This code is based on reverse engineering, and may not be correct.
	// TODO: Is the first sample for transparency?

	// I don't know how to figure out the bytes per row. This logic works for the
	// few example files I have.
	rowspan = d->width * 4;
	if(d->idat_data_size/d->height > rowspan) {
		rowspan = d->idat_data_size/d->height;
	}

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			clr = dbuf_getRGB(c->infile, d->idat_pos + j*rowspan + i*4+1, 0);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL);
done:
	de_bitmap_destroy(img);
}

static void do_write_image(deark *c, lctx *d)
{
	de_int64 dsize;

	if(!d->idsc_found) {
		de_err(c, "Missing idsc atom\n");
		return;
	}

	dsize = (d->idat_data_size>0) ? d->idat_data_size : d->idat_size;
	if(dsize<=0) return;

	if(!de_memcmp(d->cmpr_type, "raw ", 4)) {
		do_decode_raw(c, d);
	}
	else if(!de_memcmp(d->cmpr_type, "jpeg", 4)) {
		dbuf_create_file_from_slice(c->infile, d->idat_pos, dsize, "jpg", NULL);
	}
	else if(!de_memcmp(d->cmpr_type, "tiff", 4)) {
		dbuf_create_file_from_slice(c->infile, d->idat_pos, dsize, "tif", NULL);
	}
	else if(!de_memcmp(d->cmpr_type, "gif ", 4)) {
		dbuf_create_file_from_slice(c->infile, d->idat_pos, dsize, "gif", NULL);
	}
	else if(!de_memcmp(d->cmpr_type, "png ", 4)) {
		dbuf_create_file_from_slice(c->infile, d->idat_pos, dsize, "png", NULL);
	}
	else if(!de_memcmp(d->cmpr_type, "kpcd", 4)) { // Kodak Photo CD
		dbuf_create_file_from_slice(c->infile, d->idat_pos, dsize, "pcd", NULL);
	}
	else {
		de_err(c, "Unsupported compression type: \"%s\"\n", d->cmpr_type_printable);
	}
}

#define BOX_idat 0x69646174U
#define BOX_idsc 0x69647363U

static int quicktime_box_handler(deark *c, struct de_boxesctx *bctx)
{
	lctx *d = (lctx*)bctx->userdata;

	if(bctx->boxtype==BOX_idat) {
		d->idat_found = 1;
		d->idat_pos = bctx->payload_pos;
		d->idat_size = bctx->payload_len;
	}
	else if(bctx->boxtype==BOX_idsc) {
		do_read_idsc(c, d, bctx->payload_pos, bctx->payload_len);
	}
	else if(bctx->is_uuid) {
		return de_fmtutil_default_box_handler(c, bctx);
	}

	return 1;
}

static void do_qtif_file_format(deark *c, lctx *d)
{
	struct de_boxesctx *bctx = NULL;

	bctx = de_malloc(c, sizeof(struct de_boxesctx));

	bctx->userdata = (void*)d;
	bctx->f = c->infile;
	bctx->handle_box_fn = quicktime_box_handler;

	de_fmtutil_read_boxes_format(c, bctx);

	if(d->idat_found) {
		do_write_image(c, d);
	}

	de_free(c, bctx);
}

static void do_raw_idsc_data(deark *c, lctx *d)
{
	int ret;

	de_dbg(c, "QuickTime 'idsc' data\n");

	de_dbg_indent(c, 1);
	ret = do_read_idsc(c, d, 0, c->infile->len);
	de_dbg_indent(c, -1);
	if(!ret) return;

	d->idat_pos = d->idsc_size;
	d->idat_size = c->infile->len - d->idat_pos;
	do_write_image(c, d);
}

static void de_run_qtif(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	if(c->module_nesting_level>1) de_dbg2(c, "in qtif module\n");

	d = de_malloc(c, sizeof(lctx));

	if(mparams && mparams->codes && de_strchr(mparams->codes, 'I')) {
		// Raw data from a PICT file
		do_raw_idsc_data(c, d);
	}
	else {
		do_qtif_file_format(c, d);
	}

	de_free(c, d);
}

static int de_identify_qtif(deark *c)
{
	if(de_input_file_has_ext(c, "qtif")) return 20;
	if(de_input_file_has_ext(c, "qti")) return 5;
	if(de_input_file_has_ext(c, "qif")) return 5;
	return 0;
}

void de_module_qtif(deark *c, struct deark_module_info *mi)
{
	mi->id = "qtif";
	mi->desc = "QTIF (QuickTime Image Format)";
	mi->run_fn = de_run_qtif;
	mi->identify_fn = de_identify_qtif;
}
