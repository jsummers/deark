// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// QTIF (QuickTime Image)

#include <deark-config.h>
#include <deark-modules.h>

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
	if(len<8) return 0;

	d->idsc_found = 1;

	d->idsc_size = de_getui32be(pos);
	de_dbg(c, "idsc size: %d\n", (int)d->idsc_size);

	de_read(d->cmpr_type, pos+4, 4);
	de_make_printable_ascii(d->cmpr_type, 4, d->cmpr_type_printable,
		sizeof(d->cmpr_type_printable), 0);
	de_dbg(c, "compression type: \"%s\"\n", d->cmpr_type_printable);

	if(len<86) return 0;
	if(d->idsc_size<86) return 0;

	d->width = de_getui16be(pos+32);
	d->height = de_getui16be(pos+34);
	d->hres = read_fixed(c->infile, pos+36);
	d->vres = read_fixed(c->infile, pos+40);
	de_dbg(c, "dpi: %.1fx%.1f\n", d->hres, d->vres);
	d->idat_data_size = de_getui32be(pos+44);
	de_dbg(c, "reported data size: %d\n", (int)d->idat_data_size);
	if(d->idat_data_size>c->infile->len) d->idat_data_size=0;
	d->bitdepth = de_getui16be(pos+82);
	d->palette_id = de_getui16be(pos+84);
	de_dbg(c, "dimensions: %dx%d, bitdepth: %d, palette: %d\n", (int)d->width,
		(int)d->height, (int)d->bitdepth, (int)d->palette_id);
	return 1;
}

static int do_atom(deark *c, lctx *d, de_int64 pos, de_int64 len, int level,
	de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_size;
	de_int64 payload_size;
	de_byte atomtype[4];
	char atomtype_printable[16];

	size32 = de_getui32be(pos);
	de_read(atomtype, pos+4, 4);

	if(size32>=8) {
		header_size = 8;
		payload_size = size32-8;
	}
	else if(size32==0) {
		header_size = 8;
		payload_size = len-8;
	}
	else if(size32==1) {
		header_size = 16;
		size64 = de_geti64be(pos+8);
		if(size64<16) return 0;
		payload_size = size64-16;
	}
	else {
		// Invalid or unsupported format.
		return 0;
	}

	if(c->debug_level>0) {
		de_make_printable_ascii(atomtype, 4, atomtype_printable, sizeof(atomtype_printable), 0);
		de_dbg(c, "atom '%s' at %d, size=%d\n", atomtype_printable,
			(int)pos, (int)payload_size);
	}

	if(!de_memcmp(atomtype, "idat", 4)) {
		d->idat_found = 1;
		d->idat_pos = pos+header_size;
		d->idat_size = payload_size;
	}
	else if(!de_memcmp(atomtype, "idsc", 4)) {
		do_read_idsc(c, d, pos+header_size, payload_size);
	}

	*pbytes_consumed = header_size + payload_size;
	return 1;
}

static void do_atom_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level)
{
	de_int64 pos;
	de_int64 atom_len;
	de_int64 endpos;
	int ret;

	if(level >= 32) { // An arbitrary recursion limit.
		return;
	}

	pos = pos1;
	endpos = pos1 + len;

	while(pos < endpos) {
		ret = do_atom(c, d, pos, endpos-pos, level, &atom_len);
		if(!ret) break;
		pos += atom_len;
	}
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
	if(!d->idsc_found) {
		de_err(c, "Missing idsc atom\n");
	}
	else if(!de_memcmp(d->cmpr_type, "raw ", 4)) {
		do_decode_raw(c, d);
	}
	else if(!de_memcmp(d->cmpr_type, "jpeg", 4)) {
		dbuf_create_file_from_slice(c->infile, d->idat_pos,
			(d->idat_data_size>0) ? d->idat_data_size : d->idat_size,
			"jpg", NULL);
	}
	//else if(!de_memcmp(d->cmpr_type, "tiff", 4)) {
	// The "tiff" compression type is apparently not exactly an embedded TIFF
	// file, and I don't know how to extract it.
	//}
	else {
		de_err(c, "Unsupported compression type: \"%s\"\n", d->cmpr_type_printable);
	}
}

static void do_qtif_file_format(deark *c, lctx *d)
{
	do_atom_sequence(c, d, 0, c->infile->len, 0);

	if(d->idat_found) {
		do_write_image(c, d);
	}
}

static void do_raw_idsc_data(deark *c, lctx *d)
{
	if(!do_read_idsc(c, d, 0, c->infile->len)) {
		return;
	}
	d->idat_pos = d->idsc_size;
	d->idat_size = c->infile->len - d->idat_pos;
	do_write_image(c, d);
}

static void de_run_qtif(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	de_dbg(c, "In qtif module\n");

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
