// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// AMOS sprite/icon bank

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 num_objects;
	de_int64 pal_pos;
	de_uint32 pal[256];

	// per-image settings
	de_int64 xsize; // 16-bit words per row per plane
	de_int64 ysize;
	de_int64 nplanes;
} lctx;

static void do_read_image(deark *c, lctx *d, de_int64 pos)
{
	de_int64 width, height;
	de_int64 i, j;
	de_int64 plane;
	unsigned int palent;
	de_byte b;
	de_int64 rowspan, planespan;
	de_uint32 clr;
	struct deark_bitmap *img = NULL;

	width = d->xsize * 16;
	height = d->ysize;

	de_dbg(c, "dimensions: %dx%d\n", (int)width, (int)height);
	de_dbg(c, "planes: %d\n", (int)d->nplanes);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	if(d->nplanes<1 || d->nplanes>6) {
		de_err(c, "Unsupported number of planes: %d\n", (int)d->nplanes);
	}

	img = de_bitmap_create(c, width, height, 4);

	rowspan = d->xsize*2;
	planespan = rowspan*d->ysize;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			palent = 0;
			for(plane=0; plane<d->nplanes; plane++) {
				b = de_get_bits_symbol(c->infile, 1, pos + plane*planespan + j*rowspan, i);
				if(b) palent |= (1<<plane);
			}
			if(palent<=255) clr = d->pal[palent];
			else clr=0;

			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL);

done:
	de_bitmap_destroy(img);
}

static int do_abk_object(deark *c, lctx *d, de_int64 obj_idx, de_int64 pos, int pass,
	de_int64 *bytes_consumed)
{

	if(pass==2) {
		de_dbg(c, "object #%d at %d\n", (int)obj_idx, (int)pos);
	}
	de_dbg_indent(c, 1);

	d->xsize = de_getui16be(pos);
	d->ysize = de_getui16be(pos+2);
	d->nplanes = de_getui16be(pos+4);
	if(pass==2) {
		do_read_image(c, d, pos+10);
	}

	*bytes_consumed = 10 + (d->xsize*d->ysize*d->nplanes*2);


	de_dbg_indent(c, -1);
	return 1;
}

// pass 1 is just to find the location of the palette/
// pass 2 decodes the images.
static void do_read_objects(deark *c, lctx *d, de_int64 pos, int pass)
{
	int ret;
	de_int64 bytes_consumed;
	de_int64 obj_idx;

	de_dbg(c, "pass %d\n", pass);

	obj_idx = 0;
	while(1) {
		if(pos >= c->infile->len) break;
		if(obj_idx >= d->num_objects) break;
		bytes_consumed = 0;
		ret = do_abk_object(c, d, obj_idx, pos, pass, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;
		pos += bytes_consumed;
		obj_idx++;
	}

	if(pass==1) {
		d->pal_pos = pos;
	}
}

static void do_read_palette(deark *c, lctx *d)
{
	de_int64 k;
	unsigned int n;
	de_byte cr, cg, cb;
	de_byte cr1, cg1, cb1;
	de_int64 pos;

	pos = d->pal_pos;
	de_dbg(c, "palette at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	for(k=0; k<32; k++) {
		n = (unsigned int)de_getui16be(pos+k*2);
		cr1 = (de_byte)((n>>8)&0xf);
		cg1 = (de_byte)((n>>4)&0xf);
		cb1 = (de_byte)(n&0xf);
		cr = cr1*17;
		cg = cg1*17;
		cb = cb1*17;
		de_dbg2(c, "pal[%2d] = 0x%04x (%2d,%2d,%2d) -> (%3d,%3d,%3d)\n", (int)k, n,
			(int)cr1, (int)cg1, (int)cb1,
			(int)cr, (int)cg, (int)cb);

		d->pal[k] = DE_MAKE_RGB(cr, cg, cb);

		// Set up colors #32-63 for 6-plane "Extra Half-Brite" mode.
		// For normal images (<=5 planes), these colors won't be used.
		d->pal[k+32] = DE_MAKE_RGB(cr/2, cg/2, cb/2);
	}

	d->pal[0] = DE_SET_ALPHA(d->pal[0], 0); // First color is transparent.
	// (Don't know if pal[32] should be transparent also.)

	de_dbg_indent(c, -1);
}

static void de_run_abk(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int is_icon;

	d = de_malloc(c, sizeof(lctx));

	is_icon = !dbuf_memcmp(c->infile, 0, "AmIc", 4);
	if(is_icon) {
		de_declare_fmt(c, "AMOS Icon Bank");
	}
	else {
		de_declare_fmt(c, "AMOS Sprite Bank");
	}

	d->num_objects = de_getui16be(4);
	de_dbg(c, "number of objects: %d\n", (int)d->num_objects);

	do_read_objects(c, d, 6, 1);

	if(d->pal_pos != c->infile->len-64) {
		de_warn(c, "Palette calculated to be at offset %d, but file size "
			"suggests it should be at offset %d\n",
			(int)d->pal_pos, (int)(c->infile->len-64));
	}
	do_read_palette(c, d);

	do_read_objects(c, d, 6, 2);

	de_free(c, d);
}

static int de_identify_abk(deark *c)
{
	de_byte b[4];
	int ext_bonus = 0;

	if(de_input_file_has_ext(c, "abk")) ext_bonus=40;

	de_read(b, 0, 4);
	if(!de_memcmp(b, "AmSp", 4))
		return 60+ext_bonus;
	if(!de_memcmp(b, "AmIc", 4))
		return 60+ext_bonus;
	return 0;
}

void de_module_abk(deark *c, struct deark_module_info *mi)
{
	mi->id = "abk_img";
	mi->desc = "AMOS sprite/icon bank";
	mi->run_fn = de_run_abk;
	mi->identify_fn = de_identify_abk;
}
