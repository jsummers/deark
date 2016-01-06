// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// AMOS sprite/icon bank

#include <deark-config.h>
#include <deark-modules.h>

#define CODE_AmBk 0x416d426bU
#define CODE_AmBs 0x416d4273U
#define CODE_AmIc 0x416d4963U
#define CODE_AmSp 0x416d5370U

// Data related to the whole file.
typedef struct localctx_struct {
	de_uint32 fmt;
} lctx;

// Data related to a "bank". Most files consist of one bank, but some have
// multiple banks.
struct amosbank {
	de_uint32 banktype;
	de_int64 bank_len;
	dbuf *f;
	const char *file_ext;

	de_int64 num_objects;
	de_int64 pal_pos;
	de_uint32 pal[256];

	// per-image settings
	de_int64 xsize; // 16-bit words per row per plane
	de_int64 ysize;
	de_int64 nplanes;
	de_int64 max_planes;
};

static void do_read_sprite_image(deark *c, lctx *d, struct amosbank *bk, de_int64 pos)
{
	de_int64 width, height;
	de_int64 i, j;
	de_int64 plane;
	unsigned int palent;
	de_byte b;
	de_int64 rowspan, planespan;
	de_uint32 clr;
	struct deark_bitmap *img = NULL;

	width = bk->xsize * 16;
	height = bk->ysize;

	de_dbg(c, "dimensions: %dx%d\n", (int)width, (int)height);
	de_dbg(c, "planes: %d\n", (int)bk->nplanes);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	if(bk->nplanes<1 || bk->nplanes>6) {
		de_err(c, "Unsupported number of planes: %d\n", (int)bk->nplanes);
	}

	img = de_bitmap_create(c, width, height, 4);

	rowspan = bk->xsize*2;
	planespan = rowspan*bk->ysize;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			palent = 0;
			for(plane=0; plane<bk->nplanes; plane++) {
				b = de_get_bits_symbol(bk->f, 1, pos + plane*planespan + j*rowspan, i);
				if(b) palent |= (1<<plane);
			}
			if(palent<=255) clr = bk->pal[palent];
			else clr=0;

			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL);

done:
	de_bitmap_destroy(img);
}

static int do_sprite_object(deark *c, lctx *d, struct amosbank *bk, de_int64 obj_idx,
	de_int64 pos, int pass, de_int64 *bytes_consumed)
{

	if(pass==2) {
		de_dbg(c, "object #%d at %d\n", (int)obj_idx, (int)pos);
	}
	de_dbg_indent(c, 1);

	bk->xsize = dbuf_getui16be(bk->f, pos);
	bk->ysize = dbuf_getui16be(bk->f, pos+2);
	bk->nplanes = dbuf_getui16be(bk->f, pos+4);

	if(pass==1) {
		if(bk->nplanes > bk->max_planes) {
			bk->max_planes = bk->nplanes;
		}
	}

	if(pass==2) {
		do_read_sprite_image(c, d, bk, pos+10);
	}

	*bytes_consumed = 10 + (bk->xsize*bk->ysize*bk->nplanes*2);

	de_dbg_indent(c, -1);
	return 1;
}

// pass 1 is just to find the location of the palette/
// pass 2 decodes the images.
static void do_read_sprite_objects(deark *c, lctx *d, struct amosbank *bk, de_int64 pos, int pass)
{
	int ret;
	de_int64 bytes_consumed;
	de_int64 obj_idx;

	de_dbg(c, "pass %d\n", pass);

	obj_idx = 0;
	while(1) {
		if(pos >= bk->f->len) break;
		if(obj_idx >= bk->num_objects) break;
		bytes_consumed = 0;
		ret = do_sprite_object(c, d, bk, obj_idx, pos, pass, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;
		pos += bytes_consumed;
		obj_idx++;
	}

	if(pass==1) {
		bk->pal_pos = pos;
		bk->bank_len = bk->pal_pos + 64;
		de_dbg(c, "palette offset: %d\n", (int)bk->pal_pos);
		de_dbg(c, "bank len: %d\n", (int)bk->bank_len);
	}
}

static void do_read_sprite_palette(deark *c, lctx *d, struct amosbank *bk)
{
	de_int64 k;
	unsigned int n;
	de_byte cr, cg, cb;
	de_byte cr1, cg1, cb1;
	de_int64 pos;
	de_int64 colors_used;

	pos = bk->pal_pos;
	de_dbg(c, "palette at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	colors_used = (de_int64)(1<<bk->max_planes);

	for(k=0; k<32; k++) {
		n = (unsigned int)dbuf_getui16be(bk->f, pos+k*2);
		cr1 = (de_byte)((n>>8)&0xf);
		cg1 = (de_byte)((n>>4)&0xf);
		cb1 = (de_byte)(n&0xf);
		cr = cr1*17;
		cg = cg1*17;
		cb = cb1*17;
		de_dbg2(c, "pal[%2d] = 0x%04x (%2d,%2d,%2d) -> (%3d,%3d,%3d)%s\n", (int)k, n,
			(int)cr1, (int)cg1, (int)cb1,
			(int)cr, (int)cg, (int)cb,
			(k>=colors_used)?" [unused]":"");

		bk->pal[k] = DE_MAKE_RGB(cr, cg, cb);

		// Set up colors #32-63 for 6-plane "Extra Half-Brite" mode.
		// For normal images (<=5 planes), these colors won't be used.
		bk->pal[k+32] = DE_MAKE_RGB(cr/2, cg/2, cb/2);
	}

	bk->pal[0] = DE_SET_ALPHA(bk->pal[0], 0); // First color is transparent.
	// (Don't know if pal[32] should be transparent also.)

	de_dbg_indent(c, -1);
}

// AmSp or AmIc
static int do_read_sprite(deark *c, lctx *d, struct amosbank *bk)
{
	bk->num_objects = dbuf_getui16be(bk->f, 4);
	de_dbg(c, "number of objects: %d\n", (int)bk->num_objects);

	do_read_sprite_objects(c, d, bk, 6, 1);

	if(d->fmt==CODE_AmBs) {
		dbuf_create_file_from_slice(bk->f, 0, bk->bank_len, bk->file_ext, NULL);
	}
	else {
		do_read_sprite_palette(c, d, bk);

		do_read_sprite_objects(c, d, bk, 6, 2);
	}

	return 1;
}

static int do_read_AmBk(deark *c, lctx *d, struct amosbank *bk)
{
	de_int64 banknum;
	de_int64 bank_len_code;
	de_int64 bank_len;

	banknum = dbuf_getui16be(bk->f, 4);
	de_dbg(c, "bank number (1-15): %d\n", (int)banknum);

	bank_len_code = dbuf_getui32be(bk->f, 8);
	bank_len = bank_len_code & 0x0fffffff;
	de_dbg(c, "bank length: %d (dlen=%d, tlen=%d)\n", (int)bank_len,
		(int)(bank_len-8), (int)(bank_len+12));
	bk->bank_len = bank_len+12;

	if(d->fmt==CODE_AmBs) {
		dbuf_create_file_from_slice(bk->f, 0, bk->bank_len, bk->file_ext, NULL);
	}

	return 1;
}

static int do_read_bank(deark *c, lctx *d, de_int64 pos, de_int64 *bytesused)
{
	struct amosbank *bk = NULL;
	de_byte banktype_buf[4];
	char banktype_printable[8];
	int ret;
	int retval = 0;

	bk = de_malloc(c, sizeof(struct amosbank));
	bk->f = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);

	dbuf_read(bk->f, banktype_buf, 0, 4);
	bk->banktype = (de_uint32)de_getui32be_direct(banktype_buf);
	de_make_printable_ascii(banktype_buf, 4, banktype_printable, sizeof(banktype_printable), 0);
	de_dbg(c, "bank type '%s'\n", banktype_printable);

	switch(bk->banktype) {
	case CODE_AmIc: bk->file_ext = "AmIc.abk"; break;
	case CODE_AmSp: bk->file_ext = "AmSp.abk"; break;
	case CODE_AmBk: bk->file_ext = "AmBk.abk"; break;
	default: bk->file_ext = "abk";
	}

	if(bk->banktype==CODE_AmIc || bk->banktype==CODE_AmSp) {
		ret = do_read_sprite(c, d, bk);
		retval = ret;
		*bytesused = bk->bank_len;
	}
	else if(bk->banktype==CODE_AmBk) {
		ret = do_read_AmBk(c, d, bk);
		retval = ret;
		*bytesused = bk->bank_len;
	}
	else {
		de_err(c, "Unsupported bank type: '%s'\n", banktype_printable);
	}

	if(bk) {
		dbuf_close(bk->f);
		de_free(c, bk);
	}
	return retval;
}

static void do_read_AmBs(deark *c, lctx *d)
{
	de_int64 bytesused;
	de_int64 nbanks;
	de_int64 i;
	de_int64 pos;
	int ret;

	nbanks = de_getui16be(4);
	de_dbg(c, "number of banks: %d\n", (int)nbanks);

	pos = 6;
	for(i=0; i<nbanks; i++) {
		if(pos >= c->infile->len) break;
		de_dbg(c, "bank #%d at %d\n", (int)i, (int)pos);
		bytesused = 0;
		de_dbg_indent(c, 1);
		ret = do_read_bank(c, d, pos, &bytesused);
		de_dbg_indent(c, -1);
		if(!ret || bytesused<1) break;
		pos += bytesused;
	}
}

static void de_run_abk(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 bytesused = 0;

	d = de_malloc(c, sizeof(lctx));

	d->fmt = (de_uint32)de_getui32be(0);

	if(d->fmt==CODE_AmIc) {
		de_declare_fmt(c, "AMOS Icon Bank");
	}
	else if(d->fmt==CODE_AmSp) {
		de_declare_fmt(c, "AMOS Sprite Bank");
	}
	else if(d->fmt==CODE_AmBs) {
		de_declare_fmt(c, "AMOS AmBs format");
	}
	else {
		de_err(c, "Unsupported format\n");
		goto done;
	}

	if(d->fmt==CODE_AmSp || d->fmt==CODE_AmIc) {
		do_read_bank(c, d, 0, &bytesused);
	}
	else if(d->fmt==CODE_AmBs) {
		do_read_AmBs(c, d);
	}

done:
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
	if(!de_memcmp(b, "AmBs", 4))
		return 60+ext_bonus;
	return 0;
}

void de_module_abk(deark *c, struct deark_module_info *mi)
{
	mi->id = "abk";
	mi->desc = "AMOS resource (sprite, icon, AmBs)";
	mi->run_fn = de_run_abk;
	mi->identify_fn = de_identify_abk;
}

static void de_run_amos_source(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 basic_len;
	de_int64 pos;
	de_int64 nbanks;

	d = de_malloc(c, sizeof(lctx));

	pos = 16;
	basic_len = de_getui32be(pos);
	pos += 4;
	de_dbg(c, "BASIC code at %d, len=%d\n", (int)pos, (int)basic_len);
	pos += basic_len;
	if(pos >= c->infile->len) goto done;
	if(dbuf_memcmp(c->infile, pos, "AmBs", 4)) {
		de_err(c, "AmBs segment not found, expected at offset %d\n", (int)pos);
		goto done;
	}

	de_dbg(c, "AmBs segment at %d\n", (int)pos);
	nbanks = de_getui16be(pos+4);
	de_dbg_indent(c, 1);
	de_dbg(c, "number of banks: %d\n", (int)nbanks);
	if(nbanks>0 || c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, pos, c->infile->len-pos, "AmBs.abk", NULL);
	}
	else {
		de_dbg(c, "not extracting emtpy AmBs segment\n");
	}
	de_dbg_indent(c, -1);


done:
	de_free(c, d);
}

static int de_identify_amos_source(deark *c)
{
	de_byte b[10];
	int ext_bonus = 0;

	if(de_input_file_has_ext(c, "amos")) ext_bonus=20;

	de_read(b, 0, 10);
	if(!de_memcmp(b, "AMOS Basic", 10))
		return 80+ext_bonus;
	if(!de_memcmp(b, "AMOS Pro", 8))
		return 80+ext_bonus;
	return 0;
}

void de_module_amos_source(deark *c, struct deark_module_info *mi)
{
	mi->id = "amos_source";
	mi->desc = "AMOS source code";
	mi->run_fn = de_run_amos_source;
	mi->identify_fn = de_identify_amos_source;
}
