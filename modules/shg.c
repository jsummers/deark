// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Segmented Hypergraphics (SHG) and Multiple Resolution Bitmap (MRB)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 signature;

	de_int64 shg_startpos;
	de_int64 num_pictures;

	de_byte picture_type;
	de_byte packing_method;
} lctx;

// compressed unsigned short
static de_int64 get_cus(dbuf *f, de_int64 *pos)
{
	de_int64 x1, x2;
	x1 = (de_int64)dbuf_getbyte(f, *pos);
	*pos += 1;
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 128 times the value of
	// the next two bytes.
	x2 = (de_int64)dbuf_getbyte(f, *pos);
	*pos += 1;
	return (x1>>1) | (x2<<7);
}

// compressed unsigned long
static de_int64 get_cul(dbuf *f, de_int64 *pos)
{
	de_int64 x1, x2;
	x1 = dbuf_getui16le(f, *pos);
	*pos += 2;
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 32768 times the value of
	// the next two bytes.
	x2 = dbuf_getui16le(f, *pos);
	*pos += 2;
	return (x1>>1) | (x2<<15);
}

static int do_dib(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 xdpi, ydpi;
	de_int64 planes;
	de_int64 bitcount;
	de_int64 width, height;
	de_int64 colors_used;
	de_int64 colors_important;
	de_int64 compressed_size;
	de_int64 hotspot_size;
	de_int64 compressed_offset;
	de_int64 hotspot_offset;
	de_int64 pos;

	pos = pos1;

	xdpi = get_cul(c->infile, &pos);
	ydpi = get_cul(c->infile, &pos);
	de_dbg(c, "dpi: %dx%d\n", (int)xdpi, (int)ydpi);

	planes = get_cus(c->infile, &pos);
	bitcount = get_cus(c->infile, &pos);
	width = get_cul(c->infile, &pos);
	height = get_cul(c->infile, &pos);
	de_dbg(c, "planes=%d, bitcount=%d, dimensions=%dx%d\n", (int)planes,
		(int)bitcount, (int)width, (int)height);

	colors_used = get_cul(c->infile, &pos);
	colors_important = get_cul(c->infile, &pos);
	de_dbg(c, "colors used=%d, important=%d\n", (int)colors_used,
		(int)colors_important);

	compressed_size = get_cul(c->infile, &pos);
	hotspot_size = get_cul(c->infile, &pos);
	compressed_offset = de_getui32le(pos);
	hotspot_offset = de_getui32le(pos+4);
	de_dbg(c, "bits offset=%d, size=%d\n", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d\n", (int)hotspot_offset,
		(int)hotspot_size);
	pos+=8;

	return 1;
}

static int do_picture(deark *c, lctx *d, de_int64 pic_index)
{
	de_int64 pic_offset;

	int retval = 0;

	de_dbg(c, "picture #%d\n", (int)pic_index);
	de_dbg_indent(c, 1);

	pic_offset = de_getui32le(d->shg_startpos + 4 + 4*pic_index);
	pic_offset += d->shg_startpos;
	de_dbg(c, "picture data at %d\n", (int)pic_offset);
	if(pic_offset >= c->infile->len) {
		goto done;
	}

	d->picture_type = de_getbyte(pic_offset);
	d->packing_method = de_getbyte(pic_offset+1);

	de_dbg(c, "picture type: %d\n", (int)d->picture_type);
	de_dbg(c, "packing method: %d\n", (int)d->packing_method);

	if(d->picture_type==5 || d->picture_type==6) { // DDB or DIB
		do_dib(c, d, pic_offset+2);
	}
	else {
		de_warn(c, "Unsupported picture type: %d\n", (int)d->picture_type);
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_shg(deark *c, lctx *d)
{
	de_int64 k;

	d->num_pictures = de_getui16le(d->shg_startpos+2);
	de_dbg(c, "number of pictures in file: %d\n", (int)d->num_pictures);
	if(d->num_pictures>DE_MAX_IMAGES_PER_FILE) {
		goto done;
	}

	for(k=0; k<d->num_pictures; k++) {
		if(!do_picture(c, d, k)) {
			goto done;
		}
	}

done:
	;
}

static void de_run_shg(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In shg module\n");

	d = de_malloc(c, sizeof(lctx));

	d->shg_startpos = 0;
	d->signature = de_getui16le(d->shg_startpos);
	if(d->signature==0x506c) {
		de_declare_fmt(c, "SHG");
	}
	else if(d->signature==0x706c) {
		de_declare_fmt(c, "MRB");
	}
	else {
		de_warn(c, "This is probably not an SHG/MRB file.\n");
	}

	do_shg(c, d);

	de_free(c, d);
	de_err(c, "SHG/MRB support is not implemented.\n");
}

static int de_identify_shg(deark *c)
{
	de_byte buf[2];
	de_read(buf, 0, 2);
	if(buf[0]==0x6c && (buf[1]==0x50 || buf[1]==0x70)) {
		return 50;
	}
	return 0;
}

void de_module_shg(deark *c, struct deark_module_info *mi)
{
	mi->id = "shg";
	mi->run_fn = de_run_shg;
	mi->identify_fn = de_identify_shg;
}
