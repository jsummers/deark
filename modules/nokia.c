// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 w, h;
	int nesting_level;
	int done_flag;
} lctx;

// **************************************************************************
// Nokia Operator Logo (NOL)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void nol_ngg_read_bitmap(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			n = de_getbyte(pos);
			pos++;
			de_bitmap_setpixel_gray(img, i, j, n=='0' ? 255 : 0);
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void de_run_nol(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In NOL module\n");

	d = de_malloc(c, sizeof(lctx));

	d->w = de_getui16le(10);
	d->h = de_getui16le(12);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	nol_ngg_read_bitmap(c, d, 20);
done:
	de_free(c, d);
}

static int de_identify_nol(deark *c)
{
	de_byte buf[3];
	de_read(buf, 0, 3);

	if(!de_memcmp(buf, "NOL", 3)) return 80;
	return 0;
}

void de_module_nol(deark *c, struct deark_module_info *mi)
{
	mi->id = "nol";
	mi->run_fn = de_run_nol;
	mi->identify_fn = de_identify_nol;
}

// **************************************************************************
// Nokia Group Graphic (NGG)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void de_run_ngg(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In NGG module\n");

	d = de_malloc(c, sizeof(lctx));

	d->w = de_getui16le(6);
	d->h = de_getui16le(8);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	nol_ngg_read_bitmap(c, d, 16);
done:
	de_free(c, d);
}

static int de_identify_ngg(deark *c)
{
	de_byte buf[3];
	de_read(buf, 0, 3);

	if(!de_memcmp(buf, "NGG", 3)) return 80;
	return 0;
}

void de_module_ngg(deark *c, struct deark_module_info *mi)
{
	mi->id = "ngg";
	mi->run_fn = de_run_ngg;
	mi->identify_fn = de_identify_ngg;
}

// **************************************************************************
// Nokia Picture Message (NPM)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void npm_nlm_read_bitmap(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 j;
	de_int64 src_rowspan;

	img = de_bitmap_create(c, d->w, d->h, 1);
	src_rowspan = (d->w+7)/8;

	for(j=0; j<d->h; j++) {
		de_convert_row_bilevel(c->infile, pos+j*src_rowspan, img, j, 1);
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void de_run_npm(deark *c, const char *params)
{
	de_int64 txt_len;
	de_int64 pos;
	lctx *d = NULL;

	de_dbg(c, "In NPM module\n");

	d = de_malloc(c, sizeof(lctx));

	pos = 4;
	txt_len = (de_int64)de_getbyte(pos);
	pos += txt_len;
	if(txt_len>0) de_dbg(c, "text length: %d\n", (int)txt_len);
	// TODO: Maybe write the text to a file.

	pos += 2;

	d->w = (de_int64)de_getbyte(pos);
	pos += 1;
	d->h = (de_int64)de_getbyte(pos);
	pos += 1;
	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	pos += 3;
	npm_nlm_read_bitmap(c, d, pos);

	de_free(c, d);
}

static int de_identify_npm(deark *c)
{
	de_byte buf[3];
	de_read(buf, 0, 3);

	if(!de_memcmp(buf, "NPM", 3)) return 80;
	return 0;
}

void de_module_npm(deark *c, struct deark_module_info *mi)
{
	mi->id = "npm";
	mi->run_fn = de_run_npm;
	mi->identify_fn = de_identify_npm;
}

// **************************************************************************
// Nokia Logo Manager bitmap (NLM)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************

static void de_run_nlm(deark *c, const char *params)
{
	lctx *d = NULL;
	de_byte imgtype;
	const char *s;

	de_dbg(c, "In NLM module\n");

	d = de_malloc(c, sizeof(lctx));

	imgtype = de_getbyte(5);
	switch(imgtype) {
	case 0: s="Operator logo"; break;
	case 1: s="Caller logo"; break;
	case 2: s="Startup logo"; break;
	case 3: s="Picture image logo"; break;
	default: s="unknown";
	}
	de_dbg(c, "image type: %d (%s)\n", (int)imgtype, s);

	d->w = (de_int64)de_getbyte(7);
	d->h = (de_int64)de_getbyte(8);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	npm_nlm_read_bitmap(c, d, 10);

	de_free(c, d);
}

static int de_identify_nlm(deark *c)
{
	de_byte buf[4];
	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "NLM ", 4)) return 80;
	return 0;
}

void de_module_nlm(deark *c, struct deark_module_info *mi)
{
	mi->id = "nlm";
	mi->run_fn = de_run_nlm;
	mi->identify_fn = de_identify_nlm;
}

// **************************************************************************
// Nokia Startup Logo (NSL)
//
// Caution: This code is not based on any official specifications.
// **************************************************************************


static void nsl_read_bitmap(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte x;

	de_dbg(c, "found NSLD chunk. bitmap at %d, len=%d\n", (int)pos, (int)len);
	d->done_flag = 1;

	if(len!=504) {
		de_err(c, "Unsupported NSL version (bitmap size=%d)\n", (int)len);
		goto done;
	}

	d->w = 84;
	d->h = 48;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			x = de_getbyte(pos + (j/8)*d->w + i);
			x = x & (1<<(j%8));
			if(x==0)
				de_bitmap_setpixel_gray(img, i, j, 255);
		}
	}

	de_bitmap_write_to_file(img, NULL);

done:
	de_bitmap_destroy(img);
}

static int read_nsl_chunk_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len);

static int read_nsl_chunk(deark *c, lctx *d, de_int64 pos1, de_int64 *plen)
{
	de_byte chunk_id[5];
	de_int64 payload_len;
	de_int64 pos;

	pos = pos1;
	de_read(chunk_id, pos, 4);
	pos += 4;
	payload_len = de_getui16be(pos);
	pos += 2;

	de_dbg(c, "[%d] chunk at %d, len=%d\n", d->nesting_level, (int)pos1, (int)payload_len);

	if(!de_memcmp(chunk_id, "FORM", 4) && d->nesting_level==0) {
		d->nesting_level++;
		read_nsl_chunk_sequence(c, d, pos, payload_len);
		d->nesting_level--;
	}
	else if(!de_memcmp(chunk_id, "NSLD", 4) && d->nesting_level==1) {
		nsl_read_bitmap(c, d, pos, payload_len);
	}

	*plen = 6 + payload_len;
	return 1;
}

static int read_nsl_chunk_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 endpos;
	de_int64 chunk_len;
	int ret;
	int retval = 0;

	endpos = pos + len;

	if(d->nesting_level>10) return 0;

	while(pos < endpos) {
		ret = read_nsl_chunk(c, d, pos, &chunk_len);
		if(!ret) goto done;
		if(d->done_flag) {
			retval = 1;
			goto done;
		}
		pos += chunk_len;
	}
	retval = 1;

done:
	return retval;
}

static void de_run_nsl(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;

	de_dbg(c, "In NSL module\n");
	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	read_nsl_chunk_sequence(c, d, pos, c->infile->len);

	de_free(c, d);
}

static int de_identify_nsl(deark *c)
{
	de_byte buf[4];
	de_int64 x;

	// NSL uses a variant of IFF, which is not so easy to identify.
	// (TODO: Write an IFF format detector.)

	de_read(buf, 0, 4);
	if(de_memcmp(buf, "FORM", 4)) return 0;

	x = de_getui16be(4);
	if(x+6 != c->infile->len) return 0;

	if(!de_input_file_has_ext(c, "nsl")) {
		return 100;
	}
	else {
		return 10;
	}

	return 0;
}

void de_module_nsl(deark *c, struct deark_module_info *mi)
{
	mi->id = "nsl";
	mi->run_fn = de_run_nsl;
	mi->identify_fn = de_identify_nsl;
}
