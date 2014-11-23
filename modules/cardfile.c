// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract graphics from Windows Cardfile .crd format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
#define DE_CRDFMT_MGC 1
#define DE_CRDFMT_RRG 2
	int fmt;
	de_int64 numcards;
} lctx;

static void do_card_index(deark *c, lctx *d, de_int64 cardnum, de_int64 pos)
{
	de_int64 datapos;
	de_int64 bitmap_length;
	de_int64 w, h;
	de_int64 src_rowspan;
	struct deark_bitmap *img = NULL;
	de_finfo *fi = NULL;

	datapos = de_getui32le(pos+6);
	de_dbg(c, "card #%d, data offset = %d\n", (int)cardnum, (int)datapos);

	if(datapos>=c->infile->len) return;
	bitmap_length = de_getui16le(datapos);
	if(bitmap_length<=0) {
		de_dbg(c, "not a graphics card\n");
		goto done;
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_slice(c, fi, c->infile, pos+11, 40, DE_CONVFLAG_STOP_AT_NUL);

	w = de_getui16le(datapos+2);
	h = de_getui16le(datapos+4);
	de_dbg(c, "bitmap %dx%d, length=%d\n", (int)w, (int)h, (int)bitmap_length);

	img = de_bitmap_create(c, w, h, 1);
	src_rowspan = ((w+15)/16)*2;

	de_convert_and_write_image_bilevel(c->infile, datapos+10,
		w, h, src_rowspan, 0, fi);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

static void de_run_cardfile(deark *c, const char *params)
{
	lctx *d = NULL;
	de_byte b;
	de_int64 pos;
	de_int64 n;

	de_dbg(c, "In cardfile module\n");

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	b = de_getbyte(pos);
	if(b=='R') d->fmt=DE_CRDFMT_RRG;
	else d->fmt=DE_CRDFMT_MGC;

	if(d->fmt==DE_CRDFMT_RRG) {
		de_err(c, "CardFile RRG format is not supported\n");
		goto done;
	}

	pos+=3;

	d->numcards = de_getui16le(pos);
	de_dbg(c, "Number of cards: %d\n", (int)d->numcards);
	pos+=2;

	for(n=0; n<d->numcards; n++) {
		do_card_index(c, d, n, pos);
		pos+=52;
	}

done:
	de_free(c, d);
}

static int de_identify_cardfile(deark *c)
{
	de_byte buf[4];
	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "MGC", 3)) return 80;
	if(!de_memcmp(buf, "RRG", 3)) return 80;
	return 0;
}

void de_module_cardfile(deark *c, struct deark_module_info *mi)
{
	mi->id = "cardfile";
	mi->run_fn = de_run_cardfile;
	mi->identify_fn = de_identify_cardfile;
}
