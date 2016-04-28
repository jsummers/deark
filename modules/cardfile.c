// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract graphics and text from Windows Cardfile .crd format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
#define DE_CRDFMT_MGC 1
#define DE_CRDFMT_RRG 2
	int fmt;
	de_int64 numcards;
} lctx;

static void do_text_data(deark *c, lctx *d, de_finfo *fi, de_int64 text_pos, de_int64 text_len)
{
	if(c->extract_level<2) return;
	if(text_len<1) return;
	if(text_pos + text_len > c->infile->len) return;

	dbuf_create_file_from_slice(c->infile, text_pos, text_len, "txt", fi, 0);
}

static void do_card_index(deark *c, lctx *d, de_int64 cardnum, de_int64 pos)
{
	de_int64 datapos;
	de_int64 bitmap_len;
	de_int64 w, h;
	de_int64 src_rowspan;
	de_int64 text_len;
	de_int64 text_pos;
	struct deark_bitmap *img = NULL;
	de_finfo *fi_bitmap = NULL;
	de_finfo *fi_text = NULL;

	datapos = de_getui32le(pos+6);
	de_dbg(c, "card #%d, data offset = %d\n", (int)cardnum, (int)datapos);

	if(datapos>=c->infile->len) return;
	bitmap_len = de_getui16le(datapos);
	de_dbg(c, "bitmap length: %d\n", (int)bitmap_len);

	if(bitmap_len==0) {
		text_len = de_getui16le(datapos+2);
		text_pos = datapos+4;
	}
	else {
		text_len = de_getui16le(datapos + bitmap_len + 10);
		text_pos = datapos + bitmap_len + 10;
	}
	de_dbg(c, "text length: %d\n", (int)text_len);

	if(bitmap_len==0 && text_len==0) {
		de_dbg(c, "empty card\n");
		goto done;
	}
	if(bitmap_len==0) {
		de_dbg(c, "text-only card\n");
	}
	else if(text_len==0) {
		de_dbg(c, "graphics-only card\n");
	}
	else {
		de_dbg(c, "graphics+text card\n");
	}

	// Text

	if(text_len!=0 && c->extract_level>=2) {
		fi_text = de_finfo_create(c);
		if(c->filenames_from_file)
			de_finfo_set_name_from_slice(c, fi_text, c->infile, pos+11, 40, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);

		do_text_data(c, d, fi_text, text_pos, text_len);
	}

	// Bitmap

	if(bitmap_len==0) goto done;

	fi_bitmap = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_slice(c, fi_bitmap, c->infile, pos+11, 40, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);

	w = de_getui16le(datapos+2);
	h = de_getui16le(datapos+4);
	de_dbg(c, "bitmap dimensions: %dx%d\n", (int)w, (int)h);

	img = de_bitmap_create(c, w, h, 1);
	src_rowspan = ((w+15)/16)*2;

	de_convert_and_write_image_bilevel(c->infile, datapos+10,
		w, h, src_rowspan, 0, fi_bitmap, 0);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi_bitmap);
	de_finfo_destroy(c, fi_text);
}

static void de_run_cardfile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte b;
	de_int64 pos;
	de_int64 n;

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
	mi->desc = "Windows Cardfile address book";
	mi->run_fn = de_run_cardfile;
	mi->identify_fn = de_identify_cardfile;
}
