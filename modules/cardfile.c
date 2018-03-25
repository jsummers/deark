// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Extract graphics and text from Windows Cardfile .crd format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cardfile);

typedef struct localctx_struct {
#define DE_CRDFMT_MGC 1
#define DE_CRDFMT_RRG 2
	int fmt;
	int input_encoding;
	de_int64 numcards;
} lctx;

static void do_extract_text_data(deark *c, lctx *d, de_finfo *fi, de_int64 text_pos, de_int64 text_len)
{
	if(text_len<1) return;
	if(text_pos + text_len > c->infile->len) return;

	// TODO: Consider trying to convert to UTF-8, especially if the user used the
	// "inenc" option.
	dbuf_create_file_from_slice(c->infile, text_pos, text_len, "txt", fi, 0);
}

static void do_dbg_text_data(deark *c, lctx *d, de_int64 text_pos, de_int64 text_len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, text_pos, text_len, DE_DBG_MAX_STRLEN, s,
		0, c->input_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_card_index(deark *c, lctx *d, de_int64 cardnum, de_int64 pos)
{
	de_int64 datapos;
	de_int64 bitmap_len;
	de_int64 w, h;
	de_int64 src_rowspan;
	de_int64 text_len;
	de_int64 text_pos;
	de_bitmap *img = NULL;
	de_finfo *fi_bitmap = NULL;
	de_finfo *fi_text = NULL;
	const char *cardtype;
	de_ucstring *name = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	datapos = de_getui32le(pos+6);
	de_dbg(c, "card #%d at %d, dpos=%d", (int)cardnum, (int)pos, (int)datapos);
	de_dbg_indent(c, 1);

	if(datapos>=c->infile->len) goto done;
	bitmap_len = de_getui16le(datapos);
	de_dbg(c, "bitmap length: %d", (int)bitmap_len);

	if(bitmap_len==0) {
		text_len = de_getui16le(datapos+2);
		text_pos = datapos+4;
	}
	else {
		text_len = de_getui16le(datapos + 10 + bitmap_len);
		text_pos = datapos + 10 + bitmap_len +2;
	}
	de_dbg(c, "text length: %d", (int)text_len);

	if(bitmap_len==0 && text_len==0) {
		cardtype = "empty";
	}
	else if(bitmap_len==0) {
		cardtype = "text-only";
	}
	else if(text_len==0) {
		cardtype = "graphics-only";
	}
	else {
		cardtype = "graphics+text";
	}
	de_dbg(c, "card type: %s", cardtype);

	if(bitmap_len==0 && text_len==0) {
		goto done;
	}

	name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+11, 40, name, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(name));

	// Text

	if(text_len!=0) {
		if(c->extract_level>=2) {
			fi_text = de_finfo_create(c);
			if(c->filenames_from_file)
				de_finfo_set_name_from_ucstring(c, fi_text, name);

			do_extract_text_data(c, d, fi_text, text_pos, text_len);
		}
		else {
			do_dbg_text_data(c, d, text_pos, text_len);
		}
	}

	// Bitmap

	if(bitmap_len==0) goto done;

	fi_bitmap = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_ucstring(c, fi_bitmap, name);

	w = de_getui16le(datapos+2);
	h = de_getui16le(datapos+4);
	de_dbg(c, "bitmap dimensions: %d"DE_CHAR_TIMES"%d", (int)w, (int)h);

	img = de_bitmap_create(c, w, h, 1);
	src_rowspan = ((w+15)/16)*2;

	de_convert_and_write_image_bilevel(c->infile, datapos+10,
		w, h, src_rowspan, 0, fi_bitmap, 0);

done:
	ucstring_destroy(name);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi_bitmap);
	de_finfo_destroy(c, fi_text);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_cardfile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte b;
	de_int64 pos;
	de_int64 n;

	d = de_malloc(c, sizeof(lctx));

	// Microsoft's (old) Cardfile format documentation says that text is in "low
	// ASCII format", but that seems doubtful on the face of it, and indeed I have
	// seen files where it is not.
	if(c->input_encoding==DE_ENCODING_UNKNOWN)
		d->input_encoding = DE_ENCODING_WINDOWS1252;
	else
		d->input_encoding = c->input_encoding;

	pos = 0;
	b = de_getbyte(pos);
	if(b=='R') d->fmt=DE_CRDFMT_RRG;
	else d->fmt=DE_CRDFMT_MGC;

	if(d->fmt==DE_CRDFMT_RRG) {
		de_err(c, "CardFile RRG format is not supported");
		goto done;
	}

	pos+=3;

	d->numcards = de_getui16le(pos);
	de_dbg(c, "number of cards: %d", (int)d->numcards);
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
