// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Extract graphics and text from Windows Cardfile .crd format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cardfile);

struct page_ctx {
	i64 cardnum;
	i64 datapos;
	i64 data_endpos;
	i64 text_item_pos;
	de_ucstring *name;
};

typedef struct localctx_struct {
#define DE_CRDFMT_MGC 1
#define DE_CRDFMT_RRG 2
#define DE_CRDFMT_DKO 3
	int fmt;
	de_encoding crd_encoding;
	de_encoding ole_encoding;
	const char *signature;
	i64 numcards;
	i64 data_area_start;
	i64 prev_datapos;
	u8 fatalerrflag;
} lctx;

static void do_extract_text_data(deark *c, lctx *d, de_finfo *fi, i64 text_pos, i64 text_len)
{
	dbuf *outf = NULL;

	if(text_len<1) goto done;
	if(text_pos + text_len > c->infile->len) goto done;

	outf = dbuf_create_output_file(c, "txt", fi, 0);
	dbuf_copy_slice_convert_to_utf8(c->infile, text_pos, text_len,
		DE_EXTENC_MAKE(d->crd_encoding, DE_ENCSUBTYPE_HYBRID),
		outf, 0x2|0x4);
done:
	dbuf_close(outf);
}

static void do_dbg_text_data(deark *c, lctx *d, i64 text_pos, i64 text_len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, text_pos, text_len, DE_DBG_MAX_STRLEN, s,
		0, d->crd_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

// returns 0 if malformed data is found
static int do_bitmap_mgc(deark *c, lctx *d, struct page_ctx *pg)
{
	int retval = 0;
	i64 w, h;
	i64 src_rowspan;
	de_bitmap *img = NULL;
	de_finfo *fi_bitmap = NULL;

	fi_bitmap = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_ucstring(c, fi_bitmap, pg->name, 0);

	w = de_getu16le(pg->datapos+2);
	h = de_getu16le(pg->datapos+4);
	de_dbg(c, "bitmap dimensions: %d"DE_CHAR_TIMES"%d", (int)w, (int)h);

	src_rowspan = ((w+15)/16)*2;
	if(pg->datapos+10 + src_rowspan*h > pg->text_item_pos) {
		goto done;
	}
	if(w==0 || h==0) {
		goto done;
	}

	img = de_bitmap_create(c, w, h, 1);

	de_convert_and_write_image_bilevel2(c->infile, pg->datapos+10,
		w, h, src_rowspan, 0, fi_bitmap, 0);

	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi_bitmap);
	retval = 1;
done:
	return retval;
}

static void do_text(deark *c, lctx *d, struct page_ctx *pg,
	i64 text_pos, i64 text_len)
{
	de_finfo *fi_text = NULL;

	if(text_len<1) goto done;

	if(c->extract_level>=2) {
		fi_text = de_finfo_create(c);
		if(c->filenames_from_file)
			de_finfo_set_name_from_ucstring(c, fi_text, pg->name, 0);

		do_extract_text_data(c, d, fi_text, text_pos, text_len);
	}
	else {
		do_dbg_text_data(c, d, text_pos, text_len);
	}

done:
	de_finfo_destroy(c, fi_text);
}

static void do_carddata_mgc(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 bitmap_len;
	i64 text_len;
	i64 text_pos;
	u8 bad_data_flag = 0;

	bitmap_len = de_getu16le(pg->datapos);
	de_dbg(c, "bitmap length: %d", (int)bitmap_len);
	if(bitmap_len==0) {
		pg->text_item_pos = pg->datapos+2;
	}
	else {
		pg->text_item_pos = pg->datapos + 10 + bitmap_len;
	}
	text_pos = pg->text_item_pos+2;

	if(pg->text_item_pos > pg->data_endpos-2) {
		bad_data_flag = 1;
		goto done;
	}

	// Look ahead at the text length field, to help detect errors.
	text_len = de_getu16le(pg->text_item_pos);
	de_dbg(c, "text length: %d", (int)text_len);

	// I don't understand this, but I have a file with some cards in which the
	// high byte of the text length seems to be unused and set to 0xff.
	if((text_pos+text_len > pg->data_endpos) && ((text_len&0xff00)==0xff00) &&
		(text_pos+(text_len & 0x00ff)==pg->data_endpos))
	{
		text_len = text_len & 0x00ff;
	}

	if(text_pos+text_len > pg->data_endpos) {
		bad_data_flag = 1;
		goto done;
	}

	if(bitmap_len!=0) {
		if(!do_bitmap_mgc(c, d, pg)) {
			bad_data_flag = 1;
			goto done;
		}
	}

	if(text_len!=0) {
		do_text(c, d, pg, text_pos, text_len);
	}

done:
	if(bad_data_flag) {
		de_err(c, "card #%d: Malformed data segment", (int)pg->cardnum);
	}
}

static int do_object_rrg(deark *c, lctx *d, struct page_ctx *pg, i64 pos1,
	i64 *bytes_consumed)
{
	de_module_params *mparams = NULL;
	i64 pos = pos1;
	i64 n1, n2, n3, n4;
	int retval = 0;

	n1 = de_getu32le_p(&pos);
	de_dbg(c, "object ID: 0x%08x", (unsigned int)n1);

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "U";
	mparams->in_params.input_encoding = d->ole_encoding;

	// TODO: Make the output filenames contain the index text
	de_dbg(c, "OLE1 data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "ole1", mparams, c->infile, pos,
		pg->data_endpos-2-14-pos);
	de_dbg_indent(c, -1);

	// Unfortunately, there is no direct way to figure out the OLE object size,
	// and we need it to find the card's text (and to know whether it has text).
	// The ole1 module will try to tell us the size, but this feature needs more
	// work, and is difficult to test.

	if(mparams->out_params.flags & 0x1) {
		pos += mparams->out_params.int64_1;
	}
	else {
		// ole1 module failed to figure out the object size
		goto done;
	}
	de_dbg(c, "[OLE object ends at %"I64_FMT"]", pos);

	n1 = de_getu16le_p(&pos);
	n2 = de_getu16le_p(&pos);
	de_dbg(c, "char width,height: %d,%d", (int)n1, (int)n2);

	n1 = de_geti16le_p(&pos);
	n2 = de_geti16le_p(&pos);
	n3 = de_getu16le_p(&pos);
	n4 = de_getu16le_p(&pos);
	de_dbg(c, "rect: %d,%d,%d,%d", (int)n1, (int)n2, (int)n3, (int)n4);

	n1 = de_getu16le_p(&pos);
	de_dbg(c, "object type: %d", (int)n1);

	*bytes_consumed = pos - pos1;
	retval = 1;
done:
	de_free(c, mparams);
	return retval;
}

static void do_carddata_rrg(deark *c, lctx *d, struct page_ctx *pg)
{
	unsigned int flags;
	int ret;
	i64 text_len;
	i64 pos = pg->datapos;

	flags = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "flags: %u", flags);
	if(flags) {
		i64 bytes_consumed = 0;
		ret = do_object_rrg(c, d, pg, pos, &bytes_consumed);
		if(!ret || bytes_consumed<1) {
			de_warn(c, "card #%d: Failed to parse OLE object; any text on this card "
				"cannot be processed.", (int)pg->cardnum);
			goto done;
		}
		pos += bytes_consumed;
	}

	text_len = de_getu16le_p(&pos);
	de_dbg(c, "text length: %d", (int)text_len);
	if(pos+text_len > pg->data_endpos) {
		de_err(c, "card #%d: Malformed data segment", (int)pg->cardnum);
		goto done;
	}
	if(text_len!=0) {
		do_text(c, d, pg, pos, text_len);
	}

done:
	;
}

#define CRD_INDEX_ITEM_LEN 52

// Process a card, given the offset of its index
static void do_card(deark *c, lctx *d, i64 cardnum, i64 pos)
{
	int saved_indent_level;
	i64 avail_data;
	u8 bad_datapos_flag = 0;
	struct page_ctx *pg = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	pg = de_malloc(c, sizeof(struct page_ctx));
	pg->cardnum = cardnum;
	de_dbg(c, "card #%d", (int)pg->cardnum);
	de_dbg_indent(c, 1);
	de_dbg(c, "index at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pg->datapos = de_getu32le(pos+6);
	de_dbg(c, "datapos: %"I64_FMT, pg->datapos);

	pg->name = ucstring_create(c);
	if(d->crd_encoding==DE_ENCODING_UTF16LE) {
		dbuf_read_to_ucstring(c->infile, pos+11, 40, pg->name, 0,
			d->crd_encoding);
		ucstring_truncate_at_NUL(pg->name);
	}
	else {
		dbuf_read_to_ucstring(c->infile, pos+11, 40, pg->name, DE_CONVFLAG_STOP_AT_NUL,
			d->crd_encoding);
	}
	de_dbg(c, "index text: \"%s\"", ucstring_getpsz_d(pg->name));

	// We're strict about the data items appearing in the same order as the
	// index items. In practice, they always seem to. There are a number of
	// seemingly malformed files out there, and this helps to detect if we've
	// gone off the rails.
	if(pg->datapos<d->data_area_start || pg->datapos>c->infile->len ||
		pg->datapos<d->prev_datapos)
	{
		bad_datapos_flag = 1;
		d->fatalerrflag = 1;
		goto done;
	}

	d->prev_datapos = pg->datapos;

	avail_data = c->infile->len - pg->datapos; // default
	if(pg->cardnum<(d->numcards-1)) { // if this is NOT the last card
		i64 next_card_dpos;

		// peek at the next card's data pointer
		next_card_dpos = de_getu32le(pos+CRD_INDEX_ITEM_LEN+6);
		if(next_card_dpos>pg->datapos && next_card_dpos<c->infile->len) {
			avail_data = next_card_dpos - pg->datapos;
		}
	}

	de_dbg2(c, "avail data: %"I64_FMT, avail_data);

	if(avail_data<2) {
		bad_datapos_flag = 1;
		goto done;
	}

	pg->data_endpos = pg->datapos + avail_data;

	de_dbg_indent(c, -1);

	de_dbg(c, "data at %"I64_FMT, pg->datapos);
	de_dbg_indent(c, 1);

	if(d->fmt==DE_CRDFMT_RRG) {
		do_carddata_rrg(c, d, pg);
	}
	else {
		do_carddata_mgc(c, d, pg);
	}

done:
	if(bad_datapos_flag) {
		de_err(c, "card #%d: Bad data pointer", (int)pg->cardnum);
	}
	if(pg) {
		ucstring_destroy(pg->name);
		de_free(c, pg);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int detect_crd_fmt(deark *c)
{
	u8 buf[4];
	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "MGC", 3)) return DE_CRDFMT_MGC;
	if(!de_memcmp(buf, "RRG", 3)) return DE_CRDFMT_RRG;
	if(!de_memcmp(buf, "DKO", 3)) return DE_CRDFMT_DKO;
	return 0;
}

static void de_run_cardfile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 n;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	d->fmt = detect_crd_fmt(c);
	if(d->fmt==DE_CRDFMT_MGC) {
		d->signature = "MGC";
		de_declare_fmt(c, "CardFile");
	}
	else if(d->fmt==DE_CRDFMT_RRG) {
		d->signature = "RRG";
		de_declare_fmt(c, "CardFile, with objects");
	}
	else if(d->fmt==DE_CRDFMT_DKO) {
		d->signature = "DKO";
		de_declare_fmt(c, "CardFile, Unicode");
	}
	else {
		de_err(c, "This is not a known/supported CardFile format");
		goto done;
	}
	de_dbg(c, "signature: %s", d->signature);
	pos+=3;

	if(d->fmt==DE_CRDFMT_DKO) {
		// TODO: Samples needed
		de_warn(c, "Unicode Cardfile files might not be supported correctly");
	}

	// Microsoft's (old) Cardfile format documentation says that text is in "low
	// ASCII format", but that seems doubtful on the face of it, and indeed I have
	// seen files where it is not.
	d->ole_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	if(d->fmt==DE_CRDFMT_DKO) {
		d->crd_encoding = DE_ENCODING_UTF16LE;
	}
	else {
		d->crd_encoding = d->ole_encoding;
	}

	if(d->fmt==DE_CRDFMT_RRG) {
		pos += 4; // Last object's ID
	}

	d->numcards = de_getu16le_p(&pos);
	de_dbg(c, "number of cards: %d", (int)d->numcards);

	d->data_area_start = pos + CRD_INDEX_ITEM_LEN*d->numcards;

	for(n=0; n<d->numcards; n++) {
		if(d->fatalerrflag) goto done;
		if(pos+CRD_INDEX_ITEM_LEN > c->infile->len) goto done;
		do_card(c, d, n, pos);
		pos += CRD_INDEX_ITEM_LEN;
	}

done:
	de_free(c, d);
}

static int de_identify_cardfile(deark *c)
{
	int fmt;

	fmt = detect_crd_fmt(c);
	if(fmt!=0) {
		return 80;
	}
	return 0;
}

void de_module_cardfile(deark *c, struct deark_module_info *mi)
{
	mi->id = "cardfile";
	mi->desc = "Windows Cardfile address book";
	mi->run_fn = de_run_cardfile;
	mi->identify_fn = de_identify_cardfile;
}
