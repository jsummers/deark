// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// SAUCE
// Special module that reads SAUCE metadata for other modules to use,
// and handles files with SAUCE records if they aren't otherwise handled.
// SAUCE = Standard Architecture for Universal Comment Extensions

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_sauce);

struct sauce_private_ctx {
	int combine_comments;
	i64 num_comments;
};

static i64 sauce_get_string_length(const u8 *buf, i64 len, int respect_trailing_spaces)
{
	i64 i;
	i64 last_nonpadding_char_pos = -1;

	for(i=len-1; i>=0; i--) {
		// Spec says to use spaces for padding, and for nonexistent data.
		// But some files use NUL bytes.
		if((buf[i]==0x20 && !respect_trailing_spaces) || buf[i]==0x00) {
			;
		}
		else {
			last_nonpadding_char_pos = i;
			break;
		}
	}
	return last_nonpadding_char_pos+1;
}

static void sauce_strip_trailing_whitespace(de_ucstring *s)
{
	while(s->len>=1 &&
		(s->str[s->len-1]==' ' || s->str[s->len-1]==0x0a)) {
		ucstring_truncate(s, s->len-1);
	}
}

// TODO?: This function could read a dbuf instead of a u8 array, but it
// would have to be combined with sauce_get_string_length() somehow.
//
// flags: 0x02: Interpret 0x0a as newline, regardless of encoding
static void sauce_bytes_to_ucstring(deark *c, const u8 *buf, i64 len,
	de_ucstring *s, de_encoding encoding, unsigned int flags)
{
	i32 u;
	i64 i;

	for(i=0; i<len; i++) {
		if((flags&0x02) && buf[i]==0x0a) {
			u = 0x000a;
		}
		else {
			u = de_char_to_unicode(c, (i32)buf[i], encoding);
		}
		ucstring_append_char(s, u);
	}
}

static int sauce_is_valid_date_string(const u8 *buf, i64 len)
{
	i64 i;

	for(i=0; i<len; i++) {
		if(buf[i]>='0' && buf[i]<='9') continue;
		// Spaces aren't allowed, but some files use them.
		if(buf[i]==' ' && (i==4 || i==6)) continue;
		return 0;
	}
	return 1;
}

static const char *get_sauce_datatype_name(u8 dt)
{
	const char *n = "?";

	switch(dt) {
	case 0: n="undefined"; break;
	case 1: n="character"; break;
	case 2: n="bitmap graphics"; break;
	case 3: n="vector graphics"; break;
	case 4: n="audio"; break;
	case 5: n="BinaryText"; break;
	case 6: n="XBIN"; break;
	case 7: n="archive"; break;
	case 8: n="executable"; break;
	}
	return n;
}

static const char *get_sauce_filetype_name(u8 dt, unsigned int t)
{
	const char *n = "?";

	if(dt==5) return "=width/2";
	switch(t) {
	case 0x0100: n="ASCII"; break;
	case 0x0101: n="ANSI"; break;
	case 0x0102: n="ANSiMation"; break;
	case 0x0103: n="RIP script"; break;
	case 0x0104: n="PCBoard"; break;
	case 0x0105: n="Avatar"; break;
	case 0x0106: n="HTML"; break;
	case 0x0108: n="TundraDraw"; break;
	case 0x0200: n="GIF"; break;
	case 0x0206: n="BMP"; break;
	case 0x020a: n="PNG"; break;
	case 0x020b: n="JPEG"; break;
	case 0x0600: n="XBIN"; break;
	case 0x0800: n="executable"; break;
	}
	// There are many more SAUCE file types defined, but it's not clear how
	// many have actually been used.

	return n;
}

// The SAUCE spec has insufficient detail about how comments are to be
// interpreted. And some ANSI editors don't obey the spec, anyway.
// Our behavior:
// * We have two modes, depending on the combine_comments flag.
// * We interpret 0x0a as a newline. All other bytes are CP437 printable
//   charaters.
// * If !combine_comments, trailing spaces and NUL bytes are ignored for
//   each comment.
// * If combine_comments, same as above except that trailing spaces are
//   respected for each comment except the last.
// * If !combine_comments, we add a newline after every comment except the
//   last.
// (Autodetecting which mode to use would be nice, and it's possible to make
// a pretty good guess, but it's not possible to get it right every time.)
static void sauce_read_comments(deark *c, struct sauce_private_ctx *d, dbuf *inf,
	struct de_SAUCE_info *si)
{
	i64 cmnt_blk_start;
	i64 k;
	i64 cmnt_pos;
	i64 cmnt_len;
	u8 buf[64];
	de_ucstring *tmpcomment = NULL;

	if(d->num_comments<1) goto done;
	cmnt_blk_start = inf->len - 128 - (5 + d->num_comments*64);

	if(dbuf_memcmp(inf, cmnt_blk_start, "COMNT", 5)) {
		de_dbg(c, "invalid SAUCE comment, not found at %d", (int)cmnt_blk_start);
		d->num_comments = 0;
		goto done;
	}

	de_dbg(c, "SAUCE comment block at %d", (int)cmnt_blk_start);

	si->comment = ucstring_create(c);
	tmpcomment = ucstring_create(c);

	de_dbg_indent(c, 1);
	for(k=0; k<d->num_comments; k++) {
		int respect_trailing_spaces = 0;

		cmnt_pos = cmnt_blk_start+5+k*64;
		dbuf_read(inf, buf, cmnt_pos, 64);

		if(d->combine_comments && k!=(d->num_comments-1)) {
			respect_trailing_spaces = 1;
		}
		cmnt_len = sauce_get_string_length(buf, 64, respect_trailing_spaces);

		de_dbg(c, "comment at %d, len=%d", (int)cmnt_pos, (int)cmnt_len);
		de_dbg_indent(c, 1);

		ucstring_empty(tmpcomment);
		sauce_bytes_to_ucstring(c, buf, cmnt_len, tmpcomment, DE_ENCODING_CP437_G, 0x02);
		ucstring_append_ucstring(si->comment, tmpcomment);
		if(!d->combine_comments && k!=(d->num_comments-1)) {
			ucstring_append_char(si->comment, 0x0a);
		}

		de_dbg(c, "comment: \"%s\"", ucstring_getpsz(tmpcomment));
		de_dbg_indent(c, -1);
	}

	sauce_strip_trailing_whitespace(si->comment);
	if(ucstring_isempty(si->comment)) {
		ucstring_destroy(si->comment);
		si->comment = NULL;
		goto done;
	}

	if(c->extract_level>=2) {
		dbuf *cmnt_outf = NULL;

		cmnt_outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, si->comment, cmnt_outf, 1);
		dbuf_puts(cmnt_outf, "\n");
		dbuf_close(cmnt_outf);
	}

	de_dbg_indent(c, -1);

done:
	ucstring_destroy(tmpcomment);
}

static void do_SAUCE_creation_date(deark *c, struct de_SAUCE_info *si,
	const u8 *date_raw, size_t date_raw_len)
{
	i64 yr, mon, mday;
	char timestamp_buf[64];
	char scanbuf[16];

	if(date_raw_len!=8) return;

	// Convert to de_timestamp format

	// year
	de_memcpy(scanbuf, &date_raw[0], 4);
	scanbuf[4] = '\0';
	yr = de_atoi64(scanbuf);

	// month
	de_memcpy(scanbuf, &date_raw[4], 2);
	scanbuf[2] = '\0';
	mon = de_atoi64(scanbuf);

	// day of month
	de_memcpy(scanbuf, &date_raw[6], 2);
	scanbuf[2] = '\0';
	mday = de_atoi64(scanbuf);

	de_make_timestamp(&si->creation_date, yr, mon, mday, 12, 0, 0);
	si->creation_date.precision = DE_TSPREC_1DAY;

	de_timestamp_to_string(&si->creation_date, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "creation date: %s", timestamp_buf);
}

// Caller allocates si using de_create_SAUCE().
// Caller must later free si using de_free_SAUCE().
static int do_read_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si)
{
	unsigned int t;
	u8 tmpbuf[40];
	i64 tmpbuf_len;
	i64 pos;
	const char *name;
	de_ucstring *tflags_descr = NULL;
	int retval = 0;
	struct sauce_private_ctx *d = NULL;

	pos = f->len - 128;
	if(dbuf_memcmp(f, pos+0, "SAUCE00", 7)) {
		goto done;
	}

	si->is_valid = 1;

	d = de_malloc(c, sizeof(struct sauce_private_ctx));
	d->combine_comments = de_get_ext_option_bool(c, "sauce:combinecomments", 0);

	// Title
	dbuf_read(f, tmpbuf, pos+7, 35);
	tmpbuf_len = sauce_get_string_length(tmpbuf, 35, 0);
	if(tmpbuf_len>0) {
		si->title = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->title, DE_ENCODING_CP437_G, 0);
	}

	// Artist / Creator
	dbuf_read(f, tmpbuf, pos+42, 20);
	tmpbuf_len = sauce_get_string_length(tmpbuf, 20, 0);
	if(tmpbuf_len>0) {
		si->artist = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->artist, DE_ENCODING_CP437_G, 0);
	}

	// Organization
	dbuf_read(f, tmpbuf, pos+62, 20);
	tmpbuf_len = sauce_get_string_length(tmpbuf, 20, 0);
	if(tmpbuf_len>0) {
		si->organization = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->organization, DE_ENCODING_CP437_G, 0);
	}

	// Creation date
	dbuf_read(f, tmpbuf, pos+82, 8);
	if(sauce_is_valid_date_string(tmpbuf, 8)) {
		do_SAUCE_creation_date(c, si, tmpbuf, 8);
	}

	si->original_file_size = dbuf_getu32le(f, pos+90);
	de_dbg(c, "original file size: %d", (int)si->original_file_size);

	si->data_type = dbuf_getbyte(f, pos+94);
	name = get_sauce_datatype_name(si->data_type);
	de_dbg(c, "data type: %d (%s)", (int)si->data_type, name);

	si->file_type = dbuf_getbyte(f, pos+95);
	t = 256*(unsigned int)si->data_type + si->file_type;
	name = get_sauce_filetype_name(si->data_type, t);
	de_dbg(c, "file type: %d (%s)", (int)si->file_type, name);

	si->tinfo1 = (u16)dbuf_getu16le(f, pos+96);
	si->tinfo2 = (u16)dbuf_getu16le(f, pos+98);
	si->tinfo3 = (u16)dbuf_getu16le(f, pos+100);
	si->tinfo4 = (u16)dbuf_getu16le(f, pos+102);
	de_dbg(c, "TInfo1: %u", (unsigned int)si->tinfo1);
	de_dbg(c, "TInfo2: %u", (unsigned int)si->tinfo2);
	de_dbg(c, "TInfo3: %u", (unsigned int)si->tinfo3);
	de_dbg(c, "TInfo4: %u", (unsigned int)si->tinfo4);

	if(t==0x0100 || t==0x0101 || t==0x0102 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->width_in_chars = (i64)si->tinfo1;
		de_dbg(c, "width in chars: %d", (int)si->width_in_chars);
	}
	if(t==0x0100 || t==0x0101 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->number_of_lines = (i64)si->tinfo2;
		de_dbg(c, "number of lines: %d", (int)si->number_of_lines);
	}

	d->num_comments = (i64)dbuf_getbyte(f, pos+104);
	de_dbg(c, "num comments: %d", (int)d->num_comments);
	if(d->num_comments>0) {
		sauce_read_comments(c, d, f, si);
	}

	si->tflags = dbuf_getbyte(f, pos+105);
	if(si->tflags!=0) {
		tflags_descr = ucstring_create(c);
		if(t==0x0100 || t==0x0101 || t==0x0102 || si->data_type==5) {
			// ANSiFlags
			if(si->tflags&0x01) {
				ucstring_append_flags_item(tflags_descr, "non-blink mode");
			}
			if((si->tflags & 0x06)>>1 == 1) {
				ucstring_append_flags_item(tflags_descr, "8-pixel font");
			}
			else if((si->tflags & 0x06)>>1 == 2) {
				ucstring_append_flags_item(tflags_descr, "9-pixel font");
			}
			if((si->tflags & 0x18)>>3 == 1) {
				ucstring_append_flags_item(tflags_descr, "non-square pixels");
			}
			else if((si->tflags & 0x18)>>3 == 2) {
				ucstring_append_flags_item(tflags_descr, "square pixels");
			}

		}
		de_dbg(c, "tflags: 0x%02x (%s)", (unsigned int)si->tflags,
			ucstring_getpsz(tflags_descr));
	}

	if(si->original_file_size==0 || si->original_file_size>f->len-128) {
		// If this field seems bad, try to correct it.
		si->original_file_size = f->len-128-(5+d->num_comments*64);
	}

	retval = 1;
done:
	ucstring_destroy(tflags_descr);
	de_free(c, d);
	return retval;
}

// When running as a submodule, we assume the caller already detected the
// presence of SAUCE (probably using detect_SAUCE()), printed a header line
// (again probably using detect_SAUCE()), and indented as needed.
static void run_sauce_as_submodule(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si_local = NULL;
	struct de_SAUCE_info *si_to_use;

	if(mparams && mparams->out_params.obj1) {
		si_to_use = (struct de_SAUCE_info*)mparams->out_params.obj1;
	}
	else {
		si_local = de_fmtutil_create_SAUCE(c);
		si_to_use = si_local;
	}

	do_read_SAUCE(c, c->infile, si_to_use);

	de_fmtutil_free_SAUCE(c, si_local);
}

static void run_sauce_direct(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si = NULL;
	struct de_SAUCE_detection_data sdd;
	int ret;

	de_fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(!sdd.has_SAUCE) {
		if(c->module_disposition==DE_MODDISP_EXPLICIT) {
			de_err(c, "No SAUCE record found");
		}
		goto done;
	}

	si = de_fmtutil_create_SAUCE(c);
	de_dbg_indent(c, 1);
	ret = do_read_SAUCE(c, c->infile, si);
	de_dbg_indent(c, -1);
	if(ret && c->module_disposition==DE_MODDISP_AUTODETECT) {
		de_err(c, "This file has a SAUCE metadata record that identifies it as "
			"DataType %d, FileType %d, but it is not a supported format.",
			(int)si->data_type, (int)si->file_type);
	}

done:
	de_fmtutil_free_SAUCE(c, si);
}

static void de_run_sauce(deark *c, de_module_params *mparams)
{
	if(c->module_disposition==DE_MODDISP_INTERNAL) {
		run_sauce_as_submodule(c, mparams);
	}
	else {
		run_sauce_direct(c, mparams);
	}
}

static int de_identify_sauce(deark *c)
{
	c->detection_data->SAUCE_detection_attempted = 1;
	if(de_fmtutil_detect_SAUCE(c, c->infile, &c->detection_data->sauce, 0)) {
		// This module should have a very low priority, but other modules can use
		// the results of its detection.
		return 2;
	}
	return 0;
}

void de_module_sauce(deark *c, struct deark_module_info *mi)
{
	mi->id = "sauce";
	mi->desc = "SAUCE metadata";
	mi->run_fn = de_run_sauce;
	mi->identify_fn = de_identify_sauce;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_SHAREDDETECTION;
}
