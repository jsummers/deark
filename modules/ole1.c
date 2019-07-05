// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// OLE1.0 objects

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ole1);

typedef struct localctx_struct {
	int input_encoding;
	int extract_all;
} lctx;

static const char *get_FormatID_name(unsigned int t)
{
	const char *name;
	switch(t) {
	case 0: name="none"; break;
	case 1: name="linked"; break;
	case 2: name="embedded"; break;
	case 3: name="static"; break;
	case 5: name="presentation"; break;
	default: name="?"; break;
	}
	return name;
}

static void do_static_bitmap(deark *c, lctx *d, i64 pos1)
{
	i64 dlen;
	i64 pos = pos1;

	pos += 8; // ??
	dlen = de_getu32le_p(&pos);
	de_dbg(c, "bitmap size: %d", (int)dlen);

	de_dbg(c, "BITMAP16 at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "ddb", "N", c->infile, pos,
		c->infile->len-pos);
	de_dbg_indent(c, -1);
}

// Presentation object, or WRI-static-"OLE" object.
// pos1 points to the first field after FormatID (classname/typename)
static int do_ole_object_presentation(deark *c, lctx *d,
	i64 pos1, i64 len, unsigned int formatID, i64 *bytes_consumed)
{
	i64 pos = pos1;
	i64 stringlen;
	struct de_stringreaderdata *classname_srd = NULL;
	struct de_stringreaderdata *clipfmtname_srd = NULL;
	const char *name;
	int retval = 0;

	name = (formatID==3)?"static":"presentation";
	stringlen = de_getu32le_p(&pos);
	classname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "%s ClassName: \"%s\"", name, ucstring_getpsz(classname_srd->str));
	pos += stringlen;

	// TODO: Better handle the fields between ClassName and PresentationData
	// (and maybe after PresentationData?).

	if(!de_strcmp(classname_srd->sz, "DIB")) {
		pos += 12;
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice(c, "dib", NULL, c->infile, pos,
			pos1+len-pos);
		de_dbg_indent(c, -1);
		goto done; // FIXME, calculate length
	}
	else if(!de_strcmp(classname_srd->sz, "METAFILEPICT")) {
		i64 dlen;
		pos += 8; // ??
		dlen = de_getu32le_p(&pos);
		de_dbg(c, "metafile size: %d", (int)dlen); // Includes "mfp", apparently
		pos += 8; // "mfp" struct
		dbuf_create_file_from_slice(c->infile, pos, dlen-8, "wmf", NULL, 0);
		pos += dlen-8;
	}
	else if(!de_strcmp(classname_srd->sz, "BITMAP")) {
		do_static_bitmap(c, d, pos);
		goto done; // FIXME, calculate length
	}
	else {
		u32 clipfmt;
		i64 clp_data_size;
		u8 buf[16];

		// This is a GenericPresentationObject, a.k.a. clipboard format,
		// either a StandardClipboardFormatPresentationObject
		// or a RegisteredClipboardFormatPresentationObject.
		clipfmt = (u32)de_getu32le_p(&pos);
		de_dbg(c, "clipboard fmt: %u", (unsigned int)clipfmt);

		if(clipfmt==0) {
			stringlen = de_getu32le_p(&pos);
			clipfmtname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
				d->input_encoding);
			de_dbg(c, "clipboard fmt name: \"%s\"", ucstring_getpsz(clipfmtname_srd->str));
			pos += stringlen;
		}

		clp_data_size = de_getu32le_p(&pos);
		de_dbg(c, "clipboard data size: %"I64_FMT, clp_data_size);

		de_read(buf, pos, de_min_int((i64)sizeof(buf), clp_data_size));

		if(clipfmtname_srd) {
			if(!de_strcmp(classname_srd->sz, "PBrush") &&
				buf[0]=='B' && buf[1]=='M')
			{
				dbuf_create_file_from_slice(c->infile, pos, clp_data_size, "bmp", NULL, 0);
			}
			else {
				de_warn(c, "OLE clipboard type (\"%s\"/\"%s\") is not supported",
					ucstring_getpsz(classname_srd->str),
					ucstring_getpsz(clipfmtname_srd->str));
			}
		}
		else {
			de_warn(c, "OLE clipboard type %u is not supported", (unsigned int)clipfmt);
		}

		pos += clp_data_size;
	}

	*bytes_consumed = pos-pos1;
	retval = 1;

done:
	de_destroy_stringreaderdata(c, classname_srd);
	de_destroy_stringreaderdata(c, clipfmtname_srd);
	return retval;
}

// Note: This function is based on reverse engineering, and may not be correct.
static int do_ole_package(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 endpos = pos1+len;
	i64 pos = pos1;
	struct de_stringreaderdata *caption = NULL;
	struct de_stringreaderdata *iconsrc = NULL;
	de_ucstring *filename = NULL;
	de_finfo *fi = NULL;
	unsigned int type_code1, type_code2;
	i64 n, fnlen, fsize;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "package at %"I64_FMT", len=%"I64_FMT, pos, len);
	de_dbg_indent(c, 1);
	type_code1 = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "stream header code: %u", type_code1);
	if(type_code1 != 2) {
		de_dbg(c, "[unknown package format]");
		goto done;
	}

	caption = dbuf_read_string(c->infile, pos, de_min_int(256, endpos-pos), 256,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	if(!caption->found_nul) goto done;
	de_dbg(c, "caption: \"%s\"", ucstring_getpsz_d(caption->str));
	pos += caption->bytes_consumed;

	iconsrc = dbuf_read_string(c->infile, pos, de_min_int(256, endpos-pos), 256,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	if(!iconsrc->found_nul) goto done;
	de_dbg(c, "icon source: \"%s\"", ucstring_getpsz_d(iconsrc->str));
	pos += iconsrc->bytes_consumed;

	n = de_getu16le_p(&pos);
	de_dbg(c, "icon #: %d", (int)n);

	type_code2 = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "package type: %u", type_code2);

	if(type_code2!=3) {
		// Code 1 apparently means "run a program".
		de_dbg(c, "[not an embedded file]");
		goto done;
	}

	// A package can contain an arbitrary embedded file, which we'll try to
	// extract.

	fnlen = de_getu32le_p(&pos);
	if(pos+fnlen > endpos) goto done;
	filename = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, fnlen, 256, filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(filename));
	pos += fnlen;

	fsize = de_getu32le_p(&pos);
	de_dbg(c, "file size: %"I64_FMT, fsize);
	if(pos+fsize > endpos) goto done;

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, filename, 0);
	dbuf_create_file_from_slice(c->infile, pos, fsize, NULL, fi, 0);
	retval = 1;

done:
	de_destroy_stringreaderdata(c, caption);
	de_destroy_stringreaderdata(c, iconsrc);
	ucstring_destroy(filename);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void extract_unknown_ole_obj(deark *c, lctx *d, i64 pos, i64 len,
	struct de_stringreaderdata *classname_srd)
{
	de_finfo *fi = NULL;
	de_ucstring *s = NULL;

	fi = de_finfo_create(c);
	s = ucstring_create(c);

	ucstring_append_sz(s, "oleobj", DE_ENCODING_LATIN1);
	if(ucstring_isnonempty(classname_srd->str)) {
		ucstring_append_sz(s, ".", DE_ENCODING_LATIN1);
		ucstring_append_ucstring(s, classname_srd->str);
	}

	de_finfo_set_name_from_ucstring(c, fi, s, 0);

	dbuf_create_file_from_slice(c->infile, pos, len, "bin", fi, 0);

	ucstring_destroy(s);
	de_finfo_destroy(c, fi);
}

static int do_ole_object(deark *c, lctx *d, i64 pos1, i64 len, int exact_size_known,
	int is_presentation, i64 *bytes_consumed);

static int do_ole_object_linked(deark *c, lctx *d,
	i64 pos1, i64 len, int exact_size_known, i64 *bytes_consumed)
{
	i64 pos = pos1;
	i64 stringlen;
	i64 bytes_consumed2 = 0;
	int ret;
	struct de_stringreaderdata *classname_srd = NULL;
	struct de_stringreaderdata *topicname_srd = NULL;
	struct de_stringreaderdata *itemname_srd = NULL;
	struct de_stringreaderdata *networkname_srd = NULL;
	int retval = 0;

	stringlen = de_getu32le_p(&pos);
	classname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "embedded ClassName: \"%s\"", ucstring_getpsz(classname_srd->str));
	pos += stringlen;

	stringlen = de_getu32le_p(&pos);
	topicname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "TopicName/filename: \"%s\"", ucstring_getpsz(topicname_srd->str));
	pos += stringlen;

	stringlen = de_getu32le_p(&pos);
	itemname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "ItemName/params: \"%s\"", ucstring_getpsz(itemname_srd->str));
	pos += stringlen;

	stringlen = de_getu32le_p(&pos);
	networkname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "NetworkName: \"%s\"", ucstring_getpsz(networkname_srd->str));
	pos += stringlen;

	pos += 4; // reserved
	pos += 4; // LinkUpdateOption

	// Nested "presentation" object
	ret = do_ole_object(c, d, pos, pos1+len-pos, exact_size_known, 1,
		&bytes_consumed2);
	if(!ret) goto done;
	pos += bytes_consumed2;

	*bytes_consumed = pos-pos1;
	retval = 1;

done:
	de_destroy_stringreaderdata(c, classname_srd);
	de_destroy_stringreaderdata(c, topicname_srd);
	de_destroy_stringreaderdata(c, itemname_srd);
	de_destroy_stringreaderdata(c, networkname_srd);
	return retval;
}

// pos1 points to the first field after FormatID (classname/typename)
static int do_ole_object_embedded(deark *c, lctx *d,
	i64 pos1, i64 len, int exact_size_known, i64 *bytes_consumed)
{
	i64 pos = pos1;
	i64 stringlen;
	i64 data_len;
	i64 bytes_consumed2 = 0;
	int ret;
	int recognized = 0;
	const char *ext = NULL;
	int handled = 0;
	u8 buf[16];
	struct de_stringreaderdata *classname_srd = NULL;
	struct de_stringreaderdata *topicname_srd = NULL;
	struct de_stringreaderdata *itemname_srd = NULL;
	int retval = 0;

	// TODO: This code (for the next 3 fields) is duplicated in the function for
	// "linked" objects.

	stringlen = de_getu32le_p(&pos);
	classname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "embedded ClassName: \"%s\"", ucstring_getpsz(classname_srd->str));
	pos += stringlen;

	stringlen = de_getu32le_p(&pos);
	topicname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "TopicName/filename: \"%s\"", ucstring_getpsz(topicname_srd->str));
	pos += stringlen;

	stringlen = de_getu32le_p(&pos);
	itemname_srd = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "ItemName/params: \"%s\"", ucstring_getpsz(itemname_srd->str));
	pos += stringlen;

	data_len = de_getu32le_p(&pos);
	de_dbg(c, "NativeData: pos=%"I64_FMT", len=%"I64_FMT, pos, data_len);

	// TODO: I don't know the extent to which it's better to sniff the data, or
	// rely on the typename.
	de_read(buf, pos, sizeof(buf));

	if(!de_strcmp(classname_srd->sz, "Package")) {
		recognized = 1;
		handled = do_ole_package(c, d, pos, data_len);
	}
	else if(!de_strncmp(classname_srd->sz, "Word.Document.", 14) ||
		!de_strncmp(classname_srd->sz, "Word.Picture.", 13))
	{
		ext = "doc";
	}
	else if (!de_strncmp(classname_srd->sz, "Excel.Chart.", 12) ||
		!de_strcmp(classname_srd->sz, "ExcelWorksheet"))
	{
		ext = "xls";
	}
	else if(!de_strcmp(classname_srd->sz, "CDraw") &&
		!de_memcmp(&buf[0], (const void*)"RIFF", 4) &&
		!de_memcmp(&buf[8], (const void*)"CDR", 3) )
	{
		ext = "cdr"; // Looks like CorelDRAW
	}
	else if (!de_strcmp(classname_srd->sz, "PaintShopPro") &&
		!de_memcmp(&buf[0], (const void*)"\x28\0\0\0", 4))
	{
		de_run_module_by_id_on_slice(c, "dib", NULL, c->infile, pos, data_len);
		handled = 1;
	}
	if(!de_strcmp(classname_srd->sz, "ShapewareVISIO20")) {
		ext = "vsd";
	}
	else if(buf[0]=='B' && buf[1]=='M') {
		// TODO: Detect true length of data?
		// TODO: This detection may be too aggressive.
		ext = "bmp";
	}

	if(ext && !handled) {
		dbuf_create_file_from_slice(c->infile, pos, data_len, ext, NULL, 0);
		handled = 1;
	}

	if(!handled) {
		if(d->extract_all) {
			extract_unknown_ole_obj(c, d, pos, data_len, classname_srd);
		}
		else if(!recognized) {
			de_warn(c, "Unknown/unsupported type of OLE object (\"%s\") at %"I64_FMT,
				ucstring_getpsz(classname_srd->str), pos1);
		}
	}

	pos += data_len;
	// Nested "presentation" object
	ret = do_ole_object(c, d, pos, pos1+len-pos, exact_size_known, 1,
		&bytes_consumed2);
	if(!ret) goto done;
	pos += bytes_consumed2;

	*bytes_consumed = pos-pos1;
	retval = 1;
done:
	de_destroy_stringreaderdata(c, classname_srd);
	de_destroy_stringreaderdata(c, topicname_srd);
	de_destroy_stringreaderdata(c, itemname_srd);
	return retval;
}

static int do_ole_object(deark *c, lctx *d, i64 pos1, i64 len, int exact_size_known,
	int is_presentation, i64 *bytes_consumed)
{
	int saved_indent_level;
	i64 pos = pos1;
	i64 nbytesleft;
	i64 bytes_consumed2;
	int ret;
	unsigned int n;
	unsigned int formatID;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	if(len<8) goto done;
	de_dbg(c, "OLE object at %"I64_FMT", len%s%"I64_FMT, pos1,
		(exact_size_known?"=":DE_CHAR_LEQ), len);
	de_dbg_indent(c, 1);

	n = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "OLEVersion: 0x%08x", n);

	formatID = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "FormatID: %u (%s)", formatID, get_FormatID_name(formatID));

	nbytesleft = pos1+len-pos;
	if(formatID==1 && !is_presentation) {
		ret = do_ole_object_linked(c, d, pos, nbytesleft, exact_size_known, &bytes_consumed2);
		if(!ret) goto done;
		pos += bytes_consumed2;
	}
	else if(formatID==2 && !is_presentation) {
		ret = do_ole_object_embedded(c, d, pos, nbytesleft, exact_size_known, &bytes_consumed2);
		if(!ret) goto done;
		pos += bytes_consumed2;
	}
	else if(formatID==3) {
		ret = do_ole_object_presentation(c, d, pos, nbytesleft, formatID, &bytes_consumed2);
		if(!ret) goto done;
		pos += bytes_consumed2;
	}
	else if(formatID==5 && is_presentation) {
		ret = do_ole_object_presentation(c, d, pos, nbytesleft, formatID, &bytes_consumed2);
		if(!ret) goto done;
		pos += bytes_consumed2;
	}
	else if(formatID==0 && is_presentation) {
		;
	}
	else {
		de_dbg(c, "[unsupported OLE FormatID]");
		goto done;
	}

	*bytes_consumed = pos-pos1;
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_ole1(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 bytes_consumed = 0;
	int ret;
	int u_flag;

	if(mparams) {
		mparams->out_params.flags = 0;
	}

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, mparams, DE_ENCODING_WINDOWS1252);
	// Use the "U" code if the exact size of the object is unknown. This will
	// improve the debug messages.
	u_flag = de_havemodcode(c, mparams, 'U');
	d->extract_all = de_get_ext_option_bool(c, "ole1:extractall",
		((c->extract_level>=2)?1:0));

	ret = do_ole_object(c, d, 0, c->infile->len, (u_flag?0:1),
		0, &bytes_consumed);
	if(ret) {
		if(mparams) {
			mparams->out_params.flags |= 0x1;
			mparams->out_params.int64_1 = bytes_consumed;
		}
		de_dbg3(c, "ole1: calculated size=%"I64_FMT, bytes_consumed);
	}
	else {
		de_dbg3(c, "ole1: failed to calculate object size");
	}

	de_free(c, d);
}

void de_module_ole1(deark *c, struct deark_module_info *mi)
{
	mi->id = "ole1";
	mi->desc = "OLE1.0 objects";
	mi->run_fn = de_run_ole1;
	mi->identify_fn = NULL;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
