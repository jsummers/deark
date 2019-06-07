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
	int wri_format;
} lctx;

static const char *get_FormatID_name(unsigned int t)
{
	const char *name;
	switch(t) {
	case 0: name="none"; break;
	case 1: name="linked"; break;
	case 2: name="embedded"; break;
	case 3: name="static/presentation"; break;
	case 5: name="presentation"; break;
	default: name="?"; break;
	}
	return name;
}

static void convert_image_pal4planar(deark *c, i64 fpos,
	i64 bytes_per_row_per_plane, de_bitmap *img)
{
	const i64 nplanes = 4;
	i64 i, j, plane;
	i64 rowspan;
	u8 *rowbuf = NULL;
	static const u32 pal16[16] = {
		0x000000,0x800000,0x008000,0x808000,0x000080,0x800080,0x008080,0x808080,
		0xc0c0c0,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xffffff
	};

	rowspan = bytes_per_row_per_plane * nplanes;
	rowbuf = de_malloc(c, rowspan);

	// The usual order seems to be
	//  row0_plane0x1, row0_plane0x2, row0_plane0x4, row0_plane0x8,
	//  row1_plane0x1, row1_plane0x2, row1_plane0x4, row1_plane0x8,
	//  ...
	// But I have seen another, and I see no way to detect/support it.

	for(j=0; j<img->height; j++) {
		de_read(rowbuf, fpos+j*rowspan, rowspan);

		for(i=0; i<img->width; i++) {
			unsigned int palent = 0;
			u32 clr;

			for(plane=0; plane<nplanes; plane++) {
				unsigned int n = 0;
				i64 idx;

				idx = bytes_per_row_per_plane*plane + i/8;
				if(idx<rowspan) n = rowbuf[idx];
				if(n & (1<<(7-i%8))) {
					palent |= (1<<plane);
				}
			}

			clr = DE_MAKE_OPAQUE(pal16[palent]);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_free(c, rowbuf);
}

static void convert_image_pal8(deark *c, i64 fpos,
	i64 rowspan, de_bitmap *img)
{
	i64 i, j;
	int badcolorflag = 0;
	// Palette is from libwps (except I might have red/blue swapped it).
	// I haven't confirmed that it's correct.
	static const u32 pal_part1[8] = {
		0x000000,0x800000,0x008000,0x808000,0x000080,0x800080,0x008080,0xc0c0c0
	};
	static const u32 pal_part2[8] = {
		0x808080,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xffffff
	};

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			unsigned int palent;
			u32 clr;

			palent = de_getbyte(fpos+j*rowspan+i);
			if(palent<8) {
				clr = pal_part1[palent];
			}
			else if(palent>=248) {
				clr = pal_part2[palent-248];
			}
			else {
				clr = DE_MAKE_RGB(254,palent,254); // Just an arbitrary color
				badcolorflag = 1;
			}
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	if(badcolorflag) {
		de_warn(c, "Image uses nonportable colors");
	}
}

static void do_static_bitmap(deark *c, lctx *d, i64 pos1)
{
	i64 dlen;
	i64 pos = pos1;
	unsigned int bmType;
	i64 bmWidth, bmHeight;
	i64 bmPlanes;
	i64 bmBitsPixel;
	i64 bytes_per_row_per_plane;
	i64 src_realbitsperpixel;
	de_bitmap *img = NULL;

	pos += 8; // ??
	dlen = de_getu32le_p(&pos);
	de_dbg(c, "bitmap size: %d", (int)dlen);

	bmType = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "bmType: %u", bmType);

	bmWidth = de_getu16le_p(&pos);
	bmHeight = de_getu16le_p(&pos);
	de_dbg_dimensions(c, bmWidth, bmHeight);

	bytes_per_row_per_plane = de_getu16le_p(&pos);
	de_dbg(c, "bytes/row: %d", (int)bytes_per_row_per_plane);

	bmPlanes = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)bmPlanes);

	bmBitsPixel = (i64)de_getbyte_p(&pos);
	de_dbg(c, "bmBitsPixel: %d", (int)bmBitsPixel);

	pos += 4; // Placeholder for a pointer?

	if((bmBitsPixel==1 && bmPlanes==1) ||
		(bmBitsPixel==1 && bmPlanes==4) ||
		(bmBitsPixel==8 && bmPlanes==1))
	{
		;
	}
	else {
		de_err(c, "This type of static OLE bitmap is not supported "
			"(bmBitsPixel=%d, planes=%d)", (int)bmBitsPixel, (int)bmPlanes);
		goto done;
	}

	src_realbitsperpixel = bmBitsPixel * bmPlanes;
	if(!de_good_image_dimensions(c, bmWidth, bmHeight)) goto done;
	img = de_bitmap_create(c, bmWidth, bmHeight, (src_realbitsperpixel==1)?1:3);

	if(bmBitsPixel==1 && bmPlanes==1) {
		de_convert_image_bilevel(c->infile, pos, bytes_per_row_per_plane, img, 0);
	}
	else if(bmBitsPixel==1 || bmPlanes==4) {
		convert_image_pal4planar(c, pos, bytes_per_row_per_plane, img);
	}
	else if(bmBitsPixel==8 || bmPlanes==1) {
		convert_image_pal8(c, pos, bytes_per_row_per_plane, img);
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

// Presentation object, or WRI-static-"OLE" object.
// pos1 points to the first field after FormatID (classname/typename)
static int do_ole_object_presentation(deark *c, lctx *d,
	i64 pos1, i64 len, unsigned int formatID)
{
	i64 pos = pos1;
	i64 stringlen;
	struct de_stringreaderdata *classname_srd = NULL;
	const char *name;

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
	}
	else if(!de_strcmp(classname_srd->sz, "METAFILEPICT")) {
		i64 dlen;
		pos += 8; // ??
		dlen = de_getu32le_p(&pos);
		de_dbg(c, "metafile size: %d", (int)dlen); // Includes "mfp", apparently
		pos += 8; // "mfp" struct
		dbuf_create_file_from_slice(c->infile, pos, dlen-8, "wmf", NULL, 0);
	}
	else if(!de_strcmp(classname_srd->sz, "BITMAP")) {
		do_static_bitmap(c, d, pos);
	}
	else {
		de_warn(c, "Static OLE picture type \"%s\" is not supported",
			ucstring_getpsz(classname_srd->str));
	}

	de_destroy_stringreaderdata(c, classname_srd);
	return 0;
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

static void do_ole_object(deark *c, lctx *d, i64 pos1, i64 len,
	int is_presentation);

// pos1 points to the first field after FormatID (classname/typename)
static int do_ole_object_embedded(deark *c, lctx *d,
	i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 stringlen;
	i64 data_len;
	int recognized = 0;
	const char *ext = NULL;
	int handled = 0;
	u8 buf[16];
	struct de_stringreaderdata *classname_srd = NULL;
	struct de_stringreaderdata *topicname_srd = NULL;
	struct de_stringreaderdata *itemname_srd = NULL;

	// Note: If we ever support "linked" objects, the code for reading these
	// first 3 string fields would have to be shared with that.

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
	do_ole_object(c, d, pos, pos1+len-pos, 1);

	de_destroy_stringreaderdata(c, classname_srd);
	de_destroy_stringreaderdata(c, topicname_srd);
	de_destroy_stringreaderdata(c, itemname_srd);
	return 1;
}

static void do_ole_object(deark *c, lctx *d, i64 pos1, i64 len,
	int is_presentation)
{
	int saved_indent_level;
	i64 pos = pos1;
	i64 nbytesleft;
	unsigned int n;
	unsigned int formatID;

	if(len<8) goto done;
	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "OLE object at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);

	n = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "OLEVersion: 0x%08x", n);

	formatID = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "FormatID: %u (%s)", formatID, get_FormatID_name(formatID));

	nbytesleft = pos1+len-pos;
	if(formatID==2 && !is_presentation) {
		do_ole_object_embedded(c, d, pos, nbytesleft);
	}
	else if(formatID==3 && d->wri_format) {
		do_ole_object_presentation(c, d, pos, nbytesleft, formatID);
	}
	else if(formatID==5 && is_presentation) {
		do_ole_object_presentation(c, d, pos, nbytesleft, formatID);
	}
	else if(formatID==0 && is_presentation) {
		;
	}
	else {
		de_dbg(c, "[unsupported OLE FormatID]");
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}



static void de_run_ole1(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, mparams, DE_ENCODING_WINDOWS1252);
	d->wri_format = de_havemodcode(c, mparams, 'W');
	d->extract_all = de_get_ext_option_bool(c, "ole1:extractall",
		((c->extract_level>=2)?1:0));

	do_ole_object(c, d, 0, c->infile->len, 0);

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
