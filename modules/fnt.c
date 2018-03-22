// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows FNT font format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_fnt);

typedef struct localctx_struct {
	de_int64 fnt_version;
	de_int64 nominal_char_width;
	de_int64 char_height;
	de_int64 hdrsize;
	de_int64 char_table_size;

	de_byte first_char;
	de_byte last_char;
	de_int64 num_chars_stored;

	de_int64 char_entry_size;
	de_int64 detected_max_width;

	de_int64 dfPoints;
	de_int64 dfFace; // Offset of font face name
	de_byte dfCharSet;

	int is_vector;
	int encoding;

	de_finfo *fi;
} lctx;

// Find the widest character.
static void do_prescan_chars(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 pos;
	de_int64 char_width;

	for(i=0; i<d->num_chars_stored; i++) {
		pos = d->hdrsize + d->char_entry_size*i;
		char_width = de_getui16le(pos);

		if(char_width > d->detected_max_width) {
			d->detected_max_width = char_width;
		}
	}
	de_dbg(c, "detected max width: %d", (int)d->detected_max_width);
}

// create bitmap_font object
static void do_make_image(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	de_int64 i;
	de_int64 pos;

	de_dbg(c, "reading characters and bitmaps");
	de_dbg_indent(c, 1);

	font = de_create_bitmap_font(c);

	font->has_nonunicode_codepoints = 1;
	if(d->encoding!=DE_ENCODING_UNKNOWN)
		font->has_unicode_codepoints = 1;
	font->prefer_unicode = 0;

	font->nominal_width = (int)d->nominal_char_width;
	font->nominal_height = (int)d->char_height;
	font->num_chars = d->num_chars_stored;
	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->num_chars_stored; i++) {
		de_int64 char_width;
		de_int64 char_offset;
		de_int32 char_index;
		de_int64 num_tiles;
		de_int64 tile;
		de_int64 row;

		pos = d->hdrsize + d->char_entry_size*i;
		char_width = de_getui16le(pos);
		if(d->char_entry_size==6)
			char_offset = de_getui32le(pos+2);
		else
			char_offset = de_getui16le(pos+2);
		de_dbg2(c, "char[%d] width=%d offset=%d", (int)(d->first_char + i), (int)char_width, (int)char_offset);

		num_tiles = (char_width+7)/8;

		if(i == d->num_chars_stored-1) {
			// Arbitrarily put the "absolute space" char at codepoint 256,
			// and U+2002 EN SPACE (best I can do).
			font->char_array[i].codepoint_nonunicode = 256;
			font->char_array[i].codepoint_unicode = 0x2002;
		}
		else {
			char_index = (de_int32)d->first_char + (de_int32)i;

			font->char_array[i].codepoint_nonunicode = char_index;

			if(font->has_unicode_codepoints) {
				if(char_index<32 && d->dfCharSet==0) {
					// This kind of font usually doesn't have glyphs below 32.
					// If it does, assume that they are VT100 line drawing characters.
					font->char_array[i].codepoint_unicode =
						de_char_to_unicode(c, 95+char_index, DE_ENCODING_DEC_SPECIAL_GRAPHICS);
				}
				else {
					font->char_array[i].codepoint_unicode =
						de_char_to_unicode(c, char_index, d->encoding);
				}
			}
		}

		font->char_array[i].width = (int)char_width;
		font->char_array[i].height = (int)d->char_height;
		font->char_array[i].rowspan = num_tiles;
		font->char_array[i].bitmap = de_malloc(c, d->char_height * num_tiles);

		for(row=0; row<d->char_height; row++) {
			for(tile=0; tile<num_tiles; tile++) {
				font->char_array[i].bitmap[row * font->char_array[i].rowspan + tile] =
					de_getbyte(char_offset + tile*d->char_height + row);
			}
		}
	}

	de_font_bitmap_font_to_image(c, font, d->fi, 0);

	if(font) {
		if(font->char_array) {
			for(i=0; i<font->num_chars; i++) {
				de_free(c, font->char_array[i].bitmap);
			}
			de_free(c, font->char_array);
		}
		de_destroy_bitmap_font(c, font);
	}

	de_dbg_indent(c, -1);
}

static void read_face_name(deark *c, lctx *d)
{
	char buf2[50];
	struct de_stringreaderdata *srd = NULL;

	if(d->dfFace<1) return;

	de_dbg(c, "face name at %d", (int)d->dfFace);
	de_dbg_indent(c, 1);

	// The facename is terminated with a NUL byte.
	// There seems to be no defined limit to its length, but Windows font face
	// names traditionally have to be quite short.
	srd = dbuf_read_string(c->infile, d->dfFace, 260, 50,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "face name: \"%s\"", ucstring_getpsz(srd->str));

	if(!c->filenames_from_file) goto done;

	d->fi = de_finfo_create(c);
	de_snprintf(buf2, sizeof(buf2), "%s-%d", srd->sz, (int)d->dfPoints);
	de_finfo_set_name_from_sz(c, d->fi, buf2, DE_ENCODING_ASCII);

done:
	de_dbg_indent(c, -1);
	de_destroy_stringreaderdata(c, srd);
}

static const char *get_charset_name(de_byte cs)
{
	struct csname_struct { de_byte id; const char *name; };
	static const struct csname_struct csname_arr[] = {
		{0x00, "ANSI"},
		{0x01, "default"},
		{0x02, "symbol"},
		{0x4d, "Mac"},
		{0x80, "Shift-JIS"},
		{0x81, "Hangul"},
		{0x82, "Johab"},
		{0x86, "GB2312"},
		{0x88, "BIG5"},
		{0xa1, "Greek"},
		{0xa2, "Turkish"},
		{0xa3, "Vietnamese"},
		{0xb1, "Hebrew"},
		{0xb2, "Arabic"},
		{0xba, "Baltic"},
		{0xcc, "Russian"},
		{0xde, "Thai"},
		{0xee, "Eastern Europe"},
		{0xff, "OEM"}
	};
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(csname_arr); i++) {
		if(cs==csname_arr[i].id) return csname_arr[i].name;
	}
	return "?";
}

static int do_read_header(deark *c, lctx *d)
{
	de_int64 dfType;
	de_int64 dfPixWidth;
	de_int64 dfPixHeight;
	de_int64 dfMaxWidth;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "fixed header at %d", (int)0);
	de_dbg_indent(c, 1);

	d->fnt_version = de_getui16le(0);
	de_dbg(c, "dfVersion: 0x%04x", (int)d->fnt_version);

	if(d->fnt_version==0x0300)
		d->hdrsize = 148;
	else
		d->hdrsize = 118;

	dfType = de_getui16le(66);
	d->is_vector = (dfType&0x1)?1:0;
	de_dbg(c, "dfType: 0x%04x (%s)", (int)dfType, d->is_vector?"vector":"bitmap");

	d->dfPoints = de_getui16le(68);
	de_dbg(c, "dfPoints: %d", (int)d->dfPoints);

	dfPixWidth = de_getui16le(86);
	de_dbg(c, "dfPixWidth: %d", (int)dfPixWidth);
	dfPixHeight = de_getui16le(88);
	de_dbg(c, "dfPixHeight: %d", (int)dfPixHeight);

	d->dfCharSet = de_getbyte(85);
	de_dbg(c, "charset: 0x%02x (%s)", (int)d->dfCharSet,
		get_charset_name(d->dfCharSet));
	if(d->dfCharSet==0x00) { // "ANSI"
		d->encoding = DE_ENCODING_WINDOWS1252; // Guess
	}
	else if(d->dfCharSet==0xff) { // "OEM"
		d->encoding = DE_ENCODING_CP437_G; // Guess
	}
	else {
		d->encoding = DE_ENCODING_UNKNOWN;
	}

	dfMaxWidth = de_getui16le(93);
	de_dbg(c, "dfMaxWidth: %d", (int)dfMaxWidth);

	if(dfPixWidth!=dfMaxWidth && dfPixWidth!=0) {
		de_warn(c, "dfMaxWidth (%d) does not equal dfPixWidth (%d)",
			(int)dfMaxWidth, (int)dfPixWidth);
	}

	d->first_char = de_getbyte(95);
	de_dbg(c, "first char: %d", (int)d->first_char);
	d->last_char = de_getbyte(96);
	de_dbg(c, "last char: %d", (int)d->last_char);

	if(d->fnt_version >= 0x0200) {
		d->dfFace = de_getui32le(105);
	}
	de_dbg_indent(c, -1);

	if(d->is_vector) {
		retval = 1;
		goto done;
	}

	// Apparently, the first 117 bytes (through the dfBitsOffset field) are
	// common to all versions
	if(d->fnt_version<0x0200) {
		de_err(c, "This version of FNT is not supported");
		goto done;
	}

	// There is an extra character at the end of the table that is an
	// "absolute-space" character, and is guaranteed to be blank.
	d->num_chars_stored = (de_int64)d->last_char - d->first_char + 1 + 1;

	if(d->fnt_version==0x0300) {
		d->char_entry_size = 6;
	}
	else {
		d->char_entry_size = 4;
	}

	d->char_table_size = d->char_entry_size * d->num_chars_stored;
	de_dbg(c, "character index at %d, size %d, %d bytes/entry", (int)d->hdrsize,
		(int)d->char_table_size, (int)d->char_entry_size);
	de_dbg_indent(c, 1);

	de_dbg(c, "pre-scanning characters");
	do_prescan_chars(c, d);
	if(d->detected_max_width<1) goto done;
	d->nominal_char_width = d->detected_max_width;

	d->char_height = dfPixHeight;
	de_dbg_indent(c, -1);

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_fnt(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_read_header(c, d)) goto done;
	read_face_name(c, d);

	if(d->is_vector) {
		de_err(c, "This is a vector font. Not supported.");
		goto done;
	}

	do_make_image(c, d);
done:
	de_finfo_destroy(c, d->fi);
	de_free(c, d);
}

static int de_identify_fnt(deark *c)
{
	de_int64 ver;

	// TODO: Better format detection.
	if(de_input_file_has_ext(c, "fnt")) {
		ver = de_getui16le(0);
		if(ver==0x0100 || ver==0x0200 || ver==0x0300)
			return 10;
	}
	return 0;
}

void de_module_fnt(deark *c, struct deark_module_info *mi)
{
	mi->id = "fnt";
	mi->desc = "Windows FNT font";
	mi->run_fn = de_run_fnt;
	mi->identify_fn = de_identify_fnt;
}
