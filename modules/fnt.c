// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows FNT font format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_fnt);

struct char_table_entry {
	int pixel_width;
	u8 is_abs_space;
	i64 v1_pixel_offset;
	i64 v23_data_pos;
};

typedef struct localctx_struct {
	unsigned int fnt_version;
	unsigned int dfType;
	int nominal_char_width;
	i64 char_height;
	i64 char_table_pos;
	i64 char_entry_size; // can be 0
	i64 char_table_size; // can be 0
	i64 dfWidthBytes;
	i64 dfBitsOffset;

	u8 first_char;
	u8 last_char;
	i64 num_chars_stored;
	struct char_table_entry *char_table; // [num_chars_stored]

	i64 dfPixWidth;
	i64 dfPixHeight;
	int detected_max_width;

	unsigned int dfPoints;
	i64 dfFace; // Offset of font face name
	u8 dfCharSet;

	int is_vector;
	int has_abs_space_char;
	de_encoding encoding;

	de_finfo *fi;
} lctx;

static void get_char_bitmap_v1(deark *c, lctx *d,
	struct char_table_entry *cte, struct de_bitmap_font_char *ch)
{
	i64 row;

	ch->rowspan = ((i64)cte->pixel_width+7)/8;
	if(d->char_height * ch->rowspan > 32768) return;
	ch->bitmap = de_malloc(c, d->char_height * ch->rowspan);

	for(row=0; row<d->char_height; row++) {
		i64 k;

		for(k=0; k<(i64)cte->pixel_width; k++){
			u8 b;
			b = de_get_bits_symbol(c->infile, 1, d->dfBitsOffset + row*d->dfWidthBytes,
				cte->v1_pixel_offset+k);
			if(b) {
				ch->bitmap[row*ch->rowspan + k/8] |= 1<<(7-k%8);
			}
		}
	}
}

static void get_char_bitmap_v23(deark *c, lctx *d,
	struct char_table_entry *cte, struct de_bitmap_font_char *ch)
{
	i64 num_tiles;
	i64 tile;
	i64 row;

	num_tiles = ((i64)cte->pixel_width+7)/8;
	ch->rowspan = num_tiles;
	if(d->char_height * num_tiles > 32768) return;
	ch->bitmap = de_malloc(c, d->char_height * num_tiles);

	for(row=0; row<d->char_height; row++) {
		for(tile=0; tile<num_tiles; tile++) {
			ch->bitmap[row * ch->rowspan + tile] =
				de_getbyte(cte->v23_data_pos + tile*d->char_height + row);
		}
	}
}

// create bitmap_font object
static void do_make_image(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	i64 i;

	de_dbg(c, "reading bitmaps");
	de_dbg_indent(c, 1);

	font = de_create_bitmap_font(c);

	font->has_nonunicode_codepoints = 1;
	if(d->encoding!=DE_ENCODING_UNKNOWN)
		font->has_unicode_codepoints = 1;
	font->prefer_unicode = 0;

	font->nominal_width = d->nominal_char_width;
	font->nominal_height = (int)d->char_height;
	font->num_chars = d->num_chars_stored;
	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->num_chars_stored; i++) {
		i32 char_index;
		struct char_table_entry *cte = &d->char_table[i];
		struct de_bitmap_font_char *ch = &font->char_array[i];

		if(cte->is_abs_space) {
			// Arbitrarily put the "absolute space" char at codepoint 256,
			// and U+2002 EN SPACE (best I can do).
			ch->codepoint_nonunicode = 256;
			ch->codepoint_unicode = 0x2002;
		}
		else {
			char_index = (i32)d->first_char + (i32)i;

			ch->codepoint_nonunicode = char_index;

			if(font->has_unicode_codepoints) {
				if(char_index<32 && d->dfCharSet==0) {
					// This kind of font usually doesn't have glyphs below 32.
					// If it does, assume that they are VT100 line drawing characters.
					ch->codepoint_unicode =
						de_char_to_unicode(c, 95+char_index, DE_ENCODING_DEC_SPECIAL_GRAPHICS);
				}
				else {
					ch->codepoint_unicode = de_char_to_unicode(c, char_index, d->encoding);
				}
			}
		}

		ch->width = cte->pixel_width;
		ch->height = (int)d->char_height;

		if(d->fnt_version==0x100) {
			get_char_bitmap_v1(c, d, cte, ch);
		}
		else {
			get_char_bitmap_v23(c, d, cte, ch);
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

// Note that there is similar code in exe.c. Any changed made here should
// potentially be copied.
static void read_face_name(deark *c, lctx *d)
{
	de_ucstring *s = NULL;

	if(d->dfFace<1) return;

	de_dbg(c, "face name at %"I64_FMT, d->dfFace);
	de_dbg_indent(c, 1);

	// The facename is terminated with a NUL byte.
	// There seems to be no defined limit to its length, but Windows font face
	// names traditionally have to be quite short.
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, d->dfFace, 64, s, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);

	de_dbg(c, "face name: \"%s\"", ucstring_getpsz_d(s));

	if(!c->filenames_from_file) goto done;

	if(!d->fi) d->fi = de_finfo_create(c);
	ucstring_printf(s, DE_ENCODING_LATIN1, "-%u", d->dfPoints);
	de_finfo_set_name_from_ucstring(c, d->fi, s, 0);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}

static int do_read_header(deark *c, lctx *d)
{
	i64 dfMaxWidth;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "fixed header at %d", (int)0);
	de_dbg_indent(c, 1);

	d->fnt_version = (unsigned int)de_getu16le(0);
	de_dbg(c, "dfVersion: 0x%04x", d->fnt_version);
	if(d->fnt_version!=0x100 && d->fnt_version!=0x200 && d->fnt_version!=0x300) {
		de_err(c, "This version of FNT (0x%04x) is not supported", d->fnt_version);
		goto done;
	}

	d->dfType = (unsigned int)de_getu16le(66);
	d->is_vector = (d->dfType&0x1)?1:0;
	de_dbg(c, "dfType: 0x%04x (%s)", d->dfType, d->is_vector?"vector":"bitmap");

	d->dfPoints = (unsigned int)de_getu16le(68);
	de_dbg(c, "dfPoints: %u", d->dfPoints);

	d->dfPixWidth = de_getu16le(86);
	de_dbg(c, "dfPixWidth: %d", (int)d->dfPixWidth);
	d->dfPixHeight = de_getu16le(88);
	d->char_height = d->dfPixHeight;
	de_dbg(c, "dfPixHeight: %d", (int)d->dfPixHeight);

	d->dfCharSet = de_getbyte(85);
	de_dbg(c, "charset: 0x%02x (%s)", (int)d->dfCharSet,
		de_fmtutil_get_windows_charset_name(d->dfCharSet));
	if(d->dfCharSet==0x00) { // "ANSI"
		d->encoding = DE_ENCODING_WINDOWS1252; // Guess
	}
	else if(d->dfCharSet==0xff) { // "OEM"
		d->encoding = DE_ENCODING_CP437_G; // Guess
	}
	else {
		d->encoding = DE_ENCODING_UNKNOWN;
	}

	dfMaxWidth = de_getu16le(93);
	de_dbg(c, "dfMaxWidth: %d", (int)dfMaxWidth);

	if(d->dfPixWidth!=dfMaxWidth && d->dfPixWidth!=0) {
		de_warn(c, "dfMaxWidth (%d) does not equal dfPixWidth (%d)",
			(int)dfMaxWidth, (int)d->dfPixWidth);
	}

	d->first_char = de_getbyte(95);
	de_dbg(c, "first char: %d", (int)d->first_char);
	d->last_char = de_getbyte(96);
	de_dbg(c, "last char: %d", (int)d->last_char);

	// 97 = dfDefaultChar
	// 98 = dfBreakChar

	d->dfWidthBytes = de_getu16le(99);
	de_dbg(c, "dfWidthBytes: %d%s", (int)d->dfWidthBytes,
		((d->fnt_version>=0x200 || d->is_vector) ? " [unused]":""));
	// 101-104 = dfDevice

	d->dfFace = de_getu32le(105);
	de_dbg(c, "dfFace: %u", (unsigned int)d->dfFace);

	// 109-112 = dfBitsPointer
	d->dfBitsOffset = de_getu32le(113);
	de_dbg(c, "dfBitsOffset: %"I64_FMT, d->dfBitsOffset);

	// Apparently, the first 117 bytes (through the dfBitsOffset field) are
	// common to all versions

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// For v1 fixed-width raster fonts.
// There is no char table (well, its size is 0), so generate a fake table.
static void do_create_char_table_v1(deark *c, lctx *d)
{
	i64 k;

	for(k=0; k<d->num_chars_stored; k++) {
		d->char_table[k].pixel_width = (int)d->dfPixWidth;
		d->char_table[k].v1_pixel_offset = d->dfPixWidth * k;
	}
}

// For v1 variable-width raster fonts
static void do_read_char_table_v1(deark *c, lctx *d)
{
	i64 k;
	i64 pos;
	i64 next_char_offset;

	for(k=0; k<d->num_chars_stored; k++) {
		pos = d->char_table_pos + d->char_entry_size*k;
		d->char_table[k].v1_pixel_offset = de_getu16le(pos);
		next_char_offset = de_getu16le(pos+2);
		d->char_table[k].pixel_width = (int)(next_char_offset - d->char_table[k].v1_pixel_offset);
		if(d->char_table[k].pixel_width<0) d->char_table[k].pixel_width=0;
	}
}

// For all v2 and v3 raster fonts
static void do_read_char_table_v23(deark *c, lctx *d)
{
	i64 k;
	i64 pos;

	for(k=0; k<d->num_chars_stored; k++) {
		pos = d->char_table_pos + d->char_entry_size*k;
		d->char_table[k].pixel_width = (int)de_getu16le(pos);
		if(d->char_entry_size==6) {
			d->char_table[k].v23_data_pos = de_getu32le(pos+2);
		}
		else {
			d->char_table[k].v23_data_pos = de_getu16le(pos+2);
		}
	}
}

// Print debug info for each char, find the max char width,
// and other tasks.
static int do_postprocess_char_table(deark *c, lctx *d)
{
	i64 k;
	int retval = 0;

	d->detected_max_width = 0;

	for(k=0; k<d->num_chars_stored; k++) {
		int codepoint;

		if(d->has_abs_space_char && (k==d->num_chars_stored-1)) {
			d->char_table[k].is_abs_space = 1;
		}

		// TODO: Maybe codepoint should be a field in char_table_entry.
		if(d->char_table[k].is_abs_space) {
			codepoint = 256;
		}
		else {
			codepoint = (int)((int)d->first_char + (int)k);
		}

		if(d->fnt_version==0x100) {
			de_dbg2(c, "char[%d] codepoint=%d pixoffset=%d width=%d", (int)k, codepoint,
				(int)d->char_table[k].v1_pixel_offset, d->char_table[k].pixel_width);
		}
		else {
			de_dbg2(c, "char[%d] codepoint=%d bitmappos=%d width=%d", (int)k, codepoint,
				(int)d->char_table[k].v23_data_pos, d->char_table[k].pixel_width);
		}

		if(d->char_table[k].pixel_width > d->detected_max_width) {
			d->detected_max_width = d->char_table[k].pixel_width;
		}
	}

	de_dbg(c, "detected max width: %d", d->detected_max_width);

	if(d->detected_max_width<1) goto done;
	d->nominal_char_width = d->detected_max_width;

	retval = 1;
done:
	return retval;
}

static int do_read_char_table(deark *c, lctx *d)
{
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->is_vector) return 0;

	// There is an extra character at the end of the table that is an
	// "absolute-space" character, and is guaranteed to be blank.
	d->has_abs_space_char = (d->fnt_version>=0x200);

	d->num_chars_stored = (i64)d->last_char - d->first_char + 1;
	if(d->has_abs_space_char) d->num_chars_stored++;
	de_dbg(c, "number of characters: %d", (int)d->num_chars_stored);

	if(d->fnt_version==0x100) {
		d->char_table_pos = 117;
		if(d->dfPixWidth==0) { // proportional raster font
			d->char_entry_size = 2;
		}
		else { // fixed-width raster font
			d->char_entry_size = 0;
		}
	}
	else if(d->fnt_version==0x200) {
		d->char_table_pos = 118;
		d->char_entry_size = 4;
	}
	else { // version 0x300
		d->char_table_pos = 148;
		d->char_entry_size = 6;
	}

	d->char_table_size = d->char_entry_size * d->num_chars_stored;
	de_dbg(c, "character table at %d, size %d, %d bytes/entry",
		(int)d->char_table_pos, (int)d->char_table_size, (int)d->char_entry_size);
	de_dbg_indent(c, 1);

	d->char_table = de_mallocarray(c, d->num_chars_stored, sizeof(struct char_table_entry));

	if(d->char_table_size==0) {
		do_create_char_table_v1(c, d);
	}
	else if(d->fnt_version==0x100) {
		do_read_char_table_v1(c, d);
	}
	else {
		do_read_char_table_v23(c, d);
	}

	if(!do_postprocess_char_table(c, d)) goto done;

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

	if(d->dfType & 0x4) {
		de_err(c, "This type of font is not supported (dfType=0x%04x)", d->dfType);
		goto done;
	}

	if(!do_read_char_table(c, d)) goto done;

	do_make_image(c, d);
done:
	if(d) {
		de_finfo_destroy(c, d->fi);
		de_free(c, d->char_table);
		de_free(c, d);
	}
}

static int de_identify_fnt(deark *c)
{
	i64 ver;

	// TODO: Better format detection.
	if(de_input_file_has_ext(c, "fnt")) {
		ver = de_getu16le(0);
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
