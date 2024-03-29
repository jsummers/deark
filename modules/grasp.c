// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GRASP GL animation format
// GRASP font format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_graspgl);
DE_DECLARE_MODULE(de_module_graspfont);

typedef struct localctx_struct {
	de_encoding input_encoding;
	int is_le;
	u8 is_amiga;
	i64 index_pos;
	i64 index_size;
} lctx;

// Returns 0 if there are no more files.
static int do_extract_file(deark *c, lctx *d, i64 fnum)
{
	i64 index_entry_pos;
	i64 data_block_pos;
	i64 dpos;
	i64 dlen;
	de_finfo *fi = NULL;
	de_ucstring *fname = NULL;
	int saved_indent_level;
	int need_errmsg = 0;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	index_entry_pos = d->index_pos+17*fnum;
	data_block_pos = dbuf_getu32x(c->infile, index_entry_pos, d->is_le);

	// The last "file" is usually not a file, but a "NULL terminator" with an
	// offset of 0. Not very useful, since we already know how long the list is.
	if(data_block_pos==0) {
		de_dbg(c, "end-of-file-list marker found");
		goto done;
	}

	de_dbg(c, "file #%d", (int)fnum);
	de_dbg_indent(c, 1);
	de_dbg(c, "index entry pos: %"I64_FMT, index_entry_pos);
	de_dbg(c, "data block pos: %"I64_FMT, data_block_pos);

	if(data_block_pos < d->index_size) {
		need_errmsg = 1;
		goto done;
	}

	if(de_getbyte(index_entry_pos+4)==0x00) {
		need_errmsg = 1; // missing file name?
		goto done;
	}

	fi = de_finfo_create(c);
	fname = ucstring_create(c);

	// Filenames are 13 bytes, NUL-padded.
	dbuf_read_to_ucstring(c->infile, index_entry_pos+4, 13, fname, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_finfo_set_name_from_ucstring(c, fi, fname, 0);
	fi->original_filename_flag = 1;
	de_dbg(c, "file name: \"%s\"", ucstring_getpsz_d(fname));

	dlen = dbuf_getu32x(c->infile, data_block_pos, d->is_le);
	dpos = data_block_pos+4;
	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, dpos, dlen);
	if(dpos+dlen > c->infile->len) {
		need_errmsg = 1;
		goto done;
	}

	dbuf_create_file_from_slice(c->infile, dpos, dlen, NULL, fi, 0);
	retval = 1;

done:
	if(need_errmsg) {
		de_err(c, "Bad file entry (#%d)", (int)fnum);
	}
	de_finfo_destroy(c, fi);
	ucstring_destroy(fname);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_graspgl(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 num_files;
	i64 pos = 0;
	i64 i;

	d = de_malloc(c, sizeof(lctx));

	if((UI)de_getu32be(0)==0x41470100U) {
		// Ref: Aminet : gl2p1.lzh
		d->is_amiga = 1;
	}

	if(d->is_amiga) {
		de_declare_fmt(c, "Amiga GRASP GL");
		pos += 4;
	}
	else {
		de_declare_fmt(c, "GRASP GL");
		d->is_le = 1;
	}

	d->input_encoding = de_get_input_encoding(c, NULL,
		(d->is_amiga ? DE_ENCODING_LATIN1 : DE_ENCODING_CP437));

	d->index_size = dbuf_getu16x(c->infile, pos, d->is_le);
	pos += 2;

	d->index_pos = pos;
	de_dbg(c, "index size: %"I64_FMT, d->index_size);

	// 17 bytes per file entry
	num_files = (d->index_size+16)/17;
	de_dbg(c, "max number of files: %d", (int)num_files);

	for(i=0; i<num_files; i++) {
		if(!do_extract_file(c, d, i))
			break;
	}

	de_free(c, d);
}

static int de_identify_graspgl(deark *c)
{
	i64 index_size;
	i64 index_pos;
	i64 first_offset;
	int is_le = 1;
	int gl_ext;

	index_size = de_getu16le(0);
	if(index_size==0x4741) {
		if((UI)de_getu16be(2)==0x0100U) {
			is_le = 0; // Amiga GL?
			index_size = de_getu16be(4);
		}
	}

	// Header should be a nonzero multiple of 17 bytes.
	if(index_size==0 || (index_size%17 != 0)) return 0;
	index_pos = is_le ? 2 : 6;
	if(index_pos+index_size>c->infile->len) return 0;

	gl_ext = de_input_file_has_ext(c, "gl");

	// Most likely, the first embedded file immediately follows
	// the header. If so, it's pretty good evidence this is a
	// grasp_gl file.
	first_offset = dbuf_getu32x(c->infile, index_pos, is_le);

	if(first_offset>c->infile->len || first_offset<index_pos+index_size) return 0;
	if(first_offset == index_pos+index_size)
		return gl_ext ? 100 : 70;

	if(gl_ext) return 5;

	return 0;
}

void de_module_graspgl(deark *c, struct deark_module_info *mi)
{
	mi->id = "graspgl";
	mi->desc = "GRASP GL animation";
	mi->run_fn = de_run_graspgl;
	mi->identify_fn = de_identify_graspgl;
}

// **************************************************************************
// GRASP font (.set/.fnt)
// **************************************************************************

static void de_run_graspfont_oldfmt(deark *c)
{
	i64 reported_filesize;
	i32 first_codepoint;
	struct de_bitmap_font *font = NULL;
	i64 bytes_per_glyph;
	i64 i;
	i64 font_data_size;
	u8 *font_data = NULL;
	i64 glyph_rowspan;
	struct de_encconv_state es;

	font = de_create_bitmap_font(c);

	reported_filesize = de_getu16le(0);
	de_dbg(c, "reported file size: %d", (int)reported_filesize);

	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints = 1;
	font->num_chars = (i64)de_getbyte(2);
	if(font->num_chars==0) font->num_chars=256;
	first_codepoint = (i32)de_getbyte(3);
	font->nominal_width = (int)de_getbyte(4);
	font->nominal_height = (int)de_getbyte(5);
	bytes_per_glyph = (i64)de_getbyte(6);

	de_dbg(c, "number of glyphs: %d, first codepoint: %d", (int)font->num_chars, (int)first_codepoint);
	de_dbg(c, "glyph dimensions: %d"DE_CHAR_TIMES"%d, size in bytes: %d", font->nominal_width,
		font->nominal_height, (int)bytes_per_glyph);

	glyph_rowspan = (font->nominal_width+7)/8;
	if(bytes_per_glyph < glyph_rowspan*font->nominal_height ||
		font->nominal_width<1 || font->nominal_height<1)
	{
		de_err(c, "Bad font metrics");
		goto done;
	}

	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));
	font_data_size = bytes_per_glyph * font->num_chars;
	font_data = de_malloc(c, font_data_size);

	// There's no way to tell what encoding a GRASP font uses, but CP437 is
	// a reasonable guess.
	de_encconv_init(&es, DE_ENCODING_CP437_G);

	de_read(font_data, 7, font_data_size);

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = glyph_rowspan;

		font->char_array[i].codepoint_nonunicode = first_codepoint + (i32)i;

		font->char_array[i].codepoint_unicode =
			de_char_to_unicode_ex(first_codepoint + (i32)i, &es);

		font->char_array[i].bitmap = &font_data[i*bytes_per_glyph];
	}

	de_font_bitmap_font_to_image(c, font, NULL, 0);

done:
	if(font) {
		if(font->char_array) {
			de_free(c, font->char_array);
		}
		de_destroy_bitmap_font(c, font);
	}
	de_free(c, font_data);
}

// Caution: This code is not based on any official specifications.
static void de_run_graspfont_newfmt(deark *c)
{
	struct de_bitmap_font *font = NULL;
	de_ucstring *fontname = NULL;
	i64 k;
	i64 glyph_offsets_table_pos;
	i64 widths_table_pos;
	i64 glyph_rowspan;
	int tmp_width;
	int ch_max_width = 0;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	font = de_create_bitmap_font(c);
	font->has_nonunicode_codepoints = 1;

	fontname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, 1, 13, fontname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(fontname));

	font->num_chars = (i64)de_getbyte(16);
	de_dbg(c, "number of glyphs: %d", (int)font->num_chars);

	tmp_width = (int)de_getbyte(19);
	de_dbg(c, "font width: %d", tmp_width);
	font->nominal_height = (int)de_getbyte(20);
	de_dbg(c, "font height: %d", font->nominal_height);

	glyph_rowspan = (i64)de_getbyte(21);

	de_dbg_indent(c, -1);

	glyph_offsets_table_pos = 59;
	widths_table_pos = glyph_offsets_table_pos +2*font->num_chars;
	if(widths_table_pos<249)
		widths_table_pos = 249;
	de_dbg(c, "glyph offsets table at %d, width table at %d", (int)glyph_offsets_table_pos,
		(int)widths_table_pos);
	de_dbg_indent(c, 1);

	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));

	for(k=0; k<font->num_chars; k++) {
		i64 ch_offset;
		i64 bitmapsize;
		struct de_bitmap_font_char *ch = &font->char_array[k];

		ch->codepoint_nonunicode = (i32)(33 + k);

		ch_offset = de_getu16le(glyph_offsets_table_pos + 2 + 2*k);

		ch->width = (int)de_getbyte(widths_table_pos + 1 + k);
		de_dbg2(c, "ch[%d]: codepoint=%d, width=%d, glyph_offs=%d", (int)k,
			(int)ch->codepoint_nonunicode,
			(int)ch->width, (int)ch_offset);

		if(ch->width<1) continue;

		if(ch->width > ch_max_width) ch_max_width = ch->width;
		ch->height = font->nominal_height;
		ch->rowspan = glyph_rowspan;
		bitmapsize = ch->rowspan * ch->height;
		ch->bitmap = de_malloc(c, bitmapsize);
		de_read(ch->bitmap, ch_offset, bitmapsize);
	}

	de_dbg_indent(c, -1);

	de_dbg(c, "calculated maximum width: %d", (int)ch_max_width);
	font->nominal_width = ch_max_width;

	de_font_bitmap_font_to_image(c, font, NULL, 0);

	if(font) {
		if(font->char_array) {
			for(k=0; k<font->num_chars; k++) {
				de_free(c, font->char_array[k].bitmap);
			}
			de_free(c, font->char_array);
		}
		de_destroy_bitmap_font(c, font);
	}

	ucstring_destroy(fontname);
}

static int gfont_is_new_format(deark *c)
{
	i64 reported_filesize;

	if(de_getbyte(0)==0x10) {
		reported_filesize = de_getu16le(25);
		if(reported_filesize == c->infile->len) {
			return 1;
		}
	}
	return 0;
}

static void de_run_graspfont(deark *c, de_module_params *mparams)
{
	if(gfont_is_new_format(c)) {
		de_declare_fmt(c, "GRASP font (new)");
		de_run_graspfont_newfmt(c);
	}
	else {
		de_declare_fmt(c, "GRASP font (old)");
		de_run_graspfont_oldfmt(c);
	}
}

static int de_identify_graspfont(deark *c)
{
	i64 reported_filesize;
	i64 num_chars;
	i64 bytes_per_glyph;

	if(!de_input_file_has_ext(c, "set") && !de_input_file_has_ext(c, "fnt"))
		return 0;

	if(gfont_is_new_format(c)) {
		return 30;
	}

	reported_filesize = de_getu16le(0);
	if(reported_filesize != c->infile->len) return 0;
	num_chars = (i64)de_getbyte(2);
	if(num_chars==0) num_chars=256;
	bytes_per_glyph = (i64)de_getbyte(6);
	if(7+num_chars*bytes_per_glyph == reported_filesize)
		return 100;
	return 0;
}

void de_module_graspfont(deark *c, struct deark_module_info *mi)
{
	mi->id = "graspfont";
	mi->desc = "GRASP font";
	mi->run_fn = de_run_graspfont;
	mi->identify_fn = de_identify_graspfont;
}
