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
	de_int64 dir_header_nbytes;
} lctx;

// Returns 0 if there are no more files.
static int do_extract_file(deark *c, lctx *d, de_int64 fnum)
{
	de_int64 pos;
	de_int64 file_info_offset;
	de_int64 file_data_offset;
	de_int64 file_size;
	de_finfo *fi = NULL;
	de_ucstring *fname = NULL;
	int saved_indent_level;
	int retval = 1;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = 2+17*fnum;
	file_info_offset = de_getui32le(pos);

	// The last "file" is usually not a file, but a "NULL terminator" with
	// an offset of 0. This is worse than useless, since we already know
	// how long the list is.
	if(file_info_offset==0) {
		de_dbg(c, "end-of-file-list marker found");
		retval = 0;
		goto done;
	}

	de_dbg(c, "file #%d offset: %d", (int)fnum, (int)file_info_offset);
	de_dbg_indent(c, 1);

	if(file_info_offset < d->dir_header_nbytes) {
		de_warn(c, "Bad file offset (%d)", (int)file_info_offset);
		goto done;
	}

	if(de_getbyte(pos+4)==0x00) {
		de_warn(c, "Missing file name");
		goto done;
	}

	fi = de_finfo_create(c);

	fname = ucstring_create(c);

	// In a Grasp GL file, filenames are 13 bytes, NUL-padded.
	dbuf_read_to_ucstring(c->infile, pos+4, 13, fname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_finfo_set_name_from_ucstring(c, fi, fname);
	fi->original_filename_flag = 1;
	de_dbg(c, "file name: %s", ucstring_getpsz(fname));

	file_size = de_getui32le(file_info_offset);
	de_dbg(c, "file size: %d", (int)file_size);

	file_data_offset = file_info_offset+4;
	if(file_data_offset > dbuf_get_length(c->infile)) goto done;
	if(file_size > DE_MAX_FILE_SIZE) goto done;

	dbuf_create_file_from_slice(c->infile, file_data_offset, file_size, NULL, fi, 0);

done:
	de_finfo_destroy(c, fi);
	ucstring_destroy(fname);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}


static void de_run_graspgl(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 num_files;
	de_int64 pos;
	de_int64 i;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	d->dir_header_nbytes = de_getui16le(pos);
	de_dbg(c, "header bytes: %d", (int)d->dir_header_nbytes);

	// 17 bytes per file entry
	num_files = (d->dir_header_nbytes+16)/17;
	de_dbg(c, "number of files: %d", (int)num_files);

	for(i=0; i<num_files; i++) {
		if(!do_extract_file(c, d, i))
			break;
	}

	de_free(c, d);
}

static int de_identify_graspgl(deark *c)
{
	de_int64 dir_header_nbytes;
	de_int64 first_offset;
	int gl_ext;

	dir_header_nbytes = de_getui16le(0);

	// Header should be a nonzero multiple of 17 bytes.
	if(dir_header_nbytes==0 || (dir_header_nbytes%17 != 0)) return 0;

	gl_ext = de_input_file_has_ext(c, "gl");

	// Most likely, the first embedded file immediately follows
	// the header. If so, it's pretty good evidence this is a
	// grasp_gl file.
	first_offset = de_getui32le(2);
	if(first_offset == dir_header_nbytes + 2)
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
	de_int64 reported_filesize;
	de_int32 first_codepoint;
	struct de_bitmap_font *font = NULL;
	de_int64 bytes_per_glyph;
	de_int64 i;
	de_int64 font_data_size;
	de_byte *font_data = NULL;
	de_int64 glyph_rowspan;

	font = de_create_bitmap_font(c);

	reported_filesize = de_getui16le(0);
	de_dbg(c, "reported file size: %d", (int)reported_filesize);

	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints = 1;
	font->num_chars = (de_int64)de_getbyte(2);
	if(font->num_chars==0) font->num_chars=256;
	first_codepoint = (de_int32)de_getbyte(3);
	font->nominal_width = (int)de_getbyte(4);
	font->nominal_height = (int)de_getbyte(5);
	bytes_per_glyph = (de_int64)de_getbyte(6);

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

	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));
	font_data_size = bytes_per_glyph * font->num_chars;
	font_data = de_malloc(c, font_data_size);

	de_read(font_data, 7, font_data_size);

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = glyph_rowspan;

		font->char_array[i].codepoint_nonunicode = first_codepoint + (de_int32)i;

		// There's no way to tell what encoding a GRASP font uses, but CP437 is
		// a reasonable guess.
		font->char_array[i].codepoint_unicode =
			de_char_to_unicode(c, first_codepoint + (de_int32)i, DE_ENCODING_CP437_G);

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
	de_int64 k;
	de_int64 glyph_offsets_table_pos;
	de_int64 widths_table_pos;
	de_int64 glyph_rowspan;
	int tmp_width;
	int ch_max_width = 0;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	font = de_create_bitmap_font(c);
	font->has_nonunicode_codepoints = 1;

	fontname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, 1, 13, fontname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(fontname));

	font->num_chars = (de_int64)de_getbyte(16);
	de_dbg(c, "number of glyphs: %d", (int)font->num_chars);

	tmp_width = (int)de_getbyte(19);
	de_dbg(c, "font width: %d", tmp_width);
	font->nominal_height = (int)de_getbyte(20);
	de_dbg(c, "font height: %d", font->nominal_height);

	glyph_rowspan = (de_int64)de_getbyte(21);

	de_dbg_indent(c, -1);

	glyph_offsets_table_pos = 59;
	widths_table_pos = glyph_offsets_table_pos +2*font->num_chars;
	if(widths_table_pos<249)
		widths_table_pos = 249;
	de_dbg(c, "glyph offsets table at %d, width table at %d", (int)glyph_offsets_table_pos,
		(int)widths_table_pos);
	de_dbg_indent(c, 1);

	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	for(k=0; k<font->num_chars; k++) {
		de_int64 ch_offset;
		de_int64 bitmapsize;
		struct de_bitmap_font_char *ch = &font->char_array[k];

		ch->codepoint_nonunicode = (de_int32)(33 + k);

		ch_offset = de_getui16le(glyph_offsets_table_pos + 2 + 2*k);

		ch->width = (int)de_getbyte(widths_table_pos + 1 + k);
		de_dbg(c, "ch[%d]: codepoint=%d, width=%d, glyph_offs=%d", (int)k,
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
	de_int64 reported_filesize;

	if(de_getbyte(0)==0x10) {
		reported_filesize = de_getui16le(25);
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
	de_int64 reported_filesize;
	de_int64 num_chars;
	de_int64 bytes_per_glyph;

	if(!de_input_file_has_ext(c, "set") && !de_input_file_has_ext(c, "fnt"))
		return 0;

	if(gfont_is_new_format(c)) {
		return 30;
	}

	reported_filesize = de_getui16le(0);
	if(reported_filesize != c->infile->len) return 0;
	num_chars = (de_int64)de_getbyte(2);
	if(num_chars==0) num_chars=256;
	bytes_per_glyph = (de_int64)de_getbyte(6);
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
