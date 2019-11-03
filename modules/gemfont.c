// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM bitmap font

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gemfont);

typedef struct localctx_struct {
	struct de_bitmap_font *font;
	i64 face_size;
	i64 first_index, last_index;
	i64 max_char_cell_width;
	i64 char_offset_table_pos;
	i64 font_data_pos;
	i64 form_width_bytes;
	i64 form_height_pixels;
	u8 byte_swap_flag;
	de_finfo *fi;
} lctx;

static int do_characters(deark *c, lctx *d)
{
	i64 i;
	i64 row;
	i64 n;
	struct de_bitmap_font_char *ch;
	i64 char_startpos;
	u8 *font_data = NULL;
	i64 form_nbytes;
	int retval = 0;

	de_dbg(c, "reading characters");
	de_dbg_indent(c, 1);

	form_nbytes = d->form_width_bytes * d->form_height_pixels;
	if(d->font_data_pos + form_nbytes > c->infile->len) {
		de_err(c, "Font data goes beyond end of file");
		goto done;
	}
	font_data = de_malloc(c, form_nbytes);
	de_read(font_data, d->font_data_pos, form_nbytes);

	for(i=0; i<d->font->num_chars; i++) {
		ch = &d->font->char_array[i];
		char_startpos = de_getu16le(d->char_offset_table_pos + 2*i);
		n = de_getu16le(d->char_offset_table_pos + 2*(i+1));
		ch->width = (int)(n - char_startpos);
		ch->height = d->font->nominal_height;
		ch->codepoint_nonunicode = (i32)(d->first_index+i);
		de_dbg2(c, "char[%d] #%d offset=%d width=%d", (int)i, (int)ch->codepoint_nonunicode,
			 (int)char_startpos, ch->width);
		if(ch->width<1 || ch->width>d->max_char_cell_width || ch->width>512) continue;

		ch->rowspan = (ch->width+7)/8;
		ch->bitmap = de_malloc(c, ch->height * ch->rowspan);

		for(row=0; row<ch->height; row++) {
			de_copy_bits(font_data + row*d->form_width_bytes, char_startpos,
				ch->bitmap + row*ch->rowspan, 0, (i64)ch->width);
		}

		if(ch->width > d->font->nominal_width) {
			// Track the maximum character width.
			d->font->nominal_width = ch->width;
		}
	}
	retval = 1;

done:
	de_dbg_indent(c, -1);
	de_free(c, font_data);
	return retval;
}

static void do_face_name(deark *c, lctx *d)
{
	de_ucstring *name = NULL;

	name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, 4, 32, name, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "face name: \"%s\"", ucstring_getpsz_d(name));
	if(!c->filenames_from_file) goto done;

	ucstring_strip_trailing_spaces(name);
	ucstring_printf(name, DE_ENCODING_LATIN1, "-%d", (int)d->face_size);
	d->fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, d->fi, name, 0);

done:
	ucstring_destroy(name);
}

static int do_header(deark *c, lctx *d)
{
	unsigned int font_flags;
	i64 max_char_width;
	i64 n;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	n = de_getu16le(0);
	de_dbg(c, "face ID: %d", (int)n);

	d->face_size = de_getu16le(2);
	de_dbg(c, "point size: %d", (int)d->face_size);

	do_face_name(c, d); // Offset 4-35

	d->first_index = de_getu16le(36);
	d->last_index = de_getu16le(38);
	de_dbg(c, "first char: %d, last char: %d", (int)d->first_index, (int)d->last_index);
	d->font->num_chars = d->last_index - d->first_index + 1;

	max_char_width = de_getu16le(50);
	d->max_char_cell_width = de_getu16le(52);
	de_dbg(c, "max char width: %d, max char cell width: %d", (int)max_char_width,
		(int)d->max_char_cell_width);

	n = de_getu16le(54);
	de_dbg(c, "left offset: %d", (int)n);
	n = de_getu16le(56);
	de_dbg(c, "right offset: %d", (int)n);

	n = de_getu16le(62);
	de_dbg(c, "lightening mask: 0x%04x", (unsigned int)n);

	font_flags = (unsigned int)de_getu16le(66);
	d->byte_swap_flag = (font_flags & 0x04) ? 1 : 0;

	de_dbg(c, "byte swap flag: %d", (int)d->byte_swap_flag);
	if(d->byte_swap_flag) {
		de_warn(c, "This font uses an unsupported byte-swap option, and might not be "
			"decoded correctly.");
	}

	n = de_getu32le(68);
	de_dbg(c, "horiz. offset table offset: %u", (unsigned int)n);

	d->char_offset_table_pos = de_getu32le(72);
	d->font_data_pos = de_getu32le(76);
	de_dbg(c, "char. offset table offset: %d", (int)d->char_offset_table_pos);
	de_dbg(c, "font data offset: %d", (int)d->font_data_pos);

	d->form_width_bytes = de_getu16le(80);
	d->form_height_pixels = de_getu16le(82);
	de_dbg(c, "form width: %d bytes", (int)d->form_width_bytes);
	de_dbg(c, "form height: %d pixels", (int)d->form_height_pixels);

	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_gemfont(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->font = de_create_bitmap_font(c);
	d->font->has_nonunicode_codepoints = 1;

	if(!do_header(c, d)) goto done;

	d->font->nominal_width = 1; // This will be calculated later
	d->font->nominal_height = (int)d->form_height_pixels;
	if(d->font->nominal_height<1 || d->font->nominal_height>512) goto done;

	if(d->font->num_chars<1) goto done;
	d->font->char_array = de_mallocarray(c, d->font->num_chars, sizeof(struct de_bitmap_font_char));

	if(!do_characters(c, d)) goto done;

	de_font_bitmap_font_to_image(c, d->font, d->fi, 0);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(d->font) {
		if(d->font->char_array) {
			for(i=0; i<d->font->num_chars; i++) {
				de_free(c, d->font->char_array[i].bitmap);
			}
			de_free(c, d->font->char_array);
		}
		de_destroy_bitmap_font(c, d->font);
	}
	de_finfo_destroy(c, d->fi);
	de_free(c, d);
}

// This is a difficult format to reliably identify.
static int de_identify_gemfont(deark *c)
{
	int has_usual_lm;
	i64 fdoffs, fwidth, fheight, eofd;

	if(!de_input_file_has_ext(c, "fnt") &&
		!de_input_file_has_ext(c, "gft"))
	{
		return 0;
	}

	has_usual_lm = !dbuf_memcmp(c->infile, 62, "UUUU", 4);
	fdoffs = de_getu32le(76);
	if(fdoffs<88) return 0;
	fwidth = de_getu16le(80);
	fheight = de_getu16le(82);
	if(fwidth<1 || fheight<1) return 0;
	eofd = fdoffs + fwidth*fheight; // end of font data
	if(eofd > c->infile->len) return 0;
	if(eofd==c->infile->len && has_usual_lm) return 100;
	if(eofd==c->infile->len) return 70;
	if(has_usual_lm) return 25;
	return 0;
}

void de_module_gemfont(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemfont";
	mi->desc = "GEM bitmap font";
	mi->run_fn = de_run_gemfont;
	mi->identify_fn = de_identify_gemfont;
}
