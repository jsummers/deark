// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// GEM bitmap font

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	struct de_bitmap_font *font;
	de_int64 face_size;
	de_int64 first_index, last_index;
	de_int64 max_char_cell_width;
	de_int64 char_offset_table_pos;
	de_int64 font_data_pos;
	de_int64 form_width_bytes;
	de_int64 form_height_pixels;
	de_byte byte_swap_flag;
	de_finfo *fi;
} lctx;

static int do_characters(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 row;
	de_int64 n;
	struct de_bitmap_font_char *ch;
	de_int64 char_startpos;
	de_byte *font_data = NULL;
	de_int64 form_nbytes;
	int retval = 0;

	form_nbytes = d->form_width_bytes * d->form_height_pixels;
	if(d->font_data_pos + form_nbytes > c->infile->len) {
		de_err(c, "Font data goes beyond end of file\n");
		goto done;
	}
	font_data = de_malloc(c, form_nbytes);
	de_read(font_data, d->font_data_pos, form_nbytes);

	for(i=0; i<d->font->num_chars; i++) {
		ch = &d->font->char_array[i];
		char_startpos = de_getui16le(d->char_offset_table_pos + 2*i);
		n = de_getui16le(d->char_offset_table_pos + 2*(i+1));
		ch->width = (int)(n - char_startpos);
		ch->height = d->font->nominal_height;
		ch->codepoint = (de_int32)(d->first_index+i);
		de_dbg2(c, "char[%d] #%d offset=%d width=%d\n", (int)i, (int)ch->codepoint,
			 (int)char_startpos, ch->width);
		if(ch->width<1 || ch->width>d->max_char_cell_width) continue;

		ch->rowspan = (ch->width+7)/8;
		ch->bitmap = de_malloc(c, ch->height * ch->rowspan);

		for(row=0; row<ch->height; row++) {
			de_copy_bits(font_data + row*d->form_width_bytes, char_startpos,
				ch->bitmap + row*ch->rowspan, 0, (de_int64)ch->width);
		}

		if(ch->width > d->font->nominal_width) {
			// Track the maximum character width.
			d->font->nominal_width = ch->width;
		}
	}
	retval = 1;

done:
	de_free(c, font_data);
	return retval;
}

static void do_face_name(deark *c, lctx *d)
{
	char buf[100];
	char buf2[100];
	size_t nlen;

	if(!c->filenames_from_file) return;

	dbuf_read_sz(c->infile, 4, buf, 32);
	nlen = de_strlen(buf);

	// Strip trailing spaces
	while(nlen>0 && buf[nlen-1]==' ') {
		buf[nlen-1] = '\0';
		nlen--;
	}

	de_snprintf(buf2, sizeof(buf2), "%s-%d", buf, (int)d->face_size);

	d->fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, d->fi, buf2, DE_ENCODING_ASCII);
}

static void de_run_gemfont(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 i;
	unsigned int font_flags;
	de_int64 max_char_width;

	d = de_malloc(c, sizeof(lctx));
	d->font = de_create_bitmap_font(c);

	d->face_size = de_getui16le(2);
	de_dbg(c, "point size: %d\n", (int)d->face_size);

	do_face_name(c, d); // Offset 4-35

	d->first_index = de_getui16le(36);
	d->last_index = de_getui16le(38);
	de_dbg(c, "first char: %d, last char: %d\n", (int)d->first_index, (int)d->last_index);
	d->font->num_chars = d->last_index - d->first_index + 1;

	max_char_width = de_getui16le(50);
	d->max_char_cell_width = de_getui16le(52);
	de_dbg(c, "max char width: %d, max char cell width: %d\n", (int)max_char_width,
		(int)d->max_char_cell_width);

	font_flags = (unsigned int)de_getui16le(66);
	d->byte_swap_flag = (font_flags & 0x04) ? 1 : 0;

	de_dbg(c, "byte swap flag: %d\n", (int)d->byte_swap_flag);
	if(d->byte_swap_flag) {
		de_warn(c, "This font uses an unsupported byte-swap option, and might not be "
			"decoded correctly.\n");
	}

	d->char_offset_table_pos = de_getui32le(72);
	d->font_data_pos = de_getui32le(76);
	de_dbg(c, "char. offset table at %d\n", (int)d->char_offset_table_pos);
	de_dbg(c, "font data at %d\n", (int)d->font_data_pos);

	d->form_width_bytes = de_getui16le(80);
	d->form_height_pixels = de_getui16le(82);
	de_dbg(c, "form width: %d bytes\n", (int)d->form_width_bytes);
	de_dbg(c, "form height: %d pixels\n", (int)d->form_height_pixels);

	d->font->nominal_width = 1; // This will be calculated later
	d->font->nominal_height = (int)d->form_height_pixels;
	if(d->font->nominal_height<1 || d->font->nominal_height>200) goto done;

	if(d->font->num_chars<1) goto done;
	d->font->char_array = de_malloc(c, d->font->num_chars * sizeof(struct de_bitmap_font_char));

	if(!do_characters(c, d)) goto done;

	de_font_bitmap_font_to_image(c, d->font, d->fi);

done:
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

static int de_identify_gemfont(deark *c)
{
	if(!de_input_file_has_ext(c, "fnt")) return 0;

	// This is a difficult format to reliably identify.
	// The following test can fail.
	if(!dbuf_memcmp(c->infile, 62, "UUUU", 4)) {
		return 70;
	}
	return 0;
}

void de_module_gemfont(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemfont";
	mi->desc = "GEM bitmap font";
	mi->run_fn = de_run_gemfont;
	mi->identify_fn = de_identify_gemfont;
}
