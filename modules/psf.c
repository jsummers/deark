// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PSF font (PC Screen Font)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_psf);

typedef struct localctx_struct {
	int version;
	de_uint32 psf2_version;
	de_uint32 flags;
	de_byte mode;
	de_int64 headersize;
	de_int64 num_glyphs;
	de_int64 glyph_width, glyph_height;
	de_int64 bytes_per_glyph;
	de_int64 font_data_size;
	int has_unicode_table;
	de_int64 unicode_table_pos;

#define MAX_EXTRA_CODEPOINTS 2000
	int read_extra_codepoints;
	de_int64 num_chars_alloc;
	de_int64 index_of_first_extra_codepoint;
	de_int64 num_extra_codepoints;
} lctx;

static void do_extra_codepoint(deark *c, lctx *d, struct de_bitmap_font *font,
	de_int64 cur_idx, de_int32 n)
{
	de_int64 extra_idx;

	if(!d->read_extra_codepoints) return;
	if(d->num_extra_codepoints >= MAX_EXTRA_CODEPOINTS) return;

	extra_idx = d->index_of_first_extra_codepoint + d->num_extra_codepoints;
	de_dbg2(c, "char[%d] alias [%d] = U+%04x\n", (int)cur_idx, (int)extra_idx,
		(unsigned int)n);
	if(n == font->char_array[cur_idx].codepoint_unicode) {
		de_dbg2(c, "ignoring superfluous alias\n");
		return;
	}
	font->char_array[extra_idx].codepoint_unicode = n;
	font->char_array[extra_idx].bitmap = font->char_array[cur_idx].bitmap;
	d->num_extra_codepoints++;
}

static void do_psf1_unicode_table(deark *c, lctx *d, struct de_bitmap_font *font)
{
	de_int64 cur_idx;
	de_int64 pos;
	int got_cp;
	int found_fffe;
	de_int32 n;

	de_dbg(c, "Unicode table at %d\n", (int)d->unicode_table_pos);
	de_dbg_indent(c, 1);

	pos = d->unicode_table_pos;
	cur_idx = 0;
	got_cp = 0; // Have we set the codepoint for glyph[cur_idx]?
	found_fffe = 0;

	while(1) {
		if(cur_idx >= d->num_glyphs) break;
		if(pos+1 >= c->infile->len) break;
		n = (de_int32)de_getui16le(pos);
		pos+=2;

		if(n==0xffff) {
			if(!got_cp) {
				de_warn(c, "Missing codepoint for char #%d\n", (int)cur_idx);
			}
			cur_idx++;
			got_cp = 0;
			found_fffe = 0;
			continue;
		}
		else if(n==0xfffe) {
			found_fffe = 1;
		}

		if(found_fffe) {
			// Anything after 0xfffe is a multi-codepoint character, which we
			// don't support.
			continue;
		}

		if(!got_cp) {
			de_dbg2(c, "char[%d] = U+%04x\n", (int)cur_idx, (unsigned int)n);
			font->char_array[cur_idx].codepoint_unicode = n;
			got_cp = 1;
			continue;
		}

		// This is an "extra" codepoint for the current glyph.
		do_extra_codepoint(c, d, font, cur_idx, n);
	}

	font->has_unicode_codepoints = 1;
	font->prefer_unicode = 1;

	de_dbg_indent(c, -1);
}

static void do_psf2_unicode_table(deark *c, lctx *d, struct de_bitmap_font *font)
{
	de_int64 cur_idx;
	de_int64 pos;
	int ret;
	de_int64 foundpos;
	de_int64 char_data_len;
	de_byte char_data_buf[200];
	de_int32 ch;
	de_int64 utf8len;

	de_dbg(c, "Unicode table at %d\n", (int)d->unicode_table_pos);
	de_dbg_indent(c, 1);

	pos = d->unicode_table_pos;
	cur_idx = 0;
	while(1) {
		de_int64 pos_in_char_data;
		de_int64 cp_idx;

		if(cur_idx >= d->num_glyphs) break;
		if(pos >= c->infile->len) break;

		// Figure out the size of the data for this glyph
		ret = dbuf_search_byte(c->infile, 0xff, pos,
			c->infile->len - pos, &foundpos);
		if(!ret) break;
		char_data_len = foundpos - pos;
		if(char_data_len<0) char_data_len=0;
		else if(char_data_len>(de_int64)sizeof(char_data_buf)) char_data_len=(de_int64)sizeof(char_data_buf);

		// Read all the data for this glyph
		de_read(char_data_buf, pos, char_data_len);

		// Read the codepoints for this glyph
		cp_idx = 0;
		pos_in_char_data = 0;
		while(1) {
			if(pos_in_char_data >= char_data_len) break;

			ret = de_utf8_to_uchar(&char_data_buf[pos_in_char_data], char_data_len-pos_in_char_data,
				&ch, &utf8len);
			if(!ret) {
				// If there are any multi-codepoint aliases for this glyph, we
				// expect de_utf8_to_uchar() to fail when it hits the 0xfe byte.
				// So, this is not necessarily an error.
				break;
			}

			if(cp_idx==0) {
				// This is the primary Unicode codepoint for this glyph
				de_dbg2(c, "char[%d] = U+%04x\n", (int)cur_idx, (unsigned int)ch);
				font->char_array[cur_idx].codepoint_unicode = ch;
			}
			else {
				do_extra_codepoint(c, d, font, cur_idx, ch);
			}

			cp_idx++;
			pos_in_char_data += utf8len;
		}

		if(cp_idx==0) {
			de_warn(c, "Missing codepoint for char #%d\n", (int)cur_idx);
		}

		// Advance to the next glyph
		pos = foundpos+1;
		cur_idx++;
	}

	font->has_unicode_codepoints = 1;
	font->prefer_unicode = 1;

	de_dbg_indent(c, -1);
}

static void do_glyphs(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	de_byte *font_data = NULL;
	de_int64 i;
	de_int64 glyph_rowspan;

	font = de_create_bitmap_font(c);
	font->has_nonunicode_codepoints = 1;
	font->nominal_width = (int)d->glyph_width;
	font->nominal_height = (int)d->glyph_height;
	font->num_chars = d->num_glyphs; // This may increase later
	glyph_rowspan = (d->glyph_width+7)/8;

	d->num_chars_alloc = d->num_glyphs;
	if(d->read_extra_codepoints)
		d->num_chars_alloc += MAX_EXTRA_CODEPOINTS;

	d->index_of_first_extra_codepoint = d->num_glyphs;
	d->num_extra_codepoints = 0;

	font->char_array = de_malloc(c, d->num_chars_alloc * sizeof(struct de_bitmap_font_char));

	font_data = de_malloc(c, d->font_data_size);
	de_read(font_data, d->headersize, d->font_data_size);

	for(i=0; i<d->num_chars_alloc; i++) {
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = glyph_rowspan;
		if(i<d->num_glyphs)
			font->char_array[i].codepoint_nonunicode = (de_int32)i;
		else
			font->char_array[i].codepoint_nonunicode = DE_INVALID_CODEPOINT;
		font->char_array[i].codepoint_unicode = DE_INVALID_CODEPOINT;
		if(i<d->num_glyphs)
			font->char_array[i].bitmap = &font_data[i*d->bytes_per_glyph];
	}

	if(d->has_unicode_table) {
		if(d->version==2)
			do_psf2_unicode_table(c, d, font);
		else
			do_psf1_unicode_table(c, d, font);
	}

	if(d->num_extra_codepoints>0) {
		font->num_chars = d->index_of_first_extra_codepoint + d->num_extra_codepoints;
		de_dbg(c, "codepoints aliases: %d\n", (int)d->num_extra_codepoints);
		de_dbg(c, "total characters: %d\n", (int)font->num_chars);
	}

	de_font_bitmap_font_to_image(c, font, NULL, 0);

	if(font) {
		de_free(c, font->char_array);
		de_destroy_bitmap_font(c, font);
	}
	de_free(c, font_data);
}

static void do_psf1_header(deark *c, lctx *d)
{
	de_int64 pos = 0;

	de_dbg(c, "PFXv1 header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->headersize = 4;

	d->mode = de_getbyte(2);
	de_dbg(c, "mode: 0x%02x\n", (unsigned int)d->mode);
	de_dbg_indent(c, 1);
	d->num_glyphs = (d->mode & 0x01) ? 512 : 256;
	de_dbg(c, "number of glyphs: %d\n", (int)d->num_glyphs);
	d->has_unicode_table = (d->mode & 0x02) ? 1 : 0;
	de_dbg(c, "has Unicode table: %s\n", d->has_unicode_table?"yes":"no");
	de_dbg_indent(c, -1);

	d->bytes_per_glyph = (de_int64)de_getbyte(3);
	d->glyph_height = d->bytes_per_glyph;
	d->glyph_width = 8;
	de_dbg(c, "glyph dimensions: %dx%d\n", (int)d->glyph_width, (int)d->glyph_height);

	de_dbg_indent(c, -1);
}

static void do_psf2_header(deark *c, lctx *d)
{
	de_int64 pos = 0;

	de_dbg(c, "PFXv2 header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->psf2_version = (de_uint32)de_getui32le(pos+4);
	de_dbg(c, "PSFv2 version number: %d\n", (int)d->psf2_version);
	if(d->psf2_version!=0) {
		de_warn(c, "Unknown PSFv2 version number: %d\n", (int)d->psf2_version);
	}

	d->headersize = de_getui32le(pos+8);
	de_dbg(c, "header size: %d\n", (int)d->headersize);

	d->flags = (de_uint32)de_getui32le(pos+12);
	de_dbg(c, "flags: 0x%08x\n", (unsigned int)d->flags);
	de_dbg_indent(c, 1);
	d->has_unicode_table = (d->flags & 0x01) ? 1 : 0;
	de_dbg(c, "has Unicode table: %s\n", d->has_unicode_table?"yes":"no");
	de_dbg_indent(c, -1);

	d->num_glyphs = de_getui32le(pos+16);
	de_dbg(c, "number of glyphs: %d\n", (int)d->num_glyphs);

	d->bytes_per_glyph = de_getui32le(pos+20);
	de_dbg(c, "bytes per glyph: %d\n", (int)d->bytes_per_glyph);

	d->glyph_height = de_getui32le(pos+24);
	d->glyph_width = de_getui32le(pos+28);
	de_dbg(c, "glyph dimensions: %dx%d\n", (int)d->glyph_width, (int)d->glyph_height);

	de_dbg_indent(c, -1);
}

static void de_run_psf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte b;
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	s = de_get_ext_option(c, "font:noaliases");
	if(s)
		d->read_extra_codepoints = 0;
	else
		d->read_extra_codepoints = 1;

	b = de_getbyte(0);
	if(b==0x36) {
		d->version=1;
	}
	else if(b==0x72) {
		d->version=2;
	}
	else {
		de_err(c, "Not a PSF file\n");
		goto done;
	}

	de_dbg(c, "PSF version: %d\n", (int)d->version);

	if(d->version==2)
		do_psf2_header(c, d);
	else
		do_psf1_header(c, d);

	d->font_data_size = d->bytes_per_glyph * d->num_glyphs;
	if(d->has_unicode_table) {
		d->unicode_table_pos = d->headersize + d->font_data_size;
		if(d->unicode_table_pos >= c->infile->len) {
			d->has_unicode_table = 0;
		}
	}

	if((d->headersize+d->font_data_size > c->infile->len) ||
		d->bytes_per_glyph<1 ||
		d->glyph_width<1 || d->glyph_width>256 ||
		d->glyph_height<1 || d->glyph_height>256 ||
		d->num_glyphs<1 || d->num_glyphs>2000000)
	{
		de_err(c, "Invalid or unsupported PSF file\n");
		goto done;
	}

	do_glyphs(c, d);

done:
	de_free(c, d);
}

static int de_identify_psf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x72\xb5\x4a\x86", 4))
		return 100;
	if(!dbuf_memcmp(c->infile, 0, "\x36\x04", 2)) {
		// TODO: Better PSFv1 detection.
		return 65;
	}
	return 0;
}

void de_module_psf(deark *c, struct deark_module_info *mi)
{
	mi->id = "psf";
	mi->desc = "PC Screen Font";
	mi->run_fn = de_run_psf;
	mi->identify_fn = de_identify_psf;
}
