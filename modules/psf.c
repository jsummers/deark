// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// PSF font (PC Screen Font)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int version;
	de_uint32 psf2_version;
	de_uint32 flags;
	de_byte mode;
	de_int64 headersize;
	de_int64 num_glyphs;
	de_int64 bytes_per_glyph;
	de_int64 max_width, max_height;
	de_int64 font_data_size;
	int has_unicode_table;
	de_int64 unicode_table_pos;
} lctx;

static void do_glyphs(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	de_byte *font_data = NULL;
	de_int64 i;
	de_int64 glyph_rowspan;

	font = de_create_bitmap_font(c);
	font->nominal_width = (int)d->max_width;
	font->nominal_height = (int)d->max_height;
	font->num_chars = d->num_glyphs;
	font->has_unicode_codepoints = 0; //d->has_unicode_table;
	font->is_unicode = 0; // d->has_unicode_table;
	glyph_rowspan = (d->max_width+7)/8;

	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	font_data = de_malloc(c, d->font_data_size);
	de_read(font_data, d->headersize, d->font_data_size);

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = glyph_rowspan;
		font->char_array[i].codepoint = (de_int32)i;
		font->char_array[i].bitmap = &font_data[i*d->bytes_per_glyph];
	}

	de_font_bitmap_font_to_image(c, font, NULL);

	if(font) {
		de_free(c, font->char_array);
		de_destroy_bitmap_font(c, font);
	}
	de_free(c, font_data);
}

static void do_psf1_unicode_table(deark *c, lctx *d)
{
	de_dbg(c, "Unicode table at %d\n", (int)d->unicode_table_pos);
	de_dbg_indent(c, 1);
	de_dbg_indent(c, -1);
	de_warn(c, "Unicode mappings not supported\n");
}

static void do_psf2_unicode_table(deark *c, lctx *d)
{
	de_dbg(c, "Unicode table at %d\n", (int)d->unicode_table_pos);
	de_dbg_indent(c, 1);
	de_dbg_indent(c, -1);
	de_warn(c, "Unicode mappings not supported\n");
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
	d->max_height = d->bytes_per_glyph;
	d->max_width = 8;
	de_dbg(c, "glyph dimensions: %dx%d\n", (int)d->max_width, (int)d->max_height);

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

	d->max_height = de_getui32le(pos+24);
	d->max_width = de_getui32le(pos+28);
	de_dbg(c, "max glyph dimensions: %dx%d\n", (int)d->max_width, (int)d->max_height);

	de_dbg_indent(c, -1);
}

static void de_run_psf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte b;

	d = de_malloc(c, sizeof(lctx));

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
		d->max_width<1 || d->max_width>256 ||
		d->max_height<1 || d->max_height>256 ||
		d->num_glyphs<1 || d->num_glyphs>2000000)
	{
		de_err(c, "Invalid or unsupported PSF file\n");
		goto done;
	}

	if(d->has_unicode_table) {
		if(d->version==2)
			do_psf2_unicode_table(c, d);
		else
			do_psf1_unicode_table(c, d);
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
