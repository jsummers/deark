// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// XBIN character graphics
// "Binary Text" character graphics
// ArtWorx ADF character graphics

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_xbin);
DE_DECLARE_MODULE(de_module_bintext);
DE_DECLARE_MODULE(de_module_artworx_adf);
DE_DECLARE_MODULE(de_module_icedraw);

typedef struct localctx_struct {
	de_int64 width_in_chars, height_in_chars;
	de_int64 font_height;
	de_byte has_palette, has_font, compression, nonblink, has_512chars;

	de_int64 font_data_len;
	de_byte *font_data;
	int is_standard_font;
	struct de_bitmap_font *font;
} lctx;

static void do_bin_main(deark *c, lctx *d, dbuf *unc_data, struct de_char_context *charctx)
{
	de_int64 i, j;
	de_byte ccode, acode;
	de_byte fgcol, bgcol;
	struct de_char_screen *screen;

	charctx->nscreens = 1;
	charctx->screens = de_malloc(c, charctx->nscreens*sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];
	screen->width = d->width_in_chars;
	screen->height = d->height_in_chars;
	screen->cell_rows = de_malloc(c, d->height_in_chars * sizeof(struct de_char_cell*));

	for(j=0; j<d->height_in_chars; j++) {
		screen->cell_rows[j] = de_malloc(c, d->width_in_chars * sizeof(struct de_char_cell));

		for(i=0; i<d->width_in_chars; i++) {
			ccode = dbuf_getbyte(unc_data, j*d->width_in_chars*2 + i*2);
			acode = dbuf_getbyte(unc_data, j*d->width_in_chars*2 + i*2 + 1);

			if((acode&0x80) && !d->nonblink) {
				screen->cell_rows[j][i].blink = 1;
				acode -= 0x80;
			}

			fgcol = (acode & 0x0f);
			bgcol = (acode & 0xf0) >> 4;

			screen->cell_rows[j][i].fgcol = (de_uint32)fgcol;
			screen->cell_rows[j][i].bgcol = (de_uint32)bgcol;
			screen->cell_rows[j][i].codepoint = (de_int32)ccode;
			screen->cell_rows[j][i].codepoint_unicode = de_char_to_unicode(c, (de_int32)ccode, DE_ENCODING_CP437_G);
		}
	}

	de_char_output_to_file(c, charctx);
}

static void do_uncompress_data(deark *c, lctx *d, de_int64 pos1, dbuf *unc_data)
{
	de_int64 pos;
	de_byte cmprtype;
	de_int64 count;
	de_int64 xpos, ypos;
	de_byte b;
	de_byte b1, b2;
	de_int64 k;

	pos = pos1;

	xpos = 0; ypos = 0;

	while(pos < c->infile->len) {
		if(xpos >= d->width_in_chars) {
			ypos++;
			xpos = 0;
		}
		if(ypos >= d->height_in_chars) {
			break;
		}

		b = de_getbyte(pos);
		pos++;
		cmprtype = b>>6;
		count = (de_int64)(b&0x3f) +1;

		switch(cmprtype) {
		case 0: // Uncompressed
			dbuf_copy(c->infile, pos, count*2, unc_data);
			pos += count*2;
			break;
		case 1: // Character compression
			b1 = de_getbyte(pos++); // character code
			for(k=0; k<count; k++) {
				b2 = de_getbyte(pos++); // attribute code
				dbuf_writebyte(unc_data, b1);
				dbuf_writebyte(unc_data, b2);
			}
			break;
		case 2: // Attribute compression
			b2 = de_getbyte(pos++); // attribute code
			for(k=0; k<count; k++) {
				b1 = de_getbyte(pos++); // character code
				dbuf_writebyte(unc_data, b1);
				dbuf_writebyte(unc_data, b2);
			}
			break;
		case 3: // Character/Attribute compression
			b1 = de_getbyte(pos++); // character code
			b2 = de_getbyte(pos++); // attribute code
			for(k=0; k<count; k++) {
				dbuf_writebyte(unc_data, b1);
				dbuf_writebyte(unc_data, b2);
			}
			break;
		}

		xpos += count;
	}
}

static void do_read_palette(deark *c, lctx *d,struct de_char_context *charctx,
	de_int64 pos, int adf_style)
{
	de_int64 k;
	de_byte cr1, cg1, cb1;
	de_byte cr2, cg2, cb2;
	de_int64 cpos;
	char tmps[64];

	de_dbg(c, "palette at %d", (int)pos);

	for(k=0; k<16; k++) {
		if(adf_style && k>=8)
			cpos = pos+(48+k)*3;
		else
			cpos = pos+k*3;
		cr1 = de_getbyte(cpos);
		cg1 = de_getbyte(cpos+1);
		cb1 = de_getbyte(cpos+2);
		cr2 = de_scale_63_to_255(cr1);
		cg2 = de_scale_63_to_255(cg1);
		cb2 = de_scale_63_to_255(cb1);
		charctx->pal[k] = DE_MAKE_RGB(cr2, cg2, cb2);
		de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
			(int)cr1, (int)cg1, (int)cb1);
		de_dbg_pal_entry2(c, k, charctx->pal[k], tmps, NULL, NULL);
	}
}

static void do_default_palette(deark *c, lctx *d, struct de_char_context *charctx)
{
	int k;

	for(k=0; k<16; k++) {
		charctx->pal[k] = de_palette_pc16(k);
	}
}

static void do_extract_font(deark *c, lctx *d)
{
	de_finfo *fi = NULL;

	if(!d->has_font || !d->font) return;
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, "font", DE_ENCODING_ASCII);

	de_font_bitmap_font_to_image(c, d->font, fi, DE_CREATEFLAG_IS_AUX);

	de_finfo_destroy(c, fi);
}

static void do_read_font_data(deark *c, lctx *d, de_int64 pos)
{
	de_uint32 crc;

	de_dbg(c, "font at %d, %d bytes", (int)pos, (int)d->font_data_len);
	de_dbg_indent(c, 1);
	d->font_data = de_malloc(c, d->font_data_len);
	de_read(d->font_data, pos, d->font_data_len);

	crc = de_crc32(d->font_data, d->font_data_len);
	d->is_standard_font = de_font_is_standard_vga_font(c, crc);
	de_dbg(c, "font crc: 0x%08x (%s)", (unsigned int)crc,
		d->is_standard_font?"known CP437 font":"unrecognized");

	if(de_get_ext_option(c, "font:dumpvgafont")) {
		dbuf *df;
		df = dbuf_create_output_file(c, "font.dat", NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_write(df, d->font_data, d->font_data_len);
		dbuf_close(df);
	}
	de_dbg_indent(c, -1);
}

// Finish populating the d->font struct.
static int do_generate_font(deark *c, lctx *d)
{
	de_int64 i;

	if(!d->font) return 0;
	if(d->font->num_chars!=256) {
		de_err(c, "Only 256-character fonts are supported");
		return 0;
	}
	if(d->font_data_len!=d->font->num_chars*d->font_height) {
		de_err(c, "Incorrect font data size");
		return 0;
	}
	d->font->nominal_width = 8;
	d->font->nominal_height = (int)d->font_height;
	d->font->char_array = de_malloc(c, d->font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->font->num_chars; i++) {
		d->font->char_array[i].codepoint_nonunicode = (de_int32)i;
		d->font->char_array[i].codepoint_unicode =
			de_char_to_unicode(c, (de_int32)i, DE_ENCODING_CP437_G);
		d->font->char_array[i].width = d->font->nominal_width;
		d->font->char_array[i].height = d->font->nominal_height;
		d->font->char_array[i].rowspan = 1;
		d->font->char_array[i].bitmap = &d->font_data[i*d->font_height];
	}

	return 1;
}

static void free_lctx(deark *c, lctx *d)
{
	if(d->font) {
		de_free(c, d->font->char_array);
		de_destroy_bitmap_font(c, d->font);
	}
	de_free(c, d->font_data);
	de_free(c, d);
}

static void de_run_xbin(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	struct de_SAUCE_detection_data sdd;
	struct de_SAUCE_info *si = NULL;
	de_int64 pos = 0;
	de_byte flags;
	dbuf *unc_data = NULL;

	d = de_malloc(c, sizeof(lctx));

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->prefer_image_output = 1;

	de_memset(&sdd, 0, sizeof(struct de_SAUCE_detection_data));
	de_detect_SAUCE(c, c->infile, &sdd);

	if(sdd.has_SAUCE) {
		si = de_malloc(c, sizeof(struct de_SAUCE_info));
		de_read_SAUCE(c, c->infile, si);
		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
		charctx->num_comments = si->num_comments;
		charctx->comments = si->comments;
	}

	d->width_in_chars = de_getui16le(5);
	d->height_in_chars = de_getui16le(7);
	d->font_height = (de_int64)de_getbyte(9);
	if(d->font_height<1 || d->font_height>32) {
		de_err(c, "Invalid font height: %d", (int)d->font_height);
		goto done;
	}

	flags = de_getbyte(10);
	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d characters", (int)d->width_in_chars, (int)d->height_in_chars);
	de_dbg(c, "font height: %d", (int)d->font_height);
	de_dbg(c, "flags: 0x%02x", (unsigned int)flags);
	d->has_palette = (flags&0x01)?1:0;
	d->has_font = (flags&0x02)?1:0;
	d->compression = (flags&0x04)?1:0;
	d->nonblink = (flags&0x08)?1:0;
	d->has_512chars = (flags&0x10)?1:0;
	de_dbg(c, " has palette: %d", (int)d->has_palette);
	de_dbg(c, " has font: %d", (int)d->has_font);
	de_dbg(c, " compression: %d", (int)d->compression);
	de_dbg(c, " non-blink mode: %d", (int)d->nonblink);
	de_dbg(c, " 512 character mode: %d", (int)d->has_512chars);

	pos = 11;

	if(d->has_palette) {
		do_read_palette(c, d, charctx, pos, 0);
		pos += 48;
	}
	else {
		de_dbg(c, "using default palette");
		do_default_palette(c, d, charctx);
	}

	if(d->has_font) {
		d->font = de_create_bitmap_font(c);
		d->font->has_nonunicode_codepoints = 1;
		d->font->has_unicode_codepoints = 1;
		d->font->prefer_unicode = 0;
		d->font->num_chars = d->has_512chars ? 512 : 256;
		d->font_data_len = d->font->num_chars * d->font_height;
		if(d->font->num_chars!=256) {
			de_err(c, "%d-character mode is not supported", (int)d->font->num_chars);
			goto done;
		}

		do_read_font_data(c, d, pos);
		pos += d->font_data_len;

		if(d->is_standard_font) {
			charctx->suppress_custom_font_warning = 1;
		}

		if(!do_generate_font(c, d)) goto done;

		if(c->extract_level>=2) {
			do_extract_font(c, d);
		}

		charctx->font = d->font;
	}
	else {
		// Use default font

		// FIXME: We probably shouldn't give up if font_height!=16, at
		// least if the output format is HTML.
		if(d->has_512chars || d->font_height!=16) {
			de_err(c, "This type of XBIN file is not supported.");
			goto done;
		}
	}

	de_dbg(c, "image data at %d", (int)pos);

	if(d->compression) {
		unc_data = dbuf_create_membuf(c, d->width_in_chars * d->height_in_chars * 2, 1);
		do_uncompress_data(c, d, pos, unc_data);
	}
	else {
		unc_data = dbuf_open_input_subfile(c->infile, pos, c->infile->len-pos);
	}
	do_bin_main(c, d, unc_data, charctx);

done:
	dbuf_close(unc_data);
	de_free_charctx(c, charctx);
	de_free_SAUCE(c, si);
	free_lctx(c, d);
}

static int de_identify_xbin(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "XBIN\x1a", 5))
		return 100;
	return 0;
}

static void de_help_xbin(deark *c)
{
	de_msg(c, "-opt char:output=html : Write HTML instead of an image file");
	de_msg(c, "-opt char:charwidth=<8|9> : Width of a character cell");
}

void de_module_xbin(deark *c, struct deark_module_info *mi)
{
	mi->id = "xbin";
	mi->desc = "XBIN character graphics";
	mi->run_fn = de_run_xbin;
	mi->identify_fn = de_identify_xbin;
	mi->help_fn = de_help_xbin;
}

////////////////////// Binary Text //////////////////////

static void de_run_bintext(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	struct de_SAUCE_detection_data sdd;
	struct de_SAUCE_info *si = NULL;
	dbuf *unc_data = NULL;
	de_int64 effective_file_size = 0;
	int valid_sauce = 0;
	const char *s;
	de_int64 width_req = 0;

	d = de_malloc(c, sizeof(lctx));

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->prefer_image_output = 0;

	s=de_get_ext_option(c, "char:width");
	if(s) {
		width_req = de_atoi(s);
	}

	de_memset(&sdd, 0, sizeof(struct de_SAUCE_detection_data));
	de_detect_SAUCE(c, c->infile, &sdd);

	if(sdd.has_SAUCE) {
		si = de_malloc(c, sizeof(struct de_SAUCE_info));
		de_read_SAUCE(c, c->infile, si);
		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
		charctx->num_comments = si->num_comments;
		charctx->comments = si->comments;

		effective_file_size = si->original_file_size;

		if(si->data_type==5) {
			valid_sauce = 1;

			// For BinText, the FileType field is inexplicably used for the width.
			d->width_in_chars = 2*(de_int64)sdd.file_type;

			if(si->tflags & 0x01) {
				d->nonblink = 1;
			}
			if((si->tflags & 0x18)>>3 == 0x02) {
				// Square pixels requested
				charctx->no_density = 1;
			}
			if((si->tflags & 0x06)>>1 == 0x02) {
				charctx->prefer_9col_mode = 1;
			}
		}
	}

	if(!valid_sauce) {
		d->width_in_chars = 160;
		effective_file_size = c->infile->len;
	}

	if(width_req>0) d->width_in_chars = width_req;

	if(d->width_in_chars<1) d->width_in_chars=160;
	if(effective_file_size%(d->width_in_chars*2)) {
		de_warn(c, "File does not contain a whole number of rows. The width may "
			"be wrong. Try \"-opt char:width=...\".");
	}
	d->height_in_chars = effective_file_size / (d->width_in_chars*2);

	de_dbg(c, "width: %d chars", (int)d->width_in_chars);
	de_dbg(c, "calculated height: %d chars", (int)d->height_in_chars);
	d->has_palette = 1;
	d->has_font = 1;
	d->compression = 0;
	d->has_512chars = 0;

	do_default_palette(c, d, charctx);

	unc_data = dbuf_open_input_subfile(c->infile, 0, effective_file_size);
	do_bin_main(c, d, unc_data, charctx);

	dbuf_close(unc_data);
	de_free_charctx(c, charctx);
	de_free_SAUCE(c, si);
	free_lctx(c, d);
}

static int de_identify_bintext(deark *c)
{
	if(!c->detection_data.sauce.detection_attempted) {
		de_err(c, "bintext internal");
		de_fatalerror(c);
	}
	if(c->detection_data.sauce.has_SAUCE) {
		if(c->detection_data.sauce.data_type==5)
		{
			return 100;
		}
	}
	return 0;
}

static void de_help_bintext(deark *c)
{
	de_msg(c, "-opt char:output=image : Write an image file instead of HTML");
	de_msg(c, " -opt char:charwidth=<8|9> : Width of a character cell");
	de_msg(c, "-opt char:width=<n> : Number of characters per row");
}

void de_module_bintext(deark *c, struct deark_module_info *mi)
{
	mi->id = "bintext";
	mi->desc = "Binary Text character graphics";
	mi->run_fn = de_run_bintext;
	mi->identify_fn = de_identify_bintext;
	mi->help_fn = de_help_bintext;
}

////////////////////// ArtWorx Data Format (ADF) //////////////////////

static void de_run_artworx_adf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	dbuf *unc_data = NULL;
	de_int64 data_start;
	de_int64 data_len;

	d = de_malloc(c, sizeof(lctx));

	// TODO: ADF files can probably have SAUCE records, so we should read
	// the SAUCE data if present. But there does not seem to be a defined
	// SAUCE file type for ADF.

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->prefer_image_output = 1;

	data_start = 1+192+4096;
	data_len = c->infile->len - data_start;
	if(data_len<0) goto done;

	d->width_in_chars = 80;
	d->height_in_chars = data_len / (d->width_in_chars*2);

	de_dbg(c, "guessed width: %d chars", (int)d->width_in_chars);
	de_dbg(c, "calculated height: %d chars", (int)d->height_in_chars);
	if(d->height_in_chars<1) goto done;
	d->has_palette = 0;
	d->has_font = 1;
	d->compression = 0;
	d->has_512chars = 0;
	d->nonblink = 1;

	do_read_palette(c, d, charctx, 1, 1);

	{
		// TODO: This duplicates a lot of the xbin code.

		d->font = de_create_bitmap_font(c);
		d->font->has_nonunicode_codepoints = 1;
		d->font->has_unicode_codepoints = 1;
		d->font->prefer_unicode = 0;
		d->font->num_chars = 256;
		d->font_height = 16;
		d->font_data_len = d->font->num_chars * d->font_height;

		do_read_font_data(c, d, 1+192);

		if(d->is_standard_font) {
			charctx->suppress_custom_font_warning = 1;
		}

		if(!do_generate_font(c, d)) goto done;

		if(c->extract_level>=2) {
			do_extract_font(c, d);
		}

		charctx->font = d->font;
	}

	unc_data = dbuf_open_input_subfile(c->infile, data_start, data_len);
	do_bin_main(c, d, unc_data, charctx);

done:
	dbuf_close(unc_data);
	de_free_charctx(c, charctx);
	free_lctx(c, d);
}

static int de_identify_artworx_adf(deark *c)
{
	de_byte ver;

	// TODO: This detection algorithm will fail if there is a SAUCE record.

	if(c->infile->len < 1+192+4096+160) {
		return 0;
	}
	if((c->infile->len - (1+192+4096))%160 != 0) {
		return 0;
	}
	if(!de_input_file_has_ext(c, "adf")) return 0;
	ver = de_getbyte(0);
	// I don't know what version numbers are allowed, but I'll assume the
	// version number should be small.
	if(ver>4) return 0;
	return 75;
}

static void de_help_artworx_adf(deark *c)
{
	de_msg(c, "-opt char:output=html : Write HTML instead of an image file");
	de_msg(c, "-opt char:charwidth=<8|9> : Width of a character cell");
	de_msg(c, "-opt char:width=<n> : Number of characters per row");
}

void de_module_artworx_adf(deark *c, struct deark_module_info *mi)
{
	mi->id = "artworx_adf";
	mi->desc = "ArtWorx Data Format (ADF)";
	mi->run_fn = de_run_artworx_adf;
	mi->identify_fn = de_identify_artworx_adf;
	mi->help_fn = de_help_artworx_adf;
}

////////////////////// iCEDraw format (.idf) //////////////////////

// This module is not yet implemented. This stub exists because it seemed
// like the simplest way to accomplish multiple goals:
//  * Avoid having iCEDraw mis-identified as ANSI Art.
//  * Avoid an error message from the SAUCE module implying that ANSI
//     Art is not a supported format.
//  * Print debugging info about the SAUCE record, if present.
//  * Print the same error message whether or not a SAUCE record is present.

static void de_run_icedraw(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_detection_data sdd;

	de_memset(&sdd, 0, sizeof(struct de_SAUCE_detection_data));
	de_detect_SAUCE(c, c->infile, &sdd);
	if(sdd.has_SAUCE) {
		// Read the SAUCE record if present, just for the debugging info.
		struct de_SAUCE_info *si = NULL;
		si = de_malloc(c, sizeof(struct de_SAUCE_info));
		de_read_SAUCE(c, c->infile, si);
		de_free_SAUCE(c, si);
	}

	de_err(c, "iCEDraw format is not supported");
}

static int de_identify_icedraw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x04\x31\x2e\x34", 4)) {
		return 100;
	}
	return 0;
}

void de_module_icedraw(deark *c, struct deark_module_info *mi)
{
	mi->id = "icedraw";
	mi->desc = "iCEDraw character graphics format";
	mi->run_fn = de_run_icedraw;
	mi->identify_fn = de_identify_icedraw;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
