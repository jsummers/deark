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
DE_DECLARE_MODULE(de_module_thedraw_com);

typedef struct localctx_struct {
	i64 width_in_chars, height_in_chars;
	i64 font_height;
	u8 has_palette, has_font, compression, nonblink, has_512chars;

	i64 font_data_len;
	u8 *font_data;
	int is_standard_font;
	struct de_bitmap_font *font;
} lctx;

static void do_bin_main(deark *c, lctx *d, dbuf *unc_data, struct de_char_context *charctx)
{
	i64 i, j;
	u8 ccode, acode;
	u8 fgcol, bgcol;
	struct de_char_screen *screen;
	struct de_encconv_state es;

	charctx->nscreens = 1;
	charctx->screens = de_mallocarray(c, charctx->nscreens, sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];
	screen->width = d->width_in_chars;
	screen->height = d->height_in_chars;
	screen->cell_rows = de_mallocarray(c, d->height_in_chars, sizeof(struct de_char_cell*));
	de_encconv_init(&es, DE_ENCODING_CP437_G);

	for(j=0; j<d->height_in_chars; j++) {
		screen->cell_rows[j] = de_mallocarray(c, d->width_in_chars, sizeof(struct de_char_cell));

		for(i=0; i<d->width_in_chars; i++) {
			ccode = dbuf_getbyte(unc_data, j*d->width_in_chars*2 + i*2);
			acode = dbuf_getbyte(unc_data, j*d->width_in_chars*2 + i*2 + 1);

			if((acode&0x80) && !d->nonblink) {
				screen->cell_rows[j][i].blink = 1;
				acode -= 0x80;
			}

			fgcol = (acode & 0x0f);
			bgcol = (acode & 0xf0) >> 4;

			screen->cell_rows[j][i].fgcol = (u32)fgcol;
			screen->cell_rows[j][i].bgcol = (u32)bgcol;
			screen->cell_rows[j][i].codepoint = (i32)ccode;
			screen->cell_rows[j][i].codepoint_unicode = de_char_to_unicode_ex((i32)ccode, &es);
		}
	}

	de_char_output_to_file(c, charctx);
}

static void do_uncompress_data(deark *c, lctx *d, i64 pos1, dbuf *unc_data)
{
	i64 pos;
	u8 cmprtype;
	i64 count;
	i64 xpos, ypos;
	u8 b;
	u8 b1, b2;
	i64 k;

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
		count = (i64)(b&0x3f) +1;

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
	i64 pos, int adf_style)
{
	i64 k;
	u8 cr1, cg1, cb1;
	u8 cr2, cg2, cb2;
	i64 cpos;
	char tmps[64];

	de_dbg(c, "palette at %d", (int)pos);

	for(k=0; k<16; k++) {
		i64 idx = k;

		if(adf_style) {
			if(k>=8) idx = 48+k;
			else if(k==6) idx = 20;
		}
		cpos = pos + idx*3;
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
	de_copy_std_palette(DE_PALID_PC16, 0, 0, charctx->pal, 16, 0);
}

static void do_extract_font(deark *c, lctx *d)
{
	de_finfo *fi = NULL;

	if(!d->has_font || !d->font) return;
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, "font", 0, DE_ENCODING_ASCII);

	de_font_bitmap_font_to_image(c, d->font, fi, DE_CREATEFLAG_IS_AUX);

	de_finfo_destroy(c, fi);
}

static void do_read_font_data(deark *c, lctx *d, i64 pos)
{
	u32 crc;
	struct de_crcobj *crco;

	de_dbg(c, "font at %d, %d bytes", (int)pos, (int)d->font_data_len);
	de_dbg_indent(c, 1);
	d->font_data = de_malloc(c, d->font_data_len);
	de_read(d->font_data, pos, d->font_data_len);

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addbuf(crco, d->font_data, d->font_data_len);
	crc = de_crcobj_getval(crco);
	de_crcobj_destroy(crco);

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
	i64 i;
	struct de_encconv_state es;

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
	d->font->char_array = de_mallocarray(c, d->font->num_chars, sizeof(struct de_bitmap_font_char));
	de_encconv_init(&es, DE_ENCODING_CP437_G);

	for(i=0; i<d->font->num_chars; i++) {
		d->font->char_array[i].codepoint_nonunicode = (i32)i;
		d->font->char_array[i].codepoint_unicode = de_char_to_unicode_ex((i32)i, &es);
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
	i64 pos = 0;
	u8 flags;
	dbuf *unc_data = NULL;

	d = de_malloc(c, sizeof(lctx));

	charctx = de_create_charctx(c, 0);
	charctx->prefer_image_output = 1;
	de_char_decide_output_format(c, charctx);

	fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(sdd.has_SAUCE) {
		si = fmtutil_create_SAUCE(c);

		de_dbg_indent(c, 1);
		fmtutil_handle_SAUCE(c, c->infile, si);
		de_dbg_indent(c, -1);

		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
		charctx->comment = si->comment;
	}

	d->width_in_chars = de_getu16le(5);
	d->height_in_chars = de_getu16le(7);
	d->font_height = (i64)de_getbyte(9);

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

	if(d->has_font && (d->font_height<1 || d->font_height>32)) {
		de_err(c, "Invalid font height: %d", (int)d->font_height);
		goto done;
	}
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

		if(d->has_512chars) {
			de_err(c, "This type of XBIN file is not supported.");
			goto done;
		}

		if(d->font_height==0) {
			// Not really legal, but we'll let it mean "default".
		}
		else if(d->font_height!=16) {
			if(charctx->outfmt==1) { // image output
				de_warn(c, "Incompatible font height (%d), using 16 instead.", (int)d->font_height);
			}
		}
		d->font_height = 16;
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
	de_free_charctx_screens(c, charctx);
	de_destroy_charctx(c, charctx);
	fmtutil_free_SAUCE(c, si);
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
	i64 effective_file_size = 0;
	int valid_sauce = 0;
	const char *s;
	i64 width_req = 0;

	d = de_malloc(c, sizeof(lctx));

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->prefer_image_output = 0;

	s=de_get_ext_option(c, "char:width");
	if(s) {
		width_req = de_atoi(s);
	}

	fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(sdd.has_SAUCE) {
		si = fmtutil_create_SAUCE(c);

		de_dbg_indent(c, 1);
		fmtutil_handle_SAUCE(c, c->infile, si);
		de_dbg_indent(c, -1);

		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
		charctx->comment = si->comment;

		effective_file_size = si->original_file_size;

		if(si->data_type==5) {
			valid_sauce = 1;

			if(si->file_type==1 && si->tinfo1>0) {
				// Some files created by ACiDDraw do this.
				d->width_in_chars = 2*(i64)si->tinfo1;
			}
			else {
				// For BinText, the FileType field is inexplicably used for the width (usually).
				d->width_in_chars = 2*(i64)si->file_type;
			}

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
	fmtutil_free_SAUCE(c, si);
	free_lctx(c, d);
}

static int de_identify_bintext(deark *c)
{
	if(!c->detection_data->SAUCE_detection_attempted) {
		// FIXME?: This is known to happen if "-disablemods sauce" was used.
		de_err(c, "bintext detection requires sauce module");
		return 0;
	}
	if(c->detection_data->sauce.has_SAUCE) {
		if(c->detection_data->sauce.data_type==5)
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
	i64 data_start;
	i64 data_len;

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
	u8 ver;

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

	fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(sdd.has_SAUCE) {
		// Read the SAUCE record if present, just for the debugging info.
		struct de_SAUCE_info *si = NULL;
		si = fmtutil_create_SAUCE(c);

		de_dbg_indent(c, 1);
		fmtutil_handle_SAUCE(c, c->infile, si);
		de_dbg_indent(c, -1);

		fmtutil_free_SAUCE(c, si);
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

////////////////////// TheDraw COM //////////////////////

struct thedrawcom_dcmpr_state {
	u8 prescan_mode;
	u8 curr_fg_code;
	u8 curr_bg_code;
	u8 curr_blink_code;
	i64 next_xpos, next_ypos;
	i64 max_xpos, max_ypos;
	i64 ypos_of_last_nonblank;
};

struct thedrawcom_ctx {
	lctx *d;
	struct de_char_context *charctx;
	dbuf *unc_data;
	struct de_crcobj *crco;
	i64 screen_pos_raw;
	i64 data_pos;
	u8 errflag;
	u8 need_errmsg;
	u8 fmt_subtype;
	i64 cmpr_len;
	i64 viewer_start;
	i64 viewer_len;
	u32 viewer_expected_crc;
	struct thedrawcom_dcmpr_state dc;
};

#define THEDRAWCOM_MAX_WIDTH   160
#define THEDRAWCOM_MAX_HEIGHT  200

static void tdc_decrunch_emit_char(deark *c, struct thedrawcom_ctx *tdc, u8 ch)
{
	if(!tdc->dc.prescan_mode) {
		dbuf_writebyte(tdc->unc_data, ch);
		dbuf_writebyte(tdc->unc_data, (u8)(tdc->dc.curr_blink_code |
			tdc->dc.curr_bg_code | tdc->dc.curr_fg_code));
	}
	if(tdc->dc.next_xpos > tdc->dc.max_xpos) {
		tdc->dc.max_xpos = tdc->dc.next_xpos;
	}
	if(tdc->dc.next_ypos > tdc->dc.max_ypos) {
		tdc->dc.max_ypos = tdc->dc.next_ypos;
	}
	if(ch!=0 && ch!=32 && tdc->dc.next_ypos>tdc->dc.ypos_of_last_nonblank) {
		tdc->dc.ypos_of_last_nonblank = tdc->dc.next_ypos;
	}
	tdc->dc.next_xpos++;
}

// Based on the description in UNCRUNCH.ASM from TheDraw 4.xx.
static void thedrawcom_decrunch(deark *c, struct thedrawcom_ctx *tdc, u8 prescan_mode)
{
	i64 pos = tdc->data_pos;
	i64 endpos = tdc->data_pos + tdc->cmpr_len;
	struct thedrawcom_dcmpr_state *dc = &tdc->dc;

	de_zeromem(dc, sizeof(struct thedrawcom_dcmpr_state));
	dc->prescan_mode = prescan_mode;
	dc->curr_fg_code = 0xf;

	if(endpos > c->infile->len) {
		tdc->errflag = 1;
		tdc->need_errmsg = 1;
		goto done;
	}

	if(!tdc->unc_data) {
		tdc->unc_data = dbuf_create_membuf(c, 80*2*25, 0);
		dbuf_set_length_limit(tdc->unc_data,
			THEDRAWCOM_MAX_WIDTH*2*THEDRAWCOM_MAX_HEIGHT);
		dbuf_enable_wbuffer(tdc->unc_data);
	}

	while(1) {
		u8 b0, b1, b2;
		i64 k;

		if(tdc->errflag) goto done;
		if(pos >= endpos) break;

		b0 = de_getbyte_p(&pos);

		if(b0>=32) {
			tdc_decrunch_emit_char(c, tdc, b0);
			continue;
		}
		if(b0<=15) {
			dc->curr_fg_code = b0;
		}
		else if(b0<=23) {
			dc->curr_bg_code = (b0-16)<<4;
		}
		else if(b0==24) { // Newline

			dc->next_ypos++;
			dc->next_xpos = 0;

			if(!dc->prescan_mode) {
				i64 expected_len;
				i64 actual_len;

				// Make sure we're in the right place in the decompressed data.
				expected_len = tdc->d->width_in_chars * 2 * dc->next_ypos;
				actual_len = dbuf_get_length(tdc->unc_data);
				if(actual_len != expected_len) {
					// It would be better to pad with spaces, but in practice
					// this doesn't happen.
					dbuf_truncate(tdc->unc_data, expected_len);
				}
			}
		}
		else if(b0==25) { // Run of spaces
			b1 = de_getbyte_p(&pos);
			for(k=0; k<(i64)b1+1; k++) {
				tdc_decrunch_emit_char(c, tdc, 32);
			}
		}
		else if(b0==26) { // Run of an arbitrary character
			b1 = de_getbyte_p(&pos);
			b2 = de_getbyte_p(&pos);
			for(k=0; k<(i64)b1+1; k++) {
				tdc_decrunch_emit_char(c, tdc, b2);
			}
		}
		else if(b0==27) { // Toggle blink mode
			dc->curr_blink_code = (dc->curr_blink_code==0) ? 0x80 : 0x00;
		}
		else { // Unknown opcode
			tdc->errflag = 1;
			tdc->need_errmsg = 1;
			goto done;
		}
	}

	// Decompression finished normally

	if((dc->max_xpos+1 > THEDRAWCOM_MAX_WIDTH) ||
		(dc->max_ypos+1 > THEDRAWCOM_MAX_HEIGHT))
	{
		tdc->errflag = 1;
		tdc->need_errmsg = 1;
		goto done;
	}

	if(dc->prescan_mode && !tdc->errflag) {
		de_dbg(c, "number of rows: %d", (int)(dc->max_ypos+1));
		de_dbg(c, "last nonblank row: %d", (int)dc->ypos_of_last_nonblank);
		tdc->d->width_in_chars = dc->max_xpos + 1;

		if(dc->max_ypos>24) {
			tdc->d->height_in_chars = dc->ypos_of_last_nonblank + 1;
		}
		else {
			tdc->d->height_in_chars = dc->max_ypos + 1;
		}

		de_dbg_dimensions(c, tdc->d->width_in_chars, tdc->d->height_in_chars);
	}

done:
	dbuf_flush(tdc->unc_data);

	if(tdc->need_errmsg) {
		de_err(c, "Decompression failed");
		tdc->need_errmsg = 0;
		tdc->errflag = 1;
	}
}

static void de_run_thedraw_com(deark *c, de_module_params *mparams)
{
	struct thedrawcom_ctx *tdc = NULL;
	u32 cv;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	tdc = de_malloc(c, sizeof(struct thedrawcom_ctx));
	tdc->d = de_malloc(c, sizeof(lctx));
	tdc->charctx = de_create_charctx(c, 0);
	do_default_palette(c, tdc->d, tdc->charctx);

	tdc->fmt_subtype = de_getbyte(6);
	de_dbg(c, "format subtype: %u", (UI)tdc->fmt_subtype);

	tdc->viewer_start = 2 + (i64)de_getbyte(1);
	de_dbg2(c, "viewer pos: %"I64_FMT, tdc->viewer_start);

	if(tdc->fmt_subtype==0) {
		tdc->viewer_len = 113;
		tdc->viewer_expected_crc = 0x440affaeU;
		tdc->data_pos = 176;
	}
	else if(tdc->fmt_subtype==1) {
		tdc->viewer_len = 68;
		tdc->viewer_expected_crc = 0xe427d2e3U;
		tdc->data_pos = 94;
	}
	else if(tdc->fmt_subtype==2) {
		tdc->viewer_len = 177;
		tdc->viewer_expected_crc = 0x492a698d;
		tdc->data_pos = 240;
	}
	else {
		de_err(c, "Unsupported format subtype: %u", (UI)tdc->fmt_subtype);
		goto done;
	}

	tdc->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(tdc->crco, c->infile, tdc->viewer_start, tdc->viewer_len);

	cv = de_crcobj_getval(tdc->crco);
	de_dbg2(c, "viewer crc: 0x%08x", (UI)cv);
	if(cv != tdc->viewer_expected_crc) {
		de_warn(c, "Unrecognized format variant. This file might not be "
			"decoded correctly.");
	}

	if(tdc->fmt_subtype==0) {
		tdc->d->height_in_chars = (i64)de_getbyte(4);
		tdc->d->width_in_chars = (i64)de_getbyte(5);
		de_dbg_dimensions(c, tdc->d->width_in_chars, tdc->d->height_in_chars);
	}

	if(tdc->fmt_subtype==1) {
		i64 nchars;

		tdc->d->width_in_chars = 80;
		nchars = de_getu16le(4);
		de_dbg(c, "num. chars: %"I64_FMT, nchars);
		tdc->d->height_in_chars = de_pad_to_n(nchars, 80)/80;
		de_dbg_dimensions(c, tdc->d->width_in_chars, tdc->d->height_in_chars);
	}

	if(tdc->fmt_subtype==2) {
		tdc->cmpr_len = de_getu16le(4);
		de_dbg(c, "cmpr len: %"I64_FMT, tdc->cmpr_len);
	}

	tdc->screen_pos_raw = de_geti16le(7);
	de_dbg(c, "screen pos: %d", (int)tdc->screen_pos_raw);
	// TODO? The screen pos is relevant if just a block, instead of a whole
	// screen, was saved.
	// We could artificially pad the image with spaces above/left/right in
	// that case.

	de_dbg(c, "data pos: %"I64_FMT, tdc->data_pos);

	if(tdc->fmt_subtype==2) {
		de_dbg(c, "decompressing");
		de_dbg_indent(c, 1);
		// The first decompression is to figure out the dimensions.
		thedrawcom_decrunch(c, tdc, 1);
		if(tdc->errflag) goto done;
		thedrawcom_decrunch(c, tdc, 0);
		if(tdc->errflag) goto done;
		de_dbg_indent(c, -1);
	}
	else {
		tdc->unc_data = dbuf_open_input_subfile(c->infile, tdc->data_pos,
			c->infile->len-tdc->data_pos);
	}

	if(!tdc->unc_data || tdc->d->width_in_chars<1 || tdc->d->height_in_chars<1) {
		tdc->need_errmsg = 1;
		goto done;
	}

	if(tdc->errflag) goto done;
	do_bin_main(c, tdc->d, tdc->unc_data, tdc->charctx);

done:
	if(tdc) {
		if(tdc->need_errmsg) {
			de_err(c, "Failed to decode this file");
		}

		dbuf_close(tdc->unc_data);
		if(tdc->charctx) {
			de_free_charctx_screens(c, tdc->charctx);
			de_destroy_charctx(c, tdc->charctx);
		}
		de_crcobj_destroy(tdc->crco);
		free_lctx(c, tdc->d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_thedraw_com(deark *c)
{
	u8 n1, n2;

	n1 = de_getbyte(0);
	if(n1!=0xeb) return 0;

	n1 = de_getbyte(1);
	n2 = de_getbyte(6);
	// Check format subtype & viewer start position.
	if((n2==0 && n1==0x3d) ||
		(n2==1 && n1==0x18) ||
		(n2==2 && n1==0x3d))
	{
		;
	}
	else {
		return 0;
	}

	if(!dbuf_memcmp(c->infile, 9, (const void*)"TheDraw COM file", 16)) {
		return 100;
	}

	if(n2==0) {
		if(!dbuf_memcmp(c->infile, 0x3f,
			(const void*)"\xb4\x0f\xcd\x10\x8c\xcb\x8e\xdb\xbb\x00", 10))
		{
			// An extra check to defend against lookalike formats, particularly
			// P-Screen (search for pscrn_55.zip).
			if(de_getbyte(0x3f+76)==0xad) {
				return 40;
			}
		}
	}
	else if(n2==1) {
		if(!dbuf_memcmp(c->infile, 0x1a,
			(const void*)"\xb4\x0f\xcd\x10\x8b\x3e\x07\x01\xbe\x5e", 10))
		{
			return 40;
		}
	}
	else if(n2==2) {
		if(!dbuf_memcmp(c->infile, 0x3f,
			(const void*)"\xb4\x0f\xcd\x10\xbb\x00\xb8\x3c\x02\x74", 10))
		{
			return 40;
		}
	}

	return 0;
}

void de_module_thedraw_com(deark *c, struct deark_module_info *mi)
{
	mi->id = "thedraw_com";
	mi->desc = "TheDraw COM file";
	mi->run_fn = de_run_thedraw_com;
	mi->identify_fn = de_identify_thedraw_com;
}
