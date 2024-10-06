// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// XBIN character graphics
// "Binary Text" character graphics
// ArtWorx ADF character graphics
// Etc.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_xbin);
DE_DECLARE_MODULE(de_module_bintext);
DE_DECLARE_MODULE(de_module_artworx_adf);
DE_DECLARE_MODULE(de_module_icedraw);
DE_DECLARE_MODULE(de_module_thedraw_com);
DE_DECLARE_MODULE(de_module_aciddraw_com);
DE_DECLARE_MODULE(de_module_grabber);

typedef struct localctx_struct_bintext {
	u8 errflag;
	u8 need_errmsg;
	u8 has_palette, has_font, compression, has_512chars;

	i64 font_height;
	i64 font_data_len;
	u8 *font_data;
	int is_standard_font;
	struct de_bitmap_font *font;
	struct fmtutil_char_simplectx csctx;
} lctx;

static void free_lctx(deark *c, lctx *d)
{
	if(d->font) {
		de_free(c, d->font->char_array);
		de_destroy_bitmap_font(c, d->font);
	}
	de_free(c, d->font_data);
	de_free(c, d);
}

static void read_and_discard_SAUCE(deark *c)
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
}

static void xbin_decompress_data(deark *c, lctx *d, i64 pos1, dbuf *unc_data)
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
		if(xpos >= d->csctx.width_in_chars) {
			ypos++;
			xpos = 0;
		}
		if(ypos >= d->csctx.height_in_chars) {
			break;
		}

		b = de_getbyte_p(&pos);
		cmprtype = b>>6;
		count = (i64)(b&0x3f) +1;

		switch(cmprtype) {
		case 0: // Uncompressed
			dbuf_copy(c->infile, pos, count*2, unc_data);
			pos += count*2;
			break;
		case 1: // Character compression
			b1 = de_getbyte_p(&pos); // character code
			for(k=0; k<count; k++) {
				b2 = de_getbyte_p(&pos); // attribute code
				dbuf_writebyte(unc_data, b1);
				dbuf_writebyte(unc_data, b2);
			}
			break;
		case 2: // Attribute compression
			b2 = de_getbyte_p(&pos); // attribute code
			for(k=0; k<count; k++) {
				b1 = de_getbyte_p(&pos); // character code
				dbuf_writebyte(unc_data, b1);
				dbuf_writebyte(unc_data, b2);
			}
			break;
		case 3: // Character/Attribute compression
			b1 = de_getbyte_p(&pos); // character code
			b2 = de_getbyte_p(&pos); // attribute code
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

	de_dbg(c, "palette at %"I64_FMT, pos);

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

	de_dbg(c, "font at %"I64_FMT", %"I64_FMT" bytes", pos, d->font_data_len);
	de_dbg_indent(c, 1);
	d->font_data = de_malloc(c, d->font_data_len);
	de_read(d->font_data, pos, d->font_data_len);

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addbuf(crco, d->font_data, d->font_data_len);
	crc = de_crcobj_getval(crco);
	de_crcobj_destroy(crco);

	d->is_standard_font = de_font_is_standard_vga_font(c, crc);
	de_dbg(c, "font crc: 0x%08x (%s)", (UI)crc,
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

	d->csctx.width_in_chars = de_getu16le(5);
	d->csctx.height_in_chars = de_getu16le(7);
	d->font_height = (i64)de_getbyte(9);

	flags = de_getbyte(10);
	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d characters", (int)d->csctx.width_in_chars,
		(int)d->csctx.height_in_chars);
	de_dbg(c, "font height: %d", (int)d->font_height);
	de_dbg(c, "flags: 0x%02x", (UI)flags);
	d->has_palette = (flags&0x01)?1:0;
	d->has_font = (flags&0x02)?1:0;
	d->compression = (flags&0x04)?1:0;
	d->csctx.nonblink = (flags&0x08)?1:0;
	d->has_512chars = (flags&0x10)?1:0;
	de_dbg_indent(c, 1);
	de_dbg(c, "has palette: %u", (UI)d->has_palette);
	de_dbg(c, "has font: %u", (UI)d->has_font);
	de_dbg(c, "compression: %u", (UI)d->compression);
	de_dbg(c, "non-blink mode: %u", (UI)d->csctx.nonblink);
	de_dbg(c, "512 character mode: %u", (UI)d->has_512chars);
	de_dbg_indent(c, -1);

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
		d->csctx.use_default_pal = 1;
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

	de_dbg(c, "image data at %"I64_FMT, pos);

	if(d->compression) {
		unc_data = dbuf_create_membuf(c, d->csctx.width_in_chars * d->csctx.height_in_chars * 2, 1);
		xbin_decompress_data(c, d, pos, unc_data);
	}
	else {
		unc_data = dbuf_open_input_subfile(c->infile, pos, c->infile->len-pos);
	}
	d->csctx.inf = unc_data;
	d->csctx.inf_pos = 0;
	d->csctx.inf_len = unc_data->len;
	fmtutil_char_simple_run(c, &d->csctx, charctx);

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
	i64 effective_file_size = 0;
	int valid_sauce = 0;
	const char *s;
	i64 width_req = 0;

	d = de_malloc(c, sizeof(lctx));
	d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	charctx = de_create_charctx(c, 0);
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
				d->csctx.width_in_chars = 2*(i64)si->tinfo1;
			}
			else {
				// For BinText, the FileType field is inexplicably used for the width (usually).
				d->csctx.width_in_chars = 2*(i64)si->file_type;
			}

			if(si->tflags & 0x01) {
				d->csctx.nonblink = 1;
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
		d->csctx.width_in_chars = 160;
		effective_file_size = c->infile->len;
	}

	if(width_req>0) d->csctx.width_in_chars = width_req;

	if(d->csctx.width_in_chars<1) d->csctx.width_in_chars=160;
	if(effective_file_size%(d->csctx.width_in_chars*2)) {
		de_warn(c, "File does not contain a whole number of rows. The width may "
			"be wrong. Try \"-opt char:width=...\".");
	}
	d->csctx.height_in_chars = effective_file_size / (d->csctx.width_in_chars*2);

	de_dbg(c, "width: %d chars", (int)d->csctx.width_in_chars);
	de_dbg(c, "calculated height: %d chars", (int)d->csctx.height_in_chars);
	d->has_palette = 1;
	d->has_font = 1;
	d->compression = 0;
	d->has_512chars = 0;

	d->csctx.use_default_pal = 1;
	d->csctx.inf = c->infile;
	d->csctx.inf_pos = 0;
	d->csctx.inf_len = effective_file_size;
	fmtutil_char_simple_run(c, &d->csctx, charctx);

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
	i64 data_start;
	i64 data_len;

	d = de_malloc(c, sizeof(lctx));

	// TODO: ADF files can probably have SAUCE records, so we should read
	// the SAUCE data if present. But there does not seem to be a defined
	// SAUCE file type for ADF.

	charctx = de_create_charctx(c, 0);
	charctx->prefer_image_output = 1;

	data_start = 1+192+4096;
	data_len = c->infile->len - data_start;
	if(data_len<0) goto done;

	d->csctx.width_in_chars = 80;
	d->csctx.height_in_chars = data_len / (d->csctx.width_in_chars*2);

	de_dbg(c, "guessed width: %d chars", (int)d->csctx.width_in_chars);
	de_dbg(c, "calculated height: %d chars", (int)d->csctx.height_in_chars);
	if(d->csctx.height_in_chars<1) goto done;
	d->has_palette = 0;
	d->has_font = 1;
	d->compression = 0;
	d->has_512chars = 0;
	d->csctx.nonblink = 1;

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

	d->csctx.inf = c->infile;
	d->csctx.inf_pos = data_start;
	d->csctx.inf_len = data_len;
	fmtutil_char_simple_run(c, &d->csctx, charctx);

done:
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
	read_and_discard_SAUCE(c);
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
		tdc->d->errflag = 1;
		tdc->d->need_errmsg = 1;
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

		if(tdc->d->errflag) goto done;
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
				expected_len = tdc->d->csctx.width_in_chars * 2 * dc->next_ypos;
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
			tdc->d->errflag = 1;
			tdc->d->need_errmsg = 1;
			goto done;
		}
	}

	// Decompression finished normally

	if((dc->max_xpos+1 > THEDRAWCOM_MAX_WIDTH) ||
		(dc->max_ypos+1 > THEDRAWCOM_MAX_HEIGHT))
	{
		tdc->d->errflag = 1;
		tdc->d->need_errmsg = 1;
		goto done;
	}

	if(dc->prescan_mode && !tdc->d->errflag) {
		de_dbg(c, "number of rows: %d", (int)(dc->max_ypos+1));
		de_dbg(c, "last nonblank row: %d", (int)dc->ypos_of_last_nonblank);
		tdc->d->csctx.width_in_chars = dc->max_xpos + 1;

		if(dc->max_ypos>24) {
			tdc->d->csctx.height_in_chars = dc->ypos_of_last_nonblank + 1;
		}
		else {
			tdc->d->csctx.height_in_chars = dc->max_ypos + 1;
		}

		de_dbg_dimensions(c, tdc->d->csctx.width_in_chars, tdc->d->csctx.height_in_chars);
	}

done:
	dbuf_flush(tdc->unc_data);

	if(tdc->d->need_errmsg) {
		de_err(c, "Decompression failed");
		tdc->d->need_errmsg = 0;
		tdc->d->errflag = 1;
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
	tdc->d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	tdc->charctx = de_create_charctx(c, 0);
	tdc->d->csctx.use_default_pal = 1;

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
		tdc->d->csctx.height_in_chars = (i64)de_getbyte(4);
		tdc->d->csctx.width_in_chars = (i64)de_getbyte(5);
		de_dbg_dimensions(c, tdc->d->csctx.width_in_chars, tdc->d->csctx.height_in_chars);
	}

	if(tdc->fmt_subtype==1) {
		i64 nchars;

		tdc->d->csctx.width_in_chars = 80;
		nchars = de_getu16le(4);
		de_dbg(c, "num. chars: %"I64_FMT, nchars);
		tdc->d->csctx.height_in_chars = de_pad_to_n(nchars, 80)/80;
		de_dbg_dimensions(c, tdc->d->csctx.width_in_chars, tdc->d->csctx.height_in_chars);
	}

	if(tdc->fmt_subtype==2) {
		tdc->cmpr_len = de_getu16le(4);
		de_dbg(c, "cmpr len: %"I64_FMT, tdc->cmpr_len);
	}

	tdc->screen_pos_raw = de_geti16le(7);
	de_dbg(c, "screen pos: %"I64_FMT, tdc->screen_pos_raw);
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
		if(tdc->d->errflag) goto done;
		thedrawcom_decrunch(c, tdc, 0);
		if(tdc->d->errflag) goto done;
		de_dbg_indent(c, -1);
	}
	else {
		tdc->unc_data = dbuf_open_input_subfile(c->infile, tdc->data_pos,
			c->infile->len-tdc->data_pos);
	}

	if(!tdc->unc_data || tdc->d->csctx.width_in_chars<1 || tdc->d->csctx.height_in_chars<1) {
		tdc->d->need_errmsg = 1;
		goto done;
	}

	if(tdc->d->errflag) goto done;
	tdc->d->csctx.inf = tdc->unc_data;
	tdc->d->csctx.inf_pos = 0;
	tdc->d->csctx.inf_len = tdc->unc_data->len;
	fmtutil_char_simple_run(c, &tdc->d->csctx, tdc->charctx);

done:
	if(tdc) {
		if(tdc->d && tdc->d->need_errmsg) {
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

	if(c->infile->len>65280) return 0;
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

////////////////////// ACiDDraw COM //////////////////////

struct aciddraw_id_data {
	u8 is_aciddraw;
	i64 jmppos;
};

struct aciddraw_ctx {
	int opt_disable_blink;
	struct de_SAUCE_info *si;
	struct de_char_context *charctx;
};

static void aciddraw_id(deark *c, u8 b0, struct aciddraw_id_data *adi)
{
	de_zeromem(adi, sizeof(struct aciddraw_id_data));
	if(b0==0xe9) {
		adi->jmppos = de_geti16le(1) + 3;
	}
	else if(b0==0xeb) {
		adi->jmppos = de_getbyte(1) + 2;
	}
	else {
		return;
	}

	if(dbuf_memcmp(c->infile, adi->jmppos,
		(const void*)"\xb8\x03\x00\xcd\x10\xb4\x01\xb9\x00\x20\xcd\x10\xe8", 13))
	{
		return;
	}
	adi->is_aciddraw = 1;
}

static void aciddraw_handle_SAUCE(deark *c, struct aciddraw_ctx *adctx)
{
	struct de_SAUCE_detection_data sdd;

	fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(!sdd.has_SAUCE) goto done;

	adctx->si = fmtutil_create_SAUCE(c);
	de_dbg_indent(c, 1);
	fmtutil_handle_SAUCE(c, c->infile, adctx->si);
	de_dbg_indent(c, -1);
	if(!adctx->si->is_valid) goto done;

	adctx->charctx->title = adctx->si->title;
	adctx->charctx->artist = adctx->si->artist;
	adctx->charctx->organization = adctx->si->organization;
	adctx->charctx->creation_date = adctx->si->creation_date;
	adctx->charctx->comment = adctx->si->comment;

	// Note about blinking text:
	// ACiDDraw has a nonblink mode (Ctrl+Z), but the COM files it writes do
	// not record or respect this mode in any way, even if a SAUCE record is
	// written. They just use whatever mode the video hardware is in, which
	// is usually the mode with blinking text.
	// So we don't bother to respect the SAUCE flag.
	// (ACiDDraw does have a separate BLINK.EXE utility that changes the mode,
	// which could maybe be useful in batch files.)

done:
	;
}

static void de_run_aciddraw_com(deark *c, de_module_params *mparams)
{
	struct aciddraw_ctx *adctx = NULL;
	lctx *d = NULL;
	u8 b;
	UI fmtver = 0;
	struct aciddraw_id_data adi;
	i64 data_pos, data_len;
	i64 num_rows;

	adctx = de_malloc(c, sizeof(struct aciddraw_ctx));
	d = de_malloc(c, sizeof(lctx));
	d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	adctx->charctx = de_create_charctx(c, 0);

	if(de_get_ext_option(c, "ansiart:noblink")) {
		adctx->opt_disable_blink = 1;
	}

	aciddraw_id(c, de_getbyte(0), &adi);
	if(!adi.is_aciddraw) {
		d->need_errmsg = 1;
		goto done;
	}

	aciddraw_handle_SAUCE(c, adctx);

	d->csctx.nonblink = adctx->opt_disable_blink;

	de_dbg(c, "jmp pos: %"I64_FMT, adi.jmppos);

	b = de_getbyte(adi.jmppos+224);
	if(b==0xe8) {
		fmtver = 20;
	}
	else if(b==0xb4) {
		fmtver = 25;
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "version: v1.%u-like", fmtver);

	data_pos = de_getu16le(adi.jmppos-24);
	data_pos -= 0x100;
	de_dbg(c, "data pos: %"I64_FMT, data_pos);

	num_rows = de_getu16le(adi.jmppos+16);
	if(fmtver==25) num_rows++;
	de_dbg(c, "num rows: %"I64_FMT, num_rows);

	d->csctx.width_in_chars = 80;
	d->csctx.height_in_chars = num_rows;

	data_len = num_rows * d->csctx.width_in_chars * 2;
	de_dbg(c, "data endpos: %"I64_FMT, data_pos + data_len);

	if(data_pos+data_len > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	d->csctx.use_default_pal = 1;
	d->csctx.inf = c->infile;
	d->csctx.inf_pos = data_pos;
	d->csctx.inf_len = data_len;
	fmtutil_char_simple_run(c, &d->csctx, adctx->charctx);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Unsupported ACiDDraw format");
		}
		free_lctx(c, d);
	}
	if(adctx) {
		de_free_charctx(c, adctx->charctx);
		fmtutil_free_SAUCE(c, adctx->si);
	}
}

static int de_identify_aciddraw_com(deark *c)
{
	u8 n1;
	struct aciddraw_id_data adi;

	if(c->infile->len>65280) return 0;
	n1 = de_getbyte(0);
	if(n1!=0xe9 && n1!=0xeb) return 0;
	aciddraw_id(c, n1, &adi);
	if(adi.is_aciddraw) {
		return 92;
	}
	return 0;
}

void de_module_aciddraw_com(deark *c, struct deark_module_info *mi)
{
	mi->id = "aciddraw_com";
	mi->desc = "ACiDDraw COM file";
	mi->run_fn = de_run_aciddraw_com;
	mi->identify_fn = de_identify_aciddraw_com;
}

////////////////////// GRABBER //////////////////////

struct grabber_id_data {
	u8 is_grabber;
	UI fmt_class;
	i64 jmppos;
};

struct grabber_ctx {
	u8 screen_mode;
	i64 data_pos, data_len;
	struct de_char_context *charctx;
	struct grabber_id_data gi;
};

static void grabber_id_com(deark *c, u8 b0, struct grabber_id_data *gi)
{
	de_zeromem(gi, sizeof(struct grabber_id_data));

	if(b0==0xfb) {
		if(!dbuf_memcmp(c->infile, 1,
			(const void*)"\xbe\x81\x00\x8a\x4c\xff\x30\xed\x09\xc9\x74", 11)) {
			gi->is_grabber = 1;
			gi->fmt_class = 200;
		}
		return;
	}

	if(b0!=0xe9) return;
	gi->jmppos = de_geti16le(1) + 3;

	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xad\x80\xfc\x0d\x74\x17\x3c\x0d\x74", 12))
	{
		gi->is_grabber = 1;
		gi->fmt_class = 300;
		return;
	}
	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xfc\xad\x80\xfc\x0d\x74\x1c\x3c\x0d\x74", 13))
	{
		gi->is_grabber = 1;
		gi->fmt_class = 334;
		return;
	}
}

static void decode_grabber_com(deark *c, lctx *d, struct grabber_ctx *gctx)
{
	i64 foundpos = 0;
	i64 pos_of_data_ptr;
	i64 pos_of_mode;
	int ret;
	u8 *mem = NULL;

#define GRABBER_SEARCH1_START 112
#define GRABBER_BUF_LEN1 1024
	mem = de_malloc(c, GRABBER_BUF_LEN1);
	de_read(mem, GRABBER_SEARCH1_START, GRABBER_BUF_LEN1);
	// Search for the byte pattern preceding the data pointer.
	// Known positions range from 121 (v2.10) to 869 (v3.34).
	ret = de_memsearch_match(mem, GRABBER_BUF_LEN1,
		(const u8*)"\xb8\x00?\x8e\xc0\xbe", 6,
		'?', &foundpos);
	if(!ret) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	pos_of_data_ptr = foundpos+GRABBER_SEARCH1_START+6;
	de_dbg(c, "pos of data ptr: %"I64_FMT, pos_of_data_ptr);

	gctx->data_pos = de_getu16le(pos_of_data_ptr);
	gctx->data_pos -= 256;
	de_dbg(c, "data pos: %"I64_FMT, gctx->data_pos);

	if(gctx->gi.fmt_class<300) {
		pos_of_mode = gctx->data_pos - 7;
	}
	else {
		pos_of_mode = gctx->data_pos - 17;
	}

	gctx->screen_mode = de_getbyte(pos_of_mode);
	de_dbg(c, "mode: 0x%02x", (UI)gctx->screen_mode);
	if(gctx->screen_mode != 3) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	gctx->data_len = de_getu16le(pos_of_mode+2);
	de_dbg(c, "data len: %"I64_FMT, gctx->data_len);
	d->csctx.width_in_chars = 80;
done:
	de_free(c, mem);
}

static void de_run_grabber(deark *c, de_module_params *mparams)
{
	struct grabber_ctx *gctx = NULL;
	lctx *d = NULL;
	UI sig;

	gctx = de_malloc(c, sizeof(struct grabber_ctx));
	gctx->charctx = de_create_charctx(c, 0);
	d = de_malloc(c, sizeof(lctx));
	d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	sig = (UI)de_getu16le(0);
	if(sig==0x5a4d || sig==0x4d5a) {
		d->need_errmsg = 1;
		goto done;
	}

	grabber_id_com(c, (sig&0xff), &gctx->gi);
	if(!gctx->gi.is_grabber) {
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "format class: %u", gctx->gi.fmt_class);
	decode_grabber_com(c, d, gctx);
	if(d->errflag) goto done;

	d->csctx.height_in_chars = de_pad_to_n(gctx->data_len, d->csctx.width_in_chars*2) /
		(d->csctx.width_in_chars*2);
	de_dbg(c, "screen size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->csctx.width_in_chars,
		d->csctx.height_in_chars);
	if(gctx->data_pos+gctx->data_len > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	d->csctx.use_default_pal = 1;
	d->csctx.inf = c->infile;
	d->csctx.inf_pos = gctx->data_pos;
	d->csctx.inf_len = gctx->data_len;
	fmtutil_char_simple_run(c, &d->csctx, gctx->charctx);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Unsupported GRABBER format");
		}
		free_lctx(c, d);
	}
	if(gctx) {
		de_free_charctx(c, gctx->charctx);
	}
}

static int de_identify_grabber(deark *c)
{
	struct grabber_id_data gi;
	u8 b0;

	if(c->infile->len>65280) return 0;
	b0 = de_getbyte(0);
	if(b0!=0xe9 && b0!=0xfb) return 0;

	grabber_id_com(c, b0, &gi);
	if(gi.is_grabber) return 100;
	return 0;
}

void de_module_grabber(deark *c, struct deark_module_info *mi)
{
	mi->id = "grabber";
	mi->desc = "GRABBER";
	mi->run_fn = de_run_grabber;
	mi->identify_fn = de_identify_grabber;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
