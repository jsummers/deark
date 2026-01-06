// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PCPaint PIC and CLP format

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pcpaint);
DE_DECLARE_MODULE(de_module_bsave_cmpr);

struct pal_info {
	UI edesc;
	i64 esize;
	u8 *data;
};

struct localctx_pcpaint;
typedef struct localctx_pcpaint lctx;

enum screen_mode_type_enum {
	SCREENMODETYPE_UNKNOWN = 0,
	SCREENMODETYPE_BITMAP,
	SCREENMODETYPE_TEXT
};

typedef void (*decoder_fn_type)(deark *c, lctx *d);

struct localctx_pcpaint {
#define FMT_PIC 1
#define FMT_CLP 2
#define FMT_CMPR_BSAVE 3
	int file_fmt;
	int ver;
	de_encoding input_encoding;
	int opt_keep_invis_chars;
	de_finfo *fi;
	i64 header_size;
	i64 npwidth, height;
	i64 pdwidth;
	u8 plane_info;
	u8 palette_flag;
	u8 video_mode; // 0 = unknown
	const char *imgtype_name;
	struct pal_info pal_info_mainfile;
	struct pal_info pal_info_palfile;
	struct pal_info *pal_info_to_use; // Points to _mainfile or _palfile
	i64 num_rle_blocks;
	dbuf *unc_pixels;
	i64 dcmpr_nbytes_consumed;
	decoder_fn_type decoder_fn;
	enum screen_mode_type_enum screen_mode_type;
	de_color pal[256]; // Final palette to use
};

static void set_density(deark *c, lctx *d)
{
	if(!d->fi) return;
	if(d->ver<2) return;

	switch(d->video_mode) {
	case 'A': // 320x200
	case 'B':
	case 'I':
	case 'J':
	case 'L':
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		d->fi->density.xdens = 240.0;
		d->fi->density.ydens = 200.0;
		break;
	case 'H': // 720x348 (Hercules)
	case 'N':
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		// Various sources suggest aspect ratios of 1.46, 1.55, 1.59, ...
		d->fi->density.xdens = 155.0;
		d->fi->density.ydens = 100.0;
		break;
	case 'E': // 640x350
	case 'F':
	case 'G':
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		d->fi->density.xdens = 480.0;
		d->fi->density.ydens = 350.0;
		break;
	case 'K':
	case 'R':
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		d->fi->density.xdens = 480.0;
		d->fi->density.ydens = 400.0;
		break;
	case 'C':
	case 'D':
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		d->fi->density.xdens = 480.0;
		d->fi->density.ydens = 200.0;
		break;
	}
}

static void acquire_palette_ega64idx(deark *c, lctx *d, i64 num_entries)
{
	i64 k;
	char tmps[32];

	for(k=0; k<num_entries; k++) {
		if(k >= d->pal_info_to_use->esize) break;
		d->pal[k] = de_get_std_palette_entry(DE_PALID_EGA64, 0, (int)d->pal_info_to_use->data[k]);
		de_snprintf(tmps, sizeof(tmps), "%2d ", (int)d->pal_info_to_use->data[k]);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}
}

static void acquire_palette_cga4color(deark *c, lctx *d)
{
	u8 pal_subid = 0;
	u8 border_col = 0;

	// Image includes information about which CGA 4-color palette it uses.

	// This assumes PIC format. That should be the case, since edesc will
	// be zero for CLP format (unless we are reading the palette from a separate
	// PIC file).
	if(d->pal_info_to_use->esize >= 1)
		pal_subid = d->pal_info_to_use->data[0];
	if(d->pal_info_to_use->esize >= 2)
		border_col = d->pal_info_to_use->data[1];
	de_dbg(c, "pal id: 0x%02x", pal_subid);
	de_dbg(c, "border: 0x%02x", border_col);
	de_copy_std_palette(DE_PALID_CGA, pal_subid, 0, d->pal, 4, 0);

	// Replace the first palette color with the border/background color.
	d->pal[0] = de_get_std_palette_entry(DE_PALID_PC16, 0, (int)border_col);
}

// We always respect this palette type. PCPaint writes the palette, but doesn't
// always respect it when reading back the image.
static void acquire_palette_indirect16col(deark *c, lctx *d, i64 num_entries)
{
	i64 k;

	for(k=0; k<16; k++) {
		if(k >= d->pal_info_to_use->esize) break;
		d->pal[k] = de_get_std_palette_entry(DE_PALID_PC16, 0, (int)d->pal_info_to_use->data[k]);
		de_dbg2(c, "pal[%3d] = %u", (int)k, (UI)d->pal_info_to_use->data[k]);
	}
}

// Create a standard RGB palette from raw RGB palette data
static void acquire_palette_rgb(deark *c, lctx *d, i64 num_entries)
{
	i64 k;
	u8 cr1, cg1, cb1;
	u8 cr2, cg2, cb2;
	int has_8bit_samples = 0;
	char tmps[64];

	// Pre-scan
	for(k=0; k<num_entries; k++) {
		if(3*k+2 >= d->pal_info_to_use->esize) break;
		cr1 = d->pal_info_to_use->data[3*k+0];
		cg1 = d->pal_info_to_use->data[3*k+1];
		cb1 = d->pal_info_to_use->data[3*k+2];
		if(cr1>63 || cg1>63 || cb1>63) {
			de_dbg(c, "[detected 8-bit palette samples]");
			has_8bit_samples = 1;
			break;
		}
	}

	// For real
	for(k=0; k<num_entries; k++) {
		if(3*k+2 >= d->pal_info_to_use->esize) break;
		cr1 = d->pal_info_to_use->data[3*k+0];
		cg1 = d->pal_info_to_use->data[3*k+1];
		cb1 = d->pal_info_to_use->data[3*k+2];

		if(has_8bit_samples) {
			cr2 = (cr1<<2) | (cr1>>6);
			cg2 = (cg1<<2) | (cg1>>6);
			cb2 = (cb1<<2) | (cb1>>6);
			d->pal[k] = DE_MAKE_RGB(cr2, cg2, cb2);
			de_dbg_pal_entry(c, k, d->pal[k]);
		}
		else {
			cr2 = de_scale_63_to_255(cr1);
			cg2 = de_scale_63_to_255(cg1);
			cb2 = de_scale_63_to_255(cb1);
			d->pal[k] = DE_MAKE_RGB(cr2, cg2, cb2);
			de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
				(int)cr1, (int)cg1, (int)cb1);
			de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
		}
	}
}

static void acquire_palette(deark *c, lctx *d, i64 ncolors)
{
	// Start with a default palette
	switch(ncolors) {
	case 2:
		d->pal[0] = DE_STOCKCOLOR_BLACK;
		d->pal[1] = DE_STOCKCOLOR_WHITE;
		break;
	case 4:
		de_copy_std_palette(DE_PALID_CGA, 2, 0, d->pal, 4, 0);
		break;
	case 16:
		de_copy_std_palette(DE_PALID_PC16, 0, 0, d->pal, 16, 0);
		break;
	case 256:
		de_copy_std_palette(DE_PALID_VGA256, 0, 0, d->pal, 256, 0);
		break;
	default:
		goto done;
	}

	switch(d->pal_info_to_use->edesc) {
	case 0:
		de_dbg(c, "palette type: standard %d-color palette (no palette in file)", (int)ncolors);
		break;
	case 1:
		de_dbg(c, "palette type: CGA coded 4-color palette");
		de_dbg_indent(c, 1);
		acquire_palette_cga4color(c, d);
		de_dbg_indent(c, -1);
		break;
	case 2:
		de_dbg(c, "palette type: %d indices into standard 16-color palette", (int)ncolors);
		de_dbg_indent(c, 1);
		acquire_palette_indirect16col(c, d, ncolors);
		de_dbg_indent(c, -1);
		break;
	case 3:
		de_dbg(c, "palette type: %d indices into standard EGA 64-color palette", (int)ncolors);
		de_dbg_indent(c, 1);
		acquire_palette_ega64idx(c, d, ncolors);
		de_dbg_indent(c, -1);
		break;
	case 4:
	case 5:
		de_dbg(c, "palette type: %d-color RGB palette (in file)", (int)ncolors);
		de_dbg_indent(c, 1);
		acquire_palette_rgb(c, d, ncolors);
		de_dbg_indent(c, -1);
		break;
	default:
		de_warn(c, "Unknown palette type: %u", (UI)d->pal_info_to_use->edesc);
	}
done:
	;
}

static void decode_text(deark *c, lctx *d)
{
	i64 width_in_chars;
	struct de_char_context *charctx = NULL;
	struct de_char_screen *screen;
	i64 i, j;
	u8 ch, attr;
	struct de_encconv_state es;

	// TODO: This might not work for monochrome text mode (d->video_mode==0x32).

	width_in_chars = d->npwidth / 2;

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->screen_image_flag = 1;
	charctx->no_density = 1;
	charctx->nscreens = 1;
	charctx->screens = de_mallocarray(c, charctx->nscreens, sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];

	screen->width = width_in_chars;
	screen->height = d->height;

	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d characters", (int)screen->width, (int)screen->height);

	if(screen->height<1) goto done;

	screen->cell_rows = de_mallocarray(c, screen->height, sizeof(struct de_char_cell*));
	de_encconv_init(&es, d->input_encoding);

	for(j=0; j<screen->height; j++) {
		i64 j2;

		j2 = screen->height-1-j;
		screen->cell_rows[j2] = de_mallocarray(c, screen->width, sizeof(struct de_char_cell));

		for(i=0; i<screen->width; i++) {
			ch = dbuf_getbyte(d->unc_pixels, j*d->npwidth + i*2);
			attr = dbuf_getbyte(d->unc_pixels, j*d->npwidth + i*2 + 1);

			screen->cell_rows[j2][i].fgcol = (de_color)(attr & 0x0f);
			screen->cell_rows[j2][i].bgcol = (de_color)((attr & 0xf0) >> 4);

			// In "blank" regions, some files have nonsense characters, with the fg
			// and bg colors the same. We turn them into spaces, so that copy/paste
			// works right with our HTML output.
			if(ch==0 ||
				(screen->cell_rows[j2][i].fgcol==screen->cell_rows[j2][i].bgcol &&
					!d->opt_keep_invis_chars))
			{
				screen->cell_rows[j2][i].codepoint = 32;
				screen->cell_rows[j2][i].codepoint_unicode = 32;
			}
			else {
				screen->cell_rows[j2][i].codepoint = (i32)ch;
				screen->cell_rows[j2][i].codepoint_unicode = de_char_to_unicode_ex((i32)ch, &es);
			}
		}
	}

	// TODO: Is this always the right palette? Maybe we can't ignore ->edesc
	de_copy_std_palette(DE_PALID_PC16, 0, 0, charctx->pal, 16, 0);

	de_char_output_to_file(c, charctx);

done:
	de_free_charctx(c, charctx);
}

static void decode_egavga16(deark *c, lctx *d)
{
	i64 src_rowspan;
	de_bitmap *img = NULL;

	acquire_palette(c, d, 16);

	d->pdwidth = de_pad_to_2(d->npwidth);
	src_rowspan = d->pdwidth/2;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, 3);
	de_convert_image_paletted(d->unc_pixels, 0, 4, src_rowspan, d->pal, img, 0);
	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);
	de_bitmap_destroy(img);
}

static void decode_egavga16_planar(deark *c, lctx *d)
{
	i64 src_rowspan;
	i64 src_planespan;
	de_bitmap *img = NULL;

	acquire_palette(c, d, 16);

	d->pdwidth = de_pad_to_n(d->npwidth, 8);
	src_rowspan = d->pdwidth/8;
	src_planespan = src_rowspan*d->height;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, 3);
	de_convert_image_paletted_planar(d->unc_pixels, 0, 4, src_rowspan,
		src_planespan, d->pal, img, 0x2);
	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);
	de_bitmap_destroy(img);
}

static void decode_vga256(deark *c, lctx *d)
{
	de_bitmap *img = NULL;

	acquire_palette(c, d, 256);

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, 3);

	de_convert_image_paletted(d->unc_pixels, 0,
		8, img->width, d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);

	de_bitmap_destroy(img);
}

static void decode_bilevel(deark *c, lctx *d)
{
	i64 src_rowspan;
	int is_grayscale;
	UI edesc = d->pal_info_to_use->edesc;
	de_bitmap *img = NULL;

	if(!d->unc_pixels) goto done;

	acquire_palette(c, d, 2);

	// PCPaint's CGA and EGA 2-color modes used gray shade 170 instead of
	// white (255). Maybe they should be interpreted as white, but for
	// historical accuracy I'll go with gray170.
	if(edesc==0 && (d->video_mode==0x43 || d->video_mode==0x45)) {
		d->pal[1] = DE_MAKE_GRAY(170);
	}

	d->pdwidth = de_pad_to_n(d->npwidth, 8);
	src_rowspan = d->pdwidth/8;
	is_grayscale = de_is_grayscale_palette(d->pal, 2);
	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, is_grayscale?1:3);

	de_convert_image_paletted(d->unc_pixels, 0,
		1, src_rowspan, d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);

done:
	de_bitmap_destroy(img);
}

static void decode_cga4(deark *c, lctx *d)
{
	i64 src_rowspan;
	de_bitmap *img = NULL;

	if(!d->unc_pixels) goto done;

	acquire_palette(c, d, 4);

	d->pdwidth = de_pad_to_4(d->npwidth);
	src_rowspan = d->pdwidth/4;
	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, 3);

	de_convert_image_paletted(d->unc_pixels, 0,
		2, src_rowspan, d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);

done:
	de_bitmap_destroy(img);
}

static void decode_4color_planar(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 src_rowspan;
	i64 src_planespan;

	acquire_palette(c, d, 4);

	d->pdwidth = de_pad_to_n(d->npwidth, 8);
	src_rowspan = d->pdwidth/8;
	src_planespan = src_rowspan*d->height;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, 3);
	de_convert_image_paletted_planar(d->unc_pixels, 0, 2, src_rowspan, src_planespan,
		d->pal, img, 0x02);
	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_FLIP_IMAGE);
}

// decompress one block
// Writes decompressed bytes to d->unc_pixels.
// packed_data_size does not include header size.
// Returns 0 on error.

static int decompress_block(deark *c, lctx *d,
	i64 pos1, i64 packed_data_size, u8 run_marker)
{
	struct de_pcpaint_rle_params *pcpp = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int retval = 0;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = packed_data_size;
	dcmpro.f = d->unc_pixels;

	pcpp = de_malloc(c, sizeof(struct de_pcpaint_rle_params));
	pcpp->one_block_mode = 1;
	pcpp->obm_run_marker = run_marker;

	fmtutil_pcpaintrle_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)pcpp);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}
	else {
		d->dcmpr_nbytes_consumed = dres.bytes_consumed;
		retval = 1;
	}

	de_free(c, pcpp);
	return retval;
}

// Uses d->num_rle_blocks
static int decompress_blocks(deark *c, lctx *d, i64 pos1)
{
	struct de_pcpaint_rle_params *pcpp = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int retval = 0;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = c->infile->len - pos1;
	dcmpro.f = d->unc_pixels;

	pcpp = de_malloc(c, sizeof(struct de_pcpaint_rle_params));
	pcpp->num_blocks_known = 1;
	pcpp->num_blocks = d->num_rle_blocks;
	fmtutil_pcpaintrle_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)pcpp);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}
	else {
		d->dcmpr_nbytes_consumed = dres.bytes_consumed;
		retval = 1;
	}

	de_free(c, pcpp);
	return retval;
}

// Decompress multiple blocks of compressed pixels.
// This is for PIC format only.
static int decompress_pic_pixels(deark *c, lctx *d)
{
	i64 pos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->num_rle_blocks<1) {
		// Not compressed
		goto done;
	}

	d->unc_pixels = dbuf_create_membuf(c, 16384, 0);
	dbuf_set_length_limit(d->unc_pixels, (d->pdwidth+7) * d->height);
	dbuf_enable_wbuffer(d->unc_pixels);

	de_dbg(c, "decompressing image");
	de_dbg_indent(c, 1);
	pos = d->header_size;

	if(!decompress_blocks(c, d, pos)) goto done;

	de_dbg_indent(c, -1);
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
		d->dcmpr_nbytes_consumed, d->unc_pixels->len);
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_read_palette_data(deark *c, lctx *d, dbuf *f, struct pal_info *palinfo)
{
	palinfo->edesc = (UI)dbuf_getu16le(f, 13);
	palinfo->esize = dbuf_getu16le(f, 15);
	palinfo->data = de_malloc(c, palinfo->esize);
	dbuf_read(f, palinfo->data, 17, palinfo->esize);
	return 1;
}

// Figure out if we're supposed to read the palette from an alternate file.
// If so, open it and read a few fields from it. Modify settings so that
// we will read the palette from the alternate file.
// The palette file is assumed to be in PIC format.
static int do_read_alt_palette_file(deark *c, lctx *d)
{
	const char *palfn;
	dbuf *palfile = NULL;
	int retval = 0;
	i64 magic;

	palfn = de_get_ext_option(c, "palfile");
	if(!palfn) palfn = de_get_ext_option(c, "file2");
	if(!palfn) {
		retval = 1;
		goto done;
	}

	de_dbg(c, "[reading palette from alternate file]");

	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) {
		goto done;
	}

	magic = dbuf_getu16le(palfile, 0);
	if(magic!=0x1234) {
		de_err(c, "Palette file is not in PIC format.");
		goto done;
	}

	do_read_palette_data(c, d, palfile, &d->pal_info_palfile);

	if(d->pal_info_palfile.edesc==0) {
		de_warn(c, "Palette file does not contain palette information.");
		retval = 1;
		goto done;
	}

	d->pal_info_to_use = &d->pal_info_palfile;
	retval = 1;

done:
	dbuf_close(palfile);
	return retval;
}

// Determine if we can decode this type of image.
// Sets d->decoder_fn and d->screen_mode_type.
// If image can't be decoded, prints an error and returns 0.
static int do_set_up_decoder(deark *c, lctx *d)
{
	i64 edesc;

	d->imgtype_name = "?";
	edesc = d->pal_info_to_use->edesc; // For brevity

	if(d->video_mode>='0' && d->video_mode<='3') {
		d->screen_mode_type = SCREENMODETYPE_TEXT;
		d->decoder_fn = decode_text;
		d->imgtype_name = "character";
	}
	else if(d->plane_info==0x01) {
		// Expected video mode(s): 0x43, 0x45, 0x48, 0x4f, 0x50, 0x55
		// CGA or EGA or VGA or Hercules 2-color
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_bilevel;
		d->imgtype_name = "bilevel";
	}
	else if(d->plane_info==0x02) {
		// Expected video mode(s): 0x41
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_cga4;
		d->imgtype_name = "4-color CGA";
	}
	else if(d->plane_info==0x04) {
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_egavga16;
		d->imgtype_name = "16-color EGA/VGA";
	}
	else if(d->plane_info==0x08) {
		// Expected video mode(s): 0x4c
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_vga256;
		d->imgtype_name = "256-color";
	}
	else if(d->plane_info==0x11) { // e.g. vmode='F'
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_4color_planar;
		d->imgtype_name = "4-color planar";
	}
	else if(d->plane_info==0x31) {
		d->screen_mode_type = SCREENMODETYPE_BITMAP;
		d->decoder_fn = decode_egavga16_planar;
		d->imgtype_name = "16-color planar EGA/VGA";
	}

	de_dbg(c, "image type: %s", d->imgtype_name);

	if(d->decoder_fn) {
		de_dbg2(c, "image details: evideo=0x%02x, bitsinf=0x%02x, edesc=%u",
			d->video_mode, d->plane_info, (UI)edesc);
		return 1;
	}

	de_err(c, "This type of PCPaint %s is not supported (evideo=0x%02x, bitsinf=0x%02x, edesc=%u)",
		(d->file_fmt==FMT_CLP) ? "CLP" : "PIC",
		d->video_mode, d->plane_info, (UI)edesc);

	return 0;
}

static void de_run_pcpaint_pic(deark *c, lctx *d, de_module_params *mparams)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_declare_fmt(c, "PCPaint PIC");

	d->fi = de_finfo_create(c);

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	d->npwidth = de_getu16le(2);
	d->pdwidth = d->npwidth; // default
	d->height = de_getu16le(4);
	de_dbg_dimensions(c, d->npwidth, d->height);

	d->plane_info = de_getbyte(10);
	d->palette_flag = de_getbyte(11);

	de_dbg(c, "plane info: 0x%02x", (int)d->plane_info);
	de_dbg(c, "palette flag: 0x%02x", (int)d->palette_flag);

	if(d->palette_flag==0xff) {
		d->ver = 2;
	}
	else if(d->palette_flag==0 && d->plane_info==1) {
		d->ver = 1;
	}

	if(d->ver!=1 && d->ver!=2) {
		de_err(c, "This version of PCPaint PIC is not supported");
		goto done;
	}
	if(d->ver!=2) {
		de_warn(c, "This version of PCPaint PIC might not be supported correctly");
	}

	if(d->ver==1) {
		// V1 support is based on the behavior of Iconvert (Infinity Engineering Services)
		d->video_mode = 0;
		d->pal_info_mainfile.edesc = 0;
		d->pal_info_mainfile.esize = 10;
	}
	else {
		d->video_mode = de_getbyte(12);
		de_dbg(c, "video mode: 0x%02x", (int)d->video_mode);

		do_read_palette_data(c, d, c->infile, &d->pal_info_mainfile);
		de_dbg(c, "edesc: %u", (UI)d->pal_info_mainfile.edesc);
		de_dbg(c, "esize: %d", (int)d->pal_info_mainfile.esize);
	}

	if(d->pal_info_mainfile.esize>0) {
		de_dbg(c, "palette or other info at %d", 17);
	}

	set_density(c, d);

	d->pal_info_to_use = &d->pal_info_mainfile; // tentative
	if(!do_read_alt_palette_file(c, d)) goto done;

	d->num_rle_blocks = de_getu16le(17+d->pal_info_mainfile.esize);

	d->header_size = 17 + d->pal_info_mainfile.esize + 2;

	de_dbg(c, "num rle blocks: %d", (int)d->num_rle_blocks);
	de_dbg_indent(c, -1);

	de_dbg(c, "image data at %d", (int)d->header_size);
	de_dbg_indent(c, 1);
	if(!do_set_up_decoder(c, d)) goto done;
	if(d->screen_mode_type==SCREENMODETYPE_BITMAP) {
		if(!de_good_image_dimensions(c, d->npwidth, d->height)) goto done;
	}

	if(d->num_rle_blocks>0) {
		// Image is compressed.
		if(!decompress_pic_pixels(c, d)) goto done;
	}
	else {
		// Image is not compressed.
		d->unc_pixels = dbuf_open_input_subfile(c->infile, d->header_size,
			c->infile->len-d->header_size);
	}

	d->decoder_fn(c, d);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_pcpaint_clp(deark *c, lctx *d, de_module_params *mparams)
{
	i64 file_size;
	u8 run_marker;
	int is_compressed;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_declare_fmt(c, "PCPaint CLP");

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	file_size = de_getu16le(0);
	de_dbg(c, "reported file size: %"I64_FMT, file_size);
	if(file_size != c->infile->len) {
		if(file_size==0x1234) {
			de_warn(c, "This is probably a .PIC file, not a CLIP file.");
		}
		else {
			de_warn(c, "Reported file size (%"I64_FMT") does not equal actual file size (%"I64_FMT"). "
				"Format may not be correct.", file_size, c->infile->len);
		}
	}

	d->npwidth = de_getu16le(2);
	d->pdwidth = d->npwidth; // default
	d->height = de_getu16le(4);
	de_dbg_dimensions(c, d->npwidth, d->height);

	d->plane_info = de_getbyte(10);

	is_compressed = (d->plane_info==0xff);

	if(is_compressed) {
		d->header_size = 13;
		d->plane_info = de_getbyte(11);
	}
	else {
		d->header_size = 11;
	}
	de_dbg(c, "compressed: %d", (int)is_compressed);
	de_dbg(c, "plane info: 0x%02x", (int)d->plane_info);

	de_dbg_indent(c, -1);

	// The colors probably won't be right, but we have no way to tell what palette
	// is used by a CLP image.
	d->video_mode = 0;
	d->pal_info_mainfile.edesc = 0;
	d->pal_info_mainfile.esize = 0;

	d->pal_info_to_use = &d->pal_info_mainfile; // tentative
	if(!do_read_alt_palette_file(c, d)) goto done;

	de_dbg(c, "image data at %"I64_FMT, d->header_size);
	de_dbg_indent(c, 1);
	if(!do_set_up_decoder(c, d)) goto done;

	if(is_compressed) {
		run_marker = de_getbyte(12);
		de_dbg3(c, "run marker: 0x%02x", (UI)run_marker);

		de_dbg(c, "decompressing image");
		de_dbg_indent(c, 1);
		d->unc_pixels = dbuf_create_membuf(c, 16384, 0);
		dbuf_set_length_limit(d->unc_pixels, (d->pdwidth+7) * d->height);
		dbuf_enable_wbuffer(d->unc_pixels);

		if(!decompress_block(c, d, d->header_size,
			file_size - d->header_size, run_marker))
		{
			goto done;
		}
		de_dbg_indent(c, -1);
		de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
			d->dcmpr_nbytes_consumed, d->unc_pixels->len);
	}
	else {
		d->unc_pixels = dbuf_open_input_subfile(c->infile,
			d->header_size, file_size-d->header_size);
	}

	d->decoder_fn(c, d);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	if(d->unc_pixels) dbuf_close(d->unc_pixels);
	de_finfo_destroy(c, d->fi);
	de_free(c, d->pal_info_mainfile.data);
	de_free(c, d->pal_info_palfile.data);
	de_free(c, d);
}

// Dispatch to either pcpaint_pic or pcpaint_clp.
static void de_run_pcpaint(deark *c, de_module_params *mparams)
{
	// 0=unknown, 1=pic, 2=clp
	const char *pcpaintfmt;
	u8 buf[16];
	lctx *d;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437_G);

	pcpaintfmt = de_get_ext_option(c, "pcpaint:fmt");
	if(pcpaintfmt) {
		if(!de_strcmp(pcpaintfmt, "pic")) {
			d->file_fmt = FMT_PIC;
		}
		else if(!de_strcmp(pcpaintfmt, "clp")) {
			d->file_fmt = FMT_CLP;
		}
		else if(!de_strcmp(pcpaintfmt, "clip")) {
			d->file_fmt = FMT_CLP;
		}
	}

	if(!d->file_fmt) {
		// File subtype not given by user. Try to detect it.
		de_read(buf, 0, 16);
		if(buf[0]==0x34 && buf[1]==0x12) {
			if(c->infile->len==0x1234) {
				// Pathological case where both formats could start with 0x1234.
				if(buf[10]==0xff) { // definitely a compressed CLP
					d->file_fmt = FMT_CLP;
				}
				else {
					de_warn(c, "Format can't be reliably identified. Try \"-opt pcpaint:fmt=clp\" if necessary.");
					d->file_fmt = FMT_PIC;
				}
			}
			else {
				d->file_fmt = FMT_PIC;
			}
		}
		else {
			d->file_fmt = FMT_CLP;
		}
	}

	d->opt_keep_invis_chars = de_get_ext_option_bool(c, "pcpaint:invistext", 0);

	if(d->file_fmt==FMT_CLP) {
		de_run_pcpaint_clp(c, d, mparams);
	}
	else {
		de_run_pcpaint_pic(c, d, mparams);
	}

	destroy_lctx(c, d);
}

static int de_identify_pcpaint(deark *c)
{
	u8 buf[12];
	int pic_ext, clp_ext;
	i64 x;

	pic_ext = de_input_file_has_ext(c, "pic");

	de_read(buf, 0, 12);
	if(buf[0]==0x34 && buf[1]==0x12) {
		if(buf[11]==0xff) {
			return pic_ext ? 100 : 50;
		}
		if(buf[11]==0x00 && buf[10]==0x01) {
			return pic_ext ? 60 : 10;
		}
	}

	clp_ext = de_input_file_has_ext(c, "clp");
	if(clp_ext) {
		x = de_getu16le_direct(&buf[0]);
		if(x==c->infile->len) {
			return 50;
		}
	}

	return 0;
}

static void de_help_pcpaint(deark *c)
{
	de_msg(c, "-file2 <file.pic> : PIC file to read the palette from");
	de_msg(c, "-opt pcpaint:fmt=pic : Assume PIC format");
	de_msg(c, "-opt pcpaint:fmt=clp : Assume CLP format");
}

void de_module_pcpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcpaint";
	mi->desc = "PCPaint PIC or CLP image";
	mi->run_fn = de_run_pcpaint;
	mi->identify_fn = de_identify_pcpaint;
	mi->help_fn = de_help_pcpaint;
}

// **************************************************************************
// PCPaint compressed BSAVE
//
// Used by PCPaint v1.5. We convert it to uncompressed BSAVE.
// **************************************************************************

#define BSAVE_HDRSIZE 7

static void de_run_bsave_cmpr(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int ret;
	i64 pos;
	i64 udata_size;
	dbuf *outf = NULL;

	de_declare_fmt(c, "PCPaint compressed BSAVE");
	d = de_malloc(c, sizeof(lctx));
	d->file_fmt = FMT_CMPR_BSAVE;

	udata_size = de_getu16le(7);
	d->unc_pixels = dbuf_create_membuf(c, BSAVE_HDRSIZE+udata_size, 0x1);
	dbuf_enable_wbuffer(d->unc_pixels);

	// Construct the 7-byte BSAVE header
	dbuf_copy(c->infile, 0, 5, d->unc_pixels);
	dbuf_copy(c->infile, 7, 2, d->unc_pixels);

	pos = 9;
	d->num_rle_blocks = de_getu16le_p(&pos);
	de_dbg(c, "num rle blocks: %d", (int)d->num_rle_blocks);

	de_dbg(c, "decompressing");
	de_dbg_indent(c, 1);
	ret = decompress_blocks(c, d, 11);
	de_dbg_indent(c, -1);
	if(!ret) goto done;

	outf = dbuf_create_output_file(c, "unc.pic", NULL, 0);
	dbuf_copy(d->unc_pixels, 0, d->unc_pixels->len, outf);

done:
	dbuf_close(outf);
	destroy_lctx(c, d);
}

static int de_identify_bsave_cmpr(deark *c)
{
	// This probably doesn't detect images that aren't 320x200, if such things exist.
	if(dbuf_memcmp(c->infile, 0, (const u8*)"\xfd\0\xb8\0\0\0\0\0\x40\x02\0", 11)) {
		return 0;
	}
	return 100;
}

void de_module_bsave_cmpr(deark *c, struct deark_module_info *mi)
{
	mi->id = "bsave_cmpr";
	mi->desc = "PCPaint compressed BSAVE";
	mi->run_fn = de_run_bsave_cmpr;
	mi->identify_fn = de_identify_bsave_cmpr;
}
