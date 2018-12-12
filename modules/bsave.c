// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// BSAVE image format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_bsave);

#define BSAVE_HDRSIZE 7

typedef struct localctx_struct {
	i64 base_addr, offset_from_base, data_size;

	int has_pcpaint_sig;
	u8 pcpaint_pal_num;
	u8 pcpaint_border_col;

	int interlaced;
	int has_dimension_fields;

	int pal_valid;
	u32 pal[256];
} lctx;

// Return a width that might be overridden by user request.
static i64 get_width(deark *c, lctx *d, i64 default_width)
{
	const char *s;
	s = de_get_ext_option(c, "bsave:width");
	if(s) return de_atoi64(s);
	return default_width;
}

static i64 get_height(deark *c, lctx *d, i64 default_height)
{
	const char *s;
	s = de_get_ext_option(c, "bsave:height");
	if(s) return de_atoi64(s);
	return default_height;
}

// 16-color 160x100 (maybe up to 160x102) mode.
// This is really a text mode, and can be processed by do_char() as well.
static int do_cga16(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 max_possible_height;
	i64 i, j;
	int retval = 0;
	u8 charcode, colorcode;
	i64 src_rowspan;
	u8 color0, color1;
	int charwarning = 0;

	de_declare_fmt(c, "BSAVE-PC 16-color CGA pseudo-graphics");

	img = de_bitmap_create_noinit(c);
	img->width = get_width(c, d, 160);
	img->height = get_height(c, d, 100);

	img->bytes_per_pixel = 3;

	// Every pair of bytes codes for two pixels; i.e. one byte per pixel.
	src_rowspan = img->width;
	max_possible_height = (d->data_size+src_rowspan-1)/src_rowspan;
	if(img->height > max_possible_height)
		img->height = max_possible_height;

	if(img->height < 1) {
		de_err(c, "Not enough data for this format");
		goto done;
	}

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i+=2) {
			charcode = de_getbyte(BSAVE_HDRSIZE + j*src_rowspan + i);
			colorcode = de_getbyte(BSAVE_HDRSIZE + j*src_rowspan + i+1);

			if(charwarning==0 && charcode!=0xdd && charcode!=0xde) {
				// TODO: We could also handle space characters and full-block characters,
				// at least. But maybe not worth the trouble.
				de_warn(c, "Unexpected code found (0x%02x). Format may not be correct.", (int)charcode);
				charwarning=1;
			}

			if(charcode==0xde) {
				color0 = colorcode>>4;
				color1 = colorcode&0x0f;
			}
			else {
				color1 = colorcode>>4;
				color0 = colorcode&0x0f;
			}

			de_bitmap_setpixel_rgb(img, i+0, j, de_palette_pc16(color0));
			de_bitmap_setpixel_rgb(img, i+1, j, de_palette_pc16(color1));
		}
	}

	retval = 1;

done:
	if(retval) {
		de_bitmap_write_to_file(img, NULL, 0);
	}
	de_bitmap_destroy(img);
	return retval;
}

// 4-color interlaced or non-interlaced
// "wh4": http://cd.textfiles.com/bthevhell/200/111/ - *.pic
static int do_4color(deark *c, lctx *d)
{
	// TODO: This may not be the right palette.
	static const u32 default_palette[4] = { 0x000000, 0x55ffff, 0xff55ff, 0xffffff };
	u32 palette[4];
	int palent;
	i64 i,j;
	i64 pos;
	i64 src_rowspan;
	de_bitmap *img = NULL;

	if(d->has_dimension_fields) {
		if(d->interlaced)
			de_declare_fmt(c, "BSAVE-PC 4-color, interlaced, 11-byte header");
		else
			de_declare_fmt(c, "BSAVE-PC 4-color, noninterlaced, 11-byte header");
	}
	else {
		if(d->interlaced)
			de_declare_fmt(c, "BSAVE-PC 4-color, interlaced");
		else
			de_declare_fmt(c, "BSAVE-PC 4-color, noninterlaced");
	}

	img = de_bitmap_create_noinit(c);
	img->bytes_per_pixel = 3;

	pos = BSAVE_HDRSIZE;

	if(d->has_dimension_fields) {
		// 11-byte header that includes width & height
		img->width = (de_getu16le(pos) + 1)/2; // width = number of bits??
		img->height = de_getu16le(pos+2);
		pos+=4;
	}
	else {
		img->width = get_width(c, d, 320);
		img->height = get_height(c, d, 200);	// TODO: Calculate this?
	}

	// Set the palette
	if(d->has_pcpaint_sig) {
		for(i=0; i<4; i++) {
			palette[i] = de_palette_pcpaint_cga4(d->pcpaint_pal_num, (int)i);
		}
		palette[0] = de_palette_pc16(d->pcpaint_border_col);
	}
	else {
		for(i=0; i<4; i++) {
			palette[i] = default_palette[i];
		}
	}

	src_rowspan = (img->width+3)/4;

	for(j=0;j<img->height;j++) {
		for(i=0;i<img->width;i++) {
			if(d->interlaced) {
				// Image is interlaced. Even-numbered scanlines are stored first.
				palent = (int)de_get_bits_symbol(c->infile, 2,
					pos + (j%2)*8192 + (j/2)*src_rowspan, i);
			}
			else {
				palent = (int)de_get_bits_symbol(c->infile, 2,
					pos + j*src_rowspan, i);
			}
			de_bitmap_setpixel_rgb(img, i, j, palette[palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
	return 1;
}

// 2-color interlaced or non-interlaced
// "cga2": http://cd.textfiles.com/bthevhell/100/21/
// "wh2": http://cd.textfiles.com/bthevhell/200/112/
static int do_2color(deark *c, lctx *d)
{
	i64 j;
	i64 src_rowspan;
	i64 pos;
	de_bitmap *img = NULL;

	img = de_bitmap_create_noinit(c);
	img->bytes_per_pixel = 1;
	pos = BSAVE_HDRSIZE;

	if(d->has_dimension_fields) {
		if(d->interlaced)
			de_declare_fmt(c, "BSAVE-PC 2-color, interlaced, 11-byte header");
		else
			de_declare_fmt(c, "BSAVE-PC 2-color, noninterlaced, 11-byte header");
	}
	else {
		if(d->interlaced)
			de_declare_fmt(c, "BSAVE-PC 2-color, interlaced");
		else
			de_declare_fmt(c, "BSAVE-PC 2-color, noninterlaced");
	}

	if(d->has_dimension_fields) {
		// 11-byte header that includes width & height
		img->width = de_getu16le(pos);
		img->height = de_getu16le(pos+2);
		pos+=4;
	}
	else {
		img->width = get_width(c, d, 640);
		img->height = get_height(c, d, 200); // TODO: calculate this?
	}

	de_dbg_dimensions(c, img->width, img->height);
	src_rowspan = (img->width+7)/8;

	for(j=0; j<img->height; j++) {
		if(d->interlaced) {
			de_convert_row_bilevel(c->infile, pos + (j%2)*8192 + (j/2)*src_rowspan,
				img, j, 0);
		}
		else {
			de_convert_row_bilevel(c->infile, pos + j*src_rowspan, img, j, 0);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
	return 1;
}

// 256-color
// http://cd.textfiles.com/advheaven2/PUZZLES/DRCODE12/
static int do_256color(deark *c, lctx *d)
{
	i64 i, j;
	u8 palent;
	u32 clr;
	de_bitmap *img = NULL;

	de_declare_fmt(c, "BSAVE-PC 256-color");

	img = de_bitmap_create_noinit(c);

	img->width = get_width(c, d, 320);
	img->height = get_height(c, d, 200);

	img->bytes_per_pixel = 3;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			palent = de_getbyte(BSAVE_HDRSIZE + j*img->width + i);
			if(d->pal_valid) {
				clr = d->pal[(int)palent];
			}
			else {
				clr = de_palette_vga256(palent);
			}
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
	return 1;
}

// 11-byte header that includes width & height, 16 color, inter-row interlaced
// http://cd.textfiles.com/advheaven2/SOLITAIR/SP107/
static int do_wh16(deark *c, lctx *d)
{
	i64 i, j;
	de_bitmap *img = NULL;
	i64 src_rowspan1;
	i64 src_rowspan;
	i64 pos;
	u8 palent;
	u8 b0, b1, b2, b3;

	de_declare_fmt(c, "BSAVE-PC 16-color, interlaced, 11-byte header");

	pos = BSAVE_HDRSIZE;
	img = de_bitmap_create_noinit(c);
	img->bytes_per_pixel = 3;

	img->width = de_getu16le(pos);
	img->height = de_getu16le(pos+2);
	pos+=4;

	de_dbg_dimensions(c, img->width, img->height);

	src_rowspan1 = (img->width+7)/8;
	src_rowspan = src_rowspan1*4;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			b0 = de_get_bits_symbol(c->infile, 1, pos + j*src_rowspan + src_rowspan1*0, i);
			b1 = de_get_bits_symbol(c->infile, 1, pos + j*src_rowspan + src_rowspan1*1, i);
			b2 = de_get_bits_symbol(c->infile, 1, pos + j*src_rowspan + src_rowspan1*2, i);
			b3 = de_get_bits_symbol(c->infile, 1, pos + j*src_rowspan + src_rowspan1*3, i);
			palent = b0 | (b1<<1) | (b2<<2) | (b3<<3);
			de_bitmap_setpixel_rgb(img, i, j, de_palette_pc16(palent));
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
	return 1;
}

// Used at http://cd.textfiles.com/bthevhell/300/265/
// A strange 2-bits/2-pixel color format.
static int do_b265(deark *c, lctx *d)
{
	static const u32 palette1[4] = { 0xffffff, 0x55ffff, 0x000000, 0xffffff };
	static const u32 palette2[4] = { 0xffffff, 0x000000, 0x000000, 0x000000 };
	int palent;
	i64 i,j;
	i64 bits_per_scanline;
	de_bitmap *img = NULL;
	i64 fakewidth;
	int retval = 0;

	de_declare_fmt(c, "BSAVE-PC special");

	img = de_bitmap_create_noinit(c);

	img->width = 320;
	fakewidth = img->width/2;
	img->height = d->data_size * 4 / fakewidth;
	img->bytes_per_pixel = 3;
	bits_per_scanline = img->width;

	for(j=0; j<img->height; j++) {
		for(i=0; i<fakewidth; i++) {
			palent = (int)de_get_bits_symbol(c->infile, 2,
				BSAVE_HDRSIZE + (j/8)*bits_per_scanline + (i/4)*8 + j%8, i%4);
			de_bitmap_setpixel_rgb(img, 2*i  , j, palette1[palent]);
			de_bitmap_setpixel_rgb(img, 2*i+1, j, palette2[palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

	retval = 1;

	de_bitmap_destroy(img);
	return retval;
}

static void do_char_1screen(deark *c, lctx *d, struct de_char_screen *screen, i64 pgnum,
	i64 pg_offset_in_data, i64 width, i64 height)
{
	i64 i, j;
	unsigned int ch;
	u8 fgcol, bgcol;
	i64 offset;
	u8 b0, b1;

	screen->width = width;
	screen->height = height;
	screen->cell_rows = de_mallocarray(c, height, sizeof(struct de_char_cell*));

	for(j=0; j<height; j++) {
		screen->cell_rows[j] = de_mallocarray(c, width, sizeof(struct de_char_cell));

		for(i=0; i<width; i++) {
			// 96 padding bytes per page?
			offset = BSAVE_HDRSIZE + pg_offset_in_data + j*(width*2) + i*2;

			b0 = de_getbyte(offset);
			b1 = de_getbyte(offset+1);

			ch = b0;
			//"The attribute byte stores the foreground color in the low nibble and the background color and blink attribute in the high nibble."
			//TODO: "blink" attribute?
			fgcol = (b1 & 0x0f);
			bgcol = (b1 & 0xf0) >> 4;

			screen->cell_rows[j][i].fgcol = (u32)fgcol;
			screen->cell_rows[j][i].bgcol = (u32)bgcol;
			screen->cell_rows[j][i].codepoint = (i32)ch;
			screen->cell_rows[j][i].codepoint_unicode = de_char_to_unicode(c, (i32)ch, DE_ENCODING_CP437_G);
		}
	}
}

static int do_char(deark *c, lctx *d)
{
	struct de_char_context *charctx = NULL;
	int retval = 0;
	i64 k;
	i64 numpages;
	i64 pgnum;
	i64 width, height;
	i64 height_for_this_page;
	i64 bytes_per_page;
	i64 bytes_for_this_page;
	i64 pg_offset_in_data;

	de_declare_fmt(c, "BSAVE-PC character graphics");

	width = get_width(c, d, 80);
	height = get_height(c, d, 25);

	// If there are multiple pages, the usually have some unused space between
	// them. Try to guess how much.

	if(width*height*2 <= 2048) {
		bytes_per_page = 2048; // E.g. 40x25(*2) = 2000
	}
	else if(width*height*2 <= 4096) {
		bytes_per_page = 4096; // E.g. 80x25(*2) = 4000
	}
	else if(width*height*2 <= 8192) {
		bytes_per_page = 8192; // Just guessing. Maybe 80x50.
	}
	else {
		bytes_per_page = 16384; // E.g. 80x100 (160x100) pseudo-graphics mode.
	}

	numpages = (d->data_size + (bytes_per_page-1))/bytes_per_page;
	if(numpages<1) {
		goto done;
	}
	de_dbg(c, "pages: %d", (int)numpages);

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->nscreens = numpages;
	charctx->screens = de_mallocarray(c, numpages, sizeof(struct de_char_screen*));

	for(k=0; k<16; k++) {
		charctx->pal[k] = de_palette_pc16((int)k);
	}

	for(pgnum=0; pgnum<numpages; pgnum++) {
		charctx->screens[pgnum] = de_malloc(c, sizeof(struct de_char_screen));

		pg_offset_in_data = bytes_per_page*pgnum;
		bytes_for_this_page = d->data_size - pg_offset_in_data;
		if(bytes_for_this_page<2) break;

		// Reduce the height if there's not enough data for it.
		height_for_this_page = (bytes_for_this_page+(width*2-1)) / (width*2);
		if(height_for_this_page>height) {
			height_for_this_page = height;
		}

		do_char_1screen(c, d, charctx->screens[pgnum], pgnum, pg_offset_in_data, width, height_for_this_page);
	}

	de_char_output_to_file(c, charctx);

	retval = 1;

done:
	de_free_charctx(c, charctx);
	return retval;
}

static int do_read_palette_file(deark *c, lctx *d, const char *palfn)
{
	dbuf *f = NULL;
	int retval = 0;
	i64 i;
	u8 buf[3];

	de_dbg(c, "reading palette file %s", palfn);

	f = dbuf_open_input_file(c, palfn);
	if(!f) {
		de_err(c, "Cannot read palette file %s", palfn);
		goto done;
	}

	for(i=0; i<256; i++) {
		dbuf_read(f, buf, BSAVE_HDRSIZE + 3*i, 3);
		d->pal[i] = DE_MAKE_RGB(de_scale_63_to_255(buf[0]),
			de_scale_63_to_255(buf[1]),
			de_scale_63_to_255(buf[2]));
	}
	d->pal_valid = 1;

	retval = 1;
done:
	dbuf_close(f);
	return retval;
}

typedef int (*decoder_fn_type)(deark *c, lctx *d);

static void de_run_bsave(deark *c, de_module_params *mparams)
{
	const char *bsavefmt;
	const char *s;
	lctx *d;
	u8 sig[14];
	decoder_fn_type decoder_fn = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->base_addr = de_getu16le(1);
	d->offset_from_base = de_getu16le(3);
	d->data_size = de_getu16le(5);

	de_dbg(c, "base_addr: 0x%04x", (int)d->base_addr);
	de_dbg(c, "offset_from_base: 0x%04x", (int)d->offset_from_base);
	de_dbg(c, "data_size: 0x%04x (%d)", (int)d->data_size, (int)d->data_size);

	bsavefmt = de_get_ext_option(c, "bsave:fmt");
	if(!bsavefmt) {
		bsavefmt="auto";
	}

	de_read(sig,8007,14);
	if(!de_memcmp(sig, "PCPaint V1.", 11)) {
		d->has_pcpaint_sig = 1;
		d->pcpaint_pal_num = sig[12];
		d->pcpaint_border_col = sig[13];
	}

	if(!de_strcmp(bsavefmt,"cga2")) {
		d->interlaced = 1;
		d->has_dimension_fields = 0;
		decoder_fn = do_2color;
	}
	else if(!de_strcmp(bsavefmt,"cga4")) {
		d->interlaced = 1;
		decoder_fn = do_4color;
	}
	else if(!de_strcmp(bsavefmt,"cga16")) {
		decoder_fn = do_cga16;
	}
	else if(!de_strcmp(bsavefmt,"mcga")) {
		decoder_fn = do_256color;
	}
	else if(!de_strcmp(bsavefmt,"char")) {
		decoder_fn = do_char;
	}
	else if(!de_strcmp(bsavefmt,"b265")) {
		decoder_fn = do_b265;
	}
	else if(!de_strcmp(bsavefmt,"wh2")) {
		d->has_dimension_fields = 1;
		decoder_fn = do_2color;
	}
	else if(!de_strcmp(bsavefmt,"wh4")) {
		d->has_dimension_fields = 1;
		decoder_fn = do_4color;
	}
	else if(!de_strcmp(bsavefmt,"wh16")) {
		decoder_fn = do_wh16;
	}
	else if(!de_strcmp(bsavefmt,"4col")) {
		decoder_fn = do_4color;
	}
	else if(!de_strcmp(bsavefmt,"2col")) {
		d->has_dimension_fields = 0;
		decoder_fn = do_2color;
	}
	else if(!de_strcmp(bsavefmt,"auto")) {
		// TODO: Better autodetection. This barely does anything.
		if(d->base_addr==0xb800 && (d->data_size==16384 || d->data_size==16383)) {
			d->interlaced = 1;
			decoder_fn = do_4color;
		}
		else if(d->base_addr==0xa000 && d->data_size==64000) {
			decoder_fn = do_256color;
		}
	}

	if(!decoder_fn) {
		de_err(c, "Unidentified BSAVE format, try \"-opt bsave:fmt=...\". "
			"Use \"-m bsave -h\" for a list.");
		goto done;
	}

	if(!de_strcmp(bsavefmt,"auto")) {
		de_warn(c, "BSAVE formats can't be reliably identified. You may need to "
			"use \"-opt bsave:fmt=...\". Use \"-m bsave -h\" for a list.");
	}

	s = de_get_ext_option(c, "palfile");
	if(!s) s = de_get_ext_option(c, "file2");
	if(s) {
		if(!do_read_palette_file(c, d, s)) goto done;
	}

	(void)decoder_fn(c, d);

done:
	de_free(c, d);
}

static int de_identify_bsave(deark *c)
{
	// Note - Make sure XZ has higher confidence.
	// Note - Make sure BLD has higher confidence.
	if(de_getbyte(0)==0xfd) return 10;
	return 0;
}

static void de_help_bsave(deark *c)
{
	de_msg(c, "-opt bsave:fmt=...");
	de_msg(c, " char  : Character graphics");
	de_msg(c, " cga2  : 2-color, 640x200");
	de_msg(c, " cga4  : 4-color, 320x200");
	de_msg(c, " cga16 : 16-color, 160x100 pseudographics");
	de_msg(c, " mcga  : 256-color, 320x200");
	de_msg(c, " wh2   : 2-color, 11-byte header");
	de_msg(c, " wh4   : 4-color, 11-byte header");
	de_msg(c, " wh16  : 16-color, 11-byte header, inter-row interlaced");
	de_msg(c, " b256  : Special");
	de_msg(c, " 2col  : 2-color noninterlaced");
	de_msg(c, " 4col  : 4-color noninterlaced");
}

void de_module_bsave(deark *c, struct deark_module_info *mi)
{
	mi->id = "bsave";
	mi->desc = "BSAVE/BLOAD image";
	mi->run_fn = de_run_bsave;
	mi->identify_fn = de_identify_bsave;
	mi->help_fn = de_help_bsave;
}
