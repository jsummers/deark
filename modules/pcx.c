// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PCX (PC Paintbrush) and DCX (multi-image PCX)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pcx);
DE_DECLARE_MODULE(de_module_mswordscr);
DE_DECLARE_MODULE(de_module_dcx);

#define PCX_HDRSIZE 128

typedef struct localctx_struct {
	u8 version;
	u8 encoding;
	i64 bits;
	i64 bits_per_pixel;
	i64 margin_L, margin_T, margin_R, margin_B;
	i64 planes;
	i64 rowspan_raw;
	i64 rowspan;
	i64 ncolors;
	u8 palette_info;
	u8 reserved1;
	i64 width, height;
	int is_mswordscr;
	int has_vga_pal;
	int has_transparency;

	// Identifier of the palette to use, if there is no palette in the file
	int default_pal_num;
	int default_pal_set;

	dbuf *unc_pixels;
	u32 pal[256];
} lctx;

static int do_read_header(deark *c, lctx *d)
{
	int retval = 0;
	i64 hres, vres;
	const char *imgtypename = "";

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	d->version = de_getbyte(1);
	d->encoding = de_getbyte(2);
	d->bits = (i64)de_getbyte(3); // Bits per pixel per plane
	d->margin_L = de_getu16le(4);
	d->margin_T = de_getu16le(6);
	d->margin_R = de_getu16le(8);
	d->margin_B = de_getu16le(10);

	hres = de_getu16le(12);
	vres = de_getu16le(14);

	// The palette (offset 16-63) will be read later.

	// For older versions of PCX, this field might be useful to help identify
	// the intended video mode. Documentation is lacking, though.
	d->reserved1 = de_getbyte(64);

	d->planes = (i64)de_getbyte(65);
	d->rowspan_raw = de_getu16le(66);
	d->palette_info = de_getbyte(68);

	de_dbg(c, "format version: %d, encoding: %d, planes: %d, bits: %d", (int)d->version,
		(int)d->encoding, (int)d->planes, (int)d->bits);
	de_dbg(c, "bytes/plane/row: %d, palette info: %d, vmode: 0x%02x", (int)d->rowspan_raw,
		(int)d->palette_info, (unsigned int)d->reserved1);
	de_dbg(c, "margins: %d, %d, %d, %d", (int)d->margin_L, (int)d->margin_T,
		(int)d->margin_R, (int)d->margin_B);

	// TODO: We could try to use the resolution field to set the pixel density,
	// but it's so unreliable that it may be best to ignore it. It might contain:
	// * The DPI
	// * The pixel dimensions of the target screen mode
	// * The dimensions of the image itself
	// * A corrupted attempt at one of the above things
	de_dbg(c, "\"resolution\": %d"DE_CHAR_TIMES"%d", (int)hres, (int)vres);

	d->width = d->margin_R - d->margin_L +1;
	d->height = d->margin_B - d->margin_T +1;
	de_dbg_dimensions(c, d->width, d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	d->rowspan = d->rowspan_raw * d->planes;
	de_dbg(c, "calculated bytes/row: %d", (int)d->rowspan);

	d->bits_per_pixel = d->bits * d->planes;

	if(d->encoding!=0 && d->encoding!=1) {
		de_err(c, "Unsupported compression type: %d", (int)d->encoding);
		goto done;
	}

	// Enumerate the known PCX image types.
	if(d->planes==1 && d->bits==1) {
		imgtypename = "2-color";
		d->ncolors = 2;
	}
	//else if(d->planes==2 && d->bits==1) {
	//	d->ncolors = 4;
	//}
	else if(d->planes==1 && d->bits==2) {
		imgtypename = "4-color";
		d->ncolors = 4;
	}
	else if(d->planes==3 && d->bits==1) {
		imgtypename = "8-color";
		d->ncolors = 8;
	}
	else if(d->planes==4 && d->bits==1) {
		imgtypename = "16-color";
		d->ncolors = 16;
	}
	//else if(d->planes==1 && d->bits==4) {
	//	d->ncolors = 16;
	//}
	//else if(d->planes==4 && d->bits==2) {
	//	d->ncolors = 16; (?)
	//}
	else if(d->planes==1 && d->bits==8) {
		imgtypename = "256-color";
		d->ncolors = 256;
	}
	//else if(d->planes==4 && d->bits==4) {
	//	d->ncolors = 4096;
	//}
	else if(d->planes==3 && d->bits==8) {
		imgtypename = "truecolor";
		d->ncolors = 16777216;
	}
	else if(d->planes==4 && d->bits==8) {
		// I can't find a PCX spec that mentions 32-bit RGBA images, but
		// ImageMagick and Wikipedia act like they're perfectly normal.
		imgtypename = "truecolor+alpha";
		d->ncolors = 16777216;
		d->has_transparency = 1;
	}
	else {
		de_err(c, "Unsupported image type (bits=%d, planes=%d)",
			(int)d->bits, (int)d->planes);
		goto done;
	}

	de_dbg(c, "image type: %s", imgtypename);

	// Sanity check
	if(d->rowspan > d->width * 4 + 100) {
		de_err(c, "Bad bytes/line (%d)", (int)d->rowspan_raw);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_read_vga_palette(deark *c, lctx *d)
{
	i64 pos;

	if(d->version<5) return 0;
	if(d->ncolors!=256) return 0;
	pos = c->infile->len - 769;
	if(pos<PCX_HDRSIZE) return 0;

	if(de_getbyte(pos) != 0x0c) {
		return 0;
	}

	de_dbg(c, "VGA palette at %d", (int)pos);
	d->has_vga_pal = 1;
	pos++;
	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, pos, 256, 3, d->pal, 256, 0);
	de_dbg_indent(c, -1);

	return 1;
}

// Maybe read the palette from a separate file.
// Returns 1 if the palette was read.
static int do_read_alt_palette_file(deark *c, lctx *d)
{
	const char *palfn;
	dbuf *palfile = NULL;
	int retval = 0;
	i64 k,z;
	u8 b1[3];
	u8 b2[3];
	int badflag = 0;
	char tmps[64];

	palfn = de_get_ext_option(c, "file2");
	if(!palfn) goto done;

	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) goto done;
	de_dbg(c, "using palette from separate file");

	if(palfile->len != d->ncolors*3) {
		badflag = 1;
	}

	de_dbg_indent(c, 1);
	for(k=0; k<d->ncolors && k*3<palfile->len; k++) {
		dbuf_read(palfile, b1, 3*k, 3);
		for(z=0; z<3; z++) {
			if(b1[z]>0x3f) badflag = 1;
			b2[z] = de_scale_63_to_255(b1[z]);
		}
		d->pal[k] = DE_MAKE_RGB(b2[0],b2[1],b2[2]);

		de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
			(int)b1[0], (int)b1[1], (int)b1[2]);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}
	de_dbg_indent(c, -1);

	if(badflag) {
		de_warn(c, "%s doesn't look like the right kind of palette file", palfn);
	}

	retval = 1;

done:
	dbuf_close(palfile);
	return retval;
}

// 16-color palettes to use, if there is no palette in the file.
// (8-color version-3 PCXs apparently use only the first 8 colors of the
// palette.)
static const u32 ega16pal[2][16] = {
	// This palette seems to be correct for at least some files.
	{0x000000,0x000080,0x008000,0x008080,0x800000,0x800080,0x808000,0x808080,
	 0xc0c0c0,0x0000ff,0x00ff00,0x00ffff,0xff0000,0xff00ff,0xffff00,0xffffff},

	// This is the "default EGA palette" used by several PCX viewers.
	// I don't know its origin.
	{0x000000,0xbf0000,0x00bf00,0xbfbf00,0x0000bf,0xbf00bf,0x00bfbf,0xc0c0c0,
	 0x808080,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xffffff}
};

static void do_palette_stuff(deark *c, lctx *d)
{
	i64 k;

	if(d->ncolors>256) {
		return;
	}

	if(d->ncolors==256) {
		// For 256-color images, start with a default grayscale palette.
		for(k=0; k<256; k++) {
			d->pal[k] = DE_MAKE_GRAY((unsigned int)k);
		}
	}

	if(do_read_alt_palette_file(c, d)) {
		return;
	}

	if(d->ncolors==2) {
		// TODO: Allegedly, some 2-color PCXs are not simply white-on-black,
		// and at least the foreground color can be something other than white.
		// The color information would be stored in the palette area, but
		// different files use different ways of conveying that information,
		// and it seems hopeless to reliably determine the correct format.
		return;
	}

	if(d->version==3 && d->ncolors>=8 && d->ncolors<=16) {
		if(!d->default_pal_set) {
			de_info(c, "Note: This paletted PCX file does not contain a palette. "
				"If it is not decoded correctly, try \"-opt pcx:pal=1\".");
		}
		de_dbg(c, "using a default EGA palette");
		for(k=0; k<16; k++) {
			d->pal[k] = ega16pal[d->default_pal_num][k];
		}
		return;
	}

	if(d->version>=5 && d->ncolors==256) {
		if(do_read_vga_palette(c, d)) {
			return;
		}
		de_warn(c, "Expected VGA palette was not found");
		// (Use the grayscale palette created earlier, as a last resort.)
		return;
	}

	if(d->ncolors==4) {
		u8 p0, p3;
		unsigned int bgcolor;
		unsigned int fgpal;

		de_warn(c, "4-color PCX images might not be supported correctly");

		p0 = de_getbyte(16);
		p3 = de_getbyte(19);
		bgcolor = p0>>4;
		fgpal = p3>>5;
		de_dbg(c, "using a CGA palette: palette #%d, bkgd color %d", (int)fgpal, (int)bgcolor);

		// Set first pal entry to background color
		d->pal[0] = de_palette_pc16(bgcolor);

		// TODO: These palettes are quite possibly incorrect. I can't find good
		// information about them.
		switch(fgpal) {
		case 0: case 2: // C=0 P=? I=0
			d->pal[1]=0x00aaaa; d->pal[2]=0xaa0000; d->pal[3]=0xaaaaaa; break;
		case 1: case 3: // C=0 P=? I=1
			d->pal[1]=0x55ffff; d->pal[2]=0xff5555; d->pal[3]=0xffffff; break;
		case 4: // C=1 P=0 I=0
			d->pal[1]=0x00aa00; d->pal[2]=0xaa0000; d->pal[3]=0xaa5500; break;
		case 5: // C=1 P=0 I=1
			d->pal[1]=0x55ff55; d->pal[2]=0xff5555; d->pal[3]=0xffff55; break;
		case 6: // C=1 P=1 I=0
			d->pal[1]=0x00aaaa; d->pal[2]=0xaa00aa; d->pal[3]=0xaaaaaa; break;
		case 7: // C=1 P=1 I=1
			d->pal[1]=0x55ffff; d->pal[2]=0xff55ff; d->pal[3]=0xffffff; break;
		}
		return;
	}

	if(d->ncolors>16 && d->ncolors<=256) {
		de_warn(c, "No suitable palette found");
	}

	de_dbg(c, "using 16-color palette from header");

	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, 16, 16, 3, d->pal, 256, 0);
	de_dbg_indent(c, -1);
}

static int do_uncompress(deark *c, lctx *d)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 expected_bytes;
	i64 endpos;

	pos = PCX_HDRSIZE;
	de_dbg(c, "compressed bitmap at %d", (int)pos);

	expected_bytes = d->rowspan * d->height;
	d->unc_pixels = dbuf_create_membuf(c, expected_bytes, 0);

	endpos = c->infile->len;
	if(d->has_vga_pal) {
		// The last 769 bytes of this file are reserved for the palette.
		// Don't try to decode them as pixels.
		endpos -= 769;
	}

	while(1) {
		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		if(d->unc_pixels->len >= expected_bytes) {
			break; // Reached the end of the image
		}
		b = de_getbyte(pos++);

		if(b>=0xc0) {
			count = (i64)(b&0x3f);
			b2 = de_getbyte(pos++);
			dbuf_write_run(d->unc_pixels, b2, count);
		}
		else {
			dbuf_writebyte(d->unc_pixels, b);
		}
	}

	if(d->unc_pixels->len < expected_bytes) {
		de_warn(c, "Expected %d bytes of image data, only found %d",
			(int)expected_bytes, (int)d->unc_pixels->len);
	}

	return 1;
}

static void do_bitmap_1bpp(deark *c, lctx *d)
{
	// The paletted algorithm would work here (if we construct a palette),
	// but this special case is easy and efficient.
	de_convert_and_write_image_bilevel(d->unc_pixels, 0,
		d->width, d->height, d->rowspan, 0, NULL, 0);
}

static void do_bitmap_paletted(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 i, j;
	i64 plane;
	u8 b;
	unsigned int palent;

	img = de_bitmap_create(c, d->width, d->height, 3);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			palent = 0;
			for(plane=0; plane<d->planes; plane++) {
				b = de_get_bits_symbol(d->unc_pixels, d->bits,
					j*d->rowspan + plane*d->rowspan_raw, i);
				palent |= b<<(plane*d->bits);
			}
			if(palent>255) palent=0; // Should be impossible.
			de_bitmap_setpixel_rgb(img, i, j, d->pal[palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_bitmap_24bpp(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 i, j;
	i64 plane;
	u8 s[4];

	de_memset(s, 0xff, sizeof(s));
	img = de_bitmap_create(c, d->width, d->height, d->has_transparency?4:3);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			for(plane=0; plane<d->planes; plane++) {
				s[plane] = dbuf_getbyte(d->unc_pixels, j*d->rowspan + plane*d->rowspan_raw +i);
			}
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(s[0], s[1], s[2], s[3]));
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_bitmap(deark *c, lctx *d)
{
	if(d->bits_per_pixel==1) {
		do_bitmap_1bpp(c, d);
	}
	else if(d->bits_per_pixel<=8) {
		do_bitmap_paletted(c, d);
	}
	else if(d->bits_per_pixel>=24) {
		do_bitmap_24bpp(c, d);
	}
	else {
		de_err(c, "Unsupported bits/pixel: %d", (int)d->bits_per_pixel);
	}
}

static void de_run_pcx_internal(deark *c, lctx *d, de_module_params *mparams)
{
	const char *s;

	s = de_get_ext_option(c, "pcx:pal");
	if(s) {
		d->default_pal_num = de_atoi(s);
		if(d->default_pal_num<0 || d->default_pal_num>1) {
			d->default_pal_num = 0;
		}
		d->default_pal_set = 1;
	}

	if(!do_read_header(c, d)) {
		goto done;
	}

	do_palette_stuff(c, d);

	if(d->encoding==0) {
		// Uncompressed PCXs are probably not standard, but support for them is not
		// uncommon. Imagemagick, for example, will create them if you ask it to.
		de_dbg(c, "uncompressed bitmap at %d", (int)PCX_HDRSIZE);
		d->unc_pixels = dbuf_open_input_subfile(c->infile,
			PCX_HDRSIZE, c->infile->len-PCX_HDRSIZE);
	}
	else {
		if(!do_uncompress(c, d)) {
			goto done;
		}
	}

	do_bitmap(c, d);

done:
	dbuf_close(d->unc_pixels);
}

static void de_run_pcx(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_run_pcx_internal(c, d, mparams);
	de_free(c, d);
}

static int de_identify_pcx(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, 8);
	if(buf[0]==0x0a && (buf[1]==0 || buf[1]==2 || buf[1]==3
		|| buf[1]==4 || buf[1]==5) &&
		(buf[2]==0 || buf[2]==1) )
	{
		if(de_input_file_has_ext(c, "pcx"))
			return 100;

		return 16;
	}
	return 0;
}

static void de_help_pcx(deark *c)
{
	de_msg(c, "-opt pcx:pal=<0|1> : Code for the predefined palette to use, "
		"if there is no palette in the file");
	de_msg(c, "-file2 <file.p13> : Read the palette from a separate file");
}

void de_module_pcx(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcx";
	mi->desc = "PCX image";
	mi->run_fn = de_run_pcx;
	mi->identify_fn = de_identify_pcx;
	mi->help_fn = de_help_pcx;
}

// **************************************************************************
// MS Word for DOS Screen Capture
// **************************************************************************

static void de_run_mswordscr(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->is_mswordscr = 1;
	de_run_pcx_internal(c, d, mparams);
	de_free(c, d);
}

static int de_identify_mswordscr(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, 8);
	if(buf[0]==0xcd && (buf[1]==0 || buf[1]==2 || buf[1]==3
		|| buf[1]==4 || buf[1]==5) &&
		buf[2]==1 )
	{
		if(de_input_file_has_ext(c, "scr") || de_input_file_has_ext(c, "mwg"))
			return 100;

		return 10;
	}
	return 0;
}

void de_module_mswordscr(deark *c, struct deark_module_info *mi)
{
	mi->id = "mswordscr";
	mi->desc = "MS Word for DOS Screen Capture";
	mi->run_fn = de_run_mswordscr;
	mi->identify_fn = de_identify_mswordscr;
}

// **************************************************************************
// DCX
// **************************************************************************

static void de_run_dcx(deark *c, de_module_params *mparams)
{
	u32 *page_offset;
	i64 num_pages;
	i64 page;
	i64 page_size;

	page_offset = de_mallocarray(c, 1023, sizeof(u32));
	num_pages = 0;
	while(num_pages < 1023) {
		page_offset[num_pages] = (u32)de_getu32le(4 + 4*num_pages);
		if(page_offset[num_pages]==0)
			break;
		num_pages++;
	}

	de_dbg(c, "number of pages: %d", (int)num_pages);

	for(page=0; page<num_pages; page++) {
		if(page == num_pages-1) {
			// Last page. Asssume it goes to the end of file.
			page_size = c->infile->len - page_offset[page];
		}
		else {
			page_size = page_offset[page+1] - page_offset[page];
		}
		if(page_size<0) page_size=0;
		de_dbg(c, "page %d at %d, size=%d", (int)page, (int)page_offset[page],
			(int)page_size);

		dbuf_create_file_from_slice(c->infile, page_offset[page], page_size, "pcx", NULL, 0);
	}
}

static int de_identify_dcx(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xb1\x68\xde\x3a", 4))
		return 100;
	return 0;
}

void de_module_dcx(deark *c, struct deark_module_info *mi)
{
	mi->id = "dcx";
	mi->desc = "DCX (multi-image PCX)";
	mi->run_fn = de_run_dcx;
	mi->identify_fn = de_identify_dcx;
}
