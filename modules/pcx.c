// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PCX (PC Paintbrush) and related formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pcx);
DE_DECLARE_MODULE(de_module_mswordscr);
DE_DECLARE_MODULE(de_module_dcx);
DE_DECLARE_MODULE(de_module_pcx2com);
DE_DECLARE_MODULE(de_module_berts_bmg);

#define PCX_HDRSIZE 128

enum resmode_type {
	RESMODE_IGNORE = 0,
	RESMODE_AUTO,
	RESMODE_DPI,
	RESMODE_SCREENDIMENSIONS
};

typedef struct localctx_PCX {
	u8 version;
	u8 encoding;
	enum resmode_type resmode;
	i64 bits;
	i64 bits_per_pixel;
	i64 margin_L, margin_T, margin_R, margin_B;
	i64 hscreensize, vscreensize;
	i64 planes;
	i64 rowspan_raw;
	i64 rowspan;
	i64 ncolors;
	UI palette_info;
	u8 reserved1;
	i64 reported_width;
	i64 padded_width;
	i64 width_to_use;
	i64 height;
	u8 is_mswordscr;
	u8 is_pcxsfx;
	int has_vga_pal;
	int has_transparency;

	// Identifier of the palette to use, if there is no palette in the file
	int default_pal_num;
	int default_pal_set;

	dbuf *unc_pixels;
	de_finfo *fi;
	de_color pal[256];
} lctx;

static void simplify_dens(i64 *pxdens, i64 *pydens, i64 factor)
{
	while(*pxdens>factor && *pydens>factor &&
		(*pxdens%factor==0) && (*pydens%factor==0))
	{
		*pxdens /= factor;
		*pydens /= factor;
	}
}

static void set_density_from_screen_res(deark *c, lctx *d, i64 hres, i64 vres)
{
	i64 xdens, ydens;

	d->fi->density.code = DE_DENSITY_UNK_UNITS;
	xdens = hres*3; // Assume 4:3 screen
	ydens = vres*4;

	simplify_dens(&xdens, &ydens, 2);
	simplify_dens(&xdens, &ydens, 3);
	simplify_dens(&xdens, &ydens, 5);

	d->fi->density.xdens = (double)xdens;
	d->fi->density.ydens = (double)ydens;
}

// The resolution field is unreliable. It might contain:
// * Zeroes
// * The DPI
// * The pixel dimensions of the target screen mode
// * The dimensions of the image itself
// * A corrupted attempt at one of the above things (perhaps copied from an
//   older version of the image)
static void do_decode_resolution(deark *c, lctx *d, i64 hres, i64 vres)
{
	enum resmode_type resmode = d->resmode;

	if(hres==0 || vres==0) return;

	// TODO: Account for d->hscreensize, d->vscreensize.

	if(resmode==RESMODE_AUTO) {
		if((hres==320 && vres==200) ||
			(hres==640 && vres==480) ||
			(hres==640 && vres==350) ||
			(hres==640 && vres==200) ||
			(hres==800 && vres==600) ||
			(hres==1024 && vres==768))
		{
			if(d->reported_width<=hres && d->height<=hres) {
				// Looks like screen dimensions, and image fits on the screen
				resmode = RESMODE_SCREENDIMENSIONS;
			}
		}
		else if(hres==d->reported_width && vres==d->height) {
			;
		}
		else {
			if(hres==vres && hres>=50 && hres<=600) {
				resmode = RESMODE_DPI;
			}
		}
	}

	if(resmode==RESMODE_DPI) {
		d->fi->density.code = DE_DENSITY_DPI;
		d->fi->density.xdens = (double)hres;
		d->fi->density.ydens = (double)vres;
	}
	else if(resmode==RESMODE_SCREENDIMENSIONS) {
		set_density_from_screen_res(c, d, hres, vres);
	}
}

static int sane_screensize(i64 h, i64 v)
{
	if(h<320 || v<200) return 0;
	if(h>4096 || v>4096) return 0;
	if((h%8 != 0) || (v%2 != 0)) return 0;
	if(v*5 < h) return 0;
	if(h*3 < v) return 0;
	return 1;
}

static int do_read_header(deark *c, lctx *d)
{
	u8 initialbyte;
	int retval = 0;
	i64 hres, vres;
	i64 pos = 0;
	const char *imgtypename = "";

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	initialbyte = de_getbyte_p(&pos);
	d->version = de_getbyte_p(&pos);
	if(!d->is_mswordscr) {
		if(initialbyte==0xeb && d->version==0x0e) {
			d->is_pcxsfx = 1;
			d->version = 5;
		}
	}
	de_dbg(c, "format version: %u", (UI)d->version);

	if(d->is_mswordscr) {
		de_declare_fmt(c, "Word for DOS screen capture");
	}
	else if(d->is_pcxsfx) {
		de_declare_fmt(c, "VGAPaint 386 PCX-SFX");
	}
	else {
		de_declare_fmt(c, "PCX");
	}

	d->encoding = de_getbyte_p(&pos);
	de_dbg(c, "encoding: %u", (UI)d->encoding);

	d->bits = (i64)de_getbyte_p(&pos); // Bits per pixel per plane
	de_dbg(c, "bits: %d", (int)d->bits);
	if(d->bits<1) d->bits = 1;

	d->margin_L = de_getu16le_p(&pos);
	d->margin_T = de_getu16le_p(&pos);
	d->margin_R = de_getu16le_p(&pos);
	d->margin_B = de_getu16le_p(&pos);
	de_dbg(c, "margins: %d, %d, %d, %d", (int)d->margin_L, (int)d->margin_T,
		(int)d->margin_R, (int)d->margin_B);
	d->reported_width = d->margin_R - d->margin_L +1;
	d->height = d->margin_B - d->margin_T +1;
	de_dbg_dimensions(c, d->reported_width, d->height);

	hres = de_getu16le_p(&pos);
	vres = de_getu16le_p(&pos);
	de_dbg(c, "resolution: %d"DE_CHAR_TIMES"%d", (int)hres, (int)vres);

	// The palette (offset 16-63) will be read later.

	pos = 64;
	// For older versions of PCX, this field might be useful to help identify
	// the intended video mode. Documentation is lacking, though.
	d->reserved1 = de_getbyte_p(&pos);
	de_dbg(c, "vmode: 0x%02x", (UI)d->reserved1);

	d->planes = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)d->planes);
	d->rowspan_raw = de_getu16le_p(&pos);
	de_dbg(c, "bytes/plane/row: %d", (int)d->rowspan_raw);

	// TODO: Is this field (@68) 1 byte or 2?
	d->palette_info = (UI)de_getbyte_p(&pos);
	pos++;
	de_dbg(c, "palette info: %u", (UI)d->palette_info);

	if(d->version>=5) {
		d->hscreensize = de_getu16le_p(&pos);
		d->vscreensize = de_getu16le_p(&pos);
		if(!sane_screensize(d->hscreensize, d->vscreensize)) {
			d->hscreensize = 0;
			d->vscreensize = 0;
		}
	}
	if(d->hscreensize) {
		de_dbg(c, "screen size: %d" DE_CHAR_TIMES "%d", (int)d->hscreensize,
			(int)d->vscreensize);
	}

	//-----

	d->padded_width = (d->rowspan_raw*8) / d->bits;
	d->width_to_use = d->reported_width;
	if(c->padpix) {
		if(d->padded_width>d->reported_width) {
			d->width_to_use = d->padded_width;
		}
	}
	else {
		if(d->width_to_use<1 && d->padded_width>0) {
			de_warn(c, "Invalid width %"I64_FMT"; using %"I64_FMT" instead",
				d->width_to_use, d->padded_width);
			d->width_to_use = d->padded_width;
		}
	}

	if(!de_good_image_dimensions(c, d->width_to_use, d->height)) goto done;

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
	else if(d->planes==1 && d->bits==4) {
		imgtypename = "16-color nonplanar";
		d->ncolors = 16;
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

	do_decode_resolution(c, d, hres, vres);

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

	de_dbg(c, "VGA palette at %"I64_FMT, pos);
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

static const de_color ega16pal_1[16] = {
	0xff000000U,0xffbf0000U,0xff00bf00U,0xffbfbf00U,
	0xff0000bfU,0xffbf00bfU,0xff00bfbfU,0xffc0c0c0U,
	0xff808080U,0xffff0000U,0xff00ff00U,0xffffff00U,
	0xff0000ffU,0xffff00ffU,0xff00ffffU,0xffffffffU
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
			d->pal[k] = DE_MAKE_GRAY((UI)k);
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
		// Come up with a 16-color palette, if there is no palette in the file.
		// (8-color version-3 PCXs apparently use only the first 8 colors of the
		// palette.)

		if(!d->default_pal_set) {
			de_info(c, "Note: This paletted PCX file does not contain a palette. "
				"If it is not decoded correctly, try \"-opt pcx:pal=1\".");
		}
		de_dbg(c, "using a default EGA palette");
		if(d->default_pal_num==1) {
			// This is the "default EGA palette" used by several PCX viewers.
			// I don't know its origin.
			de_memcpy(d->pal, ega16pal_1, sizeof(ega16pal_1));
		}
		else {
			// This palette seems to be correct for at least some files.
			de_copy_std_palette(DE_PALID_WIN16, 2, 0, d->pal, 16, 0);
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
		UI bgcolor;
		UI fgpal;
		int pal_subid;

		de_warn(c, "4-color PCX images might not be supported correctly");

		p0 = de_getbyte(16);
		p3 = de_getbyte(19);
		bgcolor = p0>>4;
		fgpal = p3>>5;
		de_dbg(c, "using a CGA palette: palette #%d, bkgd color %d", (int)fgpal, (int)bgcolor);

		// Set first pal entry to background color
		d->pal[0] = de_get_std_palette_entry(DE_PALID_PC16, 0, (int)bgcolor);

		// TODO: These palettes are quite possibly incorrect. I can't find good
		// information about them.
		switch(fgpal) {
		case 1: case 3:
			pal_subid = 5; break; // C=0 P=? I=1
		case 4:
			pal_subid = 1; break; // C=1 P=0 I=0
		case 5:
			pal_subid = 4; break; // C=1 P=0 I=1
		case 6:
			pal_subid = 0; break; // C=1 P=1 I=0
		case 7:
			pal_subid = 3; break; // C=1 P=1 I=1
		default: // 0, 2
			pal_subid = 2; break; // C=0 P=? I=0
		}
		de_copy_std_palette(DE_PALID_CGA, pal_subid, 1, &d->pal[1], 3, 0);
		return;
	}

	if(d->ncolors>16 && d->ncolors<=256) {
		de_warn(c, "%u-color image format with 16-color palette", (UI)d->ncolors);
	}

	de_dbg(c, "using 16-color palette from header");

	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, 16, 16, 3, d->pal, 256, 0);
	de_dbg_indent(c, -1);
}

static int do_decompress(deark *c, lctx *d)
{
	i64 pos;
	//u8 b, b2;
	//i64 count;
	i64 expected_bytes;
	i64 endpos;
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	pos = PCX_HDRSIZE;
	de_dbg(c, "compressed bitmap at %"I64_FMT, pos);

	expected_bytes = d->rowspan * d->height;
	d->unc_pixels = dbuf_create_membuf(c, expected_bytes, 0);
	dbuf_enable_wbuffer(d->unc_pixels);

	endpos = c->infile->len;
	if(d->has_vga_pal) {
		// The last 769 bytes of this file are reserved for the palette.
		// Don't try to decode them as pixels.
		endpos -= 769;
	}

	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = endpos - pos;
	dcmpro.f = d->unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = expected_bytes;

	fmtutil_pcxrle_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}
	retval = 1;
	if(d->unc_pixels->len < expected_bytes) {
		de_warn(c, "Expected %"I64_FMT" bytes of image data, only found %"I64_FMT,
			expected_bytes, d->unc_pixels->len);
	}

done:
	return retval;
}

static void do_bitmap_1bpp(deark *c, lctx *d)
{
	// The paletted algorithm would work here (if we construct a palette),
	// but this special case is easy and efficient.
	de_convert_and_write_image_bilevel2(d->unc_pixels, 0,
		d->width_to_use, d->height, d->rowspan_raw, 0, d->fi, 0);
}

static void do_bitmap_paletted(deark *c, lctx *d)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, d->width_to_use, d->height, 3);

	// Impossible to get here unless one of the following conditions is true.
	if(d->planes==1) {
		de_convert_image_paletted(d->unc_pixels, 0, d->bits, d->rowspan,
			d->pal, img, 0);
	}
	else if(d->bits==1) {
		de_convert_image_paletted_planar(d->unc_pixels, 0, d->planes, d->rowspan,
			d->rowspan_raw, d->pal, img, 0x2);
	}

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void do_bitmap_24bpp(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 i, j;
	i64 plane;
	u8 s[4];

	de_memset(s, 0xff, sizeof(s));
	img = de_bitmap_create(c, d->width_to_use, d->height, d->has_transparency?4:3);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width_to_use; i++) {
			for(plane=0; plane<d->planes; plane++) {
				s[plane] = dbuf_getbyte(d->unc_pixels, j*d->rowspan + plane*d->rowspan_raw +i);
			}
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(s[0], s[1], s[2], s[3]));
		}
	}

	de_bitmap_write_to_file_finfoOLD(img, d->fi, 0);
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

	d->resmode = RESMODE_AUTO;
	s = de_get_ext_option(c, "pcx:resmode");
	if(s) {
		if(!de_strcmp(s, "auto")) {
			d->resmode = RESMODE_AUTO;
		}
		else if(!de_strcmp(s, "dpi")) {
			d->resmode = RESMODE_DPI;
		}
		else if(!de_strcmp(s, "screen")) {
			d->resmode = RESMODE_SCREENDIMENSIONS;
		}
	}

	d->fi = de_finfo_create(c);

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
		if(!do_decompress(c, d)) {
			goto done;
		}
	}
	dbuf_flush(d->unc_pixels);

	do_bitmap(c, d);

done:
	dbuf_close(d->unc_pixels);
	d->unc_pixels = NULL;
	de_finfo_destroy(c, d->fi);
	d->fi = NULL;
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

	// VGAPaint 386 PCX SFX
	if(buf[0]==0xeb && buf[1]==0x0e && buf[2]==1 && buf[3]==8 &&
		(de_getbyte(16)==0xe8))
	{
		if(de_input_file_has_ext(c, "pcx"))
			return 80;
		return 8;
	}

	return 0;
}

static void de_help_pcx(deark *c)
{
	de_msg(c, "-opt pcx:pal=<0|1> : Code for the predefined palette to use, "
		"if there is no palette in the file");
	de_msg(c, "-opt pcx:resmode=<ignore|dpi|screen|auto> : How to interpret the "
		"\"resolution\" field");
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
			// Last page. Assume it goes to the end of file.
			page_size = c->infile->len - page_offset[page];
		}
		else {
			page_size = page_offset[page+1] - page_offset[page];
		}
		if(page_size<0) page_size=0;
		de_dbg(c, "page %d at %u, size=%"I64_FMT, (int)page, (UI)page_offset[page],
			page_size);

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

// **************************************************************************
// PCX2COM
// DOS utility by "Dr.Destiny".
// graph/pcx2com.zip in the SAC archive.
// **************************************************************************

static void de_run_pcx2com(deark *c, de_module_params *mparams)
{
	i64 pos;
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "pcx", NULL, 0);

	// header
	dbuf_enable_wbuffer(outf);
	dbuf_write(outf, (const u8*)"\x0a\x05\x01\x08\x00\x00\x00\x00\x3f\x01\xc7", 11);
	dbuf_truncate(outf, 64);
	dbuf_write(outf, (const u8*)"\x00\x01\x40\x01\x01\x00\x40\x01\xc8", 9);
	dbuf_truncate(outf, 128);

	// image data, and 0x0c palette marker
	dbuf_copy(c->infile, 920, c->infile->len-920, outf);

	// VGA palette
	pos = 152;
	while(pos < 152+768) {
		u8 x;

		x = de_getbyte_p(&pos);
		dbuf_writebyte(outf, de_scale_63_to_255(x));
	}

	dbuf_close(outf);
}

static int de_identify_pcx2com(deark *c)
{
	if(c->infile->len<922 || c->infile->len>65280) return 0;

	if((UI)de_getu32be(0)!=0xb81300cdU) return 0;
	if(de_getbyte(c->infile->len-1) != 0x0c) return 0;

	// The is the substring "Self PCX", xor 0x80.
	if(dbuf_memcmp(c->infile, 104,
		(const u8*)"\xd3\xe5\xec\xe6\xa0\xd0\xc3\xd8", 8))
	{
		return 0;
	}

	return 100;
}

void de_module_pcx2com(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcx2com";
	mi->desc = "PCX2COM self-displaying image";
	mi->run_fn = de_run_pcx2com;
	mi->identify_fn = de_identify_pcx2com;
}

// **************************************************************************
// BMG - Bert's Coloring Programs:
// - Bert's African Animals
// - Bert's Christmas
// - Bert's Dinosaurs
// - Bert's Prehistoric Animals
// - Bert's Whales and Dolphins
// - Rachel's Fashion Dolls
// **************************************************************************

// This is an unorthodox Deark module: It recognizes specific known files,
// which is not ideal.

// The problem with these files is that they are valid PCX files, but they
// usually contain the wrong palette.

// There are three known "legit" palettes, and each program is hardcoded to use
// one of the three when it displays images.

// A BMG file contains one of three known possible palettes. Two of these
// palettes are among the "legit" possibilities, but it is not always the
// correct palette for that file.

// A few files do contain the correct palette, but we don't do anything special
// in such cases. It is never possible to be sure what the correct palette is,
// short of actually examining the image pixels.

#define BERTSPAL_UNK   0 // Must be 0
#define BERTSPAL_1     1 // [0]/[5] = gray/purple
#define BERTSPAL_2     2 // black/gray
#define BERTSPAL_3     3 // gray/green
#define BERTSPAL_GRAY  4
#define BERTSPAL_BLACK 5 // all black

struct berts_ctx {
	u32 pal_crc;
	u32 image_crc;
	u8 forced_pal;
	u8 default_pal;
	u8 auto_pal;
	u8 pal_to_use;
	struct de_crcobj *crco;
	de_color pal[16];
};

// Used with palettes found in files, and palettes that
// we may write.
static const char *bmg_pal_id_to_name(u8 x)
{
	const char *name = NULL;

	switch(x) {
	case BERTSPAL_BLACK: name = "none"; break;
	case BERTSPAL_1: name = "1"; break;
	case BERTSPAL_2: name = "2"; break;
	case BERTSPAL_3: name = "3"; break;
	case BERTSPAL_GRAY: name = "gray"; break;
	}
	return name?name:"unrecognized";
}

// If name is unrecognized, reports an error and returns _UNKNOWN.
static u8 bmg_name_to_pal_id(deark *c, const char *name)
{
	if(!de_strcmp(name, "1")) {
		return BERTSPAL_1;
	}
	if(!de_strcmp(name, "2")) {
		return BERTSPAL_2;
	}
	if(!de_strcmp(name, "3")) {
		return BERTSPAL_3;
	}
	if(!de_strcmp(name, "gray")) {
		return BERTSPAL_GRAY;
	}

	de_err(c, "Unknown palette \"%s\"", name);
	return BERTSPAL_UNK;
}

// Used with palettes found in files
static u8 bmg_pal_crc_to_pal_id(u32 v)
{
	u8 x = BERTSPAL_UNK;

	switch(v) {
	case 0xf288b395U: x = BERTSPAL_BLACK; break;  // all black
	case 0xc6599c5cU: x = BERTSPAL_1; break; // gray/purple
	case 0xbf0acb94U: x = BERTSPAL_2; break; // black/gray
	}
	return x;
}

static int is_crc_of_bmg_palette(u32 v)
{
	return (bmg_pal_crc_to_pal_id(v) != BERTSPAL_UNK);
}

static void write_palette_to_rgb24(de_color *pal, size_t ncolors, dbuf *outf)
{
	size_t k;

	for(k=0; k<ncolors; k++) {
		dbuf_writebyte(outf, DE_COLOR_R(pal[k]));
		dbuf_writebyte(outf, DE_COLOR_G(pal[k]));
		dbuf_writebyte(outf, DE_COLOR_B(pal[k]));
	}
}

static void berts_main(deark *c, struct berts_ctx *d)
{
	dbuf *outf = NULL;
	outf = dbuf_create_output_file(c, "pcx", NULL, 0);

	dbuf_enable_wbuffer(outf);

	// Initial 16-byte header:
	// [...
	dbuf_copy(c->infile, 0, 12, outf);
	// In BMG, the "resolution" fields are normally 640x480, which is wrong
	// -- the images target a screen with square pixels, and unknown density.
	// So we "correct" it to be 0x0. A density of 0x0 is common enough in PCX
	// files that it should not cause problems.
	dbuf_write_zeroes(outf, 4);
	// ...]

	// 48-byte palette:
	write_palette_to_rgb24(d->pal, 16, outf);

	// 64 bytes after the palette (first 10 are used, others are reserved):
	// [...
	dbuf_copy(c->infile, 64, 47, outf);

	// An arbitrary mark, to distinguish our repaired files from original BMG.
	// We don't really have to do this, because the palettes we write are
	// always a little different (in the low bits) from the ones found in
	// original BMG files. And we may change the DPI fields.
	// But this way is easy and robust.
	dbuf_writebyte(outf, 'P');

	dbuf_copy(c->infile, 112, 16, outf);
	// ...]

	// The image data:
	dbuf_copy(c->infile, 128, c->infile->len-128, outf);

	dbuf_close(outf);
}

static int is_usable_bmg_file(deark *c, struct berts_ctx *d)
{
	u8 b;
	UI bits, planes;

	b = de_getbyte(0);
	if(b!=0x0a) return 0;

	// Make sure image has 16 colors.
	bits = (UI)de_getbyte(3);
	planes = (UI)de_getbyte(65);
	if(bits*planes != 4) return 0;

	b = de_getbyte(111);
	if(b=='P') {
		de_dbg(c, "[file already processed]");
	}

	return 1;
}

// Uses d->image_crc.
// Returns palette BERTSPAL_1, _2, _3, or _UNK.
static u8 bmg_detect_pal_from_image_crc(struct berts_ctx *d)
{
	u8 x = BERTSPAL_UNK;

	// Note: Normally, the objects associated with CRCs like this will be
	// recorded in the "deark-extras" companion project. But I doubt I will
	// do that in this case, due to size and copyright considerations.
	// None of these source files is *too* difficult to find, I think.

	// Note: Rare (modified or corrupt) variants of some of these files
	// exist. I'm not planning to list them here, unless they've been widely
	// distributed.

	switch(d->image_crc) {
	case 0x3d3e4eb5U: // BD30 BD.IBG
	case 0xb1e9886aU: // BD30 DINO.BMG
	case 0x7120efdbU: // BAF30 BAF.IBG
	case 0x29177435U: // BAF30 AFRICA.BMG
	case 0x9bf4a2adU: // BPA30 BPA.IBG
	case 0xc85eda3fU: // BPA30 MAMMOTH.BMG
	case 0x3dbfb6ccU: // BCH32 BCH.IBG
	case 0xf7993b50U: // BCH32 BCH.BMG
		x = BERTSPAL_1;
		break;
	case 0xe91706d6U: // BWD30 BWD.IBG
	case 0xb9bc1f08U: // BWD30 HUMPBACK.BMG
	case 0x7183a578U: // BAF32 BAF.IBG
	case 0xd76f8557U: // BAF32 ZEBRA.BMG
		x = BERTSPAL_2;
		break;
	case 0xe5cc7840U: // DOLL10,26 DOLL.IBG
	case 0xf605e72eU: // DOLL10 RACHEL.BMG
	case 0x89f60611U: // DOLL26 RACHEL.BMG
	case 0x0b9eee2cU: // BD46 BD.IBG
	case 0xd273cc18U: // BD46 DINO.BMG
	case 0xa999e621U: // BWD46 BWD.IBG
	case 0x62021fa5U: // BWD46 BWD.BMG
	case 0xc018769dU: // BAF46 BAF.IBG
	case 0x3c5a5143U: // BAF46 BUFFALO.BMG
	case 0x07b4e115U: // BCH46 BCH.IBG
	case 0x49648857U: // BCH46 BCH.BMG
	case 0x3c28f954U: // BPA46 BPA.IBG
	case 0x332b2b9eU: // BPA46 BPA.BMG
		x = BERTSPAL_3;
		break;
	}

	return x;
}

static void bmg_acquire_palette(deark *c, struct berts_ctx *d)
{
	static const u8 bmg_palraw_1[48] = {
		0x82,0x82,0x82, 0x00,0x00,0x00, 0x00,0x00,0xff, 0x00,0x00,0xc3,
		0x00,0xa2,0xc3, 0xb2,0x00,0xcb, 0x00,0xc3,0x51, 0x00,0xa2,0x00,
		0x00,0x71,0x00, 0xc3,0x71,0x00, 0xa2,0x51,0x00, 0x82,0x00,0x00,
		0xff,0x00,0x00, 0xd3,0x00,0x00, 0xef,0xef,0x3c, 0xff,0xff,0xff
	};

	static const u8 bmg_palraw_3[48] = {
		0xaa,0xaa,0xaa,	0x00,0x00,0x00,	0x82,0x00,0x82,	0xff,0x00,0x00,
		0x41,0x82,0x82,	0x00,0xc3,0x00,	0x00,0x00,0xff,	0x55,0x55,0x55,
		0xff,0xc3,0xa2,	0xff,0xff,0x00,	0xff,0x00,0xff,	0xff,0x61,0x82,
		0x00,0xff,0xff,	0xa2,0x61,0x41,	0xa2,0xe3,0xff,	0xff,0xff,0xff
	};

	if(d->pal_to_use==BERTSPAL_1) {
		de_copy_palette_from_rgb24(bmg_palraw_1, d->pal, 16);
	}
	else if(d->pal_to_use==BERTSPAL_2) {
		de_copy_palette_from_rgb24(bmg_palraw_1, d->pal, 16);
		// pal[0] should be 0, but since pal[1] is also 0, in the interest
		// of not losing information, I don't want them to be the same.
		d->pal[0] = DE_MAKE_GRAY(0x01);
		d->pal[5] = DE_MAKE_GRAY(0x82);
	}
	else if(d->pal_to_use==BERTSPAL_3) {
		de_copy_palette_from_rgb24(bmg_palraw_3, d->pal, 16);
	}
	else { // grayscale
		size_t idx;
		u8 gv;

		// [1] is always black, used for the line drawing.
		// For the other colors, we'll use light grays.
		idx = 15;
		gv = 255;
		while(1) {
			if(idx==1) {
				d->pal[1] = DE_STOCKCOLOR_BLACK;
				idx = 0;
			}
			d->pal[idx] = DE_MAKE_GRAY(gv);
			if(idx==0) break;
			idx--;
			gv -= 8;
		}
	}
}

static void de_run_berts_bmg(deark *c, de_module_params *mparams)
{
	struct berts_ctx *d = NULL;
	u8 pal_id_in_file = BERTSPAL_UNK;
	u8 x;
	const char *s;

	d = de_malloc(c, sizeof(struct berts_ctx));

	s = de_get_ext_option(c, "berts_bmg:forcepal");
	if(s) {
		x = bmg_name_to_pal_id(c, s);
		if(x==BERTSPAL_UNK) {
			goto done;
		}
		d->forced_pal = x;
	}
	if(d->forced_pal==BERTSPAL_UNK) {
		s = de_get_ext_option(c, "berts_bmg:defpal");
		if(s) {
			if(!de_strcmp(s, "fail")) {
				;
			}
			else {
				x = bmg_name_to_pal_id(c, s);
				if(x==BERTSPAL_UNK) {
					goto done;
				}
				d->default_pal = x;
			}
		}
	}

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	de_crcobj_addslice(d->crco, c->infile, 16, 48);
	d->pal_crc = de_crcobj_getval(d->crco);
	pal_id_in_file = bmg_pal_crc_to_pal_id(d->pal_crc);
	de_dbg(c, "palette in file: %s", bmg_pal_id_to_name(pal_id_in_file));

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, 128, c->infile->len-128);
	d->image_crc = de_crcobj_getval(d->crco);

	d->auto_pal = bmg_detect_pal_from_image_crc(d);

	de_dbg(c, "img crc: 0x%08x (%sknown)", (UI)d->image_crc,
		(d->auto_pal?"":"un"));

	if(!is_usable_bmg_file(c, d)) {
		de_err(c, "Not a BMG-compatible file");
		goto done;
	}

	if(d->forced_pal!=BERTSPAL_UNK) {
		d->pal_to_use = d->forced_pal;
	}
	else if(d->auto_pal!=BERTSPAL_UNK) {
		d->pal_to_use = d->auto_pal;
	}
	else if(d->default_pal!=BERTSPAL_UNK) {
		d->pal_to_use = d->default_pal;
	}

	if(d->pal_to_use==BERTSPAL_UNK) {
		de_err(c, "Don't know what palette to use (try \"-opt berts_bmg:defpal=...\")");
		goto done;
	}

	de_dbg(c, "using palette: %s", bmg_pal_id_to_name(d->pal_to_use));
	bmg_acquire_palette(c, d);

	berts_main(c, d);

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int has_bmg_palette(deark *c)
{
	struct de_crcobj *crco;
	u32 v;

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(crco, c->infile, 16, 48);
	v = de_crcobj_getval(crco);
	de_crcobj_destroy(crco);
	return is_crc_of_bmg_palette(v);
}

static int de_identify_berts_bmg(deark *c)
{
	int has_ext;

	if(dbuf_memcmp(c->infile, 0,
		(const void*)"\x0a\x05\x01\x01\x50\x00\x00\x00\x7f\x02\xdf\x01\x80\x02\xe0\x01", 16))
	{
		return 0;
	}

	has_ext = de_input_file_has_ext(c, "bmg") || de_input_file_has_ext(c, "ibg");
	if(!has_ext) return 0;

	if(dbuf_memcmp(c->infile, 64,
		(const void*)"\x00\x04\x46\x00\x01\x00\x80\x02\xe0\x01", 10))
	{
		return 0;
	}

	// Test that the reserved bytes are all 0. This will screen out our
	// repaired files.
	if(!dbuf_is_all_zeroes(c->infile, 74, 54)) {
		return 0;
	}

	if(!has_bmg_palette(c)) return 0;

	return 100;
}

static void de_help_berts_bmg(deark *c)
{
	de_msg(c, "-opt berts_bmg:defpal=<name> : Default palette "
		"(options: 1, 2, 3, gray, fail)");
	de_msg(c, "-opt berts_bmg:forcepal=<name> : Use this palette "
		"unconditionally");
}

void de_module_berts_bmg(deark *c, struct deark_module_info *mi)
{
	mi->id = "berts_bmg";
	mi->desc = "Bert's Coloring Programs BMG";
	mi->run_fn = de_run_berts_bmg;
	mi->identify_fn = de_identify_berts_bmg;
	mi->help_fn = de_help_berts_bmg;
}
