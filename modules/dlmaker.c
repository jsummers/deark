// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// DL animation format, used by DL MAKER / DL VIEWER
//   by Davide Tome' & Luca De Gregorio

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_dlmaker);

#define DL_SCREEN_WIDTH 320
#define DL_SCREEN_HEIGHT 200
#define DL_SCREEN_SIZE_IN_BYTES 64000

typedef struct localctx_struct {
	de_ext_encoding input_encoding;
	int opt_montage;
	u8 ver;
	u8 screen_format;
	i64 hdr_size;
	i64 img_xsize, img_ysize;
	i64 num_frames;
	// A "screen" is a 320x200 aggregate image containing 1 or more real images.
	i64 imgs_per_screen;
	i64 num_screens;
	i64 num_images;
	de_finfo *fi;
	de_bitmap *screen_img;
	de_bitmap *img;
	u32 pal[256];
} lctx;

static void read_name20(deark *c, lctx *d, i64 pos, de_ucstring *s)
{
	size_t i;
	u8 buf[20];

	de_read(buf, pos, 20);
	for(i=0; i<20; i++) {
		if(buf[i]) buf[i] ^= 0xff;
	}
	ucstring_append_bytes(s, buf, 20, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
}

static void do_screen(deark *c, lctx *d, i64 pos)
{
	if(!d->screen_img) {
		d->screen_img = de_bitmap_create(c, DL_SCREEN_WIDTH, DL_SCREEN_HEIGHT, 3);
	}
	de_convert_image_paletted(c->infile, pos, 8, DL_SCREEN_WIDTH, d->pal, d->screen_img, 0);
	if(d->imgs_per_screen<=1 || d->opt_montage) {
		de_bitmap_write_to_file_finfo(d->screen_img, d->fi, 0);
	}
	else {
		i64 i;
		i64 xpos = 0;
		i64 ypos = 0;

		if(!d->img) {
			d->img = de_bitmap_create(c, d->img_xsize, d->img_ysize, 3);
		}

		for(i=0; i<d->imgs_per_screen; i++) {
			de_bitmap_copy_rect(d->screen_img, d->img, xpos, ypos, d->img_xsize, d->img_ysize,
				0, 0, 0);
			de_bitmap_write_to_file_finfo(d->img, d->fi, 0);

			xpos += d->img_xsize;
			if(xpos >= DL_SCREEN_WIDTH) {
				xpos = 0;
				ypos += d->img_ysize;
			}
		}
	}
}

static void read_palette(deark *c, lctx *d, i64 pos1)
{
	i64 k;
	i64 pos = pos1;

	de_dbg(c, "palette at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	for(k=0; k<256; k++) {
		u8 cr1, cg1, cb1;
		u8 cr2, cg2, cb2;
		char tmps[64];

		cr1 = de_getbyte_p(&pos);
		cg1 = de_getbyte_p(&pos);
		cb1 = de_getbyte_p(&pos);
		cr2 = de_scale_63_to_255(cr1 & 0x3f);
		cg2 = de_scale_63_to_255(cg1 & 0x3f);
		cb2 = de_scale_63_to_255(cb1 & 0x3f);
		d->pal[k] = DE_MAKE_RGB(cr2, cg2, cb2);
		de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
			(int)cr1, (int)cg1, (int)cb1);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}
	de_dbg_indent(c, -1);
}

static int read_header(deark *c, lctx *d)
{
	int retval = 0;
	i64 pos = 0;
	de_ucstring *s = NULL;

	d->ver = de_getbyte_p(&pos);
	de_dbg(c, "version: %u", (UI)d->ver);
	if(d->ver<1 || d->ver>3) {
		de_err(c, "Not a DL file");
		goto done;
	}
	if(d->ver!=1 && d->ver!=2) {
		de_err(c, "This version of DL (%u) is not supported", (UI)d->ver);
		goto done;
	}

	if(d->ver==1) {
		d->screen_format = 1;
	}
	else {
		d->screen_format = de_getbyte_p(&pos);
		de_dbg(c, "screen format: %u", (UI)d->screen_format);
	}

	switch(d->screen_format) {
	case 0:
		d->img_xsize = 320;
		d->img_ysize = 200;
		break;
	case 1:
		d->img_xsize = 160;
		d->img_ysize = 100;
		break;
	case 2:
		d->img_xsize = 80;
		d->img_ysize = 50;
		break;
	default:
		de_err(c, "Invalid/unsupported DL format");
		goto done;
	}
	d->imgs_per_screen = (DL_SCREEN_WIDTH/d->img_xsize) * (DL_SCREEN_HEIGHT/d->img_ysize);
	de_dbg_dimensions(c, d->img_xsize, d->img_ysize);
	de_dbg(c, "images/screen: %u", (UI)d->imgs_per_screen);

	s = ucstring_create(c);
	read_name20(c, d, pos, s);
	de_dbg(c, "title: \"%s\"", ucstring_getpsz_d(s));
	pos += 20;

	if(d->ver!=1) {
		ucstring_empty(s);
		read_name20(c, d, pos, s);
		de_dbg(c, "author: \"%s\"", ucstring_getpsz_d(s));
		pos += 20;
	}

	d->num_screens = (i64)de_getbyte_p(&pos);
	de_dbg(c, "num screens: %u", (UI)d->num_screens);

	if(d->ver==1) {
		d->num_frames = de_getu16le_p(&pos);
	}
	else {
		d->num_frames = de_getu32le_p(&pos);
	}
	de_dbg(c, "num frames: %"I64_FMT, d->num_frames);

	d->num_images = d->num_screens * d->imgs_per_screen;
	de_dbg(c, "num images (calculated): %"I64_FMT, d->num_images);

	read_palette(c, d, pos);
	pos += 256*3;
	d->hdr_size = pos;
	retval = 1;

done:
	ucstring_destroy(s);
	return retval;
}

static void de_run_dlmaker(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;
	i64 k;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->input_encoding = DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID);
	d->opt_montage = de_get_ext_option_bool(c, "dlmaker:montage", 0);

	d->fi = de_finfo_create(c);
	d->fi->density.code = DE_DENSITY_UNK_UNITS;
	d->fi->density.xdens = 6.0;
	d->fi->density.ydens = 5.0;

	if(!read_header(c, d)) goto done;
	pos = d->hdr_size;

	for(k=0; k<d->num_screens; k++) {
		if(pos+DL_SCREEN_SIZE_IN_BYTES > c->infile->len) goto done;
		de_dbg(c, "screen #%u at %"I64_FMT, (UI)k, pos);
		do_screen(c, d, pos);
		pos += DL_SCREEN_SIZE_IN_BYTES;
	}

done:
	if(d) {
		de_bitmap_destroy(d->screen_img);
		de_bitmap_destroy(d->img);
		de_finfo_destroy(c, d->fi);
		de_free(c, d);
	}
}

static int de_identify_dlmaker(deark *c)
{
	u8 v;
	i64 nscrn;
	i64 hsize;
	i64 ctlsize;
	i64 expected_filesize;

	if(!de_input_file_has_ext(c, "dl")) return 0;
	v = de_getbyte(0);
	if(v==1) {
		nscrn = (i64)de_getbyte(21);
		ctlsize = de_getu16le(22); // num frames * 1 byte
		hsize = 792;
	}
	else if(v==2) {
		if(de_getbyte(1)>2) return 0;
		nscrn = (i64)de_getbyte(42);
		ctlsize = de_getu32le(43) * 2;
		hsize = 815;
	}
	else { // TODO: v3
		return 0;
	}

	if(nscrn==0 || ctlsize==0) return 0;
	expected_filesize = hsize + DL_SCREEN_SIZE_IN_BYTES*nscrn + ctlsize;
	if(c->infile->len == expected_filesize) return 90;
	if(c->infile->len < expected_filesize) return 0;
	// Allow for some padding or other unknown data at EOF.
	if(c->infile->len > expected_filesize+511) return 0;
	return 10;
}

static void de_help_dlmaker(deark *c)
{
	de_msg(c, "-opt dlmaker:montage : Output the \"screens\", instead of the "
		"individual images");
}

void de_module_dlmaker(deark *c, struct deark_module_info *mi)
{
	mi->id = "dlmaker";
	mi->desc = "DL animation (DL MAKER)";
	mi->run_fn = de_run_dlmaker;
	mi->identify_fn = de_identify_dlmaker;
	mi->help_fn = de_help_dlmaker;
}
