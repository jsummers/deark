// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// DL animation format, used by DL MAKER / DL VIEWER
//   by Davide Tome' & Luca De Gregorio

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_dlmaker);

#define V12_SCREEN_WIDTH 320
#define V12_SCREEN_HEIGHT 200
#define V12_SCREEN_SIZE_IN_BYTES 64000

struct v12_fields {
	int opt_montage;
	u8 screen_format;
	i64 img_xsize, img_ysize;
	// A "screen" is a 320x200 aggregate image containing 1 or more real images.
	i64 imgs_per_screen;
	i64 num_screens;
	de_bitmap *screen_img;
	de_bitmap *img;
};

typedef struct localctx_struct {
	de_ext_encoding input_encoding;
	u8 ver;
	struct v12_fields v12; // fields only used in v1 and v2
	i64 hdr_size;
	i64 num_anim_code_units;
	i64 anim_code_unit_size;
	i64 num_audio_components;
	i64 num_images;
	de_finfo *fi;
	u32 pal[256];
} lctx;

static void read_name(deark *c, lctx *d, i64 pos, de_ucstring *s, size_t nsize)
{
	size_t i;
	u8 buf[40];

	if(nsize>40) return;
	de_read(buf, pos, nsize);
	for(i=0; i<nsize; i++) {
		if(buf[i]) buf[i] ^= 0xff;
	}
	ucstring_append_bytes(s, buf, nsize, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
}

static void do_v12screen(deark *c, lctx *d, i64 pos)
{
	int single_image;

	single_image = (d->v12.imgs_per_screen<=1 || d->v12.opt_montage);

	if(!d->v12.screen_img) {
		d->v12.screen_img = de_bitmap_create(c, V12_SCREEN_WIDTH, V12_SCREEN_HEIGHT, 3);
		if(!single_image) {
			d->v12.screen_img->is_internal = 1;
		}
	}
	de_convert_image_paletted(c->infile, pos, 8, V12_SCREEN_WIDTH, d->pal, d->v12.screen_img, 0);
	if(single_image) {
		de_bitmap_write_to_file_finfo(d->v12.screen_img, d->fi, 0);
	}
	else {
		i64 i;
		i64 xpos = 0;
		i64 ypos = 0;

		if(!d->v12.img) {
			d->v12.img = de_bitmap_create(c, d->v12.img_xsize, d->v12.img_ysize, 3);
		}

		for(i=0; i<d->v12.imgs_per_screen; i++) {
			de_bitmap_copy_rect(d->v12.screen_img, d->v12.img, xpos, ypos, d->v12.img_xsize, d->v12.img_ysize,
				0, 0, 0);
			de_bitmap_write_to_file_finfo(d->v12.img, d->fi, 0);

			xpos += d->v12.img_xsize;
			if(xpos >= V12_SCREEN_WIDTH) {
				xpos = 0;
				ypos += d->v12.img_ysize;
			}
		}
	}
}

static void do_extract_v3_image(deark *c, lctx *d, i64 pos, i64 xsize, i64 ysize)
{
	de_bitmap *img = NULL;

	if(!de_good_image_dimensions(c, xsize, ysize)) goto done;

	img = de_bitmap_create(c, xsize, ysize, 3);
	de_convert_image_paletted(c->infile, pos, 8, xsize, d->pal, img, 0);
	de_bitmap_write_to_file_finfo(img, d->fi, 0);

done:
	de_bitmap_destroy(img);
}

static void do_extract_audio_component(deark *c, lctx *d, i64 pos, i64 len)
{
	dbuf *outf = NULL;

	if(pos+len > c->infile->len) goto done;
	if(len <= 26) goto done;
	outf = dbuf_create_output_file(c, "voc", NULL, 0);
	dbuf_write(outf, (const u8*)"Creative Voice File\x1a", 20);
	dbuf_copy(c->infile, pos+20, len-20, outf);
done:
	dbuf_close(outf);
}

static void do_audio(deark *c, lctx *d, i64 pos1)
{
	i64 i;
	i64 pos = pos1;

	for(i=0; i<d->num_audio_components; i++) {
		i64 dlen;

		if(pos+5 > c->infile->len) goto done;
		de_dbg(c, "audio component at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		dlen = de_getu32le_p(&pos);
		de_dbg(c, "len: %"I64_FMT, dlen);
		pos++; // unused?
		do_extract_audio_component(c, d, pos, dlen);
		de_dbg_indent(c, -1);
		pos += dlen;
	}

done:
	;
}

static int do_read_header(deark *c, lctx *d)
{
	int retval = 0;
	i64 pos = 0;
	size_t nsize;
	de_ucstring *s = NULL;

	d->ver = de_getbyte_p(&pos);
	de_dbg(c, "version: %u", (UI)d->ver);
	if(d->ver<1 || d->ver>3) {
		de_err(c, "Not a DL file");
		goto done;
	}

	if(d->ver==1) {
		d->v12.screen_format = 1;
	}
	else if(d->ver==2) {
		d->v12.screen_format = de_getbyte_p(&pos);
		de_dbg(c, "screen format: %u", (UI)d->v12.screen_format);
	}
	else {
		pos++;
	}

	if(d->ver<=2) {
		switch(d->v12.screen_format) {
		case 0:
			d->v12.img_xsize = 320;
			d->v12.img_ysize = 200;
			break;
		case 1:
			d->v12.img_xsize = 160;
			d->v12.img_ysize = 100;
			break;
		case 2:
			d->v12.img_xsize = 80;
			d->v12.img_ysize = 50;
			break;
		default:
			de_err(c, "Invalid/unsupported DL format");
			goto done;
		}

		d->v12.imgs_per_screen = (V12_SCREEN_WIDTH/d->v12.img_xsize) *
			(V12_SCREEN_HEIGHT/d->v12.img_ysize);
		if(d->ver==2) {
			de_dbg_indent(c, 1);
			de_dbg_dimensions(c, d->v12.img_xsize, d->v12.img_ysize);
			de_dbg(c, "images/screen: %u", (UI)d->v12.imgs_per_screen);
			de_dbg_indent(c, -1);
		}
	}

	if(d->ver==3) pos += 50;

	s = ucstring_create(c);
	nsize = (d->ver==3) ? 40 : 20;
	read_name(c, d, pos, s, nsize);
	de_dbg(c, "title: \"%s\"", ucstring_getpsz_d(s));
	pos += nsize;

	if(d->ver!=1) {
		ucstring_empty(s);
		read_name(c, d, pos, s, nsize);
		de_dbg(c, "author: \"%s\"", ucstring_getpsz_d(s));
		pos += nsize;
	}

	if(d->ver==3) {
		d->num_images = de_getu16le_p(&pos);
		de_dbg(c, "num images: %u", (UI)d->num_images);
	}
	else {
		d->v12.num_screens = (i64)de_getbyte_p(&pos);
		de_dbg(c, "num screens: %u", (UI)d->v12.num_screens);
		d->num_images = d->v12.num_screens * d->v12.imgs_per_screen;
		de_dbg(c, "num images (calculated): %"I64_FMT, d->num_images);
	}

	if(d->ver==1) {
		d->num_anim_code_units = de_getu16le_p(&pos);
		d->anim_code_unit_size = 1;
	}
	else if(d->ver==3) {
		d->num_anim_code_units = de_getu16le_p(&pos);
		d->anim_code_unit_size = 2;
	}
	else {
		d->num_anim_code_units = de_getu32le_p(&pos);
		d->anim_code_unit_size = 2;
	}
	de_dbg(c, "num frames: %"I64_FMT, d->num_anim_code_units);

	if(d->ver==3) {
		d->num_audio_components = de_getu16le_p(&pos);
		de_dbg(c, "num audio components: %"I64_FMT, d->num_audio_components);
	}

	de_read_simple_palette(c, c->infile, pos, 256, 3, d->pal, 256, DE_RDPALTYPE_VGA18BIT, 0);
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
	i64 anim_cmds_size;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->input_encoding = DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID);
	d->v12.opt_montage = de_get_ext_option_bool(c, "dlmaker:montage", 0);

	d->fi = de_finfo_create(c);
	d->fi->density.code = DE_DENSITY_UNK_UNITS;
	d->fi->density.xdens = 6.0;
	d->fi->density.ydens = 5.0;

	if(!do_read_header(c, d)) goto done;
	pos = d->hdr_size;

	if(d->ver==3) {
		for(k=0; k<d->num_images; k++) {
			i64 xsize, ysize;

			if(pos >= c->infile->len) goto done;
			de_dbg(c, "image #%u at %"I64_FMT, (UI)k, pos);
			de_dbg_indent(c, 1);
			xsize = de_getu16le_p(&pos);
			ysize = de_getu16le_p(&pos);
			de_dbg_dimensions(c, xsize, ysize);
			do_extract_v3_image(c, d, pos, xsize, ysize);
			pos += xsize*ysize;
			de_dbg_indent(c, -1);
		}
	}
	else {
		for(k=0; k<d->v12.num_screens; k++) {
			if(pos >= c->infile->len) goto done;
			de_dbg(c, "screen #%u at %"I64_FMT, (UI)k, pos);
			de_dbg_indent(c, 1);
			if(pos+V12_SCREEN_SIZE_IN_BYTES > c->infile->len) goto done;
			do_v12screen(c, d, pos);
			pos += V12_SCREEN_SIZE_IN_BYTES;
			de_dbg_indent(c, -1);
		}
	}

	anim_cmds_size = d->num_anim_code_units * d->anim_code_unit_size;
	de_dbg(c, "anim commands at %"I64_FMT", len=%"I64_FMT, pos, anim_cmds_size);
	pos += anim_cmds_size;
	if(d->ver==3) {
		do_audio(c, d, pos);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(d) {
		de_bitmap_destroy(d->v12.screen_img);
		de_bitmap_destroy(d->v12.img);
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
	else if(v==3) {
		nscrn = (i64)de_getbyte(132);
		ctlsize = de_getu16le(134) * 2;
		hsize = 906;
	}
	else {
		return 0;
	}

	if(nscrn==0 || ctlsize==0) return 0;
	if(v==3) {
		// This is just a minimum file size. v3 is hard to identify.
		expected_filesize = hsize + nscrn*5 + ctlsize;
		if(c->infile->len < expected_filesize) return 0;
		return 10;
	}
	expected_filesize = hsize + V12_SCREEN_SIZE_IN_BYTES*nscrn + ctlsize;
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
