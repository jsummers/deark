// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// NIE - One of the "Naive Image Formats" used with the Wuffs project.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_nie);

static u8 unpremultiply_alpha(u8 cval, u8 a)
{
	if(a==0xff) {
		return cval;
	}
	if(a==0 || cval==0) {
		return 0;
	}
	if(cval>=a) {
		return 0xff;
	}
	return (u8)(0.5 + (double)cval / ((double)a/255.0));
}

static void de_run_nie(deark *c, de_module_params *mparams)
{
	u8 b;
	int is_bgra = 0;
	int need_errmsg = 0;
	int premultiplied_alpha = 0;
	i64 bytes_per_pixel;
	i64 w, h;
	i64 i, j;
	i64 k;
	i64 pos = 0;
	i64 sample_offset[4]; // R, G, B, A
	de_bitmap *img = NULL;

	pos += 3; // common part of signature
	b = de_getbyte_p(&pos);
	if(b!='E') {
		de_err(c, "Not an NIE file");
		goto done;
	}

	b = de_getbyte_p(&pos);
	if(b!=0xff) {
		need_errmsg = 1;
		goto done;
	}

	b = de_getbyte_p(&pos);
	if(b=='b') {
		is_bgra = 1;
	}
	else if(b!='r') {
		need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "sample order: %sA", (is_bgra?"BGR":"RGB"));

	b = de_getbyte_p(&pos);
	if(b=='p') {
		premultiplied_alpha = 1;
	}
	else if(b!='n') {
		need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "premultiplied alpha: %d", premultiplied_alpha);

	b = de_getbyte_p(&pos);
	if(b=='8') {
		bytes_per_pixel = 8;
	}
	else if(b=='4') {
		bytes_per_pixel = 4;
	}
	else {
		need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "bytes/pixel: %d", (int)bytes_per_pixel);

	w = de_getu32le_p(&pos);
	h = de_getu32le_p(&pos);
	de_dbg_dimensions(c, w, h);
	if(!de_good_image_dimensions(c, w, h)) {
		goto done;
	}

	// Make a sample-to-byte-offset map.
	for(k=0; k<4; k++) {
		sample_offset[k] = k; // Defaults
	}
	if(is_bgra) {
		sample_offset[0] = 2; // R sample is byte 2
		sample_offset[2] = 0; // B sample is byte 0
	}
	if(bytes_per_pixel==8) { // If 16 bits/sample, look only at the high byte
		for(k=0; k<4; k++) {
			sample_offset[k] = sample_offset[k]*2 + 1;
		}
	}

	img = de_bitmap_create(c, w, h, 4);

	for(j=0; j<h; j++) {
		for(i=0; i<w; i++) {
			u8 pbuf[8];
			u8 s[4];

			de_read(pbuf, pos, bytes_per_pixel);
			pos += bytes_per_pixel;

			for(k=0; k<4; k++) {
				s[k] = pbuf[sample_offset[k]];
			}

			if(premultiplied_alpha && (s[3]!=0xff)) {
				for(k=0; k<3; k++) {
					s[k] = unpremultiply_alpha(s[k], s[3]);
				}
			}

			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(s[0],s[1],s[2],s[3]));
		}
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	if(need_errmsg) {
		de_err(c, "Bad or unsupported NIE format");
	}
	de_bitmap_destroy(img);
}

static int de_identify_nie(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x6e\xc3\xaf" "E", 4)) return 100;
	return 0;
}

void de_module_nie(deark *c, struct deark_module_info *mi)
{
	mi->id = "nie";
	mi->desc = "NIE (Naive Image Formats)";
	mi->run_fn = de_run_nie;
	mi->identify_fn = de_identify_nie;
}
