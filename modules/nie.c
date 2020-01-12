// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// NIE - One of the "Naive Image Formats" used with the Wuffs project.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_nie);

typedef struct localctx_struct {
#define SIG_NIA 0x6ec3af41U
#define SIG_NIE 0x6ec3af45U
#define SIG_NII 0x6ec3af49U
	unsigned int sig;
	const char *fmtname;
	int is_bgra;
	int premultiplied_alpha;
	i64 bytes_per_pixel;
	i64 width, height;
	int bad_image_flag;
	int found_last_frame_flag;
} lctx;

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

// 8-byte "NII payload"
static void read_NIIpayload(deark *c, lctx *d, i64 pos, int printCCD)
{
	u64 ccd_code;
	i64 ccd;

	ccd_code = dbuf_getu64le(c->infile, pos);
	if(ccd_code & 0x1) {
		d->found_last_frame_flag = 1;
	}
	if(printCCD) {
		ccd = (i64)(ccd_code>>2);
		de_dbg(c, "CCD: %"I64_FMT" (%f seconds)", ccd,
			(double)ccd/705600000.0);
	}
}

// Decode the header, after the 4-byte signature.
// That's 12 bytes for NIE, 20 bytes for NII/NIA.
// On parse error, prints an error and returns 0.
// If the image has invalid attributes, sets d->bad_image_flag (only NIE cares
// about this).
static int do_header(deark *c, lctx *d, i64 pos)
{
	u8 b;

	b = de_getbyte_p(&pos);
	if(b!=0xff) {
		de_err(c, "Unknown %s version", d->fmtname);
		return 0;
	}

	if(d->sig==SIG_NII) {
		pos += 3; // padding
	}
	else {
		b = de_getbyte_p(&pos);
		if(b=='b') {
			d->is_bgra = 1;
		}
		else if(b!='r') {
			d->bad_image_flag = 1;
		}
		de_dbg(c, "sample order: %sA", (d->is_bgra?"BGR":"RGB"));

		b = de_getbyte_p(&pos);
		if(b=='p') {
			d->premultiplied_alpha = 1;
		}
		else if(b!='n') {
			d->bad_image_flag = 1;
		}
		de_dbg(c, "premultiplied alpha: %d", d->premultiplied_alpha);

		b = de_getbyte_p(&pos);
		if(b=='8') {
			d->bytes_per_pixel = 8;
		}
		else if(b=='4') {
			d->bytes_per_pixel = 4;
		}
		else {
			d->bad_image_flag = 1;
		}
		de_dbg(c, "bytes/pixel: %d", (int)d->bytes_per_pixel);
	}

	d->width = de_getu32le_p(&pos);
	d->height = de_getu32le_p(&pos);
	de_dbg_dimensions(c, d->width, d->height);

	if(d->sig==SIG_NIE) return 1;

	read_NIIpayload(c, d, pos, 0);
	return 1;
}

static void do_decode_nie(deark *c, lctx *d)
{
	i64 i, j;
	i64 k;
	i64 pos = 0;
	i64 sample_offset[4]; // R, G, B, A
	de_bitmap *img = NULL;

	pos += 4; // signature, already read

	if(!do_header(c, d, pos)) goto done;
	if(d->bad_image_flag) {
		de_err(c, "Bad or unsupported NIE format");
		goto done;
	}
	pos += 12;

	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}

	// Make a sample-to-byte-offset map.
	for(k=0; k<4; k++) {
		sample_offset[k] = k; // Defaults
	}
	if(d->is_bgra) {
		sample_offset[0] = 2; // R sample is byte 2
		sample_offset[2] = 0; // B sample is byte 0
	}
	if(d->bytes_per_pixel==8) { // If 16 bits/sample, look only at the high byte
		for(k=0; k<4; k++) {
			sample_offset[k] = sample_offset[k]*2 + 1;
		}
	}

	img = de_bitmap_create(c, d->width, d->height, 4);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			u8 pbuf[8];
			u8 s[4];

			de_read(pbuf, pos, d->bytes_per_pixel);
			pos += d->bytes_per_pixel;

			for(k=0; k<4; k++) {
				s[k] = pbuf[sample_offset[k]];
			}

			if(d->premultiplied_alpha && (s[3]!=0xff)) {
				for(k=0; k<3; k++) {
					s[k] = unpremultiply_alpha(s[k], s[3]);
				}
			}

			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(s[0],s[1],s[2],s[3]));
		}
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img);
}

static void do_decode_nii(deark *c, lctx *d)
{
	i64 pos = 4;

	if(!do_header(c, d, pos)) goto done;
	pos += 20;

	while(1) {
		if(d->found_last_frame_flag) break;
		de_dbg(c, "frame info at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		read_NIIpayload(c, d, pos, 1);
		pos += 8;
		de_dbg_indent(c, -1);
	}
	// TODO?: footer
done:
	;
}

static void do_decode_nia(deark *c, lctx *d)
{
	i64 pos = 4;
	i64 frame_size, frame_size_padded;

	if(!do_header(c, d, pos)) goto done;
	pos += 20;

	frame_size = 16 + d->width*d->height*d->bytes_per_pixel;
	de_dbg(c, "frame size: %"I64_FMT" bytes", frame_size);
	if(frame_size<16 || frame_size>DE_MAX_SANE_OBJECT_SIZE) {
		goto done;
	}
	frame_size_padded = de_pad_to_n(frame_size, 8);

	while(1) {
		if(d->found_last_frame_flag) break;
		if(pos+frame_size_padded > c->infile->len) goto done;
		de_dbg(c, "frame at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		dbuf_create_file_from_slice(c->infile, pos, frame_size, "nie", NULL, 0x0);
		pos += frame_size_padded;
		read_NIIpayload(c, d, pos, 1);
		pos += 8;
		de_dbg_indent(c, -1);
	}
	// TODO?: footer
done:
	;
}

static void de_run_nie(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->sig = (unsigned int)de_getu32be(0);

	if(d->sig==SIG_NIE) {
		d->fmtname = "NIE";
	}
	else if(d->sig==SIG_NII) {
		d->fmtname = "NII";
	}
	else if(d->sig==SIG_NIA) {
		d->fmtname = "NIA";
	}
	else {
		de_err(c, "File not in NIE/NII/NIA format");
		goto done;
	}

	de_declare_fmt(c, d->fmtname);

	if(d->sig==SIG_NIE) {
		do_decode_nie(c, d);
	}
	else if(d->sig==SIG_NII) {
		do_decode_nii(c, d);
	}
	else if(d->sig==SIG_NIA) {
		do_decode_nia(c, d);
	}

done:
	de_free(c, d);
}

static int de_identify_nie(deark *c)
{
	unsigned int sig;

	sig = (unsigned int)de_getu32be(0);
	if(sig==SIG_NIE || sig==SIG_NII || sig==SIG_NIA) return 100;
	return 0;
}

void de_module_nie(deark *c, struct deark_module_info *mi)
{
	mi->id = "nie";
	mi->desc = "NIE/NII/NIA (Naive Image Formats)";
	mi->run_fn = de_run_nie;
	mi->identify_fn = de_identify_nie;
}
