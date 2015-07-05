// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// DEGAS / DEGAS Elite images

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

struct localctx_struct;
typedef struct localctx_struct lctx;

typedef int (*decoder_fn_type)(deark *c, lctx *d);

struct localctx_struct {
	dbuf *unc_pixels;
	unsigned int compression_code;
	de_int64 bpp;
	de_int64 w, h;
	de_int64 ncolors;
	de_uint32 pal[16];
	struct deark_bitmap *img;
};

static de_byte scale7to255(de_byte n)
{
	return (de_byte)(0.5+(255.0/7.0)*(double)n);
}

static void read_palette(deark *c, lctx *d, de_int64 pos)
{
	de_int64 i;
	unsigned int n;
	de_byte cr, cg, cb;
	de_byte cr1, cg1, cb1;

	for(i=0; i<16; i++) {
		n = (unsigned int)de_getui16be(pos);
		cr1 = (de_byte)((n>>8)&7);
		cg1 = (de_byte)((n>>4)&7);
		cb1 = (de_byte)(n&7);
		cr = scale7to255(cr1);
		cg = scale7to255(cg1);
		cb = scale7to255(cb1);
		de_dbg2(c, "pal[%2d] = 0x%04x (%d,%d,%d) -> (%3d,%3d,%3d)%s\n", (int)i, n,
			(int)cr1, (int)cg1, (int)cb1,
			(int)cr, (int)cg, (int)cb,
			(i>=d->ncolors)?" [unused]":"");

		d->pal[i] = DE_MAKE_RGB(cr, cg, cb);
		pos+=2;
	}
}

static int decode_lowres(deark *c, lctx *d)
{
	de_int64 i, j, k;
	unsigned int palent;
	unsigned int x;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			palent = 0;
			for(k=0; k<d->bpp; k++) {
				if(d->compression_code) {
					x = (unsigned int)de_get_bits_symbol(d->unc_pixels, 1,
						(j*d->bpp+k)*(d->w/8), i);
				}
				else {
					x = (unsigned int)de_get_bits_symbol(d->unc_pixels, 1,
						j*(d->w/2) + 2*k + (i/2-(i/2)%16)+8*((i%32)/16), i%16);
				}
				if(x) palent |= 1<<k;
			}
			de_bitmap_setpixel_rgb(d->img, i, j, d->pal[palent]);
		}
	}
	return 1;
}

static int decode_medres(deark *c, lctx *d)
{
	de_int64 i, j, k;
	unsigned int palent;
	unsigned int x;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			palent = 0;
			for(k=0; k<d->bpp; k++) {
				if(d->compression_code) {
					x = (unsigned int)de_get_bits_symbol(d->unc_pixels, 1,
						(j*d->bpp+k)*(d->w/8), i);
				}
				else {
					x = (unsigned int)de_get_bits_symbol(d->unc_pixels, 1,
						j*(d->w/4) + 2*k + (i/16)*2, i);
				}
				if(x) palent |= 1<<k;
			}
			de_bitmap_setpixel_rgb(d->img, i, j, d->pal[palent]);
		}
	}
	return 1;
}

static int decode_hires(deark *c, lctx *d)
{
	de_int64 i, j;
	unsigned int palent;
	de_int64 rowspan;

	rowspan = d->w/8;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			palent = (unsigned int)de_get_bits_symbol(d->unc_pixels, 1, j*rowspan, i);
			de_bitmap_setpixel_rgb(d->img, i, j, d->pal[palent]);
		}
	}
	return 1;
}

static void do_anim_fields(deark *c, lctx *d, de_int64 pos)
{
	de_int64 i;
	de_int64 n;

	for(i=0; i<4; i++) {
		n = de_getui16be(pos + 2*i);
		de_dbg2(c, "left_color_anim[%d] = %d\n", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getui16be(pos + 8 + 2*i);
		de_dbg2(c, "right_color_anim[%d] = %d\n", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getui16be(pos + 16 + 2*i);
		de_dbg2(c, "channel_direction[%d] = %d\n", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getui16be(pos + 24 + 2*i);
		de_dbg2(c, "channel_delay_code[%d] = %d\n", (int)i, (int)n);
	}

	// TODO: Can we determine if palette animation is actually used,
	// and only show the warning if it is?
	de_warn(c, "This image may use palette color animation, which is not supported.\n");
}

static void de_run_degas(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	decoder_fn_type decoder_fn = NULL;
	unsigned int format_code, resolution_code;
	int is_grayscale;
	double xdens, ydens;
	de_int64 cmpr_bytes_consumed = 0;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	format_code = (unsigned int)de_getui16be(pos);
	de_dbg(c, "format code: 0x%04x\n", format_code);
	resolution_code = format_code & 0x0003;
	d->compression_code = (format_code & 0x8000)>>15;
	de_dbg_indent(c, 1);
	de_dbg(c, "resolution code: %u\n", resolution_code);
	de_dbg(c, "compression code: %u\n", d->compression_code);
	de_dbg_indent(c, -1);
	pos += 2;

	switch(resolution_code) {
	case 0:
		d->bpp = 4;
		d->w = 320;
		d->h = 200;
		xdens = 240.0;
		ydens = 200.0;
		decoder_fn = decode_lowres;
		break;
	case 1:
		d->bpp = 2;
		d->w = 640;
		d->h = 200;
		xdens = 480.0;
		ydens = 200.0;
		decoder_fn = decode_medres;
		break;
	case 2:
		d->bpp = 1;
		d->w = 640;
		d->h = 400;
		xdens = 480.0;
		ydens = 400.0;
		decoder_fn = decode_hires;
		break;
	default:
		de_dbg(c, "Invalid or unsupported resolution (%u)\n", resolution_code);
		goto done;
	}
	d->ncolors = (de_int64)(1<<d->bpp);

	de_dbg(c, "dimensions: %dx%d, colors: %d\n", (int)d->w, (int)d->h, (int)d->ncolors);

	read_palette(c, d, pos);
	pos += 2*16;

	if(d->compression_code) {
		d->unc_pixels = dbuf_create_membuf(c, 32000);
		dbuf_set_max_length(d->unc_pixels, 32000);

		// TODO: Need to track how many compressed bytes are consumed, so we can locate the
		// fields following the compressed data.
		if(!de_fmtutil_uncompress_packbits(c->infile, pos, c->infile->len-pos, d->unc_pixels, &cmpr_bytes_consumed))
			goto done;

		de_dbg(c, "Compressed bytes found: %d\n", (int)cmpr_bytes_consumed);
		pos += cmpr_bytes_consumed;
	}
	else {
		de_int64 avail_bytes = 32000;
		if(pos+32000 > c->infile->len) {
			avail_bytes = c->infile->len - pos;
			de_warn(c, "Unexpected end of file (expected 32000 bytes, got %d)\n", (int)avail_bytes);
		}
		d->unc_pixels = dbuf_open_input_subfile(c->infile, pos, avail_bytes);
		pos += avail_bytes;
	}

	if(pos + 32 == c->infile->len) {
		do_anim_fields(c, d, pos);
	}

	is_grayscale = de_is_grayscale_palette(d->pal, d->ncolors);

	// TODO: Create a grayscale bitmap if all colors are black or white.
	d->img = de_bitmap_create(c, d->w, d->h, is_grayscale?1:3);

	d->img->density_code = DE_DENSITY_UNK_UNITS;
	d->img->xdens = xdens;
	d->img->ydens = ydens;

	decoder_fn(c, d);

	de_bitmap_write_to_file(d->img, NULL);

done:
	if(d->unc_pixels) dbuf_close(d->unc_pixels);
	de_bitmap_destroy(d->img);
	de_free(c, d);
}

static int de_identify_degas(deark *c)
{
	// TODO: Better identification
	if(de_input_file_has_ext(c, "pi1")) return 10;
	if(de_input_file_has_ext(c, "pi2")) return 10;
	if(de_input_file_has_ext(c, "pi3")) return 10;
	if(de_input_file_has_ext(c, "pc1")) return 10;
	if(de_input_file_has_ext(c, "pc2")) return 10;
	if(de_input_file_has_ext(c, "pc3")) return 10;
	return 0;
}

void de_module_degas(deark *c, struct deark_module_info *mi)
{
	mi->id = "degas";
	mi->run_fn = de_run_degas;
	mi->identify_fn = de_identify_degas;
}
