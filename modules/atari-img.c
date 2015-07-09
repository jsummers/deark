// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

struct atari_img_decode_data {
	de_int64 bpp;
	de_int64 w, h;
	dbuf *unc_pixels;
	int was_compressed;
	de_uint32 *pal;
	struct deark_bitmap *img;
};

static de_byte scale7to255(de_byte n)
{
	return (de_byte)(0.5+(255.0/7.0)*(double)n);
}

static de_byte scale1000to255(de_int64 n)
{
	if(n>=1000) return 255;
	if(n<=0) return 0;
	return (de_byte)(0.5+(((double)n)*(255.0/1000.0)));
}

static int decode_atari_image_paletted(deark *c, struct atari_img_decode_data *adata)
{
	de_int64 i, j;
	de_int64 plane;
	de_int64 rowspan;
	de_byte b;
	de_uint32 v;
	de_int64 planespan;

	planespan = 2*((adata->w+15)/16);
	rowspan = planespan*adata->bpp;

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = 0;

			for(plane=0; plane<adata->bpp; plane++) {
				if(adata->was_compressed==0) {
					// TODO: Simplify this.
					if(adata->bpp==1) {
						b = de_get_bits_symbol(adata->unc_pixels, 1, j*rowspan, i);
					}
					else if(adata->bpp==2) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i/16)*2, i);
					}
					else if(adata->bpp==4) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i/2-(i/2)%16)+8*((i%32)/16), i%16);
					}
					else if(adata->bpp==8) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i-i%16), i%16);
					}
					else {
						b = 0;
					}
				}
				else {
					b = de_get_bits_symbol(adata->unc_pixels, 1, j*rowspan + plane*planespan, i);
				}
				if(b) v |= 1<<plane;
			}

			if(v>255) v=255;
			de_bitmap_setpixel_rgb(adata->img, i, j, adata->pal[v]);
		}
	}
	return 1;
}

static int decode_atari_image_16(deark *c, struct atari_img_decode_data *adata)
{
	de_int64 i, j;
	de_int64 rowspan;
	de_uint32 v;
	de_int64 planespan;

	planespan = 2*((adata->w+15)/16);
	rowspan = planespan*adata->bpp;

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = (de_uint32)dbuf_getui16be(adata->unc_pixels, j*rowspan + 2*i);
			v = de_rgb565_to_888(v);
			de_bitmap_setpixel_rgb(adata->img, i, j,v);
		}
	}
	return 1;
}

static int de_decode_atari_image(deark *c, struct atari_img_decode_data *adata)
{
	switch(adata->bpp) {
	case 16:
		return decode_atari_image_16(c, adata);
	case 8: case 4: case 2: case 1:
		return decode_atari_image_paletted(c, adata);
	}

	de_err(c, "Unsupported bits/pixel (%d)\n", (int)adata->bpp);
	return 0;
}

// **************************************************************************
// DEGAS / DEGAS Elite images
// **************************************************************************

typedef struct degasctx_struct {
	de_int64 ncolors;
	unsigned int compression_code;
	de_uint32 pal[16];
	struct atari_img_decode_data adata;
} degasctx;

static void degas_read_palette(deark *c, degasctx *d, de_int64 pos)
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

static void do_degas_anim_fields(deark *c, degasctx *d, de_int64 pos)
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
	//de_warn(c, "This image may use palette color animation, which is not supported.\n");
}

static void de_run_degas(deark *c, const char *params)
{
	degasctx *d = NULL;
	de_int64 pos;
	unsigned int format_code, resolution_code;
	int is_grayscale;
	double xdens, ydens;
	de_int64 cmpr_bytes_consumed = 0;

	d = de_malloc(c, sizeof(degasctx));

	d->adata.pal = d->pal;

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
		d->adata.bpp = 4;
		d->adata.w = 320;
		d->adata.h = 200;
		xdens = 240.0;
		ydens = 200.0;
		break;
	case 1:
		d->adata.bpp = 2;
		d->adata.w = 640;
		d->adata.h = 200;
		xdens = 480.0;
		ydens = 200.0;
		break;
	case 2:
		d->adata.bpp = 1;
		d->adata.w = 640;
		d->adata.h = 400;
		xdens = 480.0;
		ydens = 400.0;
		break;
	default:
		de_dbg(c, "Invalid or unsupported resolution (%u)\n", resolution_code);
		goto done;
	}
	d->ncolors = (de_int64)(1<<d->adata.bpp);

	de_dbg(c, "dimensions: %dx%d, colors: %d\n", (int)d->adata.w, (int)d->adata.h, (int)d->ncolors);

	degas_read_palette(c, d, pos);
	pos += 2*16;

	if(d->compression_code) {
		d->adata.was_compressed = 1;
		d->adata.unc_pixels = dbuf_create_membuf(c, 32000);
		dbuf_set_max_length(d->adata.unc_pixels, 32000);

		// TODO: Need to track how many compressed bytes are consumed, so we can locate the
		// fields following the compressed data.
		if(!de_fmtutil_uncompress_packbits(c->infile, pos, c->infile->len-pos, d->adata.unc_pixels, &cmpr_bytes_consumed))
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
		d->adata.unc_pixels = dbuf_open_input_subfile(c->infile, pos, avail_bytes);
		pos += avail_bytes;
	}

	if(pos + 32 == c->infile->len) {
		do_degas_anim_fields(c, d, pos);
	}

	is_grayscale = de_is_grayscale_palette(d->pal, d->ncolors);

	// TODO: Create a grayscale bitmap if all colors are black or white.
	d->adata.img = de_bitmap_create(c, d->adata.w, d->adata.h, is_grayscale?1:3);

	d->adata.img->density_code = DE_DENSITY_UNK_UNITS;
	d->adata.img->xdens = xdens;
	d->adata.img->ydens = ydens;

	de_decode_atari_image(c, &d->adata);

	de_bitmap_write_to_file(d->adata.img, NULL);

done:
	dbuf_close(d->adata.unc_pixels);
	de_bitmap_destroy(d->adata.img);
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

// **************************************************************************
// Atari Prism Paint (.pnt)
// **************************************************************************

typedef struct prismctx_struct {
	de_int64 pal_size;
	de_int64 compression_code;
	de_int64 pic_data_size;
	de_uint32 pal[256];
	struct atari_img_decode_data adata;
} prixmctx;

// A color value of N does not necessarily refer to Nth color in the palette.
// Some of them are mixed up. Apparently this is called "VDI order".
// Reference: http://toshyp.atari.org/en/VDI_fundamentals.html
static unsigned int map_vdi_pal(de_int64 bpp, unsigned int v)
{
	if(bpp==1) return v;
	switch(v) {
		case 1: return 2;
		case 2: return 3;
		case 3: return bpp>2 ? 6 : 1;
		case 5: return 7;
		case 6: return 5;
		case 7: return 8;
		case 8: return 9;
		case 9: return 10;
		case 10: return 11;
		case 11: return 14;
		case 13: return 15;
		case 14: return 13;
		case 15: return bpp==8 ? 255 : 1;
		case 255: return 1;
	}
	return v;
}

static void do_prism_read_palette(deark *c, prixmctx *d)
{
	de_int64 i;
	de_int64 r1, g1, b1;
	de_byte r, g, b;
	de_uint32 pal1[256];

	de_memset(pal1, 0, sizeof(pal1));

	for(i=0; i<d->pal_size; i++) {
		r1 = de_getui16be(128+6*i+0);
		g1 = de_getui16be(128+6*i+2);
		b1 = de_getui16be(128+6*i+4);
		r = scale1000to255(r1);
		g = scale1000to255(g1);
		b = scale1000to255(b1);
		de_dbg2(c, "pal#%3d (%5d,%5d,%5d) (%3d,%3d,%3d)\n", (int)i, (int)r1, (int)g1, (int)b1,
			(int)r, (int)g, (int)b);
		if(i>255) continue;
		pal1[i] = DE_MAKE_RGB(r,g,b);
	}

	for(i=0; i<d->pal_size; i++) {
		d->pal[i] = pal1[map_vdi_pal(d->adata.bpp, (unsigned int)i)];
	}
}

static void de_run_prismpaint(deark *c, const char *params)
{
	prixmctx *d = NULL;
	de_int64 pixels_start;

	d = de_malloc(c, sizeof(prixmctx));

	d->adata.pal = d->pal;
	d->pal_size = de_getui16be(6);
	d->adata.w = de_getui16be(8);
	d->adata.h = de_getui16be(10);
	de_dbg(c, "pal_size: %d, dimensions: %dx%d\n", (int)d->pal_size,
		(int)d->adata.w, (int)d->adata.h);
	if(!de_good_image_dimensions(c, d->adata.w, d->adata.h)) goto done;

	d->adata.bpp = de_getui16be(12);
	d->compression_code = de_getui16be(14);
	de_dbg(c, "bits/pixel: %d, compression: %d\n", (int)d->adata.bpp,
		(int)d->compression_code);

	d->pic_data_size = de_getui32be(16);
	de_dbg(c, "reported (uncompressed) picture data size: %d\n", (int)d->pic_data_size);

	do_prism_read_palette(c, d);

	if(d->adata.bpp!=1 && d->adata.bpp!=2 && d->adata.bpp!=4
		&& d->adata.bpp!=8 && d->adata.bpp!=16)
	{
		de_err(c, "Unsupported bits/pixel (%d)\n", (int)d->adata.bpp);
		goto done;
	}
	if(d->compression_code!=0 && d->compression_code!=1) {
		de_err(c, "Unsupported compression (%d)\n", (int)d->compression_code);
		goto done;
	}
	if(d->adata.bpp==16 && d->compression_code!=0) {
		de_warn(c, "Compressed 16-bit image support is untested, and may not work.\n");
	}

	pixels_start = 128 + 2*3*d->pal_size;
	de_dbg(c, "pixel data starts at %d\n", (int)pixels_start);
	if(pixels_start >= c->infile->len) goto done;

	if(d->compression_code==0) {
		d->adata.unc_pixels = dbuf_open_input_subfile(c->infile, pixels_start,
			c->infile->len - pixels_start);
	}
	else {
		d->adata.was_compressed = 1;
		// TODO: Calculate the initial size more accurately.
		d->adata.unc_pixels = dbuf_create_membuf(c, d->adata.w*d->adata.h);
		//dbuf_set_max_length(unc_pixels, ...);

		de_fmtutil_uncompress_packbits(c->infile, pixels_start, c->infile->len - pixels_start,
			d->adata.unc_pixels, NULL);
		de_dbg(c, "uncompressed to %d bytes\n", (int)d->adata.unc_pixels->len);
	}

	d->adata.img = de_bitmap_create(c, d->adata.w, d->adata.h, 3);
	de_decode_atari_image(c, &d->adata);
	de_bitmap_write_to_file(d->adata.img, NULL);
	de_bitmap_destroy(d->adata.img);
	d->adata.img = NULL;

done:
	dbuf_close(d->adata.unc_pixels);
	de_free(c, d);
}

static int de_identify_prismpaint(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PNT\x00", 4))
		return 100;
	return 0;
}

void de_module_prismpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "prismpaint";
	mi->run_fn = de_run_prismpaint;
	mi->identify_fn = de_identify_prismpaint;
}

// **************************************************************************
// Atari Falcon True Color .FTC
// **************************************************************************

static void de_run_ftc(deark *c, const char *params)
{
	struct atari_img_decode_data *adata = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = 16;
	adata->w = 384;
	adata->h = 240;
	adata->unc_pixels = c->infile;
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_decode_atari_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL);
	de_bitmap_destroy(adata->img);
	de_free(c, adata);
}

static int de_identify_ftc(deark *c)
{
	if(c->infile->len != 184320) return 0;
	if(!de_input_file_has_ext(c, "ftc")) return 0;
	return 60;
}

void de_module_ftc(deark *c, struct deark_module_info *mi)
{
	mi->id = "ftc";
	mi->run_fn = de_run_ftc;
	mi->identify_fn = de_identify_ftc;
}
