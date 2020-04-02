// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_degas);
DE_DECLARE_MODULE(de_module_prismpaint);
DE_DECLARE_MODULE(de_module_ftc);
DE_DECLARE_MODULE(de_module_eggpaint);
DE_DECLARE_MODULE(de_module_indypaint);
DE_DECLARE_MODULE(de_module_godpaint);
DE_DECLARE_MODULE(de_module_tinystuff);
DE_DECLARE_MODULE(de_module_doodle);
DE_DECLARE_MODULE(de_module_neochrome);
DE_DECLARE_MODULE(de_module_neochrome_ani);
DE_DECLARE_MODULE(de_module_fpaint_pi4);
DE_DECLARE_MODULE(de_module_fpaint_pi9);
DE_DECLARE_MODULE(de_module_atari_pi7);
DE_DECLARE_MODULE(de_module_falcon_xga);
DE_DECLARE_MODULE(de_module_coke);
DE_DECLARE_MODULE(de_module_animatic);

static void fix_dark_pal(deark *c, struct atari_img_decode_data *adata);

static void help_respectpal(deark *c)
{
	de_msg(c, "-opt atari:respectpal : Don't ignore a seemingly bad 2-color palette");
}

// **************************************************************************
// DEGAS / DEGAS Elite images
// **************************************************************************

typedef struct degasctx_struct {
	unsigned int compression_code;
	int degas_elite_flag;
	u32 pal[16];
} degasctx;

static void do_degas_anim_fields(deark *c, degasctx *d, i64 pos)
{
	i64 i;
	i64 n;

	for(i=0; i<4; i++) {
		n = de_getu16be(pos + 2*i);
		de_dbg2(c, "left_color_anim[%d] = %d", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getu16be(pos + 8 + 2*i);
		de_dbg2(c, "right_color_anim[%d] = %d", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getu16be(pos + 16 + 2*i);
		de_dbg2(c, "channel_direction[%d] = %d", (int)i, (int)n);
	}
	for(i=0; i<4; i++) {
		n = de_getu16be(pos + 24 + 2*i);
		de_dbg2(c, "channel_delay_code[%d] = %d", (int)i, (int)n);
	}

	// TODO: Can we determine if palette animation is actually used,
	// and only show the warning if it is?
	//de_warn(c, "This image may use palette cycling animation, which is not supported.");
}

// Try to figure out if this is a DEGAS Elite file (as opposed to original DEGAS).
static int is_degas_elite(deark *c, degasctx *d)
{
	i64 n;
	i64 x;
	i64 pos;
	int all_zero = 1;

	if(d->compression_code) return 1; // Only DEGAS Elite supports compression.
	if(c->infile->len < 32066) return 0;

	// Test if the animation segment seems to have valid values, to try to distinguish
	// it from meaningless padding. (This is overkill.)
	pos = 32034;
	for(n=0; n<8; n++) {
		// The first 8 fields are "color numbers".
		// Guessing that they should be 0-15.
		x = de_getu16be(pos+n*2);
		if(x>0x0f) return 0;
		if(x) all_zero = 0;
	}
	pos += 8*2;
	for(n=0; n<4; n++) {
		// The next 4 fields (channel direction) should be 0, 1, or 2.
		x = de_getu16be(pos+n*2);
		if(x>2) return 0;
		if(x) all_zero = 0;
	}
	pos += 4*2;
	for(n=0; n<4; n++) {
		// The next 4 fields (delay) must be from 0 to 128.
		x = de_getu16be(pos+n*2);
		if(x>128) return 0;
		if(x) all_zero = 0;
	}

	if(all_zero && c->infile->len>32068) {
		// If every field was 0, and the file size doesn't suggest Elite,
		// just assume it's not valid.
		return 0;
	}

	return 1;
}

static void de_run_degas(deark *c, de_module_params *mparams)
{
	degasctx *d = NULL;
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	i64 pos;
	unsigned int format_code, resolution_code;
	int is_grayscale;
	i64 cmpr_bytes_consumed = 0;

	d = de_malloc(c, sizeof(degasctx));
	adata = de_malloc(c, sizeof(struct atari_img_decode_data));

	adata->pal = d->pal;

	pos = 0;
	format_code = (unsigned int)de_getu16be(pos);
	de_dbg(c, "format code: 0x%04x", format_code);
	resolution_code = format_code & 0x0003;
	d->compression_code = (format_code & 0x8000)>>15;
	de_dbg_indent(c, 1);
	de_dbg(c, "resolution code: %u", resolution_code);
	de_dbg(c, "compression code: %u", d->compression_code);
	de_dbg_indent(c, -1);
	pos += 2;

	switch(resolution_code) {
	case 0:
		adata->bpp = 4;
		adata->w = 320;
		adata->h = 200;
		break;
	case 1:
		adata->bpp = 2;
		adata->w = 640;
		adata->h = 200;
		break;
	case 2:
		adata->bpp = 1;
		adata->w = 640;
		adata->h = 400;
		break;
	default:
		de_dbg(c, "Invalid or unsupported resolution (%u)", resolution_code);
		goto done;
	}
	adata->ncolors = de_pow2(adata->bpp);

	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d, colors: %d", (int)adata->w, (int)adata->h, (int)adata->ncolors);

	d->degas_elite_flag = is_degas_elite(c, d);
	de_declare_fmtf(c, "DEGAS%s %d-color %scompressed",
		d->degas_elite_flag?" Elite":"",
		(int)adata->ncolors,
		d->compression_code?"":"un");

	de_fmtutil_read_atari_palette(c, c->infile, pos, adata->pal, 16, adata->ncolors, 0);
	pos += 2*16;
	fix_dark_pal(c, adata);

	if(d->compression_code) {
		adata->was_compressed = 1;
		adata->unc_pixels = dbuf_create_membuf(c, 32000, 1);

		if(!de_fmtutil_decompress_packbits(c->infile, pos, c->infile->len-pos, adata->unc_pixels, &cmpr_bytes_consumed))
			goto done;

		de_dbg(c, "Compressed bytes found: %d", (int)cmpr_bytes_consumed);
		pos += cmpr_bytes_consumed;
	}
	else {
		i64 avail_bytes = 32000;
		if(pos+32000 > c->infile->len) {
			avail_bytes = c->infile->len - pos;
			de_warn(c, "Unexpected end of file (expected 32000 bytes, got %d)", (int)avail_bytes);
		}
		adata->unc_pixels = dbuf_open_input_subfile(c->infile, pos, avail_bytes);
		pos += avail_bytes;
	}

	if(pos + 32 == c->infile->len) {
		do_degas_anim_fields(c, d, pos);
	}

	is_grayscale = de_is_grayscale_palette(adata->pal, adata->ncolors);

	adata->img = de_bitmap_create(c, adata->w, adata->h, is_grayscale?1:3);

	fi = de_finfo_create(c);
	de_fmtutil_atari_set_standard_density(c, adata, fi);

	de_fmtutil_atari_decode_image(c, adata);

	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

done:
	if(adata) {
		dbuf_close(adata->unc_pixels);
		de_bitmap_destroy(adata->img);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
	de_free(c, d);
}

static int de_identify_degas(deark *c)
{
	static const char *exts[6] = {"pi1", "pi2", "pi3", "pc1", "pc2", "pc3" };
	i64 i;
	int flag;
	i64 sig;

	flag = 0;
	for(i=0; i<6; i++) {
		if(de_input_file_has_ext(c, exts[i])) {
			flag = 1;
			break;
		}
	}
	if(!flag) return 0;

	sig = de_getu16be(0);
	if(sig==0x0000 || sig==0x0001 || sig==0x0002) {
		if(c->infile->len==32034) return 100; // DEGAS
		if(c->infile->len==32066) return 100; // DEGAS Elite
		if(c->infile->len==32128) return 40; // Could be padded to a multiple of 128 bytes
		if(c->infile->len>16000) return 10;
	}
	else if(sig==0x8000 || sig==0x8001 || sig==0x8002) {
		return 60;
	}

	return 0;
}

static void de_help_degas(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
	help_respectpal(c);
}

void de_module_degas(deark *c, struct deark_module_info *mi)
{
	mi->id = "degas";
	mi->desc = "Atari DEGAS or DEGAS Elite image";
	mi->run_fn = de_run_degas;
	mi->identify_fn = de_identify_degas;
	mi->help_fn = de_help_degas;
}

// **************************************************************************
// Atari Prism Paint (.pnt)
// **************************************************************************

typedef struct prismctx_struct {
	i64 pal_size;
	i64 compression_code;
	i64 pic_data_size;
	u32 pal[256];
} prismctx;

// A color value of N does not necessarily refer to Nth color in the palette.
// Some of them are mixed up. Apparently this is called "VDI order".
// Reference: http://toshyp.atari.org/en/VDI_fundamentals.html
static unsigned int map_vdi_pal(i64 bpp, unsigned int v)
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

static void do_prism_read_palette(deark *c, prismctx *d, struct atari_img_decode_data *adata)
{
	i64 i;
	i64 r1, g1, b1;
	u8 r, g, b;
	u32 pal1[256];
	u32 clr;
	char tmps[32];

	de_zeromem(pal1, sizeof(pal1));

	for(i=0; i<d->pal_size; i++) {
		r1 = de_getu16be(128+6*i+0);
		g1 = de_getu16be(128+6*i+2);
		b1 = de_getu16be(128+6*i+4);
		r = de_scale_1000_to_255(r1);
		g = de_scale_1000_to_255(g1);
		b = de_scale_1000_to_255(b1);
		clr = DE_MAKE_RGB(r,g,b);
		de_snprintf(tmps, sizeof(tmps), "(%4d,%4d,%4d) "DE_CHAR_RIGHTARROW" ",
			(int)r1, (int)g1, (int)b1);
		de_dbg_pal_entry2(c, i, clr, tmps, NULL, NULL);
		if(i<256) {
			pal1[i] = clr;
		}
	}

	for(i=0; i<d->pal_size; i++) {
		d->pal[i] = pal1[map_vdi_pal(adata->bpp, (unsigned int)i)];
	}
}

static void de_run_prismpaint(deark *c, de_module_params *mparams)
{
	prismctx *d = NULL;
	i64 pixels_start;
	struct atari_img_decode_data *adata = NULL;

	d = de_malloc(c, sizeof(prismctx));

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));

	adata->pal = d->pal;
	d->pal_size = de_getu16be(6);
	adata->w = de_getu16be(8);
	adata->h = de_getu16be(10);
	de_dbg(c, "pal_size: %d, dimensions: %d"DE_CHAR_TIMES"%d", (int)d->pal_size,
		(int)adata->w, (int)adata->h);
	if(!de_good_image_dimensions(c, adata->w, adata->h)) goto done;

	adata->bpp = de_getu16be(12);
	d->compression_code = de_getu16be(14);
	de_dbg(c, "bits/pixel: %d, compression: %d", (int)adata->bpp,
		(int)d->compression_code);

	d->pic_data_size = de_getu32be(16);
	de_dbg(c, "reported (uncompressed) picture data size: %d", (int)d->pic_data_size);

	do_prism_read_palette(c, d, adata);

	if(adata->bpp!=1 && adata->bpp!=2 && adata->bpp!=4
		&& adata->bpp!=8 && adata->bpp!=16)
	{
		de_err(c, "Unsupported bits/pixel (%d)", (int)adata->bpp);
		goto done;
	}
	if(d->compression_code!=0 && d->compression_code!=1) {
		de_err(c, "Unsupported compression (%d)", (int)d->compression_code);
		goto done;
	}
	if(adata->bpp==16 && d->compression_code!=0) {
		de_warn(c, "Compressed 16-bit image support is untested, and may not work.");
	}

	pixels_start = 128 + 2*3*d->pal_size;
	de_dbg(c, "pixel data starts at %d", (int)pixels_start);
	if(pixels_start >= c->infile->len) goto done;

	if(d->compression_code==0) {
		adata->unc_pixels = dbuf_open_input_subfile(c->infile, pixels_start,
			c->infile->len - pixels_start);
	}
	else {
		adata->was_compressed = 1;
		// TODO: Calculate the initial size more accurately.
		adata->unc_pixels = dbuf_create_membuf(c, adata->w*adata->h, 0);
		//dbuf_set_max_length(unc_pixels, ...);

		de_fmtutil_decompress_packbits(c->infile, pixels_start, c->infile->len - pixels_start,
			adata->unc_pixels, NULL);
		de_dbg(c, "decompressed to %d bytes", (int)adata->unc_pixels->len);
	}

	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL, 0);

done:
	if(adata) {
		dbuf_close(adata->unc_pixels);
		de_bitmap_destroy(adata->img);
		de_free(c, adata);
	}
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
	mi->desc = "Atari Prism Paint .PNT, a.k.a. TruePaint .TPI";
	mi->run_fn = de_run_prismpaint;
	mi->identify_fn = de_identify_prismpaint;
}

// **************************************************************************
// Atari Falcon True Color .FTC
// **************************************************************************

static void de_run_ftc(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = 16;
	adata->w = 384;
	adata->h = 240;
	adata->unc_pixels = c->infile;
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = 288;
	fi->density.ydens = 240;
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);
	de_bitmap_destroy(adata->img);
	de_finfo_destroy(c, fi);
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
	mi->desc = "Atari Falcon True Color .FTC";
	mi->run_fn = de_run_ftc;
	mi->identify_fn = de_identify_ftc;
}

// **************************************************************************
// Atari Falcon EggPaint .TRP
// **************************************************************************

static void de_run_eggpaint(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));

	if(!dbuf_memcmp(c->infile, 0, "tru?", 4)) {
		de_declare_fmt(c, "Spooky Sprites");
	}
	else {
		de_declare_fmt(c, "EggPaint");
	}

	adata->bpp = 16;
	adata->w = de_getu16be(4);
	adata->h = de_getu16be(6);
	de_dbg_dimensions(c, adata->w, adata->h);
	adata->unc_pixels = dbuf_open_input_subfile(c->infile, 8, c->infile->len-8);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL, 0);

	dbuf_close(adata->unc_pixels);
	de_bitmap_destroy(adata->img);
	de_free(c, adata);
}

static int de_identify_eggpaint(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "TRUP", 4)) {
		return 80;
	}
	if(!dbuf_memcmp(c->infile, 0, "tru?", 4)) {
		return 100;
	}
	return 0;
}

void de_module_eggpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "eggpaint";
	mi->desc = "Atari EggPaint .TRP";
	mi->run_fn = de_run_eggpaint;
	mi->identify_fn = de_identify_eggpaint;
}

// **************************************************************************
// Atari Falcon IndyPaint .TRU
// **************************************************************************

static void de_run_indypaint(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = 16;
	adata->w = de_getu16be(4);
	adata->h = de_getu16be(6);
	de_dbg_dimensions(c, adata->w, adata->h);
	adata->unc_pixels = dbuf_open_input_subfile(c->infile, 256, c->infile->len-256);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL, 0);

	dbuf_close(adata->unc_pixels);
	de_bitmap_destroy(adata->img);
	de_free(c, adata);
}

static int de_identify_indypaint(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Indy", 4)) {
		return 70;
	}
	return 0;
}

void de_module_indypaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "indypaint";
	mi->desc = "Atari IndyPaint .TRU";
	mi->run_fn = de_run_indypaint;
	mi->identify_fn = de_identify_indypaint;
}

// **************************************************************************
// Atari Falcon GodPaint .GOD
// **************************************************************************

static void de_run_godpaint(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = 16;
	adata->w = de_getu16be(2);
	adata->h = de_getu16be(4);
	de_dbg_dimensions(c, adata->w, adata->h);
	adata->unc_pixels = dbuf_open_input_subfile(c->infile, 6, c->infile->len-6);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL, 0);

	dbuf_close(adata->unc_pixels);
	de_bitmap_destroy(adata->img);
	de_free(c, adata);
}

static int de_identify_godpaint(deark *c)
{
	i64 sig;

	sig = de_getu16be(0);
	if(sig!=0x4734 && sig!=0x0400) return 0;
	if(de_input_file_has_ext(c, "god")) return 100;
	if(sig==0x4734) return 5;
	return 0;
}

void de_module_godpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "godpaint";
	mi->desc = "Atari Falcon GodPaint";
	mi->run_fn = de_run_godpaint;
	mi->identify_fn = de_identify_godpaint;
}

// **************************************************************************
// Tiny Stuff
// **************************************************************************

typedef struct tinyctx_struct {
	u8 res_code;
	i64 num_control_bytes;
	i64 num_data_words;
	u32 pal[16];

	// Decompression params:
	i64 numstripes;
	i64 numscans;
	i64 dst_rowspan;

	// Decompression state:
	int stopflag;
	i64 ypos;
	i64 stripe;
	i64 scan;
	i64 column;
	i64 dcmpr_word_count;
} tinyctx;

static void tiny_setword(deark *c, tinyctx *d, struct atari_img_decode_data *adata, const u8 *wordbuf)
{
	i64 dstpos;

	// As each word is emitted from the decompressor, we store it in the unc_pixels buffer
	// in a particular location. The location is chosen so as to make the pixel data more
	// contiguous, but (for 2bpp and 4bpp images) more work will still have to be done when
	// the image is generated.

	if(d->stopflag) return;
	d->dcmpr_word_count++;
	dstpos = d->stripe * 8 + d->column*2 + (d->ypos * d->numscans + d->scan)*d->dst_rowspan;
	dbuf_write_at(adata->unc_pixels, dstpos, wordbuf, 2);
	d->ypos++;
	if(d->ypos >= 200) {
		d->ypos = 0;
		d->stripe++;
		if(d->stripe >= d->numstripes) {
			d->stripe = 0;
			d->scan++;
			if(d->scan >= d->numscans) {
				d->scan = 0;
				d->column++;
				if(d->column >= 4) {
					d->stopflag = 1;
					return;
				}
			}
		}
	}
}

// Uncompress to adata->unc_pixels.
static int tiny_uncompress(deark *c, tinyctx *d, struct atari_img_decode_data *adata, i64 pos)
{
	u8 *control_bytes = NULL;
	i64 k;
	i64 count;
	i64 cpos;
	u8 ctrl;
	u8 wordbuf[2];

	if(adata->bpp==1) {
		d->numscans = 2;
		d->numstripes = 10;
		d->dst_rowspan = 80;
	}
	else {
		d->numscans = 1;
		d->numstripes = 20;
		d->dst_rowspan = 160;
	}

	de_dbg(c, "RLE control bytes at %d", (int)pos);
	control_bytes = de_malloc(c, d->num_control_bytes +2);
	de_read(control_bytes, pos, d->num_control_bytes);
	pos += d->num_control_bytes;

	de_dbg(c, "RLE data words at %d", (int)pos);

	cpos = 0;

	d->stopflag = 0;
	d->scan = 0;
	d->ypos = 0;
	d->column = 0;
	d->stripe = 0;
	d->dcmpr_word_count = 0;

	while(1) {
		if(d->stopflag) break;
		if(cpos >= d->num_control_bytes) break;
		ctrl = control_bytes[cpos++];

		if(ctrl >= 128) { // Uncompressed run, count encoded in control byte
			count = 256 - (i64)ctrl;
			for(k=0; k<count; k++) {
				dbuf_read(c->infile, wordbuf, pos, 2);
				pos += 2;
				tiny_setword(c, d, adata, wordbuf);
			}
		}
		else if(ctrl == 0) { // RLE, 16-bit count in next 2 control bytes
			count = de_getu16be_direct(&control_bytes[cpos]);
			cpos += 2;
			dbuf_read(c->infile, wordbuf, pos, 2);
			pos += 2;
			for(k=0; k<count; k++) {
				tiny_setword(c, d, adata, wordbuf);
			}
		}
		else if(ctrl == 1) { // Uncompressed run, 16-bit count in next 2 control bytes
			count = de_getu16be_direct(&control_bytes[cpos]);
			cpos += 2;

			for(k=0; k<count; k++) {
				dbuf_read(c->infile, wordbuf, pos, 2);
				pos += 2;
				tiny_setword(c, d, adata, wordbuf);
			}
		}
		else { // RLE, count encoded in control byte
			count = (i64)ctrl;
			dbuf_read(c->infile, wordbuf, pos, 2);
			pos += 2;
			for(k=0; k<count; k++) {
				tiny_setword(c, d, adata, wordbuf);
			}
		}
	}

	de_dbg(c, "decompressed words: %d", (int)d->dcmpr_word_count);
	if(d->dcmpr_word_count<16000) {
		de_warn(c, "Expected 16000 decompressed words, got %d", (int)d->dcmpr_word_count);
	}

	de_free(c, control_bytes);
	return 1;
}

static void do_tinystuff_1bpp(deark *c, tinyctx *d, struct atari_img_decode_data *adata)
{
	de_convert_image_paletted(adata->unc_pixels, 0, 1, d->dst_rowspan, adata->pal,
		adata->img, 0);
}

static void do_tinystuff_2or4bpp(deark *c, tinyctx *d, struct atari_img_decode_data *adata)
{
	i64 x, y;
	i64 pos = 0;
	i64 width;
	UI bpp;

	bpp = (UI)adata->bpp;
	if(bpp!=2 && bpp!=4) return;

	if(bpp==2) width = 640;
	else width = 320;

	for(y=0; y<200; y++) {
		for(x=0; x<width; x+=16) {
			UI n[4];
			UI b_idx;
			UI k;

			// 2bpp: Every 2 words (4 bytes; 32 bits) makes 16 pixels
			// 4bpp: Every 4 words (8 bytes; 64 bits) makes 16 pixels
			for(b_idx=0; b_idx<bpp; b_idx++) {
				n[b_idx] = (UI)dbuf_getu16be_p(adata->unc_pixels, &pos);
			}

			for(k=0; k<16; k++) {
				UI v = 0;

				for(b_idx=0; b_idx<bpp; b_idx++) {
					if(n[b_idx]&(1U<<(15-k))) v += (1U<<b_idx);
				}
				de_bitmap_setpixel_rgb(adata->img, x+(i64)k, y, adata->pal[v]);
			}
		}
	}
}

static void do_tinystuff_image(deark *c, tinyctx *d, struct atari_img_decode_data *adata)
{
	switch(adata->bpp) {
	case 1:
		do_tinystuff_1bpp(c, d, adata);
		break;
	case 2:
	case 4:
		do_tinystuff_2or4bpp(c, d, adata);
		break;
	}
}

// Some 1bpp images apparently have the palette set to [001, 000],
// or other nonsense, instead of [777, 000].
// Try to handle that.
static void fix_dark_pal(deark *c, struct atari_img_decode_data *adata)
{
	u32 ap[2];

	if(adata->bpp!=1) return;

	ap[0] = adata->pal[0]&0xffffff;
	ap[1] = adata->pal[1]&0xffffff;

	// Always respect white/black and black/white palettes.
	if(ap[0]==0xffffff && ap[1]==0x000000) return; // The usual palette
	if(ap[0]==0x000000 && ap[1]==0xffffff) return;

	// Otherwise assume white/black, unless the user told us not to.
	if(de_get_ext_option(c, "atari:respectpal")) return;

	adata->pal[0] = DE_STOCKCOLOR_WHITE;
	adata->pal[1] = DE_STOCKCOLOR_BLACK;
}

static void de_run_tinystuff(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	tinyctx *d = NULL;
	i64 pos = 0;
	i64 expected_min_file_size;
	i64 expected_max_file_size;
	int is_grayscale;

	d = de_malloc(c, sizeof(tinyctx));

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->pal = d->pal;
	adata->was_compressed = 1;

	d->res_code = de_getbyte(pos);
	pos++;
	de_dbg(c, "resolution code: %d", (int)d->res_code);

	switch(d->res_code) {
	case 0: case 3:
		adata->bpp = 4;
		adata->w = 320;
		adata->h = 200;
		break;
	case 1: case 4:
		adata->bpp = 2;
		adata->w = 640;
		adata->h = 200;
		break;
	case 2: case 5:
		adata->bpp = 1;
		adata->w = 640;
		adata->h = 400;
		break;
	default:
		de_err(c, "Invalid resolution code (%d). This is not a Tiny Stuff file.",
			(int)d->res_code);
		goto done;
	}

	adata->ncolors = de_pow2(adata->bpp);

	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d, colors: %d", (int)adata->w, (int)adata->h, (int)adata->ncolors);

	if(d->res_code>=3) {
		de_warn(c, "This image uses palette cycling animation, which is not supported.");
		pos += 4; // skip animation_info
	}

	de_fmtutil_read_atari_palette(c, c->infile, pos, adata->pal, 16, adata->ncolors, 0);
	fix_dark_pal(c, adata);
	pos += 16*2;

	d->num_control_bytes = de_getu16be(pos);
	pos += 2;
	de_dbg(c, "number of RLE control bytes: %d", (int)d->num_control_bytes);

	d->num_data_words = de_getu16be(pos);
	pos += 2;
	de_dbg(c, "number of RLE data words: %d (%d bytes)", (int)d->num_data_words,
		2*(int)(d->num_data_words));

	// It seems that files are often padded to the next multiple of 128 bytes,
	// so don't warn about that.
	expected_min_file_size = pos + d->num_control_bytes + 2*d->num_data_words;
	expected_max_file_size = ((expected_min_file_size+127)/128)*128;
	de_dbg(c, "expected file size: %d or %d", (int)expected_min_file_size, (int)expected_max_file_size);
	if(c->infile->len<expected_min_file_size || c->infile->len>expected_max_file_size) {
		de_warn(c, "Expected file size to be %d, but it is %d.", (int)expected_min_file_size,
			(int)c->infile->len);
	}

	adata->unc_pixels = dbuf_create_membuf(c, 32000, 1);

	if(!tiny_uncompress(c, d, adata, pos)) {
		goto done;
	}

	is_grayscale = de_is_grayscale_palette(adata->pal, adata->ncolors);

	adata->img = de_bitmap_create(c, adata->w, adata->h, is_grayscale?1:3);

	fi = de_finfo_create(c);
	de_fmtutil_atari_set_standard_density(c, adata, fi);

	do_tinystuff_image(c, d, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

done:
	if(adata) {
		de_bitmap_destroy(adata->img);
		dbuf_close(adata->unc_pixels);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
	de_free(c, d);
}

static int de_identify_tinystuff(deark *c)
{
	// TODO: Can we identify these files?
	if(de_getbyte(0)>0x05) return 0;
	if(de_input_file_has_ext(c, "tny") ||
		de_input_file_has_ext(c, "tn1") ||
		de_input_file_has_ext(c, "tn2") ||
		de_input_file_has_ext(c, "tn3") ||
		de_input_file_has_ext(c, "tn4"))
	{
		return 8;
	}
	return 0;
}

static void de_help_tinystuff(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
	help_respectpal(c);
}

void de_module_tinystuff(deark *c, struct deark_module_info *mi)
{
	mi->id = "tinystuff";
	mi->desc = "Atari Tiny Stuff, a.k.a. Tiny image format";
	mi->run_fn = de_run_tinystuff;
	mi->identify_fn = de_identify_tinystuff;
	mi->help_fn = de_help_tinystuff;
}

// **************************************************************************
// Doodle (.doo)
// **************************************************************************

static void de_run_doodle(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	u32 pal[2];

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->pal = pal;
	adata->bpp = 1;

	adata->w = 640;
	adata->h = 400;
	adata->ncolors = 2;
	adata->pal[0] = DE_STOCKCOLOR_WHITE;
	adata->pal[1] = DE_STOCKCOLOR_BLACK;

	adata->unc_pixels = c->infile;
	adata->img = de_bitmap_create(c, adata->w, adata->h, 1);
	fi = de_finfo_create(c);
	de_fmtutil_atari_set_standard_density(c, adata, fi);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

	if(adata) {
		de_bitmap_destroy(adata->img);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
}

static int de_identify_doodle(deark *c)
{
	if(c->infile->len!=32000) return 0;
	if(de_input_file_has_ext(c, "doo")) {
		return 10;
	}
	return 0;
}

void de_module_doodle(deark *c, struct deark_module_info *mi)
{
	mi->id = "doodle";
	mi->desc = "Atari Doodle";
	mi->run_fn = de_run_doodle;
	mi->identify_fn = de_identify_doodle;
}

// **************************************************************************
// NEOchrome (.neo)
// **************************************************************************

static void de_run_neochrome(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	unsigned int resolution_code;
	int is_grayscale;
	u32 pal[16];

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->pal = pal;

	resolution_code = (unsigned int)de_getu16be(2);
	de_dbg(c, "resolution code: %u", resolution_code);
	if(resolution_code!=0) {
		de_err(c, "Invalid or unsupported NEOchrome image (resolution=%d)", (int)resolution_code);
		goto done;
	}

	// TODO: Warn about palette animation settings.
	// TODO: (Maybe) Use the embedded filename, if it seems valid.

	adata->bpp = 4;
	adata->w = 320;
	adata->h = 200;
	adata->ncolors = de_pow2(adata->bpp);
	de_dbg(c, "dimensions: %d"DE_CHAR_TIMES"%d, colors: %d", (int)adata->w, (int)adata->h, (int)adata->ncolors);

	de_fmtutil_read_atari_palette(c, c->infile, 4, adata->pal, 16, adata->ncolors, 0);
	adata->unc_pixels = dbuf_open_input_subfile(c->infile, 128, 32000);
	is_grayscale = de_is_grayscale_palette(adata->pal, adata->ncolors);
	adata->img = de_bitmap_create(c, adata->w, adata->h, is_grayscale?1:3);
	fi = de_finfo_create(c);
	de_fmtutil_atari_set_standard_density(c, adata, fi);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

done:
	if(adata) {
		dbuf_close(adata->unc_pixels);
		de_bitmap_destroy(adata->img);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
}

static int de_identify_neochrome(deark *c)
{
	if(de_input_file_has_ext(c, "neo")) {
		if(c->infile->len == 32128) {
			return 100;
		}
		else if(c->infile->len > 32128) {
			return 10;
		}
	}
	return 0;
}

static void de_help_neochrome(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
}

void de_module_neochrome(deark *c, struct deark_module_info *mi)
{
	mi->id = "neochrome";
	mi->desc = "Atari NEOchrome image";
	mi->run_fn = de_run_neochrome;
	mi->identify_fn = de_identify_neochrome;
	mi->help_fn = de_help_neochrome;
}

// **************************************************************************
// NEOchrome animation (.ani)
// **************************************************************************

static void de_run_neochrome_ani(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	i64 width_in_bytes;
	i64 nframes;
	i64 bytes_per_frame;
	i64 frame;
	i64 k;
	u32 pal[16];

	de_declare_fmt(c, "NEOchrome Animation");

	de_warn(c, "NEOchrome Animation images may not be decoded correctly.");

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));

	// TODO: What palette should we use?
	for(k=0; k<16; k++) {
		pal[k] = DE_MAKE_GRAY((unsigned int)(k*17));
	}
	adata->pal = pal;
	adata->bpp = 4;
	adata->ncolors = 16;

	width_in_bytes = de_getu16be(4); // Always a multiple of 8
	adata->w = ((width_in_bytes+7)/8)*16;
	adata->h = de_getu16be(6);
	de_dbg_dimensions(c, adata->w, adata->h);
	if(!de_good_image_dimensions(c, adata->w, adata->h)) goto done;

	bytes_per_frame = de_getu16be(8);
	bytes_per_frame -= 10;
	de_dbg(c, "bytes/frame: %d", (int)bytes_per_frame);
	if(bytes_per_frame<1) goto done;

	nframes = de_getu16be(14);
	de_dbg(c, "number of frames: %d", (int)nframes);
	if(!de_good_image_count(c, nframes)) goto done;

	for(frame=0; frame<nframes; frame++) {
		adata->unc_pixels = dbuf_open_input_subfile(c->infile, 22 + frame*bytes_per_frame, bytes_per_frame);
		adata->img = de_bitmap_create(c, adata->w, adata->h, 3);

		de_fmtutil_atari_decode_image(c, adata);
		de_bitmap_write_to_file(adata->img, NULL, 0);

		de_bitmap_destroy(adata->img);
		adata->img = NULL;

		dbuf_close(adata->unc_pixels);
		adata->unc_pixels = NULL;
	}

done:
	de_free(c, adata);
}

static int de_identify_neochrome_ani(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xba\xbe\xeb\xea", 4)) {
		return 100;
	}
	return 0;
}

void de_module_neochrome_ani(deark *c, struct deark_module_info *mi)
{
	mi->id = "neochrome_ani";
	mi->desc = "NEOchrome Animation";
	mi->run_fn = de_run_neochrome_ani;
	mi->identify_fn = de_identify_neochrome_ani;
	mi->flags |= DE_MODFLAG_NONWORKING;
}

// **************************************************************************
// Animatic Film (.flm)
// **************************************************************************

static void de_run_animatic(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	i64 nframes;
	i64 frame;
	i64 planespan, rowspan, framespan;
	i64 frame_bitmap_pos;
	u32 pal[16];

	de_declare_fmt(c, "Animatic Film");

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));

	nframes = de_getu16be(0);
	de_dbg(c, "number of frames: %d", (int)nframes);
	if(!de_good_image_count(c, nframes)) goto done;

	adata->bpp = 4;
	adata->ncolors = 16;
	adata->pal = pal;
	de_dbg_indent(c, 1);
	de_fmtutil_read_atari_palette(c, c->infile, 2, adata->pal, 16, adata->ncolors, 0);
	de_dbg_indent(c, -1);

	adata->w = de_getu16be(40);
	adata->h = de_getu16be(42);
	de_dbg_dimensions(c, adata->w, adata->h);
	if(!de_good_image_dimensions(c, adata->w, adata->h)) goto done;

	planespan = 2*((adata->w+15)/16);
	rowspan = planespan*adata->bpp;
	framespan = rowspan*adata->h;

	for(frame=0; frame<nframes; frame++) {
		frame_bitmap_pos = 64 + frame*framespan;
		de_dbg(c, "frame %d bitmap at %d", (int)frame, (int)frame_bitmap_pos);

		adata->unc_pixels = dbuf_open_input_subfile(c->infile, frame_bitmap_pos, framespan);
		adata->img = de_bitmap_create(c, adata->w, adata->h, 3);

		de_fmtutil_atari_decode_image(c, adata);
		de_bitmap_write_to_file(adata->img, NULL, 0);

		de_bitmap_destroy(adata->img);
		adata->img = NULL;

		dbuf_close(adata->unc_pixels);
		adata->unc_pixels = NULL;
	}

done:
	de_free(c, adata);
}

static int de_identify_animatic(deark *c)
{
	if(!dbuf_memcmp(c->infile, 48, "\x27\x18\x28\x18", 4)) {
		return 100;
	}
	return 0;
}

static void de_help_animatic(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
}

void de_module_animatic(deark *c, struct deark_module_info *mi)
{
	mi->id = "animatic";
	mi->desc = "Animatic Film";
	mi->run_fn = de_run_animatic;
	mi->identify_fn = de_identify_animatic;
	mi->help_fn = de_help_animatic;
}

// **************************************************************************
// Atari .PI4/.PI9
// **************************************************************************

static void decode_falcon_8bit_image(deark *c, struct atari_img_decode_data *adata, i64 pos)
{
	i64 i, j, k;
	unsigned int v;
	unsigned int n;
	de_finfo *fi = NULL;

	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);

	fi = de_finfo_create(c);
	if(adata->w==320 && adata->h==200) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 240.0;
		fi->density.ydens = 200.0;
	}

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = 0;
			for(k=0; k<8; k++) {
				n = (u32)de_getu16be(pos+j*adata->w + (i-i%16) +2*k);
				if(n&(1<<(15-i%16))) v |= 1<<k;
			}
			de_bitmap_setpixel_rgb(adata->img, i, j, adata->pal[v]);
		}
	}

	de_bitmap_write_to_file_finfo(adata->img, fi, 0);
	de_bitmap_destroy(adata->img);
	adata->img = NULL;
	de_finfo_destroy(c, fi);
}

static void do_atari_falcon_8bit_img(deark *c, i64 width, i64 height)
{
	struct atari_img_decode_data *adata = NULL;
	i64 k;
	u8 cr, cg, cb;
	u32 pal[256];

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	de_zeromem(pal, sizeof(pal));
	adata->pal = pal;
	adata->bpp = 8;
	adata->ncolors = 256;
	adata->w = width;
	adata->h = height;
	de_dbg_dimensions(c, adata->w, adata->h);

	for(k=0; k<256; k++) {
		cr = de_getbyte(k*4+0);
		cg = de_getbyte(k*4+1);
		cb = de_getbyte(k*4+3);
		pal[k] = DE_MAKE_RGB(cr, cg, cb);
		de_dbg_pal_entry(c, k, pal[k]);
	}

	decode_falcon_8bit_image(c, adata, 1024);

	de_free(c, adata);
}

static void de_run_fpaint_pi4(deark *c, de_module_params *mparams)
{
	do_atari_falcon_8bit_img(c, 320, 240);
}

// Atari falcon 320x240
static int de_identify_fpaint_pi4(deark *c)
{
	if(c->infile->len==77824) {
		if(de_input_file_has_ext(c, "pi4") ||
			de_input_file_has_ext(c, "pi9"))
		{
			return 50; // Must be lower than fpaint_pi9
		}
	}
	return 0;
}

void de_module_fpaint_pi4(deark *c, struct deark_module_info *mi)
{
	mi->id = "fpaint_pi4";
	mi->desc = "Atari Falcon PI4 image";
	mi->run_fn = de_run_fpaint_pi4;
	mi->identify_fn = de_identify_fpaint_pi4;
}

static void de_run_fpaint_pi9(deark *c, de_module_params *mparams)
{
	do_atari_falcon_8bit_img(c, 320, 200);
}

// Atari falcon 320x200
static int de_identify_fpaint_pi9(deark *c)
{
	int pi4_ext, pi9_ext;

	if(c->infile->len!=77824 && c->infile->len!=65024) return 0;

	pi4_ext = de_input_file_has_ext(c, "pi4");
	pi9_ext = de_input_file_has_ext(c, "pi9");
	if(!pi4_ext && !pi9_ext) return 0;

	if(c->infile->len==65024) return 60;

	// If file size is 77824, we need to distinguish between PI4 (320x240) and
	// PI9 (320x200) format.
	// Best guess is that if the last 12800 bytes are all 0, we should assume PI9.
	if(!dbuf_is_all_zeroes(c->infile, 65024, 12800)) {
		return 0; // Will be identified elsewhere as PI4.
	}

	return 60; // PI9. Must be higher than the value PI4 uses.
}

void de_module_fpaint_pi9(deark *c, struct deark_module_info *mi)
{
	mi->id = "fpaint_pi9";
	mi->desc = "Atari Falcon PI9 image";
	mi->run_fn = de_run_fpaint_pi9;
	mi->identify_fn = de_identify_fpaint_pi9;
}

// **************************************************************************
// Atari .PI7
// **************************************************************************

static void de_run_atari_pi7(deark *c, de_module_params *mparams)
{
	do_atari_falcon_8bit_img(c, 640, 480);
}

static int de_identify_atari_pi7(deark *c)
{
	if(c->infile->len==308224) {
		if(de_input_file_has_ext(c, "pi7"))
		{
			return 50;
		}
	}
	return 0;
}

void de_module_atari_pi7(deark *c, struct deark_module_info *mi)
{
	mi->id = "atari_pi7";
	mi->desc = "Atari PI7 image";
	mi->run_fn = de_run_atari_pi7;
	mi->identify_fn = de_identify_atari_pi7;
}

// **************************************************************************
// Atari Falcon XGA
// **************************************************************************

static void de_run_falcon_xga(deark *c, de_module_params *mparams)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	if(c->infile->len==153600) {
		adata->bpp = 16;
		adata->w = 320;
		adata->h = 240;
	}
	else {
		adata->bpp = 16;
		adata->w = 384;
		adata->h = 480;
	}
	de_dbg_dimensions(c, adata->w, adata->h);
	adata->unc_pixels = c->infile;
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	fi = de_finfo_create(c);
	if(adata->w==384 && adata->h == 480) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 384;
		fi->density.ydens = 640;
	}
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);
	de_bitmap_destroy(adata->img);
	de_finfo_destroy(c, fi);
	de_free(c, adata);
}

static int de_identify_falcon_xga(deark *c)
{
	if(c->infile->len==153600 || c->infile->len==368640) {
		if(de_input_file_has_ext(c, "xga"))
		{
			return 50;
		}
	}
	return 0;
}

void de_module_falcon_xga(deark *c, struct deark_module_info *mi)
{
	mi->id = "falcon_xga";
	mi->desc = "Atari Falcon XGA image";
	mi->run_fn = de_run_falcon_xga;
	mi->identify_fn = de_identify_falcon_xga;
}

// **************************************************************************
// Atari Falcon COKE (.tg1)
// **************************************************************************

static void de_run_coke(deark *c, de_module_params *mparams)
{
	i64 imgdatapos;
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = 16;
	adata->w = de_getu16be(12);
	adata->h = de_getu16be(14);
	de_dbg_dimensions(c, adata->w, adata->h);
	imgdatapos = de_getu16be(16);
	de_dbg(c, "image data pos: %d", (int)imgdatapos);

	adata->unc_pixels = dbuf_open_input_subfile(c->infile,
		imgdatapos, c->infile->len-imgdatapos);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);

	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = 288;
	fi->density.ydens = 240;

	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

	if(adata) {
		dbuf_close(adata->unc_pixels);
		de_bitmap_destroy(adata->img);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
}

static int de_identify_coke(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, (const void*)"COKE format.", 12)) {
		return 100;
	}
	return 0;
}

void de_module_coke(deark *c, struct deark_module_info *mi)
{
	mi->id = "coke";
	mi->desc = "Atari Falcon COKE image (.TG1)";
	mi->run_fn = de_run_coke;
	mi->identify_fn = de_identify_coke;
}
