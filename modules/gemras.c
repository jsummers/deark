// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM VDI Bit Image / Gem Raster

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gemraster);

typedef struct localctx_struct {
	int is_ximg;
	i64 w, h;
	i64 nplanes;
	i64 patlen;
	i64 rowspan_per_plane;
	i64 rowspan_total;
	i64 pixwidth, pixheight;
	i64 header_size_in_words;
	i64 header_size_in_bytes;
	u8 *pattern_buf;
	u32 pal[256];
} lctx;

// Caller must initialize *repeat_count.
static void uncompress_line(deark *c, lctx *d, dbuf *unc_line,
	i64 pos1, i64 rownum,
	i64 *bytes_consumed, i64 *repeat_count)
{
	i64 pos;
	u8 b0, b1;
	u8 val;
	i64 count;
	i64 k;
	i64 tmp_repeat_count;
	i64 unc_line_len_orig;

	*bytes_consumed = 0;
	pos = pos1;
	unc_line_len_orig = unc_line->len;

	while(1) {
		if(pos >= c->infile->len) break;
		if(unc_line->len - unc_line_len_orig >= d->rowspan_per_plane) break;

		b0 = de_getbyte(pos++);

		if(b0==0) { // Pattern run or scanline run
			b1 = de_getbyte(pos++);
			if(b1>0) { // pattern run
				de_read(d->pattern_buf, pos, d->patlen);
				pos += d->patlen;
				count = (i64)b1;
				for(k=0; k<count; k++) {
					dbuf_write(unc_line, d->pattern_buf, d->patlen);
				}
			}
			else { // (b1==0) scanline run
				u8 flagbyte;
				flagbyte = de_getbyte(pos);
				if(flagbyte==0xff) {
					pos++;
					tmp_repeat_count = (i64)de_getbyte(pos++);
					if(tmp_repeat_count == 0) {
						de_dbg(c, "row %d: bad repeat count", (int)rownum);
					}
					else {
						*repeat_count = tmp_repeat_count;
					}
				}
				else {
					de_dbg(c, "row %d: bad scanline run marker: 0x%02x",
						(int)rownum, (unsigned int)flagbyte);
				}
			}
		}
		else if(b0==0x80) { // "Uncompressed bit string"
			count = (i64)de_getbyte(pos++);
			dbuf_copy(c->infile, pos, count, unc_line);
			pos += count;
		}
		else { // "solid run"
			val = (b0&0x80) ? 0xff : 0x00;
			count = (i64)(b0 & 0x7f);
			dbuf_write_run(unc_line, val, count);
		}
	}

	*bytes_consumed = pos - pos1;
}

static void uncompress_pixels(deark *c, lctx *d, dbuf *unc_pixels,
	i64 pos1, i64 len)
{
	i64 bytes_consumed;
	i64 pos;
	i64 ypos;
	i64 repeat_count;
	i64 k;
	i64 plane;
	dbuf *unc_line = NULL;

	d->pattern_buf = de_malloc(c, d->patlen);
	unc_line = dbuf_create_membuf(c, d->rowspan_total, 0);

	pos = pos1;

	ypos = 0;
	while(1) {
		if(ypos >= d->h) break;

		repeat_count = 1;

		dbuf_empty(unc_line);
		for(plane=0; plane<d->nplanes; plane++) {
			uncompress_line(c, d, unc_line,
				pos, ypos, &bytes_consumed, &repeat_count);
			pos+=bytes_consumed;
			if(bytes_consumed<1) goto done1;
		}

		for(k=0; k<repeat_count; k++) {
			if(ypos >= d->h) break;
			dbuf_copy(unc_line, 0, d->rowspan_total, unc_pixels);
			ypos++;
		}
	}
done1:
	dbuf_close(unc_line);
	de_free(c, d->pattern_buf);
	d->pattern_buf = NULL;
}

static void set_density(deark *c, lctx *d, de_finfo *fi)
{
	if(d->pixwidth>0 && d->pixheight>0) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = 25400.0/(double)d->pixwidth;
		fi->density.ydens = 25400.0/(double)d->pixheight;
	}
}

static void read_paletted_image(deark *c, lctx *d, dbuf *unc_pixels, de_bitmap *img)
{
	i64 i, j, plane;
	unsigned int n;
	u8 x;

	if(d->nplanes<1 || d->nplanes>8) return;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			n = 0;
			for(plane=0; plane<d->nplanes; plane++) {
				x = de_get_bits_symbol(unc_pixels, 1, j*d->rowspan_total + plane*d->rowspan_per_plane, i);
				if(x) n |= 1<<plane;
			}

			de_bitmap_setpixel_rgb(img, i, j, d->pal[n]);
		}
	}
}

static void read_rgb_image(deark *c, lctx *d, dbuf *unc_pixels, de_bitmap *img)
{
	// Not implemented
}

// These palettes are based on Image Alchemy's interpretation of GEM raster files.
static const u32 pal3bit[8] = {
	0xffffff,0x00ffff,0xff00ff,0xffff00,0x0000ff,0x00ff00,0xff0000,0x000000
};

static const u32 pal4bit[16] = {
	0xffffff,0x00ffff,0xff00ff,0xffff00,0x0000ff,0x00ff00,0xff0000,0xc0c0c0,
	0x808080,0x008080,0x800080,0x808000,0x000080,0x008000,0x800000,0x000000
};

static int do_gem_img(deark *c, lctx *d)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	int is_color = 0;
	i64 k;

	if(d->header_size_in_words==9 && (d->nplanes==3 || d->nplanes==4)) {
		i64 x;
		x = de_getu16be(8*2);
		if(x==0) {
			is_color = 1;
		}
	}

	de_dbg(c, "image at %d", (int)d->header_size_in_bytes);

	unc_pixels = dbuf_create_membuf(c, d->rowspan_total*d->h, 0);

	uncompress_pixels(c, d, unc_pixels, d->header_size_in_bytes, c->infile->len-d->header_size_in_bytes);

	img = de_bitmap_create(c, d->w, d->h, is_color?3:1);

	fi = de_finfo_create(c);
	set_density(c, d, fi);

	if(d->nplanes==1) {
		de_convert_image_bilevel(unc_pixels, 0, d->rowspan_per_plane, img, DE_CVTF_WHITEISZERO);
	}
	else if(is_color && d->nplanes==3) {
		for(k=0; k<8; k++) {
			d->pal[k] = pal3bit[k];
		}
		read_paletted_image(c, d, unc_pixels, img);
	}
	else if(is_color && d->nplanes==4) {
		for(k=0; k<16; k++) {
			d->pal[k] = pal4bit[k];
		}
		read_paletted_image(c, d, unc_pixels, img);
	}
	else {
		de_make_grayscale_palette(d->pal, ((i64)1)<<((unsigned int)d->nplanes), 1);
		read_paletted_image(c, d, unc_pixels, img);
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);

	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	dbuf_close(unc_pixels);
	return 1;
}

static void read_palette_ximg(deark *c, lctx *d)
{
	i64 pal_entries_in_file;
	i64 pal_entries_to_read;
	i64 i;
	i64 cr1, cg1, cb1;
	u8 cr, cg, cb;
	int range_warned = 0;
	char tmps[64];

	pal_entries_in_file = (d->header_size_in_bytes-22)/3;
	if(pal_entries_in_file<1) return;
	if(d->nplanes<=8)
		pal_entries_to_read = de_pow2(d->nplanes);
	else
		pal_entries_to_read = 0;
	if(pal_entries_to_read>pal_entries_in_file)
		pal_entries_to_read = pal_entries_in_file;
	if(pal_entries_to_read>256)
		pal_entries_to_read = 256;

	if(pal_entries_in_file<1) return;

	de_dbg(c, "palette at %d", 22);
	de_dbg_indent(c, 1);
	for(i=0; i<pal_entries_to_read; i++) {
		cr1 = de_getu16be(22 + 6*i);
		cg1 = de_getu16be(22 + 6*i + 2);
		cb1 = de_getu16be(22 + 6*i + 4);

		cr = de_scale_1000_to_255(cr1);
		cg = de_scale_1000_to_255(cg1);
		cb = de_scale_1000_to_255(cb1);

		d->pal[i] = DE_MAKE_RGB(cr, cg, cb);

		de_snprintf(tmps, sizeof(tmps), "(%4d,%4d,%4d) "DE_CHAR_RIGHTARROW" ",
			(int)cr1, (int)cg1, (int)cb1);
		de_dbg_pal_entry2(c, (int)i, d->pal[i], tmps, NULL, NULL);

		// TODO: Maybe some out-of-range colors have special meaning?
		if(!range_warned && (cr1>1000 || cg1>1000 || cb1>1000)) {
			de_warn(c, "Bad palette color #%d: is (%d,%d,%d), max=(1000,1000,1000).",
				(int)i, (int)cr1, (int)cg1, (int)cb1);
			range_warned=1;
		}
	}
	de_dbg_indent(c, -1);
}

// XIMG and similar formats.
// TODO: Should this function be merged with do_gem_img()?
static int do_gem_ximg(deark *c, lctx *d)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "header (continued) at %d", 8*2);
	de_dbg_indent(c, 1);

	if((d->nplanes>=1 && d->nplanes<=8) /* || d->nplanes==24 */) {
		;
	}
	else {
		if(d->is_ximg)
			de_err(c, "%d-plane XIMG images are not supported", (int)d->nplanes);
		else
			de_err(c, "This type of %d-plane image is not supported", (int)d->nplanes);
		goto done;
	}

	if(d->header_size_in_words==25 && !d->is_ximg) {
		i64 pal_pos = d->header_size_in_bytes-32;
		de_dbg(c, "palette at %d", (int)pal_pos);
		de_dbg_indent(c, 1);
		de_fmtutil_read_atari_palette(c, c->infile, pal_pos,
			d->pal, 16, ((i64)1)<<d->nplanes, 0);
		de_dbg_indent(c, -1);
	}
	else {
		read_palette_ximg(c, d);
	}

	if(d->nplanes==1 && d->pal[0]==d->pal[1]) {
		de_dbg(c, "Palette doesn't seem to be present. Using a default palette.");
		d->pal[0] = DE_STOCKCOLOR_WHITE;
		d->pal[1] = DE_STOCKCOLOR_BLACK;
	}

	de_dbg_indent(c, -1);

	de_dbg(c, "image at %d", (int)d->header_size_in_bytes);

	unc_pixels = dbuf_create_membuf(c, d->rowspan_total*d->h, 0);
	uncompress_pixels(c, d, unc_pixels, d->header_size_in_bytes, c->infile->len-d->header_size_in_bytes);

	img = de_bitmap_create(c, d->w, d->h, 3);

	fi = de_finfo_create(c);
	set_density(c, d, fi);

	if(d->nplanes>8) {
		read_rgb_image(c, d, unc_pixels, img);
	}
	else {
		read_paletted_image(c, d, unc_pixels, img);
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);

	retval = 1;

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_gemraster(deark *c, de_module_params *mparams)
{
	i64 ver;
	i64 ext_word0 = 0;
	lctx *d = NULL;
	int need_format_warning = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "header (base part) at %d", 0);
	de_dbg_indent(c, 1);
	ver = de_getu16be(0);
	de_dbg(c, "version: %d", (int)ver);
	d->header_size_in_words = de_getu16be(2);
	d->header_size_in_bytes = d->header_size_in_words*2;
	de_dbg(c, "header size: %d words (%d bytes)", (int)d->header_size_in_words,
		(int)d->header_size_in_bytes);
	d->nplanes = de_getu16be(4);
	de_dbg(c, "planes: %d", (int)d->nplanes);

	if(d->header_size_in_words>=11) {
		d->is_ximg = !dbuf_memcmp(c->infile, 16, "XIMG", 4);
	}

	d->patlen = de_getu16be(6);
	de_dbg(c, "pattern def len: %d", (int)d->patlen);
	d->pixwidth = de_getu16be(8);
	d->pixheight = de_getu16be(10);
	de_dbg(c, "pixel size: %d"DE_CHAR_TIMES"%d microns", (int)d->pixwidth, (int)d->pixheight);
	d->w = de_getu16be(12);
	d->h = de_getu16be(14);
	de_dbg_dimensions(c, d->w, d->h);
	de_dbg_indent(c, -1);

	if(d->header_size_in_words>=9) {
		// This may help to detect the image format.
		ext_word0 = de_getu16be(16);
	}

	if(ver>2) {
		de_err(c, "This version of GEM Raster (%d) is not supported.", (int)ver);
		goto done;
	}

	if(d->is_ximg) {
		de_declare_fmt(c, "GEM VDI Bit Image, XIMG extension");
	}
	else if(d->header_size_in_words==25 && d->patlen==2 && ext_word0==0x0080) {
		de_declare_fmt(c, "GEM VDI Bit Image, Hyperpaint extension");
	}
	else if(d->header_size_in_words==8 && d->nplanes==1) {
		;
	}
	else if(d->header_size_in_words==8 && (d->nplanes>=2 && d->nplanes<=8)) {
		need_format_warning = 1;
	}
	else if(d->header_size_in_words==9 && (d->nplanes>=1 && d->nplanes<=8)) {
		need_format_warning = 1;
	}
	else {
		if(d->header_size_in_words==27 && ext_word0==0x5354) {
			de_declare_fmt(c, "GEM VDI Bit Image, STTT extension");
		}
		de_err(c, "This version of GEM Raster is not supported.");
		goto done;
	}

	if(need_format_warning) {
		de_warn(c, "This type of GEM Raster image is not very portable, and might "
			"not be handled correctly.");
	}

	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	d->rowspan_per_plane = (d->w+7)/8;
	d->rowspan_total = d->rowspan_per_plane * d->nplanes;

	// If we haven't declared the format yet, do so.
	de_declare_fmt(c, "GEM VDI Bit Image");

	if(d->is_ximg) {
		do_gem_ximg(c, d);
	}
	else if(d->header_size_in_words==25) {
		do_gem_ximg(c, d);
	}
	else {
		do_gem_img(c, d);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, d);
}

static int de_identify_gemraster(deark *c)
{
	i64 ver, x2;
	i64 nplanes;

	if(!de_input_file_has_ext(c, "img") &&
		!de_input_file_has_ext(c, "ximg"))
	{
		return 0;
	}
	ver = de_getu16be(0);
	if(ver!=1 && ver!=2 && ver!=3) return 0;
	x2 = de_getu16be(2);
	if(x2<0x0008 || x2>0x0800) return 0;
	nplanes = de_getu16be(4);
	if(!(nplanes>=1 && nplanes<=8) && nplanes!=15 && nplanes!=16 && nplanes!=24 &&
		nplanes!=32)
	{
		return 0;
	}
	if(ver==1 && x2==0x08) return 70;
	if(!dbuf_memcmp(c->infile, 16, "XIMG", 4)) {
		return 100;
	}
	return 10;
}

static void de_help_gemraster(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
}

void de_module_gemraster(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemraster";
	mi->desc = "GEM VDI Bit Image, a.k.a. GEM Raster";
	mi->run_fn = de_run_gemraster;
	mi->identify_fn = de_identify_gemraster;
	mi->help_fn = de_help_gemraster;
}
