// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM VDI Bit Image / Gem Raster

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gemraster);

#define CODE_STTT 0x53545454U
#define CODE_TIMG 0x54494d47U
#define CODE_XIMG 0x58494d47U

typedef struct localctx_struct {
	u8 errflag;
	u8 is_ximg;
	i64 npwidth, h;
	i64 pdwidth;
	i64 nplanes;
	i64 patlen;
	i64 rowspan_per_plane;
	i64 rowspan_total;
	i64 pixwidth, pixheight;
	double dens_x, dens_y;
	i64 header_size_in_words;
	i64 header_size_in_bytes;
	de_color pal[256];
} lctx;

struct decompr_ctx {
	i64 curpos; // Position in the input file. Maintained by the decompressor.
	i64 rownum;
	i64 plane;
	dbuf *unc_line;
	u8 *pattern_buf; // size = d->patlen
	i64 repeat_count; // Set/updated when plane=0.
};

// Caller maintains dctx->rownum, dctx->plane, etc.
// Decompressed data is appended to dctx->unc_line.
static void decompress_plane_row(deark *c, lctx *d, struct decompr_ctx *dctx)
{
	i64 pos1 = dctx->curpos;
	u8 val;
	i64 count;
	i64 k;
	i64 unc_line_endpos;

	unc_line_endpos = dctx->unc_line->len + d->rowspan_per_plane;
	if(dctx->plane==0) {
		// By default, an encoded scanline is rendered once. This may be overridden by a
		// scanline run opcode.
		dctx->repeat_count = 1;
	}
	de_dbg3(c, "[row %u plane %u at %"I64_FMT"]", (UI)dctx->rownum, (UI)dctx->plane, pos1);

	while(1) {
		u8 b0, b1;
		i64 opcode_pos = dctx->curpos;

		if(dctx->curpos >= c->infile->len) break;
		if(dctx->unc_line->len >= unc_line_endpos) break;

		b0 = de_getbyte_p(&dctx->curpos);

		if(b0==0) { // Pattern run or scanline run
			b1 = de_getbyte_p(&dctx->curpos);
			if(b1>0) { // pattern run
				de_read(dctx->pattern_buf, dctx->curpos, d->patlen);
				dctx->curpos += d->patlen;
				count = (i64)b1;
				for(k=0; k<count; k++) {
					dbuf_write(dctx->unc_line, dctx->pattern_buf, d->patlen);
				}
			}
			else { // (b1==0) scanline run
				u8 flagbyte;

				flagbyte = de_getbyte_p(&dctx->curpos);
				if(flagbyte!=0xff) {
					de_err(c, "row %u: Invalid 00 00 opcode at %"I64_FMT, (UI)dctx->rownum,
						opcode_pos);
					d->errflag = 1;
					goto done;
				}

				// Note that the 'repeat scanline' opcode appears *before* the
				// scanline (row) to be repeated.
				// We're assuming it is only allowed at the very start of a row.
				// The count seems to the total number of times the row is
				// rendered, so the minimum useful count is 2, and we don't allow
				// a count of 0.
				if(dctx->plane!=0 || opcode_pos!=pos1) {
					de_err(c, "row %u plane %u: Invalid scanline run at %"I64_FMT, (UI)dctx->rownum,
						(UI)dctx->plane, opcode_pos);
					d->errflag = 1;
					goto done;
				}

				dctx->repeat_count = (i64)de_getbyte_p(&dctx->curpos);
				de_dbg3(c, "scanline run row=%u plane=%u pos=%"I64_FMT" count=%u", (UI)dctx->rownum,
					(UI)dctx->plane, opcode_pos, (UI)dctx->repeat_count);
				if(dctx->repeat_count == 0) {
					de_err(c, "row %u: Bad scanline run count", (UI)dctx->rownum);
					d->errflag = 1;
					goto done;
				}
			}
		}
		else if(b0==0x80) { // "Uncompressed bit string"
			count = (i64)de_getbyte_p(&dctx->curpos);
			dbuf_copy(c->infile, dctx->curpos, count, dctx->unc_line);
			dctx->curpos += count;
		}
		else { // "solid run"
			val = (b0&0x80) ? 0xff : 0x00;
			count = (i64)(b0 & 0x7f);
			dbuf_write_run(dctx->unc_line, val, count);
		}
	}

done:
	;
}

static void decompress_pixels(deark *c, lctx *d, dbuf *unc_pixels,
	i64 pos1, i64 len)
{
	i64 k;
	i64 plane;
	struct decompr_ctx *dctx = NULL;

	dctx = de_malloc(c, sizeof(struct decompr_ctx));
	dctx->pattern_buf = de_malloc(c, d->patlen);
	dctx->unc_line = dbuf_create_membuf(c, d->rowspan_total, 0);
	dctx->curpos = pos1;

	dctx->rownum = 0;
	while(1) {
		i64 expected_len;

		if(dctx->rownum >= d->h) break;

		dctx->repeat_count = 0;
		dbuf_empty(dctx->unc_line);
		for(plane=0; plane<d->nplanes; plane++) {
			i64 prev_ipos = dctx->curpos;
			i64 prev_opos = dctx->unc_line->len;

			if(dctx->curpos >= c->infile->len) goto done;
			dctx->plane = plane;
			decompress_plane_row(c, d, dctx);
			if(d->errflag) goto done;
			if(dctx->curpos<=prev_ipos) goto done;

			expected_len = (plane+1)*d->rowspan_per_plane;
			if(dctx->unc_line->len != expected_len) {
				i64 obytes_this_time;

				obytes_this_time = dctx->unc_line->len - prev_opos;

				// Tolerate a few extra bytes, but if there are a lot, treat it
				// as a fatal error.
				if(obytes_this_time > d->rowspan_per_plane+4) {
					de_err(c, "[row %u plane %u] Expected %"I64_FMT" bytes, "
						"got %"I64_FMT". This file might use an unsupported "
						"GEM Raster variant.",
						(UI)dctx->rownum, (UI)plane,
						d->rowspan_per_plane, obytes_this_time);
					d->errflag = 1;
					goto done;
				}

				de_dbg(c, "[row %u plane %u] expected %"I64_FMT" bytes, "
					"got %"I64_FMT, (UI)dctx->rownum, (UI)plane,
					d->rowspan_per_plane, obytes_this_time);

				dbuf_truncate(dctx->unc_line, expected_len);
			}
		}

		for(k=0; k<dctx->repeat_count; k++) {
			if(dctx->rownum >= d->h) break;
			dbuf_copy(dctx->unc_line, 0, d->rowspan_total, unc_pixels);
			dctx->rownum++;
		}
	}

done:
	if(dctx) {
		dbuf_close(dctx->unc_line);
		de_free(c, dctx->pattern_buf);
		de_free(c, dctx);
	}
}

static double microns_to_dpi(i64 x)
{
	if(x>0)
		return 25400.0/(double)x;
	return 0;
}

static void set_density(deark *c, lctx *d, de_finfo *fi)
{
	if(d->pixwidth>1 && d->pixheight>1) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = d->dens_x;
		fi->density.ydens = d->dens_y;
	}
}

static void read_paletted_image(deark *c, lctx *d, dbuf *unc_pixels, de_bitmap *img)
{
	if(d->nplanes<1 || d->nplanes>8) return;

	de_convert_image_paletted_planar(unc_pixels, 0, d->nplanes, d->rowspan_total,
		d->rowspan_per_plane, d->pal, img, 0x2);
}

static void read_rgb_image(deark *c, lctx *d, dbuf *unc_pixels, de_bitmap *img)
{
	// Not implemented
}

// These palettes are based on Image Alchemy's interpretation of GEM raster files.
static const de_color pal3bit[8] = {
	0xffffff,0x00ffff,0xff00ff,0xffff00,0x0000ff,0x00ff00,0xff0000,0x000000
};
#if 0
static const de_color pal4bit[16] = {
	0xffffff,0x00ffff,0xff00ff,0xffff00,0x0000ff,0x00ff00,0xff0000,0xc0c0c0,
	0x808080,0x008080,0x800080,0x808000,0x000080,0x008000,0x800000,0x000000
};
#else
// This palette is from the Encyclopedia of Graphics File Formats.
static const de_color pal4bit[16] = {
	0xffffffffU,0xffff0000U,0xff00ff00U,0xffffff00U,
	0xff0000ffU,0xffff00ffU,0xff00ffffU,0xffaeaeaeU,
	0xff555555U,0xffae0000U,0xff00ae00U,0xffaeae00U,
	0xff0000aeU,0xffae00aeU,0xff00aeaeU,0xff000000U
};
#endif

static void do_gem_img(deark *c, lctx *d)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	int is_color = 0;
	UI createflags = 0;
	i64 k;

	if(d->header_size_in_words==9 && (d->nplanes==3 || d->nplanes==4)) {
		i64 x;
		x = de_getu16be(8*2);
		if(x==0) {
			is_color = 1;
		}
	}

	de_dbg(c, "image at %"I64_FMT, d->header_size_in_bytes);

	unc_pixels = dbuf_create_membuf(c, d->rowspan_total*d->h, 0);

	decompress_pixels(c, d, unc_pixels, d->header_size_in_bytes, c->infile->len-d->header_size_in_bytes);
	if(d->errflag) goto done;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->h, is_color?3:1);

	fi = de_finfo_create(c);
	set_density(c, d, fi);

	if(d->nplanes==1) {
		de_convert_image_bilevel(unc_pixels, 0, d->rowspan_per_plane, img, DE_CVTF_WHITEISZERO);
		createflags |= DE_CREATEFLAG_IS_BWIMG;
	}
	else if(is_color && d->nplanes==3) {
		de_dbg(c, "[using default 8-color palette]");
		for(k=0; k<8; k++) {
			d->pal[k] = pal3bit[k];
		}
		read_paletted_image(c, d, unc_pixels, img);
	}
	else if(is_color && d->nplanes==4) {
		de_dbg(c, "[using default 16-color palette]");
		for(k=0; k<16; k++) {
			d->pal[k] = pal4bit[k];
		}
		read_paletted_image(c, d, unc_pixels, img);
	}
	else {
		de_make_grayscale_palette(d->pal, ((i64)1)<<((UI)d->nplanes), 1);
		read_paletted_image(c, d, unc_pixels, img);
	}

	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE | createflags);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	dbuf_close(unc_pixels);
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
		fmtutil_read_atari_palette(c, c->infile, pal_pos,
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

	de_dbg(c, "image at %"I64_FMT, d->header_size_in_bytes);

	unc_pixels = dbuf_create_membuf(c, d->rowspan_total*d->h, 0);
	decompress_pixels(c, d, unc_pixels, d->header_size_in_bytes, c->infile->len-d->header_size_in_bytes);
	if(d->errflag) goto done;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->h, 3);

	fi = de_finfo_create(c);
	set_density(c, d, fi);

	if(d->nplanes>8) {
		read_rgb_image(c, d, unc_pixels, img);
	}
	else {
		read_paletted_image(c, d, unc_pixels, img);
	}

	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

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

	if(d->header_size_in_words>=10) {
		u32 sig16;

		sig16 = (UI)de_getu32be(16);
		if(sig16==CODE_XIMG) d->is_ximg = 1;
	}

	d->patlen = de_getu16be(6);
	de_dbg(c, "pattern def len: %d", (int)d->patlen);
	d->pixwidth = de_getu16be(8);
	d->pixheight = de_getu16be(10);
	d->dens_x = microns_to_dpi(d->pixwidth);
	d->dens_y = microns_to_dpi(d->pixheight);
	de_dbg(c, "pixel size: %d"DE_CHAR_TIMES"%d microns (%.1f"DE_CHAR_TIMES"%.1f dpi)",
		(int)d->pixwidth, (int)d->pixheight, d->dens_x, d->dens_y);
	d->npwidth = de_getu16be(12);
	d->pdwidth = de_pad_to_n(d->npwidth, 8);
	d->h = de_getu16be(14);
	de_dbg_dimensions(c, d->npwidth, d->h);
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

	if(d->patlen>16) {
		de_err(c, "Bad or unsupported file");
	}

	if(need_format_warning) {
		de_warn(c, "This type of GEM Raster image is not very portable, and might "
			"not be handled correctly.");
	}

	if(!de_good_image_dimensions(c, d->npwidth, d->h)) goto done;

	d->rowspan_per_plane = d->pdwidth/8;
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

struct gemras_id {
	UI ver;
	UI hdrlen;
	UI nplanes;
	UI patlen;
	UI pixwidth, pixheight;
	u32 sig16;
	int has_ext;
};

static int hdrlen_seems_ok(deark *c, struct gemras_id *id)
{
	if(id->hdrlen<8 || (i64)id->hdrlen*2>c->infile->len) {
		return 0;
	}

	if(id->hdrlen<=59) return 1;

	// Header lengths (in words) for XIMG w/ 1 to 8 bits/pixel are probably
	// 11 + 3*2^(bpp): 17, 23, 35, 59, 107, 203, 395, 779.
	switch(id->hdrlen) {
	case 107: case 203: case 395: case 779:
		return 1;
	}
	return 0;
}

static int has_sane_density(struct gemras_id *id)
{
	if(id->pixwidth==0 && id->pixheight==0) return 1;
	if(id->pixwidth==1 && id->pixheight==1) return 1;

	// Assume dpi should be at least ~20.
	if(id->pixwidth>1300 || id->pixheight>1300) return 0;

	// Assume dpi should be at most ~1200
	if(id->pixwidth<20 || id->pixheight<20) return 0;

	if(id->pixwidth*3 < id->pixheight) return 0;
	if(id->pixheight*3 < id->pixwidth) return 0;
	return 1;
}

static int de_identify_gemraster(deark *c)
{
	struct gemras_id id;
	i64 pos = 0;
	int dens_ok;

	de_zeromem(&id, sizeof(struct gemras_id));
	id.ver = (UI)de_getu16be_p(&pos);
	if(id.ver>3) return 0;
	id.hdrlen = (UI)de_getu16be_p(&pos);
	id.nplanes = (UI)de_getu16be_p(&pos);
	if((id.nplanes>=1 && id.nplanes<=8) || id.nplanes==15 ||
		id.nplanes==16 || id.nplanes==24 || id.nplanes==32)
	{
		;
	}
	else {
		return 0;
	}
	id.patlen = (UI)de_getu16be_p(&pos);
	// patlen possibly can be up to 8, but 3 is the most I've seen.
	if(id.patlen>4) return 0;
	if(!hdrlen_seems_ok(c, &id)) {
		return 0;
	}
	id.pixwidth = (UI)de_getu16be_p(&pos);
	id.pixheight = (UI)de_getu16be_p(&pos);
	// TODO: Consolidate with set_density().
	dens_ok = has_sane_density(&id);

	if(id.hdrlen>=10) {
		id.sig16 = (u32)de_getu32be(16);
	}
	id.has_ext = de_input_file_has_ext(c, "img");
	if(id.sig16==CODE_XIMG) {
		return id.has_ext?90:70;
	}

	if(dens_ok && (id.sig16==CODE_STTT || id.sig16==CODE_TIMG)) {
		return 40;
	}

	if(!dens_ok && !id.has_ext) return 0;

	// Unfortunately, some files with version=0 exist.
	// If version is >1, require a known signature.
	// TODO: False negatives apparently exist, but we need more info to
	// support them.
	if(id.ver==0) {
		if(!id.has_ext || !dens_ok) return 0;
	}
	else if(id.ver==1) {
		;
	}
	else {
		return 0;
	}

	if(id.hdrlen==8 || id.hdrlen==9 || id.hdrlen==25) {
		return id.has_ext?70:50;
	}

	if(id.has_ext) return 14;
	return 0;
}

static void de_help_gemraster(deark *c)
{
	fmtutil_atari_help_palbits(c);
}

void de_module_gemraster(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemraster";
	mi->id_alias[0] = "gemras";
	mi->desc = "GEM VDI Bit Image, a.k.a. GEM Raster";
	mi->run_fn = de_run_gemraster;
	mi->identify_fn = de_identify_gemraster;
	mi->help_fn = de_help_gemraster;
}
