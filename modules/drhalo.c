// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Dr. Halo .CUT image
// Dr. Halo .PIC image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_drhalocut);
DE_DECLARE_MODULE(de_module_drhalopic);

struct pic_modeinfo_item {
	// 0x08 = de-interlace 16k
	// 0x10 = Mode known, but not supported
	u16 board_id;
	u16 mode_id; // used if hdrlen>=12
	u16 width;
	u16 height;
	u16 nplanes;
	u16 bits_per_pixel_per_plane;
	u16 hdrlen;
	// nominal... = Number of bytes that are typically actually stored in the file.
	// Often includes padding at the end. We don't really need it to be correct,
	// so long as it's big enough for the visible part.
	u32 nominal_bytes_per_plane;
	u32 flags;
};

typedef struct localctx_struct {
	i64 w, h;
	u8 have_palfile;
	u8 opt_pal_pc16;
	u8 max_color_val;
	UI color_count;
	de_color pal[256];

	// PIC-only fields
	UI board_id;
	UI mode_id;
	i64 bytes_per_row_per_plane;
	i64 ncolors;
	i64 dcmpr_endpos;
	const struct pic_modeinfo_item *modeinfo;
	char modename[50];
} lctx;

static int do_read_header(deark *c, lctx *d)
{
	d->w = de_getu16le(0);
	d->h = de_getu16le(2);
	de_dbg_dimensions(c, d->w, d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) return 0;
	return 1;
}

static int do_decompress_scanline(deark *c, lctx *d, i64 line_idx,
	i64 pos1, i64 len, dbuf *unc_pixels)
{
	u8 b, b2;
	i64 count;
	i64 pos = pos1;
	i64 opos1 = unc_pixels->len;

	while(1) {
		if((pos-pos1) >= len) break;

		b = de_getbyte_p(&pos);

		if(b==0 || b==0x80) { // end of row
			break;
		}
		else if(b & 0x80) { // RLE block
			count = (i64)(b - 0x80);
			b2 = de_getbyte_p(&pos);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // uncompressed block
			count = (i64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}

	de_dbg3(c, "scanline[%d]: decompressed %"I64_FMT
		" bytes (expected %"I64_FMT") to %"I64_FMT" bytes",
		(int)line_idx, pos-pos1,
		len, (unc_pixels->len - opos1));
	return 1;
}

static int do_decompress(deark *c, lctx *d, i64 pos1, dbuf *unc_pixels)
{
	i64 j;
	i64 pos = pos1;

	for(j=0; j<d->h; j++) {
		i64 linebytecount;

		// Make sure we're at the right place in the uncompressed pixels.
		dbuf_truncate(unc_pixels, j*d->w);

		if(pos > c->infile->len-2) break;
		linebytecount = de_getu16le_p(&pos);
		do_decompress_scanline(c, d, j, pos, linebytecount, unc_pixels);
		pos += linebytecount;
	}

	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT" bytes",
		(pos-pos1), unc_pixels->len);

	return 1;
}

// Assumes analyze_image() has already been called.
static void do_write_image_gray(deark *c, lctx *d, dbuf *unc_pixels)
{
	de_bitmap *img = NULL;

	de_make_grayscale_palette(d->pal, (i64)d->max_color_val+1, 0);
	img = de_bitmap_create(c, d->w, d->h, 1);
	de_convert_image_paletted(unc_pixels, 0, 8, d->w, d->pal, img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void do_write_image_pal(deark *c, lctx *d, dbuf *unc_pixels)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, d->w, d->h, 3);
	de_convert_image_paletted(unc_pixels, 0, 8, d->w, d->pal, img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void analyze_image(deark *c, lctx *d, dbuf *unc_pixels)
{
	i64 k;
	u8 b;
	u8 *v_used = NULL;

	v_used = de_malloc(c, 256);
	d->max_color_val = 0;
	d->color_count = 0;
	for(k=0; k<unc_pixels->len; k++) {
		b = dbuf_getbyte(unc_pixels, k);
		if(b > d->max_color_val)
			d->max_color_val = b;
		if(v_used[(UI)b]==0) {
			v_used[(UI)b] = 1;
			d->color_count++;
		}
	}
	de_dbg(c, "detected max val: %u", (UI)d->max_color_val);
	if(d->max_color_val<1) d->max_color_val=1;
	de_dbg(c, "detected color count: %u", d->color_count);
	de_free(c, v_used);
}

static void write_cut_image(deark *c, lctx *d, dbuf *unc_pixels)
{
	if(d->have_palfile) {
		do_write_image_pal(c, d, unc_pixels);
		return;
	}

	analyze_image(c, d, unc_pixels);

	if(d->opt_pal_pc16 && d->max_color_val<16) {
		de_copy_std_palette(DE_PALID_PC16, 0, 0, d->pal, 16, 0);
		do_write_image_pal(c, d, unc_pixels);
		return;
	}

	do_write_image_gray(c, d, unc_pixels);
}

static int do_read_pal_file(deark *c, lctx *d, const char *palfn)
{
	dbuf *palfile = NULL;
	i64 pos;
	i64 sig;
	i64 filever;
	i64 datasize;
	i64 k, z;
	i64 num_entries;
	i64 maxidx;
	i64 maxsamp[3];
	UI board_id;
	UI graphics_mode;
	u8 filetype;
	u8 filesubtype;
	i64 osamp[3];
	u8 samp[3];
	int retval = 0;
	char tmps[64];

	de_dbg(c, "palette file");
	de_dbg_indent(c, 1);

	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) {
		goto done;
	}

	sig = dbuf_getu16le(palfile, 0);
	filever = dbuf_getu16le(palfile, 2);
	de_dbg(c, "file version: %d", (int)filever);
	datasize = dbuf_getu16le(palfile, 4);
	de_dbg(c, "data size: %"I64_FMT, datasize);
	filetype = dbuf_getbyte(palfile, 6);
	de_dbg(c, "file type: 0x%02x", (UI)filever);
	filesubtype = dbuf_getbyte(palfile, 7);
	de_dbg(c, "file subtype: 0x%02x", (UI)filesubtype);

	if(sig!=0x4841 /* "HA" */ || filetype!=0x0a) {
		de_err(c, "Invalid palette file");
		goto done;
	}

	board_id = (UI)dbuf_getu16le(palfile, 8);
	de_dbg(c, "board id: 0x%04x", board_id);
	graphics_mode = (UI)dbuf_getu16le(palfile, 10);
	de_dbg(c, "graphics mode: 0x%04x", graphics_mode);

	if(filesubtype!=0) {
		de_warn(c, "Hardware-specific palettes are not supported");
		retval = 1;
		goto done;
	}

	maxidx = dbuf_getu16le(palfile, 0x0c);
	de_dbg(c, "maxidx: %u", (UI)maxidx);

	for(k=0; k<3; k++) {
		maxsamp[k] = dbuf_getu16le(palfile, 0x0e + 2*k);
		de_dbg(c, "maxsamp[%d]: %u", (int)k, (UI)maxsamp[k]);
		if(maxsamp[k]<1) maxsamp[k]=1;
	}

	pos = 0x14;

	pos += 20; // Skip palette name  TODO: Display this

	num_entries = maxidx+1;
	if(num_entries>256) num_entries=256;

	for(k=0; k<num_entries; k++) {
		// If we imagine the palette file being split into 512-byte chunks, a
		// (6-byte) palette entry is not allowed to cross a chunk boundary.
		// If an entry would do so, it instead starts at the beginning of the
		// next chunk.
		if((pos%512) > 506) {
			pos = de_pad_to_n(pos, 512);
		}

		for(z=0; z<3; z++) {
			osamp[z] = dbuf_getu16le_p(palfile, &pos);
			// I think portable palette samples are always in the range 0-255,
			// regardless of the maxsamp fields.
			if(maxsamp[z]>255) {
				samp[z] = de_scale_n_to_255(maxsamp[z], osamp[z]);
			}
			else {
				samp[z] = (u8)osamp[z];
			}
		}
		d->pal[k] = DE_MAKE_RGB(samp[0], samp[1], samp[2]);

		de_snprintf(tmps, sizeof(tmps), "(%5d,%5d,%5d) "DE_CHAR_RIGHTARROW" ",
			(int)osamp[0], (int)osamp[1], (int)osamp[2]);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}

	d->have_palfile = 1;
	retval = 1;
done:
	dbuf_close(palfile);
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_drhalocut(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	dbuf *unc_pixels = NULL;
	const char *palfn;
	const char *tmps;

	d = de_malloc(c, sizeof(lctx));

	palfn = de_get_ext_option(c, "file2");
	if(palfn) {
		if(!do_read_pal_file(c, d, palfn)) goto done;
	}

	tmps = de_get_ext_option(c, "drhalocut:pal");
	if(tmps) {
		if(!de_strcmp(tmps, "pc16"))
			d->opt_pal_pc16 = 1;
	}

	pos = 0;
	if(!do_read_header(c, d)) goto done;
	pos += 6;

	unc_pixels = dbuf_create_membuf(c, d->w*d->h, 0x1);
	if(!do_decompress(c, d, pos, unc_pixels)) goto done;

	write_cut_image(c, d, unc_pixels);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_drhalocut(deark *c)
{
	i64 n;

	if(!de_input_file_has_ext(c, "cut")) return 0;
	n = de_getu16le(4);
	if(n!=0) return 0;
	n = de_getu16le(0);
	if(n<1 || n>4096) return 0;
	n = de_getu16le(2);
	if(n<1 || n>4096) return 0;
	return 10;
}

static void help_common(deark *c)
{
	de_msg(c, "-file2 <file.pal> : Read the palette from this file");
}

static void de_help_drhalocut(deark *c)
{
	help_common(c);
	de_msg(c, "-opt drhalocut:pal=pc16 : Use standard 16-color palette if possible");
}

void de_module_drhalocut(deark *c, struct deark_module_info *mi)
{
	mi->id = "drhalocut";
	mi->desc = "Dr. Halo .CUT image";
	mi->run_fn = de_run_drhalocut;
	mi->identify_fn = de_identify_drhalocut;
	mi->help_fn = de_help_drhalocut;
}

// **************************************************************************
// Dr. Halo .PIC
// **************************************************************************

// Sets d->dcmpr_endpos.
static int do_decompress_pic_plane(deark *c, lctx *d,
	i64 pos1, i64 len, dbuf *unc_pixels)
{
	u8 b, b2;
	i64 count;
	i64 pos = pos1;

	dbuf_enable_wbuffer(unc_pixels);
	while(1) {
		if((pos-pos1) >= len) break;

		b = de_getbyte_p(&pos);

		if(b==0x00) {
			pos = de_pad_to_n(pos, 512);
			break;
		}
		if(b==0x80) {
			pos = de_pad_to_n(pos, 512);
			continue;
		}

		if(b & 0x80) { // RLE block
			count = (i64)(b - 0x80);
			b2 = de_getbyte_p(&pos);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // uncompressed block
			count = (i64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}

	dbuf_disable_wbuffer(unc_pixels);
	d->dcmpr_endpos = pos;
	return 1;
}

static int do_decompress_pic(deark *c, lctx *d, dbuf *unc_pixels)
{
	i64 pn;
	i64 pos;

	pos = (i64)d->modeinfo->hdrlen;
	for(pn=0; pn<(i64)d->modeinfo->nplanes; pn++) {
		i64 old_unc_pixels_len;

		dbuf_truncate(unc_pixels, pn * (i64)d->modeinfo->nominal_bytes_per_plane);

		de_dbg(c, "plane[%u] at %"I64_FMT, (UI)pn, pos);
		de_dbg_indent(c, 1);
		old_unc_pixels_len = unc_pixels->len;
		do_decompress_pic_plane(c, d, pos, c->infile->len-pos, unc_pixels);

		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT" bytes",
			d->dcmpr_endpos - pos, unc_pixels->len - old_unc_pixels_len);
		de_dbg_indent(c, -1);

		pos = d->dcmpr_endpos;
	}

	return 1;
}

static void deinterlace_pic_16k(deark *c, lctx *d, dbuf *unc_pixels)
{
	dbuf *tmpdbuf = NULL;
	i64 i;

	tmpdbuf = dbuf_create_membuf(c, unc_pixels->len, 0);
	dbuf_copy(unc_pixels, 0, unc_pixels->len, tmpdbuf);

	dbuf_truncate(unc_pixels, 0);

	for(i=0; i<200; i++) {
		i64 spos;

		spos = (i/2)*80 + (i%2)*8192;
		dbuf_copy(tmpdbuf, spos, 80, unc_pixels);

	}

	dbuf_close(tmpdbuf);
}

static void deinterlace_pic_hercules(deark *c, lctx *d, dbuf *unc_pixels)
{
	dbuf *tmpdbuf = NULL;
	i64 i;

	tmpdbuf = dbuf_create_membuf(c, unc_pixels->len, 0);
	dbuf_copy(unc_pixels, 0, unc_pixels->len, tmpdbuf);
	dbuf_truncate(unc_pixels, 0);

	for(i=0; i<348; i++) {
		i64 spos;

		spos = (i/4)*90 + (i%4)*8192;
		dbuf_copy(tmpdbuf, spos, 90, unc_pixels);
	}

	dbuf_close(tmpdbuf);
}

// We'll try to support the most standard graphics cards/modes.
// Some editions of Dr. Halo evidently support many more.
static const struct pic_modeinfo_item pic_modeinfo_arr[] = {
	{0x01, 0x00, 320, 200, 1, 2, 16, 16384, 0x08}, // CGA 320x200 4c
	{0x01, 0x01, 640, 200, 1, 1, 16, 16384, 0x08}, // CGA 640x200 2c
	{0x07, 0x00, 720, 348, 1, 1, 10, 32768, 0x00}, // Hercules
	{0x15, 0x02, 320, 200, 4, 1, 12,  8192, 0x00}, // EGA 320x200 16c
	{0x15, 0x03, 640, 200, 4, 1, 12, 16384, 0x00}, // EGA 640x200 16c
	{0x15, 0x04, 640, 350, 4, 1, 12, 28000, 0x00}, // EGA 640x350 16c
	{0x15, 0x05, 640, 800, 4, 1, 12, 64000, 0x00}, // EGA 640x800 16c (special)
	{0x15, 0x0a, 640, 350, 4, 1, 12, 28000, 0x00}, // EGA 640x350 4c (?)
	{0x3c, 0x00, 320, 200, 1, 2, 16, 16384, 0x08}, // VGA 320x200 4c
	{0x3c, 0x01, 640, 200, 1, 1, 16, 16384, 0x08}, // VGA 640x200 2c
	{0x3c, 0x02, 640, 480, 1, 1, 16, 40960, 0x00}, // VGA 640x480 2c
	{0x3c, 0x03, 320, 200, 1, 8, 16, 65536, 0x00}, // VGA 320x200 256c
	{0x47, 0x04, 320, 200, 4, 1, 12,  8192, 0x00}, // VGA 320x200 16c
	{0x47, 0x05, 640, 200, 4, 1, 12, 16384, 0x00}, // VGA 640x200 16c
	{0x47, 0x06, 640, 350, 4, 1, 12, 28000, 0x00}, // VGA 640x350 16c
	{0x47, 0x07, 640, 480, 4, 1, 12, 38400, 0x00}, // VGA 640x480 16c
};

static const struct pic_modeinfo_item *get_pic_modeinfo(UI board_id, UI mode_id)
{
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(pic_modeinfo_arr); i++) {
		const struct pic_modeinfo_item *m = &pic_modeinfo_arr[i];

		if((UI)m->board_id!=board_id) continue;
		if(m->hdrlen>=12) {
			if((UI)m->mode_id!=mode_id) continue;
		}
		return m;
	}
	return NULL;
}

// Sets d->modename, based on d->modeinfo etc.
static void set_pic_mode_name(deark *c, lctx *d)
{
	const char *m1;

	switch(d->modeinfo->board_id) {
	case 0x01: m1="CGA"; break;
	case 0x07: m1="Hercules"; break;
	case 0x15: m1="EGA"; break;
	case 0x3c: case 0x47: m1="VGA"; break;
	default: m1="?";
	}

	de_snprintf(d->modename, sizeof(d->modename), "%s %u" DE_CHAR_TIMES "%u %d-color", m1,
		(UI)d->modeinfo->width, (UI)d->modeinfo->height,
		(int)d->ncolors);
}

// Default 256-color palette is a whiteless RGB332 thing.
static void make_stdpal_256col(deark *c, lctx *d)
{
	UI i;
	static const u8 samples8[8] = {
		0, 35, 67, 99, 131, 163, 195, 227 };
	static const u8 samples4[4] = { 0, 67, 131, 195 };

	for(i=0; i<256; i++) {
		u8 r, g, b;

		r = samples8[i%8];
		g = samples8[(i%64)/8];
		b = samples4[i/64];
		d->pal[i] = DE_MAKE_RGB(r, g, b);
	}
}

static void pic_set_density(deark *c, lctx *d, de_finfo *fi)
{
	u16 w = d->modeinfo->width;
	u16 h = d->modeinfo->height;

	if(w==320 && h==200) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 240.0;
		fi->density.ydens = 200.0;
	}
	else if(w==640 && h==350) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 480.0;
		fi->density.ydens = 350.0;
	}
	else if(w==640 && h==200) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 480.0;
		fi->density.ydens = 200.0;
	}
	else if(w==720 && h==348) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 155.0;
		fi->density.ydens = 100.0;
	}
}

static void de_run_drhalopic(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	const char *palfn;
	de_finfo *fi = NULL;

	d = de_malloc(c, sizeof(lctx));

	palfn = de_get_ext_option(c, "file2");

	d->board_id = (UI)de_getbyte(7);
	de_dbg(c, "board id: 0x%02x", d->board_id);
	if(d->board_id!=0x07) {
		d->mode_id = (UI)de_getu16le(10);
		de_dbg(c, "mode id: 0x%04x", d->mode_id);
	}

	d->modeinfo = get_pic_modeinfo(d->board_id, d->mode_id);
	if(!d->modeinfo) {
		de_err(c, "Unsupported image type (board=0x%02x, mode=0x%04x)",
			d->board_id, d->mode_id);
		goto done;
	}

	d->w = (i64)d->modeinfo->width;
	d->h = (i64)d->modeinfo->height;
	d->bytes_per_row_per_plane = d->w * (i64)d->modeinfo->bits_per_pixel_per_plane / 8;
	d->ncolors = 1LL<<((UI)d->modeinfo->bits_per_pixel_per_plane * (UI)d->modeinfo->nplanes);

	set_pic_mode_name(c, d);

	de_dbg(c, "mode: %s", d->modename);

	if((d->modeinfo->flags & 0x10)!=0) {
		de_err(c, "Unsupported image type: %s", d->modename);
		goto done;
	}

	if(d->ncolors==16) {
		de_copy_std_palette(DE_PALID_PC16, 0, 0, d->pal, 16, 0);
	}
	else if(d->ncolors==256) {
		make_stdpal_256col(c, d);
	}
	else if(d->ncolors==4) {
		u8 b12, b14;
		u8 palf1, palf2;
		int pal_subifd;

		if(d->modeinfo->hdrlen>=16) {
			b12 = de_getbyte(12);
			b14 = de_getbyte(14);
		}
		else {
			b12 = b14 = 0x00;
		}

		// CGA palette
		palf1 = (b12 & 0x10)?1:0;
		palf2 = (b14 & 0x01);
		if(palf1 && palf2) pal_subifd = 3;
		else if(!palf1 && palf2) pal_subifd = 0;
		else if(palf1 && !palf2) pal_subifd = 4;
		else pal_subifd = 1;
		de_copy_std_palette(DE_PALID_CGA, pal_subifd, 0, d->pal, 4, 0);

		// "background" color
		d->pal[0] = de_get_std_palette_entry(DE_PALID_PC16, 0, (int)(b12 & 0x0f));
	}

	if(palfn) {
		if(!do_read_pal_file(c, d, palfn)) goto done;
	}

	unc_pixels = dbuf_create_membuf(c,
		(i64)d->modeinfo->nominal_bytes_per_plane * (i64)d->modeinfo->nplanes, 0x1);
	if(!do_decompress_pic(c, d, unc_pixels)) goto done;

	if((d->modeinfo->flags & 0x08)!=0) {
		deinterlace_pic_16k(c, d, unc_pixels);
	}
	else if(d->modeinfo->board_id==0x07) {
		deinterlace_pic_hercules(c, d, unc_pixels);
	}

	img = de_bitmap_create(c, d->w, d->h, 3);

	if(d->modeinfo->nplanes>1) {
		de_convert_image_paletted_planar(unc_pixels, 0, 4, d->bytes_per_row_per_plane,
			d->modeinfo->nominal_bytes_per_plane, d->pal, img, 0x2);
	}
	else if(d->modeinfo->bits_per_pixel_per_plane==1) {
		de_convert_image_bilevel(unc_pixels, 0, d->bytes_per_row_per_plane, img, 0);
	}
	else {
		de_convert_image_paletted(unc_pixels, 0, (i64)d->modeinfo->bits_per_pixel_per_plane,
			d->bytes_per_row_per_plane, d->pal, img, 0);
	}

	fi = de_finfo_create(c);
	pic_set_density(c, d, fi);

	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	de_free(c, d);
}

static int de_identify_drhalopic(deark *c)
{
	if((UI)de_getu16be(0)!=0x4148) return 0;
	if(de_getbyte(6)!=0x02) return 0;
	if(de_input_file_has_ext(c, "pic")) return 70;
	return 30;
}

static void de_help_drhalopic(deark *c)
{
	help_common(c);
}

void de_module_drhalopic(deark *c, struct deark_module_info *mi)
{
	mi->id = "drhalopic";
	mi->desc = "Dr. Halo .PIC image";
	mi->run_fn = de_run_drhalopic;
	mi->identify_fn = de_identify_drhalopic;
	mi->help_fn = de_help_drhalopic;
}
