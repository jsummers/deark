// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Dr. Halo .CUT image

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
	int have_pal;
	i64 pal_entries;
	u32 pal[256];

	// PIC-only fields
	UI offs2;
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

		b = de_getbyte(pos++);

		if(b==0 || b==0x80) { // end of row
			break;
		}
		else if(b & 0x80) { // RLE block
			count = (i64)(b - 0x80);
			b2 = dbuf_getbyte(c->infile, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // uncompressed block
			count = (i64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}

	de_dbg3(c, "scanline[%d]: decompressed %d bytes (expected %d) to %d bytes",
		(int)line_idx, (int)(pos-pos1),
		(int)len, (int)(unc_pixels->len - opos1));
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
		linebytecount = de_getu16le(pos);
		pos += 2;
		do_decompress_scanline(c, d, j, pos, linebytecount, unc_pixels);
		pos += linebytecount;
	}

	de_dbg(c, "decompressed %d bytes to %d bytes",
		(int)(pos-pos1), (int)unc_pixels->len);

	return 1;
}

static void do_write_image_gray(deark *c, lctx *d, dbuf *unc_pixels)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 b;
	i64 k;
	u8 max_val;

	max_val = 0;
	for(k=0; k<unc_pixels->len; k++) {
		b = dbuf_getbyte(unc_pixels, k);
		if(b > max_val)
			max_val = b;
	}
	de_dbg(c, "detected max val: %d", (int)max_val);
	if(max_val<1) max_val=1;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			b = dbuf_getbyte(unc_pixels, j*d->w + i);
			b = de_scale_n_to_255(max_val, (i64)b);
			de_bitmap_setpixel_gray(img, i, j, b);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_write_image_pal(deark *c, lctx *d, dbuf *unc_pixels)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 b;

	img = de_bitmap_create(c, d->w, d->h, 3);

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			b = dbuf_getbyte(unc_pixels, j*d->w + i);
			de_bitmap_setpixel_rgb(img, i, j, d->pal[(unsigned int)b]);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
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
	unsigned int board_id;
	unsigned int graphics_mode;
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
	de_dbg(c, "data size: %d", (int)datasize);
	filetype = dbuf_getbyte(palfile, 6);
	de_dbg(c, "file type: 0x%02x", (unsigned int)filever);
	filesubtype = dbuf_getbyte(palfile, 7);
	de_dbg(c, "file subtype: 0x%02x", (unsigned int)filesubtype);

	if(sig!=0x4841 /* "HA" */ || filetype!=0x0a) {
		de_err(c, "Invalid palette file");
		goto done;
	}

	board_id = (unsigned int)dbuf_getu16le(palfile, 8);
	de_dbg(c, "board id: 0x%04x", board_id);
	graphics_mode = (unsigned int)dbuf_getu16le(palfile, 10);
	de_dbg(c, "graphics mode: 0x%04x", graphics_mode);

	if(filesubtype!=0) {
		de_warn(c, "Hardware-specific palettes are not supported");
		retval = 1;
		goto done;
	}

	maxidx = dbuf_getu16le(palfile, 0x0c);
	de_dbg(c, "maxidx: %u", (unsigned int)maxidx);

	for(k=0; k<3; k++) {
		maxsamp[k] = dbuf_getu16le(palfile, 0x0e + 2*k);
		de_dbg(c, "maxsamp[%d]: %u", (int)k, (unsigned int)maxsamp[k]);
		if(maxsamp[k]<1) maxsamp[k]=1;
	}

	pos = 0x14;

	pos += 20; // Skip palette name  TODO: Display this

	num_entries = maxidx+1;
	if(num_entries>256) num_entries=256;

	for(k=0; k<num_entries; k++) {
		// As far as I can tell:
		// If we imagine the palette file being split into 512-byte chunks, a
		// (6-byte) palette entry is not allowed to cross a chunk boundary.
		// If an entry would do so, it instead starts at the beginning of the
		// next chunk.
		while((pos%512) > 506) {
			pos += 2;
		}

		for(z=0; z<3; z++) {
			osamp[z] = dbuf_getu16le(palfile, pos);
			pos += 2;
			samp[z] = de_scale_n_to_255(maxsamp[z], osamp[z]);
		}
		d->pal[k] = DE_MAKE_RGB(samp[0], samp[1], samp[2]);

		de_snprintf(tmps, sizeof(tmps), "(%5d,%5d,%5d) "DE_CHAR_RIGHTARROW" ",
			(int)osamp[0], (int)osamp[1], (int)osamp[2]);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}

	d->have_pal = 1;
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

	d = de_malloc(c, sizeof(lctx));

	palfn = de_get_ext_option(c, "file2");
	if(palfn) {
		if(!do_read_pal_file(c, d, palfn)) goto done;
	}

	pos = 0;
	if(!do_read_header(c, d)) goto done;
	pos += 6;

	unc_pixels = dbuf_create_membuf(c, d->w*d->h, 0x1);
	if(!do_decompress(c, d, pos, unc_pixels)) goto done;

	if(d->have_pal)
		do_write_image_pal(c, d, unc_pixels);
	else
		do_write_image_gray(c, d, unc_pixels);

done:
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_drhalocut(deark *c)
{
	if(de_input_file_has_ext(c, "cut")) return 10;
	return 0;
}

static void de_help_drhalocut(deark *c)
{
	de_msg(c, "-file2 <file.pal> : Read the palette from this file");
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
			b2 = dbuf_getbyte(c->infile, pos++);
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
			old_unc_pixels_len = unc_pixels->len;
		do_decompress_pic_plane(c, d, pos, c->infile->len-pos, unc_pixels);

		de_dbg(c, "plane[%u]: decompressed %"I64_FMT" bytes to %"I64_FMT" bytes",
			(UI)pn,
			d->dcmpr_endpos - pos, unc_pixels->len - old_unc_pixels_len);

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

// TODO: Write a library function that can be used for this.
static void pic_convert_image_16colplanar(deark *c, lctx *d, dbuf *unc_pixels, de_bitmap *img)
{
	i64 nbytes_per_plane;
	i64 i;
	i64 rowspan;
	UI pn;

	rowspan = d->bytes_per_row_per_plane;
	nbytes_per_plane = rowspan * d->h;

	for(i=0; i<nbytes_per_plane; i++) {
		u8 b[4];
		UI palent;
		de_color clr;
		UI k;

		// Read 8 pixels worth of bytes
		for(pn=0; pn<4; pn++) {
			b[pn] = dbuf_getbyte(unc_pixels, pn*(i64)d->modeinfo->nominal_bytes_per_plane + i);
		}

		for(k=0; k<8; k++) {
			palent = 0;

			for(pn=0; pn<4; pn++) {
				if(b[pn] & (1U<<(7-k))) {
					palent |= 1<<pn;
				}
			}

			clr = DE_MAKE_OPAQUE(d->pal[(UI)palent]);
			de_bitmap_setpixel_rgb(img, (i%rowspan)*8+k, i/rowspan, clr);
		}
	}
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

	de_snprintf(d->modename, sizeof(d->modename), "%s %ux%u %d-color", m1,
		(UI)d->modeinfo->width, (UI)d->modeinfo->height,
		(int)d->ncolors);
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
	u8 b;

	d = de_malloc(c, sizeof(lctx));

	palfn = de_get_ext_option(c, "file2");

	d->offs2 = (UI)de_getbyte(2);
	d->board_id = (UI)de_getu16le(7); // Is this 2 bytes or 1?
	de_dbg(c, "board id: 0x%02x", d->board_id);
	if(d->board_id!=0x07) {
		d->mode_id = (UI)de_getu16le(10); // Is this 2 bytes or 1?
		de_dbg(c, "mode id: 0x%02x", d->mode_id);
	}

	d->modeinfo = get_pic_modeinfo(d->board_id, d->mode_id);
	if(!d->modeinfo) {
		de_err(c, "Unsupported image type (board=0x%04x, mode=0x%04x)",
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
		de_copy_std_palette(DE_PALID_PC16, 0, 0, 16, d->pal, 16, 0);
	}
	else if(d->ncolors==256) {
		// FIXME: This is probably not the default palette.
		de_copy_std_palette(DE_PALID_VGA256, 0, 0, 256, d->pal, 256, 0);
	}
	else if(d->ncolors==4) {
		if(d->modeinfo->hdrlen>=16) {
			b = de_getbyte(14); // This is a guess
		}
		else {
			b = 0x00;
		}
		if(b==0x00) {
			de_copy_std_palette(DE_PALID_CGA, 1, 0, 4, d->pal, 4, 0);
		}
		else {
			de_copy_std_palette(DE_PALID_CGA, 0, 0, 4, d->pal, 4, 0);
		}
	}

	if(palfn) {
		// FIXME: This doesn't always work right.
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
	// TODO: aspect ratio

	if(d->modeinfo->nplanes>1) {
		pic_convert_image_16colplanar(c, d, unc_pixels, img);
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

void de_module_drhalopic(deark *c, struct deark_module_info *mi)
{
	mi->id = "drhalopic";
	mi->desc = "Dr. Halo .PIC image";
	mi->run_fn = de_run_drhalopic;
	mi->identify_fn = de_identify_drhalopic;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
