// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Dr. Halo .CUT image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_drhalocut);

typedef struct localctx_struct {
	i64 w, h;
	int have_pal;
	i64 pal_entries;
	u32 pal[256];
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
