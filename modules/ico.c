// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows ICO and CUR formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_ico);
DE_DECLARE_MODULE(de_module_win1ico);

struct page_ctx {
	i64 img_num;
	i64 data_size;
	i64 data_offset;
	int hotspot_x, hotspot_y; // Valid if lctx::is_cur
	i64 fg_start, bg_start;
	i64 pdwidth, mask_pdwidth;
	int use_mask;
	int has_alpha_channel;
	int has_inv_bkgd;
	struct de_bmpinfo bi;
	de_bitmap *img;
	de_bitmap *mask_img;
	u32 pal[256];
};

typedef struct localctx_struct {
	int is_cur;
	int extract_unused_masks;
} lctx;

static void do_extract_png(deark *c, lctx *d, i64 pos, i64 len)
{
	char ext[64];
	i64 w, h;

	// Peek at the PNG data, to figure out the dimensions.
	w = de_getu32be(pos+16);
	h = de_getu32be(pos+20);

	de_snprintf(ext, sizeof(ext), "%dx%d.png", (int)w, (int)h);

	// TODO?: Might be nice to edit the PNG file to add an htSP chunk for the
	// hotspot, but it seems like more trouble than it's worth.
	dbuf_create_file_from_slice(c->infile, pos, len, ext, NULL, 0);
}

static u32 get_inv_bkgd_replacement_clr(i64 i, i64 j)
{
	if((i+j)%2) {
		return DE_MAKE_RGBA(255,0,128,128);
	}
	return DE_MAKE_RGBA(128,0,255,128);
}

static void warn_inv_bkgd(deark *c)
{
	de_warn(c, "This image contains inverse background pixels, which are not "
		"fully supported.");
}

static void decode_fg_image_default(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 i, j;
	de_bitmap *img = pg->img;

	// Read the main image
	if(pg->bi.bitcount==24) {
		de_convert_image_rgb(c->infile, pg->fg_start, pg->bi.rowspan, 3,
			img, DE_GETRGBFLAG_BGR);
	}
	else if(pg->bi.bitcount<=8) {
		de_convert_image_paletted(c->infile, pg->fg_start, pg->bi.bitcount,
			pg->bi.rowspan, pg->pal, img, 0);
	}
	else {
		return;
	}

	// Apply the mask (already read) to the main image
	for(j=0; j<img->height; j++) {
		for(i=0; i<pg->bi.width; i++) {
			u8 maskclr;
			de_color fgclr;

			maskclr = DE_COLOR_K(de_bitmap_getpixel(pg->mask_img, i, j));
			if(maskclr==0) continue; // normal opaque pixel

			fgclr = de_bitmap_getpixel(pg->img, i, j);
			if((fgclr & 0x00ffffffU)==0) {
				// normal transparent pixel
				de_bitmap_setpixel_rgba(pg->img, i, j, DE_STOCKCOLOR_TRANSPARENT);
			}
			else {
				u32 newclr;

				pg->has_inv_bkgd = 1;
				newclr = get_inv_bkgd_replacement_clr(i, j);
				de_bitmap_setpixel_rgba(pg->img, i, j, newclr);
			}
		}
	}
}

static void decode_fg_image_32(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 i, j;
	i64 pos;
	de_bitmap *img = pg->img;

	for(j=0; j<img->height; j++) {
		pos = pg->fg_start + pg->bi.rowspan*j;

		for(i=0; i<pg->pdwidth; i++) {
			u8 cr, cg, cb, ca;

			cb = de_getbyte_p(&pos);
			cg = de_getbyte_p(&pos);
			cr = de_getbyte_p(&pos);
			ca = de_getbyte_p(&pos);
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(cr,cg,cb,ca));
		}
	}
}

static void do_image_data(deark *c, lctx *d, struct page_ctx *pg)
{
	de_finfo *fi = NULL;
	char filename_token[32];
	i64 pos1 = pg->data_offset;
	i64 len = pg->data_size;

	if(pos1+len > c->infile->len) goto done;

	if(!fmtutil_get_bmpinfo(c, c->infile, &pg->bi, pos1, len, DE_BMPINFO_ICO_FORMAT)) {
		de_err(c, "Invalid bitmap");
		goto done;
	}

	if(pg->bi.file_format == DE_BMPINFO_FMT_PNG) {
		do_extract_png(c, d, pos1, len);
		goto done;
	}

	switch(pg->bi.bitcount) {
	case 1: case 2: case 4: case 8: case 24: case 32:
		break;
	case 16:
		de_err(c, "(image #%d) Unsupported bit count (%d)", (int)pg->img_num, (int)pg->bi.bitcount);
		goto done;
	default:
		de_err(c, "(image #%d) Invalid bit count (%d)", (int)pg->img_num, (int)pg->bi.bitcount);
		goto done;
	}

	if(pg->bi.compression_field!=0) {
		// TODO: Support BITFIELDS
		de_err(c, "Compression / BITFIELDS not supported");
		goto done;
	}

	if(pg->bi.bitcount==32) {
		// 32bpp images have both an alpha channel, and a 1bpp "mask".
		// We never use a 32bpp image's mask (although we may extract it
		// separately).
		// I'm not sure that's necessarily the best thing to do. I think that
		// in theory the mask could be used to get inverted-background-color
		// pixels, though I don't know if Windows allows that.
		pg->use_mask = 0;
		pg->has_alpha_channel = 1;
	}
	else {
		pg->use_mask = 1;
	}

	de_snprintf(filename_token, sizeof(filename_token), "%dx%dx%d",
		(int)pg->bi.width, (int)pg->bi.height, (int)pg->bi.bitcount);

	pg->pdwidth = (pg->bi.rowspan * 8)/pg->bi.bitcount;
	pg->mask_pdwidth = pg->bi.mask_rowspan * 8;

	pg->img = de_bitmap_create2(c, pg->bi.width, pg->pdwidth, pg->bi.height, 4);

	// Read palette
	if (pg->bi.pal_entries > 0) {
		if(pg->bi.pal_entries>256) goto done;

		de_read_palette_rgb(c->infile,
			pos1+pg->bi.infohdrsize, pg->bi.pal_entries, pg->bi.bytes_per_pal_entry,
			pg->pal, 256, DE_GETRGBFLAG_BGR);
	}

	pg->fg_start = pos1 + pg->bi.size_of_headers_and_pal;
	pg->bg_start = pos1 + pg->bi.size_of_headers_and_pal + pg->bi.foreground_size;

	de_dbg(c, "foreground at %d, mask at %d", (int)pg->fg_start, (int)pg->bg_start);

	// Foreground padding pixels exist if the width times the bitcount is not a
	// multiple of 32. This is rare.
	// Mask padding pixels exist if the width is not a multiple of 32. This is
	// common (when width=16 or 48).

	// Note: For the -padpix feature, we never combine the mask image's padding
	// pixels with the foreground image's padding pixels.
	// Issues:
	//   (1) There may be more mask padding pixels than image padding pixels.
	//   (2) Inverse background pixels, and the warning about them.
	// The mask's padding will be normally be ignored, but the padded mask will
	// be written to a separate file if d->extract_unused_masks is enabled.

	pg->mask_img = de_bitmap_create2(c, pg->bi.width, pg->mask_pdwidth, pg->bi.height, 1);
	de_convert_image_bilevel(c->infile, pg->bg_start, pg->bi.mask_rowspan, pg->mask_img, 0);

	if(pg->bi.bitcount==32) {
		decode_fg_image_32(c, d, pg);
	}
	else {
		decode_fg_image_default(c, d, pg);
	}

	if(pg->has_inv_bkgd) {
		warn_inv_bkgd(c);
	}

	de_bitmap_optimize_alpha(pg->img, (pg->bi.bitcount==32)?0x1:0x0);

	fi = de_finfo_create(c);

	de_finfo_set_name_from_sz(c, fi, filename_token, 0, DE_ENCODING_ASCII);

	if(d->is_cur) {
		fi->has_hotspot = 1;
		fi->hotspot_x = pg->hotspot_x;
		fi->hotspot_y = pg->hotspot_y;
	}

	de_bitmap_write_to_file_finfo(pg->img, fi, DE_CREATEFLAG_FLIP_IMAGE);

	if(d->extract_unused_masks && (!pg->use_mask || (c->padpix && pg->mask_pdwidth>pg->bi.width))) {
		char maskname_token[32];

		de_snprintf(maskname_token, sizeof(maskname_token), "%dx%dx%dmask",
			(int)pg->bi.width, (int)pg->bi.height, (int)pg->bi.bitcount);
		de_bitmap_write_to_file(pg->mask_img, maskname_token, DE_CREATEFLAG_IS_AUX | DE_CREATEFLAG_FLIP_IMAGE);
	}

done:
	if(pg) {
		de_bitmap_destroy(pg->img);
		pg->img = NULL;
		de_bitmap_destroy(pg->mask_img);
		pg->mask_img = NULL;
	}
	de_finfo_destroy(c, fi);
}

static void do_image_dir_entry(deark *c, lctx *d, i64 img_num, i64 pos)
{
	struct page_ctx *pg = NULL;

	pg = de_malloc(c, sizeof(struct page_ctx));
	pg->img_num = img_num;

	de_dbg(c, "image #%d, index at %d", (int)pg->img_num, (int)pos);
	de_dbg_indent(c, 1);
	if(d->is_cur) {
		pg->hotspot_x = (int)de_getu16le(pos+4);
		pg->hotspot_y = (int)de_getu16le(pos+6);
		de_dbg(c, "hotspot: %d,%d", pg->hotspot_x, pg->hotspot_y);
	}
	pg->data_size = de_getu32le(pos+8);
	pg->data_offset = de_getu32le(pos+12);
	de_dbg(c, "offset=%"I64_FMT", size=%"I64_FMT, pg->data_offset, pg->data_size);

	do_image_data(c, d, pg);

	de_free(c, pg);
	de_dbg_indent(c, -1);
}

static void de_run_ico(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 x;
	i64 num_images;
	i64 i;

	d = de_malloc(c, sizeof(lctx));
	d->extract_unused_masks = (c->extract_level>=2);

	x = de_getu16le(2);
	if(x==1) {
		d->is_cur=0;
		de_declare_fmt(c, "Windows Icon");
	}
	else if(x==2) {
		d->is_cur=1;
		de_declare_fmt(c, "Windows Cursor");
	}
	else {
		de_dbg(c, "Not an ICO/CUR file");
		goto done;
	}

	num_images = de_getu16le(4);
	de_dbg(c, "images in file: %d", (int)num_images);
	if(!de_good_image_count(c, num_images)) {
		goto done;
	}

	for(i=0; i<num_images; i++) {
		do_image_dir_entry(c, d, i, 6+16*i);
	}

done:
	de_free(c, d);
}

// Windows icons and cursors don't have a distinctive signature. This
// function tries to screen out other formats.
static int is_windows_ico_or_cur(deark *c)
{
	i64 numicons;
	i64 i;
	i64 size, offset;
	u8 buf[4];

	de_read(buf, 0, 4);
	if(de_memcmp(buf, "\x00\x00\x01\x00", 4) &&
		de_memcmp(buf, "\x00\x00\x02\x00", 4))
	{
		return 0;
	}

	numicons = de_getu16le(4);

	// Each icon must use at least 16 bytes for the directory, 40 for the
	// info header, 4 for the foreground, and 4 for the mask.
	if(numicons<1 || (6+numicons*64)>c->infile->len) return 0;

	// Examine the first few icon index entries.
	for(i=0; i<numicons && i<8; i++) {
		size = de_getu32le(6+16*i+8);
		offset = de_getu32le(6+16*i+12);
		if(size<48) return 0;
		if(offset < 6+numicons*16) return 0;
		if(offset+size > c->infile->len) return 0;
	}
	return 1;
}

static int de_identify_ico(deark *c)
{
	if(is_windows_ico_or_cur(c)) {
		return 80;
	}
	return 0;
}

void de_module_ico(deark *c, struct deark_module_info *mi)
{
	mi->id = "ico";
	mi->desc = "Windows icon/cursor";
	mi->run_fn = de_run_ico;
	mi->identify_fn = de_identify_ico;
}

////////////////////////////////////////////////////////////////

typedef struct win1ctx_struct {
	unsigned int type_code;
	int is_cur;
	const char *type_name;
	i64 bytes_consumed;
} win1ctx;

static int decode_win1_icon(deark *c, win1ctx *d, i64 pos1)
{
	de_bitmap *mask = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	i64 npwidth, h;
	i64 pdwidth;
	i64 rowspan;
	i64 i, j;
	i64 pos = pos1;
	int has_inv_bkgd = 0;
	int hotspot_x = 0;
	int hotspot_y = 0;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos1+12 > c->infile->len) goto done;

	de_dbg(c, "%s at %"I64_FMT, d->type_name, pos);
	de_dbg_indent(c, 1);

	if(d->is_cur) {
		hotspot_x = (int)de_getu16le(pos);
		hotspot_y = (int)de_getu16le(pos+2);
		de_dbg(c, "hotspot: %d,%d", hotspot_x, hotspot_y);
	}
	pos += 4;

	npwidth = de_getu16le_p(&pos);
	h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, npwidth, h);
	if(!de_good_image_dimensions(c, npwidth, h)) goto done;

	rowspan = de_getu16le_p(&pos);
	de_dbg(c, "bytes/row: %d", (int)rowspan);
	pdwidth = rowspan*8;

	if(d->is_cur) {
		unsigned int csColor;
		csColor = (unsigned int)de_getu16le(pos);
		de_dbg(c, "csColor: 0x%04x", csColor);
	}
	pos += 2;

	mask = de_bitmap_create2(c, npwidth, pdwidth, h, 1);
	img = de_bitmap_create2(c, npwidth, pdwidth, h, 4);
	de_dbg(c, "mask at %"I64_FMT, pos);
	de_convert_image_bilevel(c->infile, pos, rowspan, mask, 0);
	pos += rowspan*h;
	de_dbg(c, "foreground at %"I64_FMT, pos);
	de_convert_image_bilevel(c->infile, pos, rowspan, img, 0);
	pos += rowspan*h;

	// This whole loop does nothing, except handle inverse-background-color
	// pixels. But we have to do something, because such pixels are not
	// uncommon.
	for(j=0; j<h; j++) {
		for(i=0; i<pdwidth; i++) {
			u8 fgclr, maskclr;
			u32 newclr;

			maskclr = DE_COLOR_K(de_bitmap_getpixel(mask, i, j));
			if(maskclr==0) continue;
			fgclr = DE_COLOR_K(de_bitmap_getpixel(img, i, j));
			if(fgclr==0) continue;

			newclr = get_inv_bkgd_replacement_clr(i, j);
			de_bitmap_setpixel_gray(mask, i, j, 255-DE_COLOR_A(newclr));
			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_OPAQUE(newclr));
			if(i<npwidth) {
				has_inv_bkgd = 1;
			}
		}
	}
	if(has_inv_bkgd) {
		warn_inv_bkgd(c);
	}

	de_bitmap_apply_mask(img, mask, DE_BITMAPFLAG_WHITEISTRNS);

	fi = de_finfo_create(c);

	if(d->is_cur) {
		fi->has_hotspot = 1;
		fi->hotspot_x = hotspot_x;
		fi->hotspot_y = hotspot_y;
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);
	d->bytes_consumed = pos - pos1;
	retval = 1;

done:
	de_bitmap_destroy(img);
	de_bitmap_destroy(mask);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_win1ico(deark *c, de_module_params *mparams)
{
	win1ctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(win1ctx));
	d->type_code = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "type code: 0x%04x", d->type_code);
	if(d->type_code==0x0003 || d->type_code==0x0103 || d->type_code==0x0203) {
		d->is_cur = 1;
		d->type_name = "cursor";
	}
	else if(d->type_code==0x0001 || d->type_code==0x0101 || d->type_code==0x0201) {
		d->type_name = "icon";
	}
	else {
		de_err(c, "Not a Windows 1.0 icon/cursor");
		goto done;
	}
	de_declare_fmtf(c, "Windows 1.0 %s", d->type_name);

	if(!decode_win1_icon(c, d, pos)) goto done;
	pos += d->bytes_consumed;
	if((d->type_code & 0xff00)==0x0200) {
		// In this case there are supposed to be two icons (this is untested).
		if(!decode_win1_icon(c, d, pos)) goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_win1ico(deark *c)
{
	u8 tclo, tchi;
	i64 w, h, wb;
	int has_ext;

	tclo = de_getbyte(0);
	tchi = de_getbyte(1);
	if((tclo==1 || tclo==3) && (tchi<=2)) {
		;
	}
	else {
		return 0;
	}

	w = de_getu16le(6);
	h = de_getu16le(8);
	wb = de_getu16le(10);
	if(w<16 || h<16 || w>256 || h>256) return 0;
	if(wb != ((w+15)/16)*2) return 0;
	has_ext = de_input_file_has_ext(c, (tclo==3)?"cur":"ico");
	if((w==32 || w==64) && h==w && has_ext) return 100;
	return has_ext ? 70 : 6;
}

void de_module_win1ico(deark *c, struct deark_module_info *mi)
{
	mi->id = "win1ico";
	mi->desc = "Windows 1.0 icon/cursor";
	mi->run_fn = de_run_win1ico;
	mi->identify_fn = de_identify_win1ico;
}
