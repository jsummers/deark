// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Inset .PIX

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_insetpix);

typedef struct localctx_struct {
	i64 item_count;
	u8 hmode;
	u8 htype;
	u8 graphics_type; // 0=character, 1=bitmap
	u8 board_type;
	i64 width, height;
	i64 gfore; // Foreground color bits
	i64 max_sample_value;
	i64 num_pal_bits[4]; // 0=intens, 1=red, 2=green, 3=blue
	i64 haspect, vaspect;

	i64 page_rows, page_cols;
	i64 stp_rows, stp_cols;

	i64 rowspan;
	i64 compression_bytes_per_row;
	int is_grayscale;

	u8 max_pal_intensity, max_pal_sample;

	i64 pal_entries_used;
	u32 pal[256];
} lctx;

static int do_palette(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 pal_entries_in_file;
	i64 i;
	i64 k;
	u8 ci1, cr1, cg1, cb1;
	u8 ci2, cr2, cg2, cb2;
	int retval = 0;
	double max_color_sample;
	double pal_sample_scalefactor[4];

	de_dbg(c, "palette at %d", (int)pos);
	de_dbg_indent(c, 1);

	pal_entries_in_file = len/4;
	de_dbg(c, "number of palette colors: %d", (int)pal_entries_in_file);

	d->pal_entries_used = d->max_sample_value+1;
	if(d->pal_entries_used > pal_entries_in_file) d->pal_entries_used = pal_entries_in_file;

	// If intensity bits are used, make the initial colors darker, so that the
	// intensity bits can lighten them.
	if(d->num_pal_bits[0]==0) max_color_sample=255.0;
	else max_color_sample=170.0;

	for(k=1; k<4; k++) {
		if(d->num_pal_bits[k]>=2)
			pal_sample_scalefactor[k] = max_color_sample / (double)(d->num_pal_bits[k]-1);
		else
			pal_sample_scalefactor[k] = max_color_sample;
	}

	for(i=0; i<pal_entries_in_file; i++) {
		char tmps[64];

		if(i>255) break;
		ci1 = de_getbyte(pos+4*i);
		cr1 = de_getbyte(pos+4*i+1);
		cg1 = de_getbyte(pos+4*i+2);
		cb1 = de_getbyte(pos+4*i+3);

		if(d->is_grayscale) {
			// This is untested. I can't find any grayscale PIX images.
			// The spec says you can make a bilevel image with "palette intensity
			// bits" set to 1, which makes it clear that that field really is a
			// number of bits, not a number of sample values.
			// But color images evidently use the "number of bits" fields to store
			// the number of sample values.
			ci2 = de_sample_nbit_to_8bit(d->num_pal_bits[0], ci1);
			cr2 = ci2;
			cg2 = ci2;
			cb2 = ci2;
			d->pal[i] = DE_MAKE_GRAY(ci2);
		}
		else {
			cr2 = (u8)(0.5+ pal_sample_scalefactor[1] * (double)cr1);
			cg2 = (u8)(0.5+ pal_sample_scalefactor[2] * (double)cg1);
			cb2 = (u8)(0.5+ pal_sample_scalefactor[3] * (double)cb1);
			if(ci1) {
				// This is just a guess. The spec doesn't say what intensity bits do.
				// This is pretty much what old PC graphics cards do when the
				// intensity bit is set.
				cr2 += 85;
				cg2 += 85;
				cb2 += 85;
			}
			d->pal[i] = DE_MAKE_RGB(cr2,cg2,cb2);
		}

		de_snprintf(tmps, sizeof(tmps), "(%d,%d,%d,intens=%d) "DE_CHAR_RIGHTARROW" ",
			(int)cr1, (int)cg1, (int)cb1, (int)ci1);
		de_dbg_pal_entry2(c, i, d->pal[i], tmps, NULL,
			i<d->pal_entries_used ? "":" [unused]");
	}

	retval = 1;

	de_dbg_indent(c, -1);
	return retval;
}

static int do_image_info(deark *c, lctx *d, i64 pos, i64 len)
{
	int retval = 0;

	de_dbg(c, "image information at %d", (int)pos);
	de_dbg_indent(c, 1);
	if(len<32) {
		de_err(c, "Image Information item too small");
		goto done;
	}

	d->hmode = de_getbyte(pos);
	de_dbg(c, "hardware mode: %d", (int)d->hmode);

	d->htype = de_getbyte(pos+1);
	d->graphics_type = d->htype & 0x01;
	d->board_type = d->htype & 0xfe;

	de_dbg(c, "graphics type: %d (%s)", (int)d->graphics_type,
		d->graphics_type?"bitmap":"character");
	de_dbg(c, "board type: %d", (int)d->board_type);

	d->width = de_getu16le(pos+18);
	d->height = de_getu16le(pos+20);
	de_dbg_dimensions(c, d->width, d->height);

	d->gfore = (i64)de_getbyte(pos+22);
	de_dbg(c, "foreground color bits: %d", (int)d->gfore);
	d->max_sample_value = de_pow2(d->gfore) -1;

	d->num_pal_bits[0] = (i64)de_getbyte(pos+25);
	d->num_pal_bits[1] = (i64)de_getbyte(pos+26);
	d->num_pal_bits[2] = (i64)de_getbyte(pos+27);
	d->num_pal_bits[3] = (i64)de_getbyte(pos+28);
	de_dbg(c, "\"number of palette bits\" (IRGB): %d,%d,%d,%d",
		(int)d->num_pal_bits[0], (int)d->num_pal_bits[1],
		(int)d->num_pal_bits[2], (int)d->num_pal_bits[3] );

	d->haspect = de_getbyte(pos+30);
	d->vaspect = de_getbyte(pos+31);
	de_dbg(c, "aspect ratio: %d"DE_CHAR_TIMES"%d", (int)d->haspect, (int)d->vaspect);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_tileinfo(deark *c, lctx *d, i64 pos, i64 len)
{
	int retval = 0;

	de_dbg(c, "tile information at %d", (int)pos);
	de_dbg_indent(c, 1);
	if(len<8) {
		de_err(c, "Tile Information item too small");
		goto done;
	}

	d->page_rows = de_getu16le(pos+0);
	d->page_cols = de_getu16le(pos+2);
	d->stp_rows = de_getu16le(pos+4);
	d->stp_cols = de_getu16le(pos+6);

	de_dbg(c, "page_rows=%d, page_cols=%d", (int)d->page_rows, (int)d->page_cols);
	de_dbg(c, "strip_rows=%d, strip_cols=%d", (int)d->stp_rows, (int)d->stp_cols);

	if(d->page_cols%8 != 0) {
		de_err(c, "page_cols must be a multiple of 8 (is %d)", (int)d->page_cols);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static u8 getbit(const u8 *m, i64 bitnum)
{
	u8 b;
	b = m[bitnum/8];
	b = (b>>(7-bitnum%8)) & 0x1;
	return b;
}

static void do_uncompress_tile(deark *c, lctx *d, i64 tile_num,
	i64 tile_loc, i64 tile_len,
	dbuf *unc_pixels, i64 num_rows)
{
	u8 *rowbuf1 = NULL;
	u8 *rowbuf2 = NULL;
	u8 *compression_bytes = NULL;
	i64 pos;
	i64 i, j;
	i64 plane;

	// There are d->gfore planes (1-bpp images). The first row of each plane is
	// uncompressed. The rest are compressed with a delta compression algorithm.
	// There are d->page_rows rows in each plane.

	rowbuf1 = de_malloc(c, d->rowspan);
	rowbuf2 = de_malloc(c, d->rowspan);
	compression_bytes = de_malloc(c, d->compression_bytes_per_row);

	pos = tile_loc;

	for(plane=0; plane<d->gfore; plane++) {
		if(pos >= tile_loc + tile_len) {
			de_warn(c, "Not enough data in tile %d", (int)tile_num);
			goto done;
		}

		for(j=0; j<num_rows; j++) {
			if(j==0) {
				// First row is stored uncompressed
				de_read(rowbuf1, pos, d->rowspan);
				pos += d->rowspan;
				de_memcpy(rowbuf2, rowbuf1, (size_t)d->rowspan);
			}
			else {
				de_read(compression_bytes, pos, d->compression_bytes_per_row);
				pos += d->compression_bytes_per_row;

				// For every 1 bit in the compression_bytes array, read a byte from the file.
				// For every 0 bit, copy the byte from the previous row.
				for(i=0; i<d->rowspan; i++) {
					if(getbit(compression_bytes, i)) {
						rowbuf2[i] = de_getbyte(pos++);
					}
					else {
						rowbuf2[i] = rowbuf1[i];
					}
				}
			}

			// TODO: Maybe instead of having separate rowbufs, we should read back what
			// we wrote to unc_pixels.
			dbuf_write(unc_pixels, rowbuf2, d->rowspan);

			// Remember the previous row
			de_memcpy(rowbuf1, rowbuf2, (size_t)d->rowspan);
		}
	}

done:
	de_free(c, compression_bytes);
	de_free(c, rowbuf1);
	de_free(c, rowbuf2);
}

static void do_render_tile(deark *c, lctx *d, de_bitmap *img,
	i64 tile_num, i64 tile_loc, i64 tile_len)
{
	i64 i, j;
	i64 plane;
	i64 x_pos_in_tiles, y_pos_in_tiles;
	i64 x_origin_in_pixels, y_origin_in_pixels;
	i64 x_pos_in_pixels, y_pos_in_pixels;
	u32 clr;
	unsigned int palent;
	u8 b;
	dbuf *unc_pixels = NULL;
	i64 nrows_expected;
	i64 planespan;

	x_pos_in_tiles = tile_num % d->stp_cols;
	y_pos_in_tiles = tile_num / d->stp_cols;

	x_origin_in_pixels = x_pos_in_tiles * d->page_cols;
	y_origin_in_pixels = y_pos_in_tiles * d->page_rows;

	// "If the actual row bound of the tile exceeds the image, the extra
	// rows are not present."
	nrows_expected = d->height - y_origin_in_pixels;
	if(nrows_expected > d->page_rows) nrows_expected = d->page_rows;
	planespan = nrows_expected * d->rowspan;

	de_dbg(c, "tile (%d,%d), pixel position (%d,%d), size %d"DE_CHAR_TIMES"%d",
		(int)x_pos_in_tiles, (int)y_pos_in_tiles,
		(int)x_origin_in_pixels, (int)y_origin_in_pixels,
		(int)d->page_cols, (int)nrows_expected);

	unc_pixels = dbuf_create_membuf(c, 4096, 0);

	do_uncompress_tile(c, d, tile_num, tile_loc, tile_len, unc_pixels, nrows_expected);

	// Paint the tile into the bitmap.
	for(j=0; j<d->page_rows; j++) {
		y_pos_in_pixels = y_origin_in_pixels+j;
		if(y_pos_in_pixels >= d->height) break;

		for(i=0; i<d->page_cols; i++) {
			x_pos_in_pixels = x_origin_in_pixels+i;
			if(x_pos_in_pixels >= d->width) break;

			palent = 0;
			for(plane=0; plane<d->gfore; plane++) {
				b = de_get_bits_symbol(unc_pixels, 1, plane*planespan + j*d->rowspan, i);
				if(b) palent |= (1<<plane);
			}

			if(palent<=255) clr = d->pal[palent];
			else clr=0;

			de_bitmap_setpixel_rgb(img, x_pos_in_pixels, y_pos_in_pixels, clr);
		}
	}

	dbuf_close(unc_pixels);
}

static void do_bitmap(deark *c, lctx *d)
{
	i64 pos;
	i64 item;
	i64 item_id;
	i64 tile_loc, tile_len;
	i64 tile_num;
	de_bitmap *img = NULL;

	de_dbg(c, "reading image data");
	de_dbg_indent(c, 1);

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	d->rowspan = d->page_cols/8;
	d->compression_bytes_per_row = (d->rowspan+7)/8; // Just a guess. Spec doesn't say.

	img = de_bitmap_create(c, d->width, d->height, d->is_grayscale?1:3);

	// Read through the items again, this time looking only at the image tiles.
	for(item=0; item<d->item_count; item++) {
		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) break;

		item_id = de_getu16le(pos);
		if(item_id<0x8000 || item_id==0xffff) continue;

		tile_len = de_getu16le(pos+2);
		tile_loc = de_getu32le(pos+4);

		tile_num = item_id-0x8000;
		de_dbg(c, "item #%d: tile #%d: loc=%d, len=%d", (int)item, (int)tile_num,
			(int)tile_loc, (int)tile_len);

		do_render_tile(c, d, img, tile_num, tile_loc, tile_len);
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_dbg_indent(c, -1);
}

static void de_run_insetpix(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pix_version;
	i64 item;
	i64 item_id;
	i64 item_loc, item_len;
	i64 pos;
	i64 imginfo_pos=0, imginfo_len=0;
	i64 pal_pos=0, pal_len=0;
	i64 tileinfo_pos=0, tileinfo_len=0;
	int indent_flag = 0;

	d = de_malloc(c, sizeof(lctx));

	de_warn(c, "The Inset PIX module is experimental, and may not work correctly.");

	pix_version = de_getu16le(0);
	d->item_count = de_getu16le(2);
	de_dbg(c, "version: %d", (int)pix_version);
	de_dbg(c, "index at 4, %d items", (int)d->item_count);

	// Scan the index, and record the location of items we care about.
	// (The index will be read again when converting the image bitmap.)
	de_dbg_indent(c, 1);
	indent_flag = 1;
	for(item=0; item<d->item_count; item++) {
		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) break;

		item_id = de_getu16le(pos);
		if(item_id>=0x8000) continue; // Skip "tile" items for now

		item_len = de_getu16le(pos+2);
		item_loc = de_getu32le(pos+4);
		de_dbg(c, "item #%d: id=%d, loc=%d, len=%d", (int)item,
			(int)item_id, (int)item_loc, (int)item_len);

		if(item_loc + item_len > c->infile->len) {
			de_err(c, "Item #%d (ID %d) goes beyond end of file",
				(int)item, (int)item_id);
			goto done;
		}

		switch(item_id) {
		case 0:
			imginfo_pos = item_loc;
			imginfo_len = item_len;
			break;
		case 1:
			if(!pal_pos) {
				pal_pos = item_loc;
				pal_len = item_len;
			}
			break;
		case 2:
			tileinfo_pos = item_loc;
			tileinfo_len = item_len;
			break;
		case 17: // Printing Options
		case 0xffff: // Empty item
			break;
		default:
			de_dbg(c, "unknown item type %d", (int)item_id);
		}
	}
	de_dbg_indent(c, -1);
	indent_flag = 0;

	if(!imginfo_pos) {
		de_err(c, "Missing Image Information item");
		goto done;
	}
	if(!do_image_info(c, d, imginfo_pos, imginfo_len)) goto done;

	if(d->graphics_type==0) {
		de_err(c, "Inset PIX character graphics not supported");
		goto done;
	}

	if(!pal_pos) {
		de_err(c, "Missing palette");
		goto done;
	}

	if(!do_palette(c, d, pal_pos, pal_len)) goto done;

	if(d->gfore<1 || d->gfore>8) {
		de_err(c, "Inset PIX with %d bits/pixel are not supported", (int)d->gfore);
		goto done;
	}

	if(d->num_pal_bits[0]!=0 && d->num_pal_bits[1]==0 &&
		d->num_pal_bits[2]==0 && d->num_pal_bits[3]==0)
	{
		d->is_grayscale = 1;
	}

	if(!tileinfo_pos) {
		de_err(c, "Missing Tile Information item");
		goto done;
	}

	if(!do_tileinfo(c, d, tileinfo_pos, tileinfo_len)) goto done;

	do_bitmap(c, d);

done:
	if(indent_flag) de_dbg_indent(c, -1);

	de_free(c, d);
}

// Inset PIX is hard to identify.
static int de_identify_insetpix(deark *c)
{
	i64 pix_version;
	i64 item_count;
	i64 item;
	i64 item_loc, item_len;

	if(!de_input_file_has_ext(c, "pix")) return 0;

	pix_version = de_getu16le(0);
	// The only version number I know of is 3, but I don't know what other
	// versions may exist.
	if(pix_version<1 || pix_version>4) return 0;

	item_count = de_getu16le(2);
	// Need at least 4 items (image info, palette info, tile info, and 1 tile).
	if(item_count<4) return 0;

	if(4 + 8*item_count >= c->infile->len) return 0;

	for(item=0; item<item_count && item<16; item++) {
		item_len = de_getu16le(4+8*item+2);
		item_loc = de_getu32le(4+8*item+4);
		if(item_loc < 4 + 8*item_count) return 0;
		if(item_loc+item_len > c->infile->len) return 0;
	}

	return 20;
}

void de_module_insetpix(deark *c, struct deark_module_info *mi)
{
	mi->id = "insetpix";
	mi->desc = "Inset .PIX image";
	mi->run_fn = de_run_insetpix;
	mi->identify_fn = de_identify_insetpix;
}
