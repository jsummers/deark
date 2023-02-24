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
	i64 npwidth, pdwidth, height;
	i64 gfore; // Foreground color bits
	i64 max_sample_value;
	u8 pal_sample_descriptor[4]; // 0=intens, 1=red, 2=green, 3=blue
	u32 descriptor_combined;
	i64 haspect, vaspect;

	i64 page_rows, page_cols;
	i64 stp_rows, stp_cols;

	i64 rowspan;
	i64 compression_bytes_per_row;
	int is_grayscale;

	u8 max_pal_intensity, max_pal_sample;

	de_bitmap *tile_img; // Re-used for each tile

	i64 pal_entries_used;
	de_color pal[256];
} lctx;

static int do_palette(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 pal_entries_in_file;
	i64 i;
	size_t k;
	u8 sm1[4]; // Original I, R, G, B
	u8 sm2[4]; // Intermediate
	u8 sm3[4]; // Post-processed samples
	u8 uses_intens = 0; // Special handling if we have RGB and 'I' values.
	int retval = 0;
	double max_color_sample;
	double pal_sample_scalefactor[4];

	de_dbg(c, "palette at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pal_entries_in_file = len/4;
	de_dbg(c, "number of palette colors: %d", (int)pal_entries_in_file);

	d->pal_entries_used = d->max_sample_value+1;
	if(d->pal_entries_used > pal_entries_in_file) d->pal_entries_used = pal_entries_in_file;

	// If intensity bits are used, make the initial colors darker, so that the
	// intensity bits can lighten them.
	uses_intens = (d->pal_sample_descriptor[0]!=0) && !d->is_grayscale;
	max_color_sample = uses_intens ? 170.0 : 255.0;

	for(k=0; k<4; k++) {
		if(d->pal_sample_descriptor[k]>=2)
			pal_sample_scalefactor[k] = max_color_sample / (double)(d->pal_sample_descriptor[k]-1);
		else
			pal_sample_scalefactor[k] = 0.0;
	}

	for(i=0; i<pal_entries_in_file; i++) {
		char tmps[64];

		if(i>255) break;

		for(k=0; k<4; k++) {
			sm1[k] = de_getbyte_p(&pos);
			sm2[k] = sm1[k];
		}

		for(k=1; k<4; k++) {
			// Best I can figure is that, in the palette definition, when there
			// are exactly 4 sample intensities, intensity 1 is brighter than
			// intensity 2. I don't know why I have to swap them like this.
			if(d->pal_sample_descriptor[k]==4) {
				if(sm2[k]==1) sm2[k] = 2;
				else if(sm2[k]==2) sm2[k] = 1;
			}
		}

		if(d->is_grayscale) {
			sm3[0] = (u8)(0.5+ pal_sample_scalefactor[0] * (double)sm2[0]);
			d->pal[i] = DE_MAKE_GRAY(sm3[0]);
		}
		else {
			sm3[1] = (u8)(0.5+ pal_sample_scalefactor[1] * (double)sm2[1]);
			sm3[2] = (u8)(0.5+ pal_sample_scalefactor[2] * (double)sm2[2]);
			sm3[3] = (u8)(0.5+ pal_sample_scalefactor[3] * (double)sm2[3]);
			if(uses_intens && sm2[0]) {
				// This is just a guess. The spec doesn't say what intensity bits do.
				// This is pretty much what old PC graphics cards do when the
				// intensity bit is set.
				sm3[1] += 85;
				sm3[2] += 85;
				sm3[3] += 85;
			}
			d->pal[i] = DE_MAKE_RGB(sm3[1],sm3[2],sm3[3]);
		}

		if(uses_intens) {
			de_snprintf(tmps, sizeof(tmps), "(%3u,%3u,%3u,intens=%u) "DE_CHAR_RIGHTARROW" ",
				(UI)sm1[1], (UI)sm1[2], (UI)sm1[3], (UI)sm1[0]);
		}
		else {
			de_snprintf(tmps, sizeof(tmps), "(%3u,%3u,%3u) "DE_CHAR_RIGHTARROW" ",
				(UI)sm1[1], (UI)sm1[2], (UI)sm1[3]);
		}
		de_dbg_pal_entry2(c, i, d->pal[i], tmps, NULL,
			i<d->pal_entries_used ? "":" [unused]");
	}

	retval = 1;

	de_dbg_indent(c, -1);
	return retval;
}

static const char *get_board_type_name(u8 bt)
{
	const char *name = NULL;

	switch(bt & 0x7e) {
	case 0: name="none"; break;
	case 8: name="CGA"; break;
	case 16: name="Hercules"; break;
	case 24: name="EGA"; break;
	}
	return name?name:"?";
}

static int do_image_info(deark *c, lctx *d, i64 pos1, i64 len)
{
	int retval = 0;
	i64 pos = pos1;

	de_dbg(c, "image information at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(len<32) {
		de_err(c, "Image Information item too small");
		goto done;
	}

	d->hmode = de_getbyte_p(&pos);
	de_dbg(c, "hardware mode: %u", (UI)d->hmode);

	d->htype = de_getbyte_p(&pos);
	d->graphics_type = d->htype & 0x01;
	d->board_type = d->htype & 0xfe;
	de_dbg(c, "htype: 0x%02x", (UI)d->htype);
	de_dbg_indent(c, 1);
	de_dbg(c, "board type: %u (%s)", (UI)d->board_type,
		get_board_type_name(d->board_type));
	de_dbg(c, "graphics type: %u (%s)", (UI)d->graphics_type,
		d->graphics_type?"bitmap":"character");
	de_dbg_indent(c, -1);

	pos = pos1 + 18;
	d->npwidth = de_getu16le_p(&pos);
	d->height = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->npwidth, d->height);

	d->gfore = (i64)de_getbyte_p(&pos);
	de_dbg(c, "foreground color bits: %d", (int)d->gfore);
	d->max_sample_value = de_pow2(d->gfore) -1;

	pos = pos1 + 25;
	d->descriptor_combined = (u32)de_getu32be_p(&pos);
	d->pal_sample_descriptor[0] = (u8)(d->descriptor_combined>>24);
	d->pal_sample_descriptor[1] = (u8)((d->descriptor_combined>>16) & 0xff);
	d->pal_sample_descriptor[2] = (u8)((d->descriptor_combined>>8) & 0xff);
	d->pal_sample_descriptor[3] = (u8)(d->descriptor_combined & 0xff);
	de_dbg(c, "palette descriptor (IRGB): %u,%u,%u,%u",
		(UI)d->pal_sample_descriptor[0], (UI)d->pal_sample_descriptor[1],
		(UI)d->pal_sample_descriptor[2], (UI)d->pal_sample_descriptor[3]);

	pos++; // "pages"
	d->haspect = de_getbyte_p(&pos);
	d->vaspect = de_getbyte_p(&pos);
	de_dbg(c, "aspect ratio: %d"DE_CHAR_TIMES"%d", (int)d->haspect, (int)d->vaspect);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_tileinfo(deark *c, lctx *d, i64 pos1, i64 len)
{
	int retval = 0;
	i64 pos = pos1;

	de_dbg(c, "tile information at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(len<8) {
		de_err(c, "Tile Information item too small");
		goto done;
	}

	d->page_rows = de_getu16le_p(&pos);
	d->page_cols = de_getu16le_p(&pos);
	d->stp_rows = de_getu16le_p(&pos);
	d->stp_cols = de_getu16le_p(&pos);

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

static void do_decompress_tile(deark *c, lctx *d, i64 tile_num,
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
	i64 x_pos_in_tiles, y_pos_in_tiles;
	i64 x_origin_in_pixels, y_origin_in_pixels;
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

	do_decompress_tile(c, d, tile_num, tile_loc, tile_len, unc_pixels, nrows_expected);

	if(d->tile_img) {
		// Clear the previous image
		de_bitmap_rect(d->tile_img, 0, 0, d->page_cols, d->page_rows, 0, 0);
	}
	else {
		d->tile_img = de_bitmap_create(c, d->page_cols, d->page_rows, d->is_grayscale?1:3);
	}

	// This will try to convert 'd->page_rows' rows, when there might only be
	// 'nrows_expected' rows, but that won't cause a problem.
	de_convert_image_paletted_planar(unc_pixels, 0, d->gfore, d->rowspan, planespan,
		d->pal, d->tile_img, 0x2);

	de_bitmap_copy_rect(d->tile_img, img, 0, 0, d->page_cols, nrows_expected, x_origin_in_pixels,
		y_origin_in_pixels, 0);

	dbuf_close(unc_pixels);
}

static void do_bitmap(deark *c, lctx *d)
{
	i64 item;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;

	de_dbg(c, "reading image data");
	de_dbg_indent(c, 1);

	if(!de_good_image_dimensions(c, d->npwidth, d->height)) goto done;

	d->rowspan = d->page_cols/8;
	d->compression_bytes_per_row = (d->rowspan+7)/8; // Just a guess. Spec doesn't say.

	if(c->padpix) {
		d->pdwidth = d->page_cols * d->stp_cols;
	}
	else {
		d->pdwidth = d->npwidth;
	}

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->height, d->is_grayscale?1:3);

	// Read through the items again, this time looking only at the image tiles.
	for(item=0; item<d->item_count; item++) {
		i64 tile_loc, tile_len;
		i64 tile_num;
		i64 item_id;
		i64 pos;

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

	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = (double)d->haspect;
	fi->density.ydens = (double)d->vaspect;
	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	de_dbg_indent(c, -1);
}

static void de_run_insetpix(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI pix_version;
	i64 item;
	i64 item_id;
	i64 item_loc, item_len;
	i64 pos;
	i64 imginfo_pos=0, imginfo_len=0;
	i64 pal_pos=0, pal_len=0;
	i64 tileinfo_pos=0, tileinfo_len=0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));

	pix_version = (UI)de_getu16le(0);
	d->item_count = de_getu16le(2);
	de_dbg(c, "version: %u", pix_version);
	de_dbg(c, "index at 4, %d items", (int)d->item_count);

	// Scan the index, and record the location of items we care about.
	// (The index will be read again when converting the image bitmap.)
	de_dbg_indent(c, 1);
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

	if(!imginfo_pos) {
		de_err(c, "Missing Image Information item");
		goto done;
	}
	if(!do_image_info(c, d, imginfo_pos, imginfo_len)) goto done;

	if(d->pal_sample_descriptor[0]!=0 && d->pal_sample_descriptor[1]==0 &&
		d->pal_sample_descriptor[2]==0 && d->pal_sample_descriptor[3]==0)
	{
		d->is_grayscale = 1;
	}

	if(d->graphics_type==0) {
		de_err(c, "Inset PIX character graphics not supported");
		goto done;
	}

	switch(d->descriptor_combined) {
	case 0x00040404U:
	case 0x00404040U:
	case 0x02000000U:
	case 0x02020202U:
		break;
	default:
		de_warn(c, "Not a known image type. This image might not be handled correctly.");
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

	if(!tileinfo_pos) {
		de_err(c, "Missing Tile Information item");
		goto done;
	}

	if(!do_tileinfo(c, d, tileinfo_pos, tileinfo_len)) goto done;

	do_bitmap(c, d);

done:
	if(d) {
		de_bitmap_destroy(d->tile_img);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// Inset PIX is hard to identify.
static int de_identify_insetpix(deark *c)
{
	UI pix_version;
	i64 item_count;
	i64 item;
	i64 item_loc, item_len;

	if(c->detection_data->best_confidence_so_far>20) return 0;

	pix_version = (UI)de_getu16le(0);
	// Other versions exist, but I don't know anything about them.
	if(pix_version!=3) return 0;

	// We're not trying to identify character graphics files.
	// (Though we'd like to.) Found one with extension ".hlp".
	if(!de_input_file_has_ext(c, "pix")) return 0;

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
