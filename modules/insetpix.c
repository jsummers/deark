// This file is part of Deark.
// Copyright (C) 2016-2024 Jason Summers
// See the file COPYING for terms of use.

// Inset .PIX

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_insetpix);

struct insetpix_item_data {
	UI id;
	UI tile_num;
	u8 is_special;
	u8 is_tile;
	i64 len;
	i64 loc;
};

typedef struct localctx_insetpix {
	de_encoding input_encoding;
	u8 hmode;
	u8 htype;
	u8 graphics_type; // 0=character, 1=bitmap
	u8 board_type;

	u8 have_image_info; // 1 = we've read the segment
	u8 have_pal_data;
	u8 have_tile_info;

	i64 imginfo_pos, imginfo_len; // 0 = no info
	i64 pal_pos, pal_len;
	i64 tileinfo_pos, tileinfo_len;

	i64 item_count;
	i64 num_tiles_found;
	i64 idx_of_1st_tile;
	i64 npwidth, pdwidth, height;
	i64 w_in_chars, h_in_chars;
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

// Sets d->have_pal_data if successful
static void do_palette(deark *c, lctx *d)
{
	i64 pos1;
	i64 pos;
	i64 pal_entries_in_file;
	i64 i;
	size_t k;
	u8 sm1[4]; // Original I, R, G, B
	u8 sm2[4]; // Intermediate
	u8 sm3[4]; // Post-processed samples
	u8 uses_intens = 0; // Special handling if we have RGB and 'I' values.
	double max_color_sample;
	double pal_sample_scalefactor[4];
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = d->pal_pos;
	if(pos1==0 || d->pal_len<4) goto done;
	pos = pos1;
	de_dbg(c, "palette at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pal_entries_in_file = d->pal_len/4;
	de_dbg(c, "number of palette colors: %d", (int)pal_entries_in_file);

	d->pal_entries_used = pal_entries_in_file; // default
	if(d->graphics_type==1) {
		d->pal_entries_used = d->max_sample_value+1;
	}
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

	d->have_pal_data = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
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

// Sets d->have_image_info if successful
static void do_image_info(deark *c, lctx *d)
{
	i64 pos1;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = d->imginfo_pos;
	if(!pos1 || d->imginfo_len<32) goto done;

	de_dbg(c, "image information at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

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

	if(d->graphics_type==0) {
		pos = pos1 + 5;
		d->w_in_chars = (i64)de_getbyte_p(&pos);
		d->h_in_chars = (i64)de_getbyte_p(&pos);
		de_dbg(c, "dimensions: %u"DE_CHAR_TIMES"%u characters",
			(UI)d->w_in_chars, (UI)d->h_in_chars);
	}

	if(d->graphics_type==1) {
		pos = pos1 + 18;
		d->npwidth = de_getu16le_p(&pos);
		d->height = de_getu16le_p(&pos);
		de_dbg_dimensions(c, d->npwidth, d->height);

		d->gfore = (i64)de_getbyte_p(&pos);
		de_dbg(c, "foreground color bits: %d", (int)d->gfore);
		d->max_sample_value = de_pow2(d->gfore) -1;
	}

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

	d->have_image_info = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Sets d->have_tile_info if successful
static void do_tileinfo(deark *c, lctx *d)
{
	i64 pos1;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = d->tileinfo_pos;
	if(!pos1 || d->tileinfo_len<8) goto done;

	de_dbg(c, "tile information at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

	d->page_rows = de_getu16le_p(&pos);
	d->page_cols = de_getu16le_p(&pos);
	d->stp_rows = de_getu16le_p(&pos);
	d->stp_cols = de_getu16le_p(&pos);
	de_dbg(c, "dimensions of a tile: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT,
		d->page_cols, d->page_rows);
	de_dbg(c, "dimensions in tiles: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT,
		d->stp_cols, d->stp_rows);

	if(d->page_cols%8 != 0) {
		de_err(c, "page_cols must be a multiple of 8 (is %d)", (int)d->page_cols);
		goto done;
	}

	if(d->num_tiles_found==0) goto done;

	d->have_tile_info = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static u8 getbit(const u8 *m, i64 bitnum)
{
	u8 b;

	b = m[bitnum/8];
	b = (b>>(7-bitnum%8)) & 0x1;
	return b;
}

static void do_decompress_tile(deark *c, lctx *d, struct insetpix_item_data *itd,
	dbuf *unc_pixels, i64 num_rows)
{
	u8 *rowbuf1 = NULL;
	u8 *compression_bytes = NULL;
	i64 pos;
	i64 i, j;
	i64 plane;
	i64 endpos = itd->loc + itd->len;

	// There are d->gfore planes (1-bpp images). The first row of each plane is
	// uncompressed. The rest are compressed with a delta compression algorithm.
	// There are d->page_rows rows in each plane.

	rowbuf1 = de_malloc(c, d->rowspan);
	compression_bytes = de_malloc(c, d->compression_bytes_per_row);

	pos = itd->loc;

	for(plane=0; plane<d->gfore; plane++) {
		for(j=0; j<num_rows; j++) {
			if(pos >= endpos) {
				de_warn(c, "Not enough data in tile %u", itd->tile_num);
				goto done;
			}

			if(j==0) {
				// First row is stored uncompressed
				dbuf_copy(c->infile, pos, d->rowspan, unc_pixels);
				pos += d->rowspan;
			}
			else {
				de_read(compression_bytes, pos, d->compression_bytes_per_row);
				pos += d->compression_bytes_per_row;

				// Read back a copy of the previous row
				dbuf_read(unc_pixels, rowbuf1, unc_pixels->len - d->rowspan, d->rowspan);

				// For every 1 bit in the compression_bytes array, read a byte from the file.
				// For every 0 bit, copy the byte from the previous row.
				for(i=0; i<d->rowspan; i++) {
					u8 b;

					if(getbit(compression_bytes, i)) {
						b =  de_getbyte_p(&pos);
					}
					else {
						b = rowbuf1[i];
					}
					dbuf_writebyte(unc_pixels, b);
				}
			}
		}
	}

	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, pos-itd->loc, unc_pixels->len);

done:
	de_free(c, compression_bytes);
	de_free(c, rowbuf1);
}

static void do_render_tile(deark *c, lctx *d, de_bitmap *img,
	struct insetpix_item_data *itd)
{
	i64 x_pos_in_tiles, y_pos_in_tiles;
	i64 x_origin_in_pixels, y_origin_in_pixels;
	dbuf *unc_pixels = NULL;
	i64 nrows_expected;
	i64 planespan;

	x_pos_in_tiles = (i64)itd->tile_num % d->stp_cols;
	y_pos_in_tiles = (i64)itd->tile_num / d->stp_cols;

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

	do_decompress_tile(c, d, itd, unc_pixels, nrows_expected);

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

static void insetpix_read_item(deark *c, i64 pos, struct insetpix_item_data *itd)
{
	itd->id = (UI)de_getu16le_p(&pos);
	itd->len = de_getu16le_p(&pos);
	itd->loc = de_getu32le(pos);
	itd->is_special = (u8)(itd->id>=0x4000);
	itd->is_tile = (u8)(itd->id>=0x8000 && itd->id<0xffff);
	if(itd->is_tile)
		itd->tile_num = itd->id-0x8000;
	else
		itd->tile_num = 0;
}

static void get_item_name(struct insetpix_item_data *itd, char *nbuf, size_t nbuf_len)
{
	const char *n1;

	if(itd->is_tile) {
		de_snprintf(nbuf, nbuf_len, "tile #%u", itd->tile_num);
		return;
	}

	switch(itd->id) {
	case 0: n1 = "image info"; break;
	case 1: n1 = "palette"; break;
	case 2: n1 = "tile info"; break;
	case 17: n1 = "printing options"; break;
	case 0xff: n1 = "empty"; break;
	default: n1 = "?";
	}
	de_strlcpy(nbuf, n1, nbuf_len);
}

static void insetpix_dbg_item(deark *c, struct insetpix_item_data *itd, i64 idx)
{
	char nbuf[40];

	get_item_name(itd, nbuf, sizeof(nbuf));
	de_dbg(c, "item #%d: id=%u (%s), loc=%"I64_FMT", len=%"I64_FMT, (int)idx,
		itd->id, nbuf, itd->loc, itd->len);
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
		struct insetpix_item_data itd;
		i64 pos;

		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) break;

		insetpix_read_item(c, pos, &itd);
		if(!itd.is_tile) continue;
		insetpix_dbg_item(c, &itd, item);

		de_dbg_indent(c, 1);
		do_render_tile(c, d, img, &itd);
		de_dbg_indent(c, -1);
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

static void do_char_graphics(deark *c, lctx *d)
{
	struct insetpix_item_data itd;
	dbuf *unc_pixels = NULL;
	struct de_char_context *charctx = NULL;
	struct fmtutil_char_simplectx *csctx = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "reading char graphics");
	de_dbg_indent(c, 1);
	if(d->num_tiles_found!=1) {
		de_err(c, "Multi-tile char. graphics not supported");
		goto done;
	}

	insetpix_read_item(c, 4 + 8*d->idx_of_1st_tile, &itd);
	insetpix_dbg_item(c, &itd, d->idx_of_1st_tile);

	unc_pixels = dbuf_create_membuf(c, 4096, 0);
	csctx = de_malloc(c, sizeof(struct fmtutil_char_simplectx));
	charctx = de_create_charctx(c, 0);
	charctx->screen_image_flag = 1;

	csctx->width_in_chars = d->page_cols;
	csctx->height_in_chars = d->page_rows;

	if(csctx->width_in_chars>80 || csctx->height_in_chars>25) {
		charctx->no_density = 1;
	}

	// Unless I'm missing something, this format is just wacky.
	// Assume the screen is 80x25. The original data is then 80x25 bytes of
	// character data, followed immediately by 80x25 bytes of attribute data.
	// So its sort of 80x50. Good so far. But then it's compressed as if it were
	// 160x25. Which is strange.
	// The first 12 rows are character data.
	// The 13th row is half character data, half attribute data.
	// The last 12 rows are attribute data.
	// The compression is only effective when a character is the same as the one
	// *two* rows above it.
	// (The format documentation does hint at this, but doesn't adequately
	// explain it.)

	d->gfore = 1; // hack (gfore is used as # of planes)
	d->rowspan = csctx->width_in_chars*2;
	d->compression_bytes_per_row = (d->rowspan+7)/8;
	do_decompress_tile(c, d, &itd, unc_pixels, csctx->height_in_chars);

	csctx->input_encoding = d->input_encoding;
	csctx->inf = unc_pixels;
	csctx->inf_pos = 0;
	csctx->inf_len = csctx->width_in_chars * csctx->height_in_chars * 2;
	csctx->fg_stride = 1;
	csctx->attr_offset = csctx->width_in_chars*csctx->height_in_chars;
	de_memcpy(&charctx->pal, &d->pal, sizeof(de_color)*16);

	fmtutil_char_simple_run(c, csctx, charctx);

done:
	de_free_charctx(c, charctx);
	de_free(c, csctx);
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_insetpix(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI pix_version;
	i64 item;
	i64 pos;
	i64 num_skipped_items = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	pix_version = (UI)de_getu16le(0);
	d->item_count = de_getu16le(2);
	de_dbg(c, "version: %u", pix_version);
	de_dbg(c, "index at 4, %d items", (int)d->item_count);

	// Scan the index, and record the location of items we care about.
	// (The index will be read again when converting the image bitmap.)
	de_dbg_indent(c, 1);
	for(item=0; item<d->item_count; item++) {
		struct insetpix_item_data itd;
		u8 skip_flag = 0;

		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) goto done;

		insetpix_read_item(c, pos, &itd);
		if(itd.is_tile) {
			if(d->num_tiles_found==0) {
				d->idx_of_1st_tile = item;
			}
			d->num_tiles_found++;
		}
		skip_flag = itd.is_special;
		if(skip_flag) {
			num_skipped_items++;
		}
		if(skip_flag && c->debug_level<2) { // Skip "tile" items for now
			continue;
		}

		insetpix_dbg_item(c, &itd, item);

		if(skip_flag) {
			continue;
		}

		if(itd.loc + itd.len > c->infile->len) {
			de_err(c, "Item #%d (ID %u) goes beyond end of file",
				(int)item, itd.id);
			goto done;
		}

		switch(itd.id) {
		case 0:
			d->imginfo_pos = itd.loc;
			d->imginfo_len = itd.len;
			break;
		case 1:
			if(!d->pal_pos) {
				d->pal_pos = itd.loc;
				d->pal_len = itd.len;
			}
			break;
		case 2:
			d->tileinfo_pos = itd.loc;
			d->tileinfo_len = itd.len;
			break;
		}
	}
	if(c->debug_level<2) {
		de_dbg(c, "other items not listed: %"I64_FMT, num_skipped_items);
	}
	de_dbg(c, "number of tiles: %"I64_FMT, d->num_tiles_found);
	de_dbg_indent(c, -1);

	do_image_info(c, d);
	if(!d->have_image_info) {
		de_err(c, "Bad or missing Image Info");
		goto done;
	}

	if(d->pal_sample_descriptor[0]!=0 && d->pal_sample_descriptor[1]==0 &&
		d->pal_sample_descriptor[2]==0 && d->pal_sample_descriptor[3]==0)
	{
		d->is_grayscale = 1;
	}

	do_palette(c, d);
	if(!d->have_pal_data) {
		de_err(c, "Bad or missing palette");
		goto done;
	}

	do_tileinfo(c, d);
	if(!d->have_tile_info) {
		de_err(c, "Bad or missing Tile Info");
		goto done;
	}

	if(d->graphics_type==0) {
		do_char_graphics(c, d);
	}
	else {
		if(d->gfore<1 || d->gfore>8) {
			de_err(c, "Inset PIX with %d bits/pixel are not supported", (int)d->gfore);
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

		do_bitmap(c, d);
	}

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
	u8 has_ext;
	u8 has_typical_1st_item;

	if(c->detection_data->best_confidence_so_far>20) return 0;

	pix_version = (UI)de_getu16le(0);
	// Other versions exist, but I don't know anything about them.
	if(pix_version!=3) return 0;

	has_ext = (u8)de_input_file_has_ext(c, "pix");
	has_typical_1st_item = (u8)((u32)de_getu32le(4)==(u32)0x00200000);
	if(!has_ext && !has_typical_1st_item) return 0;

	item_count = de_getu16le(2);
	// Need at least 4 items (image info, palette info, tile info, and 1 tile).
	if(item_count<4 || item_count>500) return 0;

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
	mi->desc = "Inset PIX image";
	mi->run_fn = de_run_insetpix;
	mi->identify_fn = de_identify_insetpix;
}
