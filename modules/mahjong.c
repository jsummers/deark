// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// Some miscellaneous Mahjong graphics formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mahj_na_til);
DE_DECLARE_MODULE(de_module_mjvga);
DE_DECLARE_MODULE(de_module_mindjongg);

// **************************************************************************
// Mah Jongg tile set
// From Nels Anderson's Mah Jongg, an EGA-centric DOS game
// **************************************************************************

struct mahj_ctx {
	de_encoding input_encoding;
	u8 opt_namefield;
	u8 need_errmsg;
	u8 has_name;
	i64 tile_w, tile_h;
	de_bitmap *curtile;
	de_bitmap *canvas;
	de_ucstring *name;
	de_finfo *fi;
	de_color pal[16];

	u8 mjvga_tis_fmt;
};

#define MAHJ_TILE_BYTESIZE  800
#define MAHJ_MAX_TILES      200
#define MAHJ_MAX_TILES_PER_ROW  10
#define MAHJ_BORDER         2

// This is slightly different from the standard PC palette.
static const u8 mahj_pal16[16*3] = {
	0x00,0x00,0x00, 0x00,0x00,0xaa, 0x00,0x55,0x00, 0x00,0xaa,0xaa,
	0xaa,0x00,0x00, 0xaa,0x00,0xaa, 0xaa,0x55,0x00, 0xaa,0xaa,0xaa,
	0x55,0x55,0x55, 0x55,0x55,0xff, 0x00,0xaa,0x00, 0x00,0xff,0xff,
	0xff,0x00,0x00, 0xff,0x00,0xff, 0xff,0xff,0x00, 0xff,0xff,0xff
};

static void mahj_destroy_ctx(deark *c, struct mahj_ctx *d)
{
	if(!d) return;
	ucstring_destroy(d->name);
	de_bitmap_destroy(d->curtile);
	de_bitmap_destroy(d->canvas);
	de_finfo_destroy(c, d->fi);
	de_free(c, d);
}

static int mahj_has_name_field(deark *c, struct mahj_ctx *d)
{
	UI i;
	u8 buf[21];
	u8 found_NUL;

	// If the first byte is not 0, the file might start with a "name" field.
	// If the name field is present, the bytes covered up by it are rendered as
	// if they were 0 (black or transparent).
	// The Mah Jongg v4.2 game thinks the field is 22 bytes long, with the last
	// byte ignored.
	// The tile editor, and the game Tile Match, think the field is 21 bytes
	// long.
	// Files exist in which the first byte is not 0, but which do not have a
	// name field. Ideally, we should try to figure this out, or at least have
	// an option to interpret those bytes as graphics, and/or to be biased in
	// one direction or the other.
	// A sometimes-related issue is that tiles exist in which the top-left and
	// bottom-right corners should not be considered to be transparent.
	// Perhaps files with fewer than 42 tiles should have different heuristics.
	// The name field is a silly little quirk, but it's frustratingly difficult
	// to deal with in a comprehensive way.
	// The "mahj_na_til:nf" option is left open for future expansion.

	if(d->opt_namefield==0) return 0;
	de_read(buf, 0, 21);
	if(buf[0]==0) return 0;
	found_NUL = 0;

	for(i=0; i<21; i++) {
		if(found_NUL) {
			// The name is NUL padded, so if there's a non-NUL after a NUL,
			// this can't be a name.
			if(buf[i]!=0) return 0;
		}
		else {
			if(buf[i]==0) {
				found_NUL = 1;
			}
		}
	}
	return 1;
}

static void de_run_mahj_na_til(deark *c, de_module_params *mparams)
{
	struct mahj_ctx *d = NULL;
	i64 num_tiles;
	i64 canvas_num_cols;
	i64 canvas_num_rows;
	i64 tile_rowspan;
	i64 bytes_per_tile;
	i64 canvas_w, canvas_h;
	i64 n;

	d = de_malloc(c, sizeof(struct mahj_ctx));
	d->opt_namefield = (u8)de_get_ext_option_bool(c, "mahj_na_til:nf", 0xff);
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	d->tile_w = 40;
	d->tile_h = 40;
	tile_rowspan = de_pad_to_2(d->tile_w)/2;
	bytes_per_tile = tile_rowspan*d->tile_h;

	num_tiles = (c->infile->len+bytes_per_tile/2) / bytes_per_tile;
	if(num_tiles<1 || num_tiles>MAHJ_MAX_TILES) {
		d->need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "num tiles: %d", (int)num_tiles);

	d->name = ucstring_create(c);
	d->has_name = mahj_has_name_field(c, d);
	if(d->has_name) {
		dbuf_read_to_ucstring(c->infile, 0, 21, d->name,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		// Supposed to be the tile set author's name. Sometimes used
		// for something else, such as the tile set title.
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->name));
	}

	de_copy_palette_from_rgb24(mahj_pal16, d->pal, 16);

	if(num_tiles < MAHJ_MAX_TILES_PER_ROW) {
		canvas_num_cols = num_tiles;
	}
	else {
		canvas_num_cols = MAHJ_MAX_TILES_PER_ROW;
	}
	canvas_num_rows = de_pad_to_n(num_tiles, canvas_num_cols) / canvas_num_cols;

	canvas_w = canvas_num_cols*(d->tile_w+MAHJ_BORDER) - MAHJ_BORDER;
	canvas_h = canvas_num_rows*(d->tile_h+MAHJ_BORDER) - MAHJ_BORDER;
	d->canvas = de_bitmap_create(c, canvas_w, canvas_h, 4);
	d->curtile = de_bitmap_create(c, d->tile_w, d->tile_h, 4);

	for(n=0; n<num_tiles; n++) {
		i64 colnum, rownum;
		i64 cnvpixpos_x, cnvpixpos_y;
		i64 i, j;

		colnum = n % canvas_num_cols;
		rownum = n / canvas_num_cols;
		cnvpixpos_x = colnum * (d->tile_w+MAHJ_BORDER);
		cnvpixpos_y = rownum * (d->tile_h+MAHJ_BORDER);

		// Read a tile to a temp bitmap
		de_bitmap_rect(d->curtile, 0, 0, d->tile_w, d->tile_h,
			DE_STOCKCOLOR_TRANSPARENT, 0);
		de_convert_image_paletted(c->infile, bytes_per_tile*n, 4, tile_rowspan,
			d->pal, d->curtile, 0);

		// Fix up some things
		for(j=0; j<d->tile_h; j++) {
			for(i=0; i<d->tile_w; i++) {
				// Refer to the comments in mahj_has_name_field().
				if(d->has_name && n==0 && (j==0 || (j==1 && i<4))) {
					de_bitmap_setpixel_rgba(d->curtile, i, j, d->pal[0]);
				}

				// Make pixels near top-left and bottom-right corners
				// transparent.
				if(!c->padpix &&
					((i+j <= 3) || (i+j >= d->tile_w+d->tile_h-5)))
				{
					de_bitmap_setsample(d->curtile, i, j, 3, 0);
				}
			}
		}

		// Paint the tile to the canvas
		de_bitmap_copy_rect(d->curtile, d->canvas, 0, 0,
			d->tile_w, d->tile_h,
			cnvpixpos_x, cnvpixpos_y, 0);
	}

	d->fi = de_finfo_create(c);
	d->fi->density.code = DE_DENSITY_UNK_UNITS;
	d->fi->density.xdens = 480.0;
	d->fi->density.ydens = 350.0;
	de_bitmap_write_to_file_finfo(d->canvas, d->fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported TIL file");
		}
		mahj_destroy_ctx(c, d);
	}
}

static int is_byte_run(dbuf *f, i64 pos1, i64 len, u8 x)
{
	i64 pos = pos1;
	i64 endpos = pos1+len;

	while(pos<endpos) {
		u8 b;

		b = dbuf_getbyte_p(f, &pos);
		if(b!=x) return 0;
	}
	return 1;
}

static int mahj_look_like_a_tile(dbuf *f, i64 pos1)
{
#define MAHJ_NUM_ROWS_TO_TEST  10
	i64 i;
	u8 e1col = 0;
	u8 e2col = 0;
	u8 buf[20];

	// Sample the bytes at the start of some rows, to see if they have
	// the usual colors. Some numbers here are arbitrary.
	for(i=0; i<MAHJ_NUM_ROWS_TO_TEST; i++) {
		u8 v;

		dbuf_read(f, buf, pos1+(i+8)*20, 20);

		// Tile "edges" are 5 pixels on the left side, 1 on the right.
		// We expect edges to be the same for all rows that aren't too
		// close to the top or bottom.
		// (One would also expect all tiles to have the same edges, but there
		// are sets where that's not the case. So it's intentional that we
		// don't test that.)

		if(i==0) {
			e1col = buf[0]&0x0f; // the face of the tile edges
			e2col = buf[2]>>4; // the outline color, usually 0
			if(e1col == e2col) return 0;
		}

		v = buf[0]>>4;    if(v!=e1col && v!=e2col) return 0;
		v = buf[0]&0x0f;  if(v!=e1col) return 0;
		v = buf[1]>>4;    if(v!=e1col) return 0;
		v = buf[1]&0x0f;  if(v!=e1col) return 0;
		v = buf[2]>>4;    if(v!=e2col) return 0;
		v = buf[19]&0x0f; if(v!=e2col) return 0;
	}
	return 1;
}

static int de_identify_mahj_na_til(deark *c)
{
	i64 num_tiles;
	i64 mod800;
	i64 mod128;
	i64 early_tile_idx;
	i64 last_tile_idx;
	u8 is_pad1 = 0;
	u8 is_pad128 = 0;
	u8 have_typical_early_tile = 0;
	u8 have_typical_last_tile = 0;
	int conf = 0;

	// The most difficult part of this format: identifying it.
	if(!de_input_file_has_ext(c, "til")) return 0;

	// Files *should* be exactly 33600 bytes (42 tiles), or 800 for the
	// single-tile format. But...
	// - Another product by the same author, Tile Match, includes a file
	//   with just 10 tiles.
	// - Some files have a 0x1a byte appended.
	// - Some files are padded to the next multiple of 128 bytes.
	// - Some files have extra tiles at the end, that are just blank or
	//   garbage or duplicates.
	// - Some files have extra tiles at the end that have a purpose, such
	//   as comments. The most I've seen is 60 (roadsgn2.til).
	// - Files that are slightly too short also exist, but nearly all of
	//   them seem to be corrupted, so we won't bother with them.

	num_tiles = c->infile->len / MAHJ_TILE_BYTESIZE;
	if(num_tiles<1 || num_tiles>64) goto done;
	mod800 = c->infile->len % MAHJ_TILE_BYTESIZE;
	mod128 = c->infile->len % 128;
	if(mod800==1) {
		is_pad1 = 1;
	}
	else if(mod800>1 && mod800<128 && mod128==0) {
		is_pad128 = 1;
	}
	if(mod800!=0 && !is_pad1 && !is_pad128) return 0;

	if(is_pad1) {
		if(de_getbyte(c->infile->len-1) != 0x1a) return 0;
	}

	if(is_pad128 && num_tiles<42) return 0;
	if(is_pad128 && num_tiles>42) {
		if(is_byte_run(c->infile, 33600, mod128, 0x1a)) {
			;
		}
		else if(dbuf_is_all_zeroes(c->infile, 33600, mod128)) {
			;
		}
		else {
			goto done;
		}
	}

	if(num_tiles<5) {
		early_tile_idx = 0;
	}
	else {
		early_tile_idx = 2;
	}

	have_typical_early_tile = mahj_look_like_a_tile(c->infile,
		early_tile_idx*MAHJ_TILE_BYTESIZE);
	if(num_tiles==1) {
		if(have_typical_early_tile) {
			conf = 25;
		}
		goto done;
	}

	last_tile_idx = (num_tiles>=42)?41:(num_tiles-1);
	have_typical_last_tile = mahj_look_like_a_tile(c->infile,
		last_tile_idx*MAHJ_TILE_BYTESIZE);

	if(num_tiles==42) {
		conf = 15;
		if(have_typical_early_tile && have_typical_last_tile) {
			conf += 70;
		}
		else if(have_typical_early_tile || have_typical_last_tile) {
			conf += 20;
		}
		goto done;
	}

	// At this point:
	// - Number of tiles is not 42, nor 1, nor too large.
	// - No padding, except maybe a single 0x1a.

	if(have_typical_early_tile && have_typical_last_tile) {
		conf = 19;
		goto done;
	}
	if(have_typical_early_tile || have_typical_last_tile) {
		conf = 10;
		goto done;
	}

done:
	return conf;
}

static void de_help_mahj_na_til(deark *c)
{
	de_msg(c, "-opt mahj_na_til:nf=<0|1> : Info about whether the file starts "
		"with an author-name field");
}

void de_module_mahj_na_til(deark *c, struct deark_module_info *mi)
{
	mi->id = "mahj_na_til";
	mi->desc = "Mah Jongg tile set";
	mi->run_fn = de_run_mahj_na_til;
	mi->identify_fn = de_identify_mahj_na_til;
	mi->help_fn = de_help_mahj_na_til;
}

// **************************************************************************
// Mah Jongg -V-G-A- tile or tile set
// By Ron Balewski
// **************************************************************************

#define MJVGA_MAX_TILES      200
#define MJVGA_MAX_TILES_PER_ROW  9
#define MJVGA_BORDER         2
#define MJVGA_TILE_HEADER_SIZE   6
#define MJVGA_TILE_TRAILER_SIZE  2

// Copied from v1.1-2.0 PAL.CFG
static const u8 mjvga_default_pal16[16*3] = {
	27, 0,23, 52,46,37,  0,44,23, 21, 0,63,
	30, 0,11, 63, 5, 5, 63,32,63, 32,32,32,
	30,62,63, 50,40,60, 11,63, 0, 21, 5, 0,
	53,51,45, 63,63, 0, 63,35,10, 63,63,63 };

static void copy_palette_from_rgb18(const u8 *src, de_color *dst, size_t ncolors)
{
	size_t i;

	for(i=0; i<ncolors; i++) {
		u8 clr[3];
		size_t k;

		for(k=0; k<3; k++) {
			clr[k] = de_scale_63_to_255(src[i*3+k]);

		}
		dst[i] = DE_MAKE_RGB(clr[0], clr[1], clr[2]);
	}
}

static int check_mjvga_sig(deark *c, i64 pos)
{
	return !dbuf_memcmp(c->infile, pos, (const void*)"\xa6\x05\x2b\x00\x3b", 5);
}

static int mjvga_read_palette(deark *c, struct mahj_ctx *d, dbuf *palfile, i64 pos1)
{
	size_t i;
	i64 pos = pos1;
	i64 count = 0;

	for(i=0; i<16; i++) {
		int ret;
		i64 content_len;
		i64 total_len;
		char linebuf[32];
		int s1[3] = {0, 0, 0};
		u8 s2[3];
		size_t k;

		ret = dbuf_find_line(palfile, pos, &content_len, &total_len);
		if(!ret || content_len<5) goto done;
		if(content_len > (i64)sizeof(linebuf)-1) goto done;
		dbuf_read(palfile, (u8*)linebuf, pos, content_len);
		linebuf[content_len] = '\0';
		ret = de_sscanf(linebuf, "%d %d %d", &s1[0], &s1[1], &s1[2]);
		if(ret!=3) goto done;
		for(k=0; k<3; k++) {
			s2[k] = de_scale_63_to_255((u8)s1[k]);
		}
		d->pal[i] = DE_MAKE_RGB(s2[0], s2[1], s2[2]);
		de_dbg_pal_entry(c, (i64)i, d->pal[i]);
		count++;
		pos += total_len;
	}
done:
	return (count>=16);
}

static int mjvga_read_palette_file(deark *c, struct mahj_ctx *d,
	const char *palfn)
{
	dbuf *palfile = NULL;
	int retval = 0;
	int ret;

	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) goto done;
	ret = mjvga_read_palette(c, d, palfile, 0);
	if(!ret) {
		de_err(c, "Bad palette file");
		goto done;
	}
	retval = 1;
done:
	dbuf_close(palfile);
	return retval;
}

static void de_run_mjvga(deark *c, de_module_params *mparams)
{
	struct mahj_ctx *d = NULL;
	i64 num_tiles;
	i64 canvas_num_cols;
	i64 canvas_num_rows;
	i64 tile_rowspan;
	i64 tiles_startpos;
	i64 palpos = 0;
	i64 n;
	i64 total_bytes_per_tile;
	i64 canvas_w, canvas_h;
	i64 tile_bprpp;
	const char *palfn = NULL;
	int ret;

	d = de_malloc(c, sizeof(struct mahj_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	palfn = de_get_ext_option(c, "file2");

	if((c->infile->len<=1536) && check_mjvga_sig(c, 0)) {
		;
	}
	else if(check_mjvga_sig(c, 96)) {
		d->mjvga_tis_fmt = 1;
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}
	de_declare_fmtf(c, "Mah Jongg -V-G-A- tile%s", (d->mjvga_tis_fmt?" set":""));

	d->tile_w = (c->padpix ? 48 : 44);
	d->tile_h = 60;
	tile_bprpp = de_pad_to_n(d->tile_w, 8)/8;
	tile_rowspan = tile_bprpp * 4;
	total_bytes_per_tile = MJVGA_TILE_HEADER_SIZE + tile_rowspan*d->tile_h +
		MJVGA_TILE_TRAILER_SIZE;

	if(d->mjvga_tis_fmt) {
		num_tiles = 44;
		tiles_startpos = 96;
		palpos = tiles_startpos + num_tiles*total_bytes_per_tile;

		if(c->infile->len < palpos-MJVGA_TILE_TRAILER_SIZE) {
			d->need_errmsg = 1;
			goto done;
		}
	}
	else {
		num_tiles = 1;
		tiles_startpos = 0;
	}
	de_dbg(c, "num tiles: %d", (int)num_tiles);

	d->name = ucstring_create(c);
	if(d->mjvga_tis_fmt) {
		dbuf_read_to_ucstring(c->infile, 0, 40, d->name,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->name));
	}

	// Start with a default palette
	copy_palette_from_rgb18(mjvga_default_pal16, d->pal, 16);

	if(palfn) {
		de_dbg(c, "palette from cfg file");
		de_dbg_indent(c, 1);
		ret = mjvga_read_palette_file(c, d, palfn);
		de_dbg_indent(c, -1);
		if(!ret) goto done;
	}
	else if(d->mjvga_tis_fmt) {
		de_dbg(c, "palette at %"I64_FMT, palpos);
		de_dbg_indent(c, 1);
		ret = mjvga_read_palette(c, d, c->infile, palpos);
		de_dbg_indent(c, -1);
		if(!ret) {
			de_warn(c, "Bad palette");
		}
	}
	else {
		de_warn(c, "Using a default palette");
	}

	if(num_tiles < MJVGA_MAX_TILES_PER_ROW) {
		canvas_num_cols = num_tiles;
	}
	else {
		canvas_num_cols = MJVGA_MAX_TILES_PER_ROW;
	}
	canvas_num_rows = de_pad_to_n(num_tiles, canvas_num_cols) / canvas_num_cols;

	canvas_w = canvas_num_cols*(d->tile_w+MJVGA_BORDER) - MJVGA_BORDER;
	canvas_h = canvas_num_rows*(d->tile_h+MJVGA_BORDER) - MJVGA_BORDER;
	d->canvas = de_bitmap_create(c, canvas_w, canvas_h, 4);
	d->curtile = de_bitmap_create(c, d->tile_w, d->tile_h, 4);

	if(d->mjvga_tis_fmt) {
		de_dbg(c, "tiles at %"I64_FMT, tiles_startpos);
	}

	for(n=0; n<num_tiles; n++) {
		i64 colnum, rownum;
		i64 cnvpixpos_x, cnvpixpos_y;
		i64 pos;

		pos = tiles_startpos + n*total_bytes_per_tile;
		pos += MJVGA_TILE_HEADER_SIZE;
		colnum = n % canvas_num_cols;
		rownum = n / canvas_num_cols;
		cnvpixpos_x = colnum * (d->tile_w+MJVGA_BORDER);
		cnvpixpos_y = rownum * (d->tile_h+MJVGA_BORDER);

		// Read a tile to a temp bitmap
		de_bitmap_rect(d->curtile, 0, 0, d->tile_w, d->tile_h,
			DE_STOCKCOLOR_TRANSPARENT, 0);
		de_convert_image_paletted_planar(c->infile, pos,
			4, tile_rowspan, tile_bprpp, d->pal, d->curtile, 0x0);

		// Paint the tile to the canvas
		de_bitmap_copy_rect(d->curtile, d->canvas, 0, 0,
			d->tile_w, d->tile_h,
			cnvpixpos_x, cnvpixpos_y, 0);
	}

	de_bitmap_write_to_file(d->canvas, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported TIS or TIL file");
		}
		mahj_destroy_ctx(c, d);
	}
}

static int de_identify_mjvga(deark *c)
{
	// TIL/ICN: Expecting len exactly 1448, but we allow some tolerance.
	if(c->infile->len>=1446 && c->infile->len<=1536) {
		if(check_mjvga_sig(c, 0)) return 91;
	}

	// TIS: Expecting len 63808, plus 16 palette entries, each 7 to 10 bytes.
	// So, 63920 to 63968 bytes.
	if((c->infile->len >= 63808+6*16) && (c->infile->len <= 64000)) {
		if(check_mjvga_sig(c, 96)) return 90;
	}

	return 0;
}

static void de_help_mjvga(deark *c)
{
	de_msg(c, "-file2 <pal.cfg> : The palette file");
}

void de_module_mjvga(deark *c, struct deark_module_info *mi)
{
	mi->id = "mjvga";
	mi->desc = "Mah Jongg -V-G-A- tile or tile set";
	mi->run_fn = de_run_mjvga;
	mi->identify_fn = de_identify_mjvga;
	mi->help_fn = de_help_mjvga;
}

// **************************************************************************
// Mindjongg .ipg
// **************************************************************************

struct mindjongg_ctx {
	u8 fmtver;
	u8 need_errmsg;
	i64 fixed_hdr_pos;
	i64 index_seg_pos;
	i64 index_seg_len;
	i64 image_seg_pos;
	i64 num_items;
	i64 img_count;
	de_finfo *fi;
};

static void mindjongg_extract(deark *c, struct mindjongg_ctx *d,
	i64 img_pos, i64 img_len, UI img_type,
	const char *token)
{
	const char *ext = NULL;
	struct fmtutil_fmtid_ctx *idctx = NULL;

	if(img_pos==0 || img_len==0 || img_type==0xffffffffU) goto done;

	// Known image type codes: 0=BMP, 1=GIF, 2=JPG, 3=TGA.
	// (I suspect PNG might also be supported, but I've never seen it.)
	// Except for TGA, which is hard to detect, we'll just autodetect the
	// format.
	if(img_type==3) {
		ext = "tga";
	}

	if(!ext) {
		idctx = de_malloc(c, sizeof(struct fmtutil_fmtid_ctx));
		idctx->inf = c->infile;
		idctx->inf_pos = img_pos;
		idctx->inf_len = img_len;
		idctx->mode = FMTUTIL_FMTIDMODE_ALL_IMG;
		fmtutil_fmtid(c, idctx);
		if(idctx->fmtid) {
			ext = idctx->ext_sz;
		}
	}

	if(ext) {
		de_finfo_set_name_from_sz(c, d->fi, token, 0, DE_ENCODING_LATIN1);
		dbuf_create_file_from_slice(c->infile, img_pos, img_len, ext, d->fi, 0);
	}
	else {
		de_err(c, "Unidentified image type (%u)", img_type);
	}
done:
	de_free(c, idctx);
}

static void do_mindjongg_v1(deark *c, struct mindjongg_ctx *d)
{
	i64 n;
	i64 pos;
	i64 i;
	i64 first_imgpos;
	UI k;
	char tmps[24];

	pos = 10;
	// Skip two length-prefixed strings
	for(k=0; k<2; k++) {
		n = (i64)de_getbyte_p(&pos);
		pos += n;
	}

	d->fixed_hdr_pos = pos;
	d->index_seg_pos = d->fixed_hdr_pos+72;
	de_dbg(c, "index pos: %"I64_FMT, d->index_seg_pos);

	// I don't know how to figure out how many items there are.
	// (An "item" is a slot. It may be empty, or contain an image.)
	// The first item is for something like an icon. We'll hope
	// it's always present, and always starts right after the item
	// array. With those assumptions, we can figure out how many
	// items there are.

	first_imgpos = de_getu32le(d->index_seg_pos);
	d->index_seg_len = first_imgpos - d->index_seg_pos;
	de_dbg(c, "apparent index size: %"I64_FMT, d->index_seg_len);

	// Smallest seen is 108 (9*12), though 72 (6*12) might be possible.
	// Largest seen is 180 (15*12).
	if(d->index_seg_len<72 || d->index_seg_len>288 ||
		(d->index_seg_len%36 != 0))
	{
		d->need_errmsg = 1;
		goto done;
	}
	d->num_items = d->index_seg_len / 12;
	de_dbg(c, "num items: %"I64_FMT, d->num_items);

	d->img_count = 0;
	pos = d->index_seg_pos;
	for(i=0; i<d->num_items; i++) {
		i64 img_pos;
		i64 img_len;
		UI img_type;

		img_pos = de_getu32le_p(&pos);
		img_len = de_getu32le_p(&pos);
		img_type = (UI)de_getu32le_p(&pos);

		if(img_pos==0 || img_len==0 || img_type==0xffffffffU) {
			de_dbg(c, "item[%d]: (empty)", (int)i);
			continue;
		}

		de_dbg(c, "item[%d]: pos=%"I64_FMT", len=%"I64_FMT", type=%u",
			(int)i, img_pos, img_len, img_type);
		if(img_pos + img_len > c->infile->len) {
			d->need_errmsg = 1;
			goto done;
		}

		d->img_count++;

		if(i==0) {
			de_strlcpy(tmps, "icon", sizeof(tmps));
		}
		else if(i>=3 && i%3==0) {
			de_snprintf(tmps, sizeof(tmps), "size%dtiles", (int)(i/3));
		}
		else if(i>=3 && i%3==1) {
			de_snprintf(tmps, sizeof(tmps), "size%dmask", (int)(i/3));
		}
		else if(i>=3 && i%3==2) {
			de_snprintf(tmps, sizeof(tmps), "size%dedges", (int)(i/3));
		}
		else {
			de_strlcpy(tmps, "", sizeof(tmps));
		}

		mindjongg_extract(c, d, img_pos, img_len, img_type, tmps);
	}

	de_dbg2(c, "images found: %"I64_FMT, d->img_count);

done:
	;
}

static void do_mindjongg_v3_image(deark *c, struct mindjongg_ctx *d,
	i64 pos1, int img_idx)
{
	i64 img_pos;
	i64 img_len;
	UI img_type;
	i64 pos = pos1;
	const char *token = NULL;

	img_pos = de_getu32le_p(&pos);
	img_type = (UI)de_getu32le_p(&pos);
	img_len = de_getu32le_p(&pos);

	if(img_pos==0 || img_len==0 || img_type==0xffffffffU) {
		de_dbg(c, "item[%d]: (empty)", img_idx);
		goto done;
	}

	de_dbg(c, "item[%d]: pos=%"I64_FMT", len=%"I64_FMT", type=%u",
		img_idx, img_pos, img_len, img_type);

	if(img_pos<(d->fixed_hdr_pos+140) || img_pos+img_len > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	switch(img_idx) {
	case 0: token = "tiles"; break;
	case 1: token = "mask"; break;
	case 2: token = "misc"; break;
	}

	mindjongg_extract(c, d, img_pos, img_len, img_type, token);
done:
	;
}

static void do_mindjongg_v3(deark *c, struct mindjongg_ctx *d)
{
	i64 n;
	i64 pos;
	UI k;

	pos = 30;
	// Skip four length-prefixed strings
	for(k=0; k<4; k++) {
		n = de_getu32le_p(&pos);
		pos += n*2;
	}

	if(pos>=c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	// We expect to be at a 140-byte structure, preceding the images.
	d->fixed_hdr_pos = pos;
	do_mindjongg_v3_image(c, d, d->fixed_hdr_pos+40, 0);
	do_mindjongg_v3_image(c, d, d->fixed_hdr_pos+68, 1);
	do_mindjongg_v3_image(c, d, d->fixed_hdr_pos+80, 2);

done:
	;
}

static void de_run_mindjongg(deark *c, de_module_params *mparams)
{
	struct mindjongg_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct mindjongg_ctx));
	d->fi = de_finfo_create(c);

	if(de_getbyte(1) == 'I') {
		d->fmtver = 1;
	}
	else if(de_getbyte(4) == 'I') {
		d->fmtver = 3;
	}

	if(d->fmtver==0) {
		d->need_errmsg = 1;
		goto done;
	}

	de_declare_fmtf(c, "Mindjongg tileset (%s)",
		(d->fmtver==3?"new":"old"));

	if(d->fmtver==3) {
		do_mindjongg_v3(c, d);
	}
	else {
		do_mindjongg_v1(c, d);
	}

done:
	if(d) {
		de_finfo_destroy(c, d->fi);
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported Mindjongg IPG file");
		}
		de_free(c, d);
	}
}

static int de_identify_mindjongg(deark *c)
{
	if(de_getbyte(0) != 0x05) return 0;
	if(!dbuf_memcmp(c->infile, 1,
		"\x49\x50\x4b\x30\x31\x01\0\0\0", 9)) {
		return 100;
	}
	if(!dbuf_memcmp(c->infile, 1,
		"\0\0\0\x49\0\x50\0\x4b\0\x30\0\x33\0\x03\0\0\0", 17)) {
		return 100;
	}
	return 0;
}

void de_module_mindjongg(deark *c, struct deark_module_info *mi)
{
	mi->id = "mindjongg";
	mi->desc = "Mindjongg tileset";
	mi->run_fn = de_run_mindjongg;
	mi->identify_fn = de_identify_mindjongg;
}
