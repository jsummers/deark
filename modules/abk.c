// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// AMOS sprite/icon bank, etc.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_abk);
DE_DECLARE_MODULE(de_module_amos_source);

#define CODE_AmBk 0x416d426bU
#define CODE_AmBs 0x416d4273U
#define CODE_AmIc 0x416d4963U
#define CODE_AmSp 0x416d5370U
#define AMOS_SCR_HDR_ID  0x12031990
#define AMOS_PIC_HDR_ID  0x06071963

// Data related to the whole file.
typedef struct localctx_AMOS {
	u32 fmt;
	int opt_allownopal;
} lctx;

// Data related to a "bank". Most files consist of one bank, but some have
// multiple banks.
struct amosbank {
	struct de_fourcc banktype4cc;
	i64 bank_len;
	i64 bank_data_len;
	dbuf *f;
	const char *file_ext;

	i64 num_objects;
	i64 pal_pos;
	u32 pal[256];

	// per-image settings
	i64 xsize; // 16-bit words per row per plane
	i64 ysize;
	i64 nplanes;
	i64 max_planes;

	// Picture Bank settings
	i64 pic_rledata_offset;
	i64 pic_points_offset;
	i64 pic_picdata_offset;
	i64 picdata_expected_unc_bytes;
	u32 amiga_mode;
};

static void destroy_amosbank(deark *c, struct amosbank *bk)
{
	if(!bk) return;
	dbuf_close(bk->f);
	de_free(c, bk);
}

static void do_read_sprite_image(deark *c, lctx *d, struct amosbank *bk, i64 pos)
{
	i64 width, height;
	i64 rowspan, planespan;
	de_bitmap *img = NULL;

	width = bk->xsize * 16;
	height = bk->ysize;

	de_dbg_dimensions(c, width, height);
	de_dbg(c, "planes: %d", (int)bk->nplanes);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	if(bk->nplanes<1 || bk->nplanes>6) {
		de_err(c, "Unsupported number of planes: %d", (int)bk->nplanes);
		goto done;
	}

	img = de_bitmap_create(c, width, height, 4);

	rowspan = bk->xsize*2;
	planespan = rowspan*bk->ysize;
	de_convert_image_paletted_planar(bk->f, pos, bk->nplanes,
		rowspan, planespan, bk->pal, img, 0x2);

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int do_sprite_object(deark *c, lctx *d, struct amosbank *bk, i64 obj_idx,
	i64 pos, int pass, i64 *bytes_consumed)
{

	if(pass==2) {
		de_dbg(c, "object #%d at %d", (int)obj_idx, (int)pos);
	}
	de_dbg_indent(c, 1);

	bk->xsize = dbuf_getu16be(bk->f, pos);
	bk->ysize = dbuf_getu16be(bk->f, pos+2);
	bk->nplanes = dbuf_getu16be(bk->f, pos+4);

	if(pass==1) {
		if(bk->nplanes > bk->max_planes) {
			bk->max_planes = bk->nplanes;
		}
	}

	if(pass==2) {
		do_read_sprite_image(c, d, bk, pos+10);
	}

	*bytes_consumed = 10 + (bk->xsize*bk->ysize*bk->nplanes*2);

	de_dbg_indent(c, -1);
	return 1;
}

// pass 1 is just to find the location of the palette/
// pass 2 decodes the images.
static void do_read_sprite_objects(deark *c, lctx *d, struct amosbank *bk, i64 pos, int pass)
{
	int ret;
	i64 bytes_consumed;
	i64 obj_idx;

	de_dbg(c, "pass %d", pass);

	obj_idx = 0;
	while(1) {
		if(pos >= bk->f->len) break;
		if(obj_idx >= bk->num_objects) break;
		bytes_consumed = 0;
		ret = do_sprite_object(c, d, bk, obj_idx, pos, pass, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;
		pos += bytes_consumed;
		obj_idx++;
	}

	if(pass==1) {
		bk->pal_pos = pos;
		bk->bank_len = bk->pal_pos + 64;
		de_dbg(c, "palette offset: %d", (int)bk->pal_pos);
		de_dbg(c, "bank len: %d", (int)bk->bank_len);
	}
}

static void do_read_sprite_palette(deark *c, lctx *d, struct amosbank *bk)
{
	i64 k;
	unsigned int n;
	u8 cr, cg, cb;
	u8 cr1, cg1, cb1;
	i64 pos;
	i64 colors_used;
	char tmps[64];

	pos = bk->pal_pos;
	de_dbg(c, "palette at %d", (int)pos);
	de_dbg_indent(c, 1);

	colors_used = de_pow2(bk->max_planes);

	for(k=0; k<32; k++) {
		n = (unsigned int)dbuf_getu16be(bk->f, pos+k*2);
		cr1 = (u8)((n>>8)&0xf);
		cg1 = (u8)((n>>4)&0xf);
		cb1 = (u8)(n&0xf);
		cr = cr1*17;
		cg = cg1*17;
		cb = cb1*17;
		bk->pal[k] = DE_MAKE_RGB(cr, cg, cb);
		de_snprintf(tmps, sizeof(tmps), "0x%04x (%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
			n, (int)cr1, (int)cg1, (int)cb1);
		de_dbg_pal_entry2(c, k, bk->pal[k], tmps, NULL,
			(k>=colors_used)?" [unused]":"");

		// Set up colors #32-63 for 6-plane "Extra Half-Brite" mode.
		// For normal images (<=5 planes), these colors won't be used.
		bk->pal[k+32] = DE_MAKE_RGB(cr/2, cg/2, cb/2);
	}

	bk->pal[0] = DE_SET_ALPHA(bk->pal[0], 0); // First color is transparent.
	// (Don't know if pal[32] should be transparent also.)

	de_dbg_indent(c, -1);
}

// AmSp or AmIc
static int do_read_sprite(deark *c, lctx *d, struct amosbank *bk)
{
	bk->num_objects = dbuf_getu16be(bk->f, 4);
	de_dbg(c, "number of objects: %d", (int)bk->num_objects);

	do_read_sprite_objects(c, d, bk, 6, 1);

	if(d->fmt==CODE_AmBs) {
		dbuf_create_file_from_slice(bk->f, 0, bk->bank_len, bk->file_ext, NULL, 0);
	}
	else {
		do_read_sprite_palette(c, d, bk);

		do_read_sprite_objects(c, d, bk, 6, 2);
	}

	return 1;
}

#define MEMBANKTYPE_DATAS    1
#define MEMBANKTYPE_MUSIC    2
#define MEMBANKTYPE_PICTURE  3
#define MEMBANKTYPE_ASM      4
#define MEMBANKTYPE_AMAL     5
#define MEMBANKTYPE_SAMPLES  6

struct membankinfo {
	int type;
	const u8 name[8];
	const char *file_ext;
};
static const struct membankinfo membankinfo_arr[] = {
	{ MEMBANKTYPE_DATAS,    {'D','a','t','a','s',' ',' ',' '}, "data.abk" },
	{ MEMBANKTYPE_MUSIC,    {'M','u','s','i','c',' ',' ',' '}, "music.abk" },
	{ MEMBANKTYPE_PICTURE,  {'P','a','c','.','P','i','c','.'}, "pic.abk" },
	{ MEMBANKTYPE_ASM,      {'A','s','m',' ',' ',' ',' ',' '}, "asm.abk" },
	{ MEMBANKTYPE_AMAL,     {'A','m','a','l',' ',' ',' ',' '}, "amal.abk" },
	{ MEMBANKTYPE_SAMPLES,  {'S','a','m','p','l','e','s',' '}, "samples.abk" },
	{ 0, {0,0,0,0,0,0,0,0}, NULL }
};

// 90-byte "Screen header"
// Has information about the intended display device. Not much of this
// is useful, other than the palette.
static void picture_bank_screen_header(deark *c, lctx *d, struct amosbank *bk, i64 pos)
{
	i64 screen_width, screen_height;
	i64 ncolors;
	i64 nplanes;

	de_dbg(c, "screen header at %d", (int)pos);
	de_dbg_indent(c, 1);

	screen_width = dbuf_getu16be(bk->f, pos+4);
	screen_height = dbuf_getu16be(bk->f, pos+6);
	de_dbg(c, "screen dimensions: %d"DE_CHAR_TIMES"%d", (int)screen_width, (int)screen_height);

	bk->amiga_mode = (u32)dbuf_getu16be(bk->f, pos+20);
	ncolors = dbuf_getu16be(bk->f, pos+22);
	nplanes = dbuf_getu16be(bk->f, pos+24);

	de_dbg(c, "screen mode: 0x%04x, colors: %d, planes: %d",
		(unsigned int)bk->amiga_mode, (int)ncolors, (int)nplanes);

	bk->pal_pos = pos + 26;

	// Set bk->max_planes, so that do_read_sprite_palette doesn't print
	// "[unused]".
	// TODO: We could look ahead at the picture header to figure out how many
	// palette entries are used. Or we could just guess that it's the same as
	// 'nplanes' in the screen header.
	bk->max_planes = 5;
	do_read_sprite_palette(c, d, bk);
	bk->max_planes = 0;

	de_dbg_indent(c, -1);
}

struct pictbank_params {
	u8 ok;
	UI num_planes;
	UI bits_per_pixel;
	i64 width_in_bytes;
	i64 height_in_lumps;
	i64 lines_per_lump;
	i64 pseudoheight;
	dbuf *unc_pixels;
	de_bitmap *img;
	de_color *pal;
};

// TODO: Consolidate this with the similar function in mbk.c.
// (Deferred for now. Should probably at least investigate HAM picture banks,
// first.)
static void render_stos_pictbank(deark *c, struct pictbank_params *pb)
{
	i64 planesize;
	i64 lump;
	u8 xbuf[8];

	if((size_t)pb->num_planes > sizeof(xbuf)) goto done;
	if(pb->bits_per_pixel != pb->num_planes) goto done;
	de_zeromem(xbuf, sizeof(xbuf));
	planesize = pb->width_in_bytes * pb->pseudoheight;

	for(lump=0; lump<pb->height_in_lumps; lump++) {
		i64 col_idx;
		i64 lump_start_srcpos_in_plane;
		i64 lump_start_ypos;

		lump_start_srcpos_in_plane = pb->width_in_bytes * pb->lines_per_lump * lump;
		lump_start_ypos = pb->lines_per_lump * lump;

		for(col_idx=0; col_idx<pb->width_in_bytes; col_idx++) {
			i64 col_start_srcpos_in_plane;
			i64 ypos_in_lump;

			col_start_srcpos_in_plane = lump_start_srcpos_in_plane +
				pb->lines_per_lump*col_idx;

			for(ypos_in_lump=0; ypos_in_lump<pb->lines_per_lump; ypos_in_lump++) {
				UI i;
				UI pn;
				i64 xpos, ypos;

				ypos = lump_start_ypos + ypos_in_lump;

				for(pn=0; pn<pb->num_planes; pn++) {
					xbuf[pn] = dbuf_getbyte(pb->unc_pixels, planesize*pn +
						col_start_srcpos_in_plane + ypos_in_lump);
				}

				for(i=0; i<8; i++) {
					UI palent;

					palent = 0;
					for(pn=0; pn<pb->bits_per_pixel; pn++) {
						if(xbuf[pn] & (1<<(7-i))) {
							palent |= (1<<pn);
						}
					}

					xpos = col_idx*8 + i;
					de_bitmap_setpixel_rgb(pb->img, xpos, ypos, pb->pal[palent]);
				}
			}
		}
	}

	pb->ok = 1;

done:
	;
}

static void picture_bank_read_picture(deark *c, lctx *d, struct amosbank *bk, i64 pos)
{
	i64 bytes_per_row_per_plane;
	i64 height_in_lumps;
	i64 lines_per_lump;
	i64 width, height;
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	struct pictbank_params *pb = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "picture header at %d", (int)pos);
	de_dbg_indent(c, 1);

	// 24-byte "Picture header"

	bytes_per_row_per_plane = dbuf_getu16be(bk->f, pos+8);
	de_dbg(c, "bytes per row per plane: %d", (int)bytes_per_row_per_plane);
	width = bytes_per_row_per_plane * 8;

	height_in_lumps = dbuf_getu16be(bk->f, pos+10);
	de_dbg(c, "height in lumps: %d", (int)height_in_lumps);
	lines_per_lump = dbuf_getu16be(bk->f, pos+12);
	de_dbg(c, "lines per lump: %d", (int)lines_per_lump);
	height = height_in_lumps * lines_per_lump;

	de_dbg(c, "calculated dimensions: %d"DE_CHAR_TIMES"%d", (int)width, (int)height);

	bk->nplanes = dbuf_getu16be(bk->f, pos+14);
	de_dbg(c, "number of bitplanes: %d", (int)bk->nplanes);

	bk->pic_rledata_offset = dbuf_getu32be(bk->f, pos+16);
	de_dbg(c, "rledata offset: %d (file offset: %d)", (int)bk->pic_rledata_offset,
		(int)(pos+bk->pic_rledata_offset));
	bk->pic_rledata_offset += pos; // Convert to absolute offset

	bk->pic_points_offset = dbuf_getu32be(bk->f, pos+20);
	de_dbg(c, "points offset: %d (file offset: %d)", (int)bk->pic_points_offset,
		(int)(pos+bk->pic_points_offset));
	bk->pic_points_offset += pos; // Convert to absolute offset

	if(!de_good_image_dimensions(c, width, height)) goto done;
	if(bk->nplanes<1 || bk->nplanes>6) {
		de_err(c, "Unsupported number of planes: %d", (int)bk->nplanes);
		goto done;
	}

	de_dbg_indent(c, -1);

	bk->pic_picdata_offset = pos + 24;
	de_dbg(c, "picdata at %d", (int)bk->pic_picdata_offset);

	bk->picdata_expected_unc_bytes = bytes_per_row_per_plane * bk->nplanes * height;
	unc_pixels = dbuf_create_membuf(c, bk->picdata_expected_unc_bytes, 0);
	fmtutil_decompress_stos_pictbank(c, c->infile, bk->pic_picdata_offset,
		bk->pic_rledata_offset, bk->pic_points_offset,
		unc_pixels, bk->picdata_expected_unc_bytes);
	img = de_bitmap_create(c, width, height, 3);

	pb = de_malloc(c, sizeof(struct pictbank_params));
	pb->num_planes = (UI)bk->nplanes;
	pb->bits_per_pixel = pb->num_planes;
	pb->width_in_bytes = bytes_per_row_per_plane;
	pb->height_in_lumps = height_in_lumps;
	pb->lines_per_lump = lines_per_lump;
	pb->pseudoheight = height;
	pb->unc_pixels = unc_pixels;
	pb->img = img;
	pb->pal = bk->pal;

	render_stos_pictbank(c, pb);

	de_bitmap_write_to_file(img, NULL, 0);
done:
	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
	de_free(c, pb);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void picture_bank_make_palette(deark *c, lctx *d, struct amosbank *bk)
{
	i64 k;
	u8 v;

	for(k=0; k<32; k++) {
		v = (u8)(0.5+ ((double)k)*(255.0/31.0));
		bk->pal[k] = DE_MAKE_GRAY(v);
		bk->pal[k+32] = DE_MAKE_GRAY(v/2);
	}
}

static void do_picture_bank(deark *c, lctx *d, struct amosbank *bk, i64 pos1)
{
	i64 pos = pos1;
	u32 segtype;
	int found_screen_header = 0;

	de_dbg(c, "picture bank");
	de_dbg_indent(c, 1);

	segtype = (u32)de_getu32be(pos);
	if(segtype==AMOS_SCR_HDR_ID) {
		found_screen_header = 1;
		picture_bank_screen_header(c, d, bk, pos);
		pos += 90;

		// TODO: Support HAM
		if(bk->amiga_mode & 0x0800) {
			de_err(c, "HAM Picture Bank images are not supported.");
			goto done;
		}

		segtype = (u32)de_getu32be(pos);
	}

	if(segtype!=AMOS_PIC_HDR_ID) {
		de_err(c, "Missing Picture Header");
		goto done;
	}

	if(!found_screen_header) {
		if(d->opt_allownopal<1) {
			de_warn(c, "No palette found. Can't decode this image.%s",
				(d->opt_allownopal<0 ?
					" (Use \"-opt abk:allownopal\" to try anyway.)" : ""));
			goto done;
		}
		de_warn(c, "No palette found. Using grayscale palette.");
		picture_bank_make_palette(c, d, bk);
	}

	picture_bank_read_picture(c, d, bk, pos);

done:
	de_dbg_indent(c, -1);
}

static void do_amos_picture_file(deark *c, lctx *d)
{
	struct amosbank *bk = NULL;

	bk = de_malloc(c, sizeof(struct amosbank));
	bk->f = dbuf_open_input_subfile(c->infile, 0, c->infile->len);
	// I don't think we need to set anything like bk->bank_len.
	do_picture_bank(c, d, bk, 0);
	destroy_amosbank(c, bk);
}

static int do_read_AmBk(deark *c, lctx *d, struct amosbank *bk)
{
	i64 banknum;
	i64 bank_len_code;
	i64 bank_len_raw;
	int membanktype = 0;
	const struct membankinfo *mbi = NULL;
	struct de_stringreaderdata *srd = NULL;
	i64 i;
	int retval = 0;

	if(bk->f->len < 20) goto done;

	banknum = dbuf_getu16be(bk->f, 4);
	de_dbg(c, "bank number (1-15): %d", (int)banknum);

	bank_len_code = dbuf_getu32be(bk->f, 8);
	bank_len_raw = bank_len_code & 0x0fffffff;
	bk->bank_len = bank_len_raw+12;
	bk->bank_data_len = bank_len_raw-8;
	de_dbg(c, "bank length: %d (dlen=%d, tlen=%d)", (int)bank_len_raw,
		(int)bk->bank_data_len, (int)bk->bank_len);

	srd = dbuf_read_string(bk->f, 12, 8, 8, 0, DE_ENCODING_ASCII);
	de_dbg(c, "bank name: \"%s\"", ucstring_getpsz(srd->str));

	if(bk->bank_data_len<0) goto done;

	for(i=0; membankinfo_arr[i].type!=0; i++) {
		if(!de_memcmp(srd->sz, membankinfo_arr[i].name, 8)) {
			mbi = &membankinfo_arr[i];
			break;
		}
	}

	if(mbi) {
		membanktype = mbi->type;
		bk->file_ext = mbi->file_ext;
	}

	if(d->fmt==CODE_AmBs) {
		// If original file is in AmBs format, just extract the AmBk file.
		dbuf_create_file_from_slice(bk->f, 0, bk->bank_len, bk->file_ext, NULL, 0);
		retval = 1;
		goto done;
	}

	switch(membanktype) {
	case MEMBANKTYPE_PICTURE:
		do_picture_bank(c, d, bk, 20); // 20 to advance past AmBk header
		retval = 1;
		goto done;
	}

	if(c->extract_level>=2) {
		// Extracting the raw memory-bank data can be useful sometimes.
		dbuf_create_file_from_slice(bk->f, 20, bk->bank_data_len, "bin", NULL, 0);
	}

	retval = 1;
done:
	de_destroy_stringreaderdata(c, srd);
	return retval;
}

static int do_read_bank(deark *c, lctx *d, i64 pos, i64 *bytesused)
{
	struct amosbank *bk = NULL;
	int ret;
	int retval = 0;

	bk = de_malloc(c, sizeof(struct amosbank));
	bk->f = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);

	dbuf_read_fourcc(bk->f, 0, &bk->banktype4cc, 4, 0x0);
	de_dbg(c, "bank type '%s'", bk->banktype4cc.id_dbgstr);

	switch(bk->banktype4cc.id) {
	case CODE_AmIc: bk->file_ext = "icon.abk"; break;
	case CODE_AmSp: bk->file_ext = "sprite.abk"; break;
	case CODE_AmBk: bk->file_ext = "AmBk.abk"; break;
	default: bk->file_ext = "abk";
	}

	if(bk->banktype4cc.id==CODE_AmIc || bk->banktype4cc.id==CODE_AmSp) {
		ret = do_read_sprite(c, d, bk);
		retval = ret;
		*bytesused = bk->bank_len;
	}
	else if(bk->banktype4cc.id==CODE_AmBk) {
		ret = do_read_AmBk(c, d, bk);
		retval = ret;
		*bytesused = bk->bank_len;
	}
	else {
		de_err(c, "Unsupported bank type: '%s'", bk->banktype4cc.id_sanitized_sz);
	}

	destroy_amosbank(c, bk);
	return retval;
}

static void do_read_AmBs(deark *c, lctx *d)
{
	i64 bytesused;
	i64 nbanks;
	i64 i;
	i64 pos;
	int ret;

	nbanks = de_getu16be(4);
	de_dbg(c, "number of banks: %d", (int)nbanks);

	pos = 6;
	for(i=0; i<nbanks; i++) {
		if(pos >= c->infile->len) break;
		de_dbg(c, "bank #%d at %d", (int)i, (int)pos);
		bytesused = 0;
		de_dbg_indent(c, 1);
		ret = do_read_bank(c, d, pos, &bytesused);
		de_dbg_indent(c, -1);
		if(!ret || bytesused<1) break;
		pos += bytesused;
	}
}

static void de_run_abk(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 bytesused = 0;

	d = de_malloc(c, sizeof(lctx));
	d->opt_allownopal = de_get_ext_option_bool(c, "abk:allownopal", -1);

	d->fmt = (u32)de_getu32be(0);

	if(d->fmt==CODE_AmBk) {
		de_declare_fmt(c, "AMOS Memory Bank");
	}
	else if(d->fmt==CODE_AmSp) {
		de_declare_fmt(c, "AMOS Sprite Bank");
	}
	else if(d->fmt==CODE_AmIc) {
		de_declare_fmt(c, "AMOS Icon Bank");
	}
	else if(d->fmt==CODE_AmBs) {
		de_declare_fmt(c, "AMOS AmBs format");
	}
	else if(d->fmt==AMOS_SCR_HDR_ID) {
		de_declare_fmt(c, "AMOS picture, with screen header");
	}
	else if(d->fmt==AMOS_PIC_HDR_ID) {
		de_declare_fmt(c, "AMOS picture, no screen header");
	}
	else {
		de_err(c, "Unsupported format");
		goto done;
	}

	if(d->fmt==CODE_AmBk ||d->fmt==CODE_AmSp || d->fmt==CODE_AmIc) {
		do_read_bank(c, d, 0, &bytesused);
	}
	else if(d->fmt==CODE_AmBs) {
		do_read_AmBs(c, d);
	}
	else if(d->fmt==AMOS_SCR_HDR_ID || d->fmt==AMOS_PIC_HDR_ID) {
		do_amos_picture_file(c, d);
	}

done:
	de_free(c, d);
}

static int is_amos_picture_file(deark *c, UI sig)
{
	UI x;
	i64 picpos;

	if(sig==AMOS_SCR_HDR_ID) {
		picpos = 90;
	}
	else if(sig==AMOS_PIC_HDR_ID) {
		// Need to be careful here, because some STOS formats also
		// start this way.
		picpos = 0;
	}
	else {
		return 0;
	}

	x = (UI)de_getu32be(picpos);
	if(x!=AMOS_PIC_HDR_ID) return 0;
	x = (UI)de_getu16be(picpos+14); // # bitplanes
	if(x>=1 && x<=6) {
		return 1;
	}
	return 0;
}

static int de_identify_abk(deark *c)
{
	int ext_bonus = 0;
	UI sig;

	if(de_input_file_has_ext(c, "abk")) ext_bonus=40;

	sig = (UI)de_getu32be(0);
	if(sig==CODE_AmBk)
		return 60+ext_bonus;
	if(sig==CODE_AmSp)
		return 60+ext_bonus;
	if(sig==CODE_AmIc)
		return 60+ext_bonus;
	if(sig==CODE_AmBs)
		return 60+ext_bonus;
	if(sig==AMOS_SCR_HDR_ID || sig==AMOS_PIC_HDR_ID) {
		if(is_amos_picture_file(c, sig)) {
			return 60+ext_bonus;
		}
	}

	return 0;
}

static void de_help_abk(deark *c)
{
	de_msg(c, "-opt abk:allownopal : Try to decode images lacking a palette");
}

void de_module_abk(deark *c, struct deark_module_info *mi)
{
	mi->id = "abk";
	mi->desc = "AMOS resource (AmBk, sprite, icon, AmBs)";
	mi->run_fn = de_run_abk;
	mi->identify_fn = de_identify_abk;
	mi->help_fn = de_help_abk;
}

static void de_run_amos_source(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 basic_len;
	i64 pos;
	i64 nbanks;

	d = de_malloc(c, sizeof(lctx));

	pos = 16;
	basic_len = de_getu32be(pos);
	pos += 4;
	de_dbg(c, "BASIC code at %d, len=%d", (int)pos, (int)basic_len);
	pos += basic_len;
	if(pos >= c->infile->len) goto done;
	if(dbuf_memcmp(c->infile, pos, "AmBs", 4)) {
		de_err(c, "AmBs segment not found, expected at offset %d", (int)pos);
		goto done;
	}

	de_dbg(c, "AmBs segment at %d", (int)pos);
	nbanks = de_getu16be(pos+4);
	de_dbg_indent(c, 1);
	de_dbg(c, "number of banks: %d", (int)nbanks);
	if(nbanks>0 || c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, pos, c->infile->len-pos, "AmBs.abk", NULL, 0);
	}
	else {
		de_dbg(c, "not extracting empty AmBs segment");
	}
	de_dbg_indent(c, -1);


done:
	de_free(c, d);
}

static int de_identify_amos_source(deark *c)
{
	u8 b[10];
	int ext_bonus = 0;

	if(de_input_file_has_ext(c, "amos")) ext_bonus=20;

	de_read(b, 0, 10);
	if(!de_memcmp(b, "AMOS Basic", 10))
		return 80+ext_bonus;
	if(!de_memcmp(b, "AMOS Pro", 8))
		return 80+ext_bonus;
	return 0;
}

void de_module_amos_source(deark *c, struct deark_module_info *mi)
{
	mi->id = "amos_source";
	mi->desc = "AMOS source code";
	mi->run_fn = de_run_amos_source;
	mi->identify_fn = de_identify_amos_source;
}
