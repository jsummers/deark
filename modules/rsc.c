// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM (Atari) .RSC resource file

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rsc);

#define RSCFMT_UNKNOWN 0
// ATARI means Atari-style (big-endian). Not necessarily limited to that platform.
#define RSCFMT_ATARI   1
#define RSCFMT_PC      2

#define MAX_RSC_ICON_WIDTH 1024
#define MAX_RSC_ICON_HEIGHT 1024

typedef struct localctx_struct {
	deark *c;
	de_ext_encoding input_encoding;
	int fmt;
	int is_le;
	u8 decode_objects;
	u8 allow_unaligned_offsets;
	i64 version;
	i64 object_offs, object_num;
	i64 objecttree_num;
	i64 iconblk_offs, iconblk_num;
	i64 bitblk_offs, bitblk_num;
	i64 imagedata_offs;
	i64 imagepointertable_offs;
	i64 rssize;
	i64 cicon_offs;
	i64 reported_file_size;
	i64 avail_file_size;

	i64 num_ciconblk;
	de_color pal16[16];
	de_color pal256[256];
} lctx;

struct iconinfo {
	i64 width, height;
	i64 mono_rowspan;
	i64 nplanes;
	de_ucstring *icon_text;
};

static int is_valid_segment_pos(deark *c, lctx *d, i64 pos, i64 len, const char *name)
{
	int ok_start = 1;
	int ok_end = 1;

	if(pos<36 && len>0) ok_start = 0;
	if(pos>d->avail_file_size) ok_start = 0;
	if(!d->allow_unaligned_offsets && (pos%2)) ok_start = 0;
	if(pos+len > d->avail_file_size) ok_end = 0;

	if(ok_start && ok_end) return 1;
	if(ok_start && !ok_end && len>=2) {
		de_err(c, "Invalid %s location: %"I64_FMT"-%"I64_FMT, name, pos, pos+len-1);
	}
	else {
		de_err(c, "Invalid %s location: %"I64_FMT, name, pos);
	}
	return 0;
}

static void destroy_iconinfo(deark *c, struct iconinfo *ii)
{
	if(!ii) return;
	if(ii->icon_text) {
		ucstring_destroy(ii->icon_text);
	}
	de_free(c, ii);
}

static i64 gem_getu16(lctx *d, i64 pos)
{
	return dbuf_getu16x(d->c->infile, pos, d->is_le);
}

static i64 gem_getu16m1(lctx *d, i64 pos)
{
	i64 n = gem_getu16(d, pos);
	if(n==0xffff) n = -1;
	return n;
}

static i64 gem_getu32(lctx *d, i64 pos)
{
	return dbuf_getu32x(d->c->infile, pos, d->is_le);
}

static i64 gem_getu32m1(lctx *d, i64 pos)
{
	i64 n = gem_getu32(d, pos);
	if(n==0xffffffffLL) n = -1;
	return n;
}

static void do_decode_bilevel_image(deark *c, lctx *d, de_bitmap *img, i64 bits_pos,
	i64 rowspan)
{
	i64 i, j;
	i64 rowspan_in_16bit_chunks;
	UI k;
	UI n;

	rowspan_in_16bit_chunks = (rowspan+1)/2;

	for(j=0; j<img->height; j++) {
		for(i=0; i<rowspan_in_16bit_chunks; i++) {
			n = (UI)gem_getu16(d, bits_pos + j*rowspan + i*2);
			for(k=0; k<16; k++) {
				u8 clr;

				clr = (n & (1U<<(15-k))) ? 0 : 0xff;
				de_bitmap_setpixel_gray(img, i*16+(i64)k, j, clr);
			}
		}
	}
}

static void do_decode_and_write_bilevel_image(deark *c, lctx *d, i64 bits_pos,
	i64 rowspan, i64 width, i64 height)
{
	de_bitmap *img = NULL;

	if(!is_valid_segment_pos(c, d, bits_pos, rowspan*height, "bitmap")) {
		goto done;
	}
	if(!de_good_image_dimensions(c, width, height)) {
		goto done;
	}

	img = de_bitmap_create(c, width, height, 1);
	do_decode_bilevel_image(c, d, img, bits_pos, rowspan);
	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_bitmap_destroy(img);
}

static int do_scan_iconblk(deark *c, lctx *d, i64 pos1, struct iconinfo *ii)
{
	i64 pos;

	// TODO: Refactor this code to better share it with old- and new-style RSC.

	pos = pos1;
	ii->width = gem_getu16(d, pos+22);
	ii->height = gem_getu16(d, pos+24);
	de_dbg_dimensions(c, ii->width, ii->height);
	if(ii->width<1 || ii->width>MAX_RSC_ICON_WIDTH ||
		ii->height<1 || ii->height>MAX_RSC_ICON_HEIGHT)
	{
		de_dbg(c, "bad or unexpected icon dimensions");
		return 0;
	}
	return 1;
}

static void set_icon_finfo(deark *c, lctx *d, de_finfo *fi, struct iconinfo *ii,
	const char *token)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	if(ucstring_isnonempty(ii->icon_text)) {
		ucstring_append_ucstring(s, ii->icon_text);
	}

	if(token) {
		if(ucstring_isnonempty(s)) {
			ucstring_append_char(s, '.');
		}
		ucstring_append_sz(s, token, DE_ENCODING_UTF8);
	}

	de_finfo_set_name_from_ucstring(c, fi, s, 0x0);
	ucstring_destroy(s);
}

static void do_bilevel_icon(deark *c, lctx *d, struct iconinfo *ii, i64 fg_pos,
	i64 mask_pos, const char *token)
{
	de_bitmap *img = NULL;
	de_bitmap *mask = NULL;
	de_finfo *fi = NULL;

	if(!is_valid_segment_pos(c, d, fg_pos, ii->height*ii->mono_rowspan, "bitmap")) {
		goto done;
	}
	if(!is_valid_segment_pos(c, d, mask_pos, ii->height*ii->mono_rowspan, "mask")) {
		goto done;
	}
	if(!de_good_image_dimensions(c, ii->width, ii->height)) {
		goto done;
	}

	img = de_bitmap_create(c, ii->width, ii->height, 2);
	mask = de_bitmap_create(c, ii->width, ii->height, 1);
	do_decode_bilevel_image(c, d, img, fg_pos, ii->mono_rowspan);
	do_decode_bilevel_image(c, d, mask, mask_pos, ii->mono_rowspan);
	de_bitmap_apply_mask(img, mask, DE_BITMAPFLAG_WHITEISTRNS);
	fi = de_finfo_create(c);
	set_icon_finfo(c, d, fi, ii, token);
	de_bitmap_write_to_file_finfo(img, fi, 0);

done:
	de_bitmap_destroy(img);
	de_bitmap_destroy(mask);
	de_finfo_destroy(c, fi);
}

static int do_old_iconblk(deark *c, lctx *d, i64 pos)
{
	i64 mask_pos, fg_pos;
	int retval = 0;
	struct iconinfo *ii = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	ii = de_malloc(c, sizeof(struct iconinfo));

	de_dbg(c, "ICONBLK at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	if(!do_scan_iconblk(c, d, pos, ii)) goto done;

	mask_pos = gem_getu32(d, pos);
	fg_pos = gem_getu32(d, pos+4);
	de_dbg(c, "fg at %"I64_FMT, fg_pos);
	de_dbg(c, "mask at %"I64_FMT, mask_pos);

	ii->mono_rowspan = ((ii->width+15)/16)*2;
	do_bilevel_icon(c, d, ii, fg_pos, mask_pos, "1");

	retval = 1;
done:
	destroy_iconinfo(c, ii);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// TODO: This palette may not be correct.
static const de_color pal16[16] = {
	0xffffff,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xc0c0c0,
	0x808080,0xff8080,0x80ff80,0xffff80,0x8080ff,0xff80ff,0x80ffff,0x000000
};

// FIXME: This palette is incomplete, and probably inaccurate.
static const de_color supplpal1[16] = {
	0xffffff,0xef0000,0x00e700,0xffff00,0x0000ef,0xcd05cd,0xcd06cd,0xd6d6d6, // 00-07
	0x808080,0x7b0000,0x008000,0xb5a531,0x000080,0x7f007f,0x007b7b,0x101810  // 08-ff
};

static const de_color supplpal2[26] = {
	                                                      0xef0000,0xe70000, // e6-e7
	0xbd0000,0xad0000,0x7b0000,0x4a0000,0x100000,0xcdedcd,0xcdeecd,0x00bd00, // e8-ef
	0x00b500,0xcdf1cd,0x004a00,0x001800,0x000010,0x00004f,0xcdf6cd,0x0000af, // f0-f7
	0x293194,0x0000e0,0xeff7ef,0xe7e7e7,0xc0c0c0,0xadb5ad,0x4a4a4a,0x000000  // f8-ff
};

static de_color getpal16(unsigned int k)
{
	if(k>=16) return 0;
	return pal16[k];
}

static de_color getpal256(unsigned int k)
{
	unsigned int x;
	u8 r, g, b;

	if(k<=15) {
		// first 16 entries
		return supplpal1[k];
	}
	else if(k<=229) {
		// next 214 entries
		x = k-15;
		r = (u8)((x/36)*0x33);
		g = ((x%36)/6)*0x33;
		b = (x%6)*0x33;
		return DE_MAKE_RGB(r,g,b);
	}
	else if(k<=255) {
		// last 26 entries
		return supplpal2[k-230];
	}
	return 0;
}

static void construct_palettes(deark *c, lctx *d)
{
	UI k;

	for(k=0; k<16; k++) {
		d->pal16[k] = DE_MAKE_OPAQUE(getpal16(k));
	}
	for(k=0; k<256; k++) {
		d->pal256[k] = DE_MAKE_OPAQUE(getpal256(k));
	}
}

// FIXME: This probably doesn't work for PC format (little-endian).
static void do_color_icon(deark *c, lctx *d, struct iconinfo *ii, i64 fg_pos,
	i64 mask_pos, const char *token)
{
	de_bitmap *img = NULL;
	de_bitmap *mask = NULL;
	de_finfo *fi = NULL;
	i64 planespan;
	const de_color *pal_to_use;

	if(ii->nplanes!=4 && ii->nplanes!=8) {
		de_warn(c, "%d-plane icons not supported", (int)ii->nplanes);
		goto done;
	}

	if(d->pal16[0]==0) {
		construct_palettes(c, d);
	}

	if(ii->nplanes==4) {
		pal_to_use = d->pal16;
	}
	else {
		pal_to_use = d->pal256;
	}

	if(!de_good_image_dimensions(c, ii->width, ii->height)) {
		goto done;
	}

	img = de_bitmap_create(c, ii->width, ii->height, 4);
	mask = de_bitmap_create(c, ii->width, ii->height, 1);

	planespan = ii->mono_rowspan * ii->height;
	de_convert_image_paletted_planar(c->infile, fg_pos, ii->nplanes,
		ii->mono_rowspan, planespan, pal_to_use, img, 0x2);

	do_decode_bilevel_image(c, d, mask, mask_pos, ii->mono_rowspan);
	de_bitmap_apply_mask(img, mask, DE_BITMAPFLAG_WHITEISTRNS);

	fi = de_finfo_create(c);
	set_icon_finfo(c, d, fi, ii, token);
	de_bitmap_write_to_file_finfo(img, fi, 0);

done:
	de_bitmap_destroy(img);
	de_bitmap_destroy(mask);
	de_finfo_destroy(c, fi);
}

static int do_ciconblk_struct(deark *c, lctx *d, i64 icon_idx, i64 pos1,
	i64 *bytes_consumed)
{
	struct iconinfo *ii = NULL;
	i64 pos;
	i64 n_cicons;
	i64 mono_bitmapsize;
	i64 color_bitmapsize;
	i64 next_res;
	i64 sel_data_flag;
	int retval = 0;
	i64 i;
	i64 mono_fgpos, mono_maskpos;
	int saved_indent_level;
	char token[16];

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "CICONBLK[%d] at %"I64_FMT, (int)icon_idx, pos1);
	de_dbg_indent(c, 1);

	ii = de_malloc(c, sizeof(struct iconinfo));

	pos = pos1;
	if(!do_scan_iconblk(c, d, pos, ii)) {
		goto done;
	}
	pos+=34;

	n_cicons = gem_getu32(d, pos);
	de_dbg(c, "number of color depths for this icon: %d", (int)n_cicons);
	pos += 4;

	ii->mono_rowspan = ((ii->width+15)/16)*2; // guess

	de_dbg2(c, "bilevel image data at %"I64_FMT" (deferred)", pos);
	mono_bitmapsize = ii->mono_rowspan * ii->height;
	mono_fgpos = pos;
	pos += mono_bitmapsize; // foreground
	mono_maskpos = pos;
	pos += mono_bitmapsize; // mask
	de_dbg2(c, "bilevel image data ends at %"I64_FMT, pos);

	if(!ii->icon_text) {
		ii->icon_text = ucstring_create(c);
	}
	ucstring_empty(ii->icon_text);
	dbuf_read_to_ucstring(c->infile, pos, 12, ii->icon_text, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "icon text: \"%s\"", ucstring_getpsz_d(ii->icon_text));
	pos += 12;

	// Go back and read the bilevel icon. (We wanted to read the icon text first.)
	de_dbg(c, "bilevel image data at %"I64_FMT, mono_fgpos);
	de_dbg_indent(c, 1);
	de_dbg(c, "fg at %"I64_FMT, mono_fgpos);
	de_dbg(c, "mask at %"I64_FMT, mono_maskpos);
	do_bilevel_icon(c, d, ii, mono_fgpos, mono_maskpos, "1");
	de_dbg_indent(c, -1);

	for(i=0; i<n_cicons; i++) {
		if(pos >= c->infile->len) goto done;
		de_dbg(c, "color depth %d of %d, at %"I64_FMT, (int)(i+1), (int)n_cicons, pos);
		de_dbg_indent(c, 1);

		ii->nplanes = gem_getu16(d, pos);
		de_dbg(c, "planes: %d", (int)ii->nplanes);
		pos += 2;

		pos += 4; // col_data (placeholder)
		pos += 4; // col_mask (placeholder)

		sel_data_flag = gem_getu32(d, pos);
		de_dbg(c, "sel_data flag: %d", (int)sel_data_flag);
		pos += 4; // sel_data

		pos += 4; // sel_mask (placeholder)

		next_res = gem_getu32(d, pos);
		de_dbg(c, "next_res flag: %d", (int)next_res);
		pos += 4;

		color_bitmapsize = mono_bitmapsize * ii->nplanes;

		de_dbg(c, "unselected image at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		de_dbg(c, "fg at %"I64_FMT, pos);
		de_dbg(c, "mask at %"I64_FMT, pos+color_bitmapsize);
		de_snprintf(token, sizeof(token), "%d", (int)ii->nplanes);
		do_color_icon(c, d, ii, pos, pos+color_bitmapsize, token);
		pos += color_bitmapsize; // color_data
		pos += mono_bitmapsize; // color_mask
		de_dbg_indent(c, -1);

		if(sel_data_flag) {
			de_dbg(c, "selected image at %"I64_FMT, pos);
			de_dbg_indent(c, 1);
			de_dbg(c, "fg at %"I64_FMT, pos);
			de_dbg(c, "mask at %"I64_FMT, pos+color_bitmapsize);
			de_snprintf(token, sizeof(token), "%d.sel", (int)ii->nplanes);
			do_color_icon(c, d, ii, pos, pos+color_bitmapsize, token);
			pos += color_bitmapsize; // select_data
			pos += mono_bitmapsize; // select_mask
			de_dbg_indent(c, -1);
		}

		*bytes_consumed = pos - pos1;

		de_dbg_indent(c, -1);
	}

	retval = 1;
done:
	destroy_iconinfo(c, ii);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_cicon_ptr_table(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 n;
	i64 count = 0;
	i64 pos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = pos1;
	*bytes_consumed = 0;

	de_dbg(c, "CICONBLK pointer table at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		if(pos>=d->avail_file_size) {
			// error
			goto done;
		}

		// Values are expected to be 0. We just have to find the -1 that marks
		// the end of this scratch space.
		n = gem_getu32m1(d, pos);
		de_dbg3(c, "item[%d]: %"I64_FMT, (int)count, n);
		pos+=4;

		if(n<0) {
			break;
		}
		count++;
	}

	d->num_ciconblk = count;
	de_dbg(c, "count of CICONBLKs: %d", (int)d->num_ciconblk);
	*bytes_consumed = pos - pos1;
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_cicon(deark *c, lctx *d)
{
	i64 bytes_consumed;
	int ret;
	i64 pos1;
	i64 pos;
	i64 i;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!is_valid_segment_pos(c, d, d->cicon_offs, 1, "CICON segment")) {
		goto done;
	}
	pos1 = d->cicon_offs;
	de_dbg(c, "CICON file segment at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;
	ret = do_cicon_ptr_table(c, d, pos, &bytes_consumed);
	if(!ret) goto done;
	pos += bytes_consumed;

	for(i=0; i<d->num_ciconblk; i++) {
		if(pos>=d->avail_file_size) goto done;
		ret = do_ciconblk_struct(c, d, i, pos, &bytes_consumed);
		if(!ret) goto done;
		pos += bytes_consumed;
	}
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_extension_array(deark *c, lctx *d)
{
	i64 pos;

	pos = d->rssize;
	de_dbg(c, "extension array at %"I64_FMT, d->rssize);
	de_dbg_indent(c, 1);
	if(!is_valid_segment_pos(c, d, d->rssize, 8, "Extension Array")) goto done;

	d->reported_file_size = gem_getu32(d, pos);
	de_dbg(c, "reported file size: %"I64_FMT, d->reported_file_size);
	d->avail_file_size = de_min_int(d->reported_file_size, c->infile->len);

	d->cicon_offs = gem_getu32m1(d, pos+4);
	if(d->cicon_offs==0) goto done;
	de_dbg(c, "CICON offset: %"I64_FMT, d->cicon_offs);

done:
	de_dbg_indent(c, -1);
}

#define OBJTYPE_IMAGE   23
#define OBJTYPE_ICON    31
#define OBJTYPE_CLRICON 33

static const char *get_obj_type_name(u8 t)
{
	const char *s = NULL;

	switch(t) {
	case 20: s="box"; break;
	case 21: s="formatted text"; break;
	case 22: s="formatted text in a box"; break;
	case OBJTYPE_IMAGE: s="image"; break;
	case 24: s="programmer-defined object"; break;
	case 25: s="invisible box"; break;
	case 26: s="push button w/string"; break;
	case 27: s="character in a box"; break;
	case 28: s="unformatted text"; break;
	case 29: s="editable formatted text"; break;
	case 30: s="editable formatted text in a box"; break;
	case OBJTYPE_ICON: s="icon"; break;
	case 32: s="menu title"; break;
	case OBJTYPE_CLRICON: s="clricon"; break;
	}
	return s?s:"?";
}

// The OBJECT table contains references to the bitmaps and icons in the file.
// It's not clear if we have to read it, because there are also pointers in
// the file header.
// TODO: Do we need to read it to get the true width of BITBLK images?
// TODO: We may need to read it to identify color icons in old-style RSC.
static int do_object(deark *c, lctx *d, i64 obj_index, i64 pos)
{
	i64 obj_type_orig;
	u8 obj_type;
	i64 next_sibling, first_child, last_child;
	i64 ob_spec;
	i64 width, height;

	de_dbg(c, "OBJECT #%d at %d", (int)obj_index, (int)pos);
	de_dbg_indent(c, 1);

	next_sibling = gem_getu16m1(d, pos);
	first_child = gem_getu16m1(d, pos+2);
	last_child = gem_getu16m1(d, pos+4);
	de_dbg(c, "next sibling: %d, first child: %d, last child: %d",
		(int)next_sibling, (int)first_child, (int)last_child);

	obj_type_orig = gem_getu16(d, pos+6);
	obj_type = (u8)(obj_type_orig&0xff);

	de_dbg(c, "type: 0x%04x (%u; %s)", (unsigned int)obj_type_orig,
		(unsigned int)obj_type, get_obj_type_name(obj_type));

	ob_spec = gem_getu32(d, pos+12);
	de_dbg(c, "ob_spec: %u (0x%08x)", (unsigned int)ob_spec, (unsigned int)ob_spec);

	// Note: This does not seem to read the width and height fields correctly.
	// Don't know what I'm doing wrong.
	// (Fortunately, we don't necessarily need them.)
	width = gem_getu16(d, pos+20);
	height = gem_getu16(d, pos+22);
	de_dbg_dimensions(c, width, height);

	de_dbg_indent(c, -1);
	return 1;
}

static int do_bitblk(deark *c, lctx *d, i64 pos)
{
	i64 bits_pos;
	i64 width_in_bytes;
	i64 width, height;
	i64 fgcol;

	de_dbg(c, "BITBLK at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	bits_pos = gem_getu32(d, pos);
	de_dbg(c, "bitmap pos: %"I64_FMT, bits_pos);
	width_in_bytes = gem_getu16(d, pos+4);
	width = width_in_bytes*8;
	de_dbg(c, "width in bytes: %d", (int)width_in_bytes);
	height = gem_getu16(d, pos+6);
	de_dbg_dimensions(c, width, height);
	fgcol = gem_getu16(d, pos+12);
	de_dbg(c, "foreground color: 0x%04x", (unsigned int)fgcol);
	// TODO: Can we do anything with the foreground color?

	do_decode_and_write_bilevel_image(c, d, bits_pos, width_in_bytes, width, height);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_OBJECTs(deark *c, lctx *d)
{
	i64 i;

	if(d->object_num<=0) return;
	de_dbg(c, "OBJECTs at %"I64_FMT, d->object_offs);
	if(!is_valid_segment_pos(c, d, d->object_offs, 24*d->object_num, "OBJECT table")) {
		return;
	}
	if(!d->decode_objects) return;

	de_dbg_indent(c, 1);
	for(i=0; i<d->object_num; i++) {
		if(d->object_offs + 24*(i+1) > d->avail_file_size) break;
		do_object(c, d, i, d->object_offs + 24*i);
	}
	de_dbg_indent(c, -1);
}

static void do_BITBLKs(deark *c, lctx *d)
{
	i64 i;

	if(d->bitblk_num<=0) return;
	de_dbg(c, "BITBLKs at %"I64_FMT, d->bitblk_offs);
	if(!is_valid_segment_pos(c, d, d->bitblk_offs, 14*d->bitblk_num, "BITBLK table")) {
		return;
	}
	de_dbg_indent(c, 1);
	for(i=0; i<d->bitblk_num; i++) {
		if(d->bitblk_offs + 14*(i+1) > d->avail_file_size) break;
		do_bitblk(c, d, d->bitblk_offs + 14*i);
	}
	de_dbg_indent(c, -1);
}

static void do_ICONBLKs(deark *c, lctx *d)
{
	i64 i;

	if(d->iconblk_num<=0) return;
	de_dbg(c, "ICONBLKs at %"I64_FMT, d->iconblk_offs);
	if(!is_valid_segment_pos(c, d, d->iconblk_offs, 34*d->iconblk_num, "ICONBLK table")) {
		return;
	}
	de_dbg_indent(c, 1);
	for(i=0; i<d->iconblk_num; i++) {
		if(d->iconblk_offs + 34*(i+1) > d->avail_file_size) break;
		do_old_iconblk(c, d, d->iconblk_offs + 34*i);
	}
	de_dbg_indent(c, -1);
}

static void detect_rsc_format(deark *c, lctx *d)
{
	i64 n_be, n_le;
	i64 pos;

	// Check the version number. Assumes PC format is always 0.
	n_be = de_getu16be(0);
	if(n_be != 0) {
		d->fmt = RSCFMT_ATARI;
		return;
	}

	// Check the (old-style) file size field
	n_le = de_getu16le(34);
	n_be = de_getu16be(34);
	if(n_le != n_be) {
		if(n_be==c->infile->len) {
			d->fmt = RSCFMT_ATARI;
			return;
		}
		if(n_le==c->infile->len) {
			d->fmt = RSCFMT_PC;
			return;
		}
	}

	// Check some file offsets
	for(pos=2; pos<=18; pos+=2) {
		n_le = de_getu16le(pos);
		if(n_le==0 || n_le==0xffff) continue;
		n_be = de_getu16be(pos);
		if(n_le > c->infile->len) {
			d->fmt = RSCFMT_ATARI;
			return;
		}
		if(n_be > c->infile->len) {
			d->fmt = RSCFMT_PC;
			return;
		}
		// Offsets should be even, I think.
		if(n_le&0x1) {
			d->fmt = RSCFMT_ATARI;
			return;
		}
		if(n_be&0x1) {
			d->fmt = RSCFMT_PC;
			return;
		}
	}

	// TODO: Is it worth doing more checks?
}

static void de_run_rsc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *tmps;

	d = de_malloc(c, sizeof(lctx));
	d->c = c;
	d->avail_file_size = c->infile->len; // Starting value. Will be adjusted later.

	d->fmt = RSCFMT_UNKNOWN;
	tmps = de_get_ext_option(c, "rsc:fmt");
	if(tmps) {
		if(!de_strcmp(tmps, "pc")) {
			d->fmt = RSCFMT_PC;
		}
		else if(!de_strcmp(tmps, "atari")) {
			d->fmt = RSCFMT_ATARI;
		}
	}

	if(d->fmt==RSCFMT_UNKNOWN) {
		detect_rsc_format(c, d);
	}

	if(d->fmt==RSCFMT_UNKNOWN) {
		d->fmt = RSCFMT_ATARI;
	}

	if(d->fmt==RSCFMT_PC) {
		de_declare_fmt(c, "GEM RSC, PC");
		d->is_le = 1;
	}
	else {
		de_declare_fmt(c, "GEM RSC, Atari");
	}

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);
	if(d->input_encoding==DE_ENCODING_UNKNOWN) {
		if(d->fmt==RSCFMT_ATARI) {
			d->input_encoding = DE_ENCODING_ATARIST;
		}
		else {
			// TODO?: This should probably be the "GEM character set", but we don't
			// support that.
			d->input_encoding = DE_ENCODING_ASCII;
		}
	}

	d->decode_objects = 1;
	// TODO: For Atari format, maybe we can disallow unaligned offsets.
	d->allow_unaligned_offsets = 1;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);
	d->version = gem_getu16(d, 0);
	de_dbg(c, "version: 0x%04x", (int)d->version);

	d->object_offs = gem_getu16(d, 2);
	d->iconblk_offs = gem_getu16(d, 6);
	d->bitblk_offs = gem_getu16(d, 8);
	d->imagedata_offs = gem_getu16(d, 14);
	d->imagepointertable_offs = gem_getu16(d, 16);
	d->object_num = gem_getu16(d, 20);
	d->objecttree_num = gem_getu16(d, 22);
	d->iconblk_num = gem_getu16(d, 26);
	d->bitblk_num = gem_getu16(d, 28);
	d->rssize = gem_getu16(d, 34);

	de_dbg(c, "OBJECT: %d at %d", (int)d->object_num, (int)d->object_offs);
	de_dbg(c, "num object trees: %d", (int)d->objecttree_num);
	de_dbg(c, "ICONBLK: %d at %d", (int)d->iconblk_num, (int)d->iconblk_offs);
	de_dbg(c, "BITBLK: %d at %d", (int)d->bitblk_num, (int)d->bitblk_offs);
	de_dbg(c, "imagedata: at %d", (int)d->imagedata_offs);
	de_dbg(c, "imagepointertable: at %d", (int)d->imagepointertable_offs);
	if(d->version & 0x0004) {
		de_dbg(c, "extension array offset: %"I64_FMT, d->rssize);
	}
	else {
		de_dbg(c, "reported file size: %"I64_FMT, d->rssize);
		d->reported_file_size = d->rssize;
		d->avail_file_size = de_min_int(d->reported_file_size, c->infile->len);
	}
	de_dbg_indent(c, -1);

	if(d->version & 0x0004) {
		do_extension_array(c, d);
	}
	else if(d->version==0 || d->version==1) {
		;
	}
	else {
		de_err(c, "Unknown or unsupported version of RSC");
		goto done;
	}

	do_OBJECTs(c, d);
	do_BITBLKs(c, d);
	do_ICONBLKs(c, d);
	if(d->version & 0x0004) {
		do_cicon(c, d);
	}

done:
	de_free(c, d);
}

// TODO: This needs to be improved, but it's complicated.
static int de_identify_rsc(deark *c)
{
	i64 ver;

	if(!de_input_file_has_ext(c, "rsc")) return 0;
	ver = de_getu16be(0);
	if(ver==0 || ver==1 || ver==4) return 70;
	return 0;
}

static void de_help_rsc(deark *c)
{
	de_msg(c, "-opt rsc:fmt=<atari|pc> : Use this byte order");
}

void de_module_rsc(deark *c, struct deark_module_info *mi)
{
	mi->id = "rsc";
	mi->desc = "GEM resource file";
	mi->run_fn = de_run_rsc;
	mi->identify_fn = de_identify_rsc;
	mi->help_fn = de_help_rsc;
}
