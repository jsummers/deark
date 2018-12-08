// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM (Atari) .RSC resource file

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rsc);

typedef struct localctx_struct {
	int decode_objects;
	i64 version;
	i64 object_offs, object_num;
	i64 objecttree_num;
	i64 iconblk_offs, iconblk_num;
	i64 bitblk_offs, bitblk_num;
	i64 imagedata_offs;
	i64 imagepointertable_offs;
	i64 rssize;

	i64 num_ciconblk;
} lctx;

struct iconinfo {
	i64 width, height;
	i64 mono_rowspan;
	i64 nplanes;
};

static int do_scan_iconblk(deark *c, lctx *d, i64 pos1, struct iconinfo *ii)
{
	i64 pos;

	// TODO: Refactor this code to better share it with old- and new-style RSC.

	de_dbg(c, "ICONBLK at %d", (int)pos1);
	pos = pos1;
	ii->width = de_getu16be(pos+22);
	ii->height = de_getu16be(pos+24);
	de_dbg_dimensions(c, ii->width, ii->height);
	if(!de_good_image_dimensions(c, ii->width, ii->height)) {
		return 0;
	}
	return 1;
}

static void do_bilevel_icon(deark *c, lctx *d, struct iconinfo *ii, i64 fg_pos,
	i64 mask_pos, const char *token)
{
	i64 i, j;
	u8 n, a;
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, ii->width, ii->height, 2);

	for(j=0; j<ii->height; j++) {
		for(i=0; i<ii->width; i++) {
			n = de_get_bits_symbol(c->infile, 1, fg_pos + j*ii->mono_rowspan, i);
			a = de_get_bits_symbol(c->infile, 1, mask_pos + j*ii->mono_rowspan, i);
			n = n ? 0 : 255;
			a = a ? 255 : 0;
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(n,n,n,a));
		}
	}

	de_bitmap_write_to_file(img, token, 0);
	de_bitmap_destroy(img);
}

static int do_old_iconblk(deark *c, lctx *d, i64 pos)
{
	i64 mask_pos, fg_pos;
	int retval = 0;
	struct iconinfo *ii = NULL;

	ii = de_malloc(c, sizeof(struct iconinfo));

	if(!do_scan_iconblk(c, d, pos, ii)) goto done;

	mask_pos = de_getu32be(pos);
	fg_pos = de_getu32be(pos+4);
	de_dbg(c, "bitmap at %d, mask at %d", (int)fg_pos, (int)mask_pos);

	ii->mono_rowspan = ((ii->width+15)/16)*2;
	do_bilevel_icon(c, d, ii, fg_pos, mask_pos, "1");

	retval = 1;
done:
	de_free(c, ii);
	return retval;
}

// TODO: This palette may not be correct.
static const u32 pal16[16] = {
	0xffffff,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xc0c0c0,
	0x808080,0xff8080,0x80ff80,0xffff80,0x8080ff,0xff80ff,0x80ffff,0x000000
};

// FIXME: This palette is incomplete, and probably inaccurate.
static const u32 supplpal1[16] = {
	0xffffff,0xef0000,0x00e700,0xffff00,0x0000ef,0xcd05cd,0xcd06cd,0xd6d6d6, // 00-07
	0x808080,0x7b0000,0x008000,0xb5a531,0x000080,0x7f007f,0x007b7b,0x101810  // 08-ff
};

static const u32 supplpal2[26] = {
	                                                      0xef0000,0xe70000, // e6-e7
	0xbd0000,0xad0000,0x7b0000,0x4a0000,0x100000,0xcdedcd,0xcdeecd,0x00bd00, // e8-ef
	0x00b500,0xcdf1cd,0x004a00,0x001800,0x000010,0x00004f,0xcdf6cd,0x0000af, // f0-f7
	0x293194,0x0000e0,0xeff7ef,0xe7e7e7,0xc0c0c0,0xadb5ad,0x4a4a4a,0x000000  // f8-ff
};

static u32 getpal16(unsigned int k)
{
	if(k>=16) return 0;
	return pal16[k];
}

static u32 getpal256(unsigned int k)
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

static void do_color_icon(deark *c, lctx *d, struct iconinfo *ii, i64 fg_pos,
	i64 mask_pos, const char *token)
{
	i64 i, j;
	u8 a;
	de_bitmap *img = NULL;
	i64 plane;
	i64 planespan;
	u8 b;
	unsigned int v;
	u32 clr;

	if(ii->nplanes!=4 && ii->nplanes!=8) {
		de_warn(c, "%d-plane icons not supported", (int)ii->nplanes);
		return;
	}

	img = de_bitmap_create(c, ii->width, ii->height, 4);

	planespan = ii->mono_rowspan * ii->height;

	for(j=0; j<ii->height; j++) {
		for(i=0; i<ii->width; i++) {
			v = 0;
			for(plane=0; plane<ii->nplanes; plane++) {
				b = de_get_bits_symbol(c->infile, 1,
					fg_pos + j*ii->mono_rowspan + plane*(planespan), i);
				if(b) v |= 1<<plane;
			}
			if(ii->nplanes==4)
				clr = getpal16(v);
			else
				clr = getpal256(v);

			a = de_get_bits_symbol(c->infile, 1, mask_pos + j*ii->mono_rowspan, i);
			a = a ? 255 : 0;

			de_bitmap_setpixel_rgba(img, i, j, DE_SET_ALPHA(clr, a));
		}
	}

	de_bitmap_write_to_file(img, token, 0);
	de_bitmap_destroy(img);
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
	char token[16];

	de_dbg(c, "-- icon #%d --", (int)icon_idx);
	de_dbg_indent(c, 1);

	ii = de_malloc(c, sizeof(struct iconinfo));

	pos = pos1;
	if(!do_scan_iconblk(c, d, pos, ii)) {
		goto done;
	}
	pos+=34;

	n_cicons = de_getu32be(pos);
	de_dbg(c, "number of color depths for this icon: %d", (int)n_cicons);
	pos += 4;

	ii->mono_rowspan = ((ii->width+15)/16)*2; // guess

	mono_bitmapsize = ii->mono_rowspan * ii->height;

	de_dbg(c, "-- bilevel image --");
	do_bilevel_icon(c, d, ii, pos, pos+mono_bitmapsize, "1");

	pos += mono_bitmapsize; // foreground
	pos += mono_bitmapsize; // mask

	// TODO: Use the text in the filename?
	pos += 12; // icon_text

	for(i=0; i<n_cicons; i++) {
		de_dbg(c, "-- color depth %d of %d --", (int)(i+1), (int)n_cicons);
		de_dbg_indent(c, 1);

		ii->nplanes = de_getu16be(pos);
		de_dbg(c, "planes: %d", (int)ii->nplanes);
		pos += 2;

		pos += 4; // col_data (placeholder)
		pos += 4; // col_mask (placeholder)

		sel_data_flag = de_getu32be(pos);
		de_dbg(c, "sel_data flag: %d", (int)sel_data_flag);
		pos += 4; // sel_data

		pos += 4; // sel_mask (placeholder)

		next_res = de_getu32be(pos);
		de_dbg(c, "next_res_flag: %d", (int)next_res);
		pos += 4;

		color_bitmapsize = mono_bitmapsize * ii->nplanes;

		de_dbg(c, "-- unselected image --");
		de_dbg_indent(c, 1);
		de_snprintf(token, sizeof(token), "%d", (int)ii->nplanes);
		do_color_icon(c, d, ii, pos, pos+color_bitmapsize, token);
		pos += color_bitmapsize; // color_data
		pos += mono_bitmapsize; // color_mask
		de_dbg_indent(c, -1);

		if(sel_data_flag) {
			de_dbg(c, "-- selected image --");
			de_dbg_indent(c, 1);
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
	de_free(c, ii);
	de_dbg_indent(c, -1);
	return retval;
}

static int do_cicon_ptr_table(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 n;
	i64 count = 0;
	i64 pos;

	pos = pos1;
	*bytes_consumed = 0;

	while(1) {
		if(pos>=c->infile->len) {
			// error
			return 0;
		}

		n = de_getu32be(pos);
		pos+=4;

		if(n==0xffffffffU) {
			break;
		}
		count++;
	}

	d->num_ciconblk = count;
	de_dbg(c, "CICONBLK pointer table at %d indicates %d CICONBLKs", (int)pos1, (int)d->num_ciconblk);
	*bytes_consumed = pos - pos1;
	return 1;
}

static int do_cicon(deark *c, lctx *d, i64 pos1)
{
	i64 bytes_consumed;
	int ret;
	i64 pos;
	i64 i;

	pos = pos1;
	ret = do_cicon_ptr_table(c, d, pos, &bytes_consumed);
	if(!ret) return 0;
	pos += bytes_consumed;

	for(i=0; i<d->num_ciconblk; i++) {
		ret = do_ciconblk_struct(c, d, i, pos, &bytes_consumed);
		if(!ret) return 0;
		pos += bytes_consumed;
	}
	return 1;
}

static void do_newformat(deark *c, lctx *d)
{
	i64 pos;
	i64 rsc_file_size;
	i64 cicon_offs;

	de_dbg(c, "extension array offset: %d", (int)d->rssize);

	pos = d->rssize;

	rsc_file_size = de_getu32be(pos);
	de_dbg(c, "reported rsc file size: %d", (int)rsc_file_size);

	cicon_offs = de_getu32be(pos+4);
	if(cicon_offs!=0 && cicon_offs!=0xffffffffU) {
		de_dbg(c, "CICON offset: %d", (int)cicon_offs);
		do_cicon(c, d, cicon_offs);
	}
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

	next_sibling = de_getu16be(pos);
	if(next_sibling==0xffff) next_sibling = -1;
	first_child = de_getu16be(pos+2);
	if(first_child==0xffff) first_child = -1;
	last_child = de_getu16be(pos+4);
	if(last_child==0xffff) last_child = -1;
	de_dbg(c, "next sibling: %d, first child: %d, last child: %d",
		(int)next_sibling, (int)first_child, (int)last_child);

	obj_type_orig = de_getu16be(pos+6);
	obj_type = (u8)(obj_type_orig&0xff);

	de_dbg(c, "type: 0x%04x (%u; %s)", (unsigned int)obj_type_orig,
		(unsigned int)obj_type, get_obj_type_name(obj_type));

	ob_spec = de_getu32be(pos+12);
	de_dbg(c, "ob_spec: %u (0x%08x)", (unsigned int)ob_spec, (unsigned int)ob_spec);

	// Note: This does not seem to read the width and height fields correctly.
	// Don't know what I'm doing wrong.
	// (Fortunately, we don't necessarily need them.)
	width = de_getu16be(pos+20);
	height = de_getu16be(pos+22);
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

	de_dbg(c, "BITBLK struct at %d", (int)pos);
	de_dbg_indent(c, 1);

	bits_pos = de_getu32be(pos);
	de_dbg(c, "bitmap pos: %d", (int)bits_pos);
	width_in_bytes = de_getu16be(pos+4);
	width = width_in_bytes*8;
	de_dbg(c, "width in bytes: %d", (int)width_in_bytes);
	height = de_getu16be(pos+6);
	de_dbg_dimensions(c, width, height);
	fgcol = de_getu16be(pos+12);
	de_dbg(c, "foreground color: 0x%04x", (unsigned int)fgcol);
	// TODO: Can we do anything with the foreground color?

	de_convert_and_write_image_bilevel(c->infile, bits_pos, width, height, width_in_bytes,
		DE_CVTF_WHITEISZERO, NULL, 0);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_oldformat(deark *c, lctx *d)
{
	i64 i;

	de_dbg(c, "reported resource file size: %d", (int)d->rssize);

	// OBJECT
	if(d->decode_objects) {
		for(i=0; i<d->object_num; i++) {
			do_object(c, d, i, d->object_offs + 24*i);
		}
	}

	// BITBLK
	for(i=0; i<d->bitblk_num; i++) {
		do_bitblk(c, d, d->bitblk_offs + 14*i);
	}

	// ICONBLK
	if(d->iconblk_num>0) {
		for(i=0; i<d->iconblk_num; i++) {
			do_old_iconblk(c, d, d->iconblk_offs + 34*i);
		}
	}
}

static void de_run_rsc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	de_warn(c, "RSC support is experimental and incomplete. Images may not be decoded correctly.");

	d = de_malloc(c, sizeof(lctx));
	d->decode_objects = 1;

	d->version = de_getu16be(0);
	de_dbg(c, "version: 0x%04x", (int)d->version);

	d->object_offs = de_getu16be(2);
	d->iconblk_offs = de_getu16be(6);
	d->bitblk_offs = de_getu16be(8);
	d->imagedata_offs = de_getu16be(14);
	d->imagepointertable_offs = de_getu16be(16);
	d->object_num = de_getu16be(20);
	d->objecttree_num = de_getu16be(22);
	d->iconblk_num = de_getu16be(26);
	d->bitblk_num = de_getu16be(28);
	d->rssize = de_getu16be(34);

	de_dbg(c, "OBJECT: %d at %d", (int)d->object_num, (int)d->object_offs);
	de_dbg(c, "ojbecttree num: %d", (int)d->objecttree_num);
	de_dbg(c, "ICONBLK: %d at %d", (int)d->iconblk_num, (int)d->iconblk_offs);
	de_dbg(c, "BITBLK: %d at %d", (int)d->bitblk_num, (int)d->bitblk_offs);
	de_dbg(c, "imagedata: at %d", (int)d->imagedata_offs);
	de_dbg(c, "imagepointertable: at %d", (int)d->imagepointertable_offs);
	if(d->version==4) {
		do_newformat(c, d);
	}
	else if(d->version==0 || d->version==1) {
		do_oldformat(c, d);
	}

	de_free(c, d);
}

static int de_identify_rsc(deark *c)
{
	i64 ver;

	if(!de_input_file_has_ext(c, "rsc")) return 0;
	ver = de_getu16be(0);
	if(ver==0 || ver==1 || ver==4) return 100;
	return 0;
}

void de_module_rsc(deark *c, struct deark_module_info *mi)
{
	mi->id = "rsc";
	mi->desc = "GEM resource file";
	mi->run_fn = de_run_rsc;
	mi->identify_fn = de_identify_rsc;
}
