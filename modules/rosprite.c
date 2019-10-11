// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Acorn Sprite / RISC OS Sprite

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rosprite);

struct old_mode_info {
	u32 mode;
	int fgbpp;
	int xdpi;
	int ydpi;
};
// Screen mode list at: http://www.riscos.com/support/users/userguide3/book3b/book3_17.html
// TODO: Find reliable information about DPI fields.
static const struct old_mode_info old_mode_info_arr[] = {
	{0,  1, 90, 45},
	{1,  2, 45, 45},
	{2,  4,  0,  0},
	{4,  1, 45, 45},
	{5,  2,  0,  0},
	{8,  2, 90, 45},
	{9,  4, 45, 45},
	{10, 8,  0,  0},
	{11, 2,  0,  0},
	{12, 4, 90, 45},
	{13, 8, 45, 45},
	{14, 4,  0,  0},
	{15, 8, 90, 45},
	{16, 4,  0,  0},
	{17, 4,  0,  0},
	{18, 1, 90, 90},
	{19, 2, 90, 90},
	{20, 4, 90, 90},
	{21, 8, 90, 90},
	{22, 4,  0,  0},
	{23, 1,  0,  0},
	{24, 8,  0,  0},
	{25, 1,  0,  0},
	{26, 2,  0,  0},
	{27, 4, 90, 90},
	{28, 8, 90, 90},
	{29, 1,  0,  0},
	{30, 2,  0,  0},
	{31, 4, 90, 90},
	{32, 8, 90, 90},
	{33, 1,  0,  0},
	{34, 2,  0,  0},
	{35, 4,  0,  0},
	{36, 8, 90, 45},
	{37, 1,  0,  0},
	{38, 2,  0,  0},
	{39, 4,  0,  0},
	{40, 8,  0,  0},
	{41, 1,  0,  0},
	{42, 2,  0,  0},
	{43, 4,  0,  0},
	{44, 1,  0,  0},
	{45, 2,  0,  0},
	{46, 4,  0,  0},
	{47, 8,  0,  0},
	{48, 4,  0,  0},
	{49, 8,  0,  0},

	// I have some mode-107 files, but I don't know how standard this is.
	{107, 16,  0,  0},

	{1000, 0, 0, 0}
};

struct page_ctx {
	i64 fgbpp;
	i64 maskbpp;
	i64 width_in_words;
	i64 first_bit, last_bit;
	i64 width, height;
	i64 xdpi, ydpi;
	i64 pixels_to_ignore_at_start_of_row;
	u32 mode;
	int has_mask;
#define MASK_TYPE_OLD    1 // Binary transparency, fgbpp bits/pixel
#define MASK_TYPE_NEW_1  2 // Binary transparency, 8 bits/pixel
#define MASK_TYPE_NEW_8  3 // Alpha transparency, 8 bits/pixel
	int mask_type;
	i64 mask_rowspan;
	i64 image_offset;
	i64 mask_offset;

	int has_custom_palette;
	i64 custom_palette_pos;
	i64 custom_palette_ncolors;
	u32 pal[256];
};

typedef struct localctx_struct {
	i64 num_images;
} lctx;

static const u32 pal4[4] = {
	0xffffff,0xbbbbbb,0x777777,0x000000
};

static u32 getpal4(int k)
{
	if(k<0 || k>3) return 0;
	return pal4[k];
}

static const u32 pal16[16] = {
	0xffffff,0xdddddd,0xbbbbbb,0x999999,0x777777,0x555555,0x333333,0x000000,
	0x4499ff,0xeeee00,0x00cc00,0xdd0000,0xeeeebb,0x558800,0xffbb00,0x00bbff
};

static u32 getpal16(int k)
{
	if(k<0 || k>15) return 0;
	return pal16[k];
}

static u32 getpal256(int k)
{
	u8 r, g, b;
	if(k<0 || k>255) return 0;
	r = k%8 + ((k%32)/16)*8;
	g = k%4 + ((k%128)/32)*4;
	b = (u8)(k%4 + ((k%16)/8)*4 + (k/128)*8);
	r = (r<<4)|r;
	g = (g<<4)|g;
	b = (b<<4)|b;
	return DE_MAKE_RGB(r,g,b);
}

static void do_image(deark *c, lctx *d, struct page_ctx *pg, de_finfo *fi)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u8 n;
	u32 clr;
	int is_grayscale;
	int bypp;

	if(pg->fgbpp<=8) {
		is_grayscale = de_is_grayscale_palette(pg->pal, ((i64)1)<<pg->fgbpp);
	}
	else {
		is_grayscale = 0;
	}

	bypp = is_grayscale?1:3;
	if(pg->has_mask) bypp++;

	img = de_bitmap_create(c, pg->width, pg->height, bypp);

	if(pg->xdpi>0) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = (double)pg->xdpi;
		fi->density.ydens = (double)pg->ydpi;
	}

	de_dbg(c, "image data at %d", (int)pg->image_offset);
	if(pg->has_mask) {
		de_dbg(c, "transparency mask at %d", (int)pg->mask_offset);
	}

	for(j=0; j<pg->height; j++) {
		for(i=0; i<pg->width; i++) {
			if(pg->fgbpp==32) {
				clr = dbuf_getRGB(c->infile, pg->image_offset + 4*pg->width_in_words*j + 4*i, 0);
			}
			else if(pg->fgbpp==16) {
				clr = (u32)de_getu16le(pg->image_offset + 4*pg->width_in_words*j + i*2);
				clr = de_bgr555_to_888(clr);
			}
			else {
				n = de_get_bits_symbol_lsb(c->infile, pg->fgbpp, pg->image_offset + 4*pg->width_in_words*j,
					i+pg->pixels_to_ignore_at_start_of_row);
				clr = pg->pal[(int)n];

				if(pg->has_mask) {
					n = de_get_bits_symbol_lsb(c->infile, pg->maskbpp, pg->mask_offset + pg->mask_rowspan*j,
						i+pg->pixels_to_ignore_at_start_of_row);

					if(pg->mask_type==MASK_TYPE_OLD || pg->mask_type==MASK_TYPE_NEW_1) {
						if(n==0)
							clr = DE_SET_ALPHA(clr, 0);
						else
							clr = DE_MAKE_OPAQUE(clr);
					}
					else if(pg->mask_type==MASK_TYPE_NEW_8) {
						clr = DE_SET_ALPHA(clr, n);
					}
				}
			}

			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);
	de_bitmap_destroy(img);
}

static u32 average_color(u32 c1, u32 c2)
{
	u8 a, r, g, b;
	a = ((u32)DE_COLOR_A(c1) + DE_COLOR_A(c2))/2;
	r = ((u32)DE_COLOR_R(c1) + DE_COLOR_R(c2))/2;
	g = ((u32)DE_COLOR_G(c1) + DE_COLOR_G(c2))/2;
	b = ((u32)DE_COLOR_B(c1) + DE_COLOR_B(c2))/2;
	return DE_MAKE_RGBA(r,g,b,a);
}

static void do_setup_palette(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 k;
	u32 clr1, clr2, clr3;

	if(pg->fgbpp>8) {
		return;
	}

	if(pg->has_custom_palette) {
		de_dbg(c, "custom palette at %d, %d entries", (int)pg->custom_palette_pos,
			(int)pg->custom_palette_ncolors);
	}
	de_dbg_indent(c, 1);

	for(k=0; k<256; k++) {
		if(pg->has_custom_palette) {
			if(k<pg->custom_palette_ncolors) {
				// Each palette entry has two colors, which are usually but not always
				// the same.
				// TODO: Figure out what to do if they are different. For now, we'll
				// average them.
				clr1 = dbuf_getRGB(c->infile, pg->custom_palette_pos + 8*k + 1, 0);
				clr2 = dbuf_getRGB(c->infile, pg->custom_palette_pos + 8*k + 4 + 1, 0);
				if(clr1==clr2) {
					pg->pal[k] = clr1;
					de_dbg_pal_entry(c, k, clr1);
				}
				else {
					char tmps[64];

					clr3 = average_color(clr1, clr2);
					pg->pal[k] = clr3;
					de_snprintf(tmps, sizeof(tmps), "(%3d,%3d,%3d),(%3d,%3d,%3d) "DE_CHAR_RIGHTARROW" ",
						(int)DE_COLOR_R(clr1), (int)DE_COLOR_G(clr1), (int)DE_COLOR_B(clr1),
						(int)DE_COLOR_R(clr2), (int)DE_COLOR_G(clr2), (int)DE_COLOR_B(clr2));
					de_dbg_pal_entry2(c, k, clr3, tmps, NULL, NULL);
				}
			}
			else {
				pg->pal[k] = getpal256((int)k);
			}
		}
		else if(pg->fgbpp==4 && k<16) {
			pg->pal[k] = getpal16((int)k);
		}
		else if(pg->fgbpp==2 && k<4) {
			pg->pal[k] = getpal4((int)k);
		}
		else if(pg->fgbpp==1 && k<2) {
			pg->pal[k] = (k==0)?DE_STOCKCOLOR_WHITE:DE_STOCKCOLOR_BLACK;
		}
		else {
			pg->pal[k] = getpal256((int)k);
		}
	}

	de_dbg_indent(c, -1);
}

static void read_sprite_name(deark *c, lctx *d, de_finfo *fi, i64 pos)
{
	de_ucstring *s = NULL;
	if(c->debug_level<1 && !c->filenames_from_file) return;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 12, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_RISCOS);
	de_dbg(c, "sprite name: \"%s\"", ucstring_getpsz(s));

	if(c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, s, 0);
	}

	ucstring_destroy(s);
}

static void do_sprite(deark *c, lctx *d, i64 index,
	i64 pos1, i64 len)
{
	i64 new_img_type;
	de_finfo *fi = NULL;
	int saved_indent_level;
	struct page_ctx *pg = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	pg = de_malloc(c, sizeof(struct page_ctx));

	de_dbg(c, "image header at %d", (int)pos1);
	de_dbg_indent(c, 1);

	// Name at pos 4, len=12
	fi = de_finfo_create(c);

	read_sprite_name(c, d, fi, pos1+4);

	pg->width_in_words = de_getu32le(pos1+16) +1;
	pg->height = de_getu32le(pos1+20) +1;
	de_dbg(c, "width-in-words: %d, height: %d", (int)pg->width_in_words, (int)pg->height);

	pg->first_bit = de_getu32le(pos1+24);
	if(pg->first_bit>31) pg->first_bit=31;
	pg->last_bit = de_getu32le(pos1+28);
	if(pg->last_bit>31) pg->last_bit=31;
	pg->image_offset = de_getu32le(pos1+32) + pos1;
	pg->mask_offset = de_getu32le(pos1+36) + pos1;
	pg->has_mask = (pg->mask_offset != pg->image_offset);
	de_dbg(c, "first bit: %d, last bit: %d", (int)pg->first_bit, (int)pg->last_bit);
	de_dbg(c, "image offset: %d, mask_offset: %d", (int)pg->image_offset, (int)pg->mask_offset);

	pg->mode = (u32)de_getu32le(pos1+40);
	de_dbg(c, "mode: 0x%08x", (unsigned int)pg->mode);

	de_dbg_indent(c, 1);

	new_img_type = (pg->mode&0x78000000U)>>27;
	if(new_img_type==0)
		de_dbg(c, "old format screen mode: %d", (int)pg->mode);
	else
		de_dbg(c, "new format image type: %d", (int)new_img_type);

	if(new_img_type==0) {
		// old format
		int x;

		for(x=0; old_mode_info_arr[x].mode<1000; x++) {
			if(pg->mode == old_mode_info_arr[x].mode) {
				pg->fgbpp = (i64)old_mode_info_arr[x].fgbpp;
				pg->xdpi = (i64)old_mode_info_arr[x].xdpi;
				pg->ydpi = (i64)old_mode_info_arr[x].ydpi;
				break;
			}
		}

		if(pg->fgbpp==0) {
			de_err(c, "Screen mode %d not supported", (int)pg->mode);
			goto done;
		}

		if(pg->fgbpp>8 && pg->has_mask) {
			de_err(c, "Transparency not supported for this image format");
			goto done;
		}

		if(pg->has_mask) {
			pg->mask_type = MASK_TYPE_OLD;
			pg->mask_rowspan = 4*pg->width_in_words;
			pg->maskbpp = pg->fgbpp;
		}
	}
	else {
		// new format
		pg->xdpi = (pg->mode&0x07ffc000)>>14;
		pg->ydpi = (pg->mode&0x00003ffe)>>1;
		de_dbg(c, "xdpi: %d, ydpi: %d", (int)pg->xdpi, (int)pg->ydpi);
		switch(new_img_type) {
		case 1:
			pg->fgbpp = 1;
			break;
		case 2:
			pg->fgbpp = 2;
			break;
		case 3:
			pg->fgbpp = 4;
			break;
		case 4:
			pg->fgbpp = 8;
			break;
		case 5:
			pg->fgbpp = 16;
			break;
		case 6:
			pg->fgbpp = 32;
			break;
		//case 7: 32bpp CMYK (TODO)
		//case 8: 24bpp (TODO)
		default:
			de_err(c, "New format type %d not supported", (int)new_img_type);
			goto done;
		}

		if(pg->has_mask) {
			pg->mask_type = (pg->mode&0x80000000U) ? MASK_TYPE_NEW_8 : MASK_TYPE_NEW_1;
			pg->maskbpp = 8;
			de_dbg(c, "mask type: %s", pg->mask_type==MASK_TYPE_NEW_8 ? "alpha" : "binary");
		}
	}

	de_dbg(c, "foreground bits/pixel: %d", (int)pg->fgbpp);

	de_dbg_indent(c, -1);

	pg->width = ((pg->width_in_words-1) * 4 * 8 + (pg->last_bit+1)) / pg->fgbpp;
	pg->pixels_to_ignore_at_start_of_row = pg->first_bit / pg->fgbpp;
	pg->width -= pg->pixels_to_ignore_at_start_of_row;
	de_dbg(c, "calculated width: %d", (int)pg->width);

	if(!de_good_image_dimensions(c, pg->width, pg->height)) goto done;

	if(pg->mask_type==MASK_TYPE_NEW_1 || pg->mask_type==MASK_TYPE_NEW_8) {
		if(pg->pixels_to_ignore_at_start_of_row>0) {
			de_warn(c, "This image has a new-style transparency mask, and a "
				"nonzero \"first bit\" field. This combination might not be "
				"handled correctly.");
		}
		pg->mask_rowspan = ((pg->width+31)/32)*4;
	}

	de_dbg_indent(c, -1);

	pg->custom_palette_pos = pos1 + 44;
	if(pg->image_offset >= pg->custom_palette_pos+8 && pg->fgbpp<=8) {
		pg->has_custom_palette = 1;
		pg->custom_palette_ncolors = (pg->image_offset - (pos1+44))/8;
		if(pg->custom_palette_ncolors>256) pg->custom_palette_ncolors=256;
	}

	do_setup_palette(c, d, pg);

	do_image(c, d, pg, fi);
done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_finfo_destroy(c, fi);
	de_free(c, pg);
}

static void de_run_rosprite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 sprite_size;
	i64 first_sprite_offset;
	i64 implied_file_size;
	i64 k;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	d->num_images = de_getu32le(pos);
	de_dbg(c, "number of images: %d", (int)d->num_images);
	first_sprite_offset = de_getu32le(pos+4) - 4;
	de_dbg(c, "first sprite offset: %d", (int)first_sprite_offset);
	implied_file_size = de_getu32le(pos+8) - 4;
	de_dbg(c, "reported file size: %d", (int)implied_file_size);
	if(implied_file_size != c->infile->len) {
		de_warn(c, "The \"first free word\" field implies the file size is %d, but it "
			"is actually %d. This may not be a sprite file.",
			(int)implied_file_size, (int)c->infile->len);
	}

	pos = 12;
	for(k=0; k<d->num_images; k++) {
		if(pos>=c->infile->len) break;
		sprite_size = de_getu32le(pos);
		de_dbg(c, "image #%d at %d, size=%d", (int)k, (int)pos, (int)sprite_size);
		if(sprite_size<1) break;
		de_dbg_indent(c, 1);
		do_sprite(c, d, k, pos, sprite_size);
		de_dbg_indent(c, -1);
		pos += sprite_size;
	}

	de_free(c, d);
}

static int de_identify_rosprite(deark *c)
{
	i64 h0, h1, h2;
	h0 = de_getu32le(0);
	h1 = de_getu32le(4);
	h2 = de_getu32le(8);

	if(h0<1 || h0>10000) return 0;
	if(h1-4<12) return 0;
	if(h1-4 >= c->infile->len) return 0;
	if(h2-4 != c->infile->len) return 0;

	return 80;
}

void de_module_rosprite(deark *c, struct deark_module_info *mi)
{
	mi->id = "rosprite";
	mi->desc = "RISC OS Sprite, a.k.a. Acorn Sprite";
	mi->run_fn = de_run_rosprite;
	mi->identify_fn = de_identify_rosprite;
}
