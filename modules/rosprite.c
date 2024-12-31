// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Acorn Sprite / RISC OS Sprite

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rosprite);

struct old_mode_info {
	u8 mode;
	u8 fgbpp;
	u8 xdpi;
	u8 ydpi;
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
	{107, 16,  0,  0}
};

struct page_ctx {
	i64 fgbpp;
	i64 maskbpp;
	i64 width_in_words;
	i64 first_bit, last_bit;
	i64 npwidth, height;
	i64 width_1; // Width of intermediate bitmap. Includes left-padding, but not right-padding.
	i64 pdwidth;
	i64 mask_width_1;
	i64 num_padding_pixels_at_start_of_row;
	i64 num_padding_pixels_at_end_of_row;
	i64 xdpi, ydpi;
	u32 mode;
	UI new_img_type; // 0 if old format
	u8 has_mask;
	u8 use_mask;
#define MASK_TYPE_OLD    1 // Binary transparency, fgbpp bits/pixel
#define MASK_TYPE_NEW_1  2 // Binary transparency, 8 bits/pixel
#define MASK_TYPE_NEW_8  3 // Alpha transparency, 8 bits/pixel
	int mask_type;
	i64 mask_rowspan;
	i64 image_offset;
	i64 mask_offset;

	de_bitmap *img;
	de_bitmap *mask;

	int has_custom_palette;
	i64 custom_palette_pos;
	i64 custom_palette_ncolors;
	de_color pal[256];
	de_color maskpal[256];
};

typedef struct localctx_struct {
	i64 num_images;
} lctx;

static const de_color pal4[4] = {
	0xffffffffU,0xffbbbbbbU,0xff777777U,0xff000000U
};

static de_color getpal4(int k)
{
	if(k<0 || k>3) return 0;
	return pal4[k];
}

static const de_color pal16[16] = {
	0xffffffffU,0xffddddddU,0xffbbbbbbU,0xff999999U,0xff777777U,0xff555555U,0xff333333U,0xff000000U,
	0xff4499ffU,0xffeeee00U,0xff00cc00U,0xffdd0000U,0xffeeeebbU,0xff558800U,0xffffbb00U,0xff00bbffU
};

static de_color getpal16(int k)
{
	if(k<0 || k>15) return 0;
	return pal16[k];
}

static de_color getpal256(int k)
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

static void remove_left_padding(deark *c, struct page_ctx *pg)
{
	de_bitmap *imgtmp;

	if(pg->num_padding_pixels_at_start_of_row<1) return;

	// Create a replacement bitmap, and copy the important pixels from the old
	// one to it.
	imgtmp = de_bitmap_create(c, pg->npwidth, pg->height, pg->img->bytes_per_pixel);
	de_bitmap_copy_rect(pg->img, imgtmp, pg->num_padding_pixels_at_start_of_row, 0,
		pg->npwidth, pg->height, 0, 0, 0);

	de_bitmap_destroy(pg->img);
	pg->img = imgtmp;
	imgtmp = NULL;
}

static void convert_image_16bit(deark *c, lctx *d, struct page_ctx *pg, de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<pg->height; j++) {
		for(i=0; i<pg->width_1; i++) {
			de_color clr;

			clr = (de_color)de_getu16le(pg->image_offset + 4*pg->width_in_words*j + i*2);
			clr = de_bgr555_to_888(clr);
			de_bitmap_setpixel_rgba(pg->img, i, j, clr);
		}
	}
}

static void do_image(deark *c, lctx *d, struct page_ctx *pg, de_finfo *fi)
{
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

	if(pg->mask_type==MASK_TYPE_OLD) {
		pg->mask_width_1 = pg->width_1;
	}
	else if(pg->mask_type==MASK_TYPE_NEW_1 || pg->mask_type==MASK_TYPE_NEW_8) {
		pg->mask_width_1 = pg->npwidth;
	}

	pg->img = de_bitmap_create(c, pg->width_1, pg->height, bypp);

	if(pg->xdpi>0) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = (double)pg->xdpi;
		fi->density.ydens = (double)pg->ydpi;
	}

	de_dbg(c, "image data at %"I64_FMT, pg->image_offset);

	if(pg->fgbpp==32) {
		de_convert_image_rgb(c->infile, pg->image_offset, 4*pg->width_in_words, 4, pg->img, 0);
	}
	else if(pg->fgbpp==16) {
		convert_image_16bit(c, d, pg, pg->img);
	}
	else {
		de_convert_image_paletted(c->infile, pg->image_offset, pg->fgbpp, 4*pg->width_in_words,
			pg->pal, pg->img, 0x1);
	}

	if(pg->has_mask && pg->use_mask) {
		de_dbg(c, "transparency mask at %"I64_FMT, pg->mask_offset);

		if(pg->maskbpp<1 || pg->maskbpp>8) {
			de_warn(c, "This type of transparency mask is not supported");
			goto after_mask;
		}

		pg->mask = de_bitmap_create(c, pg->mask_width_1, pg->height, 1);

		// Make a palette to use with de_convert_image_paletted().
		if(pg->mask_type==MASK_TYPE_NEW_8) {
			de_make_grayscale_palette(pg->maskpal, 256, 0);
		}
		else {
			// Supposedly, anything nonzero is opaque.
			de_memset(pg->maskpal, 0xff, sizeof(pg->maskpal));
			pg->maskpal[0] = DE_STOCKCOLOR_BLACK;
		}

		// Start with an opaque mask.
		de_bitmap_rect(pg->mask, 0, 0, pg->mask->width, pg->mask->height, DE_STOCKCOLOR_WHITE, 0);

		de_convert_image_paletted(c->infile, pg->mask_offset, pg->maskbpp, pg->mask_rowspan,
			pg->maskpal, pg->mask, 0x1);

		de_bitmap_apply_mask(pg->img, pg->mask, 0);
		de_bitmap_destroy(pg->mask);
		pg->mask = NULL;
	}
after_mask:

	if(pg->num_padding_pixels_at_start_of_row>0 && !c->padpix) {
		remove_left_padding(c, pg);
	}

	de_bitmap_write_to_file_finfo(pg->img, fi, DE_CREATEFLAG_OPT_IMAGE);
}

static de_color average_color(de_color c1, de_color c2)
{
	u8 a, r, g, b;
	a = ((de_color)DE_COLOR_A(c1) + DE_COLOR_A(c2))/2;
	r = ((de_color)DE_COLOR_R(c1) + DE_COLOR_R(c2))/2;
	g = ((de_color)DE_COLOR_G(c1) + DE_COLOR_G(c2))/2;
	b = ((de_color)DE_COLOR_B(c1) + DE_COLOR_B(c2))/2;
	return DE_MAKE_RGBA(r,g,b,a);
}

static void do_setup_palette(deark *c, lctx *d, struct page_ctx *pg)
{
	i64 k;
	de_color clr1, clr2, clr3;

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
	de_finfo *fi = NULL;
	struct page_ctx *pg = NULL;
	i64 image_offset_raw, mask_offset_raw;
	i64 pos;
	int saved_indent_level;
	char descr[32];

	de_dbg_indent_save(c, &saved_indent_level);
	pg = de_malloc(c, sizeof(struct page_ctx));

	de_dbg(c, "image header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	fi = de_finfo_create(c);

	pos = pos1+4;
	read_sprite_name(c, d, fi, pos);
	pos += 12;

	pg->width_in_words = de_getu32le_p(&pos) +1;
	pg->height = de_getu32le_p(&pos) +1;
	de_dbg(c, "width in words: %"I64_FMT, pg->width_in_words);
	de_dbg(c, "height: %"I64_FMT, pg->height);

	pg->first_bit = de_getu32le_p(&pos);
	if(pg->first_bit>31) pg->first_bit=31;
	pg->last_bit = de_getu32le_p(&pos);
	if(pg->last_bit>31) pg->last_bit=31;
	de_dbg(c, "first bit: %u", (UI)pg->first_bit);
	de_dbg(c, "last bit: %u", (UI)pg->last_bit);

	image_offset_raw = de_getu32le_p(&pos);
	pg->image_offset = pos1 + image_offset_raw;
	de_dbg(c, "image offset: %"I64_FMT" ("DE_CHAR_RIGHTARROW"%"I64_FMT")",
		image_offset_raw, pg->image_offset);

	mask_offset_raw = de_getu32le_p(&pos);
	pg->mask_offset = pos1 + mask_offset_raw;
	if(mask_offset_raw && (mask_offset_raw!=image_offset_raw)) {
		pg->has_mask = 1;
		pg->use_mask = 1; // Default
	}
	if(pg->has_mask) {
		de_snprintf(descr, sizeof(descr), DE_CHAR_RIGHTARROW"%"I64_FMT,
			pg->mask_offset);
	}
	else {
		de_strlcpy(descr, "no mask", sizeof(descr));
	}
	de_dbg(c, "mask offset: %"I64_FMT" (%s)", mask_offset_raw, descr);

	pg->mode = (u32)de_getu32le_p(&pos);
	de_dbg(c, "mode: 0x%08x", (unsigned int)pg->mode);

	de_dbg_indent(c, 1);

	pg->new_img_type = (pg->mode&0x78000000U)>>27;
	de_dbg(c, "format version: %s", (pg->new_img_type?"new":"old"));
	if(pg->new_img_type==0)
		de_dbg(c, "old format screen mode: %u", (UI)pg->mode);
	else
		de_dbg(c, "new format image type: %u", (UI)pg->new_img_type);

	if(pg->new_img_type!=0 && pg->first_bit!=0) {
		de_warn(c, "Invalid \"first bit\" value for new image format");
		pg->first_bit = 0;
	}

	if(pg->new_img_type==0) {
		// old format
		size_t x;

		for(x=0; x<DE_ARRAYCOUNT(old_mode_info_arr); x++) {
			if(pg->mode == (u32)old_mode_info_arr[x].mode) {
				pg->fgbpp = (i64)old_mode_info_arr[x].fgbpp;
				pg->xdpi = (i64)old_mode_info_arr[x].xdpi;
				pg->ydpi = (i64)old_mode_info_arr[x].ydpi;
				break;
			}
		}

		if(pg->fgbpp==0) {
			de_err(c, "Screen mode %u not supported", (UI)pg->mode);
			goto done;
		}

		if(pg->has_mask) {
			pg->mask_type = MASK_TYPE_OLD;
			pg->mask_rowspan = 4*pg->width_in_words;
			pg->maskbpp = pg->fgbpp;
			de_dbg(c, "mask type: old");
		}

		if(pg->fgbpp>8 && pg->has_mask) {
			de_warn(c, "Transparency not supported for this image type");
			pg->use_mask = 0;
		}

	}
	else {
		// new format
		pg->xdpi = (pg->mode&0x07ffc000)>>14;
		pg->ydpi = (pg->mode&0x00003ffe)>>1;
		de_dbg(c, "dpi: %d"DE_CHAR_TIMES"%d", (int)pg->xdpi, (int)pg->ydpi);
		switch(pg->new_img_type) {
		case 1: // ->1
		case 2: // ->2
		case 3: // ->4
		case 4: // ->8
		case 5: // ->16
		case 6: // ->32
			pg->fgbpp = 1LL<<(pg->new_img_type-1);
			break;
		//case 7: 32bpp CMYK (TODO)
		//case 8: 24bpp (TODO)
		default:
			de_err(c, "New format type %u not supported", (UI)pg->new_img_type);
			goto done;
		}

		if(pg->has_mask) {
			if(pg->mode&0x80000000U) {
				pg->mask_type = MASK_TYPE_NEW_8;
				pg->maskbpp = 8;
			}
			else {
				pg->mask_type = MASK_TYPE_NEW_1;
				pg->maskbpp = 1;
			}
			de_dbg(c, "mask type: new - %s", pg->mask_type==MASK_TYPE_NEW_8 ? "alpha" : "binary");
		}
	}

	de_dbg(c, "foreground bits/pixel: %d", (int)pg->fgbpp);

	de_dbg_indent(c, -1);

	pg->pdwidth = (pg->width_in_words * 32)/pg->fgbpp;
	pg->num_padding_pixels_at_start_of_row = pg->first_bit / pg->fgbpp;
	pg->num_padding_pixels_at_end_of_row = (32 - (pg->last_bit+1)) / pg->fgbpp;
	pg->npwidth = pg->pdwidth - pg->num_padding_pixels_at_start_of_row -
		pg->num_padding_pixels_at_end_of_row;
	if(c->padpix) {
		pg->width_1 = pg->pdwidth;
	}
	else {
		pg->width_1 = pg->pdwidth - pg->num_padding_pixels_at_end_of_row;
	}
	de_dbg(c, "width (calculated): %"I64_FMT, pg->npwidth);

	if(!de_good_image_dimensions(c, pg->npwidth, pg->height)) goto done;
	if(pg->width_1<1) goto done;

	if(pg->mask_type==MASK_TYPE_NEW_1 || pg->mask_type==MASK_TYPE_NEW_8) {
		pg->mask_rowspan = de_pad_to_n(pg->maskbpp*pg->npwidth, 32) / 8;
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
	if(pg) {
		if(pg->img) de_bitmap_destroy(pg->img);
		if(pg->mask) de_bitmap_destroy(pg->mask);
		de_free(c, pg);
	}
}

static void de_run_rosprite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 sprite_size;
	i64 first_sprite_offset_raw;
	i64 first_sprite_offset;
	i64 implied_file_size_raw;
	i64 implied_file_size;
	i64 k;
	i64 sprite_count = 0;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	d->num_images = de_getu32le_p(&pos);
	de_dbg(c, "number of images: %"I64_FMT, d->num_images);
	first_sprite_offset_raw = de_getu32le_p(&pos);
	first_sprite_offset = first_sprite_offset_raw - 4;
	de_dbg(c, "first sprite offset: %"I64_FMT" ("DE_CHAR_RIGHTARROW"%"I64_FMT")",
		first_sprite_offset_raw, first_sprite_offset);
	implied_file_size_raw = de_getu32le_p(&pos);
	implied_file_size = implied_file_size_raw - 4;
	de_dbg(c, "reported file size: %"I64_FMT" ("DE_CHAR_RIGHTARROW"%"I64_FMT")",
		implied_file_size_raw, implied_file_size);
	if(implied_file_size != c->infile->len) {
		de_warn(c, "Reported and actual file sizes differ "
			"(%"I64_FMT", %"I64_FMT")", implied_file_size, c->infile->len);
	}

	pos = first_sprite_offset;
	for(k=0; k<d->num_images; k++) {
		if(pos>=c->infile->len) goto done;
		sprite_size = de_getu32le(pos);
		de_dbg(c, "image #%d at %"I64_FMT", size=%"I64_FMT, (int)k, pos, sprite_size);
		if(sprite_size<1) goto done;
		// We intentionally allow sprite_size to be set wrong, because
		// such files exist, and we don't need it for *this* sprite.
		de_dbg_indent(c, 1);
		do_sprite(c, d, k, pos, sprite_size);
		sprite_count++;
		de_dbg_indent(c, -1);
		if(sprite_size<40) goto done;
		pos += sprite_size;
	}

done:
	if(sprite_count < d->num_images) {
		de_warn(c, "Expected %"I64_FMT" images, only found %"I64_FMT,
			d->num_images, sprite_count);
	}
	de_free(c, d);
}

static int de_identify_rosprite(deark *c)
{
	i64 num_images, first_sprite_offset, implied_file_size;
	i64 offset2;

	num_images = de_getu32le(0);
	if(num_images<1 || num_images>1000) return 0;

	first_sprite_offset = de_getu32le(4) - 4;
	// I've only ever seen this be 12 or (rarely) 28, though it's legal
	// for it to have other values
	if(first_sprite_offset!=12 && first_sprite_offset!=28) return 0;
	if(first_sprite_offset+48 > c->infile->len) return 0;

	implied_file_size = de_getu32le(8) - 4;
	if(implied_file_size > c->infile->len) return 0;

	if(num_images!=1) {
		// TODO?: A multi-sprite file with extra junk at EOF will not be detected.
		// To better detect multi-sprite files, we'd probably have to walk through
		// the file.
		if(implied_file_size != c->infile->len) return 0;
		return 55;
	}

	offset2 = de_getu32le(first_sprite_offset);
	if(offset2==implied_file_size && implied_file_size==c->infile->len) {
		// Found some bad files where this pointer is absolute when it should be
		// relative.
		return 15;
	}
	offset2 += first_sprite_offset;
	if(offset2 != implied_file_size) return 0;
	if(implied_file_size == c->infile->len) return 80;
	return 30;
}

void de_module_rosprite(deark *c, struct deark_module_info *mi)
{
	mi->id = "rosprite";
	mi->desc = "RISC OS Sprite, a.k.a. Acorn Sprite";
	mi->run_fn = de_run_rosprite;
	mi->identify_fn = de_identify_rosprite;
}
