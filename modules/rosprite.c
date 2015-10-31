// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Acorn Sprite / RISC OS Sprite

#include <deark-config.h>
#include <deark-modules.h>

struct old_mode_info {
	de_uint32 mode;
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

typedef struct localctx_struct {
	de_int64 num_images;

	de_int64 width_in_words;
	de_int64 first_bit, last_bit;
	de_int64 width, height;
	de_int64 image_offset;
	de_int64 mask_offset;

	de_uint32 mode;
	de_int64 fgbpp;
	de_int64 maskbpp;
	de_int64 xdpi, ydpi;
	de_int64 pixels_to_ignore_at_start_of_row;
	de_int64 mask_rowspan;
	int has_mask;
#define MASK_TYPE_OLD    1 // Binary transparency, fgbpp bits/pixel
#define MASK_TYPE_NEW_1  2 // Binary transparency, 8 bits/pixel
#define MASK_TYPE_NEW_8  3 // Alpha transparency, 8 bits/pixel
	int mask_type;

	int has_custom_palette;
	de_int64 custom_palette_pos;
	de_int64 custom_palette_ncolors;
	de_uint32 palette[256];
} lctx;

static const de_uint32 pal4[4] = {
	0xffffff,0xbbbbbb,0x777777,0x000000
};

static de_uint32 getpal4(int k)
{
	if(k<0 || k>3) return 0;
	return pal4[k];
}

static const de_uint32 pal16[16] = {
	0xffffff,0xdddddd,0xbbbbbb,0x999999,0x777777,0x555555,0x333333,0x000000,
	0x4499ff,0xeeee00,0x00cc00,0xdd0000,0xeeeebb,0x558800,0xffbb00,0x00bbff
};

static de_uint32 getpal16(int k)
{
	if(k<0 || k>15) return 0;
	return pal16[k];
}

static de_uint32 getpal256(int k)
{
	de_byte r, g, b;
	if(k<0 || k>255) return 0;
	r = k%8 + ((k%32)/16)*8;
	g = k%4 + ((k%128)/32)*4;
	b = k%4 + ((k%16)/8)*4 + (k/128)*8;
	r = (r<<4)|r;
	g = (g<<4)|g;
	b = (b<<4)|b;
	return DE_MAKE_RGB(r,g,b);
}

static void do_image(deark *c, lctx *d, de_finfo *fi)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n;
	de_uint32 clr;

	img = de_bitmap_create(c, d->width, d->height, d->has_mask?4:3);
	img->density_code = DE_DENSITY_DPI;
	img->xdens = (double)d->xdpi;
	img->ydens = (double)d->ydpi;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			if(d->fgbpp==32) {
				clr = dbuf_getRGB(c->infile, d->image_offset + 4*d->width_in_words*j + 4*i, 0);
			}
			else if(d->fgbpp==16) {
				clr = (de_uint32)de_getui16le(d->image_offset + 4*d->width_in_words*j + i*2);
				clr = de_bgr555_to_888(clr);
			}
			else {
				n = de_get_bits_symbol_lsb(c->infile, d->fgbpp, d->image_offset + 4*d->width_in_words*j,
					i+d->pixels_to_ignore_at_start_of_row);
				clr = d->palette[(int)n];

				if(d->has_mask) {
					n = de_get_bits_symbol_lsb(c->infile, d->maskbpp, d->mask_offset + d->mask_rowspan*j,
						i+d->pixels_to_ignore_at_start_of_row);

					if(d->mask_type==MASK_TYPE_OLD || d->mask_type==MASK_TYPE_NEW_1) {
						if(n==0)
							clr = DE_SET_ALPHA(clr, 0);
						else
							clr = DE_MAKE_OPAQUE(clr);
					}
					else if(d->mask_type==MASK_TYPE_NEW_8) {
						clr = DE_SET_ALPHA(clr, n);
					}
				}
			}

			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file_finfo(img, fi);
	de_bitmap_destroy(img);
}

static de_uint32 average_color(de_uint32 c1, de_uint32 c2)
{
	de_byte a, r, g, b;
	a = ((de_uint32)DE_COLOR_A(c1) + DE_COLOR_A(c2))/2;
	r = ((de_uint32)DE_COLOR_R(c1) + DE_COLOR_R(c2))/2;
	g = ((de_uint32)DE_COLOR_G(c1) + DE_COLOR_G(c2))/2;
	b = ((de_uint32)DE_COLOR_B(c1) + DE_COLOR_B(c2))/2;
	return DE_MAKE_RGBA(r,g,b,a);
}

static void do_setup_palette(deark *c, lctx *d)
{
	de_int64 k;
	de_uint32 clr1, clr2;

	if(d->fgbpp>8) {
		for(k=0; k<256; k++) {
			d->palette[k] = 0;
		}
		return;
	}

	for(k=0; k<256; k++) {
		if(d->has_custom_palette) {
			if(k<d->custom_palette_ncolors) {
				// Each palette entry has two colors, which are usually but not always
				// the same.
				// TODO: Figure out what to do if they are different. For now, we'll
				// average them.
				clr1 = dbuf_getRGB(c->infile, d->custom_palette_pos + 8*k + 1, 0);
				clr2 = dbuf_getRGB(c->infile, d->custom_palette_pos + 8*k + 4 + 1, 0);
				if(clr1==clr2)
					d->palette[k] = clr1;
				else
					d->palette[k] = average_color(clr1, clr2);
			}
			else {
				d->palette[k] = getpal256((int)k);
			}
		}
		else if(d->fgbpp==4 && k<16) {
			d->palette[k] = getpal16((int)k);
		}
		else if(d->fgbpp==2 && k<4) {
			d->palette[k] = getpal4((int)k);
		}
		else {
			d->palette[k] = getpal256((int)k);
		}
	}
}

static void do_sprite(deark *c, lctx *d, de_int64 index,
	de_int64 pos1, de_int64 len)
{
	de_int64 new_img_type;
	de_finfo *fi = NULL;

	d->fgbpp = 0;
	d->maskbpp = 0;
	d->width = 0;
	d->height = 0;
	d->xdpi = 0;
	d->ydpi = 0;
	d->pixels_to_ignore_at_start_of_row = 0;
	d->mask_type = 0;
	d->mask_rowspan = 0;
	d->has_custom_palette = 0;

	// Name at pos 4, len=12
	fi = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_slice(c, fi, c->infile, pos1+4, 12, DE_CONVFLAG_STOP_AT_NUL);

	d->width_in_words = de_getui32le(pos1+16) +1;
	d->height = de_getui32le(pos1+20) +1;
	de_dbg(c, "width-in-words: %d, height: %d\n", (int)d->width_in_words, (int)d->height);

	d->first_bit = de_getui32le(pos1+24);
	if(d->first_bit>31) d->first_bit=31;
	d->last_bit = de_getui32le(pos1+28);
	if(d->last_bit>31) d->last_bit=31;
	d->image_offset = de_getui32le(pos1+32) + pos1;
	d->mask_offset = de_getui32le(pos1+36) + pos1;
	d->has_mask = (d->mask_offset != d->image_offset);
	d->mode = (de_uint32)de_getui32le(pos1+40);
	de_dbg(c, "first bit: %d, last bit: %d\n", (int)d->first_bit, (int)d->last_bit);
	de_dbg(c, "image offset: %d, mask_offset: %d\n", (int)d->image_offset, (int)d->mask_offset);
	de_dbg(c, "mode: 0x%08x\n", (unsigned int)d->mode);

	new_img_type = (d->mode&0x78000000U)>>27;
	if(new_img_type==0)
		de_dbg(c, "old format screen mode: %d\n", (int)d->mode);
	else
		de_dbg(c, "new format image type: %d\n", (int)new_img_type);

	d->custom_palette_pos = pos1 + 44;
	if(d->image_offset >= d->custom_palette_pos+8 && d->fgbpp<=8) {
		d->has_custom_palette = 1;
		d->custom_palette_ncolors = (d->image_offset - (pos1+44))/8;
		if(d->custom_palette_ncolors>256) d->custom_palette_ncolors=256;
		de_dbg(c, "custom palette at %d, %d colors\n", (int)d->custom_palette_pos,
			(int)d->custom_palette_ncolors);
	}

	if(new_img_type==0) {
		// old format
		int x;

		for(x=0; old_mode_info_arr[x].mode<1000; x++) {
			if(d->mode == old_mode_info_arr[x].mode) {
				d->fgbpp = (de_int64)old_mode_info_arr[x].fgbpp;
				d->xdpi = (de_int64)old_mode_info_arr[x].xdpi;
				d->ydpi = (de_int64)old_mode_info_arr[x].ydpi;
				break;
			}
		}

		if(d->fgbpp==0) {
			de_err(c, "Screen mode %d not supported\n", (int)d->mode);
			goto done;
		}

		if(d->fgbpp>8 && d->has_mask) {
			de_err(c, "Transparency not supported for this image format\n");
			goto done;
		}

		if(d->has_mask) {
			d->mask_type = MASK_TYPE_OLD;
			d->mask_rowspan = 4*d->width_in_words;
			d->maskbpp = d->fgbpp;
		}
	}
	else {
		// new format
		d->xdpi = (d->mode&0x07ffc000)>>14;
		d->ydpi = (d->mode&0x00003ffe)>>1;
		de_dbg(c, "xdpi: %d, ydpi: %d\n", (int)d->xdpi, (int)d->ydpi);
		switch(new_img_type) {
		case 1:
			d->fgbpp = 1;
			break;
		case 2:
			d->fgbpp = 2;
			break;
		case 3:
			d->fgbpp = 4;
			break;
		case 4:
			d->fgbpp = 8;
			break;
		case 5:
			d->fgbpp = 16;
			break;
		case 6:
			d->fgbpp = 32;
			break;
		//case 7: 32bpp CMYK (TODO)
		//case 8: 24bpp (TODO)
		default:
			de_err(c, "New format type %d not supported\n", (int)new_img_type);
			goto done;
		}

		if(d->has_mask) {
			d->mask_type = (d->mode&0x80000000U) ? MASK_TYPE_NEW_8 : MASK_TYPE_NEW_1;
			d->maskbpp = 8;
			de_dbg(c, "mask type: %s\n", d->mask_type==MASK_TYPE_NEW_8 ? "alpha" : "binary");
		}
	}

	d->width = ((d->width_in_words-1) * 4 * 8 + (d->last_bit+1)) / d->fgbpp;
	d->pixels_to_ignore_at_start_of_row = d->first_bit / d->fgbpp;
	d->width -= d->pixels_to_ignore_at_start_of_row;

	de_dbg(c, "foreground bits/pixel: %d\n", (int)d->fgbpp);
	de_dbg(c, "calculated width: %d\n", (int)d->width);

	if(d->mask_type==MASK_TYPE_NEW_1 || d->mask_type==MASK_TYPE_NEW_8) {
		if(d->pixels_to_ignore_at_start_of_row>0) {
			de_warn(c, "This image has a new-style transparency mask, and a "
				"nonzero \"first bit\" field. This combination might not be "
				"handled correctly.");
		}
		d->mask_rowspan = ((d->width+31)/32)*4;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	do_setup_palette(c, d);

	do_image(c, d, fi);
done:
	de_finfo_destroy(c, fi);
}

static void de_run_rosprite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 sprite_size;
	de_int64 first_sprite_offset;
	de_int64 implied_file_size;
	de_int64 k;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	d->num_images = de_getui32le(0);
	de_dbg(c, "number of images: %d\n", (int)d->num_images);
	first_sprite_offset = de_getui32le(4) - 4;
	de_dbg(c, "first sprite offset: %d\n", (int)first_sprite_offset);
	implied_file_size = de_getui32le(8) - 4;
	de_dbg(c, "reported file size: %d\n", (int)implied_file_size);
	if(implied_file_size != c->infile->len) {
		de_warn(c, "The \"first free word\" field implies the file size is %d, but it "
			"is actually %d. This may not be a sprite file.\n",
			(int)implied_file_size, (int)c->infile->len);
	}

	pos = 12;
	for(k=0; k<d->num_images; k++) {
		if(pos>=c->infile->len) break;
		sprite_size = de_getui32le(pos);
		de_dbg(c, "image #%d at %d, size=%d\n", (int)k, (int)pos, (int)sprite_size);
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
	de_int64 h0, h1, h2;
	h0 = de_getui32le(0);
	h1 = de_getui32le(4);
	h2 = de_getui32le(8);

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
