// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

// Acorn Sprite / RISC OS Sprite

struct old_mode_info {
	de_uint32 mode;
	int fgbpp;
	int maskbpp;
	int xdpi;
	int ydpi;
};
static const struct old_mode_info old_mode_info_arr[] = {
	{15, 8, 1, 90, 45},
	{20, 4, 1, 90, 90},
	{32, 8, 1, 90, 90},
	{1000, 0, 0, 0, 0}
};

typedef struct localctx_struct {
	de_int64 num_images;

	de_int64 width_in_words;
	de_int64 first_bit, last_bit;
	de_int64 width, height;
	de_int64 image_offset;
	de_int64 mask_offset;

	de_uint32 mode;
	de_uint32 img_type;
	de_int64 fgbpp;
	de_int64 maskbpp;
	de_int64 xdpi, ydpi;
	int has_mask;
} lctx;

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

static void do_image(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte n;
	de_uint32 clr;

	img = de_bitmap_create(c, d->width, d->height, 3);
	img->density_code = DE_DENSITY_DPI;
	img->xdens = (double)d->xdpi;
	img->ydens = (double)d->ydpi;

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			n = de_get_bits_symbol_lsb(c->infile, d->fgbpp, d->image_offset + 4*d->width_in_words*j, i);

			if(d->fgbpp==8) {
				clr = getpal256((int)n);
			}
			else if(d->fgbpp==4) {
				clr = getpal16((int)n);
			}
			else {
				clr = 0;
			}

			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_sprite(deark *c, lctx *d, de_int64 index,
	de_int64 pos1, de_int64 len)
{
	// TODO: Name at pos 4, len=12

	d->width_in_words = de_getui32le(pos1+16) +1;
	d->height = de_getui32le(pos1+20) +1;
	de_dbg(c, "width-in-words: %d, height: %d\n", (int)d->width_in_words, (int)d->height);

	d->first_bit = de_getui32le(pos1+24);
	d->last_bit = de_getui32le(pos1+28);
	d->image_offset = de_getui32le(pos1+32) + pos1;
	d->mask_offset = de_getui32le(pos1+36) + pos1;
	d->has_mask = (d->mask_offset != d->image_offset);
	d->mode = (de_uint32)de_getui32le(pos1+40);
	de_dbg(c, "first bit: %d, last bit: %d\n", (int)d->first_bit, (int)d->last_bit);
	de_dbg(c, "image offset: %d, mask_offset: %d\n", (int)d->image_offset, (int)d->mask_offset);
	de_dbg(c, "mode: 0x%08x\n", (unsigned int)d->mode);
	d->img_type = (d->mode&0xf8000000U)>>27;
	de_dbg(c, "image type: %d%s\n", (int)d->img_type, d->img_type==0?" (old format)":"");

	d->fgbpp=0;
	d->maskbpp=0;
	d->xdpi = 0;
	d->ydpi = 0;

	if(d->has_mask) {
		de_err(c, "Transparency not supported\n");
		goto done;
	}

	if(d->img_type==0) {
		// "old mode"
		int x;

		for(x=0; old_mode_info_arr[x].mode<1000; x++) {
			if(d->mode == old_mode_info_arr[x].mode) {
				d->fgbpp = (de_int64)old_mode_info_arr[x].fgbpp;
				d->maskbpp = (de_int64)old_mode_info_arr[x].maskbpp;
				d->xdpi = (de_int64)old_mode_info_arr[x].xdpi;
				d->ydpi = (de_int64)old_mode_info_arr[x].ydpi;
				break;
			}
		}

		if(d->fgbpp==0) {
			de_err(c, "Mode %d not supported\n", (int)d->mode);
			goto done;
		}
	}
	else {
		de_err(c, "New format not supported\n");
		goto done;
	}

	// Temp hack. TODO: Use first_bit, last_bit.
	d->width = (d->width_in_words * 4 * 8) / d->fgbpp;

	de_dbg(c, "foreground bits/pixel: %d\n", (int)d->fgbpp);
	if(d->has_mask) de_dbg(c, "mask bits/pixel: %d\n", (int)d->maskbpp);
	de_dbg(c, "calculated width: %d\n", (int)d->width);

	do_image(c, d);
done:
	;
}

static void de_run_sprite(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 sprite_size;
	de_int64 first_sprite_offset;
	de_int64 implied_file_size;
	de_int64 k;

	de_dbg(c, "In sprite module\n");

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

static int de_identify_sprite(deark *c)
{
	de_int64 h0, h1, h2;
	h0 = de_getui32le(0);
	h1 = de_getui32le(4);
	h2 = de_getui32le(8);

	if(h0<1 || h0>DE_MAX_IMAGES_PER_FILE) return 0;
	if(h1-4<12) return 0;
	if(h1-4 >= c->infile->len) return 0;
	if(h2-4 != c->infile->len) return 0;

	return 80;
}

void de_module_sprite(deark *c, struct deark_module_info *mi)
{
	mi->id = "sprite";
	mi->run_fn = de_run_sprite;
	mi->identify_fn = de_identify_sprite;
}
