// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// MAKIchan graphics
//  Supported: .MAG
//  TODO: .MAX, .MKI

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 width, height;
	de_int64 header_pos;
	de_int64 flag_a_offset;
	de_int64 flag_b_offset;
	de_int64 flag_b_size;
	de_int64 pixels_offset;
	de_int64 pixels_size;
	de_int64 num_colors;
	de_int64 bits_per_pixel;
	de_int64 rowspan;
	de_byte aspect_ratio_flag;
	int is_max;
	int is_mki;
	dbuf *unc_pixels;
	de_uint32 pal[256];
} lctx;

static void read_palette(deark *c, lctx *d, de_int64 pos)
{
	de_int64 k;
	de_byte cr, cg, cb;

	de_dbg(c, "palette at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	for(k=0; k<d->num_colors; k++) {
		cg = de_getbyte(pos+3*k);
		cr = de_getbyte(pos+3*k+1);
		cb = de_getbyte(pos+3*k+2);
		d->pal[k] = DE_MAKE_RGB(cr,cg,cb);
		de_dbg_pal_entry(c, k, d->pal[k]);
	}

	de_dbg_indent(c, -1);
}

static int read_mki_header(deark *c, lctx *d)
{
	de_int64 pos;

	de_dbg(c, "MKI header at %d\n", (int)d->header_pos);
	de_dbg_indent(c, 1);

	pos = d->header_pos;

	d->width = de_getui16be(pos+12);
	d->height = de_getui16be(pos+14);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);
	d->num_colors = 16;
	d->bits_per_pixel = 4;

	de_dbg_indent(c, -1);
	return 1;
}

static int read_mag_header(deark *c, lctx *d)
{
	de_int64 xoffset, yoffset;
	de_int64 width_raw, height_raw;
	de_int64 pos;
	de_byte model_code;
	de_byte model_flags;
	de_byte screen_mode;
	de_byte colors_code;
	int retval = 0;

	de_dbg(c, "header at %d\n", (int)d->header_pos);
	de_dbg_indent(c, 1);

	pos = d->header_pos;

	model_code = de_getbyte(pos+1);
	model_flags = de_getbyte(pos+2);
	de_dbg(c, "model code: 0x%02x, flags: 0x%02x\n",
		(unsigned int)model_code, (unsigned int)model_flags);
	if(model_code==0x03 && model_flags==0x44) { // Just a guess
		de_warn(c, "This looks like MAX format, which is not correctly supported.\n");
		d->is_max = 1;
	}

	screen_mode = de_getbyte(pos+3);
	de_dbg(c, "screen mode: %d\n", (int)screen_mode);
	de_dbg_indent(c, 1);
	d->aspect_ratio_flag = screen_mode&0x01;
	colors_code = screen_mode&0x82;
	if(colors_code==0x00) {
		d->num_colors = 16;
		d->bits_per_pixel = 4;
	}
	else if(colors_code==0x80) {
		d->num_colors = 256;
		d->bits_per_pixel = 8;
	}
	else if(colors_code==0x02) {
		d->num_colors = 8;
		// TODO: Support 8 color images
	}
	de_dbg(c, "number of colors: %d\n", (int)d->num_colors);
	de_dbg_indent(c, -1);

	xoffset = de_getui16le(pos+4);
	yoffset = de_getui16le(pos+6);
	de_dbg(c, "image offset: (%d,%d)\n", (int)xoffset, (int)yoffset);

	width_raw = de_getui16le(pos+8);
	height_raw = de_getui16le(pos+10);
	d->width = width_raw - xoffset + 1;
	d->height = height_raw - yoffset + 1;
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	d->flag_a_offset = de_getui32le(pos+12);
	d->flag_a_offset += d->header_pos;
	de_dbg(c, "flag A offset: %d\n", (int)d->flag_a_offset);

	d->flag_b_offset = de_getui32le(pos+16);
	d->flag_b_offset += d->header_pos;
	d->flag_b_size = de_getui32le(pos+20);
	de_dbg(c, "flag B offset: %d, size=%d\n", (int)d->flag_b_offset, (int)d->flag_b_size);

	d->pixels_offset = de_getui32le(pos+24);
	d->pixels_offset += d->header_pos;
	d->pixels_size = de_getui32le(pos+28);
	de_dbg(c, "pixels offset: %d, size=%d\n", (int)d->pixels_offset, (int)d->pixels_size);

	if(d->bits_per_pixel!=4 && d->bits_per_pixel!=8) {
		de_err(c, "Unsupported or unknown bits/pixel\n");
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_decompress(deark *c, lctx *d)
{
	static const de_byte deltax[16] = { 0,1,2,4,0,1,0,1,2,0,1,2,0,1,2, 0 };
	static const de_byte deltay[16] = { 0,0,0,0,1,1,2,2,2,4,4,4,8,8,8,16 };
	de_int64 x, y;
	de_int64 a_pos, b_pos;
	de_int64 p_pos;
	int a_bitnum;
	de_byte a_byte, b_byte;
	de_byte action_byte;
	de_byte flag_a_bit;
	unsigned int dcode;
	int k;
	de_int64 dpos;
	de_byte *action_byte_buf = NULL;
	de_byte wordbuf[2];

	de_dbg(c, "decompressing pixels\n");

	// Presumably, due to the compression scheme, every row must have a
	// multiple of 4 bytes.
	d->rowspan = ((d->width * d->bits_per_pixel + 31)/32)*4;

	d->unc_pixels = dbuf_create_membuf(c, d->rowspan * d->height);

	a_pos = d->flag_a_offset;
	a_byte = de_getbyte(a_pos++);
	a_bitnum = 7;
	b_pos = d->flag_b_offset;
	p_pos = d->pixels_offset;

	action_byte_buf = de_malloc(c, d->rowspan/4);

	for(y=0; y<d->height; y++) {
		for(x=0; x<d->rowspan/4; x++) {
			// Read next flag A bit
			flag_a_bit = a_byte & (1 << a_bitnum--);
			if(a_bitnum<0) {
				a_byte = de_getbyte(a_pos++);
				a_bitnum = 7;
			}

			if(flag_a_bit) {
				// If flag_a_bit is unset, re-use the action byte from the
				// previous row.
				// If flag bit A is set, the new action byte is the one from the
				// previous row XORed with the next B byte (don't ask me why).
				b_byte = de_getbyte(b_pos++);
				action_byte_buf[x] ^= b_byte;
			}

			action_byte = action_byte_buf[x];

			// Produce 4 uncompressed bytes, 2 for each nibble in the
			// action byte.
			for(k=0; k<2; k++) {
				if(k==0)
					dcode = (unsigned int)((action_byte&0xf0)>>4);
				else
					dcode = (unsigned int)(action_byte&0x0f);

				if(dcode==0) {
					// An "uncompressed" data word. Read it from the source file.
					de_read(wordbuf, p_pos, 2);
					p_pos += 2;
				}
				else {
					// Copy the data word from an earlier location in the image.
					dpos = d->unc_pixels->len -
						d->rowspan*(de_int64)deltay[dcode] -
						2*(de_int64)deltax[dcode];
					dbuf_read(d->unc_pixels, wordbuf, dpos, 2);
				}
				dbuf_write(d->unc_pixels, wordbuf, 2);
			}
		}
	}

	de_free(c, action_byte_buf);
	return 1;
}

static void do_create_image(deark *c, lctx *d)
{
	de_int64 i, j;
	unsigned int palent;
	struct deark_bitmap *img = NULL;

	img = de_bitmap_create(c, d->width, d->height, 3);

	if(d->aspect_ratio_flag) {
		img->density_code = DE_DENSITY_UNK_UNITS;
		img->xdens = 2.0;
		img->ydens = 1.0;
	}

	for(i=0; i<d->width; i++) {
		for(j=0; j<d->height; j++) {
			palent = (unsigned int)de_get_bits_symbol(d->unc_pixels, d->bits_per_pixel, j*d->rowspan, i);
			de_bitmap_setpixel_rgb(img, i, j, d->pal[palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

// Sets d->header_pos
static int find_mag_header(deark *c, lctx *d)
{
	de_int64 pos_1a = 0;
	int ret;

	// Find the first 0x1a byte.
	ret = dbuf_search_byte(c->infile, '\x1a', 0, c->infile->len, &pos_1a);
	if(ret) {
		// Find the first 0x00 byte after the first 0x1a byte.
		// TODO: Is this the correct algorithm, or should we just assume the
		// header starts immediately after the first 0x1a byte?
		ret = dbuf_search_byte(c->infile, '\0', pos_1a+1, c->infile->len-pos_1a-1, &d->header_pos);
		de_dbg(c, "header found at %d\n", (int)d->header_pos);
		return 1;
	}

	de_err(c, "Failed to find header. This is probably not a MAKIchan file.\n");
	return 0;
}

static void de_run_makichan(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "MAKI01", 6)) {
		d->is_mki = 1;
	}

	if(d->is_mki) {
		d->header_pos = 32;
		if(!read_mki_header(c, d)) goto done;
		read_palette(c, d, d->header_pos+16);
		de_err(c, "MKI format is not supported.\n");
		goto done;
	}
	else {
		if(!find_mag_header(c, d)) goto done;
		if(!read_mag_header(c, d)) goto done;
		read_palette(c, d, d->header_pos+32);
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	if(!do_decompress(c, d)) goto done;
	do_create_image(c, d);

done:
	dbuf_close(d->unc_pixels);
	de_free(c, d);
}

static int de_identify_makichan(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "MAKI0", 5))
		return 100;
	return 0;
}

void de_module_makichan(deark *c, struct deark_module_info *mi)
{
	mi->id = "makichan";
	mi->desc = "MAKIchan graphics";
	mi->run_fn = de_run_makichan;
	mi->identify_fn = de_identify_makichan;
}
