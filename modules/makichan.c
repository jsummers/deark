// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// MAKIchan graphics
//  Supported: Most .MAG, .MKI
//  Not supported: .MAX, some variant formats

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_makichan);

typedef struct localctx_struct {
	i64 width, height;
	i64 header_pos;
	i64 flag_a_offset;
	i64 flag_b_offset;
	i64 flag_b_size;
	i64 pixels_offset;
	i64 pixels_size;
	i64 num_colors;
	i64 bits_per_pixel;
	i64 rowspan;
	i64 width_adj, height_adj;

	u8 aspect_ratio_flag;
	int is_max;
	int is_mki;
	int is_mki_b;
	dbuf *virtual_screen;
	dbuf *unc_pixels;
	u32 pal[256];
} lctx;

static i64 de_int_round_up(i64 n, i64 m)
{
	return ((n+(m-1))/m)*m;
}

static void read_palette(deark *c, lctx *d, i64 pos)
{
	i64 k;
	u8 cr, cg, cb;

	de_dbg(c, "palette at %d", (int)pos);
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
	i64 xoffset, yoffset;
	i64 width_raw, height_raw;
	i64 pos;
	i64 flag_a_size;
	i64 pix_data_a_size;
	i64 pix_data_b_size;
	i64 expected_file_size;
	unsigned int extension_flags;
	int retval = 0;

	de_dbg(c, "MKI header at %d", (int)d->header_pos);
	de_dbg_indent(c, 1);

	pos = d->header_pos;

	d->flag_b_size = de_getu16be(pos+0);
	pix_data_a_size = de_getu16be(pos+2);
	pix_data_b_size = de_getu16be(pos+4);
	d->pixels_size = pix_data_a_size + pix_data_b_size;

	extension_flags = (unsigned int)de_getu16be(pos+6);
	de_dbg(c, "extension flags: 0x%04x", extension_flags);
	de_dbg_indent(c, 1);
	d->aspect_ratio_flag = extension_flags&0x0001;
	if(extension_flags&0x0002) {
		d->num_colors = 8;
	}
	else {
		d->num_colors = 16;
		d->bits_per_pixel = 4;
	}
	de_dbg(c, "number of colors: %d", (int)d->num_colors);
	de_dbg_indent(c, -1);

	xoffset = de_getu16be(pos+8);
	yoffset = de_getu16be(pos+10);
	de_dbg(c, "image offset: (%d,%d)", (int)xoffset, (int)yoffset);

	width_raw = de_getu16be(pos+12);
	d->width = width_raw - xoffset;
	height_raw = de_getu16be(pos+14);
	d->height = height_raw - yoffset;
	de_dbg_dimensions(c, d->width, d->height);
	if(d->width%64 != 0) {
		de_warn(c, "Width is not a multiple of 64. This image may not be handled correctly.");
	}
	d->width_adj = de_int_round_up(d->width, 64);
	if(d->height%4 != 0) {
		de_warn(c, "Height is not a multiple of 4. This image may not be handled correctly.");
	}
	d->height_adj = de_int_round_up(d->height, 4);

	d->flag_a_offset = pos + 16 + 48;
	// The documentation seems to say that flag A is *always* 1000 bytes, regardless of
	// how many bytes would actually be needed.
	// This would imply that a MAKI image can't have more than 256000 pixels.
	flag_a_size = 1000;
	//flag_a_size = (d->width_adj*d->height_adj)/256;

	d->flag_b_offset = d->flag_a_offset + flag_a_size;
	d->pixels_offset = d->flag_b_offset + d->flag_b_size;
	expected_file_size = d->pixels_offset + d->pixels_size;
	de_dbg(c, "flag A offset=%d, size=%d", (int)d->flag_a_offset, (int)flag_a_size);
	de_dbg(c, "flag B calculated_offset=%d, size=%d", (int)d->flag_b_offset, (int)d->flag_b_size);
	de_dbg(c, "pix data size_A=%d, size_B=%d", (int)pix_data_a_size, (int)pix_data_b_size);
	de_dbg(c, "pix data calculated_offset=%d, calculated_size=%d", (int)d->pixels_offset, (int)d->pixels_size);
	de_dbg(c, "calculated file size: %d", (int)expected_file_size);

	if(d->bits_per_pixel!=4 && d->bits_per_pixel!=8) {
		de_err(c, "Unsupported or unknown bits/pixel");
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void mki_decompress_virtual_screen(deark *c, lctx *d)
{
	i64 i, j;
	i64 a_pos, b_pos;
	i64 vs_rowspan;
	i64 k;
	u8 tmpn[4];
	u8 v;
	u8 a_byte = 0x00;
	int a_bitnum;

	vs_rowspan = d->width_adj/16;
	a_pos = d->flag_a_offset;
	a_bitnum = -1;
	b_pos = d->flag_b_offset;
	d->virtual_screen = dbuf_create_membuf(c, vs_rowspan*d->height_adj, 1);

	for(j=0; j<d->height_adj/4; j++) {
		for(i=0; i<d->width_adj/8; i++) {
			u8 flag_a_bit;

			// Read next flag A bit
			if(a_bitnum<0) {
				a_byte = de_getbyte(a_pos++);
				a_bitnum = 7;
			}
			flag_a_bit = a_byte & (1 << a_bitnum--);

			if(!flag_a_bit)
				continue;

			// Read the next two bytes from flag B, and split them into 4 nibbles.
			tmpn[0] = de_getbyte(b_pos++);
			tmpn[2] = de_getbyte(b_pos++);
			tmpn[1] = tmpn[0]&0x0f;
			tmpn[3] = tmpn[2]&0x0f;
			tmpn[0] >>= 4;
			tmpn[2] >>= 4;

			for(k=0; k<4; k++) {
				i64 vs_pos;

				vs_pos = (4*j+k)*vs_rowspan + i/2;
				if(i%2==0) {
					v = tmpn[k]<<4;
				}
				else {
					v = dbuf_getbyte(d->virtual_screen, vs_pos) | tmpn[k];
				}
				dbuf_writebyte_at(d->virtual_screen, vs_pos, v);
			}
		}
	}
}

static void mki_decompress_pixels(deark *c, lctx *d)
{
	i64 i, j;
	i64 p_pos;
	i64 delta_y;
	i64 vs_pos;
	int vs_bitnum;
	u8 vs_byte = 0x00;

	d->rowspan = d->width_adj/2;
	vs_pos = 0;
	vs_bitnum = -1;
	p_pos = d->pixels_offset;
	delta_y = d->is_mki_b ? 4 : 2;
	d->unc_pixels = dbuf_create_membuf(c, d->rowspan*d->height_adj, 1);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->rowspan; i++) {
			u8 vs_bit;
			u8 v;

			// Read the next virtual-screen bit
			if(vs_bitnum<0) {
				vs_byte = dbuf_getbyte(d->virtual_screen, vs_pos++);
				vs_bitnum = 7;
			}
			vs_bit = vs_byte & (1 << vs_bitnum--);

			if(vs_bit) {
				v = de_getbyte(p_pos++);
			}
			else {
				v = 0x00;
			}

			if(j>=delta_y) {
				v ^= dbuf_getbyte(d->unc_pixels, (j-delta_y)*d->rowspan + i);
			}
			dbuf_writebyte(d->unc_pixels, v);
		}
	}
}

static int read_mag_header(deark *c, lctx *d)
{
	i64 xoffset, yoffset;
	i64 width_raw, height_raw;
	i64 pos;
	u8 model_code;
	u8 model_flags;
	u8 screen_mode;
	u8 colors_code;
	int retval = 0;

	de_dbg(c, "header at %d", (int)d->header_pos);
	de_dbg_indent(c, 1);

	pos = d->header_pos;

	model_code = de_getbyte(pos+1);
	model_flags = de_getbyte(pos+2);
	de_dbg(c, "model code: 0x%02x, flags: 0x%02x",
		(unsigned int)model_code, (unsigned int)model_flags);
	if(model_code==0x03 && (model_flags==0x44 || model_flags==0x24)) {
		de_warn(c, "This looks like MAX format, which is not correctly supported.");
		d->is_max = 1;
	}

	screen_mode = de_getbyte(pos+3);
	de_dbg(c, "screen mode: %d", (int)screen_mode);
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
	de_dbg(c, "number of colors: %d", (int)d->num_colors);
	de_dbg_indent(c, -1);

	xoffset = de_getu16le(pos+4);
	yoffset = de_getu16le(pos+6);
	de_dbg(c, "image offset: (%d,%d)", (int)xoffset, (int)yoffset);

	width_raw = de_getu16le(pos+8);
	height_raw = de_getu16le(pos+10);
	d->width = width_raw - xoffset + 1;
	d->height = height_raw - yoffset + 1;
	de_dbg_dimensions(c, d->width, d->height);

	d->flag_a_offset = de_getu32le(pos+12);
	d->flag_a_offset += d->header_pos;
	de_dbg(c, "flag A offset: %d", (int)d->flag_a_offset);

	d->flag_b_offset = de_getu32le(pos+16);
	d->flag_b_offset += d->header_pos;
	d->flag_b_size = de_getu32le(pos+20);
	de_dbg(c, "flag B offset: %d, size=%d", (int)d->flag_b_offset, (int)d->flag_b_size);

	d->pixels_offset = de_getu32le(pos+24);
	d->pixels_offset += d->header_pos;
	d->pixels_size = de_getu32le(pos+28);
	de_dbg(c, "pixels offset: %d, size=%d", (int)d->pixels_offset, (int)d->pixels_size);

	if(d->bits_per_pixel!=4 && d->bits_per_pixel!=8) {
		de_err(c, "Unsupported or unknown bits/pixel");
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_mag_decompress(deark *c, lctx *d)
{
	static const u8 delta_x[16] = { 0,1,2,4,0,1,0,1,2,0,1,2,0,1,2, 0 };
	static const u8 delta_y[16] = { 0,0,0,0,1,1,2,2,2,4,4,4,8,8,8,16 };
	i64 x, y;
	i64 a_pos, b_pos;
	i64 p_pos;
	int a_bitnum; // Index of next bit to read. -1 = no more bits in a_byte.
	u8 a_byte = 0x00;
	u8 b_byte;
	int k;
	i64 dpos;
	u8 *action_byte_buf = NULL;
	u8 wordbuf[2];

	de_dbg(c, "decompressing pixels");

	// Presumably, due to the compression scheme, every row must have a
	// multiple of 4 bytes.
	d->rowspan = ((d->width * d->bits_per_pixel + 31)/32)*4;

	d->unc_pixels = dbuf_create_membuf(c, d->rowspan * d->height, 1);

	a_pos = d->flag_a_offset;
	a_bitnum = -1;
	b_pos = d->flag_b_offset;
	p_pos = d->pixels_offset;

	action_byte_buf = de_malloc(c, d->rowspan/4);

	for(y=0; y<d->height; y++) {
		for(x=0; x<d->rowspan/4; x++) {
			u8 action_byte;
			u8 flag_a_bit;

			// Read next flag A bit
			if(a_bitnum<0) {
				a_byte = de_getbyte(a_pos++);
				a_bitnum = 7;
			}
			flag_a_bit = a_byte & (1 << a_bitnum--);

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
				unsigned int dcode;

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
						d->rowspan*(i64)delta_y[dcode] -
						2*(i64)delta_x[dcode];
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
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;

	img = de_bitmap_create(c, d->width, d->height, 3);

	fi = de_finfo_create(c);

	if(d->aspect_ratio_flag) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 2.0;
		fi->density.ydens = 1.0;
	}

	de_convert_image_paletted(d->unc_pixels, 0,
		d->bits_per_pixel, d->rowspan, d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, fi, 0);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

// Sets d->header_pos
static int find_mag_header(deark *c, lctx *d)
{
	i64 pos_1a = 0;
	int ret;

	// Find the first 0x1a byte.
	ret = dbuf_search_byte(c->infile, '\x1a', 0, c->infile->len, &pos_1a);
	if(ret) {
		// Find the first 0x00 byte after the first 0x1a byte.
		// TODO: Is this the correct algorithm, or should we just assume the
		// header starts immediately after the first 0x1a byte?
		ret = dbuf_search_byte(c->infile, '\0', pos_1a+1, c->infile->len-pos_1a-1, &d->header_pos);
		de_dbg(c, "header found at %d", (int)d->header_pos);
		return 1;
	}

	de_err(c, "Failed to find header. This is probably not a MAKIchan file.");
	return 0;
}

static void do_mag(deark *c, lctx *d)
{
	if(!find_mag_header(c, d)) goto done;
	if(!read_mag_header(c, d)) goto done;
	read_palette(c, d, d->header_pos+32);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	if(!do_mag_decompress(c, d)) goto done;
	do_create_image(c, d);
done:
	;
}

static void do_mki(deark *c, lctx *d)
{
	d->header_pos = 32;
	if(!read_mki_header(c, d)) goto done;
	read_palette(c, d, d->header_pos+16);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	mki_decompress_virtual_screen(c, d);
	mki_decompress_pixels(c, d);
	do_create_image(c, d);
done:
	;
}

static void de_run_makichan(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "MAKI01", 6)) {
		d->is_mki = 1;
		if(de_getbyte(6)=='B') {
			d->is_mki_b = 1;
		}
	}

	if(d->is_mki) {
		do_mki(c, d);
	}
	else {
		do_mag(c, d);
	}

	dbuf_close(d->unc_pixels);
	dbuf_close(d->virtual_screen);
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
