// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Spectrum 512 Uncompressed (.SPU)
// Spectrum 512 Compressed (.SPC)
// Spectrum 512 Smooshed (.SPS)

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_spectrum512u);
DE_DECLARE_MODULE(de_module_spectrum512c);
DE_DECLARE_MODULE(de_module_spectrum512s);

// **************************************************************************

static void do_spu_internal(deark *c, dbuf *inf)
{
	struct atari_img_decode_data *adata = NULL;
	static const de_int64 num_colors = 199*48;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->is_spectrum512 = 1;
	adata->pal = de_malloc(c, num_colors*sizeof(de_uint32));
	adata->bpp = 4;
	adata->w = 320;
	adata->h = 199;
	adata->ncolors = num_colors;

	if(!dbuf_memcmp(inf, 0, (const void*)"5BIT", 4)) {
		de_warn(c, "This looks like an \"Enhanced\" Spectrum 512 file, "
			"which is not fully supported.\n");
	}

	de_fmtutil_read_atari_palette(c, inf, 32000, adata->pal, num_colors, num_colors);

	adata->unc_pixels = dbuf_open_input_subfile(inf, 160, inf->len-160);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	de_fmtutil_atari_set_standard_density(c, adata);
	de_fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file(adata->img, NULL, 0);

	if(adata) {
		de_bitmap_destroy(adata->img);
		de_free(c, adata->pal);
		dbuf_close(adata->unc_pixels);
		de_free(c, adata);
	}
}

static void de_run_spectrum512u(deark *c, de_module_params *mparams)
{
	do_spu_internal(c, c->infile);
}

static int de_identify_spectrum512u(deark *c)
{
	if(c->infile->len!=51104 && c->infile->len!=51200)
		return 0;

	if(de_input_file_has_ext(c, "spu")) {
		return (c->infile->len==51104) ? 90 : 10;
	}
	return 0;
}

void de_module_spectrum512u(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512u";
	mi->desc = "Spectrum 512 Uncompressed";
	mi->run_fn = de_run_spectrum512u;
	mi->identify_fn = de_identify_spectrum512u;
}

// **************************************************************************

// This is almost PackBits, but not quite.
static void do_uncompress_spc_pixels(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(unc_pixels->max_len>0 && unc_pixels->len>=unc_pixels->max_len) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>=128) { // A compressed run
			count = 258 - (de_int64)b;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
	}
}

// After SPC decompression, we have a 320x199 image, but with the
// bytes in an inconvenient order, different from SPU format.
// This converts an SPC after-decompression byte offset (from 0 to 31839)
// to the corresponding SPU file offset (from 160 to 31999).
static de_int64 spc_cvtpos(de_int64 a)
{
	de_int64 b;

	if(a%2)
		b = 160 + (a-1)*4 + 1; // if odd
	else
		b = 160 + a*4; // if even

	while(b>=32000) {
		b -= (32000-(160+2));
	}
	return b;
}

static void spc_deplanarize(deark *c, dbuf *src, dbuf *dst)
{
	de_int64 i;
	de_byte b;

	for(i=0; i<src->len; i++) {
		b = dbuf_getbyte(src, i);
		dbuf_writebyte_at(dst, spc_cvtpos(i), b);
	}
}

// Read from c->infile at offset pos1, append to uncmpr_pal
static void spc_uncompress_pal(deark *c, de_int64 pos1, dbuf *uncmpr_pal)
{
	static const de_int64 num_pals = 199*3;
	de_int64 pos = pos1;
	de_int64 i, k;
	unsigned int code;

	for(i=0; i<num_pals; i++) {
		code = (unsigned int)de_getui16be(pos);
		pos += 2;
		for(k=0; k<16; k++) {
			// Bit 15 is ignored. The corresponding pal entry will always be black.
			if(k<=14 && (code&0x1)) {
				dbuf_copy(c->infile, pos, 2, uncmpr_pal);
				pos += 2;
			}
			else {
				dbuf_write_zeroes(uncmpr_pal, 2);
			}
			code >>= 1;
		}
	}
}

static void de_run_spectrum512c(deark *c, de_module_params *mparams)
{
	de_int64 pixels_cmpr_len;
	de_int64 pal_cmpr_len;
	de_int64 pos;
	dbuf *unc_pixels_planar = NULL;
	dbuf *spufile = NULL;
	int to_spu = 0;

	if(de_get_ext_option(c, "spectrum512:tospu")) {
		to_spu = 1;
	}

	pos = 4;
	pixels_cmpr_len = de_getui32be(pos);
	de_dbg(c, "pixels compressed len: %d\n", (int)pixels_cmpr_len);
	pos += 4;
	pal_cmpr_len = de_getui32be(pos);
	de_dbg(c, "palette compressed len: %d\n", (int)pal_cmpr_len);
	pos += 4;

	de_dbg(c, "pixels at %d\n", (int)pos);
	// Decompress the pixel data into an in-memory buffer.
	unc_pixels_planar = dbuf_create_membuf(c, 32000, 1);
	do_uncompress_spc_pixels(c->infile, pos, pixels_cmpr_len, unc_pixels_planar);
	pos += pixels_cmpr_len;

	// We'll construct an in-memory SPU file, then (usually) use our
	// SPU module's decoder to process it.
	spufile = dbuf_create_membuf(c, 51104, 0x1);

	// Rearrange the bytes in the image data, as we write them to our
	// in-memory image of an SPU file.
	// (This could be done more efficiently during decompression,
	// but the code would be messier.)
	spc_deplanarize(c, unc_pixels_planar, spufile);

	// Make sure we write the uncompressed palette at exactly offset 32000.
	dbuf_truncate(spufile, 32000);

	de_dbg(c, "palette at %d\n", (int)pos);
	spc_uncompress_pal(c, pos, spufile);

	if(to_spu) {
		// Instead of decoding the image, write it in .SPU format
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "spu", NULL, 0);
		dbuf_copy(spufile, 0, spufile->len, outf);
		dbuf_close(outf);
	}
	else {
		do_spu_internal(c, spufile);
	}

	dbuf_close(unc_pixels_planar);
	dbuf_close(spufile);
}

static int de_identify_spectrum512c(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x53\x50\x00\x00", 4))
		return 0;

	if(de_input_file_has_ext(c, "spc")) {
		return 100;
	}

	if(de_input_file_has_ext(c, "sps")) {
		return 0;
	}

	return 10;
}

void de_module_spectrum512c(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512c";
	mi->desc = "Spectrum 512 Compressed";
	mi->run_fn = de_run_spectrum512c;
	mi->identify_fn = de_identify_spectrum512c;
}

// **************************************************************************

// After SPS0 decompression, we have a 320x199 image, but with the
// bytes in an inconvenient order, different from SPU format.
// This converts an SPS0 after-decompression byte offset (from 0 to 31839)
// to the corresponding SPU file offset (from 160 to 31999).
static de_int64 sps0_cvtpos(de_int64 a)
{
	de_int64 b;
	b = 160 + (a%199)*160 + ((a%7960)/398)*8 + (a/(199*40))*2 + (a%398)/199;
	return b;
}

static void sps0_deplanarize(deark *c, dbuf *src, dbuf *dst)
{
	de_int64 i;
	de_byte b;

	for(i=0; i<src->len; i++) {
		b = dbuf_getbyte(src, i);
		dbuf_writebyte_at(dst, sps0_cvtpos(i), b);
	}
}

static void do_uncompress_sps_pixels(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(unc_pixels->max_len>0 && unc_pixels->len>=unc_pixels->max_len) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b<=127) { // A compressed run
			count = (de_int64)b +3;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else { // An uncompressed run
			count = (de_int64)b - 127;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
	}
}

struct bit_reader {
	de_int64 nextbytepos;
	de_byte cur_byte;
	unsigned int bits_left;
};

static unsigned int bit_reader_getbit(dbuf *f, struct bit_reader *br)
{
	if(br->bits_left<1) {
		br->cur_byte = dbuf_getbyte(f, br->nextbytepos++);
		br->bits_left = 8;
	}
	return (br->cur_byte>>(--br->bits_left))&0x1;
}

static unsigned int bit_reader_getint(dbuf *f, struct bit_reader *br, unsigned int nbits)
{
	unsigned int k;
	unsigned int n = 0;

	for(k=0; k<nbits; k++) {
		n = (n<<1) | bit_reader_getbit(f, br);
	}
	return n;
}

// Read from c->infile at offset pos1, append to uncmpr_pal
static void spu_uncompress_pal(deark *c, de_int64 pos1, dbuf *uncmpr_pal)
{
	static const de_int64 num_pals = 199*3;
	de_int64 i;
	unsigned int k;
	unsigned int code;
	struct bit_reader br;

	br.nextbytepos = pos1;
	br.cur_byte = 0;
	br.bits_left = 0;

	for(i=0; i<num_pals; i++) {
		code = bit_reader_getint(c->infile, &br, 14);

		for(k=0; k<16; k++) {
			// Palette entries 0 and 15 are always black
			if(k>=1 && k<=14 && (code&(1<<(14-k)))) {
				unsigned int cr, cg, cb;
				unsigned int palcode;
				cr = bit_reader_getint(c->infile, &br, 3);
				cg = bit_reader_getint(c->infile, &br, 3);
				cb = bit_reader_getint(c->infile, &br, 3);
				palcode = (cr<<8)|(cg<<4)|cb;
				dbuf_writeui16be(uncmpr_pal, palcode);
			}
			else {
				dbuf_write_zeroes(uncmpr_pal, 2);
			}
		}
	}
}

static void de_run_spectrum512s(deark *c, de_module_params *mparams)
{
	de_int64 pixels_cmpr_len;
	de_int64 pal_cmpr_len;
	de_int64 pal_pos;
	de_int64 pos;
	dbuf *unc_pixels_planar = NULL;
	dbuf *spufile = NULL;
	int to_spu = 0;
	unsigned int format_code;

	// TODO: Consolidate most of this code with .SPC

	if(de_get_ext_option(c, "spectrum512:tospu")) {
		to_spu = 1;
	}

	pos = 4;
	pixels_cmpr_len = de_getui32be(pos);
	de_dbg(c, "pixels compressed len: %d\n", (int)pixels_cmpr_len);
	pos += 4;
	pal_cmpr_len = de_getui32be(pos);
	de_dbg(c, "palette compressed len: %d\n", (int)pal_cmpr_len);
	pos += 4;

	pal_pos = pos + pixels_cmpr_len;

	if(pal_pos + pal_cmpr_len > c->infile->len) {
		de_err(c, "Invalid or truncated file\n");
		goto done;
	}

	format_code = de_getbyte(pal_pos + pal_cmpr_len-1);
	format_code &= 0x1;
	de_dbg(c, "format code: %u\n", format_code);

	de_dbg(c, "pixels at %d\n", (int)pos);
	// Decompress the pixel data into an in-memory buffer.
	unc_pixels_planar = dbuf_create_membuf(c, 32000, 1);
	do_uncompress_sps_pixels(c->infile, pos, pixels_cmpr_len, unc_pixels_planar);
	pos += pixels_cmpr_len;

	// We'll construct an in-memory SPU file, then (usually) use our
	// SPU module's decoder to process it.
	spufile = dbuf_create_membuf(c, 51104, 0x1);

	// Rearrange the bytes in the image data, as we write them to our
	// in-memory image of an SPU file.
	// (This could be done more efficiently during decompression,
	// but the code would be messier.)
	if(format_code==0) {
		sps0_deplanarize(c, unc_pixels_planar, spufile);
	}
	else {
		spc_deplanarize(c, unc_pixels_planar, spufile);
	}

	// Make sure we write the uncompressed palette at exactly offset 32000.
	dbuf_truncate(spufile, 32000);

	pos = pal_pos;
	de_dbg(c, "palette at %d\n", (int)pos);
	spu_uncompress_pal(c, pos, spufile);

	if(to_spu) {
		// Instead of decoding the image, write it in .SPU format
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "spu", NULL, 0);
		dbuf_copy(spufile, 0, spufile->len, outf);
		dbuf_close(outf);
	}
	else {
		do_spu_internal(c, spufile);
	}

done:
	dbuf_close(unc_pixels_planar);
	dbuf_close(spufile);
}

static int de_identify_spectrum512s(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x53\x50\x00\x00", 4))
		return 0;

	if(de_input_file_has_ext(c, "sps")) {
		return 100;
	}

	// No reason to return anything but 0. The file will be identified as SPC.
	return 0;
}

void de_module_spectrum512s(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512s";
	mi->desc = "Spectrum 512 Smooshed";
	mi->run_fn = de_run_spectrum512s;
	mi->identify_fn = de_identify_spectrum512s;
}
