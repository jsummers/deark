// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Spectrum 512 Compressed (.SPC)

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_spectrum512c);

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
	static const de_int64 num_colors = 199*48;
	de_int64 pixels_cmpr_len;
	de_int64 pal_cmpr_len;
	de_int64 pos;
	dbuf *unc_pixels_planar = NULL;
	dbuf *spufile = NULL;
	de_uint32 *pal = NULL;

	pal = de_malloc(c, num_colors*sizeof(de_uint32));

	pos = 4;
	pixels_cmpr_len = de_getui32be(pos);
	de_dbg(c, "pixels compressed len: %d\n", (int)pixels_cmpr_len);
	pos += 4;
	pal_cmpr_len = de_getui32be(pos);
	de_dbg(c, "palette compressed len: %d\n", (int)pal_cmpr_len);
	pos += 4;

	de_dbg(c, "pixels at %d\n", (int)pos);
	unc_pixels_planar = dbuf_create_membuf(c, 32000, 1);
	do_uncompress_spc_pixels(c->infile, pos, pixels_cmpr_len, unc_pixels_planar);
	pos += pixels_cmpr_len;

	// We'll construct an in-memory SPU file, then use our SPU module to
	// process it. (TODO: This is probably temporary.)
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

	de_run_module_by_id_on_slice(c, "spectrum512u", NULL, spufile, 0, spufile->len);

	dbuf_close(unc_pixels_planar);
	dbuf_close(spufile);
	de_free(c, pal);
}

static int de_identify_spectrum512c(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x53\x50\x00\x00", 4))
		return 0;

	if(de_input_file_has_ext(c, "spc")) {
		return 100;
	}
	return 80;
}

void de_module_spectrum512c(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512c";
	mi->desc = "Spectrum 512 Compressed";
	mi->run_fn = de_run_spectrum512c;
	mi->identify_fn = de_identify_spectrum512c;
}
