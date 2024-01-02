// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Spectrum 512 Uncompressed (.SPU)
// Spectrum 512 Compressed (.SPC)
// Spectrum 512 Smooshed (.SPS)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_spectrum512u);
DE_DECLARE_MODULE(de_module_spectrum512c);
DE_DECLARE_MODULE(de_module_spectrum512s);

// **************************************************************************

static void do_spu_internal(deark *c, dbuf *inf, int is_enhanced)
{
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	static const i64 num_colors = 199*48;

	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->is_spectrum512 = 1;
	adata->pal = de_mallocarray(c, num_colors, sizeof(u32));
	adata->bpp = 4;
	adata->w = 320;
	adata->h = 199;
	adata->ncolors = num_colors;

	fmtutil_read_atari_palette(c, inf, 32000, adata->pal, num_colors, num_colors,
		is_enhanced?DE_FLAG_ATARI_15BIT_PAL:0);

	adata->unc_pixels = dbuf_open_input_subfile(inf, 160, inf->len-160);
	adata->img = de_bitmap_create(c, adata->w, adata->h, 3);
	fi = de_finfo_create(c);
	fmtutil_atari_set_standard_density(c, adata, fi);
	fmtutil_atari_decode_image(c, adata);
	de_bitmap_write_to_file_finfo(adata->img, fi, 0);

	if(adata) {
		de_bitmap_destroy(adata->img);
		de_free(c, adata->pal);
		dbuf_close(adata->unc_pixels);
		de_free(c, adata);
	}
	de_finfo_destroy(c, fi);
}

static void de_run_spectrum512u(deark *c, de_module_params *mparams)
{
	int is_enhanced = 0;

	if(!dbuf_memcmp(c->infile, 0, (const void*)"5BIT", 4)) {
		is_enhanced = 1;
	}
	de_declare_fmtf(c, "Spectrum 512 Uncompressed%s", (is_enhanced?" Enhanced":""));

	do_spu_internal(c, c->infile, is_enhanced);
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

static void de_help_spectrum512u(deark *c)
{
	fmtutil_atari_help_palbits(c);
}

void de_module_spectrum512u(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512u";
	mi->desc = "Spectrum 512 Uncompressed";
	mi->run_fn = de_run_spectrum512u;
	mi->identify_fn = de_identify_spectrum512u;
	mi->help_fn = de_help_spectrum512u;
}

// **************************************************************************

struct spc_sps_ctx {
	int is_sps;
	u8 sps_format_code;
	i64 pixels_pos;
	i64 pixels_cmpr_len;
	i64 pal_pos;
	i64 pal_cmpr_len;
};

// This is almost PackBits, but not quite.
static void spc_decompress_pixels(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 endpos;
	i64 nbytes_written = 0;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	while(1) {
		if(dcmpro->len_known && nbytes_written >= dcmpro->expected_len) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos+2 > endpos) { // Min item size is 2 bytes
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(dcmpri->f, pos++);

		if(b>=128) { // A compressed run
			count = 258 - (i64)b;
			b2 = dbuf_getbyte(dcmpri->f, pos++);
			dbuf_write_run(dcmpro->f, b2, count);
			nbytes_written += count;
		}
		else { // An uncompressed run
			count = 1 + (i64)b;
			if(pos+count > endpos) {
				pos--;
				break;
			}
			dbuf_copy(dcmpri->f, pos, count, dcmpro->f);
			pos += count;
			nbytes_written += count;
		}
	}

	dbuf_flush(dcmpro->f);
	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

static void sps_decompress_pixels(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 endpos;
	i64 nbytes_written = 0;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	while(1) {
		if(dcmpro->len_known && nbytes_written >= dcmpro->expected_len) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos+2 > endpos) { // Min item size is 2 bytes
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(dcmpri->f, pos++);

		if(b<=127) { // A compressed run
			count = (i64)b +3;
			b2 = dbuf_getbyte(dcmpri->f, pos++);
			dbuf_write_run(dcmpro->f, b2, count);
			nbytes_written += count;
		}
		else { // An uncompressed run
			count = (i64)b - 127;
			if(pos+count > endpos) {
				pos--;
				break;
			}
			dbuf_copy(dcmpri->f, pos, count, dcmpro->f);
			pos += count;
			nbytes_written += count;
		}
	}

	dbuf_flush(dcmpro->f);
	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

static void decompress_spc_or_sps(deark *c, struct spc_sps_ctx *d, dbuf *unc_pixels_planar)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = d->pixels_pos;
	dcmpri.len = d->pixels_cmpr_len;
	dcmpro.f = unc_pixels_planar;
	dcmpro.len_known = 1;
	dcmpro.expected_len = 32000;

	if(d->is_sps) {
		sps_decompress_pixels(c, &dcmpri, &dcmpro, &dres);
	}
	else {
		spc_decompress_pixels(c, &dcmpri, &dcmpro, &dres);
	}

	if(dres.bytes_consumed_valid) {
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
			dres.bytes_consumed, unc_pixels_planar->len);
	}

	// We expect exactly 31840.
	if(unc_pixels_planar->len<31840 || unc_pixels_planar->len>31970) {
		de_warn(c, "Decompression may have failed");
	}

	if(unc_pixels_planar->len > 31840) {
		dbuf_truncate(unc_pixels_planar, 31840);
	}
}

// After SPC decompression, we have a 320x199 image, but with the
// bytes in an inconvenient order, different from SPU format.
// This converts an SPC after-decompression byte offset (from 0 to 31839)
// to the corresponding SPU file offset (from 160 to 31999).
static i64 reorderfn_spc(i64 a)
{
	i64 b;

	if(a%2)
		b = 160 + (a-1)*4 + 1; // if odd
	else
		b = 160 + a*4; // if even

	while(b>=32000) {
		b -= (32000-(160+2));
	}
	return b;
}

// For SPS type 0. See reorderfn_spc() comments for details.
static i64 reorderfn_sps0(i64 a)
{
	i64 b;
	b = 160 + (a%199)*160 + ((a%7960)/398)*8 + (a/7960)*2 + (a%398)/199;
	return b;
}

typedef i64 (*reorder_fn)(i64 a);

static void reorder_img_bytes(deark *c, dbuf *src, dbuf *dst, reorder_fn rfn)
{
	i64 i;
	u8 b;

	for(i=0; i<src->len; i++) {
		b = dbuf_getbyte(src, i);
		dbuf_writebyte_at(dst, rfn(i), b);
	}
}

// Read from c->infile at offset pos1, append to uncmpr_pal
static void spc_decompress_pal(deark *c, i64 pos1, dbuf *uncmpr_pal)
{
	static const i64 num_pals = 199*3;
	i64 pos = pos1;
	i64 i, k;
	UI code;

	for(i=0; i<num_pals; i++) {
		code = (UI)de_getu16be(pos);
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

// Read from c->infile at offset pos1, append to uncmpr_pal
static void sps_decompress_pal(deark *c, i64 pos1, dbuf *uncmpr_pal)
{
	static const i64 num_pals = 199*3;
	i64 i;
	UI k;
	UI code;
	struct de_bitreader bitrd;

	de_zeromem(&bitrd, sizeof(struct de_bitreader));
	bitrd.f = c->infile;
	bitrd.curpos = pos1;
	bitrd.endpos = c->infile->len;

	for(i=0; i<num_pals; i++) {
		code = (UI)de_bitreader_getbits(&bitrd, 14);

		for(k=0; k<16; k++) {
			// Palette entries 0 and 15 are always black
			if(k>=1 && k<=14 && (code&(1<<(14-k)))) {
				UI cr, cg, cb;
				UI palcode;

				cr = (UI)de_bitreader_getbits(&bitrd, 3);
				cg = (UI)de_bitreader_getbits(&bitrd, 3);
				cb = (UI)de_bitreader_getbits(&bitrd, 3);
				palcode = (cr<<8)|(cg<<4)|cb;
				dbuf_writeu16be(uncmpr_pal, palcode);
			}
			else {
				dbuf_write_zeroes(uncmpr_pal, 2);
			}
		}
	}
}

static void do_run_spectrum512c_s_internal(deark *c, de_module_params *mparams, int is_sps1)
{
	struct spc_sps_ctx *d = NULL;
	i64 pos;
	dbuf *unc_pixels_planar = NULL;
	dbuf *spufile = NULL;
	int to_spu = 0;

	d = de_malloc(c, sizeof(struct spc_sps_ctx));
	d->is_sps = is_sps1;
	de_declare_fmtf(c, "Spectrum 512 %s", (d->is_sps?"Smooshed":"Compressed"));

	if(de_get_ext_option(c, "spectrum512:tospu")) {
		to_spu = 1;
	}

	pos = 4;
	d->pixels_cmpr_len = de_getu32be_p(&pos);
	de_dbg(c, "pixels compressed len: %"I64_FMT, d->pixels_cmpr_len);
	d->pal_cmpr_len = de_getu32be_p(&pos);
	de_dbg(c, "palette compressed len: %"I64_FMT, d->pal_cmpr_len);

	d->pixels_pos = pos;
	d->pal_pos = d->pixels_pos + d->pixels_cmpr_len;

	if(d->pal_pos + d->pal_cmpr_len > c->infile->len) {
		de_err(c, "Invalid or truncated file");
		goto done;
	}

	if(d->is_sps) {
		de_dbg(c, "format code at %"I64_FMT, d->pal_pos + d->pal_cmpr_len-1);
		d->sps_format_code = de_getbyte(d->pal_pos + d->pal_cmpr_len-1);
		d->sps_format_code &= 0x1;
		de_dbg(c, "format code: %u", (UI)d->sps_format_code);
	}

	de_dbg(c, "pixels at %"I64_FMT, d->pixels_pos);
	// Decompress the pixel data into an in-memory buffer.
	unc_pixels_planar = dbuf_create_membuf(c, 32000, 1);
	dbuf_enable_wbuffer(unc_pixels_planar);
	decompress_spc_or_sps(c, d, unc_pixels_planar);
	dbuf_disable_wbuffer(unc_pixels_planar);

	// We'll construct an in-memory SPU file, then (usually) use our
	// SPU module's decoder to process it.
	spufile = dbuf_create_membuf(c, 51104, 0x1);

	// Rearrange the bytes in the image data, as we write them to our
	// in-memory image of an SPU file.
	// (This could be done more efficiently during decompression,
	// but the code would be messier.)
	if(d->is_sps && d->sps_format_code==0) {
		reorder_img_bytes(c, unc_pixels_planar, spufile, reorderfn_sps0);
	}
	else {
		reorder_img_bytes(c, unc_pixels_planar, spufile, reorderfn_spc);
	}

	// Make sure we write the uncompressed palette at exactly offset 32000.
	dbuf_truncate(spufile, 32000);

	de_dbg(c, "palette at %"I64_FMT, d->pal_pos);
	if(d->is_sps) {
		sps_decompress_pal(c, d->pal_pos, spufile);
	}
	else {
		spc_decompress_pal(c, d->pal_pos, spufile);
	}

	if(to_spu) {
		// Instead of decoding the image, write it in .SPU format
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "spu", NULL, 0);
		dbuf_copy(spufile, 0, spufile->len, outf);
		dbuf_close(outf);
	}
	else {
		do_spu_internal(c, spufile, 0);
	}

done:
	dbuf_close(unc_pixels_planar);
	dbuf_close(spufile);
	de_free(c, d);
}

static void de_run_spectrum512c(deark *c, de_module_params *mparams)
{
	do_run_spectrum512c_s_internal(c, mparams, 0);
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

static void de_help_spectrum512cs(deark *c)
{
	de_msg(c, "-opt spectrum512:tospu : Output to an .spu file");
	fmtutil_atari_help_palbits(c);
}

void de_module_spectrum512c(deark *c, struct deark_module_info *mi)
{
	mi->id = "spectrum512c";
	mi->desc = "Spectrum 512 Compressed";
	mi->run_fn = de_run_spectrum512c;
	mi->identify_fn = de_identify_spectrum512c;
	mi->help_fn = de_help_spectrum512cs;
}

static void de_run_spectrum512s(deark *c, de_module_params *mparams)
{
	do_run_spectrum512c_s_internal(c, mparams, 1);
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
	mi->help_fn = de_help_spectrum512cs;
}
