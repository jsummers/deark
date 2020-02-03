// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Decompression, etc.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

// Returns a message that is valid until the next operation on dres.
const char *de_dfilter_get_errmsg(deark *c, struct de_dfilter_results *dres)
{
	if(dres->errcode==0) {
		return "No error";
	}
	if(dres->errmsg[0]) {
		return dres->errmsg;
	}
	return "Unspecified error";
}

// Initialize or reset a dfilter results struct
void de_dfilter_results_clear(deark *c, struct de_dfilter_results *dres)
{
	de_zeromem(dres, sizeof(struct de_dfilter_results));
}

// Note: It is also okay to init these objects by zeroing out their bytes.
void de_dfilter_init_objects(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	if(dcmpri)
		de_zeromem(dcmpri, sizeof(struct de_dfilter_in_params));
	if(dcmpro)
		de_zeromem(dcmpro, sizeof(struct de_dfilter_out_params));
	if(dres)
		de_dfilter_results_clear(c, dres);
}

void de_dfilter_set_errorf(deark *c, struct de_dfilter_results *dres, const char *modname,
	const char *fmt, ...)
{
	va_list ap;

	if(dres->errcode != 0) return; // Only record the first error
	dres->errcode = 1;

	va_start(ap, fmt);
	if(modname) {
		char tmpbuf[80];

		de_vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);
		de_snprintf(dres->errmsg, sizeof(dres->errmsg), "[%s] %s", modname, tmpbuf);
	}
	else {
		de_vsnprintf(dres->errmsg, sizeof(dres->errmsg), fmt, ap);
	}
	va_end(ap);
}

void de_dfilter_set_generic_error(deark *c, struct de_dfilter_results *dres, const char *modname)
{
	if(dres->errcode != 0) return;
	de_dfilter_set_errorf(c, dres, modname, "Unspecified error");
}

// This is a decompression API that uses a "push" input model. The client
// sends data to the codec as the data becomes available.
// (The client must still be able to consume any amount of output data
// immediately.)
// This model makes it easier to chain multiple codecs together, and to handle
// input data that is not contiguous.

struct de_dfilter_ctx *de_dfilter_create(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_dfilter_ctx *dfctx = NULL;

	dfctx = de_malloc(c, sizeof(struct de_dfilter_ctx));
	dfctx->c = c;
	dfctx->dres = dres;
	dfctx->dcmpro = dcmpro;

	if(codec_init_fn) {
		codec_init_fn(dfctx, codec_private_params);
	}
	// TODO: How should we handle failure to initialize a codec?

	return dfctx;
}

void de_dfilter_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	if(dfctx->codec_addbuf_fn) {
		dfctx->codec_addbuf_fn(dfctx, buf, buf_len);
	}
}

void de_dfilter_finish(struct de_dfilter_ctx *dfctx)
{
	if(dfctx->codec_finish_fn) {
		dfctx->codec_finish_fn(dfctx);
	}
}

void de_dfilter_destroy(struct de_dfilter_ctx *dfctx)
{
	deark *c;

	if(!dfctx) return;
	c = dfctx->c;
	if(dfctx->codec_destroy_fn) {
		dfctx->codec_destroy_fn(dfctx);
	}

	de_free(c, dfctx);
}

static int my_dfilter_oneshot_buffered_read_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx *)brctx->userdata;

	de_dfilter_addbuf(dfctx, buf, buf_len);
	if(dfctx->finished_flag) return 0;
	return 1;
}

// Use a "pushable" codec in a non-pushable way.
void de_dfilter_decompress_oneshot(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_dfilter_ctx *dfctx = NULL;

	dfctx = de_dfilter_create(c, codec_init_fn, codec_private_params,
		dcmpro, dres);
	dbuf_buffered_read(dcmpri->f, dcmpri->pos, dcmpri->len,
		my_dfilter_oneshot_buffered_read_cbfn, (void*)dfctx);
	de_dfilter_finish(dfctx);
	de_dfilter_destroy(dfctx);
}

// Trivial "decompression" of uncompressed data.
void fmtutil_decompress_uncompressed(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, uint flags)
{
	i64 len;
	i64 nbytes_avail;

	nbytes_avail = de_min_int(dcmpri->len, dcmpri->f->len - dcmpri->pos);

	if(dcmpro->len_known) {
		len = dcmpro->expected_len;
	}
	else {
		len = dcmpri->len;
	}

	if(len>nbytes_avail) len = nbytes_avail;
	if(len<0) len = 0;

	dbuf_copy(dcmpri->f, dcmpri->pos, len, dcmpro->f);
	dres->bytes_consumed = len;
	dres->bytes_consumed_valid = 1;
}

void de_fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 endpos;
	i64 outf_len_limit = 0;
	dbuf *f = dcmpri->f;
	dbuf *unc_pixels = dcmpro->f;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	if(dcmpro->len_known) {
		outf_len_limit = unc_pixels->len + dcmpro->expected_len;
	}

	while(1) {
		if(dcmpro->len_known && unc_pixels->len >= outf_len_limit) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (i64)b;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (i64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
		// Else b==128. No-op.
		// TODO: Some (but not most) ILBM specs say that code 128 is used to
		// mark the end of compressed data, so maybe there should be options to
		// tell us what to do when code 128 is encountered.
	}

	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

// Returns 0 on failure (currently impossible).
int de_fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = 0;
	de_dfilter_init_objects(f->c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = f;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	if(unc_pixels->has_len_limit) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = unc_pixels->len_limit - unc_pixels->len;
	}

	de_fmtutil_decompress_packbits_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

// A 16-bit variant of de_fmtutil_uncompress_packbits().
void de_fmtutil_decompress_packbits16_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b1, b2;
	i64 k;
	i64 count;
	i64 endpos;
	i64 outf_len_limit = 0;
	dbuf *f = dcmpri->f;
	dbuf *unc_pixels = dcmpro->f;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	if(dcmpro->len_known) {
		outf_len_limit = unc_pixels->len + dcmpro->expected_len;
	}

	while(1) {
		if(dcmpro->len_known && unc_pixels->len >= outf_len_limit) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (i64)b;
			b1 = dbuf_getbyte(f, pos++);
			b2 = dbuf_getbyte(f, pos++);
			for(k=0; k<count; k++) {
				dbuf_writebyte(unc_pixels, b1);
				dbuf_writebyte(unc_pixels, b2);
			}
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (i64)b;
			dbuf_copy(f, pos, count*2, unc_pixels);
			pos += count*2;
		}
		// Else b==128. No-op.
	}

	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

int de_fmtutil_decompress_packbits16(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = 0;
	de_dfilter_init_objects(f->c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = f;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	if(unc_pixels->has_len_limit) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = unc_pixels->len_limit - unc_pixels->len;
	}

	de_fmtutil_decompress_packbits16_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

void de_fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	de_dfilter_decompress_oneshot(c, dfilter_rle90_codec, NULL,
		dcmpri, dcmpro, dres);
}

struct rle90ctx {
	i64 total_nbytes_processed;
	i64 nbytes_written;
	u8 last_output_byte;
	int countcode_pending;
};

static void my_rle90_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	int i;
	u8 b;
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(!rctx) return;

	for(i=0; i<buf_len; i++) {
		if(dfctx->dcmpro->len_known &&
			(rctx->nbytes_written >= dfctx->dcmpro->expected_len))
		{
			dfctx->finished_flag = 1;
			break;
		}

		b = buf[i];
		rctx->total_nbytes_processed++;

		if(rctx->countcode_pending && b==0) {
			// Not RLE, just an escaped 0x90 byte.
			dbuf_writebyte(dfctx->dcmpro->f, 0x90);
			rctx->nbytes_written++;
			rctx->last_output_byte = 0x90;
			rctx->countcode_pending = 0;
		}
		else if(rctx->countcode_pending) {
			i64 count;

			// RLE. We already emitted one byte (because the byte to repeat
			// comes before the repeat count), so write countcode-1 bytes.
			count = (i64)(b-1);
			if(dfctx->dcmpro->len_known &&
				(rctx->nbytes_written+count > dfctx->dcmpro->expected_len))
			{
				count = dfctx->dcmpro->expected_len - rctx->nbytes_written;
			}
			dbuf_write_run(dfctx->dcmpro->f, rctx->last_output_byte, count);
			rctx->nbytes_written += count;

			rctx->countcode_pending = 0;
		}
		else if(b==0x90) {
			rctx->countcode_pending = 1;
		}
		else {
			dbuf_writebyte(dfctx->dcmpro->f, b);
			rctx->nbytes_written++;
			rctx->last_output_byte = b;
		}
	}
}

static void my_rle90_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(!rctx) return;
	dfctx->dres->bytes_consumed = rctx->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;
}

static void my_rle90_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// RLE algorithm occasionally called "RLE90". Variants of this are used by
// BinHex, ARC, StuffIt, and others.
// codec_private_params: Unused, must be NULL.
void dfilter_rle90_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct rle90ctx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct rle90ctx));
	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = my_rle90_codec_addbuf;
	dfctx->codec_finish_fn = my_rle90_codec_finish;
	dfctx->codec_destroy_fn = my_rle90_codec_destroy;
}

struct hlplz77ctx {
	uint control_byte;
	uint control_byte_bits_left;
	u8 matchcode_first_byte;
	int matchcode_second_byte_pending;
	i64 nbytes_consumed;
	i64 nbytes_written;
	dbuf *outf;
	uint wpos;
	u8 window[4096];
};

static void hlp_lz77_emit_byte(struct hlplz77ctx *hctx, u8 b)
{
	dbuf_writebyte(hctx->outf, b);
	hctx->nbytes_written++;
	hctx->window[hctx->wpos] = b;
	hctx->wpos = (hctx->wpos+1) & 4095;
}

// This is very similar to the mscompress SZDD algorithm, but
// gratuitously different.
static void  my_hlp_lz77_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	struct hlplz77ctx *hctx = (struct hlplz77ctx*)dfctx->codec_private;
	i64 k;

	for(k=0; k<buf_len; k++) {

		if(hctx->matchcode_second_byte_pending) {
			uint x;
			uint matchpos;
			uint matchlen;

			x = (((uint)buf[k])<<8) | hctx->matchcode_first_byte;
			hctx->matchcode_second_byte_pending = 0;
			hctx->nbytes_consumed += 2;

			matchlen = (x>>12) + 3;
			matchpos = (hctx->wpos - ((x & 0x0fff)+1)) & 4095;
			while(matchlen--) {
				hlp_lz77_emit_byte(hctx, hctx->window[matchpos]);
				matchpos = (matchpos+1) & 4095;
			}
			continue;
		}

		if(hctx->control_byte_bits_left==0) {
			hctx->control_byte = buf[k];
			hctx->control_byte_bits_left = 8;
			hctx->nbytes_consumed++;
			continue;
		}

		hctx->control_byte_bits_left--;
		if((hctx->control_byte & (1<<(7-hctx->control_byte_bits_left)))==0) { // literal
			hlp_lz77_emit_byte(hctx, buf[k]);
			hctx->nbytes_consumed++;
		}
		else { // match (first byte)
			hctx->matchcode_first_byte = buf[k];
			hctx->matchcode_second_byte_pending = 1;
		}
	}
}

static void my_hlp_lz77_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct hlplz77ctx *hctx = (struct hlplz77ctx*)dfctx->codec_private;

	dfctx->dres->bytes_consumed_valid = 1;
	dfctx->dres->bytes_consumed = hctx->nbytes_consumed;
}

static void my_hlp_lz77_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct hlplz77ctx *hctx = (struct hlplz77ctx*)dfctx->codec_private;

	de_free(dfctx->c, hctx);
}

void dfilter_hlp_lz77_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct hlplz77ctx *hctx = NULL;

	hctx = de_malloc(dfctx->c, sizeof(struct hlplz77ctx));
	hctx->outf = dfctx->dcmpro->f;
	de_memset(hctx->window, 0x20, 4096);
	hctx->wpos = 0;

	dfctx->codec_private = (void*)hctx;
	dfctx->codec_finish_fn = my_hlp_lz77_codec_finish;
	dfctx->codec_destroy_fn = my_hlp_lz77_codec_destroy;
	dfctx->codec_addbuf_fn = my_hlp_lz77_codec_addbuf;
}

void fmtutil_decompress_hlp_lz77(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	de_dfilter_decompress_oneshot(c, dfilter_hlp_lz77_codec, NULL,
		dcmpri, dcmpro, dres);
}

struct my_2layer_userdata {
	struct de_dfilter_ctx *dfctx_codec2;
	i64 intermediate_nbytes;
};

static void my_2layer_write_cb(dbuf *f, void *userdata,
	const u8 *buf, i64 size)
{
	struct my_2layer_userdata *u = (struct my_2layer_userdata*)userdata;

	de_dfilter_addbuf(u->dfctx_codec2, buf, size);
	u->intermediate_nbytes += size;
}

static void dres_transfer_error(deark *c, struct de_dfilter_results *src,
	struct de_dfilter_results *dst)
{
	if(src->errcode) {
		dst->errcode = src->errcode;
		de_strlcpy(dst->errmsg, src->errmsg, sizeof(dst->errmsg));
	}
}

// Decompress an arbitrary two-layer compressed format.
// codec1 is the first one that will be used during decompression (i.e. the second
// method used when during *compression*).
 void de_dfilter_decompress_two_layer(deark *c,
	dfilter_codec_type codec1, void *codec1_private_params,
	dfilter_codec_type codec2, void *codec2_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	dbuf *outf_codec1 = NULL;
	struct de_dfilter_out_params dcmpro_codec1;
	struct de_dfilter_results dres_codec2;
	struct my_2layer_userdata u;
	struct de_dfilter_ctx *dfctx_codec2 = NULL;

	de_dfilter_init_objects(c, NULL, &dcmpro_codec1, NULL);
	de_dfilter_init_objects(c, NULL, NULL, &dres_codec2);
	de_zeromem(&u, sizeof(struct my_2layer_userdata));

	// Make a custom dbuf. The output from the first decompressor will be written
	// to it, and it will relay that output to the second decompressor.
	outf_codec1 = dbuf_create_custom_dbuf(c, 0, 0);
	outf_codec1->userdata_for_customwrite = (void*)&u;
	outf_codec1->customwrite_fn = my_2layer_write_cb;
	dcmpro_codec1.f = outf_codec1;
	dcmpro_codec1.len_known = 0;
	dcmpro_codec1.expected_len = 0;

	dfctx_codec2 = de_dfilter_create(c, codec2, codec2_private_params, dcmpro, &dres_codec2);
	u.dfctx_codec2 = dfctx_codec2;

	// The first codec in the chain does not need the advanced (de_dfilter_create) API.
	de_dfilter_decompress_oneshot(c, codec1, codec1_private_params,
		dcmpri, &dcmpro_codec1, dres);
	de_dfilter_finish(dfctx_codec2);

	if(dres->errcode) goto done;
	de_dbg2(c, "size after intermediate decompression: %"I64_FMT, u.intermediate_nbytes);

	if(dres_codec2.errcode) {
		// An error occurred in codec2, and not in codec1.
		// Copy the error info to the dres that will be returned to the caller.
		// TODO: Make a cleaner way to do this.
		dres_transfer_error(c, &dres_codec2, dres);
		goto done;
	}

done:
	de_dfilter_destroy(dfctx_codec2);
	dbuf_close(outf_codec1);
}
