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
	if(dfctx->codec_addbuf_fn && (buf_len>0)) {
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
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, UI flags)
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

void fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
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
int fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
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

	fmtutil_decompress_packbits_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

// A 16-bit variant of de_fmtutil_uncompress_packbits().
void fmtutil_decompress_packbits16_ex(deark *c, struct de_dfilter_in_params *dcmpri,
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

int fmtutil_decompress_packbits16(dbuf *f, i64 pos1, i64 len,
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

	fmtutil_decompress_packbits16_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

void fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
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

struct szdd_ctx {
	i64 nbytes_written;
	int stop_flag;
	struct de_dfilter_out_params *dcmpro;
	struct de_lz77buffer *ringbuf;
};

static void szdd_lz77buf_writebytecb(struct de_lz77buffer *rb, const u8 n)
{
	struct szdd_ctx *sctx = (struct szdd_ctx*)rb->userdata;

	if(sctx->stop_flag) return;
	if(sctx->dcmpro->len_known) {
		if(sctx->nbytes_written >= sctx->dcmpro->expected_len) {
			sctx->stop_flag = 1;
			return;
		}
	}

	dbuf_writebyte(sctx->dcmpro->f, n);
	sctx->nbytes_written++;
}

static void szdd_init_window_default(struct de_lz77buffer *ringbuf)
{
	de_lz77buffer_clear(ringbuf, 0x20);
	ringbuf->curpos = 4096 - 16;
}

static void szdd_init_window_lz5(struct de_lz77buffer *ringbuf)
{
	size_t wpos;
	int i;

	de_zeromem(ringbuf->buf, 4096);
	wpos = 13;
	for(i=1; i<256; i++) {
		de_memset(&ringbuf->buf[wpos], i, 13);
		wpos += 13;
	}
	for(i=0; i<256; i++) {
		ringbuf->buf[wpos++] = i;
	}
	for(i=255; i>=0; i--) {
		ringbuf->buf[wpos++] = i;
	}
	wpos += 128;
	de_memset(&ringbuf->buf[wpos], 0x20, 110);
	wpos += 110;
	ringbuf->curpos = (UI)wpos;
}

// Partially based on the libmspack's format documentation at
// <https://www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html>
// flags:
//   0x1: LArc lz5 mode
void fmtutil_decompress_szdd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, unsigned int flags)
{
	i64 pos = dcmpri->pos;
	i64 endpos = dcmpri->pos + dcmpri->len;
	struct szdd_ctx *sctx = NULL;

	sctx = de_malloc(c, sizeof(struct szdd_ctx));
	sctx->dcmpro = dcmpro;
	sctx->ringbuf = de_lz77buffer_create(c, 4096);
	sctx->ringbuf->writebyte_cb = szdd_lz77buf_writebytecb;
	sctx->ringbuf->userdata = (void*)sctx;

	if(flags & 0x1) {
		szdd_init_window_lz5(sctx->ringbuf);
	}
	else {
		szdd_init_window_default(sctx->ringbuf);
	}

	while(1) {
		UI control;
		UI cbit;

		if(pos+1 > endpos) goto unc_done; // Out of input data
		control = (UI)dbuf_getbyte(dcmpri->f, pos++);

		for(cbit=0x01; cbit<=0x80; cbit<<=1) {
			if(control & cbit) { // literal
				u8 b;

				if(pos+1 > endpos) goto unc_done;
				b = dbuf_getbyte(dcmpri->f, pos++);
				de_lz77buffer_add_literal_byte(sctx->ringbuf, b);
				if(sctx->stop_flag) goto unc_done;
			}
			else { // match
				UI x0, x1;
				UI matchpos;
				UI matchlen;

				if(pos+2 > endpos) goto unc_done;
				x0 = (UI)dbuf_getbyte_p(dcmpri->f, &pos);
				x1 = (UI)dbuf_getbyte_p(dcmpri->f, &pos);
				matchpos = ((x1 & 0xf0) << 4) | x0;
				matchlen = (x1 & 0x0f) + 3;
				de_lz77buffer_copy_from_hist(sctx->ringbuf, matchpos, matchlen);
				if(sctx->stop_flag) goto unc_done;
			}
		}
	}

unc_done:
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = pos - dcmpri->pos;
	if(sctx) {
		de_lz77buffer_destroy(c, sctx->ringbuf);
		de_free(c, sctx);
	}
}

//======================= hlp_lz77 =======================

struct hlplz77ctx {
	i64 nbytes_written;
	int stop_flag;
	struct de_dfilter_out_params *dcmpro;
	struct de_lz77buffer *ringbuf;
};

static void hlplz77_lz77buf_writebytecb(struct de_lz77buffer *rb, const u8 n)
{
	struct hlplz77ctx *sctx = (struct hlplz77ctx*)rb->userdata;

	if(sctx->stop_flag) return;
	if(sctx->dcmpro->len_known) {
		if(sctx->nbytes_written >= sctx->dcmpro->expected_len) {
			sctx->stop_flag = 1;
			return;
		}
	}

	dbuf_writebyte(sctx->dcmpro->f, n);
	sctx->nbytes_written++;
}

// This is very similar to the mscompress SZDD algorithm, but
// gratuitously different.
void fmtutil_hlp_lz77_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	i64 pos = dcmpri->pos;
	i64 endpos = dcmpri->pos + dcmpri->len;
	struct hlplz77ctx *sctx = NULL;

	sctx = de_malloc(c, sizeof(struct hlplz77ctx));
	sctx->dcmpro = dcmpro;
	sctx->ringbuf = de_lz77buffer_create(c, 4096);
	sctx->ringbuf->writebyte_cb = hlplz77_lz77buf_writebytecb;
	sctx->ringbuf->userdata = (void*)sctx;
	de_lz77buffer_clear(sctx->ringbuf, 0x20);

	while(1) {
		UI control;
		UI cbit;

		if(pos+1 > endpos) goto unc_done; // Out of input data
		control = (UI)dbuf_getbyte(dcmpri->f, pos++);

		for(cbit=0x01; cbit<=0x80; cbit<<=1) {
			if((control & cbit)==0) { // literal
				u8 b;

				if(pos+1 > endpos) goto unc_done;
				b = dbuf_getbyte(dcmpri->f, pos++);
				de_lz77buffer_add_literal_byte(sctx->ringbuf, b);
				if(sctx->stop_flag) goto unc_done;
			}
			else { // match
				UI x;
				UI matchpos;
				UI matchlen;

				if(pos+2 > endpos) goto unc_done;
				x = (UI)dbuf_getu16le_p(dcmpri->f, &pos);
				matchlen = (x>>12) + 3;
				matchpos = sctx->ringbuf->curpos - ((x & 0x0fff)+1);
				de_lz77buffer_copy_from_hist(sctx->ringbuf, matchpos, matchlen);
				if(sctx->stop_flag) goto unc_done;
			}
		}
	}

unc_done:
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = pos - dcmpri->pos;
	if(sctx) {
		de_lz77buffer_destroy(c, sctx->ringbuf);
		de_free(c, sctx);
	}
}

//========================================================

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
// tlp->codec1* is the first one that will be used during decompression (i.e. the second
// method used when during *compression*).
void de_dfilter_decompress_two_layer(deark *c, struct de_dcmpr_two_layer_params *tlp)
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
	if(tlp->intermed_len_known) {
		dcmpro_codec1.len_known = 1;
		dcmpro_codec1.expected_len = tlp->intermed_expected_len;
	}
	else {
		dcmpro_codec1.len_known = 0;
		dcmpro_codec1.expected_len = 0;
	}

	dfctx_codec2 = de_dfilter_create(c, tlp->codec2, tlp->codec2_private_params, tlp->dcmpro, &dres_codec2);
	u.dfctx_codec2 = dfctx_codec2;

	// The first codec in the chain does not need the advanced (de_dfilter_create) API.
	if(tlp->codec1_type1) {
		tlp->codec1_type1(c, tlp->dcmpri, &dcmpro_codec1, tlp->dres, tlp->codec1_private_params);
	}
	else {
		de_dfilter_decompress_oneshot(c, tlp->codec1_pushable, tlp->codec1_private_params,
			tlp->dcmpri, &dcmpro_codec1, tlp->dres);
	}
	de_dfilter_finish(dfctx_codec2);

	if(tlp->dres->errcode) goto done;
	de_dbg2(c, "size after intermediate decompression: %"I64_FMT, u.intermediate_nbytes);

	if(dres_codec2.errcode) {
		// An error occurred in codec2, and not in codec1.
		// Copy the error info to the dres that will be returned to the caller.
		// TODO: Make a cleaner way to do this.
		dres_transfer_error(c, &dres_codec2, tlp->dres);
		goto done;
	}

done:
	de_dfilter_destroy(dfctx_codec2);
	dbuf_close(outf_codec1);
}

// TODO: Retire this function.
void de_dfilter_decompress_two_layer_type2(deark *c,
	dfilter_codec_type codec1, void *codec1_private_params,
	dfilter_codec_type codec2, void *codec2_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_dcmpr_two_layer_params tlp;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_pushable = codec1;
	tlp.codec1_private_params = codec1_private_params;
	tlp.codec2 = codec2;
	tlp.codec2_private_params = codec2_private_params;
	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;
	de_dfilter_decompress_two_layer(c, &tlp);
}

 struct de_lz77buffer *de_lz77buffer_create(deark *c, UI bufsize)
{
	struct de_lz77buffer *rb;

	rb = de_malloc(c, sizeof(struct de_lz77buffer));
	rb->buf = de_malloc(c, (i64)bufsize);
	rb->bufsize = bufsize;
	rb->mask = bufsize - 1;
	return rb;
}

void de_lz77buffer_destroy(deark *c, struct de_lz77buffer *rb)
{
	if(!rb) return;
	de_free(c, rb->buf);
	de_free(c, rb);
}

// Set all bytes to the same value, and reset the current position to 0.
void de_lz77buffer_clear(struct de_lz77buffer *rb, UI val)
{
	de_memset(rb->buf, val, rb->bufsize);
	rb->curpos = 0;
}

void de_lz77buffer_set_curpos(struct de_lz77buffer *rb, UI newpos)
{
	rb->curpos = newpos & rb->mask;
}

void de_lz77buffer_add_literal_byte(struct de_lz77buffer *rb, u8 b)
{
	rb->writebyte_cb(rb, b);
	rb->buf[rb->curpos] = b;
	rb->curpos = (rb->curpos+1) & rb->mask;
}

void de_lz77buffer_copy_from_hist(struct de_lz77buffer *rb,
	UI startpos, UI count)
{
	UI frompos;
	UI i;

	frompos = startpos & rb->mask;
	for(i=0; i<count; i++) {
		de_lz77buffer_add_literal_byte(rb, rb->buf[frompos]);
		frompos = (frompos+1) & rb->mask;
	}
}
