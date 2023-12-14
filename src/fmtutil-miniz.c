// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// Compression and decompression of Deflate and zlib, using miniz

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 0
#define MINIZ_NO_STDIO
#define MINIZ_NO_ARCHIVE_APIS
#define USE_EXTERNAL_MZCRC
#include "../foreign/miniz-c.h"

static void *our_miniz_alloc_func(void *opaque, size_t items, size_t size)
{
	return de_mallocarray((deark*)opaque, (i64)items, size);
}

static void our_miniz_free_func(void *opaque, void *address)
{
	de_free((deark*)opaque, address);
}

///////////////////// Deflate pushable decompressor using miniz

#define DE_DEFLATEP_MAX_OUTBUF_SIZE 65536

struct deflate_pushable_ctx {
	UI flags;
	u8 stream_open_flag;
	i64 nbytes_written_total;
	i64 total_nbytes_processed;
	unsigned int outbuf_size; // Type=unsigned int, for compatibility with miniz
	u8 *outbuf;
	const char *modname;
	mz_stream strm;
};

static void my_deflate_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	struct deflate_pushable_ctx *dc = (struct deflate_pushable_ctx*)dfctx->codec_private;
	int ret;
	i64 nbytes_to_write;

	deark *c = dfctx->c;
	struct de_dfilter_results *dres = dfctx->dres;
	struct de_dfilter_out_params *dcmpro = dfctx->dcmpro;

	if(!dc->stream_open_flag) return;
	if(dres->errcode) return;

	if(!dc->outbuf) {
		if(dcmpro->len_known && dcmpro->expected_len<DE_DEFLATEP_MAX_OUTBUF_SIZE) {
			dc->outbuf_size = (unsigned int)dcmpro->expected_len;
		}
		else {
			dc->outbuf_size = DE_DEFLATEP_MAX_OUTBUF_SIZE;
		}
		dc->outbuf = de_malloc(c, (i64)dc->outbuf_size);
	}

	dc->strm.next_in = buf;
	dc->strm.avail_in = (unsigned int)buf_len;

	while(1) {
		unsigned int old_avail_in;

		// If we have written enough bytes, stop.
		if((dcmpro->len_known) && (dc->nbytes_written_total >= dcmpro->expected_len)) {
			dfctx->finished_flag = 1;
			goto done;
		}

		dc->strm.next_out = dc->outbuf;
		dc->strm.avail_out = dc->outbuf_size;
		old_avail_in = dc->strm.avail_in;

		ret = mz_inflate(&dc->strm, MZ_SYNC_FLUSH);

		if(ret!=MZ_STREAM_END && ret!=MZ_OK && ret!=MZ_BUF_ERROR) {
			de_dfilter_set_errorf(c, dres, dc->modname, "Inflate error (%d)", (int)ret);
			goto done;
		}

		nbytes_to_write = dc->outbuf_size - dc->strm.avail_out;

		if(ret==MZ_BUF_ERROR) {
			if(dc->strm.avail_in==0 && nbytes_to_write==0) {
				// Consumed all the input, can't produce any more output: suspend
				goto done;
			}
		}

		dbuf_write(dcmpro->f, dc->outbuf, nbytes_to_write);
		dc->nbytes_written_total += nbytes_to_write;

		if(ret==MZ_STREAM_END) {
			dfctx->finished_flag = 1;
			goto done;
		}

		if(dc->strm.avail_in==old_avail_in && nbytes_to_write==0) {
			// No progress? Probably shouldn't happen, but we want to defend against
			// infinite loops.
			de_dfilter_set_generic_error(c, dres, dc->modname);
			goto done;
		}
	}

done:
	dc->total_nbytes_processed += buf_len - (i64)dc->strm.avail_in;
}

static void deflate_codec_init(struct de_dfilter_ctx *dfctx)
{
	struct deflate_pushable_ctx *dc = (struct deflate_pushable_ctx*)dfctx->codec_private;
	deark *c = dfctx->c;
	int ret;

	dfctx->dres->bytes_consumed = 0;

	dc->strm.zalloc = our_miniz_alloc_func;
	dc->strm.zfree = our_miniz_free_func;
	dc->strm.opaque = (void*)c;

	if(dc->flags&DE_DEFLATEFLAG_ISZLIB) {
		ret = mz_inflateInit(&dc->strm);
	}
	else {
		ret = mz_inflateInit2(&dc->strm, -MZ_DEFAULT_WINDOW_BITS);
	}
	if(ret!=MZ_OK) {
		de_dfilter_set_errorf(c, dfctx->dres, dc->modname, "Inflate error");
		goto done;
	}

	dc->stream_open_flag = 1;
done:
	;
}

static void my_deflate_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct deflate_pushable_ctx *dc = (struct deflate_pushable_ctx*)dfctx->codec_private;

	if(dc->stream_open_flag) {
		if(!dfctx->dres->errcode) {
			de_dbgx(dfctx->c, 4, "inflated %u to %u bytes", (unsigned int)dc->strm.total_in,
				(unsigned int)dc->strm.total_out);
		}
		mz_inflateEnd(&dc->strm);
		dc->stream_open_flag = 0;
	}

	dfctx->dres->bytes_consumed = dc->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;
	dfctx->finished_flag = 1;
}

static void my_deflate_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct deflate_pushable_ctx *dc = (struct deflate_pushable_ctx*)dfctx->codec_private;
	deark *c = dfctx->c;

	if(dc) {
		de_free(c, dc->outbuf);
		de_free(c, dc);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: de_deflate_params, or NULL for default params.
//   .ringbuf_to_use is not used
void dfilter_deflate_codec_miniz(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct deflate_pushable_ctx *dc = NULL;
	struct de_deflate_params *deflparams = (struct de_deflate_params*)codec_private_params;

	dc = de_malloc(dfctx->c, sizeof(struct deflate_pushable_ctx));
	dc->modname = "deflate-mz";
	if(deflparams) {
		dc->flags = deflparams->flags;
	}

	dfctx->codec_private = (void*)dc;
	dfctx->codec_addbuf_fn = my_deflate_codec_addbuf;
	dfctx->codec_finish_fn = my_deflate_codec_finish;
	dfctx->codec_destroy_fn = my_deflate_codec_destroy;

	deflate_codec_init(dfctx);
}

//////////////////////////////////////

void fmtutil_deflate_codectype1_miniz(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	de_dfilter_decompress_oneshot(c, dfilter_deflate_codec_miniz, codec_private_params,
		dcmpri, dcmpro, dres);
}

//////////////////////////////////////

struct fmtutil_tdefl_ctx {
	deark *c;
	tdefl_compressor pComp;
};

static mz_bool my_fmtutil_tdefl_output_buffer_putter(const void *pBuf, int len, void *pUser)
{
	dbuf *f = (dbuf*)pUser;

	dbuf_write(f, (const u8*)pBuf, (i64)len);
	return MZ_TRUE;
}

struct fmtutil_tdefl_ctx *fmtutil_tdefl_create(deark *c, dbuf *outf, int flags)
{
	struct fmtutil_tdefl_ctx *tdctx = NULL;

	tdctx = de_malloc(c, sizeof(struct fmtutil_tdefl_ctx));
	tdctx->c = c;
	tdefl_init(&tdctx->pComp, my_fmtutil_tdefl_output_buffer_putter, (void*)outf,
		flags);
	return tdctx;
}

static enum fmtutil_tdefl_status tdefl_status_to_fmtutil(tdefl_status n)
{
	switch(n) {
	case TDEFL_STATUS_BAD_PARAM: return FMTUTIL_TDEFL_STATUS_BAD_PARAM;
	case TDEFL_STATUS_PUT_BUF_FAILED: return FMTUTIL_TDEFL_STATUS_PUT_BUF_FAILED;
	case TDEFL_STATUS_OKAY: return FMTUTIL_TDEFL_STATUS_OKAY;
	case TDEFL_STATUS_DONE: return FMTUTIL_TDEFL_STATUS_DONE;
	}
	return FMTUTIL_TDEFL_STATUS_PUT_BUF_FAILED;
}

static tdefl_flush fmtutil_flush_to_tdefl(enum fmtutil_tdefl_flush n)
{
	switch(n) {
	case FMTUTIL_TDEFL_NO_FLUSH: return TDEFL_NO_FLUSH;
	case FMTUTIL_TDEFL_SYNC_FLUSH: return TDEFL_SYNC_FLUSH;
	case FMTUTIL_TDEFL_FULL_FLUSH: return TDEFL_FULL_FLUSH;
	case FMTUTIL_TDEFL_FINISH: return TDEFL_FINISH ;
	}
	return TDEFL_NO_FLUSH;
}

enum fmtutil_tdefl_status fmtutil_tdefl_compress_buffer(struct fmtutil_tdefl_ctx *tdctx,
	const void *pIn_buf, size_t in_buf_size, enum fmtutil_tdefl_flush flush)
{
	tdefl_status st;

	st = tdefl_compress_buffer(&tdctx->pComp, pIn_buf, in_buf_size,
		fmtutil_flush_to_tdefl(flush));
	return tdefl_status_to_fmtutil(st);
}

void fmtutil_tdefl_destroy(struct fmtutil_tdefl_ctx *tdctx)
{
	deark *c;

	if(!tdctx) return;
	c = tdctx->c;
	de_free(c, tdctx);
}

unsigned int fmtutil_tdefl_create_comp_flags_from_zip_params(int level, int window_bits,
	int strategy)
{
	return (unsigned int)tdefl_create_comp_flags_from_zip_params(level, window_bits,
		strategy);
}
