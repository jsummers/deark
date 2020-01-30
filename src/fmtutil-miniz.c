// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// Compression and decompression of Deflate and zlib

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_STDIO
#define MINIZ_NO_ARCHIVE_APIS
#include "../foreign/miniz.h"

static void de_inflate_internal(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, const u8 *starting_dict)
{
	mz_stream strm;
	int ret;
	int ok = 0;
#define DE_DFL_INBUF_SIZE   32768
#define DE_DFL_OUTBUF_SIZE  (DE_DFL_INBUF_SIZE*4)
	u8 *inbuf = NULL;
	u8 *outbuf = NULL;
	i64 inbuf_num_valid_bytes; // Number of valid bytes in inbuf, starting with [0].
	i64 inbuf_num_consumed_bytes; // Of inbuf_num_valid_bytes, the number that have been consumed.
	i64 inbuf_num_consumed_bytes_this_time;
	unsigned int orig_avail_in;
	i64 input_cur_pos;
	i64 output_bytes_this_time;
	i64 nbytes_to_read;
	i64 nbytes_to_write;
	i64 nbytes_written_total = 0;
	int stream_open_flag = 0;
	static const char *modname = "inflate";

	dres->bytes_consumed = 0;
	if(dcmpri->len<0) {
		de_dfilter_set_errorf(c, dres, modname, "Internal error");
		goto done;
	}

	inbuf = de_malloc(c, DE_DFL_INBUF_SIZE);
	outbuf = de_malloc(c, DE_DFL_OUTBUF_SIZE);

	de_zeromem(&strm, sizeof(strm));
	if(flags&DE_DEFLATEFLAG_ISZLIB) {
		ret = mz_inflateInit(&strm);
	}
	else {
		ret = mz_inflateInit2(&strm, -MZ_DEFAULT_WINDOW_BITS);
	}
	if(ret!=MZ_OK) {
		de_dfilter_set_errorf(c, dres, modname, "Inflate error");
		goto done;
	}

	if(starting_dict) {
		inflate_state *pDecomp = (inflate_state *)strm.state;

		de_memcpy(pDecomp->m_dict, starting_dict, 32768);
	}

	stream_open_flag = 1;

	input_cur_pos = dcmpri->pos;

	inbuf_num_valid_bytes = 0;
	inbuf_num_consumed_bytes = 0;

	de_dbg2(c, "inflating up to %d bytes", (int)dcmpri->len);

	while(1) {
		de_dbg3(c, "input remaining: %d", (int)(dcmpri->pos+dcmpri->len-input_cur_pos));

		// If we have written enough bytes, stop.
		if((dcmpro->len_known) && (nbytes_written_total >= dcmpro->expected_len)) {
			break;
		}

		if(inbuf_num_consumed_bytes>0) {
			if(inbuf_num_valid_bytes>inbuf_num_consumed_bytes) {
				// Move unconsumed bytes to the beginning of the input buffer
				de_memmove(inbuf, &inbuf[inbuf_num_consumed_bytes], (size_t)(inbuf_num_valid_bytes-inbuf_num_consumed_bytes));
				inbuf_num_valid_bytes -= inbuf_num_consumed_bytes;
				inbuf_num_consumed_bytes = 0;
			}
			else {
				inbuf_num_valid_bytes = 0;
				inbuf_num_consumed_bytes = 0;
			}
		}

		nbytes_to_read = dcmpri->pos+dcmpri->len-input_cur_pos;
		if(nbytes_to_read>DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes) {
			nbytes_to_read = DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes;
		}

		// top off input buffer
		dbuf_read(dcmpri->f, &inbuf[inbuf_num_valid_bytes], input_cur_pos, nbytes_to_read);
		input_cur_pos += nbytes_to_read;
		inbuf_num_valid_bytes += nbytes_to_read;

		strm.next_in = inbuf;
		strm.avail_in = (unsigned int)inbuf_num_valid_bytes;
		orig_avail_in = strm.avail_in;

		strm.next_out = outbuf;
		strm.avail_out = DE_DFL_OUTBUF_SIZE;

		ret = mz_inflate(&strm, MZ_SYNC_FLUSH);

		if(ret!=MZ_STREAM_END && ret!=MZ_OK) {
			de_dfilter_set_errorf(c, dres, modname, "Inflate error (%d)", (int)ret);
			goto done;
		}

		output_bytes_this_time = DE_DFL_OUTBUF_SIZE - strm.avail_out;
		de_dbg3(c, "got %d output bytes", (int)output_bytes_this_time);

		nbytes_to_write = output_bytes_this_time;
		if((dcmpro->len_known) &&
			(nbytes_to_write > dcmpro->expected_len - nbytes_written_total))
		{
			nbytes_to_write = dcmpro->expected_len - nbytes_written_total;
		}
		dbuf_write(dcmpro->f, outbuf, nbytes_to_write);
		nbytes_written_total += nbytes_to_write;

		if(ret==MZ_STREAM_END) {
			de_dbg2(c, "inflate finished normally");
			ok = 1;
			goto done;
		}

		inbuf_num_consumed_bytes_this_time = (i64)(orig_avail_in - strm.avail_in);
		if(inbuf_num_consumed_bytes_this_time<1 && output_bytes_this_time<1) {
			de_dfilter_set_errorf(c, dres, modname, "Inflate error");
			goto done;
		}
		inbuf_num_consumed_bytes += inbuf_num_consumed_bytes_this_time;
	}

done:
	if(ok) {
		dres->bytes_consumed = (i64)strm.total_in;
		dres->bytes_consumed_valid = 1;
		de_dbg2(c, "inflated %u to %u bytes", (unsigned int)strm.total_in,
			(unsigned int)strm.total_out);
	}
	if(stream_open_flag) {
		mz_inflateEnd(&strm);
	}
	de_free(c, inbuf);
	de_free(c, outbuf);
}

// flags:
//   DE_DEFLATEFLAG_ISZLIB
//   DE_DEFLATEFLAG_USEMAXUNCMPRSIZE
int fmtutil_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags)
{
	deark *c = inf->c;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	if(bytes_consumed) *bytes_consumed = 0;

	dcmpri.f = inf;
	dcmpri.pos = inputstart;
	dcmpri.len = inputsize;

	dcmpro.f = outf;
	if(flags & DE_DEFLATEFLAG_USEMAXUNCMPRSIZE) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = maxuncmprsize;
		flags -= DE_DEFLATEFLAG_USEMAXUNCMPRSIZE;
	}

	de_inflate_internal(c, &dcmpri, &dcmpro, &dres, flags, NULL);

	if(bytes_consumed && dres.bytes_consumed_valid) {
		*bytes_consumed = dres.bytes_consumed;
	}

	if(dres.errcode != 0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		return 0;
	}
	return 1;
}

// flags:
//   DE_DEFLATEFLAG_ISZLIB
// starting_dict: Usually NULL. This is a hack needed by MSZIP format.
void fmtutil_decompress_deflate_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, const u8 *starting_dict)
{
	de_inflate_internal(c, dcmpri, dcmpro, dres, flags, starting_dict);
}

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
