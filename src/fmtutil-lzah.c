// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// LZH with adaptive Huffman coding

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#include "../foreign/lzhuf.h"

void fmtutil_get_lzhuf_d_code_and_len(UI n, UI *pd_code, UI *pd_len)
{
	if(n<32 || n>=256) { *pd_code = 0; *pd_len = 3; }
	else if(n<80) { *pd_code = (n-16)>>4; *pd_len = 4; }
	else if(n<144) { *pd_code = (n-48)>>3; *pd_len = 5; }
	else if(n<192) { *pd_code = (n-96)>>2; *pd_len = 6; }
	else if(n<240) { *pd_code = (n-144)>>1; *pd_len = 7; }
	else { *pd_code = n-192; *pd_len = 8; };
}

static void my_lh1_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	struct lzahuf_ctx *cctx = (struct lzahuf_ctx*)dfctx->codec_private;

	if(dfctx->finished_flag || cctx->errflag) {
		goto done;
	}

	cctx->ibuf2 = buf;
	cctx->ibuf2_len = (size_t)buf_len;
	lzhuf_Decode_continue(cctx, 0);

done:
	if(cctx->errflag) {
		dfctx->finished_flag = 1;
	}
}

static void my_lh1_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct lzahuf_ctx *cctx = (struct lzahuf_ctx*)dfctx->codec_private;

	cctx->ibuf2 = NULL;
	cctx->ibuf2_len = 0;
	lzhuf_Decode_continue(cctx, 1);
	cctx->ibuf1_curpos = 0;
	cctx->ibuf1_len = 0;

	dfctx->dres->bytes_consumed = cctx->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;

	if(cctx->errflag) {
		de_dfilter_set_generic_error(cctx->c, dfctx->dres, cctx->modname);
	}
}

static void my_lh1_codec_command(struct de_dfilter_ctx *dfctx, int cmd)
{
	struct lzahuf_ctx *cctx = (struct lzahuf_ctx*)dfctx->codec_private;

	if(cmd==DE_DFILTER_COMMAND_FINISH_BLOCK) {
		cctx->ibuf2 = NULL;
		cctx->ibuf2_len = 0;
		lzhuf_Decode_continue(cctx, 1);
		cctx->ibuf1_curpos = 0;
		cctx->ibuf1_len = 0;
		de_bitbuf_lowlevel_empty(&cctx->bbll);
		if(cctx->lh1p.is_dms_deep) {
			de_lz77buffer_set_curpos(cctx->ringbuf, cctx->ringbuf->curpos + 60);
		}
	}
	else if(cmd==DE_DFILTER_COMMAND_RESET_COUNTERS) {
		cctx->nbytes_written = 0;
		cctx->total_nbytes_processed = 0;
		cctx->errflag = 0;
		dfctx->finished_flag = 0;
	}
}

static void my_lh1_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct lzahuf_ctx *cctx = (struct lzahuf_ctx*)dfctx->codec_private;

	if(cctx) {
		de_lz77buffer_destroy(cctx->c, cctx->ringbuf);
		cctx->ringbuf = NULL;
		de_free(dfctx->c, cctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: 'struct de_lh1_params'. Can be NULL.
void dfilter_lh1_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct lzahuf_ctx *cctx = NULL;

	cctx = de_malloc(dfctx->c, sizeof(struct lzahuf_ctx));
	cctx->c = dfctx->c;
	cctx->modname = "lzhuf";
	cctx->dfctx = dfctx;
	cctx->dcmpro = dfctx->dcmpro;
	cctx->dres = dfctx->dres;

	dfctx->codec_private = (void*)cctx;
	dfctx->codec_addbuf_fn = my_lh1_codec_addbuf;
	dfctx->codec_finish_fn = my_lh1_codec_finish;
	dfctx->codec_command_fn = my_lh1_codec_command;
	dfctx->codec_destroy_fn = my_lh1_codec_destroy;

	if(codec_private_params) {
		// Use params from caller, if present.
		de_memcpy(&cctx->lh1p, codec_private_params, sizeof(struct de_lh1_params));
	}
	else {
		// Set default params.
		cctx->lh1p.history_fill_val = 0x20;
	}

	lzhuf_Decode_init(cctx);
}

// codec_private_params: 'struct de_lh1_params'. Can be NULL.
void fmtutil_lh1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	de_dfilter_decompress_oneshot(c, dfilter_lh1_codec, codec_private_params,
		dcmpri, dcmpro, dres);
}
