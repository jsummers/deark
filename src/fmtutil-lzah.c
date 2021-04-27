// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// LZH with adaptive Huffman coding

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#include "../foreign/lzhuf.h"

UI fmtutil_get_lzhuf_d_code(UI n)
{
	if(n<32 || n>=256) return 0;
	if(n<80) return (n-16)>>4;
	if(n<144) return (n-48)>>3;
	if(n<192) return (n-96)>>2;
	if(n<240) return (n-144)>>1;
	return n-192;
}

UI fmtutil_get_lzhuf_d_len(UI n)
{
	static const u8 d_len[16] = {
		3,3,4,4,4,5,5,5,5,6,6,6,7,7,7,8
	};

	return (UI)d_len[(n&0xff)/16];
}

// codec_private_params: 'struct de_lh1_params'. Can be NULL.
void fmtutil_lh1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct lzahuf_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzahuf_ctx));
	cctx->c = c;
	cctx->modname = "lzhuf";
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	if(codec_private_params) {
		// Use params from caller, if present.
		de_memcpy(&cctx->lh1p, codec_private_params, sizeof(struct de_lh1_params));
	}
	else {
		// Set default params.
		cctx->lh1p.history_fill_val = 0x20;
	}

	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	lzhuf_Decode(cctx);

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

	de_free(c, cctx);
}
