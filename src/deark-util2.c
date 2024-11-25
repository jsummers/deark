// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// deark-util2.c: Some library functions that need additional
// header files, including deark-fmtutil.h.

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

// This is mainly intended for internal data.
int de_decompress_zlib_mem2mem(deark *c,
	const u8 *src, i64 src_len, u8 *dst, i64 dst_len)
{
	int retval = 0;
	dbuf *outf = NULL;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_deflate_params inflparams;
	struct de_dfilter_ctx *dfctx = NULL;

	de_zeromem(&inflparams, sizeof(struct de_deflate_params));
	inflparams.flags = DE_DEFLATEFLAG_ISZLIB;

	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);

	outf = dbuf_create_membuf(c, dst_len, 0x1);
	dbuf_enable_wbuffer(outf);

	dcmpro.f = outf;
	dcmpro.expected_len = dst_len;
	dcmpro.len_known = 1;

	dfctx = de_dfilter_create(c, dfilter_deflate_codec_miniz, (void*)&inflparams,
		&dcmpro, &dres);

	de_dfilter_addbuf(dfctx, src, src_len);
	de_dfilter_finish(dfctx);
	dbuf_flush(outf);
	if(dres.errcode==0) {
		retval = 1;
	}
	// TODO: There's too much copying. Could use a custom dbuf to
	// reduce the # of copies by 1.
	dbuf_read(outf, dst, 0, dst_len);

	de_dfilter_destroy(dfctx);
	dbuf_close(outf);
	return retval;
}

#include "../foreign/cp932data.h"

#define DE_PERSISTENT_ITEM_CP932_TBL 4

#define CP932_UNC_TBL_SIZE 65536

static void make_cp932_table(deark *c)
{
	u8 *tbl;
	int ret;

	if(c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL]) {
		return;
	}

	tbl = de_malloc(c, CP932_UNC_TBL_SIZE);
	ret = de_decompress_zlib_mem2mem(c, de_cp932data, DE_CP932DATA_LEN,
		tbl, CP932_UNC_TBL_SIZE);
	if(!ret) {
		de_internal_err_fatal(c, "Problem with cp932 data");
	}
	c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL] = (void*)tbl;
}

de_rune de_cp932_lookup(deark *c, u16 n, UI flags)
{
	u8 *tbl;

	if(n<32768 /* || n>65535 */) return 0;

	if(!c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL]) {
		make_cp932_table(c);
	}

	tbl = (u8*)c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL];
	if(!tbl) {
		return 0;
	}

	return ((de_rune)tbl[n-32768]<<8)|tbl[n];
}
