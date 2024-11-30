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

static void make_cp932_table(deark *c)
{
	u8 *tbl;
	int ret;

	if(c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL]) {
		return;
	}

	tbl = de_malloc(c, DE_CP932DATA_ORIG_LEN);
	ret = de_decompress_zlib_mem2mem(c, de_cp932data, DE_CP932DATA_LEN,
		tbl, DE_CP932DATA_ORIG_LEN);
	if(!ret) {
		de_internal_err_fatal(c, "Problem with cp932 data");
	}
	c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL] = (void*)tbl;
}

// Returns the number of runes set (0, 1, or 2)
int de_cp932_lookup(deark *c, u16 n, UI flags, de_rune *pr1, de_rune *pr2)
{
	u8 *tbl;
	u8 plane_code;

	*pr1 = 0;
	*pr2 = 0;

	if(n<32768) {
		if(flags & 0x1) {
			// This is probably(??) what we want to do most of the time, but
			// until all of Deark's path-separator-detection code is reviewed,
			// it's too risky to turn backslashes into yen signs.
			if(n==0x5c) {
				*pr1 = 0x00a5; // YEN SIGN
				return 1;
			}
			if(n==0x7e) {
				*pr1 = 0x203e; // OVERLINE
				return 1;
			}
		}
		if(n<=0x7f) {
			*pr1 = (de_rune)n;
			return 1;
		}
		if(n>=0xa1 && n<=0xdf) {
			*pr1 = (de_rune)n + (0xff61-0xa1);
			return 1;
		}
		return 0;
	}

	if(!c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL]) {
		make_cp932_table(c);
	}

	tbl = (u8*)c->persistent_item[DE_PERSISTENT_ITEM_CP932_TBL];
	if(!tbl) {
		return 0;
	}

	*pr1 = ((de_rune)tbl[n]<<8)|tbl[n+32768];

	plane_code = tbl[n-32768];
	if(plane_code==0) return 1;
	if(plane_code<=0x10) {
		*pr1 |= ((de_rune)plane_code<<16);
		return 1;
	}

	// Some hacky special handling of the case where a Shift JIS code
	// maps to *two* Unicode codepoints.
	// E.g. 0x8663 -> U+00E6 U+0300
	switch(plane_code) {
	case 0xf0: *pr2 = 0x02e5; break;
	case 0xf1: *pr2 = 0x02e9; break;
	case 0xf2: *pr2 = 0x0300; break;
	case 0xf3: *pr2 = 0x0301; break;
	case 0xf4: *pr2 = 0x309a; break;
	}
	if(*pr2 != 0) return 2;
	return 0;
}
