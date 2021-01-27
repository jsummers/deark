// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// Compression formats specific to ZIP

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#define OZUR_UINT8     u8
#define OZUR_OFF_T     i64
#include "../foreign/ozunreduce.h"

// Struct for userdata
struct ozXX_udatatype {
	deark *c;
	dbuf *inf;
	i64 inf_curpos;
	dbuf *outf;
	int dumptrees;
};

static size_t ozXX_read(struct ozXX_udatatype *uctx, u8 *buf, size_t size)
{
	dbuf_read(uctx->inf, buf, uctx->inf_curpos, (i64)size);
	uctx->inf_curpos += (i64)size;
	return size;
}

static size_t ozXX_write(struct ozXX_udatatype *uctx, const u8 *buf, size_t size)
{
	dbuf_write(uctx->outf, buf, (i64)size);
	return size;
}

// params: Unused, should be NULL
void fmtutil_decompress_zip_shrink(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *params)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ZIPSHRINK;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static size_t my_ozur_read(ozur_ctx *ozur, OZUR_UINT8 *buf, size_t size)
{
	return ozXX_read((struct ozXX_udatatype*)ozur->userdata, buf, size);
}

static size_t my_ozur_write(ozur_ctx *ozur, const OZUR_UINT8 *buf, size_t size)
{
	return ozXX_write((struct ozXX_udatatype*)ozur->userdata, buf, size);
}

static void my_ozur_post_follower_sets_hook(ozur_ctx *ozur)
{
	struct ozXX_udatatype *uctx = (struct ozXX_udatatype*)ozur->userdata;

	de_dbg2(uctx->c, "finished reading follower sets, pos=%"I64_FMT, uctx->inf_curpos);
}

void fmtutil_decompress_zip_reduce(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_zipreduce_params *params)
{
	int retval = 0;
	ozur_ctx *ozur = NULL;
	struct ozXX_udatatype uctx;
	static const char *modname = "unreduce";

	if(!dcmpro->len_known) goto done;

	de_zeromem(&uctx, sizeof(struct ozXX_udatatype));
	uctx.c = c;
	uctx.inf = dcmpri->f;
	uctx.inf_curpos = dcmpri->pos;
	uctx.outf = dcmpro->f;

	ozur = de_malloc(c, sizeof(ozur_ctx));
	ozur->userdata = (void*)&uctx;
	ozur->cb_read = my_ozur_read;
	ozur->cb_write = my_ozur_write;
	ozur->cb_post_follower_sets = my_ozur_post_follower_sets_hook;

	ozur->cmpr_size = dcmpri->len;
	ozur->uncmpr_size = dcmpro->expected_len;
	ozur->cmpr_factor = params->cmpr_factor;

	ozur_run(ozur);

	if(ozur->error_code) {
		de_dfilter_set_errorf(c, dres, modname, "Decompression failed (code %d)",
			ozur->error_code);
	}
	else {
		dres->bytes_consumed = ozur->cmpr_nbytes_consumed;
		dres->bytes_consumed_valid = 1;
		retval = 1;
	}

done:
	de_free(c, ozur);
	if(retval==0 && !dres->errcode) {
		de_dfilter_set_generic_error(c, dres, modname);
	}
}
