// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// LZW decompressor
// (work in progress)

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

struct delzwctx_struct;
typedef struct delzwctx_struct delzwctx;

#define DELZW_ERRCODE_NOTIMPL 100

typedef size_t (*delzw_cb_write_type)(delzwctx *dc, const u8 *buf, size_t size);

struct delzwctx_struct {
	deark *c;
	void *userdata;
	int basefmt;
	delzw_cb_write_type cb_write;
	int errcode;
	char errmsg[80];
};

static delzwctx *delzw_create(deark *c, void *userdata)
{
	delzwctx *dc;

	dc = de_malloc(c, sizeof(delzwctx));
	dc->c = c;
	dc->userdata = userdata;
	return dc;
}

static void delzw_destroy(delzwctx *dc)
{
	if(!dc) return;
	de_free(dc->c, dc);
}

static void delzw_addbuf(delzwctx *dc, const u8 *buf, size_t buf_len)
{
	de_dbg(dc->c, "[read %d bytes]", (int)buf_len);
	dc->cb_write(dc, buf, buf_len); // temporary
}

static void delzw_finish(delzwctx *dc)
{
	dc->errcode = DELZW_ERRCODE_NOTIMPL;
	de_strlcpy(dc->errmsg, "Not implemented", sizeof(dc->errmsg));
}

///////////////////////////////////////////////////

struct my_delzw_userdata {
	delzwctx *dc;
	dbuf *outf;
};

static size_t my_delzw_write(delzwctx *dc, const u8 *buf, size_t buf_len)
{
	struct my_delzw_userdata *u = (struct my_delzw_userdata*)dc->userdata;

	dbuf_write(u->outf, buf, (i64)buf_len);
	return buf_len;
}

static int my_delzw_buffered_read_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct my_delzw_userdata *u = (struct my_delzw_userdata*)brctx->userdata;

	delzw_addbuf(u->dc, buf, (size_t)buf_len);
	return 1;
}

void de_fmtutil_decompress_lzw(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct delzw_params *delzwp)
{
	delzwctx *dc = NULL;
	const char *modname = "delzw";
	struct my_delzw_userdata u;

	de_zeromem(&u, sizeof(struct my_delzw_userdata));
	u.outf = dcmpro->f;

	dc = delzw_create(c, (void*)&u);
	if(!dc) goto done;
	u.dc = dc;
	dc->cb_write = my_delzw_write;

	dbuf_buffered_read(dcmpri->f, dcmpri->pos, dcmpri->len,
		my_delzw_buffered_read_cbfn, (void*)&u);

	delzw_finish(dc);

	if(dc->errcode) {
		de_dfilter_set_errorf(c, dres, modname, "%s", dc->errmsg);
	}

done:
	delzw_destroy(dc);
}
