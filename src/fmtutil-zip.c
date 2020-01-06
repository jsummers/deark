// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// Compression formats specific to ZIP

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

static void *ozXX_calloc(void *userdata, size_t nmemb, size_t size);
static void ozXX_free(void *userdata, void *ptr);

#define OZUR_UINT8     u8
#define OZUR_OFF_T     i64
#include "../foreign/ozunreduce.h"

#define UI6A_UINT8     u8
#define UI6A_UINT16    u16
#define UI6A_UINT32    u32
#define UI6A_OFF_T     i64
#define UI6A_ZEROMEM   de_zeromem
#define UI6A_MEMCPY    de_memcpy
#define UI6A_CALLOC(u, nmemb, size, ty) ozXX_calloc((u), (nmemb), (size))
#define UI6A_FREE      ozXX_free
#include "../foreign/unimplode6a.h"

// Struct for userdata, shared by Implode and Reduce decoders
struct ozXX_udatatype {
	deark *c;
	dbuf *inf;
	i64 inf_curpos;
	dbuf *outf;
	int dumptrees;
};

static void *ozXX_calloc(void *userdata, size_t nmemb, size_t size)
{
	deark *c = ((struct ozXX_udatatype *)userdata)->c;

	return de_mallocarray(c, (i64)nmemb, size);
}

static void ozXX_free(void *userdata, void *ptr)
{
	deark *c = ((struct ozXX_udatatype *)userdata)->c;

	de_free(c, ptr);
}

// Used by Implode and Reduce decoders
static size_t ozXX_read(struct ozXX_udatatype *uctx, u8 *buf, size_t size)
{
	dbuf_read(uctx->inf, buf, uctx->inf_curpos, (i64)size);
	uctx->inf_curpos += (i64)size;
	return size;
}

// Used by Implode and Reduce decoders
static size_t ozXX_write(struct ozXX_udatatype *uctx, const u8 *buf, size_t size)
{
	dbuf_write(uctx->outf, buf, (i64)size);
	return size;
}

void fmtutil_decompress_zip_shrink(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_ZIPSHRINK;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
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

//static void do_decompress_reduce(deark *c, lctx *d, struct compression_params *cparams,
//	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
//	struct de_dfilter_results *dres)
void fmtutil_decompress_zip_reduce(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int cmpr_factor, unsigned int flags)
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
	ozur->cmpr_factor = cmpr_factor;

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

static void zipexpl_huft_dump1(struct ozXX_udatatype *zu, struct ui6a_huft *t, unsigned int idx)
{
	de_dbg(zu->c, "[%u:%p] e=%u b=%u n=%u t=%p",
		idx, (void*)t, (unsigned int)t->e, (unsigned int)t->b,
		(unsigned int)t->n, (void*)t->t_arr);
}

static void zipexpl_huft_dump(struct ozXX_udatatype *zu, struct ui6a_htable *tbl)
{
	deark *c = zu->c;
	struct ui6a_huftarray *t = tbl->first_array;
	struct ui6a_huftarray *p = t;

	de_dbg(c, "huffman [%s] table %p", tbl->tblname, (void*)p);

	de_dbg_indent(c, 1);

	while(1) {
		struct ui6a_huftarray *q;
		unsigned int k;

		if(!p) {
			de_dbg(c, "table arr: NULL");
			break;
		}
		de_dbg(c, "table arr: %p, h[]=%p", (void*)p, (void*)p->h);

		q = p->next_array;

		de_dbg_indent(c, 1);
		de_dbg(c, "count=%u", p->num_alloc_h);
		for(k=0; k<p->num_alloc_h; k++) {
			zipexpl_huft_dump1(zu, &p->h[k], k);
		}
		de_dbg_indent(c, -1);

		p = q;
	}

	de_dbg_indent(c, -1);
}

static size_t my_zipexpl_read(ui6a_ctx *ui6a, UI6A_UINT8 *buf, size_t size)
{
	return ozXX_read((struct ozXX_udatatype*)ui6a->userdata, buf, size);
}

static size_t my_zipexpl_write(ui6a_ctx *ui6a, const UI6A_UINT8 *buf, size_t size)
{
	return ozXX_write((struct ozXX_udatatype *)ui6a->userdata, buf, size);
}

static void my_zipexpl_cb_post_read_trees(ui6a_ctx *ui6a, struct ui6a_htables *tbls)
{
	struct ozXX_udatatype *zu = (struct ozXX_udatatype *)ui6a->userdata;

	if(zu->dumptrees) {
		zipexpl_huft_dump(zu, &tbls->d);
		zipexpl_huft_dump(zu, &tbls->l);
		zipexpl_huft_dump(zu, &tbls->b);
	}
}

//static void do_decompress_implode(deark *c, lctx *d, struct compression_params *cparams,
//	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
//	struct de_dfilter_results *dres)
void fmtutil_decompress_zip_implode(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int bit_flags, unsigned int flags)
{
	ui6a_ctx *ui6a = NULL;
	struct ozXX_udatatype zu;
	int retval = 0;
	static const char *modname = "unimplode";

	de_zeromem(&zu, sizeof(struct ozXX_udatatype));
	if(!dcmpro->len_known) goto done;

	zu.c = c;
	zu.dumptrees = de_get_ext_option_bool(c, "zip:dumptrees", 0);
	zu.inf = dcmpri->f;
	zu.inf_curpos = dcmpri->pos;
	zu.outf = dcmpro->f;

	ui6a = ui6a_create((void*)&zu);
	if(!ui6a) goto done;

	ui6a->cmpr_size = dcmpri->len;
	ui6a->uncmpr_size = dcmpro->expected_len;
	ui6a->bit_flags = (UI6A_UINT16)bit_flags;
	ui6a->emulate_pkzip10x = de_get_ext_option_bool(c, "zip:implodebug", 0);

	ui6a->cb_read = my_zipexpl_read;
	ui6a->cb_write =  my_zipexpl_write;
	ui6a->cb_post_read_trees = my_zipexpl_cb_post_read_trees;

	ui6a_unimplode(ui6a);
	if(ui6a->error_code == UI6A_ERRCODE_OK) {
		dres->bytes_consumed = ui6a->cmpr_nbytes_consumed;
		dres->bytes_consumed_valid = 1;
		retval = 1;
	}
	else {
		de_dfilter_set_errorf(c, dres, modname, "Decompression failed (code %d)", ui6a->error_code);
	}

done:
	ui6a_destroy(ui6a);

	if(!retval && !dres->errcode) {
		de_dfilter_set_generic_error(c, dres, modname);
	}
}
