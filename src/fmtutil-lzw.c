// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// LZW decompressor
// (work in progress)

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

static void *my_delzw_calloc(void *userdata, size_t nmemb, size_t size);
static void my_delzw_free(void *userdata, void *ptr);

#define DELZW_UINT8   u8
#define DELZW_UINT16  u16
#define DELZW_UINT32  u32
#define DELZW_OFF_T   i64
#define DELZW_MEMCPY  de_memcpy
#define DELZW_STRLCPY de_strlcpy
#define DELZW_VSNPRINTF de_vsnprintf
#define DELZW_GNUC_ATTRIBUTE de_gnuc_attribute
#define DELZW_CALLOC(u, nmemb, size, ty) my_delzw_calloc((u), (nmemb), (size))
#define DELZW_FREE      my_delzw_free

#include "../foreign/delzw.h"

///////////////////////////////////////////////////

static void setup_delzw_common(deark *c, delzwctx *dc, struct delzw_params *delzwp)
{
	dc->debug_level = c->debug_level;

	if(delzwp->fmt==DE_LZWFMT_UNIXCOMPRESS) {
		dc->basefmt = DELZW_BASEFMT_UNIXCOMPRESS;
		dc->auto_inc_codesize = 1;
		if(delzwp->flags & DE_LZWFLAG_HAS3BYTEHEADER) {
			dc->header_type = DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE;
		}
		else if(delzwp->flags & DE_LZWFLAG_HAS1BYTEHEADER) {
			dc->header_type = DELZW_HEADERTYPE_ARC1BYTE;
		}
		else {
			dc->unixcompress_has_clear_code = 1;
			dc->max_codesize = delzwp->max_code_size;
		}

		if((delzwp->flags & DE_LZWFLAG_TOLERATETRAILINGJUNK) &&
			!dc->output_len_known)
		{
			dc->stop_on_invalid_code = 1;
		}
	}
	else if(delzwp->fmt==DE_LZWFMT_ZIPSHRINK) {
		dc->basefmt = DELZW_BASEFMT_ZIPSHRINK;
	}
	else if(delzwp->fmt==DE_LZWFMT_GIF) {
		dc->basefmt = DELZW_BASEFMT_GIF;
		dc->gif_root_codesize = delzwp->gif_root_code_size;
	}
	else if(delzwp->fmt==DE_LZWFMT_ZOOLZD) {
		dc->basefmt = DELZW_BASEFMT_ZOOLZD;
		dc->auto_inc_codesize = 1;
		dc->max_codesize = delzwp->max_code_size;
	}
}

void de_fmtutil_decompress_lzw(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct delzw_params *delzwp)
{
	de_dfilter_decompress_oneshot(c, dfilter_lzw_codec, (void*)delzwp,
		dcmpri, dcmpro, dres);
}

static size_t wrapped_dfctx_write_cb(delzwctx *dc, const DELZW_UINT8 *buf, size_t size,
	unsigned int *outflags)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx*)dc->userdata;

	// Note: We could be writing to a custom dbuf, in which case the client has
	// a chance to examine the decompressed bytes, and might want to stop the
	// decompression based on their contents. But there's currently no way to
	// do that.
	dbuf_write(dfctx->dcmpro->f, buf, (i64)size);
	return size;
}

static void wrapped_dfctx_debugmsg(delzwctx *dc, int level, const char *msg)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx*)dc->userdata;

	de_dbg(dfctx->c, "[delzw:i%"I64_FMT"/o%"I64_FMT"] %s",
		(i64)dc->total_nbytes_processed, (i64)dc->uncmpr_nbytes_decoded, msg);
}

static void my_lzw_codec_finish(struct de_dfilter_ctx *dfctx)
{
	const char *modname = "delzw";
	delzwctx *dc = (delzwctx*)dfctx->codec_private;

	if(!dc) return;
	delzw_finish(dc);

	dfctx->dres->bytes_consumed = dc->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;

	if(dc->errcode) {
		de_dfilter_set_errorf(dfctx->c, dfctx->dres, modname, "%s", dc->errmsg);
	}
}

static void my_lzw_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	delzwctx *dc = (delzwctx*)dfctx->codec_private;

	if(!dc) return;
	delzw_addbuf(dc, buf, (size_t)buf_len);
	if(dc->state == DELZW_STATE_FINISHED) {
		dfctx->finished_flag = 1;
	}
}

static void my_lzw_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	delzwctx *dc = (delzwctx*)dfctx->codec_private;

	delzw_destroy(dc);
	dfctx->codec_private = NULL;
}

// Print dbg messages and warnings about the header
static void my_lzw_after_header_parsed(delzwctx *dc)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx *)dc->userdata;
	deark *c = dfctx->c;

	if(dc->header_type==DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE) {
		de_dbg(c, "LZW mode: 0x%02x", (unsigned int)dc->header_unixcompress_mode);
		de_dbg_indent(c, 1);
		de_dbg(c, "maxbits: %u", (unsigned int)dc->header_unixcompress_max_codesize);
		de_dbg(c, "blockmode: %d", (int)dc->header_unixcompress_block_mode);
		if(!dc->header_unixcompress_block_mode) {
			de_warn(c, "This file uses an obsolete compress'd format, which "
				"might not be decompressed correctly");
		}
		de_dbg_indent(c, -1);
	}
	else if(dc->header_type==DELZW_HEADERTYPE_ARC1BYTE) {
		de_dbg(c, "LZW maxbits: %u", (unsigned int)dc->header_unixcompress_max_codesize);
	}
}

static void *my_delzw_calloc(void *userdata, size_t nmemb, size_t size)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx*)userdata;

	return de_mallocarray(dfctx->c, (i64)nmemb, size);
}

static void my_delzw_free(void *userdata, void *ptr)
{
	struct de_dfilter_ctx *dfctx = (struct de_dfilter_ctx*)userdata;

	de_free(dfctx->c, ptr);
}

// codec_private_params is type struct delzw_params.
void dfilter_lzw_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	delzwctx *dc = NULL;
	struct delzw_params *delzwp = (struct delzw_params*)codec_private_params;

	dc = delzw_create((void*)dfctx);
	if(!dc) goto done;
	dfctx->codec_private = (void*)dc;
	dfctx->codec_finish_fn = my_lzw_codec_finish;
	dfctx->codec_destroy_fn = my_lzw_codec_destroy;
	dfctx->codec_addbuf_fn = my_lzw_codec_addbuf;

	dc->cb_write = wrapped_dfctx_write_cb;
	dc->cb_debugmsg = wrapped_dfctx_debugmsg;
	dc->cb_after_header_parsed = my_lzw_after_header_parsed;
	dc->output_len_known = dfctx->dcmpro->len_known;
	dc->output_expected_len = dfctx->dcmpro->expected_len;

	setup_delzw_common(dfctx->c, dc, delzwp);
done:
	;
}

struct de_dfilter_ctx *de_dfilter_create_delzw(deark *c, struct delzw_params *delzwp,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	return de_dfilter_create(c, dfilter_lzw_codec, (void*)delzwp,
		dcmpro, dres);
}
