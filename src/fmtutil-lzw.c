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

#define DELZW_CODE u16
#define DELZW_MAXMAXCODESIZE 16

struct delzw_tableentry {
	DELZW_CODE parent;
	u8 value;
	u8 flags;
};

typedef size_t (*delzw_cb_write_type)(delzwctx *dc, const u8 *buf, size_t size);

struct delzwctx_struct {
	deark *c;
	void *userdata;
#define DELZW_BASEFMT_UNIXCOMPRESS 1
	int basefmt;

#define DELZW_HEADERTYPE_NONE  0
#define DELZW_HEADERTYPE_3BYTE 1
#define DELZW_HEADERTYPE_1BYTE 2
	int header_type;

	delzw_cb_write_type cb_write;

#define DELZW_ERRCODE_NOTIMPL 100
	int errcode;

	unsigned int mincodesize;
	unsigned int maxcodesize;
	int codesize_is_dynamic;

#define DELZW_STATE_INIT            0
#define DELZW_STATE_READING_HEADER  1
#define DELZW_STATE_READING_CODES   2
#define DELZW_STATE_SKIPPING_BITS   3
	int state;
	i64 header_size;
	i64 total_nbytes_processed;
	unsigned int curcodesize;
	size_t num_tbl_items;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	u8 header_buf[3];

	struct delzw_tableentry *codetbl;

	char errmsg[80];
};

static void delzw_set_error(delzwctx *dc, int code, const char *msg)
{
	if(dc->errcode) return;
	dc->errcode = code;
	de_strlcpy(dc->errmsg, msg, sizeof(dc->errmsg));
}

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
	deark *c;

	if(!dc) return;
	c = dc->c;
	de_free(c, dc->codetbl);
	de_free(c, dc);
}

static void delzw_init_decompression(delzwctx *dc)
{
	if(dc->header_type==DELZW_HEADERTYPE_3BYTE) {
		dc->header_size = 3;
	}

	if(dc->header_size>0) {
		dc->state = DELZW_STATE_READING_HEADER;
	}
	else {
		dc->state = DELZW_STATE_READING_CODES;
	}
}

// Set any remaining params needed, and validate params.
static void delzw_after_header(delzwctx *dc)
{
	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		dc->mincodesize = 9;
	}

	dc->curcodesize = dc->mincodesize;

	dc->num_tbl_items = ((size_t)1)<<dc->maxcodesize;
	dc->codetbl = de_mallocarray(dc->c, dc->num_tbl_items, sizeof(struct delzw_tableentry));
}

static void delzw_process_unixcompress_header(delzwctx *dc)
{
	if(dc->header_buf[0]!=0x1f || dc->header_buf[1]!=0x9d) {
		delzw_set_error(dc, 1, "Not in compress format");
		return;
	}

	dc->maxcodesize = (unsigned int)(dc->header_buf[2] & 0x1f);
	dc->codesize_is_dynamic = (dc->header_buf[2] & 0x80) ? 1 : 0;
}

static void delzw_process_header(delzwctx *dc)
{
	de_dbg(dc->c, "process_header");
	if(dc->header_type==DELZW_HEADERTYPE_3BYTE) {
		delzw_process_unixcompress_header(dc);
	}
	delzw_after_header(dc);
	dc->state = DELZW_STATE_READING_CODES;
}

static void delzw_add_byte_to_bitbuf(delzwctx *dc, u8 b)
{
	// Add a byte's worth of bits to the pending code
	dc->bitreader_buf |= ((unsigned int)b)<<dc->bitreader_nbits_in_buf;
	dc->bitreader_nbits_in_buf += 8;
}

static DELZW_CODE delzw_get_code(delzwctx *dc, unsigned int nbits)
{
	unsigned int n;

	n = dc->bitreader_buf & ((1U<<nbits)-1U);
	dc->bitreader_buf >>= nbits;
	dc->bitreader_nbits_in_buf -= nbits;
	return (DELZW_CODE)n;
}

static void delzw_process_code(delzwctx *dc, DELZW_CODE code)
{
}

static void delzw_process_byte(delzwctx *dc, u8 b)
{
	if(dc->state==DELZW_STATE_INIT) {
		delzw_init_decompression(dc);

		if(dc->header_size==0) {
			delzw_after_header(dc);
			dc->state=DELZW_STATE_READING_CODES;
		}
		else {
			dc->state=DELZW_STATE_READING_HEADER;
		}
	}

	if(dc->state==DELZW_STATE_READING_HEADER) {
		if(dc->total_nbytes_processed < dc->header_size) {
			dc->header_buf[dc->total_nbytes_processed] = b;
		}
		if(dc->total_nbytes_processed+1 >= dc->header_size) {
			delzw_process_header(dc);
		}
	}
	else if(dc->state==DELZW_STATE_READING_CODES) {
		delzw_add_byte_to_bitbuf(dc, b);

		while(dc->bitreader_nbits_in_buf >= dc->curcodesize) {
			DELZW_CODE code;

			if(dc->errcode) break;
			code = delzw_get_code(dc, dc->curcodesize);
			delzw_process_code(dc, code);
		}
	}
}

static void delzw_addbuf(delzwctx *dc, const u8 *buf, size_t buf_len)
{
	size_t i;

	de_dbg(dc->c, "[read %d bytes]", (int)buf_len);
	for(i=0; i<buf_len; i++) {
		if(dc->errcode) break;
		delzw_process_byte(dc, buf[i]);
		dc->total_nbytes_processed++;
	}
}

static void delzw_finish(delzwctx *dc)
{
	delzw_set_error(dc, DELZW_ERRCODE_NOTIMPL, "Not implemented");
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
	if(u->dc->errcode) return 0;
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
	if(delzwp->fmt==DE_LZWFMT_UNIXCOMPRESS) {
		dc->basefmt = DELZW_BASEFMT_UNIXCOMPRESS;
		dc->header_type = DELZW_HEADERTYPE_3BYTE;
	}

	dbuf_buffered_read(dcmpri->f, dcmpri->pos, dcmpri->len,
		my_delzw_buffered_read_cbfn, (void*)&u);

	delzw_finish(dc);

	if(dc->errcode) {
		de_dfilter_set_errorf(c, dres, modname, "%s", dc->errmsg);
	}

done:
	delzw_destroy(dc);
}
