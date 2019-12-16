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
#define DELZW_CODETYPE_INVALID     0x00
#define DELZW_CODETYPE_STATIC      0x01
#define DELZW_CODETYPE_DYN_UNUSED  0x02
#define DELZW_CODETYPE_DYN_USED    0x03
#define DELZW_CODETYPE_CLEAR       0x08
#define DELZW_CODETYPE_STOP        0x09
#define DELZW_CODETYPE_SPECIAL     0x0f
	u8 codetype;
	u8 flags;
};

typedef size_t (*delzw_cb_write_type)(delzwctx *dc, const u8 *buf, size_t size);

struct delzwctx_struct {
	deark *c;
	void *userdata;
#define DELZW_BASEFMT_UNIXCOMPRESS 1
#define DELZW_BASEFMT_ZIPSHRINK    3
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
	i64 uncmpr_nbytes_written;
	unsigned int curr_code_size;
	size_t ct_capacity;
	i64 have_oldcode;
	DELZW_CODE oldcode;
	DELZW_CODE last_code_added;
	u8 last_value;
	DELZW_CODE highest_code_ever_used;
	DELZW_CODE free_code_search_start;
	DELZW_CODE first_dynamic_code;
	int escaped_code_is_pending;
	int has_clear_code;
	DELZW_CODE clear_code_value;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	size_t outbuf_nbytes_used;

	struct delzw_tableentry *ct;

	u8 header_buf[3];
	size_t valbuf_capacity;
	u8 *valbuf;
	char errmsg[80];

#define DELZW_OUTBUF_SIZE 1024
	u8 outbuf[DELZW_OUTBUF_SIZE];
};

#if 0
static void delzw_dumptable(delzwctx *dc) {
	DELZW_CODE k;
	for(k=0; k<dc->highest_code_ever_used; k++) {
		de_dbg(dc->c, "[%d] p=%d v=%d ty=%d f=%d",
			(int)k, (int)dc->ct[k].parent,
			(int)dc->ct[k].value, (int)dc->ct[k].codetype, (int)dc->ct[k].flags);
	}
}
#endif

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
	de_free(c, dc->ct);
	de_free(c, dc->valbuf);
	de_free(c, dc);
}

static void delzw_write_unbuffered(delzwctx *dc, const u8 *buf, size_t n)
{
	size_t ret;

	if(dc->errcode) return;
	if(n<1) return;
	ret = dc->cb_write(dc, buf, n);
	if(ret != n) {
		delzw_set_error(dc, 1, "1");
		return;
	}
	dc->uncmpr_nbytes_written += (i64)n;
}

static void delzw_flush(delzwctx *dc)
{
	if(dc->errcode) return;
	delzw_write_unbuffered(dc, dc->outbuf, dc->outbuf_nbytes_used);
	dc->outbuf_nbytes_used = 0;
}

static void delzw_write(delzwctx *dc, const u8 *buf, size_t n)
{
	if(dc->errcode) return;

	// If there's enough room in outbuf, copy it there, and we're done.
	if(dc->outbuf_nbytes_used + n <= DELZW_OUTBUF_SIZE) {
		de_memcpy(&dc->outbuf[dc->outbuf_nbytes_used], buf, n);
		dc->outbuf_nbytes_used += n;
		return;
	}

	// Flush anything currently in outbuf.
	delzw_flush(dc);
	if(dc->errcode) return;

	// If too big for outbuf, write without buffering.
	if(n > DELZW_OUTBUF_SIZE) {
		delzw_write_unbuffered(dc, buf, n);
		return;
	}

	// Otherwise copy to outbuf
	de_memcpy(dc->outbuf, buf, n);
	dc->outbuf_nbytes_used += n;
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
// (This is always called, even if there is no header.)
static void delzw_after_header(delzwctx *dc)
{
	DELZW_CODE i;

	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		dc->mincodesize = 9;
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		dc->mincodesize = 9;
		dc->maxcodesize = 13;
	}

	dc->curr_code_size = dc->mincodesize;

	dc->ct_capacity = ((size_t)1)<<dc->maxcodesize;
	dc->ct = de_mallocarray(dc->c, dc->ct_capacity, sizeof(struct delzw_tableentry));
	dc->valbuf_capacity = dc->ct_capacity;
	dc->valbuf = de_malloc(dc->c, dc->valbuf_capacity);

	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		for(i=0; i<256; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (u8)i;
		}

		if(dc->codesize_is_dynamic) {
			dc->ct[256].codetype = DELZW_CODETYPE_CLEAR;
			dc->first_dynamic_code = 257;
		}
		else {
			dc->first_dynamic_code = 256;
		}

		for(i=dc->first_dynamic_code; i<dc->ct_capacity; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_DYN_UNUSED;
		}
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		dc->first_dynamic_code = 257;
		dc->free_code_search_start = 257;

		for(i=0; i<256; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (u8)i;
		}
		dc->ct[256].codetype = DELZW_CODETYPE_SPECIAL;
		for(i=dc->first_dynamic_code; i<dc->ct_capacity; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_DYN_UNUSED;
		}
	}
}

static void delzw_process_unixcompress_header(delzwctx *dc)
{
	if(dc->header_buf[0]!=0x1f || dc->header_buf[1]!=0x9d) {
		delzw_set_error(dc, 1, "Not in compress format");
		return;
	}

	dc->maxcodesize = (unsigned int)(dc->header_buf[2] & 0x1f);
	dc->codesize_is_dynamic = (dc->header_buf[2] & 0x80) ? 1 : 0;

	if(dc->codesize_is_dynamic) {
		dc->has_clear_code = 1;
		dc->clear_code_value = 256;
	}
	else {
		dc->has_clear_code = 0;
	}
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

static void delzw_partial_clear(delzwctx *dc)
{
	DELZW_CODE i;

	for(i=257; i<=dc->highest_code_ever_used; i++) {
		// If this code is in use
		if(dc->ct[i].codetype==DELZW_CODETYPE_DYN_USED) {
			// and its parent is a dynamic code,
			//   mark its parent as having a child
			if(dc->ct[i].parent>=257) {
				dc->ct[dc->ct[i].parent].flags = 1;
			}
		}
	}

	for(i=257; i<=dc->highest_code_ever_used; i++) {
		if(dc->ct[i].flags==0) {
			// If this code has no children, clear it
			dc->ct[i].codetype = DELZW_CODETYPE_DYN_UNUSED;
			dc->ct[i].parent = 0;
			dc->ct[i].value = 0;
		}
		else {
			// Leave all flags clear, for next time
			dc->ct[i].flags = 0;
		}
	}

	dc->free_code_search_start = 257;
}

// Is this a valid code with a value (a static, or in-use dynamic code)?
static int delzw_code_is_in_table(delzwctx *dc, DELZW_CODE code)
{
	u8 codetype = dc->ct[code].codetype;

	if(codetype==DELZW_CODETYPE_STATIC) return 1;
	if(codetype==DELZW_CODETYPE_DYN_USED) return 1;
	return 0;
}

// Decode an LZW code to one or more values, and write the values.
// Updates ctx->last_value.
static void delzw_emit_code(delzwctx *dc, DELZW_CODE code1)
{
	DELZW_CODE code = code1;
	size_t valbuf_pos = dc->valbuf_capacity; // = First entry that's used

	while(1) {
		if(code >= dc->ct_capacity) {
			delzw_set_error(dc, 1, "2");
			return;
		}

		if(valbuf_pos==0) {
			// We must be in an infinite loop (probably an internal error).
			delzw_set_error(dc, 1, "3");
			return;
		}

		// valbuf is a stack, essentially. We fill it in the reverse direction,
		// to make it simpler to write the final byte sequence.
		valbuf_pos--;

		if(dc->ct[code].codetype==DELZW_CODETYPE_DYN_UNUSED) {
			dc->valbuf[valbuf_pos] = dc->last_value;
			code = dc->oldcode;
			continue;
		}

		dc->valbuf[valbuf_pos] = dc->ct[code].value;

		if(dc->ct[code].codetype==DELZW_CODETYPE_STATIC) {
			dc->last_value = dc->ct[code].value;
			break;
		}

		// Traverse the tree, back toward the root codes.
		code = dc->ct[code].parent;
	}

	// Write out the collected values.
	delzw_write(dc, &dc->valbuf[valbuf_pos], dc->valbuf_capacity - valbuf_pos);
}

static void delzw_find_first_free_entry(delzwctx *dc, DELZW_CODE *pentry)
{
	DELZW_CODE k;

	for(k=dc->free_code_search_start; k<dc->ct_capacity; k++) {
		if(dc->ct[k].codetype==DELZW_CODETYPE_DYN_UNUSED) {
			*pentry = k;
			return;
		}
	}

	*pentry = (DELZW_CODE)(dc->ct_capacity-1);
	delzw_set_error(dc, 1, "4");
}

// Add a code to the dictionary.
// Sets delzw->last_code_added to the position where it was added.
static void delzw_add_to_dict(delzwctx *dc, DELZW_CODE parent, u8 value)
{
	DELZW_CODE newpos;

	delzw_find_first_free_entry(dc, &newpos);
	if(dc->errcode) return;

	dc->ct[newpos].parent = parent;
	dc->ct[newpos].value = value;
	dc->ct[newpos].codetype = DELZW_CODETYPE_DYN_USED;
	dc->last_code_added = newpos;
	dc->free_code_search_start = newpos+1;
	if(newpos > dc->highest_code_ever_used) {
		dc->highest_code_ever_used = newpos;
	}
}

static void delzw_process_data_code(delzwctx *dc, DELZW_CODE code)
{
	if(code >= dc->ct_capacity) {
		return;
	}

	if(!dc->have_oldcode) {
		// Special case for the first code.
		delzw_emit_code(dc, code);
		dc->oldcode = code;
		dc->have_oldcode = 1;
		dc->last_value = (u8)dc->oldcode;
		return;
	}

	if(delzw_code_is_in_table(dc, code)) {
		delzw_emit_code(dc, code);
		if(dc->errcode) return;

		// Let k = the first character of the translation of the code.
		// Add <oldcode>k to the dictionary.
		delzw_add_to_dict(dc, dc->oldcode, dc->last_value);
	}
	else {
		// Let k = the first char of the translation of oldcode.
		// Add <oldcode>k to the dictionary.
		delzw_add_to_dict(dc, dc->oldcode, dc->last_value);
		if(dc->errcode) return;

		// Write <oldcode>k to the output stream.
		delzw_emit_code(dc, dc->last_code_added);
	}

	dc->oldcode = code;

}

static void delzw_process_code(delzwctx *dc, DELZW_CODE code)
{
	if(code >= dc->ct_capacity) return;

	if(dc->escaped_code_is_pending) {
		dc->escaped_code_is_pending = 0;
		if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
			if(code==1 && (dc->curr_code_size<dc->maxcodesize)) {
				dc->curr_code_size++;
			}
			else if(code==2) {
				delzw_partial_clear(dc);
			}
		}
		return;
	}

	switch(dc->ct[code].codetype) {
	case DELZW_CODETYPE_STATIC:
	case DELZW_CODETYPE_DYN_UNUSED:
	case DELZW_CODETYPE_DYN_USED:
		delzw_process_data_code(dc, code);
		break;
	case DELZW_CODETYPE_SPECIAL:
		if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK && code==256) {
			dc->escaped_code_is_pending = 1;
		}
		break;
	}
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

		while(dc->bitreader_nbits_in_buf >= dc->curr_code_size) {
			DELZW_CODE code;

			if(dc->errcode) break;
			code = delzw_get_code(dc, dc->curr_code_size);
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
	if(dc->basefmt != DELZW_BASEFMT_ZIPSHRINK) {
		delzw_set_error(dc, DELZW_ERRCODE_NOTIMPL, "Not implemented");
	}

	if(dc->errcode) return;

	delzw_flush(dc);
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
	else if(delzwp->fmt==DE_LZWFMT_ZIPSHRINK) {
		dc->basefmt = DELZW_BASEFMT_ZIPSHRINK;
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
