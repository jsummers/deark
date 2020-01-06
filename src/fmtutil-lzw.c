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

#define DELZW_CODE           u32 // int type used in most cases
#define DELZW_CODE_MINRANGE  u16 // int type used for parents in table entries
#define DELZW_MINMINCODESIZE 3
#define DELZW_MAXMAXCODESIZE 16
#define DELZW_NBITS_TO_MAXCODE(n) ((DELZW_CODE)((1<<(n))-1))
#define DELZW_NBITS_TO_NCODES(n) ((DELZW_CODE)(1<<(n)))

struct delzw_tableentry {
	DELZW_CODE_MINRANGE parent;
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

// Normally, the client must consume all the bytes in 'buf', and return 'size'.
// The other options are:
// - Set *outflags to 1, and return a number <='size'. This indicates that
// that decompression can stop; the client has all the data it needs.
// - Return a number !='size'. This is interpreted as a write error, and
// decompression will stop.
typedef size_t (*delzw_cb_write_type)(delzwctx *dc, const u8 *buf, size_t size,
	unsigned int *outflags);

typedef void (*delzw_cb_debugmsg_type)(delzwctx *dc, int level, const char *msg);

struct delzwctx_struct {
	// Fields the user can or must set:
	deark *c;
	void *userdata;
	int debug_level;
	delzw_cb_write_type cb_write;
	delzw_cb_debugmsg_type cb_debugmsg;

#define DELZW_BASEFMT_UNIXCOMPRESS 1
#define DELZW_BASEFMT_GIF          2
#define DELZW_BASEFMT_ZIPSHRINK    3
#define DELZW_BASEFMT_ZOOLZD       4
	int basefmt;

#define DELZW_HEADERTYPE_NONE  0
#define DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE 1
#define DELZW_HEADERTYPE_ARC1BYTE 2
	int header_type;

	unsigned gif_root_codesize;

	int stop_on_invalid_code;

	int output_len_known;
	i64 output_expected_len;

	// Fields that may be set by the user, or derived from other fields:
	int auto_inc_codesize;
	int unixcompress_has_clear_code;
	unsigned int min_codesize;
	unsigned int max_codesize;

	// Derived fields:
	i64 header_size;
	int has_partial_clearing;

	// Internal state:
#define DELZW_ERRCODE_OK                    0
#define DELZW_ERRCODE_GENERIC_ERROR         1
#define DELZW_ERRCODE_BAD_CDATA             2
#define DELZW_ERRCODE_MALLOC_FAILED         3
#define DELZW_ERRCODE_WRITE_FAILED          7
#define DELZW_ERRCODE_INSUFFICIENT_CDATA    8
#define DELZW_ERRCODE_UNSUPPORTED_OPTION    9
#define DELZW_ERRCODE_INTERNAL_ERROR        10
	int errcode;

#define DELZW_STATE_INIT            0
#define DELZW_STATE_READING_HEADER  1
#define DELZW_STATE_READING_CODES   2
#define DELZW_STATE_FINISHED        3
	int state;
	i64 total_nbytes_processed;
	i64 uncmpr_nbytes_written; // (Not including those in outbuf)
	i64 uncmpr_nbytes_decoded; // (Including those in outbuf)

	i64 ncodes_in_this_bitgroup;
	i64 nbytes_left_to_skip;

	unsigned int curr_codesize;

	i64 have_oldcode;
	DELZW_CODE oldcode;
	DELZW_CODE last_code_added;
	u8 last_value;
	DELZW_CODE highest_code_ever_used;
	DELZW_CODE free_code_search_start;
	DELZW_CODE first_dynamic_code;
	int escaped_code_is_pending;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	size_t outbuf_nbytes_used;

	DELZW_CODE ct_capacity;
	struct delzw_tableentry *ct;

	u8 header_buf[3];

	size_t valbuf_capacity;
	u8 *valbuf;

	char errmsg[80];

#define DELZW_OUTBUF_SIZE 1024
	u8 outbuf[DELZW_OUTBUF_SIZE];
};

static void delzw_debugmsg(delzwctx *dc, int level, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

static void delzw_debugmsg(delzwctx *dc, int level, const char *fmt, ...)
{
	va_list ap;
	char msg[200];

	if(!dc->cb_debugmsg) return;
	if(level>dc->debug_level) return;

	va_start(ap, fmt);
	de_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	dc->cb_debugmsg(dc, level, msg);
}

static void delzw_dumptable(delzwctx *dc)
{
	DELZW_CODE k;
	for(k=0; k<dc->highest_code_ever_used; k++) {
		delzw_debugmsg(dc, 4, "[%d] ty=%d p=%d v=%d f=%d",
			(int)k, (int)dc->ct[k].codetype, (int)dc->ct[k].parent,
			(int)dc->ct[k].value, (int)dc->ct[k].flags);
	}
}

static void delzw_stop(delzwctx *dc, const char *reason)
{
	if(dc->state == DELZW_STATE_FINISHED) return;
	delzw_debugmsg(dc, 2, "stopping due to %s", reason);
	dc->state = DELZW_STATE_FINISHED;
}

static void delzw_set_errorf(delzwctx *dc, int errcode, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

static void delzw_set_errorf(delzwctx *dc, int errcode, const char *fmt, ...)
{
	va_list ap;

	delzw_stop(dc, "error");
	if(dc->errcode) return;
	dc->errcode = errcode;
	va_start(ap, fmt);
	de_vsnprintf(dc->errmsg, sizeof(dc->errmsg), fmt, ap);
	va_end(ap);
}

static void delzw_set_error(delzwctx *dc, int errcode, const char *msg)
{
	delzw_stop(dc, "error");
	if(dc->errcode) return;
	dc->errcode = errcode;
	if(!msg || !msg[0]) {
		msg = "LZW decompression error";
	}
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

static void delzw_write_unbuffered(delzwctx *dc, const u8 *buf, size_t n1)
{
	i64 nbytes_written;
	unsigned int outflags = 0;
	i64 n = (i64)n1;

	if(dc->errcode) return;
	if(dc->output_len_known) {
		if(dc->uncmpr_nbytes_written + n > dc->output_expected_len) {
			n = dc->output_expected_len - dc->uncmpr_nbytes_written;
		}
	}
	if(n<1) return;
	nbytes_written = (i64)dc->cb_write(dc, buf, (size_t)n, &outflags);
	if((outflags & 0x1) && (nbytes_written<=n)) {
		delzw_stop(dc, "client request");
	}
	else if(nbytes_written != n) {
		delzw_set_error(dc, DELZW_ERRCODE_WRITE_FAILED, "Write failed");
		return;
	}
	dc->uncmpr_nbytes_written += (i64)nbytes_written;
}

static void delzw_flush(delzwctx *dc)
{
	if(dc->outbuf_nbytes_used<1) return;
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

static void delzw_process_unixcompress_3byteheader(delzwctx *dc)
{
	unsigned int options;

	if(dc->header_buf[0]!=0x1f || dc->header_buf[1]!=0x9d) {
		delzw_set_error(dc, DELZW_ERRCODE_BAD_CDATA, "Not in compress format");
		return;
	}

	options = (unsigned int)dc->header_buf[2];
	delzw_debugmsg(dc, 1, "LZW mode: 0x%02x", options);
	dc->max_codesize = (unsigned int)(options & 0x1f);
	delzw_debugmsg(dc, 1, " max code size: %u", dc->max_codesize);
	dc->unixcompress_has_clear_code = (options & 0x80) ? 1 : 0;
	delzw_debugmsg(dc, 1, " block mode: %d", dc->unixcompress_has_clear_code);
	if(!dc->unixcompress_has_clear_code) {
		// TODO: Handle warnings with a callback function, or something.
		de_warn(dc->c, "This file uses an obsolete compress'd format, which "
			"might not be decompressed correctly");
	}
}

static void delzw_process_arc_1byteheader(delzwctx *dc)
{
	dc->max_codesize = (unsigned int)(dc->header_buf[0] & 0x1f);
	delzw_debugmsg(dc, 1, "max code size: %u", dc->max_codesize);
	dc->unixcompress_has_clear_code = 1;
}

static void delzw_clear_bitbuf(delzwctx *dc)
{
	dc->bitreader_nbits_in_buf = 0;
	dc->bitreader_buf = 0;
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
			delzw_set_errorf(dc, DELZW_ERRCODE_GENERIC_ERROR, "Bad LZW code (%d)", (int)code);
			return;
		}

		if(valbuf_pos==0) {
			// We must be in an infinite loop (probably an internal error).
			delzw_set_error(dc, DELZW_ERRCODE_GENERIC_ERROR, NULL);
			if(dc->debug_level>=4) {
				delzw_dumptable(dc);
			}
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
	dc->uncmpr_nbytes_decoded += (i64)(dc->valbuf_capacity - valbuf_pos);
}

static void delzw_find_first_free_entry(delzwctx *dc, DELZW_CODE *pentry)
{
	DELZW_CODE k;

	for(k=dc->free_code_search_start; k<dc->ct_capacity; k++) {
		if(dc->ct[k].codetype==DELZW_CODETYPE_DYN_UNUSED) {
			*pentry = (DELZW_CODE)k;
			return;
		}
	}

	*pentry = (DELZW_CODE)(dc->ct_capacity-1);
	delzw_set_error(dc, DELZW_ERRCODE_BAD_CDATA, "LZW table unexpectedly full");
}

static void delzw_unixcompress_end_bitgroup(delzwctx *dc)
{
	i64 ncodes_alloc;
	i64 nbits_left_to_skip;

	// The Unix 'compress' format has a quirk.
	// The codes are written 8 at a time, with all 8 having the same codesize.
	// The codesize cannot change in the middle of a block of 8. If it needs to,
	// the remainder of the block is unused padding, which we must skip over.
	// Ths is relevant when we encounter a clear code, and *potentially* when the
	// codesize is auto-incremented. But except possibly for the first group of
	// codes (the 9-bit codes), the number of codes is always (?) a power of 2,
	// and a multiple of 8. So no padding is present.
	// As it happens, when code 256 is reserved as the clear code, it reduces the
	// number of 9-bit codes from 257 to 256, so still no padding is present.
	// But "v2" format does not use a clear code, and AFAICT it does have padding
	// after the 9-bit codes.

	ncodes_alloc = de_pad_to_n(dc->ncodes_in_this_bitgroup, 8);
	nbits_left_to_skip = (ncodes_alloc - dc->ncodes_in_this_bitgroup) * dc->curr_codesize;

	// My thinking:
	// Each "bitgroup" has a whole number of bytes.
	// When we get here, we've just read a code, so the bitreader's buffer can have no more than
	// 7 bits in it.
	// All of the bits in it will be part of the "bits to skip". After accounting for them, we'll
	// be left with a whole number of *bytes* left to skip, which always start on a byte boundary
	// in the input stream.
	// So, whenever the main input loop needs to skip anything, it will be a whole byte, and the
	// bitreader's buffer will be empty. That's good; it makes it easier to deal with this
	// padding.

	if(nbits_left_to_skip>0) {
		delzw_debugmsg(dc, 2, "padding bits: %d", (int)nbits_left_to_skip);
	}

	dc->ncodes_in_this_bitgroup = 0;
	if(dc->bitreader_nbits_in_buf>7 || dc->bitreader_nbits_in_buf>nbits_left_to_skip) {
		delzw_set_error(dc, DELZW_ERRCODE_INTERNAL_ERROR, NULL);
		return;
	}

	nbits_left_to_skip -= dc->bitreader_nbits_in_buf;
	if(nbits_left_to_skip%8 != 0) {
		delzw_set_error(dc, DELZW_ERRCODE_INTERNAL_ERROR, NULL);
		return;
	}

	delzw_clear_bitbuf(dc);
	dc->nbytes_left_to_skip = nbits_left_to_skip/8;
}

static void delzw_increase_codesize(delzwctx *dc)
{
	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		delzw_unixcompress_end_bitgroup(dc);
	}

	if(dc->curr_codesize<dc->max_codesize) {
		dc->curr_codesize++;
		delzw_debugmsg(dc, 2, "increased code size to %u", dc->curr_codesize);
	}
}

// Add a code to the dictionary.
// Sets delzw->last_code_added to the position where it was added.
static void delzw_add_to_dict(delzwctx *dc, DELZW_CODE parent, u8 value)
{
	DELZW_CODE newpos;

	if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		delzw_find_first_free_entry(dc, &newpos);
	}
	else {
		newpos = dc->free_code_search_start;
	}
	if(dc->errcode) return;
	if(newpos >= dc->ct_capacity) {
		return;
	}

	if(newpos < dc->first_dynamic_code) {
		delzw_set_error(dc, DELZW_ERRCODE_GENERIC_ERROR, NULL);
		return;
	}

	dc->ct[newpos].parent = (DELZW_CODE_MINRANGE)parent;
	dc->ct[newpos].value = value;
	dc->ct[newpos].codetype = DELZW_CODETYPE_DYN_USED;
	dc->last_code_added = newpos;
	dc->free_code_search_start = newpos+1;
	if(newpos > dc->highest_code_ever_used) {
		dc->highest_code_ever_used = newpos;
	}

	if(dc->auto_inc_codesize &&
		dc->free_code_search_start>DELZW_NBITS_TO_MAXCODE(dc->curr_codesize))
	{
		delzw_increase_codesize(dc);
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
		if(code>dc->free_code_search_start && !dc->has_partial_clearing) {
			if(dc->stop_on_invalid_code) {
				delzw_debugmsg(dc, 1, "bad code: %d when max=%d (assuming data stops here)",
					(int)code, (int)dc->free_code_search_start);
				delzw_stop(dc, "bad LZW code");
				return;
			}
			delzw_set_errorf(dc, DELZW_ERRCODE_BAD_CDATA, "Bad LZW code (%d when max=%d)",
				(int)code, (int)dc->free_code_search_start);
			return;
		}

		// Let k = the first char of the translation of oldcode.
		// Add <oldcode>k to the dictionary.
		delzw_add_to_dict(dc, dc->oldcode, dc->last_value);
		if(dc->errcode) return;

		// Write <oldcode>k to the output stream.
		delzw_emit_code(dc, dc->last_code_added);
	}

	dc->oldcode = code;
}

static void delzw_clear_one_dynamic_code(delzwctx *dc, DELZW_CODE code)
{
	if(code<dc->first_dynamic_code || code>=dc->ct_capacity) return;
	dc->ct[code].codetype = DELZW_CODETYPE_DYN_UNUSED;
	dc->ct[code].parent = 0;
	dc->ct[code].value = 0;
}

static void delzw_clear(delzwctx *dc)
{
	DELZW_CODE i;

	delzw_debugmsg(dc, 2, "clear code");

	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		delzw_unixcompress_end_bitgroup(dc);
	}

	for(i=dc->first_dynamic_code; i<=dc->highest_code_ever_used; i++) {
		delzw_clear_one_dynamic_code(dc, i);
	}

	dc->curr_codesize = dc->min_codesize;
	dc->free_code_search_start = dc->first_dynamic_code;
	dc->have_oldcode = 0;
	dc->oldcode = 0;
	dc->last_code_added = 0;
	dc->last_value = 0;

	delzw_debugmsg(dc, 2, "code size: %u", dc->curr_codesize);
}

static void delzw_partial_clear(delzwctx *dc)
{
	DELZW_CODE i;

	delzw_debugmsg(dc, 2, "partial clear code");

	for(i=dc->first_dynamic_code; i<=dc->highest_code_ever_used; i++) {
		// If this code is in use
		if(dc->ct[i].codetype==DELZW_CODETYPE_DYN_USED) {
			// and its parent is a dynamic code,
			//   mark its parent as having a child
			if(dc->ct[i].parent>=257) {
				dc->ct[dc->ct[i].parent].flags = 1;
			}
		}
	}

	for(i=dc->first_dynamic_code; i<=dc->highest_code_ever_used; i++) {
		if(dc->ct[i].flags==0) {
			// If this code has no children, clear it
			delzw_clear_one_dynamic_code(dc, i);
		}
		else {
			// Leave all flags clear, for next time
			dc->ct[i].flags = 0;
		}
	}

	dc->free_code_search_start = dc->first_dynamic_code;
}

static void delzw_process_code(delzwctx *dc, DELZW_CODE code)
{
	if(dc->debug_level>=3) {
		delzw_debugmsg(dc, 3, "code=%d oc=%d lca=%d lv=%d next=%d",
			(int)code,
			(int)dc->oldcode, (int)dc->last_code_added, (int)dc->last_value,
			(int)dc->free_code_search_start);
	}

	if(dc->escaped_code_is_pending) {
		dc->escaped_code_is_pending = 0;
		if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
			if(code==1 && (dc->curr_codesize<dc->max_codesize)) {
				delzw_increase_codesize(dc);
			}
			else if(code==2) {
				delzw_partial_clear(dc);
			}
			else {
				delzw_set_error(dc, DELZW_ERRCODE_BAD_CDATA, NULL);
			}
		}
		return;
	}

	if(code >= dc->ct_capacity) return;

	switch(dc->ct[code].codetype) {
	case DELZW_CODETYPE_STATIC:
	case DELZW_CODETYPE_DYN_UNUSED:
	case DELZW_CODETYPE_DYN_USED:
		delzw_process_data_code(dc, code);
		break;
	case DELZW_CODETYPE_CLEAR:
		delzw_clear(dc);
		break;
	case DELZW_CODETYPE_STOP:
		delzw_stop(dc, "stop code");
		break;
	case DELZW_CODETYPE_SPECIAL:
		if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK && code==256) {
			dc->escaped_code_is_pending = 1;
		}
		break;
	}
}

static void delzw_on_decompression_start(delzwctx *dc)
{
	if(dc->basefmt!=DELZW_BASEFMT_ZIPSHRINK &&
		dc->basefmt!=DELZW_BASEFMT_GIF &&
		dc->basefmt!=DELZW_BASEFMT_UNIXCOMPRESS &&
		dc->basefmt!=DELZW_BASEFMT_ZOOLZD)
	{
		delzw_set_error(dc, DELZW_ERRCODE_UNSUPPORTED_OPTION, "Unsupported LZW format");
		goto done;
	}

	if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		dc->has_partial_clearing = 1;
	}

	if(dc->header_type==DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE) {
		dc->header_size = 3;
	}
	else if(dc->header_type==DELZW_HEADERTYPE_ARC1BYTE) {
		dc->header_size = 1;
	}

done:
	;
}

// Process the header, if any.
// Set any remaining params needed, and validate params.
// This is called upon encountering the first byte after the header.
// (If zero bytes of data were compressed, it might never be called.)
static void delzw_on_codes_start(delzwctx *dc)
{
	DELZW_CODE i;

	if(dc->errcode) goto done;

	if(dc->header_size > 0) {
		delzw_debugmsg(dc, 2, "processing header");

		if(dc->header_type==DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE) {
			delzw_process_unixcompress_3byteheader(dc);
		}
		else if(dc->header_type==DELZW_HEADERTYPE_ARC1BYTE) {
			delzw_process_arc_1byteheader(dc);
		}
	}

	delzw_debugmsg(dc, 2, "start of codes");

	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		dc->min_codesize = 9;
	}
	else if(dc->basefmt==DELZW_BASEFMT_GIF) {
		dc->auto_inc_codesize = 1;
		dc->min_codesize = dc->gif_root_codesize + 1;
		dc->max_codesize = 12;
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		dc->min_codesize = 9;
		dc->max_codesize = 13;
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZOOLZD) {
		dc->min_codesize = 9;
		if(dc->max_codesize==0) {
			dc->max_codesize = 13;
		}
	}

	if(dc->min_codesize<DELZW_MINMINCODESIZE || dc->min_codesize>DELZW_MAXMAXCODESIZE ||
		dc->max_codesize<DELZW_MINMINCODESIZE || dc->max_codesize>DELZW_MAXMAXCODESIZE ||
		dc->min_codesize>dc->max_codesize)
	{
		delzw_set_errorf(dc, DELZW_ERRCODE_UNSUPPORTED_OPTION, "Unsupported code size (%u,%u)",
			dc->min_codesize, dc->max_codesize);
		goto done;
	}

	delzw_debugmsg(dc, 2, "code size: %u, max=%u", dc->min_codesize, dc->max_codesize);

	dc->curr_codesize = dc->min_codesize;

	dc->ct_capacity = ((DELZW_CODE)1)<<dc->max_codesize;
	dc->ct = de_mallocarray(dc->c, dc->ct_capacity, sizeof(struct delzw_tableentry));
	dc->valbuf_capacity = dc->ct_capacity;
	dc->valbuf = de_malloc(dc->c, dc->valbuf_capacity);

	if(dc->basefmt==DELZW_BASEFMT_UNIXCOMPRESS) {
		for(i=0; i<256; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (u8)i;
		}

		if(dc->unixcompress_has_clear_code) {
			dc->ct[256].codetype = DELZW_CODETYPE_CLEAR;
			dc->first_dynamic_code = 257;
		}
		else {
			dc->first_dynamic_code = 256;
		}
	}
	else if(dc->basefmt==DELZW_BASEFMT_GIF) {
		DELZW_CODE n = DELZW_NBITS_TO_NCODES(dc->gif_root_codesize);

		for(i=0; i<n; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (i<=255)?((u8)i):0;
		}
		dc->ct[n].codetype = DELZW_CODETYPE_CLEAR;
		dc->ct[n+1].codetype = DELZW_CODETYPE_STOP;
		dc->first_dynamic_code = n+2;
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZIPSHRINK) {
		dc->first_dynamic_code = 257;

		for(i=0; i<256; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (u8)i;
		}
		dc->ct[256].codetype = DELZW_CODETYPE_SPECIAL;
	}
	else if(dc->basefmt==DELZW_BASEFMT_ZOOLZD) {
		for(i=0; i<256; i++) {
			dc->ct[i].codetype = DELZW_CODETYPE_STATIC;
			dc->ct[i].value = (u8)i;
		}
		dc->ct[256].codetype = DELZW_CODETYPE_CLEAR;
		dc->ct[257].codetype = DELZW_CODETYPE_STOP;
		dc->first_dynamic_code = 258;
	}

	for(i=dc->first_dynamic_code; i<dc->ct_capacity; i++) {
		dc->ct[i].codetype = DELZW_CODETYPE_DYN_UNUSED;
	}

	dc->free_code_search_start = dc->first_dynamic_code;

done:
	;
}

static int delzw_have_enough_output(delzwctx *dc)
{
	if(dc->output_len_known) {
		if(dc->uncmpr_nbytes_written + (i64)dc->outbuf_nbytes_used >=
			dc->output_expected_len)
		{
			return 1;
		}
	}
	return 0;
}

static void delzw_process_byte(delzwctx *dc, u8 b)
{
	if(dc->state==DELZW_STATE_INIT) {
		delzw_on_decompression_start(dc);
		dc->state = DELZW_STATE_READING_HEADER;
	}

	if(dc->state==DELZW_STATE_READING_HEADER) {
		if(dc->total_nbytes_processed < dc->header_size) {
			dc->header_buf[dc->total_nbytes_processed] = b;
			return;
		}

		// (This is the first byte after the header.)
		delzw_on_codes_start(dc);
		dc->state = DELZW_STATE_READING_CODES;
	}

	if(dc->state==DELZW_STATE_READING_CODES) {
		if(dc->nbytes_left_to_skip>0) {
			dc->nbytes_left_to_skip--;
			return;
		}

		delzw_add_byte_to_bitbuf(dc, b);

		while(1) {
			DELZW_CODE code;

			if(dc->errcode) break;
			if(dc->bitreader_nbits_in_buf < dc->curr_codesize) {
				break;
			}

			code = delzw_get_code(dc, dc->curr_codesize);
			dc->ncodes_in_this_bitgroup++;
			delzw_process_code(dc, code);

			if(dc->state != DELZW_STATE_READING_CODES) {
				break;
			}
			if(dc->nbytes_left_to_skip>0) {
				break;
			}
		}
	}
}

static void delzw_addbuf(delzwctx *dc, const u8 *buf, size_t buf_len)
{
	size_t i;

	if(dc->debug_level>=3) {
		delzw_debugmsg(dc, 3, "received %d bytes of input", (int)buf_len);
	}

	for(i=0; i<buf_len; i++) {
		if(dc->errcode) break;
		if(dc->state == DELZW_STATE_FINISHED) break;
		if(delzw_have_enough_output(dc)) {
			delzw_stop(dc, "sufficient output");
			break;
		}
		delzw_process_byte(dc, buf[i]);
		dc->total_nbytes_processed++;
	}
}

static void delzw_finish(delzwctx *dc)
{
	const char *reason;

	delzw_flush(dc);

	if(dc->output_len_known && (dc->uncmpr_nbytes_decoded==dc->output_expected_len)) {
		reason = "end of input and sufficient output";
	}
	else {
		reason = "end of input";
	}

	delzw_stop(dc, reason);
}

///////////////////////////////////////////////////

static void setup_delzw_common(deark *c, delzwctx *dc, struct delzw_params *delzwp)
{
	dc->debug_level = c->debug_level;

	if(delzwp->fmt==DE_LZWFMT_UNIXCOMPRESS) {
		dc->basefmt = DELZW_BASEFMT_UNIXCOMPRESS;
		dc->auto_inc_codesize = 1;
		if(delzwp->unixcompress_flags & DE_LIBLZWFLAG_HAS3BYTEHEADER) {
			dc->header_type = DELZW_HEADERTYPE_UNIXCOMPRESS3BYTE;
		}
		else if(delzwp->unixcompress_flags & DE_LIBLZWFLAG_HAS1BYTEHEADER) {
			dc->header_type = DELZW_HEADERTYPE_ARC1BYTE;
		}
		else {
			dc->unixcompress_has_clear_code = 1;
			dc->max_codesize = (delzwp->unixcompress_lzwmode & 0x1f);
		}

		if((delzwp->unixcompress_flags & DE_LIBLZWFLAG_ARCFSMODE) &&
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

static size_t wrapped_dfctx_write_cb(delzwctx *dc, const u8 *buf, size_t size,
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

// codec_private_params is type struct delzw_params.
void dfilter_lzw_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	delzwctx *dc = NULL;
	struct delzw_params *delzwp = (struct delzw_params*)codec_private_params;

	dc = delzw_create(dfctx->c, (void*)dfctx);
	if(!dc) goto done;
	dfctx->codec_private = (void*)dc;
	dfctx->codec_finish_fn = my_lzw_codec_finish;
	dfctx->codec_destroy_fn = my_lzw_codec_destroy;
	dfctx->codec_addbuf_fn = my_lzw_codec_addbuf;

	dc->cb_write = wrapped_dfctx_write_cb;
	dc->cb_debugmsg = wrapped_dfctx_debugmsg;
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

// Semi-deprecated function. Maybe should be renamed and redesigned.
void de_fmtutil_decompress_liblzw_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, u8 lzwmode)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.unixcompress_flags = flags;
	delzwp.unixcompress_lzwmode = lzwmode;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}
