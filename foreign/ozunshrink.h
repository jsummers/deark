// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.
// (This file might soon be converted to an independent library.)
//
// ZIP "shrink" decompression

#define OZUS_VERSION 20190000

#ifndef OZUS_UINT8
#define OZUS_UINT8   unsigned char
#endif
#ifndef OZUS_UINT16
#define OZUS_UINT16  uint16_t
#endif
#ifndef OZUS_OFF_T
#define OZUS_OFF_T   off_t
#endif

#define OZUS_ERRCODE_OK             0
#define OZUS_ERRCODE_GENERIC_ERROR  1
#define OZUS_ERRCODE_BAD_CDATA      2
#define OZUS_ERRCODE_READ_FAILED    6
#define OZUS_ERRCODE_WRITE_FAILED   7
#define OZUS_ERRCODE_INSUFFICIENT_CDATA 8

typedef OZUS_UINT16 OZUS_CODE;

#define OZUS_INITIAL_CODE_SIZE 9
#define OZUS_MAX_CODE_SIZE 13
#define OZUS_NUM_CODES 8192

// For entries <=256, .parent is always set to OZUS_INVALID_CODE.
// For entries >256, .parent==OZUS_INVALID_CODE means code is unused
#define OZUS_INVALID_CODE 256

struct ozus_tableentry {
	OZUS_CODE parent; // pointer to previous table entry (if not a root code)
	OZUS_UINT8 value;
	OZUS_UINT8 flags;
};

struct ozus_ctx_type;
typedef struct ozus_ctx_type ozus_ctx;

typedef size_t (*ozus_cb_read_type)(ozus_ctx *ozus, OZUS_UINT8 *buf, size_t size);
typedef size_t (*ozus_cb_write_type)(ozus_ctx *ozus, const OZUS_UINT8 *buf, size_t size);

struct ozus_ctx_type {
	// Fields the user can or must set:
	void *userdata;
	OZUS_OFF_T cmpr_size; // compressed size
	OZUS_OFF_T uncmpr_size; // reported uncompressed size
	ozus_cb_read_type cb_read;
	ozus_cb_write_type cb_write;

	// Fields the user can read:
	int error_code;
	OZUS_OFF_T cmpr_nbytes_consumed;
	OZUS_OFF_T uncmpr_nbytes_written;

	// Fields private to the library:
	unsigned int curr_code_size;
	int have_oldcode;
	OZUS_CODE oldcode;
	OZUS_CODE last_code_added;
	OZUS_CODE free_code_search_start;
	OZUS_UINT8 last_value;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	struct ozus_tableentry ct[OZUS_NUM_CODES];

// Need room for the max possible chain length, which I calculate to be
// 8192 - 257 + 1 = 7936.
#define OZUS_VALBUFSIZE 7936
	OZUS_UINT8 valbuf[OZUS_VALBUFSIZE];
};

static void ozus_set_error(ozus_ctx *ozus, int error_code)
{
	// Only record the first error.
	if (ozus->error_code == OZUS_ERRCODE_OK) {
		ozus->error_code = error_code;
	}
}

static void ozus_init(ozus_ctx *ozus)
{
	OZUS_CODE i;

	for(i=0; i<256; i++) {
		ozus->ct[i].parent = OZUS_INVALID_CODE;
		ozus->ct[i].value = (OZUS_UINT8)i;
	}
	for(i=256; i<OZUS_NUM_CODES; i++) {
		ozus->ct[i].parent = OZUS_INVALID_CODE;
	}

	ozus->free_code_search_start = 257;
}

// TODO: Buffering
static OZUS_UINT8 ozus_getnextbyte(ozus_ctx *ozus)
{
	size_t ret;
	OZUS_UINT8 b;

	if(ozus->error_code) return 0;
	if(ozus->cmpr_nbytes_consumed >= ozus->cmpr_size) {
		ozus_set_error(ozus, OZUS_ERRCODE_INSUFFICIENT_CDATA);
		return 0;
	}
	ret = ozus->cb_read(ozus, &b, 1);
	if(ret != 1) {
		ozus_set_error(ozus, OZUS_ERRCODE_READ_FAILED);
		return 0;
	}
	ozus->cmpr_nbytes_consumed++;
	return b;
}

static OZUS_CODE ozus_getnextcode(ozus_ctx *ozus)
{
	unsigned int nbits = ozus->curr_code_size;
	unsigned int n;

	while(ozus->bitreader_nbits_in_buf < nbits) {
		OZUS_UINT8 b;

		b = ozus_getnextbyte(ozus);
		if(ozus->error_code) return 0;
		ozus->bitreader_buf |= ((unsigned int)b)<<ozus->bitreader_nbits_in_buf;
		ozus->bitreader_nbits_in_buf += 8;
	}

	n = ozus->bitreader_buf & ((1U<<nbits)-1U);
	ozus->bitreader_buf >>= nbits;
	ozus->bitreader_nbits_in_buf -= nbits;
	return (OZUS_CODE)n;
}

// TODO: Buffering
static void ozus_write(ozus_ctx *ozus, const OZUS_UINT8 *buf, size_t n)
{
	size_t ret;

	if(ozus->error_code) return;
	if(ozus->uncmpr_nbytes_written + (OZUS_OFF_T)n > ozus->uncmpr_size) {
		n = ozus->uncmpr_size - ozus->uncmpr_nbytes_written;
	}
	if(n==0) return;
	ret = ozus->cb_write(ozus, buf, n);
	if(ret != n) {
		ozus_set_error(ozus, OZUS_ERRCODE_WRITE_FAILED);
		return;
	}
	ozus->uncmpr_nbytes_written += n;
}

// Decode an LZW code to one or more values, and write the values.
// Updates ctx->last_value.
static void ozus_emit_code(ozus_ctx *ozus, OZUS_CODE code1)
{
	OZUS_CODE code = code1;
	size_t valbuf_pos = OZUS_VALBUFSIZE; // = First entry that's used

	while(1) {
		if(code >= OZUS_NUM_CODES) {
			ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
			return;
		}

		if(valbuf_pos==0) {
			// We must be in an infinite loop (probably an internal error).
			ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
			return;
		}

		// valbuf is a stack, essentially. We fill it in the reverse direction,
		// to make it simpler to write the final byte sequence.
		valbuf_pos--;
		ozus->valbuf[valbuf_pos] = ozus->ct[code].value;

		if(code < 257) {
			ozus->last_value = ozus->ct[code].value;
			break;
		}

		// Traverse the tree, back toward the root codes.
		code = ozus->ct[code].parent;
	}

	// Write out the collected values.
	ozus_write(ozus, &ozus->valbuf[valbuf_pos], OZUS_VALBUFSIZE - valbuf_pos);
}

static void ozus_find_first_free_entry(ozus_ctx *ozus, OZUS_CODE *pentry)
{
	OZUS_CODE k;

	for(k=ozus->free_code_search_start; k<OZUS_NUM_CODES; k++) {
		if(ozus->ct[k].parent==OZUS_INVALID_CODE) {
			*pentry = k;
			return;
		}
	}

	*pentry = OZUS_NUM_CODES-1;
	ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
}

// Add a code to the dictionary.
// Sets ozus->last_code_added to the position where it was added.
static void ozus_add_to_dict(ozus_ctx *ozus, OZUS_CODE parent, OZUS_UINT8 value)
{
	OZUS_CODE newpos;

	ozus_find_first_free_entry(ozus, &newpos);
	if(ozus->error_code) return;

	ozus->ct[newpos].parent = parent;
	ozus->ct[newpos].value = value;
	ozus->last_code_added = newpos;
	ozus->free_code_search_start = newpos+1;
}

// Process a single (nonspecial) LZW code that was read from the input stream.
static void ozus_process_data_code(ozus_ctx *ozus, OZUS_CODE code)
{
	if(code >= OZUS_NUM_CODES) {
		ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
		return;
	}

	if(!ozus->have_oldcode) {
		// Special case for the first code.
		ozus_emit_code(ozus, code);
		ozus->oldcode = code;
		ozus->have_oldcode = 1;
		ozus->last_value = (OZUS_UINT8)ozus->oldcode;
		return;
	}

	// Is code in code table?
	if(code<256 || ozus->ct[code].parent!=OZUS_INVALID_CODE) {
		// Yes, code is in table.
		ozus_emit_code(ozus, code);
		if(ozus->error_code) return;

		// Let k = the first character of the translation of the code.
		// Add <oldcode>k to the dictionary.
		ozus_add_to_dict(ozus, ozus->oldcode, ozus->last_value);
	}
	else {
		// No, code is not in table.
		// Let k = the first char of the translation of oldcode.
		// Add <oldcode>k to the dictionary.
		ozus_add_to_dict(ozus, ozus->oldcode, ozus->last_value);
		if(ozus->error_code) return;

		// Write <oldcode>k to the output stream.
		ozus_emit_code(ozus, ozus->last_code_added);
	}

	ozus->oldcode = code;
}

static void ozus_partial_clear(ozus_ctx *ozus)
{
	OZUS_CODE i;

	for(i=257; i<OZUS_NUM_CODES; i++) {
		if(ozus->ct[i].parent!=OZUS_INVALID_CODE) {
			ozus->ct[ozus->ct[i].parent].flags = 1; // Mark codes that have a child
		}
	}

	for(i=257; i<OZUS_NUM_CODES; i++) {
		if(ozus->ct[i].flags == 0) {
			ozus->ct[i].parent = OZUS_INVALID_CODE; // Clear this code
			ozus->ct[i].value = 0;
		}
		else {
			ozus->ct[i].flags = 0; // Leave all flags at 0, for next time.
		}
	}

	ozus->free_code_search_start = 257;
}

static void ozus_run(ozus_ctx *ozus)
{
	OZUS_CODE code;

	ozus_init(ozus);
	if(ozus->error_code) goto done;

	ozus->curr_code_size = OZUS_INITIAL_CODE_SIZE;

	while(1) {
		if(ozus->uncmpr_nbytes_written >= ozus->uncmpr_size) {
			goto done; // Have enough output data.
		}

		code = ozus_getnextcode(ozus);
		if(ozus->error_code) goto done;

		if(code==256) {
			OZUS_CODE n;

			n = ozus_getnextcode(ozus);
			if(ozus->error_code) goto done;

			if(n==1 && (ozus->curr_code_size<OZUS_MAX_CODE_SIZE)) {
				ozus->curr_code_size++;
			}
			else if(n==2) {
				ozus_partial_clear(ozus);
			}
			else {
				ozus_set_error(ozus, OZUS_ERRCODE_BAD_CDATA);
				goto done;
			}

		}
		else {
			ozus_process_data_code(ozus, code);
			if(ozus->error_code) goto done;
		}
	}

done:
	;
}
