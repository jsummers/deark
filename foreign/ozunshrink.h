// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.
// (This file might soon be converted to an independent library.)
//
// ZIP "shrink" decompression

#ifndef OZUS_UINT8
#define OZUS_UINT8   unsigned char
#endif
#ifndef OZUS_UINT16
#define OZUS_UINT16  uint16_t
#endif
#ifndef OZUS_OFF_T
#define OZUS_OFF_T   off_t
#endif
#ifndef OZUS_CALLOC
#define OZUS_CALLOC(u, nmemb, size, ty) (ty)calloc((nmemb), (size))
#endif
#ifndef OZUS_FREE
#define OZUS_FREE(u, ptr) free(ptr)
#endif

#define OZUS_ERRCODE_OK             0
#define OZUS_ERRCODE_GENERIC_ERROR  1
#define OZUS_ERRCODE_BAD_CDATA      2
#define OZUS_ERRCODE_MALLOC_FAILED  3
#define OZUS_ERRCODE_READ_FAILED    6
#define OZUS_ERRCODE_WRITE_FAILED   7
#define OZUS_ERRCODE_INSUFFICIENT_CDATA 8

typedef OZUS_UINT16 OZUS_CODE;

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
	deark *c;
	OZUS_OFF_T cmpr_size; // compressed size
	OZUS_OFF_T uncmpr_size; // reported uncompressed size
	ozus_cb_read_type cb_read;
	ozus_cb_write_type cb_write;

	// Fields the user can read:
	int error_code;
	OZUS_OFF_T cmpr_nbytes_consumed;
	OZUS_OFF_T uncmpr_nbytes_written;

	// Fields private to the library:
	int have_oldcode;
	OZUS_CODE oldcode;
	OZUS_CODE last_code_added;
	OZUS_CODE free_code_search_start;
	OZUS_UINT8 last_value;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	unsigned int initial_code_size;
	unsigned int max_code_size;
	OZUS_CODE ct_arraysize;
	struct ozus_tableentry *ct;
	dbuf *tmpbuf;
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

	ozus->initial_code_size = 9;
	ozus->max_code_size = 13;

	ozus->ct_arraysize = ((size_t)1)<<ozus->max_code_size;
	ozus->ct = OZUS_CALLOC(ozus->userdata, ozus->ct_arraysize, sizeof(struct ozus_tableentry),
		struct ozus_tableentry*);
	if(!ozus->ct) {
		ozus_set_error(ozus, OZUS_ERRCODE_MALLOC_FAILED);
		return;
	}

	for(i=0; i<256; i++) {
		ozus->ct[i].parent = OZUS_INVALID_CODE;
		ozus->ct[i].value = (OZUS_UINT8)i;
	}
	for(i=256; i<ozus->ct_arraysize; i++) {
		ozus->ct[i].parent = OZUS_INVALID_CODE;
	}

	ozus->free_code_search_start = 257;
	ozus->tmpbuf = dbuf_create_membuf(ozus->c, 0, 0);
}

static ozus_ctx *ozus_create(deark *c, void *userdata)
{
	ozus_ctx *ozus;

	ozus = OZUS_CALLOC(userdata, 1, sizeof(ozus_ctx), ozus_ctx*);
	if(!ozus) return NULL;
	ozus->userdata = userdata;
	ozus->c = c;
	return ozus;
}

static void ozus_destroy(ozus_ctx *ozus)
{
	if(!ozus) return;
	dbuf_close(ozus->tmpbuf);
	OZUS_FREE(ozus->userdata, ozus->ct);
	OZUS_FREE(ozus->userdata, ozus);
}

static OZUS_UINT8 ozus_nextbyte(ozus_ctx *ozus)
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

static OZUS_CODE ozus_bitreader_getbits(ozus_ctx *ozus, unsigned int nbits)
{
	unsigned int n;

	if(nbits<1 || nbits>ozus->max_code_size) return 0;

	while(ozus->bitreader_nbits_in_buf < nbits) {
		OZUS_UINT8 b;

		b = ozus_nextbyte(ozus);
		if(ozus->error_code) return 0;
		ozus->bitreader_buf |= ((unsigned int)b)<<ozus->bitreader_nbits_in_buf;
		ozus->bitreader_nbits_in_buf += 8;
	}

	n = (ozus->bitreader_buf & (0xffff >> (16-nbits)));
	ozus->bitreader_buf >>= nbits;
	ozus->bitreader_nbits_in_buf -= nbits;
	return (OZUS_CODE)n;
}

static void ozus_writebyte(ozus_ctx *ozus, OZUS_UINT8 b)
{
	size_t ret;

	if(ozus->error_code) return;
	if(ozus->uncmpr_nbytes_written >= ozus->uncmpr_size) return;
	ret = ozus->cb_write(ozus, &b, 1);
	if(ret != 1) {
		ozus_set_error(ozus, OZUS_ERRCODE_WRITE_FAILED);
		return;
	}
	ozus->uncmpr_nbytes_written++;
}

// Decode an LZW code to one or more values, and write the values.
// Updates ctx->last_value.
static void ozus_emit_code(ozus_ctx *ozus, OZUS_CODE code1)
{
	OZUS_CODE code = code1;
	OZUS_CODE count = 0;
	i64 k;

	// Use a temp buffer, because we have to reverse the order of the bytes
	// before writing them.
	dbuf_truncate(ozus->tmpbuf, 0);

	while(1) {
		if(code >= ozus->ct_arraysize) {
			ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
			return;
		}

		dbuf_writebyte(ozus->tmpbuf, ozus->ct[code].value);

		count++;
		if(count >= ozus->ct_arraysize) {
			// Max possible chain length is less than this.
			// We must be in an infinite loop (probably an internal error).
			ozus_set_error(ozus, OZUS_ERRCODE_GENERIC_ERROR);
			return;
		}

		if(code < 257) {
			ozus->last_value = ozus->ct[code].value;
			break;
		}

		// Traverse the tree, back toward the root codes.
		code = ozus->ct[code].parent;
	}

	// Write out the collected values, in reverse order.
	for(k=ozus->tmpbuf->len-1; k>=0; k--) {
		ozus_writebyte(ozus, dbuf_getbyte(ozus->tmpbuf, k));
	}
}

static void ozus_find_first_free_entry(ozus_ctx *ozus, OZUS_CODE *pentry)
{
	OZUS_CODE k;

	for(k=ozus->free_code_search_start; k<ozus->ct_arraysize; k++) {
		if(ozus->ct[k].parent==OZUS_INVALID_CODE) {
			*pentry = k;
			return;
		}
	}

	*pentry = ozus->ct_arraysize-1;
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
	if(code >= ozus->ct_arraysize) {
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

	for(i=257; i<ozus->ct_arraysize; i++) {
		if(ozus->ct[i].parent!=OZUS_INVALID_CODE) {
			ozus->ct[ozus->ct[i].parent].flags = 1; // Mark codes that have a child
		}
	}

	for(i=257; i<ozus->ct_arraysize; i++) {
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
	unsigned int curr_code_size;

	ozus_init(ozus);
	if(ozus->error_code) goto done;

	curr_code_size = ozus->initial_code_size;

	while(1) {
		if(ozus->uncmpr_nbytes_written >= ozus->uncmpr_size) {
			goto done; // Have enough output data.
		}

		code = ozus_bitreader_getbits(ozus, curr_code_size);
		if(ozus->error_code) goto done;

		if(code==256) {
			OZUS_CODE n;

			n = ozus_bitreader_getbits(ozus, curr_code_size);
			if(ozus->error_code) goto done;

			if(n==1 && (curr_code_size<ozus->max_code_size)) {
				curr_code_size++;
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
