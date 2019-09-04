// Old ZIP Unreduce - Decompressor for "Reduce" compression
//
// This file is part of Deark (for now, at least).
// Copyright (C) 2019 Jason Summers
// See Deark's main COPYING file for terms of use.

#define OZUR_UINT8    u8
#define OZUR_OFF_T    i64

#define OZUR_ERRCODE_OK             0
#define OZUR_ERRCODE_GENERIC_ERROR  1
#define OZUR_ERRCODE_BAD_CDATA      2
#define OZUR_ERRCODE_READ_FAILED    6
#define OZUR_ERRCODE_WRITE_FAILED   7
#define OZUR_ERRCODE_INSUFFICIENT_CDATA 8

struct ozur_follower_item {
	unsigned int count; // N - 0<=count<=32
	unsigned int nbits; // B(N) - Valid if count>0
	u8 values[32]; // S - First 'count' values are valid
};

struct ozur_ctx_type;
typedef struct ozur_ctx_type ozur_ctx;
typedef size_t (*ozur_cb_read_type)(ozur_ctx *ozur, OZUR_UINT8 *buf, size_t size);
typedef size_t (*ozur_cb_write_type)(ozur_ctx *ozur, const OZUR_UINT8 *buf, size_t size);
typedef void (*ozur_cb_post_follower_sets_type)(ozur_ctx *ozur);

struct ozur_ctx_type {
	// Fields the user can or must set:
	void *userdata;
	int cmpr_factor;
	OZUR_OFF_T cmpr_size;
	OZUR_OFF_T uncmpr_size;
	ozur_cb_read_type cb_read;
	ozur_cb_write_type cb_write;
	ozur_cb_post_follower_sets_type cb_post_follower_sets; // Optional hook

	// Fields the user can read:
	int error_code;
	OZUR_OFF_T uncmpr_nbytes_written;
	OZUR_OFF_T cmpr_nbytes_consumed;

	// Fields private to the library:
	OZUR_OFF_T cmpr_nbytes_read; // (Number of bytes read, not necessarily consumed.)
	OZUR_OFF_T uncmpr_nbytes_emitted; // (Number of output bytes decoded, not necessarily flushed.)
	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;
	int state;
	unsigned int var_Len;
	OZUR_UINT8 last_char;
	OZUR_UINT8 var_V;
	struct ozur_follower_item followers[256];
	size_t circbuf_pos;
#define OZUR_CIRCBUF_SIZE 4096 // Must be at least 4096
	OZUR_UINT8 circbuf[OZUR_CIRCBUF_SIZE];
	size_t inbuf_nbytes_consumed;
	size_t inbuf_nbytes_total;
#define OZUR_INBUF_SIZE 1024
	OZUR_UINT8 inbuf[OZUR_INBUF_SIZE];
};

static void ozur_set_error(ozur_ctx *ozur, int error_code)
{
	// Only record the first error.
	if (ozur->error_code==0) {
		ozur->error_code = error_code;
	}
}

static void ozur_refill_inbuf(ozur_ctx *ozur)
{
	size_t ret;
	size_t nbytes_to_read;

	ozur->inbuf_nbytes_total = 0;
	ozur->inbuf_nbytes_consumed = 0;

	nbytes_to_read = OZUR_INBUF_SIZE;
	if((ozur->cmpr_size - ozur->cmpr_nbytes_read) > OZUR_INBUF_SIZE) {
		nbytes_to_read = OZUR_INBUF_SIZE;
	}
	else {
		nbytes_to_read = (size_t)(ozur->cmpr_size - ozur->cmpr_nbytes_read);
	}
	if(nbytes_to_read<1 || nbytes_to_read>OZUR_INBUF_SIZE) return;

	ret = ozur->cb_read(ozur, ozur->inbuf, nbytes_to_read);
	if(ret != nbytes_to_read) {
		ozur_set_error(ozur, OZUR_ERRCODE_READ_FAILED);
		return;
	}
	ozur->inbuf_nbytes_total = nbytes_to_read;
}

static OZUR_UINT8 ozur_nextbyte(ozur_ctx *ozur)
{
	OZUR_UINT8 x;

	if(ozur->error_code) return 0;

	if(ozur->cmpr_nbytes_consumed >= ozur->cmpr_size) {
		ozur_set_error(ozur, OZUR_ERRCODE_INSUFFICIENT_CDATA);
		return 0;
	}
	// Another byte should be available, somewhere.
	if(ozur->inbuf_nbytes_consumed >= ozur->inbuf_nbytes_total) {
		// No bytes left in inbuf. Refill it.
		ozur_refill_inbuf(ozur);
		if(ozur->inbuf_nbytes_total<1) return 0;
	}

	x = ozur->inbuf[ozur->inbuf_nbytes_consumed++];
	ozur->cmpr_nbytes_consumed++;
	return x;
}

static OZUR_UINT8 ozur_bitreader_getbits(ozur_ctx *ozur, unsigned int nbits)
{
	OZUR_UINT8 n;

	if(nbits<1 || nbits>8) return 0;

	if(ozur->bitreader_nbits_in_buf < nbits) {
		OZUR_UINT8 b;

		b = ozur_nextbyte(ozur);
		if(ozur->error_code) return 0;
		ozur->bitreader_buf |= ((unsigned int)b)<<ozur->bitreader_nbits_in_buf;
		ozur->bitreader_nbits_in_buf += 8;
	}

	n = (OZUR_UINT8)(ozur->bitreader_buf & (0xff >> (8-nbits)));
	ozur->bitreader_buf >>= nbits;
	ozur->bitreader_nbits_in_buf -= nbits;
	return n;
}

// "the minimal number of bits required to encode the value of x-1".
// Assumes 1 <= x <= 32.
static unsigned int ozur_func_B(ozur_ctx *ozur, unsigned int x)
{
	if(x<=2) return 1;
	if(x<=4) return 2;
	if(x<=8) return 3;
	if(x<=16) return 4;
	return 5;
}

static void ozur_part1_readfollowersets(ozur_ctx *ozur)
{
	int k;

	for(k=255; k>=0; k--) {
		unsigned int z;
		struct ozur_follower_item *f_i;

		f_i = &ozur->followers[k];

		f_i->count = (unsigned int)ozur_bitreader_getbits(ozur, 6);
		if(ozur->error_code) goto done;
		if(f_i->count>32) {
			ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
			goto done;
		}

		if(f_i->count > 0) {
			f_i->nbits = ozur_func_B(ozur, f_i->count);
		}

		for(z=0; z<f_i->count; z++) {
			f_i->values[z] = ozur_bitreader_getbits(ozur, 8);
			if(ozur->error_code) goto done;
		}
	}
done:
	;
}

static OZUR_UINT8 ozur_part1_getnextbyte(ozur_ctx *ozur)
{
	OZUR_UINT8 outbyte = 0;
	struct ozur_follower_item *f_i;

	f_i = &ozur->followers[(unsigned int)ozur->last_char];

	if(f_i->count==0) { // Follower set is empty
		outbyte = ozur_bitreader_getbits(ozur, 8);
	}
	else { // Follower set not empty
		OZUR_UINT8 bitval;

		bitval = ozur_bitreader_getbits(ozur, 1);
		if(bitval) {
			outbyte = ozur_bitreader_getbits(ozur, 8);
		}
		else {
			unsigned int var_I;

			var_I = (unsigned int)ozur_bitreader_getbits(ozur, f_i->nbits);
			outbyte = f_i->values[var_I];
		}
	}

	ozur->last_char = outbyte;
	return outbyte;
}

// Write the bytes in the circular buffer, up to the current position.
// Does not change the state of the buffer.
// This must only be called just before setting the buffer pos to 0,
// or at the end of input.
static void ozur_flush(ozur_ctx *ozur)
{
	size_t ret;
	size_t n;

	if(ozur->error_code) return;
	n = ozur->circbuf_pos;
	if(n<1 || n>OZUR_CIRCBUF_SIZE) return;
	ret = ozur->cb_write(ozur, ozur->circbuf, n);
	if(ret != n) {
		ozur_set_error(ozur, OZUR_ERRCODE_WRITE_FAILED);
		return;
	}
	ozur->uncmpr_nbytes_written += (OZUR_OFF_T)ret;
}

static void ozur_emit_byte(ozur_ctx *ozur, OZUR_UINT8 x)
{
	ozur->circbuf[ozur->circbuf_pos++] = x;
	if(ozur->circbuf_pos >= OZUR_CIRCBUF_SIZE) {
		ozur_flush(ozur);
		ozur->circbuf_pos = 0;
	}
	ozur->uncmpr_nbytes_emitted++;
}

static void ozur_emit_copy_of_prev_bytes(ozur_ctx *ozur,
	size_t nbytes_to_look_back, size_t nbytes)
{
	size_t i;
	size_t src_pos;

	// Maximum possible is (255>>4)*255 + 255 + 1 = 4096
	if(nbytes_to_look_back>4096) {
		ozur_set_error(ozur, OZUR_ERRCODE_GENERIC_ERROR);
		return;
	}
	// Maximum possible is 255 + 127 + 3 = 385
	if(nbytes>nbytes_to_look_back) {
		ozur_set_error(ozur, OZUR_ERRCODE_BAD_CDATA);
		return;
	}

	src_pos = (ozur->circbuf_pos + OZUR_CIRCBUF_SIZE - nbytes_to_look_back) %
		OZUR_CIRCBUF_SIZE;

	for(i=0; i<nbytes; i++) {
		ozur_emit_byte(ozur, ozur->circbuf[src_pos++]);
		if(src_pos >= OZUR_CIRCBUF_SIZE) {
			src_pos = 0;
		}
	}
}

// Process one byte of output from part 1.
static void ozur_part2(ozur_ctx *ozur, OZUR_UINT8 var_C)
{
	size_t nbytes_to_look_back;
	size_t nbytes_to_copy;

	switch(ozur->state) {
	case 0:
		if(var_C==144) {
			ozur->state = 1;
		}
		else {
			ozur_emit_byte(ozur, var_C);
		}
		break;

	case 1:
		if(var_C) {
			ozur->var_V = var_C;
			ozur->var_Len = (unsigned int)(ozur->var_V & (0xff>>ozur->cmpr_factor));
			ozur->state = (ozur->var_Len==(unsigned int)(0xff>>ozur->cmpr_factor)) ? 2 : 3; // F()
		}
		else {
			ozur_emit_byte(ozur, 144);
			ozur->state = 0;
		}
		break;

	case 2:
		ozur->var_Len += (unsigned int)var_C;
		ozur->state = 3;
		break;

	case 3:
		nbytes_to_look_back = (size_t)(ozur->var_V>>(8-ozur->cmpr_factor)) * 256 + (size_t)var_C + 1; // D()
		nbytes_to_copy = (size_t)ozur->var_Len + 3;
		ozur_emit_copy_of_prev_bytes(ozur, nbytes_to_look_back, nbytes_to_copy);
		ozur->state = 0;
		break;
	}
}

static void ozur_run(ozur_ctx *ozur)
{
	// Part 1 is undoing the "probabilistic" compression.
	// It starts with a header, then we'll decompress 1 byte at a time.
	ozur_part1_readfollowersets(ozur);
	if(ozur->error_code) goto done;

	if(ozur->cb_post_follower_sets) {
		ozur->cb_post_follower_sets(ozur);
	}

	while(1) {
		OZUR_UINT8 outbyte;

		if(ozur->error_code) goto done;
		if(ozur->uncmpr_nbytes_emitted >= ozur->uncmpr_size) break; // Have enough output data

		outbyte = ozur_part1_getnextbyte(ozur);
		if(ozur->error_code) goto done;

		// Part 2 is undoing "compress repeated byte sequences" --
		// apparently a kind of LZ77.
		ozur_part2(ozur, outbyte);
	}

done:
	ozur_flush(ozur);
}
