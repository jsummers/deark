// Old ZIP Unreduce - Decompressor for "Reduce" compression
//
// This file is part of Deark (for now, at least).
// Copyright (C) 2019 Jason Summers
// See Deark's main COPYING file for terms of use.

struct unreduce_follower_item {
	unsigned int count; // N - 0<=count<=32
	unsigned int nbits; // B(N) - Valid if count>0
	u8 values[32]; // S - First 'count' values are valid
};

struct unreducectx_type;
typedef size_t (*unr_cb_read_type)(struct unreducectx_type *rdctx, u8 *buf, size_t size);
typedef size_t (*unr_cb_write_type)(struct unreducectx_type *rdctx, const u8 *buf, size_t size);
typedef void (*unr_cb_post_follower_sets_type)(struct unreducectx_type *rdctx);

struct unreducectx_type {
	void *userdata;
	int cmpr_factor;
#define UNREDUCE_ERRCODE_OK             0
#define UNREDUCE_ERRCODE_GENERIC_ERROR  1
#define UNREDUCE_ERRCODE_BAD_CDATA      2
#define UNREDUCE_ERRCODE_READ_FAILED    6
#define UNREDUCE_ERRCODE_WRITE_FAILED   7
#define UNREDUCE_ERRCODE_INSUFFICIENT_CDATA 8
	int error_code;
	i64 uncmpr_size;
	unr_cb_read_type cb_read;
	unr_cb_write_type cb_write;
	unr_cb_post_follower_sets_type cb_post_follower_sets; // Optional hook

	i64 cmpr_size;
	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;

	u8 last_char;
	int state;
	u8 var_V;
	i64 var_Len;
	i64 uncmpr_nbytes_emitted; // (Number of output bytes decoded, not necessarily flushed.)
	i64 cmpr_nbytes_consumed;

	struct unreduce_follower_item followers[256];

	i64 circbuf_pos;
#define UNREDUCE_CIRCBUF_SIZE 4096 // Must be at least 4096
	u8 circbuf[UNREDUCE_CIRCBUF_SIZE];
};

static void unreduce_set_error(struct unreducectx_type *rdctx, int error_code)
{
	// Only record the first error.
	if (rdctx->error_code==0) {
		rdctx->error_code = error_code;
	}
}

static u8 unr_nextbyte(struct unreducectx_type *rdctx)
{
	u8 buf[1];
	size_t ret;

	if(rdctx->error_code) return 0;
	if(rdctx->cmpr_nbytes_consumed >= rdctx->cmpr_size) {
		unreduce_set_error(rdctx, UNREDUCE_ERRCODE_INSUFFICIENT_CDATA);
		return 0;
	}
	ret = rdctx->cb_read(rdctx, buf, 1);
	if(ret != 1) {
		unreduce_set_error(rdctx, UNREDUCE_ERRCODE_READ_FAILED);
		return 0;
	}
	rdctx->cmpr_nbytes_consumed++;
	return buf[0];
}

static u8 unreduce_bitreader_getbits(struct unreducectx_type *rdctx, unsigned int nbits)
{
	u8 n;

	if(nbits<1 || nbits>8) return 0;

	if(rdctx->bitreader_nbits_in_buf < nbits) {
		u8 b;

		b = unr_nextbyte(rdctx);
		if(rdctx->error_code) return 0;
		rdctx->bitreader_buf |= ((unsigned int)b)<<rdctx->bitreader_nbits_in_buf;
		rdctx->bitreader_nbits_in_buf += 8;
	}

	n = (u8)(rdctx->bitreader_buf & (0xff >> (8-nbits)));
	rdctx->bitreader_buf >>= nbits;
	rdctx->bitreader_nbits_in_buf -= nbits;
	return n;
}

// "the minimal number of bits required to encode the value of x-1".
// Assumes 1 <= x <= 32.
static unsigned int unreduce_func_B(struct unreducectx_type *rdctx, unsigned int x)
{
	if(x<=2) return 1;
	if(x<=4) return 2;
	if(x<=8) return 3;
	if(x<=16) return 4;
	return 5;
}

static void unreduce_part1_readfollowersets(struct unreducectx_type *rdctx)
{
	int k;

	for(k=255; k>=0; k--) {
		unsigned int z;
		struct unreduce_follower_item *f_i;

		f_i = &rdctx->followers[k];

		f_i->count = (unsigned int)unreduce_bitreader_getbits(rdctx, 6);
		if(rdctx->error_code) goto done;
		if(f_i->count>32) {
			unreduce_set_error(rdctx, UNREDUCE_ERRCODE_BAD_CDATA);
			goto done;
		}

		if(f_i->count > 0) {
			f_i->nbits = unreduce_func_B(rdctx, f_i->count);
		}

		for(z=0; z<f_i->count; z++) {
			f_i->values[z] = unreduce_bitreader_getbits(rdctx, 8);
			if(rdctx->error_code) goto done;
		}
	}
done:
	;
}

static u8 unreduce_part1_getnextbyte(struct unreducectx_type *rdctx)
{
	u8 outbyte = 0;
	struct unreduce_follower_item *f_i;

	f_i = &rdctx->followers[(unsigned int)rdctx->last_char];

	if(f_i->count==0) { // Follower set is empty
		outbyte = unreduce_bitreader_getbits(rdctx, 8);
	}
	else { // Follower set not empty
		u8 bitval;

		bitval = unreduce_bitreader_getbits(rdctx, 1);
		if(bitval) {
			outbyte = unreduce_bitreader_getbits(rdctx, 8);
		}
		else {
			unsigned int var_I;

			var_I = (unsigned int)unreduce_bitreader_getbits(rdctx, f_i->nbits);
			outbyte = f_i->values[var_I];
		}
	}

	rdctx->last_char = outbyte;
	return outbyte;
}

// Write the bytes in the circular buffer, up to the current position.
// Does not change the state of the buffer.
// This must only be called just before setting the buffer pos to 0,
// or at the end of input.
static void unreduce_flush(struct unreducectx_type *rdctx)
{
	size_t ret;
	size_t n;

	if(rdctx->error_code) return;
	if(rdctx->circbuf_pos<1) return;
	n = (size_t)rdctx->circbuf_pos;
	ret = rdctx->cb_write(rdctx, rdctx->circbuf, n);
	if(ret != n) {
		unreduce_set_error(rdctx, UNREDUCE_ERRCODE_WRITE_FAILED);
	}
}

static void unreduce_emit_byte(struct unreducectx_type *rdctx, u8 x)
{
	rdctx->circbuf[rdctx->circbuf_pos++] = x;
	if(rdctx->circbuf_pos >= UNREDUCE_CIRCBUF_SIZE) {
		unreduce_flush(rdctx);
		rdctx->circbuf_pos = 0;
	}
	rdctx->uncmpr_nbytes_emitted++;
}

static void unreduce_emit_copy_of_prev_bytes(struct unreducectx_type *rdctx,
	i64 nbytes_to_look_back, i64 nbytes)
{
	i64 i;
	i64 src_pos;

	// Maximum possible is (255>>4)*255 + 255 + 1 = 4096
	if(nbytes_to_look_back<0 || nbytes_to_look_back>4096) {
		unreduce_set_error(rdctx, UNREDUCE_ERRCODE_GENERIC_ERROR);
		return;
	}
	// Maximum possible is 255 + 127 + 3 = 385
	if(nbytes<0 || nbytes>nbytes_to_look_back) {
		unreduce_set_error(rdctx, UNREDUCE_ERRCODE_BAD_CDATA);
		return;
	}

	src_pos = (rdctx->circbuf_pos + UNREDUCE_CIRCBUF_SIZE - nbytes_to_look_back) %
		UNREDUCE_CIRCBUF_SIZE;

	for(i=0; i<nbytes; i++) {
		unreduce_emit_byte(rdctx, rdctx->circbuf[src_pos++]);
		if(src_pos >= UNREDUCE_CIRCBUF_SIZE) {
			src_pos = 0;
		}
	}
}

// Process one byte of output from part 1.
static void unreduce_part2(struct unreducectx_type *rdctx, u8 var_C)
{
	i64 nbytes_to_look_back;
	i64 nbytes_to_copy;

	switch(rdctx->state) {
	case 0:
		if(var_C==144) {
			rdctx->state = 1;
		}
		else {
			unreduce_emit_byte(rdctx, var_C);
		}
		break;

	case 1:
		if(var_C) {
			rdctx->var_V = var_C;
			rdctx->var_Len = (i64)(rdctx->var_V & (0xff>>rdctx->cmpr_factor));
			rdctx->state = (rdctx->var_Len==(i64)(0xff>>rdctx->cmpr_factor)) ? 2 : 3; // F()
		}
		else {
			unreduce_emit_byte(rdctx, 144);
			rdctx->state = 0;
		}
		break;

	case 2:
		rdctx->var_Len += (i64)var_C;
		rdctx->state = 3;
		break;

	case 3:
		nbytes_to_look_back = (i64)(rdctx->var_V>>(8-rdctx->cmpr_factor)) * 256 + (i64)var_C + 1; // D()
		nbytes_to_copy = rdctx->var_Len + 3;
		unreduce_emit_copy_of_prev_bytes(rdctx, nbytes_to_look_back, nbytes_to_copy);
		rdctx->state = 0;
		break;
	}
}

static void unreduce_run(struct unreducectx_type *rdctx)
{
	// Part 1 is undoing the "probabilistic" compression.
	// It starts with a header, then we'll decompress 1 byte at a time.
	unreduce_part1_readfollowersets(rdctx);
	if(rdctx->error_code) goto done;

	if(rdctx->cb_post_follower_sets) {
		rdctx->cb_post_follower_sets(rdctx);
	}

	while(1) {
		u8 outbyte;

		if(rdctx->error_code) goto done;
		if(rdctx->uncmpr_nbytes_emitted >= rdctx->uncmpr_size) break; // Have enough output data

		outbyte = unreduce_part1_getnextbyte(rdctx);
		if(rdctx->error_code) goto done;

		// Part 2 is undoing "compress repeated byte sequences" --
		// apparently a kind of LZ77.
		unreduce_part2(rdctx, outbyte);
	}

done:
	unreduce_flush(rdctx);
}
