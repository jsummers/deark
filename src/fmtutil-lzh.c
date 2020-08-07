// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Decompressor for some LZH formats

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

struct de_lz77buffer;
typedef void (*fmtutil_lz77buffer_cb_type)(struct de_lz77buffer *rb, const u8 *buf, i64 buf_len);

struct de_lz77buffer {
	void *userdata;
	fmtutil_lz77buffer_cb_type write_cb;
	UI curpos; // Must be kept valid at all times (0...bufsize-1)

	UI mask;
	UI bufsize; // Required to be a power of 2
	u8 *buf;
};

struct lzh_tree_wrapper {
	struct fmtutil_huffman_tree *ht;
	UI null_val; // Used if ht==NULL
};

struct lzh_ctx {
	deark *c;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	const char *modname;

	i64 curpos;
	i64 endpos;
	int eof_flag; // Always set if err_flag is set.
	int err_flag;

	u64 bit_buf;
	UI nbits_in_bitbuf;

	struct de_lz77buffer *ringbuf;
	struct lzh_tree_wrapper codelengths_tree;
	struct lzh_tree_wrapper codes_tree;
	struct lzh_tree_wrapper offsets_tree;
};

static void lzh_set_eof_flag(struct lzh_ctx *cctx)
{
	cctx->eof_flag = 1;
}

static void lzh_set_err_flag(struct lzh_ctx *cctx)
{
	lzh_set_eof_flag(cctx);
	cctx->err_flag = 1;
}

static struct de_lz77buffer *de_lz77buffer_create(deark *c, UI bufsize)
{
	struct de_lz77buffer *rb;

	rb = de_malloc(c, sizeof(struct de_lz77buffer));
	rb->buf = de_malloc(c, (i64)bufsize);
	rb->bufsize = bufsize;
	rb->mask = bufsize - 1;
	return rb;
}

static void de_lz77buffer_destroy(deark *c, struct de_lz77buffer *rb)
{
	if(!rb) return;
	de_free(c, rb->buf);
	de_free(c, rb);
}

// Set all bytes to the same value, and reset the current position to 0.
static void de_lz77buffer_clear(struct de_lz77buffer *rb, UI val)
{
	de_memset(rb->buf, val, rb->bufsize);
	rb->curpos = 0;
}

static void de_lz77buffer_addbyte(struct de_lz77buffer *rb, u8 b)
{
	rb->write_cb(rb, &b, 1);
	rb->buf[rb->curpos] = b;
	rb->curpos = (rb->curpos+1) & rb->mask;
}

static void de_lz77buffer_copy_and_write(struct de_lz77buffer *rb,
	UI startpos, UI count, dbuf *outf)
{
	UI frompos;
	UI i;

	frompos = startpos & rb->mask;
	// TODO: This could be done more efficiently
	for(i=0; i<count; i++) {
		de_lz77buffer_addbyte(rb, rb->buf[frompos]);
		frompos = (frompos+1) & rb->mask;
	}
}

static void lzh_add_byte_to_bitbuf(struct lzh_ctx *cctx, u8 n)
{
	cctx->bit_buf = (cctx->bit_buf<<8) | n;
	cctx->nbits_in_bitbuf += 8;
}

static u64 lzh_getbits(struct lzh_ctx *cctx, UI nbits)
{
	u64 n;

	if(cctx->eof_flag) return 0;
	if(nbits > 48) {
		lzh_set_err_flag(cctx);
		return 0;
	}

	while(cctx->nbits_in_bitbuf < nbits) {
		u8 b;

		if(cctx->curpos >= cctx->endpos) {
			lzh_set_eof_flag(cctx);
			return 0;
		}
		b = dbuf_getbyte_p(cctx->dcmpri->f, &cctx->curpos);
		lzh_add_byte_to_bitbuf(cctx, b);
	}

	cctx->nbits_in_bitbuf -= nbits;
	n = cctx->bit_buf >> cctx->nbits_in_bitbuf;
	cctx->bit_buf &= ((u64)1 << cctx->nbits_in_bitbuf)-1;
	return n;
}

static UI lh5x_read_a_code_length(struct lzh_ctx *cctx)
{
	UI n;

	n = (UI)lzh_getbits(cctx, 3);
	if(n==7) {
		while(1) {
			UI b;

			b = (UI)lzh_getbits(cctx, 1);
			if(cctx->eof_flag) break;
			if(b==0) break;
			n++;
			// TODO: What is the length limit?
			if(n>48) {
				lzh_set_err_flag(cctx);
				return 48;
			}
		}
	}
	return n;
}

// Construct the "canonical" Huffman tree, given an array of code lengths.
// Caller creates ht.
static int construct_tree_from_lengths(struct lzh_ctx *cctx,
	struct fmtutil_huffman_tree *ht, const UI *lengths, UI num_lengths)
{
	deark *c = cctx->c;
	UI max_sym_len_used;
	UI i;
	UI symlen;
	UI prev_code_bit_length = 0;
	u64 prev_code = 0; // valid if prev_code_bit_length>0
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg2(c, "constructing huffman tree:");
	de_dbg_indent(c, 1);

	// Find the maximum length
	max_sym_len_used = 0;
	for(i=0; i<num_lengths; i++) {
		if(lengths[i] > max_sym_len_used) {
			max_sym_len_used = lengths[i];
		}
	}
	if(max_sym_len_used>48) {
		goto done;
	}

	// For each possible symbol length...
	for(symlen=1; symlen<=max_sym_len_used; symlen++) {
		UI k;

		// Find all the codes that use this symbol length, in order
		for(k=0; k<num_lengths; k++) {
			int ret;
			u64 thiscode;

			if(lengths[k] != symlen) continue;
			// Found a code of the length we're looking for.

			if(prev_code_bit_length==0) { // this is the first code
				thiscode = 0;
			}
			else {
				thiscode = prev_code + 1;
				if(symlen > prev_code_bit_length) {
					thiscode <<= (symlen - prev_code_bit_length);
				}
			}

			prev_code_bit_length = symlen;
			prev_code = thiscode;

			if(c->debug_level>=2) {
				de_dbg2(c, "addcode 0x%"U64_FMTx" [%u bits] = %u", thiscode, symlen, k);
			}
			ret = fmtutil_huffman_add_code(c, ht, thiscode, symlen, (i32)k);
			if(!ret) {
				goto done;
			}
		}
	}
	retval = 1;

done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static UI read_next_code_using_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree)
{
	i32 val = 0;
	int tmp_count = 0;

	if(!tree->ht) {
		return tree->null_val;
	}

	while(1) {
		int ret;
		u8 b;

		b = (u8)lzh_getbits(cctx, 1);
		if(cctx->eof_flag) {
			de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
				"Unexpected end of compressed data");
			lzh_set_err_flag(cctx);
			val = 0;
			goto done;
		}

		tmp_count++;

		ret = fmtutil_huffman_decode_bit(tree->ht, b, &val);
		if(ret==1) { // finished the code
			if(cctx->c->debug_level>=3) {
				de_dbg3(cctx->c, "hbits: %d", tmp_count);
			}
			goto done;
		}
		else if(ret!=2) {
			de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
				"Huffman decoding error");
			lzh_set_err_flag(cctx);
			val = 0;
			goto done;
		}
	}
done:
	return (UI)val;
}

// TODO?: Maybe consolidate the lh5 read-tree functions (at least codelengths & offsets).

// TODO: Should this be or 20, or 19?
#define LH5X_CODELENGTHS_TREE_MAX_CODES 20

static int lh5x_read_codelengths_tree(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	UI *lengths = NULL; // array[ncodes]
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "code-lengths tree");
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, 5);
	de_dbg(c, "num codes: %u", ncodes);

	if(ncodes>LH5X_CODELENGTHS_TREE_MAX_CODES) {
		ncodes = LH5X_CODELENGTHS_TREE_MAX_CODES;
	}

	if(ncodes==0) {
		cctx->codelengths_tree.null_val = (UI)lzh_getbits(cctx, 5);
		de_dbg2(c, "val0: %u", cctx->codelengths_tree.null_val);
		retval = 1;
		goto done;
	}

	lengths = de_mallocarray(c, ncodes, sizeof(UI));

	curr_idx = 0;
	while(curr_idx < ncodes) {
		lengths[curr_idx] = lh5x_read_a_code_length(cctx);
		de_dbg2(c, "len[%u] = %u", curr_idx, lengths[curr_idx]);
		curr_idx++;

		if(curr_idx==3) {
			UI extraskip;

			// After the first three lengths is a special 2-bit code that may tell us
			// to skip forward in the lengths table.
			// TODO: Verify that it exists when the number of lengths is exactly 3.
			extraskip = (UI)lzh_getbits(cctx, 2);
			if(extraskip>0) {
				de_dbg2(c, "extra skip: %u", extraskip);
				curr_idx += extraskip;
			}
		}
	}
	if(cctx->eof_flag) goto done;

	cctx->codelengths_tree.ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(!construct_tree_from_lengths(cctx, cctx->codelengths_tree.ht, lengths, ncodes)) goto done;

	retval = 1;
done:
	de_free(cctx->c, lengths);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Returns number of extra codes to skip (in excess of the 1 that is always skipped).
static UI lh5x_read_a_skip_length(struct lzh_ctx *cctx, UI rcode)
{
	if(rcode==0) {
		return 0;
	}
	else if(rcode==1) {
		return 2 + (UI)lzh_getbits(cctx, 4);
	}
	return 19 + (UI)lzh_getbits(cctx, 9);
}

#define LH5X_CODE_TREE_MAX_CODES 510

static int lh5x_read_codes_tree(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	UI *lengths = NULL; // array[ncodes]
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "codes tree");
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, 9);
	de_dbg(c, "num codes: %u", ncodes);

	if(ncodes>LH5X_CODE_TREE_MAX_CODES) { // TODO: Is this an error?
		ncodes = LH5X_CODE_TREE_MAX_CODES;
	}
	if(ncodes==0) {
		cctx->codes_tree.null_val = (UI)lzh_getbits(cctx, 9);
		retval = 1;
		goto done;
	}

	lengths = de_mallocarray(c, ncodes, sizeof(UI));

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI x;

		x = read_next_code_using_tree(cctx, &cctx->codelengths_tree);

		if(x<=2) {
			UI sk;

			sk = lh5x_read_a_skip_length(cctx, x);
			de_dbg2(c, "len[%u]: code=%u => skip:range_code=%u,extra_skip=%u",
				curr_idx, x, x, sk);
			curr_idx += 1 + sk;
		}
		else {
			lengths[curr_idx] = x-2;
			de_dbg2(c, "len[%u]: code=%u => len=%u", curr_idx, x, lengths[curr_idx]);
			curr_idx++;
		}
	}
	if(cctx->eof_flag) goto done;

	cctx->codes_tree.ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(!construct_tree_from_lengths(cctx, cctx->codes_tree.ht, lengths, ncodes)) goto done;

	retval = 1;
done:
	de_free(c, lengths);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

#define LH5X_OFFSET_TREE_NBITS 4
#define LH5X_OFFSET_TREE_MAX_CODES 14

static int lh5x_read_offsets_tree(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	UI *lengths = NULL; // array[ncodes]
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "offsets tree");
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, LH5X_OFFSET_TREE_NBITS);
	de_dbg(c, "num codes: %u", ncodes);

	if(ncodes>LH5X_OFFSET_TREE_MAX_CODES) { // TODO: Is this an error?
		ncodes = LH5X_OFFSET_TREE_MAX_CODES;
	}
	if(ncodes==0) {
		cctx->offsets_tree.null_val = (UI)lzh_getbits(cctx, LH5X_OFFSET_TREE_NBITS);
		de_dbg2(c, "val0: %u", cctx->offsets_tree.null_val);
		retval = 1;
		goto done;
	}

	lengths = de_mallocarray(c, ncodes, sizeof(UI));

	curr_idx = 0;
	while(curr_idx < ncodes) {
		lengths[curr_idx] = lh5x_read_a_code_length(cctx);
		de_dbg2(c, "len[%u] = %u", curr_idx, lengths[curr_idx]);
		curr_idx++;
	}
	if(cctx->eof_flag) goto done;

	cctx->offsets_tree.ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(!construct_tree_from_lengths(cctx, cctx->offsets_tree.ht, lengths, ncodes)) goto done;

	retval = 1;
done:
	de_free(c, lengths);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void lh5x_do_lzh_block(struct lzh_ctx *cctx, int blk_idx)
{
	deark *c = cctx->c;
	UI ncodes_in_this_block;
	UI ncodes_remaining_this_block;
	i64 block_start_pos;
	UI block_start_pos_bits;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	block_start_pos = cctx->curpos;
	block_start_pos_bits = cctx->nbits_in_bitbuf;

	ncodes_in_this_block = (UI)lzh_getbits(cctx, 16);
	if(cctx->eof_flag) {
		de_dbg2(c, "stopping, not enough room for a block at %"I64_FMT" minus %u bits",
			block_start_pos, block_start_pos_bits);
		goto done;
	}
	de_dbg(c, "block#%d at %"I64_FMT" minus %u bits", blk_idx, block_start_pos,
		block_start_pos_bits);
	de_dbg_indent(c, 1);
	de_dbg(cctx->c, "num codes: %u", (UI)ncodes_in_this_block);

	if(cctx->codelengths_tree.ht) {
		fmtutil_huffman_destroy_tree(c, cctx->codelengths_tree.ht);
		cctx->codelengths_tree.ht = NULL;
	}
	if(cctx->codes_tree.ht) {
		fmtutil_huffman_destroy_tree(c, cctx->codes_tree.ht);
		cctx->codes_tree.ht = NULL;
	}
	if(cctx->offsets_tree.ht) {
		fmtutil_huffman_destroy_tree(c, cctx->offsets_tree.ht);
		cctx->offsets_tree.ht = NULL;
	}

	if(!lh5x_read_codelengths_tree(cctx)) goto done;
	if(!lh5x_read_codes_tree(cctx)) goto done;
	if(!lh5x_read_offsets_tree(cctx)) goto done;

	de_dbg(c, "cmpr data codes at %"I64_FMT" minus %u bits", cctx->curpos, cctx->nbits_in_bitbuf);
	ncodes_remaining_this_block = ncodes_in_this_block;
	while(1) {
		UI code;

		if(ncodes_remaining_this_block==0) goto done;
		if(cctx->eof_flag) goto done;

		code = read_next_code_using_tree(cctx, &cctx->codes_tree);
		if(cctx->eof_flag) goto done;
		if(c->debug_level>=3) {
			de_dbg3(c, "code: %u (opos=%"I64_FMT")", code, cctx->dcmpro->f->len);
		}

		if(code < 256) { // literal
			de_lz77buffer_addbyte(cctx->ringbuf, (u8)code);
		}
		else { // repeat previous bytes
			UI offset;
			UI length;
			UI ocode1, ocode2;

			length = code-253;

			ocode1 = read_next_code_using_tree(cctx, &cctx->offsets_tree);

			if(cctx->eof_flag) goto done;
			de_dbg3(c, "ocode1: %u", ocode1);

			if(ocode1<=1) {
				offset = ocode1;
			}
			else {
				ocode2 = (UI)lzh_getbits(cctx, ocode1-1);
				if(cctx->eof_flag) goto done;
				de_dbg3(c, "ocode2: %u", ocode2);

				offset = ocode2 + (1U<<(ocode1-1));
			}
			de_dbg3(c, "offset: %u", offset);

			de_lz77buffer_copy_and_write(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-offset-1),
				length, cctx->dcmpro->f);
		}

		ncodes_remaining_this_block--;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void lha5like_lz77buf_writecb(struct de_lz77buffer *rb, const u8 *buf, i64 buf_len)
{
	struct lzh_ctx *cctx = (struct lzh_ctx*)rb->userdata;

	// TODO: Don't write more bytes than expected
	dbuf_write(cctx->dcmpro->f, buf, buf_len);
}

static void decompress_lha_lh5like(struct lzh_ctx *cctx)
{
	int blk_idx = 0;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, 8192);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->write_cb = lha5like_lz77buf_writecb;
	de_lz77buffer_clear(cctx->ringbuf, 0x20);

	while(1) {
		if(cctx->eof_flag) break;
		lh5x_do_lzh_block(cctx, blk_idx);
		blk_idx++;
	}
}

void fmtutil_decompress_lzh(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_lzh_params *lzhp)
{
	struct lzh_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "unlzh";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->curpos = dcmpri->pos;
	cctx->endpos = dcmpri->pos + dcmpri->len;

	if(lzhp->fmt==DE_LZH_FMT_LH5LIKE && lzhp->subfmt=='5') {
		decompress_lha_lh5like(cctx);
	}
	else {
		de_dfilter_set_errorf(c, dres, cctx->modname,
			"Don't know how to decompress this LZH format");
		goto done;
	}

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "LZH decoding error");
		goto done;
	}

	cctx->dres->bytes_consumed = cctx->curpos - cctx->dcmpri->pos;
	cctx->dres->bytes_consumed -= cctx->nbits_in_bitbuf / 8;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	if(cctx) {
		fmtutil_huffman_destroy_tree(c, cctx->codelengths_tree.ht);
		fmtutil_huffman_destroy_tree(c, cctx->codes_tree.ht);
		fmtutil_huffman_destroy_tree(c, cctx->offsets_tree.ht);
		de_lz77buffer_destroy(c, cctx->ringbuf);
		de_free(c, cctx);
	}
}
