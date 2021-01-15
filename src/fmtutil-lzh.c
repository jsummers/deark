// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Decompressor for some LZH formats

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

struct lzh_tree_wrapper {
	struct fmtutil_huffman_tree *ht;
};

struct lzh_ctx {
	deark *c;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	const char *modname;

	i64 nbytes_written;
	int err_flag;

	// bitrd.eof_flag: Always set if err_flag is set.
	struct de_bitreader bitrd;

	u8 zero_codes_block_behavior; // DE_LZH_ZCB_*
	u8 warn_about_zero_codes_block;
	u8 zero_codes_block_warned;

	struct de_lz77buffer *ringbuf;

	u8 is_lhark_lh7;
	UI lh5x_codes_tree_max_codes;
	UI lh5x_offsets_tree_fields_nbits;
	UI lh5x_offsets_tree_max_codes;
	struct lzh_tree_wrapper codelengths_tree;
	struct lzh_tree_wrapper codes_tree;
	struct lzh_tree_wrapper offsets_tree;
};

static void lzh_set_err_flag(struct lzh_ctx *cctx)
{
	cctx->bitrd.eof_flag = 1;
	cctx->err_flag = 1;
}

static u64 lzh_getbits(struct lzh_ctx *cctx, UI nbits)
{
	return de_bitreader_getbits(&cctx->bitrd, nbits);
}

static UI lh5x_read_a_code_length(struct lzh_ctx *cctx)
{
	UI n;

	n = (UI)lzh_getbits(cctx, 3);
	if(n==7) {
		while(1) {
			UI b;

			b = (UI)lzh_getbits(cctx, 1);
			if(cctx->bitrd.eof_flag) break;
			if(b==0) break;
			n++;
			// TODO: What is the length limit?
			if(n>FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) {
				lzh_set_err_flag(cctx);
				return FMTUTIL_HUFFMAN_MAX_CODE_LENGTH;
			}
		}
	}
	return n;
}

static UI read_next_code_using_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree)
{
	fmtutil_huffman_valtype val = 0;
	UI bitcount = 0;
	int ret;

	if(!tree->ht) {
		return 0;
	}

	ret = fmtutil_huffman_read_next_value(tree->ht, &cctx->bitrd, &val, &bitcount);
	if(cctx->bitrd.eof_flag) {
		de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
			"Unexpected end of compressed data");
		lzh_set_err_flag(cctx);
		val = 0;
		goto done;
	}
	else if(!ret) {
		de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
			"Huffman decoding error");
		lzh_set_err_flag(cctx);
		val = 0;
		goto done;
	}

	if(cctx->c->debug_level>=4) {
		de_dbgx(cctx->c, 4, "hbits: %u", bitcount);
	}

done:
	return (UI)val;
}

// TODO?: Maybe consolidate the lh5 read-tree functions (at least codelengths & offsets).

// TODO: Should this be or 20, or 19?
#define LH5X_CODELENGTHS_TREE_MAX_CODES 20

static int lh5x_read_codelengths_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree,
	const char *name)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	int retval = 0;
	int saved_indent_level;
	char pos_descr[32];

	de_dbg_indent_save(c, &saved_indent_level);
	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "%s tree at %s", name, pos_descr);
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, 5);
	de_dbg2(c, "num codes in %s tree: %u", name, ncodes);

	if(ncodes>LH5X_CODELENGTHS_TREE_MAX_CODES) {
		ncodes = LH5X_CODELENGTHS_TREE_MAX_CODES;
	}

	tree->ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, 5);
		de_dbg3(c, "val0: %u", null_val);
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI symlen;

		symlen = lh5x_read_a_code_length(cctx);
		de_dbg3(c, "len[%u] = %u", curr_idx, symlen);
		fmtutil_huffman_record_a_code_length(c, tree->ht, (fmtutil_huffman_valtype)curr_idx, symlen);
		curr_idx++;

		if(curr_idx==3) {
			UI extraskip;

			// After the first three lengths is a special 2-bit code that may tell us
			// to skip forward in the lengths table.
			// TODO: Verify that it exists when the number of lengths is exactly 3.
			extraskip = (UI)lzh_getbits(cctx, 2);
			if(extraskip>0) {
				de_dbg3(c, "extra skip: %u", extraskip);
				curr_idx += extraskip;
			}
		}
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht, 0)) goto done;

	retval = 1;
done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
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

static int lh5x_read_codes_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree,
	const char *name)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	int retval = 0;
	int saved_indent_level;
	char pos_descr[32];

	de_dbg_indent_save(c, &saved_indent_level);
	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "%s tree at %s", name, pos_descr);
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, 9);
	de_dbg2(c, "num codes in %s tree: %u", name, ncodes);

	tree->ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(ncodes>cctx->lh5x_codes_tree_max_codes) {
		goto done;
	}
	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, 9);
		de_dbg3(c, "val0: %u", null_val);
		if(null_val >= cctx->lh5x_codes_tree_max_codes) goto done;
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI x;

		x = read_next_code_using_tree(cctx, &cctx->codelengths_tree);

		if(x<=2) {
			UI sk;

			sk = lh5x_read_a_skip_length(cctx, x);
			de_dbg3(c, "len[%u]: code=%u => skip:range_code=%u,extra_skip=%u",
				curr_idx, x, x, sk);
			curr_idx += 1 + sk;
		}
		else {
			UI symlen;

			symlen = x-2;
			de_dbg3(c, "len[%u]: code=%u => len=%u", curr_idx, x, symlen);
			fmtutil_huffman_record_a_code_length(c, tree->ht, (fmtutil_huffman_valtype)curr_idx, symlen);
			curr_idx++;
		}
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht, 0)) goto done;

	retval = 1;
done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int lh5x_read_offsets_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree,
	const char *name)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	int retval = 0;
	int saved_indent_level;
	char pos_descr[32];

	de_dbg_indent_save(c, &saved_indent_level);
	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "%s tree at %s", name, pos_descr);
	de_dbg_indent(c, 1);

	ncodes = (UI)lzh_getbits(cctx, cctx->lh5x_offsets_tree_fields_nbits);
	de_dbg2(c, "num codes in %s tree: %u", name, ncodes);

	if(ncodes>cctx->lh5x_offsets_tree_max_codes) {
		goto done;
	}

	tree->ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, cctx->lh5x_offsets_tree_fields_nbits);
		de_dbg3(c, "val0: %u", null_val);
		if(null_val >= cctx->lh5x_offsets_tree_max_codes) goto done;
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI symlen;

		symlen = lh5x_read_a_code_length(cctx);
		de_dbg3(c, "len[%u] = %u", curr_idx, symlen);
		fmtutil_huffman_record_a_code_length(c, tree->ht, (fmtutil_huffman_valtype)curr_idx, symlen);
		curr_idx++;
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht, 0)) goto done;

	retval = 1;
done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void lzh_destroy_trees(struct lzh_ctx *cctx)
{
	if(cctx->codelengths_tree.ht) {
		fmtutil_huffman_destroy_tree(cctx->c, cctx->codelengths_tree.ht);
		cctx->codelengths_tree.ht = NULL;
	}
	if(cctx->codes_tree.ht) {
		fmtutil_huffman_destroy_tree(cctx->c, cctx->codes_tree.ht);
		cctx->codes_tree.ht = NULL;
	}
	if(cctx->offsets_tree.ht) {
		fmtutil_huffman_destroy_tree(cctx->c, cctx->offsets_tree.ht);
		cctx->offsets_tree.ht = NULL;
	}
}

static int lh5x_do_read_trees(struct lzh_ctx *cctx)
{
	int retval = 0;

	lzh_destroy_trees(cctx);
	if(!lh5x_read_codelengths_tree(cctx, &cctx->codelengths_tree, "code-lengths")) goto done;
	if(!lh5x_read_codes_tree(cctx, &cctx->codes_tree, "codes")) goto done;
	if(!lh5x_read_offsets_tree(cctx, &cctx->offsets_tree, "offsets")) goto done;
	retval = 1;
done:
	return retval;
}

static void lh5x_do_lzh_block(struct lzh_ctx *cctx, int blk_idx)
{
	deark *c = cctx->c;
	UI ncodes_in_this_block;
	UI ncodes_remaining_this_block;
	int saved_indent_level;
	char pos_descr[32];

	de_dbg_indent_save(c, &saved_indent_level);

	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	ncodes_in_this_block = (UI)lzh_getbits(cctx, 16);
	if(cctx->bitrd.eof_flag) {
		de_dbg2(c, "stopping, not enough room for a block at %s", pos_descr);
		goto done;
	}
	de_dbg2(c, "block#%d at %s", blk_idx, pos_descr);
	de_dbg_indent(c, 1);
	de_dbg2(cctx->c, "num codes in block: %u", (UI)ncodes_in_this_block);

	if(ncodes_in_this_block==0) {
		if(cctx->warn_about_zero_codes_block && !cctx->zero_codes_block_warned) {
			de_warn(c, "Block with \"0\" codes found. This file might not be portable.");
			cctx->zero_codes_block_warned = 1;
		}

		if(cctx->zero_codes_block_behavior==DE_LZH_ZCB_0) {
			;
		}
		else if(cctx->zero_codes_block_behavior==DE_LZH_ZCB_65536) {
			ncodes_in_this_block = 65536;
		}
		else if(cctx->zero_codes_block_behavior==DE_LZH_ZCB_STOP) {
			de_dbg2(c, "stopping, 'stop' code found");
			cctx->bitrd.eof_flag = 1;
			goto done;
		}
		else {
			de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad LZH 'blocksize'");
			cctx->bitrd.eof_flag = 1;
			goto done;
		}
	}

	if(!lh5x_do_read_trees(cctx)) {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad Huffman tree definitions");
		goto done;
	}

	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "cmpr data codes at %s", pos_descr);
	ncodes_remaining_this_block = ncodes_in_this_block;
	while(1) {
		UI code;

		if(ncodes_remaining_this_block==0) goto done;
		if(cctx->bitrd.eof_flag) goto done;

		code = read_next_code_using_tree(cctx, &cctx->codes_tree);
		if(cctx->bitrd.eof_flag) goto done;
		if(c->debug_level>=3) {
			de_dbg3(c, "code: %u (opos=%"I64_FMT")", code, cctx->dcmpro->f->len);
		}

		if(code < 256) { // literal
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)code);
		}
		else { // repeat previous bytes
			UI offset;
			UI length;
			UI ocode1;
			UI offs_low_nbits;
			UI ocode2;

			if(cctx->is_lhark_lh7 && code>=264) {
				if(code<288) {
					UI len_low;
					UI len_low_nbits;

					len_low_nbits = (code-260)/4;
					len_low = (UI)lzh_getbits(cctx, len_low_nbits);
					if(cctx->bitrd.eof_flag) goto done;
					length = ((4+(code%4)) << len_low_nbits) + len_low + 3;
				}
				else { // presumably, code==288
					length = 514;
				}
				de_dbg3(c, "matchlen: %u", (UI)length);
			}
			else {
				length = code-253;
			}

			ocode1 = read_next_code_using_tree(cctx, &cctx->offsets_tree);
			if(cctx->bitrd.eof_flag) goto done;
			de_dbg3(c, "ocode1: %u", ocode1);

			if(cctx->is_lhark_lh7) {
				if(ocode1<=3) {
					offset = ocode1;
				}
				else {
					offs_low_nbits = (ocode1-2)/2;
					ocode2 = (UI)lzh_getbits(cctx, offs_low_nbits);
					if(cctx->bitrd.eof_flag) goto done;
					de_dbg3(c, "ocode2: %u", ocode2);
					offset = ((2+(ocode1%2))<<offs_low_nbits) + ocode2;
				}
			}
			else {
				if(ocode1<=1) {
					offset = ocode1;
				}
				else {
					offs_low_nbits = ocode1-1;
					ocode2 = (UI)lzh_getbits(cctx, offs_low_nbits);
					if(cctx->bitrd.eof_flag) goto done;
					de_dbg3(c, "ocode2: %u", ocode2);
					offset = (1U<<offs_low_nbits) + ocode2;
				}
			}
			de_dbg3(c, "offset: %u", offset);

			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-offset-1), length);
		}

		ncodes_remaining_this_block--;
	}

done:
	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg3(c, "block ends at %s", pos_descr);

	de_dbg_indent_restore(c, saved_indent_level);
}

static int lzh_have_enough_output(struct lzh_ctx *cctx)
{
	if(cctx->dcmpro->len_known) {
		if(cctx->nbytes_written >= cctx->dcmpro->expected_len) {
			return 1;
		}
	}
	return 0;
}

static void lzh_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct lzh_ctx *cctx = (struct lzh_ctx*)rb->userdata;

	if(lzh_have_enough_output(cctx)) {
		return;
	}
	dbuf_writebyte(cctx->dcmpro->f, n);
	cctx->nbytes_written++;
}

static void decompress_lha_lh5like(struct lzh_ctx *cctx, struct de_lzh_params *lzhp)
{
	int blk_idx = 0;
	UI rb_size;

	cctx->lh5x_codes_tree_max_codes = 510;

	if(lzhp->fmt==DE_LZH_FMT_LHARK) {
		cctx->is_lhark_lh7 = 1;
		rb_size = 65536;
		cctx->lh5x_codes_tree_max_codes = 289;
		cctx->lh5x_offsets_tree_fields_nbits = 6;
		cctx->lh5x_offsets_tree_max_codes = 32;
	}
	else if(lzhp->subfmt=='6') {
		rb_size = 32768;
		cctx->lh5x_offsets_tree_fields_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 16;
	}
	else if(lzhp->subfmt=='7' || lzhp->subfmt=='8') {
		rb_size = 65536;
		cctx->lh5x_offsets_tree_fields_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 17;
	}
	else { // assume lh5 (or lh4, for which these params should also work)
		rb_size = 8192;
		cctx->lh5x_offsets_tree_fields_nbits = 4;
		cctx->lh5x_offsets_tree_max_codes = 14;
	}

	cctx->zero_codes_block_behavior = lzhp->zero_codes_block_behavior;
	cctx->warn_about_zero_codes_block = lzhp->warn_about_zero_codes_block;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;
	if(lzhp->use_history_fill_val) {
		if(lzhp->history_fill_val!=0x00) {
			de_lz77buffer_clear(cctx->ringbuf, lzhp->history_fill_val);
		}
	}
	else {
		de_lz77buffer_clear(cctx->ringbuf, 0x20);
	}

	while(1) {
		if(cctx->bitrd.eof_flag) break;
		if(lzh_have_enough_output(cctx)) break;

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

	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	if(lzhp->fmt==DE_LZH_FMT_LH5LIKE && (lzhp->subfmt>='4' && lzhp->subfmt<='8'))
	{
		decompress_lha_lh5like(cctx, lzhp);
	}
	else if(lzhp->fmt==DE_LZH_FMT_LHARK) {
		decompress_lha_lh5like(cctx, lzhp);
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

	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	cctx->dres->bytes_consumed -= cctx->bitrd.bbll.nbits_in_bitbuf / 8;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	if(cctx) {
		lzh_destroy_trees(cctx);
		de_lz77buffer_destroy(c, cctx->ringbuf);
		de_free(c, cctx);
	}
}

void fmtutil_lzh_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	fmtutil_decompress_lzh(c, dcmpri, dcmpro, dres,
		(struct de_lzh_params *)codec_private_params);
}

//////////////////// Deflate - native decoder (not miniz)

static UI deflate_decode_length(deark *c, struct lzh_ctx *cctx, UI code)
{
	UI length = 0;
	UI more_bits_count = 0;

	if(code<=264) {
		length = code - 254;
		more_bits_count = 0;
	}
	else if(code>=265 && code<=284) {
		more_bits_count = (code-261)/4;
		length = ((4 + (code+3)%4) << more_bits_count) + 3;
	}
	else if(code==285) {
		length = 258;
		more_bits_count = 0;
	}
	else {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad length code");
		cctx->err_flag = 1;
		goto done;
	}

	if(more_bits_count>0) {
		UI more_bits_val;

		more_bits_val = (UI)de_bitreader_getbits(&cctx->bitrd, more_bits_count);
		length += more_bits_val;
	}

done:
	return length;
}

static UI deflate_read_and_decode_distance(deark *c, struct lzh_ctx *cctx)
{
	UI dist_code;
	UI dist = 1;
	UI more_bits_count;
	UI more_bits_val;

	dist_code = read_next_code_using_tree(cctx, &cctx->offsets_tree);
	if(dist_code<=3) {
		dist = dist_code + 1;
		more_bits_count = 0;
	}
	else if(dist_code<=29) {
		more_bits_count = (dist_code/2)-1;
		dist = ((2 + dist_code%2) << more_bits_count) + 1;
	}
	else {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad distance code");
		cctx->err_flag = 1;
		goto done;
	}

	if(more_bits_count > 0) {
		more_bits_val = (UI)de_bitreader_getbits(&cctx->bitrd, more_bits_count);
		dist += more_bits_val;
	}

done:
	return dist;
}

// Call record_a_code_length() for a range of codes, all the same length
static int huffman_record_len_for_range(deark *c, struct fmtutil_huffman_tree *ht,
	fmtutil_huffman_valtype range_start, i64 count, UI codelen)
{
	for(i64 i=0; i<count; i++) {
		int ret = fmtutil_huffman_record_a_code_length(c, ht,
			range_start+(fmtutil_huffman_valtype)i, codelen);
		if(!ret) return 0;
	}
	return 1;
}

static int deflate_block_type1_make_fixed_trees(deark *c, struct lzh_ctx *cctx)
{
	int retval = 0;

	cctx->codes_tree.ht =  fmtutil_huffman_create_tree(c, 288, 288);
	huffman_record_len_for_range(c, cctx->codes_tree.ht, 0, 144, 8); // 0..143
	huffman_record_len_for_range(c, cctx->codes_tree.ht, 144, 112, 9); // 144..255
	huffman_record_len_for_range(c, cctx->codes_tree.ht, 256, 24, 7); // 256..279
	huffman_record_len_for_range(c, cctx->codes_tree.ht, 280, 8, 8); // 280..287
	de_dbg3(c, "[lit/len codebook]");
	if(!fmtutil_huffman_make_canonical_tree(c, cctx->codes_tree.ht, 0)) goto done;

	// This is a trivial Huffman tree -- We could do without it and just read
	// 5 bits directly, though we'd have to reverse the order of the bits.
	cctx->offsets_tree.ht =  fmtutil_huffman_create_tree(c, 32, 32);
	huffman_record_len_for_range(c, cctx->offsets_tree.ht, 0, 32, 5);
	de_dbg3(c, "[offsets codebook]");
	if(!fmtutil_huffman_make_canonical_tree(c, cctx->offsets_tree.ht, 0)) goto done;

	retval = 1;
done:
	return retval;
}

static int deflate_block_type2_read_trees(deark *c, struct lzh_ctx *cctx)
{
	UI n;
	UI i;
	UI num_total_codes;
	int retval = 0;
	int ret;
	static const u8 cll_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11,
		4, 12, 3, 13, 2, 14, 1, 15};
	UI cll[19]; // sorted code length lengths
	UI prev_code = 0;
	UI num_rle_codes_left = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	lzh_destroy_trees(cctx);
	de_zeromem(cll, sizeof(cll));

	n = (UI)lzh_getbits(cctx, 5);
	UI num_literal_codes = n + 257;
	de_dbg2(c, "num lit/len codes: %u", num_literal_codes);

	n = (UI)lzh_getbits(cctx, 5);
	UI num_dist_codes = n + 1;
	de_dbg2(c, "num dist codes: %u", num_dist_codes);

	n = (UI)lzh_getbits(cctx, 4);
	UI num_bit_length_codes = n + 4;
	de_dbg2(c, "num bit-length codes: %u", num_bit_length_codes);

	// "Meta" tree - An unencoded sequence of Huffman code lengths, used
	// to construct a Huffman tree containing the code values (which
	// themselves are usually code lengths) used in the rest of the tree
	// definition section.

	cctx->codelengths_tree.ht = fmtutil_huffman_create_tree(c, 19, 19);
	for(i=0; i<num_bit_length_codes; i++) {
		n = (UI)lzh_getbits(cctx, 3);
		cll[(UI)cll_order[i]] = n;
		if(c->debug_level>=3) {
			de_dbg3(c, "%u. length[%u] = %u", i, (UI)cll_order[i], n);
		}
	}
	for(i=0; i<19; i++) {
		if(cll[i]>0) {
			fmtutil_huffman_record_a_code_length(c, cctx->codelengths_tree.ht,
				(fmtutil_huffman_valtype)i, cll[i]);
		}
	}

	de_dbg3(c, "[codelengths codebook]");
	if(!fmtutil_huffman_make_canonical_tree(c, cctx->codelengths_tree.ht, 0)) goto done;

	cctx->codes_tree.ht = fmtutil_huffman_create_tree(c, num_literal_codes, 286);
	cctx->offsets_tree.ht = fmtutil_huffman_create_tree(c, num_dist_codes, 32);

	de_dbg3(c, "[main lit/len/offsets definition table]");
	de_dbg_indent(c, 1);
	num_total_codes = num_literal_codes + num_dist_codes;
	for(i=0; i<num_total_codes; i++) {
		UI x;
		const char *tblname;
		UI code_bias;

		if(i<num_literal_codes) {
			tblname = "lit/len";
			code_bias = 0;
		}
		else {
			tblname = "offset";
			code_bias = num_literal_codes;
		}

		if(num_rle_codes_left>0) {
			x = prev_code;
			num_rle_codes_left--;
		}
		else {
			x = read_next_code_using_tree(cctx, &cctx->codelengths_tree);

			if(x<=15) {
				prev_code = x;
				de_dbg3(c, "%s %u codelen: %u", tblname, i-code_bias, x);
			}
			else if(x==16) { // Read next 2 bits, copy prev code 3-6 times
				x = prev_code;
				n = (UI)lzh_getbits(cctx, 2);
				num_rle_codes_left = n + 3 - 1;
				de_dbg3(c, "[next %u codes same as prev]", n+3);
			}
			else if(x==17) { // Read next 3 bits, next 3-10 codes are 0
				x = 0;
				prev_code = 0;
				n = (UI)lzh_getbits(cctx, 3);
				num_rle_codes_left = n + 3 - 1;
				de_dbg3(c, "[next %u codes = 0]", n+3);
			}
			else if(x==18) { // Read next 7 bits, next 11-138 codes are 0
				x = 0;
				prev_code = 0;
				n = (UI)lzh_getbits(cctx, 7);
				num_rle_codes_left = n + 11 - 1;
				de_dbg3(c, "[next %u codes = 0]", n+11);
			}
			else {
				goto done;
			}
		}

		if(i<num_literal_codes) {
			ret = fmtutil_huffman_record_a_code_length(c, cctx->codes_tree.ht,
				(fmtutil_huffman_valtype)i, x);
		}
		else {
			ret = fmtutil_huffman_record_a_code_length(c, cctx->offsets_tree.ht,
				(fmtutil_huffman_valtype)(i-code_bias), x);
		}
		if(!ret) goto done;

	}
	de_dbg_indent(c, -1);

	de_dbg3(c, "[lit/len codebook]");
	if(!fmtutil_huffman_make_canonical_tree(c, cctx->codes_tree.ht, 0)) goto done;

	de_dbg3(c, "[offsets codebook]");
	if(!fmtutil_huffman_make_canonical_tree(c, cctx->offsets_tree.ht, 0)) goto done;

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int lzh_do_deflate_block_type1_2(deark *c, struct lzh_ctx *cctx, UI blktype)
{
	int retval = 0;

	if(blktype==1) {
		if(!deflate_block_type1_make_fixed_trees(c, cctx)) goto done;
	}
	else {
		if(!deflate_block_type2_read_trees(c, cctx)) goto done;
	}

	while(1) {
		UI code;

		if(cctx->bitrd.eof_flag || cctx->err_flag) break;

		code = read_next_code_using_tree(cctx, &cctx->codes_tree);
		if(code<=255) {
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)code);
		}
		else if(code>=257 && code<=285) { // beginning of a match
			UI length = deflate_decode_length(c, cctx, code);
			UI dist = deflate_read_and_decode_distance(c, cctx);
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-dist), length);
		}
		else if(code==256) { // end of block
			retval = 1;
			goto done;
		}
		else {
			de_dbg(c, "unsupported code %u", code);
			cctx->err_flag = 1;
			goto done;
		}
	}

done:
	return retval;
}

// Copy uncompressed aligned bytes
static int lzh_copy_aligned_bytes(deark *c, struct lzh_ctx *cctx, i64 nbytes_to_copy1)
{
	i64 nbytes_left_to_copy = nbytes_to_copy1;

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	while(nbytes_left_to_copy>0) {
		if(cctx->bitrd.curpos >= cctx->bitrd.endpos) {
			cctx->bitrd.eof_flag = 1;
			goto done;
		}
		u8 b = dbuf_getbyte_p(cctx->bitrd.f, &cctx->bitrd.curpos);
		de_lz77buffer_add_literal_byte(cctx->ringbuf, b);
		nbytes_left_to_copy--;
	}

done:
	if(nbytes_left_to_copy!=0) {
		return 0;
	}
	return 1;
}

static int lzh_do_deflate_block_type0(deark *c, struct lzh_ctx *cctx)
{
	int retval = 0;
	UI blk_dlen;
	UI blk_check, blk_check_expected;

	// Go to the next byte boundary
	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);

	// Next, two 16-bit fields
	blk_dlen = (UI)lzh_getbits(cctx, 16);
	de_dbg(c, "non-compressed block dlen: %u", blk_dlen);
	blk_check_expected = blk_dlen ^ 0xffff;
	blk_check = (UI)lzh_getbits(cctx, 16);
	de_dbg(c, "consistency check: 0x%04u", blk_check);
	if(blk_check != blk_check_expected) {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname,
			"Non-compressed block failed consistency check");
		goto done;
	}

	// Then the literal bytes
	if(!lzh_copy_aligned_bytes(c, cctx, (i64)blk_dlen)) goto done;
	retval = 1;

done:
	return retval;
}

// Returns 0 if this was the last block, or on error.
static int lzh_do_deflate_block(deark *c, struct lzh_ctx *cctx)
{
	UI is_last;
	UI blktype;
	int blkret;
	char pos_descr[32];
	int retval = 0;

	lzh_destroy_trees(cctx);

	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	is_last = (UI)lzh_getbits(cctx, 1);
	blktype = (UI)lzh_getbits(cctx, 2);
	de_dbg(c, "block at %s, type=%u, last=%u", pos_descr, blktype, is_last);
	de_dbg_indent(c, 1);

	switch(blktype) {
	case 0:
		blkret = lzh_do_deflate_block_type0(c, cctx);
		break;
	case 1:
	case 2:
		blkret = lzh_do_deflate_block_type1_2(c, cctx, blktype);
		break;
	default:
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Unsupported block type: %u",
			blktype);
		blkret = 0;
	}

	if(blkret && !is_last) {
		retval = 1;
	}

	de_dbg_indent(c, -1);
	return retval;
}

static void decompress_deflate_internal(struct lzh_ctx *cctx)
{
	UI rb_size;
	deark *c = cctx->c;

	rb_size = 32768;
	cctx->ringbuf = de_lz77buffer_create(c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;

	while(1) {
		int ret;

		if(cctx->bitrd.eof_flag || cctx->err_flag) break;
		if(lzh_have_enough_output(cctx)) break;

		ret = lzh_do_deflate_block(c, cctx);
		if(!ret) break;
	}
}

// Maybe inflate/deflate ought to be handled by fmtutil_decompress_lzh(), but for
// convenience it may be best to keep it separate.
static void fmtutil_inflate_codectype1_native(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params1)
{
	struct lzh_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "inflate-native";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 1;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	decompress_deflate_internal(cctx);

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "Deflate decoding error");
		goto done;
	}

	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	cctx->dres->bytes_consumed -= cctx->bitrd.bbll.nbits_in_bitbuf / 8;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	if(cctx) {
		lzh_destroy_trees(cctx);
		de_lz77buffer_destroy(c, cctx->ringbuf);
		de_free(c, cctx);
	}
}

void fmtutil_inflate_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct de_inflate_params *inflparams = (struct de_inflate_params*)codec_private_params;

	// Cases where we have to use miniz:
	if((inflparams->flags & DE_DEFLATEFLAG_ISZLIB) || inflparams->starting_dict) {
		fmtutil_inflate_codectype1_miniz(c, dcmpri, dcmpro, dres, codec_private_params);
		return;
	}

	if(c->deflate_decoder_id==0) {
		const char *o;

		o = de_get_ext_option(c, "deflatecodec");
		if(o && !de_strcmp(o, "native")) {
			c->deflate_decoder_id = 2;
		}
		else {
			c->deflate_decoder_id = 1;
		}
	}

	if(c->deflate_decoder_id==2) {
		fmtutil_inflate_codectype1_native(c, dcmpri, dcmpro, dres, codec_private_params);
	}
	else {
		fmtutil_inflate_codectype1_miniz(c, dcmpri, dcmpro, dres, codec_private_params);
	}
}

/////////////////////////////

void fmtutil_decompress_zip_implode(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_zipimplode_params *params)
{
	fmtutil_decompress_zip_implode_ui6a(c, dcmpri, dcmpro, dres, params);
}
