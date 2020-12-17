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
	UI lh5x_offset_nbits;
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
			if(n>48) {
				lzh_set_err_flag(cctx);
				return 48;
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

	if(cctx->c->debug_level>=3) {
		de_dbg3(cctx->c, "hbits: %u", bitcount);
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
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		de_dbg3(c, "val0: %u", null_val);
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

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht)) goto done;

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

#define LH5X_CODE_TREE_MAX_CODES 510

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

	// Note: For lhark format, max codes is probably 289.
	if(ncodes>LH5X_CODE_TREE_MAX_CODES) { // TODO: Is this an error?
		ncodes = LH5X_CODE_TREE_MAX_CODES;
	}
	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, 9);
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		de_dbg3(c, "val0: %u", null_val);
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

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht)) goto done;

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

	ncodes = (UI)lzh_getbits(cctx, cctx->lh5x_offset_nbits);
	de_dbg2(c, "num codes in %s tree: %u", name, ncodes);

	if(ncodes>cctx->lh5x_offsets_tree_max_codes) { // TODO: Is this an error?
		ncodes = cctx->lh5x_offsets_tree_max_codes;
	}

	tree->ht = fmtutil_huffman_create_tree(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, cctx->lh5x_offset_nbits);
		fmtutil_huffman_add_code(c, tree->ht, 0, 0, (fmtutil_huffman_valtype)null_val);
		de_dbg3(c, "val0: %u", null_val);
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

	if(!fmtutil_huffman_make_canonical_tree(c, tree->ht)) goto done;

	retval = 1;
done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int lh5x_do_read_trees(struct lzh_ctx *cctx)
{
	int retval = 0;

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
				if(code==288) {
					length = 514;
				}
				else if(code>288) {
					de_dbg(c, "unknown lhark code: %u", (UI)code);
					goto done;
				}
				else {
					UI len_low;
					UI len_low_nbits;

					len_low_nbits = (code-260)/4;
					len_low = (UI)lzh_getbits(cctx, len_low_nbits);
					if(cctx->bitrd.eof_flag) goto done;
					length = ((4+(code%4)) << len_low_nbits) + len_low + 3;
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

static void lha5like_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
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

	if(lzhp->fmt==DE_LZH_FMT_LHARK) {
		cctx->is_lhark_lh7 = 1;
		rb_size = 65536;
		cctx->lh5x_offset_nbits = 6;
		cctx->lh5x_offsets_tree_max_codes = 63; // Max observed is 32
	}
	else if(lzhp->subfmt=='6') {
		rb_size = 32768;
		cctx->lh5x_offset_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 16;
	}
	else if(lzhp->subfmt=='7' || lzhp->subfmt=='8') {
		rb_size = 65536;
		cctx->lh5x_offset_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 17;
	}
	else { // assume lh5 (or lh4, for which these params should also work)
		rb_size = 8192;
		cctx->lh5x_offset_nbits = 4;
		cctx->lh5x_offsets_tree_max_codes = 14;
	}

	cctx->zero_codes_block_behavior = lzhp->zero_codes_block_behavior;
	cctx->warn_about_zero_codes_block = lzhp->warn_about_zero_codes_block;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lha5like_lz77buf_writebytecb;
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
		fmtutil_huffman_destroy_tree(c, cctx->codelengths_tree.ht);
		fmtutil_huffman_destroy_tree(c, cctx->codes_tree.ht);
		fmtutil_huffman_destroy_tree(c, cctx->offsets_tree.ht);
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
