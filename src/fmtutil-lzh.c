// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Decompressor for some LZH formats

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

struct lzh_tree_wrapper {
	struct fmtutil_huffman_decoder *ht;
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
	int ringbuf_owned_by_caller; // hack

	u8 is_deflate64;
	u8 is_lhark_lh7;
	UI lh5x_literals_tree_max_codes;
	UI lh5x_offsets_tree_fields_nbits;
	UI lh5x_offsets_tree_max_codes;
	struct lzh_tree_wrapper meta_tree; // Usually encodes code lengths for other table(s)
	struct lzh_tree_wrapper literals_tree; // Literals+lengths, or just literals
	struct lzh_tree_wrapper offsets_tree;
	struct lzh_tree_wrapper matchlengths_tree; // Used if literals and lengths are separate

	u8 implode_8k_buffer;
	u8 implode_3_trees;
	UI implode_min_match_len;
	UI dist_code_extra_bits;
	struct de_crcobj *crco;
	i64 max_offset_used;
};

static void lzh_destroy_trees(struct lzh_ctx *cctx);

static void destroy_lzh_ctx(struct lzh_ctx *cctx)
{
	deark *c;

	if(!cctx) return;
	c = cctx->c;
	lzh_destroy_trees(cctx);
	if(cctx->ringbuf && !cctx->ringbuf_owned_by_caller) {
		de_lz77buffer_destroy(c, cctx->ringbuf);
		cctx->ringbuf = NULL;
	}
	if(cctx->crco) de_crcobj_destroy(cctx->crco);
	de_free(c, cctx);
}

static void lzh_set_err_flag(struct lzh_ctx *cctx)
{
	cctx->bitrd.eof_flag = 1;
	cctx->err_flag = 1;
}

static u64 lzh_getbits(struct lzh_ctx *cctx, UI nbits)
{
	return de_bitreader_getbits(&cctx->bitrd, nbits);
}

static void lzh_make_tree_from_bytearrays(struct lzh_ctx *cctx,
	struct lzh_tree_wrapper *tree,
	const u8 *codes, const u8 *lengths, UI ncodes,
	const char *dbgtitle)
{
	deark *c = cctx->c;
	UI n;
	char b2buf[72];

	tree->ht = fmtutil_huffman_create_decoder(c, ncodes, ncodes);
	if(dbgtitle) {
		de_dbg3(c, "[%s]", dbgtitle);
	}
	de_dbg_indent(c, 1);
	for(n=0; n<ncodes; n++) {
		UI nbits;
		u64 code;

		nbits = (UI)lengths[n];
		code = (u64)codes[n];

		if(dbgtitle && c->debug_level>=3) {
			de_dbg3(c, "code: \"%s\" = %d",
				de_print_base2_fixed(b2buf, sizeof(b2buf), code, nbits), (int)n);
		}
		fmtutil_huffman_add_code(c, tree->ht->bk, code, nbits,
			(fmtutil_huffman_valtype)n);
	}
	de_dbg_indent(c, -1);
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

	ret = fmtutil_huffman_read_next_value(tree->ht->bk, &cctx->bitrd, &val, &bitcount);
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

	tree->ht = fmtutil_huffman_create_decoder(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, 5);
		de_dbg3(c, "val0: %u", null_val);
		fmtutil_huffman_add_code(c, tree->ht->bk, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI symlen;

		symlen = lh5x_read_a_code_length(cctx);
		de_dbg3(c, "len[%u] = %u", curr_idx, symlen);
		fmtutil_huffman_record_a_code_length(c, tree->ht->builder, (fmtutil_huffman_valtype)curr_idx, symlen);
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

	if(!fmtutil_huffman_make_canonical_code(c, tree->ht->bk, tree->ht->builder, 0, NULL)) goto done;

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

static int lh5x_read_literals_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree,
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

	tree->ht = fmtutil_huffman_create_decoder(c, (i64)ncodes, (i64)ncodes);

	if(ncodes>cctx->lh5x_literals_tree_max_codes) {
		goto done;
	}
	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, 9);
		de_dbg3(c, "val0: %u", null_val);
		if(null_val >= cctx->lh5x_literals_tree_max_codes) goto done;
		fmtutil_huffman_add_code(c, tree->ht->bk, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI x;

		x = read_next_code_using_tree(cctx, &cctx->meta_tree);

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
			fmtutil_huffman_record_a_code_length(c, tree->ht->builder, (fmtutil_huffman_valtype)curr_idx, symlen);
			curr_idx++;
		}
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_code(c, tree->ht->bk, tree->ht->builder, 0, NULL)) goto done;

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

	tree->ht = fmtutil_huffman_create_decoder(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)lzh_getbits(cctx, cctx->lh5x_offsets_tree_fields_nbits);
		de_dbg3(c, "val0: %u", null_val);
		if(null_val >= cctx->lh5x_offsets_tree_max_codes) goto done;
		fmtutil_huffman_add_code(c, tree->ht->bk, 0, 0, (fmtutil_huffman_valtype)null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI symlen;

		symlen = lh5x_read_a_code_length(cctx);
		de_dbg3(c, "len[%u] = %u", curr_idx, symlen);
		fmtutil_huffman_record_a_code_length(c, tree->ht->builder, (fmtutil_huffman_valtype)curr_idx, symlen);
		curr_idx++;
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_code(c, tree->ht->bk, tree->ht->builder, 0, NULL)) goto done;

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
	if(cctx->meta_tree.ht) {
		fmtutil_huffman_destroy_decoder(cctx->c, cctx->meta_tree.ht);
		cctx->meta_tree.ht = NULL;
	}
	if(cctx->literals_tree.ht) {
		fmtutil_huffman_destroy_decoder(cctx->c, cctx->literals_tree.ht);
		cctx->literals_tree.ht = NULL;
	}
	if(cctx->offsets_tree.ht) {
		fmtutil_huffman_destroy_decoder(cctx->c, cctx->offsets_tree.ht);
		cctx->offsets_tree.ht = NULL;
	}
	if(cctx->matchlengths_tree.ht) {
		fmtutil_huffman_destroy_decoder(cctx->c, cctx->matchlengths_tree.ht);
		cctx->matchlengths_tree.ht = NULL;
	}
}

static int lh5x_do_read_trees(struct lzh_ctx *cctx)
{
	int retval = 0;

	lzh_destroy_trees(cctx);
	if(!lh5x_read_codelengths_tree(cctx, &cctx->meta_tree, "code-lengths")) goto done;
	if(!lh5x_read_literals_tree(cctx, &cctx->literals_tree, "codes")) goto done;
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

		if(cctx->zero_codes_block_behavior==DE_LH5X_ZCB_0) {
			;
		}
		else if(cctx->zero_codes_block_behavior==DE_LH5X_ZCB_65536) {
			ncodes_in_this_block = 65536;
		}
		else if(cctx->zero_codes_block_behavior==DE_LH5X_ZCB_STOP) {
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

		code = read_next_code_using_tree(cctx, &cctx->literals_tree);
		if(cctx->bitrd.eof_flag) goto done;

		if(code < 256) { // literal
			if(c->debug_level>=4) {
				de_dbg(c, "lit %u", code);
			}
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
			}
			else {
				length = code-253;
			}

			ocode1 = read_next_code_using_tree(cctx, &cctx->offsets_tree);
			if(cctx->bitrd.eof_flag) goto done;

			if(cctx->is_lhark_lh7) {
				if(ocode1<=3) {
					offset = ocode1;
				}
				else {
					offs_low_nbits = (ocode1-2)/2;
					ocode2 = (UI)lzh_getbits(cctx, offs_low_nbits);
					if(cctx->bitrd.eof_flag) goto done;
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
					offset = (1U<<offs_low_nbits) + ocode2;
				}
			}

			if(c->debug_level>=4) {
				de_dbg(c, "match d=%u l=%u", offset+1, length);
			}
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-offset-1), length);
			if((i64)offset+1 > cctx->max_offset_used) {
				cctx->max_offset_used = (i64)offset+1;
			}
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

static void lzh_update_crc(struct lzh_ctx *cctx, u8 n)
{
	de_crcobj_addbuf(cctx->crco, &n, 1);
}

static void lzh_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct lzh_ctx *cctx = (struct lzh_ctx*)rb->userdata;

	if(lzh_have_enough_output(cctx)) {
		return;
	}
	dbuf_writebyte(cctx->dcmpro->f, n);
	if(cctx->crco) lzh_update_crc(cctx, n);
	cctx->nbytes_written++;
}

static void lzh_lz77buf_writebytecb_flagerrors(struct de_lz77buffer *rb, u8 n)
{
	struct lzh_ctx *cctx = (struct lzh_ctx*)rb->userdata;

	if(lzh_have_enough_output(cctx)) {
		cctx->err_flag = 1;
		return;
	}
	dbuf_writebyte(cctx->dcmpro->f, n);
	if(cctx->crco) lzh_update_crc(cctx, n);
	cctx->nbytes_written++;
}

static void decompress_lh5x_internal(struct lzh_ctx *cctx, struct de_lh5x_params *lzhp)
{
	int blk_idx = 0;
	UI rb_size;

	cctx->lh5x_literals_tree_max_codes = 510;

	if(lzhp->fmt==DE_LH5X_FMT_LH5) {
		rb_size = 8192;
		cctx->lh5x_offsets_tree_fields_nbits = 4;
		cctx->lh5x_offsets_tree_max_codes = 14;
	}
	else if(lzhp->fmt==DE_LH5X_FMT_LH6) {
		rb_size = 32768;
		cctx->lh5x_offsets_tree_fields_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 16;
	}
	else if(lzhp->fmt==DE_LH5X_FMT_LH7) {
		rb_size = 65536;
		cctx->lh5x_offsets_tree_fields_nbits = 5;
		cctx->lh5x_offsets_tree_max_codes = 17;
	}
	else if(lzhp->fmt==DE_LH5X_FMT_LHARK) {
		cctx->is_lhark_lh7 = 1;
		rb_size = 65536;
		cctx->lh5x_literals_tree_max_codes = 289;
		cctx->lh5x_offsets_tree_fields_nbits = 6;
		cctx->lh5x_offsets_tree_max_codes = 32;
	}
	else {
		de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
			"Don't know how to decompress this LZH format");
		goto done;
	}

	cctx->zero_codes_block_behavior = lzhp->zero_codes_block_behavior;
	cctx->warn_about_zero_codes_block = lzhp->warn_about_zero_codes_block;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;
	if(lzhp->history_fill_val!=0x00) {
		de_lz77buffer_clear(cctx->ringbuf, lzhp->history_fill_val);
	}

	while(1) {
		if(cctx->bitrd.eof_flag) break;
		if(lzh_have_enough_output(cctx)) break;

		lh5x_do_lzh_block(cctx, blk_idx);
		blk_idx++;
	}

done:
	lzhp->max_offset_used = cctx->max_offset_used;
}

void fmtutil_decompress_lh5x(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_lh5x_params *lzhp)
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

	decompress_lh5x_internal(cctx, lzhp);

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "LZH decoding error");
		goto done;
	}

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}

void fmtutil_lh5x_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	fmtutil_decompress_lh5x(c, dcmpri, dcmpro, dres,
		(struct de_lh5x_params *)codec_private_params);
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
		if(cctx->is_deflate64) {
			length = 3;
			more_bits_count = 16;
		}
		else {
			length = 258;
			more_bits_count = 0;
		}
	}
	else {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad length code");
		cctx->err_flag = 1;
		goto done;
	}

	if(more_bits_count>0) {
		UI more_bits_val;

		more_bits_val = (UI)lzh_getbits(cctx, more_bits_count);
		length += more_bits_val;
	}

done:
	return length;
}

static UI deflate_read_and_decode_distance(deark *c, struct lzh_ctx *cctx)
{
	UI dist_code;
	UI dist = 0;
	UI more_bits_count;
	UI more_bits_val;

	dist_code = read_next_code_using_tree(cctx, &cctx->offsets_tree);
	if(dist_code<=3) {
		dist = dist_code;
		more_bits_count = 0;
	}
	else if(dist_code<=29 || (cctx->is_deflate64 && dist_code<=31)) {
		more_bits_count = (dist_code/2)-1;
		dist = (2 + dist_code%2) << more_bits_count;
	}
	else {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad distance code");
		cctx->err_flag = 1;
		goto done;
	}

	if(more_bits_count > 0) {
		more_bits_val = (UI)lzh_getbits(cctx, more_bits_count);
		dist += more_bits_val;
	}

done:
	return dist;
}

// Call record_a_code_length() for a range of codes, all the same length
static int huffman_record_len_for_range(deark *c, struct fmtutil_huffman_decoder *ht,
	fmtutil_huffman_valtype range_start, i64 count, UI codelen)
{
	i64 i;

	for(i=0; i<count; i++) {
		int ret = fmtutil_huffman_record_a_code_length(c, ht->builder,
			range_start+(fmtutil_huffman_valtype)i, codelen);
		if(!ret) return 0;
	}
	return 1;
}

static int deflate_block_type1_make_fixed_trees(deark *c, struct lzh_ctx *cctx)
{
	int retval = 0;

	cctx->literals_tree.ht =  fmtutil_huffman_create_decoder(c, 288, 288);
	huffman_record_len_for_range(c, cctx->literals_tree.ht, 0, 144, 8); // 0..143
	huffman_record_len_for_range(c, cctx->literals_tree.ht, 144, 112, 9); // 144..255
	huffman_record_len_for_range(c, cctx->literals_tree.ht, 256, 24, 7); // 256..279
	huffman_record_len_for_range(c, cctx->literals_tree.ht, 280, 8, 8); // 280..287
	if(!fmtutil_huffman_make_canonical_code(c, cctx->literals_tree.ht->bk,
		cctx->literals_tree.ht->builder, 0, "lit/len codebook"))
	{
		goto done;
	}

	// This is a trivial Huffman tree -- We could do without it and just read
	// 5 bits directly, though we'd have to reverse the order of the bits.
	cctx->offsets_tree.ht =  fmtutil_huffman_create_decoder(c, 32, 32);
	huffman_record_len_for_range(c, cctx->offsets_tree.ht, 0, 32, 5);
	if(!fmtutil_huffman_make_canonical_code(c, cctx->offsets_tree.ht->bk,
		cctx->offsets_tree.ht->builder, 0, "offsets codebook"))
	{
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static int deflate_block_type2_read_trees(deark *c, struct lzh_ctx *cctx)
{
	UI n;
	UI i;
	UI num_total_codes;
	UI num_literal_codes;
	UI num_dist_codes;
	UI num_bit_length_codes;
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
	num_literal_codes = n + 257;
	de_dbg2(c, "num lit/len codes: %u", num_literal_codes);

	n = (UI)lzh_getbits(cctx, 5);
	num_dist_codes = n + 1;
	de_dbg2(c, "num dist codes: %u", num_dist_codes);

	n = (UI)lzh_getbits(cctx, 4);
	num_bit_length_codes = n + 4;
	de_dbg2(c, "num bit-length codes: %u", num_bit_length_codes);

	// "Meta" tree - An unencoded sequence of Huffman code lengths, used
	// to construct a Huffman tree containing the code values (which
	// themselves are usually code lengths) used in the rest of the tree
	// definition section.

	cctx->meta_tree.ht = fmtutil_huffman_create_decoder(c, 19, 19);
	for(i=0; i<num_bit_length_codes; i++) {
		n = (UI)lzh_getbits(cctx, 3);
		cll[(UI)cll_order[i]] = n;
		if(c->debug_level>=3) {
			de_dbg3(c, "%u. length[%u] = %u", i, (UI)cll_order[i], n);
		}
	}
	for(i=0; i<19; i++) {
		if(cll[i]>0) {
			fmtutil_huffman_record_a_code_length(c, cctx->meta_tree.ht->builder,
				(fmtutil_huffman_valtype)i, cll[i]);
		}
	}

	if(!fmtutil_huffman_make_canonical_code(c, cctx->meta_tree.ht->bk,
		cctx->meta_tree.ht->builder, 0, "derived codelengths codebook"))
	{
		goto done;
	}

	cctx->literals_tree.ht = fmtutil_huffman_create_decoder(c, num_literal_codes, 286);
	cctx->offsets_tree.ht = fmtutil_huffman_create_decoder(c, num_dist_codes, 32);

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
			x = read_next_code_using_tree(cctx, &cctx->meta_tree);

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
			ret = fmtutil_huffman_record_a_code_length(c, cctx->literals_tree.ht->builder,
				(fmtutil_huffman_valtype)i, x);
		}
		else {
			ret = fmtutil_huffman_record_a_code_length(c, cctx->offsets_tree.ht->builder,
				(fmtutil_huffman_valtype)(i-code_bias), x);
		}
		if(!ret) goto done;

	}
	de_dbg_indent(c, -1);

	if(!fmtutil_huffman_make_canonical_code(c, cctx->literals_tree.ht->bk,
		cctx->literals_tree.ht->builder, 0, "derived lit/len codebook"))
	{
		goto done;
	}

	if(!fmtutil_huffman_make_canonical_code(c, cctx->offsets_tree.ht->bk,
		cctx->offsets_tree.ht->builder, 0, "derived offsets codebook"))
	{
		goto done;
	}

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

		code = read_next_code_using_tree(cctx, &cctx->literals_tree);
		if(code<=255) {
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "%u lit", code);
			}
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)code);
		}
		else if(code>=257 && code<=285) { // beginning of a match
			UI length = deflate_decode_length(c, cctx, code);
			UI dist = deflate_read_and_decode_distance(c, cctx);
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "%u match d=%u l=%u", code, dist+1, length);
			}
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-1-dist), length);
		}
		else if(code==256) { // end of block
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "%u stop", code);
			}
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
		u8 b;

		if(cctx->bitrd.curpos >= cctx->bitrd.endpos) {
			cctx->bitrd.eof_flag = 1;
			goto done;
		}
		b = dbuf_getbyte_p(cctx->bitrd.f, &cctx->bitrd.curpos);
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
	de_dbg2(c, "non-compressed block dlen: %u", blk_dlen);
	blk_check_expected = blk_dlen ^ 0xffff;
	blk_check = (UI)lzh_getbits(cctx, 16);
	de_dbg2(c, "consistency check: 0x%04x", blk_check);
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
	deark *c = cctx->c;

	while(1) {
		int ret;

		if(cctx->bitrd.eof_flag || cctx->err_flag) break;
		if(lzh_have_enough_output(cctx)) break;

		ret = lzh_do_deflate_block(c, cctx);
		if(!ret) break;
	}
}

static int lzh_read_zlib_header(deark *c, struct lzh_ctx *cctx)
{
	u8 h[2];
	UI meth, cinfo;
	UI fcheck, fdict, flevel;
	UI chk;
	int retval = 0;

	de_dbg(c, "zlib header at %"I64_FMT, cctx->bitrd.curpos);
	de_dbg_indent(c, 1);
	h[0] = (u8)lzh_getbits(cctx, 8);
	h[1] = (u8)lzh_getbits(cctx, 8);

	meth = (UI)(h[0]&0x0f);
	de_dbg2(c, "CM: %u", meth);
	cinfo = (UI)(h[0]>>4);
	de_dbg2(c, "CINFO: %u", cinfo);

	fcheck = (UI)(h[1]&0x1f);
	de_dbg2(c, "FCHECK: %u", fcheck);
	fdict = (UI)((h[1]>>5)&0x1);
	de_dbg2(c, "FDICT: %u", fdict);
	flevel = (UI)((h[1]>>6)&0x3);
	de_dbg2(c, "FLEVEL: %u", flevel);

	chk = (((UI)h[0])<<8) | (UI)h[1];
	if(chk%31 != 0) goto done;
	if(meth!=8) goto done;
	if(cinfo>7) goto done;
	if(fdict) goto done;
	retval = 1;

done:
	if(!retval) {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad or unsupported zlib parameters");
	}
	de_dbg_indent(c, -1);
	return retval;
}

static int lzh_read_zlib_trailer(deark *c, struct lzh_ctx *cctx)
{
	u32 cs_reported;
	u32 cs_calc;
	int retval = 0;

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	de_dbg(c, "zlib trailer at %"I64_FMT, cctx->bitrd.curpos);
	de_dbg_indent(c, 1);
	if(cctx->bitrd.curpos + 4 > cctx->bitrd.endpos) goto done;
	cs_reported = (u32)dbuf_getu32be_p(cctx->bitrd.f, &cctx->bitrd.curpos);
	de_dbg2(c, "checksum (reported): 0x%08x", (UI)cs_reported);
	cs_calc = de_crcobj_getval(cctx->crco);
	de_dbg2(c, "checksum (calculated): 0x%08x", (UI)cs_calc);
	if(cs_calc != cs_reported) goto done;
	retval = 1;

done:
	if(!retval) {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname, "Bad zlib trailer");
	}
	de_dbg_indent(c, -1);
	return retval;
}

static void fmtutil_deflate_codectype1_native(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct de_deflate_params *deflparams = (struct de_deflate_params*)codec_private_params;
	struct lzh_ctx *cctx = NULL;
	u8 is_zlib = 0;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "deflate-native";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	if(deflparams->flags & DE_DEFLATEFLAG_ISZLIB) is_zlib = 1;
	if(deflparams->flags & DE_DEFLATEFLAG_DEFLATE64) cctx->is_deflate64 = 1;

	cctx->bitrd.bbll.is_lsb = 1;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	if(is_zlib) {
		if(!lzh_read_zlib_header(c, cctx)) goto done;

		cctx->crco = de_crcobj_create(c, DE_CRCOBJ_ADLER32);
	}

	if(deflparams->ringbuf_to_use) {
		cctx->ringbuf = deflparams->ringbuf_to_use;
		cctx->ringbuf_owned_by_caller = 1;
	}
	else {
		cctx->ringbuf = de_lz77buffer_create(c, (cctx->is_deflate64 ? 65536 : 32768));
	}

	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;

	decompress_deflate_internal(cctx);

	cctx->ringbuf->userdata = NULL;
	cctx->ringbuf->writebyte_cb = NULL;

	if(!cctx->err_flag && is_zlib) {
		if(!lzh_read_zlib_trailer(c, cctx)) goto done;
	}

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "Deflate decoding error");
		goto done;
	}

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}

// codec_private_params is type de_deflate_params. Cannot be NULL.
void fmtutil_deflate_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct de_deflate_params *deflparams = (struct de_deflate_params*)codec_private_params;
	int must_use_miniz = 0;
	int must_use_native = 0;

	if(!deflparams) return;

	if(deflparams->ringbuf_to_use || (deflparams->flags & DE_DEFLATEFLAG_DEFLATE64)) {
		must_use_native = 1;
	}

	if(must_use_miniz && must_use_native) return;

	if(must_use_miniz) {
		fmtutil_deflate_codectype1_miniz(c, dcmpri, dcmpro, dres, codec_private_params);
		return;
	}
	if(must_use_native) {
		fmtutil_deflate_codectype1_native(c, dcmpri, dcmpro, dres, codec_private_params);
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
		fmtutil_deflate_codectype1_native(c, dcmpri, dcmpro, dres, codec_private_params);
	}
	else {
		fmtutil_deflate_codectype1_miniz(c, dcmpri, dcmpro, dres, codec_private_params);
	}
}

void fmtutil_decompress_deflate_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_deflate_params *params)
{
	fmtutil_deflate_codectype1(c, dcmpri, dcmpro, dres, (void*)params);
}

// flags:
//   DE_DEFLATEFLAG_ISZLIB
//   DE_DEFLATEFLAG_USEMAXUNCMPRSIZE
int fmtutil_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags)
{
	deark *c = inf->c;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_deflate_params deflparams;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	if(bytes_consumed) *bytes_consumed = 0;

	dcmpri.f = inf;
	dcmpri.pos = inputstart;
	dcmpri.len = inputsize;

	dcmpro.f = outf;
	if(flags & DE_DEFLATEFLAG_USEMAXUNCMPRSIZE) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = maxuncmprsize;
		flags -= DE_DEFLATEFLAG_USEMAXUNCMPRSIZE;
	}

	de_zeromem(&deflparams, sizeof(struct de_deflate_params));
	deflparams.flags = flags;
	fmtutil_deflate_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&deflparams);

	if(bytes_consumed && dres.bytes_consumed_valid) {
		*bytes_consumed = dres.bytes_consumed;
	}

	if(dres.errcode != 0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		return 0;
	}
	return 1;
}

///////////////////// Implode (ZIP method #6)

// Note that trees are always constructed so that the minimum value stored
// in them is 0. If that's not the desired minimum value, values must be de-biased
// after reading them.
static int implode_read_a_tree(struct lzh_ctx *cctx,
	struct lzh_tree_wrapper *tree, UI num_values_expected, const char *name)
{
	UI n;
	UI num_rle_items;
	UI i;
	UI next_val = 0;
	deark *c = cctx->c;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg2(c, "%s tree at %"I64_FMT, name, cctx->bitrd.curpos);
	if(num_values_expected!=64 && num_values_expected!=256) goto done;
	de_dbg_indent(c, 1);
	n = (UI)dbuf_getbyte_p(cctx->bitrd.f, &cctx->bitrd.curpos);
	num_rle_items = n + 1;
	de_dbg2(c, "num RLE entries: %u", num_rle_items);

	de_dbg_indent(c, 1);
	for(i=0; i<num_rle_items; i++) {
		u8 b;
		UI this_bit_length;
		UI num_codes_with_this_bit_length;

		b = dbuf_getbyte_p(cctx->bitrd.f, &cctx->bitrd.curpos);
		num_codes_with_this_bit_length = ((UI)b >> 4) + 1;
		this_bit_length = ((UI)b & 0x0f) + 1;
		de_dbg3(c, "%u items (%u..%u) w/bit length %u", num_codes_with_this_bit_length,
			next_val, (UI)(next_val+num_codes_with_this_bit_length-1), this_bit_length);

		if(next_val < num_values_expected) {
			if(!huffman_record_len_for_range(c, tree->ht, (fmtutil_huffman_valtype)next_val,
				(i64)num_codes_with_this_bit_length, this_bit_length))
			{
				goto done;
			}
		}
		next_val += num_codes_with_this_bit_length;
	}
	de_dbg_indent(c, -1);

	// The Implode specification apparently requires the trees to always be fully
	// populated (with 256 or 64 items), even though that's inefficient, and there's
	// nothing about the format that really demands it.
	de_dbg2(c, "number of items: %u (expected %u)", next_val, num_values_expected);

	if(!fmtutil_huffman_make_canonical_code(c, tree->ht->bk, tree->ht->builder,
		FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES | FMTUTIL_MCTFLAG_LAST_CODE_FIRST, NULL))
	{
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int implode_read_trees(struct lzh_ctx *cctx)
{
	int retval = 0;

	if(cctx->implode_3_trees) {
		cctx->literals_tree.ht = fmtutil_huffman_create_decoder(cctx->c, 256, 256);
		if(!implode_read_a_tree(cctx, &cctx->literals_tree, 256, "literals")) {
			goto done;
		}
	}

	cctx->matchlengths_tree.ht = fmtutil_huffman_create_decoder(cctx->c, 64, 256);
	if(!implode_read_a_tree(cctx, &cctx->matchlengths_tree, 64, "match-lengths")) {
		goto done;
	}

	cctx->offsets_tree.ht = fmtutil_huffman_create_decoder(cctx->c, 64, 256);
	if(!implode_read_a_tree(cctx, &cctx->offsets_tree, 64, "offsets")) {
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static void decompress_implode_internal(struct lzh_ctx *cctx)
{
	UI rb_size;
	UI offset_num_low_bits;
	deark *c = cctx->c;

	rb_size = (cctx->implode_8k_buffer) ? 8192 : 4096;

	cctx->ringbuf = de_lz77buffer_create(c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;

	if(!implode_read_trees(cctx)) {
		cctx->err_flag = 1;
		goto done;
	}

	de_dbg2(c, "compressed data codes at %"I64_FMT, cctx->bitrd.curpos);
	offset_num_low_bits = (cctx->implode_8k_buffer) ? 7 : 6;

	while(1) {
		UI n;

		if(cctx->bitrd.eof_flag || cctx->err_flag) break;
		if(lzh_have_enough_output(cctx)) break;

		n = (UI)lzh_getbits(cctx, 1);
		if(n) { // literal
			u8 b;

			if(cctx->literals_tree.ht) {
				b = (u8)read_next_code_using_tree(cctx, &cctx->literals_tree);
			}
			else {
				b = (u8)lzh_getbits(cctx, 8);
			}
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "lit %u", (UI)b);
			}
			de_lz77buffer_add_literal_byte(cctx->ringbuf, b);
		}
		else { // match
			UI offset_low_bits, offset_high_bits, offset;
			UI matchlen_code, matchlen;

			offset_low_bits = (UI)lzh_getbits(cctx, offset_num_low_bits);
			offset_high_bits = (UI)read_next_code_using_tree(cctx, &cctx->offsets_tree);
			offset = (offset_high_bits << offset_num_low_bits) | offset_low_bits;

			matchlen_code = (UI)read_next_code_using_tree(cctx, &cctx->matchlengths_tree);
			if(matchlen_code == 63) {
				n = (UI)lzh_getbits(cctx, 8);
				matchlen = cctx->implode_min_match_len + 63 + n;
			}
			else {
				matchlen = cctx->implode_min_match_len + matchlen_code;
			}

			if(c->debug_level>=4) {
				de_dbg(c, "match d=%u l=%u", offset+1, matchlen);
			}
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-1-offset), matchlen);
		}
	}

done:
	;
}

#define IMPLODE_FLAG_8KDICT 0x0002
#define IMPLODE_FLAG_3TREES 0x0004

void fmtutil_decompress_zip_implode(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_zipimplode_params *params)
{
	struct lzh_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "implode";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 1;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	if(params->bit_flags & IMPLODE_FLAG_8KDICT) {
		cctx->implode_8k_buffer = 1;
	}
	if(params->bit_flags & IMPLODE_FLAG_3TREES) {
		cctx->implode_3_trees = 1;
	}
	if(params->mml_bug) {
		cctx->implode_min_match_len = cctx->implode_8k_buffer ? 3 : 2;
	}
	else {
		cctx->implode_min_match_len = cctx->implode_3_trees ? 3 : 2;
	}

	decompress_implode_internal(cctx);

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "Implode decoding error");
		goto done;
	}

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}

///////////////////// PKWARE DCL Implode

// These tables are compacted, and have two 4-bit values per byte. High bits first.
static const u8 dclimpl_litlengths[256/2] = {
	0xbc,0xcc,0xcc,0xcc,0xc8,0x7c,0xc7,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xdc,0xcc,0xcc,
	0x4a,0x8c,0xac,0xa8,0x77,0x89,0x76,0x78,0x76,0x77,0x77,0x87,0x78,0x8c,0xb7,0x9b,
	0xc6,0x76,0x65,0x78,0x86,0xb9,0x67,0x66,0x7b,0x66,0x67,0x98,0x99,0xb8,0xb9,0xc8,
	0xc5,0x66,0x65,0x66,0x65,0xb7,0x56,0x55,0x6a,0x55,0x55,0x87,0x88,0xab,0xbc,0xcc,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xdc,0xdd,0xdc,0xdd,0xdc,0xdd,0xdd,0xcd,0xdd,0xcc,0xcd,0xdd,0xdd,0xdd,0xdd,0xdd
};
static const u8 dclimpl_lenlengths[16/2] = {
	0x23,0x33,0x44,0x45,0x55,0x56,0x66,0x77
};
static const u8 dclimpl_distlengths[64/2] = {
	0x24,0x45,0x55,0x56,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x77,0x77,0x77,0x77,0x77,
	0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x88,0x88,0x88,0x88,0x88,0x88,0x88,0x88
};

static UI dclimplode_getcodelenfromarray(const u8 *arr, UI idx)
{
	if(idx%2==0) return (UI)(arr[idx/2]>>4);
	return (UI)(arr[idx/2] & 0x0f);
}

static void make_dclimplode_tree(deark *c, struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree,
	i64 num_codes, const u8 *codelengths)
{
	i64 i;

	tree->ht = fmtutil_huffman_create_decoder(c, num_codes, num_codes);

	for(i=0; i<num_codes; i++) {
		fmtutil_huffman_record_a_code_length(c, tree->ht->builder, (fmtutil_huffman_valtype)i,
			dclimplode_getcodelenfromarray(codelengths, (UI)i));
	}

	fmtutil_huffman_make_canonical_code(c, tree->ht->bk, tree->ht->builder,
		FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES | FMTUTIL_MCTFLAG_LAST_CODE_FIRST, NULL);
}

static void dclimplode_internal(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;
	u8 b;

	if(cctx->dcmpri->len==0) {
		// This special case is possibly a standard part of DCL Implode format:
		// A zero-length input file, with no header or stop code, decompresses to
		// a zero-length output file.
		goto done;
	}

	b = (u8)lzh_getbits(cctx, 8);
	if(b==1) {
		cctx->implode_3_trees = 1;
	}
	else if(b!=0) {
		cctx->err_flag = 1;
		goto done;
	}
	de_dbg2(c, "has literals tree: %u", (UI)cctx->implode_3_trees);

	cctx->dist_code_extra_bits = (UI)lzh_getbits(cctx, 8);
	de_dbg2(c, "dist code extra bits: %u", cctx->dist_code_extra_bits);
	if(cctx->dist_code_extra_bits<4 || cctx->dist_code_extra_bits>6) {
		cctx->err_flag = 1;
		goto done;
	}

	if(cctx->implode_3_trees) {
		make_dclimplode_tree(c, cctx, &cctx->literals_tree, 256, dclimpl_litlengths);
	}
	make_dclimplode_tree(c, cctx, &cctx->matchlengths_tree, 16, dclimpl_lenlengths);
	make_dclimplode_tree(c, cctx, &cctx->offsets_tree, 64, dclimpl_distlengths);

	// Need at least:
	//  1024 if dist_code_extra_bits==4
	//  2048 if dist_code_extra_bits==5
	//  4096 if dist_code_extra_bits==6
	cctx->ringbuf = de_lz77buffer_create(cctx->c, 4096);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb_flagerrors;

	while(1) {
		UI n;

		if(cctx->bitrd.eof_flag || cctx->err_flag) {
			if(!cctx->err_flag) {
				de_dfilter_set_errorf(c, cctx->dres, cctx->modname,
					"Decoding error (end-of-data code not found)");
				cctx->err_flag = 1;
			}
			goto done;
		}

		n = (UI)lzh_getbits(cctx, 1);
		if(n==0) { // literal
			u8 b;

			if(cctx->literals_tree.ht) {
				b = (u8)read_next_code_using_tree(cctx, &cctx->literals_tree);
			}
			else {
				b = (u8)lzh_getbits(cctx, 8);
			}
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "lit %u", (UI)b);
			}
			de_lz77buffer_add_literal_byte(cctx->ringbuf, b);
		}
		else {
			UI matchlen_code, matchlen;
			UI more_bits_count;
			UI more_bits;
			UI offset_code, offset;

			matchlen_code = (UI)read_next_code_using_tree(cctx, &cctx->matchlengths_tree);
			if(matchlen_code>=16) goto done;

			if(matchlen_code==0) {
				matchlen = 3;
			}
			else if(matchlen_code==1) {
				matchlen = 2;
			}
			else if(matchlen_code<=7) {
				matchlen = matchlen_code + 2;
			}
			else { // 8..15
				more_bits_count = matchlen_code - 7;
				more_bits = (UI)lzh_getbits(cctx, more_bits_count);
				matchlen = (1U << more_bits_count) + more_bits + 8;
			}
			if(matchlen==519) goto done;

			offset_code = (UI)read_next_code_using_tree(cctx, &cctx->offsets_tree);
			if(matchlen==2) {
				more_bits_count = 2;
			}
			else {
				more_bits_count = cctx->dist_code_extra_bits;
			}
			more_bits = (UI)lzh_getbits(cctx, more_bits_count);
			offset = (offset_code << more_bits_count) + more_bits;

			if(cctx->c->debug_level>=4) {
				de_dbg(c, "match d=%u l=%u", offset+1, matchlen);
			}
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-1-offset), matchlen);
		}
	}

done:
	;
}

void fmtutil_dclimplode_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct lzh_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "dclimplode";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 1;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	dclimplode_internal(cctx);

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "Decoding error");
		goto done;
	}

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}

//-------------------------- PAK/ARC "Distilled" --------------------------

#define DISTILLED_MAX_NODES 628

struct distilled_node {
	u8 in_use;
	u16 dval;
};

struct distilled_nodetable_decoder {
	deark *c;
	UI nodecount;
	u8 err_flag;
	struct fmtutil_huffman_decoder *ht; // An extra pointer; do not destroy
	struct distilled_node node[DISTILLED_MAX_NODES];
	char b2buf[72];
};

static void distilled_interpret_node_pair(struct distilled_nodetable_decoder *ntd,
	UI nodenum, u64 currcode, UI currcode_nbits);

// (This is similar to the code for Squeeze format.)
static void distilled_interpret_dval(struct distilled_nodetable_decoder *ntd,
	UI dval, u64 currcode, UI currcode_nbits)
{
	if(ntd->err_flag) return;
	if(currcode_nbits>=FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) {
		ntd->err_flag = 1;
		return;
	}

	if(dval < ntd->nodecount) {
		distilled_interpret_node_pair(ntd, dval, currcode, currcode_nbits);
	}
	else { // a leaf node
		fmtutil_huffman_valtype adj_value;

		adj_value = (fmtutil_huffman_valtype)(dval - ntd->nodecount);
		if(ntd->c->debug_level>=3) {
			de_dbg3(ntd->c, "code: \"%s\" = %d",
				de_print_base2_fixed(ntd->b2buf, sizeof(ntd->b2buf), currcode, currcode_nbits),
				(int)adj_value);
		}
		fmtutil_huffman_add_code(ntd->c, ntd->ht->bk, currcode, currcode_nbits, adj_value);
	}
}

static void distilled_interpret_node_pair(struct distilled_nodetable_decoder *ntd,
	UI nodenum, u64 currcode, UI currcode_nbits)
{
	if(ntd->err_flag) return;
	if(currcode_nbits >= FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) {
		ntd->err_flag = 1;
		return;
	}
	if(nodenum > ntd->nodecount-2) {
		ntd->err_flag = 1;
		return;
	}

	if(ntd->node[nodenum].in_use || ntd->node[nodenum+1].in_use) {
		ntd->err_flag = 1;
		return;
	}

	ntd->node[nodenum].in_use = 1;
	ntd->node[nodenum+1].in_use = 1;
	distilled_interpret_dval(ntd, ntd->node[nodenum].dval, currcode<<1, currcode_nbits+1);
	distilled_interpret_dval(ntd, ntd->node[nodenum+1].dval, (currcode<<1) | 1, currcode_nbits+1);
	ntd->node[nodenum].in_use = 0;
	ntd->node[nodenum+1].in_use = 0;
}

static void distilled_read_nodetable(deark *c, struct lzh_ctx *cctx)
{
	struct distilled_nodetable_decoder *ntd = NULL;

	UI k;
	UI code_len;
	UI num_codes_in_tree;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	ntd = de_malloc(c, sizeof(struct distilled_nodetable_decoder));
	ntd->c = c;

	de_dbg2(c, "[node table]");
	de_dbg_indent(c, 1);

	ntd->nodecount = (UI)de_bitreader_getbits(&cctx->bitrd, 16);
	de_dbg2(c, "node count: %u", ntd->nodecount);
	// Expected to be an even number from 2 to 628.
	// There are 315 codes: 256 literal, 1 special, 58 distance (3..60).
	// Max table entries needed is (315-1)*2 = 628.
	if(ntd->nodecount<2 || ntd->nodecount>DISTILLED_MAX_NODES ||
		(ntd->nodecount & 0x1))
	{
		cctx->err_flag = 1;
		goto done;
	}

	num_codes_in_tree = 1 + ntd->nodecount/2;

	code_len = (UI)de_bitreader_getbits(&cctx->bitrd, 8);
	de_dbg2(c, "code len: %u", code_len);
	if(code_len<1 || code_len>12) { // Expecting 9 or 10
		cctx->err_flag = 1;
		goto done;
	}

	de_dbg2(c, "[node table entries]");
	de_dbg_indent(c, 1);
	for(k=0; k<ntd->nodecount; k++) {
		UI val;

		val = (UI)de_bitreader_getbits(&cctx->bitrd, code_len);
		ntd->node[k].dval = val;
		de_dbg2(c, "node[%u] = %u", k, val);
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);
	de_dbg3(c, "[codebook for literals/lengths]");
	de_dbg_indent(c, 1);

	cctx->literals_tree.ht = fmtutil_huffman_create_decoder(c,
		(i64)num_codes_in_tree, (i64)num_codes_in_tree);

	ntd->ht = cctx->literals_tree.ht;
	distilled_interpret_node_pair(ntd, ntd->nodecount-2, 0, 0);

done:
	if(ntd) {
		de_free(c, ntd);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static UI get_lzhuf_p_len(UI n)
{
	UI p_len;

	if(n==0) p_len = 3;
	else if(n<4) p_len = 4;
	else if(n<12) p_len = 5;
	else if(n<24) p_len = 6;
	else if(n<48) p_len = 7;
	else p_len = 8;
	return p_len;
}

static void distilled_make_offsets_tree(deark *c, struct lzh_ctx *cctx)
{
	UI n;
	static const u8 distilled_offsetcodes[64] = {
		0x00,0x04,0x02,0x03,0x10,0x0c,0x0a,0x0e,0x11,0x0d,0x0b,0x0f,0x28,0x24,0x2c,0x2a,
		0x26,0x2e,0x29,0x25,0x2d,0x2b,0x27,0x2f,0x60,0x70,0x68,0x64,0x74,0x6c,0x62,0x72,
		0x6a,0x66,0x76,0x6e,0x61,0x71,0x69,0x65,0x75,0x6d,0x63,0x73,0x6b,0x67,0x77,0x6f,
		0xf0,0xf8,0xf4,0xfc,0xf2,0xfa,0xf6,0xfe,0xf1,0xf9,0xf5,0xfd,0xf3,0xfb,0xf7,0xff
	};
	char b2buf[72];

	cctx->offsets_tree.ht = fmtutil_huffman_create_decoder(c, 64, 64);
	de_dbg3(c, "[standard codebook for offsets]");
	de_dbg_indent(c, 1);
	for(n=0; n<64; n++) {
		UI nbits;
		u64 code;

		nbits = get_lzhuf_p_len(n);
		code = (u64)distilled_offsetcodes[n];

		if(c->debug_level>=3) {
			de_dbg3(c, "code: \"%s\" = %d",
				de_print_base2_fixed(b2buf, sizeof(b2buf), code, nbits), (int)n);
		}
		fmtutil_huffman_add_code(c, cctx->offsets_tree.ht->bk, code, nbits, (fmtutil_huffman_valtype)n);
	}
	de_dbg_indent(c, -1);
}

static UI distilled_get_num_extra_bits(struct lzh_ctx *cctx)
{
	UI x;
	i64 n = cctx->nbytes_written + 60;

	for(x=12; x>=6; x--) {
		if(n >= ((i64)1 << x)) return x-5;
	}
	return 0;
}

static void distilled_main(deark *c, struct lzh_ctx *cctx)
{
	int expecting_stop_code = 0;

	while(1) {
		UI code;

		if(cctx->bitrd.eof_flag) goto done;
		if(lzh_have_enough_output(cctx)) {
			// Try to make sure we read the STOP code, so we can report the
			// proper number of bytes consumed.
			if(expecting_stop_code) goto done;
			expecting_stop_code = 1;
		}

		code = read_next_code_using_tree(cctx, &cctx->literals_tree);

		if(code<256) { // literal
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)code);
		}
		else if(code==256) {
			goto done;
		}
		else { // match
			UI matchlen;
			UI matchdist;
			UI ocode1, ocode2;
			UI num_extra_bits;

			matchlen = code-254;
			ocode1 = read_next_code_using_tree(cctx, &cctx->offsets_tree);
			num_extra_bits = distilled_get_num_extra_bits(cctx);
			ocode2 = (UI)lzh_getbits(cctx, num_extra_bits);
			matchdist = (ocode1<<num_extra_bits)|ocode2;
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-1-matchdist),  matchlen);
		}
	}

done:
	;
}

void fmtutil_distilled_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct lzh_ctx *cctx = NULL;
	char pos_descr[32];

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "distilled";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 1;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, 8192);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb;
	de_lz77buffer_clear(cctx->ringbuf, 0x20);

	distilled_read_nodetable(c, cctx);
	if(cctx->err_flag) goto done;

	distilled_make_offsets_tree(c, cctx);

	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "cmpr data codes at %s", pos_descr);
	de_dbg_indent(c, 1);
	distilled_main(c, cctx);
	de_dbg_indent(c, -1);

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	if(cctx) {
		if(cctx->err_flag) {
			de_dfilter_set_generic_error(c, dres, cctx->modname);
		}
		destroy_lzh_ctx(cctx);
	}
}

//-------------------------- LZS (Stac) --------------------------

static void lzstac_decompress_block(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;

	while(1) {
		UI n;

		if(cctx->bitrd.eof_flag || cctx->err_flag) {
			if(!cctx->err_flag) {
				de_dfilter_set_errorf(c, cctx->dres, cctx->modname,
					"Decoding error (end-of-data code not found)");
				cctx->err_flag = 1;
			}
			goto done;
		}

		n = (UI)lzh_getbits(cctx, 1);
		if(n==0) { // a literal
			u8 b;

			b = (u8)lzh_getbits(cctx, 8);
			if(cctx->c->debug_level>=4) {
				de_dbg(c, "lit %u", (UI)b);
			}
			de_lz77buffer_add_literal_byte(cctx->ringbuf, b);
		}
		else { // an offset+distance, or a stop code

			UI matchlen_code, matchlen;
			UI offset_code, offset;

			// Read the offset

			n = (UI)lzh_getbits(cctx, 1);
			if(n==0) { // an 11-bit offset...
				offset_code = (UI)lzh_getbits(cctx, 11);
				if(offset_code==0) { // Expecting at least 128
					cctx->err_flag = 1;
					goto done;
				}
				offset = offset_code - 1;
			}
			else { // 7-bit offset, or stop code
				offset_code = (UI)lzh_getbits(cctx, 7);
				if(offset_code==0) {
					if(cctx->c->debug_level>=4) {
						de_dbg(c, "stop code");
					}
					goto done;
				}
				offset = offset_code - 1;

			}

			// Read the match-length

			matchlen_code = (UI)read_next_code_using_tree(cctx, &cctx->matchlengths_tree);

			if(matchlen_code < 6) {
				matchlen = matchlen_code + 2;
			}
			else {
				matchlen = 8; // This will be increased as we read more bits

				while(1) {
					matchlen_code = (UI)lzh_getbits(cctx, 4);
					matchlen += matchlen_code;

					// Arbitrary limit. The matchlen can definitely be *much* larger
					// than the history buffer.
					if(matchlen > 0x80000000) {
						cctx->err_flag = 1;
						goto done;
					}

					if(matchlen_code < 15) {
						break;
					}
				}
			}

			if(cctx->c->debug_level>=4) {
				de_dbg(c, "match d=%u l=%u", offset+1, matchlen);
			}
			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-1-offset), matchlen);
		}
	}

done:
	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
}

// codec_private_params = struct de_lzstac_params, or NULL.
//  params.flags:
//    0x1 = disallow zero blocks
//    0x2 = disallow more than 1 block
void fmtutil_lzstac_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct lzh_ctx *cctx = NULL;
	int block_count = 0;
	UI flags = 0;
	static const u8 lzstac_lencodes[7] = {
		// The first 6 codes are for lengths 2-7, and the last is special.
		0x00,0x01,0x02,0x0c,0x0d,0x0e,0x0f
	};
	static const u8 lzstac_lenlengths[7] = {
		0x02,0x02,0x02,0x04,0x04,0x04,0x04
	};

	if(codec_private_params) {
		struct de_lzstac_params *params;

		params = (struct de_lzstac_params*)codec_private_params;
		flags = params->flags;
	}

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "LZStac";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 0;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	lzh_make_tree_from_bytearrays(cctx, &cctx->matchlengths_tree,
		lzstac_lencodes, lzstac_lenlengths, 7, NULL);

	cctx->ringbuf = de_lz77buffer_create(cctx->c, 2048);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb_flagerrors;

	while(1) {
		if(block_count==0 && (dcmpri->len<=0) && !(flags & 0x1)) {
			// No input data (0 blocks), and it is allowed. Stop.
			break;
		}

		if(block_count>0 && (flags & 0x2)) {
			// More than 1 block not allowed, so stop.
			break;
		}

		de_dbg3(c, "LZS block at %"I64_FMT, cctx->bitrd.curpos);
		de_dbg_indent(c, 1);
		lzstac_decompress_block(cctx);
		de_dbg_indent(c, -1);

		block_count++;
		if(cctx->err_flag) break;
		if(cctx->bitrd.curpos >= cctx->bitrd.endpos) break;
	}

	if(cctx->err_flag) {
		de_dfilter_set_errorf(c, dres, cctx->modname, "Decoding error");
		goto done;
	}

	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}

//-------------------------- XPK:MASH --------------------------

struct mash_ctx {
	deark *c;
	u8 errflag;
	i64 cur_ipos;
	i64 end_ipos;
	i64 nbytes_written;
	const char *modname;
	struct de_bitbuf_lowlevel bbll;
	struct de_lz77buffer *ringbuf;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
};

static int mash_have_enough_output(struct mash_ctx *mctx)
{
	if(mctx->dcmpro->len_known &&
		mctx->nbytes_written >= mctx->dcmpro->expected_len)
	{
		return 1;
	}
	return 0;
}

static void mash_fill_bitbuf(struct mash_ctx *mctx)
{
	u8 b;

	if(mctx->errflag) return;
	if(mctx->cur_ipos >= mctx->end_ipos) {
		mctx->errflag = 1;
		return;
	}

	b = dbuf_getbyte_p(mctx->dcmpri->f, &mctx->cur_ipos);
	de_bitbuf_lowlevel_add_byte(&mctx->bbll, b);
}

static u8 mash_getbit(struct mash_ctx *mctx)
{
	u8 v;

	if(mctx->errflag) return 0;

	if(mctx->bbll.nbits_in_bitbuf==0) {
		mash_fill_bitbuf(mctx);
	}

	v = (u8)de_bitbuf_lowlevel_get_bits(&mctx->bbll, 1);

	return v;
}

static UI mash_getbits(struct mash_ctx *mctx, UI nbits)
{
	UI i;
	UI n = 0;

	for(i=0; i<nbits; i++) {
		n <<= 1;
		n |= (UI)mash_getbit(mctx);
	}

	return n;
}

static UI mash_read_offset(struct mash_ctx *mctx)
{
	UI ocode;
	UI offset;
	static const u8 numextrabits[8] = {5, 7, 9, 10, 11, 12, 13, 14};

	ocode = mash_getbits(mctx, 3);
	offset = mash_getbits(mctx, numextrabits[ocode]);
	if(ocode==1) {
		offset += 32;
	}
	else if(ocode>=2) {
		offset += (1<<numextrabits[ocode]) - 352;
	}
	return offset;
}

static UI mash_read_run_of_1_bits(struct mash_ctx *mctx, UI max1bits)
{
	UI count_of_1s = 0;

	while(1) {
		u8 b;

		if(count_of_1s>=max1bits) break;
		b = mash_getbit(mctx);
		if(b==0) break;
		count_of_1s++;
	}

	return count_of_1s;
}

static void mash_main(deark *c, struct mash_ctx *mctx)
{
	while(1) {
		UI count_of_1s;
		UI offset = 0;
		UI matchlen = 0;
		UI unc_run_len = 0;
		u8 hflag1, hflag2;

		if(mctx->errflag) goto done;
		if(mash_have_enough_output(mctx)) goto done;

		// Read/decode the length of an uncompressed run (may be 0)

		count_of_1s = mash_read_run_of_1_bits(mctx, 6);
		if(count_of_1s<=5) {
			unc_run_len = count_of_1s;
		}
		else {
			count_of_1s = mash_read_run_of_1_bits(mctx, 16);
			if(count_of_1s>=16) {
				// TODO: Verify this limit
				mctx->errflag = 1;
				goto done;
			}

			unc_run_len = mash_getbits(mctx, count_of_1s+1);
			unc_run_len += (2<<count_of_1s) + 4;
		}

		// Copy the literal bytes

		if(unc_run_len>0) {
			UI ii;
			u8 ib;

			for(ii=0; ii<unc_run_len; ii++) {
				if(mctx->cur_ipos >= mctx->end_ipos) {
					mctx->errflag = 1;
					return;
				}
				ib = dbuf_getbyte_p(mctx->dcmpri->f, &mctx->cur_ipos);
				if(c->debug_level>=4) {
					de_dbg(c, "lit %u", (UI)ib);
				}
				de_lz77buffer_add_literal_byte(mctx->ringbuf, ib);
				if(mctx->errflag) goto done;
			}
		}

		if(mash_have_enough_output(mctx)) goto done;

		// Read/decode a matchlen and offset

		hflag1 = mash_getbit(mctx);
		if(hflag1==0) {
			hflag2 = mash_getbit(mctx);
			if(hflag2==0) {
				matchlen = 2;
				offset = mash_getbits(mctx, 9);
			}
			else {
				matchlen = 3;
				offset = mash_read_offset(mctx);
			}
		}
		else {
			count_of_1s = mash_read_run_of_1_bits(mctx, 15);
			if(count_of_1s>=15) {
				// TODO: Verify this limit
				mctx->errflag = 1;
				goto done;
			}

			matchlen = mash_getbits(mctx, count_of_1s+1);
			matchlen += (2<<count_of_1s) + 2;
			offset = mash_read_offset(mctx);
		}

		if(c->debug_level>=4) {
			de_dbg(c, "match d=%u l=%u", offset, matchlen);
		}

		if(offset==0) {
			// TODO: Figure out what offset 0 means
			// (seen at end of final chunk).
			goto done;
		}

		if((i64)offset > mctx->nbytes_written) {
			de_dfilter_set_errorf(c, mctx->dres, mctx->modname, "Bad offset");
			mctx->errflag = 1;
			goto done;
		}

		de_lz77buffer_copy_from_hist(mctx->ringbuf,
			(UI)(mctx->ringbuf->curpos-offset), matchlen);
	}

done:
	;
}

static void mash_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct mash_ctx *mctx = (struct mash_ctx*)rb->userdata;

	if(mash_have_enough_output(mctx)) {
		// This ought to be an error, but in practice there's often an extra
		// decompressed byte that we have to ignore.
		return;
	}
	dbuf_writebyte(mctx->dcmpro->f, n);
	mctx->nbytes_written++;
}

void fmtutil_xpkMASH_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct mash_ctx *mctx = NULL;

	mctx = de_malloc(c, sizeof(struct mash_ctx));
	mctx->c = c;
	mctx->modname = "mash";
	mctx->bbll.is_lsb = 0;
	mctx->dcmpri = dcmpri;
	mctx->dcmpro = dcmpro;
	mctx->dres = dres;
	mctx->cur_ipos = dcmpri->pos;
	mctx->end_ipos = dcmpri->pos + dcmpri->len;

	mctx->ringbuf = de_lz77buffer_create(c, 32768);
	mctx->ringbuf->userdata = (void*)mctx;
	mctx->ringbuf->writebyte_cb = mash_lz77buf_writebytecb;

	mash_main(c, mctx);

	if(mctx->errflag) {
		de_dfilter_set_generic_error(c, dres, mctx->modname);
	}
	de_lz77buffer_destroy(c, mctx->ringbuf);
	de_free(c, mctx);
}

///////////////////// InstaCompOne

static UI read_run_of_1_bits(struct lzh_ctx *cctx, UI max1bits)
{
	UI count_of_1s = 0;

	while(1) {
		u8 b;

		if(count_of_1s>=max1bits) break;
		b = (u8)lzh_getbits(cctx, 1);
		if(b==0) break;
		count_of_1s++;
	}

	return count_of_1s;
}

static void make_ic1_trees(deark *c, struct lzh_ctx *cctx)
{
#define ICL_NUM_ML_CODES 14
	static const u8 codes[ICL_NUM_ML_CODES] = {
		0,1,4,0xa,0xb,0x18,0x19,0x34,0x35,0x36,0x37,0x0e,0x1e,0x1f };
	static const u8 lengths[ICL_NUM_ML_CODES] = {
		2,2,3,4,  4,  5,   5,   6,   6,   6,   6,   4,   5,   5 };
	static const u8 vals[ICL_NUM_ML_CODES] = {
		0,1,2,3,  4,  5,   6,   7,   8,   9,   10,  103, 104, 105 };
	size_t k;

	cctx->matchlengths_tree.ht = fmtutil_huffman_create_decoder(c, ICL_NUM_ML_CODES, 0);

	for(k=0; k<ICL_NUM_ML_CODES; k++) {
		fmtutil_huffman_add_code(c, cctx->matchlengths_tree.ht->bk,
			codes[k], lengths[k], vals[k]);
	}
}

static UI ic1_read_matchlencode(struct lzh_ctx *cctx)
{
	fmtutil_huffman_valtype n = 0;
	UI v = 0;
	UI num_extra_bits = 0;

	n = read_next_code_using_tree(cctx, &cctx->matchlengths_tree);

	if(n<100) {
		v = (UI)n;
	}
	else if(n==103) {
		v = 11;
		num_extra_bits = 3;
	}
	else if(n==104) {
		v = 19;
		num_extra_bits = 3;
	}
	else { // 105
		UI count_of_1s;

		// Note that we've already read 5 1s.
		count_of_1s = (UI)read_run_of_1_bits(cctx, 32);
		if(count_of_1s>26) { // TODO: What is the limit?
			de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
				"Match-len too large");
			cctx->err_flag = 1;
			goto done;
		}
		count_of_1s += 5;
		num_extra_bits = count_of_1s;
		v = (1U<<count_of_1s) - 5;
	}

	if(num_extra_bits>0) {
		UI x;

		x = (UI)lzh_getbits(cctx, num_extra_bits);
		v += x;
	}

done:
	return v;
}

static UI ic1_read_litlen(struct lzh_ctx *cctx)
{
	UI n1;
	UI x;
	UI v = 0;

	n1 = read_run_of_1_bits(cctx, 5);
	v = 1<<n1;
	x = (UI)lzh_getbits(cctx, n1);
	v = v | x;
	return v;
}

static UI ic1_read_distance(struct lzh_ctx *cctx)
{
	i64 bd;
	UI v = 0;
	UI n_extra_bits1 = 0;
	UI n_extra_bits2 = 0;
	UI bias1 = 0;
	UI code11_param = 0;
	u8 b0, b1;
	deark *c = cctx->c;

	bd = cctx->nbytes_written;

	if(bd<=10) {
		n_extra_bits1 = 2;
	}
	else if(bd<=20) {
		n_extra_bits1 = 3;
	}
	else if(bd<=40) {
		n_extra_bits1 = 4;
	}
	else if(bd<=80) {
		n_extra_bits1 = 5;
	}
	else if(bd<=160) {
		n_extra_bits1 = 6;
	}
	else if(bd<=672) {
		n_extra_bits1 = 7;
	}
	else if(bd<=1000) {
		// ??? Obviously this should be 1344, not 1000. But 1344 doesn't work.
		n_extra_bits1 = 8;
	}
	else if(bd<=2688) {
		n_extra_bits1 = 9;
	}
	else if(bd<=5376) {
		n_extra_bits1 = 10;
	}
	else if(bd<=10752) {
		n_extra_bits1 = 11;
	}
	else if(bd<=21504) {
		n_extra_bits1 = 12;
	}
	else {
		n_extra_bits1 = 13;
	}

	if(n_extra_bits1>=2) {
		n_extra_bits2 = n_extra_bits1 - 2;
		bias1 = 1U<<n_extra_bits2;
	}
	if(n_extra_bits1>=3) {
		code11_param = (1U<<(n_extra_bits1-3))*10;
	}

	b0 = (u8)lzh_getbits(cctx, 1);
	if(b0==1) {
		b1 = (u8)lzh_getbits(cctx, 1);
		if(b1==0) { // addressing mode "10"
			v = (UI)lzh_getbits(cctx, n_extra_bits1);
			v += bias1;
		}
		else { // addressing mode "11"
			if(code11_param) {
				UI n_extra_bits3;

				if(bd>=1652 && bd<=1664) {
					// FIXME: This hack probably shouldn't be here, and this range
					// is surely too small.
					n_extra_bits3 = 11;
				}
				else if(bd>43008 && bd<=65536) {
					n_extra_bits3 = 15;
				}
				else {
					n_extra_bits3 = (UI)de_log2_rounded_up((i64)bd-(i64)code11_param);
				}

				v = (UI)lzh_getbits(cctx, n_extra_bits3);
				v += code11_param;
			}
			else {
				cctx->err_flag = 1;
				de_dfilter_set_errorf(c, cctx->dres, cctx->modname,
					"TODO code11 bd=%"I64_FMT, bd);
				goto done;
			}
		}
	}
	else { // addressing mode "0"
		v = (UI)lzh_getbits(cctx, n_extra_bits2);
	}

done:
	return v;
}

static void ic1_internal(struct lzh_ctx *cctx)
{
	deark *c = cctx->c;
	u8 mode = 1;
	UI k;
	char descr[32];

	(void)lzh_getbits(cctx, 32); // unused?

	make_ic1_trees(c, cctx);

	cctx->ringbuf = de_lz77buffer_create(cctx->c, 65536*2);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzh_lz77buf_writebytecb_flagerrors;

	while(1) {
		UI matchlencode;

		if(c->debug_level>=4) {
			de_bitreader_describe_curpos(&cctx->bitrd, descr, sizeof(descr));
			de_dbg(c, "at %s mode=%u", descr, (UI)mode);
		}

		if(cctx->bitrd.eof_flag || cctx->err_flag) {
			goto done;
		}
		if(lzh_have_enough_output(cctx)) {
			goto done;
		}

		if(cctx->nbytes_written >= 65536) {
			cctx->err_flag = 1;
			de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
				"Files over 64k are not supported");
			goto done;
		}

		matchlencode = ic1_read_matchlencode(cctx);
		if(cctx->err_flag) goto done;

		if(matchlencode>0 || mode==0) {
			UI matchlen;
			UI offset;

			matchlen = matchlencode + 2;
			if(mode==0) {
				matchlen++;
			}

			offset = ic1_read_distance(cctx);
			if(cctx->err_flag) goto done;
			if(offset > cctx->nbytes_written) {
				cctx->err_flag = 1;
				de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
					"Bad distance code: %u", offset);
				goto done;
			}

			if(c->debug_level>=4) {
				de_dbg(c, "op=%"I64_FMT" match d=%u l=%u", cctx->nbytes_written,
					offset+1, matchlen);
			}

			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos-offset-1), matchlen);

			mode = 1;
		}
		else { // run of literals
			UI litlen;

			litlen = ic1_read_litlen(cctx);
			if(c->debug_level>=4) {
				de_dbg(c, "op=%"I64_FMT" lit_run %u", cctx->nbytes_written,
					litlen);
			}
			for(k=0; k<litlen; k++) {
				u8 b;
				b = (u8)lzh_getbits(cctx, 8);
				de_lz77buffer_add_literal_byte(cctx->ringbuf, b);
			}

			mode = (litlen < 63) ? 0 : 1;
		}
	}

done:
	;
}

void fmtutil_ic1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct lzh_ctx *cctx = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "instacomp1";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;

	cctx->bitrd.bbll.is_lsb = 0;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	ic1_internal(cctx);

	if(cctx->err_flag) {
		// A default error message
		de_dfilter_set_errorf(c, dres, cctx->modname, "Decoding error");
		goto done;
	}

	de_bitreader_skip_to_byte_boundary(&cctx->bitrd);
	cctx->dres->bytes_consumed = cctx->bitrd.curpos - cctx->dcmpri->pos;
	if(cctx->dres->bytes_consumed<0) {
		cctx->dres->bytes_consumed = 0;
	}
	cctx->dres->bytes_consumed_valid = 1;

done:
	destroy_lzh_ctx(cctx);
}
