// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Functions related to Huffman coding decompression

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#define NODE_REF_TYPE u32
#define MAX_MAX_NODES  66000

struct huffman_nval_pointer_data {
	NODE_REF_TYPE noderef;
};
struct huffman_nval_value_data {
	fmtutil_huffman_valtype value;
};

union huffman_nval_data {
	struct huffman_nval_pointer_data hnpd;
	struct huffman_nval_value_data hnvd;
};

struct huffman_node {
#define CHILDSTATUS_UNUSED  0
#define CHILDSTATUS_POINTER 1
#define CHILDSTATUS_VALUE   2
	u8 child_status[2];
	u8 depth;
	union huffman_nval_data child[2];
};

struct huffman_lengths_arr_item {
	fmtutil_huffman_valtype val;
	UI len;
};

struct fmtutil_huffman_code_builder {
	i64 lengths_arr_numalloc;
	i64 lengths_arr_numused;
	struct huffman_lengths_arr_item *lengths_arr; // array[lengths_arr_numalloc]
};

struct fmtutil_huffman_cursor {
	NODE_REF_TYPE curr_noderef;
};

struct fmtutil_huffman_codebook {
	i64 max_nodes;
	NODE_REF_TYPE next_avail_node;
	NODE_REF_TYPE nodes_alloc;
	struct huffman_node *nodes; // array[nodes_alloc]
	u8 has_null_code;
	fmtutil_huffman_valtype value_of_null_code;

	i64 num_codes;
	UI max_bits;
};

// Ensure that at least n nodes are allocated (0 through n-1)
static int huffman_ensure_alloc(deark *c, struct fmtutil_huffman_codebook *bk, NODE_REF_TYPE n)
{
	i64 new_nodes_alloc;

	if(n <= bk->nodes_alloc) return 1;
	if((i64)n > bk->max_nodes) return 0;

	new_nodes_alloc = (i64)bk->nodes_alloc * 2;
	if(new_nodes_alloc > bk->max_nodes) new_nodes_alloc = bk->max_nodes;
	if(new_nodes_alloc < (i64)n) new_nodes_alloc = (i64)n;
	if(new_nodes_alloc < 16) new_nodes_alloc = 16;

	bk->nodes = de_reallocarray(c, bk->nodes, bk->nodes_alloc, sizeof(struct huffman_node),
		new_nodes_alloc);
	bk->nodes_alloc = (NODE_REF_TYPE)new_nodes_alloc;
	return 1;
}

// Tracks the number of items with VALUE status ("codes").
static void huffman_setchildstatus(struct fmtutil_huffman_codebook *bk, NODE_REF_TYPE n,
	u8 child_idx, u8 newstatus)
{
	if(n>=bk->nodes_alloc) return;
	if(child_idx>1) return;

	if(bk->nodes[n].child_status[child_idx]==newstatus) return;
	if(bk->nodes[n].child_status[child_idx]==CHILDSTATUS_VALUE) {
		bk->num_codes--;
	}
	if(newstatus==CHILDSTATUS_VALUE) {
		bk->num_codes++;
	}
	bk->nodes[n].child_status[child_idx] = newstatus;
}

// The size of the longest current code.
// This is mainly for debugging info -- it is not guaranteed to be correct if
// the tree was constructed improperly.
UI fmtutil_huffman_get_max_bits(struct fmtutil_huffman_codebook *bk)
{
	return bk->max_bits;
}

// The number of codes (symbols) in the the tree.
// This is mainly for debugging info -- it is not guaranteed to be correct if
// the tree was constructed improperly.
i64 fmtutil_huffman_get_num_codes(struct fmtutil_huffman_codebook *bk)
{
	if(bk->num_codes>=0) return bk->num_codes;
	return 0;
}

void fmtutil_huffman_reset_cursor(struct fmtutil_huffman_cursor *cursor)
{
	cursor->curr_noderef = 0;
}

// Add a code, adding to the current tree structure as needed. Codes can be
// added in any order.
//
// If inconsistent codes are added (i.e. a code is a prefix of another code, or
// the tree is left incomplete), we only promise that it will be safe to use
// the decoding functions. Such errors will not necessarily be detected.
//
// Note that adding the 0-length code is allowed.
int fmtutil_huffman_add_code(deark *c, struct fmtutil_huffman_codebook *bk,
	u64 code, UI code_nbits, fmtutil_huffman_valtype val)
{
	UI k;
	NODE_REF_TYPE curr_noderef = 0; // Note that this may temporarily point to an unallocated node
	int retval = 0;

	if(code_nbits>FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) goto done;

	if(code_nbits<1) {
		bk->value_of_null_code = val;
		bk->has_null_code = 1;
		retval = 1;
		goto done;
	}
	bk->has_null_code = 0;

	if(code_nbits > bk->max_bits) {
		bk->max_bits = code_nbits;
	}

	// Iterate through the bits, high bit first.
	for(k=0; k<code_nbits; k++) {
		UI child_idx; // 0 or 1

		// Make sure the current node exists
		if(curr_noderef >= bk->nodes_alloc) {
			if(!huffman_ensure_alloc(c, bk, curr_noderef+1)) goto done;
		}
		// Claim the current node, if necessary
		if(curr_noderef >= bk->next_avail_node) {
			bk->next_avail_node = curr_noderef+1;
			bk->nodes[curr_noderef].depth = (u8)k;
		}

		child_idx = (code>>(code_nbits-1-k))&0x1;

		if(k==code_nbits-1) {
			// Reached the "leaf" node. Set the value for this child_idx.
			huffman_setchildstatus(bk, curr_noderef, child_idx, CHILDSTATUS_VALUE);
			bk->nodes[curr_noderef].child[child_idx].hnvd.value = val;
		}
		else {
			// Not at the leaf node yet.
			if(bk->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_POINTER) {
				// It's already a pointer.
				curr_noderef = bk->nodes[curr_noderef].child[child_idx].hnpd.noderef;
			}
			else {
				NODE_REF_TYPE next_noderef;

				// It's not a pointer -- make it one.
				if(bk->next_avail_node >= bk->max_nodes) goto done;
				next_noderef = bk->next_avail_node;
				huffman_setchildstatus(bk, curr_noderef, child_idx, CHILDSTATUS_POINTER);
				bk->nodes[curr_noderef].child[child_idx].hnpd.noderef = next_noderef;
				curr_noderef = next_noderef;
			}
		}
	}

	retval = 1;

done:
	return retval;
}

// Caller supplies one bit of data to the decoder (the low bit of bitval).
// Returns:
//  1 = This was the last bit of a code; value returned in *pval
//  2 = Need more bits (*pval unchanged)
//  0 = Error (*pval unchanged)
// If return value is not 2, resets the cursor before returning.
// Note that, by itself, this function cannot read the zero-length code.
int fmtutil_huffman_decode_bit(struct fmtutil_huffman_codebook *bk, struct fmtutil_huffman_cursor *cursor,
	u8 bitval, fmtutil_huffman_valtype *pval)
{
	UI child_idx;
	int retval = 0;
	NODE_REF_TYPE curr_noderef = cursor->curr_noderef;

	if(curr_noderef >= bk->nodes_alloc) goto done;
	if(curr_noderef >= bk->next_avail_node) goto done;
	child_idx = bitval & 0x01;

	if(bk->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_VALUE) {
		*pval = bk->nodes[curr_noderef].child[child_idx].hnvd.value;
		retval = 1;
		goto done;
	}
	else if(bk->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_POINTER) {
		cursor->curr_noderef = bk->nodes[curr_noderef].child[child_idx].hnpd.noderef;
		retval = 2;
		goto done;
	}

done:
	if(retval!=2) {
		fmtutil_huffman_reset_cursor(cursor);
	}
	return retval;
}

// Read the next Huffman code from a bitreader, and decode it.
// *pval will always be written to. On error, it will be set to 0.
// pnbits returns the number of bits read. Can be NULL.
// Return value:
//  nonzero on success
//  0 on error - Can happen if the tree was not constructed properly, or on EOF
//    (bitrd->eof_flag can distinguish these cases).
int fmtutil_huffman_read_next_value(struct fmtutil_huffman_codebook *bk,
	struct de_bitreader *bitrd, fmtutil_huffman_valtype *pval, UI *pnbits)
{
	int bitcount = 0;
	int retval = 0;
	struct fmtutil_huffman_cursor tmpcursor;

	if(bitrd->eof_flag) goto done;
	tmpcursor.curr_noderef = 0;

	if(bk->has_null_code) {
		*pval = bk->value_of_null_code;
		retval = 1;
		goto done;
	}

	while(1) {
		int ret;
		u8 b;

		b = (u8)de_bitreader_getbits(bitrd, 1);
		if(bitrd->eof_flag) goto done;
		bitcount++;
		if(bitcount>FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) goto done; // Should be impossible

		ret = fmtutil_huffman_decode_bit(bk, &tmpcursor, b, pval);
		if(ret==1) { // finished the code
			retval = 1;
			goto done;
		}
		else if(ret!=2) { // decoding error
			goto done;
		}
	}
done:
	if(!retval) {
		*pval = 0;
	}
	if(pnbits) {
		*pnbits = retval ? bitcount : 0;
	}
	return retval;
}

// For debugging
void fmtutil_huffman_dump(deark *c, struct fmtutil_huffman_decoder *ht)
{
	NODE_REF_TYPE k;
	de_ucstring *tmps = NULL;

	de_dbg(c, "internal huffman table:");
	de_dbg_indent(c, 1);

	de_dbg(c, "number of codes: %"I64_FMT, fmtutil_huffman_get_num_codes(ht->bk));
	de_dbg(c, "max code size: %u bits", fmtutil_huffman_get_max_bits(ht->bk));
	tmps = ucstring_create(c);
	for(k=0; k<ht->bk->next_avail_node && k<ht->bk->nodes_alloc; k++) {
		UI child_idx;
		struct huffman_node *nd = &ht->bk->nodes[k];

		ucstring_empty(tmps);
		ucstring_printf(tmps, DE_ENCODING_LATIN1, "node[%u]: depth=%u (", (UI)k, (UI)nd->depth);

		for(child_idx=0; child_idx<=1; child_idx++) {
			if(child_idx==1) {
				ucstring_append_sz(tmps, " ", DE_ENCODING_LATIN1);
			}
			if(nd->child_status[child_idx]==CHILDSTATUS_POINTER) {
				ucstring_printf(tmps, DE_ENCODING_LATIN1, "next=%u",
					(UI)nd->child[child_idx].hnpd.noderef);
			}
			else if(nd->child_status[child_idx]==CHILDSTATUS_VALUE) {
				ucstring_printf(tmps, DE_ENCODING_LATIN1, "value=%d",
					(int)nd->child[child_idx].hnvd.value);
			}
			else {
				ucstring_append_sz(tmps, "unused", DE_ENCODING_LATIN1);
			}
		}
		ucstring_printf(tmps, DE_ENCODING_LATIN1, ")");
		de_dbg(c, "%s", ucstring_getpsz_d(tmps));
	}
	ucstring_destroy(tmps);
	de_dbg_indent(c, -1);
}

i64 fmtutil_huffman_hcb_get_num_codes(struct fmtutil_huffman_code_builder *builder)
{
	return builder->lengths_arr_numused;
}

// This is only used with fmtutil_huffman_make_canonical_tree().
// Call this first, once per item.
// The order that you supply the items matters, at least within the set of items
// having the same length.
// Cannot be used for zero-length items. If len==0, it's a successful no-op.
int fmtutil_huffman_record_a_code_length(deark *c, struct fmtutil_huffman_code_builder *builder,
	fmtutil_huffman_valtype val, UI len)
{
	if(len==0) return 1;
	if(len > FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) return 0;
	if(builder->lengths_arr_numused > MAX_MAX_NODES) return 0;

	if(builder->lengths_arr_numused >= builder->lengths_arr_numalloc) {
		i64 new_numalloc;

		new_numalloc = builder->lengths_arr_numused + 128;
		builder->lengths_arr = de_reallocarray(c, builder->lengths_arr, builder->lengths_arr_numalloc,
			sizeof(struct huffman_lengths_arr_item), new_numalloc);
		builder->lengths_arr_numalloc = new_numalloc;
	}
	builder->lengths_arr[builder->lengths_arr_numused].val = val;
	builder->lengths_arr[builder->lengths_arr_numused++].len = len;
	return 1;
}

// The usual canonical format - leaves are left-aligned
static int fmtutil_huffman_make_canonical_tree1(deark *c, struct fmtutil_huffman_codebook *bk,
	struct fmtutil_huffman_code_builder *builder, UI max_sym_len_used)
{
	UI symlen;
	UI codes_count_total = 0;
	UI prev_code_bit_length = 0;
	u64 prev_code = 0;
	int retval = 0;
	char b2buf[72];

	// For each possible symbol length...
	for(symlen=1; symlen<=max_sym_len_used; symlen++) {
		UI k;

		// Find all the codes that use this symbol length, in order
		for(k=0; k<(UI)builder->lengths_arr_numused; k++) {
			int ret;
			u64 thiscode;

			if(builder->lengths_arr[k].len != symlen) continue;
			// Found a code of the length we're looking for.

			if(codes_count_total==0) {
				thiscode = 0;
			}
			else {
				thiscode = prev_code + 1;
				if(symlen > prev_code_bit_length) {
					thiscode <<= (symlen - prev_code_bit_length);
				}
			}

			prev_code = thiscode;
			prev_code_bit_length = symlen;
			codes_count_total++;

			if(c->debug_level>=3) {
				de_dbg3(c, "code: \"%s\" = %d",
					de_print_base2_fixed(b2buf, sizeof(b2buf), thiscode, symlen),
					(int)builder->lengths_arr[k].val);
			}
			ret = fmtutil_huffman_add_code(c, bk, thiscode, symlen, builder->lengths_arr[k].val);
			if(!ret) {
				goto done;
			}
		}
	}
	retval = 1;

done:
	return retval;
}

// "pack" style - branches are left-aligned
static int fmtutil_huffman_make_canonical_tree2(deark *c, struct fmtutil_huffman_codebook *bk,
	struct fmtutil_huffman_code_builder *builder, UI max_sym_len_used)
{
	UI symlen;
	UI codes_count_total = 0;
	UI prev_code_bit_length = 0;
	u64 prev_code = 0;
	int retval = 0;
	char b2buf[72];

	// For each possible symbol length...
	for(symlen=max_sym_len_used; symlen>=1; symlen--) {
		UI k;

		// Find all the codes that use this symbol length, in order
		for(k=0; k<(UI)builder->lengths_arr_numused; k++) {
			int ret;
			u64 this_code;

			if(builder->lengths_arr[k].len != symlen) continue;
			// Found a code of the length we're looking for.

			if(codes_count_total==0) {
				this_code = 0;
			}
			else  {
				this_code = (prev_code>>(prev_code_bit_length-symlen)) + 1;
			}

			prev_code = this_code;
			prev_code_bit_length = symlen;
			codes_count_total++;

			if(c->debug_level>=3) {
				de_dbg3(c, "code: \"%s\" = %d",
					de_print_base2_fixed(b2buf, sizeof(b2buf), this_code, symlen),
					(int)builder->lengths_arr[k].val);
			}
			ret = fmtutil_huffman_add_code(c, bk, this_code, symlen, builder->lengths_arr[k].val);
			if(!ret) {
				goto done;
			}
		}
	}
	retval = 1;

done:
	return retval;
}

static void reverse_lengths_array(struct fmtutil_huffman_code_builder *builder)
{
	i64 i;
	i64 num_swaps = builder->lengths_arr_numused / 2;
	struct huffman_lengths_arr_item tmpitem;

	for(i=0; i<num_swaps; i++) {
		tmpitem = builder->lengths_arr[i]; // struct copy
		builder->lengths_arr[i] = builder->lengths_arr[builder->lengths_arr_numused-1-i];
		builder->lengths_arr[builder->lengths_arr_numused-1-i] = tmpitem;
	}
}

// Call this after calling huffman_record_item_length() (usually many times).
// Creates a canonical Huffman tree derived from the known code lengths.
// 'title' is just for the dbg messages, and can be NULL.
int fmtutil_huffman_make_canonical_code(deark *c, struct fmtutil_huffman_codebook *bk,
	struct fmtutil_huffman_code_builder *builder, UI flags, const char *title)
{
	UI max_sym_len_used;
	UI i;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg3(c, "%s:", (title?title:"derived huffman codebook"));
	de_dbg_indent(c, 1);

	if(!builder->lengths_arr) {
		retval = 1;
		goto done;
	}

	if(flags & FMTUTIL_MCTFLAG_LAST_CODE_FIRST) {
		// Bit of a hack. Instead of each worker function having to have a way
		// to read the array from back to front, reverse the order of items in
		// the array, so we don't have to deal with it later.
		reverse_lengths_array(builder);
	}

	// Find the maximum length
	max_sym_len_used = 0;
	for(i=0; i<(UI)builder->lengths_arr_numused; i++) {
		if(builder->lengths_arr[i].len > max_sym_len_used) {
			max_sym_len_used = builder->lengths_arr[i].len;
		}
	}
	if(max_sym_len_used>FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) {
		goto done;
	}

	if(flags & FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES) {
		retval = fmtutil_huffman_make_canonical_tree2(c, bk, builder, max_sym_len_used);
	}
	else {
		retval = fmtutil_huffman_make_canonical_tree1(c, bk, builder, max_sym_len_used);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static struct fmtutil_huffman_codebook *huffman_create_codebook(deark *c,
	i64 initial_codes, i64 max_codes)
{
	struct fmtutil_huffman_codebook *bk;
	i64 initial_nodes;

	bk = de_malloc(c, sizeof(struct fmtutil_huffman_codebook));
	if(max_codes>0) {
		bk->max_nodes = max_codes;
	}
	else {
		bk->max_nodes = MAX_MAX_NODES;
	}
	if(bk->max_nodes > MAX_MAX_NODES) {
		bk->max_nodes = MAX_MAX_NODES;
	}

	if(initial_codes>0) {
		initial_nodes = initial_codes;
	}
	else {
		initial_nodes = 1;
	}
	if(initial_nodes > MAX_MAX_NODES) {
		initial_nodes = MAX_MAX_NODES;
	}

	huffman_ensure_alloc(c, bk, (NODE_REF_TYPE)initial_nodes);
	bk->next_avail_node = 0;
	bk->num_codes = 0;
	bk->max_bits = 0;
	return bk;
}

static void huffman_destroy_codebook(deark *c, struct fmtutil_huffman_codebook *bk)
{
	if(!bk) return;
	de_free(c, bk->nodes);
	de_free(c, bk);
}

// initial_codes: If not 0, pre-allocate enough nodes for this many codes.
// max_codes: If not 0, attempting to add substantially more codes than this will fail.
struct fmtutil_huffman_decoder *fmtutil_huffman_create_decoder(deark *c, i64 initial_codes, i64 max_codes)
{
	struct fmtutil_huffman_decoder *ht = NULL;

	ht = de_malloc(c, sizeof(struct fmtutil_huffman_decoder));
	ht->cursor = de_malloc(c, sizeof(struct fmtutil_huffman_cursor));
	ht->bk = huffman_create_codebook(c, initial_codes, max_codes);
	ht->builder = de_malloc(c, sizeof(struct fmtutil_huffman_code_builder));
	fmtutil_huffman_reset_cursor(ht->cursor);
	return ht;
}

void fmtutil_huffman_destroy_decoder(deark *c, struct fmtutil_huffman_decoder *ht)
{
	if(!ht) return;
	huffman_destroy_codebook(c, ht->bk);
	ht->bk = NULL;
	de_free(c, ht->builder->lengths_arr);
	de_free(c, ht->builder);
	de_free(c, ht->cursor);
	de_free(c, ht);
}
