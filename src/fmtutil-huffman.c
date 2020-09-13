// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Functions related to Huffman coding decompression

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#define NODE_REF_TYPE u32
#define MAX_TREE_DEPTH 56
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

struct huffman_cursor {
	NODE_REF_TYPE curr_noderef;
};

struct fmtutil_huffman_tree {
	// In principle, the cursor should be separate, so we could have multiple
	// cursors for one tree. But that's inconvenient, and it's not clear that
	// it would be of any use in practice.
	struct huffman_cursor cursor;

	i64 max_nodes;
	NODE_REF_TYPE next_avail_node;
	NODE_REF_TYPE nodes_alloc;
	struct huffman_node *nodes; // array[nodes_alloc]
	u8 has_null_code;
	fmtutil_huffman_valtype value_of_null_code;

	i64 num_codes;
	UI max_bits;

	i64 lengths_arr_numalloc;
	i64 lengths_arr_numused;
	struct huffman_lengths_arr_item *lengths_arr; // array[lengths_arr_numalloc]
};

// Ensure that at least n nodes are allocated (0 through n-1)
static int huffman_ensure_alloc(deark *c, struct fmtutil_huffman_tree *ht, NODE_REF_TYPE n)
{
	i64 new_nodes_alloc;

	if(n <= ht->nodes_alloc) return 1;
	if((i64)n > ht->max_nodes) return 0;

	new_nodes_alloc = (i64)ht->nodes_alloc * 2;
	if(new_nodes_alloc > ht->max_nodes) new_nodes_alloc = ht->max_nodes;
	if(new_nodes_alloc < (i64)n) new_nodes_alloc = (i64)n;
	if(new_nodes_alloc < 16) new_nodes_alloc = 16;

	ht->nodes = de_reallocarray(c, ht->nodes, ht->nodes_alloc, sizeof(struct huffman_node),
		new_nodes_alloc);
	ht->nodes_alloc = (NODE_REF_TYPE)new_nodes_alloc;
	return 1;
}

// Tracks the number of items with VALUE status ("codes").
static void huffman_setchildstatus(struct fmtutil_huffman_tree *ht, NODE_REF_TYPE n,
	u8 child_idx, u8 newstatus)
{
	if(n>=ht->nodes_alloc) return;
	if(child_idx>1) return;

	if(ht->nodes[n].child_status[child_idx]==newstatus) return;
	if(ht->nodes[n].child_status[child_idx]==CHILDSTATUS_VALUE) {
		ht->num_codes--;
	}
	if(newstatus==CHILDSTATUS_VALUE) {
		ht->num_codes++;
	}
	ht->nodes[n].child_status[child_idx] = newstatus;
}

// The size of the longest current code.
// This is mainly for debugging info -- it is not guaranteed to be correct if
// the tree was constructed improperly.
UI fmtutil_huffman_get_max_bits(struct fmtutil_huffman_tree *ht)
{
	return ht->max_bits;
}

// The number of codes (symbols) in the the tree.
// This is mainly for debugging info -- it is not guaranteed to be correct if
// the tree was constructed improperly.
i64 fmtutil_huffman_get_num_codes(struct fmtutil_huffman_tree *ht)
{
	if(ht->num_codes>=0) return ht->num_codes;
	return 0;
}

void fmtutil_huffman_reset_cursor(struct fmtutil_huffman_tree *ht)
{
	ht->cursor.curr_noderef = 0;
}

// Add a code, adding to the current tree structure as needed. Codes can be
// added in any order.
//
// If inconsistent codes are added (i.e. a code is a prefix of another code, or
// the tree is left incomplete), we only promise that it will be safe to use
// the decoding functions. Such errors will not necessarily be detected.
//
// Note that adding the 0-length code is allowed.
int fmtutil_huffman_add_code(deark *c, struct fmtutil_huffman_tree *ht,
	u64 code, UI code_nbits, fmtutil_huffman_valtype val)
{
	UI k;
	NODE_REF_TYPE curr_noderef = 0; // Note that this may temporarily point to an unallocated node
	int retval = 0;

	if(code_nbits>MAX_TREE_DEPTH) goto done;

	if(code_nbits<1) {
		ht->value_of_null_code = val;
		ht->has_null_code = 1;
		retval = 1;
		goto done;
	}
	ht->has_null_code = 0;

	if(code_nbits > ht->max_bits) {
		ht->max_bits = code_nbits;
	}

	// Iterate through the bits, high bit first.
	for(k=0; k<code_nbits; k++) {
		UI child_idx; // 0 or 1

		// Make sure the current node exists
		if(curr_noderef >= ht->nodes_alloc) {
			if(!huffman_ensure_alloc(c, ht, curr_noderef+1)) goto done;
		}
		// Claim the current node, if necessary
		if(curr_noderef >= ht->next_avail_node) {
			ht->next_avail_node = curr_noderef+1;
			ht->nodes[curr_noderef].depth = (u8)k;
		}

		child_idx = (code>>(code_nbits-1-k))&0x1;

		if(k==code_nbits-1) {
			// Reached the "leaf" node. Set the value for this child_idx.
			huffman_setchildstatus(ht, curr_noderef, child_idx, CHILDSTATUS_VALUE);
			ht->nodes[curr_noderef].child[child_idx].hnvd.value = val;
		}
		else {
			// Not at the leaf node yet.
			if(ht->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_POINTER) {
				// It's already a pointer.
				curr_noderef = ht->nodes[curr_noderef].child[child_idx].hnpd.noderef;
			}
			else {
				NODE_REF_TYPE next_noderef;

				// It's not a pointer -- make it one.
				if(ht->next_avail_node >= ht->max_nodes) goto done;
				next_noderef = ht->next_avail_node;
				huffman_setchildstatus(ht, curr_noderef, child_idx, CHILDSTATUS_POINTER);
				ht->nodes[curr_noderef].child[child_idx].hnpd.noderef = next_noderef;
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
int fmtutil_huffman_decode_bit(struct fmtutil_huffman_tree *ht, u8 bitval, fmtutil_huffman_valtype *pval)
{
	UI child_idx;
	int retval = 0;
	NODE_REF_TYPE curr_noderef = ht->cursor.curr_noderef;

	if(curr_noderef >= ht->nodes_alloc) goto done;
	if(curr_noderef >= ht->next_avail_node) goto done;
	child_idx = bitval & 0x01;

	if(ht->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_VALUE) {
		*pval = ht->nodes[curr_noderef].child[child_idx].hnvd.value;
		retval = 1;
		goto done;
	}
	else if(ht->nodes[curr_noderef].child_status[child_idx]==CHILDSTATUS_POINTER) {
		ht->cursor.curr_noderef = ht->nodes[curr_noderef].child[child_idx].hnpd.noderef;
		retval = 2;
		goto done;
	}

done:
	if(retval!=2) {
		fmtutil_huffman_reset_cursor(ht);
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
int fmtutil_huffman_read_next_value(struct fmtutil_huffman_tree *ht,
	struct de_bitreader *bitrd, fmtutil_huffman_valtype *pval, UI *pnbits)
{
	int bitcount = 0;
	int retval = 0;

	if(bitrd->eof_flag) goto done;

	if(ht->has_null_code) {
		*pval = ht->value_of_null_code;
		retval = 1;
		goto done;
	}

	while(1) {
		int ret;
		u8 b;

		b = (u8)de_bitreader_getbits(bitrd, 1);
		if(bitrd->eof_flag) goto done;
		bitcount++;
		if(bitcount>64) goto done; // Should be impossible

		ret = fmtutil_huffman_decode_bit(ht, b, pval);
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
void fmtutil_huffman_dump(deark *c, struct fmtutil_huffman_tree *ht)
{
	NODE_REF_TYPE k;
	de_ucstring *tmps = NULL;

	de_dbg(c, "number of codes: %"I64_FMT, fmtutil_huffman_get_num_codes(ht));
	de_dbg(c, "max code size: %u bits", fmtutil_huffman_get_max_bits(ht));
	tmps = ucstring_create(c);
	for(k=0; k<ht->next_avail_node && k<ht->nodes_alloc; k++) {
		UI child_idx;
		struct huffman_node *nd = &ht->nodes[k];

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
}

// This only used with fmtutil_huffman_make_canonical_tree().
// Call this first, once per item.
// The order that you supply the items matters, at least within the set of items
// having the same length.
// Cannot be used for zero-length items. If len==0, it's a successful no-op.
int fmtutil_huffman_record_a_code_length(deark *c, struct fmtutil_huffman_tree *ht,
	fmtutil_huffman_valtype val, UI len)
{
	if(len==0) return 1;
	if(ht->lengths_arr_numused > MAX_MAX_NODES) return 0;

	if(ht->lengths_arr_numused >= ht->lengths_arr_numalloc) {
		i64 new_numalloc;

		new_numalloc = ht->lengths_arr_numused + 128;
		ht->lengths_arr = de_reallocarray(c, ht->lengths_arr, ht->lengths_arr_numalloc,
			sizeof(struct huffman_lengths_arr_item), new_numalloc);
		ht->lengths_arr_numalloc = new_numalloc;
	}
	ht->lengths_arr[ht->lengths_arr_numused].val = val;
	ht->lengths_arr[ht->lengths_arr_numused++].len = len;
	return 1;
}

// Call this after calling huffman_record_item_length() (usually many times).
// Creates the canonical Huffman tree derived from the known code lengths.
int fmtutil_huffman_make_canonical_tree(deark *c, struct fmtutil_huffman_tree *ht)
{
	UI max_sym_len_used;
	UI i;
	UI symlen;
	UI prev_code_bit_length = 0;
	u64 prev_code = 0; // valid if prev_code_bit_length>0
	int retval = 0;
	int saved_indent_level;
	char b2buf[72];

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg2(c, "constructing huffman tree:");
	de_dbg_indent(c, 1);

	if(!ht->lengths_arr) {
		retval = 1;
		goto done;
	}

	// Find the maximum length
	max_sym_len_used = 0;
	for(i=0; i<(UI)ht->lengths_arr_numused; i++) {
		if(ht->lengths_arr[i].len > max_sym_len_used) {
			max_sym_len_used = ht->lengths_arr[i].len;
		}
	}
	if(max_sym_len_used>48) {
		goto done;
	}

	// For each possible symbol length...
	for(symlen=1; symlen<=max_sym_len_used; symlen++) {
		UI k;

		// Find all the codes that use this symbol length, in order
		for(k=0; k<(UI)ht->lengths_arr_numused; k++) {
			int ret;
			u64 thiscode;

			if(ht->lengths_arr[k].len != symlen) continue;
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
				de_dbg2(c, "adding code \"%s\" = %d",
					de_print_base2_fixed(b2buf, sizeof(b2buf), thiscode, symlen),
					(int)ht->lengths_arr[k].val);
			}
			ret = fmtutil_huffman_add_code(c, ht, thiscode, symlen, ht->lengths_arr[k].val);
			if(!ret) {
				goto done;
			}
		}
	}
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// initial_codes: If not 0, pre-allocate enough nodes for this many codes.
// max_codes: If not 0, attempting to add substantially more codes than this will fail.
struct fmtutil_huffman_tree *fmtutil_huffman_create_tree(deark *c, i64 initial_codes, i64 max_codes)
{
	i64 initial_nodes;
	struct fmtutil_huffman_tree *ht = NULL;

	ht = de_malloc(c, sizeof(struct fmtutil_huffman_tree));

	if(max_codes>0) {
		ht->max_nodes = max_codes;
	}
	else {
		ht->max_nodes = MAX_MAX_NODES;
	}
	if(ht->max_nodes > MAX_MAX_NODES) {
		ht->max_nodes = MAX_MAX_NODES;
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

	huffman_ensure_alloc(c, ht, (NODE_REF_TYPE)initial_nodes);
	ht->next_avail_node = 0;
	ht->num_codes = 0;
	ht->max_bits = 0;

	return ht;
}

void fmtutil_huffman_destroy_tree(deark *c, struct fmtutil_huffman_tree *ht)
{
	if(!ht) return;
	de_free(c, ht->lengths_arr);
	de_free(c, ht);
}

///////////////////////////////////
// "Squeeze"-style Huffman decoder

// The first node you add allows for 2 symbols, and each additional node adds 1.
// So in general, you need one less node than the number of symbols.
// The max number of symbols is 257: 256 byte values, plus a special "stop" code.
#define SQUEEZE_MAX_NODES 256

struct squeeze_data_item {
	i16 dval;
};

struct squeeze_node {
	u8 in_use;
	struct squeeze_data_item child[2];
};

struct squeeze_ctx {
	deark *c;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	const char *modname;
	i64 nbytes_written;
	i64 nodecount;
	struct fmtutil_huffman_tree *ht;
	struct de_bitreader bitrd;
	struct squeeze_node tmpnodes[SQUEEZE_MAX_NODES]; // Temporary use when decoding the node table
};

static void squeeze_interpret_node(struct squeeze_ctx *sqctx,
	i64 nodenum, u64 currcode, UI currcode_nbits);

static void squeeze_interpret_dval(struct squeeze_ctx *sqctx,
	i16 dval, u64 currcode, UI currcode_nbits)
{
	char b2buf[72];

	if(dval>=0) { // a pointer to a node
		if((i64)dval < sqctx->nodecount) {
			squeeze_interpret_node(sqctx, (i64)dval, currcode, currcode_nbits);
		}
	}
	else if(dval>=(-257) && dval<=(-1)) {
		fmtutil_huffman_valtype adj_value;

		//  -257 => 256 (stop code)
		//  -256 => 255 (byte value)
		//  -255 => 254 (byte value)
		//  ...
		//  -1   => 0   (byte value)
		adj_value = -(((fmtutil_huffman_valtype)dval)+1);
		if(sqctx->c->debug_level>=2) {
			de_dbg2(sqctx->c, "adding code \"%s\" = %d",
				de_print_base2_fixed(b2buf, sizeof(b2buf), currcode, currcode_nbits),
				(int)adj_value);
		}
		fmtutil_huffman_add_code(sqctx->c, sqctx->ht, currcode, currcode_nbits, adj_value);
	}
	// TODO: Report errors?
}

static void squeeze_interpret_node(struct squeeze_ctx *sqctx,
	i64 nodenum, u64 currcode, UI currcode_nbits)
{
	// TODO: Report errors?
	if(nodenum<0 || nodenum>=sqctx->nodecount) return;
	if(sqctx->tmpnodes[nodenum].in_use) return; // Loops are bad
	if(currcode_nbits>=48) return;

	sqctx->tmpnodes[nodenum].in_use = 1;
	squeeze_interpret_dval(sqctx, sqctx->tmpnodes[nodenum].child[0].dval, currcode<<1, currcode_nbits+1);
	squeeze_interpret_dval(sqctx, sqctx->tmpnodes[nodenum].child[1].dval, ((currcode<<1) | 1), currcode_nbits+1);
	sqctx->tmpnodes[nodenum].in_use = 0;
}

static int squeeze_process_nodetable(deark *c, struct squeeze_ctx *sqctx)
{
	int retval = 0;

	// It feels a little wrong to go to the trouble of decoding this node table into
	// the form required by our Huffman library's API, when we know it's going to
	// just convert it back into a table much like it was originally. Maybe there
	// should be a better way to do this.
	de_dbg2(c, "interpreting huffman table:");
	de_dbg_indent(c, 1);
	squeeze_interpret_node(sqctx, 0, 0, 0);
	de_dbg_indent(c, -1);

	if(c->debug_level>=2) {
		de_dbg2(c, "constructed huffman table:");
		de_dbg_indent(c, 1);
		fmtutil_huffman_dump(c, sqctx->ht);
		de_dbg_indent(c, -1);
	}

	retval = 1;
	return retval;
}

static int squeeze_read_nodetable(deark *c, struct squeeze_ctx *sqctx)
{
	i64 k;
	int retval = 0;

	if(sqctx->bitrd.curpos+2 > sqctx->bitrd.endpos) goto done;
	sqctx->nodecount = dbuf_getu16le_p(sqctx->dcmpri->f, &sqctx->bitrd.curpos);
	de_dbg(c, "node count: %d", (int)sqctx->nodecount);
	if(sqctx->nodecount > SQUEEZE_MAX_NODES) {
		de_dfilter_set_errorf(c, sqctx->dres, sqctx->modname,
			"Invalid node count");
		goto done;
	}

	de_dbg2(c, "node table:");
	de_dbg_indent(c, 1);
	for(k=0; k<sqctx->nodecount; k++) {
		sqctx->tmpnodes[k].child[0].dval = (i16)dbuf_geti16le_p(sqctx->dcmpri->f, &sqctx->bitrd.curpos);
		sqctx->tmpnodes[k].child[1].dval = (i16)dbuf_geti16le_p(sqctx->dcmpri->f, &sqctx->bitrd.curpos);
		if(c->debug_level >= 2) {
			de_dbg2(c, "nodetable[%d]: %d %d", (int)k, (int)sqctx->tmpnodes[k].child[0].dval,
				(int)sqctx->tmpnodes[k].child[1].dval);
		}
	}
	de_dbg_indent(c, -1);
	if(sqctx->bitrd.curpos > sqctx->bitrd.endpos) goto done;

	if(!squeeze_process_nodetable(c, sqctx)) goto done;

	retval = 1;
done:
	return retval;
}

static int squeeze_read_codes(deark *c, struct squeeze_ctx *sqctx)
{
	int retval = 0;

	sqctx->bitrd.bbll.is_lsb = 1;
	de_bitbuf_lowelevel_empty(&sqctx->bitrd.bbll);

	if(fmtutil_huffman_get_max_bits(sqctx->ht) < 1) {
		// Empty tree? Assume this is an empty file.
		retval = 1;
		goto done;
	}

	while(1) {
		int ret;
		fmtutil_huffman_valtype val = 0;

		ret = fmtutil_huffman_read_next_value(sqctx->ht, &sqctx->bitrd, &val, NULL);
		if(!ret || val<0 || val>256) {
			if(sqctx->bitrd.eof_flag) {
				retval = 1;
			}
			else {
				de_dfilter_set_errorf(c, sqctx->dres, sqctx->modname, "Huffman decode error");
			}
			goto done;
		}

		if(val>=0 && val<=255) {
			dbuf_writebyte(sqctx->dcmpro->f, (u8)val);
			sqctx->nbytes_written++;
			if(sqctx->dcmpro->len_known && (sqctx->nbytes_written >= sqctx->dcmpro->expected_len)) {
				retval = 1;
				goto done;
			}
		}
		else if(val==256) { // STOP code
			retval = 1;
			goto done;
		}
	}

done:
	return retval;
}

void fmtutil_huff_squeeze_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct squeeze_ctx *sqctx = NULL;
	int ok = 0;

	sqctx = de_malloc(c, sizeof(struct squeeze_ctx));
	sqctx->c = c;
	sqctx->modname = "unsqueeze";
	sqctx->dcmpri = dcmpri;
	sqctx->dcmpro = dcmpro;
	sqctx->dres = dres;

	sqctx->bitrd.f = dcmpri->f;
	sqctx->bitrd.curpos = dcmpri->pos;
	sqctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	sqctx->ht = fmtutil_huffman_create_tree(c, 257, 257);

	if(!squeeze_read_nodetable(c, sqctx)) goto done;
	if(!squeeze_read_codes(c, sqctx)) goto done;

	dres->bytes_consumed = sqctx->bitrd.curpos - dcmpri->pos;
	if(dres->bytes_consumed > dcmpri->len) {
		dres->bytes_consumed = dcmpri->len;
	}
	dres->bytes_consumed_valid = 1;
	ok = 1;

done:
	if(!ok || dres->errcode) {
		de_dfilter_set_errorf(c, dres, sqctx->modname, "Squeeze decompression failed");
	}

	if(sqctx) {
		fmtutil_huffman_destroy_tree(c, sqctx->ht);
		de_free(c, sqctx);
	}
}
