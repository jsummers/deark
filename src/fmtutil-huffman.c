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
	i32 value;
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

struct fmtutil_huffman_cursor {
	NODE_REF_TYPE curr_noderef;
};

struct fmtutil_huffman_tree {
	// In principle, the cursor should be separate, so we could have multiple
	// cursors for one tree. But that's inconvenient, and it's not clear that
	// it would be of any use in practice.
	struct fmtutil_huffman_cursor cursor;

	i64 max_nodes;
	NODE_REF_TYPE next_avail_node;
	NODE_REF_TYPE nodes_alloc;
	struct huffman_node *nodes; // array[nodes_alloc]
	struct huffman_nval_value_data value_of_null_code;

	i64 num_codes;
	UI max_bits;
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
// Note that we allow adding the 0-length code, but (as of this writing) there
// is no way to read back its value.
int fmtutil_huffman_add_code(deark *c, struct fmtutil_huffman_tree *ht,
	u64 code, UI code_nbits, i32 val)
{
	UI k;
	NODE_REF_TYPE curr_noderef = 0; // Note that this may temporarily point to an unallocated node
	int retval = 0;

	if(code_nbits>MAX_TREE_DEPTH) goto done;

	if(code_nbits<1) {
		ht->value_of_null_code.value = val;
		retval = 1;
		goto done;
	}
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
int fmtutil_huffman_decode_bit(struct fmtutil_huffman_tree *ht, u8 bitval, i32 *pval)
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
	const char *modname;
	struct fmtutil_huffman_tree *ht;
	i64 byte_idx;
	i64 nbytes_consumed;
	i64 nbytes_written;

#define SQSTATE_INIT               0
#define SQSTATE_NODECOUNT1         1 // We've read the first byte of nodecount
#define SQSTATE_READING_NODETABLE  2
#define SQSTATE_READING_CODES      3
#define SQSTATE_EOF                4
	UI state;
	i64 nodecount;
	dbuf *nodetable; // The raw bytes of the node table
	struct squeeze_node tmpnodes[SQUEEZE_MAX_NODES]; // Temporary use when decoding the node table
};

static void squeeze_interpret_node(struct de_dfilter_ctx *dfctx, struct squeeze_ctx *sqctx,
	i64 nodenum, u64 currcode, UI currcode_nbits);

static void squeeze_interpret_dval(struct de_dfilter_ctx *dfctx, struct squeeze_ctx *sqctx,
	i16 dval, u64 currcode, UI currcode_nbits)
{
	if(dval>=0) { // a pointer to a node
		if((i64)dval < sqctx->nodecount) {
			squeeze_interpret_node(dfctx, sqctx, (i64)dval, currcode, currcode_nbits);
		}
	}
	else if(dval>=(-257) && dval<=(-1)) {
		i32 adj_value;

		//  -257 => 256 (stop code)
		//  -256 => 255 (byte value)
		//  -255 => 254 (byte value)
		//  ...
		//  -1   => 0   (byte value)
		adj_value = -(((i32)dval)+1);
		if(dfctx->c->debug_level>=2) {
			de_dbg2(dfctx->c, "adding code 0x%x [%u bits]: %d", (UI)currcode, currcode_nbits, (int)adj_value);
		}
		fmtutil_huffman_add_code(dfctx->c, sqctx->ht, currcode, currcode_nbits, adj_value);
	}
	// TODO: Report errors?
}

static void squeeze_interpret_node(struct de_dfilter_ctx *dfctx, struct squeeze_ctx *sqctx,
	i64 nodenum, u64 currcode, UI currcode_nbits)
{
	// TODO: Report errors?
	if(nodenum<0 || nodenum>=sqctx->nodecount) return;
	if(sqctx->tmpnodes[nodenum].in_use) return; // Loops are bad
	if(currcode_nbits>=48) return;

	sqctx->tmpnodes[nodenum].in_use = 1;
	squeeze_interpret_dval(dfctx, sqctx, sqctx->tmpnodes[nodenum].child[0].dval, currcode<<1, currcode_nbits+1);
	squeeze_interpret_dval(dfctx, sqctx, sqctx->tmpnodes[nodenum].child[1].dval, ((currcode<<1) | 1), currcode_nbits+1);
	sqctx->tmpnodes[nodenum].in_use = 0;
}

static void squeeze_process_nodetable(struct de_dfilter_ctx *dfctx, struct squeeze_ctx *sqctx)
{
	i64 k;
	i64 ntpos = 0;
	deark *c = dfctx->c;

	de_dbg2(c, "node table:");
	de_dbg_indent(c, 1);
	for(k=0; k<sqctx->nodecount; k++) {
		sqctx->tmpnodes[k].child[0].dval = (i16)dbuf_geti16le_p(sqctx->nodetable, &ntpos);
		sqctx->tmpnodes[k].child[1].dval = (i16)dbuf_geti16le_p(sqctx->nodetable, &ntpos);
		if(c->debug_level >= 2) {
			de_dbg2(c, "nodetable[%d]: %d %d", (int)k, (int)sqctx->tmpnodes[k].child[0].dval,
				(int)sqctx->tmpnodes[k].child[1].dval);
		}
	}
	de_dbg_indent(c, -1);

	// It feels a little wrong to go to the trouble of decoding this node table into
	// the form required by our Huffman library's API, when we know it's going to
	// just convert it back into a table much like it was originally. Maybe there
	// should be a better way to do this.
	de_dbg2(c, "interpreting huffman table:");
	de_dbg_indent(c, 1);
	squeeze_interpret_node(dfctx, sqctx, 0, 0, 0);
	de_dbg_indent(c, -1);

	if(c->debug_level>=2) {
		de_dbg2(c, "constructed huffman table:");
		de_dbg_indent(c, 1);
		fmtutil_huffman_dump(c, sqctx->ht);
		de_dbg_indent(c, -1);
	}
}

static void my_squeeze_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	struct squeeze_ctx *sqctx = (struct squeeze_ctx*)dfctx->codec_private;
	i64 i;

	for(i=0; i<buf_len; i++) {
		u8 n = buf[i];
		int z;

		if(sqctx->state==SQSTATE_EOF) goto done;

		sqctx->nbytes_consumed++;

		if(sqctx->state==SQSTATE_READING_NODETABLE &&
			(sqctx->nodetable->len >= sqctx->nodecount*4))
		{
			squeeze_process_nodetable(dfctx, sqctx);
			sqctx->state = SQSTATE_READING_CODES;
		}

		switch(sqctx->state) {
		case SQSTATE_INIT:
			sqctx->nodecount = (i64)buf[i];
			sqctx->state = SQSTATE_NODECOUNT1;
			break;
		case SQSTATE_NODECOUNT1:
			sqctx->nodecount |= ((i64)buf[i])<<8;
			de_dbg(dfctx->c, "node count: %d", (int)sqctx->nodecount);

			if(sqctx->nodecount > SQUEEZE_MAX_NODES) {
				de_dfilter_set_errorf(dfctx->c, dfctx->dres, sqctx->modname,
					"Invalid node count");
				sqctx->state = SQSTATE_EOF;
			}
			else {
				sqctx->state = SQSTATE_READING_NODETABLE;
			}
			break;
		case SQSTATE_READING_NODETABLE:
			dbuf_writebyte(sqctx->nodetable, n);
			break;
		case SQSTATE_READING_CODES:
			for(z=0; z<=7; z++) {
				int hret;
				i32 val;

				hret = fmtutil_huffman_decode_bit(sqctx->ht, ((n>>z)&0x1), &val);
				if(hret==1) {
					if(val>=0 && val<=255) {
						dbuf_writebyte(dfctx->dcmpro->f, (u8)val);
						sqctx->nbytes_written++;
						if(dfctx->dcmpro->len_known && (sqctx->nbytes_written >= dfctx->dcmpro->expected_len)) {
							sqctx->state = SQSTATE_EOF;
							goto done;
						}
					}
					else if(val==256) { // STOP code
						sqctx->state = SQSTATE_EOF;
						goto done;
					}
				}
			}
			break;
		}
	}

done:
	if(sqctx->state==SQSTATE_EOF) {
		dfctx->finished_flag = 1;
	}
}

static void my_squeeze_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct squeeze_ctx *sqctx = (struct squeeze_ctx*)dfctx->codec_private;

	dfctx->dres->bytes_consumed = sqctx->nbytes_consumed;
	dfctx->dres->bytes_consumed_valid = 1;
}

static void my_squeeze_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct squeeze_ctx *sqctx = (struct squeeze_ctx*)dfctx->codec_private;

	if(sqctx) {
		dbuf_close(sqctx->nodetable);
		fmtutil_huffman_destroy_tree(dfctx->c, sqctx->ht);
		de_free(dfctx->c, sqctx);
	}
	dfctx->codec_private = NULL;
}

// Squeeze = RLE90 + Huffman.
// This codec is just for the Huffman part.
void dfilter_huff_squeeze_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct squeeze_ctx *sqctx = NULL;

	sqctx = de_malloc(dfctx->c, sizeof(struct squeeze_ctx));
	dfctx->codec_private = (void*)sqctx;
	dfctx->codec_addbuf_fn = my_squeeze_codec_addbuf;
	dfctx->codec_finish_fn = my_squeeze_codec_finish;
	dfctx->codec_destroy_fn = my_squeeze_codec_destroy;

	sqctx->modname = "unsqueeze";
	sqctx->nodetable = dbuf_create_membuf(dfctx->c, SQUEEZE_MAX_NODES*4, 0x1);
	sqctx->ht = fmtutil_huffman_create_tree(dfctx->c, 257, 257);
}
