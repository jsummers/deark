// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Functions related to Huffman coding decompression

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#define NODE_REF_TYPE u32
#define MAX_TREE_DEPTH 56
#define MAX_MAX_NODES  (65536*2)

struct huffman_node_tree_data {
	NODE_REF_TYPE child[2]; // child[n]==0 means not-set
};
struct huffman_node_value_data {
	i32 value;
};

struct huffman_node {
#define NODESTATUS_UNUSED 0
#define NODESTATUS_TREE   1
#define NODESTATUS_VALUE  2
	u8 status;
	u8 depth;
	union huffman_node_data {
		struct huffman_node_tree_data hntd;
		struct huffman_node_value_data hnvd;
	} hnd;
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
	i64 num_codes;
	UI max_bits;
	NODE_REF_TYPE nodes_used; // highest node used, +1
	NODE_REF_TYPE nodes_alloc;
	struct huffman_node *nodes; // array[nodes_alloc]
};

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

// Tracks the number of nodes with VALUE status ("codes").
static void huffman_setnodestatus(struct fmtutil_huffman_tree *ht, NODE_REF_TYPE n, u8 newstatus)
{
	if(ht->nodes[n].status==newstatus) return;
	if(ht->nodes[n].status==NODESTATUS_VALUE) {
		ht->num_codes--;
	}
	if(newstatus==NODESTATUS_VALUE) {
		ht->num_codes++;
	}
	ht->nodes[n].status = newstatus;
}

UI fmtutil_huffman_get_max_bits(struct fmtutil_huffman_tree *ht)
{
	return ht->max_bits;
}

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
	NODE_REF_TYPE curr_noderef = 0;
	int retval = 0;

	if(code_nbits>MAX_TREE_DEPTH) goto done;

	// Iterate through the bits, high bit first.
	// For every bit, there will be one "TREE" node. Then at the end, there
	// will be an additional ("VALUE") node.
	for(k=0; k<code_nbits; k++) {
		NODE_REF_TYPE next_noderef;
		UI b;

		if(curr_noderef>=ht->nodes_used) goto done;

		// If the current node is not already a TREE node, make it one.
		if(ht->nodes[curr_noderef].status != NODESTATUS_TREE) {
			huffman_setnodestatus(ht, curr_noderef, NODESTATUS_TREE);
			ht->nodes[curr_noderef].hnd.hntd.child[0] = 0;
			ht->nodes[curr_noderef].hnd.hntd.child[1] = 0;
		}

		ht->nodes[curr_noderef].depth = (u8)k;

		b = (code>>(code_nbits-1-k))&0x1;

		// If the child node we'll go to doesn't exist yet, append it to the array
		next_noderef = ht->nodes[curr_noderef].hnd.hntd.child[b];
		if(next_noderef==0) {
			if(!huffman_ensure_alloc(c, ht, ht->nodes_used+1)) goto done;
			next_noderef = ht->nodes_used;
			ht->nodes_used++;
			ht->nodes[curr_noderef].hnd.hntd.child[b] = next_noderef;
		}

		if(next_noderef <= curr_noderef) goto done;

		curr_noderef = next_noderef;
	}

	if(curr_noderef>=ht->nodes_used) goto done;

	// Make the final node a VALUE node
	huffman_setnodestatus(ht, curr_noderef, NODESTATUS_VALUE);
	ht->nodes[curr_noderef].depth = (u8)code_nbits;
	ht->nodes[curr_noderef].hnd.hnvd.value = val;
	if(code_nbits > ht->max_bits) {
		ht->max_bits = code_nbits;
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
	int retval = 0;
	NODE_REF_TYPE curr_noderef = ht->cursor.curr_noderef;
	NODE_REF_TYPE next_noderef;

	if(curr_noderef >= ht->nodes_used) goto done;
	if(ht->nodes[curr_noderef].status != NODESTATUS_TREE) goto done;

	next_noderef = ht->nodes[curr_noderef].hnd.hntd.child[bitval & 0x1];
	if(next_noderef<1 || next_noderef<=curr_noderef || next_noderef>=ht->nodes_used) return 0;

	curr_noderef = next_noderef;
	if(ht->nodes[curr_noderef].status==NODESTATUS_VALUE) {
		*pval = ht->nodes[curr_noderef].hnd.hnvd.value;
		retval = 1;
		goto done;
	}

	ht->cursor.curr_noderef = curr_noderef;
	retval = 2;

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

	de_dbg(c, "number of codes: %"I64_FMT, fmtutil_huffman_get_num_codes(ht));
	de_dbg(c, "max code size: %u bits", fmtutil_huffman_get_max_bits(ht));
	for(k=0; k<ht->nodes_used; k++) {
		struct huffman_node *nd = &ht->nodes[k];

		if(nd->status==NODESTATUS_TREE) {
			de_dbg(c, "node[%u]: d=%u (%u, %u)", (UI)k, (UI)nd->depth,
				(UI)nd->hnd.hntd.child[0], (UI)nd->hnd.hntd.child[1]);
		}
		else if(nd->status==NODESTATUS_VALUE) {
			de_dbg(c, "node[%u]: d=%u value=%u", (UI)k, (UI)nd->depth, (UI)nd->hnd.hnvd.value);
		}
	}
}

// initial_codes: If not 0, pre-allocate enough nodes for this many codes.
// max_codes: If not 0, attempting to add substantially more codes than this will fail.
struct fmtutil_huffman_tree *fmtutil_huffman_create_tree(deark *c, i64 initial_codes, i64 max_codes)
{
	i64 initial_nodes;
	struct fmtutil_huffman_tree *ht = NULL;

	ht = de_malloc(c, sizeof(struct fmtutil_huffman_tree));

	if(max_codes>0) {
		ht->max_nodes = max_codes*2;
	}
	else {
		ht->max_nodes = MAX_MAX_NODES;
	}
	if(ht->max_nodes > MAX_MAX_NODES) {
		ht->max_nodes = MAX_MAX_NODES;
	}

	if(initial_codes>0) {
		initial_nodes = initial_codes*2;
	}
	else {
		initial_nodes = 1;
	}
	if(initial_nodes > MAX_MAX_NODES) {
		initial_nodes = MAX_MAX_NODES;
	}

	huffman_ensure_alloc(c, ht, (NODE_REF_TYPE)initial_nodes);
	ht->num_codes = 0;
	ht->max_bits = 0;

	// Start with a trivial tree (= "the zero-length code has value 0")
	huffman_setnodestatus(ht, 0, NODESTATUS_VALUE);
	ht->nodes[0].hnd.hnvd.value = 0;
	ht->nodes_used = 1;

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
