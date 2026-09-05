// This file is part of Deark.
// Copyright (C) 2026 Jason Summers
// See the file COPYING for terms of use.

// FTCOMP/PACK2 (fT19/fT21) decompressor, used by OS/2 PACK2 (FTCOMP) archives.

// Credit: Dimitriy Ryazantcev reverse-engineered the decompression algorithm,
// and wrote the original decompression code for Deark. Some changes to the
// code may have been made since then. Most of the comments beyond this point
// are his.

// This decompressor supports both known variants, "fT19" and "fT21",
// identified by a 4-byte tag at the start of each compressed block.

// FTCOMP overview:
// - Stage 1 is an adaptive-Huffman decoder. A fixed "descriptor" tree
//   (built once from a bootstrap weight table) decodes, per block, a set
//   of per-symbol frequency weights and four "model bytes"; those are
//   used to rescale the weights and rebuild two working trees ("Table A"
//   and "Table B", aliased when they'd be identical) that decode the
//   block's actual symbol stream. Multi-digit numeric fields (match
//   lengths/distances) are decoded through a separate "digit chain" tree
//   with its own small MRU/rank caches, so recently-used values get
//   shorter codes on reuse.
// - Stage 2 expands Stage 1's symbol stream into literal bytes and
//   LZ77 back-references (ftc_lz_expand), using an escape byte to mark
//   non-literal chunks and a preset dictionary (ftc_preset_dict) to seed
//   matches at the start of a block.
// - fT21 additionally runs each block's Stage-2 output through an RLE
//   pass (ftc_rle21) with its own marker/escape byte.
//
// fT19 and fT21 share nearly all of this logic; fT21 differs in a few
// places: some digit-chain table weights are patched, a couple of
// length-gate thresholds and escape-byte values change, and the RLE21
// post-pass is fT21-only.
//
// The bootstrap Huffman weight tables and preset dictionary are stored
// compressed in the source (ftcompdata.h) and unpacked at runtime.

// FTCOMP's algorithm (RLE21 marker/escape byte + multi-table Huffman selected
// per block, MTF/rank-style short-coding of recent LZ77 literals, and a small
// set of predetermined weight tables picked per block) resembles ideas from
// several older compression patents, though none is known to be a literal
// source:
//  - US4626829A (Hauck, Intelligent Storage Inc., 1985/1986): RLE with a
//    flag byte between literal and run-length, flag-byte-doubling escape for
//    a literal occurrence of the flag byte, and multiple Huffman tables
//    selected by context. Cf. ftc_rle21()'s marker/escape handling and the
//    model_m0..model_m3 table selection in ftc_scale_frequencies().
//  - US6218970B1 (Jaquette, IBM, 1998/2001): MRU/LRU literal array with
//    move-to-front reordering, giving shorter codes to recently-used values.
//    Cf. struct ftc_mrurank / ftc_mrurank_unrank() (a much smaller, 2-slot
//    MRU cache per "site", not a full 256-entry MTF stack).
//  - US5608396A (Cheng/Craft/Garibay/Karnin, IBM, 1995/1997): LZ1-family
//    dictionary compression with a limited match-length codebook and unused
//    codebook slots repurposed as control codes. Cf. Stage 2's LZ77 expansion
//    (ftc_decode_stage2 / ftc_lz_expand) and its use of FTC_LZESCAPE_BYTE.
//  - US10700702B2 (IBM Research, 2016/2020): flash-controller "pseudo-dynamic
//    compression" that selects among a small set of predetermined prefix-code
//    tables by frequency. Conceptually similar to per-block table selection here, but
//    this patent postdates FTCOMP (mid-1990s) by ~20 years, so any connection
//    is at most a shared IBM lineage of ideas, not derivation.

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#define FTC_DESCRIPTORTABLE_LEN  433
#define FTC_LEAF_LIMIT_WO  (FTC_DESCRIPTORTABLE_LEN*4) // 1732
#define FTC_NODETABLE_LEN  ((FTC_DESCRIPTORTABLE_LEN + 2) * 2) // 870

#define FTC_EXTRASTEP_TABLE_LEN  129

#define FTC_PRESET_DICT_LEN  ((i64)4986)

// Static bootstrap Huffman weight tables + PRESET_DICT, extracted from the
// packer/transfer-tool binaries (TKXFER.EXE/PACK2.EXE).
//
// Compressed blob packing, in order:
//   ftc_descriptor_weights[FTC_DESCRIPTORTABLE_LEN] (u16le),
//   ftc_digitchain_weights[FTC_DESCRIPTORTABLE_LEN] (u16le),
//   ftc_type_table[FTC_DESCRIPTORTABLE_LEN] (u16le),
//   ftc_extrastep_table[FTC_EXTRASTEP_TABLE_LEN] (u16le),
//   ftc_preset_dict[FTC_PRESET_DICT_LEN] (u8) --
//   7842 bytes uncompressed, 2512(-ish) compressed.

#include "../foreign/ftcompdata.h"

#define DE_PERSISTENT_ITEM_FTCOMP_DATA 5

struct ftc_tbls_type {
	u16 ftc_descriptor_weights[FTC_DESCRIPTORTABLE_LEN];
	u16 ftc_digitchain_weights[FTC_DESCRIPTORTABLE_LEN];
	u16 ftc_type_table[FTC_DESCRIPTORTABLE_LEN];
	u16 ftc_extrastep_table[FTC_EXTRASTEP_TABLE_LEN];
	u8 ftc_preset_dict[FTC_PRESET_DICT_LEN];
	int ftc_tables_ready;
};

struct ftc_tbls_wrapper {
	struct ftc_tbls_type *tbls;
};

static void initialize_ftctables(deark *c, struct ftc_tbls_type *tbls)
{
	unsigned int i;
	dbuf *tables_out = NULL;
	u8 *ftcdata = NULL;
	i64 tp;
	int ret;

	if(tbls->ftc_tables_ready) goto done;

	tables_out = dbuf_create_membuf(c, 0, 0);
	dbuf_enable_wbuffer(tables_out);

	ftcdata = de_malloc(c, FTC_TABLES_UNCOMPRESSED_LEN);
	ret = de_decompress_zlib_mem2dbuf(c, de_ftcompdata, FTC_TABLES_CMPR_LEN,
		tables_out, FTC_TABLES_UNCOMPRESSED_LEN);
	if(!ret || tables_out->len!=FTC_TABLES_UNCOMPRESSED_LEN) {
		de_internal_err_fatal(c, "Problem with ftcomp");
		goto done;
	}

	tp = 0;
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) {
		tbls->ftc_descriptor_weights[i] = (u16)dbuf_getu16le_p(tables_out, &tp);
	}
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) {
		tbls->ftc_digitchain_weights[i] = (u16)dbuf_getu16le_p(tables_out, &tp);
	}
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) {
		tbls->ftc_type_table[i] = (u16)dbuf_getu16le_p(tables_out, &tp);
	}
	for(i=0; i<FTC_EXTRASTEP_TABLE_LEN; i++) {
		tbls->ftc_extrastep_table[i] = (u16)dbuf_getu16le_p(tables_out, &tp);
	}
	dbuf_read(tables_out, tbls->ftc_preset_dict, tp, FTC_PRESET_DICT_LEN);
	tbls->ftc_tables_ready = 1;

done:
	dbuf_close(tables_out);
	de_free(c, ftcdata);
}

// Unpack (if not already done), and return a pointer to, the plain weight
// tables + LZ77 preset dictionary.
static void acquire_ftctables(deark *c, struct ftc_tbls_wrapper *tblsw)
{
	if(!c->persistent_item[DE_PERSISTENT_ITEM_FTCOMP_DATA]) {
		c->persistent_item[DE_PERSISTENT_ITEM_FTCOMP_DATA] = de_malloc(c, sizeof(struct ftc_tbls_type));
	}

	tblsw->tbls = (struct ftc_tbls_type*)c->persistent_item[DE_PERSISTENT_ITEM_FTCOMP_DATA];
	if(!tblsw->tbls->ftc_tables_ready) {
		initialize_ftctables(c, tblsw->tbls);
	}
}

#define FTC_MRURING_SIZE  32
#define FTC_MRURING_MASK  (FTC_MRURING_SIZE-1)

#define FTC_MODE_FT19  1
#define FTC_MODE_FT21  2

#define CODE_fT19 0x66543139U
#define CODE_fT21 0x66543231U

// Marks a non-literal chunk in the Stage-1 output / Stage-2 LZ77 stream (see ftc_lz_expand).
#define FTC_LZESCAPE_BYTE  0x9e

// Size of the Stage-2 LZ history ring. Must be a power of 2, and >=65536 so
// any 16-bit match distance is always resolvable.
#define FTC_LZWINDOW_LEN  65536

// Circular buffer of recently-seen values (stage1-output byte positions, or
// instant-match distances): peek an entry, push a new one, or promote an
// existing entry to the front while overwriting it.
struct ftc_mruring {
	u16 buf[FTC_MRURING_SIZE];
	unsigned int idx;
};

static u16 ftc_mruring_peek(struct ftc_mruring *r, unsigned int nwords)
{
	return r->buf[(r->idx + nwords) & FTC_MRURING_MASK];
}

static void ftc_mruring_push(struct ftc_mruring *r, u16 value)
{
	r->idx = (r->idx - 1) & FTC_MRURING_MASK;
	r->buf[r->idx] = value;
}

static void ftc_mruring_promote(struct ftc_mruring *r, unsigned int nwords, u16 value)
{
	int i;

	for(i=(int)nwords-1; i>=0; i--) {
		r->buf[(r->idx + (unsigned int)i + 1) & FTC_MRURING_MASK] =
			r->buf[(r->idx + (unsigned int)i) & FTC_MRURING_MASK];
	}
	r->buf[r->idx] = value;
}

// Two-value MRU ("move-to-front") un-ranking used by the digit-chain
// refinement logic: for fT19, a simple passthrough; for fT21, dv==0x100/0x101
// reuse mru/mru2, and any other dv is a rank excluding {mru, mru2}.
struct ftc_mrurank {
	u16 mru;
	u16 mru2;
};

static void ftc_mrurank_init(struct ftc_mrurank *mr)
{
	mr->mru = 0;
	mr->mru2 = 1;
}

static u16 ftc_mrurank_unrank(struct ftc_mrurank *mr, u16 dv, unsigned int mode)
{
	u16 out;

	if(mode>=FTC_MODE_FT21) {
		if(dv==0x100) {
			out = mr->mru;
		}
		else if(dv==0x101) {
			out = mr->mru2;
			mr->mru2 = mr->mru;
		}
		else {
			u16 v = dv;
			u16 lo = (u16)de_min_int(mr->mru, mr->mru2);
			u16 hi = (u16)de_max_int(mr->mru, mr->mru2);

			if(lo <= v) v++;
			if(hi <= v) v++;
			out = v;
			mr->mru2 = mr->mru;
		}
	}
	else {
		out = (dv==0x100) ? mr->mru : dv;
	}
	mr->mru = out;
	return out;
}

// Per-member decoder state: rings/decoders/stream_pos persist across a
// member's blocks; raw_weights/model are per-block scratch; dec_digitchain
// (and the mode patch to the shared ftc_type_table/ftc_extrastep_table
// globals) is owned by ftc_ensure_digitchain_decoder.
struct ftc_decstate {
	deark *c; // needed to create/destroy fmtutil_huffman decoders
	struct ftc_tbls_type *tbls;

	u16 raw_weights[FTC_DESCRIPTORTABLE_LEN];
	struct ftc_mruring ring_lenpos;
	struct ftc_mruring ring_matchdist;

	// Huffman tree build workspace. parentbit is the node table. sort_scratch
	// is the merge-queue array (also its own recursion stack, and later
	// reused by ftc_rle21's byte-histogram sort); qweight mirrors it, one
	// weight per queue slot -- except the recursion-stack tail, which has no
	// qweight entry. leaf_weight is the real id-indexed weight table, always
	// repopulated before ftc_build_tree runs.
	u16 parentbit[FTC_NODETABLE_LEN];
	u16 leaf_weight[FTC_DESCRIPTORTABLE_LEN];
	u16 sort_scratch[512];
	u16 qweight[512];
	int emit_failed; // sticky, set by ftc_emit_codes on any add_code failure

	struct fmtutil_huffman_decoder *dec_a; // "backup"/Table A -- rebuilt every block
	struct fmtutil_huffman_decoder *dec_b; // "live"/Table B -- aliases dec_a when B isn't rebuilt this block
	struct fmtutil_huffman_decoder *dec_descriptor; // built once, cold init
	struct fmtutil_huffman_decoder *dec_digitchain; // per-mode digit-chain decoder; rebuilt only on a mode change (see last_mode)

	unsigned int mode;
	unsigned int last_mode; // 0 initially; mode is always 1 or 2, so the first ftc_ensure_digitchain_decoder call always misses this cache.

	u32 stream_pos; // exact per-member decompressed length so far; see comment above FTC_STREAM_POS_THRESH1

	u16 model_m0, model_m1, model_m2, model_m3;
};

// Bit reader: shared struct de_bitreader (MSB-first: bbll.is_lsb left at its
// zeroed default), constructed with endpos set far beyond any reachable
// curpos (see ftc_decode_stage1) so it never latches eof_flag -- a
// truncated/corrupt bitstream must keep reading (dbuf-OOB-safe) zero bits
// forever rather than stop cold, matching this codec's own truncation
// tolerance. `f`'s addressing covers the whole file, not just this
// block/member: a block's bitstream may legitimately read a little past its
// own boundary.

// Decodes one symbol via the given fmtutil_huffman decoder, one bit at a
// time. Returns the symbol's own value (see ftc_emit_codes). A malformed
// bitstream yields 0.
static u16 ftc_br_read_sym(struct de_bitreader *br, struct fmtutil_huffman_decoder *hd)
{
	fmtutil_huffman_valtype val = 0;
	unsigned int guard;

	fmtutil_huffman_reset_cursor(hd->cursor);
	for(guard=0; guard<FMTUTIL_HUFFMAN_MAX_CODE_LENGTH; guard++) {
		u8 bit;
		int ret;

		bit = (u8)de_bitreader_getbits(br, 1);

		ret = fmtutil_huffman_decode_bit(hd->bk, hd->cursor, bit, &val);
		if(ret==1) return (u16)val;
		if(ret!=2) break;
	}
	return 0;
}

// Leaf-id-indexed weight accessors; `wo` is the word-offset (pre-scaled by
// 4). Unlike queue weight (ftc_queue_weight_get/_set), this is genuine input
// data that outlives the merge queue.
static u16 ftc_leaf_weight_get(struct ftc_decstate *ds, unsigned int wo) { return ds->leaf_weight[wo>>2]; }
static void ftc_leaf_weight_set(struct ftc_decstate *ds, unsigned int wo, u16 v) { ds->leaf_weight[wo>>2] = v; }
static void ftc_parent_set(struct ftc_decstate *ds, unsigned int child_wo, unsigned int parent_wo, unsigned int is_child0)
{
	ds->parentbit[child_wo>>2] = (u16)((parent_wo>>2) | (is_child0 ? 0x8000 : 0));
}

static u16 ftc_queue_id_get(struct ftc_decstate *ds, unsigned int i) { return ds->sort_scratch[i]; }
static void ftc_queue_id_set(struct ftc_decstate *ds, unsigned int i, u16 v) { ds->sort_scratch[i] = v; }
static u16 ftc_queue_id_next_get(struct ftc_decstate *ds, unsigned int i) { return ds->sort_scratch[i+1]; }
static void ftc_queue_id_next_set(struct ftc_decstate *ds, unsigned int i, u16 v) { ds->sort_scratch[i+1] = v; }

// qweight[i] holds the weight of whatever id sits at sort_scratch[i], moved
// in lockstep on every write/swap/memmove -- needed since internal nodes,
// once queued, have no leaf_weight entry to fall back on.
static u16 ftc_queue_weight_get(struct ftc_decstate *ds, unsigned int i) { return ds->qweight[i]; }
static void ftc_queue_weight_set(struct ftc_decstate *ds, unsigned int i, u16 v) { ds->qweight[i] = v; }
static u16 ftc_queue_weight_next_get(struct ftc_decstate *ds, unsigned int i) { return ds->qweight[i+1]; }

// Sorts sort_scratch[first_index .. stack_base] by weight (qweight), using a
// hybrid quicksort (Hoare partition) / insertion-sort (spans <=16). Tie-break
// order matters for byte-exact code assignment. The quicksort's explicit
// recursion stack lives in sort_scratch's own tail, past stack_base.
static void ftc_sort_range(struct ftc_decstate *ds, unsigned int stack_base, unsigned int first_index)
{
	unsigned int stack_ptr;

	ftc_queue_id_set(ds, stack_base+1, (u16)first_index);
	ftc_queue_id_set(ds, stack_base+2, (u16)stack_base);
	stack_ptr = stack_base + 3;
	while(1) {
		unsigned int hi = stack_ptr - 1;
		unsigned int lo;
		unsigned int next_lo, next_hi;

		stack_ptr = stack_ptr - 2;
		lo = ftc_queue_id_get(ds, stack_ptr);
		hi = ftc_queue_id_get(ds, hi);
		do {
			next_hi = hi;
			if(hi - lo <= 16) {
				// ---- insertion sort (span of 16 elements or fewer) ----
				unsigned int ins_end = lo + 1;

				next_lo = hi;
				if(ins_end <= hi) {
					unsigned int scan_pos = ins_end;

					do {
						u16 key = ftc_queue_id_get(ds, scan_pos);
						u16 key_w = ftc_queue_weight_get(ds, scan_pos);
						unsigned int shift_from = lo;

						if(ftc_queue_weight_get(ds, lo) < key_w) {
							unsigned int shift_scan = lo;

							do {
								if(ins_end <= shift_from) break;
								shift_from++;
								shift_scan++;
							} while(ftc_queue_weight_get(ds, shift_scan) < key_w);
						}
						{
							unsigned int shift_len = ins_end - shift_from;

							if(shift_len>0) {
								de_memmove(&ds->sort_scratch[shift_from+1],
									&ds->sort_scratch[shift_from],
									shift_len*sizeof(u16));
								de_memmove(&ds->qweight[shift_from+1],
									&ds->qweight[shift_from],
									shift_len*sizeof(u16));
							}
						}
						ftc_queue_id_set(ds, shift_from, key);
						ftc_queue_weight_set(ds, shift_from, key_w);
						scan_pos++;
						ins_end++;
					} while(ins_end <= hi);
				}
			}
			else {
				// ---- Hoare partition (span >= 17 elements) ----
				unsigned int pivot_idx = (hi + lo) >> 1;
				u16 pivot_weight = ftc_queue_weight_get(ds, pivot_idx);
				unsigned int left = lo;
				unsigned int right = hi;

				do {
					if(ftc_queue_weight_get(ds, left) < pivot_weight) {
						do { left++; } while(ftc_queue_weight_get(ds, left) < pivot_weight);
					}
					if(pivot_weight < ftc_queue_weight_get(ds, right)) {
						do { right--; } while(pivot_weight < ftc_queue_weight_get(ds, right));
					}
					if(left <= right) {
						u16 tmp = ftc_queue_id_get(ds, left);
						u16 tmp_w = ftc_queue_weight_get(ds, left);

						ftc_queue_id_set(ds, left, ftc_queue_id_get(ds, right));
						ftc_queue_weight_set(ds, left, ftc_queue_weight_get(ds, right));
						left++;
						ftc_queue_id_set(ds, right, tmp);
						ftc_queue_weight_set(ds, right, tmp_w);
						right--;
					}
				} while(left <= right);

				// Recurse into the smaller half directly; push the larger
				// half onto the stack for a later loop iteration.
				if(right - lo < hi - left) {
					next_lo = lo;
					next_hi = right;
					if(left < hi) {
						ftc_queue_id_set(ds, stack_ptr, (u16)left);
						ftc_queue_id_set(ds, stack_ptr+1, (u16)hi);
						stack_ptr += 2;
					}
				}
				else {
					next_lo = left;
					if(lo < right) {
						ftc_queue_id_set(ds, stack_ptr, (u16)lo);
						ftc_queue_id_set(ds, stack_ptr+1, (u16)right);
						stack_ptr += 2;
					}
				}
			}
			lo = next_lo;
			hi = next_hi;
		} while(next_lo < next_hi);
		if(stack_base+1 == stack_ptr) return;
	}
}

// Builds a canonical Huffman tree from leaf_weight, recording each node's
// parent in parentbit as it merges (read back by ftc_emit_codes). Returns 0
// only for the all-zero-weights case (never valid encoder output).
static int ftc_build_tree(struct ftc_decstate *ds)
{
	unsigned int num_leaves = 0, unit_weight_count = 0;
	unsigned int unit_chain_idx = 0;
	unsigned int last_nonunit_node = 0;
	unsigned int wo;
	unsigned int next_internal_node;
	unsigned int front;

	for(wo=0; wo<FTC_LEAF_LIMIT_WO; wo+=4) {
		unsigned int carry_node = wo;
		u16 w;

		w = ftc_leaf_weight_get(ds, wo);
		if(w!=0) {
			if(w==1) {
				carry_node = last_nonunit_node;
				ftc_queue_id_set(ds, num_leaves, ftc_queue_id_get(ds, unit_chain_idx));
				num_leaves++;
				ftc_queue_id_set(ds, unit_chain_idx, (u16)wo);
				unit_weight_count++;
				unit_chain_idx++;
			}
			else {
				ftc_queue_id_set(ds, num_leaves, (u16)wo);
				num_leaves++;
			}
		}
		last_nonunit_node = carry_node;
	}
	if(num_leaves==0) {
		return 0;
	}
	if(num_leaves==1) {
		// Degenerate case: exactly one nonzero-weight symbol. Synthesize a
		// second, weight-1 leaf so the merge loop below always has >=2 items.
		ftc_queue_id_next_set(ds, 0, ftc_queue_id_get(ds, unit_weight_count));
		num_leaves = 2;
		ftc_queue_id_set(ds, unit_weight_count, (u16)last_nonunit_node);
		unit_weight_count++;
		ftc_leaf_weight_set(ds, last_nonunit_node, 1);
	}
	// Populate qweight for the whole queue (leaf ids only, at this point)
	// from leaf_weight before sort/merge take over co-located tracking.
	{
		unsigned int qi;

		for(qi=0; qi<num_leaves; qi++) {
			ftc_queue_weight_set(ds, qi, ftc_leaf_weight_get(ds, ftc_queue_id_get(ds, qi)));
		}
	}
	ftc_sort_range(ds, num_leaves-1, unit_weight_count);

	// ---- repeatedly merge the two lowest-weight remaining items ----
	next_internal_node = FTC_LEAF_LIMIT_WO;
	front = 0;
	if(num_leaves!=2) {
		unsigned int remaining = num_leaves;

		do {
			u16 child0, child1;
			unsigned int search_lo, mid, search_hi, insert_pos;
			u16 merged_weight;

			remaining--;
			child0 = ftc_queue_id_get(ds, front);
			child1 = ftc_queue_id_next_get(ds, front);
			merged_weight = (u16)(ftc_queue_weight_next_get(ds, front) + ftc_queue_weight_get(ds, front));
			search_lo = front + 2;
			front++;
			mid = (num_leaves + search_lo) >> 1;
			search_hi = num_leaves;
			insert_pos = mid;
			if(search_lo < num_leaves) {
				int cont;

				do {
					if(ftc_queue_weight_get(ds, mid) < merged_weight) {
						search_lo = mid + 1;
						mid = search_hi;
					}
					insert_pos = (search_lo + mid) >> 1;
					cont = (search_lo < mid) ? 1 : 0;
					search_hi = mid;
					mid = insert_pos;
				} while(cont);
			}
			{
				unsigned int shift_count = (insert_pos - 1) - front;

				if((int)shift_count > 0) {
					de_memmove(&ds->sort_scratch[front],
						&ds->sort_scratch[front+1],
						shift_count*sizeof(u16));
					de_memmove(&ds->qweight[front],
						&ds->qweight[front+1],
						shift_count*sizeof(u16));
				}
			}
			ftc_queue_id_set(ds, insert_pos-1, (u16)next_internal_node);
			ftc_queue_weight_set(ds, insert_pos-1, merged_weight);
			ftc_parent_set(ds, child0, next_internal_node, 1);
			ftc_parent_set(ds, child1, next_internal_node, 0);
			next_internal_node += 4;
		} while(remaining!=2);
	}
	// Final merge: combine the last two remaining items into the root. Its
	// weight is never needed again (nothing looks it up after this), so
	// unlike every other merge step, no qweight write is needed here.
	{
		u16 last_child0 = ftc_queue_id_get(ds, front);
		u16 last_child1 = ftc_queue_id_next_get(ds, front);

		ftc_parent_set(ds, last_child0, next_internal_node, 1);
		ftc_parent_set(ds, last_child1, next_internal_node, 0);
	}
	return 1;
}

// For each leaf with a parent (parentbit!=0 -- weight-0 leaves never entered
// the merge queue), climbs parentbit up to the root, building the code
// bottom-up: the branch bit at depth d becomes code bit d, so the leaf's own
// bit ends up as the LSB and the root's as the MSB -- equivalent to a
// top-down MSB-first walk (bit 1 -> child0, bit 0 -> child1) without needing
// a child0/child1 table. Registers each leaf's index (node>>2) as the value.
static void ftc_emit_codes(struct ftc_decstate *ds, struct fmtutil_huffman_decoder *hd)
{
	unsigned int wo;

	for(wo=0; wo<FTC_LEAF_LIMIT_WO; wo+=4) {
		u64 code = 0;
		unsigned int nbits = 0;
		unsigned int cur = wo;

		if(ds->parentbit[wo>>2]==0) continue;
		while(1) {
			u16 pb = ds->parentbit[cur>>2];

			if(pb==0) break;
			if(nbits >= FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) { ds->emit_failed = 1; break; }
			code |= ((u64)((pb & 0x8000) ? 1 : 0)) << nbits;
			nbits++;
			cur = (unsigned int)(pb & 0x7fff) << 2;
		}
		if(ds->emit_failed) return;
		if(!fmtutil_huffman_add_code(ds->c, hd->bk, code, nbits, (fmtutil_huffman_valtype)(wo>>2))) {
			ds->emit_failed = 1;
			return;
		}
	}
}

// Builds a fresh fmtutil_huffman decoder from parentbit (populated by a
// preceding ftc_build_tree call), destroying any decoder already in *dst.
// Returns 0 (leaving *dst NULL) only on an unexpected add_code failure.
static int ftc_build_decoder(struct ftc_decstate *ds, struct fmtutil_huffman_decoder **dst)
{
	struct fmtutil_huffman_decoder *hd;

	if(*dst) {
		fmtutil_huffman_destroy_decoder(ds->c, *dst);
		*dst = NULL;
	}
	hd = fmtutil_huffman_create_decoder(ds->c, FTC_DESCRIPTORTABLE_LEN, 0);
	ds->emit_failed = 0;
	ftc_emit_codes(ds, hd);
	if(ds->emit_failed) {
		fmtutil_huffman_destroy_decoder(ds->c, hd);
		return 0;
	}
	*dst = hd;
	return 1;
}

// Destroys dec_b if it owns a distinct allocation (not just aliasing dec_a),
// then clears it. Shared by ftc_scale_frequencies and final teardown.
static void ftc_dec_b_release(struct ftc_decstate *ds)
{
	if(ds->dec_b && ds->dec_b != ds->dec_a) {
		fmtutil_huffman_destroy_decoder(ds->c, ds->dec_b);
	}
	ds->dec_b = NULL;
}

// Scales raw_weights[] by one of the block's 4 "model bytes" (per-symbol via
// ftc_type_table), normalizes so the max scaled weight fits under 0x10000, and
// builds a tree. ftc_scale_frequencies (below) always uses this for Table A;
// for Table B only when the model bytes lack a "mirror" symmetry -- otherwise
// dec_b just aliases dec_a.
static int ftc_compute_scaled_freq(struct ftc_decstate *ds, unsigned int mult0, unsigned int mult1)
{
	unsigned int i;
	u16 max_w = 0;
	unsigned int scale;

	de_zeromem(ds->parentbit, sizeof(ds->parentbit));
	de_zeromem(ds->leaf_weight, sizeof(ds->leaf_weight));
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) {
		u16 raw = ds->raw_weights[i];

		if(raw!=0) {
			unsigned int mult = (ds->tbls->ftc_type_table[i]==0) ? mult0 : mult1;
			u16 v = (u16)((raw * mult) & 0xffff);

			ftc_leaf_weight_set(ds, i*4, v);
			if(max_w < v) max_w = v;
		}
	}
	scale = 0;
	if(max_w >= 0x100) scale = 0xffffU / max_w;
	if(scale!=0) {
		unsigned int wo;

		for(wo=0; wo<FTC_LEAF_LIMIT_WO; wo+=4) {
			u16 w = ftc_leaf_weight_get(ds, wo);
			unsigned int v = (w * scale) >> 8;

			if(w!=0 && v==0) v = 1;
			ftc_leaf_weight_set(ds, wo, (u16)v);
		}
	}
	return ftc_build_tree(ds);
}

static int ftc_scale_frequencies(struct ftc_decstate *ds)
{
	// dec_a is about to be rebuilt, invalidating any alias to it.
	ftc_dec_b_release(ds);

	if(!ftc_compute_scaled_freq(ds, ds->model_m0, ds->model_m1)) return 0;
	if(!ftc_build_decoder(ds, &ds->dec_a)) return 0;
	ds->dec_b = ds->dec_a;

	if(ds->model_m2 != ds->model_m1 || ds->model_m0 != ds->model_m3) {
		if(ds->model_m2!=0 || ds->model_m3!=0) {
			if(!ftc_compute_scaled_freq(ds, ds->model_m3, ds->model_m2)) return 0;
			// dec_a still owns the aliased allocation; just clear the pointer.
			ds->dec_b = NULL;
			if(!ftc_build_decoder(ds, &ds->dec_b)) return 0;
		}
		// else: mult (0,0) would zero every weight, so this branch is
		// skipped -- rebuilding would just reproduce Table A's tree exactly
		// (ftc_build_tree is pure in ds->leaf_weight, untouched since Table
		// A). dec_b stays aliased to dec_a above.
	}
	return 1;
}

// On a mode change, patches the shared ftc_type_table[320]/
// ftc_extrastep_table[64] globals and (re)builds dec_digitchain. A
// single-slot cache, not one per mode: real files never toggle mode within a
// member, so a toggle just costs a rebuild (still correct, just not free).
// The globals are safe to patch in place: fmtutil_ftcomp_codectype1
// re-unpacks them fresh at the top of every call, and calls are never nested
// or concurrent, so there's no cross-call or cross-member leakage.
static int ftc_ensure_digitchain_decoder(struct ftc_decstate *ds, unsigned int mode)
{
	unsigned int i;

	ds->mode = mode;
	if(ds->last_mode==mode) return 1;
	ds->last_mode = mode;

	// TODO?: Modifying the shared tables in-place like this is not ideal.
	// It won't work if someone wants to make the decoder thread-safe.
	if(mode>=FTC_MODE_FT21) {
		ds->tbls->ftc_type_table[320] = 1;
		ds->tbls->ftc_extrastep_table[64] = 2;
	}
	else {
		ds->tbls->ftc_type_table[320] = 0;
		ds->tbls->ftc_extrastep_table[64] = 0;
	}

	de_zeromem(ds->parentbit, sizeof(ds->parentbit));
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) ftc_leaf_weight_set(ds, i*4, ds->tbls->ftc_digitchain_weights[i]);
	if(mode>=FTC_MODE_FT21) {
		ftc_leaf_weight_set(ds, 252*4, 4);
		ftc_leaf_weight_set(ds, 253*4, 4);
		ftc_leaf_weight_set(ds, 254*4, 0);
		ftc_leaf_weight_set(ds, 255*4, 0);
		ftc_leaf_weight_set(ds, 257*4, 0x78);
	}
	if(!ftc_build_tree(ds)) return 0;
	if(!ftc_build_decoder(ds, &ds->dec_digitchain)) return 0;
	return 1;
}

// ===========================================================================
// STAGE 1 FSM: struct ftc_stage1state is owned for the duration of one
// ftc_decode_stage1 call; decoder state / bitreader / output buffer are
// passed in separately to each function.
// ===========================================================================

// CHAIN_STEP_2/3 are the multi-step chain's middle values; CHAIN_TERMINAL is
// a comparison target only, never itself a stored chain_state value.
#define FTC_CS_FRESH          0
#define FTC_CS_SINGLE         1
#define FTC_CS_COMBINE        2
#define FTC_CS_CHAIN_STEP_1   3
#define FTC_CS_CHAIN_STEP_2   4
#define FTC_CS_CHAIN_STEP_3   5
#define FTC_CS_CHAIN_TERMINAL 6

// --- Stream-position tracking for the digit-chain width gate ---------------
// ds->stream_pos is the exact count of decompressed bytes produced by the
// member so far, seeded from FTC_PRESET_DICT_LEN and advanced by each
// block's real (stage-2-measured) length in ftc_decode_block -- never by
// the per-symbol estimate below.
// st->stream_pos_est is a working copy taken from ds->stream_pos at the
// start of each block (FTC_STREAM_POS_DISABLED for fT19, which never gates)
// and advanced per-symbol in ftc_read_fresh/ftc_read_chain_continuation --
// an estimate of position *within* the block, used only to pick a
// digit-chain bit-width form at the threshold checks below. It is
// discarded at block end and never written back to ds->stream_pos.
#define FTC_STREAM_POS_THRESH1  20736
#define FTC_STREAM_POS_THRESH2  37120

// Sentinel stream_pos_est for fT19 (no gating applies): far above both
// thresholds above, and since stream_pos_est only ever increases by at
// most tens of millions total per call, it can never fall back into range.
#define FTC_STREAM_POS_DISABLED  0x40000000u

struct ftc_stage1state {
	unsigned int chain_state;
	unsigned int table_sel; // 0 -> dec_a (Table A); nonzero -> dec_b (Table B)

	// This block's running estimate; see the stream-position comment
	// above FTC_STREAM_POS_THRESH1.
	u32 stream_pos_est;

	// Chosen digit-chain form (0/1/2); persists stale across unrelated
	// sequences, reassigned only by the non-chain_alt_flag branch.
	unsigned int last_digit_form;

	// Set when a length-class symbol's extra_step_table offset is exactly
	// 0x40 and mode>=FT21; selects a simpler 2-bit read for the next sequence.
	unsigned int chain_alt_flag;

	struct ftc_mrurank mtf_single; // chain_state===SINGLE site
	struct ftc_mrurank mtf_form0;  // form-class 0 (shift_amt=4, +0x10)
	struct ftc_mrurank mtf_form1;  // form-class 1 (shift_amt=6, +0x44)
	struct ftc_mrurank mtf_form2;  // form-class 2 (shift_amt=7, +0xa2)
	struct ftc_mrurank mtf_chain;  // chain-final site (chain_state reaches CHAIN_TERMINAL)
	struct ftc_mrurank mtf_alt;    // fT21-only "alt" site; used only when chain_alt_flag set
};

static void ftc_stage1state_init(struct ftc_stage1state *st, struct ftc_decstate *ds)
{
	de_zeromem(st, sizeof(struct ftc_stage1state));
	st->chain_state = FTC_CS_FRESH;
	st->stream_pos_est = (ds->mode>=FTC_MODE_FT21) ? ds->stream_pos : FTC_STREAM_POS_DISABLED;
	ftc_mrurank_init(&st->mtf_single);
	ftc_mrurank_init(&st->mtf_form0);
	ftc_mrurank_init(&st->mtf_form1);
	ftc_mrurank_init(&st->mtf_form2);
	ftc_mrurank_init(&st->mtf_chain);
	ftc_mrurank_init(&st->mtf_alt);

	de_zeromem(ds->ring_matchdist.buf, sizeof(ds->ring_matchdist.buf));
	ds->ring_matchdist.idx = FTC_MRURING_SIZE;
	de_zeromem(ds->ring_lenpos.buf, sizeof(ds->ring_lenpos.buf));
	ds->ring_lenpos.idx = FTC_MRURING_SIZE;
}

// Symbol-class boundaries, mirroring ftc_type_table's own grouping of the
// 433 descriptor leaves.
#define FTC_SYM_LENCLASS_START    0x100 // sym < this: literal byte; sym >= this: length-class escape (offset = sym-LENCLASS_START, indexes extra_step_table)
#define FTC_SYM_RECENTWORD_START  0x181 // sym >= this (and < MATCHDIST_START): replay a short-lookback output window
#define FTC_SYM_MATCHDIST_START   0x191 // sym >= this (and < LENPOS_START): replay via ring_matchdist
#define FTC_SYM_LENPOS_START      0x1a1 // sym >= this: replay via ring_lenpos

// Reads one symbol, dispatching by ftc_type_table into literal /
// length-class-escape / instant-match-replay. Always updates
// table_sel/chain_state; chain_alt_flag only in the length-class branch.
static void ftc_read_fresh(struct ftc_stage1state *st, struct ftc_decstate *ds, struct de_bitreader *br, dbuf *out)
{
	unsigned int chain_state = FTC_CS_FRESH;
	unsigned int sym;
	u32 gate_delta = 0;
	// out's length before this symbol's own writes below -- needed (not just
	// dbuf_get_length(out) inline) because some branches read this position
	// again after already having appended their own bytes to out.
	i64 pos_before = dbuf_get_length(out);

	sym = ftc_br_read_sym(br, (st->table_sel==0) ? ds->dec_a : ds->dec_b);
	st->table_sel = (unsigned int)ds->tbls->ftc_type_table[sym];

	if(sym < FTC_SYM_LENCLASS_START) {
		gate_delta = 1;
		dbuf_writebyte(out, (u8)sym);
		if(sym==FTC_LZESCAPE_BYTE && ds->mode>=FTC_MODE_FT21) {
			dbuf_writebyte(out, 0xff);
		}
	}
	else if(sym < FTC_SYM_RECENTWORD_START) {
		unsigned int len_class_offset = sym - FTC_SYM_LENCLASS_START;
		u8 escbuf[2];

		escbuf[0] = FTC_LZESCAPE_BYTE;
		escbuf[1] = (u8)len_class_offset;
		dbuf_write(out, escbuf, 2);
		chain_state = (unsigned int)ds->tbls->ftc_extrastep_table[len_class_offset];
		if(chain_state != FTC_CS_FRESH) {
			if(chain_state <= FTC_CS_COMBINE) gate_delta = (len_class_offset & 0x3f) + 3;
			st->chain_alt_flag = (len_class_offset==0x40 && ds->mode>=FTC_MODE_FT21) ? 1 : 0;
			ftc_mruring_push(&ds->ring_lenpos, (u16)(pos_before + 1));
		}
	}
	else if(sym < FTC_SYM_MATCHDIST_START) {
		// Short-lookback replay: word_val comes from output bytes already
		// written a few positions back (sym==385 -> last 2 bytes, ...,
		// sym==400 -> 17 back), then cached into ring_matchdist for reuse.
		unsigned int word_val = (unsigned int)dbuf_getu16le(out, pos_before + 383 - (i64)sym);

		dbuf_writeu16le(out, word_val);
		gate_delta = ((word_val & 0xff)==FTC_LZESCAPE_BYTE) ? 1 : 2;
		ftc_mruring_push(&ds->ring_matchdist, (u16)word_val);
	}
	else if(sym >= FTC_SYM_LENPOS_START) {
		// Replays a previously-seen length-class escape from ring_lenpos
		// (mirrors ftc_lz_expand's non-literal shapes):
		//   src0==0x80: 0x9E + length byte + 2-byte distance (4 payload bytes)
		//   src0&0x40:  0x9E + 1 extra byte + 2-byte distance (3 payload bytes)
		//   otherwise:  0x9E + 2-byte distance (2 payload bytes)
		unsigned int n_words = sym - FTC_SYM_LENPOS_START;
		i64 src_pos = ftc_mruring_peek(&ds->ring_lenpos, n_words);
		i64 pair;
		u8 src0;

		dbuf_writebyte(out, FTC_LZESCAPE_BYTE);
		// src_pos+1 can equal pos_before exactly, so this read must stay
		// after the write above to observe the ESCAPE_BYTE just written.
		pair = dbuf_getu16le(out, src_pos);
		src0 = (u8)(pair & 0xff);
		dbuf_writeu16le(out, pair);
		if(src0==0x80) {
			dbuf_writeu16le(out, dbuf_getu16le(out, src_pos+2));
		}
		else if(src0 & 0x40) {
			dbuf_writebyte(out, dbuf_getbyte(out, src_pos+2));
		}
		if(src0<=0x80 && ds->tbls->ftc_extrastep_table[src0]<3) {
			gate_delta = (src0 & 0x3f) + 3;
		}
		else {
			// == dbuf_getbyte(out, src_pos+1): already captured in pair's high byte.
			gate_delta = (u32)((pair >> 8) & 0xff) + 0x43;
		}
		ftc_mruring_promote(&ds->ring_lenpos, n_words, (u16)(pos_before + 1));
	}
	else {
		// MRU-ring replay of a word_val previously cached by the
		// short-lookback class above.
		unsigned int n_words = sym - FTC_SYM_MATCHDIST_START;
		unsigned int word_val = ftc_mruring_peek(&ds->ring_matchdist, n_words);

		dbuf_writeu16le(out, word_val);
		gate_delta = ((word_val & 0xff)==FTC_LZESCAPE_BYTE) ? 1 : 2;
		ftc_mruring_promote(&ds->ring_matchdist, n_words, (u16)word_val);
	}
	st->stream_pos_est += gate_delta;
	st->chain_state = chain_state;
}

// Resumes a chain started by the previous ftc_read_fresh call: either reads
// one more raw digit (chain_state>COMBINE), or performs the combine-form
// value assembly (SINGLE/COMBINE) -- picking one of 3 length-bucket forms
// (0/1/2) plus a small immediate field for that form's low bits. Always
// always mutates st->chain_state/stream_pos_est (the latter by a
// zero delta when not gated); last_digit_form only where touched.
static void ftc_read_chain_continuation(struct ftc_stage1state *st, struct ftc_decstate *ds,
	struct de_bitreader *br, dbuf *out)
{
	unsigned int chain_state = st->chain_state;
	u32 gate_delta = 0;

	if(chain_state > FTC_CS_COMBINE) {
		// One more raw digit-chain step: the final (TERMINAL) step
		// un-ranks via MTF; every earlier step just remaps per mode.
		unsigned int digit = ftc_br_read_sym(br, ds->dec_digitchain);

		chain_state = chain_state + 1;
		if(chain_state==FTC_CS_CHAIN_TERMINAL) {
			chain_state = FTC_CS_FRESH;
			digit = ftc_mrurank_unrank(&st->mtf_chain, digit, ds->mode);
		}
		else if(ds->mode>=FTC_MODE_FT21) {
			digit = (digit < 0x100) ? (digit + 2) : (digit - 0x100);
			if(chain_state==FTC_CS_CHAIN_STEP_2) gate_delta = digit + 0x43;
		}
		else if(digit==0x100) {
			digit = 0; // fT19 escape sentinel
		}
		else {
			digit = digit + 1; // fT19: shift up past the reserved value 0
		}
		dbuf_writebyte(out, (u8)(digit & 0xff));
	}
	else {
		unsigned int immediate = 0, form_sel = 0;
		unsigned int digit;

		if(chain_state==FTC_CS_COMBINE) {
			// 9-bit lookahead: w9 bit8 = next unconsumed bit, bit7 = 2nd,
			// ..., bit0 = 9th. de_bitbuf_lowlevel_get_bits doesn't clear the
			// underlying bits, only the valid-bit count, so widening
			// nbits_in_bitbuf back up by (9-width) below un-consumes
			// whatever w9 bits this branch didn't end up using.
			u32 w9 = (u32)de_bitreader_getbits(br, 9);
			unsigned int width;

			// Variable-length prefix code, gated by stream_pos_est:
			//   chain_alt_flag set     : 2 bits immediate; form = last_digit_form (reused)
			//   next bit == 0          : 5 bits (flag+4-bit imm); form 0
			//   stream_pos_est < THRESH1: 7 bits (flag+6-bit imm); form 1
			//   2nd bit == 1           : 8 or 9 bits (stream_pos_est < THRESH2?); form 2
			//   otherwise              : 8 bits (2 flags+6-bit imm); form 1
			if(st->chain_alt_flag) {
				immediate = (w9 >> 7) & 0x3;
				width = 2;
				form_sel = st->last_digit_form;
			}
			else if((w9 & 0x100)==0) {
				immediate = (w9 >> 4) & 0xf;
				width = 5;
				form_sel = 0;
			}
			else if(st->stream_pos_est < FTC_STREAM_POS_THRESH1) {
				immediate = (w9 >> 2) & 0x3f;
				width = 7;
				form_sel = 1;
			}
			else if(w9 & 0x80) {
				if(st->stream_pos_est < FTC_STREAM_POS_THRESH2) {
					immediate = (w9 >> 1) & 0x3f;
					width = 8;
				}
				else {
					immediate = w9 & 0x7f;
					width = 9;
				}
				form_sel = 2;
			}
			else {
				immediate = (w9 >> 1) & 0x3f;
				width = 8;
				form_sel = 1;
			}
			br->bbll.nbits_in_bitbuf += (9 - width);

			st->last_digit_form = form_sel;
		}
		digit = ftc_br_read_sym(br, ds->dec_digitchain);
		if(chain_state==FTC_CS_SINGLE) {
			unsigned int unranked = ftc_mrurank_unrank(&st->mtf_single, digit, ds->mode);

			dbuf_writebyte(out, (u8)(unranked & 0xff));
		}
		else {
			// Combines the MRU-unranked digit-class value (offset by a
			// per-form base) with the immediate field:
			// ((unranked + base) << shift_amt) + immediate.
			unsigned int shift_amt, base, unranked;
			u32 assembled;

			if(st->chain_alt_flag) {
				unranked = ftc_mrurank_unrank(&st->mtf_alt, digit, ds->mode);
				shift_amt = 2; base = 0x40;
			}
			else if(form_sel==0) {
				unranked = ftc_mrurank_unrank(&st->mtf_form0, digit, ds->mode);
				shift_amt = 4; base = 0x10;
			}
			else if(form_sel==1) {
				unranked = ftc_mrurank_unrank(&st->mtf_form1, digit, ds->mode);
				shift_amt = 6; base = 0x44;
			}
			else if(st->stream_pos_est < FTC_STREAM_POS_THRESH2) {
				unranked = ftc_mrurank_unrank(&st->mtf_form2, digit, ds->mode);
				shift_amt = 6; base = 0x144;
			}
			else {
				unranked = ftc_mrurank_unrank(&st->mtf_form2, digit, ds->mode);
				shift_amt = 7; base = 0xa2;
			}
			assembled = ((((u32)unranked + base) << shift_amt) + immediate) & 0xffff;
			dbuf_writeu16le(out, assembled);
		}
		chain_state = FTC_CS_FRESH;
	}
	st->stream_pos_est += gate_delta;
	st->chain_state = chain_state;
}

// ===========================================================================
// STAGE 1: compressed bits -> chunk stream (the escape-coded 0x9E LZ token
// stream later expanded by Stage 2, ftc_lz_expand). `block_start` is the
// offset into `body` of the u16 length-or-0xFFFF field, right after the
// "fT19"/"fT21" tag. Returns a membuf dbuf (caller dbuf_close's it) with
// *new_pos set past this block's bitstream, or NULL on a clean decode error.
// ===========================================================================
static dbuf *ftc_decode_stage1(deark *c, struct ftc_decstate *ds, dbuf *f, i64 body_base, i64 body_len,
	i64 block_start, i64 *new_pos)
{
	unsigned int len_field;
	dbuf *out;
	struct de_bitreader br;
	struct ftc_stage1state st;
	unsigned int sym;

	len_field = (unsigned int)dbuf_getu16le(f, body_base+block_start);

	if(len_field==0xffff) {
		i64 raw_len = dbuf_getu16le(f, body_base+block_start+2);
		i64 avail;

		out = dbuf_create_membuf(c, raw_len, 0);
		avail = body_len - (block_start+4);
		if(avail>raw_len) avail = raw_len;
		if(avail>0) dbuf_copy(f, body_base+block_start+4, avail, out);
		dbuf_truncate(out, raw_len); // zero-pads to raw_len, matching de_malloc's zero-fill
		*new_pos = block_start + 4 + raw_len;
		return out;
	}

	ds->model_m0 = dbuf_getbyte(f, body_base+block_start+2);
	ds->model_m1 = dbuf_getbyte(f, body_base+block_start+3);
	ds->model_m2 = dbuf_getbyte(f, body_base+block_start+4);
	ds->model_m3 = dbuf_getbyte(f, body_base+block_start+5);

	de_zeromem(&br, sizeof(struct de_bitreader));
	br.f = f;
	br.curpos = body_base + block_start + 6;
	// Set far beyond any reachable curpos so eof_flag never latches: this
	// codec needs a truncated/corrupt block to keep reading dbuf-OOB-safe
	// zero bits forever (see the struct de_bitreader comment above
	// ftc_br_read_sym), not stop cold the way de_bitreader_getbits normally
	// does once curpos reaches the (usually real) endpos.
	br.endpos = (i64)1 << 60;

	// ---- descriptor decode: 433 symbols via the fixed descriptor tree ----
	sym = 0;
	while(sym < FTC_DESCRIPTORTABLE_LEN) {
		unsigned int val = ftc_br_read_sym(&br, ds->dec_descriptor);

		if(val==0x100) {
			unsigned int n = 0;

			while(1) {
				if(sym+n > FTC_DESCRIPTORTABLE_LEN-1) break;
				ds->raw_weights[sym+n] = 0;
				n++;
				if(n>=0x10) break;
			}
			sym += n;
		}
		else {
			ds->raw_weights[sym] = (u16)(val & 0xff);
			sym++;
		}
	}

	if(!ftc_scale_frequencies(ds)) return NULL;

	out = dbuf_create_membuf(c, (i64)len_field + 8, 0);

	ftc_stage1state_init(&st, ds);

	if(len_field != 0) {
		do {
			if(st.chain_state==FTC_CS_FRESH) {
				ftc_read_fresh(&st, ds, &br, out);
			}
			else {
				ftc_read_chain_continuation(&st, ds, &br, out);
			}
		} while(dbuf_get_length(out) < (i64)len_field);
	}

	*new_pos = (br.curpos - body_base) - ((i64)br.bbll.nbits_in_bitbuf >> 3);
	return out;
}

// ===========================================================================
// STAGE 2 (chunks -> raw bytes). `ring` is the real, member-wide LZ history:
// a de_lz77buffer seeded from ftc_preset_dict and never reset between
// blocks, sized (see fmtutil_ftcomp_codectype1) to fit the whole member's
// output, so curpos advances monotonically and never wraps -- each block's
// output is one contiguous `ring->buf` slice, and cross-block back-references
// resolve through the same buffer.
//
// `cap_limit` hardens against a lying orig_len header exhausting memory:
// ring is pre-sized at least that large, so it's normally never hit; it
// exists so a corrupt/adversarial stream that tries to write past it fails
// cleanly (sticky `failed`) instead of wrapping curpos and corrupting
// earlier blocks' output.
// ===========================================================================
struct ftc_histbuf {
	i64 total_len; // running per-member total emitted so far, for the cap_limit gate below
	i64 cap_limit;
	int failed;
	struct de_lz77buffer *ring; // persists across the whole member
};

// hb->ring's writebyte_cb: tracks the running per-member total and sets
// sticky `failed` once it would exceed cap_limit (see the struct comment above).
static void ftc_hist_append_cb(struct de_lz77buffer *rb, u8 val)
{
	struct ftc_histbuf *hb = (struct ftc_histbuf*)rb->userdata;

	(void)val;
	if(hb->failed) return;
	hb->total_len++;
	if(hb->total_len > hb->cap_limit) hb->failed = 1;
}

// ===========================================================================
// Stage-2 LZ77 expander over one 0x9E-escape-coded chunk body, appending
// into `hb`'s history ring at its current position (matches are member-wide,
// not chunk-local -- the ring is never re-seeded between blocks). A non-0x9E
// byte is a literal; 0x9E starts an escape sequence, whose next byte (`flag`)
// selects one of 4 forms:
//   flag==lit_esc_byte : escaped literal 0x9E byte                  src+=2
//   flag==0x80         : len = src[2]+0x43,   dist = u16LE(src[3..4]) src+=5
//   (flag&0x40)==0     : len = flag+3,        dist = src[2]           src+=3
//   otherwise          : len = (flag&0x3f)+3, dist = u16LE(src[2..3]) src+=4
// lit_esc_byte is 0x40 for fT19, 0xff for fT21. `src_pos` is this chunk's
// absolute position within `stage1_out` (many chunks back-to-back); reads
// past `src_len` (this chunk's own boundary) return 0 rather than spilling
// into the next chunk, on corrupt input. Exception: the u16LE `dist` reads
// clamp only against stage1_out's overall length, not src_len -- a real but
// wrong-chunk byte on a truncated chunk, never an OOB access.
// ===========================================================================
static i64 ftc_lz_expand(struct ftc_histbuf *hb, i64 dest_off, dbuf *stage1_out, i64 src_pos, i64 src_len,
	unsigned int mode)
{
	u8 lit_esc_byte = (mode>=FTC_MODE_FT21) ? 0xff : 0x40;
	i64 s = 0;
	i64 d = dest_off;

	while(!hb->failed && s<src_len) {
		u8 cur_byte = dbuf_getbyte(stage1_out, src_pos+s);
		u8 flag;
		i64 len, dist;

		if(cur_byte != FTC_LZESCAPE_BYTE) {
			de_lz77buffer_add_literal_byte(hb->ring, cur_byte);
			d++; s++;
			continue;
		}

		flag = (s+1<src_len) ? dbuf_getbyte(stage1_out, src_pos+s+1) : 0;

		if(flag==lit_esc_byte) {
			de_lz77buffer_add_literal_byte(hb->ring, FTC_LZESCAPE_BYTE);
			d++;
			s += 2;
		}
		else if(flag==0x80) {
			u8 len_byte = (s+2<src_len) ? dbuf_getbyte(stage1_out, src_pos+s+2) : 0;

			len = (i64)len_byte + 0x43;
			dist = dbuf_getu16le(stage1_out, src_pos+s+3);
			de_lz77buffer_copy_from_hist(hb->ring, (UI)(d-1-dist), (UI)len);
			d += len;
			s += 5;
		}
		else if((flag & 0x40)==0) {
			u8 dist_byte = (s+2<src_len) ? dbuf_getbyte(stage1_out, src_pos+s+2) : 0;

			len = (i64)flag + 3;
			dist = (i64)dist_byte;
			de_lz77buffer_copy_from_hist(hb->ring, (UI)(d-1-dist), (UI)len);
			d += len;
			s += 3;
		}
		else {
			len = ((i64)flag & 0x3f) + 3;
			dist = dbuf_getu16le(stage1_out, src_pos+s+2);
			de_lz77buffer_copy_from_hist(hb->ring, (UI)(d-1-dist), (UI)len);
			d += len;
			s += 4;
		}
	}
	return d - dest_off;
}

// Walks Stage-1 output as u16-length-prefixed chunks (length includes the
// chunk's own flag byte). Flag byte 0 means already-literal; otherwise
// chunk[1..] is escape-coded, expanded via ftc_lz_expand. Both paths append
// into `hb`'s ring so back-references reach across chunk/block boundaries.
static void ftc_decode_stage2(struct ftc_histbuf *hb, dbuf *stage1_out, unsigned int mode)
{
	i64 stage1_len = dbuf_get_length(stage1_out);
	i64 p = 0;

	while(p < stage1_len) {
		i64 chunk_len, body_len, chunk_body_pos;

		if(hb->failed) return;
		if(p+2 > stage1_len) { hb->failed = 1; return; }
		chunk_len = dbuf_getu16le(stage1_out, p);
		p += 2;
		if(chunk_len<1 || p+chunk_len > stage1_len) { hb->failed = 1; return; }
		chunk_body_pos = p;
		p += chunk_len;
		body_len = chunk_len - 1;

		if(dbuf_getbyte(stage1_out, chunk_body_pos)==0) {
			i64 i;

			for(i=0; i<body_len; i++) {
				de_lz77buffer_add_literal_byte(hb->ring, dbuf_getbyte(stage1_out, chunk_body_pos+1+i));
			}
		}
		else {
			ftc_lz_expand(hb, (i64)hb->ring->curpos, stage1_out, chunk_body_pos+1, body_len, mode);
		}
	}
}

// ===========================================================================
// FRAMING (container walk, ties STAGE 1/STAGE 2/POST-PASS together).
// ===========================================================================

struct ftc_ctx {
	deark *c;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	int failed;

	dbuf *f;
	i64 body_base;
	i64 body_len;

	struct ftc_decstate dec;
	struct ftc_histbuf hb;
};

static void ftc_fail(struct ftc_ctx *ctx, const char *msg)
{
	if(ctx->failed) return;
	ctx->failed = 1;
	de_dfilter_set_errorf(ctx->c, ctx->dres, "ftcomp", "%s", msg);
}

// fT21-only RLE/MTF post-pass over one block's raw Stage-2 output (`buf`,
// `total` bytes), called from ftc_decode_block once the block is expanded.
// All reads go through dbuf_getbyte/dbuf_search_byte/dbuf_copy, so an
// out-of-range position (e.g. a corrupt `cnt`) reads as 0 / empty, never OOB.
//
// marker (input[0])==0xff means "disabled" -- plain copy of the rest.
// Otherwise: a 16-bit count at input[1..2] marks off a trailing
// control-byte region (the last `cnt` bytes); a byte-frequency histogram
// over input[0, tail_start) is built and sorted (reusing ftc_sort_range /
// ctx->dec's Huffman-build workspace -- safe, since that workspace is always
// fully repopulated before use, regardless of what a prior block left in
// it), then remapped to inverse ranks (rarest byte -> rank 255, most common
// -> rank 0). The main stream [3, tail_start) is copied literally except at
// `marker` occurrences: the next control byte is looked up; rank 0xff means
// "not a real run" (marker emitted literally), otherwise the following byte
// is repeated rank+4 times. Streams its result directly to ctx->dcmpro->f.
static void ftc_rle21(struct ftc_ctx *ctx, const u8 *buf, i64 total)
{
	dbuf *input;
	u8 marker;
	i64 cnt, tail_start;
	i64 p, src_pos, tail_pos;

	if(ctx->failed) return;

	input = dbuf_create_membuf(ctx->c, total, 0);
	dbuf_write(input, buf, total);

	marker = dbuf_getbyte(input, 0);
	if(marker==0xff) {
		if(total>1) dbuf_copy(input, 1, total-1, ctx->dcmpro->f);
		dbuf_close(input);
		return;
	}

	cnt = dbuf_getu16le(input, 1);
	if(cnt > total) {
		ftc_fail(ctx, "RLE21: control region count out of bounds");
		dbuf_close(input);
		return;
	}
	tail_start = (total - cnt) & 0xffff;

	for(p=0; p<256; p++) {
		ftc_queue_id_set(&ctx->dec, (unsigned int)p, (u16)(p*4));
		ftc_leaf_weight_set(&ctx->dec, (unsigned int)(p*4), 0);
	}
	for(p=0; p<tail_start; p++) {
		u8 b = dbuf_getbyte(input, p);

		ftc_leaf_weight_set(&ctx->dec, (unsigned int)b*4, ftc_leaf_weight_get(&ctx->dec, (unsigned int)b*4) + 1);
	}
	// queue_id(p)==p*4 (identity, set above) still holds here, so leaf_weight
	// keyed by byte value doubles as qweight keyed by queue position.
	for(p=0; p<256; p++) {
		ftc_queue_weight_set(&ctx->dec, (unsigned int)p, ftc_leaf_weight_get(&ctx->dec, (unsigned int)(p*4)));
	}
	ftc_sort_range(&ctx->dec, 0xff, 0);
	for(p=0; p<256; p++) {
		u16 byte_val = ftc_queue_id_get(&ctx->dec, (unsigned int)p);

		ftc_leaf_weight_set(&ctx->dec, byte_val, (u16)(0xff - p));
	}

	tail_pos = tail_start;
	src_pos = 3;
	while(src_pos < tail_start) {
		i64 run_start = src_pos;
		i64 found_pos = tail_start;

		dbuf_search_byte(input, marker, src_pos, tail_start-src_pos, &found_pos);
		if(found_pos > run_start) {
			dbuf_copy(input, run_start, found_pos-run_start, ctx->dcmpro->f);
		}
		src_pos = found_pos;
		if(src_pos >= tail_start) break;

		{
			u8 ctrl = dbuf_getbyte(input, tail_pos);
			u16 rank;

			tail_pos++;
			rank = ftc_leaf_weight_get(&ctx->dec, (unsigned int)ctrl*4);
			if(rank==0xff) {
				dbuf_writebyte(ctx->dcmpro->f, marker);
			}
			else {
				u8 rep = dbuf_getbyte(input, src_pos+1);
				i64 count = (i64)rank + 4;

				dbuf_write_run(ctx->dcmpro->f, rep, count);
				src_pos++;
			}
		}
		src_pos++;
	}
	dbuf_close(input);
}

// Decodes one framed fT19/fT21 block starting at *pos (right after its tag),
// emits its output, and advances *pos. ctx->dec is intentionally NOT reset
// between blocks -- the adaptive Huffman state / MRU rings persist across a
// member; only the transmitted descriptor is rebuilt fresh each block.
// Cross-block LZ back-references resolve through ctx->hb.ring, a persistent
// window spanning the whole member.
static void ftc_decode_block(struct ftc_ctx *ctx, i64 *pos, unsigned int mode)
{
	dbuf *stage1_out;
	i64 new_pos = 0;
	i64 block_start_pos;
	i64 block_len;

	if(ctx->failed) return;
	if(!ftc_ensure_digitchain_decoder(&ctx->dec, mode)) { ftc_fail(ctx, "internal Huffman tree build failure"); return; }

	stage1_out = ftc_decode_stage1(ctx->c, &ctx->dec, ctx->f, ctx->body_base, ctx->body_len, *pos, &new_pos);
	if(!stage1_out) { ftc_fail(ctx, "Stage-1 decode failed (corrupt data)"); return; }

	block_start_pos = (i64)ctx->hb.ring->curpos;
	ftc_decode_stage2(&ctx->hb, stage1_out, mode);
	dbuf_close(stage1_out);

	if(ctx->hb.failed) { ftc_fail(ctx, "Stage-2 expansion failed (corrupt data, or output too large)"); return; }

	// ring never wraps over a member's lifetime (see fmtutil_ftcomp_codectype1),
	// so this block's bytes are exactly ring->buf[block_start_pos, curpos).
	block_len = (i64)ctx->hb.ring->curpos - block_start_pos;

	// Folds this block's measured output length into stream_pos, which seeds
	// the NEXT block's digit-chain bit-field-width gate (fT19 never uses it).
	ctx->dec.stream_pos += (u32)block_len;

	*pos = new_pos;

	if(mode>=FTC_MODE_FT21) {
		ftc_rle21(ctx, &ctx->hb.ring->buf[block_start_pos], block_len);
	}
	else {
		dbuf_write(ctx->dcmpro->f, &ctx->hb.ring->buf[block_start_pos], block_len);
	}
}

// Top-level per-member pipeline: loops over ftc_decode_block until the tag
// stops matching -- there's no outer length field. Skips the leading 4-byte
// stream-marker; the first tag after it MUST be fT19/fT21, but every later
// non-match just means "no more blocks".
static void ftc_decode_member(struct ftc_ctx *ctx)
{
	i64 pos = 4;
	i64 iter = 0;

	while(pos+4 <= ctx->body_len) {
		unsigned int mode;
		struct de_fourcc tag4cc;

		dbuf_read_fourcc(ctx->f, ctx->body_base+pos, &tag4cc, 4, 0x0);
		if(tag4cc.id==CODE_fT21) mode = FTC_MODE_FT21;
		else if(tag4cc.id==CODE_fT19) mode = FTC_MODE_FT19;
		else break;
		pos += 4;

		ftc_decode_block(ctx, &pos, mode);
		if(ctx->failed) return;

		iter++;
	}

	if(iter==0) {
		// No tag matched at all. If the leftover bytes are exactly the
		// expected output size, it's a "stored" member -- marker + raw
		// bytes, no fT19/fT21 tag (used when compressing wouldn't help).
		if((ctx->body_len-pos)==ctx->dcmpro->expected_len) {
			dbuf_copy(ctx->f, ctx->body_base+pos, ctx->body_len-pos, ctx->dcmpro->f);
		}
		else {
			ftc_fail(ctx, "Missing fT19/fT21 tag");
		}
	}
}

// ===========================================================================
// Public entry point: FTCOMP/PACK2 (fT19/fT21) decompressor.
// ===========================================================================
void fmtutil_ftcomp_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct ftc_ctx *ctx = NULL;
	i64 ring_bufsize;
	unsigned int i;
	struct ftc_tbls_wrapper tblsw;

	de_zeromem(&tblsw, sizeof(struct ftc_tbls_wrapper));

	if(dcmpri->len < 4) {
		de_dfilter_set_errorf(c, dres, "ftcomp", "Compressed data too short");
		goto done;
	}

	ctx = de_malloc(c, sizeof(struct ftc_ctx));
	ctx->c = c;
	ctx->dcmpro = dcmpro;
	ctx->dres = dres;
	ctx->f = dcmpri->f;
	ctx->body_base = dcmpri->pos;
	ctx->body_len = dcmpri->len;
	// Sanity ceiling for ctx->hb growth, so a lying orig_len header can't
	// exhaust memory: expected size plus a small margin. The DE_MAX_MALLOC
	// clamp keeps the ring_bufsize doubling loop below from an unbounded header value.
	ctx->hb.cap_limit = dcmpro->expected_len + 1024;
	if(ctx->hb.cap_limit > DE_MAX_MALLOC) ctx->hb.cap_limit = DE_MAX_MALLOC;

	acquire_ftctables(c, &tblsw);

	// ring_bufsize: a power of 2 (for the ring's mask-based addressing) big
	// enough to hold a whole member's decompressed output without wrapping.
	ring_bufsize = FTC_LZWINDOW_LEN;
	while(ring_bufsize < ctx->hb.cap_limit) ring_bufsize *= 2;
	ctx->hb.ring = de_lz77buffer_create(c, (UI)ring_bufsize);
	ctx->hb.ring->writebyte_cb = ftc_hist_append_cb;
	ctx->hb.ring->userdata = (void*)&ctx->hb;

	// Zero-fill the ring, then overlay ftc_preset_dict at its tail end
	// (behind curpos 0). Via the ring's own mod-bufsize wraparound, a match
	// distance reaching before the member's first byte resolves into the
	// dict (nearest byte first); reaching further back resolves to 0. Since
	// dist<=65535, the deepest reach (d=0, dist=65535) lands at
	// ring_bufsize-65536 -- real position 0, or the zero-filled gap below
	// the dict when ring_bufsize is larger -- never past position 0.
	de_lz77buffer_clear(ctx->hb.ring, 0x00);
	de_memcpy(&ctx->hb.ring->buf[ring_bufsize - FTC_PRESET_DICT_LEN], tblsw.tbls->ftc_preset_dict,
		(size_t)FTC_PRESET_DICT_LEN);

	// One-time init: builds the descriptor tree from ftc_descriptor_weights,
	// and (via ftc_ensure_digitchain_decoder) the fT19 digit-chain tree.
	de_zeromem(&ctx->dec, sizeof(struct ftc_decstate));
	ctx->dec.c = c;
	ctx->dec.tbls = tblsw.tbls;

	de_zeromem(ctx->dec.parentbit, sizeof(ctx->dec.parentbit));
	for(i=0; i<FTC_DESCRIPTORTABLE_LEN; i++) ftc_leaf_weight_set(&ctx->dec, i*4, tblsw.tbls->ftc_descriptor_weights[i]);
	if(!ftc_build_tree(&ctx->dec) || !ftc_build_decoder(&ctx->dec, &ctx->dec.dec_descriptor)) {
		ftc_fail(ctx, "Internal Huffman tree build failure");
		goto done;
	}

	ctx->dec.stream_pos = (u32)FTC_PRESET_DICT_LEN;
	if(!ftc_ensure_digitchain_decoder(&ctx->dec, FTC_MODE_FT19)) {
		ftc_fail(ctx, "Internal Huffman tree build failure");
		goto done;
	}

	ftc_decode_member(ctx);

done:
	dbuf_flush(dcmpro->f);
	if(ctx) {
		// Destroy every fmtutil_huffman decoder owned by ctx->dec.
		ftc_dec_b_release(&ctx->dec);
		if(ctx->dec.dec_a) fmtutil_huffman_destroy_decoder(c, ctx->dec.dec_a);
		if(ctx->dec.dec_descriptor) fmtutil_huffman_destroy_decoder(c, ctx->dec.dec_descriptor);
		if(ctx->dec.dec_digitchain) fmtutil_huffman_destroy_decoder(c, ctx->dec.dec_digitchain);
		de_lz77buffer_destroy(c, ctx->hb.ring);
		de_free(c, ctx);
	}
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = dcmpri->len;
}
