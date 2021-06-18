// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Amiga DMS (Disk Masher System) disk image

// The DMS module was developed with the help of information from xDMS -
// public domain(-ish) software by Andre Rodrigues de la Rocha.

// Note:
// DMS does a thing I call "persistent decompression state".
// Roughly speaking, the state of some decompressors is reset only after
// processing a track for which the low bit of the track_flags field is 0.
// Otherwise it persists, and will most likely be used with a future track.
// I don't understand the fine details of how this works, especially when it
// comes to "extra" tracks that are not part of the main track sequence.
// xDMS behaves as if the state from an extra track never persists into a
// "real" track, or vice versa, even if its flag says it does. I have a file
// that seems to confirm that that is the case.
// But that still leaves a lot of open questions. (What's the precise
// definition of an extra track? What if there are multiple compressed extra
// tracks? Or an extra track in the middle of the real tracks? To what extent
// can multiple compression methods be used in the same file, and how do they
// interact?)

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_amiga_dms);

// Used as both the maximum number of physical tracks in the file, and (one more
// than) the highest logical track number allowed for a "real" track.
#define DMS_MAX_TRACKS 200

#define DMS_FILE_HDR_LEN 56
#define DMS_TRACK_HDR_LEN 20

#define DMSCMPR_NONE 0
#define DMSCMPR_RLE 1
#define DMSCMPR_QUICK 2
#define DMSCMPR_MEDIUM 3
#define DMSCMPR_DEEP 4
#define DMSCMPR_HEAVY1 5
#define DMSCMPR_HEAVY2 6

struct dms_track_info {
	i64 track_num; // The reported (logical) track number
	i64 dpos;
	i64 cmpr_len;
	i64 intermediate_len;
	i64 uncmpr_len;
	UI track_flags;
	UI cmpr_type;
	u8 is_real;
	u32 cksum_reported;
	u32 crc_cmprdata_reported;
	u32 crc_header_reported;
	u32 cksum_calc;
	char shortname[80];
};

struct dms_tracks_by_file_order_entry {
	i64 file_pos;
	u32 track_num;
	u8 is_real;
};

struct dms_tracks_by_track_num_entry {
	u32 order_in_file;
	u8 in_use;
};

struct dms_std_cmpr_state;
struct dmsheavy_cmpr_state;

struct std_saved_state_wrapper {
	struct dms_std_cmpr_state *saved_state;
};

struct dmsctx {
	UI info_bits;
	UI cmpr_type;
	i64 first_track, last_track;
	i64 num_tracks_in_file;

	// Entries in use: 0 <= n < .num_tracks_in_file
	struct dms_tracks_by_file_order_entry tracks_by_file_order[DMS_MAX_TRACKS];

	// Entries potentially in use: .first_track <= n <= .last_track
	struct dms_tracks_by_track_num_entry tracks_by_track_num[DMS_MAX_TRACKS];

	struct std_saved_state_wrapper saved_medium_state;
	struct std_saved_state_wrapper saved_deep_cmpr_state;
	struct dmsheavy_cmpr_state *saved_heavy_state;
};

// For some decompressors, the portion of the decompression context that can
// persist between tracks
struct dms_std_cmpr_state {
	UI cmpr_meth;
	const char *cmpr_meth_name;

	struct de_dfilter_ctx *dfctx_codec1;
	struct de_dfilter_ctx *dfctx_rle;
	i64 intermediate_nbytes;

	dbuf *outf_codec1;
	struct de_dfilter_out_params dcmpro1;
	struct de_dfilter_results dres1;
};

static const char *dms_get_cmprtype_name(UI n)
{
	const char *name = NULL;
	switch(n) {
	case DMSCMPR_NONE: name="uncompressed"; break;
	case DMSCMPR_RLE: name="simple (RLE)"; break;
	case DMSCMPR_QUICK: name="quick"; break;
	case DMSCMPR_MEDIUM: name="medium (RLE + LZ77)"; break;
	case DMSCMPR_DEEP: name="deep (RLE + LZ77+dynamic_huffman)"; break;
	case DMSCMPR_HEAVY1: name="heavy1 (optional RLE + LZ77-4K+Huffman)"; break;
	case DMSCMPR_HEAVY2: name="heavy2 (optional RLE + LZ77-8K+Huffman)"; break;
	}
	return name?name:"?";
}

static void read_unix_timestamp(deark *c, i64 pos, struct de_timestamp *ts, const char *name)
{
	i64 t;
	char timestamp_buf[64];

	t = de_geti32be(pos);
	de_unix_time_to_timestamp(t, ts, 0x1);
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t, timestamp_buf);
}

static void destroy_std_cmpr_state(deark *c, struct dms_std_cmpr_state *cst)
{
	if(!cst) return;
	if(cst->dfctx_codec1) {
		de_dfilter_destroy(cst->dfctx_codec1);
	}
	if(cst->dfctx_rle) {
		de_dfilter_destroy(cst->dfctx_rle);
	}
	dbuf_close(cst->outf_codec1);
	de_free(c, cst);
}

static void my_std1_write_cb(dbuf *f, void *userdata,
	const u8 *buf, i64 size)
{
	struct dms_std_cmpr_state *u = (struct dms_std_cmpr_state*)userdata;

	if(!u->dfctx_rle) {
		de_internal_err_fatal(f->c, "%s", u->cmpr_meth_name);
	}
	de_dfilter_addbuf(u->dfctx_rle, buf, size);
	u->intermediate_nbytes += size;
}

/////// Heavy (LZH) compression ///////

// Note: A lot of this is very similar to the code in fmtutil-lzh.c.
// The main problem with using standard LZH code for DMS is that some of the
// decompression state persists from one track to the next. But not all of it
// -- you can't just concatenate the compressed data together before
// decompressing it.

struct lzh_tree_wrapper {
	struct fmtutil_huffman_decoder *ht;
};

// The portion of the Heavy decompression context that can persist between tracks.
struct dmsheavy_cmpr_state {
	UI cmpr_type;
	UI heavy_prev_offset;
	struct de_lz77buffer *ringbuf;
	u8 trees_exist;
	struct lzh_tree_wrapper literals_tree;
	struct lzh_tree_wrapper offsets_tree;
};

// The portion of the Heavy decompression context that does *not* persist between tracks.
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

	UI heavy_np;
};

struct dmslzh_params {
	UI cmpr_type; // 5=heavy1, 6=heavy2
	u8 dms_track_flags;
	struct dmsheavy_cmpr_state *heavy_state;
};

static void lzh_set_eof_flag(struct lzh_ctx *cctx)
{
	cctx->bitrd.eof_flag = 1;
}

static void lzh_set_err_flag(struct lzh_ctx *cctx)
{
	lzh_set_eof_flag(cctx);
	cctx->err_flag = 1;
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

static UI read_next_code_using_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *tree)
{
	fmtutil_huffman_valtype val = 0;
	int ret;

	if(!tree->ht) goto done;

	ret = fmtutil_huffman_read_next_value(tree->ht->bk, &cctx->bitrd, &val, NULL);
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

static int dmsheavy_read_tree(struct lzh_ctx *cctx, struct lzh_tree_wrapper *htw,
	UI ncodes_nbits, UI symlen_nbits)
{
	deark *c = cctx->c;
	UI ncodes;
	UI curr_idx;
	int retval = 0;

	if(htw->ht) goto done;

	ncodes = (UI)de_bitreader_getbits(&cctx->bitrd, ncodes_nbits);
	de_dbg2(c, "num codes: %u", ncodes);

	htw->ht = fmtutil_huffman_create_decoder(c, (i64)ncodes, (i64)ncodes);

	if(ncodes==0) {
		UI null_val;

		null_val = (UI)de_bitreader_getbits(&cctx->bitrd, ncodes_nbits);
		fmtutil_huffman_add_code(c, htw->ht->bk, 0, 0, (fmtutil_huffman_valtype)null_val);
		de_dbg3(c, "val0: %u", null_val);
		retval = 1;
		goto done;
	}

	curr_idx = 0;
	while(curr_idx < ncodes) {
		UI symlen;

		symlen = (UI)de_bitreader_getbits(&cctx->bitrd, symlen_nbits);
		de_dbg3(c, "len[%u] = %u", curr_idx, symlen);
		fmtutil_huffman_record_a_code_length(c, htw->ht->builder, (fmtutil_huffman_valtype)curr_idx, symlen);
		curr_idx++;
	}
	if(cctx->bitrd.eof_flag) goto done;

	if(!fmtutil_huffman_make_canonical_code(c, htw->ht->bk, htw->ht->builder, 0)) goto done;

	retval = 1;
done:
	if(!retval) {
		lzh_set_err_flag(cctx);
	}
	return retval;
}

static void dmsheavy_discard_tree(deark *c, struct lzh_tree_wrapper *htw)
{
	if(htw->ht) {
		fmtutil_huffman_destroy_decoder(c, htw->ht);
		htw->ht = NULL;
	}
}

static void decompress_dms_heavy(struct lzh_ctx *cctx, struct dmslzh_params *lzhp,
	struct dmsheavy_cmpr_state *hvst)
{
	deark *c = cctx->c;
	UI rb_size;
	int ret;
	int saved_indent_level;
	char pos_descr[32];

	de_dbg_indent_save(c, &saved_indent_level);

	if(lzhp->cmpr_type != hvst->cmpr_type) {
		de_dfilter_set_errorf(c, cctx->dres, cctx->modname,
			"Mixing Heavy compression types is not supported");
		goto done;
	}

	if(lzhp->cmpr_type==DMSCMPR_HEAVY1) {
		rb_size = 4096;
		cctx->heavy_np = 14; // for heavy1
	}
	else {
		rb_size = 8192;
		cctx->heavy_np = 15; // for heavy2
	}

	if(!hvst->ringbuf) {
		hvst->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	}

	hvst->ringbuf->userdata = (void*)cctx;
	hvst->ringbuf->writebyte_cb = lha5like_lz77buf_writebytecb;

	if(!cctx->dcmpro->len_known) {
		// I think we (may) have to know the output length, because zero-length Huffman
		// codes are(?) possible, and unlike lh5 we aren't told how many codes there are.
		de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname, "Internal error");
		goto done;
	}

	if(lzhp->dms_track_flags & 0x02) {
		dmsheavy_discard_tree(c, &hvst->literals_tree);
		dmsheavy_discard_tree(c, &hvst->offsets_tree);
		hvst->trees_exist = 0;
	}

	if(!hvst->trees_exist) {
		hvst->trees_exist = 1;
		de_dbg2(c, "c tree");
		de_dbg_indent(c, 1);
		ret = dmsheavy_read_tree(cctx, &hvst->literals_tree, 9, 5);
		de_dbg_indent(c, -1);
		if(!ret) goto done;

		de_dbg2(c, "p tree");
		de_dbg_indent(c, 1);
		ret = dmsheavy_read_tree(cctx, &hvst->offsets_tree, 5, 4);
		de_dbg_indent(c, -1);
		if(!ret) goto done;
	}

	de_bitreader_describe_curpos(&cctx->bitrd, pos_descr, sizeof(pos_descr));
	de_dbg2(c, "cmpr data codes at %s", pos_descr);
	de_dbg_indent(c, 1);
	while(1) {
		UI code;

		if(cctx->bitrd.eof_flag) goto done;
		if(lzh_have_enough_output(cctx)) goto done;

		code = read_next_code_using_tree(cctx, &hvst->literals_tree);
		if(cctx->bitrd.eof_flag) goto done;
		if(c->debug_level>=3) {
			de_dbg3(c, "code: %u (opos=%"I64_FMT")", code, cctx->dcmpro->f->len);
		}

		if(code < 256) { // literal
			de_lz77buffer_add_literal_byte(hvst->ringbuf, (u8)code);
		}
		else { // repeat previous bytes
			UI offset;
			UI length;
			UI ocode1;

			length = code-253;
			ocode1 = read_next_code_using_tree(cctx, &hvst->offsets_tree);
			if(cctx->bitrd.eof_flag) goto done;

			if(ocode1 == cctx->heavy_np-1) {
				offset = hvst->heavy_prev_offset;
			}
			else {
				if(ocode1 < 1) {
					offset = ocode1;
				}
				else {
					UI ocode2;

					ocode2 = (UI)de_bitreader_getbits(&cctx->bitrd, ocode1-1);
					if(cctx->bitrd.eof_flag) goto done;
					offset = ocode2 | (1U<<(ocode1-1));
				}
				hvst->heavy_prev_offset = offset;
			}

			de_lz77buffer_copy_from_hist(hvst->ringbuf,
				(UI)(hvst->ringbuf->curpos-offset-1), length);
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void destroy_heavy_state(deark *c, struct dmsheavy_cmpr_state *hvst)
{
	if(!hvst) return;
	dmsheavy_discard_tree(c, &hvst->literals_tree);
	dmsheavy_discard_tree(c, &hvst->offsets_tree);
	de_lz77buffer_destroy(c, hvst->ringbuf);
}

static void dmslzh_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct dmslzh_params *lzhp = (struct dmslzh_params*)codec_private_params;
	struct lzh_ctx *cctx = NULL;
	struct dmsheavy_cmpr_state *hvst = NULL;

	cctx = de_malloc(c, sizeof(struct lzh_ctx));
	cctx->modname = "undmslzh";
	cctx->c = c;
	cctx->dcmpri = dcmpri;
	cctx->dcmpro = dcmpro;
	cctx->dres = dres;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	if(lzhp->heavy_state) {
		// If a previous decompression state exists, use it.
		hvst = lzhp->heavy_state;
		lzhp->heavy_state = NULL;
	}
	else {
		hvst = de_malloc(c, sizeof(struct dmsheavy_cmpr_state));
		hvst->cmpr_type = lzhp->cmpr_type;
	}

	decompress_dms_heavy(cctx, lzhp, hvst);

	hvst->ringbuf->userdata = NULL;
	hvst->ringbuf->writebyte_cb = NULL;
	lzhp->heavy_state = hvst;
	hvst = NULL;

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
	if(hvst) destroy_heavy_state(c, hvst);
	de_free(c, cctx);
}

/////// RLE compression ///////

// DMS RLE:
// n1     n2          n3  n4  n5
// ---------------------------------------------------------
// 0x90   0x00                     emit 0x90
// 0x90   0x01..0xfe  n3           emit n2 copies of n3
// 0x90   0xff        n3  n4  n5   emit (n4#n5) copies of n3
// !0x90                           emit n1

enum dmsrle_state {
	DMSRLE_STATE_NEUTRAL = 0,
	DMSRLE_STATE_90,
	DMSRLE_STATE_90_N2,
	DMSRLE_STATE_90_FF_N3,
	DMSRLE_STATE_90_FF_N3_N4
};

struct dmsrle_ctx {
	enum dmsrle_state state;
	u8 n2, n3, n4;
};

static void dmsrle_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	i64 i;
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(!rctx) goto done;

	for(i=0; i<buf_len; i++) {
		u8 n;
		i64 count;

		n = buf[i];

		switch(rctx->state) {
		case DMSRLE_STATE_NEUTRAL:
			if(n==0x90) {
				rctx->state = DMSRLE_STATE_90;
			}
			else {
				dbuf_writebyte(dfctx->dcmpro->f, n);
			}
			break;
		case DMSRLE_STATE_90:
			if(n==0x00) {
				dbuf_writebyte(dfctx->dcmpro->f, 0x90);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			else {
				rctx->n2 = n;
				rctx->state = DMSRLE_STATE_90_N2;
			}
			break;
		case DMSRLE_STATE_90_N2:
			if(rctx->n2==0xff) {
				rctx->n3 = n;
				rctx->state = DMSRLE_STATE_90_FF_N3;
			}
			else {
				count = (i64)rctx->n2;
				dbuf_write_run(dfctx->dcmpro->f, n, count);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			break;
		case DMSRLE_STATE_90_FF_N3:
			rctx->n4 = n;
			rctx->state = DMSRLE_STATE_90_FF_N3_N4;
			break;
		case DMSRLE_STATE_90_FF_N3_N4:
			count = (i64)(((UI)rctx->n4 << 8) | n);
			dbuf_write_run(dfctx->dcmpro->f, rctx->n3, count);
			rctx->state = DMSRLE_STATE_NEUTRAL;
			break;
		}
	}
done:
	;
}

static void dmsrle_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: Unused, should be NULL.
static void dmsrle_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct dmsrle_ctx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct dmsrle_ctx));
	rctx->state = DMSRLE_STATE_NEUTRAL;
	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = dmsrle_codec_addbuf;
	dfctx->codec_finish_fn = NULL;
	dfctx->codec_destroy_fn = dmsrle_codec_destroy;
}

///////////////// Codec for the LZ77 part of "Medium" decompression //////////////

enum medlzst_enum {
	MEDLZST_NEUTRAL=0,
	MEDLZST_WAITING_FOR_OCODE1,
	MEDLZST_WAITING_FOR_OCODE2
};

struct medium_state_machine {
	enum medlzst_enum state;
	// TODO: We don't really need this much state.
	UI first_code;
	UI ocode1_nbits;
	UI ocode1;
	UI ocode2_nbits;
	UI ocode2;
	UI tmp_code;
	UI d_code1, d_len1;
	UI d_code2, d_len2;
};

struct medium_ctx {
	deark *c;
	const char *modname;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	int errflag;
	i64 nbytes_written;
	struct de_lz77buffer *ringbuf;
	struct de_bitbuf_lowlevel bbll;
	struct medium_state_machine mdst;
};

static int medium_have_enough_output(struct medium_ctx *mctx)
{
	if(mctx->dcmpro->len_known) {
		if(mctx->nbytes_written >= mctx->dcmpro->expected_len) {
			return 1;
		}
	}
	return 0;
}

static void mediumlz77_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	struct medium_ctx *mctx = (struct medium_ctx *)dfctx->codec_private;
	struct medium_state_machine *mdst = &mctx->mdst;
	i64 bufpos = 0;
	UI n;
	UI offset_rel;
	UI length;

	if(dfctx->finished_flag || mctx->errflag) {
		goto done;
	}

	while(1) {
		if(medium_have_enough_output(mctx)) {
			dfctx->finished_flag = 1;
			goto done;
		}

		// Top off the bitbuf, if possible. 32 is an arbitrary number that's
		// large enough for this format.
		while(bufpos<buf_len && mctx->bbll.nbits_in_bitbuf<32) {
			de_bitbuf_lowlevel_add_byte(&mctx->bbll, buf[bufpos++]);
		}

		if(mdst->state==MEDLZST_WAITING_FOR_OCODE1) goto read_ocode1;
		if(mdst->state==MEDLZST_WAITING_FOR_OCODE2) goto read_ocode2;

		// Make sure we have enough source data to read the flag bit,
		// plus either the literal byte or the first_code.
		if(mctx->bbll.nbits_in_bitbuf < 9) goto done;

		n = (UI)de_bitbuf_lowlevel_get_bits(&mctx->bbll, 1);

		if(n) { // literal byte
			u8 b;

			b = (u8)de_bitbuf_lowlevel_get_bits(&mctx->bbll, 8);
			de_lz77buffer_add_literal_byte(mctx->ringbuf, (u8)b);
			continue;
		}

		// TODO: This seems overly complicated. Is there a simpler way to
		// implement this?

		mdst->first_code = (UI)de_bitbuf_lowlevel_get_bits(&mctx->bbll, 8);
		fmtutil_get_lzhuf_d_code_and_len(mdst->first_code, &mdst->d_code1, &mdst->d_len1);

	read_ocode1:
		mdst->ocode1_nbits = mdst->d_len1;
		if(mctx->bbll.nbits_in_bitbuf < mdst->ocode1_nbits) {
			mdst->state = MEDLZST_WAITING_FOR_OCODE1;
			goto done;
		}
		mdst->ocode1 = (UI)de_bitbuf_lowlevel_get_bits(&mctx->bbll, mdst->ocode1_nbits);

		mdst->tmp_code = ((mdst->first_code << mdst->ocode1_nbits) | mdst->ocode1) & 0xff;
		fmtutil_get_lzhuf_d_code_and_len(mdst->tmp_code, &mdst->d_code2, &mdst->d_len2);

	read_ocode2:
		mdst->ocode2_nbits = mdst->d_len2;
		if(mctx->bbll.nbits_in_bitbuf < mdst->ocode2_nbits) {
			mdst->state = MEDLZST_WAITING_FOR_OCODE2;
			goto done;
		}
		mdst->ocode2 = (UI)de_bitbuf_lowlevel_get_bits(&mctx->bbll, mdst->ocode2_nbits);

		offset_rel = (mdst->d_code2 << 8) | (((mdst->tmp_code << mdst->ocode2_nbits) | mdst->ocode2) & 0xff);
		length = mdst->d_code1 + 3;
		de_lz77buffer_copy_from_hist(mctx->ringbuf, mctx->ringbuf->curpos - 1 - offset_rel, length);
		mdst->state = MEDLZST_NEUTRAL;
	}

done:
	if(!dfctx->finished_flag && !mctx->errflag) {
		if(bufpos<buf_len) {
			// It shouldn't be possible to get here. If we do, it means some input
			// bytes will be lost.
			de_dfilter_set_generic_error(dfctx->c, mctx->dres, mctx->modname);
			mctx->errflag = 1;
		}
	}
}

static void medium_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct medium_ctx *mctx = (struct medium_ctx *)rb->userdata;

	if(medium_have_enough_output(mctx)) {
		return;
	}
	dbuf_writebyte(mctx->dcmpro->f, n);
	mctx->nbytes_written++;
}

static void mediumlz77_codec_command(struct de_dfilter_ctx *dfctx, int cmd, UI flags)
{
	struct medium_ctx *mctx = (struct medium_ctx*)dfctx->codec_private;

	if(cmd==DE_DFILTER_COMMAND_FINISH_BLOCK) {
		de_bitbuf_lowlevel_empty(&mctx->bbll);
		mctx->mdst.state = MEDLZST_NEUTRAL;
		de_lz77buffer_set_curpos(mctx->ringbuf, mctx->ringbuf->curpos + 66);
	}
	else if(cmd==DE_DFILTER_COMMAND_RESET_COUNTERS) {
		mctx->nbytes_written = 0;
		mctx->errflag = 0;
		dfctx->finished_flag = 0;
	}
}

static void mediumlz77_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct medium_ctx *mctx = (struct medium_ctx*)dfctx->codec_private;

	if(mctx) {
		de_lz77buffer_destroy(dfctx->c, mctx->ringbuf);
		de_free(dfctx->c, mctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: unused
static void dmsmediumlz77_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct medium_ctx *mctx = NULL;

	mctx = de_malloc(dfctx->c, sizeof(struct medium_ctx));
	mctx->c = dfctx->c;
	mctx->modname = "dmsmedium_lz77";
	mctx->dcmpro = dfctx->dcmpro;
	mctx->dres = dfctx->dres;

	dfctx->codec_private = (void*)mctx;
	dfctx->codec_addbuf_fn = mediumlz77_codec_addbuf;
	dfctx->codec_command_fn = mediumlz77_codec_command;
	dfctx->codec_destroy_fn = mediumlz77_codec_destroy;

	mctx->ringbuf = de_lz77buffer_create(dfctx->c, 16*1024);
	// The set_curpos isn't needed, but could help with debugging. It makes our
	// internal state the same as most other DMS software.
	de_lz77buffer_set_curpos(mctx->ringbuf, 0x3fbe);

	mctx->ringbuf->userdata = (void*)mctx;
	mctx->ringbuf->writebyte_cb = medium_lz77buf_writebytecb;
}

///////////////// "Medium" and "Deep" decompression //////////////

// Note: The Medium and Deep decompressors have a different design than Heavy.
// Both the codecs are "pushable", which is a good thing for DMS's segmented
// format.
// It may look more complicated, but ultimately it's cleaner and less hacky.

static void do_decompress_track_medium_or_deep(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct dms_std_cmpr_state *cst = NULL;
	struct std_saved_state_wrapper *ssw;

	if(tri->cmpr_type==DMSCMPR_DEEP) {
		ssw = &d->saved_deep_cmpr_state;
	}
	else {
		ssw = &d->saved_medium_state;
	}

	if(ssw->saved_state) {
		if(tri->is_real) {
			// Reclaim saved decompression state, if any
			cst = ssw->saved_state;
			ssw->saved_state = NULL;

			cst->dcmpro1.len_known = 1;
			cst->dcmpro1.expected_len = tri->intermediate_len;

			de_dfilter_command(cst->dfctx_codec1, DE_DFILTER_COMMAND_RESET_COUNTERS, 0);
		}
		else {
			destroy_std_cmpr_state(c, ssw->saved_state);
			ssw->saved_state = NULL;
		}
	}

	if(!cst) {
		cst = de_malloc(c, sizeof(struct dms_std_cmpr_state));
		cst->cmpr_meth = tri->cmpr_type;
		if(cst->cmpr_meth==DMSCMPR_DEEP) {
			cst->cmpr_meth_name = "deepcmpr";
		}
		else {
			cst->cmpr_meth_name = "mediumcmpr";
		}

		cst->outf_codec1 = dbuf_create_custom_dbuf(c, 0, 0);
		cst->outf_codec1->userdata_for_customwrite = (void*)cst;
		cst->outf_codec1->customwrite_fn = my_std1_write_cb;

		cst->dcmpro1.f = cst->outf_codec1;
		cst->dcmpro1.len_known = 1;
		cst->dcmpro1.expected_len = tri->intermediate_len;
	}

	// Reset the "length" of this virtual dbuf.
	dbuf_truncate(cst->outf_codec1, 0);

	if(cst->dfctx_rle) {
		de_dfilter_destroy(cst->dfctx_rle);
		cst->dfctx_rle = NULL;
	}
	cst->dfctx_rle = de_dfilter_create(c, dmsrle_codec, NULL, dcmpro, dres);

	if(!cst->dfctx_codec1) {
		if(cst->cmpr_meth==DMSCMPR_DEEP) {
			struct de_lh1_params lh1p;

			de_zeromem(&lh1p, sizeof(struct de_lh1_params));
			lh1p.is_dms_deep = 1;
			cst->dfctx_codec1 = de_dfilter_create(c, dfilter_lh1_codec,
				(void*)&lh1p, &cst->dcmpro1, &cst->dres1);
		}
		else {
			cst->dfctx_codec1 = de_dfilter_create(c, dmsmediumlz77_codec,
				NULL, &cst->dcmpro1, &cst->dres1);
		}
	}

	cst->dfctx_codec1->input_file_offset = dcmpri->pos;
	cst->intermediate_nbytes = 0;

	de_dfilter_addslice(cst->dfctx_codec1, dcmpri->f, dcmpri->pos, dcmpri->len);
	de_dfilter_command(cst->dfctx_codec1, DE_DFILTER_COMMAND_FINISH_BLOCK, 0);
	de_dfilter_finish(cst->dfctx_rle);

	// If cst->dfctx_lzah->dres has the error message we need, copy it to the
	// real dres.
	de_dfilter_transfer_error(c, cst->dfctx_codec1->dres, dres);

	if(tri->is_real) {
		// Note that this saved state may be deleted soon, in dms_decompress_track().
		ssw->saved_state = cst;
	}
	else {
		destroy_std_cmpr_state(c, cst);
	}
}

///////////////////////////////////

static void do_decompress_heavy_lzh_rle(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres, struct dmslzh_params *lzhparams)
{
	struct de_dcmpr_two_layer_params tlp;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_type1 = dmslzh_codectype1;
	tlp.codec1_private_params = (void*)lzhparams;
	tlp.codec2 = dmsrle_codec;
	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;
	tlp.intermed_expected_len = tri->intermediate_len;
	tlp.intermed_len_known = 1;
	de_dfilter_decompress_two_layer(c, &tlp);
}

static void do_decompress_heavy(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct dmslzh_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct dmslzh_params));
	lzhparams.cmpr_type = tri->cmpr_type;
	lzhparams.dms_track_flags = tri->track_flags;
	if(tri->is_real) {
		lzhparams.heavy_state = d->saved_heavy_state;
		d->saved_heavy_state = NULL;
	}

	if(tri->track_flags & 0x04) {
		do_decompress_heavy_lzh_rle(c, d, tri, dcmpri, dcmpro, dres, &lzhparams);
	}
	else {
		// LZH, no RLE
		dmslzh_codectype1(c, dcmpri, dcmpro, dres, (void*)&lzhparams);
	}

	if(tri->is_real) {
		d->saved_heavy_state = lzhparams.heavy_state;
	}
	else {
		destroy_heavy_state(c, lzhparams.heavy_state);
	}
}

static void destroy_saved_dcrmpr_state(deark *c, struct dmsctx *d)
{
	if(d->saved_medium_state.saved_state) {
		destroy_std_cmpr_state(c, d->saved_medium_state.saved_state);
		d->saved_medium_state.saved_state = NULL;
	}
	if(d->saved_deep_cmpr_state.saved_state) {
		destroy_std_cmpr_state(c, d->saved_deep_cmpr_state.saved_state);
		d->saved_deep_cmpr_state.saved_state = NULL;
	}
	if(d->saved_heavy_state) {
		destroy_heavy_state(c, d->saved_heavy_state);
		d->saved_heavy_state = NULL;
	}
}

static int dms_decompress_track(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	dbuf *outf)
{
	int retval = 0;
	i64 unc_nbytes;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(outf->len!=0) goto done;

	if(tri->dpos + tri->cmpr_len > c->infile->len) {
		de_err(c, "Track goes beyond end of file");
		goto done;
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = tri->dpos;
	dcmpri.len = tri->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = tri->uncmpr_len;

	tri->cksum_calc = 0;

	if(tri->cmpr_type==DMSCMPR_NONE) {
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
	}
	else if(tri->cmpr_type==DMSCMPR_RLE) {
		de_dfilter_decompress_oneshot(c, dmsrle_codec, NULL,
			&dcmpri, &dcmpro, &dres);
	}
	else if(tri->cmpr_type==DMSCMPR_MEDIUM) {
		do_decompress_track_medium_or_deep(c, d, tri, &dcmpri, &dcmpro, &dres);
	}
	else if(tri->cmpr_type==DMSCMPR_DEEP) {
		do_decompress_track_medium_or_deep(c, d, tri, &dcmpri, &dcmpro, &dres);
	}
	else if(tri->cmpr_type==DMSCMPR_HEAVY1 || tri->cmpr_type==DMSCMPR_HEAVY2) {
		do_decompress_heavy(c, d, tri, &dcmpri, &dcmpro, &dres);
	}
	else {
		de_err(c, "[%s] Unsupported compression method: %u (%s)",
			tri->shortname, tri->cmpr_type,
			dms_get_cmprtype_name(tri->cmpr_type));
		goto done;
	}

	if(dres.errcode) {
		de_err(c, "[%s] Decompression failed: %s", tri->shortname,
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	unc_nbytes = outf->len;

	dbuf_truncate(outf, tri->uncmpr_len);

	if(unc_nbytes < tri->uncmpr_len) {
		de_err(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
		goto done;
	}
	if(unc_nbytes > tri->uncmpr_len) {
		de_warn(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
	}

	retval = 1;

done:
	if(tri->is_real && !(tri->track_flags & 0x1)) {
		destroy_saved_dcrmpr_state(c, d);
	}
	return retval;
}

static int dms_checksum_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	u32 *cksum = (u32*)brctx->userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		*cksum += (u32)buf[i];
	}
	return 1;
}

// outf is presumed to be membuf containing one track, and nothing else.
static u32 dms_calc_checksum(deark *c, dbuf *outf)
{
	u32 cksum = 0;

	dbuf_buffered_read(outf, 0, outf->len, dms_checksum_cbfn, (void*)&cksum);
	cksum &= 0xffff;
	return cksum;
}

static void get_trackflags_descr(deark *c, de_ucstring *s, UI tflags1, UI cmpr)
{
	UI tflags = tflags1;

	if(cmpr==5 || cmpr==6) {
		if(tflags & 0x4) {
			ucstring_append_flags_item(s, "w/RLE");
			tflags -= 0x4;
		}
		if(tflags & 0x2) {
			ucstring_append_flags_item(s, "track has Huffman tree defs");
			tflags -= 0x2;
		}
	}
	if(tflags & 0x1) {
		ucstring_append_flags_item(s, "persist decompr. state");
		tflags -= 0x1;
	}
	if(tflags>0) ucstring_append_flags_itemf(s, "0x%02x", tflags);
}

// Read track and decompress to outf (which caller supplies as an empty membuf).
// track_idx: the index into d->tracks_by_file_order
// Returns nonzero if successfully decompressed.
static int dms_read_and_decompress_track(deark *c, struct dmsctx *d,
	i64 track_idx, dbuf *outf)
{
	i64 pos1, pos;
	struct dms_track_info *tri = NULL;
	de_ucstring *descr = NULL;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	tri = de_malloc(c, sizeof(struct dms_track_info));
	pos1 = d->tracks_by_file_order[track_idx].file_pos;
	tri->track_num = (i64)d->tracks_by_file_order[track_idx].track_num;
	tri->is_real = d->tracks_by_file_order[track_idx].is_real;
	de_snprintf(tri->shortname, sizeof(tri->shortname), "%strack %d",
		(tri->is_real?"":"extra "), (int)tri->track_num);

	de_dbg(c, "%s at %"I64_FMT, tri->shortname, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;
	pos += 2; // signature, already checked
	pos += 2; // reported track number, already read
	pos += 2; // Unknown field
	tri->cmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "cmpr len: %"I64_FMT, tri->cmpr_len);
	tri->intermediate_len = de_getu16be_p(&pos);
	de_dbg(c, "intermediate len: %"I64_FMT, tri->intermediate_len);
	tri->uncmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "uncmpr len: %"I64_FMT, tri->uncmpr_len);

	tri->track_flags = (UI)de_getbyte_p(&pos);
	tri->cmpr_type = (UI)de_getbyte_p(&pos);

	descr = ucstring_create(c);
	get_trackflags_descr(c, descr, tri->track_flags, tri->cmpr_type);
	de_dbg(c, "track flags: 0x%02x (%s)", tri->track_flags, ucstring_getpsz_d(descr));

	de_dbg(c, "track cmpr type: %u (%s)", tri->cmpr_type, dms_get_cmprtype_name(tri->cmpr_type));
	tri->cksum_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "checksum (reported): 0x%04x", (UI)tri->cksum_reported);
	tri->crc_cmprdata_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "crc of cmpr data (reported): 0x%04x", (UI)tri->crc_cmprdata_reported);
	tri->crc_header_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "crc of header (reported): 0x%04x", (UI)tri->crc_header_reported);

	tri->dpos = pos1 + DMS_TRACK_HDR_LEN;
	de_dbg(c, "cmpr data at %"I64_FMT, tri->dpos);
	de_dbg_indent(c, 1);
	if(!dms_decompress_track(c, d, tri, outf)) goto done;
	de_dbg_indent(c, -1);

	tri->cksum_calc = dms_calc_checksum(c, outf);
	de_dbg(c, "checksum (calculated): 0x%04x", (UI)tri->cksum_calc);
	if(tri->cksum_calc != tri->cksum_reported) {
		de_err(c, "[%s] Checksum check failed", tri->shortname);
		goto done;
	}
	retval = 1;

done:
	ucstring_destroy(descr);
	de_free(c, tri);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void write_extra_track(deark *c, struct dmsctx *d, i64 track_idx, dbuf *trackbuf)
{
	char ext[80];
	dbuf *outf_extra = NULL;

	de_snprintf(ext, sizeof(ext), "extratrack%d.bin",
		(int)d->tracks_by_file_order[track_idx].track_num);
	outf_extra = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_copy(trackbuf, 0, trackbuf->len, outf_extra);
	dbuf_close(outf_extra);
}

// Write out all the tracks, whether real or extra.
static void do_dms_main(deark *c, struct dmsctx *d)
{
	i64 i;
	int real_track_failure_flag = 0;
	dbuf *outf = NULL;
	dbuf *trackbuf = NULL;

	trackbuf = dbuf_create_membuf(c, 11264, 0);
	outf = dbuf_create_output_file(c, "adf", NULL, 0);

	for(i=0; i<d->num_tracks_in_file; i++) {
		int ret_dcmpr;

		if(real_track_failure_flag && d->tracks_by_file_order[i].is_real) {
			continue;
		}

		dbuf_truncate(trackbuf, 0);

		ret_dcmpr = dms_read_and_decompress_track(c, d, i, trackbuf);

		if(!ret_dcmpr) {
			if(d->tracks_by_file_order[i].is_real) {
				real_track_failure_flag = 1;
			}
			continue;
		}

		if(d->tracks_by_file_order[i].is_real) {
			dbuf_copy(trackbuf, 0, trackbuf->len, outf);
		}
		else {
			write_extra_track(c, d, i, trackbuf);
		}
	}

	dbuf_close(outf);
	dbuf_close(trackbuf);
}

static int do_dms_header(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 n;
	i64 pos = pos1;
	struct de_timestamp cr_time;
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// [0..3] = signature
	pos = pos1+8;
	d->info_bits = (UI)de_getu32be_p(&pos); // [8..11] = info bits
	de_dbg(c, "infobits: 0x%08x", d->info_bits);

	de_zeromem(&cr_time, sizeof(struct de_timestamp));
	read_unix_timestamp(c, pos, &cr_time, "creation time");
	pos += 4;

	d->first_track = de_getu16be_p(&pos); // [16..17] = firsttrack
	de_dbg(c, "first track: %d", (int)d->first_track);
	if(d->first_track >= DMS_MAX_TRACKS) goto done;
	if(d->first_track != 0) {
		de_info(c, "Note: First track is #%d, not #0. This may be a partial disk image.",
			(int)d->first_track);
	}

	d->last_track = de_getu16be_p(&pos); // [18..19] = lasttrack
	de_dbg(c, "last track: %u", (int)d->last_track);
	if(d->last_track < d->first_track) goto done;
	if(d->last_track >= DMS_MAX_TRACKS) goto done;

	n = de_getu32be_p(&pos); // [20..23] = packed len
	de_dbg(c, "compressed len: %"I64_FMT, n);

	n = de_getu32be_p(&pos); // [24..27] = unpacked len
	de_dbg(c, "decompressed len: %"I64_FMT, n);

	// [46..47] = creating software version
	pos = pos1+50;
	n = de_getu16be_p(&pos); // [50..51] = disk type
	de_dbg(c, "disk type: %u", (UI)n);

	d->cmpr_type = (UI)de_getu16be_p(&pos); // [52..53] = compression mode
	de_dbg(c, "compression type: %u (%s)", d->cmpr_type,
		dms_get_cmprtype_name(d->cmpr_type));

	n = de_getu16be_p(&pos); // [54..55] = crc
	de_dbg(c, "crc (reported): 0x%04x", (UI)n);

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int dms_scan_file(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 i;
	u32 next_real_tracknum_expected;
	int retval = 0;

	de_dbg(c, "scanning file");
	de_dbg_indent(c, 1);

	d->num_tracks_in_file = 0;

	while(1) {
		i64 track_num_reported;
		i64 cmpr_len;
		i64 uncmpr_len;
		u8 track_flags;
		u8 cmpr_type;

		if(pos+DMS_TRACK_HDR_LEN > c->infile->len) break;

		if(dbuf_memcmp(c->infile, pos, "TR", 2)) {
			de_dbg(c, "[track not found at %"I64_FMT"; assuming disk image ends here]", pos);
			break;
		}
		if(d->num_tracks_in_file >= DMS_MAX_TRACKS) {
			de_err(c, "Too many tracks in file");
			break;
		}

		track_num_reported = de_getu16be(pos+2);
		cmpr_len = de_getu16be(pos+6);
		uncmpr_len = de_getu16be(pos+10);
		track_flags = de_getbyte(pos+12);
		cmpr_type = de_getbyte(pos+13);

		de_dbg(c, "track[%d] at %"I64_FMT", #%d, len=%"I64_FMT"/%"I64_FMT", cmpr=%u, flags=0x%02x",
			(int)d->num_tracks_in_file, pos, (int)track_num_reported, cmpr_len, uncmpr_len,
			(UI)cmpr_type, (UI)track_flags);

		d->tracks_by_file_order[d->num_tracks_in_file].file_pos = pos;
		d->tracks_by_file_order[d->num_tracks_in_file].track_num = (u32)track_num_reported;

		if(track_num_reported>=d->first_track && track_num_reported<=d->last_track) {
			d->tracks_by_track_num[track_num_reported].order_in_file = (u32)d->num_tracks_in_file;
			d->tracks_by_track_num[track_num_reported].in_use = 1;
		}

		d->num_tracks_in_file++;
		pos += DMS_TRACK_HDR_LEN + cmpr_len;
	}

	// Make sure all expected tracks are present, and mark the "real" tracks in
	// tracks_by_file_order[].
	// One reason for doing it this way is that there may be two tracks numbered 0,
	// with the second one being the real one.
	for(i=d->first_track; i<=d->last_track; i++) {
		if(!d->tracks_by_track_num[i].in_use) {
			// TODO: Maybe we should write a track of all zeroes instead (but how many zeroes?)
			de_err(c, "Could not find track #%d", (int)i);
			goto done;
		}

		d->tracks_by_file_order[d->tracks_by_track_num[i].order_in_file].is_real = 1;
	}


	next_real_tracknum_expected = (u32)d->first_track;
	for(i=0; i<d->num_tracks_in_file; i++) {
		if(d->tracks_by_file_order[i].is_real) {
			// I'm not going to bother supporting out-of-order tracks, at least until
			// I learn that such files exist.
			if(d->tracks_by_file_order[i].track_num != next_real_tracknum_expected) {
				de_err(c, "Track numbers not in order. Not supported.");
				goto done;
			}
			next_real_tracknum_expected = d->tracks_by_file_order[i].track_num + 1;
		}
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_amiga_dms(deark *c, de_module_params *mparams)
{
	struct dmsctx *d = NULL;

	d = de_malloc(c, sizeof(struct dmsctx));
	if(!do_dms_header(c, d, 0)) goto done;
	if(!dms_scan_file(c, d, DMS_FILE_HDR_LEN)) goto done;
	do_dms_main(c, d);

done:
	if(d) {
		destroy_saved_dcrmpr_state(c, d);
		de_free(c, d);
	}
}

static int de_identify_amiga_dms(deark *c)
{
	i64 dcmpr_size;

	if(dbuf_memcmp(c->infile, 0, "DMS!", 4)) return 0;
	dcmpr_size = de_getu32be(24);
	if(dcmpr_size==901120) return 100;
	return 85;
}

void de_module_amiga_dms(deark *c, struct deark_module_info *mi)
{
	mi->id = "amiga_dms";
	mi->desc = "Amiga DMS disk image";
	mi->run_fn = de_run_amiga_dms;
	mi->identify_fn = de_identify_amiga_dms;
}
