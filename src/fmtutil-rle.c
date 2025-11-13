// This file is part of Deark.
// Copyright (C) 2018-2025 Jason Summers
// See the file COPYING for terms of use.

// Some decompression routines that (more or less) only use
// run-length encoding.

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

///////////////////////////////////
// PackBits

enum packbits_state_enum {
	PACKBITS_STATE_NEUTRAL = 0,
	PACKBITS_STATE_COPYING_LITERAL,
	PACKBITS_STATE_READING_UNIT_TO_REPEAT
};

#define DE_PACKBITS_MAX_NBYTES_PER_UNIT 8
struct packbitsctx {
	size_t nbytes_per_unit;
	size_t nbytes_in_unitbuf;
	u8 unitbuf[DE_PACKBITS_MAX_NBYTES_PER_UNIT];
	i64 total_nbytes_processed;
	i64 nbytes_written;
	enum packbits_state_enum state;
	i64 nliteral_bytes_remaining;
	i64 repeat_count;
	const char *modname;
};

static void my_packbits_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	int i;
	u8 b;
	struct packbitsctx *rctx = (struct packbitsctx*)dfctx->codec_private;

	if(!rctx) return;
	if(dfctx->dres->errcode) return;
	if(dfctx->finished_flag) return;

	for(i=0; i<buf_len; i++) {
		if(dfctx->dcmpro->len_known &&
			(rctx->nbytes_written >= dfctx->dcmpro->expected_len))
		{
			dfctx->finished_flag = 1;
			break;
		}

		b = buf[i];
		rctx->total_nbytes_processed++;

		switch(rctx->state) {
		case PACKBITS_STATE_NEUTRAL: // this is a code byte
			if(b>128) { // A compressed run
				rctx->repeat_count = 257 - (i64)b;
				rctx->state = PACKBITS_STATE_READING_UNIT_TO_REPEAT;
			}
			else if(b<128) { // An uncompressed run
				rctx->nliteral_bytes_remaining = (1 + (i64)b) * (i64)rctx->nbytes_per_unit;
				rctx->state = PACKBITS_STATE_COPYING_LITERAL;
			}
			// Else b==128. No-op.
			// TODO: Some (but not most) ILBM specs say that code 128 is used to
			// mark the end of compressed data, so maybe there should be options to
			// tell us what to do when code 128 is encountered.
			break;
		case PACKBITS_STATE_COPYING_LITERAL: // This byte is uncompressed
			dbuf_writebyte(dfctx->dcmpro->f, b);
			rctx->nbytes_written++;
			rctx->nliteral_bytes_remaining--;
			if(rctx->nliteral_bytes_remaining<=0) {
				rctx->state = PACKBITS_STATE_NEUTRAL;
			}
			break;
		case PACKBITS_STATE_READING_UNIT_TO_REPEAT:
			if(rctx->nbytes_per_unit==1) { // Optimization for standard PackBits
				dbuf_write_run(dfctx->dcmpro->f, b, rctx->repeat_count);
				rctx->nbytes_written += rctx->repeat_count;
				rctx->state = PACKBITS_STATE_NEUTRAL;
			}
			else {
				rctx->unitbuf[rctx->nbytes_in_unitbuf++] = b;
				if(rctx->nbytes_in_unitbuf >= rctx->nbytes_per_unit) {
					i64 k;

					for(k=0; k<rctx->repeat_count; k++) {
						dbuf_write(dfctx->dcmpro->f, rctx->unitbuf, (i64)rctx->nbytes_per_unit);
					}
					rctx->nbytes_in_unitbuf = 0;
					rctx->nbytes_written += rctx->repeat_count * (i64)rctx->nbytes_per_unit;
					rctx->state = PACKBITS_STATE_NEUTRAL;
				}
			}
			break;
		}
	}
}

static void my_packbits_codec_command(struct de_dfilter_ctx *dfctx, int cmd, UI flags)
{
	struct packbitsctx *rctx = (struct packbitsctx*)dfctx->codec_private;

	if(cmd==DE_DFILTER_COMMAND_SOFTRESET || cmd==DE_DFILTER_COMMAND_REINITIALIZE) {
		// "soft reset" - reset the low-level compression state, but don't update
		// dres, or the total-bytes counters, etc.
		rctx->state = PACKBITS_STATE_NEUTRAL;
		rctx->nbytes_in_unitbuf = 0;
		rctx->nliteral_bytes_remaining = 0;
		rctx->repeat_count = 0;
	}
	if(cmd==DE_DFILTER_COMMAND_REINITIALIZE) {
		rctx->total_nbytes_processed = 0;
		rctx->nbytes_written = 0;
	}
}

static void my_packbits_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct packbitsctx *rctx = (struct packbitsctx*)dfctx->codec_private;

	if(!rctx) return;
	dfctx->dres->bytes_consumed = rctx->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;
}

static void my_packbits_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct packbitsctx *rctx = (struct packbitsctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: de_packbits_params, or NULL for default params.
void dfilter_packbits_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct packbitsctx *rctx = NULL;
	struct de_packbits_params *pbparams = (struct de_packbits_params*)codec_private_params;

	rctx = de_malloc(dfctx->c, sizeof(struct packbitsctx));
	rctx->modname = "packbits";

	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = my_packbits_codec_addbuf;
	dfctx->codec_finish_fn = my_packbits_codec_finish;
	dfctx->codec_command_fn = my_packbits_codec_command;
	dfctx->codec_destroy_fn = my_packbits_codec_destroy;

	rctx->nbytes_per_unit = 1;
	if(pbparams) {
		if(pbparams->nbytes_per_unit>DE_PACKBITS_MAX_NBYTES_PER_UNIT) {
			de_dfilter_set_generic_error(dfctx->c, dfctx->dres, rctx->modname);
		}
		else if(pbparams->nbytes_per_unit>1) {
			rctx->nbytes_per_unit = pbparams->nbytes_per_unit;
		}
	}
}

void fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_packbits_params *pbparams)
{
	de_dfilter_decompress_oneshot(c, dfilter_packbits_codec, (void*)pbparams,
		dcmpri, dcmpro, dres);
}

// Returns 0 on failure.
int fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = 0;
	de_dfilter_init_objects(f->c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = f;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	if(unc_pixels->has_len_limit) {
		dcmpro.len_known = 1;
		dbuf_flush(unc_pixels);
		dcmpro.expected_len = unc_pixels->len_limit - unc_pixels->len;
	}

	de_dfilter_decompress_oneshot(f->c, dfilter_packbits_codec, NULL,
		&dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

///////////////////////////////////
// RLE90

void fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	de_dfilter_decompress_oneshot(c, dfilter_rle90_codec, NULL,
		dcmpri, dcmpro, dres);
}

struct rle90ctx {
	i64 total_nbytes_processed;
	i64 nbytes_written;
	u8 last_output_byte;
	int countcode_pending;
};

static void my_rle90_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	int i;
	u8 b;
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(!rctx) return;

	for(i=0; i<buf_len; i++) {
		if(dfctx->dcmpro->len_known &&
			(rctx->nbytes_written >= dfctx->dcmpro->expected_len))
		{
			dfctx->finished_flag = 1;
			break;
		}

		b = buf[i];
		rctx->total_nbytes_processed++;

		if(rctx->countcode_pending && b==0) {
			// Not RLE, just an escaped 0x90 byte.
			dbuf_writebyte(dfctx->dcmpro->f, 0x90);
			rctx->nbytes_written++;
			rctx->last_output_byte = 0x90;
			rctx->countcode_pending = 0;
		}
		else if(rctx->countcode_pending) {
			i64 count;

			// RLE. We already emitted one byte (because the byte to repeat
			// comes before the repeat count), so write countcode-1 bytes.
			count = (i64)(b-1);
			if(dfctx->dcmpro->len_known &&
				(rctx->nbytes_written+count > dfctx->dcmpro->expected_len))
			{
				count = dfctx->dcmpro->expected_len - rctx->nbytes_written;
			}
			dbuf_write_run(dfctx->dcmpro->f, rctx->last_output_byte, count);
			rctx->nbytes_written += count;

			rctx->countcode_pending = 0;
		}
		else if(b==0x90) {
			rctx->countcode_pending = 1;
		}
		else {
			dbuf_writebyte(dfctx->dcmpro->f, b);
			rctx->nbytes_written++;
			rctx->last_output_byte = b;
		}
	}
}

static void my_rle90_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(!rctx) return;
	dfctx->dres->bytes_consumed = rctx->total_nbytes_processed;
	dfctx->dres->bytes_consumed_valid = 1;
}

static void my_rle90_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct rle90ctx *rctx = (struct rle90ctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// RLE algorithm occasionally called "RLE90". Variants of this are used by
// BinHex, ARC, StuffIt, and others.
// codec_private_params: Unused, must be NULL.
void dfilter_rle90_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct rle90ctx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct rle90ctx));
	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = my_rle90_codec_addbuf;
	dfctx->codec_finish_fn = my_rle90_codec_finish;
	dfctx->codec_destroy_fn = my_rle90_codec_destroy;
}

///////////////////////////////////
// STOS picture bank compression

void fmtutil_decompress_stos_pictbank(deark *c, dbuf *inf,
	i64 picdatapos1, i64 rledatapos1, i64 pointspos1,
	dbuf *unc_pixels, i64 unc_image_size)
{
	i64 picdatapos;
	i64 rledatapos;
	u8 picbyte;
	u8 rlebyte;
	u8 rlebit;
	i64 cmpr_pic_bytes, cmpr_rle_bytes, points_bytes;
	struct de_bitbuf_lowlevel *bbll_r = NULL;
	struct de_bitreader *bitrd_p = NULL;
	i64 t;

	de_dbg(c, "decompressing picture");
	de_dbg_indent(c, 1);

	bbll_r = de_malloc(c, sizeof(struct de_bitbuf_lowlevel));
	bitrd_p = de_malloc(c, sizeof(struct de_bitreader));
	bitrd_p->f = inf;
	bitrd_p->curpos = pointspos1;
	bitrd_p->endpos = inf->len;

	picdatapos = picdatapos1;
	rledatapos = rledatapos1;

	// Note that the first picbyte and/or rlebyte can potentially be overwritten
	// before being used. That's just the way it is, apparently.
	picbyte = dbuf_getbyte_p(inf, &picdatapos);
	rlebyte = dbuf_getbyte_p(inf, &rledatapos);

	for(t=0; t<unc_image_size; t++) {
		// We'll need an rle bit.
		// If we've run out of them, read a "points" bit to decide whether
		// to repeat the previous 8 rle bits (stored in rlebyte), or to read
		// a new set of 8 rle bits.
		if(bbll_r->nbits_in_bitbuf==0) {
			u8 pointsbit;

			pointsbit = (u8)de_bitreader_getbits(bitrd_p, 1);
			if(pointsbit) {
				rlebyte = dbuf_getbyte_p(inf, &rledatapos);
			}

			de_bitbuf_lowlevel_add_byte(bbll_r, rlebyte);
		}

		rlebit = (u8)de_bitbuf_lowlevel_get_bits(bbll_r, 1);
		if(rlebit) {
			picbyte = dbuf_getbyte_p(inf, &picdatapos);
		}

		dbuf_writebyte(unc_pixels, picbyte);
	}

	dbuf_flush(unc_pixels);
	cmpr_pic_bytes = picdatapos - picdatapos1;
	cmpr_rle_bytes = rledatapos - rledatapos1;
	de_bitreader_skip_to_byte_boundary(bitrd_p);
	points_bytes = bitrd_p->curpos - pointspos1;
	de_dbg(c, "compressed pic bytes: %"I64_FMT, cmpr_pic_bytes);
	de_dbg(c, "compressed rle bytes: %"I64_FMT, cmpr_rle_bytes);
	de_dbg(c, "points bytes: %"I64_FMT, points_bytes);
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
		cmpr_pic_bytes + cmpr_rle_bytes + points_bytes, unc_pixels->len);

	de_free(c, bbll_r);
	de_free(c, bitrd_p);
	de_dbg_indent(c, -1);
}

///////////////////////////////////
// PCPaint PIC compression

struct pcpaintrle_blk_ctx {
	UI block_idx;
	i64 block_pos;
	i64 end_of_this_block;
	i64 packed_block_size;
	i64 unpacked_block_size;
	i64 nbytes_decompressed_this_block;
	u8 run_marker;
};

// codec_private_params = de_pcpaint_rle_params (can't be NULL).
void fmtutil_pcpaintrle_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct de_pcpaint_rle_params *pcpp = (struct de_pcpaint_rle_params*)codec_private_params;
	i64 inf_pos = dcmpri->pos;
	i64 inf_endpos = dcmpri->pos + dcmpri->len;
	i64 nbytes_decompressed = 0;
	UI nblocks_started = 0;
	struct pcpaintrle_blk_ctx blk;

	de_zeromem(&blk, sizeof(struct pcpaintrle_blk_ctx));

	if(pcpp->one_block_mode) {
		// TODO? One-block mode is handled in a way that's kind of a hack.
		// Maybe it should be redesigned, but maybe not worth it.
		blk.block_idx = 0;
		blk.block_pos = inf_pos;
		blk.end_of_this_block = inf_endpos;
		blk.run_marker = pcpp->obm_run_marker;
	}
	else {
		blk.end_of_this_block = inf_pos;
	}

	while(1) {
		u8 x;
		i64 count;

		if(inf_pos >= inf_endpos) goto done;
		if(dcmpro->len_known && nbytes_decompressed>=dcmpro->expected_len) goto done;

		if(inf_pos>blk.end_of_this_block) {
			de_dfilter_set_generic_error(c, dres, NULL);
			goto done;
		}

		// Things to do at the start of a block
		if(inf_pos==blk.end_of_this_block) {
			// Next block should begin here

			// Validate the previous block
			if(nblocks_started>0 && blk.nbytes_decompressed_this_block!=blk.unpacked_block_size) {
				de_dfilter_set_generic_error(c, dres, NULL);
				goto done;
			}

			if(pcpp->one_block_mode) {
				goto done;
			}
			if(pcpp->num_blocks_known && nblocks_started>=pcpp->num_blocks) {
				goto done;
			}
			de_zeromem(&blk, sizeof(struct pcpaintrle_blk_ctx));
			blk.block_idx = nblocks_started;
			nblocks_started++;
			blk.block_pos = inf_pos;

			de_dbg3(c, "block #%u at %"I64_FMT, blk.block_idx, blk.block_pos);
			if(blk.block_pos+5 > inf_endpos) {
				de_dfilter_set_generic_error(c, dres, NULL);
				goto done;
			}

			blk.nbytes_decompressed_this_block = 0;
			blk.packed_block_size = dbuf_getu16le_p(dcmpri->f, &inf_pos);
			blk.unpacked_block_size = dbuf_getu16le_p(dcmpri->f, &inf_pos);
			blk.run_marker = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			blk.end_of_this_block = blk.block_pos + blk.packed_block_size;
			de_dbg_indent(c, 1);
			de_dbg3(c, "packed size: %"I64_FMT, blk.packed_block_size);
			de_dbg3(c, "unpacked size: %"I64_FMT, blk.unpacked_block_size);
			de_dbg3(c, "run marker: 0x%02x", (UI)blk.run_marker);
			if(blk.packed_block_size<5) {
				de_dfilter_set_generic_error(c, dres, NULL);
				goto done;
			}
			de_dbg_indent(c, -1);
		}

		x = dbuf_getbyte_p(dcmpri->f, &inf_pos);
		if(x==blk.run_marker) { // A compressed run.
			x = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			if(x!=0) {
				// If nonzero, this byte is the run length.
				count = (i64)x;
			}
			else {
				// If zero, it is followed by a 16-bit run length
				count = dbuf_getu16le_p(dcmpri->f, &inf_pos);
			}

			x = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			dbuf_write_run(dcmpro->f, x, count);
			blk.nbytes_decompressed_this_block += count;
			nbytes_decompressed += count;
		}
		else { // A non-compressed part of the image
			dbuf_writebyte(dcmpro->f, x);
			blk.nbytes_decompressed_this_block ++;
			nbytes_decompressed++;
		}

		if(!pcpp->one_block_mode &&
			(blk.nbytes_decompressed_this_block > blk.unpacked_block_size))
		{
			de_dfilter_set_generic_error(c, dres, NULL);
			goto done;
		}
	}

done:
	dbuf_flush(dcmpro->f);
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = inf_pos - dcmpri->pos;
}

///////////////////////////////////
// PCX-style RLE

// codec_private_params: Unused
void fmtutil_pcxrle_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	i64 inf_pos = dcmpri->pos;
	i64 inf_endpos = dcmpri->pos + dcmpri->len;
	i64 nbytes_decompressed = 0;

	while(1) {
		i64 count;
		u8 b0, b1;

		if(inf_pos >= inf_endpos) goto done;
		if(dcmpro->len_known && nbytes_decompressed>=dcmpro->expected_len) goto done;

		b0 = dbuf_getbyte_p(dcmpri->f, &inf_pos);
		if(b0 >= 0xc0) {
			count = (i64)b0 - 0xc0;
			b1 = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			dbuf_write_run(dcmpro->f, b1, count);
			nbytes_decompressed += count;
		}
		else {
			dbuf_writebyte(dcmpro->f, b0);
			nbytes_decompressed++;
		}
	}

done:
	dbuf_flush(dcmpro->f);
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = inf_pos - dcmpri->pos;
}
