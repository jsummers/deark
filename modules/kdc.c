// This file is part of Deark.
// Copyright (C) 2023-2026 Jason Summers
// See the file COPYING for terms of use.

// Knowledge Dynamics Corp. formats

#include <deark-private.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_red);
DE_DECLARE_MODULE(de_module_lif_kdc);

static void noncompressed_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_decompress_uncompressed(md->c, md->dcmpri, md->dcmpro, md->dres, 0);
}

// **************************************************************************
// Knowledge Dynamics .RED (including newer .LIF files)
// **************************************************************************

#define RED_STD_HDR_SIZE 41

struct red_ctx {
	dbuf *tmpinf;
	u8 split_file_found;
};

// The raw compressed data is split into 4094-byte segments (the last
// is usually smaller). A 2-byte CRC-of-compressed data is inserted
// after every segment. Here we delete the CRCs, normally so that we
// can use our standard LHA decompressor.
// (For 'combine' mode, we need to move/recompute some of the CRCs, so
// we start by deleting the old ones.)
// TODO? We could validate the CRCs, but meh.
static void red_desegment_and_copy(deark *c,
	dbuf *inf, i64 inf_pos1, i64 inf_len, dbuf *outf)
{
	i64 n = 0; // num input bytes processed

	while(n < inf_len) {
		i64 blksize;

		blksize = de_min_int(inf_len - n, 4096);
		if(blksize>=2) { // Should always be true
			dbuf_copy(inf, inf_pos1 + n, blksize-2, outf);
		}
		n += blksize;
	}
}

static void red_decompressor_fn(struct de_arch_member_data *md)
{
	struct de_lh5x_params lzhparams;

	if(md->cmpr_meth==11) {
		de_zeromem(&lzhparams, sizeof(struct de_lh5x_params));
		lzhparams.fmt = DE_LH5X_FMT_LH5;
		lzhparams.history_fill_val = 0x20;
		lzhparams.zero_codes_block_behavior = DE_LH5X_ZCB_ERROR;
		fmtutil_lh5x_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, &lzhparams);
	}
	else {
		fmtutil_decompress_uncompressed(md->c, md->dcmpri, md->dcmpro, md->dres, 0);
	}
}

// Caller creates/destroys md, and sets a few fields.
static void red_do_member(deark *c, de_arch_lctx *d, struct red_ctx *rctx,
	struct de_arch_member_data *md)
{
	int saved_indent_level;
	i64 pos = md->member_hdr_pos;
	i64 real_cmpr_pos = 0; // in c->infile
	i64 real_cmpr_len = 0;
	UI id;
	UI seg_num, is_last_seg;
	u32 hdr_crc_reported, hdr_crc_calc;
	u32 crc1_reported;
	u8 b;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, md->member_hdr_pos);
	de_dbg_indent(c, 1);

	id = (UI)de_getu16be_p(&pos);
	b = de_getbyte_p(&pos); // Format version? Always 1.
	md->member_hdr_size = (i64)de_getbyte_p(&pos); // Always 41?
	if(id!=0x5252U || b!=0x01 || md->member_hdr_size<39) {
		de_err(c, "Member not found at %"I64_FMT, md->member_hdr_pos);
		d->fatalerrflag = 1;
		goto done;
	}

	de_arch_read_field_dttm_p(d, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_TD, &pos);
	de_arch_read_field_cmpr_len_p(md, &pos);
	de_arch_read_field_orig_len_p(md, &pos);
	md->member_total_size = md->member_hdr_size + md->cmpr_len;

	crc1_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc1 (reported): 0x%04x", (UI)crc1_reported);
	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc2 (reported): 0x%04x", (UI)md->crc_reported);

	seg_num = (UI)de_getu16le_p(&pos);
	if(seg_num!=0) {
		de_dbg(c, "fragment: %u", seg_num);
	}
	is_last_seg = (UI)de_getu16le_p(&pos);
	de_dbg(c, "last fragment flag: %u", is_last_seg);

	md->cmpr_meth = (UI)de_getu16le_p(&pos);
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);

	pos = md->member_hdr_pos + 26;
	dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += 13;

	md->cmpr_pos = md->member_hdr_pos + md->member_hdr_size;

	// Guessing that the header CRC is always the last field
	hdr_crc_reported = (u32)de_getu16be(md->cmpr_pos-2);
	de_dbg(c, "header crc (reported): 0x%02x", (UI)hdr_crc_reported);
	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, md->member_hdr_pos+2,
		md->member_hdr_size-4);
	hdr_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "header crc (calculated): 0x%02x", (UI)hdr_crc_calc);
	if(hdr_crc_calc != hdr_crc_reported) {
		de_warn(c, "Wrong header CRC: reported=0x%02x, calculated=0x%02x",
			(UI)hdr_crc_reported, (UI)hdr_crc_calc);
	}

	if(seg_num>1 || is_last_seg==0) {
		de_err(c, "Split files are not supported");
		rctx->split_file_found = 1;
		goto done;
	}

	de_dbg(c, "compressed data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);
	if(!de_arch_good_cmpr_data_pos(md)) {
		d->fatalerrflag = 1;
		goto done;
	}

	if(md->cmpr_meth!=1 && md->cmpr_meth!=11) {
		de_err(c, "Unsupported compression: %u", (UI)md->cmpr_meth);
		goto done;
	}

	dbuf_empty(rctx->tmpinf);
	real_cmpr_pos = md->cmpr_pos;
	real_cmpr_len = md->cmpr_len;

	if(md->cmpr_meth==11) {
		red_desegment_and_copy(c, c->infile, md->cmpr_pos, md->cmpr_len, rctx->tmpinf);
		d->inf = rctx->tmpinf;
		md->cmpr_pos = 0;
		md->cmpr_len = rctx->tmpinf->len;
	}

	md->dfn = red_decompressor_fn;
	de_arch_extract_member_file(md);

done:
	d->inf = c->infile;
	md->cmpr_pos = real_cmpr_pos;
	md->cmpr_len = real_cmpr_len;
	de_dbg_indent_restore(c, saved_indent_level);
}

static void run_red_normally(deark *c, de_module_params *mparams)
{
	struct red_ctx *rctx = NULL;
	de_arch_lctx *d = NULL;
	i64 pos = 0;
	struct de_arch_member_data *md = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	rctx = de_malloc(c, sizeof(struct red_ctx));

	d = de_arch_create_lctx(c);
	d->userdata = (void*)rctx;
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_IBM3740);
	rctx->tmpinf = dbuf_create_membuf(c, 0, 0);

	while(1) {
		if(pos >= c->infile->len) goto done;
		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, d);
		md->member_hdr_pos = pos;
		md->validate_crc = 1;

		red_do_member(c, d, rctx, md);
		if(d->stop_flag || d->fatalerrflag || md->member_total_size==0) goto done;

		pos += md->member_total_size;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(md) {
		de_arch_destroy_md(c, md);
		md = NULL;
	}
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported RED file");
		}
		de_arch_destroy_lctx(c, d);
	}
	if(rctx) {
		if(rctx->split_file_found) {
			de_info(c, "Note: Try \"-mp -opt red:combine\" to convert to a "
				"single-volume RED file.");
		}
		dbuf_close(rctx->tmpinf);
		de_free(c, rctx);
	}
}

struct redcmb_ctx {
	u8 errflag;
	u8 need_errmsg;
	int num_volumes;
	i64 prev_member_total_size;
	int cur_vol;
	dbuf *cur_volf; // A copy. Do not close directly.
	dbuf *outf;
	struct de_crcobj *crco; // Various use
	UI frag_count;
	UI frag1_cmpr_meth;
	dbuf *frag1_hdr;
	dbuf *combined_hdr;
	dbuf *combined_cmpr_data;
	u8 frag1_filename[13];
};

// 'f' is modified in-place.
static void red_resegment(deark *c, struct redcmb_ctx *rcctx, dbuf *f)
{
	dbuf *tmpf = NULL;
	i64 srcpos;

	// TODO: Do this without a temporary copy.
	tmpf = dbuf_create_membuf(c, f->len, 0);
	dbuf_copy(f, 0, f->len, tmpf);
	dbuf_empty(f);

	srcpos = 0;
	while(srcpos < tmpf->len) {
		i64 nbytes_to_copy;

		if(tmpf->len - srcpos >= 4094) {
			nbytes_to_copy = 4094;
		}
		else {
			nbytes_to_copy = tmpf->len - srcpos;
		}

		dbuf_copy(tmpf, srcpos, nbytes_to_copy, f);

		de_crcobj_reset(rcctx->crco);
		de_crcobj_addslice(rcctx->crco, tmpf, srcpos, nbytes_to_copy);
		dbuf_writeu16be(f, de_crcobj_getval(rcctx->crco));

		srcpos += nbytes_to_copy;
	}

	dbuf_close(tmpf);
}

static void red_combiner_reset_frag_data(deark *c, struct redcmb_ctx *rcctx)
{
	dbuf_empty(rcctx->frag1_hdr);
	dbuf_empty(rcctx->combined_hdr);
	dbuf_empty(rcctx->combined_cmpr_data);
	rcctx->frag_count = 0;
	rcctx->frag1_cmpr_meth = 0;
	de_zeromem(rcctx->frag1_filename, 13);
}

static void red_combiner_open_outf(deark *c, struct redcmb_ctx *rcctx)
{
	if(rcctx->outf) return;
	rcctx->outf = dbuf_create_output_file(c, "red", NULL, 0);
}

// Sets rcctx->prev_member_total_size
static void red_combiner_do_memberfragment(deark *c, struct redcmb_ctx *rcctx,
	i64 member_pos)
{
	UI id;
	i64 member_hdr_size;
	i64 cmpr_size;
	UI frag_num;
	u8 is_split;
	u8 is_first_frag = 0;
	UI is_last_frag;
	dbuf *inf = rcctx->cur_volf;

	id = (UI)dbuf_getu16be(inf, member_pos);
	member_hdr_size = (i64)dbuf_getbyte(inf, member_pos+3);

	if(id!=0x5252U || member_hdr_size!=RED_STD_HDR_SIZE) {
		rcctx->errflag = 1;
		rcctx->need_errmsg = 1;
		goto done;
	}

	cmpr_size = dbuf_getu32le(inf, member_pos+8);
	if(member_pos+member_hdr_size+cmpr_size > inf->len) {
		rcctx->errflag = 1;
		rcctx->need_errmsg = 1;
		goto done;
	}

	frag_num = (UI)dbuf_getu16le(inf, member_pos+20);
	is_last_frag = (UI)dbuf_getu16le(inf, member_pos+22);
	rcctx->prev_member_total_size = member_hdr_size + cmpr_size;

	is_split = (frag_num>1) || (!is_last_frag);
	if(is_split) {
		if(frag_num<2 && !is_last_frag) {
			is_first_frag = 1;
		}
	}

	// FIXME: This code could be cleaned up.

	if(rcctx->frag_count==0) {
		if(is_split && !is_first_frag) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}
	}
	else { // frag_count>0
		if(!is_split) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}
		if(frag_num != rcctx->frag_count+1) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}
		if(dbuf_memcmp(inf, member_pos+26, rcctx->frag1_filename, 13)) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}
	}

	if(is_split && is_first_frag) {
		red_combiner_reset_frag_data(c, rcctx);
		dbuf_copy(inf, member_pos, member_hdr_size, rcctx->frag1_hdr);
		rcctx->frag1_cmpr_meth = (UI)dbuf_getu16le(rcctx->frag1_hdr, 24);
		dbuf_read(rcctx->frag1_hdr, rcctx->frag1_filename, 26, 13);
	}

	if(is_split) {
		UI frag_cmpr_meth;

		frag_cmpr_meth = (UI)dbuf_getu16le(inf, member_pos+24);
		if(frag_cmpr_meth!=1 && frag_cmpr_meth!=11) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}

		if(!is_first_frag && frag_cmpr_meth!=rcctx->frag1_cmpr_meth) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}
	}

	if(is_split) {
		rcctx->frag_count++;
		if(frag_num != rcctx->frag_count) {
			rcctx->errflag = 1;
			rcctx->need_errmsg = 1;
			goto done;
		}

		de_dbg(c, "[storing fragment %u]", rcctx->frag_count);
		if(rcctx->frag1_cmpr_meth==11) {
			red_desegment_and_copy(c, inf, member_pos+member_hdr_size,
				cmpr_size, rcctx->combined_cmpr_data);
		}
		else {
			dbuf_copy(inf, member_pos+member_hdr_size, cmpr_size,
				rcctx->combined_cmpr_data);
		}

		if(is_last_frag) {
			red_combiner_open_outf(c, rcctx);

			de_dbg(c, "[writing combined member file]");

			if(rcctx->frag1_cmpr_meth==11) {
				red_resegment(c, rcctx, rcctx->combined_cmpr_data);
			}

			// Copy/modify hdr
			dbuf_empty(rcctx->combined_hdr);
			dbuf_copy(rcctx->frag1_hdr, 0, 8, rcctx->combined_hdr);
			dbuf_writeu32le(rcctx->combined_hdr, rcctx->combined_cmpr_data->len);
			dbuf_copy(rcctx->frag1_hdr, 12, 4, rcctx->combined_hdr); // orig size

			// CRC fields
			if(rcctx->frag1_cmpr_meth==1) {
				u32 newcrc;

				// For method 1, unfortunately, we have to recompute the whole-
				// file CRC, making it useless for error detection.
				// TODO: We could validate the CRC of each fragment, though
				// that's of limited value.
				de_crcobj_reset(rcctx->crco);
				de_crcobj_addslice(rcctx->crco, rcctx->combined_cmpr_data, 0,
					rcctx->combined_cmpr_data->len);
				newcrc = de_crcobj_getval(rcctx->crco);
				dbuf_writeu16le(rcctx->combined_hdr, (i64)newcrc);
				dbuf_writeu16le(rcctx->combined_hdr, (i64)newcrc);
			}
			else {
				dbuf_copy(rcctx->frag1_hdr, 16, 4, rcctx->combined_hdr);
			}

			dbuf_writeu16le(rcctx->combined_hdr, 0); // frag. num
			dbuf_writeu16le(rcctx->combined_hdr, 1); // is-last-frag
			dbuf_copy(rcctx->frag1_hdr, 24, RED_STD_HDR_SIZE-26, rcctx->combined_hdr);

			// header checksum
			de_crcobj_reset(rcctx->crco);
			de_crcobj_addslice(rcctx->crco, rcctx->combined_hdr, 2, RED_STD_HDR_SIZE-4);
			dbuf_writeu16be(rcctx->combined_hdr, de_crcobj_getval(rcctx->crco));

			dbuf_copy(rcctx->combined_hdr, 0, RED_STD_HDR_SIZE, rcctx->outf);

			dbuf_copy(rcctx->combined_cmpr_data, 0,
				rcctx->combined_cmpr_data->len, rcctx->outf);

			red_combiner_reset_frag_data(c, rcctx);
		}
	}

	if(!is_split) {
		red_combiner_open_outf(c, rcctx);
		// Copy header
		dbuf_copy(inf, member_pos, member_hdr_size, rcctx->outf);
		// Copy cmpr data
		dbuf_copy(inf, member_pos+member_hdr_size, cmpr_size, rcctx->outf);
	}

done:
	;
}

static void red_combine_1vol(deark *c, struct redcmb_ctx *rcctx)
{
	i64 member_pos = 0;

	while(1) {
		if(member_pos >= rcctx->cur_volf->len) goto done;

		de_dbg(c, "member at %"I64_FMT, member_pos);

		rcctx->prev_member_total_size = 0;

		red_combiner_do_memberfragment(c, rcctx, member_pos);
		if(rcctx->prev_member_total_size==0) {
			rcctx->errflag = 1;
		}
		if(rcctx->errflag) goto done;

		member_pos += rcctx->prev_member_total_size;
	}

done:
	;
}

static void run_red_combiner(deark *c, de_module_params *mparams)
{
	struct redcmb_ctx *rcctx = NULL;

	rcctx = de_malloc(c, sizeof(struct redcmb_ctx));
	rcctx->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_IBM3740);
	rcctx->num_volumes = 1;
	if(c->mp_data) {
		rcctx->num_volumes += c->mp_data->count;
	}
	de_dbg(c, "num volumes: %d", rcctx->num_volumes);

	rcctx->frag1_hdr = dbuf_create_membuf(c, 0, 0);
	rcctx->combined_hdr = dbuf_create_membuf(c, 0, 0);
	rcctx->combined_cmpr_data = dbuf_create_membuf(c, 0, 0);
	red_combiner_reset_frag_data(c, rcctx);

	for(rcctx->cur_vol=0; rcctx->cur_vol<rcctx->num_volumes; rcctx->cur_vol++) {
		de_dbg(c, "[volume %d]", (rcctx->cur_vol+1));
		rcctx->cur_volf = de_mp_acquire_dbuf(c, rcctx->cur_vol);
		if(!rcctx->cur_volf) {
			rcctx->errflag = 1;
			goto done;
		}
		de_dbg_indent(c, 1);
		red_combine_1vol(c, rcctx);
		de_dbg_indent(c, -1);
		de_mp_release_dbuf(c, rcctx->cur_vol, &rcctx->cur_volf);
		if(rcctx->errflag) goto done;
	}

done:
	if(rcctx) {
		if(!rcctx->errflag) {
			// If there's an unfinished fragment, error.
			if(rcctx->frag_count>0) {
				rcctx->need_errmsg = 1;
			}
		}
		dbuf_close(rcctx->outf);
		dbuf_close(rcctx->frag1_hdr);
		dbuf_close(rcctx->combined_hdr);
		dbuf_close(rcctx->combined_cmpr_data);
		de_crcobj_destroy(rcctx->crco);
		if(rcctx->need_errmsg) {
			de_err(c, "Failed to process multi-volume RED archive");
		}
		de_free(c, rcctx);
	}
}

static void de_run_red(deark *c, de_module_params *mparams)
{
	u8 combine_mode = 0;

	combine_mode = (u8)de_get_ext_option_bool(c, "red:combine", 0);

	if(combine_mode) {
		run_red_combiner(c, mparams);
	}
	else {
		if(c->mp_data && c->mp_data->count>0) {
			de_err(c, "Multi-volume archives are only supported "
				"with \"-opt red:combine\"");
			goto done;
		}
		run_red_normally(c, mparams);
	}

done:
	;
}

static int de_identify_red(deark *c)
{
	if((UI)de_getu32be(0) != 0x52520129U) return 0;
	return 100;
}

static void de_help_red(deark *c)
{
	de_msg(c, "-mp -opt red:combine : Instead of decoding, "
		"combine a multi-volume archive into one file");
}

void de_module_red(deark *c, struct deark_module_info *mi)
{
	mi->id = "red";
	mi->desc = "RED installer archive (Knowledge Dynamics Corp)";
	mi->run_fn = de_run_red;
	mi->identify_fn = de_identify_red;
	mi->help_fn = de_help_red;
	mi->flags |= DE_MODFLAG_MULTIPART;
}

// **************************************************************************
// Knowledge Dynamics .LIF (old format)
// **************************************************************************

// It's ugly to have two different ways of reading these ASCII-encoded-hex-
// digits fields. But the needs of the 'identify' phase, and the 'run' phase,
// are different enough that it's how I've chosen to do it.

static i64 lif_read_field(dbuf *f, i64 pos1, i64 len, int *perrflag)
{
	i64 val = 0;
	i64 i;
	i64 pos = pos1;

	for(i=0; i<len; i++) {
		u8 b;
		i64 nv;

		b = dbuf_getbyte_p(f, &pos);
		if(b>='0' && b<='9') {
			nv = b - 48;
		}
		else if(b>='a' && b<='f') {
			nv = b - 87;
		}
		else {
			*perrflag = 1;
			return 0;
		}

		val = (val<<4) | nv;
	}
	return val;
}

static int lif_kdc_convert_hdr(deark *c, i64 pos1, dbuf *f2)
{
	i64 pos = pos1;
	int i;
	int errorflag = 0;

	for(i=0; i<17; i++) {
		u8 b0, b1;
		u8 x0, x1;

		b0 = de_getbyte_p(&pos);
		b1 = de_getbyte_p(&pos);
		x0 = de_decode_hex_digit(b0, &errorflag);
		if(errorflag) return 0;
		x1 = de_decode_hex_digit(b1, &errorflag);
		if(errorflag) return 0;
		dbuf_writebyte(f2, (u8)((x0<<4)|x1));
	}
	return 1;
}

static void lif_method2_decompressor_fn(struct de_arch_member_data *md)
{
	deark *c = md->c;
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ZOOLZD;
	fmtutil_decompress_lzw(c, md->dcmpri, md->dcmpro, md->dres, &delzwp);
}

static void de_run_lif_kdc(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	i64 pos = 0;
	struct de_arch_member_data *md = NULL;
	dbuf *f2 = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_arch_create_lctx(c);
	d->is_le = 0;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_IBM3740);
	f2 = dbuf_create_membuf(c, 17, 0);

	while(1) {
		i64 f2_pos;
		u32 crc1_reported;

		if(pos >= c->infile->len) goto done;
		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}

		dbuf_empty(f2);
		// Decode the hex-encoded part of the header, so that we can read it
		// more easily.
		if(!lif_kdc_convert_hdr(c, pos, f2)) {
			d->need_errmsg = 1;
			goto done;
		}

		md = de_arch_create_md(c, d);
		md->member_hdr_pos = pos;
		md->member_hdr_size = 54;

		de_dbg(c, "member at %"I64_FMT, md->member_hdr_pos);
		de_dbg_indent(c, 1);

		d->inf = f2;
		f2_pos = 0;

		de_arch_read_field_dttm_p(d, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
			DE_ARCH_TSTYPE_DOS_DT, &f2_pos);
		de_arch_read_field_cmpr_len_p(md, &f2_pos);
		de_arch_read_field_orig_len_p(md, &f2_pos);

		crc1_reported = (u32)dbuf_getu16be_p(f2, &f2_pos);
		de_dbg(c, "crc of cmpr. data (reported): 0x%04x", (UI)crc1_reported);
		md->crc_reported = (u32)dbuf_getu16be_p(f2, &f2_pos);
		de_dbg(c, "crc of orig. data (reported): 0x%04x", (UI)md->crc_reported);

		md->cmpr_meth = (UI)dbuf_getbyte_p(f2, &f2_pos);
		de_dbg(c, "cmpr. method: %u", md->cmpr_meth);
		d->inf = c->infile;

		pos = md->member_hdr_pos + 34;
		// TODO: How long is the filename field?
		dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));

		md->cmpr_pos = md->member_hdr_pos + md->member_hdr_size;
		de_dbg(c, "compressed data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);

		md->validate_crc = 1;
		if(md->cmpr_meth==1) {
			md->dfn = noncompressed_decompressor_fn;
			de_arch_extract_member_file(md);
		}
		else if(md->cmpr_meth==2) {
			md->dfn = lif_method2_decompressor_fn;
			de_arch_extract_member_file(md);
		}
		else {
			de_err(c, "Unsupported compression: %u", (UI)md->cmpr_meth);
		}

		de_dbg_indent(c, -1);
		pos = md->cmpr_pos + md->cmpr_len;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(md) {
		de_arch_destroy_md(c, md);
		md = NULL;
	}
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported LIF file");
		}
		de_arch_destroy_lctx(c, d);
	}
	dbuf_close(f2);
}

static int de_identify_lif_kdc(deark *c)
{
	i64 cmprmeth;
	int errflag = 0;
	int has_ext;
	u8 b;
	i64 i;
	i64 n[4];

	cmprmeth = lif_read_field(c->infile, 32, 2, &errflag);
	if(errflag) return 0;
	if(cmprmeth<1 || cmprmeth>3) return 0;

	b = de_getbyte(34); // 1st char of filename
	if(b<32) return 0;
	b = de_getbyte(53); // last char of NUL-padded filename field??
	if(b!=0) return 0;

	for(i=0; i<4; i++) {
		n[i] = lif_read_field(c->infile, 8*i, 8, &errflag);
		if(errflag) return 0;
	}
	if(54+n[1] > c->infile->len) return 0; // File too short

	has_ext = de_input_file_has_ext(c, "lif");
	return has_ext ? 45 : 15;
}

void de_module_lif_kdc(deark *c, struct deark_module_info *mi)
{
	mi->id = "lif_kdc";
	mi->desc = "LIF installer archive (Knowledge Dynamics Corp)";
	mi->run_fn = de_run_lif_kdc;
	mi->identify_fn = de_identify_lif_kdc;
}
