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

struct red_ctx {
	dbuf *tmpinf;
};

// The raw compressed data is split into 4094-byte segments (the last
// is usually smaller). A 2-byte CRC-of-compressed data is inserted
// after every segment. Here we delete the CRCs, so that we can use our
// standard LHA decompressor.
// TODO? We could validate the CRCs, but meh.
static void red_desegment(deark *c, de_arch_lctx *d, struct red_ctx *rctx,
	struct de_arch_member_data *md)
{
	i64 in_nbytes_processed = 0;

	while(in_nbytes_processed < md->cmpr_len) {
		i64 nbytes_left_to_process;

		nbytes_left_to_process = md->cmpr_len - in_nbytes_processed;
		if(nbytes_left_to_process >= 4096) {
			dbuf_copy(c->infile, md->cmpr_pos + in_nbytes_processed,
				4094, rctx->tmpinf);
			in_nbytes_processed += 4096;
		}
		else {
			// TODO?: We should also delete the last two bytes of the
			// compressed data, but they do no harm.
			dbuf_copy(c->infile, md->cmpr_pos + in_nbytes_processed,
				nbytes_left_to_process, rctx->tmpinf);
			in_nbytes_processed += nbytes_left_to_process;
		}
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

	pos += 2; // (probably crc of cmpr data, or 0xffff if unused)
	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)md->crc_reported);

	//pos += 4 ; // ?
	seg_num = (UI)de_getu16le_p(&pos);
	if(seg_num!=0) {
		de_dbg(c, "segment: %u", seg_num);
	}
	is_last_seg = (UI)de_getu16le_p(&pos);
	de_dbg(c, "last segment flag: %u", is_last_seg);

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
		de_err(c, "Wrong header CRC: reported=0x%02x, calculated=0x%02x",
			(UI)hdr_crc_reported, (UI)hdr_crc_calc);
	}

	if(seg_num>1 || is_last_seg==0) {
		de_err(c, "Split files are not supported");
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
		red_desegment(c, d, rctx, md);
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

static void de_run_red(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	i64 pos = 0;
	struct red_ctx *rctx = NULL;
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
		dbuf_close(rctx->tmpinf);
	}
}

static int de_identify_red(deark *c)
{
	if((UI)de_getu32be(0) != 0x52520129U) return 0;
	return 100;
}

void de_module_red(deark *c, struct deark_module_info *mi)
{
	mi->id = "red";
	mi->desc = "RED installer archive (Knowledge Dynamics Corp)";
	mi->run_fn = de_run_red;
	mi->identify_fn = de_identify_red;
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
