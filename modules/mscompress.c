// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// MS-DOS installation compression (compress.exe, expand.exe, MSLZ, etc.)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mscompress);

#define FMT_SZDD 1
#define FMT_KWAJ 2

#define CMPR_NONE    0
#define CMPR_XOR     1
#define CMPR_SZDD    2
#define CMPR_LZHUFF  3
#define CMPR_MSZIP   4

typedef struct localctx_struct {
	int fmt;
	int input_encoding;
	UI cmpr_meth;
	i64 cmpr_data_pos;
	i64 cmpr_data_len;
	u8 uncmpr_len_known;
	i64 uncmpr_len;
	de_ucstring *filename;
} lctx;

static int cmpr_meth_is_supported(lctx *d, UI n)
{
	switch(n) {
	case CMPR_NONE:
	case CMPR_XOR:
	case CMPR_SZDD:
	case CMPR_LZHUFF:
	case CMPR_MSZIP:
		return 1;
	}
	return 0;
}

static const char *get_cmpr_meth_name(UI n)
{
	char *name = NULL;

	switch(n) {
	case CMPR_NONE: name="uncompressed"; break;
	case CMPR_XOR: name="XOR"; break;
	case CMPR_SZDD: name="SZDD"; break;
	case CMPR_LZHUFF: name="LZ+Huffman"; break;
	case CMPR_MSZIP: name="MSZIP"; break;
	}
	return name?name:"?";
}

static int do_header_SZDD(deark *c, lctx *d, i64 pos1)
{
	u8 cmpr_mode;
	u8 fnchar;
	i64 pos = pos1;
	char tmps[80];
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->cmpr_data_pos = 14;
	d->cmpr_data_len = c->infile->len - d->cmpr_data_pos;

	pos += 8; // signature

	cmpr_mode = de_getbyte(pos++);
	de_dbg(c, "compression mode: 0x%02x ('%c')", (unsigned int)cmpr_mode,
		de_byte_to_printable_char(cmpr_mode));
	if(cmpr_mode != 0x41) {
		de_err(c, "Unsupported compression mode");
		goto done;
	}
	d->cmpr_meth = CMPR_SZDD;

	fnchar = de_getbyte(pos++);
	if(fnchar>=32 && fnchar<=126) {
		de_snprintf(tmps, sizeof(tmps), " ('%c')", fnchar);
	}
	else if(fnchar==0) {
		de_snprintf(tmps, sizeof(tmps), " (unknown)");
	}
	else {
		de_strlcpy(tmps, "", sizeof(tmps));
	}
	de_dbg(c, "missing filename char: 0x%02x%s", (unsigned int)fnchar, tmps);

	d->uncmpr_len = de_getu32le(pos);
	d->uncmpr_len_known = 1;
	de_dbg(c, "uncompressed len: %"I64_FMT"", d->uncmpr_len);
	pos += 4;

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_header_KWAJ(deark *c, lctx *d, i64 pos1)
{
	unsigned int flags;
	i64 pos = pos1;
	i64 n;
	i64 foundpos;
	int retval = 0;
	int ret;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 8; // signature

	d->cmpr_meth = (UI)de_getu16le_p(&pos);
	de_dbg(c, "compression method: %u (%s)", d->cmpr_meth, get_cmpr_meth_name(d->cmpr_meth));

	d->cmpr_data_pos = de_getu16le_p(&pos);
	de_dbg(c, "compressed data offset: %"I64_FMT, d->cmpr_data_pos);
	d->cmpr_data_len = c->infile->len - d->cmpr_data_pos;

	flags = (UI)de_getu16le_p(&pos);
	de_dbg(c, "header extension flags: 0x%04x", flags);

	if(flags & 0x0001) { // bit 0
		d->uncmpr_len = de_getu32le_p(&pos);
		d->uncmpr_len_known = 1;
		de_dbg(c, "uncompressed len: %"I64_FMT"", d->uncmpr_len);
	}
	if(flags & 0x0002) { // bit 1
		pos += 2;
	}
	if(flags & 0x0004) { // bit 2
		n = de_getu16le_p(&pos);
		pos += n;
	}
	if(flags & 0x0008) { // bit 3, base part of filename
		foundpos = 0;
		ret = dbuf_search_byte(c->infile, 0x00, pos, 9, &foundpos);
		if(!ret) goto header_extensions_done;
		d->filename = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, foundpos-pos, d->filename, 0, d->input_encoding);
		pos = foundpos+1;
	}
	if(flags & 0x0010) { // bit 4, filename extension
		foundpos = 0;
		ret = dbuf_search_byte(c->infile, 0x00, pos, 4, &foundpos);
		if(!ret) goto header_extensions_done;
		if(d->filename && (foundpos-pos > 0)) {
			ucstring_append_char(d->filename, '.');
			dbuf_read_to_ucstring(c->infile, pos, foundpos-pos, d->filename, 0, d->input_encoding);
		}
		pos = foundpos+1;
	}
	if(flags & 0x0020) { // bit 5
		// TODO (comment?)
	}

header_extensions_done:
	if(ucstring_isnonempty(d->filename)) {
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(d->filename));
	}

	// If no compression, don't copy/convert more bytes than given by the uncmpr_len field.
	if(d->uncmpr_len_known && (d->cmpr_meth==CMPR_NONE || d->cmpr_meth==CMPR_XOR) &&
		d->uncmpr_len < d->cmpr_data_len)
	{
		d->cmpr_data_len = d->uncmpr_len;
	}

	retval = 1;

	de_dbg_indent(c, -1);
	return retval;
}

// The max code length is *probably* 15, but some length compression methods
// can be (mis?)used to make larger lengths possible.
#define MSLZH_MAX_CODELENGTH  20

#define MSLZH_SYMLEN_TYPE  u8  // Assumed to be unsigned

#define MSLZH_VALUE_TYPE   u8  // Type of a decoded symbol

struct mslzh_tree {
	UI enctype;
	UI num_symbols;
	MSLZH_SYMLEN_TYPE *symlengths; // array[num_symbols]
	struct fmtutil_huffman_tree *fmtuht;
};

struct mslzh_context {
	deark *c;
	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;
	dbuf *inf;
	struct de_dfilter_out_params *dcmpro;
	i64 nbytes_written;
	int error_flag; // Bad data in the LZ77 part should not set this flag. Set eof_flag instead.

	// bitrd.eof_flag: Always set if error_flag is set.
	struct de_bitreader bitrd;

	struct de_dfilter_results *dres;
	const char *modname;
	struct de_lz77buffer *ringbuf;
#define MSLZH_TREE_IDX_MATCHLEN   0
#define MSLZH_TREE_IDX_MATCHLEN2  1
#define MSLZH_TREE_IDX_LITLEN     2
#define MSLZH_TREE_IDX_OFFSET     3
#define MSLZH_TREE_IDX_LITERAL    4
#define MSLZH_NUM_TREES   5
	struct mslzh_tree htree[MSLZH_NUM_TREES];
};

static void mslzh_set_errorflag(struct mslzh_context *lzhctx)
{
	lzhctx->error_flag = 1;
	lzhctx->bitrd.eof_flag = 1;
}

static UI mslzh_getbits(struct mslzh_context *lzhctx, UI nbits)
{
	return (UI)de_bitreader_getbits(&lzhctx->bitrd, nbits);
}

static void mslzh_read_huffman_tree_enctype_0(struct mslzh_context *lzhctx, struct mslzh_tree *htr)
{
	MSLZH_SYMLEN_TYPE n;
	UI sym_idx;

	n = (MSLZH_SYMLEN_TYPE)de_log2_rounded_up((i64)htr->num_symbols);
	for(sym_idx=0; sym_idx<htr->num_symbols; sym_idx++) {
		htr->symlengths[sym_idx] = n;
	}
}

static void mslzh_read_huffman_tree_enctype_1(struct mslzh_context *lzhctx, struct mslzh_tree *htr)
{
	MSLZH_SYMLEN_TYPE prev_sym_len;
	UI sym_idx;
	UI n;

	htr->symlengths[0] = (MSLZH_SYMLEN_TYPE)mslzh_getbits(lzhctx, 4);
	prev_sym_len = htr->symlengths[0];

	for(sym_idx=1; sym_idx<htr->num_symbols; sym_idx++) {
		if(lzhctx->bitrd.eof_flag) goto done;

		n = mslzh_getbits(lzhctx, 1);
		if(n==0) { // 0
			htr->symlengths[sym_idx] = prev_sym_len;
		}
		else { // 1...
			n = mslzh_getbits(lzhctx, 1);
			if(n==0) { // 10
				htr->symlengths[sym_idx] = prev_sym_len + 1;
			}
			else { // 11...
				htr->symlengths[sym_idx] = (MSLZH_SYMLEN_TYPE)mslzh_getbits(lzhctx, 4);
			}
		}

		prev_sym_len = htr->symlengths[sym_idx];
	}
done:
	;
}

static void mslzh_read_huffman_tree_enctype_2(struct mslzh_context *lzhctx, struct mslzh_tree *htr)
{
	MSLZH_SYMLEN_TYPE prev_sym_len;
	UI sym_idx;
	UI n;

	htr->symlengths[0] = (MSLZH_SYMLEN_TYPE)mslzh_getbits(lzhctx, 4);
	prev_sym_len = htr->symlengths[0];

	for(sym_idx=1; sym_idx<htr->num_symbols; sym_idx++) {
		if(lzhctx->bitrd.eof_flag) goto done;

		n = mslzh_getbits(lzhctx, 2);
		if(n==3) {
			htr->symlengths[sym_idx] = (MSLZH_SYMLEN_TYPE)mslzh_getbits(lzhctx, 4);
		}
		else {
			htr->symlengths[sym_idx] = prev_sym_len + (MSLZH_SYMLEN_TYPE)n - 1;
		}

		prev_sym_len = htr->symlengths[sym_idx];
	}
done:
	;
}

static void mslzh_read_huffman_tree_enctype_3(struct mslzh_context *lzhctx, struct mslzh_tree *htr)
{
	UI sym_idx;

	for(sym_idx=0; sym_idx<htr->num_symbols; sym_idx++) {
		if(lzhctx->bitrd.eof_flag) goto done;
		htr->symlengths[sym_idx] = (MSLZH_SYMLEN_TYPE)mslzh_getbits(lzhctx, 4);
	}
done:
	;
}

// On error, sets lzhctx->eof_flag
static MSLZH_VALUE_TYPE mslzh_getnextcode(struct mslzh_context *lzhctx,
	struct mslzh_tree *htr)
{
	i32 val = 0;
	int ret;

	fmtutil_huffman_reset_cursor(htr->fmtuht); // Should be unnecessary

	ret = fmtutil_huffman_read_next_value(htr->fmtuht, &lzhctx->bitrd, &val, NULL);
	if(!ret) return 0;
	return (MSLZH_VALUE_TYPE)val;
}

static void mslzh_read_huffman_tree(struct mslzh_context *lzhctx, UI idx)
{
	UI i;
	int saved_indent_level;
	deark *c = lzhctx->c;
	struct mslzh_tree *htr = &lzhctx->htree[idx];
	char tmps[32];

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(lzhctx->c, "huffman tree #%u at %s, nsyms=%u, enctype=%u",
		idx, de_bitreader_describe_curpos(&lzhctx->bitrd, tmps, sizeof(tmps)),
		htr->num_symbols, htr->enctype);
	de_dbg_indent(c, 1);

	htr->symlengths = de_mallocarray(c, htr->num_symbols, sizeof(htr->symlengths[0]));

	switch(htr->enctype) {
	case 0:
		mslzh_read_huffman_tree_enctype_0(lzhctx, htr);
		break;
	case 1:
		mslzh_read_huffman_tree_enctype_1(lzhctx, htr);
		break;
	case 2:
		mslzh_read_huffman_tree_enctype_2(lzhctx, htr);
		break;
	case 3:
		mslzh_read_huffman_tree_enctype_3(lzhctx, htr);
		break;
	default:
		mslzh_set_errorflag(lzhctx);
	}

	if(lzhctx->bitrd.eof_flag) {
		mslzh_set_errorflag(lzhctx);
		goto done;
	}

	for(i=0; i<htr->num_symbols; i++) {
		de_dbg2(c, "length[%u] = %u", i, (UI)htr->symlengths[i]);
		fmtutil_huffman_record_a_code_length(c, htr->fmtuht, (i32)i, (UI)htr->symlengths[i]);
	}

	if(!fmtutil_huffman_make_canonical_tree(c, htr->fmtuht)) {
		de_dfilter_set_errorf(c, lzhctx->dres, lzhctx->modname, "Failed to construct Huffman tree");
		mslzh_set_errorflag(lzhctx);
		goto done;
	}

	if(c->debug_level>=2) {
		de_dbg(c, "constructed huffman tree:");
		de_dbg_indent(c, 1);
		fmtutil_huffman_dump(c, htr->fmtuht);
		de_dbg_indent(c, -1);
	}

done:
	de_free(c, htr->symlengths);
	htr->symlengths = NULL;
	de_dbg_indent_restore(c, saved_indent_level);
}

static int mslzh_have_enough_output(struct mslzh_context *lzhctx)
{
	if(lzhctx->dcmpro->len_known &&
		(lzhctx->nbytes_written>=lzhctx->dcmpro->expected_len))
	{
		return 1;
	}
	return 0;
}

static void mslzh_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct mslzh_context *lzhctx = (struct mslzh_context*)rb->userdata;

	if(mslzh_have_enough_output(lzhctx)) return;
	dbuf_writebyte(lzhctx->dcmpro->f, n);
	lzhctx->nbytes_written++;
}

static void mslzh_decompress_main(struct mslzh_context *lzhctx)
{
	MSLZH_VALUE_TYPE v;
	struct mslzh_tree *curr_matchlen_table;
	char tmps[32];

	de_dbg(lzhctx->c, "LZ data at %s",
		de_bitreader_describe_curpos(&lzhctx->bitrd, tmps, sizeof(tmps)));

	curr_matchlen_table = &lzhctx->htree[MSLZH_TREE_IDX_MATCHLEN];

	while(1) {
		if(mslzh_have_enough_output(lzhctx)) goto unc_done;
		if(lzhctx->bitrd.eof_flag) goto unc_done;

		v = mslzh_getnextcode(lzhctx, curr_matchlen_table);
		if(lzhctx->bitrd.eof_flag) goto unc_done;

		if(v!=0) { // match
			UI matchlen;
			UI matchpos;
			UI x, y;

			matchlen = v + 2;

			x = mslzh_getnextcode(lzhctx, &lzhctx->htree[MSLZH_TREE_IDX_OFFSET]);
			y = mslzh_getbits(lzhctx, 6);
			if(lzhctx->bitrd.eof_flag) goto unc_done;

			// This may underflow -- that's ok.
			matchpos = lzhctx->ringbuf->curpos - (x<<6 | y);

			curr_matchlen_table = &lzhctx->htree[MSLZH_TREE_IDX_MATCHLEN];

			de_lz77buffer_copy_from_hist(lzhctx->ringbuf, matchpos, matchlen);
		}
		else { // run of literals
			UI x;
			UI count;
			UI i;

			x = mslzh_getnextcode(lzhctx, &lzhctx->htree[MSLZH_TREE_IDX_LITLEN]);
			if(lzhctx->bitrd.eof_flag) goto unc_done;
			if(x != 31) {
				curr_matchlen_table = &lzhctx->htree[MSLZH_TREE_IDX_MATCHLEN2];
			}
			// read & emit x+1 literals using LITERAL table
			count = x+1;
			for(i=0; i<count; i++) {
				v = mslzh_getnextcode(lzhctx, &lzhctx->htree[MSLZH_TREE_IDX_LITERAL]);
				if(lzhctx->bitrd.eof_flag) goto unc_done;
				de_lz77buffer_add_literal_byte(lzhctx->ringbuf, (u8)v);
			}
		}
	}

unc_done:
	;
}

static void do_decompress_LZHUFF(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct mslzh_context *lzhctx = NULL;
	i64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	lzhctx = de_malloc(c, sizeof(struct mslzh_context));
	lzhctx->c = c;
	lzhctx->modname = "lzhuff";
	lzhctx->inf = dcmpri->f;
	lzhctx->dcmpro = dcmpro;
	lzhctx->dres = dres;

	lzhctx->bitrd.f = dcmpri->f;
	lzhctx->bitrd.curpos = dcmpri->pos;
	lzhctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	lzhctx->htree[MSLZH_TREE_IDX_MATCHLEN].num_symbols = 16;
	lzhctx->htree[MSLZH_TREE_IDX_MATCHLEN2].num_symbols = 16;
	lzhctx->htree[MSLZH_TREE_IDX_LITLEN].num_symbols = 32;
	lzhctx->htree[MSLZH_TREE_IDX_OFFSET].num_symbols = 64;
	lzhctx->htree[MSLZH_TREE_IDX_LITERAL].num_symbols = 256;

	for(k=0; k<MSLZH_NUM_TREES; k++) {
		lzhctx->htree[k].fmtuht = fmtutil_huffman_create_tree(c,
				lzhctx->htree[k].num_symbols, lzhctx->htree[k].num_symbols);
	}

	// 3-byte header
	de_dbg(c, "LZH header at %"I64_FMT, lzhctx->bitrd.curpos);
	de_dbg_indent(c, 1);
	for(k=0; k<MSLZH_NUM_TREES; k++) {
		lzhctx->htree[k].enctype = mslzh_getbits(lzhctx, 4);
		de_dbg2(c, "huffman tree enctype[%d] = %u", (int)k, lzhctx->htree[k].enctype);
	}
	(void)mslzh_getbits(lzhctx, 4); // unused
	if(lzhctx->bitrd.eof_flag) {
		mslzh_set_errorflag(lzhctx);
		goto done;
	}
	de_dbg_indent(c, -1);

	for(k=0; k<MSLZH_NUM_TREES; k++) {
		mslzh_read_huffman_tree(lzhctx, (UI)k);
		if(lzhctx->bitrd.eof_flag) {
			mslzh_set_errorflag(lzhctx);
			goto done;
		}
	}

	lzhctx->ringbuf = de_lz77buffer_create(c, 4096);
	lzhctx->ringbuf->writebyte_cb = mslzh_lz77buf_writebytecb;
	lzhctx->ringbuf->userdata = (void*)lzhctx;
	de_lz77buffer_clear(lzhctx->ringbuf, 0x20);

	mslzh_decompress_main(lzhctx);

done:
	if(lzhctx) {
		size_t tr;

		if(lzhctx->error_flag) {
			de_dfilter_set_generic_error(c, dres, lzhctx->modname);
		}

		de_lz77buffer_destroy(c, lzhctx->ringbuf);

		for(tr=0; tr<MSLZH_NUM_TREES; tr++) {
			fmtutil_huffman_destroy_tree(c, lzhctx->htree[tr].fmtuht);
		}
		de_free(c, lzhctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int XOR_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 k;
	dbuf *f = (dbuf*)brctx->userdata;

	for(k=0; k<buf_len; k++) {
		dbuf_writebyte(f, ~buf[k]);
	}
	return 1;
}

static void do_decompress_XOR(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	dbuf_buffered_read(dcmpri->f, dcmpri->pos, dcmpri->len, XOR_cbfn, (void*)dcmpro->f);
}

static void do_decompress_MSZIP(deark *c, struct de_dfilter_in_params *dcmpri1,
	struct de_dfilter_out_params *dcmpro1, struct de_dfilter_results *dres)
{
	const char *modname = "mszip";
	i64 pos = dcmpri1->pos;
	int saved_indent_level;
	dbuf *tmpdbuf = NULL;
	struct de_dfilter_in_params dcmpri2;
	struct de_dfilter_out_params dcmpro2;
	u8 *prev_dict = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dfilter_init_objects(c, &dcmpri2, &dcmpro2, NULL);
	tmpdbuf = dbuf_create_membuf(c, 32768, 0);

	dcmpri2.f = dcmpri1->f;
	dcmpro2.f = tmpdbuf;
	dcmpro2.len_known = 1;
	dcmpro2.expected_len = 32768;

	while(1) {
		i64 blkpos;
		i64 blklen_raw;
		i64 blk_dlen;
		UI sig;
		struct de_inflate_params inflparams;

		if(pos > dcmpri1->pos + dcmpri1->len -4) {
			goto done;
		}
		blkpos = pos;
		de_dbg(c, "MSZIP block at %"I64_FMT, blkpos);
		de_dbg_indent(c, 1);
		blklen_raw = dbuf_getu16le_p(dcmpri1->f, &pos);
		blk_dlen = blklen_raw - 2;
		sig = (UI)dbuf_getu16be_p(dcmpri1->f, &pos);
		if(sig != 0x434b) { // "CK"
			de_dfilter_set_errorf(c, dres, modname, "Failed to find MSZIP block "
				"at %"I64_FMT, blkpos);
			goto done;
		}
		de_dbg(c, "block dpos: %"I64_FMT", dlen: %d", pos, (int)blk_dlen);
		if(blk_dlen < 0) goto done;
		dcmpri2.pos = pos;
		dcmpri2.len = blk_dlen;
		de_zeromem(&inflparams, sizeof(struct de_inflate_params));
		inflparams.flags = 0;
		inflparams.starting_dict = prev_dict;
		fmtutil_inflate_codectype1(c, &dcmpri2, &dcmpro2, dres, (void*)&inflparams);
		if(dres->errcode) goto done;
		dbuf_copy(tmpdbuf, 0, tmpdbuf->len, dcmpro1->f);
		pos += blk_dlen;
		if(tmpdbuf->len < 32768) break; // Presumably we're done.

		// Save the history buffer, for the next chunk.
		if(!prev_dict) {
			prev_dict = de_malloc(c, 32768);
		}
		dbuf_read(tmpdbuf, prev_dict, 0, 32768);

		dbuf_truncate(tmpdbuf, 0);
		de_dbg_indent(c, -1);
	}

done:
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = pos - dcmpri1->pos;
	dbuf_close(tmpdbuf);
	de_free(c, prev_dict);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_decompress(deark *c, lctx *d, dbuf *outf)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = d->cmpr_data_pos;
	dcmpri.len = d->cmpr_data_len;

	dcmpro.f = outf;
	dcmpro.len_known = d->uncmpr_len_known;
	dcmpro.expected_len =  d->uncmpr_len;

	switch(d->cmpr_meth) {
	case CMPR_NONE:
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case CMPR_XOR:
		do_decompress_XOR(c, &dcmpri, &dcmpro, &dres);
		break;
	case CMPR_SZDD:
		fmtutil_decompress_szdd(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case CMPR_LZHUFF:
		do_decompress_LZHUFF(c, &dcmpri, &dcmpro, &dres);
		break;
	case CMPR_MSZIP:
		do_decompress_MSZIP(c, &dcmpri, &dcmpro, &dres);
		break;
	}

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(dres.bytes_consumed_valid) {
		de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
			dres.bytes_consumed, outf->len);
	}

	if(d->uncmpr_len_known && (outf->len != d->uncmpr_len)) {
		de_warn(c, "Expected %"I64_FMT" output bytes, got %"I64_FMT,
			d->uncmpr_len, outf->len);
	}

done:
	;
}

static void do_extract_file(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

	de_dbg(c, "compressed data at %"I64_FMT, d->cmpr_data_pos);
	if(!cmpr_meth_is_supported(d, d->cmpr_meth)) {
		de_err(c, "Compression method %u (%s) is not supported", d->cmpr_meth,
			get_cmpr_meth_name(d->cmpr_meth));
		goto done;
	}
	if(d->cmpr_data_len<0) goto done;

	de_dbg_indent(c, 1);
	fi = de_finfo_create(c);
	if(ucstring_isnonempty(d->filename)) {
		de_finfo_set_name_from_ucstring(c, fi, d->filename, 0);
		fi->original_filename_flag = 1;
	}
	else {
		de_finfo_set_name_from_sz(c, fi, "bin", 0, DE_ENCODING_LATIN1);
	}
	outf = dbuf_create_output_file(c, NULL, fi, 0);
	do_decompress(c, d, outf);
	de_dbg_indent(c, -1);

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static int detect_fmt_internal(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "\x53\x5a\x44\x44\x88\xf0\x27\x33", 8))
		return FMT_SZDD;

	if(!de_memcmp(buf, "\x4b\x57\x41\x4a\x88\xf0\x27\xd1", 8))
		return FMT_KWAJ;
	return 0;
}

static void de_run_mscompress(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	d->fmt = detect_fmt_internal(c);
	if(d->fmt==FMT_SZDD) {
		de_declare_fmt(c, "MS Installation Compression, SZDD variant");
	}
	else if(d->fmt==FMT_KWAJ) {
		de_declare_fmt(c, "MS Installation Compression, KWAJ variant");
	}
	else {
		de_err(c, "Unidentified format");
		goto done;
	}

	if(d->fmt==FMT_KWAJ) {
		if(!do_header_KWAJ(c, d, 0)) goto done;
	}
	else {
		if(!do_header_SZDD(c, d, 0)) goto done;
	}

	do_extract_file(c, d);

done:
	if(d) {
		ucstring_destroy(d->filename);
		de_free(c, d);
	}
}

static int de_identify_mscompress(deark *c)
{
	int fmt;
	fmt = detect_fmt_internal(c);
	if(fmt!=0) return 100;
	return 0;
}

void de_module_mscompress(deark *c, struct deark_module_info *mi)
{
	mi->id = "mscompress";
	mi->desc = "MS-DOS Installation Compression";
	mi->run_fn = de_run_mscompress;
	mi->identify_fn = de_identify_mscompress;
}
