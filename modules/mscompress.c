// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// MS-DOS installation compression (compress.exe, expand.exe, MSLZ, etc.)

#include <deark-config.h>
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
	uint cmpr_meth;
	i64 cmpr_data_pos;
	i64 cmpr_data_len;
	u8 uncmpr_len_known;
	i64 uncmpr_len;
	de_ucstring *filename;
} lctx;

static int cmpr_meth_is_supported(uint n)
{
	switch(n) {
	case CMPR_NONE:
	case CMPR_XOR:
	case CMPR_SZDD:
	case CMPR_MSZIP:
		return 1;
	}
	return 0;
}

static const char *get_cmpr_meth_name(uint n)
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

	d->cmpr_meth = (uint)de_getu16le_p(&pos);
	de_dbg(c, "compression method: %u (%s)", d->cmpr_meth, get_cmpr_meth_name(d->cmpr_meth));

	d->cmpr_data_pos = de_getu16le_p(&pos);
	de_dbg(c, "compressed data offset: %"I64_FMT, d->cmpr_data_pos);
	d->cmpr_data_len = c->infile->len - d->cmpr_data_pos;

	flags = (uint)de_getu16le_p(&pos);
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

struct szdd_ctx {
	i64 nbytes_written;
	struct de_dfilter_out_params *dcmpro;
	uint wpos;
	u8 window[4096];
};

static void szdd_emit_byte(deark *c, struct szdd_ctx *sctx, u8 b)
{
	dbuf_writebyte(sctx->dcmpro->f, b);
	sctx->nbytes_written++;
	sctx->window[sctx->wpos] = b;
	sctx->wpos = (sctx->wpos+1) & 4095;
}

// Based on the libmspack's format documentation at
// <https://www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html>
static void do_decompress_SZDD(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos = dcmpri->pos;
	i64 endpos = dcmpri->pos + dcmpri->len;
	struct szdd_ctx *sctx = NULL;

	sctx = de_malloc(c, sizeof(struct szdd_ctx));
	sctx->dcmpro = dcmpro;
	sctx->wpos = 4096 - 16;
	de_memset(sctx->window, 0x20, 4096);

	while(1) {
		uint control;
		uint cbit;

		if(pos+1 > endpos) goto unc_done; // Out of input data
		control = (uint)dbuf_getbyte(dcmpri->f, pos++);

		for(cbit=0x01; cbit<=0x80; cbit<<=1) {
			if(control & cbit) { // literal
				u8 b;

				if(pos+1 > endpos) goto unc_done;
				b = dbuf_getbyte(dcmpri->f, pos++);
				szdd_emit_byte(c, sctx, b);
				if(dcmpro->len_known && sctx->nbytes_written>=dcmpro->expected_len) goto unc_done;
			}
			else { // match
				uint x0, x1;
				uint matchpos;
				uint matchlen;

				if(pos+2 > endpos) goto unc_done;
				x0 = (uint)dbuf_getbyte_p(dcmpri->f, &pos);
				x1 = (uint)dbuf_getbyte_p(dcmpri->f, &pos);
				matchpos = ((x1 & 0xf0) << 4) | x0;
				matchlen = (x1 & 0x0f) + 3;

				while(matchlen--) {
					szdd_emit_byte(c, sctx, sctx->window[matchpos]);
					if(dcmpro->len_known && sctx->nbytes_written>=dcmpro->expected_len) goto unc_done;
					matchpos = (matchpos+1) & 4095;
				}
			}
		}
	}

unc_done:
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = pos - dcmpri->pos;
	de_free(c, sctx);
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
		uint sig;

		if(pos > dcmpri1->pos + dcmpri1->len -4) {
			goto done;
		}
		blkpos = pos;
		de_dbg(c, "MSZIP block at %"I64_FMT, blkpos);
		de_dbg_indent(c, 1);
		blklen_raw = dbuf_getu16le_p(dcmpri1->f, &pos);
		blk_dlen = blklen_raw - 2;
		sig = (uint)dbuf_getu16be_p(dcmpri1->f, &pos);
		if(sig != 0x434b) { // "CK"
			de_dfilter_set_errorf(c, dres, modname, "Failed to find MSZIP block "
				"at %"I64_FMT, blkpos);
			goto done;
		}
		de_dbg(c, "block dpos: %"I64_FMT", dlen: %d", pos, (int)blk_dlen);
		if(blk_dlen < 0) goto done;
		dcmpri2.pos = pos;
		dcmpri2.len = blk_dlen;
		fmtutil_decompress_deflate_ex(c, &dcmpri2, &dcmpro2, dres, 0, prev_dict);
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
		do_decompress_SZDD(c, &dcmpri, &dcmpro, &dres);
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
	if(!cmpr_meth_is_supported(d->cmpr_meth)) {
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
