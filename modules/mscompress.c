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

typedef struct localctx_struct {
	int fmt;
	i64 header_len;
	i64 uncmpr_len;
} lctx;

static int do_header_SZDD(deark *c, lctx *d, i64 pos1)
{
	u8 cmpr_mode;
	u8 fnchar;
	i64 pos = pos1;
	char tmps[80];
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 8; // signature

	cmpr_mode = de_getbyte(pos++);
	de_dbg(c, "compression mode: 0x%02x ('%c')", (unsigned int)cmpr_mode,
		de_byte_to_printable_char(cmpr_mode));
	if(cmpr_mode != 0x41) {
		de_err(c, "Unsupported compression mode");
		goto done;
	}

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
	de_dbg(c, "uncompressed len: %"I64_FMT"", d->uncmpr_len);
	pos += 4;

	d->header_len = pos - pos1;
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_header_KWAJ(deark *c, lctx *d, i64 pos1)
{
	int cmpr_method;
	i64 data_offs;
	unsigned int flags;
	i64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 8; // signature

	cmpr_method = (int)de_getu16le(pos);
	de_dbg(c, "compression method: %d", cmpr_method);
	pos+=2;

	data_offs = de_getu16le(pos);
	de_dbg(c, "compressed data offset: %d", (int)data_offs);
	pos+=2;

	flags = (unsigned int)de_getu16le(pos);
	de_dbg(c, "header extension flags: 0x%04x", flags);
	pos+=2;

	if(flags&0x01) {
		d->uncmpr_len = de_getu32le(pos);
		de_dbg(c, "uncompressed len: %"I64_FMT"", d->uncmpr_len);
		//pos += 4;
	}
	// TODO: More header fields

	de_dbg_indent(c, -1);
	return 0;
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

static void do_decompress(deark *c,
	lctx *d, dbuf *inf, i64 pos, i64 input_len,
	dbuf *outf, i64 expected_output_len)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = inf;
	dcmpri.pos = pos;
	dcmpri.len = input_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = expected_output_len;
	do_decompress_SZDD(c, &dcmpri, &dcmpro, &dres);

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(dres.bytes_consumed_valid) {
		de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
			dres.bytes_consumed, outf->len);
	}

	if(outf->len != expected_output_len) {
		de_warn(c, "Expected %"I64_FMT" output bytes, got %"I64_FMT,
			expected_output_len, outf->len);
	}

done:
	;
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
	i64 pos = 0;
	dbuf *outf = NULL;

	d = de_malloc(c, sizeof(lctx));

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
		do_header_KWAJ(c, d, pos);
		// TODO: KWAJ format
		de_err(c, "MS Compress KWAJ format is not supported");
		goto done;
	}
	else {
		if(!do_header_SZDD(c, d, pos)) goto done;
	}
	pos += d->header_len;

	de_dbg(c, "compressed data at %d", (int)pos);
	de_dbg_indent(c, 1);
	outf = dbuf_create_output_file(c, "bin", NULL, 0);
	do_decompress(c, d, c->infile, pos, c->infile->len-pos, outf, d->uncmpr_len);
	de_dbg_indent(c, -1);

done:
	dbuf_close(outf);
	de_free(c, d);
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
