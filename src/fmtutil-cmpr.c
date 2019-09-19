// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Decompression, etc.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

// Initialize or reset a dfilter results struct
void de_dfilter_results_clear(deark *c, struct de_dfilter_results *dres)
{
	de_zeromem(dres, sizeof(struct de_dfilter_results));
	de_strlcpy(dres->errmsg, "Unspecified error", sizeof(dres->errmsg));
}

void de_dfilter_set_errorf(deark *c, struct de_dfilter_results *dres, const char *modname,
	const char *fmt, ...)
{
	va_list ap;

	if(dres->errcode != 0) return; // Only record the first error
	dres->errcode = 1;

	va_start(ap, fmt);
	if(modname) {
		char tmpbuf[80];

		de_vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);
		de_snprintf(dres->errmsg, sizeof(dres->errmsg), "[%s] %s", modname, tmpbuf);
	}
	else {
		de_vsnprintf(dres->errmsg, sizeof(dres->errmsg), fmt, ap);
	}
	va_end(ap);
}

void de_dfilter_set_generic_error(deark *c, struct de_dfilter_results *dres, const char *modname)
{
	if(dres->errcode != 0) return;
	de_dfilter_set_errorf(c, dres, modname, "Unspecified error");
}

void de_fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 endpos;
	i64 outf_len_limit = 0;
	dbuf *f = dcmpri->f;
	dbuf *unc_pixels = dcmpro->f;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	if(dcmpro->len_known) {
		outf_len_limit = unc_pixels->len + dcmpro->expected_len;
	}

	while(1) {
		if(dcmpro->len_known && unc_pixels->len >= outf_len_limit) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (i64)b;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (i64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
		// Else b==128. No-op.
		// TODO: Some (but not most) ILBM specs say that code 128 is used to
		// mark the end of compressed data, so maybe there should be options to
		// tell us what to do when code 128 is encountered.
	}

	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

// Returns 0 on failure (currently impossible).
int de_fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = 0;
	de_zeromem(&dcmpri, sizeof(struct de_dfilter_in_params));
	de_zeromem(&dcmpro, sizeof(struct de_dfilter_out_params));
	de_dfilter_results_clear(f->c, &dres);

	dcmpri.f = f;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	if(unc_pixels->has_len_limit) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = unc_pixels->len_limit - unc_pixels->len;
	}

	de_fmtutil_decompress_packbits_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

// A 16-bit variant of de_fmtutil_uncompress_packbits().
void de_fmtutil_decompress_packbits16_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b1, b2;
	i64 k;
	i64 count;
	i64 endpos;
	i64 outf_len_limit = 0;
	dbuf *f = dcmpri->f;
	dbuf *unc_pixels = dcmpro->f;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;

	if(dcmpro->len_known) {
		outf_len_limit = unc_pixels->len + dcmpro->expected_len;
	}

	while(1) {
		if(dcmpro->len_known && unc_pixels->len >= outf_len_limit) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (i64)b;
			b1 = dbuf_getbyte(f, pos++);
			b2 = dbuf_getbyte(f, pos++);
			for(k=0; k<count; k++) {
				dbuf_writebyte(unc_pixels, b1);
				dbuf_writebyte(unc_pixels, b2);
			}
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (i64)b;
			dbuf_copy(f, pos, count*2, unc_pixels);
			pos += count*2;
		}
		// Else b==128. No-op.
	}

	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

int de_fmtutil_decompress_packbits16(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = 0;
	de_zeromem(&dcmpri, sizeof(struct de_dfilter_in_params));
	de_zeromem(&dcmpro, sizeof(struct de_dfilter_out_params));
	de_dfilter_results_clear(f->c, &dres);

	dcmpri.f = f;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	if(unc_pixels->has_len_limit) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = unc_pixels->len_limit - unc_pixels->len;
	}

	de_fmtutil_decompress_packbits16_ex(f->c, &dcmpri, &dcmpro, &dres);

	if(cmpr_bytes_consumed && dres.bytes_consumed_valid) {
		*cmpr_bytes_consumed = dres.bytes_consumed;
	}
	if(dres.errcode != 0) return 0;
	return 1;
}

void de_fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	int ret;

	ret = de_fmtutil_decompress_rle90(dcmpri->f, dcmpri->pos, dcmpri->len,
		dcmpro->f, (unsigned int)dcmpro->len_known, dcmpro->expected_len,
		flags);

	if(!ret) {
		de_dfilter_set_generic_error(c, dres, "rle90");
	}
}

// RLE algorithm occasionally called "RLE90". Variants of this are used by
// BinHex, ARC, StuffIt, and others.
// TODO: Make de_fmtutil_decompress_rle90_ex the main function.
int de_fmtutil_decompress_rle90(dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, unsigned int has_maxlen, i64 max_out_len, unsigned int flags)
{
	i64 pos = pos1;
	u8 b;
	u8 lastbyte = 0x00;
	u8 countcode;
	i64 count;
	i64 nbytes_written = 0;

	while(pos < pos1+len) {
		if(has_maxlen && nbytes_written>=max_out_len) break;

		b = dbuf_getbyte(inf, pos);
		pos++;
		if(b!=0x90) {
			dbuf_writebyte(outf, b);
			nbytes_written++;
			lastbyte = b;
			continue;
		}

		// b = 0x90, which is a special code.
		countcode = dbuf_getbyte(inf, pos);
		pos++;

		if(countcode==0x00) {
			// Not RLE, just an escaped 0x90 byte.
			dbuf_writebyte(outf, 0x90);
			nbytes_written++;

			// Here there is an inconsistency between different RLE90
			// implementations.
			// Some of them can compress a run of 0x90 bytes, because the byte
			// to repeat is defined to be the "last byte emitted".
			// Others do not allow this. If the "0x90 0x00 0x90 0xNN" sequence
			// (with 0xNN>0) is encountered, they may (by accident?) repeat the
			// last non-0x90 byte emitted, or do something else.
			// Hopefully, valid files in such formats never contain this byte
			// sequence, so it shouldn't matter what we do here. But maybe not.
			// We might need to add an option to do something else.
			lastbyte = 0x90;
			continue;
		}

		// RLE. We already emitted one byte (because the byte to repeat
		// comes before the repeat count), so write countcode-1 bytes.
		count = (i64)(countcode-1);
		if(has_maxlen && (nbytes_written+count > max_out_len)) {
			count = max_out_len - nbytes_written;
		}
		dbuf_write_run(outf, lastbyte, count);
		nbytes_written += count;
	}

	return 1;
}
