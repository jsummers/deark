// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// MS-DOS installation compression (compress.exe, expand.exe, MSLZ, etc.)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_mscompress);

#define FMT_SZDD 1
#define FMT_KWAJ 2

typedef struct localctx_struct {
	int fmt;
	de_int64 header_len;
	de_int64 uncmpr_len;
} lctx;

static int do_header_SZDD(deark *c, lctx *d, de_int64 pos1)
{
	de_byte cmpr_mode;
	de_byte fnchar;
	de_int64 pos = pos1;
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

	d->uncmpr_len = de_getui32le(pos);
	de_dbg(c, "uncompressed len: %"INT64_FMT"", d->uncmpr_len);
	pos += 4;

	d->header_len = pos - pos1;
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_header_KWAJ(deark *c, lctx *d, de_int64 pos1)
{
	int cmpr_method;
	de_int64 data_offs;
	unsigned int flags;
	de_int64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 8; // signature

	cmpr_method = (int)de_getui16le(pos);
	de_dbg(c, "compression method: %d", cmpr_method);
	pos+=2;

	data_offs = de_getui16le(pos);
	de_dbg(c, "compressed data offset: %d", (int)data_offs);
	pos+=2;

	flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "header extension flags: 0x%04x", flags);
	pos+=2;

	if(flags&0x01) {
		d->uncmpr_len = de_getui32le(pos);
		de_dbg(c, "uncompressed len: %"INT64_FMT"", d->uncmpr_len);
		pos += 4;
	}
	// TODO: More header fields

	de_dbg_indent(c, -1);
	return 0;
}

// Based on the libmspack's format documentation at
// <https://www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html>
static void do_uncompress_SZDD(deark *c,
	dbuf *inf, de_int64 pos1, de_int64 input_len,
	dbuf *outf, de_int64 expected_output_len)
{
	de_int64 pos = pos1;
	de_byte *window = NULL;
	unsigned int wpos;
	de_int64 nbytes_read;

	window = de_malloc(c, 4096);
	wpos = 4096 - 16;
	de_memset(window, 0x20, 4096);

	while(1) {
		unsigned int control;
		unsigned int cbit;

		if(pos >= (pos1+input_len)) break; // Out of input data

		control = (unsigned int)dbuf_getbyte(inf, pos++);

		for(cbit=0x01; cbit&0xff; cbit<<=1) {
			if(control & cbit) { // literal
				de_byte b;
				b = dbuf_getbyte(inf, pos++);
				dbuf_writebyte(outf, b);
				if(outf->len >= expected_output_len) goto unc_done;
				window[wpos] = b;
				wpos++; wpos &= 4095;
			}
			else { // match
				unsigned int matchpos;
				unsigned int matchlen;
				matchpos = (unsigned int)dbuf_getbyte(inf, pos++);
				matchlen = (unsigned int)dbuf_getbyte(inf, pos++);
				matchpos |= (matchlen & 0xf0) << 4;
				matchpos &= 4095;
				matchlen = (matchlen & 0x0f) + 3;
				while(matchlen--) {
					dbuf_writebyte(outf, window[matchpos]);
					if(outf->len >= expected_output_len) goto unc_done;
					window[wpos] = window[matchpos];
					wpos++; wpos &= 4095;
					matchpos++; matchpos &= 4095;
				}
			}
		}
	}

unc_done:
	nbytes_read = pos-pos1;
	de_dbg(c, "uncompressed %d bytes to %d bytes",
		(int)nbytes_read, (int)outf->len);

	if(outf->len != expected_output_len) {
		de_warn(c, "Expected %d output bytes, got %d\n",
			(int)expected_output_len, (int)outf->len);
	}

	de_free(c, window);
}

static int detect_fmt_internal(deark *c)
{
	de_byte buf[8];

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
	de_int64 pos = 0;
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
	do_uncompress_SZDD(c, c->infile, pos, c->infile->len-pos, outf, d->uncmpr_len);
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
