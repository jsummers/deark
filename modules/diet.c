// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// DIET compression format

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_diet);

#define MAX_DIET_DCMPR_LEN 4194304

#define FTYPE_DATA 1
#define FTYPE_COM  2
#define FTYPE_EXE  3

#define FMT_DATA_100  1   // v1.00, 1.00d
#define FMT_DATA_102  2   // v1.02b, 1.10a, 1.20
#define FMT_DATA_144  3   // v1.44, 1.45f
#define FMT_COM_100   11  // v1.00, 1.00d
#define FMT_COM_102   12  // v1.02b, 1.10a, 1.20
#define FMT_COM_144   13  // v1.044, 1.45f

typedef struct localctx_struct_diet {
	u8 errflag;
	u8 need_errmsg;
	u8 ftype;
	u8 cmpr_len_known;
	u8 orig_len_known;
	UI fmt;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	u32 crc_reported;
	dbuf *o_dcmpr_code;
	i64 o_dcmpr_code_nbytes_written;
	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;
} lctx;

struct diet_identify_data {
	// The change log from v1.45f suggests there should be at least 20-25
	// versions of DIET, but just 7 are known to exist:
	// 1.00, 1.00d, 1.02b, 1.10a, 1.20, 1.44, 1.45f
	UI fmt;
};

static void identify_diet_fmt(deark *c, struct diet_identify_data *dd)
{
	u8 b1;
	static const u8 *sigs = (const u8*)"\x9d\x89""dlz";
	static const u8 *int21sig = (const u8*)"\xb4\x4c\xcd\x21";
	static const u8 *oldsig = (const u8*)"\xfd\xf3\xa5\xfc\x8b\xf7\xbf\x00";
	de_zeromem(dd, sizeof(struct diet_identify_data));

	b1 = de_getbyte(0);

	if(b1==0xbe) {
		if(!dbuf_memcmp(c->infile, 35, &sigs[2], 3)) {
			if(!dbuf_memcmp(c->infile, 17, oldsig, 8))
			{
				dd->fmt = FMT_COM_102;
				return;
			}
		}
	}

	if(b1==0xbf) {
		if(!dbuf_memcmp(c->infile, 17, oldsig, 8))
		{
			dd->fmt = FMT_COM_100;
			return;
		}
	}

	if(b1==0xf9) {
		if(!dbuf_memcmp(c->infile, 65, &sigs[2], 3)) {
			if(!dbuf_memcmp(c->infile, 10, &sigs[0], 2)) {
				dd->fmt = FMT_COM_144;
				return;
			}
		}
	}

	if(b1==0xb4) {
		if(!dbuf_memcmp(c->infile, 0, int21sig, 4)) {
			if(!dbuf_memcmp(c->infile, 4, sigs, 5)) {
				dd->fmt = FMT_DATA_144;
				return;
			}

			if(!dbuf_memcmp(c->infile, 4, &sigs[0], 2)) {
				dd->fmt = FMT_DATA_100;
				return;
			}
		}
	}

	if(!dbuf_memcmp(c->infile, 0, sigs, 5)) {
		dd->fmt = FMT_DATA_102;
	}
}

static void fill_bitbuf(deark *c, lctx *d)
{
	UI i;

	if(d->errflag) return;
	if(d->dcmpr_cur_ipos+2 > c->infile->len) {
		d->errflag = 1;
		d->need_errmsg = 1;
		return;
	}

	for(i=0; i<2; i++) {
		u8 b;
		b = de_getbyte_p(&d->dcmpr_cur_ipos);
		de_bitbuf_lowlevel_add_byte(&d->bbll, b);
	}
}

static u8 diet_getbit(deark *c, lctx *d)
{
	u8 v;

	if(d->errflag) return 0;

	if(d->bbll.nbits_in_bitbuf==0) {
		fill_bitbuf(c, d);
	}

	v = (u8)de_bitbuf_lowlevel_get_bits(&d->bbll, 1);

	if(d->bbll.nbits_in_bitbuf==0) {
		fill_bitbuf(c, d);
	}

	return v;
}

static void my_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	lctx *d = (lctx*)rb->userdata;

	dbuf_writebyte(d->o_dcmpr_code, n);
	d->o_dcmpr_code_nbytes_written++;
}

static UI read_matchlen(deark *c, lctx *d)
{
	UI matchlen;
	u8 x, x1, x2, x3, x4, x5;
	u8 v;
	UI nbits_read = 0;

	// Read up to 4 bits, stopping early if we get a 1.
	while(1) {
		x = diet_getbit(c, d);
		nbits_read++;
		if(x) {
			matchlen = 2+nbits_read;
			goto done;
		}
		if(nbits_read>=4) break;
	}
	// At this point we've read 4 bits, all 0.

	x1 = diet_getbit(c, d);
	x2 = diet_getbit(c, d);

	if(x1==1) { // length 7-8
		matchlen = 7+x2;
		goto done;
	}

	if(x2==0) { // length 9-16
		x3 = diet_getbit(c, d);
		x4 = diet_getbit(c, d);
		x5 = diet_getbit(c, d);
		matchlen = 9 + 4*(UI)x3 + 2*(UI)x4 + (UI)x5;
		goto done;
	}

	// length 17-272
	v = de_getbyte_p(&d->dcmpr_cur_ipos);
	matchlen = 17 + (UI)v;

done:
	return matchlen;
}

static void do_decompress_code(deark *c, lctx *d)
{
	struct de_lz77buffer *ringbuf = NULL;
	u8 v;
	u8 x1, x2;
	u8 a1, a2, a3, a4, a5, a6, a7, a8;

	if(d->cmpr_pos + d->cmpr_len > c->infile->len) {
		d->errflag = 1;
		d->need_errmsg = 1;
	}
	de_dbg(c, "decompressing cmpr code at %"I64_FMT, d->cmpr_pos);
	de_dbg_indent(c, 1);

	ringbuf = de_lz77buffer_create(c, 8192);
	ringbuf->userdata = (void*)d;
	ringbuf->writebyte_cb = my_lz77buf_writebytecb;

	d->dcmpr_cur_ipos = d->cmpr_pos;
	d->bbll.is_lsb = 1;
	de_bitbuf_lowlevel_empty(&d->bbll);

	while(1) {
		UI matchpos = 0;
		UI matchlen;

		if(d->errflag) goto done;

		x1 = diet_getbit(c, d);
		if(x1) { // 1... -> literal byte
			u8 b;

			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			if(c->debug_level>=4) {
				de_dbg(c, "lit 0x%02x", (UI)b);
			}
			de_lz77buffer_add_literal_byte(ringbuf, b);
			continue;
		}

		x2 = diet_getbit(c, d);
		v = de_getbyte_p(&d->dcmpr_cur_ipos);

		if(x2==0) { // 00[XX]... -> 2-byte match or special code
			a1 = diet_getbit(c, d); // Always need at least 1 more bit
			if(a1) { // "long" two-byte match
				matchlen = 2;
				a2 = diet_getbit(c, d);
				a3 = diet_getbit(c, d);
				a4 = diet_getbit(c, d);
				matchpos = 2303 - (1024*(UI)a2 + 512*(UI)a3 + 256*(UI)a4 + v);
				goto ready_for_match;
			}
			else if(v!=0xff) { // "short" two-byte match
				matchlen = 2;
				matchpos = 0xff - (UI)v;
				goto ready_for_match;
			}

			// special code

			a2 = diet_getbit(c, d);
			if(a2==0) { // 00[FF]00
				de_dbg3(c, "stop code");
				goto after_decompress;
			}

			// 00[FF]01
			if(d->ftype==FTYPE_EXE) {
				de_dbg3(c, "segment refresh");
				continue;
			}
			de_err(c, "Unsupported feature");
			d->errflag = 1;
			goto done;
		}

		// 01[v] -> 3 or more byte match

		a1 = diet_getbit(c, d);
		a2 = diet_getbit(c, d);

		if(a2) { // 01[v]?1
			matchpos = 511 - (256*(UI)a1 + (UI)v);
			goto ready_for_len;
		}

		a3 = diet_getbit(c, d);
		if(a3) { // 01[v]?01
			matchpos = 1023 - (256*(UI)a1 + (UI)v);
			goto ready_for_len;
		}

		// 01[v]?00
		a4 = diet_getbit(c, d);
		a5 = diet_getbit(c, d);

		if(a5) { // 01[v]?00?1
			matchpos = 2047 - (512*(UI)a1 + 256* (UI)a4 + (UI)v);
			goto ready_for_len;
		}

		// 01[v]?00?0
		a6 = diet_getbit(c, d);
		a7 = diet_getbit(c, d);

		if(a7) { // 01[v]?00?0?1
			matchpos = 4095 - (1024*(UI)a1 + 512*(UI)a4 + 256*(UI)a6 + (UI)v);
			goto ready_for_len;
		}

		// 01[v]?00?0?0
		a8 = diet_getbit(c, d);
		matchpos = 8191 - (2048*(UI)a1 + 1024*(UI)a4 + 512*(UI)a6 + 256*(UI)a8 + (UI)v);


ready_for_len:
		matchlen = read_matchlen(c, d);
		if(d->errflag) goto done;

ready_for_match:
		if(c->debug_level>=3) {
			de_dbg3(c, "match pos=%u len=%u", matchpos+1, matchlen);
		}
		if((i64)matchpos+1 > d->o_dcmpr_code_nbytes_written) {
			// Match refers to data before the beginning of the file --
			// DIET doesn't do this.
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		if(matchlen > (i64)matchpos+1) {
			// Some matching data hasn't been decompressed yet.
			// This is a legitimate feature of LZ77, but DIET apparently doesn't
			// use it.
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		de_lz77buffer_copy_from_hist(ringbuf,
			(UI)(ringbuf->curpos-1-matchpos), matchlen);
	}

after_decompress:
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, (d->dcmpr_cur_ipos-d->cmpr_pos),
		d->o_dcmpr_code_nbytes_written);

done:
	dbuf_flush(d->o_dcmpr_code);
	de_lz77buffer_destroy(c, ringbuf);
	de_dbg_indent(c, -1);
}

static void write_data_or_com_file(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	const char *ext;

	if(d->ftype==FTYPE_COM) ext = "com";
	else ext = "bin";

	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	if(d->ftype==FTYPE_COM) {
		de_stdwarn_execomp(c);
	}

	dbuf_close(outf);
}

static void read_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	u8 bitfields1 = 0;
	u8 bitfields2 = 0;
	UI flags = 0;
	u8 has_full_hdr;
	i64 n;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(d->fmt==FMT_DATA_100 || d->fmt==FMT_COM_100) {
		has_full_hdr = 0;
	}
	else {
		has_full_hdr = 1;
	}

	if(has_full_hdr) {
		pos += 3; // "dlz"
		bitfields1 = de_getbyte_p(&pos);
		flags = bitfields1 & 0xf0;
		de_dbg(c, "flags: 0x%02x", flags);
		d->cmpr_len = (i64)(bitfields1&0x0f)<<16;
		n = de_getu16le_p(&pos);
		d->cmpr_len |= n;
		de_dbg(c, "cmpr len: %"I64_FMT, d->cmpr_len);
		d->cmpr_len_known = 1;
	}

	d->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)d->crc_reported);

	if(has_full_hdr) {
		bitfields2 = de_getbyte_p(&pos);
		d->orig_len = (i64)(bitfields2&0xfc)<<14;
		n = de_getu16le_p(&pos);
		d->orig_len |= n;
		de_dbg(c, "orig len: %"I64_FMT, d->orig_len);
		d->orig_len_known = 1;
	}

	if(flags!=0 || (bitfields2 & 0x03)!=0) {
		d->errflag = 1; // Unsupported feature
		d->need_errmsg = 1;
		goto done;
	}

	d->cmpr_pos = pos;

	if(d->fmt==FMT_DATA_100) {
		d->cmpr_len = c->infile->len - pos;
		d->cmpr_len_known = 1;
	}

done:
	de_dbg_indent(c, -1);
}

static void check_diet_crc(deark *c, lctx *d)
{
	u32 crc_calc;
	struct de_crcobj *crco = NULL;

	if(!d->cmpr_len_known) {
		// TODO: For v1.00 COM format, we don't know how to figure out the
		// compressed data size, and it doesn't end at the end of the file.
		// (Testing the CRC *after* decompression, after we've found the "stop"
		// code, isn't the right thing to do for this type of CRC.)
		goto done;
	}

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	de_crcobj_addslice(crco, c->infile, d->cmpr_pos, d->cmpr_len);
	crc_calc = de_crcobj_getval(crco);
	de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calc);
	// Unfortunately, this is a CRC of the *compressed* data, so we can't use it
	// to tell if we decompressed the data correctly.
	if(crc_calc!=d->crc_reported) {
		de_warn(c, "CRC check failed (expected 0x%04x, got 0x%04x). "
			"File may be corrupted.", (UI)d->crc_reported,
			(UI)crc_calc);
	}
done:
	de_crcobj_destroy(crco);
}

static void de_run_diet(deark *c, de_module_params *mparams)
{
	struct diet_identify_data dd;
	lctx *d = NULL;
	i64 hdrpos = 0; // pos of "dlz" if it exists, otherwise arbitrary
	const char *fmtn = NULL;

	d = de_malloc(c, sizeof(lctx));
	identify_diet_fmt(c, &dd);
	if(dd.fmt==FMT_DATA_100) {
		fmtn = "file (v1.00)";
		hdrpos = 6;
		d->ftype = FTYPE_DATA;
	}
	else if(dd.fmt==FMT_DATA_102) {
		fmtn = "file (v1.02b-1.20)";
		d->ftype = FTYPE_DATA;
		hdrpos = 2;
	}
	else if(dd.fmt==FMT_DATA_144) {
		fmtn = "file (v1.44+)";
		d->ftype = FTYPE_DATA;
		hdrpos = 6;
	}
	else if(dd.fmt==FMT_COM_100) {
		fmtn = "COM (v1.00)";
		d->ftype = FTYPE_COM;
		hdrpos = 35;
	}
	else if(dd.fmt==FMT_COM_102) {
		fmtn = "COM (v1.02b-1.20)";
		d->ftype = FTYPE_COM;
		hdrpos = 35;
	}
	else if(dd.fmt==FMT_COM_144) {
		fmtn = "COM (v1.44+)";
		d->ftype = FTYPE_COM;
		hdrpos = 65;
	}

	d->fmt = dd.fmt;

	if(fmtn) {
		de_declare_fmtf(c, "DIET-compressed %s", fmtn);
	}

	if(!fmtn || d->errflag) {
		de_err(c, "Unsupported DIET format");
		goto done;
	}

	read_header(c, d, hdrpos);
	if(d->errflag) goto done;

	check_diet_crc(c, d);

	if(d->orig_len_known) {
		d->o_dcmpr_code = dbuf_create_membuf(c, d->orig_len, 0x1);
	}
	else {
		d->o_dcmpr_code = dbuf_create_membuf(c, MAX_DIET_DCMPR_LEN, 0x1);
	}
	dbuf_enable_wbuffer(d->o_dcmpr_code);

	do_decompress_code(c, d);
	if(d->errflag) goto done;
	if(d->ftype==FTYPE_DATA || d->ftype==FTYPE_COM) {
		write_data_or_com_file(c, d);
	}

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported file");
		}
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d);
	}
}

static int de_identify_diet(deark *c)
{
	struct diet_identify_data dd;

	identify_diet_fmt(c, &dd);
	if(dd.fmt!=0) return 90;
	return 0;
}

void de_module_diet(deark *c, struct deark_module_info *mi)
{
	mi->id = "diet";
	mi->desc = "DIET compression";
	mi->run_fn = de_run_diet;
	mi->identify_fn = de_identify_diet;
}
