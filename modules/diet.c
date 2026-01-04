// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// DIET compression format

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_diet);

#define MAX_DIET_DCMPR_LEN 4194304

enum ftype_enum {
	FTYPE_UNKNOWN=0, FTYPE_DATA, FTYPE_COM, FTYPE_EXE
};

enum fmt_enum {
	FMT_UNKNOWN=0,
	FMT_DATA_100, // v1.00, 1.00d
	FMT_DATA_102, // v1.02b, 1.10a, 1.20
	FMT_DATA_144, // v1.44, 1.45f
	FMT_COM_100,
	FMT_COM_102,
	FMT_COM_144,
	FMT_EXE_100,
	FMT_EXE_102,
	FMT_EXE_144,
	FMT_EXE_145F
};

struct diet_identify_data {
	// The change log from v1.45f suggests there should be at least 20-25
	// versions of DIET, but just 7 are known to exist:
	// 1.00, 1.00d, 1.02b, 1.10a, 1.20, 1.44, 1.45f
	enum fmt_enum fmt;
	enum ftype_enum ftype;
	u8 dlz_pos_known;
	u8 crc_pos_known;
	u8 cmpr_pos_known;
	u8 com2exe_flag;
	u8 maybe_lglz;
	i64 dlz_pos;
	i64 crc_pos;
	i64 cmpr_pos;
};

typedef struct localctx_struct_diet {
	struct diet_identify_data idd;
	u8 errflag;
	u8 need_errmsg;
	u8 cmpr_len_known;
	u8 orig_len_known;
	u8 raw_mode; // 0xff = not set
	u8 hdr_flags1; // Valid if dlz_pos_known (otherwise 0)
	u8 hdr_flags2; // Valid if dlz_pos_known (otherwise 0)
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	u32 crc_reported;
	struct fmtutil_exe_info *host_ei;
	dbuf *dcmpr_code; // (Maybe shouldn't be named "code".)
	i64 dcmpr_code_nbytes_written;
	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;
} lctx;

static void check_for_com2exe(deark *c, struct diet_identify_data *idd,
	struct fmtutil_exe_info *ei)
{
	UI n;

	if(!ei) return;
	// This seems to work, but I'm sure there's a better way to detect that
	// the original file was in COM format.
	n = (UI)de_getu16be(ei->end_of_dos_code - 13);
	if(n==0xed55) {
		idd->com2exe_flag = 1;
	}
}

// idmode==1: We're in the 'identify' phase -- Do just enough to
//   detect COM & data formats.
// ei can be NULL.
static void identify_diet_fmt(deark *c, struct diet_identify_data *idd, u8 idmode,
	struct fmtutil_exe_info *ei)
{
	static const u8 *sig_9d89 = (const u8*)"\x9d\x89";
	static const u8 *sig_dlz = (const u8*)"dlz";
	static const u8 *sig_int21 = (const u8*)"\xb4\x4c\xcd\x21";
	static const u8 *sig_old = (const u8*)"\xfd\xf3\xa5\xfc\x8b\xf7\xbf\x00";
	static const u8 *sig_8edb = (const u8*)"\x8e\xdb\x8e\xc0\x33\xf6\x33\xff\xb9";
	u8 buf[9];

	de_read(buf, 0, sizeof(buf));

	if(buf[0]==0xbe) {
		if(!dbuf_memcmp(c->infile, 35, sig_dlz, 3)) {
			if(!dbuf_memcmp(c->infile, 17, sig_old, 8))
			{
				idd->ftype = FTYPE_COM;
				idd->fmt = FMT_COM_102;
				idd->dlz_pos_known = 1;
				idd->dlz_pos = 35;
				goto done;
			}
		}
	}

	if(buf[0]==0xbf) {
		if(!dbuf_memcmp(c->infile, 17, sig_old, 8))
		{
			idd->ftype = FTYPE_COM;
			idd->fmt = FMT_COM_100;
			idd->crc_pos_known = 1;
			idd->crc_pos = 35;
			idd->cmpr_pos_known = 1;
			idd->cmpr_pos = 37;
			goto done;
		}
	}

	if(buf[0]==0xf9) {
		if(!dbuf_memcmp(c->infile, 65, sig_dlz, 3)) {
			if(!dbuf_memcmp(c->infile, 10, sig_9d89, 2)) {
				idd->ftype = FTYPE_COM;
				idd->fmt = FMT_COM_144;
				idd->dlz_pos_known = 1;
				idd->dlz_pos = 65;
				goto done;
			}
		}
	}

	if(buf[0]==0xb4) {
		if(!de_memcmp(&buf[0], sig_int21, 4)) {
			if(!de_memcmp(&buf[4], sig_9d89, 2)) {
				idd->ftype = FTYPE_DATA;
				if(!de_memcmp(&buf[6], sig_dlz, 3)) {
					idd->fmt = FMT_DATA_144;
					idd->dlz_pos_known = 1;
					idd->dlz_pos =  6;
					goto done;
				}
				idd->fmt = FMT_DATA_100;
				idd->crc_pos_known = 1;
				idd->crc_pos = 6;
				idd->cmpr_pos_known = 1;
				idd->cmpr_pos = 8;
				goto done;
			}
		}
	}

	if(buf[0]==0x9d) {
		if(!de_memcmp(&buf[0], sig_9d89, 2)) {
			if(!de_memcmp(&buf[2], sig_dlz, 3)) {
				idd->ftype = FTYPE_DATA;
				idd->fmt = FMT_DATA_102;
				idd->dlz_pos_known = 1;
				idd->dlz_pos = 2;
				goto done;
			}
		}
	}

	// Don't autodetect EXE -- It's handled by the "exe" module.
	if(idmode) goto done;

	if((buf[0]=='M' && buf[1]=='Z') || (buf[0]=='Z' && buf[1]=='M')) {
		i64 codestart;
		i64 sig_8edb_pos_rel = 0;
		u8 x;

		// TODO?: Probing for the 8e db 8e... byte pattern is good enough for
		// all the DIET-EXE files I've encountered. But it probably ought to be
		// improved, somehow.
		// I've found some files in which the "dlz" signature has been modified,
		// so checking for it wouldn't help much.

		codestart = 16 * de_getu16le(8); // Expected to be 32

		if(!dbuf_memcmp(c->infile, codestart-32+77, sig_8edb, 8)) {
			sig_8edb_pos_rel = 77-32;
		}
		else if(!dbuf_memcmp(c->infile, codestart-32+72, sig_8edb, 8)) {
			sig_8edb_pos_rel = 72-32;
		}
		else if(!dbuf_memcmp(c->infile, codestart-32+52, sig_8edb, 8)) {
			sig_8edb_pos_rel = 52-32;
		}
		else if(!dbuf_memcmp(c->infile, codestart-32+55, sig_8edb, 8)) {
			sig_8edb_pos_rel = 55-32;
		}

		if(sig_8edb_pos_rel==0) goto done;

		x = de_getbyte(codestart+sig_8edb_pos_rel+26);
		if(x==0x95) {
			idd->maybe_lglz = 1;
		}

		if(sig_8edb_pos_rel == 77-32) {
			idd->ftype = FTYPE_EXE;
			idd->fmt = FMT_EXE_145F;
			idd->dlz_pos_known = 1;
			idd->dlz_pos = codestart-32+108;
			check_for_com2exe(c, idd, ei);
			goto done;
		}

		if(sig_8edb_pos_rel == 72-32) {
			idd->ftype = FTYPE_EXE;
			idd->fmt = FMT_EXE_144;
			idd->dlz_pos_known = 1;
			idd->dlz_pos = codestart-32+107;
			check_for_com2exe(c, idd, ei);
			goto done;
		}

		if(sig_8edb_pos_rel == 52-32) {
			idd->ftype = FTYPE_EXE;
			idd->fmt = FMT_EXE_102;
			idd->dlz_pos_known = 1;
			idd->dlz_pos = codestart-32+87;
			goto done;
		}

		if(sig_8edb_pos_rel == 55-32) {
			idd->ftype = FTYPE_EXE;
			idd->fmt = FMT_EXE_100;
			idd->crc_pos_known = 1;
			idd->crc_pos = 18;
			idd->cmpr_pos_known = 1;
			idd->cmpr_pos = codestart-32+90;
			goto done;
		}
	}

done:
	if(idd->dlz_pos_known) {
		idd->crc_pos_known = 1;
		idd->cmpr_pos_known = 1;
		idd->crc_pos = idd->dlz_pos + 6;
		idd->cmpr_pos = idd->dlz_pos + 11;
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

	dbuf_writebyte(d->dcmpr_code, n);
	d->dcmpr_code_nbytes_written++;
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
			if(d->idd.ftype==FTYPE_EXE) {
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
		if((i64)matchpos+1 > d->dcmpr_code_nbytes_written) {
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
		d->dcmpr_code_nbytes_written);

done:
	dbuf_flush(d->dcmpr_code);
	de_lz77buffer_destroy(c, ringbuf);
	de_dbg_indent(c, -1);
}

static void write_data_or_com_file(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	const char *ext;

	if(d->idd.ftype==FTYPE_COM || d->idd.com2exe_flag) ext = "com";
	else ext = "bin";

	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(d->dcmpr_code, 0, d->dcmpr_code->len, outf);

	if(d->idd.ftype==FTYPE_COM) {
		de_stdwarn_execomp(c);
	}

	dbuf_close(outf);
}

struct exe_dcmpr_ctx {
	i64 mz_pos; // pos in d->dcmpr_code
	i64 encoded_reloc_tbl_pos; // pos in d->dcmpr_code
	i64 encoded_reloc_tbl_size; // size in d->dcmpr_code
	i64 cdata1_size;
	i64 cdata2_size; // Size in the original file; may be abbreviated in d->dcmpr_code
	struct fmtutil_exe_info guest_ei;
};

// For v1.00 format, there doesn't seem to be a good way to figure out the exact
// offset of the "MZ" header within the blob of bytes produced by the main
// decompression algorithm.
// I've never seen DIET fail to correctly decompress such a file, but I'm
// starting to suspect it might be possible to construct a pathological file
// for which it fails.
// We can narrow it down to 16 possibilities, and if there's exactly one that
// is potentially valid, we go with it. In practice, this should be good enough.
static void find_v100_mz_pos(deark *c, lctx *d, struct exe_dcmpr_ctx *ectx,
	i64 mz_pos_approx)
{
	i64 cmpr_endpos;
	i64 params_pos = 0;
	i64 reloc_tbl_rel = 0;
	i64 nrelocs_r = 0;
	i64 nbytes_to_search;
	int found_count = 0;
	u8 fclass = 0; // 0=unknown, 1=has params at params_pos, 2=no reloc table
	i64 i;
	i64 n;
	i64 foundpos;
	int ret;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "[searching for MZ pos in intermed. data]");
	de_dbg_indent(c, 1);

	cmpr_endpos = d->cmpr_pos + d->cmpr_len;
	de_dbg(c, "cmpr data end: %"I64_FMT, cmpr_endpos);

	// Sanity check. This part of the decompressor always seems to start with
	// these bytes.
	n = de_getu32be(cmpr_endpos);
	if(n != 0xd1edfecaU) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	// We're looking for some parameters in the part of the code that
	// appears after the compressed data. (But if there are 0 relocations,
	// then the params won't be present, and we have to detect that as
	// a special case.)
	// Probing at precise offsets doesn't seem to be robust enough, so we
	// resort to doing a search for characteristic byte patterns.

	nbytes_to_search = de_min_int(d->host_ei->end_of_dos_code - cmpr_endpos, 1000);

	if(fclass==0) {
		ret = dbuf_search(c->infile, (const u8*)"\x5d\x0e\x1f\xbe", 4, cmpr_endpos,
			nbytes_to_search, &foundpos);
		if(ret) {
			fclass = 1;
			params_pos = foundpos+4;
		}
	}

	if(fclass==0) {
		// The case where there are no relocations
		ret = dbuf_search(c->infile, (const u8*)"\x5d\x07\x1f\x81", 4, cmpr_endpos,
			nbytes_to_search, &foundpos);
		if(ret) {
			fclass = 2;
			nrelocs_r = 0;
		}
	}

	if(fclass==0) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(fclass==1) {
		de_dbg(c, "params pos: %"I64_FMT" (b+%"I64_FMT"; e-%"I64_FMT")",
			params_pos, params_pos - cmpr_endpos,
			d->host_ei->end_of_dos_code - params_pos);
		reloc_tbl_rel = de_getu16le(params_pos);
		de_dbg(c, "reloc tbl intermed. pos: approx_MZ+%"I64_FMT, reloc_tbl_rel);
		nrelocs_r =  de_getu16le(params_pos+3);
	}

	de_dbg(c, "nrelocs (reported): %"I64_FMT, nrelocs_r);

	// Search for the MZ header, hopefully avoiding false positives.
	for(i=0; i<16; i++) {
		int sig;

		// Look for "MZ" or "ZM"
		sig = (int)dbuf_getbyte(d->dcmpr_code, mz_pos_approx+i);
		if(sig!='M' && sig!='Z') continue;
		sig += (int)dbuf_getbyte(d->dcmpr_code, mz_pos_approx+i+1);
		if(sig != 'M'+'Z') continue;

		// Validate the reloc count
		n = dbuf_getu16le(d->dcmpr_code, mz_pos_approx+i+6);
		if(n!=nrelocs_r) continue;

		// Validate the reloc pos if possible
		if(fclass==1) {
			n = dbuf_getu16le(d->dcmpr_code, mz_pos_approx+i+24);
			if(i+n!=reloc_tbl_rel) continue;
		}

		found_count++;
		if(found_count>1) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		ectx->mz_pos = mz_pos_approx+i;
		break;
	}

	if(found_count!=1) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "MZ header found at %"I64_FMT, ectx->mz_pos);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Caller creates and passes empty newhdr to us.
static void acquire_new_exe_header(deark *c, lctx *d, struct exe_dcmpr_ctx *ectx,
	dbuf *newhdr)
{
	i64 iparam1;
	i64 n;
	i64 ioffset1;
	i64 mz_pos_approx;
	u8 byte3;

	if(d->errflag) return;

	switch(d->idd.fmt) {
	case FMT_EXE_100:
	case FMT_EXE_102:
		ioffset1 = 53;
		break;
	case FMT_EXE_144:
		ioffset1 = 73;
		break;
	case FMT_EXE_145F:
		ioffset1 = 26;
		break;
	default:
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	iparam1 = de_getu16le(d->host_ei->entry_point + ioffset1);
	mz_pos_approx = iparam1 * 16;
	de_dbg(c, "approx MZ pos in intermed. data: %"I64_FMT, mz_pos_approx);

	if(d->idd.fmt==FMT_EXE_100) {
		find_v100_mz_pos(c, d, ectx, mz_pos_approx);
		if(d->errflag) goto done;
	}
	else {
		if(!d->orig_len_known || !(d->hdr_flags1 & 0x20)) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		ectx->mz_pos = mz_pos_approx + (d->orig_len % 16);
		de_dbg(c, "expected MZ pos in intermed. data: %"I64_FMT, ectx->mz_pos);
		// Verify that this seems to be the right place.
		n = dbuf_getu16be(d->dcmpr_code, ectx->mz_pos);
		if(n!=0x4d5a && n!=0x5a4d) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
	}

	// Note: DIET elides trailing 0-valued bytes from the intermediate format
	// we store in dcmpr_code.
	// In some cases, dcmpr_code ends even before the end of the 28-byte
	// MZ header.
	// So, this and later calls to dbuf_copy() may read beyond the end of
	// dcmpr_code. That's by design -- we rely on dbuf_copy to replace
	// missing bytes with 0-valued bytes.
	dbuf_copy(d->dcmpr_code, ectx->mz_pos, 28, newhdr);

	byte3 = dbuf_getbyte(newhdr, 3);
	dbuf_writebyte_at(newhdr, 3, (byte3 & 0x01));

	fmtutil_collect_exe_info(c, newhdr, &ectx->guest_ei);

	// collect_exe_info() will not have calculated the overlay len, because we
	// didn't tell it the correct file size. So, patch it up here.
	ectx->guest_ei.overlay_len = ectx->guest_ei.start_of_dos_code + ectx->mz_pos -
		ectx->guest_ei.end_of_dos_code;
	if(ectx->guest_ei.overlay_len<0) ectx->guest_ei.overlay_len = 0;

	ectx->encoded_reloc_tbl_pos = ectx->mz_pos + ectx->guest_ei.reloc_table_pos;

	if(ectx->guest_ei.num_relocs==0) {
		ectx->cdata1_size = ectx->guest_ei.start_of_dos_code - 28;
		ectx->cdata2_size = 0;
	}
	else {
		ectx->cdata1_size = ectx->guest_ei.reloc_table_pos - 28;
		ectx->cdata2_size = ectx->guest_ei.start_of_dos_code - (ectx->guest_ei.reloc_table_pos +
			4*ectx->guest_ei.num_relocs);
	}
	if(ectx->cdata1_size<0 || ectx->cdata2_size<0) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	if(d->errflag && d->need_errmsg) {
		de_err(c, "Unsupported variety of DIET-EXE file");
		d->need_errmsg = 0;
	}
}

// Sets ectx->encoded_reloc_tbl_size
static void decode_reloc_tbl(deark *c, lctx *d, struct exe_dcmpr_ctx *ectx,
	dbuf *inf, i64 ipos1, i64 nrelocs, dbuf *outf)
{
	UI seg = 0;
	UI offs = 0;
	i64 i;
	i64 ipos = ipos1;

	for(i=0; i<nrelocs; i++) {
		UI n;

		n = (UI)dbuf_getu16le_p(inf, &ipos);
		if(n & 0x8000) {
			// Special code: segment stays the same, and offset is adjusted
			// relative to the previous offset.
			if(n >= 0xc000) {
				offs += n;
			}
			else {
				offs += (n-0x8000);
			}
			offs &= 0xffff;
		}
		else {
			seg = n;
			offs = (UI)dbuf_getu16le_p(inf, &ipos);
		}

		dbuf_writeu16le(outf, (i64)offs);
		dbuf_writeu16le(outf, (i64)seg);
	}

	if(d->hdr_flags1 & 0x20) {
		ectx->encoded_reloc_tbl_size = ipos - ipos1;
	}
	else {
		ectx->encoded_reloc_tbl_size = nrelocs*4;
	}
}

static void write_exe_file(deark *c, lctx *d)
{
	struct exe_dcmpr_ctx *ectx = NULL;
	dbuf *outf = NULL;
	dbuf *hdr_for_dcmpr_file = NULL;
	dbuf *guest_reloc_table = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!d->dcmpr_code) goto done;

	ectx = de_malloc(c, sizeof(struct exe_dcmpr_ctx));

	de_dbg(c, "[writing EXE]");
	de_dbg_indent(c, 1);
	hdr_for_dcmpr_file = dbuf_create_membuf(c, 28, 0);
	acquire_new_exe_header(c, d, ectx, hdr_for_dcmpr_file);
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "exe", NULL, 0);

	// 28-byte MZ header
	dbuf_copy(hdr_for_dcmpr_file, 0, 28, outf);

	// Copy the custom data up to the relocation table.
	// (If there's no relocation table, this will be everything up to the
	// code image).
	dbuf_copy(d->dcmpr_code, ectx->mz_pos+28, ectx->cdata1_size, outf);

	if(ectx->guest_ei.num_relocs!=0) {
		// Relocation table
		guest_reloc_table = dbuf_create_membuf(c, 4*ectx->guest_ei.num_relocs, 0);
		decode_reloc_tbl(c, d, ectx, d->dcmpr_code, ectx->encoded_reloc_tbl_pos,
			ectx->guest_ei.num_relocs, guest_reloc_table);
		dbuf_copy(guest_reloc_table, 0, 4*ectx->guest_ei.num_relocs, outf);

		// Custom data following the relocation table
		dbuf_copy(d->dcmpr_code,
			ectx->encoded_reloc_tbl_pos + ectx->encoded_reloc_tbl_size,
			ectx->cdata2_size, outf);
	}

	// Code image and (internal, compressed) overlay
	dbuf_copy(d->dcmpr_code, 0, ectx->mz_pos, outf);

	// Copy external overlay. Pristine DIET-compressed files never have such a
	// thing, but some other workflows (e.g. ARJ v2.00 SFX) create such files.
	if(d->host_ei->overlay_len>0) {
		if(ectx->guest_ei.overlay_len>0) {
			de_warn(c, "Ignoring overlay at %"I64_FMT" -- file already "
				"has an overlay", d->host_ei->end_of_dos_code);
		}
		else {
			de_dbg(c, "overlay data at %"I64_FMT", len=%"I64_FMT, d->host_ei->end_of_dos_code,
				d->host_ei->overlay_len);
			dbuf_copy(c->infile, d->host_ei->end_of_dos_code, d->host_ei->overlay_len, outf);
		}
	}

done:
	dbuf_close(guest_reloc_table);
	if(outf) {
		dbuf_close(outf);
		if(!d->errflag) {
			if(d->host_ei->is_extended) {
				// Disk Express creates hybrid DOS(w/DIET) / OS/2 files.
				de_warn(c, "This might be an extended EXE format. "
					"Only the DOS part will work after decompression.");
			}
			de_stdwarn_execomp(c);
		}
	}
	dbuf_close(hdr_for_dcmpr_file);
	if(ectx) {
		de_free(c, ectx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_header(deark *c, lctx *d)
{
	i64 pos = 0;
	i64 n;
	u8 x;
	de_ucstring *flags_str = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	flags_str = ucstring_create(c);

	if(d->idd.dlz_pos_known) {
		de_dbg(c, "header at %"I64_FMT, d->idd.dlz_pos);
		de_dbg_indent(c, 1);

		pos = d->idd.dlz_pos + 3;
		x = de_getbyte_p(&pos);
		d->hdr_flags1 = x & 0xf0;
		if(d->hdr_flags1 & 0x80) ucstring_append_flags_item(flags_str, "has following block");
		if(d->hdr_flags1 & 0x20) ucstring_append_flags_item(flags_str, "new EXE format");
		if(d->hdr_flags1 & 0x10) ucstring_append_flags_item(flags_str, "has segment refresh data");
		de_dbg(c, "flags: 0x%02x (%s)", d->hdr_flags1, ucstring_getpsz(flags_str));
		d->cmpr_len = (i64)(x & 0x0f)<<16;
		n = de_getu16le_p(&pos);
		d->cmpr_len |= n;
		de_dbg(c, "cmpr len: %"I64_FMT, d->cmpr_len);
		d->cmpr_len_known = 1;
	}
	else if(d->idd.fmt==FMT_EXE_100) {
		d->cmpr_len = de_getu32le(32);
		d->cmpr_len &= 0xfffff; // Dunno if this is 24-bits, or maybe just 20 bits
		de_dbg(c, "cmpr len: %"I64_FMT, d->cmpr_len);
		d->cmpr_len_known = 1;
	}

	if(d->idd.crc_pos_known) {
		d->crc_reported = (u32)de_getu16le(d->idd.crc_pos);
		de_dbg(c, "crc (reported): 0x%04x", (UI)d->crc_reported);
	}

	if(d->idd.dlz_pos_known) {
		pos = d->idd.dlz_pos + 8;
		x = de_getbyte_p(&pos);
		d->orig_len = (i64)(x & 0xfc)<<14;
		d->hdr_flags2 = (i64)(x & 0x03); // probably unused
		n = de_getu16le_p(&pos);
		d->orig_len |= n;
		de_dbg(c, "orig len: %"I64_FMT, d->orig_len);
		d->orig_len_known = 1;
	}

	if(!d->cmpr_len_known && d->idd.fmt==FMT_DATA_100) {
		d->cmpr_len = c->infile->len - d->cmpr_pos;
		d->cmpr_len_known = 1;
	}

	ucstring_destroy(flags_str);
	de_dbg_indent_restore(c, saved_indent_level);
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
	if(d->cmpr_pos+d->cmpr_len > c->infile->len) goto done;

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

static void check_unsupp_features(deark *c, lctx *d)
{
	if(d->hdr_flags1&0x80) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	;
}

static void de_run_diet(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *fmtn = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->host_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	d->raw_mode = (u8)de_get_ext_option_bool(c, "diet:raw", 0xff);

	fmtutil_collect_exe_info(c, c->infile, d->host_ei);

	identify_diet_fmt(c, &d->idd, 0, d->host_ei);
	switch(d->idd.fmt) {
	case FMT_DATA_100:
		fmtn = "file (v1.00)";
		break;
	case FMT_DATA_102:
		fmtn = "file (v1.02-1.20)";
		break;
	case FMT_DATA_144:
		fmtn = "file (v1.44-1.45)";
		break;
	case FMT_COM_100:
		fmtn = "COM (v1.00)";
		break;
	case FMT_COM_102:
		fmtn = "COM (v1.02-1.20)";
		break;
	case FMT_COM_144:
		fmtn = "COM (v1.44-1.45)";
		break;
	case FMT_EXE_100:
		fmtn = "EXE (v1.00)";
		break;
	case FMT_EXE_102:
		fmtn = "EXE (v1.02-1.20)";
		break;
	case FMT_EXE_144:
		if(d->idd.com2exe_flag)
			fmtn = "EXE-from-COM (v1.44)";
		else
			fmtn = "EXE (v1.44)";
		break;
	case FMT_EXE_145F:
		if(d->idd.com2exe_flag)
			fmtn = "EXE-from-COM (v1.45)";
		else
			fmtn = "EXE (v1.45)";
		break;
	default:
		break;
	}

	if(fmtn) {
		de_declare_fmtf(c, "DIET-compressed %s", fmtn);
	}

	if(d->idd.maybe_lglz) {
		de_warn(c, "This file might be LGLZ-compressed, not DIET");
	}

	if(!fmtn || !d->idd.cmpr_pos_known) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
	d->cmpr_pos = d->idd.cmpr_pos;

	read_header(c, d);
	if(d->errflag) goto done;

	check_diet_crc(c, d);

	check_unsupp_features(c, d);
	if(d->errflag) goto done;

	d->dcmpr_code = dbuf_create_membuf(c,
		(d->orig_len_known ? d->orig_len : MAX_DIET_DCMPR_LEN), 0x1);
	dbuf_enable_wbuffer(d->dcmpr_code);

	do_decompress_code(c, d);
	if(d->errflag) goto done;
	if(d->idd.ftype==FTYPE_DATA || d->idd.ftype==FTYPE_COM ||
		d->idd.com2exe_flag ||
		(d->idd.ftype==FTYPE_EXE && d->raw_mode==1))
	{
		write_data_or_com_file(c, d);
	}
	else if(d->idd.ftype==FTYPE_EXE && d->raw_mode!=1) {
		write_exe_file(c, d);
	}

done:
	if(d) {
		de_free(c, d->host_ei);
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported file");
		}
		dbuf_close(d->dcmpr_code);
		de_free(c, d);
	}
}

static int de_identify_diet(deark *c)
{
	struct diet_identify_data idd;

	de_zeromem(&idd, sizeof(struct diet_identify_data));
	identify_diet_fmt(c, &idd, 1, NULL);
	if(idd.ftype!=FTYPE_UNKNOWN) return 90;
	return 0;
}

static void de_help_diet(deark *c)
{
	de_msg(c, "-opt diet:raw : Instead of an EXE file, write raw decompressed data");
}

void de_module_diet(deark *c, struct deark_module_info *mi)
{
	mi->id = "diet";
	mi->desc = "DIET compression";
	mi->run_fn = de_run_diet;
	mi->identify_fn = de_identify_diet;
	mi->help_fn = de_help_diet;
}
