// This file is part of Deark.
// Copyright (C) 2016-2021 Jason Summers
// See the file COPYING for terms of use.

// This file is for miscellaneous formats that are easy to support.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_copy);
DE_DECLARE_MODULE(de_module_null);
DE_DECLARE_MODULE(de_module_join);
DE_DECLARE_MODULE(de_module_split);
DE_DECLARE_MODULE(de_module_xor);
DE_DECLARE_MODULE(de_module_plaintext);
DE_DECLARE_MODULE(de_module_cp437);
DE_DECLARE_MODULE(de_module_crc);
DE_DECLARE_MODULE(de_module_datetime);
DE_DECLARE_MODULE(de_module_hexdump);
DE_DECLARE_MODULE(de_module_bytefreq);
DE_DECLARE_MODULE(de_module_deflate);
DE_DECLARE_MODULE(de_module_zlib);
DE_DECLARE_MODULE(de_module_mrw);
DE_DECLARE_MODULE(de_module_zbr);
DE_DECLARE_MODULE(de_module_compress);
DE_DECLARE_MODULE(de_module_hpi);
DE_DECLARE_MODULE(de_module_dclimplode);
DE_DECLARE_MODULE(de_module_lgcompress);
DE_DECLARE_MODULE(de_module_lzss_oku);
DE_DECLARE_MODULE(de_module_lzhuf);
DE_DECLARE_MODULE(de_module_compress_lzh);
DE_DECLARE_MODULE(de_module_lzstac);
DE_DECLARE_MODULE(de_module_npack);
DE_DECLARE_MODULE(de_module_lzs221);
DE_DECLARE_MODULE(de_module_xpk);

// **************************************************************************
// "copy" module
//
// This is a trivial module that makes a copy of the input file.
// **************************************************************************

static void de_run_copy(deark *c, de_module_params *mparams)
{
	dbuf_create_file_from_slice(c->infile, 0, c->infile->len, "bin", NULL, 0);
}

void de_module_copy(deark *c, struct deark_module_info *mi)
{
	mi->id = "copy";
	mi->desc = "Copy the file unchanged";
	mi->run_fn = de_run_copy;
}

// **************************************************************************
// "null" module
//
// This is a trivial module that does nothing.
// **************************************************************************

static void de_run_null(deark *c, de_module_params *mparams)
{
	;
}

void de_module_null(deark *c, struct deark_module_info *mi)
{
	mi->id = "null";
	mi->desc = "Do nothing";
	mi->run_fn = de_run_null;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// "join"
//
// This is basically a multi-part example module.
// **************************************************************************

static void de_run_join(deark *c, de_module_params *mparams)
{
	int k;
	int num_parts = 1;
	dbuf *outf = NULL;

	if(c->mp_data) {
		num_parts += c->mp_data->count;
	}

	outf = dbuf_create_output_file(c, "bin", NULL, 0);

	for(k=0; k<num_parts; k++) {
		dbuf *inf;

		if(k>0 && c->mp_data) {
			de_dbg(c, "[mp file %d: %s]", k-1, c->mp_data->item[k-1].fn);
		}
		inf = de_mp_acquire_dbuf(c, k);
		if(!inf) {
			goto done;
		}

		dbuf_copy(inf, 0, inf->len, outf);

		de_mp_release_dbuf(c, k, &inf);
	}

done:
	dbuf_close(outf);
}

void de_module_join(deark *c, struct deark_module_info *mi)
{
	mi->id = "join";
	mi->desc = "Concatenate files";
	mi->run_fn = de_run_join;
	mi->flags |= DE_MODFLAG_MULTIPART;
}

// **************************************************************************
// split
// Split the input file into equal-sized chunks.
// **************************************************************************

static void do_split_onechunk(deark *c, i64 chunknum, i64 offset, i64 size)
{
	dbuf *outf = NULL;
	char ext[32];

	de_snprintf(ext, sizeof(ext), "part%"I64_FMT, chunknum);
	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(c->infile, offset, size, outf);
	dbuf_close(outf);
}

static void de_run_split(deark *c, de_module_params *mparams)
{
	const char *s;
	i64 pos;
	i64 chunknum;
	i64 chunksize, chunkstride;
	i64 chunkcount;

	s = de_get_ext_option(c, "split:size");
	if(!s) {
		de_err(c, "\"-opt split:size=<n>\" is required.");
		goto done;
	}
	chunksize = de_atoi64(s);
	if(chunksize<1) {
		de_err(c, "Invalid chunk size");
		goto done;
	}

	s = de_get_ext_option(c, "split:stride");
	if(s) {
		chunkstride = de_atoi64(s);
		if(chunkstride<chunksize) {
			de_err(c, "Stride must be "DE_CHAR_GEQ" size");
			goto done;
		}
	}
	else {
		chunkstride = chunksize;
	}

	chunkcount = (c->infile->len + (chunkstride-1)) / chunkstride;

	if((chunkcount>256) && (!c->user_set_max_output_files)) {
		de_err(c, "Large number of chunks; use \"-maxfiles %"I64_FMT"\" if you "
			"really want to do this.", chunkcount);
		goto done;
	}

	pos = 0;
	for(chunknum = 0; chunknum<chunkcount; chunknum++) {
		i64 this_chunk_size;

		this_chunk_size = de_min_int(chunksize, c->infile->len-pos);
		do_split_onechunk(c, chunknum, pos, this_chunk_size);

		pos += chunkstride;
	}

done:
	;
}

static void de_help_split(deark *c)
{
	de_msg(c, "-opt split:size=<n> : The size of each chunk, in bytes");
	de_msg(c, "-opt split:stride=<n> : Source distance between chunks");
}

void de_module_split(deark *c, struct deark_module_info *mi)
{
	mi->id = "split";
	mi->desc = "Split the file into equal-sized chunks";
	mi->run_fn = de_run_split;
	mi->help_fn = de_help_split;
}

// **************************************************************************
// xor
// Apply an XOR key to the file. Can be used to de-obfuscate some files.
// **************************************************************************

struct xorctx_struct {
	dbuf *outf;
	UI key_len;
	UI key_pos;
	u8 key[100];
};

static int xor_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 i;
	struct xorctx_struct *xorctx = (struct xorctx_struct*)brctx->userdata;

	for(i=0; i<buf_len; i++) {
		dbuf_writebyte(xorctx->outf, buf[i] ^ xorctx->key[xorctx->key_pos]);
		if(xorctx->key_len>1) {
			xorctx->key_pos = (xorctx->key_pos+1) % xorctx->key_len;
		}
	}
	return 1;
}

static void de_run_xor(deark *c, de_module_params *mparams)
{
	struct xorctx_struct *xorctx = NULL;
	int badkey_flag = 0;
	const char *opt_key;

	xorctx = de_malloc(c, sizeof(struct xorctx_struct));
	xorctx->key[0] = 0xff;
	xorctx->key_len = 1;

	opt_key = de_get_ext_option(c, "xor:key");
	if(opt_key) {
		UI key_strlen;
		UI k;

		key_strlen = (UI)de_strlen(opt_key);
		if(key_strlen%2) { badkey_flag = 1; goto done; }
		xorctx->key_len = key_strlen/2;
		if(xorctx->key_len<1 || (size_t)xorctx->key_len>sizeof(xorctx->key)) {
			badkey_flag = 1;
			goto done;
		}
		for(k=0; k<xorctx->key_len; k++) {
			u8 d1, d2;
			int errflag1 = 0;
			int errflag2 = 0;

			d1 = de_decode_hex_digit(opt_key[k*2], &errflag1);
			d2 = de_decode_hex_digit(opt_key[k*2+1], &errflag2);
			if(errflag1 || errflag2) { badkey_flag = 1; goto done; }
			xorctx->key[k] = (d1<<4) | d2;
		}
	}

	xorctx->outf = dbuf_create_output_file(c, "bin", NULL, 0);
	dbuf_enable_wbuffer(xorctx->outf);
	dbuf_buffered_read(c->infile, 0, c->infile->len, xor_cbfn, (void*)xorctx);

done:
	if(badkey_flag) {
		de_err(c, "Bad XOR key");
	}
	if(xorctx) {
		dbuf_close(xorctx->outf);
		de_free(c, xorctx);
	}
}

static void de_help_xor(deark *c)
{
	de_msg(c, "-opt xor:key=<aabbcc...> : Hex bytes to use as XOR key");
}

void de_module_xor(deark *c, struct deark_module_info *mi)
{
	mi->id = "xor";
	mi->desc = "Invert bits, or XOR with a key";
	mi->run_fn = de_run_xor;
	mi->help_fn = de_help_xor;
}

// **************************************************************************
// plaintext
// Convert text files to UTF-8.
// **************************************************************************

static de_encoding get_bom_enc(deark *c, UI *blen)
{
	u8 buf[3];

	de_read(buf, 0, 3);
	if(buf[0]==0xef && buf[1]==0xbb && buf[2]==0xbf) {
		*blen = 3;
		return DE_ENCODING_UTF8;
	}
	else if(buf[0]==0xfe && buf[1]==0xff) {
		*blen = 2;
		return DE_ENCODING_UTF16BE;
	}
	else if(buf[0]==0xff && buf[1]==0xfe) {
		*blen = 2;
		return DE_ENCODING_UTF16LE;
	}
	*blen = 0;
	return DE_ENCODING_UNKNOWN;
}

static void de_run_plaintext(deark *c, de_module_params *mparams)
{
	de_encoding input_encoding;
	de_encoding enc_from_bom;
	UI existing_bom_len = 0;
	i64 dpos, dlen;
	dbuf *outf = NULL;

	enc_from_bom = get_bom_enc(c, &existing_bom_len);
	input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);
	if(input_encoding==DE_ENCODING_UNKNOWN) {
		if(enc_from_bom!=DE_ENCODING_UNKNOWN) {
			input_encoding = enc_from_bom;
		}
		else {
			input_encoding = DE_ENCODING_UTF8;
		}
	}
	if(input_encoding!=enc_from_bom) {
		// Even if there was something that looked like a BOM, ignore it.
		existing_bom_len = 0;
	}

	dpos = (i64)existing_bom_len;
	dlen = c->infile->len - dpos;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	dbuf_enable_wbuffer(outf);

	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(outf, 0xfeff);
	}

	dbuf_copy_slice_convert_to_utf8(c->infile, dpos, dlen,
		DE_EXTENC_MAKE(input_encoding, DE_ENCSUBTYPE_HYBRID),
		outf, 0);

	dbuf_close(outf);
}

void de_module_plaintext(deark *c, struct deark_module_info *mi)
{
	mi->id = "plaintext";
	mi->desc = "Plain text";
	mi->desc2 = "Convert to UTF-8";
	mi->run_fn = de_run_plaintext;
}

// **************************************************************************
// CP437
// Convert CP437 text files to UTF-8.
// **************************************************************************

struct cp437ctx_struct {
	dbuf *outf;
	struct de_encconv_state es;
};

static int cp437_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i32 u;
	i64 i;
	u8 ch;
	struct cp437ctx_struct *cp437ctx = (struct cp437ctx_struct*)brctx->userdata;

	for(i=0; i<buf_len; i++) {
		ch = buf[i];
		if(ch==0x09 || ch==0x0a || ch==0x0c || ch==0x0d) {
			// Leave HT, NL, FF, CR as-is.
			u = (i32)ch;
		}
		else if(ch==0x1a) {
			// Lots of CP437 files end with a Ctrl+Z character, but modern files
			// don't use any in-band character to signify end-of-file.
			// I don't just want to delete the character, though, so I guess I'll
			// change it to U+2404 SYMBOL FOR END OF TRANSMISSION.
			u = 0x2404;
		}
		else {
			u = de_char_to_unicode_ex((i32)ch, &cp437ctx->es);
		}
		dbuf_write_uchar_as_utf8(cp437ctx->outf, u);
	}

	return 1;
}

static void de_run_cp437(deark *c, de_module_params *mparams)
{
	struct cp437ctx_struct cp437ctx;

	cp437ctx.outf = dbuf_create_output_file(c, "txt", NULL, 0);
	dbuf_enable_wbuffer(cp437ctx.outf);
	de_encconv_init(&cp437ctx.es, DE_ENCODING_CP437_G);
	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(cp437ctx.outf, 0xfeff);
	}
	dbuf_buffered_read(c->infile, 0, c->infile->len, cp437_cbfn, (void*)&cp437ctx);
	dbuf_close(cp437ctx.outf);
}

void de_module_cp437(deark *c, struct deark_module_info *mi)
{
	mi->id = "cp437";
	mi->desc = "Code Page 437 text";
	mi->run_fn = de_run_cp437;
}

// **************************************************************************
// crc
// Prints various CRCs and checksums. Does not create any files.
// **************************************************************************

struct crcm_alg_info {
	UI crctype;
	u8 flags; // 1 = computed by default
	u8 nbits; // 0 = special
	const char *name;
};

#define CRCM_NUMCRCS 11
static const struct crcm_alg_info crcm_map[CRCM_NUMCRCS] = {
	{ DE_CRCOBJ_CRC32_IEEE, 1, 32, "CRC-32-IEEE" },
	{ DE_CRCOBJ_CRC16_ARC, 1, 16, "CRC-16/ARC"},
	{ DE_CRCOBJ_CRC16_XMODEM, 1, 16, "CRC-16/XMODEM" },
	{ DE_CRCOBJ_CRC32_JAMCRC, 0, 32, "CRC-32/JAMCRC" },
	{ DE_CRCOBJ_CRC32_PL, 0, 32, "CRC-32/PL" },
	{ DE_CRCOBJ_ADLER32, 0, 32, "Adler-32" },
	{ DE_CRCOBJ_CRC16_IBMSDLC, 0, 16, "CRC-16/IBM-SDLC" },
	{ DE_CRCOBJ_CRC16_IBM3740, 0, 16, "CRC-16/IBM-3740" },
	{ DE_CRCOBJ_SUM_BYTES, 1, 0, "Sum of bytes" },
	{ DE_CRCOBJ_SUM_U16LE, 0, 0, "Sum of uint16-LE" },
	{ DE_CRCOBJ_SUM_U16BE, 0, 0, "Sum of uint16-BE" }
};

struct crcctx_struct {
	u8 opt_all;
	struct de_crcobj *crcos[CRCM_NUMCRCS];
};

static int crc_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct crcctx_struct *crcctx = (struct crcctx_struct*)brctx->userdata;
	size_t n;

	for(n=0; n<CRCM_NUMCRCS; n++) {
		if(!crcctx->crcos[n]) continue;
		de_crcobj_addbuf(crcctx->crcos[n], buf, buf_len);
	}

	return 1;
}

static void de_run_crc(deark *c, de_module_params *mparams)
{
	struct crcctx_struct crcctx;
	size_t n;

	de_zeromem(&crcctx, sizeof(struct crcctx_struct));
	crcctx.opt_all = (u8)de_get_ext_option_bool(c, "crc:all", 0xff);
	if(crcctx.opt_all==0xff) {
		if(c->extract_level>=2) {
			crcctx.opt_all = 1;
		}
		else {
			crcctx.opt_all = 0;
		}
	}

	for(n=0; n<CRCM_NUMCRCS; n++) {
		if((crcm_map[n].flags & 0x1)==0 && !crcctx.opt_all) continue;
		crcctx.crcos[n] = de_crcobj_create(c, crcm_map[n].crctype);
	}

	dbuf_buffered_read(c->infile, 0, c->infile->len, crc_cbfn, (void*)&crcctx);

	for(n=0; n<CRCM_NUMCRCS; n++) {
		u32 val = 0;
		u64 val64 = 0;

		if(!crcctx.crcos[n]) continue;

		if(crcm_map[n].nbits==0) {
			val64 = de_crcobj_getval64(crcctx.crcos[n]);
		}
		else {
			val = de_crcobj_getval(crcctx.crcos[n]);
		}

		if(crcm_map[n].nbits==0) {
			de_msg(c, "%-18s: 0x%"U64_FMTx, crcm_map[n].name, val64);
		}
		else if(crcm_map[n].nbits==16) {
			de_msg(c, "%-18s: 0x%04x", crcm_map[n].name, (UI)val);
		}
		else {
			de_msg(c, "%-18s: 0x%08x", crcm_map[n].name, (UI)val);
		}
	}

	for(n=0; n<CRCM_NUMCRCS; n++) {
		de_crcobj_destroy(crcctx.crcos[n]);
	}
}

static void de_help_crc(deark *c)
{
	de_msg(c, "-a : Also compute uncommon checksum types");
}

void de_module_crc(deark *c, struct deark_module_info *mi)
{
	mi->id = "crc";
	mi->id_alias[0] = "crc32";
	mi->desc = "Calculate various CRCs";
	mi->run_fn = de_run_crc;
	mi->help_fn = de_help_crc;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// datetime
// Interpret the start of the file as a date/time field, in various formats.
// **************************************************************************

static void datetime_msg(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_msg(c, "%s: %s", name, timestamp_buf);
}

static void de_run_datetime(deark *c, de_module_params *mparams)
{
	struct de_timestamp timestamp;
	i64 dtime, ddate;
	i64 t;

	dtime = de_getu16le(0);
	ddate = de_getu16le(2);
	de_dos_datetime_to_timestamp(&timestamp, ddate, dtime);
	datetime_msg(c, &timestamp, "DOS time,date");

	ddate = de_getu16le(0);
	dtime = de_getu16le(2);
	de_dos_datetime_to_timestamp(&timestamp, ddate, dtime);
	datetime_msg(c, &timestamp, "DOS date,time");

	t = de_geti32le(0);
	de_unix_time_to_timestamp(t, &timestamp, 0x1);
	datetime_msg(c, &timestamp, "Unix-LE");

	t = de_geti32be(0);
	de_unix_time_to_timestamp(t, &timestamp, 0x1);
	datetime_msg(c, &timestamp, "Unix-BE");

	t = de_getu32be(0);
	de_mac_time_to_timestamp(t, &timestamp);
	datetime_msg(c, &timestamp, "Mac/HFS-BE");

	t = de_geti64le(0);
	de_FILETIME_to_timestamp(t, &timestamp, 0x1);
	datetime_msg(c, &timestamp, "Windows FILETIME");
}

void de_module_datetime(deark *c, struct deark_module_info *mi)
{
	mi->id = "datetime";
	mi->desc = "Interpret a date/time field";
	mi->run_fn = de_run_datetime;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// hexdump
// Prints a hex dump. Does not create any files.
// **************************************************************************

static void de_run_hexdump(deark *c, de_module_params *mparams)
{
	de_hexdump2(c, c->infile, 0, c->infile->len,
		c->infile->len, 0x3);
}

void de_module_hexdump(deark *c, struct deark_module_info *mi)
{
	mi->id = "hexdump";
	mi->desc = "Print a hex dump";
	mi->run_fn = de_run_hexdump;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// bytefreq
// Prints a summary of how many times each byte value occurs.
// **************************************************************************

struct bytefreqentry {
	i64 count;
#define DE_BYTEFREQ_NUMLOC 3
	i64 locations[DE_BYTEFREQ_NUMLOC];
};

struct bytefreqctx_struct {
	struct bytefreqentry e[256];
};

static int bytefreq_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 k;
	struct bytefreqctx_struct *bfctx = (struct bytefreqctx_struct*)brctx->userdata;

	for(k=0; k<buf_len; k++) {
		struct bytefreqentry *bf = &bfctx->e[(unsigned int)buf[k]];

		// Save the location of the first few occurrences of this byte value.
		if(bf->count<DE_BYTEFREQ_NUMLOC) {
			bf->locations[bf->count] = brctx->offset + k;
		}
		bf->count++;
	}
	return 1;
}

static void de_run_bytefreq(deark *c, de_module_params *mparams)
{
	struct bytefreqctx_struct *bfctx = NULL;
	de_ucstring *s = NULL;
	unsigned int k;
	de_encoding input_encoding;
	struct de_encconv_state es;

	bfctx = de_malloc(c, sizeof(struct bytefreqctx_struct));
	input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	if(input_encoding==DE_ENCODING_UTF8) {
		input_encoding=DE_ENCODING_ASCII;
	}
	de_encconv_init(&es, input_encoding);

	dbuf_buffered_read(c->infile, 0, c->infile->len, bytefreq_cbfn, (void*)bfctx);

	de_msg(c, "====Byte==== ===Count=== ==Locations==");
	s = ucstring_create(c);
	for(k=0; k<256; k++) {
		i32 ch;
		int cflag;
		unsigned int z;
		struct bytefreqentry *bf = &bfctx->e[k];

		if(bf->count==0) continue;
		ucstring_empty(s);

		ucstring_printf(s, DE_ENCODING_LATIN1, "%3u 0x%02x ", k, k);

		ch = de_char_to_unicode_ex((i32)k, &es);
		if(ch==DE_CODEPOINT_INVALID) {
			cflag = 0;
		}
		else {
			cflag = de_is_printable_uchar(ch);
		}

		if(cflag) {
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
			ucstring_append_char(s, ch);
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
		}
		else {
			ucstring_append_sz(s, "   ", DE_ENCODING_LATIN1);
		}

		ucstring_printf(s, DE_ENCODING_LATIN1, " %11"I64_FMT" ", bf->count);

		for(z=0; z<DE_BYTEFREQ_NUMLOC && z<bf->count; z++) {
			ucstring_printf(s, DE_ENCODING_LATIN1, "%"I64_FMT, bf->locations[z]);
			if(z<bf->count-1) {
				ucstring_append_sz(s, ",", DE_ENCODING_LATIN1);
			}
		}
		if(bf->count>DE_BYTEFREQ_NUMLOC) {
			ucstring_append_sz(s, "...", DE_ENCODING_LATIN1);
		}

		de_msg(c, "%s", ucstring_getpsz(s));
	}
	de_msg(c, "      Total: %11"I64_FMT, c->infile->len);
	ucstring_destroy(s);
	de_free(c, bfctx);
}

void de_module_bytefreq(deark *c, struct deark_module_info *mi)
{
	mi->id = "bytefreq";
	mi->desc = "Print a byte frequence analysis";
	mi->run_fn = de_run_bytefreq;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// Raw "Deflate"-compressed data
// **************************************************************************

static void run_deflate_internal(deark *c, UI flags)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_deflate_params deflparams;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	de_zeromem(&deflparams, sizeof(struct de_deflate_params));
	deflparams.flags = flags;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = outf;
	fmtutil_decompress_deflate_ex(c, &dcmpri, &dcmpro, &dres, &deflparams);
	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}
	if(dres.bytes_consumed_valid) {
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, dres.bytes_consumed,
			outf->len);
	}

done:
	dbuf_close(outf);
}

static void de_run_deflate(deark *c, de_module_params *mparams)
{
	UI flags = 0;

	if(de_get_ext_option_bool(c, "deflate:deflate64", 0)) {
		flags |= DE_DEFLATEFLAG_DEFLATE64;
	}

	run_deflate_internal(c, flags);
}

void de_module_deflate(deark *c, struct deark_module_info *mi)
{
	mi->id = "deflate";
	mi->desc = "Raw Deflate compressed data";
	mi->run_fn = de_run_deflate;
}

// **************************************************************************
// zlib module
//
// This module is for decompressing zlib-compressed files.
// **************************************************************************

static void de_run_zlib(deark *c, de_module_params *mparams)
{
	run_deflate_internal(c, DE_DEFLATEFLAG_ISZLIB);
}

static int de_identify_zlib(deark *c)
{
	u8 b[2];
	de_read(b, 0, 2);

	if((b[0]&0x0f) != 8)
		return 0;

	if(b[0]<0x08 || b[0]>0x78)
		return 0;

	if(((((unsigned int)b[0])<<8)|b[1])%31 != 0)
		return 0;

	return 50;
}

void de_module_zlib(deark *c, struct deark_module_info *mi)
{
	mi->id = "zlib";
	mi->desc = "Raw zlib compressed data";
	mi->run_fn = de_run_zlib;
	mi->identify_fn = de_identify_zlib;
}

// **************************************************************************
// Minolta RAW (MRW)
// **************************************************************************

static void do_mrw_seg_list(deark *c, i64 pos1, i64 len)
{
	i64 pos;
	u8 seg_id[4];
	i64 data_len;

	pos = pos1;
	while(pos < pos1+len) {
		de_read(seg_id, pos, 4);
		data_len = de_getu32be(pos+4);
		pos+=8;
		if(pos+data_len > pos1+len) break;
		if(!de_memcmp(seg_id, "\0TTW", 4)) { // Exif
			fmtutil_handle_exif(c, pos, data_len);
		}
		pos+=data_len;
	}
}

static void de_run_mrw(deark *c, de_module_params *mparams)
{
	i64 mrw_seg_size;

	mrw_seg_size = de_getu32be(4);
	do_mrw_seg_list(c, 8, mrw_seg_size);
}

static int de_identify_mrw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x4d\x52\x4d", 4))
		return 100;
	return 0;
}

void de_module_mrw(deark *c, struct deark_module_info *mi)
{
	mi->id = "mrw";
	mi->desc = "Minolta RAW";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_mrw;
	mi->identify_fn = de_identify_mrw;
}

// **************************************************************************
// ZBR (Zoner Zebra Metafile)
// **************************************************************************

static void de_run_zbr(deark *c, de_module_params *mparams)
{
	i64 pos = 0;
	dbuf *outf = NULL;
	static const u8 hdrs[54] = {
		0x42,0x4d,0xc6,0x14,0,0,0,0,0,0,0x76,0,0,0, // FILEHEADER
		0x28,0,0,0,0x64,0,0,0,0x64,0,0,0,0x01,0,0x04,0, // INFOHEADER...
		0,0,0,0,0x50,0x14,0,0,0,0,0,0,0,0,0,0,
		0x10,0,0,0,0,0,0,0 };

	pos += 4; // signature, version
	pos += 100; // comment

	de_dbg(c, "preview image at %d", (int)pos);
	// By design, this image is formatted as a headerless BMP/DIB. We'll just
	// add the 54 bytes of headers needed to make it a BMP, and call it done.
	outf = dbuf_create_output_file(c, "preview.bmp", NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_write(outf, hdrs, 54);
	dbuf_copy(c->infile, pos, 16*4 + 100*52, outf);
	dbuf_close(outf);
}

static int de_identify_zbr(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x9a\x02", 2)) {
		if(de_input_file_has_ext(c, "zbr")) return 100;
		return 25;
	}
	return 0;
}

void de_module_zbr(deark *c, struct deark_module_info *mi)
{
	mi->id = "zbr";
	mi->desc = "ZBR (Zebra Metafile)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_zbr;
	mi->identify_fn = de_identify_zbr;
}

// **************************************************************************
// compress (.Z)
// **************************************************************************

static void de_run_compress(deark *c, de_module_params *mparams)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_lzw_params delzwp;
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "bin", NULL, 0);
	dbuf_enable_wbuffer(f);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = f;
	dcmpro.len_known = 0;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS3BYTEHEADER;

	fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);
	dbuf_flush(f);
	if(dres.errcode!=0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
	}
	dbuf_close(f);
}

static int de_identify_compress(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1f\x9d", 2))
		return 100;
	return 0;
}

void de_module_compress(deark *c, struct deark_module_info *mi)
{
	mi->id = "compress";
	mi->desc = "Compress (.Z)";
	mi->run_fn = de_run_compress;
	mi->identify_fn = de_identify_compress;
}

// **************************************************************************
// Hemera Photo-Object image (.hpi)
// **************************************************************************

static void de_run_hpi(deark *c, de_module_params *mparams)
{
	i64 jpgpos, pngpos;
	i64 jpglen, pnglen;
	i64 pos;

	pos = 12;
	jpgpos = de_getu32le_p(&pos);
	jpglen = de_getu32le_p(&pos);
	de_dbg(c, "jpeg: pos=%"I64_FMT", len=%"I64_FMT, jpgpos, jpglen);
	pngpos = de_getu32le_p(&pos);
	pnglen = de_getu32le_p(&pos);
	de_dbg(c, "png: pos=%"I64_FMT", len=%"I64_FMT, pngpos, pnglen);

	if(jpglen>0 && jpgpos+jpglen<=c->infile->len && de_getbyte(jpgpos)==0xff) {
		const char *ext;

		if(pnglen==0) ext="jpg";
		else ext="foreground.jpg";
		dbuf_create_file_from_slice(c->infile, jpgpos, jpglen, ext, NULL, 0);
	}
	if(pnglen>0 && pngpos+pnglen<=c->infile->len && de_getbyte(pngpos)==0x89) {
		dbuf_create_file_from_slice(c->infile, pngpos, pnglen, "mask.png", NULL, 0);
	}
}

static int de_identify_hpi(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x89\x48\x50\x49\x0d\x0a\x1a\x0a", 8)) return 100;
	return 0;
}

void de_module_hpi(deark *c, struct deark_module_info *mi)
{
	mi->id = "hpi";
	mi->desc = "Hemera Photo-Object image";
	mi->run_fn = de_run_hpi;
	mi->identify_fn = de_identify_hpi;
}

// **************************************************************************
// PKWARE DCL Implode compressed file
// **************************************************************************

static void dclimplode_main(deark *c, i64 cmpr_pos, i64 cmpr_len,
	u8 orig_len_known, i64 orig_len)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = cmpr_pos;
	dcmpri.len = cmpr_len;
	dcmpro.f = outf;
	if(orig_len_known) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = orig_len;
	}

	fmtutil_dclimplode_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}

	dbuf_close(outf);
}

static void de_run_dclimplode(deark *c, de_module_params *mparams)
{
	dclimplode_main(c, 0, c->infile->len, 0, 0);
}

static int de_identify_dclimplode(deark *c)
{
	u8 b0, b1;
	int i;
	u32 x;

	if(c->infile->len<4) return 0;
	b0 = de_getbyte(0);
	if(b0>1) return 0;
	b1 = de_getbyte(1);
	if(b1<4 || b1>6) return 0;

	// Look for the end-of-data code in the last 2 or 3 bytes.
	// Assumes the last byte is padded with '0' bits, and there are
	// no extraneous bytes after that.
	x = (u32)de_getu32le(c->infile->len-4);
	for(i=0; i<8; i++) {
		if((x & 0xfffffe00U)==0x01fe0200U) {
			if(b0==0 && b1==6) return 40;
			return 10;
		}
		x >>= 1;
	}
	return 0;
}

void de_module_dclimplode(deark *c, struct deark_module_info *mi)
{
	mi->id = "dclimplode";
	mi->id_alias[0] = "ttcomp";
	mi->desc = "PKWARE DCL Implode compressed file";
	mi->run_fn = de_run_dclimplode;
	mi->identify_fn = de_identify_dclimplode;
}

// **************************************************************************
// Logitech Compress / LGEXPAND (v2)
// **************************************************************************

static void de_run_lgcompress(deark *c, de_module_params *mparams)
{
	u8 mfnc;
	i64 orig_len;

	mfnc = de_getbyte(2);
	if(mfnc>=0x33 && mfnc<=126) {
		de_dbg(c, "missing filename char: '%c'", (int)mfnc);
	}
	orig_len = de_getu32le(4);
	de_dbg(c, "orig len: %"I64_FMT, orig_len);

	dclimplode_main(c, 8, c->infile->len-8, 1, orig_len);
}

static int de_identify_lgcompress(deark *c)
{
	if(de_getu16be(0) != 0xdafa) return 0;
	if(de_getu16be(8) != 0x0006) return 0;
	// TODO?: We could do more checks, especially at EOF.
	return 80;
}

void de_module_lgcompress(deark *c, struct deark_module_info *mi)
{
	mi->id = "lgcompress";
	mi->desc = "Logitech Compress";
	mi->run_fn = de_run_lgcompress;
	mi->identify_fn = de_identify_lgcompress;
}

// **************************************************************************
// LZSS (Haruhiko Okumura) compressed file
// **************************************************************************

static void de_run_lzss_oku(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = outf;

	fmtutil_decompress_lzss1(c, &dcmpri, &dcmpro, &dres, 0x0);
	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}

	dbuf_close(outf);
}

void de_module_lzss_oku(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzss_oku";
	mi->desc = "LZSS.C by Haruhiko Okumura";
	mi->run_fn = de_run_lzss_oku;
}

// **************************************************************************
// LZHUF (Haruyasu Yoshizaki) compressed file
// **************************************************************************

static void de_run_lzhuf(deark *c, de_module_params *mparams)
{
	i64 unc_filesize;
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	// We're assuming the size field is 4 bytes, little-endian. (But it could
	// be platform-specific.)
#define LZHUF_HDRSIZE 4
#define LZHUF_IS_LE   1

	if(c->infile->len<LZHUF_HDRSIZE) goto done;
	unc_filesize = dbuf_getint_ext(c->infile, 0, LZHUF_HDRSIZE, LZHUF_IS_LE, 0);
	de_dbg(c, "orig filesize: %"I64_FMT, unc_filesize);

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = LZHUF_HDRSIZE;
	dcmpri.len = c->infile->len-LZHUF_HDRSIZE;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = unc_filesize;

	fmtutil_lh1_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}
done:
	dbuf_close(outf);
}

void de_module_lzhuf(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzhuf";
	mi->desc = "LZHUF compressed file";
	mi->run_fn = de_run_lzhuf;
}

// **************************************************************************
// SCO compress LZH
// **************************************************************************

static void de_run_compress_lzh(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lh5x_params lzhparams;

#define SCOLZH_HDRSIZE 2
	if(c->infile->len<SCOLZH_HDRSIZE) goto done;
	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = SCOLZH_HDRSIZE;
	dcmpri.len = c->infile->len-SCOLZH_HDRSIZE;
	dcmpro.f = outf;

	de_zeromem(&lzhparams, sizeof(struct de_lh5x_params));
	lzhparams.fmt = DE_LH5X_FMT_LH5;
	lzhparams.zero_codes_block_behavior = DE_LH5X_ZCB_STOP;

	fmtutil_decompress_lh5x(c, &dcmpri, &dcmpro, &dres, &lzhparams);
	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}
done:
	dbuf_close(outf);
}

static int de_identify_compress_lzh(deark *c)
{
	if((UI)de_getu16be(0) != 0x1fa0) return 0;
	if(de_input_file_has_ext(c, "z")) return 90;
	return 10;
}

void de_module_compress_lzh(deark *c, struct deark_module_info *mi)
{
	mi->id = "compress_lzh";
	mi->desc = "SCO compress LZH";
	mi->run_fn = de_run_compress_lzh;
	mi->identify_fn = de_identify_compress_lzh;
}

// **************************************************************************
// Raw LZS (Stac) compressed data
// **************************************************************************

static void do_lzstac_internal(deark *c, i64 cmpr_pos, i64 cmpr_len, UI flags)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lzstac_params lzstacparams;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	dbuf_enable_wbuffer(outf);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = cmpr_pos;
	dcmpri.len = cmpr_len;
	dcmpro.f = outf;

	de_zeromem(&lzstacparams, sizeof(struct de_lzstac_params));
	lzstacparams.flags = flags;
	fmtutil_lzstac_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&lzstacparams);

	dbuf_flush(outf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}
	if(dres.bytes_consumed_valid) {
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, dres.bytes_consumed,
			outf->len);
		if(dres.bytes_consumed<cmpr_len) {
			de_warn(c, "%"I64_FMT" extra bytes at end of file. File might not "
				"have decompressed correctly.", cmpr_len - dres.bytes_consumed);
		}
	}

done:
	dbuf_close(outf);
}

static void de_run_lzstac(deark *c, de_module_params *mparams)
{
	do_lzstac_internal(c, 0, c->infile->len, 0);
}

void de_module_lzstac(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzstac";
	mi->desc = "Raw LZS (Stac) compressed data";
	mi->run_fn = de_run_lzstac;
}

// **************************************************************************
// NPack
// An installer format by Symantec & Stac
// **************************************************************************

static void de_run_npack(deark *c, de_module_params *mparams)
{
	// NPack decompresses at most 1 LZS block, hence the 0x2 flag.
	do_lzstac_internal(c, 5, c->infile->len-5, 0x2);
}

static int de_identify_npack(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"MSTSM", 5)) {
		return 0;
	}
	return 85;
}

void de_module_npack(deark *c, struct deark_module_info *mi)
{
	mi->id = "npack";
	mi->desc = "NPack compressed file";
	mi->run_fn = de_run_npack;
	mi->identify_fn = de_identify_npack;
}

// **************************************************************************
// LZS221
// e.g. LZSDEMO v3.1 by Stac
// **************************************************************************

static void de_run_lzs221(deark *c, de_module_params *mparams)
{
	do_lzstac_internal(c, 4, c->infile->len-4, 0);
}

static int de_identify_lzs221(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"sTaC", 4)) {
		return 0;
	}
	return 85;
}

void de_module_lzs221(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzs221";
	mi->desc = "LZS221 compressed file";
	mi->run_fn = de_run_lzs221;
	mi->identify_fn = de_identify_lzs221;
}

// **************************************************************************
// XPK compressed file format (XPKF)
// **************************************************************************

#define CODE_XPKF 0x58504b46U

static void xpkf_internal(deark *c)
{
	dbuf *tmpoutf = NULL;
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	tmpoutf = dbuf_create_membuf(c, 0, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = tmpoutf;

	fmtutil_xpk_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(tmpoutf);

	if(dres.errcode==0 || tmpoutf->len>0) {
		outf = dbuf_create_output_file(c, "unc", NULL, 0);
		dbuf_copy(tmpoutf, 0, tmpoutf->len, outf);
	}

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

done:
	dbuf_close(outf);
	dbuf_close(tmpoutf);
}

static void de_run_xpk(deark *c, de_module_params *mparams)
{
	xpkf_internal(c);
}

static int de_identify_xpk(deark *c)
{
	if((u32)de_getu32be(0)!=CODE_XPKF) return 0;
	return 85;
}

void de_module_xpk(deark *c, struct deark_module_info *mi)
{
	mi->id = "xpk";
	mi->desc = "XPK compressed file";
	mi->run_fn = de_run_xpk;
	mi->identify_fn = de_identify_xpk;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
