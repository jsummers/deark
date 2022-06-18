// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// ARJ compressed archive

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arj);

#define ARJ_MIN_BASIC_HEADER_SIZE 30
#define ARJ_MAX_BASIC_HEADER_SIZE 2600 // From the ARJ TECHNOTE file
#define MIN_VER_WITH_ANSIPAGE_FLAG 9 // Anything from 6-9 probably works
#define MIN_VER_WITH_ENCVER        8
#define MIN_VER_WITH_CHAPTERS      8
#define MIN_VER_WITH_FLAGS2        11
#define MIN_VER_WITH_ARCH_MTIME    6

static const u8 *g_arj_hdr_id = (const u8*)"\x60\xea";

enum objtype_enum {
	ARJ_OBJTYPE_MAINHDR = 100,
	ARJ_OBJTYPE_MEMBERFILE, // Including directories, volume labels
	ARJ_OBJTYPE_CHAPTERLABEL,
	ARJ_OBJTYPE_UNKNOWN,
	ARJ_OBJTYPE_EOA
};

#define ARJ_FILETYPE_BINARY       0
#define ARJ_FILETYPE_TEXT         1
#define ARJ_FILETYPE_MAINHDR      2
#define ARJ_FILETYPE_DIR          3
#define ARJ_FILETYPE_VOLUMELABEL  4
#define ARJ_FILETYPE_CHAPTERLABEL 5

#define ARJ_OS_DOS      0
#define ARJ_OS_UNIX     2
#define ARJ_OS_OS2      5
#define ARJ_OS_NEXT     8
#define ARJ_OS_WIN95    10
#define ARJ_OS_WIN32    11

struct member_data {
	de_encoding input_encoding;
	UI hdr_id;
	enum objtype_enum objtype; // Artificial field; tells how to parse and process this item
	u8 archiver_ver_num_raw;
	u8 archiver_ver_num_adj;
	u8 min_ver_to_extract;
	u8 os;
	u8 unix_timestamp_format;
	u8 flags;
	u8 method;
	u8 file_type; // ARJ_FILETYPE_*
	u8 is_dir;
	u8 is_executable;
	u8 is_nonexecutable;
	UI file_mode;
	u32 crc_reported;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];
	struct de_stringreaderdata *name_srd;
};

typedef struct localctx_struct {
	de_encoding input_encoding; // if DE_ENCODING_UNKNOWN, autodetect for each member
	u8 ansipage_flag;
	u8 is_secured;
	u8 is_old_secured;
	u8 arjprot_flag;
	u8 encryption_ver;
	i64 archive_start;
	i64 security_envelope_pos;
	i64 security_envelope_len;
	i64 arjprot_pos;
	struct de_crcobj *crco;
} lctx;

static void read_arj_datetime(deark *c, lctx *d, struct member_data *md,
	i64 pos, struct de_timestamp *ts1, const char *name)
{
	i64 dosdt, dostm;
	char timestamp_buf[64];

	dostm = de_getu16le(pos);
	dosdt = de_getu16le(pos+2);
	if(dostm==0 && dosdt==0) {
		de_snprintf(timestamp_buf, sizeof(timestamp_buf), "[not set]");
	}
	else if(md->unix_timestamp_format) {
		i64 ut;

		// Unix time is usually signed, but it seems that Open Source ARJ makes
		// it unsigned, so the valid dates are from 1970-2106.
		ut = (dosdt<<16) | dostm;
		de_unix_time_to_timestamp(ut, ts1, 0x1);
		de_timestamp_to_string(ts1, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_dos_datetime_to_timestamp(ts1, dosdt, dostm);
		ts1->tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(ts1, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	de_dbg(c, "%s time: %s", name, timestamp_buf);
}

static void handle_comment(deark *c, lctx *d, struct member_data *md, i64 pos,
	i64 nbytes_avail)
{
	de_ucstring *s = NULL;
	dbuf *outf = NULL;

	if(nbytes_avail<2) goto done;
	s = ucstring_create(c);
	// The header containing the comment is limited to about 2.5KB, so we don't have
	// check sizes here.
	dbuf_read_to_ucstring(c->infile, pos, nbytes_avail, s, DE_CONVFLAG_STOP_AT_NUL,
		DE_EXTENC_MAKE(md->input_encoding, DE_ENCSUBTYPE_HYBRID));
	if(s->len<1) goto done;
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));

	if(c->extract_level>=2) {
		const char *token;

		if(md->objtype==ARJ_OBJTYPE_MAINHDR) token = "comment.txt";
		else token = "fcomment.txt";

		outf = dbuf_create_output_file(c, token, NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
	}

done:
	dbuf_close(outf);
	ucstring_destroy(s);
}

static const char *get_host_os_name(u8 n)
{
	static const char *names[12] = { "MSDOS", "PRIMOS", "Unix", "Amiga", "MacOS",
		"OS/2", "Apple GS", "Atari ST", "NeXT", "VMS", "Win95", "WIN32" };

	if(n<=11) return names[(UI)n];
	return "?";
}

static const char *get_file_type_name(struct member_data *md, u8 n)
{
	const char *name = NULL;

	switch(n) {
	case 0: name = "binary"; break;
	case 1: name = "text"; break;
	case 2: name = "main header"; break;
	case 3: name = "directory"; break;
	case 4: name = "volume label"; break;
	case 5: name = "chapter"; break;
	}

	return name?name:"?";
}

static void get_flags_descr(struct member_data *md, u8 n1, de_ucstring *s)
{
	u8 n = n1;

	if(n & 0x01) {
		ucstring_append_flags_item(s, "GARBLED");
		n -= 0x01;
	}

	if((n & 0x02) && (md->objtype==ARJ_OBJTYPE_MAINHDR)) {
		if(md->archiver_ver_num_adj >= MIN_VER_WITH_ANSIPAGE_FLAG) {
			// ANSIPAGE introduced around ARJ v2.62.
			ucstring_append_flags_item(s, "ANSIPAGE");
		}
		else {
			// Suspect this is supported thru v2.39b, and was replaced with
			// (new) SECURED in v2.39c, with no versions that support both.
			ucstring_append_flags_item(s, "OLD_SECURED");
		}
		n -= 0x02;
	}

	if(n & 0x04) {
		ucstring_append_flags_item(s, "VOLUME");
		n -= 0x04;
	}

	if(n & 0x08) {
		if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
			ucstring_append_flags_item(s, "ARJPROT");
		}
		else {
			ucstring_append_flags_item(s, "EXTFILE");
		}
		n -= 0x08;
	}

	if(n & 0x10) {
		ucstring_append_flags_item(s, "PATHSYM");
		n -= 0x10;
	}

	if((n & 0x40) && (md->objtype==ARJ_OBJTYPE_MAINHDR)) {
		ucstring_append_flags_item(s, "SECURED");
		n -= 0x40;
	}

	if((n & 0x80) && (md->objtype==ARJ_OBJTYPE_MAINHDR)) {
		ucstring_append_flags_item(s, "ALTNAME");
		n -= 0x80;
	}

	if(n!=0) {
		ucstring_append_flags_itemf(s, "0x%02x", (UI)n);
	}
}

struct method4_ctx {
	i64 nbytes_written;
	int stop_flag;
	struct de_dfilter_out_params *dcmpro;
	struct de_bitreader bitrd;
};

static void method4_lz77buf_writebytecb(struct de_lz77buffer *rb, const u8 n)
{
	struct method4_ctx *cctx = (struct method4_ctx*)rb->userdata;

	if(cctx->stop_flag) return;
	if(cctx->dcmpro->len_known) {
		if(cctx->nbytes_written >= cctx->dcmpro->expected_len) {
			cctx->stop_flag = 1;
			return;
		}
	}

	dbuf_writebyte(cctx->dcmpro->f, n);
	cctx->nbytes_written++;
}

static UI method4_read_a_length_code(struct method4_ctx *cctx)
{
	UI onescount = 0;
	UI n;

	// Read up to 7 bits, counting the number of 1 bits, stopping after the first 0.
	while(1) {
		n = (UI)de_bitreader_getbits(&cctx->bitrd, 1);
		if(n==0) break;
		onescount++;
		if(onescount>=7) break;
	}

	// However many ones there were, read that number of bits.
	if(onescount==0) return 0;
	n = (UI)de_bitreader_getbits(&cctx->bitrd, onescount);
	return (1U<<onescount)-1 + n;
}

static UI method4_read_an_offset(struct method4_ctx *cctx)
{
	UI onescount = 0;
	UI n;

	// Read up to 4 bits, counting the number of 1 bits, stopping after the first 0.
	while(1) {
		n = (UI)de_bitreader_getbits(&cctx->bitrd, 1);
		if(n==0) break;
		onescount++;
		if(onescount>=4) break;
	}

	// Read {9 + the number of 1 bits} more bits.
	n = (UI)de_bitreader_getbits(&cctx->bitrd, 9+onescount);
	return (1U<<(9+onescount))-512 + n;
}

static void decompress_method_4(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct method4_ctx *cctx = NULL;
	struct de_lz77buffer *ringbuf = NULL;

	cctx = de_malloc(c, sizeof(struct method4_ctx));
	cctx->dcmpro = dcmpro;
	cctx->bitrd.f = dcmpri->f;
	cctx->bitrd.curpos = dcmpri->pos;
	cctx->bitrd.endpos = dcmpri->pos + dcmpri->len;

	// The maximum offset that can be encoded is 15871, so a 16K history is enough.
	ringbuf = de_lz77buffer_create(c, 16384);
	ringbuf->writebyte_cb = method4_lz77buf_writebytecb;
	ringbuf->userdata = (void*)cctx;

	while(1) {
		UI len_code;

		if(cctx->bitrd.eof_flag) goto done;
		if(cctx->stop_flag) goto done;
		if(cctx->dcmpro->len_known && (cctx->nbytes_written >= cctx->dcmpro->expected_len)) {
			goto done;
		}

		len_code = method4_read_a_length_code(cctx);
		if(len_code==0) {
			u8 b;

			b = (u8)de_bitreader_getbits(&cctx->bitrd, 8);
			de_lz77buffer_add_literal_byte(ringbuf, b);
		}
		else {
			UI offs;

			offs = method4_read_an_offset(cctx);
			de_lz77buffer_copy_from_hist(ringbuf, ringbuf->curpos-1-offs, len_code+2);
		}
	}

done:
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = cctx->bitrd.curpos - dcmpri->pos;
	de_lz77buffer_destroy(c, ringbuf);
	de_free(c, cctx);
}

static void decompress_method_1(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lh5x_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lh5x_params));
	lzhparams.fmt = DE_LH5X_FMT_LH6;

	// ARJ does not appear to allow LZ77 offsets that point to data before
	// the beginning of the file, so it doesn't matter what we initialize the
	// history buffer to.
	lzhparams.history_fill_val = 0x00;

	lzhparams.zero_codes_block_behavior = DE_LH5X_ZCB_65536;
	lzhparams.warn_about_zero_codes_block = 1;
	fmtutil_decompress_lh5x(c, dcmpri, dcmpro, dres, &lzhparams);
}

static void extract_member_file(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	size_t k;
	int need_to_decompress;
	u32 crc_calc;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(md->objtype!=ARJ_OBJTYPE_MEMBERFILE) goto done;
	if(!md->name_srd) goto done;

	if(md->is_dir || (md->orig_len==0))
		need_to_decompress = 0;
	else
		need_to_decompress = 1;

	if(md->file_type==9) { // Presumably ARJZ -t9
		de_err(c, "%s: Unsupported file type",
			ucstring_getpsz_d(md->name_srd->str));
		goto done;
	}

	if((md->flags & 0x01) && need_to_decompress) {
		de_err(c, "%s: %sed files are not supported",
			ucstring_getpsz_d(md->name_srd->str),
			(d->encryption_ver>=2 ? "Encrypt":"Garbl"));
		goto done;
	}

	if(need_to_decompress && (md->method>4)) {
		de_err(c, "%s: Compression method %u is not supported",
			ucstring_getpsz_d(md->name_srd->str), (UI)md->method);
		goto done;
	}

	fi = de_finfo_create(c);

	de_finfo_set_name_from_ucstring(c, fi, md->name_srd->str, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;

	fi->is_directory = md->is_dir;
	fi->is_volume_label = (md->file_type==ARJ_FILETYPE_VOLUMELABEL);
	if(!fi->is_directory && !fi->is_volume_label) {
		if(md->is_executable) {
			fi->mode_flags |= DE_MODEFLAG_EXE;
		}
		else if(md->is_nonexecutable) {
			fi->mode_flags |= DE_MODEFLAG_NONEXE;
		}
	}

	for(k=0; k<DE_TIMESTAMPIDX_COUNT; k++) {
		fi->timestamp[k] = md->tmstamp[k];
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_enable_wbuffer(outf);

	if(md->is_dir) goto done;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_pos;
	dcmpri.len = md->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_len;

	de_crcobj_reset(d->crco);
	dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)d->crco);

	if(md->orig_len==0) {
		;
	}
	else if(md->method==0) {
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
	}
	else if(md->method>=1 && md->method<=3) {
		decompress_method_1(c, d, md, &dcmpri, &dcmpro, &dres);
	}
	else if(md->method==4) {
		decompress_method_4(c, d, md, &dcmpri, &dcmpro, &dres);
	}
	dbuf_flush(dcmpro.f);

	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->name_srd->str),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%08x", (UI)crc_calc);
	if(crc_calc != md->crc_reported) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->name_srd->str));
		goto done;
	}

done:
	dbuf_close(outf);
	if(fi) de_finfo_destroy(c, fi);
}

static const char *get_objtype_name(enum objtype_enum t) {
	const char *name = NULL;

	switch(t) {
	case ARJ_OBJTYPE_MAINHDR: name="archive header"; break;
	case ARJ_OBJTYPE_MEMBERFILE: name="member file"; break;
	case ARJ_OBJTYPE_CHAPTERLABEL: name="chapter label"; break;
	case ARJ_OBJTYPE_EOA: name="end of archive"; break;
	default: break;
	}
	return name?name:"?";
}

static void fixup_path(de_ucstring *s)
{
	i64 i;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='\\') {
			s->str[i] = '/';
		}
	}
}

static char *get_archiver_ver_name(u8 v, char *buf, size_t buflen)
{
	static const char *anames[11] = {
		"0.13-0.14", "0.15-1.00", "1.10-2.22", "2.30", "2.39a-b",
		"2.39c-2.41a", "2.42a-2.50a", "2.55-2.61", "2.62-2.63", "2.63-2.76",
		"2.81+" };
	static const char *a32names[3] = { "3.00a-3.01a", "3.02-3.09", "3.10+" };

	if(v>=1 && v<=11) {
		// v=9 could also be ARJ32 3.00, but it's not worth listing.
		de_snprintf(buf, buflen, "ARJ %s", anames[(UI)v-1]);
	}
	else if(v>=100 && v<=102) {
		de_snprintf(buf, buflen, "ARJ32 %s", a32names[(UI)v-100]);
	}
	else if(v>=50 && v<=51) {
		de_strlcpy(buf, "ARJZ", buflen);
	}
	else {
		de_strlcpy(buf, "?", buflen);
	}
	return buf;
}

static int do_extended_headers(deark *c, lctx *d, struct member_data *md,
	i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	int idx = 0;
	u32 crc_reported;
	u32 crc_calc;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "ext hdrs at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		i64 ext_hdr_size;
		i64 ext_hdr_startpos = pos;
		i64 dpos;

		ext_hdr_size = de_getu16le_p(&pos);

		if(ext_hdr_size==0) {
			de_dbg(c, "end of ext hdrs at %"I64_FMT, pos);
			retval = 1;
			goto done;
		}
		de_dbg(c, "ext hdr #%d at %"I64_FMT", dlen=%"I64_FMT, idx, ext_hdr_startpos,
			ext_hdr_size);
		de_dbg_indent(c, 1);

		if(pos+ext_hdr_size+4 > c->infile->len) goto done;

		dpos = pos;

		de_crcobj_reset(d->crco);
		de_crcobj_addslice(d->crco, c->infile, dpos, ext_hdr_size);
		crc_calc = de_crcobj_getval(d->crco);

		pos = dpos + ext_hdr_size;
		crc_reported = (u32)de_getu32le_p(&pos);

		de_dbg(c, "ext hdr crc (reported): 0x%08x", (UI)crc_reported);
		de_dbg(c, "ext hdr crc (calculated): 0x%08x", (UI)crc_calc);
		if(crc_calc != crc_reported) goto done; // Assume we've gone off the rails

		de_dbg_hexdump(c, c->infile, dpos, ext_hdr_size, 256, NULL, 0x1);

		idx++;
		de_dbg_indent(c, -1);
	}

done:
	*pbytes_consumed = pos - pos1;
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// If successfully parsed, sets *pbytes_consumed.
// Returns 1 normally, 2 if this is the EOA marker, 0 on fatal error.
static int do_header_or_member(deark *c, lctx *d, i64 pos1, int expecting_archive_hdr,
	i64 *pbytes_consumed)
{
	i64 pos = pos1;
	i64 basic_hdr_size;
	i64 first_hdr_size;
	i64 first_hdr_endpos;
	i64 extra_data_len;
	i64 nbytes_avail;
	i64 n;
	i64 basic_hdr_endpos;
	i64 bytes_consumed;
	u32 basic_hdr_crc_reported;
	u32 basic_hdr_crc_calc;
	struct member_data *md = NULL;
	de_ucstring *flags_descr = NULL;
	int retval = 0;
	int saved_indent_level;
	u8 b;
	char namebuf[32];
	char tmpbuf[64];

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));

	md->hdr_id = (UI)de_getu16le_p(&pos);
	if(md->hdr_id!=0xea60) {
		de_err(c, "ARJ data not found at %"I64_FMT, pos1);
		goto done;
	}

	de_dbg(c, "block at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	basic_hdr_size = de_getu16le_p(&pos);
	de_dbg(c, "basic header size: %"I64_FMT, basic_hdr_size);
	if(basic_hdr_size==0) {
		md->objtype = ARJ_OBJTYPE_EOA;
	}
	else {
		// Skip ahead to read some fields that can affect fields that appear
		// before them.
		md->archiver_ver_num_raw = de_getbyte(pos1+5);
		md->file_type = de_getbyte(pos1+10);

		if(md->file_type==ARJ_FILETYPE_MAINHDR) {
			md->objtype = ARJ_OBJTYPE_MAINHDR;
		}
		else if(md->file_type==ARJ_FILETYPE_CHAPTERLABEL) {
			md->objtype = ARJ_OBJTYPE_CHAPTERLABEL;
		}
		else if(md->file_type<=4) {
			md->objtype = ARJ_OBJTYPE_MEMBERFILE;
		}
		else if(md->file_type==9 && md->archiver_ver_num_raw==51) {
			md->objtype = ARJ_OBJTYPE_MEMBERFILE; // ARJZ with -t9 option
		}
		else {
			md->objtype = ARJ_OBJTYPE_UNKNOWN;
		}
	}
	de_dbg(c, "block type: %s", get_objtype_name(md->objtype));

	if(basic_hdr_size==0) {
		*pbytes_consumed = 4;
		retval = 2;
		goto done;
	}

	if(basic_hdr_size>ARJ_MAX_BASIC_HEADER_SIZE) {
		de_err(c, "Bad header size");
		goto done;
	}

	de_dbg(c, "basic header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "first header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	basic_hdr_endpos = pos1 + 4 + basic_hdr_size;
	first_hdr_size = (i64)de_getbyte_p(&pos);
	de_dbg(c, "first header size: %"I64_FMT, first_hdr_size);
	first_hdr_endpos = pos1 + 4 + first_hdr_size;
	pos++; // md->archiver_ver_num_raw, already read
	de_dbg(c, "archiver version: %u (%s)", (UI)md->archiver_ver_num_raw,
		get_archiver_ver_name(md->archiver_ver_num_raw, namebuf, sizeof(namebuf)));

	// ARJ32 uses wacky version numbers starting with 100. Try to "correct" them.
	if(md->archiver_ver_num_raw>=100 && md->archiver_ver_num_raw<200) {
		md->archiver_ver_num_adj = md->archiver_ver_num_raw - 91;
	}
	else {
		md->archiver_ver_num_adj = md->archiver_ver_num_raw;
	}

	md->min_ver_to_extract = de_getbyte_p(&pos);
	de_dbg(c, "min ver to extract: %u", (UI)md->min_ver_to_extract);

	md->os = de_getbyte_p(&pos);
	de_dbg(c, "host OS: %u (%s)", (UI)md->os, get_host_os_name(md->os));

	if((md->os==ARJ_OS_UNIX || md->os==ARJ_OS_NEXT) &&
		(md->archiver_ver_num_raw>=11 && md->archiver_ver_num_raw<50))
	{
		// Ref: Open Source ARJ, resource/en/readme.txt
		md->unix_timestamp_format = 1;
	}

	md->flags = de_getbyte_p(&pos);
	flags_descr = ucstring_create(c);
	get_flags_descr(md, md->flags, flags_descr);
	de_dbg(c, "flags: 0x%02x (%s)", (UI)md->flags, ucstring_getpsz_d(flags_descr));
	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		if(md->archiver_ver_num_adj>=MIN_VER_WITH_ANSIPAGE_FLAG && (md->flags & 0x02)) {
			d->ansipage_flag = 1;
		}
		if(md->flags & 0x40) {
			d->is_secured = 1;
		}
		else if(md->archiver_ver_num_adj<MIN_VER_WITH_ANSIPAGE_FLAG && (md->flags & 0x02)) {
			d->is_old_secured = 1;
		}
		if(md->flags & 0x08) {
			d->arjprot_flag = 1;
		}
	}

	// Now we have enough information to choose a character encoding.
	md->input_encoding = d->input_encoding;
	if(md->input_encoding==DE_ENCODING_UNKNOWN) {
		if(d->ansipage_flag) {
			md->input_encoding = DE_ENCODING_WINDOWS1252;
		}
		else {
			md->input_encoding = DE_ENCODING_CP437;
		}
	}

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		b = de_getbyte_p(&pos);
		if(d->is_secured) {
			de_dbg(c, "security version: %u", (UI)b);
		}
	}
	else {
		md->method = de_getbyte_p(&pos);
		de_dbg(c, "cmpr method: %u", (UI)md->method);
	}

	pos++; // file_type already read
	de_dbg(c, "file type: %u (%s)", (UI)md->file_type, get_file_type_name(md, md->file_type));
	if(expecting_archive_hdr && md->file_type!=ARJ_FILETYPE_MAINHDR) {
		de_err(c, "Invalid or missing archive header");
		goto done;
	}
	if(md->objtype==ARJ_OBJTYPE_UNKNOWN) {
		de_err(c, "Unknown file type: %u", (UI)md->file_type);
		// (try to continue)
	}

	pos++; // reserved

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		read_arj_datetime(c, d, md, pos, &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "archive creation");
		pos += 4;
	}
	else if(md->objtype==ARJ_OBJTYPE_CHAPTERLABEL) {
		read_arj_datetime(c, d, md, pos,  &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "creation");
		pos += 4;
	}
	else {
		read_arj_datetime(c, d, md, pos, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod");
		pos += 4;
	}

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		md->cmpr_len = 0;
		if(d->is_old_secured) {
			n = de_getu32le_p(&pos);
			de_dbg(c, "archive size: %"I64_FMT, n); // This is a guess
		}
		else if(md->archiver_ver_num_adj>=MIN_VER_WITH_ARCH_MTIME) {
			read_arj_datetime(c, d, md, pos, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "archive mod");
			pos += 4;
		}
		else {
			pos += 4;
		}
	}
	else {
		// Assume this field always exists, except for the main header and EOA.
		// We need it just to parse the file.
		md->cmpr_len = de_getu32le_p(&pos);
		de_dbg(c, "compressed size: %"I64_FMT, md->cmpr_len);
	}

	if(md->objtype==ARJ_OBJTYPE_MAINHDR && d->is_old_secured) {
		// This is a guess
		de_dbg(c, "security data: %s",
			de_render_hexbytes_from_dbuf(c->infile, pos, 12, tmpbuf, sizeof(tmpbuf)));
		pos += 12;
		goto at_offset_32;
	}

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		n = de_getu32le_p(&pos);
		if(d->is_secured) {
			de_dbg(c, "archive size: %"I64_FMT, n);
		}
	}
	else if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
		md->orig_len = de_getu32le_p(&pos);
		de_dbg(c, "original size: %"I64_FMT, md->orig_len);
	}
	else {
		pos += 4;
	}

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		n = de_getu32le_p(&pos);
		if(d->is_secured) {
			d->security_envelope_pos = n;
			de_dbg(c, "security envelope pos: %"I64_FMT, d->security_envelope_pos);
		}
		else if(d->arjprot_flag) {
			d->arjprot_pos = n; // This is a guess
			de_dbg(c, "ARJPROT data pos: %"I64_FMT, d->arjprot_pos);
		}
	}
	else {
		md->crc_reported = (u32)de_getu32le_p(&pos);
		de_dbg(c, "crc (reported): 0x%08x", (UI)md->crc_reported);
	}

	n = de_getu16le_p(&pos);
	de_dbg(c, "filespec pos in filename: %d", (int)n);

	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		n = de_getu16le_p(&pos);
		if(d->is_secured) {
			d->security_envelope_len = n;
			de_dbg(c, "security envelope len: %"I64_FMT, d->security_envelope_len);
		}
	}
	else {
		de_ucstring *mode_descr;

		md->file_mode = (UI)de_getu16le_p(&pos);
		mode_descr = ucstring_create(c);
		if(md->os==ARJ_OS_DOS || md->os==ARJ_OS_OS2 || md->os==ARJ_OS_WIN95 || md->os==ARJ_OS_WIN32) {
			de_describe_dos_attribs(c, md->file_mode, mode_descr, 0);
		}
		else if(md->os==ARJ_OS_UNIX || md->os==ARJ_OS_NEXT) {
			ucstring_printf(mode_descr, DE_ENCODING_LATIN1, "octal %03o", md->file_mode);
			if((md->file_mode)&0111) {
				md->is_executable = 1;
			}
			else {
				md->is_nonexecutable = 1;
			}
		}
		else {
			ucstring_append_char(mode_descr, '?');
		}

		de_dbg(c, "access mode: 0x%02x (%s)", md->file_mode, ucstring_getpsz_d(mode_descr));
		ucstring_destroy(mode_descr);
	}

at_offset_32:

	b = de_getbyte_p(&pos); // first chapter / encryption ver / host data (byte1) / unused
	if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
		if(md->archiver_ver_num_adj>=MIN_VER_WITH_ENCVER) {
			de_dbg(c, "encryption ver: %u", (UI)b);
			// We expect the GARBLED flag to be set in the main header when this field
			// is meaningful, but I don't think ARJ requires that.
			d->encryption_ver = b;
		}
	}
	else {
		if(md->archiver_ver_num_adj>=MIN_VER_WITH_CHAPTERS) {
			de_dbg(c, "first chapter: %u", (UI)b);
		}
	}

	b = de_getbyte_p(&pos); // last chapter / host data (byte2) / unused
	if(md->archiver_ver_num_adj>=MIN_VER_WITH_CHAPTERS)
	{
		de_dbg(c, "last chapter: %u", (UI)b);
	}

	extra_data_len = first_hdr_endpos - pos;
	de_dbg(c, "extra data at %"I64_FMT", len=%"I64_FMT, pos, extra_data_len);
	if(extra_data_len>0) {
		de_dbg_indent(c, 1);

		if(md->objtype==ARJ_OBJTYPE_MAINHDR) {
			if(extra_data_len>=1) {
				b = de_getbyte_p(&pos);
				if(md->flags & 0x08) {
					de_dbg(c, "protection factor: %u", (UI)b);
				}
			}
			if(extra_data_len>=2) {
				b = de_getbyte_p(&pos);
				if(md->archiver_ver_num_adj>=MIN_VER_WITH_FLAGS2) {
					de_dbg(c, "flags (2nd set): 0x%02x", (UI)b);
				}
			}
		}
		else if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
			if(extra_data_len>=4) {
				n = de_getu32le_p(&pos);
				de_dbg(c, "ext. file pos: %"I64_FMT, n);
			}
			if(extra_data_len>=12) {
				read_arj_datetime(c, d, md, pos, &md->tmstamp[DE_TIMESTAMPIDX_ACCESS], "access");
				pos += 4;
				read_arj_datetime(c, d, md, pos, &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "create");
				pos += 4;
			}
			if(extra_data_len>=16) {
				n = de_getu32le_p(&pos);
				de_dbg(c, "ext. orig size: %"I64_FMT, n);
			}
		}

		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
	pos = first_hdr_endpos; // Now at the offset of the filename field
	nbytes_avail = basic_hdr_endpos - pos;
	de_dbg(c, "filename/comment area at %"I64_FMT", len=%"I64_FMT, pos, nbytes_avail);
	de_dbg_indent(c, 1);
	md->name_srd = dbuf_read_string(c->infile, pos, nbytes_avail, 256, DE_CONVFLAG_STOP_AT_NUL,
		md->input_encoding);
	if(!(md->flags & 0x10)) {
		// "PATHSYM" flag missing, need to convert '\' to '/'
		fixup_path(md->name_srd->str);
	}
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->name_srd->str));

	if(md->name_srd->found_nul) {
		pos += md->name_srd->bytes_consumed;
		nbytes_avail = basic_hdr_endpos - pos;
		handle_comment(c, d, md, pos, nbytes_avail);
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);
	pos = basic_hdr_endpos; // Now at the offset just after the 'comment' field
	basic_hdr_crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "basic hdr crc (reported): 0x%08x", (UI)basic_hdr_crc_reported);

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, pos1+4, basic_hdr_size);
	basic_hdr_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "basic hdr crc (calculated): 0x%08x", (UI)basic_hdr_crc_calc);
	if(basic_hdr_crc_calc != basic_hdr_crc_reported) {
		de_warn(c, "Header CRC check failed");
	}

	if(!do_extended_headers(c, d, md, pos, &bytes_consumed)) {
		de_err(c, "Bad extended headers - can't continue");
		goto done;
	}
	pos += bytes_consumed;

	md->is_dir = (md->file_type==ARJ_FILETYPE_DIR);

	md->cmpr_pos = pos;
	if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
		de_dbg(c, "compressed data at %"I64_FMT, md->cmpr_pos);
		de_dbg_indent(c, 1);
		extract_member_file(c, d, md);
		de_dbg_indent(c, -1);
	}
	pos += md->cmpr_len;

	*pbytes_consumed = pos - pos1;
	retval = 1;

done:
	ucstring_destroy(flags_descr);
	if(md) {
		de_destroy_stringreaderdata(c, md->name_srd);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_member_sequence(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 num_extra_bytes;

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos+2 > c->infile->len) goto done;

		ret = do_header_or_member(c, d, pos, 0, &bytes_consumed);
		if(ret==0 || bytes_consumed<2) goto done;
		pos += bytes_consumed;
		if(ret==2) { // End of archive
			break;
		}
	}

	if(d->security_envelope_len!=0 || d->arjprot_flag) {
		// (TODO?) This check is not implemented in these situations.
		num_extra_bytes = 0;
	}
	else {
		num_extra_bytes = c->infile->len - pos;
	}
	if(num_extra_bytes>1) {
		de_dbg(c, "[%"I64_FMT" extra bytes at EOF, starting at %"I64_FMT"]", num_extra_bytes, pos);
	}

done:
	;
}

static void do_security_envelope(deark *c, lctx *d)
{
	if(d->security_envelope_len==0) return;
	de_dbg(c, "security envelope at %"I64_FMT", len=%"I64_FMT, d->security_envelope_pos,
		d->security_envelope_len);
	de_dbg_indent(c, 1);
	de_dbg_hexdump(c, c->infile, d->security_envelope_pos, d->security_envelope_len,
		256, NULL, 0x0);
	de_dbg_indent(c, -1);
}

// Low-level options, needed by the relocator utility
struct options_struct {
	de_module_params *mparams;
	const char *reloc_opt;
	i64 archive_start;
};

// Tries to figure out if an ARJ archive starts at the given offset.
// It must start with the archive header.
// Note that this is not the algorithm specified in the ARJ TECHNOTE file.
// The function is used when we want to tolerate a bad header CRC.
static int is_arj_data_at(deark *c, i64 pos1)
{
	i64 pos;
	i64 basic_hdr_size, first_ext_hdr_size;
	UI hdr_id;

	pos = pos1+2;

	basic_hdr_size = de_getu16le_p(&pos);
	if(basic_hdr_size>ARJ_MAX_BASIC_HEADER_SIZE || basic_hdr_size<ARJ_MIN_BASIC_HEADER_SIZE) return 0;
	pos += basic_hdr_size + 4;
	first_ext_hdr_size = de_getu16le_p(&pos);
	if(first_ext_hdr_size!=0) pos += first_ext_hdr_size+4;

	// Should now be at the start of the 1st member file (after the archive header)
	hdr_id = (UI)de_getu16le(pos);
	if(hdr_id==0xea60) {
		return 1;
	}
	return 0;
}

static u8 is_exe_format(deark *c)
{
	u8 sig[2];

	de_read(sig, 0, 2);
	if((sig[0]=='M' && sig[1]=='Z') || (sig[0]=='Z' && sig[1]=='M')) {
		return 1;
	}
	return 0;
}

static i64 get_exe_overlay_pos(deark *c)
{
	struct fmtutil_exe_info ei;

	de_zeromem(&ei, sizeof(struct fmtutil_exe_info));
	// TODO: Should collect_exe_info do more validation of the format?
	fmtutil_collect_exe_info(c, c->infile, &ei);
	return ei.end_of_dos_code;
}

static void do_run_arj_relocator(deark *c, struct options_struct *arj_opts);

static void de_run_arj(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 bytes_consumed = 0;
	u8 archive_start_req_flag = 0;
	u8 used_scan = 0;
	i64 archive_start_req = 0;
	i64 exact_archive_start = 0;
	const char *s;
	u8 scan_opt; // 0 or 1, 0xff for unset
	int modcode_R = 0;
	struct options_struct *arj_opts = NULL;

	arj_opts = de_malloc(c, sizeof(struct options_struct));
	arj_opts->mparams = mparams;

	if(c->module_disposition==DE_MODDISP_INTERNAL) {
		modcode_R = de_havemodcode(c, mparams, 'R');
	}

	if(c->module_disposition!=DE_MODDISP_INTERNAL) {
		scan_opt = (u8)de_get_ext_option_bool(c, "arj:scan", 0xff);
	}
	else {
		scan_opt = 0xff;
	}

	// Starting point for the scan for the archive header
	// (or the exact header pos if scan=0).
	if(c->module_disposition!=DE_MODDISP_INTERNAL) {
		s = de_get_ext_option(c, "arj:entrypoint");
		if(s) {
			archive_start_req_flag = 1;
			archive_start_req = de_atoi64(s);
		}
	}

	// Try various things to find the start of the ARJ archive.
	// TODO?: This is unpleasantly complicated.

	if(archive_start_req_flag && scan_opt==0) {
		exact_archive_start = archive_start_req;
		goto after_archive_start_known;
	}

	if(modcode_R && mparams && mparams->in_params.obj1) {
		struct fmtutil_specialexe_detection_data *edd;

		edd = (struct fmtutil_specialexe_detection_data*)mparams->in_params.obj1;
		if(edd->payload_valid) {
			exact_archive_start = edd->payload_pos;
			goto after_archive_start_known;
		}
	}

	if(c->module_disposition==DE_MODDISP_AUTODETECT) {
		exact_archive_start = 0; // The "identify" routine only looks here
		goto after_archive_start_known;
	}

	if(scan_opt!=0) {
		int ret;
		i64 scan_startpos;
		u8 allow_bad_crc;

		if(archive_start_req_flag) {
			scan_startpos = archive_start_req;
			allow_bad_crc = 1;
		}
		else if(is_exe_format(c)) {
			scan_startpos = get_exe_overlay_pos(c);
			allow_bad_crc = 0;
		}
		else {
			scan_startpos = 0;
			allow_bad_crc = 1;
		}

		if(allow_bad_crc) {
			if(is_arj_data_at(c, scan_startpos)) {
				exact_archive_start = scan_startpos;
				goto after_archive_start_known;
			}
		}

		ret = fmtutil_scan_for_arj_data(c->infile, scan_startpos, c->infile->len-scan_startpos, 0,
			&exact_archive_start);
		if(ret) {
			if(exact_archive_start != archive_start_req) {
				used_scan = 1;
			}
			goto after_archive_start_known;
		}
	}

	exact_archive_start = 0; // Give up

after_archive_start_known:
	arj_opts->archive_start = exact_archive_start;

	if(dbuf_memcmp(c->infile, arj_opts->archive_start, g_arj_hdr_id, 2)) {
		if(!modcode_R) {
			de_err(c, "Not an ARJ file, or could not find ARJ data");
		}
		goto done;
	}

	if(used_scan) {
		de_dbg(c, "ARJ data found at %"I64_FMT, arj_opts->archive_start);
	}

	if(c->module_disposition!=DE_MODDISP_INTERNAL) {
		const char *s;

		s = de_get_ext_option(c, "arj:reloc");
		if(s) {
			arj_opts->reloc_opt = s;
			do_run_arj_relocator(c, arj_opts);
			goto done;
		}
	}

	if(modcode_R) {
		do_run_arj_relocator(c, arj_opts);
		goto done;
	}

	d = de_malloc(c, sizeof(lctx));

	d->archive_start = arj_opts->archive_start;

	de_declare_fmt(c, "ARJ");
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	pos = d->archive_start;
	if(do_header_or_member(c, d, pos, 1, &bytes_consumed) != 1) goto done;
	pos += bytes_consumed;
	if(d->is_secured) {
		do_security_envelope(c, d);
	}

	do_member_sequence(c, d, pos);

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
	de_free(c, arj_opts);
}

static int de_identify_arj(deark *c)
{
	i64 basic_hdr_size;

	if(dbuf_memcmp(c->infile, 0, g_arj_hdr_id, 2)) return 0;
	basic_hdr_size = de_getu16le(2);
	if(basic_hdr_size>ARJ_MAX_BASIC_HEADER_SIZE || basic_hdr_size<ARJ_MIN_BASIC_HEADER_SIZE) return 0;
	if(de_input_file_has_ext(c, "arj")) return 100;
	return 75;
}

static void de_help_arj(deark *c)
{
	de_msg(c, "-opt arj:entrypoint=<n> : Offset of archive header");
	de_msg(c, "-opt arj:scan=0 : Disable scanning for the ARJ data");
	de_msg(c, "-opt arj:reloc[=<n>] : Move the ARJ data");
}

void de_module_arj(deark *c, struct deark_module_info *mi)
{
	mi->id = "arj";
	mi->desc = "ARJ";
	mi->run_fn = de_run_arj;
	mi->identify_fn = de_identify_arj;
	mi->help_fn = de_help_arj;
}

/////////////////////// ARJ relocator utility
// This routine converts an ARJ file to one in which the ARJ data starts at
// beginning of the file, or optionally after some padding.
// This is useful for "extracting" a pure ARJ file from a self-extracting
// archive.
// It also disables any v2 "security envelope". If we didn't do that, the ARJ
// software would reject the modified file.

struct arjreloc_ctx {
	i64 src_startpos;
	dbuf *ahdr;
};

// Edit the archive header to disable any v2 security envelope.
// Writes to d->ahdr as many bytes as should be replaced in the ARJ file.
static int reloc_process_archive_hdr(deark *c, struct arjreloc_ctx *d)
{
	struct de_crcobj *crco = NULL;
	int retval = 0;
	i64 basic_hdr_size;
	UI hdr_id;
	i32 newcrc;
	u8 flags;
	u8 file_type;

	hdr_id = (UI)de_getu16le(d->src_startpos);
	if(hdr_id!=0xea60) goto done;
	basic_hdr_size = de_getu16le(d->src_startpos+2);
	if(basic_hdr_size>ARJ_MAX_BASIC_HEADER_SIZE || basic_hdr_size<ARJ_MIN_BASIC_HEADER_SIZE) goto done;

	flags = de_getbyte(d->src_startpos+8);
	file_type = de_getbyte(d->src_startpos+10);
	if(file_type!=ARJ_FILETYPE_MAINHDR) goto done;

	if(flags & 0x40) {
		de_info(c, "Note: Disabling ARJ security envelope");
		flags -= 0x40;
	}
	else if(flags & 0x08) {
		de_info(c, "Note: Disabling ARJ-PROTECT");
		flags -= 0x08;
	}
	else {
		// Not secured, or not a problematic type of security. Just copy everything.
		retval = 1;
		goto done;
	}

	// Copy, with changes as needed
	dbuf_copy(c->infile, d->src_startpos, 8, d->ahdr);

	// Alter some of the bytes
	dbuf_writebyte(d->ahdr, flags);
	dbuf_writebyte(d->ahdr, 0); // security version
	dbuf_copy(c->infile, d->src_startpos+10, 10, d->ahdr); // filetype...modtime
	dbuf_writeu32le(d->ahdr, 0); // archive size
	dbuf_writeu32le(d->ahdr, 0); // security envelope or ARJPROT pos
	dbuf_copy(c->infile, d->src_startpos+28, 2, d->ahdr); // filespec pos
	dbuf_writeu16le(d->ahdr, 0); // security envelope len
	// (now at file offset 32) Copy the rest of the basic header
	dbuf_copy(c->infile, d->src_startpos+32, (4+basic_hdr_size)-32, d->ahdr);

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(crco, d->ahdr, 4, basic_hdr_size);
	newcrc = de_crcobj_getval(crco);
	dbuf_writeu32le(d->ahdr, newcrc); // basic hdr crc

	// Note - This is not the end of the archive header, but anything after
	// this can remain unchanged.
	retval = 1;
done:
	de_crcobj_destroy(crco);
	return retval;
}

static void do_run_arj_relocator(deark *c, struct options_struct *arj_opts)
{
	dbuf *outf = NULL;
	i64 dst_startpos = 0;
	i64 archive_size;
	struct arjreloc_ctx *d = NULL;
	int ok = 0;

	de_dbg(c, "ARJ relocation mode");
	d = de_malloc(c, sizeof(struct arjreloc_ctx));

	if(arj_opts->reloc_opt) {
		dst_startpos = de_atoi64(arj_opts->reloc_opt);
	}
	if(dst_startpos<0) dst_startpos = 0;

	d->ahdr = dbuf_create_membuf(c, 0, 0);

	d->src_startpos = arj_opts->archive_start;
	archive_size = c->infile->len - d->src_startpos;
	if(archive_size<1) goto done;

	if(!reloc_process_archive_hdr(c, d)) goto done;

	de_dbg(c, "reloc from %"I64_FMT" to %"I64_FMT, d->src_startpos, dst_startpos);
	outf = dbuf_create_output_file(c, "arj", NULL, 0);
	dbuf_write_zeroes(outf, dst_startpos);

	// Copy the potentially-changed part of the file
	dbuf_copy(d->ahdr, 0, d->ahdr->len, outf);
	// Copy the definitely-unchanged part of the file
	dbuf_copy(c->infile, d->src_startpos+d->ahdr->len, archive_size-d->ahdr->len, outf);
	ok = 1;

done:
	if(ok) {
		if(arj_opts->mparams) {
			// Inform the caller of success
			arj_opts->mparams->out_params.flags |= 0x1;
		}
	}
	else {
		de_err(c, "Cannot relocate/extract this ARJ file");
	}
	dbuf_close(outf);
	if(d) {
		dbuf_close(d->ahdr);
		de_free(c, d);
	}
}
