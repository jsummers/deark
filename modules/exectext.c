// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// TXT2COM, etc.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_txt2com);
DE_DECLARE_MODULE(de_module_show_gmr);
DE_DECLARE_MODULE(de_module_asc2com);
DE_DECLARE_MODULE(de_module_doc2com);
DE_DECLARE_MODULE(de_module_makeread);
DE_DECLARE_MODULE(de_module_gtxt);
DE_DECLARE_MODULE(de_module_readmake);
DE_DECLARE_MODULE(de_module_texe);
DE_DECLARE_MODULE(de_module_readamatic);
DE_DECLARE_MODULE(de_module_ascom);
DE_DECLARE_MODULE(de_module_textlife);

// TODO: For some formats containing special codes (doc2com, asc2com),
// it might be useful to have a mode that converts the format (somehow),
// without translating the character encoding. Current, it's both or
// neither. (Well, gtxt already has such a mode.)

// Note: An option to convert to HTML would be cool, but seems like more
// trouble than it's worth.

enum et_proctype {
	ET_PROCTYPE_INVALID=0,
	ET_PROCTYPE_RAW,
	ET_PROCTYPE_FMTCONV_ONLY,
	ET_PROCTYPE_FMTCONV_AND_ENCCONV
};

struct ecnv_ctx {
	de_ucstring *tmpstr;
	dbuf *outf;
	deark *c;
	enum et_proctype proctype;
	int ext_enc;
	struct de_encconv_state es;
};

typedef struct localctx_exectext {
	void *userdata;
	de_encoding input_encoding;
	UI fmtcode;
	u8 opt_fmtconv; // Use proctype instead of this.
	u8 opt_encconv; // Use proctype instead of this.
	u8 errflag;
	u8 need_errmsg;
	u8 found_text;
	u8 is_encrypted;
	u8 allow_tlen_0;
	u8 supports_fmtconv; // Set if PROCTYPE_FMTCONV_ONLY is different from RAW
	enum et_proctype proctype;
	dbuf *inf; // This is a copy; do not free.
	i64 tpos;
	i64 tlen;
#define ETCT_PRINTABLE   0
#define ETCT_CONTROL     1
#define ETCT_SPECIAL     2 // untranslatable code
#define ETCT_8SPACES     100
#define ETCT_DOC2COMSPECIAL 101
#define ETCT_CRLF        102
	u8 chartypes[256];
} lctx;

static void exectext_set_common_enc_opts(deark *c, lctx *d, de_encoding dflt_enc)
{
	d->input_encoding = de_get_input_encoding(c, NULL, dflt_enc);
	d->opt_fmtconv = (u8)de_get_ext_option_bool(c, "text:fmtconv", 1);
	d->opt_encconv = (u8)de_get_ext_option_bool(c, "text:encconv", 1);
	if(d->input_encoding==DE_ENCODING_ASCII) {
		d->opt_encconv = 0;
	}
	if(d->opt_fmtconv) {
		if(d->opt_encconv) {
			d->proctype = ET_PROCTYPE_FMTCONV_AND_ENCCONV;
		}
		else {
			d->proctype = ET_PROCTYPE_FMTCONV_ONLY;
		}
	}
	else {
		d->proctype = ET_PROCTYPE_RAW;
	}

	if(!d->supports_fmtconv) {
		if(d->proctype==ET_PROCTYPE_FMTCONV_ONLY) {
			d->proctype = ET_PROCTYPE_RAW;
		}
	}
}

static void exectext_check_tpos(deark *c, lctx *d)
{
	if(d->tpos<0 || (d->tpos==0 && d->inf==c->infile) ||
		d->tlen<0 || (d->tlen==0 && !d->allow_tlen_0) ||
		(d->tpos+d->tlen > d->inf->len))
	{
		d->errflag = 1;
		d->need_errmsg = 1;
	}
}

static lctx *create_lctx(deark *c)
{
	lctx *d;

	d = de_malloc(c, sizeof(lctx));
	d->inf = c->infile;
	return d;
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_free(c, d);
}

static struct ecnv_ctx *ecnv_create(deark *c, enum et_proctype proctype,
	int ext_enc, dbuf *outf)
{
	struct ecnv_ctx *ecnv;

	ecnv = (struct ecnv_ctx*)de_malloc(c, sizeof(struct ecnv_ctx));
	ecnv->c = c;
	ecnv->tmpstr = ucstring_create(c);
	ecnv->outf = outf;
	ecnv->proctype = proctype;
	ecnv->ext_enc = ext_enc;
	de_encconv_init(&ecnv->es, ext_enc);
	return ecnv;
}

static void ecnv_destroy(deark *c, struct ecnv_ctx *ecnv)
{
	if(!ecnv) return;
	ucstring_destroy(ecnv->tmpstr);
	de_free(c, ecnv);
}

// Write everything we have to outf, but don't process or discard
// partially-decoded characters.
static void ecnv_soft_flush(struct ecnv_ctx *ecnv)
{
	if(ucstring_isnonempty(ecnv->tmpstr)) {
		ucstring_write_as_utf8(ecnv->c, ecnv->tmpstr, ecnv->outf, 0);
		ucstring_empty(ecnv->tmpstr);
	}
}

// Process any partially-decoded character, to reset the converter state.
static void ecnv_barrier(struct ecnv_ctx *ecnv)
{
	// TODO: This is inefficient. We ought to have a quick way to tell
	// if it's needed.
	ucstring_append_bytes_ex(ecnv->tmpstr, (const u8*)"", 0, 0, &ecnv->es);
}

static void ecnv_flush_if_needed(struct ecnv_ctx *ecnv)
{
	if(ecnv->tmpstr->len > 1000) {
		ecnv_soft_flush(ecnv);
	}
}

static void ecnv_add_byte(struct ecnv_ctx *ecnv, u8 b)
{
	if(ecnv->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
		ucstring_append_bytes_ex(ecnv->tmpstr, &b, 1, DE_CONVFLAG_PARTIAL_DATA, &ecnv->es);
		ecnv_flush_if_needed(ecnv);
	}
	else {
		dbuf_writebyte(ecnv->outf, b);
	}
}

static void ecnv_add_rune(struct ecnv_ctx *ecnv, de_rune n)
{
	if(ecnv->proctype!=ET_PROCTYPE_FMTCONV_AND_ENCCONV) return;
	ecnv_barrier(ecnv);
	ucstring_append_char(ecnv->tmpstr, n);
	ecnv_flush_if_needed(ecnv);
}

// Call at the end of data, or before writing to ecnv->outf in some other way.
static void ecnv_hard_flush(deark *c, struct ecnv_ctx *ecnv)
{
	if(ecnv->proctype!=ET_PROCTYPE_FMTCONV_AND_ENCCONV) return;
	ecnv_barrier(ecnv);
	ecnv_soft_flush(ecnv);
}

#if 0
static void exectext_extract_verbatim(deark *c, lctx *d)
{
	dbuf *outf = NULL;

	exectext_check_tpos(c, d);
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	dbuf_copy(d->inf, d->tpos, d->tlen, outf);

done:
	dbuf_close(outf);
}
#endif

// Processing of a byte depends on the flags in d->chartypes[].
static void exectext_convert_and_write_slice(deark *c, lctx *d,
	i64 pos1, i64 len, struct ecnv_ctx *ecnv)
{
	i64 pos = pos1;
	i64 endpos = pos1 + len;

	while(pos < endpos) {
		u8 x;
		u8 tmpbyte;
		u8 next_byte_is_same;
		int k;

		x = dbuf_getbyte_p(d->inf, &pos);
		switch(d->chartypes[x]) {

		case ETCT_CONTROL:
			if(ecnv->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
				ecnv_add_rune(ecnv, (de_rune)x);
			}
			else {
				ecnv_add_byte(ecnv, x);
			}
			break;
		case ETCT_SPECIAL:
			if(ecnv->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
				ecnv_add_rune(ecnv, 0xfffd);
			}
			break;
		case ETCT_8SPACES:
			for(k=0; k<8; k++) {
				ecnv_add_byte(ecnv, 0x20);
			}
			break;
		case ETCT_CRLF:
			if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
				ecnv_add_rune(ecnv, 0x0d);
				ecnv_add_rune(ecnv, 0x0a);
			}
			else {
				ecnv_add_byte(ecnv, 0x0d);
				ecnv_add_byte(ecnv, 0x0a);
			}
			break;
		case ETCT_DOC2COMSPECIAL:
			next_byte_is_same = 0;
			// Escaping is done by doubling the special character.
			// Peek ahead at the next byte:
			if(pos < endpos-1) {
				tmpbyte = dbuf_getbyte(d->inf, pos);
				if(tmpbyte==x) {
					next_byte_is_same = 1;
				}
			}
			if(next_byte_is_same) {
				ecnv_add_byte(ecnv, x);
				pos++; // Skip the extra byte we read
			}
			else {
				if(ecnv->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
					ecnv_add_rune(ecnv, 0xfffd);
				}
			}
			break;
		default:
			ecnv_add_byte(ecnv, x);
		}
	}
}

// Extract or convert in the typical way.
// - Uses d->inf, d->tpos, d->tlen.
// - Validates the source position
// - Respects d->input_encoding if relevant
// - Respects d->proctype and d->chartypes[]
static void exectext_extract_default(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	static struct ecnv_ctx *ecnv = NULL;

	if(d->errflag) goto done;
	exectext_check_tpos(c, d);
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	if(d->proctype!=ET_PROCTYPE_RAW) {
		dbuf_enable_wbuffer(outf);

		if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
			ecnv = ecnv_create(c, d->proctype, DE_EXTENC_MAKE(d->input_encoding,
				DE_ENCSUBTYPE_PRINTABLE), outf);
			if(c->write_bom) {
				dbuf_write_uchar_as_utf8(outf, 0xfeff);
			}
		}
		if(!ecnv) {
			ecnv = ecnv_create(c, d->proctype, DE_ENCODING_UNKNOWN, outf);
		}

		exectext_convert_and_write_slice(c, d, d->tpos, d->tlen, ecnv);
	}
	else {
		dbuf_copy(d->inf, d->tpos, d->tlen, outf);
	}

done:
	if(ecnv) {
		ecnv_hard_flush(c, ecnv);
		ecnv_destroy(c, ecnv);
	}
	dbuf_close(outf);
}

static void txt2com_read_textpos(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 pos_of_tlen;

	de_dbg(c, "pos of tlen pointer: %"I64_FMT, pos1);

	pos_of_tlen = de_getu16le_p(&pos) - 256;
	de_dbg(c, "pos of tlen: %"I64_FMT, pos_of_tlen);

	pos += 2;

	d->tpos = de_getu16le_p(&pos) - 256;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	d->tlen = de_getu16le(pos_of_tlen);
	de_dbg(c, "tlen: %"I64_FMT, d->tlen);
}

// For all TXT2COM versions, and TXT2RES v1.0.
static void txt2com_search1(deark *c, lctx *d)
{
#define TXT2COM_BUF_POS1 700
#define TXT2COM_BUF_LEN1 3000
	u8 *mem = NULL;
	i64 foundpos;
	int ret;

	mem = de_malloc(c, TXT2COM_BUF_LEN1);
	de_read(mem, TXT2COM_BUF_POS1, TXT2COM_BUF_LEN1);
	ret = de_memsearch_match(mem, TXT2COM_BUF_LEN1,
		(const u8*)"\x8b\xd8\xb4\x40\x8b\x0e??\x8d\x16??\xcd\x21\xb4\x3e", 16,
		'?', &foundpos);
	if(!ret) goto done;
	d->found_text = 1;
	txt2com_read_textpos(c, d, TXT2COM_BUF_POS1+foundpos+6);

done:
	de_free(c, mem);
}

// For:
// * TXT2RES v2.03 (= code variant 1)
// * TXT2RES v2.06 (= code variant 1)
// * TXT2RES v2.10 (= code variant 1)
// * TXT2PAS v2.03 (= code variant 2)
// * TXT2PAS v2.06 (= code variant 3)
// * TXT2PAS v2.10 (= code variant 3)
// The code variants have enough common bytes that we try to get away with
// only doing a single search.
static void txt2com_search2(deark *c, lctx *d)
{
#define TXT2COM_BUF_POS2 7500
#define TXT2COM_BUF_LEN2 4000
	u8 *mem = NULL;
	i64 foundpos;
	int ret;

	mem = de_malloc(c, TXT2COM_BUF_LEN2);
	de_read(mem, TXT2COM_BUF_POS2, TXT2COM_BUF_LEN2);
	ret = de_memsearch_match(mem, TXT2COM_BUF_LEN2,
		(const u8*)"\xcd?\xa1??\xd1\xe0\x03\x06??\x8d???\x03", 16,
		'?', &foundpos);
	if(!ret) goto done;
	d->found_text = 1;
	txt2com_read_textpos(c, d, TXT2COM_BUF_POS2+foundpos+9);

done:
	de_free(c, mem);
}

static void de_run_txt2com(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = create_lctx(c);
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;
	de_declare_fmt(c, "TXT2COM");

	txt2com_search1(c, d);
	if(!d->found_text) {
		txt2com_search2(c, d);
	}
	if(!d->found_text) {
		d->need_errmsg = 1;
		goto done;
	}
	if(d->errflag) goto done;

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a TXT2COM file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
}

static int de_identify_txt2com(deark *c)
{
	u8 b1;
	u8 flag = 0;
	u8 buf[28];
	const char *ids[3] = {"TXT2COM C", "TXT2RES C", "TXT2PAS C"};

	if(c->infile->len>65280) return 0;
	b1 = de_getbyte(0);
	if(b1!=0x8d && b1!=0xe8 && b1!=0xe9) return 0;
	de_read(buf, 0, sizeof(buf));
	if(b1==0x8d) {
		if(!de_memcmp(&buf[14], ids[0], 9)) flag = 1;
	}
	else if(b1==0xe8) {
		if(!de_memcmp(&buf[5], ids[0], 9)) flag = 1;
	}
	else if(b1==0xe9) {
		if(!de_memcmp(&buf[3], ids[0], 9)) flag = 1;
		else if(!de_memcmp(&buf[3], ids[1], 9)) flag = 1;
		else if(!de_memcmp(&buf[3], ids[2], 9)) flag = 1;
	}
	return flag ? 92 : 0;
}

static void print_conv_options_simple(deark *c)
{
	de_msg(c, "-opt text:fmtconv=0 : Do minimal processing, and don't convert to UTF-8");
	de_msg(c, "-opt text:encconv=0 : Same as text:fmtconv=0");
}

static void print_conv_options_adv(deark *c)
{
	de_msg(c, "-opt text:fmtconv=0 : Do minimal processing");
	de_msg(c, "-opt text:encconv=0 : Don't convert to UTF-8");
}

static void de_help_txt2com(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_txt2com(deark *c, struct deark_module_info *mi)
{
	mi->id = "txt2com";
	mi->desc = "TXT2COM (K. P. Graham)";
	mi->run_fn = de_run_txt2com;
	mi->identify_fn = de_identify_txt2com;
	mi->help_fn = de_help_txt2com;
}

///////////////////////////////////////////////////
// SHOW (Gary M. Raymond, Simple Software)

// Finding the text in a precise way seems difficult.
// Instead, we search for the byte pattern that appears right before the start
// of the text.
// The text *length* does not seem to be present in the file at all. The text
// just ends at the 0x1a byte that should be at the end of the file.
static void showgmr_search(deark *c, lctx *d)
{
#define SHOW_BUF_POS1 1800
#define SHOW_BUF_LEN1 1200
	u8 *mem = NULL;
	i64 foundpos;
	int ret;

	mem = de_malloc(c, SHOW_BUF_LEN1);
	de_read(mem, SHOW_BUF_POS1, SHOW_BUF_LEN1);

	// v2.0, 2.0A, 2.1(?)
	ret = de_memsearch_match(mem, SHOW_BUF_LEN1,
		(const u8*)"\x06?\x03\x19\xa1\x6c\x00\x3b\x06?\x03\x72\xf7\x58\x1f\xc3", 16,
		'?', &foundpos);
	if(ret) {
		d->found_text = 1;
		d->tpos = SHOW_BUF_POS1+foundpos+16;
		goto done;
	}

	// v1.0, 1.4, 1.5
	ret = de_memsearch_match(mem, SHOW_BUF_LEN1,
		(const u8*)"\x4e\x8a\x04\x3c\x0a\x75\xf9\x4d\x75\xf5\x46\x89\x36?\x02\xc3", 16,
		'?', &foundpos);
	if(ret) {
		d->found_text = 1;
		d->tpos = SHOW_BUF_POS1+foundpos+16;
		goto done;
	}

done:
	de_free(c, mem);
}

static void de_run_show_gmr(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = create_lctx(c);
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);
	de_declare_fmt(c, "SHOW (executable text)");
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	showgmr_search(c, d);
	if(!d->found_text) {
		d->need_errmsg = 1;
		goto done;
	}
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	d->tlen = c->infile->len - d->tpos;
	if(de_getbyte(c->infile->len-1) == 0x1a) {
		d->tlen--;
	}

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a SHOW file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
}

static int de_identify_show_gmr(deark *c)
{
	if(c->infile->len>65280) return 0;
	if(de_getbyte(0) != 0xe9) return 0;
	// Testing the last byte of the file may screen out corrupt files, but
	// more importantly screens out the SHOW.COM utility itself, which
	// annoyingly has the same the start-of-file signature as the files it
	// generates.
	if(de_getbyte(c->infile->len-1) != 0x1a) return 0;
	// Byte at offset 3 is 0x30 in pristine files, but it's used to save the
	// color scheme (it's a self-modifying COM file).
	if(dbuf_memcmp(c->infile, 4,
		(const u8*)"\x00\x1f\xa0\x00\x00\x53\x48\x4f\x57", 9))
	{
		return 0;
	}
	return 100;
}

static void de_help_show_gmr(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_show_gmr(deark *c, struct deark_module_info *mi)
{
	mi->id = "show_gmr";
	mi->desc = "SHOW (G. M. Raymond)";
	mi->run_fn = de_run_show_gmr;
	mi->identify_fn = de_identify_show_gmr;
	mi->help_fn = de_help_show_gmr;
}

///////////////////////////////////////////////////
// Asc2Com (MorganSoft)

struct asc2com_ctx {
	UI version;
	UI lister;
};

struct asc2com_detection_data {
	u8 found;
	u8 is_compressed;
	UI fmtcode;
	i64 tpos;
};

struct asc2com_idinfo {
	const u8 sig1[3];
	// flags&0x03: sig2 type  1=\x49\xe3..., 2="ASC2COM"
	// flags&0x40: need to validate txtpos pointer
	// flags&0x80: compressed
	u8 flags;
	u16 sig2pos;
	u16 txtpos;
	UI fmtcode;
};

// lister codes: 0=full/default, 1=page, 2=lite,
//  3=wide, 4=print, 5=compressed
static const struct asc2com_idinfo asc2com_idinfo_arr[] = {
	{ {0xe8,0xd2,0x00}, 0x01,  867,  1350, 0x11020000 }, // 1.10b
	{ {0xe8,0x25,0x01}, 0x01, 1283,  1819, 0x12510100 }, // 1.25 (?)
	{ {0xe8,0x25,0x01}, 0x01, 1288,  1840, 0x12510200 }, // 1.25 (?)
	{ {0xe8,0x1d,0x01}, 0x01, 1360,  1877, 0x13010000 }, // 1.30
	{ {0xe9,0x18,0x05}, 0x01, 2827,  3734, 0x16510100 }, // 1.65 full (?)
	{ {0xe9,0x18,0x05}, 0x01, 2834,  3750, 0x16610000 }, // 1.66 full
	{ {0xe9,0x1d,0x05}, 0x01, 2916,  4050, 0x17510000 }, // 1.75 full
	{ {0xe9,0x18,0x05}, 0x01, 2911,  4051, 0x17610000 }, // 1.76 full
	{ {0xe9,0x12,0x06}, 0x01, 3203,  4517, 0x20010000 }, // 2.00 full
	{ {0xe9,0x21,0x06}, 0x01, 3231,  4533, 0x20060000 }, // 2.00f-2.05 full

	{ {0xe8,0x06,0x01}, 0x01, 1337,  1854, 0x13010001 }, // 1.30 page
	{ {0xe9,0xc4,0x04}, 0x01, 2725,  3638, 0x16510101 }, // 1.65 page (?)
	{ {0xe9,0xc4,0x04}, 0x01, 2732,  3638, 0x16610001 }, // 1.66 page
	{ {0xe9,0xc9,0x04}, 0x41, 2814,  3938, 0x17510001 }, // 1.75 page
	{ {0xe9,0xc9,0x04}, 0x41, 2814,  3955, 0x17610001 }, // 1.76 page
	{ {0xe9,0x12,0x06}, 0x01, 3185,  4485, 0x20010001 }, // 2.00 page
	{ {0xe9,0x21,0x06}, 0x01, 3213,  4517, 0x20060001 }, // 2.00f-2.05 page

	{ {0xe9,0x7e,0x01}, 0x01, 1523,  1555, 0x16510102 }, // 1.65 lite (?)
	{ {0xe9,0x81,0x01}, 0x01, 1526,  1558, 0x16610002 }, // 1.66 lite
	{ {0xe9,0x8f,0x01}, 0x01, 1722,  1799, 0x17510002 }, // 1.75-1.76 lite
	{ {0xe9,0xfc,0x01}, 0x01, 1868,  2005, 0x20010002 }, // 2.00-2.05 lite

	{ {0xe9,0x8c,0x01}, 0x01, 1747,  1816, 0x16610003 }, // 1.66 wide
	{ {0xe9,0xf5,0x01}, 0x01, 2045,  2161, 0x17510003 }, // 1.75-1.76 wide
	{ {0xe9,0x4d,0x02}, 0x01, 2165,  2341, 0x20010003 }, // 2.00-2.05 wide

	{ {0xbb,0x01,0x00}, 0x02,  240,   382, 0x13010004 }, // 1.30 print
	{ {0xeb,0x03,0x00}, 0x02,  245,   387, 0x16610004 }, // 1.66 print
	{ {0xeb,0x2b,0x00}, 0x02,  295,   437, 0x17510004 }, // 1.75-1.76 print
	{ {0xeb,0x40,0x00}, 0x02,  462,   613, 0x20010004 }, // 2.00-2.05 print

	{ {0xe9,0xaa,0x05}, 0x82, 1078, 10263, 0x20010005 }, // 2.00 compr
	{ {0xe9,0xab,0x05}, 0x82, 1078, 10263, 0x20060005 }, // 2.00f compr
	{ {0xe9,0xad,0x05}, 0x82, 1065, 10407, 0x20110005 }, // 2.01 compr
	{ {0xe9,0xa8,0x05}, 0x82, 1065, 10391, 0x20510005 }  // 2.05 compr
};

static void asc2com_identify(deark *c, struct asc2com_detection_data *idd, UI idmode)
{
	u8 buf[3];
	size_t k;
	const struct asc2com_idinfo *found_item = NULL;

	dbuf_read(c->infile, buf, 0, 3);
	if(buf[0]!=0xe8 && buf[0]!=0xe9 && buf[0]!=0xbb && buf[0]!=0xeb) return;

	for(k=0; k<DE_ARRAYCOUNT(asc2com_idinfo_arr); k++) {
		const struct asc2com_idinfo *t;
		u8 sig_type;

		t = &asc2com_idinfo_arr[k];

		if(buf[0]==t->sig1[0] && buf[1]==t->sig1[1] &&
			(t->sig1[0]==0xeb || (buf[2]==t->sig1[2])))
		{

			sig_type = t->flags & 0x03;
			if(sig_type==1) {
				if(!dbuf_memcmp(c->infile, (i64)t->sig2pos,
					(const void*)"\x49\xe3\x0e\x33\xd2\x8a\x14\xfe\xc2\x03\xf2\x49", 12))
				{
					if(t->flags & 0x40) {
						i64 tmptxtpos;

						tmptxtpos = de_getu16le((i64)t->sig2pos-2) - 0x100;
						if(tmptxtpos == t->txtpos) {
							found_item = t;
						}
					}
					else {
						found_item = t;
					}
				}
			}
			else if(sig_type==2) {
				if(!dbuf_memcmp(c->infile, (i64)t->sig2pos,
					(const void*)"ASC2COM", 7))
				{
					found_item = t;
				}
			}
		}

		if(found_item) {
			break;
		}
	}
	if(!found_item) return;
	idd->found = 1;
	if(idmode) return;

	idd->tpos = (i64)found_item->txtpos;
	idd->fmtcode = found_item->fmtcode;
	if(found_item->flags & 0x80) {
		idd->is_compressed = 1;
	}
}

// Lines stored in the file are prefixed with a byte giving their length.
// This function converts to plain text and writes to outf.
// Reads from d->inf.
static void asc2com_filter_and_write(deark *c, lctx *d,
	i64 ipos1, i64 endpos, dbuf *outf)
{
	i64 ipos;
	u8 n;
	static struct ecnv_ctx *ecnv = NULL;

	if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
		ecnv = ecnv_create(c, d->proctype, DE_EXTENC_MAKE(d->input_encoding,
			DE_ENCSUBTYPE_PRINTABLE), outf);

		if(c->write_bom) {
			dbuf_write_uchar_as_utf8(outf, 0xfeff);
		}
	}

	if(!ecnv) {
		// This object won't necessarily be used, but that's ok.
		ecnv = ecnv_create(c, d->proctype, DE_ENCODING_UNKNOWN, outf);
	}

	ipos = ipos1;
	while(ipos < endpos) {
		n = dbuf_getbyte_p(d->inf, &ipos);
		if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
			exectext_convert_and_write_slice(c, d, ipos, (i64)n, ecnv);
			ecnv_add_rune(ecnv, 13);
			ecnv_add_rune(ecnv, 10);
		}
		else if(d->proctype==ET_PROCTYPE_FMTCONV_ONLY) {
			exectext_convert_and_write_slice(c, d, ipos, (i64)n, ecnv);
			ecnv_add_byte(ecnv, 13);
			ecnv_add_byte(ecnv, 10);
		}
		else { // ET_PROCTYPE_RAW
			dbuf_copy(d->inf, ipos, (i64)n, outf);
			dbuf_write(outf, (const u8*)"\x0d\x0a", 2);
		}
		ipos += (i64)n;
	}

	if(ecnv) {
		ecnv_hard_flush(c, ecnv);
		ecnv_destroy(c, ecnv);
	}
}

static void asc2com_extract_compressed(deark *c, lctx *d)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lzw_params delzwp;
	dbuf *tmpf = NULL;
	dbuf *outf = NULL;

	tmpf = dbuf_create_membuf(c, 0, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = d->tpos;
	dcmpri.len = d->tlen;
	dcmpro.f = tmpf;
	dcmpro.len_known = 0;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ASC2COM;
	fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);
	dbuf_flush(tmpf);

	if(tmpf->len>0) {
		outf = dbuf_create_output_file(c, "txt", NULL, 0);
		dbuf_enable_wbuffer(outf);
		d->inf = tmpf;
		asc2com_filter_and_write(c, d, 0, tmpf->len, outf);
	}

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

done:
	dbuf_close(tmpf);
	dbuf_close(outf);
}

static void asc2com_extract_uncompressed(deark *c, lctx *d)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	dbuf_enable_wbuffer(outf);
	asc2com_filter_and_write(c, d, d->tpos, d->tpos+d->tlen, outf);
	dbuf_close(outf);
}

static void asc2com_find_special_chars(deark *c, lctx *d,
	struct asc2com_detection_data *idd)
{
	u8 sctype = 0;
	i64 pos;
	u8 b;
	struct asc2com_ctx *a2cc = (struct asc2com_ctx*)d->userdata;
	de_ucstring *tmpstr = NULL;

	if(a2cc->lister==4) {
		// The 'print' lister doesn't do special chars.
		// TODO: Investigate how tabs and other control chars are handled.
		d->chartypes[9] = ETCT_CONTROL;
		goto done;
	}

	if(a2cc->version<0x165) goto done;

	// Tabs. (Sigh.)
	// Before v1.75, they're just graphics characters.
	// v1.75-1.76 attempts to rewrite files so that tabs in the COM file must
	// be printed as a full 8 spaces. (The rewrite step is buggy, but that's
	// not our problem.)
	// v2.00-2.05 just seems to always interpret tabs as 8 spaces.
	if(a2cc->version>=0x175) {
		d->chartypes[9] = ETCT_8SPACES;
	}

	if(a2cc->version>=0x165 && a2cc->version<=0x166) {
		sctype = 1;
	}
	else if(a2cc->version>=0x175 && a2cc->version<=0x176) {
		sctype = 2;
	}
	else if(a2cc->version>=0x200 && a2cc->version<=0x205) {
		sctype = 3;
	}

	if(sctype==0) goto done;

	tmpstr = ucstring_create(c);

	// "TagLine" feature.
	// In v1.75+, these codes are quasi-configurable, but for our purposes
	// they're not. They always get changed to 0x00 and 0xff in the document
	// itself.
	d->chartypes[0x00] = ETCT_SPECIAL;
	d->chartypes[0xff] = ETCT_SPECIAL;
	ucstring_append_sz(tmpstr, " 00 ff", DE_ENCODING_LATIN1);

	if(sctype==2) {
		// Three codes are configurable, and are stored in the COM file outside
		// the document.
		for(pos=8; pos<=12; pos+=2) {
			b = de_getbyte(pos);
			d->chartypes[(UI)b] = ETCT_SPECIAL;
			ucstring_printf(tmpstr, DE_ENCODING_LATIN1, " %02x", (UI)b);
		}
	}
	else if(sctype==3) {
		// (The original TagLine codes are stored in the file, at offset 78-79.
		// We don't use them for anything. I guess that, if we're not translating
		// to UTF-8, they could be used to help construct something a little
		// closer to the original source document.)

		// Four configurable codes:
		for(pos=80; pos<=83; pos++) {
			b = de_getbyte(pos);
			d->chartypes[(UI)b] = ETCT_SPECIAL;
			ucstring_printf(tmpstr, DE_ENCODING_LATIN1, " %02x", (UI)b);
		}
	}

done:
	if(ucstring_isnonempty(tmpstr)) {
		de_dbg(c, "special chars:%s", ucstring_getpsz(tmpstr));
	}
	ucstring_destroy(tmpstr);
}

static void de_run_asc2com(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct asc2com_ctx *a2cc = NULL;
	struct asc2com_detection_data idd;

	a2cc = de_malloc(c, sizeof(struct asc2com_ctx));

	de_zeromem(&idd, sizeof(struct asc2com_detection_data));
	asc2com_identify(c, &idd, 0);
	if(!idd.found) {
		de_err(c, "Not a known Asc2Com format");
		goto done;
	}
	de_dbg(c, "format code: 0x%08x", idd.fmtcode);
	de_dbg(c, "compressed: %u", (UI)idd.is_compressed);
	a2cc->version = (idd.fmtcode >> 20) & 0xfff;
	a2cc->lister = idd.fmtcode & 0xf;

	d = create_lctx(c);
	d->userdata = (void*)a2cc;

	d->supports_fmtconv = 1;
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	asc2com_find_special_chars(c, d, &idd);

	d->tpos = idd.tpos;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);
	d->tlen = c->infile->len - d->tpos;

	// TODO: Can we read and use the original filename?
	if(idd.is_compressed) {
		asc2com_extract_compressed(c, d);
	}
	else {
		asc2com_extract_uncompressed(c, d);
	}

done:
	destroy_lctx(c, d);
	de_free(c, a2cc);
}

static int de_identify_asc2com(deark *c)
{
	struct asc2com_detection_data idd;

	if(c->infile->len>65280) return 0;
	de_zeromem(&idd, sizeof(struct asc2com_detection_data));
	asc2com_identify(c, &idd, 1);
	if(idd.found) return 72;
	return 0;
}

static void de_help_asc2com(deark *c)
{
	print_conv_options_adv(c);
}

void de_module_asc2com(deark *c, struct deark_module_info *mi)
{
	mi->id = "asc2com";
	mi->desc = "Asc2Com executable text";
	mi->run_fn = de_run_asc2com;
	mi->identify_fn = de_identify_asc2com;
	mi->help_fn = de_help_asc2com;
}

///////////////////////////////////////////////////
// DOC2COM (Gerald DePyper)

struct doc2com_detection_data {
	u8 found;
	UI fmtcode;
};

static void doc2com_detect(deark *c, struct doc2com_detection_data *idd, UI idmode)
{
	u8 buf[22];

	dbuf_read(c->infile, buf, 0, sizeof(buf));

	if(buf[0]==0xbe && buf[15]==0x72) {
		if(!de_memcmp(&buf[3], (const void*)"\xb9\x18\x00\xe8\xb2\x01\xe2\xfb\x3b\x36", 10)) {
			idd->fmtcode = 10; // old unversioned releases
			idd->found = 1;
		}
	}
	else if(buf[0]==0xfc && buf[1]==0xbe && buf[16]==0x72) {
		if(!de_memcmp(&buf[4], (const void*)"\xb9\x18\x00\xe8\x2f\x02\xe2\xfb\x3b\x36", 10)) {
			idd->fmtcode = 20; // v1.2
			idd->found = 1;
		}
	}
	else if(buf[0]==0xfc && buf[5]==0x49) {
		// Expecting all v1.3+ files to start with:
		//  fc ?? ?? ?? ?? 49 8b 36 ?? ?? 8b fe ac 32 04 aa e2 fa ac 34 ff aa ...
		// First 3 bytes:
		//  fc 8b 0e if encrypted
		//  fc eb 13 if not encrypted
		if(!de_memcmp(&buf[10],
			(const void*)"\x8b\xfe\xac\x32\x04\xaa\xe2\xfa\xac\x34\xff\xaa", 12))
		{
			idd->fmtcode = 30; // v1.3+
			idd->found = 1;
		}
	}
}

static void doc2com_analyze(deark *c, lctx *d)
{
	i64 pos_a, pos_b, pos_c, pos_d;
	i64 pos_of_tpos;
	i64 pos_of_tlen;
	i64 pos_of_endpos;
	i64 endpos;

	if(d->fmtcode==30) {
		if(de_getbyte(1) != 0xeb) {
			d->is_encrypted = 1;
		}
	}

	if(d->fmtcode==10) {
		pos_of_tpos = 1;
	}
	else if(d->fmtcode==20) {
		pos_of_tpos = 2;
	}
	else if(d->fmtcode==30) {
		pos_d = de_getu16le(8);
		pos_of_tpos = pos_d - 0x100;
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "pos of tpos: %"I64_FMT, pos_of_tpos);
	pos_a = de_getu16le(pos_of_tpos);
	d->tpos = pos_a - 0x100;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	if(d->fmtcode==10 || d->fmtcode==20) {
		if(d->fmtcode==20) {
			pos_b = de_getu16le(25);
		}
		else { // 10
			pos_b = de_getu16le(24);
		}
		pos_of_endpos = pos_b - 0x100;
		de_dbg(c, "pos of endpos: %"I64_FMT, pos_of_endpos);
		pos_c = de_getu16le(pos_of_endpos);
		endpos = pos_c - 0x100;
		de_dbg(c, "endpos: %"I64_FMT, endpos);
		d->tlen = endpos - d->tpos;
	}
	else { // 30
		pos_b = de_getu16le(3);
		pos_of_tlen = pos_b - 0x100;
		de_dbg(c, "pos of tlen: %"I64_FMT, pos_of_tlen);
		d->tlen = de_getu16le(pos_of_tlen);
	}

	de_dbg(c, "tlen: %"I64_FMT, d->tlen);
	de_dbg(c, "encrypted: %u", (UI)d->is_encrypted);
done:
	;
}

static void doc2com_output(deark *c, lctx *d)
{
	dbuf *tmpdbuf = NULL;

	exectext_check_tpos(c, d);
	if(d->errflag) goto done;

	if(d->is_encrypted) {
		u8 this_byte = 0;
		u8 next_byte = 0;
		u8 init_flag = 0;
		i64 i;

		tmpdbuf = dbuf_create_membuf(c, d->tlen, 0);
		dbuf_enable_wbuffer(tmpdbuf);

		for(i=0; i<d->tlen; i++) {
			u8 b;

			if(init_flag) {
				this_byte = next_byte;
			}
			else {
				this_byte = de_getbyte(d->tpos+i);
				init_flag = 1;
			}

			if(i+1 < d->tlen) {
				next_byte = de_getbyte(d->tpos+i+1);
			}
			else {
				next_byte = 0xff;
			}

			b = this_byte ^ next_byte;
			dbuf_writebyte(tmpdbuf, b);
		}

		dbuf_flush(tmpdbuf);
		d->inf = tmpdbuf;
		d->tpos = 0;
	}

	// Notes:
	//
	// - By default, DOC2COM doesn't support most control characters and
	// extended ASCII characters. It just displays them as spaces.
	// But with the /e option, it supports these characters the way that
	// most programs do.
	// Any undisplayed characters are still in the COM file. While we could
	// detect the non-use of /e, and do something differently, I think it's
	// best to behave as if /e were always used.
	//
	// - V1.3+ has the ability to define arbitrary characters to be special
	// codes that change the colors. A color-change code is just a single
	// character like "^". Doubling a code (e.g. "^^") escapes it. If we're
	// translating to UTF-8, we replace these codes with the Unicode
	// replacement char.

	exectext_extract_default(c, d);

done:
	dbuf_close(tmpdbuf);
}

static void doc2com_find_special_codes(deark *c, lctx *d)
{
	i64 foundpos;
	int ret;
	i64 count;
	i64 i;
	i64 pos;
	de_ucstring *tmpstr = NULL;

	ret = dbuf_search(c->infile, (const u8*)"\x74\xda\xeb\xf3", 4,
		633, 5, &foundpos);
	if(!ret) goto done;
	pos = foundpos+4;
	de_dbg(c, "pos of special chars: %"I64_FMT, pos);

	count = (i64)de_getbyte_p(&pos);
	de_dbg(c, "num special chars: %"I64_FMT, count);
	if(count<1 || count>16) goto done;
	tmpstr = ucstring_create(c);
	for(i=0; i<count; i++) {
		i64 b;
		b = de_getbyte_p(&pos);
		d->chartypes[(UI)b] = ETCT_DOC2COMSPECIAL;
		ucstring_printf(tmpstr, DE_ENCODING_LATIN1, " %02x", (UI)b);
	}

done:
	if(ucstring_isnonempty(tmpstr)) {
		de_dbg(c, "special chars:%s", ucstring_getpsz(tmpstr));
	}
	ucstring_destroy(tmpstr);
}

static void de_run_doc2com(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct doc2com_detection_data idd;

	d = create_lctx(c);
	d->supports_fmtconv = 1;
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	de_zeromem(&idd, sizeof(struct doc2com_detection_data));
	doc2com_detect(c, &idd, 0);
	if(!idd.found) {
		d->need_errmsg = 1;
		goto done;
	}
	d->fmtcode = idd.fmtcode;
	de_dbg(c, "fmt code: %u", d->fmtcode);
	doc2com_analyze(c, d);

	d->allow_tlen_0 = 1;
	d->chartypes[9] = ETCT_CONTROL;
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[12] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	doc2com_find_special_codes(c, d);

	if(d->errflag) goto done;
	doc2com_output(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a DOC2COM file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
}

static int de_identify_doc2com(deark *c)
{
	struct doc2com_detection_data idd;
	u8 b;

	if(c->infile->len>65280) return 0;
	b = de_getbyte(0);
	if(b!=0xbe && b!=0xfc) return 0;

	de_zeromem(&idd, sizeof(struct doc2com_detection_data));
	doc2com_detect(c, &idd, 1);
	if(idd.found) return 73;
	return 0;
}

static void de_help_doc2com(deark *c)
{
	print_conv_options_adv(c);
}

void de_module_doc2com(deark *c, struct deark_module_info *mi)
{
	mi->id = "doc2com";
	mi->desc = "DOC2COM executable text (G. DePyper)";
	mi->run_fn = de_run_doc2com;
	mi->identify_fn = de_identify_doc2com;
	mi->help_fn = de_help_doc2com;
}

///////////////////////////////////////////////////
// MAKEREAD (R. Gans)

static void de_run_makeread(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos_of_tpos = 0;
	i64 pos_of_tlen = 0;
	UI n;
	UI b1, b2;

	d = create_lctx(c);
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);
	d->chartypes[7] = ETCT_CONTROL;
	d->chartypes[8] = ETCT_CONTROL;
	d->chartypes[9] = ETCT_CONTROL;
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;
	d->chartypes[27] = ETCT_CONTROL;

	n = (UI)de_getu16le(1);
	if(n==0x0093) {
		d->fmtcode = 1; // v1.4-1.5
		pos_of_tpos = 171;
		pos_of_tlen = 178;
	}
	else if(n==0x0107) {
		d->fmtcode = 2; // v1.8
		pos_of_tpos = 293;
		pos_of_tlen = 300;
	}
	else if(n==0x10c) {
		d->fmtcode = 3; // v1.8a
		pos_of_tpos = 298;
		pos_of_tlen = 305;
	}

	if(d->fmtcode==0) goto done;
	if(de_getbyte(pos_of_tpos-1)!=0xbf) goto done;
	de_dbg(c, "fmt code: %u", d->fmtcode);
	d->tpos = de_getu16le(pos_of_tpos);
	d->tpos -= 0x100;
	if(d->fmtcode==2 || d->fmtcode==3) d->tpos--;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	b1 = de_getbyte(pos_of_tlen);
	b2 = de_getbyte(pos_of_tlen+2);
	d->tlen = ((UI)b1<<8) | b2;
	de_dbg(c, "tlen: %"I64_FMT, d->tlen);

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a MAKEREAD file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
}

static int de_identify_makeread(deark *c)
{
	UI n;
	i64 pos;

	if(c->infile->len>65280) return 0;
	n = (UI)de_getu32be(0);
	if(n==0xe9930000U) {
		pos = 27;
	}
	else if(n==0xe9070100U) {
		pos = 19;
	}
	else if(n==0xe90c0100U) {
		if(!dbuf_memcmp(c->infile, 19, (const void*)"< H=Home", 8)) {
			return 89;
		}
		return 0;
	}
	else {
		return 0;
	}

	if(dbuf_memcmp(c->infile, pos, (const void*)"Press  Home  P", 14)) {
		return 0;
	}
	return 89;
}

static void de_help_makeread(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_makeread(deark *c, struct deark_module_info *mi)
{
	mi->id = "makeread";
	mi->id_alias[0] = "doc2com_dkn";
	mi->desc = "MAKEREAD executable text (R. Gans)";
	mi->run_fn = de_run_makeread;
	mi->identify_fn = de_identify_makeread;
	mi->help_fn = de_help_makeread;
}

///////////////////////////////////////////////////
// GTXT / MakeScroll (Eric Gans)

// TODO? Consider integrating this into exectext_convert_and_write_slice.
// But it's different enough that it might not be worth it.
static void gtxt_convert_to_text(deark *c, lctx *d, dbuf *outf)
{
	struct ecnv_ctx *ecnv = NULL;
	u8 esc_mode = 0;
	u8 cur_mask;
	i64 endpos = d->tpos + d->tlen;
	i64 pos;

	if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
		ecnv = ecnv_create(c, d->proctype, DE_EXTENC_MAKE(d->input_encoding,
			DE_ENCSUBTYPE_PRINTABLE), outf);
		if(c->write_bom) {
			dbuf_write_uchar_as_utf8(outf, 0xfeff);
		}
	}
	if(!ecnv) {
		ecnv = ecnv_create(c, d->proctype, DE_ENCODING_UNKNOWN, outf);
	}

	pos = d->tpos;
	cur_mask = 0x7f;

	while(pos < endpos) {
		u8 x_raw, x_mod;
		u8 was_escaped = 0;
		de_rune u;

		x_raw = de_getbyte_p(&pos);
		if(x_raw==0x00) goto done;

		x_mod = x_raw & cur_mask;
		cur_mask = 0x7f; // We used the mask, now reset it to the default

		was_escaped = esc_mode;
		esc_mode = 0; // Reset to default

		// GTXT applies the mask *before* special characters are checked for.
		if(!was_escaped && (x_mod=='%')) {
			esc_mode = 1;
			cur_mask = 0xff;
		}
		else if(!was_escaped && (x_mod=='^')) {
			esc_mode = 1;
			cur_mask = 0x3f;
		}
		else if(!was_escaped && (x_mod=='~')) {
			if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
				u = 0x240c; // Page break -> SYMBOL FOR FORM FEED, I guess.
				ecnv_add_rune(ecnv, 0x0d);
				ecnv_add_rune(ecnv, 0x0a);
				ecnv_add_rune(ecnv, u);
			}
			else {
				ecnv_add_byte(ecnv, 0x0d);
				ecnv_add_byte(ecnv, 0x0a);
				ecnv_add_byte(ecnv, 0x0c); // Page break -> form feed, I guess.
			}
		}
		else {
			// Process literal byte x_mod
			if(d->proctype==ET_PROCTYPE_FMTCONV_AND_ENCCONV) {
				if(d->chartypes[(UI)x_mod]==ETCT_CONTROL) {
					u = (de_rune)x_mod;
					ecnv_add_rune(ecnv, u);
				}
				else {
					ecnv_add_byte(ecnv, x_mod);
				}
			}
			else {
				ecnv_add_byte(ecnv, x_mod);
			}
		}
	}

done:
	if(ecnv) {
		ecnv_hard_flush(c, ecnv);
		ecnv_destroy(c, ecnv);
	}
}

static void de_run_gtxt(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 endpos;
	UI b1, b2;
	dbuf *outf = NULL;

	d = create_lctx(c);
	d->supports_fmtconv = 1;
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	d->chartypes[7] = ETCT_CONTROL;
	d->chartypes[8] = ETCT_CONTROL;
	d->chartypes[9] = ETCT_CONTROL;
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;
	d->chartypes[27] = ETCT_CONTROL;

	d->tpos = 188;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	endpos = c->infile->len;
	b1 = de_getbyte(endpos-2);
	b2 = de_getbyte(endpos-1);

	if(b1==0) {
		endpos -= 2;
	}
	else if(b2==0) {
		endpos -= 1;
	}

	d->tlen = endpos - d->tpos;
	de_dbg(c, "tlen: %"I64_FMT, d->tlen);
	exectext_check_tpos(c, d);
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	dbuf_enable_wbuffer(outf);

	if(d->proctype==ET_PROCTYPE_RAW) {
		dbuf_copy(c->infile, d->tpos, d->tlen, outf);
	}
	else {
		gtxt_convert_to_text(c, d, outf);
	}

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a GTXT file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
	dbuf_close(outf);
}

static int de_identify_gtxt(deark *c)
{
	if(c->infile->len>65280) return 0;
	if(de_getbyte(0) != 0xbb) return 0;

	if(dbuf_memcmp(c->infile, 1, (const void*)"\xbc\x01\xb4\x02\xb1\x00\x8a", 7)) {
		return 0;
	}
	if(dbuf_memcmp(c->infile, 95, (const void*)"\x73\x01\xc3\x2c\x40\xc3\xcd\x20", 8)) {
		return 0;
	}
	return 100;
}

static void de_help_gtxt(deark *c)
{
	print_conv_options_adv(c);
}

void de_module_gtxt(deark *c, struct deark_module_info *mi)
{
	mi->id = "gtxt";
	mi->desc = "GTXT (E. Gans)";
	mi->run_fn = de_run_gtxt;
	mi->identify_fn = de_identify_gtxt;
	mi->help_fn = de_help_gtxt;
}

///////////////////////////////////////////////////
// READMAKE (by Bruce Guthrie and Wayne Software)

struct readmake_ctx {
	const char *msgpfx;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
};

// On apparent success, sets d->tpos to nonzero.
static void readmake_find_text(deark *c, struct readmake_ctx *rmctx, lctx *d)
{
	i64 pos;
	i64 n;

	pos = rmctx->ei->end_of_dos_code;
	n = de_getu32le(pos);
	pos += n;

	n = de_getu32le(pos);
	if(n==4) {
		// Later files have an extra field (expected value 4) or segment
		// (expected length 4). The segment after that is expected to
		// be larger. We use that to tell the difference.
		pos += 4;
		n = de_getu32le(pos);
	}
	else if(n<14) {
		d->need_errmsg = 1;
		goto done;
	}

	pos += n;
	d->tpos = pos;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	// TODO?: There might be a better way to figure out the length, but for
	// pristine files we can use the end of file.
	d->tlen = c->infile->len - d->tpos;

done:
	;
}

static void de_run_readmake(deark *c, de_module_params *mparams)
{
	struct readmake_ctx *rmctx = NULL;
	lctx *d = NULL;

	d = create_lctx(c);

	rmctx = de_malloc(c, sizeof(struct readmake_ctx));
	rmctx->msgpfx = "[READMAKE] ";
	rmctx->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	d->allow_tlen_0 = 1;
	d->chartypes[8] = ETCT_CONTROL;
	d->chartypes[9] = ETCT_CONTROL;
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	fmtutil_collect_exe_info(c, c->infile, rmctx->ei);

	rmctx->edd.restrict_to_fmt = DE_SPECIALEXEFMT_READMAKE;
	fmtutil_detect_specialexe(c, rmctx->ei, &rmctx->edd);
	if(rmctx->edd.detected_fmt!=DE_SPECIALEXEFMT_READMAKE) {
		d->need_errmsg = 1;
		goto done;
	}

	readmake_find_text(c, rmctx, d);
	if(d->tpos==0 || d->errflag) goto done;

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg && rmctx) {
			de_err(c, "%sBad or unsupported READMAKE file", rmctx->msgpfx);
		}
		de_free(c, d);
		d = NULL;
	}
	if(rmctx) {
		de_free(c, rmctx->ei);
		de_free(c, rmctx);
		rmctx = NULL;
	}
}

static void de_help_readmake(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_readmake(deark *c, struct deark_module_info *mi)
{
	mi->id = "readmake";
	mi->desc = "READMAKE executable text";
	mi->run_fn = de_run_readmake;
	mi->help_fn = de_help_readmake;
}

///////////////////////////////////////////////////
// TEXE (Raymond Payette)

struct texe_ctx {
	const char *msgpfx;
	u8 use_cr_hack;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
};

static void texe_find_text(deark *c, struct texe_ctx *tctx, lctx *d)
{
	i64 endpos;
	u8 buf[2];

	d->tpos = tctx->ei->end_of_dos_code;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);

	de_read(buf, d->tpos, 2);
	if(buf[1]==0x0a && buf[0]!=0x0d) {
		tctx->use_cr_hack = 1;
	}

	endpos = c->infile->len;
	// Files normally end with an extraneous space, which we'll strip off.
	if(de_getbyte(endpos-1) == 0x20) {
		endpos--;
	}
	d->tlen = endpos - d->tpos;
}

static void de_run_texe(deark *c, de_module_params *mparams)
{
	struct texe_ctx *tctx = NULL;
	lctx *d = NULL;
	dbuf *tmpdbuf = NULL;

	d = create_lctx(c);

	tctx = de_malloc(c, sizeof(struct texe_ctx));
	tctx->msgpfx = "[TEXE] ";
	tctx->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	fmtutil_collect_exe_info(c, c->infile, tctx->ei);

	tctx->edd.restrict_to_fmt = DE_SPECIALEXEFMT_TEXE;
	fmtutil_detect_specialexe(c, tctx->ei, &tctx->edd);
	if(tctx->edd.detected_fmt!=DE_SPECIALEXEFMT_TEXE) {
		d->need_errmsg = 1;
		goto done;
	}

	if(tctx->ei->overlay_len<2 || tctx->ei->overlay_len > 640*1024) {
		d->need_errmsg = 1;
		goto done;
	}

	texe_find_text(c, tctx, d);
	if(d->errflag) goto done;

	if(tctx->use_cr_hack) {
		// The first byte of the file seems lost, due to an apparent bug in
		// TEXE.
		// But if the second byte is LF, we assume the first byte was CR, and
		// can fix it.
		// (Here we make a modified copy of the data.)
		tmpdbuf = dbuf_create_membuf(c, d->tlen, 0);
		dbuf_writebyte(tmpdbuf, 0x0d);
		dbuf_copy(c->infile, d->tpos+1, d->tlen-1, tmpdbuf);
		dbuf_flush(tmpdbuf);
		d->inf = tmpdbuf;
		d->tpos = 0;
	}

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg && tctx) {
			de_err(c, "%sBad or unsupported TEXE file", tctx->msgpfx);
		}
		de_free(c, d);
		d = NULL;
	}
	if(tctx) {
		de_free(c, tctx->ei);
		de_free(c, tctx);
		tctx = NULL;
	}
	dbuf_close(tmpdbuf);
}

static void de_help_texe(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_texe(deark *c, struct deark_module_info *mi)
{
	mi->id = "texe";
	mi->desc = "TEXE executable text";
	mi->run_fn = de_run_texe;
	mi->help_fn = de_help_texe;
}

///////////////////////////////////////////////////
// Read-A-Matic

struct readamatic_ctx {
	const char *msgpfx;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
};

static void readamatic_find_text(deark *c, struct readamatic_ctx *tctx, lctx *d)
{
	i64 foundpos;
	i64 pos;
	int ret;

	// 10 byte header
	pos = tctx->ei->end_of_dos_code + 10;

	// Then a variable-length title we need to skip over.
	ret = dbuf_search_byte(c->infile, 0x0a, pos, 256, &foundpos);
	if(!ret) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	d->tpos = foundpos+1;
	d->tlen = c->infile->len - d->tpos;

done:
	;
}

static void de_run_readamatic(deark *c, de_module_params *mparams)
{
	struct readamatic_ctx *tctx = NULL;
	lctx *d = NULL;
	dbuf *tmpdbuf = NULL;

	d = create_lctx(c);

	tctx = de_malloc(c, sizeof(struct readamatic_ctx));
	tctx->msgpfx = "[Read-A-Matic] ";
	tctx->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	fmtutil_collect_exe_info(c, c->infile, tctx->ei);

	tctx->edd.restrict_to_fmt = DE_SPECIALEXEFMT_READAMATIC;
	fmtutil_detect_specialexe(c, tctx->ei, &tctx->edd);
	if(tctx->edd.detected_fmt!=DE_SPECIALEXEFMT_READAMATIC) {
		d->need_errmsg = 1;
		goto done;
	}

	if(tctx->ei->overlay_len<2 || tctx->ei->overlay_len > 640*1024) {
		d->need_errmsg = 1;
		goto done;
	}

	readamatic_find_text(c, tctx, d);
	if(d->errflag) goto done;

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg && tctx) {
			de_err(c, "%sBad or unsupported Read-A-Matic file", tctx->msgpfx);
		}
		de_free(c, d);
		d = NULL;
	}
	if(tctx) {
		de_free(c, tctx->ei);
		de_free(c, tctx);
		tctx = NULL;
	}
	dbuf_close(tmpdbuf);
}

static void de_help_readamatic(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_readamatic(deark *c, struct deark_module_info *mi)
{
	mi->id = "readamatic";
	mi->desc = "Read-A-Matic executable text";
	mi->run_fn = de_run_readamatic;
	mi->help_fn = de_help_readamatic;
}

///////////////////////////////////////////////////
// ASCOM (Kevin Tseng)
// Probably only v1.0f is supported.

static void ascom_decrypt(deark *c, lctx *d, dbuf *tmpdbuf)
{
	i64 i;

	for(i=0; i<d->tlen; i++) {
		u8 b;

		b = de_getbyte(d->tpos + i);
		b = b ^ 0x01;
		dbuf_writebyte(tmpdbuf, b);
	}
	dbuf_flush(tmpdbuf);
}

static void de_run_ascom(deark *c, de_module_params *mparams)
{
	i64 n;
	lctx *d = NULL;
	dbuf *tmpdbuf = NULL;

	d = create_lctx(c);
	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);
	de_declare_fmt(c, "ASCOM (executable text)");
	d->chartypes[10] = ETCT_CONTROL;
	d->chartypes[13] = ETCT_CONTROL;

	// Some arbitrary tests, to try to make sure we have the right version
	if(dbuf_memcmp(c->infile, 50, (const u8*)"\x72\x41\xc2\xfe\xd1\x7f\xca\xfe", 8) ||
		dbuf_memcmp(c->infile, 2048, (const u8*)"\xee\x40\x20\xf2\x47\xae\xfe\x43", 8))
	{
		d->need_errmsg = 1;
		goto done;
	}

	d->is_encrypted = 1;
	// TODO?: Figure out how to read this offset from the file.
	d->tpos = 3132;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);
	n = de_getu16le(48);
	d->tlen = 0xf400 - n;
	de_dbg(c, "tlen: %"I64_FMT, d->tlen);
	exectext_check_tpos(c, d);
	if(d->errflag) goto done;

	// Note: The heading is around offset 3040, XORed with 0xfe.

	tmpdbuf = dbuf_create_membuf(c, d->tlen, 0);
	dbuf_enable_wbuffer(tmpdbuf);
	ascom_decrypt(c, d, tmpdbuf);
	d->inf = tmpdbuf;
	d->tpos = 0;

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not an ASCOM file, or unsupported version");
		}
		destroy_lctx(c, d);
	}
	dbuf_close(tmpdbuf);
}

static int de_identify_ascom(deark *c)
{
	if(c->infile->len>65280) return 0;
	if(de_getbyte(0) != 0xe9) return 0;
	if(dbuf_memcmp(c->infile, 1,
		(const u8*)"\x00\x00\xe8\x00\x00\x8b\xfc\x36\x8b\x2d\x83\xc4\x02\x81\xed", 15))
	{
		return 0;
	}
	return 100;
}

static void de_help_ascom(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_ascom(deark *c, struct deark_module_info *mi)
{
	mi->id = "ascom";
	mi->desc = "ASCOM";
	mi->run_fn = de_run_ascom;
	mi->identify_fn = de_identify_ascom;
	mi->help_fn = de_help_ascom;
}

///////////////////////////////////////////////////
// TextLife, and Breeze Text-to-EXE

struct textlife_ctx {
	const char *msgpfx;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
};

static void de_run_textlife(deark *c, de_module_params *mparams)
{
	struct textlife_ctx *tctx = NULL;
	lctx *d = NULL;

	d = create_lctx(c);
	tctx = de_malloc(c, sizeof(struct textlife_ctx));
	tctx->msgpfx = "[TextLife] ";
	tctx->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	exectext_set_common_enc_opts(c, d, DE_ENCODING_CP437);

	// TextLife filters/optimizes the data before storing it. Known filters:
	// * Convert CR+LF to CR.
	// * Replace runs of 8 spaces with TAB.
	// I don't think extracting the raw bytes from the file is a useful thing
	// to do. So we always at least undo the filtering.
	// Files can contain C0 control characters used for special purposes (e.g.
	// italics), but I don't think they will cause serious problems with
	// encoding translation. So we just leave them as-is.
	if(d->proctype==ET_PROCTYPE_RAW) {
		d->proctype = ET_PROCTYPE_FMTCONV_ONLY;
	}

	d->chartypes[3] = ETCT_CONTROL;
	d->chartypes[4] = ETCT_CONTROL;
	d->chartypes[5] = ETCT_CONTROL;
	d->chartypes[6] = ETCT_CONTROL;
	d->chartypes[9] = ETCT_8SPACES;
	d->chartypes[0x0d] = ETCT_CRLF;
	d->chartypes[0x0f] = ETCT_CONTROL;
	d->chartypes[0x10] = ETCT_CONTROL;
	d->chartypes[0x11] = ETCT_CONTROL;

	fmtutil_collect_exe_info(c, c->infile, tctx->ei);

	tctx->edd.restrict_to_fmt = DE_SPECIALEXEFMT_TEXTLIFE;
	fmtutil_detect_specialexe(c, tctx->ei, &tctx->edd);
	if(tctx->edd.detected_fmt!=DE_SPECIALEXEFMT_TEXTLIFE) {
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "text marker pos: %"I64_FMT, tctx->edd.special_pos_1);
	d->tpos = tctx->edd.special_pos_1+6;
	de_dbg(c, "tpos: %"I64_FMT, d->tpos);
	d->tlen = de_getu16le(tctx->edd.special_pos_1 - 2) - 1;
	de_dbg(c, "tlen: %"I64_FMT, d->tlen);

	exectext_extract_default(c, d);

done:
	if(d) {
		if(d->need_errmsg && tctx) {
			de_err(c, "%sBad or unsupported TextLife file", tctx->msgpfx);
		}
		de_free(c, d);
		d = NULL;
	}
	if(tctx) {
		de_free(c, tctx->ei);
		de_free(c, tctx);
	}
}

static void de_help_textlife(deark *c)
{
	print_conv_options_simple(c);
}

void de_module_textlife(deark *c, struct deark_module_info *mi)
{
	mi->id = "textlife";
	mi->desc = "TextLife or Breeze executable text";
	mi->run_fn = de_run_textlife;
	mi->help_fn = de_help_textlife;
}
