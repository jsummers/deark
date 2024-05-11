// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// TXT2COM, etc.

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_txt2com);

typedef struct localctx_exectext {
	de_encoding input_encoding;
	u8 errflag;
	u8 need_errmsg;
	u8 found_text;
	i64 tpos;
	i64 tlen;
} lctx;

static int exectext_search_match(const u8 *mem, i64 mem_len,
	const u8 *pattern, i64 pattern_len, u8 wildcard, i64 *pfoundpos)
{
	i64 num_start_positions_to_search;
	i64 i;

	*pfoundpos = 0;
	if(pattern_len<1 || pattern_len>mem_len) return 0;
	num_start_positions_to_search = mem_len-pattern_len+1;

	for(i=0; i<num_start_positions_to_search; i++) {
		int ret;

		if(pattern[0]!=mem[i] && pattern[0]!=wildcard) continue;
		ret = de_memmatch(&mem[i], pattern, (size_t)pattern_len, wildcard, 0);
		if(ret) {
			*pfoundpos = i;
			return 1;
		}
	}

	return 0;
}

static void exectext_extract(deark *c, lctx *d)
{
	dbuf *outf = NULL;

	if(d->errflag) goto done;
	if(d->tpos<=0 || d->tlen<=0 || d->tpos+d->tlen>c->infile->len) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	outf = dbuf_create_output_file(c, "txt", NULL, 0);
	// TODO: This is not perfect. For example, TXT2COM displays byte 0x09 as
	// a visible character (like U+25cb), while we think it's a tab.
	dbuf_copy_slice_convert_to_utf8(c->infile, d->tpos, d->tlen,
		DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID), outf, 0x1|0x4);

done:
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
	ret = exectext_search_match(mem, TXT2COM_BUF_LEN1,
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
	ret = exectext_search_match(mem, TXT2COM_BUF_LEN2,
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

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
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

	exectext_extract(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Not a TXT2COM file, or unsupported version");
		}
		de_free(c, d);
	}
}

static int de_identify_txt2com(deark *c)
{
	u8 b1;
	u8 flag = 0;
	u8 buf[28];
	const char *ids[3] = {"TXT2COM C", "TXT2RES C", "TXT2PAS C"};

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

void de_module_txt2com(deark *c, struct deark_module_info *mi)
{
	mi->id = "txt2com";
	mi->desc = "TXT2COM (K.P.G.)";
	mi->run_fn = de_run_txt2com;
	mi->identify_fn = de_identify_txt2com;
}
