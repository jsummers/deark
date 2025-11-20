// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress PKLITE executable compression

// In a PKLITE-compressed EXE file, reliably determining the critical
// compression params is quite difficult. They are embedded or encoded in the
// machine code, and there are many different versions and variants of the
// format to deal with.
//
// While some params are encoded in the "version info" field at offset 28,
// this field is not trustworthy.
//
// This module painstakingly walks through the file, looking for known byte
// patterns, to identify known components, the parameters contained in them,
// and the location of following components.
//
// See also my "pkla" project, a script that does a better job of printing
// information about PKLITE-compressed files, and reporting problems.

// I thank Sergei Kolzun (private communication) for information about the
// v1.20 formats.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pklite);

// Things we need to figure out, to decompress the main compressed data.
struct decompr_params_struct {
	i64 cmpr_data_pos;
	u8 extra_cmpr; // 0=no, 1=yes, 2=special
	u8 large_cmpr;
	u8 v120_cmpr;
	u8 offset_xor_key;
};

struct ver_info_struct {
	UI ver_num; // e.g. 0x103 = 1.03
	char pklver_str[40];
};

struct footer_struct {
	i64 regSS;
	i64 regSP;
	i64 regCS;
	i64 regIP;
};

typedef struct localctx_pklite {
	u8 errflag;
	u8 errmsg_handled;
	u8 dcmpr_ok;
	u8 wrote_exe;
	u8 raw_mode;

	u8 is_com;
	u8 data_before_decoder;
	u8 load_high;
	u8 has_psp_sig;
	u8 psp_sig_type;
	int default_code_alignment;
	struct decompr_params_struct dparams;

	struct fmtutil_exe_info *host_ei; // For the PKLITE file
	struct fmtutil_exe_info *guest_ei; // For the decompressed file

	UI intro_class_fmtutil;
#define INTRO_CLASS_BETA      8
#define INTRO_CLASS_BETA_LH   9
#define INTRO_CLASS_100       10
#define INTRO_CLASS_112       12
#define INTRO_CLASS_114       14
#define INTRO_CLASS_150       50
#define INTRO_CLASS_UN2PACK   100
#define INTRO_CLASS_MEGALITE  101
#define INTRO_CLASS_COM_BETA  240
#define INTRO_CLASS_COM_100   241
#define INTRO_CLASS_COM_150   242
	u8 intro_class;

	UI initial_key;
	i64 position2; // The next section after the intro [relative to entry point]

#define DESCRAMBLER_CLASS_114              14
#define DESCRAMBLER_CLASS_150              50
#define DESCRAMBLER_CLASS_150IBM           51
#define DESCRAMBLER_CLASS_120VAR1A         101
#define DESCRAMBLER_CLASS_120VAR1B         102
#define DESCRAMBLER_CLASS_120VAR2          103
#define DESCRAMBLER_CLASS_PKZIP204CLIKE    105
#define DESCRAMBLER_CLASS_PKLITE201LIKE    110
#define DESCRAMBLER_CLASS_CHK4LITE201LIKE  111
	u8 descrambler_class;
	u8 scrambled_decompressor;
#define SCRAMBLE_METHOD_XOR 1
#define SCRAMBLE_METHOD_ADD 2
	u8 scramble_method;
	i64 scrambled_word_count;
	i64 pos_of_last_scrambled_word;

	i64 copier_pos;
#define COPIER_CLASS_COMMON         1
#define COPIER_CLASS_150SCR         2
#define COPIER_CLASS_120VAR1SMALL   10
#define COPIER_CLASS_PKLITE201LIKE  20
#define COPIER_CLASS_UN2PACK        100
#define COPIER_CLASS_MEGALITE       101
#define COPIER_CLASS_OTHER          200
#define COPIER_CLASS_COM_BETA       240
#define COPIER_CLASS_COM_100        241
#define COPIER_CLASS_COM_115        242
	u8 copier_class;

	i64 decompr_pos;
	i64 approx_end_of_decompressor;
#define DECOMPR_CLASS_COMMON        1
#define DECOMPR_CLASS_BETA          9
#define DECOMPR_CLASS_115           15
#define DECOMPR_CLASS_120SMALL_OLD  50
#define DECOMPR_CLASS_120SMALL      51
#define DECOMPR_CLASS_COM_BETA      240
#define DECOMPR_CLASS_COM_100       241
	u8 decompr_class;

	i64 cmpr_data_endpos; // = reloc_tbl_pos
	i64 reloc_tbl_endpos;
	i64 cmpr_data_area_endpos; // where the footer ends
	i64 footer_pos; // 0 if unknown
	struct footer_struct footer;

	dbuf *hdr_for_dcmpr_file; // copied or constructed header for the decompressed file
	dbuf *guest_reloc_table;
	dbuf *dcmpr_code;

	struct ver_info_struct ver_reported;

	// A copy of the bytes at the EXE entry point, generally up to but not
	// including the compressed data. The most we expect to need is about 800,
	// e.g. for PKLITE Pro 2.01 w/ large + extra + checksum.
#define EPBYTES_LEN 1000
	u8 epbytes[EPBYTES_LEN];
} lctx;

struct decompr_internal_state {
	lctx *d;
	dbuf *inf;
	const struct decompr_params_struct *dparams;
	u8 has_uncompressed_area;
	i64 dcmpr_code_nbytes_written;
	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;
	struct fmtutil_huffman_decoder *lengths_tree;
	struct fmtutil_huffman_decoder *offsets_tree;
};

#define pkl_memmatch de_memmatch

// Search a region of a block of memory for the given pattern.
//
// search endpos is the end of the search region (the first byte beyond it).
//   The entire pattern must fit into the region.
// pattern_len is the number of non-padding bytes. Must be at least 1.
// *pfoundpos is relative to the beginning of the 'mem'.
static int pkl_search_match(const u8 *mem, i64 mem_len,
	i64 search_startpos, i64 search_endpos,
	const u8 *pattern, i64 pattern_len,
	u8 wildcard, UI flags, i64 *pfoundpos)
{
	i64 foundpos2;
	int ret;

	*pfoundpos = 0;

	if(pattern_len<1) return 0;
	if(search_startpos<0) search_startpos = 0;
	if(search_endpos>mem_len) search_endpos = mem_len;
	if(pattern_len > search_endpos-search_startpos) return 0;

	ret = de_memsearch_match(&mem[search_startpos], search_endpos-search_startpos,
		pattern, pattern_len, wildcard, &foundpos2);
	if(ret) {
		*pfoundpos = search_startpos + foundpos2;
	}
	return ret;
}

static void info_bytes_to_version_struct(UI ver_info, struct ver_info_struct *v)
{
	v->ver_num = ver_info & 0x0fff;
	de_snprintf(v->pklver_str, sizeof(v->pklver_str), "%u.%02u%s%s%s",
		(UI)(v->ver_num>>8), (UI)(v->ver_num&0xff),
		((ver_info&0x4000)?"/h":""),
		((ver_info&0x2000)?"/l":"/s"),
		((ver_info&0x1000)?"/e":""));
}

static void do_read_version_info(deark *c, lctx *d, i64 pos)
{
	UI ver_info;

	ver_info = (UI)de_getu16le(pos);
	info_bytes_to_version_struct(ver_info, &d->ver_reported);
	de_dbg(c, "reported PKLITE version: %s", d->ver_reported.pklver_str);
}

static i64 ip_to_eprel(lctx *d, i64 ip)
{
	i64 n;

	// TODO: This works, but might not be technically correct.
	n = d->host_ei->start_of_dos_code + (ip - 0x0100) - d->host_ei->entry_point;
	if(n<0) n=0;
	return n;
}

static i64 read_and_follow_1byte_jump(lctx *d, i64 pos1)
{
	i64 pos2;

	if(pos1>=EPBYTES_LEN) return 0;
	pos2 = pos1 + 1 + (i64)d->epbytes[pos1];
	return pos2;
}

static void analyze_intro(deark *c, lctx *d)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "intro at ep+0");
	de_dbg_indent(c, 1);

	// FIXME: We shouldn't print these opaque "class" identifiers in the
	// debug info, but for now it's better than nothing.
	de_dbg(c, "intro class/prelim: %u", d->intro_class_fmtutil);

	// Initial DX register is sometimes used as a key.
	if(pkl_memmatch(&d->epbytes[0], (const u8*)"\xb8??\xba", 4, '?', 0)) {
		d->initial_key = (UI)de_getu16le_direct(&d->epbytes[4]);
	}
	else if(pkl_memmatch(&d->epbytes[0], (const u8*)"\x50\xb8??\xba", 5, '?', 0)) {
		d->initial_key = (UI)de_getu16le_direct(&d->epbytes[5]);
	}

	if(d->intro_class_fmtutil==90) {
		d->intro_class = INTRO_CLASS_BETA;
		d->data_before_decoder = 1;
	}
	else if(d->intro_class_fmtutil==91) {
		d->intro_class = INTRO_CLASS_BETA_LH;
		d->data_before_decoder = 1;
		d->load_high = 1;
	}
	else if(d->intro_class_fmtutil==100) {
		d->intro_class = INTRO_CLASS_100;
		d->position2 = 16;
	}
	else if(d->intro_class_fmtutil==112) {
		if(d->epbytes[13]==0x73) {
			d->intro_class = INTRO_CLASS_112;
			d->position2 = 15;
		}
		else if(d->epbytes[13]==0x72) {
			d->intro_class = INTRO_CLASS_114;
			d->position2 = read_and_follow_1byte_jump(d, 14);
		}
	}
	else if(d->intro_class_fmtutil==150) {
		if(d->epbytes[14]==0x72) {
			d->intro_class = INTRO_CLASS_150;
			d->position2 = read_and_follow_1byte_jump(d, 15);
		}
	}
	else if(d->intro_class_fmtutil==250) {
		d->intro_class = INTRO_CLASS_UN2PACK;
		d->position2 = 34;
	}
	else if(d->intro_class_fmtutil==251) {
		if(d->epbytes[13]==0x72) {
			d->intro_class = INTRO_CLASS_MEGALITE;
			d->position2 = read_and_follow_1byte_jump(d, 14);
		}
	}

	if(d->data_before_decoder) return;

	if(!d->intro_class || !d->position2) {
		d->errflag = 1;
	}
	if(!d->errflag) {
		de_dbg(c, "intro class: %u", (UI)d->intro_class);
		de_dbg(c, "after intro: ep+%"I64_FMT, d->position2);
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

static void analyze_descrambler(deark *c, lctx *d)
{
	i64 pos;
	i64 pos_of_endpos_field = 0;
	i64 pos_of_jmp_field = 0;
	i64 pos_of_op = 0;
	i64 pos_of_scrambled_word_count = 0;
	i64 scrambled_endpos_raw;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	switch(d->intro_class) {
		// Classes that might be scrambled:
	case INTRO_CLASS_112:
	case INTRO_CLASS_114:
	case INTRO_CLASS_150:
		break;
	default:
		goto done;
	}

	pos = d->position2;
	if(pos + 200 > EPBYTES_LEN) goto done;

	if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x2d\x20\x00\x8e\xd0\x2d??\x50\x52\xb9??\xbe??\x8b\xfe"
		"\xfd\x90\x49\x74?\xad\x92\x33\xc2\xab\xeb\xf6", 30, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_114;
		pos_of_scrambled_word_count = pos+11;
		pos_of_endpos_field = pos+14;
		pos_of_jmp_field = pos+22;
		pos_of_op = pos+25;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe"
		"\xfd\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6", 28, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_120VAR1A;
		pos_of_scrambled_word_count = pos+10;
		pos_of_endpos_field = pos+13;
		pos_of_jmp_field = pos+20;
		pos_of_op = pos+23;
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe"
		"\xfd\x90\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6", 29, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_120VAR1B;
		pos_of_scrambled_word_count = pos+10;
		pos_of_endpos_field = pos+13;
		pos_of_jmp_field = pos+21;
		pos_of_op = pos+24;
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x59\x2d\x20\x00\x8e\xd0\x51??\x00\x50\x80\x3e"
		"\x41\x01\xc3\x75\xe6\x52\xb8??\xbe??\x56\x56\x52\x50\x90"
		"???????\x74", 38, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_150;
		pos_of_scrambled_word_count = pos+20;
		pos_of_endpos_field = pos+23;
		pos_of_jmp_field = pos+38;
		pos_of_op = pos+45;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x2d\x20\x00????????????\xb9??\xbe????????\x74???\x03",
		32, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_120VAR2;
		pos_of_scrambled_word_count = pos+16;
		pos_of_endpos_field = pos+19;
		pos_of_jmp_field = pos+28;
		pos_of_op = pos+31;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x2d\x20\x00????????????\xb9??\xbe?????????\x74???\x03",
		33, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_PKZIP204CLIKE;
		pos_of_scrambled_word_count = pos+16;
		pos_of_endpos_field = pos+19;
		pos_of_jmp_field = pos+29;
		pos_of_op = pos+32;
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x2d\x20\x00?????????????????\xb9??\xbe??????????\x74???\x03",
		39, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_PKLITE201LIKE;
		pos_of_scrambled_word_count = pos+21;
		pos_of_endpos_field = pos+24;
		pos_of_jmp_field = pos+35;
		pos_of_op = pos+38;
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x8b\xfc\x81?????????????\xbb??\xbe??????\x74???\x03",
		31, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_CHK4LITE201LIKE;
		pos_of_scrambled_word_count = pos+17;
		pos_of_endpos_field = pos+20;
		pos_of_jmp_field = pos+27;
		pos_of_op = pos+30;
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x59\x2d\x20\x00\x8e\xd0\x51\x2d??\x50\x52\xb9??\xbe??\x8b\xfe"
		"\xfd\x90\x49\x74?\xad\x92\x33", 28, '?', 0))
	{
		d->descrambler_class = DESCRAMBLER_CLASS_150IBM;
		pos_of_scrambled_word_count = pos+13;
		pos_of_endpos_field = pos+16;
		pos_of_jmp_field = pos+24;
		pos_of_op = pos+27;
	}

	if(!d->descrambler_class) {
		goto done;
	}

	d->scrambled_decompressor = 1;

	if(d->epbytes[pos_of_op]==0x33) {
		d->scramble_method = SCRAMBLE_METHOD_XOR;
	}
	else if(d->epbytes[pos_of_op]==0x03) {
		d->scramble_method = SCRAMBLE_METHOD_ADD;
	}
	else {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "descrambler at ep+%"I64_FMT, d->position2);
	de_dbg_indent(c, 1);
	de_dbg(c, "descrambler class: %u", (UI)d->descrambler_class);

	de_dbg(c, "scramble method: %u", (UI)d->scramble_method);
	d->scrambled_word_count = de_getu16le_direct(&d->epbytes[pos_of_scrambled_word_count]);
	if(d->scrambled_word_count>0) d->scrambled_word_count--;
	de_dbg(c, "scrambled word count: %u", (UI)d->scrambled_word_count);
	scrambled_endpos_raw = de_getu16le_direct(&d->epbytes[pos_of_endpos_field]);
	d->pos_of_last_scrambled_word = ip_to_eprel(d, scrambled_endpos_raw);
	de_dbg(c, "pos of last scrambled word: %u", (UI)d->pos_of_last_scrambled_word);
	d->copier_pos = read_and_follow_1byte_jump(d, pos_of_jmp_field);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(!d->errflag) {
		if(!d->scrambled_decompressor && !d->data_before_decoder) {
			d->copier_pos = d->position2;
		}
		de_dbg(c, "is scrambled: %u", (UI)d->scrambled_decompressor);
	}
}

static void descramble_decompressor(deark *c, lctx *d)
{
	i64 startpos;
	i64 pos;
	UI this_word_scr;
	UI next_word_scr;
	UI this_word_dscr;

	if(!d->scrambled_decompressor || d->scrambled_word_count<1) {
		goto done;
	}
	de_dbg(c, "[descrambling]");

	if(d->pos_of_last_scrambled_word+2 > EPBYTES_LEN) {
		d->errflag = 1;
		goto done;
	}

	startpos = d->pos_of_last_scrambled_word+2-d->scrambled_word_count*2;
	if(startpos < 0) {
		d->errflag = 1;
		goto done;
	}

	this_word_scr = (UI)de_getu16le_direct(&d->epbytes[startpos]);

	for(pos=startpos; pos<=d->pos_of_last_scrambled_word; pos+=2) {
		if(pos==d->pos_of_last_scrambled_word) {
			next_word_scr = d->initial_key;
		}
		else {
			next_word_scr = (UI)de_getu16le_direct(&d->epbytes[pos+2]);
		}

		if(d->scramble_method==2) {
			this_word_dscr = (this_word_scr + next_word_scr) & 0xffff;
		}
		else {
			this_word_dscr = this_word_scr ^ next_word_scr;
		}

		de_writeu16le_direct(&d->epbytes[pos], (i64)this_word_dscr);
		this_word_scr = next_word_scr;
	}

done:
	;
}

static void analyze_copier(deark *c, lctx *d)
{
	i64 pos_of_decompr_pos_field = 0;
	i64 foundpos = 0;
	i64 pos = d->copier_pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->data_before_decoder) goto done;
	if(!pos) {
		d->errflag = 1;
		goto done;
	}
	if(pos+200 > EPBYTES_LEN) {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "copier at ep+%u", (UI)pos);
	de_dbg_indent(c, 1);

	if(pkl_search_match(d->epbytes, EPBYTES_LEN,
		pos, pos+75,
		(const u8*)"\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5", 12, '?', 0, &foundpos))
	{
		if(d->epbytes[foundpos+12]==0xcb) {
			d->copier_class = COPIER_CLASS_COMMON;
		}
		else if(d->epbytes[foundpos+12]==0xca) {
			d->copier_class = COPIER_CLASS_150SCR;
		}
		else {
			d->copier_class = COPIER_CLASS_OTHER;
		}
		pos_of_decompr_pos_field = foundpos+7;
	}

	else if(pkl_search_match(d->epbytes, EPBYTES_LEN,
		pos, pos+75,
		(const u8*)"\xb9??\x33\xff\x57\xfc\xbe??\xf3\xa5\xcb", 13, '?', 0, &foundpos))
	{
		d->copier_class = COPIER_CLASS_PKLITE201LIKE;
		pos_of_decompr_pos_field = foundpos+8;
	}

	else if(pkl_search_match(d->epbytes, EPBYTES_LEN,
		pos, pos+75,
		(const u8*)"\x57\xb9??\xbe??\xfc\xf3\xa5\xc3", 11, '?', 0, &foundpos))
	{
		d->copier_class = COPIER_CLASS_120VAR1SMALL;
		pos_of_decompr_pos_field = foundpos+5;
	}
	else if(pkl_search_match(d->epbytes, EPBYTES_LEN,
		pos, pos+75,
		(const u8*)"\xb9??\x33\xff\x56\xbe??\xfc\xf2\xa5\xca", 13, '?', 0, &foundpos))
	{
		d->copier_class = COPIER_CLASS_MEGALITE;
		pos_of_decompr_pos_field = foundpos+7;
	}
	else if(pkl_search_match(d->epbytes, EPBYTES_LEN,
		pos, pos+75,
		(const u8*)"\xb9??\x2b\xff\x57\xbe??\xfc\xf3\xa5\xcb", 13, '?', 0, &foundpos))
	{
		d->copier_class = COPIER_CLASS_UN2PACK;
		pos_of_decompr_pos_field = foundpos+7;
	}

	if(!d->copier_class) {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "copier class: %u", (UI)d->copier_class);
	de_dbg(c, "copier subclass: %"I64_FMT, pos_of_decompr_pos_field-pos);
	d->decompr_pos = ip_to_eprel(d, de_getu16le_direct(&d->epbytes[pos_of_decompr_pos_field]));

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void find_decompr_pos_beta(deark *c, lctx *d)
{
	if(pkl_memmatch(&d->epbytes[0x59],
		(const u8*)"\xf3\xa5\x2e\xa1????????\xcb\xfc", 14, '?', 0))
	{
		// small
		d->decompr_pos = 0x66;
	}
	else if(pkl_memmatch(&d->epbytes[0x5b],
		(const u8*)"\xf3\xa5\x85\xed????????????\xcb\xfc", 18, '?', 0))
	{
		// large
		d->decompr_pos = 0x6c;
	}
	else if(pkl_memmatch(&d->epbytes[0],
		(const u8*)"\x2e\x8c\x1e??\xfc\x8c\xc8\x2e\x2b\x06", 11, '?', 0))
	{
		// load-high
		d->decompr_pos = 0x5;
	}
}

static void analyze_decompressor(deark *c, lctx *d)
{
	i64 pos;
	i64 n;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(!d->decompr_pos && d->data_before_decoder) {
		find_decompr_pos_beta(c, d);
	}

	pos = d->decompr_pos;
	if(!pos) {
		d->errflag = 1;
		goto done;
	}
	if(pos+200 > EPBYTES_LEN) {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "decompressor at ep+%u", (UI)pos);
	de_dbg_indent(c, 1);

	if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\x8c\xdb\x53\x83\xc3", 6, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_COMMON;
		n = (i64)d->epbytes[pos+6];
		n *= 16;
		d->dparams.cmpr_data_pos = d->host_ei->entry_point + ip_to_eprel(d, n);
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\x8c\xdb\x53\x81\xc3", 6, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_115;
		n = de_getu16le_direct(&d->epbytes[pos+6]);
		n *= 16;
		d->dparams.cmpr_data_pos = d->host_ei->entry_point + ip_to_eprel(d, n);
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\x5f\xc7\x85????\x4f\x4f\xbe??\x03\xf2"
		"\x8b\xca\xd1\xe9\xf3", 20, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_120SMALL;
		n = de_getu16le_direct(&d->epbytes[pos+11]);
		d->dparams.cmpr_data_pos = d->host_ei->entry_point + 2 + ip_to_eprel(d, n);
	}

	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\x5f\x4f\x4f\xbe??\x03\xf2\x8b\xca\xd1\xe9\xf3", 14, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_120SMALL_OLD;
		n = de_getu16le_direct(&d->epbytes[pos+5]);
		d->dparams.cmpr_data_pos = d->host_ei->entry_point + 2 + ip_to_eprel(d, n);
	}


	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfc\x8c\xc8\x2e\x2b\x06??\x8e\xd8\xbf", 11, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_BETA;
		d->dparams.cmpr_data_pos = d->host_ei->start_of_dos_code;
	}

	if(!d->decompr_class) {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "decompressor class: %u", (UI)d->decompr_class);
	de_dbg(c, "cmpr data pos: %"I64_FMT, d->dparams.cmpr_data_pos);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void analyze_detect_large_and_v120_cmpr(deark *c, lctx *d)
{
	i64 foundpos = 0;
	int ret;

	if(d->decompr_class==DECOMPR_CLASS_120SMALL ||
		d->decompr_class==DECOMPR_CLASS_120SMALL_OLD)
	{
		d->dparams.v120_cmpr = 1;
		d->dparams.large_cmpr = 0;
		goto done;
	}

	// TODO?: A better search function to use when there are no wildcards.
	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->approx_end_of_decompressor-60, d->approx_end_of_decompressor,
		(const u8*)"\x01\x02\x00\x00\x03\x04\x05\x06"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x07\x08\x09\x0a\x0b", 21, 0x3f,
		0, &foundpos);
	if(ret && foundpos>0) {
		u8 prec_b;

		prec_b = d->epbytes[foundpos-1];
		if(prec_b==0x09) {
			d->dparams.large_cmpr = 0;
		}
		else if(prec_b==0x18) {
			d->dparams.large_cmpr = 1;
		}
		else {
			d->errflag = 1;
		}
		goto done;
	}

	// The only thing left should be v1.20 w/ large cmpr, which always uses extra cmpr
	if(!d->dparams.extra_cmpr) {
		d->errflag = 1;
		goto done;
	}

	// Files w/o the above pattern, but with the below pattern, are presumed
	// to be v1.20.
	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->approx_end_of_decompressor-50, d->approx_end_of_decompressor,
		(const u8*)"\x33\xc0\x8b\xd8\x8b\xc8\x8b\xd0\x8b\xe8\x8b\xf0\x8b", 13, 0x3f,
		0, &foundpos);
	if(ret) {
		d->dparams.v120_cmpr = 1;
		d->dparams.large_cmpr = 1;
		goto done;
	}

	d->errflag = 1;

done:
	if(!d->errflag) {
		de_dbg(c, "large cmpr: %u", (UI)d->dparams.large_cmpr);
		de_dbg(c, "v1.20 cmpr: %u", (UI)d->dparams.v120_cmpr);
	}
}

static void analyze_detect_obf_offsets(deark *c, lctx *d)
{
	i64 foundpos = 0;
	int ret;
	u8 has_obf_offsets = 0;

	if(!d->dparams.v120_cmpr) goto done;

	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->decompr_pos+200, d->approx_end_of_decompressor,
		(const u8*)"\xac\x34?\x8a", 4, 0x3f,
		0, &foundpos);
	if(ret) {
		has_obf_offsets = 1;
		d->dparams.offset_xor_key = d->epbytes[foundpos+2];
	}

done:
	if(d->dparams.v120_cmpr) {
		de_dbg(c, "obfuscated offsets: %u", (UI)has_obf_offsets);
		if(has_obf_offsets) {
			de_dbg_indent(c, 1);
			de_dbg(c, "offsets key: 0x%02x", (UI)d->dparams.offset_xor_key);
			de_dbg_indent(c, -1);
		}
	}
}

static void analyze_detect_extra_cmpr(deark *c, lctx *d)
{
	int ret;
	i64 foundpos;

	if(d->decompr_pos==0 || d->approx_end_of_decompressor==0) {
		d->errflag = 1;
		goto done;
	}

	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->decompr_pos, d->approx_end_of_decompressor,
		(const u8*)"\xad\x95\xb2\x10\x72\x08\xa4\xd1\xed\x4a\x74", 11, 0x3f,
		0, &foundpos);
	if(ret) {
		d->dparams.extra_cmpr = 0;
		goto done;
	}

	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->decompr_pos, d->approx_end_of_decompressor,
		(const u8*)"\xad\x95\xb2\x10\x72\x0b\xac??\xaa\xd1\xed\x4a\x74", 14, 0x3f,
		0, &foundpos);
	if(ret) {
		if(d->epbytes[foundpos+7]==0x32 && d->epbytes[foundpos+8]==0xc2) {
			d->dparams.extra_cmpr = 1;
			goto done;
		}
		else if(d->epbytes[foundpos+7]==0xf6 && d->epbytes[foundpos+8]==0xd0) {
			// Customized "v1.23" format seen in files from RemoteAccess v1.11
			// BBS software by Andrew Milner / Continental Software.
			//  http://cd.textfiles.com/librisbritannia/
			//  https://archive.org/details/LibrisBritannia
			//   ... COMMUNIC/BULLETIN/3220A.ZIP
			//   ... COMMUNIC/BULLETIN/3220B.ZIP
			d->dparams.extra_cmpr = 2;
			goto done;
		}
	}

	d->errflag = 1;

done:
	if(!d->errflag) {
		de_dbg(c, "extra cmpr: %u", (UI)d->dparams.extra_cmpr);
	}
}

static void analyze_detect_psp_sig(deark *c, lctx *d)
{
	int ret;
	i64 foundpos;
	const u8 *pattern;

	if(d->decompr_pos==0 || d->approx_end_of_decompressor==0) {
		goto done;
	}

	// It's kind of overkill to always do this search, and always look for both
	// signatures. We could probably be much more discriminiating, e.g. by
	// by using the apparent correspondence to scramble_method. But we would
	// risk false negatives.

	pattern = (const u8*)"\xc7\x06\x5c\x00\x70\x6b"; // "pk"
	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->decompr_pos, d->approx_end_of_decompressor,
		pattern, 6, 0x3f, 0, &foundpos);
	if(ret) {
		d->has_psp_sig = 1;
		d->psp_sig_type = 2;
		goto done;
	}

	pattern = (const u8*)"\xc7\x06\x5c\x00\x50\x4b"; // "PK"
	ret = pkl_search_match(d->epbytes, EPBYTES_LEN,
		d->decompr_pos, d->approx_end_of_decompressor,
		pattern, 6, 0x3f, 0, &foundpos);
	if(ret) {
		d->has_psp_sig = 1;
		d->psp_sig_type = 1;
	}

done:
	;
}

// Do whatever we need to do to figure out the compression params
// (mainly d->dparams).
static void do_analyze_pklite_exe(deark *c, lctx *d)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "code start: %"I64_FMT, d->host_ei->start_of_dos_code);
	de_dbg(c, "entry point: %"I64_FMT, d->host_ei->entry_point);

	de_dbg(c, "[analyzing file]");
	de_dbg_indent(c, 1);

	analyze_intro(c, d);
	if(d->errflag) goto done;

	analyze_descrambler(c, d);
	if(d->errflag) goto done;

	if(d->scrambled_decompressor) {
		descramble_decompressor(c, d);
		if(d->errflag) goto done;
	}

	analyze_copier(c, d);
	if(d->errflag) goto done;

	analyze_decompressor(c, d);
	if(d->errflag) goto done;

	if(!d->dparams.cmpr_data_pos) {
		d->errflag = 1;
		goto done;
	}

	if(d->data_before_decoder) {
		d->approx_end_of_decompressor = d->host_ei->end_of_dos_code - d->host_ei->entry_point;
		d->cmpr_data_area_endpos = d->host_ei->entry_point;
	}
	else {
		d->approx_end_of_decompressor = d->dparams.cmpr_data_pos - d->host_ei->entry_point;
		d->cmpr_data_area_endpos = d->host_ei->end_of_dos_code;
	}
	de_dbg(c, "approx end of decompressor: ep+%"I64_FMT, d->approx_end_of_decompressor);

	analyze_detect_extra_cmpr(c, d);
	if(d->errflag) goto done;
	analyze_detect_large_and_v120_cmpr(c, d);
	if(d->errflag) goto done;
	analyze_detect_obf_offsets(c, d);
	if(d->errflag) goto done;
	analyze_detect_psp_sig(c, d);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void fill_bitbuf(deark *c, struct decompr_internal_state *dctx)
{
	UI i;

	if(dctx->d->errflag) return;
	if(dctx->dcmpr_cur_ipos+2 > dctx->inf->len) {
		de_err(c, "Unexpected end of file during decompression");
		dctx->d->errflag = 1;
		dctx->d->errmsg_handled = 1;
		return;
	}

	for(i=0; i<2; i++) {
		u8 b;
		b = dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);
		de_bitbuf_lowlevel_add_byte(&dctx->bbll, b);
	}
}

static u8 pklite_getbit(deark *c, struct decompr_internal_state *dctx)
{
	u8 v;

	if(dctx->d->errflag) return 0;
	v = (u8)de_bitbuf_lowlevel_get_bits(&dctx->bbll, 1);

	if(dctx->bbll.nbits_in_bitbuf==0) {
		fill_bitbuf(c, dctx);
	}

	return v;
}

static void pklite_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct decompr_internal_state *dctx = (struct decompr_internal_state *)rb->userdata;

	dbuf_writebyte(dctx->d->dcmpr_code, n);
	dctx->dcmpr_code_nbytes_written++;
}

// Allocates and populates a huffman_decoder.
// Caller supplies htp: A pointer to an initially-NULL pointer.
// Caller must eventually call fmtutil_huffman_destroy_decoder() on the returned
//  pointer.
// lengths_and_codes: High 4 bits is the code length (0..12),
//  low 12 bits is the code.
static void huffman_make_tree_from_u16array(deark *c,
	struct fmtutil_huffman_decoder **htp,
	const u16 *lengths_and_codes, UI ncodes,
	const char *dbgtitle)
{
	UI n;
	char b2buf[72];

	if(*htp) return;
	*htp = fmtutil_huffman_create_decoder(c, ncodes, ncodes);
	if(dbgtitle) {
		de_dbg3(c, "[%s codebook]", dbgtitle);
	}
	de_dbg_indent(c, 1);
	for(n=0; n<ncodes; n++) {
		UI nbits;
		u64 code;

		nbits = ((UI)lengths_and_codes[n])>>12;
		code = ((u64)lengths_and_codes[n]) & 0x0fff;

		if(dbgtitle && c->debug_level>=3) {
			de_dbg3(c, "code: \"%s\" = %d",
				de_print_base2_fixed(b2buf, sizeof(b2buf), code, nbits), (int)n);
		}
		fmtutil_huffman_add_code(c, (*htp)->bk, code, nbits,
			(fmtutil_huffman_valtype)n);
	}
	de_dbg_indent(c, -1);
}

static void make_matchlengths_tree(deark *c, struct decompr_internal_state *dctx)
{
	static const char *name = "match lengths";
	static const u16 matchlengthsdata_lg[24] = {
		0x2003,0x3000,0x4002,0x4003,0x4004,0x500a,0x500b,0x500c,
		0x601a,0x601b,0x703a,0x703b,0x703c,0x807a,0x807b,0x807c,
		0x90fa,0x90fb,0x90fc,0x90fd,0x90fe,0x90ff,0x601c,0x2002
	};
	static const u16 matchlengthsdata_sm[9] = {
		0x2000,0x3004,0x3005,0x400c,0x400d,0x400e,0x400f,0x3003,
		0x3002
	};
	static const u16 matchlengthsdata120_lg[21] = {
		0x2003,0x3000,0x4005,0x4006,0x5006,0x5007,0x6008,0x6009,
		0x7020,0x7021,0x7022,0x7023,0x8048,0x8049,0x804a,0x9096,
		0x9097,0x6013,0x2002,0x4007,0x5005
	};
	static const u16 matchlengthsdata120_sm[11] = {
		0x2003,0x3000,0x4004,0x4005,0x500e,0x601e,0x601f,0x4006,
		0x2002,0x4003,0x4002
	};

	if(dctx->dparams->large_cmpr) {
		if(dctx->dparams->v120_cmpr) {
			huffman_make_tree_from_u16array(c, &dctx->lengths_tree,
				matchlengthsdata120_lg, 21, name);
		}
		else {
			huffman_make_tree_from_u16array(c, &dctx->lengths_tree,
				matchlengthsdata_lg, 24, name);
		}
	}
	else {
		if(dctx->dparams->v120_cmpr) {
			huffman_make_tree_from_u16array(c, &dctx->lengths_tree,
				matchlengthsdata120_sm, 11, name);
		}
		else {
			huffman_make_tree_from_u16array(c, &dctx->lengths_tree,
				matchlengthsdata_sm, 9, name);
		}
	}
}

static void make_offsets_tree(deark *c, struct decompr_internal_state *dctx)
{
	static const char *name = "offsets";
	static const u16 offsetsdata[32] = {
		0x1001,0x4000,0x4001,0x5004,0x5005,0x5006,0x5007,0x6010,
		0x6011,0x6012,0x6013,0x6014,0x6015,0x6016,0x702e,0x702f,
		0x7030,0x7031,0x7032,0x7033,0x7034,0x7035,0x7036,0x7037,
		0x7038,0x7039,0x703a,0x703b,0x703c,0x703d,0x703e,0x703f
	};
	static const u16 offsetsdata120[32] = {
		0x1001,0x3000,0x5004,0x5005,0x5006,0x5007,0x6010,0x6011,
		0x6012,0x6013,0x6014,0x6015,0x702c,0x702d,0x702e,0x702f,
		0x7030,0x7031,0x7032,0x7033,0x7034,0x7035,0x7036,0x7037,
		0x7038,0x7039,0x703a,0x703b,0x703c,0x703d,0x703e,0x703f
	};

	if(dctx->dparams->v120_cmpr) {
		huffman_make_tree_from_u16array(c, &dctx->offsets_tree,
			offsetsdata120, 32, name);
	}
	else {
		huffman_make_tree_from_u16array(c, &dctx->offsets_tree,
			offsetsdata, 32, name);
	}
}

static UI read_pklite_code_using_tree(deark *c, struct decompr_internal_state *dctx,
	struct fmtutil_huffman_decoder *ht)
{
	int ret;
	fmtutil_huffman_valtype val = 0;

	while(1) {
		u8 b;

		b = pklite_getbit(c, dctx);
		if(dctx->d->errflag) goto done;

		ret = fmtutil_huffman_decode_bit(ht->bk, ht->cursor, b, &val);
		if(ret==1) goto done; // finished the code
		if(ret!=2) {
			dctx->d->errflag = 1;
			goto done;
		}
	}
done:
	return val;
}

static void do_uncompressed_area(deark *c, struct decompr_internal_state *dctx,
	struct de_lz77buffer *ringbuf)
{
	UI len;
	UI i;
	u8 b;
	const u8 *uasig = (const u8*)"PKLITE\x26\xa3";

	dctx->has_uncompressed_area = 1;
	len = (UI)dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);
	de_dbg3(c, "uncompressed area at %"I64_FMT", len=%u", dctx->dcmpr_cur_ipos, len);

	// The only files that I have, that use an uncompressed area, are
	// registered versions of PKZIP.EXE. When they decompress themselves
	// (e.g., use UNP) 9 bytes of what looks like garbage appear before the
	// uncompressed bytes. Probably, whatever happened to be in memory is
	// just left there by the decompressor.
	// Based on the PKLITE 2.01 documentation, in the original file, an
	// uncompressed area is marked by an 8-byte signature, which is followed
	// by a length byte. So, the numbers add up. Instead of trying to do
	// exactly what the decompressor does, we'll do our best to reproduce the
	// original file.
	//
	// (Granted, files made at PKWARE, like PKZIP.EXE, might well have used a
	// different signature. But there's no way for me to know that.)
	//
	// It doesn't really matter what we write here, anyway. After an
	// uncompressed area, the "match" codes never seem to refer to any of the
	// bytes in the uncompressed area, or before it. In effect, the history
	// buffer gets cleared.
	//
	// To emphasize this, we won't even add these bytes to the history buffer,
	// and we'll clear the history buffer before continuing.

	for(i=0; i<8; i++) {
		ringbuf->writebyte_cb(ringbuf, uasig[i]);
	}
	ringbuf->writebyte_cb(ringbuf, (u8)len);

	for(i=0; i<len; i++) {
		b = dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);
		ringbuf->writebyte_cb(ringbuf, b);
	}

	de_lz77buffer_clear(ringbuf, 0);
}

// Decompress the main part of the file.
// Uses:
//   c->infile
//   d->dparams.*
// Returns:
//   d->dcmpr_code
//   d->cmpr_data_endpos
//   d->errflag
//   d->errmsg_handled
static void do_decompress(deark *c, lctx *d)
{
	struct decompr_internal_state *dctx = NULL;
	struct de_lz77buffer *ringbuf = NULL;
	u8 b;
	u8 allow_prehistory = 0;
	UI value_of_long_ml_code;
	UI value_of_ml2_0_code;
	UI value_of_ml2_1_code = 0xffff;
	UI value_of_lit0_code = 0xffff;
	UI long_matchlen_bias;

	de_dbg(c, "decompressing cmpr code at %"I64_FMT, d->dparams.cmpr_data_pos);
	de_dbg_indent(c, 1);

	dctx = de_malloc(c, sizeof(struct decompr_internal_state));
	dctx->d = d;
	dctx->inf = c->infile;
	dctx->dparams = &d->dparams;

	if(d->ver_reported.ver_num == 0x100) {
		// Need this for v1.00beta/1990-07-17. It makes use of an implied
		// 0-valued byte before the actual data (or it has a bug that does
		// that).
		allow_prehistory = 1;
	}

	if(d->dparams.large_cmpr) {
		if(d->dparams.v120_cmpr) {
			// There are 17 normal codes, and 4 special
			value_of_long_ml_code = 17;
			value_of_ml2_0_code = value_of_long_ml_code+1;
			value_of_ml2_1_code = value_of_long_ml_code+2;
			value_of_lit0_code = value_of_long_ml_code+3;
			long_matchlen_bias = 20;
		}
		else {
			// There are 22 normal codes, and 2 special
			value_of_long_ml_code = 22;
			value_of_ml2_0_code = value_of_long_ml_code+1;
			long_matchlen_bias = 25;
		}
	}
	else {
		if(d->dparams.v120_cmpr) {
			// There are 7 normal codes, and 4 special
			value_of_long_ml_code = 7;
			value_of_ml2_0_code = value_of_long_ml_code+1;
			value_of_ml2_1_code = value_of_long_ml_code+2;
			value_of_lit0_code = value_of_long_ml_code+3;
			long_matchlen_bias = 10;
		}
		else {
			// There are 7 normal codes, and 2 special
			value_of_long_ml_code = 7;
			value_of_ml2_0_code = value_of_long_ml_code+1;
			long_matchlen_bias = 10;
		}
	}

	make_matchlengths_tree(c, dctx);
	make_offsets_tree(c, dctx);

	d->dcmpr_code = dbuf_create_membuf(c, 0, 0);
	dbuf_set_length_limit(d->dcmpr_code, 1048576);
	dbuf_enable_wbuffer(d->dcmpr_code);

	ringbuf = de_lz77buffer_create(c, 8192);
	ringbuf->userdata = (void*)dctx;
	ringbuf->writebyte_cb = pklite_lz77buf_writebytecb;

	dctx->dcmpr_cur_ipos = d->dparams.cmpr_data_pos;
	dctx->bbll.is_lsb = 1;
	de_bitbuf_lowlevel_empty(&dctx->bbll);

	fill_bitbuf(c, dctx);

	while(1) {
		u8 x;
		UI len_raw;
		UI matchlen;
		UI offs_hi_bits = 0;
		u8 offs_lo_byte;
		u8 offs_have_hi_bits = 0;
		UI matchpos;

		if(d->errflag) goto after_dcmpr;

		x = pklite_getbit(c, dctx);
		if(x==0) {
			b = dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);
			if(d->dparams.extra_cmpr==1) {
				b ^= (u8)(dctx->bbll.nbits_in_bitbuf);
			}
			else if(d->dparams.extra_cmpr==2) {
				b ^= 0xff;
			}
			if(c->debug_level>=3) {
				de_dbg3(c, "lit 0x%02x", (UI)b);
			}
			de_lz77buffer_add_literal_byte(ringbuf, b);
			continue;
		}

		len_raw = read_pklite_code_using_tree(c, dctx, dctx->lengths_tree);
		if(d->errflag) goto after_dcmpr;

		if(len_raw<value_of_long_ml_code) {
			matchlen = len_raw+3;
		}
		else if(len_raw==value_of_ml2_0_code) {
			matchlen = 2;
			// Leave offs_hi_bits at 0.
			offs_have_hi_bits = 1;
		}
		else if(len_raw==value_of_long_ml_code) {
			b = dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);

			if(b >= 0xfd) {
				if(b==0xfd && d->dparams.large_cmpr) {
					do_uncompressed_area(c, dctx, ringbuf);
					continue;
				}
				if(b==0xfe && d->dparams.large_cmpr) {
					// (segment separator) Just a no-op?
					de_dbg3(c, "code 0xfe");
					continue;
				}
				if(b==0xff) {
					de_dbg3(c, "stop code");
					goto after_dcmpr; // Normal completion
				}
				de_err(c, "Unexpected code (0x%02x) or unsupported feature", (UI)b);
				d->errflag = 1;
				d->errmsg_handled = 1;
				goto after_dcmpr;
			}
			matchlen = (UI)b+long_matchlen_bias;
		}
		else if(len_raw==value_of_lit0_code) {
			if(c->debug_level>=3) {
				de_dbg3(c, "lit 0x00 (special)");
			}
			de_lz77buffer_add_literal_byte(ringbuf, 0x00);
			continue;
		}
		else if(len_raw==value_of_ml2_1_code) {
			matchlen = 2;
			offs_hi_bits = 1;
			offs_have_hi_bits = 1;
		}
		else {
			d->errflag = 1;
			goto done;
		}

		if(!offs_have_hi_bits) {
			offs_hi_bits = read_pklite_code_using_tree(c, dctx, dctx->offsets_tree);
		}

		offs_lo_byte = dbuf_getbyte_p(dctx->inf, &dctx->dcmpr_cur_ipos);
		offs_lo_byte ^= d->dparams.offset_xor_key;
		if(d->errflag) goto after_dcmpr;

		matchpos = (offs_hi_bits<<8) | (UI)offs_lo_byte;

		if(c->debug_level>=3) {
			de_dbg3(c, "match pos=%u len=%u", matchpos, matchlen);
		}

		// PKLITE confirmed to use distances 1 to 8191. Have not observed matchpos=0.
		// Have not observed it to use distances larger than the number of bytes
		// decompressed so far [with one small exception].
		if(allow_prehistory && (matchpos == dctx->dcmpr_code_nbytes_written+1)) {
			;
		}
		else if(matchpos==0 || (i64)matchpos>dctx->dcmpr_code_nbytes_written) {
			de_err(c, "Bad or unsupported compressed data (dist=%u, expected 1 to %"I64_FMT")",
				matchpos, dctx->dcmpr_code_nbytes_written);
			d->errflag = 1;
			d->errmsg_handled = 1;
			goto after_dcmpr;
		}
		de_lz77buffer_copy_from_hist(ringbuf,
				(UI)(ringbuf->curpos-matchpos), matchlen);
	}

after_dcmpr:
	if(!d->dcmpr_code) goto done;
	dbuf_flush(d->dcmpr_code);

	if(!d->errflag) {
		d->cmpr_data_endpos = dctx->dcmpr_cur_ipos;
		de_dbg(c, "cmpr data end: %"I64_FMT, d->cmpr_data_endpos);
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
			d->cmpr_data_endpos-d->dparams.cmpr_data_pos, d->dcmpr_code->len);

		if(dctx->has_uncompressed_area) {
			de_dbg(c, "[has an uncompressed area]");
		}
	}

done:
	if(dctx) {
		fmtutil_huffman_destroy_decoder(c, dctx->lengths_tree);
		fmtutil_huffman_destroy_decoder(c, dctx->offsets_tree);
		de_free(c, dctx);
	}
	de_dbg_indent(c, -1);
}

#define MAX_RELOCS 65535

static void do_read_reloc_table_short(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 reloc_count = 0;
	i64 pos = pos1;
	i64 endpos = pos1+len;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "reading 'short' reloc table at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		UI i;
		UI count;
		i64 seg, offs;

		if(pos+1 > endpos) {
			d->errflag = 1;
			goto done;
		}
		count = (UI)de_getbyte_p(&pos);
		if(count==0) {
			de_dbg2(c, "end-of-data");
			break; // normal completion
		}
		de_dbg2(c, "count: %u", count);

		if(reloc_count+count > MAX_RELOCS) {
			d->errflag = 1;
			goto done;
		}
		if(pos+2+(i64)count*2 > endpos) {
			d->errflag = 1;
			goto done;
		}
		seg = de_getu16le_p(&pos);
		de_dbg2(c, "seg: 0x%04x", (UI)seg);
		de_dbg_indent(c, 1);
		for(i=0; i<count; i++) {
			if(reloc_count>=MAX_RELOCS) {
				d->errflag = 1;
				goto done;
			}
			offs = de_getu16le_p(&pos);
			de_dbg2(c, "offs: 0x%04x", (UI)offs);
			dbuf_writeu16le(d->guest_reloc_table, offs);
			dbuf_writeu16le(d->guest_reloc_table, seg);
			reloc_count++;
		}
		de_dbg_indent(c, -1);
	}

	d->reloc_tbl_endpos = pos;
	de_dbg(c, "cmpr reloc table ends at %"I64_FMT", entries=%d", d->reloc_tbl_endpos,
		(int)reloc_count);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_read_reloc_table_long(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 reloc_count = 0;
	i64 pos = pos1;
	i64 seg = 0;
	i64 endpos = pos1+len;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "reading 'long%s' reloc table at %"I64_FMT,
		(d->scramble_method==2?"/reversed":""), pos1);
	de_dbg_indent(c, 1);
	while(1) {
		UI i;
		UI count;
		i64 offs;

		if(pos+2 > endpos) {
			d->errflag = 1;
			goto done;
		}

		count = (UI)de_getu16le_p(&pos);
		if(count==0xffff) {
			de_dbg2(c, "end-of-data");
			break; // normal completion
		}
		de_dbg2(c, "count: %u", count);

		if(seg > 0xffff) {
			d->errflag = 1;
			goto done;
		}
		de_dbg2(c, "seg: 0x%04x", (UI)seg);

		if(reloc_count+count > MAX_RELOCS) {
			d->errflag = 1;
			goto done;
		}
		if(pos+(i64)count*2 > endpos) {
			d->errflag = 1;
			goto done;
		}

		de_dbg_indent(c, 1);
		for(i=0; i<count; i++) {
			if(d->scramble_method==2) {
				offs = de_getu16be_p(&pos);
			}
			else {
				offs = de_getu16le_p(&pos);
			}
			de_dbg2(c, "offs: 0x%04x", (UI)offs);
			dbuf_writeu16le(d->guest_reloc_table, offs);
			dbuf_writeu16le(d->guest_reloc_table, seg);
			reloc_count++;
		}
		de_dbg_indent(c, -1);
		seg += 0x0fff;
	}

	d->reloc_tbl_endpos = pos;
	de_dbg(c, "cmpr reloc table ends at %"I64_FMT", entries=%d", d->reloc_tbl_endpos,
		(int)reloc_count);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_read_reloc_table(deark *c, lctx *d)
{
	i64 reloc_tbl_len; // number of bytes available for encoded table

	d->guest_reloc_table = dbuf_create_membuf(c, 0, 0);

	reloc_tbl_len = d->cmpr_data_area_endpos - 8 - d->cmpr_data_endpos;

	if(d->dparams.extra_cmpr) {
		do_read_reloc_table_long(c, d, d->cmpr_data_endpos, reloc_tbl_len);
	}
	else {
		do_read_reloc_table_short(c, d, d->cmpr_data_endpos, reloc_tbl_len);
	}

	if(d->errflag) {
		de_err(c, "Failed to decode relocation table");
		d->errmsg_handled = 1;
	}
}

static void find_min_mem_needed(deark *c, lctx *d, i64 *pminmem)
{
	i64 pos;
	i64 n;
	u8 b;

	if(d->data_before_decoder) {
		// File from a registered v1.00beta?
		return;
	}

	pos = d->host_ei->entry_point;
	b = de_getbyte_p(&pos);
	if(b==0x50) {
		b = de_getbyte_p(&pos);
	}
	if(b==0xb8) {
		// This is not always exactly right. Not sure that's possible.
		n = de_getu16le_p(&pos);
		n = (n<<4) + 0x100 - d->dcmpr_code->len;
		if(n>=0) {
			*pminmem = (n+0xf)>>4;
		}
	}
}

static void do_write_data_only(deark *c, lctx *d)
{
	if(!d->dcmpr_code) return;
	dbuf_create_file_from_slice(d->dcmpr_code, 0, d->dcmpr_code->len, "bin", NULL, 0);
}

// Generate the decompressed file
static void do_write_dcmpr(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 amt_to_copy;

	if(d->errflag || !d->guest_ei || !d->hdr_for_dcmpr_file || !d->dcmpr_code ||
		!d->guest_reloc_table)
	{
		return;
	}
	de_dbg(c, "generating decompressed EXE file");
	de_dbg_indent(c, 1);

	outf = dbuf_create_output_file(c, "exe", NULL, 0);
	d->wrote_exe = 1;

	// Write the original header, up to the relocation table
	amt_to_copy = de_min_int(d->hdr_for_dcmpr_file->len, d->guest_ei->reloc_table_pos);
	dbuf_copy(d->hdr_for_dcmpr_file, 0, amt_to_copy, outf);
	dbuf_truncate(outf, d->guest_ei->reloc_table_pos);

	// Write the relocation table
	dbuf_copy(d->guest_reloc_table, 0, d->guest_reloc_table->len, outf);

	// Pad up to the start of DOS code.
	// (Note that PKLITE does not record data between the end of the relocation
	// table, and the start of DOS code, so we can't reconstruct that.)
	dbuf_truncate(outf, d->guest_ei->start_of_dos_code);

	// Write the decompressed program code
	dbuf_copy(d->dcmpr_code, 0, d->dcmpr_code->len, outf);

	// "Overlay" segment
	if(d->host_ei->overlay_len>0) {
		if(outf->len == d->guest_ei->end_of_dos_code) {
			dbuf_copy(c->infile, d->host_ei->end_of_dos_code, d->host_ei->overlay_len, outf);
		}
		else {
			// We don't want to write the overlay to the wrong offset, but it's
			// not clear what to do here. This should not happen with pristine
			// files, but could happen if an overlay was added later.
			de_warn(c, "Overlay not copied to new file, due to inconsistent file "
				"structure");
		}
	}

	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

// Try to read the copy of the original EXE header, into d->hdr_for_dcmpr_file.
// Returns 0 if it doesn't exist, or if it seems bad.
static int read_orig_header(deark *c, lctx *d)
{
	i64 orig_hdr_len;
	i64 orig_reloc_pos;
	i64 n1, n2;
	i64 dcmpr_bytes_expected;
	i64 orig_hdr_pos;
	const char *name;
	enum ohdisp_enum {
		OHDISP_MISSING_E, OHDISP_MISSING, OHDISP_PRESENT, OHDISP_BAD
	} ohdisp;

	if(d->dparams.extra_cmpr) {
		ohdisp = OHDISP_MISSING_E;
		goto done;
	}
	orig_hdr_pos = d->host_ei->reloc_table_pos + 4*d->host_ei->num_relocs;

	orig_hdr_len = d->host_ei->start_of_dos_code - orig_hdr_pos; // tentative
	if(orig_hdr_len < 26) {
		ohdisp = OHDISP_MISSING;
		goto done;
	}

	// Peek at the reloc table offs field to figure out how much to read
	orig_reloc_pos = de_getu16le(orig_hdr_pos + 22);
	if(orig_reloc_pos>=28 && orig_reloc_pos<2+orig_hdr_len) {
		orig_hdr_len = orig_reloc_pos-2;
	}

	de_dbg(c, "orig. hdr: at %"I64_FMT", len=(2+)%"I64_FMT, orig_hdr_pos, orig_hdr_len);

	n1 = de_getu16le(orig_hdr_pos); // len of final block
	n2 = de_getu16le(orig_hdr_pos+2); // numBlocks
	if(n1>511 || n2==0) {
		ohdisp = OHDISP_BAD;
		goto done;
	}

	dbuf_copy(c->infile, orig_hdr_pos, orig_hdr_len, d->hdr_for_dcmpr_file);

	fmtutil_collect_exe_info(c, d->hdr_for_dcmpr_file, d->guest_ei);
	if(d->guest_ei->reloc_table_pos<28) {
		d->guest_ei->reloc_table_pos = 28;
	}

	if((d->guest_ei->regSS != d->footer.regSS) ||
		(d->guest_ei->regSP != d->footer.regSP) ||
		(d->guest_ei->regCS != d->footer.regCS) ||
		(d->guest_ei->regIP != d->footer.regIP))
	{
		ohdisp = OHDISP_BAD;
		goto done;
	}

	if(d->guest_ei->num_relocs != (d->guest_reloc_table->len / 4)) {
		ohdisp = OHDISP_BAD;
		goto done;
	}

	dcmpr_bytes_expected = d->guest_ei->end_of_dos_code - d->guest_ei->start_of_dos_code;

	if(d->dcmpr_code->len != dcmpr_bytes_expected) {
		const char *note2;

		if(d->dcmpr_code->len < dcmpr_bytes_expected) {
			// If the original file's reported file size is larger than its
			// actual size, PKLITE can still correctly compress it (with a
			// misleading warning that it "may contain overlays"), and can
			// decompress it as well. There is unfortunately no way for us
			// to distinguish this not-really-an-error situation from some
			// sort of decompression failure that really ought to be
			// reported.
			note2 = ". (This could mean the original file was slightly "
				"malformed, before PKLITE compressed it.)";
		}
		else {
			note2 = "";
		}

		de_warn(c, "Expected %"I64_FMT" decompressed bytes, got %"I64_FMT"%s",
			dcmpr_bytes_expected, d->dcmpr_code->len, note2);
	}

	ohdisp = OHDISP_PRESENT;

done:
	switch(ohdisp) {
	case OHDISP_PRESENT: name="present"; break;
	case OHDISP_MISSING_E: name="n/a"; break;
	case OHDISP_MISSING: name="missing"; break;
	default: name="bad"; break;
	}
	de_dbg(c, "copy of orig hdr: %s", name);
	if(ohdisp==OHDISP_BAD) {
		de_warn(c, "Original header seems bad. Ignoring it.");
	}
	return (ohdisp==OHDISP_PRESENT);
}

static void reconstruct_header(deark *c, lctx *d)
{
	i64 num_relocs;
	const i64 reloc_table_start = 28;
	i64 start_of_dos_code;
	i64 end_of_dos_code;
	i64 minmem; // in 16-byte units
	i64 maxmem;

	// "MZ" should already be written
	if(d->hdr_for_dcmpr_file->len!=2 || !d->footer_pos) {
		d->errflag = 1;
		return;
	}

	// By default, keep the same values as the container. These are likely to
	// be higher than the original, but it's better to be too high than too low.
	minmem = de_getu16le(10);
	maxmem = de_getu16le(12);
	if(maxmem==0) {
		// Unlikely, but could possibly happen for beta files with the
		// load-high option
		maxmem = 65535;
	}
	find_min_mem_needed(c, d, &minmem);
	// TODO: For maxmem, it may be possible to do better.
	if(maxmem<minmem) maxmem = minmem;

	num_relocs = d->guest_reloc_table->len / 4;
	start_of_dos_code = de_pad_to_n(reloc_table_start + num_relocs*4,
		(i64)d->default_code_alignment);
	end_of_dos_code = start_of_dos_code + d->dcmpr_code->len;
	dbuf_writeu16le(d->hdr_for_dcmpr_file, end_of_dos_code%512);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, (end_of_dos_code+511)/512);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, num_relocs);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, start_of_dos_code/16);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, minmem);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, maxmem);
	dbuf_writei16le(d->hdr_for_dcmpr_file, d->footer.regSS);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, d->footer.regSP);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, 0); // checksum
	dbuf_writeu16le(d->hdr_for_dcmpr_file, d->footer.regIP);
	dbuf_writei16le(d->hdr_for_dcmpr_file, d->footer.regCS);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, reloc_table_start);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, 0); // overlay indicator

	fmtutil_collect_exe_info(c, d->hdr_for_dcmpr_file, d->guest_ei);
}

// Either copy the original header, or if we can't do that,
// construct a new EXE header from other information.
// Creates and populates d->hdr_for_dcmpr_file, d->o_ei
static void acquire_new_exe_header(deark *c, lctx *d)
{
	int ret;

	d->guest_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	d->hdr_for_dcmpr_file =  dbuf_create_membuf(c, 0, 0);
	dbuf_writeu16le(d->hdr_for_dcmpr_file, 0x5a4d); // "MZ"

	ret = read_orig_header(c, d);
	if(ret) goto done; // If success, we're done. Otherwise try other method.

	dbuf_truncate(d->hdr_for_dcmpr_file, 2);
	reconstruct_header(c, d);
done:
	;
}

static void do_pklite_exe(deark *c, lctx *d)
{
	const char *s;

	d->raw_mode = (u8)de_get_ext_option_bool(c, "pklite:raw", 0xff);

	s = de_get_ext_option(c, "execomp:align");
	if(s) {
		d->default_code_alignment = de_atoi(s);
	}
	if(d->default_code_alignment != 512) {
		d->default_code_alignment = 16;
	}

	fmtutil_collect_exe_info(c, c->infile, d->host_ei);

	de_read(d->epbytes, d->host_ei->entry_point, EPBYTES_LEN);
	d->intro_class_fmtutil = fmtutil_detect_pklite_by_exe_ep(c, d->epbytes, EPBYTES_LEN, 0xff);

	if(d->intro_class_fmtutil==0) {
		de_err(c, "Not a PKLITE-compressed file, or not a known type");
		d->errflag = 1;
		d->errmsg_handled = 1;
		goto done;
	}

	de_declare_fmt(c, "PKLITE-compressed EXE");

	do_read_version_info(c, d, 28);

	do_analyze_pklite_exe(c, d);
	if(d->errflag) goto done;

	do_decompress(c, d);
	dbuf_flush(d->dcmpr_code);
	if(d->errflag) goto done;
	d->dcmpr_ok = 1;

	if(d->raw_mode==1) {
		do_write_data_only(c, d);
		goto done;
	}

	do_read_reloc_table(c, d);
	if(d->errflag) goto done;

	d->footer_pos = d->reloc_tbl_endpos;
	if(d->footer_pos!=0) {
		i64 footer_capacity;

		footer_capacity = d->cmpr_data_area_endpos - d->footer_pos;
		de_dbg(c, "footer at %"I64_FMT", len=%"I64_FMT, d->footer_pos, footer_capacity);
		de_dbg_indent(c, 1);

		if(c->debug_level>=3) {
			de_dbg_hexdump(c, c->infile, d->footer_pos, footer_capacity, 32, "footer", 0);
		}

		// Footer is usually 8 bytes, but there can be up to 15 extra bytes, to
		// accommodate the checksum feature.
		if(footer_capacity < 8) {
			d->footer_pos = 0; // Error
		}
		else if(footer_capacity > 8+15) {
			de_warn(c, "Unexpected data at end of code segment (near %"I64_FMT")",
				d->footer_pos+8);
		}

		if(d->footer_pos!=0) {
			d->footer.regSS = de_geti16le(d->footer_pos);
			d->footer.regSP = de_getu16le(d->footer_pos+2);
			d->footer.regCS = de_geti16le(d->footer_pos+4);
			d->footer.regIP = de_getu16le(d->footer_pos+6);
		}

		de_dbg_indent(c, -1);
	}

	if(d->footer_pos==0) {
		d->errflag = 1;
		goto done;
	}

	acquire_new_exe_header(c, d);
	if(d->errflag) goto done;

	do_write_dcmpr(c, d);
	if(d->errflag) goto done;

	de_stdwarn_execomp(c);
	if(d->has_psp_sig) {
		de_warn(c, "This file has a tamper-detection feature (PSP signature \"%s\"). "
			"It might not run correctly when decompressed.",
			((d->psp_sig_type==2) ? "pk" : "PK"));

		// TODO: It is possible to patch the decompressed file, so that it stands
		// a chance of passing this protection check. But it's not easy.
	}

done:
	;
}

static void analyze_intro_COM(deark *c, lctx *d)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "intro at 0");
	de_dbg_indent(c, 1);

	if(pkl_memmatch(&d->epbytes[0],
		(const u8*)"\xb8??\xba??\x3b\xc4\x73", 9, '?', 0))
	{
		d->copier_class = INTRO_CLASS_COM_100;
		d->position2 = 10;
	}
	else if(pkl_memmatch(&d->epbytes[0],
		(const u8*)"\x50\xb8??\xba??\x3b\xc4\x73", 10, '?', 0))
	{
		d->copier_class = INTRO_CLASS_COM_150;
		d->position2 = 11;
	}
	else if(pkl_memmatch(&d->epbytes[0],
		(const u8*)"\xba??\xa1\x02\x00\x2d??\x8c\xcb??????\x77", 18, '?', 0))
	{
		d->copier_class = INTRO_CLASS_COM_BETA;
		d->position2 = read_and_follow_1byte_jump(d, 18);
	}

	if(!d->position2) {
		d->errflag = 1;
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void analyze_copier_COM(deark *c, lctx *d)
{
	int saved_indent_level;
	i64 pos = d->position2;
	i64 pos_of_decompr_pos_field = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos<0 || pos+100>EPBYTES_LEN) goto done;

	de_dbg(c, "copier at %u", (UI)pos);
	de_dbg_indent(c, 1);

	if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x8b\xc4\x2d??\x25\xf0\xff\x8b\xf8\xb9??\xbe", 14, '?', 0))
	{
		d->copier_class = COPIER_CLASS_COM_100;
		pos_of_decompr_pos_field = pos+14;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\x8b\xc4\x2d??\x90\x25\xf0\xff\x8b\xf8\xb9??\x90\xbe", 16, '?', 0))
	{
		d->copier_class = COPIER_CLASS_COM_115;
		pos_of_decompr_pos_field = pos+16;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfa\xbc\x00\x02\x8e\xd0\xfb", 7, '?', 0))
	{
		d->copier_class = COPIER_CLASS_COM_BETA;
		d->decompr_pos = pos+24;
	}

	if(pos_of_decompr_pos_field) {
		d->decompr_pos = de_getu16le_direct(&d->epbytes[pos_of_decompr_pos_field]) - 0x100;
	}

done:
	if(!d->decompr_pos) {
		d->errflag = 1;
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void analyze_decompressor_COM(deark *c, lctx *d)
{
	int saved_indent_level;
	i64 pos = d->decompr_pos;
	i64 keypos = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos<0 || pos+100>EPBYTES_LEN) goto done;

	de_dbg(c, "decompressor at %u", (UI)pos);
	de_dbg_indent(c, 1);

	if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\x8b\xf8\x4f\x4f\xbe", 6, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_COM_100;
		keypos = pos+6;
	}
	else if(pkl_memmatch(&d->epbytes[pos],
		(const u8*)"\xfd\xbe??\x03\xf2\x8b\xfa\x4f\x4f", 10, '?', 0))
	{
		d->decompr_class = DECOMPR_CLASS_COM_BETA;
		keypos = pos+2;
	}

	if(keypos) {
		d->dparams.cmpr_data_pos = de_getu16le_direct(&d->epbytes[keypos]) + 2 - 0x100;
	}

done:
	if(d->dparams.cmpr_data_pos<1 || d->dparams.cmpr_data_pos>c->infile->len) {
		d->dparams.cmpr_data_pos = 0;
		d->errflag = 1;
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// This function's only real purpose is to set d->dparams.cmpr_data_pos.
static void do_analyze_pklite_com(deark *c, lctx *d)
{
	d->dparams.large_cmpr = 0;
	d->dparams.extra_cmpr = 0;
	d->dparams.v120_cmpr = 0;

	analyze_intro_COM(c, d);
	if(d->errflag) goto done;

	analyze_copier_COM(c, d);
	if(d->errflag) goto done;

	analyze_decompressor_COM(c, d);

done:
	;
}

static int pklite_com_has_copyright_string(dbuf *f, i64 verpos)
{
	u8 buf[4];

	if(verpos==38) {
		return !dbuf_memcmp(f, verpos+2, (const void*)"PK Copyr", 8);
	}
	dbuf_read(f, buf, verpos+2, sizeof(buf));

	if((buf[0]=='P') && (buf[1]=='K' || buf[1]=='k') &&
		(buf[2]=='L' || buf[2]=='l') && (buf[3]=='I' || buf[3]=='i'))
	{
		return 1;
	}
	return 0;
}

static int detect_pklite_com_quick(dbuf *f, i64 *pverpos)
{
	u8 b[10];

	dbuf_read(f, b, 0, sizeof(b));
	if(b[0]==0xb8 && b[3]==0xba && b[6]==0x3b && b[7]==0xc4) {
		if(b[9]==0x67) { // Probably v1.00-1.14
			*pverpos = 44;
			return 1;
		}
		else if(b[9]==0x69) { // Probably v1.15 (usually mislabeled as 1.14)
			*pverpos = 46;
			return 1;
		}
	}
	else if(b[0]==0x50 && b[1]==0xb8 && b[4]==0xba && b[7]==0x3b) {
		*pverpos = 46; // v1.50-2.01
		return 1;
	}
	else if(b[0]==0xba && b[3]==0xa1 && b[6]==0x2d && b[7]==0x20) {
		*pverpos = 36; // v1.00beta
		return 1;
	}
	return 0;
}

static void read_and_process_com_version_number(deark *c, lctx *d, i64 verpos)
{
	de_dbg(c, "version number pos: %"I64_FMT, verpos);
	do_read_version_info(c, d, verpos);
}

static void report_detected_version_number_com(deark *c, lctx *d)
{
	const char *s = "?";

	if(d->dparams.cmpr_data_pos==500) {
		s = "1.00beta";
	}
	else if(d->dparams.cmpr_data_pos==448) {
		switch(de_getbyte(260)) {
		case 0x1d: s = "1.00-1.03"; break;
		case 0x1c: s = "1.05-1.14"; break;
		default: s = "1.00-1.14"; break;
		}
	}
	else if(d->dparams.cmpr_data_pos==450) {
		s = "1.15";
	}
	else if(d->dparams.cmpr_data_pos==464) {
		s = "1.50-2.01";
	}

	de_dbg(c, "detected PKLITE version: %s", s);
}

static void do_pklite_com(deark *c, lctx *d)
{
	i64 verpos = 0;

	if(!detect_pklite_com_quick(c->infile, &verpos)) {
		de_err(c, "Not a known/supported PKLITE format");
		goto done;
	}

	d->is_com = 1;
	d->host_ei->f = c->infile;
	de_declare_fmt(c, "PKLITE-compressed COM");

	de_read(d->epbytes, 0, EPBYTES_LEN);

	read_and_process_com_version_number(c, d, verpos);

	if(c->module_disposition==DE_MODDISP_AUTODETECT) {
		// Check if the user requested that we not do executable decompression.
		// This feels like a hack. I'm not sure how it should work.
		if(de_get_ext_option_bool(c, "execomp", 1) == 0) {
			goto done;
		}
	}

	do_analyze_pklite_com(c, d);

	report_detected_version_number_com(c, d);

	if(d->errflag || d->dparams.cmpr_data_pos==0) {
		de_err(c, "Unsupported PKLITE format version");
		goto done;
	}

	do_decompress(c, d);
	if(!d->dcmpr_code) goto done;
	dbuf_flush(d->dcmpr_code);
	if(d->errflag) goto done;
	d->dcmpr_ok = 1;

	dbuf_create_file_from_slice(d->dcmpr_code, 0, d->dcmpr_code->len, "com", NULL, 0);
	de_stdwarn_execomp(c);

done:
	;
}

static void de_run_pklite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u8 buf[2];

	d = de_malloc(c, sizeof(lctx));
	d->host_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	de_read(buf, 0, 2);
	if((buf[0]=='M' && buf[1]=='Z') || (buf[0]=='Z' && buf[1]=='M')) {
		do_pklite_exe(c, d);
	}
	else {
		do_pklite_com(c, d);
	}

	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "PKLITE decompression failed");
		}

		if(!d->is_com && d->raw_mode==0xff && d->dcmpr_ok && !d->wrote_exe) {
			de_info(c, "Note: Try \"-opt pklite:raw\" to decompress the raw data");
		}

		dbuf_close(d->hdr_for_dcmpr_file);
		dbuf_close(d->guest_reloc_table);
		dbuf_close(d->dcmpr_code);
		de_free(c, d->guest_ei);
		de_free(c, d->host_ei);
		de_free(c, d);
	}
}

// By design, only detects COM format.
// EXE files are handled by the "exe" module by default.
static int de_identify_pklite(deark *c)
{
	i64 verpos;

	if(c->infile->len>65280) return 0;
	if(detect_pklite_com_quick(c->infile, &verpos)) {
		if(pklite_com_has_copyright_string(c->infile, verpos)) {
			return 100;
		}
		// TODO: False positives may be possible. Maybe we should be more
		// discriminating.
		return 15;
	}
	return 0;
}

static void de_help_pklite(deark *c)
{
	de_msg(c, "-opt pklite:raw : Instead of an EXE file, write raw decompressed data");
	de_msg(c, "-opt execomp:align=<16|512> : Alignment of code image (hint)");
}

void de_module_pklite(deark *c, struct deark_module_info *mi)
{
	mi->id = "pklite";
	mi->desc = "PKLITE-compressed EXE/COM";
	mi->run_fn = de_run_pklite;
	mi->identify_fn = de_identify_pklite;
	mi->help_fn = de_help_pklite;
}
