// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress PKLITE executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pklite);

#define PKLITE_UNK_VER_NUM 0x963 // Unknown but possibly supported version

#define DE_PKLITE_SHAPE_BETA      2  // 1.00beta
#define DE_PKLITE_SHAPE_BETA_LH   3  // 1.00beta/loadhigh
#define DE_PKLITE_SHAPE_100       4  // 1.00-1.05 or 1.10(?)
#define DE_PKLITE_SHAPE_112       5  // 1.12-1.13
#define DE_PKLITE_SHAPE_114       6  // 1.14-1.15 or 1.20var1 or ZIP2EXEv2.04
#define DE_PKLITE_SHAPE_150       7  // 1.50-2.01 or 1.20var3
#define DE_PKLITE_SHAPE_120V2     8  // 1.20var2
#define DE_PKLITE_SHAPE_120V4     9  // 1.20var4 or ZIP2EXEv2.50
#define DE_PKLITE_SHAPE_MEGALITE  10
#define DE_PKLITE_SHAPE_UN2PACK   11
#define DE_PKLITE_SHAPE_114LOOSE  12
#define DE_PKLITE_SHAPE_150LOOSE  13

struct ver_info_struct {
	UI ver_num; // e.g. 0x103 = 1.03
	u8 valid; // have the non-derived fields been set?
	u8 is_beta;
	u8 extra_cmpr;
	u8 extra_cmpr_confidence; // likelihood that extra_cmpr is correct
	u8 large_cmpr;
	u8 load_high;
	const char *suffix;

	// derived fields:
	char pklver_str[40];
};

struct footer_struct {
	i64 regSS;
	i64 regSP;
	i64 regCS;
	i64 regIP;
};

typedef struct localctx_struct {
	struct ver_info_struct ver_reported;
	struct ver_info_struct ver_detected;
	struct ver_info_struct ver;

	struct fmtutil_exe_info *ei; // For the PKLITE file
	struct fmtutil_exe_info *o_ei; // For the decompressed file
	u8 is_com;
	u8 data_before_decoder;
	u8 decoder_shape;
	u8 dcmpr_ok;
	u8 wrote_exe;
	i64 cmpr_data_pos;
	i64 cmpr_data_endpos; // = reloc_tbl_pos
	i64 reloc_tbl_endpos;
	i64 cmpr_data_area_endpos; // where the footer ends
	i64 footer_pos; // 0 if unknown
	i64 predicted_cmpr_data_pos; // based on the 01 02 00 00 03... pattern, 0 if unknown
	struct footer_struct footer;

	int errflag;
	int errmsg_handled;
	dbuf *o_orig_header; // copied or constructed header for the decompressed file
	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;
	i64 o_dcmpr_code_nbytes_written;

	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;

	struct fmtutil_huffman_decoder *lengths_tree;
	struct fmtutil_huffman_decoder *offsets_tree;
} lctx;

// Sets d->cmpr_data_pos and d->cmpr_data_area_endpos, or reports an error.
static void find_cmprdata_pos(deark *c, lctx *d, struct ver_info_struct *v)
{
	if(d->errflag) return;

	d->cmpr_data_pos = d->predicted_cmpr_data_pos;

	if(d->cmpr_data_pos!=0) {
		if(d->cmpr_data_pos >= c->infile->len) {
			d->cmpr_data_pos = 0;
		}
	}

	if(d->cmpr_data_pos!=0) {
		// The first byte of compressed data can't be odd, because the first instruction must
		// be a literal.
		// This is just an extra sanity check that might improve the error message.
		if(de_getbyte(d->cmpr_data_pos) & 0x01) {
			d->cmpr_data_pos = 0;
		}
	}

	if(d->cmpr_data_pos!=0) {
		de_dbg(c, "cmpr data pos: %"I64_FMT" (%"I64_FMT" from code start)", d->cmpr_data_pos,
			d->cmpr_data_pos - d->ei->start_of_dos_code);

		if(d->data_before_decoder) {
			d->cmpr_data_area_endpos = d->ei->entry_point;
		}
		else {
			d->cmpr_data_area_endpos = d->ei->end_of_dos_code;
		}
	}

	if(d->cmpr_data_pos==0) {
		if(d->ver_detected.valid) {
			de_err(c, "Not a supported PKLITE version (reported=%s, detected=%s)",
				d->ver_reported.pklver_str, d->ver_detected.pklver_str);
		}
		else {
			de_err(c, "Not a PKLITE-compressed file, or not a supported version (%s)",
				d->ver_reported.pklver_str);
		}
		d->errflag = 1;
		d->errmsg_handled = 1;
	}
}

static void info_bytes_to_version_struct(UI ver_info, struct ver_info_struct *v)
{
	v->valid = 1;
	v->ver_num = ver_info & 0x0fff;
	v->extra_cmpr = (ver_info & 0x1000)?1:0;
	v->large_cmpr = (ver_info & 0x2000)?1:0;
	if(v->ver_num==0x100 && (ver_info & 0x4000)) v->load_high = 1;
}

// Caller first sets (at least) .valid and .ver_info
static void derive_version_fields(deark *c, lctx *d, struct ver_info_struct *v)
{
	char ver_text[16];

	if(!v->valid) {
		de_strlcpy(v->pklver_str, "unknown", sizeof(v->pklver_str));
		return;
	}

	if(v->ver_num == PKLITE_UNK_VER_NUM) {
		de_strlcpy(ver_text, "?.??", sizeof(ver_text));
	}
	else {
		de_snprintf(ver_text, sizeof(ver_text), "%u.%02u",
			(UI)(v->ver_num>>8), (UI)(v->ver_num&0xff));
	}

	de_snprintf(v->pklver_str, sizeof(v->pklver_str), "%s%s%s%s%s",
		ver_text,
		(v->suffix?v->suffix:""),
		(v->load_high?"/h":""),
		(v->large_cmpr?"/l":"/s"),
		(v->extra_cmpr?"/e":""));
}

struct ver_fingerprint_item {
	u32 crc;
	UI ver_info;
	UI flags;
	const char *suffix;
};
static const struct ver_fingerprint_item ver_fingerprint_arr[] = {
	{0xb1083464U, 0x0100, 1, "beta"},
	{0xf1ee04cfU, 0x0100, 0, "-1.03"},
	{0x4c8409f4U, 0x0105, 0, NULL},
	{0x705fd509U, 0x010c, 0, NULL},
	{0x750a2002U, 0x010d, 0, NULL},
	{0x25481db5U, 0x010e, 0, NULL},
	{0x5e3413ffU, 0x010f, 0, NULL},
	{0x1f735486U, 0x0132, 0, "-2.01"},
	{0xb5153795U, 0x110c, 0, NULL},
	{0xfa91a037U, 0x110d, 0, NULL},
	{0x9f8d6c74U, 0x1114, 0, "[ZIP2EXEv2.04c]"},
	{0xdf1595baU, 0x1114, 0, "[ZIP2EXEv2.04cReg]"}, // unconfirmed
	{0xe95a2c43U, 0x1114, 0, "[ZIP2EXEv2.04e-g]"},
	{0xa218a5f3U, 0x1114, 0, "[ZIP2EXEv2.04gReg]"},
	{0x9debdd68U, 0x1114, 0, "[ZIP2EXEv2.50]"},
	{0xc12bb6cfU, 0x2100, 1, "beta"},
	{0xd8441452U, 0x2100, 0, NULL},
	{0x77f75f9dU, 0x2103, 0, NULL},
	{0xabdd9ef2U, 0x2105, 0, NULL},
	{0x0e0e1602U, 0x210c, 0, NULL},
	{0xc51830b1U, 0x210d, 0, NULL},
	{0xbc75491dU, 0x210e, 0, NULL},
	{0xd332a6e7U, 0x210f, 0, NULL},
	{0x43eb077fU, 0x2132, 0, "-2.01"},
	{0x2892b2bdU, 0x3105, 0, NULL},
	{0xbc0ec35eU, 0x310c, 0, NULL},
	{0x61a65992U, 0x310d, 0, NULL},
	{0xd9911c85U, 0x4100, 1, "beta"}, // -l (load high) option
	{0x89cb9e7fU, 0x6100, 1, "beta"}  // -l
};

struct matchrule_struct {
	const u8 *pattern;
	size_t patlen;
	u8 result;
};

static const char *get_decoder_shape_name(u8 n)
{
	const char *name = NULL;

	switch(n) {
	case DE_PKLITE_SHAPE_BETA: name="beta"; break;
	case DE_PKLITE_SHAPE_BETA_LH: name="beta_LH"; break;
	case DE_PKLITE_SHAPE_100: name="v1.00"; break;
	case DE_PKLITE_SHAPE_112: name="v1.12"; break;
	case DE_PKLITE_SHAPE_114: name="v1.14"; break;
	case DE_PKLITE_SHAPE_150: name="v1.50"; break;
	case DE_PKLITE_SHAPE_120V2: name="v1.20var2"; break;
	case DE_PKLITE_SHAPE_120V4: name="v1.20var4"; break;
	case DE_PKLITE_SHAPE_MEGALITE: name="megalite"; break;
	case DE_PKLITE_SHAPE_UN2PACK: name="un2pack"; break;
	case DE_PKLITE_SHAPE_114LOOSE: name="v1.14_loose"; break;
	case DE_PKLITE_SHAPE_150LOOSE: name="v1.50_loose"; break;
	}
	return name?name:"?";
}

static void detect_pklite_decoder_shape(deark *c, struct fmtutil_exe_info *ei, u8 *pshape)
{
	static const u8 *shape_BETA = (const u8*)"\x2e\x8c\x1e??\x8b\x1e\x02";
	static const u8 *shape_BETA_LH = (const u8*)"\x2e\x8c\x1e??\xfc\x8c\xc8";
	static const u8 *shape_100 = (const u8*)"\xb8??\xba??\x8c\xdb\x03\xd8\x3b\x1e\x02\x00\x73\x1d\x83\xeb\x20\xfa\x8e"
		"\xd3\xbc\x00\x02\xfb\x83\xeb?\x8e\xc3\x53\xb9??\x33";
	static const u8 *shape_112 = (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x73\x1a\x2d\x20\x00\xfa\x8e\xd0"
		"\xfb\x2d?\x00\x8e\xc0\x50\xb9??\x33\xff\x57\xbe\x44";
	static const u8 *shape_114 = (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72\x1b\xb4\x09\xba\x18\x01\xcd"
		"\x21\xcd\x20";
	static const u8 *shape_150 = (const u8*)"\x50\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72?\xb4\x09\xba??\xcd\x21\xb8"
		"\x01\x4c\xcd\x21";
	static const u8 *shape_MEGALITE = (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x2d\x73\x67\x72";
	static const u8 *shape_UN2PACK = (const u8*)"\x9c\xba??\x2d??\x81\xe1?\x00\x81\xf3?\x00\xb4";
	static const u8 *shape_120V2 = (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72?\xb4\x09\xba??\xcd\x21\xb4\x4c"
		"\xcd\x21";
	static const u8 *shape_120V4 = (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x06\x02\x00\x72?\xb4\x09\xba??\xcd\x21\xb8\x01"
		"\x4c\xcd\x21";
	struct matchrule_struct matchrules[] = {
		{ shape_100, 36, DE_PKLITE_SHAPE_100 },
		{ shape_112, 36, DE_PKLITE_SHAPE_112 },
		{ shape_114, 24, DE_PKLITE_SHAPE_114 },
		{ shape_150, 28, DE_PKLITE_SHAPE_150 },
		{ shape_120V2, 26, DE_PKLITE_SHAPE_120V2 },
		{ shape_120V4, 27, DE_PKLITE_SHAPE_120V4 },
		{ shape_BETA, 8, DE_PKLITE_SHAPE_BETA },
		{ shape_BETA_LH, 8, DE_PKLITE_SHAPE_BETA_LH },
		{ shape_MEGALITE, 14, DE_PKLITE_SHAPE_MEGALITE },
		{ shape_UN2PACK, 16, DE_PKLITE_SHAPE_UN2PACK },
		{ shape_114, 14, DE_PKLITE_SHAPE_114LOOSE },
		{ shape_150, 10, DE_PKLITE_SHAPE_150LOOSE }
	};
	size_t i;
	u8 buf[36];

	*pshape = 0;
	de_read(buf, ei->entry_point, 36);

	for(i=0; i<DE_ARRAYCOUNT(matchrules); i++) {
		if(de_memmatch(buf, matchrules[i].pattern, matchrules[i].patlen, '?', 0)) {
			*pshape = matchrules[i].result;
			goto done;
		}
	}

done:
	;
}

static void detect_pklite_version_part1(deark *c, lctx *d, struct de_crcobj *crco)
{
	u32 crc1;
	size_t i;
	const struct ver_fingerprint_item *fi = NULL;

	de_crcobj_reset(crco);
	de_crcobj_addslice(crco, c->infile, d->ei->entry_point+80, 240);
	crc1 = de_crcobj_getval(crco);
	de_dbg3(c, "CRC fingerprint: %08x", (UI)crc1);

	for(i=0; i<DE_ARRAYCOUNT(ver_fingerprint_arr); i++) {
		if(ver_fingerprint_arr[i].crc==crc1) {
			fi = &ver_fingerprint_arr[i];
			break;
		}
	}

	if(fi) {
		info_bytes_to_version_struct(fi->ver_info, &d->ver_detected);
		d->ver_detected.extra_cmpr_confidence = 95;
		d->ver_detected.suffix = fi->suffix;
		d->ver_detected.is_beta = (fi->flags & 0x1)?1:0;

		if((d->ver_detected.ver_num)==0x10c && !d->ver_detected.suffix) {
			if(!dbuf_memcmp(c->infile, 45, "90-92 PK", 8)) {
				d->ver_detected.suffix = "[fake v1.20]";
			}
		}
	}
}

// Try to detect versions 110e, 310e, 110f, 310f.
// These are among the versions that have most of the decompression code obfuscated.
static void detect_pklite_version_part2(deark *c, lctx *d, struct de_crcobj *crco)
{
	u32 crc2;
	u8 b;
	i64 pos;

	pos = d->ei->entry_point+13;
	if(de_getbyte_p(&pos) != 0x72) goto done;
	b = de_getbyte(pos);
	// This byte seems to locate the end of the "Not enough memory" message.
	// We want to fingerprint some bytes right after that.
	pos += (i64)b;

	de_crcobj_reset(crco);
	de_crcobj_addslice(crco, c->infile, pos, 30);
	crc2 = de_crcobj_getval(crco);
	de_dbg3(c, "CRC2: %08x", (UI)crc2);
	switch(crc2) {
	case 0x40d95670U: d->ver_detected.ver_num = 0x10e; break; // 110e
	case 0xd388219aU: d->ver_detected.ver_num = 0x10f; break; // 110f
	case 0x9d8d46f8U: d->ver_detected.ver_num = 0x10e; break; // 310e
	case 0xda594188U: d->ver_detected.ver_num = 0x10f; break; // 310f
	default: goto done;
	}

	d->ver_detected.valid = 1;
	d->ver_detected.extra_cmpr = 1;
	d->ver_detected.extra_cmpr_confidence = 90;
	// d->ver_detected.large_cmpr will be determined later

done:
	;
}

// Try to detect versions 1132, 3132, 1201, 3201.
static void detect_pklite_version_part3(deark *c, lctx *d, struct de_crcobj *crco)
{
	u32 crc3;
	u8 b;
	i64 pos;

	if(de_getbyte(d->ei->entry_point) != 0x50) goto done;
	pos = d->ei->entry_point+58;
	de_crcobj_reset(crco);
	de_crcobj_addslice(crco, c->infile, pos, 16);
	de_crcobj_addslice(crco, c->infile, pos+18, 10);
	crc3 = de_crcobj_getval(crco);
	de_dbg3(c, "CRC3: %08x", (UI)crc3);
	if(crc3 != 0xff6f0596U) goto done;

	b = de_getbyte(pos+29);
	if(b==0x00) {
		d->ver_detected.ver_num = 0x132; // 1132 or 1201
	}
	else if(b==0x01) {
		d->ver_detected.ver_num = 0x132; // 3132 or 3201
	}
	else {
		goto done;
	}
	d->ver_detected.valid = 1;
	d->ver_detected.extra_cmpr = 1;
	d->ver_detected.extra_cmpr_confidence = 60;
	d->ver_detected.suffix = "-2.01";

done:
	;
}

// len is assumed to be a multiple of 2
static void descramble_decoder_section(dbuf *inf, i64 pos1, i64 len, dbuf *outf)
{
	i64 i;
	i64 pos = pos1;
	u8 prev_b0;
	u8 prev_b1;
	u8 b0, b1;

	prev_b0 = dbuf_getbyte(inf, pos-2);
	prev_b1 = dbuf_getbyte(inf, pos-1);
	for(i=0; i<len; i+=2) {
		b0 = dbuf_getbyte_p(inf, &pos);
		b1 = dbuf_getbyte_p(inf, &pos);
		dbuf_writebyte(outf, (b0^prev_b0));
		dbuf_writebyte(outf, (b1^prev_b1));
		prev_b0 = b0;
		prev_b1 = b1;
	}
}

// Detection by searching for the distinctive lookup table(?) byte pattern at
// the end of the decoder.
// In v1.14+ with -e, this section of the code is scrambled, so we descramble
// it and search that as well.
static void detect_pklite_version_part4(deark *c, lctx *d)
{
	int found = 0;
	int scrambled = 0;

#define PART4_NEEDLE_LEN 21
	static const u8 *str = (const u8*)"\x01\x02\x00\x00\x03\x04\x05\x06"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x07\x08\x09\x0a\x0b";
	i64 foundpos_abs = 0;
	u8 prec_b;
	u8 is_beta;
	u8 large_cmpr;
	u8 extra_cmpr;
	u8 extra_cmpr_confidence = 0;
	int ret;
	dbuf *tmpdbuf = NULL;

	is_beta = d->data_before_decoder;

// offset from entry point (note - load-high files have the earliest starting pos)
#define PART4_HAYSTACK_START 336
#define PART4_HAYSTACK_LEN (832-PART4_HAYSTACK_START)

	ret = dbuf_search(c->infile, str, PART4_NEEDLE_LEN,
		d->ei->entry_point+PART4_HAYSTACK_START, PART4_HAYSTACK_LEN, &foundpos_abs);
	if(ret) {
		prec_b = de_getbyte(foundpos_abs-1);
	}
	if(!ret) {
		i64 foundpos2 = 0;

		tmpdbuf = dbuf_create_membuf(c, 0, 0);
		dbuf_enable_wbuffer(tmpdbuf);
		descramble_decoder_section(c->infile, d->ei->entry_point+PART4_HAYSTACK_START,
			PART4_HAYSTACK_LEN, tmpdbuf);
		dbuf_flush(tmpdbuf);
		ret = dbuf_search(tmpdbuf, str, PART4_NEEDLE_LEN, 0, tmpdbuf->len, &foundpos2);
		if(ret) {
			foundpos_abs = d->ei->entry_point+PART4_HAYSTACK_START+foundpos2;
			prec_b = dbuf_getbyte(tmpdbuf, foundpos2-1);
			scrambled = 1;
		}
	}
	if(!ret) {
		goto done;
	}

	if(prec_b==0x09) {
		large_cmpr = 0;
	}
	else if(prec_b==0x18) {
		large_cmpr = 1;
	}
	else {
		goto done;
	}
	found = 1;

	// Try to figure out if extra compression was used

	if(scrambled) {
		extra_cmpr = 1;
		extra_cmpr_confidence = 100;
		goto after_extra_cmpr;
	}

	if(d->decoder_shape==DE_PKLITE_SHAPE_114 || d->decoder_shape==DE_PKLITE_SHAPE_150 ||
		d->decoder_shape==DE_PKLITE_SHAPE_114LOOSE || d->decoder_shape==DE_PKLITE_SHAPE_150LOOSE ||
		d->decoder_shape==DE_PKLITE_SHAPE_MEGALITE)
	{
		extra_cmpr = 0;
		extra_cmpr_confidence = 70;
		goto after_extra_cmpr;
	}

	if(d->decoder_shape==DE_PKLITE_SHAPE_100 || d->decoder_shape==DE_PKLITE_SHAPE_112) {
		UI nn;

		if(d->decoder_shape==DE_PKLITE_SHAPE_100) {
			nn = (UI)de_getu16le(d->ei->entry_point+33);
		}
		else {
			nn = (UI)de_getu16le(d->ei->entry_point+29);
		}

		switch(nn) {
		case 0x00c3: case 0x00c4: case 0x0122: case 0x0123:
			extra_cmpr = 0;
			extra_cmpr_confidence = 55;
			goto after_extra_cmpr;
		case 0x00c7: case 0x00c8: case 0x0125: case 0x0126:
			extra_cmpr = 1;
			extra_cmpr_confidence = 55;
			goto after_extra_cmpr;
		}
	}

	if(d->ei->start_of_dos_code>=80 && d->ei->start_of_dos_code<=96) {
		extra_cmpr = 1;
		extra_cmpr_confidence = 50;
	}
	else {
		extra_cmpr = 0;
		extra_cmpr_confidence = 30;
	}

after_extra_cmpr:

	// The compressed code presumably starts at the first multiple of 16 after
	// the end of the table. But unfortunately the table doesn't always end in
	// a consistent way.
	// The end of the table is usually at +23, but for v1.14-e it seems
	// to be at +21, and for v1.50+ w/o -e it might be +24.
	// It happens that for every file I've seen, both +23 and +24 work. (The only
	// files that are aligned such that it would make a difference are from
	// v1.00beta, and for that version it's irrelevant.)
	// But there could be files out there for which one or the other doesn't work.
	if(is_beta) {
		d->predicted_cmpr_data_pos = d->ei->start_of_dos_code;
	}
	else {
		d->predicted_cmpr_data_pos = de_pad_to_n(foundpos_abs+23, 16);
	}

	if(!d->ver_detected.valid) {
		if(is_beta) {
			d->ver_detected.ver_num = 0x100;
			d->ver_detected.suffix = "beta";
			d->ver_detected.is_beta = 1;
		}
		else {
			d->ver_detected.ver_num = PKLITE_UNK_VER_NUM;
		}
		d->ver_detected.valid = 1;
	}

	d->ver_detected.large_cmpr = large_cmpr;

	if(extra_cmpr_confidence >  d->ver_detected.extra_cmpr_confidence) {
		d->ver_detected.extra_cmpr = extra_cmpr;
		d->ver_detected.extra_cmpr_confidence = extra_cmpr_confidence;
	}

done:
	de_dbg2(c, "tables found: %d", found);
	if(found) {
		de_dbg2(c, "tables scrambled: %d", scrambled);
	}
	dbuf_close(tmpdbuf);
}

static void detect_pklite_version(deark *c, lctx *d)
{
	struct de_crcobj *crco = NULL;

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	detect_pklite_decoder_shape(c, d->ei, &d->decoder_shape);
	de_dbg(c, "decompressor class: %s", get_decoder_shape_name(d->decoder_shape));

	detect_pklite_version_part1(c, d, crco);

	if(!d->ver_detected.valid) {
		detect_pklite_version_part2(c, d, crco);
	}

	if(!d->ver_detected.valid) {
		detect_pklite_version_part3(c, d, crco);
	}

	detect_pklite_version_part4(c, d);

	derive_version_fields(c, d, &d->ver_detected);

	de_crcobj_destroy(crco);
}

// Read what we need, before we can decompress
static void do_read_header_and_detect_version(deark *c, lctx *d)
{
	UI ver_info;

	//d->ver_reported.
	ver_info = (UI)de_getu16le(28);
	info_bytes_to_version_struct(ver_info, &d->ver_reported);
	d->ver_reported.extra_cmpr_confidence = 10;
	//.valid = 1;
	derive_version_fields(c, d, &d->ver_reported);

	de_dbg(c, "reported PKLITE version: %s", d->ver_reported.pklver_str);

	if(de_getbyte(d->ei->entry_point)==0x2e && (d->ei->entry_point > d->ei->start_of_dos_code)) {
		d->data_before_decoder = 1;
	}
	de_dbg(c, "start of executable code: %"I64_FMT, d->ei->start_of_dos_code);

	detect_pklite_version(c, d);
	de_dbg(c, "detected PKLITE version: %s", d->ver_detected.pklver_str);
	if(d->ver_detected.valid) {
		d->ver = d->ver_detected; // struct copy
	}
	else {
		d->ver = d->ver_reported;
	}
}

static void fill_bitbuf(deark *c, lctx *d)
{
	UI i;

	if(d->errflag) return;
	if(d->dcmpr_cur_ipos+2 > c->infile->len) {
		de_err(c, "Unexpected end of file during decompression");
		d->errflag = 1;
		d->errmsg_handled = 1;
		return;
	}

	for(i=0; i<2; i++) {
		u8 b;
		b = de_getbyte_p(&d->dcmpr_cur_ipos);
		de_bitbuf_lowlevel_add_byte(&d->bbll, b);
	}
}

static u8 pklite_getbit(deark *c, lctx *d)
{
	u8 v;

	if(d->errflag) return 0;
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

static void make_matchlengths_tree(deark *c, lctx *d)
{
	static const u8 matchlength_codelengths_lg[24] = {
		2, 2, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8,
		8, 9, 9, 9, 9, 9, 9, 6
	};
	static const u8 matchlength_codes_lg[24] = {
		2,3,0,2,3,4,10,11,12,26,27,58,59,60,122,123,
		124,250,251,252,253,254,255,28
	};
	static const u8 matchlength_codelengths_sm[9] = {
		3, 2, 3, 3, 4, 4, 4, 4, 3
	};
	static const u8 matchlength_codes_sm[9] = {
		2, 0, 4, 5, 12, 13, 14, 15, 3
	};
	static const u8 *ml_codelengths;
	static const u8 *ml_codes;
	i64 i;
	i64 num_codes;

	if(d->lengths_tree) return;
	if(d->ver.large_cmpr) {
		num_codes = (i64)DE_ARRAYCOUNT(matchlength_codelengths_lg);
		ml_codelengths = matchlength_codelengths_lg;
		ml_codes = matchlength_codes_lg;
	}
	else {
		num_codes = (i64)DE_ARRAYCOUNT(matchlength_codelengths_sm);
		ml_codelengths = matchlength_codelengths_sm;
		ml_codes = matchlength_codes_sm;
	}

	d->lengths_tree = fmtutil_huffman_create_decoder(c, num_codes, num_codes);

	for(i=0; i<num_codes; i++) {
		fmtutil_huffman_add_code(c, d->lengths_tree->bk, ml_codes[i], ml_codelengths[i],
			(fmtutil_huffman_valtype)i);
	}
}

static void make_offsets_tree(deark *c, lctx *d)
{
	i64 i;
	UI curr_len = 1;
	fmtutil_huffman_valtype curr_code = 1;

	if(d->offsets_tree) return;
	d->offsets_tree = fmtutil_huffman_create_decoder(c, 32, 32);

	for(i=0; i<32; i++) {
		// Are we at a place where we adjust our counters?
		if(i==1) {
			curr_len = 4;
			curr_code = 0;
		}
		else if(i==3) {
			curr_len++;
			curr_code = 4;
		}
		else if(i==7) {
			curr_len++;
			curr_code = 16;
		}
		else if(i==14) {
			curr_len++;
			curr_code = 46;
		}

		fmtutil_huffman_add_code(c, d->offsets_tree->bk, curr_code, curr_len,
			(fmtutil_huffman_valtype)i);
		curr_code++;
	}
}

static UI read_pklite_code_using_tree(deark *c, lctx *d, struct fmtutil_huffman_decoder *ht)
{
	int ret;
	fmtutil_huffman_valtype val = 0;

	while(1) {
		u8 b;

		b = pklite_getbit(c, d);
		if(d->errflag) goto done;

		ret = fmtutil_huffman_decode_bit(ht->bk, ht->cursor, b, &val);
		if(ret==1) goto done; // finished the code
		if(ret!=2) {
			d->errflag = 1;
			goto done;
		}
	}
done:
	return val;
}

static void do_decompress(deark *c, lctx *d)
{
	struct de_lz77buffer *ringbuf = NULL;
	u8 b;
	UI value_of_special_code;
	UI large_matchlen_bias;

	de_dbg(c, "decompressing cmpr code at %"I64_FMT, d->cmpr_data_pos);
	de_dbg_indent(c, 1);

	if(d->ver.large_cmpr) {
		value_of_special_code = 23;
		large_matchlen_bias = 25;
	}
	else {
		value_of_special_code = 8;
		large_matchlen_bias = 10;
	}

	make_matchlengths_tree(c, d);
	make_offsets_tree(c, d);

	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);
	dbuf_set_length_limit(d->o_dcmpr_code, 1048576);
	dbuf_enable_wbuffer(d->o_dcmpr_code);

	ringbuf = de_lz77buffer_create(c, 8192);
	ringbuf->userdata = (void*)d;
	ringbuf->writebyte_cb = my_lz77buf_writebytecb;

	d->dcmpr_cur_ipos = d->cmpr_data_pos;
	d->bbll.is_lsb = 1;
	de_bitbuf_lowlevel_empty(&d->bbll);

	fill_bitbuf(c, d);

	while(1) {
		u8 x;
		UI len_raw;
		UI matchlen;
		UI offs_hi_bits;
		u8 offs_lo_byte;
		UI matchpos;

		if(d->errflag) goto after_dcmpr;

		x = pklite_getbit(c, d);
		if(x==0) {
			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			if(d->ver.extra_cmpr) {
				b ^= (u8)(d->bbll.nbits_in_bitbuf);
			}
			if(c->debug_level>=3) {
				de_dbg3(c, "lit 0x%02x", (UI)b);
			}
			de_lz77buffer_add_literal_byte(ringbuf, b);
			continue;
		}

		len_raw = read_pklite_code_using_tree(c, d, d->lengths_tree);
		if(d->errflag) goto after_dcmpr;

		if(len_raw==value_of_special_code) {
			b = de_getbyte_p(&d->dcmpr_cur_ipos);

			if(b >= 0xfd) {
				if(b==0xfe && d->ver.large_cmpr) {
					// Just a no-op?
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
			matchlen = (UI)b+large_matchlen_bias;
		}
		else {
			matchlen = len_raw+2;
		}

		if(matchlen==2) {
			offs_hi_bits = 0;
		}
		else {
			offs_hi_bits = read_pklite_code_using_tree(c, d, d->offsets_tree);
		}

		offs_lo_byte = de_getbyte_p(&d->dcmpr_cur_ipos);
		if(d->errflag) goto after_dcmpr;

		matchpos = (offs_hi_bits<<8) | (UI)offs_lo_byte;

		if(c->debug_level>=3) {
			de_dbg3(c, "match pos=%u len=%u", matchpos, matchlen);
		}

		// PKLITE confirmed to use distances 1 to 8191. Have not observed matchpos=0.
		// Have not observed it to use distances larger than the number of bytes
		// decompressed so far.
		if(matchpos==0 || (i64)matchpos>d->o_dcmpr_code_nbytes_written) {
			de_err(c, "Bad or unsupported compressed data (dist=%u, expected 1 to %"I64_FMT")",
				matchpos, d->o_dcmpr_code_nbytes_written);
			d->errflag = 1;
			d->errmsg_handled = 1;
			goto after_dcmpr;
		}
		de_lz77buffer_copy_from_hist(ringbuf,
				(UI)(ringbuf->curpos-matchpos), matchlen);
	}

after_dcmpr:
	if(!d->o_dcmpr_code) goto done;
	dbuf_flush(d->o_dcmpr_code);

	if(!d->errflag) {
		d->cmpr_data_endpos = d->dcmpr_cur_ipos;
		de_dbg(c, "cmpr data end: %"I64_FMT, d->cmpr_data_endpos);
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
			d->cmpr_data_endpos-d->cmpr_data_pos, d->o_dcmpr_code->len);
	}

done:
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
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
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
	de_dbg(c, "reading 'long' reloc table at %"I64_FMT, pos1);
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
			offs = de_getu16le_p(&pos);
			de_dbg2(c, "offs: 0x%04x", (UI)offs);
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
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

	d->o_reloc_table = dbuf_create_membuf(c, 0, 0);

	reloc_tbl_len = d->cmpr_data_area_endpos - 8 - d->cmpr_data_endpos;

	if(d->ver.extra_cmpr /* && d->ver.ver_only>=0x10c */) {
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

	pos = d->ei->entry_point;
	b = de_getbyte_p(&pos);
	if(b==0x50) {
		b = de_getbyte_p(&pos);
	}
	if(b==0xb8) {
		// This is not always exactly right. Not sure that's possible.
		n = de_getu16le_p(&pos);
		n = (n<<4) + 0x100 - d->o_dcmpr_code->len;
		if(n>=0) {
			*pminmem = (n+0xf)>>4;
		}
	}
}

static void do_write_data_only(deark *c, lctx *d)
{
	if(!d->o_dcmpr_code) return;

	de_info(c, "Low-level decompression may have succeeded, but something else failed. "
		"Writing the decompressed code only.");
	dbuf_create_file_from_slice(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, "bin", NULL, 0);
}

// Generate the decompressed file
static void do_write_dcmpr(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 amt_to_copy;
	i64 overlay_len;

	if(d->errflag || !d->o_ei || !d->o_orig_header || !d->o_dcmpr_code || !d->o_reloc_table) return;
	de_dbg(c, "generating decompressed EXE file");
	de_dbg_indent(c, 1);

	outf = dbuf_create_output_file(c, "exe", NULL, 0);
	d->wrote_exe = 1;

	// Write the original header, up to the relocation table
	amt_to_copy = de_min_int(d->o_orig_header->len, d->o_ei->reloc_table_pos);
	dbuf_copy(d->o_orig_header, 0, amt_to_copy, outf);
	dbuf_truncate(outf, d->o_ei->reloc_table_pos);

	// Write the relocation table
	dbuf_copy(d->o_reloc_table, 0, d->o_reloc_table->len, outf);

	// Pad up to the start of DOS code.
	// (Note that PKLITE does not record data between the end of the relocation
	// table, and the start of DOS code, so we can't reconstruct that.)
	dbuf_truncate(outf, d->o_ei->start_of_dos_code);

	// Write the decompressed program code
	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	// "Overlay" segment
	overlay_len = c->infile->len - d->ei->end_of_dos_code;
	if(overlay_len>0) {
		dbuf_copy(c->infile, d->ei->end_of_dos_code, overlay_len, outf);
	}

	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

// Try to read the copy of the original EXE header, into d->o_orig_header.
// Returns 0 if it doesn't exist, or if it seems bad.
static int read_orig_header(deark *c, lctx *d)
{
	i64 orig_hdr_len;
	i64 orig_reloc_pos;
	i64 n1, n2;
	int retval = 0;
	i64 dcmpr_bytes_expected;
	i64 orig_hdr_pos;
	int may_need_warning = 0;

	orig_hdr_pos = d->ei->reloc_table_pos + 4*d->ei->num_relocs;

	if(d->ei->start_of_dos_code - orig_hdr_pos < 26) {
		goto done;
	}
	else if(d->ver.ver_num>=0x10a && d->ver.extra_cmpr) {
		goto done;
	}

	may_need_warning = 1;

	orig_hdr_len = d->ei->start_of_dos_code - orig_hdr_pos; // tentative
	// Peek at the reloc table offs field to figure out how much to read
	orig_reloc_pos = de_getu16le(orig_hdr_pos + 22);
	if(orig_reloc_pos>=28 && orig_reloc_pos<2+orig_hdr_len) {
		orig_hdr_len = orig_reloc_pos-2;
	}

	de_dbg(c, "orig. hdr: at %"I64_FMT", len=(2+)%"I64_FMT, orig_hdr_pos, orig_hdr_len);

	n1 = de_getu16le(orig_hdr_pos); // len of final block
	n2 = de_getu16le(orig_hdr_pos+2); // numBlocks
	if(n1>511 || n2==0) {
		goto done;
	}

	dbuf_copy(c->infile, orig_hdr_pos, orig_hdr_len, d->o_orig_header);

	fmtutil_collect_exe_info(c, d->o_orig_header, d->o_ei);
	if(d->o_ei->reloc_table_pos<28) {
		d->o_ei->reloc_table_pos = 28;
	}

	if((d->o_ei->regSS != d->footer.regSS) ||
		(d->o_ei->regSP != d->footer.regSP) ||
		(d->o_ei->regCS != d->footer.regCS) ||
		(d->o_ei->regIP != d->footer.regIP))
	{
		goto done;
	}

	if(d->o_ei->num_relocs != (d->o_reloc_table->len / 4)) {
		goto done;
	}

	dcmpr_bytes_expected = d->o_ei->end_of_dos_code - d->o_ei->start_of_dos_code;

	if(d->o_dcmpr_code->len != dcmpr_bytes_expected) {
		de_warn(c, "Expected %"I64_FMT" decompressed bytes, got %"I64_FMT, dcmpr_bytes_expected,
			d->o_dcmpr_code->len);
	}

	retval = 1;
done:
	if(retval==0 && may_need_warning) {
		de_warn(c, "Original header seems bad. Ignoring it.");
	}
	return retval;
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
	if(d->o_orig_header->len!=2 || !d->footer_pos) {
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

	num_relocs = d->o_reloc_table->len / 4;
	start_of_dos_code = de_pad_to_n(reloc_table_start + num_relocs*4, 16);
	end_of_dos_code = start_of_dos_code + d->o_dcmpr_code->len;
	dbuf_writeu16le(d->o_orig_header, end_of_dos_code%512);
	dbuf_writeu16le(d->o_orig_header, (end_of_dos_code+511)/512);
	dbuf_writeu16le(d->o_orig_header, num_relocs);
	dbuf_writeu16le(d->o_orig_header, start_of_dos_code/16);
	dbuf_writeu16le(d->o_orig_header, minmem);
	dbuf_writeu16le(d->o_orig_header, maxmem);
	dbuf_writei16le(d->o_orig_header, d->footer.regSS);
	dbuf_writeu16le(d->o_orig_header, d->footer.regSP);
	dbuf_writeu16le(d->o_orig_header, 0); // checksum
	dbuf_writeu16le(d->o_orig_header, d->footer.regIP);
	dbuf_writei16le(d->o_orig_header, d->footer.regCS);
	dbuf_writeu16le(d->o_orig_header, reloc_table_start);
	dbuf_writeu16le(d->o_orig_header, 0); // overlay indicator

	fmtutil_collect_exe_info(c, d->o_orig_header, d->o_ei);
}

// Either copy the original header, or if we can't do that,
// construct a new EXE header from other information.
// Creates and populates d->o_orig_header, d->o_ei
static void acquire_new_exe_header(deark *c, lctx *d)
{
	int ret;

	d->o_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	d->o_orig_header =  dbuf_create_membuf(c, 0, 0);
	dbuf_writeu16le(d->o_orig_header, 0x5a4d); // "MZ"

	ret = read_orig_header(c, d);
	if(ret) goto done; // If success, we're done. Otherwise try other method.

	dbuf_truncate(d->o_orig_header, 2);
	reconstruct_header(c, d);
done:
	;
}

static void do_pklite_exe(deark *c, lctx *d)
{
	struct fmtutil_specialexe_detection_data edd;

	fmtutil_collect_exe_info(c, c->infile, d->ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_PKLITE;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(edd.detected_fmt==DE_SPECIALEXEFMT_PKLITE) {
		de_declare_fmt(c, "PKLITE-compressed EXE");
	}
	else if(c->module_disposition==DE_MODDISP_EXPLICIT) {
		de_warn(c, "This might not be a PKLITE-compressed EXE file");
	}

	do_read_header_and_detect_version(c, d);
	if(d->errflag) goto done;
	find_cmprdata_pos(c, d, &d->ver);
	if(d->errflag) goto done;
	do_decompress(c, d);
	dbuf_flush(d->o_dcmpr_code);
	if(d->errflag) goto done;
	d->dcmpr_ok = 1;

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

		// Expecting 8, but some v2.x files have seem to have larger footers (10,
		// 11, 20, ...). Don't know why.
		if(footer_capacity<8 || footer_capacity>100) {
			// Not sure we have a valid footer.
			d->footer_pos = 0;
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

static int detect_pklite_com_quick(dbuf *f, i64 *pverpos, i64 *pdatapos)
{
	u8 b[10];

	dbuf_read(f, b, 0, sizeof(b));
	if(b[0]==0xb8 && b[3]==0xba && b[6]==0x3b && b[7]==0xc4) {
		if(b[9]==0x67) { // Probably v1.00-1.14
			*pverpos = 44;
			*pdatapos = 448;
			return 1;
		}
		else if(b[9]==0x69) { // Probably v1.15 (usually mislabeled as 1.14)
			*pverpos = 46;
			*pdatapos = 450;
			return 1;
		}
	}
	else if(b[0]==0x50 && b[1]==0xb8 && b[4]==0xba && b[7]==0x3b) {
		*pverpos = 46; // v1.50-2.01
		*pdatapos = 464;
		return 1;
	}
	else if(b[0]==0xba && b[3]==0xa1 && b[6]==0x2d && b[7]==0x20) {
		*pverpos = 36; // v1.00beta
		*pdatapos = 500;
		return 1;
	}
	return 0;
}

static void read_and_process_com_version_number(deark *c, lctx *d, i64 verpos)
{
	const char *s = "?";

	d->ver.extra_cmpr = 0;
	d->ver.large_cmpr = 0;

	de_dbg(c, "version number pos: %"I64_FMT, verpos);
	d->ver_reported.ver_num = (UI)de_getu16le(verpos);
	d->ver_reported.ver_num &= 0xfff;
	d->ver_reported.valid = 1;

	de_dbg(c, "reported PKLITE version: %u.%02u",
		(UI)((d->ver_reported.ver_num&0xf00)>>8),
		(UI)(d->ver_reported.ver_num&0x00ff));

	if(d->cmpr_data_pos==500) {
		s = "1.00beta";
	}
	else if(d->cmpr_data_pos==448) {
		switch(de_getbyte(260)) {
		case 0x1d: s = "1.00-1.03"; break;
		case 0x1c: s = "1.05-1.14"; break;
		default: s = "1.00-1.14"; break;
		}
	}
	else if(d->cmpr_data_pos==450) {
		s = "1.15";
	}
	else if(d->cmpr_data_pos==464) {
		s = "1.50-2.01";
	}

	de_strlcpy(d->ver_detected.pklver_str, s, sizeof(d->ver_detected.pklver_str));
	de_dbg(c, "detected PKLITE version: %s", d->ver_detected.pklver_str);
}

static void do_pklite_com(deark *c, lctx *d)
{
	i64 verpos = 0;

	if(!detect_pklite_com_quick(c->infile, &verpos, &d->cmpr_data_pos)) {
		de_err(c, "Not a known/supported PKLITE format");
		goto done;
	}

	d->is_com = 1;
	d->ei->f = c->infile;
	de_declare_fmt(c, "PKLITE-compressed COM");

	read_and_process_com_version_number(c, d, verpos);

	if(c->module_disposition==DE_MODDISP_AUTODETECT) {
		// Check if the user requested that we not do executable decompression.
		// This feels like a hack. I'm not sure how it should work.
		if(de_get_ext_option_bool(c, "execomp", 1) == 0) {
			goto done;
		}
	}

	// TODO: COM support was added in a way that's a bit of a hack. Ought to clean
	// it up.
	do_decompress(c, d);
	if(!d->o_dcmpr_code) goto done;
	dbuf_flush(d->o_dcmpr_code);
	if(d->errflag) goto done;
	d->dcmpr_ok = 1;

	dbuf_create_file_from_slice(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, "com", NULL, 0);
done:
	;
}

static void de_run_pklite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u8 buf[2];

	d = de_malloc(c, sizeof(lctx));
	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

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

		if(!d->is_com && d->dcmpr_ok && !d->wrote_exe) {
			do_write_data_only(c, d);
		}

		dbuf_close(d->o_orig_header);
		dbuf_close(d->o_reloc_table);
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d->o_ei);
		de_free(c, d->ei);
		fmtutil_huffman_destroy_decoder(c, d->lengths_tree);
		fmtutil_huffman_destroy_decoder(c, d->offsets_tree);
		de_free(c, d);
	}
}

// By design, only detects COM format.
// EXE files are handled by the "exe" module by default.
static int de_identify_pklite(deark *c)
{
	i64 verpos, datapos;

	 if(detect_pklite_com_quick(c->infile, &verpos, &datapos)) {
		 if(pklite_com_has_copyright_string(c->infile, verpos)) {
			 return 100;
		 }
		 // TODO: False positives may be possible. Maybe we should be more
		 // discriminating.
		 return 15;
	 }
	 return 0;
}

void de_module_pklite(deark *c, struct deark_module_info *mi)
{
	mi->id = "pklite";
	mi->desc = "PKLITE-compressed EXE/COM";
	mi->run_fn = de_run_pklite;
	mi->identify_fn = de_identify_pklite;
}
