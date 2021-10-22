// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress PKLITE executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pklite);

struct ver_info_struct {
	u8 valid;
	u8 isbeta;
	UI ver_info; // e.g. 0x3103 = 1.03/l/e
	const char *suffix;

	UI ver_only; // e.g. 0x103 = 1.03
	u8 extra_cmpr;
	u8 large_cmpr;
	u8 load_high;
	char pklver_str[32];
};

typedef struct localctx_struct {
	struct ver_info_struct ver_reported;
	struct ver_info_struct ver_detected;
	struct ver_info_struct ver;

	struct fmtutil_exe_info *ei; // For the PKLITE file
	struct fmtutil_exe_info *o_ei; // For the decompressed file
	u8 have_orig_header;
	u8 uncompressed_region;
	u8 dcmpr_ok;
	u8 wrote_exe;
	i64 cmpr_data_pos;
	i64 cmpr_data_endpos;
	i64 footer_pos;

	int errflag;
	int errmsg_handled;
	dbuf *o_orig_header;
	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;

	struct fmtutil_huffman_decoder *lengths_tree;
	struct fmtutil_huffman_decoder *offsets_tree;
} lctx;

static void find_offset_2132(deark *c, lctx *d)
{
	i64 n;

	n = de_getu16le(d->ei->entry_point+72);
	n = ((n*2+98)>>4)<<4;
	d->cmpr_data_pos = d->ei->entry_point + n;
}

static void find_offset_3132(deark *c, lctx *d)
{
	i64 n;

	// This is guesswork, with a hint from mz-explode that the byte @89 is
	// important (but mz-explode's formula doesn't seem to work).
	n = de_getu16le(d->ei->entry_point+89);
	n = n>>4;
	if(n<0x0f) return;
	n = (n-0x0f)<<4;
	d->cmpr_data_pos = d->ei->entry_point + n;
}

// Sets d->cmpr_data_pos, or reports an error.
static void find_cmprdata_pos(deark *c, lctx *d, struct ver_info_struct *v)
{
	int unsupp_ver_flag = 0;
	UI adj_ver = v->ver_info;

	if(d->errflag) return;
	if(!v->valid || v->isbeta) {
		unsupp_ver_flag = 1;
		goto done;
	}

	// Try to handle some versions we can't fully detect.
	if(adj_ver>=0x1132 && adj_ver<=0x1201) {
		adj_ver = 0x1132;
	}
	else if(adj_ver>=0x3132 && adj_ver<=0x3201) {
		adj_ver = 0x3132;
	}

	switch(adj_ver) {
	case 0x0100: case 0x0103: case 0x0105:
	case 0x010c: case 0x010d: case 0x010e: case 0x010f:
		d->cmpr_data_pos = d->ei->entry_point + 0x1d0;
		break;
	case 0x0132: case 0x0201:
		find_offset_2132(c, d);
		break;
	case 0x110c: case 0x110d:
		d->cmpr_data_pos = d->ei->entry_point + 0x1e0;
		break;
	case 0x110e: case 0x110f:
		d->cmpr_data_pos = d->ei->entry_point + 0x200;
		break;
	case 0x1132: case 0x1201:
		find_offset_3132(c, d);
		break;
	case 0x2100: case 0x2103: case 0x2105: case 0x210a:
	case 0x210c: case 0x210d: case 0x210e: case 0x210f:
		d->cmpr_data_pos = d->ei->entry_point + 0x290;
		break;
	case 0x2132: case 0x2201:
		find_offset_2132(c, d);
		break;
	case 0x310c: case 0x310d:
		d->cmpr_data_pos = d->ei->entry_point + 0x290;
		break;
	case 0x310e: case 0x310f:
		d->cmpr_data_pos = d->ei->entry_point + 0x2c0;
		break;
	case 0x3132: case 0x3201:
		find_offset_3132(c, d);
		break;
	default:
		unsupp_ver_flag = 1;
	}

done:
	if(d->errflag) return;

	if(d->uncompressed_region) {
		// TODO: Detect if uncompressed regions are used.
		d->cmpr_data_pos = 0;
	}

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
		de_dbg(c, "cmpr data pos: %"I64_FMT, d->cmpr_data_pos);
	}

	if(unsupp_ver_flag) {
		de_err(c, "This PKLITE version (%s) is not supported", d->ver.pklver_str);
		d->errflag = 1;
		d->errmsg_handled = 1;
	}
	else if(d->cmpr_data_pos==0) {
		de_err(c, "Can't figure out where the compressed data starts. "
			"This variety of PKLITE is not supported.");
		d->errflag = 1;
		d->errmsg_handled = 1;
	}
}

// Caller first sets (at least) .valid and .ver_info
static void derive_version_fields(deark *c, lctx *d, struct ver_info_struct *v)
{
	if(!v->valid) {
		de_strlcpy(v->pklver_str, "unknown", sizeof(v->pklver_str));
		return;
	}

	v->ver_only = v->ver_info & 0x0fff;
	if(v->ver_only==0x100) {
		v->ver_info &= 0x7fff;
	}
	else {
		v->ver_info &= 0x3fff;
	}
	v->extra_cmpr = (v->ver_info & 0x1000)?1:0;
	v->large_cmpr = (v->ver_info & 0x2000)?1:0;
	if(v->ver_only==0x100 && (v->ver_info & 0x4000)) v->load_high = 1;
	de_snprintf(v->pklver_str, sizeof(v->pklver_str), "%u.%02u%s%s%s%s",
		(UI)(v->ver_only>>8), (UI)(v->ver_only&0xff),
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
	{0xc12bb6cfU, 0x2100, 1, "beta"},
	{0xd8441452U, 0x2100, 0, NULL},
	{0x77f75f9dU, 0x2103, 0, NULL},
	{0xabdd9ef2U, 0x2105, 0, NULL},
	{0x0e0e1602U, 0x210c, 0, NULL},
	{0xc51830b1U, 0x210d, 0, NULL},
	{0xbc75491dU, 0x210e, 0, NULL},
	{0xd332a6e7U, 0x210f, 0, NULL},
	{0x43eb077fU, 0x2132, 0, "-2.01"},
	{0xbc0ec35eU, 0x310c, 0, NULL},
	{0x61a65992U, 0x310d, 0, NULL},
	{0xd9911c85U, 0x4100, 1, "beta"}, // -l (load high) option
	{0x89cb9e7fU, 0x6100, 1, "beta"}  // -l
	// Note: "-e" files starting with v1.14 or 1.15 seem to be obfuscated
	// in a way that prevents this kind of fingerprinting.
};

static void detect_pklite_version(deark *c, lctx *d)
{
	struct de_crcobj *crco = NULL;
	u32 crc1;
	size_t i;
	const struct ver_fingerprint_item *fi = NULL;

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(crco, c->infile, d->ei->entry_point+80, 240);
	crc1 = de_crcobj_getval(crco);
	de_dbg3(c, "CRC fingerprint: %08x", (UI)crc1);
	de_crcobj_destroy(crco);

	for(i=0; i<DE_ARRAYCOUNT(ver_fingerprint_arr); i++) {
		if(ver_fingerprint_arr[i].crc==crc1) {
			fi = &ver_fingerprint_arr[i];
			break;
		}
	}

	if(fi) {
		d->ver_detected.ver_info = fi->ver_info;
		d->ver_detected.suffix = fi->suffix;
		d->ver_detected.isbeta = (fi->flags & 0x1)?1:0;

		if((d->ver_detected.ver_info&0xfff)==0x10c && !d->ver_detected.suffix) {
			if(!dbuf_memcmp(c->infile, 45, "90-92 PK", 8)) {
				d->ver_detected.suffix = "[fake v1.20]";
			}
		}
	}

	if(d->ver_detected.ver_info!=0) {
		d->ver_detected.valid = 1;
	}

	derive_version_fields(c, d, &d->ver_detected);
}

// Read what we need, before we can decompress
static void do_read_header(deark *c, lctx *d)
{
	i64 reloc_table_endpos;

	// Start to reconstruct the original header
	d->o_orig_header = dbuf_create_membuf(c, 0, 0);
	dbuf_writeu16le(d->o_orig_header, 0x5a4d); // "MZ"

	d->ver_reported.ver_info = (UI)de_getu16le(28);
	d->ver_reported.valid = 1;
	derive_version_fields(c, d, &d->ver_reported);

	de_dbg(c, "reported PKLITE version: %s", d->ver_reported.pklver_str);

	de_dbg(c, "start of executable code: %"I64_FMT, d->ei->start_of_dos_code);

	detect_pklite_version(c, d);
	de_dbg(c, "detected PKLITE version: %s", d->ver_detected.pklver_str);
	if(d->ver_detected.valid) {
		d->ver = d->ver_detected; // struct copy
	}
	else {
		d->ver = d->ver_reported;
	}

	d->o_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	reloc_table_endpos = d->ei->reloc_table_pos + 4*d->ei->num_relocs;
	if(d->ei->start_of_dos_code - reloc_table_endpos < 26) {
		d->have_orig_header = 0;
	}
	else if(d->ver.ver_only>=0x10a && d->ver.extra_cmpr) {
		d->have_orig_header = 0;
	}
	else {
		d->have_orig_header = 1;
	}

	if(d->have_orig_header) {
		i64 orig_hdr_pos, orig_hdr_len;
		i64 orig_reloc_pos;

		orig_hdr_pos = reloc_table_endpos;
		orig_hdr_len = d->ei->start_of_dos_code - orig_hdr_pos; // tentative
		// Peek at the reloc table offs field to figure out how much to read
		orig_reloc_pos = de_getu16le(orig_hdr_pos + 22);
		if(orig_reloc_pos>=28 && orig_reloc_pos<2+orig_hdr_len) {
			orig_hdr_len = orig_reloc_pos-2;
		}

		de_dbg(c, "orig. hdr: at %"I64_FMT", len=(2+)%"I64_FMT, orig_hdr_pos, orig_hdr_len);
		dbuf_copy(c->infile, orig_hdr_pos, orig_hdr_len, d->o_orig_header);

		fmtutil_collect_exe_info(c, d->o_orig_header, d->o_ei);
	}

	find_cmprdata_pos(c, d, &d->ver);
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
	i64 dcmpr_bytes_expected = 0;
	int dcmpr_len_known = 0;
	u8 b;

	de_dbg(c, "decompressing cmpr code at %"I64_FMT, d->cmpr_data_pos);
	de_dbg_indent(c, 1);

	if(d->have_orig_header) {
		// TODO: This is probably not the best way to get this info
		dcmpr_len_known = 1;
		dcmpr_bytes_expected = d->o_ei->end_of_dos_code - d->o_ei->start_of_dos_code;
	}

	make_matchlengths_tree(c, d);
	make_offsets_tree(c, d);

	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);

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

		if((len_raw==23 && d->ver.large_cmpr) || (len_raw==8 && !d->ver.large_cmpr)) {
			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			if(b==0xfe) {
				// TODO - Do we have to do anything here?
				de_dbg3(c, "code 0xfe");
				continue;
			}
			if(b==0xff) {
				de_dbg3(c, "stop code");
				goto after_dcmpr; // Normal completion
			}
			matchlen = (UI)b+(d->ver.large_cmpr?25:10);
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
		if(matchpos==0 || (i64)matchpos>d->o_dcmpr_code->len) {
			de_err(c, "Bad or unsupported compressed data (dist=%u, expected 1 to %"I64_FMT")",
				matchpos, d->o_dcmpr_code->len);
			d->errflag = 1;
			d->errmsg_handled = 1;
			goto after_dcmpr;
		}
		de_lz77buffer_copy_from_hist(ringbuf,
				(UI)(ringbuf->curpos-matchpos), matchlen);
	}

after_dcmpr:
	if(!d->o_dcmpr_code) goto done;

	if(!d->errflag) {
		d->cmpr_data_endpos = d->dcmpr_cur_ipos;
		de_dbg(c, "cmpr data end: %"I64_FMT, d->cmpr_data_endpos);
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
			d->cmpr_data_endpos-d->cmpr_data_pos, d->o_dcmpr_code->len);
	}

	if(!d->errflag && dcmpr_len_known) {
		if(d->o_dcmpr_code->len != dcmpr_bytes_expected) {
			de_warn(c, "Expected %"I64_FMT" decompressed bytes, got %"I64_FMT, dcmpr_bytes_expected,
				d->o_dcmpr_code->len);
		}
	}

done:
	de_dbg_indent(c, -1);
}

static void do_read_reloc_table_short(deark *c, lctx *d)
{
	i64 reloc_count = 0;
	i64 pos = d->cmpr_data_endpos;

	while(1) {
		UI i;
		UI count;
		i64 seg, offs;

		count = (UI)de_getbyte_p(&pos);
		if(count==0) goto done; // normal completion

		seg = de_getu16le_p(&pos);
		for(i=0; i<count; i++) {
			if(reloc_count>=d->o_ei->num_relocs) {
				d->errflag = 1;
				goto done;
			}
			offs = de_getu16le_p(&pos);
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
			reloc_count++;
		}
	}

done:
	if(d->have_orig_header && (reloc_count!=d->o_ei->num_relocs)) {
		d->errflag = 1;
	}
}

#define MAX_RELOCS (320*1024)
static void do_read_reloc_table_long(deark *c, lctx *d)
{
	i64 reloc_count = 0;
	i64 pos = d->cmpr_data_endpos;
	i64 seg = 0;

	while(1) {
		UI i;
		UI count;
		i64 offs;

		if(pos+2 > c->infile->len) {
			d->errflag = 1;
			goto done;
		}

		count = (UI)de_getu16le_p(&pos);
		if(count==0xffff) goto done; // normal completion
		if(pos+(i64)count*2 > c->infile->len) {
			d->errflag = 1;
			goto done;
		}

		for(i=0; i<count; i++) {
			if(reloc_count>=MAX_RELOCS) {
				d->errflag = 1;
				goto done;
			}
			offs = de_getu16le_p(&pos);
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
			reloc_count++;
		}
		seg += 0x0fff;
	}

done:
	if(!d->errflag) {
		d->footer_pos = pos;
	}
}

static void do_read_reloc_table(deark *c, lctx *d)
{
	if(d->have_orig_header) {
		d->o_reloc_table = dbuf_create_membuf(c, d->o_ei->num_relocs*4, 0x1);
	}
	else {
		d->o_reloc_table = dbuf_create_membuf(c, 0, 0);
	}

	if(d->ver.extra_cmpr && d->ver.ver_only>=0x10c) {
		do_read_reloc_table_long(c, d);
	}
	else {
		do_read_reloc_table_short(c, d);
	}

	if(d->errflag) {
		de_err(c, "Failed to decode relocation table");
		d->errmsg_handled = 1;
	}
}

static void reconstruct_header(deark *c, lctx *d)
{
	i64 num_relocs;
	const i64 reloc_table_start = 28;
	i64 start_of_dos_code;
	i64 end_of_dos_code;

	de_warn(c, "This EXE file might not be reconstructed perfectly");

	// "MZ" should already be written
	if(d->o_orig_header->len != 2) {
		d->errflag = 1;
		return;
	}

	num_relocs = d->o_reloc_table->len / 4;
	start_of_dos_code = de_pad_to_n(reloc_table_start + num_relocs*4, 16);
	end_of_dos_code = start_of_dos_code + d->o_dcmpr_code->len;
	dbuf_writeu16le(d->o_orig_header, end_of_dos_code%512);
	dbuf_writeu16le(d->o_orig_header, (end_of_dos_code+511)/512);
	dbuf_writeu16le(d->o_orig_header, num_relocs);
	dbuf_writeu16le(d->o_orig_header, start_of_dos_code/16);
	dbuf_writeu16le(d->o_orig_header, 0); // TODO - minmem
	dbuf_writeu16le(d->o_orig_header, 65535); // TODO - maxmem
	dbuf_copy(c->infile, d->footer_pos, 4, d->o_orig_header); // SS, SP
	dbuf_writeu16le(d->o_orig_header, 0); // checksum
	dbuf_copy(c->infile, d->footer_pos+6, 2, d->o_orig_header); // IP
	dbuf_copy(c->infile, d->footer_pos+4, 2, d->o_orig_header); // CS
	dbuf_writeu16le(d->o_orig_header, reloc_table_start);
	dbuf_writeu16le(d->o_orig_header, 0); // overlay idicator

	fmtutil_collect_exe_info(c, d->o_orig_header, d->o_ei);
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

static void de_run_pklite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));

	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, c->infile, d->ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_PKLITE;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(edd.detected_fmt!=DE_SPECIALEXEFMT_PKLITE) {
		de_err(c, "Not a PKLITE file");
		goto done;
	}
	de_declare_fmt(c, "PKLITE-compressed EXE");

	do_read_header(c, d);
	if(d->errflag) goto done;
	do_decompress(c, d);
	if(d->errflag) goto done;
	d->dcmpr_ok = 1;

	do_read_reloc_table(c, d);
	if(d->errflag) goto done;

	if(!d->have_orig_header) {
		reconstruct_header(c, d);
		if(d->errflag) goto done;
	}

	do_write_dcmpr(c, d);

done:
	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "PKLITE decompression failed");
		}

		if(d->dcmpr_ok && !d->wrote_exe) {
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

void de_module_pklite(deark *c, struct deark_module_info *mi)
{
	mi->id = "pklite";
	mi->desc = "PKLITE executable compression";
	mi->run_fn = de_run_pklite;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
