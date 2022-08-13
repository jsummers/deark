// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// RAR

#include <deark-private.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_rar);

static const u8 *g_rar_oldsig = (const u8*)"RE\x7e\x5e";
static const u8 *g_rar4_sig = (const u8*)"Rar!\x1a\x07\x00";
static const u8 *g_rar5_sig = (const u8*)"Rar!\x1a\x07\x01\x00";

static void rar_handle_noncmpr_comment(deark *c, de_arch_lctx *d, i64 pos, i64 len,
	de_encoding enc, int is_file_comment)
{
	de_ucstring *comment = NULL;
	const char *ext;

	if(len<1) goto done;

	ext = is_file_comment?"fcomment.txt":"comment.txt";

	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, pos, len, ext,
			NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		comment = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN,
			comment, 0, DE_EXTENC_MAKE(enc, DE_ENCSUBTYPE_HYBRID));
		de_dbg(c, "%scomment: \"%s\"", (is_file_comment?"file ":""),
			ucstring_getpsz_d(comment));
	}

done:
	ucstring_destroy(comment);
}

static void do_rar_old_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
{
	i64 n;
	u8 b;
	i64 pos = md->member_hdr_pos;
	i64 hdrlen;
	i64 fnlen;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member file at %"I64_FMT, md->member_hdr_pos);
	de_dbg_indent(c, 1);

	de_arch_read_field_cmpr_len_p(md, &pos);
	de_arch_read_field_orig_len_p(md, &pos);

	// Note: This is a checksum of the decompressed bytes. Algorithm:
	//  Initialize ck = 0x0000
	//  For each byte b:
	//    * ck = ck + b
	//    * Rotate ck left 1 bit,
	//      i.e. ck = (ck & 0x7fff)<<1 | (ck & 0x8000)>>15)
	n = de_getu16le_p(&pos);
	de_dbg(c, "checksum: 0x%04x", (UI)n);

	hdrlen = de_getu16le_p(&pos);
	de_dbg(c, "hdr len: %u", (int)hdrlen);

	if(hdrlen < 12) {
		d->fatalerrflag = 1;
		goto done;
	}

	md->member_total_size = hdrlen + md->cmpr_len;

	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_TD, &pos);
	de_arch_read_field_dos_attr_p(md, &pos);

	md->file_flags = (UI)de_getbyte_p(&pos); // status flags
	de_dbg(c, "flags: 0x%02x", md->file_flags);

	b = de_getbyte_p(&pos);
	de_dbg(c, "min ver needed to unpack: %u", (UI)b);

	fnlen = (i64)de_getbyte_p(&pos);

	md->cmpr_meth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);

	// Spec says the filename occurs *after* the comment, but (for v1.40.2)
	// it just isn't true.
	dbuf_read_to_ucstring(c->infile, pos, fnlen, md->filename, 0,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += fnlen;

	if(md->file_flags & 0x08) {
		i64 cmtlen;

		cmtlen = de_getu16le_p(&pos);
		de_dbg(c, "file comment at %"I64_FMT", len=%"I64_FMT, pos, cmtlen);
		rar_handle_noncmpr_comment(c, d, pos, cmtlen, d->input_encoding, 1);
		pos += cmtlen;
	}

	md->cmpr_pos = md->member_hdr_pos + hdrlen;
	de_dbg(c, "cmpr. data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Intended to work for, at least, RAR v1.40.2 (RAR1_402.EXE).
// Ref: Search for a file named RAR140DC.EXE, containing technote.doc.
static void do_rar_old(deark *c, de_arch_lctx *d)
{
	i64 pos = d->data_startpos;
	i64 hdrpos;
	i64 hdrlen;
	struct de_arch_member_data *md = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_declare_fmt(c, "RAR (<v1.50)");
	hdrpos = pos;
	de_dbg(c, "archive header at %"I64_FMT, hdrpos);
	de_dbg_indent(c, 1);
	pos += 4; // header ID
	hdrlen = de_getu16le_p(&pos);
	de_dbg(c, "hdr len: %"I64_FMT, hdrlen);
	d->archive_flags = (UI)de_getbyte_p(&pos);
	de_dbg(c, "flags: 0x%02x", d->archive_flags);

	if(d->archive_flags & 0x02) {
		i64 cmtlen;

		cmtlen = de_getu16le_p(&pos);
		de_dbg(c, "archive comment at %"I64_FMT", len=%"I64_FMT", compressed=%d",
			pos, cmtlen, (int)((d->archive_flags & 0x10)!=0));
		if((d->archive_flags & 0x10)==0) {
			// The old format suports a non-compressed archive comment, though for
			// v1.4.0+ it is always(?) compressed.
			rar_handle_noncmpr_comment(c, d, pos, cmtlen, d->input_encoding, 0);
		}
		pos += cmtlen;
	}

	if(d->archive_flags & 0x20) {
		i64 ext1len;

		ext1len = de_getu16le_p(&pos);
		de_dbg(c, "EXT1 field at %"I64_FMT", len=%"I64_FMT, pos, ext1len);
		pos += ext1len;
	}

	de_dbg_indent_restore(c, saved_indent_level);

	pos = hdrpos + hdrlen;
	while(1) {
		if(pos >= c->infile->len) break;
		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, d);
		md->member_hdr_pos = pos;
		do_rar_old_member(c, d, md);

		if(d->fatalerrflag) goto done;
		if(md->member_total_size <= 0) goto done;
		pos += md->member_total_size;
	}

done:
	if(md) {
		de_arch_destroy_md(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

struct rar4_block {
	i64 block_pos;
	i64 block_max_endpos;
	u32 crc_reported;
	UI flags;
	u8 type;
	u8 parent_type; // 0 for none
	u8 parsed_ok;
	u8 last_block;
	i64 data1_pos;
	i64 block_size_1;
	i64 data2_pos;
	i64 block_size_2;
	i64 block_size_high;
	i64 block_size_full;
};

struct rar5_block {
	i64 block_pos;
	i64 block_size_full;
	u32 crc_reported;
	UI type;
	UI hdr_flags;
	i64 extra_area_pos;
	i64 extra_area_size;
	i64 data_area_pos;
	i64 data_area_size;
	i64 pos_after_standard_fields;
};

static void rar4_free_block(deark *c, struct rar4_block *rb)
{
	if(!rb) return;
	de_free(c, rb);
}

static void rar5_free_block(deark *c, struct rar5_block *rb)
{
	if(!rb) return;
	de_free(c, rb);
}

static const char *rar_get_v4_blktype_name(u8 n)
{
	const char *name = NULL;

	switch(n) {
	case 0x72: name = "marker"; break;
	case 0x73: name = "archive header"; break;
	case 0x74: name = "file header"; break;
	case 0x75: name = "comment"; break;
	case 0x76: name = "extra info"; break;
	case 0x77: name = "subblock (old)"; break;
	case 0x78: name = "recovery record"; break;
	case 0x79: name = "auth info"; break;
	case 0x7a: name = "subblock (new)"; break;
	case 0x7b: name = "end of archive"; break;
	}

	return name?name:"?";
}

static const char *rar4_get_OS_name(u8 n)
{
	const char *name = NULL;

	switch(n) {
	case 0: name = "DOS"; break;
	case 1: name = "OS/2"; break;
	case 2: name = "Windows"; break;
	case 3: name = "Unix"; break;
	case 4: name = "Mac"; break;
	}
	return name?name:"?";
}

static void rar_read_v4_block(deark *c, de_arch_lctx *d, struct rar4_block *rb);

// Header type 0x73
static void do_rar4_block_archiveheader(deark *c, de_arch_lctx *d, struct rar4_block *rb)
{
	i64 pos;

	pos = rb->data1_pos;
	pos += 2; // reserved1
	pos += 4; // reserved2

	if(rb->flags & 0x0002) {
		struct rar4_block *cmt_rb;

		cmt_rb = de_malloc(c, sizeof(struct rar4_block));
		cmt_rb->block_pos = pos;
		cmt_rb->block_max_endpos = rb->data2_pos;
		cmt_rb->parent_type = rb->type;
		rar_read_v4_block(c, d, cmt_rb);
		rar4_free_block(c, cmt_rb);
	}
}

// Header type 0x74 or 0x7a
static void do_rar4_block_fileheader(deark *c, de_arch_lctx *d, struct rar4_block *rb)
{
	struct de_arch_member_data *md = NULL;
	i64 pos;
	i64 fnlen;
	u32 filecrc_reported;
	UI attribs;
	u8 os;
	u8 b;

	md = de_arch_create_md(c, d);

	pos = rb->data1_pos;

	md->cmpr_pos = rb->data2_pos;
	md->cmpr_len = rb->block_size_2 + rb->block_size_high;
	de_arch_read_field_orig_len_p(md, &pos);

	os = de_getbyte_p(&pos);
	de_dbg(c, "OS: %u (%s)", (UI)os, rar4_get_OS_name(os));

	filecrc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "file crc: 0x%08x", (UI)filecrc_reported);

	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_TD, &pos);

	b = de_getbyte_p(&pos);
	de_dbg(c, "min ver needed to unpack: %u", (UI)b);

	md->cmpr_meth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);

	fnlen = de_getu16le_p(&pos);

	attribs = (UI)de_getu32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", attribs);
	if(os==0 || os==1 || os==2) {
		de_dbg_indent(c, 1);
		de_arch_handle_field_dos_attr(md, (attribs & 0xff));
		de_dbg_indent(c, -1);
	}

	if(rb->flags & 0x0100) {
		pos += 4; // HIGH_PACK_SIZE, already read
		pos += 4; // TODO: HIGH_UNP_SIZE
	}

	// TODO: Handle UTF-8 names
	dbuf_read_to_ucstring_n(c->infile, pos, fnlen, 2048, md->filename,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "%sname: \"%s\"", (rb->type==0x7a?"":"file"), ucstring_getpsz_d(md->filename));
	pos += fnlen;

	if(rb->flags & 0x0400) {
		pos += 8; // salt (first documented in v3.00)
	}

	if((rb->flags & 0x1008)==0x1008) {
		// Ext time and comment shouldn't both be present.
		// Ext time first documented in v3.40, which is also when the docs
		// started saying that RAR 3.x doesn't set the 0x0008 flag.
		goto done;
	}
	if(rb->type==0x7a && (rb->flags & 0x0008)) {
		// A new subblock can't have an old comment
		goto done;
	}

	// TODO: ext time (rb->flags & 0x1000)

	// Old-style comment -- A nested block
	if(rb->flags & 0x0008) {
		struct rar4_block *cmt_rb;

		cmt_rb = de_malloc(c, sizeof(struct rar4_block));
		cmt_rb->block_pos = pos;
		cmt_rb->block_max_endpos = rb->data2_pos;
		cmt_rb->parent_type = rb->type;
		rar_read_v4_block(c, d, cmt_rb);
		pos += cmt_rb->block_size_full;
		rar4_free_block(c, cmt_rb);
	}

	de_dbg(c, "cmpr. data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);

done:
	de_arch_destroy_md(c, md);
}

// Header type 0x75, expected to be nested in type 0x73 or 0x74
static void do_rar4_block_oldcomment(deark *c, de_arch_lctx *d, struct rar4_block *rb)
{
	i64 cmpr_len;
	i64 orig_len;
	i64 pos = rb->data1_pos;
	u8 ver_needed;
	u8 cmpr_meth;
	u32 crc_reported;
	int is_file_comment;

	is_file_comment = (rb->parent_type==0x74);
	orig_len = de_getu16le_p(&pos);
	de_dbg(c, "uncompr. comment len: %"I64_FMT, orig_len);
	ver_needed = de_getbyte_p(&pos);
	de_dbg(c, "ver needed to read comment: %u", (UI)ver_needed);
	cmpr_meth = de_getbyte_p(&pos);
	de_dbg(c, "cmpr. method: %u", cmpr_meth);
	crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)crc_reported);

	cmpr_len = rb->data2_pos - pos;
	de_dbg(c, "%s comment at %"I64_FMT", len=%"I64_FMT,
		(is_file_comment?"file":"archive"), pos, cmpr_len);
	if(cmpr_len<1) goto done;
	if(cmpr_meth!=48) goto done; // compressed
	rar_handle_noncmpr_comment(c, d, pos, cmpr_len, d->input_encoding, is_file_comment);

done:
	;
}

static const char *rar4_get_oldsubblock_name(UI t)
{
	const char *name = NULL;

	if(t==0x100) name="OS/2 ext attribs";
	return name?name:"?";
}

static void do_rar4_block_oldsubblock(deark *c, de_arch_lctx *d, struct rar4_block *rb)
{
	UI sbtype;
	i64 pos = rb->data1_pos;

	sbtype = (UI)de_getu16le_p(&pos);
	de_dbg(c, "subblock type: 0x%04x (%s)", sbtype, rar4_get_oldsubblock_name(sbtype));
}

// Caller supplies descr
static void get_rar4_flags_descr(struct rar4_block *rb, de_ucstring *s)
{
	UI bf = rb->flags;
	UI x;

	ucstring_empty(s);
	if(rb->type==0x73) { // archive hdr
		if(bf & 0x0001) {
			ucstring_append_flags_item(s, "volume");
			bf -= 0x0001;
		}
		if(bf & 0x0002) {
			ucstring_append_flags_item(s, "has comment (old)");
			bf -= 0x0002;
		}
		if(bf & 0x0004) {
			ucstring_append_flags_item(s, "locked");
			bf -= 0x0004;
		}
		if(bf & 0x0008) {
			ucstring_append_flags_item(s, "solid");
			bf -= 0x0008;
		}
		if(bf & 0x0020) {
			ucstring_append_flags_item(s, "has auth info (old)");
			bf -= 0x0020;
		}
		if(bf & 0x0040) {
			ucstring_append_flags_item(s, "has recovery record");
			bf -= 0x0040;
		}
	}
	else if(rb->type==0x74 || rb->type==0x7a) { // file hdr or new subblock
		if(bf & 0x0001) {
			ucstring_append_flags_item(s, "continued from prev vol");
			bf -= 0x0001;
		}
		if(bf & 0x0002) {
			ucstring_append_flags_item(s, "continued in next vol");
			bf -= 0x0002;
		}
		if(bf & 0x0004) {
			ucstring_append_flags_item(s, "encrypted");
			bf -= 0x0004;
		}
		if(bf & 0x0008) {
			ucstring_append_flags_item(s, "has comment (old)");
			bf -= 0x0008;
		}
		if(bf & 0x0010) {
			ucstring_append_flags_item(s, "solid");
			bf -= 0x0010;
		}

		x = bf & 0x00e0;
		bf -= x;
		x >>= 5;
		if(x==0x7) {
			ucstring_append_flags_item(s, "directory");
		}
		else {
			ucstring_append_flags_itemf(s, "dict=%uK", (UI)(64<<x));
		}

		if(bf & 0x0100) {
			ucstring_append_flags_item(s, "large");
			bf -= 0x0100;
		}
		if(bf & 0x0200) {
			ucstring_append_flags_item(s, "Unicode filename");
			bf -= 0x0200;
		}
		if(bf & 0x0400) {
			ucstring_append_flags_item(s, "salt");
			bf -= 0x0400;
		}
		if(bf & 0x0800) {
			ucstring_append_flags_item(s, "old version");
			bf -= 0x0800;
		}
		if(bf & 0x1000) {
			ucstring_append_flags_item(s, "has ext time field");
			bf -= 0x1000;
		}
	}

	if(bf & 0x4000) {
		ucstring_append_flags_item(s, "unsafe to copy");
		bf -= 0x4000;
	}
	if(bf & 0x8000) {
		ucstring_append_flags_item(s, "long block");
		bf -= 0x8000;
	}
	if(bf!=0) {
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

// Caller allocates/frees rb, and sets:
//    ->block_pos,
//    ->block_max_endpos,
//    ->parent_type if applicable
static void rar_read_v4_block(deark *c, de_arch_lctx *d, struct rar4_block *rb)
{
	int saved_indent_level;
	i64 pos;
	i64 n;
	u32 crc_calc;
	de_ucstring *descr = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = rb->block_pos;

	de_dbg(c, "block at %"I64_FMT, rb->block_pos);
	de_dbg_indent(c, 1);
	rb->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)rb->crc_reported);

	rb->type = de_getbyte_p(&pos);
	de_dbg(c, "block type: 0x%02x (%s)", (UI)rb->type, rar_get_v4_blktype_name(rb->type));

	// The only nested block allowed is a comment block.
	if(rb->parent_type!=0 && rb->type!=0x75) goto done;

	if(rb->type==0x7b) {
		rb->last_block = 1;
	}

	rb->flags = (UI)de_getu16le_p(&pos);
	descr = ucstring_create(c);
	get_rar4_flags_descr(rb, descr);
	de_dbg(c, "block flags: 0x%04x (%s)", (UI)rb->flags, ucstring_getpsz_d(descr));

	rb->block_size_1 = de_getu16le_p(&pos);
	de_dbg(c, "block size (part 1): %"I64_FMT, rb->block_size_1);
	if(rb->block_pos + rb->block_size_1 > rb->block_max_endpos) goto done;

	if(rb->type==0x75) n = 11; // Special case for old-style comment blocks
	else n = rb->block_size_1-2;
	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, rb->block_pos+2, n);
	crc_calc = de_crcobj_getval(d->crco);
	crc_calc &= 0xffff;
	de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calc);

	if(rb->flags & 0x8000) {
		rb->block_size_2 = de_getu32le_p(&pos);
		de_dbg(c, "block size (part 2): %"I64_FMT, rb->block_size_2);
	}

	if((rb->type==0x74 || rb->type==0x7a) && (rb->flags & 0x0100)) {
		rb->block_size_high = de_getu32le(pos+17); // HIGH_PACK_SIZE
		if(rb->block_size_high > 0x7ffffffe) {
			// Legal, but we can't allow integer overflow (after <<32
			// then adding 0xffffffff + 0xffff).
			goto done;
		}
		rb->block_size_high <<= 32;
	}

	rb->data1_pos = pos;
	rb->data2_pos = rb->block_pos + rb->block_size_1;

	rb->block_size_full = rb->block_size_1 + rb->block_size_2 + rb->block_size_high;
	de_dbg(c, "block size (total): %"I64_FMT, rb->block_size_full);
	if(rb->block_pos + rb->block_size_full > rb->block_max_endpos) goto done;
	rb->parsed_ok = 1;

	switch(rb->type) {
	case 0x73:
		do_rar4_block_archiveheader(c, d, rb);
		break;
	case 0x74:
	case 0x7a:
		do_rar4_block_fileheader(c, d, rb);
		break;
	case 0x75:
		do_rar4_block_oldcomment(c, d, rb);
		break;
	case 0x77:
		do_rar4_block_oldsubblock(c, d, rb);
		break;
	}

done:
	ucstring_destroy(descr);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_rar_v4(deark *c, de_arch_lctx *d)
{
	struct rar4_block *rb = NULL;
	i64 pos = d->data_startpos;

	de_declare_fmt(c, "RAR (v1.50-4.20)");
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	while(1) {
		if(pos >= c->infile->len) break;

		if(rb) {
			rar4_free_block(c, rb);
			rb = NULL;
		}
		rb = de_malloc(c, sizeof(struct rar4_block));
		rb->block_pos = pos;
		rb->block_max_endpos = c->infile->len;
		rb->parent_type = 0;
		rar_read_v4_block(c, d, rb);
		if(!rb->parsed_ok) goto done;
		if(rb->last_block) goto done;
		if(rb->block_size_full <= 0) goto done;
		pos += rb->block_size_full;
	}

done:
	rar4_free_block(c, rb);
}

static u64 rar_get_vint_p(de_arch_lctx *d, dbuf *f, i64 *ppos)
{
	u64 val = 0;
	UI nbits_set = 0;

	// TODO: Better handling of errors & oversized ints
	while(1) {
		u8 b;

		if(nbits_set>=64) { val = 0; break; }
		b = dbuf_getbyte_p(f, ppos);
		if(nbits_set < 64) {
			val |= (((u64)(b&0x7f))<<nbits_set);
			nbits_set += 7;
		}
		if((b&0x80)==0) break;
	}
	return val;
}

static i64 rar_get_vint_i64_p(de_arch_lctx *d, dbuf *f, i64 *ppos)
{
	u64 v1u;
	i64 v1i;

	v1u = rar_get_vint_p(d, f, ppos);
	v1i = (i64)v1u;
	if(v1i<0) v1i = 0;
	return v1i;
}

#define RAR5_HDRTYPE_ARCHIVE   1
#define RAR5_HDRTYPE_FILE      2
#define RAR5_HDRTYPE_SERVICE   3
#define RAR5_HDRTYPE_EOA       5

static const char *rar_get_v5_hdrtype_name(UI n)
{
	const char *name = NULL;

	switch(n) {
	case RAR5_HDRTYPE_ARCHIVE: name = "archive header"; break;
	case RAR5_HDRTYPE_FILE: name = "file header"; break;
	case RAR5_HDRTYPE_SERVICE: name = "service header"; break;
	case 4: name = "encryption header"; break;
	case RAR5_HDRTYPE_EOA: name = "end of archive"; break;
	}

	return name?name:"?";
}

static void on_rar5_file_end(deark *c, de_arch_lctx *d)
{
	if(!d->cur_md) return;
	de_arch_destroy_md(c, d->cur_md);
	d->cur_md = NULL;
}

static void on_rar5_file_begin(deark *c, de_arch_lctx *d)
{
	on_rar5_file_end(c, d);
	d->cur_md = de_arch_create_md(c, d);
}

struct rar5_extra_data {
	u8 have_timestamps;
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];
};

struct rar5_file_or_svc_hdr_data {
	UI file_flags;
	u64 attribs;
	i64 orig_len;
	u32 crc_reported;
	UI cmpr_info;
	UI cmpr_meth;
	UI os;
	struct de_timestamp mtime1;
	struct de_stringreaderdata *name_srd;
};

static void do_rar5_comment(deark *c, de_arch_lctx *d, struct rar5_block *rb,
	struct rar5_file_or_svc_hdr_data *hd)
{
	i64 cmt_len;
	de_ucstring *comment = NULL;

	if(hd->cmpr_meth!=0) goto done;
	cmt_len = de_min_int(rb->data_area_size, hd->orig_len);
	if(cmt_len<1) goto done;

	rar_handle_noncmpr_comment(c, d, rb->data_area_pos, cmt_len, DE_ENCODING_UTF8, 0);

done:
	ucstring_destroy(comment);
}

static const char *get_rar5_extra_record_name(struct rar5_block *rb, UI t)
{
	const char *name = NULL;

	if(rb->type==RAR5_HDRTYPE_FILE || rb->type==RAR5_HDRTYPE_SERVICE) {
		switch(t) {
		case 1: name="encryption"; break;
		case 2: name="hash"; break;
		case 3: name="timestamps"; break;
		case 4: name="version"; break;
		case 5: name="redirection"; break;
		case 6: name="owner (Unix)"; break;
		case 7: name="service data"; break;
		}
	}
	else if(rb->type==RAR5_HDRTYPE_ARCHIVE) {
		if(t==1) name="locator";
	}
	return name?name:"?";
}

static void do_rar5_extrarec_timestamps(deark *c, de_arch_lctx *d, struct rar5_extra_data *ed,
	i64 pos1, i64 len)
{
	UI flags;
	enum de_arch_tstype_enum tstype;
	i64 pos = pos1;
	i64 n;
	double subsec;

	if(len<1) goto done;
	ed->have_timestamps = 1;
	flags = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "flags: 0x%x", flags);
	tstype = (flags & 0x1) ? DE_ARCH_TSTYPE_UNIX_U : DE_ARCH_TSTYPE_FILETIME;
	if(flags & 0x2) {
		de_arch_read_field_dttm_p(d, &ed->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
			tstype, &pos);
	}
	if(flags & 0x4) {
		de_arch_read_field_dttm_p(d, &ed->tmstamp[DE_TIMESTAMPIDX_CREATE], "create",
			tstype, &pos);
	}
	if(flags & 0x8) {
		de_arch_read_field_dttm_p(d, &ed->tmstamp[DE_TIMESTAMPIDX_ACCESS], "access",
			tstype, &pos);
	}

	// Unix time w/nanosecond precision.
	// FIXME: This ought to be shown in the debug message above.
	if((flags & 0x13)==0x13) {
		n = de_getu32le_p(&pos);
		subsec = ((double)n) / 1000000000.0;
		de_timestamp_set_subsec(&ed->tmstamp[DE_TIMESTAMPIDX_MODIFY], subsec);
	}
	if((flags & 0x15)==0x15) {
		n = de_getu32le_p(&pos);
		subsec = ((double)n) / 1000000000.0;
		de_timestamp_set_subsec(&ed->tmstamp[DE_TIMESTAMPIDX_CREATE], subsec);
	}
	if((flags & 0x19)==0x19) {
		n = de_getu32le_p(&pos);
		subsec = ((double)n) / 1000000000.0;
		de_timestamp_set_subsec(&ed->tmstamp[DE_TIMESTAMPIDX_ACCESS], subsec);
	}

done:
	;
}

static void do_rar5_extra_area(deark *c, de_arch_lctx *d, struct rar5_block *rb)
{
	int saved_indent_level;
	i64 pos = rb->extra_area_pos;
	i64 endpos = rb->data_area_pos;
	struct rar5_extra_data *ed = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	ed = de_malloc(c, sizeof(struct rar5_extra_data));
	if(rb->extra_area_size<1) goto done;

	de_dbg(c, "extra area at %"I64_FMT", len=%"I64_FMT, rb->extra_area_pos,
		rb->extra_area_size);
	de_dbg_indent(c, 1);
	while(1) {
		i64 reclen;
		i64 rec_dpos;
		i64 rec_dlen;
		i64 next_record_pos;
		UI rectype;
		int decoded;

		if(pos >= endpos) break;
		de_dbg(c, "record at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		reclen = rar_get_vint_i64_p(d, c->infile, &pos);
		de_dbg(c, "record len: %"I64_FMT, reclen);

		// Extra checks like the following are to guard against integer overflow.
		if(reclen > rb->extra_area_size) goto done;

		next_record_pos = pos + reclen;
		if(next_record_pos > endpos) goto done;
		rectype = (UI)rar_get_vint_p(d, c->infile, &pos);
		de_dbg(c, "record type: %u (%s)", rectype,
			get_rar5_extra_record_name(rb, rectype));

		rec_dpos = pos;
		rec_dlen = next_record_pos - rec_dpos;
		de_dbg(c, "record dpos: %"I64_FMT", len: %"I64_FMT, rec_dpos, rec_dlen);

		decoded = 0;
		if(rb->type==RAR5_HDRTYPE_FILE || rb->type==RAR5_HDRTYPE_SERVICE) {
			if(rectype==3) {
				do_rar5_extrarec_timestamps(c, d, ed, rec_dpos, rec_dlen);
				decoded = 1;
			}
		}

		if(!decoded && rec_dlen>0) {
			de_dbg_hexdump(c, c->infile, pos, rec_dlen, 256, NULL, 0x1);
		}

		pos = next_record_pos;
		de_dbg_indent(c, -1);
	}

done:
	de_free(c, ed);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_rar5_file_or_service_hdr(deark *c, de_arch_lctx *d, struct rar5_block *rb)
{
	UI u;
	i64 namelen;
	i64 pos;
	struct rar5_file_or_svc_hdr_data *hd = NULL;

	hd = de_malloc(c, sizeof(struct rar5_file_or_svc_hdr_data));
	pos = rb->pos_after_standard_fields;

	if(rb->type==RAR5_HDRTYPE_FILE) {
		on_rar5_file_begin(c, d);
	}

	hd->file_flags = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "file flags: 0x%x", hd->file_flags);
	hd->orig_len = rar_get_vint_i64_p(d, c->infile, &pos);
	de_dbg(c, "original size: %"I64_FMT, hd->orig_len);
	hd->attribs = rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "attribs: 0x%"U64_FMTx, hd->attribs);

	if(hd->file_flags & 0x2) { // TODO: Test this
		de_arch_read_field_dttm_p(d, &hd->mtime1, "mod", DE_ARCH_TSTYPE_UNIX_U, &pos);
	}
	if(hd->file_flags & 0x4) {
		hd->crc_reported = (u32)de_getu32le_p(&pos);
		de_dbg(c, "data crc: 0x%08x", (UI)hd->crc_reported);
	}

	hd->cmpr_info = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "cmpr info: 0x%x", hd->cmpr_info);
	de_dbg_indent(c, 1);
	u = hd->cmpr_info & 0x3f;
	de_dbg(c, "version: %u", u);
	u = (hd->cmpr_info >> 6) & 0x1;
	de_dbg(c, "solid: %u", u);
	hd->cmpr_meth = (hd->cmpr_info >> 7) & 0x7;
	de_dbg(c, "method: %u", hd->cmpr_meth);
	u = (hd->cmpr_info >> 10) & 0xf;
	de_dbg(c, "dict size: %u (%uk)", u, (UI)(128<<u));
	de_dbg_indent(c, -1);

	hd->os = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "os: %u", hd->os);

	namelen = rar_get_vint_i64_p(d, c->infile, &pos);
#define RAR_MAX_NAMELEN 65535
	if(namelen > RAR_MAX_NAMELEN) goto done;

	hd->name_srd = dbuf_read_string(c->infile, pos, namelen, namelen, 0,
		DE_ENCODING_UTF8);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(hd->name_srd->str));

	if(rb->type==RAR5_HDRTYPE_SERVICE) {
		if(!de_strcmp(hd->name_srd->sz, "CMT")) {
			do_rar5_comment(c, d, rb, hd);
		}
	}
done:
	if(hd) {
		de_destroy_stringreaderdata(c, hd->name_srd);
		de_free(c, hd);
	}
}

static void rar_read_v5_block(deark *c, de_arch_lctx *d, struct rar5_block *rb, i64 pos1)
{
	i64 pos;
	i64 hdr_size;
	i64 pos_of_hdr_type_field;
	u32 crc_calc;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	rb->block_pos = pos1;
	pos = rb->block_pos;

	de_dbg(c, "block at %"I64_FMT, rb->block_pos);
	de_dbg_indent(c, 1);
	rb->crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "hdr crc (reported): 0x%08x", (UI)rb->crc_reported);

	hdr_size = rar_get_vint_i64_p(d, c->infile, &pos);
	de_dbg(c, "hdr size: %"I64_FMT, hdr_size);
	if(hdr_size > 0x1fffff) goto done;

	pos_of_hdr_type_field = pos;

	rb->type = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "hdr type: %u (%s)", rb->type, rar_get_v5_hdrtype_name(rb->type));
	if(rb->type==RAR5_HDRTYPE_EOA) {
		d->stop_flag = 1;
	}

	rb->hdr_flags = (UI)rar_get_vint_p(d, c->infile, &pos);
	de_dbg(c, "hdr flags: %u", rb->hdr_flags);

	if(rb->hdr_flags & 0x1) {
		rb->extra_area_size = rar_get_vint_i64_p(d, c->infile, &pos);
		de_dbg(c, "extra area len: %"I64_FMT, rb->extra_area_size);
		// Extra checks like the following are to guard against integer overflow.
		if(rb->extra_area_size > c->infile->len) goto done;
	}

	if(rb->hdr_flags & 0x2) {
		rb->data_area_size = rar_get_vint_i64_p(d, c->infile, &pos);
		de_dbg(c, "data area len: %"I64_FMT, rb->data_area_size);
		if(rb->data_area_size > c->infile->len) goto done;
	}

	rb->pos_after_standard_fields = pos;

	// (If there's no data area, then this is the end of the block.)
	rb->data_area_pos = pos_of_hdr_type_field + hdr_size;
	if(rb->data_area_pos + rb->data_area_size > c->infile->len) goto done;

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, rb->block_pos+4, rb->data_area_pos-(rb->block_pos+4));
	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "hdr crc (calculated): 0x%08x", (UI)crc_calc);
	if(crc_calc != rb->crc_reported) goto done;

	rb->block_size_full = (rb->data_area_pos + rb->data_area_size) - rb->block_pos;

	rb->extra_area_pos = rb->data_area_pos - rb->extra_area_size;
	if(rb->hdr_flags & 0x1) {
		de_dbg(c, "extra area pos %"I64_FMT, rb->extra_area_pos);
	}

	if(rb->hdr_flags & 0x2) {
		de_dbg(c, "data area pos: %"I64_FMT, rb->data_area_pos);
	}

	switch(rb->type) {
	case RAR5_HDRTYPE_FILE:
	case RAR5_HDRTYPE_SERVICE:
		do_rar5_file_or_service_hdr(c, d, rb);
		break;
	}

	do_rar5_extra_area(c, d, rb);

done:
	if(rb->block_size_full==0) {
		d->fatalerrflag = 1;
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_rar_v5(deark *c, de_arch_lctx *d)
{
	struct rar5_block *rb = NULL;
	i64 pos = d->data_startpos;

	de_declare_fmt(c, "RAR 5.0");
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	pos += 8;

	while(1) {
		if(pos >= c->infile->len) break;

		if(rb) {
			rar5_free_block(c, rb);
			rb = NULL;
		}
		rb = de_malloc(c, sizeof(struct rar5_block));
		rar_read_v5_block(c, d, rb, pos);
		if(d->fatalerrflag || d->stop_flag) goto done;
		if(rb->block_size_full <= 0) goto done;
		pos += rb->block_size_full;
	}

done:
	on_rar5_file_end(c, d);
	rar5_free_block(c, rb);
}

static int rar_get_fmtver(dbuf *f, i64 pos)
{
	u8 buf[8];

	dbuf_read(f, buf, pos, sizeof(buf));
	if(!de_memcmp(buf, g_rar4_sig, 7)) {
		return 4; // ver 1.5x-4.xx
	}
	if(!de_memcmp(buf, g_rar5_sig, 8)) {
		return 5;
	}
	if(!de_memcmp(buf, g_rar_oldsig, 4)) {
		return 1; // ver < 1.50
	}
	return 0;
}

static int rar_search_for_archive(deark *c, de_arch_lctx *d, i64 *pfoundpos)
{
	int ret;

	// Search for the common prefix of g_rar4_sig & g_rar5_sig
	ret = dbuf_search(c->infile, g_rar4_sig, 6, 0, c->infile->len, pfoundpos);
	if(ret) return 1;

	ret = dbuf_search(c->infile, g_rar_oldsig, 4, 0, c->infile->len, pfoundpos);
	if(ret) return 1;
	return 0;
}

static void de_run_rar(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;

	d = de_arch_create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->data_startpos = 0;

	d->fmtver = rar_get_fmtver(c->infile, d->data_startpos);
	if(d->fmtver==0 && c->module_disposition==DE_MODDISP_EXPLICIT) {
		if(rar_search_for_archive(c, d, &d->data_startpos)) {
			de_dbg(c, "likely RAR data found at %"I64_FMT, d->data_startpos);
			d->fmtver = rar_get_fmtver(c->infile, d->data_startpos);
		}
	}

	if(d->fmtver==0) {
		de_err(c, "Not a RAR file");
		goto done;
	}
	if(c->module_disposition==DE_MODDISP_AUTODETECT) {
		de_info(c, "Note: RAR files can be parsed, but not decompressed.");
	}

	if(d->fmtver==1) {
		do_rar_old(c, d);
	}
	else if(d->fmtver==4) {
		do_rar_v4(c, d);
	}
	else {
		do_rar_v5(c, d);
	}

done:
	de_arch_destroy_lctx(c, d);
}

static int de_identify_rar(deark *c)
{
	int v;

	v = rar_get_fmtver(c->infile, 0);
	return v?100:0;
}

void de_module_rar(deark *c, struct deark_module_info *mi)
{
	mi->id = "rar";
	mi->desc = "RAR archive";
	mi->run_fn = de_run_rar;
	mi->identify_fn = de_identify_rar;
}
