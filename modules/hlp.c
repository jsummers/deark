// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Windows HLP

// This module was developed with the help of information from the helpfile.txt
// document included with the helpdeco software by M. Winterhoff.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_hlp);

#define TOPICBLOCKHDRSIZE 12
#define INVALIDPOS 0xffffffffU

enum hlp_filetype {
	FILETYPE_UNKNOWN = 0,
	FILETYPE_OTHERSPECIAL,
	FILETYPE_EXTRACTABLE,
	FILETYPE_INTERNALDIR,
	FILETYPE_SYSTEM,
	FILETYPE_TOPIC,
	FILETYPE_SHG,
	FILETYPE_PHRASES,
	FILETYPE_PHRINDEX,
	FILETYPE_PHRIMAGE
};

struct bptree {
	unsigned int flags;
	i64 pagesize;
	i64 root_page;
	i64 num_levels;
	i64 num_pages;
	i64 num_entries;
	i64 pagesdata_pos;
	i64 first_leaf_page;
};

struct phrase_item {
	u32 pos; // pos in ->phrases_data
	u32 len;
};

typedef struct localctx_struct {
	int input_encoding;
	int output_is_utf8;
	int extract_text;
	u8 extract_raw_streams;
	i64 internal_dir_FILEHEADER_offs;
	struct bptree bpt;
	u8 found_system_file;
	u8 found_Phrases_file;
	u8 found_PhrIndex_file;
	u8 found_PhrImage_file;
	u8 found_TOPIC_file;
	u8 valid_Phrases_file;
	i64 offset_of_system_file;
	i64 offset_of_Phrases;
	i64 offset_of_PhrIndex;
	i64 offset_of_PhrImage;
	i64 offset_of_TOPIC;
	int ver_major;
	int ver_minor;
	i64 topic_block_size;
	int is_lz77_compressed;
	int uses_old_phrase_compression;
	int uses_hall_compression;
	int pass;
	int has_shg, has_ico, has_bmp;
	i64 internal_dir_num_levels;
	dbuf *outf_text;
	i64 num_topic_blocks;
	dbuf *tmpdbuf1;
	dbuf *unc_linkdata2_dbuf;
	i64 PhrImageUncSize;
	i64 PhrImageCmprSize;
	dbuf *phrases_data;
	unsigned int num_phrases;
	struct phrase_item *phrase_info; // array [num_phrases]
	de_ucstring *tmpucstring1;
	de_ucstring *help_file_title;
	de_ucstring *help_file_copyright;
	struct de_timestamp gendate;
} lctx;

static void do_file(deark *c, lctx *d, i64 pos1, enum hlp_filetype file_fmt, int extract_only,
	struct de_stringreaderdata *fn);

struct systemrec_info {
	unsigned int rectype;

	// low 8 bits = version info
	// 0x0010 = STRINGZ type
	unsigned int flags;

	const char *name;
	void *reserved;
};
static const struct systemrec_info systemrec_info_arr[] = {
	{ 1,  0x0010, "Title", NULL },
	{ 2,  0x0010, "Copyright", NULL },
	{ 3,  0x0000, "Contents", NULL },
	{ 4,  0x0010, "Macro", NULL },
	{ 5,  0x0000, "Icon", NULL },
	{ 6,  0x0000, "Window", NULL },
	{ 8,  0x0010, "Citation", NULL },
	{ 9,  0x0000, "Language ID", NULL },
	{ 10, 0x0010, "CNT file name", NULL },
	{ 11, 0x0000, "Charset", NULL },
	{ 12, 0x0000, "Default dialog font", NULL },
	{ 13, 0x0010, "Defined GROUPs", NULL },
	{ 14, 0x0011, "IndexSeparators", NULL },
	{ 14, 0x0002, "Multimedia Help Files", NULL },
	{ 18, 0x0010, "Defined language", NULL },
	{ 19, 0x0000, "Defined DLLMAPS", NULL }
};
static const struct systemrec_info systemrec_info_default =
	{ 0, 0x0000, "?", NULL };

static void format_topiclink(deark *c, lctx *d, u32 n, char *buf, size_t buf_len)
{
	if(d->ver_minor<=16) {
		de_snprintf(buf, buf_len, "%u", (uint)n);
	}
	else {
		if(n==INVALIDPOS) {
			de_strlcpy(buf, "-1", buf_len);
		}
		else {
			de_snprintf(buf, buf_len, "Blk%u:%u", (uint)(n/16384),
				(uint)(n%16384));
		}
	}
}

static void hlptime_to_timestamp(i64 ht, struct de_timestamp *ts)
{
	if(ht!=0) {
		de_unix_time_to_timestamp(ht, ts, 0);
	}
	else {
		ts->is_valid = 0;
	}
}

// s can be NULL, or it can be a string to save the value in.
static void do_display_and_store_STRINGZ(deark *c, lctx *d, i64 pos1, i64 len,
	const char *name, de_ucstring *s1)
{
	de_ucstring *s_tmp = NULL;
	de_ucstring *s;

	if(s1) {
		s = s1;
	}
	else {
		s_tmp = ucstring_create(c);
		s = s_tmp;
	}

	ucstring_empty(s);
	if(len<1) return;

	dbuf_read_to_ucstring_n(c->infile,
		pos1, len, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));

	if(s_tmp) ucstring_destroy(s_tmp);
}

static void do_SYSTEMREC_STRINGZ(deark *c, lctx *d, unsigned int recordtype,
	i64 pos1, i64 len, const struct systemrec_info *sti, de_ucstring *s)
{
	do_display_and_store_STRINGZ(c, d, pos1, len, sti->name, s);
}

static void do_SYSTEMREC_uint32_hex(deark *c, lctx *d, unsigned int recordtype,
	i64 pos1, i64 len)
{
	unsigned int n;

	if(len!=4) return;
	n = (unsigned int)de_getu32le(pos1);
	de_dbg(c, "value: 0x%08x", n);
}

static void extract_system_icon(deark *c, lctx *d, i64 pos, i64 len)
{
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);
	fi->mod_time = d->gendate;
	dbuf_create_file_from_slice(c->infile, pos, len, "ico", fi, DE_CREATEFLAG_IS_AUX);
	de_finfo_destroy(c, fi);
}

static void do_SYSTEMREC(deark *c, lctx *d, unsigned int recordtype,
	i64 pos1, i64 len, const struct systemrec_info *sti)
{
	if(recordtype==1) { // title
		if(!d->help_file_title) {
			d->help_file_title = ucstring_create(c);
		}
		do_SYSTEMREC_STRINGZ(c, d, recordtype, pos1, len, sti, d->help_file_title);
	}
	else if(recordtype==2) { // copyright
		if(!d->help_file_copyright) {
			d->help_file_copyright = ucstring_create(c);
		}
		do_SYSTEMREC_STRINGZ(c, d, recordtype, pos1, len, sti, d->help_file_copyright);
	}
	else if(recordtype==3 && len==4) { // contents
		do_SYSTEMREC_uint32_hex(c, d, recordtype, pos1, len);
	}
	else if(recordtype==5) { // Icon
		d->has_ico = 1;
		extract_system_icon(c, d, pos1, len);
	}
	else if(sti->flags&0x10) {
		do_SYSTEMREC_STRINGZ(c, d, recordtype, pos1, len, sti, NULL);
	}
	else {
		if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, pos1, len, 256, NULL, 0x1);
		}
	}
}

static const struct systemrec_info *find_sysrec_info(deark *c, lctx *d, unsigned int t)
{
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(systemrec_info_arr); i++) {
		const struct systemrec_info *sti;
		sti = &systemrec_info_arr[i];
		if(sti->rectype==t &&
			(sti->flags&0x0f)==0)
		{
			return sti;
		}
	}
	return &systemrec_info_default;
}

static int do_file_SYSTEM_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 magic;
	i64 gen_date;
	unsigned int flags;
	char timestamp_buf[64];
	int retval = 0;

	magic = de_getu16le_p(&pos);
	if(magic!=0x036c) {
		de_err(c, "Expected SYSTEM data at %d not found", (int)pos1);
		goto done;
	}

	de_dbg(c, "SYSTEM file data at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->ver_minor = (int)de_getu16le_p(&pos);
	d->ver_major = (int)de_getu16le_p(&pos);
	de_dbg(c, "help format version: %d.%d", d->ver_major, d->ver_minor);

	if(d->ver_major!=1) {
		de_err(c, "Unsupported file version: %d.%d", d->ver_major, d->ver_minor);
		goto done;
	}

	gen_date = de_geti32le_p(&pos);
	hlptime_to_timestamp(gen_date, &d->gendate);
	de_timestamp_to_string(&d->gendate, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "GenDate: %d (%s)", (int)gen_date, timestamp_buf);

	flags = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "system flags: 0x%04x", flags);

	if(d->ver_minor>16) {
		if(flags==8) {
			d->is_lz77_compressed = 1;
			d->topic_block_size = 2048;
		}
		else if(flags==4) {
			d->is_lz77_compressed = 1;
			d->topic_block_size = 4096;
		}
		else {
			d->is_lz77_compressed = 0;
			d->topic_block_size = 4096;
		}
	}
	else {
		d->is_lz77_compressed = 0;
		d->topic_block_size = 2048;
	}
	de_dbg(c, "lz77 compression: %d", d->is_lz77_compressed);
	de_dbg(c, "topic block size: %d", (int)d->topic_block_size);

	retval = 1;
done:
	return retval;
}

static void do_file_SYSTEM_SYSTEMRECS(deark *c, lctx *d, i64 pos1, i64 len,
	int systemrecs_pass)
{
	i64 pos = pos1;

	while((pos1+len)-pos >=4) {
		unsigned int recordtype;
		i64 datasize;
		i64 systemrec_startpos;
		const struct systemrec_info *sti;

		systemrec_startpos = pos;

		recordtype = (unsigned int)de_getu16le_p(&pos);
		datasize = de_getu16le_p(&pos);

		sti = find_sysrec_info(c, d, recordtype);
		de_dbg(c, "SYSTEMREC type %u (%s) at %d, dpos=%d, dlen=%d",
			recordtype, sti->name,
			(int)systemrec_startpos, (int)pos, (int)datasize);

		if(pos+datasize > pos1+len) break; // bad data
		de_dbg_indent(c, 1);
		do_SYSTEMREC(c, d, recordtype, pos, datasize, sti);
		de_dbg_indent(c, -1);
		pos += datasize;
	}
}

static void do_file_SYSTEM(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	// We'll read the SYSTEM "file" before pass 2, most importantly to record
	// the format version information.
	//
	// The SYSTEM file may contain a series of SYSTEMREC records that we want
	// to parse.
	// Note: It seems like we might have to make two (sub)passes over the
	// SYSTEMREC records, the first pass to collect the "charset" setting, so it
	// can be used to interpret records that appear before it. But I've never
	// seen a charset record that I can make sense of -- it's usually just a
	// random number of NUL bytes.

	if(d->pass!=1) goto done;

	if(!do_file_SYSTEM_header(c, d, pos)) goto done;
	pos += 12;

	if(d->ver_minor<=16) {
		d->help_file_title = ucstring_create(c);
		do_display_and_store_STRINGZ(c, d, pos, (pos1+len)-pos, "HelpFileTitle", d->help_file_title);
	}
	else {
		// A sequence of variable-sized SYSTEMRECs
		do_file_SYSTEM_SYSTEMRECS(c, d, pos, (pos1+len)-pos, 1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file_SHG(deark *c, lctx *d, i64 pos1, i64 used_space)
{
	i64 oldsig;
	const char *ext;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

	// Reportedly, 0x506c = SHG = 1 image, and 0x706c = MRB = >1 image.
	// But I'm not convinced that's correct.
	// I'm to sure what to do, as far as selecting a file extension, and potentially
	// correcting the signature. Current behavior is to leave the signature the same,
	// and derive the file extension from the number of images.
	oldsig = de_getu16le(pos1);

	if(oldsig==0x506c || oldsig==0x706c) {
		i64 num_images;

		num_images = de_getu16le(pos1+2);
		if(num_images>1) {
			ext="mrb";
		}
		else {
			ext="shg";
		}
	}
	else {
		ext="bin";
	}

	fi = de_finfo_create(c);
	// (Note that if we were to correct the signature, we probably should not copy
	// the mod time.)
	fi->mod_time = d->gendate;
	outf = dbuf_create_output_file(c, ext, fi, 0);
	dbuf_copy(c->infile, pos1, used_space, outf);
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static void do_extract_raw_file(deark *c, lctx *d, i64 pos1, i64 used_space,
	struct de_stringreaderdata *fn)
{
	de_finfo *fi = NULL;
	const char *ext = NULL;

	fi = de_finfo_create(c);
	fi->mod_time = d->gendate;
	if(fn && ucstring_isnonempty(fn->str)) {
		de_finfo_set_name_from_ucstring(c, fi, fn->str, 0);
		fi->original_filename_flag = 1;
	}
	else {
		ext = "bin";
	}
	dbuf_create_file_from_slice(c->infile, pos1, used_space, ext, fi, 0);

	de_finfo_destroy(c, fi);
}

struct topiclink_data {
	i64 blocksize;
	i64 datalen2;
	u32 prevblock;
	u32 nextblock;
	i64 datalen1;
	u8 recordtype;

	i64 linkdata1_pos;
	i64 linkdata1_len;
	i64 linkdata2_pos;
	i64 linkdata2_cmprlen;
	i64 linkdata2_uncmprlen;

	i64 paragraphinfo_pos;
	u8 seems_compressed;
};

struct topic_block_info_item {
	i64 pos; // position in ->unc_topicdata
	i64 len;
};

struct topic_ctx {
	i64 num_topic_blocks;
	struct topic_block_info_item *topic_block_info; // array [num_topic_blocks]
	dbuf *unc_topicdata;
	u32 pos_of_first_topiclink;
};

static void ensure_text_output_file_open(deark *c, lctx *d)
{
	if(d->outf_text) return;
	d->outf_text = dbuf_create_output_file(c, "dump.txt", NULL, 0);
	if(d->output_is_utf8 && c->write_bom) {
		dbuf_write_uchar_as_utf8(d->outf_text, 0xfeff);
	}
	if(ucstring_isnonempty(d->help_file_title)) {
		dbuf_puts(d->outf_text, "Title: ");
		// TODO: This doesn't do the right thing if !d->output_is_utf8.
		ucstring_write_as_utf8(c, d->help_file_title, d->outf_text, 0);
		dbuf_puts(d->outf_text, "\n");
	}
	if(ucstring_isnonempty(d->help_file_copyright)) {
		dbuf_puts(d->outf_text, "Copyright: ");
		ucstring_write_as_utf8(c, d->help_file_copyright, d->outf_text, 0);
		dbuf_puts(d->outf_text, "\n");
	}
}

// Emit a string that needs no conversion.
static void emit_raw_sz(deark *c, lctx *d, const char *sz)
{
	if(!d->outf_text) return;
	dbuf_puts(d->outf_text, sz);
}

// Emit a content string, i.e. one that might need character encoding conversion
// or escaping.
static void emit_slice(deark *c, lctx *d, dbuf *inf, i64 pos, i64 len)
{
	if(!d->outf_text) return;

	if(!d->output_is_utf8) {
		dbuf_copy(inf, pos, len, d->outf_text);
		return;
	}

	ucstring_empty(d->tmpucstring1);
	dbuf_read_to_ucstring(inf, pos, len, d->tmpucstring1, 0, d->input_encoding);
	ucstring_write_as_utf8(c, d->tmpucstring1, d->outf_text, 0);
}

static void emit_phrase(deark *c, lctx *d, dbuf *outf, unsigned int phrasenum)
{
	if(phrasenum < d->num_phrases) {
		dbuf_copy(d->phrases_data, (i64)d->phrase_info[phrasenum].pos,
			(i64)d->phrase_info[phrasenum].len, outf);
	}
}

static void do_phrase_decompression(deark *c, lctx *d, dbuf *inf, i64 pos1, i64 len,
	dbuf *outf,  i64 unc_len_expected)
{
	i64 pos = pos1;
	i64 endpos = pos1+len;

	if(!d->phrases_data) return;

	while(1) {
		u8 b;

		if(pos >= endpos) break;
		b = dbuf_getbyte_p(inf, &pos);
		if(b==0 || b>=0x10) {
			dbuf_writebyte(outf, b);
		}
		else {
			u8 b2;
			unsigned int n;

			if(pos >= endpos) break;
			b2 = dbuf_getbyte_p(inf, &pos);
			n = ((unsigned int)(b-1)<<8) | b2;
			emit_phrase(c, d, outf, n>>1);
			if(n & 0x1) {
				dbuf_writebyte(outf, ' ');
			}
		}
	}
}

static void do_hall_decompression(deark *c, lctx *d, dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, i64 unc_len_expected)
{
	static const u8 action[16] = {0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4};
	i64 pos = pos1;
	i64 endpos = pos1+len;
	unsigned int n;
	i64 outf_expected_endpos;

	outf_expected_endpos = outf->len + unc_len_expected;

	while(1) {
		u8 b;

		if(outf->len >= outf_expected_endpos) goto unc_done;
		if(pos >= endpos) goto unc_done;
		b = dbuf_getbyte_p(inf, &pos);
		switch(action[b&0x0f]) {
		case 0:
			emit_phrase(c, d, outf, b>>1);
			break;
		case 1:
			if(pos >= endpos) goto unc_done;
			n = (((unsigned int)b & 0xfc) << 6) | 0x80;
			n += dbuf_getbyte_p(inf, &pos);
			emit_phrase(c, d, outf, n);
			break;
		case 2:
			n = (b >> 3) +1;
			if(pos + (i64)n > endpos) goto unc_done;
			dbuf_copy(inf, pos, (i64)n, outf);
			pos += (i64)n;
			break;
		case 3:
			dbuf_write_run(outf, ' ', (i64)(b>>4)+1);
			break;
		default: // 4
			dbuf_write_zeroes(outf, (i64)(b>>4)+1);
			break;
		}
	}
unc_done:
	;
}

static int do_topiclink_rectype_32_linkdata1(deark *c, lctx *d,
	struct topic_ctx *tctx, struct topiclink_data *tld)
{
	i64 pos = tld->linkdata1_pos;
	dbuf *inf = tctx->unc_topicdata;
	i64 topicsize;
	i64 topiclength;
	unsigned int id;
	unsigned int bits;
	int retval = 0;

	// TODO: type 33 (table)
	if(tld->recordtype!=1 && tld->recordtype!=32) goto done;

	topicsize = fmtutil_hlp_get_csl_p(inf, &pos);
	de_dbg(c, "topic size: %"I64_FMT, topicsize);

	if(tld->recordtype==32) {
		topiclength = fmtutil_hlp_get_cus_p(inf, &pos);
		de_dbg(c, "topic length: %"I64_FMT, topiclength);
	}

	pos++; // unknownUnsignedChar
	pos++; // unknownBiasedChar
	id = (unsigned int)dbuf_getu16le_p(inf, &pos);
	de_dbg(c, "id: %u", id);
	bits = (unsigned int)dbuf_getu16le_p(inf, &pos);
	de_dbg(c, "bits: 0x%04x", bits);

	if(bits & 0x0001) { // Unknown
		(void)fmtutil_hlp_get_csl_p(inf, &pos);
	}
	if(bits & 0x0002) { // SpacingAbove
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	if(bits & 0x0004) { // SpacingBelow
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	if(bits & 0x0008) { // SpacingLines
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	if(bits & 0x0010) { // LeftIndent
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	if(bits & 0x0020) { // RightIndent
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	if(bits & 0x0040) { // FirstlineIndent
		(void)fmtutil_hlp_get_css_p(inf, &pos);
	}
	// 0x0080 = unused
	if(bits & 0x0100) { // Borderinfo
		goto done; // TODO
	}
	if(bits & 0x0200) { // Tabinfo
		goto done; // TODO
	}
	// 0x0400 = RightAlignedParagraph
	// 0x0800 = CenterAlignedParagraph

	tld->paragraphinfo_pos = pos;
	retval = 1;
done:
	return retval;
}

// linkdata2 = after Phrase/Hall decompression
static void do_topiclink_rectype_1_32(deark *c, lctx *d,
	struct topic_ctx *tctx, struct topiclink_data *tld, dbuf *linkdata2)
{
	i64 pos;
	int in_string = 0;
	int string_count = 0;
	int byte_count = 0;

	if(!d->extract_text) goto done;
	ensure_text_output_file_open(c, d);

	do_topiclink_rectype_32_linkdata1(c, d, tctx, tld);

	// TODO: This is very quick & dirty.
	// The linkdata2 is a collection of NUL-terminated strings. We'd have to
	// interpret the command bytes from linkdata1 to know how to format them.

	pos = 0;
	dbuf_truncate(d->tmpdbuf1, 0); // A place to collect the current output string

	while(1) {
		u8 b;

		if(pos >= linkdata2->len) break;
		b = dbuf_getbyte_p(linkdata2, &pos);
		if(b==0x00) {
			if(in_string) {
				emit_slice(c, d, d->tmpdbuf1, 0, d->tmpdbuf1->len);
				dbuf_truncate(d->tmpdbuf1, 0);
				emit_raw_sz(c, d, "\n");
				string_count++;
				in_string = 0;
			}
		}
		else {
			dbuf_writebyte(d->tmpdbuf1, b);
			byte_count++;
			in_string = 1;
		}
	}
	if(in_string) {
		emit_slice(c, d, d->tmpdbuf1, 0, d->tmpdbuf1->len);
		dbuf_truncate(d->tmpdbuf1, 0);
		emit_raw_sz(c, d, "\n");
		string_count++;
	}
	de_dbg2(c, "[emitted %d strings, totaling %d bytes]", string_count, byte_count);

done:
	;
}

// TOPIC header
static void do_topiclink_rectype_2_linkdata2(deark *c, lctx *d,
	struct topic_ctx *tctx, struct topiclink_data *tld, dbuf *linkdata2)
{
	i64 k;
	int bytecount = 0;

	dbuf_truncate(d->tmpdbuf1, 0);
	emit_raw_sz(c, d, "# ");

	for(k=0; k<linkdata2->len; k++) {
		u8 b;

		b = dbuf_getbyte(linkdata2, k);
		if(b==0) break;
		dbuf_writebyte(d->tmpdbuf1, b);
		bytecount++;
	}

	if(bytecount>0) {
		emit_slice(c, d, d->tmpdbuf1, 0, d->tmpdbuf1->len);
	}
	else {
		emit_raw_sz(c, d, "(untitled topic)");
	}

	emit_raw_sz(c, d, " #\n");
}

// topic header and title
static void do_topiclink_rectype_2(deark *c, lctx *d,
	struct topic_ctx *tctx, struct topiclink_data *tld, dbuf *linkdata2)
{
	if(!d->extract_text) goto done;
	ensure_text_output_file_open(c, d);

	do_topiclink_rectype_2_linkdata2(c, d, tctx, tld, linkdata2);
done:
	;
}

// Returns 1 if we set next_pos_code
static int do_topiclink(deark *c, lctx *d, struct topic_ctx *tctx, i64 pos1, u32 *next_pos_code)
{
	struct topiclink_data *tld = NULL;
	i64 pos = pos1;
	i64 linkdata2_nbytes_avail;
	int retval = 0;
	dbuf *inf = tctx->unc_topicdata;
	char tmpbuf[24];

	tld = de_malloc(c, sizeof(struct topiclink_data));

	tld->blocksize = dbuf_geti32le_p(inf, &pos);
	de_dbg(c, "blocksize: %d", (int)tld->blocksize);
	if((tld->blocksize<21) || (pos1 + tld->blocksize > inf->len)) {
		de_dbg(c, "bad topiclink blocksize");
		goto done;
	}
	tld->datalen2 = dbuf_geti32le_p(inf, &pos);
	de_dbg(c, "datalen2 (after any decompression): %d", (int)tld->datalen2);

	tld->prevblock = (u32)dbuf_getu32le_p(inf, &pos);
	format_topiclink(c, d, tld->prevblock, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "prevblock: %s", tmpbuf);

	tld->nextblock = (u32)dbuf_getu32le_p(inf, &pos);
	format_topiclink(c, d, tld->nextblock, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "nextblock: %s", tmpbuf);
	*next_pos_code = (u32)tld->nextblock;
	retval = 1;

	tld->datalen1 = dbuf_geti32le_p(inf, &pos);
	de_dbg(c, "datalen1: %d", (int)tld->datalen1);
	tld->recordtype = dbuf_getbyte_p(inf, &pos);
	de_dbg(c, "record type: %d", (int)tld->recordtype);

	tld->linkdata1_pos = pos1 + 21;
	tld->linkdata1_len = tld->datalen1 - 21;
	de_dbg(c, "linkdata1: pos=[%"I64_FMT"], len=%"I64_FMT, tld->linkdata1_pos, tld->linkdata1_len);

	tld->linkdata2_pos = tld->linkdata1_pos + tld->linkdata1_len;
	linkdata2_nbytes_avail = tld->blocksize - tld->datalen1;

	if(d->uses_old_phrase_compression || d->uses_hall_compression) {
		if(tld->datalen2 > linkdata2_nbytes_avail) {
			// Phrase/Hall compression used in this topiclink
			tld->seems_compressed = 1;
			tld->linkdata2_cmprlen = linkdata2_nbytes_avail;
			tld->linkdata2_uncmprlen = tld->datalen2;
		}
		else {
			// Phrase/Hall compression used in this file, but not in this topiclink
			tld->linkdata2_cmprlen = tld->datalen2;
			tld->linkdata2_uncmprlen = tld->datalen2;
		}
	}
	else {
		// Phrase/Hall compression not used in this file
		tld->linkdata2_cmprlen = de_min_int(tld->datalen2, linkdata2_nbytes_avail);
		tld->linkdata2_uncmprlen = tld->linkdata2_cmprlen;
	}

	if((tld->linkdata1_pos<pos1) || (tld->linkdata2_pos<pos1) ||
		(tld->linkdata1_len<0) || (tld->linkdata2_cmprlen<0) ||
		(tld->linkdata1_pos + tld->linkdata1_len > pos1+tld->blocksize) ||
		(tld->linkdata2_pos + tld->linkdata2_cmprlen > pos1+tld->blocksize))
	{
		de_dbg(c, "bad linkdata");
		goto done;
	}

	de_dbg(c, "linkdata2: pos=[%"I64_FMT"], cmprlen=%"I64_FMT", uncmprlen=%"I64_FMT,
		tld->linkdata2_pos, tld->linkdata2_cmprlen, tld->linkdata2_uncmprlen);

	// Decompress linkdata2 if necessary
	dbuf_truncate(d->unc_linkdata2_dbuf, 0);
	if(tld->seems_compressed && d->uses_old_phrase_compression) {
		do_phrase_decompression(c, d, inf, tld->linkdata2_pos, tld->linkdata2_cmprlen,
			d->unc_linkdata2_dbuf, tld->linkdata2_uncmprlen);
	}
	else if(tld->seems_compressed && d->uses_hall_compression) {
		do_hall_decompression(c, d, inf, tld->linkdata2_pos, tld->linkdata2_cmprlen,
			d->unc_linkdata2_dbuf,tld->linkdata2_uncmprlen);
	}
	else {
		dbuf_copy(inf, tld->linkdata2_pos, tld->linkdata2_cmprlen, d->unc_linkdata2_dbuf);
	}

	switch(tld->recordtype) {
	case 1:
	case 32:
	case 35:
		do_topiclink_rectype_1_32(c, d, tctx, tld, d->unc_linkdata2_dbuf);
		break;
	case 2:
		do_topiclink_rectype_2(c, d, tctx, tld, d->unc_linkdata2_dbuf);
		break;
	default:
		de_warn(c, "Unsupported record type: %d", (int)tld->recordtype);
	}

done:
	de_free(c, tld);
	return retval;
}

static int topicpos_to_abspos(deark *c, lctx *d, struct topic_ctx *tctx, i64 topicpos,
	i64 *pabspos)
{
	i64 blknum, blkoffs;

	if(!d->topic_block_size) return 0;
	blkoffs = topicpos % 16384;
	if(blkoffs<TOPICBLOCKHDRSIZE) return 0;
	blknum = topicpos / 16384;
	if(blknum<0 || blknum>=tctx->num_topic_blocks) return 0;
	*pabspos = tctx->topic_block_info[blknum].pos + (blkoffs-TOPICBLOCKHDRSIZE);
	return 1;
}

static i64 hc30_abspos_plus_offset_to_abspos(deark *c, lctx *d, i64 pos, i64 offset)
{
	i64 blksize = d->topic_block_size-TOPICBLOCKHDRSIZE;
	i64 start_of_curr_block;
	i64 end_of_curr_block;
	i64 n;

	// We're at a position in blocks of size (d->topic_block_size-12). We need to add
	// 'offset', but subtract 12 every time we cross a block boundary.
	start_of_curr_block = (pos/blksize)*blksize;
	end_of_curr_block = start_of_curr_block + blksize;
	if(pos+offset <= end_of_curr_block) {
		return pos + offset;
	}

	n = pos+offset - end_of_curr_block;
	return pos + offset - TOPICBLOCKHDRSIZE*(1+(n / blksize));
}

static int calc_next_topiclink_pos(deark *c, lctx *d, struct topic_ctx *tctx, i64 curpos,
	u32 next_pos_code, i64 *pnextpos)
{
	*pnextpos = 0;

	if(next_pos_code==INVALIDPOS) {
		de_dbg(c, "[stopping TOPIC parsing, end-of-links marker found]");
		return 0;
	}

	if(d->ver_minor<=16) {
		if(next_pos_code < 21) {
			de_dbg(c, "[stopping TOPIC parsing, no nextblock available]");
			return 0;
		}
		*pnextpos = hc30_abspos_plus_offset_to_abspos(c, d, curpos, next_pos_code);
	}
	else {
		if(!topicpos_to_abspos(c, d, tctx, next_pos_code, pnextpos)) {
			de_dbg(c, "[stopping TOPIC parsing, no nextblock available]");
			return 0;
		}

		if((*pnextpos) <= curpos) {
			de_dbg(c, "[stopping TOPIC parsing, blocks not in order]");
			return 0;
		}
	}

	return 1;
}

static void do_topicdata(deark *c, lctx *d, struct topic_ctx *tctx)
{
	i64 pos;
	int saved_indent_level, saved_indent_level2;
	dbuf *inf = tctx->unc_topicdata;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "topic data");

	de_dbg_indent(c, 1);
	if(!inf) {
		goto done;
	}

	de_dbg_indent_save(c, &saved_indent_level2);

	if(tctx->pos_of_first_topiclink==INVALIDPOS || tctx->pos_of_first_topiclink<TOPICBLOCKHDRSIZE) {
		de_warn(c, "Bad first topic link");
		pos = 0;
	}
	else {
		// Maybe we should call topicpos_to_abspos(), etc., but this should be
		// correct since an offset in the first topicblock.
		pos = tctx->pos_of_first_topiclink - TOPICBLOCKHDRSIZE;
	}

	while(1) {
		u32 next_pos_code;
		i64 next_pos = 0;
		int ret;

		if(pos > inf->len) {
			de_dbg(c, "[stopping TOPIC parsing, exceeded end of data]");
			break;
		}
		if(pos == inf->len) {
			de_dbg(c, "[stopping TOPIC parsing, reached end of data]");
			break;
		}
		if(pos + 21 > inf->len) {
			de_warn(c, "Error parsing TOPIC, not enough room for another TOPICLINK (%"I64_FMT
				", %"I64_FMT")", pos, inf->len);
			break;
		}

		// TODO: Display as "Blk#:offs"
		de_dbg(c, "topiclink at [%"I64_FMT"]", pos);
		de_dbg_indent(c, 1);
		next_pos_code = 0;
		if(!do_topiclink(c, d, tctx, pos, &next_pos_code)) goto done;
		de_dbg_indent(c, -1);

		ret = calc_next_topiclink_pos(c, d, tctx, pos, next_pos_code, &next_pos);
		if(!ret) break;
		pos = next_pos;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void decompress_topic_block(deark *c, lctx *d, struct topic_ctx *tctx,
	i64 blknum, i64 blk_dpos, i64 blk_dlen,
	dbuf *outf)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	i64 len_before;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = c->infile;
	dcmpri.pos = blk_dpos;
	dcmpri.len = blk_dlen;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	// TODO: Confirm what happens if a block decompresses to more than 16384-12 bytes.
	dcmpro.expected_len = 16384-TOPICBLOCKHDRSIZE;
	len_before = outf->len;
	fmtutil_decompress_hlp_lz77(c, &dcmpri, &dcmpro, &dres);
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", blk_dlen,
		outf->len - len_before);
}

static void do_file_TOPIC(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int saved_indent_level;
	struct topic_ctx *tctx = NULL;
	i64 blknum;

	de_dbg_indent_save(c, &saved_indent_level);
	tctx = de_malloc(c, sizeof(struct topic_ctx));
	de_dbg(c, "TOPIC at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);

	if(!d->found_system_file || d->topic_block_size<2048) {
		de_err(c, "SYSTEM file not found");
		goto done;
	}

	if(d->extract_text) {
		tctx->unc_topicdata = dbuf_create_membuf(c, 0, 0);
	}
	tctx->num_topic_blocks = (len + (d->topic_block_size - TOPICBLOCKHDRSIZE)) % d->topic_block_size;
	tctx->topic_block_info = de_mallocarray(c, tctx->num_topic_blocks, sizeof(struct topic_block_info_item));

	tctx->pos_of_first_topiclink = INVALIDPOS;

	// A series of blocks, each with a 12-byte header
	for(blknum=0; blknum<tctx->num_topic_blocks; blknum++) {
		u32 lastlink, firstlink, lastheader;
		i64 blklen;
		i64 blk_dpos;
		i64 blk_dlen;
		char tbuf1[24], tbuf2[24], tbuf3[24];

		blklen = d->topic_block_size;
		if(blklen > (pos1+len)-pos) {
			blklen = (pos1+len)-pos;
		}
		if(blklen<TOPICBLOCKHDRSIZE) break;
		blk_dpos = pos+TOPICBLOCKHDRSIZE;
		blk_dlen = blklen-TOPICBLOCKHDRSIZE;

		de_dbg(c, "TOPIC block #%d at %d, dpos=%d, dlen=%d", (int)blknum, (int)pos,
			(int)blk_dpos, (int)blk_dlen);
		de_dbg_indent(c, 1);
		lastlink = (u32)de_getu32le(pos);
		firstlink = (u32)de_getu32le(pos+4);
		lastheader = (u32)de_getu32le(pos+8);
		format_topiclink(c, d, lastlink, tbuf1, sizeof(tbuf1));
		format_topiclink(c, d, firstlink, tbuf2, sizeof(tbuf2));
		format_topiclink(c, d, lastheader, tbuf3, sizeof(tbuf3));
		de_dbg(c, "LastLink=%s, FirstLink=%s, LastHeader=%s",
			tbuf1, tbuf2, tbuf3);
		if(tctx->pos_of_first_topiclink==INVALIDPOS && firstlink!=INVALIDPOS) {
			tctx->pos_of_first_topiclink = firstlink;
		}

		if(d->extract_text && tctx->unc_topicdata) {
			// Record the position for later reference.
			tctx->topic_block_info[blknum].pos = tctx->unc_topicdata->len;

			if(d->is_lz77_compressed) {
				decompress_topic_block(c, d, tctx, blknum, blk_dpos, blk_dlen, tctx->unc_topicdata);
			}
			else {
				dbuf_copy(c->infile, blk_dpos, blk_dlen, tctx->unc_topicdata);
			}

			tctx->topic_block_info[blknum].len = tctx->unc_topicdata->len - tctx->topic_block_info[blknum].pos;

			de_dbg2(c, "[current decompressed size: %"I64_FMT"]", tctx->unc_topicdata->len);
		}

		de_dbg_indent(c, -1);
		pos += blklen;
	}

	if(tctx->unc_topicdata && tctx->unc_topicdata->len>0) {
		do_topicdata(c, d, tctx);
	}

done:
	if(tctx) {
		dbuf_close(tctx->unc_topicdata);
		de_free(c, tctx->topic_block_info);
		de_free(c, tctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);

}
static void do_index_page(deark *c, lctx *d, i64 pos1, i64 *prev_page)
{
	*prev_page = de_geti16le(pos1+4);
	de_dbg(c, "PreviousPage: %d", (int)*prev_page);
}

static int de_is_digit(char x)
{
	return (x>='0' && x<='9');
}

static enum hlp_filetype filename_to_filetype(deark *c, lctx *d, const char *fn)
{
	const char *ext;
	size_t extlen;

	if(fn[0]=='|') {
		if(!de_strcmp(fn, "|TOPIC")) return FILETYPE_TOPIC;
		if(!de_strcmp(fn, "|SYSTEM")) return FILETYPE_SYSTEM;
		if(!de_strncmp(fn, "|bm", 3) && de_is_digit(fn[3])) return FILETYPE_SHG;
		if(!de_strcmp(fn, "|Phrases")) return FILETYPE_PHRASES;
		if(!de_strcmp(fn, "|PhrIndex")) return FILETYPE_PHRINDEX;
		if(!de_strcmp(fn, "|PhrImage")) return FILETYPE_PHRIMAGE;
		return FILETYPE_OTHERSPECIAL;
	}

	ext = de_get_sz_ext(fn);
	extlen = de_strlen(ext);

	// Some SHG streams' names don't start with "|". Assume it is SHG if it
	// starts with "bm" and a digit, and doesn't have a ".".
	if(extlen==0) {
		if(!de_strncmp(fn, "bm", 2) && de_is_digit(fn[2])) return FILETYPE_SHG;
	}

	// Not sure how bold to be here. Should we extract every file that we can't
	// identify? Or maybe only those that have a filename extension?
	return FILETYPE_EXTRACTABLE;
}

static void do_leaf_page(deark *c, lctx *d, i64 pos1, i64 *pnext_page)
{
	i64 n;
	i64 pos = pos1;
	i64 foundpos;
	i64 num_entries;
	i64 file_offset;
	i64 k;
	struct de_stringreaderdata *fn_srd = NULL;
	enum hlp_filetype file_type;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	n = de_getu16le_p(&pos); // "Unused"
	de_dbg(c, "free bytes at end of this page: %d", (int)n);

	num_entries = de_geti16le_p(&pos);
	de_dbg(c, "NEntries: %d", (int)num_entries);

	n = de_geti16le_p(&pos);
	de_dbg(c, "PreviousPage: %d", (int)n);

	n = de_geti16le_p(&pos);
	de_dbg(c, "NextPage: %d", (int)n);
	if(pnext_page) *pnext_page = n;

	for(k=0; k<num_entries; k++) {
		int pass_for_this_file;

		de_dbg(c, "entry[%d]", (int)k);
		de_dbg_indent(c, 1);

		if(!dbuf_search_byte(c->infile, 0x00, pos, 260, &foundpos)) {
			de_err(c, "Malformed leaf page at %d", (int)pos1);
			goto done;
		}

		if(fn_srd) {
			de_destroy_stringreaderdata(c, fn_srd);
		}
		fn_srd = dbuf_read_string(c->infile, pos, foundpos-pos, foundpos-pos, 0, d->input_encoding);
		de_dbg(c, "FileName: \"%s\"", ucstring_getpsz_d(fn_srd->str));
		pos = foundpos + 1;

		file_offset = de_geti32le_p(&pos);
		de_dbg(c, "FileOffset: %d", (int)file_offset);

		file_type = filename_to_filetype(c, d, fn_srd->sz);

		switch(file_type) {
		case FILETYPE_SYSTEM:
			d->found_system_file = 1;
			d->offset_of_system_file = file_offset;
			pass_for_this_file = 1;
			break;
		case FILETYPE_TOPIC:
			d->found_TOPIC_file = 1;
			d->offset_of_TOPIC = file_offset;
			pass_for_this_file = 1;
			break;
		case FILETYPE_PHRASES:
			d->found_Phrases_file = 1;
			d->offset_of_Phrases = file_offset;
			pass_for_this_file = 1;
			break;
		case FILETYPE_PHRINDEX:
			d->found_PhrIndex_file = 1;
			d->offset_of_PhrIndex = file_offset;
			pass_for_this_file = 1;
			break;
		case FILETYPE_PHRIMAGE:
			d->found_PhrImage_file = 1;
			d->offset_of_PhrImage = file_offset;
			pass_for_this_file = 1;
			break;
		default:
			pass_for_this_file = 2;
		}

		if(d->pass==2 && d->extract_raw_streams) {
			do_file(c, d, file_offset, file_type, 1, fn_srd);
		}
		else if(d->pass==2 && pass_for_this_file==2) {
			do_file(c, d, file_offset, file_type, 0, fn_srd);
		}

		de_dbg_indent(c, -1);
	}

done:
	de_destroy_stringreaderdata(c, fn_srd);
	de_dbg_indent_restore(c, saved_indent_level);
}

// Sets d->bpt.first_leaf_page
static int find_first_leaf_page(deark *c, lctx *d)
{
	i64 curr_page;
	i64 curr_level;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	curr_page = d->bpt.root_page;
	curr_level = d->bpt.num_levels;

	de_dbg(c, "looking for first leaf page");
	de_dbg_indent(c, 1);

	while(curr_level>1) {
		i64 prev_page;
		i64 page_pos;

		if(curr_page<0) goto done;
		page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

		de_dbg(c, "page %d is an index page, level=%d", (int)curr_page, (int)curr_level);

		prev_page = -1;
		de_dbg_indent(c, 1);
		do_index_page(c, d, page_pos, &prev_page);
		de_dbg_indent(c, -1);

		curr_page = prev_page;
		curr_level--;
	}

	de_dbg(c, "page %d is the first leaf page", (int)curr_page);
	d->bpt.first_leaf_page = curr_page;

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void sanitize_phrase_info(deark *c, lctx *d)
{
	unsigned int k;

	if(!d->phrases_data) {
		d->num_phrases = 0;
		return;
	}

	for(k=0; k<d->num_phrases; k++) {
		if((i64)d->phrase_info[k].pos + (i64)d->phrase_info[k].len > d->phrases_data->len) {
			d->phrase_info[k].pos = 0;
			d->phrase_info[k].len = 0;
		}
	}
}

static void do_after_pass_1(deark *c, lctx *d)
{
	// Read the SYSTEM file first -- lots of other things depend on it.
	if(d->found_system_file) {
		do_file(c, d, d->offset_of_system_file, FILETYPE_SYSTEM, 0, NULL);
	}

	if(d->found_Phrases_file) {
		d->uses_old_phrase_compression = 1;
	}
	else if(d->found_PhrIndex_file && d->found_PhrImage_file) {
		d->uses_hall_compression = 1;
	}

	if(d->input_encoding==DE_ENCODING_UNKNOWN || d->input_encoding==DE_ENCODING_ASCII) {
		d->output_is_utf8 = 0;
	}
	else {
		d->output_is_utf8 = 1;
	}

	// Read other special files, in a suitable order.

	if(d->found_Phrases_file && d->uses_old_phrase_compression) {
		do_file(c, d, d->offset_of_Phrases, FILETYPE_PHRASES, 0, NULL);
	}

	if(d->found_PhrIndex_file && d->uses_hall_compression) {
		do_file(c, d, d->offset_of_PhrIndex, FILETYPE_PHRINDEX, 0, NULL);
	}
	if(d->found_PhrImage_file && d->uses_hall_compression) {
		do_file(c, d, d->offset_of_PhrImage, FILETYPE_PHRIMAGE, 0, NULL);
	}
	sanitize_phrase_info(c, d);

	if(d->found_TOPIC_file) {
		do_file(c, d, d->offset_of_TOPIC, FILETYPE_TOPIC, 0, NULL);
	}
}

// This function is only for the "internal directory" tree.
// There are other data objects in HLP files that use the same kind of data
// structure. If we ever want to parse them, this function will have to be
// genericized.
static void do_bplustree(deark *c, lctx *d, i64 pos1, i64 len,
	int is_internaldir)
{
	i64 pos = pos1;
	i64 n;
	int saved_indent_level;
	u8 *page_seen = NULL;
	struct de_stringreaderdata *structure = NULL;

	if(!is_internaldir) return;

	de_dbg_indent_save(c, &saved_indent_level);

	n = de_getu16le_p(&pos);
	if(n != 0x293b) {
		de_err(c, "Expected B+ tree structure at %d not found", (int)pos1);
		goto done;
	}

	//de_dbg(c, "B+ tree at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->bpt.flags = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "Btree flags: 0x%04x", d->bpt.flags);

	d->bpt.pagesize = de_getu16le_p(&pos);
	de_dbg(c, "PageSize: %d", (int)d->bpt.pagesize);

	// TODO: Understand the Structure field
	structure = dbuf_read_string(c->infile, pos, 16, 16, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "Structure: \"%s\"", ucstring_getpsz_d(structure->str));
	de_destroy_stringreaderdata(c, structure);
	structure = NULL;
	pos += 16;

	pos += 2; // MustBeZero
	pos += 2; // PageSplits

	d->bpt.root_page = de_geti16le_p(&pos);
	de_dbg(c, "RootPage: %d", (int)d->bpt.root_page);

	pos += 2; // MustBeNegOne

	d->bpt.num_pages = de_geti16le_p(&pos);
	de_dbg(c, "TotalPages: %d", (int)d->bpt.num_pages);

	d->bpt.num_levels = de_geti16le_p(&pos);
	de_dbg(c, "NLevels: %d", (int)d->bpt.num_levels);
	if(is_internaldir) d->internal_dir_num_levels = d->bpt.num_levels;

	d->bpt.num_entries = de_geti32le_p(&pos);
	de_dbg(c, "TotalBtreeEntries: %d", (int)d->bpt.num_entries);

	d->bpt.pagesdata_pos = pos;
	de_dbg(c, "num pages: %d, %d bytes each, at %d (total size=%d)",
		(int)d->bpt.num_pages, (int)d->bpt.pagesize, (int)d->bpt.pagesdata_pos,
		(int)(d->bpt.num_pages * d->bpt.pagesize));

	if(!find_first_leaf_page(c, d)) goto done;

	page_seen = de_malloc(c, d->bpt.num_pages); // For loop detection

	for(d->pass=1; d->pass<=2; d->pass++) {
		i64 curr_page;

		de_zeromem(page_seen, (size_t)d->bpt.num_pages);

		de_dbg(c, "pass %d", d->pass);
		de_dbg_indent(c, 1);

		curr_page = d->bpt.first_leaf_page;

		while(1) {
			i64 page_pos;
			i64 next_page;

			if(curr_page<0) break;
			if(curr_page>d->bpt.num_pages) goto done;

			if(d->pass==1 && page_seen[curr_page]) {
				de_err(c, "Page loop detected");
				goto done;
			}
			page_seen[curr_page] = 1;

			page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

			de_dbg(c, "page[%d] at %d (leaf page)", (int)curr_page, (int)page_pos);

			next_page = -1;
			de_dbg_indent(c, 1);
			do_leaf_page(c, d, page_pos, &next_page);
			de_dbg_indent(c, -1);

			curr_page = next_page;
		}

		de_dbg_indent(c, -1);

		if(d->pass==1) {
			de_dbg(c, "reading items after pass 1");
			de_dbg_indent(c, 1);
			do_after_pass_1(c, d);
			de_dbg_indent(c, -1);
		}
	}

done:
	de_free(c, page_seen);
	if(structure) de_destroy_stringreaderdata(c, structure);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file_INTERNALDIR(deark *c, lctx *d, i64 pos1, i64 len)
{
	de_dbg(c, "internal dir data at %d", (int)pos1);
	do_bplustree(c, d, pos1, len, 1);
}

static void dump_phrase_offset_table(deark *c, lctx *d)
{
	unsigned int k;

	for(k=0; k<d->num_phrases; k++) {
		de_dbg2(c, "phrase[%u]: offs=%u, len=%u", k, d->phrase_info[k].pos,
			d->phrase_info[k].len);
	}
}

static void decompress_Phrases(deark *c, lctx *d, i64 pos, i64 cmpr_len, i64 uncmpr_len)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = cmpr_len;
	dcmpro.f = d->phrases_data;
	dcmpro.len_known = 1;
	dcmpro.expected_len = uncmpr_len;
	fmtutil_decompress_hlp_lz77(c, &dcmpri, &dcmpro, &dres);
	if(dres.errcode || (d->phrases_data->len!=uncmpr_len)) {
		de_warn(c, "Phrases decompression may have failed");
	}
}

static void do_file_Phrases(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos;
	i64 s0, s1, s2;
	i64 phrase_data_pos;
	i64 phrase_data_cmpr_len;
	i64 phrase_data_uncmpr_len = 0;
	i64 phrase_offset_table_pos;
	i64 phrase_offset_table_len;
	unsigned int k;
	int is_MVB_format = 0;
	int is_compressed = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!d->extract_text) goto done;

	de_dbg(c, "Phrases data at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);
	if(len<6) goto done;

	s0 = de_getu16le(pos1);
	s1 = de_getu16le(pos1+2);
	s2 = de_getu16le(pos1+4);

	if(s0==0x0800 && s1!=0x0100 && s2==0x0100) {
		is_MVB_format = 1;
	}
	else if(s1==0x0100) {
		;
	}
	else {
		de_err(c, "Unknown Phrases format");
		goto done;
	}
	de_dbg(c, "MVB format: %d", is_MVB_format);
	if(is_MVB_format) {
		de_err(c, "Unsupported Phrases format");
		goto done;
	}

	d->num_phrases = (unsigned int)s0;
	de_dbg(c, "num phrases: %u", d->num_phrases);
	pos = pos1+4;

	if(d->ver_minor>16) {
		is_compressed = 1;
	}
	de_dbg(c, "Phrases are lzw-compressed: %d", is_compressed);

	if(is_compressed) {
		phrase_data_uncmpr_len = de_getu32le_p(&pos);
		de_dbg(c, "decompressed len (reported): %"I64_FMT, phrase_data_uncmpr_len);
	}

	// Phrase offsets are measured from the start of the offset table.
	phrase_offset_table_pos = pos;
	phrase_offset_table_len = ((i64)d->num_phrases+1)*2;
	de_dbg(c, "offset table at %"I64_FMT", len=%"I64_FMT, phrase_offset_table_pos,
		phrase_offset_table_len);

	phrase_data_pos = phrase_offset_table_pos + phrase_offset_table_len;
	phrase_data_cmpr_len = pos1+len - phrase_data_pos; // (before any decompression)
	if(phrase_data_cmpr_len<0) goto done;
	if(!is_compressed) {
		phrase_data_uncmpr_len = phrase_data_cmpr_len;
	}

	d->phrase_info = de_mallocarray(c, (i64)d->num_phrases, sizeof(struct phrase_item));
	for(k=0; k<d->num_phrases+1; k++) {
		u32 offs;

		offs = (u32)de_getu16le_p(&pos);
		offs -= (u32)phrase_offset_table_len;

		if(k<d->num_phrases) {
			d->phrase_info[k].pos = offs;
		}
		if(k>=1) {
			d->phrase_info[k-1].len = offs - d->phrase_info[k-1].pos;
		}
	}
	if(c->debug_level>=2) {
		dump_phrase_offset_table(c, d);
	}

	de_dbg(c, "phrase data at %"I64_FMT", len=%"I64_FMT, phrase_data_pos, phrase_data_cmpr_len);

	if(is_compressed) {
		decompress_Phrases(c, d, phrase_data_pos, phrase_data_cmpr_len, phrase_data_uncmpr_len);
	}
	else {
		dbuf_copy(c->infile, phrase_data_pos, phrase_data_cmpr_len, d->phrases_data);
	}

	d->valid_Phrases_file = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

struct PhrIndex_ctx {
	i64 curpos;
	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;
};

static unsigned int phrgetbits(deark *c, lctx *d, struct PhrIndex_ctx *pctx, unsigned int nbits)
{
	unsigned int n;

	while(pctx->bitreader_nbits_in_buf < nbits) {
		u8 b;

		b = de_getbyte_p(&pctx->curpos);
		pctx->bitreader_buf |= ((unsigned int)b)<<pctx->bitreader_nbits_in_buf;
		pctx->bitreader_nbits_in_buf += 8;
	}

	n = pctx->bitreader_buf & ((1U<<nbits)-1U);
	pctx->bitreader_buf >>= nbits;
	pctx->bitreader_nbits_in_buf -= nbits;
	return n;
}

static void phrdecompress(deark *c, lctx *d, i64 pos1, i64 len, unsigned int BitCount)
{
	unsigned int n;
	unsigned int i;
	struct PhrIndex_ctx pctx;

	de_zeromem(&pctx, sizeof(struct PhrIndex_ctx));

	pctx.curpos = pos1;
	d->phrase_info[0].pos = 0;

	for(i=0; i<d->num_phrases; i++) {
		unsigned int num1bits = 0;

		while(phrgetbits(c, d, &pctx, 1)) {
			if(pctx.curpos > pos1+len) goto done; // emergency brake
			num1bits++;
		}
		n = num1bits<<BitCount;
		n += phrgetbits(c, d, &pctx, BitCount) + 1;

		d->phrase_info[i].len = n;
		if(i+1<d->num_phrases) {
			d->phrase_info[i+1].pos = d->phrase_info[i].pos+n;
		}
	}

done:
	if(c->debug_level>=2) {
		dump_phrase_offset_table(c, d);
	}
}

static void do_file_PhrIndex(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 cmprsize;
	i64 n;
	unsigned int bits;
	unsigned int bitcount;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(len<30) goto done;
	n = de_getu32le_p(&pos);
	if(n!=1) goto done;
	d->num_phrases = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "num phrases: %u", d->num_phrases);
	d->phrase_info = de_mallocarray(c, (i64)d->num_phrases, sizeof(struct phrase_item));

	cmprsize = de_getu32le_p(&pos);
	de_dbg(c, "index cmpr size: %"I64_FMT, cmprsize);
	d->PhrImageUncSize = de_getu32le_p(&pos);
	de_dbg(c, "PhrImage uncmpr size: %"I64_FMT, d->PhrImageUncSize);
	d->PhrImageCmprSize = de_getu32le_p(&pos);
	de_dbg(c, "PhrImage cmpr size: %"I64_FMT, d->PhrImageCmprSize);
	pos += 4;
	bits = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "bits: 0x%04x", bits);
	de_dbg_indent(c, 1);
	bitcount = bits & 0xf;
	de_dbg(c, "bit count: %u", bitcount);
	de_dbg_indent(c, -1);
	pos += 2;

	de_dbg(c, "avail size: %d", (int)(pos1+len-pos));
	phrdecompress(c, d, pos, pos1+len-pos, bitcount);
done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file_PhrImage(deark *c, lctx *d, i64 pos1, i64 len)
{
	de_dbg(c, "PhrImage data at %"I64_FMT", len=%"I64_FMT, pos1, len);
	if(len < d->PhrImageCmprSize) {
		return;
	}

	if(d->PhrImageCmprSize == d->PhrImageUncSize) {
		dbuf_copy(c->infile, pos1, d->PhrImageCmprSize, d->phrases_data);
	}
	else {
		decompress_Phrases(c, d, pos1, d->PhrImageCmprSize, d->PhrImageUncSize);
		de_dbg(c, "decompressed to %"I64_FMT" bytes", d->phrases_data->len);
	}
}

static const char* file_type_to_type_name(enum hlp_filetype file_fmt)
{
	const char *name = "unspecified";
	switch(file_fmt) {
	case FILETYPE_SYSTEM: name="system"; break;
	case FILETYPE_TOPIC: name="topic"; break;
	case FILETYPE_SHG: name="SHG/MRB"; break;
	case FILETYPE_INTERNALDIR: name="directory"; break;
	case FILETYPE_PHRASES: name="Phrases"; break;
	case FILETYPE_PHRINDEX: name="PhrIndex"; break;
	case FILETYPE_PHRIMAGE: name="PhrImage"; break;
	case FILETYPE_OTHERSPECIAL: name="other special stream"; break;
	case FILETYPE_EXTRACTABLE: name="other extractable file"; break;
	default: ;
	}
	return name;
}

static void do_file(deark *c, lctx *d, i64 pos1, enum hlp_filetype file_fmt, int force_extract,
	struct de_stringreaderdata *fn)
{
	i64 reserved_space;
	i64 used_space;
	i64 pos = pos1;
	unsigned int fileflags;

	de_dbg(c, "file at %d, type=%s", (int)pos1, file_type_to_type_name(file_fmt));
	de_dbg_indent(c, 1);

	// FILEHEADER
	reserved_space = de_getu32le_p(&pos);
	de_dbg(c, "ReservedSpace: %d", (int)reserved_space);

	used_space = de_getu32le_p(&pos);
	de_dbg(c, "UsedSpace: %d", (int)used_space);

	fileflags = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "FileFlags: 0x%02x", fileflags);

	if(pos+used_space > c->infile->len) {
		de_err(c, "Bad file size");
		goto done;
	}

	if(force_extract) {
		do_extract_raw_file(c, d, pos, used_space, fn);
		goto done;
	}

	switch(file_fmt) {
	case FILETYPE_INTERNALDIR:
		do_file_INTERNALDIR(c, d, pos, used_space);
		break;
	case FILETYPE_TOPIC:
		do_file_TOPIC(c, d, pos, used_space);
		break;
	case FILETYPE_PHRASES:
		do_file_Phrases(c, d, pos, used_space);
		break;
	case FILETYPE_PHRINDEX:
		do_file_PhrIndex(c, d, pos, used_space);
		break;
	case FILETYPE_PHRIMAGE:
		do_file_PhrImage(c, d, pos, used_space);
		break;
	case FILETYPE_SYSTEM:
		do_file_SYSTEM(c, d, pos, used_space);
		break;
	case FILETYPE_SHG:
		d->has_shg = 1;
		do_file_SHG(c, d, pos, used_space);
		break;
	case FILETYPE_EXTRACTABLE:
		do_extract_raw_file(c, d, pos, used_space, fn);
		break;
	default: ;
	}

done:
	de_dbg_indent(c, -1);
}

static void do_header(deark *c, lctx *d, i64 pos)
{
	i64 n;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->internal_dir_FILEHEADER_offs = de_geti32le(4);
	de_dbg(c, "internal dir FILEHEADER pos: %d", (int)d->internal_dir_FILEHEADER_offs);

	n = de_geti32le(8);
	de_dbg(c, "FREEHEADER pos: %d", (int)n);

	n = de_geti32le(12);
	de_dbg(c, "reported file size: %d", (int)n);

	de_dbg_indent(c, -1);
}

static void de_run_hlp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	d->extract_text = de_get_ext_option_bool(c, "hlp:extracttext",
		((c->extract_level>=2)?1:0));
	d->extract_raw_streams = (u8)de_get_ext_option_bool(c, "hlp:extractstreams", 0);
	d->tmpdbuf1 = dbuf_create_membuf(c, 0, 0);
	d->unc_linkdata2_dbuf = dbuf_create_membuf(c, 0, 0);
	d->tmpucstring1 = ucstring_create(c);
	d->phrases_data = dbuf_create_membuf(c, 0, 0);

	pos = 0;
	do_header(c, d, pos);

	do_file(c, d, d->internal_dir_FILEHEADER_offs, FILETYPE_INTERNALDIR, 0, NULL);

	de_dbg(c, "summary: v%d.%d %s%s%s blksize=%d levels=%d%s%s%s",
		d->ver_major, d->ver_minor,
		d->is_lz77_compressed?"lz77":"no_lz77",
		d->uses_old_phrase_compression?" phrase_compression":"",
		d->uses_hall_compression?" Hall_compression":"",
		(int)d->topic_block_size,
		(int)d->internal_dir_num_levels,
		d->has_shg?" has-shg":"",
		d->has_ico?" has-ico":"",
		d->has_bmp?" has-bmp":"");

	if(d) {
		dbuf_close(d->tmpdbuf1);
		dbuf_close(d->unc_linkdata2_dbuf);
		dbuf_close(d->phrases_data);
		ucstring_destroy(d->tmpucstring1);
		ucstring_destroy(d->help_file_title);
		ucstring_destroy(d->help_file_copyright);
		dbuf_close(d->outf_text);
		de_free(c, d->phrase_info);
		de_free(c, d);
	}
}

static int de_identify_hlp(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x3f\x5f\x03\x00", 4))
		return 100;
	return 0;
}

static void de_help_hlp(deark *c)
{
	de_msg(c, "-opt hlp:extracttext : Write the text (unformatted) to a file");
	de_msg(c, "-opt hlp:extractstreams : Extract raw files, instead of decoding");
}

void de_module_hlp(deark *c, struct deark_module_info *mi)
{
	mi->id = "hlp";
	mi->desc = "HLP";
	mi->run_fn = de_run_hlp;
	mi->identify_fn = de_identify_hlp;
	mi->help_fn = de_help_hlp;
}
