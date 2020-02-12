// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ARC compressed archive
// Spark

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arc);
DE_DECLARE_MODULE(de_module_spark);

#define FMT_ARC 1
#define FMT_SPARK 2

#define MAX_NESTING_LEVEL 24

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;
typedef void (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags;
	const char *name;
	decompressor_fn decompressor;
};

struct persistent_member_data {
	de_ucstring *comment;
	de_ucstring *path;
};

struct member_data {
	u8 cmpr_meth;
	u8 cmpr_meth_masked;
	const struct cmpr_meth_info *cmi;
	const char *cmpr_meth_name;
	i64 orig_size;
	i64 cmpr_data_pos;
	i64 cmpr_size;
	u32 crc_reported;
	u32 crc_calc;
	de_ucstring *fn;
	struct de_timestamp arc_timestamp;
	struct de_riscos_file_attrs rfa;
	int is_dir;
};

struct localctx_struct {
	int fmt;
	const char *fmtname;
	int input_encoding;
	int append_type;
	int recurse_subdirs;
	u8 prescan_found_eoa;
	u8 has_trailer_data;
	i64 prescan_pos_after_eoa;
	i64 num_top_level_members; // Not including EOA marker
	struct de_crcobj *crco;
	struct de_strarray *curpath;
	struct persistent_member_data *persistent_md; // optional array[num_top_level_members]
};

static void decompressor_stored(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static void decompressor_spark_compressed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS1BYTEHEADER;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompressor_squashed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.max_code_size = 13;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompressor_packed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_rle90_ex(c, dcmpri, dcmpro, dres, 0);
}

static void decompressor_crunched8(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	// "Crunched" means "packed", then "compressed".
	// So we have to "uncompress" (LZW), then "unpack" (RLE90).

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS1BYTEHEADER;

	de_dfilter_decompress_two_layer(c, dfilter_lzw_codec, (void*)&delzwp,
		dfilter_rle90_codec, NULL, dcmpri, dcmpro, dres);
}

// Flags:
//  0x01 = valid in ARC
//  0x02 = valid in Spark
//  0x80 = assume high bit of cmpr_meth is set for Spark format
static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x00, 0x03, "end of archive marker", NULL },
	{ 0x01, 0x83, "stored (old format)", decompressor_stored },
	{ 0x02, 0x83, "stored", decompressor_stored },
	{ 0x03, 0x83, "packed (RLE)", decompressor_packed },
	{ 0x04, 0x83, "squeezed (RLE + Huffman)", NULL },
	{ 0x05, 0x83, "crunched5 (static LZW)", NULL },
	{ 0x06, 0x83, "crunched6 (RLE + static LZW)", NULL },
	{ 0x07, 0x83, "crunched7 (ARC 4.6)", NULL },
	{ 0x08, 0x83, "crunched8 (RLE + dynamic LZW)", decompressor_crunched8 },
	{ 0x09, 0x83, "squashed (dynamic LZW)", decompressor_squashed },
	{ 10,   0x01, "trimmed or crushed", NULL },
	{ 0x0b, 0x01, "distilled", NULL },
	{ 20,   0x01, "archive info", NULL },
	{ 21,   0x01, "extended file info", NULL },
	{ 0x1e, 0x01, "subdir", NULL },
	{ 0x1f, 0x01, "end of subdir marker", NULL },
	{ 0x80, 0x02, "end of archive marker", NULL },
	{ 0xff, 0x02, "compressed", decompressor_spark_compressed }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(lctx *d, u8 cmpr_meth)
{
	size_t k;
	const struct cmpr_meth_info *p;

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_info_arr); k++) {
		u8 meth_adjusted;

		p = &cmpr_meth_info_arr[k];
		if(d->fmt==FMT_ARC && !(p->flags & 0x1)) continue;
		if(d->fmt==FMT_SPARK && !(p->flags & 0x2)) continue;
		meth_adjusted = p->cmpr_meth;
		if(d->fmt==FMT_SPARK && (p->flags & 0x80)) {
			meth_adjusted |= 0x80;
		}
		if(meth_adjusted != cmpr_meth) continue;
		return p;
	}
	return NULL;
}

static void read_one_pk_comment(deark *c, lctx *d, i64 pos, de_ucstring *s)
{
	dbuf_read_to_ucstring(c->infile, pos, 32, s, 0, d->input_encoding);
	ucstring_strip_trailing_spaces(s);
}

static void init_trailer_data(deark *c, lctx *d)
{
	d->has_trailer_data = 1;
	if(!d->persistent_md) {
		d->persistent_md = de_mallocarray(c, d->num_top_level_members,
			sizeof(struct persistent_member_data));
	}
}

static void do_pk_comments(deark *c, lctx *d)
{
	i64 sig_pos;
	i64 comments_descr_pos;
	int has_file_comments = 0;
	int has_archive_comment = 0;
	i64 file_comments_pos;
	i64 num_file_comments;
	de_ucstring *archive_comment = NULL;
	u8 dscr[4];

	if(!d->prescan_found_eoa) return;
	sig_pos = c->infile->len-8;
	if(sig_pos < d->prescan_pos_after_eoa) return;
	if(de_getu32be(sig_pos) != 0x504baa55) {
		return;
	}
	init_trailer_data(c, d);

	de_dbg(c, "PKARC/PKPAK comment block found");
	de_dbg_indent(c, 1);
	// Note: This logic is based on reverse engineering, and could be wrong.
	comments_descr_pos = de_getu32le(c->infile->len-4);
	de_dbg(c, "descriptor pos: %"I64_FMT, comments_descr_pos);
	if(comments_descr_pos >= sig_pos) goto done;

	de_read(dscr, comments_descr_pos, 4);
	if(dscr[0]==0x20 && dscr[1]==0x20 && dscr[2]==0x20 && dscr[3]==0x00) {
		has_file_comments = 0;
		has_archive_comment = 1;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x20) {
		has_file_comments = 1;
		has_archive_comment = 0;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x00) {
		has_file_comments = 1;
		has_archive_comment = 1;
	}
	else {
		de_dbg(c, "[unrecognized comments descriptor]");
	}

	if(has_file_comments) {
		file_comments_pos = comments_descr_pos + 32;
		if(sig_pos - file_comments_pos < 32) {
			has_file_comments = 0;
		}
	}

	if(has_archive_comment) {
		archive_comment = ucstring_create(c);
		read_one_pk_comment(c, d, comments_descr_pos-32, archive_comment);
		de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(archive_comment));
	}

	if(has_file_comments) {
		i64 i;

		num_file_comments = (sig_pos - file_comments_pos)/32;
		de_dbg(c, "apparent number of file comments: %d", (int)num_file_comments);

		for(i=0; i<num_file_comments && i<d->num_top_level_members; i++) {
			if(!d->persistent_md[i].comment) {
				d->persistent_md[i].comment = ucstring_create(c);
			}
			if(ucstring_isnonempty(d->persistent_md[i].comment)) continue;
			read_one_pk_comment(c, d,file_comments_pos + i*32, d->persistent_md[i].comment);
		}
	}

done:
	ucstring_destroy(archive_comment);
	de_dbg_indent(c, -1);
}

static int do_pak_ext_record(deark *c, lctx *d, i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	u8 rectype;
	const char *rtname = "?";
	int retval = 0;
	i64 filenum;
	i64 filenum_adj = 0;
	i64 dlen;
	de_ucstring *archive_comment = NULL;
	struct persistent_member_data *pmd = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(de_getbyte_p(&pos) != 0xfe) goto done;
	de_dbg(c, "record at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	rectype = de_getbyte_p(&pos);
	switch(rectype) {
	case 0: rtname = "end"; break;
	case 1: rtname = "remark"; break;
	case 2: rtname = "path"; break;
	}
	de_dbg(c, "rectype: %d (%s)", (int)rectype, rtname);
	if(rectype==0) goto done;

	filenum = de_getu16le_p(&pos);
	de_dbg(c, "file num: %d", (int)filenum);
	dlen = de_getu32le_p(&pos);
	de_dbg(c, "dlen: %"I64_FMT, dlen);
	if(pos+dlen > c->infile->len) goto done;

	*pbytes_consumed = 8 + dlen;
	retval = 1;

	if(filenum > 0) {
		filenum_adj = filenum - 1;
		if(filenum_adj < d->num_top_level_members) {
			pmd = &d->persistent_md[filenum_adj];
		}
	}

	if(rectype==1) { // remark
		if(filenum==0) { // archive comment
			archive_comment = ucstring_create(c);
			dbuf_read_to_ucstring_n(c->infile, pos, dlen, 16384, archive_comment,
				0, d->input_encoding);
			de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(archive_comment));
		}
		else { // file comment
			if(!pmd) goto done;

			if(!pmd->comment) {
				pmd->comment = ucstring_create(c);
			}
			if(ucstring_isnonempty(pmd->comment)) goto done;
			dbuf_read_to_ucstring_n(c->infile, pos, dlen, 2048, pmd->comment,
				0, d->input_encoding);
		}
	}
	else if(rectype==2) {
		if(!pmd) goto done;
		if(!pmd->path) {
			pmd->path = ucstring_create(c);
		}
		if(ucstring_isnonempty(pmd->path)) goto done;
		dbuf_read_to_ucstring_n(c->infile, pos, dlen, 512, pmd->path,
			0, d->input_encoding);
	}

done:
	if(archive_comment) ucstring_destroy(archive_comment);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_pak_trailer(deark *c, lctx *d)
{
	u8 b;
	i64 pos;

	if(!d->prescan_found_eoa) return;
	if(c->infile->len - d->prescan_pos_after_eoa < 2) return;
	if(de_getbyte(d->prescan_pos_after_eoa) != 0xfe) return;
	b = de_getbyte(d->prescan_pos_after_eoa+1);
	if(b>4) return;

	pos = d->prescan_pos_after_eoa;
	de_dbg(c, "PAK extended records at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	init_trailer_data(c, d);

	while(1) {
		i64 bytes_consumed = 0;

		if(pos > c->infile->len-2) break;
		if(!do_pak_ext_record(c, d, pos, &bytes_consumed)) break;
		if(bytes_consumed<8) break;
		pos += bytes_consumed;
	}

	de_dbg_indent(c, -1);
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

// TODO: Consider merging this function into do_extract_member_file().
static int do_extract_internal(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro)
{
	int retval = 0;
	struct de_dfilter_results dres;
	int have_dres = 0;

	de_dfilter_results_clear(c, &dres);
	if(dcmpri->pos + dcmpri->len > dcmpri->f->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(md->fn));
		goto done;
	}

	if(md->cmi && md->cmi->decompressor) {
		md->cmi->decompressor(c, d, md, dcmpri, dcmpro, &dres);
		have_dres = 1;
	}
	else {
		goto done; // Should be impossible
	}

	if(have_dres && dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->fn),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

// Convert backslashes to slashes, and make sure the string ends with a /.
static void fixup_path(deark *c, lctx *d, de_ucstring *s)
{
	i64 i;

	if(s->len<1) return;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='\\') {
			s->str[i] = '/';
		}
	}

	if(s->str[s->len-1]!='/') {
		ucstring_append_char(s, '/');
	}
}

static void do_extract_member_file(deark *c, lctx *d, struct member_data *md,
	struct persistent_member_data *pmd, de_finfo *fi, i64 pos)
{
	de_ucstring *fullfn = NULL;
	dbuf *outf = NULL;
	struct de_dfilter_in_params *dcmpri = NULL;
	struct de_dfilter_out_params *dcmpro = NULL;
	int ignore_failed_crc = 0;
	int ret;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	fullfn = ucstring_create(c);

	if(pmd && ucstring_isnonempty(pmd->path)) {
		// For PAK-style paths.
		// (Pretty useless, until we support cmpr. meth. #11.)
		// Note that PAK-style paths, and directory recursion, are not expected to
		// be possible in the same file.
		ucstring_append_ucstring(fullfn, pmd->path);
		fixup_path(c, d, fullfn);
	}

	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	if(d->append_type && md->rfa.file_type_known) {
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	de_dbg_indent(c, 1);

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);
	de_crcobj_reset(d->crco);

	dcmpri = de_malloc(c, sizeof(struct de_dfilter_in_params));
	dcmpro = de_malloc(c, sizeof(struct de_dfilter_out_params));
	dcmpri->f = c->infile;
	dcmpri->pos = pos;
	dcmpri->len = md->cmpr_size;
	dcmpro->f = outf;
	dcmpro->len_known = 1;
	dcmpro->expected_len = md->orig_size;

	ret = do_extract_internal(c, d, md, dcmpri, dcmpro);
	if(!ret) goto done;

	md->crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)md->crc_calc);
	if(md->crc_reported==0 && !d->recurse_subdirs && md->rfa.file_type_known &&
		md->rfa.file_type==0xddc && md->cmpr_meth==0x82)
	{
		ignore_failed_crc = 1;
	}
	if((md->crc_calc!=md->crc_reported) && !ignore_failed_crc) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fn));
	}

done:
	dbuf_close(outf);
	ucstring_destroy(fullfn);
	de_free(c, dcmpri);
	de_free(c, dcmpro);
	de_dbg_indent_restore(c, saved_indent_level);
}

// "Extract" a directory entry
static void do_extract_member_dir(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	de_ucstring *fullfn = NULL;

	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	fi->is_directory = 1;
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_close(outf);
	ucstring_destroy(fullfn);
}

static void do_info_record_string(deark *c, lctx *d, i64 pos, i64 len, const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, 2048, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_info_item(deark *c, lctx *d, struct member_data *md)
{
	int saved_indent_level;
	i64 pos = md->cmpr_data_pos;
	i64 endpos = md->cmpr_data_pos+md->cmpr_size;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "info item data (meth=%d) at %"I64_FMT" len=%"I64_FMT, (int)md->cmpr_meth,
		md->cmpr_data_pos, md->cmpr_size);
	de_dbg_indent(c, 1);

	while(1) {
		i64 reclen;
		i64 recpos;
		i64 dpos;
		i64 dlen;
		u8 rectype;

		recpos = pos;
		if(pos+3 > endpos) goto done;
		reclen = de_getu16le_p(&pos);
		rectype = de_getbyte_p(&pos);
		if(reclen<3 || recpos+reclen > endpos) goto done;
		dpos = recpos + 3;
		dlen = reclen - 3;
		de_dbg(c, "record type %d at %"I64_FMT", len=%"I64_FMT, (int)rectype, recpos, reclen);
		de_dbg_indent(c, 1);
		if(md->cmpr_meth==20) {
			if(rectype==0) {
				do_info_record_string(c, d, dpos, dlen, "archive comment");
			}
		}
		else if(md->cmpr_meth==21) {
			if(rectype==0) {
				do_info_record_string(c, d, dpos, dlen, "file comment");
			}
		}
		de_dbg_indent(c, -1);
		pos = recpos + reclen;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level);

// Returns 1 if we can and should continue after this member.
static int do_member(deark *c, lctx *d, i64 pos1, i64 nbytes_avail,
	int nesting_level, i64 member_idx, i64 *bytes_consumed, int *is_eoa)
{
	u8 magic;
	int saved_indent_level;
	int retval = 0;
	i64 pos = pos1;
	i64 hdrsize;
	i64 mod_time_raw, mod_date_raw;
	de_finfo *fi = NULL;
	struct member_data *md = NULL;
	int need_curpath_pop = 0;
	struct persistent_member_data *pmd = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md = de_malloc(c, sizeof(struct member_data));

	if(nesting_level==0 && d->persistent_md && (member_idx < d->num_top_level_members)) {
		pmd = &d->persistent_md[member_idx];
		if(ucstring_isnonempty(pmd->comment)) {
			de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(pmd->comment));
		}
		if(ucstring_isnonempty(pmd->path)) {
			de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(pmd->path));
		}
	}

	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(member_idx==0 && nesting_level==0) {
			de_err(c, "Not a(n) %s file", d->fmtname);
		}
		else {
			de_err(c, "Failed to find %s member at %"I64_FMT, d->fmtname, pos1);
		}
		goto done;
	}

	md->cmpr_meth = de_getbyte_p(&pos);
	md->cmpr_meth_masked = md->cmpr_meth & 0x7f;

	md->cmi = get_cmpr_meth_info(d, md->cmpr_meth);
	if(md->cmi && md->cmi->name) {
		md->cmpr_meth_name = md->cmi->name;
	}
	else {
		md->cmpr_meth_name = "?";
	}

	de_dbg(c, "cmpr meth: 0x%02x (%s)", (unsigned int)md->cmpr_meth, md->cmpr_meth_name);

	if(md->cmpr_meth_masked==0x00 || md->cmpr_meth==0x1f) {
		hdrsize = 2;
	}
	else {
		if(md->cmpr_meth_masked==0x01) {
			hdrsize = 25;
		}
		else {
			hdrsize = 29;
		}
		if(md->cmpr_meth>=128) {
			hdrsize += 12;
		}
	}
	if(nbytes_avail<hdrsize) {
		de_err(c, "Insufficient data for archive member at %"I64_FMT, pos1);
		goto done;
	}

	if(md->cmpr_meth_masked==0x00 || md->cmpr_meth==0x1f) { // end of archive/dir marker
		*is_eoa = 1;
		*bytes_consumed = 2;
		goto done;
	}

	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	md->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);

	mod_date_raw = de_getu16le_p(&pos);
	mod_time_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&md->arc_timestamp, mod_date_raw, mod_time_raw);
	md->arc_timestamp.tzcode = DE_TZCODE_LOCAL;
	dbg_timestamp(c, &md->arc_timestamp, ((d->fmt==FMT_SPARK) ? "timestamp (ARC)":"timestamp"));

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if((md->cmpr_meth_masked)==0x01) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	if(d->fmt == FMT_SPARK) {
		de_fmtutil_riscos_read_load_exec(c, c->infile, &md->rfa, pos);
		pos += 8;

		de_fmtutil_riscos_read_attribs_field(c, c->infile, &md->rfa, pos, 0);
		pos += 4;
	}

	md->cmpr_data_pos = pos;

	de_strarray_push(d->curpath, md->fn);
	need_curpath_pop = 1;

	// TODO: Is it possible to distinguish between a subdirectory, and a Spark
	// member file that should always be extracted? Does a nonzero CRC mean
	// we should not recurse?
	if(d->fmt==FMT_SPARK && d->recurse_subdirs && md->rfa.file_type_known &&
		(md->rfa.file_type==0xddc) && md->cmpr_meth==0x82)
	{
		md->is_dir = 1;
	}
	else if(d->fmt==FMT_ARC && d->recurse_subdirs && md->cmpr_meth==0x1e) {
		md->is_dir = 1;
	}

	if(d->recurse_subdirs) {
		de_dbg(c, "is directory: %d", md->is_dir);
	}

	*bytes_consumed = md->cmpr_data_pos + md->cmpr_size - pos1;
	retval = 1;

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, md->cmpr_data_pos, md->cmpr_size);

	// Extract...
	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;

	if(md->rfa.mod_time.is_valid) {
		fi->mod_time = md->rfa.mod_time;
	}
	else if(md->arc_timestamp.is_valid) {
		fi->mod_time = md->arc_timestamp;
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}

	if(md->is_dir) {
		do_extract_member_dir(c, d, md, fi);

		// Nested subdirectory archives (ARC 6 "z" option, or Spark) have both a known
		// length (md->cmpr_size), and an end-of-archive marker. So there are two
		// ways to parse them:
		// 1) Recursively, meaning we trust the md->cmpr_size field (or maybe we should
		//    use orig_size instead?).
		// 2) As a flat sequence of members, meaning we trust that a nested archive
		//    will not have extra data after the end-of-archive marker.
		// Here, we use the recursive method.
		do_sequence_of_members(c, d, md->cmpr_data_pos, md->cmpr_size, nesting_level+1);
	}
	else if(md->cmpr_meth>=20 && md->cmpr_meth<=29) {
		if(md->cmpr_meth==20 || md->cmpr_meth==21) {
			do_info_item(c, d, md);
		}
		else {
			de_warn(c, "Ignoring extension type %d at %"I64_FMT, (int)md->cmpr_meth, pos1);
		}
	}
	else {
		do_extract_member_file(c, d, md, pmd, fi, md->cmpr_data_pos);
	}

done:
	if(need_curpath_pop) {
		de_strarray_pop(d->curpath);
	}
	if(fi) de_finfo_destroy(c, fi);
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level)
{
	i64 pos = pos1;
	i64 member_idx = 0;

	if(nesting_level >= MAX_NESTING_LEVEL) {
		de_err(c, "Max subdir nesting level exceeded");
		return;
	}

	de_dbg(c, "archive at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		int ret;
		int is_eoa = 0;
		i64 nbytes_avail;
		i64 bytes_consumed = 0;

		nbytes_avail = pos1+len-pos;
		if(nbytes_avail<2) break;
		ret = do_member(c, d, pos, nbytes_avail, nesting_level, member_idx, &bytes_consumed, &is_eoa);
		pos += bytes_consumed;

		if(is_eoa) {
			break;
		}

		if(!ret || (bytes_consumed<1)) break;
		member_idx++;
	}

	de_dbg_indent(c, -1);
}

// Unfortunately, a pre-pass is necessary for robust handling of some ARC format
// extensions. The main issue is member-file comments, which we want to be
// available when we process that member file, but can only be found after we've
// read through the whole ARC file.
static void do_prescan_file(deark *c, lctx *d, i64 pos1)
{
	i64 memberpos = pos1;

	de_dbg2(c, "prescan");
	d->num_top_level_members = 0;
	de_dbg_indent(c, 1);

	while(1) {
		u8 magic;
		u8 cmpr_meth, cmpr_meth_masked;
		i64 pos;
		i64 cmpr_size;

		pos = memberpos;
		if(pos + 2 > c->infile->len) break;
		magic = de_getbyte_p(&pos);
		if(magic!=0x1a) break;
		cmpr_meth = de_getbyte_p(&pos);
		cmpr_meth_masked = cmpr_meth & 0x7f;
		de_dbg2(c, "member at %"I64_FMT, memberpos);

		if(cmpr_meth_masked==0x00) { // end of archive
			memberpos = pos;
			d->prescan_found_eoa = 1;
			d->prescan_pos_after_eoa = memberpos;
			de_dbg2(c, "end of member sequence at %"I64_FMT, d->prescan_pos_after_eoa);
			break;
		}

		pos += 13;
		cmpr_size = de_getu32le_p(&pos);
		pos += 2+2+2;
		if(cmpr_meth_masked!=0x01) {
			pos += 4; // original size
		}
		if(cmpr_meth & 0x80) {
			pos += 12; // Spark-specific data
		}
		pos += cmpr_size;
		memberpos = pos;
		d->num_top_level_members++;
	}

	de_dbg_indent(c, -1);
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_strarray_destroy(d->curpath);
	if(d->persistent_md) {
		i64 i;

		for(i=0; i<d->num_top_level_members; i++) {
			ucstring_destroy(d->persistent_md[i].comment);
			ucstring_destroy(d->persistent_md[i].path);
		}
		de_free(c, d->persistent_md);
	}
	de_free(c, d);
}

static void do_run_arc_spark_internal(deark *c, lctx *d)
{
	i64 pos = 0;

	if(de_getbyte(0)!=0x1a && de_getbyte(3)==0x1a) {
		// Possible self-extracting COM file
		pos += 3;
	}

	de_declare_fmt(c, d->fmtname);

	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_prescan_file(c, d, pos);

	if(d->fmt==FMT_ARC) {
		do_pk_comments(c, d);
		do_pak_trailer(c, d);
	}

	do_sequence_of_members(c, d, pos, c->infile->len, 0);

	if(d->prescan_found_eoa && !d->has_trailer_data) {
		i64 num_extra_bytes;

		num_extra_bytes = c->infile->len - d->prescan_pos_after_eoa;
		if(num_extra_bytes>0) {
			de_dbg(c, "extra bytes at end of archive: %"I64_FMT" (at %"I64_FMT")",
				num_extra_bytes, d->prescan_pos_after_eoa);
		}
	}
}

static void de_run_spark(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = FMT_SPARK;
	d->fmtname = "Spark";
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_RISCOS);
	d->recurse_subdirs = de_get_ext_option_bool(c, "spark:recurse", 1);
	d->append_type = de_get_ext_option_bool(c, "spark:appendtype", 0);

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_spark(deark *c)
{
	u8 b;
	u32 load_addr;
	int ldaddrcheck = 0;
	int has_trailer = 0;

	if(de_getbyte(0) != 0x1a) return 0;
	b = de_getbyte(1); // compression method
	if(b==0x82 || b==0x83 || b==0x88 || b==0x89 || b==0xff) {
		;
	}
	else if(b==0x81 || b==0x84 || b==0x85 || b==0x86) {
		; // TODO: Verify that these are possible in Spark.
	}
	else {
		return 0;
	}

	load_addr = (u32)de_getu32le(29);
	if((load_addr & 0xfff00000) == 0xfff00000) {
		ldaddrcheck = 1;
	}

	if(de_getu16be(c->infile->len-2) == 0x1a80) {
		has_trailer = 1;
	}

	if(has_trailer && ldaddrcheck) return 85;
	if(ldaddrcheck) return 30;
	if(has_trailer) return 10;
	return 0;
}

static void de_help_spark(deark *c)
{
	de_msg(c, "-opt spark:appendtype : Append the file type to the filename");
	de_msg(c, "-opt spark:recurse=0 : Extract subdirs as Spark files");
}

void de_module_spark(deark *c, struct deark_module_info *mi)
{
	mi->id = "spark";
	mi->desc = "Spark archive";
	mi->run_fn = de_run_spark;
	mi->identify_fn = de_identify_spark;
	mi->help_fn = de_help_spark;
}

static void de_run_arc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = FMT_ARC;
	d->fmtname = "ARC";
	// TODO: Make 'recurse' configurable. Would require us to make the embedded
	// archives end with the correct marker.
	d->recurse_subdirs = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437_G);

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_arc(deark *c)
{
	static const char *exts[] = {"arc", "ark", "pak", "spk", "com"};
	int has_ext = 0;
	int maybe_sfx = 0;
	int ends_with_trailer = 0;
	int ends_with_comments = 0;
	int starts_with_trailer = 0;
	i64 arc_start = 0;
	size_t k;
	u8 cmpr_meth;

	if(de_getbyte(0) != 0x1a) {
		if(de_input_file_has_ext(c, "com")) {
			maybe_sfx = 1;
		}
		if(maybe_sfx && de_getbyte(3)==0x1a) {
			arc_start = 3;
		}
		else {
			return 0;
		}
	}

	cmpr_meth = de_getbyte(arc_start+1);
	if(cmpr_meth>11 && cmpr_meth!=20 && cmpr_meth!=21 && cmpr_meth!=30) return 0;
	if(cmpr_meth==0) starts_with_trailer = 1;

	for(k=0; k<DE_ARRAYCOUNT(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}

	if(starts_with_trailer && c->infile->len==2) {
		if(has_ext) return 15; // Empty archive, 2-byte file
		return 0;
	}

	if((!starts_with_trailer) && (de_getu16be(c->infile->len-2) == 0x1a00)) {
		ends_with_trailer = 1;
	}
	if(de_getu32be(c->infile->len-8) == 0x504baa55) {
		// PKARC trailer, for files with comments
		ends_with_comments = 1;
	}

	if(!ends_with_trailer && !ends_with_comments) {
		// PAK-style extensions
		if(de_getu16be(c->infile->len-2) == 0xfe00) {
			ends_with_comments = 1;
		}
	}

	if(starts_with_trailer) {
		if(ends_with_comments) return 25;
		else return 0;
	}
	if(has_ext && (ends_with_trailer || ends_with_comments)) return 90;
	if(ends_with_trailer || ends_with_comments) return 25;
	if(has_ext || maybe_sfx) return 15;
	return 0;
}

void de_module_arc(deark *c, struct deark_module_info *mi)
{
	mi->id = "arc";
	mi->desc = "ARC compressed archive";
	mi->run_fn = de_run_arc;
	mi->identify_fn = de_identify_arc;
}
