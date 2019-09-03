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

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;
typedef void (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags; // 0x1=valid in ARC. 0x2=valid in Spark.
	const char *name;
	decompressor_fn decompressor;
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

typedef struct localctx_struct {
	int fmt;
	const char *fmtname;
	int input_encoding;
	int append_type;
	int recurse_subdirs;
	i64 nmembers;  // Counts top-level members
#define MAX_SPARK_NESTING_LEVEL 24
	int level; // subdirectory nesting level
	struct de_crcobj *crco;
	struct de_strarray *curpath;
	int has_comments;
	int has_file_comments;
	i64 num_file_comments;
	i64 file_comments_pos;
} lctx;

static void decompressor_stored(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	dbuf_copy(dcmpri->f, dcmpri->pos, dcmpri->len, dcmpro->f);
}

static void decompressor_spark_compressed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_liblzw_ex(c, dcmpri, dcmpro, dres, DE_LIBLZWFLAG_HAS1BYTEHEADER, 0);
}

static void decompressor_squashed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_liblzw_ex(c, dcmpri, dcmpro, dres, 0, 0x80|13);
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
	dbuf *tmpf = NULL;
	struct de_dfilter_out_params tmpoparams;
	struct de_dfilter_in_params tmpiparams;

	de_zeromem(&tmpoparams, sizeof(struct de_dfilter_out_params));
	de_zeromem(&tmpiparams, sizeof(struct de_dfilter_in_params));

	// "Crunched" means "packed", then "compressed".
	// So we have to "uncompress", then "unpack".
	tmpf = dbuf_create_membuf(c, 0, 0);

	tmpoparams.f = tmpf;
	tmpoparams.len_known = 0;
	tmpoparams.expected_len = 0;
	decompressor_spark_compressed(c, d, md, dcmpri, &tmpoparams, dres);
	if(dres->errcode) goto done;
	de_dbg2(c, "size after intermediate decompression: %"I64_FMT, tmpf->len);

	tmpiparams.f = tmpf;
	tmpiparams.pos = 0;
	tmpiparams.len = tmpf->len;
	decompressor_packed(c, d, md, &tmpiparams, dcmpro, dres);

done:
	dbuf_close(tmpf);
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x00, 0x3, "end of archive marker", NULL },
	{ 0x01, 0x1, "stored (old format)", decompressor_stored },
	{ 0x02, 0x1, "stored", decompressor_stored },
	{ 0x03, 0x1, "packed (RLE)", decompressor_packed },
	{ 0x04, 0x1, "squeezed (Huffman)", NULL },
	{ 0x05, 0x1, "crunched5 (static LZW)", NULL },
	{ 0x06, 0x1, "crunched6 (RLE + static LZW)", NULL },
	{ 0x07, 0x1, "crunched7 (SEA internal)", NULL },
	{ 0x08, 0x1, "Crunched8 (RLE + dynamic LZW)", decompressor_crunched8 },
	{ 0x09, 0x1, "squashed (dynamic LZW)", decompressor_squashed },
	{ 0x80, 0x2, "end of archive marker", NULL },
	{ 0x81, 0x2, "stored (old format)", decompressor_stored },
	{ 0x82, 0x2, "stored", decompressor_stored },
	{ 0x83, 0x2, "packed (RLE)", decompressor_packed },
	{ 0x88, 0x2, "crunched", decompressor_crunched8 },
	{ 0x89, 0x2, "squashed", decompressor_squashed },
	{ 0xff, 0x2, "compressed", decompressor_spark_compressed }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(int fmt, u8 cmpr_meth)
{
	size_t k;
	const struct cmpr_meth_info *p;

	for(k=0; k<DE_ITEMS_IN_ARRAY(cmpr_meth_info_arr); k++) {
		p = &cmpr_meth_info_arr[k];
		if(p->cmpr_meth != cmpr_meth) continue;
		if(fmt==FMT_ARC && (p->flags & 0x1)) return p;
		if(fmt==FMT_SPARK && (p->flags & 0x2)) return p;
	}
	return NULL;
}

static void read_one_comment(deark *c, lctx *d, i64 pos, de_ucstring *s)
{
	dbuf_read_to_ucstring(c->infile, pos, 32, s, 0, d->input_encoding);
	ucstring_strip_trailing_spaces(s);
}

static void do_comments(deark *c, lctx *d)
{
	i64 sig_pos;
	i64 comments_descr_pos;
	int has_archive_comment = 0;
	de_ucstring *s = NULL;
	u8 dscr[4];

	sig_pos = c->infile->len-8;
	if(de_getu32be(sig_pos) != 0x504baa55) {
		return;
	}
	// TODO: False positives are possible here. Ideally, we'd pre-scan the
	// whole file, to make sure the comments occur after the end of the
	// main part of the archive.
	d->has_comments = 1;

	de_dbg(c, "PKARC/PKPAK comment block found");
	de_dbg_indent(c, 1);
	// Note: This logic is based on reverse engineering, and could be wrong.
	comments_descr_pos = de_getu32le(c->infile->len-4);
	de_dbg(c, "descriptor pos: %"I64_FMT, comments_descr_pos);
	if(comments_descr_pos >= sig_pos) goto done;

	de_read(dscr, comments_descr_pos, 4);
	if(dscr[0]==0x20 && dscr[1]==0x20 && dscr[2]==0x20 && dscr[3]==0x00) {
		d->has_file_comments = 0;
		has_archive_comment = 1;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x20) {
		d->has_file_comments = 1;
		has_archive_comment = 0;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x00) {
		d->has_file_comments = 1;
		has_archive_comment = 1;
	}
	else {
		de_dbg(c, "[unrecognized comments descriptor]");
	}

	if(d->has_file_comments) {
		d->file_comments_pos = comments_descr_pos + 32;
		if(sig_pos - d->file_comments_pos < 32) {
			d->has_file_comments = 0;
		}
	}

	if(has_archive_comment) {
		s = ucstring_create(c);
		read_one_comment(c, d, comments_descr_pos-32, s);
		de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(s));
	}

	if(d->has_file_comments) {
		d->num_file_comments = (sig_pos - d->file_comments_pos)/32;
		de_dbg(c, "apparent number of file comments: %d", (int)d->num_file_comments);
	}

done:
	ucstring_destroy(s);
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
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->fn), dres.errmsg);
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_extract_member_file(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi, i64 pos)
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
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
	if(d->append_type && md->rfa.file_type_known) {
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, pos, md->cmpr_size);
	de_dbg_indent(c, 1);

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;
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
static void do_spark_extract_member_dir(deark *c, lctx *d, struct member_data *md,
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

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len);

// Note: This shares a lot of code with ARC.
// Returns 1 if we can and should continue after this member.
static int do_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed, int *is_eoa)
{
	u8 magic;
	int saved_indent_level;
	int retval = 0;
	i64 pos = pos1;
	i64 mod_time_raw, mod_date_raw;
	de_finfo *fi = NULL;
	struct member_data *md = NULL;
	int need_curpath_pop = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md = de_malloc(c, sizeof(struct member_data));

	if(d->has_file_comments && (d->nmembers < d->num_file_comments)) {
		de_ucstring *comment;

		comment = ucstring_create(c);
		read_one_comment(c, d, d->file_comments_pos + d->nmembers*32, comment);
		de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(comment));
		ucstring_destroy(comment);
	}

	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(d->nmembers==0 && d->level==0) {
			de_err(c, "Not a(n) %s file", d->fmtname);
		}
		else {
			de_err(c, "Failed to find %s member at %"I64_FMT, d->fmtname, pos1);
		}
		goto done;
	}

	md->cmpr_meth = de_getbyte_p(&pos);
	md->cmpr_meth_masked = md->cmpr_meth & 0x7f;

	md->cmi = get_cmpr_meth_info(d->fmt, md->cmpr_meth);
	if(md->cmi && md->cmi->name) {
		md->cmpr_meth_name = md->cmi->name;
	}
	else {
		md->cmpr_meth_name = "?";
	}

	de_dbg(c, "cmpr meth: 0x%02x (%s)", (unsigned int)md->cmpr_meth, md->cmpr_meth_name);

	if(md->cmpr_meth_masked==0x00) { // end of dir marker
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
	md->is_dir = (d->recurse_subdirs && md->rfa.file_type_known &&
		(md->rfa.file_type==0xddc) && md->cmpr_meth==0x82);

	if(d->recurse_subdirs) {
		de_dbg(c, "is directory: %d", md->is_dir);
	}

	*bytes_consumed = md->cmpr_data_pos + md->cmpr_size - pos1;
	retval = 1;

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
		do_spark_extract_member_dir(c, d, md, fi);

		// Nested Spark archives (which double as subdirectories) have both a known
		// length (md->cmpr_size), and an end-of-archive marker. So there are two
		// ways to parse them:
		// 1) Recursively, meaning we trust the md->cmpr_size field (or maybe we should
		//    use orig_size instead?).
		// 2) As a flat sequence of members, meaning we trust that a nested archive
		//    will not have extra data after the end-of-archive marker.
		// Here, we use the recursive method.
		d->level++;
		do_sequence_of_members(c, d, md->cmpr_data_pos, md->cmpr_size);
		d->level--;
	}
	else {
		do_extract_member_file(c, d, md, fi, md->cmpr_data_pos);
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

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int found_eoa = 0;

	if(d->level >= MAX_SPARK_NESTING_LEVEL) {
		de_err(c, "Max subdir nesting level exceeded");
		return;
	}

	de_dbg(c, "archive at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		int ret;
		int is_eoa = 0;
		i64 bytes_consumed = 0;

		if(pos >= pos1+len) break;
		ret = do_member(c, d, pos, &bytes_consumed, &is_eoa);
		pos += bytes_consumed;

		if(is_eoa) {
			found_eoa = 1;
			break;
		}

		if(!ret || (bytes_consumed<1)) break;
		if(d->level==0) {
			d->nmembers++;
		}
	}

	if(found_eoa && (pos < pos1+len) && !(d->level==0 && d->has_comments)) {
		de_dbg(c, "extra bytes at end of archive: %"I64_FMT" (at %"I64_FMT")",
			pos1+len-pos, pos);
	}

	de_dbg_indent(c, -1);
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_strarray_destroy(d->curpath);
	de_free(c, d);
}

static void do_run_arc_spark_internal(deark *c, lctx *d)
{
	de_declare_fmt(c, d->fmtname);

	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	if(d->fmt==FMT_ARC) {
		do_comments(c, d);
	}

	do_sequence_of_members(c, d, 0, c->infile->len);
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
	d->recurse_subdirs = 0;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437_G);

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_arc(deark *c)
{
	static const char *exts[] = {"arc", "ark", "pak", "spk"};
	int has_ext = 0;
	int ends_with_trailer = 0;
	int ends_with_comments = 0;
	int starts_with_trailer = 0;
	size_t k;
	u8 cmpr_meth;

	if(de_getbyte(0) != 0x1a) return 0;
	cmpr_meth = de_getbyte(1);
	if(cmpr_meth>9) return 0;
	if(cmpr_meth==0) starts_with_trailer = 1;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {if(de_input_file_has_ext(c, exts[k])) {
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

	if(starts_with_trailer) {
		if(ends_with_comments) return 25;
		else return 0;
	}
	if(has_ext && (ends_with_trailer || ends_with_comments)) return 90;
	if(ends_with_trailer || ends_with_comments) return 25;
	if(has_ext) return 15;
	return 0;
}

void de_module_arc(deark *c, struct deark_module_info *mi)
{
	mi->id = "arc";
	mi->desc = "ARC compressed archive";
	mi->run_fn = de_run_arc;
	mi->identify_fn = de_identify_arc;
}
