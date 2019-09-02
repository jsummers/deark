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

///////////////////////////////////////////////////////////////////////////
// ARC
// TODO: Merge this into the Spark module

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;
typedef int (*decompressor_fn)(deark *c, lctx *d, struct member_data *md, dbuf *outf);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags;
	const char *name;
	decompressor_fn decompressor;
};

struct member_data {
	u8 cmpr_meth;
	const struct cmpr_meth_info *cmi;
	i64 cmpr_size;
	i64 orig_size;
	i64 cmpr_data_pos;
	u32 crc_reported;
	u32 crc_calc;
	de_ucstring *fn;
};

struct localctx_struct {
	int input_encoding;
	i64 member_count;
	int has_comments;
	int has_file_comments;
	i64 num_file_comments;
	i64 file_comments_pos;
	struct de_crcobj *crco;
};

static int decompress_stored(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	dbuf_copy(c->infile, md->cmpr_data_pos, md->cmpr_size, outf);
	return 1;
}

static int decompress_packed(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	int ret;

	ret = de_fmtutil_decompress_rle90(c->infile, md->cmpr_data_pos, md->cmpr_size, outf,
		1, md->orig_size, 0);
	return ret;
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x01, 0, "stored (old format)", decompress_stored },
	{ 0x02, 0, "stored", decompress_stored },
	{ 0x03, 0, "packed (RLE)", decompress_packed },
	{ 0x04, 0, "squeezed (Huffman)", NULL },
	{ 0x05, 0, "crunched5 (static LZW)", NULL },
	{ 0x06, 0, "crunched6 (RLE + static LZW)", NULL },
	{ 0x07, 0, "crunched7 (SEA internal)", NULL },
	{ 0x08, 0, "Crunched8 (RLE + dynamic LZW)", NULL },
	{ 0x09, 0, "squashed (dynamic LZW)", NULL }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(u8 cmpr_meth)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(cmpr_meth_info_arr); k++) {
		if(cmpr_meth_info_arr[k].cmpr_meth == cmpr_meth) {
			return &cmpr_meth_info_arr[k];
		}
	}
	return NULL;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void read_one_comment(deark *c, lctx *d, i64 pos, de_ucstring *s)
{
	dbuf_read_to_ucstring(c->infile, pos, 32, s, 0, d->input_encoding);
	ucstring_strip_trailing_spaces(s);
}

// Returns 1 if we parsed this member successfully, and it's not the
// EOF marker.
static int do_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	int retval = 0;
	int saved_indent_level;
	i64 pos = pos1;
	i64 mod_time_raw, mod_date_raw;
	u8 magic;
	u8 cmpr_meth;
	struct member_data *md = NULL;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct de_timestamp tmp_timestamp;
	char timestamp_buf[64];

	de_dbg_indent_save(c, &saved_indent_level);
	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(d->member_count==0) {
			de_err(c, "Not an ARC file");
		}
		else {
			de_err(c, "Failed to find ARC member at %"I64_FMT", stopping", pos1);
		}
		goto done;
	}

	cmpr_meth = de_getbyte_p(&pos);
	if(cmpr_meth == 0) {
		de_dbg(c, "eof marker at %"I64_FMT, pos1);
		if((pos < c->infile->len) && !d->has_comments) {
			de_dbg(c, "extra bytes at eof: %"I64_FMT, (c->infile->len-pos));
		}
		goto done;
	}

	md = de_malloc(c, sizeof(struct member_data));
	md->fn = ucstring_create(c);

	md->cmpr_meth = cmpr_meth;

	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(d->has_file_comments && (d->member_count < d->num_file_comments)) {
		de_ucstring *comment;

		comment = ucstring_create(c);
		read_one_comment(c, d, d->file_comments_pos + d->member_count*32, comment);
		de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(comment));
		ucstring_destroy(comment);
	}

	md->cmi = get_cmpr_meth_info(md->cmpr_meth);
	de_dbg(c, "cmpr method: %u (%s)", (unsigned int)md->cmpr_meth,
		(md->cmi ? md->cmi->name : "?"));

	dbuf_read_to_ucstring(c->infile, pos, 13, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	md->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);

	mod_date_raw = de_getu16le_p(&pos);
	mod_time_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&tmp_timestamp, mod_date_raw, mod_time_raw);
	tmp_timestamp.tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "timestamp: %s", timestamp_buf);

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if(md->cmpr_meth == 1) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	md->cmpr_data_pos = pos;
	pos += md->cmpr_size;
	if(pos > c->infile->len) goto done;
	retval = 1;

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type %u not supported", ucstring_getpsz_d(md->fn),
			(unsigned int)md->cmpr_meth);
		goto done;
	}

	fi = de_finfo_create(c);
	fi->mod_time = tmp_timestamp;
	de_finfo_set_name_from_ucstring(c, fi, md->fn, 0);
	fi->original_filename_flag = 1;
	outf = dbuf_create_output_file(c, NULL, fi, 0);

	de_crcobj_reset(d->crco);
	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;

	if(!md->cmi->decompressor(c, d, md, outf)) {
		goto done;
	}

	md->crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)md->crc_calc);
	if(md->crc_calc != md->crc_reported) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fn));
	}

done:
	*bytes_consumed = pos - pos1;
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
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

static void de_run_arc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437_G);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_comments(c, d);

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		ret = do_member(c, d, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) break;
		pos += bytes_consumed;
		d->member_count++;
	}

	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
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
	// Note: If 0x82, 0x83, 0x88, or 0xff, this may be Spark format.
	if(cmpr_meth>9) return 0;
	if(cmpr_meth==0) starts_with_trailer = 1;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
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

///////////////////////////////////////////////////////////////////////////
// Spark

struct spark_member_data {
	struct de_riscos_file_attrs rfa;
	int is_dir;
	u8 cmpr_meth;
	u8 cmpr_meth_masked;
	i64 orig_size;
	i64 cmpr_size;
	u32 crc_reported;
	const char *cmpr_meth_name;
	de_ucstring *fn;
	struct de_timestamp arc_timestamp;
};

typedef struct sparkctx_struct {
	int input_encoding;
	int append_type;
	int recurse_subdirs;
	i64 nmembers;  // Counts all members, including nested members
#define MAX_SPARK_NESTING_LEVEL 24
	int level; // subdirectory nesting level
	struct de_crcobj *crco;
	struct de_strarray *curpath;
} spkctx;

static const char *get_spark_info_byte_name(u8 t)
{
	const char *name = NULL;
	switch(t) {
	case 0x82: name="stored"; break;
	case 0x83: name="packed (RLE)"; break;
	case 0x88: name="crunched"; break;
	case 0x89: name="squashed"; break;
	case 0xff: name="compressed"; break;
	}
	return name?name:"?";
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static int is_spark_cmpr_meth_supported(deark *c, spkctx *d, u8 n)
{
	switch(n) {
	case 0x82: case 0x83: case 0x88: case 0xff:
		return 1;
	}
	return 0;
}

static void do_spark_compressed(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_liblzw_ex(c, dcmpri, dcmpro, dres, DE_LIBLZWFLAG_HASSPARKHEADER, 0);
}

static void do_spark_packed(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_rle90_ex(c, dcmpri, dcmpro, dres, 0);
}

static void do_spark_crunched(deark *c, struct de_dfilter_in_params *dcmpri,
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
	do_spark_compressed(c, dcmpri, &tmpoparams, dres);
	if(dres->errcode) goto done;
	de_dbg2(c, "size after intermediate decompression: %"I64_FMT, tmpf->len);

	tmpiparams.f = tmpf;
	tmpiparams.pos = 0;
	tmpiparams.len = tmpf->len;
	do_spark_packed(c, &tmpiparams, dcmpro, dres);

done:
	dbuf_close(tmpf);
}

// fname = a filename to use in error messages
static int do_spark_extract_file(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, u8 cmpr_meth, de_ucstring *fname)
{
	int retval = 0;
	struct de_dfilter_results dres;
	int have_dres = 0;

	de_dfilter_results_clear(c, &dres);
	if(dcmpri->pos + dcmpri->len > dcmpri->f->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(fname));
		goto done;
	}

	if(cmpr_meth==0x82) { // stored
		dbuf_copy(dcmpri->f, dcmpri->pos, dcmpri->len, dcmpro->f);
	}
	else if(cmpr_meth==0x83) {
		do_spark_packed(c, dcmpri, dcmpro, &dres);
		have_dres = 1;
	}
	else if(cmpr_meth==0x88) {
		do_spark_crunched(c, dcmpri, dcmpro, &dres);
		have_dres = 1;
	}
	else if(cmpr_meth==0xff) {
		do_spark_compressed(c, dcmpri, dcmpro, &dres);
		have_dres = 1;
	}
	else {
		goto done; // Should be impossible
	}

	if(have_dres && dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(fname), dres.errmsg);
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void spark_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_spark_extract_member_file(deark *c, spkctx *d, struct spark_member_data *md,
	de_finfo *fi, i64 pos)
{
	de_ucstring *fullfn = NULL;
	dbuf *outf = NULL;
	struct de_dfilter_in_params *dcmpri = NULL;
	struct de_dfilter_out_params *dcmpro = NULL;
	int ignore_failed_crc = 0;
	int ret;
	u32 crc_calc;
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

	if(!is_spark_cmpr_meth_supported(c, d, md->cmpr_meth)) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	outf->writecallback_fn = spark_writecallback;
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

	ret = do_spark_extract_file(c, dcmpri, dcmpro, md->cmpr_meth, md->fn);
	if(!ret) goto done;

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(md->crc_reported==0 && !d->recurse_subdirs && md->rfa.file_type_known &&
		md->rfa.file_type==0xddc && md->cmpr_meth==0x82)
	{
		ignore_failed_crc = 1;
	}
	if((crc_calc!=md->crc_reported) && !ignore_failed_crc) {
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
static void do_spark_extract_member_dir(deark *c, spkctx *d, struct spark_member_data *md,
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

static void do_spark_sequence_of_members(deark *c, spkctx *d, i64 pos1, i64 len);

// Note: This shares a lot of code with ARC.
// Returns 1 if we can and should continue after this member.
static int do_spark_member(deark *c, spkctx *d, i64 pos1, i64 *bytes_consumed)
{
	u8 magic;
	int saved_indent_level;
	int retval = 0;
	i64 pos = pos1;
	i64 mod_time_raw, mod_date_raw;
	de_finfo *fi = NULL;
	struct spark_member_data *md = NULL;
	int need_curpath_pop = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md = de_malloc(c, sizeof(struct spark_member_data));
	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(d->nmembers==0) {
			de_err(c, "Not a Spark file");
		}
		else {
			de_err(c, "Failed to find Spark member at %"I64_FMT, pos1);
		}
		goto done;
	}

	md->cmpr_meth = de_getbyte_p(&pos);
	md->cmpr_meth_masked = md->cmpr_meth & 0x7f;
	if(md->cmpr_meth>=0x81) {
		md->cmpr_meth_name = get_spark_info_byte_name(md->cmpr_meth);
	}
	else if(md->cmpr_meth_masked==0x00) {
		md->cmpr_meth_name = "end of dir marker";
	}
	else {
		md->cmpr_meth_name = "?";
	}
	de_dbg(c, "cmpr meth: 0x%02x (%s)", (unsigned int)md->cmpr_meth, md->cmpr_meth_name);

	if(md->cmpr_meth_masked==0x00) { // end of dir marker
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
	dbg_timestamp(c, &md->arc_timestamp, "timestamp (ARC)");

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if((md->cmpr_meth_masked)==0x01) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	de_fmtutil_riscos_read_load_exec(c, c->infile, &md->rfa, pos);
	pos += 8;

	de_fmtutil_riscos_read_attribs_field(c, c->infile, &md->rfa, pos, 0);
	pos += 4;

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

	*bytes_consumed = pos + md->cmpr_size - pos1;
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
		do_spark_sequence_of_members(c, d, pos, md->cmpr_size);
		d->level--;
	}
	else {
		do_spark_extract_member_file(c, d, md, fi, pos);
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

static void do_spark_sequence_of_members(deark *c, spkctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;

	if(d->level >= MAX_SPARK_NESTING_LEVEL) {
		de_err(c, "Max subdir nesting level exceeded");
		return;
	}

	de_dbg(c, "archive at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= pos1+len) break;
		ret = do_spark_member(c, d, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) break;
		pos += bytes_consumed;
		d->nmembers++;
	}

	de_dbg_indent(c, -1);
}

static void de_run_spark(deark *c, de_module_params *mparams)
{
	spkctx *d = NULL;

	d = de_malloc(c, sizeof(spkctx));
	d->input_encoding = DE_ENCODING_RISCOS;
	d->recurse_subdirs = de_get_ext_option_bool(c, "spark:recurse", 1);
	d->append_type = de_get_ext_option_bool(c, "spark:appendtype", 0);
	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_spark_sequence_of_members(c, d, 0, c->infile->len);

	if(d) {
		de_crcobj_destroy(d->crco);
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
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
