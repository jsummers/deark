// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// This file is for miscellaneous small archive-format modules.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_cpshrink);
DE_DECLARE_MODULE(de_module_dwc);
DE_DECLARE_MODULE(de_module_tscomp);
DE_DECLARE_MODULE(de_module_edi_pack);
DE_DECLARE_MODULE(de_module_rar);

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;

typedef void (*decompressor_cbfn)(struct member_data *md);

struct member_data {
	deark *c;
	lctx *d;
	i64 member_idx;
	i64 member_hdr_pos;
	i64 member_total_size;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	u8 orig_len_known;
	de_ucstring *filename; // Allocated by create_md().
	de_ucstring *tmpfn_base; // Client allocates, freed automatically.
	de_ucstring *tmpfn_path; // Client allocates, freed automatically.
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];
	UI set_name_flags; // e.g. DE_SNFLAG_FULLPATH
	u8 is_encrypted;

	// Private use fields for the format decoder:
	UI cmpr_meth;
	UI file_flags;

	// The extract_member_file() will temporarily set dcmpri/dcmpro/dres,
	// and call ->dfn() if it is set.
	decompressor_cbfn dfn;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
};

struct localctx_struct {
	deark *c;
	int is_le;
	u8 need_errmsg;
	de_encoding input_encoding;
	i64 num_members;
	i64 cmpr_data_curpos;
	struct de_crcobj *crco; // decoder must create; is destroyed automatically
	int fatalerrflag;

	// Private use fields for the format decoder:
	int private_fmtver;
	int private1;
	UI archive_flags;
};

static struct member_data *create_md(deark *c, lctx *d)
{
	struct member_data *md;

	md = de_malloc(c, sizeof(struct member_data));
	md->c = c;
	md->d = d;
	md->filename = ucstring_create(c);
	return md;
}

static void destroy_md(deark *c, struct member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->filename);
	ucstring_destroy(md->tmpfn_base);
	ucstring_destroy(md->tmpfn_path);
	de_free(c, md);
}

static lctx *create_lctx(deark *c)
{
	lctx *d;

	d = de_malloc(c, sizeof(lctx));
	d->c = c;
	return d;
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_free(c, d);
}

static void handle_field_orig_len(struct member_data *md, i64 n)
{
	md->orig_len = n;
	md->orig_len_known = 1;
	de_dbg(md->c, "original size: %"I64_FMT, md->orig_len);
}

static void read_field_orig_len_p(struct member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->c->infile, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_orig_len(md, n);
}

static void handle_field_cmpr_len(struct member_data *md, i64 n)
{
	md->cmpr_len = n;
	de_dbg(md->c, "compressed size: %"I64_FMT, md->cmpr_len);
}

static void read_field_cmpr_len_p(struct member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->c->infile, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_cmpr_len(md, n);
}

// tstype:
//   1 = Unix
//   2 = DOS,date first
//   3 = DOS,time first
static void read_field_dttm_p(lctx *d,
	struct de_timestamp *ts, const char *name,
	int tstype, i64 *ppos)
{
	i64 n1, n2;
	char timestamp_buf[64];
	int is_set = 0;

	ts->is_valid = 0;
	if(tstype==1) {
		n1 = dbuf_getu32x(d->c->infile, *ppos, d->is_le);
		de_unix_time_to_timestamp(n1, ts, 0x1);
		is_set = 1;
	}
	else if(tstype==2 || tstype==3) {
		i64 dosdt, dostm;

		n1 = dbuf_getu16x(d->c->infile, *ppos, d->is_le);
		n2 = dbuf_getu16x(d->c->infile, *ppos+2, d->is_le);
		if(tstype==3) {
			dosdt = n2;
			dostm = n1;
		}
		else {
			dosdt = n1;
			dostm = n2;
		}

		if(dostm!=0 || dosdt!=0) {
			is_set = 1;
			de_dos_datetime_to_timestamp(ts, dosdt, dostm);
			ts->tzcode = DE_TZCODE_LOCAL;
		}
	}

	if(is_set) {
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_snprintf(timestamp_buf, sizeof(timestamp_buf), "[not set]");
	}
	de_dbg(d->c, "%s time: %s", name, timestamp_buf);

	*ppos += 4;
}

// Assumes md->filename is set
static int good_cmpr_data_pos(struct member_data *md)
{
	if(md->cmpr_pos<0 || md->cmpr_len<0 ||
		md->cmpr_pos+md->cmpr_len > md->c->infile->len)
	{
		de_err(md->c, "%s: Data goes beyond end of file",
			ucstring_getpsz_d(md->filename));
		return 0;
	}
	return 1;
}

static void extract_member_file(struct member_data *md)
{
	deark *c = md->c;
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	size_t k;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(md->orig_len>0 && !md->orig_len_known) goto done; // sanity check
	if(md->is_encrypted) {
		de_err(c, "%s: Encrypted files are not supported", ucstring_getpsz_d(md->filename));
		goto done;
	}
	if(!good_cmpr_data_pos(md)) {
		goto done;
	}

	fi = de_finfo_create(c);

	if(ucstring_isnonempty(md->filename)) {
		de_finfo_set_name_from_ucstring(c, fi, md->filename, md->set_name_flags);
		fi->original_filename_flag = 1;
	}

	for(k=0; k<DE_TIMESTAMPIDX_COUNT; k++) {
		fi->timestamp[k] = md->tmstamp[k];
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_enable_wbuffer(outf);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_pos;
	dcmpri.len = md->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = md->orig_len_known;
	dcmpro.expected_len = md->orig_len;
	md->dcmpri = &dcmpri;
	md->dcmpro = &dcmpro;
	md->dres = &dres;

	if(md->orig_len_known && md->orig_len==0) {
		;
	}
	else if(md->dfn) {
		md->dfn(md);
	}
	else {
		de_dfilter_set_generic_error(c, &dres, NULL);
	}
	dbuf_flush(dcmpro.f);

	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->filename),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(md->orig_len_known && (outf->len != md->orig_len)) {
		de_err(c, "%s: Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			ucstring_getpsz_d(md->filename), md->orig_len, outf->len);
		goto done;
	}

done:
	dbuf_close(outf);
	if(fi) de_finfo_destroy(c, fi);
	md->dcmpri = NULL;
	md->dcmpro = NULL;
	md->dres = NULL;
}

// **************************************************************************
// CP Shrink (.cpz)
// **************************************************************************

static void cpshrink_decompressor_fn(struct member_data *md)
{
	deark *c = md->c;

	switch(md->cmpr_meth) {
	case 0:
	case 1:
		fmtutil_dclimplode_codectype1(c, md->dcmpri, md->dcmpro, md->dres, NULL);
		break;
	case 2:
		fmtutil_decompress_uncompressed(c, md->dcmpri, md->dcmpro, md->dres, 0);
		break;
	default:
		de_dfilter_set_generic_error(c, md->dres, NULL);
	}
}

// Caller creates/destroys md, and sets a few fields.
static void cpshrink_do_member(deark *c, lctx *d, struct member_data *md)
{
	i64 pos = md->member_hdr_pos;
	UI cdata_crc_reported;
	UI cdata_crc_calc;

	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	md->cmpr_pos = d->cmpr_data_curpos;

	de_dbg(c, "member #%u: hdr at %"I64_FMT", cmpr data at %"I64_FMT,
		(UI)md->member_idx, md->member_hdr_pos, md->cmpr_pos);
	de_dbg_indent(c, 1);

	cdata_crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "CRC of cmpr. data (reported): 0x%08x", (UI)cdata_crc_reported);

	dbuf_read_to_ucstring(c->infile, pos, 15, md->filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	pos += 15;
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));

	md->cmpr_meth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);

	read_field_orig_len_p(md, &pos);
	read_field_cmpr_len_p(md, &pos);
	d->cmpr_data_curpos += md->cmpr_len;

	read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 2, &pos);

	if(!good_cmpr_data_pos(md)) {
		d->fatalerrflag = 1;
		goto done;
	}

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, md->cmpr_pos, md->cmpr_len);
	cdata_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "CRC of cmpr. data (calculated): 0x%08x", (UI)cdata_crc_calc);
	if(cdata_crc_calc!=cdata_crc_reported) {
		de_err(c, "File data CRC check failed (expected 0x%08x, got 0x%08x). "
			"CPZ file may be corrupted.", (UI)cdata_crc_reported,
			(UI)cdata_crc_calc);
	}

	md->dfn = cpshrink_decompressor_fn;
	extract_member_file(md);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_cpshrink(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 member_hdrs_pos;
	i64 member_hdrs_len;
	u32 member_hdrs_crc_reported;
	u32 member_hdrs_crc_calc;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	pos = 0;
	de_dbg(c, "archive header at %d", (int)pos);
	de_dbg_indent(c, 1);
	// Not sure if this is a 16-bit, or 32-bit, field, but CP Shrink doesn't
	// work right if the 2 bytes at offset 2 are not 0.
	d->num_members = de_getu32le_p(&pos);
	de_dbg(c, "number of members: %"I64_FMT, d->num_members);
	if(d->num_members<1 || d->num_members>0xffff) {
		de_err(c, "Bad member file count");
		goto done;
	}
	member_hdrs_crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "member hdrs crc (reported): 0x%08x", (UI)member_hdrs_crc_reported);
	de_dbg_indent(c, -1);

	member_hdrs_pos = pos;
	member_hdrs_len = d->num_members * 32;
	d->cmpr_data_curpos = member_hdrs_pos+member_hdrs_len;

	de_dbg(c, "member headers at %"I64_FMT, member_hdrs_pos);
	de_dbg_indent(c, 1);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(d->crco, c->infile, member_hdrs_pos, member_hdrs_len);
	member_hdrs_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "member hdrs crc (calculated): 0x%08x", (UI)member_hdrs_crc_calc);
	if(member_hdrs_crc_calc!=member_hdrs_crc_reported) {
		de_err(c, "Header CRC check failed (expected 0x%08x, got 0x%08x). "
			"This is not a valid CP Shrink file", (UI)member_hdrs_crc_reported,
			(UI)member_hdrs_crc_calc);
	}
	de_dbg_indent(c, -1);

	de_dbg(c, "cmpr data starts at %"I64_FMT, d->cmpr_data_curpos);

	for(i=0; i<d->num_members; i++) {
		struct member_data *md;

		md = create_md(c, d);
		md->member_idx = i;
		md->member_hdr_pos = pos;
		pos += 32;

		cpshrink_do_member(c, d, md);
		destroy_md(c, md);
		if(d->fatalerrflag) goto done;
	}

done:
	destroy_lctx(c, d);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_cpshrink(deark *c)
{
	i64 n;

	if(!de_input_file_has_ext(c, "cpz")) return 0;
	n = de_getu32le(0);
	if(n<1 || n>0xffff) return 0;
	if(de_getbyte(27)>2) return 0; // cmpr meth of 1st file
	return 25;
}

void de_module_cpshrink(deark *c, struct deark_module_info *mi)
{
	mi->id = "cpshrink";
	mi->desc = "CP Shrink .CPZ";
	mi->run_fn = de_run_cpshrink;
	mi->identify_fn = de_identify_cpshrink;
}

// **************************************************************************
// DWC archive
// **************************************************************************

static void dwc_decompressor_fn(struct member_data *md)
{
	deark *c = md->c;

	if(md->cmpr_meth==1) {
		struct de_lzw_params delzwp;

		de_zeromem(&delzwp, sizeof(struct de_lzw_params));
		delzwp.fmt = DE_LZWFMT_DWC;
		fmtutil_decompress_lzw(c, md->dcmpri, md->dcmpro, md->dres, &delzwp);
	}
	else if(md->cmpr_meth==2) {
		fmtutil_decompress_uncompressed(c, md->dcmpri, md->dcmpro, md->dres, 0);
	}
	else {
		de_dfilter_set_generic_error(c, md->dres, NULL);
	}
}

static void squash_slashes(de_ucstring *s)
{
	i64 i;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='/') {
			s->str[i] = '_';
		}
	}
}

// Convert backslashes to slashes, and make sure the string ends with a /.
static void fixup_path(de_ucstring *s)
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

// Set md->filename to the full-path filename, using tmpfn_path + tmpfn_base.
static void dwc_process_filename(deark *c, lctx *d, struct member_data *md)
{
	ucstring_empty(md->filename);
	squash_slashes(md->tmpfn_base);
	if(ucstring_isempty(md->tmpfn_path)) {
		ucstring_append_ucstring(md->filename, md->tmpfn_base);
		return;
	}

	md->set_name_flags |= DE_SNFLAG_FULLPATH;
	ucstring_append_ucstring(md->filename, md->tmpfn_path);
	fixup_path(md->filename);
	if(ucstring_isempty(md->tmpfn_base)) {
		ucstring_append_char(md->filename, '_');
	}
	else {
		ucstring_append_ucstring(md->filename, md->tmpfn_base);
	}
}

static void do_dwc_member(deark *c, lctx *d, i64 pos1, i64 fhsize)
{
	i64 pos = pos1;
	struct member_data *md = NULL;
	i64 cmt_len = 0;
	i64 path_len = 0;
	UI cdata_crc_reported = 0;
	UI cdata_crc_calc;
	u8 have_cdata_crc = 0;
	u8 b;
	de_ucstring *comment = NULL;

	md = create_md(c, d);

	de_dbg(c, "member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md->tmpfn_base = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 12, md->tmpfn_base, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->tmpfn_base));
	// tentative md->filename (could be used by error messages)
	ucstring_append_ucstring(md->filename, md->tmpfn_base);
	pos += 13;

	read_field_orig_len_p(md, &pos);
	read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 1, &pos);
	read_field_cmpr_len_p(md, &pos);
	md->cmpr_pos = de_getu32le_p(&pos);
	de_dbg(c, "cmpr. data pos: %"I64_FMT, md->cmpr_pos);

	b = de_getbyte_p(&pos);
	md->cmpr_meth = ((UI)b) & 0x0f;
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);
	md->file_flags = ((UI)b) >> 4;
	de_dbg(c, "flags: 0x%x", md->file_flags);
	if(md->file_flags & 0x4) {
		md->is_encrypted = 1;
	}

	if(fhsize>=31) {
		cmt_len = (i64)de_getbyte_p(&pos);
		de_dbg(c, "comment len: %d", (int)cmt_len);
	}
	if(fhsize>=32) {
		path_len = (i64)de_getbyte_p(&pos);
		de_dbg(c, "path len: %d", (int)path_len);
	}
	if(fhsize>=34) {
		cdata_crc_reported = (u32)de_getu16le_p(&pos);
		de_dbg(c, "CRC of cmpr. data (reported): 0x%04x", (UI)cdata_crc_reported);
		have_cdata_crc = 1;
	}

	if(!good_cmpr_data_pos(md)) {
		goto done;
	}

	if(path_len>1) {
		md->tmpfn_path = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, md->cmpr_pos+md->cmpr_len,
			path_len-1,
			md->tmpfn_path, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(md->tmpfn_path));
	}
	if(cmt_len>1) {
		comment = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, md->cmpr_pos+md->cmpr_len+path_len,
			cmt_len-1, comment, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(comment));
	}

	dwc_process_filename(c, d, md);

	if(have_cdata_crc) {
		if(!d->crco) {
			d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
		}
		de_crcobj_reset(d->crco);
		de_crcobj_addslice(d->crco, c->infile, md->cmpr_pos, md->cmpr_len);
		cdata_crc_calc = de_crcobj_getval(d->crco);
		de_dbg(c, "CRC of cmpr. data (calculated): 0x%04x", (UI)cdata_crc_calc);
		if(cdata_crc_calc!=cdata_crc_reported) {
			de_err(c, "File data CRC check failed (expected 0x%04x, got 0x%04x). "
				"DWC file may be corrupted.", (UI)cdata_crc_reported,
				(UI)cdata_crc_calc);
		}
	}

	if(d->private1) {
		md->dfn = dwc_decompressor_fn;
		extract_member_file(md);
	}

done:
	de_dbg_indent(c, -1);
	destroy_md(c, md);
	ucstring_destroy(comment);
}

static int has_dwc_sig(deark *c)
{
	return !dbuf_memcmp(c->infile, c->infile->len-3, (const u8*)"DWC", 3);
}

static void de_run_dwc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 trailer_pos;
	i64 trailer_len;
	i64 nmembers;
	i64 fhsize; // size of each file header
	i64 pos;
	i64 i;
	struct de_timestamp tmpts;
	int need_errmsg = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->private1 = de_get_ext_option_bool(c, "dwc:extract", 0);

	if(!has_dwc_sig(c)) {
		de_err(c, "Not a DWC file");
		goto done;
	}
	de_declare_fmt(c, "DWC archive");

	if(!d->private1) {
		de_info(c, "Note: Use \"-opt dwc:extract\" to attempt decompression "
			"(works for most small files).");
	}

	de_dbg(c, "trailer");
	de_dbg_indent(c, 1);

	pos = c->infile->len - 27; // Position of the "trailer size" field
	trailer_len = de_getu16le_p(&pos); // Usually 27
	trailer_pos = c->infile->len - trailer_len;
	de_dbg(c, "size: %"I64_FMT" (starts at %"I64_FMT")", trailer_len, trailer_pos);
	if(trailer_len<27 || trailer_pos<0) {
		need_errmsg = 1;
		goto done;
	}

	fhsize = (i64)de_getbyte_p(&pos);
	de_dbg(c, "file header entry size: %d", (int)fhsize);
	if(fhsize<30) {
		need_errmsg = 1;
		goto done;
	}

	pos += 13; // TODO?: name of header file ("h" command)
	read_field_dttm_p(d, &tmpts, "archive last-modified", 1, &pos);

	nmembers = de_getu16le_p(&pos);
	de_dbg(c, "number of member files: %d", (int)nmembers);
	de_dbg_indent(c, -1);

	pos = trailer_pos - fhsize*nmembers;
	if(pos<0) {
		need_errmsg = 1;
		goto done;
	}
	for(i=0; i<nmembers; i++) {
		do_dwc_member(c, d, pos, fhsize);
		if(d->fatalerrflag) goto done;
		pos += fhsize;
	}

done:
	if(need_errmsg) {
		de_err(c, "Bad DWC file");
	}
	destroy_lctx(c, d);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_dwc(deark *c)
{
	i64 tsize;
	int has_ext;
	u8 dsize;

	if(!has_dwc_sig(c)) return 0;
	tsize = de_getu16le(c->infile->len-27);
	if(tsize<27 || tsize>c->infile->len) return 0;
	dsize = de_getbyte(c->infile->len-25);
	if(dsize<30) return 0;
	has_ext = de_input_file_has_ext(c, "dwc");
	if(tsize==27 && dsize==34) {
		if(has_ext) return 100;
		return 60;
	}
	if(has_ext) return 10;
	return 0;
}

static void de_help_dwc(deark *c)
{
	de_msg(c, "-opt dwc:extract : Try to decompress");
}

void de_module_dwc(deark *c, struct deark_module_info *mi)
{
	mi->id = "dwc";
	mi->desc = "DWC compressed archive";
	mi->run_fn = de_run_dwc;
	mi->identify_fn = de_identify_dwc;
	mi->help_fn = de_help_dwc;
	mi->flags |= DE_MODFLAG_NONWORKING;
}

// **************************************************************************
// The Stirling Compressor" ("TSComp")
// **************************************************************************

// Probably only TSComp v1.3 is supported.

static void tscomp_decompressor_fn(struct member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

// Caller creates/destroys md, and sets a few fields.
static void tscomp_do_member(deark *c, lctx *d, struct member_data *md)
{
	i64 pos = md->member_hdr_pos;
	i64 fnlen;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member #%u at %"I64_FMT, (UI)md->member_idx,
		md->member_hdr_pos);
	de_dbg_indent(c, 1);

	pos += 1;
	read_field_cmpr_len_p(md, &pos);
	pos += 4; // ??
	read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 2, &pos);
	pos += 2; // ??

	fnlen = de_getbyte_p(&pos);

	// STOP_AT_NUL is probably not needed.
	dbuf_read_to_ucstring(c->infile, pos, fnlen, md->filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += fnlen;
	pos += 1; // ??

	md->cmpr_pos = pos;
	md->dfn = tscomp_decompressor_fn;
	extract_member_file(md);

	pos += md->cmpr_len;
	md->member_total_size = pos - md->member_hdr_pos;

	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_tscomp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 i;
	int saved_indent_level;
	u8 b;
	const char *name;

	de_dbg_indent_save(c, &saved_indent_level);
	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	pos = 0;
	de_dbg(c, "archive header at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 4;

	b = de_getbyte_p(&pos);
	if(b!=0x08) { d->need_errmsg = 1; goto done; }
	pos += 3; // version?? (01 03 00)
	b = de_getbyte_p(&pos);
	switch(b) {
	case 0: name = "old version"; break;
	case 1: name = "without wildcard"; break;
	case 2: name = "with wildcard"; break;
	default: name = "?";
	}
	de_dbg(c, "filename style: %u (%s)", (UI)b, name);
	if(b!=1 && b!=2) { d->need_errmsg = 1; goto done; }

	pos += 4; // ??
	de_dbg_indent(c, -1);

	i = 0;
	while(1) {
		struct member_data *md;

		if(d->fatalerrflag) goto done;
		if(pos+17 > c->infile->len) goto done;
		if(de_getbyte(pos) != 0x12) { d->need_errmsg = 1; goto done; }

		md = create_md(c, d);
		md->member_idx = i;
		md->member_hdr_pos = pos;

		tscomp_do_member(c, d, md);
		if(md->member_total_size<=0) d->fatalerrflag = 1;

		pos += md->member_total_size;
		destroy_md(c, md);
		i++;
	}

done:
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported TSComp format");
	}
	destroy_lctx(c, d);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_tscomp(deark *c)
{
	i64 n;

	n = de_getu32be(0);
	// Note: The "13" might be a version number. The "8c" is a mystery,
	// and seems to be ignored.
	if(n == 0x655d138cU) return 100;
	return 0;
}

void de_module_tscomp(deark *c, struct deark_module_info *mi)
{
	mi->id = "tscomp";
	mi->desc = "The Stirling Compressor";
	mi->run_fn = de_run_tscomp;
	mi->identify_fn = de_identify_tscomp;
}

// **************************************************************************
// EDI Install [Pro] packed file / EDI Pack / EDI LZSS / EDI LZSSLib
// **************************************************************************

static const u8 *g_edilzss_sig = (const u8*)"EDILZSS";

static void edi_pack_decompressor_fn(struct member_data *md)
{
	fmtutil_decompress_lzss1(md->c, md->dcmpri, md->dcmpro, md->dres, 0x0);
}

// This basically checks for a valid DOS filename.
// EDI Pack is primarily a Windows 3.x format -- I'm not sure what filenames are
// allowed.
static int edi_is_filename_at(deark *c, lctx *d, i64 pos)
{
	u8 buf[13];
	size_t i;
	int found_nul = 0;
	int found_dot = 0;
	int base_len = 0;
	int ext_len = 0;

	if(pos+13 > c->infile->len) return 0;
	de_read(buf, pos, 13);

	for(i=0; i<13; i++) {
		u8 b;

		b = buf[i];
		if(b==0) {
			found_nul = 1;
			break;
		}
		else if(b=='.') {
			if(found_dot) return 0;
			found_dot = 1;
		}
		else if(b<33 || b=='"' || b=='*' || b=='+' || b==',' || b=='/' ||
			b==':' || b==';' || b=='<' || b=='=' || b=='>' || b=='?' ||
			b=='[' || b=='\\' || b==']' || b=='|' || b==127)
		{
			return 0;
		}
		else {
			// TODO: Are capital letters allowed in this format? If not, that
			// would be a good thing to check for.
			if(found_dot) ext_len++;
			else base_len++;
		}
	}

	if(!found_nul || base_len<1 || base_len>8 || ext_len>3) return 0;
	return 1;
}

// Sets d->private_fmtver to:
//  0 = Not a known format
//  1 = EDI Pack "EDILZSS1"
//  2 = EDI Pack "EDILZSS2"
//  10 = EDI LZSSLib EDILZSSA.DLL
//  Other formats might exist, but are unlikely to ever be supported:
//  * EDI LZSSLib EDILZSSB.DLL
//  * EDI LZSSLib EDILZSSC.DLL
static void edi_detect_fmt(deark *c, lctx *d)
{
	u8 ver;
	i64 pos = 0;

	if(dbuf_memcmp(c->infile, pos, g_edilzss_sig, 7)) {
		d->need_errmsg = 1;
		return;
	}
	pos += 7;

	ver = de_getbyte_p(&pos);
	if(ver=='1') {
		// There's no easy way to distinguish some LZSS1 formats. This will not
		// always work.
		if(edi_is_filename_at(c, d, pos)) {
			d->private_fmtver = 1;
		}
		else {
			d->private_fmtver = 10;
		}
	}
	else if(ver=='2') {
		d->private_fmtver = 2;
	}
	else {
		d->need_errmsg = 1;
	}
}

static void de_run_edi_pack(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct member_data *md = NULL;
	i64 pos = 0;

	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	edi_detect_fmt(c, d);
	if(d->private_fmtver==0) goto done;
	else if(d->private_fmtver==10) {
		de_declare_fmt(c, "EDI LZSSLib");
	}
	else {
		de_declare_fmtf(c, "EDI Pack LZSS%d", d->private_fmtver);
	}
	pos = 8;

	md = create_md(c, d);
	if(d->private_fmtver==1 || d->private_fmtver==2) {
		dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
		pos += 13;
	}

	if(d->private_fmtver==2) {
		read_field_orig_len_p(md, &pos);
	}

	if(pos > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	md->cmpr_pos = pos;
	md->cmpr_len = c->infile->len - md->cmpr_pos;
	md->dfn = edi_pack_decompressor_fn;
	extract_member_file(md);

done:
	destroy_md(c, md);
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported EDI Pack format");
	}
	destroy_lctx(c, d);
}

static int de_identify_edi_pack(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, g_edilzss_sig, 7)) {
		u8 v;

		v = de_getbyte(7);
		if(v=='1' || v=='2') return 100;
		return 0;
	}
	return 0;
}

void de_module_edi_pack(deark *c, struct deark_module_info *mi)
{
	mi->id = "edi_pack";
	mi->desc = "EDI Install packed file";
	mi->run_fn = de_run_edi_pack;
	mi->identify_fn = de_identify_edi_pack;
}

// **************************************************************************
// RAR
// **************************************************************************

static const u8 *g_rar_oldsig = (const u8*)"RE\x7e\x5e";
static const u8 *g_rar2_sig = (const u8*)"Rar!\x1a\x07\x00";
static const u8 *g_rar5_sig = (const u8*)"Rar!\x1a\x07\x01\x00";

static void do_rar_old_member(deark *c, lctx *d, struct member_data *md)
{
	i64 n;
	u8 b;
	i64 pos = md->member_hdr_pos;
	i64 hdrlen;
	i64 fnlen;
	de_ucstring *comment = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member file at %"I64_FMT, md->member_hdr_pos);
	de_dbg_indent(c, 1);

	read_field_cmpr_len_p(md, &pos);
	read_field_orig_len_p(md, &pos);

	// TODO: What is this a checksum of?
	n = de_getu16le_p(&pos);
	de_dbg(c, "checksum: %u", (UI)n);

	hdrlen = de_getu16le_p(&pos);
	de_dbg(c, "hdr len: %u", (int)hdrlen);

	if(hdrlen < 12) {
		d->fatalerrflag = 1;
		goto done;
	}

	md->member_total_size = hdrlen + md->cmpr_len;

	read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 3, &pos);

	b = de_getbyte_p(&pos);
	de_dbg(c, "attribs: 0x%02x", (UI)b);

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
		comment = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, cmtlen, comment, 0,
			DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID));
		de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(comment));
		pos += cmtlen;
	}

	pos = md->member_hdr_pos + hdrlen;
	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, pos, md->cmpr_len);

done:
	ucstring_destroy(comment);
	de_dbg_indent_restore(c, saved_indent_level);
}

// Intended to work for, at least, RAR v1.40.2 (RAR1_402.EXE).
// Ref: Search for a file named RAR140DC.EXE, containing technote.doc.
static void do_rar_old(deark *c, lctx *d)
{
	i64 pos = 0;
	i64 hdrpos;
	i64 hdrlen;
	struct member_data *md = NULL;
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
			destroy_md(c, md);
			md = NULL;
		}
		md = create_md(c, d);
		md->member_hdr_pos = pos;
		do_rar_old_member(c, d, md);

		if(d->fatalerrflag) goto done;
		if(md->member_total_size <= 0) goto done;
		pos += md->member_total_size;
	}

done:
	if(md) {
		destroy_md(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}


struct rar_block {
	i64 block_pos;
	u32 crc_reported;
	UI flags;
	u8 type;
	i64 block_size_1;
	i64 block_size_2;
	i64 block_size_full;
};

static const char *rar_get_blktype_name(u8 n)
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
	case 0x7b: name = "trailer"; break; // ?
	}

	return name?name:"?";
}

static void do_rar2_block_fileheader(deark *c, lctx *d, struct rar_block *rb)
{
	struct member_data *md = NULL;
	i64 pos;
	i64 fnlen;
	u32 filecrc_reported;
	UI attribs;
	u8 b;

	md = create_md(c, d);

	pos = rb->block_pos + 11;

	md->cmpr_len = rb->block_size_2;
	read_field_orig_len_p(md, &pos);

	b = de_getbyte_p(&pos);
	de_dbg(c, "OS: %u", (UI)b);

	filecrc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "file crc: 0x%08x", (UI)filecrc_reported);

	read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 3, &pos);

	b = de_getbyte_p(&pos);
	de_dbg(c, "min ver needed to unpack: %u", (UI)b);

	md->cmpr_meth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);

	fnlen = de_getu16le_p(&pos);

	attribs = (UI)de_getu32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", attribs);

	// TODO: Handle UTF-8 names
	dbuf_read_to_ucstring_n(c->infile, pos, fnlen, 2048, md->filename,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += fnlen;

	// TODO: Comment block

	destroy_md(c, md);
}

static void rar_read_v2_block(deark *c, lctx *d, struct rar_block *rb, i64 pos1)
{
	int saved_indent_level;
	i64 pos;
	u32 crc_calc;

	de_dbg_indent_save(c, &saved_indent_level);
	de_zeromem(rb, sizeof(struct rar_block));
	rb->block_pos = pos1;
	pos = rb->block_pos;

	de_dbg(c, "block at %"I64_FMT, rb->block_pos);
	de_dbg_indent(c, 1);
	rb->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)rb->crc_reported);

	rb->type = de_getbyte_p(&pos);
	de_dbg(c, "block type: 0x%02x (%s)", (UI)rb->type, rar_get_blktype_name(rb->type));

	rb->flags = (UI)de_getu16le_p(&pos);
	de_dbg(c, "block flags: 0x%04x", (UI)rb->flags);

	rb->block_size_1 = de_getu16le_p(&pos);
	de_dbg(c, "block size (part 1): %"I64_FMT, rb->block_size_1);

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, rb->block_pos+2, rb->block_size_1-2);
	crc_calc = de_crcobj_getval(d->crco);
	crc_calc &= 0xffff;
	de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calc);

	if(rb->flags & 0x8000) {
		rb->block_size_2 = de_getu32le_p(&pos);
		de_dbg(c, "block size (part 2): %"I64_FMT, rb->block_size_2);
	}

	rb->block_size_full = rb->block_size_1 + rb->block_size_2;
	de_dbg(c, "block size (total): %"I64_FMT, rb->block_size_full);

	switch(rb->type) {
	case 0x74: do_rar2_block_fileheader(c, d, rb);
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_rar_v2(deark *c, lctx *d)
{
	struct rar_block *rb = NULL;
	i64 pos = 0;

	de_declare_fmt(c, "RAR (v1.50-4.20)");
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	rb = de_malloc(c, sizeof(struct rar_block));

	while(1) {
		if(pos >= c->infile->len) break;
		rar_read_v2_block(c, d, rb, pos);
		if(d->fatalerrflag) goto done;
		if(rb->block_size_full <= 0) goto done;
		pos += rb->block_size_full;
	}

done:
	de_free(c, rb);
}

static void de_run_rar(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	if(!dbuf_memcmp(c->infile, 0, g_rar2_sig, 7)) {
		d->private_fmtver = 2;
	}
	else if(!dbuf_memcmp(c->infile, 0, g_rar5_sig, 8)) {
		d->private_fmtver = 5;
	}
	else if(!dbuf_memcmp(c->infile, 0, g_rar_oldsig, 4)) {
		d->private_fmtver = 1;
	}

	if(d->private_fmtver==0) {
		de_err(c, "Not a RAR file");
		goto done;
	}

	if(d->private_fmtver==1) {
		do_rar_old(c, d);
	}
	else if(d->private_fmtver==2) {
		do_rar_v2(c, d);
	}
	else {
		de_err(c, "Unsupported RAR version");
		goto done;
	}

done:
	destroy_lctx(c, d);
}

static int de_identify_rar(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, g_rar2_sig, 7)) {
		return 100;
	}
	if(!dbuf_memcmp(c->infile, 0, g_rar_oldsig, 4)) {
		return 100;
	}
	return 0;
}

void de_module_rar(deark *c, struct deark_module_info *mi)
{
	mi->id = "rar";
	mi->desc = "RAR archive";
	mi->run_fn = de_run_rar;
	mi->identify_fn = de_identify_rar;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
