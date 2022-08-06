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
DE_DECLARE_MODULE(de_module_qip);
DE_DECLARE_MODULE(de_module_rar);

// de_arch mini-library
// (May eventually be moved to the fmtutil subsystem.)

struct de_arch_localctx_struct;
typedef struct de_arch_localctx_struct de_arch_lctx;
struct de_arch_member_data;

typedef void (*de_arch_decompressor_cbfn)(struct de_arch_member_data *md);

struct de_arch_member_data {
	deark *c;
	de_arch_lctx *d;
	i64 member_idx;
	i64 member_hdr_pos;
	i64 member_total_size;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	u32 crc_reported; // CRC of decompressed file
	u8 orig_len_known;
	de_ucstring *filename; // Allocated by de_arch_create_md().
	de_ucstring *tmpfn_base; // Client allocates, freed automatically.
	de_ucstring *tmpfn_path; // Client allocates, freed automatically.
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];
	UI set_name_flags; // e.g. DE_SNFLAG_FULLPATH
	UI dos_attribs;
	u8 is_encrypted;
	u8 has_dos_attribs;

	// Private use fields for the format decoder:
	UI cmpr_meth;
	UI file_flags;

	u8 validate_crc; // Tell de_arch_extract_member_file() to check crc_reported
	u8 extracted_ok; // Status returned by de_arch_extract_member_file()

	// The de_arch_extract_member_file() will temporarily set dcmpri/dcmpro/dres,
	// and call ->dfn() if it is set.
	de_arch_decompressor_cbfn dfn;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
};

struct de_arch_localctx_struct {
	deark *c;
	int is_le;
	u8 need_errmsg;
	de_encoding input_encoding;
	i64 num_members;
	i64 cmpr_data_curpos;
	struct de_crcobj *crco; // decoder must create; is destroyed automatically
	int fatalerrflag;

	// Private use fields for the format decoder:
	i64 data_startpos;
	int stop_flag;
	int fmtver;
	int private1;
	UI archive_flags;
	struct de_arch_member_data *cur_md;
};

static struct de_arch_member_data *de_arch_create_md(deark *c, de_arch_lctx *d)
{
	struct de_arch_member_data *md;

	md = de_malloc(c, sizeof(struct de_arch_member_data));
	md->c = c;
	md->d = d;
	md->filename = ucstring_create(c);
	return md;
}

static void de_arch_destroy_md(deark *c, struct de_arch_member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->filename);
	ucstring_destroy(md->tmpfn_base);
	ucstring_destroy(md->tmpfn_path);
	de_free(c, md);
}

static de_arch_lctx *de_arch_create_lctx(deark *c)
{
	de_arch_lctx *d;

	d = de_malloc(c, sizeof(de_arch_lctx));
	d->c = c;
	return d;
}

static void de_arch_destroy_lctx(deark *c, de_arch_lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_free(c, d);
}

static void handle_field_orig_len(struct de_arch_member_data *md, i64 n)
{
	md->orig_len = n;
	md->orig_len_known = 1;
	de_dbg(md->c, "original size: %"I64_FMT, md->orig_len);
}

static void de_arch_read_field_orig_len_p(struct de_arch_member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->c->infile, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_orig_len(md, n);
}

static void handle_field_cmpr_len(struct de_arch_member_data *md, i64 n)
{
	md->cmpr_len = n;
	de_dbg(md->c, "compressed size: %"I64_FMT, md->cmpr_len);
}

static void de_arch_read_field_cmpr_len_p(struct de_arch_member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->c->infile, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_cmpr_len(md, n);
}

static void de_arch_handle_field_dos_attr(struct de_arch_member_data *md, UI attr)
{
	de_ucstring *descr = NULL;

	md->dos_attribs = attr;
	md->has_dos_attribs = 1;
	descr = ucstring_create(md->c);
	de_describe_dos_attribs(md->c, md->dos_attribs, descr, 0);
	de_dbg(md->c, "DOS attribs: 0x%02x (%s)", md->dos_attribs, ucstring_getpsz_d(descr));
	ucstring_destroy(descr);
}

// Read and process a 1-byte DOS attributes field
static void de_arch_read_field_dos_attr_p(struct de_arch_member_data *md, i64 *ppos)
{
	UI attr;

	attr = (UI)dbuf_getbyte_p(md->c->infile, ppos);
	de_arch_handle_field_dos_attr(md, attr);
}

enum de_arch_tstype_enum {
	DE_ARCH_TSTYPE_UNIX=1,
	DE_ARCH_TSTYPE_UNIX_U,
	DE_ARCH_TSTYPE_DOS_DT,
	DE_ARCH_TSTYPE_DOS_TD,
	DE_ARCH_TSTYPE_FILETIME
};

static void de_arch_read_field_dttm_p(de_arch_lctx *d,
	struct de_timestamp *ts, const char *name,
	enum de_arch_tstype_enum tstype, i64 *ppos)
{
	i64 n1, n2;
	char timestamp_buf[64];
	int is_set = 0;

	ts->is_valid = 0;
	if(tstype==DE_ARCH_TSTYPE_UNIX || tstype==DE_ARCH_TSTYPE_UNIX_U) {
		if(tstype==DE_ARCH_TSTYPE_UNIX_U) {
			n1 = dbuf_getu32x(d->c->infile, *ppos, d->is_le);
		}
		else {
			n1 = dbuf_geti32x(d->c->infile, *ppos, d->is_le);
		}
		de_unix_time_to_timestamp(n1, ts, 0x1);
		is_set = 1;
	}
	else if(tstype==DE_ARCH_TSTYPE_DOS_DT || tstype==DE_ARCH_TSTYPE_DOS_TD) {
		i64 dosdt, dostm;

		n1 = dbuf_getu16x(d->c->infile, *ppos, d->is_le);
		n2 = dbuf_getu16x(d->c->infile, *ppos+2, d->is_le);
		if(tstype==DE_ARCH_TSTYPE_DOS_TD) {
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
	else if(tstype==DE_ARCH_TSTYPE_FILETIME) {
		n1 = dbuf_geti64x(d->c->infile, *ppos, d->is_le);
		if(n1!=0) {
			de_FILETIME_to_timestamp(n1, ts, 0x1);
			is_set = 1;
		}
	}

	if(is_set) {
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_snprintf(timestamp_buf, sizeof(timestamp_buf), "[not set]");
	}
	de_dbg(d->c, "%s time: %s", name, timestamp_buf);

	if(tstype==DE_ARCH_TSTYPE_FILETIME) {
		*ppos += 8;
	}
	else {
		*ppos += 4;
	}
}

// Assumes md->filename is set
static int de_arch_good_cmpr_data_pos(struct de_arch_member_data *md)
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

static void de_arch_extract_member_file(struct de_arch_member_data *md)
{
	deark *c = md->c;
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	size_t k;
	u32 crc_calc;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	md->extracted_ok = 0;
	if(md->orig_len>0 && !md->orig_len_known) goto done; // sanity check
	if(md->validate_crc && !md->d->crco) goto done;
	if(md->is_encrypted) {
		de_err(c, "%s: Encrypted files are not supported", ucstring_getpsz_d(md->filename));
		goto done;
	}
	if(!de_arch_good_cmpr_data_pos(md)) {
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
	if(md->validate_crc) {
		dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)md->d->crco);
	}

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

	if(md->validate_crc) {
		de_crcobj_reset(md->d->crco);
	}

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

	if(md->validate_crc) {
		crc_calc = de_crcobj_getval(md->d->crco);
		de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
		if(crc_calc!=md->crc_reported) {
			de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->filename));
			goto done;
		}
	}

	md->extracted_ok = 1;

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

static void cpshrink_decompressor_fn(struct de_arch_member_data *md)
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
static void cpshrink_do_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
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

	de_arch_read_field_orig_len_p(md, &pos);
	de_arch_read_field_cmpr_len_p(md, &pos);
	d->cmpr_data_curpos += md->cmpr_len;

	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_DT, &pos);

	if(!de_arch_good_cmpr_data_pos(md)) {
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
	de_arch_extract_member_file(md);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_cpshrink(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	i64 pos;
	i64 member_hdrs_pos;
	i64 member_hdrs_len;
	u32 member_hdrs_crc_reported;
	u32 member_hdrs_crc_calc;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_arch_create_lctx(c);
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
		struct de_arch_member_data *md;

		md = de_arch_create_md(c, d);
		md->member_idx = i;
		md->member_hdr_pos = pos;
		pos += 32;

		cpshrink_do_member(c, d, md);
		de_arch_destroy_md(c, md);
		if(d->fatalerrflag) goto done;
	}

done:
	de_arch_destroy_lctx(c, d);
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

static void dwc_decompressor_fn(struct de_arch_member_data *md)
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
static void dwc_process_filename(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
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

static void do_dwc_member(deark *c, de_arch_lctx *d, i64 pos1, i64 fhsize)
{
	i64 pos = pos1;
	struct de_arch_member_data *md = NULL;
	i64 cmt_len = 0;
	i64 path_len = 0;
	UI cdata_crc_reported = 0;
	UI cdata_crc_calc;
	u8 have_cdata_crc = 0;
	u8 b;
	de_ucstring *comment = NULL;

	md = de_arch_create_md(c, d);

	de_dbg(c, "member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md->tmpfn_base = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 12, md->tmpfn_base, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->tmpfn_base));
	// tentative md->filename (could be used by error messages)
	ucstring_append_ucstring(md->filename, md->tmpfn_base);
	pos += 13;

	de_arch_read_field_orig_len_p(md, &pos);
	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_UNIX, &pos);
	de_arch_read_field_cmpr_len_p(md, &pos);
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

	if(!de_arch_good_cmpr_data_pos(md)) {
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
		de_arch_extract_member_file(md);
	}

done:
	de_dbg_indent(c, -1);
	de_arch_destroy_md(c, md);
	ucstring_destroy(comment);
}

static int has_dwc_sig(deark *c)
{
	return !dbuf_memcmp(c->infile, c->infile->len-3, (const u8*)"DWC", 3);
}

static void de_run_dwc(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
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

	d = de_arch_create_lctx(c);
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
	de_arch_read_field_dttm_p(d, &tmpts, "archive last-modified", DE_ARCH_TSTYPE_UNIX, &pos);

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
	de_arch_destroy_lctx(c, d);
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

static void tscomp_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

// Caller creates/destroys md, and sets a few fields.
static void tscomp_do_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
{
	i64 pos = md->member_hdr_pos;
	i64 fnlen;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member #%u at %"I64_FMT, (UI)md->member_idx,
		md->member_hdr_pos);
	de_dbg_indent(c, 1);

	pos += 1;
	de_arch_read_field_cmpr_len_p(md, &pos);
	pos += 4; // ??
	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_DT, &pos);
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
	de_arch_extract_member_file(md);

	pos += md->cmpr_len;
	md->member_total_size = pos - md->member_hdr_pos;

	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_tscomp(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	i64 pos;
	i64 i;
	int saved_indent_level;
	u8 b;
	const char *name;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_arch_create_lctx(c);
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
		struct de_arch_member_data *md;

		if(d->fatalerrflag) goto done;
		if(pos+17 > c->infile->len) goto done;
		if(de_getbyte(pos) != 0x12) { d->need_errmsg = 1; goto done; }

		md = de_arch_create_md(c, d);
		md->member_idx = i;
		md->member_hdr_pos = pos;

		tscomp_do_member(c, d, md);
		if(md->member_total_size<=0) d->fatalerrflag = 1;

		pos += md->member_total_size;
		de_arch_destroy_md(c, md);
		i++;
	}

done:
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported TSComp format");
	}
	de_arch_destroy_lctx(c, d);
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

static void edi_pack_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_decompress_lzss1(md->c, md->dcmpri, md->dcmpro, md->dres, 0x0);
}

// This basically checks for a valid DOS filename.
// EDI Pack is primarily a Windows 3.x format -- I'm not sure what filenames are
// allowed.
static int edi_is_filename_at(deark *c, de_arch_lctx *d, i64 pos)
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

// Sets d->fmtver to:
//  0 = Not a known format
//  1 = EDI Pack "EDILZSS1"
//  2 = EDI Pack "EDILZSS2"
//  10 = EDI LZSSLib EDILZSSA.DLL
//  Other formats might exist, but are unlikely to ever be supported:
//  * EDI LZSSLib EDILZSSB.DLL
//  * EDI LZSSLib EDILZSSC.DLL
static void edi_detect_fmt(deark *c, de_arch_lctx *d)
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
			d->fmtver = 1;
		}
		else {
			d->fmtver = 10;
		}
	}
	else if(ver=='2') {
		d->fmtver = 2;
	}
	else {
		d->need_errmsg = 1;
	}
}

static void de_run_edi_pack(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	struct de_arch_member_data *md = NULL;
	i64 pos = 0;

	d = de_arch_create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	edi_detect_fmt(c, d);
	if(d->fmtver==0) goto done;
	else if(d->fmtver==10) {
		de_declare_fmt(c, "EDI LZSSLib");
	}
	else {
		de_declare_fmtf(c, "EDI Pack LZSS%d", d->fmtver);
	}
	pos = 8;

	md = de_arch_create_md(c, d);
	if(d->fmtver==1 || d->fmtver==2) {
		dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
		pos += 13;
	}

	if(d->fmtver==2) {
		de_arch_read_field_orig_len_p(md, &pos);
	}

	if(pos > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	md->cmpr_pos = pos;
	md->cmpr_len = c->infile->len - md->cmpr_pos;
	md->dfn = edi_pack_decompressor_fn;
	de_arch_extract_member_file(md);

done:
	de_arch_destroy_md(c, md);
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported EDI Pack format");
	}
	de_arch_destroy_lctx(c, d);
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
// Quarterdeck QIP
// **************************************************************************

static void qip_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

// Returns 0 if no member was found at md->member_hdr_pos.
static int do_qip_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
{
	int saved_indent_level;
	i64 pos;
	UI index;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, md->member_hdr_pos);
	de_dbg_indent(c, 1);
	pos = md->member_hdr_pos;
	if(dbuf_memcmp(c->infile, pos, "QD", 2)) goto done;
	pos += 2;
	retval = 1;
	pos += 2; // ?
	de_arch_read_field_cmpr_len_p(md, &pos);
	index = (UI)de_getu16le_p(&pos); // ?
	de_dbg(c, "index: %u", index);

	if(d->fmtver>=2) {
		md->crc_reported = (u32)de_getu32le_p(&pos);
		de_dbg(c, "crc (reported): 0x%08x", (UI)md->crc_reported);
	}

	de_arch_read_field_dos_attr_p(md, &pos); // ?

	de_arch_read_field_dttm_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_TD, &pos);
	de_arch_read_field_orig_len_p(md, &pos);
	dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += 12;
	pos += 1; // Maybe to allow the name to always be NUL terminated?

	md->cmpr_pos = pos;
	de_dbg(c, "cmpr data at %"I64_FMT, md->cmpr_pos);
	md->dfn = qip_decompressor_fn;
	if(d->fmtver>=2) {
		md->validate_crc = 1;
	}

	de_arch_extract_member_file(md);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void qip_do_v1(deark *c, de_arch_lctx *d)
{
	i64 pos = 0;
	struct de_arch_member_data *md = NULL;

	// This version doesn't have an index, but we sort of pretend it does,
	// so that v1 and v2 can be handled pretty much the same.

	while(1) {
		i64 cmpr_len;

		if(pos+32 >= c->infile->len) goto done;

		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, d);

		md->member_hdr_pos = pos;
		cmpr_len = de_getu32le(pos+4);
		if(!do_qip_member(c, d, md)) {
			goto done;
		}
		pos += 32 + cmpr_len;
	}

done:
	if(md) {
		de_arch_destroy_md(c, md);
	}
}

static void qip_do_v2(deark *c, de_arch_lctx *d)
{
	i64 pos;
	i64 index_pos;
	i64 index_len;
	i64 index_endpos;
	i64 i;
	struct de_arch_member_data *md = NULL;

	pos = 2;
	d->num_members = de_getu16le_p(&pos);
	de_dbg(c, "number of members: %"I64_FMT, d->num_members);
	index_len = de_getu32le_p(&pos);
	de_dbg(c, "index size: %"I64_FMT, index_len); // ??
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	index_pos = 16;

	de_dbg(c, "index at %"I64_FMT, index_pos);
	index_endpos = index_pos+index_len;
	if(index_endpos > c->infile->len) goto done;
	pos = index_pos;

	for(i=0; i<d->num_members; i++) {
		if(pos+16 > index_endpos) goto done;

		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, d);

		md->member_hdr_pos = de_getu32le_p(&pos);
		(void)do_qip_member(c, d, md);
		pos += 12;
	}

done:
	if(md) {
		de_arch_destroy_md(c, md);
	}
}

static void de_run_qip(deark *c, de_module_params *mparams)
{
	de_arch_lctx *d = NULL;
	u8 b;
	int unsupp_flag = 0;

	d = de_arch_create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	b = de_getbyte(1);
	if(b=='P') {
		d->fmtver = 2;
	}
	else if(b=='D') {
		d->fmtver = 1;
	}
	else {
		unsupp_flag = 1;
		goto done;
	}

	if(d->fmtver==2) {
		if(de_getbyte(8)!=0x02) {
			unsupp_flag = 1;
			goto done;
		}
	}

	if(d->fmtver==1) {
		qip_do_v1(c, d);
	}
	else {
		qip_do_v2(c, d);
	}

done:
	if(unsupp_flag) {
		de_err(c, "Not a supported QIP format");
	}
	de_arch_destroy_lctx(c, d);
}

static int de_identify_qip(deark *c)
{
	u8 b;
	i64 n;

	if(de_getbyte(0)!='Q') return 0;
	b = de_getbyte(1);
	if(b=='P') {
		if(de_getbyte(8)!=0x02) return 0;
		n = de_getu32le(16);
		if(n>c->infile->len) return 0;
		if(!dbuf_memcmp(c->infile, n, "QD", 2)) return 100;
	}
	else if(b=='D') {
		if(de_getu16le(2)==0 &&
			de_getu16le(8)==1)
		{
			return 70;
		}
	}
	return 0;
}

void de_module_qip(deark *c, struct deark_module_info *mi)
{
	mi->id = "qip";
	mi->desc = "QIP (Quarterdeck)";
	mi->run_fn = de_run_qip;
	mi->identify_fn = de_identify_qip;
}

// **************************************************************************
// RAR
// **************************************************************************

static const u8 *g_rar_oldsig = (const u8*)"RE\x7e\x5e";
static const u8 *g_rar4_sig = (const u8*)"Rar!\x1a\x07\x00";
static const u8 *g_rar5_sig = (const u8*)"Rar!\x1a\x07\x01\x00";

static void do_rar_old_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
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

	de_arch_read_field_cmpr_len_p(md, &pos);
	de_arch_read_field_orig_len_p(md, &pos);

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
	u32 crc_reported;
	UI flags;
	u8 type;
	i64 data1_pos;
	i64 block_size_1;
	i64 data2_pos;
	i64 block_size_2;
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
	case 0x7b: name = "trailer"; break; // ?
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
	md->cmpr_len = rb->block_size_2;
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

	// TODO: Handle UTF-8 names
	dbuf_read_to_ucstring_n(c->infile, pos, fnlen, 2048, md->filename,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += fnlen;

	// TODO: Comment block

	if(rb->flags & 0x0100) {
		// TODO: I think this requires special processing (HIGH_PACK_SIZE)
		d->fatalerrflag = 1;
		goto done;
	}

	de_dbg(c, "cmpr. data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);

done:
	de_arch_destroy_md(c, md);
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
	else if(rb->type==0x74) { // file hdr
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

		if(bf & 0x0200) {
			ucstring_append_flags_item(s, "Unicode filename");
			bf -= 0x0200;
		}
		if(bf & 0x1000) {
			ucstring_append_flags_item(s, "has ext time field");
			bf -= 0x1000;
		}
		// TODO: More fields
	}

	if(bf & 0x4000) {
		ucstring_append_flags_item(s, "unsafe to copy");
		bf -= 0x4000;
	}
	if(bf & 0x8000) {
		ucstring_append_flags_item(s, "full block");
		bf -= 0x8000;
	}
	if(bf!=0) {
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

static void rar_read_v4_block(deark *c, de_arch_lctx *d, struct rar4_block *rb, i64 pos1)
{
	int saved_indent_level;
	i64 pos;
	u32 crc_calc;
	de_ucstring *descr = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	rb->block_pos = pos1;
	pos = rb->block_pos;

	de_dbg(c, "block at %"I64_FMT, rb->block_pos);
	de_dbg_indent(c, 1);
	rb->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (UI)rb->crc_reported);

	rb->type = de_getbyte_p(&pos);
	de_dbg(c, "block type: 0x%02x (%s)", (UI)rb->type, rar_get_v4_blktype_name(rb->type));

	rb->flags = (UI)de_getu16le_p(&pos);
	descr = ucstring_create(c);
	get_rar4_flags_descr(rb, descr);
	de_dbg(c, "block flags: 0x%04x (%s)", (UI)rb->flags, ucstring_getpsz_d(descr));

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

	rb->data1_pos = pos;
	rb->data2_pos = rb->block_pos + rb->block_size_1;

	rb->block_size_full = rb->block_size_1 + rb->block_size_2;
	de_dbg(c, "block size (total): %"I64_FMT, rb->block_size_full);

	switch(rb->type) {
	case 0x74:
		do_rar4_block_fileheader(c, d, rb);
		break;
	case 0x77:
		do_rar4_block_oldsubblock(c, d, rb);
		break;
	}

	ucstring_destroy(descr);
	de_dbg_indent_restore(c, saved_indent_level);
}

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
		rar_read_v4_block(c, d, rb, pos);
		if(d->fatalerrflag) goto done;
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

	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, rb->data_area_pos, cmt_len, "comment.txt",
			NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		comment = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, rb->data_area_pos, cmt_len, DE_DBG_MAX_STRLEN,
			comment, 0, DE_ENCODING_UTF8);
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(comment));
	}

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
	// TODO: Unix time w/nanosecond precision
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
