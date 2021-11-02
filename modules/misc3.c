// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// This file is for miscellaneous small archive-format modules.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_cpshrink);
DE_DECLARE_MODULE(de_module_dwc);

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;

typedef void (*decompressor_cbfn)(struct member_data *md);

struct member_data {
	deark *c;
	lctx *d;
	i64 member_idx;
	i64 member_hdr_pos;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	de_ucstring *filename;
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];

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
	de_encoding input_encoding;
	i64 num_members;
	i64 cmpr_data_curpos;
	struct de_crcobj *crco;
	int errflag; // set on fatal error
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
static void read_field_dttm_mod_p(lctx *d,
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
	else if(tstype==2) {
		i64 dosdt, dostm;

		n1 = dbuf_getu16x(d->c->infile, *ppos, d->is_le);
		n2 = dbuf_getu16x(d->c->infile, *ppos+2, d->is_le);
		dosdt = n1;
		dostm = n2;

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

	fi = de_finfo_create(c);

	de_finfo_set_name_from_ucstring(c, fi, md->filename, 0);
	fi->original_filename_flag = 1;

	for(k=0; k<DE_TIMESTAMPIDX_COUNT; k++) {
		fi->timestamp[k] = md->tmstamp[k];
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_pos;
	dcmpri.len = md->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_len;
	md->dcmpri = &dcmpri;
	md->dcmpro = &dcmpro;
	md->dres = &dres;

	if(md->dfn) {
		md->dfn(md);
	}
	else {
		de_dfilter_set_generic_error(c, &dres, NULL);
	}

	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->filename),
			de_dfilter_get_errmsg(c, &dres));
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

	read_field_dttm_mod_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 2, &pos);

	if(!good_cmpr_data_pos(md)) {
		d->errflag = 1;
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
		if(d->errflag) goto done;
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

	md = create_md(c, d);

	de_dbg(c, "member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	dbuf_read_to_ucstring(c->infile, pos, 12, md->filename, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += 13;

	read_field_orig_len_p(md, &pos);
	read_field_dttm_mod_p(d, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod", 1, &pos);
	read_field_cmpr_len_p(md, &pos);
	md->cmpr_pos = de_getu32le_p(&pos);
	de_dbg(c, "cmpr. data pos: %"I64_FMT, md->cmpr_pos);

	b = de_getbyte_p(&pos);
	md->cmpr_meth = ((UI)b) & 0x0f;
	md->file_flags = ((UI)b) >> 4;
	de_dbg(c, "cmpr. method: %u", md->cmpr_meth);
	de_dbg(c, "flags: 0x%x", md->file_flags);

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
		d->errflag = 1;
		goto done;
	}

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

done:
	de_dbg_indent(c, -1);
	destroy_md(c, md);
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
	de_info(c, "Note: DWC files can be parsed, but no files can be extracted from them.");
	d = create_lctx(c);
	d->is_le = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	de_dbg(c, "trailer");
	de_dbg_indent(c, 1);

	if(!has_dwc_sig(c)) {
		de_err(c, "Not a DWC file");
		goto done;
	}

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
	read_field_dttm_mod_p(d, &tmpts, "archive last-modified", 1, &pos);

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
		if(d->errflag) goto done;
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

void de_module_dwc(deark *c, struct deark_module_info *mi)
{
	mi->id = "dwc";
	mi->desc = "DWC compressed archive";
	mi->run_fn = de_run_dwc;
	mi->identify_fn = de_identify_dwc;
}
