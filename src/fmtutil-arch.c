// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// de_arch mini-library - Helper functions for archive formats

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil-arch.h"

struct de_arch_member_data *de_arch_create_md(deark *c, de_arch_lctx *d)
{
	struct de_arch_member_data *md;

	md = de_malloc(c, sizeof(struct de_arch_member_data));
	md->c = c;
	md->d = d;
	md->filename = ucstring_create(c);
	md->name_for_msgs = ucstring_create(c);
	md->fi = de_finfo_create(c);
	return md;
}

void de_arch_destroy_md(deark *c, struct de_arch_member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->filename);
	ucstring_destroy(md->name_for_msgs);
	ucstring_destroy(md->tmpfn_base);
	ucstring_destroy(md->tmpfn_path);
	de_finfo_destroy(c, md->fi);
	de_free(c, md);
}

de_arch_lctx *de_arch_create_lctx(deark *c)
{
	de_arch_lctx *d;

	d = de_malloc(c, sizeof(de_arch_lctx));
	d->c = c;
	d->inf = c->infile;
	return d;
}

void de_arch_destroy_lctx(deark *c, de_arch_lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_free(c, d);
}

static void ensure_name_for_msgs_is_set(struct de_arch_member_data *md)
{
	if(md->name_for_msgs_flag) return;

	if(ucstring_isnonempty(md->filename)) {
		ucstring_empty(md->name_for_msgs);
		ucstring_append_ucstring(md->name_for_msgs, md->filename);
	}
	else {
		if(ucstring_isempty(md->name_for_msgs)) {
			ucstring_append_sz(md->name_for_msgs, "(unknown filename)", DE_ENCODING_LATIN1);
		}
	}
}

// Convert backslashes to slashes, and append a slash if path is not empty.
// flags: Unused.
void de_arch_fixup_path(de_ucstring *s, UI flags)
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

static void handle_field_orig_len(struct de_arch_member_data *md, i64 n)
{
	md->orig_len = n;
	md->orig_len_known = 1;
	de_dbg(md->c, "original size: %"I64_FMT, md->orig_len);
}

void de_arch_read_field_orig_len_p(struct de_arch_member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->d->inf, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_orig_len(md, n);
}

static void handle_field_cmpr_len(struct de_arch_member_data *md, i64 n)
{
	md->cmpr_len = n;
	de_dbg(md->c, "compressed size: %"I64_FMT, md->cmpr_len);
}

void de_arch_read_field_cmpr_len_p(struct de_arch_member_data *md, i64 *ppos)
{
	i64 n;

	n = dbuf_getu32x(md->d->inf, *ppos, md->d->is_le);
	*ppos += 4;
	handle_field_cmpr_len(md, n);
}

void de_arch_handle_field_dos_attr(struct de_arch_member_data *md, UI attr)
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
void de_arch_read_field_dos_attr_p(struct de_arch_member_data *md, i64 *ppos)
{
	UI attr;

	attr = (UI)dbuf_getbyte_p(md->d->inf, ppos);
	de_arch_handle_field_dos_attr(md, attr);
}

void de_arch_read_field_dttm_p(de_arch_lctx *d,
	struct de_timestamp *ts, const char *name,
	enum de_arch_tstype_enum tstype, i64 *ppos)
{
	i64 n1, n2;
	char timestamp_buf[64];
	int is_set = 0;

	ts->is_valid = 0;
	if(tstype==DE_ARCH_TSTYPE_UNIX || tstype==DE_ARCH_TSTYPE_UNIX_U) {
		if(tstype==DE_ARCH_TSTYPE_UNIX_U) {
			n1 = dbuf_getu32x(d->inf, *ppos, d->is_le);
		}
		else {
			n1 = dbuf_geti32x(d->inf, *ppos, d->is_le);
		}
		de_unix_time_to_timestamp(n1, ts, 0x1);
		is_set = 1;
	}
	else if(tstype==DE_ARCH_TSTYPE_DOS_DT || tstype==DE_ARCH_TSTYPE_DOS_TD ||
		tstype==DE_ARCH_TSTYPE_DOS_DXT)
	{
		i64 dosdt, dostm;

		n1 = dbuf_getu16x(d->inf, *ppos, d->is_le);
		if(tstype==DE_ARCH_TSTYPE_DOS_DXT) {
			// Date, then 2 unused bytes, then time.
			n2 = dbuf_getu16x(d->inf, *ppos+4, d->is_le);
		}
		else {
			n2 = dbuf_getu16x(d->inf, *ppos+2, d->is_le);
		}

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
		n1 = dbuf_geti64x(d->inf, *ppos, d->is_le);
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

	if(tstype==DE_ARCH_TSTYPE_FILETIME || tstype==DE_ARCH_TSTYPE_DOS_DXT) {
		*ppos += 8;
	}
	else {
		*ppos += 4;
	}
}

// If md->filename is going to be set, it's best to set it before calling
// this function.
int de_arch_good_cmpr_data_pos(struct de_arch_member_data *md)
{
	if(md->cmpr_pos<0 || md->cmpr_len<0 ||
		md->cmpr_pos+md->cmpr_len > md->d->inf->len)
	{
		ensure_name_for_msgs_is_set(md);
		de_err(md->c, "%s: Data goes beyond end of file",
			ucstring_getpsz_d(md->name_for_msgs));
		return 0;
	}
	return 1;
}

// Caller should write something to the md->filename field, if possible.
// Normally, the caller should *not* call de_finfo_set_name_* on the
// md->fi object -- instead use md->filename and md->set_name_flags.
// If de_finfo_set_name_* is called, though, it will be used.
void de_arch_extract_member_file(struct de_arch_member_data *md)
{
	deark *c = md->c;
	dbuf *outf = NULL;
	u32 crc_calc;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	md->extracted_ok = 0;
	ensure_name_for_msgs_is_set(md);
	if(md->orig_len>0 && !md->orig_len_known) goto done; // sanity check
	if(md->validate_crc && !md->d->crco) goto done;
	if(md->is_encrypted) {
		de_err(c, "%s: Encrypted files are not supported", ucstring_getpsz_d(md->name_for_msgs));
		goto done;
	}
	if(!de_arch_good_cmpr_data_pos(md)) {
		goto done;
	}

	if(!md->fi->file_name_internal && ucstring_isnonempty(md->filename)) {
		de_finfo_set_name_from_ucstring(c, md->fi, md->filename, md->set_name_flags);
		md->fi->original_filename_flag = 1;
	}

	outf = dbuf_create_output_file(c, NULL, md->fi, 0);
	dbuf_enable_wbuffer(outf);
	if(md->validate_crc) {
		dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)md->d->crco);
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = md->d->inf;
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
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->name_for_msgs),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(md->orig_len_known && (outf->len != md->orig_len)) {
		de_err(c, "%s: Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			ucstring_getpsz_d(md->name_for_msgs), md->orig_len, outf->len);
		goto done;
	}

	if(md->validate_crc) {
		crc_calc = de_crcobj_getval(md->d->crco);
		de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
		if(crc_calc!=md->crc_reported) {
			if(md->behavior_on_wrong_crc==1) {
				de_warn(c, "%s: CRC check not available", ucstring_getpsz_d(md->name_for_msgs));
			}
			else {
				de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->name_for_msgs));
				goto done;
			}
		}
	}

	md->extracted_ok = 1;

done:
	dbuf_close(outf);
	md->dcmpri = NULL;
	md->dcmpro = NULL;
	md->dres = NULL;
}
