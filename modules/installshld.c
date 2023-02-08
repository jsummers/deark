// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// InstallShield Z
// InstallShield installer archive

#include <deark-private.h>
#include <deark-fmtutil.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_is_z);
DE_DECLARE_MODULE(de_module_is_instarch);
DE_DECLARE_MODULE(de_module_tscomp);

#define ISZ_MAX_DIRS          1000 // arbitrary
#define ISZ_MAX_FILES         5000 // arbitrary
#define ISZ_MAX_DIR_NAME_LEN  32768 // arbitrary
#define ISZ_SIGNATURE  0x8c655d13U

static void dclimplode_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

struct isz_dir_array_item {
	de_ucstring *dname;
};

// We don't need this struct; it's just here for future expansion
struct isz_member_data {
	UI dir_id;
};

struct isz_ctx {
	struct de_arch_localctx_struct *da;
	i64 directory_pos;
	i64 filelist_pos;
	i64 num_dirs;

	struct isz_dir_array_item *dir_array; // array[num_dirs]
};

static int isz_do_one_file(deark *c, struct isz_ctx *d, i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	i64 name_len;
	i64 segment_size;
	int retval = 0;
	struct de_arch_member_data *md = NULL;
	struct isz_member_data *mdi = NULL;
	struct isz_dir_array_item *di = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	mdi = de_malloc(c, sizeof(struct isz_member_data));
	md = de_arch_create_md(c, d->da);
	md->userdata = (void*)mdi;

	de_dbg(c, "file entry at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pos += 1; // ?

	mdi->dir_id = (UI)de_getu16le_p(&pos); // 1
	de_dbg(c, "dir id: %u", mdi->dir_id);
	if(mdi->dir_id >= d->num_dirs) {
		de_err(c, "Invalid directory");
		goto done;
	}
	di = &d->dir_array[mdi->dir_id];

	de_arch_read_field_orig_len_p(md, &pos); // 3
	de_arch_read_field_cmpr_len_p(md, &pos); // 7
	md->cmpr_pos = de_getu32le_p(&pos); // 11
	de_dbg(c, "cmpr data pos: %"I64_FMT, md->cmpr_pos);
	de_arch_read_field_dttm_p(d->da, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_DT, &pos);

	pos += 4; // ? (maybe a bit-field?)

	segment_size = de_getu16le_p(&pos);
	de_dbg(c, "segment size: %"I64_FMT, segment_size);
	if(segment_size<30) goto done;

	pos += 4; // ?

	name_len = (i64)de_getbyte_p(&pos);
	de_dbg(c, "name len: %"I64_FMT, name_len);
	md->tmpfn_base = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, name_len, md->tmpfn_base, 0, d->da->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->tmpfn_base));

	if(ucstring_isempty(md->tmpfn_base)) {
		ucstring_append_char(md->tmpfn_base, '_');
	}
	ucstring_append_ucstring(md->filename, di->dname);
	ucstring_append_ucstring(md->filename, md->tmpfn_base);
	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->filename));

	*pbytes_consumed = segment_size;
	retval = 1;

	md->set_name_flags |= DE_SNFLAG_FULLPATH;
	md->dfn = dclimplode_decompressor_fn;
	de_arch_extract_member_file(md);

done:
	de_arch_destroy_md(c, md);
	de_free(c, mdi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void isz_do_filelist(deark *c, struct isz_ctx *d)
{
	i64 pos = d->filelist_pos;
	i64 i;

	for(i=0; i<d->da->num_members; i++) {
		i64 bytes_consumed = 0;

		if(!isz_do_one_file(c, d, pos, &bytes_consumed)) goto done;
		if(bytes_consumed<=0) goto done;
		pos += bytes_consumed;
	}

done:
	;
}

static int isz_do_onedir(deark *c, struct isz_ctx *d, i64 dir_idx, i64 pos1, i64 *pbytes_consumed)
{
	i64 num_files;
	i64 segment_size;
	i64 name_len;
	i64 pos = pos1;
	i64 endpos;
	int retval = 0;
	struct isz_dir_array_item *di;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "dir entry at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	if(dir_idx<0 || dir_idx>=d->num_dirs) goto done;
	di = &d->dir_array[dir_idx];

	num_files = de_getu16le_p(&pos);
	de_dbg(c, "num files in this dir: %"I64_FMT, num_files);
	segment_size = de_getu16le_p(&pos);
	de_dbg(c, "segment size: %"I64_FMT, segment_size);
	if(segment_size<6) goto done;
	endpos = pos1 + segment_size;

	name_len = de_getu16le_p(&pos);
	de_dbg(c, "dir name len: %"I64_FMT, name_len);
	if(pos+name_len > endpos) goto done;
	if(name_len > ISZ_MAX_DIR_NAME_LEN) goto done;

	di->dname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, name_len, di->dname, 0, d->da->input_encoding);
	de_dbg(c, "dir name: \"%s\"", ucstring_getpsz_d(di->dname));
	de_arch_fixup_path(di->dname, 0);

	*pbytes_consumed = segment_size;
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void isz_do_dirlist(deark *c, struct isz_ctx *d)
{
	i64 pos;
	i64 i;

	pos = d->directory_pos;
	for(i=0; i<d->num_dirs; i++) {
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) goto done;
		if(!isz_do_onedir(c, d, i, pos, &bytes_consumed)) goto done;
		if(bytes_consumed<=0) goto done;
		pos += bytes_consumed;
	}
done:
	;
}

static void de_run_is_z(deark *c, de_module_params *mparams)
{
	struct isz_ctx *d = NULL;
	int saved_indent_level;
	struct de_timestamp tmp_timestamp;
	i64 tmp_pos;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct isz_ctx));
	d->da = de_arch_create_lctx(c);
	d->da->userdata = (void*)d;
	d->da->is_le = 1;

	d->da->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	// 0   13 5D 65 8C   = signature
	// 4   3A 01 02 00   = ?
	// 8... ?
	// 12  ui16  number of files
	// 14  ui16  date
	// 16  ui16  time
	// 18... ?
	// 41  ui32  offset of directory sequence
	// 45... ?
	// 49  ui16  number of dirs
	// 51  ui32  offset of files sequence

	if(de_getu32le(0)!=ISZ_SIGNATURE) {
		de_err(c, "Not an InstallShield Z file");
		goto done;
	}

	de_dbg(c, "main header");
	de_dbg_indent(c, 1);

	d->da->num_members = de_getu16le(12);
	de_dbg(c, "total number of files: %"I64_FMT, d->da->num_members);
	if(d->da->num_members>ISZ_MAX_FILES) goto done;

	tmp_pos = 14;
	de_arch_read_field_dttm_p(d->da, &tmp_timestamp, "archive",
		DE_ARCH_TSTYPE_DOS_DT, &tmp_pos);

	d->directory_pos = de_getu32le(41);
	de_dbg(c, "start of dir entries: %"I64_FMT, d->directory_pos);

	d->num_dirs = de_getu16le(49);
	de_dbg(c, "number of dirs: %"I64_FMT, d->num_dirs);
	if(d->num_dirs>ISZ_MAX_DIRS) goto done;

	d->filelist_pos = de_getu32le(51);
	de_dbg(c, "start of file entries: %"I64_FMT, d->filelist_pos);

	de_dbg_indent(c, -1);

	d->dir_array = de_mallocarray(c, d->num_dirs, sizeof(struct isz_dir_array_item));

	isz_do_dirlist(c, d);
	isz_do_filelist(c, d);

done:
	if(d) {
		if(d->dir_array) {
			i64 i;

			for(i=0; i<d->num_dirs; i++) {
				ucstring_destroy(d->dir_array[i].dname);
			}
			de_free(c, d->dir_array);
		}
		de_arch_destroy_lctx(c, d->da);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_is_z(deark *c)
{
	if(de_getu32le(0)==ISZ_SIGNATURE)
		return 100;
	return 0;
}

void de_module_is_z(deark *c, struct deark_module_info *mi)
{
	mi->id = "is_z";
	mi->desc = "InstallShield Z";
	mi->run_fn = de_run_is_z;
	mi->identify_fn = de_identify_is_z;
}

// **************************************************************************
// InstallShield installer archive
// **************************************************************************

static int do_instarch_member(deark *c, de_arch_lctx *da, struct de_arch_member_data *md)
{
	int retval = 0;
	int saved_indent_level;
	i64 pos = md->member_hdr_pos;
	i64 nlen;
	de_ucstring *tmps = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, md->member_hdr_pos);

	de_dbg_indent(c, 1);

	md->cmpr_pos = de_getu32le_p(&pos);
	de_dbg(c, "cmpr. data pos: %"I64_FMT, md->cmpr_pos);
	de_arch_read_field_cmpr_len_p(md, &pos);
	if(!de_arch_good_cmpr_data_pos(md)) {
		goto done;
	}

	de_arch_read_field_orig_len_p(md, &pos);
	pos += 8; // Unused?

	nlen = de_getu16le_p(&pos);
	dbuf_read_to_ucstring(c->infile, pos, nlen, md->filename, 0, da->input_encoding);
	de_dbg(c, "name 1: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += nlen;

	// I don't know why each file seemingly has two names.
	nlen = de_getu16le_p(&pos);
	tmps = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, nlen, tmps, 0, da->input_encoding);
	de_dbg(c, "name 2: \"%s\"", ucstring_getpsz_d(tmps));
	pos += nlen;

	md->dfn = dclimplode_decompressor_fn;
	de_arch_extract_member_file(md);

	md->member_hdr_size = pos - md->member_hdr_pos;
	retval = 1;
done:
	ucstring_destroy(tmps);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_is_instarch(deark *c, de_module_params *mparams)
{
	de_arch_lctx *da = NULL;
	i64 pos;
	i64 i;
	struct de_arch_member_data *md = NULL;

	da = de_arch_create_lctx(c);
	da->is_le = 1;
	da->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	pos = 78;
	da->num_members = de_getu16le_p(&pos); // This might actually be a 32-bit field
	de_dbg(c, "number of members: %"I64_FMT, da->num_members);
	pos += 2;

	for(i=0; i<da->num_members; i++) {
		if(pos >= c->infile->len) goto done;

		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, da);
		md->member_hdr_pos = pos;
		if(!do_instarch_member(c, da, md)) goto done;
		if(md->member_hdr_size<=0) goto done;
		pos += md->member_hdr_size;
	}

done:
	if(md) {
		de_arch_destroy_md(c, md);
	}
	if(da) {
		de_arch_destroy_lctx(c, da);
	}
}

static int de_identify_is_instarch(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x2a\xab\x79\xd8\x00\x01", 6)) {
		return 0;
	}
	return 100;
}

void de_module_is_instarch(deark *c, struct deark_module_info *mi)
{
	mi->id = "is_instarch";
	mi->id_alias[0] = "is_inst32i";
	mi->desc = "InstallShield installer archive (_inst32i.ex_)";
	mi->run_fn = de_run_is_instarch;
	mi->identify_fn = de_identify_is_instarch;
}

// **************************************************************************
// The Stirling Compressor" ("TSComp")
// **************************************************************************

// Probably only TSComp v1.3 is supported.

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
	de_arch_read_field_dttm_p(d, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
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
	md->dfn = dclimplode_decompressor_fn;
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
