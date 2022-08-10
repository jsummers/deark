// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// InstallShield Z

#include <deark-private.h>
#include <deark-fmtutil.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_is_z);

#define ISZ_MAX_DIRS          1000 // arbitrary
#define ISZ_MAX_FILES         5000 // arbitrary
#define ISZ_MAX_DIR_NAME_LEN  32768 // arbitrary
#define ISZ_SIGNATURE  0x8c655d13U

struct dir_array_item {
	de_ucstring *dname;
};

// We don't need this struct; it's just here for future expansion
struct isz_member_data {
	UI dir_id;
};

typedef struct localctx_struct {
	struct de_arch_localctx_struct *da;
	i64 directory_pos;
	i64 filelist_pos;
	i64 num_dirs;

	struct dir_array_item *dir_array; // array[num_dirs]
} lctx;

static void isz_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

static int do_one_file(deark *c, lctx *d, i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	i64 name_len;
	i64 segment_size;
	int retval = 0;
	struct de_arch_member_data *md = NULL;
	struct isz_member_data *mdi = NULL;
	struct dir_array_item *di = NULL;
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
	de_arch_read_field_dttm_p(d->da, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod",
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
	md->dfn = isz_decompressor_fn;
	de_arch_extract_member_file(md);

done:
	de_arch_destroy_md(c, md);
	de_free(c, mdi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_filelist(deark *c, lctx *d)
{
	i64 pos = d->filelist_pos;
	i64 i;

	for(i=0; i<d->da->num_members; i++) {
		i64 bytes_consumed = 0;

		if(!do_one_file(c, d, pos, &bytes_consumed)) goto done;
		if(bytes_consumed<=0) goto done;
		pos += bytes_consumed;
	}

done:
	;
}

static int do_onedir(deark *c, lctx *d, i64 dir_idx, i64 pos1, i64 *pbytes_consumed)
{
	i64 num_files;
	i64 segment_size;
	i64 name_len;
	i64 pos = pos1;
	i64 endpos;
	int retval = 0;
	struct dir_array_item *di;
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

static void do_dirlist(deark *c, lctx *d)
{
	i64 pos;
	i64 i;

	pos = d->directory_pos;
	for(i=0; i<d->num_dirs; i++) {
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) goto done;
		if(!do_onedir(c, d, i, pos, &bytes_consumed)) goto done;
		if(bytes_consumed<=0) goto done;
		pos += bytes_consumed;
	}
done:
	;
}

static void de_run_is_z(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int saved_indent_level;
	struct de_timestamp tmp_timestamp;
	i64 tmp_pos;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
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

	d->dir_array = de_mallocarray(c, d->num_dirs, sizeof(struct dir_array_item));

	do_dirlist(c, d);
	do_filelist(c, d);

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
