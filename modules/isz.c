// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// InstallShield Z

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_is_z);

#define ISZ_MAX_DIRS          1000 // arbitrary
#define ISZ_MAX_FILES         5000 // arbitrary
#define ISZ_MAX_DIR_NAME_LEN  32768 // arbitrary

struct dir_array_item {
	de_ucstring *dname;
};

struct member_data {
	i64 unc_size;
	i64 cmpr_size;
	i64 cmpr_data_pos;
	UI dir_id;
	de_ucstring *fname;
	de_ucstring *full_fname;
};

typedef struct localctx_struct {
	de_encoding input_encoding;
	i64 directory_pos;
	i64 filelist_pos;
	i64 num_dirs;
	i64 num_files_total;

	struct dir_array_item *dir_array; // array[num_dirs]
} lctx;

static int do_one_file(deark *c, lctx *d, i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	i64 name_len;
	i64 segment_size;
	int retval = 0;
	struct member_data *md = NULL;
	struct dir_array_item *di = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	md = de_malloc(c, sizeof(struct member_data));
	de_dbg(c, "file entry at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pos += 1; // ?

	md->dir_id = (UI)de_getu16le_p(&pos); // 1
	de_dbg(c, "dir id: %u", md->dir_id);
	if(md->dir_id >= d->num_dirs) {
		de_err(c, "Invalid directory");
		goto done;
	}
	di = &d->dir_array[md->dir_id];
	
	md->unc_size = de_getu32le_p(&pos); // 3
	de_dbg(c, "orig size: %"I64_FMT, md->unc_size);
	md->cmpr_size = de_getu32le_p(&pos); // 7
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);
	md->cmpr_data_pos = de_getu32le_p(&pos); // 11
	de_dbg(c, "cmpr data pos: %"I64_FMT, md->cmpr_data_pos);

	pos += 4; // datetime
	pos += 4; // ?

	segment_size = de_getu16le_p(&pos);
	de_dbg(c, "segment size: %"I64_FMT, segment_size);
	if(segment_size<30) goto done;

	pos += 4; // ?

	name_len = (i64)de_getbyte_p(&pos);
	de_dbg(c, "name len: %"I64_FMT, name_len);
	md->fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, name_len, md->fname, 0, d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->fname));

	if(ucstring_isempty(md->fname)) {
		ucstring_append_char(md->fname, '_');
	}
	md->full_fname = ucstring_clone(di->dname);
	ucstring_append_ucstring(md->full_fname, md->fname);

	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->full_fname));

	*pbytes_consumed = segment_size;
	retval = 1;

done:
	if(md) {
		ucstring_destroy(md->fname);
		ucstring_destroy(md->full_fname);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_filelist(deark *c, lctx *d)
{
	i64 pos = d->filelist_pos;
	i64 i;

	for(i=0; i<d->num_files_total; i++) {
		i64 bytes_consumed = 0;

		if(!do_one_file(c, d, pos, &bytes_consumed)) goto done;
		if(bytes_consumed<=0) goto done;
		pos += bytes_consumed;
	}

done:
	return 1;
}

// Convert backslashes to slashes, and append a slash if path is not empty.
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
	dbuf_read_to_ucstring(c->infile, pos, name_len, di->dname, 0, d->input_encoding);
	de_dbg(c, "dir name: \"%s\"", ucstring_getpsz_d(di->dname));
	fixup_path(di->dname);

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

	de_dbg_indent_save(c, &saved_indent_level);

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	// 0   13 5D 65 8C   = signature
	// 4   3A 01 02 00   = ?
	// 5...
	// 12  ui16  number of files
	// 14  byte[6] ?
	// ...
	// 41  ui32  offset of directory sequence
	// 45...
	// 49  ui16  number of dirs
	// 51  ui32  offset of files sequence

	de_dbg(c, "main header");
	de_dbg_indent(c, 1);

	d->num_files_total = de_getu16le(12);
	de_dbg(c, "total number of files: %"I64_FMT, d->num_files_total);
	if(d->num_files_total>ISZ_MAX_FILES) goto done;

	d->directory_pos = de_getu32le(41);
	de_dbg(c, "start of directory entries: %"I64_FMT, d->directory_pos);

	d->num_dirs = de_getu16le(49);
	de_dbg(c, "num dirs: %"I64_FMT, d->num_dirs);
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
			for(i64 i=0; i<d->num_dirs; i++) {
				ucstring_destroy(d->dir_array[i].dname);
			}
			de_free(c, d->dir_array);
		}
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_is_z(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x13\x5d\x65\x8c", 4))
		return 100;
	return 0;
}

void de_module_is_z(deark *c, struct deark_module_info *mi)
{
	mi->id = "is_z";
	mi->desc = "InstallShield Z";
	mi->run_fn = de_run_is_z;
	mi->identify_fn = de_identify_is_z;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
