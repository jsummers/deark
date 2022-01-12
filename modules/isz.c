// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// InstallShield Z

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_is_z);

#define ISZ_MAX_DIRS          1000 // arbitrary
#define ISZ_MAX_FILES         5000 // arbitrary
#define ISZ_MAX_DIR_NAME_LEN  32768 // arbitrary
#define ISZ_SIGNATURE  0x8c655d13U

struct dir_array_item {
	de_ucstring *dname;
};

struct member_data {
	i64 orig_size;
	i64 cmpr_size;
	i64 cmpr_data_pos;
	UI dir_id;
	de_ucstring *fname;
	de_ucstring *full_fname;
	struct de_timestamp mod_time;
};

typedef struct localctx_struct {
	de_encoding input_encoding;
	i64 directory_pos;
	i64 filelist_pos;
	i64 num_dirs;
	i64 num_files_total;

	struct dir_array_item *dir_array; // array[num_dirs]
} lctx;

static void extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(md->cmpr_data_pos + md->cmpr_size > c->infile->len) {
		de_err(c, "%s: Data goes beyond end of file",
			ucstring_getpsz_d(md->fname));
		goto done;
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, md->full_fname, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;
	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_enable_wbuffer(outf);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_data_pos;
	dcmpri.len = md->cmpr_size;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_size;

	fmtutil_dclimplode_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(dcmpro.f);
	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->fname),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static void read_timestamp(deark *c, lctx *d, struct de_timestamp *ts,
	i64 pos, const char *name)
{
	i64 mod_time_raw, mod_date_raw;
	char timestamp_buf[64];

	mod_date_raw = de_getu16le(pos);
	mod_time_raw = de_getu16le(pos+2);
	de_dos_datetime_to_timestamp(ts, mod_date_raw, mod_time_raw);
	ts->tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

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

	md->orig_size = de_getu32le_p(&pos); // 3
	de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	md->cmpr_size = de_getu32le_p(&pos); // 7
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);
	md->cmpr_data_pos = de_getu32le_p(&pos); // 11
	de_dbg(c, "cmpr data pos: %"I64_FMT, md->cmpr_data_pos);

	read_timestamp(c, d, &md->mod_time, pos, "mod time");
	pos += 4;

	pos += 4; // ? (maybe a bit-field?)

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

	extract_file(c, d, md);

done:
	if(md) {
		ucstring_destroy(md->fname);
		ucstring_destroy(md->full_fname);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_filelist(deark *c, lctx *d)
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
	;
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
	struct de_timestamp tmp_timestamp;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

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

	d->num_files_total = de_getu16le(12);
	de_dbg(c, "total number of files: %"I64_FMT, d->num_files_total);
	if(d->num_files_total>ISZ_MAX_FILES) goto done;

	read_timestamp(c, d, &tmp_timestamp, 14, "timestamp");

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
