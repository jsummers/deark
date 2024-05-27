// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// CRUSH archive (PocketWare)
// Format is documented (CRUSH18.ZIP/MANUAL.DOC), though not in full detail.

#include <deark-private.h>
#include <deark-fmtutil.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_crush);

#define CRUSH_HEADER_LEN 26
#define CRUSH_DIRENTRY_LEN 24

struct crush_member_data {
	UI path_num; // 0 = no path, 1 = paths[0], 2 = paths[1], ...
};

typedef struct localctx_struct {
	struct de_arch_localctx_struct *da;
	UI ver_maj, ver_min;
	int is_cri;
	i64 num_paths;
	i64 dir_segment_pos;
	int paths_segment_len_known;
	i64 paths_segment_pos;
	i64 paths_segment_len;
	de_ucstring **paths; // array[num_paths]
} lctx;

// Squash slashes, ensure not empty.
static void fixup_filename(de_ucstring *s)
{
	i64 i;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='/') {
			s->str[i] = '_';
		}
	}

	if(ucstring_isempty(s)) {
		ucstring_append_char(s, '_');
	}
}

static int do_read_paths(deark *c, lctx *d)
{
	i64 pos;
	i64 i;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->num_paths > 255) {
		// Number of paths can't be >255 in the known versions of the format,
		// because paths are indexed by a 1-byte int.
		d->num_paths = 255;
	}

	if(d->num_paths <= 0) {
		d->paths_segment_len = 0;
		d->paths_segment_len_known = 1;
		retval = 1;
		goto done;
	}

	d->paths = de_mallocarray(c, d->num_paths, sizeof(de_ucstring*));
	for(i=0; i<d->num_paths; i++) {
		d->paths[i] = ucstring_create(c);
	}

	de_dbg(c, "paths at %"I64_FMT, d->paths_segment_pos);
	de_dbg_indent(c, 1);

	pos = d->paths_segment_pos;
	for(i=0; i<d->num_paths; i++) {
		int ret;
		i64 foundpos = 0;
		i64 path_len;

		if(pos >= c->infile->len) goto done;
		ret = dbuf_search_byte(c->infile, 0x00, pos, c->infile->len-pos, &foundpos);
		if(!ret) goto done;
		path_len = foundpos - pos;
		if(path_len > 260) goto done;
		dbuf_read_to_ucstring(c->infile, pos, path_len, d->paths[i], 0, d->da->input_encoding);
		de_dbg(c, "path #%d: \"%s\"", (int)(i+1), ucstring_getpsz_d(d->paths[i]));
		de_arch_fixup_path(d->paths[i], 0x1);
		pos = foundpos + 1;
	}
	d->paths_segment_len = pos - d->paths_segment_pos;
	d->paths_segment_len_known = 1;
	retval = 1;
done:
	if(!retval) {
		de_warn(c, "Could not read path table");
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_comment(deark *c, lctx *d)
{
	i64 pos;
	i64 len;
	i64 avail_len;
	i64 foundpos;
	int ret;
	de_ucstring *s = NULL;

	if(!d->paths_segment_len_known) goto done;
	pos = d->paths_segment_pos + d->paths_segment_len;
	avail_len = c->infile->len - pos;
	if(avail_len<=1) goto done;

	// Find the terminating NUL
	ret = dbuf_search_byte(c->infile, 0x00, pos, c->infile->len-pos, &foundpos);
	if(!ret) goto done;
	len = foundpos - pos;
	if(len<1 || len>2048) goto done;

	de_dbg(c, "comment at %"I64_FMT, pos);
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0,
		DE_EXTENC_MAKE(d->da->input_encoding, DE_ENCSUBTYPE_HYBRID));
	de_dbg_indent(c, 1);
	de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(s));
	de_dbg_indent(c, -1);

done:
	ucstring_destroy(s);
}

static void make_fullfilename(deark *c, lctx *d, struct de_arch_member_data *md)
{
	struct crush_member_data *mdc = (struct crush_member_data*)md->userdata;

	if(mdc->path_num>0 && mdc->path_num<=d->num_paths &&
		d->paths && ucstring_isnonempty(d->paths[mdc->path_num-1]))
	{
		ucstring_append_ucstring(md->filename, d->paths[mdc->path_num-1]);
	}

	ucstring_append_ucstring(md->filename, md->tmpfn_base);
}

static void uncmpr_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_decompress_uncompressed(md->c, md->dcmpri, md->dcmpro, md->dres, 0);
}

// Uses and updates d->file_data_curpos
static int do_member_file(deark *c, lctx *d, i64 idx, i64 pos1)
{
	int retval = 0;
	struct de_arch_member_data *md = NULL;
	struct crush_member_data *mdc = NULL;
	de_ucstring *descr = NULL;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_arch_create_md(c, d->da);
	mdc = de_malloc(c, sizeof(struct crush_member_data));
	md->userdata = (void*)mdc;
	md->tmpfn_base = ucstring_create(c);

	de_dbg(c, "member file[%d]", (int)idx);
	de_dbg_indent(c, 1);
	de_dbg(c, "dir entry at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

	mdc->path_num = (UI)de_getbyte_p(&pos);
	de_dbg(c, "path num: %u", mdc->path_num);

	de_arch_read_field_dos_attr_p(md, &pos);

	de_arch_read_field_dttm_p(d->da, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_TD, &pos);

	de_arch_read_field_orig_len_p(md, &pos);
	md->cmpr_len = md->orig_len;

	dbuf_read_to_ucstring(c->infile, pos, 12, md->tmpfn_base, DE_CONVFLAG_STOP_AT_NUL,
		d->da->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->tmpfn_base));
	fixup_filename(md->tmpfn_base);
	make_fullfilename(c, d, md);
	md->set_name_flags |= DE_SNFLAG_FULLPATH;
	de_dbg_indent(c, -1);

	// If this is just an index (.CRI) file, there's nothing to extract.
	// We can't tell the difference between an index file, and an archive file
	// containing only zero-length members, so extract zero-length files just
	// in case.
	if(d->is_cri && md->cmpr_len!=0) {
		retval = 1;
		goto done;
	}

	de_dbg(c, "file data at %"I64_FMT, d->da->cmpr_data_curpos);

	if(d->da->cmpr_data_curpos + md->cmpr_len > d->dir_segment_pos) {
		de_err(c, "Malformed CRU archive");
		goto done;
	}

	md->cmpr_pos = d->da->cmpr_data_curpos;
	d->da->cmpr_data_curpos += md->cmpr_len;
	retval = 1;

	if((md->dos_attribs & 0x18) != 0x00) {
		// I don't know if subdirs or volume labels can be in these archives.
		de_warn(c, "%s: Not a regular file", ucstring_getpsz_d(md->filename));
	}

	md->dfn = uncmpr_decompressor_fn;
	de_arch_extract_member_file(md);

done:
	ucstring_destroy(descr);
	if(mdc) {
		de_free(c, mdc);
	}
	de_arch_destroy_md(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_read_dir_and_extract_files(deark *c, lctx *d)
{
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->da->num_members<1) {
		goto done;
	}
	de_dbg(c, "directory at %"I64_FMT, d->dir_segment_pos);
	de_dbg_indent(c, 1);

	d->da->cmpr_data_curpos = CRUSH_HEADER_LEN;

	for(i=0; i<d->da->num_members; i++) {
		if(!do_member_file(c, d, i, d->dir_segment_pos + CRUSH_DIRENTRY_LEN * i)) {
			goto done;
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_archive_header(deark *c, lctx *d)
{
	i64 pos1 = 0;
	u8 b;

	de_dbg(c, "archive header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	b = de_getbyte(pos1+7);
	if(b>='0' && b<='9') d->ver_maj = (UI)(b-'0');
	b = (UI)de_getbyte(pos1+9);
	if(b>='0' && b<='9') d->ver_min = (UI)(b-'0');
	de_dbg(c, "version: %u.%u", d->ver_maj, d->ver_min);

	d->num_paths = de_getu16le(pos1+16);
	de_dbg(c, "num paths %"I64_FMT, d->num_paths);
	d->da->num_members = de_getu16le(pos1+18);
	de_dbg(c, "num files %"I64_FMT, d->da->num_members);
	d->dir_segment_pos = de_getu32le(pos1+22);
	de_dbg(c, "directory pos: %"I64_FMT, d->dir_segment_pos);

	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_crush(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->da = de_arch_create_lctx(c);
	d->da->userdata = (void*)d;
	d->da->is_le = 1;

	d->da->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	if(!do_archive_header(c, d)) goto done;
	d->is_cri = (d->dir_segment_pos == CRUSH_HEADER_LEN);
	de_declare_fmtf(c, "CRUSH %s", d->is_cri ? "index" : "archive");

	d->paths_segment_pos = d->dir_segment_pos + (CRUSH_DIRENTRY_LEN * d->da->num_members);

	(void)do_read_paths(c, d);
	do_comment(c, d);
	do_read_dir_and_extract_files(c, d);

done:
	if(d) {
		if(d->paths) {
			i64 i;

			for(i=0; i<d->num_paths; i++) {
				ucstring_destroy(d->paths[i]);
			}
		}
		de_arch_destroy_lctx(c, d->da);
		de_free(c, d);
	}
}

static int de_identify_crush(deark *c)
{
	u8 buf[14];

	de_read(buf, 0, 14);
	if(!de_memcmp(buf, "CRUSH v", 7) &&
		buf[10]==0x0a && buf[11]==0x1a && buf[12]==0x00)
	{
		return 100;
	}

	return 0;
}

void de_module_crush(deark *c, struct deark_module_info *mi)
{
	mi->id = "crush";
	mi->desc = "CRUSH archive";
	mi->run_fn = de_run_crush;
	mi->identify_fn = de_identify_crush;
}
