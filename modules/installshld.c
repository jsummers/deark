// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// InstallShield Z
// InstallShield installer archive
// Etc.

#include <deark-private.h>
#include <deark-fmtutil.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_is_z);
DE_DECLARE_MODULE(de_module_is_instarch);
DE_DECLARE_MODULE(de_module_tscomp);
DE_DECLARE_MODULE(de_module_is_sfx);

#define ISZ_MAX_DIRS          1000 // arbitrary
#define ISZ_MAX_FILES         5000 // arbitrary
#define ISZ_MAX_DIR_NAME_LEN  32768 // arbitrary
#define ISZ_SIGNATURE  0x8c655d13U

static void dclimplode_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_dclimplode_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

static void noncompressed_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_decompress_uncompressed(md->c, md->dcmpri, md->dcmpro, md->dres, 0);
}

struct isz_dir_array_item {
	de_ucstring *dname;
};

// We don't need this struct; it's just here for future expansion
struct isz_member_data {
	UI dir_id;
	UI start_vol;
	UI end_vol;
	UI attribs;
	u8 is_split;
};

struct isz_ctx {
	struct de_arch_localctx_struct *da;
	i64 directory_pos;
	i64 filelist_pos;
	i64 num_dirs;
	u8 is_multivol;
	i64 tot_orig_size;
	i64 tot_cmpr_size;
	UI volume_number;

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

	mdi->end_vol = (UI)de_getbyte_p(&pos);
	de_dbg(c, "ending volume: %u", (UI)mdi->end_vol);

	mdi->dir_id = (UI)de_getu16le_p(&pos); // 1
	de_dbg(c, "dir id: %u", mdi->dir_id);
	if(mdi->dir_id >= d->num_dirs) {
		de_err(c, "Invalid directory");
		goto done;
	}
	di = &d->dir_array[mdi->dir_id];

	de_arch_read_field_orig_len_p(md, &pos); // 3
	d->tot_orig_size += md->orig_len;
	de_arch_read_field_cmpr_len_p(md, &pos); // 7
	d->tot_cmpr_size += md->cmpr_len;
	md->cmpr_pos = de_getu32le_p(&pos); // 11
	// printing cmpr_pos is deferred until we read the volume

	de_arch_read_field_dttm_p(d->da, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_DT, &pos);

	pos += 4; // ? (maybe a bit-field?)

	segment_size = de_getu16le_p(&pos);
	de_dbg(c, "segment size: %"I64_FMT, segment_size);
	if(segment_size<30) goto done;

	mdi->attribs = (UI)de_getbyte_p(&pos);
	de_dbg(c, "attribs: 0x%02x", (UI)mdi->attribs);

	mdi->is_split = de_getbyte_p(&pos);
	de_dbg(c, "is split: %u", (UI)mdi->is_split);

	pos += 1; // ?

	mdi->start_vol = (UI)de_getbyte_p(&pos);
	de_dbg(c, "cmpr data pos: %"I64_FMT", volume=%u",
		md->cmpr_pos, (UI)mdi->start_vol);

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

	if(mdi->is_split) {
		de_err(c, "%s: Fragmented files aren't supported",
			ucstring_getpsz_d(md->filename));
		goto done;
	}
	if(mdi->start_vol != d->volume_number) {
		de_err(c, "%s: File not on this volume",
			ucstring_getpsz_d(md->filename));
		goto done;
	}

	md->set_name_flags |= DE_SNFLAG_FULLPATH;
	if(mdi->attribs & 0x10) {
		md->dfn = noncompressed_decompressor_fn;
	}
	else {
		md->dfn = dclimplode_decompressor_fn;
	}
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
	de_arch_fixup_path(di->dname, 0x1);

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
	UI multivol_flag;
	UI volume_count = 0;
	i64 n;
	i64 pos;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct isz_ctx));
	d->da = de_arch_create_lctx(c);
	d->da->userdata = (void*)d;
	d->da->is_le = 1;

	d->da->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	// 0   13 5D 65 8C   = signature
	// 4   3A 01 02 00   = ?
	// 8... ?
	// 10  ui16  multivolume flag
	// 12  ui16  number of files
	// 14  ui16  date
	// 16  ui16  time
	// 18... ?
	// 18  ui32 ? approx sum of cmpr sizes or volume sizes
	// 22  ui32 sum of orig sizes
	// 30  u8    volume count (sometimes)
	// 31  u8    volume
	// 32... ?
	// 33  ui32  split begin addr (sometimes)
	// 37  ui32  split end addr
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

	pos = 10;
	multivol_flag = (UI)de_getu16le_p(&pos);
	de_dbg(c, "is multivolume: %u", multivol_flag);

	d->da->num_members = de_getu16le_p(&pos);
	de_dbg(c, "total number of files: %"I64_FMT, d->da->num_members);
	if(d->da->num_members>ISZ_MAX_FILES) goto done;

	pos = 14;
	de_arch_read_field_dttm_p(d->da, &tmp_timestamp, "archive",
		DE_ARCH_TSTYPE_DOS_DT, &pos);

	n = de_getu32le_p(&pos);
	de_dbg2(c, "archive cmpr size (approx total?): %"I64_FMT, n);
	n = de_getu32le_p(&pos);
	de_dbg(c, "archive orig size (sum total): %"I64_FMT, n);

	if(multivol_flag) {
		pos = 30;
		volume_count = (UI)de_getbyte_p(&pos);
		if(volume_count) {
			de_dbg(c, "num volumes: %u", (UI)volume_count);
		}
		d->volume_number = (UI)de_getbyte_p(&pos);
		de_dbg(c, "volume number: %u", (UI)d->volume_number);

		if(volume_count!=1 || d->volume_number>1) {
			d->is_multivol = 1;
		}
	}

	pos = 33;
	n = de_getu32le_p(&pos);
	// Not sure what all this field does.
	// = 255 (start of data segment) on vol 1 if no split file.
	// = 0 on last volume of a multivolume set.
	de_dbg(c, "offset of start of split file (cont'd to next vol), "
		"if applicable: %"I64_FMT, n);

	n = de_getu32le_p(&pos);
	de_dbg(c, "offset of end of split file (cont'd from prev vol): %"I64_FMT, n);

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
		if(d->da && !d->da->fatalerrflag) {
			de_dbg2(c, "total cmpr size: %"I64_FMT, d->tot_cmpr_size);
			de_dbg2(c, "total orig size: %"I64_FMT, d->tot_orig_size);
		}

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

	if(!de_arch_good_cmpr_data_pos(md)) {
		goto done;
	}

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

	md->next_member_pos = de_getu32le_p(&pos);
	de_dbg(c, "next member pos: %"I64_FMT, md->next_member_pos);
	if(md->next_member_pos && (md->next_member_pos>md->member_hdr_pos)  &&
		(md->next_member_pos<c->infile->len))
	{
		md->next_member_exists = 1;
	}

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
	struct de_arch_member_data *md = NULL;

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
	case 1: name = "without wildcard"; break;
	case 2: name = "with wildcard"; break;
		// 0: seems to identify an "old" version (but it might be a significantly
		// different format).
	default: name = "?";
	}
	de_dbg(c, "filename style: %u (%s)", (UI)b, name);
	if(b!=1 && b!=2) { d->need_errmsg = 1; goto done; }

	pos += 4; // ??
	de_dbg_indent(c, -1);

	i = 0;
	while(1) {
		if(d->fatalerrflag) goto done;
		if(de_getbyte(pos) != 0x12) { d->need_errmsg = 1; goto done; }

		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}

		md = de_arch_create_md(c, d);
		md->member_idx = i;
		md->member_hdr_pos = pos;

		tscomp_do_member(c, d, md);

		if(!md->next_member_exists) goto done;
		pos = md->next_member_pos;
		i++;
	}

done:
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported TSComp format");
	}
	de_arch_destroy_md(c, md);
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
// InstallShield SFX EXE
// **************************************************************************

struct ishieldsfxdata {
	u8 need_errmsg;
	i64 rsrc_pos;
	i64 rsrc_len;
	i64 data_pos;
	i64 data_endpos;
	i64 num_member_files;
};

static void is_sfx_acquire_filename(deark *c, struct ishieldsfxdata *d,
	i64 idx, i64 member_dpos, i64 member_dlen, de_finfo *fi)
{
	de_ucstring *fn = NULL;
	struct fmtutil_fmtid_ctx *idctx = NULL;

	idctx = de_malloc(c, sizeof(struct fmtutil_fmtid_ctx));
	idctx->inf = c->infile;
	idctx->inf_pos = member_dpos;
	idctx->inf_len = member_dlen;
	idctx->default_ext = "dat";
	idctx->mode = FMTUTIL_FMTIDMODE_ISH_SFX;
	fmtutil_fmtid(c, idctx);

	fn = ucstring_create(c);
	ucstring_printf(fn, DE_ENCODING_LATIN1, "ishield%03u.%s", (UI)idx, idctx->ext_sz);
	de_finfo_set_name_from_ucstring(c, fi, fn, 0);

	ucstring_destroy(fn);
	de_free(c, idctx);
}

static void is_sfx_main(deark *c, struct ishieldsfxdata *d)
{
	de_finfo *fi = NULL;
	i64 i;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "rsrc pos: %"I64_FMT", len=%"I64_FMT, d->rsrc_pos, d->rsrc_len);
	if(d->rsrc_len<16) goto done;
	de_dbg_indent(c, 1);
	d->data_pos = de_getu32le(d->rsrc_pos+8);
	de_dbg(c, "data seg pos: %"I64_FMT, d->data_pos);
	d->num_member_files = de_getu32le(d->rsrc_pos+12);
	de_dbg(c, "num members: %"I64_FMT, d->num_member_files);

	// Sometimes @+16 is file size (or more likely, the data segment end pos).
	// But not always.
	d->data_endpos = c->infile->len;
	if(d->data_endpos > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}
	de_dbg_indent(c, -1);

	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;
	pos = d->data_pos;

	for(i=0; i<d->num_member_files; i++) {
		i64 hdr1_dlen;
		i64 member_dlen;
		i64 member_dpos;

		de_dbg(c, "member %u at %"I64_FMT, (UI)i, pos);
		de_dbg_indent(c, 1);

		if(pos+12 > d->data_endpos) {
			d->need_errmsg = 1;
			goto done;
		}

		hdr1_dlen = de_getu32le_p(&pos);
		de_dbg(c, "hdr1 dlen: %"I64_FMT, hdr1_dlen);
		// If this is large, assume we've gone off the rails.
		// Have observed values from 9 to 77.
		if(hdr1_dlen > 1024) {
			d->need_errmsg = 1;
			goto done;
		}

		pos += hdr1_dlen;
		pos += 4; // unknown
		member_dlen = de_getu32le_p(&pos);
		member_dpos = pos;
		de_dbg(c, "member dpos: %"I64_FMT, member_dpos);
		de_dbg(c, "member dlen: %"I64_FMT, member_dlen);

		pos = member_dpos + member_dlen;
		if(pos > d->data_endpos) {
			d->need_errmsg = 1;
			goto done;
		}

		is_sfx_acquire_filename(c, d, i, member_dpos, member_dlen, fi);

		dbuf_create_file_from_slice(c->infile, member_dpos, member_dlen, NULL, fi, 0);
		de_dbg_indent(c, -1);
	}

done:
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_is_sfx(deark *c, de_module_params *mparams)
{
	struct ishieldsfxdata *d = NULL;

	d = de_malloc(c, sizeof(struct ishieldsfxdata));

	// This module isn't smart enough to decode NE format to find the
	// pointers it needs. It can only be used via the exe module.
	if(c->module_disposition!=DE_MODDISP_INTERNAL) {
		goto done;
	}

	d->rsrc_pos = (i64)mparams->in_params.uint1;
	d->rsrc_len = (i64)mparams->in_params.uint2;

	is_sfx_main(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Failed to extract InstallShield SFX data");
		}
		de_free(c, d);
	}
}

void de_module_is_sfx(deark *c, struct deark_module_info *mi)
{
	mi->id = "is_sfx";
	mi->desc = "InstallShield SFX EXE";
	mi->run_fn = de_run_is_sfx;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_INTERNALONLY;
}
