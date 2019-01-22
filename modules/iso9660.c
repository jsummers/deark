// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ISO 9660 CD-ROM image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iso9660);

struct dir_record {
	u8 file_flags;
	u8 is_dir;
	u8 is_thisdir;
	u8 is_parentdir;
	i64 len_dir_rec;
	i64 len_ext_attr_rec;
	i64 data_len;
	i64 file_id_len;
	i64 extent_blk;
	de_ucstring *fname;
};

typedef struct localctx_struct {
	u8 file_structure_version;
	i64 secsize;
	i64 path_table_size;
	i64 path_table_L_secnum;
	i64 path_table_M_secnum;
	struct dir_record *root_dr;
	struct de_strarray *curpath;
	struct de_inthashtable *dirs_seen;
} lctx;

static i64 getu16bbo_p(dbuf *f, i64 *ppos)
{
	i64 val;
	val = dbuf_getu16be(f, (*ppos)+2);
	*ppos += 4;
	return val;
}

static i64 getu32bbo_p(dbuf *f, i64 *ppos)
{
	i64 val;
	val = dbuf_getu32be(f, (*ppos)+4);
	*ppos += 8;
	return val;
}

static void read_iso_string(deark *c, lctx *d, i64 pos, i64 len, de_ucstring *s)
{
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, len, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
}

static void free_dir_record(deark *c, struct dir_record *dr)
{
	if(!dr) return;
	ucstring_destroy(dr->fname);
	de_free(c, dr);
}

static const char *get_vol_descr_type_name(u8 t)
{
	const char *name = NULL;
	switch(t) {
	case 0: name="boot record"; break;
	case 1: name="primary volume descriptor"; break;
	case 2: name="supplementary or enhanced volume descriptor"; break;
	case 3: name="volume partition descriptor"; break;
	case 255: name="volume descriptor set terminator"; break;
	}
	return name?name:"?";
}

static void fixup_filename(deark *c, lctx *d, de_ucstring *fname)
{
	if(fname->len<3) return;
	if(fname->str[fname->len-2]==';' &&
		fname->str[fname->len-1]=='1')
	{
		ucstring_truncate(fname, fname->len-2);
	}
}

// Handle (presumably extract) the contents of the file represented by the
// given dir_record.
static void do_file(deark *c, lctx *d, struct dir_record *dr)
{
	i64 dpos, dlen;
	de_finfo *fi = NULL;
	de_ucstring *final_name = NULL;

	if(dr->extent_blk<1) goto done;
	dpos = dr->extent_blk * d->secsize;
	dlen = dr->data_len;

	if(dpos+dlen > c->infile->len) goto done;

	fi = de_finfo_create(c);

	final_name = ucstring_create(c);
	de_strarray_make_path(d->curpath, final_name, 0);

	if(ucstring_isnonempty(dr->fname)) {
		ucstring_append_ucstring(final_name, dr->fname);
		fixup_filename(c, d, final_name);
		de_finfo_set_name_from_ucstring(c, fi, final_name);
		fi->original_filename_flag = 1;
	}

	dbuf_create_file_from_slice(c->infile, dpos, dlen, NULL, fi, 0);

done:
	ucstring_destroy(final_name);
	de_finfo_destroy(c, fi);
}

static void do_directory(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level);

// Caller allocates dr
static int do_directory_record(deark *c, lctx *d, i64 pos1, struct dir_record *dr, int nesting_level)
{
	i64 n;
	i64 pos = pos1;
	u8 b;
	de_ucstring *tmps = NULL;
	int retval = 0;

	dr->len_dir_rec = (i64)de_getbyte_p(&pos);
	de_dbg(c, "dir rec len: %u", (unsigned int)dr->len_dir_rec);
	if(dr->len_dir_rec<1) goto done;

	dr->len_ext_attr_rec = (i64)de_getbyte_p(&pos);
	de_dbg(c, "ext attrib rec len: %u", (unsigned int)dr->len_ext_attr_rec);

	dr->extent_blk = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "loc. of extent: block #%u", (unsigned int)dr->extent_blk);
	dr->data_len = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "data length: %u", (unsigned int)dr->data_len);
	pos += 7; // recording time

	dr->file_flags = de_getbyte_p(&pos);
	tmps = ucstring_create(c);
	if(dr->file_flags & 0x01) ucstring_append_flags_item(tmps, "hidden");
	if(dr->file_flags & 0x02) {
		ucstring_append_flags_item(tmps, "directory");
		dr->is_dir = 1;
	}
	if(dr->file_flags & 0x04) ucstring_append_flags_item(tmps, "associated file");
	if(dr->file_flags & 0x08) ucstring_append_flags_item(tmps, "record format");
	if(dr->file_flags & 0x10) ucstring_append_flags_item(tmps, "protected");
	if(dr->file_flags & 0x80) ucstring_append_flags_item(tmps, "multi-extent");
	de_dbg(c, "file flags: 0x%02x (%s)", (unsigned int)dr->file_flags,
		ucstring_getpsz_d(tmps));

	b = de_getbyte_p(&pos);
	de_dbg(c, "file unit size: %u", (unsigned int)b);
	b = de_getbyte_p(&pos);
	de_dbg(c, "interleave gap size: %u", (unsigned int)b);
	n = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume sequence number: %u", (unsigned int)n);
	dr->file_id_len = (i64)de_getbyte_p(&pos);

	dr->fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, dr->file_id_len, dr->fname, 0, DE_ENCODING_PRINTABLEASCII);
	de_dbg(c, "file id: \"%s\"", ucstring_getpsz_d(dr->fname));
	if(dr->is_dir && dr->file_id_len==1) {
		b = de_getbyte(pos);
		if(b==0x00) {
			dr->is_thisdir = 1;
		}
		else if(b==0x01) {
			dr->is_parentdir = 1;
		}
	}

	if(dr->is_dir && !dr->is_thisdir && !dr->is_parentdir) {
		de_strarray_push(d->curpath, dr->fname);
		do_directory(c, d, dr->extent_blk * d->secsize, dr->data_len, nesting_level+1);
		de_strarray_pop(d->curpath);
	}
	else if(!dr->is_dir) {
		do_file(c, d, dr);
	}

	pos += dr->file_id_len;
	retval = 1;

done:
	ucstring_destroy(tmps);
	return retval;
}

// A sequence of directory_records
static void do_directory(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level)
{
	struct dir_record *dr = NULL;
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos1<=0) goto done;

	de_dbg(c, "directory at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(!de_inthashtable_add_item(c, d->dirs_seen, pos1, NULL)) {
		de_warn(c, "Duplicate directory or loop detected (@%"I64_FMT")", pos1);
		goto done;
	}

	if(nesting_level>32) {
		de_err(c, "Maximum directory nesting level exceeded");
		goto done;
	}

	while(1) {
		int ret;

		if(pos >= pos1+len) break;

		de_dbg(c, "directory record at %"I64_FMT" (for directory@%"I64_FMT")", pos, pos1);
		dr = de_malloc(c, sizeof(struct dir_record));
		de_dbg_indent(c, 1);
		ret = do_directory_record(c, d, pos, dr, nesting_level);
		de_dbg_indent(c, -1);
		if(!ret) break;
		if(dr->len_dir_rec<1) break;

		pos += dr->len_dir_rec; // + ext_len??
		free_dir_record(c, dr);
		dr = NULL;
	}

done:
	if(dr) free_dir_record(c, dr);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_path_table_record(deark *c, lctx *d, i64 idx,
	i64 pos1, int is_le, i64 *bytes_consumed)
{
	i64 n;
	i64 dir_id_len;
	i64 pos = pos1;
	de_ucstring *s = NULL;

	de_dbg(c, "path table record #%"I64_FMT" at %"I64_FMT, idx, pos1);
	de_dbg_indent(c, 1);

	dir_id_len = (i64)de_getbyte_p(&pos);

	pos += 1; // extended attribute record len (TODO)

	n = dbuf_getu32x(c->infile, pos, is_le);
	pos += 4;
	de_dbg(c, "location of extent: block #%u", (unsigned int)n);

	n = dbuf_getu16x(c->infile, pos, is_le);
	pos += 2;
	de_dbg(c, "parent dir number: %u", (unsigned int)n);

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, dir_id_len, s, 0, DE_ENCODING_PRINTABLEASCII);
	de_dbg(c, "dir id: \"%s\"", ucstring_getpsz_d(s));
	pos += dir_id_len;

	if(dir_id_len%2) pos++; // padding

	*bytes_consumed = pos - pos1;

	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}

static void do_path_table(deark *c, lctx *d, i64 pos1, int is_le)
{
	i64 pos = pos1;
	i64 idx = 1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "path table at %"I64_FMT, pos1);
	if(d->file_structure_version!=1) {
		de_err(c, "Unsupported file structure version");
		goto done;
	}
	de_dbg_indent(c, 1);

	while(1) {
		i64 recsize = 0;
		if(pos >= pos1+d->path_table_size) break;
		do_path_table_record(c, d, idx, pos, is_le, &recsize);
		if(recsize<1) break;
		pos += recsize;
		idx++;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_primary_volume_descriptor(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1 + 8;
	i64 vol_space_size;
	i64 vol_set_size;
	i64 vol_seq_num;
	i64 block_size;
	i64 n;
	de_ucstring *tmpstr = NULL;

	tmpstr = ucstring_create(c);
	read_iso_string(c, d, pos, 32, tmpstr);
	de_dbg(c, "system id: \"%s\"", ucstring_getpsz(tmpstr));
	pos += 32;

	read_iso_string(c, d, pos, 32, tmpstr);
	de_dbg(c, "volume id: \"%s\"", ucstring_getpsz(tmpstr));
	pos += 32;

	pos += 8; // 73-80 unused

	vol_space_size = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "volume space size: %"I64_FMT" blocks", vol_space_size);

	pos += 32; // 89-120 unused

	vol_set_size = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume set size: %u", (unsigned int)vol_set_size);
	vol_seq_num = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume sequence number: %u", (unsigned int)vol_seq_num);
	block_size = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "block size: %u bytes", (unsigned int)block_size);
	d->path_table_size = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "path table size: %"I64_FMT" bytes", d->path_table_size);

	d->path_table_L_secnum = de_getu32le_p(&pos);
	de_dbg(c, "loc. of type L path table: block #%u", (unsigned int)d->path_table_L_secnum);
	n = de_getu32le_p(&pos);
	de_dbg(c, "loc. of optional type L path table: block #%u", (unsigned int)n);
	d->path_table_M_secnum = de_getu32be_p(&pos);
	de_dbg(c, "loc. of type M path table: block #%u", (unsigned int)d->path_table_M_secnum);
	n = de_getu32be_p(&pos);
	de_dbg(c, "loc. of optional type M path table: block #%u", (unsigned int)n);

	de_dbg(c, "dir record for root dir");
	de_dbg_indent(c, 1);
	d->root_dr = de_malloc(c, sizeof(struct dir_record));
	do_directory_record(c, d, pos, d->root_dr, 0);

	de_dbg_indent(c, -1);
	pos += 34;

	read_iso_string(c, d, pos, 128, tmpstr);
	de_dbg(c, "volume set id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 128;

	read_iso_string(c, d, pos, 128, tmpstr);
	de_dbg(c, "publisher id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 128;

	read_iso_string(c, d, pos, 128, tmpstr);
	de_dbg(c, "data preparer id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 128;

	read_iso_string(c, d, pos, 128, tmpstr);
	de_dbg(c, "application id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 128;

	read_iso_string(c, d, pos, 37, tmpstr);
	de_dbg(c, "copyright file id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 37;

	read_iso_string(c, d, pos, 37, tmpstr);
	de_dbg(c, "abstract file id id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 37;

	read_iso_string(c, d, pos, 37, tmpstr);
	de_dbg(c, "bibliographic file id: \"%s\"", ucstring_getpsz_d(tmpstr));
	pos += 37;

	pos += 17; // volume creation time (TODO)
	pos += 17; // volume mod time
	pos += 17; // volume expiration time
	pos += 17; // volume effective time

	d->file_structure_version = de_getbyte_p(&pos);
	de_dbg(c, "file structure version: %u", (unsigned int)d->file_structure_version);

	ucstring_destroy(tmpstr);
}

// Returns 0 if this is a terminator, or on serious error.
// Returns 1 normally.
static int do_volume_descriptor(deark *c, lctx *d, i64 secnum)
{
	u8 dtype;
	u8 dvers;
	int saved_indent_level;
	i64 pos1 = secnum*d->secsize;
	i64 pos = pos1;
	const char *vdtname;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "volume descriptor at %"I64_FMT" (sector %d)", pos, (int)secnum);
	de_dbg_indent(c, 1);

	dtype = de_getbyte_p(&pos);
	if(dbuf_memcmp(c->infile, pos, "CD001", 5)) {
		de_err(c, "Sector %d is not a volume descriptor", (int)secnum);
		goto done;
	}
	pos += 5;

	vdtname = get_vol_descr_type_name(dtype);
	de_dbg(c, "volume descriptor type: %u (%s)", (unsigned int)dtype, vdtname);
	if(dtype!=255) {
		retval = 1;
	}

	dvers = de_getbyte_p(&pos);
	de_dbg(c, "volume descriptor version: %u", (unsigned int)dvers);

	switch(dtype) {
	case 1:
		do_primary_volume_descriptor(c, d, pos1);
		break;
	case 255:
		break;
	default:
		de_warn(c, "Unsupported volume descriptor type: %u (%s)",
			(unsigned int)dtype, vdtname);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_iso9660(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 cursec;

	d = de_malloc(c, sizeof(lctx));

	d->secsize = 2048;

	cursec = 16;
	while(1) {
		if(!do_volume_descriptor(c, d, cursec)) break;
		cursec++;
	}

	if(de_get_ext_option_bool(c, "iso9660:readpathtable", 0)) {
		if(d->path_table_L_secnum) {
			do_path_table(c, d, d->secsize * d->path_table_L_secnum, 1);
		}
		else if(d->path_table_M_secnum) {
			do_path_table(c, d, d->secsize * d->path_table_M_secnum, 0);
		}
	}

	d->dirs_seen = de_inthashtable_create(c);
	d->curpath = de_strarray_create(c);

	if(d->root_dr) {
		do_directory(c, d, d->secsize * d->root_dr->extent_blk, d->root_dr->data_len, 0);
	}

	if(d) {
		free_dir_record(c, d->root_dr);
		de_strarray_destroy(d->curpath);
		de_inthashtable_destroy(c, d->dirs_seen);
		de_free(c, d);
	}
}

static int de_identify_iso9660(deark *c)
{
	u8 buf[6];
	dbuf_read(c->infile, buf, 32768, sizeof(buf));
	if(de_memcmp(&buf[1], "CD001", 5)) return 0;
	if(buf[0]>3 && buf[0]<255) return 0;
	return 25;
}

void de_module_iso9660(deark *c, struct deark_module_info *mi)
{
	mi->id = "iso9660";
	mi->desc = "ISO 9660 (CD-ROM) image";
	mi->run_fn = de_run_iso9660;
	mi->identify_fn = de_identify_iso9660;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
