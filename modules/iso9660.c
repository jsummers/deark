// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ISO 9660 CD-ROM image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iso9660);

#define CODE_AA 0x4141U
#define CODE_BA 0x4241U
#define CODE_CE 0x4345U
#define CODE_ER 0x4552U
#define CODE_NM 0x4e4dU
#define CODE_PX 0x5058U
#define CODE_SP 0x5350U
#define CODE_ST 0x5354U
#define CODE_TF 0x5446U

struct dir_record {
	u8 file_flags;
	u8 is_dir;
	u8 is_thisdir;
	u8 is_parentdir;
	u8 is_root_dot; // The "." entry in the root dir
	u8 rr_is_executable;
	u8 rr_is_nonexecutable;
	i64 len_dir_rec;
	i64 len_ext_attr_rec;
	i64 data_len;
	i64 file_id_len;
	i64 extent_blk;
	de_ucstring *fname;
	de_ucstring *rr_name;
	struct de_timestamp recording_time;
	struct de_timestamp rr_modtime;
};

typedef struct localctx_struct {
	u8 file_structure_version;
	int rr_encoding;
	i64 secsize;
	struct dir_record *root_dr;
	struct de_strarray *curpath;
	struct de_inthashtable *dirs_seen;
	u8 uses_SUSP;
	u8 system_use_area_seen; // Have we seen any nonempty system-use areas?
	i64 SUSP_default_bytes_to_skip;
} lctx;

static i64 read_signed_byte(dbuf *f, i64 pos)
{
	u8 b;

	b = dbuf_getbyte(f, pos);
	if(b<=127) return (i64)b;
	return ((i64)b)-256;
}

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

static void handle_iso_string_p(deark *c, lctx *d, const char *name,
	i64 *ppos, i64 len, de_ucstring *tmpstr)
{
	read_iso_string(c, d, *ppos, len, tmpstr);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(tmpstr));
	*ppos += len;
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *field_name)
{
	char timestamp_buf[64];

	if(ts->is_valid) {
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "%s: %s", field_name, timestamp_buf);
	}
	else {
		de_dbg(c, "%s: (not set)", field_name);
	}
}

static i64 read_decimal_substr(dbuf *f, i64 pos, i64 len)
{
	char buf[24];

	if(len<1 || len>23) return 0;
	dbuf_read(f, (u8*)buf, pos, len);
	buf[len] = '\0';
	return de_atoi64(buf);
}

static void read_datetime17(deark *c, lctx *d, i64 pos, struct de_timestamp *ts)
{
	i64 yr, mo, da;
	i64 hr, mi, se, hs;
	i64 offs;

	de_zeromem(ts, sizeof(struct de_timestamp));
	yr = read_decimal_substr(c->infile, pos, 4);
	if(yr==0) return;
	mo = read_decimal_substr(c->infile, pos+4, 2);
	da = read_decimal_substr(c->infile, pos+6, 2);
	hr = read_decimal_substr(c->infile, pos+8, 2);
	mi = read_decimal_substr(c->infile, pos+10, 2);
	se = read_decimal_substr(c->infile, pos+12, 2);
	hs = read_decimal_substr(c->infile, pos+14, 2);
	offs = read_signed_byte(c->infile, pos+16);
	de_make_timestamp(ts, yr, mo, da, hr, mi, se);
	de_timestamp_set_subsec(ts, ((double)hs)/100.0);
	de_timestamp_cvt_to_utc(ts, -offs*60*15);
}

static void read_datetime7(deark *c, lctx *d, i64 pos, struct de_timestamp *ts)
{
	i64 yr, mo, da;
	i64 hr, mi, se;
	i64 offs;

	ts->is_valid = 0;

	yr = de_getbyte(pos);
	mo = de_getbyte(pos+1);
	if(mo==0) return;
	da = de_getbyte(pos+2);
	hr = de_getbyte(pos+3);
	mi = de_getbyte(pos+4);
	se = de_getbyte(pos+5);
	offs = read_signed_byte(c->infile, pos+6);

	de_make_timestamp(ts, 1900+yr, mo, da, hr, mi, se);
	de_timestamp_cvt_to_utc(ts, -offs*60*15);
}

static void free_dir_record(deark *c, struct dir_record *dr)
{
	if(!dr) return;
	ucstring_destroy(dr->fname);
	ucstring_destroy(dr->rr_name);
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

		if(fname->len>1) {
			if(fname->str[fname->len-1]=='.') {
				ucstring_truncate(fname, fname->len-1);
			}
		}
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

	if(ucstring_isnonempty(dr->rr_name)) {
		ucstring_append_ucstring(final_name, dr->rr_name);
		de_finfo_set_name_from_ucstring(c, fi, final_name, DE_SNFLAG_FULLPATH);
		fi->original_filename_flag = 1;
	}
	else if(ucstring_isnonempty(dr->fname)) {
		ucstring_append_ucstring(final_name, dr->fname);
		fixup_filename(c, d, final_name);
		de_finfo_set_name_from_ucstring(c, fi, final_name, DE_SNFLAG_FULLPATH);
		fi->original_filename_flag = 1;
	}

	if(dr->rr_modtime.is_valid) {
		fi->mod_time = dr->rr_modtime;
	}
	else if(dr->recording_time.is_valid) {
		// Apparently, the "recording time" (whatever that is) is
		// sometimes used as the mod time.
		fi->mod_time = dr->recording_time;
	}

	if(dr->rr_is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(dr->rr_is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	dbuf_create_file_from_slice(c->infile, dpos, dlen, NULL, fi, 0);

done:
	ucstring_destroy(final_name);
	de_finfo_destroy(c, fi);
}

static void do_SUSP_SP(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	if(!dr->is_root_dot) return;
	if(len<7) return;
	d->SUSP_default_bytes_to_skip = (i64)de_getbyte(pos1+6);
	de_dbg(c, "bytes skipped: %d", (int)d->SUSP_default_bytes_to_skip);
}

static void do_SUSP_CE(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len,
	i64 *ca_blk, i64 *ca_offs, i64 *ca_len)
{
	i64 pos = pos1 + 4;


	if(len<28) return;
	*ca_blk = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "loc. of continuation area: block #%u", (unsigned int)*ca_blk);
	*ca_offs = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "continuation area offset: %u bytes", (unsigned int)*ca_offs);
	*ca_len = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "continuation area len: %u bytes", (unsigned int)*ca_len);
}

static void do_SUSP_ER(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	i64 pos = pos1+4;
	i64 len_id, len_des, len_src;
	u8 ext_ver;
	de_ucstring *tmpstr = NULL;

	if(!dr->is_root_dot) goto done;
	if(len<8) goto done;
	len_id = (i64)de_getbyte_p(&pos);
	len_des = (i64)de_getbyte_p(&pos);
	len_src = (i64)de_getbyte_p(&pos);
	ext_ver = de_getbyte_p(&pos);
	de_dbg(c, "extension version: %u", (unsigned int)ext_ver);
	if(8+len_id+len_des+len_src > len) goto done;
	tmpstr = ucstring_create(c);
	handle_iso_string_p(c, d, "extension id", &pos, len_id, tmpstr);
	handle_iso_string_p(c, d, "extension descriptor", &pos, len_des, tmpstr);
	handle_iso_string_p(c, d, "extension source", &pos, len_src, tmpstr);

done:
	ucstring_destroy(tmpstr);
}

static void do_SUSP_rockridge_NM(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	u8 flags;

	flags = de_getbyte(pos1+4);
	de_dbg(c, "flags: 0x%02x", (unsigned int)flags);
	if(len<6) return;
	if(!dr->rr_name)
		dr->rr_name = ucstring_create(c);
	// It is intentional that this may append to a name in a previous NM item.
	dbuf_read_to_ucstring(c->infile, pos1+5, len-5, dr->rr_name, 0x0,
		d->rr_encoding);
	de_dbg(c, "Rock Ridge name: \"%s\"", ucstring_getpsz_d(dr->rr_name));
}

static void do_SUSP_rockridge_PX(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	i64 pos = pos1+4;
	u32 perms;

	if(len<36) return; // 36 in v1r1.10; 44 in v1.12
	perms = (u32)getu32bbo_p(c->infile, &pos);
	de_dbg(c, "perms: octal(%06o)", (unsigned int)perms);
	if((perms&0170000)==0) { // regular file
		if(perms&0111) {
			dr->rr_is_executable = 1;
		}
		else {
			dr->rr_is_nonexecutable = 1;
		}
	}
}

static void do_SUSP_rockridge_TF(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	i64 pos = pos1+4;
	unsigned int flags;
	unsigned int i;
	i64 bytes_per_field;
	static const char *names[7] = { "create", "mod", "access",
		"attrib-change", "backup", "expire", "effective" };

	if(len<5) return;
	flags = (unsigned int)de_getbyte_p(&pos);
	bytes_per_field = (flags&0x80) ? 17 : 7;

	for(i=0; i<=6; i++) {
		struct de_timestamp tmpts;
		char tmpsz[32];

		// Flag bits indicate which timestamps are present.
		if(flags & (1<<i)) {
			if(bytes_per_field==17) {
				read_datetime17(c, d, pos, &tmpts);
			}
			else {
				read_datetime7(c, d, pos, &tmpts);
			}
			de_snprintf(tmpsz, sizeof(tmpsz), "%s time", names[i]);
			dbg_timestamp(c, &tmpts, tmpsz);

			if(i==1 && tmpts.is_valid) { // Save the mod time
				dr->rr_modtime = tmpts;
			}
			pos += bytes_per_field;
		}
	}
}

static int is_SUSP_indicator(deark *c, i64 pos, i64 len)
{
	u8 buf[6];

	if(len<6) return 0;
	de_read(buf, pos, 6);
	if(buf[0]=='S' && buf[1]=='P' && buf[4]==0xbe && buf[5]==0xef) {
		return 1;
	}
	return 0;
}

// Decode a contiguous set of SUSP entries.
// Does not follow a "CE" continuation entry, but returns info about it.
static void do_dir_rec_SUSP_set(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len,
	i64 *ca_blk, i64 *ca_offs, i64 *ca_len)
{
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "SUSP data at %"I64_FMT", len=%d", pos1, (int)len);
	de_dbg_indent(c, 1);

	while(1) {
		struct de_fourcc sig4cc;
		i64 itempos;
		i64 itemlen, dlen;
		u8 itemver;

		itempos = pos;
		if(itempos+4 > pos1+len) break;
		dbuf_read_fourcc(c->infile, pos, &sig4cc, 2, 0x0);
		pos += 2;
		itemlen = (i64)de_getbyte_p(&pos);
		if(itemlen<4) break;
		dlen = itemlen-4;
		if(itempos+itemlen > pos1+len) break;
		itemver = de_getbyte_p(&pos);
		de_dbg(c, "entry '%s' at %"I64_FMT", len=%d, ver=%u, dlen=%d",
			sig4cc.id_dbgstr, itempos, (int)itemlen, (unsigned int)itemver, (int)dlen);

		de_dbg_indent(c, 1);
		switch(sig4cc.id) {
		case CODE_SP:
			do_SUSP_SP(c, d, dr, itempos, itemlen);
			break;
		case CODE_CE:
			do_SUSP_CE(c, d, dr, itempos, itemlen, ca_blk, ca_offs, ca_len);
			break;
		case CODE_ER:
			do_SUSP_ER(c, d, dr, itempos, itemlen);
			break;
		case CODE_ST:
			goto done;
		case CODE_NM:
			do_SUSP_rockridge_NM(c, d, dr, itempos, itemlen);
			break;
		case CODE_PX:
			do_SUSP_rockridge_PX(c, d, dr, itempos, itemlen);
			break;
		case CODE_TF:
			do_SUSP_rockridge_TF(c, d, dr, itempos, itemlen);
			break;
		default:
			if(c->debug_level>=2) {
				de_dbg_hexdump(c, c->infile, pos, itemlen-4, 256, NULL, 0x1);
			}
		}
		pos = itempos+itemlen;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_dir_rec_SUSP(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len1)
{
	i64 pos = pos1;
	i64 len = len1;

	while(1) {
		i64 ca_blk = 0;
		i64 ca_offs = 0;
		i64 ca_len = 0;

		do_dir_rec_SUSP_set(c, d, dr, pos, len, &ca_blk, &ca_offs, &ca_len);

		if(ca_blk==0) {
			break;
		}

		// Prepare to jump to a continuation area

		pos = ca_blk * d->secsize + ca_offs;

		// Prevent loops
		if(!de_inthashtable_add_item(c, d->dirs_seen, pos, NULL)) {
			break;
		}

		len = ca_len;
	}
}

static void do_directory(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level);

// Caller allocates dr
static int do_directory_record(deark *c, lctx *d, i64 pos1, struct dir_record *dr, int nesting_level)
{
	i64 n;
	i64 pos = pos1;
	i64 sys_use_len;
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

	read_datetime7(c, d, pos, &dr->recording_time);
	dbg_timestamp(c, &dr->recording_time, "recording time");
	pos += 7;

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
	if(nesting_level==0 && dr->is_thisdir) {
		dr->is_root_dot = 1;
	}
	pos += dr->file_id_len;

	if((dr->file_id_len%2)==0) pos++; // padding byte

	// System Use area
	sys_use_len = pos1+dr->len_dir_rec-pos;
	if(sys_use_len>0) {
		i64 non_SUSP_len = sys_use_len;
		i64 SUSP_len = 0;

		if(dr->is_root_dot) {
			if(is_SUSP_indicator(c, pos, sys_use_len)) {
				d->uses_SUSP = 1;
				non_SUSP_len = 0;
				SUSP_len = sys_use_len;
			}
		}
		else if(d->uses_SUSP) {
			non_SUSP_len = d->SUSP_default_bytes_to_skip;
			SUSP_len = sys_use_len - d->SUSP_default_bytes_to_skip;
		}

		if(!d->system_use_area_seen && !d->uses_SUSP && sys_use_len>=4) {
			u32 maybe_id;

			// This is the first system use area encountered, and
			// it's not a SUSP indicator.
			maybe_id = (u32)de_getu16be(pos);
			if(maybe_id==CODE_AA || maybe_id==CODE_BA) { // Apple ISO 9660 extensions
				de_dbg(c, "[Likely SUSP-like entry detected. Enabling SUSP.]");
				d->uses_SUSP = 1;
				non_SUSP_len = 0;
				SUSP_len = sys_use_len;
			}
		}

		d->system_use_area_seen = 1;

		if(non_SUSP_len>0) {
			de_dbg(c, "[%d bytes of system use data at %"I64_FMT"]",
				(int)non_SUSP_len, pos);
		}

		if(d->uses_SUSP && SUSP_len>0) {
			do_dir_rec_SUSP(c, d, dr, pos+non_SUSP_len, SUSP_len);
		}
	}

	if(dr->len_ext_attr_rec>0) {
		// TODO
		de_err(c, "Can't handle files with extended attribute records");
		goto done;
	}

	if(dr->is_dir && !dr->is_thisdir && !dr->is_parentdir) {
		if(ucstring_isnonempty(dr->rr_name)) {
			de_strarray_push(d->curpath, dr->rr_name);
		}
		else {
			de_strarray_push(d->curpath, dr->fname);
		}
		do_directory(c, d, dr->extent_blk * d->secsize, dr->data_len, nesting_level+1);
		de_strarray_pop(d->curpath);
	}
	else if(!dr->is_dir) {
		do_file(c, d, dr);
	}

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

static void do_primary_volume_descriptor(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1 + 8;
	i64 vol_space_size;
	i64 vol_set_size;
	i64 vol_seq_num;
	i64 block_size;
	i64 n;
	de_ucstring *tmpstr = NULL;
	struct de_timestamp tmpts;

	tmpstr = ucstring_create(c);
	handle_iso_string_p(c, d, "system id", &pos, 32, tmpstr);
	handle_iso_string_p(c, d, "volume id", &pos, 32, tmpstr);

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
	n = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "path table size: %"I64_FMT" bytes", n);

	n = de_getu32le_p(&pos);
	de_dbg(c, "loc. of type L path table: block #%u", (unsigned int)n);
	n = de_getu32le_p(&pos);
	de_dbg(c, "loc. of optional type L path table: block #%u", (unsigned int)n);
	n = de_getu32be_p(&pos);
	de_dbg(c, "loc. of type M path table: block #%u", (unsigned int)n);
	n = de_getu32be_p(&pos);
	de_dbg(c, "loc. of optional type M path table: block #%u", (unsigned int)n);

	de_dbg(c, "dir record for root dir");
	de_dbg_indent(c, 1);
	d->root_dr = de_malloc(c, sizeof(struct dir_record));
	// This is a copy of the main information in the root directory's
	// directory entry, basically for bootstrapping.
	// It should be effectively identical to the "." entry in the root
	// directory.
	do_directory_record(c, d, pos, d->root_dr, 0);

	de_dbg_indent(c, -1);
	pos += 34;

	handle_iso_string_p(c, d, "volume set id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, "publisher id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, "data preparer id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, "application id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, "copyright file id", &pos, 37, tmpstr);
	handle_iso_string_p(c, d, "abstract file id", &pos, 37, tmpstr);
	handle_iso_string_p(c, d, "bibliographic file id", &pos, 37, tmpstr);

	read_datetime17(c, d, pos, &tmpts);
	dbg_timestamp(c, &tmpts, "volume creation time");
	pos += 17;

	read_datetime17(c, d, pos, &tmpts);
	dbg_timestamp(c, &tmpts, "volume mod time");
	pos += 17;

	read_datetime17(c, d, pos, &tmpts);
	dbg_timestamp(c, &tmpts, "volume expiration time");
	pos += 17;

	read_datetime17(c, d, pos, &tmpts);
	dbg_timestamp(c, &tmpts, "volume effective time");
	pos += 17;

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

	if(c->input_encoding==DE_ENCODING_UNKNOWN) {
		d->rr_encoding = DE_ENCODING_UTF8;
	}
	else {
		d->rr_encoding = c->input_encoding;
	}
	d->secsize = 2048;

	cursec = 16;
	while(1) {
		if(!do_volume_descriptor(c, d, cursec)) break;
		cursec++;
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
}
