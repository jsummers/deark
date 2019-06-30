// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ISO 9660 CD-ROM image
// NRG CD-ROM image

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_iso9660);
DE_DECLARE_MODULE(de_module_cd_raw);
DE_DECLARE_MODULE(de_module_nrg);

#define CODE_AA 0x4141U
#define CODE_CE 0x4345U
#define CODE_ER 0x4552U
#define CODE_NM 0x4e4dU
#define CODE_PX 0x5058U
#define CODE_SF 0x5346U
#define CODE_SP 0x5350U
#define CODE_ST 0x5354U
#define CODE_TF 0x5446U
#define CODE_ZF 0x5a46U

struct dir_record {
	u8 file_flags;
	u8 is_dir;
	u8 is_thisdir;
	u8 is_parentdir;
	u8 is_root_dot; // The "." entry in the root dir
	u8 rr_is_executable;
	u8 rr_is_nonexecutable;
	u8 is_symlink;
	u8 is_specialfiletype;
	u8 is_specialfileformat;
	u8 has_archimedes_ext;
	i64 len_dir_rec;
	i64 len_ext_attr_rec;
	i64 data_len;
	i64 file_id_len;
	i64 extent_blk;
	de_ucstring *fname;
	de_ucstring *rr_name;
	struct de_timestamp recording_time;
	struct de_timestamp rr_modtime;
	struct de_timestamp riscos_timestamp;
	u32 archimedes_attribs;
};

struct vol_record {
	i64 secnum;
	i64 root_dir_extent_blk;
	i64 root_dir_data_len;
	i64 block_size;
	de_encoding encoding; // Char encoding associated with this volume descriptor
	u8 file_structure_version;
	u8 is_joliet;
	u8 is_cdxa;
	u8 quality;
};

typedef struct localctx_struct {
	int rr_encoding;
	u8 names_to_lowercase;
	u8 vol_desc_sector_forced;
	u8 dirsize_hack;
	i64 vol_desc_sector_to_use;
	i64 secsize;
	i64 primary_vol_desc_count;
	i64 suppl_vol_desc_count;
	struct de_strarray *curpath;
	struct de_inthashtable *dirs_seen;
	struct de_inthashtable *voldesc_crc_hash;
	u8 uses_SUSP;
	u8 is_udf;
	i64 SUSP_default_bytes_to_skip;
	struct vol_record *vol; // Volume descriptor to use
	struct de_crcobj *crco;
} lctx;

static i64 sector_dpos(lctx *d, i64 secnum)
{
	return secnum * d->secsize;
}

static i64 getu16bbo_p(dbuf *f, i64 *ppos)
{
	i64 val;
	val = dbuf_getu16be(f, (*ppos)+2);
	*ppos += 4;
	return val;
}

static i64 getu32bbo(dbuf *f, i64 pos)
{
	return dbuf_getu32be(f, pos+4);
}

static i64 getu32bbo_p(dbuf *f, i64 *ppos)
{
	i64 val;
	val = getu32bbo(f, *ppos);
	*ppos += 8;
	return val;
}

// If vol is not NULL, use its encoding. Else ASCII.
static void read_iso_string(deark *c, lctx *d, struct vol_record *vol,
	i64 pos, i64 len, de_ucstring *s)
{
	de_encoding encoding;

	ucstring_empty(s);
	encoding = vol ? vol->encoding : DE_ENCODING_ASCII;
	if(encoding==DE_ENCODING_UTF16BE) {
		if(len%2) {
			len--;
		}
	}
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	ucstring_truncate_at_NUL(s);
	ucstring_strip_trailing_spaces(s);
}

static void handle_iso_string_p(deark *c, lctx *d, struct vol_record *vol,
	const char *name, i64 *ppos, i64 len, de_ucstring *tmpstr)
{
	read_iso_string(c, d, vol, *ppos, len, tmpstr);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(tmpstr));
	*ppos += len;
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *field_name)
{
	char timestamp_buf[64];

	if(ts->is_valid) {
		de_dbg_timestamp_to_string(c, ts, timestamp_buf, sizeof(timestamp_buf), 0);
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
	offs = dbuf_geti8(c->infile, pos+16);
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
	offs = dbuf_geti8(c->infile, pos+6);

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

enum voldesctype_enum {
	VOLDESCTYPE_UNKNOWN,
	VOLDESCTYPE_OTHERVALID,
	VOLDESCTYPE_CD_PRIMARY,
	VOLDESCTYPE_CD_SUPPL,
	VOLDESCTYPE_CD_BOOT,
	VOLDESCTYPE_CD_PARTDESCR,
	VOLDESCTYPE_CD_TERM,
	VOLDESCTYPE_BEA,
	VOLDESCTYPE_TEA,
	VOLDESCTYPE_NSR
};

static const char *get_vol_descr_type_name(enum voldesctype_enum vdt)
{
	const char *name = NULL;
	switch(vdt) {
	case VOLDESCTYPE_CD_BOOT: name="boot record"; break;
	case VOLDESCTYPE_CD_PRIMARY: name="primary volume descriptor"; break;
	case VOLDESCTYPE_CD_SUPPL: name="supplementary or enhanced volume descriptor"; break;
	case VOLDESCTYPE_CD_PARTDESCR: name="volume partition descriptor"; break;
	case VOLDESCTYPE_CD_TERM: name="volume descriptor set terminator"; break;
	case VOLDESCTYPE_BEA: name="beginning of extended descriptors"; break;
	case VOLDESCTYPE_TEA: name="end of extended descriptors"; break;
	case VOLDESCTYPE_NSR: name="UDF indicator"; break;
	case VOLDESCTYPE_OTHERVALID: name="(other/valid)"; break;
	case VOLDESCTYPE_UNKNOWN: break;
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
static void do_extract_file(deark *c, lctx *d, struct dir_record *dr)
{
	i64 dpos, dlen;
	de_finfo *fi = NULL;
	de_ucstring *final_name = NULL;

	if(dr->extent_blk<1) goto done;
	dpos = sector_dpos(d, dr->extent_blk);
	if(dr->is_dir) {
		dlen = 0;
	}
	else {
		dlen = dr->data_len;
	}

	fi = de_finfo_create(c);

	final_name = ucstring_create(c);

	if(!dr->is_root_dot) {
		de_strarray_make_path(d->curpath, final_name, 0);
	}

	if(dr->is_root_dot) {
		fi->is_root_dir = 1;
	}
	else if(ucstring_isnonempty(dr->rr_name)) {
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

	if(dr->riscos_timestamp.is_valid) {
		fi->mod_time = dr->riscos_timestamp;
	}
	else if(dr->rr_modtime.is_valid) {
		fi->mod_time = dr->rr_modtime;
	}
	else if(dr->recording_time.is_valid) {
		// Apparently, the "recording time" (whatever that is) is
		// sometimes used as the mod time.
		fi->mod_time = dr->recording_time;
	}

	if(dr->is_dir) {
		fi->is_directory = 1;
	}
	else if(dr->rr_is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(dr->rr_is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	if(dpos+dlen > c->infile->len) {
		de_err(c, "%s goes beyond end of file", ucstring_getpsz(final_name));
		goto done;
	}

	if(dr->is_specialfileformat) {
		de_warn(c, "%s has an advanced file structure, and might not be "
			"extracted correctly.", ucstring_getpsz(final_name));
	}
	else if(dr->is_symlink) {
		de_warn(c, "%s is a symlink. It will not be extracted as such.",
			ucstring_getpsz(final_name));
	}
	else if(dr->is_specialfiletype) { // E.g. FIFO, device, ...
		de_warn(c, "%s is a special file. It will not be extracted as such.",
			ucstring_getpsz(final_name));
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
	handle_iso_string_p(c, d, NULL, "extension id", &pos, len_id, tmpstr);
	handle_iso_string_p(c, d, NULL, "extension descriptor", &pos, len_des, tmpstr);
	handle_iso_string_p(c, d, NULL, "extension source", &pos, len_src, tmpstr);

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
	// It is intentional that this may append to a name that started in a previous
	// NM item.
	dbuf_read_to_ucstring(c->infile, pos1+5, len-5, dr->rr_name, 0x0,
		d->rr_encoding);
	de_dbg(c, "Rock Ridge name: \"%s\"", ucstring_getpsz_d(dr->rr_name));
}

static void do_SUSP_rockridge_PX(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	i64 pos = pos1+4;
	u32 perms;
	u32 ftype;

	if(len<36) return; // 36 in v1r1.10; 44 in v1.12
	perms = (u32)getu32bbo_p(c->infile, &pos);
	de_dbg(c, "perms: octal(%06o)", (unsigned int)perms);
	ftype = (perms&0170000);
	if(ftype==0100000 || ftype==0) { // regular file
		if(perms&0111) {
			dr->rr_is_executable = 1;
		}
		else {
			dr->rr_is_nonexecutable = 1;
		}
	}
	else if(ftype==040000U) { // directory
		;
	}
	else if(ftype==0120000U) {
		dr->is_symlink = 1;
	}
	else {
		dr->is_specialfiletype = 1;
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

static void do_SUSP_ZF(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	struct de_fourcc cmprtype;
	i64 n;
	i64 pos = pos1+4;

	dr->is_specialfileformat = 1;
	if(len<16) goto done;

	dbuf_read_fourcc(c->infile, pos, &cmprtype, 2, 0x0);
	de_dbg(c, "cmpr algorithm: '%s'", cmprtype.id_dbgstr);
	pos += 2;

	n = (i64)de_getbyte_p(&pos);
	de_dbg(c, "header size: %u (%u bytes)", (unsigned int)n,
		(unsigned int)(n*4));

	n = (i64)de_getbyte_p(&pos);
	de_dbg(c, "block size: 2^%u (%u bytes)", (unsigned int)n,
		(unsigned int)(1U<<(unsigned int)n));

	n = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "uncmpr. size: %"I64_FMT" bytes", n);

done:
	;
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

static void do_Apple_AA_HFS(deark *c, lctx *d, struct dir_record *dr, i64 pos1, i64 len)
{
	unsigned int finder_flags;
	struct de_fourcc type4cc;
	struct de_fourcc creator4cc;
	i64 pos = pos1+4;

	de_dbg(c, "Apple AA/HFS extension at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	dbuf_read_fourcc(c->infile, pos, &type4cc, 4, 0x0);
	de_dbg(c, "type: '%s'", type4cc.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator4cc, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator4cc.id_dbgstr);
	pos += 4;
	finder_flags = (unsigned int)de_getu16be_p(&pos);
	de_dbg(c, "finder flags: 0x%04x", finder_flags);
	de_dbg_indent(c, -1);
}

static void do_ARCHIMEDES(deark *c, lctx *d, struct dir_record *dr, i64 pos1, i64 len)
{
	i64 pos = pos1;
	u32 ld, ex;

	de_dbg(c, "ARCHIMEDES extension at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(len<10+12) goto done;
	dr->has_archimedes_ext = 1;
	pos += 10; // signature
	ld = (u32)de_getu32le_p(&pos);
	ex = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)ld,
		(unsigned int)ex);

	if((ld&0xfff00000U)==0xfff00000U) {
		unsigned int file_type;
		char timestamp_buf[64];

		de_dbg_indent(c, 1);
		file_type = (unsigned int)((ld&0xfff00)>>8);
		de_dbg(c, "file type: %03X", file_type);

		de_riscos_loadexec_to_timestamp(ld, ex, &dr->riscos_timestamp);
		de_timestamp_to_string(&dr->riscos_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "timestamp: %s", timestamp_buf);
		de_dbg_indent(c, -1);
	}

	dr->archimedes_attribs = (u32)de_getu32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)dr->archimedes_attribs);

done:
	de_dbg_indent(c, -1);
}

static void do_CDXA_dirdata(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1)
{
	unsigned int attribs;

	de_dbg(c, "CD-ROM XA data at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	attribs = (unsigned int)de_getu16be(pos1+4);
	de_dbg(c, "attribs: 0x%04x", attribs);
	de_dbg_indent(c, -1);
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
		case CODE_SF:
			dr->is_specialfileformat = 1; // Sparse file
			break;
		case CODE_ZF: // zisofs
			do_SUSP_ZF(c, d, dr, itempos, itemlen);
			break;
		default:
			if(sig4cc.id==CODE_AA && itemlen==14 && itemver==2) {
				// Apple AA extensions are not SUSP, but I've seen them used
				// as SUSP anyway. They're sufficiently compatible.
				do_Apple_AA_HFS(c, d, dr, itempos, itemlen);
			}
			else if(c->debug_level>=2) {
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

		pos = sector_dpos(d, ca_blk) + ca_offs;

		// Prevent loops
		if(!de_inthashtable_add_item(c, d->dirs_seen, pos, NULL)) {
			break;
		}

		len = ca_len;
	}
}

static void do_dir_rec_system_use_area(deark *c, lctx *d, struct dir_record *dr,
	i64 pos1, i64 len)
{
	i64 pos = pos1;
	int non_SUSP_handled = 0;
	i64 non_SUSP_len = len; // default
	i64 SUSP_len = 0; // default

	de_dbg(c, "[%"I64_FMT" bytes of system use data at %"I64_FMT"]", len, pos1);

	if(dr->is_root_dot) {
		if(is_SUSP_indicator(c, pos, len)) {
			d->uses_SUSP = 1;
			non_SUSP_len = 0;
			SUSP_len = len;
		}
	}
	else if(d->uses_SUSP) {
		non_SUSP_len = d->SUSP_default_bytes_to_skip;
		SUSP_len = len - d->SUSP_default_bytes_to_skip;
	}

	if(non_SUSP_len>0) {
		u8 buf[10];

		// TODO: Detect & handle more non-SUSP formats here.
		// - Apple AA/ProDOS
		// - Apple BA

		de_zeromem(buf, sizeof(buf));
		de_read(buf, pos, de_min_int(sizeof(buf), non_SUSP_len));

		if(d->vol->is_cdxa && non_SUSP_len>=14 && buf[6]=='X' && buf[7]=='A') {
			do_CDXA_dirdata(c, d, dr, pos);
			non_SUSP_handled = 1;
		}
		else if(non_SUSP_len>=14 && buf[0]=='A' && buf[1]=='A' && buf[2]==0x0e &&
			buf[3]==0x02)
		{
			// TODO: Support XA + AA
			do_Apple_AA_HFS(c, d, dr, pos, non_SUSP_len);
			non_SUSP_handled = 1;
		}
		else if(non_SUSP_len>=10 && !de_memcmp(buf, "ARCHIMEDES", 10)) {
			do_ARCHIMEDES(c, d, dr, pos, non_SUSP_len);
			non_SUSP_handled = 1;
		}
	}

	if(non_SUSP_len>0 && !non_SUSP_handled) {
		de_dbg(c, "[unidentified system use data]");
		if(c->debug_level>=2) {
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, pos, non_SUSP_len, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
		}
	}

	if(d->uses_SUSP && SUSP_len>0) {
		do_dir_rec_SUSP(c, d, dr, pos+non_SUSP_len, SUSP_len);
	}
	// TODO?: There can potentially also be non-SUSP data *after* the SUSP data,
	// but I don't know if we need to worry about that.
}

static void name_to_lowercase(de_ucstring *s)
{
	i64 i;

	if(!s) return;
	for(i=0; i<s->len; i++) {
		if(s->str[i]>='A' && s->str[i]<='Z') {
			s->str[i] += 32;
		}
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
	u8 specialfnbyte;
	de_ucstring *tmps = NULL;
	int retval = 0;
	int file_id_encoding;

	dr->len_dir_rec = (i64)de_getbyte_p(&pos);
	de_dbg(c, "dir rec len: %u", (unsigned int)dr->len_dir_rec);
	if(dr->len_dir_rec<1) goto done;

	dr->len_ext_attr_rec = (i64)de_getbyte_p(&pos);
	de_dbg(c, "ext attrib rec len: %u", (unsigned int)dr->len_ext_attr_rec);

	dr->extent_blk = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "loc. of extent: %"I64_FMT" (block #%u)", sector_dpos(d, dr->extent_blk),
		(unsigned int)dr->extent_blk);
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
	if(dr->file_flags & 0x04) {
		ucstring_append_flags_item(tmps, "associated file");
	}
	if(dr->file_flags & 0x08) {
		ucstring_append_flags_item(tmps, "record format");
		dr->is_specialfileformat = 1;
	}
	if(dr->file_flags & 0x10) ucstring_append_flags_item(tmps, "protected");
	if(dr->file_flags & 0x80) {
		ucstring_append_flags_item(tmps, "multi-extent");
		dr->is_specialfileformat = 1;
	}
	de_dbg(c, "file flags: 0x%02x (%s)", (unsigned int)dr->file_flags,
		ucstring_getpsz_d(tmps));

	b = de_getbyte_p(&pos);
	de_dbg(c, "file unit size: %u", (unsigned int)b);

	b = de_getbyte_p(&pos);
	de_dbg(c, "interleave gap size: %u", (unsigned int)b);
	if(b!=0) {
		dr->is_specialfileformat = 1;
	}

	n = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume sequence number: %u", (unsigned int)n);
	dr->file_id_len = (i64)de_getbyte_p(&pos);

	if(dr->is_dir && dr->file_id_len==1) {
		// Peek at the first (& only) byte of the filename.
		specialfnbyte = de_getbyte(pos);
	}
	else {
		specialfnbyte = 0xff;
	}

	if(specialfnbyte==0x00 || specialfnbyte==0x01) {
		// To better display the "thisdir" and "parentdir" directory entries
		file_id_encoding = DE_ENCODING_PRINTABLEASCII;
	}
	else {
		file_id_encoding = d->vol->encoding;
	}

	dr->fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, dr->file_id_len, dr->fname, 0, file_id_encoding);
	de_dbg(c, "file id: \"%s\"", ucstring_getpsz_d(dr->fname));

	if(d->names_to_lowercase && !d->vol->is_joliet) {
		name_to_lowercase(dr->fname);
	}

	if(specialfnbyte==0x00) {
		dr->is_thisdir = 1;
		if(nesting_level==0) {
			dr->is_root_dot = 1;
		}
	}
	else if(specialfnbyte==0x01) {
		dr->is_parentdir = 1;
	}
	pos += dr->file_id_len;

	if((dr->file_id_len%2)==0) pos++; // padding byte

	// System Use area
	sys_use_len = pos1+dr->len_dir_rec-pos;
	if(sys_use_len>0) {
		do_dir_rec_system_use_area(c, d, dr, pos, sys_use_len);
	}

	if(dr->has_archimedes_ext && (dr->archimedes_attribs&0x100)) {
		// Based on what Linux does, and other evidence: If a certain attribute bit
		// is set, the filename is supposed to start with an exclamation point.
		if(ucstring_isnonempty(dr->fname)) {
			if(dr->fname->str[0]=='_') {
				dr->fname->str[0] = '!';
			}
		}
	}

	if(dr->len_ext_attr_rec>0) {
		// TODO
		de_err(c, "Can't handle files with extended attribute records");
		goto done;
	}

	if(dr->is_dir && !dr->is_thisdir && !dr->is_parentdir) {
		do_extract_file(c, d, dr);
		if(ucstring_isnonempty(dr->rr_name)) {
			de_strarray_push(d->curpath, dr->rr_name);
		}
		else {
			de_strarray_push(d->curpath, dr->fname);
		}
		do_directory(c, d, sector_dpos(d, dr->extent_blk), dr->data_len, nesting_level+1);
		de_strarray_pop(d->curpath);
	}
	else if(!dr->is_dir) {
		do_extract_file(c, d, dr);
	}
	else if(dr->is_root_dot) {
		do_extract_file(c, d, dr);
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
	int idx = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos1<=0) goto done;

	if(d->dirsize_hack) {
		// I have a volume for which the high bits of the dir-length fields
		// are corrupted.
		len &= 0x00ffffffLL;
	}

	de_dbg(c, "directory at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);

	if(!de_inthashtable_add_item(c, d->dirs_seen, pos1, NULL)) {
		de_warn(c, "Duplicate directory or loop detected (@%"I64_FMT")", pos1);
		goto done;
	}

	if(nesting_level>32) {
		de_err(c, "Maximum directory nesting level exceeded");
		goto done;
	}

	if(pos1+len > c->infile->len) {
		de_warn(c, "Directory at %"I64_FMT" goes beyond end of file (size=%"I64_FMT")",
			pos1, len);
	}

	while(1) {
		int ret;

		if(pos >= pos1+len) break;
		if(pos >= c->infile->len) break;

		// Peek at the first byte of the dir record (the length)
		if(pos%d->secsize != 0) {
			if(de_getbyte(pos)==0) {
				// No more dir records in this sector; advance to the next sector
				pos = de_pad_to_n(pos, d->secsize);
			}

			if(pos >= pos1+len) break;
			if(pos >= c->infile->len) break;
		}

		de_dbg(c, "file/dir record at %"I64_FMT" (item[%d] in dir@%"I64_FMT")", pos,
			idx, pos1);
		dr = de_malloc(c, sizeof(struct dir_record));
		de_dbg_indent(c, 1);
		ret = do_directory_record(c, d, pos, dr, nesting_level);
		de_dbg_indent(c, -1);
		if(!ret) break;
		if(dr->len_dir_rec<1) break;

		pos += dr->len_dir_rec; // + ext_len??
		free_dir_record(c, dr);
		dr = NULL;
		idx++;
	}

done:
	if(dr) free_dir_record(c, dr);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_boot_volume_descr(deark *c, lctx *d, i64 pos1)
{
	de_ucstring *tmpstr = NULL;
	struct de_stringreaderdata *boot_sys_id = NULL;
	i64 pos = pos1 + 7;
	i64 n;

	tmpstr = ucstring_create(c);
	boot_sys_id = dbuf_read_string(c->infile, pos, 32, 32, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	pos += 32;
	de_dbg(c, "boot system id: \"%s\"", ucstring_getpsz(boot_sys_id->str));

	handle_iso_string_p(c, d, NULL, "boot id", &pos, 32, tmpstr);

	if(!de_strcmp(boot_sys_id->sz, "EL TORITO SPECIFICATION")) {
		n = de_getu32le_p(&pos);
		de_dbg(c, "first sector of boot catalog: %u", (unsigned int)n);
	}

	ucstring_destroy(tmpstr);
	de_destroy_stringreaderdata(c, boot_sys_id);
}

static void read_escape_sequences(deark *c, lctx *d, struct vol_record *vol, i64 pos)
{
	u8 es[8];

	de_dbg(c, "escape sequences:");
	de_dbg_indent(c, 1);
	de_dbg_hexdump(c, c->infile, pos, 32, 32, NULL, 0);
	de_read(es, pos, sizeof(es));

	// 40, 43, 45 are for UCS-2.
	// 4a-4c are for UTF-16, probably not used by Joliet since it predates UTF-16,
	// but it shouldn't hurt to allow it.
	if(es[0]==0x25 && es[1]==0x2f && (es[2]==0x40 || es[2]==0x43 || es[2]==0x45 ||
		es[2]==0x4a || es[2]==0x4b || es[3]==0x4c))
	{
		vol->is_joliet = 1;
		vol->encoding = DE_ENCODING_UTF16BE;
	}
	de_dbg(c, "is joliet: %u", (unsigned int)vol->is_joliet);
	de_dbg_indent(c, -1);
}

static void do_primary_or_suppl_volume_descr_internal(deark *c, lctx *d,
	struct vol_record *vol, i64 secnum, i64 pos1, int is_primary)
{
	i64 pos = pos1 + 7;
	i64 vol_space_size;
	i64 vol_set_size;
	i64 vol_seq_num;
	i64 n;
	unsigned int vol_flags;
	u32 crc;
	int is_dup;
	de_ucstring *tmpstr = NULL;
	struct de_timestamp tmpts;

	// Check whether this is a copy of a previous descriptor
	if(!d->crco) {
		d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	}
	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, pos1, d->secsize);
	crc = de_crcobj_getval(d->crco);

	is_dup = (de_inthashtable_add_item(c, d->voldesc_crc_hash, (i64)crc, NULL) == 0);
	// False positives are *possible*, but note that we always allow the first
	// primary descriptor (multiple unique primary descriptors are not allowed), and
	// the first supplemental descriptor (multiple unique supplemental descriptors
	// are rare).
	if(is_primary) {
		if(d->primary_vol_desc_count==0) is_dup = 0;
		d->primary_vol_desc_count++;
	}
	else {
		if(d->suppl_vol_desc_count==0) is_dup = 0;
		d->suppl_vol_desc_count++;
	}

	if(is_dup) {
		de_dbg(c, "[this is an extra copy of a previous volume descriptor]");
		if(d->vol_desc_sector_forced && (secnum==d->vol_desc_sector_to_use)) {
			; // ... but we have to read it anyway.
		}
		else {
			vol->quality = 0;
			goto done;
		}
	}
	/////////

	vol->encoding = DE_ENCODING_ASCII; // default

	if(!is_primary) {
		vol_flags = de_getbyte(pos);
		de_dbg(c, "volume flags: 0x%02x", vol_flags);
	}
	pos++;

	if(!is_primary) {
		// Look ahead at the escape sequences field, because fields that appear
		// before it may depend on it.
		read_escape_sequences(c, d, vol, pos1+88);
	}

	tmpstr = ucstring_create(c);
	handle_iso_string_p(c, d, vol, "system id", &pos, 32, tmpstr);
	handle_iso_string_p(c, d, vol, "volume id", &pos, 32, tmpstr);

	pos += 8; // 73-80 unused

	vol_space_size = getu32bbo_p(c->infile, &pos);
	de_dbg(c, "volume space size: %"I64_FMT" blocks", vol_space_size);

	pos += 32; // escape sequences (already read) or unused

	vol_set_size = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume set size: %u", (unsigned int)vol_set_size);
	vol_seq_num = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "volume sequence number: %u", (unsigned int)vol_seq_num);
	vol->block_size = getu16bbo_p(c->infile, &pos);
	de_dbg(c, "block size: %u bytes", (unsigned int)vol->block_size);
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
	// This is a copy of the main information in the root directory's
	// directory entry, basically for bootstrapping.
	// It should be effectively identical to the "." entry in the root
	// directory. The only fields we care about:
	vol->root_dir_extent_blk = getu32bbo(c->infile, pos+2);
	de_dbg(c, "loc. of extent: block #%u", (unsigned int)vol->root_dir_extent_blk);
	vol->root_dir_data_len = getu32bbo(c->infile, pos+10);
	de_dbg(c, "data length: %u", (unsigned int)vol->root_dir_data_len);

	de_dbg_indent(c, -1);
	pos += 34;

	handle_iso_string_p(c, d, vol, "volume set id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, vol, "publisher id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, vol, "data preparer id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, vol, "application id", &pos, 128, tmpstr);
	handle_iso_string_p(c, d, vol, "copyright file id", &pos, 37, tmpstr);
	handle_iso_string_p(c, d, vol, "abstract file id", &pos, 37, tmpstr);
	handle_iso_string_p(c, d, vol, "bibliographic file id", &pos, 37, tmpstr);

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

	vol->file_structure_version = de_getbyte_p(&pos);
	de_dbg(c, "file structure version: %u", (unsigned int)vol->file_structure_version);

	vol->is_cdxa = !dbuf_memcmp(c->infile, pos1+1024, "CD-XA001", 8);
	de_dbg(c, "is CD-ROM XA: %u", (unsigned int)vol->is_cdxa);

	vol->quality = 1 +
		((vol->block_size==2048)?80:0) +
		((vol->is_joliet)?40:0) +
		((vol->file_structure_version<=1)?10:0) +
		((vol->file_structure_version==1)?10:0) +
		((is_primary)?5:0);

done:
	ucstring_destroy(tmpstr);
}

static void do_primary_or_suppl_volume_descr(deark *c, lctx *d, i64 secnum,
	i64 pos1, int is_primary)
{
	struct vol_record *newvol;

	newvol = de_malloc(c, sizeof(struct vol_record));
	newvol->secnum = secnum;

	do_primary_or_suppl_volume_descr_internal(c, d, newvol, secnum, pos1, is_primary);

	if(newvol->quality==0) goto done; // not usable
	if(d->vol_desc_sector_forced && (secnum!=d->vol_desc_sector_to_use)) {
		// User told us not to use this volume descriptor.
		goto done;
	}

	if(d->vol) {
		// We already have a volume descriptor. Is the new one preferable?
		if(newvol->quality > d->vol->quality) {
			de_free(c, d->vol);
			d->vol = newvol;
			newvol = NULL;
		}
	}
	else {
		d->vol = newvol;
		newvol = NULL;
	}

done:
	if(newvol) de_free(c, newvol);
}

// Returns 0 if this is a terminator, or on serious error.
// Returns 1 normally.
static int do_volume_descriptor(deark *c, lctx *d, i64 secnum)
{
	u8 dtype;
	u8 dvers;
	int saved_indent_level;
	i64 pos1, pos;
	const char *vdtname;
	int retval = 0;
	enum voldesctype_enum vdt = VOLDESCTYPE_UNKNOWN;
	struct de_stringreaderdata *standard_id = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	pos1 = sector_dpos(d, secnum);
	pos = pos1;

	dtype = de_getbyte_p(&pos);
	standard_id = dbuf_read_string(c->infile, pos, 5, 5, 0, DE_ENCODING_ASCII);
	pos += 5;
	dvers = de_getbyte_p(&pos);

	if(!de_strcmp(standard_id->sz, "CD001")) {
		switch(dtype) {
		case 0: vdt = VOLDESCTYPE_CD_BOOT; break;
		case 1: vdt = VOLDESCTYPE_CD_PRIMARY; break;
		case 2: vdt = VOLDESCTYPE_CD_SUPPL; break;
		case 3: vdt = VOLDESCTYPE_CD_PARTDESCR; break;
		case 0xff: vdt = VOLDESCTYPE_CD_TERM; break;
		default: vdt = VOLDESCTYPE_OTHERVALID; break;
		}
	}
	else if(!de_strncmp(standard_id->sz, "NSR0", 4))
	{
		vdt = VOLDESCTYPE_NSR;
	}
	else if(!de_strncmp(standard_id->sz, "BEA0", 4)) {
		vdt = VOLDESCTYPE_BEA;
	}
	else if(!de_strncmp(standard_id->sz, "TEA0", 4)) {
		vdt = VOLDESCTYPE_TEA;
	}
	else if(!de_strncmp(standard_id->sz, "BOOT", 4) ||
		!de_strncmp(standard_id->sz, "CDW0", 4))
	{
		vdt = VOLDESCTYPE_OTHERVALID;
	}

	if(vdt==VOLDESCTYPE_UNKNOWN) {
		de_warn(c, "Expected volume descriptor at %"I64_FMT" not found", pos1);
		goto done;
	}

	de_dbg(c, "volume descriptor at %"I64_FMT" (sector %d)", pos1, (int)secnum);
	de_dbg_indent(c, 1);

	de_dbg(c, "type: %u", (unsigned int)dtype);
	de_dbg(c, "standard id: \"%s\"", ucstring_getpsz_d(standard_id->str));
	de_dbg(c, "version: %u", (unsigned int)dvers);

	vdtname = get_vol_descr_type_name(vdt);
	de_dbg(c, "interpreted type: %s", vdtname);

	retval = 1;
	if(vdt==VOLDESCTYPE_TEA) {
		retval = 0;
	}
	else if(vdt==VOLDESCTYPE_CD_TERM) {
		// Minor hack: Peak ahead at the next sector. Unless it looks like a
		// BEA descriptor, signifying that there are extended descriptors,
		// assume this is the last descriptor.
		if(dbuf_memcmp(c->infile, sector_dpos(d, secnum+1)+1, "BEA0", 4)) {
			retval = 0;
		}
	}

	switch(vdt) {
	case VOLDESCTYPE_CD_BOOT:
		do_boot_volume_descr(c, d, pos1);
		break;
	case VOLDESCTYPE_CD_PRIMARY:
		do_primary_or_suppl_volume_descr(c, d, secnum, pos1, 1);
		break;
	case VOLDESCTYPE_CD_SUPPL: // supplementary or enhanced
		do_primary_or_suppl_volume_descr(c, d, secnum, pos1, 0);
		break;
	case VOLDESCTYPE_NSR:
		d->is_udf = 1;
		break;
	case VOLDESCTYPE_BEA:
	case VOLDESCTYPE_CD_TERM:
	case VOLDESCTYPE_TEA:
		break;
	default:
		de_dbg(c, "[disregarding this volume descriptor]");
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_destroy_stringreaderdata(c, standard_id);
	return retval;
}

static void de_run_iso9660(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 cursec;
	const char *s;

	d = de_malloc(c, sizeof(lctx));

	if(de_get_ext_option_bool(c, "iso9660:tolower", 0)) {
		d->names_to_lowercase = 1;
	}

	if(de_get_ext_option_bool(c, "iso9660:dirsizehack", 0)) {
		d->dirsize_hack = 1;
	}

	s = de_get_ext_option(c, "iso9660:voldesc");
	if(s) {
		d->vol_desc_sector_forced = 1;
		d->vol_desc_sector_to_use = de_atoi(s);
	}

	d->rr_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UTF8);

	d->secsize = 2048;

	if(!dbuf_memcmp(c->infile, 512, "PM\x00\x00", 4)) {
		de_info(c, "Note: This file includes an Apple Partition Map. "
			"Use \"-m apm\" to read it.");
	}

	d->voldesc_crc_hash = de_inthashtable_create(c);
	cursec = 16;
	while(1) {
		if(!do_volume_descriptor(c, d, cursec)) break;
		cursec++;
	}

	if(d->is_udf) {
		de_warn(c, "This file might have UDF-specific content, which is "
			"not supported.");
	}

	if(!d->vol) {
		de_err(c, "No usable volume descriptor found");
		goto done;
	}

	de_dbg(c, "[using volume descriptor at sector %u]", (unsigned int)d->vol->secnum);

	if(d->vol->block_size != 2048) {
		// TODO: Figure out sector size vs. block size.
		de_err(c, "Unsupported block size: %u", (unsigned int)d->vol->block_size);
		goto done;
	}

	d->dirs_seen = de_inthashtable_create(c);
	d->curpath = de_strarray_create(c);

	if(d->vol->root_dir_extent_blk) {
		do_directory(c, d, sector_dpos(d, d->vol->root_dir_extent_blk),
			d->vol->root_dir_data_len, 0);
	}

done:
	if(d) {
		de_free(c, d->vol);
		de_strarray_destroy(d->curpath);
		de_inthashtable_destroy(c, d->dirs_seen);
		de_inthashtable_destroy(c, d->voldesc_crc_hash);
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int cdsig_at(dbuf *f, i64 pos)
{
	u8 buf[6];

	dbuf_read(f, buf, pos, sizeof(buf));
	if(de_memcmp(&buf[1], "CD001", 5)) return 0;
	if(buf[0]>3 && buf[0]<255) return 0;
	return 1;
}

static int cdsig_at2(dbuf *f, i64 pos1, i64 pos2)
{
	return (cdsig_at(f, pos1) &&
		cdsig_at(f, pos2));
}

static int de_identify_iso9660(deark *c)
{
	if(cdsig_at2(c->infile, 32768, 32768+2048)) {
		// Confidence is practically 100%, but since hybrid formats are
		// possible, we want other modules to be able to have precedence.
		return 80;
	}
	return 0;
}

static void de_help_iso9660(deark *c)
{
	de_msg(c, "-opt iso9660:tolower : Convert original-style filenames to lowercase.");
	de_msg(c, "-opt iso9660:voldesc=<n> : Use the volume descriptor at sector <n>.");
}

void de_module_iso9660(deark *c, struct deark_module_info *mi)
{
	mi->id = "iso9660";
	mi->desc = "ISO 9660 (CD-ROM) image";
	mi->run_fn = de_run_iso9660;
	mi->identify_fn = de_identify_iso9660;
	mi->help_fn = de_help_iso9660;
}

struct cdraw_params {
	int ok;
	i64 sector_total_len;
	i64 sector_dlen;
	i64 sector_data_offset;
	const char *ext;
};

// If the volume has an ISO 9660 "volume identifier", try to read it to use as
// part of the output filename.
// This is quick and dirty, and somewhat duplicates code from the iso9660 module.
static void cdraw_set_name_from_vol_id(deark *c, struct cdraw_params *cdrp, de_finfo *fi)
{
	de_ucstring *vol_id = NULL;
	i64 pos;

	pos = 16*cdrp->sector_total_len + cdrp->sector_data_offset;
	if(dbuf_memcmp(c->infile, pos, "\x01" "CD001", 6)) goto done;

	vol_id = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+40, 32, vol_id, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(vol_id);

	if(ucstring_isnonempty(vol_id)) {
		de_dbg(c, "iso9660 volume id: \"%s\"", ucstring_getpsz_d(vol_id));
		de_finfo_set_name_from_ucstring(c, fi, vol_id, 0);
	}

done:
	ucstring_destroy(vol_id);
}

static void do_cdraw_convert(deark *c, struct cdraw_params *cdrp)
{
	i64 pos;
	de_finfo *fi = NULL;
	dbuf *outf = NULL;

	fi = de_finfo_create(c);
	cdraw_set_name_from_vol_id(c, cdrp, fi);

	outf = dbuf_create_output_file(c, cdrp->ext, fi, 0x0);

	pos = cdrp->sector_data_offset;
	while(1) {
		if(pos >= c->infile->len) break;
		dbuf_copy(c->infile, pos, cdrp->sector_dlen, outf);
		pos += cdrp->sector_total_len;
	}

	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static void cdraw_setdefaults(struct cdraw_params *cdrp)
{
	cdrp->ok = 0;
	cdrp->sector_total_len = 2048;
	cdrp->sector_dlen = 2048;
	cdrp->sector_data_offset = 0;
	cdrp->ext = "bin";
}

static int syncbytes_at(dbuf *f, i64 pos)
{
	return !dbuf_memcmp(f, pos,
		"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", 12);
}

static void cdraw_detect_params(dbuf *f, struct cdraw_params *cdrp)
{
	if(cdsig_at2(f, 2336*16+8, 2336*17+8)) {
		cdrp->ok = 1;
		cdrp->sector_total_len = 2336;
		cdrp->sector_data_offset = 8;
		cdrp->ext = "iso";
		return;
	}
	if(cdsig_at2(f, 2352*16+16, 2352*17+16)) {
		cdrp->ok = 1;
		cdrp->sector_total_len = 2352;
		cdrp->sector_data_offset = 16;
		cdrp->ext = "iso";
		return;
	}
	if(cdsig_at2(f, 2352*16+24, 2352*17+24)) {
		cdrp->ok = 1;
		cdrp->sector_total_len = 2352;
		cdrp->sector_data_offset = 24;
		cdrp->ext = "iso";
		return;
	}
	if(cdsig_at2(f, 2448*16+16, 2448*17+16)) {
		cdrp->ok = 1;
		cdrp->sector_total_len = 2448;
		cdrp->sector_data_offset = 16;
		cdrp->ext = "iso";
		return;
	}
	if(cdsig_at2(f, 2448*16+24, 2448*17+24)) {
		cdrp->ok = 1;
		cdrp->sector_total_len = 2448;
		cdrp->sector_data_offset = 24;
		cdrp->ext = "iso";
		return;
	}
	if(syncbytes_at(f, 0)) {
		if(syncbytes_at(f, 2352)) {
			if(!dbuf_memcmp(f, 512+16, "PM", 2)) {
				cdrp->ok = 1;
				cdrp->sector_total_len = 2352;
				cdrp->sector_data_offset = 16;
				cdrp->ext = "apm";
				return;
			}
		}
	}
	// TODO: More formats?
}

static void de_run_cd_raw(deark *c, de_module_params *mparams)
{
	struct cdraw_params cdrp;

	cdraw_setdefaults(&cdrp);
	cdraw_detect_params(c->infile, &cdrp);
	if(!cdrp.ok) {
		de_err(c, "Failed to detect raw CD format");
		goto done;
	}

	de_dbg(c, "total bytes/sector: %"I64_FMT, cdrp.sector_total_len);
	de_dbg(c, "data bytes/sector: %"I64_FMT, cdrp.sector_dlen);
	de_dbg(c, "data offset: %"I64_FMT, cdrp.sector_data_offset);

	do_cdraw_convert(c, &cdrp);

done:
	;
}

static int de_identify_cd_raw(deark *c)
{
	struct cdraw_params cdrp;

	cdraw_setdefaults(&cdrp);
	cdraw_detect_params(c->infile, &cdrp);
	if(cdrp.ok) return 70;
	return 0;
}

void de_module_cd_raw(deark *c, struct deark_module_info *mi)
{
	mi->id = "cd_raw";
	mi->desc = "Raw CD image";
	mi->run_fn = de_run_cd_raw;
	mi->identify_fn = de_identify_cd_raw;
}

struct nrg_ctx {
	int ver;
	i64 chunk_list_start;
	i64 chunk_list_size;
};

#define CODE_CDTX 0x43445458U
#define CODE_CUES 0x43554553U
#define CODE_CUEX 0x43554558U
#define CODE_DAOI 0x44414f49U
#define CODE_DAOX 0x44414f58U
#define CODE_END_ 0x454e4421U // END!
#define CODE_ETNF 0x45544e46U
#define CODE_SINF 0x53494e46U

static int detect_nrg_internal(deark *c)
{
	if(!dbuf_memcmp(c->infile, c->infile->len-8, "NERO", 4)) {
		return 1;
	}
	if(!dbuf_memcmp(c->infile, c->infile->len-12, "NER5", 4)) {
		return 2;
	}
	return 0;
}

static void do_nrg_ETNF(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	i64 pos = chunkctx->dpos;
	i64 t = 0;

	while(1) {
		i64 track_offs_bytes, track_len_bytes, start_lba;
		unsigned int mode;

		if(chunkctx->dpos + chunkctx->dlen - pos < 20) break;
		de_dbg(c, "track #%d", (int)t);
		de_dbg_indent(c, 1);
		track_offs_bytes = de_getu32be(pos);
		track_len_bytes = de_getu32be(pos+4);
		de_dbg(c, "offset: %"I64_FMT", len: %"I64_FMT, track_offs_bytes, track_len_bytes);
		mode = (unsigned int)de_getu32be(pos+8);
		de_dbg(c, "mode: %u", mode);
		start_lba = de_getu32be(pos+12);
		de_dbg(c, "start lba: %"I64_FMT, start_lba);
		de_dbg_indent(c, -1);
		pos += 20;
		t++;
	}
}

static int my_preprocess_nrg_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_CDTX: name = "CD-text"; break;
	case CODE_CUES: case CODE_CUEX: name = "cue sheet"; break;
	case CODE_DAOI: case CODE_DAOX: name = "DAO info"; break;
	case CODE_ETNF: name = "extended track info"; break;
	case CODE_SINF: name = "session info"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	return 1;
}


static int my_nrg_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	// Always set this, because we never want the IFF parser to try to handle
	// a chunk itself.
	ictx->handled = 1;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ETNF:
		do_nrg_ETNF(c, ictx, ictx->chunkctx);
		break;
	}

	if(ictx->chunkctx->chunk4cc.id==CODE_END_) {
		return 0;
	}
	return 1;
}

static void do_nrg_chunks(deark *c, struct nrg_ctx *nrg)
{
	struct de_iffctx *ictx = NULL;

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)nrg;
	ictx->preprocess_chunk_fn = my_preprocess_nrg_chunk_fn;
	ictx->handle_chunk_fn = my_nrg_chunk_handler;
	ictx->f = c->infile;
	ictx->is_le = 0;
	ictx->reversed_4cc = 0;

	de_fmtutil_read_iff_format(c, ictx, nrg->chunk_list_start, nrg->chunk_list_size);
}

static void de_run_nrg(deark *c, de_module_params *mparams)
{
	struct cdraw_params cdrp;
	struct nrg_ctx *nrg = NULL;

	nrg = de_malloc(c, sizeof(struct nrg_ctx));

	nrg->ver = detect_nrg_internal(c);
	if(nrg->ver==0) {
		de_err(c, "Not in NRG format");
		goto done;
	}

	if(nrg->ver==2) {
		nrg->chunk_list_start = de_geti64be(c->infile->len-8);
		nrg->chunk_list_size = c->infile->len - 12 - nrg->chunk_list_start;
	}
	else {
		nrg->chunk_list_start = de_getu32be(c->infile->len-4);
		nrg->chunk_list_size = c->infile->len - 8 - nrg->chunk_list_start;
	}
	de_dbg(c, "chunk list: offset=%"I64_FMT", len=%"I64_FMT,
		nrg->chunk_list_start, nrg->chunk_list_size);

	do_nrg_chunks(c, nrg);

	// TODO: The NRG data we just read probably tells us the image format,
	// somehow, so it seems wrong to autodetect it.

	if(cdsig_at2(c->infile, 32768, 32768+2048)) {
		de_dbg(c, "ISO 9660 image at %d", 0);
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice(c, "iso9660", NULL, c->infile, 0, nrg->chunk_list_start);
		de_dbg_indent(c, -1);
		goto done;
	}

	cdraw_setdefaults(&cdrp);
	cdraw_detect_params(c->infile, &cdrp);
	if(cdrp.ok) {
		de_dbg(c, "raw CD image at %d", 0);
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice(c, "cd_raw", NULL, c->infile, 0, nrg->chunk_list_start);
		de_dbg_indent(c, -1);
	}

done:
	de_free(c, nrg);
}

static int de_identify_nrg(deark *c)
{
	if(!de_input_file_has_ext(c, "nrg")) return 0;
	if(detect_nrg_internal(c)>0) {
		return 85;
	}
	return 0;
}

void de_module_nrg(deark *c, struct deark_module_info *mi)
{
	mi->id = "nrg";
	mi->desc = "NRG CD-ROM image";
	mi->run_fn = de_run_nrg;
	mi->identify_fn = de_identify_nrg;
}
