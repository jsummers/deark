// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// LHA/LZH compressed archive format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_lha);
DE_DECLARE_MODULE(de_module_car_lha);

#define MAX_SUBDIR_LEVEL 32

#define CODE_S_LH0 0x204c4830 // SAR
#define CODE_S_LH5 0x204c4835 // SAR
#define CODE_ah0 0x2d616830U // MAR
#define CODE_ari 0x2d617269U // MAR
#define CODE_hf0 0x2d686630U // MAR
#define CODE_lZ0 0x2d6c5a30U // PUT
#define CODE_lZ1 0x2d6c5a31U // PUT
#define CODE_lZ5 0x2d6c5a35U // PUT
#define CODE_lh0 0x2d6c6830U
#define CODE_lh1 0x2d6c6831U
#define CODE_lh2 0x2d6c6832U
#define CODE_lh3 0x2d6c6833U
#define CODE_lh4 0x2d6c6834U
#define CODE_lh5 0x2d6c6835U
#define CODE_lh6 0x2d6c6836U
#define CODE_lh7 0x2d6c6837U // standard, or LHARK
#define CODE_lh8 0x2d6c6838U
#define CODE_lh9 0x2d6c6839U
#define CODE_lha 0x2d6c6861U
#define CODE_lhb 0x2d6c6862U
#define CODE_lhc 0x2d6c6863U
#define CODE_lhd 0x2d6c6864U
#define CODE_lhe 0x2d6c6865U
#define CODE_lhx 0x2d6c6878U
#define CODE_lz2 0x2d6c7a32U
#define CODE_lz3 0x2d6c7a33U
#define CODE_lz4 0x2d6c7a34U
#define CODE_lz5 0x2d6c7a35U
#define CODE_lz7 0x2d6c7a37U
#define CODE_lz8 0x2d6c7a38U
#define CODE_lzs 0x2d6c7a73U
#define CODE_pc1 0x2d706331U
#define CODE_pm0 0x2d706d30U
#define CODE_pm1 0x2d706d31U
#define CODE_pm2 0x2d706d32U

#define TIMESTAMPIDX_INVALID (-1)
struct timestamp_data {
	struct de_timestamp ts; // The best timestamp of this type found so far
	int quality;
};

struct cmpr_meth_info;

struct member_data {
	u8 hlev; // header level
	de_encoding encoding;
	i64 member_pos;
	i64 total_size;
	struct cmpr_meth_info *cmi;
	u8 is_dir;
	u8 is_special;
	u8 is_nonexecutable;
	u8 is_executable;
	i64 orig_size;
	UI hdr_checksum_calc;

	u8 have_hdr_crc_reported;
	u32 hdr_crc_reported;
	u32 hdr_crc_calc;
	i64 hdr_crc_field_pos;

	u32 crc16;
	u8 os_id;
	i64 compressed_data_pos; // relative to beginning of file
	i64 compressed_data_len;
	de_ucstring *dirname;
	de_ucstring *filename;
	de_ucstring *fullfilename;
	struct timestamp_data tsdata[DE_TIMESTAMPIDX_COUNT];
};

typedef struct localctx_struct {
	de_encoding input_encoding;
	u8 unsupp_warned;
	int member_count;
	struct de_crcobj *crco;
} lctx;

typedef void (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	u8 is_recognized;
	u32 uniq_id;
	decompressor_fn decompressor;
	char id_printable_sz[6];
	char descr[80];
};

struct exthdr_type_info_struct;

typedef void (*exthdr_decoder_fn)(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen);

struct exthdr_type_info_struct {
	u8 id;
	u8 flags;
	const char *name;
	exthdr_decoder_fn decoder_fn;
};

static int lha_isdigit(u8 x)
{
	return (x>='0' && x<='9');
}

static int lha_isalpha(u8 x)
{
	return ((x>='A' && x<='Z') || (x>='a' && x<='z'));
}

static int lha_isalnum(u8 x)
{
	return (lha_isdigit(x) || lha_isalpha(x));
}

static int is_possible_cmpr_meth(const u8 m[5])
{
	if(m[0]!=m[4]) return 0;
	if(m[0]==' ' && m[1]=='L' && m[2]=='H' && lha_isdigit(m[3])) return 1;
	if(m[0]!='-') return 0;
	if(!lha_isalpha(m[1]) ||
		!lha_isalnum(m[2]) ||
		!lha_isalnum(m[3]))
	{
		return 0;
	}
	return 1;
}

static void apply_timestamp(deark *c, lctx *d, struct member_data *md,
	int tsidx, const struct de_timestamp *ts, int quality)
{
	if(!ts->is_valid) return;
	if(tsidx<0 || tsidx>=DE_TIMESTAMPIDX_COUNT) return;
	if(quality < md->tsdata[tsidx].quality) return;
	md->tsdata[tsidx].ts = *ts;
	md->tsdata[tsidx].quality = quality;
}

static void read_msdos_modtime(deark *c, lctx *d, struct member_data *md,
	i64 pos, const char *name)
{
	i64 mod_time_raw, mod_date_raw;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	mod_time_raw = de_getu16le(pos);
	mod_date_raw = de_getu16le(pos+2);
	if(mod_time_raw==0 && mod_date_raw==0) {
		de_dbg(c, "%s: (not set)", name);
		return;
	}
	de_dos_datetime_to_timestamp(&tmp_timestamp, mod_date_raw, mod_time_raw);
	tmp_timestamp.tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
	apply_timestamp(c, d, md, DE_TIMESTAMPIDX_MODIFY, &tmp_timestamp, 10);
}

static void read_windows_FILETIME(deark *c, lctx *d, struct member_data *md,
	i64 pos, int tsidx, const char *name)
{
	i64 t_FILETIME;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	t_FILETIME = de_geti64le(pos);
	de_FILETIME_to_timestamp(t_FILETIME, &tmp_timestamp, 0x1);
	if(t_FILETIME<=0) tmp_timestamp.is_valid = 0;
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t_FILETIME, timestamp_buf);
	apply_timestamp(c, d, md, tsidx, &tmp_timestamp, 90);
}

static void read_unix_timestamp(deark *c, lctx *d, struct member_data *md,
	i64 pos, int tsidx, const char *name)
{
	i64 t;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, &tmp_timestamp, 0x1);
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %d (%s)", name, (int)t, timestamp_buf);
	apply_timestamp(c, d, md, tsidx, &tmp_timestamp, 50);
}

static void rp_add_component(deark *c, lctx *d, struct member_data *md,
	dbuf *f, i64 pos, i64 len, struct de_strarray *sa, de_ucstring *tmpstr)
{
	if(len<1) return;
	ucstring_empty(tmpstr);
	dbuf_read_to_ucstring(f, pos, len, tmpstr, 0, md->encoding);
	de_strarray_push(sa, tmpstr);
}

static void read_path_to_strarray(deark *c, lctx *d, struct member_data *md,
	dbuf *inf, i64 pos, i64 len, struct de_strarray *sa, int is_exthdr_dirname)
{
	dbuf *tmpdbuf = NULL;
	de_ucstring *tmpstr = NULL;
	i64 component_startpos;
	i64 component_len;
	i64 i;

	tmpstr = ucstring_create(c);

	tmpdbuf = dbuf_create_membuf(c, len, 0);
	dbuf_copy(inf, pos, len, tmpdbuf);

	component_startpos = 0;
	component_len = 0;

	for(i=0; i<len; i++) {
		u8 ch;

		ch = dbuf_getbyte(tmpdbuf, i);
		if(ch==0x00) break; // Tolerate NUL termination
		if((is_exthdr_dirname && ch==0xff) ||
			(!is_exthdr_dirname && (ch=='\\' || ch=='/')))
		{
			component_len = i - component_startpos;
			rp_add_component(c, d, md, tmpdbuf, component_startpos, component_len, sa, tmpstr);
			component_startpos = i+1;
			component_len = 0;
		}
		else {
			component_len++;
		}
	}
	rp_add_component(c, d, md, tmpdbuf, component_startpos, component_len, sa, tmpstr);

	dbuf_close(tmpdbuf);
	ucstring_destroy(tmpstr);
}

static void read_filename_hlev0(deark *c, lctx *d, struct member_data *md,
	i64 pos, i64 len)
{
	struct de_strarray *sa = NULL;

	if(md->filename) {
		ucstring_empty(md->filename);
	}
	else {
		md->filename = ucstring_create(c);
	}

	sa = de_strarray_create(c, MAX_SUBDIR_LEVEL+2);
	read_path_to_strarray(c, d, md, c->infile, pos, len, sa, 0);

	de_strarray_make_path(sa, md->filename, DE_MPFLAG_NOTRAILINGSLASH);
	de_dbg(c, "filename (parsed): \"%s\"", ucstring_getpsz_d(md->filename));

	de_strarray_destroy(sa);
}

static void read_filename_hlev1_or_exthdr(deark *c, lctx *d, struct member_data *md,
	i64 pos, i64 len)
{
	i64 i;

	if(md->filename) {
		ucstring_empty(md->filename);
	}
	else {
		md->filename = ucstring_create(c);
	}

	// Some files seem to assume NUL termination is allowed.
	dbuf_read_to_ucstring(c->infile, pos, len,
		md->filename, DE_CONVFLAG_STOP_AT_NUL, md->encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));

	// I don't think slashes are allowed
	for(i=0; i<md->filename->len; i++) {
		if(md->filename->str[i]=='/') {
			md->filename->str[i]='_';
		}
	}
}

static void exthdr_common(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	if(dlen<2) return;
	md->hdr_crc_reported = (u32)de_getu16le(pos);
	md->have_hdr_crc_reported = 1;
	md->hdr_crc_field_pos = pos;
	de_dbg(c, "header crc (reported): 0x%04x", (unsigned int)md->hdr_crc_reported);
	// TODO: Additional information
}

static void exthdr_filename(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	read_filename_hlev1_or_exthdr(c, d, md, pos, dlen);
}

static void exthdr_dirname(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	struct de_strarray *dirname_sa = NULL;

	if(md->dirname) {
		ucstring_empty(md->dirname);
	}
	else {
		md->dirname = ucstring_create(c);
	}

	dirname_sa = de_strarray_create(c, MAX_SUBDIR_LEVEL+2);
	// 0xff is used as the path separator. Don't know what happens if a directory
	// name contains an actual 0xff byte.
	read_path_to_strarray(c, d, md, c->infile, pos, dlen, dirname_sa, 1);
	de_strarray_make_path(dirname_sa, md->dirname, DE_MPFLAG_NOTRAILINGSLASH);
	de_dbg(c, "%s (parsed): \"%s\"", e->name, ucstring_getpsz_d(md->dirname));

	de_strarray_destroy(dirname_sa);
}

static void exthdr_msdosattribs(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	u32 attribs;
	de_ucstring *descr = NULL;

	if(dlen<2) goto done;
	attribs = (u32)de_getu16le(pos);
	descr = ucstring_create(c);
	de_describe_dos_attribs(c, (UI)attribs, descr, 0);
	de_dbg(c, "%s: 0x%04x (%s)", e->name, (UI)attribs, ucstring_getpsz_d(descr));
done:
	ucstring_destroy(descr);
}

static void exthdr_filesize(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	// TODO: Support this
	de_warn(c, "Unsupported \"file size\" extended header found. This may prevent "
		"the rest of the file from being processed correctly.");
}

static void exthdr_windowstimestamp(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	if(dlen<24) return;
	read_windows_FILETIME(c, d, md, pos,    DE_TIMESTAMPIDX_CREATE, "create time");
	read_windows_FILETIME(c, d, md, pos+8,  DE_TIMESTAMPIDX_MODIFY, "mod time   ");
	read_windows_FILETIME(c, d, md, pos+16, DE_TIMESTAMPIDX_ACCESS, "access time");
}

static void interpret_unix_perms(deark *c, lctx *d, struct member_data *md, unsigned int mode)
{
	if(mode & 0100000) { // regular file
		if(mode & 0111) { // executable
			md->is_executable = 1;
		}
		else {
			md->is_nonexecutable = 1;
		}
	}

	if((mode & 0170000) == 0120000) {
		md->is_special = 1; // symlink
	}
}

static void exthdr_unixperms(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	unsigned int mode;

	if(dlen<2) return;
	mode = (unsigned int)de_getu16le(pos);
	de_dbg(c, "mode: octal(%06o)", mode);
	interpret_unix_perms(c, d, md, mode);
}

static void exthdr_unixuidgid(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	i64 uid, gid;
	if(dlen<4) return;

	// It's strange that the GID comes first, while the UID comes first in the
	// level-0 "extended area".
	gid = de_getu16le(pos);
	de_dbg(c, "gid: %d", (int)gid);
	uid = de_getu16le(pos+2);
	de_dbg(c, "uid: %d", (int)uid);
}

static void exthdr_unixtimestamp(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	if(dlen<4) return;
	read_unix_timestamp(c, d, md, pos, DE_TIMESTAMPIDX_MODIFY, "last-modified");
}

static void exthdr_lev3newattribs2(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	if(dlen<20) return;

	// TODO: Permission
	// TODO: GID/UID

	// [Documented as "creation time", but this is a Unix-style header, so I
	// wonder if someone mistranslated "ctime" (=change time).]
	read_unix_timestamp(c, d, md, pos+12, TIMESTAMPIDX_INVALID, "create(?) time");

	read_unix_timestamp(c, d, md, pos+16, DE_TIMESTAMPIDX_ACCESS, "access time   ");
}

static void exthdr_codepage(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	int n_codepage;
	de_encoding n_encoding;
	char descr[100];

	if(dlen!=4) return;
	n_codepage = (int)de_geti32le(pos);
	n_encoding = de_windows_codepage_to_encoding(c, n_codepage, descr, sizeof(descr), 0);
	de_dbg(c, "codepage: %d (%s)", n_codepage, descr);
	if(n_encoding != DE_ENCODING_UNKNOWN) {
		md->encoding = n_encoding;
	}
}

static const struct exthdr_type_info_struct exthdr_type_info_arr[] = {
	{ 0x00, 0, "common", exthdr_common },
	{ 0x01, 0, "filename", exthdr_filename },
	{ 0x02, 0, "dir name", exthdr_dirname },
	{ 0x39, 0, "multi-disc", NULL },
	{ 0x3f, 0, "comment", NULL },
	{ 0x40, 0, "MS-DOS file attribs", exthdr_msdosattribs },
	{ 0x41, 0, "Windows timestamp", exthdr_windowstimestamp },
	{ 0x42, 0, "MS-DOS file size", exthdr_filesize },
	{ 0x43, 0, "time zone", NULL },
	{ 0x44, 0, "UTF-16 filename", NULL },
	{ 0x45, 0, "UTF-16 dir name", NULL },
	{ 0x46, 0, "codepage", exthdr_codepage },
	{ 0x50, 0, "Unix perms", exthdr_unixperms },
	{ 0x51, 0, "Unix UID/GID", exthdr_unixuidgid },
	{ 0x52, 0, "Unix group name", NULL },
	{ 0x53, 0, "Unix username", NULL },
	{ 0x54, 0, "Unix timestamp", exthdr_unixtimestamp },
	{ 0x7d, 0, "capsule", NULL },
	{ 0x7e, 0, "OS/2 extended attribs", NULL },
	{ 0x7f, 0, "level 3 new attribs type-1", NULL }, // (OS/2 only)
	{ 0xff, 0, "level 3 new attribs type-2", exthdr_lev3newattribs2 }
};

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->dirname);
	ucstring_destroy(md->filename);
	ucstring_destroy(md->fullfilename);
	de_free(c, md->cmi);
	de_free(c, md);
}

static const struct exthdr_type_info_struct *get_exthdr_type_info(u8 id)
{
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(exthdr_type_info_arr); i++) {
		if(id == exthdr_type_info_arr[i].id) {
			return &exthdr_type_info_arr[i];
		}
	}
	return NULL;
}

static void do_read_ext_header(deark *c, lctx *d, struct member_data *md,
	i64 pos1, i64 len, i64 dlen)
{
	u8 id = 0;
	const char *name;
	const struct exthdr_type_info_struct *e = NULL;

	if(dlen>=1) {
		id = de_getbyte(pos1);
		e = get_exthdr_type_info(id);
	}
	name = e ? e->name : "?";

	de_dbg(c, "ext header at %d, len=%d (1+%d+%d), id=0x%02x (%s)", (int)pos1, (int)len,
		(int)(dlen-1), (int)(len-dlen), (unsigned int)id, name);

	if(dlen<1) return; // Invalid header, too short to even have an id field

	if(e && e->decoder_fn) {
		de_dbg_indent(c, 1);
		e->decoder_fn(c, d, md, id, e, pos1+1, dlen-1);
		de_dbg_indent(c, -1);
	}
	else {
		if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, pos1+1, dlen-1, 256, NULL, 0x1);
		}
	}
}

static const char *get_os_name(u8 id)
{
	const char *name = NULL;
	switch(id) {
	case ' ': name="unspecified"; break;
	case '2': name="OS/2"; break;
	case '3': name="OS/386?"; break;
	case '9': name="OS-9"; break;
	case 'A': name="Amiga"; break;
	case 'C': name="CP/M"; break;
	case 'F': name="FLEX"; break;
	case 'H': name="Human68K"; break;
	case 'J': name="JVM"; break;
	case 'K': name="OS-9/68K"; break;
	case 'M': name="DOS"; break;
	case 'R': name="RUNser"; break;
	case 'T': name="TownsOS"; break;
	case 'U': name="Unix"; break;
	case 'W': name="Windows NT"; break;
	case 'a': name="Atari ST?"; break;
	case 'm': name="Macintosh"; break;
	case 'w': name="Windows"; break;
	}
	return name?name:"?";
}

static void do_lev0_ext_area(deark *c, lctx *d, struct member_data *md,
	i64 pos1, i64 len)
{
	if(len<1) return;
	md->os_id = de_getbyte(pos1);
	de_dbg(c, "OS id: %d ('%c') (%s)", (int)md->os_id,
		de_byte_to_printable_char(md->os_id), get_os_name(md->os_id));

	// TODO: Finish this
	if(md->os_id=='U') {
		unsigned int mode;
		i64 uid, gid;

		if(len<12) goto done;

		read_unix_timestamp(c, d, md, pos1+2, DE_TIMESTAMPIDX_MODIFY, "last-modified");

		mode = (unsigned int)de_getu16le(pos1+6);
		de_dbg(c, "mode: octal(%06o)", mode);
		interpret_unix_perms(c, d, md, mode);

		uid = de_getu16le(pos1+8);
		de_dbg(c, "uid: %d", (int)uid);
		gid = de_getu16le(pos1+10);
		de_dbg(c, "gid: %d", (int)gid);
	}

done: ;
}

// AFAICT, we're expected to think of the extended headers as a kind of linked
// list. The last field in each node is the "size of next node" (instead of
// "pointer to next node", as a real linked list would have). A size of 0 is
// like a "nil" pointer, and marks the end of the list.
// The "size of the first node" field (analogous to the "head" pointer) is
// conceptually not part of the extended headers section.
//
// Note that if we simply shift our frame of reference, this format is identical
// to a more typical length-prefixed format. But our code follows the
// linked-list model, to make it more consistent with most LHA documentation,
// and the various "size" fields.
//
// A return value of 0 means we failed to calculate the size of the
// extended headers segment.
static int do_read_ext_headers(deark *c, lctx *d, struct member_data *md,
	i64 pos1, i64 len, i64 first_ext_hdr_size, i64 *tot_bytes_consumed)
{
	i64 pos = pos1;
	i64 this_ext_hdr_size, next_ext_hdr_size;
	int retval = 0;
	i64 size_of_size_field;

	*tot_bytes_consumed = 0;

	if(first_ext_hdr_size==0) {
		return 1;
	}

	de_dbg(c, "ext headers section at %d", (int)pos);
	de_dbg_indent(c, 1);

	size_of_size_field = (md->hlev==3) ? 4 : 2;

	next_ext_hdr_size = first_ext_hdr_size;
	while(1) {
		this_ext_hdr_size = next_ext_hdr_size;
		if(this_ext_hdr_size==0) {
			retval = 1;
			*tot_bytes_consumed = pos - pos1;
			goto done;
		}
		if(this_ext_hdr_size<size_of_size_field) goto done;
		if(pos+this_ext_hdr_size > pos1+len) goto done;

		do_read_ext_header(c, d, md, pos, this_ext_hdr_size, this_ext_hdr_size-size_of_size_field);

		// Each ext header ends with a "size of next header" field.
		// We'll read it at this level, instead of in do_read_ext_header().
		pos += this_ext_hdr_size-size_of_size_field;
		if(size_of_size_field==2) {
			next_ext_hdr_size = de_getu16le(pos);
		}
		else {
			next_ext_hdr_size = de_getu32le(pos);
		}
		pos += size_of_size_field;
	}

done:
	if(retval) {
		de_dbg(c, "size of ext headers section: %d", (int)*tot_bytes_consumed);
	}
	else {
		de_dbg(c, "failed to parse all extended headers");
	}
	de_dbg_indent(c, -1);
	return retval;
}

static void make_fullfilename(deark *c, lctx *d, struct member_data *md)
{
	if(md->fullfilename) return;

	if(!md->filename) {
		md->filename = ucstring_create(c);
	}
	md->fullfilename = ucstring_create(c);

	if(md->hlev==0) {
		ucstring_append_ucstring(md->fullfilename, md->filename);
	}
	else {
		if(md->is_dir) {
			ucstring_append_ucstring(md->fullfilename, md->dirname);
		}
		else {
			if(ucstring_isnonempty(md->dirname)) {
				ucstring_append_ucstring(md->fullfilename, md->dirname);
				ucstring_append_sz(md->fullfilename, "/", DE_ENCODING_LATIN1);
			}
			if(ucstring_isnonempty(md->filename)) {
				ucstring_append_ucstring(md->fullfilename, md->filename);
			}
			else {
				ucstring_append_char(md->fullfilename, '_');
			}
		}
	}
}

static void decompress_uncompressed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static void decompress_lh5(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lzh_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lzh_params));
	lzhparams.fmt = DE_LZH_FMT_LH5LIKE;
	lzhparams.subfmt = '5';
	fmtutil_decompress_lzh(c, dcmpri, dcmpro, dres, &lzhparams);
}

static void decompress_lh6(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lzh_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lzh_params));
	lzhparams.fmt = DE_LZH_FMT_LH5LIKE;
	lzhparams.subfmt = '6';
	fmtutil_decompress_lzh(c, dcmpri, dcmpro, dres, &lzhparams);
}

static void decompress_lz5(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_szdd(c, dcmpri, dcmpro, dres, 0x1);
}

struct cmpr_meth_array_item {
	unsigned int flags;
	u32 uniq_id;
	const char *descr;
	decompressor_fn decompressor;
};

// Compression methods with a decompressor or a description are usually
// listed here, but note that it is also possible for get_cmpr_meth_info()
// to handle them procedurally.
static const struct cmpr_meth_array_item cmpr_meth_arr[] = {
	{ 0x00, CODE_lhd, "directory", NULL },
	{ 0x00, CODE_lh0, "uncompressed", decompress_uncompressed },
	{ 0x00, CODE_lh1, "LZ77, 4K, codes = dynamic Huffman", NULL },
	{ 0x00, CODE_lh5, "LZ77, 8K, static Huffman", decompress_lh5 },
	{ 0x00, CODE_lh6, "LZ77, 32K, static Huffman", decompress_lh6 },
	{ 0x00, CODE_lz4, "uncompressed (LArc)", decompress_uncompressed },
	{ 0x00, CODE_lz5, "LZSS, 4K (LArc)", decompress_lz5 },
	{ 0x00, CODE_pm0, "uncompressed (PMArc)", decompress_uncompressed },
	{ 0x00, CODE_lZ0, "uncompressed (MicroFox PUT)", decompress_uncompressed },
	{ 0x00, CODE_lZ1, "MicroFox PUT lZ1", NULL },
	{ 0x00, CODE_lZ5, "MicroFox PUT lZ5", decompress_lh5 },
	{ 0x00, CODE_S_LH0, "uncompressed (SAR)", decompress_uncompressed },
	{ 0x00, CODE_S_LH5, "SAR LH5", decompress_lh5 }
};

static const u32 other_known_cmpr_methods[] = {
	CODE_ah0, CODE_ari, CODE_hf0,
	CODE_lh2, CODE_lh3, CODE_lh4, CODE_lh7, CODE_lh8, CODE_lh9,
	CODE_lha, CODE_lhb, CODE_lhc, CODE_lhe, CODE_lhx,
	CODE_lz2, CODE_lz3, CODE_lz7, CODE_lz8, CODE_lzs,
	CODE_pc1, CODE_pm1, CODE_pm2 };

// Only call this after is_possible_cmpr_meth() return nonzero.
// Caller allocates cmi, and initializes to zeroes.
static void get_cmpr_meth_info(const u8 idbuf[5], struct cmpr_meth_info *cmi)
{
	size_t k;
	const struct cmpr_meth_array_item *cmai = NULL;

	// The first 4 bytes are unique for all known methods.
	cmi->uniq_id = (u32)de_getu32be_direct(idbuf);

	// All "possible" methods only use printable characters.
	de_memcpy(cmi->id_printable_sz, idbuf, 5);
	cmi->id_printable_sz[5] = '\0';

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_arr); k++) {
		if(cmpr_meth_arr[k].uniq_id == cmi->uniq_id) {
			cmai = &cmpr_meth_arr[k];
			break;
		}
	}

	if(cmai) {
		cmi->is_recognized = 1;
		cmi->decompressor = cmai->decompressor;
	}
	else {
		for(k=0; k<DE_ARRAYCOUNT(other_known_cmpr_methods); k++) {
			if(other_known_cmpr_methods[k] == cmi->uniq_id) {
				cmi->is_recognized = 1;
				break;
			}
		}
	}

	if(cmai && cmai->descr) {
		de_strlcpy(cmi->descr, cmai->descr, sizeof(cmi->descr));
	}
	else if(cmi->is_recognized) {
		de_strlcpy(cmi->descr, "recognized, but no info avail.", sizeof(cmi->descr));
	}
	else {
		de_strlcpy(cmi->descr, "?", sizeof(cmi->descr));
	}
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	u32 crc_calc;
	int tsidx;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(!md->cmi) goto done;
	if(md->is_special) {
		de_dbg(c, "[not extracting special file]");
		goto done;
	}
	else if(md->is_dir) {
		;
	}
	else if(!(md->cmi->decompressor)) {
		if(!d->unsupp_warned) {
			de_info(c, "Note: LHA support is incomplete. Some common "
				"compression methods are not supported.");
			d->unsupp_warned = 1;
		}
		de_err(c, "%s: Unsupported compression method '%s'",
			ucstring_getpsz_d(md->fullfilename), md->cmi->id_printable_sz);
		goto done;
	}

	fi = de_finfo_create(c);

	for(tsidx=0; tsidx<DE_TIMESTAMPIDX_COUNT; tsidx++) {
		if(md->tsdata[tsidx].ts.is_valid) {
			fi->timestamp[tsidx] = md->tsdata[tsidx].ts;
		}
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}
	else if(md->is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(md->is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	de_finfo_set_name_from_ucstring(c, fi, md->fullfilename, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	de_crcobj_reset(d->crco);
	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->compressed_data_pos;
	dcmpri.len = md->compressed_data_len;
	dcmpro.f = outf;
	dcmpro.expected_len = md->orig_size;
	dcmpro.len_known = 1;

	if(md->is_dir) goto done; // For directories, we're done.

	if(md->cmi->decompressor) {
		md->cmi->decompressor(c, d, md, &dcmpri, &dcmpro, &dres);
	}

	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->fullfilename),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(crc_calc != md->crc16) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fullfilename));
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static int cksum_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf, i64 buf_len)
{
	UI *pcksum = (UI*)brctx->userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		*pcksum = (*pcksum + buf[i]) & 0xff;
	}
	return 1;
}

static void do_check_header_crc(deark *c, lctx *d, struct member_data *md)
{
	// LHA members don't have to have a header CRC field, though it's probably
	// considered best practice to have one when the checksum field doesn't
	// exist, or there are any extended headers.
	if(!md->have_hdr_crc_reported) return;
	de_crcobj_reset(d->crco);

	// Everything before the CRC field:
	de_crcobj_addslice(d->crco, c->infile, md->member_pos,
		md->hdr_crc_field_pos - md->member_pos);

	// The zeroed-out CRC field:
	de_crcobj_addzeroes(d->crco, 2);

	// Everything after the CRC field:
	de_crcobj_addslice(d->crco, c->infile, md->hdr_crc_field_pos+2,
		md->compressed_data_pos - (md->hdr_crc_field_pos+2));

	md->hdr_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "header crc (calculated): 0x%04x", (UI)md->hdr_crc_calc);
	if(md->hdr_crc_calc != md->hdr_crc_reported) {
		de_err(c, "Wrong header CRC: reported=0x%04x, calculated=0x%04x",
				(UI)md->hdr_crc_reported, (UI)md->hdr_crc_calc);
	}
}

enum lha_whats_next_enum {
	LHA_WN_MEMBER,
	LHA_WN_TRAILER,
	LHA_WN_TRAILER_AND_JUNK,
	LHA_WN_JUNK,
	LHA_WN_NOTHING
};

static enum lha_whats_next_enum lha_classify_whats_next(deark *c, lctx *d, i64 pos, i64 len)
{
	u8 b[21];

	if(len<=0) return LHA_WN_NOTHING;
	b[0] = de_getbyte(pos);
	if(b[0]==0 && len<=2) return LHA_WN_TRAILER;
	if(b[0]==0 && len<21) return LHA_WN_TRAILER_AND_JUNK;
	de_read(&b[1], pos+1, sizeof(b)-1);
	if(b[0]==0 && b[1]==0) return LHA_WN_TRAILER_AND_JUNK;
	if(b[0]==0 && b[20]!=2) return LHA_WN_TRAILER_AND_JUNK;
	if(b[20]>3) return LHA_WN_JUNK;
	if(is_possible_cmpr_meth(&b[2])) return LHA_WN_MEMBER;
	return LHA_WN_JUNK;
}

// This single function parses all the different header formats, using lots of
// "if" statements. It is messy, but it's a no-win situation.
// The alternative of four separate functions would be have a lot of redundant
// code, and be harder to maintain.
//
// Caller allocates and initializes md.
// If the member was successfully parsed, sets md->total_size and returns nonzero.
static int do_read_member(deark *c, lctx *d, struct member_data *md)
{
	int retval = 0;
	i64 lev0_header_size = 0;
	i64 lev1_base_header_size = 0;
	i64 lev1_skip_size = 0;
	i64 lev2_total_header_size = 0;
	i64 lev3_header_size = 0;
	i64 pos1 = md->member_pos;
	i64 pos = pos1;
	i64 nbytes_avail;
	i64 exthdr_bytes_consumed = 0;
	i64 fnlen = 0;
	UI attribs;
	UI hdr_checksum_reported = 0;
	u8 has_hdr_checksum = 0;
	int is_compressed;
	int ret;
	enum lha_whats_next_enum wn;
	u8 cmpr_meth_raw[5];
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	nbytes_avail = c->infile->len - pos1;
	wn = lha_classify_whats_next(c, d, pos1, nbytes_avail);
	if(wn!=LHA_WN_MEMBER) {
		if(d->member_count==0) {
			de_err(c, "Not an LHA file");
		}
		else if(wn==LHA_WN_TRAILER || wn==LHA_WN_TRAILER_AND_JUNK) {
			de_dbg(c, "trailer at %"I64_FMT, pos1);
			if(wn==LHA_WN_TRAILER_AND_JUNK) {
				de_info(c, "Note: %"I64_FMT" extra bytes at end of file (offset %"I64_FMT")",
					nbytes_avail-1, pos1+1);
			}
		}
		else if(wn==LHA_WN_JUNK) {
			de_warn(c, "%"I64_FMT" bytes of non-LHA data found at end of file (offset %"I64_FMT")",
				nbytes_avail, pos1);
		}
		goto done;
	}

	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// Look ahead to figure out the header format version.
	// This byte was originally the high byte of the "MS-DOS file attribute" field,
	// which happened to always be zero.
	// In later LHA versions, it is overloaded to identify the header format
	// version (called "header level" in LHA jargon).
	md->hlev = de_getbyte(pos1+20);
	de_dbg(c, "header level: %d", (int)md->hlev);
	if(md->hlev>3) {
		goto done; // Shouldn't be possible; checked in lha_classify_whats_next().
	}

	if(md->hlev==0) {
		lev0_header_size = (i64)de_getbyte_p(&pos);
		de_dbg(c, "header size: (2+)%d", (int)lev0_header_size);
		hdr_checksum_reported = (UI)de_getbyte_p(&pos);
		has_hdr_checksum = 1;
		dbuf_buffered_read(c->infile, pos, lev0_header_size, cksum_cbfn, (void*)&md->hdr_checksum_calc);
	}
	else if(md->hlev==1) {
		lev1_base_header_size = (i64)de_getbyte_p(&pos);
		de_dbg(c, "base header size: %d", (int)lev1_base_header_size);
		hdr_checksum_reported = (UI)de_getbyte_p(&pos);
		has_hdr_checksum = 1;
		dbuf_buffered_read(c->infile, pos, lev1_base_header_size, cksum_cbfn, (void*)&md->hdr_checksum_calc);
	}
	else if(md->hlev==2) {
		lev2_total_header_size = de_getu16le_p(&pos);
		de_dbg(c, "total header size: %d", (int)lev2_total_header_size);
	}
	else if(md->hlev==3) {
		i64 lev3_word_size;
		lev3_word_size = de_getu16le_p(&pos);
		de_dbg(c, "word size: %d", (int)lev3_word_size);
		if(lev3_word_size!=4) {
			de_err(c, "Unsupported word size: %d", (int)lev3_word_size);
			goto done;
		}
	}

	if(has_hdr_checksum) {
		de_dbg(c, "header checksum (reported): 0x%02x", hdr_checksum_reported);
		de_dbg(c, "header checksum (calculated): 0x%02x", md->hdr_checksum_calc);
		if(md->hdr_checksum_calc != hdr_checksum_reported) {
			de_err(c, "Wrong header checksum: reported=0x%02x, calculated=0x%02x",
				hdr_checksum_reported, md->hdr_checksum_calc);
		}
	}

	de_read(cmpr_meth_raw, pos, 5);
	md->cmi = de_malloc(c, sizeof(struct cmpr_meth_info));
	get_cmpr_meth_info(cmpr_meth_raw, md->cmi);
	de_dbg(c, "cmpr method: '%s' (%s)", md->cmi->id_printable_sz, md->cmi->descr);
	pos+=5;

	if(md->cmi->uniq_id == CODE_lhd) {
		is_compressed = 0;
		md->is_dir = 1;
	}
	else if(md->cmi->decompressor == decompress_uncompressed) {
		is_compressed = 0;
	}
	else {
		is_compressed = 1;
	}

	if(md->hlev==1) {
		// lev1_skip_size is the distance from the third byte of the extended
		// header section, to the end of the compressed data.
		lev1_skip_size = de_getu32le_p(&pos);
		de_dbg(c, "skip size: %u", (unsigned int)lev1_skip_size);
		md->total_size = 2 + lev1_base_header_size + lev1_skip_size;
	}
	else {
		md->compressed_data_len = de_getu32le(pos);
		de_dbg(c, "compressed size: %"I64_FMT, md->compressed_data_len);
		pos += 4;

		if(md->hlev==0) {
			md->total_size = 2 + lev0_header_size + md->compressed_data_len;
		}
		else if(md->hlev==2) {
			md->total_size = lev2_total_header_size + md->compressed_data_len;
		}
	}

	md->orig_size = de_getu32le(pos);
	de_dbg(c, "original size: %u", (unsigned int)md->orig_size);
	pos += 4;

	if(md->hlev==0 || md->hlev==1) {
		read_msdos_modtime(c, d, md, pos, "last-modified");
		pos += 4; // modification time/date (MS-DOS)
	}
	else if(md->hlev==2 || md->hlev==3) {
		read_unix_timestamp(c, d, md, pos, DE_TIMESTAMPIDX_MODIFY, "last-modified");
		pos += 4; // Unix time
	}

	attribs = (UI)de_getbyte_p(&pos);
	if(md->hlev==0) {
		de_ucstring *attr_descr;

		// This is a 2-byte field, but the high byte must be 0 here because it's
		// also the header level.
		attr_descr = ucstring_create(c);
		de_describe_dos_attribs(c, attribs, attr_descr, 0);
		de_dbg(c, "attribs: 0x%04x (%s)", attribs, ucstring_getpsz_d(attr_descr));
		ucstring_destroy(attr_descr);
	}
	else {
		de_dbg(c, "obsolete attribs low byte: 0x%02x", attribs);
	}
	pos++; // header level or high byte of attribs, already handled

	if(md->hlev<=1) {
		fnlen = de_getbyte(pos++);
		de_dbg(c, "filename len: %d", (int)fnlen);
		if(md->hlev==0) {
			read_filename_hlev0(c, d, md, pos, fnlen);
		}
		else {
			read_filename_hlev1_or_exthdr(c, d, md, pos, fnlen);
		}
		pos += fnlen;
	}

	md->crc16 = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc16 (reported): 0x%04x", (unsigned int)md->crc16);

	if(md->hlev==1 || md->hlev==2 || md->hlev==3) {
		md->os_id = de_getbyte_p(&pos);
		de_dbg(c, "OS id: %d ('%c') (%s)", (int)md->os_id,
			de_byte_to_printable_char(md->os_id), get_os_name(md->os_id));
	}

	if(md->hlev==3) {
		lev3_header_size = de_getu32le_p(&pos);
		md->total_size = lev3_header_size + md->compressed_data_len;
	}

	if(md->hlev==0) {
		i64 ext_headers_size = (2+lev0_header_size) - (pos-pos1);
		md->compressed_data_pos = pos1 + 2 + lev0_header_size;
		if(ext_headers_size>0) {
			de_dbg(c, "extended header area at %d, len=%d", (int)pos, (int)ext_headers_size);
			de_dbg_indent(c, 1);
			do_lev0_ext_area(c, d, md, pos, ext_headers_size);
			de_dbg_indent(c, -1);
		}
	}
	else if(md->hlev==1) {
		i64 first_ext_hdr_size;

		// The last two bytes of the base header are the size of the first ext. header.
		pos = pos1 + 2 + lev1_base_header_size - 2;
		// TODO: sanitize pos?
		first_ext_hdr_size = de_getu16le_p(&pos);
		de_dbg(c, "first ext hdr size: %d", (int)first_ext_hdr_size);

		ret = do_read_ext_headers(c, d, md, pos, lev1_skip_size, first_ext_hdr_size,
			&exthdr_bytes_consumed);

		if(!ret) {
			de_err(c, "Error parsing extended headers at %d. Cannot extract this file.",
				(int)pos);
			retval = 1;
			goto done;
		}

		pos += exthdr_bytes_consumed;
		md->compressed_data_pos = pos;
		md->compressed_data_len = lev1_skip_size - exthdr_bytes_consumed;
	}
	else if(md->hlev==2) {
		i64 first_ext_hdr_size;

		if(md->os_id=='K') {
			// So that some lhasa test files will work.
			// TODO: The extended headers section is (usually?) self-terminating, so we
			// should be able to parse it and figure out if this bug is present. That
			// would be better than just guessing.
			lev2_total_header_size += 2;
			md->total_size = lev2_total_header_size + md->compressed_data_len;
			de_dbg(c, "attempting bug workaround: changing total header size to %d",
				(int)lev2_total_header_size);
		}

		md->compressed_data_pos = pos1+lev2_total_header_size;

		first_ext_hdr_size = de_getu16le_p(&pos);
		de_dbg(c, "first ext hdr size: %d", (int)first_ext_hdr_size);

		do_read_ext_headers(c, d, md, pos, pos1+lev2_total_header_size-pos,
			first_ext_hdr_size, &exthdr_bytes_consumed);
	}
	else if(md->hlev==3) {
		i64 first_ext_hdr_size;

		md->compressed_data_pos = pos1+lev3_header_size;

		first_ext_hdr_size = de_getu32le_p(&pos);
		de_dbg(c, "first ext hdr size: %d", (int)first_ext_hdr_size);

		do_read_ext_headers(c, d, md, pos, pos1+lev3_header_size-pos,
			first_ext_hdr_size, &exthdr_bytes_consumed);
	}

	do_check_header_crc(c, d, md);

	de_dbg(c, "member data (%scompressed) at %"I64_FMT", len=%"I64_FMT,
		is_compressed?"":"un",
		md->compressed_data_pos, md->compressed_data_len);

	make_fullfilename(c, d, md);

	de_dbg_indent(c, 1);
	do_extract_file(c, d, md);
	de_dbg_indent(c, -1);

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_lha(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	struct member_data *md = NULL;

	d = de_malloc(c, sizeof(lctx));
	// It's not really safe to guess CP437, because Japanese-encoded (CP932?)
	// filenames are common.
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	pos = 0;
	while(1) {
		if(pos >= c->infile->len) break;

		md = de_malloc(c, sizeof(struct member_data));
		md->encoding = d->input_encoding;
		md->member_pos = pos;
		if(!do_read_member(c, d, md)) goto done;
		if(md->total_size<1) goto done;

		d->member_count++;
		pos += md->total_size;

		destroy_member_data(c, md);
		md = NULL;
	}

done:
	destroy_member_data(c, md);
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_lha(deark *c)
{
	int has_ext = 0;
	u8 b[22];
	struct cmpr_meth_info cmi;

	de_read(b, 0, sizeof(b));
	if(b[20]>3) return 0; // header level

	if(!is_possible_cmpr_meth(&b[2])) return 0;

	if(b[20]==0) {
		if(b[0]<22) return 0;
		if(22 + (int)b[21] + 2 > 2 + (int)b[0]) return 0;
	}
	else if(b[20]==1) {
		if(b[0]<25) return 0;
		if(22 + (int)b[21] + 5 > 2 + (int)b[0]) return 0;
	}
	else if(b[20]==2) {
		i64 hsize = de_getu16le_direct(&b[0]);
		if(hsize < 26) return 0;
	}
	else if(b[20]==3) {
		if((b[0]!=4 && b[0]!=8) || b[1]!=0) return 0;
	}

	de_zeromem(&cmi, sizeof(struct cmpr_meth_info));
	get_cmpr_meth_info(&b[2], &cmi);
	if(!cmi.is_recognized) {
		return 0;
	}

	if(de_input_file_has_ext(c, "lzh") ||
		de_input_file_has_ext(c, "lha"))
	{
		has_ext = 1;
	}

	if(has_ext) return 100;
	return 80; // Must be less than car_lha
}

void de_module_lha(deark *c, struct deark_module_info *mi)
{
	mi->id = "lha";
	mi->desc = "LHA/LZH/PMA archive";
	mi->run_fn = de_run_lha;
	mi->identify_fn = de_identify_lha;
}

/////////////////////// CAR (MylesHi!)

struct car_member_data {
	i64 member_pos;
	i64 total_size;
	UI hdr_checksum_calc;
};

struct car_ctx {
	dbuf *hdr_tmp;
	dbuf *lha_outf;
};

static int looks_like_car_member(deark *c, i64 pos)
{
	u8 b[16];

	de_read(b, pos, 16);
	if(b[2]!='-' || b[3]!='l'|| b[4]!='h' || b[6]!='-') return 0;
	if(b[5]!='0' && b[5]!='5') return 0;
	if((int)b[0] != (int)b[15] + 25) return 0;
	if(dbuf_memcmp(c->infile, pos + (i64)b[15] + 24, (const u8*)"\x20\x00\x00", 3)) return 0;
	return 1;
}

static int do_car_member(deark *c, struct car_ctx *d, struct car_member_data *md)
{
	i64 lev1_base_header_size;
	i64 fnlen;
	i64 hdr_endpos;
	i64 compressed_data_len;
	i64 pos1 = md->member_pos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// Figure out where everything is...
	lev1_base_header_size = (i64)de_getbyte(pos1);
	de_dbg(c, "base header size: %d", (int)lev1_base_header_size);
	hdr_endpos = pos1 + 2 + lev1_base_header_size;
	fnlen = lev1_base_header_size - 25;
	de_dbg(c, "implied filename len: %d", (int)fnlen);
	if(fnlen<0) goto done;

	compressed_data_len = de_getu32le(pos1 + 7);
	de_dbg(c, "compressed size: %"I64_FMT, compressed_data_len);
	if(hdr_endpos + compressed_data_len > c->infile->len) goto done;

	// Convert to an LHA level-1 header
	dbuf_empty(d->hdr_tmp);

	// Fields through uncmpr_size are the same (we'll patch the checksum later)
	dbuf_copy(c->infile, pos1, 15, d->hdr_tmp);

	dbuf_copy(c->infile, hdr_endpos-7, 4, d->hdr_tmp); // timestamp

	// attribute (low byte)
	dbuf_copy(c->infile, hdr_endpos-9, 1, d->hdr_tmp);
	dbuf_writebyte(d->hdr_tmp, 0x01); // level identifier

	// Fields starting with filename length, through crc
	dbuf_copy(c->infile, pos1+15, 1+fnlen+2, d->hdr_tmp);

	dbuf_writebyte(d->hdr_tmp, 77); // OS ID = 'M' = MS-DOS

	// Recalculate checksum
	dbuf_buffered_read(d->hdr_tmp, 2, lev1_base_header_size, cksum_cbfn,
		(void*)&md->hdr_checksum_calc);
	de_dbg(c, "header checksum (calculated): 0x%02x", md->hdr_checksum_calc);
	dbuf_writebyte_at(d->hdr_tmp, 1, (u8)md->hdr_checksum_calc);
	dbuf_truncate(d->hdr_tmp, 2+lev1_base_header_size);

	// Write everything out
	dbuf_copy(d->hdr_tmp, 0, d->hdr_tmp->len, d->lha_outf);
	de_dbg(c, "member data at %"I64_FMT", len=%"I64_FMT, hdr_endpos, compressed_data_len);
	dbuf_copy(c->infile, hdr_endpos, compressed_data_len, d->lha_outf);
	md->total_size = hdr_endpos + compressed_data_len;
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_car_lha(deark *c, de_module_params *mparams)
{
	struct car_ctx *d = NULL;
	struct car_member_data *md = NULL;
	int ok = 0;
	i64 pos = 0;

	d = de_malloc(c, sizeof(struct car_ctx));

	if(!looks_like_car_member(c, 0)) {
		de_err(c, "Not a CAR file");
		goto done;
	}

	d->lha_outf = dbuf_create_output_file(c, "lha", NULL, 0);
	d->hdr_tmp = dbuf_create_membuf(c, 0, 0);

	md = de_malloc(c, sizeof(struct car_member_data));
	while(1) {
		if(de_getbyte(pos)==0) {
			de_dbg(c, "trailer at %"I64_FMT, pos);
			dbuf_writebyte(d->lha_outf, 0);
			ok = 1;
			break;
		}
		if(pos+27 > c->infile->len) goto done;
		if(!looks_like_car_member(c, pos)) goto done;

		de_zeromem(md, sizeof(struct car_member_data));
		md->member_pos = pos;
		if(!do_car_member(c, d, md)) goto done;
		pos += md->total_size;
	}

done:
	de_free(c, md);
	if(d) {
		if(d->lha_outf) {
			dbuf_close(d->lha_outf);
			if(!ok) {
				de_err(c, "Conversion to LHA format failed");
			}
		}
		dbuf_close(d->hdr_tmp);
		de_free(c, d);
	}
}

static int de_identify_car_lha(deark *c)
{
	if(!de_input_file_has_ext(c, "car")) return 0;
	if(looks_like_car_member(c, 0)) {
		return 95;
	}
	return 0;
}

void de_module_car_lha(deark *c, struct deark_module_info *mi)
{
	mi->id = "car_lha";
	mi->desc = "CAR (MylesHi!) LHA-like archive";
	mi->run_fn = de_run_car_lha;
	mi->identify_fn = de_identify_car_lha;
}
