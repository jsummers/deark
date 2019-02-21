// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// LHA/LZH compressed archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_lha);

#define CODE_lh0 0x6c6830U
#define CODE_lhd 0x6c6864U

struct member_data {
	u8 hlev; // header level
	i64 total_size;
	struct de_stringreaderdata *cmpr_method;
	u32 cmpr_meth_code;
	int is_dir;
	i64 orig_size;
	u32 crc16;
	u8 os_id;
	int codepage_encoding; // Encoding based on the "codepage" ext hdr
	i64 compressed_data_pos; // relative to beginning of file
	i64 compressed_data_len;
	de_ucstring *dirname;
	de_ucstring *filename;
	de_ucstring *fullfilename;
	struct de_timestamp mod_time; // The best timestamp found so far
	int mod_time_quality;
};

typedef struct localctx_struct {
	int member_count;
	int try_to_extract;
	struct de_crcobj *crco;
} lctx;

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

static void apply_mod_time(deark *c, lctx *d, struct member_data *md,
	const struct de_timestamp *ts, int quality)
{
	if(!ts->is_valid) return;
	if(quality < md->mod_time_quality) return;
	md->mod_time = *ts;
	md->mod_time_quality = quality;
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
	apply_mod_time(c, d, md, &tmp_timestamp, 10);
}

static void read_windows_FILETIME(deark *c, lctx *d, struct member_data *md,
	i64 pos, int is_modtime, const char *name)
{
	i64 t_FILETIME;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	t_FILETIME = de_geti64le(pos);
	de_FILETIME_to_timestamp(t_FILETIME, &tmp_timestamp, 0x1);
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
	if(is_modtime) apply_mod_time(c, d, md, &tmp_timestamp, 90);
}

static void read_unix_timestamp(deark *c, lctx *d, struct member_data *md,
	i64 pos, int is_modtime, const char *name)
{
	i64 t;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, &tmp_timestamp, 0x1);
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %d (%s)", name, (int)t, timestamp_buf);
	if(is_modtime) apply_mod_time(c, d, md, &tmp_timestamp, 50);
}

static void read_filename(deark *c, lctx *d, struct member_data *md,
	i64 pos, i64 len)
{
	i64 i;

	md->filename = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len,
		md->filename, 0, DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));

	if(md->hlev==0) {
		// Slashes (usually backslashes) allowed
		for(i=0; i<md->filename->len; i++) {
			if(md->filename->str[i]=='\\') {
				md->filename->str[i]='/';
			}
		}
	}
	else {
		// I don't think slashes are allowed
		for(i=0; i<md->filename->len; i++) {
			if(md->filename->str[i]=='/') {
				md->filename->str[i]='_';
			}
		}
	}
}

static void exthdr_common(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	u32 crchdr;

	if(dlen<2) return;
	crchdr = (u32)de_getu16le(pos);
	de_dbg(c, "crc16 of header (reported): 0x%04x", (unsigned int)crchdr);
	// TODO: Additional information
}

static void exthdr_filename(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	read_filename(c, d, md, pos, dlen);
}

static void exthdr_dirname(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	i64 i;
	int ends_with_ff = 0;

	if(md->dirname) {
		ucstring_empty(md->dirname);
	}
	else {
		md->dirname = ucstring_create(c);
	}

	dbuf_read_to_ucstring(c->infile, pos, dlen,
		md->dirname, 0, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", e->name, ucstring_getpsz(md->dirname));

	// Fixup dir name.
	// (This is slightly hacky. It would be cleaner to handle the special
	// 0xff bytes *before* converting to ucstring format.)
	for(i=0; i<md->dirname->len; i++) {
		if(md->dirname->str[i]==DE_CODEPOINT_BYTEFF) {
			if(i==md->dirname->len-1) {
				ends_with_ff = 1;
			}
			md->dirname->str[i] = '/';
		}
		else if(md->dirname->str[i]=='/') {
			md->dirname->str[i] = '_';
		}
	}

	if(ends_with_ff) {
		ucstring_truncate(md->dirname, md->dirname->len - 1);
	}
}

static void exthdr_msdosattribs(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	u32 attribs;

	if(dlen<2) return;
	attribs = (u32)de_getu16le(pos);
	de_dbg(c, "%s: 0x%04x", e->name, (unsigned int)attribs);
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
	read_windows_FILETIME(c, d, md, pos,    0, "create time");
	read_windows_FILETIME(c, d, md, pos+8,  1, "mod time   ");
	read_windows_FILETIME(c, d, md, pos+16, 0, "access time");
}

static void exthdr_unixperms(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	i64 mode;

	if(dlen<2) return;
	mode = de_getu16le(pos);
	de_dbg(c, "mode: octal(%06o)", (unsigned int)mode);
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
	read_unix_timestamp(c, d, md, pos, 1, "last-modified");
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
	read_unix_timestamp(c, d, md, pos+12, 0, "create(?) time");

	read_unix_timestamp(c, d, md, pos+16, 0, "access time   ");
}

static void exthdr_codepage(deark *c, lctx *d, struct member_data *md,
	u8 id, const struct exthdr_type_info_struct *e,
	i64 pos, i64 dlen)
{
	int n;
	char descr[100];

	if(dlen!=4) return;
	n = (int)de_geti32le(pos);
	md->codepage_encoding = de_windows_codepage_to_encoding(c, n, descr, sizeof(descr), 0);
	de_dbg(c, "codepage: %d (%s)", n, descr);
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
	de_destroy_stringreaderdata(c, md->cmpr_method);
	ucstring_destroy(md->dirname);
	ucstring_destroy(md->filename);
	ucstring_destroy(md->fullfilename);
	de_free(c, md);
}

static const struct exthdr_type_info_struct *get_exthdr_type_info(u8 id)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(exthdr_type_info_arr); i++) {
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

static void do_lev0_ext_area(deark *c, lctx *d, struct member_data *md,
	i64 pos1, i64 len)
{
	if(len<1) return;
	md->os_id = de_getbyte(pos1);
	de_dbg(c, "OS id: %d ('%c')", (int)md->os_id,
		de_byte_to_printable_char(md->os_id));

	// TODO: Finish this
	if(md->os_id=='U') {
		i64 mode;
		i64 uid, gid;

		if(len<12) goto done;

		read_unix_timestamp(c, d, md, pos1+2, 1, "last-modified");

		mode = de_getu16le(pos1+6);
		de_dbg(c, "mode: octal(%06o)", (unsigned int)mode);

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
			ucstring_append_ucstring(md->fullfilename, md->filename);
		}
	}
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	u32 crc_calc;

	if(!d->try_to_extract) return;
	if(md->is_dir) {
		;
	}
	else if(md->cmpr_meth_code==CODE_lh0) {
		;
	}
	else {
		de_err(c, "%s: Unsupported compression method",
			ucstring_getpsz_d(md->fullfilename));
		return;
	}

	fi = de_finfo_create(c);

	fi->mod_time = md->mod_time;

	if(md->is_dir) {
		fi->is_directory = 1;
	}

	de_finfo_set_name_from_ucstring(c, fi, md->fullfilename, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	if(!d->crco) {
		d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	}
	else {
		de_crcobj_reset(d->crco);
	}
	outf->userdata = (void*)d->crco;
	outf->writecallback_fn = our_writecallback;

	dbuf_copy(c->infile, md->compressed_data_pos, md->compressed_data_len, outf);

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(crc_calc != md->crc16) {
		de_err(c, "CRC check failed");
	}

	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

// This single function parses all the different header formats, using lots of
// "if" statements. It is messy, but it's a no-win situation.
// The alternative of four separate functions would be have a lot of redundant
// code, and be harder to maintain.
//
// Caller allocates and initializes md.
static int do_read_member(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	int retval = 0;
	i64 lev0_header_size = 0;
	i64 lev1_base_header_size = 0;
	i64 lev1_skip_size = 0;
	i64 lev2_total_header_size = 0;
	i64 lev3_header_size = 0;
	i64 pos = pos1;
	i64 exthdr_bytes_consumed = 0;
	i64 fnlen = 0;
	int is_compressed;
	int ret;

	if(c->infile->len - pos1 < 21) {
		goto done;
	}

	de_dbg(c, "member at %d", (int)pos);
	de_dbg_indent(c, 1);

	// Read this first, to help decide whether this is LHA data at all.
	md->cmpr_method = dbuf_read_string(c->infile, pos1+2, 5, 5, 0, DE_ENCODING_ASCII);
	if(md->cmpr_method->sz[0]!='-' || md->cmpr_method->sz[4]!='-') {
		if(d->member_count==0) {
			de_err(c, "Not an LHA file");
			goto done;
		}
		else {
			de_warn(c, "Extra non-LHA data found at end of file (offset %d)", (int)pos1);
			goto done;
		}
	}

	md->cmpr_meth_code = (u32)(u8)md->cmpr_method->sz[1] << 16;
	md->cmpr_meth_code |= (u32)(u8)md->cmpr_method->sz[2] << 8;
	md->cmpr_meth_code |= (u32)(u8)md->cmpr_method->sz[3];

	// Look ahead to figure out the header format version.
	// This byte was originally the high byte of the "MS-DOS file attribute" field,
	// which happened to always be zero.
	// In later LHA versions, it is overloaded to identify the header format
	// version (called "header level" in LHA jargon).
	md->hlev = de_getbyte(pos+20);
	de_dbg(c, "header level: %d", (int)md->hlev);
	if(md->hlev>3) {
		de_err(c, "Invalid or unsupported header level: %d", (int)md->hlev);
		goto done;
	}

	if(md->hlev==0) {
		lev0_header_size = (i64)de_getbyte_p(&pos);
		de_dbg(c, "header size: (2+)%d", (int)lev0_header_size);
		pos++; // Cksum
	}
	else if(md->hlev==1) {
		lev1_base_header_size = (i64)de_getbyte_p(&pos);
		de_dbg(c, "base header size: %d", (int)lev1_base_header_size);
		pos++; // Cksum
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

	// This field was read earlier.
	de_dbg(c, "cmpr method: \"%s\"", ucstring_getpsz(md->cmpr_method->str));
	pos+=5;

	if(md->cmpr_meth_code==CODE_lhd) {
		is_compressed = 0;
		md->is_dir = 1;
	}
	else if(md->cmpr_meth_code==CODE_lh0) {
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
		read_unix_timestamp(c, d, md, pos, 1, "last-modified");
		pos += 4; // Unix time
	}

	if(md->hlev==0) {
		pos += 2; // MS-DOS file attributes
	}
	else if(md->hlev==1 || md->hlev==2 || md->hlev==3) {
		pos++; // reserved
		pos++; // header level
	}

	if(md->hlev<=1) {
		fnlen = de_getbyte(pos++);
		de_dbg(c, "filename len: %d", (int)fnlen);
		read_filename(c, d, md, pos, fnlen);
		pos += fnlen;
	}

	md->crc16 = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc16 (reported): 0x%04x", (unsigned int)md->crc16);

	if(md->hlev==1 || md->hlev==2 || md->hlev==3) {
		md->os_id = de_getbyte_p(&pos);
		de_dbg(c, "OS id: %d ('%c')", (int)md->os_id,
			de_byte_to_printable_char(md->os_id));
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

	de_dbg(c, "%scompressed member data at %"I64_FMT", len=%"I64_FMT,
		is_compressed?"":"un",
		md->compressed_data_pos, md->compressed_data_len);

	make_fullfilename(c, d, md);

	do_extract_file(c, d, md);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_lha(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	struct member_data *md = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->try_to_extract = de_get_ext_option_bool(c, "lha:extract", -1);
	if(d->try_to_extract == -1) {
		de_info(c, "Note: LHA files can be parsed, but no files can be extracted from them.");
		d->try_to_extract = 0;
	}

	pos = 0;
	while(1) {
		if(pos >= c->infile->len) break;

		md = de_malloc(c, sizeof(struct member_data));
		if(!do_read_member(c, d, md, pos)) goto done;
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
	u8 b[7];

	de_read(b, 0, 7);
	if(b[2]!='-' || b[6]!='-') return 0;
	if(b[3]=='l') {
		if(b[4]=='h' || b[4]=='z') {
			return 100;
		}
	}
	else if(b[3]=='p') {
		if(b[4]=='c' || b[4]=='m') {
			return 100;
		}
	}
	return 0;
}


static void de_help_lha(deark *c)
{
	de_msg(c, "-opt lha:extract : Extract when possible (uncompressed files only)");
}

void de_module_lha(deark *c, struct deark_module_info *mi)
{
	mi->id = "lha";
	mi->desc = "LHA/LZW/PMA archive";
	mi->run_fn = de_run_lha;
	mi->identify_fn = de_identify_lha;
	mi->help_fn = de_help_lha;
}
