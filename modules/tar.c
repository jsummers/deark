// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Tar archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_tar);

// Represents a single physical header block, and the associated data that
// follows it.
// Sometimes, a logical member file is composed of multiple physical members.
struct phys_member_data {
#define TARFMT_UNKNOWN  0
#define TARFMT_POSIX    1
#define TARFMT_GNU      2
#define TARFMT_STAR     3
	int fmt;
	u8 linkflag;
	i64 mode;
	i64 modtime_unix;
	struct de_timestamp mod_time;
	i64 file_data_pos;
	i64 filesize;
	i64 checksum;
	i64 checksum_calc;
	de_ucstring *name;
	struct de_stringreaderdata *linkname;
	de_ucstring *prefix;
};

// A struct to collect various exended attributes from a logical member
// (or for global attributes).
struct extattr_data {
	de_ucstring *alt_name;
	de_ucstring *linkname;
	struct de_timestamp alt_mod_time;
	u8 main_file_is_special;
	u8 has_alt_size;
	i64 alt_size;
};

struct member_data {
	de_ucstring *filename;
	de_finfo *fi;
	int is_dir, is_regular_file, is_symlink;
};

typedef struct localctx_struct {
	int input_encoding;
	int found_trailer;
	struct extattr_data *global_ea;
} lctx;

static const char* get_fmt_name(int fmt)
{
	const char *n = "unknown or old-style";
	switch(fmt) {
	case TARFMT_POSIX: n = "POSIX"; break;
	case TARFMT_GNU: n = "GNU"; break;
	case TARFMT_STAR: n = "star"; break;
	}
	return n;
}

static int read_ascii_octal_number(dbuf *f, i64 pos, i64 fieldsize,
	i64 *value)
{
	u8 b1;
	b1 = dbuf_getbyte(f, pos);

	if(b1<0x80) {
		// The usual ASCII-octal format
		return dbuf_read_ascii_number(f, pos, fieldsize, 8, value);
	}

	// "base-256" or some other special format
	if(b1==0x80) { // positive base-256 number
		*value = dbuf_getint_ext(f, pos+1, (unsigned int)(fieldsize-1), 0, 0);
		return 1;
	}
	else if(b1==0xff) { // negative base-256 number
		*value = dbuf_getint_ext(f, pos+1, (unsigned int)(fieldsize-1), 0, 1);
		return 1;
	}

	*value = 0;
	return 0;
}

// Sets md->checksum_calc
static void calc_checksum(deark *c, lctx *d, struct phys_member_data *pmd,
	const u8 *hdrblock)
{
	size_t i;

	pmd->checksum_calc = 0;
	for(i=0; i<512; i++) {
		if(i>=148 && i<156)
			pmd->checksum_calc += 32; // (The checksum field itself)
		else
			pmd->checksum_calc += (i64)hdrblock[i];
	}
}

// Returns 1 if it was parsed successfully, and is not a trailer.
static int read_phys_member_header(deark *c, lctx *d,
	struct phys_member_data *pmd, i64 pos1)
{
	char timestamp_buf[64];
	i64 n;
	int ret;
	i64 pos = pos1;
	de_ucstring *tmpstr = NULL;
	int retval = 0;
	int saved_indent_level;
	u8 hdrblock[512];

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "physical archive member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// Look ahead to try to figure out some things about the format of this member.

	de_read(hdrblock, pos1, 512);
	calc_checksum(c, d, pmd, hdrblock);

	if(pmd->checksum_calc==8*32 && de_is_all_zeroes(&hdrblock[148], 8)) {
		// "The end of the archive is indicated by two records consisting
		// entirely of zero bytes."
		// Most tar programs seem to stop at the first "zero block", so that's
		// what we'll do.
		de_dbg(c, "[trailer record]");
		d->found_trailer = 1;
		goto done;
	}

	pmd->linkflag = hdrblock[156];

	if(!de_memcmp(&hdrblock[257], (const void*)"ustar  \0", 8)) {
		pmd->fmt = TARFMT_GNU;
	}
	else if(!de_memcmp(&hdrblock[257], (const void*)"ustar\0", 6)) {
		pmd->fmt = TARFMT_POSIX;
	}
	else if(!de_memcmp(&hdrblock[508], (const void*)"tar\0", 4)) {
		pmd->fmt = TARFMT_STAR;
	}

	de_dbg(c, "tar format: %s", get_fmt_name(pmd->fmt));

	pmd->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 100, pmd->name, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	pos += 100;
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(pmd->name));

	ret = read_ascii_octal_number(c->infile, pos, 8, &pmd->mode);
	if(ret) {
		de_dbg(c, "mode: octal(%06o)", (unsigned int)pmd->mode);
	}
	pos += 8;

	ret = read_ascii_octal_number(c->infile, pos, 8, &n);
	if(ret) {
		de_dbg(c, "uid: %"I64_FMT, n);
	}
	pos += 8;
	ret = read_ascii_octal_number(c->infile, pos, 8, &n);
	if(ret) {
		de_dbg(c, "gid: %"I64_FMT, n);
	}
	pos += 8;

	ret = read_ascii_octal_number(c->infile, pos, 12, &pmd->filesize);
	if(!ret) goto done;
	pos += 12;
	de_dbg(c, "size: %"I64_FMT, pmd->filesize);
	pmd->file_data_pos = pos1 + 512;

	ret = read_ascii_octal_number(c->infile, pos, 12, &pmd->modtime_unix);
	if(ret) {
		de_unix_time_to_timestamp(pmd->modtime_unix, &pmd->mod_time, 0x1);
		de_dbg_timestamp_to_string(c, &pmd->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "mtime: %"I64_FMT" (%s)", pmd->modtime_unix, timestamp_buf);
	}
	pos += 12;

	(void)read_ascii_octal_number(c->infile, pos, 8, &pmd->checksum);
	de_dbg(c, "header checksum (reported): %"I64_FMT, pmd->checksum);
	de_dbg(c, "header checksum (calculated): %"I64_FMT, pmd->checksum_calc);
	if(pmd->checksum != pmd->checksum_calc) {
		de_err(c, "%s: Header checksum failed: reported=%"I64_FMT", calculated=%"I64_FMT,
			ucstring_getpsz_d(pmd->name), pmd->checksum, pmd->checksum_calc);
	}
	pos += 8;

	// linkflag already set, above
	de_dbg(c, "linkflag/typeflag: 0x%02x ('%c')", (unsigned int)pmd->linkflag,
		de_byte_to_printable_char(pmd->linkflag));
	pos += 1;

	if(de_getbyte(pos)!=0) {
		pmd->linkname = dbuf_read_string(c->infile, pos, 100, 100, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding);
		de_dbg(c, "linkname: \"%s\"", ucstring_getpsz_d(pmd->linkname->str));
	}
	pos += 100;

	tmpstr = ucstring_create(c);

	if(c->debug_level>=2) {
		ucstring_empty(tmpstr);
		dbuf_read_to_ucstring(c->infile, pos, 8, tmpstr, 0,
			DE_ENCODING_PRINTABLEASCII);
		de_dbg2(c, "magic/version: \"%s\"", ucstring_getpsz_d(tmpstr));
	}
	pos += 6; // magic
	pos += 2; // version

	if(pmd->fmt==TARFMT_POSIX || pmd->fmt==TARFMT_GNU) {
		ucstring_empty(tmpstr);
		dbuf_read_to_ucstring(c->infile, pos, 32, tmpstr, DE_CONVFLAG_STOP_AT_NUL,
			DE_ENCODING_ASCII);
		de_dbg(c, "uname: \"%s\"", ucstring_getpsz(tmpstr));
	}
	pos += 32;

	if(pmd->fmt==TARFMT_POSIX || pmd->fmt==TARFMT_GNU) {
		ucstring_empty(tmpstr);
		dbuf_read_to_ucstring(c->infile, pos, 32, tmpstr, DE_CONVFLAG_STOP_AT_NUL,
			DE_ENCODING_ASCII);
		de_dbg(c, "gname: \"%s\"", ucstring_getpsz(tmpstr));
	}
	pos += 32;

	pos += 8; // devmajor
	pos += 8; // devminor

	if((pmd->fmt==TARFMT_POSIX || pmd->fmt==TARFMT_STAR) && (de_getbyte(pos)!=0)) {
		// This field might only be 131 bytes, instead of 155. Let's hope that
		// that it's NUL terminated in that case.
		pmd->prefix = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, 155, pmd->prefix,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "prefix: \"%s\"", ucstring_getpsz_d(pmd->prefix));
	}
	pos += 131; // first 133 bytes of prefix, or all of prefix
	pos += 12; // next 12 bytes of prefix, or atime
	pos += 12; // last 12 bytes of prefix, or ctime

	pos += 12; // pad

	retval = 1;

done:
	ucstring_destroy(tmpstr);

	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void destroy_pmd(deark *c, struct phys_member_data *pmd)
{
	if(!pmd) return;
	ucstring_destroy(pmd->name);
	de_destroy_stringreaderdata(c, pmd->linkname);
	ucstring_destroy(pmd->prefix);
	de_free(c, pmd);
}

static void destroy_extattr_data(deark *c, struct extattr_data *ea)
{
	if(!ea) return;
	ucstring_destroy(ea->alt_name);
	ucstring_destroy(ea->linkname);
}

static void read_gnu_longpath(deark *c, lctx *d, struct phys_member_data *pmd,
	struct extattr_data *ea)
{
	i64 pos = pmd->file_data_pos;
	i64 ext_name_len = pmd->filesize;

	de_dbg(c, "LongPath data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	if(ext_name_len<1) goto done;

	if(pmd->linkflag=='K') {
		if(!ea->linkname) {
			ea->linkname = ucstring_create(c);
		}
		ucstring_empty(ea->linkname);
		// TODO: It's a little inconsistent that we convert a GNU extended linkname
		// to a ucstring, while we keep the original bytes of old-style linknames.
		dbuf_read_to_ucstring_n(c->infile, pos, ext_name_len-1, 32767, ea->linkname, 0,
			d->input_encoding);
		de_dbg(c, "ext. linkname: \"%s\"", ucstring_getpsz_d(ea->linkname));
	}
	else { // 'L', presumably
		if(!ea->alt_name) {
			ea->alt_name = ucstring_create(c);
		}
		ucstring_empty(ea->alt_name);
		dbuf_read_to_ucstring_n(c->infile, pos, ext_name_len-1, 32767, ea->alt_name, 0,
			d->input_encoding);
		de_dbg(c, "ext. filename: \"%s\"", ucstring_getpsz_d(ea->alt_name));
	}

done:
	de_dbg_indent(c, -1);
}

struct exthdr_item {
	i64 base_pos;
	i64 fieldlen;
	i64 fieldlen_offs;
	i64 fieldlen_len;
	i64 name_offs;
	i64 name_len;
	i64 val_offs;
	i64 val_len;
	struct de_stringreaderdata *name;
	struct de_stringreaderdata *value;
};

static void do_exthdr_mtime(deark *c, lctx *d, struct phys_member_data *pmd,
	struct exthdr_item *ehi, struct extattr_data *ea)
{
	double val_dbl;
	double val_frac;
	i64 val_int;
	char timestamp_buf[64];

	if(ehi->val_len<1) return;

	// TODO: There is probably roundoff error here than there needs to be.
	val_dbl = de_strtod(ehi->value->sz, NULL);
	if(val_dbl > 0.0) {
		val_int = (i64)val_dbl;
		val_frac = val_dbl - (double)val_int;
	}
	else {
		val_int = (i64)val_dbl;
		val_frac = 0.0;
	}

	de_unix_time_to_timestamp(val_int, &ea->alt_mod_time, 0x1);
	if(val_frac > 0.0) {
		de_timestamp_set_subsec(&ea->alt_mod_time, val_frac);
	}

	de_dbg_timestamp_to_string(c, &ea->alt_mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static int read_exthdr_item(deark *c, lctx *d, struct phys_member_data *pmd,
	struct extattr_data *ea,
	i64 pos1, i64 max_len, i64 *bytes_consumed)
{
	struct exthdr_item *ehi = NULL;
	int retval = 0;
	int ret;
	int saved_indent_level;
	i64 offs;
	i64 n;
	enum {
		STATE_LOOKING_FOR_LEN, STATE_READING_LEN,
		STATE_LOOKING_FOR_NAME, STATE_READING_NAME, STATE_DONE
	} state;

	state = STATE_LOOKING_FOR_LEN;
	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "extended header field at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	ehi = de_malloc(c, sizeof(struct exthdr_item));
	ehi->base_pos = pos1;

	if(max_len<1) {
		goto done;
	}

	// Parse one header item. We will read the initial "length" field
	// immediately, because it is needed for proper parsing.
	// For the name and value fields, we only record their location and size.
	for(offs=0; ; offs++) {
		u8 ch;
		int is_whitespace;

		if(state==STATE_DONE) break;

		if(offs>=max_len) goto done;

		// If we know the reported length of this item, enforce it.
		if(state>STATE_READING_LEN && offs>=ehi->fieldlen) goto done;

		ch = de_getbyte(pos1+offs);
		is_whitespace = (ch==' ' || ch==0x09);

		if(state==STATE_LOOKING_FOR_LEN) {
			if(is_whitespace) continue;
			ehi->fieldlen_offs = offs;
			state = STATE_READING_LEN;
		}
		else if(state==STATE_READING_LEN) {
			if(is_whitespace) {
				ehi->fieldlen_len = offs - ehi->fieldlen_offs;
				ret = dbuf_read_ascii_number(c->infile,
					pos1+ehi->fieldlen_offs, ehi->fieldlen_len, 10, &ehi->fieldlen);
				if(!ret) {
					goto done;
				}
				de_dbg(c, "length: %d", (int)ehi->fieldlen);
				if(ehi->fieldlen > max_len) {
					goto done;
				}
				state = STATE_LOOKING_FOR_NAME;
			}
		}
		else if(state==STATE_LOOKING_FOR_NAME) {
			if(is_whitespace) continue;
			ehi->name_offs = offs;
			state = STATE_READING_NAME;
		}
		else if(state==STATE_READING_NAME) {
			if(ch=='=') {
				ehi->name_len = offs - ehi->name_offs;
				ehi->val_offs = offs+1;
				ehi->val_len = ehi->fieldlen - offs - 2;
				if(ehi->val_len<0) goto done;
				state = STATE_DONE;
			}
		}
	}

	// Sanity check: The item must end with a newline
	if(de_getbyte(pos1+ehi->fieldlen-1) != 0x0a) {
		goto done;
	}

	n = de_min_int(ehi->name_len, 256);
	ehi->name = dbuf_read_string(c->infile, pos1+ehi->name_offs,
		n, n, 0, DE_ENCODING_UTF8);
	de_dbg(c, "keyword: \"%s\"", ucstring_getpsz_d(ehi->name->str));

	n = de_min_int(ehi->val_len, 65536);
	ehi->value = dbuf_read_string(c->infile, pos1+ehi->val_offs,
		n, n, 0, DE_ENCODING_UTF8);de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(ehi->value->str));

	if(!de_strncmp(ehi->name->sz, "GNU.sparse.", 11)) {
		ea->main_file_is_special = 1;
	}

	if(!de_strcmp(ehi->name->sz, "path") ||
		!de_strcmp(ehi->name->sz, "GNU.sparse.name"))
	{
		if(!ea->alt_name) ea->alt_name = ucstring_create(c);
		ucstring_empty(ea->alt_name);
		ucstring_append_ucstring(ea->alt_name, ehi->value->str);
	}
	else if(!de_strcmp(ehi->name->sz, "linkpath")) {
		if(!ea->linkname) ea->linkname = ucstring_create(c);
		ucstring_empty(ea->linkname);
		ucstring_append_ucstring(ea->linkname, ehi->value->str);
	}
	else if(!de_strcmp(ehi->name->sz, "mtime")) {
		do_exthdr_mtime(c, d, pmd, ehi, ea);
	}
	else if(!de_strcmp(ehi->name->sz, "size")) {
		if(ehi->val_len==0) {
			ea->has_alt_size = 0;
		}
		else {
			ea->has_alt_size = 1;
			ea->alt_size = de_strtoll(ehi->value->sz, NULL, 10);
		}
	}
	// TODO: "hdrcharset"

	*bytes_consumed = ehi->fieldlen;
	retval = 1;

done:
	if(!retval) {
		de_warn(c, "Failed to parse extended header at %"I64_FMT, pos1);
	}
	if(ehi) {
		de_destroy_stringreaderdata(c, ehi->name);
		de_destroy_stringreaderdata(c, ehi->value);
		de_free(c, ehi);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void read_exthdr(deark *c, lctx *d, struct phys_member_data *pmd,
	struct extattr_data *ea)
{
	int saved_indent_level;
	i64 pos = pmd->file_data_pos;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "POSIX extended header data at %"I64_FMT, pmd->file_data_pos);
	de_dbg_indent(c, 1);

	if(c->debug_level>=2) {
		de_ucstring *tmps;
		tmps = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, pmd->file_data_pos, pmd->filesize,
			32768, tmps, 0, DE_ENCODING_UTF8);
		de_dbg(c, "data: \"%s\"", ucstring_getpsz_d(tmps));
		ucstring_destroy(tmps);
	}

	while(pos < pmd->file_data_pos + pmd->filesize) {
		i64 bytes_consumed = 0;

		if(!read_exthdr_item(c, d, pmd, ea, pos,
			pmd->file_data_pos+pmd->filesize-pos, &bytes_consumed))
		{
			break;
		}
		if(bytes_consumed<1) break;
		pos += bytes_consumed;
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

static int read_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed_member)
{
	int saved_indent_level;
	int retval = 0;
	struct member_data *md = NULL;
	struct phys_member_data *pmd = NULL;
	struct extattr_data *ea = NULL;
	dbuf *outf = NULL;
	unsigned int snflags;
	i64 pos = pos1;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "logical archive member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct member_data));
	md->fi = de_finfo_create(c);
	md->fi->detect_root_dot_dir = 1;
	md->filename = ucstring_create(c);

	ea = de_malloc(c, sizeof(struct extattr_data));

	while(1) {
		int is_supplemental_item = 0;

		if(pos >= c->infile->len) goto done;
		if(pmd) {
			destroy_pmd(c, pmd);
		}
		pmd = de_malloc(c, sizeof(struct phys_member_data));

		if(!read_phys_member_header(c, d, pmd, pos)) {
			goto done;
		}
		pos += 512;

		if(pmd->linkflag=='L' || pmd->linkflag=='K') {
			is_supplemental_item = 1;
			read_gnu_longpath(c, d, pmd, ea);
		}
		else if(pmd->linkflag == 'x' || pmd->linkflag == 'X') {
			is_supplemental_item = 1;
			read_exthdr(c, d, pmd, ea);
		}
		else if(pmd->linkflag == 'g') {
			read_exthdr(c, d, pmd, d->global_ea);
		}
		// TODO: linkflag 'K'

		if(!is_supplemental_item) {
			break;
		}

		// Prepare to read the next physical member
		pos += de_pad_to_n(pmd->filesize, 512);
	}
	if(!pmd) goto done;

	// At this point, pmd is the main physical member for this logical file.
	// Any other pmd's have been discarded, other than extended attributes
	// that were recorded in ea.

	if(ea->has_alt_size) {
		pmd->filesize = ea->alt_size;
	}
	pos += de_pad_to_n(pmd->filesize, 512);

	retval = 1;

	if((pmd->checksum != pmd->checksum_calc) && c->extract_level<2) {
		// TODO: This little more than a hack, so that we don't extract so
		// much garbage if the file is corrupt, or we go off the rails.
		// There are more robust ways to deal with such issues.
		de_dbg(c, "[not extracting, due to bad checksum]");
		goto done;
	}

	// Decide on a filename
	if(ucstring_isnonempty(ea->alt_name)) {
		ucstring_append_ucstring(md->filename, ea->alt_name);
	}
	else {
		if(ucstring_isnonempty(pmd->prefix)) {
			ucstring_append_ucstring(md->filename, pmd->prefix);
			ucstring_append_char(md->filename, '/');
		}
		if(ucstring_isnonempty(pmd->name)) {
			ucstring_append_ucstring(md->filename, pmd->name);
		}
	}

	// Try to figure out what kind of "file" this is.

	if(pmd->linkflag=='2') {
		md->is_symlink = 1;
	}
	else if(pmd->fmt==TARFMT_POSIX || pmd->fmt==TARFMT_STAR) {
		if(pmd->linkflag=='0' || pmd->linkflag==0) {
			md->is_regular_file = 1;
		}
		else if(pmd->linkflag=='5') {
			md->is_dir = 1;
		}
	}
	else if(pmd->fmt==TARFMT_GNU) {
		if(pmd->linkflag=='0' || pmd->linkflag=='7' || pmd->linkflag==0) {
			md->is_regular_file = 1;
		}
		else if(pmd->linkflag=='5') {
			md->is_dir = 1;
		}
	}
	else {
		if(pmd->name->len>=1 && pmd->name->str[pmd->name->len-1]=='/') {
			md->is_dir = 1;
		}
		else if(pmd->linkflag==0 || pmd->linkflag=='0') {
			md->is_regular_file = 1;
		}
	}

	if(ea->main_file_is_special) {
		md->is_regular_file = 0;
	}

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, pmd->file_data_pos,
		pmd->filesize);

	if(ea->alt_mod_time.is_valid) {
		md->fi->mod_time = ea->alt_mod_time;
	}
	else if(pmd->mod_time.is_valid) {
		md->fi->mod_time = pmd->mod_time;
	}

	if(!md->is_regular_file && !md->is_dir) {
		de_warn(c, "\"%s\" is a %s. It will not be extracted as such.",
			ucstring_getpsz(md->filename),
			md->is_symlink?"symlink":"special file");
	}

	snflags = DE_SNFLAG_FULLPATH;
	if(md->is_dir) {
		md->fi->is_directory = 1;
		snflags |= DE_SNFLAG_STRIPTRAILINGSLASH;
	}
	else if(md->is_regular_file) {
		if((pmd->mode & 0111)!=0) {
			md->fi->mode_flags |= DE_MODEFLAG_EXE;
		}
		else {
			md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
		}
	}
	de_finfo_set_name_from_ucstring(c, md->fi, md->filename, snflags);
	md->fi->original_filename_flag = 1;

	if(pmd->file_data_pos + pmd->filesize > c->infile->len) goto done;

	outf = dbuf_create_output_file(c, NULL, md->fi, 0);

	// If a symlink has no data, write the 'linkname' field instead.
	if(md->is_symlink && pmd->filesize==0) {
		if(ucstring_isnonempty(ea->linkname)) {
			ucstring_write_as_utf8(c, ea->linkname, outf, 0);
			goto done;
		}
		else if(pmd->linkname) {
			dbuf_write(outf, (const u8*)pmd->linkname->sz,
				(i64)de_strlen(pmd->linkname->sz));
			goto done;
		}
	}

	dbuf_copy(c->infile, pmd->file_data_pos, pmd->filesize, outf);

done:
	dbuf_close(outf);
	*bytes_consumed_member = pos - pos1;
	destroy_pmd(c, pmd);
	destroy_extattr_data(c, ea);
	if(md) {
		ucstring_destroy(md->filename);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_tar(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 item_len;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	d->global_ea = de_malloc(c, sizeof(struct extattr_data));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UTF8);

	pos = 0;
	while(1) {
		if(d->found_trailer) break;
		if(pos >= c->infile->len) break;
		if(pos+512 > c->infile->len) {
			de_warn(c, "Ignoring %d extra bytes at end of file", (int)(c->infile->len - pos));
			break;
		}

		ret = read_member(c, d, pos, &item_len);
		if(!ret || item_len<1) break;
		pos += item_len;
	}

	if(d) {
		destroy_extattr_data(c, d->global_ea);
		de_free(c, d);
	}
}

static int de_identify_tar(deark *c)
{
	int has_ext;
	u8 buf[8];
	i64 k;
	i64 digit_count;

	has_ext = de_input_file_has_ext(c, "tar");;
	if(!dbuf_memcmp(c->infile, 257, "ustar", 5)) {
		return has_ext ? 100 : 90;
	}

	if(has_ext) {
		if(!dbuf_memcmp(c->infile, 508, "tar\0", 4)) {
			return 90;
		}
	}

	// Try to detect tar formats that don't have the "ustar" identifier.
	if(!has_ext) return 0;

	// The 'checksum' field has a fairly distinctive format.
	// "This field should be stored as six octal digits followed by a null and
	// a space character."

	de_read(buf, 148, 8);
	digit_count = 0;
	for(k=0; k<6; k++) {
		if(buf[k]>='0' && buf[k]<='7') {
			digit_count++;
		}
		else if(buf[k]!=' ') {
			return 0;
		}
	}
	if(digit_count<1) return 0;
	if(buf[6]!=0x00) return 0;
	if(buf[7]!=' ') return 0;
	return 60;
}

void de_module_tar(deark *c, struct deark_module_info *mi)
{
	mi->id = "tar";
	mi->desc = "tar archive";
	mi->run_fn = de_run_tar;
	mi->identify_fn = de_identify_tar;
}
