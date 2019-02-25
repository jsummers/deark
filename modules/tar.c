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
	de_ucstring *prefix;
	de_ucstring *alt_name;
	struct de_timestamp alt_mod_time;
};

struct member_data {
	de_ucstring *filename;
	de_finfo *fi;
};

typedef struct localctx_struct {
	int input_encoding;
	int found_trailer;
} lctx;

static const char* get_fmt_name(int fmt)
{
	const char *n = "unknown or old-style";
	switch(fmt) {
	case TARFMT_POSIX: n = "POSIX"; break;
	case TARFMT_GNU: n = "GNU"; break;
	}
	return n;
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

	if(hdrblock[0] == 0x00) {
		// "The end of the archive is indicated by two records consisting
		// entirely of zero bytes."
		// TODO: We should maybe test more than just the first byte.
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

	calc_checksum(c, d, pmd, hdrblock);

	de_dbg(c, "tar format: %s", get_fmt_name(pmd->fmt));

	pmd->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 100, pmd->name, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	pos += 100;
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(pmd->name));

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 8, &pmd->mode);
	if(!ret) goto done;
	pos += 8;
	de_dbg(c, "mode: octal(%06o)", (unsigned int)pmd->mode);

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 8, &n);
	if(ret) {
		de_dbg(c, "uid: %"I64_FMT, n);
	}
	pos += 8;
	ret = dbuf_read_ascii_number(c->infile, pos, 8, 8, &n);
	if(ret) {
		de_dbg(c, "gid: %"I64_FMT, n);
	}
	pos += 8;

	ret = dbuf_read_ascii_number(c->infile, pos, 12, 8, &pmd->filesize);
	if(!ret) goto done;
	pos += 12;
	de_dbg(c, "size: %"I64_FMT, pmd->filesize);
	pmd->file_data_pos = pos1 + 512;

	ret = dbuf_read_ascii_number(c->infile, pos, 12, 8, &pmd->modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(pmd->modtime_unix, &pmd->mod_time, 0x1);
	de_timestamp_to_string(&pmd->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mtime: %d (%s)", (int)pmd->modtime_unix, timestamp_buf);
	pos += 12;

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 8, &pmd->checksum);
	if(ret) {
		de_dbg(c, "header checksum (reported): %"I64_FMT, pmd->checksum);
	}
	de_dbg(c, "header checksum (calculated): %"I64_FMT, pmd->checksum_calc);
	if(pmd->checksum != pmd->checksum_calc) {
		de_warn(c, "%s: Header checksum failed: reported=%"I64_FMT", calculated=%"I64_FMT,
			ucstring_getpsz_d(pmd->name), pmd->checksum, pmd->checksum_calc);
	}
	pos += 8;

	// linkflag already set, above
	de_dbg(c, "linkflag/typeflag: 0x%02x ('%c')", (unsigned int)pmd->linkflag,
		de_byte_to_printable_char(pmd->linkflag));
	pos += 1;

	pos += 100; // linkname (TODO)

	pos += 6; // magic
	pos += 2; // version

	tmpstr = ucstring_create(c);
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

	if(pmd->fmt==TARFMT_POSIX && (de_getbyte(pos)!=0)) {
		// This field might only be 131 bytes, instead of 155. Let's hope that
		// that it's NUL terminated in that case.
		pmd->prefix = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, 155, pmd->prefix,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "prefix: \"%s\"", ucstring_getpsz_d(pmd->prefix));
	}
	pos += 155; // prefix, or prefix+atime+ctime

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
	ucstring_destroy(pmd->prefix);
	ucstring_destroy(pmd->alt_name);
	de_free(c, pmd);
}

static void read_gnu_longpath(deark *c, lctx *d, struct phys_member_data *pmd)
{
	i64 pos = pmd->file_data_pos;
	i64 ext_name_len = pmd->filesize;

	de_dbg(c, "LongPath data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	if(ext_name_len<1 || ext_name_len>32768) goto done;

	de_dbg(c, "ext. filename at %"I64_FMT, pos);
	pmd->alt_name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, ext_name_len-1, pmd->alt_name, 0,
		d->input_encoding);
	de_dbg(c, "ext. filename: \"%s\"", ucstring_getpsz_d(pmd->alt_name));

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
	struct exthdr_item *ehi)
{
	double val_dbl;
	double val_frac;
	i64 val_int;
	char timestamp_buf[64];

	if(ehi->val_len<1) return;

	// TODO: There is probably roundoff error here than there needs to be.
	val_dbl = strtod(ehi->value->sz, NULL);
	// Negative values are legal, but improbable, and our code won't correctly
	// handle them.
	if(val_dbl < 0.0) return;
	val_int = (int)val_dbl;
	val_frac = val_dbl - (double)val_int;

	de_unix_time_to_timestamp(val_int, &pmd->alt_mod_time, 0x1);
	if(val_frac > 0.0) {
		de_timestamp_set_subsec(&pmd->alt_mod_time, val_frac);
	}

	de_timestamp_to_string(&pmd->alt_mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static int read_exthdr_item(deark *c, lctx *d, struct phys_member_data *pmd,
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
		n, n, 0, DE_ENCODING_UTF8);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(ehi->value->str));

	if(!de_strcmp(ehi->name->sz, "path")) {
		if(!pmd->alt_name) pmd->alt_name = ucstring_create(c);
		ucstring_empty(pmd->alt_name);
		ucstring_append_ucstring(pmd->alt_name, ehi->value->str);
	}
	else if(!de_strcmp(ehi->name->sz, "mtime")) {
		do_exthdr_mtime(c, d, pmd, ehi);
	}
	// TODO: "size"
	// TODO: "linkpath"
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

static void read_exthdr(deark *c, lctx *d, struct phys_member_data *pmd)
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

		if(!read_exthdr_item(c, d, pmd, pos,
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
	struct phys_member_data *pmd_special = NULL;
	int is_dir, is_regular_file;
	unsigned int snflags;
	i64 pos = pos1;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "logical archive member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct member_data));
	md->fi = de_finfo_create(c);
	md->filename = ucstring_create(c);

	pmd = de_malloc(c, sizeof(struct phys_member_data));

	if(!read_phys_member_header(c, d, pmd, pos)) {
		goto done;
	}
	pos += 512;
	pos += de_pad_to_n(pmd->filesize, 512);

	if(pmd->linkflag == 'L') {
		pmd_special = pmd;
		pmd = NULL;
		read_gnu_longpath(c, d, pmd_special);
	}
	else if(pmd->linkflag == 'x') {
		pmd_special = pmd;
		pmd = NULL;
		read_exthdr(c, d, pmd_special);
	}

	// If a special preamble member was found, we set pmd to NULL. In that case
	// we need to try again to read the real member.
	if(!pmd) {
		pmd = de_malloc(c, sizeof(struct phys_member_data));
		if(!read_phys_member_header(c, d, pmd, pos)) {
			goto done;
		}
		pos += 512;
		pos += de_pad_to_n(pmd->filesize, 512);
	}

	retval = 1;

	// Decide on a filename
	if(pmd_special && ucstring_isnonempty(pmd_special->alt_name)) {
		ucstring_append_ucstring(md->filename, pmd_special->alt_name);
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

	is_dir = 0;
	is_regular_file = 0;

	if(pmd->fmt==TARFMT_POSIX) {
		if(pmd->linkflag=='0' || pmd->linkflag==0) {
			is_regular_file = 1;
		}
		else if(pmd->linkflag=='5') {
			is_dir = 1;
		}
	}
	else if(pmd->fmt==TARFMT_GNU) {
		if(pmd->linkflag=='0' || pmd->linkflag=='7' || pmd->linkflag==0) {
			is_regular_file = 1;
		}
		else if(pmd->linkflag=='5') { // TODO: 'D'
			is_dir = 1;
		}
	}
	else {
		if(pmd->name->len>=1 && pmd->name->str[pmd->name->len-1]=='/') {
			is_dir = 1;
		}
		else if(pmd->linkflag==0 || pmd->linkflag=='0') {
			is_regular_file = 1;
		}
	}

	de_dbg(c, "file data at %"I64_FMT, pos);

	if(pmd_special && pmd_special->alt_mod_time.is_valid) {
		md->fi->mod_time = pmd_special->alt_mod_time;
	}
	else if(pmd->mod_time.is_valid) {
		md->fi->mod_time = pmd->mod_time;
	}

	if(!is_regular_file && !is_dir) {
		de_warn(c, "\"%s\" is a special file. It will not be extracted as such.",
			ucstring_getpsz(md->filename));
	}

	snflags = DE_SNFLAG_FULLPATH;
	if(is_dir) {
		md->fi->is_directory = 1;
		snflags |= DE_SNFLAG_STRIPTRAILINGSLASH;
	}
	else if(is_regular_file) {
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
	dbuf_create_file_from_slice(c->infile, pmd->file_data_pos, pmd->filesize, NULL, md->fi, 0);

done:
	*bytes_consumed_member = pos - pos1;
	destroy_pmd(c, pmd);
	destroy_pmd(c, pmd_special);
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

	if(c->input_encoding==DE_ENCODING_UNKNOWN)
		d->input_encoding = DE_ENCODING_UTF8;
	else
		d->input_encoding = c->input_encoding;

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

	de_free(c, d);
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
