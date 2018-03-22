// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Tar archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_tar);

struct member_data {
#define TARFMT_UNKNOWN  0
#define TARFMT_POSIX    1
#define TARFMT_GNU      2
	int fmt;
	de_byte linkflag;
	de_int64 mode;
	de_int64 filesize;
	de_ucstring *filename;
	de_finfo *fi;
};

typedef struct localctx_struct {
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

static int read_member(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed_member)
{
	struct member_data *md = NULL;
	char rawname_sz[100];
	char magic[8];
	char timestamp_buf[64];
	de_int64 ext_name_len;
	size_t rawname_sz_len;
	de_byte linkflag1;
	de_ucstring *rawname = NULL;
	de_int64 modtime_unix;
	int is_dir, is_regular_file;
	int ret;
	de_int64 longpath_data_len = 0;
	de_int64 pos = pos1;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	md = de_malloc(c, sizeof(struct member_data));

	md->filename = ucstring_create(c);

	de_dbg(c, "archive member at %d", (int)pos1);
	de_dbg_indent(c, 1);

	// Look ahead to try to figure out some things about the format of this member.

	if(de_getbyte(pos1) == 0x00) {
		// "The end of the archive is indicated by two records consisting
		// entirely of zero bytes."
		// TODO: We should maybe test more than just the first byte.
		de_dbg(c, "[trailer record]");
		d->found_trailer = 1;
		retval = 1;
		goto done;
	}

	linkflag1 = de_getbyte(pos1+156);

	de_read((de_byte*)magic, 257, 8);
	if(!de_memcmp(magic, (const void*)"ustar  \0", 8)) {
		md->fmt = TARFMT_GNU;
	}
	else if(!de_memcmp(magic, (const void*)"ustar\0", 6)) {
		md->fmt = TARFMT_POSIX;
	}

	de_dbg(c, "tar format: %s", get_fmt_name(md->fmt));

	////

	if(linkflag1 == 'L') {
		de_dbg(c, "LongPath data at %d", (int)pos);
		de_dbg_indent(c, 1);
		ret = dbuf_read_ascii_number(c->infile, pos+124, 11, 8, &ext_name_len);
		if(!ret) goto done;
		de_dbg(c, "ext. filename len: %d", (int)ext_name_len);
		if(ext_name_len<1 || ext_name_len>32768) goto done;

		pos += 512; // LongPath header record
		de_dbg(c, "ext. filename at %d", (int)pos);
		dbuf_read_to_ucstring(c->infile, pos, ext_name_len-1, md->filename, 0, DE_ENCODING_UTF8);
		de_dbg(c, "ext. filename: \"%s\"", ucstring_getpsz_d(md->filename));

		pos += de_pad_to_n(ext_name_len, 512); // The long filename

		longpath_data_len = pos - pos1;
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	de_read((de_byte*)rawname_sz, pos, 99);
	rawname_sz[99] = '\0';
	pos += 100;
	rawname_sz_len = de_strlen(rawname_sz);

	md->fi = de_finfo_create(c);

	rawname = ucstring_create(c);
	ucstring_append_bytes(rawname, (const de_byte*)rawname_sz, rawname_sz_len, 0, DE_ENCODING_UTF8);
	de_dbg(c, "member raw name: \"%s\"", ucstring_getpsz(rawname));

	if(md->filename->len==0) {
		ucstring_append_ucstring(md->filename, rawname);
	}

	ret = dbuf_read_ascii_number(c->infile, pos, 7, 8, &md->mode);
	if(!ret) goto done;
	pos += 8;
	de_dbg(c, "mode: octal(%06o)", (unsigned int)md->mode);
	if((md->mode & 0111)!=0) {
		md->fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else {
		md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	pos += 8; // uid
	pos += 8; // gid

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &md->filesize);
	if(!ret) goto done;
	pos += 12;
	de_dbg(c, "size: %"INT64_FMT"", md->filesize);

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->mod_time);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mtime: %d (%s)", (int)modtime_unix, timestamp_buf);
	pos += 12;

	pos += 8; // checksum

	md->linkflag = de_getbyte(pos);
	de_dbg(c, "linkflag/typeflag: 0x%02x ('%c')", (unsigned int)md->linkflag,
		de_byte_to_printable_char(md->linkflag));
	pos += 1;

	pos += 100; // linkname (TODO)

	pos += 255; // pad or magic, ... (TODO)

	de_dbg_indent(c, -1);

	// Try to figure out what kind of "file" this is.

	is_dir = 0;
	is_regular_file = 0;

	if(md->fmt==TARFMT_POSIX) {
		if(md->linkflag=='0' || md->linkflag==0) {
			is_regular_file = 1;
		}
		else if(md->linkflag=='5') {
			is_dir = 1;
		}
	}
	else if(md->fmt==TARFMT_GNU) {
		if(md->linkflag=='0' || md->linkflag=='7' || md->linkflag==0) {
			is_regular_file = 1;
		}
		else if(md->linkflag=='5') { // TODO: 'D'
			is_dir = 1;
		}
	}
	else {
		if(rawname_sz_len>0 && rawname_sz[rawname_sz_len-1]=='/') {
			is_dir = 1;
		}
		else if(md->linkflag==0 || md->linkflag=='0') {
			is_regular_file = 1;
		}
	}

	if(is_dir) {
		de_dbg(c, "[directory, not extracting]");
		md->filesize = 0;
		retval = 1;
		goto done;
	}

	if(!is_regular_file) {
		de_dbg(c, "[not a regular file, not extracting]");
		md->filesize = 0; // FIXME: There may be cases where this is wrong.
		retval = 1;
		goto done;
	}

	de_dbg(c, "file data at %d", (int)pos);
	de_dbg_indent(c, 1);

	de_finfo_set_name_from_ucstring(c, md->fi, md->filename);
	md->fi->original_filename_flag = 1;

	if(pos + md->filesize > c->infile->len) goto done;
	dbuf_create_file_from_slice(c->infile, pos, md->filesize, NULL, md->fi, 0);

	de_dbg_indent(c, -1);

	retval = 1;

done:
	*bytes_consumed_member = longpath_data_len + 512 + de_pad_to_n(md->filesize, 512);
	ucstring_destroy(rawname);

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
	de_int64 pos;
	de_int64 item_len;
	int ret;

	d = de_malloc(c, sizeof(lctx));

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
	de_byte buf[8];
	de_int64 k;
	de_int64 digit_count;

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
