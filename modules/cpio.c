// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// cpio archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cpio);

#define SUBFMT_BINARY_LE      1
#define SUBFMT_BINARY_BE      2
#define SUBFMT_ASCII_PORTABLE 3
#define SUBFMT_ASCII_NEW      4
#define SUBFMT_ASCII_NEWCRC   5

struct member_data {
	int subfmt;
	de_int64 startpos;
	de_int64 fixed_header_size; // Not including the filename
	de_int64 namesize;
	de_int64 namesize_padded;
	de_int64 filesize;
	de_int64 filesize_padded;
	de_int64 mode;
};

typedef struct localctx_struct {
	int first_subfmt;
} lctx;

static de_int64 pad_to_4(de_int64 n)
{
	return ((n+3)/4)*4;
}

static int read_ascii_number(deark *c, lctx *d, de_int64 pos,
	de_int64 fieldsize, int base, de_int64 *value)
{
	char buf[17];

	*value = 0;
	if(fieldsize>(de_int64)(sizeof(buf)-1)) return 0;

	de_read((de_byte*)buf, pos, fieldsize);
	buf[fieldsize] = '\0';

	*value = de_strtoll(buf, NULL, base);
	return 1;
}

// Returns a value suitable for format identification.
// If format is unidentified, subfmt=0
static int identify_cpio_internal(deark *c, de_int64 pos, int *subfmt)
{
	de_byte b[6];

	*subfmt = 0;
	de_read(b, pos, sizeof(b));

	if(!de_memcmp(b, "070707", 6)) {
		*subfmt = SUBFMT_ASCII_PORTABLE;
		return 100;
	}
	if(!de_memcmp(b, "070701", 6)) {
		*subfmt = SUBFMT_ASCII_NEW;
		return 100;
	}
	if(!de_memcmp(b, "070702", 6)) {
		*subfmt = SUBFMT_ASCII_NEWCRC;
		return 100;
	}

	// TODO: Other variant formats

	return 0;
}

// Header decoders are responsible for setting:
// - md->fixed_header_size
// - md->namesize
// - md->namesize_padded
// - md->filesize
// - md->filesize_padded
// (among other things)
static int read_header_ascii_new(deark *c, lctx *d, struct member_data *md)
{
	de_int64 pos;
	int ret;
	de_int64 n;
	de_int64 header_and_namesize_padded;
	int retval = 0;

	pos = md->startpos;

	pos += 6;

	ret = read_ascii_number(c, d, pos, 8, 16, &n);
	if(!ret) goto done;
	de_dbg(c, "c_ino: %d\n", (int)n);
	pos += 8;

	ret = read_ascii_number(c, d, pos, 8, 16, &md->mode);
	if(!ret) goto done;
	de_dbg(c, "c_mode: octal(%06o)\n", (unsigned int)md->mode);
	pos += 8;

	pos += 8; // c_uid
	pos += 8; // c_gid
	pos += 8; // c_nlink
	pos += 8; // c_mtime

	ret = read_ascii_number(c, d, pos, 8, 16, &md->filesize);
	if(!ret) goto done;
	de_dbg(c, "c_filesize: %d\n", (int)md->filesize);
	pos += 8;

	pos += 8; // c_devmajor
	pos += 8; // c_devminor
	pos += 8; // c_rdevmajor
	pos += 8; // c_rdevminor

	ret = read_ascii_number(c, d, pos, 8, 16, &md->namesize);
	if(!ret) goto done;
	de_dbg(c, "c_namesize: %d\n", (int)md->namesize);
	pos += 8;

	pos += 8; // c_check

	md->fixed_header_size = pos - md->startpos;

	header_and_namesize_padded = pad_to_4(md->fixed_header_size + md->namesize);
	md->namesize_padded = header_and_namesize_padded - md->fixed_header_size;

	md->filesize_padded = pad_to_4(md->filesize);

	retval = 1;

done:
	return retval;
}

static void read_member_name(deark *c, lctx *d, struct member_data *md)
{
	de_ucstring *s = NULL;

	// Filenames end with a NUL byte, which is included in the namesize field.
	if(md->namesize<1) goto done;

	s = ucstring_create(c);

	// No telling what encoding to use.
	dbuf_read_to_ucstring_n(c->infile, md->startpos + md->fixed_header_size,
		md->namesize-1, 300, s, 0, DE_ENCODING_UTF8);

	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(s));

done:
	ucstring_destroy(s);
}

static int read_member(deark *c, lctx *d, de_int64 pos1,
	de_int64 *bytes_consumed_member)
{
	int retval = 0;
	struct member_data *md = NULL;
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "member at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "fixed header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct member_data));
	md->startpos = pos1;

	pos = md->startpos;
	identify_cpio_internal(c, md->startpos, &md->subfmt);
	if(md->subfmt==0) {
		de_err(c, "Unknown cpio format at %d\n", (int)md->startpos);
		goto done;
	}

	if(md->subfmt==SUBFMT_ASCII_NEW) {
		;
	}
	else {
		de_err(c, "Unsupported cpio format at %d\n", (int)md->startpos);
		goto done;
	}

	read_header_ascii_new(c, d, md);

	de_dbg_indent(c, -1);
	de_dbg(c, "member name at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	read_member_name(c, d, md);
	pos = md->startpos + md->fixed_header_size + md->namesize_padded;
	de_dbg_indent(c, -1);

	de_dbg(c, "member data at %d, len=%d\n", (int)pos, (int)md->filesize);
	de_dbg_indent(c, 1);

	if(pos + md->filesize > c->infile->len) {
		goto done;
	}

	if((md->mode & 0170000) != 0100000) {
		de_dbg(c, "[Not a regular file. Skipping.]\n");
	}
	else {
		dbuf_create_file_from_slice(c->infile, pos, md->filesize, "bin", NULL, 0);
	}

	de_dbg_indent(c, -1);

	retval = 1;

done:
	de_dbg_indent(c, -1);
	if(retval && md) {
		*bytes_consumed_member = md->fixed_header_size + md->namesize_padded + md->filesize_padded;
	}
	de_free(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_cpio(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 bytes_consumed;
	de_int64 pos;
	int ret;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;

	if(identify_cpio_internal(c, pos, &d->first_subfmt)==0) {
		de_err(c, "Not a cpio file, or unknown cpio format\n");
		goto done;
	}

	while(1) {
		if(pos >= c->infile->len) break;
		bytes_consumed = 0;
		ret = read_member(c, d, pos, &bytes_consumed);
		if(!ret) break;
		if(bytes_consumed<1) break;
		pos += bytes_consumed;
	}

done:
	de_free(c, d);
}

static int de_identify_cpio(deark *c)
{
	//int subfmt;
	//return identify_cpio_internal(c, 0, &subfmt);
	return 0;
}

void de_module_cpio(deark *c, struct deark_module_info *mi)
{
	mi->id = "cpio";
	mi->desc = "cpio archive";
	mi->run_fn = de_run_cpio;
	mi->identify_fn = de_identify_cpio;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
