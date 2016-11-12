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
	int is_le;
	de_int64 startpos;
	de_int64 fixed_header_size; // Not including the filename
	de_int64 namesize;
	de_int64 namesize_padded;
	de_int64 filesize;
	de_int64 filesize_padded;
	de_int64 mode;
	de_ucstring *filename;
	de_finfo *fi;
};

typedef struct localctx_struct {
	int first_subfmt;
	int trailer_found;
} lctx;

static de_int64 pad_to_2(de_int64 n)
{
	return (n&0x1) ? n+1 : n;
}

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
	if(b[0]==0xc7 && b[1]==0x71) {
		*subfmt = SUBFMT_BINARY_LE;
		return 70;
	}
	if(b[0]==0x71 && b[1]==0xc7) {
		*subfmt = SUBFMT_BINARY_BE;
		return 70;
	}

	return 0;
}

// Header decoders are responsible for setting:
// - md->fixed_header_size
// - md->namesize
// - md->namesize_padded
// - md->filesize
// - md->filesize_padded
// (among other things)

static int read_header_ascii_portable(deark *c, lctx *d, struct member_data *md)
{
	de_int64 pos;
	int ret;
	de_int64 n;
	de_int64 modtime_unix;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 6; // c_magic
	pos += 6; // c_dev

	ret = read_ascii_number(c, d, pos, 6, 8, &n);
	if(!ret) goto done;
	de_dbg(c, "c_ino: %d\n", (int)n);
	pos += 6;

	ret = read_ascii_number(c, d, pos, 6, 8, &md->mode);
	if(!ret) goto done;
	de_dbg(c, "c_mode: octal(%06o)\n", (unsigned int)md->mode);
	pos += 6;

	pos += 6; // c_uid
	pos += 6; // c_gid
	pos += 6; // c_nlink
	pos += 6; // c_rdev

	ret = read_ascii_number(c, d, pos, 11, 8, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->mod_time);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "c_mtime: %d (%s)\n", (int)modtime_unix, timestamp_buf);
	pos += 11;

	ret = read_ascii_number(c, d, pos, 6, 8, &md->namesize);
	if(!ret) goto done;
	de_dbg(c, "c_namesize: %d\n", (int)md->namesize);
	pos += 6;

	ret = read_ascii_number(c, d, pos, 11, 8, &md->filesize);
	if(!ret) goto done;
	de_dbg(c, "c_filesize: %d\n", (int)md->filesize);
	pos += 11;

	md->fixed_header_size = pos - md->startpos;
	md->namesize_padded = md->namesize;
	md->filesize_padded = md->filesize;

	retval = 1;

done:
	return retval;
}

static int read_header_ascii_new(deark *c, lctx *d, struct member_data *md)
{
	de_int64 pos;
	int ret;
	de_int64 n;
	de_int64 modtime_unix;
	de_int64 header_and_namesize_padded;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 6; // c_magic

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

	ret = read_ascii_number(c, d, pos, 8, 16, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->mod_time);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "c_mtime: %d (%s)\n", (int)modtime_unix, timestamp_buf);
	pos += 8;

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

static int read_header_binary(deark *c, lctx *d, struct member_data *md)
{
	de_int64 pos;
	de_int64 n;
	de_int64 modtime_msw, modtime_lsw;
	de_int64 modtime_unix;
	de_int64 filesize_msw, filesize_lsw;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 2; // c_magic
	pos += 2; // c_dev

	n = dbuf_getui16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_ino: %d\n", (int)n);
	pos += 2;

	md->mode = dbuf_getui16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_mode: octal(%06o)\n", (unsigned int)md->mode);
	pos += 2;

	pos += 2; // c_uid
	pos += 2; // c_gid
	pos += 2; // c_nlink
	pos += 2; // c_rdev

	modtime_msw = dbuf_getui16x(c->infile, pos, md->is_le);
	modtime_lsw = dbuf_getui16x(c->infile, pos+2, md->is_le);
	modtime_unix = (modtime_msw<<16) | modtime_lsw;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->mod_time);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "c_mtime: %d (%s)\n", (int)modtime_unix, timestamp_buf);
	pos += 4;

	md->namesize = dbuf_getui16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_namesize: %d\n", (int)md->namesize);
	pos += 2;

	filesize_msw = dbuf_getui16x(c->infile, pos, md->is_le);
	filesize_lsw = dbuf_getui16x(c->infile, pos+2, md->is_le);
	md->filesize = (filesize_msw<<16) | filesize_lsw;
	de_dbg(c, "c_filesize: %d\n", (int)md->filesize);
	pos += 4;

	md->fixed_header_size = pos - md->startpos;
	md->namesize_padded = pad_to_2(md->namesize);
	md->filesize_padded = pad_to_2(md->filesize);

	retval = 1;
	return retval;
}

// Allocates md->namesize.
static void read_member_name(deark *c, lctx *d, struct member_data *md)
{
	// Filenames end with a NUL byte, which is included in the namesize field.
	if(md->namesize<1) goto done;

	md->filename = ucstring_create(c);

	// The encoding is presumably whatever encoding the filenames used on the
	// system on which the archive was created, and there's no way to tell
	// what that was.
	// This should maybe be a command line option.
	dbuf_read_to_ucstring_n(c->infile, md->startpos + md->fixed_header_size,
		md->namesize-1, 300, md->filename, 0, DE_ENCODING_UTF8);

	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(md->filename));

	de_finfo_set_name_from_ucstring(c, md->fi, md->filename);
	md->fi->original_filename_flag = 1;

done:
	;
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
	md->fi = de_finfo_create(c);

	pos = md->startpos;
	identify_cpio_internal(c, md->startpos, &md->subfmt);
	if(md->subfmt==0) {
		de_err(c, "Unknown cpio format at %d\n", (int)md->startpos);
		goto done;
	}

	if(md->subfmt==SUBFMT_ASCII_PORTABLE) {
		read_header_ascii_portable(c, d, md);
	}
	else if(md->subfmt==SUBFMT_ASCII_NEW || md->subfmt==SUBFMT_ASCII_NEWCRC) {
		read_header_ascii_new(c, d, md);
	}
	else if(md->subfmt==SUBFMT_BINARY_LE) {
		md->is_le = 1;
		read_header_binary(c, d, md);
	}
	else if(md->subfmt==SUBFMT_BINARY_BE) {
		read_header_binary(c, d, md);
	}
	else {
		de_err(c, "Unsupported cpio format at %d\n", (int)md->startpos);
		goto done;
	}

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
		int msgflag = 0;

		if(md->mode==0 && md->namesize==11 && md->filesize==0) {
			if(!ucstring_strcmp(md->filename, "TRAILER!!!", DE_ENCODING_ASCII)) {
				de_dbg(c, "[Trailer. Not extracting.]\n");
				msgflag = 1;
				d->trailer_found = 1;
			}
		}

		if(!msgflag) {
			de_dbg(c, "[Not a regular file. Skipping.]\n");
		}
	}
	else {
		dbuf_create_file_from_slice(c->infile, pos, md->filesize, NULL, md->fi, 0);
	}

	de_dbg_indent(c, -1);

	retval = 1;

done:
	de_dbg_indent(c, -1);
	if(retval && md) {
		*bytes_consumed_member = md->fixed_header_size + md->namesize_padded + md->filesize_padded;
	}
	if(md) {
		ucstring_destroy(md->filename);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
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

	switch(d->first_subfmt) {
	case SUBFMT_BINARY_LE:
		de_declare_fmt(c, "cpio Binary little-endian");
		break;
	case SUBFMT_BINARY_BE:
		de_declare_fmt(c, "cpio Binary big-endian");
		break;
	case SUBFMT_ASCII_PORTABLE:
		de_declare_fmt(c, "cpio ASCII Portable");
		break;
	case SUBFMT_ASCII_NEW:
		de_declare_fmt(c, "cpio ASCII New");
		break;
	case SUBFMT_ASCII_NEWCRC:
		de_declare_fmt(c, "cpio ASCII New-CRC");
		break;
	}

	while(1) {
		if(d->trailer_found) break;
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
	int subfmt;
	return identify_cpio_internal(c, 0, &subfmt);
}

void de_module_cpio(deark *c, struct deark_module_info *mi)
{
	mi->id = "cpio";
	mi->desc = "cpio archive";
	mi->run_fn = de_run_cpio;
	mi->identify_fn = de_identify_cpio;
}
