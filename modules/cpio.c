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
	i64 startpos;
	i64 fixed_header_size; // Not including the filename
	i64 namesize;
	i64 namesize_padded;
	i64 filesize;
	i64 filesize_padded;
	i64 mode;
	u32 checksum_reported;
	struct de_stringreaderdata *filename_srd;
	de_finfo *fi;
	u32 checksum_calculated;
};

typedef struct localctx_struct {
	int first_subfmt;
	int trailer_found;
	int input_encoding;
} lctx;

// Returns a value suitable for format identification.
// If format is unidentified, subfmt=0
static int identify_cpio_internal(deark *c, i64 pos, int *subfmt)
{
	u8 b[6];

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
	i64 pos;
	int ret;
	i64 n;
	i64 modtime_unix;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 6; // c_magic
	pos += 6; // c_dev

	ret = dbuf_read_ascii_number(c->infile, pos, 6, 8, &n);
	if(!ret) goto done;
	de_dbg(c, "c_ino: %d", (int)n);
	pos += 6;

	ret = dbuf_read_ascii_number(c->infile, pos, 6, 8, &md->mode);
	if(!ret) goto done;
	de_dbg(c, "c_mode: octal(%06o)", (unsigned int)md->mode);
	pos += 6;

	pos += 6; // c_uid
	pos += 6; // c_gid
	pos += 6; // c_nlink
	pos += 6; // c_rdev

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], 0x1);
	de_timestamp_to_string(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "c_mtime: %d (%s)", (int)modtime_unix, timestamp_buf);
	pos += 11;

	ret = dbuf_read_ascii_number(c->infile, pos, 6, 8, &md->namesize);
	if(!ret) goto done;
	de_dbg(c, "c_namesize: %d", (int)md->namesize);
	pos += 6;

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &md->filesize);
	if(!ret) goto done;
	de_dbg(c, "c_filesize: %d", (int)md->filesize);
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
	i64 pos;
	int ret;
	i64 n;
	i64 modtime_unix;
	i64 header_and_namesize_padded;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 6; // c_magic

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &n);
	if(!ret) goto done;
	de_dbg(c, "c_ino: %d", (int)n);
	pos += 8;

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &md->mode);
	if(!ret) goto done;
	de_dbg(c, "c_mode: octal(%06o)", (unsigned int)md->mode);
	pos += 8;

	pos += 8; // c_uid
	pos += 8; // c_gid
	pos += 8; // c_nlink

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], 0x1);
	de_timestamp_to_string(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "c_mtime: %d (%s)", (int)modtime_unix, timestamp_buf);
	pos += 8;

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &md->filesize);
	if(!ret) goto done;
	de_dbg(c, "c_filesize: %d", (int)md->filesize);
	pos += 8;

	pos += 8; // c_devmajor
	pos += 8; // c_devminor
	pos += 8; // c_rdevmajor
	pos += 8; // c_rdevminor

	ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &md->namesize);
	if(!ret) goto done;
	de_dbg(c, "c_namesize: %d", (int)md->namesize);
	pos += 8;

	if(md->subfmt==SUBFMT_ASCII_NEWCRC) {
		ret = dbuf_read_ascii_number(c->infile, pos, 8, 16, &n);
		if(!ret) goto done;
		md->checksum_reported = (u32)n;
		de_dbg(c, "c_check: %u", (unsigned int)md->checksum_reported);
	}
	pos += 8; // c_check

	md->fixed_header_size = pos - md->startpos;

	header_and_namesize_padded = de_pad_to_4(md->fixed_header_size + md->namesize);
	md->namesize_padded = header_and_namesize_padded - md->fixed_header_size;

	md->filesize_padded = de_pad_to_4(md->filesize);

	retval = 1;

done:
	return retval;
}

static int read_header_binary(deark *c, lctx *d, struct member_data *md)
{
	i64 pos;
	i64 n;
	i64 modtime_msw, modtime_lsw;
	i64 modtime_unix;
	i64 filesize_msw, filesize_lsw;
	int retval = 0;
	char timestamp_buf[64];

	pos = md->startpos;

	pos += 2; // c_magic
	pos += 2; // c_dev

	n = dbuf_getu16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_ino: %d", (int)n);
	pos += 2;

	md->mode = dbuf_getu16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_mode: octal(%06o)", (unsigned int)md->mode);
	pos += 2;

	pos += 2; // c_uid
	pos += 2; // c_gid
	pos += 2; // c_nlink
	pos += 2; // c_rdev

	modtime_msw = dbuf_getu16x(c->infile, pos, md->is_le);
	modtime_lsw = dbuf_getu16x(c->infile, pos+2, md->is_le);
	modtime_unix = (modtime_msw<<16) | modtime_lsw;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], 0x1);
	de_timestamp_to_string(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "c_mtime: %d (%s)", (int)modtime_unix, timestamp_buf);
	pos += 4;

	md->namesize = dbuf_getu16x(c->infile, pos, md->is_le);
	de_dbg(c, "c_namesize: %d", (int)md->namesize);
	pos += 2;

	filesize_msw = dbuf_getu16x(c->infile, pos, md->is_le);
	filesize_lsw = dbuf_getu16x(c->infile, pos+2, md->is_le);
	md->filesize = (filesize_msw<<16) | filesize_lsw;
	de_dbg(c, "c_filesize: %d", (int)md->filesize);
	pos += 4;

	md->fixed_header_size = pos - md->startpos;
	md->namesize_padded = de_pad_to_2(md->namesize);
	md->filesize_padded = de_pad_to_2(md->filesize);

	retval = 1;
	return retval;
}

// Always allocates md->filename_srd.
static void read_member_name(deark *c, lctx *d, struct member_data *md)
{
	i64 namesize_adjusted;

	// Filenames end with a NUL byte, which is included in the namesize field.
	namesize_adjusted = md->namesize - 1;
	if(namesize_adjusted<0) namesize_adjusted=0;
	if(namesize_adjusted>DE_DBG_MAX_STRLEN) namesize_adjusted=DE_DBG_MAX_STRLEN;

	md->filename_srd = dbuf_read_string(c->infile, md->startpos + md->fixed_header_size,
		namesize_adjusted, namesize_adjusted, 0, d->input_encoding);

	de_dbg(c, "name: \"%s\"", ucstring_getpsz(md->filename_srd->str));
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	i64 k;
	struct member_data *md = (struct member_data *)userdata;

	for(k=0; k<buf_len; k++) {
		// The 32-bit unsigned integer overflow is by design.
		md->checksum_calculated += (u32)buf[k];
	}
}

static int read_member(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed_member)
{
	int retval = 0;
	struct member_data *md = NULL;
	i64 pos = pos1;
	unsigned int unix_filetype;
	enum { CPIOFT_SPECIAL=0, CPIOFT_REGULAR,
		CPIOFT_DIR, CPIOFT_TRAILER } cpio_filetype;
	dbuf *outf = NULL;
	unsigned int snflags;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "member at %d", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "fixed header at %d", (int)pos);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct member_data));
	md->startpos = pos1;
	md->fi = de_finfo_create(c);
	md->fi->detect_root_dot_dir = 1;

	identify_cpio_internal(c, md->startpos, &md->subfmt);
	if(md->subfmt==0) {
		de_err(c, "Unknown cpio format at %d", (int)md->startpos);
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
		de_err(c, "Unsupported cpio format at %d", (int)md->startpos);
		goto done;
	}

	de_dbg_indent(c, -1);
	de_dbg(c, "member name at %d", (int)(md->startpos + md->fixed_header_size));
	de_dbg_indent(c, 1);
	read_member_name(c, d, md);

	pos = md->startpos + md->fixed_header_size + md->namesize_padded;
	de_dbg_indent(c, -1);

	de_dbg(c, "member data at %d, len=%d", (int)pos, (int)md->filesize);
	de_dbg_indent(c, 1);

	if(pos + md->filesize > c->infile->len) {
		goto done;
	}

	retval = 1;

	unix_filetype = (unsigned int)md->mode & 0170000;

	if(unix_filetype==040000) {
		cpio_filetype = CPIOFT_DIR;
	}
	else if(unix_filetype==0100000) {
		cpio_filetype = CPIOFT_REGULAR;
	}
	else {
		cpio_filetype = CPIOFT_SPECIAL;
		if(md->mode==0 && md->namesize==11) {
			if(!de_strcmp(md->filename_srd->sz, "TRAILER!!!")) {
				cpio_filetype = CPIOFT_TRAILER;
				de_dbg(c, "[Trailer. Not extracting.]");
				d->trailer_found = 1;
			}
		}

		if(cpio_filetype==CPIOFT_SPECIAL) {
			de_dbg(c, "[Not a regular file. Skipping.]");
		}
	}

	if(cpio_filetype!=CPIOFT_REGULAR && cpio_filetype!=CPIOFT_DIR) {
		goto done; // Not extracting this member
	}

	snflags = DE_SNFLAG_FULLPATH;
	if(cpio_filetype==CPIOFT_DIR) {
		md->fi->is_directory = 1;
		// Directory members might or might not end in a slash.
		snflags |= DE_SNFLAG_STRIPTRAILINGSLASH;
	}
	else if((md->mode & 0111) != 0) {
		md->fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else {
		md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	de_finfo_set_name_from_ucstring(c, md->fi, md->filename_srd->str, snflags);
	md->fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, md->fi, 0);

	if(md->subfmt==SUBFMT_ASCII_NEWCRC) {
		// Use a callback function to calculate the checksum.
		dbuf_set_writelistener(outf, our_writelistener_cb, (void*)md);
		md->checksum_calculated = 0;
	}

	dbuf_copy(c->infile, pos, md->filesize, outf);

	if(md->subfmt==SUBFMT_ASCII_NEWCRC) {
		de_dbg(c, "checksum (calculated): %u", (unsigned int)md->checksum_calculated);
		if(md->checksum_calculated != md->checksum_reported) {
			de_warn(c, "Checksum failed for file %s: Expected %u, got %u",
				ucstring_getpsz_d(md->filename_srd->str),
				(unsigned int)md->checksum_reported, (unsigned int)md->checksum_calculated);
		}
	}

done:
	dbuf_close(outf);
	if(retval && md) {
		*bytes_consumed_member = md->fixed_header_size + md->namesize_padded + md->filesize_padded;
	}
	if(md) {
		de_destroy_stringreaderdata(c, md->filename_srd);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_cpio(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 bytes_consumed;
	i64 pos;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UTF8);

	pos = 0;

	if(identify_cpio_internal(c, pos, &d->first_subfmt)==0) {
		de_err(c, "Not a cpio file, or unknown cpio format");
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
