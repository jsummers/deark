// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Tar archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_tar);

struct member_data {
	de_int64 mode;
	de_int64 filesize;
	de_int64 filesize_padded;
	de_ucstring *filename;
	de_finfo *fi;
};

typedef struct localctx_struct {
	int reserved;
} lctx;

static int read_member(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed_member)
{
	struct member_data *md = NULL;
	char name_orig[100];
	size_t name_orig_len;
	de_ucstring *rawname_ucstring = NULL;
	de_int64 modtime_unix;
	char timestamp_buf[64];
	int is_dir;
	int retval = 0;
	int ret;
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "archive member at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct member_data));

	de_read((de_byte*)name_orig, pos, 99);
	name_orig[99] = '\0';
	pos += 100;
	name_orig_len = de_strlen(name_orig);

	if(name_orig_len==0) {
		// "The end of the archive is indicated by two records consisting
		// entirely of zero bytes."
		de_dbg(c, "trailer record\n");
		retval = 1;
		goto done;
	}

	md->fi = de_finfo_create(c);

	rawname_ucstring = ucstring_create(c);
	ucstring_append_bytes(rawname_ucstring, (const de_byte*)name_orig, name_orig_len, 0, DE_ENCODING_UTF8);
	de_dbg(c, "member raw name: \"%s\"\n", ucstring_get_printable_sz(rawname_ucstring));

	is_dir = 0;
	if(name_orig_len>0 && name_orig[name_orig_len-1]=='/') {
		is_dir = 1;
	}

	ret = dbuf_read_ascii_number(c->infile, pos, 7, 8, &md->mode);
	if(!ret) goto done;
	pos += 8;
	de_dbg(c, "mode: octal(%06o)\n", (unsigned int)md->mode);
	if((md->mode & 0111)!=0) {
		md->fi->is_executable = 1;
	}

	pos += 8; // uid
	pos += 8; // gid

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &md->filesize);
	if(!ret) goto done;
	pos += 12;
	de_dbg(c, "size: %"INT64_FMT"\n", md->filesize);
	if(is_dir) md->filesize = 0;

	md->filesize_padded = de_pad_to_n(md->filesize, 512);

	ret = dbuf_read_ascii_number(c->infile, pos, 11, 8, &modtime_unix);
	if(!ret) goto done;
	de_unix_time_to_timestamp(modtime_unix, &md->fi->mod_time);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mtime: %d (%s)\n", (int)modtime_unix, timestamp_buf);
	pos += 12;

	pos += 8; // checksum
	pos += 1; // linkflag (TODO)
	pos += 100; // linkname (TODO)

	pos += 255; // pad or magic, ... (TODO)

	de_dbg_indent(c, -1);

	if(is_dir) {
		de_dbg(c, "[directory, not extracting]\n");
		retval = 1;
		goto done;
	}

	de_dbg(c, "file data at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	de_finfo_set_name_from_ucstring(c, md->fi, rawname_ucstring);
	md->fi->original_filename_flag = 1;

	if(pos + md->filesize > c->infile->len) goto done;
	dbuf_create_file_from_slice(c->infile, pos, md->filesize, NULL, md->fi, 0);

	de_dbg_indent(c, -1);

	retval = 1;

done:
	*bytes_consumed_member = 512 + md->filesize_padded;
	ucstring_destroy(rawname_ucstring);

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
		if(pos >= c->infile->len) break;
		if(pos+512 > c->infile->len) {
			de_warn(c, "Ignoring %d extra bytes at end of file\n", (int)(c->infile->len - pos));
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
	//if(!dbuf_memcmp(c->infile, 257, "ustar", 5))
	//	return 75;
	return 0;
}

void de_module_tar(deark *c, struct deark_module_info *mi)
{
	mi->id = "tar";
	mi->desc = "tar archive";
	mi->run_fn = de_run_tar;
	mi->identify_fn = de_identify_tar;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
