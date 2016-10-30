// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// gzip compressed file format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gzip);

typedef struct lctx_struct {
#define GZIPFLAG_FTEXT    0x01
#define GZIPFLAG_FHCRC    0x02
#define GZIPFLAG_FEXTRA   0x04
#define GZIPFLAG_FNAME    0x08
#define GZIPFLAG_FCOMMENT 0x10
	de_byte flags;
	dbuf *output_file;
} lctx;

static int do_gzip_read_member(deark *c, lctx *d, de_int64 pos1, de_int64 *member_size)
{
	de_byte b0, b1;
	de_int64 cmpr_code;
	de_int64 pos;
	de_int64 n;
	de_int64 foundpos;
	de_int64 string_len;
	de_int64 cmpr_data_len;
#if 0
	de_int64 isize;
	de_uint32 crc32_field;
#endif
	de_ucstring *member_name = NULL;
	de_finfo *fi = NULL;
	int saved_indent_level;
	int ret;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "gzip member at %d\n", (int)pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

	b0 = de_getbyte(pos+0);
	b1 = de_getbyte(pos+1);
	if(b0!=0x1f || b1!=0x8b) {
		de_err(c, "Invalid gzip signature at %d. This is not a valid gzip file.\n",
			(int)pos1);
		goto done;
	}

	cmpr_code=de_getbyte(pos+2);
	if(cmpr_code!=0x08) {
		de_err(c, "Unsupported compression type (%d)\n", (int)cmpr_code);
		goto done;
	}

	d->flags = de_getbyte(pos+3);
	de_dbg(c, "flags: 0x%02x\n", (unsigned int)d->flags);

	// TODO: MTIME
	// TODO: XFL
	// TODO: OS

	pos += 10;

	if(d->flags & GZIPFLAG_FEXTRA) {
		n = de_getui16le(pos);
		pos += 2;
		pos += n;
	}

	if(d->flags & GZIPFLAG_FNAME) {
		ret =  dbuf_search_byte(c->infile, 0x00, pos, c->infile->len - pos,
			&foundpos);
		if(!ret) {
			de_err(c, "Invalid NAME field\n");
			goto done;
		}

		string_len = foundpos - pos;

		member_name = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, pos, string_len, 300, member_name, 0, DE_ENCODING_LATIN1);
		de_dbg(c, "file name at %d, len=%d: \"%s\"\n", (int)pos, (int)string_len,
			ucstring_get_printable_sz(member_name));
		pos = foundpos + 1;
	}

	if(d->flags & GZIPFLAG_FCOMMENT) {
		ret =  dbuf_search_byte(c->infile, 0x00, pos, c->infile->len - pos,
			&foundpos);
		if(!ret) {
			de_err(c, "Invalid COMMENT field\n");
			goto done;
		}
		pos = foundpos + 1;
	}

	if(d->flags & GZIPFLAG_FHCRC) {
		pos += 2;
	}

	de_dbg(c, "compressed blocks at %d\n", (int)pos);

	if(!d->output_file) {
		if(member_name && c->filenames_from_file) {
			fi = de_finfo_create(c);
			de_finfo_set_name_from_ucstring(c, fi, member_name);
			fi->original_filename_flag = 1;
			d->output_file = dbuf_create_output_file(c, NULL, fi, 0);
		}
		else {
			d->output_file = dbuf_create_output_file(c, "bin", NULL, 0);
		}
	}

	ret = de_uncompress_deflate(c->infile, pos, c->infile->len - pos, d->output_file, &cmpr_data_len);

	if(!ret) goto done;
	pos += cmpr_data_len;

	de_warn(c, "gzip is not fully supported. Files with multiple \"members\" will be truncated.\n");
#if 0
	crc32_field = (de_uint32)de_getui32le(pos);
	de_dbg(c, "crc32: 0x%08x\n", (unsigned int)crc32_field);
	pos += 4;

	isize = de_getui32le(pos);
	de_dbg(c, "uncompressed size (mod 2^32): %u\n", (unsigned int)isize);
	pos += 4;
#endif

	retval = 1;

done:
	if(retval)
		*member_size = pos - pos1;
	else
		*member_size = 0;
	ucstring_destroy(member_name);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_gzip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 member_size;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	while(1) {
		if(pos >= c->infile->len) break;
		if(!do_gzip_read_member(c, d, pos, &member_size)) {
			break;
		}
		if(member_size<=0) break;

		pos += member_size;
		break; // FIXME
	}
	dbuf_close(d->output_file);

	de_free(c, d);
}

static int de_identify_gzip(deark *c)
{
	de_byte buf[3];

	de_read(buf, 0, 3);
	if(buf[0]==0x1f && buf[1]==0x8b) {
		if(buf[2]==0x08) return 100;
		return 10;
	}
	return 0;
}

void de_module_gzip(deark *c, struct deark_module_info *mi)
{
	mi->id = "gzip";
	mi->run_fn = de_run_gzip;
	mi->identify_fn = de_identify_gzip;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
