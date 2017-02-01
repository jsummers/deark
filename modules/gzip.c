// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// gzip compressed file format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gzip);

typedef struct lctx_struct {
	// TODO: Some of these fields really belong in a separate per-member struct.
#define GZIPFLAG_FTEXT    0x01
#define GZIPFLAG_FHCRC    0x02
#define GZIPFLAG_FEXTRA   0x04
#define GZIPFLAG_FNAME    0x08
#define GZIPFLAG_FCOMMENT 0x10
	de_byte flags;
	dbuf *output_file;
	de_uint32 crc_calculated;
} lctx;

static const char *get_os_name(de_byte n)
{
	const char *names[14] = { "FAT", "Amiga", "VMS", "Unix",
		"VM/CMS", "Atari", "HPFS", "Mac", "Z-System", "CP/M",
		"TOPS-20", "NTFS", "QDOS", "RISCOS" };
	const char *name = "?";

	if((unsigned int)n<=13) {
		name = names[(unsigned int)n];
	}
	return name;
}

static void our_writecallback(dbuf *f, const de_byte *buf, de_int64 buf_len)
{
	lctx *d = (lctx*)f->userdata;
	d->crc_calculated = de_crc32_continue(d->crc_calculated, buf, buf_len);
}

static int do_gzip_read_member(deark *c, lctx *d, de_int64 pos1, de_int64 *member_size)
{
	de_byte b0, b1;
	de_int64 cmpr_code;
	de_int64 pos;
	de_int64 n;
	de_int64 foundpos;
	de_int64 string_len;
	de_int64 cmpr_data_len;
	de_int64 isize;
	de_int64 mod_time_unix;
	struct de_timestamp mod_time_ts;
	de_uint32 crc16_reported;
	de_uint32 crc32_reported;
	de_ucstring *member_name = NULL;
	de_finfo *fi = NULL;
	int saved_indent_level;
	int ret;
	int retval = 0;

	mod_time_ts.is_valid = 0;

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
	pos += 4;

	mod_time_unix = de_getui32le(pos);
	de_unix_time_to_timestamp(mod_time_unix, &mod_time_ts);
	if(mod_time_ts.is_valid) {
		char timestamp_buf[64];
		de_timestamp_to_string(&mod_time_ts, timestamp_buf, sizeof(timestamp_buf), 1);
		de_dbg(c, "mod time: %" INT64_FMT " (%s)\n", mod_time_unix, timestamp_buf);
	}
	pos += 4;

	b0 = de_getbyte(pos++);
	de_dbg(c, "extra flags: 0x%02x\n", (unsigned int)b0);

	b0 = de_getbyte(pos++);
	de_dbg(c, "OS or filesystem: %d (%s)\n", (int)b0, get_os_name(b0));

	if(d->flags & GZIPFLAG_FEXTRA) {
		n = de_getui16le(pos); // XLEN
		// TODO: It might be interesting to dissect these extra fields, but it's
		// hard to find even a single file that uses them.
		de_dbg(c, "[extra fields at %d, dpos=%d, dlen=%d]\n",
			(int)pos, (int)(pos+2), (int)n);
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
		crc16_reported = (de_uint32)de_getui16le(pos);
		de_dbg(c, "crc16 (reported): 0x%04x\n", (unsigned int)crc16_reported);
		pos += 2;
	}

	de_dbg(c, "compressed blocks at %d\n", (int)pos);

	if(!d->output_file) {
		fi = de_finfo_create(c);

		if(member_name && c->filenames_from_file) {
			de_finfo_set_name_from_ucstring(c, fi, member_name);
			fi->original_filename_flag = 1;
		}

		if(mod_time_ts.is_valid) {
			fi->mod_time = mod_time_ts;
		}

		d->output_file = dbuf_create_output_file(c, member_name?NULL:"bin", fi, 0);
	}

	d->output_file->writecallback_fn = our_writecallback;
	d->output_file->userdata = (void*)d;
	d->crc_calculated = de_crc32(NULL, 0);

	ret = de_uncompress_deflate(c->infile, pos, c->infile->len - pos, d->output_file, &cmpr_data_len);

	if(!ret) goto done;
	pos += cmpr_data_len;

	de_dbg(c, "crc32 (calculated): 0x%08x\n", (unsigned int)d->crc_calculated);

	crc32_reported = (de_uint32)de_getui32le(pos);
	de_dbg(c, "crc32 (reported)  : 0x%08x\n", (unsigned int)crc32_reported);
	pos += 4;

	if(d->crc_calculated != crc32_reported) {
		de_warn(c, "CRC check failed: Expected 0x%08x, got 0x%08x\n",
			(unsigned int)crc32_reported, (unsigned int)d->crc_calculated);
	}

	isize = de_getui32le(pos);
	de_dbg(c, "uncompressed size (mod 2^32): %u\n", (unsigned int)isize);
	pos += 4;

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
	mi->desc = "gzip compressed file";
	mi->run_fn = de_run_gzip;
	mi->identify_fn = de_identify_gzip;
}
