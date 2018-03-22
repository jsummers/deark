// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// gzip compressed file format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gzip);

struct member_data {
#define GZIPFLAG_FTEXT    0x01
#define GZIPFLAG_FHCRC    0x02
#define GZIPFLAG_FEXTRA   0x04
#define GZIPFLAG_FNAME    0x08
#define GZIPFLAG_FCOMMENT 0x10
	de_byte flags;
	de_byte cmpr_code;
	de_uint32 crc16_reported;
	de_uint32 crc32_reported;
	de_int64 isize;
	struct de_timestamp mod_time_ts;

	de_uint32 crc_calculated;
};

typedef struct lctx_struct {
	dbuf *output_file;
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
	struct member_data *md = (struct member_data *)f->userdata;
	md->crc_calculated = de_crc32_continue(md->crc_calculated, buf, buf_len);
}

static int do_gzip_read_member(deark *c, lctx *d, de_int64 pos1, de_int64 *member_size)
{
	de_byte b0, b1;
	de_int64 pos;
	de_int64 n;
	de_int64 foundpos;
	de_int64 string_len;
	de_int64 cmpr_data_len;
	de_int64 mod_time_unix;
	de_ucstring *member_name = NULL;
	int saved_indent_level;
	int ret;
	struct member_data *md = NULL;
	int retval = 0;

	md = de_malloc(c, sizeof(struct member_data));

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "gzip member at %d", (int)pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

	b0 = de_getbyte(pos+0);
	b1 = de_getbyte(pos+1);
	if(b0!=0x1f || b1!=0x8b) {
		de_err(c, "Invalid gzip signature at %d. This is not a valid gzip file.",
			(int)pos1);
		goto done;
	}

	md->cmpr_code = de_getbyte(pos+2);
	if(md->cmpr_code!=0x08) {
		de_err(c, "Unsupported compression type (%d)", (int)md->cmpr_code);
		goto done;
	}

	md->flags = de_getbyte(pos+3);
	de_dbg(c, "flags: 0x%02x", (unsigned int)md->flags);
	pos += 4;

	mod_time_unix = de_getui32le(pos);
	de_unix_time_to_timestamp(mod_time_unix, &md->mod_time_ts);
	if(md->mod_time_ts.is_valid) {
		char timestamp_buf[64];
		de_timestamp_to_string(&md->mod_time_ts, timestamp_buf, sizeof(timestamp_buf), 1);
		de_dbg(c, "mod time: %" INT64_FMT " (%s)", mod_time_unix, timestamp_buf);
	}
	pos += 4;

	b0 = de_getbyte(pos++);
	de_dbg(c, "extra flags: 0x%02x", (unsigned int)b0);

	b0 = de_getbyte(pos++);
	de_dbg(c, "OS or filesystem: %d (%s)", (int)b0, get_os_name(b0));

	if(md->flags & GZIPFLAG_FEXTRA) {
		n = de_getui16le(pos); // XLEN
		// TODO: It might be interesting to dissect these extra fields, but it's
		// hard to find even a single file that uses them.
		de_dbg(c, "[extra fields at %d, dpos=%d, dlen=%d]",
			(int)pos, (int)(pos+2), (int)n);
		pos += 2;
		pos += n;
	}

	if(md->flags & GZIPFLAG_FNAME) {
		ret =  dbuf_search_byte(c->infile, 0x00, pos, c->infile->len - pos,
			&foundpos);
		if(!ret) {
			de_err(c, "Invalid NAME field");
			goto done;
		}

		string_len = foundpos - pos;

		member_name = ucstring_create(c);
#define DE_GZIP_MAX_FNLEN 300
		dbuf_read_to_ucstring_n(c->infile, pos, string_len, DE_GZIP_MAX_FNLEN,
			member_name, 0, DE_ENCODING_LATIN1);
		de_dbg(c, "file name at %d, len=%d: \"%s\"", (int)pos, (int)string_len,
			ucstring_getpsz_d(member_name));
		pos = foundpos + 1;
	}

	if(md->flags & GZIPFLAG_FCOMMENT) {
		ret =  dbuf_search_byte(c->infile, 0x00, pos, c->infile->len - pos,
			&foundpos);
		if(!ret) {
			de_err(c, "Invalid COMMENT field");
			goto done;
		}
		pos = foundpos + 1;
	}

	if(md->flags & GZIPFLAG_FHCRC) {
		md->crc16_reported = (de_uint32)de_getui16le(pos);
		de_dbg(c, "crc16 (reported): 0x%04x", (unsigned int)md->crc16_reported);
		pos += 2;
	}

	de_dbg(c, "compressed blocks at %d", (int)pos);

	if(!d->output_file) {
		// Although any member can have a name and mod time, this metadata
		// is ignored for members after the first one.
		de_finfo *fi = NULL;

		fi = de_finfo_create(c);

		if(member_name && c->filenames_from_file) {
			de_finfo_set_name_from_ucstring(c, fi, member_name);
			fi->original_filename_flag = 1;
		}

		if(md->mod_time_ts.is_valid) {
			fi->mod_time = md->mod_time_ts;
		}

		d->output_file = dbuf_create_output_file(c, member_name?NULL:"bin", fi, 0);

		de_finfo_destroy(c, fi);
	}

	d->output_file->writecallback_fn = our_writecallback;
	d->output_file->userdata = (void*)md;
	md->crc_calculated = de_crc32(NULL, 0);

	ret = de_uncompress_deflate(c->infile, pos, c->infile->len - pos, d->output_file, &cmpr_data_len);

	d->output_file->writecallback_fn = NULL;
	d->output_file->userdata = NULL;

	if(!ret) goto done;
	pos += cmpr_data_len;

	de_dbg(c, "crc32 (calculated): 0x%08x", (unsigned int)md->crc_calculated);

	md->crc32_reported = (de_uint32)de_getui32le(pos);
	de_dbg(c, "crc32 (reported)  : 0x%08x", (unsigned int)md->crc32_reported);
	pos += 4;

	if(md->crc_calculated != md->crc32_reported) {
		de_warn(c, "CRC check failed: Expected 0x%08x, got 0x%08x",
			(unsigned int)md->crc32_reported, (unsigned int)md->crc_calculated);
	}

	md->isize = de_getui32le(pos);
	de_dbg(c, "uncompressed size (mod 2^32): %u", (unsigned int)md->isize);
	pos += 4;

	retval = 1;

done:
	if(retval)
		*member_size = pos - pos1;
	else
		*member_size = 0;
	ucstring_destroy(member_name);
	de_free(c, md);
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
