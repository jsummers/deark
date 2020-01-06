// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// gzip compressed file format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gzip);

struct member_data {
#define GZIPFLAG_FTEXT    0x01
#define GZIPFLAG_FHCRC    0x02
#define GZIPFLAG_FEXTRA   0x04
#define GZIPFLAG_FNAME    0x08
#define GZIPFLAG_FCOMMENT 0x10
	u8 flags;
	u8 cmpr_code;
	u32 crc16_reported;
	u32 crc32_reported;
	i64 isize;
	struct de_timestamp mod_time_ts;

	struct de_crcobj *crco; // A copy of lctx->crco
};

typedef struct lctx_struct {
	dbuf *output_file;
	struct de_crcobj *crco;
} lctx;

static const char *get_os_name(u8 n)
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

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct member_data *md = (struct member_data *)userdata;
	de_crcobj_addbuf(md->crco, buf, buf_len);
}

static int do_gzip_read_member(deark *c, lctx *d, i64 pos1, i64 *member_size)
{
	u8 b0, b1;
	i64 pos;
	i64 n;
	i64 foundpos;
	i64 string_len;
	i64 cmpr_data_len;
	i64 mod_time_unix;
	u32 crc_calculated;
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

	mod_time_unix = de_getu32le(pos);
	de_unix_time_to_timestamp(mod_time_unix, &md->mod_time_ts, 0x1);
	if(md->mod_time_ts.is_valid) {
		char timestamp_buf[64];
		de_timestamp_to_string(&md->mod_time_ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "mod time: %" I64_FMT " (%s)", mod_time_unix, timestamp_buf);
	}
	pos += 4;

	b0 = de_getbyte(pos++);
	de_dbg(c, "extra flags: 0x%02x", (unsigned int)b0);

	b0 = de_getbyte(pos++);
	de_dbg(c, "OS or filesystem: %d (%s)", (int)b0, get_os_name(b0));

	if(md->flags & GZIPFLAG_FEXTRA) {
		n = de_getu16le(pos); // XLEN
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
		md->crc16_reported = (u32)de_getu16le(pos);
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
			de_finfo_set_name_from_ucstring(c, fi, member_name, 0);
			fi->original_filename_flag = 1;
		}

		if(md->mod_time_ts.is_valid) {
			fi->mod_time = md->mod_time_ts;
		}

		d->output_file = dbuf_create_output_file(c, member_name?NULL:"bin", fi, 0);

		de_finfo_destroy(c, fi);
	}

	dbuf_set_writelistener(d->output_file, our_writelistener_cb, (void*)md);
	md->crco = d->crco;
	de_crcobj_reset(md->crco);

	ret = fmtutil_decompress_deflate(c->infile, pos, c->infile->len - pos, d->output_file,
		0, &cmpr_data_len, 0);

	crc_calculated = de_crcobj_getval(md->crco);
	dbuf_set_writelistener(d->output_file, NULL, NULL);

	if(!ret) goto done;
	pos += cmpr_data_len;

	de_dbg(c, "crc32 (calculated): 0x%08x", (unsigned int)crc_calculated);

	md->crc32_reported = (u32)de_getu32le(pos);
	de_dbg(c, "crc32 (reported)  : 0x%08x", (unsigned int)md->crc32_reported);
	pos += 4;

	if(crc_calculated != md->crc32_reported) {
		de_warn(c, "CRC check failed: Expected 0x%08x, got 0x%08x",
			(unsigned int)md->crc32_reported, (unsigned int)crc_calculated);
	}

	md->isize = de_getu32le(pos);
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
	i64 pos;
	i64 member_size;

	d = de_malloc(c, sizeof(lctx));
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

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

	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_gzip(deark *c)
{
	u8 buf[3];

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
