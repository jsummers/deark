// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// ArcFS
// Squash

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arcfs);
DE_DECLARE_MODULE(de_module_squash);

struct member_data {
	int is_dir;
	int is_regular_file;
	int file_type_known;
	u8 cmpr_method;
	unsigned int lzwmaxbits;
	u32 attribs;
	u32 crc;
	u32 load_addr, exec_addr;
	unsigned int file_type;
	i64 file_data_offs_rel;
	i64 file_data_offs_abs;
	i64 orig_len;
	i64 cmpr_len;
	const char *cmpr_meth_name;
	de_ucstring *fn;
	struct de_timestamp mod_time;
};

typedef struct localctx_struct {
	int append_type;
	i64 nmembers;
	i64 data_offs;
	struct de_crcobj *crco;
	struct de_strarray *curpath;
} lctx;

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static int do_file_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 hlen;
	u32 ver_r, ver_rw;
	u32 format_ver;
	int retval = 0;

	de_dbg(c, "file header at %d", (int)pos1);
	de_dbg_indent(c, 1);
	pos += 8; // Signature

	hlen = de_getu32le_p(&pos);
	d->nmembers = hlen/36;
	de_dbg(c, "header len: %d (%d members)", (int)hlen, (int)d->nmembers);

	d->data_offs = de_getu32le_p(&pos);
	de_dbg(c, "data offset: %d", (int)d->data_offs);

	ver_r = (u32)de_getu32le_p(&pos);
	de_dbg(c, "version req'd for read: %u.%02u", (unsigned int)(ver_r/100),
		(unsigned int)(ver_r%100));
	ver_rw = (u32)de_getu32le_p(&pos);
	de_dbg(c, "version req'd for read/write: %u.%02u", (unsigned int)(ver_rw/100),
		(unsigned int)(ver_rw%100));

	// ??
	format_ver = (u32)de_getu32le_p(&pos);
	de_dbg(c, "format version: %u", (unsigned int)format_ver);
	if(format_ver!=0) {
		de_err(c, "Unsupported format version: %u", (unsigned int)format_ver);
		goto done;
	}

	// 68 reserved bytes here

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_compressed(deark *c, lctx *d, struct member_data *md, dbuf *outf,
	int limit_size_flag)
{
	u8 lzwmode;
	int retval = 0;

	lzwmode = (u8)(md->lzwmaxbits | 0x80);
	retval = de_decompress_liblzw(c->infile, md->file_data_offs_abs, md->cmpr_len,
		outf, limit_size_flag, md->orig_len, 0x2, lzwmode);
	return retval;
}

static int do_crunched(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	dbuf *tmpf = NULL;
	int ret1, ret2;
	int retval = 0;

	// "Crunched" apparently means "packed", then "compressed".
	// So we have to "uncompress", then "unpack".

	// TODO: It would be better to unpack the bytes in a streaming fashion, instead
	// of uncompressing the whole file to a memory buffer.
	// TODO: We should at least set a size limit on tmpf, but it's not clear what
	// the limit should be.
	tmpf = dbuf_create_membuf(c, 0, 0);
	ret1 = do_compressed(c, d, md, tmpf, 0);
	de_dbg2(c, "size after intermediate decompression: %d", (int)tmpf->len);

	ret2 = de_fmtutil_decompress_rle90(tmpf, 0, tmpf->len, outf, 1, md->orig_len, 0);
	if(!ret1 || !ret2) goto done;

	retval = 1;

done:
	dbuf_close(tmpf);
	return retval;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_extract_member_file(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	u32 crc_calc;
	int ret;
	de_ucstring *fullfn = NULL;

	if(md->file_data_offs_abs + md->cmpr_len > c->infile->len) goto done;

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT,
		md->file_data_offs_abs, md->cmpr_len);

	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, 0);
	ucstring_append_ucstring(fullfn, md->fn);
	if(d->append_type && md->file_type_known) {
		// Append the file type to the filename, like nspark's -X option.
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->file_type);
	}

	if(md->cmpr_method!=0x82 && md->cmpr_method!=0x83 && md->cmpr_method!=0x88 &&
		md->cmpr_method!=0xff)
	{
		de_err(c, "Compression type 0x%02x (%s) is not supported.",
			(unsigned int)md->cmpr_method, md->cmpr_meth_name);
		goto done;
	}

	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;
	de_crcobj_reset(d->crco);

	if(md->cmpr_method==0x82) { // stored
		dbuf_copy(c->infile, md->file_data_offs_abs, md->cmpr_len, outf);
	}
	else if(md->cmpr_method==0x83) {
		de_fmtutil_decompress_rle90(c->infile, md->file_data_offs_abs, md->cmpr_len,
			outf, 1, md->orig_len, 0);
	}
	else if(md->cmpr_method==0xff) {
		ret = do_compressed(c, d, md, outf, 1);
		if(!ret) {
			goto done;
		}
	}
	else if(md->cmpr_method==0x88) {
		ret = do_crunched(c, d, md, outf);
		if(!ret) {
			goto done;
		}
	}

	if(outf->len != md->orig_len) {
		de_err(c, "Decompression failed for file %s, expected size %"I64_FMT
			", got %"I64_FMT, ucstring_getpsz_d(md->fn), md->orig_len, outf->len);
		goto done;
	}

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(crc_calc != md->crc) {
		if(md->crc==0) {
			de_warn(c, "CRC check not available for file %s", ucstring_getpsz_d(md->fn));
		}
		else {
			de_err(c, "CRC check failed for file %s", ucstring_getpsz_d(md->fn));
		}
	}

done:
	dbuf_close(outf);
	ucstring_destroy(fullfn);
}

// "Extract" a directory entry
static void do_extract_member_dir(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	de_ucstring *fullfn = NULL;

	fullfn = ucstring_create(c);
	// Note that md->fn has already been added to d->curpath
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	fi->is_directory = 1;
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_close(outf);
	ucstring_destroy(fullfn);
}

static void do_extract_member(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;
	if(md->mod_time.is_valid) {
		fi->mod_time = md->mod_time;
	}

	if(md->is_regular_file) {
		do_extract_member_file(c, d, md, fi);
	}
	else if(md->is_dir) {
		do_extract_member_dir(c, d, md, fi);
	}

	de_finfo_destroy(c, fi);
}

static const char *get_info_byte_name(u8 t)
{
	const char *name = NULL;
	switch(t) {
	case 0x00: name="end of dir marker"; break;
	case 0x01: name="deleted object"; break;
	case 0x82: name="stored"; break;
	case 0x83: name="packed (RLE)"; break;
	case 0x88: name="crunched"; break;
	case 0xff: name="compressed"; break;
	}
	return name?name:"?";
}

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->fn);
	de_free(c, md);
}

static void do_member(deark *c, lctx *d, i64 idx, i64 pos1)
{
	i64 pos = pos1;
	u32 info_word;
	u8 info_byte;
	int saved_indent_level;
	struct member_data *md;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));
	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	info_byte = de_getbyte_p(&pos);
	md->cmpr_meth_name = get_info_byte_name(info_byte);
	de_dbg(c, "info byte: 0x%02x (%s)", (unsigned int)info_byte, md->cmpr_meth_name);
	if(info_byte==1) goto done; // deleted object
	if(info_byte==0) { // end of directory marker
		de_strarray_pop(d->curpath);
		goto done;
	}
	md->cmpr_method = info_byte;

	// Look ahead at the "information word".
	// TODO: Is this the right way to check for a directory?
	info_word = (u32)de_getu32le(pos1+32);
	md->is_dir = (info_word&0x80000000U)?1:0;
	md->is_regular_file = !md->is_dir;

	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 11, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_RISCOS);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	if(md->is_dir) {
		de_strarray_push(d->curpath, md->fn);
	}
	pos += 11;

	md->orig_len = de_getu32le_p(&pos);
	if(md->is_regular_file) {
		de_dbg(c, "orig file length: %"I64_FMT, md->orig_len);
	}

	md->load_addr = (u32)de_getu32le_p(&pos);
	md->exec_addr = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)md->load_addr,
		(unsigned int)md->exec_addr);
	de_dbg_indent(c, 1);
	if((md->load_addr&0xfff00000U)==0xfff00000U) {
		md->file_type = (unsigned int)((md->load_addr&0xfff00)>>8);
		md->file_type_known = 1;
		de_dbg(c, "file type: %03X", md->file_type);

		de_riscos_loadexec_to_timestamp(md->load_addr, md->exec_addr, &md->mod_time);
		dbg_timestamp(c, &md->mod_time, "timestamp");
	}
	de_dbg_indent(c, -1);

	md->attribs = (u32)de_getu32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)md->attribs);
	de_dbg_indent(c, 1);
	md->crc = md->attribs>>16;
	if(md->is_regular_file) {
		de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc);
	}
	if(md->cmpr_method==0xff || md->cmpr_method==0x88) {
		md->lzwmaxbits = (unsigned int)((md->attribs&0xff00)>>8);
		de_dbg(c, "lzw maxbits: %u", md->lzwmaxbits);
	}
	de_dbg_indent(c, -1);

	md->cmpr_len = de_getu32le_p(&pos);
	if(md->is_regular_file) {
		de_dbg(c, "compressed length: %"I64_FMT, md->cmpr_len);
	}

	de_dbg(c, "info word: 0x%08x", (unsigned int)info_word);
	de_dbg_indent(c, 1);
	de_dbg(c, "is directory: %d", md->is_dir);
	if(md->is_regular_file) {
		md->file_data_offs_rel = (i64)info_word;
		md->file_data_offs_abs = d->data_offs+md->file_data_offs_rel;
		de_dbg(c, "file data offset: (%"I64_FMT"+)%"I64_FMT,
			d->data_offs, md->file_data_offs_rel);
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);

	do_extract_member(c, d, md);

done:
	destroy_member_data(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_members(deark *c, lctx *d, i64 pos1)
{
	i64 k;
	i64 pos = pos1;

	for(k=0; k<d->nmembers; k++) {
		if(pos>=c->infile->len) break;
		de_dbg(c, "member[%d]", (int)k);
		de_dbg_indent(c, 1);
		do_member(c, d, k, pos);
		de_dbg_indent(c, -1);
		pos += 36;
	}
}

static void de_run_arcfs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->append_type = de_get_ext_option_bool(c, "arcfs:appendtype", 0);

	pos = 0;
	if(!do_file_header(c, d, pos)) goto done;
	pos += 96;

	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	do_members(c, d, pos);

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
}

static int de_identify_arcfs(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Archive\x00", 8))
		return 100;
	return 0;
}

static void de_help_arcfs(deark *c)
{
	de_msg(c, "-opt arcfs:appendtype : Append the file type to the filename");
}

void de_module_arcfs(deark *c, struct deark_module_info *mi)
{
	mi->id = "arcfs";
	mi->desc = "ArcFS (RISC OS archive)";
	mi->run_fn = de_run_arcfs;
	mi->identify_fn = de_identify_arcfs;
	mi->help_fn = de_help_arcfs;
}

///////////////////////////////////////////////////////////////////////////
// Squash

// TODO?: The squash module has a lot of duplicated code with the arcfs and
// compress modules. This could be consolidated, but it might not be worth the
// added complexity.

typedef struct sqctx_struct {
	int reserved;
} sqctx;

static void do_squash_header(deark *c, sqctx *d, struct member_data *md, i64 pos1)
{
	i64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos1);

	de_dbg_indent(c, 1);
	pos += 4; // signature
	md->orig_len = de_getu32le_p(&pos);
	de_dbg(c, "orig file length: %"I64_FMT, md->orig_len);

	md->load_addr = (u32)de_getu32le_p(&pos);
	md->exec_addr = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)md->load_addr,
		(unsigned int)md->exec_addr);
	de_dbg_indent(c, 1);
	if((md->load_addr&0xfff00000U)==0xfff00000U) {
		md->file_type = (unsigned int)((md->load_addr&0xfff00)>>8);
		md->file_type_known = 1;
		de_dbg(c, "file type: %03X", md->file_type);

		de_riscos_loadexec_to_timestamp(md->load_addr, md->exec_addr, &md->mod_time);
		dbg_timestamp(c, &md->mod_time, "timestamp");
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);
}

static void de_run_squash(deark *c, de_module_params *mparams)
{
	sqctx *d = NULL;
	struct member_data *md = NULL;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *fn = NULL;
	int ret;

	d = de_malloc(c, sizeof(sqctx));
	md = de_malloc(c, sizeof(struct member_data));

	do_squash_header(c, d, md, 0);

	md->file_data_offs_abs = 20;
	md->cmpr_len = c->infile->len - md->file_data_offs_abs;
	de_dbg(c, "compressed data at %"I64_FMT, md->file_data_offs_abs);

	fi = de_finfo_create(c);

	fn = ucstring_create(c);
	ucstring_append_sz(fn, "bin", DE_ENCODING_LATIN1);
	if(md->file_type_known && c->filenames_from_file) {
		ucstring_printf(fn, DE_ENCODING_LATIN1, ",%03X", md->file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fn, 0);

	if(md->mod_time.is_valid) {
		fi->mod_time = md->mod_time;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	ret = de_decompress_liblzw(c->infile, md->file_data_offs_abs, md->cmpr_len,
		outf, 1, md->orig_len, 0x1, 0);

	if(!ret) goto done;

	if(outf->len != md->orig_len) {
		de_err(c, "Decompression failed, expected size %"I64_FMT
			", got %"I64_FMT, md->orig_len, outf->len);
		goto done;
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn);
	destroy_member_data(c, md);
	de_free(c, d);
}

static int de_identify_squash(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "SQSH", 4))
		return 100;
	return 0;
}

void de_module_squash(deark *c, struct deark_module_info *mi)
{
	mi->id = "squash";
	mi->desc = "Squash (RISC OS compressed file)";
	mi->run_fn = de_run_squash;
	mi->identify_fn = de_identify_squash;
}
