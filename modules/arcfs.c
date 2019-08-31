// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// ArcFS
// Spark
// Squash

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arcfs);
DE_DECLARE_MODULE(de_module_spark);
DE_DECLARE_MODULE(de_module_squash);

struct de_riscos_file_attrs {
	u8 file_type_known;
	u32 load_addr, exec_addr;
	u32 attribs;
	unsigned int file_type;
	unsigned int lzwmaxbits;
	u32 crc_from_attribs;
	struct de_timestamp mod_time;
};

struct arcfs_member_data {
	struct de_riscos_file_attrs rfa;
	int is_dir;
	int is_regular_file;
	u8 cmpr_method;
	i64 file_data_offs_rel;
	i64 file_data_offs_abs;
	i64 orig_len;
	i64 cmpr_len;
	const char *cmpr_meth_name;
	de_ucstring *fn;
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

static void do_riscos_read_load_exec(deark *c, struct de_riscos_file_attrs *rfa, i64 pos1)
{
	i64 pos = pos1;

	rfa->load_addr = (u32)de_getu32le_p(&pos);
	rfa->exec_addr = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)rfa->load_addr,
		(unsigned int)rfa->exec_addr);
	de_dbg_indent(c, 1);
	if((rfa->load_addr&0xfff00000U)==0xfff00000U) {
		rfa->file_type = (unsigned int)((rfa->load_addr&0xfff00)>>8);
		rfa->file_type_known = 1;
		de_dbg(c, "file type: %03X", rfa->file_type);

		de_riscos_loadexec_to_timestamp(rfa->load_addr, rfa->exec_addr, &rfa->mod_time);
		dbg_timestamp(c, &rfa->mod_time, "timestamp");
	}
	de_dbg_indent(c, -1);
}

#define DE_RISCOS_FLAG_HAS_CRC          0x1
#define DE_RISCOS_FLAG_HAS_LZWMAXBITS   0x2
static void do_riscos_read_attribs_field(deark *c, struct de_riscos_file_attrs *rfa,
	i64 pos, unsigned int flags)
{
	rfa->attribs = (u32)de_getu32le(pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)rfa->attribs);
	de_dbg_indent(c, 1);
	rfa->crc_from_attribs = rfa->attribs>>16;
	if(flags & DE_RISCOS_FLAG_HAS_CRC) {
		de_dbg(c, "crc (reported): 0x%04x", (unsigned int)rfa->crc_from_attribs);
	}
	if(flags & DE_RISCOS_FLAG_HAS_LZWMAXBITS) {
		rfa->lzwmaxbits = (unsigned int)((rfa->attribs&0xff00)>>8);
		de_dbg(c, "lzw maxbits: %u", rfa->lzwmaxbits);
	}
	de_dbg_indent(c, -1);
}

static int do_arcfs_file_header(deark *c, lctx *d, i64 pos1)
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

static int do_arcfs_compressed(deark *c, lctx *d, struct arcfs_member_data *md, dbuf *outf,
	int limit_size_flag)
{
	u8 lzwmode;
	int retval = 0;

	lzwmode = (u8)(md->rfa.lzwmaxbits | 0x80);
	retval = de_decompress_liblzw(c->infile, md->file_data_offs_abs, md->cmpr_len,
		outf, limit_size_flag, md->orig_len, 0x2, lzwmode);
	return retval;
}

static int do_arcfs_crunched(deark *c, lctx *d, struct arcfs_member_data *md, dbuf *outf)
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
	ret1 = do_arcfs_compressed(c, d, md, tmpf, 0);
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

static void do_arcfs_extract_member_file(deark *c, lctx *d, struct arcfs_member_data *md,
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
	if(d->append_type && md->rfa.file_type_known) {
		// Append the file type to the filename, like nspark's -X option.
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->rfa.file_type);
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
		ret = do_arcfs_compressed(c, d, md, outf, 1);
		if(!ret) {
			goto done;
		}
	}
	else if(md->cmpr_method==0x88) {
		ret = do_arcfs_crunched(c, d, md, outf);
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
	if(crc_calc != md->rfa.crc_from_attribs) {
		if(md->rfa.crc_from_attribs==0) {
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
static void do_arcfs_extract_member_dir(deark *c, lctx *d, struct arcfs_member_data *md,
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

static void do_arcfs_extract_member(deark *c, lctx *d, struct arcfs_member_data *md)
{
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;
	if(md->rfa.mod_time.is_valid) {
		fi->mod_time = md->rfa.mod_time;
	}

	if(md->is_regular_file) {
		do_arcfs_extract_member_file(c, d, md, fi);
	}
	else if(md->is_dir) {
		do_arcfs_extract_member_dir(c, d, md, fi);
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

static void destroy_arcfs_member_data(deark *c, struct arcfs_member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->fn);
	de_free(c, md);
}

static void do_arcfs_member(deark *c, lctx *d, i64 idx, i64 pos1)
{
	i64 pos = pos1;
	u32 info_word;
	u8 info_byte;
	unsigned int tmpflags;
	int saved_indent_level;
	struct arcfs_member_data *md;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct arcfs_member_data));
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

	do_riscos_read_load_exec(c, &md->rfa, pos);
	pos += 8;

	tmpflags = 0;
	if(md->is_regular_file)
		tmpflags |= DE_RISCOS_FLAG_HAS_CRC;
	if(md->cmpr_method==0xff || md->cmpr_method==0x88)
		tmpflags |= DE_RISCOS_FLAG_HAS_LZWMAXBITS;
	do_riscos_read_attribs_field(c, &md->rfa, pos, tmpflags);
	pos += 4;

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

	do_arcfs_extract_member(c, d, md);

done:
	destroy_arcfs_member_data(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_arcfs_members(deark *c, lctx *d, i64 pos1)
{
	i64 k;
	i64 pos = pos1;

	for(k=0; k<d->nmembers; k++) {
		if(pos>=c->infile->len) break;
		de_dbg(c, "member[%d]", (int)k);
		de_dbg_indent(c, 1);
		do_arcfs_member(c, d, k, pos);
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
	if(!do_arcfs_file_header(c, d, pos)) goto done;
	pos += 96;

	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	do_arcfs_members(c, d, pos);

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
// Spark

struct spark_member_data {
	struct de_riscos_file_attrs rfa;
	int is_dir;
	u8 cmpr_meth;
	i64 orig_size;
	i64 cmpr_size;
	u32 crc_reported;
	const char *cmpr_meth_name;
	de_ucstring *fn;
	struct de_timestamp arc_timestamp;
};

typedef struct sparkctx_struct {
	int input_encoding;
	int append_type;
	i64 nmembers;
	int level; // subdirectory nesting level
	struct de_crcobj *crco;
	struct de_strarray *curpath;
} spkctx;

struct riscos_dcmpr_params {
	dbuf *inf;
	dbuf *outf;
	i64 cmpr_pos;
	i64 cmpr_len;
	i64 uncmpr_len_expected;
	u8 cmpr_meth;
	const char *cmpr_meth_name;
};

static int is_spark_cmpr_meth_supported(deark *c, spkctx *d, u8 n)
{
	if(n==0x82) return 1;
	if(n==0xff) return 1;
	return 0;
}

static int do_dcmpr_compressed(deark *c, struct riscos_dcmpr_params *dcmpr, de_ucstring *fname)
{
	int retval = 0;
	u8 lzwmaxbits;

	// Note: This is Spark-specific.
	if(dcmpr->cmpr_len < 1) {
		goto done;
	}

	lzwmaxbits = dbuf_getbyte(dcmpr->inf, dcmpr->cmpr_pos);
	de_dbg(c, "lzw maxbits: %u", (unsigned int)lzwmaxbits);

	retval = de_decompress_liblzw(dcmpr->inf, dcmpr->cmpr_pos+1, dcmpr->cmpr_len-1,
		dcmpr->outf, 1, dcmpr->uncmpr_len_expected, 0x0, 0x80|lzwmaxbits);

done:
	if(!retval) {
		de_err(c, "%s: 'compressed' decompression failed", ucstring_getpsz_d(fname));
	}
	return retval;
}

// fname = a filename to use in error messages
static int do_riscos_extract_file(deark *c, struct riscos_dcmpr_params *dcmpr, de_ucstring *fname)
{
	int retval = 0;

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT,
		dcmpr->cmpr_pos, dcmpr->cmpr_len);

	if(dcmpr->cmpr_pos + dcmpr->cmpr_len > dcmpr->inf->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(fname));
		goto done;
	}

	if(dcmpr->cmpr_meth==0x82) { // stored
		dbuf_copy(dcmpr->inf, dcmpr->cmpr_pos, dcmpr->cmpr_len, dcmpr->outf);
	}
	else if(dcmpr->cmpr_meth==0xff) {
		if(!do_dcmpr_compressed(c, dcmpr, fname)) {
			goto done;
		}
	}
	else {
		de_err(c, "%s: Extraction not implemented", ucstring_getpsz_d(fname));
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void spark_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_spark_extract_member_file(deark *c, spkctx *d, struct spark_member_data *md,
	de_finfo *fi, i64 pos)
{
	de_ucstring *fullfn = NULL;
	dbuf *outf = NULL;
	struct riscos_dcmpr_params *dcmpr = NULL;
	int ret;
	u32 crc_calc;

	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
	if(d->append_type && md->rfa.file_type_known) {
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	if(!is_spark_cmpr_meth_supported(c, d, md->cmpr_meth)) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	outf->writecallback_fn = spark_writecallback;
	outf->userdata = (void*)d->crco;
	de_crcobj_reset(d->crco);

	dcmpr = de_malloc(c, sizeof(struct riscos_dcmpr_params));
	dcmpr->cmpr_meth = md->cmpr_meth;
	dcmpr->cmpr_meth_name = md->cmpr_meth_name;
	dcmpr->inf = c->infile;
	dcmpr->outf = outf;
	dcmpr->cmpr_pos = pos;
	dcmpr->cmpr_len = md->cmpr_size;
	dcmpr->uncmpr_len_expected = md->orig_size;

	ret = do_riscos_extract_file(c, dcmpr, md->fn);
	if(!ret) goto done;

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(crc_calc != md->crc_reported) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fn));
	}

done:
	dbuf_close(outf);
	ucstring_destroy(fullfn);
	de_free(c, dcmpr);
}

// "Extract" a directory entry
static void do_spark_extract_member_dir(deark *c, spkctx *d, struct spark_member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	de_ucstring *fullfn = NULL;

	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	fi->is_directory = 1;
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_close(outf);
	ucstring_destroy(fullfn);
}

// Note: This shares a lot of code with ARC.
// Returns 1 if we can and should continue after this member.
static int do_spark_member(deark *c, spkctx *d, i64 pos1, i64 *bytes_consumed)
{
	u8 magic;
	int saved_indent_level;
	int retval = 0;
	i64 pos = pos1;
	i64 mod_time_raw, mod_date_raw;
	de_finfo *fi = NULL;
	struct spark_member_data *md = NULL;
	int need_curpath_pop = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md = de_malloc(c, sizeof(struct spark_member_data));
	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(d->nmembers==0) {
			de_err(c, "Not a Spark file");
		}
		else {
			de_err(c, "Failed to find Spark member at %"I64_FMT", stopping", pos1);
		}
		goto done;
	}

	md->cmpr_meth = de_getbyte_p(&pos);
	if(md->cmpr_meth>=0x81) {
		md->cmpr_meth_name = get_info_byte_name(md->cmpr_meth);
	}
	else if(md->cmpr_meth==0x80) {
		md->cmpr_meth_name = "end of dir marker";
	}
	else {
		md->cmpr_meth_name = "?";
	}
	de_dbg(c, "cmpr meth: 0x%02x (%s)", (unsigned int)md->cmpr_meth, md->cmpr_meth_name);

	if(md->cmpr_meth==0x80) { // end of dir marker
		*bytes_consumed = 2;

		if(d->level<1) { // actually, end of the whole archive
			goto done;
		}

		d->level--;
		de_strarray_pop(d->curpath);
		retval = 1;
		goto done;
	}

	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	md->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);

	mod_date_raw = de_getu16le_p(&pos);
	mod_time_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&md->arc_timestamp, mod_date_raw, mod_time_raw);
	md->arc_timestamp.tzcode = DE_TZCODE_LOCAL;
	dbg_timestamp(c, &md->arc_timestamp, "timestamp (ARC)");

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if((md->cmpr_meth & 0x7f)==0x01) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	do_riscos_read_load_exec(c, &md->rfa, pos);
	pos += 8;

	do_riscos_read_attribs_field(c, &md->rfa, pos, 0);
	pos += 4;

	de_strarray_push(d->curpath, md->fn);

	md->is_dir = (md->rfa.file_type_known && (md->rfa.file_type==0xddc));
	if(md->is_dir) {
		d->level++;
		md->orig_size = 0;
		md->cmpr_size = 0;
	}
	else {
		need_curpath_pop = 1;
	}
	de_dbg(c, "is directory: %d", md->is_dir);

	*bytes_consumed = pos + md->cmpr_size - pos1;
	retval = 1;

	// Extract...
	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;

	if(md->rfa.mod_time.is_valid) {
		fi->mod_time = md->rfa.mod_time;
	}
	else if(md->arc_timestamp.is_valid) {
		fi->mod_time = md->arc_timestamp;
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}

	if(md->is_dir) {
		do_spark_extract_member_dir(c, d, md, fi);
	}
	else {
		do_spark_extract_member_file(c, d, md, fi, pos);
	}

done:
	if(need_curpath_pop) {
		de_strarray_pop(d->curpath);
	}
	if(fi) de_finfo_destroy(c, fi);
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_spark(deark *c, de_module_params *mparams)
{
	spkctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(spkctx));
	d->input_encoding = DE_ENCODING_RISCOS;
	d->append_type = de_get_ext_option_bool(c, "spark:appendtype", 0);
	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		ret = do_spark_member(c, d, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) break;
		pos += bytes_consumed;
		d->nmembers++;
	}

	if(d) {
		de_crcobj_destroy(d->crco);
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
}

static int de_identify_spark(deark *c)
{
	u8 b;
	u32 load_addr;
	int ldaddrcheck = 0;
	int has_trailer = 0;

	if(de_getbyte(0) != 0x1a) return 0;
	b = de_getbyte(1);
	if(b==0x82 || b==0x83 || b==0x84 || b==0x85 ||
		b==0x86 || b==0x88 || b==0x89 || b==0xff)
	{
		;
	}
	else {
		return 0;
	}

	load_addr = (u32)de_getu32le(29);
	if((load_addr & 0xfff00000) == 0xfff00000) {
		ldaddrcheck = 1;
	}

	if(de_getu16be(c->infile->len-2) == 0x1a80) {
		has_trailer = 1;
	}

	if(has_trailer && ldaddrcheck) return 85;
	if(ldaddrcheck) return 30;
	if(has_trailer) return 10;
	return 0;
}

void de_module_spark(deark *c, struct deark_module_info *mi)
{
	mi->id = "spark";
	mi->desc = "Spark archive";
	mi->run_fn = de_run_spark;
	mi->identify_fn = de_identify_spark;
}

///////////////////////////////////////////////////////////////////////////
// Squash

typedef struct sqctx_struct {
	i64 cmpr_data_pos;
	i64 orig_len;
	i64 cmpr_len;
	struct de_riscos_file_attrs rfa;
} sqctx;

static void do_squash_header(deark *c, sqctx *d, i64 pos1)
{
	i64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos1);

	de_dbg_indent(c, 1);
	pos += 4; // signature
	d->orig_len = de_getu32le_p(&pos);
	de_dbg(c, "orig file length: %"I64_FMT, d->orig_len);

	do_riscos_read_load_exec(c, &d->rfa, pos);
	pos += 8;
	de_dbg_indent(c, -1);
}

static void de_run_squash(deark *c, de_module_params *mparams)
{
	sqctx *d = NULL;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *fn = NULL;
	int ret;

	d = de_malloc(c, sizeof(sqctx));

	do_squash_header(c, d, 0);

	d->cmpr_data_pos = 20;
	d->cmpr_len = c->infile->len - d->cmpr_data_pos;
	de_dbg(c, "compressed data at %"I64_FMT, d->cmpr_data_pos);

	fi = de_finfo_create(c);

	fn = ucstring_create(c);
	ucstring_append_sz(fn, "bin", DE_ENCODING_LATIN1);
	if(d->rfa.file_type_known && c->filenames_from_file) {
		ucstring_printf(fn, DE_ENCODING_LATIN1, ",%03X", d->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fn, 0);

	if(d->rfa.mod_time.is_valid) {
		fi->mod_time = d->rfa.mod_time;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	ret = de_decompress_liblzw(c->infile, d->cmpr_data_pos, d->cmpr_len,
		outf, 1, d->orig_len, 0x1, 0);

	if(!ret) goto done;

	if(outf->len != d->orig_len) {
		de_err(c, "Decompression failed, expected size %"I64_FMT
			", got %"I64_FMT, d->orig_len, outf->len);
		goto done;
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn);
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
