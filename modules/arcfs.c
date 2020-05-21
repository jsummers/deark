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

#define MAX_NESTING_LEVEL 32

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
	int subdir_level;
	i64 nmembers;
	i64 data_offs;
	struct de_crcobj *crco;
	struct de_strarray *curpath;
} lctx;

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

static void do_arcfs_compressed(deark *c, lctx *d, struct arcfs_member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.max_code_size = md->rfa.lzwmaxbits;
	if(!dcmpro->len_known) {
		delzwp.flags |= DE_LZWFLAG_TOLERATETRAILINGJUNK;
	}
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void do_arcfs_crunched(deark *c, lctx *d, struct arcfs_member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	// "Crunched" means "packed", then "compressed".
	// So we have to "uncompress" (LZW), then "unpack" (RLE90).

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.max_code_size = md->rfa.lzwmaxbits;

	// This flag tells the LZW decompressor to stop, instead of reporting failure,
	// if bad LZW compressed data is encountered.
	// The problem is that some ArcFS files have garbage at the end of the
	// compressed data.
	// Apparently, we're expected to have a single decompression algorithm that
	// handles both layers of compression simultaneously, without any buffering
	// between them. That way, we could stop immediately when we've decompressed
	// a sufficient number of bytes, and never encounter the garbage. But we
	// don't have that.
	delzwp.flags |= DE_LZWFLAG_TOLERATETRAILINGJUNK;

	de_dfilter_decompress_two_layer(c, dfilter_lzw_codec, (void*)&delzwp,
		dfilter_rle90_codec, NULL, dcmpri, dcmpro, dres);
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_arcfs_extract_member_file(deark *c, lctx *d, struct arcfs_member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	u32 crc_calc;
	de_ucstring *fullfn = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int have_dres = 0;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
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

	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);
	de_crcobj_reset(d->crco);

	dcmpri.f = c->infile;
	dcmpri.pos = md->file_data_offs_abs;
	dcmpri.len = md->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_len;

	if(md->cmpr_method==0x82) { // stored
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
	}
	else if(md->cmpr_method==0x83) {
		de_fmtutil_decompress_rle90_ex(c, &dcmpri, &dcmpro, &dres, 0);
		have_dres = 1;
	}
	else if(md->cmpr_method==0xff) {
		do_arcfs_compressed(c, d, md, &dcmpri, &dcmpro, &dres);
		have_dres = 1;
	}
	else if(md->cmpr_method==0x88) {
		do_arcfs_crunched(c, d, md, &dcmpri, &dcmpro, &dres);
		have_dres = 1;
	}

	if(have_dres && dres.errcode!=0) {
		de_err(c, "%s: Decompression failed: %s",
			ucstring_getpsz_d(md->fn), de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(outf->len != md->orig_len) {
		de_err(c, "%s: Decompression failed: Expected size %"I64_FMT
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
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->rfa.mod_time;
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
	case 0x89: name="squashed"; break;
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

// Returns 0 only if we should stop parsing the entire arcfs file.
static int do_arcfs_member(deark *c, lctx *d, i64 idx, i64 pos1)
{
	i64 pos = pos1;
	u32 info_word;
	u8 info_byte;
	unsigned int tmpflags;
	int saved_indent_level;
	struct arcfs_member_data *md;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct arcfs_member_data));
	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	retval = 1;
	info_byte = de_getbyte_p(&pos);
	md->cmpr_meth_name = get_info_byte_name(info_byte);
	de_dbg(c, "info byte: 0x%02x (%s)", (unsigned int)info_byte, md->cmpr_meth_name);
	if(info_byte==1) goto done; // deleted object
	if(info_byte==0) { // end of directory marker
		if(d->subdir_level>0) d->subdir_level--;
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
		if(d->subdir_level >= MAX_NESTING_LEVEL) {
			de_err(c, "Directories nested too deeply");
			retval = 0;
			goto done;
		}
		d->subdir_level++;
		de_strarray_push(d->curpath, md->fn);
	}
	pos += 11;

	md->orig_len = de_getu32le_p(&pos);
	if(md->is_regular_file) {
		de_dbg(c, "orig file length: %"I64_FMT, md->orig_len);
	}

	de_fmtutil_riscos_read_load_exec(c, c->infile, &md->rfa, pos);
	pos += 8;

	tmpflags = 0;
	if(md->is_regular_file)
		tmpflags |= DE_RISCOS_FLAG_HAS_CRC;
	if(md->cmpr_method==0xff || md->cmpr_method==0x88)
		tmpflags |= DE_RISCOS_FLAG_HAS_LZWMAXBITS;
	de_fmtutil_riscos_read_attribs_field(c, c->infile, &md->rfa, pos, tmpflags);
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
	return retval;
}

static void do_arcfs_members(deark *c, lctx *d, i64 pos1)
{
	i64 k;
	i64 pos = pos1;

	for(k=0; k<d->nmembers; k++) {
		int ret;

		if(pos>=c->infile->len) break;
		de_dbg(c, "member[%d]", (int)k);
		de_dbg_indent(c, 1);
		ret = do_arcfs_member(c, d, k, pos);
		de_dbg_indent(c, -1);
		if(!ret) break;
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

	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);
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
// Squash

typedef struct sqctx_struct {
	i64 orig_len;
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

	de_fmtutil_riscos_read_load_exec(c, c->infile, &d->rfa, pos);
	pos += 8;
	de_dbg_indent(c, -1);
}

static void do_squash_main(deark *c, sqctx *d)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *fn = NULL;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct delzw_params delzwp;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = c->infile;
	dcmpri.pos = 20;
	dcmpri.len = c->infile->len - dcmpri.pos;
	de_dbg(c, "compressed data at %"I64_FMT, dcmpri.pos);
	de_dbg_indent(c, 1);

	fi = de_finfo_create(c);

	fn = ucstring_create(c);
	ucstring_append_sz(fn, "bin", DE_ENCODING_LATIN1);
	if(d->rfa.file_type_known && c->filenames_from_file) {
		ucstring_printf(fn, DE_ENCODING_LATIN1, ",%03X", d->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fn, 0);

	if(d->rfa.mod_time.is_valid) {
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = d->rfa.mod_time;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	dcmpro.f = outf;
	dcmpro.len_known = 0;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS3BYTEHEADER;

	de_fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(outf->len != d->orig_len) {
		de_err(c, "Decompression failed, expected size %"I64_FMT
			", got %"I64_FMT, d->orig_len, outf->len);
		goto done;
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_squash(deark *c, de_module_params *mparams)
{
	sqctx *d = NULL;

	d = de_malloc(c, sizeof(sqctx));

	do_squash_header(c, d, 0);
	do_squash_main(c, d);

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
