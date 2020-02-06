// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ZIP format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_zip);

struct localctx_struct;
typedef struct localctx_struct lctx;

#define CODE_PK12 0x02014b50U
#define CODE_PK34 0x04034b50U
static const u8 g_zipsig34[4] = {'P', 'K', 0x03, 0x04};
static const u8 g_zipsig56[4] = {'P', 'K', 0x05, 0x06};
static const u8 g_zipsig66[4] = {'P', 'K', 0x06, 0x06};
static const u8 g_zipsig67[4] = {'P', 'K', 0x06, 0x07};

struct compression_params {
	// ZIP-specific params (not in de_dfilter_*_params) that may be needed to
	// to decompress something.
	int cmpr_meth;
	unsigned int bit_flags;
};

typedef void (*decompressor_fn)(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	int cmpr_meth;
	unsigned int flags;
	const char *name;
	decompressor_fn decompressor;
};

struct dir_entry_data {
	unsigned int ver_needed;
	unsigned int ver_needed_hi, ver_needed_lo;
	i64 cmpr_size, uncmpr_size;
	int cmpr_meth;
	const struct cmpr_meth_info *cmi;
	unsigned int bit_flags;
	u32 crc_reported;
	i64 main_fname_pos;
	i64 main_fname_len;
	de_ucstring *fname;
};

struct member_data {
	unsigned int ver_made_by;
	unsigned int ver_made_by_hi, ver_made_by_lo;
	unsigned int attr_i, attr_e;
	i64 offset_of_local_header;
	i64 disk_number_start;
	i64 file_data_pos;
	int is_nonexecutable;
	int is_executable;
	int is_dir;
	int is_symlink;
	struct de_crcobj *crco; // copy of lctx::crco
	struct de_timestamp mod_time; // The best timestamp found so far
	int mod_time_quality;

	struct dir_entry_data central_dir_entry_data;
	struct dir_entry_data local_dir_entry_data;

	i64 cmpr_size, uncmpr_size;
	u32 crc_reported;
};

struct extra_item_type_info_struct;

struct extra_item_info_struct {
	u32 id;
	i64 dpos;
	i64 dlen;
	const struct extra_item_type_info_struct *eiti;
	struct member_data *md;
	struct dir_entry_data *dd;
	int is_central;
};

struct localctx_struct {
	i64 end_of_central_dir_pos;
	i64 central_dir_num_entries;
	i64 central_dir_byte_size;
	i64 central_dir_offset;
	i64 this_disk_num;
	i64 zip64_eocd_pos;
	i64 zip64_cd_pos;
	unsigned int zip64_eocd_disknum;
	unsigned int zip64_cd_disknum;
	i64 offset_discrepancy;
	int used_offset_discrepancy;
	int is_zip64;
	int using_scanmode;
	struct de_crcobj *crco;
};

typedef void (*extrafield_decoder_fn)(deark *c, lctx *d,
	struct extra_item_info_struct *eii);

static int is_compression_method_supported(lctx *d, const struct cmpr_meth_info *cmi)
{
	if(cmi && cmi->decompressor) return 1;
	return 0;
}

static void do_decompress_shrink(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_zip_shrink(c, dcmpri, dcmpro, dres, 0);
}

static void do_decompress_reduce(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	unsigned int flags = 0;

	fmtutil_decompress_zip_reduce(c, dcmpri, dcmpro, dres,
		(unsigned int)(cparams->cmpr_meth-1), flags);
}

static void do_decompress_implode(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	unsigned int flags = 0;

	fmtutil_decompress_zip_implode(c, dcmpri, dcmpro, dres,
		cparams->bit_flags, flags);
}

static void do_decompress_deflate(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_deflate_ex(c, dcmpri, dcmpro, dres, 0, NULL);
}

static void do_decompress_stored(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0, 0x00, "stored", do_decompress_stored },
	{ 1, 0x00, "shrink", do_decompress_shrink },
	{ 2, 0x00, "reduce, CF=1", do_decompress_reduce },
	{ 3, 0x00, "reduce, CF=2", do_decompress_reduce },
	{ 4, 0x00, "reduce, CF=3", do_decompress_reduce },
	{ 5, 0x00, "reduce, CF=4", do_decompress_reduce },
	{ 6, 0x00, "implode", do_decompress_implode },
	{ 8, 0x00, "deflate", do_decompress_deflate },
	{ 9, 0x00, "deflate64", NULL },
	{ 10, 0x00, "PKWARE DCL implode", NULL },
	{ 12, 0x00, "bzip2", NULL },
	{ 14, 0x00, "LZMA", NULL },
	{ 16, 0x00, "IBM z/OS CMPSC", NULL },
	{ 18, 0x00, "IBM TERSE (new)", NULL },
	{ 19, 0x00, "IBM LZ77 z Architecture", NULL },
	{ 94, 0x00, "MP3", NULL },
	{ 95, 0x00, "XZ", NULL },
	{ 96, 0x00, "JPEG", NULL },
	{ 97, 0x00, "WavPack", NULL },
	{ 98, 0x00, "PPMd", NULL },
	{ 99, 0x00, "AES", NULL }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(int cmpr_meth)
{
	size_t k;

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_info_arr); k++) {
		if(cmpr_meth_info_arr[k].cmpr_meth == cmpr_meth) {
			return &cmpr_meth_info_arr[k];
		}
	}
	return NULL;
}

// Decompress some data from inf, using the given ZIP compression method,
// and append it to outf.
// On failure, prints an error and returns 0.
// Returns 1 on apparent success.
// TODO: How should this low-level function report errors and warnings?
static int do_decompress_data(deark *c, lctx *d,
	dbuf *inf, i64 inf_pos, i64 inf_size,
	dbuf *outf, i64 maxuncmprsize,
	int cmpr_meth, const struct cmpr_meth_info *cmi, unsigned int bit_flags)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct compression_params cparams;

	de_zeromem(&cparams, sizeof(struct compression_params));
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	cparams.cmpr_meth = cmpr_meth;
	cparams.bit_flags = bit_flags;
	dcmpri.f = inf;
	dcmpri.pos = inf_pos;
	dcmpri.len = inf_size;
	dcmpro.f = outf;
	dcmpro.expected_len = maxuncmprsize;
	dcmpro.len_known = 1;

	if(cmi && cmi->decompressor) {
		cmi->decompressor(c, d, &cparams, &dcmpri, &dcmpro, &dres);
		if(dres.errcode) {
			de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		}
		else {
			if(dres.bytes_consumed_valid && (dres.bytes_consumed < inf_size)) {
				de_warn(c, "Decompression may have failed (used only "
					"%"I64_FMT" of %"I64_FMT" compressed bytes)",
					dres.bytes_consumed, inf_size);
			}
			retval = 1;
		}
		goto done;
	}

	de_err(c, "Unsupported compression method: %d (%s)", cmpr_meth,
		(cmi ? cmi->name : "?"));

done:
	return retval;
}

// As we read a member file's attributes, we may encounter multiple timestamps,
// which can differ in their precision, and whether they use UTC.
// This function is called to remember the "best" file modification time
// encountered so far.
static void apply_mod_time(deark *c, lctx *d, struct member_data *md,
	const struct de_timestamp *ts, int quality)
{
	if(!ts->is_valid) return;

	// In case of a tie, we prefer the later timestamp that we encountered.
	// This makes local headers have priority over central headers, for
	// example.
	if(quality >= md->mod_time_quality) {
		md->mod_time = *ts;
		md->mod_time_quality = quality;
	}
}

static void do_read_filename(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	i64 pos, i64 len, int utf8_flag)
{
	de_encoding from_encoding;

	ucstring_empty(dd->fname);
	from_encoding = utf8_flag ? DE_ENCODING_UTF8 : DE_ENCODING_CP437_G;
	dbuf_read_to_ucstring(c->infile, pos, len, dd->fname, 0, from_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(dd->fname));
}

static void do_comment_display(deark *c, lctx *d, i64 pos, i64 len, de_encoding encoding,
	const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment_extract(deark *c, lctx *d, i64 pos, i64 len, de_encoding encoding,
	const char *ext)
{
	dbuf *f = NULL;
	de_ucstring *s = NULL;

	f = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	ucstring_write_as_utf8(c, s, f, 1);
	ucstring_destroy(s);
}

static void do_comment(deark *c, lctx *d, i64 pos, i64 len, int utf8_flag,
	const char *name, const char *ext)
{
	de_encoding encoding;

	if(len<1) return;
	encoding = utf8_flag ? DE_ENCODING_UTF8 : DE_ENCODING_CP437_C;
	if(c->extract_level>=2) {
		do_comment_extract(c, d, pos, len, encoding, ext);
	}
	else {
		do_comment_display(c, d, pos, len, encoding, name);
	}
}

static void read_unix_timestamp(deark *c, lctx *d, i64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	i64 t;
	char timestamp_buf[64];

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, timestamp, 0x1);
	de_dbg_timestamp_to_string(c, timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t, timestamp_buf);
}

static void read_FILETIME(deark *c, lctx *d, i64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	i64 t_FILETIME;
	char timestamp_buf[64];

	t_FILETIME = de_geti64le(pos);
	de_FILETIME_to_timestamp(t_FILETIME, timestamp, 0x1);
	de_dbg_timestamp_to_string(c, timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void ef_zip64extinfo(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 n;
	i64 pos = eii->dpos;

	if(pos+8 > eii->dpos+eii->dlen) goto done;
	n = de_geti64le(pos); pos += 8;
	de_dbg(c, "orig uncmpr file size: %"I64_FMT, n);
	if(eii->dd->uncmpr_size==0xffffffffLL) {
		eii->dd->uncmpr_size = n;
	}

	if(pos+8 > eii->dpos+eii->dlen) goto done;
	n = de_geti64le(pos); pos += 8;
	de_dbg(c, "cmpr data size: %"I64_FMT, n);
	if(eii->dd->cmpr_size==0xffffffffLL) {
		eii->dd->cmpr_size = n;
	}

	if(pos+8 > eii->dpos+eii->dlen) goto done;
	n = de_geti64le(pos); pos += 8;
	de_dbg(c, "offset of local header record: %"I64_FMT, n);

	if(pos+4 > eii->dpos+eii->dlen) goto done;
	n = de_getu32le_p(&pos);
	de_dbg(c, "disk start number: %"I64_FMT, n);
done:
	;
}

// Extra field 0x5455
static void ef_extended_timestamp(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	u8 flags;
	i64 endpos;
	int has_mtime, has_atime, has_ctime;
	struct de_timestamp timestamp_tmp;

	endpos = pos + eii->dlen;
	if(pos+1>endpos) return;
	flags = de_getbyte_p(&pos);
	if(eii->is_central) {
		has_mtime = (eii->dlen>=5);
		has_atime = 0;
		has_ctime = 0;
	}
	else {
		has_mtime = (flags & 0x01)?1:0;
		has_atime = (flags & 0x02)?1:0;
		has_ctime = (flags & 0x04)?1:0;
	}
	if(has_mtime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "mtime");
		apply_mod_time(c, d, eii->md, &timestamp_tmp, 50);
		pos+=4;
	}
	if(has_atime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "atime");
		pos+=4;
	}
	if(has_ctime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "creation time");
		pos+=4;
	}
}

// Extra field 0x5855
static void ef_infozip1(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 uidnum, gidnum;
	struct de_timestamp timestamp_tmp;

	if(eii->is_central && eii->dlen<8) return;
	if(!eii->is_central && eii->dlen<12) return;
	read_unix_timestamp(c, d, eii->dpos, &timestamp_tmp, "atime");
	read_unix_timestamp(c, d, eii->dpos+4, &timestamp_tmp, "mtime");
	apply_mod_time(c, d, eii->md, &timestamp_tmp, 45);
	if(!eii->is_central) {
		uidnum = de_getu16le(eii->dpos+8);
		gidnum = de_getu16le(eii->dpos+10);
		de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
	}
}

// Extra field 0x7075 - Info-ZIP Unicode Path
static void ef_unicodepath(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	u8 ver;
	de_ucstring *fn = NULL;
	i64 fnlen;
	u32 crc_reported, crc_calculated;
	struct de_crcobj *fncrco = NULL;

	if(eii->dlen<1) goto done;
	ver = de_getbyte(eii->dpos);
	de_dbg(c, "version: %u", (unsigned int)ver);
	if(ver!=1) goto done;
	if(eii->dlen<6) goto done;
	crc_reported = (u32)de_getu32le(eii->dpos+1);
	de_dbg(c, "name-crc (reported): 0x%08x", (unsigned int)crc_reported);
	fn = ucstring_create(c);
	fnlen = eii->dlen - 5;
	dbuf_read_to_ucstring(c->infile, eii->dpos+5, fnlen, fn, 0, DE_ENCODING_UTF8);
	de_dbg(c, "unicode name: \"%s\"", ucstring_getpsz_d(fn));

	// Need to go back and calculate a CRC of the main filename. This is
	// protection against the case where a ZIP editor may have changed the
	// original filename, but retained a now-orphaned Unicode Path field.
	fncrco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(fncrco, c->infile, eii->dd->main_fname_pos, eii->dd->main_fname_len);
	crc_calculated = de_crcobj_getval(fncrco);
	de_dbg(c, "name-crc (calculated): 0x%08x", (unsigned int)crc_calculated);

	if(crc_calculated == crc_reported) {
		ucstring_empty(eii->dd->fname);
		ucstring_append_ucstring(eii->dd->fname, fn);
	}

done:
	ucstring_destroy(fn);
	de_crcobj_destroy(fncrco);
}

// Extra field 0x7855
static void ef_infozip2(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 uidnum, gidnum;

	if(eii->is_central) return;
	if(eii->dlen<4) return;
	uidnum = de_getu16le(eii->dpos);
	gidnum = de_getu16le(eii->dpos+2);
	de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
}

// Extra field 0x7875
static void ef_infozip3(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 uidnum, gidnum;
	u8 ver;
	i64 endpos;
	i64 sz;

	endpos = pos+eii->dlen;

	if(pos+1>endpos) return;
	ver = de_getbyte_p(&pos);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=1) return;

	if(pos+1>endpos) return;
	sz = (i64)de_getbyte_p(&pos);
	if(pos+sz>endpos) return;
	uidnum = dbuf_getint_ext(c->infile, pos, (unsigned int)sz, 1, 0);
	pos += sz;

	if(pos+1>endpos) return;
	sz = (i64)de_getbyte_p(&pos);
	if(pos+sz>endpos) return;
	gidnum = dbuf_getint_ext(c->infile, pos, (unsigned int)sz, 1, 0);
	pos += sz;

	de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
}

// Extra field 0x000a
static void ef_ntfs(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 endpos;
	i64 attr_tag;
	i64 attr_size;
	const char *name;
	struct de_timestamp timestamp_tmp;

	endpos = pos+eii->dlen;
	pos += 4; // skip reserved field

	while(1) {
		if(pos+4>endpos) break;
		attr_tag = de_getu16le_p(&pos);
		attr_size = de_getu16le_p(&pos);
		if(attr_tag==0x0001) name="NTFS filetimes";
		else name="?";
		de_dbg(c, "tag: 0x%04x (%s), dlen: %d", (unsigned int)attr_tag, name,
			(int)attr_size);
		if(pos+attr_size>endpos) break;

		de_dbg_indent(c, 1);
		if(attr_tag==0x0001 && attr_size>=24) {
			read_FILETIME(c, d, pos, &timestamp_tmp, "mtime");
			apply_mod_time(c, d, eii->md, &timestamp_tmp, 90);
			read_FILETIME(c, d, pos+8, &timestamp_tmp, "atime");
			read_FILETIME(c, d, pos+16, &timestamp_tmp, "creation time");
		}
		de_dbg_indent(c, -1);

		pos += attr_size;
	}
}

// Extra field 0x0009
static void ef_os2(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 endpos;
	i64 unc_size;
	i64 cmpr_type;
	i64 crc;

	endpos = pos+eii->dlen;
	if(pos+4>endpos) return;
	unc_size = de_getu32le_p(&pos);
	de_dbg(c, "uncmpr ext attr data size: %d", (int)unc_size);
	if(eii->is_central) return;

	if(pos+2>endpos) return;
	cmpr_type = de_getu16le_p(&pos);
	de_dbg(c, "ext attr cmpr method: %d", (int)cmpr_type);

	if(pos+4>endpos) return;
	crc = de_getu32le_p(&pos);
	de_dbg(c, "ext attr crc: 0x%08x", (unsigned int)crc);

	de_dbg(c, "cmpr ext attr data at %"I64_FMT", len=%d", pos, (int)(endpos-pos));
	// TODO: Uncompress and decode OS/2 extended attribute structure (FEA2LIST)
}

// Extra field 0x2705 (ZipIt Macintosh 1.3.5+)
static void ef_zipitmac_2705(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	struct de_fourcc sig;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	if(eii->dlen<4) goto done;
	dbuf_read_fourcc(c->infile, eii->dpos, &sig, 4, 0x0);
	de_dbg(c, "signature: '%s'", sig.id_dbgstr);
	if(sig.id!=0x5a504954U) goto done; // expecting 'ZPIT'
	if(eii->dlen<12) goto done;
	dbuf_read_fourcc(c->infile, eii->dpos+4, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	dbuf_read_fourcc(c->infile, eii->dpos+8, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);

done:
	;
}

// The time will be returned in the caller-supplied 'ts'
static void handle_mac_time(deark *c, lctx *d,
	i64 mt_raw, i64 mt_offset,
	struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];
	de_mac_time_to_timestamp(mt_raw - mt_offset, ts);
	ts->tzcode = DE_TZCODE_UTC;
	de_dbg_timestamp_to_string(c, ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" %+"I64_FMT" (%s)", name,
		mt_raw, -mt_offset, timestamp_buf);
}

// Extra field 0x334d (Info-ZIP Macintosh)
static void ef_infozipmac(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 dpos;
	i64 ulen;
	i64 cmpr_attr_size;
	unsigned int flags;
	int cmpr_meth;
	const struct cmpr_meth_info *cmi = NULL;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	de_ucstring *flags_str = NULL;
	dbuf *attr_data = NULL;
	int ret;
	i64 create_time_raw;
	i64 create_time_offset;
	i64 mod_time_raw;
	i64 mod_time_offset;
	i64 backup_time_raw;
	i64 backup_time_offset;
	struct de_timestamp tmp_timestamp;
	int charset;
	struct de_stringreaderdata *srd;

	if(eii->dlen<14) goto done;

	ulen = de_getu32le_p(&pos);
	de_dbg(c, "uncmpr. finder attr. size: %d", (int)ulen);

	flags = (unsigned int)de_getu16le_p(&pos);
	flags_str = ucstring_create(c);
	if(flags&0x0001) ucstring_append_flags_item(flags_str, "data_fork");
	if(flags&0x0002) ucstring_append_flags_item(flags_str, "0x0002"); // something about the filename
	ucstring_append_flags_item(flags_str,
		(flags&0x0004)?"uncmpressed_attribute_data":"compressed_attribute_data");
	if(flags&0x0008) ucstring_append_flags_item(flags_str, "64-bit_times");
	if(flags&0x0010) ucstring_append_flags_item(flags_str, "no_timezone_offsets");
	de_dbg(c, "flags: 0x%04x (%s)", flags, ucstring_getpsz(flags_str));

	dbuf_read_fourcc(c->infile, pos, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);
	pos += 4;

	if(eii->is_central) goto done;

	if(flags&0x0004) { // Uncompressed attribute data
		cmpr_meth = 0;
	}
	else {
		unsigned int crc_reported;

		cmpr_meth = (int)de_getu16le_p(&pos);
		cmi = get_cmpr_meth_info(cmpr_meth);
		de_dbg(c, "finder attr. cmpr. method: %d (%s)", cmpr_meth, (cmi ? cmi->name : "?"));

		crc_reported = (unsigned int)de_getu32le_p(&pos);
		de_dbg(c, "finder attr. data crc (reported): 0x%08x", crc_reported);
	}

	// The rest of the data is Finder attribute data
	cmpr_attr_size = eii->dpos+eii->dlen - pos;
	de_dbg(c, "cmpr. finder attr. size: %d", (int)cmpr_attr_size);
	if(ulen<1 || ulen>1000000) goto done;

	// Type 6 (implode) compression won't work here, because it needs
	// additional parameters seemingly not provided by the Finder attr data.
	if(cmpr_meth==6 || !is_compression_method_supported(d, cmi)) {
		de_warn(c, "Finder attribute data: Unsupported compression method: %d (%s)",
			cmpr_meth, (cmi ? cmi->name : "?"));
	}

	// Decompress and decode the Finder attribute data
	attr_data = dbuf_create_membuf(c, ulen, 0x1);
	ret = do_decompress_data(c, d, c->infile, pos, cmpr_attr_size,
		attr_data, 65536, cmpr_meth, cmi, 0);
	if(!ret) {
		de_warn(c, "Failed to decompress finder attribute data");
		goto done;
	}

	dpos = 0;
	dpos += 2; // Finder flags
	dpos += 4; // Icon location
	dpos += 2; // Folder
	dpos += 16; // FXInfo
	dpos += 1; // file version number
	dpos += 1; // dir access rights

	if(flags&0x0008) goto done; // We don't support 64-bit times
	if(flags&0x0010) goto done; // We want timezone offsets
	if(attr_data->len - dpos < 6*4) goto done;

	create_time_raw = dbuf_getu32le_p(attr_data, &dpos);
	mod_time_raw    = dbuf_getu32le_p(attr_data, &dpos);
	backup_time_raw = dbuf_getu32le_p(attr_data, &dpos);
	create_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;
	mod_time_offset    = dbuf_geti32le(attr_data, dpos); dpos += 4;
	backup_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;

	handle_mac_time(c, d, create_time_raw, create_time_offset, &tmp_timestamp, "create time");
	handle_mac_time(c, d, mod_time_raw,    mod_time_offset,    &tmp_timestamp, "mod time   ");
	if(mod_time_raw>0) {
		apply_mod_time(c, d, eii->md, &tmp_timestamp, 40);
	}
	handle_mac_time(c, d, backup_time_raw, backup_time_offset, &tmp_timestamp, "backup time");

	// Expecting 2 bytes for charset, and at least 2 more for the 2 NUL-terminated
	// strings that follow.
	if(attr_data->len - dpos < 4) goto done;

	charset = (int)dbuf_getu16le_p(attr_data, &dpos);
	de_dbg(c, "charset for fullpath/comment: %d", charset);

	// TODO: Can we use the correct encoding?
	srd = dbuf_read_string(attr_data, dpos, attr_data->len-dpos, DE_DBG_MAX_STRLEN,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "fullpath: \"%s\"", ucstring_getpsz(srd->str));
	dpos += srd->bytes_consumed;
	de_destroy_stringreaderdata(c, srd);

	srd = dbuf_read_string(attr_data, dpos, attr_data->len-dpos, DE_DBG_MAX_STRLEN,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz(srd->str));
	dpos += srd->bytes_consumed;
	de_destroy_stringreaderdata(c, srd);

done:
	ucstring_destroy(flags_str);
	dbuf_close(attr_data);
}

// Acorn / SparkFS / RISC OS
static void ef_acorn(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	struct de_riscos_file_attrs rfa;

	if(eii->dlen<16) return;
	if(dbuf_memcmp(c->infile, eii->dpos, "ARC0", 4)) {
		de_dbg(c, "[unsupported Acorn extra-field type]");
		return;
	}
	pos += 4;

	de_zeromem(&rfa, sizeof(struct de_riscos_file_attrs));
	de_fmtutil_riscos_read_load_exec(c, c->infile, &rfa, pos);
	pos += 8;
	if(rfa.mod_time.is_valid) {
		apply_mod_time(c, d, eii->md, &rfa.mod_time, 70);
	}

	de_fmtutil_riscos_read_attribs_field(c, c->infile, &rfa, pos, 0);
	// Note: attribs does not have any information that we care about (no
	// 'executable' or 'is-directory' flag).
}

struct extra_item_type_info_struct {
	u16 id;
	const char *name;
	extrafield_decoder_fn fn;
};
static const struct extra_item_type_info_struct extra_item_type_info_arr[] = {
	{ 0x0001 /*    */, "Zip64 extended information", ef_zip64extinfo },
	{ 0x0007 /*    */, "AV Info", NULL },
	{ 0x0008 /*    */, "extended language encoding data", NULL },
	{ 0x0009 /*    */, "OS/2", ef_os2 },
	{ 0x000a /*    */, "NTFS", ef_ntfs },
	{ 0x000c /*    */, "OpenVMS", NULL },
	{ 0x000d /*    */, "Unix", NULL },
	{ 0x000e /*    */, "file stream and fork descriptors", NULL },
	{ 0x000f /*    */, "Patch Descriptor", NULL },
	{ 0x0014 /*    */, "PKCS#7 Store for X.509 Certificates", NULL },
	{ 0x0015 /*    */, "X.509 Certificate ID and Signature for individual file", NULL },
	{ 0x0016 /*    */, "X.509 Certificate ID for Central Directory", NULL },
	{ 0x0017 /*    */, "Strong Encryption Header", NULL },
	{ 0x0018 /*    */, "Record Management Controls", NULL },
	{ 0x0019 /*    */, "PKCS#7 Encryption Recipient Certificate List", NULL },
	{ 0x0021 /*    */, "Policy Decryption Key", NULL },
	{ 0x0022 /*    */, "Smartcrypt Key Provider", NULL },
	{ 0x0023 /*    */, "Smartcrypt Policy Key Data", NULL },
	{ 0x0065 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes", NULL },
	{ 0x0066 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes - compressed", NULL },
	{ 0x07c8 /*    */, "Macintosh", NULL },
	{ 0x2605 /*    */, "ZipIt Macintosh", NULL },
	{ 0x2705 /*    */, "ZipIt Macintosh 1.3.5+", ef_zipitmac_2705 },
	{ 0x2805 /*    */, "ZipIt Macintosh 1.3.5+", NULL },
	{ 0x334d /* M3 */, "Info-ZIP Macintosh", ef_infozipmac },
	{ 0x4154 /* TA */, "Tandem NSK", NULL },
	{ 0x4341 /* AC */, "Acorn/SparkFS", ef_acorn },
	{ 0x4453 /* SE */, "Windows NT security descriptor (binary ACL)", NULL },
	{ 0x4690 /*    */, "POSZIP 4690", NULL },
	{ 0x4704 /*    */, "VM/CMS", NULL },
	{ 0x470f /*    */, "MVS", NULL },
	{ 0x4854 /* TH */, "Theos, old unofficial port", NULL }, // unzip:extrafld.txt says "inofficial"
	{ 0x4b46 /* FK */, "FWKCS MD5", NULL },
	{ 0x4c41 /* AL */, "OS/2 access control list (text ACL)", NULL },
	{ 0x4d49 /* IM */, "Info-ZIP OpenVMS", NULL },
	{ 0x4d63 /* cM */, "Macintosh SmartZIP", NULL },
	{ 0x4f4c /* LO */, "Xceed original location", NULL },
	{ 0x5350 /* PS */, "Psion?", NULL }, // observed in some Psion files
	{ 0x5356 /* VS */, "AOS/VS (ACL)", NULL },
	{ 0x5455 /* UT */, "extended timestamp", ef_extended_timestamp },
	{ 0x554e /* NU */, "Xceed unicode", NULL },
	{ 0x5855 /* UX */, "Info-ZIP Unix, first version", ef_infozip1 },
	{ 0x6375 /* uc */, "Info-ZIP Unicode Comment", NULL },
	{ 0x6542 /* Be */, "BeOS/BeBox", NULL },
	{ 0x6854 /* Th */, "Theos", NULL },
	{ 0x7075 /* up */, "Info-ZIP Unicode Path", ef_unicodepath },
	{ 0x7441 /* At */, "AtheOS", NULL },
	{ 0x756e /* nu */, "ASi Unix", NULL },
	{ 0x7855 /* Ux */, "Info-ZIP Unix, second version", ef_infozip2 },
	{ 0x7875 /* ux */, "Info-ZIP Unix, third version", ef_infozip3 },
	{ 0xa220 /*    */, "Microsoft Open Packaging Growth Hint", NULL },
	{ 0xfb4a /*    */, "SMS/QDOS", NULL }, // according to Info-ZIP zip 3.0
	{ 0xfd4a /*    */, "SMS/QDOS", NULL }  // according to ZIP v6.3.4 APPNOTE
};

static const struct extra_item_type_info_struct *get_extra_item_type_info(i64 id)
{
	static const struct extra_item_type_info_struct default_ei =
		{ 0, "?", NULL };
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(extra_item_type_info_arr); i++) {
		if(id == (i64)extra_item_type_info_arr[i].id) {
			return &extra_item_type_info_arr[i];
		}
	}
	return &default_ei;
}

static void do_extra_data(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	i64 pos1, i64 len, int is_central)
{
	i64 pos;

	de_dbg(c, "extra data at %"I64_FMT", len=%d", pos1, (int)len);
	de_dbg_indent(c, 1);

	pos = pos1;
	while(1) {
		struct extra_item_info_struct eii;

		if(pos+4 >= pos1+len) break;
		de_zeromem(&eii, sizeof(struct extra_item_info_struct));
		eii.md = md;
		eii.dd = dd;
		eii.is_central = is_central;
		eii.dpos = pos+4;

		eii.id = (u32)de_getu16le(pos);
		eii.dlen = de_getu16le(pos+2);

		eii.eiti = get_extra_item_type_info(eii.id);

		de_dbg(c, "item id=0x%04x (%s), dlen=%d", (unsigned int)eii.id, eii.eiti->name,
			(int)eii.dlen);
		if(pos+4+eii.dlen > pos1+len) break;

		if(eii.eiti->fn) {
			de_dbg_indent(c, 1);
			eii.eiti->fn(c, d, &eii);
			de_dbg_indent(c, -1);
		}

		pos += 4+eii.dlen;
	}

	de_dbg_indent(c, -1);
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct member_data *md = (struct member_data *)userdata;
	de_crcobj_addbuf(md->crco, buf, buf_len);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct dir_entry_data *ldd = &md->local_dir_entry_data;
	u32 crc_calculated;
	int ret;

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, md->file_data_pos,
		md->cmpr_size);

	if(ldd->bit_flags & 0x1) {
		de_err(c, "%s: Encryption is not supported", ucstring_getpsz_d(ldd->fname));
		goto done;
	}

	if(!is_compression_method_supported(d, ldd->cmi)) {
		de_err(c, "%s: Unsupported compression method: %d (%s)",
			ucstring_getpsz_d(ldd->fname),
			ldd->cmpr_meth, (ldd->cmi ? ldd->cmi->name : "?"));
		goto done;
	}

	if(md->file_data_pos+md->cmpr_size > c->infile->len) {
		de_err(c, "Member data goes beyond end of file");
		goto done;
	}

	if(md->is_symlink) {
		de_warn(c, "\"%s\" is a symbolic link. It will not be extracted as a link.",
			ucstring_getpsz_d(ldd->fname));
	}

	fi = de_finfo_create(c);
	fi->detect_root_dot_dir = 1;

	if(ucstring_isnonempty(ldd->fname)) {
		unsigned int snflags = DE_SNFLAG_FULLPATH;
		if(md->is_dir) snflags |= DE_SNFLAG_STRIPTRAILINGSLASH;
		de_finfo_set_name_from_ucstring(c, fi, ldd->fname, snflags);
		fi->original_filename_flag = 1;
	}

	if(md->mod_time.is_valid) {
		fi->mod_time = md->mod_time;
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}
	else if(md->is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(md->is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	if(md->is_dir) {
		goto done;
	}

	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)md);
	md->crco = d->crco;
	de_crcobj_reset(md->crco);

	ret = do_decompress_data(c, d, c->infile, md->file_data_pos, md->cmpr_size,
		outf, md->uncmpr_size, ldd->cmpr_meth, ldd->cmi, ldd->bit_flags);
	if(!ret) goto done;

	crc_calculated = de_crcobj_getval(md->crco);
	de_dbg(c, "crc (calculated): 0x%08x", (unsigned int)crc_calculated);

	if(crc_calculated != md->crc_reported) {
		de_err(c, "%s: CRC check failed: Expected 0x%08x, got 0x%08x",
			ucstring_getpsz_d(ldd->fname),
			(unsigned int)md->crc_reported, (unsigned int)crc_calculated);
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static const char *get_platform_name(unsigned int ver_hi)
{
	static const char *pltf_names[20] = {
		"MS-DOS, etc.", "Amiga", "OpenVMS", "Unix",
		"VM/CMS", "Atari ST", "HPFS", "Macintosh",
		"Z-System", "CP/M", "NTFS or TOPS-20", "MVS or NTFS",
		"VSE or SMS/QDOS", "Acorn RISC OS", "VFAT", "MVS",
		"BeOS", "Tandem", "OS/400", "OS X" };

	if(ver_hi<20)
		return pltf_names[ver_hi];
	if(ver_hi==30) return "AtheOS/Syllable";
	return "?";
}

// Look at the attributes, and set some other fields based on them.
static void process_ext_attr(deark *c, lctx *d, struct member_data *md)
{
	if(d->using_scanmode) {
		// In this mode, there is no 'external attribs' field.
		return;
	}

	if(md->ver_made_by_hi==3) { // Unix
		unsigned int unix_filetype;
		unix_filetype = (md->attr_e>>16)&0170000;
		if(unix_filetype == 0040000) {
			md->is_dir = 1;
		}
		else if(unix_filetype == 0120000) {
			md->is_symlink = 1;
		}

		if((md->attr_e>>16)&0111) {
			md->is_executable = 1;
		}
		else {
			md->is_nonexecutable = 1;
		}
	}

	// MS-DOS-style attributes.
	// Technically, we should only do this if
	// md->central_dir_entry_data.ver_made_by_hi==0.
	// However, most(?) zip programs set the low byte of the external attribs
	// to the equivalent MS-DOS attribs, at least in cases where it matters.
	if(md->attr_e & 0x10) {
		md->is_dir = 1;
	}

	// TODO: Support more platforms.
	// TODO: The 0x756e (ASi Unix) extra field might be important, as it contains
	// file permissions.

	if(md->is_dir && md->uncmpr_size!=0) {
		// I'd expect a subdirectory entry to have zero size. If it doesn't,
		// let's just assume we misidentified it as a subdirectory, and
		// extract its data.
		md->is_dir = 0;
	}
}

static void describe_internal_attr(deark *c, struct member_data *md,
	de_ucstring *s)
{
	unsigned int bf = md->attr_i;

	if(bf & 0x0001) {
		ucstring_append_flags_item(s, "text file");
		bf -= 0x0001;
	}

	if(bf!=0) { // Report any unrecognized flags
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

// Uses dd->bit_flags, dd->cmpr_method
static void describe_general_purpose_bit_flags(deark *c, struct dir_entry_data *dd,
	de_ucstring *s)
{
	const char *name;
	unsigned int bf = dd->bit_flags;

	if(bf & 0x0001) {
		ucstring_append_flags_item(s, "encrypted");
		bf -= 0x0001;
	}

	if(dd->cmpr_meth==6) { // implode
		if(bf & 0x0002) {
			name = "8K";
			bf -= 0x0002;
		}
		else {
			name = "4K";
		}
		ucstring_append_flags_itemf(s, "%s sliding dictionary", name);

		if(bf & 0x0004) {
			name = "3";
			bf -= 0x0004;
		}
		else {
			name = "2";
		}
		ucstring_append_flags_itemf(s, "%s trees", name);
	}

	if(dd->cmpr_meth==8 || dd->cmpr_meth==9) { // deflate flags
		unsigned int code;

		code = (bf & 0x0006)>>1;
		switch(code) {
		case 1: name="max"; break;
		case 2: name="fast"; break;
		case 3: name="super_fast"; break;
		default: name="normal";
		}
		ucstring_append_flags_itemf(s, "cmprlevel=%s", name);
		bf -= (bf & 0x0006);
	}

	if(bf & 0x0008) {
		ucstring_append_flags_item(s, "uses data descriptor");
		bf -= 0x0008;
	}

	if(bf & 0x0800) {
		ucstring_append_flags_item(s, "UTF-8");
		bf -= 0x0800;
	}

	if(bf!=0) { // Report any unrecognized flags
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

static void describe_msdos_attribs(deark *c, unsigned int attr, de_ucstring *s)
{
	unsigned int bf = attr;

	if(bf & 0x01) {
		ucstring_append_flags_item(s, "read-only");
		bf -= 0x01;
	}
	if(bf & 0x10) {
		ucstring_append_flags_item(s, "directory");
		bf -= 0x10;
	}
	if(bf & 0x20) {
		ucstring_append_flags_item(s, "archive");
		bf -= 0x20;
	}

	if(bf!=0) { // Report any unrecognized flags
		ucstring_append_flags_itemf(s, "0x%02x", bf);
	}
}

// Read either a central directory entry (a.k.a. central directory file header),
// or a local file header.
static int do_file_header(deark *c, lctx *d, struct member_data *md,
	int is_central, i64 pos1, i64 *p_entry_size)
{
	i64 pos;
	u32 sig;
	i64 fn_len, extra_len, comment_len;
	int utf8_flag;
	int retval = 0;
	i64 fixed_header_size;
	i64 mod_time_raw, mod_date_raw;
	struct dir_entry_data *dd; // Points to either md->central or md->local
	de_ucstring *descr = NULL;
	struct de_timestamp dos_timestamp;
	char timestamp_buf[64];

	pos = pos1;
	descr = ucstring_create(c);
	if(is_central) {
		dd = &md->central_dir_entry_data;
		fixed_header_size = 46;
		de_dbg(c, "central dir entry at %"I64_FMT, pos);
	}
	else {
		dd = &md->local_dir_entry_data;
		fixed_header_size = 30;
		if(md->disk_number_start!=d->this_disk_num) {
			de_err(c, "Member file not in this ZIP file");
			return 0;
		}
		de_dbg(c, "local file header at %"I64_FMT, pos);
	}
	de_dbg_indent(c, 1);

	sig = (u32)de_getu32le_p(&pos);
	if(is_central && sig!=CODE_PK12) {
		de_err(c, "Central dir file header not found at %"I64_FMT, pos1);
		goto done;
	}
	else if(!is_central && sig!=CODE_PK34) {
		de_err(c, "Local file header not found at %"I64_FMT, pos1);
		goto done;
	}

	if(is_central) {
		md->ver_made_by = (unsigned int)de_getu16le_p(&pos);
		md->ver_made_by_hi = (unsigned int)((md->ver_made_by&0xff00)>>8);
		md->ver_made_by_lo = (unsigned int)(md->ver_made_by&0x00ff);
		de_dbg(c, "version made by: platform=%u (%s), ZIP spec=%u.%u",
			md->ver_made_by_hi, get_platform_name(md->ver_made_by_hi),
			(unsigned int)(md->ver_made_by_lo/10), (unsigned int)(md->ver_made_by_lo%10));
	}

	dd->ver_needed = (unsigned int)de_getu16le_p(&pos);
	dd->ver_needed_hi = (unsigned int)((dd->ver_needed&0xff00)>>8);
	dd->ver_needed_lo = (unsigned int)(dd->ver_needed&0x00ff);
	de_dbg(c, "version needed to extract: platform=%u (%s), ZIP spec=%u.%u",
		dd->ver_needed_hi, get_platform_name(dd->ver_needed_hi),
		(unsigned int)(dd->ver_needed_lo/10), (unsigned int)(dd->ver_needed_lo%10));

	dd->bit_flags = (unsigned int)de_getu16le_p(&pos);
	dd->cmpr_meth = (int)de_getu16le_p(&pos);
	dd->cmi = get_cmpr_meth_info(dd->cmpr_meth);

	utf8_flag = (dd->bit_flags & 0x800)?1:0;
	ucstring_empty(descr);
	describe_general_purpose_bit_flags(c, dd, descr);
	de_dbg(c, "flags: 0x%04x (%s)", dd->bit_flags, ucstring_getpsz(descr));

	de_dbg(c, "cmpr method: %d (%s)", dd->cmpr_meth,
		(dd->cmi ? dd->cmi->name : "?"));

	mod_time_raw = de_getu16le_p(&pos);
	mod_date_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&dos_timestamp, mod_date_raw, mod_time_raw);
	dos_timestamp.tzcode = DE_TZCODE_LOCAL;
	de_dbg_timestamp_to_string(c, &dos_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
	apply_mod_time(c, d, md, &dos_timestamp, 10);

	dd->crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "crc (reported): 0x%08x", (unsigned int)dd->crc_reported);

	dd->cmpr_size = de_getu32le_p(&pos);
	dd->uncmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %" I64_FMT ", uncmpr size: %" I64_FMT, dd->cmpr_size, dd->uncmpr_size);

	fn_len = de_getu16le_p(&pos);

	extra_len = de_getu16le_p(&pos);

	if(is_central) {
		comment_len = de_getu16le_p(&pos);
	}
	else {
		comment_len = 0;
	}

	if(!is_central) {
		md->file_data_pos = pos + fn_len + extra_len;
	}

	if(is_central) {
		md->disk_number_start = de_getu16le_p(&pos);

		md->attr_i = (unsigned int)de_getu16le_p(&pos);
		ucstring_empty(descr);
		describe_internal_attr(c, md, descr);
		de_dbg(c, "internal file attributes: 0x%04x (%s)", md->attr_i,
			ucstring_getpsz(descr));

		md->attr_e = (unsigned int)de_getu32le_p(&pos);
		de_dbg(c, "external file attributes: 0x%08x", md->attr_e);
		de_dbg_indent(c, 1);

		{
			// The low byte is, AFAIK, *almost* universally used for MS-DOS-style
			// attributes.
			unsigned int dos_attrs = (md->attr_e & 0xff);
			ucstring_empty(descr);
			describe_msdos_attribs(c, dos_attrs, descr);
			de_dbg(c, "%sMS-DOS attribs: 0x%02x (%s)",
				(md->ver_made_by_hi==0)?"":"(hypothetical) ",
				dos_attrs, ucstring_getpsz(descr));
		}

		if((md->attr_e>>16) != 0) {
			// A number of platforms put Unix-style file attributes here, so
			// decode them as such whenever they are nonzero.
			de_dbg(c, "%sUnix attribs: octal(%06o)",
				(md->ver_made_by_hi==3)?"":"(hypothetical) ",
				(unsigned int)(md->attr_e>>16));
		}

		de_dbg_indent(c, -1);

		md->offset_of_local_header = de_getu32le_p(&pos);
		de_dbg(c, "offset of local header: %"I64_FMT", disk: %d", md->offset_of_local_header,
			(int)md->disk_number_start);
	}

	if(is_central) {
		de_dbg(c, "filename_len: %d, extra_len: %d, comment_len: %d", (int)fn_len,
			(int)extra_len, (int)comment_len);
	}
	else {
		de_dbg(c, "filename_len: %d, extra_len: %d", (int)fn_len,
			(int)extra_len);
	}

	*p_entry_size = fixed_header_size + fn_len + extra_len + comment_len;

	dd->main_fname_pos = pos1+fixed_header_size;
	dd->main_fname_len = fn_len;
	do_read_filename(c, d, md, dd, pos1+fixed_header_size, fn_len, utf8_flag);

	if(extra_len>0) {
		do_extra_data(c, d, md, dd, pos1+fixed_header_size+fn_len, extra_len, is_central);
	}

	if(comment_len>0) {
		do_comment(c, d, pos1+fixed_header_size+fn_len+extra_len, comment_len, utf8_flag,
			"member file comment", "fcomment.txt");
	}

	if(is_central) {
		if(d->used_offset_discrepancy) {
			md->offset_of_local_header += d->offset_discrepancy;
			de_dbg(c, "assuming local header is really at %"I64_FMT, md->offset_of_local_header);
		}
		else if(d->offset_discrepancy!=0) {
			u32 sig1, sig2;
			i64 alt_pos;

			sig1 = (u32)de_getu32le(md->offset_of_local_header);
			if(sig1!=CODE_PK34) {
				alt_pos = md->offset_of_local_header + d->offset_discrepancy;
				sig2 = (u32)de_getu32le(alt_pos);
				if(sig2==CODE_PK34) {
					de_warn(c, "Local file header found at %"I64_FMT" instead of %"I64_FMT". "
						"Assuming offsets are wrong by %"I64_FMT" bytes.",
						alt_pos, md->offset_of_local_header, d->offset_discrepancy);
					md->offset_of_local_header += d->offset_discrepancy;
					d->used_offset_discrepancy = 1;
				}
			}
		}
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(descr);
	return retval;
}

static struct member_data *create_member_data(deark *c, lctx *d)
{
	struct member_data *md;

	md = de_malloc(c, sizeof(struct member_data));
	md->local_dir_entry_data.fname = ucstring_create(c);
	md->central_dir_entry_data.fname = ucstring_create(c);
	return md;
}

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->central_dir_entry_data.fname);
	ucstring_destroy(md->local_dir_entry_data.fname);
	de_free(c, md);
}

static i32 ucstring_lastchar(de_ucstring *s)
{
	if(!s || s->len<1) return 0;
	return s->str[s->len-1];
}

// Things to do after both the central and local headers have been read.
// E.g., extract the file.
static int do_process_member(deark *c, lctx *d, struct member_data *md)
{
	int retval = 0;

	// Set the final file size and crc fields.
	if(md->local_dir_entry_data.bit_flags & 0x0008) {
		if(d->using_scanmode) {
			de_err(c, "File is incompatible with scan mode");
			goto done;
		}

		// Indicates that certain fields are not present in the local file header,
		// and are instead in a "data descriptor" after the file data.
		// Let's hope they are also in the central file header.
		md->cmpr_size = md->central_dir_entry_data.cmpr_size;
		md->uncmpr_size = md->central_dir_entry_data.uncmpr_size;
		md->crc_reported = md->central_dir_entry_data.crc_reported;
	}
	else {
		md->cmpr_size = md->local_dir_entry_data.cmpr_size;
		md->uncmpr_size = md->local_dir_entry_data.uncmpr_size;
		md->crc_reported = md->local_dir_entry_data.crc_reported;
	}

	process_ext_attr(c, d, md);

	// In some cases, detect directories by checking whether the filename ends
	// with a slash.
	if(!md->is_dir && md->uncmpr_size==0 &&
		(d->using_scanmode || (md->ver_made_by_lo<20)))
	{
		if(ucstring_lastchar(md->local_dir_entry_data.fname) == '/') {
			de_dbg(c, "[assuming this is a subdirectory]");
			md->is_dir = 1;
		}
	}

	do_extract_file(c, d, md);
	retval = 1;

done:
	return retval;
}

// In *entry_size, returns the size of the central dir entry.
// Returns 0 if the central dir entry could not even be parsed.
static int do_member_from_central_dir_entry(deark *c, lctx *d,
	struct member_data *md, i64 central_index, i64 pos, i64 *entry_size)
{
	i64 tmp_entry_size;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	*entry_size = 0;

	if(pos >= d->central_dir_offset+d->central_dir_byte_size) {
		goto done;
	}

	de_dbg(c, "central dir entry #%d", (int)central_index);
	de_dbg_indent(c, 1);

	// Read the central dir file header
	if(!do_file_header(c, d, md, 1, pos, entry_size)) {
		goto done;
	}

	// If we were able to read the central dir file header, we might be able
	// to continue and read more files, even if the local file header fails.
	retval = 1;

	// Read the local file header
	if(!do_file_header(c, d, md, 0, md->offset_of_local_header, &tmp_entry_size)) {
		goto done;
	}

	do_process_member(c, d, md);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_central_dir_entry(deark *c, lctx *d,
	i64 central_index, i64 pos, i64 *entry_size)
{
	struct member_data *md = NULL;
	int ret;

	md = create_member_data(c, d);
	ret = do_member_from_central_dir_entry(c, d, md, central_index, pos, entry_size);
	destroy_member_data(c, md);
	return ret;
}

static int do_local_dir_only(deark *c, lctx *d, i64 pos1, i64 *pmember_size)
{
	struct member_data *md = NULL;
	i64 tmp_entry_size;
	int retval = 0;

	md = create_member_data(c, d);

	md->offset_of_local_header = pos1;

	// Read the local file header
	if(!do_file_header(c, d, md, 0, md->offset_of_local_header, &tmp_entry_size)) {
		goto done;
	}

	if(!do_process_member(c, d, md)) goto done;

	*pmember_size = md->file_data_pos + md->cmpr_size - pos1;
	retval = 1;

done:
	destroy_member_data(c, md);
	return retval;
}

static void de_run_zip_scanmode(deark *c, lctx *d)
{
	i64 pos = 0;

	d->using_scanmode = 1;

	while(1) {
		int ret;
		i64 foundpos = 0;
		i64 member_size = 0;

		if(pos > c->infile->len-4) break;
		ret = dbuf_search(c->infile, g_zipsig34, 4, pos, c->infile->len-pos, &foundpos);
		if(!ret) break;
		pos = foundpos;
		de_dbg(c, "zip member at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = do_local_dir_only(c, d, pos, &member_size);
		de_dbg_indent(c, -1);
		if(!ret) break;
		if(member_size<1) break;
		pos += member_size;
	}
}

static int do_central_dir(deark *c, lctx *d)
{
	i64 i;
	i64 pos;
	i64 entry_size;
	int retval = 0;

	pos = d->central_dir_offset;
	de_dbg(c, "central dir at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	for(i=0; i<d->central_dir_num_entries; i++) {
		if(!do_central_dir_entry(c, d, i, pos, &entry_size)) {
			// TODO: Decide exactly what to do if something fails.
			goto done;
		}
		pos += entry_size;
	}
	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_zip64_eocd(deark *c, lctx *d)
{
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->zip64_eocd_disknum!=0) goto done;

	pos = d->zip64_eocd_pos;
	if(dbuf_memcmp(c->infile, pos, g_zipsig66, 4)) {
		de_err(c, "Zip64 end-of-central-directory record not found at %"I64_FMT, pos);
		goto done;
	}

	de_dbg(c, "zip64 end-of-central-dir record at %"I64_FMT, pos);
	pos += 4;
	de_dbg_indent(c, 1);

	pos += 8; // size of zip64 eocd record
	pos += 2; // version made by
	pos += 2; // version needed
	pos += 4; // number of this disk
	d->zip64_cd_disknum = (unsigned int)de_getu32le_p(&pos);
	pos += 8; // # of entries in cd, this disk
	pos += 8; // # of entries in cd, total
	pos += 8; // size of cd
	d->zip64_cd_pos = de_geti64le(pos); pos += 8;
	de_dbg(c, "central dir offset: %"I64_FMT", disk: %u",
		d->zip64_cd_pos, d->zip64_cd_disknum);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_zip64_eocd_locator(deark *c, lctx *d)
{
	i64 n;
	i64 pos = d->end_of_central_dir_pos - 20;

	if(dbuf_memcmp(c->infile, pos, g_zipsig67, 4)) {
		return;
	}
	de_dbg(c, "zip64 eocd locator at %"I64_FMT, pos);
	pos += 4;
	d->is_zip64 = 1;
	de_dbg_indent(c, 1);
	d->zip64_eocd_disknum = (unsigned int)de_getu32le_p(&pos);
	d->zip64_eocd_pos = de_geti64le(pos); pos += 8;
	de_dbg(c, "offset of zip64 eocd: %"I64_FMT", disk: %u",
		d->zip64_eocd_pos, d->zip64_eocd_disknum);
	n = de_getu32le_p(&pos);
	de_dbg(c, "total number of disks: %u", (unsigned int)n);
	de_dbg_indent(c, -1);
}

static int do_end_of_central_dir(deark *c, lctx *d)
{
	i64 pos;
	i64 num_entries_this_disk;
	i64 disk_num_with_central_dir_start;
	i64 comment_length;
	i64 alt_central_dir_offset;
	int retval = 0;

	pos = d->end_of_central_dir_pos;
	de_dbg(c, "end-of-central-dir record at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->this_disk_num = de_getu16le(pos+4);
	de_dbg(c, "this disk num: %d", (int)d->this_disk_num);
	disk_num_with_central_dir_start = de_getu16le(pos+6);

	num_entries_this_disk = de_getu16le(pos+8);
	de_dbg(c, "num entries on this disk: %d", (int)num_entries_this_disk);

	d->central_dir_num_entries = de_getu16le(pos+10);
	d->central_dir_byte_size  = de_getu32le(pos+12);
	d->central_dir_offset = de_getu32le(pos+16);
	de_dbg(c, "central dir num entries: %d", (int)d->central_dir_num_entries);
	de_dbg(c, "central dir offset: %"I64_FMT", disk: %d", d->central_dir_offset,
		(int)disk_num_with_central_dir_start);
	if(d->is_zip64 && (d->central_dir_offset==0xffffffffLL)) {
		d->central_dir_offset = d->zip64_cd_pos;
	}
	de_dbg(c, "central dir size: %d", (int)d->central_dir_byte_size);

	comment_length = de_getu16le(pos+20);
	de_dbg(c, "comment length: %d", (int)comment_length);
	if(comment_length>0) {
		// The comment for the whole .ZIP file presumably has to use
		// cp437 encoding. There's no flag that could indicate otherwise.
		do_comment(c, d, pos+22, comment_length, 0,
			"ZIP file comment", "comment.txt");
	}

	// TODO: Figure out exactly how to detect disk spanning.
	if(disk_num_with_central_dir_start!=d->this_disk_num ||
		(d->is_zip64 && d->zip64_eocd_disknum!=d->this_disk_num))
	{
		de_err(c, "Disk spanning not supported");
		goto done;
	}

	if(d->this_disk_num!=0) {
		de_warn(c, "This ZIP file might be part of a multi-part archive, and "
			"might not be supported correctly");
	}

	if(num_entries_this_disk!=d->central_dir_num_entries) {
		de_warn(c, "This ZIP file might not be supported correctly "
			"(number-of-entries-this-disk=%d, number-of-entries-total=%d)",
			(int)num_entries_this_disk, (int)d->central_dir_num_entries);
	}

	alt_central_dir_offset =
		(d->is_zip64 ? d->zip64_eocd_pos : d->end_of_central_dir_pos) -
		d->central_dir_byte_size;

	if(alt_central_dir_offset != d->central_dir_offset) {
		u32 sig;

		de_warn(c, "Inconsistent central directory offset. Reported to be %"I64_FMT", "
			"but based on its reported size, it should be %"I64_FMT".",
			d->central_dir_offset, alt_central_dir_offset);

		sig = (u32)de_getu32le(alt_central_dir_offset);
		if(sig==CODE_PK12) {
			d->offset_discrepancy = alt_central_dir_offset - d->central_dir_offset;
			de_dbg(c, "likely central dir found at %"I64_FMT, alt_central_dir_offset);
			d->central_dir_offset = alt_central_dir_offset;
		}
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_zip_normally(deark *c, lctx *d)
{
	int eocd_found;

	if(c->detection_data && c->detection_data->zip_eocd_looked_for) {
		eocd_found = (int)c->detection_data->zip_eocd_found;
		d->end_of_central_dir_pos = c->detection_data->zip_eocd_pos;
	}
	else {
		eocd_found = de_fmtutil_find_zip_eocd(c, c->infile, &d->end_of_central_dir_pos);
	}
	if(!eocd_found) {
		de_err(c, "Not a ZIP file");
		goto done;
	}

	de_dbg(c, "end-of-central-dir record signature found at %"I64_FMT,
		d->end_of_central_dir_pos);

	do_zip64_eocd_locator(c, d);

	if(d->is_zip64)
		de_declare_fmt(c, "ZIP-Zip64");
	else
		de_declare_fmt(c, "ZIP");

	if(d->is_zip64) {
		do_zip64_eocd(c, d);
	}

	if(!do_end_of_central_dir(c, d)) {
		goto done;
	}

	if(!do_central_dir(c, d)) {
		goto done;
	}

done:
	;
}

static void de_run_zip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	if(de_get_ext_option(c, "zip:scanmode")) {
		de_run_zip_scanmode(c, d);
	}
	else {
		de_run_zip_normally(c, d);
	}

	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_zip(deark *c)
{
	u8 b[4];
	int has_zip_ext;
	int has_mz_sig = 0;

	has_zip_ext = de_input_file_has_ext(c, "zip");

	// Fast tests:

	de_read(b, 0, 4);
	if(!de_memcmp(b, g_zipsig34, 4)) {
		return has_zip_ext ? 100 : 90;
	}
	if(b[0]=='M' && b[1]=='Z') has_mz_sig = 1;

	if(c->infile->len >= 22) {
		de_read(b, c->infile->len - 22, 4);
		if(!de_memcmp(b, g_zipsig56, 4)) {
			return has_zip_ext ? 100 : 19;
		}
	}

	// Things to consider:
	// * We want de_fmtutil_find_zip_eocd() to be called no more than once, and
	// only on files that for some reason we suspect could be ZIP files.
	// * If the user disables exe format detection (e.g. with "-onlydetect zip"),
	// we want self-extracting-ZIP .exe files to be detected as ZIP instead.
	// * And we want the above to work even if the file has a ZIP file comment,
	// making it expensive to detect as ZIP.

	// Tests below can't return a confidence higher than this.
	if(c->detection_data->best_confidence_so_far >= 19) return 0;

	// Slow tests:

	if(has_mz_sig || has_zip_ext) {
		i64 eocd_pos = 0;

		c->detection_data->zip_eocd_looked_for = 1;
		if(de_fmtutil_find_zip_eocd(c, c->infile, &eocd_pos)) {
			c->detection_data->zip_eocd_found = 1;
			c->detection_data->zip_eocd_pos = eocd_pos;
			return 19;
		}
	}

	return 0;
}

static void de_help_zip(deark *c)
{
	de_msg(c, "-opt zip:scanmode : Do not use the \"central directory\"");
	de_msg(c, "-opt zip:implodebug : Behave like PKZIP 1.01/1.02");
}

void de_module_zip(deark *c, struct deark_module_info *mi)
{
	mi->id = "zip";
	mi->desc = "ZIP archive";
	mi->run_fn = de_run_zip;
	mi->identify_fn = de_identify_zip;
	mi->help_fn = de_help_zip;
}
