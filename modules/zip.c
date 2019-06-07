// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ZIP format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

#include "../foreign/explode.h"

DE_DECLARE_MODULE(de_module_zip);

struct dir_entry_data {
	unsigned int ver_needed;
	unsigned int ver_needed_hi, ver_needed_lo;
	i64 cmpr_size, uncmpr_size;
	int cmpr_method;
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

typedef struct localctx_struct {
	u8 support_implode;
	i64 end_of_central_dir_pos;
	i64 central_dir_num_entries;
	i64 central_dir_byte_size;
	i64 central_dir_offset;
	i64 zip64_eocd_pos;
	i64 zip64_cd_pos;
	unsigned int zip64_eocd_disknum;
	unsigned int zip64_cd_disknum;
	i64 offset_discrepancy;
	int used_offset_discrepancy;
	int is_zip64;
	struct de_crcobj *crco;
} lctx;

typedef void (*extrafield_decoder_fn)(deark *c, lctx *d,
	struct extra_item_info_struct *eii);

static int is_compression_method_supported(lctx *d, int cmpr_method)
{
	if(cmpr_method==0 || cmpr_method==8) return 1;
	if(cmpr_method==6 && d->support_implode) return 1;
	return 0;
}

static int do_decompress_implode(deark *c, lctx *d, struct member_data *md,
	dbuf *inf, i64 inf_pos, i64 inf_size, dbuf *outf)
{
	Uz_Globs *pG = NULL;

	if(!md) return 0;
	pG = globalsCtor(c);

	pG->c = c;
	pG->ucsize = md->uncmpr_size;
	pG->csize = inf_size;
	pG->lrec_general_purpose_bit_flag = md->local_dir_entry_data.bit_flags;

	pG->inf = inf;
	pG->inf_curpos = inf_pos;
	pG->inf_endpos = inf_pos + inf_size;
	pG->outf = outf;
	pG->dumptrees = de_get_ext_option_bool(c, "zip:dumptrees", 0);

	explode(pG);
	// TODO: How is failure reported?

	globalsDtor(pG);
	return 1;
}

static int do_decompress_deflate(deark *c, lctx *d,
	dbuf *inf, i64 inf_pos, i64 inf_size,
	dbuf *outf, i64 maxuncmprsize)
{
	int ret;
	i64 bytes_consumed = 0;

	ret = de_decompress_deflate(inf, inf_pos, inf_size, outf, maxuncmprsize,
		&bytes_consumed, DE_DEFLATEFLAG_USEMAXUNCMPRSIZE);
	return ret;
}

// Decompress some data from inf, using the given ZIP compression method,
// and append it to outf.
// 'md' is allowed to be NULL in some cases.
static int do_decompress_data(deark *c, lctx *d, struct member_data *md,
	dbuf *inf, i64 inf_pos, i64 inf_size,
	dbuf *outf, i64 maxuncmprsize, int cmpr_method)
{
	int retval = 0;
	int ret;

	switch(cmpr_method) {
	case 0: // uncompressed
		dbuf_copy(inf, inf_pos, inf_size, outf);
		retval = 1;
		break;
	case 6: // implode
		if(!md) goto done;
		ret = do_decompress_implode(c, d, md, inf, inf_pos, inf_size, outf);
		if(!ret) goto done;
		retval = 1;
		break;
	case 8: // deflate
		ret = do_decompress_deflate(c, d, inf, inf_pos, inf_size, outf, maxuncmprsize);
		if(!ret) goto done;
		retval = 1;
		break;
	}

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

	if(!dd->fname) {
		dd->fname = ucstring_create(c);
	}
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
		if(!eii->dd->fname) {
			eii->dd->fname = ucstring_create(c);
		}
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
	unsigned int cmprtype;
	unsigned int crc_reported;
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
		cmprtype = 0;
		crc_reported = 0;
	}
	else {
		cmprtype = (unsigned int)de_getu16le_p(&pos);
		de_dbg(c, "finder attr. cmpr. method: %d", (int)cmprtype);

		crc_reported = (unsigned int)de_getu32le_p(&pos);
		de_dbg(c, "finder attr. data crc (reported): 0x%08x", crc_reported);
	}

	// The rest of the data is Finder attribute data
	cmpr_attr_size = eii->dpos+eii->dlen - pos;
	de_dbg(c, "cmpr. finder attr. size: %d", (int)cmpr_attr_size);
	if(ulen<1 || ulen>1000000) goto done;

	if(!is_compression_method_supported(d, cmprtype)) {
		de_warn(c, "Finder attribute data: Unsupported compression method: %d", (int)cmprtype);
	}

	// Decompress and decode the Finder attribute data
	attr_data = dbuf_create_membuf(c, ulen, 0x1);
	ret = do_decompress_data(c, d, NULL, c->infile, pos, cmpr_attr_size,
		attr_data, 65536, cmprtype);
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
	u32 ld, ex;
	u32 attribs;

	if(eii->dlen<16) return;
	if(dbuf_memcmp(c->infile, eii->dpos, "ARC0", 4)) {
		de_dbg(c, "[unsupported Acorn extra-field type]");
		return;
	}
	pos += 4;
	ld = (u32)de_getu32le_p(&pos);
	ex = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)ld,
		(unsigned int)ex);

	de_dbg_indent(c, 1);
	if((ld&0xfff00000U)==0xfff00000U) {
		struct de_timestamp mod_time;
		unsigned int file_type;
		char timestamp_buf[64];

		file_type = (unsigned int)((ld&0xfff00)>>8);
		de_dbg(c, "file type: %03X", file_type);

		de_riscos_loadexec_to_timestamp(ld, ex, &mod_time);
		de_dbg_timestamp_to_string(c, &mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "timestamp: %s", timestamp_buf);
		apply_mod_time(c, d, eii->md, &mod_time, 70);
	}
	de_dbg_indent(c, -1);

	attribs = (u32)de_getu32le_p(&pos);
	de_dbg(c, "file perms: 0x%08x", (unsigned int)attribs);
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

	for(i=0; i<DE_ITEMS_IN_ARRAY(extra_item_type_info_arr); i++) {
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

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct member_data *md = (struct member_data *)f->userdata;
	de_crcobj_addbuf(md->crco, buf, buf_len);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct dir_entry_data *ldd = &md->local_dir_entry_data;
	u32 crc_calculated;

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, md->file_data_pos,
		md->cmpr_size);

	if(ldd->bit_flags & 0x1) {
		de_err(c, "Encryption is not supported");
		goto done;
	}

	if(!is_compression_method_supported(d, ldd->cmpr_method)) {
		de_err(c, "Unsupported compression method: %d",
			(int)ldd->cmpr_method);
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

	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)md;

	md->crco = d->crco;
	de_crcobj_reset(md->crco);

	do_decompress_data(c, d, md, c->infile, md->file_data_pos, md->cmpr_size,
		outf, md->uncmpr_size, ldd->cmpr_method);

	crc_calculated = de_crcobj_getval(md->crco);
	de_dbg(c, "crc (calculated): 0x%08x", (unsigned int)crc_calculated);

	if(crc_calculated != md->crc_reported) {
		de_warn(c, "CRC check failed for %s: Expected 0x%08x, got 0x%08x",
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

static const char *get_cmpr_meth_name(int n)
{
	const char *s = "?";
	switch(n) {
	case 0: s="uncompressed"; break;
	case 1: s="shrink"; break;
	case 2: case 3: case 4: case 5: s="reduce"; break;
	case 6: s="implode"; break;
	case 8: s="deflate"; break;
	case 9: s="deflate64"; break;
	case 10: s="PKWARE DCL implode"; break;
	case 12: s="bzip2"; break;
	case 14: s="LZMA"; break;
	case 16: s="IBM z/OS CMPSC "; break;
	case 18: s="IBM TERSE (new)"; break;
	case 19: s="IBM LZ77 z Architecture"; break;
	case 94: s="MP3"; break;
	case 95: s="XZ"; break;
	case 96: s="JPEG"; break;
	case 97: s="WavPack"; break;
	case 98: s="PPMd"; break;
	case 99: s="AES"; break;
	}
	return s;
}

// Look at the attributes, and set some other fields based on them.
static void process_ext_attr(deark *c, lctx *d, struct member_data *md)
{
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

	if(dd->cmpr_method==6) { // implode
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

	if(dd->cmpr_method==8 || dd->cmpr_method==9) { // deflate flags
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
		if(md->disk_number_start!=0) return 0;
		de_dbg(c, "local file header at %"I64_FMT, pos);
	}
	de_dbg_indent(c, 1);

	sig = (u32)de_getu32le_p(&pos);
	if(is_central && sig!=0x02014b50U) {
		de_err(c, "Central dir file header not found at %"I64_FMT, pos1);
		goto done;
	}
	else if(!is_central && sig!=0x04034b50U) {
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
	dd->cmpr_method = (int)de_getu16le_p(&pos);

	utf8_flag = (dd->bit_flags & 0x800)?1:0;
	ucstring_empty(descr);
	describe_general_purpose_bit_flags(c, dd, descr);
	de_dbg(c, "flags: 0x%04x (%s)", dd->bit_flags, ucstring_getpsz(descr));

	de_dbg(c, "cmpr method: %d (%s)", dd->cmpr_method,
		get_cmpr_meth_name(dd->cmpr_method));

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
			if(sig1!=0x04034b50U) {
				alt_pos = md->offset_of_local_header + d->offset_discrepancy;
				sig2 = (u32)de_getu32le(alt_pos);
				if(sig2==0x04034b50U) {
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

static int do_central_dir_entry(deark *c, lctx *d,
	i64 central_index, i64 pos, i64 *entry_size)
{
	struct member_data *md = NULL;
	i64 tmp_entry_size;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));
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

	// Set the final file size and crc fields.
	if(md->local_dir_entry_data.bit_flags & 0x0008) {
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

	do_extract_file(c, d, md);

done:
	if(md) {
		if(md->central_dir_entry_data.fname)
			ucstring_destroy(md->central_dir_entry_data.fname);
		if(md->local_dir_entry_data.fname)
			ucstring_destroy(md->local_dir_entry_data.fname);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
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

	if(!d->crco) {
		d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	}

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
	if(dbuf_memcmp(c->infile, pos, "PK\x06\x06", 4)) {
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

	if(dbuf_memcmp(c->infile, pos, "PK\x06\x07", 4)) {
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
	i64 this_disk_num;
	i64 num_entries_this_disk;
	i64 disk_num_with_central_dir_start;
	i64 comment_length;
	i64 alt_central_dir_offset;
	int retval = 0;

	pos = d->end_of_central_dir_pos;
	de_dbg(c, "end-of-central-dir record at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	this_disk_num = de_getu16le(pos+4);
	de_dbg(c, "this disk num: %d", (int)this_disk_num);
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
	if(this_disk_num!=0 || disk_num_with_central_dir_start!=0 ||
		(d->is_zip64 && d->zip64_eocd_disknum!=0))
	{
		de_err(c, "Disk spanning not supported");
		goto done;
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
		if(sig==0x02014b50U) {
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

static void de_run_zip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->support_implode = 1;

	if(!de_fmtutil_find_zip_eocd(c, c->infile, &d->end_of_central_dir_pos)) {
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
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_zip(deark *c)
{
	u8 b[4];
	int has_zip_ext;

	has_zip_ext = de_input_file_has_ext(c, "zip");

	// This will not detect every ZIP file, but there is no cheap way to do that.

	de_read(b, 0, 4);
	if(!de_memcmp(b, "PK\x03\x04", 4)) {
		return has_zip_ext ? 100 : 90;
	}

	if(c->infile->len >= 22) {
		de_read(b, c->infile->len - 22, 4);
		if(!de_memcmp(b, "PK\x05\x06", 4)) {
			return has_zip_ext ? 100 : 19;
		}
	}

	return 0;
}

void de_module_zip(deark *c, struct deark_module_info *mi)
{
	mi->id = "zip";
	mi->desc = "ZIP archive";
	mi->run_fn = de_run_zip;
	mi->identify_fn = de_identify_zip;
}
