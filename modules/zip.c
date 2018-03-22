// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ZIP format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_zip);

struct dir_entry_data {
	unsigned int ver_needed;
	de_int64 cmpr_size, uncmpr_size;
	int cmpr_method;
	unsigned int bit_flags;
	de_uint32 crc_reported;
	struct de_timestamp mod_time;
	de_ucstring *fname;
};

struct member_data {
	de_int64 ver_made_by;
	unsigned int ver_made_by_hi, ver_made_by_lo;
	unsigned int attr_i, attr_e;
	de_int64 offset_of_local_header;
	de_int64 disk_number_start;
	de_int64 file_data_pos;
	int is_nonexecutable;
	int is_executable;
	int is_dir;
	int is_symlink;
	de_uint32 crc_calculated;

	struct dir_entry_data central_dir_entry_data;
	struct dir_entry_data local_dir_entry_data;
};

typedef struct localctx_struct {
	de_int64 end_of_central_dir_pos;
	de_int64 central_dir_num_entries;
	de_int64 central_dir_byte_size;
	de_int64 central_dir_offset;
} lctx;

typedef void (*extrafield_decoder_fn)(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd, de_int64 fieldtype,
	de_int64 pos, de_int64 len, int is_central);

static int is_compression_method_supported(int cmpr_method)
{
	if(cmpr_method==0 || cmpr_method==8) return 1;
	return 0;
}

// Decompress some data from inf, using the given ZIP compression method,
// and append it to outf.
static int do_decompress_data(deark *c, lctx *d,
	dbuf *inf, de_int64 inf_pos, de_int64 inf_size,
	dbuf *outf, int cmpr_method)
{
	int retval = 0;
	int ret;
	de_int64 bytes_consumed = 0;

	switch(cmpr_method) {
	case 0: // uncompressed
		dbuf_copy(inf, inf_pos, inf_size, outf);
		retval = 1;
		break;
	case 8: // deflate
		ret = de_uncompress_deflate(inf, inf_pos, inf_size, outf, &bytes_consumed);
		if(!ret) goto done;
		retval = 1;
		break;
	}

done:
	return retval;
}

static void do_read_filename(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 pos, de_int64 len, int utf8_flag)
{
	int from_encoding;

	if(dd->fname)
		ucstring_destroy(dd->fname);
	dd->fname = ucstring_create(c);
	from_encoding = utf8_flag ? DE_ENCODING_UTF8 : DE_ENCODING_CP437_G;
	dbuf_read_to_ucstring(c->infile, pos, len, dd->fname, 0, from_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(dd->fname));
}


static void do_comment_display(deark *c, lctx *d, de_int64 pos, de_int64 len, int encoding,
	const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment_extract(deark *c, lctx *d, de_int64 pos, de_int64 len, int encoding,
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

static void do_comment(deark *c, lctx *d, de_int64 pos, de_int64 len, int utf8_flag,
	const char *name, const char *ext)
{
	int encoding;

	if(len<1) return;
	encoding = utf8_flag ? DE_ENCODING_UTF8 : DE_ENCODING_CP437_C;
	if(c->extract_level>=2) {
		do_comment_extract(c, d, pos, len, encoding, ext);
	}
	else {
		do_comment_display(c, d, pos, len, encoding, name);
	}
}

static void read_unix_timestamp(deark *c, lctx *d, de_int64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	de_int64 t;
	char timestamp_buf[64];

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, timestamp);
	de_timestamp_to_string(timestamp, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "%s: %d (%s)", name, (int)t, timestamp_buf);
}

static void read_FILETIME(deark *c, lctx *d, de_int64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	de_int64 t_FILETIME;
	char timestamp_buf[64];

	t_FILETIME = de_geti64le(pos);
	de_FILETIME_to_timestamp(t_FILETIME, timestamp);
	de_timestamp_to_string(timestamp, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

// Extra field 0x5455
static void ef_extended_timestamp(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd, de_int64 fieldtype,
	de_int64 pos, de_int64 len, int is_central)
{
	de_byte flags;
	de_int64 endpos;
	int has_mtime, has_atime, has_ctime;
	struct de_timestamp timestamp_tmp;

	endpos = pos+len;
	if(pos+1>endpos) return;
	flags = de_getbyte(pos);
	pos++;
	if(is_central) {
		has_mtime = (len>=5);
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
		read_unix_timestamp(c, d, pos, &dd->mod_time, "mtime");
		pos+=4;
	}
	if(has_atime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "atime");
		pos+=4;
	}
	if(has_ctime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "ctime");
		pos+=4;
	}
}

// Extra field 0x5855
static void ef_infozip1(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd, de_int64 fieldtype,
	de_int64 pos, de_int64 len, int is_central)
{
	de_int64 uidnum, gidnum;
	struct de_timestamp timestamp_tmp;

	if(is_central && len<8) return;
	if(!is_central && len<12) return;
	read_unix_timestamp(c, d, pos, &timestamp_tmp, "atime");
	read_unix_timestamp(c, d, pos+4, &dd->mod_time, "mtime");
	if(!is_central) {
		uidnum = de_getui16le(pos+8);
		gidnum = de_getui16le(pos+10);
		de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
	}
}

// Extra field 0x7855
static void ef_infozip2(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd, de_int64 fieldtype,
	de_int64 pos, de_int64 len, int is_central)
{
	de_int64 uidnum, gidnum;

	if(is_central) return;
	if(len<4) return;
	uidnum = de_getui16le(pos);
	gidnum = de_getui16le(pos+2);
	de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
}

static de_int64 get_variable_length_uint_le(dbuf *f, de_int64 pos, de_int64 len)
{
	de_int64 val = 0;
	de_int64 i;

	for(i=0; i<len && i<8; i++) {
		val |= ((de_int64)dbuf_getbyte(f, pos+i))<<(i*8);
	}
	return val;
}

// Extra field 0x7875
static void ef_infozip3(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd, de_int64 fieldtype,
	de_int64 pos, de_int64 len, int is_central)
{
	de_int64 uidnum, gidnum;
	de_byte ver;
	de_int64 endpos;
	de_int64 sz;

	endpos = pos+len;

	if(pos+1>endpos) return;
	ver = de_getbyte(pos);
	pos++;
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=1) return;

	if(pos+1>endpos) return;
	sz = (de_int64)de_getbyte(pos);
	pos++;
	if(pos+sz>endpos) return;
	uidnum = get_variable_length_uint_le(c->infile, pos, sz);
	pos += sz;

	if(pos+1>endpos) return;
	sz = (de_int64)de_getbyte(pos);
	pos++;
	if(pos+sz>endpos) return;
	gidnum = get_variable_length_uint_le(c->infile, pos, sz);
	pos += sz;

	de_dbg(c, "uid: %d, gid: %d", (int)uidnum, (int)gidnum);
}

// Extra field 0x000a
static void ef_ntfs(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 fieldtype, de_int64 pos, de_int64 len, int is_central)
{
	de_int64 endpos;
	de_int64 attr_tag;
	de_int64 attr_size;
	const char *name;
	struct de_timestamp timestamp_tmp;

	endpos = pos+len;
	pos += 4; // skip reserved field

	while(1) {
		if(pos+4>endpos) break;
		attr_tag = de_getui16le(pos);
		attr_size = de_getui16le(pos+2);
		pos += 4;
		if(attr_tag==0x0001) name="NTFS filetimes";
		else name="?";
		de_dbg(c, "tag: 0x%04x (%s), dlen: %d", (unsigned int)attr_tag, name,
			(int)attr_size);
		if(pos+attr_size>endpos) break;

		de_dbg_indent(c, 1);
		if(attr_tag==0x0001 && attr_size>=24) {
			read_FILETIME(c, d, pos, &dd->mod_time, "mtime");
			read_FILETIME(c, d, pos+8, &timestamp_tmp, "atime");
			read_FILETIME(c, d, pos+16, &timestamp_tmp, "ctime");
		}
		de_dbg_indent(c, -1);

		pos += attr_size;
	}
}

// Extra field 0x0009
static void ef_os2(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 fieldtype, de_int64 pos, de_int64 len, int is_central)
{
	de_int64 endpos;
	de_int64 unc_size;
	de_int64 cmpr_type;
	de_int64 crc;

	endpos = pos+len;
	if(pos+4>endpos) return;
	unc_size = de_getui32le(pos);
	pos += 4;
	de_dbg(c, "uncmpr ext attr data size: %d", (int)unc_size);
	if(is_central) return;

	if(pos+2>endpos) return;
	cmpr_type = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "ext attr cmpr method: %d", (int)cmpr_type);

	if(pos+4>endpos) return;
	crc = de_getui32le(pos);
	pos += 4;
	de_dbg(c, "ext attr crc: 0x%08x", (unsigned int)crc);

	de_dbg(c, "cmpr ext attr data at %d, len=%d", (int)pos, (int)(endpos-pos));
	// TODO: Uncompress and decode OS/2 extended attribute structure (FEA2LIST)
}

// Extra field 0x2705 (ZipIt Macintosh 1.3.5+)
static void ef_zipitmac_2705(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 fieldtype, de_int64 pos, de_int64 len, int is_central)
{
	struct de_fourcc sig;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	if(len<4) goto done;
	dbuf_read_fourcc(c->infile, pos, &sig, 0);
	de_dbg(c, "signature: '%s'", sig.id_printable);
	if(sig.id!=0x5a504954U) goto done; // expecting 'ZPIT'
	if(len<12) goto done;
	dbuf_read_fourcc(c->infile, pos+4, &filetype, 0);
	de_dbg(c, "filetype: '%s'", filetype.id_printable);
	dbuf_read_fourcc(c->infile, pos+8, &creator, 0);
	de_dbg(c, "creator: '%s'", creator.id_printable);

done:
	;
}

// The time will be returned in the caller-supplied 'ts'
static void handle_mac_time(deark *c, lctx *d,
	de_int64 mt_raw, de_int64 mt_offset,
	struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];
	de_mac_time_to_timestamp(mt_raw - mt_offset, ts);
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "%s: %"INT64_FMT" %+"INT64_FMT" (%s)", name,
		mt_raw, -mt_offset, timestamp_buf);
}

// Extra field 0x334d (Info-ZIP Macintosh)
static void ef_infozipmac(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 fieldtype, de_int64 pos1, de_int64 len, int is_central)
{
	de_int64 pos = pos1;
	de_int64 dpos;
	de_int64 ulen;
	de_int64 cmpr_attr_size;
	unsigned int flags;
	unsigned int cmprtype;
	unsigned int crc_reported;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	de_ucstring *flags_str = NULL;
	dbuf *attr_data = NULL;
	int ret;
	de_int64 create_time_raw;
	de_int64 create_time_offset;
	de_int64 mod_time_raw;
	de_int64 mod_time_offset;
	de_int64 backup_time_raw;
	de_int64 backup_time_offset;
	struct de_timestamp tmp_timestamp;
	int charset;
	struct de_stringreaderdata *srd;

	if(len<14) goto done;

	ulen = de_getui32le(pos);
	de_dbg(c, "uncmpr. finder attr. size: %d", (int)ulen);
	pos += 4;

	flags = (unsigned int)de_getui16le(pos);
	flags_str = ucstring_create(c);
	if(flags&0x0001) ucstring_append_flags_item(flags_str, "data_fork");
	if(flags&0x0002) ucstring_append_flags_item(flags_str, "0x0002"); // something about the filename
	ucstring_append_flags_item(flags_str,
		(flags&0x0004)?"uncmpressed_attribute_data":"compressed_attribute_data");
	if(flags&0x0008) ucstring_append_flags_item(flags_str, "64-bit_times");
	if(flags&0x0010) ucstring_append_flags_item(flags_str, "no_timezone_offsets");
	de_dbg(c, "flags: 0x%04x (%s)", flags, ucstring_getpsz(flags_str));
	pos += 2;

	dbuf_read_fourcc(c->infile, pos, &filetype, 0);
	de_dbg(c, "filetype: '%s'", filetype.id_printable);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator, 0);
	de_dbg(c, "creator: '%s'", creator.id_printable);
	pos += 4;

	if(is_central) goto done;

	if(flags&0x0004) { // Uncompressed attribute data
		cmprtype = 0;
		crc_reported = 0;
	}
	else {
		cmprtype = (unsigned int)de_getui16le(pos);
		de_dbg(c, "finder attr. cmpr. method: %d", (int)cmprtype);
		pos += 2;

		crc_reported = (unsigned int)de_getui32le(pos);
		de_dbg(c, "finder attr. data crc (reported): 0x%08x", crc_reported);
		pos += 4;
	}

	// The rest of the data is Finder attribute data
	cmpr_attr_size = pos1+len - pos;
	de_dbg(c, "cmpr. finder attr. size: %d", (int)cmpr_attr_size);
	if(ulen<1 || ulen>1000000) goto done;

	if(!is_compression_method_supported(cmprtype)) {
		de_warn(c, "Finder attribute data: Unsupported compression method: %d", (int)cmprtype);
	}

	// Decompress and decode the Finder attribute data
	attr_data = dbuf_create_membuf(c, ulen, 0x1);
	ret = do_decompress_data(c, d, c->infile, pos, cmpr_attr_size, attr_data, cmprtype);
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

	create_time_raw = dbuf_getui32le(attr_data, dpos); dpos += 4;
	mod_time_raw    = dbuf_getui32le(attr_data, dpos); dpos += 4;
	backup_time_raw = dbuf_getui32le(attr_data, dpos); dpos += 4;
	create_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;
	mod_time_offset    = dbuf_geti32le(attr_data, dpos); dpos += 4;
	backup_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;

	handle_mac_time(c, d, create_time_raw, create_time_offset, &tmp_timestamp, "create time");
	// TODO: Remember the mod_time? Need to decide what mod_time field takes precedence.
	handle_mac_time(c, d, mod_time_raw,    mod_time_offset,    &tmp_timestamp, "mod time   ");
	handle_mac_time(c, d, backup_time_raw, backup_time_offset, &tmp_timestamp, "backup time");

	// Expecting 2 bytes for charset, and at least 2 more for the 2 NUL-terminated
	// strings that follow.
	if(attr_data->len - dpos < 4) goto done;

	charset = (int)dbuf_getui16le(attr_data, dpos);
	dpos += 2;
	de_dbg(c, "charset for fullpath/comment: %d", (int)charset);

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

struct extra_item_type_info_struct {
	de_uint16 id;
	const char *name;
	extrafield_decoder_fn fn;
};
static const struct extra_item_type_info_struct extra_item_type_info_arr[] = {
	{ 0x0001 /*    */, "Zip64 extended information", NULL },
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
	{ 0x0065 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes", NULL },
	{ 0x0066 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes - compressed", NULL },
	{ 0x07c8 /*    */, "Macintosh", NULL },
	{ 0x2605 /*    */, "ZipIt Macintosh", NULL },
	{ 0x2705 /*    */, "ZipIt Macintosh 1.3.5+", ef_zipitmac_2705 },
	{ 0x2805 /*    */, "ZipIt Macintosh 1.3.5+", NULL },
	{ 0x334d /* M3 */, "Info-ZIP Macintosh", ef_infozipmac },
	{ 0x4154 /* TA */, "Tandem NSK", NULL },
	{ 0x4341 /* AC */, "Acorn/SparkFS", NULL },
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
	{ 0x7075 /* up */, "Info-ZIP Unicode Path", NULL },
	{ 0x7441 /* At */, "AtheOS", NULL },
	{ 0x756e /* nu */, "ASi Unix", NULL },
	{ 0x7855 /* Ux */, "Info-ZIP Unix, second version", ef_infozip2 },
	{ 0x7875 /* ux */, "Info-ZIP Unix, third version", ef_infozip3 },
	{ 0xa220 /*    */, "Microsoft Open Packaging Growth Hint", NULL },
	{ 0xfb4a /*    */, "SMS/QDOS", NULL }, // according to Info-ZIP zip 3.0
	{ 0xfd4a /*    */, "SMS/QDOS", NULL }  // according to ZIP v6.3.4 APPNOTE
};

static const struct extra_item_type_info_struct *get_extra_item_type_info(de_int64 id)
{
	static const struct extra_item_type_info_struct default_ei =
		{ 0, "?", NULL };
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(extra_item_type_info_arr); i++) {
		if(id == (de_int64)extra_item_type_info_arr[i].id) {
			return &extra_item_type_info_arr[i];
		}
	}
	return &default_ei;
}

static void do_extra_data(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	de_int64 pos1, de_int64 len, int is_central)
{
	de_int64 pos;
	de_int64 item_id;
	de_int64 item_len;
	const struct extra_item_type_info_struct *ei;

	de_dbg(c, "extra data at %d, len=%d", (int)pos1, (int)len);
	de_dbg_indent(c, 1);

	pos = pos1;
	while(1) {
		if(pos+4 >= pos1+len) break;
		item_id = de_getui16le(pos);
		item_len = de_getui16le(pos+2);

		ei = get_extra_item_type_info(item_id);

		de_dbg(c, "item id=0x%04x (%s), dlen=%d", (unsigned int)item_id, ei->name,
			(int)item_len);
		if(pos+4+item_len > pos1+len) break;

		if(ei->fn) {
			de_dbg_indent(c, 1);
			ei->fn(c, d, md, dd, item_id, pos+4, item_len, is_central);
			de_dbg_indent(c, -1);
		}

		pos += 4+item_len;
	}

	de_dbg_indent(c, -1);
}

static void our_writecallback(dbuf *f, const de_byte *buf, de_int64 buf_len)
{
	struct member_data *md = (struct member_data *)f->userdata;
	md->crc_calculated = de_crc32_continue(md->crc_calculated, buf, buf_len);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct dir_entry_data *ldd = &md->local_dir_entry_data;

	de_dbg(c, "file data at %d, len=%d", (int)md->file_data_pos,
		(int)ldd->cmpr_size);

	if(!is_compression_method_supported(ldd->cmpr_method)) {
		de_err(c, "Unsupported compression method: %d",
			(int)ldd->cmpr_method);
		goto done;
	}

	if(md->is_dir && ldd->uncmpr_size==0) {
		de_msg(c, "Note: \"%s\" is a directory. Ignoring.",
			ucstring_getpsz_d(ldd->fname));
		goto done;
	}

	if(md->is_symlink) {
		de_warn(c, "\"%s\" is a symbolic link. It will not be extracted as a link.",
			ucstring_getpsz_d(ldd->fname));
	}

	fi = de_finfo_create(c);

	if(ldd->fname) {
		de_finfo_set_name_from_ucstring(c, fi, ldd->fname);
		fi->original_filename_flag = 1;
	}

	if(ldd->mod_time.is_valid) {
		fi->mod_time = ldd->mod_time;
	}

	if(md->is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(md->is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)md;

	md->crc_calculated = de_crc32(NULL, 0);

	do_decompress_data(c, d, c->infile, md->file_data_pos, ldd->cmpr_size, outf, ldd->cmpr_method);

	de_dbg(c, "crc (calculated): 0x%08x", (unsigned int)md->crc_calculated);

	if(md->crc_calculated != ldd->crc_reported) {
		de_warn(c, "CRC check failed: Expected 0x%08x, got 0x%08x",
			(unsigned int)ldd->crc_reported, (unsigned int)md->crc_calculated);
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
	case 12: s="bzip2"; break;
	case 14: s="LZMA"; break;
	}
	return s;
}

// Look at md->attr_e, and set some other fields based on it.
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
	// TODO: Support platforms other than Unix.
}

// Read either a central directory entry (a.k.a. central directory file header),
// or a local file header.
static int do_file_header(deark *c, lctx *d, struct member_data *md,
	int is_central, de_int64 pos1, de_int64 *p_entry_size)
{
	de_int64 pos;
	de_int64 sig;
	de_int64 fn_len, extra_len, comment_len;
	int utf8_flag;
	int retval = 0;
	de_int64 fixed_header_size;
	de_int64 mod_time_raw, mod_date_raw;
	struct dir_entry_data *dd; // Points to either md->central or md->local
	char timestamp_buf[64];

	pos = pos1;
	if(is_central) {
		dd = &md->central_dir_entry_data;
		fixed_header_size = 46;
		de_dbg(c, "central dir entry at %d", (int)pos);
	}
	else {
		dd = &md->local_dir_entry_data;
		fixed_header_size = 30;
		if(md->disk_number_start!=0) return 0;
		de_dbg(c, "local file header at %d", (int)pos);
	}
	de_dbg_indent(c, 1);

	sig = de_getui32le(pos);
	pos += 4;
	if(is_central && sig!=0x02014b50) {
		de_err(c, "Invalid central file header at %d", (int)pos1);
		goto done;
	}
	else if(!is_central && sig!=0x04034b50) {
		de_err(c, "Invalid local file header at %d", (int)pos1);
		goto done;
	}

	if(is_central) {
		const char *pltf_name;
		md->ver_made_by = de_getui16le(pos);
		pos += 2;
		md->ver_made_by_hi = (unsigned int)((md->ver_made_by&0xff00)>>8);
		md->ver_made_by_lo = (unsigned int)(md->ver_made_by&0x00ff);
		pltf_name = get_platform_name(md->ver_made_by_hi);
		de_dbg(c, "version made by: platform=%u (%s), ZIP spec=%u.%u",
			md->ver_made_by_hi, pltf_name,
			(unsigned int)(md->ver_made_by_lo/10), (unsigned int)(md->ver_made_by_lo%10));
	}

	dd->ver_needed = (unsigned int)de_getui16le(pos);
	pos += 2;
	de_dbg(c, "version needed to extract: %u.%u",
		(unsigned int)(dd->ver_needed/10), (unsigned int)(dd->ver_needed%10));

	dd->bit_flags = (unsigned int)de_getui16le(pos);
	pos += 2;
	de_dbg(c, "flags: 0x%04x", dd->bit_flags);

	utf8_flag = (dd->bit_flags & 0x800)?1:0;

	dd->cmpr_method = (int)de_getui16le(pos);
	pos += 2;
	de_dbg(c, "cmpr method: %d (%s)", dd->cmpr_method,
		get_cmpr_meth_name(dd->cmpr_method));

	mod_time_raw = de_getui16le(pos);
	pos += 2;
	mod_date_raw = de_getui16le(pos);
	pos += 2;
	de_dos_datetime_to_timestamp(&dd->mod_time, mod_date_raw, mod_time_raw, 0);
	de_timestamp_to_string(&dd->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);

	dd->crc_reported = (de_uint32)de_getui32le(pos);
	pos += 4;
	de_dbg(c, "crc (reported): 0x%08x", (unsigned int)dd->crc_reported);

	dd->cmpr_size = de_getui32le(pos);
	pos += 4;
	dd->uncmpr_size = de_getui32le(pos);
	pos += 4;
	de_dbg(c, "cmpr size: %" INT64_FMT ", uncmpr size: %" INT64_FMT "", dd->cmpr_size, dd->uncmpr_size);

	fn_len = de_getui16le(pos);
	pos += 2;

	extra_len = de_getui16le(pos);
	pos += 2;

	if(is_central) {
		comment_len = de_getui16le(pos);
		pos += 2;
	}
	else {
		comment_len = 0;
	}

	if(!is_central) {
		md->file_data_pos = pos + fn_len + extra_len;
	}

	if(is_central) {
		md->disk_number_start = de_getui16le(pos);
		pos += 2;

		md->attr_i = (unsigned int)de_getui16le(pos);
		pos += 2;
		md->attr_e = (unsigned int)de_getui32le(pos);
		pos += 4;
		de_dbg(c, "file attributes: internal=0x%04x, external=0x%08x",
			md->attr_i, md->attr_e);
		process_ext_attr(c, d, md);

		md->offset_of_local_header = de_getui32le(pos);
		pos += 4;
		de_dbg(c, "offset of local header: %d, disk: %d", (int)md->offset_of_local_header,
			(int)md->disk_number_start);
	}

	if(is_central) {
		de_dbg(c, "filename_len=%d, extra_len=%d, comment_len=%d", (int)fn_len,
			(int)extra_len, (int)comment_len);
	}
	else {
		de_dbg(c, "filename_len=%d, extra_len=%d", (int)fn_len,
			(int)extra_len);
	}

	*p_entry_size = fixed_header_size + fn_len + extra_len + comment_len;

	do_read_filename(c, d, md, dd, pos1+fixed_header_size, fn_len, utf8_flag);

	if(extra_len>0) {
		do_extra_data(c, d, md, dd, pos1+fixed_header_size+fn_len, extra_len, is_central);
	}

	if(comment_len>0) {
		do_comment(c, d, pos1+fixed_header_size+fn_len+extra_len, comment_len, utf8_flag,
			"member file comment", "fcomment.txt");
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_central_dir_entry(deark *c, lctx *d,
	de_int64 central_index, de_int64 pos, de_int64 *entry_size)
{
	struct member_data *md = NULL;
	de_int64 tmp_entry_size;
	int retval = 0;

	md = de_malloc(c, sizeof(struct member_data));
	*entry_size = 0;

	if(pos >= d->central_dir_offset+d->central_dir_byte_size) {
		goto done;
	}

	de_dbg(c, "central dir entry #%d", (int)central_index);
	de_dbg_indent(c, 1);

	if(!do_file_header(c, d, md, 1, pos, entry_size)) {
		goto done;
	}
	if(!do_file_header(c, d, md, 0, md->offset_of_local_header, &tmp_entry_size)) {
		goto done;
	}
	do_extract_file(c, d, md);
	retval = 1;

done:
	de_dbg_indent(c, -1);
	if(md) {
		if(md->central_dir_entry_data.fname)
			ucstring_destroy(md->central_dir_entry_data.fname);
		if(md->local_dir_entry_data.fname)
			ucstring_destroy(md->local_dir_entry_data.fname);
		de_free(c, md);
	}
	return retval;
}

static int do_central_dir(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 pos;
	de_int64 entry_size;
	int retval = 0;

	pos = d->central_dir_offset;
	de_dbg(c, "central dir at %d", (int)pos);
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

static int do_end_of_central_dir(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 this_disk_num;
	de_int64 num_entries_this_disk;
	de_int64 disk_num_with_central_dir_start;
	de_int64 comment_length;
	int retval = 0;

	pos = d->end_of_central_dir_pos;
	de_dbg(c, "end-of-central-dir record at %d", (int)pos);
	de_dbg_indent(c, 1);

	this_disk_num = de_getui16le(pos+4);
	de_dbg(c, "this disk num: %d", (int)this_disk_num);
	disk_num_with_central_dir_start = de_getui16le(pos+6);
	de_dbg(c, "disk with central dir start: %d", (int)disk_num_with_central_dir_start);
	num_entries_this_disk = de_getui16le(pos+8);

	d->central_dir_num_entries = de_getui16le(pos+10);
	d->central_dir_byte_size  = de_getui32le(pos+12);
	d->central_dir_offset = de_getui32le(pos+16);

	de_dbg(c, "central dir: num_entries=%d, offset=%d, size=%d",
		(int)d->central_dir_num_entries,
		(int)d->central_dir_offset,
		(int)d->central_dir_byte_size);

	comment_length = de_getui16le(pos+20);
	de_dbg(c, "comment length: %d", (int)comment_length);
	if(comment_length>0) {
		// The comment for the whole .ZIP file presumably has to use
		// cp437 encoding. There's no flag that could indicate otherwise.
		do_comment(c, d, pos+22, comment_length, 0,
			"ZIP file comment", "comment.txt");
	}

	// TODO: Figure out exactly how to detect disk spanning.
	if(this_disk_num!=0 || disk_num_with_central_dir_start!=0 ||
		num_entries_this_disk!=d->central_dir_num_entries)
	{
		de_err(c, "Disk spanning not supported");
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int find_end_of_central_dir(deark *c, lctx *d)
{
	de_int64 x;
	de_byte *buf = NULL;
	int retval = 0;
	de_int64 buf_offset;
	de_int64 buf_size;
	de_int64 i;

	if(c->infile->len < 22) goto done;

	// End-of-central-dir record usually starts 22 bytes from EOF. Try that first.
	x = de_getui32le(c->infile->len - 22);
	if(x == 0x06054b50) {
		d->end_of_central_dir_pos = c->infile->len - 22;
		retval = 1;
		goto done;
	}

	// Search for the signature.
	// The end-of-central-directory record could theoretically appear anywhere
	// in the file. We'll follow Info-Zip/UnZip's lead and search the last 66000
	// bytes.
#define MAX_EOCD_SEARCH 66000
	buf_size = c->infile->len;
	if(buf_size > MAX_EOCD_SEARCH) buf_size = MAX_EOCD_SEARCH;

	buf = de_malloc(c, buf_size);
	buf_offset = c->infile->len - buf_size;
	de_read(buf, buf_offset, buf_size);

	for(i=buf_size-22; i>=0; i--) {
		if(buf[i]=='P' && buf[i+1]=='K' && buf[i+2]==5 && buf[i+3]==6) {
			d->end_of_central_dir_pos = buf_offset + i;
			retval = 1;
			goto done;
		}
	}

done:
	de_free(c, buf);
	return retval;
}

static void de_run_zip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	de_declare_fmt(c, "ZIP");

	if(!find_end_of_central_dir(c, d)) {
		de_err(c, "Not a ZIP file");
		goto done;
	}

	de_dbg(c, "end-of-central-dir record signature found at %d", (int)d->end_of_central_dir_pos);

	if(!do_end_of_central_dir(c, d)) {
		goto done;
	}

	if(!do_central_dir(c, d)) {
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_zip(deark *c)
{
	de_byte b[4];

	// This will not detect every ZIP file, but there is no cheap way to do that.

	de_read(b, 0, 4);
	if(!de_memcmp(b, "PK\x03\x04", 4)) {
		return 90;
	}

	if(c->infile->len >= 22) {
		de_read(b, c->infile->len - 22, 4);
		if(!de_memcmp(b, "PK\x05\x06", 4)) {
			return 90;
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
