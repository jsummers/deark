// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// OLE Property Sets
// Refer to the Microsoft document "[MS-OLEPS]".

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_olepropset);

// Fields related to the whole PropertySetStream
typedef struct localctx_struct {
	dbuf *f; // The full data stream
	unsigned int propset_version;
	int asciipropnames;
} lctx;

struct dictionary_entry {
	u32 prop_id;
	de_ucstring *str;
};

// Fields related to the current property set
struct propset_struct {
	i64 tbloffset;
	u32 sfmtid;
	int code_page; // value of the Code Page property
	de_encoding encoding;

	size_t num_dict_entries;
	struct dictionary_entry *dictionary;
};

struct prop_info_struct {
	u32 prop_id;
	u32 data_type;
	i64 data_offs_rel;
	i64 dpos; // = si->tbloffset+pinfo->data_offs+4

	int name_disposition; // 0=unknown, 1=standard, 2=from dictionary
	char name[80];
};

struct fmtid_info_entry {
	const u8 guid[16];
	u32 sfmtid; // short ID
	const char *name;
};

#define SFMTID_UNKNOWN             0
#define SFMTID_COMMON              1
#define SFMTID_SUMMARYINFO         10
#define SFMTID_DOCSUMMARYINFO      11
#define SFMTID_USERDEFINEDPROPS    12
#define SFMTID_IMAGECONTENTS       13
#define SFMTID_IMAGEINFO           14
#define SFMTID_GLOBALINFO          15
#define SFMTID_SRCRESDESCR         30
#define SFMTID_TRANSFORM           31
#define SFMTID_OPERATION           32
#define SFMTID_EXTENSIONLIST       33

static const struct fmtid_info_entry fmtid_info_arr[] = {
	{{0x56,0x61,0x60,0x10,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_EXTENSIONLIST, "Extension List"},
	{{0x56,0x61,0x60,0x80,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_SRCRESDESCR, "Source/Result Description"},
	{{0x56,0x61,0x64,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_IMAGECONTENTS, "ImageContents"},
	{{0x56,0x61,0x65,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_IMAGEINFO, "ImageInfo"},
	{{0x56,0x61,0x6a,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_TRANSFORM, "Transform"},
	{{0x56,0x61,0x6f,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_GLOBALINFO, "GlobalInfo"},
	{{0x56,0x61,0x6e,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, SFMTID_OPERATION, "Operation"},
	{{0xd5,0xcd,0xd5,0x02,0x2e,0x9c,0x10,0x1b,0x93,0x97,0x08,0x00,0x2b,0x2c,0xf9,0xae}, SFMTID_DOCSUMMARYINFO, "DocSummaryInformation"},
	{{0xd5,0xcd,0xd5,0x05,0x2e,0x9c,0x10,0x1b,0x93,0x97,0x08,0x00,0x2b,0x2c,0xf9,0xae}, SFMTID_USERDEFINEDPROPS, "UserDefinedProperties"},
	{{0xf2,0x9f,0x85,0xe0,0x4f,0xf9,0x10,0x68,0xab,0x91,0x08,0x00,0x2b,0x27,0xb3,0xd9}, SFMTID_SUMMARYINFO, "SummaryInformation"}
};

struct prop_info_entry {
	u32 sfmtid;
	u32 prop_id;
#define MSK1 0xffffffffU
	u32 prop_id_mask;
	u32 flags;
	const char *name;
	void *reserved;
};

static void do_prop_blob(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, const char *name,
	i64 pos1, i64 *bytes_consumed)
{
	i64 blob_data_start;
	i64 blob_data_size;
	i64 pos = pos1;
	u8 magic[8];

	blob_data_size = dbuf_getu32le_p(d->f, &pos);
	de_dbg(c, "%s data size: %"I64_FMT, name, blob_data_size);

	blob_data_start = pos;
	if(blob_data_start + blob_data_size > d->f->len) return;

	*bytes_consumed = 4 + de_pad_to_4(blob_data_size);

	if(blob_data_size>=8) {
		// Minor hack. If a blob looks like a JPEG file, extract it.
		dbuf_read(d->f, magic, blob_data_start, 8);

		if(magic[0]==0xff && magic[1]==0xd8 && magic[2]==0xff) {
			dbuf_create_file_from_slice(d->f, blob_data_start, blob_data_size,
				"oleblob.jpg", NULL, DE_CREATEFLAG_IS_AUX);
			goto done;
		}
	}

	de_dbg_hexdump(c, d->f, blob_data_start, blob_data_size, 256, NULL, 0x1);

done:
	;
}

static void do_prop_clipboard(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo,
	i64 pos1, i64 *bytes_consumed)
{
	u32 cbtype;
	i64 cbsize_reported;
	i64 cbsize_payload;
	i64 cbdatapos;
	const char *cbtype_name;

	cbsize_reported = dbuf_getu32le(d->f, pos1);
	de_dbg(c, "clipboard data size: %d", (int)cbsize_reported);

	cbtype = (u32)dbuf_getu32le(d->f, pos1+8);
	if(cbtype==0x54434950U) {
		cbtype_name="PICT";
	}
	else {
		cbtype_name = de_fmtutil_get_windows_cb_data_type_name((unsigned int)cbtype);
	}
	de_dbg(c, "clipboard data type: 0x%08x (%s)", (unsigned int)cbtype, cbtype_name);

	cbdatapos = pos1+12;
	cbsize_payload = cbsize_reported-8;
	if(cbdatapos + cbsize_payload > d->f->len) goto done;

	*bytes_consumed = de_pad_to_4(cbsize_reported);

	if(cbtype==3) { // CF_METAFILEPICT
		dbuf_create_file_from_slice(d->f, cbdatapos+8, cbsize_payload-8,
			"wmf", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(cbtype==8) { // CF_DIB
		de_run_module_by_id_on_slice2(c, "dib", "X", d->f,
			cbdatapos, cbsize_payload);
	}
	else if(cbtype==0x54434950U) { // "PICT"
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "pict", NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_write_zeroes(outf, 512);
		dbuf_copy(d->f, cbdatapos, cbsize_payload, outf);
		dbuf_close(outf);
	}

done:
	;
}

static void dbg_FILETIME_as_duration(deark *c, lctx *d, i64 t, const char *name)
{
	i64 n_d, n_h, n_m;
	double n_s;

	n_d = t/864000000000LL;
	n_h = (t%864000000000LL)/36000000000LL;
	n_m = (t%36000000000LL)/600000000;
	n_s = ((double)(t%600000000))/10000000.0;
	de_dbg(c, "%s: %"I64_FMT" (%"I64_FMT"d %"I64_FMT"h %"I64_FMT"m %.3fs)",
		name, t, n_d, n_h, n_m, n_s);
}

static int do_prop_FILETIME(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, const char *name, i64 pos)
{
	i64 ts_as_FILETIME;
	int is_duration = 0;

	ts_as_FILETIME = dbuf_geti64le(d->f, pos);

	if(si->sfmtid==SFMTID_SUMMARYINFO && pinfo->prop_id==10) {
		is_duration = 1; // The "Editing time" property is special.
	}

	if(ts_as_FILETIME<=0) {
		de_dbg(c, "%s: %"I64_FMT, name, ts_as_FILETIME);
	}
	else if(is_duration) {
		dbg_FILETIME_as_duration(c, d, ts_as_FILETIME, name);
	}
	else {
		struct de_timestamp ts;
		char timestamp_buf[64];

		de_FILETIME_to_timestamp(ts_as_FILETIME, &ts, 0x1);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "%s: %"I64_FMT" (%s)", name, ts_as_FILETIME, timestamp_buf);
	}

	return 1;
}

static void do_prop_DATE(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, const char *name, i64 pos)
{
	double dval;

	dval = dbuf_getfloat64x(d->f, pos, 1);
	// TODO: Decode this better.
	de_dbg(c, "%s: %f", name, dval);
}

static void do_prop_UnicodeString(deark *c, lctx *d, struct propset_struct *si,
	const char *name, i64 dpos, i64 *bytes_consumed)
{
	i64 n, n_raw;
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	n_raw = dbuf_geti32le(d->f, dpos);
	n = n_raw;
	if(n>0) n--; // Ignore the trailing NUL
	if(n<0) n=0;
	dbuf_read_to_ucstring_n(d->f, dpos+4, n*2, DE_DBG_MAX_STRLEN*2, s,
		0, DE_ENCODING_UTF16LE);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));

	ucstring_destroy(s);
	// TODO: This is supposed to be padded to a multiple of 4 bytes, but in the
	// sample files I have, it is not.
	*bytes_consumed = 4 + n_raw*2;
}

// Caller creates and supplies s. The decoded string will be written to it.
static void do_prop_CodePageString2(deark *c, lctx *d, struct propset_struct *si,
	const char *name, i64 dpos, int is_dict_name, i64 *bytes_consumed,
	de_ucstring *s)
{
	i64 n_raw;
	int is_utf16 = (si->code_page==1200);
	de_encoding encoding = si->encoding;

	if(is_utf16 && is_dict_name && d->asciipropnames) {
		// A hack that the user can enable. Some dictionaries use an 8-bit
		// encoding even though they have CodePage=1200, and I don't know
		// how to detect this.
		is_utf16 = 0;
		encoding = DE_ENCODING_ASCII;
	}

	n_raw = dbuf_getu32le(d->f, dpos);

	if(is_utf16) {
		i64 n;

		if(is_dict_name) {
			n = n_raw*2;
		}
		else {
			n = n_raw;
		}
		dbuf_read_to_ucstring_n(d->f, dpos+4, n, DE_DBG_MAX_STRLEN*2, s,
			0, encoding);
		ucstring_truncate_at_NUL(s);
		if(is_dict_name) {
			*bytes_consumed = 4 + de_pad_to_4(n_raw*2);
		}
		else {
			*bytes_consumed = 4 + de_pad_to_4(n_raw);
		}
	}
	else {
		dbuf_read_to_ucstring_n(d->f, dpos+4, n_raw, DE_DBG_MAX_STRLEN, s,
			DE_CONVFLAG_STOP_AT_NUL, encoding);
		*bytes_consumed = 4 + n_raw;
	}
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
}

static void do_prop_CodePageString(deark *c, lctx *d, struct propset_struct *si,
	const char *name, i64 dpos, int is_dict_name, i64 *bytes_consumed)
{
	de_ucstring *s = NULL;
	s = ucstring_create(c);
	do_prop_CodePageString2(c, d, si, name, dpos, is_dict_name, bytes_consumed, s);
	ucstring_destroy(s);
}

static void do_prop_CLSID(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, const char *name, i64 pos)
{
	u8 clsid[16];
	char clsid_string[50];

	dbuf_read(d->f, clsid, pos, 16);
	de_fmtutil_guid_to_uuid(clsid);
	de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
	de_dbg(c, "%s: {%s}", name, clsid_string);
}

struct prop_data_type_info_struct {
	u32 dt;
	u32 flags;
	const char *name;
};
static const struct prop_data_type_info_struct prop_data_type_info_arr[] = {
	{0x00, 0, "empty"},
	{0x02, 0, "int16"},
	{0x03, 0, "int32"},
	{0x04, 0, "float32"},
	{0x05, 0, "float64"},
	{0x07, 0, "DATE"},
	{0x08, 0, "BSTR/CodePageString"},
	{0x0b, 0, "BOOL"},
	{0x0c, 0, "VARIANT"},
	{0x11, 0, "uint8"},
	{0x12, 0, "uint16"},
	{0x13, 0, "uint32"},
	{0x15, 0, "uint64"},
	{0x1e, 0, "CodePageString"},
	{0x1f, 0, "UnicodeString"},
	{0x40, 0, "FILETIME"},
	{0x41, 0, "blob"},
	{0x42, 0, "VT_STREAM"},
	{0x43, 0, "VT_STORAGE"},
	{0x47, 0, "ClipboardData"},
	{0x48, 0, "CLSID/GUID"}
};

static char *get_prop_data_type_name(char *buf, size_t buf_len, u32 dt)
{
	const char *name = NULL;
	const char *prefix = "";
	size_t k;

	if(dt>=0x1000 && dt<0x2000) {
		prefix = "vector of ";
		dt -= 0x1000;
	}
	else if(dt>=0x2000 && dt<0x3000) {
		prefix = "array of ";
		dt -= 0x2000;
	}

	for(k=0; k<DE_ARRAYCOUNT(prop_data_type_info_arr); k++) {
		if(prop_data_type_info_arr[k].dt == dt) {
			name = prop_data_type_info_arr[k].name;
			break;
		}
	}

	if(name) {
		de_snprintf(buf, buf_len, "%s%s", prefix, name);
	}
	else {
		de_strlcpy(buf, "?", buf_len);
	}

	return buf;
}

static void do_prop_any_int(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, const char *name, i64 pos,
	unsigned int nbytes, int is_signed)
{
	i64 n;
	char descr[200];

	// FIXME: This doesn't really support uint64.
	n = dbuf_getint_ext(d->f, pos, nbytes, 1, is_signed);

	descr[0] = '\0';

	if(pinfo->prop_id==0x00000001U) { // code page
		// Code page is usually a *signed* 16-bit int, which means the maximum
		// value is 32767, even though code pages can go up to 65535.
		// Apparently, code pages over 32767 are stored as negative numbers.
		if(n<0) {
			si->code_page = (int)(n + 65536);
		}
		else {
			si->code_page = (int)n;
		}

		si->encoding = de_windows_codepage_to_encoding(c, si->code_page,
			descr, sizeof(descr), 0x1);
		if(si->encoding==DE_ENCODING_UNKNOWN) {
			si->encoding = DE_ENCODING_ASCII;
		}
	}

	if(descr[0]) {
		de_dbg(c, "%s: %"I64_FMT" (%s)", name, n, descr);
	}
	else {
		de_dbg(c, "%s: %"I64_FMT, name, n);
	}
}

// Caller sets pos to the start of data (not to the 'type' field).
// Uses the scalar_type param, not the top-level pinfo->data_type.
// Returns 0 if the type is not supported.
static int do_prop_simple_type(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, u32 scalar_type, const char *name,
	i64 pos, i64 *bytes_consumed)
{
	double dval;

	*bytes_consumed = 0;

	switch(scalar_type) {
	case 0x00: // VT_EMPTY
	case 0x01: // VT_NULL
		break;

	case 0x11: // VT_UI1 = uint8
		do_prop_any_int(c, d, si, pinfo, name, pos, 1, 0);
		*bytes_consumed = 1;
		break;
	case 0x12: // VT_UI2 = uint16
	case 0x0b: // VT_BOOL (VARIANT_BOOL)
		do_prop_any_int(c, d, si, pinfo, name, pos, 2, 0);
		*bytes_consumed = 2;
		break;
	case 0x13: // VT_UI4 = uint32
	case 0x17: // VT_UINT
		do_prop_any_int(c, d, si, pinfo, name, pos, 4, 0);
		*bytes_consumed = 4;
		break;
	case 0x15: // VT_UI8
		do_prop_any_int(c, d, si, pinfo, name, pos, 8, 0);
		*bytes_consumed = 8;
		break;

	case 0x10: // VT_I1
		do_prop_any_int(c, d, si, pinfo, name, pos, 1, 1);
		*bytes_consumed = 1;
		break;
	case 0x02: // VT_I2 = int16
		do_prop_any_int(c, d, si, pinfo, name, pos, 2, 1);
		*bytes_consumed = 2;
		break;
	case 0x03: // VT_I4 = int32
	case 0x16: // VT_INT
		do_prop_any_int(c, d, si, pinfo, name, pos, 4, 1);
		*bytes_consumed = 4;
		break;
	case 0x14: // VT_I8
		do_prop_any_int(c, d, si, pinfo, name, pos, 8, 1);
		*bytes_consumed = 8;
		break;

	case 0x04: // VT_R4 = float32
		dval = dbuf_getfloat32x(d->f, pos, 1);
		de_dbg(c, "%s: %f", name, dval);
		*bytes_consumed = 4;
		break;
	case 0x05: // VT_R8 = float64
		dval = dbuf_getfloat64x(d->f, pos, 1);
		de_dbg(c, "%s: %f", name, dval);
		*bytes_consumed = 8;
		break;
	case 0x07: // VT_DATE
		do_prop_DATE(c, d, si, pinfo, name, pos);
		*bytes_consumed = 8;
		break;

	case 0x40:
		do_prop_FILETIME(c, d, si, pinfo, name, pos);
		*bytes_consumed = 8;
		break;

	case 0x48: // VT_CLSID
		do_prop_CLSID(c, d, si, pinfo, name, pos);
		*bytes_consumed = 16;
		break;

	case 0x08: // VT_BSTR
	case 0x1e: // VT_LPSTR
	case 0x42: // VT_STREAM
	case 0x43: // VT_STORAGE
	case 0x44: // VT_STREAMED_OBJECT
	case 0x45: // VT_STORED_OBJECT
		do_prop_CodePageString(c, d, si, name, pos, 0, bytes_consumed);
		break;

	case 0x1f: // Unicodestring
		do_prop_UnicodeString(c, d, si, name, pos, bytes_consumed);
		break;

	case 0x47:
		do_prop_clipboard(c, d, si, pinfo, pos, bytes_consumed);
		break;

	case 0x41:
		do_prop_blob(c, d, si, pinfo, name, pos, bytes_consumed);
		break;

	default:
		return 0;
	}

	return 1;
}

static void read_vectorheader(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, i64 *numitems)
{
	*numitems = dbuf_getu32le(d->f, pinfo->dpos);
	de_dbg(c, "number of items: %u", (unsigned int)(*numitems));
}

static int do_prop_vector_of_scalar(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo, u32 scalar_type)
{
	i64 k;
	i64 nitems;
	i64 pos = pinfo->dpos;

	read_vectorheader(c, d, si, pinfo, &nitems);
	pos += 4;

	// Note: These are the valid types:
	//  2,3,4,5,6,7,8,0xa,0xb,
	//  0x10,0x11,0x12,0x13,0x14,0x15,0x1e,0x1f,
	//  0x40,0x47,0x48
	//  (0xc is also a valid vector type, but is not handled here)

	for(k=0; k<nitems; k++) {
		i64 bytes_consumed = 0;
		int ret;
		char name[80];

		if(pos >= d->f->len) break;
		if(k>500) break;

		de_snprintf(name, sizeof(name), "%s[%u]",
			(pinfo->name_disposition==1)?pinfo->name:"value", (unsigned int)k);
		ret = do_prop_simple_type(c, d, si, pinfo, scalar_type, name, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) return 0;
		pos += bytes_consumed;
	}

	return 1;
}

static int do_prop_vector_of_variant(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo)
{
	i64 k;
	i64 nitems;
	i64 pos = pinfo->dpos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	read_vectorheader(c, d, si, pinfo, &nitems);
	pos += 4;

	for(k=0; k<nitems; k++) {
		u32 data_type;
		i64 bytes_consumed = 0;
		int ok;
		char dtname[80];

		if(pos >= d->f->len) break;
		if(k>500) break;

		de_dbg(c, "item[%u]:", (unsigned int)k);
		de_dbg_indent(c, 1);

		data_type = (u32)dbuf_getu16le_p(d->f, &pos);
		de_dbg(c, "data type: 0x%04x (%s)", (unsigned int)data_type,
			get_prop_data_type_name(dtname, sizeof(dtname), data_type));
		pos += 2; // padding

		// TODO: Probably need a better way to detect errors here.
		// Unlike in a vector, bytes_consumed can legitimately be 0.
		ok = do_prop_simple_type(c, d, si, pinfo, data_type, "value", pos, &bytes_consumed);
		if(!ok) goto done;
		pos += bytes_consumed;

		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return 1;
}

// Read the value(s) of any property.
// The type is pinfo->data_type, which can be a variant or aggregate type.
static void do_prop_toplevel(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo)
{
	char dtname[80];
	u32 scalar_type;
	int ok = 0;
	i64 bytes_consumed = 0;

	// TODO: There's some confusion about whether this is a 16-bit, or a 32-bit int.
	pinfo->data_type = (u32)dbuf_getu16le(d->f, si->tbloffset+pinfo->data_offs_rel);
	de_dbg(c, "data type: 0x%04x (%s)", (unsigned int)pinfo->data_type,
		get_prop_data_type_name(dtname, sizeof(dtname), pinfo->data_type));

	scalar_type = pinfo->data_type&0x00ff;

	if((pinfo->data_type&0xff00)==0x0000) {
		ok = do_prop_simple_type(c, d, si, pinfo, scalar_type,
			(pinfo->name_disposition==1)?pinfo->name:"value",
			pinfo->dpos, &bytes_consumed);
	}
	else if((pinfo->data_type&0xff00)==0x1000) {
		if(scalar_type==0x0c) {
			ok = do_prop_vector_of_variant(c, d, si, pinfo);
		}
		else {
			ok = do_prop_vector_of_scalar(c, d, si, pinfo, scalar_type);
		}
	}

	if(!ok) {
		de_dbg(c, "[data type 0x%04x not supported]", (unsigned int)pinfo->data_type);
	}
}

static void do_dictionary(deark *c, lctx *d, struct propset_struct *si,
	struct prop_info_struct *pinfo)
{
	size_t k;
	int saved_indent_level;
	i64 pos = si->tbloffset+pinfo->data_offs_rel;

	de_dbg_indent_save(c, &saved_indent_level);
	if(si->dictionary) goto done;
	si->num_dict_entries = (size_t)dbuf_getu32le_p(d->f, &pos);
	de_dbg(c, "number of dictionary entries: %u", (unsigned int)si->num_dict_entries);
	if(si->num_dict_entries > 500) {
		si->num_dict_entries = 0;
		goto done;
	}

	si->dictionary = de_mallocarray(c, (i64)si->num_dict_entries, sizeof(struct dictionary_entry));

	for(k=0; k<si->num_dict_entries; k++) {
		i64 bytes_consumed = 0;

		if(pos >= d->f->len) {
			de_warn(c, "Malformed Property Set dictionary, or unsupported dictionary format");
			break;
		}

		de_dbg(c, "entry[%u]:", (unsigned int)k);
		de_dbg_indent(c, 1);
		si->dictionary[k].prop_id = (u32)dbuf_getu32le_p(d->f, &pos);
		de_dbg(c, "prop id: 0x%08x", (unsigned int)si->dictionary[k].prop_id);
		si->dictionary[k].str = ucstring_create(c);
		do_prop_CodePageString2(c, d, si, "name", pos, 1, &bytes_consumed, si->dictionary[k].str);
		pos += bytes_consumed;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static const struct prop_info_entry prop_info_arr[] = {
	{SFMTID_COMMON, 0x00000000, MSK1, 0, "Dictionary", NULL},
	{SFMTID_COMMON, 0x00000001, MSK1, 0, "Code page", NULL},
	{SFMTID_COMMON, 0x80000000, MSK1, 0, "Locale", NULL},
	{SFMTID_COMMON, 0x80000001, MSK1, 0, "Behavior?", NULL},
	{SFMTID_COMMON, 0x80000003, MSK1, 0, "Behavior?", NULL},
	{SFMTID_SUMMARYINFO, 0x00000002, MSK1, 0, "Title", NULL},
	{SFMTID_SUMMARYINFO, 0x00000003, MSK1, 0, "Subject", NULL},
	{SFMTID_SUMMARYINFO, 0x00000004, MSK1, 0, "Author", NULL},
	{SFMTID_SUMMARYINFO, 0x00000005, MSK1, 0, "Keywords", NULL},
	{SFMTID_SUMMARYINFO, 0x00000006, MSK1, 0, "Comments", NULL},
	{SFMTID_SUMMARYINFO, 0x00000007, MSK1, 0, "Template", NULL},
	{SFMTID_SUMMARYINFO, 0x00000008, MSK1, 0, "Last saved by", NULL},
	{SFMTID_SUMMARYINFO, 0x00000009, MSK1, 0, "Revision number", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000a, MSK1, 0, "Editing time", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000b, MSK1, 0, "Last printed", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000c, MSK1, 0, "Create time", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000d, MSK1, 0, "Saved time", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000e, MSK1, 0, "Number of pages", NULL},
	{SFMTID_SUMMARYINFO, 0x0000000f, MSK1, 0, "Number of words", NULL},
	{SFMTID_SUMMARYINFO, 0x00000010, MSK1, 0, "Number of chars", NULL},
	{SFMTID_SUMMARYINFO, 0x00000011, MSK1, 0, "Thumbnail", NULL},
	{SFMTID_SUMMARYINFO, 0x00000012, MSK1, 0, "App name", NULL},
	{SFMTID_SUMMARYINFO, 0x00000013, MSK1, 0, "Security", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000002, MSK1, 0, "Category", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000003, MSK1, 0, "PresentationTarget", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000004, MSK1, 0, "Bytes", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000005, MSK1, 0, "Lines", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000006, MSK1, 0, "Paragraphs", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000007, MSK1, 0, "Slides", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000008, MSK1, 0, "Notes", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000009, MSK1, 0, "HiddenSlides", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000a, MSK1, 0, "MMClips", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000b, MSK1, 0, "ScaleCrop", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000c, MSK1, 0, "HeadingPairs", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000d, MSK1, 0, "TitlesofParts", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000e, MSK1, 0, "Manager", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000000f, MSK1, 0, "Company", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000010, MSK1, 0, "LinksUpToDate", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000011, MSK1, 0, "CCHWITHSPACES", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000013, MSK1, 0, "SHAREDDOC", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000014, MSK1, 0, "LINKBASE", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000015, MSK1, 0, "HLINKS", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000016, MSK1, 0, "HYPERLINKSCHANGED", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000017, MSK1, 0, "VERSION", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x00000018, MSK1, 0, "DIGSIG", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000001a, MSK1, 0, "CONTENTTYPE", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000001b, MSK1, 0, "CONTENTSTATUS", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000001c, MSK1, 0, "LANGUAGE", NULL},
	{SFMTID_DOCSUMMARYINFO, 0x0000001d, MSK1, 0, "DOCVERSION", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000000, MSK1, 0, "Number of resolutions", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000002, MSK1, 0, "Highest resolution width", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000003, MSK1, 0, "Highest resolution height", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000004, MSK1, 0, "Default display height", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000005, MSK1, 0, "Default display width", NULL},
	{SFMTID_IMAGECONTENTS, 0x01000006, MSK1, 0, "Display height/width units", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000000, 0xff00ffff, 0, "Subimage width", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000001, 0xff00ffff, 0, "Subimage height", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000002, 0xff00ffff, 0, "Subimage color", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000003, 0xff00ffff, 0, "Subimage numerical format", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000004, 0xff00ffff, 0, "Decimation method", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000005, 0xff00ffff, 0, "Decimation prefilter width", NULL},
	{SFMTID_IMAGECONTENTS, 0x02000007, 0xff00ffff, 0, "Subimage ICC profile", NULL},
	{SFMTID_IMAGECONTENTS, 0x03000001, 0xff00ffff, 0, "JPEG tables", NULL},
	{SFMTID_IMAGECONTENTS, 0x03000002, MSK1, 0, "Maximum JPEG table index", NULL},
	{SFMTID_SRCRESDESCR, 0x00010000, MSK1, 0, "Data object ID", NULL},
	{SFMTID_SRCRESDESCR, 0x00010002, MSK1, 0, "Locked property list", NULL},
	{SFMTID_SRCRESDESCR, 0x00010003, MSK1, 0, "Data object title", NULL},
	{SFMTID_SRCRESDESCR, 0x00010004, MSK1, 0, "Last modifier", NULL},
	{SFMTID_SRCRESDESCR, 0x00010005, MSK1, 0, "Revision number", NULL},
	{SFMTID_SRCRESDESCR, 0x00010006, MSK1, 0, "Creation time and date", NULL},
	{SFMTID_SRCRESDESCR, 0x00010007, MSK1, 0, "Modification time and date", NULL},
	{SFMTID_SRCRESDESCR, 0x00010008, MSK1, 0, "Creating application", NULL},
	{SFMTID_SRCRESDESCR, 0x00010100, MSK1, 0, "Status", NULL},
	{SFMTID_SRCRESDESCR, 0x00010101, MSK1, 0, "Creator", NULL},
	{SFMTID_SRCRESDESCR, 0x00010102, MSK1, 0, "Users", NULL},
	{SFMTID_SRCRESDESCR, 0x10000000, MSK1, 0, "Cached image height", NULL},
	{SFMTID_SRCRESDESCR, 0x10000001, MSK1, 0, "Cached image width", NULL},
	{SFMTID_EXTENSIONLIST, 0x10000000, MSK1, 0, "Used extension numbers", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000001, 0x0000ffff, 0, "Extension name", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000002, 0x0000ffff, 0, "Extension class ID", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000003, 0x0000ffff, 0, "Extension persistence", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000004, 0x0000ffff, 0, "Extension creation date", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000005, 0x0000ffff, 0, "Extension modification date", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000006, 0x0000ffff, 0, "Creating application", NULL},
	{SFMTID_EXTENSIONLIST, 0x00000007, 0x0000ffff, 0, "Extension description", NULL},
	{SFMTID_EXTENSIONLIST, 0x00001000, 0x0000ffff, 0, "Storage / stream pathname", NULL},
	{SFMTID_EXTENSIONLIST, 0x00002000, 0x0000ffff, 0, "FlashPix stream pathname", NULL},
	{SFMTID_EXTENSIONLIST, 0x00002001, 0x0000ffff, 0, "FlashPix stream field offset", NULL},
	{SFMTID_EXTENSIONLIST, 0x00003000, 0x0000ffff, 0, "Property set pathname", NULL},
	{SFMTID_EXTENSIONLIST, 0x00003001, 0x0000f00f, 0, "Property set ID codes", NULL},
	{SFMTID_EXTENSIONLIST, 0x00003002, 0x0000f00f, 0, "Property vector elements", NULL},
	{SFMTID_EXTENSIONLIST, 0x00004000, 0x0000ffff, 0, "Subimage number/resolution", NULL}
};

// Sets pinfo->name based on pinfo->type and si->sfmtid.
static void set_prop_name(deark *c, struct propset_struct *si, struct prop_info_struct *pinfo)
{
	size_t k;

	// Check the dictionary
	if(si->dictionary) {
		for(k=0; k<si->num_dict_entries; k++) {
			if(si->dictionary[k].prop_id == pinfo->prop_id) {
				pinfo->name_disposition = 2;
				ucstring_to_sz(si->dictionary[k].str, pinfo->name, sizeof(pinfo->name),
					0, DE_ENCODING_UTF8);
				return;
			}
		}
	}

	// Check our table of known types
	for(k=0; k<DE_ARRAYCOUNT(prop_info_arr); k++) {
		if((prop_info_arr[k].sfmtid != si->sfmtid) &&
			(prop_info_arr[k].sfmtid != SFMTID_COMMON))
		{
			continue;
		}
		if((prop_info_arr[k].prop_id) != (pinfo->prop_id & prop_info_arr[k].prop_id_mask))
			continue;

		pinfo->name_disposition = 1;
		de_strlcpy(pinfo->name, prop_info_arr[k].name, sizeof(pinfo->name));
		return;
	}

	// Not found
	pinfo->name_disposition = 0;
	de_strlcpy(pinfo->name, "???", sizeof(pinfo->name));
}

// Caller must set si->tbloffset and si->sfmtid
static void do_PropertySet(deark *c, lctx *d, struct propset_struct *si,
	i64 tblindex)
{
	i64 nproperties;
	i64 n;
	i64 i;
	struct prop_info_struct pinfo;
	u8 *whichpass = NULL;
	u8 pass;

	// I think this is the length of the data section
	n = dbuf_getu32le(d->f, si->tbloffset);
	de_dbg(c, "property data length: %d", (int)n);

	nproperties = dbuf_getu32le(d->f, si->tbloffset+4);
	de_dbg(c, "number of properties: %d", (int)nproperties);
	if(nproperties>200) goto done;

	// AFAICT it's legal for the interpretation of a property to depend on
	// properties that appear *after* it in the property table. For example,
	// a Dictionary really needs to be interpreted after Code Page, and before
	// any properties whose names are given in it. But it can appear anywhere.
	whichpass = de_malloc(c, nproperties);
	for(i=0; i<nproperties; i++) {
		u32 prop_id;
		prop_id = (u32)dbuf_getu32le(d->f, si->tbloffset+8 + 8*i);
		if(prop_id==0x00000001U || prop_id==0x80000000U || prop_id==0x80000001U ||
			prop_id==0x80000003U)
		{
			whichpass[i] = 1;
		}
		else if(prop_id==0x00000000U) {
			whichpass[i] = 2;
		}
		else {
			whichpass[i] = 3;
		}
	}

	for(pass=1; pass<=3; pass++) {
		de_dbg2(c, "pass %u", (unsigned int)pass);

		for(i=0; i<nproperties; i++) {
			char displayname[100];

			if(whichpass[i] != pass) continue;

			de_zeromem(&pinfo, sizeof(struct prop_info_struct));

			pinfo.prop_id = (u32)dbuf_getu32le(d->f, si->tbloffset+8 + 8*i);
			pinfo.data_offs_rel = dbuf_getu32le(d->f, si->tbloffset+8 + 8*i + 4);
			pinfo.dpos = si->tbloffset+pinfo.data_offs_rel+4;
			set_prop_name(c, si, &pinfo);

			if(pinfo.name_disposition==1) {
				de_strlcpy(displayname, pinfo.name, sizeof(displayname));
			}
			else if(pinfo.name_disposition==2) {
				de_snprintf(displayname, sizeof(displayname), "\"%s\"", pinfo.name);
			}
			else {
				de_strlcpy(displayname, "?", sizeof(displayname));
			}

			de_dbg(c, "prop[%d]: id=0x%08x (%s), data_offs=%d", (int)i,
				(unsigned int)pinfo.prop_id, displayname, (int)pinfo.data_offs_rel);
			de_dbg_indent(c, 1);
			if(pinfo.prop_id==0x00000000U) {
				do_dictionary(c, d, si, &pinfo);
			}
			else {
				do_prop_toplevel(c, d, si, &pinfo);
			}
			de_dbg_indent(c, -1);
		}
	}

done:
	de_free(c, whichpass);
}

static const struct fmtid_info_entry *find_fmtid_info(const u8 *b)
{
	size_t k;
	for(k=0; k<DE_ARRAYCOUNT(fmtid_info_arr); k++) {
		if(!de_memcmp(fmtid_info_arr[k].guid, b, 16)) {
			return &fmtid_info_arr[k];
		}
	}
	return NULL;
}

static void destroy_propset_struct(deark *c, struct propset_struct *si)
{
	if(!si) return;
	if(si->dictionary) {
		size_t k;
		for(k=0; k<si->num_dict_entries; k++) {
			ucstring_destroy(si->dictionary[k].str);
		}
		de_free(c, si->dictionary);
	}
	de_free(c, si);
}

static void do_decode_PropertySetStream(deark *c, lctx *d)
{
	i64 n;
	int saved_indent_level;
	i64 nsets;
	i64 k;
	i64 pos = 0;
	u8 clsid[16];
	char clsid_string[50];

	de_dbg_indent_save(c, &saved_indent_level);

	// expecting 48 (or more?) bytes of header info.
	n = dbuf_getu16le_p(d->f, &pos);
	de_dbg(c, "byte order code: 0x%04x", (unsigned int)n);
	if(n != 0xfffe) goto done;

	d->propset_version = (unsigned int)dbuf_getu16le_p(d->f, &pos);
	de_dbg(c, "property set version: %u", d->propset_version);

	n = dbuf_getu16le_p(d->f, &pos);
	de_dbg(c, "OS ver: 0x%04x", (unsigned int)n);
	n = dbuf_getu16le_p(d->f, &pos);
	de_dbg(c, "OS: 0x%04x", (unsigned int)n);

	dbuf_read(d->f, clsid, pos, 16);
	pos += 16;
	de_fmtutil_guid_to_uuid(clsid);
	de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
	de_dbg(c, "clsid: {%s}", clsid_string);

	nsets = dbuf_getu32le_p(d->f, &pos);
	de_dbg(c, "number of property sets: %d", (int)nsets);
	if(nsets>2) goto done;

	for(k=0; k<nsets; k++) {
		struct propset_struct *si = NULL;
		const struct fmtid_info_entry *fmtid_info;

		si = de_malloc(c, sizeof(struct propset_struct));
		si->encoding = DE_ENCODING_ASCII;

		dbuf_read(d->f, clsid, pos, 16);
		pos += 16;
		de_fmtutil_guid_to_uuid(clsid);
		fmtid_info = find_fmtid_info(clsid);
		de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
		de_dbg(c, "fmtid[%d]: {%s} (%s)", (int)k, clsid_string, fmtid_info?fmtid_info->name:"?");

		si->sfmtid = fmtid_info ? fmtid_info->sfmtid : SFMTID_UNKNOWN;

		// This is supposed to be a DWORD, but I've seen some with only two valid
		// bytes. And it shouldn't be much bigger than 48.
		si->tbloffset = dbuf_getu16le_p(d->f, &pos);
		pos += 2;

		de_dbg(c, "PropertySet[%d] table at %d", (int)k, (int)si->tbloffset);
		de_dbg_indent(c, 1);
		do_PropertySet(c, d, si, k);
		de_dbg_indent(c, -1);

		destroy_propset_struct(c, si);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_olepropset(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->f = c->infile;

	if(de_get_ext_option(c, "olepropset:asciipropnames")) {
		d->asciipropnames = 1;
	}

	do_decode_PropertySetStream(c, d);

	de_free(c, d);
}

void de_module_olepropset(deark *c, struct deark_module_info *mi)
{
	mi->id = "olepropset";
	mi->desc = "OLE Property Set";
	mi->run_fn = de_run_olepropset;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
