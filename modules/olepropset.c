// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// OLE Property Sets
// Refer to the Microsoft document "[MS-OLEPS]".

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_olepropset);

struct ole_prop_set_struct {
	dbuf *f; // The full data stream
	de_int64 tbloffset;
	de_uint32 sfmtid;
	int encoding;
};

struct prop_info_struct {
	de_uint32 prop_id;
	de_uint32 data_type;
	const char *name; // if known, or NULL
	const char *name_dbg; // name, or "value"
	de_int64 data_offs_rel;
	de_int64 dpos; // = si->tbloffset+pinfo->data_offs+4
};

static void read_timestamp(deark *c, dbuf *f, de_int64 pos,
	struct de_timestamp *ts, const char *field_name)
{
	de_int64 ts_as_FILETIME;
	char timestamp_buf[64];

	de_memset(ts, 0, sizeof(struct de_timestamp));
	ts_as_FILETIME = dbuf_geti64le(f, pos);
	if(ts_as_FILETIME==0) {
		de_dbg(c, "%s: %"INT64_FMT, field_name, ts_as_FILETIME);
	}
	else {
		de_FILETIME_to_timestamp(ts_as_FILETIME, ts);
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 1);
		de_dbg(c, "%s: %s", field_name, timestamp_buf);
	}
}

struct fmtid_info_entry {
	const de_byte guid[16];
	de_uint32 sfmtid; // short ID
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
	de_uint32 sfmtid;
	de_uint32 prop_id;
#define MSK1 0xffffffffU
	de_uint32 prop_id_mask;
	de_uint32 flags;
	const char *name;
	void *reserved;
};

static void do_prop_blob(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 blob_data_start;
	de_int64 blob_data_size;
	de_byte magic[8];

	blob_data_size = dbuf_getui32le(si->f, pinfo->dpos);
	de_dbg(c, "blob data size: %"INT64_FMT, blob_data_size);

	blob_data_start = pinfo->dpos+4;
	if(blob_data_start + blob_data_size > si->f->len) return;
	if(blob_data_size<8) return;

	// Minor hack. If a blob looks like a JPEG file, extract it.
	dbuf_read(si->f, magic, blob_data_start, 8);

	if(magic[0]==0xff && magic[1]==0xd8 && magic[2]==0xff) {
		dbuf_create_file_from_slice(si->f, blob_data_start, blob_data_size,
			"oleblob.jpg", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void do_prop_clipboard(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_uint32 cbtype;
	de_int64 cbsize_reported;
	de_int64 cbsize_payload;
	de_int64 cbdatapos;

	cbsize_reported = dbuf_getui32le(si->f, pinfo->dpos);
	de_dbg(c, "clipboard data size: %d", (int)cbsize_reported);

	cbtype = (de_uint32)dbuf_getui32le(si->f, pinfo->dpos+8);
	de_dbg(c, "clipboard data type: 0x%08x", (unsigned int)cbtype);

	cbdatapos = pinfo->dpos+12;
	cbsize_payload = cbsize_reported-8;
	if(cbdatapos + cbsize_payload > si->f->len) goto done;

	if(cbtype==3) { // CF_METAFILEPICT
		dbuf_create_file_from_slice(si->f, cbdatapos+8, cbsize_payload-8,
			"wmf", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(cbtype==8) { // CF_DIB
		de_run_module_by_id_on_slice2(c, "dib", "X", si->f,
			cbdatapos, cbsize_payload);
	}
	else if(cbtype==0x54434950U) { // "PICT"
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "pict", NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_write_zeroes(outf, 512);
		dbuf_copy(si->f, cbdatapos, cbsize_payload, outf);
		dbuf_close(outf);
	}

done:
	;
}

static void do_prop_int(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo, de_int64 n)
{
	de_dbg(c, "%s: %"INT64_FMT, pinfo->name_dbg, n);

	if(pinfo->prop_id==0x01) { // code page
		de_int64 n2;

		// I've seen some files in which the Code Page property appears
		// *after* some string properties. I don't know how to interpret
		// that, but for now, I'm not going to apply it retroactively.

		// Code page is usually a *signed* 16-bit int, which means the maximum
		// value is 32767, even though code pages can go up to 65535.
		// Apparently, code pages over 32767 are stored as negative numbers.
		n2 = n;
		if(n2<0) n2 += 65536;

		switch(n2) {
		case 1200: si->encoding = DE_ENCODING_UTF16LE; break;
		case 1252: si->encoding = DE_ENCODING_WINDOWS1252; break;
		case 10000: si->encoding = DE_ENCODING_MACROMAN; break;
		case 65001: si->encoding = DE_ENCODING_UTF8; break;
		default: si->encoding = DE_ENCODING_ASCII;
		}
	}
}

static int do_prop_FILETIME(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	struct de_timestamp ts;

	if(si->sfmtid==SFMTID_SUMMARYINFO && pinfo->prop_id==10) {
		de_int64 n;
		// The "Editing time" property typically has a data type of FILETIME,
		// but it is not actually a FILETIME (I assume it's an *amount* of time).
		n = dbuf_geti64le(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		return 1;
	}

	read_timestamp(c, si->f, pinfo->dpos, &ts, pinfo->name_dbg);
	return 1;
}


static void do_prop_UnicodeString_lowlevel(deark *c, struct ole_prop_set_struct *si,
	const char *name, de_int64 dpos, de_int64 *bytes_consumed)
{
	de_int64 n, n_raw;
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	n_raw = dbuf_geti32le(si->f, dpos);
	n = n_raw;
	if(n>0) n--; // Ignore the trailing NUL
	if(n<0) n=0;
	dbuf_read_to_ucstring_n(si->f, dpos+4, n*2, DE_DBG_MAX_STRLEN*2, s,
		0, DE_ENCODING_UTF16LE);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));

	ucstring_destroy(s);
	*bytes_consumed = 4 + n_raw*2;
}

static void do_prop_UnicodeString(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 bytes_consumed = 0;
	do_prop_UnicodeString_lowlevel(c, si, pinfo->name_dbg,
		pinfo->dpos, &bytes_consumed);
}

// a VectorHeader followed by a sequence of UnicodeString packets.
static void do_prop_UnicodeStringVector(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 pos = pinfo->dpos;
	de_int64 nitems;
	de_int64 k;

	nitems = dbuf_getui32le_p(si->f, &pos);
	de_dbg(c, "number of items: %u", (unsigned int)nitems);
	for(k=0; k<nitems; k++) {
		de_int64 bytes_consumed = 0;
		if(pos >= si->f->len) break;
		do_prop_UnicodeString_lowlevel(c, si, pinfo->name_dbg,
			pos, &bytes_consumed);
		pos += bytes_consumed;
	}
}

static void do_prop_CodePageString_lowlevel(deark *c, struct ole_prop_set_struct *si,
	const char *name, de_int64 dpos, de_int64 *bytes_consumed)
{
	de_int64 n, n_raw;
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	n_raw = dbuf_geti32le(si->f, dpos);
	n = n_raw;

	if(si->encoding==DE_ENCODING_UTF16LE) {
		dbuf_read_to_ucstring_n(si->f, dpos+4, n, DE_DBG_MAX_STRLEN*2, s,
			0, si->encoding);
		ucstring_truncate_at_NUL(s);
	}
	else {
		dbuf_read_to_ucstring_n(si->f, dpos+4, n, DE_DBG_MAX_STRLEN, s,
			DE_CONVFLAG_STOP_AT_NUL, si->encoding);
	}
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));

	ucstring_destroy(s);
	*bytes_consumed = 4 + n_raw;
}

static void do_prop_CodePageString(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 bytes_consumed = 0;
	do_prop_CodePageString_lowlevel(c, si, pinfo->name_dbg, pinfo->dpos, &bytes_consumed);
}

static void do_prop_CodePageStringVector(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 pos = pinfo->dpos;
	de_int64 nitems;
	de_int64 k;
	char name[80];

	nitems = dbuf_getui32le_p(si->f, &pos);
	de_dbg(c, "number of items: %u", (unsigned int)nitems);
	for(k=0; k<nitems; k++) {
		de_int64 bytes_consumed = 0;
		if(pos >= si->f->len) break;
		de_snprintf(name, sizeof(name), "%s[%u]", pinfo->name_dbg, (unsigned int)k);
		do_prop_CodePageString_lowlevel(c, si, name, pos, &bytes_consumed);
		pos += bytes_consumed;
	}
}

static void do_prop_CLSID(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_byte clsid[16];
	char clsid_string[50];

	dbuf_read(si->f, clsid, pinfo->dpos, 16);
	de_fmtutil_guid_to_uuid(clsid);
	de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
	de_dbg(c, "clsid: {%s}", clsid_string);
}

struct prop_data_type_info_struct {
	de_uint32 dt;
	de_uint32 flags;
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

static char *get_prop_data_type_name(char *buf, size_t buf_len, de_uint32 dt)
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

	for(k=0; k<DE_ITEMS_IN_ARRAY(prop_data_type_info_arr); k++) {
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

// Read the value for one property.
static void do_prop_data(deark *c, struct ole_prop_set_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 n;
	double dval;
	char dtname[80];

	// TODO: There's some confusion about whether this is a 16-bit, or a 32-bit int.
	pinfo->data_type = (de_uint32)dbuf_getui16le(si->f, si->tbloffset+pinfo->data_offs_rel);
	de_dbg(c, "data type: 0x%04x (%s)", (unsigned int)pinfo->data_type,
		get_prop_data_type_name(dtname, sizeof(dtname), pinfo->data_type));

	switch(pinfo->data_type) {
	case 0x00:
	case 0x01:
		break;
	case 0x02: // int16
		n = dbuf_geti16le(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		break;
	case 0x03: // int32
	case 0x16:
		n = dbuf_geti32le(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		break;
	case 0x04: // float32
		dval = dbuf_getfloat32x(si->f, pinfo->dpos, 1);
		de_dbg(c, "%s: %f", pinfo->name_dbg, dval);
		break;
	case 0x05: // float64
		dval = dbuf_getfloat64x(si->f, pinfo->dpos, 1);
		de_dbg(c, "%s: %f", pinfo->name_dbg, dval);
		break;
	case 0x11: // uint8
		n = (de_int64)dbuf_getbyte(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		break;
	case 0x12: // uint16
	case 0x0b: // BOOL (VARIANT_BOOL)
		n = dbuf_getui16le(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		break;
	case 0x13: // uint32
	case 0x17:
		n = dbuf_getui32le(si->f, pinfo->dpos);
		do_prop_int(c, si, pinfo, n);
		break;
	case 0x1e: // string with length prefix
		do_prop_CodePageString(c, si, pinfo);
		break;
	case 0x101e:
		do_prop_CodePageStringVector(c, si, pinfo);
		break;
	case 0x1f: // Unicodestring
		do_prop_UnicodeString(c, si, pinfo);
		break;
	case 0x101f:
		do_prop_UnicodeStringVector(c, si, pinfo);
		break;
	case 0x40:
		do_prop_FILETIME(c, si, pinfo);
		break;
	case 0x41:
		do_prop_blob(c, si, pinfo);
		break;
	case 0x47:
		do_prop_clipboard(c, si, pinfo);
		break;
	case 0x48:
		do_prop_CLSID(c, si, pinfo);
		break;
	default:
		de_dbg(c, "[data type 0x%04x not supported]", (unsigned int)pinfo->data_type);
	}
}

static const struct prop_info_entry prop_info_arr[] = {
	{SFMTID_COMMON, 0x00000001, MSK1, 0, "Code page", NULL},
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
static void set_prop_name(deark *c, struct ole_prop_set_struct *si, struct prop_info_struct *pinfo)
{
	const struct prop_info_entry *pi = NULL;
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(prop_info_arr); k++) {
		if((prop_info_arr[k].sfmtid != si->sfmtid) &&
			(prop_info_arr[k].sfmtid != SFMTID_COMMON))
		{
			continue;
		}
		if((prop_info_arr[k].prop_id) != (pinfo->prop_id & prop_info_arr[k].prop_id_mask))
			continue;
		pi = &prop_info_arr[k];
		break;
	}

	if(pi) {
		pinfo->name = pi->name;
	}

	pinfo->name_dbg = pinfo->name ? pinfo->name : "value";
}

// Caller must set si->tbloffset and si->sfmtid
static void do_property_table(deark *c, struct ole_prop_set_struct *si,
	de_int64 tblindex)
{
	de_int64 nproperties;
	de_int64 n;
	de_int64 i;
	struct prop_info_struct pinfo;

	// I think this is the length of the data section
	n = dbuf_getui32le(si->f, si->tbloffset);
	de_dbg(c, "property data length: %d", (int)n);

	nproperties = dbuf_getui32le(si->f, si->tbloffset+4);
	de_dbg(c, "number of properties: %d", (int)nproperties);
	if(nproperties>200) goto done;

	for(i=0; i<nproperties; i++) {
		de_memset(&pinfo, 0, sizeof(struct prop_info_struct));

		pinfo.prop_id = (de_uint32)dbuf_getui32le(si->f, si->tbloffset+8 + 8*i);
		pinfo.data_offs_rel = dbuf_getui32le(si->f, si->tbloffset+8 + 8*i + 4);
		pinfo.dpos = si->tbloffset+pinfo.data_offs_rel+4;
		set_prop_name(c, si, &pinfo);

		de_dbg(c, "prop[%d]: type=0x%08x (%s), data_offs=%d", (int)i,
			(unsigned int)pinfo.prop_id, pinfo.name?pinfo.name:"?",
			(int)pinfo.data_offs_rel);
		de_dbg_indent(c, 1);
		do_prop_data(c, si, &pinfo);
		de_dbg_indent(c, -1);
	}

done:
	;
}

static const struct fmtid_info_entry *find_fmtid_info(const de_byte *b)
{
	size_t k;
	for(k=0; k<DE_ITEMS_IN_ARRAY(fmtid_info_arr); k++) {
		if(!de_memcmp(fmtid_info_arr[k].guid, b, 16)) {
			return &fmtid_info_arr[k];
		}
	}
	return NULL;
}

static void do_decode_ole_property_set(deark *c, dbuf *f)
{
	de_int64 n;
	int saved_indent_level;
	struct ole_prop_set_struct *si = NULL;
	de_int64 nsets;
	de_int64 k;
	de_int64 pos = 0;
	de_byte clsid[16];
	char clsid_string[50];

	de_dbg_indent_save(c, &saved_indent_level);
	si = de_malloc(c, sizeof(struct ole_prop_set_struct));
	// TODO: ASCII may not always be the best default.
	si->encoding = DE_ENCODING_ASCII;
	si->f = f;

	// expecting 48 (or more?) bytes of header info.
	n = dbuf_getui16le_p(si->f, &pos);
	de_dbg(c, "byte order code: 0x%04x", (unsigned int)n);
	if(n != 0xfffe) goto done;

	n = dbuf_getui16le_p(si->f, &pos);
	de_dbg(c, "property set version: %d", (unsigned int)n);

	n = dbuf_getui16le_p(si->f, &pos);
	de_dbg(c, "OS ver: 0x%04x", (unsigned int)n);
	n = dbuf_getui16le_p(si->f, &pos);
	de_dbg(c, "OS: 0x%04x", (unsigned int)n);

	dbuf_read(si->f, clsid, pos, 16);
	pos += 16;
	de_fmtutil_guid_to_uuid(clsid);
	de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
	de_dbg(c, "clsid: {%s}", clsid_string);

	nsets = dbuf_getui32le_p(si->f, &pos);
	de_dbg(c, "number of property sets: %d", (int)nsets);
	if(nsets>2) goto done;

	for(k=0; k<nsets; k++) {
		const struct fmtid_info_entry *fmtid_info;

		dbuf_read(si->f, clsid, pos, 16);
		pos += 16;
		de_fmtutil_guid_to_uuid(clsid);
		fmtid_info = find_fmtid_info(clsid);
		de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
		de_dbg(c, "fmtid[%d]: {%s} (%s)", (int)k, clsid_string, fmtid_info?fmtid_info->name:"?");

		si->sfmtid = fmtid_info ? fmtid_info->sfmtid : SFMTID_UNKNOWN;

		// This is supposed to be a DWORD, but I've seen some with only two valid
		// bytes. And it shouldn't be much bigger than 48.
		si->tbloffset = dbuf_getui16le_p(si->f, &pos);
		pos += 2;
		de_dbg(c, "table[%d] offset: %d", (int)k, (int)si->tbloffset);

		de_dbg(c, "property table[%d]", (int)k);
		de_dbg_indent(c, 1);
		do_property_table(c, si, k);
		de_dbg_indent(c, -1);
	}

done:
	de_free(c, si);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_olepropset(deark *c, de_module_params *mparams)
{
	do_decode_ole_property_set(c, c->infile);
}

void de_module_olepropset(deark *c, struct deark_module_info *mi)
{
	mi->id = "olepropset";
	mi->desc = "OLE Property Set";
	mi->run_fn = de_run_olepropset;
	mi->identify_fn = de_identify_none;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
