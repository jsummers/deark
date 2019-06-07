// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ID3 metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_id3);

// **************************************************************************
// ID3v2
// **************************************************************************

#define CODE_APIC 0x41504943U
#define CODE_COM  0x434f4dU
#define CODE_COMM 0x434f4d4dU
#define CODE_GEO  0x47454fU
#define CODE_GEOB 0x47454f42U
#define CODE_PIC  0x504943U
#define CODE_POP  0x504f50U
#define CODE_POPM 0x504f504dU
#define CODE_PRIV 0x50524956U
#define CODE_TXX  0x545858U
#define CODE_TXXX 0x54585858U
#define CODE_WXX  0x575858U
#define CODE_WXXX 0x57585858U

#define ID3ENC_ISO_8859_1 0
#define ID3ENC_UTF16      1
#define ID3ENC_UTF16BE    2
#define ID3ENC_UTF8       3

typedef struct id3v2ctx_struct {
	u8 has_id3v2;
	u8 wmpicture_mode;

	i64 total_len;

	// "data" is the extended header, the frames, and the padding, in the
	// original file.
	i64 data_start;
	i64 data_len;

	int has_padding;
	i64 approx_padding_pos;

	// Sigh. One would think that the "major version" of ID3v2 would
	// necessarily always be 2. One would be wrong. It depends on context.
	// The "2" is not stored in the file, which is fine. But the spec calls the
	// first number that *is* stored the "major version", and the second number
	// the "revision number".
	u8 version_code, ver_revision;

	// If set, the data is unsynched as a single blob, 2.3.x-style.
	u8 global_level_unsync;

	// If set, 2.4.x-style frame-level unsynch is used for all frames.
	u8 global_frame_level_unsync;

	u8 has_ext_header;
	u8 is_experimental;
	u8 has_footer;

	const char *approx_mark;
} id3v2ctx;

static i64 get_synchsafe_int(dbuf *f, i64 pos)
{
	u8 buf[4];
	dbuf_read(f, buf, pos, 4);
	return (buf[0]<<21)|(buf[1]<<14)|(buf[2]<<7)|(buf[3]);
}

static const char *get_id3v2_textenc_name(id3v2ctx *d, u8 id3_encoding)
{
	const char *encname;

	switch(id3_encoding) {
	case 0: encname = "ISO-8859-1"; break;
	case 1:
		if(d->version_code==2) encname = "UCS-2";
		else if(d->version_code==3) encname = "UCS-2 w/BOM";
		else encname = "UTF-16 w/BOM";
		break;
	case 2: encname = "UTF-16BE"; break;
	case 3: encname = "UTF-8"; break;
	default: encname = "?";
	}
	return encname;
}

static void id3v2_read_to_ucstring(deark *c, dbuf *f, i64 pos1, i64 len,
	de_ucstring *s, u8 id3_encoding)
{
	i64 pos = pos1;
	const char *bomdesc = "none";
	de_encoding encoding_to_use = DE_ENCODING_UNKNOWN;

	if(len<=0) goto done;

	if(id3_encoding==ID3ENC_ISO_8859_1) {
		encoding_to_use = DE_ENCODING_LATIN1;
	}
	else if(id3_encoding==ID3ENC_UTF16) {
		u32 bom_id;

		if(len<2) goto done;
		bom_id = (u32)dbuf_getu16be(f, pos);

		if(bom_id==0xfeff) {
			encoding_to_use = DE_ENCODING_UTF16BE;
			bomdesc = "BE";
		}
		else if(bom_id==0xfffe) {
			encoding_to_use = DE_ENCODING_UTF16LE;
			bomdesc = "LE";
		}
		else {
			// TODO: What should we do if there's no BOM?
			// v2.2.x does not say anything about a BOM, but it also does not
			// say anything about what byte order is used.
			// v2.3.x and 2.4.x require a BOM.
			goto done;
		}
		pos += 2;
	}
	else if(id3_encoding==ID3ENC_UTF16BE) {
		encoding_to_use = DE_ENCODING_UTF16BE;
	}
	else if(id3_encoding==ID3ENC_UTF8) { // UTF-8
		encoding_to_use = DE_ENCODING_UTF8;
	}
	else {
		goto done; // Error
	}

	// TODO: Maybe shouldn't use DE_DBG_MAX_STRLEN here.
	dbuf_read_to_ucstring_n(f, pos, pos1+len-pos, DE_DBG_MAX_STRLEN, s, 0, encoding_to_use);
	ucstring_truncate_at_NUL(s);

done:
	if(id3_encoding==ID3ENC_UTF16 && c->debug_level>=2) {
		de_dbg2(c, "BOM: %s", bomdesc);
	}
}

static int read_id3v2_terminated_string(deark *c, id3v2ctx *d, dbuf *f,
	i64 pos, i64 nbytes_avail, i64 nbytes_to_scan, u8 id3_encoding,
	de_ucstring *s, i64 *bytes_consumed)
{
	i64 foundpos = 0;
	i64 stringlen;
	int ret;
	int retval = 0;

	if(nbytes_to_scan > nbytes_avail)
		nbytes_to_scan = nbytes_avail;
	if(nbytes_to_scan < 0)
		nbytes_to_scan = 0;

	if(id3_encoding==ID3ENC_UTF16 || id3_encoding==ID3ENC_UTF16BE) {
		// A 2-byte encoding
		int foundflag = 0;

		foundflag = dbuf_get_utf16_NULterm_len(f, pos, nbytes_to_scan, bytes_consumed);
		if(!foundflag) goto done;
		stringlen = (*bytes_consumed)-2;
	}
	else {
		// A 1-byte encoding
		ret = dbuf_search_byte(f, 0x00, pos, nbytes_to_scan, &foundpos);
		if(!ret) goto done;
		stringlen = foundpos - pos;
		*bytes_consumed = stringlen + 1;
	}

	id3v2_read_to_ucstring(c, f, pos, stringlen, s, id3_encoding);

	retval = 1;
done:
	return retval;
}

// Read 10-byte main ID3v2 header
static int do_id3v2_header(deark *c, dbuf *f, id3v2ctx *d)
{
	i64 pos;
	u8 flags;
	int retval = 0;
	int has_global_compression = 0;

	pos = 0;
	d->approx_mark = "";

	de_dbg(c, "ID3v2 header at %d", (int)pos);
	de_dbg_indent(c, 1);

	// TODO: Verify signature
	d->has_id3v2 = 1;
	pos += 3; // ID3v2 file identifier

	d->version_code = dbuf_getbyte(f, pos++);
	d->ver_revision = dbuf_getbyte(f, pos++);
	de_dbg(c, "ID3v2 version: (2.)%d.%d", (int)d->version_code, (int)d->ver_revision);
	if(d->version_code<2 || d->version_code>4) {
		de_warn(c, "Unsupported ID3v2 version: (2.)%d.x", (int)d->version_code);
		goto done;
	}

	flags = dbuf_getbyte(f, pos++);
	de_dbg(c, "flags: 0x%02x", (unsigned int)flags);
	de_dbg_indent(c, 1);

	if(d->version_code<=3) {
		d->global_level_unsync = (flags&0x80)?1:0;
		de_dbg(c, "global-level unsynchronisation: %d", (int)d->global_level_unsync);
	}
	else if(d->version_code==4) {
		d->global_frame_level_unsync = (flags&0x80)?1:0;
		de_dbg(c, "all frames use unsynchronisation: %d", (int)d->global_frame_level_unsync);
	}

	if(d->global_level_unsync) {
		d->approx_mark = "~";
	}

	if(d->version_code==2) {
		has_global_compression = (flags&0x40)?1:0;
		de_dbg(c, "uses compression: %d", d->has_ext_header);
	}
	else if(d->version_code>=3) {
		d->has_ext_header = (flags&0x40)?1:0;
		de_dbg(c, "has extended header: %d", d->has_ext_header);
	}

	if(d->version_code>=3) {
		d->is_experimental = (flags&0x20)?1:0;
		de_dbg(c, "is experimental: %d", d->is_experimental);
	}

	if(d->version_code >= 4) {
		d->has_footer = (flags&0x10)?1:0;
		de_dbg(c, "has footer: %d", d->has_footer);
	}

	de_dbg_indent(c, -1);

	d->data_len = get_synchsafe_int(f, pos);
	de_dbg(c, "size: %d", (int)d->data_len);
	pos += 4;

	d->data_start = 10;

	d->total_len = d->data_start + d->data_len;
	if(d->has_footer) d->total_len += 10;

	de_dbg(c, "calculated end of ID3v2 data: %d", (int)d->total_len);

	if(has_global_compression) {
		de_warn(c, "ID3v2.2.x Compression not supported");
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

// This type of escaping is called "unsynchronisation", but I'm just calling it
// "escaping" in some places, because otherwise it's too confusing for me.
// The term "unsynchronisation" makes it sound like it's *un*doing something,
// which it's not.
// Also, the process of undoing unsynchronisation does not seem to have a
// name. Calling it "synchronisation" would be confusing, and not really
// accurate; and "ununsynchronisation" would be a word crime.
static void unescape_id3v2_data(deark *c, dbuf *inf, i64 inf_start,
	i64 inf_len, dbuf *outf)
{
	i64 srcpos = inf_start;
	u8 b0;

	de_dbg(c, "unescaping \"unsynchronised\" ID3v2 data");
	de_dbg_indent(c, 1);

	while(srcpos<inf_start+inf_len) {
		b0 = dbuf_getbyte(inf, srcpos++);
		if(b0==0xff && srcpos<(inf_start+inf_len-1) && dbuf_getbyte(inf, srcpos)==0x00) {
			srcpos++;
		}
		dbuf_writebyte(outf, b0);
	}

	de_dbg(c, "unescaped %d bytes to %d bytes", (int)inf_len, (int)outf->len);
	de_dbg_indent(c, -1);
}

static void decode_id3v2_frame_text(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len, struct de_fourcc *tag4cc)
{
	u8 id3_encoding;
	de_ucstring *s = NULL;
	i64 pos = pos1;

	if(len<1) goto done;
	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding,
		get_id3v2_textenc_name(d, id3_encoding));

	s = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, s, id3_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
}

// From frames starting with "W", except WXXX
static void decode_id3v2_frame_urllink(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len, struct de_fourcc *tag4cc)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(f, pos1, len, s, 0, DE_ENCODING_LATIN1);
	de_dbg(c, "url: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);
}

// TXX, TXXX, WXX, WXXX
static void decode_id3v2_frame_txxx_etc(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len, struct de_fourcc *tag4cc)
{
	i64 pos = pos1;
	u8 id3_encoding;
	de_ucstring *description = NULL;
	de_ucstring *value = NULL;
	i64 bytes_consumed;
	const char *name;
	int ret;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding,
		get_id3v2_textenc_name(d, id3_encoding));

	description = ucstring_create(c);
	bytes_consumed = 0;
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding, description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_getpsz(description));
	pos += bytes_consumed;

	value = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, value, id3_encoding);
	if(tag4cc->id==CODE_WXX || tag4cc->id==CODE_WXXX) name="url";
	else name="value";
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(value));

done:
	ucstring_destroy(description);
	ucstring_destroy(value);
}

static void decode_id3v2_frame_priv(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	struct de_stringreaderdata *owner = NULL;
	i64 pos = pos1;
	i64 nbytes_to_scan;
	i64 payload_len;

	nbytes_to_scan = pos1+len-pos;
	if(nbytes_to_scan>256) nbytes_to_scan=256;

	owner = dbuf_read_string(f, pos, nbytes_to_scan, nbytes_to_scan,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	if(!owner->found_nul) goto done;

	de_dbg(c, "owner: \"%s\"", ucstring_getpsz(owner->str));
	pos += owner->bytes_consumed;

	payload_len = pos1+len-pos;
	if(payload_len<1) goto done;

	de_dbg(c, "private frame data at %"I64_FMT", len=%"I64_FMT, pos, payload_len);
	if(!de_strcmp(owner->sz, "XMP")) {
		dbuf_create_file_from_slice(f, pos, payload_len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(c->debug_level>=2) {
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, f, pos, payload_len, 256, NULL, 0x1);
		de_dbg_indent(c, -1);
	}

done:
	de_destroy_stringreaderdata(c, owner);
}

static void decode_id3v2_frame_comm(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	u8 id3_encoding;
	i64 pos = pos1;
	de_ucstring *lang = NULL;
	de_ucstring *shortdesc = NULL;
	de_ucstring *comment_text = NULL;
	i64 bytes_consumed;
	int ret;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding,
		get_id3v2_textenc_name(d, id3_encoding));

	lang = ucstring_create(c);
	dbuf_read_to_ucstring(f, pos, 3, lang, 0, DE_ENCODING_ASCII);
	de_dbg(c, "language: \"%s\"", ucstring_getpsz(lang));
	pos += 3;

	shortdesc = ucstring_create(c);
	bytes_consumed = 0;
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		shortdesc, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "short description: \"%s\"", ucstring_getpsz(shortdesc));
	pos += bytes_consumed;

	comment_text = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, comment_text, id3_encoding);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz(comment_text));

done:
	ucstring_destroy(lang);
	ucstring_destroy(shortdesc);
	ucstring_destroy(comment_text);
}

struct apic_type_info {
	u8 picture_type;
	const char *name;
	const char *token;
};
static const struct apic_type_info apic_type_info_arr[] = {
	{0x00, "other/unspecified", NULL},
	{0x01, "standard file icon", "icon"},
	{0x02, "file icon", "icon"},
	{0x03, "front cover", "front_cover"},
	{0x04, "back cover", "back_cover"},
	{0x05, "leaflet page", NULL},
	{0x06, "media", "media"},
	{0x07, "lead artist", NULL},
	{0x08, "artist", NULL},
	{0x09, "conductor", NULL},
	{0x0a, "band", NULL},
	{0x0b, "composer", NULL},
	{0x0c, "lyricist", NULL},
	{0x0d, "recording location", NULL},
	{0x0e, "picture taken during recording", NULL},
	{0x0f, "picture taken during performance", NULL},
	{0x10, "frame from video", NULL},
	{0x12, "illustration", NULL},
	{0x13, "logo of artist", NULL},
	{0x14, "logo of publisher/studio", NULL}
};

static const struct apic_type_info *get_apic_type_info(u8 t)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(apic_type_info_arr); k++) {
		if(apic_type_info_arr[k].picture_type == t) {
			return &apic_type_info_arr[k];
		}
	}
	return NULL;
}

static void extract_pic_apic(deark *c, id3v2ctx *d, dbuf *f,
	 i64 pos, i64 len, const struct apic_type_info *ptinfo)
{
	const char *ext;
	char fullext[32];
	u8 sig[2];
	const char *token = NULL;

	dbuf_read(f, sig, pos, 2);
	if(sig[0]==0x89 && sig[1]==0x50) ext="png";
	else if(sig[0]==0xff && sig[1]==0xd8) ext="jpg";
	else ext="bin";

	if(ptinfo && ptinfo->token) token = ptinfo->token;
	if(!token) {
		if(d->wmpicture_mode) token = "wmpic";
	}
	if(!token) token = "id3pic";

	de_snprintf(fullext, sizeof(fullext), "%s.%s", token, ext);

	dbuf_create_file_from_slice(f, pos, len, fullext, NULL, DE_CREATEFLAG_IS_AUX);
}

// Similar to decode_id3v2_frame_pic_apic()
static void decode_id3v2_frame_wmpicture(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	u8 picture_type;
	i64 pos = pos1;
	i64 pic_data_len;
	i64 stringlen; // includes terminating 0x0000
	de_ucstring *mimetype = NULL;
	de_ucstring *description = NULL;
	const struct apic_type_info *ptinfo = NULL;
	int ret;

	picture_type = dbuf_getbyte(f, pos++);
	ptinfo = get_apic_type_info(picture_type);
	de_dbg(c, "picture type: 0x%02x (%s)", (unsigned int)picture_type,
		ptinfo?ptinfo->name:"?");

	pic_data_len = dbuf_getu32le(f, pos);
	de_dbg(c, "picture size: %u", (unsigned int)pic_data_len);
	pos += 4;

	ret = dbuf_get_utf16_NULterm_len(f, pos, pos1+len-pos, &stringlen);
	if(!ret) goto done;
	mimetype = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, stringlen-2, 256, mimetype, 0, DE_ENCODING_UTF16LE);
	de_dbg(c, "mime type: \"%s\"", ucstring_getpsz_d(mimetype));
	pos += stringlen;

	ret = dbuf_get_utf16_NULterm_len(f, pos, pos1+len-pos, &stringlen);
	if(!ret) goto done;
	mimetype = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, stringlen-2, 2048, mimetype, 0, DE_ENCODING_UTF16LE);
	de_dbg(c, "description: \"%s\"", ucstring_getpsz_d(mimetype));
	// TODO: Maybe the description should be used in the filename?
	pos += stringlen;

	if(pos+pic_data_len > pos1+len) goto done;
	extract_pic_apic(c, d, f, pos, pic_data_len, ptinfo);

done:
	ucstring_destroy(mimetype);
	ucstring_destroy(description);
}

static void decode_id3v2_frame_pic_apic(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len, struct de_fourcc *tag4cc)
{
	u8 id3_encoding;
	u8 picture_type;
	i64 pos = pos1;
	struct de_stringreaderdata *fmt_srd = NULL;
	de_ucstring *mimetype = NULL;
	de_ucstring *description = NULL;
	const struct apic_type_info *ptinfo = NULL;
	i64 bytes_consumed = 0;
	int ret;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding,
		get_id3v2_textenc_name(d, id3_encoding));

	if(tag4cc->id==CODE_PIC) {
		fmt_srd = dbuf_read_string(f, pos, 3, 3, 0, DE_ENCODING_ASCII);
		de_dbg(c, "format: \"%s\"", ucstring_getpsz(fmt_srd->str));
		pos += 3;
	}
	else {
		mimetype = ucstring_create(c);
		ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
			mimetype, &bytes_consumed);
		if(!ret) goto done;
		de_dbg(c, "mime type: \"%s\"", ucstring_getpsz(mimetype));
		pos += bytes_consumed;
	}

	picture_type = dbuf_getbyte(f, pos++);
	ptinfo = get_apic_type_info(picture_type);
	de_dbg(c, "picture type: 0x%02x (%s)", (unsigned int)picture_type,
		ptinfo?ptinfo->name:"?");

	description = ucstring_create(c);
	// "The description has a maximum length of 64 characters" [we'll allow more]
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_getpsz(description));
	pos += bytes_consumed;

	if(pos >= pos1+len) goto done;
	extract_pic_apic(c, d, f, pos, pos1+len-pos, ptinfo);

done:
	de_destroy_stringreaderdata(c, fmt_srd);
	ucstring_destroy(mimetype);
	ucstring_destroy(description);
}

// FLAC "PICTURE" format is, I think it's safe to say, inspired by ID3 PIC/APIC
// format. But it's quite different in detail.
// This function probably belongs in the flac module instead of here, but it's
// a tough call. Putting it here is easier for now, as it makes it easy to
// reuse some code.
static void decode_flacpicture(deark *c, id3v2ctx *d, dbuf *f,
	i64 pos1, i64 len)
{
	u32 picture_type;
	i64 pos = pos1;
	i64 pic_data_len;
	i64 stringlen;
	de_ucstring *mimetype = NULL;
	de_ucstring *description = NULL;
	const struct apic_type_info *ptinfo = NULL;

	picture_type = (u32)dbuf_getu32be_p(f, &pos);
	if(picture_type<=0xff) {
		ptinfo = get_apic_type_info((u8)picture_type);
	}
	de_dbg(c, "picture type: 0x%04x (%s)", (unsigned int)picture_type,
		ptinfo?ptinfo->name:"?");

	stringlen = dbuf_getu32be_p(f, &pos);
	mimetype = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, stringlen, 256, mimetype, 0, DE_ENCODING_UTF8);
	de_dbg(c, "mime type: \"%s\"", ucstring_getpsz_d(mimetype));
	pos += stringlen;

	stringlen = dbuf_getu32be_p(f, &pos);
	description = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, stringlen, 512, description, 0, DE_ENCODING_UTF8);
	de_dbg(c, "description: \"%s\"", ucstring_getpsz_d(description));
	pos += stringlen;

	pos += 4; // width
	pos += 4; // height
	pos += 4; // bits/pixel
	pos += 4; // # palette entries
	pic_data_len = dbuf_getu32be_p(f, &pos);
	de_dbg(c, "picture size: %u", (unsigned int)pic_data_len);
	if(pos+pic_data_len > pos1+len) goto done;
	extract_pic_apic(c, d, f, pos, pic_data_len, ptinfo);

done:
	ucstring_destroy(mimetype);
	ucstring_destroy(description);
}

static void decode_id3v2_frame_geob(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	u8 id3_encoding;
	i64 pos = pos1;
	de_ucstring *mimetype = NULL;
	de_ucstring *filename = NULL;
	de_ucstring *description = NULL;
	i64 bytes_consumed = 0;
	int ret;
	i64 objlen;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding,
		get_id3v2_textenc_name(d, id3_encoding));

	mimetype = ucstring_create(c);
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
		mimetype, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "mime type: \"%s\"", ucstring_getpsz(mimetype));
	pos += bytes_consumed;

	filename = ucstring_create(c);
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		filename, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(filename));
	pos += bytes_consumed;

	description = ucstring_create(c);
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_getpsz(description));
	pos += bytes_consumed;

	objlen = pos1+len-pos;
	if(objlen<1) goto done;

	de_dbg(c, "[%d bytes of encapsulated object data]", (int)objlen);

	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(f, pos, objlen, "encobj.bin",
			NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(c->debug_level>=2) {
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, f, pos, objlen, 256, NULL, 0x1);
		de_dbg_indent(c, -1);
	}

done:
	ucstring_destroy(mimetype);
	ucstring_destroy(filename);
	ucstring_destroy(description);
}

// Popularimeter
static void decode_id3v2_frame_pop_popm(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	i64 bytes_consumed = 0;
	de_ucstring *email = NULL;
	i64 pos = pos1;
	int rating;
	int ret;

	email = ucstring_create(c);
	ret = read_id3v2_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
		email, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "email/id: \"%s\"", ucstring_getpsz(email));
	pos += bytes_consumed;

	if(pos1+len-pos < 1) goto done;
	rating = (int)dbuf_getbyte(f, pos++);
	de_dbg(c, "rating: %d%s", rating, (rating==0)?" (unknown)":"/255");

	// TODO: There can be a "counter" field here.

done:
	ucstring_destroy(email);
}

static void decode_id3v2_frame_internal(deark *c, id3v2ctx *d, dbuf *f,
	i64 pos1, i64 len, struct de_fourcc *tag4cc)
{
	if(d->version_code==2) {
		if(tag4cc->id==CODE_TXX || tag4cc->id==CODE_WXX) {
			decode_id3v2_frame_txxx_etc(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->bytes[0]=='T') {
			decode_id3v2_frame_text(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->bytes[0]=='W') {
			decode_id3v2_frame_urllink(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->id==CODE_COM) {
			decode_id3v2_frame_comm(c, d, f, pos1, len);
		}
		else if(tag4cc->id==CODE_GEO) {
			decode_id3v2_frame_geob(c, d, f, pos1, len);
		}
		else if(tag4cc->id==CODE_PIC) {
			decode_id3v2_frame_pic_apic(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->id==CODE_POP) {
			decode_id3v2_frame_pop_popm(c, d, f, pos1, len);
		}
	}
	else if(d->version_code>=3) {
		// "All text frame identifiers begin with "T". Only text frame identifiers
		// begin with "T", with the exception of the "TXXX" frame."
		if(tag4cc->id==CODE_TXXX || tag4cc->id==CODE_WXXX) {
			decode_id3v2_frame_txxx_etc(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->bytes[0]=='T') {
			decode_id3v2_frame_text(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->bytes[0]=='W') {
			decode_id3v2_frame_urllink(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->id==CODE_COMM) {
			decode_id3v2_frame_comm(c, d, f, pos1, len);
		}
		else if(tag4cc->id==CODE_GEOB) {
			decode_id3v2_frame_geob(c, d, f, pos1, len);
		}
		else if(tag4cc->id==CODE_PRIV) {
			decode_id3v2_frame_priv(c, d, f, pos1, len);
		}
		else if(tag4cc->id==CODE_APIC) {
			decode_id3v2_frame_pic_apic(c, d, f, pos1, len, tag4cc);
		}
		else if(tag4cc->id==CODE_POPM) {
			decode_id3v2_frame_pop_popm(c, d, f, pos1, len);
		}
	}
}

static void decode_id3v2_frame(deark *c, id3v2ctx *d, dbuf *f,
	i64 pos1, i64 len,
	struct de_fourcc *tag4cc, unsigned int flags1, unsigned int flags2)
{
	u8 frame_level_unsynch = d->global_frame_level_unsync;
	dbuf *unescaped_frame = NULL;

	if(d->version_code==3) {
		if(flags2&0x80) { // 'i'
			de_dbg(c, "[compressed frame not supported]");
			goto done;
		}
		if(flags2&0x40) { // 'j'
			de_dbg(c, "[encrypted frame not supported]");
			goto done;
		}
		if(flags2&0x20) { // 'k'
			de_dbg(c, "[grouped frame not supported]");
			goto done;
		}
	}
	if(d->version_code==4) {
		if(flags2&0x40) { // 'h'
			de_dbg(c, "[grouped frame not supported]");
			goto done;
		}
		if(flags2&0x08) { // 'k'
			de_dbg(c, "[compressed frame not supported]");
			goto done;
		}
		if(flags2&0x04) { // 'm'
			de_dbg(c, "[encrypted frame not supported]");
			goto done;
		}
		if(flags2&0x02) { // 'n'
			// If the global 'unsynch' flag is set, but a frame's local flag
			// is not, evidence suggests the global flag has priority.
			// So if this flag makes a change, it will only be 0->1, never 1->0.
			frame_level_unsynch = 1;
		}
		if(flags2&0x01) { // 'p';
			de_dbg(c, "[frame with data-length-indicator not supported]");
			goto done;
		}
	}

	if(frame_level_unsynch) {
		unescaped_frame = dbuf_create_membuf(c, 0, 0);
		unescape_id3v2_data(c, f, pos1, len, unescaped_frame);
		decode_id3v2_frame_internal(c, d, unescaped_frame, 0, unescaped_frame->len, tag4cc);
	}
	else {
		decode_id3v2_frame_internal(c, d, f, pos1, len, tag4cc);
	}

done:
	dbuf_close(unescaped_frame);
}

static const char *get_id3v2_frame_name(id3v2ctx *d, u32 id)
{
	struct frame_list_entry {
		u32 threecc, fourcc;
		const char *name;
	};
	static const struct frame_list_entry frame_list[] = {
		// This is a partial list, of some of the common frame types.
		{0x54414cU, 0x54414c42U, "Album/Movie/Show title"},
		{CODE_PIC,  CODE_APIC,   "Attached picture"},
		{0x545032U, 0x54504532U, "Band/orchestra/accompaniment"},
		{0x544250U, 0x5442504dU, "Beats per minute"},
		{CODE_COM,  CODE_COMM,   "Comments"},
		{0x57434dU, 0x57434f4dU, "Commercial information"},
		{0x54434dU, 0x54434f4dU, "Composer"},
		{0x545033U, 0x54504533U, "Conductor"},
		{0x54434fU, 0x54434f4eU, "Content type"},
		{0x544352U, 0x54434f50U, "Copyright message"},
		{0x544441U, 0x54444154U, "Date"},
		{0x54454eU, 0x54454e43U, "Encoded by"},
		{CODE_GEO,  CODE_GEOB,   "General encapsulated object"},
		{0x544b45U, 0x544b4559U, "Initial key"},
		{0,         0x54434d50U, "iTunes Compilation Flag"}, // TCMP
		{0x544c41U, 0x544c414eU, "Language"},
		{0x545031U, 0x54504531U, "Lead artist/Performing group"}, // TP1,TPE1
		{0x544c45U, 0x544c454eU, "Length"},
		{0x545854U, 0x54455854U, "Lyricist"},
		{0x4d4349U, 0x4d434449U, "Music CD identifier"},
		{0x574152U, 0x574f4152U, "Official artist/performer webpage"},
		{0x574146U, 0x574f4146U, "Official audio file webpage"},
		{0x574153U, 0x574f4153U, "Official audio source webpage"},
		{0x544f54U, 0x544f414cU, "Original album/movie/show title"},
		{0x544f41U, 0x544f5045U, "Original artist/performer"},
		{0x544f4cU, 0x544f4c59U, "Original lyricist"},
		{0,         0x54504f53U, "Part of a set"}, // TPOS
		{CODE_POP,  CODE_POPM,   "Popularimeter"},
		{0,         CODE_PRIV,   "Private frame"},
		{0x545042U, 0x54505542U, "Publisher"},
		{0,         0x54445243U, "Recording time"},
		{0x525641U, 0x52564144U, "Relative volume adjustment"},
		{0x545353U, 0x54535345U, "Software/Hardware and settings used for encoding"},
		{0x54494dU, 0x54494d45U, "Time"},
		{0x545432U, 0x54495432U, "Title"},
		{0x54524bU, 0x5452434bU, "Track number"},
		{0x554c54U, 0x55534c54U, "Unsychronized lyric transcription"},
		{CODE_TXX,  CODE_TXXX,   "User defined text information"},
		{CODE_WXX,  CODE_WXXX,   "User defined URL link"},
		{0x545945U, 0x54594552U, "Year"}
	};
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(frame_list); k++) {
		if(d->version_code==2) {
			if(id==frame_list[k].threecc)
				return frame_list[k].name;
		}
		else {
			if(id==frame_list[k].fourcc)
				return frame_list[k].name;
		}
	}
	return "?";
}

static void do_id3v2_frames(deark *c, id3v2ctx *d,
	dbuf *f, i64 pos1, i64 len, i64 orig_pos)
{
	i64 pos = pos1;
	struct de_fourcc tag4cc;
	int saved_indent_level;
	i64 frame_idx = 0;
	i64 frame_header_len;

	de_zeromem(&tag4cc, sizeof(struct de_fourcc));
	if(d->version_code<=2) frame_header_len = 6;
	else frame_header_len = 10;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "ID3v2 frames at %d", (int)orig_pos);
	de_dbg_indent(c, 1);

	while(1) {
		i64 frame_dlen;
		u8 flags1, flags2;
		u8 b;
		char *flg2name;

		if(pos+frame_header_len > pos1+len) break;

		// Peek at the next byte
		b = dbuf_getbyte(f, pos);
		if(b==0x00) {
			d->has_padding = 1;
			d->approx_padding_pos = orig_pos+pos;
			break;
		}

		// The offset we print might not be exact, because of (pre-v2.4.x)
		// unsynchronisation.
		// (We have no efficient way to map the position in the unescaped data
		// back to the corresponding position in the original file.)
		de_dbg(c, "frame #%d at %s%d", (int)frame_idx, d->approx_mark, (int)(orig_pos+pos));
		de_dbg_indent(c, 1);

		if(d->version_code<=2) {
			// Version 2.2.x uses a "THREECC".
			dbuf_read_fourcc(f, pos, &tag4cc, 3, 0x0);
			pos += 3;
		}
		else {
			dbuf_read_fourcc(f, pos, &tag4cc, 4, 0x0);
			pos += 4;
		}

		de_dbg(c, "tag: '%s' (%s)", tag4cc.id_dbgstr,
			get_id3v2_frame_name(d, tag4cc.id));

		if(d->version_code<=2) {
			frame_dlen = dbuf_getint_ext(f, pos, 3, 0, 0); // read 24-bit BE uint
			pos += 3;
		}
		else if(d->version_code==3) {
			frame_dlen = dbuf_getu32be(f, pos);
			pos += 4;
		}
		else {
			frame_dlen = get_synchsafe_int(f, pos);
			pos += 4;
		}
		de_dbg(c, "size: %d", (int)frame_dlen);

		if(d->version_code<=2) {
			flags1 = 0;
			flags2 = 0;
		}
		else {
			flags1 = dbuf_getbyte(f, pos++);
			flags2 = dbuf_getbyte(f, pos++);
			if(d->version_code<=3) flg2name = "encoding";
			else flg2name = "format_description";
			de_dbg(c, "flags: status_messages=0x%02x, %s=0x%02x",
				(unsigned int)flags1, flg2name, (unsigned int)flags2);
		}

		if(pos+frame_dlen > pos1+len) goto done;
		decode_id3v2_frame(c, d, f, pos, frame_dlen, &tag4cc, flags1, flags2);

		pos += frame_dlen;
		frame_idx++;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// WM/Picture a metadata element that occurs in ASF, and maybe other, Microsoft
// formats. Microsoft says
//   "This attribute is compatible with the ID3 frame, APIC."
// That's slightly misleading. It contains the same information, but formatted
// in an incompatible way.
// It seems to be a serialization of the WM_PICTURE struct, with the fields in
// a different order.
static void do_wmpicture(deark *c, dbuf *f, i64 pos, i64 len)
{
	id3v2ctx *d = NULL;

	d = de_malloc(c, sizeof(id3v2ctx));
	d->wmpicture_mode = 1;
	decode_id3v2_frame_wmpicture(c, d, f, pos, len);
	de_free(c, d);
}

static void do_flacpicture(deark *c, dbuf *f, i64 pos, i64 len)
{
	id3v2ctx *d = NULL;

	d = de_malloc(c, sizeof(id3v2ctx));
	decode_flacpicture(c, d, f, pos, len);
	de_free(c, d);
}

static void do_id3v2(deark *c, dbuf *f, i64 pos, i64 bytes_avail,
	 i64 *bytes_consumed)
{
	id3v2ctx *d = NULL;
	dbuf *unescaped_data = NULL;
	i64 ext_header_size = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	*bytes_consumed = 0;
	d = de_malloc(c, sizeof(id3v2ctx));
	if(!do_id3v2_header(c, f, d)) goto done;
	if(!d->has_id3v2) goto done;

	if(d->has_ext_header) {
		de_dbg(c, "ID3v2 extended header at %d", (int)d->data_start);
		de_dbg_indent(c, 1);
		if(d->version_code==3 && !d->global_level_unsync) {
			ext_header_size = 4 + dbuf_getu32be(f, d->data_start);
			de_dbg(c, "extended header size: %d", (int)ext_header_size);
			// TODO: Decode the rest of the extended header
		}
		else if(d->version_code==4) {
			u8 ext_flags;
			ext_header_size = get_synchsafe_int(f, d->data_start);
			de_dbg(c, "extended header size: %d", (int)ext_header_size);
			// [d->data_start+5] = flag byte count that should always be 1
			ext_flags = dbuf_getbyte(f, d->data_start+5);
			de_dbg(c, "extended flags: 0x%02x", (unsigned int)ext_flags);
			// TODO: Decode the rest of the extended header
		}
		else {
			de_warn(c, "Extended header not supported");
			goto done; // TODO: v2.3.x w/ unsynch
		}
		de_dbg_indent(c, -1);
		if(ext_header_size > d->data_len) goto done;
	}

	if(d->global_level_unsync) {
		unescaped_data = dbuf_create_membuf(c, 0, 0);
		unescape_id3v2_data(c, f, d->data_start,
			d->data_len, unescaped_data);
	}
	else {
		unescaped_data = dbuf_open_input_subfile(f,
			d->data_start + ext_header_size,
			d->data_len - ext_header_size);
	}

	do_id3v2_frames(c, d, unescaped_data, 0, unescaped_data->len,
		d->data_start + ext_header_size);

	if(d->has_padding) {
		de_dbg(c, "ID3v2 padding at %s%d", d->approx_mark, (int)d->approx_padding_pos);
	}

	*bytes_consumed = d->total_len;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(unescaped_data);
	de_free(c, d);
}

// **************************************************************************
// ID3v1
// **************************************************************************

static const char *get_id3v1_genre_name(u8 g)
{
	struct genre_list_entry {
		u8 id;
		const char *name;
	};
	static const struct genre_list_entry genre_list[] = {
		{0, "Blues"}, {1, "Classic Rock"}, {2, "Country"}, {3, "Dance"}, {4, "Disco"},
		{5, "Funk"}, {6, "Grunge"}, {7, "Hip-Hop"}, {8, "Jazz"}, {9, "Metal"},
		{10, "New Age"}, {11, "Oldies"}, {12, "Other"}, {13, "Pop"}, {14, "R&B"},
		{15, "Rap"}, {16, "Reggae"}, {17, "Rock"}, {18, "Techno"}, {19, "Industrial"},
		{20, "Alternative"}, {21, "Ska"}, {22, "Death Metal"}, {23, "Pranks"}, {24, "Soundtrack"},
		{25, "Euro-Techno"}, {26, "Ambient"}, {27, "Trip-Hop"}, {28, "Vocal"}, {29, "Jazz+Funk"},
		{30, "Fusion"}, {31, "Trance"}, {32, "Classical"}, {33, "Instrumental"}, {34, "Acid"},
		{35, "House"}, {36, "Game"}, {37, "Sound Clip"}, {38, "Gospel"}, {39, "Noise"},
		{40, "AlternRock"}, {41, "Bass"}, {42, "Soul"}, {43, "Punk"}, {44, "Space"},
		{45, "Meditative"}, {46, "Instrumental Pop"}, {47, "Instrumental Rock"}, {48, "Ethnic"}, {49, "Gothic"},
		{50, "Darkwave"}, {51, "Techno-Industrial"}, {52, "Electronic"}, {53, "Pop-Folk"}, {54, "Eurodance"},
		{55, "Dream"}, {56, "Southern Rock"}, {57, "Comedy"}, {58, "Cult"}, {59, "Gangsta"},
		{60, "Top 40"}, {61, "Christian Rap"}, {62, "Pop/Funk"}, {63, "Jungle"}, {64, "Native American"},
		{65, "Cabaret"}, {66, "New Wave"}, {67, "Psychedelic"}, {68, "Rave"}, {69, "Showtunes"},
		{70, "Trailer"}, {71, "Lo-Fi"}, {72, "Tribal"}, {73, "Acid Punk"}, {74, "Acid Jazz"},
		{75, "Polka"}, {76, "Retro"}, {77, "Musical"}, {78, "Rock & Roll"}, {79, "Hard Rock"},
		{80, "Folk"}, {81, "Folk-Rock"}, {82, "National Folk"}, {83, "Swing"}, {84, "Fast Fusion"},
		{85, "Bebob"}, {86, "Latin"}, {87, "Revival"}, {88, "Celtic"}, {89, "Bluegrass"},
		{90, "Avantgarde"}, {91, "Gothic Rock"}, {92, "Progressive Rock"}, {93, "Psychedelic Rock"}, {94, "Symphonic Rock"},
		{95, "Slow Rock"}, {96, "Big Band"}, {97, "Chorus"}, {98, "Easy Listening"}, {99, "Acoustic"},
		{100, "Humour"}, {101, "Speech"}, {102, "Chanson"}, {103, "Opera"}, {104, "Chamber Music"},
		{105, "Sonata"}, {106, "Symphony"}, {107, "Booty Brass"}, {108, "Primus"}, {109, "Porn Groove"},
		{110, "Satire"}, {111, "Slow Jam"}, {112, "Club"}, {113, "Tango"}, {114, "Samba"},
		{115, "Folklore"}, {116, "Ballad"}, {117, "Poweer Ballad"}, {118, "Rhytmic Soul"}, {119, "Freestyle"},
		{120, "Duet"}, {121, "Punk Rock"}, {122, "Drum Solo"}, {123, "A Capela"}, {124, "Euro-House"},
		{125, "Dance Hall"},
		{255, "unspecified"} };
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(genre_list); k++) {
		if(genre_list[k].id==g) {
			return genre_list[k].name;
		}
	}
	return "unknown";
}

static void do_id3v1(deark *c, i64 pos1)
{
	i64 pos = pos1;
	de_ucstring *s = NULL;
	u8 genre;

	s = ucstring_create(c);
	pos += 3;

	dbuf_read_to_ucstring(c->infile, pos, 30, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "song title: \"%s\"", ucstring_getpsz(s));
	pos += 30;

	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 30, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "artist: \"%s\"", ucstring_getpsz(s));
	pos += 30;

	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 30, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "album: \"%s\"", ucstring_getpsz(s));
	pos += 30;

	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 4, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "year: \"%s\"", ucstring_getpsz(s));
	pos += 4;

	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 30, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz(s));
	pos += 28;
	if(de_getbyte(pos)==0) {
		u8 trknum;
		trknum = de_getbyte(pos+1);
		if(trknum!=0) {
			// Looks like ID3v1.1
			de_dbg(c, "track number: %d", (int)trknum);
		}
	}
	pos += 2;

	genre = de_getbyte(pos);
	de_dbg(c, "genre: %d (%s)", (int)genre, get_id3v1_genre_name(genre));

	ucstring_destroy(s);
}

// **************************************************************************

static void de_run_id3(deark *c, de_module_params *mparams)
{
	if(de_havemodcode(c, mparams, 'I')) { // raw ID3v2
		i64 bytes_consumed_id3v2 = 0;
		do_id3v2(c, c->infile, 0, c->infile->len, &bytes_consumed_id3v2);
		if(mparams) {
			mparams->out_params.int64_1 = bytes_consumed_id3v2;
		}
		goto done;
	}
	if(de_havemodcode(c, mparams, '1')) { // raw ID3v1
		do_id3v1(c, 0);
		goto done;
	}
	if(de_havemodcode(c, mparams, 'P')) { // Windows WM/Picture
		do_wmpicture(c, c->infile, 0, c->infile->len);
		goto done;
	}
	if(de_havemodcode(c, mparams, 'F')) { // FLAC PICTURE
		do_flacpicture(c, c->infile, 0, c->infile->len);
		goto done;
	}

done:
	;
}

// Figure out the size of the ID3V2 segment at the beginning of the file.
// Sets c->detection_data.id3.bytes_at_start, etc.
// Note code duplication with do_id3v2_header().
// Note code duplication with de_fmtutil_handle_id3().
static int de_identify_id3(deark *c)
{
	u8 flags;
	u8 version_code;
	u8 has_footer = 0;
	i64 total_len;

	c->detection_data.id3.detection_attempted = 1;
	if(dbuf_memcmp(c->infile, 0, "ID3", 3)) return 0;
	c->detection_data.id3.has_id3v2 = 1;

	version_code = dbuf_getbyte(c->infile, 3);
	flags = dbuf_getbyte(c->infile, 5);
	if(version_code >= 4) {
		has_footer = (flags&0x10)?1:0;
	}

	total_len = 10;
	total_len += get_synchsafe_int(c->infile, 6);
	if(has_footer) total_len += 10;

	de_dbg2(c, "[id3detect] calculated end of ID3v2 data: %u", (unsigned int)total_len);
	c->detection_data.id3.bytes_at_start = (u32)total_len;

	// This module is never "detected". It's only used for its side effects,
	// and as a submodule.
	return 0;
}

void de_module_id3(deark *c, struct deark_module_info *mi)
{
	mi->id = "id3";
	mi->desc = "ID3 metadata";
	mi->run_fn = de_run_id3;
	mi->identify_fn = de_identify_id3;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_SHAREDDETECTION;
}
