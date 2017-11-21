// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ID3v2 metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_id3v2);

#define CODE_APIC 0x41504943U
#define CODE_COM  0x434f4d00U
#define CODE_COMM 0x434f4d4dU
#define CODE_GEO  0x47454f00U
#define CODE_GEOB 0x47454f42U
#define CODE_PIC  0x50494300U
#define CODE_POP  0x504f5000U
#define CODE_POPM 0x504f504dU
#define CODE_PRIV 0x50524956U
#define CODE_TXX  0x54585800U
#define CODE_TXXX 0x54585858U
#define CODE_WXX  0x57585800U
#define CODE_WXXX 0x57585858U

#define ID3ENC_ISO_8859_1 0
#define ID3ENC_UTF16      1
#define ID3ENC_UTF16BE    2
#define ID3ENC_UTF8       3

typedef struct localctx_struct {
	de_byte has_id3v2;

	de_int64 total_len;

	// "data" is the extended header, the frames, and the padding, in the
	// original file.
	de_int64 data_start;
	de_int64 data_len;

	// Sigh. One would think that the "major version" of ID3v2 would
	// necessarily always be 2. One would be wrong. It depends on context.
	// The "2" is not stored in the file, which is fine. But the spec calls the
	// first number that *is* stored the "major version", and the second number
	// the "revision number".
	de_byte version_code, ver_revision;

	// If set, the data is unsynched as a single blob, 2.3.x-style.
	de_byte global_level_unsync;

	// If set, 2.4.x-style frame-level unsynch is used for all frames.
	de_byte global_frame_level_unsync;

	de_byte has_ext_header;
	de_byte is_experimental;
	de_byte has_footer;
} lctx;

static de_int64 get_ui24be(dbuf *f, de_int64 pos)
{
	de_byte buf[3];
	dbuf_read(f, buf, pos, 3);
	return (buf[0]<<16)|(buf[1]<<8)|(buf[2]);
}

static de_int64 get_synchsafe_int(dbuf *f, de_int64 pos)
{
	de_byte buf[4];
	dbuf_read(f, buf, pos, 4);
	return (buf[0]<<21)|(buf[1]<<14)|(buf[2]<<7)|(buf[3]);
}

static const char *get_textenc_name(lctx *d, de_byte id3_encoding)
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

static void id3v2_read_to_ucstring(deark *c, dbuf *f, de_int64 pos1, de_int64 len,
	de_ucstring *s, de_byte id3_encoding)
{
	de_int64 pos = pos1;
	const char *bomdesc = "none";
	int encoding_to_use = DE_ENCODING_UNKNOWN;

	if(len<=0) goto done;

	if(id3_encoding==ID3ENC_ISO_8859_1) {
		encoding_to_use = DE_ENCODING_LATIN1;
	}
	else if(id3_encoding==ID3ENC_UTF16) {
		de_uint32 bom_id;

		if(len<2) goto done;
		bom_id = (de_uint32)dbuf_getui16be(f, pos);

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

static int read_terminated_string(deark *c, lctx *d, dbuf *f,
	de_int64 pos, de_int64 nbytes_avail, de_int64 nbytes_to_scan, de_byte id3_encoding,
	de_ucstring *s, de_int64 *bytes_consumed)
{
	de_int64 foundpos = 0;
	de_int64 stringlen;
	int ret;
	int retval = 0;

	if(nbytes_to_scan > nbytes_avail)
		nbytes_to_scan = nbytes_avail;
	if(nbytes_to_scan < 0)
		nbytes_to_scan = 0;

	if(id3_encoding==ID3ENC_UTF16 || id3_encoding==ID3ENC_UTF16BE) {
		// A 2-byte encoding
		de_int64 k;
		int foundflag = 0;

		// Search for the aligned pair of 0x00 bytes that marks the end of string.
		for(k=0; k<=(nbytes_to_scan-2); k+=2) {
			de_int64 x;
			x = dbuf_getui16be(f, pos+k);
			if(x==0) {
				foundflag = 1;
				stringlen = k;
				*bytes_consumed = stringlen + 2;
			}
		}
		if(!foundflag) goto done;
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
static int do_id3v2_header(deark *c, dbuf *f, lctx *d)
{
	de_int64 pos;
	de_byte flags;
	int retval = 0;
	int has_global_compression = 0;

	pos = 0;

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
static void unescape_id3v2_data(deark *c, dbuf *inf, de_int64 inf_start,
	de_int64 inf_len, dbuf *outf)
{
	de_int64 srcpos = inf_start;
	de_byte b0;

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

static void decode_id3v2_frame_text(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
{
	de_byte id3_encoding;
	de_ucstring *s = NULL;
	de_int64 pos = pos1;

	if(len<1) goto done;
	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, get_textenc_name(d, id3_encoding));

	s = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, s, id3_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_get_printable_sz(s));

done:
	ucstring_destroy(s);
}

// From frames starting with "W", except WXXX
static void decode_id3v2_frame_urllink(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(f, pos1, len, s, 0, DE_ENCODING_LATIN1);
	de_dbg(c, "url: \"%s\"", ucstring_get_printable_sz(s));
	ucstring_destroy(s);
}

// TXX, TXXX, WXX, WXXX
static void decode_id3v2_frame_txxx_etc(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
{
	de_int64 pos = pos1;
	de_byte id3_encoding;
	de_ucstring *description = NULL;
	de_ucstring *value = NULL;
	de_int64 bytes_consumed;
	const char *name;
	int ret;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, get_textenc_name(d, id3_encoding));

	description = ucstring_create(c);
	bytes_consumed = 0;
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding, description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_get_printable_sz(description));
	pos += bytes_consumed;

	value = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, value, id3_encoding);
	if(tag4cc->id==CODE_WXX || tag4cc->id==CODE_WXXX) name="url";
	else name="value";
	de_dbg(c, "%s: \"%s\"", name, ucstring_get_printable_sz(value));

done:
	ucstring_destroy(description);
	ucstring_destroy(value);
}

static void decode_id3v2_frame_priv(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len)
{
	struct de_stringreaderdata *owner = NULL;
	de_int64 pos = pos1;
	de_int64 nbytes_to_scan;
	de_int64 payload_len;

	nbytes_to_scan = pos1+len-pos;
	if(nbytes_to_scan>256) nbytes_to_scan=256;

	owner = dbuf_read_string(f, pos, nbytes_to_scan, nbytes_to_scan,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	if(!owner->found_nul) goto done;

	de_dbg(c, "owner: \"%s\"", ucstring_get_printable_sz(owner->str));
	pos += owner->bytes_consumed;

	payload_len = pos1+len-pos;
	if(payload_len<1) goto done;

	if(!de_strcmp((const char*)owner->sz, "XMP")) {
		dbuf_create_file_from_slice(f, pos, payload_len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
	}

done:
	de_destroy_stringreaderdata(c, owner);
}

static void decode_id3v2_frame_comm(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len)
{
	de_byte id3_encoding;
	de_int64 pos = pos1;
	de_ucstring *lang = NULL;
	de_ucstring *shortdesc = NULL;
	de_ucstring *comment_text = NULL;
	de_int64 bytes_consumed;
	int ret;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, get_textenc_name(d, id3_encoding));

	lang = ucstring_create(c);
	dbuf_read_to_ucstring(f, pos, 3, lang, 0, DE_ENCODING_ASCII);
	de_dbg(c, "language: \"%s\"", ucstring_get_printable_sz(lang));
	pos += 3;

	shortdesc = ucstring_create(c);
	bytes_consumed = 0;
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding, shortdesc, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "short description: \"%s\"", ucstring_get_printable_sz(shortdesc));
	pos += bytes_consumed;

	comment_text = ucstring_create(c);
	id3v2_read_to_ucstring(c, f, pos, pos1+len-pos, comment_text, id3_encoding);
	de_dbg(c, "comment: \"%s\"", ucstring_get_printable_sz(comment_text));

done:
	ucstring_destroy(lang);
	ucstring_destroy(shortdesc);
	ucstring_destroy(comment_text);
}

static void decode_id3v2_frame_pic_apic(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
{
	de_byte id3_encoding;
	de_byte picture_type;
	de_int64 pos = pos1;
	struct de_stringreaderdata *fmt_srd = NULL;
	de_ucstring *mimetype = NULL;
	de_ucstring *description = NULL;
	de_int64 bytes_consumed = 0;
	int ret;
	const char *ext;
	de_byte sig[2];

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, get_textenc_name(d, id3_encoding));

	if(tag4cc->id==CODE_PIC) {
		fmt_srd = dbuf_read_string(f, pos, 3, 3, 0, DE_ENCODING_ASCII);
		de_dbg(c, "format: \"%s\"", ucstring_get_printable_sz(fmt_srd->str));
		pos += 3;
	}
	else {
		mimetype = ucstring_create(c);
		ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
			mimetype, &bytes_consumed);
		if(!ret) goto done;
		de_dbg(c, "mime type: \"%s\"", ucstring_get_printable_sz(mimetype));
		pos += bytes_consumed;
	}

	picture_type = dbuf_getbyte(f, pos++);
	de_dbg(c, "picture type: 0x%02x", (unsigned int)picture_type);

	description = ucstring_create(c);
	// "The description has a maximum length of 64 characters" [we'll allow more]
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_get_printable_sz(description));
	pos += bytes_consumed;

	if(pos >= pos1+len) goto done;

	dbuf_read(f, sig, pos, 2);
	if(sig[0]==0x89 && sig[1]==0x50) ext="id3pic.png";
	else if(sig[0]==0xff && sig[1]==0xd8) ext="id3pic.jpg";
	else ext="id3pic.bin";
	dbuf_create_file_from_slice(f, pos, pos1+len-pos, ext, NULL, DE_CREATEFLAG_IS_AUX);

done:
	de_destroy_stringreaderdata(c, fmt_srd);
	ucstring_destroy(mimetype);
	ucstring_destroy(description);
}

static void decode_id3v2_frame_geob(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len)
{
	de_byte id3_encoding;
	de_int64 pos = pos1;
	de_ucstring *mimetype = NULL;
	de_ucstring *filename = NULL;
	de_ucstring *description = NULL;
	de_int64 bytes_consumed = 0;
	int ret;
	de_int64 objlen;

	id3_encoding = dbuf_getbyte(f, pos++);
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, get_textenc_name(d, id3_encoding));

	mimetype = ucstring_create(c);
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
		mimetype, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "mime type: \"%s\"", ucstring_get_printable_sz(mimetype));
	pos += bytes_consumed;

	filename = ucstring_create(c);
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		filename, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "filename: \"%s\"", ucstring_get_printable_sz(filename));
	pos += bytes_consumed;

	description = ucstring_create(c);
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, id3_encoding,
		description, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "description: \"%s\"", ucstring_get_printable_sz(description));
	pos += bytes_consumed;

	objlen = pos1+len-pos;
	if(objlen<1) goto done;

	de_dbg(c, "[%d bytes of encapsulated object data]", (int)objlen);

	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(f, pos, objlen, "encobj.bin",
			NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(c->debug_level>=2) {
		de_int64 dumplen = objlen;
		if(dumplen>256) dumplen=256;
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, f, pos, dumplen, "data", 0x1);
		de_dbg_indent(c, -1);
	}

done:
	ucstring_destroy(mimetype);
	ucstring_destroy(filename);
	ucstring_destroy(description);
}

// Popularimeter
static void decode_id3v2_frame_pop_popm(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len)
{
	de_int64 bytes_consumed = 0;
	de_ucstring *email = NULL;
	de_int64 pos = pos1;
	int rating;
	int ret;

	email = ucstring_create(c);
	ret = read_terminated_string(c, d, f, pos, pos1+len-pos, 256, ID3ENC_ISO_8859_1,
		email, &bytes_consumed);
	if(!ret) goto done;
	de_dbg(c, "email/id: \"%s\"", ucstring_get_printable_sz(email));
	pos += bytes_consumed;

	if(pos1+len-pos < 1) goto done;
	rating = (int)dbuf_getbyte(f, pos++);
	de_dbg(c, "rating: %d%s", rating, (rating==0)?" (unknown)":"/255");

	// TODO: There can be a "counter" field here.

done:
	ucstring_destroy(email);
}

static void decode_id3v2_frame_internal(deark *c, lctx *d, dbuf *f,
	de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
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

static void decode_id3v2_frame(deark *c, lctx *d, dbuf *f,
	de_int64 pos1, de_int64 len,
	struct de_fourcc *tag4cc, unsigned int flags1, unsigned int flags2)
{
	de_byte frame_level_unsynch = d->global_frame_level_unsync;
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

static const char *get_frame_name(lctx *d, de_uint32 id)
{
	struct frame_list_entry {
		de_uint32 threecc, fourcc;
		const char *name;
	};
	static const struct frame_list_entry frame_list[] = {
		// This is a partial list, of some of the common frame types.
		{0x54414c00U, 0x54414c42U, "Album/Movie/Show title"},
		{CODE_PIC,    CODE_APIC,   "Attached picture"},
		{0x54503200U, 0x54504532U, "Band/orchestra/accompaniment"},
		{0x54425000U, 0x5442504dU, "Beats per minute"},
		{CODE_COM,    CODE_COMM,   "Comments"},
		{0x57434d00U, 0x57434f4dU, "Commercial information"},
		{0x54434d00U, 0x54434f4dU, "Composer"},
		{0x54503300U, 0x54504533U, "Conductor"},
		{0x54434f00U, 0x54434f4eU, "Content type"},
		{0x54435200U, 0x54434f50U, "Copyright message"},
		{0x54444100U, 0x54444154U, "Date"},
		{0x54454e00U, 0x54454e43U, "Encoded by"},
		{CODE_GEO,    CODE_GEOB,   "General encapsulated object"},
		{0x544b4500U, 0x544b4559U, "Initial key"},
		{0x544c4100U, 0x544c414eU, "Language"},
		{0x54503100U, 0,           "Lead artist/Performing group"},
		{0,           0x54504531U, "Lead performer"},
		{0x544c4500U, 0x544c454eU, "Length"},
		{0x54585400U, 0x54455854U, "Lyricist"},
		{0x4d434900U, 0x4d434449U, "Music CD identifier"},
		{0x57415200U, 0x574f4152U, "Official artist/performer webpage"},
		{0x57414600U, 0x574f4146U, "Official audio file webpage"},
		{0x57415300U, 0x574f4153U, "Official audio source webpage"},
		{0x544f5400U, 0x544f414cU, "Original album/movie/show title"},
		{0x544f4100U, 0x544f5045U, "Original artist/performer"},
		{0x544f4c00U, 0x544f4c59U, "Original lyricist"},
		{CODE_POP,    CODE_POPM,   "Popularimeter"},
		{0,           CODE_PRIV,   "Private frame"},
		{0x54504200U, 0x54505542U, "Publisher"},
		{0,           0x54445243U, "Recording time"},
		{0x52564100U, 0x52564144U, "Relative volume adjustment"},
		{0x54535300U, 0x54535345U, "Software/Hardware and settings used for encoding"},
		{0x54494d00U, 0x54494d45U, "Time"},
		{0x54543200U, 0x54495432U, "Title"},
		{0x54524b00U, 0x5452434bU, "Track number"},
		{0x554c5400U, 0x55534c54U, "Unsychronized lyric transcription"},
		{CODE_TXX,    CODE_TXXX,   "User defined text information"},
		{CODE_WXX,    CODE_WXXX,   "User defined URL link"},
		{0x54594500U, 0x54594552U, "Year"}
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

static void do_id3v2_frames(deark *c, lctx *d,
	dbuf *f, de_int64 pos1, de_int64 len, de_int64 orig_pos)
{
	de_int64 pos = pos1;
	struct de_fourcc tag4cc;
	int saved_indent_level;
	de_int64 frame_idx = 0;
	de_int64 frame_header_len;

	de_memset(&tag4cc, 0, sizeof(struct de_fourcc));
	if(d->version_code<=2) frame_header_len = 6;
	else frame_header_len = 10;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "ID3v2 frames at %d", (int)orig_pos);
	de_dbg_indent(c, 1);

	while(1) {
		de_int64 frame_dlen;
		de_byte flags1, flags2;
		de_byte b;
		char *flg2name;

		if(pos+frame_header_len > pos1+len) break;

		// Peek at the next byte
		b = dbuf_getbyte(f, pos);
		if(b==0x00) {
			de_dbg(c, "[found padding]");
			break;
		}

		de_dbg(c, "frame #%d", (int)frame_idx);
		de_dbg_indent(c, 1);

		if(d->version_code<=2) {
			// Version 2.2.x uses a "THREECC".
			dbuf_read(f, tag4cc.bytes, pos, 3);
			tag4cc.id = (tag4cc.bytes[0]<<24)|(tag4cc.bytes[1]<<16)|(tag4cc.bytes[2]<<8);
			de_bytes_to_printable_sz(tag4cc.bytes, 3,
				tag4cc.id_printable, sizeof(tag4cc.id_printable),
				0, DE_ENCODING_ASCII);
			pos += 3;
		}
		else {
			dbuf_read_fourcc(f, pos, &tag4cc, 0);
			pos += 4;
		}

		de_dbg(c, "tag: '%s' (%s)", tag4cc.id_printable,
			get_frame_name(d, tag4cc.id));

		if(d->version_code<=2) {
			frame_dlen = get_ui24be(f, pos);
			pos += 3;
		}
		else if(d->version_code==3) {
			frame_dlen = dbuf_getui32be(f, pos);
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
			else flg2name = "format description";
			de_dbg(c, "flags: status messages=0x%02x, %s=0x%02x",
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

static void de_run_id3v2(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *unescaped_data = NULL;
	de_int64 ext_header_size = 0;

	d = de_malloc(c, sizeof(lctx));
	if(!do_id3v2_header(c, c->infile, d)) goto done;
	if(!d->has_id3v2) goto done;

	if(d->has_ext_header) {
		if(d->version_code!=4) {
			de_warn(c, "extended header not supported");
			goto done; // TODO
		}
		de_dbg(c, "ID3v2 extended header at %d", (int)d->data_start);
		ext_header_size = get_synchsafe_int(c->infile, d->data_start);
		de_dbg_indent(c, 1);
		de_dbg(c, "extended header size: %d", (int)ext_header_size);
		de_dbg_indent(c, -1);
		if(ext_header_size > d->data_len) goto done;
	}

	if(d->global_level_unsync) {
		unescaped_data = dbuf_create_membuf(c, 0, 0);
		unescape_id3v2_data(c, c->infile, d->data_start,
			d->data_len, unescaped_data);
	}
	else {
		unescaped_data = dbuf_open_input_subfile(c->infile,
			d->data_start + ext_header_size,
			d->data_len - ext_header_size);
	}

	do_id3v2_frames(c, d, unescaped_data, 0, unescaped_data->len,
		d->data_start + ext_header_size);

done:
	dbuf_close(unescaped_data);
	de_free(c, d);
}

static int de_identify_id3v2(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "ID3", 3))
		return 45;
	return 0;
}

void de_module_id3v2(deark *c, struct deark_module_info *mi)
{
	mi->id = "id3v2";
	mi->desc = "ID3v2 metadata";
	mi->run_fn = de_run_id3v2;
	mi->identify_fn = de_identify_id3v2;
}
