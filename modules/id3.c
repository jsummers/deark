// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ID3v2 metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_id3v2);

#define CODE_TXXX 0x54585858U
#define CODE_TXX  0x54585800U

struct id3v2_ctx {
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
};

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

// Read 10-byte main ID3v2 header
static int do_id3v2_header(deark *c, dbuf *f, struct id3v2_ctx *dd)
{
	de_int64 pos;
	de_byte flags;
	int retval = 0;
	int has_global_compression = 0;

	pos = 0;

	de_dbg(c, "ID3v2 header at %d", (int)pos);
	de_dbg_indent(c, 1);

	// TODO: Verify signature
	dd->has_id3v2 = 1;

	pos += 3; // ID3v2 file identifier
	dd->version_code = dbuf_getbyte(f, pos++);
	dd->ver_revision = dbuf_getbyte(f, pos++);
	de_dbg(c, "ID3v2 version: (2.)%d.%d", (int)dd->version_code, (int)dd->ver_revision);
	if(dd->version_code<2 || dd->version_code>4) {
		de_warn(c, "Unsupported ID3v2 version: (2.)%d.x", (int)dd->version_code);
		goto done;
	}

	flags = dbuf_getbyte(f, pos++);
	de_dbg(c, "flags: 0x%02x", (unsigned int)flags);
	de_dbg_indent(c, 1);

	if(dd->version_code<=3) {
		dd->global_level_unsync = (flags&0x80)?1:0;
		de_dbg(c, "global-level unsynchronisation: %d", (int)dd->global_level_unsync);
	}
	else if(dd->version_code==4) {
		dd->global_frame_level_unsync = (flags&0x80)?1:0;
		de_dbg(c, "all frames use unsynchronisation: %d", (int)dd->global_frame_level_unsync);
	}

	if(dd->version_code==2) {
		has_global_compression = (flags&0x40)?1:0;
		de_dbg(c, "uses compression: %d", dd->has_ext_header);
	}
	else if(dd->version_code>=3) {
		dd->has_ext_header = (flags&0x40)?1:0;
		de_dbg(c, "has extended header: %d", dd->has_ext_header);
	}

	if(dd->version_code>=3) {
		dd->is_experimental = (flags&0x20)?1:0;
		de_dbg(c, "is experimental: %d", dd->is_experimental);
	}

	if(dd->version_code >= 4) {
		dd->has_footer = (flags&0x10)?1:0;
		de_dbg(c, "has footer: %d", dd->has_footer);
	}

	de_dbg_indent(c, -1);

	dd->data_len = get_synchsafe_int(f, pos);
	de_dbg(c, "size: %d", (int)dd->data_len);
	pos += 4;

	dd->data_start = 10;

	dd->total_len = dd->data_start + dd->data_len;
	if(dd->has_footer) dd->total_len += 10;

	de_dbg(c, "calculated end of ID3v2 data: %d", (int)dd->total_len);

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

	while(srcpos<inf_start+inf_len) {
		b0 = dbuf_getbyte(inf, srcpos++);
		if(b0==0xff && srcpos<(inf_start+inf_len-1) && dbuf_getbyte(inf, srcpos)==0x00) {
			srcpos++;
		}
		dbuf_writebyte(outf, b0);
	}

	de_dbg(c, "unescaped %d bytes to %d bytes", (int)inf_len, (int)outf->len);
}


static void decode_id3v2_text_frame(deark *c, dbuf *f, de_int64 pos1, de_int64 len,
	struct de_fourcc *tag4cc)
{
	de_byte id3_encoding;
	de_ucstring *s = NULL;
	de_int64 pos = pos1;
	int encoding_to_use = DE_ENCODING_UNKNOWN;
	const char *encname;

	if(len<1) goto done;
	s = ucstring_create(c);
	id3_encoding = dbuf_getbyte(f, pos++);
	switch(id3_encoding) {
	case 0: encname = "ISO-8859-1"; break;
	case 1: encname = "UTF-16 w/BOM"; break;
	case 2: encname = "UTF-16BE"; break;
	case 3: encname = "UTF-8"; break;
	default: encname = "?";
	}
	de_dbg(c, "text encoding: %d (%s)", (int)id3_encoding, encname);

	if(id3_encoding==0x00) { // ISO-8859-1
		encoding_to_use = DE_ENCODING_LATIN1;
	}
	else if(id3_encoding==0x01) { // UTF-16 with BOM
		de_uint32 bom_id;
		if(pos+2 <= pos1+len) {
			bom_id = (de_uint32)dbuf_getui16be(f, pos);
			pos += 2;
			if(bom_id==0xfeff) {
				encoding_to_use = DE_ENCODING_UTF16BE;
			}
			else if(bom_id==0xfffe) {
				encoding_to_use = DE_ENCODING_UTF16LE;
			}
		}
	}
	else if(id3_encoding==0x02) { // UTF-16BE
		encoding_to_use = DE_ENCODING_UTF16BE;
	}
	else if(id3_encoding==0x03) { // UTF-8
		encoding_to_use = DE_ENCODING_UTF8;
	}
	else {
		de_dbg(c, "text: [unsupported encoding]");
		goto done;
	}

	dbuf_read_to_ucstring_n(f, pos, pos1+len-pos, DE_DBG_MAX_STRLEN, s, 0, encoding_to_use);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "text: \"%s\"", ucstring_get_printable_sz(s));

done:
	ucstring_destroy(s);
}

static void decode_id3v2_frame_internal(deark *c, struct id3v2_ctx *dd, dbuf *f,
	de_int64 pos1, de_int64 len, struct de_fourcc *tag4cc)
{
	// "All text frame identifiers begin with "T". Only text frame identifiers
	// begin with "T", with the exception of the "TXXX" frame."
	if(dd->version_code==2) {
		if(tag4cc->bytes[0]=='T' && tag4cc->id!=CODE_TXX) {
			decode_id3v2_text_frame(c, f, pos1, len, tag4cc);
		}
	}
	else if(dd->version_code>=3) {
		if(tag4cc->bytes[0]=='T' && tag4cc->id!=CODE_TXXX) {
			decode_id3v2_text_frame(c, f, pos1, len, tag4cc);
		}
	}
}

static void decode_id3v2_frame(deark *c, struct id3v2_ctx *dd, dbuf *f,
	de_int64 pos1, de_int64 len,
	struct de_fourcc *tag4cc, unsigned int flags1, unsigned int flags2)
{
	de_byte frame_level_unsynch = dd->global_frame_level_unsync;
	dbuf *unescaped_frame = NULL;

	if(dd->version_code==3) {
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
	if(dd->version_code==4) {
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
		decode_id3v2_frame_internal(c, dd, unescaped_frame, 0, unescaped_frame->len, tag4cc);
	}
	else {
		decode_id3v2_frame_internal(c, dd, f, pos1, len, tag4cc);
	}

done:
	dbuf_close(unescaped_frame);
}

static void do_id3v2_frames(deark *c, struct id3v2_ctx *dd,
	dbuf *f, de_int64 pos1, de_int64 len, de_int64 orig_pos)
{
	de_int64 pos = pos1;
	struct de_fourcc tag4cc;
	int saved_indent_level;
	de_int64 frame_idx = 0;
	de_int64 frame_header_len;

	de_memset(&tag4cc, 0, sizeof(struct de_fourcc));
	if(dd->version_code<=2) frame_header_len = 6;
	else frame_header_len = 10;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "ID3v2 frames at %d", (int)orig_pos);
	de_dbg_indent(c, 1);

	while(1) {
		de_int64 frame_dlen;
		de_byte flags1, flags2;
		de_byte b;
		char *flgname;

		if(pos+frame_header_len > pos1+len) break;

		// Peek at the next byte
		b = dbuf_getbyte(f, pos);
		if(b==0x00) {
			de_dbg(c, "[found padding]");
			break;
		}

		de_dbg(c, "frame #%d", (int)frame_idx);
		de_dbg_indent(c, 1);

		if(dd->version_code<=2) {
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

		de_dbg(c, "tag: '%s'", tag4cc.id_printable);

		if(dd->version_code<=2) {
			frame_dlen = get_ui24be(f, pos);
			pos += 3;
		}
		else if(dd->version_code==3) {
			frame_dlen = dbuf_getui32be(f, pos);
			pos += 4;
		}
		else {
			frame_dlen = get_synchsafe_int(f, pos);
			pos += 4;
		}
		de_dbg(c, "size: %d", (int)frame_dlen);

		if(dd->version_code<=2) {
			flags1 = 0;
			flags2 = 0;
		}
		else {
			flags1 = dbuf_getbyte(f, pos++);
			de_dbg(c, "status messages flags: 0x%02x", (unsigned int)flags1);

			flags2 = dbuf_getbyte(f, pos++);
			if(dd->version_code<=3) flgname = "encoding";
			else flgname = "format description";
			de_dbg(c, "%s flags: 0x%02x", flgname, (unsigned int)flags2);
		}

		if(pos+frame_dlen > pos1+len) goto done;
		decode_id3v2_frame(c, dd, f, pos, frame_dlen, &tag4cc, flags1, flags2);

		pos += frame_dlen;
		frame_idx++;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_id3v2(deark *c, de_module_params *mparams)
{
	struct id3v2_ctx *dd = NULL;
	dbuf *unescaped_data = NULL;
	de_int64 ext_header_size = 0;

	dd = de_malloc(c, sizeof(struct id3v2_ctx));
	if(!do_id3v2_header(c, c->infile, dd)) goto done;
	if(!dd->has_id3v2) goto done;

	if(dd->has_ext_header) {
		if(dd->version_code!=4) {
			de_warn(c, "extended header not supported");
			goto done; // TODO
		}
		de_dbg(c, "ID3v2 extended header at %d", (int)dd->data_start);
		ext_header_size = get_synchsafe_int(c->infile, dd->data_start);
		de_dbg_indent(c, 1);
		de_dbg(c, "extended header size: %d", (int)ext_header_size);
		de_dbg_indent(c, -1);
		if(ext_header_size > dd->data_len) goto done;
	}

	if(dd->global_level_unsync) {
		unescaped_data = dbuf_create_membuf(c, 0, 0);
		unescape_id3v2_data(c, c->infile, dd->data_start,
			dd->data_len, unescaped_data);
	}
	else {
		unescaped_data = dbuf_open_input_subfile(c->infile,
			dd->data_start + ext_header_size,
			dd->data_len - ext_header_size);
	}

	do_id3v2_frames(c, dd, unescaped_data, 0, unescaped_data->len,
		dd->data_start + ext_header_size);

done:
	dbuf_close(unescaped_data);
	de_free(c, dd);
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
