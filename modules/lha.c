// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// LHA/LZH compressed archive format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_lha);

struct member_data {
	de_byte hlev; // header level
	de_int64 total_size;
	struct de_stringreaderdata *cmpr_method;
	int is_dir;
	de_int64 orig_size;
	de_uint32 crc16;
	de_byte os_id;
};

typedef struct localctx_struct {
	int reserved;
} lctx;

struct exthdr_type_info_struct;

typedef void (*exthdr_decoder_fn)(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen);

struct exthdr_type_info_struct {
	de_byte id;
	de_byte flags;
	const char *name;
	exthdr_decoder_fn decoder_fn;
};

static void read_msdos_datetime(deark *c, lctx *d, struct member_data *md,
	de_int64 pos, const char *name)
{
	de_int64 mod_time_raw, mod_date_raw;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	mod_time_raw = de_getui16le(pos);
	mod_date_raw = de_getui16le(pos+2);
	de_dos_datetime_to_timestamp(&tmp_timestamp, mod_date_raw, mod_time_raw, 0);
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s\n", name, timestamp_buf);
}

static void read_unix_timestamp(deark *c, lctx *d, struct member_data *md,
	de_int64 pos, const char *name)
{
	de_int64 t;
	char timestamp_buf[64];
	struct de_timestamp tmp_timestamp;

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, &tmp_timestamp);
	de_timestamp_to_string(&tmp_timestamp, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "%s: %d (%s)\n", name, (int)t, timestamp_buf);
}

static void read_filename(deark *c, lctx *d, struct member_data *md,
	de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len,
		s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_destroy(s);
}

static void exthdr_filename(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	read_filename(c, d, md, pos, dlen);
}

static void exthdr_dirname(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	// TODO: The path delimiter in this field is 0xff. It's not clear what we
	// ought to do about that, if anything.

	if(dlen>=1) {
		// This field is expected to end with 0xff. If that is the case, we'll
		// ignore the last byte.
		de_byte lastbyte;
		lastbyte = de_getbyte(pos+dlen-1);
		if(lastbyte==0xff) {
			dlen--;
		}
	}

	dbuf_read_to_ucstring(c->infile, pos, dlen,
		s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "dir name: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_destroy(s);
}

static void exthdr_filesize(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	// TODO: Support this
	de_warn(c, "Unsupported \"file size\" extended header found. This may prevent "
		"the rest of the file from being processed correctly.\n");
}

static void exthdr_unixperms(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	de_int64 mode;

	if(dlen<2) return;
	mode = de_getui16le(pos);
	de_dbg(c, "mode: octal(%06o)\n", (unsigned int)mode);
}

static void exthdr_unixuidgid(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	de_int64 uid, gid;
	if(dlen<4) return;

	// It's strange that the GID comes first, while the UID comes first in the
	// level-0 "extended area".
	gid = de_getui16le(pos);
	de_dbg(c, "gid: %d\n", (int)gid);
	uid = de_getui16le(pos+2);
	de_dbg(c, "uid: %d\n", (int)uid);
}

static void exthdr_unixtimestamp(deark *c, lctx *d, struct member_data *md,
	de_byte id, const struct exthdr_type_info_struct *e,
	de_int64 pos, de_int64 dlen)
{
	if(dlen<4) return;
	read_unix_timestamp(c, d, md, pos, "last-modified");
}

static const struct exthdr_type_info_struct exthdr_type_info_arr[] = {
	{ 0x00, 0, "common/CRC", NULL },
	{ 0x01, 0, "filename", exthdr_filename },
	{ 0x02, 0, "dir name", exthdr_dirname },
	{ 0x39, 0, "multi-disc", NULL },
	{ 0x3f, 0, "comment", NULL },
	{ 0x40, 0, "MS-DOS file attribs", NULL },
	{ 0x41, 0, "Windows timestamp", NULL },
	{ 0x42, 0, "MS-DOS file size", exthdr_filesize },
	{ 0x50, 0, "Unix perms", exthdr_unixperms },
	{ 0x51, 0, "Unix UID/GID", exthdr_unixuidgid },
	{ 0x52, 0, "Unix group name", NULL },
	{ 0x53, 0, "Unix username", NULL },
	{ 0x54, 0, "Unix timestamp", exthdr_unixtimestamp },
	{ 0x7d, 0, "capsule", NULL },
	{ 0x7e, 0, "OS/2 extended attribs", NULL },
	{ 0x7f, 0, "level 3 new attribs type-1", NULL },
	{ 0xff, 0, "level 3 new attribs type-2", NULL }
};

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	de_destroy_stringreaderdata(c, md->cmpr_method);
	de_free(c, md);
}

static const struct exthdr_type_info_struct *get_exthdr_type_info(de_byte id)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(exthdr_type_info_arr); i++) {
		if(id == exthdr_type_info_arr[i].id) {
			return &exthdr_type_info_arr[i];
		}
	}
	return NULL;
}

static void do_read_ext_header(deark *c, lctx *d, struct member_data *md,
	de_int64 pos1, de_int64 len, de_int64 dlen)
{
	de_byte id = 0;
	const char *name;
	const struct exthdr_type_info_struct *e = NULL;

	if(dlen>=1) {
		id = de_getbyte(pos1);
		e = get_exthdr_type_info(id);
	}
	name = e ? e->name : "?";

	de_dbg(c, "ext header at %d, len=%d (1+%d+%d), id=0x%02x (%s)\n", (int)pos1, (int)len,
		(int)(dlen-1), (int)(len-dlen), (unsigned int)id, name);

	if(dlen<1) return; // Invalid header, too short to even have an id field

	if(e && e->decoder_fn) {
		de_dbg_indent(c, 1);
		e->decoder_fn(c, d, md, id, e, pos1+1, dlen-1);
		de_dbg_indent(c, -1);
	}
}

static void do_lev0_ext_area(deark *c, lctx *d, struct member_data *md,
	de_int64 pos1, de_int64 len)
{
	if(len<1) return;
	md->os_id = de_getbyte(pos1);
	de_dbg(c, "OS id: %d ('%c')\n", (int)md->os_id,
		de_byte_to_printable_char(md->os_id));

	// TODO: Finish this
	if(md->os_id=='U') {
		de_int64 mode;
		de_int64 uid, gid;

		if(len<12) goto done;

		read_unix_timestamp(c, d, md, pos1+2, "last-modified");

		mode = de_getui16le(pos1+6);
		de_dbg(c, "mode: octal(%06o)\n", (unsigned int)mode);

		uid = de_getui16le(pos1+8);
		de_dbg(c, "uid: %d\n", (int)uid);
		gid = de_getui16le(pos1+10);
		de_dbg(c, "gid: %d\n", (int)gid);
	}

done: ;
}

// AFAICT, we're expected to think of the extended headers as a kind of linked
// list. The last field in each node is the "size of next node" (instead of
// "pointer to next node", as a real linked list would have). A size of 0 is
// like a "nil" pointer, and marks the end of the list.
// The "size of the first node" field (analogous to the "head" pointer) is
// conceptually not part of the extended headers section.
//
// Note that if we simply shift our frame of reference, this format is identical
// to a more typical length-prefixed format. But our code follows the
// linked-list model, to make it more consistent with most LHA documentation,
// and the various "size" fields.
//
// A return value of 0 means we failed to calculate the size of the
// extended headers segment.
static int do_read_ext_headers(deark *c, lctx *d, struct member_data *md,
	de_int64 pos1, de_int64 len, de_int64 first_ext_hdr_size, de_int64 *tot_bytes_consumed)
{
	de_int64 pos = pos1;
	de_int64 this_ext_hdr_size, next_ext_hdr_size;
	int retval = 0;
	de_int64 size_of_size_field;

	*tot_bytes_consumed = 0;

	if(first_ext_hdr_size==0) {
		return 1;
	}

	de_dbg(c, "ext headers section at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	size_of_size_field = (md->hlev==3) ? 4 : 2;

	next_ext_hdr_size = first_ext_hdr_size;
	while(1) {
		this_ext_hdr_size = next_ext_hdr_size;
		if(this_ext_hdr_size==0) {
			retval = 1;
			*tot_bytes_consumed = pos - pos1;
			goto done;
		}
		if(this_ext_hdr_size<size_of_size_field) goto done;
		if(pos+this_ext_hdr_size > pos1+len) goto done;

		do_read_ext_header(c, d, md, pos, this_ext_hdr_size, this_ext_hdr_size-size_of_size_field);

		// Each ext header ends with a "size of next header" field.
		// We'll read it at this level, instead of in do_read_ext_header().
		pos += this_ext_hdr_size-size_of_size_field;
		if(size_of_size_field==2) {
			next_ext_hdr_size = de_getui16le(pos);
		}
		else {
			next_ext_hdr_size = de_getui32le(pos);
		}
		pos += size_of_size_field;
	}

done:
	if(retval) {
		de_dbg(c, "size of ext headers section: %d\n", (int)*tot_bytes_consumed);
	}
	de_dbg_indent(c, -1);
	return retval;
}

// This single function parses all the different header formats, using lots of
// "if" statements. It is messy, but it's a no-win situation.
// The alternative of four separate functions would be have a lot of redundant
// code, and be harder to maintain.
//
// Caller allocates and initializes md.
static int do_read_member(deark *c, lctx *d, struct member_data *md, de_int64 pos1)
{
	int retval = 0;
	de_int64 lev0_header_size = 0;
	de_int64 lev1_base_header_size = 0;
	de_int64 lev1_skip_size = 0;
	de_int64 lev2_total_header_size = 0;
	de_int64 lev3_header_size = 0;
	de_int64 pos = pos1;
	de_int64 exthdr_bytes_consumed = 0;
	de_int64 fnlen = 0;
	de_int64 compressed_data_pos = 0; // relative to beginning of file
	de_int64 compressed_data_len = 0;
	int ret;

	if(c->infile->len - pos1 < 21) {
		goto done;
	}

	de_dbg(c, "member at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	// Look ahead to figure out the header format version.
	// This byte was originally the high byte of the "MS-DOS file attribute" field,
	// which happened to always be zero.
	// In later LHA versions, it is overloaded to identify the header format
	// version (called "header level" in LHA jargon).
	md->hlev = de_getbyte(pos+20);
	de_dbg(c, "header level: %d\n", (int)md->hlev);
	if(md->hlev>3) {
		de_err(c, "Invalid or unsupported header level: %d\n", (int)md->hlev);
		goto done;
	}

	if(md->hlev==0) {
		lev0_header_size = (de_int64)de_getbyte(pos);
		de_dbg(c, "header size: (2+)%d\n", (int)lev0_header_size);
		pos++;
		pos++; // Cksum
	}
	else if(md->hlev==1) {
		lev1_base_header_size = (de_int64)de_getbyte(pos);
		de_dbg(c, "base header size: %d\n", (int)lev1_base_header_size);
		pos++;
		pos++; // Cksum
	}
	else if(md->hlev==2) {
		lev2_total_header_size = de_getui16le(pos);
		de_dbg(c, "total header size: %d\n", (int)lev2_total_header_size);
		pos += 2;
	}
	else if(md->hlev==3) {
		de_int64 lev3_word_size;
		lev3_word_size = de_getui16le(pos);
		de_dbg(c, "word size: %d\n", (int)lev3_word_size);
		pos += 2;
		if(lev3_word_size!=4) {
			de_err(c, "Unsupported word size: %d\n", (int)lev3_word_size);
			goto done;
		}
	}

	md->cmpr_method = dbuf_read_string(c->infile, pos, 5, 5, 0, DE_ENCODING_ASCII);
	de_dbg(c, "cmpr method: \"%s\"\n", ucstring_get_printable_sz(md->cmpr_method->str));
	pos+=5;

	if(!de_strcmp("-lhd-", (const char*)md->cmpr_method->sz)) {
		md->is_dir = 1;
	}

	if(md->hlev==1) {
		// lev1_skip_size is the distance from the third byte of the extended
		// header section, to the end of the compressed data.
		lev1_skip_size = de_getui32le(pos);
		de_dbg(c, "skip size: %u\n", (unsigned int)lev1_skip_size);
		pos += 4;
		md->total_size = 2 + lev1_base_header_size + lev1_skip_size;
	}
	else {
		compressed_data_len = de_getui32le(pos);
		de_dbg(c, "compressed size: %u\n", (unsigned int)compressed_data_len);
		pos += 4;

		if(md->hlev==0) {
			md->total_size = 2 + lev0_header_size + compressed_data_len;
		}
		else if(md->hlev==2) {
			md->total_size = lev2_total_header_size + compressed_data_len;
		}
	}

	md->orig_size = de_getui32le(pos);
	de_dbg(c, "original size: %u\n", (unsigned int)md->orig_size);
	pos += 4;

	if(md->hlev==0 || md->hlev==1) {
		read_msdos_datetime(c, d, md, pos, "late-modified");
		pos += 4; // modification time/date (MS-DOS)
	}
	else if(md->hlev==2 || md->hlev==3) {
		read_unix_timestamp(c, d, md, pos, "late-modified");
		pos += 4; // Unix time
	}

	if(md->hlev==0) {
		pos += 2; // MS-DOS file attributes
	}
	else if(md->hlev==1 || md->hlev==2 || md->hlev==3) {
		pos++; // reserved
		pos++; // header level
	}

	if(md->hlev<=1) {
		fnlen = de_getbyte(pos++);
		de_dbg(c, "filename len: %d\n", (int)fnlen);
		read_filename(c, d, md, pos, fnlen);
		pos += fnlen;
	}

	md->crc16 = (de_uint32)de_getui16le(pos);
	de_dbg(c, "crc16 (reported): 0x%04x\n", (unsigned int)md->crc16);
	pos += 2; // CRC16

	if(md->hlev==1 || md->hlev==2 || md->hlev==3) {
		md->os_id = de_getbyte(pos++);
		de_dbg(c, "OS id: %d ('%c')\n", (int)md->os_id,
			de_byte_to_printable_char(md->os_id));
	}

	if(md->hlev==3) {
		lev3_header_size = de_getui32le(pos);
		pos += 4;
		md->total_size = lev3_header_size + compressed_data_len;
	}

	if(md->hlev==0) {
		de_int64 ext_headers_size = (2+lev0_header_size) - (pos-pos1);
		compressed_data_pos = pos1 + 2 + lev0_header_size;
		if(ext_headers_size>0) {
			de_dbg(c, "extended header area at %d, len=%d\n", (int)pos, (int)ext_headers_size);
			de_dbg_indent(c, 1);
			do_lev0_ext_area(c, d, md, pos, ext_headers_size);
			de_dbg_indent(c, -1);
		}
	}
	else if(md->hlev==1) {
		de_int64 first_ext_hdr_size;

		// The last two bytes of the base header are the size of the first ext. header.
		pos = pos1 + 2 + lev1_base_header_size - 2;
		// TODO: sanitize pos?
		first_ext_hdr_size = de_getui16le(pos);
		de_dbg(c, "first ext hdr size: %d\n", (int)first_ext_hdr_size);
		pos += 2;

		ret = do_read_ext_headers(c, d, md, pos, lev1_skip_size, first_ext_hdr_size,
			&exthdr_bytes_consumed);

		if(!ret) {
			de_err(c, "Error parsing extended headers at %d. Cannot extract this file.\n",
				(int)pos);
			retval = 1;
			goto done;
		}

		pos += exthdr_bytes_consumed;
		compressed_data_pos = pos;
		compressed_data_len = lev1_skip_size - exthdr_bytes_consumed;
	}
	else if(md->hlev==2) {
		de_int64 first_ext_hdr_size;

		compressed_data_pos = pos1+lev2_total_header_size;

		first_ext_hdr_size = de_getui16le(pos);
		de_dbg(c, "first ext hdr size: %d\n", (int)first_ext_hdr_size);
		pos += 2;

		do_read_ext_headers(c, d, md, pos, pos1+lev2_total_header_size-pos,
			first_ext_hdr_size, &exthdr_bytes_consumed);
	}
	else if(md->hlev==3) {
		de_int64 first_ext_hdr_size;

		compressed_data_pos = pos1+lev3_header_size;

		first_ext_hdr_size = de_getui32le(pos);
		de_dbg(c, "first ext hdr size: %d\n", (int)first_ext_hdr_size);
		pos += 4;

		do_read_ext_headers(c, d, md, pos, pos1+lev3_header_size-pos,
			first_ext_hdr_size, &exthdr_bytes_consumed);
	}

	de_dbg(c, "compressed member data at %d, len=%d\n",
		(int)compressed_data_pos, (int)compressed_data_len);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_lha(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	struct member_data *md = NULL;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	while(1) {
		if(pos >= c->infile->len) break;

		md = de_malloc(c, sizeof(struct member_data));
		if(!do_read_member(c, d, md, pos)) goto done;
		if(md->total_size<1) goto done;

		pos += md->total_size;

		destroy_member_data(c, md);
		md = NULL;
	}

done:
	destroy_member_data(c, md);
	de_free(c, d);
}

static int de_identify_lha(deark *c)
{
	de_byte b[7];

	de_read(b, 0, 7);

	if(b[2]=='-' && b[3]=='l' && b[6]=='-' && (b[4]=='h' || b[4]=='z')) {
		return 100;
	}
	return 0;
}

void de_module_lha(deark *c, struct deark_module_info *mi)
{
	mi->id = "lha";
	mi->desc = "LHA/LZW";
	mi->run_fn = de_run_lha;
	mi->identify_fn = de_identify_lha;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
