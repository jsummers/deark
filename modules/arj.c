// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// ARJ compressed archive

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_arj);

struct member_data {
	de_encoding input_encoding;
	UI hdr_id;
#define ARJ_OBJTYPE_ARCHIVEHDR  1
#define ARJ_OBJTYPE_MEMBERFILE  2
#define ARJ_OBJTYPE_CHAPTERHDR  3
#define ARJ_OBJTYPE_EOA         4
	u8 objtype;
	u8 archiver_ver_num;
	u8 min_ver_to_extract;
	u8 os;
	u8 flags;
	u8 method;
	u8 file_type;
	UI file_mode;
	u32 crc_reported;
	i64 cmpr_len;
	i64 orig_len;
	struct de_timestamp tmstamp[DE_TIMESTAMPIDX_COUNT];
};

typedef struct localctx_struct {
	de_encoding input_encoding; // if DE_ENCODING_UNKNOWN, autodetect for each member
	u8 archive_flags;
	u8 is_secured;
	i64 security_envelope_pos;
	i64 security_envelope_len;
	struct de_crcobj *crco;
} lctx;

static void read_arj_datetime(deark *c, lctx *d, i64 pos, struct de_timestamp *ts1, const char *name)
{
	i64 dosdt, dostm;
	char timestamp_buf[64];

	dostm = de_getu16le(pos);
	dosdt = de_getu16le(pos+2);
	de_dos_datetime_to_timestamp(ts1, dosdt, dostm);
	ts1->tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(ts1, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s time: %s", name, timestamp_buf);
}

static void handle_comment(deark *c, lctx *d, struct member_data *md, i64 pos,
	i64 nbytes_avail)
{
	de_ucstring *s = NULL;
	dbuf *outf = NULL;

	if(nbytes_avail<2) goto done;
	s = ucstring_create(c);
	// The header containing the comment is limited to about 2.5KB, so we don't have
	// check sizes here.
	dbuf_read_to_ucstring(c->infile, pos, nbytes_avail, s, DE_CONVFLAG_STOP_AT_NUL,
		DE_EXTENC_MAKE(md->input_encoding, DE_ENCSUBTYPE_HYBRID));
	if(s->len<1) goto done;
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));

	if(c->extract_level>=2) {
		const char *token;

		if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) token = "comment.txt";
		else token = "fcomment.txt";

		outf = dbuf_create_output_file(c, token, NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
	}

done:
	dbuf_close(outf);
	ucstring_destroy(s);
}

static const char *get_host_os_name(u8 n)
{
	static const char *names[12] = { "MSDOS", "PRIMOS", "Unix", "Amiga", "MacOS",
		"OS/2", "Apple GS", "Atari ST", "NeXT", "VMS", "Win95", "WIN32" };

	if(n<=11) return names[(UI)n];
	return "?";
}

static const char *get_file_type_name(struct member_data *md, u8 n)
{
	const char *name = NULL;

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		if(n==2) name = "main header";
	}
	else {
		switch(n) {
		case 0: name = "binary"; break;
		case 1: name = "text"; break;
		case 2:
			if(md->objtype==ARJ_OBJTYPE_CHAPTERHDR) {
				name = "comment header";
			}
			break;
		case 3: name = "directory"; break;
		case 4: name = "volume label"; break;
		case 5: name = "chapter label"; break;
		}
	}
	return name?name:"?";
}

static void get_flags_descr(struct member_data *md, u8 n1, de_ucstring *s)
{
	u8 n = n1;

	if(n & 0x01) {
		ucstring_append_flags_item(s, "GARBLED");
		n -= 0x01;
	}

	if((n & 0x02) && (md->objtype==ARJ_OBJTYPE_ARCHIVEHDR)) {
		if(md->os==10 || md->os==11) {
			ucstring_append_flags_item(s, "ANSIPAGE");
			n -= 0x02;
		}
	}

	if(n & 0x04) {
		ucstring_append_flags_item(s, "VOLUME");
		n -= 0x04;
	}

	if(n & 0x08) {
		if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
			ucstring_append_flags_item(s, "ARJPROT");
		}
		else {
			ucstring_append_flags_item(s, "EXTFILE");
		}
		n -= 0x08;
	}

	if(n & 0x10) {
		ucstring_append_flags_item(s, "PATHSYM");
		n -= 0x10;
	}

	if((n & 0x40) && (md->objtype==ARJ_OBJTYPE_ARCHIVEHDR)) {
		ucstring_append_flags_item(s, "SECURED");
		n -= 0x40;
	}

	if((n & 0x80) && (md->objtype==ARJ_OBJTYPE_ARCHIVEHDR)) {
		ucstring_append_flags_item(s, "ALTNAME");
		n -= 0x80;
	}

	if(n!=0) {
		ucstring_append_flags_itemf(s, "0x%02x", (UI)n);
	}
}

static const char *get_objtype_name(u8 t) {
	const char *name = NULL;

	switch(t) {
	case ARJ_OBJTYPE_ARCHIVEHDR: name="archive header"; break;
	case ARJ_OBJTYPE_MEMBERFILE: name="member file"; break;
	case ARJ_OBJTYPE_CHAPTERHDR: name="chapter header"; break;
	case ARJ_OBJTYPE_EOA: name="end of archive"; break;
	}
	return name?name:"?";
}

// If successfully parsed, sets *pbytes_consumed.
// Returns 1 normally, 2 if this is the EOA marker, 0 on fatal error.
static int do_header_or_member(deark *c, lctx *d, i64 pos1, int expecting_archive_hdr,
	i64 *pbytes_consumed)
{
	i64 pos = pos1;
	i64 basic_hdr_size;
	i64 first_hdr_size;
	i64 first_hdr_endpos;
	i64 first_ext_hdr_size;
	i64 extra_data_len;
	i64 nbytes_avail;
	i64 n;
	i64 basic_hdr_endpos;
	u32 basic_hdr_crc_reported;
	u32 basic_hdr_crc_calc;
	struct member_data *md = NULL;
	struct de_stringreaderdata *name_srd = NULL;
	de_ucstring *flags_descr = NULL;
	int retval = 0;
	int saved_indent_level;
	u8 b;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));

	md->hdr_id = (UI)de_getu16le_p(&pos);
	if(expecting_archive_hdr) {
		if(md->hdr_id==0xea60) {
			md->objtype = ARJ_OBJTYPE_ARCHIVEHDR;
		}
		else {
			de_err(c, "Not an ARJ file");
			goto done;
		}
	}
	else if(md->hdr_id==0xea60) {
		md->objtype = ARJ_OBJTYPE_MEMBERFILE; // tentative?
	}
	else if(md->hdr_id==0x6000) {
		md->objtype = ARJ_OBJTYPE_CHAPTERHDR;
	}
	else {
		de_err(c, "ARJ member not found at %"I64_FMT, pos1);
		goto done;
	}

	de_dbg(c, "object at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	basic_hdr_size = de_getu16le_p(&pos);
	de_dbg(c, "basic header size: %"I64_FMT, basic_hdr_size);
	if(basic_hdr_size==0) {
		md->objtype = ARJ_OBJTYPE_EOA;
	}
	de_dbg(c, "object type: %s", get_objtype_name(md->objtype));

	if(basic_hdr_size==0) {
		*pbytes_consumed = 4;
		goto done;
	}

	if(basic_hdr_size>2600) {
		de_err(c, "Bad header size");
		goto done;
	}

	de_dbg(c, "[basic header]");
	de_dbg_indent(c, 1);

	de_dbg(c, "[first header]");
	de_dbg_indent(c, 1);

	basic_hdr_endpos = pos1 + 4 + basic_hdr_size;
	first_hdr_size = (i64)de_getbyte_p(&pos);
	de_dbg(c, "first header size: %"I64_FMT, first_hdr_size);
	first_hdr_endpos = pos1 + 4 + first_hdr_size;
	md->archiver_ver_num = de_getbyte_p(&pos);
	de_dbg(c, "archiver version: %u", (UI)md->archiver_ver_num);
	md->min_ver_to_extract = de_getbyte_p(&pos);
	de_dbg(c, "min ver to extract: %u", (UI)md->min_ver_to_extract);

	md->os = de_getbyte_p(&pos);
	de_dbg(c, "host OS: %u (%s)", (UI)md->os, get_host_os_name(md->os));

	md->flags = de_getbyte_p(&pos);
	flags_descr = ucstring_create(c);
	get_flags_descr(md, md->flags, flags_descr);
	de_dbg(c, "flags: 0x%02x (%s)", (UI)md->flags, ucstring_getpsz_d(flags_descr));
	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		d->archive_flags = md->flags;
		if(d->archive_flags & 0x40) d->is_secured = 1;
	}

	// Now we have enough information to choose a character encoding.
	md->input_encoding = d->input_encoding;
	if(md->input_encoding==DE_ENCODING_UNKNOWN) {
		if((d->archive_flags&0x02) && (md->os==10 || md->os==11)) {
			md->input_encoding = DE_ENCODING_WINDOWS1252;
		}
		else {
			md->input_encoding = DE_ENCODING_CP437;
		}
	}

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		b = de_getbyte_p(&pos);
		de_dbg(c, "security version: %u", (UI)b);
	}
	else {
		md->method = de_getbyte_p(&pos);
		de_dbg(c, "cmpr method: %u", (UI)md->method);
	}

	md->file_type = de_getbyte_p(&pos);
	de_dbg(c, "file type: %u (%s)", (UI)md->file_type, get_file_type_name(md, md->file_type));

	pos++; // reserved

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		read_arj_datetime(c, d, pos, &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "archive creation");
		pos += 4;
	}
	else if(md->objtype==ARJ_OBJTYPE_CHAPTERHDR) {
		read_arj_datetime(c, d, pos,  &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "creation");
		pos += 4;
	}
	else {
		read_arj_datetime(c, d, pos, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "mod");
		pos += 4;
	}

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		read_arj_datetime(c, d, pos, &md->tmstamp[DE_TIMESTAMPIDX_MODIFY], "archive mod");
		pos += 4;
	}
	else if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
		md->cmpr_len = de_getu32le_p(&pos);
		de_dbg(c, "compressed size: %"I64_FMT, md->cmpr_len);
	}
	else {
		pos += 4;
	}

	if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
		md->orig_len = de_getu32le_p(&pos);
		de_dbg(c, "original size: %"I64_FMT, md->orig_len);
	}
	else {
		pos += 4;
	}

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		n = de_getu32le_p(&pos);
		if(d->is_secured) {
			d->security_envelope_pos = n;
			de_dbg(c, "security envelope pos: %"I64_FMT, d->security_envelope_pos);
		}
	}
	else {
		md->crc_reported = (u32)de_getu32le_p(&pos);
		de_dbg(c, "crc (reported): 0x%08x", (UI)md->crc_reported);
	}

	n = de_getu16le_p(&pos);
	de_dbg(c, "filespec pos in filename: %d", (int)n);

	if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
		n = de_getu16le_p(&pos);
		if(d->is_secured) {
			d->security_envelope_len = n;
			de_dbg(c, "security envelope len: %"I64_FMT, d->security_envelope_len);
		}
	}
	else {
		de_ucstring *mode_descr;

		md->file_mode = (UI)de_getu16le_p(&pos);
		mode_descr = ucstring_create(c);
		de_describe_dos_attribs(c, md->file_mode, mode_descr, 0);
		de_dbg(c, "access mode: 0x%02x (%s)", md->file_mode, ucstring_getpsz_d(mode_descr));
		ucstring_destroy(mode_descr);
	}

	pos++; // first chapter / encryption ver
	pos++; // last chapter

	extra_data_len = first_hdr_endpos - pos;
	if(extra_data_len>0) {
		de_dbg(c, "extra data: %"I64_FMT" bytes at %"I64_FMT"", extra_data_len, pos);
		de_dbg_indent(c, 1);

		if(md->objtype==ARJ_OBJTYPE_ARCHIVEHDR) {
			if(extra_data_len>=1) {
				b = de_getbyte_p(&pos);
				de_dbg(c, "protection factor: %u", (UI)b);
			}
			if(extra_data_len>=2) {
				b = de_getbyte_p(&pos);
				de_dbg(c, "flags (2nd set): 0x%02x", (UI)b);
			}
		}
		else if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
			if(extra_data_len>=4) {
				n = de_getu32le_p(&pos);
				de_dbg(c, "ext. file pos: %"I64_FMT, n);
			}
			if(extra_data_len>=12) {
				read_arj_datetime(c, d, pos, &md->tmstamp[DE_TIMESTAMPIDX_ACCESS], "access");
				pos += 4;
				read_arj_datetime(c, d, pos, &md->tmstamp[DE_TIMESTAMPIDX_CREATE], "create");
				pos += 4;
			}
			if(extra_data_len>=16) {
				n = de_getu32le_p(&pos);
				de_dbg(c, "ext. orig size: %"I64_FMT, n);
			}
		}

		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
	pos = first_hdr_endpos; // Now at the offset of the filename field
	nbytes_avail = basic_hdr_endpos - pos;
	name_srd = dbuf_read_string(c->infile, pos, nbytes_avail, 256, DE_CONVFLAG_STOP_AT_NUL,
		md->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(name_srd->str));

	if(name_srd->found_nul) {
		pos += name_srd->bytes_consumed;
		nbytes_avail = basic_hdr_endpos - pos;
		handle_comment(c, d, md, pos, nbytes_avail);
	}

	de_dbg_indent(c, -1);
	pos = basic_hdr_endpos; // Now at the offset just after the 'comment' field
	basic_hdr_crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "basic hdr crc (reported): 0x%08x", (UI)basic_hdr_crc_reported);

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, pos1+4, basic_hdr_size);
	basic_hdr_crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "basic hdr crc (calculated): 0x%08x", (UI)basic_hdr_crc_calc);

	first_ext_hdr_size = de_getu16le_p(&pos);
	de_dbg(c, "first ext header size: %"I64_FMT, first_ext_hdr_size);
	if(first_ext_hdr_size != 0) {
		pos += 4; // first ext hdr crc
	}

	if(md->objtype==ARJ_OBJTYPE_MEMBERFILE) {
		de_dbg(c, "compressed data at %"I64_FMT, pos);
		pos += md->cmpr_len;
	}

	*pbytes_consumed = pos - pos1;
	retval = 1;

done:
	ucstring_destroy(flags_descr);
	de_destroy_stringreaderdata(c, name_srd);
	if(md) {
		de_free(c, md);
	}
	de_dbg_indent(c, -1);
	return retval;
}

static void do_member_sequence(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 num_extra_bytes;

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos+2 > c->infile->len) goto done;

		ret = do_header_or_member(c, d, pos, 0, &bytes_consumed);
		if(ret==0 || bytes_consumed<2) goto done;
		if(ret==2) { // End of archive
			break;
		}
		pos += bytes_consumed;
	}

	num_extra_bytes = c->infile->len - pos;
	if(num_extra_bytes>1) {
		de_dbg(c, "[%"I64_FMT" extra bytes at EOF, starting at %"I64_FMT"]", num_extra_bytes, pos);
	}
done:
	;
}

static void do_security_envelope(deark *c, lctx *d)
{
	if(d->security_envelope_len==0) return;
	de_dbg(c, "security envelope at %"I64_FMT", len=%"I64_FMT, d->security_envelope_pos,
		d->security_envelope_len);
	de_dbg_indent(c, 1);
	de_dbg_hexdump(c, c->infile, d->security_envelope_pos, d->security_envelope_len,
		256, NULL, 0x0);
	de_dbg_indent(c, -1);
}

static void de_run_arj(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 bytes_consumed = 0;

	d = de_malloc(c, sizeof(lctx));

	de_declare_fmt(c, "ARJ");
	de_info(c, "Note: ARJ files are not fully supported.");

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	pos = 0;
	if(do_header_or_member(c, d, pos, 1, &bytes_consumed) != 1) goto done;
	pos += bytes_consumed;
	if(d->is_secured) {
		do_security_envelope(c, d);
	}

	do_member_sequence(c, d, pos);

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_arj(deark *c)
{
	i64 basic_hdr_size;

	if(dbuf_memcmp(c->infile, 0, "\x60\xea", 2)) return 0;
	basic_hdr_size = de_getu16le(2);
	if(basic_hdr_size>2600) return 0;
	if(de_input_file_has_ext(c, "arj")) return 100;
	return 75;
}

void de_module_arj(deark *c, struct deark_module_info *mi)
{
	mi->id = "arj";
	mi->desc = "ARJ";
	mi->run_fn = de_run_arj;
	mi->identify_fn = de_identify_arj;
}
