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

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	de_destroy_stringreaderdata(c, md->cmpr_method);
	de_free(c, md);
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

static void do_read_ext_header(deark *c, lctx *d, struct member_data *md,
	de_int64 pos1, de_int64 len, de_int64 dlen)
{
	de_byte id = 0;

	if(dlen>=1)
		id = de_getbyte(pos1);
	de_dbg(c, "ext header at %d, len=%d, dlen=%d, id=0x%02x\n", (int)pos1, (int)len,
		(int)dlen, (unsigned int)id);
}

static void do_lev0_ext_area(deark *c, lctx *d, struct member_data *md,
	de_int64 pos1, de_int64 len)
{
	if(len<1) return;
	md->os_id = de_getbyte(pos1);
	de_dbg(c, "OS id: %d ('%c')\n", (int)md->os_id,
		de_byte_to_printable_char(md->os_id));
	// TODO
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

	*tot_bytes_consumed = 0;

	if(first_ext_hdr_size==0) {
		return 1;
	}

	de_dbg(c, "ext headers section at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	next_ext_hdr_size = first_ext_hdr_size;
	while(1) {
		this_ext_hdr_size = next_ext_hdr_size;
		if(this_ext_hdr_size==0) {
			retval = 1;
			*tot_bytes_consumed = pos - pos1;
			goto done;
		}
		if(this_ext_hdr_size<2) goto done;
		if(pos+this_ext_hdr_size > pos1+len) goto done;

		do_read_ext_header(c, d, md, pos, this_ext_hdr_size, this_ext_hdr_size-2);

		// Each ext header ends with a "size of next header" field.
		// We'll read it at this level, instead of in do_read_ext_header().
		pos += this_ext_hdr_size-2;
		next_ext_hdr_size = de_getui16le(pos);
		pos += 2;
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
	if(md->hlev!=0 && md->hlev!=1 && md->hlev!=2) {
		// TODO: Support level 3
		de_err(c, "Unsupported header level: %d\n", (int)md->hlev);
		goto done;
	}
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
		pos += 4; // modification time/date (MS-DOS)
	}
	else if(md->hlev==2) {
		pos += 4; // Unix time
	}

	if(md->hlev==0) {
		pos += 2; // MS-DOS file attributes
	}
	else if(md->hlev==1 || md->hlev==2) {
		pos++; // reserved
		pos++; // header level
	}

	if(md->hlev<=1) {
		fnlen = de_getbyte(pos++);
		de_dbg(c, "filename len: %d\n", (int)fnlen);
		read_filename(c, d, md, pos, fnlen);
		pos += fnlen;
	}

	if(md->hlev==0 || md->hlev==1 || md->hlev==2) {
		md->crc16 = (de_uint32)de_getui16le(pos);
		de_dbg(c, "crc16 (reported): 0x%04x\n", (unsigned int)md->crc16);
		pos += 2; // CRC16
	}

	if(md->hlev==1 || md->hlev==2) {
		md->os_id = de_getbyte(pos++);
		de_dbg(c, "OS id: %d ('%c')\n", (int)md->os_id,
			de_byte_to_printable_char(md->os_id));
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
