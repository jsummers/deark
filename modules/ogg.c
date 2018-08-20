// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Ogg multimedia format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ogg);

struct page_info {
	de_byte version;
	de_byte hdr_type;
	de_int64 granule_pos;
	de_int64 stream_serialno;
	de_int64 page_seq_num;
	de_int64 dpos;
	de_int64 dlen;
};

struct stream_info {
	de_int64 serialno;

#define STREAMTYPE_VORBIS 1
#define STREAMTYPE_THEORA 2
	int stream_type;

	// Number of pages we've counted for this stream so far.
	// Expected to equal page_info::page_seq_num.
	de_int64 page_count;

	const char *stream_type_name;

	// Private use data, owned by the stream type.

	// Vorbis/Theora:
	//  0 = Headers have not been processed.
	//  1 = Headers have been processed.
	unsigned int stream_state;

	// Theora: A copy of the Comment and Setup streams.
	dbuf *header_stream;
};

typedef struct localctx_struct {
	int always_hexdump;
	de_int64 total_page_count;
	de_int64 bitstream_count;
	struct de_inthashtable *streamtable;
} lctx;

static unsigned int getui24be_p(dbuf *f, de_int64 *ppos)
{
	unsigned int u;
	u = (unsigned int)dbuf_getint_ext(f, *ppos, 3, 0, 0);
	*ppos += 3;
	return u;
}

static char *get_hdrtype_descr(deark *c, char *buf, size_t buflen, de_byte hdr_type)
{
	if(hdr_type==0) {
		de_strlcpy(buf, "", buflen);
	}
	else {
		de_ucstring *s = NULL;
		s = ucstring_create(c);
		if(hdr_type&0x01) ucstring_append_flags_item(s, "continuation page");
		if(hdr_type&0x02) ucstring_append_flags_item(s, "first page");
		if(hdr_type&0x04) ucstring_append_flags_item(s, "last page");
		de_snprintf(buf, buflen, " (%s)", ucstring_getpsz(s));
		ucstring_destroy(s);
	}
	return buf;
}

static void do_vorbis_id_header(deark *c, lctx *d, struct stream_info *si, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	unsigned int u1;
	de_int64 x;

	pos += 7; // Skip signature
	u1 = (unsigned int)de_getui32le_p(&pos);
	de_dbg(c, "version: %u", u1);
	u1 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "channels: %u", u1);
	u1 = (unsigned int)de_getui32le_p(&pos);
	de_dbg(c, "sample rate: %u", u1);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "max bitrate: %d", (int)x);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "nominal bitrate: %d", (int)x);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "min bitrate: %d", (int)x);
}

static void do_theora_id_header(deark *c, lctx *d, struct stream_info *si, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_byte vmaj, vmin, vrev;
	de_int64 x1, x2;
	unsigned int u1, u2;

	pos += 7; // Skip signature
	vmaj = de_getbyte_p(&pos);
	vmin = de_getbyte_p(&pos);
	vrev = de_getbyte_p(&pos);
	de_dbg(c, "version: %u.%u.%u", (unsigned int)vmaj, (unsigned int)vmin,
		(unsigned int)vrev);
	x1 = de_getui16be_p(&pos);
	x2 = de_getui16be_p(&pos);
	de_dbg(c, "frame dimensions: %d"DE_CHAR_TIMES"%d macroblocks", (int)x1, (int)x2);

	u1 = getui24be_p(c->infile, &pos);
	u2 = getui24be_p(c->infile, &pos);
	de_dbg(c, "picture dimensions: %u"DE_CHAR_TIMES"%u pixels", u1, u2);

	u1 = (unsigned int)de_getbyte_p(&pos);
	u2 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "picture region offset: %u,%u pixels", u1, u2);

	u1 = (unsigned int)de_getui32be_p(&pos);
	u2 = (unsigned int)de_getui32be_p(&pos);
	de_dbg(c, "frame rate: %u/%u", u1, u2);

	u1 = getui24be_p(c->infile, &pos);
	u2 = getui24be_p(c->infile, &pos);
	de_dbg(c, "aspect ratio: %u/%u", u1, u2);

	u1 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "color space: %u", u1);

	u1 = getui24be_p(c->infile, &pos);
	de_dbg(c, "nominal bitrate: %u bits/sec", u1);
}

static void do_theora_vorbis_after_headers(deark *c, lctx *d, struct stream_info *si)
{
	de_int64 n;
	de_int64 pos = 0;
	de_int64 ncomments;
	de_int64 k;
	int saved_indent_level;
	dbuf *f = NULL;
	de_ucstring *s = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(si->stream_state!=0) goto done;
	if(!si->header_stream) goto done;
	if(!si->stream_type_name) goto done;
	f = si->header_stream;

	de_dbg(c, "[decoding %s comment/setup headers, %d bytes]",
		si->stream_type_name, (int)si->header_stream->len);
	de_dbg_indent(c, 1);

	// Make sure the comment header signature is present.
	if(si->stream_type==STREAMTYPE_VORBIS) {
		if(dbuf_memcmp(f, 0, "\x03" "vorbis", 7)) {
			goto done;
		}
		pos += 7;
	}
	else if(si->stream_type==STREAMTYPE_THEORA) {
		if(dbuf_memcmp(f, 0, "\x81" "theora", 7)) {
			goto done;
		}
		pos += 7;
	}

	n = dbuf_getui32le_p(f, &pos);
	if(pos+n > f->len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, n, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
	de_dbg(c, "vendor: \"%s\"", ucstring_getpsz_d(s));
	pos += n;

	ncomments = dbuf_getui32le_p(f, &pos);
	de_dbg(c, "number of comments: %d", (int)ncomments);

	for(k=0; k<ncomments; k++) {
		if(pos+4 > f->len) goto done;
		n = dbuf_getui32le_p(f, &pos);
		if(pos+n > f->len) goto done;
		ucstring_empty(s);
		dbuf_read_to_ucstring_n(f, pos, n, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
		de_dbg(c, "comment[%d]: \"%s\"", (int)k, ucstring_getpsz_d(s));
		pos += n;
	}

	// TODO: "Setup" header

done:
	si->stream_state = 1;
	ucstring_destroy(s);
	dbuf_close(si->header_stream);
	si->header_stream = NULL;
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_vorbis_page(deark *c, lctx *d, struct page_info *pgi, struct stream_info *si)
{
	de_byte firstbyte;

	// We want to save a copy of the Comment and Setup header data,
	// but not the Identification header which is handled elsewhere.

	if(si->stream_state!=0) {
		// We've already handled the Comment & Setup headers.
		goto done;
	}

	if(pgi->dlen<1) goto done;

	firstbyte = de_getbyte(pgi->dpos);

	if(si->page_count==0 || pgi->page_seq_num==0 || (pgi->hdr_type&0x02)) {
		// This appears to be the Identification header page. Skip it.
		goto done;
	}

	if(pgi->page_seq_num>=1 && (firstbyte&0x01)) {
		// This appears to be one of the pages we care about.
		// Save its data for later.
		if(!si->header_stream) {
			si->header_stream = dbuf_create_membuf(c, 1048576, 1);
		}
		dbuf_copy(c->infile, pgi->dpos, pgi->dlen, si->header_stream);
	}
	else if((firstbyte&0x01)==0) {
		// Reached the end of headers (by encountering a non-header page).
		// (There is required to be an Ogg page break immediately after the
		// Vorbis headers, so the start of the first data *page* must correspond
		// to the start of the first data *packet*. A Vorbis data packet always
		// begins with a byte whose low bit is 0.)
		do_theora_vorbis_after_headers(c, d, si);
	}

done:
	;
}

static void do_theora_page(deark *c, lctx *d, struct page_info *pgi, struct stream_info *si)
{
	de_byte firstbyte;

	// We want to save a copy of the Comment and Setup header data,
	// but not the Identification header which is handled elsewhere.

	if(si->stream_state!=0) {
		// We've already handled the Comment & Setup headers.
		goto done;
	}

	if(pgi->dlen<1) goto done;

	firstbyte = de_getbyte(pgi->dpos);

	if(si->page_count==0 || pgi->page_seq_num==0 || (pgi->hdr_type&0x02)) {
		// This appears to be the Identification header page. Skip it.
		goto done;
	}

	if(pgi->page_seq_num>=1 && firstbyte>=0x80) {
		// This appears to be one of the pages we care about.
		// Save its data for later.
		if(!si->header_stream) {
			si->header_stream = dbuf_create_membuf(c, 1048576, 1);
		}
		dbuf_copy(c->infile, pgi->dpos, pgi->dlen, si->header_stream);
	}
	else if(firstbyte<0x80) {
		// Reached the end of headers (by encountering a non-header page).
		// (There is required to be an Ogg page break immediately after the
		// Theora headers, so the start of the first data *page* must correspond
		// to the start of the first data *packet*. A Theora data packet always
		// begins with a byte < 0x80.)
		do_theora_vorbis_after_headers(c, d, si);
	}

done:
	;
}

static void do_init_new_bitstream(deark *c, lctx *d, struct stream_info *si)
{
	de_dbg(c, "bitstream type: %s", si->stream_type_name?si->stream_type_name:"unknown");
	if(d->total_page_count==0) {
		char tmps[80];
		// This is the first bitstream in the file. We'll consider it to be the
		// main "file format", though this is not always the best logic.
		de_snprintf(tmps, sizeof(tmps), "Ogg %s", si->stream_type_name?si->stream_type_name:"(other)");
		de_declare_fmt(c, tmps);
	}
}

static void do_bitstream_firstpage(deark *c, lctx *d, struct stream_info *si, de_int64 pos, de_int64 len)
{
	de_byte idbuf[16];
	size_t bytes_to_scan;

	bytes_to_scan = (size_t)len;
	if(bytes_to_scan > sizeof(idbuf)) {
		bytes_to_scan = sizeof(idbuf);
	}

	// The first Ogg page of a bitstream usually contains enough data to be
	// useful. So, we'll try to process it directly, without reconstructing
	// the codec bitstream.
	de_read(idbuf, pos, bytes_to_scan);

	if(!de_memcmp(idbuf, "\x01" "vorbis", 7)) {
		si->stream_type = STREAMTYPE_VORBIS;
		si->stream_type_name = "Vorbis";
		do_init_new_bitstream(c, d, si);
		do_vorbis_id_header(c, d, si, pos, len);
	}
	else if(!de_memcmp(idbuf, "\x80" "theora", 7)) {
		si->stream_type = STREAMTYPE_THEORA;
		si->stream_type_name = "Theora";
		do_init_new_bitstream(c, d, si);
		do_theora_id_header(c, d, si, pos, len);
	}
	else if(!de_memcmp(idbuf, "fishead\0", 8)) {
		si->stream_type_name = "Skeleton";
		do_init_new_bitstream(c, d, si);
	}
	else if(!de_memcmp(idbuf, "Speex   ", 8)) {
		si->stream_type_name = "Speex";
		do_init_new_bitstream(c, d, si);
	}
	else {
		do_init_new_bitstream(c, d, si);
	}
}

// This function is a continuation of do_ogg_page(). Here we dig
// a little deeper, and look at the bitstream type and contents.
static void do_bitstream_page(deark *c, lctx *d, struct page_info *pgi,
	struct stream_info *si)
{
	int is_first_page;

	// Apparently we have 3 ways to identify the first page of a bitstream.
	// We'll require them all to be consistent.
	is_first_page = (si->page_count==0) && (pgi->page_seq_num==0) && ((pgi->hdr_type&0x02)!=0);

	if(d->always_hexdump || (is_first_page && (c->debug_level>=2))) {
		de_dbg_hexdump(c, c->infile, pgi->dpos, pgi->dlen, 256, NULL, 0x1);
	}

	if(is_first_page) {
		do_bitstream_firstpage(c, d, si, pgi->dpos, pgi->dlen);
	}

	if(si->stream_type==STREAMTYPE_VORBIS) {
		do_vorbis_page(c, d, pgi, si);
	}
	else if(si->stream_type==STREAMTYPE_THEORA) {
		do_theora_page(c, d, pgi, si);
	}
}

static int do_ogg_page(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_int64 x;
	de_int64 num_page_segments;
	de_int64 k;
	char buf[100];
	int retval = 0;
	int ret;
	struct stream_info *si = NULL;
	struct page_info *pgi = NULL;

	pgi = de_malloc(c, sizeof(struct page_info));
	pos += 4; // signature, already read

	pgi->version = de_getbyte_p(&pos);
	de_dbg(c, "version: %d", (int)pgi->version);

	pgi->hdr_type = de_getbyte_p(&pos);
	de_dbg(c, "header type: 0x%02x%s", (unsigned int)pgi->hdr_type,
		get_hdrtype_descr(c, buf, sizeof(buf), pgi->hdr_type));

	pgi->granule_pos = de_geti64le(pos); pos += 8;
	de_dbg(c, "granule position: %"INT64_FMT, pgi->granule_pos);

	pgi->stream_serialno = de_getui32le_p(&pos);
	de_dbg(c, "bitstream serial number: %"INT64_FMT, pgi->stream_serialno);

	ret = de_inthashtable_get_item(c, d->streamtable, pgi->stream_serialno, (void**)&si);
	if(ret) {
		// We've seen this stream before.
		de_dbg_indent(c, 1);
		de_dbg(c, "bitstream %"INT64_FMT" type: %s", pgi->stream_serialno,
			si->stream_type_name?si->stream_type_name:"unknown");
		de_dbg_indent(c, -1);
	}
	else {
		// This the first page we've encountered of this stream.
		si = de_malloc(c, sizeof(struct stream_info));
		de_inthashtable_add_item(c, d->streamtable, pgi->stream_serialno, (void*)si);
		d->bitstream_count++;
	}
	si->serialno = pgi->stream_serialno;

	pgi->page_seq_num = de_getui32le_p(&pos);
	de_dbg(c, "page sequence number: %"INT64_FMT, pgi->page_seq_num);

	x = de_getui32le_p(&pos);
	de_dbg(c, "crc (reported): 0x%08x", (unsigned int)x);

	num_page_segments = (de_int64)de_getbyte_p(&pos);
	de_dbg(c, "number of page segments: %d", (int)num_page_segments);

	// Read page table
	pgi->dlen = 0;
	for(k=0; k<num_page_segments; k++) {
		x = (de_int64)de_getbyte_p(&pos);
		pgi->dlen += x;
	}

	pgi->dpos = pos;

	// Page data
	de_dbg(c, "[%"INT64_FMT" total bytes of page data, at %"INT64_FMT"]", pgi->dlen, pgi->dpos);
	de_dbg_indent(c, 1);
	do_bitstream_page(c, d, pgi, si);
	de_dbg_indent(c, -1);

	pos += pgi->dlen;
	si->page_count++;

	*bytes_consumed = pos - pos1;
	retval = 1;

	de_free(c, pgi);
	return retval;
}

static void destroy_bitstream(deark *c, lctx *d, struct stream_info *si)
{
	if(!si) return;

	if((si->stream_type==STREAMTYPE_VORBIS || si->stream_type==STREAMTYPE_THEORA)
		&& si->stream_state==0)
	{
		do_theora_vorbis_after_headers(c, d, si);
	}

	if(si->header_stream) {
		dbuf_close(si->header_stream);
	}

	de_free(c, si);
}

static void destroy_streamtable(deark *c, lctx *d)
{
	while(1) {
		de_int64 key;
		struct stream_info *si;

		if(!de_inthashtable_remove_any_item(c, d->streamtable, &key, (void**)&si)) {
			break;
		}
		destroy_bitstream(c, d, si);
	}

	de_inthashtable_destroy(c, d->streamtable);
	d->streamtable = NULL;
}

static void de_run_ogg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	d->always_hexdump = de_get_ext_option(c, "ogg:hexdump")?1:0;
	d->streamtable = de_inthashtable_create(c);

	pos = 0;
	while(1) {
		de_uint32 sig;
		int ret;
		de_int64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		sig = (de_uint32)de_getui32be(pos);
		if(sig!=0x04f676753U) {
			de_err(c, "Ogg page signature not found at %"INT64_FMT, pos);
			break;
		}
		de_dbg(c, "page at %"INT64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = do_ogg_page(c, d, pos, &bytes_consumed);
		de_dbg_indent(c, -1);
		if(!ret || bytes_consumed<=4) break;
		pos += bytes_consumed;
		d->total_page_count++;
	}

	de_dbg(c, "number of bitstreams: %d", (int)d->bitstream_count);

	if(d && d->streamtable) {
		destroy_streamtable(c, d);
	}
	de_free(c, d);
}

static int de_identify_ogg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "OggS", 4))
		return 100;
	return 0;
}

static void de_help_ogg(deark *c)
{
	de_msg(c, "-opt ogg:hexdump : Hex dump the first part of all segments");
}

void de_module_ogg(deark *c, struct deark_module_info *mi)
{
	mi->id = "ogg";
	mi->desc = "Ogg multimedia";
	mi->run_fn = de_run_ogg;
	mi->identify_fn = de_identify_ogg;
	mi->help_fn = de_help_ogg;
}
