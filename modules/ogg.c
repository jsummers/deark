// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Ogg multimedia format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_ogg);

struct localctx_struct;
typedef struct localctx_struct lctx;
struct page_info;
struct stream_info;

typedef void (*page_handler_fn_type)(deark *c, lctx *d,
	struct page_info *pgi, struct stream_info *si);

#define STREAMTYPE_VORBIS   1
#define STREAMTYPE_THEORA   2
#define STREAMTYPE_SKELETON 3
#define STREAMTYPE_FLAC     4
#define STREAMTYPE_SPEEX    5
#define STREAMTYPE_OPUS     6
#define STREAMTYPE_DIRAC    7
#define STREAMTYPE_KATE     8
#define STREAMTYPE_MIDI     9
#define STREAMTYPE_PCM      10
#define STREAMTYPE_YUV4MPEG 11
#define STREAMTYPE_OGM_V    20
#define STREAMTYPE_OGM_A    21
#define STREAMTYPE_OGM_T    22
#define STREAMTYPE_OGM_S    23

	struct stream_type_info {
	int stream_type;
	unsigned int flags;
	int magic_len;
	const u8 *magic;
	const char *name;
	page_handler_fn_type page_fn;
};

struct page_info {
	u8 version;
	u8 hdr_type;
	int is_first_page; // Is this the first page of some bitstream?
	i64 granule_pos;
	i64 stream_serialno;
	i64 page_seq_num;
	i64 dpos;
	i64 dlen;
};

struct stream_info {
	int stream_type; // 0 if unknown
	const struct stream_type_info *sti; // NULL if stream type is unknown

	i64 serialno;

	// Number of pages we've counted for this stream so far.
	// Expected to equal page_info::page_seq_num.
	i64 page_count;

	// Private use data, owned by the stream type.

	// Vorbis/Theora:
	//  0 = Headers have not been processed.
	//  1 = Headers have been processed.
	unsigned int stream_state;

	// Theora: A copy of the Comment and Setup streams.
	dbuf *header_stream;
};

struct localctx_struct {
	int always_hexdump;
	i64 total_page_count;
	i64 bitstream_count;
	struct de_inthashtable *streamtable;

	u8 format_declared;
	u8 found_skeleton, found_ogm;
	u8 found_vorbis, found_theora;

	int first_stream_type_valid;
	int first_stream_type;
	int has_unknown_or_multiple_stream_types;
	int has_non_vorbis_non_theora_stream;
	const struct stream_type_info *first_stream_sti;
};

static unsigned int getu24be_p(dbuf *f, i64 *ppos)
{
	unsigned int u;
	u = (unsigned int)dbuf_getint_ext(f, *ppos, 3, 0, 0);
	*ppos += 3;
	return u;
}

// To be called when we encounter a page that is not the first page of
// its bitstream (or at EOF).
static void declare_ogg_format(deark *c, lctx *d)
{
	char tmps[80];
	const char *name = NULL;

	if(d->format_declared) return;
	d->format_declared = 1;

	// There's no nice way, that I know of, to characterize the contents of an Ogg
	// file. But I think it's worth trying.

	if(d->bitstream_count<1) {
		// If there are zero streams : "other"
	}
	else if(d->found_ogm) {
		// else if there's an OGM stream of any kind...
		name="OGM";
	}
	else if(d->found_skeleton) {
		// else If there's a Skeleton stream...
		name="Skeleton";
	}
	else if(d->first_stream_type_valid && d->first_stream_sti &&
		!d->has_unknown_or_multiple_stream_types)
	{
		// else if all streams are the same known type: that stream type
		name = d->first_stream_sti->name;
	}
	else if(d->found_theora && d->found_vorbis && !d->has_non_vorbis_non_theora_stream) {
		// else if there are Theora and Vorbis streams and nothing else...
		name="Theora+Vorbis";
	}
	else if(d->found_theora) {
		// else if there's a Theora stream...
		name="Theora+other";
	}
	// (else "other")

	de_snprintf(tmps, sizeof(tmps), "Ogg %s", name?name:"(other)");
	de_declare_fmt(c, tmps);
}

static char *get_hdrtype_descr(deark *c, char *buf, size_t buflen, u8 hdr_type)
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

static void do_vorbis_id_header(deark *c, lctx *d, struct page_info *pgi, struct stream_info *si)
{
	i64 pos = pgi->dpos;
	unsigned int u1;
	i64 x;

	pos += 7; // Skip signature
	u1 = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "version: %u", u1);
	u1 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "channels: %u", u1);
	u1 = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "sample rate: %u", u1);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "max bitrate: %d", (int)x);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "nominal bitrate: %d", (int)x);
	x = de_geti32le(pos); pos += 4;
	de_dbg(c, "min bitrate: %d", (int)x);
}

static void do_theora_id_header(deark *c, lctx *d, struct page_info *pgi, struct stream_info *si)
{
	i64 pos = pgi->dpos;
	u8 vmaj, vmin, vrev;
	i64 x1, x2;
	unsigned int u1, u2;

	pos += 7; // Skip signature
	vmaj = de_getbyte_p(&pos);
	vmin = de_getbyte_p(&pos);
	vrev = de_getbyte_p(&pos);
	de_dbg(c, "version: %u.%u.%u", (unsigned int)vmaj, (unsigned int)vmin,
		(unsigned int)vrev);
	x1 = de_getu16be_p(&pos);
	x2 = de_getu16be_p(&pos);
	de_dbg(c, "frame dimensions: %d"DE_CHAR_TIMES"%d macroblocks", (int)x1, (int)x2);

	u1 = getu24be_p(c->infile, &pos);
	u2 = getu24be_p(c->infile, &pos);
	de_dbg(c, "picture dimensions: %u"DE_CHAR_TIMES"%u pixels", u1, u2);

	u1 = (unsigned int)de_getbyte_p(&pos);
	u2 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "picture region offset: %u,%u pixels", u1, u2);

	u1 = (unsigned int)de_getu32be_p(&pos);
	u2 = (unsigned int)de_getu32be_p(&pos);
	de_dbg(c, "frame rate: %u/%u", u1, u2);

	u1 = getu24be_p(c->infile, &pos);
	u2 = getu24be_p(c->infile, &pos);
	de_dbg(c, "aspect ratio: %u/%u", u1, u2);

	u1 = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "color space: %u", u1);

	u1 = getu24be_p(c->infile, &pos);
	de_dbg(c, "nominal bitrate: %u bits/sec", u1);
}

static void do_vorbis_comment_block(deark *c, lctx *d, dbuf *f, i64 pos1)
{
	i64 pos = pos1;
	i64 n;
	i64 ncomments;
	i64 k;
	de_ucstring *s = NULL;

	n = dbuf_getu32le_p(f, &pos);
	if(pos+n > f->len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(f, pos, n, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
	de_dbg(c, "vendor: \"%s\"", ucstring_getpsz_d(s));
	pos += n;

	ncomments = dbuf_getu32le_p(f, &pos);
	de_dbg(c, "number of comments: %d", (int)ncomments);

	for(k=0; k<ncomments; k++) {
		if(pos+4 > f->len) goto done;
		n = dbuf_getu32le_p(f, &pos);
		if(pos+n > f->len) goto done;
		ucstring_empty(s);
		dbuf_read_to_ucstring_n(f, pos, n, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
		de_dbg(c, "comment[%d]: \"%s\"", (int)k, ucstring_getpsz_d(s));
		pos += n;
	}

done:
	ucstring_destroy(s);
}

static void do_theora_vorbis_after_headers(deark *c, lctx *d, struct stream_info *si)
{
	i64 pos = 0;
	int saved_indent_level;
	dbuf *f = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(si->stream_state!=0) goto done;
	if(!si->header_stream) goto done;
	if(!si->sti) goto done;
	f = si->header_stream;

	de_dbg(c, "[decoding %s comment/setup headers, %d bytes]",
		si->sti->name, (int)si->header_stream->len);
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

	do_vorbis_comment_block(c, d, f, pos);

	// TODO: "Setup" header

done:
	si->stream_state = 1;
	dbuf_close(si->header_stream);
	si->header_stream = NULL;
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_vorbis_page(deark *c, lctx *d, struct page_info *pgi, struct stream_info *si)
{
	u8 firstbyte;

	if(pgi->is_first_page) {
		// The first Ogg page of a bitstream usually contains enough data to be
		// useful. So, we'll try to process it directly, without reconstructing
		// the codec bitstream.
		do_vorbis_id_header(c, d, pgi, si);
	}

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
	u8 firstbyte;

	if(pgi->is_first_page) {
		do_theora_id_header(c, d, pgi, si);
	}

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

// .flags: 0x1=An OGM stream type
const struct stream_type_info stream_type_info_arr[] = {
	{ STREAMTYPE_VORBIS,  0, 7,  (const u8*)"\x01" "vorbis", "Vorbis", do_vorbis_page },
	{ STREAMTYPE_THEORA,  0, 7,  (const u8*)"\x80" "theora", "Theora", do_theora_page },
	{ STREAMTYPE_SKELETON, 0, 8, (const u8*)"fishead\0",     "Skeleton", NULL },
	{ STREAMTYPE_FLAC,    0, 5,  (const u8*)"\x7f" "FLAC",   "FLAC", NULL },
	{ STREAMTYPE_SPEEX,   0, 8,  (const u8*)"Speex   ",      "Speex", NULL },
	{ STREAMTYPE_OPUS,    0, 8,  (const u8*)"OpusHead",      "Opus", NULL },
	{ STREAMTYPE_DIRAC,   0, 5,  (const u8*)"BBCD\0",        "Dirac", NULL },
	{ STREAMTYPE_KATE,    0, 8,  (const u8*)"\x80" "kate\0\0\0", "Kate", NULL },
	{ STREAMTYPE_MIDI,    0, 8,  (const u8*)"OggMIDI\0",     "MIDI", NULL },
	{ STREAMTYPE_PCM,     0, 8,  (const u8*)"PCM     ",      "PCM", NULL },
	{ STREAMTYPE_YUV4MPEG, 0, 8, (const u8*)"YUV4MPEG",      "YUV4MPEG", NULL },
	{ STREAMTYPE_OGM_V, 0x1, 6,  (const u8*)"\x01" "video",  "OGM video", NULL },
	{ STREAMTYPE_OGM_A, 0x1, 6,  (const u8*)"\x01" "audio",  "OGM audio", NULL },
	{ STREAMTYPE_OGM_T, 0x1, 5,  (const u8*)"\x01" "text",   "OGM text", NULL },
	{ STREAMTYPE_OGM_S, 0x1, 16, (const u8*)"\x01" "Direct Show Sam", "OGM DS samples", NULL }
};

static void do_identify_bitstream(deark *c, lctx *d, struct stream_info *si, i64 pos, i64 len)
{
	u8 idbuf[16];
	size_t bytes_to_scan;
	size_t k;

	bytes_to_scan = (size_t)len;
	if(bytes_to_scan > sizeof(idbuf)) {
		bytes_to_scan = sizeof(idbuf);
	}

	de_read(idbuf, pos, bytes_to_scan);

	for(k=0; k<DE_ITEMS_IN_ARRAY(stream_type_info_arr); k++) {
		if(!de_memcmp(idbuf, stream_type_info_arr[k].magic,
			stream_type_info_arr[k].magic_len))
		{
			si->sti = &stream_type_info_arr[k];
			si->stream_type = si->sti->stream_type;
			break;
		}
	}

	if(si->stream_type==STREAMTYPE_VORBIS) {
		d->found_vorbis = 1;
	}
	else if(si->stream_type==STREAMTYPE_THEORA) {
		d->found_theora = 1;
	}
	else if(si->stream_type==STREAMTYPE_SKELETON) {
		d->found_skeleton = 1;
	}
	else if(si->sti && (si->sti->flags&0x1)) {
		d->found_ogm = 1;
	}

	if(si->stream_type!=STREAMTYPE_VORBIS && si->stream_type!=STREAMTYPE_THEORA) {
		d->has_non_vorbis_non_theora_stream = 1;
	}

	de_dbg(c, "bitstream type: %s", si->sti?si->sti->name:"unknown");
}

// This function is a continuation of do_ogg_page(). Here we dig
// a little deeper, and look at the bitstream type and contents.
static void do_bitstream_page(deark *c, lctx *d, struct page_info *pgi,
	struct stream_info *si)
{
	if(d->always_hexdump || (pgi->is_first_page && (c->debug_level>=2))) {
		de_dbg_hexdump(c, c->infile, pgi->dpos, pgi->dlen, 256, NULL, 0x1);
	}

	if(pgi->is_first_page) {
		do_identify_bitstream(c, d, si, pgi->dpos, pgi->dlen);

		if(d->total_page_count==0) {
			// This is the first stream in the file.
			if(si->sti && si->stream_type!=0) {
				// This stream's type is known. Remember it, for format declaration purpose.
				d->first_stream_type = si->stream_type;
				d->first_stream_sti = si->sti;
				d->first_stream_type_valid = 1;
			}
		}
		else {
			// Not the first stream in the file
			if(si->stream_type!=0 && d->first_stream_type_valid &&
				(si->stream_type==d->first_stream_type))
			{
				// This stream is the same type as the first stream. Do nothing.
			}
			else {
				d->has_unknown_or_multiple_stream_types = 1;
			}
		}

		if(si->stream_type==0) {
			d->has_unknown_or_multiple_stream_types = 1;
		}
	}
	else {
		if(!d->format_declared) declare_ogg_format(c, d);
	}

	if(si->sti && si->sti->page_fn) {
		si->sti->page_fn(c, d, pgi, si);
	}
}

static int do_ogg_page(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	i64 x;
	i64 num_page_segments;
	i64 k;
	char buf[100];
	int retval = 0;
	int ret;
	void *item = NULL;
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
	de_dbg(c, "granule position: %"I64_FMT, pgi->granule_pos);

	pgi->stream_serialno = de_getu32le_p(&pos);
	de_dbg(c, "bitstream serial number: %"I64_FMT, pgi->stream_serialno);

	ret = de_inthashtable_get_item(c, d->streamtable, pgi->stream_serialno, &item);
	if(ret) {
		si = (struct stream_info*)item;
		// We've seen this stream before.
		de_dbg_indent(c, 1);
		de_dbg(c, "bitstream %"I64_FMT" type: %s", pgi->stream_serialno,
			si->sti?si->sti->name:"unknown");
		de_dbg_indent(c, -1);
	}
	else {
		// This the first page we've encountered of this stream.
		si = de_malloc(c, sizeof(struct stream_info));
		de_inthashtable_add_item(c, d->streamtable, pgi->stream_serialno, (void*)si);
		d->bitstream_count++;
	}
	si->serialno = pgi->stream_serialno;

	pgi->page_seq_num = de_getu32le_p(&pos);
	de_dbg(c, "page sequence number: %"I64_FMT, pgi->page_seq_num);

	x = de_getu32le_p(&pos);
	de_dbg(c, "crc (reported): 0x%08x", (unsigned int)x);

	num_page_segments = (i64)de_getbyte_p(&pos);
	de_dbg(c, "number of page segments: %d", (int)num_page_segments);

	// Read page table
	pgi->dlen = 0;
	for(k=0; k<num_page_segments; k++) {
		x = (i64)de_getbyte_p(&pos);
		pgi->dlen += x;
	}

	pgi->dpos = pos;

	// Apparently we have 3 ways to identify the first page of a bitstream.
	// We'll require them all to be consistent.
	pgi->is_first_page = (si->page_count==0) && (pgi->page_seq_num==0) && ((pgi->hdr_type&0x02)!=0);

	// Page data
	de_dbg(c, "[%"I64_FMT" total bytes of page data, at %"I64_FMT"]", pgi->dlen, pgi->dpos);
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
		i64 key;
		void *removed_item = NULL;
		struct stream_info *si;

		if(!de_inthashtable_remove_any_item(c, d->streamtable, &key, &removed_item)) {
			break;
		}
		si = (struct stream_info *)removed_item;
		destroy_bitstream(c, d, si);
	}

	de_inthashtable_destroy(c, d->streamtable);
	d->streamtable = NULL;
}

static void run_ogg_internal(deark *c, lctx *d)
{
	i64 pos;
	i64 ogg_end;
	struct de_id3info id3i;

	d->always_hexdump = de_get_ext_option(c, "ogg:hexdump")?1:0;
	d->streamtable = de_inthashtable_create(c);

	de_fmtutil_handle_id3(c, c->infile, &id3i, 0);
	pos = id3i.main_start;
	ogg_end = id3i.main_end;

	while(1) {
		u32 sig;
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= ogg_end) break;
		sig = (u32)de_getu32be(pos);
		if(sig!=0x04f676753U) {
			de_err(c, "Ogg page signature not found at %"I64_FMT, pos);
			break;
		}
		de_dbg(c, "page at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = do_ogg_page(c, d, pos, &bytes_consumed);
		de_dbg_indent(c, -1);
		if(!ret || bytes_consumed<=4) break;
		pos += bytes_consumed;
		d->total_page_count++;
	}

	if(!d->format_declared) declare_ogg_format(c, d);

	de_dbg(c, "number of bitstreams: %d", (int)d->bitstream_count);
}

static void de_run_ogg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(de_havemodcode(c, mparams, 'C')) {
		do_vorbis_comment_block(c, d, c->infile, 0);
		goto done;
	}

	run_ogg_internal(c, d);

done:
	if(d && d->streamtable) {
		destroy_streamtable(c, d);
	}
	de_free(c, d);
}

static int de_identify_ogg(deark *c)
{
	i64 pos = 0;

	if(!c->detection_data.id3.detection_attempted) {
		de_err(c, "ogg detection requires id3 module");
		return 0;
	}

	if(c->detection_data.id3.has_id3v2) {
		pos = (i64)c->detection_data.id3.bytes_at_start;
	}

	if(!dbuf_memcmp(c->infile, pos, "OggS", 4))
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
