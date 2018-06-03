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
};

struct stream_info {
	de_int64 serialno;

#define STREAMTYPE_VORBIS 1
#define STREAMTYPE_THEORA 2
	int stream_type;

	// Number of pages we've counted for this stream so far.
	// Expected to equal page_info::page_seq_num.
	de_int64 page_count;
};

typedef struct localctx_struct {
	int always_hexdump;
	de_int64 total_page_count;
	struct de_inthashtable *streamtable;
} lctx;

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

static void do_init_new_bitstream(deark *c, lctx *d, struct stream_info *si, const char *name)
{
	de_dbg(c, "bitstream type: %s", name?name:"unknown");
	if(d->total_page_count==0) {
		char tmps[80];
		// This is the first bitstream in the file. We'll consider it to be the
		// main "file format", though this is not always the best logic.
		de_snprintf(tmps, sizeof(tmps), "Ogg %s", name?name:"(other)");
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
		do_init_new_bitstream(c, d, si, "Vorbis");
	}
	else if(!de_memcmp(idbuf, "\x80" "theora", 7)) {
		si->stream_type = STREAMTYPE_THEORA;
		do_init_new_bitstream(c, d, si, "Theora");
	}
	else if(!de_memcmp(idbuf, "fishead\0", 8)) {
		do_init_new_bitstream(c, d, si, "Skeleton");
	}
	else if(!de_memcmp(idbuf, "Speex   ", 8)) {
		do_init_new_bitstream(c, d, si, "Speex");	}
	else {
		do_init_new_bitstream(c, d, si, NULL);
	}
}

// This function is a continuation of do_ogg_page(). Here we dig
// a little deeper, and look at the bitstream type and contents.
static void do_bitstream_page(deark *c, lctx *d, struct page_info *pgi,
	struct stream_info *si, de_int64 pos, de_int64 len)
{
	int is_first_page;

	// Apparently we have 3 ways to identify the first page of a bitstream.
	// We'll require them all to be consistent.
	is_first_page = (si->page_count==0) && (pgi->page_seq_num==0) && ((pgi->hdr_type&0x02)!=0);

	if(d->always_hexdump || (is_first_page && (c->debug_level>=2))) {
		de_dbg_hexdump(c, c->infile, pos, len, 256, NULL, 0x1);
	}

	if(is_first_page) {
		do_bitstream_firstpage(c, d, si, pos, len);
	}
}

static int do_ogg_page(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_int64 x;
	de_int64 num_page_segments;
	de_int64 k;
	de_int64 bytecount;
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
	if(!ret) {
		si = de_malloc(c, sizeof(struct stream_info));
		de_inthashtable_add_item(c, d->streamtable, pgi->stream_serialno, (void*)si);
	}
	si->serialno = pgi->stream_serialno;

	pgi->page_seq_num = de_getui32le_p(&pos);
	de_dbg(c, "page sequence number: %"INT64_FMT, pgi->page_seq_num);

	x = de_getui32le_p(&pos);
	de_dbg(c, "crc (reported): 0x%08x", (unsigned int)x);

	num_page_segments = (de_int64)de_getbyte_p(&pos);
	de_dbg(c, "number of page segments: %d", (int)num_page_segments);

	// Read page table
	bytecount = 0;
	for(k=0; k<num_page_segments; k++) {
		x = (de_int64)de_getbyte_p(&pos);
		bytecount += x;
	}

	// Page data
	de_dbg(c, "[%"INT64_FMT" total bytes of page data, at %"INT64_FMT"]", bytecount, pos);
	de_dbg_indent(c, 1);
	do_bitstream_page(c, d, pgi, si, pos, bytecount);
	de_dbg_indent(c, -1);

	pos += bytecount;
	si->page_count++;

	*bytes_consumed = pos - pos1;
	retval = 1;

	de_free(c, pgi);
	return retval;
}

static void destroy_bitstream(deark *c, lctx *d, struct stream_info *si)
{
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

void de_module_ogg(deark *c, struct deark_module_info *mi)
{
	mi->id = "ogg";
	mi->desc = "Ogg multimedia";
	mi->run_fn = de_run_ogg;
	mi->identify_fn = de_identify_ogg;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
