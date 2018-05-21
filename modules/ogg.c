// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Ogg multimedia format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ogg);

typedef struct localctx_struct {
	de_int64 page_count;
	de_byte version;
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

static void do_init_new_bitstream(deark *c, lctx *d, const char *name)
{
	de_dbg(c, "bitstream type: %s", name?name:"unknown");
	if(d->page_count==0) {
		char tmps[80];
		// This is the first bitstream in the file. We'll consider it to be the
		// main "file format", though this is not always the best logic.
		de_snprintf(tmps, sizeof(tmps), "Ogg %s", name?name:"(other)");
		de_declare_fmt(c, tmps);
	}
}

static void do_vorbis_id_header(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	do_init_new_bitstream(c, d, "Vorbis");
}

static void do_theora_id_header(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	do_init_new_bitstream(c, d, "Theora");
}

static void do_speex_id_header(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	do_init_new_bitstream(c, d, "Speex");
}

static void do_skeleton_header(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	do_init_new_bitstream(c, d, "Skeleton");
}

static void do_bitstream_firstpage(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_byte idbuf[16];
	size_t bytes_to_scan;

	if(c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, pos, len, 256, NULL, 0x1);
	}

	bytes_to_scan = (size_t)len;
	if(bytes_to_scan > sizeof(idbuf)) {
		bytes_to_scan = sizeof(idbuf);
	}

	// The first Ogg page of a bitstream usually contains enough data to be
	// useful. So, we'll try to process it directly, without reconstructing
	// the codec bitstream.
	de_read(idbuf, pos, bytes_to_scan);

	if(!de_memcmp(idbuf, "\x01" "vorbis", 7)) {
		do_vorbis_id_header(c, d, pos, len);
	}
	else if(!de_memcmp(idbuf, "\x80" "theora", 7)) {
		do_theora_id_header(c, d, pos, len);
	}
	else if(!de_memcmp(idbuf, "fishead\0", 8)) {
		do_skeleton_header(c, d, pos, len);
	}
	else if(!de_memcmp(idbuf, "Speex   ", 8)) {
		do_speex_id_header(c, d, pos, len);
	}
	else {
		do_init_new_bitstream(c, d, NULL);
	}
}

static int do_ogg_page(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_byte hdr_type;
	de_int64 x;
	de_int64 num_page_segments;
	de_int64 k;
	de_int64 bytecount;
	char buf[100];
	int retval = 0;

	pos += 4; // signature, already read

	d->version = de_getbyte_p(&pos);
	de_dbg(c, "version: %d", (int)d->version);

	hdr_type = de_getbyte_p(&pos);
	de_dbg(c, "header type: 0x%02x%s", (unsigned int)hdr_type,
		get_hdrtype_descr(c, buf, sizeof(buf), hdr_type));

	x = de_geti64le(pos); pos += 8;
	de_dbg(c, "granule position: %"INT64_FMT, x);

	x = de_getui32le_p(&pos);
	de_dbg(c, "bitstream serial number: %"INT64_FMT, x);

	x = de_getui32le_p(&pos);
	de_dbg(c, "page sequence number: %"INT64_FMT, x);

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
	if(hdr_type&0x02) {
		de_dbg_indent(c, 1);
		do_bitstream_firstpage(c, d, pos, bytecount);
		de_dbg_indent(c, -1);
	}

	pos += bytecount;

	*bytes_consumed = pos - pos1;
	retval = 1;

	return retval;
}

static void de_run_ogg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

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
		d->page_count++;
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
