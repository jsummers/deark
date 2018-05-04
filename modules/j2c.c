// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// J2C - JPEG 2000 codestream

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_j2c);

struct page_ctx {
	de_int64 ncomp;
	de_int64 j2c_sot_pos;
	de_int64 j2c_sot_length;
};

typedef struct localctx_struct {
	int reserved;
} lctx;

struct marker_info;

typedef void (*handler_fn_type)(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos, de_int64 data_size);

#define FLAG_NO_DATA       0x0100

struct marker_info {
	de_byte seg_type;
	unsigned int flags;
	char shortname[12];
	char longname[80];
	handler_fn_type hfn;
};

// Static info about markers/segments.
struct marker_info1 {
	de_byte seg_type;
	unsigned int flags;
	const char *shortname;
	const char *longname;
	handler_fn_type hfn;
};

static void handle_comment(deark *c, lctx *d, de_int64 pos, de_int64 comment_size,
   int encoding)
{
	de_ucstring *s = NULL;
	int write_to_file;

	// If c->extract_level>=2, write the comment to a file;
	// otherwise if we have debugging output, write (at least part of) it
	// to the debug output;
	// otherwise do nothing.

	if(c->extract_level<2 && c->debug_level<1) return;
	if(comment_size<1) return;

	write_to_file = (c->extract_level>=2);

	if(write_to_file && encoding==DE_ENCODING_UNKNOWN) {
		// If we don't know the encoding, dump the raw bytes to a file.
		dbuf_create_file_from_slice(c->infile, pos, comment_size, "comment.txt",
			NULL, DE_CREATEFLAG_IS_AUX);
		goto done;
	}

	if(encoding==DE_ENCODING_UNKNOWN) {
		// In this case, we're printing the comment in the debug info.
		// If we don't know the encoding, pretend it's ASCII-like.
		encoding=DE_ENCODING_PRINTABLEASCII;
	}

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, comment_size, s, 0, encoding);

	if(write_to_file) {
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}
	else {
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));
	}

done:
	ucstring_destroy(s);
}

static void handler_cme(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos, de_int64 data_size)
{
	de_int64 reg_val;
	de_int64 comment_pos;
	de_int64 comment_size;
	const char *name;

	if(data_size<2) goto done;

	reg_val = de_getui16be(pos);
	switch(reg_val) {
	case 0: name="binary"; break;
	case 1: name="text"; break;
	default: name="?";
	}
	de_dbg(c, "comment/extension type: %d (%s)", (int)reg_val, name);

	comment_pos = pos+2;
	comment_size = data_size-2;

	if(reg_val==1) {
		handle_comment(c, d, comment_pos, comment_size, DE_ENCODING_LATIN1);
	}
	else {
		de_dbg_hexdump(c, c->infile, comment_pos, comment_size, 256, NULL, 0x1);
	}

done:
	;
}

static void handler_siz(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	unsigned int capa;
	de_int64 w, h;
	de_int64 pos = pos1;
	de_int64 ncomp;
	de_int64 k;

	capa = (unsigned int)de_getui16be_p(&pos);
	de_dbg(c, "capabilities: 0x%04x", capa);

	w = de_getui32be_p(&pos);
	h = de_getui32be_p(&pos);
	de_dbg(c, "dimensions of reference grid: %"INT64_FMT DE_CHAR_TIMES "%"INT64_FMT, w, h);

	w = de_getui32be_p(&pos);
	h = de_getui32be_p(&pos);
	de_dbg(c, "offset to image area: %"INT64_FMT",%"INT64_FMT, w, h);

	w = de_getui32be_p(&pos);
	h = de_getui32be_p(&pos);
	de_dbg(c, "dimensions of reference tile: %"INT64_FMT DE_CHAR_TIMES "%"INT64_FMT, w, h);

	w = de_getui32be_p(&pos);
	h = de_getui32be_p(&pos);
	de_dbg(c, "offset to first tile: %"INT64_FMT",%"INT64_FMT, w, h);

	ncomp = de_getui16be_p(&pos);
	de_dbg(c, "number of components: %d", (int)ncomp);

	for(k=0; k<ncomp; k++) {
		de_byte prec, xr, yr;

		if(pos >= pos1+len) goto done;
		de_dbg(c, "component[%d] info at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		prec = de_getbyte_p(&pos);
		de_dbg(c, "precision: %d", (int)prec);
		xr = de_getbyte_p(&pos);
		yr = de_getbyte_p(&pos);
		de_dbg(c, "separation: %d,%d", (int)xr, (int)yr);
		de_dbg_indent(c, -1);
	}

done:
	;
}

static void handler_tlm(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	de_byte b;
	de_byte item_size_code;
	de_int64 item_size;
	de_int64 pos = pos1;
	de_byte t_code, p_code;
	de_int64 t_size, p_size;
	de_int64 num_items;
	de_int64 k;

	if(len<2) goto done;
	b = de_getbyte_p(&pos);
	de_dbg(c, "index: %d", (int)b);

	item_size_code = (de_int64)de_getbyte_p(&pos);
	de_dbg(c, "item size code: 0x%02x", (unsigned int)item_size_code);
	de_dbg_indent(c, 1);
	t_code = (item_size_code & 0x30)>>4;
	de_dbg(c, "size code for number field: %d", (int)t_code);
	p_code = (item_size_code & 0x40)>>6;
	de_dbg(c, "size code for length field: %d", (int)p_code);
	de_dbg_indent(c, -1);
	if(t_code==0) t_size=0;
	else if(t_code==1) t_size = 1;
	else if(t_code==2) t_size = 2;
	else goto done;
	if(p_code==0) p_size = 2;
	else p_size = 4;
	item_size = t_size + p_size;

	num_items = (pos1 + len - pos)/item_size;
	de_dbg(c, "calculated number of items: %d", (int)num_items);

	for(k=0; k<num_items; k++) {
		de_int64 x;
		de_dbg(c, "item[%d] at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		if(t_size>0) {
			if(t_size==1) {
				x = (de_int64)de_getbyte_p(&pos);
			}
			else {
				x = de_getui16be_p(&pos);
			}
			de_dbg(c, "tile number: %u", (unsigned int)x);
		}

		if(p_size==2) {
			x = de_getui16be_p(&pos);
		}
		else {
			x = de_getui32be_p(&pos);
		}
		de_dbg(c, "tile length: %u", (unsigned int)x);
		de_dbg_indent(c, -1);
	}

done:
	;
}

static void handler_sot(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	de_int64 x;
	de_int64 b;
	de_int64 pos = pos1;

	pg->j2c_sot_pos = 0;
	pg->j2c_sot_length = 0;
	if(len<8) return;

	pg->j2c_sot_pos = pos1 - 4;
	x = de_getui16be_p(&pos);
	de_dbg(c, "tile number: %d", (int)x);
	pg->j2c_sot_length = de_getui32be_p(&pos);
	de_dbg(c, "length: %u", (unsigned int)pg->j2c_sot_length);
	b = de_getbyte_p(&pos);
	de_dbg(c, "tile-part instance: %d", (int)b);
	b = de_getbyte_p(&pos);
	de_dbg(c, "number of tile-parts: %d", (int)b);
}

static void handler_cod(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_byte coding_style;
	de_ucstring *s = NULL;
	de_byte b;
	de_int64 n;

	if(len<5) goto done;
	coding_style = de_getbyte_p(&pos);
	s = ucstring_create(c);

	if((coding_style&0xf8)==0) {
		switch(coding_style&0x01) {
		case 0x0: ucstring_append_flags_item(s, "entropy coder, without partitions"); break;
		case 0x1: ucstring_append_flags_item(s, "entropy coder, with partitions"); break;
		}
		switch((coding_style&0x02)>>1) {
		case 0x0: ucstring_append_flags_item(s, "no SOP segments"); break;
		case 0x1: ucstring_append_flags_item(s, "has SOP segments"); break;
		}
		switch((coding_style&0x04)>>2) {
		case 0x0: ucstring_append_flags_item(s, "no EPH segments"); break;
		case 0x1: ucstring_append_flags_item(s, "has EPH segments"); break;
		}
	}
	else {
		ucstring_append_flags_item(s, "?");
	}
	de_dbg(c, "coding style: 0x%02x (%s)", (unsigned int)coding_style,
		ucstring_getpsz(s));

	b = de_getbyte_p(&pos);
	de_dbg(c, "progression order: %d", (int)b);
	n = de_getui16be_p(&pos);
	de_dbg(c, "number of layers: %d", (int)n);
	b = de_getbyte_p(&pos);

	if(pos < pos1+len) {
		// TODO
		de_dbg2(c, "[not decoding the rest of this segment]");
	}

done:
	ucstring_destroy(s);
}

static void handler_qcd(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_byte q_style;

	if(len<1) goto done;
	q_style = de_getbyte_p(&pos);
	de_dbg(c, "quantization style: 0x%02x", (unsigned int)q_style);

	if(pos < pos1+len) {
		// TODO
		de_dbg2(c, "[not decoding the rest of this segment]");
	}
done:
	;
}

static void handler_qcc(deark *c, lctx *d, struct page_ctx *pg,
	const struct marker_info *mi, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 compnum;

	if(pg->ncomp<257) {
		compnum = de_getbyte_p(&pos);
	}
	else {
		compnum = de_getui16be_p(&pos);
	}
	de_dbg(c, "component number: %d", (int)compnum);

	if(pos < pos1+len) {
		// TODO
		de_dbg2(c, "[not decoding the rest of this segment]");
	}
}

static const struct marker_info1 marker_info1_arr[] = {
	{0x4f, 0x0100, "SOC", "Start of codestream", NULL},
	{0x51, 0x0000, "SIZ", "Image and tile size", handler_siz},
	{0x52, 0x0000, "COD", "Coding style default", handler_cod},
	{0x53, 0x0000, "COC", "Coding style component", NULL},
	{0x55, 0x0000, "TLM", "Tile-part lengths, main header", handler_tlm},
	{0x57, 0x0000, "PLM", "Packet length, main header", NULL},
	{0x58, 0x0000, "PLT", "Packet length, tile-part header", NULL},
	{0x5c, 0x0000, "QCD", "Quantization default", handler_qcd},
	{0x5d, 0x0000, "QCC", "Quantization component", handler_qcc},
	{0x5e, 0x0000, "RGN", "Region-of-interest", NULL},
	{0x5f, 0x0000, "POD", "Progression order default", NULL},
	{0x60, 0x0000, "PPM", "Packed packet headers, main header", NULL},
	{0x61, 0x0000, "PPT", "Packed packet headers, tile-part header", NULL},
	{0x64, 0x0000, "CME", "Comment and extension", handler_cme},
	{0x90, 0x0000, "SOT", "Start of tile-part", handler_sot},
	{0x91, 0x0000, "SOP", "Start of packet", NULL},
	{0x92, 0x0100, "EPH", "End of packet header", NULL},
	{0x93, 0x0100, "SOD", "Start of data", NULL},
	{0xd9, 0x0100, "EOC", "End of codestream", NULL}
};

// Caller allocates mi
static int get_marker_info(deark *c, lctx *d, struct page_ctx *pg, de_byte seg_type,
	struct marker_info *mi)
{
	de_int64 k;

	de_memset(mi, 0, sizeof(struct marker_info));
	mi->seg_type = seg_type;

	// First, try to find the segment type in the static marker info.
	for(k=0; k<(de_int64)DE_ITEMS_IN_ARRAY(marker_info1_arr); k++) {
		const struct marker_info1 *mi1 = &marker_info1_arr[k];

		if(mi1->seg_type == seg_type) {
			mi->flags = mi1->flags;
			mi->hfn = mi1->hfn;
			de_strlcpy(mi->shortname, mi1->shortname, sizeof(mi->shortname));
			if(mi1->longname) {
				de_snprintf(mi->longname, sizeof(mi->longname), "%s: %s",
					mi1->shortname, mi1->longname);
			}
			goto done;
		}
	}

	// Handle some pattern-based markers.

	// fcd15444-1: "The marker range 0xFF30 - 0xFF3F is reserved [...] for markers
	// without marker parameters."
	if(seg_type>=0x30 && seg_type<=0x3f) {
		mi->flags |= FLAG_NO_DATA;
	}

	de_strlcpy(mi->shortname, "???", sizeof(mi->shortname));
	de_strlcpy(mi->longname, "???", sizeof(mi->longname));
	return 0;

done:
	if(!mi->longname[0]) {
		// If no longname was set, use the shortname
		de_strlcpy(mi->longname, mi->shortname, sizeof(mi->longname));
	}
	return 1;
}

static void do_segment(deark *c, lctx *d, struct page_ctx *pg, const struct marker_info *mi,
	de_int64 payload_pos, de_int64 payload_size)
{
	de_dbg(c, "segment 0x%02x (%s) at %d, dpos=%d, dlen=%d",
		(unsigned int)mi->seg_type, mi->longname, (int)(payload_pos-4),
		(int)payload_pos, (int)payload_size);

	if(mi->hfn) {
		// If a handler function is available, use it.
		de_dbg_indent(c, 1);
		mi->hfn(c, d, pg, mi, payload_pos, payload_size);
		de_dbg_indent(c, -1);
	}
}

static int do_read_scan_data(deark *c, lctx *d, struct page_ctx *pg,
	de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_byte b0, b1;

	*bytes_consumed = c->infile->len - pos1; // default
	de_dbg(c, "scan data at %d", (int)pos1);

	de_dbg_indent(c, 1);

	if(pg->j2c_sot_length>0) {
		// The previous SOT segment may have told us where this scan data ends.
		*bytes_consumed = pg->j2c_sot_pos + pg->j2c_sot_length - pos1;
		if(*bytes_consumed < 0) *bytes_consumed = 0;
		de_dbg(c, "[%"INT64_FMT" bytes of scan data at %"INT64_FMT"]",
			*bytes_consumed, pos1);
		pg->j2c_sot_pos = 0;
		pg->j2c_sot_length = 0;
		goto done;
	}

	while(1) {
		if(pos >= c->infile->len) goto done;
		b0 = de_getbyte_p(&pos);
		if(b0==0xff) {
			b1 = de_getbyte_p(&pos);
			if(b1==0x00) {
				; // an escaped 0xff
			}
			else if(b1<0x90) {
				// In J2C, 0xff bytes are not escaped if they're followed by a
				// a byte less than 0x90.
				;
			}
			else if(b1==0xff) { // a "fill byte" (TODO: Does J2C have these?)
				pos--;
			}
			else {
				// A marker that is not part of the scan.
				// Subtract the bytes consumed by it, and stop.
				pos -= 2;
				*bytes_consumed = pos - pos1;
				de_dbg(c, "end of scan data found at %d (len=%d)", (int)pos, (int)*bytes_consumed);
				break;
			}
		}
	}

done:
	de_dbg_indent(c, -1);
	return 1;
}

// Process a single JPEG codestream (through the EOC marker).
// Note: This module is structured like this because the code was split off
// from the jpeg module. Support for multiple codestreams is disabled, and
// might never need to be implemented.)
static int do_j2c_page(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_byte b;
	de_int64 pos = pos1;
	de_int64 seg_size;
	de_byte seg_type;
	int found_marker;
	struct marker_info mi;
	de_int64 scan_byte_count;
	int retval = 0;
	struct page_ctx *pg = NULL;

	pg = de_malloc(c, sizeof(struct page_ctx));

	found_marker = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte_p(&pos);
		if(b==0xff) {
			found_marker = 1;
			continue;
		}

		if(!found_marker) {
			// Not an 0xff byte, and not preceded by an 0xff byte. Just ignore it.
			continue;
		}

		found_marker = 0; // Reset this flag.

		if(b==0x00) {
			continue; // Escaped 0xff
		}

		seg_type = b;

		get_marker_info(c, d, pg, seg_type, &mi);

		if(mi.flags & FLAG_NO_DATA) {
			de_dbg(c, "marker 0x%02x (%s) at %d", (unsigned int)seg_type,
				mi.longname, (int)(pos-2));

			if(seg_type==0xd9) { // EOC
				retval = 1;
				goto done;
			}

			if(seg_type==0x93) {
				// SOD (JPEG 2000 marker sort of like SOS)
				if(!do_read_scan_data(c, d, pg, pos, &scan_byte_count)) {
					break;
				}
				pos += scan_byte_count;
			}

			continue;
		}

		// If we get here, we're reading a segment that has a size field.
		seg_size = de_getui16be(pos);
		if(pos<2) break; // bogus size

		do_segment(c, d, pg, &mi, pos+2, seg_size-2);

		pos += seg_size;
	}

done:
	if(pg) {
		de_free(c, pg);
	}

	*bytes_consumed = pos - pos1;
	return retval;
}

static void do_j2c_internal(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 bytes_consumed;

	pos = 0;
	if(pos >= c->infile->len) goto done;
	bytes_consumed = 0;
	do_j2c_page(c, d, pos, &bytes_consumed);
done:
	;
}

static void de_run_j2c(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	de_declare_fmt(c, "JPEG 2000 codestream");
	d = de_malloc(c, sizeof(lctx));
	do_j2c_internal(c, d);
	de_free(c, d);
}

static int de_identify_j2c(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xff\x4f\xff\x51", 4))
		return 100;
	return 0;
}

void de_module_j2c(deark *c, struct deark_module_info *mi)
{
	mi->id = "j2c";
	mi->desc = "JPEG 2000 codestream";
	mi->run_fn = de_run_j2c;
	mi->identify_fn = de_identify_j2c;
}
