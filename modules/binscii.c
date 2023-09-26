// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// BinSCII (Apple II format)

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_binscii);

#define BINSCII_LINE_MAXLEN 72
#define BINSCII_ENCODED_UNITS_PER_LINE 16
#define BINSCII_DECODED_BYTES_PER_LINE (BINSCII_ENCODED_UNITS_PER_LINE*3)
#define BINSCII_ENCODED_BYTES_PER_LINE (BINSCII_ENCODED_UNITS_PER_LINE*4)
static const u8* g_binscii_seg_sig = (const u8*)"FiLeStArTfIlEsTaRt";

enum binscii_parse_state {
	BSC_NEUTRAL = 0,
	BSC_READY_FOR_HEADER1,
	BSC_READY_FOR_HEADER2,
	BSC_READY_FOR_DATA,
	BSC_READY_FOR_CRC
};

struct binscii_segment {
	i64 pos;
	i64 fn_len;
	i64 orig_len;
	i64 offset;
	u8 acmode;
	u8 filetype;
	UI auxtype;
	u8 storetype;
	i64 size_in_blocks;
	UI crdate_raw;
	UI crtime_raw;
	UI moddate_raw;
	UI modtime_raw;
	i64 segment_len;
	u32 hdr_crc_reported;
	i64 nbytes_processed;
	u8 bmap[256];
};

struct binscii_md {
	UI seg_count; // Num segments encountered so far (maybe unused)
	i64 orig_len;
	i64 nbytes_written;
	de_ucstring *fn;
	dbuf *outf;
	struct de_timestamp mod_time;
	struct de_timestamp create_time;
};

struct binscii_ctx  {
	struct binscii_md *cur_md;
	enum binscii_parse_state parse_state;
	u8 errflag;
	u8 need_errmsg;
	UI seg_count_total;
	i64 pos;
	dbuf *tmpdbuf;
	struct de_crcobj *crco_header;
	struct de_crcobj *crco_segdata;
	i64 linebuf_used;
	u8 linebuf[BINSCII_LINE_MAXLEN];
	struct binscii_segment cur_seg;
};

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void de_prodos_datetime_to_timestamp(struct de_timestamp *ts,
	i64 ddate, i64 dtime)
{
	i64 yr, mo, da, hr, mi, se;

	if(ddate==0 || (dtime&0xe0c0)!=0) {
		de_zeromem(ts, sizeof(struct de_timestamp));
		ts->is_valid = 0;
		return;
	}

	yr = 1900+((ddate&0xfe00)>>9);
	mo = (ddate&0x01e0)>>5;
	da = (ddate&0x001f);
	hr = (dtime&0x1f00)>>8;
	mi = (dtime&0x003f);
	se = 0;
	de_make_timestamp(ts, yr, mo, da, hr, mi, se);
	ts->precision = DE_TSPREC_1MIN;
}

static void binscii_set_generic_error(deark *c, struct binscii_ctx *d)
{
	if(d->errflag) return;
	d->errflag = 1;
	d->need_errmsg = 1;
}

// Destroys d->cur_md
static void binscii_close_cur_file(deark *c, struct binscii_ctx *d)
{
	struct binscii_md *md;

	md = d->cur_md;
	if(!d->cur_md) return;
	de_dbg(c, "closing file");
	if(d->cur_md->orig_len != d->cur_md->nbytes_written) {
		binscii_set_generic_error(c, d);
	}
	dbuf_close(md->outf);
	ucstring_destroy(md->fn);
	de_free(c, md);
	d->cur_md = NULL;
}

static struct binscii_md *binscii_create_md(deark *c)
{
	struct binscii_md *md;

	md = de_malloc(c, sizeof(struct binscii_md));
	return md;
}

// Decode some encoded "units", from memory to a dbuf.
// Each unit is 4 bytes encoded, 3 bytes decoded.
static void binscii_decode(deark *c, struct binscii_ctx *d, const u8 *src,
	i64 num_units, dbuf *outf)
{
	i64 i;
	u8 ib[4];

	for(i=0; i<num_units; i++) {
		UI j;

		for(j=0; j<4; j++) {
			ib[j] = d->cur_seg.bmap[(UI)src[i*4+j]];
		}
		dbuf_writebyte(outf, (ib[3]<<2)|(ib[2]>>4));
		dbuf_writebyte(outf, ((ib[2]&0x0f)<<4)|(ib[1]>>2));
		dbuf_writebyte(outf, ((ib[1]&0x03)<<6)|ib[0]);
	}
}

static void do_binscii_header1(deark *c, struct binscii_ctx *d)
{
	i64 i;

	// The "alphabet" line
	for(i=0; i<64; i++) {
		d->cur_seg.bmap[(UI)d->linebuf[i]] = (u8)i;
	}
}

static void binscii_create_output_file(deark *c, struct binscii_ctx *d)
{
	de_finfo *fi = NULL;

	if(!d->cur_md) {
		binscii_set_generic_error(c, d);
		goto done;
	}
	if(d->cur_md->outf) {
		binscii_set_generic_error(c, d);
		goto done;
	}

	fi = de_finfo_create(c);
	if(d->cur_md->fn) {
		de_finfo_set_name_from_ucstring(c, fi, d->cur_md->fn, 0);
		fi->original_filename_flag = 1;
	}
	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = d->cur_md->mod_time;
	fi->timestamp[DE_TIMESTAMPIDX_CREATE] = d->cur_md->create_time;

	d->cur_md->outf = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_enable_wbuffer(d->cur_md->outf);

done:
	de_finfo_destroy(c, fi);
}

static void do_binscii_header2(deark *c, struct binscii_ctx *d)
{
	i64 pos;
	u32 hdr_crc_calc;
	u8 is_first_seg;
	struct binscii_segment *seg = &d->cur_seg;
	de_ucstring *fn = NULL;

	// Some fields we process for all segments.
	// Others we only process only for the first segment of a file
	// (or we process them differently).

	// TODO: Does the fn length use d->bmap, or is the coding fixed as
	// 'A'=1, 'B'==2, ... ?
	// (Some BinSCII decoders do it one way, some do it the other.)
	if(d->linebuf[0]>=64+1 && d->linebuf[0]<=64+15) {
		seg->fn_len = (i64)d->linebuf[0] - 64;
	}
	else {
		binscii_set_generic_error(c, d);
		goto done;
	}
	fn = ucstring_create(c);
	ucstring_append_bytes(fn, &d->linebuf[1],
		seg->fn_len, 0, DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(fn));

	dbuf_empty(d->tmpdbuf);
	binscii_decode(c, d, &d->linebuf[16], 9, d->tmpdbuf);

	pos = 0;
	seg->orig_len = dbuf_getint_ext(d->tmpdbuf, pos, 3, 1, 0);
	de_dbg(c, "orig len: %"I64_FMT, seg->orig_len);
	pos += 3;

	seg->offset = dbuf_getint_ext(d->tmpdbuf, pos, 3, 1, 0);
	de_dbg(c, "seg offset: %"I64_FMT, seg->offset);
	pos += 3;

	is_first_seg = (seg->offset==0);

	if(is_first_seg) {
		// If we're already in the middle of a file, close it.
		if(d->cur_md) {
			binscii_close_cur_file(c, d);
			if(d->errflag) goto done;
		}

		// Open a new file
		d->cur_md = binscii_create_md(c);
	}

	if(!d->cur_md) {
		binscii_set_generic_error(c, d);
		goto done;
	}

	// After this point, we can freely use both cur_md and cur_seg.

	if(is_first_seg) {
		d->cur_md->orig_len = seg->orig_len;
	}

	if(is_first_seg) {
		// TODO: Better decoding & use of file attributes
		seg->acmode = dbuf_getbyte_p(d->tmpdbuf, &pos);
		de_dbg(c, "access mode: 0x%02x", (UI)seg->acmode);
		seg->filetype = dbuf_getbyte_p(d->tmpdbuf, &pos);
		de_dbg(c, "file type: 0x%02x", (UI)seg->filetype);
		seg->auxtype = (UI)dbuf_getu16le_p(d->tmpdbuf, &pos);
		de_dbg(c, "aux file type: 0x%04x", (UI)seg->auxtype);
		seg->storetype = dbuf_getbyte_p(d->tmpdbuf, &pos);
		de_dbg(c, "storage type: 0x%02x", (UI)seg->storetype);
		seg->size_in_blocks = dbuf_getu16le_p(d->tmpdbuf, &pos);
		de_dbg(c, "orig len in blocks: %"I64_FMT, seg->size_in_blocks);
	}
	else {
		pos += 7;
	}

	if(is_first_seg) {
		seg->crdate_raw = (UI)dbuf_getu16le_p(d->tmpdbuf, &pos);
		seg->crtime_raw = (UI)dbuf_getu16le_p(d->tmpdbuf, &pos);
		de_prodos_datetime_to_timestamp(&d->cur_md->create_time, seg->crdate_raw, seg->crtime_raw);
		dbg_timestamp(c, &d->cur_md->create_time, "create time");
		seg->moddate_raw = (UI)dbuf_getu16le_p(d->tmpdbuf, &pos);
		seg->modtime_raw = (UI)dbuf_getu16le_p(d->tmpdbuf, &pos);
		de_prodos_datetime_to_timestamp(&d->cur_md->mod_time, seg->moddate_raw, seg->modtime_raw);
		dbg_timestamp(c, &d->cur_md->mod_time, "mod time");
	}
	else {
		pos += 8;
	}

	seg->segment_len = dbuf_getint_ext(d->tmpdbuf, pos, 3, 1, 0);
	de_dbg(c, "seg len: %"I64_FMT, seg->segment_len);
	pos += 3;

	seg->hdr_crc_reported = (u32)dbuf_getu16le_p(d->tmpdbuf, &pos);
	de_dbg(c, "header crc (reported): 0x%04x", (UI)seg->hdr_crc_reported);
	de_crcobj_reset(d->crco_header);
	de_crcobj_addslice(d->crco_header, d->tmpdbuf, 0, 24);
	hdr_crc_calc = de_crcobj_getval(d->crco_header);
	de_dbg(c, "header crc (calculated): 0x%04x", (UI)hdr_crc_calc);

	if(hdr_crc_calc!=seg->hdr_crc_reported) {
		de_err(c, "Header CRC check failed for segment at %"I64_FMT, d->cur_seg.pos);
		d->errflag = 1;
		goto done;
	}

	if(seg->offset != d->cur_md->nbytes_written) {
		binscii_set_generic_error(c, d);
		goto done;
	}

	if(is_first_seg) {
		if(!d->cur_md->fn) {
			d->cur_md->fn = ucstring_clone(fn);
		}
		if(!d->cur_md->outf) {
			binscii_create_output_file(c, d);
		}
	}

	d->cur_md->seg_count++;
done:
	ucstring_destroy(fn);
}

static void do_binscii_data_line(deark *c, struct binscii_ctx *d)
{
	i64 amt_to_write;

	if(!d->cur_md || !d->cur_md->outf) goto done;

	dbuf_empty(d->tmpdbuf);
	binscii_decode(c, d, d->linebuf, BINSCII_ENCODED_UNITS_PER_LINE, d->tmpdbuf);

	// CRC calculation includes padding bytes.
	de_crcobj_addslice(d->crco_segdata, d->tmpdbuf, 0, BINSCII_DECODED_BYTES_PER_LINE);

	amt_to_write = d->cur_md->orig_len - d->cur_md->nbytes_written;
	amt_to_write = de_min_int(amt_to_write, BINSCII_DECODED_BYTES_PER_LINE);
	dbuf_copy(d->tmpdbuf, 0, amt_to_write, d->cur_md->outf);

	d->cur_seg.nbytes_processed += BINSCII_DECODED_BYTES_PER_LINE;
	if(d->cur_seg.nbytes_processed >= d->cur_seg.segment_len) {
		d->parse_state = BSC_READY_FOR_CRC;
	}

	d->cur_md->nbytes_written += amt_to_write;

done:
	;
}

static void do_binscii_crc_line(deark *c, struct binscii_ctx *d)
{
	u32 crc_reported, crc_calc;

	if(!d->cur_md) goto done;

	// For a CRC line, we expect linebuf_used==4.
	if(d->linebuf_used<4 || d->linebuf_used>=BINSCII_ENCODED_BYTES_PER_LINE) {
		binscii_set_generic_error(c, d);
		goto done;
	}

	dbuf_empty(d->tmpdbuf);
	binscii_decode(c, d, d->linebuf, 1, d->tmpdbuf);
	crc_reported = (u32)dbuf_getu16le(d->tmpdbuf, 0);
	de_dbg(c, "segment data crc (reported): 0x%04x", (UI)crc_reported);

	crc_calc = de_crcobj_getval(d->crco_segdata);
	de_dbg(c, "segment data crc (calculated): 0x%04x", (UI)crc_calc);

	if(crc_calc!=crc_reported) {
		de_err(c, "Data CRC check failed for segment at %"I64_FMT, d->cur_seg.pos);
		d->errflag = 1;
		goto done;
	}

	if(d->cur_md->nbytes_written >= d->cur_md->orig_len) {
		binscii_close_cur_file(c, d);
	}

done:
	;
}

// Caller sets d->linebuf, d->linebuf_used
static void do_binscii_line(deark *c, struct binscii_ctx *d)
{
	switch(d->parse_state) {
	case BSC_NEUTRAL:
		if(!de_memcmp(d->linebuf, g_binscii_seg_sig, 18)) {
			de_zeromem(&d->cur_seg, sizeof(struct binscii_segment));
			d->cur_seg.pos = d->pos;
			de_crcobj_reset(d->crco_segdata);
			de_dbg(c, "segment at %"I64_FMT, d->cur_seg.pos);
			de_dbg_indent(c, 1);
			d->parse_state = BSC_READY_FOR_HEADER1;
			d->seg_count_total++;
		}
		break;
	case BSC_READY_FOR_HEADER1:
		do_binscii_header1(c, d);
		d->parse_state = BSC_READY_FOR_HEADER2;
		break;
	case BSC_READY_FOR_HEADER2:
		do_binscii_header2(c, d);
		d->parse_state = BSC_READY_FOR_DATA;
		break;
	case BSC_READY_FOR_DATA:
		do_binscii_data_line(c, d);
		break;
	case BSC_READY_FOR_CRC:
		do_binscii_crc_line(c, d);
		d->parse_state = BSC_NEUTRAL;
		de_dbg_indent(c, -1);
		break;
	}
}

static void de_run_binscii(deark *c, de_module_params *mparams)
{
	struct binscii_ctx *d = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct binscii_ctx));
	d->tmpdbuf = dbuf_create_membuf(c, 128, 0);
	d->crco_segdata = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);
	d->crco_header = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);

	while(1) {
		int ret;
		i64 content_len, total_len;

		if(d->errflag) goto done;
		ret = dbuf_find_line(c->infile, d->pos, &content_len, &total_len);
		if(!ret) goto done;

		d->linebuf_used = (content_len<=BINSCII_LINE_MAXLEN) ? content_len : BINSCII_LINE_MAXLEN;
		de_zeromem(d->linebuf, BINSCII_LINE_MAXLEN);
		de_read(d->linebuf, d->pos, d->linebuf_used);
		do_binscii_line(c, d);
		d->pos += total_len;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	if(d) {
		binscii_close_cur_file(c, d);
		dbuf_close(d->tmpdbuf);
		de_crcobj_destroy(d->crco_header);
		de_crcobj_destroy(d->crco_segdata);
		if(d->need_errmsg) {
			de_err(c, "Failed to decode file");
		}
		else if(d->seg_count_total==0 && !d->errflag) {
			de_err(c, "No BinSCII data found");
		}
		de_free(c, d);
	}
}

static int de_identify_binscii(deark *c)
{
	int has_ext;
	int ret;
	i64 foundpos;

	has_ext = de_input_file_has_ext(c, "bsc") ||
		de_input_file_has_ext(c, "bsq");
	if(!dbuf_memcmp(c->infile, 0, g_binscii_seg_sig, 18)) {
		return has_ext?100:90;
	}

	if(!has_ext) return 0;

	ret = dbuf_search(c->infile, g_binscii_seg_sig, 18, 0, 4096, &foundpos);
	if(ret) {
		// TODO? We could do better, by making sure the string starts at the
		// beginning of a line, etc.
		return 35;
	}
	return 0;
}

void de_module_binscii(deark *c, struct deark_module_info *mi)
{
	mi->id = "binscii";
	mi->desc = "BinSCII";
	mi->run_fn = de_run_binscii;
	mi->identify_fn = de_identify_binscii;
}
