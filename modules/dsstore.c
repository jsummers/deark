// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// .DS_Store

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_dsstore);

#define HDRSIZE 4
#define DSSTORE_MAX_DEPTH 16

#define CODE_blob 0x626c6f62U
#define CODE_bool 0x626f6f6cU
#define CODE_comp 0x636f6d70U
#define CODE_dutc 0x64757463U
#define CODE_long 0x6c6f6e67U
#define CODE_shor 0x73686f72U
#define CODE_type 0x74797065U
#define CODE_ustr 0x75737472U

struct record_info {
	de_int64 dpos;
	de_int64 dlen;
	de_ucstring *filename;
	struct de_fourcc rtype;
	struct de_fourcc dtype;
};

struct addr_table_entry {
	de_uint32 addr_code;
	de_byte decoded;
};

typedef struct localctx_struct {
	de_int64 infoblk_offs;
	de_int64 infoblk_size;

	int found_dsdb;
	de_uint32 dsdb_block_id;

	de_uint32 root_node_block_id;

	de_int64 blkcount;
	struct addr_table_entry *block_addr_table; // 'blkcount' entries
	int depth;
} lctx;

static void do_dir_entry(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_uint32 blk_id;
	de_int64 pos = pos1;
	de_int64 nlen;
	struct de_stringreaderdata *name_srd = NULL;

	nlen = (de_int64)de_getbyte_p(&pos);
	*bytes_consumed = 1 + nlen + 4;
	name_srd = dbuf_read_string(c->infile, pos, nlen, nlen, 0, DE_ENCODING_MACROMAN);
	pos += nlen;
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(name_srd->str));
	blk_id = (de_uint32)de_getui32be_p(&pos);
	de_dbg(c, "block id: %u", (unsigned int)blk_id);

	if(!de_strcmp((const char*)name_srd->sz, "DSDB")) {
		d->found_dsdb = 1;
		d->dsdb_block_id = blk_id;
	}

	de_destroy_stringreaderdata(c, name_srd);
}

static void do_info_block(deark *c, lctx *d)
{
	de_int64 pos = d->infoblk_offs;
	de_int64 dircount;
	de_int64 blk_addr_array_start;
	de_int64 blk_addr_array_size_padded;
	de_int64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "info block at %"INT64_FMT, d->infoblk_offs);
	de_dbg_indent(c, 1);
	d->blkcount = de_getui32be_p(&pos);
	de_dbg(c, "block count: %u", (unsigned int)d->blkcount);
	if(d->blkcount>1000000) goto done;
	pos += 4; // unknown

	blk_addr_array_start = pos;
	blk_addr_array_size_padded = de_pad_to_n(d->blkcount*4, 1024);

	de_dbg(c, "block address table at %d", (int)pos);
	d->block_addr_table = de_malloc(c, d->blkcount * sizeof(struct addr_table_entry));
	de_dbg_indent(c, 1);
	for(k=0; k<d->blkcount; k++) {
		d->block_addr_table[k].addr_code = (de_uint32)de_getui32be_p(&pos);
		if(d->block_addr_table[k].addr_code!=0) {
			de_dbg(c, "addr[%d] = 0x%08x", (int)k,
				(unsigned int)d->block_addr_table[k].addr_code);
		}
	}
	de_dbg_indent(c, -1);

	pos = blk_addr_array_start + blk_addr_array_size_padded;
	dircount = de_getui32be_p(&pos);
	de_dbg(c, "dir count: %u", (unsigned int)dircount);
	if(dircount>1000000) goto done;
	for(k=0; k<dircount; k++) {
		de_int64 bytes_consumed;

		de_dbg(c, "dir entry[%d] at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		do_dir_entry(c, d, pos, &bytes_consumed);
		pos += bytes_consumed;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int block_id_to_offset_and_size(deark *c, lctx *d, de_uint32 blk_id,
	de_int64 *poffs, de_int64 *psize)
{
	int retval = 0;
	de_uint32 addr_code;
	unsigned int size_indicator;

	if((de_int64)blk_id>=d->blkcount) {
		goto done;
	}

	addr_code = d->block_addr_table[blk_id].addr_code;
	size_indicator = addr_code&0x1f;
	*psize = (de_int64)(1U<<size_indicator);
	*poffs = HDRSIZE+(de_int64)(addr_code-size_indicator);

	retval = 1;
done:
	if(!retval) {
		*poffs = c->infile->len;
		*psize = 0;
	}
	return retval;
}

static void do_blob(deark *c, lctx *d, struct record_info *ri)
{
	de_int64 len;
	de_int64 blobpos;

	len = de_getui32be(ri->dpos);
	de_dbg(c, "blob len: %d", (int)len);
	ri->dlen = 4+len;
	blobpos = ri->dpos+4;

	if(len>=8 && !dbuf_memcmp(c->infile, blobpos, "bplist00", 8)) {
		de_finfo *fi = NULL;
		de_ucstring *fn = NULL;

		de_dbg(c, "binary plist at %d", (int)blobpos);
		de_dbg_indent(c, 1);
		fn = ucstring_create(c);
		if(c->filenames_from_file) {
			ucstring_append_ucstring(fn, ri->filename);
			ucstring_append_sz(fn, ".", DE_ENCODING_LATIN1);
		}
		ucstring_printf(fn, DE_ENCODING_ASCII, "%s.plist", ri->rtype.id_sanitized_sz);
		fi = de_finfo_create(c);
		de_finfo_set_name_from_ucstring(c, fi, fn);
		de_fmtutil_handle_plist(c, c->infile, blobpos, len, fi, 0);
		ucstring_destroy(fn);
		de_finfo_destroy(c, fi);
		de_dbg_indent(c, -1);
	}
	else {
		de_dbg_hexdump(c, c->infile, blobpos, len, 256, NULL, 0x1);
	}
}

static void do_ustr(deark *c, lctx *d, struct record_info *ri)
{
	de_int64 len;
	de_ucstring *s = NULL;

	len = de_getui32be(ri->dpos);
	ri->dlen = 4+len;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, ri->dpos+4, len*2, DE_DBG_MAX_STRLEN*2, s, 0,
		DE_ENCODING_UTF16BE);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_record_int(deark *c, lctx *d, struct record_info *ri,
	de_int64 dpos, de_int64 dlen)
{
	de_int64 val;

	val = dbuf_getint_ext(c->infile, dpos, (unsigned int)dlen, 0, 0);
	de_dbg(c, "value: %"INT64_FMT, val);
}

static void do_record_date(deark *c, lctx *d, struct record_info *ri)
{
	de_uint64 val1;
	de_int64 val2;
	struct de_timestamp ts;
	char timestamp_buf[64];

	val1 = dbuf_getui64be(c->infile, ri->dpos);
	val2 = (de_int64)(val1>>16);
	de_mac_time_to_timestamp(val2, &ts);
	ts.tzcode = DE_TZCODE_UTC;
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "date: %"UINT64_FMT" (%s)", val1, timestamp_buf);
}

// Returns 1 if we calculated the bytes_consumed.
static int do_record(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 nlen;
	de_int64 pos = pos1;
	struct record_info ri;
	int retval = 0;

	de_zeromem(&ri, sizeof(struct record_info));

	nlen = de_getui32be_p(&pos);
	if(nlen>2048) goto done;
	ri.filename = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, nlen*2, ri.filename, 0, DE_ENCODING_UTF16BE);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(ri.filename));
	pos += 2*nlen;

	dbuf_read_fourcc(c->infile, pos, &ri.rtype, 4, 0x0);
	de_dbg(c, "record type: '%s'", ri.rtype.id_dbgstr);
	pos += 4;

	dbuf_read_fourcc(c->infile, pos, &ri.dtype, 4, 0x0);
	de_dbg(c, "data type: '%s'", ri.dtype.id_dbgstr);
	pos += 4;

	ri.dpos = pos;

	switch(ri.dtype.id) {
	case CODE_blob:
		do_blob(c, d, &ri);
		break;
	case CODE_bool:
		ri.dlen = 1;
		do_record_int(c, d, &ri, ri.dpos, ri.dlen);
		break;
	case CODE_comp:
		ri.dlen = 8;
		do_record_int(c, d, &ri, ri.dpos, ri.dlen);
		break;
	case CODE_dutc:
		ri.dlen = 8;
		do_record_date(c, d, &ri);
		break;
	case CODE_long:
		ri.dlen = 4;
		do_record_int(c, d, &ri, ri.dpos, ri.dlen);
		break;
	case CODE_shor:
		ri.dlen = 4;
		do_record_int(c, d, &ri, ri.dpos+2, 2);
		break;
	case CODE_type:
		ri.dlen = 4;
		break;
	case CODE_ustr:
		do_ustr(c, d, &ri);
		break;
	default:
		de_warn(c, "Unknown data type '%s'. Remaining records in this node cannot "
			"be processed.", ri.dtype.id_sanitized_sz);
		goto done;
	}
	if(ri.dlen<1) goto done;
	pos += ri.dlen;

	retval = 1;
done:
	*bytes_consumed = pos-pos1;
	ucstring_destroy(ri.filename);
	return retval;
}

static void do_one_node(deark *c, lctx *d, de_uint32 blk_id)
{
	de_int64 node_offs, node_size;
	unsigned int mode;
	de_int64 count;
	de_int64 pos;
	de_int64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d->depth++;
	if(d->depth > DSSTORE_MAX_DEPTH) goto done;
	if(blk_id >= d->blkcount) goto done;
	if(d->block_addr_table[blk_id].decoded) goto done;
	d->block_addr_table[blk_id].decoded = 1;

	if(!block_id_to_offset_and_size(c, d, blk_id, &node_offs,
		&node_size))
	{
		goto done;
	}

	de_dbg(c, "node: id=%u, offs=%d, len=%d", (unsigned int)blk_id,
		(int)node_offs, (int)node_size);
	de_dbg_indent(c, 1);
	pos = node_offs;
	mode = (unsigned int)de_getui32be_p(&pos);
	de_dbg(c, "mode: %u", mode);
	count = de_getui32be_p(&pos);
	de_dbg(c, "count: %d", (int)count);

	{
		// If 'mode' is 0, there are 'count' records here.
		de_int64 bytes_consumed = 0;

		if(mode!=0) {
			de_uint32 next_blk_id;
			next_blk_id = (de_uint32)de_getui32be_p(&pos);
			de_dbg(c, "next block id: %u", (unsigned int)next_blk_id);
			do_one_node(c, d, next_blk_id);
		}

		for(k=0; k<count; k++) {
			de_dbg(c, "record[%d] at %d (for node@%d)", (int)k, (int)pos, (int)node_offs);
			de_dbg_indent(c, 1);
			if(!do_record(c, d, pos, &bytes_consumed)) break;
			de_dbg_indent(c, -1);
			pos += bytes_consumed;
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	d->depth--;
}

static int do_dsdb(deark *c, lctx *d)
{
	de_int64 dsdb_offs, dsdb_size;
	de_int64 pos;
	de_int64 n;
	int retval = 0;

	if(!d->found_dsdb) goto done;
	if(!block_id_to_offset_and_size(c, d, d->dsdb_block_id, &dsdb_offs,
		&dsdb_size))
	{
		goto done;
	}

	de_dbg(c, "DSDB block: id=%u, offs=%d, len=%d", (unsigned int)d->dsdb_block_id,
		(int)dsdb_offs, (int)dsdb_size);

	de_dbg_indent(c, 1);
	pos = dsdb_offs;
	d->root_node_block_id = (de_uint32)de_getui32be_p(&pos);
	de_dbg(c, "root node block id: %u", (unsigned int)d->root_node_block_id);

	n = de_getui32be_p(&pos);
	de_dbg(c, "num levels: %d", (int)n);
	n = de_getui32be_p(&pos);
	de_dbg(c, "num records in tree: %d", (int)n);
	n = de_getui32be_p(&pos);
	de_dbg(c, "num blocks in tree: %d", (int)n);
	de_dbg_indent(c, -1);

	retval = 1;
done:
	return retval;
}

static void de_run_dsstore(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 8;
	d->infoblk_offs = de_getui32be_p(&pos);
	de_dbg(c, "info block offset: (%d+)%"INT64_FMT, HDRSIZE, d->infoblk_offs);
	d->infoblk_offs += HDRSIZE;
	d->infoblk_size = de_getui32be_p(&pos);
	de_dbg(c, "info block size: %"INT64_FMT, d->infoblk_size);

	do_info_block(c, d);

	if(!d->found_dsdb) {
		de_err(c, "DSDB block not found. This file is probably corrupted, or "
			"an unsupported version.");
		goto done;
	}
	if(!do_dsdb(c, d)) goto done;

	do_one_node(c, d, d->root_node_block_id);

done:
	if(d) {
		de_free(c, d->block_addr_table);
		de_free(c, d);
	}
}

static int de_identify_dsstore(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x00\x00\x01" "Bud1", 8))
		return 100;
	return 0;
}

static void de_help_dsstore(deark *c)
{
	de_msg(c, "-opt extractplist : Write plist records to files");
}

void de_module_dsstore(deark *c, struct deark_module_info *mi)
{
	mi->id = "dsstore";
	mi->desc = "Mac Finder .DS_Store format";
	mi->run_fn = de_run_dsstore;
	mi->identify_fn = de_identify_dsstore;
	mi->help_fn = de_help_dsstore;
}
