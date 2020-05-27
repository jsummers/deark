// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Amiga disk image (ADF)
// Amiga DMS (Disk Masher System) disk image

// The DMS module was developed with the help of information from xDMS -
// public domain software by Andre Rodrigues de la Rocha.
//
// Note: Unfortunately, I might never finish the DMS module, because on closer
// inspection, the source code I really need (the algorithms that use Huffman
// coding) appears to be potentially a lot less public domain than advertised.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_amiga_adf);
DE_DECLARE_MODULE(de_module_amiga_dms);

#define ADF_T_HEADER      2
#define ADF_T_DATA        8
#define ADF_T_LIST        16

#define ADF_ST_ROOT       1
#define ADF_ST_USERDIR    2
#define ADF_ST_FILE       (-3)

#define MAX_ADF_BLOCKS 3520
#define MAX_NESTING_LEVEL 16

struct block_ptrs_tbl {
	i64 high_seq;
	i64 blocks_tbl_capacity;
	i64 *blocks_tbl; // array[blocks_tbl_capacity]
};

struct member_data {
	i64 header_blknum;
	i64 header_pos;

	u8 is_dir;
	i64 fsize;
	i64 first_data_block;
	i64 first_ext_block;
	int sec_type;
	de_ucstring *fn;
	struct de_timestamp mod_time;

	dbuf *outf;
	i64 nbytes_written;
	i64 next_block_to_read;
	de_finfo *fi;
	struct block_ptrs_tbl tmpbpt; // reused for each extension block
};

typedef struct localctx_struct {
	u8 is_ffs;
	u8 intnl_mode;
	u8 dirc_mode;
	i64 bsize;
	i64 root_block;
	i64 num_blocks;
	int nesting_level;
	u8 bootblock_flags;
	u8 *block_used_flags; // array[num_blocks]
	struct de_strarray *curpath;
} lctx;

static i64 blocknum_to_offset(lctx *d, i64 blknum)
{
	return d->bsize * blknum;
}

static void on_adf_error(deark *c, lctx *d, int code)
{
	de_err(c, "ADF decode error (%d)", code);
}

// Remember which blocks have been processed, to prevent infinite loops.
// In failure, reports an error and returns 0.
static int claim_block(deark *c, lctx *d, i64 blknum)
{
	if(blknum<0 || blknum>=d->num_blocks) {
		de_err(c, "Bad block number: %"I64_FMT, blknum);
		return 0;
	}
	if(!d->block_used_flags) {
		d->block_used_flags = de_malloc(c, d->num_blocks);
	}
	if(d->block_used_flags[blknum]) {
		de_err(c, "Attempt to reuse block #%"I64_FMT, blknum);
		return 0;
	}
	d->block_used_flags[blknum] = 1;
	return 1;
}

// Reads a file data block.
// On success, returns nonzero and sets md->next_block_to_read.
static int do_file_ofs_data_block(deark *c, lctx *d, struct member_data *md,
	i64 seq_num_expected, i64 blknum)
{
	i64 pos1, pos;
	i64 data_size;
	i64 dpos;
	i64 n;
	int blocktype;
	int retval = 0;
	int dbg = (c->debug_level>=2);
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = blocknum_to_offset(d, blknum);
	if(dbg) de_dbg(c, "data block: blk#%"I64_FMT" (%"I64_FMT"), seq=%d", blknum, pos1,
		(int)seq_num_expected);
	de_dbg_indent(c, 1);

	if(!claim_block(c, d, blknum)) {
		goto done;
	}

	pos = pos1;
	blocktype = (int)de_geti32be_p(&pos);
	if(dbg) de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_DATA) {
		de_err(c, "%s: Bad block type in data block %d (%d, expected %d)",
			ucstring_getpsz_d(md->fn), (int)seq_num_expected,
			blocktype, (int)ADF_T_DATA);
		goto done;
	}

	n = de_getu32be_p(&pos);
	if(dbg) de_dbg(c, "header_key: %u", (UI)n);
	if(n!=md->header_blknum) {
		on_adf_error(c, d, 12);
		goto done;
	}

	n = de_getu32be_p(&pos);
	if(dbg) de_dbg(c, "seq_num: %u", (UI)n);
	if(n!=seq_num_expected) {
		on_adf_error(c, d, 13);
		goto done;
	}
	data_size = de_getu32be_p(&pos);
	if(dbg) de_dbg(c, "data size: %"I64_FMT, data_size);
	if(data_size > d->bsize-24) {
		de_err(c, "%s: Bad data size in data block %d (%"I64_FMT", max=%"I64_FMT")",
			ucstring_getpsz_d(md->fn), (int)seq_num_expected,
			data_size, (i64)(d->bsize-24));
		goto done;
	}
	if(md->nbytes_written + data_size > md->fsize) {
		on_adf_error(c, d, 15);
		goto done;
	}

	md->next_block_to_read = de_getu32be_p(&pos);
	if(dbg) de_dbg(c, "next data block: %"I64_FMT, md->next_block_to_read);

	dpos = pos1 + 24;
	dbuf_copy(c->infile, dpos, data_size, md->outf);
	md->nbytes_written += data_size;

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void read_ofs_timestamp(deark *c, i64 pos1, struct de_timestamp *ts,
	const char *name)
{
	i64 pos = pos1;
	i64 days, mins, ticks;
	i64 ut;
	char timestamp_buf[64];

	ts->is_valid = 0;
	days = de_getu32be_p(&pos);
	mins = de_getu32be_p(&pos);
	ticks = de_getu32be_p(&pos);
	ut = (6*365 + 2*366) * 86400; // 1970-01-01 to 1978-01-01
	ut += days * 86400;
	ut += mins * 60;
	ut += ticks / 50;

	if(days!=0) {
		de_unix_time_to_timestamp(ut, ts, 0);
		de_timestamp_set_subsec(ts, (double)(ticks%50) / 50.0);
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_strlcpy(timestamp_buf, "none", sizeof(timestamp_buf));
	}

	de_dbg(c, "%s: [%"I64_FMT",%"I64_FMT",%"I64_FMT"] (%s)",
		name, days, mins, ticks, timestamp_buf);
}

static void read_file_ofs_style(deark *c, lctx *d, struct member_data *md)
{
	i64 seq_num;

	md->next_block_to_read = md->first_data_block;
	seq_num = 1;
	while(1) {
		int ret;

		if(md->next_block_to_read==0) break;

		ret = do_file_ofs_data_block(c, d, md, seq_num, md->next_block_to_read);
		if(!ret) goto done;
		seq_num++;
	}
done:
	;
}

static void read_blocks_table(deark *c, lctx *d, i64 pos, struct block_ptrs_tbl *bpt)
{
	i64 k;

	for(k=0; k<bpt->blocks_tbl_capacity; k++) {
		bpt->blocks_tbl[k] = de_getu32be(pos + 4*k);
		if(c->debug_level>=2 && bpt->blocks_tbl[k]!=0) {
			de_dbg2(c, "blktbl[%d]: %u", (int)k, (UI)bpt->blocks_tbl[k]);
		}
	}
}

static int read_file_segment_from_blocks_tbl(deark *c, lctx *d, struct member_data *md)
{
	i64 nbytes_left_to_copy;
	i64 k;
	int retval = 0;

	nbytes_left_to_copy = md->fsize - md->outf->len;

	for(k=0; k<md->tmpbpt.high_seq; k++) {
		i64 blknum;
		i64 blkpos;
		i64 nbytes_to_copy;

		if(nbytes_left_to_copy<1) break;

		blknum = md->tmpbpt.blocks_tbl[md->tmpbpt.blocks_tbl_capacity-1-k];
		if(!claim_block(c, d, blknum)) {
			goto done;
		}

		blkpos = blocknum_to_offset(d, blknum);
		nbytes_to_copy = d->bsize;
		if(!d->is_ffs) {
			// TODO: If we allow this, it might be better to call
			// do_file_ofs_data_block(), somehow.
			blkpos += 24;
			nbytes_to_copy -= 24;
		}

		if(nbytes_to_copy > nbytes_left_to_copy) {
			nbytes_to_copy = nbytes_left_to_copy;
		}
		dbuf_copy(c->infile, blkpos, nbytes_to_copy, md->outf);
		nbytes_left_to_copy -= nbytes_to_copy;
	}
	retval = 1;

done:
	return retval;
}

static int read_file_segment_from_extension_block(deark *c, lctx *d, struct member_data *md,
	i64 blknum, i64 *pnextblock)
{
	u64 pos1;
	int blocktype;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	pos1 = blocknum_to_offset(d, blknum);
	de_dbg(c, "file ext. block #%"I64_FMT, blknum);
	de_dbg_indent(c, 1);

	if(!claim_block(c, d, blknum)) {
		goto done;
	}

	blocktype = (int)de_geti32be(pos1);
	de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_LIST) {
		de_err(c, "%s: Bad extension block type in (%d, expected %d)",
			ucstring_getpsz_d(md->fn), blocktype, (int)ADF_T_LIST);
		goto done;
	}

	md->tmpbpt.high_seq = de_getu32be(pos1+8);
	de_dbg(c, "high_seq: %u", (UI)md->tmpbpt.high_seq);
	read_blocks_table(c, d, pos1+24, &md->tmpbpt);

	if(!read_file_segment_from_blocks_tbl(c, d, md)) {
		goto done;
	}

	*pnextblock = de_getu32be(pos1+d->bsize-8);
	de_dbg(c, "next ext. block: %"I64_FMT, (i64)(*pnextblock));

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void read_file_using_blocks_table(deark *c, lctx *d, struct member_data *md)
{
	i64 cur_ext_header_blk;

	if(md->tmpbpt.high_seq > md->tmpbpt.blocks_tbl_capacity) {
		on_adf_error(c, d, 30);
		goto done;
	}

	// Process the blocks table stored in the main file header
	if(!read_file_segment_from_blocks_tbl(c, d, md)) goto done;

	// Process the chain of extended header blocks
	if(md->first_ext_block) {
		cur_ext_header_blk = md->first_ext_block;
		while(1) {
			i64 next_ext_header_blk = 0;

			if(cur_ext_header_blk == 0) break;
			if(md->outf->len >= md->fsize) break;

			if(!read_file_segment_from_extension_block(c, d, md, cur_ext_header_blk,
				&next_ext_header_blk))
			{
				goto done;
			}
			cur_ext_header_blk = next_ext_header_blk;
		}
	}

	if(md->outf->len < md->fsize) {
		on_adf_error(c, d, 26);
		goto done;
	}

done:
	;
}

static void read_protection_flags(deark *c, lctx *d, struct member_data *md, i64 pos)
{
	UI n;

	n = (UI)de_getu32be(pos);
	de_dbg(c, "protection flags: 0x%08x", n);
	if(md->fi && !md->is_dir) {
		// Some disks use the 0x2 bit to mean "non executable", but I don't think
		// there's a good way to tell *which* disks.
		if((n & 0x0000ff0f)!=0) { // If these flags seem to be used...
			if(n & 0x00000002) {
				md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
			}
			else {
				md->fi->mode_flags |= DE_MODEFLAG_EXE;
			}
		}
	}
}

static void do_file(deark *c, lctx *d, struct member_data *md)
{
	i64 pos1, pos;
	i64 fnlen;
	i64 header_key;
	i64 blocks_tbl_pos;
	i64 n;
	int need_curpath_pop = 0;
	de_ucstring *fullfn = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(md->sec_type!=ADF_ST_FILE) goto done;
	pos1 = md->header_pos;
	de_dbg(c, "file, header at blk#%"I64_FMT" (%"I64_FMT")", md->header_blknum, pos1);
	de_dbg_indent(c, 1);

	pos = pos1 + 4;
	header_key = de_getu32be_p(&pos);
	de_dbg(c, "header_key: %u", (UI)header_key);
	md->tmpbpt.high_seq = de_getu32be_p(&pos);
	de_dbg(c, "high_seq: %u", (UI)md->tmpbpt.high_seq);
	pos += 4; // data_size - unused
	md->first_data_block = de_getu32be_p(&pos);
	de_dbg(c, "first data block: %"I64_FMT, md->first_data_block);

	if(header_key!=md->header_blknum) {
		de_err(c, "Bad self-pointer (%"I64_FMT") in block #%"I64_FMT, header_key,
			md->header_blknum);
		goto done;
	}

	blocks_tbl_pos = md->header_pos + 24;
	md->tmpbpt.blocks_tbl_capacity = (d->bsize/4) - 56;
	md->tmpbpt.blocks_tbl = de_mallocarray(c, md->tmpbpt.blocks_tbl_capacity,
		sizeof(md->tmpbpt.blocks_tbl[0]));

	read_blocks_table(c, d, blocks_tbl_pos, &md->tmpbpt);

	read_protection_flags(c, d, md, pos1+d->bsize-192);

	pos = pos1+d->bsize-188;
	md->fsize = de_getu32be_p(&pos);
	de_dbg(c, "file size: %"I64_FMT, md->fsize);

	pos = pos1+d->bsize-92;
	read_ofs_timestamp(c, pos, &md->mod_time, "mod time");

	pos = pos1+d->bsize-80;
	fnlen = (i64)de_getbyte_p(&pos);
	if(fnlen>30) fnlen=30;
	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, fnlen, md->fn, 0, DE_ENCODING_LATIN1);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	de_strarray_push(d->curpath, md->fn);
	need_curpath_pop = 1;

	pos = pos1+d->bsize-12;
	n = de_getu32be_p(&pos);
	de_dbg(c, "parent dir: %"I64_FMT, n);
	md->first_ext_block = de_getu32be_p(&pos);
	de_dbg(c, "first ext. block: %"I64_FMT, md->first_ext_block);

	if(md->sec_type!=ADF_ST_FILE) {
		de_dbg(c, "[not a supported file type]");
		goto done;
	}

	md->fi->original_filename_flag = 1;
	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
	de_finfo_set_name_from_ucstring(c, md->fi, fullfn, DE_SNFLAG_FULLPATH);

	if(md->mod_time.is_valid) {
		md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;
	}

	md->outf = dbuf_create_output_file(c, NULL, md->fi, 0x0);

	if(d->is_ffs) {
		read_file_using_blocks_table(c, d, md);
	}
	else {
		read_file_ofs_style(c, d, md);
	}

done:
	if(need_curpath_pop) {
		de_strarray_pop(d->curpath);
	}
	ucstring_destroy(fullfn);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_header_block(deark *c, lctx *d, i64 blknum);

static void do_file_list(deark *c, lctx *d, i64 blknum)
{
	i64 pos1;
	i64 next_in_chain;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	pos1 = blocknum_to_offset(d, blknum);
	de_dbg(c, "file list starting at blk#%"I64_FMT, blknum);
	de_dbg_indent(c, 1);

	while(1) {
		if(blknum<1) break;
		if(!do_header_block(c, d, blknum)) goto done;
		next_in_chain = de_getu32be(pos1+d->bsize-16);
		de_dbg(c, "next: %"I64_FMT, next_in_chain);
		blknum = next_in_chain;
		pos1 = blocknum_to_offset(d, blknum);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_hashtable(deark *c, lctx *d, i64 pos1, i64 ht_size_in_longs)
{
	i64 k;
	i64 pos = pos1;
	int saved_indent_level;
	i64 used_count = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "hashtable at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	for(k=0; k<ht_size_in_longs; k++) {
		i64 n;
		n = de_getu32be_p(&pos);
		if(n>0 || c->debug_level>=2) {
			de_dbg(c, "ht[%u]: %u", (UI)k, (UI)n);
		}
		if(n>0) {
			used_count++;
			de_dbg_indent(c, 1);
			do_file_list(c, d, n);
			de_dbg_indent(c, -1);
		}
	}
	de_dbg(c, "hash buckets in use: %d of %d", (int)used_count, (int)ht_size_in_longs);

	de_dbg_indent_restore(c, saved_indent_level);
}

// ST_ROOT or ST_USERDIR
static void do_directory(deark *c, lctx *d, struct member_data *md)
{
	i64 pos1;
	i64 ht_size_in_longs;
	int saved_indent_level;
	int need_curpath_pop = 0;
	de_ucstring *fullfn = NULL;
	struct de_timestamp tmpts;

	de_dbg_indent_save(c, &saved_indent_level);

	md->is_dir = 1;
	pos1 = md->header_pos;
	de_dbg(c, "directory header block: #%"I64_FMT" (%"I64_FMT")", md->header_blknum, pos1);
	de_dbg_indent(c, 1);
	if(md->sec_type!=ADF_ST_ROOT && md->sec_type!=ADF_ST_USERDIR) {
		goto done;
	}

	if(md->sec_type==ADF_ST_ROOT) {
		ht_size_in_longs = de_getu32be(pos1+12);
		de_dbg(c, "hashtable size: %"I64_FMT" longwords", ht_size_in_longs);
		if(ht_size_in_longs>128) {
			on_adf_error(c, d, 20);
			goto done;
		}
	}
	else {
		ht_size_in_longs = (d->bsize/4) - 56;
	}

	read_protection_flags(c, d, md, pos1+d->bsize-192);

	read_ofs_timestamp(c, pos1+d->bsize-92, &md->mod_time, "dir mod time");

	if(md->sec_type==ADF_ST_USERDIR) {
		i64 fnlen;

		fnlen = (i64)de_getbyte(pos1+d->bsize-80);
		if(fnlen>30) fnlen=30;
		md->fn = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos1+d->bsize-79, fnlen, md->fn, 0, DE_ENCODING_LATIN1);
		de_dbg(c, "dirname: \"%s\"", ucstring_getpsz_d(md->fn));
		de_strarray_push(d->curpath, md->fn);
		need_curpath_pop = 1;
	}

	if(md->sec_type==ADF_ST_ROOT) {
		read_ofs_timestamp(c, pos1+d->bsize-40, &tmpts, "disk mod time");
		read_ofs_timestamp(c, pos1+d->bsize-28, &tmpts, "filesystem create time");
	}

	// "extract"
	md->fi->is_directory = 1;
	if(md->sec_type==ADF_ST_ROOT) {
		md->fi->is_root_dir = 1;
	}
	if(md->sec_type==ADF_ST_USERDIR) {
		if(md->fn) {
			md->fi->original_filename_flag = 1;
			fullfn = ucstring_create(c);
			de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
			de_finfo_set_name_from_ucstring(c, md->fi, fullfn, DE_SNFLAG_FULLPATH);
		}
	}

	if(md->mod_time.is_valid) {
		md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;
	}

	md->outf = dbuf_create_output_file(c, NULL, md->fi, 0x0);
	dbuf_close(md->outf);
	md->outf = NULL;

	// Now recurse into the files and subdirs in this directory.
	do_hashtable(c, d, pos1+24, ht_size_in_longs);

done:
	if(need_curpath_pop) {
		de_strarray_pop(d->curpath);
	}
	ucstring_destroy(fullfn);
	de_dbg_indent_restore(c, saved_indent_level);
}

// For block type 2 (ST_HEADER).
// Returns 1 unless the block isn't a header block.
static int do_header_block(deark *c, lctx *d, i64 blknum)
{
	i64 pos1;
	int blocktype;
	int retval = 0;
	int saved_indent_level;
	struct member_data *md = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	d->nesting_level++;
	if(d->nesting_level>MAX_NESTING_LEVEL) goto done;

	pos1 = blocknum_to_offset(d, blknum);

	if(!claim_block(c, d, blknum)) {
		goto done;
	}

	blocktype = (int)de_geti32be(pos1);
	if(blocktype==ADF_T_HEADER) {
		retval = 1;
	}

	md = de_malloc(c, sizeof(struct member_data));
	md->header_blknum = blknum;
	md->header_pos = blocknum_to_offset(d, md->header_blknum);
	md->fi = de_finfo_create(c);

	de_dbg(c, "header block: #%"I64_FMT" (%"I64_FMT")", blknum, pos1);
	de_dbg_indent(c, 1);

	de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_HEADER) {
		de_err(c, "Expected header block #%"I64_FMT" (at %"I64_FMT") not found", blknum, pos1);
		goto done;
	}
	md->sec_type = (UI)de_getu32be(pos1+d->bsize-4);
	de_dbg(c, "block secondary type: %d", md->sec_type);

	if(md->sec_type==ADF_ST_ROOT || md->sec_type==ADF_ST_USERDIR) {
		do_directory(c, d, md);
	}
	else if(md->sec_type==ADF_ST_FILE) {
		do_file(c, d, md);
	}
	else {
		de_warn(c, "Unsupported file type: %d", md->sec_type);
		goto done;
	}

done:
	if(md) {
		if(md->outf) {
			dbuf_close(md->outf);
		}
		de_finfo_destroy(c, md->fi);
		ucstring_destroy(md->fn);
		de_free(c, md->tmpbpt.blocks_tbl);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	d->nesting_level--;
	return retval;
}

// If true, sets d->root_block
static int test_root_block(deark *c, lctx *d, i64 blknum)
{
	i64 pos;

	pos = blocknum_to_offset(d, blknum);
	if(de_getu32be(pos) != ADF_T_HEADER) return 0;
	if(de_getu32be(pos+d->bsize-4) != ADF_ST_ROOT) return 0;
	d->root_block = blknum;
	return 1;
}

// If found, sets d->root_block
static int find_root_block(deark *c, lctx *d, i64 root_block_reported)
{
	if(c->infile->len >= 1802240) {
		if(test_root_block(c, d, 880*2)) return 1;
	}
	else {
		if(test_root_block(c, d, 880)) return 1;
	}

	if(test_root_block(c, d, root_block_reported)) return 1;

	if((c->infile->len >= (901120+d->bsize)) && (c->infile->len < 1802240)) {
		if(test_root_block(c, d, 880*2)) return 1;
	}

	return 0;
}

static void de_run_amiga_adf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 root_block_reported;
	int saved_indent_level;
	de_ucstring *flags_descr;

	de_dbg_indent_save(c, &saved_indent_level);

	d = de_malloc(c, sizeof(lctx));
	d->bsize = 512;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	d->bootblock_flags = (de_getbyte(3) & 0x07);
	flags_descr = ucstring_create(c);

	if(d->bootblock_flags & 0x1) {
		d->is_ffs = 1;
	}
	if(d->bootblock_flags & 0x2) {
		d->intnl_mode = 1;
	}
	if(d->bootblock_flags & 0x4) {
		d->intnl_mode = 1;
		d->dirc_mode = 1;
	}
	ucstring_append_flags_item(flags_descr, d->is_ffs?"FFS":"OFS");
	if(d->intnl_mode) {
		ucstring_append_flags_item(flags_descr, "international mode");
	}
	if(d->dirc_mode) {
		ucstring_append_flags_item(flags_descr, "dircache mode");
	}
	de_dbg(c, "flags: 0x%02x (%s)", (UI)d->bootblock_flags, ucstring_getpsz_d(flags_descr));
	ucstring_destroy(flags_descr);

	de_declare_fmtf(c, "Amiga ADF, %s", d->is_ffs?"FFS":"OFS");

	root_block_reported = de_getu32be(8);
	de_dbg(c, "root block (reported): %"I64_FMT, root_block_reported);

	d->num_blocks = de_pad_to_n(c->infile->len, 512) / 512;
	if(d->num_blocks > MAX_ADF_BLOCKS) {
		d->num_blocks = MAX_ADF_BLOCKS;
	}
	de_dbg_indent(c, -1);

	if(d->dirc_mode || d->intnl_mode) {
		de_warn(c, "This type of ADF file might not be supported correctly");
	}

	if(!find_root_block(c, d, root_block_reported)) {
		de_err(c, "Root block not found");
		goto done;
	}

	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);

	if(!do_header_block(c, d, d->root_block)) goto done;

done:
	if(d) {
		de_free(c, d->block_used_flags);
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_amiga_adf(deark *c)
{
	int has_size;
	int has_ext;

	if(dbuf_memcmp(c->infile, 0, "DOS", 3)) return 0;
	if(de_getbyte(3)>0x05) return 0;
	has_ext = de_input_file_has_ext(c, "adf");
	has_size = (c->infile->len==901120 || c->infile->len==1802240);
	if(has_ext && has_size) return 100;
	if(has_size) return 90;
	if(has_ext) return 60;
	return 20;
}

void de_module_amiga_adf(deark *c, struct deark_module_info *mi)
{
	mi->id = "amiga_adf";
	mi->desc = "Amiga disk image";
	mi->run_fn = de_run_amiga_adf;
	mi->identify_fn = de_identify_amiga_adf;
}

////////////////////////// DMS //////////////////////////

// Used as both the maximum number of physical tracks in the file, and (one more
// than) the highest logical track number allowed for a "real" track.
#define DMS_MAX_TRACKS 200

#define DMS_FILE_HDR_LEN 56
#define DMS_TRACK_HDR_LEN 20

struct dms_track_info {
	i64 track_num; // The reported (logical) track number
	i64 dpos;
	i64 cmpr_len;
	i64 intermediate_len;
	i64 uncmpr_len;
	UI flags;
	UI cmpr_type;
	u8 is_real;
	char shortname[80];
};

struct dms_tracks_by_file_order_entry {
	i64 file_pos;
	u32 track_num;
	u8 is_real;
};

struct dms_tracks_by_track_num_entry {
	u32 order_in_file;
	u8 in_use;
};

struct dmsctx {
	UI info_bits;
	UI cmpr_type;
	i64 first_track, last_track;
	i64 num_tracks_in_file;

	// Entries in use: 0 <= n < .num_tracks_in_file
	struct dms_tracks_by_file_order_entry tracks_by_file_order[DMS_MAX_TRACKS];

	// Entries potentially in use: .first_track <= n <= .last_track
	struct dms_tracks_by_track_num_entry tracks_by_track_num[DMS_MAX_TRACKS];
};

static const char *dms_get_cmprtype_name(UI n)
{
	const char *name = NULL;
	switch(n) {
	case 0: name="uncompressed"; break;
	case 1: name="simple (RLE)"; break;
	case 2: name="quick"; break;
	case 3: name="medium"; break;
	case 4: name="deep (LZ+dynamic_huffman + RLE)"; break;
	case 5: name="heavy1"; break;
	case 6: name="heavy2"; break;
	}
	return name?name:"?";
}

static void read_unix_timestamp(deark *c, i64 pos, struct de_timestamp *ts, const char *name)
{
	i64 t;
	char timestamp_buf[64];

	t = de_geti32be(pos);
	de_unix_time_to_timestamp(t, ts, 0x1);
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t, timestamp_buf);
}

// DMS RLE:
// n1     n2          n3  n4  n5
// ---------------------------------------------------------
// 0x90   0x00                     emit 0x90
// 0x90   0x01..0xfe  n3           emit n2 copies of n3
// 0x90   0xff        n3  n4  n5   emit (n4#n5) copies of n3
// !0x90                           emit n1

enum dmsrle_state {
	DMSRLE_STATE_NEUTRAL = 0,
	DMSRLE_STATE_90,
	DMSRLE_STATE_90_N2,
	DMSRLE_STATE_90_FF_N3,
	DMSRLE_STATE_90_FF_N3_N4
};

struct dmsrle_ctx {
	enum dmsrle_state state;
	u8 n2, n3, n4;
};

static void dmsrle_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	i64 i;
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(!rctx) goto done;

	for(i=0; i<buf_len; i++) {
		u8 n;
		i64 count;

		n = buf[i];

		switch(rctx->state) {
		case DMSRLE_STATE_NEUTRAL:
			if(n==0x90) {
				rctx->state = DMSRLE_STATE_90;
			}
			else {
				dbuf_writebyte(dfctx->dcmpro->f, n);
			}
			break;
		case DMSRLE_STATE_90:
			if(n==0x00) {
				dbuf_writebyte(dfctx->dcmpro->f, 0x90);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			else {
				rctx->n2 = n;
				rctx->state = DMSRLE_STATE_90_N2;
			}
			break;
		case DMSRLE_STATE_90_N2:
			if(rctx->n2==0xff) {
				rctx->n3 = n;
				rctx->state = DMSRLE_STATE_90_FF_N3;
			}
			else {
				count = (i64)rctx->n2;
				dbuf_write_run(dfctx->dcmpro->f, n, count);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			break;
		case DMSRLE_STATE_90_FF_N3:
			rctx->n4 = n;
			rctx->state = DMSRLE_STATE_90_FF_N3_N4;
			break;
		case DMSRLE_STATE_90_FF_N3_N4:
			count = (i64)(((UI)rctx->n4 << 8) | n);
			dbuf_write_run(dfctx->dcmpro->f, rctx->n3, count);
			rctx->state = DMSRLE_STATE_NEUTRAL;
			break;
		}
	}
done:
	;
}

static void dmsrle_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: Unused, should be NULL.
static void dmsrle_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct dmsrle_ctx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct dmsrle_ctx));
	rctx->state = DMSRLE_STATE_NEUTRAL;
	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = dmsrle_codec_addbuf;
	dfctx->codec_finish_fn = NULL;
	dfctx->codec_destroy_fn = dmsrle_codec_destroy;
}

static int dms_decompress_track(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	dbuf *outf)
{
	int retval = 0;
	i64 unc_nbytes;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(outf->len!=0) goto done;

	if(tri->dpos + tri->cmpr_len > c->infile->len) {
		de_err(c, "Track goes beyond end of file");
		goto done;
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = tri->dpos;
	dcmpri.len = tri->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = tri->uncmpr_len;

	switch(tri->cmpr_type) {
	case 0:
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case 1:
		de_dfilter_decompress_oneshot(c, dmsrle_codec, NULL,
			&dcmpri, &dcmpro, &dres);
		break;
	default:
		de_err(c, "[%s] Unsupported compression method: %u (%s)",
			tri->shortname, tri->cmpr_type,
			dms_get_cmprtype_name(tri->cmpr_type));
		goto done;
	}

	if(dres.errcode) {
		de_err(c, "[%s] Decompression failed: %s", tri->shortname,
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	unc_nbytes = outf->len;

	dbuf_truncate(outf, tri->uncmpr_len);

	if(unc_nbytes < tri->uncmpr_len) {
		de_err(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
		goto done;
	}
	if(unc_nbytes > tri->uncmpr_len) {
		de_warn(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
	}

	retval = 1;

done:
	return retval;
}

// Read track and decompress to outf (which caller supplies as an empty membuf).
// track_idx: the index into d->tracks_by_file_order
// Returns nonzero if successfully decompressed.
static int dms_read_and_decompress_track(deark *c, struct dmsctx *d,
	i64 track_idx, dbuf *outf)
{
	i64 pos1, pos;
	struct dms_track_info *tri = NULL;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	tri = de_malloc(c, sizeof(struct dms_track_info));
	pos1 = d->tracks_by_file_order[track_idx].file_pos;
	tri->track_num = (i64)d->tracks_by_file_order[track_idx].track_num;
	tri->is_real = d->tracks_by_file_order[track_idx].is_real;
	de_snprintf(tri->shortname, sizeof(tri->shortname), "%strack %d",
		(tri->is_real?"":"extra "), (int)tri->track_num);

	de_dbg(c, "%s at %"I64_FMT, tri->shortname, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;
	pos += 2; // signature, already checked
	pos += 2; // reported track number, already read
	pos += 2; // Unknown field
	tri->cmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "cmpr len: %"I64_FMT, tri->cmpr_len);
	tri->intermediate_len = de_getu16be_p(&pos);
	de_dbg(c, "intermediate len: %"I64_FMT, tri->intermediate_len);
	tri->uncmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "uncmpr len: %"I64_FMT, tri->uncmpr_len);

	tri->flags = (UI)de_getbyte_p(&pos);
	de_dbg(c, "track flags: 0x%02x", tri->flags);
	tri->cmpr_type = (UI)de_getbyte_p(&pos);
	de_dbg(c, "track cmpr type: %u (%s)", tri->cmpr_type, dms_get_cmprtype_name(tri->cmpr_type));
	// TODO: CRC/checksum validation

	tri->dpos = pos1 + DMS_TRACK_HDR_LEN;
	if(!dms_decompress_track(c, d, tri, outf)) goto done;
	retval = 1;

done:
	de_free(c, tri);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_dms_real_tracks(deark *c, struct dmsctx *d)
{
	i64 i;
	dbuf *outf = NULL;
	dbuf *trackbuf = NULL;

	trackbuf = dbuf_create_membuf(c, 0, 0);

	for(i=d->first_track; i<=d->last_track; i++) {
		int ret;
		u32 file_idx;

		if(!d->tracks_by_track_num[i].in_use) {
			continue;
		}

		file_idx = d->tracks_by_track_num[i].order_in_file;

		dbuf_truncate(trackbuf, 0);
		ret = dms_read_and_decompress_track(c, d, file_idx, trackbuf);
		if(!ret) goto done;

		if(!outf) {
			outf = dbuf_create_output_file(c, "adf", NULL, 0);
		}
		dbuf_copy(trackbuf, 0, trackbuf->len, outf);
	}

done:
	dbuf_close(outf);
	dbuf_close(trackbuf);
}

static void do_dms_extra_tracks(deark *c, struct dmsctx *d)
{
	i64 i;
	dbuf *trackbuf = NULL;

	for(i=0; i<d->num_tracks_in_file; i++) {
		int ret;
		dbuf *outf = NULL;
		char ext[80];

		if(d->tracks_by_file_order[i].is_real) continue;

		if(!trackbuf) {
			trackbuf = dbuf_create_membuf(c, 0, 0);
		}

		dbuf_truncate(trackbuf, 0);
		ret = dms_read_and_decompress_track(c, d, i, trackbuf);
		if(!ret) continue;

		de_snprintf(ext, sizeof(ext), "extratrack%d.bin",
			(int)d->tracks_by_file_order[i].track_num);
		outf = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_copy(trackbuf, 0, trackbuf->len, outf);
		dbuf_close(outf);
		outf = NULL;
	}

	dbuf_close(trackbuf);
}

static int do_dms_header(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 n;
	i64 pos = pos1;
	struct de_timestamp cr_time;
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// [0..3] = signature
	pos = pos1+8;
	d->info_bits = (UI)de_getu32be_p(&pos); // [8..11] = info bits
	de_dbg(c, "infobits: 0x%08x", d->info_bits);

	de_zeromem(&cr_time, sizeof(struct de_timestamp));
	read_unix_timestamp(c, pos, &cr_time, "creation time");
	pos += 4;

	d->first_track = de_getu16be_p(&pos); // [16..17] = firsttrack
	de_dbg(c, "first track: %d", (int)d->first_track);
	if(d->first_track >= DMS_MAX_TRACKS) goto done;
	d->last_track = de_getu16be_p(&pos); // [18..19] = lasttrack
	de_dbg(c, "last track: %u", (int)d->last_track);
	if(d->last_track < d->first_track) goto done;
	if(d->last_track >= DMS_MAX_TRACKS) goto done;

	n = de_getu32be_p(&pos); // [20..23] = packed len
	de_dbg(c, "compressed len: %"I64_FMT, n);

	n = de_getu32be_p(&pos); // [24..27] = unpacked len
	de_dbg(c, "decompressed len: %"I64_FMT, n);

	// [46..47] = creating software version
	pos = pos1+50;
	n = de_getu16be_p(&pos); // [50..51] = disk type
	de_dbg(c, "disk type: %u", (UI)n);

	d->cmpr_type = (UI)de_getu16be_p(&pos); // [52..53] = compression mode
	de_dbg(c, "compression type: %u (%s)", d->cmpr_type,
		dms_get_cmprtype_name(d->cmpr_type));

	n = de_getu16be_p(&pos); // [54..55] = crc
	de_dbg(c, "crc (reported): 0x%04x", (UI)n);

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int dms_scan_file(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 i;
	int retval = 0;

	de_dbg(c, "scanning file");
	de_dbg_indent(c, 1);

	d->num_tracks_in_file = 0;

	while(1) {
		i64 track_num_reported;
		i64 cmpr_len;
		i64 uncmpr_len;

		if(pos+DMS_TRACK_HDR_LEN > c->infile->len) break;

		if(dbuf_memcmp(c->infile, pos, "TR", 2)) {
			de_dbg(c, "[track not found at %"I64_FMT"; assuming disk image ends here]", pos);
			break;
		}
		if(d->num_tracks_in_file >= DMS_MAX_TRACKS) {
			de_err(c, "Too many tracks in file");
			break;
		}

		track_num_reported = de_getu16be(pos+2);
		cmpr_len = de_getu16be(pos+6);
		uncmpr_len = de_getu16be(pos+10);

		de_dbg(c, "track[%d] at %"I64_FMT", #%d, len=%"I64_FMT"/%"I64_FMT,
			(int)d->num_tracks_in_file, pos, (int)track_num_reported, cmpr_len, uncmpr_len);

		d->tracks_by_file_order[d->num_tracks_in_file].file_pos = pos;
		d->tracks_by_file_order[d->num_tracks_in_file].track_num = (u32)track_num_reported;

		if(track_num_reported>=d->first_track && track_num_reported<=d->last_track) {
			d->tracks_by_track_num[track_num_reported].order_in_file = (u32)d->num_tracks_in_file;
			d->tracks_by_track_num[track_num_reported].in_use = 1;
		}

		d->num_tracks_in_file++;
		pos += DMS_TRACK_HDR_LEN + cmpr_len;
	}

	// Make sure all expected tracks are present, and mark the "real" tracks in
	// tracks_by_file_order[].
	// One reason for doing it this way is that there may be two tracks numbered 0,
	// with the second one being the real one.
	for(i=d->first_track; i<=d->last_track; i++) {
		if(!d->tracks_by_track_num[i].in_use) {
			de_err(c, "Could not find track #%d", (int)i);
			goto done;
		}

		d->tracks_by_file_order[d->tracks_by_track_num[i].order_in_file].is_real = 1;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_amiga_dms(deark *c, de_module_params *mparams)
{
	struct dmsctx *d = NULL;

	d = de_malloc(c, sizeof(struct dmsctx));
	if(!do_dms_header(c, d, 0)) goto done;
	if(!dms_scan_file(c, d, DMS_FILE_HDR_LEN)) goto done;
	do_dms_real_tracks(c, d);
	do_dms_extra_tracks(c, d);

done:
	de_free(c, d);
}

static int de_identify_amiga_dms(deark *c)
{
	i64 dcmpr_size;

	if(dbuf_memcmp(c->infile, 0, "DMS!", 4)) return 0;
	dcmpr_size = de_getu32be(24);
	if(dcmpr_size==901120) return 100;
	return 85;
}

void de_module_amiga_dms(deark *c, struct deark_module_info *mi)
{
	mi->id = "amiga_dms";
	mi->desc = "Amiga DMS disk image";
	mi->run_fn = de_run_amiga_dms;
	mi->identify_fn = de_identify_amiga_dms;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
