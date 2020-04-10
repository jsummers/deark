// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Amiga disk image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_amiga_adf);

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
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = blocknum_to_offset(d, blknum);
	de_dbg(c, "data block: blk#%"I64_FMT" (%"I64_FMT"), seq=%d", blknum, pos1,
		(int)seq_num_expected);
	de_dbg_indent(c, 1);

	if(!claim_block(c, d, blknum)) {
		goto done;
	}

	pos = pos1;
	blocktype = (int)de_geti32be_p(&pos);
	de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_DATA) {
		de_err(c, "%s: Bad block type in data block %d (%d, expected %d)",
			ucstring_getpsz_d(md->fn), (int)seq_num_expected,
			blocktype, (int)ADF_T_DATA);
		goto done;
	}

	n = de_getu32be_p(&pos);
	de_dbg(c, "header_key: %u", (UI)n);
	if(n!=md->header_blknum) {
		on_adf_error(c, d, 12);
		goto done;
	}

	n = de_getu32be_p(&pos);
	de_dbg(c, "seq_num: %u", (UI)n);
	if(n!=seq_num_expected) {
		on_adf_error(c, d, 13);
		goto done;
	}
	data_size = de_getu32be_p(&pos);
	de_dbg(c, "data size: %"I64_FMT, data_size);
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
	de_dbg(c, "next data block: %"I64_FMT, md->next_block_to_read);

	dpos = pos1 + 24;
	dbuf_copy(c->infile, dpos, data_size, md->outf);
	md->nbytes_written += data_size;

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void read_ofs_timestamp(deark *c, lctx *d, i64 pos1, struct de_timestamp *ts,
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
	read_ofs_timestamp(c, d, pos, &md->mod_time, "mod time");

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

	read_ofs_timestamp(c, d, pos1+d->bsize-92, &md->mod_time, "dir mod time");

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
		read_ofs_timestamp(c, d, pos1+d->bsize-40, &tmpts, "disk mod time");
		read_ofs_timestamp(c, d, pos1+d->bsize-28, &tmpts, "filesystem create time");
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

	d->curpath = de_strarray_create(c);

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
