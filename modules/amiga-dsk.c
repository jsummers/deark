// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Amiga disk image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_amiga_adf);

#define ADF_T_HEADER      2
#define ADF_T_DATA        8

#define ADF_ST_ROOT       1
#define ADF_ST_USERDIR    2
#define ADF_ST_FILE       (-3)

#define MAX_ADF_BLOCKS 3520
#define MAX_NESTING_LEVEL 16

struct member_data {
	i64 header_blknum;
	i64 header_pos;

	i64 fsize;
	i64 first_data_block;
	int sec_type;
	de_ucstring *fn;

	dbuf *outf;
	i64 nbytes_written;
	i64 next_block_to_read;
	de_finfo *fi;
};

typedef struct localctx_struct {
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
static int claim_block(deark *c, lctx *d, i64 blknum)
{
	if(blknum<0 || blknum>=d->num_blocks) return 0;
	if(!d->block_used_flags) {
		d->block_used_flags = de_malloc(c, d->num_blocks);
	}
	if(d->block_used_flags[blknum]) return 0;
	d->block_used_flags[blknum] = 1;
	return 1;
}

// Reads a file data block.
// On success, returns nonzero and sets md->next_block_to_read.
static int do_file_data_block(deark *c, lctx *d, struct member_data *md,
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
		on_adf_error(c, d, 10);
		goto done;
	}

	pos = pos1;
	blocktype = (int)de_geti32be_p(&pos);
	de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_DATA) {
		on_adf_error(c, d, 11);
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
		on_adf_error(c, d, 14);
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

static void do_file(deark *c, lctx *d, struct member_data *md)
{
	i64 pos1, pos;
	i64 fnlen;
	i64 header_key;
	i64 seq_num;
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
	n = de_getu32be_p(&pos);
	de_dbg(c, "high_seq: %u", (UI)n);
	pos += 4; // data_size - unused
	md->first_data_block = de_getu32be_p(&pos);
	de_dbg(c, "first data block: %"I64_FMT, md->first_data_block);

	if(header_key!=md->header_blknum) {
		on_adf_error(c, d, 17);
		goto done;
	}

	pos = pos1+d->bsize-188;
	md->fsize = de_getu32be_p(&pos);
	de_dbg(c, "file size: %"I64_FMT, md->fsize);

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

	if(md->sec_type!=ADF_ST_FILE) {
		de_dbg(c, "[not a supported file type]");
		goto done;
	}

	md->fi->original_filename_flag = 1;
	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
	de_finfo_set_name_from_ucstring(c, md->fi, fullfn, DE_SNFLAG_FULLPATH);

	md->outf = dbuf_create_output_file(c, NULL, md->fi, 0x0);

	md->next_block_to_read = md->first_data_block;
	seq_num = 1;
	while(1) {
		int ret;

		if(md->next_block_to_read==0) break;

		ret = do_file_data_block(c, d, md, seq_num, md->next_block_to_read);
		if(!ret) goto done;
		seq_num++;
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
			de_dbg_indent(c, 1);
			do_file_list(c, d, n);
			de_dbg_indent(c, -1);
		}
	}

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

	de_dbg_indent_save(c, &saved_indent_level);

	pos1 = md->header_pos;
	de_dbg(c, "directory header block: #%"I64_FMT" (%"I64_FMT")", md->header_blknum, pos1);
	de_dbg_indent(c, 1);
	if(md->sec_type!=ADF_ST_ROOT && md->sec_type!=ADF_ST_USERDIR) {
		de_err(c, "not implemented");
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

// For block type 2 (ST_HEADER)
static int do_header_block(deark *c, lctx *d, i64 blknum)
{
	i64 pos1, pos;
	int blocktype;
	int retval = 0;
	int saved_indent_level;
	struct member_data *md = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	d->nesting_level++;
	if(d->nesting_level>MAX_NESTING_LEVEL) goto done;

	pos1 = blocknum_to_offset(d, blknum);

	if(!claim_block(c, d, blknum)) {
		on_adf_error(c, d, 18);
		goto done;
	}

	md = de_malloc(c, sizeof(struct member_data));
	md->header_blknum = blknum;
	md->header_pos = blocknum_to_offset(d, md->header_blknum);
	md->fi = de_finfo_create(c);

	md->sec_type = (UI)de_getu32be(pos1+d->bsize-4);

	de_dbg(c, "header block: #%"I64_FMT" (%"I64_FMT")", blknum, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;

	blocktype = (int)de_geti32be_p(&pos);
	de_dbg(c, "block type: %d", blocktype);
	if(blocktype!=ADF_T_HEADER) {
		on_adf_error(c, d, 19);
		goto done;
	}
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

	retval = 1;
done:
	if(md) {
		if(md->outf) {
			dbuf_close(md->outf);
		}
		de_finfo_destroy(c, md->fi);
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	d->nesting_level--;
	return retval;
}

static void de_run_amiga_adf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d = de_malloc(c, sizeof(lctx));
	d->bsize = 512;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);
	d->bootblock_flags = de_getbyte(3);
	de_dbg(c, "flags: 0x%02x", (UI)d->bootblock_flags);
	d->root_block = de_getu32be(8);
	de_dbg(c, "root block (reported): %"I64_FMT, d->root_block);

	d->num_blocks = de_pad_to_n(c->infile->len, 512) / 512;
	if(d->num_blocks > MAX_ADF_BLOCKS) {
		d->num_blocks = MAX_ADF_BLOCKS;
	}
	de_dbg_indent(c, -1);

	if(d->bootblock_flags!=0) {
		de_err(c, "Unsupported type of ADF file");
		goto done;
	}

	d->curpath = de_strarray_create(c);

	if(!do_header_block(c, d, 880)) goto done;

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
	has_size = (c->infile->len==901120); // TODO: High density disks?
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
	mi->flags |= DE_MODFLAG_NONWORKING;
}
