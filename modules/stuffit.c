// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// StuffIt

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
#include "../foreign/unsit.h"
DE_DECLARE_MODULE(de_module_stuffit);

struct cmpr_meth_info;

struct fork_data {
	u8 is_rsrc_fork;
	u8 cmpr_meth_etc;
#define CMPR_NONE       0
#define CMPR_RLE        1
#define CMPR_LZW        2
#define CMPR_HUFFMAN    3
#define CMPR_LZAH       5
#define CMPR_FIXEDHUFF  6
#define CMPR_MW         8
#define CMPR_LZHUFF     13
	u8 is_a_file;
	u8 cmpr_meth;
	u8 is_encrypted;
	u32 crc;
	i64 unc_len;
	i64 cmpr_pos;
	i64 cmpr_len;
	const struct cmpr_meth_info *cmi;
};

struct member_data {
	u8 is_folder;
	unsigned int finder_flags;
	de_ucstring *fname;
	de_ucstring *full_fname;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	struct de_timestamp mod_time;
	struct de_timestamp create_time;
	struct fork_data rfork;
	struct fork_data dfork;
};

typedef struct localctx_struct {
	int file_fmt; // 1=old, 2=new
	int nmembers;
	int subdir_level;
	u8 ver;
	i64 archive_size;
	struct de_strarray *curpath;
	struct de_crcobj *crco;
} lctx;

typedef int (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf);

struct cmpr_meth_info {
	u8 id;
	const char *name;
	decompressor_fn decompressor;
};

static int do_decompr_uncompressed(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf)
{
	dbuf_copy(c->infile, frk->cmpr_pos, frk->cmpr_len, outf);
	return 1;
}

static int do_decompr_rle(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf)
{
	return de_fmtutil_decompress_rle90(c->infile, frk->cmpr_pos, frk->cmpr_len,
		outf, 1, frk->unc_len, 0);
}

static int do_decompr_lzw(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf)
{
	u8 lzwmode;
	int retval = 0;

	// TODO: What are the right lzw settings?
	lzwmode = (u8)(14 | 0x80);
	retval = de_decompress_liblzw(c->infile, frk->cmpr_pos, frk->cmpr_len, outf,
		1, frk->unc_len, 0x0, lzwmode);
	return retval;
}

static int do_decompr_huffman(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf)
{
	int ret;
	struct huffctx hctx;

	de_zeromem(&hctx, sizeof(struct huffctx));
	hctx.c = c;
	hctx.inf = c->infile;
	hctx.cmpr_pos = frk->cmpr_pos;
	hctx.cmpr_len = frk->cmpr_len;
	hctx.outf = outf;
	hctx.unc_len = frk->unc_len;

	ret = huff_main(&hctx);
	return ret;
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ CMPR_NONE, "uncompressed", do_decompr_uncompressed },
	{ CMPR_RLE, "RLE",  do_decompr_rle },
	{ CMPR_LZW, "LZW", do_decompr_lzw },
	{ CMPR_HUFFMAN, "Huffman", do_decompr_huffman },
	{ CMPR_LZAH, "LZAH", NULL },
	{ CMPR_FIXEDHUFF, "fixed Huffman", NULL },
	{ CMPR_MW, "MW", NULL },
	{ CMPR_LZHUFF, "LZ+Huffman", NULL },
	{ 14, "installer", NULL },
	{ 15, "Arsenic", NULL }
};

static const struct cmpr_meth_info *find_cmpr_meth_info(deark *c, u8 id)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(cmpr_meth_info_arr); k++) {
		if(id == cmpr_meth_info_arr[k].id)
			return &cmpr_meth_info_arr[k];
	}
	return NULL;
}

// Given a 'fork_data' fk with fk.cmpr_meth_etc set,
//  - sets fk.is_a_file
//  - sets fk.cmpr_meth
//  - sets fk.is_encrypted
//  - sets fk.cmi
//  - writes a description to the 's' string
static void decode_cmpr_meth(deark *c, struct fork_data *fk,
	de_ucstring *s)
{
	const char *name = NULL;
	u8 cmpr = fk->cmpr_meth_etc;

	if(cmpr<32 && (cmpr & 16)) {
		fk->is_encrypted = 1;
		cmpr -= 16;
	}

	if(cmpr<16) {
		fk->is_a_file = 1;
		fk->cmpr_meth = cmpr;
	}

	if(fk->is_a_file) {
		fk->cmi = find_cmpr_meth_info(c, fk->cmpr_meth);
	}

	if(fk->cmi) {
		name = fk->cmi->name;
	}
	else if(fk->cmpr_meth_etc==32) {
		name = "folder";
	}
	else if(fk->cmpr_meth_etc==33) {
		name = "end of folder marker";
	}

	if(!name) name="?";
	ucstring_append_flags_item(s, name);
	if(fk->is_encrypted) {
		ucstring_append_flags_item(s, "encrypted");
	}
}

static int do_member_header(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	i64 pos = pos1;
	i64 fnlen;
	i64 n;
	de_ucstring *descr = NULL;
	int saved_indent_level;
	char timestamp_buf[64];

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md->rfork.cmpr_meth_etc = de_getbyte_p(&pos);
	descr = ucstring_create(c);
	decode_cmpr_meth(c, &md->rfork, descr);
	de_dbg(c, "rsrc cmpr meth (etc.): %u (%s)", (unsigned int)md->rfork.cmpr_meth_etc,
		ucstring_getpsz(descr));

	md->dfork.cmpr_meth_etc = de_getbyte_p(&pos);
	ucstring_empty(descr);
	decode_cmpr_meth(c, &md->dfork, descr);
	de_dbg(c, "data cmpr meth (etc.): %u (%s)", (unsigned int)md->dfork.cmpr_meth_etc,
		ucstring_getpsz(descr));

	fnlen = (i64)de_getbyte_p(&pos);
	if(fnlen>63) fnlen=63;
	md->fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, fnlen, md->fname, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(md->fname));
	pos += 63;

	dbuf_read_fourcc(c->infile, pos, &md->filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", md->filetype.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &md->creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", md->creator.id_dbgstr);
	pos += 4;

	md->finder_flags = (unsigned int)de_getu16be_p(&pos);
	de_dbg(c, "finder flags: 0x%04x", md->finder_flags);

	n = de_getu32be_p(&pos);
	de_mac_time_to_timestamp(n, &md->create_time);
	de_timestamp_to_string(&md->create_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "create time: %"I64_FMT" (%s)", n, timestamp_buf);

	n = de_getu32be_p(&pos);
	de_mac_time_to_timestamp(n, &md->mod_time);
	de_timestamp_to_string(&md->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %"I64_FMT" (%s)", n, timestamp_buf);

	md->rfork.unc_len = de_getu32be_p(&pos);
	md->dfork.unc_len = de_getu32be_p(&pos);
	md->rfork.cmpr_len = de_getu32be_p(&pos);
	md->dfork.cmpr_len = de_getu32be_p(&pos);
	de_dbg(c, "rsrc uncmpr len: %"I64_FMT, md->rfork.unc_len);
	de_dbg(c, "rsrc cmpr len: %"I64_FMT, md->rfork.cmpr_len);
	de_dbg(c, "data uncmpr len: %"I64_FMT, md->dfork.unc_len);
	de_dbg(c, "data cmpr len: %"I64_FMT, md->dfork.cmpr_len);

	md->rfork.crc = (u32)de_getu16be_p(&pos);
	de_dbg(c, "rsrc crc (reported): 0x%04x", (unsigned int)md->rfork.crc);
	md->dfork.crc = (u32)de_getu16be_p(&pos);
	de_dbg(c, "data crc (reported): 0x%04x", (unsigned int)md->dfork.crc);

	pos += 6; // reserved, etc.

	n = de_getu16be_p(&pos);
	de_dbg(c, "file header crc (reported): 0x%04x", (unsigned int)n);

	de_dbg_indent(c, -1);

	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(descr);
	return 1;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_decompress_fork(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *final_fname = NULL;
	int ret;
	u32 crc_calc;

	if(!frk->is_a_file) {
		goto done;
	}

	// TODO: What is the correct way to determine the nonexistence of a fork?
	if(frk->unc_len==0 && frk->cmpr_len==0) {
		goto done;
	}

	de_dbg(c, "cmpr method: %u (%s)", (unsigned int)frk->cmpr_meth,
		frk->cmi?frk->cmi->name:"?");

	if(!frk->cmi) {
		de_err(c, "Unknown compression method: %u", (unsigned int)frk->cmpr_meth);
		goto done;
	}

	if(!frk->cmi->decompressor) {
		de_err(c, "Unsupported compression method: %u (%s)", (unsigned int)frk->cmpr_meth,
			frk->cmi->name);
		goto done;
	}

	if(frk->is_encrypted) {
		de_err(c, "Encrypted files are not supported");
		goto done;
	}

	fi = de_finfo_create(c);

	final_fname = ucstring_clone(md->full_fname);
	if(frk->is_rsrc_fork) {
		ucstring_append_sz(final_fname, ".rsrc", DE_ENCODING_LATIN1);
	}
	de_finfo_set_name_from_ucstring(c, fi, final_fname, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;
	fi->mod_time = md->mod_time;

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;
	de_crcobj_reset(d->crco);

	ret = frk->cmi->decompressor(c, d, md, frk, outf);
	if(!ret) {
		de_err(c, "Decompression failed for file %s", ucstring_getpsz_d(final_fname));
		goto done;
	}

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)crc_calc);
	if(crc_calc != frk->crc) {
		de_err(c, "CRC check failed for file %s", ucstring_getpsz_d(final_fname));
		goto done;
	}

done:
	if(outf) dbuf_close(outf);
	if(fi) de_finfo_destroy(c, fi);
	if(final_fname) ucstring_destroy(final_fname);
}

static void do_extract_folder(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

	if(!md->is_folder) goto done;
	fi = de_finfo_create(c);
	fi->is_directory = 1;
	de_finfo_set_name_from_ucstring(c, fi, md->full_fname, DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;
	fi->mod_time = md->mod_time;
	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}


// Returns:
//  0 if the member could not be parsed sufficiently to determine its size
//  1 normally
static int do_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	struct member_data *md = NULL;
	int saved_indent_level;
	int retval = 0;

	*bytes_consumed = 0;
	de_dbg_indent_save(c, &saved_indent_level);

	md = de_malloc(c, sizeof(struct member_data));
	md->rfork.is_rsrc_fork = 1;

	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(!do_member_header(c, d, md, pos)) goto done;

	*bytes_consumed = 112;

	if(md->rfork.cmpr_meth_etc==32 || md->dfork.cmpr_meth_etc==32) {
		md->is_folder = 1;
		md->rfork.cmpr_len = 0;
		md->dfork.cmpr_len = 0;
	}
	else if(md->rfork.cmpr_meth_etc==33 || md->dfork.cmpr_meth_etc==33) {
		// end of folder marker
		if(d->subdir_level>0) d->subdir_level--;
		de_strarray_pop(d->curpath);
		retval = 1;
		goto done;
	}
	else if(md->rfork.cmpr_meth_etc>33 || md->dfork.cmpr_meth_etc>33) {
		de_err(c, "Unknown member type. Cannot continue.");
		goto done;
	}

	*bytes_consumed += md->rfork.cmpr_len + md->dfork.cmpr_len;
	retval = 1;

	pos += 112;

	md->full_fname = ucstring_create(c);
	de_strarray_make_path(d->curpath, md->full_fname, 0);
	ucstring_append_ucstring(md->full_fname, md->fname);
	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->full_fname));

	if(md->is_folder) {
		d->subdir_level++;
		de_strarray_push(d->curpath, md->fname);
		do_extract_folder(c, d, md);
		goto done;
	}

	// resource fork
	md->rfork.cmpr_pos = pos;
	if(md->rfork.cmpr_len>0) {
		de_dbg(c, "rsrc fork data at %"I64_FMT", len=%"I64_FMT,
			pos, md->rfork.cmpr_len);
		de_dbg_indent(c, 1);
		do_decompress_fork(c, d, md, &md->rfork);
		de_dbg_indent(c, -1);
		pos += md->rfork.cmpr_len;
	}

	// data fork
	md->dfork.cmpr_pos = pos;
	if(md->dfork.cmpr_len>0) {
		de_dbg(c, "data fork data at %"I64_FMT", len=%"I64_FMT,
			pos, md->dfork.cmpr_len);
		de_dbg_indent(c, 1);
		do_decompress_fork(c, d, md, &md->dfork);
		de_dbg_indent(c, -1);
		pos += md->dfork.cmpr_len;
	}

done:
	if(md) {
		ucstring_destroy(md->fname);
		ucstring_destroy(md->full_fname);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_master_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;

	de_dbg(c, "master header at %d", (int)pos1);
	de_dbg_indent(c, 1);
	pos += 4; // signature

	d->nmembers = (int)de_getu16be_p(&pos);
	de_dbg(c, "number of members: %d", d->nmembers);

	d->archive_size = de_getu32be_p(&pos);
	de_dbg(c, "reported archive file size: %"I64_FMT, d->archive_size);

	pos += 4; // expected to be "rLau"

	d->ver = de_getbyte_p(&pos);
	de_dbg(c, "version: %u", (unsigned int)d->ver);

	de_dbg_indent(c, -1);
	return 1;
}

// If nmembers==-1, number of members is unknown
static void do_sequence_of_members(deark *c, lctx *d, i64 pos1)
{
	int root_member_count = 0;
	i64 pos = pos1;

	while(1) {
		int ret;
		int is_root_member;
		i64 bytes_consumed = 0;

		if((d->subdir_level==0) && (root_member_count >= d->nmembers)) break;
		if(pos >= c->infile->len) break;

		is_root_member = (d->subdir_level==0);
		ret = do_member(c, d, pos, &bytes_consumed);
		if(ret==0) break;
		if(bytes_consumed<1) break;
		pos += bytes_consumed;
		if(is_root_member) root_member_count++;
	}
}

static void de_run_stuffit(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "SIT!", 4)) {
		d->file_fmt = 1;
	}
	else if(!dbuf_memcmp(c->infile, 0, "StuffIt", 7)) {
		d->file_fmt = 2;
		de_err(c, "This version of StuffIt format is not supported.");
		goto done;
	}
	else {
		de_err(c, "Not a StuffIt file, or unknown version.");
		goto done;
	}

	pos = 0;
	if(!do_master_header(c, d, pos)) goto done;
	pos += 22;

	d->curpath = de_strarray_create(c);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_sequence_of_members(c, d, pos);

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
}

static int de_identify_stuffit(deark *c)
{
	u8 buf[8];

	de_read(buf, 0, 8);
	if(!de_memcmp(buf, "SIT!", 4) ||
		!de_memcmp(buf, "StuffIt ", 8))
	{
		return 100;
	}
	return 0;
}

void de_module_stuffit(deark *c, struct deark_module_info *mi)
{
	mi->id = "stuffit";
	mi->desc = "StuffIt archive";
	mi->run_fn = de_run_stuffit;
	mi->identify_fn = de_identify_stuffit;
}
