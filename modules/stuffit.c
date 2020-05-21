// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// StuffIt

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
#include "../foreign/unsit.h"
DE_DECLARE_MODULE(de_module_stuffit);

#define MAX_NESTING_LEVEL 32

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
	const char *forkname;
	const struct cmpr_meth_info *cmi;
};

struct member_data {
	u8 is_folder;
	unsigned int finder_flags;
	struct de_advfile *advf;
	struct de_stringreaderdata *fname;
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
	int input_encoding;
	int nmembers;
	int subdir_level;
	u8 ver;
	i64 archive_size;
	struct de_strarray *curpath;
	struct de_crcobj *crco_rfork;
	struct de_crcobj *crco_dfork;
} lctx;

typedef void (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);

struct cmpr_meth_info {
	u8 id;
	const char *name;
	decompressor_fn decompressor;
};

static void do_decompr_uncompressed(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static void do_decompr_rle(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	de_fmtutil_decompress_rle90_ex(c, dcmpri, dcmpro, dres, 0);
}

static void do_decompr_lzw(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	// TODO: What are the right lzw settings?
	delzwp.max_code_size = 14;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void do_decompr_huffman(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct huffctx *hctx = NULL;

	hctx = de_malloc(c, sizeof(struct huffctx));
	hctx->c = c;
	hctx->dcmpri = dcmpri;
	hctx->dcmpro = dcmpro;
	hctx->dres = dres;
	huff_main(hctx);
	de_free(c, hctx);
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

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_info_arr); k++) {
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
	md->fname = dbuf_read_string(c->infile, pos, fnlen, fnlen, 0, d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(md->fname->str));
	pos += 63;

	if(md->dfork.is_a_file || md->rfork.is_a_file) {
		dbuf_read_fourcc(c->infile, pos, &md->filetype, 4, 0x0);
		de_dbg(c, "filetype: '%s'", md->filetype.id_dbgstr);
		de_memcpy(md->advf->typecode, md->filetype.bytes, 4);
		md->advf->has_typecode = 1;
		pos += 4;
		dbuf_read_fourcc(c->infile, pos, &md->creator, 4, 0x0);
		de_dbg(c, "creator: '%s'", md->creator.id_dbgstr);
		de_memcpy(md->advf->creatorcode, md->creator.bytes, 4);
		md->advf->has_creatorcode = 1;
		pos += 4;

		md->finder_flags = (unsigned int)de_getu16be_p(&pos);
		de_dbg(c, "finder flags: 0x%04x", md->finder_flags);
		md->advf->finderflags = (u16)md->finder_flags;
		md->advf->has_finderflags = 1;
	}
	else {
		// Don't know if these fields mean anything for folders.
		// Possibly they're the first 10 bytes of DInfo (Finder Info for
		// folders), though that seems a little odd.
		pos += 10;
	}

	n = de_getu32be_p(&pos);
	de_mac_time_to_timestamp(n, &md->create_time);
	de_timestamp_to_string(&md->create_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "create time: %"I64_FMT" (%s)", n, timestamp_buf);
	md->advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE] = md->create_time;

	n = de_getu32be_p(&pos);
	de_mac_time_to_timestamp(n, &md->mod_time);
	de_timestamp_to_string(&md->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %"I64_FMT" (%s)", n, timestamp_buf);
	md->advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;

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

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

// Sets md->advf->*fork.fork_exists, according to whether we think we
// can decompress the fork.
static void do_pre_decompress_fork(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk)
{
	struct de_advfile_forkinfo *advfki;
	int ok = 0;

	if(frk->is_rsrc_fork) {
		advfki = &md->advf->rsrcfork;
	}
	else {
		advfki = &md->advf->mainfork;
	}

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
		de_err(c, "%s %s fork: Unsupported compression method: %u (%s)",
			ucstring_getpsz_d(md->full_fname), frk->forkname,
			(unsigned int)frk->cmpr_meth, frk->cmi->name);
		goto done;
	}

	if(frk->is_encrypted) {
		de_err(c, "Encrypted files are not supported");
		goto done;
	}

	ok = 1;

	advfki->writelistener_cb = our_writelistener_cb;
	if(frk->is_rsrc_fork) {
		advfki->userdata_for_writelistener = (void*)d->crco_rfork;
		de_crcobj_reset(d->crco_rfork);
	}
	else {
		advfki->userdata_for_writelistener = (void*)d->crco_dfork;
		de_crcobj_reset(d->crco_dfork);
	}

done:
	advfki->fork_exists = (ok)?1:0;
}

static void do_main_decompress_fork(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, dbuf *outf)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(!frk || !frk->cmi || !frk->cmi->decompressor) {
		goto done;
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = frk->cmpr_pos;
	dcmpri.len = frk->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = frk->unc_len;
	frk->cmi->decompressor(c, d, md, frk, &dcmpri, &dcmpro, &dres);
	if(dres.errcode) {
		de_err(c, "Decompression failed for file %s %s fork: %s", ucstring_getpsz_d(md->full_fname),
			frk->forkname, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

done:
	;
}

static void do_post_decompress_fork(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk)
{
	u32 crc_calc;

	if(frk->is_rsrc_fork) {
		crc_calc = de_crcobj_getval(d->crco_rfork);
	}
	else {
		crc_calc = de_crcobj_getval(d->crco_dfork);
	}
	de_dbg(c, "%s crc (calculated): 0x%04x", frk->forkname, (unsigned int)crc_calc);
	if(crc_calc != frk->crc) {
		de_err(c, "CRC check failed for file %s %s fork", ucstring_getpsz_d(md->full_fname),
			frk->forkname);
	}
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
	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;
	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

struct advfudata {
	lctx *d;
	struct member_data *md;
};

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	struct advfudata *u = (struct advfudata*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		do_main_decompress_fork(c, u->d, u->md, &u->md->dfork, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		do_main_decompress_fork(c, u->d, u->md, &u->md->rfork, afp->outf);
	}

	return 1;
}

// Returns:
//  0 if the member could not be parsed sufficiently to determine its size
//  1 normally
static int do_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	struct member_data *md = NULL;
	int saved_indent_level;
	struct advfudata u;
	int retval = 0;

	*bytes_consumed = 0;
	de_dbg_indent_save(c, &saved_indent_level);

	md = de_malloc(c, sizeof(struct member_data));
	md->rfork.is_rsrc_fork = 1;
	md->dfork.forkname = "data";
	md->rfork.forkname = "resource";

	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md->advf = de_advfile_create(c);

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
	ucstring_append_ucstring(md->full_fname, md->fname->str);
	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->full_fname));
	ucstring_append_ucstring(md->advf->filename, md->full_fname);
	md->advf->original_filename_flag = 1;
	md->advf->snflags = DE_SNFLAG_FULLPATH;
	de_advfile_set_orig_filename(md->advf, md->fname->sz, md->fname->sz_strlen);

	if(md->is_folder) {
		if(d->subdir_level >= MAX_NESTING_LEVEL) {
			de_err(c, "Directories nested too deeply");
			retval = 0;
			goto done;
		}
		d->subdir_level++;
		de_strarray_push(d->curpath, md->fname->str);
		do_extract_folder(c, d, md);
		goto done;
	}

	// resource fork
	md->rfork.cmpr_pos = pos;
	if(md->rfork.cmpr_len>0) {
		de_dbg(c, "rsrc fork data at %"I64_FMT", len=%"I64_FMT,
			pos, md->rfork.cmpr_len);
		md->advf->rsrcfork.fork_len = md->rfork.unc_len;
		de_dbg_indent(c, 1);
		do_pre_decompress_fork(c, d, md, &md->rfork);
		de_dbg_indent(c, -1);
		pos += md->rfork.cmpr_len;
	}

	// data fork
	md->dfork.cmpr_pos = pos;
	if(md->dfork.cmpr_len>0) {
		de_dbg(c, "data fork data at %"I64_FMT", len=%"I64_FMT,
			pos, md->dfork.cmpr_len);
		md->advf->mainfork.fork_len = md->dfork.unc_len;
		de_dbg_indent(c, 1);
		do_pre_decompress_fork(c, d, md, &md->dfork);
		de_dbg_indent(c, -1);
		//pos += md->dfork.cmpr_len;
	}

	u.d = d;
	u.md = md;
	md->advf->userdata = (void*)&u;
	md->advf->writefork_cbfn = my_advfile_cbfn;
	de_advfile_run(md->advf);

	if(md->advf->rsrcfork.fork_exists) {
		do_post_decompress_fork(c, d, md, &md->rfork);
	}
	if(md->advf->mainfork.fork_exists) {
		do_post_decompress_fork(c, d, md, &md->dfork);
	}

done:
	if(md) {
		de_destroy_stringreaderdata(c, md->fname);
		ucstring_destroy(md->full_fname);
		de_advfile_destroy(md->advf);
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
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);

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

	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);
	d->crco_rfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	d->crco_dfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_sequence_of_members(c, d, pos);

done:
	if(d) {
		de_crcobj_destroy(d->crco_rfork);
		de_crcobj_destroy(d->crco_dfork);
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
