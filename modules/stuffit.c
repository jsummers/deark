// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// StuffIt

#include <deark-private.h>
#include <deark-fmtutil.h>
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
	u32 crc_reported;
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
	i64 v5_next_member_pos;
	i64 v5_first_entry_pos; // valid if is_folder
	i64 v5_num_files_in_folder; // valid if is_folder
	u8 v5_need_strarray_pop;
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
	struct de_crcobj *crco_hdr;
	u8 v5_archive_flags;
	i64 v5_first_entry_pos; // for the root directory
	struct de_inthashtable *v5_offsets_seen;
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
	fmtutil_decompress_rle90_ex(c, dcmpri, dcmpro, dres, 0);
}

static void do_decompr_lzw(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	// TODO: What are the right lzw settings?
	delzwp.max_code_size = 14;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

struct sit_huffctx {
	deark *c;
	const char *modname;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	struct fmtutil_huffman_tree *ht;
	int eofflag;
	int errflag;
	i64 inpos;
	UI nbits_in_bitsbuf;
	u8 bitsbuf;
};

static u8 sit_huff_getbit(struct sit_huffctx *hctx)
{
	u8 n;

	if(hctx->eofflag || hctx->errflag) return 0;

	if(hctx->nbits_in_bitsbuf<1) {
		if(hctx->inpos >= hctx->dcmpri->pos + hctx->dcmpri->len) {
			hctx->eofflag = 1;
			return 0;
		}
		hctx->bitsbuf = dbuf_getbyte_p(hctx->dcmpri->f, &hctx->inpos);
		hctx->nbits_in_bitsbuf = 8;
	}

	n = (hctx->bitsbuf & (1U<<(hctx->nbits_in_bitsbuf-1))) ? 1 : 0;
	hctx->nbits_in_bitsbuf--;
	return n;
}

static u8 sit_huff_getbyte(struct sit_huffctx *hctx)
{
	UI k;
	u8 v = 0;

	for(k=0; k<8; k++) {
		v = (v<<1) | sit_huff_getbit(hctx);
	}
	return v;
}

// A recursive function to read the tree definition.
static void sit_huff_read_tree(struct sit_huffctx *hctx, u64 curr_code, UI curr_code_nbits)
{
	u8 x;

	if(curr_code_nbits>48) {
		hctx->errflag = 1;
	}
	if(hctx->eofflag || hctx->errflag) return;

	x = sit_huff_getbit(hctx);
	if(hctx->eofflag) return;

	if(x==0) {
		sit_huff_read_tree(hctx, curr_code<<1, curr_code_nbits+1);
		if(hctx->eofflag || hctx->errflag) return;
		sit_huff_read_tree(hctx, (curr_code<<1) | 1, curr_code_nbits+1);
	}
	else {
		int ret;
		i32 val;

		val = (i32)sit_huff_getbyte(hctx);
		ret = fmtutil_huffman_add_code(hctx->c, hctx->ht, curr_code, curr_code_nbits, val);
		if(!ret) {
			hctx->errflag = 1;
		}
	}
}

// While its code is no longer used by Deark, I credit:
//   Unsit Version 1 (January 15, 1988), for StuffIt 1.31: unsit.c
//   by Allan G. Weber
// for helping me understand the StuffIt type 3 (Huffman) compression format.
static void do_decompr_huffman(deark *c, lctx *d, struct member_data *md,
	struct fork_data *frk, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct sit_huffctx *hctx = NULL;
	i64 nbytes_written = 0;

	hctx = de_malloc(c, sizeof(struct sit_huffctx));
	hctx->c = c;
	hctx->modname = "huffman";
	hctx->dcmpri = dcmpri;
	hctx->dcmpro = dcmpro;
	hctx->dres = dres;
	hctx->ht = fmtutil_huffman_create_tree(c, 256, 512);
	hctx->inpos = dcmpri->pos;

	// Read the tree definition
	sit_huff_read_tree(hctx, 0, 0);
	if(hctx->errflag) goto done;
	if(c->debug_level>=2) {
		fmtutil_huffman_dump(c, hctx->ht);
	}
	if(fmtutil_huffman_get_max_bits(hctx->ht)<1) {
		goto done;
	}

	// Read the data section
	while(1) {
		int ret;
		i32 val = 0;
		u8 n;

		if(dcmpro->len_known) {
			if(nbytes_written >= dcmpro->expected_len) break;
		}

		if(hctx->eofflag || hctx->errflag) break;
		n = sit_huff_getbit(hctx);
		if(hctx->eofflag || hctx->errflag) break;
		ret = fmtutil_huffman_decode_bit(hctx->ht, n, &val);
		if(ret==0) {
			hctx->errflag = 1;
			break;
		}
		else if(ret==1) {
			dbuf_writebyte(dcmpro->f, (u8)val);
			nbytes_written++;
		}
	}

done:
	if(hctx->errflag) {
		de_dfilter_set_generic_error(c, dres, hctx->modname);
	}
	if(hctx) {
		fmtutil_huffman_destroy_tree(c, hctx->ht);
		de_free(c, hctx);
	}
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
static void decode_cmpr_meth(deark *c, lctx *d, struct fork_data *fk,
	de_ucstring *s)
{
	const char *name = NULL;
	u8 cmpr = fk->cmpr_meth_etc;

	if(d->file_fmt==1 && cmpr<32 && (cmpr & 16)) {
		fk->is_encrypted = 1;
		cmpr -= 16;
	}

	if(d->file_fmt==2 || cmpr<16) {
		fk->is_a_file = 1;
		fk->cmpr_meth = cmpr;
	}

	if(fk->is_a_file) {
		fk->cmi = find_cmpr_meth_info(c, fk->cmpr_meth);
	}

	if(fk->cmi) {
		name = fk->cmi->name;
	}
	else if(d->file_fmt==1 && fk->cmpr_meth_etc==32) {
		name = "folder";
	}
	else if(d->file_fmt==1 && fk->cmpr_meth_etc==33) {
		name = "end of folder marker";
	}

	if(!name) name="?";
	ucstring_append_flags_item(s, name);
	if(d->file_fmt==1 && fk->is_encrypted) {
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
	decode_cmpr_meth(c, d, &md->rfork, descr);
	de_dbg(c, "rsrc cmpr meth (etc.): %u (%s)", (unsigned int)md->rfork.cmpr_meth_etc,
		ucstring_getpsz(descr));

	md->dfork.cmpr_meth_etc = de_getbyte_p(&pos);
	ucstring_empty(descr);
	decode_cmpr_meth(c, d, &md->dfork, descr);
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

	md->rfork.crc_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "rsrc crc (reported): 0x%04x", (UI)md->rfork.crc_reported);
	md->dfork.crc_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "data crc (reported): 0x%04x", (UI)md->dfork.crc_reported);

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

	if(frk->cmpr_pos + frk->cmpr_len > c->infile->len) {
		de_err(c, "Unexpected end of file");
		goto done;
	}

	de_dbg(c, "cmpr method: %u (%s)", (unsigned int)frk->cmpr_meth,
		frk->cmi?frk->cmi->name:"?");

	if(!frk->cmi) {
		de_err(c, "Unknown compression method: %u", (unsigned int)frk->cmpr_meth);
		goto done;
	}

	if(!frk->cmi->decompressor) {
		de_err(c, "%s[%s fork]: Unsupported compression method: %u (%s)",
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
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frk || !frk->cmi || !frk->cmi->decompressor) {
		goto done;
	}

	de_dbg(c, "decompressing %s fork", frk->forkname);
	de_dbg_indent(c, 1);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = frk->cmpr_pos;
	dcmpri.len = frk->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = frk->unc_len;
	frk->cmi->decompressor(c, d, md, frk, &dcmpri, &dcmpro, &dres);
	if(dres.errcode) {
		de_err(c, "Decompression failed for file %s[%s fork]: %s", ucstring_getpsz_d(md->full_fname),
			frk->forkname, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
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
	if(crc_calc != frk->crc_reported) {
		de_err(c, "CRC check failed for file %s[%s fork]", ucstring_getpsz_d(md->full_fname),
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

// This is for files only. Use do_extract_folder() for folders.
static void do_extract_member_file(deark *c, lctx *d, struct member_data *md)
{
	struct advfudata u;

	ucstring_append_ucstring(md->advf->filename, md->full_fname);
	md->advf->original_filename_flag = 1;
	md->advf->snflags = DE_SNFLAG_FULLPATH;
	de_advfile_set_orig_filename(md->advf, md->fname->sz, md->fname->sz_strlen);

	// resource fork
	if(md->rfork.cmpr_len>0) {
		de_dbg(c, "rsrc fork data at %"I64_FMT", len=%"I64_FMT,
			md->rfork.cmpr_pos, md->rfork.cmpr_len);
		md->advf->rsrcfork.fork_len = md->rfork.unc_len;
		de_dbg_indent(c, 1);
		do_pre_decompress_fork(c, d, md, &md->rfork);
		de_dbg_indent(c, -1);
	}

	// data fork
	if(md->dfork.cmpr_len>0) {
		de_dbg(c, "data fork data at %"I64_FMT", len=%"I64_FMT,
			md->dfork.cmpr_pos, md->dfork.cmpr_len);
		md->advf->mainfork.fork_len = md->dfork.unc_len;
		de_dbg_indent(c, 1);
		do_pre_decompress_fork(c, d, md, &md->dfork);
		de_dbg_indent(c, -1);
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
	int curpath_need_pop = 0;

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
	de_strarray_push(d->curpath, md->fname->str);
	curpath_need_pop = 1;
	de_strarray_make_path(d->curpath, md->full_fname, DE_MPFLAG_NOTRAILINGSLASH);
	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->full_fname));

	if(md->is_folder) {
		if(d->subdir_level >= MAX_NESTING_LEVEL) {
			de_err(c, "Directories nested too deeply");
			retval = 0;
			goto done;
		}
		d->subdir_level++;
		curpath_need_pop = 0;
		do_extract_folder(c, d, md);
		goto done;
	}

	md->rfork.cmpr_pos = pos;
	pos += md->rfork.cmpr_len;
	md->dfork.cmpr_pos = pos;
	//pos += md->dfork.cmpr_len;

	do_extract_member_file(c, d, md);

done:
	if(curpath_need_pop) {
		de_strarray_pop(d->curpath);
	}
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

static void do_oldfmt(deark *c, lctx *d)
{
	i64 pos = 0;

	if(!do_master_header(c, d, pos)) goto done;
	pos += 22;
	do_sequence_of_members(c, d, pos);

done:
	;
}

static void do_v5_comment(deark *c, lctx *d, struct member_data *md, i64 pos, i64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, 4096, s, 0, d->input_encoding);
	de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_v5_list_of_members(deark *c, lctx *d, i64 first_member_pos,
	i64 num_members_expected);

static int do_v5_member_header(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	i64 pos = pos1;
	i64 fnlen, fnlen_sanitized;
	i64 n;
	i64 hdrsize;
	i64 hdr_endpos;
	u32 hdr_crc_reported;
	u32 hdr_crc_calc;
	u8 flags;
	de_ucstring *descr = NULL;
	int saved_indent_level;
	int retval = 0;
	char timestamp_buf[64];

	de_dbg_indent_save(c, &saved_indent_level);
	if(pos1==0) goto done;

	de_dbg(c, "member header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	n = de_getu32be_p(&pos);
	if(n!=0xa5a5a5a5) {
		de_err(c, "Expected member not found at %"I64_FMT, pos1);
		goto done;
	}

	descr = ucstring_create(c);

	pos++; // ver?
	pos++; // ?
	hdrsize = de_getu16be_p(&pos);
	hdr_endpos = pos1 + hdrsize;
	de_dbg(c, "base header at %"I64_FMT", len=%"I64_FMT, pos1, hdrsize);
	de_dbg_indent(c, 1);
	if(hdrsize<48 || hdrsize>2000) {
		de_err(c, "Bad header");
		goto done;
	}

	// calculate actual header crc
	de_crcobj_reset(d->crco_hdr);
	de_crcobj_addslice(d->crco_hdr, c->infile, pos1, 32);
	de_crcobj_addbuf(d->crco_hdr, (const u8*)"\0\0", 2);
	de_crcobj_addslice(d->crco_hdr, c->infile, pos1+34, hdrsize-34);
	hdr_crc_calc = de_crcobj_getval(d->crco_hdr);

	pos++; // ?
	flags = de_getbyte_p(&pos);
	ucstring_empty(descr);
	if(flags & 0x40) {
		md->is_folder = 1;
		ucstring_append_flags_item(descr, "folder");
	}
	if(flags & 0x20) {
		md->dfork.is_encrypted = 1;
		md->rfork.is_encrypted = 1;
		ucstring_append_flags_item(descr, "encrypted");
	}
	de_dbg(c, "flags: 0x%02x (%s)", (UI)flags, ucstring_getpsz_d(descr));

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

	n = de_getu32be_p(&pos);
	de_dbg(c, "prev: %"I64_FMT, n);
	md->v5_next_member_pos = de_getu32be_p(&pos);
	de_dbg(c, "next: %"I64_FMT, md->v5_next_member_pos);
	retval = 1;

	// at offset 26
	n = de_getu32be_p(&pos);
	de_dbg(c, "parent: %"I64_FMT, n);

	fnlen = de_getu16be_p(&pos);
	de_dbg(c, "filename len: %u", (UI)fnlen);
	fnlen_sanitized = de_min_int(fnlen, 1024);

	hdr_crc_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "header crc (reported): 0x%04x", (UI)hdr_crc_reported);
	de_dbg(c, "header crc (calculated): 0x%04x", (UI)hdr_crc_calc);
	if(hdr_crc_reported != hdr_crc_calc) {
		de_warn(c, "Bad header CRC (reported 0x%04x, calculated 0x%04x)", (UI)hdr_crc_reported,
			(UI)hdr_crc_calc);
	}

	// at offset 34
	if(md->is_folder) {
		md->v5_first_entry_pos = de_getu32be_p(&pos);
		de_dbg(c, "offset of first entry: %"I64_FMT, md->v5_first_entry_pos);

		n = de_getu32be_p(&pos);
		de_dbg(c, "folder size: %"I64_FMT, n);

		pos += 2; // data fork old crc16
		pos += 2; // ?

		md->v5_num_files_in_folder = de_getu16be_p(&pos);
		de_dbg(c, "number of files: %"I64_FMT, md->v5_num_files_in_folder);
	}
	else {
		md->dfork.unc_len = de_getu32be_p(&pos);
		de_dbg(c, "data fork uncmpr len: %"I64_FMT, md->dfork.unc_len);
		// at offset 38
		md->dfork.cmpr_len = de_getu32be_p(&pos);
		de_dbg(c, "data fork cmpr len: %"I64_FMT, md->dfork.cmpr_len);

		md->dfork.crc_reported = (u32)de_getu16be_p(&pos);
		de_dbg(c, "data fork old crc (reported): 0x%04x", (UI)md->dfork.crc_reported);

		pos += 2; // ?

		md->dfork.cmpr_meth_etc = de_getbyte_p(&pos);
		ucstring_empty(descr);
		decode_cmpr_meth(c, d, &md->dfork, descr);
		de_dbg(c, "data fork cmpr meth: %u (%s)", (unsigned int)md->dfork.cmpr_meth_etc,
			ucstring_getpsz(descr));

		// at offset 47
		n = (i64)de_getbyte_p(&pos);
		de_dbg(c, "data fork passwd len: %u", (UI)n);
		pos += n;
	}

	md->fname = dbuf_read_string(c->infile, pos, fnlen_sanitized, fnlen_sanitized, 0, d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fname->str));
	de_strarray_push(d->curpath, md->fname->str);
	md->v5_need_strarray_pop = 1;
	pos += fnlen;

	if(hdr_endpos-pos >= 5) {
		n = de_getu16be_p(&pos); // comment len
		pos += 2;
		if(pos + n <= hdr_endpos) {
			do_v5_comment(c, d, md, pos, n);
		}
	}

	de_dbg_indent(c, -1); // end of first part of header

	pos = hdr_endpos;

	if(!md->is_folder) {
		UI flags2;

		flags2 = (UI)de_getu16be_p(&pos);
		de_dbg(c, "flags2: 0x%04x", flags2);
		pos += 2; // ?

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

		pos += 22; // ?

		if(flags2 & 0x0001) {
			md->rfork.unc_len = de_getu32be_p(&pos);
			de_dbg(c, "rsrc fork uncmpr len: %"I64_FMT, md->rfork.unc_len);
			md->rfork.cmpr_len = de_getu32be_p(&pos);
			de_dbg(c, "rsrc fork cmpr len: %"I64_FMT, md->rfork.cmpr_len);

			md->rfork.crc_reported = (u32)de_getu16be_p(&pos);
			de_dbg(c, "rsrc fork old crc (reported): 0x%04x", (UI)md->rfork.crc_reported);

			pos += 2; // ?

			md->rfork.cmpr_meth_etc = de_getbyte_p(&pos);
			ucstring_empty(descr);
			decode_cmpr_meth(c, d, &md->rfork, descr);
			de_dbg(c, "rsrc fork cmpr meth: %u (%s)", (unsigned int)md->rfork.cmpr_meth_etc,
				ucstring_getpsz(descr));

			n = (i64)de_getbyte_p(&pos);
			de_dbg(c, "rsrc fork passwd len: %u", (UI)n);
			pos += n;
		}
	}

	if(!md->is_folder) {
		md->rfork.cmpr_pos = pos;
		pos += md->rfork.cmpr_len;

		md->dfork.cmpr_pos = pos;
		pos += md->dfork.cmpr_len;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(descr);
	return retval;
}

static int do_v5_member(deark *c, lctx *d, i64 member_idx,
	i64 pos1, i64 *pnext_member_pos)
{
	struct member_data *md = NULL;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	if(pos1==0) goto done;

	if(!de_inthashtable_add_item(c, d->v5_offsets_seen, pos1, NULL)) {
		de_err(c, "Loop detected");
		goto done;
	}

	md = de_malloc(c, sizeof(struct member_data));
	md->rfork.is_rsrc_fork = 1;
	md->dfork.forkname = "data";
	md->rfork.forkname = "resource";

	de_dbg(c, "member[%d] at %"I64_FMT, (int)member_idx, pos1);
	de_dbg_indent(c, 1);

	if(pos1<0 || pos1>=c->infile->len) {
		de_err(c, "Bad file offset");
		goto done;
	}

	md->advf = de_advfile_create(c);

	if(!do_v5_member_header(c, d, md, pos1)) goto done;
	*pnext_member_pos = md->v5_next_member_pos;

	if(!md->full_fname) {
		md->full_fname = ucstring_create(c);
		de_strarray_make_path(d->curpath, md->full_fname, DE_MPFLAG_NOTRAILINGSLASH);
	}
	de_dbg(c, "full name: \"%s\"", ucstring_getpsz_d(md->full_fname));

	if(md->is_folder) {
		do_extract_folder(c, d, md);

		if(d->subdir_level >= MAX_NESTING_LEVEL) {
			de_err(c, "Directories nested too deeply");
			retval = 0;
			goto done;
		}
		de_dbg(c, "[folder contents]");
		de_dbg_indent(c, 1);
		d->subdir_level++;
		do_v5_list_of_members(c, d, md->v5_first_entry_pos, md->v5_num_files_in_folder);
		d->subdir_level--;
		de_dbg_indent(c, -1);
	}
	else {
		do_extract_member_file(c, d, md);
	}

	retval = 1;

done:
	if(md) {
		if(md->v5_need_strarray_pop) {
			de_strarray_pop(d->curpath);
		}
		de_destroy_stringreaderdata(c, md->fname);
		ucstring_destroy(md->full_fname);
		de_advfile_destroy(md->advf);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_v5_list_of_members(deark *c, lctx *d, i64 first_member_pos,
	i64 num_members_expected)
{
	i64 member_count = 0;
	i64 pos = first_member_pos;

	while(1) {
		int ret;
		i64 next_pos = 0;

		if(pos==0) break;
		if(member_count >= num_members_expected) break;

		ret = do_v5_member(c, d, member_count, pos, &next_pos);
		if(!ret) break;
		if(next_pos==0) break;

		pos = next_pos;
		member_count++;
	}
}

static int do_v5_archivehdr(deark *c, lctx *d, i64 pos1)
{
	i64 n;
	i64 pos = pos1;
	int retval = 0;

	de_dbg(c, "archive header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos += 80; // text
	pos += 2; // ?
	n = de_getbyte_p(&pos);
	de_dbg(c, "archive version: %u", (UI)n);
	d->v5_archive_flags = de_getbyte_p(&pos);
	de_dbg(c, "archive flags: 0x%02x", (UI)d->v5_archive_flags);

	d->archive_size = de_getu32be_p(&pos);
	de_dbg(c, "reported archive file size: %"I64_FMT, d->archive_size);

	pos += 4; // ?

	d->nmembers = (int)de_getu16be_p(&pos);
	de_dbg(c, "number of root members: %d", d->nmembers);

	d->v5_first_entry_pos = de_getu32be_p(&pos);
	de_dbg(c, "pos of first root member: %"I64_FMT, d->v5_first_entry_pos);

	n = de_getu16be_p(&pos);
	de_dbg(c, "archive crc (reported): 0x%04x", (UI)n);

	//if(d->v5_archive_flags & 0x10) pos += 14; // reserved
	// TODO: Archive comment
	retval = 1;

	de_dbg_indent(c, -1);
	return retval;
}

static void do_v5(deark *c, lctx *d)
{
	d->v5_offsets_seen = de_inthashtable_create(c);
	if(!do_v5_archivehdr(c, d, 0)) goto done;
	do_v5_list_of_members(c, d, d->v5_first_entry_pos, d->nmembers);
done:
	;
}

static void de_run_stuffit(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "SIT!", 4)) {
		d->file_fmt = 1;
	}
	else if(!dbuf_memcmp(c->infile, 0, "StuffIt ", 8)) {
		d->file_fmt = 2;
	}
	else {
		de_err(c, "Not a StuffIt file, or unknown version.");
		goto done;
	}

	if(d->file_fmt==2) {
		d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UTF8);
	}
	else {
		d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);
	}

	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);
	d->crco_rfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	d->crco_dfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	d->crco_hdr = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	if(d->file_fmt==1) {
		de_declare_fmt(c, "StuffIt, old format");
		do_oldfmt(c, d);
	}
	else if(d->file_fmt==2) {
		de_declare_fmt(c, "StuffIt, v5 format");
		do_v5(c, d);
	}
	else {
		de_err(c, "This version of StuffIt format is not supported.");
	}

done:
	if(d) {
		de_crcobj_destroy(d->crco_rfork);
		de_crcobj_destroy(d->crco_dfork);
		de_crcobj_destroy(d->crco_hdr);
		de_strarray_destroy(d->curpath);
		if(d->v5_offsets_seen) de_inthashtable_destroy(c, d->v5_offsets_seen);
		de_free(c, d);
	}
}

static int de_identify_stuffit(deark *c)
{
	u8 buf[9];

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "SIT!", 4)) {
		return 100;
	}
	if(!de_memcmp(buf, "StuffIt (", 9)) {
		if(de_getbyte(82)==0x05) return 100;
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
