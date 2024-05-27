// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_tome);

// Tome (Mac installation archive)

struct tome_ctx;
struct tome_md;

struct tome_fork_data {
	struct tome_md *md;
	UI forknum;
	u8 is_compressed;
	u8 decompress_succeeded;
	u32 checksum_reported;
	u32 checksum_calc;
	i64 orig_len;
	i64 cmpr_pos;
	i64 cmpr_len;
	char forkname[8];
};

struct tome_md {
	deark *c;
	struct tome_ctx *d;
	i64 member_idx;
	i64 hdr_pos;
	i64 namelen;
	UI finder_flags;

	struct de_advfile *advf;
	struct de_stringreaderdata *fname;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	struct de_timestamp mod_time;
	struct de_timestamp create_time;

	struct tome_fork_data frk[2];
};

struct tome_ctx {
	de_encoding input_encoding;
	u8 fatalerrflag;
	u8 need_errmsg;
	i64 num_members;
};

static void tome_writelistener(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct tome_fork_data *fdata = (struct tome_fork_data*)userdata;
	struct tome_md *md = fdata->md;
	i64 i;

	for(i=0; i<buf_len; i++) {
		md->frk[fdata->forknum].checksum_calc = (u32)buf[i] ^
			((u32)(md->frk[fdata->forknum].checksum_calc >> 0x18) +
				(u32)(md->frk[fdata->forknum].checksum_calc <<8));
	}
}

static void tome_decompress_fork(struct tome_md *md, UI fn, dbuf *outf)
{
	deark *c = md->c;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->frk[fn].cmpr_pos;
	dcmpri.len = md->frk[fn].cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->frk[fn].orig_len;

	fmtutil_ic1_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);

	if(dres.errcode) {
		de_err(c, "Decompression failed for file %s[%s fork]: %s",
			ucstring_getpsz_d(md->fname->str),
			md->frk[fn].forkname, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	md->frk[fn].decompress_succeeded = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void tome_copy_fork(struct tome_md *md, UI fn, dbuf *outf)
{
	i64 ipos;
	i64 nbytes_left;

	ipos = md->frk[fn].cmpr_pos;
	nbytes_left = md->frk[fn].orig_len;
	while(nbytes_left>0) {
		i64 nbytes_this_segment;

		ipos += 4; // skip over marker (?)
		nbytes_this_segment = de_min_int(nbytes_left, 65536);
		dbuf_copy(md->advf->c->infile, ipos, nbytes_this_segment, outf);
		ipos += nbytes_this_segment;
		nbytes_left -= nbytes_this_segment;
	}

	md->frk[fn].decompress_succeeded = 1;
}

static int tome_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	UI forknum;
	struct tome_md *md = (struct tome_md*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		forknum = 0;
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		forknum = 1;
	}
	else {
		return 0;
	}

	if(md->frk[forknum].is_compressed) {
		tome_decompress_fork(md, forknum, afp->outf);
	}
	else {
		tome_copy_fork(md, forknum, afp->outf);
	}
	return 1;
}

static void tome_read_timestamp(deark *c, struct tome_ctx *d, struct tome_md *md,
	i64 pos, UI tzi, const char *name)
{
	i64 n;
	struct de_timestamp ts;
	char timestamp_buf[64];

	n = dbuf_getu32be(c->infile, pos);
	de_mac_time_to_timestamp(n, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s time: %"U64_FMT" (%s)", name, n, timestamp_buf);
	md->advf->mainfork.fi->timestamp[tzi] = ts;
}

static int tome_test_checksum(u32 ckr, u32 ckc)
{
	u32 ck;
	UI i;

	ck = ckr ^ ckc;
	for(i=0; i<4; i++) {
		if((ck&0xff)!=0x00 && (ck&0xff)!=0xff) return 0;
		ck >>= 8;
	}
	return 1;
}

static void tome_do_member(deark *c, struct tome_ctx *d, struct tome_md *md)
{
	i64 pos = md->hdr_pos;
	i64 fnlen;
	UI fn;
	i64 n;
	i64 seqno;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member header at %"I64_FMT, md->hdr_pos);
	de_dbg_indent(c, 1);

	n = de_getu16be_p(&pos);
	de_dbg(c, "unk. f1: %u", (UI)n);
	seqno = de_getu32be_p(&pos);
	de_dbg(c, "file idx: %"I64_FMT, seqno);
	if(seqno!=(md->member_idx+1)) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	fnlen = de_getbyte_p(&pos);
	if(fnlen>31) goto done;
	md->fname = dbuf_read_string(c->infile, pos, fnlen, fnlen, 0, d->input_encoding);
	pos += 31;
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fname->str));

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

	tome_read_timestamp(c, d, md, pos, DE_TIMESTAMPIDX_CREATE, "create");
	pos += 4;
	tome_read_timestamp(c, d, md, pos, DE_TIMESTAMPIDX_MODIFY, "modify");
	pos += 4;

	pos += 2; // version?
	pos += 2; // ?

	md->finder_flags = (UI)dbuf_getu16be_p(c->infile, &pos);
	de_dbg(c, "finder flags: 0x%04x", md->finder_flags);
	md->advf->finderflags = (u16)md->finder_flags;
	md->advf->has_finderflags = 1;

	for(fn=0; fn<2; fn++) {
		md->frk[fn].orig_len = de_getu32be_p(&pos);
		md->frk[fn].cmpr_pos = de_getu32be_p(&pos);
		md->frk[fn].cmpr_len = de_getu32be_p(&pos);
		de_dbg(c, "orig len [%s]: %"I64_FMT, md->frk[fn].forkname, md->frk[fn].orig_len);
		de_dbg(c, "cmpr pos [%s]: %"I64_FMT, md->frk[fn].forkname, md->frk[fn].cmpr_pos);
		de_dbg(c, "cmpr len [%s]: %"I64_FMT, md->frk[fn].forkname, md->frk[fn].cmpr_len);
		md->frk[fn].checksum_reported = (u32)de_getu32be_p(&pos);
		de_dbg(c, "checksum (reported) [%s]: 0x%08x", md->frk[fn].forkname,
			(UI)md->frk[fn].checksum_reported);
	}

	md->advf->mainfork.fork_len = md->frk[0].orig_len;
	md->advf->rsrcfork.fork_len = md->frk[1].orig_len;
	md->advf->mainfork.fork_exists = (md->frk[0].orig_len!=0 ||
		md->frk[1].orig_len==0);
	md->advf->rsrcfork.fork_exists = (md->frk[1].orig_len!=0);

	md->advf->mainfork.writelistener_cb = tome_writelistener;
	md->advf->mainfork.userdata_for_writelistener = (void*)&md->frk[0];
	md->advf->rsrcfork.writelistener_cb = tome_writelistener;
	md->advf->rsrcfork.userdata_for_writelistener = (void*)&md->frk[1];
	md->frk[0].checksum_calc = 0;
	md->frk[1].checksum_calc = 0;

	for(fn=0; fn<2; fn++) {
		i64 expected_cmpr_len;
		i64 tmpn;

		if(md->frk[fn].orig_len!=0) {
			tmpn = de_pad_to_n(md->frk[fn].orig_len, 65536);
			expected_cmpr_len = md->frk[fn].orig_len + tmpn/16384;
			if(md->frk[fn].cmpr_len != expected_cmpr_len) {
				md->frk[fn].is_compressed = 1;
			}
		}
	}

	md->advf->userdata = (void*)md;
	md->advf->writefork_cbfn = tome_advfile_cbfn;
	ucstring_append_ucstring(md->advf->filename, md->fname->str);
	md->advf->original_filename_flag = 1;
	de_advfile_set_orig_filename(md->advf, md->fname->sz, md->fname->sz_strlen);

	de_advfile_run(md->advf);

	for(fn=0; fn<2; fn++) {
		int ckres;

		if(md->frk[fn].orig_len && md->frk[fn].decompress_succeeded) {
			de_dbg(c, "checksum (calculated) [%s]: 0x%08x", md->frk[fn].forkname,
				(UI)md->frk[fn].checksum_calc);
			ckres = tome_test_checksum(md->frk[fn].checksum_reported,
				md->frk[fn].checksum_calc);
			de_dbg(c, "checksum result [%s]: 0x%08x (%s)", md->frk[fn].forkname,
				(UI)(md->frk[fn].checksum_calc ^ md->frk[fn].checksum_reported),
				(ckres?"ok":"error"));
			if(!ckres) {
				de_err(c, "Checksum failed [%s]", md->frk[fn].forkname);
			}
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void destroy_tome_md(deark *c, struct tome_md *md)
{
	if(!md) return;
	de_advfile_destroy(md->advf);
	de_destroy_stringreaderdata(c, md->fname);
	de_free(c, md);
}

static void de_run_tome(deark *c, de_module_params *mparams)
{
	struct tome_ctx *d = NULL;
	struct tome_md *md = NULL;
	i64 pos;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct tome_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);

	pos = 0;
	de_dbg(c, "archive header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 4;
	pos += 24;
	d->num_members = de_getu32be_p(&pos);
	de_dbg(c, "number of members: %"I64_FMT, d->num_members);
	pos += 4;
	de_dbg_indent(c, -1);

	for(i=0; i<d->num_members; i++) {
		if(md) {
			destroy_tome_md(c, md);
		}
		md = de_malloc(c, sizeof(struct tome_md));
		md->c = c;
		md->d = d;
		md->frk[0].md = md;
		md->frk[1].md = md;
		md->frk[0].forknum = 0;
		md->frk[1].forknum = 1;
		de_strlcpy(md->frk[0].forkname, "data", sizeof(md->frk[0].forkname));
		de_strlcpy(md->frk[1].forkname, "rsrc", sizeof(md->frk[1].forkname));
		md->advf = de_advfile_create(c);
		md->advf->enable_wbuffer = 1;
		md->member_idx = i;
		md->hdr_pos = pos;
		tome_do_member(c, d, md);
		if(d->fatalerrflag) goto done;
		pos += 128;
	}

done:
	destroy_tome_md(c, md);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Failed to decode Tome file");
		}
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_tome(deark *c)
{
	UI n;

	n = (UI)de_getu32be(0);
	if(n!=0x6b630001U) return 0;
	return 90;
}

void de_module_tome(deark *c, struct deark_module_info *mi)
{
	mi->id = "tome";
	mi->desc = "Tome";
	mi->run_fn = de_run_tome;
	mi->identify_fn = de_identify_tome;
	mi->flags |= DE_MODFLAG_WARNPARSEONLY;
}
