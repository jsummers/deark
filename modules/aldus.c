// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// Aldus LZW, Aldus PKZP

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_aldus_inst);

#define ALDUS_MAX_SEGS  2048 // arbitrary

struct seg_data {
	i64 cmpr_pos;
	i64 cmpr_len;
	i64 orig_len;
};

struct fork_data {
	u8 fork_exists;
	u8 is_rsrc_fork;
	u8 decompress_succeeded;
	i64 pos;
	i64 orig_len;
	const char *forkname;
	i64 nominal_seg_size;
	i64 nsegs;
	i64 orig_len_of_last_seg;
	struct seg_data *sdata; // array[nsegs]
};

typedef struct localctx_aldus {
	UI fmtcode;
	de_encoding input_encoding;
	u8 errflag;
	u8 need_errmsg;
	u8 has_4cc_codes;
	u8 no_dfork_flag;
	u8 found_rsrc_fork;
	i64 fork1pos;
	i64 total_orig_len;
	struct de_advfile *advf;
	struct de_stringreaderdata *fname;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	struct fork_data rfork;
	struct fork_data dfork;
} lctx;

static void decompress_fork(deark *c, lctx *d, struct fork_data *fkd,
	dbuf *outf)
{
	i64 i;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	for(i=0; i<fkd->nsegs; i++) {
		i64 len1, len_diff;

		de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

		dcmpri.f = c->infile;
		dcmpri.pos = fkd->sdata[i].cmpr_pos;
		dcmpri.len = fkd->sdata[i].cmpr_len;
		dcmpro.f = outf;

		dbuf_flush(dcmpro.f);
		len1 = dcmpro.f->len;

		if(d->fmtcode==1) {
			struct de_lzw_params delzwp;

			de_zeromem(&delzwp, sizeof(struct de_lzw_params));
			delzwp.fmt = DE_LZWFMT_TIFFNEW;
			delzwp.max_code_size = 12;
			fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);
		}
		else {
			// Each segment seems to be compressed independently. They don't
			// share a history buffer.
			// TODO: It's not efficient to start over for each segment, because
			// DCL Implode has some overhead. We should have a better way to do it.
			fmtutil_dclimplode_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
		}
		dbuf_flush(dcmpro.f);

		if(dres.errcode) {
			de_err(c, "[%s fork, seg %"I64_FMT"] Decompression failed: %s",
				fkd->forkname, i, de_dfilter_get_errmsg(c, &dres));
			goto done;
		}

		len_diff = dcmpro.f->len - len1;
		if(len_diff != fkd->sdata[i].orig_len) {
			de_err(c, "[%s fork, seg %"I64_FMT"] Expected %"I64_FMT" bytes, "
				"got %"I64_FMT, fkd->forkname, i, fkd->sdata[i].orig_len,
				len_diff);
			goto done;
		}
	}

	fkd->decompress_succeeded = 1;

done:
	if(!fkd->decompress_succeeded) {
		d->errflag = 1;
	}
}

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	lctx *d = (lctx*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		decompress_fork(c, d, &d->dfork, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		decompress_fork(c, d, &d->rfork, afp->outf);
	}

	return 1;
}

static void read_timestamp(deark *c, lctx *d)
{
	i64 n;
	struct de_timestamp *ts;
	char timestamp_buf[64];

	ts = &d->advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY];

	if(d->fmtcode==2) {
		n = de_getu32le(54);
		// Best guess is the epoch is the beginning of Dec. 30, 1899.
		// But this could very well be wrong.
		n -= (i64)86400*(70*365 + 17 + 2);
		if(n<=0) return;
		de_unix_time_to_timestamp(n, ts, 0);
	}
	else if(d->fmtcode==1 && !d->has_4cc_codes) {
		n = de_geti32le(54);
		if(n<=0) return;
		de_unix_time_to_timestamp(n, ts, 0);
	}
	else if(d->fmtcode==1 && d->has_4cc_codes) {
		n = de_getu32be(68);
		if(n<=0x01000000) return;
		de_mac_time_to_timestamp(n, ts);
	}
	else {
		return;
	}

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "timestamp: %s", timestamp_buf);
}

static void read_typecreator_codes(deark *c, lctx *d, i64 pos)
{
	dbuf_read_fourcc(c->infile, pos, &d->filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", d->filetype.id_dbgstr);
	de_memcpy(d->advf->typecode, d->filetype.bytes, 4);
	d->advf->has_typecode = 1;

	dbuf_read_fourcc(c->infile, pos+4, &d->creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", d->creator.id_dbgstr);
	de_memcpy(d->advf->creatorcode, d->creator.bytes, 4);
	d->advf->has_creatorcode = 1;
}

// May set d->found_rsrc_fork and d->rfork.pos.
static void aldus_read_fork(deark *c, lctx *d, struct fork_data *fkd)
{
	i64 cur_cmpr_pos;
	i64 num_orig_bytes_remaining;
	i64 pos1 = fkd->pos;
	i64 pos;
	i64 i;
	i64 offset_to_seg_table;
	i64 data_area_pos, next_fork_pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	fkd->fork_exists = 1;
	de_dbg(c, "fork at %"I64_FMT, fkd->pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "fork type: %s", fkd->forkname);

	offset_to_seg_table = de_getu16be(pos1);

	fkd->nominal_seg_size = de_getu16be(pos1+2);
	de_dbg(c, "nominal orig bytes/seg: %"I64_FMT, fkd->nominal_seg_size);
	if(fkd->nominal_seg_size<1) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	fkd->orig_len_of_last_seg = de_getu16be(pos1+4);
	de_dbg(c, "last seg orig size: %"I64_FMT, fkd->orig_len_of_last_seg);

	fkd->nsegs = de_getu32be(pos1+6);
	de_dbg(c, "num segs: %"I64_FMT, fkd->nsegs);

	if(fkd->nsegs<1 || fkd->nsegs>ALDUS_MAX_SEGS) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	fkd->orig_len = fkd->nominal_seg_size*(fkd->nsegs-1) + fkd->orig_len_of_last_seg;
	de_dbg(c, "orig len (calculated): %"I64_FMT, fkd->orig_len);

	pos = pos1+14;
	data_area_pos = de_getu32be_p(&pos);
	de_dbg(c, "data area pos: %"I64_FMT, data_area_pos);
	next_fork_pos = de_getu32be_p(&pos);
	de_dbg(c, "next fork pos: %"I64_FMT, next_fork_pos);
	if((!fkd->is_rsrc_fork) && (d->total_orig_len > fkd->orig_len) &&
		(next_fork_pos < c->infile->len))
	{
		de_dbg(c, "[has resource fork]");
		d->found_rsrc_fork = 1;
		d->rfork.pos = next_fork_pos;
	}

	fkd->sdata = de_mallocarray(c, fkd->nsegs, sizeof(struct seg_data));

	pos = pos1+offset_to_seg_table;
	de_dbg(c, "segment table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	cur_cmpr_pos = data_area_pos;
	num_orig_bytes_remaining = fkd->orig_len;
	for(i=0; i<fkd->nsegs; i++) {
		fkd->sdata[i].cmpr_pos = cur_cmpr_pos;
		// Note that cmpr_len may be padded (with garbage?) to always be an
		// even number.
		// (Not a problem, since both compression schemes are self-terminating.)
		fkd->sdata[i].cmpr_len = de_getu16be_p(&pos);
		cur_cmpr_pos += fkd->sdata[i].cmpr_len;

		fkd->sdata[i].orig_len = fkd->nominal_seg_size;
		if(fkd->sdata[i].orig_len > num_orig_bytes_remaining) {
			fkd->sdata[i].orig_len = num_orig_bytes_remaining;
		}
		num_orig_bytes_remaining -= fkd->sdata[i].orig_len;

		de_dbg(c, "seg[%"I64_FMT"]: pos=%"I64_FMT", c_len=%"I64_FMT
			", u_len=%"I64_FMT, i,fkd->sdata[i].cmpr_pos,
			fkd->sdata[i].cmpr_len, fkd->sdata[i].orig_len);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void destroy_fork_contents(deark *c, struct fork_data *fkd)
{
	de_free(c, fkd->sdata);
}

static void aldus_main(deark *c, de_module_params *mparams, UI fmtcode)
{
	lctx *d = NULL;
	i64 pos;
	i64 n;
	u8 frag_flag = 0;

	d = de_malloc(c, sizeof(lctx));
	d->fmtcode = fmtcode;
	d->rfork.is_rsrc_fork = 1;
	d->dfork.forkname = "data";
	d->rfork.forkname = "resource";

	d->advf = de_advfile_create(c);
	d->advf->userdata = (void*)d;
	d->advf->enable_wbuffer = 1;

	// For lack of a better idea, this is how we distinguish Mac and PC formats.
	if(d->fmtcode==1 && de_getbyte(60)!=0 && de_getbyte(64)!=0) {
		d->has_4cc_codes = 1;
	}

	d->input_encoding = de_get_input_encoding(c, NULL,
		(d->has_4cc_codes?DE_ENCODING_MACROMAN:DE_ENCODING_WINDOWS1252));

	d->fork1pos = de_getu16be(16);
	de_dbg(c, "first fork pos: %"I64_FMT, d->fork1pos);
	if(d->fork1pos<100) {
		d->need_errmsg = 1;
		goto done;
	}

	d->fname = dbuf_read_string(c->infile, 18, 32, 32, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(d->fname->str));

	pos = 50;
	d->total_orig_len = de_getu32be_p(&pos);
	de_dbg(c, "orig len (sum of all forks): %"I64_FMT, d->total_orig_len);

	read_timestamp(c, d); // offset 54 or 68

	if(d->has_4cc_codes) {
		read_typecreator_codes(c, d, 60);
	}

	n = de_getu32be(78);
	if(n != d->fork1pos) {
		// The 2-byte field at offset 16, and the 4(?)-byte field at offset 78,
		// are always the same. Either 100 or 200.
		// So I don't know which is the one I want.
		d->need_errmsg = 1;
		goto done;
	}

	if(d->fmtcode==1) {
		d->no_dfork_flag = de_getbyte(82);
	}

	if(d->fmtcode==2) {
		frag_flag = de_getbyte(98);
	}
	if(frag_flag) {
		de_err(c, "Unsupported type of file (fragmented?)");
		goto done;
	}

	if(d->no_dfork_flag) {
		d->rfork.pos = d->fork1pos;
		aldus_read_fork(c, d, &d->rfork);
		if(d->errflag) goto done;
	}
	else {
		// We're assuming that if both forks exist, the data fork is always
		// first.
		d->dfork.pos = d->fork1pos;
		aldus_read_fork(c, d, &d->dfork);
		if(d->errflag) goto done;

		if(d->found_rsrc_fork) {
			aldus_read_fork(c, d, &d->rfork);
			if(d->errflag) goto done;
		}
	}

	ucstring_append_ucstring(d->advf->filename, d->fname->str);
	d->advf->original_filename_flag = 1;

	de_advfile_set_orig_filename(d->advf, d->fname->sz,
		d->fname->sz_strlen);

	if(!d->dfork.fork_exists && !d->rfork.fork_exists) goto done;

	if(d->dfork.fork_exists) {
		d->advf->mainfork.fork_exists = 1;
		d->advf->mainfork.fork_len = d->dfork.orig_len;
	}
	if(d->rfork.fork_exists) {
		d->advf->rsrcfork.fork_exists = 1;
		d->advf->rsrcfork.fork_len = d->rfork.orig_len;
	}

	d->advf->writefork_cbfn = my_advfile_cbfn;

	de_advfile_run(d->advf);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported file");
		}
		de_advfile_destroy(d->advf);
		destroy_fork_contents(c, &d->dfork);
		destroy_fork_contents(c, &d->rfork);
		de_destroy_stringreaderdata(c, d->fname);
		de_free(c, d);
	}
}

static void de_run_aldus_inst(deark *c, de_module_params *mparams)
{
	u8 b;

	b = de_getbyte(6);
	if(b=='L') {
		de_declare_fmt(c, "Aldus LZW");
		aldus_main(c, mparams, 1);
	}
	else {
		de_declare_fmt(c, "Aldus PKZP");
		aldus_main(c, mparams, 2);
	}
}

static int de_identify_aldus_inst(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const u8*)"ALDUS ", 6)) return 0;

	if(!dbuf_memcmp(c->infile, 6, (const u8*)"PKZP  2.", 8))
		return 100;
	if(!dbuf_memcmp(c->infile, 6, (const u8*)"LZW   1.", 8))
		return 100;
	return 0;
}

void de_module_aldus_inst(deark *c, struct deark_module_info *mi)
{
	mi->id = "aldus_inst";
	mi->desc = "Aldus LZW and PKZP";
	mi->run_fn = de_run_aldus_inst;
	mi->identify_fn = de_identify_aldus_inst;
}
