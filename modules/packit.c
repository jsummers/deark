// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// PackIt (Mac format, kind of a predecessor of StuffIt)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_packit);

#define CODE_PMa  0x504d61U
#define CODE_PEnd 0x50456e64U

struct packit_md {
	i64 marker_pos; // in c->infile
	i64 total_encoded_size; // in c->infile, from the start of marker
	i64 hdr_pos_in_inf; // in ->inf, pos of the NameLen field
	dbuf *inf; // Copy of c->infile or ->unc_data; do not close
	u8 is_compressed;
	u8 encoding_type;
	i64 namelen;
	UI finder_flags;

	struct de_advfile *advf;
	struct de_stringreaderdata *fname;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	struct de_timestamp mod_time;
	struct de_timestamp create_time;
	i64 dfork_pos;  // in ->inf
	i64 dfork_len;
	i64 rfork_pos;  // in ->inf
	i64 rfork_len;
	dbuf *unc_data;
};

struct packit_ctx {
	u8 fatalerrflag;
	u8 need_errmsg;
	struct de_crcobj *crco_datarsrc;
	struct de_crcobj *crco_hdr;
};

static void packit_destroy_pmd(deark *c, struct packit_md *pmd)
{
	if(!pmd) return;
	dbuf_close(pmd->unc_data);
	de_destroy_stringreaderdata(c, pmd->fname);
	de_advfile_destroy(pmd->advf);
	de_free(c, pmd);
}

static void packit_read_member_header(deark *c, struct packit_ctx *d,
	struct packit_md *pmd)
{
	i64 pos = pmd->hdr_pos_in_inf;
	i64 n;
	u32 hdr_crc_reported;
	u32 hdr_crc_calc;
	char timestamp_buf[64];

	pmd->namelen = (i64)dbuf_getbyte_p(pmd->inf, &pos);
	if(pmd->namelen<1 || pmd->namelen>63) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
	pmd->fname = dbuf_read_string(pmd->inf, pos, pmd->namelen, pmd->namelen,
		0, DE_ENCODING_MACROMAN);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(pmd->fname->str));
	pos += 63;

	dbuf_read_fourcc(pmd->inf, pos, &pmd->filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", pmd->filetype.id_dbgstr);
	de_memcpy(pmd->advf->typecode, pmd->filetype.bytes, 4);
	pmd->advf->has_typecode = 1;
	pos += 4;
	dbuf_read_fourcc(pmd->inf, pos, &pmd->creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", pmd->creator.id_dbgstr);
	de_memcpy(pmd->advf->creatorcode, pmd->creator.bytes, 4);
	pmd->advf->has_creatorcode = 1;
	pos += 4;

	pmd->finder_flags = (UI)dbuf_getu16be_p(pmd->inf, &pos);
	de_dbg(c, "finder flags: 0x%04x", pmd->finder_flags);
	pmd->advf->finderflags = (u16)pmd->finder_flags;
	pmd->advf->has_finderflags = 1;

	pos += 2; // "locked"

	pmd->dfork_pos = pmd->hdr_pos_in_inf + 94;
	pmd->dfork_len = dbuf_getu32be_p(pmd->inf, &pos);
	de_dbg(c, "data fork len: %"I64_FMT, pmd->dfork_len);
	pmd->advf->mainfork.fork_len = pmd->dfork_len;

	pmd->rfork_pos = pmd->dfork_pos + pmd->dfork_len;
	pmd->rfork_len = dbuf_getu32be_p(pmd->inf, &pos);
	de_dbg(c, "rsrc fork len: %"I64_FMT, pmd->rfork_len);
	pmd->advf->rsrcfork.fork_len = pmd->rfork_len;

	pmd->advf->mainfork.fork_exists = (pmd->dfork_len!=0 ||
		pmd->rfork_len==0);
	pmd->advf->rsrcfork.fork_exists = (pmd->rfork_len!=0);

	n = dbuf_getu32be_p(pmd->inf, &pos);
	de_mac_time_to_timestamp(n, &pmd->create_time);
	de_timestamp_to_string(&pmd->create_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "create time: %"I64_FMT" (%s)", n, timestamp_buf);
	if(n > 100000000) {
		pmd->advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE] = pmd->create_time;
	}

	n = dbuf_getu32be_p(pmd->inf, &pos);
	de_mac_time_to_timestamp(n, &pmd->mod_time);
	de_timestamp_to_string(&pmd->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %"I64_FMT" (%s)", n, timestamp_buf);
	// TODO: Many files have nonsense timestamps, and there's probably a reason.
	// Maybe they can be decoded.
	if(n > 100000000) {
		pmd->advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = pmd->mod_time;
	}

	hdr_crc_reported = (u32)dbuf_getu16be_p(pmd->inf, &pos);
	de_dbg(c, "header crc (reported): 0x%04x", (UI)hdr_crc_reported);

	de_crcobj_reset(d->crco_hdr);
	de_crcobj_addslice(d->crco_hdr, pmd->inf, pmd->hdr_pos_in_inf, 92);
	hdr_crc_calc = de_crcobj_getval(d->crco_hdr);
	de_dbg(c, "header crc (calculated): 0x%04x", (UI)hdr_crc_calc);
	if(hdr_crc_reported != hdr_crc_calc) {
		// TODO: Maybe should be a warning? Or nonfatal?
		de_err(c, "Bad header CRC (reported 0x%04x, calculated 0x%04x)", (UI)hdr_crc_reported,
			(UI)hdr_crc_calc);
		d->fatalerrflag = 1;
		goto done;
	}

done:
	;
}

// Continues where packit_read_member_header() left off
static void packit_scan_member_data(deark *c, struct packit_ctx *d,
	struct packit_md *pmd)
{
	u32 datarsrc_crc_reported;
	u32 datarsrc_crc_calc;

	if(pmd->rfork_pos + pmd->rfork_len + 2 > pmd->inf->len) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	datarsrc_crc_reported = (u32)dbuf_getu16be(pmd->inf, pmd->rfork_pos +
		pmd->rfork_len);
	de_dbg(c, "data/resource crc (reported): 0x%04x", (UI)datarsrc_crc_reported);

	de_crcobj_reset(d->crco_datarsrc);
	de_crcobj_addslice(d->crco_datarsrc, pmd->inf, pmd->dfork_pos,
		pmd->dfork_len + pmd->rfork_len);
	datarsrc_crc_calc = de_crcobj_getval(d->crco_datarsrc);
	de_dbg(c, "data/resource crc (calculated): 0x%04x", (UI)datarsrc_crc_calc);
	if(datarsrc_crc_reported != datarsrc_crc_calc) {
		// TODO: Maybe should be a warning? Or nonfatal?
		de_err(c, "Bad data/resource CRC (reported 0x%04x, calculated 0x%04x)",
			(UI)datarsrc_crc_reported, (UI)datarsrc_crc_calc);
		d->fatalerrflag = 1;
		goto done;
	}

done:
	;
}

struct packit_advfudata {
	struct packit_ctx *d;
	struct packit_md *pmd;
};

static int packit_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	struct packit_advfudata *u = (struct packit_advfudata*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		dbuf_copy(u->pmd->inf, u->pmd->dfork_pos, u->pmd->dfork_len, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		dbuf_copy(u->pmd->inf, u->pmd->rfork_pos, u->pmd->rfork_len, afp->outf);
	}

	return 1;
}

static void packit_do_huffman_cmpr_member(deark *c, struct packit_ctx *d,
	struct packit_md *pmd)
{
	int saved_indent_level;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg_indent_save(c, &saved_indent_level);
	pmd->unc_data = dbuf_create_membuf(c, 0, 0);

	// This is one of those irritating formats where we know neither the size of
	// the compressed data, nor the size of the decompressed data.
	// And the compression format isn't even self-terminating.
	// We're supposed to decompress until we've reached 94 decompressed
	// bytes (the header). Then decode those bytes to figure out how many more
	// bytes of decompressed data there are, then continue the decompression
	// where we left off.
	// Unfortunately, we don't have a good way to do that, and it's too much
	// trouble to implement one.
	// So we'll decompress just the header, decode it, then start over and
	// decompress everything.

	// Decompress the header
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pmd->marker_pos+4;
	dcmpri.len = c->infile->len - dcmpri.pos;
	dcmpro.f = pmd->unc_data;
	dcmpro.len_known = 1;
	dcmpro.expected_len = 94;

	de_dbg(c, "decompressing (pass 1)");
	de_dbg_indent(c, 1);
	fmtutil_huff_packit_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(dcmpro.f);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		d->fatalerrflag = 1;
		goto done;
	}
	de_dbg_indent(c, -1);

	// Decode the header
	pmd->inf = pmd->unc_data;
	pmd->hdr_pos_in_inf = 0;
	packit_read_member_header(c, d, pmd);
	if(d->fatalerrflag) goto done;

#define PACKIT_MAX_FILE_DATA 50000000
	if(pmd->dfork_len + pmd->rfork_len > PACKIT_MAX_FILE_DATA) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	// Decompress everything
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dbuf_empty(pmd->unc_data);
	dcmpri.f = c->infile;
	dcmpri.pos = pmd->marker_pos+4;
	dcmpri.len = c->infile->len - dcmpri.pos;
	dcmpro.f = pmd->unc_data;
	dcmpro.len_known = 1;
	dcmpro.expected_len = 94 + pmd->dfork_len + pmd->rfork_len + 2;

	de_dbg(c, "decompressing (pass 2)");
	de_dbg_indent(c, 1);
	fmtutil_huff_packit_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(dcmpro.f);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		d->fatalerrflag = 1;
		goto done;
	}
	if(!dres.bytes_consumed_valid) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
		dres.bytes_consumed, pmd->unc_data->len);
	pmd->total_encoded_size = 4 + dres.bytes_consumed;

	de_dbg_indent(c, -1);

	// Validate what we decompressed
	packit_scan_member_data(c, d, pmd);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void packit_do_member(deark *c, struct packit_ctx *d,
	struct packit_md *pmd)
{
	int saved_indent_level;
	i64 pos = pmd->marker_pos+3;
	struct packit_advfudata u;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member file at %"I64_FMT, pmd->marker_pos);
	de_dbg_indent(c, 1);

	pmd->encoding_type = de_getbyte_p(&pos);
	de_dbg(c, "encoding type: 0x%02x", (UI)pmd->encoding_type);

	if(pmd->encoding_type=='g') { // not compressed or encrypted
		pmd->inf = c->infile;
		pmd->hdr_pos_in_inf = pmd->marker_pos+4;
		packit_read_member_header(c, d, pmd);
		if(d->fatalerrflag) goto done;
		pmd->total_encoded_size = 4 + 94 + pmd->dfork_len + pmd->rfork_len + 2;
		packit_scan_member_data(c, d, pmd);
		if(d->fatalerrflag) goto done;
	}
	else if(pmd->encoding_type=='4') {
		pmd->is_compressed = 1;
		packit_do_huffman_cmpr_member(c, d, pmd);
		if(d->fatalerrflag) goto done;
	}
	else {
		de_err(c, "Unsupported encoding type");
		d->fatalerrflag = 1;
		goto done;
	}

	de_zeromem(&u, sizeof(struct packit_advfudata));
	u.d = d;
	u.pmd = pmd;
	pmd->advf->userdata = (void*)&u;
	ucstring_append_ucstring(pmd->advf->filename, pmd->fname->str);
	pmd->advf->original_filename_flag = 1;
	de_advfile_set_orig_filename(pmd->advf, pmd->fname->sz, pmd->fname->sz_strlen);
	pmd->advf->writefork_cbfn = packit_advfile_cbfn;
	de_advfile_run(pmd->advf);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_packit(deark *c, de_module_params *mparams)
{
	struct packit_ctx *d = NULL;
	struct packit_md *pmd = NULL;
	i64 pos = 0;
	u32 code;

	d = de_malloc(c, sizeof(struct packit_ctx));
	d->crco_datarsrc = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);
	d->crco_hdr = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);

	while(1) {
		code = (u32)de_getu32be(pos);
		if(code==CODE_PEnd) {
			de_dbg(c, "EOF marker at %"I64_FMT, pos);
			goto done;
		}
		if(code>>8 != CODE_PMa) {
			de_err(c, "Expected marker not found at %"I64_FMT, pos);
			goto done;
		}

		if(pmd) {
			packit_destroy_pmd(c, pmd);
			pmd = NULL;
		}

		pmd = de_malloc(c, sizeof(struct packit_md));
		pmd->advf = de_advfile_create(c);

		pmd->marker_pos = pos;
		packit_do_member(c, d, pmd);
		if(d->fatalerrflag) goto done;
		if(pmd->total_encoded_size<1) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		pos += pmd->total_encoded_size;
	}

done:
	if(pmd) {
		packit_destroy_pmd(c, pmd);
	}
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Failed to decode PackIt file");
		}
		de_crcobj_destroy(d->crco_datarsrc);
		de_crcobj_destroy(d->crco_hdr);
	}
}

static int de_identify_packit(deark *c)
{
	u8 t;

	if(dbuf_memcmp(c->infile, 0, (const void*)"PMa", 3)) {
		return 0;
	}
	t = de_getbyte(3);
	if(t=='g' || t=='4') return 100;
	if(t>='1' && t<='7') return 35;
	return 0;
}

void de_module_packit(deark *c, struct deark_module_info *mi)
{
	mi->id = "packit";
	mi->desc = "PackIt";
	mi->run_fn = de_run_packit;
	mi->identify_fn = de_identify_packit;
}
