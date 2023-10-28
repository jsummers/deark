// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// NuFX / ShrinkIt (Apple II format)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_nufx);

#define MAX_THREADS_PER_RECORD 16
#define INVALID_THREAD_IDX 0xffffffffU
#define VALID_THREAD_IDX(rec, n) ((n) < (rec)->num_threads)

struct nufx_ctx;

struct nufx_thread {
	UI idx;
	UI thread_class;
	UI cmpr_meth;
	UI kind;
	u32 crc_reported;
	i64 orig_len;
	i64 cmpr_len;
	i64 cmpr_pos;
};

struct nufx_record {
	struct nufx_ctx *d;
	UI idx;
	UI version;
	i64 hdr_pos;
	i64 hdr_len; // including thread hdrs, excluding data
	i64 attrib_count;
	u32 header_crc;
	UI num_threads;
	UI filesys_id;
	UI filesys_info;
	UI access_code;
	u32 file_type;
	u32 extra_type;
	UI storage_type;
	i64 option_size;
	i64 cur_data_pos;
	struct de_timestamp create_time;
	struct de_timestamp mod_time;
	struct de_timestamp archived_time;
	de_ucstring *filename;
	struct nufx_thread *threads; // array[rec->num_threads]
	struct nufx_thread *filename_thread_ptr; // pointer to somewhere in ->threads, or NULL
	struct nufx_thread *data_thread_ptr; // ...
	struct nufx_thread *resource_thread_ptr; // ...
	struct nufx_thread *disk_image_thread_ptr; // ...
};

struct nufx_ctx {
	u8 fatalerrflag;
	u8 need_errmsg;
	u8 extract_comments;
	de_encoding input_encoding;
	UI master_ver;
	u32 master_crc_reported;
	i64 total_records;
	i64 master_eof;
	i64 next_record_pos;
	struct de_timestamp archive_create_time;
	struct de_timestamp archive_mod_time;
	struct de_crcobj *crco_misc;
	struct de_crcobj *crco_for_lzw_codec;
	struct de_crcobj *crco_rfork;
	struct de_crcobj *crco_dfork;
};

static const char *get_cmpr_meth_name(UI n)
{
	const char *name = NULL;

	switch(n) {
	case 0: name="uncompressed"; break;
	case 1: name="Squeeze"; break;
	case 2: name="ShrinkIt LZW/1"; break;
	case 3: name="ShrinkIt LZW/2"; break;
	case 4: name="Unix compress 12-bit"; break;
	case 5: name="Unix compress 16-bit"; break;
	}
	return name?name:"?";
}

static int cmpr_meth_is_supported(UI meth)
{
	if(meth==0 || meth==2) return 1;
	return 0;
}

static const char *get_thread_type_name(UI cla, UI kind)
{
	if(cla==0) { // "message"
		if(kind==0) return "text (obsolete)";
		if(kind==1) return "comment"; // (?)
		if(kind==2) return "icon";
	}
	if(cla==1) { // "control"
		if(kind==0) return "directory";
		return "unknown 'control' thread";
	}
	if(cla==2) { // "data"
		if(kind==0) return "data fork";
		if(kind==1) return "disk image";
		if(kind==2) return "resource fork";
		return "unknown 'data' thread";
	}
	if(cla==3) { // "filename"
		if(kind==0) return "filename";
	}
	return "?";
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void nufx_read_datetime_to_timestamp_p(dbuf *f, i64 *ppos,
	struct de_timestamp *ts)
{
	i64 yr, mo, da, hr, mi, se;
	i64 pos;

	pos = *ppos;
	*ppos += 8;

	se = (i64)dbuf_getbyte_p(f, &pos);
	mi = (i64)dbuf_getbyte_p(f, &pos);
	hr = (i64)dbuf_getbyte_p(f, &pos);
	yr = 1900 + (i64)dbuf_getbyte_p(f, &pos);
	da = 1 + (i64)dbuf_getbyte_p(f, &pos);
	mo = 1 + (i64)dbuf_getbyte_p(f, &pos);

	if(yr==1900) {
		de_zeromem(ts, sizeof(struct de_timestamp));
		ts->is_valid = 0;
		return;
	}
	de_make_timestamp(ts, yr, mo, da, hr, mi, se);
	ts->precision = DE_TSPREC_1SEC;
}

static void do_nufx_master_record(deark *c, struct nufx_ctx *d)
{
	i64 pos1, pos;
	u32 master_crc_calc;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = 0;
	de_dbg(c, "master record at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1 + 6;

	d->master_crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "master crc (reported): 0x%04x", (UI)d->master_crc_reported);

	de_crcobj_reset(d->crco_misc);
	de_crcobj_addslice(d->crco_misc, c->infile, pos, 40);
	master_crc_calc = de_crcobj_getval(d->crco_misc);
	de_dbg(c, "master crc (calculated): 0x%04x", (UI)master_crc_calc);

	d->total_records = de_getu32le_p(&pos);
	de_dbg(c, "total records: %"I64_FMT, d->total_records);

	nufx_read_datetime_to_timestamp_p(c->infile, &pos, &d->archive_create_time);
	dbg_timestamp(c, &d->archive_create_time, "archive create time");
	nufx_read_datetime_to_timestamp_p(c->infile, &pos, &d->archive_mod_time);
	dbg_timestamp(c, &d->archive_mod_time, "archive mod time");

	d->master_ver = (UI)de_getu16le_p(&pos);
	de_dbg(c, "fmt ver: %u", d->master_ver);
	pos += 8; // reserved

	d->master_eof = de_getu32le_p(&pos);
	de_dbg(c, "master eof: %"I64_FMT, d->master_eof);
	pos += 6; // reserved, I guess

	d->next_record_pos = pos;

	if(d->master_eof > c->infile->len) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Updates rec->cur_data_pos
static void read_thread_header(deark *c,
	struct nufx_ctx *d, struct nufx_record *rec,
	struct nufx_thread *t,
	i64 pos1)
{
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "thread #%u header at %"I64_FMT, t->idx, pos1);
	de_dbg_indent(c, 1);

	t->thread_class = (UI)de_getu16le_p(&pos);
	de_dbg(c, "thread class: 0x%04x", t->thread_class);
	t->cmpr_meth = (UI)de_getu16le_p(&pos);
	de_dbg(c, "cmpr meth: 0x%04x (%s)", t->cmpr_meth,
		get_cmpr_meth_name(t->cmpr_meth));
	t->kind = (UI)de_getu16le_p(&pos);
	de_dbg(c, "thread kind: 0x%04x", t->kind);

	de_dbg(c, "interpreted type: %s",
		get_thread_type_name(t->thread_class, t->kind));

	// If record_version==3, this crc should be present.
	// If record_version==2, the spec. is confusing.
	// If record_version==1, no crc is present here. (I guess this field is 0?)
	t->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "thread crc (reported): 0x%04x%s", (UI)t->crc_reported,
		((rec->version<2)?" [unused]":""));

	t->orig_len = de_getu32le_p(&pos);
	de_dbg(c, "orig len: %"I64_FMT, t->orig_len);
	t->cmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "cmpr len: %"I64_FMT, t->cmpr_len);

	t->cmpr_pos = rec->cur_data_pos;
	de_dbg(c, "cmpr data pos: %"I64_FMT, t->cmpr_pos);

	rec->cur_data_pos += t->cmpr_len;

	if(rec->cur_data_pos > d->master_eof) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	// Track the threads we care about.
	if(t->thread_class==3 && t->kind==0) {
		rec->filename_thread_ptr = t;
	}
	else if(t->thread_class==2 && t->kind==0) {
		rec->data_thread_ptr = t;
	}
	else if(t->thread_class==2 && t->kind==2) {
		rec->resource_thread_ptr = t;
	}
	else if(t->thread_class==2 && t->kind==1) {
		rec->disk_image_thread_ptr = t;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Read the record header, except for the thread headers
static void do_nufx_record_header(deark *c,
	struct nufx_ctx *d, struct nufx_record *rec)
{
	i64 pos;
	i64 pos_after_fnlen_field;
	i64 attributes_size_in_bytes;
	i64 fnlen;
	u32 rh_crc_calc;
	UI tidx;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "record header at %"I64_FMT, rec->hdr_pos);
	de_dbg_indent(c, 1);

	pos = rec->hdr_pos+4;
	rec->header_crc = (u32)de_getu16le_p(&pos);
	de_dbg(c, "record header crc (reported): 0x%04x", (UI)rec->header_crc);

	rec->attrib_count = de_getu16le_p(&pos);
	de_dbg(c, "attrib count: %"I64_FMT, rec->attrib_count);
	pos_after_fnlen_field = rec->hdr_pos+ rec->attrib_count;

	rec->version = (UI)de_getu16le_p(&pos);
	de_dbg(c, "record version: %u", (UI)rec->version);

	rec->num_threads = (UI)de_getu32le_p(&pos);
	de_dbg(c, "total threads: %u", rec->num_threads);
	if(rec->num_threads > MAX_THREADS_PER_RECORD) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	rec->filesys_id = (UI)de_getu16le_p(&pos);
	de_dbg(c, "filesys id: 0x%04x", rec->filesys_id);

	rec->filesys_info = (UI)de_getu16le_p(&pos);
	de_dbg(c, "filesys info: 0x%04x", rec->filesys_info);

	rec->access_code = (UI)de_getu32le_p(&pos);
	de_dbg(c, "access: 0x%08x", rec->access_code);

	rec->file_type = (u32)de_getu32le_p(&pos);
	de_dbg(c, "file type: 0x%08x", (UI)rec->file_type);
	rec->extra_type = (u32)de_getu32le_p(&pos);
	de_dbg(c, "extra type: 0x%08x", (UI)rec->extra_type);

	rec->storage_type = (UI)de_getu16le_p(&pos);
	de_dbg(c, "storage type: 0x%04x", rec->storage_type);

	nufx_read_datetime_to_timestamp_p(c->infile, &pos, &rec->create_time);
	dbg_timestamp(c, &rec->create_time, "create time");
	nufx_read_datetime_to_timestamp_p(c->infile, &pos, &rec->mod_time);
	dbg_timestamp(c, &rec->mod_time, "mod time");
	nufx_read_datetime_to_timestamp_p(c->infile, &pos, &rec->archived_time);
	dbg_timestamp(c, &rec->archived_time, "archived time");

	rec->option_size = de_getu16le_p(&pos);
	de_dbg(c, "option size: %"I64_FMT, rec->option_size);
	pos += de_pad_to_2(rec->option_size);

	attributes_size_in_bytes = pos_after_fnlen_field - 2 - pos;
	de_dbg(c, "attributes segment at %"I64_FMT", len=%"I64_FMT, pos,
		attributes_size_in_bytes);

	pos += attributes_size_in_bytes;
	// TODO: Support this (assuming old-format files exist)
	fnlen = de_getu16le_p(&pos);
	de_dbg(c, "filename len (obsolete): %"I64_FMT, fnlen);
	pos += fnlen;

	rec->hdr_len = (pos + 16*rec->num_threads) - rec->hdr_pos;

	de_crcobj_reset(d->crco_misc);
	de_crcobj_addslice(d->crco_misc, c->infile, rec->hdr_pos+6,
		rec->hdr_len-6);
	rh_crc_calc = de_crcobj_getval(d->crco_misc);
	de_dbg(c, "record header crc (calculated): 0x%04x", (UI)rh_crc_calc);

	rec->threads = de_mallocarray(c, rec->num_threads, sizeof(struct nufx_thread));

	rec->cur_data_pos = rec->hdr_pos + rec->hdr_len;

	for(tidx=0; tidx<rec->num_threads; tidx++) {
		struct nufx_thread *t;

		t = &rec->threads[tidx];
		t->idx = tidx;
		read_thread_header(c, d, rec, t, pos);
		if(d->fatalerrflag) goto done;
		pos += 16;
	}

	d->next_record_pos = rec->cur_data_pos;

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void decompress_chunk_rle_layer(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, u8 rlechar)
{
	i64 srcpos = dcmpri->pos;
	i64 endpos;
	i64 nbytes_written = 0;
	const char *modname = "rle";

	endpos = dcmpri->pos + dcmpri->len;
	while(srcpos < endpos) {
		u8 x;

		if(nbytes_written >= dcmpro->expected_len) break;
		x = dbuf_getbyte_p(dcmpri->f, &srcpos);
		if(x==rlechar) {
			i64 count;
			u8 val;

			val = dbuf_getbyte_p(dcmpri->f, &srcpos);
			count = 1 + (i64)dbuf_getbyte_p(dcmpri->f, &srcpos);
			if(nbytes_written+count > dcmpro->expected_len) {
				goto done;
			}
			dbuf_write_run(dcmpro->f, val, count);
			nbytes_written += count;
		}
		else {
			dbuf_writebyte(dcmpro->f, x);
			nbytes_written++;
		}
	}

done:
	if(nbytes_written != dcmpro->expected_len) {
		de_dfilter_set_generic_error(c, dres, modname);
	}
	dres->bytes_consumed = srcpos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

static void decompress_chunk_lzw1_lzw_layer(deark *c,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_SHRINKIT1;
	delzwp.max_code_size = 12;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompress_lzw_1(deark *c, struct nufx_ctx *d,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	u32 lzwcrc_reported;
	u32 lzwcrc_calc;
	i64 pos = dcmpri->pos;
	i64 nbytes_to_copy;
	u8 volnum;
	u8 rlechar;
	i64 output_bytes_remaining;
	dbuf *tmpdbuf_lzw = NULL;
	dbuf *tmpdbuf_rle = NULL;
	struct de_dfilter_in_params *dcmpri_lzw = NULL;
	struct de_dfilter_out_params *dcmpro_lzw = NULL;
	struct de_dfilter_results *dres_lzw = NULL;
	struct de_dfilter_in_params *dcmpri_rle = NULL;
	struct de_dfilter_out_params *dcmpro_rle = NULL;
	struct de_dfilter_results *dres_rle = NULL;
	const char *modname = "nufx_lzw1";

	output_bytes_remaining = dcmpro->expected_len;
	tmpdbuf_lzw = dbuf_create_membuf(c, 4096, 0);
	tmpdbuf_rle = dbuf_create_membuf(c, 4096, 0);
	dcmpri_lzw = de_malloc(c, sizeof(struct de_dfilter_in_params));
	dcmpro_lzw = de_malloc(c, sizeof(struct de_dfilter_out_params));
	dres_lzw = de_malloc(c, sizeof(struct de_dfilter_results));
	dcmpri_rle = de_malloc(c, sizeof(struct de_dfilter_in_params));
	dcmpro_rle = de_malloc(c, sizeof(struct de_dfilter_out_params));
	dres_rle = de_malloc(c, sizeof(struct de_dfilter_results));

	// The compressed data is chunked. There's an initial 4-byte header, then each
	// chunk has a 3-byte header.
	// Every chunk should decompress to exactly 4096 bytes. (The last chunk is padded,
	// and the padding is included in the internal CRC computation).
	// A chunk may use LZW, RLE, both, or neither.
	// We can tell which methods are used, as well as the intermediate-decompressed size,
	// from the chunk header.
	// We need to do LZW decompression first (if applicable), then RLE decompression (if
	// applicable).
	// There's no easy way to figure out the size of a chunk of compressed data.
	// We can only do it after we do the LZW decompression, and see how much source data
	// was consumed (rounding up to the next whole byte) in order to produce the
	// intermediate number of bytes.
	// Our LZW decompressor tells us this info (though we'd rather not have to rely on it).

	lzwcrc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "lzwcodec crc (reported): 0x%04x", (UI)lzwcrc_reported);
	volnum = dbuf_getbyte_p(dcmpri->f, &pos);
	de_dbg(c, "lzwcodec vol num: %u", (UI)volnum);
	rlechar = dbuf_getbyte_p(dcmpri->f, &pos);
	de_dbg(c, "lzwcodec rle char: 0x%02x", (UI)rlechar);

	de_crcobj_reset(d->crco_for_lzw_codec);

	while(1) {
		i64 chkpos;
		i64 intermed_chunk_len; // size we expect after RLE decompression, before LZW decompression
		u8 uses_rle;
		u8 uses_lzw;

		if(output_bytes_remaining<1) break;
		if(pos+3 > dcmpri->pos + dcmpri->len) break;
		chkpos = pos;
		intermed_chunk_len = dbuf_getu16le_p(dcmpri->f, &pos); // if 4096, no RLE
		uses_rle = (intermed_chunk_len != 4096);
		uses_lzw = dbuf_getbyte_p(dcmpri->f, &pos); // if 0, no LZW
		de_dbg(c, "chunk at %"I64_FMT", intermed_len=%"I64_FMT", rle=%u, lzw=%u",
			chkpos, intermed_chunk_len, (UI)uses_lzw, (UI)uses_rle);

		dbuf_empty(tmpdbuf_lzw);
		if(uses_lzw) {
			de_dfilter_init_objects(c, dcmpri_lzw, dcmpro_lzw, dres_lzw);
			dcmpri_lzw->f = dcmpri->f;
			dcmpri_lzw->pos = pos;
			// ->len is just a maximum. We don't know the compressed data size yet.
			dcmpri_lzw->len = dcmpri->len + dcmpri->pos - pos;
			dcmpro_lzw->f = tmpdbuf_lzw;
			dcmpro_lzw->len_known = 1;
			dcmpro_lzw->expected_len = intermed_chunk_len;
			decompress_chunk_lzw1_lzw_layer(c, dcmpri_lzw, dcmpro_lzw, dres_lzw);
			if(dres_lzw->errcode) {
				de_dfilter_transfer_error2(c, dres_lzw, dres, modname);
				goto done;
			}
			if(!dres_lzw->bytes_consumed_valid) {
				de_dfilter_set_generic_error(c, dres, modname);
				goto done;
			}
			pos += dres_lzw->bytes_consumed;
		}
		else {
			dbuf_copy(dcmpri->f, pos, intermed_chunk_len, tmpdbuf_lzw);
			pos += intermed_chunk_len;
		}

		dbuf_empty(tmpdbuf_rle);
		if(uses_rle) {
			de_dfilter_init_objects(c, dcmpri_rle, dcmpro_rle, dres_rle);
			dcmpri_rle->f = tmpdbuf_lzw;
			dcmpri_rle->pos = 0;
			dcmpri_rle->len = tmpdbuf_lzw->len;
			dcmpro_rle->f = tmpdbuf_rle;
			dcmpro_rle->len_known = 1;
			dcmpro_rle->expected_len = 4096;
			decompress_chunk_rle_layer(c, dcmpri_rle, dcmpro_rle, dres_rle, rlechar);
			if(dres_rle->errcode) {
				de_dfilter_transfer_error2(c, dres_rle, dres, modname);
				goto done;
			}
		}
		else {
			dbuf_copy(tmpdbuf_lzw, 0, 4096, tmpdbuf_rle);
		}

		de_crcobj_addslice(d->crco_for_lzw_codec, tmpdbuf_rle, 0, 4096);

		nbytes_to_copy = de_min_int(output_bytes_remaining, 4096);
		dbuf_copy(tmpdbuf_rle, 0, nbytes_to_copy, dcmpro->f);
		output_bytes_remaining -= nbytes_to_copy;
	}

	lzwcrc_calc = de_crcobj_getval(d->crco_for_lzw_codec);
	de_dbg(c, "lzwcodec crc (calculated): 0x%04x", (UI)lzwcrc_calc);
	if(lzwcrc_calc != lzwcrc_reported) {
		de_dfilter_set_errorf(c, dres, modname, "Codec internal CRC check failed");
		goto done;
	}

done:
	dbuf_close(tmpdbuf_lzw);
	de_free(c, dcmpri_lzw);
	de_free(c, dcmpro_lzw);
	de_free(c, dres_lzw);
	de_free(c, dcmpri_rle);
	de_free(c, dcmpro_rle);
	de_free(c, dres_rle);
}

static int decompress_thread(deark *c,
	struct nufx_ctx *d, struct nufx_record *rec,
	struct nufx_thread *t, dbuf *outf)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg(c, "[reading thread #%u]", t->idx);
	de_dbg_indent(c, 1);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	if(!t) goto done;
	if(t->cmpr_pos + t->cmpr_len > c->infile->len) goto done;

	dcmpri.f = c->infile;
	dcmpri.pos = t->cmpr_pos;
	dcmpri.len = t->cmpr_len;
	dcmpro.f = outf;
	dcmpro.expected_len = t->orig_len;
	dcmpro.len_known = 1;

	if(t->cmpr_meth==0 || t->orig_len==0) {
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
	}
	else if(t->cmpr_meth==2) {
		decompress_lzw_1(c, d, &dcmpri, &dcmpro, &dres);
	}
	else {
		de_dfilter_set_errorf(c, &dres, NULL, "Unsupported compression method");
	}

	if(dres.errcode) {
		de_err(c, "Decompression failed for record#%u thread#%u: %s",
			rec->idx, t->idx, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	retval = 1;
	goto done;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	struct nufx_record *rec = (struct nufx_record*)advf->userdata;
	struct nufx_ctx *d = rec->d;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		decompress_thread(c, d, rec, rec->data_thread_ptr, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		decompress_thread(c, d, rec, rec->resource_thread_ptr, afp->outf);
	}

	return 1;
}

static void extract_data_and_rsrc_forks(deark *c, struct nufx_ctx *d,
	struct nufx_record *rec)
{
	struct de_advfile *advf = NULL;
	struct nufx_thread *t_d;
	struct nufx_thread *t_r;
	u32 d_crc_calc, r_crc_calc;
	u8 ok_cmpr;

	t_d = rec->data_thread_ptr;
	t_r = rec->resource_thread_ptr;

	if(!t_d && !t_r) {
		de_warn(c, "Skipping record: No data or resource fork");
		goto done;
	}

	ok_cmpr = 1;
	if(t_d) {
		if(t_d->orig_len>0 && !cmpr_meth_is_supported(t_d->cmpr_meth)) {
			ok_cmpr = 0;
		}
	}
	if(t_r) {
		if(t_r->orig_len>0 && !cmpr_meth_is_supported(t_r->cmpr_meth)) {
			ok_cmpr = 0;
		}
	}
	// Continue only if we're pretty sure we can decompress both forks.
	if(!ok_cmpr) {
		de_err(c, "record #%u: Compression method not supported", rec->idx);
		goto done;
	}

	advf = de_advfile_create(c);
	advf->userdata = (void*)rec;
	advf->writefork_cbfn = my_advfile_cbfn;
	advf->enable_wbuffer = 1;

	advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = rec->mod_time;
	advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE] = rec->create_time;

	ucstring_append_ucstring(advf->filename, rec->filename);
	advf->original_filename_flag = 1;
	//de_advfile_set_orig_filename(rec->advf, ...); // TODO?

	if(t_d) {
		advf->mainfork.fork_exists = 1;
		advf->mainfork.fork_len = t_d->orig_len;
		advf->mainfork.writelistener_cb = de_writelistener_for_crc;
		advf->mainfork.userdata_for_writelistener = (void*)d->crco_dfork;
		de_crcobj_reset(d->crco_dfork);
		de_crcobj_setval(d->crco_dfork, 0xffff);
	}
	if(t_r) {
		advf->rsrcfork.fork_exists = 1;
		advf->rsrcfork.fork_len = t_r->orig_len;
		advf->rsrcfork.writelistener_cb = de_writelistener_for_crc;
		advf->rsrcfork.userdata_for_writelistener = (void*)d->crco_rfork;
		de_crcobj_reset(d->crco_rfork);
		de_crcobj_setval(d->crco_rfork, 0xffff);
	}

	de_advfile_run(advf);

	if(t_d) {
		d_crc_calc = de_crcobj_getval(d->crco_dfork);
		de_dbg(c, "data fork crc (calculated): 0x%04x", (UI)d_crc_calc);
		if(d_crc_calc!=t_d->crc_reported && rec->version>=2 && t_d->crc_reported!=0) {
			de_err(c, "CRC check failed for record #%u data fork", rec->idx);
		}
	}
	if(t_r) {
		r_crc_calc = de_crcobj_getval(d->crco_rfork);
		de_dbg(c, "rsrc fork crc (calculated): 0x%04x", (UI)r_crc_calc);
		if(r_crc_calc!=t_r->crc_reported && rec->version>=2 && t_r->crc_reported!=0) {
			de_err(c, "CRC check failed for record #%u resource fork", rec->idx);
		}
	}

done:
	de_advfile_destroy(advf);
}

static void do_extract_aux_thread(deark *c, struct nufx_ctx *d,
	struct nufx_record *rec, struct nufx_thread *t, const char *name)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;

	fi = de_finfo_create(c);
	// TODO: Better file naming
	de_finfo_set_name_from_sz(c, fi, name, 0, DE_ENCODING_UTF8);
	outf = dbuf_create_output_file(c, NULL, fi, DE_CREATEFLAG_IS_AUX);
	decompress_thread(c, d, rec, t, outf);
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static void do_dbg_comment(deark *c, struct nufx_ctx *d,
	struct nufx_record *rec, struct nufx_thread *t)
{
	dbuf *tmpdbuf = NULL;
	de_ucstring *s = NULL;

	tmpdbuf = dbuf_create_membuf(c, DE_DBG_MAX_STRLEN, 0x1);
	if(!decompress_thread(c, d, rec, t, tmpdbuf)) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(tmpdbuf, 0, tmpdbuf->len, DE_DBG_MAX_STRLEN,
		s, 0, d->input_encoding);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));

done:
	dbuf_close(tmpdbuf);
	ucstring_destroy(s);
}

static void extract_from_record(deark *c,
	struct nufx_ctx *d, struct nufx_record *rec)
{
	dbuf *filename_dbuf = NULL;
	UI tidx;
	int ret;

	filename_dbuf = dbuf_create_membuf(c, 0, 0);
	if(rec->filename_thread_ptr) {
		ret = decompress_thread(c, d, rec, rec->filename_thread_ptr,
			filename_dbuf);
		if(!ret || filename_dbuf->len<1) {
			goto done;
		}
		dbuf_read_to_ucstring_n(filename_dbuf, 0, filename_dbuf->len, 255,
			rec->filename, 0, d->input_encoding);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(rec->filename));
	}

	if(rec->disk_image_thread_ptr) {
		de_err(c, "Disk images are not supported");
		goto done;
	}

	de_dbg(c, "[extracting files]");
	de_dbg_indent(c, 1);
	extract_data_and_rsrc_forks(c, d, rec);

	// Handle ancillary threads, such as comments.
	for(tidx=0; tidx<rec->num_threads; tidx++) {
		struct nufx_thread *t;

		t = &rec->threads[tidx];
		if(t->orig_len>0 && t->thread_class==0 && t->kind==1) {
			if(d->extract_comments) {
				do_extract_aux_thread(c, d, rec, t, "comment");
			}
			else {
				do_dbg_comment(c, d, rec, t);
			}
		}
	}

	de_dbg_indent(c, -1);

done:
	dbuf_close(filename_dbuf);
}

static void do_nufx_record(deark *c,
	struct nufx_ctx *d, struct nufx_record *rec)
{
	int saved_indent_level;
	UI id;

	de_dbg_indent_save(c, &saved_indent_level);

	id = (UI)de_getu32be(rec->hdr_pos);
	if(id != 0x4ef546d8) {
		de_err(c, "Expected record not found at %"I64_FMT, rec->hdr_pos);
		d->fatalerrflag = 1;
		goto done;
	}

	de_dbg(c, "record #%u at %"I64_FMT, rec->idx, rec->hdr_pos);
	de_dbg_indent(c, 1);

	do_nufx_record_header(c, d, rec);
	if(d->fatalerrflag) goto done;

	extract_from_record(c, d, rec);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void destroy_record(deark *c, struct nufx_record *rec)
{
	if(!rec) return;
	ucstring_destroy(rec->filename);
	de_free(c, rec->threads);
	de_free(c, rec);
}

static void de_run_nufx(deark *c, de_module_params *mparams)
{
	struct nufx_ctx *d = NULL;
	struct nufx_record *rec = NULL;
	i64 pos;
	UI rec_idx = 0;

	d = de_malloc(c, sizeof(struct nufx_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	d->extract_comments = (c->extract_level>=2);
	d->crco_misc = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);
	d->crco_for_lzw_codec = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);
	d->crco_dfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);
	d->crco_rfork = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);

	do_nufx_master_record(c, d);
	if(d->fatalerrflag) goto done;
	pos = d->next_record_pos;

	while(1) {
		if(pos >= d->master_eof) break;

		if(rec) {
			destroy_record(c, rec);
			rec = NULL;
		}

		rec = de_malloc(c, sizeof(struct nufx_record));
		rec->d = d;
		rec->idx = rec_idx;
		rec->filename = ucstring_create(c);
		rec->hdr_pos = pos;
		do_nufx_record(c, d, rec);
		if(d->fatalerrflag) goto done;

		pos = d->next_record_pos;
		rec_idx++;
	}

done:
	destroy_record(c, rec);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported NuFX file");
		}
		de_crcobj_destroy(d->crco_misc);
		de_crcobj_destroy(d->crco_for_lzw_codec);
		de_crcobj_destroy(d->crco_dfork);
		de_crcobj_destroy(d->crco_rfork);
		de_free(c, d);
	}
}

static int de_identify_nufx(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"\x4e\xf5\x46\xe9\x6c\xe5", 6)) {
		return 0;
	}
	return 100;
}

void de_module_nufx(deark *c, struct deark_module_info *mi)
{
	mi->id = "nufx";
	mi->desc = "NuFX / ShrinkIt";
	mi->run_fn = de_run_nufx;
	mi->identify_fn = de_identify_nufx;
	mi->flags |= DE_MODFLAG_WARNPARSEONLY;
}
