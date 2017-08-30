// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm Database (PDB)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_palmdb);

#define CODE_appl 0x6170706cU
#define CODE_clpr 0x636c7072U
#define CODE_pqa  0x70716120U

struct rec_data_struct {
	de_uint32 offset;
};

typedef struct localctx_struct {
#define FMT_PDB 0
#define FMT_PQA 1
#define FMT_PRC 2
	int file_fmt;
	const char *fmt_shortname;
	de_int64 num_recs;
	de_int64 rec_size; // bytes per record
	struct de_fourcc dtype4cc;
	struct de_fourcc creator4cc;
	de_int64 appinfo_offs;
	de_int64 sortinfo_offs;
	struct rec_data_struct *rec_data;
} lctx;

static void handle_palm_timestamp(deark *c, lctx *d, de_int64 pos, const char *name)
{
	struct de_timestamp ts;
	char timestamp_buf[64];
	de_int64 ts_int;

	ts_int = de_getui32be(pos);
	if(ts_int==0) {
		de_dbg(c, "%s: 0 (not set)\n", name);
		return;
	}

	de_dbg(c, "%s: ...\n", name);
	de_dbg_indent(c, 1);

	// I've seen three different ways to interpret this 32-bit timestamp, and
	// I don't know how to guess the correct one.

	de_unix_time_to_timestamp(ts_int - 2082844800, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "... if Mac-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);

	ts_int = de_getui32le(pos);
	if(ts_int>2082844800) { // Assume dates before 1970 are wrong
		de_unix_time_to_timestamp(ts_int - 2082844800, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Mac-LE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	ts_int = dbuf_geti32be(c->infile, pos);
	if(ts_int>0) {
		de_unix_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0x1);
		de_dbg(c, "... if Unix-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	de_dbg_indent(c, -1);
}

static int do_read_header(deark *c, lctx *d)
{
	de_int64 pos1 = 0;
	de_ucstring *dname = NULL;
	de_uint32 attribs;
	de_uint32 version;
	de_int64 x;

	de_dbg(c, "header at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	dname = ucstring_create(c);
	// TODO: What exactly is the encoding?
	dbuf_read_to_ucstring(c->infile, pos1, 32, dname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(dname));

	attribs = (de_uint32)de_getui16be(pos1+32);
	de_dbg(c, "attributes: 0x%04x\n", (unsigned int)attribs);

	version = (de_uint32)de_getui16be(pos1+34);
	de_dbg(c, "version: 0x%04x\n", (unsigned int)version);

	handle_palm_timestamp(c, d, pos1+36, "create date");
	handle_palm_timestamp(c, d, pos1+40, "mod date");
	handle_palm_timestamp(c, d, pos1+44, "backup date");

	x = de_getui32be(pos1+48);
	de_dbg(c, "mod number: %d\n", (int)x);
	d->appinfo_offs = de_getui32be(pos1+52);
	de_dbg(c, "app info pos: %d\n", (int)d->appinfo_offs);
	d->sortinfo_offs = de_getui32be(pos1+56);
	de_dbg(c, "sort info pos: %d\n", (int)d->sortinfo_offs);

	dbuf_read_fourcc(c->infile, pos1+60, &d->dtype4cc, 0);
	de_dbg(c, "type: \"%s\"\n", d->dtype4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos1+64, &d->creator4cc, 0);
	de_dbg(c, "creator: \"%s\"\n", d->creator4cc.id_printable);

	if(d->dtype4cc.id==CODE_appl) {
		d->file_fmt = FMT_PRC;
		d->fmt_shortname = "PRC";
		de_declare_fmt(c, "Palm PRC");
	}
	else if(d->dtype4cc.id==CODE_pqa && d->creator4cc.id==CODE_clpr) {
		d->file_fmt = FMT_PQA;
		d->fmt_shortname = "PQA";
		de_declare_fmt(c, "Palm PQA");
	}
	else {
		d->file_fmt = FMT_PDB;
		d->fmt_shortname = "PDB";
		de_declare_fmt(c, "Palm PDB");
	}

	x = de_getui32be(68);
	de_dbg(c, "uniqueIDseed: %d\n", (int)x);
	x = de_getui32be(72);
	de_dbg(c, "nextRecordListID: %d\n", (int)x);
	d->num_recs = de_getui16be(76);
	de_dbg(c, "number of records: %d\n", (int)d->num_recs);

	de_dbg_indent(c, -1);
	ucstring_destroy(dname);
	return 1;
}

static de_int64 calc_rec_len(deark *c, lctx *d, de_int64 rec_idx)
{
	de_int64 len;
	if(rec_idx+1 < d->num_recs) {
		len = (de_int64)(d->rec_data[rec_idx+1].offset - d->rec_data[rec_idx].offset);
	}
	else {
		len = c->infile->len - (de_int64)d->rec_data[rec_idx].offset;
	}
	return len;
}

static void extract_item(deark *c, lctx *d, de_int64 data_offs, de_int64 data_len,
	const char *ext, unsigned int createflags)
{
	de_finfo *fi = NULL;

	if(c->extract_level<2) goto done;
	if(data_offs<0 || data_len<0) goto done;
	if(data_offs+data_len > c->infile->len) goto done;
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, ext, DE_ENCODING_ASCII);
	dbuf_create_file_from_slice(c->infile, data_offs, data_len, NULL, fi, createflags);
done:
	de_finfo_destroy(c, fi);
}

// For PDB or PQA format
static int do_read_pdb_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_int64 data_offs;
	de_byte attribs;
	de_uint32 id;
	de_int64 data_len;

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	data_offs = (int)d->rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);

	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	if(d->file_fmt==FMT_PDB) {
		attribs = de_getbyte(pos1+4);
		de_dbg(c, "attributes: 0x%02x\n", (unsigned int)attribs);

		id = (de_getbyte(pos1+5)<<16) |
			(de_getbyte(pos1+6)<<8) |
			(de_getbyte(pos1+7));
		de_dbg(c, "id: %d\n", (int)id);
	}

	extract_item(c, d, data_offs, data_len, "bin", 0);

	de_dbg_indent(c, -1);
	return 1;
}

static int do_read_prc_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_uint32 id;
	struct de_fourcc name4cc;
	de_int64 data_offs;
	de_int64 data_len;
	char ext[80];

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos1, &name4cc, 0);
	de_dbg(c, "name: \"%s\"\n", name4cc.id_printable);

	id = (de_uint32)de_getui16be(pos1+4);
	de_dbg(c, "id: %d\n", (int)id);

	data_offs = (de_int64)d->rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);
	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	de_snprintf(ext, sizeof(ext), "%s.bin", name4cc.id_printable);
	extract_item(c, d, data_offs, data_len, ext, 0);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	de_dbg(c, "%s records section at %d\n", d->fmt_shortname, (int)pos1);
	de_dbg_indent(c, 1);

	for(i=0; i<d->num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			if(!do_read_prc_record(c, d, i, pos1+d->rec_size*i))
				goto done;
		}
		else {
			if(!do_read_pdb_record(c, d, i, pos1+d->rec_size*i))
				goto done;
		}
	}
done:
	de_dbg_indent(c, -1);
}

// Allocates and populates the d->rec_data array.
// Sets d->rec_size.
// Tests for sanity, and returns 0 if there is a problem.
static int do_prescan_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	if(d->file_fmt==FMT_PRC) d->rec_size = 10;
	else d->rec_size = 8;

	if(d->num_recs<1) return 1;
	// num_recs is untrusted, but it is a 16-bit int that can be at most 65535.
	d->rec_data = de_malloc(c, sizeof(struct rec_data_struct)*d->num_recs);
	for(i=0; i<d->num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			d->rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i + 6);
		}
		else {
			d->rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i);
		}

		// Record data must not start beyond the end of file.
		if((de_int64)d->rec_data[i].offset > c->infile->len) {
			de_err(c, "Record %d (at %d) starts after end of file (%d)\n",
				(int)i, (int)d->rec_data[i].offset, (int)c->infile->len);
			return 0;
		}

		// Record data must not start before the previous record's data.
		if(i>0) {
			if(d->rec_data[i].offset < d->rec_data[i-1].offset) {
				de_err(c, "Record %d (at %d) starts before previous record (at %d)\n",
					(int)i, (int)d->rec_data[i].offset, (int)d->rec_data[i-1].offset);
				return 0;
			}
		}
	}
	return 1;
}

static void do_app_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->appinfo_offs==0) return;
	de_dbg(c, "app info block at %d\n", (int)d->appinfo_offs);

	de_dbg_indent(c, 1);
	if(d->sortinfo_offs) {
		len = d->sortinfo_offs - d->appinfo_offs;
	}
	else if(d->num_recs>0) {
		len = (de_int64)d->rec_data[0].offset - d->appinfo_offs;
	}
	else {
		len = c->infile->len - d->appinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		extract_item(c, d, d->appinfo_offs, len, "appinfo.bin", DE_CREATEFLAG_IS_AUX);
	}

	de_dbg_indent(c, -1);
}

static void do_sort_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->sortinfo_offs==0) return;
	de_dbg(c, "sort info block at %d\n", (int)d->sortinfo_offs);

	de_dbg_indent(c, 1);
	if(d->num_recs>0) {
		len = (de_int64)d->rec_data[0].offset - d->sortinfo_offs;
	}
	else {
		len = c->infile->len - d->sortinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		extract_item(c, d, d->sortinfo_offs, len, "sortinfo.bin", DE_CREATEFLAG_IS_AUX);
	}

	de_dbg_indent(c, -1);
}

static void de_run_palmdb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	if(!do_read_header(c, d)) goto done;
	if(!do_prescan_records(c, d, 78)) goto done;
	do_read_records(c, d, 78);
	do_app_info_block(c, d);
	do_sort_info_block(c, d);

done:
	if(d) {
		de_free(c, d->rec_data);
		de_free(c, d);
	}
}

static int de_identify_palmdb(deark *c)
{
	int has_ext = 0;
	de_byte id[8];
	static const char *exts[] = {"pdb", "prc", "pqa", "mobi"};
	static const char *ids[] = {"vIMGView", "TEXtREAd", "pqa clpr", "BOOKMOBI"};
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}
	if(!has_ext) return 0;

	de_read(id, 60, 8);

	if(!de_memcmp(id, "appl", 4)) return 100;

	for(k=0; k<DE_ITEMS_IN_ARRAY(ids); k++) {
		if(!de_memcmp(id, ids[k], 8)) return 100;
	}

	// TODO: More work is needed here.
	return 0;
}

void de_module_palmdb(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmdb";
	mi->desc = "Palm OS PDB, PRC, PQA";
	mi->run_fn = de_run_palmdb;
	mi->identify_fn = de_identify_palmdb;
}
