// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm Database (PDB)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_palmdb);

#define CODE_appl 0x6170706cU

typedef struct localctx_struct {
	de_int64 num_recs;
	struct de_fourcc dtype4cc;
	struct de_fourcc creator4cc;
} lctx;

static void palm_date_to_timestamp_and_string(de_int64 pt, struct de_timestamp *ts,
	char *timestamp_buf, size_t timestamp_buf_len)
{
	unsigned int flags = 0;

	if((pt&0x80000000LL) || (pt==0)) {
		// TODO: This is clearly wrong for some files.
		// TODO: What timezone are these times in?
		ts->unix_time = pt - 2082844800;
	}
	else { // Assume Unix-style time
		ts->unix_time = pt;
		flags &= 0x1;
	}

	if(pt==0) {
		de_strlcpy(timestamp_buf, "not set", timestamp_buf_len);
		ts->is_valid = 0;
	}
	else {
		de_timestamp_to_string(ts, timestamp_buf, timestamp_buf_len, flags);
		ts->is_valid = 1;
	}
}

static int do_read_header(deark *c, lctx *d)
{
	de_int64 pos1 = 0;
	de_ucstring *dname = NULL;
	de_uint32 attribs;
	de_uint32 version;
	de_int64 ctime, mtime, btime;
	struct de_timestamp ctime_ts, mtime_ts, btime_ts;
	de_int64 x;
	de_int64 appinfo_offs;
	de_int64 sortinfo_offs;
	char timestamp_buf[64];

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

	ctime = de_getui32be(pos1+36);
	palm_date_to_timestamp_and_string(ctime, &ctime_ts, timestamp_buf, sizeof(timestamp_buf));
	de_dbg(c, "create date: %"INT64_FMT" (%s)\n", ctime, timestamp_buf);

	mtime = de_getui32be(pos1+40);
	palm_date_to_timestamp_and_string(mtime, &mtime_ts, timestamp_buf, sizeof(timestamp_buf));
	de_dbg(c, "mod date: %"INT64_FMT" (%s)\n", mtime, timestamp_buf);

	btime = de_getui32be(pos1+44);
	palm_date_to_timestamp_and_string(btime, &btime_ts, timestamp_buf, sizeof(timestamp_buf));
	de_dbg(c, "backup date: %"INT64_FMT" (%s)\n", btime, timestamp_buf);

	x = de_getui32be(pos1+48);
	de_dbg(c, "mod number: %d\n", (int)x);
	appinfo_offs = de_getui32be(pos1+52);
	de_dbg(c, "app info pos: %d\n", (int)appinfo_offs);
	sortinfo_offs = de_getui32be(pos1+56);
	de_dbg(c, "sort info pos: %d\n", (int)sortinfo_offs);

	dbuf_read_fourcc(c->infile, pos1+60, &d->dtype4cc, 0);
	de_dbg(c, "type: \"%s\"\n", d->dtype4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos1+64, &d->creator4cc, 0);
	de_dbg(c, "creator: \"%s\"\n", d->creator4cc.id_printable);

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

static int do_read_pdb_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_int64 data_offset;
	de_byte attribs;
	de_uint32 id;

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	data_offset = de_getui32be(pos1);
	de_dbg(c, "data pos: %d\n", (int)data_offset);

	attribs = de_getbyte(pos1+4);
	de_dbg(c, "attributes: 0x%02x\n", (unsigned int)attribs);

	id = (de_getbyte(pos1+5)<<16) |
		(de_getbyte(pos1+6)<<8) |
		(de_getbyte(pos1+7));
	de_dbg(c, "id: %d\n", (int)id);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_pdb_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	de_dbg(c, "PDB records section at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	for(i=0; i<d->num_recs; i++) {
		if(!do_read_pdb_record(c, d, i, pos1+8*i))
			goto done;
	}
done:
	de_dbg_indent(c, -1);
}

static int do_read_prc_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_int64 data_offset;
	de_uint32 id;
	struct de_fourcc name4cc;

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos1, &name4cc, 0);
	de_dbg(c, "name: \"%s\"\n", name4cc.id_printable);

	id = (de_uint32)de_getui16be(pos1+4);
	de_dbg(c, "id: %d\n", (int)id);

	data_offset = de_getui32be(pos1+6);
	de_dbg(c, "data pos: %d\n", (int)data_offset);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_prc_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	de_dbg(c, "PRC records section at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	for(i=0; i<d->num_recs; i++) {
		if(!do_read_prc_record(c, d, i, pos1+10*i))
			goto done;
	}
done:
	de_dbg_indent(c, -1);
}

static void de_run_palmdb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	if(!do_read_header(c, d)) goto done;

	if(d->dtype4cc.id == 0x6170706c) {
		do_read_prc_records(c, d, 78);
	}
	else {
		do_read_pdb_records(c, d, 78);
	}

done:
	de_free(c, d);
}

static int de_identify_palmdb(deark *c)
{
	// TODO
	return 0;
}

void de_module_palmdb(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmdb";
	mi->desc = "PDB (PalmOS Database), or PRC";
	mi->run_fn = de_run_palmdb;
	mi->identify_fn = de_identify_palmdb;
}
