// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// Apple Partition Map

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_apm);

struct partition_info {
	i64 partition_startsec;
	i64 partition_startpos;
	i64 partition_size_in_secs;
	i64 partition_size_in_bytes;
	unsigned int partition_status;
	de_ucstring *pname;
	struct de_stringreaderdata *ptype;
};

typedef struct localctx_struct {
	i64 secsize;
	i64 npartitions;
} lctx;

static void destroy_partition_info(deark *c, struct partition_info *pi)
{
	if(!pi) return;
	ucstring_destroy(pi->pname);
	de_destroy_stringreaderdata(c, pi->ptype);
	de_free(c, pi);
}

static void do_extract_partition(deark *c, lctx *d, struct partition_info *pi)
{
	de_finfo *fi = NULL;
	const char *ext = "partition";
	i64 len_to_extract;
	int use_pname_in_name = 1;
	int use_ptype_in_name = 1;
	de_ucstring *outfname = NULL;

	if(pi->partition_startpos >= c->infile->len) goto done;
	len_to_extract = pi->partition_size_in_bytes;
	if(pi->partition_startpos + len_to_extract > c->infile->len) {
		de_warn(c, "Partition at %"I64_FMT" goes beyond end of file", pi->partition_startpos);
		len_to_extract = c->infile->len - pi->partition_startpos;
	}

	fi = de_finfo_create(c);
	outfname = ucstring_create(c);

	if(!de_strcmp(pi->ptype->sz, "Apple_partition_map")) {
		ext = "bin";
		use_pname_in_name = 0;
	}
	else if(!de_strcmp(pi->ptype->sz, "Apple_HFS")) {
		unsigned int sig = (unsigned int)de_getu16be(pi->partition_startpos+1024);
		if(sig==0x4244) { // "BD"
			ext = "hfs";
			use_ptype_in_name = 0;
		}
		else if(sig==0x482b) { // "H+"
			ext="hfs+.hfs";
			use_ptype_in_name = 0;
		}
		else if(sig==0x4858) { // "HX"
			ext="hfsx.hfs";
			use_ptype_in_name = 0;
		}
	}

	if(use_pname_in_name && ucstring_isnonempty(pi->pname)) {
		ucstring_append_ucstring(outfname, pi->pname);
	}
	if(use_ptype_in_name && ucstring_isnonempty(pi->ptype->str)) {
		if(outfname->len>1) {
			ucstring_append_sz(outfname, ".", DE_ENCODING_LATIN1);
		}
		ucstring_append_ucstring(outfname, pi->ptype->str);
	}
	if(outfname->len>1) {
		de_finfo_set_name_from_ucstring(c, fi, outfname, 0);
	}

	dbuf_create_file_from_slice(c->infile, pi->partition_startpos,
		len_to_extract, ext, fi, 0);

done:
	de_finfo_destroy(c, fi);
	ucstring_destroy(outfname);
}

static int do_entry_at_sector(deark *c, lctx *d, i64 secnum)
{
	i64 pos = secnum*d->secsize;
	i64 npartitions;
	int retval = 0;
	int saved_indent_level;
	struct partition_info *pi = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	if(dbuf_memcmp(c->infile, pos, "PM", 2)) {
		de_err(c, "Partition map entry not found at %"I64_FMT, pos);
		goto done;
	}

	pi = de_malloc(c, sizeof(struct partition_info));

	de_dbg(c, "partition map entry at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 4;

	npartitions = de_getu32be_p(&pos);
	de_dbg(c, "total number of partitions: %d", (int)npartitions);
	if(secnum==1) {
		d->npartitions = npartitions;
	}
	retval = 1;

	pi->partition_startsec = de_getu32be_p(&pos);
	pi->partition_startpos = pi->partition_startsec * d->secsize;
	de_dbg(c, "starting sector of partition: %"I64_FMT" (offset %"I64_FMT")",
		pi->partition_startsec, pi->partition_startpos);

	pi->partition_size_in_secs = de_getu32be_p(&pos);
	pi->partition_size_in_bytes = pi->partition_size_in_secs * d->secsize;
	de_dbg(c, "partition size: %"I64_FMT" sectors (%"I64_FMT" bytes)",
		pi->partition_size_in_secs, pi->partition_size_in_bytes);

	pi->pname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 32, pi->pname, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "partition name: \"%s\"", ucstring_getpsz(pi->pname));
	pos += 32;

	pi->ptype = dbuf_read_string(c->infile, pos, 32, 32, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "partition type: \"%s\"", ucstring_getpsz(pi->ptype->str));
	pos += 32;

	pi->partition_status = (unsigned int)de_getu32be_p(&pos);
	de_dbg(c, "status: 0x%08x", (unsigned int)pi->partition_status);

	// TODO: More fields here

	do_extract_partition(c, d, pi);

done:
	if(pi) destroy_partition_info(c, pi);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_apm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 i;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	d->secsize = 512;

	// Read the first map entry (should set d->npartitions)
	ret = do_entry_at_sector(c, d, 1);
	if(!ret) goto done;

	// Read the rest of the entries
	for(i=1; i<d->npartitions; i++) {
		ret = do_entry_at_sector(c, d, 1+i);
		if(!ret) goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_apm(deark *c)
{
	i64 i;

	for(i=0; i<2; i++) {
		if(dbuf_memcmp(c->infile, 512+i*512, "PM\x00\x00", 4))
			return 0;
	}
	return 75;
}

void de_module_apm(deark *c, struct deark_module_info *mi)
{
	mi->id = "apm";
	mi->desc = "Apple Partition Map";
	mi->run_fn = de_run_apm;
	mi->identify_fn = de_identify_apm;
}
