// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Binary PLIST (property list format used mainly by Apple)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_plist);

struct objref_struct {
	de_uint32 offs;
};

typedef struct localctx_struct {
	unsigned int nbytes_per_objref_table_entry;
	unsigned int nbytes_per_object_refnum;
	de_int64 top_object_refnum;
	de_int64 objref_table_start;

	// objref_table maps object refnums to file offsets.
	// It has .num_objrefs elements.
	de_int64 num_objrefs;
	struct objref_struct *objref_table;
} lctx;

static int do_header(deark *c, lctx *d, de_int64 pos)
{
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);

	if(dbuf_memcmp(c->infile, pos, "bplist", 6)) {
		de_err(c, "Not in binary PLIST format");
		goto done;
	}
	if(dbuf_memcmp(c->infile, pos+6, "00", 2)) {
		// TODO: Support other versions?
		de_err(c, "Unsupported binary PLIST version");
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static int do_trailer(deark *c, lctx *d, de_int64 pos1)
{
	int retval = 0;
	de_int64 pos = pos1;

	de_dbg(c, "trailer at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 5; // unused
	pos++; // sort version

	d->nbytes_per_objref_table_entry = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "bytes per objref table entry: %u", d->nbytes_per_objref_table_entry);

	d->nbytes_per_object_refnum = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "bytes per object refnum: %u", d->nbytes_per_object_refnum);

	d->num_objrefs = de_geti64be(pos);
	de_dbg(c, "num objrefs: %d", (int)d->num_objrefs);
	pos += 8;

	d->top_object_refnum = de_geti64be(pos);
	de_dbg(c, "root object refnum: %"INT64_FMT, d->top_object_refnum);
	pos += 8;

	d->objref_table_start = de_geti64be(pos);
	de_dbg(c, "objref table start: %"INT64_FMT, d->objref_table_start);
	pos += 8;

	if(d->nbytes_per_objref_table_entry<1 || d->nbytes_per_objref_table_entry>8 ||
		d->nbytes_per_object_refnum<1 || d->nbytes_per_object_refnum>8)
	{
		de_err(c, "Bad or unsupported PLIST format");
		goto done;
	}

	if(d->num_objrefs<0 || d->num_objrefs>1000000) {
		de_err(c, "Too many PLIST objects (%"INT64_FMT")", d->num_objrefs);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_one_object_by_offset(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_byte marker;

	de_dbg(c, "object at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);
	if(pos<8 || pos>=c->infile->len-32) goto done;

	marker = de_getbyte_p(&pos);
	de_dbg(c, "marker: 0x%02x", (unsigned int)marker);
done:
	de_dbg_indent(c, -1);
}

static void do_one_object_by_refnum(deark *c, lctx *d, de_int64 refnum)
{
	if(refnum<0 || refnum>d->num_objrefs) return;
	do_one_object_by_offset(c, d, d->objref_table[refnum].offs);
}

static void read_offset_table(deark *c, lctx *d)
{
	de_int64 k;
	de_int64 pos = d->objref_table_start;

	de_dbg(c, "objref table at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);

	d->objref_table = de_malloc(c, d->num_objrefs * sizeof(struct objref_struct));

	for(k=0; k<d->num_objrefs; k++) {
		de_int64 offs;

		if(pos+(de_int64)d->nbytes_per_objref_table_entry > c->infile->len-32) break;
		offs = dbuf_getint_ext(c->infile, pos, d->nbytes_per_objref_table_entry, 0, 0);
		if(c->debug_level>=2)
			de_dbg(c, "objref[%"INT64_FMT"] offset: %"INT64_FMT, k, offs);
		d->objref_table[k].offs = (de_uint32)offs;
		pos += (de_int64)d->nbytes_per_objref_table_entry;
	}

	de_dbg_indent(c, -1);
}

static void de_run_plist(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos = 0;

	d = de_malloc(c, sizeof(lctx));

	if(c->infile->len>0xffffffffU) {
		// We *could* support huge PLIST files, but until I learn that they
		// are valid, for efficiency I'll make sure an offset can fit in
		// 4 bytes.
		de_err(c, "PLIST too large (%"INT64_FMT")", c->infile->len);
		goto done;
	}

	if(!do_header(c, d, pos)) goto done;
	pos += 8;

	if(!do_trailer(c, d, c->infile->len-32)) goto done;
	read_offset_table(c, d);

	do_one_object_by_refnum(c, d, d->top_object_refnum);

done:
	if(d) {
		de_free(c, d->objref_table);
		de_free(c, d);
	}
}

static int de_identify_plist(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "bplist00", 8))
		return 100;
	return 0;
}

void de_module_plist(deark *c, struct deark_module_info *mi)
{
	mi->id = "plist";
	mi->desc = "PLIST (binary format)";
	mi->run_fn = de_run_plist;
	mi->identify_fn = de_identify_plist;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
