// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Mac Resource [Manager] format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_macrsrc);

typedef struct localctx_struct {
	de_int64 data_offs, map_offs;
	de_int64 data_size, map_size;
} lctx;

static void do_type(deark *c, lctx *d, de_int64 idx, de_int64 pos1)
{
}

static void do_type_list(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 type_count_raw;
	de_int64 type_count;
	de_int64 k;

	de_dbg(c, "type list at %d", (int)pos1);
	de_dbg_indent(c, 1);
	type_count_raw = de_getui16be_p(&pos);
	type_count = (type_count_raw==0xffff)?0:(type_count_raw+1);
	de_dbg(c, "count: %d", (int)type_count);

	for(k=0; k<type_count; k++) {
		de_dbg(c, "type record[%d] at %d", (int)k, (int)pos);
		de_dbg_indent(c, 1);
		do_type(c, d, k, pos);
		pos += 8;
		de_dbg_indent(c, -1);
	}
	de_dbg_indent(c, -1);
}

static void do_map(deark *c, lctx *d, de_int64 map_offs, de_int64 map_size)
{
	de_int64 pos = map_offs;
	de_int64 typeListOffset_rel, nameListOffset_rel;
	de_int64 n;

	n = de_getui32be(map_offs+4);
	if(n!=map_offs) {
		de_err(c, "Resource map section not found, expected to be at %d", (int)map_offs);
		return;
	}

	de_dbg(c, "resource map section at %d", (int)map_offs);
	de_dbg_indent(c, 1);

	pos += 16; // copy of header
	pos += 4; // nextResourceMap
	pos += 2; // fileRef
	pos += 2; // attributes
	typeListOffset_rel = de_getui16be_p(&pos);
	de_dbg(c, "type list offset: (%d+)%d", (int)map_offs,
		(int)typeListOffset_rel);
	nameListOffset_rel = de_getui16be_p(&pos);
	de_dbg(c, "name list offset: (%d+)%d", (int)map_offs,
		(int)nameListOffset_rel);

	if(typeListOffset_rel<28) {
		de_err(c, "Invalid typeListOffset");
		goto done;
	}

	do_type_list(c, d, map_offs+typeListOffset_rel);

done:
	de_dbg_indent(c, 1);
}

static void de_run_macrsrc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	d->data_offs = de_getui32be_p(&pos);
	d->map_offs = de_getui32be_p(&pos);
	d->data_size = de_getui32be_p(&pos);
	d->map_size = de_getui32be_p(&pos);
	de_dbg(c, "data: pos=%"INT64_FMT", len=%"INT64_FMT, d->data_offs, d->data_size);
	de_dbg(c, "map: pos=%"INT64_FMT", len=%"INT64_FMT, d->map_offs, d->map_size);
	do_map(c, d, d->map_offs, d->map_size);
	de_free(c, d);
}

static int de_identify_macrsrc(deark *c)
{
	return 0;
}

void de_module_macrsrc(deark *c, struct deark_module_info *mi)
{
	mi->id = "macrsrc";
	mi->desc = "Macintosh Resource";
	mi->run_fn = de_run_macrsrc;
	mi->identify_fn = de_identify_macrsrc;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
