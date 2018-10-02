// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// AppleDouble, etc.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_applesingle);
DE_DECLARE_MODULE(de_module_appledouble);

typedef struct localctx_struct {
	de_uint32 version;
} lctx;

struct entry_struct {
	unsigned int idx;
	unsigned int id;
	de_int64 offset;
	de_int64 length;
};

typedef void (*handler_fn_type)(deark *c, lctx *d, struct entry_struct *e);

struct entry_id_struct {
	unsigned int id;
	const char *name;
	handler_fn_type hfn;
};

static void handler_data(deark *c, lctx *d, struct entry_struct *e)
{
	dbuf_create_file_from_slice(c->infile, e->offset, e->length,
		"data", NULL, 0x0);
}

static void handler_rsrc(deark *c, lctx *d, struct entry_struct *e)
{
	if(e->length<1) return;
	dbuf_create_file_from_slice(c->infile, e->offset, e->length,
		"rsrc", NULL, 0x0);
}

static const struct entry_id_struct entry_id_arr[] = {
	{1, "data fork", handler_data},
	{2, "resource fork", handler_rsrc},
	{3, "real name", NULL},
	{4, "comment", NULL},
	{5, "b/w icon", NULL},
	{6, "color icon", NULL},
	{8, "file dates", NULL},
	{9, "Finder info", NULL},
	{10, "Macintosh file info", NULL},
	{11, "ProDOS file info", NULL},
	{12, "MS-DOS file info", NULL},
	{13, "short name", NULL},
	{14, "AFP file info", NULL},
	{15, "directory ID", NULL}
};

static const struct entry_id_struct *find_entry_id_info(unsigned int id)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(entry_id_arr); k++) {
		if(entry_id_arr[k].id==id) return &entry_id_arr[k];
	}
	return NULL;
}

static void do_sd_entry(deark *c, lctx *d, unsigned int idx, de_int64 pos1)
{
	struct entry_struct e;
	const struct entry_id_struct *eid;
	de_int64 pos = pos1;

	de_memset(&e, 0, sizeof(struct entry_struct));
	e.idx = idx;
	e.id = (unsigned int)de_getui32be_p(&pos);
	eid =  find_entry_id_info(e.id);
	de_dbg(c, "id: %u (%s)", e.id, eid?eid->name:"?");
	e.offset = de_getui32be_p(&pos);
	de_dbg(c, "offset: %"INT64_FMT, e.offset);
	e.length = de_getui32be_p(&pos);
	de_dbg(c, "length: %"INT64_FMT, e.length);

	if(e.offset > c->infile->len) goto done;
	if(e.offset+e.length > c->infile->len) {
		de_warn(c, "Entry %u goes beyond end of file. Reducing size from %"INT64_FMT
			" to %"INT64_FMT".", e.idx, e.length, c->infile->len-e.offset);
		e.length = c->infile->len - e.offset;
	}

	if(eid && eid->hfn) {
		eid->hfn(c, d, &e);
	}

done:
	;
}

static void de_run_sd_internal(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_int64 nentries;
	de_int64 k;

	pos += 4; // signature
	d->version = (de_uint32)de_getui32be_p(&pos);
	de_dbg(c, "version: 0x%08x", (unsigned int)d->version);
	pos += 16; // filler

	nentries = de_getui16be_p(&pos);
	de_dbg(c, "number of entries: %d", (int)nentries);

	for(k=0; k<nentries; k++) {
		if(pos+12>c->infile->len) break;
		de_dbg(c, "entry[%u]", (unsigned int)k);
		de_dbg_indent(c, 1);
		do_sd_entry(c, d, (unsigned int)k, pos);
		pos += 12;
		de_dbg_indent(c, -1);
	}
}

static void de_run_appledouble(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_run_sd_internal(c, d);
	de_free(c, d);
}

static int de_identify_appledouble(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x05\x16\x07", 4))
		return 100;
	return 0;
}

void de_module_appledouble(deark *c, struct deark_module_info *mi)
{
	mi->id = "appledouble";
	mi->desc = "AppleDouble Header file";
	mi->run_fn = de_run_appledouble;
	mi->identify_fn = de_identify_appledouble;
}

static void de_run_applesingle(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_run_sd_internal(c, d);
	de_free(c, d);
}

static int de_identify_applesingle(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x05\x16\x00", 4))
		return 100;
	return 0;
}

void de_module_applesingle(deark *c, struct deark_module_info *mi)
{
	mi->id = "applesingle";
	mi->desc = "AppleSingle";
	mi->run_fn = de_run_applesingle;
	mi->identify_fn = de_identify_applesingle;
}
