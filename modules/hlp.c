// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Windows HLP

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_hlp);

struct bptree {
	unsigned int flags;
	de_int64 pagesize;
	de_int64 root_page;
	de_int64 num_levels;
	de_int64 num_pages;
	de_int64 num_entries;
	de_int64 pagesdata_pos;
};

typedef struct localctx_struct {
	de_int64 internal_dir_FILEHEADER_offs;
	struct bptree bpt;
} lctx;

static void do_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 n;

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->internal_dir_FILEHEADER_offs = de_geti32le(4);
	de_dbg(c, "internal dir FILEHEADER pos: %d\n", (int)d->internal_dir_FILEHEADER_offs);

	n = de_geti32le(8);
	de_dbg(c, "FREEHEADER pos: %d\n", (int)n);

	n = de_geti32le(12);
	de_dbg(c, "reported file size: %d\n", (int)n);

	de_dbg_indent(c, -1);
}

static void do_index_page(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 n;
	de_int64 pos = pos1;

	de_dbg(c, "index page at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	pos += 2; // Unused

	n = de_geti16le(pos);
	de_dbg(c, "NEntries: %d\n", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "PreviousPage: %d\n", (int)n);
	pos += 2;

	de_dbg_indent(c, -1);
}

static void do_leaf_page(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 n;
	de_int64 pos = pos1;

	de_dbg(c, "leaf page at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	pos += 2; // Unused

	n = de_geti16le(pos);
	de_dbg(c, "NEntries: %d\n", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "PreviousPage: %d\n", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "NextPage: %d\n", (int)n);
	pos += 2;

	de_dbg_indent(c, -1);
}

static void do_bplustree(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 n;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	n = de_getui16le(pos);
	if(n != 0x293b) {
		de_err(c, "Expected B+ tree structure at %d not found\n", (int)pos1);
		goto done;
	}
	pos += 2;

	de_dbg(c, "B+ tree at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	d->bpt.flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x\n", d->bpt.flags);
	pos += 2;

	d->bpt.pagesize = de_getui16le(pos);
	de_dbg(c, "PageSize: %d\n", (int)d->bpt.pagesize);
	pos += 2;

	pos += 16; // TODO: Structure
	pos += 2; // MustBeZero
	pos += 2; // PageSplits

	d->bpt.root_page = de_geti16le(pos);
	de_dbg(c, "RootPage: %d\n", (int)d->bpt.root_page);
	pos += 2;

	pos += 2; // MustBeNegOne

	d->bpt.num_pages = de_geti16le(pos);
	de_dbg(c, "TotalPages: %d\n", (int)d->bpt.num_pages);
	pos += 2;

	d->bpt.num_levels = de_geti16le(pos);
	de_dbg(c, "NLevels: %d\n", (int)d->bpt.num_levels);
	pos += 2;

	d->bpt.num_entries = de_geti32le(pos);
	de_dbg(c, "TotalBtreeEntries: %d\n", (int)d->bpt.num_entries);
	pos += 4;

	d->bpt.pagesdata_pos = pos;
	de_dbg(c, "%d page(s), %d bytes each, at %d (total size=%d)\n",
		(int)d->bpt.num_pages, (int)d->bpt.pagesize, (int)d->bpt.pagesdata_pos,
		(int)(d->bpt.num_pages * d->bpt.pagesize));

	if(d->bpt.num_levels>1) {
		if(d->bpt.root_page>=0) {
			do_index_page(c, d,
				d->bpt.pagesdata_pos + d->bpt.root_page*d->bpt.pagesize);
		}
	}
	else {
		do_leaf_page(c, d,
			d->bpt.pagesdata_pos + d->bpt.root_page*d->bpt.pagesize);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_internal_dir_FILEHEADER(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 usedspace;
	de_int64 n;
	de_byte b;

	pos = d->internal_dir_FILEHEADER_offs;
	if(pos<16) goto done;

	de_dbg(c, "internal dir at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	n = de_geti32le(pos);
	de_dbg(c, "ReservedSpace: %d\n", (int)n);
	usedspace = de_geti32le(pos+4);
	de_dbg(c, "UsedSpace: %d\n", (int)usedspace);
	b = de_getbyte(pos+8);
	de_dbg(c, "FileFlags: 0x%02x\n", (unsigned int)b);
	pos += 9;

	do_bplustree(c, d, pos, usedspace);

	de_dbg_indent(c, -1);
done:
	;
}

static void de_run_hlp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	do_header(c, d, pos);

	do_internal_dir_FILEHEADER(c, d);

	de_free(c, d);
}

static int de_identify_hlp(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x3f\x5f\x03\x00", 4))
		return 100;
	return 0;
}

void de_module_hlp(deark *c, struct deark_module_info *mi)
{
	mi->id = "hlp";
	mi->desc = "HLP";
	mi->run_fn = de_run_hlp;
	mi->identify_fn = de_identify_hlp;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
