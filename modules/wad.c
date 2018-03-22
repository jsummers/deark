// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Doom WAD

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wad);

typedef struct localctx_struct {
	de_int64 nlumps;
	de_int64 dir_pos;
} lctx;

static void do_lump_extract(deark *c, lctx *d, de_int64 dpos, de_int64 dlen, struct de_stringreaderdata *srd)
{
	de_finfo *fi = NULL;

	// 0-length lumps are assumed to be special "virtual" lumps.
	if(dlen<=0) return;
	if(dpos<0 || dpos>=c->infile->len || dpos+dlen>c->infile->len) return;

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, srd->str);
	fi->original_filename_flag = 1;
	dbuf_create_file_from_slice(c->infile, dpos, dlen, NULL, fi, 0);
	de_finfo_destroy(c, fi);
}

static void do_lump_entry(deark *c, lctx *d, de_int64 lump_idx, de_int64 pos)
{
	de_int64 lump_pos;
	de_int64 lump_size;
	struct de_stringreaderdata *srd = NULL;

	de_dbg(c, "lump[%d] dir entry at %d", (int)lump_idx, (int)pos);
	de_dbg_indent(c, 1);
	lump_pos = de_getui32le(pos);
	de_dbg(c, "data pos: %d", (int)lump_pos);
	lump_size = de_getui32le(pos+4);
	de_dbg(c, "data size: %d", (int)lump_size);

	// dbuf_read_string is used (instead of dbuf_read_to_ucstring) because
	// the names have special meanings, so someday we might want to run
	// comparisons against them. But currently we don't do that.
	srd = dbuf_read_string(c->infile, pos+8, 8, 8, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(srd->str));

	do_lump_extract(c, d, lump_pos, lump_size, srd);

	de_dbg_indent(c, -1);
	de_destroy_stringreaderdata(c, srd);
}

static int do_directory(deark *c, lctx *d, de_int64 pos)
{
	de_int64 k;
	de_dbg(c, "directory at %d", (int)pos);
	de_dbg_indent(c, 1);

	if(pos<0 || pos>=c->infile->len) goto done;
	if(d->nlumps<1 || d->nlumps>10000) goto done;

	for(k=0; k<d->nlumps; k++) {
		if(pos+16*k > c->infile->len-16) break;
		do_lump_entry(c, d, k, pos+16*k);
	}

done:
	de_dbg_indent(c, -1);
	return 1;
}

static int do_header(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->nlumps = de_getui32le(pos+4);
	de_dbg(c, "#lumps: %d", (int)d->nlumps);
	d->dir_pos = de_getui32le(pos+8);
	de_dbg(c, "dir pos: %d", (int)d->dir_pos);
	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_wad(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_header(c, d, pos)) goto done;
	pos += 12;

	do_directory(c, d, d->dir_pos);

done:
	de_free(c, d);
}

static int de_identify_wad(deark *c)
{
	if(!dbuf_memcmp(c->infile, 1, "WAD", 3)) {
		de_byte b0;
		b0 = de_getbyte(0);
		if(b0=='I' || b0=='P') return 80;
	}
	return 0;
}

void de_module_wad(deark *c, struct deark_module_info *mi)
{
	mi->id = "wad";
	mi->desc = "Doom WAD";
	mi->run_fn = de_run_wad;
	mi->identify_fn = de_identify_wad;
}
