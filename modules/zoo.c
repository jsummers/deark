// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ZOO compressed archive format
// PackDir compressed archive format

#include <deark-config.h>
#include <deark-private.h>

#include "../foreign/unzoo.h"
#include "../foreign/zoo-lzd.h"

DE_DECLARE_MODULE(de_module_zoo);
DE_DECLARE_MODULE(de_module_packdir);

static void de_run_zoo(deark *c, de_module_params *mparams)
{
	ExtrArch(c, c->infile);
}

static int de_identify_zoo(deark *c)
{
	if(!dbuf_memcmp(c->infile, 20, "\xdc\xa7\xc4\xfd", 4))
		return 100;
	return 0;
}

void de_module_zoo(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo";
	mi->desc = "ZOO compressed archive format";
	mi->run_fn = de_run_zoo;
	mi->identify_fn = de_identify_zoo;
}

// **************************************************************************
// TODO: PackDir doesn't really belong in this file, but because its
// compression format is the same(-ish) as Zoo's, for now it's easiest to
// just put it here.

struct pdctx_object {
	u32 load_addr, exec_addr;
	u32 attribs;
	u32 object_type;
	u8 is_dir;
	i64 num_children; //  valid if is_dir
	i64 orig_len; // valid if !is_dir
	i64 cmpr_len;
	int is_compressed;
	de_ucstring *name;
};

struct pdctx_struct {
	unsigned int lzw_maxbits;
};

static int do_packdir_header(deark *c, struct pdctx_struct *d)
{
	unsigned int maxbits_raw;
	i64 pos = 0;

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 5; // signature
	maxbits_raw = (unsigned int)de_getu32le_p(&pos);
	d->lzw_maxbits = maxbits_raw + 12;
	de_dbg(c, "lzw maxbits: %u (+12=%u)", maxbits_raw, d->lzw_maxbits);
	de_dbg_indent(c, -1);
	return 1;
}

static void do_packdir_file_compressed(deark *c, struct pdctx_struct *d,
	struct pdctx_object *md, i64 pos, dbuf *outf)
{
	struct unzooctx *uz = NULL;

	uz = de_malloc(c, sizeof(struct unzooctx));
	uz->c = c;
	uz->ReadArch = c->infile;
	uz->ReadArch_fpos = pos;

	lzd(uz, outf, d->lzw_maxbits);

	if(uz) {
		de_free(c, uz);
	}
}

static void do_packdir_extract_file(deark *c, struct pdctx_struct *d,
	struct pdctx_object *md, i64 pos)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "bin", NULL, 0);

	if(md->is_compressed) {
		do_packdir_file_compressed(c, d, md, pos, outf);
	}
	else {
		dbuf_copy(c->infile, pos, md->cmpr_len, outf);
	}

	dbuf_close(outf);
}

// Process and object, and all its descendants.
// Returns 0 on fatal error.
static int do_packdir_object(deark *c, struct pdctx_struct *d, i64 pos1,
	int level, i64 *bytes_consumed1)
{
	int saved_indent_level;
	i64 foundpos = 0;
	i64 pos = pos1;
	i64 name_len;
	i64 length_raw;
	struct pdctx_object *md = NULL;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct pdctx_object));
	de_dbg(c, "object at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	*bytes_consumed1 = 0;

	if(!dbuf_search_byte(c->infile, 0x00, pos, 128, &foundpos)) {
		goto done;
	}
	name_len = foundpos - pos1;
	md->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, name_len, md->name, 0x0, DE_ENCODING_RISCOS);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->name));
	pos += name_len + 1;

	md->load_addr = (u32)de_getu32le_p(&pos);
	md->exec_addr = (u32)de_getu32le_p(&pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)md->load_addr,
		(unsigned int)md->exec_addr);
	de_dbg_indent(c, 1);
	de_dbg_indent(c, -1);

	length_raw = de_getu32le_p(&pos);
	md->attribs = (u32)de_getu32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)md->attribs);

	if(level==0) {
		md->object_type = 1;
	}
	else {
		md->object_type = (u32)de_getu32le_p(&pos);
		de_dbg(c, "type: %u", (unsigned int)md->object_type);
	}

	if(md->object_type==0) {
		; // regular file
	}
	else if(md->object_type==1) {
		md->is_dir = 1;
	}
	else {
		goto done; // unknown type
	}

	if(md->is_dir) {
		i64 bytes_consumed2 = 0;
		i64 i;
		int ret;

		md->num_children = length_raw;
		de_dbg(c, "number of dir entries: %"I64_FMT, md->num_children);

		for(i=0; i<md->num_children; i++) {
			if(pos >= c->infile->len) goto done;
			ret = do_packdir_object(c, d, pos, level+1, &bytes_consumed2);
			if((!ret) || bytes_consumed2<1) goto done;
			pos += bytes_consumed2;
		}
	}
	else {
		md->orig_len = length_raw;
		de_dbg(c, "original len: %"I64_FMT, md->orig_len);

		md->cmpr_len = de_getu32le_p(&pos);
		if(md->cmpr_len==0xffffffffLL) {
			// uncompressed
			md->cmpr_len = md->orig_len;
		}
		else {
			md->is_compressed = 1;
		}
		de_dbg(c, "is compressed: %d", md->is_compressed);
		if(md->is_compressed) {
			de_dbg(c, "cmpr len: %"I64_FMT, md->cmpr_len);
		}

		do_packdir_extract_file(c, d, md, pos);

		pos += md->cmpr_len;
	}

	*bytes_consumed1 = pos - pos1;
	retval = 1;

done:
	if(!retval && c->error_count==0) {
		de_err(c, "Can't parse object at %"I64_FMT, pos1);
	}
	if(md) {
		ucstring_destroy(md->name);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_packdir(deark *c, de_module_params *mparams)
{
	struct pdctx_struct *d = NULL;
	i64 bytes_consumed;

	d = de_malloc(c, sizeof(struct pdctx_struct));

	if(!do_packdir_header(c, d)) goto done;
	do_packdir_object(c, d, 9, 0, &bytes_consumed);

done:
	de_free(c, d);
}

static int de_identify_packdir(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PACK\0", 5))
		return 100;
	return 0;
}

void de_module_packdir(deark *c, struct deark_module_info *mi)
{
	mi->id = "packdir";
	mi->desc = "PackDir compressed archive format";
	mi->run_fn = de_run_packdir;
	mi->identify_fn = de_identify_packdir;
}
