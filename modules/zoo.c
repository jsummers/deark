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
	u8 is_root_dir;
	i64 num_children; //  valid if is_dir
	i64 orig_len; // valid if !is_dir
	i64 cmpr_len;
	int is_compressed;
	de_ucstring *name;
	struct de_timestamp mod_time;
};

struct pdctx_struct {
	unsigned int lzw_maxbits;
	struct de_strarray *curpath;
};

static int do_packdir_header(deark *c, struct pdctx_struct *d)
{
	unsigned int maxbits_raw;
	i64 pos = 0;
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 5; // signature
	maxbits_raw = (unsigned int)de_getu32le_p(&pos);
	d->lzw_maxbits = maxbits_raw + 12;
	de_dbg(c, "lzw maxbits: %u (+12=%u)", maxbits_raw, d->lzw_maxbits);
	if(d->lzw_maxbits>16) {
		de_err(c, "Unspported \"maxbits\" value: %u", d->lzw_maxbits);
		goto done;
	}
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_packdir_file_compressed(deark *c, struct pdctx_struct *d,
	struct pdctx_object *md, i64 pos, dbuf *outf)
{
	struct unzooctx *uz = NULL;

	uz = de_malloc(c, sizeof(struct unzooctx));
	uz->c = c;
	uz->ReadArch = c->infile;
	uz->ReadArch_fpos = pos;

	(void)lzd(uz, md->cmpr_len, outf, d->lzw_maxbits);

	if(outf->len != md->orig_len) {
		de_err(c, "%s: Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			ucstring_getpsz_d(md->name), md->orig_len, outf->len);
	}

	if(uz) {
		de_free(c, uz);
	}
}

static void do_packdir_extract_file(deark *c, struct pdctx_struct *d,
	struct pdctx_object *md, i64 pos)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *fullfn = NULL;

	de_dbg(c, "%"I64_FMT" bytes of %scompressed data at %"I64_FMT,
		md->cmpr_len, (md->is_compressed?"":"un"), pos);
	fi = de_finfo_create(c);

	if(md->is_dir && md->is_root_dir) {
		fi->is_directory = 1;
		fi->is_root_dir = 1;
	}
	else {
		fullfn = ucstring_create(c);
		if(md->is_dir) {
			fi->is_directory = 1;
			de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);
		}
		else {
			de_strarray_make_path(d->curpath, fullfn, 0);
			ucstring_append_ucstring(fullfn, md->name);
		}
		de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);
		fi->original_filename_flag = 1;
	}

	fi->mod_time = md->mod_time;

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	if(md->is_compressed) {
		do_packdir_file_compressed(c, d, md, pos, outf);
	}
	else {
		dbuf_copy(c->infile, pos, md->cmpr_len, outf);
	}

	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fullfn);
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
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
	int need_dirname_pop = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	if(level >= 32) {
		goto done;
	}

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
	if((md->load_addr&0xfff00000U)==0xfff00000U) {
		// todo: filetype
		de_riscos_loadexec_to_timestamp(md->load_addr, md->exec_addr, &md->mod_time);
		dbg_timestamp(c, &md->mod_time, "timestamp");
	}
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

		// TODO: Should we try to construct a root dirname?
		// (e.g. the part after the last "." or ":"?)
		if(level<=0) {
			md->is_root_dir = 1;
		}
		else {
			de_strarray_push(d->curpath, md->name);
			need_dirname_pop = 1;
		}

		md->is_compressed = 0;
		md->orig_len = 0;
		md->cmpr_len = 0;
		do_packdir_extract_file(c, d, md, pos);

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
	if(need_dirname_pop) {
		de_strarray_pop(d->curpath);
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
	d->curpath = de_strarray_create(c);
	do_packdir_object(c, d, 9, 0, &bytes_consumed);

done:
	if(d) {
		de_strarray_destroy(d->curpath);
		de_free(c, d);
	}
}

static int de_identify_packdir(deark *c)
{
	i64 n;

	if(dbuf_memcmp(c->infile, 0, "PACK\0", 5)) return 0;
	n = de_getu32le(5);
	if(n<=4) return 100; // maxbits = 12...16
	if(n<=8) return 10; // Dunno what the "maxbits" limit is.
	return 0; // Could be Git pack format
}

void de_module_packdir(deark *c, struct deark_module_info *mi)
{
	mi->id = "packdir";
	mi->desc = "PackDir compressed archive format";
	mi->run_fn = de_run_packdir;
	mi->identify_fn = de_identify_packdir;
}
