// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// PackDir compressed archive format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_packdir);

#define MAX_NESTING_LEVEL 32

struct pdctx_object {
	u32 attribs;
	u32 object_type;
	u8 is_dir;
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
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = md->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_len;

	de_fmtutil_decompress_zoo_lzd(c, &dcmpri, &dcmpro, &dres, d->lzw_maxbits);

	if(dres.errcode) {
		de_err(c, "%s: %s", ucstring_getpsz_d(md->name), de_dfilter_get_errmsg(c, &dres));
	}
	else if(outf->len != md->orig_len) {
		de_err(c, "%s: Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			ucstring_getpsz_d(md->name), md->orig_len, outf->len);
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

	if(pos + md->cmpr_len > c->infile->len) {
		de_err(c, "Unexpected EOF");
		goto done;
	}

	fi = de_finfo_create(c);

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

	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_time;

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	if(md->is_compressed) {
		do_packdir_file_compressed(c, d, md, pos, outf);
	}
	else {
		dbuf_copy(c->infile, pos, md->cmpr_len, outf);
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fullfn);
}

// The name of the root object is usually something ugly like
// "RAM::RamDisc0.$.MyProg". Try to make it nicer by only using the last part
// of it.
static void convert_root_name(deark *c, struct pdctx_struct *d,
	de_ucstring *nsrc, de_ucstring *ndst)
{
	i64 k;

	for(k=0; k<nsrc->len; k++) {
		i32 ch = nsrc->str[k];
		if(ch=='.' || ch==':') {
			ucstring_empty(ndst);
		}
		else {
			ucstring_append_char(ndst, ch);
		}
	}
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
	struct de_riscos_file_attrs rfa;

	de_dbg_indent_save(c, &saved_indent_level);

	if(level >= MAX_NESTING_LEVEL) {
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

	de_zeromem(&rfa, sizeof(struct de_riscos_file_attrs));
	de_fmtutil_riscos_read_load_exec(c, c->infile, &rfa, pos);
	pos += 8;
	md->mod_time = rfa.mod_time;

	length_raw = de_getu32le_p(&pos);

	de_fmtutil_riscos_read_attribs_field(c, c->infile, &rfa, pos, 0);
	pos += 4;
	md->attribs = rfa.attribs;

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

		if(level<=0) {
			de_ucstring *tmpstr = ucstring_create(c);
			convert_root_name(c, d, md->name, tmpstr);
			de_strarray_push(d->curpath, tmpstr);
			ucstring_destroy(tmpstr);
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
	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);
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
