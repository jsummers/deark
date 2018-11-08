// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// ArcFS

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arcfs);

struct member_data {
	de_byte cmpr_method;
	de_uint32 attribs;
	de_int64 file_data_offs_rel;
	de_int64 file_data_offs_abs;
	de_int64 orig_len;
	de_int64 cmpr_len;
	const char *cmpr_meth_name;
	de_ucstring *fn;
};

typedef struct localctx_struct {
	de_int64 nmembers;
	de_int64 data_offs;
} lctx;

static int do_file_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 hlen;
	de_uint32 ver_r, ver_rw;
	de_uint32 format_ver;
	int retval = 0;

	de_dbg(c, "file header at %d", (int)pos1);
	de_dbg_indent(c, 1);
	pos += 8; // Signature

	hlen = de_getui32le_p(&pos);
	d->nmembers = hlen/36;
	de_dbg(c, "header len: %d (%d members)", (int)hlen, (int)d->nmembers);

	d->data_offs = de_getui32le_p(&pos);
	de_dbg(c, "data offset: %d", (int)d->data_offs);

	ver_r = (de_uint32)de_getui32le_p(&pos);
	de_dbg(c, "version req'd for read: %u.%02u", (unsigned int)(ver_r/100),
		(unsigned int)(ver_r%100));
	ver_rw = (de_uint32)de_getui32le_p(&pos);
	de_dbg(c, "version req'd for read/write: %u.%02u", (unsigned int)(ver_rw/100),
		(unsigned int)(ver_rw%100));

	// ??
	format_ver = (de_uint32)de_getui32le_p(&pos);
	de_dbg(c, "format version: %u", (unsigned int)format_ver);
	if(format_ver!=0) {
		de_err(c, "Unsupported format version: %u", (unsigned int)format_ver);
		goto done;
	}

	// 68 reserved bytes here

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_extract_member(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;

	if(md->file_data_offs_abs + md->cmpr_len > c->infile->len) goto done;

	de_dbg(c, "file data at %"INT64_FMT", len=%"INT64_FMT,
		md->file_data_offs_abs, md->cmpr_len);

	if(md->cmpr_method!=0x82 && md->cmpr_method!=0x83) {
		de_err(c, "Compression type 0x%02x (%s) is not supported.",
			(unsigned int)md->cmpr_method, md->cmpr_meth_name);
		goto done;
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, md->fn);
	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_set_max_length(outf, md->orig_len+256);

	if(md->cmpr_method==0x82) { // stored
		dbuf_copy(c->infile, md->file_data_offs_abs, md->cmpr_len, outf);
	}
	else if(md->cmpr_method==0x83) {
		de_fmtutil_decompress_binhexrle(c->infile, md->file_data_offs_abs, md->cmpr_len, outf);
	}

	if(outf->len != md->orig_len) {
		de_err(c, "Decompression failed, expected size %"INT64_FMT
			", got %"INT64_FMT, md->orig_len, outf->len);
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

static const char *get_cmpr_meth_name(de_byte t)
{
	const char *name = NULL;
	switch(t) {
	case 0x00: name="end of dir marker"; break;
	case 0x01: name="deleted object"; break;
	case 0x82: name="stored"; break;
	case 0x83: name="packed (RLE)"; break;
	case 0x88: name="crunched"; break;
	case 0xff: name="compressed"; break;
	}
	return name?name:"?";
}

static void do_member(deark *c, lctx *d, de_int64 idx, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_uint32 info_word;
	de_byte info_byte;
	int is_dir;
	int saved_indent_level;
	struct member_data *md;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));
	de_dbg(c, "header at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);

	info_byte = de_getbyte_p(&pos);
	md->cmpr_meth_name = get_cmpr_meth_name(info_byte);
	de_dbg(c, "info byte: 0x%02x (%s)", (unsigned int)info_byte, md->cmpr_meth_name);
	if(info_byte==0) goto done; // end of directory marker
	if(info_byte==1) goto done; // deleted object
	md->cmpr_method = info_byte;

	// Look ahead at the "information word".
	info_word = (de_uint32)de_getui32le(pos1+32);
	is_dir = (info_word&0x80000000U)?1:0;

	md->fn = ucstring_create(c);
	// TODO: What encoding is this?
	dbuf_read_to_ucstring(c->infile, pos, 11, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 11;

	md->orig_len = de_getui32le_p(&pos);
	if(!is_dir) {
		de_dbg(c, "orig file length: %"INT64_FMT, md->orig_len);
	}

	pos += 4; // load addr
	pos += 4; // exec addr

	md->attribs = (de_uint32)de_getui32le_p(&pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)md->attribs);

	md->cmpr_len = de_getui32le_p(&pos);
	if(!is_dir) {
		de_dbg(c, "compressed length: %"INT64_FMT, md->cmpr_len);
	}

	de_dbg(c, "info word: 0x%08x", (unsigned int)info_word);
	de_dbg_indent(c, 1);
	de_dbg(c, "is directory: %d", is_dir);
	if(!is_dir) {
		md->file_data_offs_rel = (de_int64)info_word;
		md->file_data_offs_abs = d->data_offs+md->file_data_offs_rel;
		de_dbg(c, "file data offset: (%"INT64_FMT"+)%"INT64_FMT,
			d->data_offs, md->file_data_offs_rel);
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);

	if(!is_dir) {
		do_extract_member(c, d, md);
	}

done:
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_members(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 k;
	de_int64 pos = pos1;

	for(k=0; k<d->nmembers; k++) {
		if(pos>=c->infile->len) break;
		de_dbg(c, "member[%d]", (int)k);
		de_dbg_indent(c, 1);
		do_member(c, d, k, pos);
		de_dbg_indent(c, -1);
		pos += 36;
	}
}

static void de_run_arcfs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_file_header(c, d, pos)) goto done;
	pos += 96;
	do_members(c, d, pos);

done:
	de_free(c, d);
}

static int de_identify_arcfs(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Archive\x00", 8))
		return 100;
	return 0;
}

void de_module_arcfs(deark *c, struct deark_module_info *mi)
{
	mi->id = "arcfs";
	mi->desc = "ArcFS (RISC OS archive)";
	mi->run_fn = de_run_arcfs;
	mi->identify_fn = de_identify_arcfs;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
