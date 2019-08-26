// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ARC compressed archive

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_arc);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags;
	const char *name;
	void *reserved;
};

struct member_data {
	u8 cmpr_meth;
	const struct cmpr_meth_info *cmi;
	i64 cmpr_size;
	i64 orig_size;
	unsigned int crc;
	de_ucstring *fn;
};

typedef struct localctx_struct {
	int member_count;
} lctx;


static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x01, 0, "stored (old format)", NULL },
	{ 0x02, 0, "stored", NULL },
	{ 0x03, 0, "packed (RLE)", NULL },
	{ 0x04, 0, "squeezed (Huffman)", NULL },
	{ 0x05, 0, "crunched5 (static LZW)", NULL },
	{ 0x06, 0, "crunched6 (RLE + static LZW)", NULL },
	{ 0x07, 0, "crunched7 (SEA internal)", NULL },
	{ 0x08, 0, "Crunched8 (RLE + dynamic LZW)", NULL },
	{ 0x09, 0, "squashed (dynamic LZW)", NULL }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(u8 cmpr_meth)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(cmpr_meth_info_arr); k++) {
		if(cmpr_meth_info_arr[k].cmpr_meth == cmpr_meth) {
			return &cmpr_meth_info_arr[k];
		}
	}
	return NULL;
}

// Returns 1 if we parsed this member successfully, and it's not the
// EOF marker.
static int do_member(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	int retval = 0;
	int saved_indent_level;
	i64 pos = pos1;
	u8 magic;
	u8 cmpr_meth;
	struct member_data *md = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	magic = de_getbyte_p(&pos);
	if(magic != 0x1a) {
		if(d->member_count==0) {
			de_err(c, "Not an ARC file");
		}
		else {
			de_err(c, "Failed to find ARC member at %"I64_FMT", stopping", pos1);
		}
		goto done;
	}

	cmpr_meth = de_getbyte_p(&pos);
	if(cmpr_meth == 0) {
		de_dbg(c, "eof marker at %"I64_FMT, pos1);
		goto done;
	}

	md = de_malloc(c, sizeof(struct member_data));
	md->fn = ucstring_create(c);

	md->cmpr_meth = cmpr_meth;

	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md->cmi = get_cmpr_meth_info(md->cmpr_meth);
	de_dbg(c, "cmpr method: %u (%s)", (unsigned int)md->cmpr_meth,
		(md->cmi ? md->cmi->name : "?"));

	dbuf_read_to_ucstring(c->infile, pos, 13, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_CP437_G);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	md->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);
	pos += 4; // date/time
	pos += 2; // crc
	if(md->cmpr_meth == 1) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	pos += md->cmpr_size;
	retval = 1;

done:
	*bytes_consumed = pos - pos1;
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_arc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(lctx));
	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		ret = do_member(c, d, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) break;
		pos += bytes_consumed;
		d->member_count++;
	}

	de_free(c, d);
}

// TODO: Better identification
static int de_identify_arc(deark *c)
{
	static const char *exts[] = {"arc", "pak", "spk"};
	int has_ext = 0;
	size_t k;

	if(de_getbyte(0) != 0x1a) return 0;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}
	if(!has_ext) return 0;

	return 15;
}

void de_module_arc(deark *c, struct deark_module_info *mi)
{
	mi->id = "arc";
	mi->desc = "ARC compressed archive";
	mi->run_fn = de_run_arc;
	mi->identify_fn = de_identify_arc;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
