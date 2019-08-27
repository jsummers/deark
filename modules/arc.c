// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ARC compressed archive

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arc);

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;
typedef int (*decompressor_fn)(deark *c, lctx *d, struct member_data *md, dbuf *outf);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags;
	const char *name;
	decompressor_fn decompressor;
};

struct member_data {
	u8 cmpr_meth;
	const struct cmpr_meth_info *cmi;
	i64 cmpr_size;
	i64 orig_size;
	i64 cmpr_data_pos;
	u32 crc_reported;
	u32 crc_calc;
	de_ucstring *fn;
};

struct localctx_struct {
	int input_encoding;
	int member_count;
	struct de_crcobj *crco;
};

static int decompress_stored(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	dbuf_copy(c->infile, md->cmpr_data_pos, md->cmpr_size, outf);
	return 1;
}

static int decompress_packed(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	int ret;

	ret = de_fmtutil_decompress_rle90(c->infile, md->cmpr_data_pos, md->cmpr_size, outf,
		1, md->orig_size, 0);
	return ret;
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x01, 0, "stored (old format)", decompress_stored },
	{ 0x02, 0, "stored", decompress_stored },
	{ 0x03, 0, "packed (RLE)", decompress_packed },
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

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
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
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

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
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	md->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);
	pos += 4; // date/time
	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if(md->cmpr_meth == 1) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	md->cmpr_data_pos = pos;
	pos += md->cmpr_size;
	if(pos > c->infile->len) goto done;
	retval = 1;

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type %u not supported", ucstring_getpsz_d(md->fn),
			(unsigned int)md->cmpr_meth);
		goto done;
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, md->fn, 0);
	fi->original_filename_flag = 1;
	outf = dbuf_create_output_file(c, NULL, fi, 0);

	de_crcobj_reset(d->crco);
	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;

	if(!md->cmi->decompressor(c, d, md, outf)) {
		goto done;
	}

	md->crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)md->crc_calc);
	if(md->crc_calc != md->crc_reported) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fn));
	}

done:
	*bytes_consumed = pos - pos1;
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
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
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437_G);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		ret = do_member(c, d, pos, &bytes_consumed);
		if(!ret || (bytes_consumed<1)) break;
		pos += bytes_consumed;
		d->member_count++;
	}

	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

// TODO: Better identification
static int de_identify_arc(deark *c)
{
	static const char *exts[] = {"arc", "ark", "pak", "spk"};
	int has_ext = 0;
	int ends_with_trailer = 0;
	size_t k;
	u8 cmpr_meth;

	if(de_getbyte(0) != 0x1a) return 0;
	cmpr_meth = de_getbyte(1);
	// TODO: We might be able to parse some files with cmpr_meth>9.
	if(cmpr_meth<1 || cmpr_meth>9) return 0;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}

	if(de_getu16be(c->infile->len-2) == 0x1a00) {
		ends_with_trailer = 1;
	}
	else if(de_getu32be(c->infile->len-8) == 0x504baa55) {
		// PKARC trailer, for files with comments
		ends_with_trailer = 1;
	}

	if(has_ext && ends_with_trailer) return 90;
	if(ends_with_trailer) return 25;
	if(has_ext) return 15;
	return 0;
}

void de_module_arc(deark *c, struct deark_module_info *mi)
{
	mi->id = "arc";
	mi->desc = "ARC compressed archive";
	mi->run_fn = de_run_arc;
	mi->identify_fn = de_identify_arc;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
