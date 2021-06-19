// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Misc. Corel / CorelDRAW formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_cdr_wl);
DE_DECLARE_MODULE(de_module_corel_bmf);
DE_DECLARE_MODULE(de_module_corel_ccx);

// **************************************************************************
// CorelDRAW CDR - old "WL" format
// **************************************************************************

static void de_run_cdr_wl(deark *c, de_module_params *mparams)
{
	u8 version;
	i64 pos = 0;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	de_module_params *mparams2 = NULL;

	de_declare_fmt(c, "CorelDRAW (WL format)");
	version = de_getbyte(2);
	de_dbg(c, "version code: 0x%02x", (unsigned int)version);
	if(version <= (u8)'e') goto done;

	pos = de_getu32le(28);
	de_dbg(c, "preview image at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, "preview", 0, DE_ENCODING_LATIN1);

	pos += 2; // ?
	// Seems to be Windows DDB format, or something like it.
	mparams2 = de_malloc(c, sizeof(de_module_params));
	mparams2->in_params.codes = "NX";
	mparams2->in_params.fi = fi;
	de_run_module_by_id_on_slice(c, "ddb", mparams2, c->infile, pos, c->infile->len-pos);
	de_dbg_indent(c, -1);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	de_free(c, mparams2);
}

static int de_identify_cdr_wl(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "WL", 2)) {
		if(de_input_file_has_ext(c, "cdr")) return 100;
		return 6;
	}
	return 0;
}

void de_module_cdr_wl(deark *c, struct deark_module_info *mi)
{
	mi->id = "cdr_wl";
	mi->desc = "CorelDRAW (old WL format)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_cdr_wl;
	mi->identify_fn = de_identify_cdr_wl;
}

// **************************************************************************
// Corel Gallery .BMF
// **************************************************************************

// Warning: The BMF preview image decoder is based on reverse engineering, may not
// be correct.

static void de_run_corel_bmf(deark *c, de_module_params *mparams1)
{
	de_module_params *mparams2 = NULL;
	int saved_indent_level;
	i64 pos;
	i64 n;
	i64 seg_size;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = 65;
	seg_size = de_getu32le_p(&pos);
	de_dbg(c, "preview image segment at %"I64_FMT", len=%"I64_FMT, pos, seg_size);
	de_dbg_indent(c, 1);

	if(pos + seg_size > c->infile->len) {
		seg_size = c->infile->len - pos;
	}

	n = de_getu32le(pos);
	if(n!=40) {
		de_err(c, "Unsupported Corel BMF version");
		goto done;
	}

	mparams2 = de_malloc(c, sizeof(de_module_params));
	mparams2->in_params.codes = "X";
	mparams2->in_params.flags = 0x81;
	de_run_module_by_id_on_slice(c, "dib", mparams2, c->infile, pos, seg_size);

done:
	de_free(c, mparams2);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_corel_bmf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "@CorelBMF\x0a\x0d", 11)) return 100;
	return 0;
}

void de_module_corel_bmf(deark *c, struct deark_module_info *mi)
{
	mi->id = "corel_bmf";
	mi->desc = "Corel Gallery BMF";
	mi->run_fn = de_run_corel_bmf;
	mi->identify_fn = de_identify_corel_bmf;
}

// **************************************************************************
// Corel CCX
// Decompress/convert Corel CCX clip art to Corel CMX
// **************************************************************************

#define CODE_CDRX 0x43445258U
#define CODE_CMX1 0x434d5831U
#define CODE_CPng 0x43506e67U
#define CODE_RIFF 0x52494646U
#define CODE_pack 0x7061636bU

typedef struct localctx_struct {
	i64 pack_pos; // 0 = not found
	i64 pack_dpos;
	i64 pack_dlen;
	int wrote_cmx_file;
} lctx;

static void do_decompress(deark *c, lctx *d)
{
	u32 cmprmeth;
	i64 pos = d->pack_dpos;
	i64 cmpr_start;
	i64 cmpr_len;
	i64 unc_len;
	i64 unc_len_padded;
	i64 unc_riff_size;
	i64 after_pack_pos;
	i64 after_pack_len;
	dbuf *outf = NULL;
	dbuf *unc_data = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_deflate_params inflparams;

	de_zeromem(&inflparams, sizeof(struct de_deflate_params));
	if(d->pack_dlen < 12) goto done;
	unc_len = de_getu32le_p(&pos);
	de_dbg(c, "uncompressed len (reported): %"I64_FMT, unc_len);
	if(unc_len > DE_MAX_SANE_OBJECT_SIZE) goto done;

	cmprmeth = (u32)de_getu32be_p(&pos);
	if(cmprmeth != CODE_CPng) {
		de_err(c, "Unsupported compression method");
		goto done;
	}
	pos += 4; // Unknown field

	unc_len_padded = de_pad_to_2(unc_len);
	cmpr_start = pos;
	cmpr_len = d->pack_dpos + d->pack_dlen - cmpr_start;
	if(cmpr_len<1) goto done;

	// Decompress the "pack" chunk to a membuf.
	// We *could* decompress directly to the output file instead, but this way
	// is more flexible.
	unc_data = dbuf_create_membuf(c, unc_len_padded, 0x1);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = cmpr_start;
	dcmpri.len = cmpr_len;
	dcmpro.f = unc_data;
	dcmpro.len_known = 1;
	dcmpro.expected_len = unc_len;
	inflparams.flags = DE_DEFLATEFLAG_ISZLIB;
	fmtutil_decompress_deflate_ex(c, &dcmpri, &dcmpro, &dres, &inflparams);

	if(dres.errcode) {
		de_err(c, "%s", dres.errmsg);
		goto done;
	}
	if(unc_data->len < unc_len) {
		de_warn(c, "Decompression may have failed (expected %"I64_FMT" bytes, got %"I64_FMT")",
			unc_len, unc_data->len);
	}
	dbuf_truncate(unc_data, unc_len_padded);

	after_pack_pos = d->pack_dpos + de_pad_to_2(d->pack_dlen);
	after_pack_len = de_pad_to_2(c->infile->len - after_pack_pos);
	unc_riff_size = d->pack_pos + unc_data->len + after_pack_len - 8;

	outf = dbuf_create_output_file(c, "cmx", NULL, 0);
	d->wrote_cmx_file = 1;

	dbuf_writeu32be(outf, CODE_RIFF);
	// Use the new the RIFF size
	dbuf_writeu32le(outf, unc_riff_size);
	// Change the RIFF type: CDRX -> CMX1
	dbuf_writeu32be(outf, CODE_CMX1);

	// Copy everything else, up to the "pack" chunk
	dbuf_copy(c->infile, 12, d->pack_pos-12, outf);

	// Copy the decompressed contents of the "pack" chunk
	dbuf_copy(unc_data, 0, unc_data->len, outf);

	// Copy everything after the "pack" chunk
	dbuf_copy(c->infile, after_pack_pos, after_pack_len, outf);

done:
	dbuf_close(unc_data);
	dbuf_close(outf);
}

static int my_ccx_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_RIFF:
		ictx->is_std_container = 1;
		return 1;
	case CODE_pack:
		d->pack_pos = ictx->chunkctx->pos;
		d->pack_dpos = ictx->chunkctx->dpos;
		d->pack_dlen = ictx->chunkctx->dlen;
		// We have what we need; tell the RIFF parser to stop.
		return 0;
	}

	ictx->handled = 1;
	return 1;
}

static void de_run_corel_ccx(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->is_le = 1;
	ictx->reversed_4cc = 0;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_ccx_chunk_handler;
	ictx->f = c->infile;

	fmtutil_read_iff_format(c, ictx, 0, c->infile->len);
	if(d->pack_pos) {
		de_dbg(c, "pack chunk found at %"I64_FMT, d->pack_pos);
		de_dbg_indent(c, 1);
		do_decompress(c, d);
		de_dbg_indent(c, -1);
	}

	de_free(c, ictx);
	if(d) {
		if(!d->wrote_cmx_file) {
			de_err(c, "Cannot convert this CCX file. Try \"-m riff\" to decode.");
		}
		de_free(c, d);
	}
}

static int de_identify_corel_ccx(deark *c)
{
	if((de_getu32be(0)==CODE_RIFF) &&
		(de_getu32be(8)==CODE_CDRX))
	{
		return 100;
	}
	return 0;
}

void de_module_corel_ccx(deark *c, struct deark_module_info *mi)
{
	mi->id = "corel_ccx";
	mi->desc = "Corel CCX";
	mi->desc2 = "Decompress to CMX";
	mi->run_fn = de_run_corel_ccx;
	mi->identify_fn = de_identify_corel_ccx;
}
