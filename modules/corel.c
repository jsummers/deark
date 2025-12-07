// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Misc. Corel / CorelDRAW formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_cdr_wl);
DE_DECLARE_MODULE(de_module_corel_clb);
DE_DECLARE_MODULE(de_module_corel_bmf);
DE_DECLARE_MODULE(de_module_corel_ccx);

// **************************************************************************
// CorelDRAW CDR - old "WL" format
// **************************************************************************

static void de_run_cdr_wl(deark *c, de_module_params *mparams)
{
	u8 version;
	int adjdim_flag;
	i64 pos = 0;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	de_module_params *mparams2 = NULL;

	de_declare_fmt(c, "CorelDRAW (WL format)");

	// For unknown reasons, old CorelDraw-related preview images just have
	// garbage in the rightmost column and bottom row.
	// I haven't found any exceptions to this, so: Deark will crop out the
	// garbage by default.
	// Just in case there are exceptions, we allow the user to disable this
	// feature.
	// (The -padpix option is not sufficient, because, e.g., there are *3*
	// possible rendering widths for a 90x90 image: 89, 90, or 96.
	adjdim_flag = de_get_ext_option_bool(c, "cdr:adjdim", 1);

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
	// N = Image structure starts with a "file type" field.
	// X = Mark the output file as "aux".
	// C = Ignore the rightmost column and bottom row (in most cases).
	if(adjdim_flag) {
		mparams2->in_params.codes = "NXC";
	}
	else {
		mparams2->in_params.codes = "NX";
	}
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

static void help_adjdim(deark *c)
{
	de_msg(c, "-opt cdr:adjdim=0 : Disable a hack that crops off unused "
		"parts of the preview image");
}

static void de_help_cdr_wl(deark *c)
{
	help_adjdim(c);
}

void de_module_cdr_wl(deark *c, struct deark_module_info *mi)
{
	mi->id = "cdr_wl";
	mi->desc = "CorelDRAW (old WL format)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_cdr_wl;
	mi->identify_fn = de_identify_cdr_wl;
	mi->help_fn = de_help_cdr_wl;
}

// **************************************************************************
// CorelMOSAIC .CLB
// **************************************************************************

struct clb_ctx {
	de_encoding input_encoding;
	int adjdim_flag;
	i64 bytes_consumed;
};

static int do_clb_item(deark *c, struct clb_ctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 nlen;
	i64 imglen;
	i64 n;
	de_ucstring *name = NULL;
	de_ucstring *tmps = NULL;
	de_finfo *fi = NULL;
	int retval = 0;
	int saved_indent_level;
	int bitmap_ok = 1;
	u8 need_errmsg = 0;
	de_module_params *mparams2 = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "item at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	nlen = de_getu16le_p(&pos);
	if(nlen<1 || nlen>63) {
		need_errmsg = 1;
		goto done;
	}
	name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, nlen, name, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(name));
	pos += nlen;

	imglen = de_getu32le_p(&pos);
	de_dbg(c, "bitmap size: %"I64_FMT, imglen);

	// Look ahead at the DDB bmBits field.
	// It seems to be used, and it seems to be an absolute file position.
	// Bail out if it's not what we expect.
	n = de_getu32le(pos+12);
	if(n!=0 && n!=pos+16) {
		de_err(c, "Unexpected value for bmBits field");
		bitmap_ok = 0;
	}

	if(bitmap_ok) {
		de_dbg(c, "bitmap at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		fi = de_finfo_create(c);
		if(c->filenames_from_file) {
			ucstring_append_char(name, '.');
		}
		else {
			ucstring_empty(name);
		}
		ucstring_append_sz(name, "preview", DE_ENCODING_LATIN1);
		de_finfo_set_name_from_ucstring(c, fi, name, 0);

		mparams2 = de_malloc(c, sizeof(de_module_params));
		// N = Image structure starts with a "file type" field.
		// C = Ignore the rightmost column and bottom row (in most cases).
		if(d->adjdim_flag) {
			mparams2->in_params.codes = "NC";
		}
		else {
			mparams2->in_params.codes = "N";
		}
		mparams2->in_params.fi = fi;
		de_run_module_by_id_on_slice(c, "ddb", mparams2, c->infile, pos+2, imglen-2);
		de_dbg_indent(c, -1);
	}

	pos += imglen;

	n = de_getu32le_p(&pos);
	if(pos+n > c->infile->len) {
		need_errmsg = 1;
		goto done;
	}
	tmps = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, n, DE_DBG_MAX_STRLEN, tmps,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "keywords: \"%s\"", ucstring_getpsz_d(tmps));
	pos += n;

	n = de_getu32le_p(&pos);
	// This is a reference to the original file from which this preview was derived
	// (should be in the companion .CLH file).
	de_dbg(c, "original file size: %"I64_FMT, n);

	d->bytes_consumed = pos-pos1;
	retval = 1;
done:
	if(need_errmsg) {
		de_err(c, "Failed to parse item at %"I64_FMT, pos1);
	}
	de_free(c, mparams2);
	de_finfo_destroy(c, fi);
	ucstring_destroy(name);
	ucstring_destroy(tmps);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_corel_clb(deark *c, de_module_params *mparams)
{
	struct clb_ctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(struct clb_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	// Refer to the comments in the cdr_wl module.
	d->adjdim_flag = de_get_ext_option_bool(c, "cdr:adjdim", 1);

	while(1) {
		if(pos+18 > c->infile->len) goto done;
		d->bytes_consumed = 0;
		if(!do_clb_item(c, d, pos)) goto done;
		if(d->bytes_consumed<=0) goto done;
		pos += d->bytes_consumed;
	}
done:
	de_free(c, d);
}

static int de_identify_corel_clb(deark *c)
{
	i64 nlen, n;

	// This might be too strict. Need more samples.
	if(!de_input_file_has_ext(c, "clb")) return 0;
	nlen = de_getu16le(0);
	if(nlen<1 || nlen>63) return 0;
	if(de_getbyte(2+nlen-1)!=0x00) return 0;
	n = de_getu32le(2+nlen+4);
	if(n!=0x00000001) return 0;
	n = de_getu32le(2+nlen+16);
	if(n!=2+nlen+20 && n!=0) return 0;
	return 100;
}

static void de_help_corel_clb(deark *c)
{
	help_adjdim(c);
}

void de_module_corel_clb(deark *c, struct deark_module_info *mi)
{
	mi->id = "corel_clb";
	mi->desc = "CorelMOSAIC .CLB library";
	mi->run_fn = de_run_corel_clb;
	mi->identify_fn = de_identify_corel_clb;
	mi->help_fn = de_help_corel_clb;
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
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
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

static int my_ccx_chunk_handler(struct de_iffctx *ictx)
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

	ictx->handled = 1; // We're just scanning the file, so suppress default chunk handling
	return 1;
}

static void de_run_corel_ccx(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	ictx = fmtutil_create_iff_decoder(c);
	ictx->is_le = 1;
	ictx->reversed_4cc = 0;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_ccx_chunk_handler;
	ictx->f = c->infile;

	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	if(d->pack_pos) {
		de_dbg(c, "pack chunk found at %"I64_FMT, d->pack_pos);
		de_dbg_indent(c, 1);
		do_decompress(c, d);
		de_dbg_indent(c, -1);
	}

	fmtutil_destroy_iff_decoder(ictx);
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
