// This file is part of Deark.
// Copyright (C) 2016-2025 Jason Summers
// See the file COPYING for terms of use.

// ZIP format

// Terminology note: For multi-file archives (disk spanning, etc.), we'll
// try to consistently use the word "segment".
// Many other terms could be used: "part", "volume", "fragment", "disk",
// "span", "split", "multi-file".
// (The ZIP documentation generally uses "segment" or "disk"; also "span"
// and "split" in certain cases.)
// There is an ambiguity regarding disk numbers. In the PKZIP user interface
// and volume labels, the first segment is number 1, whereas in the file,
// it is (usually?) number 0. We pretty much exclusively use the number in
// the file.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_zip);

struct localctx_struct;
typedef struct localctx_struct lctx;

#define CODE_PK12 0x504b0102U
#define CODE_PK14 0x504b0104U
#define CODE_PK34 0x504b0304U
#define CODE_PK36 0x504b0306U
#define CODE_PK66 0x504b0606U
#define CODE_PK67 0x504b0607U
#define CODE_PK78 0x504b0708U
#define CODE_PK00 0x504b3030U
static const u8 g_zipsig34[4] = {'P', 'K', 0x03, 0x04};

#define ZIP_LDIR_FIXED_SIZE 30
#define ZIP_CDIR_FIXED_SIZE 46

struct compression_params {
	// ZIP-specific params (not in de_dfilter_*_params) that may be needed to
	// to decompress something.
	int cmpr_meth;
	UI bit_flags;
	u8 implode_mml_bug;
};

typedef void (*decompressor_fn)(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	int cmpr_meth;
	UI flags;
	const char *name;
	decompressor_fn decompressor;
};

struct dir_entry_data {
	UI ver_needed;
	UI ver_needed_hi, ver_needed_lo;
	i64 cmpr_size, uncmpr_size;
	int cmpr_meth;
	const struct cmpr_meth_info *cmi;
	UI bit_flags;
	u32 crc_reported;
	i64 main_fname_pos;
	i64 main_fname_len;
	de_ucstring *fname;
	u8 have_read_sig_and_hdrsize;
	i64 fn_len, extra_len, comment_len;
	i64 hdrsize;
};

struct timestamp_data {
	struct de_timestamp ts; // The best timestamp of this type found so far
	int quality;
};

struct member_data {
	UI ver_made_by;
	UI ver_made_by_hi, ver_made_by_lo;
	UI attr_i, attr_e;
	i64 offset_of_local_header;
	i64 seg_number_start;
	i64 file_data_pos;
	int is_nonexecutable;
	int is_executable;
	int is_dir;
	u8 is_volume_label;
	int is_symlink;
	struct timestamp_data tsdata[DE_TIMESTAMPIDX_COUNT];
	u8 has_riscos_data;
	struct de_riscos_file_attrs rfa;

	struct dir_entry_data central_dir_entry_data;
	struct dir_entry_data local_dir_entry_data;

	i64 cmpr_size, uncmpr_size;
	u32 crc_reported;
	u8 has_extts, has_extts_atime, has_extts_crtime;
	u8 questionable_atime, questionable_crtime;
};

struct extra_item_type_info_struct;

struct extra_item_info_struct {
	u32 id;
	i64 dpos;
	i64 dlen;
	const struct extra_item_type_info_struct *eiti;
	struct member_data *md;
	struct dir_entry_data *dd;
	int is_central;
};

// This struct can be used with both the original EOCD, and Zip64 EOCD.
struct eocd_struct {
	i64 this_seg_num;
	i64 cdir_starting_seg_num;
	i64 cdir_num_entries_this_seg;
	i64 cdir_num_entries_total;
	i64 cdir_byte_size;
	i64 cdir_offset;
	i64 archive_comment_len;
	u8 is_likely_zip64;
};

struct localctx_struct {
	de_encoding default_enc_for_filenames;
	de_encoding default_enc_for_comments;
	// eocd = the effective EOCD: The original, later potentially updated by
	// the Zip64 EOCD.
	struct eocd_struct eocd;
	struct eocd_struct eocd64;
	i64 eocd_pos;
	i64 zip64_eocd_pos;
	i64 zip64_eocd_segnum;
	i64 offset_correction;
	int used_offset_correction;
	u8 is_zip64;
	u8 is_resof;
	u8 seg_id_mismatch_warned;
	u8 opt_mml_bug_flag; // "implodebug" opt has been checked for.
	u8 mml_bug_policy; // 0=no bug, 1=bug, 0xff=undetermined
	int using_scanmode;
	struct de_crcobj *crco;
};

typedef void (*extrafield_decoder_fn)(deark *c, lctx *d,
	struct extra_item_info_struct *eii);

// TODO? There are more fields that technically should use these Zip64
// formatting functions, though it's rarely an issue.

static char *format_int_with_zip64_override(lctx *d, i64 v, i64 specialval,
	char *tmpbuf, size_t tmpbuf_len)
{
	static const char *g_zip64_override_msg = "[overridden by Zip64]";

	if(d->is_zip64 && v==specialval) {
		de_strlcpy(tmpbuf, g_zip64_override_msg, tmpbuf_len);
	}
	else {
		de_snprintf(tmpbuf, tmpbuf_len, "%"I64_FMT, v);
	}
	return tmpbuf;
}

static char *format_u32_with_zip64_override(lctx *d, i64 v,
	char *tmpbuf, size_t tmpbuf_len)
{
	return format_int_with_zip64_override(d, v, 0xffffffffLL, tmpbuf, tmpbuf_len);
}

static char *format_u16_with_zip64_override(lctx *d, i64 v,
	char *tmpbuf, size_t tmpbuf_len)
{
	return format_int_with_zip64_override(d, v, 0xffff, tmpbuf, tmpbuf_len);
}

// (Timezone info and precision are ignored.)
static int timestamps_are_valid_and_equal(const struct de_timestamp *ts1,
	const struct de_timestamp *ts2)
{
	if(!ts1->is_valid || !ts2->is_valid) return 0;
	return (ts1->ts_FILETIME == ts2->ts_FILETIME);
}

static int looks_like_cdir_record(deark *c, dbuf *inf, i64 pos)
{
	u32 sig;
	UI cmpr_meth;

	sig = (u32)dbuf_getu32be(inf, pos);
	if(sig!=CODE_PK12) return 0;
	cmpr_meth = (UI)dbuf_getu16le(inf, pos+10);
	if(cmpr_meth>99) return 0;
	return 1;
}

static int is_matching_ldir_at(deark *c, lctx *d, struct member_data *md,
	i64 pos1)
{
	u32 sig1;
	u32 crc;

	if(pos1+ZIP_LDIR_FIXED_SIZE > c->infile->len) return 0;
	sig1 = (u32)de_getu32be(pos1);
	if(sig1!=CODE_PK34) return 0;

	// TODO: We should compare more fields, at least the filename.
	crc = (u32)de_getu32le(pos1+14);
	if(crc != md->central_dir_entry_data.crc_reported) {
		return 0;
	}
	return 1;
}

static void print_multisegment_note(deark *c, lctx *d)
{
	if(d->is_zip64) return;
	de_info(c, "Note: Try \"-mp -opt zip:combine\" to convert to a "
		"single-segment ZIP file.");
}

// ----------
// Generic "walk central dir" function.

struct zip_wcd_ctx;

typedef void (*zip_wcd_callback)(deark *c, struct zip_wcd_ctx *wcdctx);

struct zip_wcd_ctx {
	// Configuration:
	zip_wcd_callback cbfn;
	void *userdata;
	int userdata_seg_id;
	u8 report_errors;
	u8 multisegment_mode;
	u8 is_resof;
	dbuf *inf;
	i64 inf_startpos;
	i64 inf_endpos; // Normally, this can be inf->len
	i64 max_entries; // Total, not just this segment

	// Other:
	u8 stop_flag; // Callback fn can set, to stop processing w/o error
	u8 errflag; // Set internally or by callback
	u8 need_errmsg; // Set internally or by callback
	i64 num_entries_completed; // Total, not just this segment
	i64 endpos_of_last_completed_entry; // Pos in inf

	// Additional data passed to the callback fn:
	i64 entry_pos;
	i64 entry_size;
	i64 fn_len, extra_len, comment_len;
};

// Caller creates/destroys wcdctx.
// Create one wcdctx object per walk per central directory.
// But if the central directory is segmented, zip_wcd_run() may be called
// multiple times with the same wcdctx -- it will pick up where it left off.
static void zip_wcd_run(deark *c, struct zip_wcd_ctx *wcdctx)
{
	i64 pos;
	u32 expected_sig;
	u8 unexpected_eof_flag = 0;

	pos = wcdctx->inf_startpos;
	wcdctx->endpos_of_last_completed_entry = pos;
	expected_sig = wcdctx->is_resof?CODE_PK14:CODE_PK12;

	while(1) {
		u32 sig;
		i64 len_avail;

		if(wcdctx->stop_flag || wcdctx->errflag) goto done;
		if(wcdctx->num_entries_completed >= wcdctx->max_entries) goto done;

		wcdctx->entry_pos = pos;
		len_avail = wcdctx->inf_endpos - wcdctx->entry_pos;
		if(len_avail < ZIP_CDIR_FIXED_SIZE) {
			// Not enough space even for the invariant part of the entry
			if(!wcdctx->multisegment_mode) {
				wcdctx->errflag = 1;
				wcdctx->need_errmsg = 1;
				unexpected_eof_flag = 1;
			}
			goto done;
		}
		sig=(u32)dbuf_getu32be(wcdctx->inf, pos);
		if(sig==0 && wcdctx->multisegment_mode) {
			// I haven't seen this, but I think it makes sense to tolerate
			// zero-padding.
			goto done;
		}
		if(sig!=expected_sig) {
			wcdctx->errflag = 1;
			if(wcdctx->report_errors) {
				de_err(c, "Central dir file header not found at %"I64_FMT,
					wcdctx->entry_pos);
			}
			else {
				wcdctx->need_errmsg = 1;
			}
			goto done;
		}
		wcdctx->fn_len = dbuf_getu16le(wcdctx->inf, pos+28);
		wcdctx->extra_len = dbuf_getu16le(wcdctx->inf, pos+30);
		wcdctx->comment_len = dbuf_getu16le(wcdctx->inf, pos+32);
		wcdctx->entry_size = 46 + wcdctx->fn_len + wcdctx->extra_len +
			wcdctx->comment_len;
		if(wcdctx->entry_size > len_avail) {
			if(!wcdctx->multisegment_mode) {
				wcdctx->errflag = 1;
				wcdctx->need_errmsg = 1;
				unexpected_eof_flag = 1;
			}
			goto done;
		}
		if(wcdctx->cbfn) {
			wcdctx->cbfn(c, wcdctx);
			// If callback set stop_flag, we assume it did *not* process
			// this item.
			if(wcdctx->stop_flag || wcdctx->errflag) goto done;
		}

		pos += wcdctx->entry_size;
		wcdctx->num_entries_completed++;
		wcdctx->endpos_of_last_completed_entry = pos;
	}

done:
	if(unexpected_eof_flag && wcdctx->report_errors) {
		de_err(c, "Central dir file header exceeds its bounds");
		wcdctx->need_errmsg = 0;
	}
	wcdctx->entry_pos = 0;
	wcdctx->entry_size = 0;
}

// ----------

static int is_compression_method_supported(lctx *d, const struct cmpr_meth_info *cmi)
{
	if(cmi && cmi->decompressor) return 1;
	return 0;
}

static void do_decompress_shrink(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_zip_shrink(c, dcmpri, dcmpro, dres, NULL);
}

static void do_decompress_reduce(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_zipreduce_params params;

	de_zeromem(&params, sizeof(struct de_zipreduce_params));
	params.cmpr_factor = (UI)(cparams->cmpr_meth-1);
	fmtutil_decompress_zip_reduce(c, dcmpri, dcmpro, dres, &params);
}

static int could_have_mml_bug(UI bit_flags)
{
	return ((bit_flags & 0x6)==2 ||
		(bit_flags & 0x6)==4);
}

static void do_decompress_implode(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_zipimplode_params params;

	de_zeromem(&params, sizeof(struct de_zipimplode_params));
	params.bit_flags = cparams->bit_flags;
	params.mml_bug = cparams->implode_mml_bug;
	fmtutil_decompress_zip_implode(c, dcmpri, dcmpro, dres, &params);
}

static void do_decompress_deflate(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_deflate_params inflparams;

	de_zeromem(&inflparams, sizeof(struct de_deflate_params));
	if(cparams->cmpr_meth==9) {
		inflparams.flags |= DE_DEFLATEFLAG_DEFLATE64;
	};
	fmtutil_decompress_deflate_ex(c, dcmpri, dcmpro, dres, &inflparams);
}

static void do_decompress_dclimplode(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_dclimplode_codectype1(c, dcmpri, dcmpro, dres, NULL);
}

static void do_decompress_stored(deark *c, lctx *d, struct compression_params *cparams,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0, 0x00, "stored", do_decompress_stored },
	{ 1, 0x00, "shrink", do_decompress_shrink },
	{ 2, 0x00, "reduce, CF=1", do_decompress_reduce },
	{ 3, 0x00, "reduce, CF=2", do_decompress_reduce },
	{ 4, 0x00, "reduce, CF=3", do_decompress_reduce },
	{ 5, 0x00, "reduce, CF=4", do_decompress_reduce },
	{ 6, 0x00, "implode", do_decompress_implode },
	{ 8, 0x00, "deflate", do_decompress_deflate },
	{ 9, 0x00, "deflate64", do_decompress_deflate },
	{ 10, 0x00, "PKWARE DCL implode", do_decompress_dclimplode },
	{ 12, 0x00, "bzip2", NULL },
	{ 14, 0x00, "LZMA", NULL },
	{ 16, 0x00, "IBM z/OS CMPSC", NULL },
	{ 18, 0x00, "IBM TERSE (new)", NULL },
	{ 19, 0x00, "IBM LZ77 z Architecture", NULL },
	{ 93, 0x00, "Zstandard", NULL },
	{ 94, 0x00, "MP3", NULL },
	{ 95, 0x00, "XZ", NULL },
	{ 96, 0x00, "JPEG", NULL },
	{ 97, 0x00, "WavPack", NULL },
	{ 98, 0x00, "PPMd", NULL },
	{ 99, 0x00, "AES", NULL }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(int cmpr_meth)
{
	size_t k;

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_info_arr); k++) {
		if(cmpr_meth_info_arr[k].cmpr_meth == cmpr_meth) {
			return &cmpr_meth_info_arr[k];
		}
	}
	return NULL;
}

// Decompress some data, using the given ZIP compression method.
// On failure, dres->errcode will be set.
static void do_decompress_lowlevel(deark *c, lctx *d, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct compression_params *cparams, const struct cmpr_meth_info *cmi)
{
	if(cmi && cmi->decompressor) {
		cmi->decompressor(c, d, cparams, dcmpri, dcmpro, dres);
		dbuf_flush(dcmpro->f);
	}
	else {
		de_internal_err_nonfatal(c, "Unsupported compression method (%d)",
			cparams->cmpr_meth);
		de_dfilter_set_generic_error(c, dres, NULL);
	}
}

// Returns 1 if decompression was apparently successful.
// (This function could easily be generalized, if we ever need it for
// compression methods other than implode.)
static int implode_dry_run(deark *c, lctx *d, struct member_data *md,
	struct compression_params *cparams, struct de_dfilter_in_params *dcmpri)
{
	dbuf *outf = NULL;
	struct de_crcobj *crco = NULL;
	u32 crc_calc;
	int old_debug_level;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int retval = 0;

	// Make a "dummy" dbuf to write to, which doesn't store the data, but
	// tracks the size and CRC.
	outf = dbuf_create_custom_dbuf(c, 0, 0);
	dbuf_enable_wbuffer(outf);
	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	dbuf_set_writelistener(outf, de_writelistener_for_crc, crco);

	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->local_dir_entry_data.uncmpr_size;

	old_debug_level = c->debug_level;
	c->debug_level = 0; // hack
	do_decompress_implode(c, d, cparams, dcmpri, &dcmpro, &dres);
	c->debug_level = old_debug_level;
	dbuf_flush(outf);

	if(dres.errcode) goto done;
	if(outf->len != md->local_dir_entry_data.uncmpr_size) goto done;
	crc_calc = de_crcobj_getval(crco);
	if(crc_calc != md->crc_reported) goto done;
	retval = 1;

done:
	dbuf_close(outf);
	de_crcobj_destroy(crco);
	return retval;
}

// May modify d->mml_bug_policy
static void detect_implode_mml_bug(deark *c, lctx *d, struct member_data *md,
	struct compression_params *cparams1, struct de_dfilter_in_params *dcmpri)
{
	int ret_withbug, ret_withoutbug;
	struct compression_params cparams2;

	if(d->mml_bug_policy!=0xff) goto done;

	de_dbg(c, "[checking for MML bug]");
	d->mml_bug_policy = 0; // default
	cparams2 = *cparams1; // struct copy

	cparams2.implode_mml_bug = 1;
	ret_withbug = implode_dry_run(c, d, md, &cparams2, dcmpri);
	if(!ret_withbug) {
		// Decompressing with the bug failed; assume file is ok.
		goto done;
	}

	cparams2.implode_mml_bug = 0;
	ret_withoutbug = implode_dry_run(c, d, md, &cparams2, dcmpri);

	if(ret_withoutbug) {
		// Compressing succeeded both ways(!). Assume there's no bug.
		goto done;
	}

	// With-bug succeeded, without-bug failed -> file is buggy.
	d->mml_bug_policy = 1;

done:
	if(d->mml_bug_policy!=0xff) {
		de_dbg(c, "MML bug detection: %u", d->mml_bug_policy);
	}
}

// Decompress a Zip member file, writing to outf.
// Does CRC calculation.
// Reports errors to the user.
// Only call this if the compression method is supported -- Call
//   is_compression_method_supported() first.
// Assumes ldd->cmi has been set, by calling get_cmpr_meth_info().
static int do_decompress_member(deark *c, lctx *d, struct member_data *md, dbuf *outf)
{
	struct dir_entry_data *ldd = &md->local_dir_entry_data;
	struct compression_params cparams;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	u32 crc_calculated;
	int retval = 0;

	de_zeromem(&cparams, sizeof(struct compression_params));
	cparams.cmpr_meth = ldd->cmpr_meth;
	cparams.bit_flags = ldd->bit_flags;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->file_data_pos;
	dcmpri.len = md->cmpr_size;

	if(ldd->cmpr_meth==6 && could_have_mml_bug(ldd->bit_flags)) {
		// Very few files have the "MML bug". I only know of PKZ101.EXE.
		if(!d->opt_mml_bug_flag) {
			d->mml_bug_policy = (u8)de_get_ext_option_bool(c, "zip:implodebug", 0xff);
			d->opt_mml_bug_flag = 1;
		}

		if(d->mml_bug_policy==0xff) {
			detect_implode_mml_bug(c, d, md, &cparams, &dcmpri);
		}

		if(d->mml_bug_policy==1) {
			cparams.implode_mml_bug = 1;
		}
	}

	dcmpro.f = outf;
	dcmpro.expected_len = md->uncmpr_size;
	dcmpro.len_known = 1;

	dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)d->crco);
	de_crcobj_reset(d->crco);

	do_decompress_lowlevel(c, d, &dcmpri, &dcmpro, &dres, &cparams,
		ldd->cmi);

	if(dres.errcode) {
		de_err(c, "%s: %s", ucstring_getpsz_d(ldd->fname),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	crc_calculated = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%08x", (UI)crc_calculated);

	if(crc_calculated != md->crc_reported) {
		de_err(c, "%s: CRC check failed: Expected 0x%08x, got 0x%08x",
			ucstring_getpsz_d(ldd->fname),
			(UI)md->crc_reported, (UI)crc_calculated);
		if(dres.bytes_consumed_valid && (dres.bytes_consumed < dcmpri.len)) {
			de_info(c, "Note: Only used %"I64_FMT" of %"I64_FMT" compressed bytes.",
				dres.bytes_consumed, dcmpri.len);
		}
		goto done;
	}

	retval = 1;
done:
	return retval;
}

// A variation of do_decompress_member() -
// works for Finder attribute data, and OS/2 extended attributes.
// Only call this if the compression method is supported -- Call
//   is_compression_method_supported() first.
// outf is assumed to be a membuf.
// dcflags: 0x1 = Validate the crc_reported param.
static int do_decompress_attrib_data(deark *c, lctx *d,
	i64 dpos, i64 dlen, dbuf *outf, i64 uncmprsize, u32 crc_reported,
	int cmpr_meth, const struct cmpr_meth_info *cmi, UI flags, const char *name)
{
	struct compression_params cparams;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	u32 crc_calculated;
	int retval = 0;

	de_zeromem(&cparams, sizeof(struct compression_params));
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = dpos;
	dcmpri.len = dlen;
	dcmpro.f = outf;
	dcmpro.expected_len = uncmprsize;
	dcmpro.len_known = 1;

	cparams.cmpr_meth = cmpr_meth;

	do_decompress_lowlevel(c, d, &dcmpri, &dcmpro, &dres, &cparams, cmi);
	if(dres.errcode) {
		goto done; // Could report the error, but this isn't critical data
	}

	if(flags & 0x1) {
		de_crcobj_reset(d->crco);
		de_crcobj_addslice(d->crco, outf, 0, outf->len);
		crc_calculated = de_crcobj_getval(d->crco);
		de_dbg(c, "%s crc (calculated): 0x%08x", name, (UI)crc_calculated);
		if(crc_calculated != crc_reported) goto done;
	}

	retval = 1;
done:
	return retval;
}

// As we read a member file's attributes, we may encounter multiple timestamps,
// which can differ in their precision, and whether they use UTC.
// This function is called to remember the "best" file modification time
// encountered so far.
static void apply_timestamp(deark *c, lctx *d, struct member_data *md, int tstype,
	const struct de_timestamp *ts, int quality)
{
	if(!ts->is_valid) return;

	// In case of a tie, we prefer the later timestamp that we encountered.
	// This makes local headers have priority over central headers, for
	// example.
	if(quality >= md->tsdata[tstype].quality) {
		md->tsdata[tstype].ts = *ts;
		md->tsdata[tstype].quality = quality;
	}
}

static void do_read_filename(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	i64 pos, i64 len, int utf8_flag)
{
	de_encoding from_encoding;

	ucstring_empty(dd->fname);
	from_encoding = utf8_flag ? DE_ENCODING_UTF8 : d->default_enc_for_filenames;
	dbuf_read_to_ucstring(c->infile, pos, len, dd->fname, 0, from_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(dd->fname));
}

static void do_comment_display(deark *c, lctx *d, i64 pos, i64 len, de_ext_encoding ee,
	const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s, 0, ee);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment_extract(deark *c, lctx *d, i64 pos, i64 len, de_ext_encoding ee,
	const char *ext)
{
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_copy_slice_convert_to_utf8(c->infile, pos, len, ee, f, 0x2|0x4);
	dbuf_close(f);
}

static void do_comment(deark *c, lctx *d, i64 pos, i64 len, int utf8_flag,
	const char *name, const char *ext)
{
	de_ext_encoding ee;

	if(len<1) return;
	ee = utf8_flag ? DE_ENCODING_UTF8 : d->default_enc_for_comments;
	ee = DE_EXTENC_MAKE(ee, DE_ENCSUBTYPE_HYBRID);
	if(c->extract_level>=2) {
		do_comment_extract(c, d, pos, len, ee, ext);
	}
	else {
		do_comment_display(c, d, pos, len, ee, name);
	}
}

static void read_unix_timestamp(deark *c, lctx *d, i64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	i64 t;
	char timestamp_buf[64];

	t = de_geti32le(pos);
	de_unix_time_to_timestamp(t, timestamp, 0x1);
	de_dbg_timestamp_to_string(c, timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t, timestamp_buf);
}

static void read_FILETIME(deark *c, lctx *d, i64 pos,
	struct de_timestamp *timestamp, const char *name)
{
	i64 t_FILETIME;
	char timestamp_buf[64];

	t_FILETIME = de_geti64le(pos);
	de_FILETIME_to_timestamp(t_FILETIME, timestamp, 0x1);
	de_dbg_timestamp_to_string(c, timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void ef_zip64extinfo(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 n;
	i64 pos = eii->dpos;
	u8 has_uncmpr_size = 0;
	u8 has_cmpr_size = 0;
	u8 has_ldir_offset = 0;
	u8 has_segment_num = 0;

	// IMO, the documentation isn't very clear about when a field is present,
	// and when it isn't. This is my best guess. It shouldn't really matter,
	// provided the encoder was sane.
	if(!eii->is_central || eii->dd->uncmpr_size==0xffffffffLL) {
		has_uncmpr_size = 1;
	}
	if(!eii->is_central || eii->dd->cmpr_size==0xffffffffLL) {
		has_cmpr_size = 1;
	}
	if(eii->is_central && eii->md->offset_of_local_header==0xffffffffLL) {
		has_ldir_offset = 1;
	}
	if(eii->is_central && eii->md->seg_number_start==0xffff) {
		has_segment_num = 1;
	}

	if(has_uncmpr_size) {
		if(pos+8 > eii->dpos+eii->dlen) goto done;
		n = de_geti64le(pos); pos += 8;
		de_dbg(c, "orig uncmpr file size: %"I64_FMT, n);
		if(eii->dd->uncmpr_size==0xffffffffLL) {
			de_sanitize_length(&n);
			eii->dd->uncmpr_size = n;
		}
	}

	if(has_cmpr_size) {
		if(pos+8 > eii->dpos+eii->dlen) goto done;
		n = de_geti64le(pos); pos += 8;
		de_dbg(c, "cmpr data size: %"I64_FMT, n);
		if(eii->dd->cmpr_size==0xffffffffLL) {
			de_sanitize_length(&n);
			eii->dd->cmpr_size = n;
		}
	}

	if(has_ldir_offset) {
		if(pos+8 > eii->dpos+eii->dlen) goto done;
		n = de_geti64le(pos); pos += 8;
		de_dbg(c, "offset of local header: %"I64_FMT, n);
		de_sanitize_offset(&n);
		eii->md->offset_of_local_header = n;
	}

	if(has_segment_num) {
		if(pos+4 > eii->dpos+eii->dlen) goto done;
		n = de_getu32le_p(&pos);
		de_dbg(c, "segment start number: %"I64_FMT, n);
		eii->md->seg_number_start = n;
	}

done:
	;
}

// Extra field 0x5455
static void ef_extended_timestamp(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	u8 flags;
	i64 endpos;
	int has_mtime, has_atime, has_ctime;
	struct de_timestamp timestamp_tmp;

	endpos = pos + eii->dlen;
	if(pos+1>endpos) return;
	flags = de_getbyte_p(&pos);
	de_dbg2(c, "flags: 0x%02x", (UI)flags);
	if(eii->is_central) {
		has_mtime = (eii->dlen>=5);
		has_atime = 0;
		has_ctime = 0;
	}
	else {
		eii->md->has_extts = 1;
		has_mtime = (flags & 0x01)?1:0;
		has_atime = (flags & 0x02)?1:0;
		has_ctime = (flags & 0x04)?1:0;
	}
	if(has_mtime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "mtime");
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_MODIFY, &timestamp_tmp, 50);
		pos+=4;
	}
	if(has_atime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "atime");
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_ACCESS, &timestamp_tmp, 50);
		eii->md->has_extts_atime = 1;
		pos+=4;
	}
	if(has_ctime) {
		if(pos+4>endpos) return;
		read_unix_timestamp(c, d, pos, &timestamp_tmp, "creation time");
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_CREATE, &timestamp_tmp, 50);
		eii->md->has_extts_crtime = 1;
		pos+=4;
	}
}

static void dbg_zip_uid_gid_num(deark *c, i64 uidnum, i64 gidnum)
{
	de_dbg(c, "uid: %d", (int)uidnum);
	de_dbg(c, "gid: %d", (int)gidnum);
}

// Extra field 0x5855
static void ef_infozip1(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 uidnum, gidnum;
	struct de_timestamp timestamp_tmp;

	if(eii->dlen<8) return;
	read_unix_timestamp(c, d, eii->dpos, &timestamp_tmp, "atime");
	apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_ACCESS, &timestamp_tmp, 45);
	read_unix_timestamp(c, d, eii->dpos+4, &timestamp_tmp, "mtime");
	apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_MODIFY, &timestamp_tmp, 45);
	if(!eii->is_central && eii->dlen>=12) {
		uidnum = de_getu16le(eii->dpos+8);
		gidnum = de_getu16le(eii->dpos+10);
		dbg_zip_uid_gid_num(c, uidnum, gidnum);
	}
}

// Extra field 0x7075 - Info-ZIP Unicode Path
static void ef_unicodepath(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	u8 ver;
	de_ucstring *fn = NULL;
	i64 fnlen;
	u32 crc_reported, crc_calculated;

	if(eii->dlen<1) goto done;
	ver = de_getbyte(eii->dpos);
	de_dbg(c, "version: %u", (UI)ver);
	if(ver!=1) goto done;
	if(eii->dlen<6) goto done;
	crc_reported = (u32)de_getu32le(eii->dpos+1);
	de_dbg(c, "name-crc (reported): 0x%08x", (UI)crc_reported);
	fn = ucstring_create(c);
	fnlen = eii->dlen - 5;
	dbuf_read_to_ucstring(c->infile, eii->dpos+5, fnlen, fn, 0, DE_ENCODING_UTF8);
	de_dbg(c, "unicode name: \"%s\"", ucstring_getpsz_d(fn));

	// Need to go back and calculate a CRC of the main filename. This is
	// protection against the case where a ZIP editor may have changed the
	// original filename, but retained a now-orphaned Unicode Path field.
	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, eii->dd->main_fname_pos, eii->dd->main_fname_len);
	crc_calculated = de_crcobj_getval(d->crco);
	de_dbg(c, "name-crc (calculated): 0x%08x", (UI)crc_calculated);

	if(crc_calculated == crc_reported) {
		ucstring_empty(eii->dd->fname);
		ucstring_append_ucstring(eii->dd->fname, fn);
	}

done:
	ucstring_destroy(fn);
}

// Extra field 0x7855
static void ef_infozip2(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 uidnum, gidnum;

	if(eii->is_central) return;
	if(eii->dlen<4) return;
	uidnum = de_getu16le(eii->dpos);
	gidnum = de_getu16le(eii->dpos+2);
	dbg_zip_uid_gid_num(c, uidnum, gidnum);
}

// Extra field 0x7875
static void ef_infozip3(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 uidnum, gidnum;
	u8 ver;
	i64 endpos;
	i64 sz;

	endpos = pos+eii->dlen;

	if(pos+1>endpos) return;
	ver = de_getbyte_p(&pos);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=1) return;

	if(pos+1>endpos) return;
	sz = (i64)de_getbyte_p(&pos);
	if(pos+sz>endpos) return;
	uidnum = dbuf_getint_ext(c->infile, pos, (UI)sz, 1, 0);
	pos += sz;

	if(pos+1>endpos) return;
	sz = (i64)de_getbyte_p(&pos);
	if(pos+sz>endpos) return;
	gidnum = dbuf_getint_ext(c->infile, pos, (UI)sz, 1, 0);
	pos += sz;

	dbg_zip_uid_gid_num(c, uidnum, gidnum);
}

// Extra field 0x000a
static void ef_ntfs(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 endpos;
	i64 attr_tag;
	i64 attr_size;
	const char *name;
	struct de_timestamp timestamp_tmp_m;
	struct de_timestamp timestamp_tmp;

	endpos = pos+eii->dlen;
	pos += 4; // skip reserved field

	while(1) {
		if(pos+4>endpos) break;
		attr_tag = de_getu16le_p(&pos);
		attr_size = de_getu16le_p(&pos);
		if(attr_tag==0x0001) name="NTFS filetimes";
		else name="?";
		de_dbg(c, "tag: 0x%04x (%s), dlen: %d", (UI)attr_tag, name,
			(int)attr_size);
		if(pos+attr_size>endpos) break;

		de_dbg_indent(c, 1);
		if(attr_tag==0x0001 && attr_size>=24) {
			read_FILETIME(c, d, pos, &timestamp_tmp_m, "mtime");
			apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_MODIFY, &timestamp_tmp_m, 90);

			read_FILETIME(c, d, pos+8, &timestamp_tmp, "atime");
			apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_ACCESS, &timestamp_tmp, 90);
			if(timestamps_are_valid_and_equal(&timestamp_tmp, &timestamp_tmp_m)) {
				eii->md->questionable_atime = 1;
			}

			read_FILETIME(c, d, pos+16, &timestamp_tmp, "creation time");
			apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_CREATE, &timestamp_tmp, 90);
			if(timestamps_are_valid_and_equal(&timestamp_tmp, &timestamp_tmp_m)) {
				eii->md->questionable_crtime = 1;
			}
		}
		de_dbg_indent(c, -1);

		pos += attr_size;
	}
}

// Extra field 0x0009
static void ef_os2(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 endpos;
	i64 ulen;
	i64 cmpr_attr_size;
	int cmpr_meth;
	u32 crc_reported;
	const struct cmpr_meth_info *cmi = NULL;
	const char *name = "OS/2 ext. attr. data";
	dbuf *attr_data = NULL;
	de_module_params *mparams = NULL;
	int ret;

	endpos = pos+eii->dlen;
	if(pos+4>endpos) goto done;
	ulen = de_getu32le_p(&pos);
	de_dbg(c, "uncmpr ext attr data size: %"I64_FMT, ulen);
	if(eii->is_central) goto done;

	if(pos+2>endpos) goto done;
	cmpr_meth = (int)de_getu16le_p(&pos);
	de_dbg(c, "ext attr cmpr method: %d", cmpr_meth);

	if(pos+4>endpos) goto done;
	crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "ext attr crc (reported): 0x%08x", (UI)crc_reported);

	cmpr_attr_size = endpos-pos;
	de_dbg(c, "cmpr ext attr data at %"I64_FMT", len=%"I64_FMT, pos, cmpr_attr_size);
	if(pos + cmpr_attr_size > endpos) goto done;

	cmi = get_cmpr_meth_info(cmpr_meth);
	if(cmpr_meth==6 || !is_compression_method_supported(d, cmi)) {
		de_warn(c, "%s: Unsupported compression method: %d (%s)",
			name, cmpr_meth, (cmi ? cmi->name : "?"));
		goto done;
	}

	attr_data = dbuf_create_membuf(c, ulen, 0x1);
	ret = do_decompress_attrib_data(c, d, pos, cmpr_attr_size,
		attr_data, ulen, crc_reported, cmpr_meth, cmi, 0x1, name);
	if(!ret) {
		de_warn(c, "Failed to decompress %s", name);
		goto done;
	}

	// attr_data contains an OS/2 extended attribute structure (FEA2LIST)
	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "L";
	if(ucstring_isnonempty(eii->dd->fname)) {
		mparams->in_params.str1 = eii->dd->fname;
		mparams->in_params.flags |= 0x8;
	}
	de_dbg(c, "decoding OS/2 ext. attribs., unc. len=%"I64_FMT, attr_data->len);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "ea_data", mparams, attr_data, 0, attr_data->len);
	de_dbg_indent(c, -1);

done:
	dbuf_close(attr_data);
	de_free(c, mparams);
}

// Extra field 0x2705 (ZipIt Macintosh 1.3.5+)
static void ef_zipitmac_2705(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	struct de_fourcc sig;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	if(eii->dlen<4) goto done;
	dbuf_read_fourcc(c->infile, eii->dpos, &sig, 4, 0x0);
	de_dbg(c, "signature: '%s'", sig.id_dbgstr);
	if(sig.id!=0x5a504954U) goto done; // expecting 'ZPIT'
	if(eii->dlen<12) goto done;
	dbuf_read_fourcc(c->infile, eii->dpos+4, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	dbuf_read_fourcc(c->infile, eii->dpos+8, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);

done:
	;
}

// The time will be returned in the caller-supplied 'ts'
static void handle_mac_time(deark *c, lctx *d,
	i64 mt_raw, i64 mt_offset,
	struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];
	de_mac_time_to_timestamp(mt_raw - mt_offset, ts);
	ts->tzcode = DE_TZCODE_UTC;
	de_dbg_timestamp_to_string(c, ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" %+"I64_FMT" (%s)", name,
		mt_raw, -mt_offset, timestamp_buf);
}

// Extra field 0x334d (Info-ZIP Macintosh)
static void ef_infozipmac(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	i64 dpos;
	i64 ulen;
	i64 cmpr_attr_size;
	UI flags;
	int cmpr_meth;
	const struct cmpr_meth_info *cmi = NULL;
	struct de_fourcc filetype;
	struct de_fourcc creator;
	de_ucstring *flags_str = NULL;
	dbuf *attr_data = NULL;
	int ret;
	i64 create_time_raw;
	i64 create_time_offset;
	i64 mod_time_raw;
	i64 mod_time_offset;
	i64 backup_time_raw;
	i64 backup_time_offset;
	struct de_timestamp tmp_timestamp;
	int charset;
	u32 crc_reported = 0;
	UI dcflags = 0;
	struct de_stringreaderdata *srd;

	if(eii->dlen<14) goto done;

	ulen = de_getu32le_p(&pos);
	de_dbg(c, "uncmpr. finder attr. size: %d", (int)ulen);

	flags = (UI)de_getu16le_p(&pos);
	flags_str = ucstring_create(c);
	if(flags&0x0001) ucstring_append_flags_item(flags_str, "data_fork");
	if(flags&0x0002) ucstring_append_flags_item(flags_str, "0x0002"); // something about the filename
	ucstring_append_flags_item(flags_str,
		(flags&0x0004)?"uncmpressed_attribute_data":"compressed_attribute_data");
	if(flags&0x0008) ucstring_append_flags_item(flags_str, "64-bit_times");
	if(flags&0x0010) ucstring_append_flags_item(flags_str, "no_timezone_offsets");
	de_dbg(c, "flags: 0x%04x (%s)", flags, ucstring_getpsz(flags_str));

	dbuf_read_fourcc(c->infile, pos, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);
	pos += 4;

	if(eii->is_central) goto done;

	if(flags&0x0004) { // Uncompressed attribute data
		cmpr_meth = 0;
	}
	else {
		dcflags |= 0x1; // CRC is known
		cmpr_meth = (int)de_getu16le_p(&pos);
		cmi = get_cmpr_meth_info(cmpr_meth);
		de_dbg(c, "finder attr. cmpr. method: %d (%s)", cmpr_meth, (cmi ? cmi->name : "?"));

		crc_reported = (u32)de_getu32le_p(&pos);
		de_dbg(c, "finder attr. data crc (reported): 0x%08x", (UI)crc_reported);
	}

	// The rest of the data is Finder attribute data
	cmpr_attr_size = eii->dpos+eii->dlen - pos;
	de_dbg(c, "cmpr. finder attr. size: %d", (int)cmpr_attr_size);
	if(ulen<1 || ulen>1000000) goto done;

	// Type 6 (implode) compression won't work here, because it needs
	// additional parameters seemingly not provided by the Finder attr data.
	if(cmpr_meth==6 || !is_compression_method_supported(d, cmi)) {
		de_warn(c, "Finder attribute data: Unsupported compression method: %d (%s)",
			cmpr_meth, (cmi ? cmi->name : "?"));
		goto done;
	}

	// Decompress and decode the Finder attribute data
	attr_data = dbuf_create_membuf(c, ulen, 0x1);
	ret = do_decompress_attrib_data(c, d, pos, cmpr_attr_size,
		attr_data, ulen, crc_reported, cmpr_meth, cmi, dcflags, "finder attr. data");
	if(!ret) {
		de_warn(c, "Failed to decompress finder attribute data");
		goto done;
	}

	dpos = 0;
	dpos += 2; // Finder flags
	dpos += 4; // Icon location
	dpos += 2; // Folder
	dpos += 16; // FXInfo
	dpos += 1; // file version number
	dpos += 1; // dir access rights

	if(flags&0x0008) goto done; // We don't support 64-bit times
	if(flags&0x0010) goto done; // We want timezone offsets
	if(attr_data->len - dpos < 6*4) goto done;

	create_time_raw = dbuf_getu32le_p(attr_data, &dpos);
	mod_time_raw    = dbuf_getu32le_p(attr_data, &dpos);
	backup_time_raw = dbuf_getu32le_p(attr_data, &dpos);
	create_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;
	mod_time_offset    = dbuf_geti32le(attr_data, dpos); dpos += 4;
	backup_time_offset = dbuf_geti32le(attr_data, dpos); dpos += 4;

	handle_mac_time(c, d, create_time_raw, create_time_offset, &tmp_timestamp, "create time");
	if(create_time_raw>0) {
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_CREATE, &tmp_timestamp, 40);
	}
	handle_mac_time(c, d, mod_time_raw,    mod_time_offset,    &tmp_timestamp, "mod time   ");
	if(mod_time_raw>0) {
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_MODIFY, &tmp_timestamp, 40);
	}
	handle_mac_time(c, d, backup_time_raw, backup_time_offset, &tmp_timestamp, "backup time");
	if(backup_time_raw>0) {
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_BACKUP, &tmp_timestamp, 40);
	}

	// Expecting 2 bytes for charset, and at least 2 more for the 2 NUL-terminated
	// strings that follow.
	if(attr_data->len - dpos < 4) goto done;

	charset = (int)dbuf_getu16le_p(attr_data, &dpos);
	de_dbg(c, "charset for fullpath/comment: %d", charset);

	// TODO: Can we use the correct encoding?
	srd = dbuf_read_string(attr_data, dpos, attr_data->len-dpos, DE_DBG_MAX_STRLEN,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "fullpath: \"%s\"", ucstring_getpsz(srd->str));
	dpos += srd->bytes_consumed;
	de_destroy_stringreaderdata(c, srd);

	srd = dbuf_read_string(attr_data, dpos, attr_data->len-dpos, DE_DBG_MAX_STRLEN,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz(srd->str));
	dpos += srd->bytes_consumed;
	de_destroy_stringreaderdata(c, srd);

done:
	ucstring_destroy(flags_str);
	dbuf_close(attr_data);
}

// Acorn / SparkFS / RISC OS
static void ef_acorn(deark *c, lctx *d, struct extra_item_info_struct *eii)
{
	i64 pos = eii->dpos;
	struct de_riscos_file_attrs rfa;

	if(eii->dlen<16) return;
	if(dbuf_memcmp(c->infile, eii->dpos, "ARC0", 4)) {
		de_dbg(c, "[unsupported Acorn extra-field type]");
		return;
	}
	pos += 4;

	de_zeromem(&rfa, sizeof(struct de_riscos_file_attrs));
	fmtutil_riscos_read_load_exec(c, c->infile, &rfa, pos);
	pos += 8;
	if(rfa.mod_time.is_valid) {
		apply_timestamp(c, d, eii->md, DE_TIMESTAMPIDX_MODIFY, &rfa.mod_time, 70);
	}

	fmtutil_riscos_read_attribs_field(c, c->infile, &rfa, pos, 0);

	if(!eii->is_central && !eii->md->has_riscos_data) {
		eii->md->has_riscos_data = 1;
		eii->md->rfa = rfa;
	}
}

struct extra_item_type_info_struct {
	u16 id;
	const char *name;
	extrafield_decoder_fn fn;
};
static const struct extra_item_type_info_struct extra_item_type_info_arr[] = {
	{ 0x0001 /*    */, "Zip64 extended information", ef_zip64extinfo },
	{ 0x0007 /*    */, "AV Info", NULL },
	{ 0x0008 /*    */, "extended language encoding data", NULL },
	{ 0x0009 /*    */, "OS/2", ef_os2 },
	{ 0x000a /*    */, "NTFS", ef_ntfs },
	{ 0x000c /*    */, "OpenVMS", NULL },
	{ 0x000d /*    */, "Unix", NULL },
	{ 0x000e /*    */, "file stream and fork descriptors", NULL },
	{ 0x000f /*    */, "Patch Descriptor", NULL },
	{ 0x0014 /*    */, "PKCS#7 Store for X.509 Certificates", NULL },
	{ 0x0015 /*    */, "X.509 Certificate ID and Signature for individual file", NULL },
	{ 0x0016 /*    */, "X.509 Certificate ID for Central Directory", NULL },
	{ 0x0017 /*    */, "Strong Encryption Header", NULL },
	{ 0x0018 /*    */, "Record Management Controls", NULL },
	{ 0x0019 /*    */, "PKCS#7 Encryption Recipient Certificate List", NULL },
	{ 0x0021 /*    */, "Policy Decryption Key", NULL },
	{ 0x0022 /*    */, "Smartcrypt Key Provider", NULL },
	{ 0x0023 /*    */, "Smartcrypt Policy Key Data", NULL },
	{ 0x0065 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes", NULL },
	{ 0x0066 /*    */, "IBM S/390 (Z390), AS/400 (I400) attributes - compressed", NULL },
	{ 0x07c8 /*    */, "Macintosh", NULL },
	{ 0x2605 /*    */, "ZipIt Macintosh", NULL },
	{ 0x2705 /*    */, "ZipIt Macintosh 1.3.5+", ef_zipitmac_2705 },
	{ 0x2805 /*    */, "ZipIt Macintosh 1.3.5+", NULL },
	{ 0x334d /* M3 */, "Info-ZIP Macintosh", ef_infozipmac },
	{ 0x4154 /* TA */, "Tandem NSK", NULL },
	{ 0x4341 /* AC */, "Acorn/SparkFS", ef_acorn },
	{ 0x4453 /* SE */, "Windows NT security descriptor (binary ACL)", NULL },
	{ 0x4690 /*    */, "POSZIP 4690", NULL },
	{ 0x4704 /*    */, "VM/CMS", NULL },
	{ 0x470f /*    */, "MVS", NULL },
	{ 0x4854 /* TH */, "Theos, old unofficial port", NULL }, // unzip:extrafld.txt says "inofficial"
	{ 0x4b46 /* FK */, "FWKCS MD5", NULL },
	{ 0x4c41 /* AL */, "OS/2 access control list (text ACL)", NULL },
	{ 0x4d49 /* IM */, "Info-ZIP OpenVMS", NULL },
	{ 0x4d63 /* cM */, "Macintosh SmartZIP", NULL },
	{ 0x4f4c /* LO */, "Xceed original location", NULL },
	{ 0x5350 /* PS */, "Psion?", NULL }, // observed in some Psion files
	{ 0x5356 /* VS */, "AOS/VS (ACL)", NULL },
	{ 0x5455 /* UT */, "extended timestamp", ef_extended_timestamp },
	{ 0x554e /* NU */, "Xceed unicode", NULL },
	{ 0x5855 /* UX */, "Info-ZIP Unix, first version", ef_infozip1 },
	{ 0x6375 /* uc */, "Info-ZIP Unicode Comment", NULL },
	{ 0x6542 /* Be */, "BeOS/BeBox", NULL },
	{ 0x6854 /* Th */, "Theos", NULL },
	{ 0x7075 /* up */, "Info-ZIP Unicode Path", ef_unicodepath },
	{ 0x7441 /* At */, "AtheOS", NULL },
	{ 0x756e /* nu */, "ASi Unix", NULL },
	{ 0x7855 /* Ux */, "Info-ZIP Unix, second version", ef_infozip2 },
	{ 0x7875 /* ux */, "Info-ZIP Unix, third version", ef_infozip3 },
	{ 0xa11e /*    */, "Data Stream Alignment", NULL },
	{ 0xa220 /*    */, "Microsoft Open Packaging Growth Hint", NULL },
	{ 0xfb4a /*    */, "SMS/QDOS", NULL }, // according to Info-ZIP zip 3.0
	{ 0xfd4a /*    */, "SMS/QDOS", NULL }  // according to ZIP v6.3.4 APPNOTE
};

static const struct extra_item_type_info_struct *get_extra_item_type_info(i64 id)
{
	static const struct extra_item_type_info_struct default_ei =
		{ 0, "?", NULL };
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(extra_item_type_info_arr); i++) {
		if(id == (i64)extra_item_type_info_arr[i].id) {
			return &extra_item_type_info_arr[i];
		}
	}
	return &default_ei;
}

static void do_extra_data(deark *c, lctx *d,
	struct member_data *md, struct dir_entry_data *dd,
	i64 pos1, i64 len, int is_central)
{
	i64 pos;

	de_dbg(c, "extra data at %"I64_FMT", len=%d", pos1, (int)len);
	de_dbg_indent(c, 1);

	pos = pos1;
	while(1) {
		struct extra_item_info_struct eii;

		if(pos+4 >= pos1+len) break;
		de_zeromem(&eii, sizeof(struct extra_item_info_struct));
		eii.md = md;
		eii.dd = dd;
		eii.is_central = is_central;
		eii.dpos = pos+4;

		eii.id = (u32)de_getu16le(pos);
		eii.dlen = de_getu16le(pos+2);

		eii.eiti = get_extra_item_type_info(eii.id);

		de_dbg(c, "item id=0x%04x (%s), dlen=%d", (UI)eii.id, eii.eiti->name,
			(int)eii.dlen);
		if(pos+4+eii.dlen > pos1+len) break;

		de_dbg_indent(c, 1);
		if(eii.eiti->fn) {
			eii.eiti->fn(c, d, &eii);
		}
		else if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, eii.dpos, eii.dlen, 256, NULL, 0x1);
		}
		de_dbg_indent(c, -1);

		pos += 4+eii.dlen;
	}

	de_dbg_indent(c, -1);
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	struct dir_entry_data *ldd = &md->local_dir_entry_data;
	struct dir_entry_data *cdd = &md->central_dir_entry_data;
	int tsidx;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, md->file_data_pos,
		md->cmpr_size);
	de_dbg_indent(c, 1);

	// Found an encrypted file where the encryption flag is only set in the
	// central dir.
	if((ldd->bit_flags & 0x1) || (cdd->bit_flags & 0x1)) {
		de_err(c, "%s: Encryption is not supported", ucstring_getpsz_d(ldd->fname));
		goto done;
	}

	if(!is_compression_method_supported(d, ldd->cmi)) {
		de_err(c, "%s: Unsupported compression method: %d (%s)",
			ucstring_getpsz_d(ldd->fname),
			ldd->cmpr_meth, (ldd->cmi ? ldd->cmi->name : "?"));
		goto done;
	}

	if(md->file_data_pos+md->cmpr_size > c->infile->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(ldd->fname));
		goto done;
	}

	if(md->is_symlink) {
		de_warn(c, "\"%s\" is a symbolic link. It will not be extracted as a link.",
			ucstring_getpsz_d(ldd->fname));
	}

	fi = de_finfo_create(c);
	fi->detect_root_dot_dir = 1;

	if(ucstring_isnonempty(ldd->fname)) {
		UI snflags = DE_SNFLAG_FULLPATH;

		if(md->has_riscos_data) {
			fmtutil_riscos_append_type_to_filename(c, fi, ldd->fname, &md->rfa, md->is_dir, 0);
		}
		if(md->is_dir) snflags |= DE_SNFLAG_STRIPTRAILINGSLASH;
		de_finfo_set_name_from_ucstring(c, fi, ldd->fname, snflags);
		fi->original_filename_flag = 1;
	}

	// This is basically a hack to better deal with Deark's ZIP writer's habit of
	// using the NTFS field to store high resolution timestamps. The problem is
	// that there seems to be no standard way to indicate the lack of a particular
	// timestamp.
	// We disregard the NTFS Access or Creation timestamp in some cases, to make it
	// more likely that a ZIP file can be round-tripped through Deark, without
	// spurious timestamps appearing in the 0x5455 (extended timestamp) field.
	if(md->questionable_atime && md->has_extts && !md->has_extts_atime) {
		md->tsdata[DE_TIMESTAMPIDX_ACCESS].ts.is_valid = 0;
	}
	if(md->questionable_crtime && md->has_extts && !md->has_extts_crtime) {
		md->tsdata[DE_TIMESTAMPIDX_CREATE].ts.is_valid = 0;
	}

	for(tsidx=0; tsidx<DE_TIMESTAMPIDX_COUNT; tsidx++) {
		if(md->tsdata[tsidx].ts.is_valid) {
			fi->timestamp[tsidx] = md->tsdata[tsidx].ts;
		}
	}

	if(md->has_riscos_data) {
		fi->has_riscos_data = 1;
		fi->riscos_attribs = md->rfa.attribs;
		fi->load_addr = md->rfa.load_addr;
		fi->exec_addr = md->rfa.exec_addr;
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}
	else if(md->is_volume_label) {
		fi->is_volume_label = 1;
	}
	else if(md->is_executable) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else if(md->is_nonexecutable) {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_enable_wbuffer(outf);
	if(md->is_dir) {
		goto done;
	}

	(void)do_decompress_member(c, d, md, outf);

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static const char *get_platform_name(UI ver_hi)
{
	static const char *pltf_names[20] = {
		"MS-DOS, etc.", "Amiga", "OpenVMS", "Unix",
		"VM/CMS", "Atari ST", "HPFS", "Macintosh",
		"Z-System", "CP/M", "NTFS or TOPS-20", "MVS or NTFS",
		"VSE or SMS/QDOS", "Acorn RISC OS", "VFAT", "MVS",
		"BeOS", "Tandem", "OS/400", "OS X" };

	if(ver_hi<20)
		return pltf_names[ver_hi];
	if(ver_hi==30) return "AtheOS/Syllable";
	return "?";
}

// Look at the attributes, and set some other fields based on them.
static void process_ext_attr(deark *c, lctx *d, struct member_data *md)
{
	if(d->using_scanmode) {
		// In this mode, there is no 'external attribs' field.
		return;
	}

	if(md->ver_made_by_hi==3) { // Unix
		UI unix_filetype;
		unix_filetype = (md->attr_e>>16)&0170000;
		if(unix_filetype == 0040000) {
			md->is_dir = 1;
		}
		else if(unix_filetype == 0120000) {
			md->is_symlink = 1;
		}

		if((md->attr_e>>16)&0111) {
			md->is_executable = 1;
		}
		else {
			md->is_nonexecutable = 1;
		}
	}

	// MS-DOS-style attributes.
	// Technically, we should only do this if
	// md->central_dir_entry_data.ver_made_by_hi==0.
	// However, most(?) zip programs set the low byte of the external attribs
	// to the equivalent MS-DOS attribs, at least in cases where it matters.
	if(md->attr_e & 0x10) {
		md->is_dir = 1;
	}
	else if(md->attr_e & 0x08) {
		// A volume label should have min-version-needed set to 1.1 or higher,
		// but we don't check that because even PKZIP (e.g. v2.04g) sets it
		// to 1.0.
		md->is_volume_label = 1;
	}

	// TODO: Support more platforms.
	// TODO: The 0x756e (ASi Unix) extra field might be important, as it contains
	// file permissions.

	if(md->is_dir && md->uncmpr_size!=0) {
		// I'd expect a subdirectory entry to have zero size. If it doesn't,
		// let's just assume we misidentified it as a subdirectory, and
		// extract its data.
		md->is_dir = 0;
	}

	if(md->is_volume_label && md->uncmpr_size!=0) {
		// Though we theoretically allow volume labels to have data, this is
		// probably a normal file that was misidentified.
		md->is_volume_label = 0;
	}
}

static void describe_internal_attr(deark *c, struct member_data *md,
	de_ucstring *s)
{
	UI bf = md->attr_i;

	if(bf & 0x0001) {
		ucstring_append_flags_item(s, "text file");
		bf -= 0x0001;
	}

	if(bf!=0) { // Report any unrecognized flags
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

// Uses dd->bit_flags, dd->cmpr_method
static void describe_general_purpose_bit_flags(deark *c, struct dir_entry_data *dd,
	de_ucstring *s)
{
	const char *name;
	UI bf = dd->bit_flags;

	if(bf & 0x0001) {
		ucstring_append_flags_item(s, "encrypted");
		bf -= 0x0001;
	}

	if(dd->cmpr_meth==6) { // implode
		if(bf & 0x0002) {
			name = "8K";
			bf -= 0x0002;
		}
		else {
			name = "4K";
		}
		ucstring_append_flags_itemf(s, "%s sliding dictionary", name);

		if(bf & 0x0004) {
			name = "3";
			bf -= 0x0004;
		}
		else {
			name = "2";
		}
		ucstring_append_flags_itemf(s, "%s trees", name);
	}

	if(dd->cmpr_meth==8 || dd->cmpr_meth==9) { // deflate flags
		UI code;

		code = (bf & 0x0006)>>1;
		switch(code) {
		case 1: name="max"; break;
		case 2: name="fast"; break;
		case 3: name="super_fast"; break;
		default: name="normal";
		}
		ucstring_append_flags_itemf(s, "cmprlevel=%s", name);
		bf -= (bf & 0x0006);
	}

	if(bf & 0x0008) {
		ucstring_append_flags_item(s, "uses data descriptor");
		bf -= 0x0008;
	}

	if(bf & 0x0800) {
		ucstring_append_flags_item(s, "UTF-8");
		bf -= 0x0800;
	}

	if(bf!=0) { // Report any unrecognized flags
		ucstring_append_flags_itemf(s, "0x%04x", bf);
	}
}

// Read either a central directory entry (a.k.a. central directory file header),
// or a local file header.
static int do_file_header(deark *c, lctx *d, struct member_data *md,
	int is_central, i64 pos1, i64 *p_entry_size)
{
	i64 pos;
	int utf8_flag;
	int retval = 0;
	i64 fixed_header_size;
	i64 mod_time_raw, mod_date_raw;
	struct dir_entry_data *dd; // Points to either md->central or md->local
	de_ucstring *descr = NULL;
	struct de_timestamp dos_timestamp;
	char tmpsz[64];

	pos = pos1;
	descr = ucstring_create(c);
	if(is_central) {
		dd = &md->central_dir_entry_data;
		fixed_header_size = 46;
		de_dbg(c, "central dir entry at %"I64_FMT, pos);
		if(!dd->have_read_sig_and_hdrsize) {
			goto done; // internal error
		}
	}
	else {
		dd = &md->local_dir_entry_data;
		fixed_header_size = 30;
		if((md->seg_number_start!=d->eocd.this_seg_num) && !d->using_scanmode) {
			int found_ldir;

			// We want to read an ldir, but it *shouldn't* be on this segment.
			// We'll check anyway.
			found_ldir = is_matching_ldir_at(c, d, md, pos1);
			if(!found_ldir) {
				de_err(c, "Member file not in this ZIP file");
				return 0;
			}
			if(!d->seg_id_mismatch_warned) {
				de_warn(c, "Segment ID mismatch (found file on segment %"I64_FMT" that "
					"should be on segment %"I64_FMT"). Trying to continue.",
					d->eocd.this_seg_num, md->seg_number_start);
				d->seg_id_mismatch_warned = 1;
			}
		}
		de_dbg(c, "local file header at %"I64_FMT, pos);
	}
	de_dbg_indent(c, 1);

	if(dd->have_read_sig_and_hdrsize) { // Currently always true for central dir entries
		pos += 4;
	}
	else {
		u32 sig;

		sig = (u32)de_getu32be_p(&pos);
		if(!is_central && sig!=(d->is_resof?CODE_PK36:CODE_PK34)) {
			de_err(c, "Local file header not found at %"I64_FMT, pos1);
			goto done;
		}
	}

	if(is_central) {
		md->ver_made_by = (UI)de_getu16le_p(&pos);
		md->ver_made_by_hi = (UI)((md->ver_made_by&0xff00)>>8);
		md->ver_made_by_lo = (UI)(md->ver_made_by&0x00ff);
		de_dbg(c, "version made by: platform=%u (%s), ZIP spec=%u.%u",
			md->ver_made_by_hi, get_platform_name(md->ver_made_by_hi),
			(UI)(md->ver_made_by_lo/10), (UI)(md->ver_made_by_lo%10));
	}

	dd->ver_needed = (UI)de_getu16le_p(&pos);
	dd->ver_needed_hi = (UI)((dd->ver_needed&0xff00)>>8);
	dd->ver_needed_lo = (UI)(dd->ver_needed&0x00ff);
	de_dbg(c, "version needed to extract: platform=%u (%s), ZIP spec=%u.%u",
		dd->ver_needed_hi, get_platform_name(dd->ver_needed_hi),
		(UI)(dd->ver_needed_lo/10), (UI)(dd->ver_needed_lo%10));

	dd->bit_flags = (UI)de_getu16le_p(&pos);
	dd->cmpr_meth = (int)de_getu16le_p(&pos);
	dd->cmi = get_cmpr_meth_info(dd->cmpr_meth);

	utf8_flag = (dd->bit_flags & 0x800)?1:0;
	ucstring_empty(descr);
	describe_general_purpose_bit_flags(c, dd, descr);
	de_dbg(c, "flags: 0x%04x (%s)", dd->bit_flags, ucstring_getpsz(descr));

	de_dbg(c, "cmpr method: %d (%s)", dd->cmpr_meth,
		(dd->cmi ? dd->cmi->name : "?"));

	mod_time_raw = de_getu16le_p(&pos);
	mod_date_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&dos_timestamp, mod_date_raw, mod_time_raw);
	dos_timestamp.tzcode = DE_TZCODE_LOCAL;
	de_dbg_timestamp_to_string(c, &dos_timestamp, tmpsz, sizeof(tmpsz), 0);
	de_dbg(c, "mod time: %s", tmpsz);
	apply_timestamp(c, d, md, DE_TIMESTAMPIDX_MODIFY, &dos_timestamp, 10);

	dd->crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "crc (reported): 0x%08x", (UI)dd->crc_reported);

	dd->cmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "cmpr size: %s", format_u32_with_zip64_override(d, dd->cmpr_size,
		tmpsz, sizeof(tmpsz)));
	dd->uncmpr_size = de_getu32le_p(&pos);
	de_dbg(c, "uncmpr size: %s", format_u32_with_zip64_override(d, dd->uncmpr_size,
		tmpsz, sizeof(tmpsz)));

	if(dd->have_read_sig_and_hdrsize) {
		pos += 4;
		if(is_central) pos += 2;
	}
	else {
		dd->fn_len = de_getu16le_p(&pos);
		dd->extra_len = de_getu16le_p(&pos);
		if(is_central) {
			dd->comment_len = de_getu16le_p(&pos);
		}
		else {
			dd->comment_len = 0;
		}
	}

	if(!is_central) {
		md->file_data_pos = pos + dd->fn_len + dd->extra_len;
	}

	if(is_central) {
		md->seg_number_start = de_getu16le_p(&pos);

		md->attr_i = (UI)de_getu16le_p(&pos);
		ucstring_empty(descr);
		describe_internal_attr(c, md, descr);
		de_dbg(c, "internal file attributes: 0x%04x (%s)", md->attr_i,
			ucstring_getpsz(descr));

		md->attr_e = (UI)de_getu32le_p(&pos);
		de_dbg(c, "external file attributes: 0x%08x", md->attr_e);
		de_dbg_indent(c, 1);

		{
			// The low byte is, AFAIK, *almost* universally used for MS-DOS-style
			// attributes.
			UI dos_attrs = (md->attr_e & 0xff);
			ucstring_empty(descr);
			de_describe_dos_attribs(c, dos_attrs, descr, 0);
			de_dbg(c, "%sMS-DOS attribs: 0x%02x (%s)",
				(md->ver_made_by_hi==0)?"":"(hypothetical) ",
				dos_attrs, ucstring_getpsz(descr));
		}

		if(((md->attr_e>>16) != 0) &&
			!(md->attr_i & 0x0004))
		{
			// A number of platforms put Unix-style file attributes here, so
			// decode them as such whenever they are nonzero.
			// [But the AV feature (spec 2.0+?) uses these bits for something
			// else, and sets attr_i bit 0x0004.]
			de_dbg(c, "%sUnix attribs: octal(%06o)",
				(md->ver_made_by_hi==3)?"":"(hypothetical) ",
				(UI)(md->attr_e>>16));
		}

		de_dbg_indent(c, -1);

		md->offset_of_local_header = de_getu32le_p(&pos);
		de_dbg(c, "offset of local header: %s, segment: %d",
			format_u32_with_zip64_override(d, md->offset_of_local_header, tmpsz, sizeof(tmpsz)),
			(int)md->seg_number_start);
	}

	de_dbg(c, "filename len: %d", (int)dd->fn_len);
	de_dbg(c, "extra len: %d", (int)dd->extra_len);
	if(is_central) {
		de_dbg(c, "comment len: %d", (int)dd->comment_len);
	}

	*p_entry_size = fixed_header_size + dd->fn_len + dd->extra_len + dd->comment_len;

	dd->main_fname_pos = pos1+fixed_header_size;
	dd->main_fname_len = dd->fn_len;
	do_read_filename(c, d, md, dd, pos1+fixed_header_size, dd->fn_len, utf8_flag);

	if(dd->extra_len>0) {
		do_extra_data(c, d, md, dd, pos1+fixed_header_size+dd->fn_len, dd->extra_len, is_central);
	}

	if(dd->comment_len>0) {
		do_comment(c, d, pos1+fixed_header_size+dd->fn_len+dd->extra_len, dd->comment_len, utf8_flag,
			"member file comment", "fcomment.txt");
	}

	if(is_central) {
		if(d->used_offset_correction) {
			md->offset_of_local_header += d->offset_correction;
			de_dbg(c, "assuming local header is really at %"I64_FMT, md->offset_of_local_header);
		}
		else if(d->offset_correction!=0) {
			u32 sig1, sig2;
			i64 alt_pos;

			sig1 = (u32)de_getu32be(md->offset_of_local_header);
			if(sig1!=CODE_PK34) {
				alt_pos = md->offset_of_local_header + d->offset_correction;
				sig2 = (u32)de_getu32be(alt_pos);
				if(sig2==CODE_PK34) {
					de_warn(c, "Local file header found at %"I64_FMT" instead of %"I64_FMT". "
						"Assuming offsets are wrong by %"I64_FMT" bytes.",
						alt_pos, md->offset_of_local_header, d->offset_correction);
					md->offset_of_local_header += d->offset_correction;
					d->used_offset_correction = 1;
				}
			}
		}
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(descr);
	return retval;
}

static struct member_data *create_member_data(deark *c, lctx *d)
{
	struct member_data *md;

	md = de_malloc(c, sizeof(struct member_data));
	md->local_dir_entry_data.fname = ucstring_create(c);
	md->central_dir_entry_data.fname = ucstring_create(c);
	return md;
}

static void destroy_member_data(deark *c, struct member_data *md)
{
	if(!md) return;
	ucstring_destroy(md->central_dir_entry_data.fname);
	ucstring_destroy(md->local_dir_entry_data.fname);
	de_free(c, md);
}

static i32 ucstring_lastchar(de_ucstring *s)
{
	if(!s || s->len<1) return 0;
	return s->str[s->len-1];
}

// Things to do after both the central and local headers have been read.
// E.g., extract the file.
static int do_process_member(deark *c, lctx *d, struct member_data *md)
{
	int retval = 0;

	// If for some reason we have a central-dir filename but not a local-dir
	// filename, use the central-dir filename.
	if(ucstring_isempty(md->local_dir_entry_data.fname) &&
		ucstring_isnonempty(md->central_dir_entry_data.fname))
	{
		ucstring_append_ucstring(md->local_dir_entry_data.fname,
			md->central_dir_entry_data.fname);
	}

	// Set the final file size and crc fields.
	if(md->local_dir_entry_data.bit_flags & 0x0008) {
		if(d->using_scanmode) {
			de_err(c, "File is incompatible with scan mode");
			goto done;
		}

		// Indicates that certain fields are not present in the local file header,
		// and are instead in a "data descriptor" after the file data.
		// Let's hope they are also in the central file header.
		md->cmpr_size = md->central_dir_entry_data.cmpr_size;
		md->uncmpr_size = md->central_dir_entry_data.uncmpr_size;
		md->crc_reported = md->central_dir_entry_data.crc_reported;
	}
	else {
		md->cmpr_size = md->local_dir_entry_data.cmpr_size;
		md->uncmpr_size = md->local_dir_entry_data.uncmpr_size;
		md->crc_reported = md->local_dir_entry_data.crc_reported;
	}

	process_ext_attr(c, d, md);

	// In some cases, detect directories by checking whether the filename ends
	// with a slash.
	if(!md->is_dir && md->uncmpr_size==0 &&
		(d->using_scanmode || (md->ver_made_by_lo<20)))
	{
		if(ucstring_lastchar(md->local_dir_entry_data.fname) == '/') {
			de_dbg(c, "[assuming this is a subdirectory]");
			md->is_dir = 1;
		}
	}

	do_extract_file(c, d, md);
	retval = 1;

done:
	return retval;
}

// In *entry_size, returns the size of the central dir entry.
// Returns 0 if the central dir entry could not even be parsed.
static int do_member_from_central_dir_entry(deark *c, lctx *d,
	struct member_data *md, i64 central_index, i64 pos, i64 *entry_size)
{
	i64 tmp_entry_size;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	*entry_size = 0;

	de_dbg(c, "central dir entry #%d", (int)central_index);
	de_dbg_indent(c, 1);

	// Read the central dir file header
	if(!do_file_header(c, d, md, 1, pos, entry_size)) {
		goto done;
	}

	// If we were able to read the central dir file header, we might be able
	// to continue and read more files, even if the local file header fails.
	retval = 1;

	// Read the local file header
	if(!do_file_header(c, d, md, 0, md->offset_of_local_header, &tmp_entry_size)) {
		goto done;
	}

	do_process_member(c, d, md);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_local_dir_only(deark *c, lctx *d, i64 pos1, i64 *pmember_size)
{
	struct member_data *md = NULL;
	i64 tmp_entry_size;
	int retval = 0;

	md = create_member_data(c, d);

	md->offset_of_local_header = pos1;

	// Read the local file header
	if(!do_file_header(c, d, md, 0, md->offset_of_local_header, &tmp_entry_size)) {
		goto done;
	}

	if(!do_process_member(c, d, md)) goto done;

	*pmember_size = md->file_data_pos + md->cmpr_size - pos1;
	retval = 1;

done:
	destroy_member_data(c, md);
	return retval;
}

static void de_run_zip_scanmode(deark *c, lctx *d)
{
	i64 pos = 0;

	d->using_scanmode = 1;

	while(1) {
		int ret;
		i64 foundpos = 0;
		i64 member_size = 0;

		if(pos > c->infile->len-4) break;
		ret = dbuf_search(c->infile, g_zipsig34, 4, pos, c->infile->len-pos, &foundpos);
		if(!ret) break;
		pos = foundpos;
		de_dbg(c, "zip member at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = do_local_dir_only(c, d, pos, &member_size);
		de_dbg_indent(c, -1);
		if(!ret) break;
		if(member_size<1) break;
		pos += member_size;
	}
}

static void main_walk_cdir_cb(deark *c, struct zip_wcd_ctx *wcdctx)
{
	lctx *d = (lctx*)wcdctx->userdata;
	struct member_data *md = NULL;
	i64 entry_size = 0;
	int ret = 0;

	md = create_member_data(c, d);
	md->central_dir_entry_data.have_read_sig_and_hdrsize = 1;
	md->central_dir_entry_data.fn_len = wcdctx->fn_len;
	md->central_dir_entry_data.extra_len = wcdctx->extra_len;
	md->central_dir_entry_data.comment_len = wcdctx->comment_len;

	ret = do_member_from_central_dir_entry(c, d, md, wcdctx->num_entries_completed,
		wcdctx->entry_pos, &entry_size);

	// TODO: Decide exactly what to do if something fails.
	if(!ret) {
		wcdctx->errflag = 1;
	}

	destroy_member_data(c, md);
}

static int do_central_dir(deark *c, lctx *d)
{
	i64 pos;
	struct zip_wcd_ctx *wcdctx = NULL;
	int retval = 0;

	pos = d->eocd.cdir_offset;
	de_dbg(c, "central dir at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	wcdctx = de_malloc(c, sizeof(struct zip_wcd_ctx));
	wcdctx->userdata = (void*)d;
	wcdctx->cbfn = main_walk_cdir_cb;
	wcdctx->max_entries = d->eocd.cdir_num_entries_total;
	wcdctx->inf = c->infile;
	wcdctx->inf_startpos = pos;
	// Note that this endpos would sometimes be wrong for multi-segment archives,
	// but we won't get here in that case.
	wcdctx->inf_endpos = pos + d->eocd.cdir_byte_size;
	wcdctx->report_errors = 1;
	wcdctx->is_resof = d->is_resof;

	zip_wcd_run(c, wcdctx);
	if(wcdctx->errflag) {
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	de_free(c, wcdctx);
	return retval;
}

static int do_zip64_eocd(deark *c, lctx *d)
{
	i64 pos;
	i64 n;
	int retval = 0;
	int saved_indent_level;
	UI ver, ver_hi, ver_lo;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->zip64_eocd_segnum!=0) {
		de_warn(c, "This might be a multi-segment Zip64 archive, which is not supported");
		retval = 1;
		d->is_zip64 = 0;
		goto done;
	}

	pos = d->zip64_eocd_pos;
	if((UI)de_getu32be(pos) != CODE_PK66) {
		de_warn(c, "Expected Zip64 end-of-central-directory record not found at %"I64_FMT, pos);
		retval = 1; // Maybe the eocd locator sig was a false positive?
		d->is_zip64 = 0;
		goto done;
	}

	de_dbg(c, "zip64 end-of-central-dir record at %"I64_FMT, pos);
	pos += 4;
	de_dbg_indent(c, 1);

	n = de_geti64le(pos); pos += 8;
	de_dbg(c, "size of zip64 eocd record: (12+)%"I64_FMT, n);

	ver = (UI)de_getu16le_p(&pos);
	ver_hi = (ver&0xff00)>>8;
	ver_lo = ver&0x00ff;
	de_dbg(c, "version made by: platform=%u (%s), ZIP spec=%u.%u",
		ver_hi, get_platform_name(ver_hi), (UI)(ver_lo/10), (UI)(ver_lo%10));

	ver = (UI)de_getu16le_p(&pos);
	ver_hi = (ver&0xff00)>>8;
	ver_lo = ver&0x00ff;
	de_dbg(c, "version needed: platform=%u (%s), ZIP spec=%u.%u",
		ver_hi, get_platform_name(ver_hi), (UI)(ver_lo/10), (UI)(ver_lo%10));

	n = de_getu32le_p(&pos);
	de_dbg(c, "this segment num: %"I64_FMT, n);

	d->eocd64.cdir_starting_seg_num = de_getu32le_p(&pos);
	d->eocd64.cdir_num_entries_this_seg = de_geti64le(pos); pos += 8;
	de_dbg(c, "central dir num entries on this segment: %"I64_FMT, d->eocd64.cdir_num_entries_this_seg);
	de_sanitize_count(&d->eocd64.cdir_num_entries_this_seg);
	d->eocd64.cdir_num_entries_total = de_geti64le(pos); pos += 8;
	de_dbg(c, "central dir num entries: %"I64_FMT, d->eocd64.cdir_num_entries_total);
	de_sanitize_count(&d->eocd64.cdir_num_entries_this_seg);
	d->eocd64.cdir_byte_size = de_geti64le(pos); pos += 8;
	de_dbg(c, "central dir size: %"I64_FMT, d->eocd64.cdir_byte_size);
	de_sanitize_length(&d->eocd64.cdir_byte_size);
	d->eocd64.cdir_offset = de_geti64le(pos); pos += 8;
	de_dbg(c, "central dir offset: %"I64_FMT", segment: %u",
		d->eocd64.cdir_offset, (UI)d->eocd64.cdir_starting_seg_num);
	de_sanitize_offset(&d->eocd64.cdir_offset);

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_zip64_eocd_locator(deark *c, lctx *d)
{
	i64 n;
	i64 pos = d->eocd_pos - 20;

	if((UI)de_getu32be(pos) != CODE_PK67) {
		return;
	}
	de_dbg(c, "zip64 eocd locator found at %"I64_FMT, pos);
	pos += 4;
	d->is_zip64 = 1;
	de_dbg_indent(c, 1);
	d->zip64_eocd_segnum = de_getu32le_p(&pos);
	d->zip64_eocd_pos = de_geti64le(pos); pos += 8;
	de_dbg(c, "offset of zip64 eocd: %"I64_FMT", segment: %u",
		d->zip64_eocd_pos, (UI)d->zip64_eocd_segnum);
	de_sanitize_offset(&d->zip64_eocd_pos);
	n = de_getu32le_p(&pos);
	de_dbg(c, "total number of segments: %u", (UI)n);
	de_dbg_indent(c, -1);
}

static int do_end_of_central_dir(deark *c, lctx *d)
{
	i64 pos;
	i64 alt_cdir_offset;
	u8 have_alt_cdir_offset = 0;
	int retval = 0;
	char tmpsz[64];

	pos = d->eocd_pos;
	de_dbg(c, "end-of-central-dir record at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->eocd.this_seg_num = de_getu16le(pos+4);
	de_dbg(c, "this segment num: %"I64_FMT, d->eocd.this_seg_num);
	d->eocd.cdir_starting_seg_num = de_getu16le(pos+6);
	de_dbg(c, "segment num with central dir start: %"I64_FMT,
		d->eocd.cdir_starting_seg_num);

	d->eocd.cdir_num_entries_this_seg = de_getu16le(pos+8);
	de_dbg(c, "central dir num entries on this segment: %s",
		format_u16_with_zip64_override(d, d->eocd.cdir_num_entries_this_seg, tmpsz, sizeof(tmpsz)));
	if(d->is_zip64 && (d->eocd.cdir_num_entries_this_seg==0xffff)) {
		d->eocd.cdir_num_entries_this_seg = d->eocd64.cdir_num_entries_this_seg;
	}

	d->eocd.cdir_num_entries_total = de_getu16le(pos+10);
	if(d->is_resof) {
		d->eocd.cdir_byte_size = - de_geti32le(pos+12);
	}
	else {
		d->eocd.cdir_byte_size = de_getu32le(pos+12);
	}

	d->eocd.cdir_offset = de_getu32le(pos+16);
	de_dbg(c, "central dir num entries: %s",
		format_u16_with_zip64_override(d, d->eocd.cdir_num_entries_total, tmpsz, sizeof(tmpsz)));
	if(d->is_zip64 && (d->eocd.cdir_num_entries_total==0xffff)) {
		d->eocd.cdir_num_entries_total = d->eocd64.cdir_num_entries_total;
	}

	de_dbg(c, "central dir size: %"I64_FMT, d->eocd.cdir_byte_size);
	if(d->is_zip64 && (d->eocd.cdir_byte_size==0xffffffffLL)) {
		d->eocd.cdir_byte_size = d->eocd64.cdir_byte_size;
	}

	de_dbg(c, "central dir offset: %s, segment: %"I64_FMT,
		format_u32_with_zip64_override(d, d->eocd.cdir_offset, tmpsz, sizeof(tmpsz)),
		d->eocd.cdir_starting_seg_num);
	if(d->is_zip64 && (d->eocd.cdir_offset==0xffffffffLL)) {
		d->eocd.cdir_offset = d->eocd64.cdir_offset;
	}

	d->eocd.archive_comment_len = de_getu16le(pos+20);
	de_dbg(c, "comment length: %d", (int)d->eocd.archive_comment_len);

	if((d->eocd.cdir_starting_seg_num==d->eocd.this_seg_num) &&
		(d->eocd.cdir_offset + d->eocd.cdir_byte_size > d->eocd_pos))
	{
		// If the central dir pos is wrong, we expect it to be too small, not
		// too large. This is probably not a ZIP file (EOCD sig. false positive).
		// TODO?: Maybe the signature-search function should be more discriminating.
		de_err(c, "Invalid EOCD record. This might not be a ZIP file.");
		goto done;
	}

	if(d->eocd.archive_comment_len>0) {
		// The comment for the whole .ZIP file presumably has to use
		// cp437 encoding. There's no flag that could indicate otherwise.
		do_comment(c, d, pos+22, d->eocd.archive_comment_len, 0,
			"ZIP file comment", "comment.txt");
	}

	if(d->eocd.cdir_starting_seg_num!=d->eocd.this_seg_num ||
		(d->is_zip64 && d->zip64_eocd_segnum!=d->eocd.this_seg_num))
	{
		de_err(c, "This looks like part of a multi-segment ZIP archive.");
		print_multisegment_note(c, d);
		goto done;
	}

	if(d->eocd.this_seg_num!=0) {
		de_warn(c, "This file might be part of a multi-segment ZIP archive.");
		print_multisegment_note(c, d);
	}

	if(d->eocd.cdir_num_entries_this_seg!=d->eocd.cdir_num_entries_total) {
		de_warn(c, "This ZIP file might not be supported correctly "
			"(number-of-entries-this-seg=%d, number-of-entries-total=%d)",
			(int)d->eocd.cdir_num_entries_this_seg, (int)d->eocd.cdir_num_entries_total);
	}

	alt_cdir_offset =
		(d->is_zip64 ? d->zip64_eocd_pos : d->eocd_pos) -
		d->eocd.cdir_byte_size;
	if(alt_cdir_offset>=0 && alt_cdir_offset!=d->eocd.cdir_offset) {
		have_alt_cdir_offset = 1;
	}

	if(have_alt_cdir_offset) {
		u32 sig;

		de_warn(c, "Inconsistent central directory offset. Reported to be %"I64_FMT", "
			"but based on its reported size, it should be %"I64_FMT".",
			d->eocd.cdir_offset, alt_cdir_offset);

		sig = (u32)de_getu32be(alt_cdir_offset);
		if(sig==CODE_PK12) {
			d->offset_correction = alt_cdir_offset - d->eocd.cdir_offset;
			de_dbg(c, "likely central dir found at %"I64_FMT, alt_cdir_offset);
			d->eocd.cdir_offset = alt_cdir_offset;
		}
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void check_for_resof_fmt(deark *c, lctx *d)
{
	if(d->is_zip64) return;
	if(c->module_disposition==DE_MODDISP_INTERNAL) return;
	if(d->eocd_pos != c->infile->len-22) return;
	// Test the high byte of the central-dir-size field. For RESOF, the sign bit
	// should be set.
	if(de_getbyte(d->eocd_pos+15) < 0x80) return;
	if(de_getu32be(0) != CODE_PK36) return;
	d->is_resof = 1;
}

static void de_run_zip_normally(deark *c, lctx *d)
{
	int eocd_found;

	if(c->detection_data && c->detection_data->zip_eocd_looked_for) {
		eocd_found = (int)c->detection_data->zip_eocd_found;
		d->eocd_pos = c->detection_data->zip_eocd_pos;
	}
	else {
		eocd_found = fmtutil_find_zip_eocd(c, c->infile, 0, &d->eocd_pos);
	}
	if(!eocd_found) {
		if(c->module_disposition==DE_MODDISP_AUTODETECT ||
			c->module_disposition==DE_MODDISP_EXPLICIT)
		{
			u32 bof_sig;

			bof_sig = (u32)de_getu32be(0);
			if(bof_sig==CODE_PK78) {
				de_err(c, "This looks like the first segment of a multi-segment ZIP archive.");
				print_multisegment_note(c, d);
				goto done;
			}
			if(bof_sig==CODE_PK34) {
				de_err(c, "ZIP central directory not found. "
					"You could try \"-opt zip:scanmode\".");
				goto done;
			}
		}
		de_err(c, "Not a valid ZIP file");
		goto done;
	}

	de_dbg(c, "end-of-central-dir record found at %"I64_FMT,
		d->eocd_pos);

	do_zip64_eocd_locator(c, d);

	if(d->is_zip64) {
		if(!do_zip64_eocd(c, d)) goto done;
	}

	check_for_resof_fmt(c, d);

	if(d->is_zip64)
		de_declare_fmt(c, "ZIP-Zip64");
	else if(d->is_resof)
		de_declare_fmt(c, "SOF/RESOF");
	else
		de_declare_fmt(c, "ZIP");

	if(!do_end_of_central_dir(c, d)) {
		goto done;
	}

	if(!do_central_dir(c, d)) {
		goto done;
	}

done:
	;
}

static void do_run_zip_relocator(deark *c, de_module_params *mparams,
	int internalmode, const char *reloc_opt);

static void do_run_zip_combiner(deark *c, de_module_params *mparams);

static void de_run_zip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;
	u8 combine_mode = 0;
	de_encoding enc;

	combine_mode = (u8)de_get_ext_option_bool(c, "zip:combine", 0);
	if(combine_mode) {
		do_run_zip_combiner(c, mparams);
		return;
	}
	else {
		if(c->mp_data && c->mp_data->count>0) {
			de_err(c, "Multi-segment archives are only supported with \"-opt zip:combine\"");
			goto done;
		}
	}

	if(de_havemodcode(c, mparams, 'R')) {
		do_run_zip_relocator(c, mparams, 1, NULL);
		return;
	}

	s = de_get_ext_option(c, "zip:reloc");
	if(s) {
		do_run_zip_relocator(c, mparams, 0, s);
		return;
	}

	d = de_malloc(c, sizeof(lctx));

	enc = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->default_enc_for_filenames = enc;
	d->default_enc_for_comments = enc;

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

	if(de_get_ext_option(c, "zip:scanmode")) {
		de_run_zip_scanmode(c, d);
	}
	else {
		de_run_zip_normally(c, d);
	}

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_zip(deark *c)
{
	u32 bof_sig;
	int has_zip_ext;
	int has_mz_sig = 0;
	i64 eocd_pos;

	has_zip_ext = de_input_file_has_ext(c, "zip");

	// Fast tests:

	bof_sig = (u32)de_getu32be(0);
	if(bof_sig==CODE_PK34 || bof_sig==CODE_PK00) {
		return has_zip_ext ? 100 : 90;
	}
	if((bof_sig>>16)==0x4d5a || (bof_sig>>16)==0x5a4d) {
		has_mz_sig = 1;
	}

	// First try "fast" mode. Note that we won't update c->detection_data
	// if this fails, because a later full search might succeed.
	if(fmtutil_find_zip_eocd(c, c->infile, 0x1, &eocd_pos)) {
		c->detection_data->zip_eocd_looked_for = 1;
		c->detection_data->zip_eocd_found = 1;
		c->detection_data->zip_eocd_pos = eocd_pos;
		return has_zip_ext ? 100 : 19;
	}

	// Things to consider:
	// * We want de_fmtutil_find_zip_eocd() to be called no more than once, and
	// only on files that for some reason we suspect could be ZIP files.
	// * If the user disables exe format detection (e.g. with "-onlydetect zip"),
	// we want self-extracting-ZIP .exe files to be detected as ZIP instead.
	// * And we want the above to work even if the file has a ZIP file comment,
	// making it expensive to detect as ZIP.

	// Tests below can't return a confidence higher than this.
	if(c->detection_data->best_confidence_so_far >= 19) return 0;

	// Slow tests:

	if(has_mz_sig || has_zip_ext) {
		c->detection_data->zip_eocd_looked_for = 1;
		if(fmtutil_find_zip_eocd(c, c->infile, 0, &eocd_pos)) {
			c->detection_data->zip_eocd_found = 1;
			c->detection_data->zip_eocd_pos = eocd_pos;
			return 19;
		}
	}

	if(has_zip_ext && bof_sig==CODE_PK78) {
		return 10; // First segment of a mult-segment archive
	}

	return 0;
}

static void de_help_zip(deark *c)
{
	de_msg(c, "-opt zip:scanmode : Do not use the \"central directory\"");
	de_msg(c, "-opt zip:implodebug : Behave like PKZIP 1.01/1.02");
	de_msg(c, "-opt zip:reloc[=<new_offset>] : Instead of decoding, "
		"copy/optimize the file");
	de_msg(c, "-mp -opt zip:combine : Instead of decoding, "
		"combine a multi-segment archive into one file");
}

void de_module_zip(deark *c, struct deark_module_info *mi)
{
	mi->id = "zip";
	mi->desc = "ZIP archive";
	mi->run_fn = de_run_zip;
	mi->identify_fn = de_identify_zip;
	mi->help_fn = de_help_zip;
	mi->flags |= DE_MODFLAG_MULTIPART;
}

/////////////////////// ZIP relocator utility
// This routine converts a ZIP file to one that has no unused space at the
// beginning (or end). It adjusts the offsets so that the new file is still
// valid.
// This is useful for "extracting" a pure ZIP file from some hybrid ZIP formats,
// mainly self-extracting ZIP archives.

struct zipreloc_ctx {
	u8 errflag;
	u8 need_errmsg;
	u8 seg_id_mismatch_flag;
	u8 quiet;
	i64 relocpos;
	struct eocd_struct eocd;
	i64 eocd_pos;
	i64 cdir_offset_reported;
	i64 cdir_offset_actual;
	i64 min_ldir_offset;
	i64 offset_correction; // Amount to add to the reported offsets to get the real offsets
	i64 offset_diff; // Amount to add to the real offsets to get the offsets in the new file
	i64 central_dir_nbytes_converted;
	dbuf *outf;
};

static void zipreloc_err(deark *c, struct zipreloc_ctx *d, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

static void zipreloc_err(deark *c, struct zipreloc_ctx *d, const char *fmt, ...)
{
	va_list ap;

	if(d->quiet) return;
	va_start(ap, fmt);
	de_verr(c, fmt, ap);
	va_end(ap);
}

// Convert a central dir entry
static void zipreloc_wcd_convert(deark *c, struct zip_wcd_ctx *wcdctx)
{
	struct zipreloc_ctx *d = (struct zipreloc_ctx*)wcdctx->userdata;
	i64 pos1 = wcdctx->entry_pos;
	i64 len = wcdctx->entry_size;
	i64 cpstart, cplen;
	i64 ldir_offset;

	// Copy the first 34 bytes of the central dir entry
	// (signature thru comment len).
	cpstart = pos1;
	cplen = 34;
	dbuf_copy(wcdctx->inf, cpstart, cplen, d->outf);

	// Segment number, that we force to 0 (offset 34 len 2)
	dbuf_write_zeroes(d->outf, 2);

	// Copy the next 6 bytes (offset 36)
	// (internal attribs, thru external attribs)
	cpstart = pos1+36;
	cplen = 6;
	dbuf_copy(wcdctx->inf, cpstart, cplen, d->outf);

	// Edit the offset-of-local-hdr field (offset 42 len 4)
	ldir_offset = de_getu32le(pos1+42) + d->offset_correction;
	dbuf_writeu32le(d->outf, ldir_offset + d->offset_diff);

	// Copy the rest of the entry (offset 46+).
	cpstart = pos1+46;
	cplen = len - 46;
	dbuf_copy(wcdctx->inf, cpstart, cplen, d->outf);
	d->central_dir_nbytes_converted += len;
}

static void zip_relocator_main(deark *c, struct zipreloc_ctx *d)
{
	i64 cpstart, cplen;
	struct zip_wcd_ctx *wcdctx = NULL;

	d->offset_diff = d->relocpos - d->min_ldir_offset;

	de_dbg(c, "[writing new file]");
	d->outf = dbuf_create_output_file(c, "zip", NULL, 0);

	// Write any extra space requested at the start of the file
	dbuf_write_zeroes(d->outf, d->relocpos);

	// Copy the main part of the ZIP file
	cpstart = d->min_ldir_offset;
	cplen = d->cdir_offset_actual - cpstart;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

	wcdctx = de_malloc(c, sizeof(struct zip_wcd_ctx));
	wcdctx->userdata = (void*)d;
	wcdctx->cbfn = zipreloc_wcd_convert;
	wcdctx->max_entries = d->eocd.cdir_num_entries_this_seg;
	wcdctx->inf = c->infile;
	wcdctx->inf_startpos = d->cdir_offset_actual;
	wcdctx->inf_endpos = c->infile->len;

	// Copy/convert the central directory
	zip_wcd_run(c, wcdctx);
	if(wcdctx->errflag) {
		d->errflag = 1;
		d->need_errmsg = wcdctx->need_errmsg;
	}

	if(d->errflag) {
		goto done;
	}

	// Copy any unused bytes at the end of the central dir
	cpstart = d->cdir_offset_actual + d->central_dir_nbytes_converted;
	cplen =  d->eocd.cdir_byte_size - d->central_dir_nbytes_converted;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

	// Copy anything between the central dir and the EOCD record
	cpstart = d->cdir_offset_actual+d->eocd.cdir_byte_size;
	cplen = d->eocd_pos - cpstart;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

	// Copy/convert the EOCD record & archive comment

	// First 4 bytes
	cpstart = d->eocd_pos;
	cplen = 4;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

	// Next 4 bytes are segment ID numbers, that we force to zero.
	dbuf_write_zeroes(d->outf, 4);

	// Next 8 bytes (num entries cdir this segment, thru cdir size)
	cpstart = d->eocd_pos+8;
	cplen = 8;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

	// Adjusted central dir offset
	dbuf_writeu32le(d->outf, d->cdir_offset_actual + d->offset_diff);

	// Last 2 bytes of EOCD record, plus archive comment
	cpstart = d->eocd_pos + 20;
	cplen = 2 + d->eocd.archive_comment_len;
	dbuf_copy(c->infile, cpstart, cplen, d->outf);

done:
	dbuf_close(d->outf);
	d->outf = NULL;
	de_free(c, wcdctx);
}

static void zipreloc_wcd_prescan(deark *c, struct zip_wcd_ctx *wcdctx)
{
	struct zipreloc_ctx *d = (struct zipreloc_ctx*)wcdctx->userdata;
	i64 pos1 = wcdctx->entry_pos;
	dbuf *inf = wcdctx->inf;
	u32 sig;
	i64 ldir_seg_num;
	i64 ldir_offset;

	de_dbg2(c, "central dir entry at %"I64_FMT, pos1);

	ldir_seg_num = dbuf_getu16le(inf, pos1+34);
	ldir_offset = dbuf_getu32le(inf, pos1+42) + d->offset_correction;
	de_dbg_indent(c, 1);
	de_dbg2(c, "local dir offset: %"I64_FMT", segment %"I64_FMT, ldir_offset,
		ldir_seg_num);
	de_dbg_indent(c, -1);

	sig = (u32)dbuf_getu32be(inf, ldir_offset);
	if(sig != CODE_PK34) {
		wcdctx->errflag = 1;
		wcdctx->need_errmsg = 1;
		goto done;
	}

	if(ldir_seg_num != d->eocd.this_seg_num) {
		u32 crc_from_cdir;
		u32 crc_from_ldir;

		crc_from_cdir = (u32)dbuf_getu32le(inf, pos1+16);
		crc_from_ldir = (u32)dbuf_getu32le(inf, ldir_offset+14);
		if(crc_from_cdir == crc_from_ldir) {
			de_dbg(c, "[tolerating mismatched segment id]");
		}
		else {
			wcdctx->errflag = 1;
			wcdctx->need_errmsg = 1;
			d->seg_id_mismatch_flag = 1;
			goto done;
		}
	}

	if(ldir_offset < d->min_ldir_offset) {
		d->min_ldir_offset = ldir_offset;
	}

done:
	;
}

static void simple_read_eocd(deark *c, dbuf *f, i64 pos1,
	struct eocd_struct *eocd)
{
	i64 pos = pos1+4;

	eocd->this_seg_num = dbuf_getu16le_p(f, &pos);
	eocd->cdir_starting_seg_num = dbuf_getu16le_p(f, &pos);
	eocd->cdir_num_entries_this_seg = dbuf_getu16le_p(f, &pos);
	eocd->cdir_num_entries_total = dbuf_getu16le_p(f, &pos);
	eocd->cdir_byte_size = dbuf_getu32le_p(f, &pos);
	eocd->cdir_offset = dbuf_getu32le_p(f, &pos);
	eocd->archive_comment_len = dbuf_getu16le_p(f, &pos);

	if((UI)dbuf_getu32be(f, pos1-20) == CODE_PK67) {
		eocd->is_likely_zip64 = 1;
	}
}

static void simple_dbg_eocd(deark *c, struct eocd_struct *eocd)
{
	de_dbg(c, "this segment num: %"I64_FMT, eocd->this_seg_num);
	de_dbg(c, "central dir num entries on this segment: %"I64_FMT,
		eocd->cdir_num_entries_this_seg);
	de_dbg(c, "central dir num entries: %"I64_FMT, eocd->cdir_num_entries_total);
	de_dbg(c, "central dir size: %"I64_FMT, eocd->cdir_byte_size);
	de_dbg(c, "central dir offset: %"I64_FMT", segment %"I64_FMT, eocd->cdir_offset,
		eocd->cdir_starting_seg_num);
}

static void do_run_zip_relocator(deark *c, de_module_params *mparams,
	int internalmode, const char *reloc_opt)
{
	struct zipreloc_ctx *d = NULL;
	struct fmtutil_specialexe_detection_data *edd_from_parent = NULL;
	struct zip_wcd_ctx *wcdctx_prescan = NULL;
	u32 sig;
	int found_cdir = 0;
	int eocd_found;

	d = de_malloc(c, sizeof(struct zipreloc_ctx));

	if(internalmode) {
		d->relocpos = 0;
		d->quiet = 1;
		if(mparams) {
			edd_from_parent = (struct fmtutil_specialexe_detection_data*)mparams->in_params.obj1;
		}
	}
	else {
		if(reloc_opt) {
			d->relocpos = de_atoi64(reloc_opt);
		}
		if(d->relocpos<0) d->relocpos = 0;
	}

	// (Trying to make Deark not call fmtutil_find_zip_eocd() more than once per
	// file, and it makes a mess of things...)
	if(edd_from_parent && edd_from_parent->zip_eocd_looked_for) {
		eocd_found = edd_from_parent->zip_eocd_found;
		if(eocd_found) {
			d->eocd_pos = edd_from_parent->zip_eocd_pos;
		}
	}
	else if(c->detection_data && c->detection_data->zip_eocd_looked_for) {
		eocd_found = (int)c->detection_data->zip_eocd_found;
		if(eocd_found) {
			d->eocd_pos = c->detection_data->zip_eocd_pos;
		}
	}
	else {
		eocd_found = fmtutil_find_zip_eocd(c, c->infile, 0, &d->eocd_pos);
	}
	if(!eocd_found) {
		zipreloc_err(c, d, "Not a ZIP file, or central directory not found.");
		goto done;
	}
	de_dbg(c, "end-of-central-dir record found at %"I64_FMT,
		d->eocd_pos);

	simple_read_eocd(c, c->infile, d->eocd_pos, &d->eocd);
	d->cdir_offset_reported = d->eocd.cdir_offset;

	de_dbg_indent(c, 1);
	simple_dbg_eocd(c, &d->eocd);
	de_dbg_indent(c, -1);

	if(d->eocd.is_likely_zip64) {
		zipreloc_err(c, d, "Relocating Zip64 is not supported");
		goto done;
	}

	if(d->eocd.cdir_num_entries_this_seg != d->eocd.cdir_num_entries_total) {
		d->errflag = 1;
		d->need_errmsg = 1;
		d->seg_id_mismatch_flag = 1;
		goto done;
	}

	if(d->eocd.cdir_starting_seg_num != d->eocd.this_seg_num) {
		d->errflag = 1;
		d->need_errmsg = 1;
		d->seg_id_mismatch_flag = 1;
		goto done;
	}

	sig = (u32)de_getu32be(d->cdir_offset_reported);
	if(sig==CODE_PK12) {
		found_cdir = 1;
		d->cdir_offset_actual = d->cdir_offset_reported;
	}

	if(!found_cdir) {
		i64 pos2;

		pos2 = d->eocd_pos - d->eocd.cdir_byte_size;
		sig = (u32)de_getu32be(pos2);
		if(sig==CODE_PK12) {
			de_dbg(c, "central dir found at %"I64_FMT, pos2);
			d->cdir_offset_actual = pos2;
			d->offset_correction = d->cdir_offset_actual - d->cdir_offset_reported;
			found_cdir = 1;
		}
	}

	if(!found_cdir) {
		zipreloc_err(c, d, "Central directory not found (expected at %"I64_FMT")",
			d->cdir_offset_reported);
		goto done;
	}

	if(d->cdir_offset_actual + d->eocd.cdir_byte_size > d->eocd_pos) {
		// We require the EOCD record to appear after the central dir.
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->eocd_pos+22+d->eocd.archive_comment_len > c->infile->len) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	// Pre-scan the central dir to find the offset of the local directory that
	// appears first in the file.
	d->min_ldir_offset = d->cdir_offset_actual; // initialize to max possible value
	de_dbg(c, "[scanning central dir]");
	de_dbg_indent(c, 1);

	wcdctx_prescan = de_malloc(c, sizeof(struct zip_wcd_ctx));
	wcdctx_prescan->userdata = (void*)d;
	wcdctx_prescan->cbfn = zipreloc_wcd_prescan;
	wcdctx_prescan->max_entries = d->eocd.cdir_num_entries_this_seg;
	wcdctx_prescan->inf = c->infile;
	wcdctx_prescan->inf_startpos = d->cdir_offset_actual;
	wcdctx_prescan->inf_endpos = c->infile->len;

	zip_wcd_run(c, wcdctx_prescan);
	d->errflag = wcdctx_prescan->errflag;
	d->need_errmsg = wcdctx_prescan->need_errmsg;

	de_dbg_indent(c, -1);

	if(d->errflag) goto done;

	de_dbg(c, "min ldir offs: %"I64_FMT, d->min_ldir_offset);
	zip_relocator_main(c, d);

	if(mparams) {
		// Inform the caller of success
		mparams->out_params.flags |= 0x1;
	}

done:
	de_free(c, wcdctx_prescan);
	if(d) {
		if(d->errflag && d->need_errmsg) {
			zipreloc_err(c, d, "Cannot optimize/relocate this ZIP file%s",
				(d->seg_id_mismatch_flag?" (disk spanning issue)":""));
		}
		de_free(c, d);
	}
}

/////////////////////// ZIP combiner utility
// This routine converts the segments of a multi-segment ZIP archive into
// a single ZIP file.

#define ZC_MAX_COMBINED_SIZE   200000000

struct zc_segment {
	i64 starting_offset; // offset in the output file
	i64 cdir_possible_padding_nbytes;
};

struct zc_advpos {
	int rel_seg_id;
	i64 rel_pos;
	i64 abs_pos;
};

struct zipcombine_ctx {
	u8 errflag;
	u8 need_errmsg;
	int num_segments;
	struct eocd_struct eocd;
	struct zc_advpos eocd_pos;
	struct zc_advpos cdir_pos;
	dbuf *combinedf; // Combined segments: membuf, edited in place

	i64 seg0_prefix_len; // Num bytes deleted at start of segment 0

	// array[num_segments]:
	//  [0] = c->infile
	//  [1..num_segments-1] = c->mp_data[0..]
	struct zc_segment *segments;
	char tmpsz[80];
};

// Writes to d->tmpsz.
static void zc_format_advpos(struct zipcombine_ctx *d, struct zc_advpos *advpos)
{
	// TODO: When d->seg0_prefix_len is relevant, this output is confusing.
	de_snprintf(d->tmpsz, sizeof(d->tmpsz), "[segment %d, + %"I64_FMT" = %"I64_FMT"]",
		advpos->rel_seg_id, advpos->rel_pos, advpos->abs_pos);
}

// zc_read_to_membuf() must be run, before calling this function.
// Caller sets advpos->rel_*.
// This function sets advpos->abs_pos, and may set d->errflag;
static void zc_relpos_to_abspos(struct zipcombine_ctx *d, struct zc_advpos *advpos)
{
	if(advpos->rel_seg_id<0 || advpos->rel_seg_id>=d->num_segments) {
		d->errflag = 1;
		advpos->abs_pos = d->combinedf->len;
		return;
	}
	advpos->abs_pos = d->segments[advpos->rel_seg_id].starting_offset + advpos->rel_pos;
	if(advpos->rel_seg_id==0) {
		advpos->abs_pos -= d->seg0_prefix_len;
	}
}

static void wcd_callback_for_cdpadding(deark *c, struct zip_wcd_ctx *wcdctx)
{
	if(c->debug_level<2) return;
	de_dbg2(c, "peek at cdir entry #%u: segment %d, pos %"I64_FMT", len %"I64_FMT,
		(UI)wcdctx->num_entries_completed,
		wcdctx->userdata_seg_id, wcdctx->entry_pos, wcdctx->entry_size);
}

// A central dir record is not supposed to be split across multiple segments,
// but some versions of PKZIP do it anyway. Other write a partial entry,
// and then at the start of the next segment, start over and write the same
// entry in its entirety.
// This function figures out the size of a partial cdir record at the end
// of a segment. (It doesn't try to figure out if it's real or not. That's
// done elsewhere.)
static i64 zc_find_cdir_possible_padding(deark *c, struct zipcombine_ctx *d,
	struct zip_wcd_ctx *wcdctx, dbuf *inf, int seg_id)
{
	i64 rvs = 0; // Default

	// Haven't reached the cdir yet, so no problem.
	if(seg_id < d->eocd.cdir_starting_seg_num) goto done;

	// The last segment isn't a problem.
	if(seg_id >= d->eocd.this_seg_num) goto done;

	// There are (probably) some cdir entries on this segment. Figure out where
	// the last one ends, and return that info to the caller.
	wcdctx->inf = inf;
	wcdctx->userdata_seg_id = seg_id;

	if(seg_id==d->eocd.cdir_starting_seg_num) {
		wcdctx->inf_startpos = d->eocd.cdir_offset;
	}
	else {
		// Not common, and probably untested. It means there was a full segment
		// consisting entirely of cdir entries.
		wcdctx->inf_startpos = 0;
	}

	wcdctx->inf_endpos = inf->len;

	zip_wcd_run(c, wcdctx);
	d->errflag = wcdctx->errflag;
	d->need_errmsg = wcdctx->need_errmsg;
	if(d->errflag) {
		goto done;
	}

	rvs = inf->len - wcdctx->endpos_of_last_completed_entry;

done:
	return rvs;
}

static void zc_scan_and_read_to_membuf(deark *c, struct zipcombine_ctx *d)
{
	int v;
	struct zip_wcd_ctx *wcdctx = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "[reading and scanning files]");
	de_dbg_indent(c, 1);

	wcdctx = de_malloc(c, sizeof(struct zip_wcd_ctx));
	wcdctx->userdata = (void*)d;
	wcdctx->multisegment_mode = 1;
	wcdctx->cbfn = wcd_callback_for_cdpadding;
	wcdctx->max_entries = d->eocd.cdir_num_entries_total;

	// TODO?: For convenience, we read all the segments into memory.
	// It wouldn't be too hard to avoid doing that, and only read the
	// central dir. (The most inconvenient issue might be where we
	// validate that the local dir signatures are present.)

	d->combinedf = dbuf_create_membuf(c, 1048576, 0);

	for(v=0; v<d->num_segments; v++) {
		dbuf *tmpsegf;
		i64 newsize;
		i64 pfx_len = 0;
		i64 nbytes_to_copy;

		tmpsegf = de_mp_acquire_dbuf(c, v);
		if(!tmpsegf) {
			d->errflag = 1;
			goto done;
		}

		d->segments[v].cdir_possible_padding_nbytes =
			zc_find_cdir_possible_padding(c, d, wcdctx, tmpsegf, v);

		nbytes_to_copy = tmpsegf->len; // tentative
		if(d->errflag) goto done;

		if(v==0) {
			u32 sig;

			// The first segment usually starts with a PK\7\8 signature, which
			// we'll delete. We don't *have* to do this, but it makes our
			// output file a little more compatible with other software.
			// And we may as well also delete the PK00 "temporary spanning
			// marker" placeholder.
			sig = (u32)dbuf_getu32be(tmpsegf, 0);
			if(sig==CODE_PK78 || sig==CODE_PK00) {
				pfx_len = 4;
				nbytes_to_copy -= pfx_len;
				d->seg0_prefix_len = pfx_len;
			}
		}

		de_dbg(c, "segment %d", v);
		de_dbg_indent(c, 1);

		if(v>0 && d->segments[v-1].cdir_possible_padding_nbytes>0) {
			// If this segment seems to start with a cdir record, any partial cdir
			// record from the previous segment was presumably just padding, that
			// we need to delete.
			if(looks_like_cdir_record(c, tmpsegf, 0)) {
				// E.g., PKZIP 2.04g does this.
				de_dbg(c, "[deleting %"I64_FMT" padding bytes from prev seg]",
					d->segments[v-1].cdir_possible_padding_nbytes);
				dbuf_truncate(d->combinedf, d->combinedf->len -
					d->segments[v-1].cdir_possible_padding_nbytes);
			}
			else {
				// E.g., PKZIP 2.60.03 for Windows 3.x does this.
				de_dbg(c, "[assuming real cdir record is split]");
			}
		}

		d->segments[v].starting_offset = d->combinedf->len;
		de_dbg(c, "starting offset: %"I64_FMT", size=%"I64_FMT,
			d->segments[v].starting_offset, nbytes_to_copy);

		if(d->segments[v].cdir_possible_padding_nbytes) {
			de_dbg(c, "cdir padding?: %"I64_FMT, d->segments[v].cdir_possible_padding_nbytes);
		}

		newsize = d->combinedf->len + nbytes_to_copy;
		if(newsize>ZC_MAX_COMBINED_SIZE || newsize>DE_MAX_MALLOC) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		dbuf_copy(tmpsegf, pfx_len, nbytes_to_copy, d->combinedf);
		de_mp_release_dbuf(c, v, &tmpsegf);
		de_dbg_indent(c, -1);
	}

done:
	de_free(c, wcdctx);
	de_dbg_indent_restore(c, saved_indent_level);

}

static void zc_writeu32le_at(struct zipcombine_ctx *d, i64 pos, i64 n)
{
	u8 buf[4];

	de_writeu32le_direct(buf, n);
	dbuf_write_at(d->combinedf, pos, buf, 4);
}

static void zc_writeu16le_at(struct zipcombine_ctx *d, i64 pos, i64 n)
{
	u8 buf[2];

	de_writeu16le_direct(buf, n);
	dbuf_write_at(d->combinedf, pos, buf, 2);
}

static void zc_modify_eocd(deark *c, struct zipcombine_ctx *d)
{
	de_dbg(c, "[adjusting eocd]");

	// this segment id -> 0
	zc_writeu16le_at(d, d->eocd_pos.abs_pos + 4, 0);

	// cdir segment num -> 0
	zc_writeu16le_at(d, d->eocd_pos.abs_pos + 6, 0);

	// cdir num entries this segment
	zc_writeu16le_at(d, d->eocd_pos.abs_pos + 8, d->eocd.cdir_num_entries_total);

	// cdir offset
	zc_writeu32le_at(d, d->eocd_pos.abs_pos + 16, d->cdir_pos.abs_pos);
}

static void wcd_callback_for_fixcdir(deark *c, struct zip_wcd_ctx *wcdctx)
{
	struct zipcombine_ctx *d = (struct zipcombine_ctx*)wcdctx->userdata;
	struct zc_advpos ldir_pos;
	u32 sig;

	de_dbg(c, "adjusting cdir entry #%u: pos %"I64_FMT", len %"I64_FMT,
		(UI)wcdctx->num_entries_completed,
		wcdctx->entry_pos, wcdctx->entry_size);

	de_zeromem(&ldir_pos, sizeof(struct zc_advpos));
	ldir_pos.rel_seg_id = (int)dbuf_getu16le(d->combinedf, wcdctx->entry_pos+34);
	ldir_pos.rel_pos = dbuf_getu32le(d->combinedf, wcdctx->entry_pos+42);

	zc_relpos_to_abspos(d, &ldir_pos);

	zc_format_advpos(d, &ldir_pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "ldir pos: %s", d->tmpsz);
	de_dbg_indent(c, -1);

	// If this is the right place, there should be a signature there.
	sig = (u32)dbuf_getu32be(d->combinedf, ldir_pos.abs_pos);
	if(sig != CODE_PK34) {
		wcdctx->errflag = 1;
		wcdctx->need_errmsg = 1;
		goto done;
	}

	// segment number -> 0
	zc_writeu16le_at(d, wcdctx->entry_pos+34, 0);
	// old offset -> new offset
	zc_writeu32le_at(d, wcdctx->entry_pos+42, ldir_pos.abs_pos);

done:
	;
}

static void zc_modify_cdir(deark *c, struct zipcombine_ctx *d)
{
	struct zip_wcd_ctx *wcdctx = NULL;

	de_dbg(c, "[adjusting cdir entries]");
	de_dbg_indent(c, 1);
	wcdctx = de_malloc(c, sizeof(struct zip_wcd_ctx));
	wcdctx->userdata = (void*)d;
	wcdctx->cbfn = wcd_callback_for_fixcdir;
	wcdctx->inf = d->combinedf;
	wcdctx->max_entries = d->eocd.cdir_num_entries_total;
	wcdctx->inf_startpos = d->cdir_pos.abs_pos;
	wcdctx->inf_endpos = d->combinedf->len;
	zip_wcd_run(c, wcdctx);
	d->errflag = wcdctx->errflag;
	d->need_errmsg = wcdctx->need_errmsg;
	if(d->errflag) {
		goto done;
	}

done:
	de_free(c, wcdctx);
	de_dbg_indent(c, -1);
}

static void do_run_zip_combiner(deark *c, de_module_params *mparams)
{
	struct zipcombine_ctx *d = NULL;
	dbuf *inf_last_segment;
	int eocd_found;
	int last_seg_xidx;
	dbuf *outf = NULL;

	d = de_malloc(c, sizeof(struct zipcombine_ctx));

	d->num_segments = 1;
	if(c->mp_data) {
		d->num_segments += c->mp_data->count;
	}
	de_dbg(c, "num segments: %d", d->num_segments);
	d->segments = de_mallocarray(c, d->num_segments, sizeof(struct zc_segment));

	last_seg_xidx = d->num_segments-1;
	inf_last_segment = de_mp_acquire_dbuf(c, last_seg_xidx);
	if(!inf_last_segment) {
		d->errflag = 1;
		goto done;
	}
	eocd_found = fmtutil_find_zip_eocd(c, inf_last_segment, 0x1, &d->eocd_pos.rel_pos);
	if(!eocd_found) {
		d->need_errmsg = 1;
		goto done;
	}

	d->eocd_pos.rel_seg_id = last_seg_xidx;
	de_dbg(c, "end-of-central-dir record found at %"I64_FMT", segment %d",
		d->eocd_pos.rel_pos, d->eocd_pos.rel_seg_id);
	simple_read_eocd(c, inf_last_segment, d->eocd_pos.rel_pos, &d->eocd);

	de_dbg_indent(c, 1);
	simple_dbg_eocd(c, &d->eocd);
	de_dbg_indent(c, -1);

	de_mp_release_dbuf(c, last_seg_xidx, &inf_last_segment);

	if(d->eocd.is_likely_zip64) {
		de_err(c, "Combining Zip64 is not supported");
		goto done;
	}

	if(d->eocd.this_seg_num != last_seg_xidx) {
		d->need_errmsg = 1;
		goto done;
	}

	zc_scan_and_read_to_membuf(c, d);
	if(d->errflag) goto done;

	zc_relpos_to_abspos(d, &d->eocd_pos);
	zc_format_advpos(d, &d->eocd_pos);
	de_dbg(c, "end-of-central-dir at %s", d->tmpsz);

	d->cdir_pos.rel_seg_id = (int)d->eocd.cdir_starting_seg_num;
	d->cdir_pos.rel_pos = d->eocd.cdir_offset;
	zc_relpos_to_abspos(d, &d->cdir_pos);
	if(d->errflag) goto done;
	zc_format_advpos(d, &d->cdir_pos);
	de_dbg(c, "central dir at %s", d->tmpsz);
	if(d->errflag) goto done;

	zc_modify_eocd(c, d);
	if(d->errflag) goto done;
	zc_modify_cdir(c, d);
	if(d->errflag) goto done;

	// Write the combined-and-modified file
	outf = dbuf_create_output_file(c, "zip", NULL, 0);
	dbuf_copy(d->combinedf, 0, d->combinedf->len, outf);

done:
	dbuf_close(outf);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Failed to process multi-segment ZIP archive");
		}
		dbuf_close(d->combinedf);
		de_free(c, d->segments);
		de_free(c, d);
	}
}
