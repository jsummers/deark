// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// ARC compressed archive
// Spark
// ArcMac

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_arc);
DE_DECLARE_MODULE(de_module_spark);
DE_DECLARE_MODULE(de_module_arcmac);

#define FMT_ARC 1
#define FMT_SPARK 2
#define FMT_ARCMAC 3

#define MAX_NESTING_LEVEL 24

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;
typedef void (*decompressor_fn)(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

struct cmpr_meth_info {
	u8 cmpr_meth;
	unsigned int flags;
	const char *name;
	decompressor_fn decompressor;
};

struct persistent_member_data {
	de_ucstring *comment;
	de_ucstring *path;
};

struct member_data {
	deark *c;
	lctx *d;

	u8 cmpr_meth;
	u8 cmpr_meth_masked;
	u8 has_spark_attribs;
	const struct cmpr_meth_info *cmi;
	const char *cmpr_meth_name;
	i64 orig_size;
	i64 cmpr_data_pos;
	i64 cmpr_size;
	u32 crc_reported;
	u32 crc_calc;
	de_ucstring *fn;
	struct de_timestamp arc_timestamp;
	struct de_riscos_file_attrs rfa;
	int is_dir;

	i64 arcmac_dforklen;
	i64 arcmac_rforklen;
	struct de_stringreaderdata *arcmac_fn;
	struct de_advfile *arcmac_advf;
};

struct localctx_struct {
	int fmt;
	const char *fmtname;
	de_ext_encoding input_encoding_for_filenames;
	de_ext_encoding input_encoding_for_comments;
	de_ext_encoding input_encoding_for_arcmac_fn;
	u8 method10; // 1=trimmed, 2=crushed
	int append_type;
	int recurse_subdirs;
	u8 sig_byte;
	u8 prescan_found_eoa;
	u8 has_trailer_data;
	u8 has_pak_trailer;
	u8 has_arc_extensions;
	i64 prescan_pos_after_eoa;
	i64 num_top_level_members; // Not including EOA marker
	struct de_crcobj *crco;
	struct de_strarray *curpath;
	struct persistent_member_data *persistent_md; // optional array[num_top_level_members]
};

struct member_parser_data {
	int nesting_level;
	int member_idx;
	u8 magic;
	u8 cmpr_meth, cmpr_meth_masked;
	i64 member_pos;
	i64 member_len;
	i64 cmpr_data_pos;
	i64 cmpr_data_len;
};

typedef void (*member_cb_type)(deark *c, lctx *d, struct member_parser_data *mpd);

// Calls the supplied callback function for each ARC member found.
// Also called for end-of-archive/directory markers.
// Also called if unexpected data is encountered (with mpd->magic != 0x1a).
static void parse_member_sequence(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level,
	member_cb_type member_cbfn)
{
	struct member_parser_data *mpd = NULL;
	int member_idx = 0;
	i64 pos = pos1;

	mpd = de_malloc(c, sizeof(struct member_parser_data));

	while(1) {
		if(pos+2 > pos1+len) break;
		de_zeromem(mpd, sizeof(struct member_parser_data));
		mpd->nesting_level = nesting_level;
		mpd->member_idx = member_idx++;
		mpd->member_pos = pos;

		mpd->magic = de_getbyte_p(&pos);
		if(mpd->magic!=d->sig_byte) {
			mpd->member_len = 1;
			mpd->cmpr_data_pos = mpd->member_pos; // dummy value
			member_cbfn(c, d, mpd);
			break;
		}
		mpd->cmpr_meth = de_getbyte_p(&pos);
		mpd->cmpr_meth_masked = mpd->cmpr_meth & 0x7f;

		if(mpd->cmpr_meth_masked==0x00 || mpd->cmpr_meth==0x1f) { // end of archive/dir
			mpd->member_len = 2;
			mpd->cmpr_data_pos = mpd->member_pos+2; // dummy value
			member_cbfn(c, d, mpd);
			break;
		}

		if(d->fmt==FMT_ARCMAC) {
			u8 magic2;

			// TODO: Check for EOF?
			pos += 57; // Skip remainder of 59-byte ArcMac preheader
			magic2 = de_getbyte_p(&pos);
			if(magic2 != 0x1a) { // Error
				// TODO: Call member_cbfn()?
				break;
			}

			// Read the "real" compression method field (should be the same?).
			mpd->cmpr_meth = de_getbyte_p(&pos);
			mpd->cmpr_meth_masked = mpd->cmpr_meth & 0x7f;
		}

		pos += 13;
		mpd->cmpr_data_len = de_getu32le_p(&pos);
		pos += 2+2+2;
		if(mpd->cmpr_meth_masked!=0x01) {
			pos += 4; // original size
		}
		if(mpd->cmpr_meth & 0x80) {
			pos += 12; // Spark-specific data
		}

		mpd->cmpr_data_pos = pos;
		mpd->member_len = mpd->cmpr_data_pos + mpd->cmpr_data_len - mpd->member_pos;
		member_cbfn(c, d, mpd);

		pos = mpd->member_pos + mpd->member_len;
	}

	de_free(c, mpd);
}

static void decompressor_stored(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	fmtutil_decompress_uncompressed(c, dcmpri, dcmpro, dres, 0);
}

static void decompressor_spark_compressed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS1BYTEHEADER;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompressor_squashed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.max_code_size = 13;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompressor_packed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	fmtutil_decompress_rle90_ex(c, dcmpri, dcmpro, dres, 0);
}

static void decompressor_squeezed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_dcmpr_two_layer_params tlp;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_type1 = fmtutil_huff_squeeze_codectype1;
	tlp.codec2 = dfilter_rle90_codec;
	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;
	de_dfilter_decompress_two_layer(c, &tlp);
}

static void decompressor_crunched5(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ARC5;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompressor_crunched6(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_dcmpr_two_layer_params tlp;
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ARC5;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_pushable = dfilter_lzw_codec;
	tlp.codec1_private_params = (void*)&delzwp;

	tlp.codec2 = dfilter_rle90_codec;

	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;

	de_dfilter_decompress_two_layer(c, &tlp);
}

static void decompressor_crunched8(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_dcmpr_two_layer_params tlp;
	struct de_lzw_params delzwp;

	// "Crunched" means "packed", then "compressed".
	// So we have to "uncompress" (LZW), then "unpack" (RLE90).

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS1BYTEHEADER;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_pushable = dfilter_lzw_codec;
	tlp.codec1_private_params = (void*)&delzwp;

	tlp.codec2 = dfilter_rle90_codec;

	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;

	de_dfilter_decompress_two_layer(c, &tlp);
}

static void decompressor_trimmed(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_dcmpr_two_layer_params tlp;
	struct de_lh1_params lh1p;

	de_zeromem(&lh1p, sizeof(struct de_lh1_params));
	lh1p.is_arc_trimmed = 1;
	lh1p.history_fill_val = 0x00;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_pushable = dfilter_lh1_codec;
	tlp.codec1_private_params = (void*)&lh1p;

	tlp.codec2 = dfilter_rle90_codec;

	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;

	de_dfilter_decompress_two_layer(c, &tlp);
}

static void decompressor_distilled(deark *c, lctx *d, struct member_data *md,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	fmtutil_distilled_codectype1(c, dcmpri, dcmpro, dres, NULL);
}

// Flags:
//  0x01 = valid in ARC
//  0x02 = valid in Spark
//  0x80 = assume high bit of cmpr_meth is set for Spark format
//  0x100, 0x200 = special
static const struct cmpr_meth_info cmpr_meth_info_arr[] = {
	{ 0x00, 0x03, "end of archive marker", NULL },
	{ 0x01, 0x83, "stored (old format)", decompressor_stored },
	{ 0x02, 0x83, "stored", decompressor_stored },
	{ 0x03, 0x83, "packed (RLE)", decompressor_packed },
	{ 0x04, 0x83, "squeezed (RLE + Huffman)", decompressor_squeezed },
	{ 0x05, 0x83, "crunched5 (static LZW)", decompressor_crunched5 },
	{ 0x06, 0x83, "crunched6 (RLE + static LZW)", decompressor_crunched6 },
	{ 0x07, 0x83, "crunched7 (ARC 4.6)", NULL },
	{ 0x08, 0x83, "crunched8 (RLE + dynamic LZW)", decompressor_crunched8 },
	{ 0x09, 0x83, "squashed (dynamic LZW)", decompressor_squashed },
	{ 10,  0x101, "trimmed", decompressor_trimmed },
	{ 10,  0x201, "crushed", NULL },
	{ 10,   0x01, "trimmed or crushed", NULL },
	{ 0x0b, 0x01, "distilled", decompressor_distilled },
	{ 20,   0x01, "archive info", NULL },
	{ 21,   0x01, "extended file info", NULL },
	{ 22,   0x01, "OS info", NULL },
	{ 0x1e, 0x01, "subdir", NULL },
	{ 0x1f, 0x01, "end of subdir marker", NULL },
	{ 0x80, 0x02, "end of archive marker", NULL },
	{ 0xff, 0x02, "compressed", decompressor_spark_compressed }
};

static const struct cmpr_meth_info *get_cmpr_meth_info(lctx *d, u8 cmpr_meth)
{
	size_t k;
	const struct cmpr_meth_info *p;

	for(k=0; k<DE_ARRAYCOUNT(cmpr_meth_info_arr); k++) {
		u8 meth_adjusted;

		p = &cmpr_meth_info_arr[k];
		if(d->fmt==FMT_ARC && !(p->flags & 0x1)) continue;
		if(d->fmt==FMT_SPARK && !(p->flags & 0x2)) continue;
		meth_adjusted = p->cmpr_meth;
		if(d->fmt==FMT_SPARK && (p->flags & 0x80)) {
			meth_adjusted |= 0x80;
		}
		if(meth_adjusted != cmpr_meth) continue;

		if(p->cmpr_meth==10) {
			// Method 10 has a conflict -- it could be either Trimmed (ARC7)
			// or Crushed (PAK).
			if(p->flags&0x100) { // Skip this unless we're sure it's Trimmed
				if(d->method10!=1) {
					if(d->has_pak_trailer || !d->has_arc_extensions) continue;
				}
			}
			else if(p->flags&0x200) { // Skip this unless we're sure it's Crushed
				if(d->method10!=2) {
					if(!d->has_pak_trailer || d->has_arc_extensions) continue;
				}
			}
		}
		return p;
	}
	return NULL;
}

static void read_one_pk_comment(deark *c, lctx *d, i64 pos, de_ucstring *s)
{
	dbuf_read_to_ucstring(c->infile, pos, 32, s, 0, d->input_encoding_for_comments);
	ucstring_strip_trailing_spaces(s);
}

static void init_trailer_data(deark *c, lctx *d)
{
	d->has_trailer_data = 1;
	if(!d->persistent_md) {
		d->persistent_md = de_mallocarray(c, d->num_top_level_members,
			sizeof(struct persistent_member_data));
	}
}

static void do_pk_comments(deark *c, lctx *d)
{
	i64 sig_pos;
	i64 comments_descr_pos;
	int has_file_comments = 0;
	int has_archive_comment = 0;
	i64 file_comments_pos = 0;
	de_ucstring *archive_comment = NULL;
	u8 dscr[4];

	if(!d->prescan_found_eoa) return;
	sig_pos = c->infile->len-8;
	if(sig_pos < d->prescan_pos_after_eoa) return;
	if(de_getu32be(sig_pos) != 0x504baa55) {
		return;
	}
	init_trailer_data(c, d);

	de_dbg(c, "PKARC/PKPAK comment block found");
	de_dbg_indent(c, 1);
	// Note: This logic is based on reverse engineering, and could be wrong.
	comments_descr_pos = de_getu32le(c->infile->len-4);
	de_dbg(c, "descriptor pos: %"I64_FMT, comments_descr_pos);
	if(comments_descr_pos >= sig_pos) goto done;

	de_read(dscr, comments_descr_pos, 4);
	if(dscr[0]==0x20 && dscr[1]==0x20 && dscr[2]==0x20 && dscr[3]==0x00) {
		has_file_comments = 0;
		has_archive_comment = 1;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x20) {
		has_file_comments = 1;
		has_archive_comment = 0;
	}
	else if(dscr[0]==0x01 && dscr[3]==0x00) {
		has_file_comments = 1;
		has_archive_comment = 1;
	}
	else {
		de_dbg(c, "[unrecognized comments descriptor]");
	}

	if(has_file_comments) {
		file_comments_pos = comments_descr_pos + 32;
		if(sig_pos - file_comments_pos < 32) {
			has_file_comments = 0;
		}
	}

	if(has_archive_comment) {
		archive_comment = ucstring_create(c);
		read_one_pk_comment(c, d, comments_descr_pos-32, archive_comment);
		de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(archive_comment));
	}

	if(has_file_comments) {
		i64 num_file_comments;
		i64 i;

		num_file_comments = (sig_pos - file_comments_pos)/32;
		de_dbg(c, "apparent number of file comments: %d", (int)num_file_comments);

		for(i=0; i<num_file_comments && i<d->num_top_level_members; i++) {
			if(!d->persistent_md[i].comment) {
				d->persistent_md[i].comment = ucstring_create(c);
			}
			if(ucstring_isnonempty(d->persistent_md[i].comment)) continue;
			read_one_pk_comment(c, d,file_comments_pos + i*32, d->persistent_md[i].comment);
		}
	}

done:
	ucstring_destroy(archive_comment);
	de_dbg_indent(c, -1);
}

static int do_pak_ext_record(deark *c, lctx *d, i64 pos1, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	u8 rectype;
	const char *rtname = "?";
	int retval = 0;
	i64 filenum;
	i64 filenum_adj = 0;
	i64 dlen;
	de_ucstring *archive_comment = NULL;
	struct persistent_member_data *pmd = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(de_getbyte_p(&pos) != 0xfe) goto done;
	de_dbg(c, "record at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	rectype = de_getbyte_p(&pos);
	switch(rectype) {
	case 0: rtname = "end"; break;
	case 1: rtname = "remark"; break;
	case 2: rtname = "path"; break;
	case 3: rtname = "security envelope"; break;
	}
	de_dbg(c, "rectype: %d (%s)", (int)rectype, rtname);
	if(rectype==0) goto done;

	filenum = de_getu16le_p(&pos);
	de_dbg(c, "file num: %d", (int)filenum);
	dlen = de_getu32le_p(&pos);
	de_dbg(c, "dlen: %"I64_FMT, dlen);
	if(pos+dlen > c->infile->len) goto done;

	*pbytes_consumed = 8 + dlen;
	retval = 1;

	if(filenum > 0) {
		filenum_adj = filenum - 1;
		if(filenum_adj < d->num_top_level_members) {
			pmd = &d->persistent_md[filenum_adj];
		}
	}

	if(rectype==1) { // remark
		if(filenum==0) { // archive comment
			archive_comment = ucstring_create(c);
			dbuf_read_to_ucstring_n(c->infile, pos, dlen, 16384, archive_comment,
				0, d->input_encoding_for_comments);
			de_dbg(c, "archive comment: \"%s\"", ucstring_getpsz_d(archive_comment));
		}
		else { // file comment
			if(!pmd) goto done;

			if(!pmd->comment) {
				pmd->comment = ucstring_create(c);
			}
			if(ucstring_isnonempty(pmd->comment)) goto done;
			dbuf_read_to_ucstring_n(c->infile, pos, dlen, 2048, pmd->comment,
				0, d->input_encoding_for_comments);
		}
	}
	else if(rectype==2) {
		if(!pmd) goto done;
		if(!pmd->path) {
			pmd->path = ucstring_create(c);
		}
		if(ucstring_isnonempty(pmd->path)) goto done;
		dbuf_read_to_ucstring_n(c->infile, pos, dlen, 512, pmd->path,
			0, d->input_encoding_for_comments);
	}

done:
	if(archive_comment) ucstring_destroy(archive_comment);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_pak_trailer(deark *c, lctx *d)
{
	u8 b;
	i64 pos;

	if(!d->prescan_found_eoa) return;
	if(c->infile->len - d->prescan_pos_after_eoa < 2) return;
	if(de_getbyte(d->prescan_pos_after_eoa) != 0xfe) return;
	b = de_getbyte(d->prescan_pos_after_eoa+1);
	if(b>4) return;

	pos = d->prescan_pos_after_eoa;
	de_dbg(c, "PAK extended records at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	d->has_pak_trailer = 1;
	init_trailer_data(c, d);

	while(1) {
		i64 bytes_consumed = 0;

		if(pos > c->infile->len-2) break;
		if(!do_pak_ext_record(c, d, pos, &bytes_consumed)) break;
		if(bytes_consumed<8) break;
		pos += bytes_consumed;
	}

	de_dbg_indent(c, -1);
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

// Convert backslashes to slashes, and make sure the string ends with a /.
static void fixup_path(deark *c, lctx *d, de_ucstring *s)
{
	i64 i;

	if(s->len<1) return;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='\\') {
			s->str[i] = '/';
		}
	}

	if(s->str[s->len-1]!='/') {
		ucstring_append_char(s, '/');
	}
}

static void do_decompress_fork_arcmac(struct member_data *md,
	dbuf *outf, const char *fork_name)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	deark *c = md->c;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(md->orig_size==0) goto done;

	de_dbg(c, "decompressing %s fork", fork_name);
	de_dbg_indent(c, 1);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_data_pos;
	dcmpri.len = md->cmpr_size;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_size;

	if(dcmpri.pos + dcmpri.len > dcmpri.f->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(md->arcmac_fn->str));
		goto done;
	}

	md->cmi->decompressor(c, md->d, md, &dcmpri, &dcmpro, &dres);
	if(dres.errcode) {
		de_err(c, "Decompression failed for file %s[%s fork]: %s",
			ucstring_getpsz_d(md->arcmac_fn->str),
			fork_name, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	md->crc_calc = de_crcobj_getval(md->d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)md->crc_calc);

	if(md->crc_calc!=md->crc_reported) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->arcmac_fn->str));
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	struct member_data *md = (struct member_data*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		do_decompress_fork_arcmac(md, afp->outf, "data");
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		do_decompress_fork_arcmac(md, afp->outf, "rsrc");
	}

	return 1;
}

// TODO: Reduce code duplication with do_extract_member_file(), etc.
// Retrofitting the arc module for arcmac format made some things messy.
// It could be made somewhat cleaner by using the "advfile" system unconditionally
// -- there are pros and cons of doing that.
static void do_extract_member_file_arcmac(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	if(md->arcmac_dforklen && md->arcmac_rforklen) {
		// This seems to be allowed, but I need sample files.
		de_err(c, "Can't handle multi-fork ArcMac file");
		goto done;
	}
	if(md->arcmac_dforklen + md->arcmac_rforklen != md->orig_size) {
		de_err(c, "Inconsistent ArcMac fork size");
		goto done;
	}

	if(md->arcmac_fn && ucstring_isnonempty(md->arcmac_fn->str)) {
		ucstring_append_ucstring(md->arcmac_advf->filename, md->arcmac_fn->str);
	}
	else {
		ucstring_append_ucstring(md->arcmac_advf->filename, md->fn);
	}
	md->arcmac_advf->original_filename_flag = 1;

	md->arcmac_advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] =
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY];

	md->arcmac_advf->userdata = (void*)md;
	md->arcmac_advf->writefork_cbfn = my_advfile_cbfn;

	md->arcmac_advf->mainfork.writelistener_cb = our_writelistener_cb;
	md->arcmac_advf->mainfork.userdata_for_writelistener = (void*)d->crco;
	md->arcmac_advf->rsrcfork.writelistener_cb = our_writelistener_cb;
	md->arcmac_advf->rsrcfork.userdata_for_writelistener = (void*)d->crco;
	de_crcobj_reset(d->crco);

	de_advfile_run(md->arcmac_advf);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_extract_member_file(deark *c, lctx *d, struct member_data *md,
	struct persistent_member_data *pmd, de_finfo *fi, i64 pos)
{
	de_ucstring *fullfn = NULL;
	dbuf *outf = NULL;
	int ignore_failed_crc = 0;
	int saved_indent_level;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg_indent_save(c, &saved_indent_level);
	fullfn = ucstring_create(c);

	if(pmd && ucstring_isnonempty(pmd->path)) {
		// For PAK-style paths.
		// (Pretty useless, until we support cmpr. meth. #11.)
		// Note that PAK-style paths, and directory recursion, are not expected to
		// be possible in the same file.
		ucstring_append_ucstring(fullfn, pmd->path);
		fixup_path(c, d, fullfn);
	}

	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	if(d->append_type && md->rfa.file_type_known) {
		ucstring_printf(fullfn, DE_ENCODING_LATIN1, ",%03X", md->rfa.file_type);
	}
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	de_dbg_indent(c, 1);

	if(!md->cmi || !md->cmi->decompressor) {
		de_err(c, "%s: Compression type 0x%02x (%s) is not supported.",
			ucstring_getpsz_d(md->fn), (unsigned int)md->cmpr_meth, md->cmpr_meth_name);
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);
	de_crcobj_reset(d->crco);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = md->cmpr_size;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->orig_size;

	if(dcmpri.pos + dcmpri.len > dcmpri.f->len) {
		de_err(c, "%s: Data goes beyond end of file", ucstring_getpsz_d(md->fn));
		goto done;
	}

	md->cmi->decompressor(c, d, md, &dcmpri, &dcmpro, &dres);
	if(dres.errcode) {
		de_err(c, "%s: Decompression failed: %s", ucstring_getpsz_d(md->fn),
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	md->crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (unsigned int)md->crc_calc);
	if(md->crc_reported==0 && !d->recurse_subdirs && md->rfa.file_type_known &&
		md->rfa.file_type==0xddc && md->cmpr_meth==0x82)
	{
		ignore_failed_crc = 1;
	}
	if((md->crc_calc!=md->crc_reported) && !ignore_failed_crc) {
		de_err(c, "%s: CRC check failed", ucstring_getpsz_d(md->fn));
	}

done:
	dbuf_close(outf);
	ucstring_destroy(fullfn);
	de_dbg_indent_restore(c, saved_indent_level);
}

// "Extract" a directory entry
static void do_extract_member_dir(deark *c, lctx *d, struct member_data *md,
	de_finfo *fi)
{
	dbuf *outf = NULL;
	de_ucstring *fullfn = NULL;

	fullfn = ucstring_create(c);
	de_strarray_make_path(d->curpath, fullfn, DE_MPFLAG_NOTRAILINGSLASH);

	fi->is_directory = 1;
	de_finfo_set_name_from_ucstring(c, fi, fullfn, DE_SNFLAG_FULLPATH);

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_close(outf);
	ucstring_destroy(fullfn);
}

struct extinfo_item_info {
	u8 cmprmeth;
	u8 rectype;
	unsigned int flags; // 0x1 = string
	const char *name;
	void *reserved;
};

static void do_info_record_string(deark *c, lctx *d, i64 pos, i64 len, const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, 2048, s, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_for_comments);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static const struct extinfo_item_info extinfo_arr[] = {
	{ 20, 0, 0x01, "archive description", NULL },
	{ 20, 1, 0x01, "archive created by", NULL },
	{ 20, 2, 0x01, "archive last modified by", NULL },
	{ 21, 0, 0x01, "file description", NULL },
	{ 21, 1, 0x01, "long name", NULL },
	{ 21, 2, 0x00, "timestamps", NULL },
	{ 21, 3, 0x00, "icon", NULL },
	{ 21, 4, 0x01, "attributes", NULL },
	{ 21, 5, 0x01, "full path", NULL }
};

static const struct extinfo_item_info *find_extinfo_item(u8 cmprmeth, u8 rectype)
{
	size_t k;

	for(k=0; k<DE_ARRAYCOUNT(extinfo_arr); k++) {
		if(extinfo_arr[k].cmprmeth==cmprmeth && extinfo_arr[k].rectype==rectype) {
			return &extinfo_arr[k];
		}
	}
	return NULL;
}

static void do_info_item(deark *c, lctx *d, struct member_data *md)
{
	int saved_indent_level;
	i64 pos = md->cmpr_data_pos;
	i64 endpos = md->cmpr_data_pos+md->cmpr_size;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "info item data (meth=%d) at %"I64_FMT" len=%"I64_FMT, (int)md->cmpr_meth,
		md->cmpr_data_pos, md->cmpr_size);
	de_dbg_indent(c, 1);

	while(1) {
		i64 reclen;
		i64 recpos;
		i64 dpos;
		i64 dlen;
		u8 rectype;
		const struct extinfo_item_info *ei;
		const char *ei_name;

		recpos = pos;
		if(pos+3 > endpos) goto done;
		reclen = de_getu16le_p(&pos);
		if(reclen<3 || recpos+reclen > endpos) goto done;
		rectype = de_getbyte_p(&pos);
		ei = find_extinfo_item(md->cmpr_meth, rectype);
		if(ei && ei->name) ei_name = ei->name;
		else ei_name = "?";

		dpos = recpos + 3;
		dlen = reclen - 3;
		de_dbg(c, "record type %d (%s) at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
			(int)rectype, ei_name, recpos, dpos, dlen);
		de_dbg_indent(c, 1);
		if(ei && (ei->flags & 0x01)) {
			do_info_record_string(c, d, dpos, dlen, ei_name);
		}
		else {
			de_dbg_hexdump(c, c->infile, dpos, dlen, 256, NULL, 0x1);
		}
		de_dbg_indent(c, -1);
		pos = recpos + reclen;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level);

static void do_arcmac_preheader(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	i64 pos = pos1;
	u16 finder_flags;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	if(md->arcmac_advf) return;
	md->arcmac_advf = de_advfile_create(c);

	pos += 2; // magic / cmprtype

	md->arcmac_fn = dbuf_read_string(c->infile, pos, 31, 31, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_for_arcmac_fn);
	de_dbg(c, "ArcMac filename: \"%s\"", ucstring_getpsz_d(md->arcmac_fn->str));
	if(md->arcmac_fn->sz_strlen>0) {
		md->arcmac_advf->original_filename_flag = 1;
		de_advfile_set_orig_filename(md->arcmac_advf, md->arcmac_fn->sz, md->arcmac_fn->sz_strlen);
	}
	pos += 32;

	dbuf_read_fourcc(c->infile, pos, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	de_memcpy(md->arcmac_advf->typecode, filetype.bytes, 4);
	md->arcmac_advf->has_typecode = 1;
	pos += 4;

	dbuf_read_fourcc(c->infile, pos, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);
	de_memcpy(md->arcmac_advf->creatorcode, creator.bytes, 4);
	md->arcmac_advf->has_creatorcode = 1;
	pos += 4;

	finder_flags = (u16)de_getu16be_p(&pos);
	de_dbg(c, "finder flags: 0x%04x", finder_flags);
	md->arcmac_advf->finderflags = finder_flags;
	md->arcmac_advf->has_finderflags = 1;
	pos += 6; // remainder of finfo

	md->arcmac_dforklen = de_getu32le_p(&pos);
	de_dbg(c, "data fork len: %"I64_FMT, md->arcmac_dforklen);
	md->arcmac_rforklen = de_getu32le_p(&pos);
	de_dbg(c, "rsrc fork len: %"I64_FMT, md->arcmac_rforklen);

	md->arcmac_advf->mainfork.fork_exists = (md->arcmac_dforklen!=0);
	md->arcmac_advf->mainfork.fork_len = md->arcmac_dforklen;
	md->arcmac_advf->rsrcfork.fork_exists = (md->arcmac_rforklen!=0);
	md->arcmac_advf->rsrcfork.fork_len = md->arcmac_rforklen;
}

// The main per-member processing function
static void member_cb_main(deark *c, lctx *d, struct member_parser_data *mpd)
{
	int saved_indent_level;
	i64 pos1 = mpd->member_pos;
	i64 pos = pos1;
	i64 hdrsize;
	i64 mod_time_raw, mod_date_raw;
	de_finfo *fi = NULL;
	struct member_data *md = NULL;
	int need_curpath_pop = 0;
	struct persistent_member_data *pmd = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	md = de_malloc(c, sizeof(struct member_data));
	md->c = c;
	md->d = d;

	if(mpd->nesting_level==0 && d->persistent_md && (mpd->member_idx < d->num_top_level_members)) {
		pmd = &d->persistent_md[mpd->member_idx];
		if(ucstring_isnonempty(pmd->comment)) {
			de_dbg(c, "file comment: \"%s\"", ucstring_getpsz_d(pmd->comment));
		}
		if(ucstring_isnonempty(pmd->path)) {
			de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(pmd->path));
		}
	}

	pos++; // 'magic' byte, already read by the parser
	if(mpd->magic != d->sig_byte) {
		de_err(c, "Failed to find %s member at %"I64_FMT, d->fmtname, pos1);
		goto done;
	}

	if(d->fmt==FMT_ARCMAC && mpd->cmpr_meth_masked!=0) {
		do_arcmac_preheader(c, d, md, mpd->member_pos);
		pos += 59;
	}

	pos++; // compression ID, already read by the parser
	md->cmpr_meth = mpd->cmpr_meth;
	md->cmpr_meth_masked = mpd->cmpr_meth_masked;

	md->cmi = get_cmpr_meth_info(d, md->cmpr_meth);
	if(md->cmi && md->cmi->name) {
		md->cmpr_meth_name = md->cmi->name;
	}
	else {
		md->cmpr_meth_name = "?";
	}

	de_dbg(c, "cmpr meth: 0x%02x (%s)", (unsigned int)md->cmpr_meth, md->cmpr_meth_name);

	if(md->cmpr_meth_masked==0x00 || md->cmpr_meth==0x1f) {
		hdrsize = 2;
	}
	else {
		if(md->cmpr_meth_masked==0x01) {
			hdrsize = 25;
		}
		else {
			hdrsize = 29;
		}
		if(md->cmpr_meth>=128) {
			hdrsize += 12;
		}
	}
	if(mpd->member_len<hdrsize) {
		de_err(c, "Insufficient data for archive member at %"I64_FMT, pos1);
		goto done;
	}

	if(md->cmpr_meth_masked==0x00 || md->cmpr_meth==0x1f) { // end of archive/dir marker
		goto done;
	}

	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_for_filenames);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 13;

	pos += 4; // cmpr_size, already read by the parser
	md->cmpr_size = mpd->cmpr_data_len;
	de_dbg(c, "cmpr size: %"I64_FMT, md->cmpr_size);

	mod_date_raw = de_getu16le_p(&pos);
	mod_time_raw = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&md->arc_timestamp, mod_date_raw, mod_time_raw);
	md->arc_timestamp.tzcode = DE_TZCODE_LOCAL;
	dbg_timestamp(c, &md->arc_timestamp, ((d->fmt==FMT_SPARK) ? "timestamp (ARC)":"timestamp"));

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	if((md->cmpr_meth_masked)==0x01) {
		md->orig_size = md->cmpr_size;
	}
	else {
		md->orig_size = de_getu32le_p(&pos);
		de_dbg(c, "orig size: %"I64_FMT, md->orig_size);
	}

	if(d->fmt == FMT_SPARK) {
		md->has_spark_attribs = 1;
		fmtutil_riscos_read_load_exec(c, c->infile, &md->rfa, pos);
		pos += 8;
		fmtutil_riscos_read_attribs_field(c, c->infile, &md->rfa, pos, 0);
		pos += 4;
	}

	md->cmpr_data_pos = mpd->cmpr_data_pos;

	de_strarray_push(d->curpath, md->fn);
	need_curpath_pop = 1;

	// TODO: Is it possible to distinguish between a subdirectory, and a Spark
	// member file that should always be extracted? Does a nonzero CRC mean
	// we should not recurse?
	if(d->fmt==FMT_SPARK && d->recurse_subdirs && md->rfa.file_type_known &&
		(md->rfa.file_type==0xddc) && md->cmpr_meth==0x82)
	{
		md->is_dir = 1;
	}
	else if(d->fmt==FMT_ARC && d->recurse_subdirs && md->cmpr_meth==0x1e) {
		md->is_dir = 1;
	}

	if(d->recurse_subdirs) {
		de_dbg(c, "is directory: %d", md->is_dir);
	}

	de_dbg(c, "file data at %"I64_FMT", len=%"I64_FMT, md->cmpr_data_pos, md->cmpr_size);

	// Extract...
	fi = de_finfo_create(c);
	fi->original_filename_flag = 1;

	if(md->rfa.mod_time.is_valid) {
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->rfa.mod_time;
	}
	else if(md->arc_timestamp.is_valid) {
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->arc_timestamp;
	}

	if(md->has_spark_attribs) {
		fi->has_riscos_data = 1;
		fi->riscos_attribs = md->rfa.attribs;
		fi->load_addr = md->rfa.load_addr;
		fi->exec_addr = md->rfa.exec_addr;
	}

	if(md->is_dir) {
		fi->is_directory = 1;
	}

	if(md->is_dir) {
		do_extract_member_dir(c, d, md, fi);

		// Nested subdirectory archives (ARC 6 "z" option, or Spark) have both a known
		// length (md->cmpr_size), and an end-of-archive marker. So there are two
		// ways to parse them:
		// 1) Recursively, meaning we trust the md->cmpr_size field (or maybe we should
		//    use orig_size instead?).
		// 2) As a flat sequence of members, meaning we trust that a nested archive
		//    will not have extra data after the end-of-archive marker.
		// Here, we use the recursive method.
		do_sequence_of_members(c, d, md->cmpr_data_pos, md->cmpr_size, mpd->nesting_level+1);
	}
	else if(md->cmpr_meth>=30 && md->cmpr_meth<=39) {
		de_warn(c, "Unknown control item type %d at %"I64_FMT, (int)md->cmpr_meth, pos1);
		goto done;
	}
	else if(md->cmpr_meth>=20 && md->cmpr_meth<=29) {
		do_info_item(c, d, md);
	}
	else if(d->fmt==FMT_ARCMAC && md->arcmac_advf) {
		do_extract_member_file_arcmac(c, d, md, fi);
	}
	else {
		do_extract_member_file(c, d, md, pmd, fi, md->cmpr_data_pos);
	}

done:
	if(need_curpath_pop) {
		de_strarray_pop(d->curpath);
	}
	if(fi) de_finfo_destroy(c, fi);
	if(md) {
		ucstring_destroy(md->fn);
		if(md->arcmac_fn) de_destroy_stringreaderdata(c, md->arcmac_fn);
		if(md->arcmac_advf) de_advfile_destroy(md->arcmac_advf);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_sequence_of_members(deark *c, lctx *d, i64 pos1, i64 len, int nesting_level)
{
	if(nesting_level >= MAX_NESTING_LEVEL) {
		de_err(c, "Max subdir nesting level exceeded");
		return;
	}

	de_dbg(c, "archive at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	parse_member_sequence(c, d, pos1, len, nesting_level, member_cb_main);
	de_dbg_indent(c, -1);
}

static void member_cb_for_prescan(deark *c, lctx *d, struct member_parser_data *mpd)
{
	if(mpd->magic!=d->sig_byte) return;
	if(mpd->cmpr_meth_masked==0x00) { // end of archive
		d->prescan_found_eoa = 1;
		d->prescan_pos_after_eoa = mpd->member_pos + mpd->member_len;
		de_dbg2(c, "end of member sequence at %"I64_FMT, d->prescan_pos_after_eoa);
		return;
	}
	if(mpd->cmpr_meth==20 || mpd->cmpr_meth==21 || mpd->cmpr_meth==30) {
		// Features we're pretty sure aren't used by PAK.
		d->has_arc_extensions = 1;
	}
	d->num_top_level_members++;
	de_dbg2(c, "member at %"I64_FMT, mpd->member_pos);
}

// Unfortunately, a pre-pass is necessary for robust handling of some ARC format
// extensions. The main issue is member-file comments, which we want to be
// available when we process that member file, but can only be found after we've
// read through the whole ARC file.
static void do_prescan_file(deark *c, lctx *d, i64 startpos)
{
	de_dbg2(c, "prescan");
	d->num_top_level_members = 0;
	de_dbg_indent(c, 1);
	parse_member_sequence(c, d, startpos, c->infile->len-startpos, 0, member_cb_for_prescan);
	de_dbg2(c, "number of members: %"I64_FMT, d->num_top_level_members);
	de_dbg_indent(c, -1);
}

static int find_arc_marker(deark *c, const u8 *buf, size_t buflen, i64 *ppos)
{
	size_t i;

	for(i=0; i<buflen; i++) {
		if(buf[i]==0x1a) {
			*ppos = (i64)i;
			return 1;
		}
	}
	return 0;
}

static void destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_crcobj_destroy(d->crco);
	de_strarray_destroy(d->curpath);
	if(d->persistent_md) {
		i64 i;

		for(i=0; i<d->num_top_level_members; i++) {
			ucstring_destroy(d->persistent_md[i].comment);
			ucstring_destroy(d->persistent_md[i].path);
		}
		de_free(c, d->persistent_md);
	}
	de_free(c, d);
}

static void do_run_arc_spark_internal(deark *c, lctx *d)
{
	i64 members_endpos;
	i64 pos = 0;

	d->sig_byte = (d->fmt==FMT_ARCMAC) ? 0x1b : 0x1a;

	if(d->sig_byte==0x1a) {
		u8 buf[33];

		// Tolerate up to sizeof(buf)-1 bytes of initial junk
		de_read(buf, 0, sizeof(buf));
		if(!find_arc_marker(c, buf, sizeof(buf), &pos)) {
			de_err(c, "Not a(n) %s file", d->fmtname);
			goto done;
		}
	}

	de_declare_fmt(c, d->fmtname);
	d->curpath = de_strarray_create(c, MAX_NESTING_LEVEL+10);
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	do_prescan_file(c, d, pos);
	if(d->prescan_found_eoa) {
		members_endpos = d->prescan_pos_after_eoa;
	}
	else {
		members_endpos = c->infile->len;
	}

	if(d->fmt==FMT_ARC) {
		do_pk_comments(c, d);
		do_pak_trailer(c, d);
	}

	do_sequence_of_members(c, d, pos, members_endpos, 0);

	if(d->prescan_found_eoa && !d->has_trailer_data) {
		i64 num_extra_bytes;

		num_extra_bytes = c->infile->len - d->prescan_pos_after_eoa;
		if(num_extra_bytes>0) {
			de_dbg(c, "extra bytes at end of archive: %"I64_FMT" (at %"I64_FMT")",
				num_extra_bytes, d->prescan_pos_after_eoa);
		}
	}

done:
	;
}

/////////////////////// ARC (core ARC-only functions)

static void de_run_arc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = FMT_ARC;
	d->fmtname = "ARC";
	// TODO: Make 'recurse' configurable. Would require us to make the embedded
	// archives end with the correct marker.
	d->recurse_subdirs = 1;
	d->input_encoding_for_filenames = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->input_encoding_for_comments = DE_EXTENC_MAKE(d->input_encoding_for_filenames,
		DE_ENCSUBTYPE_HYBRID);

	// TODO: It would probably be worth it to have a separate module for PAK, so we
	// can take the .PAK file extension into account when guessing what method #10
	// is. It's complicated, though, and not very useful until we support Crushed
	// decompression.

	s = de_get_ext_option(c, "arc:method10");
	if(s) {
		if(!de_strcmp(s, "trimmed")) {
			d->method10 = 1;
		}
		else if(!de_strcmp(s, "crushed")) {
			d->method10 = 2;
		}
	}

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_arc(deark *c)
{
	static const char *exts[] = {"arc", "ark", "pak", "spk", "sdn", "com"};
	int has_ext = 0;
	int ends_with_trailer = 0;
	int ends_with_comments = 0;
	int starts_with_trailer = 0;
	i64 arc_start = 0;
	size_t k;
	u8 cmpr_meth;
	u8 buf[5];

	de_read(buf, 0, sizeof(buf));

	// Look for 0x1a in the first 4 bytes. Some .COM-style self-extracting
	// archives start with 1-3 bytes of code before the ARC marker.
	if(!find_arc_marker(c, buf, sizeof(buf)-1, &arc_start)) {
		return 0;
	}

	cmpr_meth = buf[arc_start+1];
	if(cmpr_meth>11 && cmpr_meth!=20 && cmpr_meth!=21 && cmpr_meth!=22 && cmpr_meth!=30) {
		return 0;
	}
	if(cmpr_meth==0) starts_with_trailer = 1;

	for(k=0; k<DE_ARRAYCOUNT(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = (int)(k+1);
			break;
		}
	}

	if(arc_start>0) {
		if(has_ext==1 || has_ext==2 || has_ext==6) { // .arc, .ark, .com
			;
		}
		else {
			return 0;
		}
	}

	if(starts_with_trailer && c->infile->len==2) {
		if(has_ext>=1 && has_ext<=4) return 15; // Empty archive, 2-byte file
		return 0;
	}

	if((!starts_with_trailer) && (de_getu16be(c->infile->len-2) == 0x1a00)) {
		ends_with_trailer = 1;
	}
	if(de_getu32be(c->infile->len-8) == 0x504baa55) {
		// PKARC trailer, for files with comments
		ends_with_comments = 1;
	}

	if(!ends_with_trailer && !ends_with_comments) {
		// PAK-style extensions
		if(de_getu16be(c->infile->len-2) == 0xfe00) {
			ends_with_comments = 1;
		}
	}

	if(starts_with_trailer) {
		if(ends_with_comments) return 25;
		else return 0;
	}
	if(has_ext && (ends_with_trailer || ends_with_comments)) return 90;
	if(ends_with_trailer || ends_with_comments) return 25;
	if(has_ext) return 15;
	return 0;
}

static void de_help_arc(deark *c)
{
	de_msg(c, "-opt arc:method10=<trimmed|crushed|auto> : How to interpret compression "
		"method #10");
}

void de_module_arc(deark *c, struct deark_module_info *mi)
{
	mi->id = "arc";
	mi->desc = "ARC compressed archive";
	mi->run_fn = de_run_arc;
	mi->identify_fn = de_identify_arc;
	mi->help_fn = de_help_arc;
}

/////////////////////// Spark

static void de_run_spark(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = FMT_SPARK;
	d->fmtname = "Spark";
	d->input_encoding_for_filenames = de_get_input_encoding(c, NULL, DE_ENCODING_RISCOS);
	d->input_encoding_for_comments = DE_EXTENC_MAKE(d->input_encoding_for_filenames,
		DE_ENCSUBTYPE_HYBRID);
	d->recurse_subdirs = de_get_ext_option_bool(c, "spark:recurse", 1);
	d->append_type = de_get_ext_option_bool(c, "spark:appendtype", 0);

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_spark(deark *c)
{
	u8 b;
	u32 load_addr;
	int ldaddrcheck = 0;
	int has_trailer = 0;

	if(de_getbyte(0) != 0x1a) return 0;
	b = de_getbyte(1); // compression method
	if(b==0x82 || b==0x83 || b==0x88 || b==0x89 || b==0xff) {
		;
	}
	else if(b==0x81 || b==0x84 || b==0x85 || b==0x86) {
		; // TODO: Verify that these are possible in Spark.
	}
	else {
		return 0;
	}

	load_addr = (u32)de_getu32le(29);
	if((load_addr & 0xfff00000) == 0xfff00000) {
		ldaddrcheck = 1;
	}

	if(de_getu16be(c->infile->len-2) == 0x1a80) {
		has_trailer = 1;
	}

	if(has_trailer && ldaddrcheck) return 85;
	if(ldaddrcheck) return 30;
	if(has_trailer) return 10;
	return 0;
}

static void de_help_spark(deark *c)
{
	de_msg(c, "-opt spark:appendtype : Append the file type to the filename");
	de_msg(c, "-opt spark:recurse=0 : Extract subdirs as Spark files");
}

void de_module_spark(deark *c, struct deark_module_info *mi)
{
	mi->id = "spark";
	mi->desc = "Spark archive";
	mi->run_fn = de_run_spark;
	mi->identify_fn = de_identify_spark;
	mi->help_fn = de_help_spark;
}

/////////////////////// ArcMac

static void de_run_arcmac(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmt = FMT_ARCMAC;
	d->fmtname = "ArcMac";
	d->recurse_subdirs = 1;
	d->input_encoding_for_arcmac_fn = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);
	d->input_encoding_for_filenames = DE_ENCODING_CP437;
	d->input_encoding_for_comments = DE_EXTENC_MAKE(d->input_encoding_for_filenames,
		DE_ENCSUBTYPE_HYBRID);

	do_run_arc_spark_internal(c, d);
	destroy_lctx(c, d);
}

static int de_identify_arcmac(deark *c)
{
	u8 buf1[2];
	u8 buf2[2];

	de_read(buf1, 0, 2);
	if(buf1[0]!=0x1b) return 0;
	if(!(buf1[1]>=1 && buf1[1]<=9)) return 0;
	de_read(buf2, 59, 2);
	if(buf2[0]!=0x1a) return 0;
	if(buf2[1]!=buf1[1]) return 0;
	return 80;
}

void de_module_arcmac(deark *c, struct deark_module_info *mi)
{
	mi->id = "arcmac";
	mi->desc = "ArcMac compressed archive";
	mi->run_fn = de_run_arcmac;
	mi->identify_fn = de_identify_arcmac;
}
