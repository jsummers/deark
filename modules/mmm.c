// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// RIFF Multimedia Movie / RMMP / .MMM

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mmm);

#define CODE_CFTC  0x43465443U
#define CODE_CLUT  0x434c5554U
#define CODE_CURS  0x43555253U
#define CODE_DIB   0x44494220U
#define CODE_McNm  0x4d634e6dU
#define CODE_RIFF  0x52494646U
#define CODE_RMMP  0x524d4d50U
#define CODE_SCVW  0x53435657U
#define CODE_STR   0x53545220U
#define CODE_STXT  0x53545854U
#define CODE_VWAC  0x56574143U
#define CODE_VWCF  0x56574346U
#define CODE_VWCR  0x56574352U
#define CODE_VWFM  0x5657464dU
#define CODE_VWLB  0x56574c42U
#define CODE_VWSC  0x56575343U
#define CODE_VWTL  0x5657544cU
#define CODE_VWtc  0x56577463U
#define CODE_Ver_  0x5665722eU // "Ver."
#define CODE_cftc  0x63667463U
#define CODE_clut  0x636c7574U
#define CODE_dib   0x64696220U
#define CODE_mcnm  0x6d636e6dU
#define CODE_snd   0x736e6420U // Not sure if 'SND' exists
#define CODE_str   0x73747220U
#define CODE_scvw  0x73637677U
#define CODE_stxt  0x73747874U
#define CODE_ver   0x76657220U // "ver "
#define CODE_vwac  0x76776163U
#define CODE_vwcf  0x76776366U
#define CODE_vwcr  0x76776372U
#define CODE_vwfm  0x7677666dU
#define CODE_vwlb  0x76776c62U
#define CODE_vwsc  0x76777363U
#define CODE_vwtc  0x76777463U
#define CODE_vwtl  0x7677746cU

struct mmm_ctx {
	int pass; // 100=reading alt. palette file
	u8 opt_allowbad;
	u8 use_alt_palfile;
	u8 force_pal; // Set if mmm:palid option was used
	int pal_id_to_use; // Valid if mmm:palid option was used
	de_encoding input_encoding;

	u8 errflag;
	u8 suppress_dib_pass2;
	int clut_count;
	int dib_count;

	int tmp_rsrcid;
	u8 have_pal;
	de_ucstring *tmp_namestr;
	de_color pal1[2];
	de_color pal[256];
};

static void mmm_default_pal256(deark *c, struct mmm_ctx *d)
{
	UI i, j, k;
	static const u8 v[6] = {0, 48, 100, 152, 204, 252};

	de_warn(c, "Using a default palette. Colors might be wrong.");

	// Note: This sets pal[40] incorrectly, but it will be fixed later.
	for(i=0; i<6; i++) {
		for(j=0; j<6; j++) {
			for(k=0; k<6; k++) {
				d->pal[40 + i*36 + j*6 + k] = DE_MAKE_RGB(v[i], v[j], v[k]);
			}
		}
	}

	for(i=0; i<=10; i++) {
		d->pal[i] = DE_MAKE_GRAY(i*24);
	}

	for(i=0; i<10; i++) {
		UI t;

		t = 16+24*i;
		if(t>=128) t += 4;
		d->pal[11+i] = DE_MAKE_RGB(0, 0, t);
		d->pal[21+i] = DE_MAKE_RGB(0, t, 0);
		d->pal[31+i] = DE_MAKE_RGB(t, 0, 0);
	}

	d->have_pal = 1;
}

static void mmm_allowbad_note(deark *c)
{
	de_info(c, "Note: Use \"-opt mmm:allowbad\" to extract anyway.");
}

static void mmm_default_pal16(deark *c, struct mmm_ctx *d)
{
	de_make_grayscale_palette(d->pal, 16, 0);
	d->have_pal = 1;

	// TODO: Figure out if there is a default 16-color palette.
	if(d->opt_allowbad) {
		de_warn(c, "No palette found. Colors will be wrong.");
	}
	else {
		de_err(c, "No palette found");
		mmm_allowbad_note(c);
		d->errflag = 1;
	}
}

// Read rsrc id to d->tmp_rsrcid
static void mmm_read_rsrcid_p(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 *ppos, const char *name)
{
	// Note: I can't rule out the possibility that this is a 16-bit field (like
	// in macrsrc format), followed by a 16-bit field that is always either 0
	// or 0xffff. I haven't found any resources for which it would make a
	// difference if we read it as 16-bit.
	d->tmp_rsrcid = (int)dbuf_geti32le_p(ictx->f, ppos);
	de_dbg(c, "%s: %d", (name ? name : "rsrc id"), d->tmp_rsrcid);
}

// Read chunk name to d->tmp_namestr
static void mmm_read_name_p(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 *ppos, const char *name)
{
	i64 pos = *ppos;
	i64 namelen;

	ucstring_empty(d->tmp_namestr);
	namelen = (i64)dbuf_getbyte(ictx->f, pos);
	if(namelen) {
		dbuf_read_to_ucstring(ictx->f, pos+1, namelen, d->tmp_namestr, 0, d->input_encoding);
		de_dbg(c, "%s: \"%s\"", (name ? name : "name"), ucstring_getpsz_d(d->tmp_namestr));
	}
	*ppos += de_pad_to_2(1+namelen);
}

static void do_mmm_mcnm(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 dpos1, i64 dlen)
{
	i64 pos = dpos1+4;

	mmm_read_name_p(c, d, ictx, &pos, "movie name");
}

static void do_mmm_ver(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 dpos1, i64 dlen)
{
	UI ver;

	ver = (UI)dbuf_getu32le(ictx->f, dpos1);
	de_dbg(c, "version: %u", ver);
}

static void do_mmm_cftc(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 dpos1, i64 dlen)
{
	i64 nentries;
	i64 i;
	i64 pos;
	struct de_fourcc tmp4cc;

	if(dlen<4) goto done;
	nentries = (dlen-4)/16;

	pos = dpos1+4;
	for(i=0; i<nentries; i++) {
		int chk_id;
		i64 chk_pos;
		i64 chk_dlen;
		de_zeromem(&tmp4cc, sizeof(struct de_fourcc));
		dbuf_read_fourcc(ictx->f, pos, &tmp4cc, 4, 0);
		pos += 4;
		if(tmp4cc.id==0) break;
		chk_dlen = dbuf_getu32le_p(ictx->f, &pos);
		chk_id = (int)dbuf_geti32le_p(ictx->f, &pos);
		chk_pos = dbuf_getu32le_p(ictx->f, &pos);
		de_dbg(c, "toc entry '%s' id=%d pos=%"I64_FMT" dlen=%"I64_FMT,
			tmp4cc.id_sanitized_sz, chk_id, chk_pos, chk_dlen);
	}

done:
	;
}

// TODO?: This duplicates some code in the macrsrc module.
// What we probably ought to do is generate a macrsrc file containing all the
// cursor and icon resources, and any other suitable resources. But that's
// easier said than done. Macrsrc is a complex format, and some things may
// have been lost in the translation to MMM format.
static void do_mmm_CURS(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	i64 pos = pos1;
	de_bitmap *img_fg = NULL;
	de_bitmap *img_mask = NULL;
	de_finfo *fi = NULL;

	mmm_read_rsrcid_p(c, d, ictx, &pos, NULL);
	mmm_read_name_p(c, d, ictx, &pos, NULL);
	if(pos1+len-pos < 68) goto done;

	fi = de_finfo_create(c);

	img_fg = de_bitmap_create(c, 16, 16, 2);
	img_mask = de_bitmap_create(c, 16, 16, 1);

	de_dbg(c, "foreground at %"I64_FMT, pos);
	de_convert_image_bilevel(c->infile, pos, 2, img_fg, DE_CVTF_WHITEISZERO);
	pos += 32;
	de_dbg(c, "mask at %"I64_FMT, pos);
	de_convert_image_bilevel(c->infile, pos, 2, img_mask, 0);
	pos += 32;
	de_bitmap_apply_mask(img_fg, img_mask, 0);

	fi->hotspot_y = (int)de_geti16be_p(&pos);
	fi->hotspot_x = (int)de_geti16be_p(&pos);
	fi->has_hotspot = 1;
	de_dbg(c, "hotspot: (%d,%d)", fi->hotspot_x, fi->hotspot_y);

	if(ucstring_isnonempty(d->tmp_namestr)) {
		ucstring_append_char(d->tmp_namestr, '.');
	}
	ucstring_append_sz(d->tmp_namestr, "CURS", DE_ENCODING_LATIN1);
	de_finfo_set_name_from_ucstring(c, fi, d->tmp_namestr, 0);
	de_bitmap_write_to_file_finfo(img_fg, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img_fg);
	de_bitmap_destroy(img_mask);
	de_finfo_destroy(c, fi);
}

static void do_mmm_dib(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	i64 pos;
	i64 i_infohdr_pos;
	i64 i_bits_pos;
	i64 infosize;
	i64 i_bits_size;
	i64 o_bits_size;
	i64 i_rowspan;
	i64 k;
	i64 j;
	u8 special_1bpp = 0;
	int ret;
	dbuf *outf = NULL;
	struct de_bmpinfo bi;

	pos = pos1;
	mmm_read_rsrcid_p(c, d, ictx, &pos, "dib id");
	mmm_read_name_p(c, d, ictx, &pos, NULL);
	i_infohdr_pos = pos;

	infosize = dbuf_getu32le(ictx->f, i_infohdr_pos);
	if(infosize<40 || infosize>124) goto done;
	i_bits_pos = i_infohdr_pos + infosize;
	i_bits_size = pos+len-i_bits_pos;

	ret = fmtutil_get_bmpinfo(c, ictx->f, &bi, i_infohdr_pos, infosize, 0);
	if(!ret) goto done;
	if(bi.num_colors > 256) goto done;

	if(bi.bitcount==1) {
		special_1bpp = 1;
	}

	if(special_1bpp) {
		i_rowspan = de_pad_to_n(bi.bitcount*bi.width, 16) / 8;
	}
	else {
		i_rowspan = bi.rowspan;
	}

	if(bi.compression_field==0) {
		o_bits_size = bi.foreground_size;
	}
	else {
		o_bits_size = i_bits_size;
	}

	// color table
	if(bi.bitcount==4 && !d->have_pal) {
		mmm_default_pal16(c, d);
	}
	if(bi.bitcount==8 && !d->have_pal) {
		mmm_default_pal256(c, d);
	}
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// file header
	fmtutil_generate_bmpfileheader(c, outf, &bi,
		14 + infosize + bi.num_colors*4 + o_bits_size);

	// info header
	dbuf_copy(ictx->f, i_infohdr_pos, 20, outf);
	if(special_1bpp) {
		// She biSizeImage field may be wrong, so zero it out.
		dbuf_write_zeroes(outf, 4);
	}
	else {
		dbuf_copy(ictx->f, i_infohdr_pos+20, 4, outf);
	}
	dbuf_copy(ictx->f, i_infohdr_pos+24, infosize-24, outf);

	// color table

	if(bi.bitcount==1) {
		for(k=0; k<2; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal1[k]));
			dbuf_writebyte(outf, 0);
		}
	}
	else if(bi.bitcount<=8) {
		if(bi.num_colors>256) goto done;
		for(k=0; k<bi.num_colors; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal[k]));
			dbuf_writebyte(outf, 0);
		}
	}

	// bits
	if(special_1bpp) {
		for(j=0; j<bi.height; j++) {
			dbuf_copy(ictx->f, i_bits_pos+(bi.height-1-j)*i_rowspan, bi.rowspan, outf);
		}
	}
	else {
		dbuf_copy(ictx->f, i_bits_pos, i_bits_size, outf);
	}

done:
	dbuf_close(outf);
}

static void do_mmm_clut(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 pos1, i64 len)
{
	i64 pos;
	i64 num_entries;
	i64 i;
	int rsrc_id;
	u8 is_correct_pass;
	u8 keep_this_pal = 0;

	pos = pos1;
	mmm_read_rsrcid_p(c, d, ictx, &pos, "pal id");
	rsrc_id = d->tmp_rsrcid;
	mmm_read_name_p(c, d, ictx, &pos, NULL);

	num_entries = (pos1+len-pos)/6;

	de_dbg(c, "palette at %"I64_FMT", %u entries", pos, (UI)num_entries);

	if(num_entries!=16 && num_entries!=256) {
		de_warn(c, "Unsupported type of palette");
		goto done;
	}

	is_correct_pass = (d->pass==1 && !d->use_alt_palfile) ||
		(d->pass==100 && d->use_alt_palfile);

	if(d->force_pal) {
		if(rsrc_id==d->pal_id_to_use && is_correct_pass) {
			keep_this_pal = 1;
		}
	}
	else if(!d->have_pal && is_correct_pass) {
		keep_this_pal = 1;
	}

	de_dbg_indent(c, 1);
	for(i=0; i<num_entries; i++) {
		UI samp[3];
		de_color clr;
		i64 idx;
		UI k;

		idx = num_entries-1-i;

		for(k=0; k<3; k++) {
			samp[k] = (UI)dbuf_getu16be_p(ictx->f, &pos);
			samp[k] = (UI)de_sample_nbit_to_8bit(16, samp[k]);
		}
		clr = DE_MAKE_RGB(samp[0], samp[1], samp[2]);
		de_dbg_pal_entry(c, idx, clr);

		if(keep_this_pal) {
			d->pal[idx] = clr;
		}
	}
	de_dbg_indent(c, -1);
	if(keep_this_pal) {
		d->have_pal = 1;
	}

done:
	d->clut_count++;
}

static int my_mmm_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct mmm_ctx *d = (struct mmm_ctx*)ictx->userdata;
	i64 dpos, dlen;

	dpos = ictx->chunkctx->dpos;
	dlen = ictx->chunkctx->dlen;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_RIFF:
		ictx->is_std_container = 1;
		goto done;
	}

	if(ictx->level != 1) goto done;

	ictx->handled = 1;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_Ver_:
	case CODE_ver:
		if(d->pass==1) {
			do_mmm_ver(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_CFTC:
	case CODE_cftc:
		if(d->pass==1) {
			do_mmm_cftc(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_CLUT:
	case CODE_clut:
		if(d->pass==1 || d->pass==100) {
			do_mmm_clut(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_DIB:
	case CODE_dib:
		if(d->pass==1) {
			d->dib_count++;
		}
		else if(d->pass==2 && !d->suppress_dib_pass2) {
			do_mmm_dib(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_CURS:
		if(d->pass==2) {
			do_mmm_CURS(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_McNm:
	case CODE_mcnm:
		if(d->pass==1) {
			do_mmm_mcnm(c, d, ictx, dpos, dlen);
		}
		break;
	default:
		if(d->pass==1) {
			// Make sure the default behavior only happens in one of the passes
			// (e.g. hexdump if the debug level is set high enough).
			ictx->handled = 0;
		}
	}

done:
	if(d->errflag) return 0;
	return 1;
}

static int looks_like_a_4cc_b(const u8 *buf)
{
	i64 i;

	for(i=0; i<4; i++) {
		if(buf[i]<32 || buf[i]>126) return 0;
	}
	return 1;
}

// A few files are seen to be malformed in the neighborhood of the VWCF chunk,
// having two extra bytes after it that shouldn't be there.
// This is a quick hack to try to handle such files.
// (But this is evidence that we really ought to be relying on the table
// of contents, instead of reading the file sequentially.)
static int my_mmm_handle_nonchunk_data_fn(struct de_iffctx *ictx,
	i64 pos, i64 *plen)
{
	u8 buf[6];

	dbuf_read(ictx->f, buf, pos, sizeof(buf));

	if(buf[0]<65 || buf[1]<65) {
		if(looks_like_a_4cc_b(&buf[2])) {
			*plen = 2;
			de_dbg(ictx->c, "[%"I64_FMT" non-RIFF bytes at %"I64_FMT"]", *plen, pos);
			return 1;
		}
	}

	return 0;
}

static int my_preprocess_mmm_chunk_fn(struct de_iffctx *ictx)
{
	size_t k;
	struct mmmnames_struct {
		u32 id1, id2;
		const char *name;
	};
	static const struct mmmnames_struct mmmnames[] = {
		{ CODE_CFTC, CODE_cftc, "table of contents" },
		{ CODE_CLUT, CODE_clut, "palette" },
		{ CODE_DIB,  CODE_dib,  "bitmap" },
		{ CODE_McNm, CODE_mcnm, "movie name" },
		{ CODE_SCVW, CODE_scvw, "director score" },
		{ CODE_snd,  CODE_snd,  "sound resource" },
		{ CODE_STR,  CODE_str,  "string table" },
		{ CODE_STXT, CODE_stxt, "styled text" },
		{ CODE_Ver_, CODE_ver,  "converter version" },
		{ CODE_VWAC, CODE_vwac, "script commands" },
		{ CODE_VWCF, CODE_vwcf, "movie config" },
		{ CODE_VWCR, CODE_vwcr, "cast record array" },
		{ CODE_VWFM, CODE_vwfm, "font mapping" },
		{ CODE_VWLB, CODE_vwlb, "label list" },
		{ CODE_VWSC, CODE_vwsc, "movie score" },
		{ CODE_VWtc, CODE_vwtc, "timecode" },
		{ CODE_VWTL, CODE_vwtl, "pixel pattern tile" }
		// Other known chunks: VWFI vwfi VWCI vwci
		// crsr CURS FOND fwst
		// icl4 icl8 ICN# ics# ics4 ics8
		// NFNT pict vers XCMD XCOD XFCN
	};

	for(k=0; k<DE_ARRAYCOUNT(mmmnames); k++) {
		if((ictx->chunkctx->chunk4cc.id == mmmnames[k].id1) ||
			(ictx->chunkctx->chunk4cc.id == mmmnames[k].id2))
		{
			ictx->chunkctx->chunk_name = mmmnames[k].name;
			break;
		}
	}
	return 1;
}

static void setup_ictx_for_mmm(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx)
{
	ictx->userdata = (void*)d;
	ictx->is_le = 1;
	ictx->handle_chunk_fn = my_mmm_chunk_handler;
	ictx->handle_nonchunk_data_fn = my_mmm_handle_nonchunk_data_fn;
	ictx->preprocess_chunk_fn = my_preprocess_mmm_chunk_fn;
}

static int read_alt_palette_file(deark *c, struct mmm_ctx *d)
{
	dbuf *palfile = NULL;
	struct de_iffctx *ictx = NULL;
	const char *palfn;
	int retval = 1;

	palfn = de_get_ext_option(c, "file2");
	if(!palfn) {
		goto done;
	}

	d->use_alt_palfile = 1;
	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) {
		retval = 0;
		goto done;
	}

	ictx = fmtutil_create_iff_decoder(c);
	setup_ictx_for_mmm(c, d, ictx);
	ictx->f = palfile;

	d->pass = 100;
	de_dbg(c, "reading alt pal file");
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, palfile->len);
	de_dbg_indent(c, -1);

	if(!d->have_pal) {
		if(d->force_pal) {
			de_err(c, "Palette %d not found", d->pal_id_to_use);
		}
		else {
			de_err(c, "No palette found");
		}
		retval = 0;
		goto done;
	}

done:
	fmtutil_destroy_iff_decoder(ictx);
	dbuf_close(palfile);

	// (hack) Reset some things that this function isn't supposed to change.
	d->errflag = 0;
	d->clut_count = 0;
	d->dib_count = 0;

	return retval;
}

static void de_run_mmm(deark *c, de_module_params *mparams)
{
	struct mmm_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *s;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct mmm_ctx));
	d->input_encoding = de_get_input_encoding(c, mparams, DE_ENCODING_ASCII);
	d->opt_allowbad = (u8)de_get_ext_option_bool(c, "mmm:allowbad", 0);
	s = de_get_ext_option(c, "mmm:palid");
	if(s) {
		d->pal_id_to_use = de_atoi(s);
		d->force_pal = 1;
	}

	d->tmp_namestr = ucstring_create(c);

	d->pal1[0] = DE_STOCKCOLOR_BLACK;
	d->pal1[1] = DE_STOCKCOLOR_WHITE;

	if(!read_alt_palette_file(c, d)) goto done;

	ictx = fmtutil_create_iff_decoder(c);
	setup_ictx_for_mmm(c, d, ictx);
	ictx->f = c->infile;

	d->pass = 1;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);
	if(d->errflag) goto done;

	if(d->force_pal && !d->have_pal && !d->opt_allowbad) {
		de_err(c, "Palette %d not found", d->pal_id_to_use);
		goto done;
	}

	if(d->clut_count>1 && d->dib_count>0 && !d->opt_allowbad && !d->force_pal) {
		de_err(c, "Multiple palettes found (not supported, "
			"or try \"-opt mmm:palid=...\").");
		mmm_allowbad_note(c);
		d->suppress_dib_pass2 = 1;
	}

	d->pass = 2;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);

done:
	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		de_dbg(c, "dib count: %d", d->dib_count);
		de_dbg(c, "clut count: %d", d->clut_count);
		ucstring_destroy(d->tmp_namestr);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_mmm(deark *c)
{
	if((u32)de_getu32be(0)!=CODE_RIFF) return 0;
	if((u32)de_getu32be(8)!=CODE_RMMP) return 0;
	return 100;
}

static void de_help_mmm(deark *c)
{
	de_msg(c, "-file2 <file.mmm> : File to read the palette from");
	de_msg(c, "-opt mmm:palid=<id> : Use this palette");
	de_msg(c, "-opt mmm:allowbad : Keep going after certain errors");

	// file2 with palid: Use that id in file2 if it exists, otherwise fatal error.
	// file2 w/o palid: Use the first palette in file2 if it exists, otherwise fatal error.
	// palid w/o file2: Use that id if it exists, otherwise fatal error.
	// neither: (not explained here)
}

void de_module_mmm(deark *c, struct deark_module_info *mi)
{
	mi->id = "mmm";
	mi->desc = "RIFF Multimedia Movie";
	mi->run_fn = de_run_mmm;
	mi->identify_fn = de_identify_mmm;
	mi->help_fn = de_help_mmm;
	// Status: Many images work correctly. Others have the wrong colors.
	// Improvements are probably possible, but only up to a point. This
	// is just a resource format; the correct color table might, for
	// example, be in a different file.
	mi->flags |= DE_MODFLAG_NONWORKING;
}
