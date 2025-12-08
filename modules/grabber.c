// This file is part of Deark.
// Copyright (C) 2024-2025 Jason Summers
// See the file COPYING for terms of use.

// GRABBER self-displaying screen capture

// Note: This module is highly experimental, and might never support
// very many of the large number of GRABBER formats.

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_grabber);

struct grabber_id_data {
	u8 is_grabber;
	UI fmt_class; // A representative version, times 10
	i64 jmppos;
};

#define GR_CMPR_NONE     0
#define GR_CMPR_PCX      1
#define GR_CMPR_PCPAINT  2
#define GR_CMPR_RLE360   3
#define GR_CMPR_TEXT360  4

typedef struct localctx_grabber {
	u8 is_exe;
	u8 errflag;
	u8 need_errmsg;
	UI exe_approx_ver;

	u8 screen_mode;
	u8 screen_mode2;
	u8 pal_info;
	i64 hdrpos;
	i64 data_infile_pos, data_infile_len;
	i64 data_dcmpr_len;
	u8 cmpr_meth;
	dbuf *data_f;
	i64 data_f_pos, data_f_len;
	de_finfo *fi;

	u8 file_structure_supported;
	i64 pos_of_mode; // May be for COM only
	i64 reported_w, reported_h;
	i64 reported_w_in_chars, reported_h_in_chars;

	struct de_char_context *charctx;
	struct fmtutil_char_simplectx csctx;
	struct grabber_id_data gi;

	struct fmtutil_exe_info ei;
	struct fmtutil_specialexe_detection_data edd;

	de_color pal[256];
	de_color pal2[256];
} lctx;

struct de_v360comp1_params {
	u8 textmode;
	i64 num_fg_bytes; // Used if textmode
};

// codec_private_params: struct de_v360comp1_params
static void v360comp1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	i64 inf_pos = dcmpri->pos;
	i64 inf_endpos = dcmpri->pos + dcmpri->len;
	i64 nbytes_decompressed = 0;
	struct de_bitbuf_lowlevel *bbll = NULL;
	i64 count;
	u8 in_attr = 0;
	u8 n;
	u8 x;
	u8 b0;
	struct de_v360comp1_params *v360c1p =
		(struct de_v360comp1_params*)codec_private_params;

	bbll = de_malloc(c, sizeof(struct de_bitbuf_lowlevel));
	bbll->is_lsb = 1;

	while(1) {
		if(inf_pos >= inf_endpos) goto done;
		if(dcmpro->len_known && nbytes_decompressed>=dcmpro->expected_len) goto done;

		if(bbll->nbits_in_bitbuf==0) {
			n = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			de_bitbuf_lowlevel_add_byte(bbll, n);
		}

		if(v360c1p->textmode && in_attr==0 &&
			nbytes_decompressed>=v360c1p->num_fg_bytes)
		{
			in_attr = 1;

			de_dbg(c, "attribs pos: %"I64_FMT, inf_pos);
			// Should be a 6-byte marker here.
			if(dbuf_memcmp(dcmpri->f, inf_pos, (const u8*)"\x00\x00RG\x00\x00", 6)) {
				de_dfilter_set_generic_error(c, dres, NULL);
				goto done;
			}
			inf_pos += 6;

			de_bitbuf_lowlevel_empty(bbll);
			n = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			de_bitbuf_lowlevel_add_byte(bbll, n);
		}

		x = (u8)de_bitbuf_lowlevel_get_bits(bbll, 1);
		if(x) { // a run
			count = (i64)dbuf_getbyte_p(dcmpri->f, &inf_pos);
			b0 = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			dbuf_write_run(dcmpro->f, b0, count);
			nbytes_decompressed += count;
		}
		else { // a literal byte
			b0 = dbuf_getbyte_p(dcmpri->f, &inf_pos);
			dbuf_writebyte(dcmpro->f, b0);
			nbytes_decompressed++;
		}

	}

done:
	dbuf_flush(dcmpro->f);
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = inf_pos - dcmpri->pos;
	de_free(c, bbll);
}

static void free_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_finfo_destroy(c, d->fi);
	de_free_charctx(c, d->charctx);
	de_free(c, d);
}

static void gr_decompress_any(deark *c, lctx *d,
	UI cmpr_meth,
	i64 cmpr_pos, i64 cmpr_len, dbuf *unc_data,
	i64 num_dcmpr_bytes_expected)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_v360comp1_params v360c1p;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = cmpr_pos;
	dcmpri.len = cmpr_len;
	dcmpro.f = unc_data;
	dcmpro.len_known = 1;
	dcmpro.expected_len = num_dcmpr_bytes_expected;

	de_dbg(c, "[decompressing]");
	de_dbg_indent(c, 1);
	if(cmpr_meth==GR_CMPR_PCPAINT) {
		struct de_pcpaint_rle_params *pcpp;

		pcpp = de_malloc(c, sizeof(struct de_pcpaint_rle_params));
		fmtutil_pcpaintrle_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)pcpp);
		de_free(c, pcpp);
	}
	else if(cmpr_meth==GR_CMPR_PCX) {
		fmtutil_pcxrle_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	}
	else if(cmpr_meth==GR_CMPR_RLE360) {
		v360c1p.textmode = 0;
		v360c1p.num_fg_bytes = 0;
		v360comp1_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&v360c1p);
	}
	else if(cmpr_meth==GR_CMPR_TEXT360) {
		v360c1p.textmode = 1;
		v360c1p.num_fg_bytes = num_dcmpr_bytes_expected / 2;
		v360comp1_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&v360c1p);
	}
	else {
		de_dfilter_set_generic_error(c, &dres, NULL);
	}

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		d->errflag = 1;
		goto done;
	}
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes",
		dres.bytes_consumed, unc_data->len);
done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_grabber_palette(deark *c, lctx *d, i64 pos1, i64 num_entries,
	de_color *pal)
{
	de_read_simple_palette(c, c->infile, pos1, num_entries, 3,
		pal, 256, DE_RDPALTYPE_VGA18BIT, 0);
}

static void read_grabber_pal_vga16(deark *c, lctx *d, UI ncolors)
{
	i64 pal1pos;
	i64 i;
	char tmps[32];

	if(ncolors>16) return;
	pal1pos = d->hdrpos + 2;
	de_dbg(c, "palette at %"I64_FMT, pal1pos);
	de_dbg_indent(c, 1);
	for(i=0; i<(i64)ncolors; i++) {
		u8 p1;

		p1 = de_getbyte(pal1pos+i);
		d->pal[i] = d->pal2[(UI)p1];
		de_snprintf(tmps, sizeof(tmps), "%2u ", (UI)p1);
		de_dbg_pal_entry2(c, i, d->pal[i], tmps, NULL, NULL);
	}
	de_dbg_indent(c, -1);
}

static void grabber_id_com(deark *c, u8 b0, struct grabber_id_data *gi)
{
	u8 b;

	de_zeromem(gi, sizeof(struct grabber_id_data));

	if(b0==0xfb) {
		if(!dbuf_memcmp(c->infile, 1,
			(const void*)"\xbe\x81\x00\x8a\x4c\xff\x30\xed\x09\xc9\x74", 11)) {
			gi->is_grabber = 1;
			gi->fmt_class = 2000;
		}
		return;
	}

	if(b0!=0xe9) return;
	gi->jmppos = de_geti16le(1) + 3;

	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xad\x80\xfc\x0d\x74\x17\x3c\x0d\x74", 12))
	{
		gi->is_grabber = 1;
		b = de_getbyte(gi->jmppos+22);
		if(b==0x04) {
			gi->fmt_class = 3000; // 3.00-3.20
		}
		else {
			gi->fmt_class = 3201; // 3.20K-3.30
		}
		return;
	}
	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xfc\xad\x80\xfc\x0d\x74\x1c\x3c\x0d\x74", 13))
	{
		gi->is_grabber = 1;
		gi->fmt_class = 3340;
		return;
	}
}

static void decode_grabber_com(deark *c, lctx *d)
{
	i64 foundpos = 0;
	i64 pos_of_data_ptr;
	i64 pos_of_mode;
	u8 maybe_ch = 0;
	u8 maybe_cw = 0;
	u8 adj_mode = 0xff;
	int ret;
	u8 *mem = NULL;

#define GRABBER_SEARCH1_START 112
#define GRABBER_BUF_LEN1 1024
	mem = de_malloc(c, GRABBER_BUF_LEN1);
	de_read(mem, GRABBER_SEARCH1_START, GRABBER_BUF_LEN1);
	// Search for the byte pattern preceding the data pointer.
	// Known positions range from 121 (v2.10) to 869 (v3.34).
	ret = de_memsearch_match(mem, GRABBER_BUF_LEN1,
		(const u8*)"\xb8\x00?\x8e\xc0\xbe", 6,
		'?', &foundpos);
	if(!ret) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	pos_of_data_ptr = foundpos+GRABBER_SEARCH1_START+6;
	de_dbg(c, "pos of data ptr: %"I64_FMT, pos_of_data_ptr);

	d->data_infile_pos = de_getu16le(pos_of_data_ptr);
	d->data_infile_pos -= 256;
	de_dbg(c, "data pos: %"I64_FMT, d->data_infile_pos);

	if(d->gi.fmt_class<3000) {
		pos_of_mode = d->data_infile_pos - 7;
	}
	else {
		pos_of_mode = d->data_infile_pos - 17;
	}

	if(d->gi.fmt_class>=3201 && d->gi.fmt_class<3500) {
		maybe_ch = de_getbyte(pos_of_mode-2);
		maybe_cw = de_getbyte(pos_of_mode-1);
		de_dbg(c, "dimensions in chars: %u"DE_CHAR_TIMES"%u", maybe_cw, maybe_ch);
	}

	d->screen_mode = de_getbyte(pos_of_mode);
	de_dbg(c, "mode: 0x%02x", (UI)d->screen_mode);

	if(d->screen_mode==4) {
		d->pal_info = de_getbyte(pos_of_mode+1);
		de_dbg(c, "palette info: 0x%02x", (UI)d->pal_info);
	}
	else if(d->screen_mode==5) {
		d->pal_info = 0x30;
	}

	d->data_infile_len = de_getu16le(pos_of_mode+2);
	de_dbg(c, "data len: %"I64_FMT, d->data_infile_len);
	d->cmpr_meth = GR_CMPR_NONE;
	d->data_dcmpr_len = d->data_infile_len;

	// Some files, including the DEMO*.COM files from v3.3, have mode=2.
	// I don't know where this comes from (TODO).
	// I think mode 2 should be some b/w text mode, but it seems to work the
	// same as mode 3.
	// AFAICT, the mode field definitely *is* related to the screen mode, and
	// it *is* used by the viewer. But it seems to be more like a hint as to
	// which viewer routine to call, than the literal screen mode.
	if(d->screen_mode==2 && d->data_dcmpr_len==4000) {
		adj_mode = 3;
	}
	if(adj_mode!=0xff && adj_mode!=d->screen_mode) {
		de_dbg(c, "[adjusting mode to %u]", (UI)adj_mode);
		d->screen_mode = adj_mode;
	}

done:
	de_free(c, mem);
}

static void do_grabber_textmode(deark *c, lctx *d)
{
	if(d->reported_w_in_chars) {
		d->csctx.width_in_chars = d->reported_w_in_chars;
	}
	else if(d->screen_mode==1) {
		d->csctx.width_in_chars = 40;
	}
	else {
		d->csctx.width_in_chars = 80;
	}
	d->charctx->screen_image_flag = 1;

	if(d->reported_h_in_chars) {
		d->csctx.height_in_chars = d->reported_h_in_chars;
	}
	else {
		d->csctx.height_in_chars = de_pad_to_n(d->data_f_len, d->csctx.width_in_chars*2) /
			(d->csctx.width_in_chars*2);
	}

	de_dbg(c, "screen size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->csctx.width_in_chars,
		d->csctx.height_in_chars);
	if(d->data_f_pos+d->data_f_len > d->data_f->len) {
		d->need_errmsg = 1;
		goto done;
	}

	// TODO: Set the density sensibly for 40x25 mode.
	if(d->csctx.width_in_chars!=80 || d->csctx.height_in_chars>25) {
		d->charctx->no_density = 1;
	}

	d->csctx.use_default_pal = 1;
	d->csctx.inf = d->data_f;
	d->csctx.inf_pos = d->data_f_pos;
	d->csctx.inf_len = d->data_f_len;
	fmtutil_char_simple_run(c, &d->csctx, d->charctx);
done:
	;
}

static void read_and_deinterlace_cga(deark *c, dbuf *inf, i64 pos1, dbuf *outf)
{
	i64 j;

	for(j=0; j<200; j++) {
		i64 spos;

		spos = pos1 + (j/2)*80 + (j%2)*8192;
		dbuf_copy(inf, spos, 80, outf);
	}
}

static void do_grabber_cga(deark *c, lctx *d, u8 is_interlaced)
{
	de_bitmap *img = NULL;
	dbuf *tmpf = NULL;
	UI createflags = 0;

	tmpf = dbuf_create_membuf(c, 16384, 0);
	if(is_interlaced) {
		read_and_deinterlace_cga(c, d->data_f, d->data_f_pos, tmpf);
	}
	else {
		dbuf_copy(d->data_f, d->data_f_pos, 16384, tmpf);
	}

	d->fi->density.code = DE_DENSITY_UNK_UNITS;

	if(d->screen_mode==6) {
		d->fi->density.xdens = 480.0;
		d->fi->density.ydens = 200.0;
		img = de_bitmap_create(c, 640, 200, 1);
		de_convert_image_bilevel(tmpf, 0, 80, img, 0);
		createflags |= DE_CREATEFLAG_IS_BWIMG;
	}
	else {
		int pal_subid = 3;

		d->fi->density.xdens = 240.0;
		d->fi->density.ydens = 200.0;

		// Intended to reflect how the file actually displays itself (on a
		// system with CGA-only graphics, in case it made a difference).
		// I.e., not necessarily the image that should have been captured.
		// GRABBER seems buggy, but I guess we'll copy the bugs.
		if((d->is_exe && d->gi.fmt_class>=3700) ||
			(!d->is_exe && d->gi.fmt_class<=3200))
		{
			switch((d->pal_info & 0x30)>>4) {
			case 0: pal_subid = 1; break;
			case 1: pal_subid = 4; break;
			case 2: pal_subid = 0; break;
			case 3: pal_subid = 3; break;
			}
		}
		else { // v3.20K-3.35
			pal_subid = (d->pal_info & 0x10)?0:1;
		}
		de_copy_std_palette(DE_PALID_CGA, pal_subid, 0, d->pal, 256, 0);
		d->pal[0] = de_get_std_palette_entry(DE_PALID_PC16, 0, (d->pal_info & 0x0f));

		img = de_bitmap_create(c, 320, 200, 3);
		de_convert_image_paletted(tmpf, 0, 2, 80, d->pal, img, 0);
	}

	de_bitmap_write_to_file_finfo(img, d->fi, createflags);

	de_bitmap_destroy(img);
	dbuf_close(tmpf);
}

static void do_grabber_v370_cga(deark *c, lctx *d)
{
	i64 num_dcmpr_bytes_expected;
	dbuf *tmpf = NULL;

	if(d->screen_mode==4 || d->screen_mode==5 || d->screen_mode==6) {
		;
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}

	num_dcmpr_bytes_expected = 16384;
	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	gr_decompress_any(c, d, GR_CMPR_PCX, d->data_infile_pos, d->data_infile_len,
		tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;
	d->data_f = tmpf;
	d->data_f_pos = 0;
	d->data_f_len = tmpf->len;
	do_grabber_cga(c, d, 0);

done:
	dbuf_close(tmpf);
}

static void rearrange_cmpr_text(deark *c, lctx *d, dbuf *unc_data)
{
	dbuf *tmp2 = NULL;
	i64 chars_per_line;
	i64 pos_1;

	chars_per_line = d->reported_w_in_chars;
	tmp2 = dbuf_create_membuf(c, unc_data->len, 0);
	dbuf_enable_wbuffer(tmp2);

	pos_1 = 0;
	while(1) {
		i64 k;

		if(pos_1 >= unc_data->len) break;
		for(k=0; k<chars_per_line; k++) {
			u8 fg, attr;

			fg = dbuf_getbyte(unc_data, pos_1+k);
			attr = dbuf_getbyte(unc_data, pos_1+k+chars_per_line);
			dbuf_writebyte(tmp2, fg);
			dbuf_writebyte(tmp2, attr);
		}
		pos_1 += chars_per_line*2;
	}

	dbuf_flush(tmp2);
	dbuf_empty(unc_data);
	dbuf_copy(tmp2, 0, tmp2->len, unc_data);

	dbuf_close(tmp2);
	dbuf_flush(unc_data);
}

static void rearrange_cmpr_text_360(deark *c, lctx *d, dbuf *unc_data)
{
	dbuf *tmp2 = NULL;
	i64 attr_stride;
	i64 k;

	attr_stride = d->reported_w_in_chars * d->reported_h_in_chars;
	tmp2 = dbuf_create_membuf(c, unc_data->len, 0);
	dbuf_enable_wbuffer(tmp2);

	for(k=0; k<attr_stride; k++) {
		u8 fg, attr;

		fg = dbuf_getbyte(unc_data, k);
		attr = dbuf_getbyte(unc_data, k+attr_stride);
		dbuf_writebyte(tmp2, fg);
		dbuf_writebyte(tmp2, attr);
	}

	dbuf_flush(tmp2);
	dbuf_empty(unc_data);
	dbuf_copy(tmp2, 0, tmp2->len, unc_data);

	dbuf_close(tmp2);
	dbuf_flush(unc_data);
}

static void do_grabber_v370_textmode(deark *c, lctx *d)
{
	i64 num_dcmpr_bytes_expected;
	dbuf *tmpf = NULL;

	num_dcmpr_bytes_expected = d->reported_h_in_chars*d->reported_w_in_chars*2;
	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	gr_decompress_any(c, d, GR_CMPR_PCX, d->data_infile_pos, d->data_infile_len,
		tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;

	rearrange_cmpr_text(c, d, tmpf);

	d->data_f = tmpf;
	d->data_f_pos = 0;
	d->data_f_len = tmpf->len;
	do_grabber_textmode(c, d);

done:
	dbuf_close(tmpf);
}

static void do_grabber_v360_cga(deark *c, lctx *d)
{
	i64 num_dcmpr_bytes_expected;
	dbuf *tmpf = NULL;

	num_dcmpr_bytes_expected = 16384;
	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	gr_decompress_any(c, d, GR_CMPR_RLE360, d->data_infile_pos, d->data_infile_len,
		tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;

	d->data_f = tmpf;
	d->data_f_pos = 0;
	d->data_f_len = tmpf->len;
	do_grabber_cga(c, d, 1);

done:
	dbuf_close(tmpf);
}

static void do_grabber_v360_textmode(deark *c, lctx *d)
{
	i64 num_dcmpr_bytes_expected;
	dbuf *tmpf = NULL;

	num_dcmpr_bytes_expected = d->reported_h_in_chars*d->reported_w_in_chars*2;
	// Or should we use data_ori_len?

	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	gr_decompress_any(c, d, GR_CMPR_TEXT360, d->data_infile_pos, d->data_infile_len,
		tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;

	rearrange_cmpr_text_360(c, d, tmpf);

	d->data_f = tmpf;
	d->data_f_pos = 0;
	d->data_f_len = tmpf->len;
	do_grabber_textmode(c, d);

done:
	dbuf_close(tmpf);
}

static void do_grabber_v370_vga(deark *c, lctx *d)
{
	i64 num_dcmpr_bytes_expected;
	dbuf *tmpf = NULL;
	de_bitmap *img = NULL;
	i64 bpp = 1;
	i64 bprpp = 1;
	i64 rowspan = 1;
	UI ncolors = 0;

	if(d->screen_mode2==0x44) {
		if(d->screen_mode==0x8f || d->screen_mode==0x91) {
			bpp = 1;
		}
		else {
			bpp = 4;
		}
		bprpp = de_pad_to_n(d->reported_w, 8)/8;
		rowspan = bprpp * bpp;
	}
	else if(d->screen_mode2==0x55) {
		bpp = 8;
		rowspan = d->reported_w;
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}

	ncolors = 1 << (UI)bpp;

	if(d->screen_mode2==0x44) {
		if(d->screen_mode & 0x80) {
			read_grabber_palette(c, d, d->data_infile_pos-768, 64, d->pal2);
		}
		else {
			de_copy_std_palette(DE_PALID_EGA64, 0, 0, d->pal2, 64, 0);
		}
		read_grabber_pal_vga16(c, d, ncolors);
	}
	else {
		read_grabber_palette(c, d, d->data_infile_pos-768, 256, d->pal);
	}

	num_dcmpr_bytes_expected = rowspan * d->reported_h;
	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	gr_decompress_any(c, d, GR_CMPR_PCPAINT, d->data_infile_pos, d->data_infile_len,
		tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;

	d->fi->density.code = DE_DENSITY_UNK_UNITS;

	if(d->reported_w==320 || d->reported_w==640 || d->reported_w==800 ||
		d->reported_w==1024)
	{
		d->fi->density.xdens = (double)d->reported_w*0.75;
		d->fi->density.ydens = (double)d->reported_h;
	}

	img = de_bitmap_create(c, d->reported_w, d->reported_h, 3);
	if(d->screen_mode2==0x44) {
		de_convert_image_paletted_planar(tmpf, 0, bpp, rowspan, bprpp, d->pal,
			img, 0x2);
	}
	else {
		de_convert_image_paletted(tmpf, 0, bpp, rowspan, d->pal, img, 0);
	}
	de_bitmap_write_to_file_finfo(img, d->fi, 0);

done:
	dbuf_close(tmpf);
	de_bitmap_destroy(img);
}

static void do_grabber_com(deark *c, lctx *d, de_module_params *mparams, u8 b0)
{
	grabber_id_com(c, b0, &d->gi);
	if(!d->gi.is_grabber) {
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "format class: %u", d->gi.fmt_class);
	decode_grabber_com(c, d);
	if(d->errflag) goto done;

	if(d->screen_mode==1 || d->screen_mode==3) {
		d->data_f = c->infile;
		d->data_f_pos = d->data_infile_pos;
		d->data_f_len = d->data_infile_len;
		do_grabber_textmode(c, d);
	}
	else if(d->screen_mode==4 || d->screen_mode==5 || d->screen_mode==6) {
		d->data_f = c->infile;
		d->data_f_pos = d->data_infile_pos;
		d->data_f_len = d->data_infile_len;
		do_grabber_cga(c, d, 1);
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	;
}

struct grabber_exe_id_item {
	const u8* marker;
	u16 marker_len;
	u16 approx_ver;
};
static const struct grabber_exe_id_item grabber_exe_id_arr[] = {
	{ (const u8*)"GR72464630", 10, 3700 },
	{ (const u8*)"G5\x8b\xf1\x53\x85\xc7\x13\x04\xb5\xf1", 11, 3910 },
	{ (const u8*)"G5\x8b\xf1\x53\x85\xc7\x13\x04\xd4\xd6", 11, 3900 },
	{ (const u8*)"G5\x8b\xf1\x53\x90\xbc\x13\x04\xd4\xd6", 11, 3800 },
	{ (const u8*)"G5\x27\xf1\x53\x90\xbc\x13\x04\xd4", 10, 3770 },
	{ (const u8*)"\x77\x02\x2c\x20\xaa\xeb\xee\x07\x1f\xc3", 10, 3600 }
};

// If successful, sets d->file_structure_supported
static void analyze_grabber_exe(deark *c, lctx *d)
{
	u8 *mem = NULL;
	size_t i;
	u8 found_flag = 0;
	size_t found_idx = 0;
	i64 foundpos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
#define GRABBER_HLEN   16384
	mem = de_malloc(c, GRABBER_HLEN);
	dbuf_read(c->infile, mem, 0, GRABBER_HLEN);

	for(i=0; i<DE_ARRAYCOUNT(grabber_exe_id_arr); i++) {
		int ret;

		ret = de_memsearch(mem, GRABBER_HLEN, grabber_exe_id_arr[i].marker,
			grabber_exe_id_arr[i].marker_len, &foundpos, 0);
		if(ret) {
			found_flag = 1;
			found_idx = i;
			break;
		}
	}

	if(!found_flag) {
		de_dbg(c, "[no marker found]");
		goto done;
	}

	d->exe_approx_ver = (UI)grabber_exe_id_arr[found_idx].approx_ver;
	de_dbg(c, "found marker type %u at %"I64_FMT,
		d->exe_approx_ver, foundpos);

	if(d->exe_approx_ver==3600) {
		i64 pos_of_mode;

		pos_of_mode = foundpos + grabber_exe_id_arr[found_idx].marker_len + 2;
		d->reported_h = (i64)de_getbyte(pos_of_mode-2);
		d->reported_w = (i64)de_getbyte(pos_of_mode-1);
		de_dbg(c, "dimensions in chars: %u"DE_CHAR_TIMES"%u", (UI)d->reported_w,
			(UI)d->reported_h);

		d->screen_mode = de_getbyte(pos_of_mode);
		de_dbg(c, "mode: 0x%02x", (UI)d->screen_mode);

		if(d->screen_mode==4) {
			d->pal_info = de_getbyte(pos_of_mode+1);
			de_dbg(c, "palette info: 0x%02x", (UI)d->pal_info);
		}

		d->data_infile_len = de_getu16le(pos_of_mode+2);
		de_dbg(c, "orig data len: %"I64_FMT, d->data_infile_len);

		d->data_infile_pos = pos_of_mode+17;
		de_dbg(c, "data pos: %"I64_FMT, d->data_infile_pos);
		d->data_infile_len = c->infile->len - d->data_infile_pos;
		d->file_structure_supported = 1;
		d->gi.fmt_class = d->exe_approx_ver;
	}
	else if(d->exe_approx_ver>=3700) {
		d->file_structure_supported = 1;
		d->gi.fmt_class = d->exe_approx_ver;
		d->hdrpos = foundpos + grabber_exe_id_arr[found_idx].marker_len;
		de_dbg(c, "header at %"I64_FMT, d->hdrpos);
		de_dbg_indent(c, 1);
		d->screen_mode2 = de_getbyte(d->hdrpos);
		d->screen_mode = de_getbyte(d->hdrpos+1);
		de_dbg(c, "mode: %02x:%02x", (UI)d->screen_mode2, (UI)d->screen_mode);

		if(d->screen_mode==4 || d->screen_mode==5) {
			d->pal_info = de_getbyte(d->hdrpos+2);
			de_dbg(c, "palette info: 0x%02x", (UI)d->pal_info);
		}

		d->reported_w = de_getu16le(d->hdrpos+19);
		d->reported_h = de_getu16le(d->hdrpos+21);
		de_dbg(c, "size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->reported_w, d->reported_h);

		d->data_infile_pos = de_getu16le(d->hdrpos+36);
		de_dbg(c, "data pos: %"I64_FMT, d->data_infile_pos);
		d->data_infile_len = c->infile->len - d->data_infile_pos;
	}

done:
	de_free(c, mem);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_grabber_exe(deark *c, lctx *d, de_module_params *mparams)
{
	u8 img_fmt_supported = 0;

	d->is_exe = 1;
	fmtutil_collect_exe_info(c, c->infile, &d->ei);
	d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_GRABBER;
	fmtutil_detect_specialexe(c, &d->ei, &d->edd);
	if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_GRABBER) {
		de_err(c, "Not a known GRABBER format");
		goto done;
	}

	analyze_grabber_exe(c, d);
	if(!d->file_structure_supported) {
		d->need_errmsg = 1;
		goto done;
	}

	if(d->exe_approx_ver>=3700) {
		if(d->screen_mode2==0x11) {
			if(((d->screen_mode==4 || d->screen_mode==5) && d->reported_w==320 && d->reported_h==200) ||
				(d->screen_mode==6 && d->reported_w==640 && d->reported_h==200))
			{
				img_fmt_supported = 1;
			}
		}
		else if(d->screen_mode2==0x33) {
			if(d->screen_mode<=0x03) {
				img_fmt_supported = 1;
				d->reported_w_in_chars = d->reported_w;
				d->reported_h_in_chars = d->reported_h;
			}
		}
		else if(d->screen_mode2==0x44) {
			// EGA/VGA 2 or 16 color
			switch(d->screen_mode) {
				// TODO: I don't want to have to enumerate these modes, but I don't
				// know how to tell whether an unknown mode is 2 color, or 16 color.
				// There's two bytes at hdrpos+41 that seem relevant, but I
				// couldn't make it work.
			case 0x10: case 0x8d: case 0x8e: case 0x8f:
			case 0x90: case 0x91: case 0x92: case 0xb7:
				img_fmt_supported = 1;
			}
		}
		else if(d->screen_mode2==0x55) {
			// VGA 256-color
			// I haven't found any images that don't work, so (for now) we won't
			// whitelist ->screen_mode.
			// Modes tested: 93 ae b0 b8 dc dd df ff
			img_fmt_supported = 1;
		}
	}
	else if(d->exe_approx_ver==3600) {
		if(d->screen_mode==0x03) {
			img_fmt_supported = 1;
			d->reported_w_in_chars = d->reported_w;
			d->reported_h_in_chars = d->reported_h;
		}
		else if(d->screen_mode==0x04 || d->screen_mode==0x06) {
			img_fmt_supported = 1;
		}
	}

	if(!img_fmt_supported) {
		d->need_errmsg = 1;
		goto done;
	}

	if(!de_good_image_dimensions(c, d->reported_w, d->reported_h)) {
		goto done;
	}

	if(d->exe_approx_ver==3600) {
		if(d->screen_mode==0x03) {
			do_grabber_v360_textmode(c, d);
		}
		else if(d->screen_mode==0x04 || d->screen_mode==0x06) {
			do_grabber_v360_cga(c, d);
		}
		else {
			d->need_errmsg = 1;
		}
		goto done;
	}

	if(d->screen_mode2==0x11) {
		do_grabber_v370_cga(c, d);
	}
	else if(d->screen_mode2==0x33) {
		do_grabber_v370_textmode(c, d);
	}
	else if(d->screen_mode2==0x44 || d->screen_mode2==0x55) {
		do_grabber_v370_vga(c, d);
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}

done:
	;
}

static void de_run_grabber(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI sig;

	d = de_malloc(c, sizeof(lctx));
	d->charctx = de_create_charctx(c, 0);
	d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->fi = de_finfo_create(c);

	sig = (UI)de_getu16le(0);
	if(sig==0x5a4d || sig==0x4d5a) {
		do_grabber_exe(c, d, mparams);
	}
	else {
		do_grabber_com(c, d, mparams, (sig&0xff));
	}

	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Unsupported GRABBER format");
		}
		free_lctx(c, d);
	}
}

static int de_identify_grabber(deark *c)
{
	struct grabber_id_data gi;
	u8 b0;

	if(c->infile->len>65280) return 0;
	b0 = de_getbyte(0);
	if(b0!=0xe9 && b0!=0xfb) return 0;

	grabber_id_com(c, b0, &gi);
	if(gi.is_grabber) return 100;
	return 0;
}

void de_module_grabber(deark *c, struct deark_module_info *mi)
{
	mi->id = "grabber";
	mi->desc = "GRABBER";
	mi->run_fn = de_run_grabber;
	mi->identify_fn = de_identify_grabber;
}
