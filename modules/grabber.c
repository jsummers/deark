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

typedef struct localctx_grabber {
	u8 errflag;
	u8 need_errmsg;

	u8 screen_mode;
	u8 pal_info;
	i64 data_ori_pos, data_ori_len;
	dbuf *data_f;
	i64 data_f_pos, data_f_len;
	de_finfo *fi;

	u8 fmt_known;
	i64 pos_of_mode;
	i64 reported_w_in_chars, reported_h_in_chars;

	struct de_char_context *charctx;
	struct fmtutil_char_simplectx csctx;
	struct grabber_id_data gi;
	de_color pal[256];

	struct fmtutil_exe_info ei;
	struct fmtutil_specialexe_detection_data edd;
} lctx;

static void free_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_finfo_destroy(c, d->fi);
	de_free_charctx(c, d->charctx);
	de_free(c, d);
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

	d->data_ori_pos = de_getu16le(pos_of_data_ptr);
	d->data_ori_pos -= 256;
	de_dbg(c, "data pos: %"I64_FMT, d->data_ori_pos);

	if(d->gi.fmt_class<3000) {
		pos_of_mode = d->data_ori_pos - 7;
	}
	else {
		pos_of_mode = d->data_ori_pos - 17;
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

	d->data_ori_len = de_getu16le(pos_of_mode+2);
	de_dbg(c, "data len: %"I64_FMT, d->data_ori_len);

	// Some files, including the DEMO*.COM files from v3.3, have mode=2.
	// I don't know where this comes from (TODO).
	// I think mode 2 should be some b/w text mode, but it seems to work the
	// same as mode 3.
	// AFAICT, the mode field definitely *is* related to the screen mode, and
	// it *is* used by the viewer. But it seems to be more like a hint as to
	// which viewer routine to call, than the literal screen mode.
	if(d->screen_mode==2 && d->data_ori_len==4000) {
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

static void do_grabber_cga(deark *c, lctx *d, dbuf *inf, i64 pos1, i64 len)
{
	de_bitmap *img = NULL;
	dbuf *tmpf = NULL;

	tmpf = dbuf_create_membuf(c, 16384, 0);
	read_and_deinterlace_cga(c, inf, pos1, tmpf);

	d->fi->density.code = DE_DENSITY_UNK_UNITS;

	if(d->screen_mode==6) {
		d->fi->density.xdens = 480.0;
		d->fi->density.ydens = 200.0;
		de_make_grayscale_palette(d->pal, 2, 0);
		img = de_bitmap_create(c, 640, 200, 1);
		de_convert_image_paletted(tmpf, 0, 1, 80, d->pal, img, 0);
	}
	else {
		int pal_subid = 3;

		d->fi->density.xdens = 240.0;
		d->fi->density.ydens = 200.0;

		// Intended to reflect how the file actually displays itself (on a
		// system with CGA-only graphics, in case it made a difference).
		// I.e., not necessarily the image that should have been captured.
		// GRABBER seems buggy, but I guess we'll copy the bugs.
		if(d->gi.fmt_class<=3200) { // v2.10-3.20
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

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_OPT_IMAGE);

	de_bitmap_destroy(img);
	dbuf_close(tmpf);
}

static void do_grabber_bitmapmode(deark *c, lctx *d)
{
	d->fi = de_finfo_create(c);

	if(d->screen_mode==4 || d->screen_mode==6) {
		do_grabber_cga(c, d, c->infile, d->data_ori_pos, d->data_ori_len);
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
done:
	;
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
		d->data_f_pos = d->data_ori_pos;
		d->data_f_len = d->data_ori_len;
		do_grabber_textmode(c, d);
	}
	else if(d->screen_mode==4 || d->screen_mode==6) {
		do_grabber_bitmapmode(c, d);
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	;
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

static void decompress_rletext_v370(deark *c, lctx *d, dbuf *unc_data,
	i64 num_dcmpr_bytes_expected)
{
	dbuf *inf = c->infile;
	i64 inf_pos = d->data_ori_pos;
	i64 inf_endpos = d->data_ori_pos + d->data_ori_len;
	i64 nbytes_decompressed = 0;

	while(1) {
		i64 count;
		u8 b0, b1;

		if(inf_pos >= inf_endpos) goto done;
		if(nbytes_decompressed >= num_dcmpr_bytes_expected) goto done;

		b0 = dbuf_getbyte_p(inf, &inf_pos);
		if(b0 >= 0xc0) {
			count = (i64)b0 - 0xc0;
			b1 = dbuf_getbyte_p(inf, &inf_pos);
			dbuf_write_run(unc_data, b1, count);
			nbytes_decompressed += count;
		}
		else {
			dbuf_writebyte(unc_data, b0);
			nbytes_decompressed++;
		}
	}

done:
	dbuf_flush(unc_data);
}

struct grabber_exe_id_item {
	u16 approx_ver;
	u16 sig_pos;
	u16 data_pos_from_mode; // 0 if not supported
	u8 mode_pos_from_sig; // 0 if not supported
	u8 sig_id;
};
static const struct grabber_exe_id_item grabber_exe_id_arr[] = {
	{3700, 4208,  117, 11, 1},
	{3701, 4206,  117, 11, 1}, // 3.70 DEMO
	{6320, 4308,  117, 11, 1},
	{3740, 4221,  117, 11, 1}, // ?
	{5510, 4358,  117, 11, 1},

	{3730, 4250,  117,  7, 3},
	{3770, 4250,  117,  7, 3},

	{3800, 4261,  116,  7, 2},
	{3810, 4338,  116,  7, 2},
	{3840, 4363,  116,  7, 2}, // 3.84, 3.85, 3.87

	{3900, 4363,  116,  7, 4},
	{3910, 4421,  116,  7, 0},
	{3911, 4469,  116,  7, 0}, // 3.91b
	{3920, 4688,  116,  7, 0}, // 3.92-3.93
	{3940, 4718,  116,  7, 0},

	{3960, 6052, 5005,  7, 0},
	{3970, 7496, 5005,  7, 0},
	{3980, 7660, 5005,  7, 0},

	{6321, 4187, 5006, 11, 1}, // 2 different 6.32 formats?
	{6500, 5552, 5006, 11, 1},
	{6600, 5592, 5006, 11, 1},

	{3600, 2227,    0,  8, 5},
	{5600, 5554,    0, 11, 1},
	{5601, 3991,    0,  0, 1},
	{6120, 2706,    0,  8, 5},
	{6200, 2625,    0,  0, 1},
	{6400, 5971,    0,  0, 1}
};

static void analyze_grabber_exe(deark *c, lctx *d)
{
	int found = 0;
	size_t found_itemnum = 0;
	size_t i;
	const struct grabber_exe_id_item *ii;

	for(i=0; i<DE_ARRAYCOUNT(grabber_exe_id_arr); i++) {
		const u8 *sig_bytes = NULL;

		ii = &grabber_exe_id_arr[i];

		switch(ii->sig_id) {
		case 1:
			sig_bytes = (const u8*)"GR7246";
			break;
		case 2:
			sig_bytes = (const u8*)"\x90\xbc\x13\x04\xd4\xd6";
			break;
		case 3:
			sig_bytes = (const u8*)"\x53\x90\xbc\x13\x04\xd4";
			break;
		case 4:
			sig_bytes = (const u8*)"\x85\xc7\x13\x04\xd4\xd6";
			break;
		case 5:
			sig_bytes = (const u8*)"\xaa\xeb\xee\x07\x1f\xc3";
			break;
		default:
			sig_bytes = (const u8*)"\x85\xc7\x13\x04\xb5\xf1";
		}
		found = !dbuf_memcmp(c->infile, (i64)ii->sig_pos, sig_bytes, 6);
		if(found) {
			found_itemnum = i;
			break;
		}
	}

	if(!found) {
		goto done;
	}

	ii = &grabber_exe_id_arr[found_itemnum];
	de_dbg(c, "approx. ver: %u.%03u", (UI)ii->approx_ver/1000, (UI)ii->approx_ver%1000);

	if(ii->mode_pos_from_sig==0) {
		goto done;
	}
	d->pos_of_mode = ii->sig_pos + (i64)ii->mode_pos_from_sig;
	d->screen_mode = de_getbyte(d->pos_of_mode);
	de_dbg(c, "mode: 0x%02x", (UI)d->screen_mode);

	if(ii->data_pos_from_mode==0) {
		goto done;
	}
	d->data_ori_pos = d->pos_of_mode + (i64)ii->data_pos_from_mode;
	d->data_ori_len = c->infile->len - d->data_ori_pos;

	if(d->screen_mode!=1 && d->screen_mode!=3) {
		goto done;
	}

	d->reported_w_in_chars = de_getu16le(d->pos_of_mode+18);
	d->reported_h_in_chars = de_getu16le(d->pos_of_mode+20);

	if(d->reported_w_in_chars<40 || d->reported_w_in_chars>132 ||
		d->reported_h_in_chars<16 || d->reported_h_in_chars>100)
	{
		goto done;
	}

	d->fmt_known = 1;

done:
	;
}

static void do_grabber_exe(deark *c, lctx *d, de_module_params *mparams)
{
	dbuf *tmpf = NULL;
	i64 num_dcmpr_bytes_expected;

	fmtutil_collect_exe_info(c, c->infile, &d->ei);
	d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_GRABBER;
	fmtutil_detect_specialexe(c, &d->ei, &d->edd);
	if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_GRABBER) {
		de_err(c, "Not a known GRABBER format");
		goto done;
	}

	analyze_grabber_exe(c, d);
	if(!d->fmt_known) {
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "data pos: %"I64_FMT, d->data_ori_pos);

	num_dcmpr_bytes_expected = d->reported_h_in_chars*d->reported_w_in_chars*2;
	tmpf = dbuf_create_membuf(c, num_dcmpr_bytes_expected, 0);
	dbuf_enable_wbuffer(tmpf);
	decompress_rletext_v370(c, d, tmpf, num_dcmpr_bytes_expected);
	if(d->errflag) goto done;

	rearrange_cmpr_text(c, d, tmpf);

	d->data_f = tmpf;
	d->data_f_pos = 0;
	d->data_f_len = tmpf->len;
	do_grabber_textmode(c, d);

done:
	dbuf_close(tmpf);
}

static void de_run_grabber(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI sig;

	d = de_malloc(c, sizeof(lctx));
	d->charctx = de_create_charctx(c, 0);
	d->csctx.input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

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
