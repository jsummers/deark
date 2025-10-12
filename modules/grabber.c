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
	i64 data_pos, data_len;
	de_finfo *fi;

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

	d->data_pos = de_getu16le(pos_of_data_ptr);
	d->data_pos -= 256;
	de_dbg(c, "data pos: %"I64_FMT, d->data_pos);

	if(d->gi.fmt_class<3000) {
		pos_of_mode = d->data_pos - 7;
	}
	else {
		pos_of_mode = d->data_pos - 17;
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

	d->data_len = de_getu16le(pos_of_mode+2);
	de_dbg(c, "data len: %"I64_FMT, d->data_len);

	// Some files, including the DEMO*.COM files from v3.3, have mode=2.
	// I don't know where this comes from (TODO).
	// I think mode 2 should be some b/w text mode, but it seems to work the
	// same as mode 3.
	// AFAICT, the mode field definitely *is* related to the screen mode, and
	// it *is* used by the viewer. But it seems to be more like a hint as to
	// which viewer routine to call, than the literal screen mode.
	if(d->screen_mode==2 && d->data_len==4000) {
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
	if(d->screen_mode==1) {
		d->csctx.width_in_chars = 40;
	}
	else {
		d->csctx.width_in_chars = 80;
	}
	d->charctx->screen_image_flag = 1;
	d->csctx.height_in_chars = de_pad_to_n(d->data_len, d->csctx.width_in_chars*2) /
		(d->csctx.width_in_chars*2);
	de_dbg(c, "screen size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->csctx.width_in_chars,
		d->csctx.height_in_chars);
	if(d->data_pos+d->data_len > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	// TODO: Set the density sensibly for 40x25 mode.
	if(d->csctx.width_in_chars!=80 || d->csctx.height_in_chars>25) {
		d->charctx->no_density = 1;
	}

	d->csctx.use_default_pal = 1;
	d->csctx.inf = c->infile;
	d->csctx.inf_pos = d->data_pos;
	d->csctx.inf_len = d->data_len;
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
		do_grabber_cga(c, d, c->infile, d->data_pos, d->data_len);
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

static void do_grabber_exe(deark *c, lctx *d, de_module_params *mparams)
{
	fmtutil_collect_exe_info(c, c->infile, &d->ei);
	d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_GRABBER;
	fmtutil_detect_specialexe(c, &d->ei, &d->edd);
	if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_GRABBER) {
		de_err(c, "Not a known GRABBER format");
		goto done;
	}
	de_err(c, "GRABBER EXE format isn't supported");
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
