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
	UI fmt_class;
	i64 jmppos;
};

typedef struct localctx_grabber {
	u8 errflag;
	u8 need_errmsg;

	u8 screen_mode;
	i64 data_pos, data_len;

	struct de_char_context *charctx;
	struct fmtutil_char_simplectx csctx;
	struct grabber_id_data gi;
} lctx;

static void free_lctx(deark *c, lctx *d)
{
	if(!d) return;
	de_free_charctx(c, d->charctx);
	de_free(c, d);
}

static void grabber_id_com(deark *c, u8 b0, struct grabber_id_data *gi)
{
	de_zeromem(gi, sizeof(struct grabber_id_data));

	if(b0==0xfb) {
		if(!dbuf_memcmp(c->infile, 1,
			(const void*)"\xbe\x81\x00\x8a\x4c\xff\x30\xed\x09\xc9\x74", 11)) {
			gi->is_grabber = 1;
			gi->fmt_class = 200;
		}
		return;
	}

	if(b0!=0xe9) return;
	gi->jmppos = de_geti16le(1) + 3;

	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xad\x80\xfc\x0d\x74\x17\x3c\x0d\x74", 12))
	{
		gi->is_grabber = 1;
		gi->fmt_class = 300;
		return;
	}
	if(!dbuf_memcmp(c->infile, gi->jmppos,
		(const void*)"\xbe\x81\x00\xfc\xad\x80\xfc\x0d\x74\x1c\x3c\x0d\x74", 13))
	{
		gi->is_grabber = 1;
		gi->fmt_class = 334;
		return;
	}
}

static void decode_grabber_com(deark *c, lctx *d)
{
	i64 foundpos = 0;
	i64 pos_of_data_ptr;
	i64 pos_of_mode;
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

	if(d->gi.fmt_class<300) {
		pos_of_mode = d->data_pos - 7;
	}
	else {
		pos_of_mode = d->data_pos - 17;
	}

	d->screen_mode = de_getbyte(pos_of_mode);
	de_dbg(c, "mode: 0x%02x", (UI)d->screen_mode);
	if(d->screen_mode != 3) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	d->data_len = de_getu16le(pos_of_mode+2);
	de_dbg(c, "data len: %"I64_FMT, d->data_len);
	d->csctx.width_in_chars = 80;
done:
	de_free(c, mem);
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

	d->charctx->screen_image_flag = 1;
	d->csctx.height_in_chars = de_pad_to_n(d->data_len, d->csctx.width_in_chars*2) /
		(d->csctx.width_in_chars*2);
	de_dbg(c, "screen size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->csctx.width_in_chars,
		d->csctx.height_in_chars);
	if(d->data_pos+d->data_len > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	if(d->csctx.width_in_chars>80 || d->csctx.height_in_chars>25) {
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

static void do_grabber_exe(deark *c, lctx *d, de_module_params *mparams)
{
	d->need_errmsg = 1;
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
	mi->flags |= DE_MODFLAG_HIDDEN;
}
