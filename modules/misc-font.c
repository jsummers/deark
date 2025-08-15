// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// Some font formats, mainly DOS 8xN screen fonts

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_vgafont);
DE_DECLARE_MODULE(de_module_fontmania);
DE_DECLARE_MODULE(de_module_pcrfont);
DE_DECLARE_MODULE(de_module_fontedit);
DE_DECLARE_MODULE(de_module_evafont);

// **************************************************************************
// 8xN "VGA" font (intended for development/debugging use)
// **************************************************************************

#define VGAFONT_MINH 3
#define VGAFONT_MAXH 20

struct vgafont_ctx {
	de_encoding encoding_req;
	de_encoding encoding_to_use;
	struct de_bitmap_font *font;
	i64 height;
	i64 font_data_pos;
	i64 font_data_size;
	u8 *fontdata;
	u8 need_errmsg;
};

static void vgafont_common_config1(deark *c, struct vgafont_ctx *d)
{
	d->encoding_req = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);
	if(d->encoding_req!=DE_ENCODING_UNKNOWN)
		d->encoding_to_use = d->encoding_req;
	else
		d->encoding_to_use = DE_ENCODING_CP437;

	d->font = de_create_bitmap_font(c);
	d->font->num_chars = 256;
	d->font->has_nonunicode_codepoints = 1;
	d->font->has_unicode_codepoints = 1;
	d->font->prefer_unicode = (d->encoding_req!=DE_ENCODING_UNKNOWN);
	d->font->nominal_width = 8;
	d->font->nominal_height = (int)d->height;
	d->font->char_array = de_mallocarray(c, d->font->num_chars,
		sizeof(struct de_bitmap_font_char));
}

static void vgafont_common_config2(deark *c, struct vgafont_ctx *d)
{
	i64 i;
	struct de_encconv_state es;

	de_encconv_init(&es, d->encoding_to_use);

	for(i=0; i<d->font->num_chars; i++) {
		d->font->char_array[i].codepoint_nonunicode = (i32)i;
		if(d->font->has_unicode_codepoints) {
			d->font->char_array[i].codepoint_unicode = de_char_to_unicode_ex((i32)i, &es);
		}
		d->font->char_array[i].width = d->font->nominal_width;
		d->font->char_array[i].height = d->font->nominal_height;
		d->font->char_array[i].rowspan = 1;
		d->font->char_array[i].bitmap = &d->fontdata[i*d->font->nominal_height];
	}
}

// This is only for fixed-size 8xX fonts.
static void vgafont_main(deark *c, struct vgafont_ctx *d, de_finfo *fi, UI createflags)
{
	u8 to_fontfmt = 0;

	de_font_decide_output_fmt(c);

	if(c->font_fmt_req!=DE_FONTFMT_IMAGE) {
		if(d->font->nominal_width==8 &&
			(d->font->nominal_height>=1 && d->font->nominal_height<=32))
		{
			to_fontfmt = 1;
		}
	}

	if(to_fontfmt) {
		// TODO? Most of the relevant formats are very similar to the PSF format
		// that this function will create. It's not ideal to go to all the trouble
		// to convert them to our internal format, only to convert them right
		// back to their original format.
		// (But since we want the option to convert them to an image, this is
		// maybe the easiest way.)
		d->font->force_fontfile_output = 1;
	}

	de_font_bitmap_font_write(c, d->font, fi, createflags);
}

static void destroy_vgafont_ctx(deark *c, struct vgafont_ctx *d)
{
	if(!d) return;
	if(d->font) {
		de_free(c, d->font->char_array);
		de_destroy_bitmap_font(c, d->font);
	}
	de_free(c, d->fontdata);
}

static void de_run_vgafont(deark *c, de_module_params *mparams)
{
	struct vgafont_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct vgafont_ctx));
	d->height = c->infile->len / 256;
	if((c->infile->len % 256) || d->height<VGAFONT_MINH || d->height>VGAFONT_MAXH) {
		de_err(c, "Bad file size");
		goto done;
	}

	d->font_data_pos = 0;
	d->font_data_size = d->height*256;
	d->fontdata = de_malloc(c, d->font_data_size);
	dbuf_read(c->infile, d->fontdata, d->font_data_pos, d->font_data_size);

	if(de_get_ext_option(c, "vgafont:c")) {
		i64 i;
		dbuf *ff;

		ff = dbuf_create_output_file(c, "h", NULL, 0);
		for(i=0; i<(d->font_data_size); i++) {
			if(i%d->height==0) dbuf_puts(ff, "\t");
			dbuf_printf(ff, "%d", (int)d->fontdata[i]);
			if(i!=(d->font_data_size-1)) dbuf_puts(ff, ",");
			if(i%d->height==(d->height-1)) dbuf_puts(ff, "\n");
		}
		dbuf_close(ff);
		goto done;
	}

	vgafont_common_config1(c, d);
	vgafont_common_config2(c, d);
	vgafont_main(c, d, NULL, 0);

done:
	destroy_vgafont_ctx(c, d);
}

static void de_help_vgafont(deark *c)
{
	de_msg(c, "-opt vgafont:c : Emit C code");
}

void de_module_vgafont(deark *c, struct deark_module_info *mi)
{
	mi->id = "vgafont";
	mi->desc = "Raw 8xN bitmap font";
	mi->run_fn = de_run_vgafont;
	mi->help_fn = de_help_vgafont;
}

// **************************************************************************
// Font Mania (REXXCOM) COM format
// **************************************************************************

static void de_run_fontmania(deark *c, de_module_params *mparams)
{
	struct vgafont_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct vgafont_ctx));
	d->font_data_pos = de_getu16le(2);
	de_dbg(c, "data pos: %"I64_FMT, d->font_data_pos);
	d->height = (i64)de_getbyte(5);
	de_dbg(c, "char size: 8"DE_CHAR_TIMES"%d", (int)d->height);
	d->font_data_size = d->height*256;

	if(d->height<VGAFONT_MINH || d->height>VGAFONT_MAXH ||
		(d->font_data_pos + d->font_data_size > c->infile->len))
	{
		d->need_errmsg = 1;
		goto done;
	}

	d->fontdata = de_malloc(c, d->font_data_size);
	de_read(d->fontdata, d->font_data_pos, d->font_data_size);

	vgafont_common_config1(c, d);
	vgafont_common_config2(c, d);
	vgafont_main(c, d, NULL, 0);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported Font Mania font");
		}
		destroy_vgafont_ctx(c, d);
	}
}

static int de_identify_fontmania(deark *c)
{
	if(c->infile->len>65280) return 0;
	if(de_getbyte(0) != 0xeb) return 0;
	if(dbuf_memcmp(c->infile, 8, (const u8*)"FONT MANIA, V", 13)) {
		return 0;
	}
	return 100;
}

void de_module_fontmania(deark *c, struct deark_module_info *mi)
{
	mi->id = "fontmania";
	mi->desc = "Font Mania .COM format";
	mi->run_fn = de_run_fontmania;
	mi->identify_fn = de_identify_fontmania;
}

// **************************************************************************
// PCR font (OPTIKS)
// **************************************************************************

static void de_run_pcrfont(deark *c, de_module_params *mparams)
{
	u8 hdr[11];
	struct vgafont_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct vgafont_ctx));

	de_read(hdr, 0, 11);
	// I assume either hdr[7] or hdr[10] is the high byte of the font data size,
	// but I don't know which.
	if(hdr[6]!=0x1 || hdr[7]!=hdr[10] || hdr[8]!=0 || hdr[9]!=0) {
		d->need_errmsg = 1;
		goto done;
	}
	d->height = (i64)hdr[7];
	de_dbg(c, "char size: 8"DE_CHAR_TIMES"%d", (int)d->height);

	d->font_data_pos = 11;
	d->font_data_size = d->height*256;
	if(d->height<VGAFONT_MINH || d->height>VGAFONT_MAXH ||
		(d->font_data_pos + d->font_data_size > c->infile->len))
	{
		d->need_errmsg = 1;
		goto done;
	}

	d->fontdata = de_malloc(c, d->font_data_size);
	dbuf_read(c->infile, d->fontdata, d->font_data_pos, d->font_data_size);

	vgafont_common_config1(c, d);
	vgafont_common_config2(c, d);
	vgafont_main(c, d, NULL, 0);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Unsupported type of PCR font");
		}
		destroy_vgafont_ctx(c, d);
	}
}

static int de_identify_pcrfont(deark *c)
{
	u8 h;

	if(dbuf_memcmp(c->infile, 0, "KPG", 3)) return 0;
	if(de_getbyte(5)!=0x20) return 0;
	h = de_getbyte(7);
	if(h<6 || h>16) return 0;
	if(de_getbyte(10)!=h) return 0;
	return 80;
}

void de_module_pcrfont(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcrfont";
	mi->desc = "PCR font";
	mi->run_fn = de_run_pcrfont;
	mi->identify_fn = de_identify_pcrfont;
}

// **************************************************************************
// FONTEDIT
// (Michael J. Mefford, PC Magazine)
// **************************************************************************

static void de_run_fontedit(deark *c, de_module_params *mparams)
{
	struct vgafont_ctx *d = NULL;
	i64 jmp1;
	u8 opt_extract_template;
	de_finfo *fi_tmpl = NULL;
	struct de_crcobj *crco = NULL;

	d = de_malloc(c, sizeof(struct vgafont_ctx));
	opt_extract_template = (u8)de_get_ext_option_bool(c, "fontedit:template",
		(c->extract_level>=2 ? 1 : 0));

	jmp1 = de_getbyte(1) + 2;
	d->height = (i64)de_getbyte(jmp1-3);
	de_dbg(c, "char size: 8"DE_CHAR_TIMES"%d", (int)d->height);
	d->font_data_pos = de_getu16le(jmp1+25) - 0x100;
	de_dbg(c, "data pos: %"I64_FMT, d->font_data_pos);
	d->font_data_size = d->height*256;

	if(d->height<VGAFONT_MINH || d->height>VGAFONT_MAXH ||
		(d->font_data_pos + d->font_data_size > c->infile->len))
	{
		d->need_errmsg = 1;
		goto done;
	}

	d->fontdata = de_malloc(c, d->font_data_size);
	de_read(d->fontdata, d->font_data_pos, d->font_data_size);

	vgafont_common_config1(c, d);
	vgafont_common_config2(c, d);
	vgafont_main(c, d, NULL, 0);

	if(opt_extract_template) {
		u32 crc1, crc2;

		crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
		de_crcobj_addbuf(crco, d->fontdata, d->font_data_size);
		crc1 = de_crcobj_getval(crco);

		d->font_data_pos += 4096;
		if(d->font_data_pos + d->font_data_size > c->infile->len) {
			de_dbg(c, "[template not present]");
			goto done;
		}
		de_dbg(c, "template pos: %"I64_FMT, d->font_data_pos);

		// This is a bit hacky, but we can just change the font data out
		// from under the pointers created by vgafont_common_config2().
		de_read(d->fontdata, d->font_data_pos, d->font_data_size);
		de_crcobj_reset(crco);
		de_crcobj_addbuf(crco, d->fontdata, d->font_data_size);
		crc2 = de_crcobj_getval(crco);

		if(crc2==crc1) {
			de_dbg(c, "[template is same as main font]");
			goto done;
		}

		fi_tmpl = de_finfo_create(c);
		de_finfo_set_name_from_sz(c, fi_tmpl, "template", 0, DE_ENCODING_LATIN1);
		vgafont_main(c, d, fi_tmpl, DE_CREATEFLAG_IS_AUX);
	}

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported FONTEDIT font");
		}
		destroy_vgafont_ctx(c, d);
	}
	de_finfo_destroy(c, fi_tmpl);
	de_crcobj_destroy(crco);
}

static int de_identify_fontedit(deark *c)
{
	u8 b1;
	i64 jmp1;

	if(c->infile->len>0x2200 || c->infile->len<(54+3*256)) return 0;
	if(de_getbyte(0) != 0xeb) return 0;
	b1 = de_getbyte(1);
	if(b1<0x32 || b1>0x33) return 0;
	jmp1 = (i64)b1 + 2;
	// Code for "INT 10/AX=1110h": the system call that sets the custom font
	if(dbuf_memcmp(c->infile, jmp1+39,
		(const void*)"\xb8\x10\x11\xcd\x10", 5))
	{
		return 0;
	}
	return 90;
}

static void de_help_fontedit(deark *c)
{
	de_msg(c, "-opt fontedit:template : Also extract the template font, if different");
}

void de_module_fontedit(deark *c, struct deark_module_info *mi)
{
	mi->id = "fontedit";
	mi->desc = "FONTEDIT font";
	mi->run_fn = de_run_fontedit;
	mi->identify_fn = de_identify_fontedit;
	mi->help_fn = de_help_fontedit;
}

// **************************************************************************
// EVAfont driver (COM format)
// **************************************************************************

static void de_run_evafont(deark *c, de_module_params *mparams)
{
	struct vgafont_ctx *d = NULL;
	u8 *mem = NULL;
	i64 foundpos;
	i64 font_data_endpos;
	int ret;

	d = de_malloc(c, sizeof(struct vgafont_ctx));

	// Tracing through the file seems difficult. Instead we search for the byte
	// pattern that appears just before the font data. It's nice that it also
	// contains a pointer to the end of the font data.

	// The pattern can appear as early as 310 (v2.01 VGA), and as late as 612
	// (v3.05 EGA).
#define EVAFONT_BUF_POS1 280
#define EVAFONT_BUF_LEN1 380
	mem = de_malloc(c, EVAFONT_BUF_LEN1);
	de_read(mem, EVAFONT_BUF_POS1, EVAFONT_BUF_LEN1);
	ret = de_memsearch_match(mem, EVAFONT_BUF_LEN1,
		(const u8*)"\xba??\xb1\x04\xd3\xea\x42\xb8\x00\x31\xcd\x21", 13,
		'?', &foundpos);
	if(!ret) {
		d->need_errmsg = 1;
		goto done;
	}
	foundpos += EVAFONT_BUF_POS1;
	de_dbg(c, "[found sig at %"I64_FMT"]", foundpos);

	d->font_data_pos = foundpos + 13;
	de_dbg(c, "data pos: %"I64_FMT, d->font_data_pos);

	font_data_endpos = de_getu16le(foundpos+1);
	font_data_endpos -= 256;
	de_dbg(c, "data endpos: %"I64_FMT, font_data_endpos);
	if(font_data_endpos > c->infile->len) {
		d->need_errmsg = 1;
		goto done;
	}

	d->font_data_size = font_data_endpos - d->font_data_pos;
	de_dbg(c, "data size: %"I64_FMT, d->font_data_size);

	if(d->font_data_size % 256) {
		d->need_errmsg = 1;
		goto done;
	}

	d->height = d->font_data_size / 256;

	de_dbg(c, "char size: 8"DE_CHAR_TIMES"%d", (int)d->height);

	if(d->height!=8 && d->height!=14 && d->height!=16) {
		d->need_errmsg = 1;
		goto done;
	}

	d->fontdata = de_malloc(c, d->font_data_size);
	de_read(d->fontdata, d->font_data_pos, d->font_data_size);

	vgafont_common_config1(c, d);
	vgafont_common_config2(c, d);
	vgafont_main(c, d, NULL, 0);

done:
	de_free(c, mem);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported EVAfont font");
		}
		destroy_vgafont_ctx(c, d);
	}
}

static int de_identify_evafont(deark *c)
{
	if(c->infile->len>65280) return 0;
	if(de_getbyte(0) != 0xe9) return 0;

	if(!dbuf_memcmp(c->infile, 7, (const u8*)" font driver v", 14)) {
		return 100; // v2.01:
	}
	if(!dbuf_memcmp(c->infile, 11, (const u8*)" font loader v", 14)) {
		return 100; // v3.05:
	}
	return 100;
}

void de_module_evafont(deark *c, struct deark_module_info *mi)
{
	mi->id = "evafont";
	mi->desc = "EVAfont .COM format";
	mi->run_fn = de_run_evafont;
	mi->identify_fn = de_identify_evafont;
}
