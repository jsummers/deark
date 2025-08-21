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
DE_DECLARE_MODULE(de_module_cpi);

// **************************************************************************
// 8xN "VGA" font (intended for development/debugging use)
// **************************************************************************

#define VGAFONT_MINH 3
#define VGAFONT_MAXH 20

struct vgafont_ctx {
	u8 support_unicode;
	de_encoding encoding_req;
	de_encoding encoding_to_use;
	struct de_bitmap_font *font;
	i64 height;
	i64 font_data_pos;
	i64 font_data_size;
	u8 *fontdata;
	u8 need_errmsg;
};

static void vgafont_common_config1_nc(deark *c, struct vgafont_ctx *d, i64 num_chars)
{
	if(d->support_unicode) {
		d->encoding_req = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);
		if(d->encoding_req!=DE_ENCODING_UNKNOWN)
			d->encoding_to_use = d->encoding_req;
		else
			d->encoding_to_use = DE_ENCODING_CP437;
	}
	else {
		d->encoding_req = DE_ENCODING_UNKNOWN;
		d->encoding_to_use = DE_ENCODING_LATIN1;
	}

	d->font = de_create_bitmap_font(c);
	d->font->num_chars = num_chars;
	d->font->has_nonunicode_codepoints = 1;
	if(d->support_unicode) {
		d->font->has_unicode_codepoints = 1;
		d->font->prefer_unicode = (d->encoding_req!=DE_ENCODING_UNKNOWN);
	}
	else {
		d->font->has_unicode_codepoints = 0;
		d->font->prefer_unicode = 0;
	}
	d->font->nominal_width = 8;
	d->font->nominal_height = (int)d->height;
	d->font->char_array = de_mallocarray(c, d->font->num_chars,
		sizeof(struct de_bitmap_font_char));
}

static void vgafont_common_config1(deark *c, struct vgafont_ctx *d)
{
	vgafont_common_config1_nc(c, d, 256);
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

static struct vgafont_ctx *create_vgafont_ctx(deark *c)
{
	struct vgafont_ctx *d;

	d = de_malloc(c, sizeof(struct vgafont_ctx));
	d->support_unicode = 1;
	return d;
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

	d = create_vgafont_ctx(c);
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

	d = create_vgafont_ctx(c);
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

	d = create_vgafont_ctx(c);

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

	d = create_vgafont_ctx(c);
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

	d = create_vgafont_ctx(c);

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
	return 0;
}

void de_module_evafont(deark *c, struct deark_module_info *mi)
{
	mi->id = "evafont";
	mi->desc = "EVAfont .COM format";
	mi->run_fn = de_run_evafont;
	mi->identify_fn = de_identify_evafont;
}

// **************************************************************************
// CPI (DOS code page info)
// **************************************************************************

// Note: This format is kind of a "wild west". So, we go to more effort than
// usual to detect and report errors, and to try to work around problems.

// Notes on CPI format:
// [This is mainly for files containing "screen" fonts. "Printer" fonts also
// exist, and have some differences. It also doesn't fully account for DRFONT
// format.]
// Roughly speaking, a CPI file contains a linked list of "code page entries"
// (c.p.e.).
// The first item has an extra 2-byte header giving the number of items in
// the list. Each item contains a pointer to the next one.
// (Theoretically, a file could have more than one such list, but we don't
// support that.)
// Each c.p.e. has a pointer (cpih_offset) to a contiguous blob of data
// containing one or more low-level fonts. It has a 6-byte header, then
// a sequence of "low level" fonts, each with its own 6-byte header.

#define CPI_MIN_HEIGHT  3
#define CPI_MAX_HEIGHT  32
#define CPI_MAX_BYTES_PER_GLYPH    32
#define DRFONT_MAX_NUM_FONT_SIZES  20

// Some of the variable names were taken from John Elliott's documentation
// of CPI format.
struct cpi_codepageentry_ctx {
	u8 errflag; // = there was an error that might be local to this c.p.e.
	UI idx;
	i64 hdr_pos;

	i64 cpeh_size; // Size of c.p.e. hdr in bytes, usually 28.
	i64 next_cpeh_offset;
	UI devtype_raw;
	u8 is_printer_cpe;
	struct de_stringreaderdata *devname_srd;
	UI codepage;
	i64 cpih_offset;

	UI cpedata_version;
	UI num_fonts;
	i64 cpedata_total_size; // (the "size" field after num_fonts)

	i64 font_data_startpos;
	i64 cpedata_max_endpos;
	i64 last_font_len;
	i64 last_font_endpos;
	de_ucstring *tmpname;
	char msgpfx[24];
	i64 dr_charmap_pos;
	u16 dr_charmap[256];
};

struct cpi_ctx {
	u8 fatalerrflag;
	u8 is_ntfmt;
	u8 is_drfont;
	u8 ptrs_are_segmented;
	u8 need_errmsg;
	UI num_printer_fonts_found;

	i64 pnum; // number of pointers
	u8 ptyp; // the "type" of the pointers
	i64 fih_offset; // "fih" = FontInfoHeader

	UI num_codepages;

	UI dr_num_font_sizes;
	u8 *dr_cellsizes; // array[dr_num_font_sizes]
	u32 *dr_dfdoffsets; // array[dr_num_font_sizes]
};

static i64 cpi_getpos_segmented_p(dbuf *f, i64 *ppos)
{
	i64 n;
	i64 n1, n2;

	n1 = dbuf_getu16le_p(f, ppos);
	n2 = dbuf_getu16le_p(f, ppos);
	n = (n2<<4) + n1;
	return n;
}

// Helps detect certain printer fonts known to be mislabeled as
// display fonts.
static int cpi_is_problematic_devname(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx)
{
	static const char *names[] = {
		"1050    ", "4201    ", "4208    ", "5202    " };
	size_t k;

	if(!cpectx->devname_srd) return 0;
	for(k=0; k<DE_ARRAYCOUNT(names); k++) {
		if(!de_strcmp(cpectx->devname_srd->sz, names[k])) {
			return 1;
		}
	}
	return 0;
}

// This may modify cpectx->is_printer_cpe.
// Assumes cpectx->cpih_offset is set.
static void cpi_detect_mislabeled_printer_font(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx)
{
	UI testval;

	if(d->is_ntfmt || d->is_drfont) goto done;
	if(cpectx->devtype_raw != 1) goto done;

	// for printer, bytes at cpectx->cpih_offset+6 should be
	//   01 00 xx xx  (or)  02 00 xx xx
	// for screen, should be (hh = font height)
	//   hh 08 00 00

	testval = (UI)de_getu16le(cpectx->cpih_offset+6);
	if(testval!=1 && testval!=2) goto done;

	if(cpi_is_problematic_devname(c, d, cpectx)) {
		de_warn(c, "%sLikely mislabeled printer font", cpectx->msgpfx);
		cpectx->is_printer_cpe = 1;
	}

done:
	;
}

static void cpi_destroy_codepageentry_ctx(deark *c,
	struct cpi_codepageentry_ctx *cpectx)
{
	if(!cpectx) return;
	de_destroy_stringreaderdata(c, cpectx->devname_srd);
	ucstring_destroy(cpectx->tmpname);
}

enum cpi_cpecheck_result {
	CPI_CPE_OK,
	CPI_CPE_EOF_MARKER,
	CPI_CPE_BEYOND_EOF,
	CPI_CPE_INVALID_OR_COMMENT,
	CPI_CPE_INVALID
};

static enum cpi_cpecheck_result cpi_check_for_cpe(deark *c, struct cpi_ctx *d,
	i64 pos1, u8 strictmode)
{
	u8 buf[8];
	UI cpeh_size;
	UI dev_type;

	if(pos1==0 || pos1==0xffffffffLL) {
		return CPI_CPE_EOF_MARKER;
	}
	if(pos1+18 > c->infile->len) {
		return CPI_CPE_BEYOND_EOF;
	}

	de_read(buf, pos1, sizeof(buf));

	// If we're near eof, this might be a comment
	if(pos1+2000 >= c->infile->len) {
		u8 looks_like_text = 1;
		UI i;

		for(i=0; i<(UI)sizeof(buf); i++) {
			if(buf[i]<0x0a) {
				looks_like_text = 0;
				break;
			}
		}

		if(looks_like_text) {
			return CPI_CPE_INVALID_OR_COMMENT;
		}
	}

	cpeh_size = (UI)de_getu16le_direct(&buf[0]);
	dev_type = (UI)de_getu16le_direct(&buf[6]);

	if(dev_type<1 || dev_type>2 || cpeh_size<18 || cpeh_size>200) {
		return CPI_CPE_INVALID;
	}
	if(strictmode && cpeh_size!=26 && cpeh_size!=28) {
		return CPI_CPE_INVALID;
	}
	return CPI_CPE_OK;
}

static int cpi_check_for_fonthdr(deark *c, struct cpi_ctx *d,
	i64 pos1, u8 strictmode)
{
	UI rectype;
	u8 w, h;
	UI num_chars;
	i64 pos = pos1;

	if(pos1==0) return 0;
	rectype = (UI)de_getu16le_p(&pos);
	if(rectype==1) {
		pos += 4;
		h = de_getbyte_p(&pos);
		w = de_getbyte_p(&pos);
		pos += 2;
		num_chars = (UI)de_getu16le_p(&pos);
		if(w!=8) return 0;
		if(num_chars!=256 && num_chars!=512) return 0;
		if(h<CPI_MIN_HEIGHT || h>CPI_MAX_HEIGHT) return 0;
		if(strictmode && (h<8 || h>24)) return 0;
		return 1;
	}
	else if(rectype==2) {
		if(strictmode) return 0;
		return 1; // TODO?: Do more checks.
	}
	return 0;
}

struct cpi_ptr_struct {
	i64 pos_if_normal;
	i64 pos_if_segmented;
};

static void cpi_read_ptr(dbuf *f, i64 pos, struct cpi_ptr_struct *px)
{
	UI word1, word2;

	word1 = (UI)dbuf_getu16le(f, pos);
	word2 = (UI)dbuf_getu16le(f, pos+2);
	px->pos_if_normal = (((i64)word2)<<16) + (i64)word1;
	px->pos_if_segmented = (((i64)word2)<<4) + (i64)word1;
}

static void cpi_do_lowlevel_font(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx, UI fntidx, i64 pos1)
{
	i64 pos = pos1;
	UI ch_height, ch_width;
	UI num_chars;
	i64 bitmap_dpos = 0;
	i64 bitmap_dlen = 0;
	UI dr_nbytes_per_glyph = 0;
	i64 dr_glyph_data_pos = 0;
	u8 eof_errflag = 0;
	u8 looks_valid;
	de_finfo *fi = NULL;
	struct vgafont_ctx *d2 = NULL;
	char msgpfx[24];

	de_snprintf(msgpfx, sizeof(msgpfx), "[cpe#%u,font#%u] ", cpectx->idx, fntidx);
	de_dbg(c, "low-level font #%u at %"I64_FMT, fntidx, pos1);
	de_dbg_indent(c, 1);

	if(pos1 >= cpectx->cpedata_max_endpos) {
		eof_errflag = 1;
		goto done;
	}

	if(d->is_drfont && (fntidx>=d->dr_num_font_sizes)) {
		// Shouldn't be possible.
		goto done;
	}

	d2 = create_vgafont_ctx(c);
	// TODO:? Some sort of Unicode support. Would like to simply record the
	// code page in the output file, but PSF doesn't seem to support that.
	d2->support_unicode = 0;

	ch_height = (UI)de_getbyte_p(&pos);
	ch_width = (UI)de_getbyte_p(&pos);
	de_dbg(c, "char size: %u"DE_CHAR_TIMES"%u", ch_width, ch_height);
	pos += 2; // aspect ratio
	num_chars = (UI)de_getu16le_p(&pos);
	de_dbg(c, "num chars: %u", num_chars);

	looks_valid = (ch_width==8 && ch_height>=CPI_MIN_HEIGHT &&
		ch_height<=CPI_MAX_HEIGHT);

	// TODO: Maybe we should allow numbers other than 256/512.
	if(looks_valid) {
		if(d->is_drfont && num_chars!=256) {
			looks_valid = 0;
		}
		else if(num_chars!=256 && num_chars!=512) {
			looks_valid = 0;
		}
	}

	if(d->is_drfont) {
		dr_nbytes_per_glyph = d->dr_cellsizes[fntidx];
		dr_glyph_data_pos = d->dr_dfdoffsets[fntidx];
		if(dr_nbytes_per_glyph != ch_height) {
			looks_valid = 0;
		}
	}

	if(!looks_valid) {
		de_err(c, "%sBad font header", msgpfx);
		cpectx->errflag = 1;
		goto done;
	}

	if(d->is_drfont) {
		de_dbg(c, "using glyph data at %"I64_FMT, dr_glyph_data_pos);
	}
	if(d->is_drfont) {
		cpectx->last_font_len = 6;
		cpectx->last_font_endpos = pos;
	}

	if(!d->is_drfont) {
		bitmap_dpos = pos;
		bitmap_dlen = num_chars * ch_height;
		de_dbg(c, "font bitmap data at %"I64_FMT", len=%"I64_FMT, bitmap_dpos, bitmap_dlen);
		cpectx->last_font_endpos = bitmap_dpos + bitmap_dlen;
		cpectx->last_font_len = cpectx->last_font_endpos - pos1;
	}

	if(cpectx->last_font_endpos > cpectx->cpedata_max_endpos) {
		eof_errflag = 1;
		goto done;
	}

	if(!cpectx->tmpname) {
		cpectx->tmpname = ucstring_create(c);
	}
	ucstring_empty(cpectx->tmpname);

	ucstring_printf(cpectx->tmpname, DE_ENCODING_LATIN1, "cp%u-%ux%u",
		cpectx->codepage, ch_width, ch_height);

	if(ucstring_isnonempty(cpectx->devname_srd->str)) {
		ucstring_append_char(cpectx->tmpname, '-');
		ucstring_append_ucstring(cpectx->tmpname, cpectx->devname_srd->str);
	}

	fi = de_finfo_create(c);
	if(c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, cpectx->tmpname, 0);
	}

	d2->height = ch_height;
	if(d->is_drfont) {
		d2->font_data_size = (i64)num_chars*(i64)dr_nbytes_per_glyph;
		d2->font_data_pos = 0; // unused
	}
	else {
		d2->font_data_size = bitmap_dlen;
		d2->font_data_pos = bitmap_dpos;
	}
	d2->fontdata = de_malloc(c, d2->font_data_size);

	if(d->is_drfont) {
		UI i;

		// For DRFONT, we need to use the char. map.
		for(i=0; i<num_chars; i++) {
			// This isn't very efficient. Lots of seeking around. But it
			// should be good enough.
			de_read(&d2->fontdata[i*dr_nbytes_per_glyph],
				dr_glyph_data_pos + (i64)cpectx->dr_charmap[i] * dr_nbytes_per_glyph,
				dr_nbytes_per_glyph);
		}
	}
	else {
		de_read(d2->fontdata, d2->font_data_pos, d2->font_data_size);
	}

	vgafont_common_config1_nc(c, d2, (i64)num_chars);
	vgafont_common_config2(c, d2);
	vgafont_main(c, d2, fi, 0);

done:
	if(eof_errflag) {
		de_err(c, "%sMalformed font or truncated file", msgpfx);
		cpectx->errflag = 1;
	}

	de_finfo_destroy(c, fi);

	if(d2) {
		destroy_vgafont_ctx(c, d2);
	}

	de_dbg_indent(c, -1);
}

static const char *cpi_get_cpedata_ver_name(struct cpi_ctx *d, UI v)
{
	const char *name = NULL;

	if(v==1) name = "standard";
	else if(v==2 && d->is_drfont) name = "DRFONT";
	return name?name:"?";
}

static void cpi_do_cpedata_screenfonts(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx)
{
	i64 pos;
	UI i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->is_drfont) {
		cpectx->dr_charmap_pos = cpectx->font_data_startpos +
			cpectx->cpedata_total_size;

		pos = cpectx->dr_charmap_pos;
		de_dbg(c, "char map at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		for(i=0; i<256; i++) {

			cpectx->dr_charmap[i] = (UI)de_getu16le_p(&pos);
			de_dbg2(c, "map[%u] = %u", i, (UI)cpectx->dr_charmap[i]);
		}
		de_dbg_indent(c, -1);
	}

	pos = cpectx->font_data_startpos;
	for(i=0; i<cpectx->num_fonts; i++) {
		cpectx->last_font_len = 0;
		cpi_do_lowlevel_font(c, d, cpectx, i, pos);
		if(cpectx->errflag || d->fatalerrflag || (cpectx->last_font_len<1)) {
			goto done;
		}
		pos += cpectx->last_font_len;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void cpi_do_cpedata(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx)
{
	int saved_indent_level;
	i64 pos1 = cpectx->cpih_offset;
	i64 pos = cpectx->cpih_offset;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "c.p.e. data at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(pos1>=c->infile->len) {
		de_err(c, "%sBad or truncated file", cpectx->msgpfx);
		cpectx->errflag = 1;
		d->fatalerrflag = 1;
		goto done;
	}

	cpectx->cpedata_version = (UI)de_getu16le_p(&pos);
	de_dbg(c, "cpedata version: %u (%s)", cpectx->cpedata_version,
		cpi_get_cpedata_ver_name(d, cpectx->cpedata_version));
	cpectx->num_fonts = (UI)de_getu16le_p(&pos);
	de_dbg(c, "num fonts: %u", cpectx->num_fonts);
	cpectx->cpedata_total_size = de_getu16le_p(&pos);
	de_dbg(c, "cpedata total size: %"I64_FMT, cpectx->cpedata_total_size);

	if(cpectx->is_printer_cpe) {
		de_dbg(c, "[printer font]");
		d->num_printer_fonts_found++;
		goto done;
	}

	if(!cpectx->is_printer_cpe && !d->is_drfont && cpectx->cpedata_version==1) {
		;
	}
	else if(!cpectx->is_printer_cpe && d->is_drfont && cpectx->cpedata_version==2) {
		;
	}
	else {
		// TODO?: Is there anything we can do with printer fonts?
		de_dbg(c, "[device or version not supported]");
		goto done;
	}

	if(d->is_drfont) {
		if(cpectx->num_fonts > d->dr_num_font_sizes) {
			d->need_errmsg = 1;
			cpectx->errflag = 1;
			goto done;
		}
	}

	cpectx->font_data_startpos = pos;
	// cpedata_max_endpos will mark the amount of data that this cpe is allowed
	// to use.
	// We'd rather calculate it using cpedata_total_size, but apparently that
	// field is sometimes wrong.
	// This limit could be improved, though. We could look at the next cpe
	// item when available, and use some intelligence.
	//cpectx->cpedata_max_endpos = cpectx->font_data_startpos + cpedata_total_size;
	cpectx->cpedata_max_endpos = c->infile->len;

	cpi_do_cpedata_screenfonts(c, d, cpectx);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static const char *cpi_get_devtype_name(struct cpi_ctx *d, UI t)
{
	const char *name = NULL;

	if(t==1) name = "screen";
	else if(t==2) name = "printer";
	return name?name:"?";
}

// Caller allocs cpectx, and sets ->hdr_pos, etc.
static void cpi_do_codepage_entry(deark *c, struct cpi_ctx *d,
	struct cpi_codepageentry_ctx *cpectx)
{
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "code page entry #%u", cpectx->idx);
	de_dbg_indent(c, 1);
	de_dbg(c, "c.p.e. header at %"I64_FMT", len=%"I64_FMT, cpectx->hdr_pos,
		cpectx->cpeh_size);
	de_dbg_indent(c, 1);
	de_dbg(c, "next c.p.e. header: %"I64_FMT, cpectx->next_cpeh_offset);
	pos = cpectx->hdr_pos+6; // skip fields already read
	cpectx->devtype_raw = (UI)de_getu16le_p(&pos);
	de_dbg(c, "device type: %u (%s)", cpectx->devtype_raw,
		cpi_get_devtype_name(d,  cpectx->devtype_raw));
	if(cpectx->devtype_raw!=1 && cpectx->devtype_raw!=2) {
		de_warn(c, "%sUnknown device type: %u", cpectx->msgpfx, cpectx->devtype_raw);
		goto done;
	}
	cpectx->is_printer_cpe = (cpectx->devtype_raw==2);

	cpectx->devname_srd = dbuf_read_string(c->infile, pos, 8, 8, 0, DE_ENCODING_CP437);
	ucstring_strip_trailing_spaces(cpectx->devname_srd->str);
	de_dbg(c, "device name: \"%s\"", ucstring_getpsz_d(cpectx->devname_srd->str));
	pos += 8;

	cpectx->codepage = (UI)de_getu16le_p(&pos);
	de_dbg(c, "code page: %u", cpectx->codepage);
	pos += 6;

	if(d->ptrs_are_segmented) {
		cpectx->cpih_offset = cpi_getpos_segmented_p(c->infile, &pos);
	}
	else {
		cpectx->cpih_offset = de_getu32le_p(&pos);
		if(cpectx->cpeh_size==26) {
			cpectx->cpih_offset &= 0xffff;
		}
	}
	if(d->is_ntfmt) {
		// In NT format, this field is relative.
		cpectx->cpih_offset += cpectx->hdr_pos;
	}

	de_dbg(c, "c.p.e. data pos: %"I64_FMT, cpectx->cpih_offset);
	if(cpectx->cpih_offset < cpectx->hdr_pos+26) {
		de_err(c, "%sBad font data pointer", cpectx->msgpfx);
		goto done;
	}

	cpi_detect_mislabeled_printer_font(c, d, cpectx);

	de_dbg_indent(c, -1);

	cpi_do_cpedata(c, d, cpectx);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// In a few files, the next_cpeh_offset and cpih_offset fields are stored
// in "segment:offset" form. Really bizarre.
static void cpi_determine_ptr_fmt(deark *c, struct cpi_ctx *d,
	i64 first_cpeh_offset)
{
	enum cpi_cpecheck_result cperet;
	enum cpi_cpecheck_result cperet1_ifnormal, cperet1_ifsegmented;
	int ret2_ifnormal, ret2_ifsegmented;
	struct cpi_ptr_struct nextptr;
	struct cpi_ptr_struct cpihptr;
	i64 pos = first_cpeh_offset;
	UI cpeh_size;

	if(d->is_ntfmt || d->is_drfont) goto done;

	cperet = cpi_check_for_cpe(c, d, pos, 0);
	if(cperet!=CPI_CPE_OK) {
		// There was a problem reading the first c.p.e., so we can't
		// even read what we need to detect the format.
		// (This error will be rediscovered later, and handled.)
		goto done;
	}

	cpeh_size =  (UI)de_getu16le(pos);
	if(cpeh_size!=28) goto done;
	cpi_read_ptr(c->infile, pos+2, &nextptr);
	cpi_read_ptr(c->infile, pos+24, &cpihptr);

	if(d->num_codepages<2 || nextptr.pos_if_normal==0) {
		// No info in this case; have to rely on cpihptr.
		cperet1_ifnormal = CPI_CPE_EOF_MARKER;
		cperet1_ifsegmented = CPI_CPE_EOF_MARKER;
	}
	else {
		cperet1_ifnormal = cpi_check_for_cpe(c, d, nextptr.pos_if_normal, 0);
		cperet1_ifsegmented = cpi_check_for_cpe(c, d, nextptr.pos_if_segmented, 1);
	}

	if(cperet1_ifnormal==CPI_CPE_OK) goto done;
	if(cperet1_ifsegmented!=CPI_CPE_OK && cperet1_ifsegmented!=CPI_CPE_EOF_MARKER) {
		goto done;
	}

	ret2_ifnormal = cpi_check_for_fonthdr(c, d, cpihptr.pos_if_normal, 0);
	ret2_ifsegmented = cpi_check_for_fonthdr(c, d, cpihptr.pos_if_segmented, 1);

	if(ret2_ifnormal) goto done;
	if(!ret2_ifsegmented) goto done;

	de_dbg(c, "[pointers seem to be segmented]");
	d->ptrs_are_segmented = 1;

done:
	;
}

// Process a list of "code page entries", where
// d->fih_offset is the offset of the header of the list
// (the offset of the "num_codepages" field).
static void cpi_do_cpelist(deark *c, struct cpi_ctx *d)
{
	int saved_indent_level;
	i64 prev_entry_hdr_pos = 0;
	UI i;
	i64 pos;
	struct cpi_codepageentry_ctx *cpectx = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "font info header at %"I64_FMT, d->fih_offset);
	de_dbg_indent(c, 1);

	pos = d->fih_offset;
	d->num_codepages = (UI)de_getu16le_p(&pos);
	de_dbg(c, "num code page entries: %u", d->num_codepages);

	de_dbg_indent(c, -1);

	cpi_determine_ptr_fmt(c, d, pos);

	for(i=0; i<d->num_codepages; i++) {
		static enum cpi_cpecheck_result cperet;

		if(d->fatalerrflag) goto done;

		// Peek at what should be the c.p.e. header, to see what's there.
		cperet = cpi_check_for_cpe(c, d, pos, 0);

		if(cperet==CPI_CPE_EOF_MARKER) {
			de_warn(c, "Expected %u code page entries, only found %u",
				d->num_codepages, i);
			goto done;
		}

		if(cperet==CPI_CPE_BEYOND_EOF) {
			de_err(c, "Bad or truncated file");
			goto done;
		}

		if(i>0 && cperet==CPI_CPE_INVALID_OR_COMMENT) {
			de_warn(c, "Found likely comment at %"I64_FMT", instead of "
				"expected c.p.e.", pos);
			goto done;
		}

		if(cperet!=CPI_CPE_OK) {
			de_err(c, "Expected c.p.e. not found at %"I64_FMT, pos);
			goto done;
		}

		if(cpectx) {
			cpi_destroy_codepageentry_ctx(c, cpectx);
		}
		cpectx = de_malloc(c, sizeof(struct cpi_codepageentry_ctx));
		de_snprintf(cpectx->msgpfx, sizeof(cpectx->msgpfx), "[cpe#%u] ", i);
		cpectx->idx = i;
		cpectx->hdr_pos = pos;

		if(cpectx->hdr_pos>=c->infile->len) {
			de_err(c, "%sBad or truncated file", cpectx->msgpfx);
			goto done;
		}
		if(cpectx->hdr_pos <= prev_entry_hdr_pos) {
			// Backward pointers might be legal, but would take some extra work
			// to handle safely. We won't allow them unless we have to.
			de_err(c, "%sMalformed file", cpectx->msgpfx);
			goto done;
		}
		prev_entry_hdr_pos = cpectx->hdr_pos;

		cpectx->cpeh_size = de_getu16le_p(&pos);

		if(d->ptrs_are_segmented) {
			cpectx->next_cpeh_offset = cpi_getpos_segmented_p(c->infile, &pos);
		}
		else {
			cpectx->next_cpeh_offset = de_getu32le_p(&pos);
		}

		if(d->is_ntfmt) {
			// In NT format, this field is relative.
			cpectx->next_cpeh_offset += cpectx->hdr_pos;
		}

		cpi_do_codepage_entry(c, d, cpectx);

		pos = cpectx->next_cpeh_offset;
	}

done:
	cpi_destroy_codepageentry_ctx(c, cpectx);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_cpi(deark *c, de_module_params *mparams)
{
	struct cpi_ctx *d = NULL;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct cpi_ctx));

	de_dbg(c, "font file header");
	de_dbg_indent(c, 1);
	if(de_getbyte(0)==0x7f) {
		d->is_drfont = 1;
	}
	else if(de_getbyte(7)=='T') {
		d->is_ntfmt = 1;
	}
	de_dbg(c, "is NT: %u", (UI)d->is_ntfmt);
	de_dbg(c, "is DRFONT: %u", (UI)d->is_drfont);

	if(d->is_drfont) {
		de_declare_fmt(c, "CPI font (DRFONT variant)");
	}
	else if(d->is_ntfmt) {
		de_declare_fmt(c, "CPI font (NT version)");
	}
	else {
		de_declare_fmt(c, "CPI font");
	}

	pos = 16;
	d->pnum = de_getu16le_p(&pos);
	de_dbg(c, "num ptrs: %d", (int)d->pnum);
	if(d->pnum>1) {
		de_warn(c, "This file has multiple \"pointers\", and is not "
			"fully supported");
	}

	d->ptyp = de_getbyte_p(&pos);
	de_dbg(c, "ptrs type: %u", (UI)d->ptyp);
	if(d->ptyp != 1) {
		de_err(c, "Bad \"pointers type\"");
		goto done;
	}

	if(d->pnum==0) goto done;

	d->fih_offset = de_getu32le_p(&pos);
	de_dbg(c, "fih pos: %"I64_FMT, d->fih_offset);

	if(d->is_drfont) { // (at offset 23)
		UI k;

		d->dr_num_font_sizes = de_getbyte_p(&pos);
		de_dbg(c, "num font sizes: %u", d->dr_num_font_sizes);
		if(d->dr_num_font_sizes>DRFONT_MAX_NUM_FONT_SIZES) {
			d->need_errmsg = 1;
			goto done;
		}
		d->dr_cellsizes = de_mallocarray(c, d->dr_num_font_sizes, 1);
		for(k=0; k<d->dr_num_font_sizes; k++) {
			d->dr_cellsizes[k] = de_getbyte_p(&pos);
		}
		d->dr_dfdoffsets = de_mallocarray(c, d->dr_num_font_sizes, sizeof(u32));
		for(k=0; k<d->dr_num_font_sizes; k++) {
			d->dr_dfdoffsets[k] = (u32)de_getu32le_p(&pos);
			de_dbg(c, "font size[%u]: bytes/char=%u, dpos=%u", k,
				(UI)d->dr_cellsizes[k], (UI)d->dr_dfdoffsets[k]);
			if(d->dr_cellsizes[k]>CPI_MAX_BYTES_PER_GLYPH) {
				d->need_errmsg = 1;
				goto done;
			}
		}
	}

	de_dbg_indent(c, -1);

	cpi_do_cpelist(c, d);

	// TODO: Try to extract the comment, if present.

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Failed to process this font file");
		}
		if(d->num_printer_fonts_found) {
			de_warn(c, "This file contains printer fonts, which are not "
				"supported");
		}
		de_free(c, d->dr_cellsizes);
		de_free(c, d->dr_dfdoffsets);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_cpi(deark *c)
{
	UI n0, n1;

	n0 = (UI)de_getu32be(0);
	if(n0==0xff464f4eU) {
		n1 = (UI)de_getu32be(4);
		if(n1==0x54202020U || n1==0x542e4e54U) {
			return 100;
		}
	}
	// TODO: Should DRFONT be a separate module?
	if(n0==0x7f445246U) { // DRFONT
		n1 = (UI)de_getu32be(4);
		if(n1==0x4f4e5420U) {
			return 100;
		}
	}
	return 0;
}

void de_module_cpi(deark *c, struct deark_module_info *mi)
{
	mi->id = "cpi";
	mi->desc = "CPI code page font";
	mi->run_fn = de_run_cpi;
	mi->identify_fn = de_identify_cpi;
}
