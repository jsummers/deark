// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// OS/2 PM bitmap font (as extracted from an LX RT_FONT resource by the
// "exe" module's OS/2 support, or found standalone as a .fnt file).

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_os2font);

#define OS2_FONT_SIGNATURE_ID 0xfffffffeU
#define OS2_FONT_ID_METRICS    1
#define OS2_FONT_ID_DEFINITION 2

#define FM_DEFN_OUTLINE 0x0001 // FONTMETRICS.fsDefn: vector font, not bitmap

typedef struct localctx_struct {
	i64 metrics_pos; // 0 = not found
	i64 def_pos; // 0 = not found
	UI usFirstChar;
	UI usLastChar;
	UI usNominalPointSize;
	UI usCodePage;
	UI fsDefn;
	de_encoding encoding; // DE_ENCODING_UNKNOWN if usCodePage is not recognized
	UI fsFontdef;
	UI fsChardef;
	UI usCellSize;
	i64 cell_width; // fallback width, from FONTDEFINITIONHEADER
	i64 cell_height;
	i64 num_chars;
	i64 chartbl_pos;
	i64 off_glyphoffset; // byte offset of ulGlyphOffset within a char record, or -1
	i64 off_width; // byte offset of the width field within a char record, or -1

	de_finfo *fi;
} lctx;

// OS/2 PM "Universal Glyph List" (UGL): for fonts with usLastChar > 255,
// glyphs 256+ are a second, fixed block (box drawing/math, Greek, Latin
// Extended-A/Central European, Cyrillic, Baltic Latin Extended-A) that is
// the same regardless of the font's code page (the FM_DEFN_UGL504 scheme
// from the OS/2 Toolkit's os2def.h; 504 = highest index + 1, for Warp 4).
// Verified byte-for-byte against real OS/2 font bitmaps, cross-checked
// against the "OS2UGL" NLS resource from Warp 4.0/4.52 install images, and
// (for 256-383, the FM_DEFN_UGL383 tier) against IBM's G25H-7191-00
// "OS/2 Warp V3 PM Programming Reference, Volume 2" (Oct 1994), ch. 32.
#define UGL_EXT_FIRST 256
#define UGL_EXT_LAST  503
static const u16 ugl_ext_table[UGL_EXT_LAST-UGL_EXT_FIRST+1] = {
	0x20a7,0x2310,0x2561,0x2562,0x2556,0x2555,0x255c,0x255b,
	0x255e,0x255f,0x2567,0x2568,0x2564,0x2565,0x2559,0x2558,
	0x2552,0x2553,0x256b,0x256a,0x258c,0x2590,0x03b1,0x0393,
	0x03c0,0x03a3,0x03c3,0x03c4,0x03a6,0x0398,0x03a9,0x03b4,
	0x221e,0x03c6,0x03b5,0x2229,0x2261,0x2265,0x2264,0x2320,
	0x2321,0x2248,0x2219,0x221a,0x207f,0x02c9,0x02d8,0x02d9,
	0x02da,0x02dd,0x02db,0x02c7,0x2018,0x2019,0x201c,0x201d,
	0x2013,0x2014,0x02c6,0x02dc,0x201a,0x201e,0x2026,0x2020,
	0x2021,0x02c6,0x2030,0x0160,0x2039,0x0152,0x0303,0x2122,
	0x0161,0x203a,0x0153,0x0178,0x011f,0x011e,0x0130,0x015f,
	0x015e,0x0103,0x0102,0x0105,0x0104,0x0107,0x0106,0x010d,
	0x010c,0x010f,0x010e,0x0111,0x011b,0x011a,0x0119,0x0118,
	0x013a,0x0139,0x013e,0x013d,0x0142,0x0141,0x0144,0x0143,
	0x0148,0x0147,0x0151,0x0150,0x0155,0x0154,0x0159,0x0158,
	0x015b,0x015a,0x0165,0x0164,0x0163,0x0162,0x0171,0x0170,
	0x016f,0x016e,0x017a,0x0179,0x017e,0x017d,0x017c,0x017b,
	0x0401,0x0402,0x0403,0x0404,0x0405,0x0406,0x0407,0x0408,
	0x0409,0x040a,0x040b,0x040c,0x040e,0x040f,0x0410,0x0411,
	0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,
	0x041a,0x041b,0x041c,0x041d,0x041e,0x041f,0x0420,0x0421,
	0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,
	0x042a,0x042b,0x042c,0x042d,0x042e,0x042f,0x0430,0x0431,
	0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,
	0x043a,0x043b,0x043c,0x043d,0x043e,0x043f,0x0440,0x0441,
	0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,
	0x044a,0x044b,0x044c,0x044d,0x044e,0x044f,0x2116,0x0451,
	0x0452,0x0453,0x0454,0x0455,0x0456,0x0457,0x0458,0x0459,
	0x045a,0x045b,0x045c,0x045e,0x045f,0x0490,0x0491,0x0156,
	0x012e,0x0100,0x0112,0x0116,0x0122,0x0136,0x012a,0x013b,
	0x0145,0x014c,0x0172,0x016a,0x0157,0x012f,0x0101,0x0113,
	0x0117,0x0123,0x0137,0x012b,0x013c,0x0146,0x014d,0x0173
};

static de_rune ugl_ext_to_unicode(UI idx)
{
	u16 v;

	if(idx<UGL_EXT_FIRST || idx>UGL_EXT_LAST) return DE_CODEPOINT_INVALID;
	v = ugl_ext_table[idx-UGL_EXT_FIRST];
	if(v==0) return DE_CODEPOINT_INVALID;
	return (de_rune)v;
}

// Unicode codepoint for a glyph at nonunicode codepoint cnu, or
// DE_CODEPOINT_INVALID if none applies.
static de_rune calc_codepoint_unicode(lctx *d, struct de_bitmap_font *font,
	i32 cnu, struct de_encconv_state *es)
{
	if(!font->has_unicode_codepoints) return DE_CODEPOINT_INVALID;
	if((UI)cnu>=UGL_EXT_FIRST) return ugl_ext_to_unicode((UI)cnu);
	if(d->encoding!=DE_ENCODING_UNKNOWN) return de_char_to_unicode_ex(cnu, es);
	return DE_CODEPOINT_INVALID;
}

// True if this run will render font in Unicode-codepoint mode. Mirrors the
// decision logic in bitmap_font_to_image() (deark-font.c).
static int will_render_as_unicode(deark *c, struct de_bitmap_font *font)
{
	int unicode_req = de_get_ext_option_bool(c, "font:tounicode", -1);

	if(unicode_req==0 &&
		(font->has_nonunicode_codepoints || !font->has_unicode_codepoints))
	{
		return 0;
	}
	if(font->has_unicode_codepoints &&
		(unicode_req>0 || font->prefer_unicode || !font->has_nonunicode_codepoints))
	{
		return 1;
	}
	return 0;
}

// Codes 1-31 are ASCII control codes; cp437/cp850-family encodings map them
// to decorative "control picture" glyphs (pilcrow, section sign, etc.). If a
// font also has a real glyph at that character's normal codepage/UGL
// position, keep that one and drop the control-range copy, instead of
// letting the generic atlas logic relocate the real glyph to the PUA. When
// rendering in Unicode mode, drop the copy's bitmap too, so it disappears
// from that atlas instead of merely not colliding.
static void hide_duplicate_control_glyphs(deark *c, struct de_bitmap_font *font,
	i64 num_chars, int render_as_unicode)
{
	i64 i;
	u8 *hi_codepoint_used = de_malloc(c, 65536/8);

	for(i=0; i<num_chars; i++) {
		struct de_bitmap_font_char *ch = &font->char_array[i];
		i32 cp = ch->codepoint_unicode;

		if((UI)ch->codepoint_nonunicode < 0x20 || !ch->bitmap) continue;
		if(cp<0 || cp>=65536) continue;
		hi_codepoint_used[cp/8] |= 1<<(cp%8);
	}
	for(i=0; i<num_chars; i++) {
		struct de_bitmap_font_char *ch = &font->char_array[i];
		i32 cp = ch->codepoint_unicode;

		if((UI)ch->codepoint_nonunicode >= 0x20 || !ch->bitmap) continue;
		if(cp<0 || cp>=65536) continue;
		if(hi_codepoint_used[cp/8] & (1<<(cp%8))) {
			ch->codepoint_unicode = DE_CODEPOINT_INVALID;
			if(render_as_unicode) {
				de_free(c, ch->bitmap);
				ch->bitmap = NULL;
			}
		}
	}
	de_free(c, hi_codepoint_used);
}

static void get_char_bitmap(deark *c, lctx *d, i64 glyph_pos,
	struct de_bitmap_font_char *ch)
{
	i64 num_tiles;
	i64 tile;
	i64 row;
	i64 height = d->cell_height;

	if(ch->width<1 || height<1) return;
	num_tiles = ((i64)ch->width+7)/8;
	ch->rowspan = num_tiles;
	if(height * num_tiles > 32768) return;
	if(glyph_pos<0 || glyph_pos+num_tiles*height > c->infile->len) return;

	ch->bitmap = de_malloc(c, height * num_tiles);

	for(row=0; row<height; row++) {
		for(tile=0; tile<num_tiles; tile++) {
			ch->bitmap[row * ch->rowspan + tile] =
				de_getbyte(glyph_pos + tile*height + row);
		}
	}
}

static void do_make_image(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	i64 i;
	int max_width = 1;
	struct de_encconv_state es;

	de_dbg(c, "reading bitmaps");
	de_dbg_indent(c, 1);

	font = de_create_bitmap_font(c);
	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints =
		(d->encoding!=DE_ENCODING_UNKNOWN || d->usLastChar>=UGL_EXT_FIRST) ? 1 : 0;
	if(d->encoding!=DE_ENCODING_UNKNOWN) {
		de_encconv_init(&es, d->encoding);
	}

	font->num_chars = d->num_chars;
	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->num_chars; i++) {
		i64 rec_pos = d->chartbl_pos + i*(i64)d->usCellSize;
		i64 glyph_pos = 0;
		i64 width = d->cell_width;
		struct de_bitmap_font_char *ch = &font->char_array[i];

		ch->codepoint_nonunicode = (i32)(d->usFirstChar + (UI)i);
		ch->codepoint_unicode = calc_codepoint_unicode(d, font, ch->codepoint_nonunicode, &es);
		if(d->off_glyphoffset>=0) {
			glyph_pos = de_getu32le(rec_pos + d->off_glyphoffset);
		}
		if(d->off_width>=0) {
			width = de_getu16le(rec_pos + d->off_width);
		}

		ch->width = (int)width;
		ch->height = (int)d->cell_height;
		if(ch->width > max_width) max_width = ch->width;

		if(glyph_pos>0 && width>0) {
			get_char_bitmap(c, d, glyph_pos, ch);
		}
	}

	hide_duplicate_control_glyphs(c, font, d->num_chars, will_render_as_unicode(c, font));

	font->nominal_width = max_width;
	font->nominal_height = (int)d->cell_height;

	de_font_bitmap_font_write(c, font, d->fi, 0);

	if(font) {
		if(font->char_array) {
			for(i=0; i<font->num_chars; i++) {
				de_free(c, font->char_array[i].bitmap);
			}
			de_free(c, font->char_array);
		}
		de_destroy_bitmap_font(c, font);
	}

	de_dbg_indent(c, -1);
}

// Note that there is similar code in fnt.c. Any changes made here should
// potentially be copied.
static void read_face_name(deark *c, lctx *d)
{
	de_ucstring *s = NULL;
	i64 facename_pos;

	if(d->metrics_pos<1) return;
	facename_pos = d->metrics_pos + 40;

	de_dbg(c, "face name at %"I64_FMT, facename_pos);
	de_dbg_indent(c, 1);

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, facename_pos, 32, s, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "face name: \"%s\"", ucstring_getpsz_d(s));

	if(!c->filenames_from_file) goto done;

	if(!d->fi) d->fi = de_finfo_create(c);
	ucstring_printf(s, DE_ENCODING_LATIN1, "-%u", d->usNominalPointSize/10);
	de_finfo_set_name_from_ucstring(c, d->fi, s, 0);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}

// Figure out, from fsChardef, the byte offset within a char record of the
// glyph-offset field (bit7, ULONG, always first when present) and of the
// width field (bit0, USHORT). Fields present per fsChardef are packed in
// bit order 7,0,1,2,3,4,5,6, each 2 bytes except bit7 which is 4 bytes.
static void calc_chardef_layout(lctx *d)
{
	i64 fp = 0;
	UI b;

	d->off_glyphoffset = -1;
	d->off_width = -1;

	if(d->fsChardef & 0x80) {
		d->off_glyphoffset = fp;
		fp += 4;
	}
	for(b=0; b<7; b++) {
		if(d->fsChardef & (1U<<b)) {
			if(b==0) d->off_width = fp;
			fp += 2;
		}
	}
}

// Maps an OS/2 FONTMETRICS.usCodePage value to the deark encoding that
// implements it, or DE_ENCODING_UNKNOWN if we don't have a table for it.
static de_encoding codepage_to_encoding(UI cp)
{
	switch(cp) {
	case 437: return DE_ENCODING_CP437;
	case 850: return DE_ENCODING_CP850;
	case 862: return DE_ENCODING_CP862;
	case 866: return DE_ENCODING_CP866;
	}
	return DE_ENCODING_UNKNOWN;
}

static int do_read_header(deark *c, lctx *d)
{
	i64 pos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(de_getu32le(0) != (i64)OS2_FONT_SIGNATURE_ID ||
		dbuf_memcmp(c->infile, 8, "OS/2 FONT", 9))
	{
		de_err(c, "Not an OS/2 PM font");
		goto done;
	}
	de_dbg(c, "signature found at %d", 0);

	pos = 20;
	while(pos+8 <= c->infile->len) {
		i64 blk_id, blk_size;

		blk_id = de_getu32le(pos);
		blk_size = de_getu32le(pos+4);
		if(blk_size<8 || pos+blk_size>c->infile->len) break;

		de_dbg(c, "block at %"I64_FMT", id=%d, size=%"I64_FMT, pos, (int)blk_id, blk_size);
		de_dbg_indent(c, 1);

		if(blk_id==OS2_FONT_ID_METRICS && blk_size>=124) {
			d->metrics_pos = pos;
			d->usCodePage = (UI)de_getu16le(pos+74);
			d->usFirstChar = (UI)de_getu16le(pos+114);
			d->usLastChar = (UI)de_getu16le(pos+116);
			d->usNominalPointSize = (UI)de_getu16le(pos+122);
			d->encoding = codepage_to_encoding(d->usCodePage);
			de_dbg(c, "code page: %u%s", d->usCodePage,
				(d->encoding==DE_ENCODING_UNKNOWN)?" (unrecognized)":"");
			de_dbg(c, "first char: %u", d->usFirstChar);
			de_dbg(c, "last char: %u", d->usLastChar);
			de_dbg(c, "nominal point size: %u.%u", d->usNominalPointSize/10,
				d->usNominalPointSize%10);
			d->fsDefn = (UI)de_getu16le(pos+130);
			de_dbg(c, "fsDefn: 0x%04x", d->fsDefn);
		}
		else if(blk_id==OS2_FONT_ID_DEFINITION && blk_size>=28) {
			d->def_pos = pos;
			d->fsFontdef = (UI)de_getu16le(pos+8);
			d->fsChardef = (UI)de_getu16le(pos+10);
			d->usCellSize = (UI)de_getu16le(pos+12);
			d->cell_width = de_getu16le(pos+14);
			d->cell_height = de_getu16le(pos+16);
			d->chartbl_pos = pos+28;
			de_dbg(c, "fsFontdef: 0x%04x", d->fsFontdef);
			de_dbg(c, "fsChardef: 0x%04x", d->fsChardef);
			de_dbg(c, "cell size: %ux%u, record size: %u bytes",
				(UI)d->cell_width, (UI)d->cell_height, d->usCellSize);
		}

		de_dbg_indent(c, -1);
		pos += blk_size;
	}

	if(d->metrics_pos<1 || d->def_pos<1) {
		de_err(c, "Failed to find required OS/2 font blocks");
		goto done;
	}
	if(d->fsDefn & FM_DEFN_OUTLINE) {
		de_err(c, "Outline OS/2 fonts are not supported");
		goto done;
	}
	if(d->usLastChar < d->usFirstChar || d->usCellSize<1) {
		de_err(c, "Invalid or unsupported OS/2 font");
		goto done;
	}

	d->num_chars = d->usLastChar - d->usFirstChar + 1;
	calc_chardef_layout(d);

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_os2font(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_read_header(c, d)) goto done;
	read_face_name(c, d);
	do_make_image(c, d);

done:
	if(d) {
		de_finfo_destroy(c, d->fi);
		de_free(c, d);
	}
}

static int de_identify_os2font(deark *c)
{
	if(de_getu32le(0) != (i64)OS2_FONT_SIGNATURE_ID) return 0;
	if(dbuf_memcmp(c->infile, 8, "OS/2 FONT", 9)) return 0;
	return 90;
}

void de_module_os2font(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2font";
	mi->desc = "OS/2 PM bitmap font";
	mi->run_fn = de_run_os2font;
	mi->identify_fn = de_identify_os2font;
}
