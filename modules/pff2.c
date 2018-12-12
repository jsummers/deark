// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PFF2 font (.pf2)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pff2);

typedef struct localctx_struct {
	struct de_bitmap_font *font;
	u8 found_CHIX_chunk;
} lctx;

#define CODE_ASCE 0x41534345U
#define CODE_CHIX 0x43484958U
#define CODE_DATA 0x44415441U
#define CODE_DESC 0x44455343U
#define CODE_FAMI 0x46414d49U
#define CODE_FILE 0x46494c45U
#define CODE_MAXH 0x4d415848U
#define CODE_MAXW 0x4d415857U
#define CODE_NAME 0x4e414d45U
#define CODE_PTSZ 0x5054535aU
#define CODE_SLAN 0x534c414eU
#define CODE_WEIG 0x57454947U

struct pff2_sectiontype_info;

typedef void (*pff2_section_handler_fn)(deark *c, lctx *d,
	const struct pff2_sectiontype_info *si, i64 pos, i64 len);

struct pff2_sectiontype_info {
	u32 id;
	// 0x1=ASCII, 0x2=uint16be
	u32 flags;
	const char *name;
	pff2_section_handler_fn hfn;
};

static void do_char(deark *c, lctx *d, i64 char_idx, i32 codepoint, i64 pos)
{
	struct de_bitmap_font_char *ch;
	i64 bitmap_pos;
	u8 *srcbitmap = NULL;
	i64 srcbitmapsize;
	i64 j;

	ch = &d->font->char_array[char_idx];

	ch->codepoint_unicode = codepoint;

	ch->width = (int)de_getu16be(pos);
	ch->height = (int)de_getu16be(pos+2);
	if(ch->width > d->font->nominal_width) d->font->nominal_width = ch->width;
	if(ch->height > d->font->nominal_height) d->font->nominal_height = ch->height;

	bitmap_pos = pos+10;
	de_dbg2(c, "%d"DE_CHAR_TIMES"%d, bitmap at %d", (int)ch->width, (int)ch->height, (int)bitmap_pos);
	ch->rowspan = (ch->width +7)/8;

	srcbitmapsize = (ch->width * ch->height + 7)/8;
	srcbitmap = de_malloc(c, srcbitmapsize);
	de_read(srcbitmap, bitmap_pos, srcbitmapsize);

	ch->bitmap = de_malloc(c, ch->rowspan * ch->height);
	for(j=0; j<ch->height; j++) {
		// The source bitmap's rows are not byte aligned (except the first row).
		de_copy_bits(srcbitmap, j*ch->width, ch->bitmap, j*ch->rowspan*8, ch->width);
	}

	de_free(c, srcbitmap);
}

static void do_code_chix(deark *c, lctx *d, const struct pff2_sectiontype_info *si,
	i64 pos1, i64 len)
{
	i64 i;
	i64 pos;
	i64 defpos;
	i32 codepoint;
	unsigned int storage_flags;

	if(d->found_CHIX_chunk) goto done;
	d->found_CHIX_chunk = 1;

	d->font->num_chars = len/9;
	de_dbg(c, "number of characters: %d", (int)d->font->num_chars);

	d->font->char_array = de_mallocarray(c, d->font->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->font->num_chars; i++) {
		pos = pos1 + 9*i;
		codepoint = (i32)de_getu32be(pos);
		storage_flags = (unsigned int)de_getbyte(pos+4);
		defpos = de_getu32be(pos+5);
		de_dbg2(c, "code point U+%04X, index at %d, definition at %d",
			(unsigned int)codepoint, (int)pos, (int)defpos);
		if((storage_flags&0x07)!=0) {
			de_err(c, "Compressed PFF2 format is not supported");
			goto done;
		}
		de_dbg_indent(c, 1);
		do_char(c, d, i, codepoint, defpos);
		de_dbg_indent(c, -1);
	}

	de_font_bitmap_font_to_image(c, d->font, NULL, 0);

done: ;
}

static const struct pff2_sectiontype_info pff2_sectiontype_info_arr[] = {
	{ CODE_ASCE, 0x00000002, "ascent, in pixels", NULL },
	{ CODE_CHIX, 0x00000000, "character index", do_code_chix },
	{ CODE_DATA, 0x00000000, "character data", NULL },
	{ CODE_DESC, 0x00000002, "descent, in pixels", NULL },
	{ CODE_FAMI, 0x00000001, "font family name", NULL },
	{ CODE_FILE, 0x00000001, "file type ID", NULL },
	{ CODE_MAXH, 0x00000002, "max char height, in pixels", NULL },
	{ CODE_MAXW, 0x00000002, "max char width, in pixels", NULL },
	{ CODE_NAME, 0x00000001, "font name", NULL },
	{ CODE_PTSZ, 0x00000002, "font point size", NULL },
	{ CODE_SLAN, 0x00000001, "font slant", NULL },
	{ CODE_WEIG, 0x00000001, "font weight", NULL }
};

static const struct pff2_sectiontype_info *find_pffs_sectiontype_info(u32 id)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(pff2_sectiontype_info_arr); i++) {
		if(pff2_sectiontype_info_arr[i].id == id) {
			return &pff2_sectiontype_info_arr[i];
		}
	}
	return NULL;
}

static int my_pff2_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;
	const struct pff2_sectiontype_info *si;

	si = find_pffs_sectiontype_info(ictx->chunkctx->chunk4cc.id);

	if(!si) goto done;

	// Default value decoders:
	if(si->flags&0x1) {
		de_ucstring *str;
		str = ucstring_create(c);
		dbuf_read_to_ucstring_n(ictx->f,
			ictx->chunkctx->dpos, ictx->chunkctx->dlen,
			DE_DBG_MAX_STRLEN, str, 0, DE_ENCODING_ASCII);
		de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(str));
		ucstring_destroy(str);
	}
	else if(si->flags&0x2) {
		i64 n;
		n = dbuf_getu16be(ictx->f, ictx->chunkctx->dpos);
		de_dbg(c, "value: %d", (int)n);
	}

	if(si->hfn) {
		si->hfn(c, d, si, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
	}

done:
	ictx->handled = 1;
	return 1;
}

static int my_preprocess_pff2_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const struct pff2_sectiontype_info *si;

	si = find_pffs_sectiontype_info(ictx->chunkctx->chunk4cc.id);
	if(si) {
		ictx->chunkctx->chunk_name = si->name;
	}

	if(ictx->chunkctx->dlen==0xffffffffU) {
		// The 'DATA' chunk's length is usually set to the special value 0xffffffff.
		// We are allowed to adjust ictx->chunkctx->dlen here.
		ictx->chunkctx->dlen = ictx->f->len - ictx->chunkctx->dpos;
	}
	return 1;
}

static void de_run_pff2(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	i64 i;

	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->userdata = (void*)d;
	ictx->alignment = 1;
	ictx->preprocess_chunk_fn = my_preprocess_pff2_chunk_fn;
	ictx->handle_chunk_fn = my_pff2_chunk_handler;
	ictx->f = c->infile;

	d->font = de_create_bitmap_font(c);
	d->font->has_nonunicode_codepoints = 0;
	d->font->has_unicode_codepoints = 1;
	d->font->prefer_unicode = 1;

	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	if(d->font) {
		if(d->font->char_array) {
			for(i=0; i<d->font->num_chars; i++) {
				de_free(c, d->font->char_array[i].bitmap);
			}
			de_free(c, d->font->char_array);
		}
		de_destroy_bitmap_font(c, d->font);
	}

	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_pff2(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "FILE\x00\x00\x00\x04PFF2", 12))
		return 100;
	return 0;
}

void de_module_pff2(deark *c, struct deark_module_info *mi)
{
	mi->id = "pff2";
	mi->desc = "PFF2 font";
	mi->run_fn = de_run_pff2;
	mi->identify_fn = de_identify_pff2;
}
