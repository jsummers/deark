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
	de_byte found_CHIX_chunk;
} lctx;

#define CODE_CHIX 0x43484958
#define CODE_DATA 0x44415441

static void do_char(deark *c, lctx *d, de_int64 char_idx, de_int32 codepoint, de_int64 pos)
{
	struct de_bitmap_font_char *ch;
	de_int64 bitmap_pos;
	de_byte *srcbitmap = NULL;
	de_int64 srcbitmapsize;
	de_int64 j;

	ch = &d->font->char_array[char_idx];

	ch->codepoint_unicode = codepoint;

	ch->width = (int)de_getui16be(pos);
	ch->height = (int)de_getui16be(pos+2);
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

static void do_code_chix(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 i;
	de_int64 pos;
	de_int64 defpos;
	de_int32 codepoint;
	unsigned int storage_flags;

	de_dbg(c, "CHIX at %d, len %d", (int)pos1, (int)len);
	if(d->found_CHIX_chunk) goto done;
	d->found_CHIX_chunk = 1;

	d->font->num_chars = len/9;
	de_dbg(c, "number of characters: %d", (int)d->font->num_chars);

	d->font->char_array = de_malloc(c, d->font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<d->font->num_chars; i++) {
		pos = pos1 + 9*i;
		codepoint = (de_int32)de_getui32be(pos);
		storage_flags = (unsigned int)de_getbyte(pos+4);
		defpos = de_getui32be(pos+5);
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

static int my_pff2_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_CHIX:
		do_code_chix(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	}

	ictx->handled = 1;
	return 1;
}

static void my_identify_and_preprocess_pff2_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	if(ictx->chunkctx->dlen==0xffffffffU) {
		// The 'DATA' chunk's length is usually set to the special value 0xffffffff.
		// We are allowed to adjust ictx->chunkctx->dlen here.
		ictx->chunkctx->dlen = ictx->f->len - ictx->chunkctx->dpos;
	}
}

static void de_run_pff2(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	de_int64 i;

	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->userdata = (void*)d;
	ictx->alignment = 1;
	ictx->identify_chunk_fn = my_identify_and_preprocess_pff2_chunk_fn;
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
