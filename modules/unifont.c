// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Unifont HEX font

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_unifont_hex);

struct de_linereader {
	dbuf *f;
	i64 f_pos;
};

static struct de_linereader *de_linereader_create(deark *c, dbuf *f)
{
	struct de_linereader *lr;
	lr = de_malloc(c, sizeof(struct de_linereader));
	lr->f = f;
	return lr;
}

static void de_linereader_destroy(deark *c, struct de_linereader *lr)
{
	if(!lr) return;
	de_free(c, lr);
}

// TODO: Make the linereader more efficient and flexible, and make
// it a standard library function.
static int de_linereader_readnextline(deark *c, struct de_linereader *lr,
	char *buf, size_t buf_len, unsigned int flags)
{
	int ret;
	i64 content_len = 0;
	i64 total_len = 0;

	buf[0] = '\0';

	ret = dbuf_find_line(lr->f, lr->f_pos, &content_len, &total_len);
	if(!ret) return 0;
	if(content_len > (i64)buf_len-1) {
		lr->f_pos += total_len;
		return 0;
	}
	dbuf_read(lr->f, (u8*)buf, lr->f_pos, content_len);
	buf[content_len] = '\0';
	lr->f_pos += total_len;
	return 1;
}

static void decode_fontdata(deark *c, const char *hexdata,
	struct de_bitmap_font_char *ch)
{
	i64 ndstbytes;
	i64 srcpos = 0;
	i64 dstpos = 0;

	ndstbytes = ch->rowspan*ch->height;
	while(1) {
		int errorflag;
		u8 h0, h1;

		h0 = de_decode_hex_digit((unsigned char)hexdata[srcpos++], &errorflag);
		if(errorflag) break;
		h1 = de_decode_hex_digit((unsigned char)hexdata[srcpos++], &errorflag);
		if(errorflag) break;
		ch->bitmap[dstpos++] = (h0<<4)|h1;
		if(dstpos>=ndstbytes) break;
	}
}

static void de_run_unifont_hex(deark *c, de_module_params *mparams)
{
	struct de_bitmap_font *font = NULL;
	i64 char_array_numalloc = 0;
	char linebuf[256];
	struct de_linereader *lr = NULL;
	int ok = 0;

	font = de_create_bitmap_font(c);
	font->has_unicode_codepoints = 1;
	font->prefer_unicode = 1;
	font->nominal_height = 16;
	char_array_numalloc = 1024;
	font->char_array = de_mallocarray(c, char_array_numalloc, sizeof(struct de_bitmap_font_char));

	lr = de_linereader_create(c, c->infile);

	while(de_linereader_readnextline(c, lr, linebuf, sizeof(linebuf), 0)) {
		i64 idx;
		struct de_bitmap_font_char *ch;
		i64 fdata_len;
		char *dptr; // Pointer into linebuf, to the char after the ":"

		if(font->num_chars>=17*65536) goto done;

		idx = font->num_chars;
		if(idx >= char_array_numalloc) {
			i64 new_numalloc = char_array_numalloc*2;
			font->char_array = de_reallocarray(c, font->char_array,
				char_array_numalloc, sizeof(struct de_bitmap_font_char),
				new_numalloc);
			char_array_numalloc = new_numalloc;
		}
		ch = &font->char_array[idx];

		dptr = de_strchr(linebuf, ':');
		if(!dptr) goto done;
		*dptr = '\0';
		dptr++;

		fdata_len = (i64)de_strlen(dptr);
		ch->codepoint_unicode = (i32)de_strtoll(linebuf, NULL, 16);
		if(ch->codepoint_unicode<0 || ch->codepoint_unicode>=17*65536) goto done;

		ch->width = (int)((fdata_len/32)*8);
		ch->height = 16;
		de_dbg2(c, "char[%d] U+%04X %d"DE_CHAR_TIMES"%d",
			(int)font->num_chars, (unsigned int)ch->codepoint_unicode,
			ch->width, ch->height);
		if(ch->width<8 || ch->width>32) goto done;
		ch->rowspan = (ch->width+7)/8;
		ch->bitmap = de_malloc(c, ch->rowspan * ch->height);
		decode_fontdata(c, dptr, ch);

		font->num_chars++;
		if(ch->width > font->nominal_width) {
			font->nominal_width = ch->width;
		}
	}

	de_dbg(c, "number of characters: %d", (int)font->num_chars);
	if(font->num_chars<1) goto done;
	if(font->nominal_width<1) goto done;

	de_font_bitmap_font_to_image(c, font, NULL, 0);
	ok = 1;

done:
	if(!ok) {
		de_err(c, "Error parsing HEX font file (offset %"I64_FMT")", lr->f_pos);
	}
	de_linereader_destroy(c, lr);
	if(font) {
		if(font->char_array) {
			i64 k;
			for(k=0; k<font->num_chars; k++) {
				de_free(c, font->char_array[k].bitmap);
			}
			de_free(c, font->char_array);
		}
		font->char_array = NULL;
		de_destroy_bitmap_font(c, font);
	}
}

void de_module_unifont_hex(deark *c, struct deark_module_info *mi)
{
	mi->id = "unifont_hex";
	mi->desc = "GNU Unifont HEX font";
	mi->run_fn = de_run_unifont_hex;
}
