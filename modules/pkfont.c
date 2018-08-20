// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// PK font ("packed font")

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pkfont);

struct page_ctx {
	de_int32 cc;
	int w, h;
	de_int64 tfm;
	de_int64 dm;
	de_int64 hoff, voff;
	de_int64 dyn_f;
	int start_with_black;
	de_int64 raster_pos;
	de_int64 raster_len;

	de_int64 curpos_x, curpos_y;
	de_int64 pixelcount;
};

typedef struct localctx_struct {
	struct de_bitmap_font *font;
	de_int64 char_array_alloc;
} lctx;

static void do_preamble(deark *c, lctx *d, de_int64 pos, de_int64 *bytesused)
{
	de_int64 comment_len;

	de_dbg(c, "preamble at %d", (int)pos);
	de_dbg_indent(c, 1);

	// (identification byte (should be 89) is at pos+1)

	comment_len = (de_int64)de_getbyte(pos+2);
	de_dbg(c, "comment length: %d", (int)comment_len);

	*bytesused = 3+comment_len+16;
	de_dbg_indent(c, -1);
}

static de_int64 do_get_signed_byte(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_getbyte(f, pos);
	if(n>=128) n -= 256;
	return n;
}

static de_int64 do_getui24be(dbuf *f, de_int64 pos)
{
	return dbuf_getint_ext(f, pos, 3, 0, 0);
}

static de_byte get_nybble(dbuf *f, de_int64 abs_byte_pos, de_int64 nybble_offs)
{
	de_byte b;
	b = dbuf_getbyte(f, abs_byte_pos + nybble_offs/2);
	if(nybble_offs%2) {
		return b&0x0f;
	}
	return b>>4;
}

static int get_packed_int(dbuf *f, de_int64 raster_pos, de_int64 *nybble_pos,
	de_int64 initial_zero_count, de_int64 *result)
{
	de_byte v = 0;
	de_int64 zero_count = initial_zero_count;
	de_int64 val;
	de_int64 i;

	while(1) {
		v = get_nybble(f, raster_pos, *nybble_pos);
		(*nybble_pos)++;

		if(v==0) {
			zero_count++;
			if(zero_count>16) { // Sanity check
				de_err(f->c, "Bad packed int at %d", (int)raster_pos);
				*result = 0;
				return 0;
			}
		}
		else {
			break;
		}
	}

	val = (de_int64)v;
	// There are zero_count+1 data nybbles, but we've already read the first one,
	// so we need to read zero_count more of them.
	for(i=0; i<zero_count; i++) {
		val = (val<<4) | get_nybble(f, raster_pos, *nybble_pos);
		(*nybble_pos)++;
	}

	*result = val;
	return 1;
}

static void set_bit_at_cur_pos(struct de_bitmap_font_char *ch, struct page_ctx *pg)
{
	de_int64 bytepos;
	de_int64 bitpos;

	if(pg->curpos_x<0 || pg->curpos_x>=pg->w) return;
	if(pg->curpos_y<0 || pg->curpos_y>=pg->h) return;

	bytepos = pg->curpos_y*ch->rowspan + pg->curpos_x/8;
	bitpos = pg->curpos_x%8;
	ch->bitmap[bytepos] |= 1<<(7-bitpos);
}

// Copy row number pg->curpos_y-1 zero more more times, updating
// pg->curpos_y as appropriate.
static void repeat_row_as_needed(struct de_bitmap_font_char *ch, struct page_ctx *pg, de_int64 repeat_count)
{
	de_int64 z;
	de_int64 from_row, to_row;

	from_row = pg->curpos_y-1;
	if(from_row<0) return;

	for(z=0; z<repeat_count; z++) {
		to_row = pg->curpos_y;
		if(to_row>=pg->h) return;
		de_memcpy(&ch->bitmap[to_row*ch->rowspan], &ch->bitmap[from_row*ch->rowspan], (size_t)ch->rowspan);
		pg->curpos_y++;
		pg->pixelcount += pg->w;
	}
}

static void do_read_raster(deark *c, lctx *d, struct page_ctx *pg)
{
	de_int64 char_idx;
	struct de_bitmap_font_char *ch;
	de_byte v, v1;
	de_int64 nybble_pos;
	de_int64 expected_num_pixels;
	de_int64 j;
	de_int64 k;
	int parity;
	int next_num_is_repeat_count;
	de_int64 number;
	de_int64 run_count;
	de_int64 repeat_count;

	de_dbg(c, "%scompressed character raster at %d, len=%d", pg->dyn_f==14?"un":"",
		(int)pg->raster_pos, (int)pg->raster_len);
	de_dbg_indent(c, 1);

	expected_num_pixels = pg->w * pg->h;
	if(expected_num_pixels<1) {
		de_dbg(c, "ignoring zero-size character (cc=%d) at %d",
			(int)pg->cc, (int)pg->raster_pos);
		goto done;
	}

	// Make sure we have room for the new character
	if(d->font->num_chars+1 > d->char_array_alloc) {
		de_int64 new_numalloc;
		new_numalloc = d->char_array_alloc*2;
		if(new_numalloc<d->font->num_chars+1) new_numalloc=d->font->num_chars+1;
		if(new_numalloc<37) new_numalloc=37;
		d->font->char_array = de_realloc(c, d->font->char_array,
			d->char_array_alloc * sizeof(struct de_bitmap_font_char),
			new_numalloc * sizeof(struct de_bitmap_font_char));
		d->char_array_alloc = new_numalloc;
	}

	// Create the new character
	char_idx = d->font->num_chars++;

	ch = &d->font->char_array[char_idx];
	ch->width = pg->w;
	ch->height = pg->h;

	// The vertical offset will be normalized later, once we know the offsets
	// of all the characters.
	ch->v_offset = (int)-pg->voff;

	ch->rowspan = (ch->width+7)/8;
	ch->bitmap = de_malloc(c, ch->rowspan * ch->height);
	ch->codepoint_nonunicode = pg->cc;

	if(pg->dyn_f==14) {
		de_byte *srcbitmap;
		de_int64 srcbitmap_size;

		srcbitmap_size = (pg->w*pg->h+7)/8;
		srcbitmap = de_malloc(c, srcbitmap_size);
		de_read(srcbitmap, pg->raster_pos, srcbitmap_size);
		for(j=0; j<pg->h; j++) {
			de_copy_bits(srcbitmap, j*ch->width, ch->bitmap, j*ch->rowspan*8, ch->width);
		}

		de_free(c, srcbitmap);
		goto done;
	}

	nybble_pos = 0;
	number = 0;
	parity = pg->start_with_black;
	repeat_count = 0;
	next_num_is_repeat_count = 0;
	pg->curpos_x = 0;
	pg->curpos_y = 0;
	pg->pixelcount = 0;

	while(1) {
		double initial_abs_nybble_pos = (double)pg->raster_pos + (double)nybble_pos/2.0;

		if(nybble_pos >= pg->raster_len*2) break; // out of source data
		if(pg->curpos_y>=pg->h) break; // reached end of image

		v = get_nybble(c->infile, pg->raster_pos, nybble_pos++);

		// The compressed data is a sequence of tokens.
		// A token consists of one or more nybbles.
		// A token beginning with nybble value 0 through 13 represents a number.
		// A number is either a "run count" or a "repeat count".
		// 14 and 15 are special one-nybble tokens.
		// 14 indicates that the next number is a repeat count (instead of a run count).
		// 15 means to set the current repeat count to 1.

		if(v==14) {
			next_num_is_repeat_count = 1;
			de_dbg2(c, "[%.1f] n=%d; repeat_count=...", initial_abs_nybble_pos,
				(int)v);
			continue;
		}
		else if(v==15) { // v==15: repeat count = 1
			de_dbg2(c, "[%.1f] n=%d; repeat_count=1", initial_abs_nybble_pos, (int)v);
			repeat_count = 1;
			continue;
		}

		// If we get here, then this nybble represents a number, or the start of a number.

		if(v==0) { // large run count
			if(!get_packed_int(c->infile, pg->raster_pos, &nybble_pos, 1, &number)) goto done;
			number = number - 15 + (13-pg->dyn_f)*16 + pg->dyn_f;
		}
		else if(v<=pg->dyn_f) { // one-nybble run count
			number = (de_int64)v;
		}
		else if(v<=13) { // two-nybble run count
			v1 = get_nybble(c->infile, pg->raster_pos, nybble_pos++);
			number = ((de_int64)v-pg->dyn_f-1)*16 + v1 + pg->dyn_f + 1;
		}

		if(next_num_is_repeat_count) {
			de_dbg2(c, "[%.1f] ...%d", initial_abs_nybble_pos, (int)number);
			repeat_count = number;
			next_num_is_repeat_count = 0;
			continue;
		}

		// If we get here, we have a number that represents a run count (not a
		// repeat count).
		// Apply it to the character bitmap.

		run_count = number;

		de_dbg2(c, "[%.1f] n=%d; run_count=%d %s", initial_abs_nybble_pos,
			(int)v, (int)run_count, parity?"B":"W");

		for(k=0; k<run_count; k++) {
			pg->pixelcount++;
			if(parity) {
				set_bit_at_cur_pos(ch, pg);
			}
			pg->curpos_x++;

			if(pg->curpos_x>=pg->w) {
				pg->curpos_y++;
				pg->curpos_x = 0;

				// A repeat count applies to the "row on which the first pixel of
				// the next run count will lie".
				// This means that repeats should be applied immediately after the
				// last pixel of a row has been emitted (as opposed to immediately
				// before the first pixel of a row is emitted).
				repeat_row_as_needed(ch, pg, repeat_count);
				repeat_count = 0;
			}
		}
		parity = !parity;
	}

	if(pg->pixelcount != expected_num_pixels) {
		de_warn(c, "Expected %d pixels, got %d (codepoint %d)", (int)expected_num_pixels,
			(int)pg->pixelcount, (int)pg->cc);
	}

done:
	de_dbg_indent(c, -1);
}

static int do_char_descr(deark *c, lctx *d, de_int64 pos, de_int64 *bytesused)
{
	de_byte flagbyte;
	de_byte lsb3;
#define CHAR_PREAMBLE_FORMAT_SHORT      1
#define CHAR_PREAMBLE_FORMAT_EXT_SHORT  2
#define CHAR_PREAMBLE_FORMAT_LONG       3
	int char_preamble_format;
	de_int64 pl;
	de_int64 tfm_offs;
	struct page_ctx *pg = NULL;
	int retval = 0;

	pg = de_malloc(c, sizeof(struct page_ctx));

	de_dbg(c, "character descriptor at %d", (int)pos);
	de_dbg_indent(c, 1);

	flagbyte = de_getbyte(pos);
	pg->dyn_f = ((de_int64)flagbyte)>>4;
	de_dbg(c, "dyn_f: %d", (int)pg->dyn_f);

	// Character preamble format: (lsb=...)
	// 0-3: short format
	// 4-6: extended short format
	// 7: long form
	lsb3 = flagbyte&0x7;

	pg->start_with_black = (flagbyte&0x8)?1:0;

	if(lsb3==7) {
		char_preamble_format = CHAR_PREAMBLE_FORMAT_LONG;
	}
	else if(lsb3>=4) {
		char_preamble_format = CHAR_PREAMBLE_FORMAT_EXT_SHORT;
	}
	else {
		char_preamble_format = CHAR_PREAMBLE_FORMAT_SHORT;
	}

	if(char_preamble_format==CHAR_PREAMBLE_FORMAT_SHORT) {
		pl = (de_int64)de_getbyte(pos+1);
		pl |= (flagbyte&0x03)<<8;
		pg->cc = (de_int32)de_getbyte(pos+2);
		tfm_offs = 3;
		pg->tfm = do_getui24be(c->infile, pos+tfm_offs);
		pg->dm = (de_int64)de_getbyte(pos+6);
		pg->w = (int)de_getbyte(pos+7);
		pg->h = (int)de_getbyte(pos+8);
		pg->hoff = do_get_signed_byte(c->infile, pos+9);
		pg->voff = do_get_signed_byte(c->infile, pos+10);
		pg->raster_pos = pos + 11;
	}
	else if(char_preamble_format==CHAR_PREAMBLE_FORMAT_EXT_SHORT) {
		pl = de_getui16be(pos+1);
		pl |= (flagbyte&0x03)<<16;
		pg->cc = (de_int32)de_getbyte(pos+3);
		tfm_offs = 4;
		pg->tfm = do_getui24be(c->infile, pos+tfm_offs);
		pg->dm = de_getui16be(pos+7);
		pg->w = (int)de_getui16be(pos+9);
		pg->h = (int)de_getui16be(pos+11);
		pg->hoff = de_geti16be(pos+13);
		pg->voff = de_geti16be(pos+15);
		pg->raster_pos = pos + 17;
	}
	else {
		de_err(c, "Unsupported character preamble format (%d)", (int)lsb3);
		goto done;
	}

	de_dbg(c, "pl=%d cc=%d tfm=%d dm=%d w=%d h=%d hoff=%d voff=%d",
		(int)pl, (int)pg->cc, (int)pg->tfm, (int)pg->dm, (int)pg->w, (int)pg->h,
		(int)pg->hoff, (int)pg->voff);

	pg->raster_len = (pos+tfm_offs+pl)-pg->raster_pos;
	do_read_raster(c, d, pg);

	*bytesused = tfm_offs + pl;
	retval = 1;

done:
	de_dbg_indent(c, -1);
	de_free(c, pg);
	return retval;
}

static const char *get_flagbyte_name(de_byte flagbyte)
{
	if(flagbyte<240) return "character descriptor";
	switch(flagbyte) {
	case 240: return "special xxx1";
	case 241: return "special xxx2";
	case 242: return "special xxx3";
	case 243: return "special xxx4";
	case 244: return "special yyy";
	case 245: return "postamble";
	case 246: return "no-op";
	case 247: return "preamble";
	}
	return "?";
}

static void scan_and_fixup_font(deark *c, lctx *d)
{
	struct de_bitmap_font_char *ch;
	de_int64 i;
	int min_v_pos = 1000000;
	int max_v_pos = -1000000;

	// Find the maximum character width, and the bounding box of the character heights.
	for(i=0; i<d->font->num_chars; i++) {
		ch = &d->font->char_array[i];

		if(ch->width > d->font->nominal_width)
			d->font->nominal_width = ch->width;

		if(ch->v_offset < min_v_pos)
			min_v_pos = ch->v_offset;

		if(ch->v_offset + ch->height > max_v_pos)
			max_v_pos = ch->v_offset + ch->height;
	}

	d->font->nominal_height = max_v_pos - min_v_pos;

	// Another pass, to fixup the v_offsets so that the minimum one is 0.
	for(i=0; i<d->font->num_chars; i++) {
		ch = &d->font->char_array[i];

		ch->v_offset -= min_v_pos;
	}
}

static void de_run_pkfont(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 bytesused;
	de_int64 i;
	de_byte flagbyte;
	de_int64 chars_in_file = 0;

	d = de_malloc(c, sizeof(lctx));
	d->font = de_create_bitmap_font(c);
	d->font->has_nonunicode_codepoints = 1;

	pos = 0;
	while(pos < c->infile->len) {
		flagbyte = de_getbyte(pos);
		de_dbg(c, "flag byte at %d: 0x%02x (%s)", (int)pos, (unsigned int)flagbyte,
			get_flagbyte_name(flagbyte));
		bytesused = 0;

		if(flagbyte >= 240) {
			switch(flagbyte) {
			case 240:
				bytesused = 2 + (de_int64)de_getbyte(pos+1);
				break;
			//case 241: // TODO
			//case 242: // TODO
			//case 243: // TODO
			case 244:
				bytesused = 5;
				break;
			case 245: // postamble
				goto done_reading;
			case 246: // no-op
				bytesused = 1;
				break;
			case 247:
				do_preamble(c, d, pos, &bytesused);
				break;
			default:
				de_err(c, "Unsupported command: %d at %d", (int)flagbyte, (int)pos);
				goto done;
			}
		}
		else {
			chars_in_file++;
			if(!do_char_descr(c, d, pos, &bytesused)) goto done;
		}

		if(bytesused<1) break;
		pos += bytesused;
	}

done_reading:
	de_dbg(c, "number of characters: %d (%d processed)", (int)chars_in_file,
		(int)d->font->num_chars);

	scan_and_fixup_font(c, d);
	de_font_bitmap_font_to_image(c, d->font, NULL, 0);

done:
	if(d->font) {
		if(d->font->char_array) {
			for(i=0; i<d->font->num_chars; i++) {
				de_free(c, d->font->char_array[i].bitmap);
			}
			de_free(c, d->font->char_array);
		}
		de_destroy_bitmap_font(c, d->font);
	}
	de_free(c, d);
}

static int de_identify_pkfont(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xf7\x59", 2))
		return 75;
	return 0;
}

void de_module_pkfont(deark *c, struct deark_module_info *mi)
{
	mi->id = "pkfont";
	mi->desc = "PK Font";
	mi->run_fn = de_run_pkfont;
	mi->identify_fn = de_identify_pkfont;
}
