// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// PKM (GrafX2)

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pkm);

struct pkm_ctx {
	de_encoding input_encoding;
	u8 respect_trns;
	u8 pack_byte;
	u8 pack_word;
	i64 w, h;
	i64 ph_size;
	i64 unc_image_size;
	i64 orig_w, orig_h;
	u8 has_back_clr;
	u8 back_clr;
	dbuf *unc_pixels;
	de_color pal[256];
};

static void pkm_decompress_image(deark *c, struct pkm_ctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 nbytes_dcmpr = 0;

	de_dbg(c, "compressed image at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		u8 b;
		u8 b2;
		i64 count;

		if(nbytes_dcmpr >= d->unc_image_size) goto done; // Sufficient output
		if(pos >= c->infile->len) goto done; // No more input

		b = de_getbyte_p(&pos);
		if(b==d->pack_byte) {
			b2 = de_getbyte_p(&pos);
			count = (i64)de_getbyte_p(&pos);
			dbuf_write_run(d->unc_pixels, b2, count);
			nbytes_dcmpr += count;
		}
		else if(b==d->pack_word) {
			b2 = de_getbyte_p(&pos);
			count = de_getu16be_p(&pos);
			dbuf_write_run(d->unc_pixels, b2, count);
			nbytes_dcmpr += count;
		}
		else {
			dbuf_writebyte(d->unc_pixels, b);
			nbytes_dcmpr++;
		}
	}

done:
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, pos-pos1, nbytes_dcmpr);
	de_dbg_indent(c, -1);
}

static void pkm_read_comment(deark *c, struct pkm_ctx *d, i64 pos, i64 len)
{
	de_ucstring *s = NULL;
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, d->input_encoding);
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void pkm_read_orig_screen_size(deark *c, struct pkm_ctx *d, i64 pos, i64 len)
{
	// TODO: Maybe this could be used to set the density, but I suspect it's
	// not reliable.
	if(len!=4) return;
	d->orig_w = de_getu16le(pos);
	d->orig_h = de_getu16le(pos+2);
	de_dbg(c, "original dimensions: %u"DE_CHAR_TIMES"%u", (UI)d->orig_w, (UI)d->orig_h);
}

static void pkm_read_back_color(deark *c, struct pkm_ctx *d, i64 pos, i64 len)
{
	if(len!=1) return;
	d->back_clr = de_getbyte(pos);
	d->has_back_clr = 1;
	de_dbg(c, "back color: 0x%02x", (UI)d->back_clr);
}

static void pkm_read_postheader(deark *c, struct pkm_ctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 endpos = pos1 + d->ph_size;
	int saved_indent_level;

	de_dbg(c, "post-header at %"I64_FMT, pos1);

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg_indent(c, 1);

	while(1) {
		u8 id;
		i64 field_pos;
		i64 field_size;

		field_pos = pos;
		if(field_pos+2 > endpos) goto done;
		id = de_getbyte_p(&pos);
		field_size = (i64)de_getbyte_p(&pos);
		de_dbg(c, "field at %"I64_FMT", type=%u, dlen=%u", field_pos, (UI)id,
			(UI)field_size);
		de_dbg_indent(c, 1);
		switch(id) {
		case 0:
			pkm_read_comment(c, d, pos, field_size);
			break;
		case 1:
			pkm_read_orig_screen_size(c, d, pos, field_size);
			break;
		case 2:
			pkm_read_back_color(c, d, pos, field_size);
			break;
		default:
			de_dbg_hexdump(c, c->infile, pos, field_size, 256, NULL, 0x1);
		}
		de_dbg_indent(c, -1);
		pos += field_size;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_pkm(deark *c, de_module_params *mparams)
{
	struct pkm_ctx *d = NULL;
	de_bitmap *img = NULL;
	i64 pos = 0;
	int bypp;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct pkm_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	d->respect_trns = (u8)de_get_ext_option_bool(c, "pkm:trans", 0);

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 3; // signature
	pos += 1; // version
	d->pack_byte = de_getbyte_p(&pos);
	d->pack_word = de_getbyte_p(&pos);

	d->w = de_getu16le_p(&pos);
	d->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	de_read_simple_palette(c, c->infile, pos, 256, 3, d->pal, 256, DE_RDPALTYPE_VGA18BIT, 0);
	pos += 3*256;

	d->ph_size = de_getu16le_p(&pos);
	de_dbg(c, "post-header size: %u", (UI)d->ph_size);
	de_dbg_indent(c, -1);

	pkm_read_postheader(c, d, pos);
	pos += d->ph_size;

	d->unc_image_size = d->w * d->h;
	d->unc_pixels = dbuf_create_membuf(c, d->unc_image_size, 0x1);
	dbuf_enable_wbuffer(d->unc_pixels);
	pkm_decompress_image(c, d, pos);
	dbuf_flush(d->unc_pixels);

	if(d->respect_trns && d->has_back_clr) {
		bypp = 4;
		// TODO: Understand the "background/transparent" color field better.
		// Making it transparent messes up some images.
		d->pal[(UI)d->back_clr] = DE_SET_ALPHA(d->pal[(UI)d->back_clr], 0);
	}
	else {
		bypp = 3;
	}
	img = de_bitmap_create(c, d->w, d->h, bypp);
	de_convert_image_paletted(d->unc_pixels, 0, 8, d->w, d->pal, img, 0);
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	if(d) {
		dbuf_close(d->unc_pixels);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_pkm(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PKM\0", 4))
		return 100;
	return 0;
}

static void de_help_pkm(deark *c)
{
	de_msg(c, "-opt pkm:trans : Make the background color transparent");
}

void de_module_pkm(deark *c, struct deark_module_info *mi)
{
	mi->id = "pkm";
	mi->desc = "PKM (GrafX2)";
	mi->run_fn = de_run_pkm;
	mi->identify_fn = de_identify_pkm;
	mi->help_fn = de_help_pkm;
}
