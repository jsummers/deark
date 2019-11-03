// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// MegaPaint BLD image
// MegaPaint .PAT
// MegaPaint .LIB

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_bld);
DE_DECLARE_MODULE(de_module_megapaint_pat);
DE_DECLARE_MODULE(de_module_megapaint_lib);

// **************************************************************************
// MegaPaint BLD image
// **************************************************************************

static void de_run_bld(deark *c, de_module_params *mparams)
{
	i64 w_raw, h_raw;
	i64 w, h;
	i64 rowspan;
	i64 pos = 0;
	int is_compressed;
	dbuf *unc_pixels = NULL;

	w_raw = de_geti16be_p(&pos);
	h_raw = de_geti16be_p(&pos);
	is_compressed = (w_raw<0);
	w = is_compressed ? ((-w_raw)+1) : (w_raw+1);
	h = h_raw+1;
	de_dbg_dimensions(c, w, h);
	de_dbg(c, "compressed: %d", is_compressed);
	if(!de_good_image_dimensions(c, w, h)) goto done;
	rowspan = (w+7)/8;

	if(is_compressed) {
		unc_pixels = dbuf_create_membuf(c, h*rowspan, 1);
		while(1) {
			u8 b1;
			i64 count;

			if(pos >= c->infile->len) break;
			if(unc_pixels->len >= h*rowspan) break;

			b1 = de_getbyte_p(&pos);
			if(b1==0x00 || b1==0xff) {
				count = 1+(i64)de_getbyte_p(&pos);
				dbuf_write_run(unc_pixels, b1, count);
			}
			else {
				dbuf_writebyte(unc_pixels, b1);
			}
		}
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len-pos);
	}

	de_convert_and_write_image_bilevel(unc_pixels, 0, w, h, rowspan,
		DE_CVTF_WHITEISZERO, NULL, 0);

done:
	dbuf_close(unc_pixels);
}

static int de_identify_bld(deark *c)
{
	if(de_input_file_has_ext(c, "bld")) return 20;
	// TODO: We could try to test if the dimensions are sane, but we'd risk
	// getting it wrong, because we probably don't know what every edition of
	// MegaPaint does.
	return 0;
}

void de_module_bld(deark *c, struct deark_module_info *mi)
{
	mi->id = "bld";
	mi->desc = "MegaPaint BLD";
	mi->run_fn = de_run_bld;
	mi->identify_fn = de_identify_bld;
}

// **************************************************************************
// MegaPaint .PAT
// **************************************************************************

static void de_run_megapaint_pat(deark *c, de_module_params *mparams)
{
	// Note: This module is based on guesswork, and may be incomplete.
	de_bitmap *mainimg = NULL;
	i64 main_w, main_h;
	i64 pos = 0;
	i64 k;

	pos += 8;
	main_w = 1+(32+1)*16;
	main_h = 1+(32+1)*2;

	mainimg = de_bitmap_create(c, main_w, main_h, 1);
	de_bitmap_rect(mainimg, 0, 0, main_w, main_h, DE_MAKE_GRAY(128), 0);

	for(k=0; k<32; k++) {
		de_bitmap *img = NULL;
		i64 imgpos_x, imgpos_y;

		img = de_bitmap_create(c, 32, 32, 1);
		de_convert_image_bilevel(c->infile, pos, 4, img, DE_CVTF_WHITEISZERO);
		pos += 4*32;

		imgpos_x = 1+(32+1)*(k%16);
		imgpos_y = 1+(32+1)*(k/16);
		de_bitmap_copy_rect(img, mainimg, 0, 0, 32, 32, imgpos_x, imgpos_y, 0);
		de_bitmap_destroy(img);
	}

	de_bitmap_write_to_file(mainimg, NULL, 0);
	de_bitmap_destroy(mainimg);
}

static int de_identify_megapaint_pat(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x07" "PAT", 4))
		return 0;
	if(c->infile->len==4396) return 100;
	return 40;
}

void de_module_megapaint_pat(deark *c, struct deark_module_info *mi)
{
	mi->id = "megapaint_pat";
	mi->desc = "MegaPaint Patterns";
	mi->run_fn = de_run_megapaint_pat;
	mi->identify_fn = de_identify_megapaint_pat;
}

// **************************************************************************
// MegaPaint .LIB
// **************************************************************************

static void de_run_megapaint_lib(deark *c, de_module_params *mparams)
{
	// Note: This module is based on guesswork, and may be incomplete.
	const i64 idxpos = 14;
	i64 k;
	i64 nsyms;

	nsyms = 1+de_getu16be(12);
	de_dbg(c, "number of symbols: %d", (int)nsyms);

	for(k=0; k<nsyms; k++) {
		i64 sym_offs;
		i64 w, h, rowspan;

		sym_offs = de_getu32be(idxpos+4*k);
		de_dbg(c, "symbol #%d", (int)(1+k));
		de_dbg_indent(c, 1);
		de_dbg(c, "offset: %u", (unsigned int)sym_offs);

		w = 1+de_getu16be(sym_offs);
		h = 1+de_getu16be(sym_offs+2);
		de_dbg_dimensions(c, w, h);
		rowspan = ((w+15)/16)*2;
		de_convert_and_write_image_bilevel(c->infile, sym_offs+4, w, h, rowspan,
			DE_CVTF_WHITEISZERO, NULL, 0);
		de_dbg_indent(c, -1);
	}
}

static int de_identify_megapaint_lib(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\x07" "LIB", 4))
		return 0;
	if(de_input_file_has_ext(c, "lib")) return 100;
	return 40;
}

void de_module_megapaint_lib(deark *c, struct deark_module_info *mi)
{
	mi->id = "megapaint_lib";
	mi->desc = "MegaPaint Symbol Library";
	mi->run_fn = de_run_megapaint_lib;
	mi->identify_fn = de_identify_megapaint_lib;
}
