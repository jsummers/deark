// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// Graphic Workshop formats (Alchemy Mindworks)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gws_thn);
DE_DECLARE_MODULE(de_module_gws_exepic);

// **************************************************************************
// Graphic Workshop .THN
// **************************************************************************

static void de_run_gws_thn(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	u8 v1, v2;
	i64 w, h;
	i64 pos;
	de_encoding encoding;
	de_ucstring *s = NULL;
	u32 pal[256];

	// This code is based on reverse engineering, and may be incorrect.
	encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	pos = 4;
	v1 = de_getbyte_p(&pos);
	v2 = de_getbyte_p(&pos);
	de_dbg(c, "version?: 0x%02x 0x%02x", (unsigned int)v1, (unsigned int)v2);

	s = ucstring_create(c);
	// For the text fields, the field size appears to be 129, but the software
	// only properly supports up to 127 non-NUL bytes.
	dbuf_read_to_ucstring(c->infile, 6, 127, s, DE_CONVFLAG_STOP_AT_NUL, encoding);
	if(s->len>0) de_dbg(c, "comments: \"%s\"", ucstring_getpsz_d(s));
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, 135, 127, s, DE_CONVFLAG_STOP_AT_NUL, encoding);
	if(s->len>0) de_dbg(c, "key words: \"%s\"", ucstring_getpsz_d(s));

	pos = 264;
	de_dbg(c, "image at %"I64_FMT, pos);
	w = 96;
	h = 96;

	// Set up the palette. There are two possible fixed palettes.
	if(v1==0) { // Original palette
		// Based on Graphic Workshop v1.1a for Windows
		static const u8 rbvals[6] = {0x00,0x57,0x83,0xab,0xd7,0xff};
		static const u8 gvals[7] = {0x00,0x2b,0x57,0x83,0xab,0xd7,0xff};
		static const u32 gwspal_last5[5] = {0x3f3f3f,0x6b6b6b,0x979797,
			0xc3c3c3,0xffffff};
		unsigned int k;

		for(k=0; k<=250; k++) {
			pal[k] = DE_MAKE_RGB(
				rbvals[k%6],
				gvals[(k%42)/6],
				rbvals[k/42]);
		}
		for(k=251; k<=255; k++) {
			pal[k] = gwspal_last5[k-251];
		}
	}
	else { // New palette (really RGB332), introduced by v1.1c
		// Based on Graphic Workshop v1.1u for Windows
		unsigned int k;

		for(k=0; k<256; k++) {
			u8 r, g, b;
			r = de_sample_nbit_to_8bit(3, k>>5);
			g = de_sample_nbit_to_8bit(3, (k>>2)&0x07);
			b = de_sample_nbit_to_8bit(2, k&0x03);
			pal[k] = DE_MAKE_RGB(r, g, b);
		}
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(c->infile, pos, 8, w, pal, img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);
	de_bitmap_destroy(img);
	ucstring_destroy(s);
}

static int de_identify_gws_thn(deark *c)
{
	if(c->infile->len!=9480) return 0;
	if(!dbuf_memcmp(c->infile, 0, "THNL", 4)) return 100;
	return 0;
}

void de_module_gws_thn(deark *c, struct deark_module_info *mi)
{
	mi->id = "gws_thn";
	mi->desc = "Graphic Workshop thumbnail .THN";
	mi->run_fn = de_run_gws_thn;
	mi->identify_fn = de_identify_gws_thn;
}

// **************************************************************************
// GWS self-displaying picture (DOS EXE format)
// **************************************************************************

struct gws_exepic_ctx {
	u8 need_errmsg;
	UI cmpr_meth;
	i64 imgpos;
	i64 depth;
	i64 w, h;
	i64 nplanes;
	i64 unc_image_size;
	i64 byprpp; // bytes per row per plane
	i64 ncolors;
	const char *msgpfx;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
	de_color pal[256];
};

static void gwsexe_decompress(deark *c, struct gws_exepic_ctx *d, dbuf *unc_pixels)
{
	i64 ipos = d->imgpos;
	i64 nbytes_decompressed = 0;

	while(1) {
		u8 b0;
		u8 val;
		i64 count;

		if(ipos >= c->infile->len) goto done;
		if(nbytes_decompressed >= d->unc_image_size) goto done;

		b0 = de_getbyte_p(&ipos);
		if(b0 < 0xc0) {
			count = 1;
			val = b0;
		}
		else {
			// TODO: Figure out what opcode 0xc0 means. I've never seen it used.
			count = (i64)(b0-0xc0);
			val = de_getbyte_p(&ipos);
		}

		dbuf_write_run(unc_pixels, val, count);
		nbytes_decompressed += count;
	}
done:
	;
}

static void gwsexe_decode_decompressed_image(deark *c, struct gws_exepic_ctx *d,
	dbuf *inf, i64 inf_pos)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, d->w, d->h, 3);
	if(d->depth==4) {
		de_convert_image_paletted_planar(inf, inf_pos, d->depth,
			d->byprpp*d->depth, d->byprpp, d->pal, img, 0x2);
	}
	else {
		de_convert_image_paletted(inf, inf_pos, d->depth, d->byprpp, d->pal,
			img, 0);
	}
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void do_gwsexe_image(deark *c, struct gws_exepic_ctx *d)
{
	dbuf *unc_pixels = NULL;

	de_dbg(c, "image at %"I64_FMT, d->imgpos);
	de_dbg_indent(c, 1);
	if(d->cmpr_meth==2) {
		unc_pixels = dbuf_create_membuf(c, d->unc_image_size, 0x1);
		gwsexe_decompress(c, d, unc_pixels);
		gwsexe_decode_decompressed_image(c, d, unc_pixels, 0);
	}
	else {
		gwsexe_decode_decompressed_image(c, d, c->infile, d->imgpos);
	}

	dbuf_close(unc_pixels);
	de_dbg_indent(c, -1);
}

static void de_run_gws_exepic(deark *c, de_module_params *mparams)
{
	struct gws_exepic_ctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(struct gws_exepic_ctx));
	d->msgpfx = "[GWS picture] ";
	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	fmtutil_collect_exe_info(c, c->infile, d->ei);

	d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_GWS_EXEPIC;
	fmtutil_detect_specialexe(c, d->ei, &d->edd);
	if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_GWS_EXEPIC) {
		d->need_errmsg = 1;
		goto done;
	}

	pos = d->ei->start_of_dos_code + 9;

	// My best guess as to how to calculate the image position.
	// The field at CS:9 is not actually used by the executable code. Instead
	// it's overwritten with a hardcoded value that is observed to be identical.
	// Then it is adjusted in some way.
	d->imgpos = de_getu16le_p(&pos);
	d->imgpos = de_pad_to_n(d->imgpos, 16);
	d->imgpos = d->ei->start_of_dos_code + d->imgpos;
	de_dbg(c, "img pos: %"I64_FMT, d->imgpos);

	d->w = de_getu16le_p(&pos);
	d->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	d->byprpp = de_getu16le_p(&pos);
	d->depth = de_getu16le_p(&pos);
	de_dbg(c, "depth: %u", (UI)d->depth);
	d->cmpr_meth = (UI)de_getu16le_p(&pos);
	de_dbg(c, "cmpr meth: %u", d->cmpr_meth);
	if(d->depth!=1 && d->depth!=4 && d->depth!=8) {
		d->need_errmsg = 1;
		goto done;
	}
	d->nplanes = (d->depth==4) ? d->depth : 1;
	d->unc_image_size = d->byprpp * d->nplanes * d->h;
	d->ncolors = (i64)1 << d->depth;
	de_read_simple_palette(c, c->infile, d->ei->start_of_dos_code+54,
		d->ncolors, 3, d->pal, 256, DE_RDPALTYPE_24BIT, 0);

	if(d->cmpr_meth!=1 && d->cmpr_meth!=2) {
		de_err(c, "%sUnsupported compression", d->msgpfx);
		goto done;
	}

	if(!de_good_image_dimensions(c, d->w, d->h)) {
		goto done;
	}

	do_gwsexe_image(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "%sBad or unsupported GWS EXE picture", d->msgpfx);
		}
		de_free(c, d->ei);
		de_free(c, d);
	}
}

void de_module_gws_exepic(deark *c, struct deark_module_info *mi)
{
	mi->id = "gws_exepic";
	mi->desc = "Graphic Workshop self-displaying picture";
	mi->run_fn = de_run_gws_exepic;
}
