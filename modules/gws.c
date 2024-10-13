// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// Graphic Workshop formats (Alchemy Mindworks)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gws_exepic);

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
