// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// IFF CDI IMAG

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_cdi_imag);

#define CODE_FORM 0x464f524dU
#define CODE_IDAT 0x49444154U
#define CODE_IHDR 0x49484452U
#define CODE_PLTE 0x504c5445U

struct cdi_imag_ctx {
	i64 npwidth, pdwidth, h;
	i64 rowspan;
	UI model;
	UI depth;
	u8 found_IHDR;
	de_color pal[256];
};

static const char *get_cdi_imag_model_name(UI n)
{
	static const char *names[10] = { "RGB888", "RGB555", "DYUV", "CLUT8",
		"CLUT7", "CLUT4", "CLUT3", "RL7", "RL3", "PLTE" };

	if(n>=1 && n<=10) return names[n-1];
	return "?";
}

static void do_cdi_imag_IHDR(deark *c, struct cdi_imag_ctx *d, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;
	if(ictx->chunkctx->dlen<10) return;
	d->found_IHDR = 1;
	d->npwidth = dbuf_getu16be_p(ictx->f, &pos);
	d->rowspan = dbuf_getu16be_p(ictx->f, &pos);
	d->h = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg_dimensions(c, d->npwidth, d->h);
	de_dbg(c, "bytes/row: %u", (UI)d->rowspan);
	d->model = (UI)dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "model: %u (%s)", d->model, get_cdi_imag_model_name(d->model));
	d->depth = (UI)dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "bits/pixel: %u", d->depth);

	if(d->depth==4 || d->depth==8) {
		d->pdwidth = (d->rowspan*8)/d->depth;
	}
}

static void do_cdi_imag_PLTE(deark *c, struct cdi_imag_ctx *d, struct de_iffctx *ictx)
{
	i64 offset;
	i64 count;

	offset = dbuf_getu16be(ictx->f, ictx->chunkctx->dpos);
	count = dbuf_getu16be(ictx->f, ictx->chunkctx->dpos+2);
	de_dbg(c, "entries: %u", (UI)count);
	if(offset>255 || count<1) return;
	de_read_palette_rgb(ictx->f, ictx->chunkctx->dpos+4, count, 3,
		&d->pal[offset], 256-offset, 0);
}

static int cdi_imag_decompress_rl7(deark *c, struct cdi_imag_ctx *d, struct de_iffctx *ictx,
	dbuf *unc_pixels)
{
	i64 pos, endpos;
	i64 xpos = 0;
	i64 ypos = 0;
	int need_errmsg = 0;

	pos = ictx->chunkctx->dpos;
	endpos = pos + ictx->chunkctx->dlen;

	while(1) {
		u8 x;
		u8 palent;
		u8 eoln_flag = 0;
		i64 count;

		if(ypos >= d->h) break;

		if(pos >= endpos) {
			need_errmsg = 1;
			goto done;
		}

		x = dbuf_getbyte_p(ictx->f, &pos);
		palent = x & 0x7f;
		if(x & 0x80) { // run
			u8 r;

			r = dbuf_getbyte_p(ictx->f, &pos);
			if(r>=2) {
				count = (i64)r;
			}
			else if(r==0) {
				eoln_flag = 1;
				count = d->npwidth - xpos;
			}
			else {
				de_err(c, "Unsupported compression feature");
				goto done;
			}
		}
		else { // single pixel
			count = 1;
		}

		if(xpos+count > d->npwidth) {
			need_errmsg = 1;
			count = d->npwidth - xpos;
		}
		dbuf_write_run(unc_pixels, palent, count);
		xpos += count;

		if(eoln_flag) {
			ypos++;
			xpos = 0;
		}
	}

done:
	dbuf_flush(unc_pixels);
	if(need_errmsg) {
		de_err(c, "Image decompression failed");
	}
	return (unc_pixels->len>0);
}

static int do_cdi_imag_model8(deark *c, struct cdi_imag_ctx *d, struct de_iffctx *ictx,
	de_bitmap *img)
{
	int retval = 0;
	dbuf *unc_pixels = NULL;

	if(d->depth!=8) return 0;

	unc_pixels = dbuf_create_membuf(c, d->npwidth*d->h, 0x1);
	dbuf_enable_wbuffer(unc_pixels);
	if(!cdi_imag_decompress_rl7(c, d, ictx, unc_pixels)) goto done;
	// Note: There are ways to change the palette partway through the image,
	// so if we were to fully support this model, we could not use
	// de_convert_image_paletted().
	de_convert_image_paletted(unc_pixels, 0, (i64)d->depth,
		d->npwidth, d->pal, img, 0);
	retval = 1;

done:
	dbuf_close(unc_pixels);
	return retval;
}

static void do_cdi_imag_IDAT(deark *c, struct cdi_imag_ctx *d, struct de_iffctx *ictx)
{
	de_bitmap *img = NULL;
	int ret = 0;

	if(!d->found_IHDR) goto done;

	if((d->model==6 && d->depth==4) ||
		(d->model==8 && d->depth==8))
	{
		;
	}
	else {
		de_err(c, "Unsupported image type: model=%u, depth=%u", d->model, d->depth);
		goto done;
	}

	if(!de_good_image_dimensions(c, d->npwidth, d->h)) goto done;

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->h, 3);

	if(d->model==6) {
		de_convert_image_paletted(ictx->f, ictx->chunkctx->dpos, (i64)d->depth,
			d->rowspan, d->pal, img, 0);
		ret = 1;
	}
	else if(d->model==8) {
		ret = do_cdi_imag_model8(c, d, ictx, img);
	}

	if(ret) {
		de_bitmap_write_to_file(img, NULL, 0);
	}

done:
	de_bitmap_destroy(img);
}

static int my_cdi_imag_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct cdi_imag_ctx *d = (struct cdi_imag_ctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		ictx->is_std_container = 1;
		break;
	case CODE_IDAT:
		do_cdi_imag_IDAT(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_IHDR:
		do_cdi_imag_IHDR(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_PLTE:
		do_cdi_imag_PLTE(c, d, ictx);
		ictx->handled = 1;
		break;
	}

	return 1;
}

static void de_run_cdi_imag(deark *c, de_module_params *mparams)
{
	struct cdi_imag_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(struct cdi_imag_ctx));
	ictx = fmtutil_create_iff_decoder(c);
	ictx->userdata = (void*)d;
	ictx->has_standard_iff_chunks = 1;
	ictx->handle_chunk_fn = my_cdi_imag_chunk_handler;
	ictx->f = c->infile;
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	fmtutil_destroy_iff_decoder(ictx);
	de_free(c, d);
}

static int de_identify_cdi_imag(deark *c)
{
	if((UI)de_getu32be(0)!=CODE_FORM) return 0;
	if(dbuf_memcmp(c->infile, 8, (const void*)"IMAGIHDR", 8)) return 0;
	return 100;
}

void de_module_cdi_imag(deark *c, struct deark_module_info *mi)
{
	mi->id = "cdi_imag";
	mi->desc = "CD-I IFF IMAG";
	mi->run_fn = de_run_cdi_imag;
	mi->identify_fn = de_identify_cdi_imag;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
