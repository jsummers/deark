// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// ADEX .img/.rle

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_adex);

// We follow Image Alchemy's implementation of ADEX, which is different from
// XnView's.
// (I wouldn't want to bet that either of them get it exactly right.)

struct adexctx {
	u8 cmpr_meth;
	u8 bpp; // bits per pixel
	i64 npwidth, pdwidth, h;
	i64 rowspan;
	i64 expected_imgsize; // uncompressed size in bytes
	i64 palentries;
	de_color pal[256];
};

// TODO: Make de_convert_image_paletted() support this.
static void convert_image_pal4_lsb(dbuf *f, i64 fpos,
	i64 rowspan, const de_color *pal, de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<img->height; j++) {
		for(i=0; i<rowspan; i++) {
			UI palent;
			u8 x;

			x = dbuf_getbyte(f, fpos+rowspan*j+i);
			palent = x & 0x0f;
			de_bitmap_setpixel_rgba(img, i*2, j, pal[palent]);
			palent = x >> 4;
			de_bitmap_setpixel_rgba(img, i*2+1, j, pal[palent]);
		}
	}
}

// I'm not sure how well I understand RLE format. It has a lot of extra "space"
// for more features to exist.
// So we go to some effort to fail if something unexpected happens -- otherwise
// this code could be much shorter.
// The format as I know it is very simple:
//   Treat the format as byte-oriented (it decompressed to bytes, not pixels).
//   Read 4 bytes at a time.
//    First two bytes are a repeat-count.
//    Last two bytes are the bytes to repeat.
//   Note: Each row ends with an item with repeat-count=0.
static int adex_decompress_rle(deark *c, struct adexctx *d, i64 pos1, dbuf *outf)
{
	i64 nbytes_written = 0;
	int retval = 0;
	i64 pos = pos1;
	i64 nbytes_this_row = 0;

	while(1) {
		i64 count;
		i64 k;
		u8 buf[2];

		if(nbytes_written >= d->expected_imgsize) break;
		if(pos > c->infile->len) {
			goto done;
		}
		if(nbytes_this_row > d->rowspan) {
			goto done;
		}

		count = de_getu16le_p(&pos);
		de_read(buf, pos, 2);
		pos += 2;

		if(count==0) { // end-of-row marker
			if(nbytes_this_row != d->rowspan) {
				goto done;
			}
			nbytes_this_row = 0;
		}
		else {
			for(k=0; k<count; k++) {
				dbuf_write(outf, buf, 2);
			}
			nbytes_written += 2*count;
			nbytes_this_row += 2*count;
		}
	}
	retval = 1;

done:
	if(!retval) {
		de_err(c, "RLE decompression failed");
	}
	return retval;
}

static void de_run_adex(deark *c, de_module_params *mparams)
{
	struct adexctx *d = NULL;
	i64 pos;
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	int need_errmsg = 0;

	d = de_malloc(c, sizeof(struct adexctx));
	pos = 4;
	d->cmpr_meth = de_getbyte_p(&pos);
	de_dbg(c, "cmpr meth: %u", (UI)d->cmpr_meth);
	d->bpp = de_getbyte_p(&pos);
	de_dbg(c, "bits/pixel: %u", (UI)d->bpp);
	d->npwidth = de_getu16le_p(&pos);
	d->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->npwidth, d->h);
	d->palentries = de_getu16le_p(&pos);
	de_dbg(c, "palette entries: %u", (UI)d->palentries);

	if(d->palentries>256) { need_errmsg = 1; goto done; }
	if(d->palentries==0) {
		// This is likely legal, but we'd have to get the palette from a different file
		need_errmsg = 1;
		goto done;
	}
	de_read_simple_palette(c, c->infile, pos, d->palentries, 3, d->pal, 256,
		DE_RDPALTYPE_24BIT, 0);
	pos += 3*d->palentries;
	pos += 2; // After the palette are two bytes of unknown purpose.

	de_dbg(c, "image data at %"I64_FMT, pos);

	if(d->cmpr_meth>1) { need_errmsg = 1; goto done; }
	if(d->bpp!=4 && d->bpp!=8) { need_errmsg = 1; goto done; }
	if(!de_good_image_dimensions(c, d->npwidth, d->h)) goto done;

	d->rowspan = de_pad_to_n(d->npwidth*d->bpp, 16)/8;
	d->pdwidth = (d->rowspan*d->bpp)/2;
	d->expected_imgsize = d->h * d->rowspan;

	if(d->cmpr_meth==1) {
		unc_pixels = dbuf_create_membuf(c, d->expected_imgsize, 0x1);
		dbuf_enable_wbuffer(unc_pixels);
		if(!adex_decompress_rle(c, d, pos, unc_pixels)) goto done;
		dbuf_flush(unc_pixels);
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, c->infile->len - pos);
	}

	img = de_bitmap_create2(c, d->npwidth, d->pdwidth, d->h, 3);
	if(d->bpp==4) {
		convert_image_pal4_lsb(unc_pixels, 0, d->rowspan, d->pal, img);
	}
	else {
		de_convert_image_paletted(unc_pixels, 0, d->bpp, d->rowspan, d->pal, img, 0);
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);
done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	if(need_errmsg) {
		de_err(c, "Bad or unsupported image type");
	}
	de_free(c, d);
}

static int de_identify_adex(deark *c)
{
	u8 b;

	if((u32)de_getu32be(0)!=0x50494354U) return 0; // "PICT"
	b = de_getbyte(4);
	if(b!=0 && b!=1) return 0;
	b = de_getbyte(5);
	if(b!=4 && b!=8) return 0;
	return 65;
}

void de_module_adex(deark *c, struct deark_module_info *mi)
{
	mi->id = "adex";
	mi->desc = "ADEX IMG/RLE";
	mi->run_fn = de_run_adex;
	mi->identify_fn = de_identify_adex;
}
