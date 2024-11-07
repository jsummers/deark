// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// XWD - X-Windows screen dump

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_xwd);

typedef struct localctx_struct_xwd {
	u8 errflag;
	u8 need_errmsg;
#define HF_HSIZE                0
#define HF_VER                  1
#define HF_PIXFMT               2
#define HF_DEPTH                3
#define HF_WIDTH                4
#define HF_HEIGHT               5
#define HF_BYTE_ORDER           7
#define HF_BITMAP_UNIT          8
#define HF_BIT_ORDER            9
#define HF_SCANLINE_PAD         10
#define HF_BITS_PER_PIX         11
#define HF_BYTES_PER_LINE       12
#define HF_VCLASS               13
#define HF_RMASK                14
#define HF_GMASK                15
#define HF_BMASK                16
#define HF_BITS_PER_RGB         17
#define HF_CMAP_NUM_ENTRIES     18
#define HF_NCOLORS              19
	UI hf[25];

	UI vclass_adj;
	i64 cmap_pos;
	i64 cmap_num_entries;
	i64 cmap_size_in_bytes;
	i64 imgpos;
	i64 expected_image_size;
	i64 actual_image_size;
	int pixel_byte_order; // 1 if LE
	i64 bytes_per_pixel; // Not used by every image type
	i64 bits_per_pixel; // Not used by every image type
	i64 width, height;
	i64 rowspan;
	UI cmpr_meth;

#define XWD_IMGTYPE_GRAY      1
#define XWD_IMGTYPE_PALETTE   2
#define XWD_IMGTYPE_RGB       3
	int imgtype;

	UI sample_bit_shift[3];
	i64 sample_maxval[3];
	de_color pal[256];
} lctx;

static void read_or_construct_colormap(deark *c, lctx *d)
{
	UI k;
	UI num_entries_to_read;
	int saved_indent_level;
	i64 pos;

	de_dbg_indent_save(c, &saved_indent_level);
	if((d->imgtype==XWD_IMGTYPE_PALETTE || d->imgtype==XWD_IMGTYPE_GRAY) &&
		(d->bits_per_pixel>=1 && d->bits_per_pixel<=8))
	{
		de_make_grayscale_palette(d->pal, 1ULL<<d->bits_per_pixel, 0);
	}

	if(d->cmap_size_in_bytes<1) goto done;

	de_dbg(c, "colormap at %"I64_FMT, d->cmap_pos);
	de_dbg_indent(c, 1);

	num_entries_to_read = d->hf[HF_CMAP_NUM_ENTRIES];
	if(num_entries_to_read>256) num_entries_to_read = 256;

	pos = d->cmap_pos;
	for(k=0; k<num_entries_to_read; k++) {
		UI s;
		u8 samp[3];

		pos += 4;
		for(s=0; s<3; s++) {
			samp[s] = de_getbyte_p(&pos);
			pos++;
		}
		d->pal[k] = DE_MAKE_RGB(samp[0], samp[1], samp[2]);
		de_dbg_pal_entry(c, (i64)k, d->pal[k]);
		pos += 2;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static const char *hnames[25] = {
	"hsize", "ver", "pix fmt", "depth", "width",
	"height", "xoffs", "byte order", "bitmap unit", "bitmap bit order",
	"scanline pad", "bits/pixel", "bytes/line", "visual class", "R mask",
	"G mask", "B mask", "bits/rgb", "cmap num entries", "ncolors",
	"window width", "window height", "window x", "window y", "window bdrwidth" };

static const char *get_pixfmt_name(UI x)
{
	const char *name = NULL;

	switch(x) {
	case 0: name = "1-bit"; break;
	case 1: name = "1-plane"; break;
	case 2: name = "multi-plane"; break;
	}
	return name?name:"?";
}

static const char *get_vclass_name(UI x)
{
	const char *name = NULL;

	switch(x) {
	case 0: name = "grayscale"; break;
	case 2: name = "colormapped"; break;
	case 4: name = "truecolor"; break;
	}
	return name?name:"?";
}

static void interpret_header(deark *c, lctx *d)
{
	u8 need_fixup_warning = 0;
	u8 depth_1248;
	UI k;

	d->cmap_pos = (i64)d->hf[HF_HSIZE];
	d->width = (i64)d->hf[HF_WIDTH];
	d->height = (i64)d->hf[HF_HEIGHT];
	d->pixel_byte_order = !d->hf[HF_BYTE_ORDER];
	d->rowspan = (i64)d->hf[HF_BYTES_PER_LINE];
	d->expected_image_size = d->height * d->rowspan;

	depth_1248 = (d->hf[HF_DEPTH]==8 || d->hf[HF_DEPTH]==4 ||
		d->hf[HF_DEPTH]==2 || d->hf[HF_DEPTH]==1);

	// paletted or grayscale, typical
	if((d->vclass_adj==0 || d->vclass_adj==2) &&
		depth_1248 &&
		d->hf[HF_BITS_PER_PIX]==d->hf[HF_DEPTH])
	{
		d->imgtype = (d->vclass_adj==0) ? XWD_IMGTYPE_GRAY : XWD_IMGTYPE_PALETTE;
		d->bits_per_pixel = (i64)d->hf[HF_DEPTH];
	}

	// paletted or grayscale, with unused bits
	if(d->imgtype==0 && (d->vclass_adj==0 || d->vclass_adj==2) &&
		depth_1248 &&
		d->hf[HF_BITS_PER_PIX]!=d->hf[HF_DEPTH] &&
		d->hf[HF_BITS_PER_PIX]==8)
	{
		d->imgtype = (d->vclass_adj==0) ? XWD_IMGTYPE_GRAY : XWD_IMGTYPE_PALETTE;
		d->bits_per_pixel = (i64)d->hf[HF_BITS_PER_PIX];
	}

	// RGB 32bits/pixel
	if(d->imgtype==0 && d->vclass_adj==4 &&
		d->hf[HF_BITMAP_UNIT]==32 &&
		(d->hf[HF_BITS_PER_PIX]==24 || d->hf[HF_BITS_PER_PIX]==32) &&
		(d->hf[HF_DEPTH]==24 || d->hf[HF_DEPTH]==32))
	{
		d->imgtype = XWD_IMGTYPE_RGB;
		d->bytes_per_pixel = 4;
	}

	// RGB 16bits/pixel
	if(d->imgtype==0 && d->vclass_adj==4 &&
		(d->hf[HF_BITMAP_UNIT]==16 || d->hf[HF_BITMAP_UNIT]==32) &&
		d->hf[HF_BITS_PER_PIX]==16 &&
		d->hf[HF_DEPTH]==16)
	{
		d->imgtype = XWD_IMGTYPE_RGB;
		d->bytes_per_pixel = 2;
	}

	// e.g. "MARBLES.XWD"
	if(d->imgtype==0 && d->vclass_adj==4 &&
		d->hf[HF_PIXFMT]==2 &&
		d->hf[HF_DEPTH]==24 &&
		d->hf[HF_BYTE_ORDER]==1 &&
		d->hf[HF_BITMAP_UNIT]==8 &&
		d->hf[HF_SCANLINE_PAD]==8 &&
		d->hf[HF_BITS_PER_PIX]==24)
	{
		d->bytes_per_pixel = 4;
		d->imgtype = XWD_IMGTYPE_RGB;
		need_fixup_warning = 1;
	}

	// If RGB image looks to be defined with 4 bytes stored per pixel, but
	// a scanline is too small for 4, something's wrong.
	// The XWD spec doesn't explain how 24-bit RGB images should be
	// labeled. But they exist.
	// E.g. BlueSteel.zip/screenshot.xwd
	if(d->imgtype==XWD_IMGTYPE_RGB && d->bytes_per_pixel==4 &&
		d->width*d->bytes_per_pixel > d->rowspan &&
		d->width*3 <= d->rowspan)
	{
		d->bytes_per_pixel = 3;
		need_fixup_warning = 1;
	}

	// Decode masks if needed
	if(d->imgtype==XWD_IMGTYPE_RGB) {
		for(k=0; k<3; k++) {
			UI x;

			x = d->hf[HF_RMASK+k];
			d->sample_maxval[k] = 255; // default

			// TODO: Generalize this code
			if(x == 0x000000ffU) {
				d->sample_bit_shift[k] = 0;
			}
			else if(x == 0x0000ff00U) {
				d->sample_bit_shift[k] = 8;
			}
			else if(x == 0x00ff0000U) {
				d->sample_bit_shift[k] = 16;
			}
			else if(x == 0xff000000U) {
				d->sample_bit_shift[k] = 24;
			}
			else if(x == 0xf800) {
				d->sample_bit_shift[k] = 11;
				d->sample_maxval[k] = 31;
			}
			else if(x == 0x07e0) {
				d->sample_bit_shift[k] = 5;
				d->sample_maxval[k] = 63;
			}
			else if(x == 0x001f) {
				d->sample_bit_shift[k] = 0;
				d->sample_maxval[k] = 31;
			}
			else {
				d->errflag = 1;
				d->need_errmsg = 1;
			}
		}
	}

	if(need_fixup_warning) {
		de_warn(c, "Inconsistent or unusual image parameters. Attempting to correct.");
	}
}

// Try to figure out the colormap size, and consequently the image position.
static void find_cmap_and_image(deark *c, lctx *d)
{
	u8 need_cmap_warning = 0;
	i64 size1, size2;
	i64 avail_size;

	d->cmap_num_entries = (i64)d->hf[HF_CMAP_NUM_ENTRIES];
	d->cmap_size_in_bytes = d->cmap_num_entries * 12;

	// It's critical that we know exactly how many entries are in the colormap.
	// Sometimes its in one field, sometimes in another, and it's not clear
	// how to tell which.

	// We hope these two fields are the same.
	if(d->hf[HF_CMAP_NUM_ENTRIES] == d->hf[HF_NCOLORS]) goto done;

	if(d->hf[HF_NCOLORS] > d->hf[HF_CMAP_NUM_ENTRIES]) {
		// I haven't seen this happen.
		goto done;
	}

	// d->hf[HF_NCOLORS] < d->hf[HF_CMAP_NUM_ENTRIES]

	size1 = d->hf[HF_NCOLORS] * 12; // Note, size1 is smaller than size2
	size2 = d->hf[HF_CMAP_NUM_ENTRIES] * 12;
	avail_size = c->infile->len - d->expected_image_size - d->cmap_pos;

	if(size2==avail_size) {
		goto done;
	}
	if(size1==avail_size) {
		d->cmap_num_entries = (i64)d->hf[HF_NCOLORS];
		goto done;
	}
	if(size2>avail_size && size1<avail_size) {
		d->cmap_num_entries = (i64)d->hf[HF_NCOLORS];
		need_cmap_warning = 1;
		goto done;
	}

	need_cmap_warning = 1;

done:
	if(need_cmap_warning) {
		de_warn(c, "Can't reliably locate the image. Might not be decoded correctly.");
	}
	d->cmap_size_in_bytes = d->cmap_num_entries * 12;
	d->imgpos = d->cmap_pos + d->cmap_size_in_bytes;
	d->actual_image_size = c->infile->len - d->imgpos;
}

static void do_header(deark *c, lctx *d)
{
	i64 pos;
	int saved_indent_level;
	UI k;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = 0;
	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	for(k=0; k<25; k++) {
		const char *name = NULL;

		d->hf[k] = (UI)de_getu32be_p(&pos);

		if(k==HF_PIXFMT) {
			name = get_pixfmt_name(d->hf[k]);
		}
		else if(k==HF_BYTE_ORDER) {
			if(d->hf[k]==0) name = "LE";
			else name = "BE";
		}
		else if(k==HF_BIT_ORDER) {
			if(d->hf[k]==0) name = "lsb first";
			else name = "msb first";
		}
		else if(k==HF_VCLASS) {
			d->vclass_adj = d->hf[k] & 0xfffffffeU;
			name = get_vclass_name(d->vclass_adj);
		}

		if(k>=HF_RMASK && k<=HF_BMASK) {
			de_dbg(c, "%s: 0x%08x", hnames[k], d->hf[k]);
		}
		else {
			if(name) {
				de_dbg(c, "%s: %u (%s)", hnames[k], d->hf[k], name);
			}
			else {
				de_dbg(c, "%s: %u", hnames[k], d->hf[k]);
			}
		}
	}

	if(d->hf[HF_HSIZE]<100) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->hf[HF_VER]!=7) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->hf[HF_WIDTH]>1000000 || d->hf[HF_HEIGHT]>1000000 ||
		d->hf[HF_BYTES_PER_LINE]>1000000)
	{
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	interpret_header(c, d);
	if(d->errflag) goto done;
	find_cmap_and_image(c, d);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void read_image_rgb(deark *c, lctx *d, dbuf *inf, i64 inf_pos1,
	de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<d->height; j++) {
		i64 rowpos;

		rowpos = inf_pos1 + j*d->rowspan;

		for(i=0; i<d->width; i++) {
			de_color clr = 0;
			u32 v;
			u32 cs[3];
			UI k;

			if(d->bytes_per_pixel==4) {
				v = (u32)dbuf_getu32x(inf, rowpos+i*d->bytes_per_pixel, d->pixel_byte_order);
			}
			else {
				v = (u32)dbuf_getint_ext(inf, rowpos+i*d->bytes_per_pixel,
					(UI)d->bytes_per_pixel, d->pixel_byte_order, 0);
			}
			for(k=0; k<3; k++) {
				UI v2;

				v2 = v & d->hf[HF_RMASK+k];
				v2 = v2 >> d->sample_bit_shift[k];

				if(d->sample_maxval[k]==255) {
					cs[k] = (u8)v2;
				}
				else {
					cs[k] = de_scale_n_to_255(d->sample_maxval[k], v2);
				}
			}
			clr = DE_MAKE_RGB(cs[0], cs[1], cs[2]);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void read_image_colormapped(deark *c, lctx *d, dbuf *inf, i64 inf_pos,
	de_bitmap *img)
{
	UI flags = 0;

	if(d->bits_per_pixel<1 || d->bits_per_pixel>8) return;

	if(d->hf[HF_BIT_ORDER]==0) {
		flags |= 0x01;
	}

	de_convert_image_paletted(inf, inf_pos, d->bits_per_pixel,
		d->rowspan, d->pal, img, flags);
}

static void read_image_grayscale(deark *c, lctx *d,  dbuf *inf, i64 inf_pos,
	de_bitmap *img)
{
	read_image_colormapped(c, d, inf, inf_pos, img);
}

static void decompress_pvwave_rle(deark *c, lctx *d, dbuf *unc_pixels)
{
	i64 pos = d->imgpos;
	i64 endpos = c->infile->len;
	i64 row_padding;
	i64 nbytes_written = 0;
	i64 xpos = 0;

	row_padding = d->rowspan - d->width;
	if(row_padding<0) goto done;

	while(1) {
		i64 count;
		u8 b;

		if(pos+3 > endpos) goto done;
		if(nbytes_written >= d->expected_image_size) goto done;

		count = de_getu16be_p(&pos);
		b = de_getbyte_p(&pos);
		dbuf_write_run(unc_pixels, b, count);
		nbytes_written += count;
		xpos += count;

		if(xpos >= d->width) {
			if(row_padding!=0 && xpos==d->width) {
				// It's stupid that we have to do this.
				dbuf_write_run(unc_pixels, 0x00, row_padding);
				nbytes_written += row_padding;
			}
			xpos = 0;
		}
	}
done:
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
		pos-d->imgpos, nbytes_written);
	dbuf_flush(unc_pixels);
}

static void detect_compression(deark *c, lctx *d)
{
	i64 count;

	if(d->actual_image_size == d->expected_image_size) goto done;
	if(d->actual_image_size%3 != 0) goto done;

	if(d->hf[HF_PIXFMT]==2 &&
		d->hf[HF_DEPTH]==8 &&
		d->hf[HF_BYTE_ORDER]==0 &&
		d->hf[HF_BITMAP_UNIT]==32 &&
		d->hf[HF_BIT_ORDER]==0 &&
		d->hf[HF_SCANLINE_PAD]==32 &&
		d->hf[HF_BITS_PER_PIX]==8 &&
		d->hf[HF_VCLASS]==3 &&
		d->hf[HF_BITS_PER_RGB]==8)
	{
		;
	}
	else {
		goto done;
	}

	// TODO: We could do better by checking more than just the first
	// compression code.
	count = de_getu16be(d->imgpos);
	if(count<1 || count>d->width) {
		goto done;
	}

	d->cmpr_meth = 100;
done:
	if(d->cmpr_meth==100) {
		de_dbg(c, "detected PV-Wave RLE compression");
	}
}

static void do_xwd_image(deark *c, lctx *d)
{
	int bypp;
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	dbuf *inf = c->infile; // This is a copy -- do not close
	i64 inf_pos = d->imgpos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "image at %"I64_FMT, d->imgpos);
	de_dbg_indent(c, 1);
	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	detect_compression(c, d);

	if(d->cmpr_meth!=0) {
		unc_pixels = dbuf_create_membuf(c, d->expected_image_size, 0x1);
		dbuf_enable_wbuffer(unc_pixels);
		decompress_pvwave_rle(c, d, unc_pixels);
		inf = unc_pixels;
		inf_pos = 0;
	}

	if(d->cmpr_meth==0) {
		if(d->imgpos + d->expected_image_size > c->infile->len+16) {
			de_err(c, "Bad or truncated XWD file");
			d->errflag = 1;
			goto done;
		}
	}

	if(d->imgtype==XWD_IMGTYPE_RGB &&
		(d->bytes_per_pixel==2 || d->bytes_per_pixel==3 || d->bytes_per_pixel==4))
	{
		;
	}
	else if(d->imgtype==XWD_IMGTYPE_PALETTE &&
		d->bits_per_pixel>0)
	{
		;
	}
	else if(d->imgtype==XWD_IMGTYPE_GRAY &&
		d->bits_per_pixel>0)
	{
		;
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	bypp = 3;
	if(d->imgtype==XWD_IMGTYPE_GRAY || d->imgtype==XWD_IMGTYPE_PALETTE) {
		if(de_is_grayscale_palette(d->pal, 256)) {
			bypp = 1;
		}
	}
	img = de_bitmap_create(c, d->width, d->height, bypp);

	if(d->imgtype==XWD_IMGTYPE_RGB) {
		read_image_rgb(c, d, inf, inf_pos, img);
	}
	else if(d->imgtype==XWD_IMGTYPE_PALETTE) {
		read_image_colormapped(c, d, inf, inf_pos, img);
	}
	else if(d->imgtype==XWD_IMGTYPE_GRAY) {
		read_image_grayscale(c, d, inf, inf_pos, img);
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	if(d->need_errmsg) {
		de_err(c, "Unsupported image type");
		d->need_errmsg = 0;
	}
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_xwd(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	do_header(c, d);
	if(d->errflag) goto done;
	// TODO?: Do something with the name that may appear after the header.

	read_or_construct_colormap(c, d);

	do_xwd_image(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported XWD file");
		}
		de_free(c, d);
	}
}

static int de_identify_xwd(deark *c)
{
	int has_ext = 0;
	i64 hdrsize;
	i64 cmapn;
	UI n;

	// TODO: Identification could be improved.

	n = (UI)de_getu32be(4); // version
	if (n!=7) return 0;

	hdrsize = (UI)de_getu32be(0);
	if(hdrsize<100 || hdrsize>500) return 0;

	n = (UI)de_getu32be(8); // pixfmt
	if(n>2) return 0;

	n = (UI)de_getu32be(12); // depth
	if(n<1 || n>32) return 0;

	cmapn = de_getu32be(76);
	if(cmapn>512) return 0;
	if(hdrsize + 12*cmapn > c->infile->len) return 0;

	has_ext = de_input_file_has_ext(c, "xwd");
	if(has_ext) return 100;
	return 75;
}

void de_module_xwd(deark *c, struct deark_module_info *mi)
{
	mi->id = "xwd";
	mi->desc = "X-Windows screen dump";
	mi->run_fn = de_run_xwd;
	mi->identify_fn = de_identify_xwd;
}
