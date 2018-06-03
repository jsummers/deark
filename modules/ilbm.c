// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Decode IFF/ILBM and related image formats

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_ilbm);
DE_DECLARE_MODULE(de_module_anim);

#define CODE_ABIT  0x41424954
#define CODE_ANHD  0x414e4844U
#define CODE_BMHD  0x424d4844
#define CODE_BODY  0x424f4459
#define CODE_CAMG  0x43414d47
#define CODE_CCRT  0x43435254U
#define CODE_CLUT  0x434c5554U
#define CODE_CMAP  0x434d4150
#define CODE_CRNG  0x43524e47
#define CODE_CTBL  0x4354424c
#define CODE_DPI   0x44504920
#define CODE_DRNG  0x44524e47U
#define CODE_FORM  0x464f524d
#define CODE_GRAB  0x47524142
#define CODE_PCHG  0x50434847
#define CODE_SHAM  0x5348414d
#define CODE_TINY  0x54494e59
#define CODE_VDAT  0x56444154

#define CODE_ILBM  0x494c424d
#define CODE_PBM   0x50424d20
#define CODE_ACBM  0x4143424d

struct img_info {
	de_int64 width, height;
	de_int64 planes_total;
	de_int64 rowspan;
	de_int64 planespan;
	de_int64 bits_per_row_per_plane;
	de_byte masking_code;
	const char *filename_token;
};

typedef struct localctx_struct {
	de_uint32 formtype; // TODO: Maybe use ictx->main_contentstype instead.

	// This struct is for image attributes that might be different in
	// thumbnail images vs. the main image.
	struct img_info main_img;

	de_int64 planes;
	de_byte found_bmhd;
	de_byte found_cmap;
	de_byte compression;
	de_byte has_camg;
	de_byte ham_flag; // "hold and modify"
	de_byte ehb_flag; // "extra halfbrite"
	de_byte is_ham6;
	de_byte is_ham8;
	de_byte in_vdat_image;
	de_byte is_vdat;
	de_byte is_sham, is_pchg, is_ctbl;
	de_byte uses_color_cycling;
	de_byte errflag; // Set if image(s) format is not supported.
	de_int64 transparent_color;

	de_int64 x_aspect, y_aspect;
	de_int64 x_dpi, y_dpi;
	de_int32 camg_mode;

	int opt_notrans;
	int opt_fixpal;

	dbuf *vdat_unc_pixels;

	// TODO: This hashtable should probably be used more than it is.
	struct de_inthashtable *chunks_seen;

	// Our palette always has 256 colors. This is how many we read from the file.
	de_int64 pal_ncolors;

	de_uint32 pal[256];
} lctx;

static int do_bmhd(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	int retval = 0;
	const char *masking_name;

	if(len<20) {
		de_err(c, "Bad BMHD chunk");
		goto done;
	}

	d->found_bmhd = 1;
	d->main_img.width = de_getui16be(pos1);
	d->main_img.height = de_getui16be(pos1+2);
	de_dbg_dimensions(c, d->main_img.width, d->main_img.height);
	d->planes = (de_int64)de_getbyte(pos1+8);
	de_dbg(c, "planes: %d", (int)d->planes);
	d->main_img.masking_code = de_getbyte(pos1+9);
	switch(d->main_img.masking_code) {
	case 0: masking_name = "no transparency"; break;
	case 1: masking_name = "1-bit transparency mask"; break;
	case 2: masking_name = "color-key transparency"; break;
	case 3: masking_name = "lasso"; break;
	default: masking_name = "unknown"; break;
	}

	d->compression = de_getbyte(pos1+10);
	de_dbg(c, "compression: %d", (int)d->compression);

	d->transparent_color = de_getui16be(pos1+12);
	de_dbg(c, "masking: %d (%s)", (int)d->main_img.masking_code, masking_name);
	if(d->main_img.masking_code==2 || d->main_img.masking_code==3) {
		de_dbg(c, " color key: %d", (int)d->transparent_color);
	}

	d->x_aspect = (de_int64)de_getbyte(pos1+14);
	d->y_aspect = (de_int64)de_getbyte(pos1+15);
	de_dbg(c, "apect ratio: %d, %d", (int)d->x_aspect, (int)d->y_aspect);

	retval = 1;
done:
	return retval;
}

static void do_cmap(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	d->found_cmap = 1;
	d->pal_ncolors = len/3;
	de_dbg(c, "number of palette colors: %d", (int)d->pal_ncolors);
	if(d->pal_ncolors>256) d->pal_ncolors=256;

	de_read_palette_rgb(c->infile, pos, d->pal_ncolors, 3, d->pal, 256, 0);
}

static void do_camg(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	if(len<4) return;
	d->has_camg = 1;

	d->camg_mode = (de_uint32)de_getui32be(pos);
	de_dbg(c, "CAMG mode: 0x%x", (unsigned int)d->camg_mode);

	if(d->camg_mode & 0x0800)
		d->ham_flag = 1;
	if(d->camg_mode & 0x0080)
		d->ehb_flag = 1;

	de_dbg_indent(c, 1);
	de_dbg(c, "HAM: %d, EHB: %d", (int)d->ham_flag, (int)d->ehb_flag);
	de_dbg_indent(c, -1);
}

static void do_dpi(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	if(len<4) return;
	d->x_dpi = de_getui16be(pos);
	d->y_dpi = de_getui16be(pos+2);
	de_dbg(c, "dpi: %d"DE_CHAR_TIMES"%d", (int)d->x_dpi, (int)d->y_dpi);
}

static de_byte getbit(const de_byte *m, de_int64 bitnum)
{
	de_byte b;
	b = m[bitnum/8];
	b = (b>>(7-bitnum%8)) & 0x1;
	return b;
}

static void do_deplanarize(deark *c, lctx *d, struct img_info *ii,
	const de_byte *row_orig, de_byte *row_deplanarized)
{
	de_int64 i;
	de_int64 sample;
	de_int64 bit;
	de_byte b;

	if(d->planes>=1 && d->planes<=8) {
		de_memset(row_deplanarized, 0, (size_t)ii->width);
		for(i=0; i<ii->width; i++) {
			for(bit=0; bit<d->planes; bit++) {
				b = getbit(row_orig, bit*ii->bits_per_row_per_plane +i);
				if(b) row_deplanarized[i] |= (1<<bit);
			}
		}
	}
	else if(d->planes==24) {
		de_memset(row_deplanarized, 0, (size_t)(ii->width*3));
		for(i=0; i<ii->width; i++) {
			for(sample=0; sample<3; sample++) {
				for(bit=0; bit<8; bit++) {
					b = getbit(row_orig, (sample*8+bit)*ii->bits_per_row_per_plane + i);
					if(b) row_deplanarized[i*3 + sample] |= (1<<bit);
				}
			}
		}
	}
}

static void get_row_acbm(deark *c, lctx *d, struct img_info *ii,
	dbuf *unc_pixels, de_int64 j, de_byte *row)
{
	de_int64 i;
	de_int64 bit;
	de_byte b;

	de_memset(row, 0, (size_t)ii->width);
	for(i=0; i<ii->width; i++) {
		for(bit=0; bit<d->planes; bit++) {
			b = de_get_bits_symbol(unc_pixels, 1, bit*ii->planespan + j*ii->rowspan, i);
			if(b) row[i] |= (1<<bit);
		}
	}
}

static void get_row_vdat(deark *c, lctx *d, struct img_info *ii,
	dbuf *unc_pixels, de_int64 j, de_byte *row)
{
	de_int64 i;
	de_int64 set;
	de_int64 bytes_per_column;
	de_int64 bytes_per_set;
	de_int64 columns_per_set;
	de_byte b;

	de_memset(row, 0, (size_t)ii->width);

	bytes_per_column = 2*ii->height;
	columns_per_set = ((ii->width + 15)/16);
	bytes_per_set = bytes_per_column * columns_per_set;

	for(i=0; i<ii->width; i++) {
		for(set=0; set<4; set++) {
			b = de_get_bits_symbol(unc_pixels, 1,
				set*bytes_per_set + (i/16)*bytes_per_column + j*2,
				i%16);
			if(b) row[i] |= (1<<set);
		}
	}
}

static void set_density(deark *c, lctx *d, de_bitmap *img)
{
	int has_aspect, has_dpi;

	has_aspect = (d->x_aspect>0 && d->y_aspect>0);
	has_dpi = (d->x_dpi>0 && d->y_dpi>0);

	// TODO: Warn about inconsistent aspect ratio vs. DPI?

	if(has_dpi) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = (double)d->x_dpi;
		img->ydens = (double)d->y_dpi;
	}
	else if(has_aspect) {
		img->density_code = DE_DENSITY_UNK_UNITS;
		img->ydens = (double)d->x_aspect;
		img->xdens = (double)d->y_aspect;
	}
}

static void do_image_24(deark *c, lctx *d, struct img_info *ii,
	dbuf *unc_pixels, unsigned int createflags)
{
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte cr, cg, cb;

	if(d->formtype!=CODE_ILBM) {
		de_err(c, "This image type is not supported");
		goto done;
	}

	ii->bits_per_row_per_plane = ((ii->width+15)/16)*16;
	ii->rowspan = (ii->bits_per_row_per_plane/8) * d->planes;
	row_orig = de_malloc(c, ii->rowspan);
	row_deplanarized = de_malloc(c, ii->width * 3);

	img = de_bitmap_create(c, ii->width, ii->height, 3);
	set_density(c, d, img);

	for(j=0; j<ii->height; j++) {
		dbuf_read(unc_pixels, row_orig, j*ii->rowspan, ii->rowspan);
		do_deplanarize(c, d, ii, row_orig, row_deplanarized);

		for(i=0; i<ii->width; i++) {
			cr = row_deplanarized[i*3];
			cg = row_deplanarized[i*3+1];
			cb = row_deplanarized[i*3+2];
			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(cr,cg,cb));
		}
	}

	de_bitmap_write_to_file(img, ii->filename_token, createflags);
done:
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
}

static void make_ehb_palette(deark *c, lctx *d)
{
	de_int64 k;
	de_byte cr, cg, cb;

	for(k=0; k<32; k++) {
		cr = DE_COLOR_R(d->pal[k]);
		cg = DE_COLOR_G(d->pal[k]);
		cb = DE_COLOR_B(d->pal[k]);
		d->pal[k+32] = DE_MAKE_RGB(cr/2, cg/2, cb/2);
	}
}

// It's clear that some ILBM images have palette colors with only 4 bits of
// precision (the low bits often being set to 0), while others have 8, or
// something in between.
// What's not clear is how to tell them apart.
// We'll guess that
// * HAM6 images always have 4.
// * HAM8 images always have 6.
// * For anything else, assume 4 if the low 4 bits are all 0.
// * Otherwise, 8.
// TODO: It may be safe to assume that 8-plane images always have 8, but
// more research is needed.
static void fixup_palette(deark *c, lctx *d)
{
	de_int64 k;
	de_byte cr, cg, cb;

	if(d->is_ham8) {
		// Assume HAM8 palette entries have 6 bits of precision
		for(k=0; k<d->pal_ncolors; k++) {
			cr = DE_COLOR_R(d->pal[k]);
			cg = DE_COLOR_G(d->pal[k]);
			cb = DE_COLOR_B(d->pal[k]);
			cr = (cr&0xfc)|(cr>>6);
			cg = (cg&0xfc)|(cg>>6);
			cb = (cb&0xfc)|(cb>>6);
			d->pal[k] = DE_MAKE_RGB(cr, cg, cb);
		}
		return;
	}

	if(!d->is_ham6) {
		for(k=0; k<d->pal_ncolors; k++) {
			cr = DE_COLOR_R(d->pal[k]);
			cg = DE_COLOR_G(d->pal[k]);
			cb = DE_COLOR_B(d->pal[k]);
			if((cr&0x0f) != 0) return;
			if((cg&0x0f) != 0) return;
			if((cb&0x0f) != 0) return;
		}
		de_dbg(c, "Palette seems to have 4 bits of precision. Rescaling palette.");
	}

	for(k=0; k<d->pal_ncolors; k++) {
		cr = DE_COLOR_R(d->pal[k]);
		cg = DE_COLOR_G(d->pal[k]);
		cb = DE_COLOR_B(d->pal[k]);
		cr = 17*(cr>>4);
		cg = 17*(cg>>4);
		cb = 17*(cb>>4);
		d->pal[k] = DE_MAKE_RGB(cr, cg, cb);
	}
}

static int do_image_1to8(deark *c, lctx *d, struct img_info *ii,
	dbuf *unc_pixels, unsigned int createflags)
{
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte val;
	de_byte cr = 0;
	de_byte cg = 0;
	de_byte cb = 0;
	de_byte ca = 255;
	de_byte b;
	de_uint32 clr;
	int dst_bytes_per_pixel;
	int retval = 0;
	de_int64 bytes_expected = 0;
	int bytes_expected_valid = 0;

	if(!d->found_cmap) {
		de_err(c, "Missing CMAP chunk");
		goto done;
	}

	if(d->ham_flag) {
		if(d->planes==6 || d->planes==5) {
			d->is_ham6 = 1;
		}
		else if(d->planes==8 || d->planes==7) {
			d->is_ham8 = 1;
		}
		else {
			de_warn(c, "Invalid bit depth (%d) for HAM image.", (int)d->planes);
		}
	}

	if(d->opt_fixpal)
		fixup_palette(c, d);

	if(d->ehb_flag && d->planes==6 && d->pal_ncolors==32) {
		make_ehb_palette(c, d);
	}

	// If using color-keyed transparency, make one of the palette colors transparent.
	if(ii->masking_code==2 && !d->opt_notrans) {
		if(d->transparent_color<=255) {
			d->pal[(int)d->transparent_color] &= 0x00ffffffU;
		}
	}

	ii->planes_total = d->planes;
	if(ii->masking_code==1) {
		if(d->formtype!=CODE_ILBM) {
			de_err(c, "This type of image is not supported.");
			goto done;
		}
		ii->planes_total++;
	}

	ii->bits_per_row_per_plane = ((ii->width+15)/16)*16;
	if(d->in_vdat_image) {
		ii->rowspan = ii->bits_per_row_per_plane/8;
	}
	else if(d->formtype==CODE_ACBM) {
		ii->rowspan = ii->bits_per_row_per_plane/8;
		ii->planespan = ii->height * ii->rowspan;
	}
	else if(d->formtype==CODE_PBM) {
		ii->rowspan = ii->width;
		// I don't know what row padding logic PBM files use.
		// I've seen some that are padded to a 2-byte boundary, while the
		// thumbnail in the same file has no row padding.
		if((ii->rowspan%2) && (unc_pixels->len >= ((ii->rowspan+1)*ii->height))) {
			ii->rowspan++;
		}
	}
	else {
		ii->rowspan = (ii->bits_per_row_per_plane/8) * ii->planes_total;
	}

	row_orig = de_malloc(c, ii->rowspan);
	row_deplanarized = de_malloc(c, ii->width);

	if(!d->is_ham6 && !d->is_ham8 && de_is_grayscale_palette(d->pal, 256))
		dst_bytes_per_pixel = 1;
	else
		dst_bytes_per_pixel = 3;

	if((ii->masking_code==1 || ii->masking_code==2) && !d->opt_notrans)
		dst_bytes_per_pixel++;

	img = de_bitmap_create(c, ii->width, ii->height, dst_bytes_per_pixel);
	set_density(c, d, img);

	for(j=0; j<ii->height; j++) {
		if(d->is_ham6 || d->is_ham8) {
			// At the beginning of each row, the color accumulators are
			// initialized to palette entry 0.
			cr = DE_COLOR_R(d->pal[0]);
			cg = DE_COLOR_G(d->pal[0]);
			cb = DE_COLOR_B(d->pal[0]);
		}

		if(d->in_vdat_image) {
			get_row_vdat(c, d, ii, unc_pixels, j, row_deplanarized);
		}
		else if(d->formtype==CODE_ACBM) {
			get_row_acbm(c, d, ii, unc_pixels, j, row_deplanarized);
		}
		else if(d->formtype==CODE_PBM) {
			if(ii->rowspan < ii->width) {
				de_err(c, "Internal error");
				goto done;
			}
			dbuf_read(unc_pixels, row_deplanarized, j*ii->rowspan, ii->width);
			bytes_expected += ii->rowspan;
			bytes_expected_valid = 1;
		}
		else {
			dbuf_read(unc_pixels, row_orig, j*ii->rowspan, ii->rowspan);
			bytes_expected += ii->rowspan;
			bytes_expected_valid = 1;
			do_deplanarize(c, d, ii, row_orig, row_deplanarized);
		}

		for(i=0; i<ii->width; i++) {
			val = row_deplanarized[i];

			if(d->is_ham6) {
				switch((val>>4)&0x3) {
				case 0x1: // Modify blue value
					cb = 17*(val&0x0f);
					break;
				case 0x2: // Modify red value
					cr = 17*(val&0x0f);
					break;
				case 0x3: // Modify green value
					cg = 17*(val&0x0f);
					break;
				default: // 0: Use colormap value
					clr = d->pal[(unsigned int)val];
					cr = DE_COLOR_R(clr);
					cg = DE_COLOR_G(clr);
					cb = DE_COLOR_B(clr);
					break;
				}
			}
			else if(d->is_ham8) {
				switch((val>>6)&0x3) {
				case 0x1:
					cb = ((val&0x3f)<<2)|((val&0x3f)>>4);
					break;
				case 0x2:
					cr = ((val&0x3f)<<2)|((val&0x3f)>>4);
					break;
				case 0x3:
					cg = ((val&0x3f)<<2)|((val&0x3f)>>4);
					break;
				default:
					clr = d->pal[(unsigned int)val];
					cr = DE_COLOR_R(clr);
					cg = DE_COLOR_G(clr);
					cb = DE_COLOR_B(clr);
					break;
				}
			}
			else {
				clr = d->pal[(unsigned int)val];
				cr = DE_COLOR_R(clr);
				cg = DE_COLOR_G(clr);
				cb = DE_COLOR_B(clr);
				ca = DE_COLOR_A(clr);
			}

			if(ii->masking_code==1 && !d->opt_notrans) {
				// The last plane is the transparency mask.
				// (This code is for ILBM format only.)
				b = getbit(row_orig, (ii->planes_total-1)*ii->bits_per_row_per_plane +i);
				ca = b ? 0xff : 0x00;
			}

			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGBA(cr,cg,cb,ca));
		}
	}

	if(bytes_expected_valid && bytes_expected!=unc_pixels->len) {
		de_warn(c, "Expected %d uncompressed bytes, got %d", (int)bytes_expected,
			(int)unc_pixels->len);
	}

	de_bitmap_write_to_file(img, ii->filename_token, createflags);
	retval = 1;

done:
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
	return retval;
}

// Print a summary line indicating the main characteristics of this file.
static void print_summary(deark *c, lctx *d)
{
	de_ucstring *summary = NULL;

	if(!d->found_bmhd) goto done;

	summary = ucstring_create(c);

	switch(d->formtype) {
	case CODE_ILBM: ucstring_append_sz(summary, "ILBM", DE_ENCODING_UTF8); break;
	case CODE_PBM:  ucstring_append_sz(summary, "PBM" , DE_ENCODING_UTF8); break;
	case CODE_ACBM: ucstring_append_sz(summary, "ACBM", DE_ENCODING_UTF8); break;
	default: ucstring_append_sz(summary, "???", DE_ENCODING_UTF8); break;
	}

	if(d->is_vdat)
		ucstring_append_sz(summary, " VDAT", DE_ENCODING_UTF8);
	else if(d->is_sham)
		ucstring_append_sz(summary, " SHAM", DE_ENCODING_UTF8);
	else if(d->is_pchg)
		ucstring_append_sz(summary, " PCHG", DE_ENCODING_UTF8);
	else if(d->is_ctbl)
		ucstring_append_sz(summary, " CBTL", DE_ENCODING_UTF8);
	else if(d->ham_flag)
		ucstring_append_sz(summary, " HAM", DE_ENCODING_UTF8);
	else if(d->ehb_flag)
		ucstring_append_sz(summary, " EHB", DE_ENCODING_UTF8);

	ucstring_printf(summary, DE_ENCODING_UTF8, " cmpr=%d", (int)d->compression);
	ucstring_printf(summary, DE_ENCODING_UTF8, " planes=%d", (int)d->planes);

	if(d->main_img.masking_code!=0)
		ucstring_printf(summary, DE_ENCODING_UTF8, " masking=%d", (int)d->main_img.masking_code);

	if(d->uses_color_cycling)
		ucstring_append_sz(summary, " color-cycling", DE_ENCODING_UTF8);

	if(de_inthashtable_item_exists(c, d->chunks_seen, (de_int64)CODE_CLUT)) {
		ucstring_append_sz(summary, " CLUT", DE_ENCODING_UTF8);
	}

	if(!d->found_cmap) {
		ucstring_append_sz(summary, " no-CMAP", DE_ENCODING_UTF8);
	}

	de_dbg(c, "summary: %s", ucstring_getpsz(summary));

done:
	ucstring_destroy(summary);
}

static int do_image(deark *c, lctx *d, struct img_info *ii,
	de_int64 pos1, de_int64 len, unsigned int createflags)
{
	dbuf *unc_pixels = NULL;
	dbuf *unc_pixels_toclose = NULL;
	int retval = 0;

	if(d->errflag) goto done;

	if(!d->found_bmhd) {
		de_err(c, "Missing BMHD chunk");
		goto done;
	}

	if(d->formtype==CODE_ILBM || d->formtype==CODE_ACBM ||
		(d->formtype==CODE_PBM && d->planes==8))
	{
		;
	}
	else {
		de_err(c, "Unsupported ILBM format");
		goto done;
	}

	if(!de_good_image_dimensions(c, ii->width, ii->height)) goto done;

	if(d->in_vdat_image) {
		// TODO: Consider using the tinystuff decoder for VDAT.
		if(d->planes!=4) {
			de_err(c, "VDAT compression not supported with planes=%d", (int)d->planes);
			goto done;
		}
		unc_pixels = d->vdat_unc_pixels;
	}
	else if(d->compression==0) {
		unc_pixels_toclose = dbuf_open_input_subfile(c->infile, pos1, len);
		unc_pixels = unc_pixels_toclose;
	}
	else if(d->compression==1) {
		unc_pixels_toclose = dbuf_create_membuf(c, 0, 0);
		unc_pixels = unc_pixels_toclose;
		// TODO: Call dbuf_set_max_length()
		if(!de_fmtutil_uncompress_packbits(c->infile, pos1, len, unc_pixels, NULL))
			goto done;
		de_dbg(c, "decompressed %d bytes to %d bytes", (int)len, (int)unc_pixels->len);
	}
	else {
		de_err(c, "Unsupported compression type: %d", (int)d->compression);
		goto done;
	}

	if(!unc_pixels) goto done;

	if(d->planes>=1 && d->planes<=8) {
		if(!do_image_1to8(c, d, ii, unc_pixels, createflags)) goto done;
	}
	else if(d->planes==24) {
		do_image_24(c, d, ii, unc_pixels, createflags);
	}
	else {
		de_err(c, "Support for this type of IFF/ILBM image is not implemented");
	}
	retval = 1;

done:
	dbuf_close(unc_pixels_toclose);
	return retval;
}

// Thumbnail chunk
static void do_tiny(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	struct img_info *ii = NULL;

	if(d->compression==2) {
		de_warn(c, "Thumbnails not supported with VDAT compression");
		goto done;
	}
	ii = de_malloc(c, sizeof(struct img_info));
	*ii = d->main_img; // structure copy
	ii->width = de_getui16be(pos1);
	if(len<=4) goto done;
	ii->height = de_getui16be(pos1+2);
	de_dbg(c, "thumbnail image, dimensions: %d"DE_CHAR_TIMES"%d", (int)ii->width, (int)ii->height);

	// Based on what little data I have, it seems that TINY images do not have
	// a transparency mask, even if the main image does.
	if(ii->masking_code==1) ii->masking_code=0;

	ii->filename_token = "thumb";
	do_image(c, d, ii, pos1+4, len-4, DE_CREATEFLAG_IS_AUX);

done:
	de_free(c, ii);
}

static void do_vdat(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_byte b0, b1;
	de_int64 count;
	de_int64 cmd_cnt;
	de_int64 i, k;
	de_byte cmd;
	de_byte *cmds = NULL;
	de_int64 prev_unc_len;

	d->is_vdat = 1;

	if(!d->vdat_unc_pixels) {
		// TODO: Ensure that a VDAT chunk with the wrong amount of uncompressed
		// data doesn't cause remaining VDAT chunks to get out of sync.
		d->vdat_unc_pixels = dbuf_create_membuf(c, 0, 0);
	}

	prev_unc_len = d->vdat_unc_pixels->len;

	pos = pos1;
	endpos = pos1+len;

	cmd_cnt = de_getui16be(pos); // command count + 2
	pos+=2;
	cmd_cnt -= 2;
	de_dbg(c, "number of command bytes: %d", (int)cmd_cnt);
	if(cmd_cnt<1) goto done;

	cmds = de_malloc(c, cmd_cnt * sizeof(de_byte));

	// Read commands
	de_read(cmds, pos, cmd_cnt);
	pos += cmd_cnt;

	// Read data
	for(i=0; i<cmd_cnt; i++) {
		if(pos>=endpos) {
			de_warn(c, "Unexpected end of data in VDAT chunk. %d of %d command bytes processed",
				(int)i, (int)cmd_cnt);
			break;
		}

		cmd = cmds[i];

		if(cmd==0x00) {
			count = de_getui16be(pos);
			pos+=2;
			count *= 2;
			dbuf_copy(c->infile, pos, count, d->vdat_unc_pixels);
			pos += count;
		}
		else if(cmd==0x01) {
			count = de_getui16be(pos);
			pos+=2;
			b0 = de_getbyte(pos++);
			b1 = de_getbyte(pos++);
			for(k=0; k<count; k++) {
				dbuf_writebyte(d->vdat_unc_pixels, b0);
				dbuf_writebyte(d->vdat_unc_pixels, b1);
			}
		}
		else if(cmd>=0x80) {
			count = 2*(128-(de_int64)(cmd&0x7f));
			dbuf_copy(c->infile, pos, count, d->vdat_unc_pixels);
			pos += count;
		}
		else { // cmd is from 0x02 to 0x7f
			b0 = de_getbyte(pos++);
			b1 = de_getbyte(pos++);
			count = (de_int64)cmd;
			for(k=0; k<count; k++) {
				dbuf_writebyte(d->vdat_unc_pixels, b0);
				dbuf_writebyte(d->vdat_unc_pixels, b1);
			}
		}
	}

	de_dbg(c, "uncompressed to %d bytes", (int)(d->vdat_unc_pixels->len - prev_unc_len));
done:
	de_free(c, cmds);
}

// A BODY or ABIT chunk
static int do_body(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len,
	de_uint32 ct, int *is_vdat)
{
	if(d->uses_color_cycling) {
		de_warn(c, "This image uses color cycling animation, which is not supported.");
	}

	if(ct==CODE_BODY && d->compression==2 &&
		!dbuf_memcmp(c->infile, pos, "VDAT", 4))
	{
		ictx->is_raw_container = 1;
		*is_vdat = 1;
		return 1;
	}

	return do_image(c, d, &d->main_img, pos, len, 0);
}

static void do_multipalette(deark *c, lctx *d, de_uint32 chunktype)
{
	if(chunktype==CODE_SHAM) { d->is_sham = 1; }
	else if(chunktype==CODE_PCHG) { d->is_pchg = 1; }
	else if(chunktype==CODE_CTBL) { d->is_ctbl = 1; }

	de_err(c, "Multi-palette ILBM images are not supported.");
	d->errflag = 1;
}

static int my_preprocess_ilbm_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_BMHD: name="bitmap header"; break;
	case CODE_BODY: name="image data"; break;
	case CODE_CAMG: name="Amiga viewport mode"; break;
	case CODE_CMAP: name="color map"; break;
	case CODE_CRNG: name="color register range info"; break;
	case CODE_DPI : name="dots/inch"; break;
	case CODE_DRNG: name="color cycle"; break;
	case CODE_GRAB: name="hotspot"; break;
	case CODE_TINY: name="thumbnail"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	else {
		de_fmtutil_default_iff_chunk_identify(c, ictx);
	}
	return 1;
}

static int my_ilbm_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	int quitflag = 0;
	int is_vdat;
	de_int64 tmp1, tmp2;
	int saved_indent_level;
	lctx *d = (lctx*)ictx->userdata;

	de_dbg_indent_save(c, &saved_indent_level);

	// Remember that we've seen at least one chunk of this type
	de_inthashtable_add_item(c, d->chunks_seen, (de_int64)ictx->chunkctx->chunk4cc.id, NULL);

	// Pretend we can handle all nonstandard chunks
	if(!de_fmtutil_is_standard_iff_chunk(c, ictx, ictx->chunkctx->chunk4cc.id)) {
		ictx->handled = 1;
	}

	// Most chunks are only processed at level 1.
	if(ictx->level!=1 && ictx->chunkctx->chunk4cc.id!=CODE_FORM &&
		ictx->chunkctx->chunk4cc.id!=CODE_VDAT)
	{
		goto done;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_BODY:
	case CODE_ABIT:
		is_vdat = 0;
		if(!do_body(c, d, ictx, ictx->chunkctx->dpos, ictx->chunkctx->dlen,
			ictx->chunkctx->chunk4cc.id, &is_vdat)) {
			d->errflag = 1;
		}

		// A lot of ILBM files have padding or garbage data at the end of the file
		// (apparently included in the file size given by the FORM chunk).
		// To avoid it, don't read past the BODY chunk.

		if(!is_vdat)
			quitflag = 1;
		break;

	case CODE_VDAT:
		if(ictx->level!=2) break;
		do_vdat(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_TINY:
		do_tiny(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_BMHD:
		if(!do_bmhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen)) {
			d->errflag = 1;
			goto done;
		}
		break;

	case CODE_CMAP:
		do_cmap(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CAMG:
		do_camg(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_DPI:
		do_dpi(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CCRT: // Graphicraft Color Cycling Range and Timing
		tmp1 = de_geti16be(ictx->chunkctx->dpos);
		de_dbg(c, "cycling direction: %d", (int)tmp1);
		if(tmp1!=0) {
			d->uses_color_cycling = 1;
		}
		break;

	case CODE_CRNG:
		if(ictx->chunkctx->dlen<8) break;
		tmp1 = de_getui16be(ictx->chunkctx->dpos+2);
		tmp2 = de_getui16be(ictx->chunkctx->dpos+4);
		de_dbg(c, "CRNG flags: 0x%04x", (unsigned int)tmp2);
		if(tmp2&0x1) {
			d->uses_color_cycling = 1;
			de_dbg(c, "rate: %.2f fps", (double)(((double)tmp1)*(60.0/16384.0)));
		}
		break;

	case CODE_DRNG:
		tmp2 = de_getui16be(ictx->chunkctx->dpos+4);
		de_dbg(c, "DRNG flags: 0x%04x", (unsigned int)tmp2);
		if(tmp2&0x1) {
			d->uses_color_cycling = 1;
		}
		break;

	case CODE_GRAB:
		if(ictx->chunkctx->dlen<4) break;
		tmp1 = de_getui16be(ictx->chunkctx->dpos);
		tmp2 = de_getui16be(ictx->chunkctx->dpos+2);
		de_dbg(c, "hotspot: (%d, %d)", (int)tmp1, (int)tmp2);
		break;

	case CODE_SHAM:
	case CODE_PCHG:
	case CODE_CTBL:
		do_multipalette(c, d, ictx->chunkctx->chunk4cc.id);
		goto done;

	case CODE_FORM:
		if(ictx->level!=0) break;
		ictx->is_std_container = 1;
		break;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static int my_on_std_container_start_fn(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->level==0 && ictx->curr_container_fmt4cc.id==CODE_FORM) {
		d->formtype = ictx->curr_container_contentstype4cc.id;

		switch(ictx->main_contentstype4cc.id) {
		case CODE_ILBM: de_declare_fmt(c, "IFF-ILBM"); break;
		case CODE_PBM:  de_declare_fmt(c, "IFF-PBM");  break;
		case CODE_ACBM: de_declare_fmt(c, "IFF-ACBM"); break;
		}
	}
	return 1;
}

static int my_on_container_end_fn(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	de_dbg2(c, "container_end(level=%d, fmt=%08x, contentstype=%08x)",
		ictx->level,
		(unsigned int)ictx->curr_container_fmt4cc.id,
		(unsigned int)ictx->curr_container_contentstype4cc.id);

	if(ictx->curr_container_fmt4cc.id==CODE_BODY) {
		d->in_vdat_image = 1;
		do_image(c, d, &d->main_img, 0, 0, 0);
		d->in_vdat_image = 0;
	}

	return 1;
}

static void de_run_ilbm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *s;

	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	s = de_get_ext_option(c, "ilbm:notrans");
	if(s) d->opt_notrans = 1;

	d->opt_fixpal = 1;
	s = de_get_ext_option(c, "ilbm:fixpal");
	if(s) d->opt_fixpal = de_atoi(s);

	ictx->userdata = (void*)d;
	ictx->preprocess_chunk_fn = my_preprocess_ilbm_chunk_fn;
	ictx->handle_chunk_fn = my_ilbm_chunk_handler;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->on_container_end_fn = my_on_container_end_fn;
	ictx->f = c->infile;
	d->chunks_seen = de_inthashtable_create(c);
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);
	print_summary(c, d);

	dbuf_close(d->vdat_unc_pixels);
	de_inthashtable_destroy(c, d->chunks_seen);
	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_ilbm(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "FORM", 4)) {
		if(!de_memcmp(&buf[8], "ILBM", 4)) return 100;
		if(!de_memcmp(&buf[8], "PBM ", 4)) return 100;
		if(!de_memcmp(&buf[8], "ACBM", 4)) return 100;
	}
	return 0;
}

static void de_help_ilbm(deark *c)
{
	de_msg(c, "-opt ilbm:notrans : Disable support for transparency");
	de_msg(c, "-opt ilbm:fixpal=<0|1> : Don't/Do try to fix palettes that are "
		"slightly too dark");
}

void de_module_ilbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ilbm";
	mi->desc = "IFF-ILBM and related image formats";
	mi->run_fn = de_run_ilbm;
	mi->identify_fn = de_identify_ilbm;
	mi->help_fn = de_help_ilbm;
}

// -----------------------------------

typedef struct animctx_struct {
	int reserved;
} animctx;

static void do_anim_anhd(deark *c, animctx *d, de_int64 pos, de_int64 len)
{
	de_byte op;
	de_int64 tmp;

	if(len<24) return;

	op = de_getbyte(pos++);
	de_dbg(c, "operation: %d", (int)op);

	pos++; // Mask
	pos+=2; // w
	pos+=2; // h
	pos+=2; // x
	pos+=2; // y
	pos+=4; // abstime

	tmp = de_getui32be(pos); // reltime
	de_dbg(c, "reltime: %.5f sec", ((double)tmp)/60.0);
	pos+=4;

	pos++; // interleave
	pos++; // pad0

	// bits
	if(op==4 || op==5) {
		tmp = de_getui32be(pos);
		de_dbg(c, "flags: 0x%08u", (unsigned int)tmp);
	}
	pos+=4;
}

static int my_anim_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	int quitflag = 0;
	int saved_indent_level;
	animctx *d = (animctx*)ictx->userdata;

	de_dbg_indent_save(c, &saved_indent_level);

	// Pretend we can handle all nonstandard chunks
	if(!de_fmtutil_is_standard_iff_chunk(c, ictx, ictx->chunkctx->chunk4cc.id)) {
		ictx->handled = 1;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANHD:
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_FORM:
		if(ictx->level>1) break;
		ictx->is_std_container = 1;
		break;
	}

	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	animctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_anim_chunk_handler;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_anim(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "FORM", 4)) {
		if(!de_memcmp(&buf[8], "ANIM", 4)) return 100;
	}
	return 0;
}

void de_module_anim(deark *c, struct deark_module_info *mi)
{
	mi->id = "anim";
	mi->desc = "IFF-ANIM animation";
	mi->run_fn = de_run_anim;
	mi->identify_fn = de_identify_anim;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
