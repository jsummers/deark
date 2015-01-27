// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Decode IFF/ILBM and related image formats

#include <deark-config.h>
#include <deark-modules.h>

#define CODE_ABIT  0x41424954
#define CODE_BMHD  0x424d4844
#define CODE_BODY  0x424f4459
#define CODE_CAMG  0x43414d47
#define CODE_CMAP  0x434d4150
#define CODE_DPI   0x44504920
#define CODE_FORM  0x464f524d
#define CODE_TINY  0x54494e59

#define CODE_ILBM  0x494c424d
#define CODE_PBM   0x50424d20
#define CODE_ACBM  0x4143424d

typedef struct localctx_struct {
	int level;
	de_uint32 formtype;

	de_int64 bmhd_width, bmhd_height; // Dimensions of the main image
	de_int64 width, height; // Dimensions of the current image
	de_int64 planes;
	de_int64 planes_total;
	de_byte found_bmhd;
	de_byte found_cmap;
	de_byte compression;
	de_byte has_camg;
	de_byte ham_flag; // "hold and modify"
	de_byte halfbrite_flag;
	de_byte masking_code;
	de_byte is_ham6;
	de_byte is_ham8;
	de_int64 transparent_color;

	de_int64 rowspan;
	de_int64 planespan;
	de_int64 bits_per_row_per_plane;
	de_int64 x_aspect, y_aspect;
	de_int64 x_dpi, y_dpi;
	de_int32 camg_mode;

	int opt_notrans;

	// Our palette always has 256 colors. This is how many we read from the file.
	de_int64 pal_ncolors;

	de_uint32 pal[256];
} lctx;

// Caller supplies buf[]
static void make_printable_code(de_uint32 code, char *buf, size_t buf_size)
{
	de_byte s1[4];
	s1[0] = (de_byte)((code & 0xff000000U)>>24);
	s1[1] = (de_byte)((code & 0x00ff0000U)>>16);
	s1[2] = (de_byte)((code & 0x0000ff00U)>>8);
	s1[3] = (de_byte)(code & 0x000000ffU);
	de_make_printable_ascii(s1, 4, buf, buf_size, 0);
}

static int do_bmhd(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	int retval = 0;

	if(len<20) {
		de_err(c, "Bad BMHD chunk\n");
		goto done;
	}

	d->found_bmhd = 1;
	d->bmhd_width = de_getui16be(pos1);
	d->bmhd_height = de_getui16be(pos1+2);
	d->planes = (de_int64)de_getbyte(pos1+8);
	d->masking_code = de_getbyte(pos1+9);
	d->compression = de_getbyte(pos1+10);
	d->transparent_color = de_getui16be(pos1+12);
	d->x_aspect = (de_int64)de_getbyte(pos1+14);
	d->y_aspect = (de_int64)de_getbyte(pos1+15);
	de_dbg(c, "dimensions: %dx%d, planes: %d, compression: %d\n", (int)d->bmhd_width,
		(int)d->bmhd_height, (int)d->planes, (int)d->compression);
	de_dbg(c, "apect ratio: %d, %d\n", (int)d->x_aspect, (int)d->y_aspect);
	de_dbg(c, "masking: %d, color key: %d\n", (int)d->masking_code, (int)d->transparent_color);

	retval = 1;
done:
	return retval;
}

static void do_cmap(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 k;

	d->found_cmap = 1;
	d->pal_ncolors = len/3;
	de_dbg(c, "number of palette colors: %d\n", (int)d->pal_ncolors);
	if(d->pal_ncolors>256) d->pal_ncolors=256;

	for(k=0; k<d->pal_ncolors; k++) {
		d->pal[k] = dbuf_getRGB(c->infile, pos+3*k, 0);
	}
}

static void do_camg(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	if(len<4) return;
	d->has_camg = 1;

	d->camg_mode = (de_uint32)de_getui32be(pos);
	de_dbg(c, "CAMG mode: 0x%x\n", (unsigned int)d->camg_mode);

	if(d->camg_mode & 0x0800)
		d->ham_flag = 1;
	if(d->camg_mode & 0x0080)
		d->halfbrite_flag = 1;

	de_dbg(c, "is HAM: %d\n", (int)d->ham_flag);
	de_dbg(c, "is Halfbrite: %d\n", (int)d->halfbrite_flag);
}

static void do_dpi(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	if(len<4) return;
	d->x_dpi = de_getui16be(pos);
	d->y_dpi = de_getui16be(pos+2);
	de_dbg(c, "dpi: %dx%d\n", (int)d->x_dpi, (int)d->y_dpi);
}

static int do_uncompress_rle(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = de_getbyte(pos++);

		if(b>128) { // A compressed run
			count = 257 - (de_int64)b;
			b2 = de_getbyte(pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
		else { // b==128
			break;
		}
	}

	de_dbg(c, "decompressed %d bytes to %d bytes\n", (int)len, (int)unc_pixels->len);

	return 1;
}

static de_byte getbit(const de_byte *m, de_int64 bitnum)
{
	de_byte b;
	b = m[bitnum/8];
	b = (b>>(7-bitnum%8)) & 0x1;
	return b;
}

static void do_deplanarize(deark *c, lctx *d, const de_byte *row_orig,
	de_byte *row_deplanarized)
{
	de_int64 i;
	de_int64 sample;
	de_int64 bit;
	de_byte b;

	if(d->planes>=1 && d->planes<=8) {
		de_memset(row_deplanarized, 0, d->width);
		for(i=0; i<d->width; i++) {
			for(bit=0; bit<d->planes; bit++) {
				b = getbit(row_orig, bit*d->bits_per_row_per_plane +i);
				if(b) row_deplanarized[i] |= (1<<bit);
			}
		}
	}
	else if(d->planes==24) {
		de_memset(row_deplanarized, 0, d->width*3);
		for(i=0; i<d->width; i++) {
			for(sample=0; sample<3; sample++) {
				for(bit=0; bit<8; bit++) {
					b = getbit(row_orig, (sample*8+bit)*d->bits_per_row_per_plane + i);
					if(b) row_deplanarized[i*3 + sample] |= (1<<bit);
				}
			}
		}
	}
}

static void get_row_acbm(deark *c, lctx *d, dbuf *unc_pixels, de_int64 j, de_byte *row)
{
	de_int64 i;
	de_int64 bit;
	de_byte b;

	de_memset(row, 0, d->width);
	for(i=0; i<d->width; i++) {
		for(bit=0; bit<d->planes; bit++) {
			b = de_get_bits_symbol(unc_pixels, 1, bit*d->planespan + j*d->rowspan, i);
			if(b) row[i] |= (1<<bit);
		}
	}
}

static void set_density(deark *c, lctx *d, struct deark_bitmap *img)
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

static void do_image_24(deark *c, lctx *d, dbuf *unc_pixels, const char *token)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte cr, cg, cb;

	if(d->formtype!=CODE_ILBM) {
		de_err(c, "This image type is not supported\n");
		goto done;
	}

	d->bits_per_row_per_plane = ((d->width+15)/16)*16;
	d->rowspan = (d->bits_per_row_per_plane/8) * d->planes;
	row_orig = de_malloc(c, d->rowspan);
	row_deplanarized = de_malloc(c, d->width * 3);

	img = de_bitmap_create(c, d->width, d->height, 3);
	set_density(c, d, img);

	for(j=0; j<d->height; j++) {
		dbuf_read(unc_pixels, row_orig, j*d->rowspan, d->rowspan);
		do_deplanarize(c, d, row_orig, row_deplanarized);

		for(i=0; i<d->width; i++) {
			cr = row_deplanarized[i*3];
			cg = row_deplanarized[i*3+1];
			cb = row_deplanarized[i*3+2];
			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(cr,cg,cb));
		}
	}

	de_bitmap_write_to_file(img, token);
done:
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
}

static int is_grayscale_palette(const de_uint32 *pal, de_int64 num_entries)
{
	de_int64 k;
	de_byte cr;

	for(k=0; k<num_entries; k++) {
		cr = DE_COLOR_R(pal[k]);
		if(cr != DE_COLOR_G(pal[k])) return 0;
		if(cr != DE_COLOR_B(pal[k])) return 0;
	}
	return 1;
}

static void make_halfbrite_palette(deark *c, lctx *d)
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
		de_dbg(c, "Palette seems to have 4 bits of precision. Trying to compensate.\n");
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

static void do_image_1to8(deark *c, lctx *d, dbuf *unc_pixels, const char *token)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte val;
	de_byte cr = 0;
	de_byte cg = 0;
	de_byte cb = 0;
	de_uint32 clr;
	int dst_bytes_per_pixel;

	if(!d->found_cmap) {
		de_err(c, "Missing CMAP chunk\n");
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
			de_warn(c, "Invalid bit depth (%d) for HAM image.\n", (int)d->planes);
		}
	}

	fixup_palette(c, d);

	if(d->halfbrite_flag && d->planes==6 && d->pal_ncolors==32) {
		make_halfbrite_palette(c, d);
	}

	// If using color-keyed transparency, make one of the palette colors transparent.
	if(d->masking_code==2 && !d->opt_notrans) {
		if(d->transparent_color<=255) {
			d->pal[(int)d->transparent_color] &= 0x00ffffffU;
		}
	}

	d->planes_total = d->planes;
	if(d->masking_code==1) d->planes_total++;

	d->bits_per_row_per_plane = ((d->width+15)/16)*16;
	if(d->formtype==CODE_ACBM) {
		d->rowspan = d->bits_per_row_per_plane/8;
		d->planespan = d->height * d->rowspan;
	}
	else {
		d->rowspan = (d->bits_per_row_per_plane/8) * d->planes_total;
	}

	row_orig = de_malloc(c, d->rowspan);
	row_deplanarized = de_malloc(c, d->width);

	if(!d->is_ham6 && !d->is_ham8 && is_grayscale_palette(d->pal, 256))
		dst_bytes_per_pixel = 1;
	else
		dst_bytes_per_pixel = 3;

	if(d->masking_code==2 && !d->opt_notrans)
		dst_bytes_per_pixel++;

	img = de_bitmap_create(c, d->width, d->height, dst_bytes_per_pixel);
	set_density(c, d, img);

	for(j=0; j<d->height; j++) {
		if(d->is_ham6 || d->is_ham8) {
			// At the beginning of each row, the color accumulators are
			// initialized to palette entry 0.
			cr = DE_COLOR_R(d->pal[0]);
			cg = DE_COLOR_G(d->pal[0]);
			cb = DE_COLOR_B(d->pal[0]);
		}

		if(d->formtype==CODE_ACBM) {
			get_row_acbm(c, d, unc_pixels, j, row_deplanarized);
		}
		else if(d->formtype==CODE_PBM) {
			dbuf_read(unc_pixels, row_deplanarized, j*d->rowspan, d->rowspan);
		}
		else {
			dbuf_read(unc_pixels, row_orig, j*d->rowspan, d->rowspan);
			do_deplanarize(c, d, row_orig, row_deplanarized);
		}

		for(i=0; i<d->width; i++) {
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
				de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(cr,cg,cb));
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
				de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(cr,cg,cb));
			}
			else {
				de_bitmap_setpixel_rgb(img, i, j, d->pal[(unsigned int)val]);
			}
		}
	}

	de_bitmap_write_to_file(img, token);
done:
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
}

// Caller must first set d->width and d->height.
static void do_image(deark *c, lctx *d, de_int64 pos1, de_int64 len, const char *token)
{
	dbuf *unc_pixels = NULL;

	if(!d->found_bmhd) {
		de_err(c, "Missing BMHD chunk\n");
		goto done;
	}

	if(d->formtype==CODE_ILBM || d->formtype==CODE_ACBM ||
		(d->formtype==CODE_PBM && d->planes==8))
	{
		;
	}
	else {
		goto done;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	if(d->compression==0) {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos1, len);
	}
	else if(d->compression==1) {
		unc_pixels = dbuf_create_membuf(c, 0);
		// TODO: Call dbuf_set_max_length()
		if(!do_uncompress_rle(c, d, pos1, len, unc_pixels))
			goto done;
	}
	else {
		de_err(c, "Unsupported compression type: %d\n", (int)d->compression);
		goto done;
	}

	if(d->planes>=1 && d->planes<=8) {
		do_image_1to8(c, d, unc_pixels, token);
	}
	else if(d->planes==24) {
		do_image_24(c, d, unc_pixels, token);
	}
	else {
		de_err(c, "Support for this type of IFF/ILBM image is not implemented\n");
	}

done:
	dbuf_close(unc_pixels);
}

// Thumbnail chunk
static void do_tiny(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	d->width = de_getui16be(pos1);
	if(len<=4) return;
	d->height = de_getui16be(pos1+2);
	de_dbg(c, "thumbnail image, dimensions: %dx%d\n", (int)d->width, (int)d->height);
	do_image(c, d, pos1+4, len-4, "thumb");
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len);

static int do_chunk(deark *c, lctx *d, de_int64 pos, de_int64 bytes_avail,
	de_int64 *bytes_consumed)
{
	de_uint32 ct;
	char printable_code[8];
	int errflag = 0;
	int doneflag = 0;
	int ret;
	de_int64 chunk_data_pos;
	de_int64 chunk_data_len;
	int need_unindent = 0;

	if(bytes_avail<8) {
		de_err(c, "Invalid chunk size (at %d, size=%d)\n", (int)pos, (int)bytes_avail);
		errflag = 1;
		goto done;
	}
	ct = (de_uint32)de_getui32be(pos);
	chunk_data_len = de_getui32be(pos+4);
	chunk_data_pos = pos+8;

	make_printable_code(ct, printable_code, sizeof(printable_code));
	de_dbg(c, "Chunk '%s' at %d, data at %d, size %d\n", printable_code, (int)pos,
		(int)chunk_data_pos, (int)chunk_data_len);
	de_dbg_indent(c, 1);
	need_unindent = 1;

	if(chunk_data_len > bytes_avail-8) {
		de_err(c, "Invalid chunk size ('%s' at %d, size=%d)\n",
			printable_code, (int)pos, (int)chunk_data_len);
		errflag = 1;
		goto done;
	}

	switch(ct) {
	case CODE_BODY:
	case CODE_ABIT:
		d->width = d->bmhd_width;
		d->height = d->bmhd_height;
		do_image(c, d, chunk_data_pos, chunk_data_len, NULL);

		// A lot of ILBM files have padding or garbage data at the end of the file
		// (apparently included in the file size given by the FORM chunk).
		// To avoid it, don't read past the BODY chunk.
		doneflag = 1;
		break;

	case CODE_TINY:
		do_tiny(c, d, chunk_data_pos, chunk_data_len);
		break;

	case CODE_BMHD:
		if(!do_bmhd(c, d, chunk_data_pos, chunk_data_len)) {
			errflag = 1;
			goto done;
		}
		break;

	case CODE_CMAP:
		do_cmap(c, d, chunk_data_pos, chunk_data_len);
		break;

	case CODE_CAMG:
		do_camg(c, d, chunk_data_pos, chunk_data_len);
		break;

	case CODE_DPI:
		do_dpi(c, d, chunk_data_pos, chunk_data_len);
		break;

	case CODE_FORM:
		if(d->level!=0) break;
		d->level++;

		// First 4 bytes of payload are the FORM type ID (usually "ILBM").
		d->formtype = (de_uint32)de_getui32be(pos+8);
		make_printable_code(d->formtype, printable_code, sizeof(printable_code));
		de_dbg(c, "FORM type: '%s'\n", printable_code);

		switch(d->formtype) {
		case CODE_ILBM: de_declare_fmt(c, "IFF-ILBM"); break;
		case CODE_PBM:  de_declare_fmt(c, "IFF-PBM");  break;
		case CODE_ACBM: de_declare_fmt(c, "IFF-ACBM"); break;
		}

		// The rest is a sequence of chunks.
		ret = do_chunk_sequence(c, d, pos+12, bytes_avail-12);
		d->level--;
		if(!ret) {
			errflag = 1;
			goto done;
		}
		break;
	}

	*bytes_consumed = 8 + chunk_data_len;
	if(chunk_data_len%2) (*bytes_consumed)++; // Padding byte

done:
	if(need_unindent)
		de_dbg_indent(c, -1);
	return (errflag || doneflag) ? 0 : 1;
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 chunk_len;
	int ret;

	if(d->level >= 10) { // An arbitrary recursion limit.
		return 0;
	}

	endpos = pos1+len;
	
	pos = pos1;
	while(pos < endpos) {
		ret = do_chunk(c, d, pos, endpos-pos, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	return 1;
}

static void de_run_ilbm(deark *c, const char *params)
{
	lctx *d = NULL;
	const char *s;

	de_warn(c, "ILBM support is experimental, and may not work correctly.\n");

	d = de_malloc(c, sizeof(lctx));

	s = de_get_ext_option(c, "ilbm:notrans");
	if(s) d->opt_notrans = 1;

	do_chunk_sequence(c, d, 0, c->infile->len);
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

void de_module_ilbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ilbm";
	mi->run_fn = de_run_ilbm;
	mi->identify_fn = de_identify_ilbm;
}
