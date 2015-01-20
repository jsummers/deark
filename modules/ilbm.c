// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Decode IFF/ILBM and related image formats

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int level;
	de_uint32 formtype;

	de_int64 width, height;
	de_int64 planes;
	de_byte found_bmhd;
	de_byte found_cmap;
	de_byte compression;

	de_int64 rowspan;
	de_int64 bits_per_row_per_plane;
	de_int64 x_aspect, y_aspect;

	de_uint32 pal[256];
} lctx;

#define CODE_FORM  0x464f524d
#define CODE_BODY  0x424f4459
#define CODE_CMAP  0x434d4150
#define CODE_BMHD  0x424d4844

#define CODE_ILBM  0x494c424d
#define CODE_PBM   0x50424d20 

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
	d->width = de_getui16be(pos1);
	d->height = de_getui16be(pos1+2);
	d->planes = (de_int64)de_getbyte(pos1+8);
	d->compression = de_getbyte(pos1+10);
	d->x_aspect = (de_int64)de_getbyte(pos1+14);
	d->y_aspect = (de_int64)de_getbyte(pos1+15);
	de_dbg(c, "dimensions: %dx%d, planes: %d, compression: %d\n", (int)d->width,
		(int)d->height, (int)d->planes, (int)d->compression);
	de_dbg(c, "apect ratio: %d, %d\n", (int)d->x_aspect, (int)d->y_aspect);

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	retval = 1;
done:
	return retval;
}

static void do_cmap(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 ncolors;
	de_int64 k;

	d->found_cmap = 1;
	ncolors = len/3;
	if(ncolors>256) ncolors=256;

	for(k=0; k<ncolors; k++) {
		d->pal[k] = dbuf_getRGB(c->infile, pos+3*k, 0);
	}
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

static void set_density(deark *c, lctx *d, struct deark_bitmap *img)
{
	if(d->x_aspect<1 || d->y_aspect<1) return;
	img->density_code = DE_DENSITY_UNK_UNITS;
	// TODO: Is this the right interpretation of the ILBM "aspect ratio" fields?
	img->ydens = (double)d->x_aspect;
	img->xdens = (double)d->y_aspect;
}

static void do_image_24(deark *c, lctx *d, dbuf *unc_pixels)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte cr, cg, cb;

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

	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
}

static void do_image_1to8(deark *c, lctx *d, dbuf *unc_pixels)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_byte *row_orig = NULL;
	de_byte *row_deplanarized = NULL;
	de_byte palent;

	if(!d->found_cmap) {
		de_err(c, "Missing CMAP chunk\n");
		goto done;
	}

	d->bits_per_row_per_plane = ((d->width+15)/16)*16;
	d->rowspan = (d->bits_per_row_per_plane/8) * d->planes;

	row_orig = de_malloc(c, d->rowspan);
	row_deplanarized = de_malloc(c, d->width);

	img = de_bitmap_create(c, d->width, d->height, 3);
	set_density(c, d, img);

	for(j=0; j<d->height; j++) {
		dbuf_read(unc_pixels, row_orig, j*d->rowspan, d->rowspan);
		do_deplanarize(c, d, row_orig, row_deplanarized);

		for(i=0; i<d->width; i++) {
			palent = row_deplanarized[i];
			de_bitmap_setpixel_rgb(img, i, j, d->pal[(unsigned int)palent]);
		}
	}

	de_bitmap_write_to_file(img, NULL);
done:
	de_bitmap_destroy(img);
	de_free(c, row_orig);
	de_free(c, row_deplanarized);
}

static void do_body(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	dbuf *unc_pixels = NULL;

	if(!d->found_bmhd) {
		de_err(c, "Missing BMHD chunk\n");
		goto done;
	}

	if(d->formtype != CODE_ILBM) {
		de_err(c, "This image format is not supported\n");
		goto done;
	}

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
		do_image_1to8(c, d, unc_pixels);
	}
	else if(d->planes==24) {
		do_image_24(c, d, unc_pixels);
	}
	else {
		de_err(c, "Support for this type of IFF/ILBM image is not implemented\n");
	}

done:
	dbuf_close(unc_pixels);
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

	if(chunk_data_len > bytes_avail-8) {
		de_err(c, "Invalid chunk size ('%s' at %d, size=%d)\n",
			printable_code, (int)pos, (int)chunk_data_len);
		errflag = 1;
		goto done;
	}

	switch(ct) {
	case CODE_BODY:
		if(d->level!=1) break;
		do_body(c, d, chunk_data_pos, chunk_data_len);

		// A lot of ILBM files have padding or garbage data at the end of the file
		// (apparently included in the file size given by the FORM chunk).
		// To avoid it, don't read past the BODY chunk.
		doneflag = 1;
		break;

	case CODE_BMHD:
		if(d->level!=1) break;
		if(!do_bmhd(c, d, chunk_data_pos, chunk_data_len)) {
			errflag = 1;
			goto done;
		}
		break;

	case CODE_CMAP:
		if(d->level!=1) break;
		do_cmap(c, d, chunk_data_pos, chunk_data_len);
		break;

	case CODE_FORM:
		de_dbg_indent(c, 1);
		d->level++;

		// First 4 bytes of payload are the FORM type ID (usually "ILBM").
		d->formtype = (de_uint32)de_getui32be(pos+8);
		make_printable_code(d->formtype, printable_code, sizeof(printable_code));
		de_dbg(c, "FORM type: '%s'\n", printable_code);

		// The rest is a sequence of chunks.
		ret = do_chunk_sequence(c, d, pos+12, bytes_avail-12);
		d->level--;
		de_dbg_indent(c, -1);
		if(!ret) {
			errflag = 1;
			goto done;
		}
		break;
	}

	*bytes_consumed = 8 + chunk_data_len;
	if(chunk_data_len%2) (*bytes_consumed)++; // Padding byte

done:
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

	de_warn(c, "ILBM support is experimental, and may not work correctly.\n");

	d = de_malloc(c, sizeof(lctx));
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
	}
	return 0;
}

void de_module_ilbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ilbm";
	mi->run_fn = de_run_ilbm;
	mi->identify_fn = de_identify_ilbm;
}
