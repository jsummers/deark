// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Encapsulated PostScript

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_eps);

typedef struct localctx_struct {
	de_int64 w, h;
	de_int64 depth;
	de_int64 lines;

	de_int64 hex_digit_count;
	de_int64 xpos, ypos;
	de_byte pending_byte;
} lctx;


static void de_run_eps_binary(deark *c)
{
	de_int64 eps_offset, eps_len;
	de_int64 wmf_offset, wmf_len;
	de_int64 tiff_offset, tiff_len;

	de_declare_fmt(c, "EPS binary");

	eps_offset  = de_getui32le(4);
	eps_len     = de_getui32le(8);
	wmf_offset  = de_getui32le(12);
	wmf_len     = de_getui32le(16);
	tiff_offset = de_getui32le(20);
	tiff_len    = de_getui32le(24);

	if(eps_len>0) {
		de_dbg(c, "Extracting EPS offs=%d len=%d", (int)eps_offset, (int)eps_len);
		dbuf_create_file_from_slice(c->infile, eps_offset, eps_len, "eps", NULL, 0);
	}
	if(wmf_len>0) {
		de_dbg(c, "Extracting WMF offs=%d len=%d", (int)wmf_offset, (int)wmf_len);
		dbuf_create_file_from_slice(c->infile, wmf_offset, wmf_len, "preview.wmf", NULL, DE_CREATEFLAG_IS_AUX);
	}
	if(tiff_len>0) {
		de_dbg(c, "Extracting TIFF offs=%d len=%d", (int)tiff_offset, (int)tiff_len);
		dbuf_create_file_from_slice(c->infile, tiff_offset, tiff_len, "preview.tif", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void process_hex_digit(deark *c, lctx *d, de_byte hexdigit, dbuf *outf)
{
	de_byte x;
	int errorflag;

	x = de_decode_hex_digit(hexdigit, &errorflag);
	if(errorflag) return; // Ignore non hex-digits

	if(d->hex_digit_count%2 == 0) {
		d->pending_byte = x;
		d->hex_digit_count++;
		// Wait for the next hex digit
		return;
	}

	dbuf_writebyte(outf, (d->pending_byte<<4) | x);
	d->hex_digit_count++;
	return;
}

static void convert_row_gray(dbuf *f, de_int64 fpos, de_bitmap *img,
	de_int64 rownum, int depth)
{
	de_int64 i;
	de_byte b;

	for(i=0; i<img->width; i++) {
		b = de_get_bits_symbol(f, depth, fpos, i);
		if(depth==1) b*=255;
		else if(depth==2) b*=85;
		else if(depth==4) b*=17;
		de_bitmap_setpixel_gray(img, i, rownum, 255-b);
	}
}

static void do_decode_epsi_image(deark *c, lctx *d, de_int64 pos1)
{
	de_bitmap *img = NULL;
	dbuf *tmpf = NULL;
	de_int64 content_len, total_len;
	de_int64 pos;
	de_int64 i, j, k;
	de_int64 src_rowspan;


	pos = pos1;
	d->hex_digit_count = 0;

	tmpf = dbuf_create_membuf(c, d->w * d->h, 0);

	// Convert from hex-encoded (base16) to binary.
	for(i=0; i<d->lines; i++) {
		if(!dbuf_find_line(c->infile, pos, &content_len, &total_len))
			break;
		for(k=0; k<content_len; k++) {
			process_hex_digit(c, d, de_getbyte(pos+k), tmpf);
		}
		pos += total_len;
	}

	// Convert from binary to an image

	img = de_bitmap_create(c, d->w, d->h, 1);

	src_rowspan = (d->w * d->depth +7)/8;

	for(j=0; j<d->h; j++) {
		convert_row_gray(tmpf, j*src_rowspan, img, j, (int)d->depth);
	}

	de_bitmap_write_to_file(img, "preview", DE_CREATEFLAG_IS_AUX);
	de_bitmap_destroy(img);
	dbuf_close(tmpf);
}

static void do_decode_epsi(deark *c, const char *hdrfields, de_int64 pos1)
{
	int width, height, depth, lines;
	int ret;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	// EPSI is a text-based format, and deark isn't very good at text formats.
	// But we'll give it a try.

	ret = de_sscanf(hdrfields, " %d %d %d %d", &width, &height, &depth, &lines);
	if(ret!=4) {
		de_err(c, "Failed to parse EPSI header line");
		return;
	}
	de_dbg(c, "w=%d h=%d d=%d l=%d", width, height, depth, lines);
	d->w = width;
	d->h = height;
	d->depth = depth;
	d->lines = lines;

	if(!de_good_image_dimensions(c, d->w, d->h)) {
		goto done;
	}
	if(d->depth!=1 && d->depth!=2 && d->depth!=4 && d->depth!=8) {
		de_err(c, "Unsupported EPSI bit depth (%d)", (int)d->depth);
		goto done;
	}
	if(d->lines>100000 || d->lines<1) {
		de_err(c, "Bad EPSI header");
		goto done;
	}

	do_decode_epsi_image(c, d, pos1);

done:
	de_free(c, d);
}

static void de_run_eps_normal(deark *c)
{
	de_int64 pos;
	de_byte linebuf[1024];
	de_int64 content_len, total_len;

	de_declare_fmt(c, "Encapsulated PostScript");

	pos = 0;
	while(dbuf_find_line(c->infile, pos, &content_len, &total_len)) {
		de_dbg2(c, "line: pos=%d c_len=%d t_len=%d", (int)pos, (int)content_len, (int)total_len);

		if(content_len > (de_int64)(sizeof(linebuf)-1))
			content_len = sizeof(linebuf)-1;

		de_read(linebuf, pos, content_len);
		linebuf[content_len] = '\0';

		if(!de_memcmp(linebuf, "%%BeginPreview:", 15)) {
			do_decode_epsi(c, (const char*)(linebuf+15), pos+total_len);
			break;
		}

		pos += total_len;
	}
}

static void de_run_eps(deark *c, de_module_params *mparams)
{
	de_byte b[2];

	de_read(b, 0, (de_int64)sizeof(b));

	if(b[0]==0xc5 && b[1]==0xd0) {
		de_run_eps_binary(c);
	}
	else if(b[0]=='%' && b[1]=='!') {
		de_run_eps_normal(c);
	}
	else {
		de_err(c, "Not an EPS file");
	}
}

static int de_identify_eps(deark *c)
{
	de_byte b[20];
	de_read(b, 0, (de_int64)sizeof(b));

	if(b[0]==0xc5 && b[1]==0xd0 && b[2]==0xd3 && b[3]==0xc6)
		return 100;

	if(!de_memcmp(b, "%!PS-Adobe-", 11) &&
		!de_memcmp(&b[14], " EPSF-", 6) )
	{
		return 100;
	}

	return 0;
}

void de_module_eps(deark *c, struct deark_module_info *mi)
{
	mi->id = "eps";
	mi->desc = "Encapsulated PostScript";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_eps;
	mi->identify_fn = de_identify_eps;
}
