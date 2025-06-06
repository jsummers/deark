// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Netpbm formats
// PNM (PBM, PGM, PPM)
// PAM

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pnm);

// Numbers 1-6 are assumed to match the "Px" number in the file signature.
#define FMT_PBM_ASCII    1
#define FMT_PGM_ASCII    2
#define FMT_PPM_ASCII    3
#define FMT_PBM_BINARY   4
#define FMT_PGM_BINARY   5
#define FMT_PPM_BINARY   6
#define FMT_PAM          7

struct page_ctx {
	int fmt;
	const char *fmt_name;
	i64 width, height;
	int maxval;

	int pam_depth; // = samples per pixel
#define PAMSUBTYPE_GRAY         1
#define PAMSUBTYPE_RGB          2
	int pam_subtype;
	int has_alpha;

	i64 hdr_parse_pos;
	i64 image_data_len;
};

typedef struct localctx_struct {
	int last_fmt;
	i64 last_bytesused;
} lctx;

static int fmt_is_pbm(int fmt)
{
	return (fmt==FMT_PBM_ASCII || fmt==FMT_PBM_BINARY);
}

static int fmt_is_ppm(int fmt)
{
	return (fmt==FMT_PPM_ASCII || fmt==FMT_PPM_BINARY);
}

static int fmt_is_binary(int fmt)
{
	return (fmt==FMT_PBM_BINARY || fmt==FMT_PGM_BINARY ||
		fmt==FMT_PPM_BINARY || fmt==FMT_PAM);
}

static int is_pnm_whitespace(u8 b)
{
	// Whitespace = space, CR, LF, TAB, VT, or FF
	return (b==9 || b==10 || b==11 || b==12 || b==13 || b==32);
}

static int read_next_token(deark *c, lctx *d, struct page_ctx *pg,
	char *tokenbuf, size_t tokenbuflen)
{
	u8 b;
	size_t token_len = 0;
	int in_comment = 0;

	token_len = 0;
	while(1) {
		if(pg->hdr_parse_pos >= c->infile->len) return 0;

		if(token_len >= tokenbuflen) {
			return 0; // Token too long.
		}

		b = de_getbyte_p(&pg->hdr_parse_pos);

		if(in_comment) {
			if(b==10 || b==13) {
				in_comment = 0;
			}
			continue;
		}
		else if(b=='#') {
			in_comment = 1;
			continue;
		}
		else if(is_pnm_whitespace(b)) {
			if(token_len>0) {
				tokenbuf[token_len] = '\0';
				return 1;
			}
			else {
				continue; // Skip leading whitespace.
			}
		}
		else {
			// Append the character to the token.
			tokenbuf[token_len] = (char)b;
			token_len++;
		}
	}

	return 0;
}

static int read_pnm_header(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	char tokenbuf[100];
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	de_dbg(c, "format: %s", pg->fmt_name);
	pg->hdr_parse_pos = pos1+2; // Skip "P?"

	if(!read_next_token(c, d, pg, tokenbuf, sizeof(tokenbuf))) goto done;
	pg->width = de_atoi64(tokenbuf);
	if(!read_next_token(c, d, pg, tokenbuf, sizeof(tokenbuf))) goto done;
	pg->height = de_atoi64(tokenbuf);
	de_dbg_dimensions(c, pg->width, pg->height);

	if(fmt_is_pbm(pg->fmt)) {
		pg->maxval = 1;
	}
	else {
		if(!read_next_token(c, d, pg, tokenbuf, sizeof(tokenbuf))) goto done;
		pg->maxval = de_atoi(tokenbuf);
		de_dbg(c, "maxval: %d", pg->maxval);
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

// Read a token from a NUL-terminated string.
static int read_next_pam_token(deark *c, lctx *d, struct page_ctx *pg,
	const char *linebuf, size_t linebuflen,
	char *tokenbuf, size_t tokenbuflen, i64 *curpos)
{
	u8 b;
	i64 token_len = 0;
	i64 linepos;

	token_len = 0;

	linepos = *curpos;
	while(1) {
		if(token_len >= (i64)tokenbuflen) {
			// Token too long.
			return 0;
		}

		if(linepos >= (i64)linebuflen) {
			return 0;
		}
		b = linebuf[linepos++];
		if(b==0) break; // End of line

		if(is_pnm_whitespace(b)) {
			if(token_len>0) {
				break;
			}
			else {
				continue; // Skip leading whitespace.
			}
		}
		else {
			// Append the character to the token.
			tokenbuf[token_len++] = b;
		}
	}

	tokenbuf[token_len] = '\0';
	*curpos = linepos;
	return 1;
}

static int read_pam_header_line(deark *c, lctx *d, struct page_ctx *pg, i64 pos,
	i64 *content_len, i64 *total_len,
	char *linebuf, size_t linebuf_len)
{
	int ret;
	i64 amt_to_read;

	linebuf[0]='\0';

	ret = dbuf_find_line(c->infile, pos,
		content_len, total_len);

	if(!ret) return 0;

	amt_to_read = *content_len;
	if(amt_to_read > (i64)(linebuf_len-1)) amt_to_read = (i64)(linebuf_len-1);

	de_read((u8*)linebuf, pos, amt_to_read);

	*content_len = amt_to_read;
	linebuf[amt_to_read] = '\0';
	return 1;
}

static int read_pam_header(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	int ret;
	i64 pos = pos1;
	int retval = 0;
	int tupltype_line_count = 0;
	char linebuf[200];
	char token1buf[200];
	char token2buf[200];

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pos += 3; // Skip "P7\n"

	while(1) {
		i64 content_len;
		i64 total_len;
		i64 curpos;

		ret = read_pam_header_line(c, d, pg, pos, &content_len, &total_len,
			linebuf, sizeof(linebuf));
		pos += total_len;

		if(!ret) {
			de_err(c, "Invalid PAM header");
			goto done;
		}

		if(content_len>0 && (de_getbyte(pos)=='#')) {
			// comment line
			pos += total_len;
			continue;
		}

		curpos = 0;
		if(!read_next_pam_token(c, d, pg, linebuf, sizeof(linebuf),
			token1buf, sizeof(token1buf), &curpos))
		{
			goto done;
		}

		if(!de_strcmp(token1buf, "ENDHDR")) {
			break;
		}

		// Other header lines have a param
		if(!read_next_pam_token(c, d, pg, linebuf, sizeof(linebuf),
			token2buf, sizeof(token2buf), &curpos))
		{
			goto done;
		}

		if(!de_strcmp(token1buf, "WIDTH")) {
			pg->width = de_atoi64(token2buf);
		}
		else if(!de_strcmp(token1buf, "HEIGHT")) {
			pg->height = de_atoi64(token2buf);
		}
		else if(!de_strcmp(token1buf, "DEPTH")) {
			pg->pam_depth = de_atoi(token2buf);
		}
		else if(!de_strcmp(token1buf, "MAXVAL")) {
			pg->maxval = de_atoi(token2buf);
		}
		else if(!de_strcmp(token1buf, "TUPLTYPE")) {
			// FIXME: The "TUPLTYPE" line(s) is wacky, and seems underspecified.
			// We do not support it correctly.
			// But I doubt any real PAM encoders are pathological enough to
			// require us to support its wackiness.
			if(tupltype_line_count>0) {
				de_err(c, "Multiple TUPLTYPE lines are not supported");
				goto done;
			}
			tupltype_line_count++;

			if(!de_strcmp(token2buf, "BLACKANDWHITE")) {
				pg->pam_subtype = PAMSUBTYPE_GRAY;
				pg->maxval = 1;
			}
			else if(!de_strcmp(token2buf, "BLACKANDWHITE_ALPHA")) {
				pg->pam_subtype = PAMSUBTYPE_GRAY;
				pg->has_alpha = 1;
				pg->maxval = 1;
			}
			else if(!de_strcmp(token2buf, "GRAYSCALE")) {
				pg->pam_subtype = PAMSUBTYPE_GRAY;
			}
			else if(!de_strcmp(token2buf, "GRAYSCALE_ALPHA")) {
				pg->pam_subtype = PAMSUBTYPE_GRAY;
				pg->has_alpha = 1;
			}
			else if(!de_strcmp(token2buf, "RGB")) {
				pg->pam_subtype = PAMSUBTYPE_RGB;
			}
			else if(!de_strcmp(token2buf, "RGB_ALPHA")) {
				pg->pam_subtype = PAMSUBTYPE_RGB;
				pg->has_alpha = 1;
			}
			else {
				de_err(c, "Unsupported color type");
				goto done;
			}
		}
	}

	if(tupltype_line_count==0) {
		// The TUPLTYPE field is technically optional, but the image is not
		// portable without it.
		switch(pg->pam_depth) {
		case 1:
			pg->pam_subtype = PAMSUBTYPE_GRAY;
			break;
		case 2:
			pg->pam_subtype = PAMSUBTYPE_GRAY;
			pg->has_alpha = 1;
			break;
		case 3:
			pg->pam_subtype = PAMSUBTYPE_RGB;
			break;
		case 4:
			pg->pam_subtype = PAMSUBTYPE_RGB;
			pg->has_alpha = 1;
			break;
		}

		if(pg->pam_subtype!=0) {
			de_warn(c, "Color type not specified. Attempting to guess.");
		}
	}

	pg->hdr_parse_pos = pos;
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_image_pbm_ascii(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	de_bitmap *img = NULL;
	i64 xpos, ypos;
	i64 pos = pos1;
	u8 b;
	u8 v;

	img = de_bitmap_create(c, pg->width, pg->height, 1);

	xpos=0; ypos=0;
	while(1) {
		if(pos >= c->infile->len) break; // end of file
		if(ypos==(pg->height-1) && xpos>=pg->width) break; // end of image
		if(ypos>=pg->height) break;

		b = de_getbyte_p(&pos);
		if(b=='1') v=0;
		else if(b=='0') v=255;
		else continue;

		de_bitmap_setpixel_gray(img, xpos, ypos, v);
		xpos++;
		if(xpos>=pg->width) {
			ypos++;
			xpos=0;
		}
	}

	de_bitmap_write_to_file_finfo(img, NULL, DE_CREATEFLAG_IS_BWIMG);
	de_bitmap_destroy(img);
	return 1;
}

static int do_image_pgm_ppm_pam_binary(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, i64 pos1);

struct pgm_ppm_ascii_ctx {
	u8 intermed_nbytes_per_sample;
	i64 sample_count;
	dbuf *intermed_img;
	size_t samplebuf_used;
	char samplebuf[32];
};

static void pgm_ppm_ascii_handle_sample(struct pgm_ppm_ascii_ctx *actx)
{
	i64 v;

	actx->samplebuf[actx->samplebuf_used] = '\0'; // NUL terminate for de_atoi64()
	v = de_atoi64((const char*)actx->samplebuf);
	actx->samplebuf_used = 0;

	if(actx->intermed_nbytes_per_sample==1) {
		dbuf_writebyte(actx->intermed_img, (u8)v);
	}
	else {
		dbuf_writeu16be(actx->intermed_img, v);
	}

	actx->sample_count++;
}

// Convert the ASCII image data to binary, then call the function to process
// that binary data.
static int do_image_pgm_ppm_ascii(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	int nsamples_per_pixel;
	i64 nsamples_per_image;
	i64 intermed_nbytes_per_image;
	i64 pos = pos1;
	int retval = 0;
	struct pgm_ppm_ascii_ctx actx;

	de_zeromem(&actx, sizeof(struct pgm_ppm_ascii_ctx));
	if(fmt_is_ppm(pg->fmt)) nsamples_per_pixel = 3;
	else nsamples_per_pixel = 1;

	nsamples_per_image = (i64)nsamples_per_pixel * pg->height * pg->width;
	actx.intermed_nbytes_per_sample = (pg->maxval>255) ? 2 : 1;
	intermed_nbytes_per_image = nsamples_per_image * (i64)actx.intermed_nbytes_per_sample;

	actx.intermed_img = dbuf_create_membuf(c, intermed_nbytes_per_image, 0x1);
	actx.samplebuf_used=0;

	actx.sample_count = 0;

	while(1) {
		u8 b;

		if(actx.sample_count >= nsamples_per_image) break;
		if(pos >= c->infile->len) { // end of file
			if(actx.samplebuf_used>0) {
				pgm_ppm_ascii_handle_sample(&actx);
			}
			break;
		}

		b = de_getbyte_p(&pos);
		if(is_pnm_whitespace(b)) {
			if(actx.samplebuf_used>0) {
				// Completed a sample
				pgm_ppm_ascii_handle_sample(&actx);
			}
			else { // Skip extra whitespace
				continue;
			}
		}
		else {
			// Non-whitespace. Save for later.
			if(actx.samplebuf_used < sizeof(actx.samplebuf_used)-1) {
				actx.samplebuf[actx.samplebuf_used++] = b;
			}
		}
	}

	retval = do_image_pgm_ppm_pam_binary(c, d, pg, actx.intermed_img, 0);
	dbuf_close(actx.intermed_img);
	return retval;
}

static int do_image_pbm_binary(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	i64 rowspan;

	rowspan = (pg->width+7)/8;
	pg->image_data_len = rowspan * pg->height;

	de_convert_and_write_image_bilevel2(c->infile, pos1, pg->width, pg->height,
		rowspan, DE_CVTF_WHITEISZERO, NULL, 0);
	return 1;
}

static int do_image_pgm_ppm_pam_binary(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, i64 pos1)
{
	de_bitmap *img = NULL;
	de_bitmap *imglo = NULL;
	i64 rowspan;
	int nsamples_per_pixel; // For both input and output
	u8 nbytes_per_sample;
	i64 i, j;
	i64 pos = pos1;
	UI samp_ori[4];
	u8 samp_adj[4]; // most significant 8 bits
	u8 samp_adj_lo[4];
	u32 clr;
	int retval = 0;

	de_zeromem(samp_adj_lo, sizeof(samp_adj_lo));

	if(pg->fmt==FMT_PAM) {
		nsamples_per_pixel = pg->pam_depth;

		if((pg->pam_subtype==PAMSUBTYPE_GRAY && !pg->has_alpha && nsamples_per_pixel==1) ||
			(pg->pam_subtype==PAMSUBTYPE_GRAY && pg->has_alpha && nsamples_per_pixel==2) ||
			(pg->pam_subtype==PAMSUBTYPE_RGB && !pg->has_alpha && nsamples_per_pixel==3) ||
			(pg->pam_subtype==PAMSUBTYPE_RGB && pg->has_alpha && nsamples_per_pixel==4))
		{
			;
		}
		else {
			de_err(c, "Unsupported PAM format");
			goto done;
		}
	}
	else if(fmt_is_ppm(pg->fmt)) {
		nsamples_per_pixel = 3;
	}
	else {
		nsamples_per_pixel = 1;
	}

	if(nsamples_per_pixel<1 || nsamples_per_pixel>4) {
		de_err(c, "Unsupported samples/pixel: %d", nsamples_per_pixel);
	}

	if(pg->maxval<=255) nbytes_per_sample = 1;
	else nbytes_per_sample = 2;

	rowspan = pg->width * (i64)nsamples_per_pixel * (i64)nbytes_per_sample;
	pg->image_data_len = rowspan * pg->height;

	img = de_bitmap_create(c, pg->width, pg->height, nsamples_per_pixel);
	if(nbytes_per_sample!=1) {
		imglo = de_bitmap_create(c, pg->width, pg->height, nsamples_per_pixel);
	}

	for(j=0; j<pg->height; j++) {
		for(i=0; i<pg->width; i++) {
			int k;

			for(k=0; k<nsamples_per_pixel; k++) {
				if(nbytes_per_sample==1) {
					samp_ori[k] = dbuf_getbyte_p(inf, &pos);
				}
				else {
					samp_ori[k] = (UI)dbuf_getu16be_p(inf, &pos);
				}

				if(nbytes_per_sample==1) {
					samp_adj[k] = de_scale_n_to_255(pg->maxval, samp_ori[k]);
				}
				else {
					de_scale_n_to_16bit(pg->maxval, (int)samp_ori[k], &samp_adj[k], &samp_adj_lo[k]);
				}
			}

			switch(nsamples_per_pixel) {
			case 4:
				clr = DE_MAKE_RGBA(samp_adj[0], samp_adj[1], samp_adj[2], samp_adj[3]);
				de_bitmap_setpixel_rgba(img, i, j, clr);
				if(imglo) {
					clr = DE_MAKE_RGBA(samp_adj_lo[0], samp_adj_lo[1], samp_adj_lo[2], samp_adj_lo[3]);
					de_bitmap_setpixel_rgba(imglo, i, j, clr);
				}
				break;
			case 3:
				clr = DE_MAKE_RGB(samp_adj[0], samp_adj[1], samp_adj[2]);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				if(imglo) {
					clr = DE_MAKE_RGB(samp_adj_lo[0], samp_adj_lo[1], samp_adj_lo[2]);
					de_bitmap_setpixel_rgb(imglo, i, j, clr);
				}
				break;
			case 2:
				clr = DE_MAKE_RGBA(samp_adj[0], samp_adj[0], samp_adj[0], samp_adj[1]);
				de_bitmap_setpixel_rgba(img, i, j, clr);
				if(imglo) {
					clr = DE_MAKE_RGBA(samp_adj_lo[0], samp_adj_lo[0], samp_adj_lo[0], samp_adj_lo[1]);
					de_bitmap_setpixel_rgba(imglo, i, j, clr);
				}
				break;
			default: // Assuming nsamples==1
				de_bitmap_setpixel_gray(img, i, j, samp_adj[0]);
				if(imglo) {
					de_bitmap_setpixel_gray(imglo, i, j, samp_adj_lo[0]);
				}
			}
		}
	}

	de_bitmap16_write_to_file_finfo(img, imglo, NULL, DE_CREATEFLAG_OPT_IMAGE);
	retval = 1;

done:
	de_bitmap_destroy(img);
	de_bitmap_destroy(imglo);
	return retval;
}

static int do_image(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	int retval = 0;

	de_dbg(c, "image data at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(pg->maxval<1 || pg->maxval>65535) {
		de_err(c, "Invalid maxval: %d", pg->maxval);
		goto done;
	}
	if(!de_good_image_dimensions(c, pg->width, pg->height)) goto done;

	switch(pg->fmt) {
	case FMT_PBM_ASCII:
		if(!do_image_pbm_ascii(c, d, pg, pos1)) goto done;
		break;
	case FMT_PGM_ASCII:
	case FMT_PPM_ASCII:
		if(!do_image_pgm_ppm_ascii(c, d, pg, pos1)) goto done;
		break;
	case FMT_PBM_BINARY:
		if(!do_image_pbm_binary(c, d, pg, pos1)) goto done;
		break;
	case FMT_PGM_BINARY:
	case FMT_PPM_BINARY:
	case FMT_PAM:
		if(!do_image_pgm_ppm_pam_binary(c, d, pg, c->infile, pos1)) goto done;
		break;
	default:
		de_err(c, "Unsupported PNM format");
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int identify_fmt(deark *c, i64 pos)
{
	u8 buf[3];

	de_read(buf, pos, 3);
	if(buf[0]!='P') return 0;

	if(buf[1]=='7' && buf[2]==0x0a)
		return FMT_PAM;
	if(buf[1]>='1' && buf[1]<='6') {
		if(buf[2]==9 || buf[2]==10 || buf[2]==13 || buf[2]==32) {
			return (int)buf[1] - '0';
		}
	}
	return 0;
}

static const char *get_fmt_name(int fmt)
{
	const char *name="unknown";
	switch(fmt) {
	case FMT_PBM_ASCII: name="PBM plain"; break;
	case FMT_PGM_ASCII: name="PGM plain"; break;
	case FMT_PPM_ASCII: name="PPM plain"; break;
	case FMT_PBM_BINARY: name="PBM"; break;
	case FMT_PGM_BINARY: name="PGM"; break;
	case FMT_PPM_BINARY: name="PPM"; break;
	case FMT_PAM: name="PAM"; break;
	}
	return name;
}

static int do_page(deark *c, lctx *d, int pagenum, i64 pos1)
{
	struct page_ctx *pg = NULL;
	int retval = 0;

	de_dbg(c, "image at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	pg = de_malloc(c, sizeof(struct page_ctx));

	pg->fmt = identify_fmt(c, pos1);
	d->last_fmt = pg->fmt;
	pg->fmt_name = get_fmt_name(pg->fmt);
	if(pg->fmt==0) {
		de_err(c, "Not PNM/PAM format");
		goto done;
	}

	if(pagenum==0) {
		de_declare_fmt(c, pg->fmt_name);
	}

	if(pg->fmt==FMT_PAM) {
		if(!read_pam_header(c, d, pg, pos1)) goto done;
	}
	else {
		if(!read_pnm_header(c, d, pg, pos1)) goto done;
	}

	if(!do_image(c, d, pg, pg->hdr_parse_pos)) {
		goto done;
	}

	d->last_bytesused = (pg->hdr_parse_pos + pg->image_data_len) - pos1;

	retval = 1;
done:
	de_dbg_indent(c, -1);
	de_free(c, pg);
	return retval;
}

static void de_run_pnm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	int ret;
	int pagenum = 0;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	while(1) {
		if(c->infile->len - pos < 8) break;
		d->last_fmt = 0;
		d->last_bytesused = 0;
		ret = do_page(c, d, pagenum, pos);
		if(!ret) break;
		if(d->last_bytesused<8) break;

		if(!fmt_is_binary(d->last_fmt))
		{
			break; // ASCII formats don't support multiple images
		}

		pos += d->last_bytesused;
		pagenum++;
	}

	de_free(c, d);
}

static int de_identify_pnm(deark *c)
{
	int fmt;

	fmt = identify_fmt(c, 0);
	if(fmt!=0) return 40;
	return 0;
}

void de_module_pnm(deark *c, struct deark_module_info *mi)
{
	mi->id = "pnm";
	mi->desc = "Netpbm formats (PNM, PBM, PGM, PPM, PAM)";
	mi->run_fn = de_run_pnm;
	mi->identify_fn = de_identify_pnm;
}
