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
	i64 maxval;

	i64 pam_num_samples;
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
	// Whitspace = space, CR, LF, TAB, VT, or FF
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

		b = de_getbyte(pg->hdr_parse_pos++);

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

	de_dbg(c, "header at %d", (int)pos1);
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
		pg->maxval = de_atoi64(tokenbuf);
		de_dbg(c, "maxval: %d", (int)pg->maxval);
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

	de_dbg(c, "header at %d", (int)pos1);
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
			pg->pam_num_samples = de_atoi64(token2buf);
		}
		else if(!de_strcmp(token1buf, "MAXVAL")) {
			pg->maxval = de_atoi64(token2buf);
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
		switch(pg->pam_num_samples) {
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

		b = de_getbyte(pos++);
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

	de_bitmap_write_to_file_finfo(img, NULL, 0);
	de_bitmap_destroy(img);
	return 1;
}

static int do_image_pgm_ppm_ascii(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	de_bitmap *img = NULL;
	i64 nsamples; // For both input and output
	i64 pos = pos1;
	i64 xpos, ypos, sampidx;
	char samplebuf[32];
	size_t samplebuf_used;
	u8 b;

	if(fmt_is_ppm(pg->fmt)) nsamples=3;
	else nsamples=1;

	img = de_bitmap_create(c, pg->width, pg->height, (int)nsamples);

	xpos=0; ypos=0;
	sampidx=0;
	samplebuf_used=0;

	while(1) {
		if(pos >= c->infile->len) break; // end of file
		if(ypos==(pg->height-1) && xpos>=pg->width) break; // end of image
		if(ypos>=pg->height) break;

		b = de_getbyte(pos++);
		if(is_pnm_whitespace(b)) {
			if(samplebuf_used>0) {
				i64 v;
				u8 v_adj;

				// Completed a sample
				samplebuf[samplebuf_used] = '\0'; // NUL terminate for de_atoi64()
				v = de_atoi64((const char*)samplebuf);
				v_adj = de_scale_n_to_255(pg->maxval, v);
				samplebuf_used = 0;

				if(nsamples>1) {
					de_bitmap_setsample(img, xpos, ypos, sampidx, v_adj);
				}
				else {
					de_bitmap_setpixel_gray(img, xpos, ypos, v_adj);
				}

				sampidx++;
				if(sampidx>=nsamples) {
					sampidx=0;
					xpos++;
					if(xpos>=pg->width) {
						xpos=0;
						ypos++;
					}
				}

			}
			else { // Skip extra whitespace
				continue;
			}
		}
		else {
			// Non-whitespace. Save for later.
			if(samplebuf_used < sizeof(samplebuf_used)-1) {
				samplebuf[samplebuf_used++] = b;
			}
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
	return 1;
}

static int do_image_pbm_binary(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	i64 rowspan;

	rowspan = (pg->width+7)/8;
	pg->image_data_len = rowspan * pg->height;

	de_convert_and_write_image_bilevel(c->infile, pos1, pg->width, pg->height,
		rowspan, DE_CVTF_WHITEISZERO, NULL, 0);
	return 1;
}

static int do_image_pgm_ppm_pam_binary(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	de_bitmap *img = NULL;
	i64 rowspan;
	i64 nsamples; // For both input and output
	i64 bytes_per_sample;
	i64 i, j, k;
	i64 pos = pos1;
	unsigned int samp_ori[4];
	u8 samp_adj[4];
	u32 clr;
	int retval = 0;

	if(pg->fmt==FMT_PAM) {
		nsamples = pg->pam_num_samples;

		if((pg->pam_subtype==PAMSUBTYPE_GRAY && !pg->has_alpha && nsamples==1) ||
			(pg->pam_subtype==PAMSUBTYPE_GRAY && pg->has_alpha && nsamples==2) ||
			(pg->pam_subtype==PAMSUBTYPE_RGB && !pg->has_alpha && nsamples==3) ||
			(pg->pam_subtype==PAMSUBTYPE_RGB && pg->has_alpha && nsamples==4))
		{
			;
		}
		else {
			de_err(c, "Unsupported PAM format");
			goto done;
		}
	}
	else if(fmt_is_ppm(pg->fmt)) {
		nsamples=3;
	}
	else {
		nsamples=1;
	}

	if(nsamples<1 || nsamples>4) {
		de_err(c, "Unsupported number of samples: %d", (int)nsamples);
	}

	if(pg->maxval<=255) bytes_per_sample=1;
	else bytes_per_sample=2;

	rowspan = pg->width * nsamples * bytes_per_sample;
	pg->image_data_len = rowspan * pg->height;

	img = de_bitmap_create(c, pg->width, pg->height, (int)nsamples);

	for(j=0; j<pg->height; j++) {
		for(i=0; i<pg->width; i++) {
			for(k=0; k<nsamples; k++) {
				if(bytes_per_sample==1) {
					samp_ori[k] = de_getbyte(pos++);
				}
				else {
					samp_ori[k] = (unsigned int)de_getbyte(pos++) << 8 ;
					samp_ori[k] |= (unsigned int)de_getbyte(pos++);
				}

				samp_adj[k] = de_scale_n_to_255(pg->maxval, samp_ori[k]);
			}

			switch(nsamples) {
			case 4:
				clr = DE_MAKE_RGBA(samp_adj[0], samp_adj[1], samp_adj[2], samp_adj[3]);
				de_bitmap_setpixel_rgba(img, i, j, clr);
				break;
			case 3:
				clr = DE_MAKE_RGB(samp_adj[0], samp_adj[1], samp_adj[2]);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				break;
			case 2:
				clr = DE_MAKE_RGBA(samp_adj[0], samp_adj[0], samp_adj[0], samp_adj[1]);
				de_bitmap_setpixel_rgba(img, i, j, clr);
				break;
			default: // Assuming nsamples==1
				de_bitmap_setpixel_gray(img, i, j, samp_adj[0]);
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	retval = 1;

done:
	de_bitmap_destroy(img);
	return retval;
}

static int do_image(deark *c, lctx *d, struct page_ctx *pg, i64 pos1)
{
	int retval = 0;

	de_dbg(c, "image data at %d", (int)pos1);
	de_dbg_indent(c, 1);

	if(pg->maxval<1 || pg->maxval>65535) {
		de_err(c, "Invalid maxval: %d", (int)pg->maxval);
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
		if(!do_image_pgm_ppm_pam_binary(c, d, pg, pos1)) goto done;
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
	if(buf[1]>='1' && buf[1]<='6')
		return buf[1] - '0';
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

	de_dbg(c, "image at %d", (int)pos1);
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
