// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// GEM VDI Bit Image / Gem Raster

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 w, h;
	de_int64 patlen;
	de_int64 rowspan;
	de_int64 pixwidth, pixheight;
	de_byte *pattern_buf;
} lctx;

static void uncompress_line(deark *c, lctx *d, dbuf *unc_line,
	de_int64 pos1, de_int64 rownum,
	de_int64 *bytes_consumed, de_int64 *repeat_count)
{
	de_int64 pos;
	de_byte b0, b1;
	de_byte val;
	de_int64 count;
	de_int64 k;

	*bytes_consumed = 0;
	*repeat_count = 1;
	pos = pos1;
	dbuf_empty(unc_line);

	while(1) {
		if(pos >= c->infile->len) break;
		if(unc_line->len >= d->rowspan) break;

		b0 = de_getbyte(pos++);
		
		if(b0==0) { // Pattern run or scanline run
			b1 = de_getbyte(pos++);
			if(b1>0) { // pattern run
				de_read(d->pattern_buf, pos, d->patlen);
				pos += d->patlen;
				count = (de_int64)b1;
				for(k=0; k<count; k++) {
					dbuf_write(unc_line, d->pattern_buf, d->patlen);
				}
			}
			else { // (b1==0) scanline run
				de_byte flagbyte;
				flagbyte = de_getbyte(pos);
				if(flagbyte==0xff) {
					pos++;
					*repeat_count = (de_int64)de_getbyte(pos++);
					if(*repeat_count == 0) {
						de_dbg(c, "row %d: bad repeat count\n", (int)rownum);
						*repeat_count = 1;
					}

				}
				else {
					de_dbg(c, "row %d: bad scanline run marker: 0x%02x\n",
						(int)rownum, (unsigned int)flagbyte);
				}
			}
		}
		else if(b0==0x80) { // "Uncompressed bit string"
			count = (de_int64)de_getbyte(pos++);
			dbuf_copy(c->infile, pos, count, unc_line);
			pos += count;
		}
		else { // "solid run"
			val = (b0&0x80) ? 0xff : 0x00;
			count = (de_int64)(b0 & 0x7f);
			dbuf_write_run(unc_line, val, count);
		}
	}

	*bytes_consumed = pos - pos1;
}

static void uncompress_pixels(deark *c, lctx *d, dbuf *unc_pixels,
	de_int64 pos1, de_int64 len)
{
	de_int64 bytes_consumed;
	de_int64 pos;
	de_int64 ypos;
	de_int64 repeat_count;
	de_int64 k;
	dbuf *unc_line = NULL;

	d->pattern_buf = de_malloc(c, d->patlen);
	unc_line = dbuf_create_membuf(c, d->rowspan);

	pos = pos1;

	ypos = 0;
	while(1) {
		if(ypos >= d->h) break;

		uncompress_line(c, d, unc_line, pos, ypos, &bytes_consumed, &repeat_count);
		pos+=bytes_consumed;
		if(bytes_consumed<1) break;

		for(k=0; k<repeat_count; k++) {
			if(ypos >= d->h) break;
			dbuf_copy(unc_line, 0, d->rowspan, unc_pixels);
			ypos++;
		}
	}

	dbuf_close(unc_line);
	de_free(c, d->pattern_buf);
	d->pattern_buf = NULL;
}

static void de_run_gemraster(deark *c, const char *params)
{
	de_int64 header_size_in_words;
	de_int64 header_size_in_bytes;
	de_int64 nplanes;
	de_int64 ver;
	lctx *d = NULL;
	dbuf *unc_pixels = NULL;
	struct deark_bitmap *img = NULL;

	d = de_malloc(c, sizeof(lctx));
	ver = de_getui16be(0);
	de_dbg(c, "version: %d\n", (int)ver);
	header_size_in_words = de_getui16be(2);
	header_size_in_bytes = header_size_in_words*2;
	de_dbg(c, "header size: %d words (%d bytes)\n", (int)header_size_in_words,
		(int)header_size_in_bytes);
	nplanes = de_getui16be(4);
	de_dbg(c, "planes: %d\n", (int)nplanes);
	if(header_size_in_words!=0x08 || nplanes!=1) {
		de_err(c, "This version of GEM Raster is not supported.\n");
		return;
	}

	d->patlen = de_getui16be(6);
	d->pixwidth = de_getui16be(8);
	d->pixheight = de_getui16be(10);
	de_dbg(c, "pixel size: %dx%d microns\n", (int)d->pixwidth, (int)d->pixheight);
	d->w = de_getui16be(12);
	d->h = de_getui16be(14);
	de_dbg(c, "dimension: %dx%d\n", (int)d->w, (int)d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	d->rowspan = (d->w+7)/8;

	unc_pixels = dbuf_create_membuf(c, d->rowspan*d->h);

	uncompress_pixels(c, d, unc_pixels, header_size_in_bytes, c->infile->len-header_size_in_bytes);

	img = de_bitmap_create(c, d->w, d->h, 1);

	if(d->pixwidth>0 && d->pixheight>0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = 25400.0/(double)d->pixwidth;
		img->ydens = 25400.0/(double)d->pixheight;
	}
	de_convert_image_bilevel(unc_pixels, 0, d->rowspan, img, DE_CVTF_WHITEISZERO);
	de_bitmap_write_to_file_finfo(img, NULL);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	de_free(c, d);
}

static int de_identify_gemraster(deark *c)
{
	de_int64 ver, x2;
	de_int64 nplanes;

	if(!de_input_file_has_ext(c, "img") &&
		!de_input_file_has_ext(c, "ximg"))
	{
		return 0;
	}
	ver = de_getui16be(0);
	if(ver!=1 && ver!=2) return 0;
	x2 = de_getui16be(2);
	if(x2<0x0008 || x2>0x0800) return 0;
	nplanes = de_getui16be(4);
	if(nplanes!=1 && nplanes!=4 && nplanes!=8) return 0;
	if(ver==1 && x2==0x08) return 70;
	if(x2>=0x3b) {
		if(!dbuf_memcmp(c->infile, 16, "XIMG", 4)) {
			if(x2==0x3b) return 100;
			return 70;
		}
	}
	if(ver!=1) return 0;
	return 10;
}

void de_module_gemraster(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemraster";
	mi->run_fn = de_run_gemraster;
	mi->identify_fn = de_identify_gemraster;
}
