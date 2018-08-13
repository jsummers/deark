// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This file is for miscellaneous formats that are easy to support.
// Combining them in one file speeds up compilation and development time.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_copy);
DE_DECLARE_MODULE(de_module_null);
DE_DECLARE_MODULE(de_module_cp437);
DE_DECLARE_MODULE(de_module_crc32);
DE_DECLARE_MODULE(de_module_zlib);
DE_DECLARE_MODULE(de_module_sauce);
DE_DECLARE_MODULE(de_module_hpicn);
DE_DECLARE_MODULE(de_module_xpuzzle);
DE_DECLARE_MODULE(de_module_winzle);
DE_DECLARE_MODULE(de_module_mrw);
DE_DECLARE_MODULE(de_module_bob);
DE_DECLARE_MODULE(de_module_alias_pix);
DE_DECLARE_MODULE(de_module_applevol);
DE_DECLARE_MODULE(de_module_hr);
DE_DECLARE_MODULE(de_module_ripicon);
DE_DECLARE_MODULE(de_module_lss16);
DE_DECLARE_MODULE(de_module_vbm);
DE_DECLARE_MODULE(de_module_fp_art);
DE_DECLARE_MODULE(de_module_ybm);
DE_DECLARE_MODULE(de_module_olpc565);
DE_DECLARE_MODULE(de_module_iim);
DE_DECLARE_MODULE(de_module_pm_xv);
DE_DECLARE_MODULE(de_module_crg);
DE_DECLARE_MODULE(de_module_farbfeld);
DE_DECLARE_MODULE(de_module_vgafont);
DE_DECLARE_MODULE(de_module_hsiraw);
DE_DECLARE_MODULE(de_module_qdv);
DE_DECLARE_MODULE(de_module_vitec);
DE_DECLARE_MODULE(de_module_hs2);
DE_DECLARE_MODULE(de_module_lumena_cel);
DE_DECLARE_MODULE(de_module_zbr);

// **************************************************************************
// "copy" module
//
// This is a trivial module that makes a copy of the input file.
// **************************************************************************

static void de_run_copy(deark *c, de_module_params *mparams)
{
	dbuf_create_file_from_slice(c->infile, 0, c->infile->len, "bin", NULL, 0);
}

void de_module_copy(deark *c, struct deark_module_info *mi)
{
	mi->id = "copy";
	mi->desc = "Copy the file unchanged";
	mi->run_fn = de_run_copy;
	mi->identify_fn = de_identify_none;
}

// **************************************************************************
// "null" module
//
// This is a trivial module that does nothing.
// **************************************************************************

static void de_run_null(deark *c, de_module_params *mparams)
{
	;
}

void de_module_null(deark *c, struct deark_module_info *mi)
{
	mi->id = "null";
	mi->desc = "Do nothing";
	mi->run_fn = de_run_null;
	mi->identify_fn = de_identify_none;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// CP437
// Convert CP437 text files to UTF-8.
// **************************************************************************

static void de_run_cp437(deark *c, de_module_params *mparams)
{
	de_int32 u;
	de_int64 i;
	de_byte ch;
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "txt", NULL, 0);

	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(outf, 0xfeff);
	}

	for(i=0; i<c->infile->len; i++) {
		ch = de_getbyte(i);
		if(ch==0x09 || ch==0x0a || ch==0x0c || ch==0x0d) {
			// Leave HT, NL, FF, CR as-is.
			u = (de_int32)ch;
		}
		else if(ch==0x1a) {
			// Lots of CP437 files end with a Ctrl+Z character, but modern files
			// don't use any in-band character to signify end-of-file.
			// I don't just want to delete the character, though, so I guess I'll
			// change it to U+2404 SYMBOL FOR END OF TRANSMISSION.
			u = 0x2404;
		}
		else {
			u = de_char_to_unicode(c, (de_int32)ch, DE_ENCODING_CP437_G);
		}
		dbuf_write_uchar_as_utf8(outf, u);
	}

	dbuf_close(outf);
}

void de_module_cp437(deark *c, struct deark_module_info *mi)
{
	mi->id = "cp437";
	mi->desc = "Code Page 437 text";
	mi->run_fn = de_run_cp437;
	mi->identify_fn = de_identify_none;
}

// **************************************************************************
// CRC-32
// Prints the CRC-32. Does not create any files.
// **************************************************************************

static void de_run_crc32(deark *c, de_module_params *mparams)
{
#define CRC32BUFSIZE 2048
	de_byte buf[CRC32BUFSIZE];
	de_int64 bytestoread;
	de_int64 pos = 0;
	de_uint32 crc;

	crc = de_crc32(NULL, 0);

	while(pos<c->infile->len) {
		bytestoread = CRC32BUFSIZE;
		if(bytestoread > c->infile->len - pos) {
			bytestoread = c->infile->len - pos;
		}

		de_read(buf, pos, bytestoread);
		crc = de_crc32_continue(crc, buf, bytestoread);
		pos += bytestoread;
	}
	de_printf(c, DE_MSGTYPE_MESSAGE, "CRC-32: 0x%08x\n", (unsigned int)crc);
}

void de_module_crc32(deark *c, struct deark_module_info *mi)
{
	mi->id = "crc32";
	mi->desc = "Calculate the IEEE CRC-32";
	mi->run_fn = de_run_crc32;
	mi->identify_fn = de_identify_none;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// zlib module
//
// This module is for decompressing zlib-compressed files.
// It uses the deark-miniz.c utilities, which in turn use miniz.c (miniz.h).
// **************************************************************************

static void de_run_zlib(deark *c, de_module_params *mparams)
{
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "unc", NULL, 0);
	de_uncompress_zlib(c->infile, 0, c->infile->len, f);
	dbuf_close(f);
}

static int de_identify_zlib(deark *c)
{
	de_byte b[2];
	de_read(b, 0, 2);

	if((b[0]&0x0f) != 8)
		return 0;

	if(b[0]<0x08 || b[0]>0x78)
		return 0;

	if(((((unsigned int)b[0])<<8)|b[1])%31 != 0)
		return 0;

	return 50;
}

void de_module_zlib(deark *c, struct deark_module_info *mi)
{
	mi->id = "zlib";
	mi->desc = "Raw zlib compressed data";
	mi->run_fn = de_run_zlib;
	mi->identify_fn = de_identify_zlib;
}

// **************************************************************************
// SAUCE
// Special module that reads SAUCE metadata for other modules to use,
// and handles files with SAUCE records if they aren't otherwise handled.
// **************************************************************************

static void de_run_sauce(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si = NULL;
	int ret;

	si = de_malloc(c, sizeof(struct de_SAUCE_info));
	ret = de_read_SAUCE(c, c->infile, si);
	if(ret && c->module_disposition==DE_MODDISP_AUTODETECT) {
		de_err(c, "This file has a SAUCE metadata record that identifies it as "
			"DataType %d, FileType %d, but it is not a supported format.",
			(int)si->data_type, (int)si->file_type);
	}
	if(!ret && c->module_disposition==DE_MODDISP_EXPLICIT) {
		de_err(c, "No SAUCE record found");
	}
	de_free_SAUCE(c, si);
}

static int de_identify_sauce(deark *c)
{
	if(de_detect_SAUCE(c, c->infile, &c->detection_data.sauce)) {
		// This module should have a very low priority, but other modules can use
		// the results of its detection.
		return 2;
	}
	return 0;
}

void de_module_sauce(deark *c, struct deark_module_info *mi)
{
	mi->id = "sauce";
	mi->desc = "SAUCE metadata";
	mi->run_fn = de_run_sauce;
	mi->identify_fn = de_identify_sauce;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// HP 100LX / HP 200LX .ICN icon format
// **************************************************************************

static void de_run_hpicn(deark *c, de_module_params *mparams)
{
	de_int64 width, height;

	width = de_getui16le(4);
	height = de_getui16le(6);
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, (width+7)/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

static int de_identify_hpicn(deark *c)
{
	de_byte b[8];
	de_read(b, 0, 8);
	if(!de_memcmp(b, "\x01\x00\x01\x00\x2c\x00\x20\x00", 8))
		return 100;
	if(!de_memcmp(b, "\x01\x00\x01\x00", 4))
		return 60;
	return 0;
}

void de_module_hpicn(deark *c, struct deark_module_info *mi)
{
	mi->id = "hpicn";
	mi->desc = "HP 100LX/200LX .ICN icon";
	mi->run_fn = de_run_hpicn;
	mi->identify_fn = de_identify_hpicn;
}

// **************************************************************************
// X11 "puzzle" format
// ftp://ftp.x.org/pub/unsupported/programs/puzzle/
// This is the format generated by Netpbm's ppmtopuzz utility.
// **************************************************************************

struct xpuzzctx {
	de_int64 w, h;
	de_int64 palentries;
};

static int xpuzz_read_header(deark *c, struct xpuzzctx *d)
{
	d->w = de_getui32be(0);
	d->h = de_getui32be(4);
	d->palentries = (de_int64)de_getbyte(8);
	if(!de_good_image_dimensions_noerr(c, d->w, d->h)) return 0;
	if(d->palentries==0) d->palentries = 256;
	return 1;
}

static void de_run_xpuzzle(deark *c, de_module_params *mparams)
{
	struct xpuzzctx *d = NULL;
	de_bitmap *img = NULL;
	de_uint32 pal[256];
	de_int64 p;

	d = de_malloc(c, sizeof(struct xpuzzctx));
	if(!xpuzz_read_header(c, d)) goto done;
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	img = de_bitmap_create(c, d->w, d->h, 3);

	// Read the palette
	de_memset(pal, 0, sizeof(pal));
	p = 9;
	de_read_palette_rgb(c->infile, p, d->palentries, 3, pal, 256, 0);
	p += 3*d->palentries;

	// Read the bitmap
	de_convert_image_paletted(c->infile, p, 8, d->w, pal, img, 0);

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_free(c, d);
}

static int de_identify_xpuzzle(deark *c)
{
	struct xpuzzctx *d = NULL;
	int retval = 0;

	d = de_malloc(c, sizeof(struct xpuzzctx));

	if(!xpuzz_read_header(c, d)) goto done;

	if(d->w * d->h + 3*d->palentries + 9 == c->infile->len) {
		retval = 20;
	}

done:
	de_free(c, d);
	return retval;
}

void de_module_xpuzzle(deark *c, struct deark_module_info *mi)
{
	mi->id = "xpuzzle";
	mi->desc = "X11 \"puzzle\" image";
	mi->run_fn = de_run_xpuzzle;
	mi->identify_fn = de_identify_xpuzzle;
}

// **************************************************************************
// Winzle! puzzle image
// **************************************************************************

static void de_run_winzle(deark *c, de_module_params *mparams)
{
	de_byte buf[256];
	de_int64 xorsize;
	de_int64 i;
	dbuf *f = NULL;

	xorsize = c->infile->len >= 256 ? 256 : c->infile->len;
	de_read(buf, 0, xorsize);
	for(i=0; i<xorsize; i++) {
		buf[i] ^= 0x0d;
	}

	f = dbuf_create_output_file(c, "bmp", NULL, 0);
	dbuf_write(f, buf, xorsize);
	if(c->infile->len > 256) {
		dbuf_copy(c->infile, 256, c->infile->len - 256, f);
	}
	dbuf_close(f);
}

static int de_identify_winzle(deark *c)
{
	de_byte b[18];
	de_read(b, 0, sizeof(b));

	if(b[0]==0x4f && b[1]==0x40) {
		if(b[14]==0x25 && b[15]==0x0d && b[16]==0x0d && b[17]==0x0d) {
			return 95;
		}
		return 40;
	}
	return 0;
}

void de_module_winzle(deark *c, struct deark_module_info *mi)
{
	mi->id = "winzle";
	mi->desc = "Winzle! puzzle image";
	mi->run_fn = de_run_winzle;
	mi->identify_fn = de_identify_winzle;
}

// **************************************************************************
// Minolta RAW (MRW)
// **************************************************************************

static void do_mrw_seg_list(deark *c, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_byte seg_id[4];
	de_int64 data_len;

	pos = pos1;
	while(pos < pos1+len) {
		de_read(seg_id, pos, 4);
		data_len = de_getui32be(pos+4);
		pos+=8;
		if(pos+data_len > pos1+len) break;
		if(!de_memcmp(seg_id, "\0TTW", 4)) { // Exif
			de_fmtutil_handle_exif(c, pos, data_len);
		}
		pos+=data_len;
	}
}

static void de_run_mrw(deark *c, de_module_params *mparams)
{
	de_int64 mrw_seg_size;

	mrw_seg_size = de_getui32be(4);
	do_mrw_seg_list(c, 8, mrw_seg_size);
}

static int de_identify_mrw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x4d\x52\x4d", 4))
		return 100;
	return 0;
}

void de_module_mrw(deark *c, struct deark_module_info *mi)
{
	mi->id = "mrw";
	mi->desc = "Minolta RAW";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_mrw;
	mi->identify_fn = de_identify_mrw;
}

// **************************************************************************
// "Bob" bitmap image
// Used by the Bob ray tracer.
// **************************************************************************

static void de_run_bob(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 w, h;
	de_uint32 pal[256];
	de_int64 p;

	w = de_getui16le(0);
	h = de_getui16le(2);
	if(!de_good_image_dimensions(c, w, h)) goto done;
	img = de_bitmap_create(c, w, h, 3);

	// Read the palette
	de_memset(pal, 0, sizeof(pal));
	p = 4;
	de_read_palette_rgb(c->infile, p, 256, 3, pal, 256, 0);
	p += 256*3;

	// Read the bitmap
	de_convert_image_paletted(c->infile, p, 8, w, pal, img, 0);

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_bob(deark *c)
{
	de_int64 w, h;

	if(!de_input_file_has_ext(c, "bob")) return 0;

	w = de_getui16le(0);
	h = de_getui16le(2);
	if(c->infile->len == 4 + 768 + w*h) {
		return 100;
	}
	return 0;
}

void de_module_bob(deark *c, struct deark_module_info *mi)
{
	mi->id = "bob";
	mi->desc = "Bob Ray Tracer bitmap image";
	mi->run_fn = de_run_bob;
	mi->identify_fn = de_identify_bob;
}

// **************************************************************************
// Alias PIX bitmap image.
// Also used by the Vivid ray tracer.
// **************************************************************************

static void de_run_alias_pix(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 w, h;
	de_int64 i;
	de_int64 pos;
	de_int64 firstline;
	de_int64 depth;
	de_int64 xpos, ypos;
	de_int64 runlen;
	de_uint32 clr;

	w = de_getui16be(0);
	h = de_getui16be(2);
	firstline = de_getui16be(4);
	depth = de_getui16be(8);

	if(!de_good_image_dimensions(c, w, h)) goto done;
	if(firstline >= h) goto done;
	if(depth!=24) {
		de_err(c, "Unsupported image type");
		goto done;
	}

	img = de_bitmap_create(c, w, h, 3);

	pos = 10;
	xpos = 0;
	// I don't know for sure what to do with the "first scanline" field, in the
	// unlikely event it is not 0. The documentation doesn't say.
	ypos = firstline;
	while(1) {
		if(pos+4 > c->infile->len) {
			break; // EOF
		}
		runlen = (de_int64)de_getbyte(pos);
		clr = dbuf_getRGB(c->infile, pos+1, DE_GETRGBFLAG_BGR);
		pos+=4;

		for(i=0; i<runlen; i++) {
			de_bitmap_setpixel_rgb(img, xpos, ypos, clr);
			xpos++; // Runs are not allowed to span rows
		}

		if(xpos >= w) {
			xpos=0;
			ypos++;
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_bitmap_destroy(img);
}

static int de_identify_alias_pix(deark *c)
{
	de_int64 w, h, firstline, lastline, depth;

	if(!de_input_file_has_ext(c, "img") &&
		!de_input_file_has_ext(c, "als") &&
		!de_input_file_has_ext(c, "pix"))
	{
		return 0;
	}

	w = de_getui16be(0);
	h = de_getui16be(2);
	firstline = de_getui16be(4);
	lastline = de_getui16be(6);
	depth = de_getui16be(8);

	if(depth!=24) return 0;
	if(firstline>lastline) return 0;
	// 'lastline' should usually be h-1, but XnView apparently sets it to h.
	if(firstline>h-1 || lastline>h) return 0;
	if(!de_good_image_dimensions_noerr(c, w, h)) return 0;
	return 30;
}

void de_module_alias_pix(deark *c, struct deark_module_info *mi)
{
	mi->id = "alias_pix";
	mi->id_alias[0] = "vivid";
	mi->desc = "Alias PIX image, Vivid .IMG";
	mi->run_fn = de_run_alias_pix;
	mi->identify_fn = de_identify_alias_pix;
}

// **************************************************************************
// Apple volume label image
// Written by netpbm: ppmtoapplevol
// **************************************************************************

static de_byte applevol_get_gray_shade(de_byte clr)
{
	switch(clr) {
		// TODO: These gray shades may not be quite right. I can't find good
		// information about them.
	case 0x00: return 0xff;
	case 0xf6: return 0xee;
	case 0xf7: return 0xdd;
	case 0x2a: return 0xcc;
	case 0xf8: return 0xbb;
	case 0xf9: return 0xaa;
	case 0x55: return 0x99;
	case 0xfa: return 0x88;
	case 0xfb: return 0x77;
	case 0x80: return 0x66;
	case 0xfc: return 0x55;
	case 0xfd: return 0x44;
	case 0xab: return 0x33;
	case 0xfe: return 0x22;
	case 0xff: return 0x11;
	case 0xd6: return 0x00;
	}
	return 0xff;
}

static void de_run_applevol(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 w, h;
	de_int64 i, j;
	de_int64 p;
	de_byte palent;

	w = de_getui16be(1);
	h = de_getui16be(3);
	if(!de_good_image_dimensions(c, w, h)) goto done;
	img = de_bitmap_create(c, w, h, 1);

	p = 5;
	for(j=0; j<h; j++) {
		for(i=0; i<w; i++) {
			palent = de_getbyte(p+w*j+i);
			de_bitmap_setpixel_gray(img, i, j, applevol_get_gray_shade(palent));
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_applevol(deark *c)
{
	de_byte buf[5];

	de_read(buf, 0, sizeof(buf));

	if(buf[0]==0x01 && buf[3]==0x00 && buf[4]==0x0c)
		return 20;
	return 0;
}

void de_module_applevol(deark *c, struct deark_module_info *mi)
{
	mi->id = "applevol";
	mi->desc = "Apple volume label image";
	mi->run_fn = de_run_applevol;
	mi->identify_fn = de_identify_applevol;
}

// **************************************************************************
// TRS-80 "HR" ("High Resolution") image
// **************************************************************************

static void de_run_hr(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, 640, 240, 1);
	img->density_code = DE_DENSITY_UNK_UNITS;
	img->xdens = 2;
	img->ydens = 1;
	de_convert_image_bilevel(c->infile, 0, 640/8, img, 0);
	de_bitmap_write_to_file_finfo(img, NULL, 0);
	de_bitmap_destroy(img);
}

static int de_identify_hr(deark *c)
{
	if(de_input_file_has_ext(c, "hr")) {
		if(c->infile->len==19200) return 70;
		if(c->infile->len>19200 && c->infile->len<=19456) return 30;
	}
	return 0;
}

void de_module_hr(deark *c, struct deark_module_info *mi)
{
	mi->id = "hr";
	mi->desc = "TRS-80 HR (High Resolution) image";
	mi->run_fn = de_run_hr;
	mi->identify_fn = de_identify_hr;
}

// **************************************************************************
// RIPterm icon (.ICN)
// **************************************************************************

static void de_run_ripicon(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 chunk_span;
	de_int64 src_rowspan;
	de_int64 i, j, k;
	de_byte x;
	de_uint32 palent;

	width = 1 + de_getui16le(0);
	height = 1 + de_getui16le(2);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) goto done;

	img = de_bitmap_create(c, width, height, 3);
	chunk_span = (width+7)/8;
	src_rowspan = 4*chunk_span;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			palent = 0;
			for(k=0; k<4; k++) {
				x = de_get_bits_symbol(c->infile, 1, 4 + j*src_rowspan + k*chunk_span, i);
				palent = (palent<<1)|x;
			}
			de_bitmap_setpixel_rgb(img, i, j, de_palette_pc16(palent));
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_bitmap_destroy(img);
}

static int de_identify_ripicon(deark *c)
{
	de_byte buf[4];
	de_int64 expected_size;
	de_int64 width, height;

	if(!de_input_file_has_ext(c, "icn")) return 0;
	de_read(buf, 0, sizeof(buf));
	width = 1 + de_getui16le(0);
	height = 1 + de_getui16le(2);
	expected_size = 4 + height*(4*((width+7)/8)) + 1;
	if(c->infile->len >= expected_size && c->infile->len <= expected_size+1) {
		return 50;
	}
	return 0;
}

void de_module_ripicon(deark *c, struct deark_module_info *mi)
{
	mi->id = "ripicon";
	mi->desc = "RIP/RIPscrip/RIPterm Icon";
	mi->run_fn = de_run_ripicon;
	mi->identify_fn = de_identify_ripicon;
}

// **************************************************************************
// LSS16 image (Used by SYSLINUX)
// **************************************************************************

struct lss16ctx {
	de_int64 pos;
	int nextnibble_valid;
	de_byte nextnibble;
};

static de_byte lss16_get_nibble(deark *c, struct lss16ctx *d)
{
	de_byte n;
	if(d->nextnibble_valid) {
		d->nextnibble_valid = 0;
		return d->nextnibble;
	}
	n = de_getbyte(d->pos);
	d->pos++;
	// The low nibble of each byte is interpreted first.
	// Record the high nibble, and return the low nibble.
	d->nextnibble = (n&0xf0)>>4;
	d->nextnibble_valid = 1;
	return n&0x0f;
}

static void de_run_lss16(deark *c, de_module_params *mparams)
{
	struct lss16ctx *d = NULL;
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 i;
	de_int64 xpos, ypos;
	de_byte n;
	de_byte prev;
	de_int64 run_len;
	de_byte cr1, cg1, cb1;
	de_byte cr2, cg2, cb2;
	de_uint32 pal[16];
	char tmps[64];

	d = de_malloc(c, sizeof(struct lss16ctx));

	d->pos = 4;
	width = de_getui16le(d->pos);
	height = de_getui16le(d->pos+2);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) goto done;

	d->pos += 4;
	for(i=0; i<16; i++) {
		cr1 = de_getbyte(d->pos);
		cg1 = de_getbyte(d->pos+1);
		cb1 = de_getbyte(d->pos+2);
		// Palette samples are from [0 to 63]. Convert to [0 to 255].
		cr2 = de_scale_63_to_255(cr1);
		cg2 = de_scale_63_to_255(cg1);
		cb2 = de_scale_63_to_255(cb1);
		pal[i] = DE_MAKE_RGB(cr2, cg2, cb2);
		de_snprintf(tmps, sizeof(tmps), "(%2d,%2d,%2d) "DE_CHAR_RIGHTARROW" ",
			(int)cr1, (int)cg1, (int)cb1);
		de_dbg_pal_entry2(c, i, pal[i], tmps, NULL, NULL);
		d->pos+=3;
	}

	img = de_bitmap_create(c, width, height, 3);

	xpos=0; ypos=0;
	prev=0;
	while(d->pos<c->infile->len && ypos<height) {
		n = lss16_get_nibble(c, d);

		if(n == prev) {
			// A run of pixels
			run_len = (de_int64)lss16_get_nibble(c, d);
			if(run_len==0) {
				run_len = lss16_get_nibble(c, d) | (lss16_get_nibble(c, d)<<4);
				run_len += 16;
			}
			for(i=0; i<run_len; i++) {
				de_bitmap_setpixel_rgb(img, xpos, ypos, pal[prev]);
				xpos++;
			}
		}
		else {
			// An uncompressed pixel
			de_bitmap_setpixel_rgb(img, xpos, ypos, pal[n]);
			xpos++;
			prev = n;
		}

		// End of row reached?
		if(xpos>=width) {
			xpos=0;
			ypos++;
			d->nextnibble_valid = 0;
			prev = 0;
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_bitmap_destroy(img);
	de_free(c, d);
}

static int de_identify_lss16(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x3d\xf3\x13\x14", 4))
		return 100;
	return 0;
}

void de_module_lss16(deark *c, struct deark_module_info *mi)
{
	mi->id = "lss16";
	mi->desc = "SYSLINUX LSS16 image";
	mi->run_fn = de_run_lss16;
	mi->identify_fn = de_identify_lss16;
}

// **************************************************************************
// VBM (VDC BitMap)
// **************************************************************************

static void de_run_vbm(deark *c, de_module_params *mparams)
{
	de_int64 width, height;
	de_byte ver;

	ver = de_getbyte(3);
	if(ver!=2) {
		// TODO: Support VBM v3.
		de_err(c, "Unsupported VBM version (%d)", (int)ver);
		return;
	}
	width = de_getui16be(4);
	height = de_getui16be(6);
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, (width+7)/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

// Note that this function must work together with de_identify_bmp().
static int de_identify_vbm(deark *c)
{
	de_byte b[4];
	de_read(b, 0, 4);
	if(de_memcmp(b, "BM\xcb", 3)) return 0;
	if(b[3]!=2 && b[3]!=3) return 0;
	if(de_input_file_has_ext(c, "vbm")) return 100;
	return 80;
}

void de_module_vbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "vbm";
	mi->desc = "C64/128 VBM (VDC BitMap)";
	mi->run_fn = de_run_vbm;
	mi->identify_fn = de_identify_vbm;
}

// **************************************************************************
// PFS: 1st Publisher clip art (.ART)
// **************************************************************************

static void de_run_fp_art(deark *c, de_module_params *mparams)
{
	de_int64 width, height;
	de_int64 rowspan;

	width = de_getui16le(2);
	height = de_getui16le(6);
	rowspan = ((width+15)/16)*2;
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, rowspan, 0, NULL, 0);
}

static int de_identify_fp_art(deark *c)
{
	de_int64 width, height;
	de_int64 rowspan;

	if(!de_input_file_has_ext(c, "art")) return 0;

	width = de_getui16le(2);
	height = de_getui16le(6);
	rowspan = ((width+15)/16)*2;
	if(8 + rowspan*height == c->infile->len) {
		return 100;
	}

	return 0;
}

void de_module_fp_art(deark *c, struct deark_module_info *mi)
{
	mi->id = "fp_art";
	mi->desc = "PFS: 1st Publisher clip art (.ART)";
	mi->run_fn = de_run_fp_art;
	mi->identify_fn = de_identify_fp_art;
}

// **************************************************************************
// YBM
// **************************************************************************

static void de_run_ybm(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 i, j;
	de_int64 rowspan;
	de_byte x;

	width = de_getui16be(2);
	height = de_getui16be(4);
	if(!de_good_image_dimensions(c, width, height)) goto done;;
	rowspan = ((width+15)/16)*2;

	img = de_bitmap_create(c, width, height, 1);

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			// This encoding is unusual: LSB-first 16-bit integers.
			x = de_get_bits_symbol(c->infile, 1, 6 + j*rowspan,
				(i-i%16) + (15-i%16));
			de_bitmap_setpixel_gray(img, i, j, x ? 0 : 255);
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_ybm(deark *c)
{
	de_int64 width, height;
	de_int64 rowspan;

	if(dbuf_memcmp(c->infile, 0, "!!", 2))
		return 0;
	width = de_getui16be(2);
	height = de_getui16be(4);
	rowspan = ((width+15)/16)*2;
	if(6+height*rowspan == c->infile->len)
		return 100;
	return 0;
}

void de_module_ybm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ybm";
	mi->desc = "Bennet Yee's face format, a.k.a. YBM";
	mi->run_fn = de_run_ybm;
	mi->identify_fn = de_identify_ybm;
}

// **************************************************************************
// OLPC .565 firmware icon
// **************************************************************************

static void de_run_olpc565(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 i, j;
	de_int64 rowspan;
	de_byte b0, b1;
	de_uint32 clr;

	width = de_getui16le(4);
	height = de_getui16le(6);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	rowspan = width*2;

	img = de_bitmap_create(c, width, height, 3);

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			b0 = de_getbyte(8 + j*rowspan + i*2);
			b1 = de_getbyte(8 + j*rowspan + i*2 + 1);
			clr = (((de_uint32)b1)<<8) | b0;
			clr = de_rgb565_to_888(clr);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_olpc565(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "C565", 4))
		return 100;
	return 0;
}

void de_module_olpc565(deark *c, struct deark_module_info *mi)
{
	mi->id = "olpc565";
	mi->desc = "OLPC .565 firmware icon";
	mi->run_fn = de_run_olpc565;
	mi->identify_fn = de_identify_olpc565;
}

// **************************************************************************
// InShape .IIM
// **************************************************************************

static void de_run_iim(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 i, j;
	de_int64 n, bpp;
	de_int64 rowspan;
	de_uint32 clr;

	// This code is based on reverse engineering, and may be incorrect.

	n = de_getui16be(8); // Unknown field
	bpp = de_getui16be(10);
	if(n!=4 || bpp!=24) {
		de_dbg(c, "This type of IIM image is not supported");
		goto done;
	}
	width = de_getui16be(12);
	height = de_getui16be(14);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	rowspan = width*3;

	img = de_bitmap_create(c, width, height, 3);

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			clr = dbuf_getRGB(c->infile, 16+j*rowspan+i*3, 0);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_iim(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "IS_IMAGE", 8))
		return 100;
	return 0;
}

void de_module_iim(deark *c, struct deark_module_info *mi)
{
	mi->id = "iim";
	mi->desc = "InShape IIM";
	mi->run_fn = de_run_iim;
	mi->identify_fn = de_identify_iim;
}

// **************************************************************************
// PM (format supported by the XV image viewer)
// **************************************************************************

static void de_run_pm_xv(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	int is_le;
	de_int64 width, height;
	de_int64 nplanes;
	de_int64 nbands;
	de_int64 pixelformat;
	de_int64 commentsize;
	de_int64 i, j;
	de_int64 plane;
	de_int64 rowspan;
	de_int64 planespan;
	de_int64 pos;
	de_byte b;

	if(!dbuf_memcmp(c->infile, 0, "WEIV", 4))
		is_le = 1;
	else
		is_le = 0;

	nplanes = dbuf_geti32x(c->infile, 4, is_le);
	de_dbg(c, "planes: %d", (int)nplanes);

	height = dbuf_geti32x(c->infile, 8, is_le);
	width = dbuf_geti32x(c->infile, 12, is_le);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) goto done;

	nbands = dbuf_geti32x(c->infile, 16, is_le);
	de_dbg(c, "bands: %d", (int)nbands);

	pixelformat = dbuf_geti32x(c->infile, 20, is_le);
	de_dbg(c, "pixel format: 0x%04x", (unsigned int)pixelformat);

	commentsize = dbuf_geti32x(c->infile, 24, is_le);
	de_dbg(c, "comment size: %d", (int)commentsize);

	pos = 28;

	if((pixelformat==0x8001 && nplanes==3 && nbands==1) ||
		(pixelformat==0x8001 && nplanes==1 && nbands==1))
	{
		;
	}
	else {
		de_err(c, "Unsupported image type (pixel format=0x%04x, "
			"planes=%d, bands=%d)", (unsigned int)pixelformat,
			(int)nplanes, (int)nbands);
		goto done;
	}

	rowspan = width;
	planespan = rowspan*height;

	img = de_bitmap_create(c, width, height, (int)nplanes);

	for(plane=0; plane<nplanes; plane++) {
		for(j=0; j<height; j++) {
			for(i=0; i<width; i++) {
				b = de_getbyte(pos + plane*planespan + j*rowspan + i);
				if(nplanes==3) {
					de_bitmap_setsample(img, i, j, plane, b);
				}
				else {
					de_bitmap_setpixel_gray(img, i, j, b);
				}
			}
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_pm_xv(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "VIEW", 4))
		return 15;
	if(!dbuf_memcmp(c->infile, 0, "WEIV", 4))
		return 15;
	return 0;
}

void de_module_pm_xv(deark *c, struct deark_module_info *mi)
{
	mi->id = "pm_xv";
	mi->desc = "PM (XV)";
	mi->run_fn = de_run_pm_xv;
	mi->identify_fn = de_identify_pm_xv;
}

// **************************************************************************
// Calamus Raster Graphic - CRG
// **************************************************************************

// Warning: The CRG decoder is based on reverse engineering, may not be
// correct, and is definitely incomplete.

static void de_run_crg(deark *c, de_module_params *mparams)
{
	de_int64 width, height;
	de_int64 rowspan;
	de_int64 pos;
	de_byte b1, b2;
	de_int64 count;
	de_int64 cmpr_img_start;
	de_int64 num_cmpr_bytes;
	dbuf *unc_pixels = NULL;

	width = de_getui32be(20);
	height = de_getui32be(24);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) goto done;

	b1 = de_getbyte(32);
	if(b1!=0x01) {
		de_err(c, "Unsupported CRG format");
		goto done;
	}

	num_cmpr_bytes = de_getui32be(38);
	de_dbg(c, "compressed data size: %d", (int)num_cmpr_bytes);
	cmpr_img_start = 42;

	if(cmpr_img_start + num_cmpr_bytes > c->infile->len) {
		num_cmpr_bytes = c->infile->len - cmpr_img_start;
	}

	// Uncompress the image
	rowspan = (width+7)/8;
	unc_pixels = dbuf_create_membuf(c, height*rowspan, 1);

	pos = cmpr_img_start;
	while(pos < cmpr_img_start + num_cmpr_bytes) {
		b1 = de_getbyte(pos++);
		if(b1<=0x7f) { // Uncompressed bytes
			count = 1+(de_int64)b1;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
		else { // A compressed run
			b2 = de_getbyte(pos++);
			count = (de_int64)(b1-127);
			dbuf_write_run(unc_pixels, b2, count);
		}
	}
	de_dbg(c, "decompressed to %d bytes", (int)unc_pixels->len);

	de_convert_and_write_image_bilevel(unc_pixels, 0, width, height, rowspan,
		DE_CVTF_WHITEISZERO, NULL, 0);

done:
	dbuf_close(unc_pixels);
}

static int de_identify_crg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "CALAMUSCRG", 10))
		return 100;
	return 0;
}

void de_module_crg(deark *c, struct deark_module_info *mi)
{
	mi->id = "crg";
	mi->desc = "Calamus Raster Graphic";
	mi->run_fn = de_run_crg;
	mi->identify_fn = de_identify_crg;
}

// **************************************************************************
// farbfeld
// **************************************************************************

static void de_run_farbfeld(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	de_int64 width, height;
	de_int64 i, j, k;
	de_int64 ppos;
	de_byte s[4];

	width = de_getui32be(8);
	height = de_getui32be(12);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) return;

	img = de_bitmap_create(c, width, height, 4);

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			ppos = 16 + 8*(width*j + i);
			for(k=0; k<4; k++) {
				s[k] = de_getbyte(ppos+2*k);
			}
			de_bitmap_setpixel_rgba(img, i, j,
				DE_MAKE_RGBA(s[0],s[1],s[2],s[3]));
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static int de_identify_farbfeld(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "farbfeld", 8))
		return 100;
	return 0;
}

void de_module_farbfeld(deark *c, struct deark_module_info *mi)
{
	mi->id = "farbfeld";
	mi->desc = "farbfeld image";
	mi->run_fn = de_run_farbfeld;
	mi->identify_fn = de_identify_farbfeld;
}

// **************************************************************************
// VGA font (intended for development/debugging use)
// **************************************************************************

static void de_run_vgafont(deark *c, de_module_params *mparams)
{
	de_byte *fontdata = NULL;
	struct de_bitmap_font *font = NULL;
	de_int64 i;
	de_int64 height;

	if(c->infile->len==16*256) {
		height = 16;
	}
	else if(c->infile->len==14*256) {
		height = 14;
	}
	else {
		de_err(c, "Bad file size");
		goto done;
	}

	fontdata = de_malloc(c, height*256);
	de_read(fontdata, 0, height*256);

	if(de_get_ext_option(c, "vgafont:c")) {
		dbuf *ff;
		ff = dbuf_create_output_file(c, "h", NULL, 0);
		for(i=0; i<(height*256); i++) {
			if(i%height==0) dbuf_puts(ff, "\t");
			dbuf_printf(ff, "%d", (int)fontdata[i]);
			if(i!=(height*256-1)) dbuf_puts(ff, ",");
			if(i%height==(height-1)) dbuf_puts(ff, "\n");
		}
		dbuf_close(ff);
		goto done;
	}

	font = de_create_bitmap_font(c);
	font->num_chars = 256;
	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints = 0;
	font->prefer_unicode = 0;
	font->nominal_width = 8;
	font->nominal_height = (int)height;
	font->char_array = de_malloc(c, font->num_chars * sizeof(struct de_bitmap_font_char));

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].codepoint_nonunicode = (de_int32)i;
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = 1;
		font->char_array[i].bitmap = &fontdata[i*font->nominal_height];
	}

	de_font_bitmap_font_to_image(c, font, NULL, 0);

done:
	if(font) {
		de_free(c, font->char_array);
		de_destroy_bitmap_font(c, font);
	}
	de_free(c, fontdata);
}

static void de_help_vgafont(deark *c)
{
	de_msg(c, "-opt vgafont:c : Emit C code");
}

void de_module_vgafont(deark *c, struct deark_module_info *mi)
{
	mi->id = "vgafont";
	mi->desc = "Raw 8x16 or 8x14 VGA font";
	mi->run_fn = de_run_vgafont;
	mi->identify_fn = de_identify_none;
	mi->help_fn = de_help_vgafont;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// HSI Raw image format (from Image Alchemy / Handmade Software)
// **************************************************************************

static void convert_image_rgb(dbuf *f, de_int64 fpos,
	de_int64 rowspan, de_int64 pixelspan,
	de_bitmap *img, unsigned int flags)
{
	de_int64 i, j;
	de_int32 clr;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			clr = dbuf_getRGB(f, fpos + j*rowspan + i*pixelspan, flags);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void de_run_hsiraw(deark *c, de_module_params *mparams)
{
	de_int64 w, h;
	de_int64 num_pal_colors;
	de_int64 pos;
	de_int64 ver;
	de_int64 hdpi, vdpi;
	de_int64 cmpr;
	de_int64 alpha_info;
	de_bitmap *img = NULL;
	de_uint32 pal[256];
	int is_grayscale;

	ver = de_getui16be(6);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=4) {
		de_warn(c, "HSI Raw version %d might not be supported correctly", (int)ver);
	}

	w = de_getui16be(8);
	if(w==0) {
		// MPlayer extension?
		de_dbg2(c, "reading 32-bit width");
		w = de_getui32be(28);
	}
	h = de_getui16be(10);
	de_dbg_dimensions(c, w, h);
	num_pal_colors = de_getui16be(12);
	de_dbg(c, "number of palette colors: %d", (int)num_pal_colors);

	hdpi = de_geti16be(14);
	vdpi = de_geti16be(16);
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d", (int)hdpi, (int)vdpi);
	// [18: Gamma]
	cmpr = de_getui16be(20);
	de_dbg(c, "compression: %d", (int)cmpr);
	alpha_info = de_getui16be(22);
	de_dbg(c, "alpha: %d", (int)alpha_info);

	if(num_pal_colors>256 || cmpr!=0 || alpha_info!=0) {
		de_err(c, "This type of HSI Raw image is not supported");
		goto done;
	}
	if(!de_good_image_dimensions(c, w, h)) goto done;

	pos = 32;
	de_memset(pal, 0, sizeof(pal));
	if(num_pal_colors==0) { // 24-bit RGB
		is_grayscale = 0;
	}
	else { // 8-bit paletted
		de_read_palette_rgb(c->infile, pos, num_pal_colors, 3, pal, 256, 0);
		pos += 3*num_pal_colors;
		is_grayscale = de_is_grayscale_palette(pal, num_pal_colors);
	}

	img = de_bitmap_create(c, w, h, is_grayscale?1:3);

	if(num_pal_colors==0) {
		convert_image_rgb(c->infile, pos, 3*w, 3, img, 0);
	}
	else {
		de_convert_image_paletted(c->infile, pos, 8, w, pal, img, 0);
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_hsiraw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "mhwanh", 6))
		return 100;
	return 0;
}

void de_module_hsiraw(deark *c, struct deark_module_info *mi)
{
	mi->id = "hsiraw";
	mi->desc = "HSI Raw";
	mi->run_fn = de_run_hsiraw;
	mi->identify_fn = de_identify_hsiraw;
}

// **************************************************************************
// QDV (Giffer)
// **************************************************************************

static void de_run_qdv(deark *c, de_module_params *mparams)
{
	de_int64 w, h;
	de_int64 num_pal_colors;
	de_int64 pos;
	de_bitmap *img = NULL;
	de_uint32 pal[256];

	// Warning: This decoder is based on reverse engineering, and may be
	// incorrect or incomplete.

	w = de_getui16be(0);
	h = de_getui16be(2);
	de_dbg_dimensions(c, w, h);
	if(!de_good_image_dimensions(c, w, h)) goto done;

	num_pal_colors = 1 + (de_int64)de_getbyte(4);
	de_dbg(c, "number of palette colors: %d", (int)num_pal_colors);

	pos = 5;
	de_memset(pal, 0, sizeof(pal));
	de_read_palette_rgb(c->infile, pos, num_pal_colors, 3, pal, 256, 0);
	pos += 3*num_pal_colors;

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(c->infile, pos, 8, w, pal, img, 0);
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_qdv(deark *c)
{
	de_int64 w, h;
	de_int64 num_pal_colors;

	w = de_getui16be(0);
	h = de_getui16be(2);
	num_pal_colors = 1 + (de_int64)de_getbyte(4);
	if(5+num_pal_colors*3+w*h != c->infile->len)
		return 0;
	if(de_input_file_has_ext(c, "qdv"))
		return 100;
	return 30;
}

void de_module_qdv(deark *c, struct deark_module_info *mi)
{
	mi->id = "qdv";
	mi->desc = "QDV (Giffer)";
	mi->run_fn = de_run_qdv;
	mi->identify_fn = de_identify_qdv;
}

// **************************************************************************
// VITec image format
// **************************************************************************

static void de_run_vitec(deark *c, de_module_params *mparams)
{
	de_int64 w, h;
	de_int64 i, j, plane;
	de_bitmap *img = NULL;
	de_int64 samplesperpixel;
	de_int64 rowspan, planespan;
	de_int64 pos;
	de_byte b;
	de_int64 h1size, h2size;
	int saved_indent_level;

	// This code is based on reverse engineering, and may be incorrect.

	de_dbg_indent_save(c, &saved_indent_level);
	de_warn(c, "VITec image support is experimental, and may not work correctly.");

	pos = 4;
	h1size = de_getui32be(pos);
	de_dbg(c, "header 1 at %d, len=%d", (int)pos, (int)h1size);
	// Don't know what's in this part of the header. Just ignore it.
	pos += h1size;
	if(pos>=c->infile->len) goto done;

	h2size = de_getui32be(pos);
	de_dbg(c, "header 2 at %d, len=%d", (int)pos, (int)h2size);
	de_dbg_indent(c, 1);

	// pos+4: Bits size?
	// pos+24: Unknown field, usually 7

	w = de_getui32be(pos+36);
	h = de_getui32be(pos+40);
	de_dbg_dimensions(c, w, h);
	if(!de_good_image_dimensions(c, w, h)) goto done;

	// pos+52: Unknown field, 1 in grayscale images

	samplesperpixel = de_getui32be(pos+56);
	de_dbg(c, "samples/pixel: %d", (int)samplesperpixel);
	if(samplesperpixel!=1 && samplesperpixel!=3) {
		de_err(c, "Unsupported samples/pixel: %d", (int)samplesperpixel);
		goto done;
	}

	pos += h2size;
	if(pos>=c->infile->len) goto done;
	de_dbg_indent(c, -1);

	de_dbg(c, "bitmap at %d", (int)pos);
	img = de_bitmap_create(c, w, h, (int)samplesperpixel);
	rowspan = ((w+7)/8)*8;
	planespan = rowspan*h;

	for(plane=0; plane<samplesperpixel; plane++) {
		for(j=0; j<h; j++) {
			for(i=0; i<w; i++) {
				b = de_getbyte(pos + plane*planespan + j*rowspan + i);
				if(samplesperpixel==3) {
					de_bitmap_setsample(img, i, j, plane, b);
				}
				else {
					de_bitmap_setpixel_gray(img, i, j, b);
				}
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_vitec(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x5b\x07\x20", 4))
		return 100;
	return 0;
}

void de_module_vitec(deark *c, struct deark_module_info *mi)
{
	mi->id = "vitec";
	mi->desc = "VITec image format";
	mi->run_fn = de_run_vitec;
	mi->identify_fn = de_identify_vitec;
}

// **************************************************************************
// HS2 module
//
// .HS2 format is associated with a program called POSTERING.
// **************************************************************************

static void de_run_hs2(deark *c, de_module_params *mparams)
{
	de_int64 width, height;
	de_int64 rowspan;

	rowspan = 105;
	width = rowspan*8;
	height = (c->infile->len+(rowspan-1))/rowspan;
	de_convert_and_write_image_bilevel(c->infile, 0, width, height, rowspan, 0, NULL, 0);
}

static int de_identify_hs2(deark *c)
{
	if(!de_input_file_has_ext(c, "hs2")) return 0;
	if(c->infile->len>0 && (c->infile->len%105 == 0)) {
		return 15;
	}
	return 0;
}

void de_module_hs2(deark *c, struct deark_module_info *mi)
{
	mi->id = "hs2";
	mi->desc = "HS2 (POSTERING)";
	mi->run_fn = de_run_hs2;
	mi->identify_fn = de_identify_hs2;
}


// **************************************************************************
// Lumena CEL
// **************************************************************************

static void de_run_lumena_cel(deark *c, de_module_params *mparams)
{
	de_int64 width, height;
	de_int64 rowspan;
	de_int64 i, j;
	de_uint32 clr;
	de_byte a;
	int is_16bit = 0;
	int is_32bit = 0;
	de_bitmap *img = NULL;
	const de_int64 headersize = 4;
	de_int64 bypp;

	width = de_getui16le(0);
	height = de_getui16le(2);
	if(!de_good_image_dimensions_noerr(c, width, height)) goto done;

	// TODO: Support multi-image files
	is_16bit = (c->infile->len == headersize + width*height*2);
	is_32bit = (c->infile->len == headersize + width*height*4);
	if(!is_16bit && !is_32bit) {
		de_warn(c, "Cannot detect bits/pixel, assuming 32");
		is_32bit = 1;
	}

	bypp = (is_32bit) ? 4 : 2;
	de_dbg(c, "bytes/pixel: %d", (int)bypp);
	rowspan = width * bypp;

	img = de_bitmap_create(c, width, height, is_32bit?4:3);
	img->flipped = 1;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			de_int64 pos = headersize + j*rowspan + i*bypp;
			if(is_32bit) {
				clr = dbuf_getRGB(c->infile, pos, 0);
				a = de_getbyte(pos + 3);
				clr = DE_SET_ALPHA(clr, a);
			}
			else {
				clr = (de_uint32)de_getui16le(pos);
				clr = de_rgb555_to_888(clr);
			}
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}

	de_optimize_image_alpha(img, 0x3);
	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

static int de_identify_lumena_cel(deark *c)
{
	de_int64 width, height;
	int is_16bit = 0;
	int is_32bit = 0;

	if(!de_input_file_has_ext(c, "cel")) return 0;
	width = de_getui16le(0);
	height = de_getui16le(2);

	is_16bit = (c->infile->len == 4 + width*height*2);
	is_32bit = (c->infile->len == 4 + width*height*4);

	if(is_16bit || is_32bit)
		return 60;

	return 0;
}

void de_module_lumena_cel(deark *c, struct deark_module_info *mi)
{
	mi->id = "lumena_cel";
	mi->desc = "Lumena CEL";
	mi->run_fn = de_run_lumena_cel;
	mi->identify_fn = de_identify_lumena_cel;
}

// **************************************************************************
// ZBR (Zoner Zebra Metafile)
// **************************************************************************

static void de_run_zbr(deark *c, de_module_params *mparams)
{
	de_int64 pos = 0;
	dbuf *outf = NULL;
	static const de_byte hdrs[54] = {
		0x42,0x4d,0xc6,0x14,0,0,0,0,0,0,0x76,0,0,0, // FILEHEADER
		0x28,0,0,0,0x64,0,0,0,0x64,0,0,0,0x01,0,0x04,0, // INFOHEADER...
		0,0,0,0,0x50,0x14,0,0,0,0,0,0,0,0,0,0,
		0x10,0,0,0,0,0,0,0 };

	pos += 4; // signature, version
	pos += 100; // comment

	de_dbg(c, "preview image at %d", (int)pos);
	// By design, this image is formatted as a headerless BMP/DIB. We'll just
	// add the 54 bytes of headers needed to make it a BMP, and call it done.
	outf = dbuf_create_output_file(c, "preview.bmp", NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_write(outf, hdrs, 54);
	dbuf_copy(c->infile, pos, 16*4 + 100*52, outf);
	dbuf_close(outf);
}

static int de_identify_zbr(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x9a\x02", 2)) {
		if(de_input_file_has_ext(c, "zbr")) return 100;
		return 25;
	}
	return 0;
}

void de_module_zbr(deark *c, struct deark_module_info *mi)
{
	mi->id = "zbr";
	mi->desc = "ZBR (Zebra Metafile)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_zbr;
	mi->identify_fn = de_identify_zbr;
}
