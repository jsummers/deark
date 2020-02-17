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
DE_DECLARE_MODULE(de_module_crc);
DE_DECLARE_MODULE(de_module_hexdump);
DE_DECLARE_MODULE(de_module_bytefreq);
DE_DECLARE_MODULE(de_module_zlib);
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
DE_DECLARE_MODULE(de_module_cdr_wl);
DE_DECLARE_MODULE(de_module_compress);
DE_DECLARE_MODULE(de_module_gws_thn);
DE_DECLARE_MODULE(de_module_deskmate_pnt);
DE_DECLARE_MODULE(de_module_corel_bmf);
DE_DECLARE_MODULE(de_module_hpi);

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
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// CP437
// Convert CP437 text files to UTF-8.
// **************************************************************************

struct cp437ctx_struct {
	dbuf *outf;
};

static int cp437_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i32 u;
	i64 i;
	u8 ch;
	struct cp437ctx_struct *cp437ctx = (struct cp437ctx_struct*)brctx->userdata;

	for(i=0; i<buf_len; i++) {
		ch = buf[i];
		if(ch==0x09 || ch==0x0a || ch==0x0c || ch==0x0d) {
			// Leave HT, NL, FF, CR as-is.
			u = (i32)ch;
		}
		else if(ch==0x1a) {
			// Lots of CP437 files end with a Ctrl+Z character, but modern files
			// don't use any in-band character to signify end-of-file.
			// I don't just want to delete the character, though, so I guess I'll
			// change it to U+2404 SYMBOL FOR END OF TRANSMISSION.
			u = 0x2404;
		}
		else {
			u = de_char_to_unicode(brctx->c, (i32)ch, DE_ENCODING_CP437_G);
		}
		dbuf_write_uchar_as_utf8(cp437ctx->outf, u);
	}

	return 1;
}

static void de_run_cp437(deark *c, de_module_params *mparams)
{
	struct cp437ctx_struct cp437ctx;

	cp437ctx.outf = dbuf_create_output_file(c, "txt", NULL, 0);
	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(cp437ctx.outf, 0xfeff);
	}
	dbuf_buffered_read(c->infile, 0, c->infile->len, cp437_cbfn, (void*)&cp437ctx);
	dbuf_close(cp437ctx.outf);
}

void de_module_cp437(deark *c, struct deark_module_info *mi)
{
	mi->id = "cp437";
	mi->desc = "Code Page 437 text";
	mi->run_fn = de_run_cp437;
}

// **************************************************************************
// CRC-32
// Prints the CRC-32. Does not create any files.
// **************************************************************************

struct crcctx_struct {
	struct de_crcobj *crco_32ieee;
	struct de_crcobj *crco_16arc;
	struct de_crcobj *crco_16ccitt;
};

static int crc_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct crcctx_struct *crcctx = (struct crcctx_struct*)brctx->userdata;
	de_crcobj_addbuf(crcctx->crco_32ieee, buf, buf_len);
	de_crcobj_addbuf(crcctx->crco_16arc, buf, buf_len);
	de_crcobj_addbuf(crcctx->crco_16ccitt, buf, buf_len);
	return 1;
}

static void de_run_crc(deark *c, de_module_params *mparams)
{
	struct crcctx_struct crcctx;

	crcctx.crco_32ieee = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	crcctx.crco_16arc = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	crcctx.crco_16ccitt = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);

	dbuf_buffered_read(c->infile, 0, c->infile->len, crc_cbfn, (void*)&crcctx);

	de_msg(c, "CRC-32-IEEE: 0x%08x",
		(unsigned int)de_crcobj_getval(crcctx.crco_32ieee));
	de_msg(c, "CRC-16-IBM/ARC: 0x%04x",
		(unsigned int)de_crcobj_getval(crcctx.crco_16arc));
	de_msg(c, "CRC-16-CCITT: 0x%04x",
		(unsigned int)de_crcobj_getval(crcctx.crco_16ccitt));

	de_crcobj_destroy(crcctx.crco_32ieee);
	de_crcobj_destroy(crcctx.crco_16arc);
	de_crcobj_destroy(crcctx.crco_16ccitt);
}

void de_module_crc(deark *c, struct deark_module_info *mi)
{
	mi->id = "crc";
	mi->id_alias[0] = "crc32";
	mi->desc = "Calculate various CRCs";
	mi->run_fn = de_run_crc;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// hexdump
// Prints a hex dump. Does not create any files.
// **************************************************************************

static void de_run_hexdump(deark *c, de_module_params *mparams)
{
	de_hexdump2(c, c->infile, 0, c->infile->len,
		c->infile->len, 0x3);
}

void de_module_hexdump(deark *c, struct deark_module_info *mi)
{
	mi->id = "hexdump";
	mi->desc = "Print a hex dump";
	mi->run_fn = de_run_hexdump;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// bytefreq
// Prints a summary of how many times each byte value occurs.
// **************************************************************************

struct bytefreqentry {
	i64 count;
#define DE_BYTEFREQ_NUMLOC 3
	i64 locations[DE_BYTEFREQ_NUMLOC];
};

struct bytefreqctx_struct {
	struct bytefreqentry e[256];
};

static int bytefreq_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 k;
	struct bytefreqctx_struct *bfctx = (struct bytefreqctx_struct*)brctx->userdata;

	for(k=0; k<buf_len; k++) {
		struct bytefreqentry *bf = &bfctx->e[(unsigned int)buf[k]];

		// Save the location of the first few occurrences of this byte value.
		if(bf->count<DE_BYTEFREQ_NUMLOC) {
			bf->locations[bf->count] = brctx->offset + k;
		}
		bf->count++;
	}
	return 1;
}

static void de_run_bytefreq(deark *c, de_module_params *mparams)
{
	struct bytefreqctx_struct *bfctx = NULL;
	de_ucstring *s = NULL;
	unsigned int k;
	int input_encoding;

	bfctx = de_malloc(c, sizeof(struct bytefreqctx_struct));
	input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	if(input_encoding==DE_ENCODING_UTF8) {
		input_encoding=DE_ENCODING_ASCII;
	}

	dbuf_buffered_read(c->infile, 0, c->infile->len, bytefreq_cbfn, (void*)bfctx);

	de_msg(c, "====Byte==== ===Count=== ==Locations==");
	s = ucstring_create(c);
	for(k=0; k<256; k++) {
		i32 ch;
		int cflag;
		unsigned int z;
		struct bytefreqentry *bf = &bfctx->e[k];

		if(bf->count==0) continue;
		ucstring_empty(s);

		ucstring_printf(s, DE_ENCODING_LATIN1, "%3u 0x%02x ", k, k);

		ch = de_char_to_unicode(c, (i32)k, input_encoding);
		if(ch==DE_CODEPOINT_INVALID) {
			cflag = 0;
		}
		else {
			cflag = de_is_printable_uchar(ch);
		}

		if(cflag) {
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
			ucstring_append_char(s, ch);
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
		}
		else {
			ucstring_append_sz(s, "   ", DE_ENCODING_LATIN1);
		}

		ucstring_printf(s, DE_ENCODING_LATIN1, " %11"I64_FMT" ", bf->count);

		for(z=0; z<DE_BYTEFREQ_NUMLOC && z<bf->count; z++) {
			ucstring_printf(s, DE_ENCODING_LATIN1, "%"I64_FMT, bf->locations[z]);
			if(z<bf->count-1) {
				ucstring_append_sz(s, ",", DE_ENCODING_LATIN1);
			}
		}
		if(bf->count>DE_BYTEFREQ_NUMLOC) {
			ucstring_append_sz(s, "...", DE_ENCODING_LATIN1);
		}

		de_msg(c, "%s", ucstring_getpsz(s));
	}
	de_msg(c, "      Total: %11"I64_FMT, c->infile->len);
	ucstring_destroy(s);
	de_free(c, bfctx);
}

void de_module_bytefreq(deark *c, struct deark_module_info *mi)
{
	mi->id = "bytefreq";
	mi->desc = "Print a byte frequence analysis";
	mi->run_fn = de_run_bytefreq;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// zlib module
//
// This module is for decompressing zlib-compressed files.
// **************************************************************************

static void de_run_zlib(deark *c, de_module_params *mparams)
{
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "unc", NULL, 0);
	fmtutil_decompress_deflate(c->infile, 0, c->infile->len, f, 0, NULL, DE_DEFLATEFLAG_ISZLIB);
	dbuf_close(f);
}

static int de_identify_zlib(deark *c)
{
	u8 b[2];
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
// HP 100LX / HP 200LX .ICN icon format
// **************************************************************************

static void de_run_hpicn(deark *c, de_module_params *mparams)
{
	i64 width, height;

	width = de_getu16le(4);
	height = de_getu16le(6);
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, (width+7)/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

static int de_identify_hpicn(deark *c)
{
	u8 b[8];
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
	i64 w, h;
	i64 palentries;
};

static int xpuzz_read_header(deark *c, struct xpuzzctx *d)
{
	d->w = de_getu32be(0);
	d->h = de_getu32be(4);
	d->palentries = (i64)de_getbyte(8);
	if(!de_good_image_dimensions_noerr(c, d->w, d->h)) return 0;
	if(d->palentries==0) d->palentries = 256;
	return 1;
}

static void de_run_xpuzzle(deark *c, de_module_params *mparams)
{
	struct xpuzzctx *d = NULL;
	de_bitmap *img = NULL;
	u32 pal[256];
	i64 p;

	d = de_malloc(c, sizeof(struct xpuzzctx));
	if(!xpuzz_read_header(c, d)) goto done;
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	img = de_bitmap_create(c, d->w, d->h, 3);

	// Read the palette
	de_zeromem(pal, sizeof(pal));
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
	u8 buf[256];
	i64 xorsize;
	i64 i;
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
	u8 b[18];
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

static void do_mrw_seg_list(deark *c, i64 pos1, i64 len)
{
	i64 pos;
	u8 seg_id[4];
	i64 data_len;

	pos = pos1;
	while(pos < pos1+len) {
		de_read(seg_id, pos, 4);
		data_len = de_getu32be(pos+4);
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
	i64 mrw_seg_size;

	mrw_seg_size = de_getu32be(4);
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
	i64 w, h;
	u32 pal[256];
	i64 p;

	w = de_getu16le(0);
	h = de_getu16le(2);
	if(!de_good_image_dimensions(c, w, h)) goto done;
	img = de_bitmap_create(c, w, h, 3);

	// Read the palette
	de_zeromem(pal, sizeof(pal));
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
	i64 w, h;

	if(!de_input_file_has_ext(c, "bob")) return 0;

	w = de_getu16le(0);
	h = de_getu16le(2);
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
	i64 w, h;
	i64 i;
	i64 pos;
	i64 firstline;
	i64 depth;
	i64 xpos, ypos;
	i64 runlen;
	u32 clr;

	w = de_getu16be(0);
	h = de_getu16be(2);
	firstline = de_getu16be(4);
	depth = de_getu16be(8);

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
		runlen = (i64)de_getbyte(pos);
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
	i64 w, h, firstline, lastline, depth;

	if(!de_input_file_has_ext(c, "img") &&
		!de_input_file_has_ext(c, "als") &&
		!de_input_file_has_ext(c, "pix"))
	{
		return 0;
	}

	w = de_getu16be(0);
	h = de_getu16be(2);
	firstline = de_getu16be(4);
	lastline = de_getu16be(6);
	depth = de_getu16be(8);

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

static u8 applevol_get_gray_shade(u8 clr)
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
	i64 w, h;
	i64 i, j;
	i64 p;
	u8 palent;

	w = de_getu16be(1);
	h = de_getu16be(3);
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
	u8 buf[5];

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
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = 2;
	fi->density.ydens = 1;
	img = de_bitmap_create(c, 640, 240, 1);
	de_convert_image_bilevel(c->infile, 0, 640/8, img, 0);
	de_bitmap_write_to_file_finfo(img, fi, 0);
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
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
	i64 width, height;
	i64 chunk_span;
	i64 src_rowspan;
	i64 i, j, k;
	u8 x;
	u32 palent;

	width = 1 + de_getu16le(0);
	height = 1 + de_getu16le(2);
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
	u8 buf[4];
	i64 expected_size;
	i64 width, height;

	if(!de_input_file_has_ext(c, "icn")) return 0;
	de_read(buf, 0, sizeof(buf));
	width = 1 + de_getu16le(0);
	height = 1 + de_getu16le(2);
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
	i64 pos;
	int nextnibble_valid;
	u8 nextnibble;
};

static u8 lss16_get_nibble(deark *c, struct lss16ctx *d)
{
	u8 n;
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
	i64 width, height;
	i64 i;
	i64 xpos, ypos;
	u8 n;
	u8 prev;
	i64 run_len;
	u8 cr1, cg1, cb1;
	u8 cr2, cg2, cb2;
	u32 pal[16];
	char tmps[64];

	d = de_malloc(c, sizeof(struct lss16ctx));

	d->pos = 4;
	width = de_getu16le(d->pos);
	height = de_getu16le(d->pos+2);
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
			run_len = (i64)lss16_get_nibble(c, d);
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
	i64 width, height;
	u8 ver;

	ver = de_getbyte(3);
	if(ver!=2) {
		// TODO: Support VBM v3.
		de_err(c, "Unsupported VBM version (%d)", (int)ver);
		return;
	}
	width = de_getu16be(4);
	height = de_getu16be(6);
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, (width+7)/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

// Note that this function must work together with de_identify_bmp().
static int de_identify_vbm(deark *c)
{
	u8 b[4];
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
	i64 width, height;
	i64 rowspan;

	width = de_getu16le(2);
	height = de_getu16le(6);
	rowspan = ((width+15)/16)*2;
	de_convert_and_write_image_bilevel(c->infile, 8, width, height, rowspan, 0, NULL, 0);
}

static int de_identify_fp_art(deark *c)
{
	i64 width, height;
	i64 rowspan;

	if(!de_input_file_has_ext(c, "art")) return 0;

	width = de_getu16le(2);
	height = de_getu16le(6);
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
	i64 width, height;
	i64 i, j;
	i64 rowspan;
	u8 x;

	width = de_getu16be(2);
	height = de_getu16be(4);
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
	i64 width, height;
	i64 rowspan;

	if(dbuf_memcmp(c->infile, 0, "!!", 2))
		return 0;
	width = de_getu16be(2);
	height = de_getu16be(4);
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
	i64 width, height;
	i64 i, j;
	i64 rowspan;
	u8 b0, b1;
	u32 clr;

	width = de_getu16le(4);
	height = de_getu16le(6);
	if(!de_good_image_dimensions(c, width, height)) goto done;
	rowspan = width*2;

	img = de_bitmap_create(c, width, height, 3);

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			b0 = de_getbyte(8 + j*rowspan + i*2);
			b1 = de_getbyte(8 + j*rowspan + i*2 + 1);
			clr = (((u32)b1)<<8) | b0;
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
	i64 width, height;
	i64 i, j;
	i64 n, bpp;
	i64 rowspan;
	u32 clr;

	// This code is based on reverse engineering, and may be incorrect.

	n = de_getu16be(8); // Unknown field
	bpp = de_getu16be(10);
	if(n!=4 || bpp!=24) {
		de_dbg(c, "This type of IIM image is not supported");
		goto done;
	}
	width = de_getu16be(12);
	height = de_getu16be(14);
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
	i64 width, height;
	i64 nplanes;
	i64 nbands;
	i64 pixelformat;
	i64 commentsize;
	i64 i, j;
	i64 plane;
	i64 rowspan;
	i64 planespan;
	i64 pos;
	u8 b;

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
	i64 width, height;
	i64 rowspan;
	i64 pos;
	u8 b1, b2;
	i64 count;
	i64 cmpr_img_start;
	i64 num_cmpr_bytes;
	dbuf *unc_pixels = NULL;

	width = de_getu32be(20);
	height = de_getu32be(24);
	de_dbg_dimensions(c, width, height);
	if(!de_good_image_dimensions(c, width, height)) goto done;

	b1 = de_getbyte(32);
	if(b1!=0x01) {
		de_err(c, "Unsupported CRG format");
		goto done;
	}

	num_cmpr_bytes = de_getu32be(38);
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
			count = 1+(i64)b1;
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
		else { // A compressed run
			b2 = de_getbyte(pos++);
			count = (i64)(b1-127);
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
	i64 width, height;
	i64 i, j, k;
	i64 ppos;
	u8 s[4];

	width = de_getu32be(8);
	height = de_getu32be(12);
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
	u8 *fontdata = NULL;
	struct de_bitmap_font *font = NULL;
	i64 i;
	i64 height;

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
	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].codepoint_nonunicode = (i32)i;
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
	mi->help_fn = de_help_vgafont;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// HSI Raw image format (from Image Alchemy / Handmade Software)
// **************************************************************************

static void de_run_hsiraw(deark *c, de_module_params *mparams)
{
	i64 w, h;
	i64 num_pal_colors;
	i64 pos;
	i64 ver;
	i64 hdpi, vdpi;
	i64 cmpr;
	i64 alpha_info;
	de_bitmap *img = NULL;
	u32 pal[256];
	int is_grayscale;

	ver = de_getu16be(6);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=4) {
		de_warn(c, "HSI Raw version %d might not be supported correctly", (int)ver);
	}

	w = de_getu16be(8);
	if(w==0) {
		// MPlayer extension?
		de_dbg2(c, "reading 32-bit width");
		w = de_getu32be(28);
	}
	h = de_getu16be(10);
	de_dbg_dimensions(c, w, h);
	num_pal_colors = de_getu16be(12);
	de_dbg(c, "number of palette colors: %d", (int)num_pal_colors);

	hdpi = de_geti16be(14);
	vdpi = de_geti16be(16);
	de_dbg(c, "density: %d"DE_CHAR_TIMES"%d", (int)hdpi, (int)vdpi);
	// [18: Gamma]
	cmpr = de_getu16be(20);
	de_dbg(c, "compression: %d", (int)cmpr);
	alpha_info = de_getu16be(22);
	de_dbg(c, "alpha: %d", (int)alpha_info);

	if(num_pal_colors>256 || cmpr!=0 || alpha_info!=0) {
		de_err(c, "This type of HSI Raw image is not supported");
		goto done;
	}
	if(!de_good_image_dimensions(c, w, h)) goto done;

	pos = 32;
	de_zeromem(pal, sizeof(pal));
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
		de_convert_image_rgb(c->infile, pos, 3*w, 3, img, 0);
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
	i64 w, h;
	i64 num_pal_colors;
	i64 pos;
	de_bitmap *img = NULL;
	u32 pal[256];

	// Warning: This decoder is based on reverse engineering, and may be
	// incorrect or incomplete.

	w = de_getu16be(0);
	h = de_getu16be(2);
	de_dbg_dimensions(c, w, h);
	if(!de_good_image_dimensions(c, w, h)) goto done;

	num_pal_colors = 1 + (i64)de_getbyte(4);
	de_dbg(c, "number of palette colors: %d", (int)num_pal_colors);

	pos = 5;
	de_zeromem(pal, sizeof(pal));
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
	i64 w, h;
	i64 num_pal_colors;

	w = de_getu16be(0);
	h = de_getu16be(2);
	num_pal_colors = 1 + (i64)de_getbyte(4);
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
	i64 w, h;
	i64 i, j, plane;
	de_bitmap *img = NULL;
	i64 samplesperpixel;
	i64 rowspan, planespan;
	i64 pos;
	u8 b;
	i64 h1size, h2size;
	int saved_indent_level;

	// This code is based on reverse engineering, and may be incorrect.

	de_dbg_indent_save(c, &saved_indent_level);
	de_warn(c, "VITec image support is experimental, and may not work correctly.");

	pos = 4;
	h1size = de_getu32be(pos);
	de_dbg(c, "header 1 at %d, len=%d", (int)pos, (int)h1size);
	// Don't know what's in this part of the header. Just ignore it.
	pos += h1size;
	if(pos>=c->infile->len) goto done;

	h2size = de_getu32be(pos);
	de_dbg(c, "header 2 at %d, len=%d", (int)pos, (int)h2size);
	de_dbg_indent(c, 1);

	// pos+4: Bits size?
	// pos+24: Unknown field, usually 7

	w = de_getu32be(pos+36);
	h = de_getu32be(pos+40);
	de_dbg_dimensions(c, w, h);
	if(!de_good_image_dimensions(c, w, h)) goto done;

	// pos+52: Unknown field, 1 in grayscale images

	samplesperpixel = de_getu32be(pos+56);
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
	i64 width, height;
	i64 rowspan;

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
	i64 width, height;
	i64 rowspan;
	i64 i, j;
	u32 clr;
	u8 a;
	int is_16bit = 0;
	int is_32bit = 0;
	de_bitmap *img = NULL;
	const i64 headersize = 4;
	i64 bypp;

	width = de_getu16le(0);
	height = de_getu16le(2);
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
			i64 pos = headersize + j*rowspan + i*bypp;
			if(is_32bit) {
				clr = dbuf_getRGB(c->infile, pos, 0);
				a = de_getbyte(pos + 3);
				clr = DE_SET_ALPHA(clr, a);
			}
			else {
				clr = (u32)de_getu16le(pos);
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
	i64 width, height;
	int is_16bit = 0;
	int is_32bit = 0;

	if(!de_input_file_has_ext(c, "cel")) return 0;
	width = de_getu16le(0);
	height = de_getu16le(2);

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
	i64 pos = 0;
	dbuf *outf = NULL;
	static const u8 hdrs[54] = {
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

// **************************************************************************
// CorelDRAW CDR - old "WL" format
// **************************************************************************

static void de_run_cdr_wl(deark *c, de_module_params *mparams)
{
	u8 version;
	u8 b;
	i64 w, h;
	i64 rowspan;
	i64 pos = 0;
	de_bitmap *img = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_declare_fmt(c, "CorelDRAW (WL format)");
	version = de_getbyte(2);
	de_dbg(c, "version code: 0x%02x", (unsigned int)version);
	if(version <= (u8)'e') goto done;

	pos = de_getu32le(28);
	de_dbg(c, "preview image at %d", (int)pos);
	de_dbg_indent(c, 1);

	// Seems to be Windows DDB format, or something like it.
	pos += 2;
	pos += 2;
	w = de_getu16le_p(&pos);
	h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, w, h);
	rowspan = de_getu16le_p(&pos);
	b = de_getbyte_p(&pos); // planes
	if(b!=1) goto done;
	b = de_getbyte_p(&pos); // bits/pixel
	if(b!=1) goto done;
	pos += 4; // bmBits

	if(!de_good_image_dimensions(c, w, h)) goto done;
	img = de_bitmap_create(c, w, h, 1);
	de_convert_image_bilevel(c->infile, pos, rowspan, img, 0);
	de_bitmap_write_to_file(img, "preview", DE_CREATEFLAG_IS_AUX);

done:
	de_bitmap_destroy(img);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_cdr_wl(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "WL", 2)) {
		if(de_input_file_has_ext(c, "cdr")) return 100;
		return 6;
	}
	return 0;
}

void de_module_cdr_wl(deark *c, struct deark_module_info *mi)
{
	mi->id = "cdr_wl";
	mi->desc = "CorelDRAW (old WL format)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_cdr_wl;
	mi->identify_fn = de_identify_cdr_wl;
}

// **************************************************************************
// compress (.Z)
// **************************************************************************

static void de_run_compress(deark *c, de_module_params *mparams)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct delzw_params delzwp;
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "bin", NULL, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = f;
	dcmpro.len_known = 0;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS3BYTEHEADER;

	de_fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);
	if(dres.errcode!=0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
	}
	dbuf_close(f);
}

static int de_identify_compress(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1f\x9d", 2))
		return 100;
	return 0;
}

void de_module_compress(deark *c, struct deark_module_info *mi)
{
	mi->id = "compress";
	mi->desc = "Compress (.Z)";
	mi->run_fn = de_run_compress;
	mi->identify_fn = de_identify_compress;
}

// **************************************************************************
// Graphic Workshop .THN
// **************************************************************************

static void de_run_gws_thn(deark *c, de_module_params *mparams)
{
	de_bitmap *img = NULL;
	u8 v1, v2;
	i64 w, h;
	i64 pos;
	de_encoding encoding;
	de_ucstring *s = NULL;
	u32 pal[256];

	// This code is based on reverse engineering, and may be incorrect.
	encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	pos = 4;
	v1 = de_getbyte_p(&pos);
	v2 = de_getbyte_p(&pos);
	de_dbg(c, "version?: 0x%02x 0x%02x", (unsigned int)v1, (unsigned int)v2);

	s = ucstring_create(c);
	// For the text fields, the field size appears to be 129, but the software
	// only properly supports up to 127 non-NUL bytes.
	dbuf_read_to_ucstring(c->infile, 6, 127, s, DE_CONVFLAG_STOP_AT_NUL, encoding);
	if(s->len>0) de_dbg(c, "comments: \"%s\"", ucstring_getpsz_d(s));
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, 135, 127, s, DE_CONVFLAG_STOP_AT_NUL, encoding);
	if(s->len>0) de_dbg(c, "key words: \"%s\"", ucstring_getpsz_d(s));

	pos = 264;
	de_dbg(c, "image at %"I64_FMT, pos);
	w = 96;
	h = 96;

	// Set up the palette. There are two possible fixed palettes.
	if(v1==0) { // Original palette
		// Based on Graphic Workshop v1.1a for Windows
		static const u8 rbvals[6] = {0x00,0x57,0x83,0xab,0xd7,0xff};
		static const u8 gvals[7] = {0x00,0x2b,0x57,0x83,0xab,0xd7,0xff};
		static const u32 gwspal_last5[5] = {0x3f3f3f,0x6b6b6b,0x979797,
			0xc3c3c3,0xffffff};
		unsigned int k;

		for(k=0; k<=250; k++) {
			pal[k] = DE_MAKE_RGB(
				rbvals[k%6],
				gvals[(k%42)/6],
				rbvals[k/42]);
		}
		for(k=251; k<=255; k++) {
			pal[k] = gwspal_last5[k-251];
		}
	}
	else { // New palette (really RGB332), introduced by v1.1c
		// Based on Graphic Workshop v1.1u for Windows
		unsigned int k;

		for(k=0; k<256; k++) {
			u8 r, g, b;
			r = de_sample_nbit_to_8bit(3, k>>5);
			g = de_sample_nbit_to_8bit(3, (k>>2)&0x07);
			b = de_sample_nbit_to_8bit(2, k&0x03);
			pal[k] = DE_MAKE_RGB(r, g, b);
		}
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(c->infile, pos, 8, w, pal, img, 0);
	img->flipped = 1;
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
	ucstring_destroy(s);
}

static int de_identify_gws_thn(deark *c)
{
	if(c->infile->len!=9480) return 0;
	if(!dbuf_memcmp(c->infile, 0, "THNL", 4)) return 100;
	return 0;
}

void de_module_gws_thn(deark *c, struct deark_module_info *mi)
{
	mi->id = "gws_thn";
	mi->desc = "Graphic Workshop thumbnail .THN";
	mi->run_fn = de_run_gws_thn;
	mi->identify_fn = de_identify_gws_thn;
}

// **************************************************************************
// Tandy DeskMate Paint .PNT
// **************************************************************************

static void de_run_deskmate_pnt(deark *c, de_module_params *mparams)
{
	i64 w, h;
	i64 rowspan;
	i64 pos = 0;
	int k;
	int is_compressed;
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	i64 unc_pixels_size;
	u32 pal[16];

	pos += 22;
	de_dbg(c, "image at %"I64_FMT, pos);
	w = 312;
	h = 176;
	rowspan = w/2;
	unc_pixels_size = rowspan * h;

	for(k=0; k<16; k++) {
		pal[k] = de_palette_pc16(k);
	}

	is_compressed = (pos+unc_pixels_size != c->infile->len);
	de_dbg(c, "compressed: %d", is_compressed);

	if(is_compressed) {
		unc_pixels = dbuf_create_membuf(c, unc_pixels_size, 0x1);
		while(1) {
			i64 count;
			u8 val;

			if(pos >= c->infile->len) break; // out of source data
			if(unc_pixels->len >= unc_pixels_size) break; // enough dst data
			val = de_getbyte_p(&pos);
			count = (i64)de_getbyte_p(&pos);
			dbuf_write_run(unc_pixels, val, count);
		}
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, unc_pixels_size);
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(unc_pixels, 0, 4, rowspan, pal, img, 0);
	de_bitmap_write_to_file(img, NULL, 0);

	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
}

static int de_identify_deskmate_pnt(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x13" "PNT", 4)) return 100;
	return 0;
}

void de_module_deskmate_pnt(deark *c, struct deark_module_info *mi)
{
	mi->id = "deskmate_pnt";
	mi->desc = "Tandy DeskMate Paint";
	mi->run_fn = de_run_deskmate_pnt;
	mi->identify_fn = de_identify_deskmate_pnt;
}


// **************************************************************************
// Corel Gallery .BMF
// **************************************************************************

// Warning: The BMF preview image decoder is based on reverse engineering, may not
// be correct.

static void de_run_corel_bmf(deark *c, de_module_params *mparams1)
{
	de_module_params *mparams2 = NULL;
	int saved_indent_level;
	i64 pos;
	i64 n;
	i64 seg_size;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = 65;
	seg_size = de_getu32le_p(&pos);
	de_dbg(c, "preview image segment at %"I64_FMT", len=%"I64_FMT, pos, seg_size);
	de_dbg_indent(c, 1);

	if(pos + seg_size > c->infile->len) {
		seg_size = c->infile->len - pos;
	}

	n = de_getu32le(pos);
	if(n!=40) {
		de_err(c, "Unsupported Corel BMF version");
		goto done;
	}

	mparams2 = de_malloc(c, sizeof(de_module_params));
	mparams2->in_params.codes = "X";
	mparams2->in_params.flags = 0x81;
	de_run_module_by_id_on_slice(c, "dib", mparams2, c->infile, pos, seg_size);

done:
	de_free(c, mparams2);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_corel_bmf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "@CorelBMF\x0a\x0d", 11)) return 100;
	return 0;
}

void de_module_corel_bmf(deark *c, struct deark_module_info *mi)
{
	mi->id = "corel_bmf";
	mi->desc = "Corel Gallery BMF";
	mi->run_fn = de_run_corel_bmf;
	mi->identify_fn = de_identify_corel_bmf;
}

// **************************************************************************
// Hemera Photo-Object image (.hpi)
// **************************************************************************

static void de_run_hpi(deark *c, de_module_params *mparams)
{
	i64 jpgpos, pngpos;
	i64 jpglen, pnglen;
	i64 pos;

	pos = 12;
	jpgpos = de_getu32le_p(&pos);
	jpglen = de_getu32le_p(&pos);
	de_dbg(c, "jpeg: pos=%"I64_FMT", len=%"I64_FMT, jpgpos, jpglen);
	pngpos = de_getu32le_p(&pos);
	pnglen = de_getu32le_p(&pos);
	de_dbg(c, "png: pos=%"I64_FMT", len=%"I64_FMT, pngpos, pnglen);

	if(jpglen>0 && jpgpos+jpglen<=c->infile->len && de_getbyte(jpgpos)==0xff) {
		const char *ext;

		if(pnglen==0) ext="jpg";
		else ext="foreground.jpg";
		dbuf_create_file_from_slice(c->infile, jpgpos, jpglen, ext, NULL, 0);
	}
	if(pnglen>0 && pngpos+pnglen<=c->infile->len && de_getbyte(pngpos)==0x89) {
		dbuf_create_file_from_slice(c->infile, pngpos, pnglen, "mask.png", NULL, 0);
	}
}

static int de_identify_hpi(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x89\x48\x50\x49\x0d\x0a\x1a\x0a", 8)) return 100;
	return 0;
}

void de_module_hpi(deark *c, struct deark_module_info *mi)
{
	mi->id = "hpi";
	mi->desc = "Hemera Photo-Object image";
	mi->run_fn = de_run_hpi;
	mi->identify_fn = de_identify_hpi;
}
