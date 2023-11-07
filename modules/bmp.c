// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows BMP image

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_bmp);
DE_DECLARE_MODULE(de_module_picjpeg);
DE_DECLARE_MODULE(de_module_dib);
DE_DECLARE_MODULE(de_module_ddb);
DE_DECLARE_MODULE(de_module_jigsaw_wk);

#define FILEHEADER_SIZE 14

#define CODE_LINK 0x4c494e4bU
#define CODE_MBED 0x4d424544U

struct bitfieldsinfo {
	u32 mask;
	unsigned int shift;
	double scale; // Amount to multiply the sample value by, to scale it to [0..255]
};

typedef struct localctx_struct {
#define DE_BMPVER_OS2V1    1 // OS2v1 or Windows v2
#define DE_BMPVER_OS2V2    2
#define DE_BMPVER_WINV345  3 // Windows v3+
#define DE_BMPVER_64BIT    10
	int version;

	de_finfo *fi;
	i64 fsize; // The "file size" field in the file header
	i64 bits_offset; // The bfOffBits field in the file header
	i64 infohdrsize;
	i64 bitcount;
	u32 compression_field;
	i64 size_image; // biSizeImage
	i64 width, pdwidth, height;
	int top_down;
	UI extra_createflags;
	i64 pal_entries; // Actual number stored in file. 0 means no palette.
	i64 pal_pos;
	i64 bytes_per_pal_entry;
	int pal_is_grayscale;

#define BF_NONE       0 // Bitfields are not applicable
#define BF_DEFAULT    1 // Use the default bitfields for this bit depth
#define BF_SEGMENT    2 // Use the bitfields segment in the file
#define BF_IN_HEADER  3 // Use the bitfields fields in the infoheader
	int bitfields_type;
	i64 bitfields_segment_len; // Used if bitfields_type==BF_SEGMENT

	i64 xpelspermeter, ypelspermeter;

#define CMPR_NONE       0
#define CMPR_RLE4       11
#define CMPR_RLE8       12
#define CMPR_RLE24      13
#define CMPR_JPEG       14
#define CMPR_PNG        15
#define CMPR_HUFFMAN1D  16
	int compression_type;

	struct de_fourcc cstype4cc;
	i64 profile_offset_raw;
	i64 profile_offset;
	i64 profile_size;

	i64 rowspan;
	struct bitfieldsinfo bitfield[4];
	u32 pal[256];
} lctx;

static i64 get_bits_size(deark *c, lctx *d)
{
	if(d->size_image>0 && d->bits_offset+d->size_image <= c->infile->len) {
		return d->size_image;
	}
	return c->infile->len - d->bits_offset;
}

// Sets d->version, and certain header fields.
static int detect_bmp_version(deark *c, lctx *d)
{
	i64 pos;

	pos = 0;
	d->fsize = de_getu32le(pos+2);

	pos += FILEHEADER_SIZE;
	d->infohdrsize = de_getu32le(pos);

	if(d->infohdrsize<=12) {
		d->bitcount = de_getu16le(pos+10);
	}
	else {
		d->bitcount = de_getu16le(pos+14);
	}

	if(d->infohdrsize==12) {
		d->version = DE_BMPVER_OS2V1;
		return 1;
	}
	if(d->infohdrsize<16) {
		return 0;
	}

	if(d->infohdrsize>=20) {
		d->compression_field = (u32)de_getu32le(pos+16);
	}

	// We're only trying to support the most basic 64-bit BMP images.
	if(d->bitcount==64 && d->infohdrsize==40 && d->compression_field==0) {
		d->version = DE_BMPVER_64BIT;
		return 1;
	}

	if(d->infohdrsize>=16 && d->infohdrsize<=64) {
		if(d->fsize==FILEHEADER_SIZE+d->infohdrsize) {
			d->version = DE_BMPVER_OS2V2;
			return 1;
		}

		if((d->compression_field==3 && d->bitcount==1) ||
			(d->compression_field==4 && d->bitcount==24))
		{
			d->version = DE_BMPVER_OS2V2;
			return 1;
		}

		if(d->infohdrsize!=40 && d->infohdrsize!=52 && d->infohdrsize!=56) {
			d->version = DE_BMPVER_OS2V2;
			return 1;
		}
	}

	d->version = DE_BMPVER_WINV345;
	return 1;
}

static int read_fileheader(deark *c, lctx *d, i64 pos)
{
	de_dbg(c, "file header at %d", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "bfSize: %d", (int)d->fsize);
	d->bits_offset = de_getu32le(pos+10);
	de_dbg(c, "bfOffBits: %d", (int)d->bits_offset);
	de_dbg_indent(c, -1);
	return 1;
}

// Calculate .shift and .scale
static void update_bitfields_info(deark *c, lctx *d)
{
	i64 k;
	u32 tmpmask;

	for(k=0; k<4; k++) {
		tmpmask = d->bitfield[k].mask;
		if(tmpmask==0) continue;
		while((tmpmask & 0x1) == 0) {
			d->bitfield[k].shift++;
			tmpmask >>= 1;
		}
		d->bitfield[k].scale = 255.0 / (double)tmpmask;
	}
}

static void do_read_bitfields(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 k;

	if(len>16) len=16;
	for(k=0; 4*k<len; k++) {
		d->bitfield[k].mask = (u32)de_getu32le(pos+4*k);
		de_dbg(c, "mask[%d]: 0x%08x", (int)k, (unsigned int)d->bitfield[k].mask);
	}
	update_bitfields_info(c, d);
}

static void set_default_bitfields(deark *c, lctx *d)
{
	if(d->bitcount==16) {
		d->bitfield[0].mask = 0x000007c00U;
		d->bitfield[1].mask = 0x0000003e0U;
		d->bitfield[2].mask = 0x00000001fU;
		update_bitfields_info(c, d);
	}
	else if(d->bitcount==32) {
		d->bitfield[0].mask = 0x00ff0000U;
		d->bitfield[1].mask = 0x0000ff00U;
		d->bitfield[2].mask = 0x000000ffU;
		update_bitfields_info(c, d);
	}
}

static void get_cstype_descr_dbgstr(struct de_fourcc *cstype4cc, char *s_dbgstr, size_t s_len)
{
	// The ID might be a FOURCC, or not.
	if(cstype4cc->id>0xffffU) {
		de_snprintf(s_dbgstr, s_len, "0x%08x ('%s')", (unsigned int)cstype4cc->id,
			cstype4cc->id_dbgstr);
	}
	else {
		const char *name = "?";
		switch(cstype4cc->id) {
		case 0: name = "LCS_CALIBRATED_RGB"; break;
		}
		de_snprintf(s_dbgstr, s_len, "%u (%s)", (unsigned int)cstype4cc->id, name);
	}
}

// Read any version of BITMAPINFOHEADER.
//
// Note: Some of this BMP parsing code is duplicated in the
// de_fmtutil_get_bmpinfo() library function. The BMP module's needs are
// not quite aligned with what that function is intended for, and it
// would be too messy to try to add the necessary features to it.
static int read_infoheader(deark *c, lctx *d, i64 pos)
{
	i64 height_raw;
	i64 clr_used_raw;
	int bitcount_ok = 0;
	int cmpr_ok = 0;
	int retval = 0;
	i64 nplanes;

	de_dbg(c, "info header at %d", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "info header size: %d", (int)d->infohdrsize);

	if(d->version==DE_BMPVER_OS2V1) {
		d->width = de_getu16le(pos+4);
		d->height = de_getu16le(pos+6);
		nplanes = de_getu16le(pos+8);
	}
	else {
		d->width = de_geti32le(pos+4);
		height_raw = de_geti32le(pos+8);
		if(height_raw<0) {
			d->top_down = 1;
			d->height = -height_raw;
		}
		else {
			d->height = height_raw;
		}
		nplanes = de_getu16le(pos+12);
	}
	d->pdwidth = d->width; // Default "padded width"
	de_dbg_dimensions(c, d->width, d->height);
	if(d->top_down) {
		de_dbg(c, "orientation: top-down");
	}
	else {
		d->extra_createflags |= DE_CREATEFLAG_FLIP_IMAGE;
	}

	de_dbg(c, "planes: %d", (int)nplanes);

	// Already read, in detect_bmp_version()
	de_dbg(c, "bits/pixel: %d", (int)d->bitcount);

	// FIXME? The conditional test for 64 may lead to misleading error messages
	// (but I'm afraid something might break without it).
	if(d->bitcount==0 || d->bitcount==1 || d->bitcount==2 || d->bitcount==4 ||
		d->bitcount==8 || d->bitcount==16 || d->bitcount==24 || d->bitcount==32 ||
		(d->bitcount==64 && d->version==DE_BMPVER_64BIT))
	{
		bitcount_ok = 1;
	}

	if(d->version==DE_BMPVER_OS2V1) {
		d->bytes_per_pal_entry = 3;
	}
	else {
		char cmprname[80];
		// d->compression_field was already read, in detect_bmp_version()
		fmtutil_get_bmp_compression_name(d->compression_field, cmprname, sizeof(cmprname),
			(d->version==DE_BMPVER_OS2V2));
		de_dbg(c, "compression (etc.): %u (%s)", (unsigned int)d->compression_field, cmprname);
		d->bytes_per_pal_entry = 4;
	}

	d->compression_type = CMPR_NONE; // Temporary default

	switch(d->compression_field) {
	case 0: // BI_RGB
		if(d->bitcount==16 || d->bitcount==32) {
			d->bitfields_type = BF_DEFAULT;
		}
		d->compression_type = CMPR_NONE;
		cmpr_ok = 1;
		break;
	case 1: // BI_RLE8
		d->compression_type=CMPR_RLE8;
		cmpr_ok = 1;
		break;
	case 2: // BI_RLE4
		d->compression_type=CMPR_RLE4;
		cmpr_ok = 1;
		break;
	case 3: // BI_BITFIELDS or Huffman_1D
		if(d->version==DE_BMPVER_OS2V2) {
			if(d->bitcount==1) {
				d->compression_type=CMPR_HUFFMAN1D;
				cmpr_ok = 1;
			}
		}
		else if(d->bitcount==16 || d->bitcount==32) {
			d->compression_type = CMPR_NONE;
			cmpr_ok = 1;
			if(d->infohdrsize>=52) {
				d->bitfields_type = BF_IN_HEADER;
			}
			else {
				d->bitfields_type = BF_SEGMENT;
				d->bitfields_segment_len = 12;
			}
		}
		break;
	case 4: // BI_JPEG or RLE24
		if(d->version==DE_BMPVER_OS2V2) {
			if(d->bitcount==24) {
				d->compression_type=CMPR_RLE24;
				cmpr_ok = 1;
			}
		}
		else {
			d->compression_type=CMPR_JPEG;
			cmpr_ok = 1;
		}
		break;
	case 5: // BI_PNG
		d->compression_type=CMPR_PNG;
		cmpr_ok = 1;
		break;
	case 6: // BI_ALPHABITFIELDS
		if(d->bitcount==16 || d->bitcount==32) {
			d->compression_type = CMPR_NONE;
			cmpr_ok = 1;
			if(d->infohdrsize>=56) {
				d->bitfields_type = BF_IN_HEADER;
			}
			else {
				d->bitfields_type = BF_SEGMENT;
				d->bitfields_segment_len = 16;
			}
		}
		break;
	}

	if(d->infohdrsize>=24) {
		d->size_image = de_getu32le(pos+20);
		de_dbg(c, "biSizeImage: %d", (int)d->size_image);
	}

	if(d->infohdrsize>=32) {
		d->xpelspermeter = de_geti32le(pos+24);
		d->ypelspermeter = de_geti32le(pos+28);
		de_dbg(c, "density: %d"DE_CHAR_TIMES"%d pixels/meter", (int)d->xpelspermeter, (int)d->ypelspermeter);
		if(d->xpelspermeter>0 && d->ypelspermeter>0) {
			d->fi->density.code = DE_DENSITY_DPI;
			d->fi->density.xdens = (double)d->xpelspermeter * 0.0254;
			d->fi->density.ydens = (double)d->ypelspermeter * 0.0254;
		}
	}

	if(d->infohdrsize>=36)
		clr_used_raw = de_getu32le(pos+32);
	else
		clr_used_raw = 0;

	if(d->bitcount>=1 && d->bitcount<=8 && clr_used_raw==0) {
		d->pal_entries = ((i64)1)<<d->bitcount;
	}
	else {
		d->pal_entries = clr_used_raw;
	}
	de_dbg(c, "number of palette colors: %d", (int)d->pal_entries);

	// Note that after 40 bytes, WINV345 and OS2V2 header fields are different,
	// so we have to pay more attention to the version.

	if(d->bitfields_type==BF_IN_HEADER) {
		do_read_bitfields(c, d, pos+40, d->infohdrsize>=56 ? 16 : 12);
	}

	if(d->bitfields_type==BF_DEFAULT) {
		set_default_bitfields(c, d);
	}

	if(d->version==DE_BMPVER_WINV345 && d->infohdrsize>=108) {
		char cstype_descr_dbgstr[80];
		dbuf_read_fourcc(c->infile, pos+56, &d->cstype4cc, 4, DE_4CCFLAG_REVERSED);
		get_cstype_descr_dbgstr(&d->cstype4cc, cstype_descr_dbgstr, sizeof(cstype_descr_dbgstr));
		de_dbg(c, "CSType: %s", cstype_descr_dbgstr);
	}

	if(d->version==DE_BMPVER_WINV345 && d->infohdrsize>=124) {
		u32 intent;
		intent = (u32)de_getu32le(pos+108);
		de_dbg(c, "intent: %u", (unsigned int)intent);
	}

	if(d->version==DE_BMPVER_WINV345 && d->infohdrsize>=124 &&
		(d->cstype4cc.id==CODE_MBED || d->cstype4cc.id==CODE_LINK))
	{
		d->profile_offset_raw = de_getu32le(pos+112);
		de_dbg(c, "profile offset: %d+%d", FILEHEADER_SIZE,
			(int)d->profile_offset_raw);
		d->profile_size = de_getu32le(pos+116);
		de_dbg(c, "profile size: %d", (int)d->profile_size);
	}

	if(!bitcount_ok) {
		de_err(c, "Bad or unsupported bits/pixel: %d", (int)d->bitcount);
		goto done;
	}
	if(!cmpr_ok) {
		de_err(c, "Unsupported compression type: %d", (int)d->compression_field);
		goto done;
	}
	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_read_linked_profile(deark *c, lctx *d)
{
	de_ucstring *fname = NULL;

	de_dbg(c, "linked profile filename at %d", (int)d->profile_offset);
	fname = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, d->profile_offset,
		d->profile_size, DE_DBG_MAX_STRLEN, fname,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_WINDOWS1252);
	de_dbg_indent(c, 1);
	de_dbg(c, "profile filename: \"%s\"", ucstring_getpsz(fname));
	de_dbg_indent(c, -1);
	ucstring_destroy(fname);
}

static void do_read_embedded_profile(deark *c, lctx *d)
{
	de_dbg(c, "embedded profile at %d, size=%d", (int)d->profile_offset,
		(int)d->profile_size);
	de_dbg_indent(c, 1);
	dbuf_create_file_from_slice(c->infile, d->profile_offset, d->profile_size, "icc",
		NULL, DE_CREATEFLAG_IS_AUX);
	de_dbg_indent(c, -1);
}

static void do_read_profile(deark *c, lctx *d)
{
	if(d->version!=DE_BMPVER_WINV345) return;
	if(d->infohdrsize<124) return;
	if(d->profile_offset_raw==0 || d->profile_size==0) return;
	d->profile_offset = FILEHEADER_SIZE + d->profile_offset_raw;
	if(d->profile_offset+d->profile_size > c->infile->len) return;
	if(d->cstype4cc.id==CODE_LINK) {
		do_read_linked_profile(c, d);
	}
	else if(d->cstype4cc.id==CODE_MBED) {
		do_read_embedded_profile(c, d);
	}
}

// Some OS/2v2 files exist with bad (3-bytes/color) palettes.
// Try to detect them.
static void do_os2v2_bad_palette(deark *c, lctx *d)
{
	i64 pal_space_avail;
	i64 pal_bytes_if_3bpc;
	i64 pal_bytes_if_4bpc;
	int nonzero_rsvd;
	int i;

	if(d->version!=DE_BMPVER_OS2V2) return;
	if(d->pal_entries<1) return;

	pal_space_avail = d->bits_offset - d->pal_pos;
	pal_bytes_if_4bpc = 4*d->pal_entries;
	pal_bytes_if_3bpc = 3*d->pal_entries;

	if(pal_space_avail>=pal_bytes_if_4bpc) return;
	if(pal_space_avail<pal_bytes_if_3bpc || pal_space_avail>(pal_bytes_if_3bpc+1)) return;

	// Look for nonzero 'reserved' bytes
	nonzero_rsvd = 0;
	for(i=0; i<pal_bytes_if_3bpc; i+=4) {
		if(de_getbyte(d->pal_pos + i + 3) != 0) {
			nonzero_rsvd = 1;
			break;
		}
	}
	if(!nonzero_rsvd) return;

	de_warn(c, "Assuming palette has 3 bytes per entry, instead of 4");
	d->bytes_per_pal_entry = 3;
}

static void do_read_palette(deark *c, lctx *d)
{
	i64 pal_size_in_bytes;

	if(d->pal_entries<1) return;

	pal_size_in_bytes = d->pal_entries*d->bytes_per_pal_entry;
	if(d->pal_pos+pal_size_in_bytes > d->bits_offset) {
		de_warn(c, "Palette at %d (size %d) overlaps bitmap at %d",
			(int)d->pal_pos, (int)pal_size_in_bytes, (int)d->bits_offset);
		if(d->version==DE_BMPVER_OS2V2) {
			do_os2v2_bad_palette(c, d);
		}
	}

	de_dbg(c, "color table at %d, %d entries", (int)d->pal_pos, (int)d->pal_entries);

	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, d->pal_pos, d->pal_entries, d->bytes_per_pal_entry,
		d->pal, 256, DE_GETRGBFLAG_BGR);

	d->pal_is_grayscale = de_is_grayscale_palette(d->pal, d->pal_entries);
	de_dbg_indent(c, -1);
}

// A wrapper for de_bitmap_create()
static de_bitmap *bmp_bitmap_create(deark *c, lctx *d, int bypp)
{
	de_bitmap *img;

	img = de_bitmap_create2(c, d->width, d->pdwidth, d->height, bypp);
	return img;
}

static void do_image_paletted(deark *c, lctx *d, dbuf *bits, i64 bits_offset)
{
	de_bitmap *img = NULL;

	img = bmp_bitmap_create(c, d, d->pal_is_grayscale?1:3);
	de_convert_image_paletted(bits, bits_offset,
		d->bitcount, d->rowspan, d->pal, img, 0);
	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_OPT_IMAGE | d->extra_createflags);
	de_bitmap_destroy(img);
}

static void do_image_24bit(deark *c, lctx *d, dbuf *bits, i64 bits_offset)
{
	de_bitmap *img = NULL;
	i64 i, j;
	u32 clr;

	img = bmp_bitmap_create(c, d, 3);
	for(j=0; j<d->height; j++) {
		i64 rowpos = bits_offset + j*d->rowspan;
		i64 pos_in_this_row = 0;
		u8 cbuf[3];

		for(i=0; i<d->pdwidth; i++) {
			dbuf_read(bits, cbuf, rowpos + pos_in_this_row, 3);
			if(pos_in_this_row+3 > d->rowspan) {
				// If -padpix was used, a partial pixel at the end of the row is
				// possible. Happens when width == 1 or 2 (mod 4).
				// To handle that, zero out the byte(s) that we shouldn't have read.
				cbuf[2] = 0;
				if(pos_in_this_row+2 > d->rowspan) {
					cbuf[1] = 0;
				}
			}
			clr = DE_MAKE_RGB(cbuf[2], cbuf[1], cbuf[0]);
			de_bitmap_setpixel_rgb(img, i, j, clr);
			pos_in_this_row += 3;
		}
	}

	de_bitmap_write_to_file_finfo(img, d->fi, d->extra_createflags);
	de_bitmap_destroy(img);
}

static void do_image_16_32bit(deark *c, lctx *d, dbuf *bits, i64 bits_offset)
{
	de_bitmap *img = NULL;
	i64 i, j;
	int has_transparency;
	u32 v;
	i64 k;
	u8 sm[4];

	if(d->bitfields_type==BF_SEGMENT) {
		has_transparency = (d->bitfields_segment_len>=16 && d->bitfield[3].mask!=0);
	}
	else if(d->bitfields_type==BF_IN_HEADER) {
		has_transparency = (d->bitfield[3].mask!=0);
	}
	else {
		has_transparency = 0;
	}

	img = bmp_bitmap_create(c, d, has_transparency?4:3);
	for(j=0; j<d->height; j++) {
		for(i=0; i<d->pdwidth; i++) {
			if(d->bitcount==16) {
				v = (u32)dbuf_getu16le(bits, bits_offset + j*d->rowspan + 2*i);
			}
			else {
				v = (u32)dbuf_getu32le(bits, bits_offset + j*d->rowspan + 4*i);
			}

			for(k=0; k<4; k++) {
				if(d->bitfield[k].mask!=0) {
					sm[k] = (u8)(0.5 + d->bitfield[k].scale * (double)((v&d->bitfield[k].mask) >> d->bitfield[k].shift));
				}
				else {
					if(k==3)
						sm[k] = 255; // Default alpha sample = opaque
					else
						sm[k] = 0; // Default other samples = 0
				}
			}
			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(sm[0], sm[1], sm[2], sm[3]));
		}
	}

	de_bitmap_write_to_file_finfo(img, d->fi, d->extra_createflags);
	de_bitmap_destroy(img);
}

static void do_image_64bit(deark *c, lctx *d, dbuf *bits, i64 bits_offset)
{
	de_bitmap *imghi = NULL;
	de_bitmap *imglo = NULL;
	i64 i, j;
	size_t k;
	u8 range_flag = 0;
	u8 sm_hi[4];
	u8 sm_lo[4];
	int sm16[4];

	imghi = bmp_bitmap_create(c, d, 4);
	imglo = bmp_bitmap_create(c, d, 4);
	for(j=0; j<d->height; j++) {
		i64 pos;

		pos = bits_offset + j*d->rowspan;
		for(i=0; i<d->pdwidth; i++) {
			sm16[2] = (int)dbuf_geti16le_p(bits, &pos);
			sm16[1] = (int)dbuf_geti16le_p(bits, &pos);
			sm16[0] = (int)dbuf_geti16le_p(bits, &pos);
			sm16[3] = (int)dbuf_geti16le_p(bits, &pos);

			// This is a signed "fixed point" format.
			// Full sample range is -32768 to 32767 (= -4.0 to +3.999);
			//  0 is the normal min brightness ("black" or transparent), and
			//  8192 is the normal max brightness ("white" or opaque).
			// Colorspace is, apparently, linear.
			for(k=0; k<4; k++) {
				if(sm16[k]<0 || sm16[k]>8192) {
					range_flag = 1;
				}
				de_scale_n_to_16bit(8192, sm16[k], &sm_hi[k], &sm_lo[k]);
			}
			de_bitmap_setpixel_rgba(imghi, i, j, DE_MAKE_RGBA(sm_hi[0], sm_hi[1], sm_hi[2], sm_hi[3]));
			de_bitmap_setpixel_rgba(imglo, i, j, DE_MAKE_RGBA(sm_lo[0], sm_lo[1], sm_lo[2], sm_lo[3]));
		}
	}

	if(range_flag) {
		de_warn(c, "Image has samples outside the normal range");
	}
	d->fi->linear_colorpace = 1;
	de_bitmap16_write_to_file_finfo(imghi, imglo, d->fi, DE_CREATEFLAG_OPT_IMAGE | d->extra_createflags);
	de_bitmap_destroy(imghi);
	de_bitmap_destroy(imglo);
}

static void do_image_rle_4_8_24(deark *c, lctx *d, dbuf *bits, i64 bits_offset)
{
	i64 pos;
	i64 xpos, ypos;
	u8 b1, b2;
	u8 b;
	u8 cr, cg, cb;
	de_bitmap *img = NULL;
	u32 clr1, clr2;
	i64 num_bytes;
	i64 num_pixels;
	i64 k;
	int bypp;

	if(d->pal_is_grayscale && d->compression_type!=CMPR_RLE24) {
		bypp = 2;
	}
	else {
		bypp = 4;
	}

	img = bmp_bitmap_create(c, d, bypp);

	pos = bits_offset;
	xpos = 0;
	ypos = 0;
	while(1) {
		// Stop if we reach the end of the input file.
		if(pos>=c->infile->len) break;

		// Stop if we reach the end of the output image.
		if(ypos>=d->height) break;
		if(ypos==(d->height-1) && xpos>=d->pdwidth) break;

		// Read the next two bytes from the input file.
		b1 = dbuf_getbyte(bits, pos++);
		b2 = dbuf_getbyte(bits, pos++);

		if(b1==0 && b2==0) { // End of line
			xpos = 0;
			ypos++;
		}
		else if(b1==0 && b2==1) { // End of bitmap
			break;
		}
		else if(b1==0 && b2==2) { // Delta
			b = dbuf_getbyte(bits, pos++);
			xpos += (i64)b;
			b = dbuf_getbyte(bits, pos++);
			ypos += (i64)b;
		}
		else if(b1==0) { // b2 uncompressed pixels follow
			num_pixels = (i64)b2;
			if(d->compression_type==CMPR_RLE4) {
				i64 pixels_copied = 0;
				// There are 4 bits per pixel, but padded to a multiple of 16 bits.
				num_bytes = ((num_pixels+3)/4)*2;
				for(k=0; k<num_bytes; k++) {
					b = dbuf_getbyte(bits, pos++);
					if(pixels_copied>=num_pixels) continue;
					clr1 = d->pal[((unsigned int)b)>>4];
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr1);
					pixels_copied++;
					if(pixels_copied>=num_pixels) continue;
					clr2 = d->pal[((unsigned int)b)&0x0f];
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr2);
					pixels_copied++;
				}
			}
			else if(d->compression_type==CMPR_RLE24) {
				for(k=0; k<num_pixels; k++) {
					cb = dbuf_getbyte_p(bits, &pos);
					cg = dbuf_getbyte_p(bits, &pos);
					cr = dbuf_getbyte_p(bits, &pos);
					clr1 = DE_MAKE_RGB(cr, cg, cb);
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr1);
				}
				if(num_pixels%2) {
					pos++; // Pad to a multiple of 16 bits
				}
			}
			else { // CMPR_RLE8
				num_bytes = num_pixels;
				if(num_bytes%2) num_bytes++; // Pad to a multiple of 16 bits
				for(k=0; k<num_bytes; k++) {
					b = dbuf_getbyte(bits, pos++);
					if(k>=num_pixels) continue;
					clr1 = d->pal[(unsigned int)b];
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr1);
				}
			}
		}
		else { // Compressed pixels
			num_pixels = (i64)b1;
			if(d->compression_type==CMPR_RLE4) {
				// b1 pixels alternating between the colors in b2
				clr1 = d->pal[((unsigned int)b2)>>4];
				clr2 = d->pal[((unsigned int)b2)&0x0f];
				for(k=0; k<num_pixels; k++) {
					de_bitmap_setpixel_rgba(img, xpos++, ypos, (k%2)?clr2:clr1);
				}
			}
			else if(d->compression_type==CMPR_RLE24) {
				cb = b2;
				cg = dbuf_getbyte_p(bits, &pos);
				cr = dbuf_getbyte_p(bits, &pos);
				clr1 = DE_MAKE_RGB(cr, cg, cb);
				for(k=0; k<num_pixels; k++) {
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr1);
				}
			}
			else { // CMPR_RLE8
				// b1 pixels of color b2
				clr1 = d->pal[(unsigned int)b2];
				for(k=0; k<num_pixels; k++) {
					de_bitmap_setpixel_rgba(img, xpos++, ypos, clr1);
				}
			}
		}
	}

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_OPT_IMAGE | d->extra_createflags);
	de_bitmap_destroy(img);
}

static void do_image_huffman1d(deark *c, lctx *d)
{
	dbuf *unc_pixels = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_fax34_params fax34params;

	// Caution: These settings might be wrong. I need more information about this format.
	de_zeromem(&fax34params, sizeof(struct de_fax34_params));
	fax34params.image_width = d->width;
	fax34params.image_height = d->height;
	fax34params.out_rowspan = d->rowspan;
	fax34params.tiff_cmpr_meth = 3;
	fax34params.t4options = 0;
	fax34params.is_lsb = (u8)de_get_ext_option_bool(c, "bmp:huffmanlsb", 0);

	unc_pixels = dbuf_create_membuf(c, d->rowspan*d->height, 0x1);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = d->bits_offset;
	dcmpri.len = get_bits_size(c, d);
	dcmpro.f = unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = d->rowspan*d->height;

	fmtutil_fax34_codectype1(c, &dcmpri, &dcmpro, &dres,
		 (void*)&fax34params);

	do_image_paletted(c, d, unc_pixels, 0);

	dbuf_close(unc_pixels);
}

static void extract_embedded_image(deark *c, lctx *d, const char *ext)
{
	i64 nbytes;

	nbytes = get_bits_size(c, d);
	if(nbytes<1) return;

	dbuf_create_file_from_slice(c->infile, d->bits_offset, nbytes, ext, NULL, 0);
}

static void do_image(deark *c, lctx *d)
{
	de_dbg(c, "bitmap at %d", (int)d->bits_offset);

	if(d->bits_offset >= c->infile->len) {
		de_err(c, "Bad bits-offset field");
		goto done;
	}

	d->rowspan = ((d->bitcount*d->width +31)/32)*4;
	if(d->compression_type==CMPR_NONE) {
		if(c->padpix && d->bitcount==24) {
			// The 24-bit decoder can handle partial pixels.
			d->pdwidth = (d->rowspan+2)/3;
		}
		else if(d->bitcount>=1 && d->bitcount<=24) {
			// By default, ignore a partial-pixel's worth of padding.
			// bits-per-row / bits-per-pixel
			d->pdwidth = (d->rowspan*8) / d->bitcount;
		}
	}

	if(d->bitcount>=1 && d->bitcount<=8 && d->compression_type==CMPR_NONE) {
		do_image_paletted(c, d, c->infile, d->bits_offset);
	}
	else if(d->bitcount==24 && d->compression_type==CMPR_NONE) {
		do_image_24bit(c, d, c->infile, d->bits_offset);
	}
	else if((d->bitcount==16 || d->bitcount==32) && d->compression_type==CMPR_NONE) {
		do_image_16_32bit(c, d, c->infile, d->bits_offset);
	}
	else if(d->bitcount==8 && d->compression_type==CMPR_RLE8) {
		do_image_rle_4_8_24(c, d, c->infile, d->bits_offset);
	}
	else if(d->bitcount==4 && d->compression_type==CMPR_RLE4) {
		do_image_rle_4_8_24(c, d, c->infile, d->bits_offset);
	}
	else if(d->bitcount==24 && d->compression_type==CMPR_RLE24) {
		do_image_rle_4_8_24(c, d, c->infile, d->bits_offset);
	}
	else if(d->version==DE_BMPVER_64BIT) {
		do_image_64bit(c, d, c->infile, d->bits_offset);
	}
	else if(d->compression_type==CMPR_JPEG) {
		extract_embedded_image(c, d, "jpg");
	}
	else if(d->compression_type==CMPR_PNG) {
		extract_embedded_image(c, d, "png");
	}
	else if(d->bitcount==1 && d->compression_type==CMPR_HUFFMAN1D) {
		do_image_huffman1d(c, d);
	}
	else {
		de_err(c, "This type of BMP image is not supported");
	}

done:
	;
}

static void de_run_bmp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));
	d->fi = de_finfo_create(c);

	if(dbuf_memcmp(c->infile, 0, "BM", 2)) {
		de_err(c, "Not a BMP file.");
		goto done;
	}

	if(!detect_bmp_version(c, d)) {
		de_err(c, "Unidentified BMP version.");
		goto done;
	}

	switch(d->version) {
	case DE_BMPVER_OS2V1:
		if(d->fsize==26) {
			de_declare_fmt(c, "BMP, OS/2 v1");
		}
		else {
			de_declare_fmt(c, "BMP, OS/2 v1 or Windows v2");
		}
		break;
	case DE_BMPVER_OS2V2: de_declare_fmt(c, "BMP, OS/2 v2"); break;
	case DE_BMPVER_WINV345:
		switch(d->infohdrsize) {
		case 40: de_declare_fmt(c, "BMP, Windows v3"); break;
		case 108: de_declare_fmt(c, "BMP, Windows v4"); break;
		case 124: de_declare_fmt(c, "BMP, Windows v5"); break;
		default: de_declare_fmt(c, "BMP, Windows v3+");
		}
		break;
	case DE_BMPVER_64BIT:
		de_declare_fmt(c, "BMP, 64-bit");
		break;
	}

	pos = 0;
	if(!read_fileheader(c, d, pos)) goto done;
	pos += FILEHEADER_SIZE;
	if(!read_infoheader(c, d, pos)) goto done;
	pos += d->infohdrsize;
	if(d->bitfields_type==BF_SEGMENT) {
		de_dbg(c, "bitfields segment at %d, len=%d", (int)pos, (int)d->bitfields_segment_len);
		if(pos+d->bitfields_segment_len > d->bits_offset) {
			de_warn(c, "BITFIELDS segment at %d (size %d) overlaps bitmap at %d",
				(int)pos, (int)d->bitfields_segment_len, (int)d->bits_offset);
		}
		de_dbg_indent(c, 1);
		do_read_bitfields(c, d, pos, d->bitfields_segment_len);
		de_dbg_indent(c, -1);
		pos += d->bitfields_segment_len;
	}
	d->pal_pos = pos;
	do_read_palette(c, d);
	do_image(c, d);
	do_read_profile(c, d);

done:
	if(d) {
		de_finfo_destroy(c, d->fi);
		de_free(c, d);
	}
}

// Note that this function must work together with de_identify_vbm().
static int de_identify_bmp(deark *c)
{
	i64 fsize;
	i64 bits_offset;
	i64 infohdrsize;
	u32 compression_field = 0;
	int bmp_ext;
	u8 buf[6];

	de_read(buf, 0, sizeof(buf));
	if(de_memcmp(buf, "BM", 2)) {
		return 0;
	}

	bmp_ext = de_input_file_has_ext(c, "bmp");
	fsize = de_getu32le_direct(&buf[2]);
	bits_offset = de_getu32le(10);
	infohdrsize = de_getu32le(14);
	if(infohdrsize>=20) {
		compression_field = (u32)de_getu32le(14+16);
		// Don't detect KQP format as BMP
		if(infohdrsize==68 && compression_field==0x4745504aU) return 0;
	}

	if(infohdrsize<12) return 0;
	if(infohdrsize>256) return 0;
	if(bits_offset>=c->infile->len) return 0;
	if(bits_offset<14+infohdrsize) return 0;
	if(fsize==c->infile->len && bmp_ext) return 100;
	if(buf[2]==0xcb) {
		// Possible VBM file.
		// Windows BMP files are highly unlikely to start with 'B' 'M' \xcb,
		// because that would imply the file is an odd number of bytes in size,
		// which is legal but silly.
		if(bmp_ext) return 90;
		return 5;
	}

	if(bmp_ext) return 100;
	if(infohdrsize==12 || infohdrsize==40 || infohdrsize==108 ||
		infohdrsize==124)
	{
		return 100;
	}
	return 90;
}

void de_module_bmp(deark *c, struct deark_module_info *mi)
{
	mi->id = "bmp";
	mi->desc = "BMP (Windows or OS/2 bitmap)";
	mi->run_fn = de_run_bmp;
	mi->identify_fn = de_identify_bmp;
}

// **************************************************************************
// Pegasus JPEG (PIC JPEG)
// Konica KQP
// **************************************************************************

// This is a JPEG parser that does only what's needed for Pegasus JPEG conversion.

struct de_scan_jpeg_data_ctx {
	// Positions are absolute, and start with the start of the marker.
	// Lengths are the total length of the segment.
	u8 error_flag;
	u8 found_sos;
	u8 found_dht;
	u8 found_dqt;
	u8 found_sof;
	u8 found_jfif;
	u8 found_pic;
	u8 found_8bim;
	i64 soi_pos;
	i64 sos_pos;
	i64 sof_pos;
	i64 jfif_pos;
	i64 pic_pos;
	i64 pic_len;
	i64 _8bim_pos;
	i64 _8bim_len;
};

// Caller initializes scan_jpeg_data_ctx.
static void de_scan_jpeg_data(deark *c, dbuf *f, i64 pos1, i64 len,
	struct de_scan_jpeg_data_ctx *sd)
{
	i64 pos = pos1;
	i64 endpos = pos1+len;

	while(1) {
		i64 seg_startpos;
		i64 seg_len;
		u8 b1;

		if(pos+4 > endpos) goto done;
		seg_startpos = pos;
		if(dbuf_getbyte_p(f, &pos) != 0xff) {
			sd->error_flag = 1;
			goto done;
		}

		b1 = dbuf_getbyte_p(f, &pos);
		if(b1==0 || b1==0xff) {
			sd->error_flag = 1;
			goto done;
		}

		if(seg_startpos==pos1) { // Expecting SOI
			if(b1!=0xd8) goto done;
			sd->soi_pos = seg_startpos;
			continue;
		}

		if(b1==0xd9) { // EOI
			goto done;
		}

		// (Not expecting any other bare markers)

		seg_len = 2 + dbuf_getu16be_p(f, &pos);

		switch(b1) {
		case 0xc4: // DHT
			sd->found_dht = 1;
			break;
		case 0xda: // SOS
			sd->found_sos = 1;
			sd->sos_pos = seg_startpos;
			goto done; // we don't scan past SOS
		case 0xdb: // DQT
			sd->found_dqt = 1;
			break;
		case 0xe0: // APP0
			if(seg_len>=11 && !sd->found_jfif) {
				if(!dbuf_memcmp(f, seg_startpos+4, "JFIF\0", 5)) {
					sd->found_jfif = 1;
					sd->jfif_pos = seg_startpos;
				}
			}
			break;
		case 0xe1: // APP1
			if(seg_len>=11 && !sd->found_pic) {
				if(!dbuf_memcmp(f, seg_startpos+4, "PIC\0", 4)) {
					sd->found_pic = 1;
					sd->pic_pos = seg_startpos;
					sd->pic_len = seg_len;
				}
			}
			break;
		case 0xe2: // APP2
			if(seg_len>8 && !sd->found_8bim) {
				if(!dbuf_memcmp(f, seg_startpos+4, "8BIM", 4)) {
					sd->found_8bim = 1;
					sd->_8bim_pos = seg_startpos;
					sd->_8bim_len = seg_len;
				}
			}
			break;
		case 0xc0: case 0xc1: case 0xc2: case 0xc3:
		case 0xc5: case 0xc6: case 0xc7:
		case 0xc9: case 0xca: case 0xcb:
		case 0xcd: case 0xce: case 0xcf:
			sd->found_sof = 1;
			sd->sof_pos = seg_startpos;
			break;
		}

		pos = seg_startpos + seg_len;
	}

done:
	;
}

static void picjpeg_scale_qtable(u8 tbl[64], UI setting)
{
	size_t i;

	for(i=0; i<64; i++) {
		UI x;

		x = tbl[i];
		// The denominator 32 might not be exactly right, but assuming this is
		// the right idea, it's not too far off.
		x = (x * setting)/32;
		if(x>255) x = 255;
		else if(x<1) x = 1;
		tbl[i] = x;
	}
}

static void de_run_picjpeg(deark *c, de_module_params *mparams)
{
	i64 bits_offset;
	i64 jpeg_data_len;
	UI lum_setting;
	UI chr_setting;
	int need_errmsg = 0;
	i64 srcpos;
	dbuf *outf = NULL;
	i64 i;
	u32 hdr[7];
	struct de_bmpinfo bi;
	struct de_scan_jpeg_data_ctx sd;

	de_declare_fmt(c, "Pegasus JPEG or KQP");

	(void)fmtutil_get_bmpinfo(c, c->infile, &bi, 0, c->infile->len,
		DE_BMPINFO_HAS_FILEHEADER|DE_BMPINFO_CMPR_IS_4CC|DE_BMPINFO_NOERR);
	// TODO?: Read the palette (for dbg info)

	bits_offset = de_getu32le(10);
	jpeg_data_len = c->infile->len - bits_offset;
	if(jpeg_data_len<2) {
		need_errmsg = 1;
		goto done;
	}

	// Extended BMP header fields
	for(i=0; i<7; i++) {
		hdr[i] = (u32)de_getu32le(54+4*i);
		de_dbg(c, "bmp ext hdr[%u]: %u", (UI)i, (UI)hdr[i]);
	}

	// Validate the extra BMP fields.
	// Not sure what all these are.
	// [5] & [6] are related to sampling factors.
	if(hdr[0]!=44 || hdr[1]!=24 || hdr[2]!=0 || hdr[3]!=2 ||
		hdr[4]!=8)
	{
		need_errmsg = 1;
		goto done;
	}

	de_zeromem(&sd, sizeof(struct de_scan_jpeg_data_ctx));
	de_scan_jpeg_data(c, c->infile, bits_offset, c->infile->len-bits_offset, &sd);
	if(sd.error_flag) {
		need_errmsg = 1;
		goto done;
	}
	if(!sd.found_pic || !sd.found_sof || !sd.found_sos) {
		need_errmsg = 1;
		goto done;
	}
	if(sd.pic_pos >= sd.sof_pos) {
		need_errmsg = 1;
		goto done;
	}

	// Read from "PIC" segment.
	lum_setting = (UI)de_getbyte(sd.pic_pos+9);
	chr_setting = (UI)de_getbyte(sd.pic_pos+10);
	de_dbg(c, "luminance: %u", lum_setting);
	de_dbg(c, "chrominance: %u", chr_setting);

	de_dbg(c, "has DHT: %u", (UI)sd.found_dht);

	outf = dbuf_create_output_file(c, "jpg", NULL, 0);

	srcpos = sd.soi_pos;
	dbuf_copy(c->infile, srcpos, 2, outf);
	srcpos += 2;

	if(sd.found_jfif && sd.jfif_pos==srcpos) {
		// Copy everything before the JFIF version number
		dbuf_copy(c->infile, srcpos, 9, outf);
		// Sometimes the JFIF version number is wrong, so we correct it.
		dbuf_writebyte(outf, 1);
		dbuf_writebyte(outf, 2);
		srcpos += 11;
	}

	// Copy everything up to the PIC segment
	dbuf_copy(c->infile, srcpos, sd.pic_pos-srcpos, outf);

	srcpos = sd.pic_pos + sd.pic_len; // Skip the PIC segment

	// Convert the Photoshop Resources segment to a more standard format
	if(sd.found_8bim && sd._8bim_pos>=srcpos && sd._8bim_pos<sd.sof_pos) {
		// Copy everything up to 8BIM
		dbuf_copy(c->infile, srcpos, sd._8bim_pos-srcpos, outf);
		srcpos = sd._8bim_pos;

		dbuf_writeu16be(outf, 0xffed);
		dbuf_writeu16be(outf, 2 + 14 + (sd._8bim_len-4));
		dbuf_write(outf, (const u8*)"Photoshop 3.0\0", 14);
		dbuf_copy(c->infile, sd._8bim_pos+4, sd._8bim_len-4, outf);
		srcpos = sd._8bim_pos + sd._8bim_len;
	}

	// Copy everything up to SOF
	dbuf_copy(c->infile, srcpos, sd.sof_pos-srcpos, outf);
	srcpos = sd.sof_pos;

	// Insert DQT segments
	if(!sd.found_dqt) {
		u8 tmptbl[64];

		dbuf_write(outf, (const u8*)"\xff\xdb\x00\x43\x00", 5);
		fmtutil_get_std_jpeg_qtable(0, tmptbl);
		picjpeg_scale_qtable(tmptbl, lum_setting);
		dbuf_write(outf, tmptbl, 64);

		dbuf_write(outf, (const u8*)"\xff\xdb\x00\x43\x01", 5);
		fmtutil_get_std_jpeg_qtable(1, tmptbl);
		picjpeg_scale_qtable(tmptbl, chr_setting);
		dbuf_write(outf, tmptbl, 64);
	}

	// Copy everything up to SOS
	dbuf_copy(c->infile, srcpos, sd.sos_pos-srcpos, outf);
	srcpos = sd.sos_pos;

	// Insert DHT segment
	if(!sd.found_dht) {
		dbuf_write(outf, (const u8*)"\xff\xc4\x01\xa2\x00", 5);
		fmtutil_write_std_jpeg_dht(outf, 0);
		dbuf_writebyte(outf, 0x10);
		fmtutil_write_std_jpeg_dht(outf, 1);
		dbuf_writebyte(outf, 0x01);
		fmtutil_write_std_jpeg_dht(outf, 2);
		dbuf_writebyte(outf, 0x11);
		fmtutil_write_std_jpeg_dht(outf, 3);
	}

	// Copy the rest of the file
	dbuf_copy(c->infile, srcpos, c->infile->len-srcpos, outf);

done:
	if(need_errmsg) {
		de_err(c, "Can't convert this Pegasus JPEG file");
	}
	dbuf_close(outf);
}

static int de_identify_picjpeg(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"BM", 2)) return 0;
	if(de_getu32le(14) != 68) return 0;
	if((UI)de_getu32le(30) != 0x4745504aU) return 0;
	return 100;
}

void de_module_picjpeg(deark *c, struct deark_module_info *mi)
{
	mi->id = "picjpeg";
	mi->desc = "Pegasus JPEG, and KQP";
	mi->run_fn = de_run_picjpeg;
	mi->identify_fn = de_identify_picjpeg;
	mi->id_alias[0] = "kqp";
}

// **************************************************************************
// Raw DIB
// **************************************************************************

static void de_run_dib(deark *c, de_module_params *mparams)
{
	struct de_bmpinfo bi;
	unsigned int createflags = 0;
	dbuf *outf = NULL;
	int implicit_size = 0;
	i64 dib_len;
	const char *ext = "bmp";
	de_finfo *fi_to_use = NULL;

	if(mparams) {
		// If flags&0x01, try to calculate the proper file size, instead of trusting
		// the length of the input file.
		if(mparams->in_params.flags & 0x01) implicit_size = 1;

		if(mparams->in_params.flags & 0x80) ext = "preview.bmp";

		fi_to_use = mparams->in_params.fi;
	}

	if(de_havemodcode(c, mparams, 'X')) {
		createflags |= DE_CREATEFLAG_IS_AUX;
	}

	if(!fmtutil_get_bmpinfo(c, c->infile, &bi, 0, c->infile->len, 0)) {
		de_err(c, "Invalid DIB, or not a DIB file");
		goto done;
	}

	if(implicit_size) {
		dib_len = bi.total_size;
		if(dib_len > c->infile->len) {
			dib_len = c->infile->len;
		}
	}
	else {
		dib_len = c->infile->len;
	}

	outf = dbuf_create_output_file(c, ext, fi_to_use, createflags);

	de_dbg(c, "writing a BMP FILEHEADER");
	fmtutil_generate_bmpfileheader(c, outf, &bi, 14+dib_len);

	de_dbg(c, "copying DIB file");
	dbuf_copy(c->infile, 0, dib_len, outf);

done:
	dbuf_close(outf);
}

static int de_identify_dib(deark *c)
{
	i64 n;

	n = de_getu32le(0); // biSize
	if(n!=40) return 0;
	n = de_getu16le(12); // biPlanes
	if(n!=1) return 0;
	n = de_getu16le(14); // biBitCount
	if(n==1 || n==4 || n==8 || n==16 || n==24 || n==32) return 15;
	return 0;
}

// BMP file without a file header.
// This module constructs a BMP file header.
void de_module_dib(deark *c, struct deark_module_info *mi)
{
	mi->id = "dib";
	mi->desc = "DIB (raw Windows bitmap)";
	mi->run_fn = de_run_dib;
	mi->identify_fn = de_identify_dib;
}

// **************************************************************************
// DDB / "BMP v1"
// **************************************************************************

struct ddbctx_struct {
	i64 bmWidthBytes;
	UI createflags;
	u8 cdr_adjdim_flag;
	de_finfo *fi;
	u8 have_custom_pal;
	de_color pal[256];
};

static void ddb_convert_pal4planar(deark *c, struct ddbctx_struct *d,
	i64 fpos, de_bitmap *img)
{
	const i64 nplanes = 4;
	i64 rowspan;
	de_color pal16[16];

	rowspan = d->bmWidthBytes * nplanes;

	// The usual order seems to be
	//  row0_plane0x1, row0_plane0x2, row0_plane0x4, row0_plane0x8,
	//  row1_plane0x1, row1_plane0x2, row1_plane0x4, row1_plane0x8,
	//  ...
	// But I have seen another, and I see no way to detect/support it.

	de_copy_std_palette(DE_PALID_WIN16, 0, 0, 16, pal16, 16, 0);
	de_convert_image_paletted_planar(c->infile, fpos, nplanes, rowspan,
		d->bmWidthBytes, pal16, img, 0x2);
}

static void ddb_convert_pal8(deark *c, struct ddbctx_struct *d,
	i64 fpos, de_bitmap *img)
{
	i64 i, j;
	size_t k;
	int badcolorflag = 0;

	de_copy_std_palette(DE_PALID_WIN16, 1, 0, 8, &d->pal[0], 8, 0);
	de_copy_std_palette(DE_PALID_WIN16, 1, 8, 8, &d->pal[248], 8, 0);

	if(!d->have_custom_pal) {
		for(k=16; k<248; k++) {
			d->pal[k] = DE_MAKE_RGB(254, (u8)k ,254); // Just an arbitrary color
		}
	}

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			unsigned int palent;
			de_color clr;

			palent = de_getbyte(fpos+j*d->bmWidthBytes+i);
			if(!d->have_custom_pal && palent>=8 && palent<248) {
				badcolorflag = 1;
			}
			clr = d->pal[(UI)palent];

			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	if(badcolorflag) {
		de_warn(c, "Image uses nonportable colors");
	}
}

static void ddb_convert_32bit(deark *c, struct ddbctx_struct *d,
	i64 fpos, de_bitmap *img)
{
	de_convert_image_rgb(c->infile, fpos, d->bmWidthBytes, 4, img, DE_GETRGBFLAG_BGR);
}

static void do_ddb_bitmap(deark *c, struct ddbctx_struct *d, i64 pos1)
{
	i64 pos = pos1;
	unsigned int bmType;
	i64 bmWidth, bmHeight;
	i64 pdwidth;
	i64 bmPlanes;
	i64 bmBitsPixel;
	i64 src_realbitsperpixel;
	de_bitmap *img = NULL;

	bmType = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "bmType: %u", bmType);

	bmWidth = de_getu16le_p(&pos);
	bmHeight = de_getu16le_p(&pos);
	de_dbg_dimensions(c, bmWidth, bmHeight);

	d->bmWidthBytes = de_getu16le_p(&pos);
	de_dbg(c, "bytes/row: %d", (int)d->bmWidthBytes);

	bmPlanes = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)bmPlanes);

	bmBitsPixel = (i64)de_getbyte_p(&pos);
	de_dbg(c, "bmBitsPixel: %d", (int)bmBitsPixel);

	pos += 4; // Placeholder for a pointer?

	if((bmBitsPixel==1 && bmPlanes==1) ||
		(bmBitsPixel==1 && bmPlanes==4) ||
		(bmBitsPixel==8 && bmPlanes==1) ||
		(bmBitsPixel==32 && bmPlanes==1))
	{
		;
	}
	else {
		de_err(c, "This type of DDB bitmap is not supported "
			"(bmBitsPixel=%d, planes=%d)", (int)bmBitsPixel, (int)bmPlanes);
		goto done;
	}

	de_dbg(c, "pixels at %"I64_FMT, pos);

	src_realbitsperpixel = bmBitsPixel * bmPlanes;

	if(d->cdr_adjdim_flag && src_realbitsperpixel==1 &&
		bmWidth==bmHeight && (bmWidth==90 || bmWidth==128))
	{
		// See comments in the cdr_wl module about "adjdim".
		bmWidth--;
		bmHeight--;
		de_dbg(c, "adjusted dimensions: %"I64_FMT DE_CHAR_TIMES"%"I64_FMT,
			bmWidth, bmHeight);
	}

	if(!de_good_image_dimensions(c, bmWidth, bmHeight)) goto done;

	pdwidth = (d->bmWidthBytes*8) / bmBitsPixel;
	img = de_bitmap_create2(c, bmWidth, pdwidth, bmHeight, (src_realbitsperpixel==1)?1:3);

	if(bmBitsPixel==1 && bmPlanes==1) {
		de_convert_image_bilevel(c->infile, pos, d->bmWidthBytes, img, 0);
	}
	else if(bmBitsPixel==1 && bmPlanes==4) {
		ddb_convert_pal4planar(c, d, pos, img);
	}
	else if(bmBitsPixel==8 && bmPlanes==1) {
		ddb_convert_pal8(c, d, pos, img);
	}
	else if(bmBitsPixel==32 && bmPlanes==1) {
		ddb_convert_32bit(c, d, pos, img);
	}

	de_bitmap_write_to_file_finfo(img, d->fi, DE_CREATEFLAG_OPT_IMAGE | d->createflags);

done:
	de_bitmap_destroy(img);
}

static void de_run_ddb(deark *c, de_module_params *mparams)
{
	int has_filetype = 1;
	struct ddbctx_struct *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(struct ddbctx_struct));
	d->createflags = 0;

	if(de_havemodcode(c, mparams, 'N')) {
		has_filetype = 0;
	}
	if(de_havemodcode(c, mparams, 'X')) {
		d->createflags |= DE_CREATEFLAG_IS_AUX;
	}
	if(!c->padpix) {
		d->cdr_adjdim_flag = (u8)de_havemodcode(c, mparams, 'C');
	}
	if(mparams) {
		if(mparams->in_params.fi) {
			d->fi = mparams->in_params.fi;
		}
		// If not NULL, obj1 points to the  palette to use (must be de_color[256]).
		if(mparams->in_params.obj1) {
			d->have_custom_pal = 1;
			de_memcpy(d->pal, mparams->in_params.obj1, 256*sizeof(de_color));
		}
	}

	if(has_filetype) {
		unsigned int file_type;
		file_type = (unsigned int)de_getu16le_p(&pos);
		de_dbg(c, "file type: 0x%04x", file_type);
	}

	do_ddb_bitmap(c, d, pos);

	de_free(c, d);
}

void de_module_ddb(deark *c, struct deark_module_info *mi)
{
	mi->id = "ddb";
	mi->desc = "Windows DDB bitmap";
	mi->run_fn = de_run_ddb;
	mi->identify_fn = NULL;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// Jigsaw .jig
// Windows 3.x program by Walter A. Kuhn
// (JIGSAW20.ZIP, JIGPUZ00.ZIP, ...)
// **************************************************************************

static int looks_like_bmp_bytes(const u8 *buf, i64 len, UI flags)
{
	int ret;

	if(len<30) return 0;
	ret = de_memmatch(buf, (const u8*)"BM????\x00\x00\x00\x00??\x00\x00"
		"?\x00\x00\x00????????\x01\x00?\x00", 30, '?', 0);
	return ret;
}

static void de_run_jigsaw_wk(deark *c, de_module_params *mparams)
{
	i64 fsize;
	dbuf *outf = NULL;

	fsize = de_getu32le(2);
	if(fsize>c->infile->len) goto done;

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);
	dbuf_write(outf, (const u8*)"BM", 2);
	dbuf_copy(c->infile, 2, fsize-2, outf);

done:
	dbuf_close(outf);
}

static int de_identify_jigsaw_wk(deark *c)
{
	i64 fsize;
	int ret;
	u8 buf[32];

	if(dbuf_memcmp(c->infile, 0, "JG", 2)) {
		return 0;
	}

	fsize = de_getu32le(2);
	if(fsize>c->infile->len) return 0;

	de_read(buf, 0, sizeof(buf));
	buf[0] = 'B';
	buf[1] = 'M';
	ret = looks_like_bmp_bytes(buf, sizeof(buf), 0);
	if(ret) {
		return 95;
	}

	return 0;
}

void de_module_jigsaw_wk(deark *c, struct deark_module_info *mi)
{
	mi->id = "jigsaw_wk";
	mi->desc = "Jigsaw .jig";
	mi->run_fn = de_run_jigsaw_wk;
	mi->identify_fn = de_identify_jigsaw_wk;
}
