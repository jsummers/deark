// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows BMP image

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_bmp);
DE_DECLARE_MODULE(de_module_kqp);
DE_DECLARE_MODULE(de_module_dib);
DE_DECLARE_MODULE(de_module_ddb);

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

	if(d->bitcount==0 || d->bitcount==1 || d->bitcount==2 || d->bitcount==4 ||
		d->bitcount==8 || d->bitcount==16 || d->bitcount==24 || d->bitcount==32)
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
	de_bitmap_write_to_file_finfo(img, d->fi, d->extra_createflags);
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
		else {
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
// Konica KQP
// **************************************************************************

static const u8 kqp_qtable_data[] = {
	0xff,0xdb,0x00,0x84,0x00,0x07,0x04,0x05,0x06,0x05,0x04,0x07,0x06,0x05,0x06,0x07,
	0x07,0x07,0x08,0x0a,0x11,0x0b,0x0a,0x09,0x09,0x0a,0x15,0x0f,0x10,0x0c,0x11,0x19,
	0x16,0x1a,0x1a,0x18,0x16,0x18,0x18,0x1c,0x1f,0x28,0x22,0x1c,0x1d,0x26,0x1e,0x18,
	0x18,0x23,0x2f,0x23,0x26,0x29,0x2a,0x2d,0x2d,0x2d,0x1b,0x21,0x31,0x34,0x31,0x2b,
	0x34,0x28,0x2c,0x2d,0x2b,0x01,0x07,0x07,0x07,0x0a,0x09,0x0a,0x14,0x0b,0x0b,0x14,
	0x2b,0x1c,0x18,0x1c,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,
	0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,
	0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,0x2b,
	0x2b,0x2b,0x2b,0x2b,0x2b,0x2b };

static const u8 kqp_htable_data[] = {
	0xff,0xc4,0x01,0xa2,0x00,0x00,0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
	0x0b,0x10,0x00,0x02,0x01,0x03,0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,
	0x01,0x7d,0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,
	0x61,0x07,0x22,0x71,0x14,0x32,0x81,0x91,0xa1,0x08,0x23,0x42,0xb1,0xc1,0x15,0x52,
	0xd1,0xf0,0x24,0x33,0x62,0x72,0x82,0x09,0x0a,0x16,0x17,0x18,0x19,0x1a,0x25,0x26,
	0x27,0x28,0x29,0x2a,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,
	0x68,0x69,0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x83,0x84,0x85,0x86,0x87,
	0x88,0x89,0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,
	0xa6,0xa7,0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,
	0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,
	0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,
	0xf7,0xf8,0xf9,0xfa,0x01,0x00,0x03,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
	0x0b,0x11,0x00,0x02,0x01,0x02,0x04,0x04,0x03,0x04,0x07,0x05,0x04,0x04,0x00,0x01,
	0x02,0x77,0x00,0x01,0x02,0x03,0x11,0x04,0x05,0x21,0x31,0x06,0x12,0x41,0x51,0x07,
	0x61,0x71,0x13,0x22,0x32,0x81,0x08,0x14,0x42,0x91,0xa1,0xb1,0xc1,0x09,0x23,0x33,
	0x52,0xf0,0x15,0x62,0x72,0xd1,0x0a,0x16,0x24,0x34,0xe1,0x25,0xf1,0x17,0x18,0x19,
	0x1a,0x26,0x27,0x28,0x29,0x2a,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,
	0x47,0x48,0x49,0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,
	0x67,0x68,0x69,0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x82,0x83,0x84,0x85,
	0x86,0x87,0x88,0x89,0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,
	0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,
	0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,
	0xd9,0xda,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf2,0xf3,0xf4,0xf5,0xf6,
	0xf7,0xf8,0xf9,0xfa };

static void de_run_kqp(deark *c, de_module_params *mparams)
{
	i64 bits_offset;
	i64 jpeg_data_len;
	int need_errmsg = 0;
	dbuf *outf = NULL;
	struct de_bmpinfo bi;

	de_declare_fmt(c, "KQP (Konica)");

	(void)fmtutil_get_bmpinfo(c, c->infile, &bi, 0, c->infile->len,
		DE_BMPINFO_HAS_FILEHEADER|DE_BMPINFO_CMPR_IS_4CC|DE_BMPINFO_NOERR);
	// TODO?: Read the palette (for dbg info)

	bits_offset = de_getu32le(10);
	jpeg_data_len = c->infile->len - bits_offset;
	if(jpeg_data_len<2) {
		need_errmsg = 1;
		goto done;
	}

	// Do a quick & dirty splicing of the JPEG data to insert the correct DQT and
	// DHT segments.

	// TODO: Use a real JPEG parser here, to find the SOF segment, etc.
	// See also the similar code for thumbsdb_msrgba in the cfb module.

	// First, try to make sure the data is in the format we expect.
	if((UI)de_getu16be(bits_offset) != 0xffd8U) { // SOI
		need_errmsg = 1;
		goto done;
	}
	if((UI)de_getu32be(bits_offset+6) != 0x4a464946U) { // "JFIF"
		need_errmsg = 1;
		goto done;
	}
	if((UI)de_getu32be(bits_offset+28) != 0x010e0e01U) { // Q table indicator(?)
		need_errmsg = 1;
		goto done;
	}
	if((UI)de_getu32be(bits_offset+32) != 0xffc00011U) { // SOF
		need_errmsg = 1;
		goto done;
	}

	outf = dbuf_create_output_file(c, "jpg", NULL, 0);

	// Everything before the JFIF version number
	dbuf_copy(c->infile, bits_offset, 11, outf);

	dbuf_writebyte(outf, 1); // Correct the JFIF version number
	dbuf_writebyte(outf, 2);

	// Everything else up to the source SOF
	dbuf_copy(c->infile, bits_offset+13, 19, outf);

	// TODO: It's almost certain that some KQP files use different quantization
	// tables ( https://groups.google.com/g/rec.photo.digital/c/lkz_8p8S2U0 ),
	// but I don't know how to support them.
	dbuf_write(outf, kqp_qtable_data, DE_ARRAYCOUNT(kqp_qtable_data)); // New DQT

	dbuf_copy(c->infile, bits_offset+32, 19, outf); // SOF

	dbuf_write(outf, kqp_htable_data, DE_ARRAYCOUNT(kqp_htable_data)); // New DHT

	// The rest of the file
	dbuf_copy(c->infile, bits_offset+51, c->infile->len-51, outf);

done:
	if(need_errmsg) {
		de_err(c, "Can't convert this KQP file");
	}
	dbuf_close(outf);
}

static int de_identify_kqp(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"BM\0\0\0\0", 6)) return 0;
	if(de_getu32le(14) != 68) return 0;
	if((UI)de_getu32le(30) != 0x4745504aU) return 0;
	return 100;
}

void de_module_kqp(deark *c, struct deark_module_info *mi)
{
	mi->id = "kqp";
	mi->desc = "KQP (Konica)";
	mi->run_fn = de_run_kqp;
	mi->identify_fn = de_identify_kqp;
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
	de_finfo *fi;
	u8 have_custom_pal;
	de_color pal[256];
};

static void ddb_convert_pal4planar(deark *c, struct ddbctx_struct *d,
	i64 fpos, de_bitmap *img)
{
	const i64 nplanes = 4;
	i64 i, j, plane;
	i64 rowspan;
	u8 *rowbuf = NULL;
	static const u32 pal16[16] = {
		0x000000,0x800000,0x008000,0x808000,0x000080,0x800080,0x008080,0x808080,
		0xc0c0c0,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xffffff
	};

	rowspan = d->bmWidthBytes * nplanes;
	rowbuf = de_malloc(c, rowspan);

	// The usual order seems to be
	//  row0_plane0x1, row0_plane0x2, row0_plane0x4, row0_plane0x8,
	//  row1_plane0x1, row1_plane0x2, row1_plane0x4, row1_plane0x8,
	//  ...
	// But I have seen another, and I see no way to detect/support it.

	for(j=0; j<img->height; j++) {
		de_read(rowbuf, fpos+j*rowspan, rowspan);

		for(i=0; i<img->width; i++) {
			unsigned int palent = 0;
			u32 clr;

			for(plane=0; plane<nplanes; plane++) {
				unsigned int n = 0;
				i64 idx;

				idx = d->bmWidthBytes*plane + i/8;
				if(idx<rowspan) n = rowbuf[idx];
				if(n & (1<<(7-i%8))) {
					palent |= (1<<plane);
				}
			}

			clr = DE_MAKE_OPAQUE(pal16[palent]);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}

	de_free(c, rowbuf);
}

static void ddb_convert_pal8(deark *c, struct ddbctx_struct *d,
	i64 fpos, de_bitmap *img)
{
	i64 i, j;
	int badcolorflag = 0;
	// Palette is from libwps (except I might have red/blue swapped it).
	// I haven't confirmed that it's correct.
	static const de_color pal_part1[8] = {
		0x000000,0x800000,0x008000,0x808000,0x000080,0x800080,0x008080,0xc0c0c0
	};
	static const de_color pal_part2[8] = {
		0x808080,0xff0000,0x00ff00,0xffff00,0x0000ff,0xff00ff,0x00ffff,0xffffff
	};

	de_memcpy(&d->pal[0], pal_part1, 8*sizeof(de_color));
	de_memcpy(&d->pal[248], pal_part2, 8*sizeof(de_color));

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			unsigned int palent;
			de_color clr;

			palent = de_getbyte(fpos+j*d->bmWidthBytes+i);
			if(!d->have_custom_pal && palent>=8 && palent<248) {
				clr = DE_MAKE_RGB(254,palent,254); // Just an arbitrary color
				badcolorflag = 1;
			}
			else {
				clr = DE_MAKE_OPAQUE(d->pal[(UI)palent]);
			}

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

	de_bitmap_write_to_file_finfo(img, d->fi, d->createflags);

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
