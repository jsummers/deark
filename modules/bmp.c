// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows BMP image

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_bmp);
DE_DECLARE_MODULE(de_module_dib);

#define FILEHEADER_SIZE 14

#define CODE_LINK 0x4c494e4bU
#define CODE_MBED 0x4d424544U

struct bitfieldsinfo {
	de_uint32 mask;
	unsigned int shift;
	double scale; // Amount to multiply the sample value by, to scale it to [0..255]
};

typedef struct localctx_struct {
#define DE_BMPVER_OS2V1    1 // OS2v1 or Windows v2
#define DE_BMPVER_OS2V2    2
#define DE_BMPVER_WINV345  3 // Windows v3+
	int version;

	de_int64 fsize; // The "file size" field in the file header
	de_int64 bits_offset; // The bfOffBits field in the file header
	de_int64 infohdrsize;
	de_int64 bitcount;
	de_uint32 compression_field;
	de_int64 size_image; // biSizeImage
	de_int64 width, height;
	int top_down;
	de_int64 pal_entries; // Actual number stored in file. 0 means no palette.
	de_int64 pal_pos;
	de_int64 bytes_per_pal_entry;
	int pal_is_grayscale;

#define BF_NONE       0 // Bitfields are not applicable
#define BF_DEFAULT    1 // Use the default bitfields for this bit depth
#define BF_SEGMENT    2 // Use the bitfields segment in the file
#define BF_IN_HEADER  3 // Use the bitfields fields in the infoheader
	int bitfields_type;
	de_int64 bitfields_segment_len; // Used if bitfields_type==BF_SEGMENT

	de_int64 xpelspermeter, ypelspermeter;

#define CMPR_NONE       0
#define CMPR_RLE4       11
#define CMPR_RLE8       12
#define CMPR_RLE24      13
#define CMPR_JPEG       14
#define CMPR_PNG        15
#define CMPR_HUFFMAN1D  16
	int compression_type;

	struct de_fourcc cstype4cc;
	de_int64 profile_offset_raw;
	de_int64 profile_offset;
	de_int64 profile_size;

	de_int64 rowspan;
	struct bitfieldsinfo bitfield[4];
	de_uint32 pal[256];
} lctx;

// Sets d->version, and certain header fields.
static int detect_bmp_version(deark *c, lctx *d)
{
	de_int64 pos;

	pos = 0;
	d->fsize = de_getui32le(pos+2);

	pos += FILEHEADER_SIZE;
	d->infohdrsize = de_getui32le(pos);

	if(d->infohdrsize<=12) {
		d->bitcount = de_getui16le(pos+10);
	}
	else {
		d->bitcount = de_getui16le(pos+14);
	}

	if(d->infohdrsize==12) {
		d->version = DE_BMPVER_OS2V1;
		return 1;
	}
	if(d->infohdrsize<16) {
		return 0;
	}

	if(d->infohdrsize>=20) {
		d->compression_field = (de_uint32)de_getui32le(pos+16);
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

static int read_fileheader(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "file header at %d", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "bfSize: %d", (int)d->fsize);
	d->bits_offset = de_getui32le(pos+10);
	de_dbg(c, "bfOffBits: %d", (int)d->bits_offset);
	de_dbg_indent(c, -1);
	return 1;
}

// Calculate .shift and .scale
static void update_bitfields_info(deark *c, lctx *d)
{
	de_int64 k;
	de_uint32 tmpmask;

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

static void do_read_bitfields(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 k;

	if(len>16) len=16;
	for(k=0; 4*k<len; k++) {
		d->bitfield[k].mask = (de_uint32)de_getui32le(pos+4*k);
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
static int read_infoheader(deark *c, lctx *d, de_int64 pos)
{
	de_int64 height_raw;
	de_int64 clr_used_raw;
	int cmpr_ok;
	int retval = 0;
	de_int64 nplanes;

	de_dbg(c, "info header at %d", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "info header size: %d", (int)d->infohdrsize);

	if(d->version==DE_BMPVER_OS2V1) {
		d->width = de_getui16le(pos+4);
		d->height = de_getui16le(pos+6);
		nplanes = de_getui16le(pos+8);
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
		nplanes = de_getui16le(pos+12);
	}
	de_dbg_dimensions(c, d->width, d->height);
	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}
	if(d->top_down) {
		de_dbg(c, "orientation: top-down");
	}

	de_dbg(c, "planes: %d", (int)nplanes);

	// Already read, in detect_bmp_version()
	de_dbg(c, "bits/pixel: %d", (int)d->bitcount);

	if(d->bitcount!=0 && d->bitcount!=1 && d->bitcount!=2 && d->bitcount!=4 &&
		d->bitcount!=8 && d->bitcount!=16 && d->bitcount!=24 && d->bitcount!=32)
	{
		de_err(c, "Bad bits/pixel: %d", (int)d->bitcount);
		goto done;
	}

	if(d->version==DE_BMPVER_OS2V1) {
		d->bytes_per_pal_entry = 3;
	}
	else {
		char cmprname[80];
		// d->compression_field was already read, in detect_bmp_version()
		de_fmtutil_get_bmp_compression_name(d->compression_field, cmprname, sizeof(cmprname),
			(d->version==DE_BMPVER_OS2V2));
		de_dbg(c, "compression (etc.): %u (%s)", (unsigned int)d->compression_field, cmprname);
		d->bytes_per_pal_entry = 4;
	}

	d->compression_type = CMPR_NONE; // Temporary default

	cmpr_ok = 0;
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

	if(!cmpr_ok) {
		de_err(c, "Unsupported compression type: %d", (int)d->compression_field);
		goto done;
	}

	if(d->infohdrsize>=24) {
		d->size_image = de_getui32le(pos+20);
		de_dbg(c, "biSizeImage: %d", (int)d->size_image);
	}

	if(d->infohdrsize>=32) {
		d->xpelspermeter = de_geti32le(pos+24);
		d->ypelspermeter = de_geti32le(pos+28);
		de_dbg(c, "density: %d"DE_CHAR_TIMES"%d pixels/meter", (int)d->xpelspermeter, (int)d->ypelspermeter);
	}

	if(d->infohdrsize>=36)
		clr_used_raw = de_getui32le(pos+32);
	else
		clr_used_raw = 0;

	if(d->bitcount>=1 && d->bitcount<=8 && clr_used_raw==0) {
		d->pal_entries = ((de_int64)1)<<d->bitcount;
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
		de_uint32 intent;
		intent = (de_uint32)de_getui32le(pos+108);
		de_dbg(c, "intent: %u", (unsigned int)intent);
	}

	if(d->version==DE_BMPVER_WINV345 && d->infohdrsize>=124 &&
		(d->cstype4cc.id==CODE_MBED || d->cstype4cc.id==CODE_LINK))
	{
		d->profile_offset_raw = de_getui32le(pos+112);
		de_dbg(c, "profile offset: %d+%d", FILEHEADER_SIZE,
			(int)d->profile_offset_raw);
		d->profile_size = de_getui32le(pos+116);
		de_dbg(c, "profile size: %d", (int)d->profile_size);
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
	de_int64 pal_space_avail;
	de_int64 pal_bytes_if_3bpc;
	de_int64 pal_bytes_if_4bpc;
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
	de_int64 pal_size_in_bytes;

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

	img = de_bitmap_create(c, d->width, d->height, bypp);
	img->flipped = !d->top_down;
	if(d->xpelspermeter>0 && d->ypelspermeter>0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = (double)d->xpelspermeter * 0.0254;
		img->ydens = (double)d->ypelspermeter * 0.0254;
	}
	return img;
}

static void do_image_paletted(deark *c, lctx *d, dbuf *bits, de_int64 bits_offset)
{
	de_bitmap *img = NULL;

	img = bmp_bitmap_create(c, d, d->pal_is_grayscale?1:3);
	de_convert_image_paletted(bits, bits_offset,
		d->bitcount, d->rowspan, d->pal, img, 0);
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_image_24bit(deark *c, lctx *d, dbuf *bits, de_int64 bits_offset)
{
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_uint32 clr;

	img = bmp_bitmap_create(c, d, 3);
	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			clr = dbuf_getRGB(bits, bits_offset + j*d->rowspan + 3*i, DE_GETRGBFLAG_BGR);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_image_16_32bit(deark *c, lctx *d, dbuf *bits, de_int64 bits_offset)
{
	de_bitmap *img = NULL;
	de_int64 i, j;
	int has_transparency;
	de_uint32 v;
	de_int64 k;
	de_byte sm[4];

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
		for(i=0; i<d->width; i++) {
			if(d->bitcount==16) {
				v = (de_uint32)dbuf_getui16le(bits, bits_offset + j*d->rowspan + 2*i);
			}
			else {
				v = (de_uint32)dbuf_getui32le(bits, bits_offset + j*d->rowspan + 4*i);
			}

			for(k=0; k<4; k++) {
				if(d->bitfield[k].mask!=0) {
					sm[k] = (de_byte)(0.5 + d->bitfield[k].scale * (double)((v&d->bitfield[k].mask) >> d->bitfield[k].shift));
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
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_image_rle_4_8_24(deark *c, lctx *d, dbuf *bits, de_int64 bits_offset)
{
	de_int64 pos;
	de_int64 xpos, ypos;
	de_byte b1, b2;
	de_byte b;
	de_byte cr, cg, cb;
	de_bitmap *img = NULL;
	de_uint32 clr1, clr2;
	de_int64 num_bytes;
	de_int64 num_pixels;
	de_int64 k;
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
		if(ypos==(d->height-1) && xpos>=d->width) break;

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
			xpos += (de_int64)b;
			b = dbuf_getbyte(bits, pos++);
			ypos += (de_int64)b;
		}
		else if(b1==0) { // b2 uncompressed pixels follow
			num_pixels = (de_int64)b2;
			if(d->compression_type==CMPR_RLE4) {
				de_int64 pixels_copied = 0;
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
			num_pixels = (de_int64)b1;
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

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);
	de_bitmap_destroy(img);
}

static void extract_embedded_image(deark *c, lctx *d, const char *ext)
{
	de_int64 nbytes;

	nbytes = d->size_image;

	if(nbytes<1 || nbytes>(c->infile->len - d->bits_offset)) {
		nbytes = c->infile->len - d->bits_offset;
	}
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
	else {
		de_err(c, "This type of BMP image is not supported");
	}

done:
	;
}

static void de_run_bmp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

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
	de_free(c, d);
}

// Note that this function must work together with de_identify_vbm().
static int de_identify_bmp(deark *c)
{
	de_int64 fsize;
	de_int64 bits_offset;
	de_int64 infohdrsize;
	int bmp_ext;
	de_byte buf[6];

	de_read(buf, 0, sizeof(buf));
	if(de_memcmp(buf, "BM", 2)) {
		return 0;
	}

	bmp_ext = de_input_file_has_ext(c, "bmp");
	fsize = de_getui32le_direct(&buf[2]);
	bits_offset = de_getui32le(10);
	infohdrsize = de_getui32le(14);

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

static void de_run_dib(deark *c, de_module_params *mparams)
{
	struct de_bmpinfo bi;
	unsigned int createflags = 0;
	dbuf *outf = NULL;

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, 0, c->infile->len, 0)) {
		de_err(c, "Invalid DIB, or not a DIB file");
		goto done;
	}

	if(mparams && mparams->in_params.codes && de_strchr(mparams->in_params.codes, 'X')) {
		createflags |= DE_CREATEFLAG_IS_AUX;
	}

	outf = dbuf_create_output_file(c, "bmp", NULL, createflags);

	de_dbg(c, "writing a BMP FILEHEADER");
	de_fmtutil_generate_bmpfileheader(c, outf, &bi, 14+c->infile->len);

	de_dbg(c, "copying DIB file");
	dbuf_copy(c->infile, 0, c->infile->len, outf);

done:
	dbuf_close(outf);
}

static int de_identify_dib(deark *c)
{
	de_int64 n;

	n = de_getui32le(0); // biSize
	if(n!=40) return 0;
	n = de_getui16le(12); // biPlanes
	if(n!=1) return 0;
	n = de_getui16le(14); // biBitCount
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
