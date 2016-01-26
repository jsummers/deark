// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Windows BMP image

#include <deark-config.h>
#include <deark-modules.h>

#define FILEHEADER_SIZE 14

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
	de_int64 width, height;
	int top_down;
	de_int64 pal_entries; // Actual number stored in file. 0 means no palette.
	de_int64 pal_pos;
	de_int64 bytes_per_pal_entry;
	int pal_is_grayscale;
	int uses_bitfields;
	int has_bitfields_segment;
	de_int64 bitfields_segment_pos;
	de_int64 bitfields_segment_len;
	de_int64 xpelspermeter, ypelspermeter;

#define CMPR_NONE       0
#define CMPR_RLE        1 // RLE4 or RLE8 or RLE24, depending on bitcount
#define CMPR_JPEG       2
#define CMPR_PNG        3
#define CMPR_HUFFMAN1D  4
	int compression_type;

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
	de_dbg(c, "file header at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "bfSize: %d\n", (int)d->fsize);
	d->bits_offset = de_getui32le(pos+10);
	de_dbg(c, "bfOffBits: %d\n", (int)d->bits_offset);
	de_dbg_indent(c, -1);
	return 1;
}

static int read_infoheader_12(deark *c, lctx *d, de_int64 pos)
{
	d->width = de_getui16le(pos+4);
	d->height = de_getui16le(pos+6);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);
	de_dbg(c, "bits/pixel: %d\n", (int)d->bitcount);

	if(d->bitcount!=1 && d->bitcount!=2 && d->bitcount!=4 &&
		d->bitcount!=8 && d->bitcount!=24)
	{
		de_err(c, "Bad bits/pixel: %d\n", (int)d->bitcount);
		return 0;
	}

	d->bytes_per_pal_entry = 3;
	if(d->bitcount<=8) {
		d->pal_entries = ((de_int64)1)<<d->bitcount;
	}

	d->compression_type = CMPR_NONE;
	return 1;
}

// This function is for reading the first 40 bytes of a Windows v3
// (or OS/2v2) style infoheader.
static int read_infoheader_40(deark *c, lctx *d, de_int64 pos)
{
	de_int64 height_raw;
	de_int64 clr_used_raw;
	int cmpr_ok;
	int retval = 0;

	de_dbg(c, "bits/pixel: %d\n", (int)d->bitcount);
	de_dbg(c, "compression (etc.): %d\n", (int)d->compression_field);
	d->width = dbuf_geti32le(c->infile, pos+4);
	height_raw = dbuf_geti32le(c->infile, pos+8);
	if(height_raw<0) {
		d->top_down = 1;
		d->height = -height_raw;
	}
	else {
		d->height = height_raw;
	}
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	if(d->bitcount!=1 && d->bitcount!=2 && d->bitcount!=4 &&
		d->bitcount!=8 && d->bitcount!=16 && d->bitcount!=24 &&
		d->bitcount!=32)
	{
		de_err(c, "Bad bits/pixel: %d\n", (int)d->bitcount);
		goto done;
	}

	// Fields after this point (after the first 16 bytes) should not be
	// assumed to exist.

	d->bytes_per_pal_entry = 4;
	d->compression_type = CMPR_NONE;

	cmpr_ok = 0;
	switch(d->compression_field) {
	case 0: // BI_RGB
		cmpr_ok = 1;
		break;
	case 1: // BI_RLE8
		if(d->bitcount==8) {
			d->compression_type=CMPR_RLE;
			cmpr_ok = 1;
		}
		break;
	case 2: // BI_RLE4
		if(d->bitcount==4) {
			d->compression_type=CMPR_RLE;
			cmpr_ok = 1;
		}
		break;
	case 3: // BI_BITFIELDS or Huffman_1D
		if(d->version==DE_BMPVER_OS2V2) {
			cmpr_ok = 1;
			d->compression_type=CMPR_HUFFMAN1D;
		}
		else if(d->bitcount==16 || d->bitcount==32) {
			cmpr_ok = 1;
			d->uses_bitfields = 1;
			if(d->infohdrsize<52) {
				d->has_bitfields_segment = 1;
				d->bitfields_segment_len = 12;
			}
		}
		break;
	case 4: // BI_JPEG or RLE24
		if(d->version==DE_BMPVER_OS2V2) {
			if(d->bitcount==24) {
				d->compression_type=CMPR_RLE;
			}
		}
		else {
			d->compression_type=CMPR_JPEG;
		}
		cmpr_ok = 1;
		break;
	case 5: // BI_PNG
		d->compression_type=CMPR_PNG;
		cmpr_ok = 1;
		break;
	case 6: // BI_ALPHABITFIELDS
		if(d->bitcount==16 || d->bitcount==32) {
			cmpr_ok = 1;
			d->uses_bitfields = 1;
			if(d->infohdrsize<56) {
				d->has_bitfields_segment = 1;
				d->bitfields_segment_len = 16;
			}
		}
		break;
	}

	if(!cmpr_ok) {
		de_err(c, "Unsupported compression type: %d\n", (int)d->compression_field);
		goto done;

	}

	if(d->infohdrsize>=32) {
		d->xpelspermeter = dbuf_geti32le(c->infile, pos+24);
		d->ypelspermeter = dbuf_geti32le(c->infile, pos+28);
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
	de_dbg(c, "number of palette colors: %d\n", (int)d->pal_entries);

	retval = 1;
done:
	return retval;
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
		de_dbg(c, "mask[%d]: 0x%08x\n", (int)k, (unsigned int)d->bitfield[k].mask);
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

// Read bytes after the first 40 of a Windows v4+ style infoheader.
// pos is the file offset of the start of the infoheader.
static int read_infoheader_winv4plus(deark *c, lctx *d, de_int64 pos)
{
	if(d->infohdrsize<52) goto done;

	if(d->uses_bitfields) {
		do_read_bitfields(c, d, pos+40, d->infohdrsize>=56 ? 16 : 12);
	}

done:
	return 1;
}

static int read_infoheader(deark *c, lctx *d, de_int64 pos)
{
	int retval = 0;

	// Note: Some of the BMP parsing code is duplicated in the
	// de_fmtutil_get_bmpinfo() library function. The BMP module's needs are
	// not quite aligned with what that function is intended for, and it
	// would be too messy to try to add the necessary features to it.

	de_dbg(c, "info header at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "info header size: %d\n", (int)d->infohdrsize);
	if(d->version==DE_BMPVER_OS2V1) {
		if(!read_infoheader_12(c, d, pos)) goto done;
	}
	else if(d->version==DE_BMPVER_OS2V2) {
		if(!read_infoheader_40(c, d, pos)) goto done;
	}
	else {
		if(!read_infoheader_40(c, d, pos)) goto done;
		if(!read_infoheader_winv4plus(c, d, pos)) goto done;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}

	if(d->uses_bitfields && !d->has_bitfields_segment && d->infohdrsize<52) {
		set_default_bitfields(c, d);
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_read_palette(deark *c, lctx *d)
{
	de_int64 k;

	if(d->pal_entries<1) return;
	de_dbg(c, "color table at %d, %d entries\n", (int)d->pal_pos, (int)d->pal_entries);

	de_dbg_indent(c, 1);
	for(k=0; k<d->pal_entries && k<256; k++) {
		d->pal[k] = dbuf_getRGB(c->infile, d->pal_pos + k*d->bytes_per_pal_entry, DE_GETRGBFLAG_BGR);
		de_dbg_pal_entry(c, k, d->pal[k]);
	}

	d->pal_is_grayscale = de_is_grayscale_palette(d->pal, d->pal_entries);
	de_dbg_indent(c, -1);
}

// A wrapper for de_bitmap_create()
static struct deark_bitmap *bmp_bitmap_create(deark *c, lctx *d, int bypp)
{
	struct deark_bitmap *img;

	img = de_bitmap_create(c, d->width, d->height, bypp);
	img->flipped = !d->top_down;
	if(d->xpelspermeter>0 && d->ypelspermeter>0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = (double)d->xpelspermeter * 0.0254;
		img->ydens = (double)d->ypelspermeter * 0.0254;
	}
	return img;
}

static void do_image_paletted(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_uint32 clr;
	de_byte b;

	img = bmp_bitmap_create(c, d, d->pal_is_grayscale?1:3);
	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			b = de_get_bits_symbol(c->infile, d->bitcount, d->bits_offset + j*d->rowspan, i);
			clr = d->pal[(unsigned int)b];
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_image_24bit(deark *c, lctx *d)
{
	struct deark_bitmap *img = NULL;
	de_int64 i, j;
	de_uint32 clr;

	img = bmp_bitmap_create(c, d, 3);
	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			clr = dbuf_getRGB(c->infile, d->bits_offset + j*d->rowspan + 3*i, DE_GETRGBFLAG_BGR);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
	de_bitmap_write_to_file(img, NULL);
	de_bitmap_destroy(img);
}

static void do_image(deark *c, lctx *d)
{
	de_dbg(c, "bitmap at %d\n", (int)d->bits_offset);

	if(d->bits_offset >= c->infile->len) {
		de_err(c, "Bad bits-offset field\n");
		goto done;
	}

	d->rowspan = ((d->bitcount*d->width +31)/32)*4;

	if(d->bitcount>=1 && d->bitcount<=8 && d->compression_type==CMPR_NONE) {
		do_image_paletted(c, d);
	}
	else if(d->bitcount==24 && d->compression_type==CMPR_NONE) {
		do_image_24bit(c, d);
	}
	// TODO: Support more image types here.
	else {
		de_err(c, "This type of image is not supported\n");
	}

done:
	;
}

static void de_run_bmp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	char *s = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	if(dbuf_memcmp(c->infile, 0, "BM", 2)) {
		de_err(c, "Not a BMP file.\n");
		goto done;
	}

	if(!detect_bmp_version(c, d)) {
		de_err(c, "Unidentified BMP version.\n");
		goto done;
	}

	switch(d->version) {
	case DE_BMPVER_OS2V1: s="OS/2 v1 or Windows v2"; break;
	case DE_BMPVER_OS2V2: s="OS/2 v2"; break;
	case DE_BMPVER_WINV345: s="Windows v3+"; break;
	default: s="(unknown)";
	}
	de_dbg(c, "BMP version detected: %s\n", s);

	pos = 0;
	if(!read_fileheader(c, d, pos)) goto done;
	pos += FILEHEADER_SIZE;
	if(!read_infoheader(c, d, pos)) goto done;
	pos += d->infohdrsize;
	if(d->has_bitfields_segment) {
		d->bitfields_segment_pos = pos;
		de_dbg(c, "bitfields segment at %d, len=%d\n", (int)d->bitfields_segment_pos, (int)d->bitfields_segment_len);
		de_dbg_indent(c, 1);
		do_read_bitfields(c, d, d->bitfields_segment_pos, d->bitfields_segment_len);
		de_dbg_indent(c, -1);
		pos += d->bitfields_segment_len;
	}
	d->pal_pos = pos;
	do_read_palette(c, d);
	do_image(c, d);

done:
	de_free(c, d);
}

static int de_identify_bmp(deark *c)
{
	// TODO: Most BMP files can be identified with much better reliability.
	if(!dbuf_memcmp(c->infile, 0, "BM", 2))
		return 45;
	return 0;
}

void de_module_bmp(deark *c, struct deark_module_info *mi)
{
	mi->id = "bmp";
	mi->desc = "BMP (Windows or OS/2 bitmap)";
	mi->run_fn = de_run_bmp;
	mi->identify_fn = de_identify_bmp;
}
