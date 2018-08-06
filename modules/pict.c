// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Macintosh PICT graphics

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pict);

struct pict_point {
	de_int64 y, x;
};

struct pict_rect {
	de_int64 t, l, b, r;
};

typedef struct localctx_struct {
	int version; // 2 if file is known to be v2, 1 otherwise.
	int is_extended_v2;
	dbuf *iccprofile_file;
} lctx;

typedef int (*item_decoder_fn)(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos,
	de_int64 *bytes_used);

struct opcode_info {
	de_uint16 opcode;
#define SZCODE_SPECIAL 0
#define SZCODE_EXACT   1
#define SZCODE_REGION  2
#define SZCODE_POLYGON 3
	de_uint16 size_code;
	de_uint32 size; // Data size, not including opcode. Logic depends on size_code.
	const char *name;
	item_decoder_fn fn;
};

static double pict_read_fixed(dbuf *f, de_int64 pos)
{
	de_int64 n;

	// I think QuickDraw's "Fixed point" numbers are signed, but I don't know
	// how negative numbers are handled.
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

// Read a QuickDraw Point. Caller supplies point struct.
static void pict_read_point(dbuf *f, de_int64 pos,
	struct pict_point *point, const char *dbgname)
{
	point->y = dbuf_geti16be(f, pos);
	point->x = dbuf_geti16be(f, pos+2);

	if(dbgname) {
		de_dbg(f->c, "%s: (%d,%d)", dbgname, (int)point->x, (int)point->y);
	}
}

// Read a QuickDraw Rectangle. Caller supplies rect struct.
static void pict_read_rect(dbuf *f, de_int64 pos,
	struct pict_rect *rect, const char *dbgname)
{
	rect->t = dbuf_geti16be(f, pos);
	rect->l = dbuf_geti16be(f, pos+2);
	rect->b = dbuf_geti16be(f, pos+4);
	rect->r = dbuf_geti16be(f, pos+6);

	if(dbgname) {
		de_dbg(f->c, "%s: (%d,%d)-(%d,%d)", dbgname, (int)rect->l, (int)rect->t,
			(int)rect->r, (int)rect->b);
	}
}

static int handler_RGBColor(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	unsigned int clr16[3];
	de_byte clr8[3];
	de_uint32 clr;
	char csamp[16];
	de_int64 pos = data_pos;
	de_int64 k;

	for(k=0; k<3; k++) {
		clr16[k] = (unsigned int)de_getui16be_p(&pos);
		clr8[k] = (de_byte)(clr16[k]>>8);
	}
	clr = DE_MAKE_RGB(clr8[0], clr8[1], clr8[2]);
	de_get_colorsample_code(c, clr, csamp, sizeof(csamp));
	de_dbg(c, "color: (0x%04x,0x%04x,0x%04x)%s", clr16[0], clr16[1], clr16[2], csamp);
	return 1;
}

// Version
static int handler_11(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 ver;

	*bytes_used = 1;
	ver = de_getbyte(data_pos);
	de_dbg(c, "version: %d", (int)ver);

	if(ver==2) {
		d->version = 2;
	}
	else if(ver!=1) {
		de_err(c, "Unsupported PICT version: %d", (int)ver);
		return 0;
	}
	return 1;
}

// LongText
static int handler_28(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 tlen;
	de_ucstring *s = NULL;
	struct pict_point pt;

	pict_read_point(c->infile, data_pos, &pt, "txLoc");
	tlen = (de_int64)de_getbyte(data_pos+4);
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, data_pos+5, tlen, s, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));
	*bytes_used = 5+tlen;
	ucstring_destroy(s);
	return 1;
}

// DVText
static int handler_DxText(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 tlen;
	de_int64 dx;
	de_ucstring *s = NULL;

	dx = (de_int64)de_getbyte(data_pos);
	de_dbg(c, "%s: %d", opcode==0x2a?"dv":"dh", (int)dx);

	tlen = (de_int64)de_getbyte(data_pos+1);
	*bytes_used = 2+tlen;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, data_pos+2, tlen, s, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

	ucstring_destroy(s);
	return 1;
}

// DHDVText
static int handler_2b(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 tlen;
	de_int64 dh, dv;
	de_ucstring *s = NULL;

	dh = (de_int64)de_getbyte(data_pos);
	dv = (de_int64)de_getbyte(data_pos+1);
	de_dbg(c, "dh,dv: (%d,%d)", (int)dh, (int)dv);

	tlen = (de_int64)de_getbyte(data_pos+2);
	de_dbg(c, "text size: %d", (int)tlen);
	*bytes_used = 3+tlen;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, data_pos+3, tlen, s, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

	return 1;
}

// fontName
static int handler_2c(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 n;
	de_int64 tlen;
	de_int64 id;
	de_ucstring *s = NULL;

	n = de_getui16be(data_pos);
	*bytes_used = 2+n;
	id = de_getui16be(data_pos+2);
	de_dbg(c, "old font id: %d", (int)id);
	tlen = (de_int64)de_getbyte(data_pos+4);
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, data_pos+5, tlen, s, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "font name: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);
	return 1;
}

static int handler_Rectangle(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	struct pict_rect rect;

	pict_read_rect(c->infile, data_pos, &rect, "rect");
	return 1;
}

struct bitmapinfo {
	de_int64 rowbytes; // The rowBytes field
	de_int64 rowspan; // Actual number of bytes/row
	de_int64 width, height;
	de_int64 packing_type;
	de_int64 pixeltype, pixelsize;
	de_int64 cmpcount, cmpsize;
	double hdpi, vdpi;
	int pixmap_flag;
	int has_colortable; // Does the file contain a colortable for this bitmap?
	int uses_pal; // Are we using the palette below?
	de_int64 num_pal_entries;
	de_uint32 pal[256];
};

// Sometimes-present baseAddr field (4 bytes)
static void read_baseaddr(deark *c, lctx *d, struct bitmapinfo *bi, de_int64 pos)
{
	de_int64 n;
	de_dbg(c, "baseAddr part of PixMap, at %d", (int)pos);
	de_dbg_indent(c, 1);
	n = de_getui32be(pos);
	de_dbg(c, "baseAddr: 0x%08x", (unsigned int)n);
	de_dbg_indent(c, -1);
}

static void read_rowbytes_and_bounds(deark *c, lctx *d, struct bitmapinfo *bi,
	de_int64 pos)
{
	struct pict_rect tmprect;
	de_int64 rowbytes_code;

	de_dbg(c, "rowBytes/bounds part of bitmap/PixMap header, at %d", (int)pos);
	de_dbg_indent(c, 1);
	rowbytes_code = de_getui16be(pos);
	bi->rowbytes = rowbytes_code & 0x7fff;
	bi->pixmap_flag = (rowbytes_code & 0x8000)?1:0;
	de_dbg(c, "rowBytes: %d", (int)bi->rowbytes);
	de_dbg(c, "pixmap flag: %d", bi->pixmap_flag);

	pict_read_rect(c->infile, pos+2, &tmprect, "rect");
	bi->width = tmprect.r - tmprect.l;
	bi->height = tmprect.b - tmprect.t;

	de_dbg_indent(c, -1);
}

// Pixmap fields that aren't read by read_baseaddr or read_rowbytes_and_bounds
// (36 bytes)
static int read_pixmap_only_fields(deark *c, lctx *d, struct bitmapinfo *bi,
	de_int64 pos)
{
	de_int64 pixmap_version;
	de_int64 pack_size;
	de_int64 plane_bytes;
	de_int64 n;

	de_dbg(c, "additional PixMap header fields, at %d", (int)pos);
	de_dbg_indent(c, 1);

	pixmap_version = de_getui16be(pos+0);
	de_dbg(c, "pixmap version: %d", (int)pixmap_version);

	bi->packing_type = de_getui16be(pos+2);
	de_dbg(c, "packing type: %d", (int)bi->packing_type);

	pack_size = de_getui32be(pos+4);
	de_dbg(c, "pixel data length: %d", (int)pack_size);

	bi->hdpi = pict_read_fixed(c->infile, pos+8);
	bi->vdpi = pict_read_fixed(c->infile, pos+12);
	de_dbg(c, "dpi: %.2f"DE_CHAR_TIMES"%.2f", bi->hdpi, bi->vdpi);

	bi->pixeltype = de_getui16be(pos+16);
	bi->pixelsize = de_getui16be(pos+18);
	bi->cmpcount = de_getui16be(pos+20);
	bi->cmpsize = de_getui16be(pos+22);
	de_dbg(c, "pixel type=%d, bits/pixel=%d, components/pixel=%d, bits/comp=%d",
		(int)bi->pixeltype, (int)bi->pixelsize, (int)bi->cmpcount, (int)bi->cmpsize);

	plane_bytes = de_getui32be(pos+24);
	de_dbg(c, "plane bytes: %d", (int)plane_bytes);

	n = de_getui32be(pos+28);
	de_dbg(c, "pmTable: 0x%08x", (unsigned int)n);

	n = de_getui32be(pos+32);
	de_dbg(c, "pmReserved: 0x%08x", (unsigned int)n);

	de_dbg_indent(c, -1);
	return 1;
}

static int read_colortable(deark *c, lctx *d, struct bitmapinfo *bi, de_int64 pos, de_int64 *bytes_used)
{
	de_int64 ct_id;
	de_uint32 ct_flags;
	de_int64 ct_size;
	de_int64 k, z;
	de_uint32 s[4];
	de_byte cr, cg, cb;
	de_uint32 clr;
	char tmps[64];

	*bytes_used = 0;
	de_dbg(c, "color table at %d", (int)pos);
	de_dbg_indent(c, 1);

	ct_id = de_getui32be(pos);
	ct_flags = (de_uint32)de_getui16be(pos+4); // a.k.a. transIndex
	ct_size = de_getui16be(pos+6);
	bi->num_pal_entries = ct_size+1;
	de_dbg(c, "color table id=0x%08x, flags=0x%04x, colors=%d", (unsigned int)ct_id,
		(unsigned int)ct_flags, (int)bi->num_pal_entries);

	for(k=0; k<bi->num_pal_entries; k++) {
		for(z=0; z<4; z++) {
			s[z] = (de_uint32)de_getui16be(pos+8+8*k+2*z);
		}
		cr = (de_byte)(s[1]>>8);
		cg = (de_byte)(s[2]>>8);
		cb = (de_byte)(s[3]>>8);
		clr = DE_MAKE_RGB(cr,cg,cb);
		de_snprintf(tmps, sizeof(tmps), "(%5d,%5d,%5d,idx=%3d) "DE_CHAR_RIGHTARROW" ",
			(int)s[1], (int)s[2], (int)s[3], (int)s[0]);
		de_dbg_pal_entry2(c, k, clr, tmps, NULL, NULL);

		// Some files don't have the palette indices set. Most PICT decoders ignore
		// the indices if the "device" flag of ct_flags is set, and that seems to
		// work (though it's not clearly documented).
		if(ct_flags & 0x8000U) {
			s[0] = (de_uint32)k;
		}

		if(s[0]<=255) {
			bi->pal[s[0]] = clr;
		}
	}

	de_dbg_indent(c, -1);
	*bytes_used = 8 + 8*bi->num_pal_entries;
	return 1;
}

// final few bitmap header fields (18 bytes)
static void read_src_dst_mode(deark *c, lctx *d, struct bitmapinfo *bi, de_int64 pos)
{
	struct pict_rect tmprect;
	de_int64 n;

	de_dbg(c, "src/dst/mode part of bitmap header, at %d", (int)pos);
	de_dbg_indent(c, 1);

	pict_read_rect(c->infile, pos, &tmprect, "srcRect");
	pos += 8;
	pict_read_rect(c->infile, pos, &tmprect, "dstRect");
	pos += 8;

	n = de_getui16be(pos);
	de_dbg(c, "transfer mode: %d", (int)n);
	pos += 2;
	de_dbg_indent(c, -1);
}

// Pre-scan the pixel data to figure out its size.
// (We could instead scan and decode it at the same time, but error handling
// would get really messy.)
// Returns 0 on fatal error (if we could not even parse the data).
static int get_pixdata_size(deark *c, lctx *d, struct bitmapinfo *bi,
	de_int64 pos1, de_int64 *pixdata_size)
{
	de_int64 pos;
	de_int64 j;
	de_int64 bytecount;
	int retval = 0;

	pos = pos1;
	de_dbg(c, "PixData at %d", (int)pos);
	de_dbg_indent(c, 1);

	if(bi->height<1 || bi->height>65535) {
		de_err(c, "Invalid bitmap height (%d)", (int)bi->height);
		goto done;
	}

	// Make sure rowbytes is sane. We use it to decide how much memory to allocate.
	if(bi->rowbytes > (bi->width * bi->pixelsize)/8 + 100) {
		de_err(c, "Bad rowBytes value (%d)", (int)bi->rowbytes);
		goto done;
	}

	if(bi->packing_type>=3 || (bi->packing_type==0 && bi->rowbytes>=8)) {
		for(j=0; j<bi->height; j++) {
			if(bi->rowbytes > 250) {
				bytecount = de_getui16be(pos);
				pos+=2;
			}
			else {
				bytecount = (de_int64)de_getbyte(pos);
				pos+=1;
			}
			pos += bytecount;
		}
	}
	else if(bi->packing_type==1 || (bi->packing_type==0 && bi->rowbytes<8)) {
		pos += bi->rowbytes * bi->height; // uncompressed
	}
	else {
		de_err(c, "Unsupported packing type: %d", (int)bi->packing_type);
		goto done;
	}

	*pixdata_size = pos - pos1;
	de_dbg(c, "PixData size: %d", (int)*pixdata_size);
	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void decode_bitmap_rgb24(deark *c, lctx *d, struct bitmapinfo *bi,
	dbuf *unc_pixels, de_bitmap *img, de_int64 pos)
{
	de_int64 i, j;
	de_byte cr, cg, cb;

	for(j=0; j<bi->height; j++) {
		for(i=0; i<bi->width; i++) {
			cr = dbuf_getbyte(unc_pixels, j*bi->rowspan + (bi->cmpcount-3+0)*bi->width + i);
			cg = dbuf_getbyte(unc_pixels, j*bi->rowspan + (bi->cmpcount-3+1)*bi->width + i);
			cb = dbuf_getbyte(unc_pixels, j*bi->rowspan + (bi->cmpcount-3+2)*bi->width + i);
			de_bitmap_setpixel_rgb(img, i, j, DE_MAKE_RGB(cr,cg,cb));
		}
	}
}

static void decode_bitmap_rgb16(deark *c, lctx *d, struct bitmapinfo *bi,
	dbuf *unc_pixels, de_bitmap *img, de_int64 pos)
{
	de_int64 i, j;
	de_byte c0, c1; //, cg, cb;
	de_uint32 clr;

	for(j=0; j<bi->height; j++) {
		for(i=0; i<bi->width; i++) {
			c0 = dbuf_getbyte(unc_pixels, j*bi->rowspan + i*2);
			c1 = dbuf_getbyte(unc_pixels, j*bi->rowspan + i*2+1);
			clr = ((de_uint32)c0 << 8)|c1;
			clr = de_rgb555_to_888(clr);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void decode_bitmap_paletted(deark *c, lctx *d, struct bitmapinfo *bi,
	dbuf *unc_pixels, de_bitmap *img, de_int64 pos)
{
	de_int64 i, j;
	de_byte b;
	de_uint32 clr;

	for(j=0; j<bi->height; j++) {
		for(i=0; i<bi->width; i++) {
			b = de_get_bits_symbol(unc_pixels, bi->pixelsize, j*bi->rowspan, i);
			clr = bi->pal[(unsigned int)b];
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static int decode_bitmap(deark *c, lctx *d, struct bitmapinfo *bi, de_int64 pos)
{
	de_int64 j;
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_int64 bytecount;
	de_int64 bitmapsize;
	int dst_nsamples;

	bi->rowspan = bi->rowbytes;
	if(bi->pixelsize==32 && bi->cmpcount==3 && bi->cmpsize==8) {
		bi->rowspan = (bi->rowbytes/4)*3;
	}

	bitmapsize = bi->height * bi->rowspan;
	unc_pixels = dbuf_create_membuf(c, bitmapsize, 1);

	for(j=0; j<bi->height; j++) {
		if(bi->rowbytes > 250) {
			bytecount = de_getui16be(pos);
			pos+=2;
		}
		else {
			bytecount = (de_int64)de_getbyte(pos);
			pos+=1;
		}

		if(bi->packing_type==3 && bi->pixelsize==16) {
			de_fmtutil_uncompress_packbits16(c->infile, pos, bytecount, unc_pixels, NULL);
		}
		else {
			de_fmtutil_uncompress_packbits(c->infile, pos, bytecount, unc_pixels, NULL);
		}

		// Make sure the data decompressed to the right number of bytes.
		if(unc_pixels->len != (j+1)*bi->rowspan) {
			dbuf_truncate(unc_pixels, (j+1)*bi->rowspan);
		}

		pos += bytecount;
	}

	dst_nsamples = 3;
	if(bi->uses_pal) {
		if(de_is_grayscale_palette(bi->pal, bi->num_pal_entries)) {
			dst_nsamples = 1;
		}
	}

	img = de_bitmap_create(c, bi->width, bi->height, dst_nsamples);
	if(bi->hdpi>=1.0 && bi->vdpi>=1.0) {
		img->density_code = DE_DENSITY_DPI;
		img->xdens = bi->hdpi;
		img->ydens = bi->vdpi;
	}

	if(bi->uses_pal) {
		decode_bitmap_paletted(c, d, bi, unc_pixels, img, pos);
	}
	else {
		if(bi->pixelsize==16) {
			decode_bitmap_rgb16(c, d, bi, unc_pixels, img, pos);
		}
		else {
			decode_bitmap_rgb24(c, d, bi, unc_pixels, img, pos);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	return 1;
}

static int decode_pixdata(deark *c, lctx *d, struct bitmapinfo *bi, de_int64 pos)
{
	int retval = 0;

	de_dbg_indent(c, 1);

	if(!de_good_image_dimensions(c, bi->width, bi->height)) goto done;

	if(bi->pixelsize!=1 && bi->pixelsize!=8 && bi->pixelsize!=16 && bi->pixelsize!=24 && bi->pixelsize!=32) {
		de_err(c, "%d bits/pixel images are not supported", (int)bi->pixelsize);
		goto done;
	}
	if((bi->uses_pal && bi->pixeltype!=0) || (!bi->uses_pal && bi->pixeltype!=16)) {
		de_err(c, "Pixel type %d is not supported", (int)bi->pixeltype);
		goto done;
	}
	if(bi->cmpcount!=1 && bi->cmpcount!=3 && bi->cmpcount!=4) {
		de_err(c, "Component count %d is not supported", (int)bi->cmpcount);
		goto done;
	}
	if(bi->cmpsize!=1 && bi->cmpsize!=5 && bi->cmpsize!=8) {
		de_err(c, "%d-bit components are not supported", (int)bi->cmpsize);
		goto done;
	}
	if(bi->packing_type!=0 && bi->packing_type!=3 && bi->packing_type!=4) {
		de_err(c, "Packing type %d is not supported", (int)bi->packing_type);
		goto done;
	}
	if((bi->uses_pal && bi->packing_type==0 && bi->pixelsize==1 && bi->cmpcount==1 && bi->cmpsize==1) ||
		(bi->uses_pal && bi->packing_type==0 && bi->pixelsize==8 && bi->cmpcount==1 && bi->cmpsize==8) ||
		(!bi->uses_pal && bi->packing_type==3 && bi->pixelsize==16 && bi->cmpcount==3 && bi->cmpsize==5) ||
		(!bi->uses_pal && bi->packing_type==4 && bi->pixelsize==32 && bi->cmpcount==3 && bi->cmpsize==8) ||
		(!bi->uses_pal && bi->packing_type==4 && bi->pixelsize==32 && bi->cmpcount==4 && bi->cmpsize==8))
	{
		;
	}
	else {
		de_err(c, "This type of image is not supported");
		goto done;
	}

	if(bi->cmpcount==4) {
		de_warn(c, "This image might have transparency, which is not supported.");
	}

	decode_bitmap(c, d, bi, pos);

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int handler_98_9a(deark *c, lctx *d, de_int64 opcode, de_int64 pos1, de_int64 *bytes_used)
{
	struct bitmapinfo *bi = NULL;
	de_int64 pixdata_size = 0;
	de_int64 colortable_size = 0;
	int retval = 0;
	de_int64 pos;

	bi = de_malloc(c, sizeof(struct bitmapinfo));
	pos = pos1;

	if(opcode==0x9a) {
		read_baseaddr(c, d, bi, pos);
		pos += 4;
	}

	read_rowbytes_and_bounds(c, d, bi, pos);
	pos += 10;

	if(bi->pixmap_flag) {
		read_pixmap_only_fields(c, d, bi, pos);
		pos += 36;
	}

	if(opcode==0x98 && bi->pixmap_flag) {
		// Prepare to read the palette
		bi->uses_pal = 1;
		bi->has_colortable = 1;
	}
	else if(opcode==0x98 && !bi->pixmap_flag) {
		// Settings implied by the lack of a PixMap header
		bi->pixelsize = 1;
		bi->cmpcount = 1;
		bi->cmpsize = 1;
		bi->uses_pal = 1;
		bi->num_pal_entries = 2;
		bi->pal[0] = DE_STOCKCOLOR_WHITE;
		bi->pal[1] = DE_STOCKCOLOR_BLACK;
	}
	else if(opcode==0x9a && !bi->pixmap_flag) {
		de_err(c, "DirectBitsRect image without PixMap flag is not supported");
		goto done;
	}

	if(bi->has_colortable) {
		if(!read_colortable(c, d, bi, pos, &colortable_size)) goto done;
		pos += colortable_size;
	}

	read_src_dst_mode(c, d, bi, pos);
	pos += 18;

	if(!get_pixdata_size(c, d, bi, pos, &pixdata_size)) {
		goto done;
	}
	decode_pixdata(c, d, bi, pos);
	pos += pixdata_size;

	*bytes_used = pos - pos1;

	retval = 1;

done:
	de_free(c, bi);
	return retval;
}

static void do_iccprofile_item(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 selector;
	de_int64 data_len;

	if(len<4) return;
	selector = de_getui32be(pos);
	data_len = len-4;
	de_dbg(c, "ICC profile segment, selector=%d, data len=%d", (int)selector,
		(int)data_len);

	if(selector!=1) {
		// If this is not a Continuation segment, close any current file.
		dbuf_close(d->iccprofile_file);
		d->iccprofile_file = NULL;
	}

	if(selector==0) { // Beginning segment
		d->iccprofile_file = dbuf_create_output_file(c, "icc", NULL, DE_CREATEFLAG_IS_AUX);
	}

	if(selector==0 || selector==1) {
		// Beginning and Continuation segments normally have profile data.
		// End segments (selector==2) are not allowed to include data.
		dbuf_copy(c->infile, pos+4, data_len, d->iccprofile_file);
	}
}

// ShortComment
static int handler_a0(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 kind;
	kind = de_getui16be(data_pos);
	de_dbg(c, "comment kind: %d", (int)kind);
	return 1;
}

// LongComment
static int handler_a1(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 kind;
	de_int64 len;

	kind = de_getui16be(data_pos);
	len = de_getui16be(data_pos+2);
	de_dbg(c, "comment kind: %d, size: %d", (int)kind, (int)len);
	*bytes_used = 4+len;

	if(kind==100 && len>=4) {
		struct de_fourcc sig4cc;

		dbuf_read_fourcc(c->infile, data_pos+4, &sig4cc, 4, 0x0);
		de_dbg(c, "application comment, signature=0x%08x '%s'",
			(unsigned int)sig4cc.id, sig4cc.id_dbgstr);
		de_dbg_hexdump(c, c->infile, data_pos+8, len-4, 256, NULL, 0x1);
	}
	else if(kind==224) {
		do_iccprofile_item(c, d, data_pos+4, len);
	}
	else {
		de_dbg_hexdump(c, c->infile, data_pos+4, len, 256, NULL, 0x1);
	}

	return 1;
}

// HeaderOp
static int handler_0c00(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 hdrver;
	double hres, vres;
	struct pict_rect srcrect;

	hdrver = de_getui16be(data_pos);
	d->is_extended_v2 = (hdrver==0xfffe);

	de_dbg(c, "extended v2: %s", d->is_extended_v2?"yes":"no");
	if(d->is_extended_v2) {
		hres = pict_read_fixed(c->infile, data_pos+4);
		vres = pict_read_fixed(c->infile, data_pos+8);
		de_dbg(c, "dpi: %.2f"DE_CHAR_TIMES"%.2f", hres, vres);
		pict_read_rect(c->infile, data_pos+12, &srcrect, "srcRect");
	}

	return 1;
}

static void do_handle_qtif_idsc(deark *c, de_int64 pos, de_int64 len)
{
	de_run_module_by_id_on_slice2(c, "qtif", "I", c->infile, pos, len);
}

// CompressedQuickTime (0x8200) & UncompressedQuickTime (0x8201)
static int handler_QuickTime(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 payload_pos;
	de_int64 payload_len;
	de_int64 endpos;
	de_int64 idsc_pos;

	payload_len = de_getui32be(data_pos);
	payload_pos = data_pos+4;
	endpos = payload_pos+payload_len;
	if(endpos > c->infile->len) return 0;
	*bytes_used = 4+payload_len;

	// Following the size field seems to be 68 or 50 bytes of data,
	// followed by QuickTime "idsc" data, followed by image data.
	idsc_pos = payload_pos + ((opcode==0x8201) ? 50 : 68);

	// The question is, should we try to extract this to QTIF or other QuickTime
	// file format? Or should we fully decode it (as we're doing now)?
	do_handle_qtif_idsc(c, idsc_pos, endpos-idsc_pos);
	return 1;
}

static const struct opcode_info opcode_info_arr[] = {
	// TODO: This list might not be complete, and it needs to be complete in
	// order to parse all PICT files.
	// Note that some opcode ranges are handled in do_handle_item().
	{ 0x0000, SZCODE_EXACT,   0,  "NOP", NULL },
	{ 0x0001, SZCODE_REGION,  0,  "Clip", NULL },
	{ 0x0002, SZCODE_EXACT,   8,  "BkPat", NULL },
	{ 0x0003, SZCODE_EXACT,   2,  "TxFont", NULL },
	{ 0x0004, SZCODE_EXACT,   1,  "TxFace", NULL },
	{ 0x0005, SZCODE_EXACT,   2,  "TxMode", NULL },
	{ 0x0006, SZCODE_EXACT,   4,  "SpExtra", NULL },
	{ 0x0007, SZCODE_EXACT,   4,  "PnSize", NULL },
	{ 0x0008, SZCODE_EXACT,   2,  "PnMode", NULL },
	{ 0x0009, SZCODE_EXACT,   8,  "PnPat", NULL },
	{ 0x000a, SZCODE_EXACT,   8,  "FillPat", NULL },
	{ 0x000b, SZCODE_EXACT,   4,  "OvSize", NULL },
	{ 0x000c, SZCODE_EXACT,   4,  "Origin", NULL },
	{ 0x000d, SZCODE_EXACT,   2,  "TxSize", NULL },
	{ 0x000e, SZCODE_EXACT,   4,  "FgColor", NULL },
	{ 0x000f, SZCODE_EXACT,   4,  "BkColor", NULL },
	{ 0x0010, SZCODE_EXACT,   8,  "TxRatio", NULL },
	{ 0x0011, SZCODE_EXACT,   1,  "Version", handler_11 },
	{ 0x0015, SZCODE_EXACT,   2,  "PnLocHFrac", NULL },
	{ 0x0016, SZCODE_EXACT,   2,  "ChExtra", NULL },
	{ 0x001a, SZCODE_EXACT,   6,  "RGBFgCol", handler_RGBColor },
	{ 0x001b, SZCODE_EXACT,   6,  "RGBBkCol", handler_RGBColor },
	{ 0x001c, SZCODE_EXACT,   0,  "HiliteMode", NULL },
	{ 0x001d, SZCODE_EXACT,   6,  "HiliteColor", handler_RGBColor },
	{ 0x001e, SZCODE_EXACT,   0,  "DefHilite", NULL },
	{ 0x001f, SZCODE_EXACT,   6,  "OpColor", handler_RGBColor },
	{ 0x0020, SZCODE_EXACT,   8,  "Line", NULL },
	{ 0x0021, SZCODE_EXACT,   4,  "LineFrom", NULL },
	{ 0x0022, SZCODE_EXACT,   6,  "ShortLine", NULL },
	{ 0x0023, SZCODE_EXACT,   2,  "ShortLineFrom", NULL },
	{ 0x0028, SZCODE_SPECIAL, 0,  "LongText", handler_28 },
	{ 0x0029, SZCODE_SPECIAL, 0,  "DHText", handler_DxText },
	{ 0x002a, SZCODE_SPECIAL, 0,  "DVText", handler_DxText },
	{ 0x002b, SZCODE_SPECIAL, 0,  "DHDVText", handler_2b },
	{ 0x002c, SZCODE_SPECIAL, 0,  "fontName", handler_2c },
	{ 0x002d, SZCODE_SPECIAL, 0,  "lineJustify", NULL },
	{ 0x002e, SZCODE_SPECIAL, 0,  "glyphState", NULL },
	{ 0x0030, SZCODE_EXACT,   8,  "frameRect", handler_Rectangle },
	{ 0x0031, SZCODE_EXACT,   8,  "paintRect", handler_Rectangle },
	{ 0x0032, SZCODE_EXACT,   8,  "eraseRect", handler_Rectangle },
	{ 0x0033, SZCODE_EXACT,   8,  "invertRect", handler_Rectangle },
	{ 0x0034, SZCODE_EXACT,   8,  "fillRect", handler_Rectangle },
	{ 0x0038, SZCODE_EXACT,   0,  "frameSameRect", NULL },
	{ 0x0039, SZCODE_EXACT,   0,  "paintSameRect", NULL },
	{ 0x003a, SZCODE_EXACT,   0,  "eraseSameRect", NULL },
	{ 0x003b, SZCODE_EXACT,   0,  "invertSameRect", NULL },
	{ 0x003c, SZCODE_EXACT,   0,  "fillSameRect", NULL },
	{ 0x0040, SZCODE_EXACT,   8,  "frameRRect", handler_Rectangle },
	{ 0x0041, SZCODE_EXACT,   8,  "paintRRect", handler_Rectangle },
	{ 0x0042, SZCODE_EXACT,   8,  "eraseRRect", handler_Rectangle },
	{ 0x0043, SZCODE_EXACT,   8,  "invertRRect", handler_Rectangle },
	{ 0x0044, SZCODE_EXACT,   8,  "fillRRect", handler_Rectangle },
	{ 0x0048, SZCODE_EXACT,   0,  "frameSameRRect", NULL },
	{ 0x0049, SZCODE_EXACT,   0,  "paintSameRRect", NULL },
	{ 0x004a, SZCODE_EXACT,   0,  "eraseSameRRect", NULL },
	{ 0x004b, SZCODE_EXACT,   0,  "invertSameRRect", NULL },
	{ 0x004c, SZCODE_EXACT,   0,  "fillSameRRect", NULL },
	{ 0x0050, SZCODE_EXACT,   8,  "frameOval", handler_Rectangle },
	{ 0x0051, SZCODE_EXACT,   8,  "paintOval", handler_Rectangle },
	{ 0x0052, SZCODE_EXACT,   8,  "eraseOval", handler_Rectangle },
	{ 0x0053, SZCODE_EXACT,   8,  "invertOval", handler_Rectangle },
	{ 0x0054, SZCODE_EXACT,   8,  "fillOval", handler_Rectangle },
	{ 0x0058, SZCODE_EXACT,   0,  "frameSameOval", NULL },
	{ 0x0059, SZCODE_EXACT,   0,  "paintSameOval", NULL },
	{ 0x005a, SZCODE_EXACT,   0,  "eraseSameOval", NULL },
	{ 0x005b, SZCODE_EXACT,   0,  "invertSameOval", NULL },
	{ 0x005c, SZCODE_EXACT,   0,  "fillSameOval", NULL },
	{ 0x0060, SZCODE_EXACT,   12, "frameArc", NULL },
	{ 0x0061, SZCODE_EXACT,   12, "paintArc", NULL },
	{ 0x0062, SZCODE_EXACT,   12, "eraseArc", NULL },
	{ 0x0063, SZCODE_EXACT,   12, "invertArc", NULL },
	{ 0x0064, SZCODE_EXACT,   12, "fillArc", NULL },
	{ 0x0068, SZCODE_EXACT,   4,  "frameSameArc", NULL },
	{ 0x0069, SZCODE_EXACT,   4,  "paintSameArc", NULL },
	{ 0x006a, SZCODE_EXACT,   4,  "eraseSameArc", NULL },
	{ 0x006b, SZCODE_EXACT,   4,  "invertSameArc", NULL },
	{ 0x006c, SZCODE_EXACT,   4,  "fillSameArc", NULL },
	{ 0x0080, SZCODE_REGION,  0,  "frameRgn", NULL },
	{ 0x0081, SZCODE_REGION,  0,  "paintRgn", NULL },
	{ 0x0082, SZCODE_REGION,  0,  "eraseRgn", NULL },
	{ 0x0083, SZCODE_REGION,  0,  "invertRgn", NULL },
	{ 0x0084, SZCODE_REGION,  0,  "fillRgn", NULL },
	{ 0x0070, SZCODE_POLYGON, 0,  "framePoly", NULL },
	{ 0x0071, SZCODE_POLYGON, 0,  "paintPoly", NULL },
	{ 0x0072, SZCODE_POLYGON, 0,  "erasePoly", NULL },
	{ 0x0073, SZCODE_POLYGON, 0,  "invertPoly", NULL },
	{ 0x0074, SZCODE_POLYGON, 0,  "fillPoly", NULL },
	{ 0x0098, SZCODE_SPECIAL, 0,  "PackBitsRect", handler_98_9a },
	{ 0x009a, SZCODE_SPECIAL, 0,  "DirectBitsRect", handler_98_9a },
	{ 0x00a0, SZCODE_EXACT,   2,  "ShortComment", handler_a0 },
	{ 0x00a1, SZCODE_SPECIAL, 0,  "LongComment", handler_a1 },
	{ 0x00ff, SZCODE_EXACT,   2,  "opEndPic", NULL },
	{ 0x0c00, SZCODE_EXACT,   24, "HeaderOp", handler_0c00 },
	{ 0x8200, SZCODE_SPECIAL, 0,  "CompressedQuickTime", handler_QuickTime },
	{ 0x8201, SZCODE_SPECIAL, 0,  "UncompressedQuickTime", handler_QuickTime }
};

static const struct opcode_info *find_opcode_info(de_int64 opcode)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(opcode_info_arr); i++) {
		if(opcode_info_arr[i].opcode == opcode) {
			return &opcode_info_arr[i];
		}
	}
	return NULL;
}

static int do_handle_item(deark *c, lctx *d, de_int64 opcode_pos, de_int64 opcode,
						   de_int64 data_pos, de_int64 *data_bytes_used)
{
	const char *opcode_name;
	const struct opcode_info *opi;
	de_int64 n;
	struct pict_rect tmprect;
	int ret = 0;

	*data_bytes_used = 0;

	opi = find_opcode_info(opcode);
	if(opi && opi->name) opcode_name = opi->name;
	else opcode_name = "?";

	if(d->version==2)
		de_dbg(c, "opcode 0x%04x (%s) at %d", (unsigned int)opcode, opcode_name, (int)opcode_pos);
	else
		de_dbg(c, "opcode 0x%02x (%s) at %d", (unsigned int)opcode, opcode_name, (int)opcode_pos);

	if(opi && opi->fn) {
		de_dbg_indent(c, 1);
		*data_bytes_used = opi->size; // Default to the size in the table.
		ret = opi->fn(c, d, opcode, data_pos, data_bytes_used);
		de_dbg_indent(c, -1);
	}
	else if(opi && opi->size_code==SZCODE_EXACT) {
		*data_bytes_used = opi->size;
		ret = 1;
	}
	else if(opi && opi->size_code==SZCODE_REGION) {
		n = de_getui16be(data_pos);
		de_dbg_indent(c, 1);
		de_dbg(c, "region size: %d", (int)n);
		if(n>=10) {
			pict_read_rect(c->infile, data_pos+2, &tmprect, "rect");
		}
		de_dbg_indent(c, -1);
		*data_bytes_used = n;
		ret = 1;
	}
	else if(opi && opi->size_code==SZCODE_POLYGON) {
		n = de_getui16be(data_pos);
		de_dbg_indent(c, 1);
		de_dbg(c, "polygon size: %d", (int)n);
		de_dbg_indent(c, -1);
		*data_bytes_used = n;
		ret = 1;
	}
	else if(opcode>=0x2c && opcode<=0x2f) {
		// Starts with 2-byte size, size does not include the "size" field.
		n = de_getui16be(data_pos);
		*data_bytes_used = 2+n;
		ret = 1;
	}
	else if(opcode>=0x8100 && opcode<=0xffff) {
		// Starts with 4-byte size, size does not include the "size" field.
		n = de_getui32be(data_pos);
		*data_bytes_used = 4+n;
		ret = 1;
	}
	else {
		de_err(c, "Unsupported opcode: 0x%04x", (unsigned int)opcode);
	}

	return ret;
}

static void do_read_items(deark *c, lctx *d, de_int64 pos)
{
	de_int64 opcode;
	de_int64 opcode_pos;
	de_int64 bytes_used;
	int ret;

	while(1) {
		if(pos%2 && d->version==2) {
			pos++; // 2-byte alignment
		}

		if(pos >= c->infile->len) break;

		opcode_pos = pos;

		if(d->version==2) {
			opcode = de_getui16be(pos);
			pos+=2;
		}
		else {
			opcode = (de_int64)de_getbyte(pos);
			pos+=1;
		}

		ret = do_handle_item(c, d, opcode_pos, opcode, pos, &bytes_used);
		if(!ret) goto done;
		if(opcode==0x00ff) goto done; // End of image

		pos += bytes_used;
	}
done:
	;
}

static void do_report_version(deark *c, lctx *d)
{
	if(!dbuf_memcmp(c->infile, 522, "\x00\x11\x02\xff\x0c\x00", 6)) {
		de_declare_fmt(c, "PICT v2");
	}
	else if(!dbuf_memcmp(c->infile, 522, "\x11\x01", 2)) {
		de_declare_fmt(c, "PICT v1");
	}
}

static void de_run_pict(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 picsize;
	struct pict_rect framerect;

	d = de_malloc(c, sizeof(lctx));

	do_report_version(c, d);

	d->version = 1;

	pos = 512;

	picsize = de_getui16be(pos);
	de_dbg(c, "picSize: %d", (int)picsize);
	pos+=2;
	pict_read_rect(c->infile, pos, &framerect, "picFrame");
	pos+=8;

	do_read_items(c, d, pos);

	dbuf_close(d->iccprofile_file);
	de_free(c, d);
}

static int de_identify_pict(deark *c)
{
	de_byte buf[6];

	if(c->infile->len<528) return 0;
	de_read(buf, 522, sizeof(buf));
	if(!de_memcmp(buf, "\x11\x01", 2)) return 5; // v1
	if(!de_memcmp(buf, "\x00\x11\x02\xff\x0c\x00", 2)) return 85; // v2
	return 0;
}

void de_module_pict(deark *c, struct deark_module_info *mi)
{
	mi->id = "pict";
	mi->desc = "Macintosh PICT";
	mi->run_fn = de_run_pict;
	mi->identify_fn = de_identify_pict;
}
