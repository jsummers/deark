// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm BitmapType

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_palmbitmap);

#define PALMBMPFLAG_COMPRESSED     0x8000U
#define PALMBMPFLAG_HASCOLORTABLE  0x4000U
#define PALMBMPFLAG_HASTRNS        0x2000U
#define PALMBMPFLAG_DIRECTCOLOR    0x0400U

#define CMPR_SCANLINE 0
#define CMPR_RLE      1
#define CMPR_PACKBITS 2
#define CMPR_NONE     0xff

static const de_uint32 palm256pal[256] = {
	0xffffff,0xffccff,0xff99ff,0xff66ff,0xff33ff,0xff00ff,0xffffcc,0xffcccc,
	0xff99cc,0xff66cc,0xff33cc,0xff00cc,0xffff99,0xffcc99,0xff9999,0xff6699,
	0xff3399,0xff0099,0xccffff,0xccccff,0xcc99ff,0xcc66ff,0xcc33ff,0xcc00ff,
	0xccffcc,0xcccccc,0xcc99cc,0xcc66cc,0xcc33cc,0xcc00cc,0xccff99,0xcccc99,
	0xcc9999,0xcc6699,0xcc3399,0xcc0099,0x99ffff,0x99ccff,0x9999ff,0x9966ff,
	0x9933ff,0x9900ff,0x99ffcc,0x99cccc,0x9999cc,0x9966cc,0x9933cc,0x9900cc,
	0x99ff99,0x99cc99,0x999999,0x996699,0x993399,0x990099,0x66ffff,0x66ccff,
	0x6699ff,0x6666ff,0x6633ff,0x6600ff,0x66ffcc,0x66cccc,0x6699cc,0x6666cc,
	0x6633cc,0x6600cc,0x66ff99,0x66cc99,0x669999,0x666699,0x663399,0x660099,
	0x33ffff,0x33ccff,0x3399ff,0x3366ff,0x3333ff,0x3300ff,0x33ffcc,0x33cccc,
	0x3399cc,0x3366cc,0x3333cc,0x3300cc,0x33ff99,0x33cc99,0x339999,0x336699,
	0x333399,0x330099,0x00ffff,0x00ccff,0x0099ff,0x0066ff,0x0033ff,0x0000ff,
	0x00ffcc,0x00cccc,0x0099cc,0x0066cc,0x0033cc,0x0000cc,0x00ff99,0x00cc99,
	0x009999,0x006699,0x003399,0x000099,0xffff66,0xffcc66,0xff9966,0xff6666,
	0xff3366,0xff0066,0xffff33,0xffcc33,0xff9933,0xff6633,0xff3333,0xff0033,
	0xffff00,0xffcc00,0xff9900,0xff6600,0xff3300,0xff0000,0xccff66,0xcccc66,
	0xcc9966,0xcc6666,0xcc3366,0xcc0066,0xccff33,0xcccc33,0xcc9933,0xcc6633,
	0xcc3333,0xcc0033,0xccff00,0xcccc00,0xcc9900,0xcc6600,0xcc3300,0xcc0000,
	0x99ff66,0x99cc66,0x999966,0x996666,0x993366,0x990066,0x99ff33,0x99cc33,
	0x999933,0x996633,0x993333,0x990033,0x99ff00,0x99cc00,0x999900,0x996600,
	0x993300,0x990000,0x66ff66,0x66cc66,0x669966,0x666666,0x663366,0x660066,
	0x66ff33,0x66cc33,0x669933,0x666633,0x663333,0x660033,0x66ff00,0x66cc00,
	0x669900,0x666600,0x663300,0x660000,0x33ff66,0x33cc66,0x339966,0x336666,
	0x333366,0x330066,0x33ff33,0x33cc33,0x339933,0x336633,0x333333,0x330033,
	0x33ff00,0x33cc00,0x339900,0x336600,0x333300,0x330000,0x00ff66,0x00cc66,
	0x009966,0x006666,0x003366,0x000066,0x00ff33,0x00cc33,0x009933,0x006633,
	0x003333,0x000033,0x00ff00,0x00cc00,0x009900,0x006600,0x003300,0x111111,
	0x222222,0x444444,0x555555,0x777777,0x888888,0xaaaaaa,0xbbbbbb,0xdddddd,
	0xeeeeee,0xc0c0c0,0x800000,0x800080,0x008000,0x008080,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000
};

struct page_ctx {
	de_int64 w, h;
	de_int64 bitsperpixel;
	de_int64 rowbytes;
	int has_trns;
	de_uint32 trns_value;
	int is_rgb;
	de_byte bitmapversion;
	int has_custom_pal;
	de_uint32 custom_pal[256];
};

typedef struct localctx_struct {
	int is_le;
	int ignore_color_table_flag;
} lctx;

static int de_identify_palmbitmap_internal(deark *c, dbuf *f, de_int64 pos, de_int64 len)
{
	de_int64 w, h;
	de_int64 rowbytes;
	de_byte ver;
	de_byte pixelsize;

	pixelsize = de_getbyte(pos+8);
	if(pixelsize==0xff) {
		pos += 16;
	}

	ver = de_getbyte(pos+9);
	if(ver>3) return 0;
	w = dbuf_getui16be(f, pos+0);
	h = dbuf_getui16be(f, pos+2);
	if(w==0 || h==0) return 0;
	rowbytes = dbuf_getui16be(f, pos+4);
	pixelsize = de_getbyte(pos+8);
	if((pixelsize==0 && ver==0) || pixelsize==1 || pixelsize==2 ||
		pixelsize==4 || pixelsize==8 || pixelsize==16)
	{
		;
	}
	else {
		return 0;
	}
	if(rowbytes==0 || (rowbytes&0x1)) return 0;
	// TODO: Make sure rowbytes is sensible
	return 1;
}

static int do_decompress_scanline_compression(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	de_int64 srcpos = pos1;
	de_int64 j;
	de_int64 blocknum;
	de_int64 blocksperrow;
	de_byte bf;
	de_byte dstb;
	unsigned int k;

	blocksperrow = (pg->rowbytes+7)/8;

	for(j=0; j<pg->h; j++) {
		de_int64 bytes_written_this_row = 0;

		for(blocknum=0; blocknum<blocksperrow; blocknum++) {
			// For each byte-per-row, we expect a lead byte, which is a
			// bitfield that tells us which of the next 8 bytes are stored
			// in the file, versus being copied from the previous row.
			bf = dbuf_getbyte(inf, srcpos++);
			for(k=0; k<8; k++) {
				if(bytes_written_this_row>=pg->rowbytes) break;

				if(bf&(1<<(7-k))) {
					// byte is present
					dstb = dbuf_getbyte(inf, srcpos++);
				}
				else {
					// copy from previous row
					dstb = dbuf_getbyte(unc_pixels, unc_pixels->len - pg->rowbytes);
				}
				dbuf_writebyte(unc_pixels, dstb);

				bytes_written_this_row++;
			}
		}
	}

	return 1;
}

// Note that this is distinct from ImageViewer RLE compression.
static int do_decompress_rle_compression(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	de_int64 srcpos = pos1;

	while(srcpos <= (pos1+len-2)) {
		de_int64 count;
		de_byte val;

		count = (de_int64)de_getbyte(srcpos++);
		val = (de_int64)de_getbyte(srcpos++);
		dbuf_write_run(unc_pixels, val, count);
	}

	return 1;
}

static int do_decompress_packbits_compression(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	int ret;

	if(pg->bitsperpixel==16) {
		ret = de_fmtutil_uncompress_packbits16(c->infile, pos1, len, unc_pixels, NULL);
	}
	else {
		ret = de_fmtutil_uncompress_packbits(c->infile, pos1, len, unc_pixels, NULL);
	}
	return ret;
}

static void do_generate_unc_image(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *unc_pixels)
{
	de_int64 i, j;
	de_byte b;
	de_byte b_adj;
	de_uint32 clr;
	int has_color;
	de_bitmap *img = NULL;

	has_color = (pg->bitsperpixel>4 || pg->has_custom_pal);

	if(pg->bitsperpixel==1 && !has_color) {
		de_convert_and_write_image_bilevel(unc_pixels, 0, pg->w, pg->h, pg->rowbytes,
			DE_CVTF_WHITEISZERO, NULL, 0);
		goto done;
	}

	img = de_bitmap_create(c, pg->w, pg->h,
		(has_color?3:1) + (pg->has_trns?1:0));

	for(j=0; j<pg->h; j++) {
		for(i=0; i<pg->w; i++) {
			if(pg->bitsperpixel==16) {
				de_uint32 clr1;
				clr1 = (de_uint32)dbuf_getui16be(unc_pixels, pg->rowbytes*j + 2*i);
				clr = de_rgb565_to_888(clr1);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				if(pg->has_trns && clr1==pg->trns_value) {
					de_bitmap_setsample(img, i, j, 3, 0);
				}
			}
			else {
				b = de_get_bits_symbol(unc_pixels, pg->bitsperpixel, pg->rowbytes*j, i);
				if(has_color) {
					if(pg->has_custom_pal)
						clr = pg->custom_pal[(unsigned int)b];
					else
						clr = DE_MAKE_OPAQUE(palm256pal[(unsigned int)b]);
				}
				else {
					// TODO: What are the correct colors (esp. for 4bpp)?
					b_adj = 255 - de_sample_nbit_to_8bit(pg->bitsperpixel, (unsigned int)b);
					clr = DE_MAKE_GRAY(b_adj);
				}

				de_bitmap_setpixel_rgb(img, i, j, clr);

				if(pg->has_trns && (de_uint32)b==pg->trns_value) {
					de_bitmap_setsample(img, i, j, 3, 0);
				}
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_bitmap_destroy(img);
}

// A wrapper that decompresses the image if necessary, then calls do_generate_unc_image().
static void do_generate_image(deark *c, lctx *d, struct page_ctx *pg,
	dbuf *inf, de_int64 pos, de_int64 len, unsigned int cmpr_type)
{
	dbuf *unc_pixels = NULL;
	de_int64 expected_num_uncmpr_image_bytes;

	expected_num_uncmpr_image_bytes = pg->rowbytes*pg->h;

	if(cmpr_type==CMPR_NONE) {
		if(expected_num_uncmpr_image_bytes > len) {
			de_warn(c, "Not enough data for image");
		}
		unc_pixels = dbuf_open_input_subfile(inf, pos, len);
	}
	else {
		de_int64 cmpr_len;
		de_int64 hdr_len;

		if(pg->bitmapversion >= 3) {
			hdr_len = 4;
			cmpr_len = dbuf_getui32x(inf, pos, d->is_le);
		}
		else {
			hdr_len = 2;
			cmpr_len = dbuf_getui16x(inf, pos, d->is_le);
		}
		de_dbg(c, "cmpr len: %d", (int)cmpr_len);
		if(cmpr_len < len) {
			// Reduce the number of available bytes, based on the cmpr_len field.
			len = cmpr_len;
		}
		// Account for the size of the cmpr_len field.
		pos += hdr_len;
		len -= hdr_len;
		if(len<0) goto done;

		unc_pixels = dbuf_create_membuf(c, expected_num_uncmpr_image_bytes, 1);

		if(cmpr_type==CMPR_SCANLINE) {
			do_decompress_scanline_compression(c, d, pg, inf, pos, len, unc_pixels);
		}
		else if(cmpr_type==CMPR_RLE) {
			do_decompress_rle_compression(c, d, pg, inf, pos, len, unc_pixels);
		}
		else if(cmpr_type==CMPR_PACKBITS) {
			do_decompress_packbits_compression(c, d, pg, inf, pos, len, unc_pixels);
		}
		else {
			de_err(c, "Unsupported compression type: %u", cmpr_type);
			goto done;
		}

		// TODO: The byte counts in this message are not very accurate.
		de_dbg(c, "decompressed %d bytes to %d bytes", (int)len,
			(int)unc_pixels->len);
	}

	do_generate_unc_image(c, d, pg, unc_pixels);

done:
	dbuf_close(unc_pixels);
}

static const char *get_cmpr_type_name(unsigned int cmpr_type)
{
	const char *name;

	switch(cmpr_type) {
	case 0: name = "ScanLine"; break;
	case 1: name = "RLE"; break;
	case 2: name = "PackBits"; break;
	case 0xff: name = "none"; break;
	default: name = "?"; break;
	}
	return name;
}

static int read_BitmapType_colortable(deark *c, lctx *d, struct page_ctx *pg,
	de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 num_entries;
	de_int64 k;
	de_int64 pos = pos1;
	unsigned int idx;
	char tmps[32];

	de_dbg(c, "color table at %d", (int)pos1);
	de_dbg_indent(c, 1);

	num_entries = dbuf_getui16x(c->infile, pos1, d->is_le);
	de_dbg(c, "number of entries: %d", (int)num_entries);
	// TODO: Documentation says "High bits (numEntries > 256) reserved."
	// What exactly does that mean?
	if(num_entries>256) {
		de_warn(c, "Invalid or unsupported type of color table");
	}
	pos += 2;

	if(num_entries>0) {
		// The only custom palettes I've seen in the wild have either 0 (!) or
		// 256 entries.
		// TODO: It might be better to treat all <=8 bit images as paletted:
		// Start with a default palette, then overlay it with any custom
		// palette entries that exist.
		pg->has_custom_pal = 1;
	}

	*bytes_consumed = 2+4*num_entries;

	for(k=0; k<num_entries && k<256; k++) {
		idx = (unsigned int)de_getbyte(pos);
		de_snprintf(tmps, sizeof(tmps), ",idx=%u", idx);
		// Not entirely sure if we should set entry #k, or entry #idx.
		// idx is documented as "The index of this color in the color table."
		pg->custom_pal[idx] = dbuf_getRGB(c->infile, pos+1, 0);
		de_dbg_pal_entry2(c, k, pg->custom_pal[idx], NULL, tmps, NULL);
		pos += 4;
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void do_BitmapDirectInfoType(deark *c, lctx *d, struct page_ctx *pg,
	de_int64 pos)
{
	de_byte cbits[3];
	de_byte t[4];

	de_dbg(c, "BitmapDirectInfoType structure at %d", (int)pos);
	de_dbg_indent(c, 1);
	cbits[0] = de_getbyte(pos);
	cbits[1] = de_getbyte(pos+1);
	cbits[2] = de_getbyte(pos+2);
	de_dbg(c, "bits/component: %d,%d,%d", (int)cbits[0], (int)cbits[1], (int)cbits[2]);

	t[0] = de_getbyte(pos+4);
	t[1] = de_getbyte(pos+5);
	t[2] = de_getbyte(pos+6);
	t[3] = de_getbyte(pos+7);
	de_dbg(c, "transparentColor: (%d,%d,%d,idx=%d)", (int)t[1], (int)t[2],
		(int)t[3], (int)t[0]);
	if(pg->has_trns) {
		// The format of this field (RGBColorType) is not the same as that of
		// the actual pixels, and I can't find documentation that says how the
		// mapping is done.
		// This appears to work (though it's quick & dirty, and only supports
		// RGB565).
		pg->trns_value =
			((((de_uint32)t[1])&0xf8)<<8) |
			((((de_uint32)t[2])&0xfc)<<3) |
			((((de_uint32)t[3])&0xf8)>>3);
	}
	de_dbg_indent(c, -1);
}

static void do_palm_BitmapType_internal(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	de_int64 *pnextbitmapoffset)
{
	de_int64 x;
	de_int64 pos;
	de_uint32 bitmapflags;
	de_byte pixelsize_raw;
	de_byte pixelformat = 0; // V3 only
	de_int64 headersize;
	de_int64 needed_rowbytes;
	de_int64 bytes_consumed;
	de_int64 nextbitmapoffs_in_bytes = 0;
	unsigned int cmpr_type;
	const char *cmpr_type_src_name = "";
	const char *bpp_src_name = "";
	struct page_ctx *pg = NULL;
	int saved_indent_level;
	de_ucstring *flagsdescr;
	char tmps[80];

	de_dbg_indent_save(c, &saved_indent_level);
	pg = de_malloc(c, sizeof(struct page_ctx));

	de_dbg(c, "BitmapType at %d, len"DE_CHAR_LEQ"%d", (int)pos1, (int)len);
	de_dbg_indent(c, 1);
	de_dbg(c, "bitmap header at %d", (int)pos1);
	de_dbg_indent(c, 1);

	// Look ahead to get the version
	pg->bitmapversion = de_getbyte(pos1+9);
	de_dbg(c, "bitmap version: %d", (int)pg->bitmapversion);

	if(pg->bitmapversion>3) {
		// Note that V3 allows the high bit of the version field to
		// be set (to mean little-endian), but we don't support that.
		de_err(c, "Unsupported bitmap version: %d", (int)pg->bitmapversion);
		goto done;
	}

	pg->w = dbuf_geti16x(c->infile, pos1, d->is_le);
	pg->h =  dbuf_geti16x(c->infile, pos1+2, d->is_le);
	de_dbg_dimensions(c, pg->w, pg->h);

	pg->rowbytes = dbuf_getui16x(c->infile, pos1+4, d->is_le);
	de_dbg(c, "rowBytes: %d", (int)pg->rowbytes);

	bitmapflags = (de_uint32)dbuf_getui16x(c->infile, pos1+6, d->is_le);
	flagsdescr = ucstring_create(c);
	if(bitmapflags&PALMBMPFLAG_COMPRESSED) ucstring_append_flags_item(flagsdescr, "compressed");
	if(bitmapflags&PALMBMPFLAG_HASCOLORTABLE) ucstring_append_flags_item(flagsdescr, "hasColorTable");
	if(bitmapflags&PALMBMPFLAG_HASTRNS) ucstring_append_flags_item(flagsdescr, "hasTransparency");
	if(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) ucstring_append_flags_item(flagsdescr, "directColor");
	if(bitmapflags==0) ucstring_append_flags_item(flagsdescr, "none");
	de_dbg(c, "bitmap flags: 0x%04x (%s)", (unsigned int)bitmapflags,
		ucstring_get_printable_sz(flagsdescr));
	ucstring_destroy(flagsdescr);
	if((bitmapflags&PALMBMPFLAG_HASCOLORTABLE) && d->ignore_color_table_flag) {
		bitmapflags -= PALMBMPFLAG_HASCOLORTABLE;
	}
	if((bitmapflags&PALMBMPFLAG_HASCOLORTABLE) && pg->bitmapversion<1) {
		de_warn(c, "BitmapTypeV%d with a color table is not standard", (int)pg->bitmapversion);
	}

	if(pg->bitmapversion>=1) {
		pixelsize_raw = de_getbyte(pos1+8);
		de_dbg(c, "pixelSize: %d", (int)pixelsize_raw);
		bpp_src_name = "based on pixelSize field";
		if(pg->bitmapversion<2 && pixelsize_raw==8) {
			de_warn(c, "BitmapTypeV%d with pixelSize=%d is not standard",
				(int)pg->bitmapversion, (int)pixelsize_raw);
		}
	}
	else {
		pixelsize_raw = 0;
	}
	if(pixelsize_raw==0) {
		pg->bitsperpixel = 1;
		bpp_src_name = "default";
	}
	else pg->bitsperpixel = (de_int64)pixelsize_raw;
	de_dbg(c, "bits/pixel: %d (%s)", (int)pg->bitsperpixel, bpp_src_name);

	if(pg->bitmapversion==1 || pg->bitmapversion==2) {
		x = dbuf_getui16x(c->infile, pos1+10, d->is_le);
		nextbitmapoffs_in_bytes = 4*x;
		if(x==0) {
			de_snprintf(tmps, sizeof(tmps), "none");
		}
		else {
			de_snprintf(tmps, sizeof(tmps), "%d + 4"DE_CHAR_TIMES"%d = %d", (int)pos1, (int)x, (int)(pos1+nextbitmapoffs_in_bytes));
		}
		de_dbg(c, "nextDepthOffset: %d (%s)", (int)x, tmps);
	}

	if(pg->bitmapversion<3) {
		headersize = 16;
	}
	else {
		headersize = (de_int64)de_getbyte(pos1+10);
		de_dbg(c, "header size: %d", (int)headersize);
	}

	if(pg->bitmapversion==3) {
		pixelformat = de_getbyte(pos1+11);
		de_dbg(c, "pixel format: %d", (int)pixelformat);
	}

	if(pg->bitmapversion==2 && (bitmapflags&PALMBMPFLAG_HASTRNS)) {
		pg->has_trns = 1;
		pg->trns_value = (de_uint32)de_getbyte(pos1+12);
		de_dbg(c, "transparent color: %u", (unsigned int)pg->trns_value);
	}

	cmpr_type_src_name = "flags";
	if(bitmapflags&PALMBMPFLAG_COMPRESSED) {
		if(pg->bitmapversion>=2) {
			cmpr_type = (unsigned int)de_getbyte(pos1+13);
			cmpr_type_src_name = "compression type field";
			de_dbg(c, "compression type field: 0x%02x", cmpr_type);
		}
		else {
			// V1 & V2 have no cmpr_type field, but can still be compressed.
			cmpr_type = CMPR_SCANLINE;
		}
	}
	else {
		cmpr_type = CMPR_NONE;
	}

	de_dbg(c, "compression type: %s (based on %s)", get_cmpr_type_name(cmpr_type), cmpr_type_src_name);

	if(pg->bitmapversion==3) {
		de_int64 densitycode;
		densitycode = dbuf_getui16x(c->infile, pos1+14, d->is_le);
		de_dbg(c, "density: %d", (int)densitycode);
		// The density is an indication of the target screen density.
		// It's tempting to interpet it as pixels per inch, and copy it to the
		// output image -- though the documentation says it "should not be
		// interpreted as representing pixels per inch".
	}

	if(pg->bitmapversion==3 && (bitmapflags&PALMBMPFLAG_HASTRNS) && headersize>=20) {
		// I'm assuming the flag affects this field. The spec is ambiguous.
		pg->has_trns = 1;
		pg->trns_value = (de_uint32)dbuf_getui32x(c->infile, pos1+16, d->is_le);
		de_dbg(c, "transparent color: 0x%08x", (unsigned int)pg->trns_value);
	}

	if(pg->bitmapversion==3 && headersize>=24) {
		// Documented as the "number of bytes to the next bitmap", but it doesn't
		// say where it is measured *from*. I'll assume it's the same logic as
		// the "nextDepthOffset" field.
		nextbitmapoffs_in_bytes = dbuf_getui32x(c->infile, pos1+20, d->is_le);
		if(nextbitmapoffs_in_bytes==0) {
			de_snprintf(tmps, sizeof(tmps), "none");
		}
		else {
			de_snprintf(tmps, sizeof(tmps), "%u + %u = %u", (unsigned int)pos1,
				(unsigned int)nextbitmapoffs_in_bytes, (unsigned int)(pos1+nextbitmapoffs_in_bytes));
		}
		de_dbg(c, "nextBitmapOffset: %u (%s)", (unsigned int)nextbitmapoffs_in_bytes, tmps);
	}

	// Now that we've read the nextBitmapOffset fields, we can stop processing this
	// image if it's invalid or unsupported.

	needed_rowbytes = (pg->w * pg->bitsperpixel +7)/8;
	if(pg->rowbytes < needed_rowbytes) {
		de_err(c, "Bad rowBytes value (is %d, need at least %d) or unsupported format version",
			(int)pg->rowbytes, (int)needed_rowbytes);
		goto done;
	}

	if(!de_good_image_dimensions(c, pg->w, pg->h)) goto done;

	de_dbg_indent(c, -1);

	if(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) {
		pg->is_rgb = 1;
		if(pg->bitmapversion<2) {
			de_warn(c, "BitmapTypeV%d with RGB color is not standard", (int)pg->bitmapversion);
		}
	}

	if(pg->bitmapversion>=3) {
		if(pixelformat>1 ||
			(pixelformat==0 && pg->bitsperpixel>8) ||
			(pixelformat==1 && pg->bitsperpixel!=16))
		{
			de_err(c, "Unsupported pixelFormat (%d) for this image", (int)pixelformat);
			goto done;
		}

		if(pixelformat==1 && pg->bitsperpixel==16) {
			// This should have already been set, by PALMBMPFLAG_DIRECTCOLOR,
			// but that flag seems kind of obsolete in V3.
			pg->is_rgb = 1;
		}
	}

	if(pg->bitmapversion==2 && pg->bitsperpixel==16 &&
		!(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) && !(bitmapflags&PALMBMPFLAG_HASCOLORTABLE))
	{
		// I have some images like this. I guess they are standard RGB565, with no
		// BitmapDirectInfoType header.
		pg->is_rgb = 1;
		de_warn(c, "This type of image (16-bit, without directColor flag) might "
			"not be decoded correctly");
	}

	if(pg->bitsperpixel!=1 && pg->bitsperpixel!=2 && pg->bitsperpixel!=4 &&
		pg->bitsperpixel!=8 && pg->bitsperpixel!=16)
	{
		de_err(c, "Unsupported bits/pixel: %d", (int)pg->bitsperpixel);
		goto done;
	}

	if((pg->is_rgb && pg->bitsperpixel!=16) ||
		(!pg->is_rgb && pg->bitsperpixel>8))
	{
		de_err(c, "This type of image is not supported");
		goto done;
	}

	pos = pos1;
	pos += headersize;
	if(pos >= pos1+len) goto done;

	if(bitmapflags&PALMBMPFLAG_HASCOLORTABLE) {
		if(!read_BitmapType_colortable(c, d, pg, pos, &bytes_consumed)) goto done;
		pos += bytes_consumed;
	}

	// If there is both a color table and a DirectInfo struct, I don't know which
	// one appears first. But that shouldn't happen.
	if((bitmapflags&PALMBMPFLAG_DIRECTCOLOR) && (pg->bitmapversion<=2)) {
		do_BitmapDirectInfoType(c, d, pg, pos);
		pos += 8;
	}

	if(pos >= pos1+len) {
		de_err(c, "Unexpected end of file");
		goto done;
	}

	de_dbg(c, "image data at %d", (int)pos);
	de_dbg_indent(c, 1);
	do_generate_image(c, d, pg, c->infile, pos, pos1+len-pos, cmpr_type);
	de_dbg_indent(c, -1);

done:
	*pnextbitmapoffset = nextbitmapoffs_in_bytes;
	de_dbg_indent_restore(c, saved_indent_level);
	if(pg) {
		de_free(c, pg);
	}
}

static void do_palm_BitmapType(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 nextbitmapoffs = 0;
	de_int64 pos = pos1;

	while(1) {
		if(de_getbyte(pos+8) == 0xff) {
			de_dbg(c, "[skipping dummy bitmap header at %d]", (int)pos);
			pos += 16;
		}

		if(pos > pos1+len-16) {
			de_err(c, "Bitmap exceeds its bounds");
			break;
		}
		do_palm_BitmapType_internal(c, d, pos, pos1+len-pos, &nextbitmapoffs);
		if(nextbitmapoffs<=0) break;
		pos += nextbitmapoffs;
	}
}

static void de_run_palmbitmap(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	if(de_get_ext_option(c, "palm:le")) {
		d->is_le = 1;
	}
	if(de_get_ext_option(c, "palm:nocolortable")) {
		// Enables a hack, for files that apparently set the hasColorTable flag
		// incorrectly
		d->ignore_color_table_flag = 1;
	}
	do_palm_BitmapType(c, d, 0, c->infile->len);
	de_free(c, d);
}

static int de_identify_palmbitmap(deark *c)
{
	if(de_input_file_has_ext(c, "palm")) {
		int x;
		x = de_identify_palmbitmap_internal(c, c->infile, 0, c->infile->len);
		if(x) return 90;
	}
	return 0;
}

static void de_help_palmbitmap(deark *c)
{
	de_msg(c, "-opt palm:le : Assume little-endian byte order");
	de_msg(c, "-opt palm:nocolortable : Ignore the hasColorTable flag, if set");
}

void de_module_palmbitmap(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmbitmap";
	mi->desc = "Palm BitmapType";
	mi->run_fn = de_run_palmbitmap;
	mi->identify_fn = de_identify_palmbitmap;
	mi->help_fn = de_help_palmbitmap;
}
