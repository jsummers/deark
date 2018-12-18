// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Convert OS/2 Icon and OS/2 Pointer format.
// Extract files in a BA (Bitmap Array) container.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_os2bmp);

#define DE_OS2FMT_BA    1
#define DE_OS2FMT_BA_BM 3
#define DE_OS2FMT_IC    4
#define DE_OS2FMT_BA_IC 5
#define DE_OS2FMT_PT    6
#define DE_OS2FMT_BA_PT 7
#define DE_OS2FMT_CI    8
#define DE_OS2FMT_BA_CI 9
#define DE_OS2FMT_CP    10
#define DE_OS2FMT_BA_CP 11

// This struct represents a raw source bitmap (it uses BMP format).
// Two of them (the foreground and the mask) will be combined to make the
// final image.
struct srcbitmap {
	struct de_bmpinfo bi;
	i64 bitssize;
	u32 pal[256];
};

// Populates srcbmp with information about a bitmap.
// Does not read the palette.
static int get_bitmap_info(deark *c, struct srcbitmap *srcbmp, const char *fmt, i64 pos)
{
	int retval = 0;
	unsigned int flags;

	flags = DE_BMPINFO_HAS_FILEHEADER;
	if(!de_strcmp(fmt,"CP")) {
		flags |= DE_BMPINFO_HAS_HOTSPOT;
	}
	if(!de_fmtutil_get_bmpinfo(c, c->infile, &srcbmp->bi, pos, c->infile->len - pos, flags)) {
		de_err(c, "Invalid or unsupported bitmap");
		goto done;
	}

	if(srcbmp->bi.is_compressed) {
		if(srcbmp->bi.sizeImage_field) {
			srcbmp->bitssize = srcbmp->bi.sizeImage_field;
		}
		else {
			de_err(c, "Cannot determine bits size");
			goto done;
		}
	}
	else {
		srcbmp->bitssize = srcbmp->bi.rowspan * srcbmp->bi.height;
	}

	retval = 1;
done:
	return retval;
}

// Read the header and palette
// Returns NULL on error.
static struct srcbitmap *do_decode_raw_bitmap_segment(deark *c, const char *fmt, i64 pos)
{
	int okay = 0;
	struct srcbitmap *srcbmp = NULL;
	i64 pal_start;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "%s bitmap at %d", fmt, (int)pos);
	de_dbg_indent(c, 1);

	srcbmp = de_malloc(c, sizeof(struct srcbitmap));

	if(!get_bitmap_info(c, srcbmp, fmt, pos))
		goto done;

	// read palette
	if (srcbmp->bi.pal_entries > 0) {
		pal_start = pos+14+srcbmp->bi.infohdrsize;
		de_dbg(c, "palette at %d", (int)pal_start);
		de_dbg_indent(c, 1);
		de_read_palette_rgb(c->infile, pal_start, srcbmp->bi.pal_entries, srcbmp->bi.bytes_per_pal_entry,
			srcbmp->pal, 256, DE_GETRGBFLAG_BGR);
		de_dbg_indent(c, -1);
	}

	okay = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);

	if(!okay) {
		if(srcbmp) {
			de_free(c, srcbmp);
			srcbmp = NULL;
		}
	}

	return srcbmp;
}

// srcbmp_main can be NULL.
static void do_generate_final_image(deark *c, struct srcbitmap *srcbmp_main, struct srcbitmap *srcbmp_mask)
{
	de_bitmap *img;
	i64 w, h;
	i64 i, j;
	i64 byte_offset;
	u8 x;
	u8 cr, cg, cb, ca;
	u8 xorbit, andbit;
	int inverse_warned = 0;

	if(srcbmp_main) {
		w = srcbmp_main->bi.width;
		h = srcbmp_main->bi.height;
	}
	else {
		w = srcbmp_mask->bi.width;
		h = srcbmp_mask->bi.height/2;
	}
	img = de_bitmap_create(c, w, h, 4);
	img->flipped = 1;

	cr=0; cg=0; cb=0; ca=255;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			if(!srcbmp_main) {
				// IC or PT (bi-level) format.
				// These images do have a palette, but it's unclear whether we're
				// supposed to do anything with it.
				cr = cg = cb = 0;
			}
			else if(srcbmp_main->bi.bitcount<=8) {
				x = de_get_bits_symbol(c->infile, srcbmp_main->bi.bitcount,
					srcbmp_main->bi.bitsoffset + srcbmp_main->bi.rowspan*j, i);
				cr = DE_COLOR_R(srcbmp_main->pal[x]);
				cg = DE_COLOR_G(srcbmp_main->pal[x]);
				cb = DE_COLOR_B(srcbmp_main->pal[x]);
			}
			else if(srcbmp_main->bi.bitcount==24) {
				byte_offset = srcbmp_main->bi.bitsoffset + srcbmp_main->bi.rowspan*j + i*3;
				cb = de_getbyte(byte_offset+0);
				cg = de_getbyte(byte_offset+1);
				cr = de_getbyte(byte_offset+2);
			}

			// Get the mask bits
			xorbit = de_get_bits_symbol(c->infile, srcbmp_mask->bi.bitcount,
				srcbmp_mask->bi.bitsoffset + srcbmp_mask->bi.rowspan*j, i);
			andbit = de_get_bits_symbol(c->infile, srcbmp_mask->bi.bitcount,
				srcbmp_mask->bi.bitsoffset + srcbmp_mask->bi.rowspan*(srcbmp_mask->bi.height/2+j), i);

			if(!andbit && !xorbit) {
				ca = 255; // Normal foreground
			}
			else if(andbit && !xorbit) {
				ca = 0; // Transparent
			}
			else if(!andbit && xorbit) {
				// Inverse of the foreground? Not expected to happen, but we'll try to support it.
				cr = 255-cr;
				cg = 255-cg;
				cb = 255-cb;
				ca = 255;
			}
			else  {  // (andbit && xorbit)
				// Inverse of the background. Not supported by PNG format.
				if(!inverse_warned) {
					de_warn(c, "This image contains inverse background pixels, which are not fully supported.");
					inverse_warned = 1;
				}
				if((i+j)%2) {
					cr = 255; cg = 0; cb=128; ca = 128;
				}
				else {
					cr = 128; cg = 0; cb=255; ca = 128;
				}
			}

			de_bitmap_setpixel_rgba(img, i, j, DE_MAKE_RGBA(cr,cg,cb,ca));
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

	de_bitmap_destroy(img);
}

static void do_decode_CI_or_CP_pair(deark *c, const char *fmt, i64 pos)
{
	i64 i;
	struct srcbitmap *srcbmp = NULL;
	struct srcbitmap *srcbmp_mask = NULL;
	struct srcbitmap *srcbmp_main = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "%s pair at %d", fmt, (int)pos);
	de_dbg_indent(c, 1);

	for(i=0; i<2; i++) {
		srcbmp = do_decode_raw_bitmap_segment(c, fmt, pos);
		if(!srcbmp) {
			goto done;
		}

		if(srcbmp->bi.size_of_headers_and_pal<26) {
			de_err(c, "Bad CI or CP image");
			goto done;
		}
		pos += srcbmp->bi.size_of_headers_and_pal;

		de_dbg_indent(c, 1);

		// Try to guess whether this is the image or the mask...
		if(srcbmp->bi.bitcount==1 && (srcbmp_mask==NULL || srcbmp_main!=NULL)) {
			de_dbg(c, "bitmap interpreted as: mask");
			srcbmp_mask = srcbmp;
			srcbmp = NULL;
		}
		else {
			de_dbg(c, "bitmap interpreted as: foreground");
			srcbmp_main = srcbmp;
			srcbmp = NULL;
		}

		de_dbg_indent(c, -1);
	}

	if(srcbmp_mask==NULL || srcbmp_main==NULL) {
		de_err(c, "Bad CI or CP image");
		goto done;
	}

	do_generate_final_image(c, srcbmp_main, srcbmp_mask);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, srcbmp_mask);
	de_free(c, srcbmp_main);
	de_free(c, srcbmp);
}

static void do_decode_IC_or_PT(deark *c, const char *fmt, i64 pos)
{
	struct srcbitmap *srcbmp_mask = NULL;

	srcbmp_mask = do_decode_raw_bitmap_segment(c, fmt, pos);
	if(!srcbmp_mask) {
		goto done;
	}
	if(srcbmp_mask->bi.size_of_headers_and_pal<26) {
		de_err(c, "Bad %s image", fmt);
		goto done;
	}

	do_generate_final_image(c, NULL, srcbmp_mask);

done:
	de_free(c, srcbmp_mask);
}

static void do_extract_CI_or_CP_pair(deark *c, const char *fmt, i64 pos)
{
	struct de_bmpinfo *bi = NULL;
	i64 i;
	dbuf *f = NULL;
	i64 hdrpos[2];
	i64 hdrsize[2];
	i64 oldbitsoffs[2];
	i64 newbitsoffs[2];
	i64 bitssize[2];
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "%s pair at %d", fmt, (int)pos);
	de_dbg_indent(c, 1);

	bi = de_malloc(c, sizeof(struct de_bmpinfo));

	if(!de_strcmp(fmt, "CP")) {
		f = dbuf_create_output_file(c, "ptr", NULL, 0);
	}
	else {
		f = dbuf_create_output_file(c, "os2.ico", NULL, 0);
	}

	for(i=0; i<2; i++) {
		de_dbg(c, "bitmap at %d", (int)pos);
		de_dbg_indent(c, 1);

		if(!de_fmtutil_get_bmpinfo(c, c->infile, bi, pos, c->infile->len - pos,
			DE_BMPINFO_HAS_FILEHEADER))
		{
			de_err(c, "Unsupported image type");
			goto done;
		}
		if(bi->compression_field!=0) {
			de_err(c, "Unsupported compression type (%d)", (int)bi->compression_field);
			goto done;
		}

		de_dbg(c, "bits size: %d", (int)bi->foreground_size);

		hdrpos[i] = pos;
		hdrsize[i] = bi->size_of_headers_and_pal;
		oldbitsoffs[i] = bi->bitsoffset;
		bitssize[i] = bi->foreground_size;

		pos += bi->size_of_headers_and_pal;

		de_dbg_indent(c, -1);
	}

	newbitsoffs[0] = hdrsize[0] + hdrsize[1];
	newbitsoffs[1] = newbitsoffs[0] + bitssize[0];

	// Write all the headers.
	for(i=0; i<2; i++) {
		// Copy the first 10 bytes of the fileheader.
		dbuf_copy(c->infile, hdrpos[i], 10, f);
		// Update the bits offset.
		dbuf_writeu32le(f, newbitsoffs[i]);
		// Copy the rest of the headers (+palette).
		dbuf_copy(c->infile, hdrpos[i]+14, hdrsize[i]-14, f);
	}
	// Write all the bitmaps.
	for(i=0; i<2; i++) {
		dbuf_copy(c->infile, oldbitsoffs[i], bitssize[i], f);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(f);
	de_free(c, bi);
}

// A BM/IC/PT image inside a BA container.
// Don't convert the image to another format; just extract it as-is in
// BMP/ICO/PTR format. Unfortunately, this requires collecting the various pieces
// of it, and adjusting pointers.
static void do_extract_one_image(deark *c, i64 pos, const char *fmt, const char *ext)
{
	struct srcbitmap *srcbmp = NULL;
	dbuf *f = NULL;

	de_dbg(c, "%s image at %d", fmt, (int)pos);
	de_dbg_indent(c, 1);

	srcbmp = de_malloc(c, sizeof(struct srcbitmap));

	if(!get_bitmap_info(c, srcbmp, fmt, pos))
		goto done;

	f = dbuf_create_output_file(c, ext, NULL, 0);

	// First 10 bytes of the FILEHEADER can be copied unchanged.
	dbuf_copy(c->infile, pos, 10, f);

	// The "bits offset" is probably the only thing we need to adjust.
	dbuf_writeu32le(f, srcbmp->bi.size_of_headers_and_pal);

	// Copy the infoheader & palette
	dbuf_copy(c->infile, pos+14, srcbmp->bi.size_of_headers_and_pal-14, f);

	// Copy the bitmap
	if(srcbmp->bi.bitsoffset+srcbmp->bitssize > c->infile->len) goto done;
	dbuf_copy(c->infile, srcbmp->bi.bitsoffset, srcbmp->bitssize, f);

done:
	de_dbg_indent(c, -1);
	dbuf_close(f);
	de_free(c, srcbmp);
}

static void do_BA_segment(deark *c, i64 pos, i64 *pnextoffset)
{
	u8 b0, b1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c,"BA segment at %d", (int)pos);
	de_dbg_indent(c, 1);

	*pnextoffset = 0;

	b0 = de_getbyte(pos+0);
	b1 = de_getbyte(pos+1);
	if(b0!='B' || b1!='A') {
		de_err(c, "Not a BA segment");
		goto done;
	}

	*pnextoffset = de_getu32le(pos+6);
	de_dbg(c, "offset of next segment: %d", (int)*pnextoffset);

	// Peek at the next two bytes
	b0 = de_getbyte(pos+14+0);
	b1 = de_getbyte(pos+14+1);
	if(b0=='C' && b1=='I') {
		do_extract_CI_or_CP_pair(c, "CI", pos+14);
	}
	else if(b0=='C' && b1=='P') {
		do_extract_CI_or_CP_pair(c, "CP", pos+14);
	}
	else if(b0=='B' && b1=='M') {
		do_extract_one_image(c, pos+14, "BM", "bmp");
	}
	else if(b0=='I' && b1=='C') {
		do_extract_one_image(c, pos+14, "IC", "os2.ico");
	}
	else if(b0=='P' && b1=='T') {
		do_extract_one_image(c, pos+14, "PT", "ptr");
	}
	else {
		de_err(c, "Not BM/IC/PT/CI/CP format. Not supported.");
		goto done;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_BA_file(deark *c)
{
	i64 pos;
	i64 nextoffset = 0;

	// The file contains a linked list of BA segments. There's nothing special
	// about the first segment, but it can be used to identify the file type.

	pos = 0;
	while(1) {
		do_BA_segment(c, pos, &nextoffset);
		if(nextoffset==0) break;
		if(nextoffset<=pos) {
			de_err(c, "Invalid BA segment offset");
			break;
		}
		pos = nextoffset;
	}
}

static int de_identify_os2bmp_internal(deark *c)
{
	u8 b[16];
	de_read(b, 0, 16);

	if(b[0]=='B' && b[1]=='A') {
		// A Bitmap Array file can contain a mixture of different image types,
		// but for the purposes of identifying the file type, we only look at
		// the first one. This is not ideal, but it really doesn't matter.
		if(b[14]=='I' && b[15]=='C') return DE_OS2FMT_BA_IC;
		if(b[14]=='P' && b[15]=='T') return DE_OS2FMT_BA_PT;
		if(b[14]=='C' && b[15]=='I') return DE_OS2FMT_BA_CI;
		if(b[14]=='C' && b[15]=='P') return DE_OS2FMT_BA_CP;
		if(b[14]=='B' && b[15]=='M') return DE_OS2FMT_BA_BM;
		return DE_OS2FMT_BA;
	}
	if(b[0]=='I' && b[1]=='C') return DE_OS2FMT_IC;
	if(b[0]=='P' && b[1]=='T') return DE_OS2FMT_PT;
	if(b[0]=='C' && b[1]=='I') return DE_OS2FMT_CI;
	if(b[0]=='C' && b[1]=='P') return DE_OS2FMT_CP;
	return 0;
}

static const char* get_fmt_name(int fmt)
{
	switch(fmt) {
	case DE_OS2FMT_IC: return "OS/2 Icon";
	case DE_OS2FMT_PT: return "OS/2 Pointer";
	case DE_OS2FMT_CI: return "OS/2 Color Icon";
	case DE_OS2FMT_CP: return "OS/2 Color Pointer";
	case DE_OS2FMT_BA: return "OS/2 Bitmap Array";
	case DE_OS2FMT_BA_IC:
	case DE_OS2FMT_BA_CI:
		return "OS/2 Bitmap Array of Icons";
	case DE_OS2FMT_BA_PT:
	case DE_OS2FMT_BA_CP:
		return "OS/2 Bitmap Array of Pointers";
	case DE_OS2FMT_BA_BM:
		return "OS/2 Bitmap Array of Bitmaps";
	}
	return NULL;
}

static void de_run_os2bmp(deark *c, de_module_params *mparams)
{
	int fmt;
	const char *name;

	fmt = de_identify_os2bmp_internal(c);

	name = get_fmt_name(fmt);
	if(name) {
		de_declare_fmt(c, name);
	}

	switch(fmt) {
	case DE_OS2FMT_IC:
		do_decode_IC_or_PT(c, "IC", 0);
		break;
	case DE_OS2FMT_PT:
		// TODO: PT support is untested.
		do_decode_IC_or_PT(c, "PT", 0);
		break;
	case DE_OS2FMT_CI:
		do_decode_CI_or_CP_pair(c, "CI", 0);
		break;
	case DE_OS2FMT_CP:
		do_decode_CI_or_CP_pair(c, "CP", 0);
		break;
	case DE_OS2FMT_BA:
	case DE_OS2FMT_BA_IC:
	case DE_OS2FMT_BA_PT:
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
		do_BA_file(c);
		break;
	default:
		de_err(c, "Format not supported");
	}
}

static int de_identify_os2bmp(deark *c)
{
	int fmt;

	// TODO: We could do a better job of identifying these formats.
	fmt = de_identify_os2bmp_internal(c);
	switch(fmt) {
	case DE_OS2FMT_BA_IC:
	case DE_OS2FMT_BA_PT:
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
		return 100;
	case DE_OS2FMT_BA:
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP:
		return 80;
	case DE_OS2FMT_IC:
	case DE_OS2FMT_PT:
		return 10;
	}
	return 0;
}

void de_module_os2bmp(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2bmp";
	mi->desc = "OS/2 icon (.ICO), cursor (.PTR), bitmap array";
	mi->run_fn = de_run_os2bmp;
	mi->identify_fn = de_identify_os2bmp;
}
