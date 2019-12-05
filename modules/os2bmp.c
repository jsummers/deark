// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Convert OS/2 Icon and OS/2 Pointer format.
// Extract files in a BA (Bitmap Array) container.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_os2bmp);

enum fmtcode {
	DE_OS2FMT_UNKNOWN = 0,
	DE_OS2FMT_BA,
	DE_OS2FMT_BM,
	DE_OS2FMT_BA_BM,
	DE_OS2FMT_IC,
	DE_OS2FMT_BA_IC,
	DE_OS2FMT_PT,
	DE_OS2FMT_BA_PT,
	DE_OS2FMT_CI,
	DE_OS2FMT_BA_CI,
	DE_OS2FMT_CP,
	DE_OS2FMT_BA_CP
};

// This struct represents a raw source bitmap (it uses BMP format).
// Two of them (the foreground and the mask) will be combined to make the
// final image.
struct srcbitmap {
	de_bitmap *img;
	struct de_bmpinfo bi;
	u8 has_hotspot;
	i64 bitssize;
	u32 pal[256];
};

struct os2icoctx {
	const char *fmtname; // Short name, like "CP"
	enum fmtcode fmt;
	struct srcbitmap *srcbmp;
	struct srcbitmap *maskbmp;
};

static const char *get_fmt_shortname_from_code(enum fmtcode fmt)
{
	switch(fmt) {
	case DE_OS2FMT_IC: return "IC";
	case DE_OS2FMT_PT: return "PT";
	case DE_OS2FMT_CI: return "CI";
	case DE_OS2FMT_CP: return "CP";
	case DE_OS2FMT_BM: return "BM";
	case DE_OS2FMT_BA:
	case DE_OS2FMT_BA_IC:
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_PT:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
		return "BA";
	default:
		break;
	}
	return "??";
}

static enum fmtcode bytes_to_fmtcode(u8 b0, u8 b1)
{
	if(b0=='C' && b1=='I') {
		return DE_OS2FMT_CI;
	}
	else if(b0=='C' && b1=='P') {
		return DE_OS2FMT_CP;
	}
	else if(b0=='I' && b1=='C') {
		return DE_OS2FMT_IC;
	}
	else if(b0=='P' && b1=='T') {
		return DE_OS2FMT_PT;
	}
	else if(b0=='B' && b1=='M') {
		return DE_OS2FMT_BM;
	}
	else if(b0=='B' && b1=='A') {
		return DE_OS2FMT_BA;
	}
	return DE_OS2FMT_UNKNOWN;
}

static void do_free_srcbmp(deark *c, struct srcbitmap *srcbmp)
{
	if(!srcbmp) return;
	if(srcbmp->img) {
		de_bitmap_destroy(srcbmp->img);
	}
	de_free(c, srcbmp);
}

// Populates srcbmp with information about a bitmap.
// Does not read the palette.
static int get_bitmap_info(deark *c, struct srcbitmap *srcbmp, enum fmtcode fmt,
	const char *fmtname, i64 pos)
{
	int retval = 0;
	unsigned int flags;

	flags = DE_BMPINFO_HAS_FILEHEADER;
	if(fmt==DE_OS2FMT_CP || fmt==DE_OS2FMT_PT) {
		srcbmp->has_hotspot = 1;
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

// Read the header and palette.
// Caller allocates srcbmp.
// On failure, prints an error, and returns 0.
static int do_bitmap_header(deark *c, struct os2icoctx *d, struct srcbitmap *srcbmp,
	i64 pos, const char *bitmapname)
{
	i64 pal_start;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "%s %s bitmap header at %"I64_FMT, d->fmtname, bitmapname, pos);
	de_dbg_indent(c, 1);

	if(!get_bitmap_info(c, srcbmp, d->fmt, d->fmtname, pos))
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

	if(srcbmp->bi.size_of_headers_and_pal<26) {
		de_err(c, "Bad %s image", d->fmtname);
		goto done;
	}

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Uses d->srcbmp, d->maskbmp (which can be NULL).
static void do_write_final_image(deark *c, struct os2icoctx *d, de_bitmap *img)
{
	de_finfo *fi = NULL;

	img->flipped = 1;

	fi = de_finfo_create(c);
	if(d->srcbmp) {
		if(d->srcbmp->has_hotspot) {
			fi->has_hotspot = 1;
			fi->hotspot_x = d->srcbmp->bi.hotspot_x;
			fi->hotspot_y = (int)img->height - 1 - d->srcbmp->bi.hotspot_y;
		}
	}
	else if(d->maskbmp) {
		if(d->maskbmp->has_hotspot) {
			fi->has_hotspot = 1;
			fi->hotspot_x = d->maskbmp->bi.hotspot_x;
			fi->hotspot_y = (int)img->height - 1 - d->maskbmp->bi.hotspot_y;
		}
	}

	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

	de_finfo_destroy(c, fi);
}

static u32 get_inv_bkgd_replacement_clr(i64 i, i64 j)
{
	if((i+j)%2) {
		return DE_MAKE_RGBA(255,0,128,128);
	}
	return DE_MAKE_RGBA(128,0,255,128);
}

// Applies mask to fg. Modifies fg.
static void do_apply_os2bmp_mask(deark *c, de_bitmap *fg, de_bitmap *mask, int is_color)
{
	i64 i, j;
	i64 mask_adj_height;
	int inverse_used = 0;

	mask_adj_height = mask->height / 2;

	for(j=0; j<fg->height && j<mask_adj_height; j++) {
		for(i=0; i<fg->width && i<mask->width; i++) {
			u8 andmaskclr;
			u8 xormaskclr;
			u32 oldclr;
			u32 newclr;

			oldclr = de_bitmap_getpixel(fg, i, j);
			newclr = oldclr;
			xormaskclr = DE_COLOR_K(de_bitmap_getpixel(mask, i, j));
			andmaskclr =  DE_COLOR_K(de_bitmap_getpixel(mask, i, mask_adj_height+j));

			if(andmaskclr==0) {
				if(is_color) {
					// For color bitmaps, the XOR bit is not used when the AND bit is 0.
					// Always use foreground color.
					;
				}
				else {
					if(xormaskclr==0) {
						newclr = DE_STOCKCOLOR_BLACK;
					}
					else {
						newclr = DE_STOCKCOLOR_WHITE;
					}
				}
			}
			else {
				if(xormaskclr==0) { // transparent
					newclr = DE_SET_ALPHA(oldclr, 0);
				}
				else { // inverse background
					newclr = get_inv_bkgd_replacement_clr(i, j);
					inverse_used = 1;
				}
			}

			if(newclr!=oldclr) {
				de_bitmap_setpixel_rgb(fg, i, j, newclr);
			}
		}
	}

	if(inverse_used) {
		de_warn(c, "This image contains inverse background pixels, which are not fully supported.");
	}
}

// Allocates srcbmp->img.
static int do_read_bitmap(deark *c, struct srcbitmap *srcbmp, int mask_mode, const char *bitmapname)
{
	int retval = 0;

	if(!srcbmp) goto done;
	if(srcbmp->img) goto done;

	if(mask_mode && srcbmp->bi.bitcount!=1) {
		mask_mode = 0;
	}

	srcbmp->img = de_bitmap_create(c, srcbmp->bi.width, srcbmp->bi.height, mask_mode?1:4);

	de_dbg(c, "%s pixel data at %"I64_FMT, bitmapname, srcbmp->bi.bitsoffset);

	if(mask_mode) {
		de_convert_image_bilevel(c->infile, srcbmp->bi.bitsoffset, srcbmp->bi.rowspan,
			srcbmp->img, 0);
	}
	else if(srcbmp->bi.bitcount<=8) {
		de_convert_image_paletted(c->infile, srcbmp->bi.bitsoffset, srcbmp->bi.bitcount,
			srcbmp->bi.rowspan, srcbmp->pal, srcbmp->img, 0);
	}
	else if(srcbmp->bi.bitcount==24) {
		de_convert_image_rgb(c->infile, srcbmp->bi.bitsoffset, srcbmp->bi.rowspan, 3,
			srcbmp->img, DE_GETRGBFLAG_BGR);
	}
	else {
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static void do_decode_CI_or_CP(deark *c, struct os2icoctx *d, i64 pos)
{
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "%s image at %"I64_FMT, d->fmtname, pos);
	de_dbg_indent(c, 1);

	d->maskbmp = de_malloc(c, sizeof(struct srcbitmap));
	if(!do_bitmap_header(c, d, d->maskbmp, pos, "mask")) {
		goto done;
	}
	pos += d->maskbmp->bi.size_of_headers_and_pal;

	d->srcbmp = de_malloc(c, sizeof(struct srcbitmap));
	if(!do_bitmap_header(c, d, d->srcbmp, pos, "foreground")) {
		goto done;
	}

	if(!do_read_bitmap(c, d->maskbmp, 1, "mask")) goto done;
	if(!do_read_bitmap(c, d->srcbmp, 0, "foreground")) goto done;
	do_apply_os2bmp_mask(c, d->srcbmp->img, d->maskbmp->img, 1);
	do_write_final_image(c, d, d->srcbmp->img);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_decode_IC_or_PT(deark *c, struct os2icoctx *d, i64 pos)
{
	de_bitmap *img_main = NULL;

	d->maskbmp = de_malloc(c, sizeof(struct srcbitmap));
	if(!do_bitmap_header(c, d, d->maskbmp, pos, "mask-like")) {
		goto done;
	}

	if(!do_read_bitmap(c, d->maskbmp, 1, "mask-like")) goto done;

	// There is no "main" image, so manufacture one.
	img_main = de_bitmap_create(c, d->maskbmp->bi.width, d->maskbmp->bi.height/2, 4);

	do_apply_os2bmp_mask(c, img_main, d->maskbmp->img, 0);
	do_write_final_image(c, d, img_main);

done:
	de_bitmap_destroy(img_main);
}

static void do_decode_icon_or_cursor(deark *c, enum fmtcode fmt)
{
	struct os2icoctx *d = NULL;

	d = de_malloc(c, sizeof(struct os2icoctx));
	d->fmt = fmt;
	d->fmtname = get_fmt_shortname_from_code(d->fmt);

	switch(fmt) {
	case DE_OS2FMT_IC:
	case DE_OS2FMT_PT:
		do_decode_IC_or_PT(c, d, 0);
		break;
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP:
		do_decode_CI_or_CP(c, d, 0);
		break;
	default:
		break;
	}

	if(d) {
		do_free_srcbmp(c, d->srcbmp);
		do_free_srcbmp(c, d->maskbmp);
		de_free(c, d);
	}
}

static void do_extract_CI_or_CP(deark *c, enum fmtcode fmt, const char *fmtname, i64 pos)
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
	de_dbg(c, "%s image at %d", fmtname, (int)pos);
	de_dbg_indent(c, 1);

	bi = de_malloc(c, sizeof(struct de_bmpinfo));

	if(fmt==DE_OS2FMT_CP) {
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
static void do_extract_one_image(deark *c, i64 pos, enum fmtcode fmt,
	const char *fmtname, const char *ext)
{
	struct srcbitmap *srcbmp = NULL;
	dbuf *f = NULL;

	de_dbg(c, "%s image at %d", fmtname, (int)pos);
	de_dbg_indent(c, 1);

	srcbmp = de_malloc(c, sizeof(struct srcbitmap));

	if(!get_bitmap_info(c, srcbmp, fmt, fmtname, pos))
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
	do_free_srcbmp(c, srcbmp);
}

static void do_BA_segment(deark *c, i64 pos, i64 *pnextoffset)
{
	u8 b0, b1;
	enum fmtcode fmt;
	const char *fmtname;
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
	fmt = bytes_to_fmtcode(b0, b1);
	fmtname = get_fmt_shortname_from_code(fmt);

	switch(fmt) {
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP:
		do_extract_CI_or_CP(c, fmt, fmtname, pos+14);
		break;
	case DE_OS2FMT_BM:
		do_extract_one_image(c, pos+14, fmt, fmtname, "bmp");
		break;
	case DE_OS2FMT_IC:
		do_extract_one_image(c, pos+14, fmt, fmtname, "os2.ico");
		break;
	case DE_OS2FMT_PT:
		do_extract_one_image(c, pos+14, fmt, fmtname, "ptr");
		break;
	default:
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

static enum fmtcode de_identify_os2bmp_internal(deark *c)
{
	enum fmtcode fmt;
	u8 b[16];

	de_read(b, 0, 16);

	fmt = bytes_to_fmtcode(b[0], b[1]);
	if(fmt==DE_OS2FMT_BA) {
		enum fmtcode ba_fmt;

		// A Bitmap Array file can contain a mixture of different image types,
		// but for the purposes of identifying the file type, we only look at
		// the first one. This is not ideal, but it really doesn't matter.
		ba_fmt = bytes_to_fmtcode(b[14], b[15]);
		if(ba_fmt==DE_OS2FMT_IC) return DE_OS2FMT_BA_IC;
		if(ba_fmt==DE_OS2FMT_PT) return DE_OS2FMT_BA_PT;
		if(ba_fmt==DE_OS2FMT_CI) return DE_OS2FMT_BA_CI;
		if(ba_fmt==DE_OS2FMT_CP) return DE_OS2FMT_BA_CP;
		if(ba_fmt==DE_OS2FMT_BM) return DE_OS2FMT_BA_BM;
		return DE_OS2FMT_BA;
	}
	if(fmt==DE_OS2FMT_IC) return DE_OS2FMT_IC;
	if(fmt==DE_OS2FMT_PT) return DE_OS2FMT_PT;
	if(fmt==DE_OS2FMT_CI) return DE_OS2FMT_CI;
	if(fmt==DE_OS2FMT_CP) return DE_OS2FMT_CP;
	return DE_OS2FMT_UNKNOWN;
}

static const char* get_fmt_longname_from_code(enum fmtcode fmt)
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
	default:
		break;
	}
	return NULL;
}

static void de_run_os2bmp(deark *c, de_module_params *mparams)
{
	enum fmtcode fmt;
	const char *name;

	fmt = de_identify_os2bmp_internal(c);

	name = get_fmt_longname_from_code(fmt);
	if(name) {
		de_declare_fmt(c, name);
	}

	switch(fmt) {
	case DE_OS2FMT_IC:
	case DE_OS2FMT_PT:
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP:
		do_decode_icon_or_cursor(c, fmt);
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
	enum fmtcode fmt;

	// TODO: We could do a better job of identifying these formats.
	fmt = de_identify_os2bmp_internal(c);
	switch(fmt) {
	case DE_OS2FMT_BA_IC:
	case DE_OS2FMT_BA_PT:
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
		return 90;
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP: // Note that Corel Photo-Paint is similar
	case DE_OS2FMT_PT:
		return 20;
	case DE_OS2FMT_BA:
	case DE_OS2FMT_IC:
		return 10;
	default:
		break;
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
