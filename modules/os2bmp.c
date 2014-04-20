// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Convert OS/2 Icon and OS/2 Pointer format.
// Extract BMP files in a BA (Bitmap Array) container.

#include <deark-config.h>
#include <deark-modules.h>

// This struct represents a raw source bitmap (it uses BMP format).
// Two of them (the foreground and the mask) will be combined to make the
// final image.
struct srcbitmap {
	de_int64 hdr_size;
	de_int64 hdrs_plus_pal_size; // size of the headers and palette, in bytes
	de_int64 bitsoffset;
	de_int64 bitcount;
	de_int64 width;
	de_int64 height;
	de_int64 rowstride;
	de_int64 bitssize;
	de_int64 pal_entries;
	de_int64 pal_bytesperentry;
	de_int64 pal_bytes;
	de_uint32 pal[256];
};

// Populates srcbmp with information about a bitmap.
// Does not read the palette.
static int get_bitmap_info(deark *c, struct srcbitmap *srcbmp, const char *fmt, de_int64 pos)
{
	de_int64 hotspot_x, hotspot_y;
	de_int64 bmihpos;
	de_int64 compression;
	int retval = 0;

	hotspot_x = de_getui16le(pos+6);
	hotspot_y = de_getui16le(pos+8);
	if(!de_strcmp(fmt,"CP")) {
		de_dbg(c, "hotspot: (%d,%d)\n", (int)hotspot_x, (int)hotspot_y);
	}

	srcbmp->bitsoffset = de_getui32le(pos+ 10);
	de_dbg(c, "bits offset: %d\n", (int)srcbmp->bitsoffset);

	bmihpos = pos+14;
	srcbmp->hdr_size = de_getui16le(bmihpos);
	de_dbg(c, "header size: %d\n", (int)srcbmp->hdr_size);

	if(srcbmp->hdr_size==12) {
		srcbmp->width = de_getui16le(bmihpos+4);
		srcbmp->height = de_getui16le(bmihpos+6);
		srcbmp->bitcount = de_getui16le(bmihpos+10);
		srcbmp->pal_bytesperentry = 3;
	}
	else if(srcbmp->hdr_size>=16 && srcbmp->hdr_size<=64) {
		srcbmp->width = de_getui32le(bmihpos+4);
		srcbmp->height = de_getui32le(bmihpos+8);
		srcbmp->bitcount = de_getui16le(bmihpos+14);
		srcbmp->pal_bytesperentry = 4;
	}
	else {
		de_err(c, "Unsupported image type (header size %d)\n", (int)srcbmp->hdr_size);
		goto done;
	}

	if(srcbmp->hdr_size>=20) {
		compression = de_getui32le(bmihpos+16);
		if(compression!=0) {
			de_err(c, "Unsupported compression type (%d)\n", (int)compression);
			goto done;
		}
	}

	de_dbg(c, "image size: %dx%d\n", (int)srcbmp->width, (int)srcbmp->height);
	de_dbg(c, "bit count: %d\n", (int)srcbmp->bitcount);

	srcbmp->rowstride = ((srcbmp->bitcount*srcbmp->width + 31) / 32) * 4;

	srcbmp->bitssize = srcbmp->rowstride * srcbmp->height;

	if(srcbmp->bitcount<=8) {
		srcbmp->pal_entries = (de_int64)(1 << (unsigned int)srcbmp->bitcount);
	}
	else {
		srcbmp->pal_entries = 0;
	}
	de_dbg(c, "palette entries: %d\n", (int)srcbmp->pal_entries);

	srcbmp->pal_bytes = srcbmp->pal_entries * srcbmp->pal_bytesperentry;

	srcbmp->hdrs_plus_pal_size = 14 + srcbmp->hdr_size + srcbmp->pal_bytes;

	retval = 1;
done:
	return retval;
}

// Read the header and palette
// Returns NULL on error.
static struct srcbitmap *do_CI_or_CP_segment(deark *c, const char *fmt, de_int64 pos)
{
	int okay = 0;
	struct srcbitmap *srcbmp = NULL;
	de_int64 pal_start;
	de_int64 p;
	de_int64 i;

	de_dbg(c, "-- %s bitmap at %d --\n", fmt, (int)pos);

	srcbmp = de_malloc(c, sizeof(struct srcbitmap));


	if(!get_bitmap_info(c, srcbmp, fmt, pos))
		goto done;

	// read palette
	if (srcbmp->pal_entries > 0) {
		pal_start = pos+14+srcbmp->hdr_size;

		for (i=0; i<srcbmp->pal_entries; i++) {
			p = pal_start + i*srcbmp->pal_bytesperentry;
			srcbmp->pal[i] = DE_MAKE_RGB(de_getbyte(p+2), de_getbyte(p+1), de_getbyte(p));
		}
	}

	okay = 1;

done:
	if(!okay) {
		if(srcbmp) {
			de_free(c, srcbmp);
			srcbmp = NULL; 
		}
	}

	return srcbmp;
}

static void do_generate_final_image(deark *c, struct srcbitmap *srcbmp_main, struct srcbitmap *srcbmp_mask)
{
	struct deark_bitmap *img;
	de_int64 i, j;
	de_int64 byte_offset;
	de_byte x;
	de_byte cr, cg, cb, ca;
	de_byte xorbit, andbit;
	int inverse_warned = 0;

	img = de_bitmap_create(c, srcbmp_main->width, srcbmp_main->height, 4);
	img->flipped = 1;

	cr=0; cg=0; cb=0; ca=255;

	for(j=0; j<srcbmp_main->height; j++) {
		for(i=0; i<srcbmp_main->width; i++) {
			if(srcbmp_main->bitcount<=8) {
				x = de_get_bits_symbol(c->infile, (int)srcbmp_main->bitcount,
					srcbmp_main->bitsoffset + srcbmp_main->rowstride*j, i);
				cr = DE_COLOR_R(srcbmp_main->pal[x]);
				cg = DE_COLOR_G(srcbmp_main->pal[x]);
				cb = DE_COLOR_B(srcbmp_main->pal[x]);
			}
			else if(srcbmp_main->bitcount==24) {
				byte_offset = srcbmp_main->bitsoffset + srcbmp_main->rowstride*j + i*3;
				cb = de_getbyte(byte_offset+0);
				cg = de_getbyte(byte_offset+1);
				cr = de_getbyte(byte_offset+2);
			}
			
			// Get the mask bits
			xorbit = de_get_bits_symbol(c->infile, (int)srcbmp_mask->bitcount,
				srcbmp_mask->bitsoffset + srcbmp_mask->rowstride*j, i);
			andbit = de_get_bits_symbol(c->infile, (int)srcbmp_mask->bitcount,
 				srcbmp_mask->bitsoffset + srcbmp_mask->rowstride*(srcbmp_mask->height/2+j), i);

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
					de_warn(c, "This image contains inverse background pixels, which is not fully supported.\n");
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

	de_bitmap_write_to_file(img, NULL);

	de_bitmap_destroy(img);
}

static void do_CI_or_CP_pair(deark *c, const char *fmt, de_int64 pos)
{
	de_int64 i;
	struct srcbitmap *srcbmp = NULL;
	struct srcbitmap *srcbmp_mask = NULL;
	struct srcbitmap *srcbmp_main = NULL;

	de_dbg(c, "---- %s pair at %d ----\n", fmt, (int)pos);

	for(i=0; i<2; i++) {
		srcbmp = do_CI_or_CP_segment(c, fmt, pos);
		if(!srcbmp) {
			goto done;
		}

		if(srcbmp->hdrs_plus_pal_size<26) {
			de_err(c, "Bad CI or CP image\n");
			goto done;
		}
		pos += srcbmp->hdrs_plus_pal_size;

		// Try to guess whether this is the image or the mask...
		if(srcbmp->bitcount==1 && (srcbmp_mask==NULL || srcbmp_main!=NULL)) {
			de_dbg(c, "bitmap interpreted as: mask\n");
			srcbmp_mask = srcbmp;
		}
		else {
			de_dbg(c, "bitmap interpreted as: foreground\n");
			srcbmp_main = srcbmp;
		}
	}

	if(srcbmp_mask==NULL || srcbmp_main==NULL) {
		de_err(c, "Bad CI or CP image\n");
		goto done;
	}

	do_generate_final_image(c, srcbmp_main, srcbmp_mask);

done:
	de_free(c, srcbmp_mask);
	de_free(c, srcbmp_main);
}

// A BM image inside a BA container.
// Don't convert the image to another format; just extract it as-is in
// BMP format. Unfortunately, this requires collecting the various pieces
// of it, and adjusting pointers.
static void do_BM(deark *c, de_int64 pos)
{
	struct srcbitmap *srcbmp = NULL;
	dbuf *f = NULL;

	de_dbg(c, "---- BM image at %d ----\n", (int)pos);

	srcbmp = de_malloc(c, sizeof(struct srcbitmap));

	if(!get_bitmap_info(c, srcbmp, "BM", pos))
		goto done;


	f = dbuf_create_output_file(c, "bmp");

	// First 10 bytes of the FILEHEADER can be copied unchanged.
	dbuf_copy(c->infile, pos, 10, f);

	// The "bits offset" is probably the only thing we need to adjust.
	dbuf_writeui32le(f, (de_uint32)srcbmp->hdrs_plus_pal_size);

	// Copy the infoheader & palette
	dbuf_copy(c->infile, pos+14, srcbmp->hdrs_plus_pal_size-14, f);

	// Copy the bitmap
	dbuf_copy(c->infile, srcbmp->bitsoffset, srcbmp->bitssize, f);

done:
	dbuf_close(f);
	de_free(c, srcbmp);
}

static void do_BA_segment(deark *c, de_int64 pos, de_int64 *pnextoffset)
{
	de_byte b0, b1;

	de_dbg(c,"------ BA segment at %d ------\n", (int)pos);
	*pnextoffset = 0;

	b0 = de_getbyte(pos+0);
	b1 = de_getbyte(pos+1);
	if(b0!='B' || b1!='A') {
		de_err(c, "Not a BA segment\n");
		goto done;
	}

	*pnextoffset = de_getui32le(pos+6);
	de_dbg(c, "offset of next segment: %d\n", (int)*pnextoffset);

	// Peek at the next two bytes
	b0 = de_getbyte(pos+14+0);
	b1 = de_getbyte(pos+14+1);
	if(b0=='C' && b1=='I') {
		do_CI_or_CP_pair(c, "CI", pos+14);
	}
	else if(b0=='C' && b1=='P') {
		do_CI_or_CP_pair(c, "CP", pos+14);
	}
	else if(b0=='B' && b1=='M') {
		do_BM(c, pos+14);
	}
	else {
		de_err(c, "Not CI, CP, or BM format. Not supported.\n");
		goto done;
	}

done:
	;
}

static void do_BA_file(deark *c)
{
	de_int64 pos;
	de_int64 nextoffset = 0;

	// The file contains a linked list of BA segments. There's nothing special
	// about the first segment, but it can be used to identify the file type.

	pos = 0;
	while(1) {
		do_BA_segment(c, pos, &nextoffset);
		if(nextoffset==0) break;
		pos = nextoffset;
	}
}

#define DE_OS2FMT_BA_CI 1
#define DE_OS2FMT_BA_CP 2
#define DE_OS2FMT_BA_BM 3
#define DE_OS2FMT_BA    4
#define DE_OS2FMT_CI    5
#define DE_OS2FMT_CP    6

static int de_identify_os2bmp_internal(deark *c)
{
	de_byte b[16];
	de_read(b, 0, 16);

	if(b[0]=='B' && b[1]=='A') {
		if(b[14]=='C' && b[15]=='I') return DE_OS2FMT_BA_CI;
		if(b[14]=='C' && b[15]=='P') return DE_OS2FMT_BA_CP;
		if(b[14]=='B' && b[15]=='M') return DE_OS2FMT_BA_BM;
		return DE_OS2FMT_BA;
	}
	if(b[0]=='C' && b[1]=='I') return DE_OS2FMT_CI;
	if(b[0]=='C' && b[1]=='P') return DE_OS2FMT_CP;
	return 0;
}

static void de_run_os2bmp(deark *c, const char *params)
{
	int fmt;

	fmt = de_identify_os2bmp_internal(c);

	switch(fmt) {
	case DE_OS2FMT_BA_CI:
		de_declare_fmt(c, "OS/2 Bitmap Array of Color Icons");
		break;
	case DE_OS2FMT_BA_CP:
		de_declare_fmt(c, "OS/2 Bitmap Array of Color Pointers");
		break;
	case DE_OS2FMT_BA_BM:
		de_declare_fmt(c, "OS/2 Bitmap Array of Bitmaps");
		break;
	case DE_OS2FMT_BA:
		de_declare_fmt(c, "OS/2 Bitmap Array");
		break;
	case DE_OS2FMT_CI:
		de_declare_fmt(c, "OS/2 Color Icon");
		break;
	case DE_OS2FMT_CP:
		de_declare_fmt(c, "OS/2 Color Pointer");
		break;
	}

	switch(fmt) {
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
	case DE_OS2FMT_BA:
		do_BA_file(c);
		break;
	case DE_OS2FMT_CI:
		do_CI_or_CP_pair(c, "CI", 0);
		break;
	case DE_OS2FMT_CP:
		do_CI_or_CP_pair(c, "CP", 0);
		break;
	default:
		de_err(c, "Format not supported\n");
	}
}

static int de_identify_os2bmp(deark *c)
{
	int fmt;
	fmt = de_identify_os2bmp_internal(c);
	switch(fmt) {
	case DE_OS2FMT_BA_CI:
	case DE_OS2FMT_BA_CP:
	case DE_OS2FMT_BA_BM:
		return 100;
	case DE_OS2FMT_BA:
	case DE_OS2FMT_CI:
	case DE_OS2FMT_CP:
		return 80;
	}
	return 0;
}

void de_module_os2bmp(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2bmp";
	mi->run_fn = de_run_os2bmp;
	mi->identify_fn = de_identify_os2bmp;
}
