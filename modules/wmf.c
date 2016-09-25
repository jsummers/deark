// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows Metafile (WMF)
// Enhanced Metafile (EMF)

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_wmf);
DE_DECLARE_MODULE(de_module_emf);

#define CODE_EMFPLUS 0x454d462bU
#define CODE_GDIC 0x47444943U

typedef struct localctx_struct {
#define FMT_WMF 1
#define FMT_EMF 2
	int file_fmt;
	int has_aldus_header;
	de_int64 wmf_file_type;
	de_int64 wmf_windows_version;

	int emf_found_header;
	de_int64 emf_version;
	de_int64 emf_num_records;
} lctx;

// Handler functions return 0 on fatal error, otherwise 1.
typedef int (*record_decoder_fn)(deark *c, lctx *d, de_int64 rectype, de_int64 recpos,
	de_int64 recsize_bytes);

// **************************************************************************
// WMF
// **************************************************************************

static int wmf_handler_0f43(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);

struct wmf_func_info {
	de_uint16 rectype;
	const char *name;
	record_decoder_fn fn;
};
static const struct wmf_func_info wmf_func_info_arr[] = {
	// This list is not necessarily complete.
	{ 0x0000, "EOF", NULL },
	{ 0x001e, "SAVEDC", NULL },
	{ 0x0035, "REALIZEPALETTE", NULL },
	{ 0x00f7, "CREATEPALETTE", NULL },
	{ 0x0102, "SETBKMODE", NULL },
	{ 0x0103, "SETMAPMODE", NULL },
	{ 0x0104, "SETROP2", NULL },
	{ 0x0105, "SETRELABS", NULL },
	{ 0x0106, "SETPOLYFILLMODE", NULL },
	{ 0x0107, "SETSTRETCHBLTMODE", NULL },
	{ 0x0127, "RESTOREDC", NULL },
	{ 0x012d, "SELECTOBJECT", NULL },
	{ 0x012e, "SETTEXTALIGN", NULL },
	{ 0x0142, "DIBCREATEPATTERNBRUSH", NULL },
	{ 0x01f0, "DELETEOBJECT", NULL },
	{ 0x01f9, "CREATEPATTERNBRUSH", NULL },
	{ 0x0201, "SETBKCOLOR", NULL },
	{ 0x0209, "SETTEXTCOLOR", NULL },
	{ 0x020b, "SETWINDOWORG", NULL },
	{ 0x020c, "SETWINDOWEXT", NULL },
	{ 0x020d, "SETVIEWPORTORG", NULL },
	{ 0x020e, "SETVIEWPORTEXT", NULL },
	{ 0x0213, "LINETO", NULL },
	{ 0x0214, "MOVETO", NULL },
	{ 0x0220, "OFFSETCLIPRGN", NULL },
	{ 0x0228, "FILLREGION", NULL },
	{ 0x0234, "SELECTPALETTE", NULL },
	{ 0x02fa, "CREATEPENINDIRECT", NULL },
	{ 0x02fb, "CREATEFONTINDIRECT", NULL },
	{ 0x02fc, "CREATEBRUSHINDIRECT", NULL },
	{ 0x0324, "POLYGON", NULL },
	{ 0x0325, "POLYLINE", NULL },
	{ 0x0415, "EXCLUDECLIPRECT", NULL },
	{ 0x0416, "INTERSECTCLIPRECT", NULL },
	{ 0x0418, "ELLIPSE", NULL },
	{ 0x0419, "FLOODFILL", NULL },
	{ 0x041b, "RECTANGLE", NULL },
	{ 0x041f, "SETPIXEL", NULL },
	{ 0x0521, "TEXTOUT", NULL },
	{ 0x0538, "POLYPOLYGON", NULL },
	{ 0x0548, "EXTFLOODFILL", NULL },
	{ 0x061c, "ROUNDRECT", NULL },
	{ 0x061d, "PATBLT", NULL },
	{ 0x0626, "ESCAPE", NULL },
	{ 0x06ff, "CREATEREGION", NULL },
	{ 0x0817, "ARC", NULL },
	{ 0x081a, "PIE", NULL },
	{ 0x0830, "CHORD", NULL },
	{ 0x0922, "BITBLT", NULL },
	{ 0x0940, "DIBBITBLT", NULL },
	{ 0x0a32, "EXTTEXTOUT", NULL },
	{ 0x0b41, "DIBSTRETCHBLT", NULL },
	{ 0x0b23, "STRETCHBLT", NULL },
	{ 0x0f43, "STRETCHDIB", wmf_handler_0f43 },
	{ 0xffff, NULL, NULL }
};

// STRETCHDIB
static int wmf_handler_0f43(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	struct de_bmpinfo bi;
	de_int64 dib_pos;
	de_int64 dib_len;
	dbuf *outf = NULL;

	// TODO: Consolidate this and extract_dib().

	if(recsize_bytes < 28) return 1;
	dib_pos = recpos + 28;
	dib_len = recsize_bytes - 28;
	if(dib_len < 12) return 1;
	de_dbg(c, "DIB at %d, size=%d\n", (int)dib_pos, (int)dib_len);

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, dib_pos, dib_len, 0)) {
		de_warn(c, "Invalid bitmap\n");
		goto done;
	}

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// Write fileheader
	dbuf_write(outf, (const de_byte*)"BM", 2);
	dbuf_writeui32le(outf, 14 + dib_len);
	dbuf_write_zeroes(outf, 4);
	dbuf_writeui32le(outf, 14 + bi.size_of_headers_and_pal);

	// Copy the DIB
	dbuf_copy(c->infile, dib_pos, dib_len, outf);

done:
	dbuf_close(outf);
	return 1;
}

static void do_read_aldus_header(deark *c, lctx *d)
{
	de_int64 left, top, right, bottom;
	de_int64 units_per_inch;

	de_dbg(c, "Aldus Placeable Metafile header at 0\n");
	de_dbg_indent(c, 1);
	left = dbuf_geti16le(c->infile, 6);
	top = dbuf_geti16le(c->infile, 8);
	right = dbuf_geti16le(c->infile, 10);
	bottom = dbuf_geti16le(c->infile, 12);
	de_dbg(c, "location: (%d,%d) - (%d,%d)\n", (int)left, (int)top,
		(int)right, (int)bottom);
	units_per_inch = de_getui16le(14);
	de_dbg(c, "metafile units per inch: %d\n", (int)units_per_inch);
	de_dbg_indent(c, -1);
}

static int do_read_wmf_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 hsize_words, maxrecsize_words, filesize_words;
	de_int64 num_objects;
	int retval = 0;

	de_dbg(c, "WMF header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->wmf_file_type = de_getui16le(pos);
	de_dbg(c, "file type: %d\n", (int)d->wmf_file_type);
	if(d->wmf_file_type!=1 && d->wmf_file_type!=2) {
		de_err(c, "Invalid or unsupported WMF file type (%d)\n", (int)d->wmf_file_type);
		goto done;
	}
	hsize_words = de_getui16le(pos+2);
	de_dbg(c, "header size: %d bytes\n", (int)(hsize_words*2));
	if(hsize_words != 9) {
		de_err(c, "Incorrect WMF header size (expected 9, is %d)\n", (int)hsize_words);
		goto done;
	}
	d->wmf_windows_version = de_getui16le(pos+4);
	de_dbg(c, "Windows version: %d.%d\n", (int)((d->wmf_windows_version&0xff00)>>8),
		(int)(d->wmf_windows_version&0x00ff));
	filesize_words = de_getui32le(pos+6);
	de_dbg(c, "reported file size: %d bytes\n", (int)(filesize_words*2));
	num_objects = de_getui16le(pos+10);
	de_dbg(c, "number of objects: %d\n", (int)num_objects);
	maxrecsize_words = de_getui32le(pos+12);
	de_dbg(c, "max record size: %d bytes\n", (int)(maxrecsize_words*2));
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static const struct wmf_func_info *find_wmf_func_info(de_int64 rectype)
{
	de_int64 i;

	for(i=0; wmf_func_info_arr[i].rectype!=0xffff; i++) {
		if(wmf_func_info_arr[i].rectype == rectype) {
			return &wmf_func_info_arr[i];
		}
	}
	return NULL;
}

// Returns 0 if EOF record was found.
static int do_wmf_record(deark *c, lctx *d, de_int64 recnum, de_int64 recpos,
	de_int64 recsize_bytes)
{
	de_int64 rectype = 0;
	const struct wmf_func_info *fnci;

	rectype = de_getui16le(recpos+4);

	fnci = find_wmf_func_info(rectype);

	de_dbg(c, "record #%d at %d, type=0x%04x (%s), size=%d bytes\n", (int)recnum,
		(int)recpos, (unsigned int)rectype,
		fnci ? fnci->name : "?",
		(int)recsize_bytes);

	if(fnci && fnci->fn) {
		de_dbg_indent(c, 1);
		fnci->fn(c, d, rectype, recpos, recsize_bytes);
		de_dbg_indent(c, -1);
	}

	return (rectype==0x0000)?0:1;
}

static void do_wmf_record_list(deark *c, lctx *d, de_int64 pos)
{
	de_int64 recpos;
	de_int64 recsize_words, recsize_bytes;
	de_int64 count;

	de_dbg(c, "record list at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	count = 0;
	while(1) {
		recpos = pos;
		if(recpos >= c->infile->len) break; // Unexpected EOF

		recsize_words = de_getui32le(recpos);
		recsize_bytes = recsize_words*2;
		if(recpos + recsize_bytes > c->infile->len) break; // Unexpected EOF
		if(recsize_bytes < 6) break; // Invalid size

		if(!do_wmf_record(c, d, count, recpos, recsize_bytes)) {
			break;
		}

		pos += recsize_bytes;
		count++;
	}

	de_dbg_indent(c, -1);
}

static void de_run_wmf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos = 0;

	d = de_malloc(c, sizeof(lctx));

	d->file_fmt = FMT_WMF;
	if(!dbuf_memcmp(c->infile, 0, "\xd7\xcd\xc6\x9a", 4)) {
		d->has_aldus_header = 1;
		de_declare_fmt(c, "WMF (placeable)");
	}
	else {
		de_declare_fmt(c, "WMF (non-placeable)");
	}

	if(d->has_aldus_header) {
		do_read_aldus_header(c, d);
		pos = 22;
	}

	if(!do_read_wmf_header(c, d, pos)) {
		goto done;
	}
	pos += 18;

	do_wmf_record_list(c, d, pos);

done:
	de_free(c, d);
}

static int de_identify_wmf(deark *c)
{
	de_byte buf[4];

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "\xd7\xcd\xc6\x9a", 4))
		return 100;

	if(de_input_file_has_ext(c, "wmf")) {
		de_int64 ftype, hsize;
		ftype = de_getui16le_direct(&buf[0]);
		hsize = de_getui16le_direct(&buf[2]);
		if(hsize==9 && (ftype==1 || ftype==2)) {
			return 80;
		}
	}

	return 0;
}

void de_module_wmf(deark *c, struct deark_module_info *mi)
{
	mi->id = "wmf";
	mi->desc = "Windows Metafile (extract bitmaps only)";
	mi->run_fn = de_run_wmf;
	mi->identify_fn = de_identify_wmf;
}

// **************************************************************************
// EMF
// **************************************************************************

static int emf_handler_01(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);
static int emf_handler_46(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);
static int emf_handler_4c(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);
static int emf_handler_50_51(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);

struct emf_func_info {
	de_uint32 rectype;
	const char *name;
	record_decoder_fn fn;
};
static const struct emf_func_info emf_func_info_arr[] = {
	// This list is not intended to be complete.
	{ 0x01, "HEADER", emf_handler_01 },
	{ 0x02, "POLYBEZIER", NULL },
	{ 0x03, "POLYGON", NULL },
	{ 0x04, "POLYLINE", NULL },
	{ 0x05, "POLYBEZIERTO", NULL },
	{ 0x06, "POLYLINETO", NULL },
	{ 0x07, "POLYPOLYLINE", NULL },
	{ 0x08, "POLYPOLYGON", NULL },
	{ 0x09, "SETWINDOWEXTEX", NULL },
	{ 0x0a, "SETWINDOWORGEX", NULL },
	{ 0x0b, "SETVIEWPORTEXTEX", NULL },
	{ 0x0c, "SETVIEWPORTORGEX", NULL },
	{ 0x0d, "SETBRUSHORGEX", NULL },
	{ 0x0e, "EOF", NULL },
	{ 0x0f, "SETPIXELV", NULL },
	{ 0x11, "SETMAPMODE", NULL },
	{ 0x12, "SETBKMODE", NULL },
	{ 0x13, "SETPOLYFILLMODE", NULL },
	{ 0x14, "SETROP2", NULL },
	{ 0x15, "SETSTRETCHBLTMODE", NULL },
	{ 0x16, "SETTEXTALIGN", NULL },
	{ 0x18, "SETTEXTCOLOR", NULL },
	{ 0x19, "SETBKCOLOR", NULL },
	{ 0x1a, "OFFSETCLIPRGN", NULL },
	{ 0x1b, "MOVETOEX", NULL },
	{ 0x1c, "SETMETARGN", NULL },
	{ 0x1d, "EXCLUDECLIPRECT", NULL },
	{ 0x1e, "INTERSECTCLIPRECT", NULL },
	{ 0x21, "SAVEDC", NULL },
	{ 0x22, "RESTOREDC", NULL },
	{ 0x23, "SETWORLDTRANSFORM", NULL },
	{ 0x24, "MODIFYWORLDTRANSFORM", NULL },
	{ 0x25, "SELECTOBJECT", NULL },
	{ 0x26, "CREATEPEN", NULL },
	{ 0x27, "CREATEBRUSHINDIRECT", NULL },
	{ 0x28, "DELETEOBJECT", NULL },
	{ 0x2a, "ELLIPSE", NULL },
	{ 0x2b, "RECTANGLE", NULL },
	{ 0x2c, "ROUNDRECT", NULL },
	{ 0x2d, "ARC", NULL },
	{ 0x2e, "CHORD", NULL },
	{ 0x2f, "PIE", NULL },
	{ 0x30, "SELECTPALETTE", NULL },
	{ 0x31, "CREATEPALETTE", NULL },
	{ 0x34, "REALIZEPALETTE", NULL },
	{ 0x36, "LINETO", NULL },
	{ 0x37, "ARCTO", NULL },
	{ 0x39, "SETARCDIRECTION", NULL },
	{ 0x3a, "SETMITERLIMIT", NULL },
	{ 0x3b, "BEGINPATH", NULL },
	{ 0x3c, "ENDPATH", NULL },
	{ 0x3d, "CLOSEFIGURE", NULL },
	{ 0x3e, "FILLPATH", NULL },
	{ 0x3f, "STROKEANDFILLPATH", NULL },
	{ 0x40, "STROKEPATH", NULL },
	{ 0x43, "SELECTCLIPPATH", NULL },
	{ 0x44, "ABORTPATH", NULL },
	{ 0x46, "COMMENT", emf_handler_46 },
	{ 0x47, "FILLRGN", NULL },
	{ 0x48, "FRAMERGN", NULL },
	{ 0x49, "INVERTRGN", NULL },
	{ 0x4a, "PAINTRGN", NULL },
	{ 0x4b, "EXTSELECTCLIPRGN", NULL },
	{ 0x4c, "BITBLT", emf_handler_4c },
	{ 0x4d, "STRETCHBLT", NULL },
	{ 0x4e, "MASKBLT", NULL },
	{ 0x4f, "PLGBLT", NULL },
	{ 0x50, "SETDIBITSTODEVICE", emf_handler_50_51 },
	{ 0x51, "STRETCHDIBITS", emf_handler_50_51 },
	{ 0x52, "EXTCREATEFONTINDIRECTW", NULL },
	{ 0x53, "EXTTEXTOUTA", NULL },
	{ 0x54, "EXTTEXTOUTW", NULL },
	{ 0x55, "POLYBEZIER16", NULL },
	{ 0x56, "POLYGON16", NULL },
	{ 0x57, "POLYLINE16", NULL },
	{ 0x58, "POLYBEZIERTO16", NULL },
	{ 0x59, "POLYLINETO16", NULL },
	{ 0x5a, "POLYPOLYLINE16", NULL },
	{ 0x5b, "POLYPOLYGON16", NULL },
	{ 0x5c, "POLYDRAW16", NULL },
	{ 0x5d, "CREATEMONOBRUSH", NULL },
	{ 0x5e, "CREATEDIBPATTERNBRUSHPT", NULL },
	{ 0x5f, "EXTCREATEPEN", NULL },
	{ 0x62, "SETICMMODE", NULL },
	{ 0x6c, "SMALLTEXTOUT", NULL },
	{ 0x73, "SETLAYOUT", NULL },
	{ 0x76, "GRADIENTFILL", NULL },
	{ 0x0, NULL, NULL }
};

struct emfplus_rec_info {
	de_uint32 rectype;
	const char *name;
	void *reserved1;
};
static const struct emfplus_rec_info emfplus_red_info_arr[] = {
	{ 0x4001, "Header", emf_handler_01 },
	{ 0x4002, "EndOfFile", NULL },
	{ 0x4003, "Comment", NULL },
	{ 0x4004, "GetDC", NULL },
	{ 0x4008, "Object", NULL },
	{ 0x4009, "Clear", NULL },
	{ 0x400a, "FillRects", NULL },
	{ 0x400b, "DrawRects", NULL },
	{ 0x400c, "FillPolygon", NULL },
	{ 0x400d, "DrawLines", NULL },
	{ 0x400e, "FillEllipse", NULL },
	{ 0x400f, "DrawEllipse", NULL },
	{ 0x4010, "FillPie", NULL },
	{ 0x4011, "DrawPie", NULL },
	{ 0x4012, "DrawArc", NULL },
	{ 0x4013, "FillRegion", NULL },
	{ 0x4014, "FillPath", NULL },
	{ 0x4015, "DrawPath", NULL },
	{ 0x4016, "FillClosedCurve", NULL },
	{ 0x4017, "DrawClosedCurve", NULL },
	{ 0x4018, "DrawCurve", NULL },
	{ 0x4019, "DrawBeziers", NULL },
	{ 0x401a, "DrawImage", NULL },
	{ 0x401b, "DrawImagePoints", NULL },
	{ 0x401c, "DrawString", NULL },
	{ 0x401e, "SetAntiAliasMode", NULL },
	{ 0x401f, "SetTextRenderingHint", NULL },
	{ 0x4020, "SetTextContrast", NULL },
	{ 0x4021, "SetInterpolationMode", NULL },
	{ 0x4022, "SetPixelOffsetMode", NULL },
	{ 0x4024, "SetCompositingQuality", NULL },
	{ 0x402a, "SetWorldTransform", NULL },
	{ 0x402b, "ResetWorldTransform", NULL },
	{ 0x402c, "MultiplyWorldTransform", NULL },
	{ 0x402d, "TranslateWorldTransform", NULL },
	{ 0x402f, "RotateWorldTransform", NULL },
	{ 0x4030, "SetPageTransform", NULL },
	{ 0x4031, "ResetClip", NULL },
	{ 0x4032, "SetClipRect", NULL },
	{ 0x4033, "SetClipPath", NULL },
	{ 0x4034, "SetClipRegion", NULL },
	{ 0x4035, "OffsetClip", NULL },
	{ 0x4038, "SerializableObject", NULL }
};

// Header record
static int emf_handler_01(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	de_int64 pos;
	de_int64 file_size;
	de_int64 handles;
	de_int64 desc_len;
	de_int64 desc_offs;
	de_int64 num_pal_entries;

	if(d->emf_found_header) return 1;
	d->emf_found_header = 1;

	if(recsize_bytes<88) {
		de_err(c, "Invalid EMF header size (is %d, must be at least 88)\n", (int)recsize_bytes);
		return 0;
	}

	// 2.2.9 Header Object
	pos = recpos + 8;
	d->emf_version = de_getui32le(pos+36);
	de_dbg(c, "version: 0x%08x\n", (unsigned int)d->emf_version);
	file_size = de_getui32le(pos+40);
	de_dbg(c, "reported file size: %d\n", (int)file_size);
	d->emf_num_records = de_getui32le(pos+44);
	de_dbg(c, "number of records in file: %d\n", (int)d->emf_num_records);
	handles = de_getui16le(pos+48);
	de_dbg(c, "handles: %d\n", (int)handles);
	desc_len = de_getui32le(pos+52);
	desc_offs = de_getui32le(pos+56);
	de_dbg(c, "description offset=%d, len=%d\n", (int)desc_offs, (int)desc_len);
	num_pal_entries = de_getui32le(pos+60);
	de_dbg(c, "num pal entries: %d\n", (int)num_pal_entries);

	return 1;
}

static void do_identify_and_extract_compressed_bitmap(deark *c, lctx *d,
	de_int64 pos, de_int64 len)
{
	const char *ext = NULL;
	de_byte buf[4];
	de_int64 nbytes_to_extract;
	de_int64 foundpos;

	if(len<=0) return;
	if(pos+len > c->infile->len) return;
	nbytes_to_extract = len; // default

	// Having dived six layers of abstraction deep into EMF+ format,
	// we finally come to an actual embedded image.
	// And we *still* don't know what format it's in! We apparently have to
	// sniff the data and make a guess.

	de_dbg(c, "bitmap at %d, padded_len=%d\n", (int)pos, (int)len);

	de_read(buf, pos, 4);
	if(buf[0]==0x89 && buf[1]==0x50) {
		ext = "png";
		// The 'len' field includes 0 to 3 padding bytes, which we want to
		// remove. All PNG files end with ae 42 60 82.
		if(dbuf_search_byte(c->infile, '\x82', pos+len-4, 4, &foundpos)) {
			nbytes_to_extract = foundpos + 1 - pos;
		}
	}
	else if(buf[0]==0xff && buf[1]==0xd8) {
		// TODO: Try to detect the true end of file.
		ext = "jpg";
	}
	else if(buf[0]=='G' && buf[1]=='I') {
		// TODO: Try to detect the true end of file.
		ext = "gif";
	}
	else if((buf[0]=='I' && buf[1]=='I') || (buf[0]=='M' && buf[1]=='M')) {
		ext = "tif";
	}
	else {
		de_warn(c, "Unidentified bitmap format at %d\n", (int)pos);
		return;
	}

	if(nbytes_to_extract<=0) return;
	dbuf_create_file_from_slice(c->infile, pos, nbytes_to_extract, ext, NULL, 0);
}

// EmfPlusBitmap
static void do_emfplus_object_image_bitmap(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 w, h;
	de_int64 ty;
	de_int64 endpos;
	const char *name;

	if(len<=0) return;
	endpos = pos + len;

	w = de_getui32le(pos);
	h = de_getui32le(pos+4);
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);

	// 8 stride
	// 12 pixelformat
	ty = de_getui32le(pos+16); // BitmapDataType
	switch(ty) {
	case 0: name="Pixel"; break;
	case 1: name="Compressed"; break;
	default: name="?"; break;
	}
	de_dbg(c, "type: %d (%s)\n", (int)ty, name);

	if(ty==1) {
		do_identify_and_extract_compressed_bitmap(c, d, pos+20, endpos - (pos+20));
	}
}

// EmfPlusMetafile
static void do_emfplus_object_image_metafile(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 ty;
	de_int64 dlen;
	const char *name;
	const char *ext = NULL;

	if(len<8) return;

	ty = de_getui32le(pos);
	switch(ty) {
	case 1: name="Wmf"; break;
	case 2: name="WmfPlaceable"; break;
	case 3: name="Emf"; break;
	case 4: name="EmfPlusOnly"; break;
	case 5: name="EmfPlusDual"; break;
	default: name = "?";
	}
	de_dbg(c, "type: %d (%s)\n", (int)ty, name);

	dlen = de_getui32le(pos+4);
	de_dbg(c, "metafile data size: %d\n", (int)dlen);

	if(dlen<1 || dlen>len-8) return;

	if(ty==1 || ty==2) ext="wmf";
	else if(ty==3 || ty==4 || ty==5) ext="emf";
	else return;

	dbuf_create_file_from_slice(c->infile, pos+8, dlen, ext, NULL, 0);
}

// EmfPlusImage
static void do_emfplus_object_image(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 ver;
	de_int64 datatype;
	de_int64 pos = pos1;
	const char *name;

	ver = de_getui32le(pos);
	datatype = de_getui32le(pos+4);
	name = "?";

	switch(datatype) { // ImageDataType
	case 0: name="Unknown"; break;
	case 1: name="Bitmap"; break; // EmfPlusBitmap
	case 2: name="Metafile"; break; // EmfPlusMetafile
	default: name="?"; break;
	}

	de_dbg(c, "Image osver=0x%08x, type=%d (%s)\n", (unsigned int)ver,
		(int)datatype, name);

	if(datatype==1) {
		do_emfplus_object_image_bitmap(c, d, pos1+8, len-8);
	}
	else if(datatype==2) {
		do_emfplus_object_image_metafile(c, d, pos1+8, len-8);
	}
}

// 0x4008 EmfPlusObject
// pos is the beginning of the 'ObjectData' field
// len is the DataSize field.
static void do_emfplus_object(deark *c, lctx *d, de_int64 pos, de_int64 len,
	de_uint32 flags)
{
	de_uint32 object_id;
	de_uint32 object_type;
	const char *name;
	static const char *names[10] = { "Invalid", "Brush", "Pen", "Path",
		"Region", "Image", "Font", "StringFormat", "ImageAttributes",
		"CustomLineCap" };

	object_type = (flags&0x7f00)>>8;
	object_id = (flags&0x00ff);

	if(object_type<=9)
		name = names[object_type];
	else
		name = "?";

	de_dbg(c, "EmfPlusObject type=%d (%s), id=%d\n", (int)object_type, name,
		(int)object_id);

	de_dbg_indent(c, 1);
	if(object_type==5) {
		do_emfplus_object_image(c, d, pos, len);
	}
	de_dbg_indent(c, -1);
}

static void do_one_emfplus_record(deark *c, lctx *d, de_int64 pos, de_int64 len,
	de_int64 *bytes_consumed, int *continuation_flag)
{
	de_uint32 rectype;
	de_uint32 flags;
	de_int64 size, datasize;
	de_int64 payload_pos;
	const struct emfplus_rec_info *epinfo = NULL;
	de_int64 i;
	int is_continued = 0;

	if(len<12) {
		*bytes_consumed = len;
		*continuation_flag = 0;
		return;
	}

	rectype = (de_uint32)de_getui16le(pos);
	flags = (de_uint32)de_getui16le(pos+2);
	size = de_getui32le(pos+4);

	is_continued = (rectype==0x4008) && (flags&0x8000);

	// The documentation suggests that the datasize field is in a different
	// place if the continuation flag is set. It also suggests the opposite
	// (or maybe just that it's safe to behave as if it were in the same place).
	// It doesn't really matter, since we don't support 'continued' records.
	//
	// I don't know why the datasize field is padded to the next multiple of 4.
	// It seems clearly unnecessary, and counterproductive.
	// There is already the 'size' field above, which is padded, so the
	// only reason for the datasize field to exist at all would be if it
	// told us the *non-padded* size. Yet it doesn't. So now I have to write
	// code to try to detect where an embedded PNG or whatever file ends.
	// (The existence of 'continued' records makes this issue more complicated,
	// but they are already a special case, so that's no excuse.)
	datasize = de_getui32le(pos+8);
	payload_pos = pos+12;

	// Find the name, etc. of this record type
	for(i=0; i<(de_int64)DE_ITEMS_IN_ARRAY(emfplus_red_info_arr); i++) {
		if(emfplus_red_info_arr[i].rectype == rectype) {
			epinfo = &emfplus_red_info_arr[i];
			break;
		}
	}

	de_dbg(c, "rectype 0x%04x (%s) at %d, flags=0x%04x, dpos=%d, dlen=%d\n",
		(unsigned int)rectype, epinfo ? epinfo->name : "?",
		(int)pos,
		(unsigned int)flags,
		(int)payload_pos, (int)datasize);

	// If this record or the previous record had the continuation flag set,
	// give up.
	if(is_continued || *continuation_flag) {
		goto done;
	}

	de_dbg_indent(c, 1);
	if(rectype==0x4008) {
		do_emfplus_object(c, d, payload_pos, datasize, flags);
	}
	de_dbg_indent(c, -1);

done:
	if(size<12) size=12;
	*bytes_consumed = size;
	*continuation_flag = is_continued;
}

// Series of EMF+ records (from a single EMF comment)
static void do_comment_emfplus(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 bytes_consumed;
	int continuation_flag = 0;

	de_dbg(c, "EMF+ data at %d, len=%d\n", (int)pos1, (int)len);
	de_dbg_indent(c, 1);

	while(1) {
		if(pos >= pos1+len) break;
		do_one_emfplus_record(c, d, pos, pos1+len-pos, &bytes_consumed, &continuation_flag);
		pos += bytes_consumed;
	}
	// EMFPlusRecords (one or more EMF+ records)
	de_dbg_indent(c, -1);
}

// Series of EMF+ records (from a single EMF comment)
static void do_comment_public(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_uint32 ty;
	const char *name;
	ty = (de_uint32)de_getui32le(pos1);
	switch(ty) {
	case 0x80000001U: name = "WINDOWS_METAFILE"; break;
	case 0x00000002U: name = "BEGINGROUP"; break;
	case 0x00000003U: name = "ENDGROUP"; break;
	case 0x40000004U: name = "MULTIFORMATS"; break;
	case 0x00000040U: name = "UNICODE_STRING"; break;
	case 0x00000080U: name = "UNICODE_END"; break;
	default: name = "?";
	}
	de_dbg(c, "public comment record type: 0x%08x (%s)\n", (unsigned int)ty, name);
}

// Comment record
static int emf_handler_46(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	struct de_fourcc id4cc;
	const char *name;
	de_int64 datasize;

	//de_dbg(c, "comment at %d len=%d\n", (int)recpos, (int)recsize_bytes);
	if(recsize_bytes<16) goto done;

	// Datasize is measured from the beginning of the next field (CommentIdentifier).
	datasize = de_getui32le(recpos+8);

	dbuf_read_fourcc(c->infile, recpos+12, &id4cc, 0);

	switch(id4cc.id) {
	case 0: name="EMR_COMMENT_EMFSPOOL"; break;
	case CODE_EMFPLUS: name="EMR_COMMENT_EMFPLUS"; break;
	case CODE_GDIC: name="EMR_COMMENT_PUBLIC"; break;
	default: name="?";
	}

	de_dbg(c, "type: 0x%08x '%s' (%s) datasize=%d\n", (unsigned int)id4cc.id, id4cc.id_printable, name,
		(int)datasize);

	if(datasize<=4 || 12+datasize > recsize_bytes) goto done; // Bad datasize

	if(id4cc.id==CODE_EMFPLUS) {
		do_comment_emfplus(c, d, recpos+16, datasize-4);
	}
	else if(id4cc.id==CODE_GDIC) {
		do_comment_public(c, d, recpos+16, datasize-4);
	}

done:
	return 1;
}

static void extract_dib(deark *c, lctx *d, de_int64 bmi_pos, de_int64 bmi_len,
	de_int64 bits_pos, de_int64 bits_len)
{
	struct de_bmpinfo bi;
	dbuf *outf = NULL;
	de_int64 real_height;

	if(bmi_len<12 || bmi_len>2048) goto done;
	if(bits_len<1 || bmi_len+bits_len>DE_MAX_FILE_SIZE) goto done;

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, bmi_pos, bmi_len, 0)) {
		de_warn(c, "Invalid bitmap\n");
		goto done;
	}

	real_height = bi.height;

	// Sometimes, only a portion of the image is present. In most cases, we
	// can compensate for that.
	if(bi.bitcount>0 && bi.rowspan>0) {
		de_int64 nscanlines_present;

		nscanlines_present = bits_len/bi.rowspan;
		if(nscanlines_present>0 && nscanlines_present<bi.height && bi.infohdrsize>=16) {
			real_height = nscanlines_present;
		}
	}

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// Write fileheader
	dbuf_write(outf, (const de_byte*)"BM", 2);
	dbuf_writeui32le(outf, 14 + bmi_len + bits_len);
	dbuf_write_zeroes(outf, 4);
	dbuf_writeui32le(outf, 14 + bi.size_of_headers_and_pal);

	if(real_height == bi.height) {
		// Copy the BITMAPINFO (headers & palette)
		dbuf_copy(c->infile, bmi_pos, bmi_len, outf);
	}
	else {
		de_byte *tmp_bmi;

		// Make a copy of the BITMAPINFO data, for us to modify.
		tmp_bmi = de_malloc(c, bmi_len);
		de_read(tmp_bmi, bmi_pos, bmi_len);

		de_writeui32le_direct(&tmp_bmi[8], real_height); // Correct the biHeight field

		if(bmi_len>=24) {
			// Correct (or set) the biSizeImage field
			de_writeui32le_direct(&tmp_bmi[20], bits_len);
		}
		dbuf_write(outf, tmp_bmi, bmi_len);
		de_free(c, tmp_bmi);
	}

	// Copy the bitmap bits
	dbuf_copy(c->infile, bits_pos, bits_len, outf);

done:
	dbuf_close(outf);
}

// BITBLT
static int emf_handler_4c(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	de_int64 rop;
	de_int64 bmi_offs;
	de_int64 bmi_len;
	de_int64 bits_offs;
	de_int64 bits_len;

	if(recsize_bytes<100) return 1;

	rop = de_getui32le(recpos+40);
	de_dbg(c, "raster operation: 0x%08x\n", (unsigned int)rop);

	bmi_offs = de_getui32le(recpos+84);
	bmi_len = de_getui32le(recpos+88);
	de_dbg(c, "bmi offset=%d, len=%d\n", (int)bmi_offs, (int)bmi_len);
	bits_offs = de_getui32le(recpos+92);
	bits_len = de_getui32le(recpos+96);
	de_dbg(c, "bits offset=%d, len=%d\n", (int)bits_offs, (int)bits_len);

	if(bmi_len<12) return 1;
	if(bmi_offs<100) return 1;
	if(bmi_offs+bmi_len>recsize_bytes) return 1;
	if(bits_len<1) return 1;
	if(bits_offs<100) return 1;
	if(bits_offs+bits_len>recsize_bytes) return 1;
	extract_dib(c, d, recpos+bmi_offs, bmi_len, recpos+bits_offs, bits_len);
	return 1;
}

// 0x50 = SetDIBitsToDevice
// 0x51 = StretchDIBits
static int emf_handler_50_51(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	de_int64 rop;
	de_int64 bmi_offs;
	de_int64 bmi_len;
	de_int64 bits_offs;
	de_int64 bits_len;
	de_int64 fixed_header_len;
	de_int64 num_scans;

	if(rectype==0x50)
		fixed_header_len = 76;
	else
		fixed_header_len = 80;

	if(recsize_bytes<fixed_header_len) return 1;

	bmi_offs = de_getui32le(recpos+48);
	bmi_len = de_getui32le(recpos+52);
	de_dbg(c, "bmi offset=%d, len=%d\n", (int)bmi_offs, (int)bmi_len);
	bits_offs = de_getui32le(recpos+56);
	bits_len = de_getui32le(recpos+60);
	de_dbg(c, "bits offset=%d, len=%d\n", (int)bits_offs, (int)bits_len);

	if(rectype==0x51) {
		rop = de_getui32le(recpos+68);
		de_dbg(c, "raster operation: 0x%08x\n", (unsigned int)rop);
	}

	if(rectype==0x50) {
		num_scans = de_getui32le(recpos+72);
		de_dbg(c, "number of scanlines: %d\n", (int)num_scans);
	}

	if(bmi_len<12) return 1;
	if(bmi_offs<fixed_header_len) return 1;
	if(bmi_offs+bmi_len>recsize_bytes) return 1;
	if(bits_len<1) return 1;
	if(bits_offs<fixed_header_len) return 1;
	if(bits_offs+bits_len>recsize_bytes) return 1;
	extract_dib(c, d, recpos+bmi_offs, bmi_len, recpos+bits_offs, bits_len);

	return 1;
}

static const struct emf_func_info *find_emf_func_info(de_int64 rectype)
{
	de_int64 i;

	for(i=0; emf_func_info_arr[i].rectype!=0; i++) {
		if(emf_func_info_arr[i].rectype == rectype) {
			return &emf_func_info_arr[i];
		}
	}
	return NULL;
}

static int do_emf_record(deark *c, lctx *d, de_int64 recnum, de_int64 recpos,
	de_int64 recsize_bytes)
{
	de_int64 rectype = 0;
	int ret;
	const struct emf_func_info *fnci;

	rectype = de_getui32le(recpos);

	fnci = find_emf_func_info(rectype);

	de_dbg(c, "record #%d at %d, type=0x%02x (%s), size=%d bytes\n", (int)recnum,
		(int)recpos, (unsigned int)rectype,
		fnci ? fnci->name : "?",
		(int)recsize_bytes);

	if(fnci && fnci->fn) {
		de_dbg_indent(c, 1);
		ret = fnci->fn(c, d, rectype, recpos, recsize_bytes);
		de_dbg_indent(c, -1);
		if(!ret) return 0;
	}

	return rectype==0x0e ? 0 : 1; // 0x0e = EOF record
}

static void do_emf_record_list(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_int64 recpos;
	de_int64 recsize_bytes;
	de_int64 count = 0;

	// The entire EMF file is a sequence of records. The header record
	// (type 0x01) is expected to appear first.

	while(1) {
		recpos = pos;

		if(recpos+8 > c->infile->len) {
			de_err(c, "Unexpected end of file (no EOF record found)\n");
			goto done;
		}

		recsize_bytes = de_getui32le(recpos+4);
		if(recpos+recsize_bytes > c->infile->len) {
			de_err(c, "Unexpected end of file in record %d\n", (int)count);
			goto done;
		}

		if(!do_emf_record(c, d, count, recpos, recsize_bytes)) {
			break;
		}

		pos += recsize_bytes;
		count++;
	}

done:
	;
}

static void de_run_emf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->file_fmt = FMT_EMF;
	de_declare_fmt(c, "EMF");
	do_emf_record_list(c, d);

	de_free(c, d);
}

static int de_identify_emf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x01\x00\x00\x00", 4) &&
		!dbuf_memcmp(c->infile, 40, " EMF", 4))
	{
		return 100;
	}
	return 0;
}

void de_module_emf(deark *c, struct deark_module_info *mi)
{
	mi->id = "emf";
	mi->desc = "Enhanced Windows Metafile (extract bitmaps only)";
	mi->run_fn = de_run_emf;
	mi->identify_fn = de_identify_emf;
}
