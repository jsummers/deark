// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Windows Metafile formats (WMF, EMF, etc.)

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

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
	// This list is not intended to be complete.
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
	{ 0x0201, "SETBKCOLOR", NULL },
	{ 0x0209, "SETTEXTCOLOR", NULL },
	{ 0x020b, "SETWINDOWORG", NULL },
	{ 0x020c, "SETWINDOWEXT", NULL },
	{ 0x020d, "SETVIEWPORTORG", NULL },
	{ 0x020e, "SETVIEWPORTEXT", NULL },
	{ 0x0213, "LINETO", NULL },
	{ 0x0214, "MOVETO", NULL },
	{ 0x0234, "SELECTPALETTE", NULL },
	{ 0x02fa, "CREATEPENINDIRECT", NULL },
	{ 0x02fb, "CREATEFONTINDIRECT", NULL },
	{ 0x02fc, "CREATEBRUSHINDIRECT", NULL },
	{ 0x0324, "POLYGON", NULL },
	{ 0x0325, "POLYLINE", NULL },
	{ 0x0416, "INTERSECTCLIPRECT", NULL },
	{ 0x0418, "ELLIPSE", NULL },
	{ 0x041b, "RECTANGLE", NULL },
	{ 0x041f, "SETPIXEL", NULL },
	{ 0x0521, "TEXTOUT", NULL },
	{ 0x0538, "POLYPOLYGON", NULL },
	{ 0x061d, "PATBLT", NULL },
	{ 0x0626, "ESCAPE", NULL },
	{ 0x0a32, "EXTTEXTOUT", NULL },
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

	if(recsize_bytes < 28) return 1;
	dib_pos = recpos + 28;
	dib_len = recsize_bytes - 28;
	if(dib_len < 12) return 1;
	de_dbg(c, "DIB at %d, size=%d\n", (int)dib_pos, (int)dib_len);

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, dib_pos, dib_len, 0)) {
		de_warn(c, "Invalid bitmap\n");
		goto done;
	}

	outf = dbuf_create_output_file(c, "bmp", NULL);

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

static void do_run_wmf(deark *c, lctx *d)
{
	de_int64 pos = 0;

	if(d->has_aldus_header) {
		do_read_aldus_header(c, d);
		pos = 22;
	}

	if(!do_read_wmf_header(c, d, pos)) {
		return;
	}
	pos += 18;

	do_wmf_record_list(c, d, pos);
}

// **************************************************************************
// EMF
// **************************************************************************

static int emf_handler_01(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes);

struct emf_func_info {
	de_uint32 rectype;
	const char *name;
	record_decoder_fn fn;
};
static const struct emf_func_info emf_func_info_arr[] = {
	// This list is not intended to be complete.
	{ 0x01, "HEADER", emf_handler_01 },
	{ 0x09, "SETWINDOWEXTEX", NULL },
	{ 0x0a, "SETWINDOWORGEX", NULL },
	{ 0x0b, "SETVIEWPORTEXTEX", NULL },
	{ 0x0c, "SETVIEWPORTORGEX", NULL },
	{ 0x0e, "EOF", NULL },
	{ 0x11, "SETMAPMODE", NULL },
	{ 0x12, "SETBKMODE", NULL },
	{ 0x14, "SETROP2", NULL },
	{ 0x15, "SETSTRETCHBLTMODE", NULL },
	{ 0x16, "SETTEXTALIGN", NULL },
	{ 0x18, "SETTEXTCOLOR", NULL },
	{ 0x19, "SETBKCOLOR", NULL },
	{ 0x1a, "OFFSETCLIPRGN", NULL },
	{ 0x1b, "MOVETOEX", NULL },
	{ 0x1c, "SETMETARGN", NULL },
	{ 0x21, "SAVEDC", NULL },
	{ 0x22, "RESTOREDC", NULL },
	{ 0x23, "SETWORLDTRANSFORM", NULL },
	{ 0x25, "SELECTOBJECT", NULL },
	{ 0x26, "CREATEPEN", NULL },
	{ 0x27, "CREATEBRUSHINDIRECT", NULL },
	{ 0x28, "DELETEOBJECT", NULL },
	{ 0x2b, "RECTANGLE", NULL },
	{ 0x36, "LINETO", NULL },
	{ 0x46, "COMMENT", NULL },
	{ 0x52, "EXTCREATEFONTINDIRECTW", NULL },
	{ 0x53, "EXTTEXTOUTA", NULL },
	{ 0x54, "EXTTEXTOUTW", NULL },
	{ 0x56, "POLYGON16", NULL },
	{ 0x57, "POLYLINE16", NULL },
	{ 0x0, NULL, NULL }
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

// TODO: Although EMF files can be parsed, there is not yet the capability
// to extract anything from them.
static void do_run_emf(deark *c, lctx *d)
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

// **************************************************************************

static void de_run_wmf_emf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "\xd7\xcd\xc6\x9a", 4)) {
		d->file_fmt = FMT_WMF;
		d->has_aldus_header = 1;
		de_declare_fmt(c, "WMF (placeable)");
	}
	else if(!dbuf_memcmp(c->infile, 0, "\x01\x00\x00\x00", 4) &&
		!dbuf_memcmp(c->infile, 40, " EMF", 4))
	{
		d->file_fmt = FMT_EMF;
		de_declare_fmt(c, "EMF");
	}
	else {
		d->file_fmt = FMT_WMF;
		de_declare_fmt(c, "WMF (non-placeable)");
	}

	if(d->file_fmt==FMT_EMF) {
		do_run_emf(c, d);
	}
	else {
		do_run_wmf(c, d);
	}

	de_free(c, d);
}

static int de_identify_wmf_emf(deark *c)
{
	de_byte buf[4];

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "\xd7\xcd\xc6\x9a", 4))
		return 100;
	if(!de_memcmp(buf, "\x01\x00\x00\x00", 4) &&
		!dbuf_memcmp(c->infile, 40, " EMF", 4))
	{
		return 100;
	}

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
	mi->run_fn = de_run_wmf_emf;
	mi->identify_fn = de_identify_wmf_emf;
}
