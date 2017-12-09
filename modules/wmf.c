// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows Metafile (WMF)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wmf);

typedef struct localctx_struct {
	int has_aldus_header;
	de_int64 wmf_file_type;
	de_int64 wmf_windows_version;
} lctx;

// Handler functions return 0 on fatal error, otherwise 1.
typedef int (*record_decoder_fn)(deark *c, lctx *d, de_int64 rectype, de_int64 recpos,
	de_int64 recsize_bytes);

struct wmf_func_info {
	de_uint16 rectype;
	const char *name;
	record_decoder_fn fn;
};

// EXTTEXTOUT
static int wmf_handler_0a32(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	de_int64 pos = recpos;
	de_int64 stringlen;
	de_ucstring *s = NULL;
	de_uint32 fwOpts;

	pos += 6; // RecordSize, RecordFunction
	pos += 4; // Y, X

	stringlen = de_getui16le(pos);
	pos += 2;

	fwOpts = (de_uint32)de_getui16le(pos);
	pos += 2;

	if(fwOpts & 0x0004) {
		// My best guess is that this flag determines whether the
		// Rectangle field exists. The specification says the field is
		// optional, but AFAICT does not say how to tell whether it exists.
		pos += 8; // Rectangle
	}

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, stringlen, DE_DBG_MAX_STRLEN, s,
		0, DE_ENCODING_WINDOWS1252);
	de_dbg(c, "text: \"%s\"", ucstring_get_printable_sz(s));

	ucstring_destroy(s);
	return 1;
}

// DIBSTRETCHBLT, STRETCHDIB
static int wmf_handler_0b41_0f43(deark *c, lctx *d, de_int64 rectype, de_int64 recpos, de_int64 recsize_bytes)
{
	de_int64 dib_pos;
	de_int64 dib_len;
	int hdrsize;// = 26;

	if(rectype==0x0b41) // DIBSTRETCHBLT
		hdrsize = 26;
	else
		hdrsize = 28;

	if(recsize_bytes < hdrsize) return 1;
	dib_pos = recpos + hdrsize;
	dib_len = recsize_bytes - hdrsize;
	if(dib_len < 12) return 1;
	de_dbg(c, "DIB at %d, size=%d", (int)dib_pos, (int)dib_len);

	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "dib", NULL, c->infile, dib_pos, dib_len);
	de_dbg_indent(c, -1);
	return 1;
}

static const struct wmf_func_info wmf_func_info_arr[] = {
	{ 0x0000, "EOF", NULL },
	{ 0x001e, "SAVEDC", NULL },
	{ 0x0035, "REALIZEPALETTE", NULL },
	{ 0x0037, "SETPALENTRIES", NULL },
	{ 0x00f7, "CREATEPALETTE", NULL },
	{ 0x0102, "SETBKMODE", NULL },
	{ 0x0103, "SETMAPMODE", NULL },
	{ 0x0104, "SETROP2", NULL },
	{ 0x0105, "SETRELABS", NULL },
	{ 0x0106, "SETPOLYFILLMODE", NULL },
	{ 0x0107, "SETSTRETCHBLTMODE", NULL },
	{ 0x0108, "SETTEXTCHAREXTRA", NULL },
	{ 0x0127, "RESTOREDC", NULL },
	{ 0x012a, "INVERTREGION", NULL },
	{ 0x012b, "PAINTREGION", NULL },
	{ 0x012c, "SELECTCLIPREGION", NULL },
	{ 0x012d, "SELECTOBJECT", NULL },
	{ 0x012e, "SETTEXTALIGN", NULL },
	{ 0x0139, "RESIZEPALETTE", NULL },
	{ 0x0142, "DIBCREATEPATTERNBRUSH", NULL },
	{ 0x0149, "SETLAYOUT", NULL },
	{ 0x01f0, "DELETEOBJECT", NULL },
	{ 0x01f9, "CREATEPATTERNBRUSH", NULL },
	{ 0x0201, "SETBKCOLOR", NULL },
	{ 0x0209, "SETTEXTCOLOR", NULL },
	{ 0x020a, "SETTEXTJUSTIFICATION", NULL },
	{ 0x020b, "SETWINDOWORG", NULL },
	{ 0x020c, "SETWINDOWEXT", NULL },
	{ 0x020d, "SETVIEWPORTORG", NULL },
	{ 0x020e, "SETVIEWPORTEXT", NULL },
	{ 0x020f, "OFFSETWINDOWORG", NULL },
	{ 0x0211, "OFFSETVIEWPORTORG", NULL },
	{ 0x0213, "LINETO", NULL },
	{ 0x0214, "MOVETO", NULL },
	{ 0x0220, "OFFSETCLIPRGN", NULL },
	{ 0x0228, "FILLREGION", NULL },
	{ 0x0231, "SETMAPPERFLAGS", NULL },
	{ 0x0234, "SELECTPALETTE", NULL },
	{ 0x02fa, "CREATEPENINDIRECT", NULL },
	{ 0x02fb, "CREATEFONTINDIRECT", NULL },
	{ 0x02fc, "CREATEBRUSHINDIRECT", NULL },
	{ 0x0324, "POLYGON", NULL },
	{ 0x0325, "POLYLINE", NULL },
	{ 0x0410, "SCALEWINDOWEXT", NULL },
	{ 0x0412, "SCALEVIEWPORTEXT", NULL },
	{ 0x0415, "EXCLUDECLIPRECT", NULL },
	{ 0x0416, "INTERSECTCLIPRECT", NULL },
	{ 0x0418, "ELLIPSE", NULL },
	{ 0x0419, "FLOODFILL", NULL },
	{ 0x041b, "RECTANGLE", NULL },
	{ 0x041f, "SETPIXEL", NULL },
	{ 0x0429, "FRAMEREGION", NULL },
	{ 0x0436, "ANIMATEPALETTE", NULL },
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
	{ 0x0a32, "EXTTEXTOUT", wmf_handler_0a32 },
	{ 0x0b41, "DIBSTRETCHBLT", wmf_handler_0b41_0f43 },
	{ 0x0b23, "STRETCHBLT", NULL },
	{ 0x0d33, "SETDIBTODEV", NULL },
	{ 0x0f43, "STRETCHDIB", wmf_handler_0b41_0f43 }
};

static void do_read_aldus_header(deark *c, lctx *d)
{
	de_int64 left, top, right, bottom;
	de_int64 units_per_inch;

	de_dbg(c, "Aldus Placeable Metafile header at 0");
	de_dbg_indent(c, 1);
	left = de_geti16le(6);
	top = de_geti16le(8);
	right = de_geti16le(10);
	bottom = de_geti16le(12);
	de_dbg(c, "location: (%d,%d) - (%d,%d)", (int)left, (int)top,
		(int)right, (int)bottom);
	units_per_inch = de_getui16le(14);
	de_dbg(c, "metafile units per inch: %d", (int)units_per_inch);
	de_dbg_indent(c, -1);
}

static int do_read_wmf_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 hsize_words, maxrecsize_words, filesize_words;
	de_int64 num_objects;
	int retval = 0;

	de_dbg(c, "WMF header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->wmf_file_type = de_getui16le(pos);
	de_dbg(c, "file type: %d", (int)d->wmf_file_type);
	if(d->wmf_file_type!=1 && d->wmf_file_type!=2) {
		de_err(c, "Invalid or unsupported WMF file type (%d)", (int)d->wmf_file_type);
		goto done;
	}
	hsize_words = de_getui16le(pos+2);
	de_dbg(c, "header size: %d bytes", (int)(hsize_words*2));
	if(hsize_words != 9) {
		de_err(c, "Incorrect WMF header size (expected 9, is %d)", (int)hsize_words);
		goto done;
	}
	d->wmf_windows_version = de_getui16le(pos+4);
	de_dbg(c, "Windows version: %d.%d", (int)((d->wmf_windows_version&0xff00)>>8),
		(int)(d->wmf_windows_version&0x00ff));
	filesize_words = de_getui32le(pos+6);
	de_dbg(c, "reported file size: %d bytes", (int)(filesize_words*2));
	num_objects = de_getui16le(pos+10);
	de_dbg(c, "number of objects: %d", (int)num_objects);
	maxrecsize_words = de_getui32le(pos+12);
	de_dbg(c, "max record size: %d bytes", (int)(maxrecsize_words*2));
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static const struct wmf_func_info *find_wmf_func_info(de_int64 rectype)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(wmf_func_info_arr); i++) {
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

	de_dbg(c, "record #%d at %d, type=0x%04x (%s), size=%d bytes", (int)recnum,
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

	de_dbg(c, "record list at %d", (int)pos);
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
	mi->desc = "Windows Metafile";
	mi->desc2 = "extract bitmaps only";
	mi->run_fn = de_run_wmf;
	mi->identify_fn = de_identify_wmf;
}
