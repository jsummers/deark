// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows Metafile (WMF)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wmf);

typedef struct localctx_struct {
	int has_aldus_header;
	int input_encoding;
	de_int64 wmf_file_type;
	de_int64 wmf_windows_version;
} lctx;

struct escape_info {
	de_uint16 escfn;
	const char *name;
	void *reserved1;
};

struct decoder_params {
	de_uint16 recfunc;
	de_byte rectype; // low byte of recfunc
	de_int64 recpos;
	de_int64 recsize_words; // total record size in 16-bit units
	de_int64 recsize_bytes; // total record size in bytes
	de_int64 dpos;
	de_int64 dlen;
};

// Handler functions return 0 on fatal error, otherwise 1.
typedef int (*record_decoder_fn)(deark *c, lctx *d, struct decoder_params *dp);

struct wmf_func_info {
	de_byte rectype; // Low byte of the RecordFunction field
	de_byte flags;
	const char *name;
	record_decoder_fn fn;
};

static int wmf_handler_TEXTOUT(deark *c, lctx *d, struct decoder_params *dp)
{
	de_int64 pos = dp->dpos;
	de_int64 stringlen;
	de_ucstring *s = NULL;

	stringlen = de_getui16le(pos);
	pos += 2;

	if(pos+stringlen > dp->dpos+dp->dlen) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, stringlen, DE_DBG_MAX_STRLEN, s,
		0, d->input_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
	return 1;
}

static int wmf_handler_BITBLT_STRETCHBLT_DIBBITBLT(deark *c, lctx *d, struct decoder_params *dp)
{
	de_int64 pos = dp->dpos;
	int has_src_bitmap;
	unsigned int RasterOperation;
	de_int64 XSrc, YSrc;
	de_int64 Width, Height;
	de_int64 YDest, XDest;

	has_src_bitmap = (dp->recsize_words != ((dp->recfunc>>8)+3));
	de_dbg(c, "has src bitmap: %d", has_src_bitmap);
	if(!has_src_bitmap) goto done;

	RasterOperation = (unsigned int)de_getui32le(pos);
	de_dbg(c, "RasterOperation: 0x%08x", RasterOperation);
	pos += 4;

	if(dp->rectype==0x23) { // STRETCHBLT
		de_int64 SrcWidth, SrcHeight;
		SrcHeight = de_geti16le(pos);
		pos += 2;
		SrcWidth = de_geti16le(pos);
		pos += 2;
		de_dbg(c, "SrcWidth, SrcHeight: %d"DE_CHAR_TIMES"%d",
			(int)SrcWidth, (int)SrcHeight);
	}

	YSrc = de_geti16le(pos);
	pos += 2;
	XSrc = de_geti16le(pos);
	pos += 2;
	de_dbg(c, "XSrc, YSrc: (%d, %d)", (int)XSrc, (int)YSrc);

	Height = de_geti16le(pos);
	pos += 2;
	Width = de_geti16le(pos);
	pos += 2;
	de_dbg_dimensions(c, Width, Height);

	YDest = de_geti16le(pos);
	pos += 2;
	XDest = de_geti16le(pos);
	pos += 2;
	de_dbg(c, "XDest, YDest: (%d, %d)", (int)XDest, (int)YDest);

	// TODO: Bitmap16 object (if BITBLT or STRETCHBLT)
	if(dp->rectype==0x40) { // DIBBITBLT
		de_int64 dib_pos, dib_len;

		// TODO: Merge this with the DIBSTRETCHBLT, STRETCHDIB code.
		dib_pos = pos;
		dib_len = dp->dpos + dp->dlen - dib_pos;

		if(dib_len<12) goto done;
		de_dbg(c, "DIB at %d, size=%d", (int)dib_pos, (int)dib_len);

		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice(c, "dib", NULL, c->infile, dib_pos, dib_len);
		de_dbg_indent(c, -1);
	}

done:
	return 1;
}

static const struct escape_info escape_info_arr[] = {
	{ 0x0001, "NEWFRAME", NULL },
	{ 0x0002, "ABORTDOC", NULL },
	{ 0x0003, "NEXTBAND", NULL },
	{ 0x0004, "SETCOLORTABLE", NULL },
	{ 0x0005, "GETCOLORTABLE", NULL },
	{ 0x0006, "FLUSHOUT", NULL },
	{ 0x0007, "DRAFTMODE", NULL },
	{ 0x0008, "QUERYESCSUPPORT", NULL },
	{ 0x0009, "SETABORTPROC", NULL },
	{ 0x000a, "STARTDOC", NULL },
	{ 0x000b, "ENDDOC", NULL },
	{ 0x000c, "GETPHYSPAGESIZE", NULL },
	{ 0x000d, "GETPRINTINGOFFSET", NULL },
	{ 0x000e, "GETSCALINGFACTOR", NULL },
	{ 0x000f, "META_ESCAPE_ENHANCED_METAFILE", NULL },
	{ 0x0010, "SETPENWIDTH", NULL },
	{ 0x0011, "SETCOPYCOUNT", NULL },
	{ 0x0012, "SETPAPERSOURCE", NULL },
	{ 0x0013, "PASSTHROUGH", NULL },
	{ 0x0014, "GETTECHNOLOGY", NULL },
	{ 0x0015, "SETLINECAP", NULL },
	{ 0x0016, "SETLINEJOIN", NULL },
	{ 0x0017, "SETMITERLIMIT", NULL },
	{ 0x0018, "BANDINFO", NULL },
	{ 0x0019, "DRAWPATTERNRECT", NULL },
	{ 0x001a, "GETVECTORPENSIZE", NULL },
	{ 0x001b, "GETVECTORBRUSHSIZE", NULL },
	{ 0x001c, "ENABLEDUPLEX", NULL },
	{ 0x001d, "GETSETPAPERBINS", NULL },
	{ 0x001e, "GETSETPRINTORIENT", NULL },
	{ 0x001f, "ENUMPAPERBINS", NULL },
	{ 0x0020, "SETDIBSCALING", NULL },
	{ 0x0021, "EPSPRINTING", NULL },
	{ 0x0022, "ENUMPAPERMETRICS", NULL },
	{ 0x0023, "GETSETPAPERMETRICS", NULL },
	{ 0x0025, "POSTSCRIPT_DATA", NULL },
	{ 0x0026, "POSTSCRIPT_IGNORE", NULL },
	{ 0x002a, "GETDEVICEUNITS", NULL },
	{ 0x0100, "GETEXTENDEDTEXTMETRICS", NULL },
	{ 0x0102, "GETPAIRKERNTABLE", NULL },
	{ 0x0200, "EXTTEXTOUT", NULL },
	{ 0x0201, "GETFACENAME", NULL },
	{ 0x0202, "DOWNLOADFACE", NULL },
	{ 0x0801, "METAFILE_DRIVER", NULL },
	{ 0x0c01, "QUERYDIBSUPPORT", NULL },
	{ 0x1000, "BEGIN_PATH", NULL },
	{ 0x1001, "CLIP_TO_PATH", NULL },
	{ 0x1002, "END_PATH", NULL },
	{ 0x100e, "OPEN_CHANNEL", NULL },
	{ 0x100f, "DOWNLOADHEADER", NULL },
	{ 0x1010, "CLOSE_CHANNEL", NULL },
	{ 0x1013, "POSTSCRIPT_PASSTHROUGH", NULL },
	{ 0x1014, "ENCAPSULATED_POSTSCRIPT", NULL },
	{ 0x1015, "POSTSCRIPT_IDENTIFY", NULL },
	{ 0x1016, "POSTSCRIPT_INJECTION", NULL },
	{ 0x1017, "CHECKJPEGFORMAT", NULL },
	{ 0x1018, "CHECKPNGFORMAT", NULL },
	{ 0x1019, "GET_PS_FEATURESETTING", NULL },
	{ 0x101a, "MXDC_ESCAPE", NULL },
	{ 0x11d8, "SPCLPASSTHROUGH2", NULL }
};

static void do_ESCAPE_EMF(deark *c, lctx *d, struct decoder_params *dp,
	de_int64 bytecount)
{
	de_int64 emfpos, emflen;
	de_uint32 id;
	de_int64 CommentRecordCount, CurrentRecordSize;
	de_int64 RemainingBytes, EnhancedMetafileDataSize;

	// I am clearly missing something here, because of the half dozen
	// WMF files I have that use this escape, only one of them uses
	// the format that is in the specification. The others are not
	// even remotely close to the documented format.

	// dp->dpos points to the beginning of the EscapeFunction field.
	// There should be 38 more bytes of headers, from this point,
	// followed by EMF data.

	emfpos = dp->dpos+38;
	emflen = bytecount-34;
	if(emflen<=0) {
		de_dbg(c, "[bad embedded EMF data (too short)]");
		goto done;
	}
	id = (de_uint32)de_getui32le(dp->dpos+4);
	if(id!=0x43464d57U) {
		de_dbg(c, "[bad embedded EMF data (bad CommentIdentifier)]");
		goto done;
	}

	CommentRecordCount = de_getui32le(dp->dpos+22);
	de_dbg(c, "CommentRecordCount: %d", (int)CommentRecordCount);
	CurrentRecordSize = de_getui32le(dp->dpos+26);
	de_dbg(c, "CurrentRecordSize: %d", (int)CurrentRecordSize);
	RemainingBytes = de_getui32le(dp->dpos+30);
	de_dbg(c, "RemainingBytes: %d", (int)RemainingBytes);

	// The spec says that the ByteCount field must be 34 +
	// EnhancedMetafileDataSize, but that doesn't make sense to me.
	// Maybe it was supposed to be 34 + CurrentRecordSize?
	EnhancedMetafileDataSize = de_getui32le(dp->dpos+34);
	de_dbg(c, "EnhancedMetafileDataSize: %d", (int)EnhancedMetafileDataSize);

	if(CommentRecordCount!=1) {
		de_dbg(c, "[not decoding EMF data (fragments not supported)]");
		goto done;
	}

	de_dbg(c, "embedded EMF data at %d, len=%d", (int)emfpos, (int)emflen);
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, emfpos, emflen, "emf", NULL, 0);
	}
	else {
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice(c, "emf", NULL, c->infile, emfpos, emflen);
		de_dbg_indent(c, -1);
	}

done:
	;
}

static int wmf_handler_ESCAPE(deark *c, lctx *d, struct decoder_params *dp)
{
	de_uint16 escfn;
	de_int64 bytecount = 0;
	const struct escape_info *einfo = NULL;
	const char *name;
	size_t k;

	escfn = (de_uint16)de_getui16le(dp->dpos);

	// Find the name, etc. of this record type
	for(k=0; k<DE_ITEMS_IN_ARRAY(escape_info_arr); k++) {
		if(escape_info_arr[k].escfn == escfn) {
			einfo = &escape_info_arr[k];
			break;
		}
	}

	if(einfo && einfo->name)
		name = einfo->name;
	else
		name = "?";

	de_dbg(c, "escape function: 0x%04x (%s)", (unsigned int)escfn, name);

	if(dp->dlen>=4) {
		bytecount = de_getui16le(dp->dpos+2);
		de_dbg(c, "bytecount: %d (offset %d + %d = %d)", (int)bytecount,
			(int)(dp->dpos+4), (int)bytecount, (int)(dp->dpos+4+bytecount));
	}

	if(4+bytecount > dp->dlen) {
		goto done;
	}

	if(escfn==0x000f) {
		do_ESCAPE_EMF(c, d, dp, bytecount);
	}

done:
	return 1;
}

static int wmf_handler_EXTTEXTOUT(deark *c, lctx *d, struct decoder_params *dp)
{
	de_int64 pos = dp->dpos;
	de_int64 stringlen;
	de_ucstring *s = NULL;
	de_uint32 fwOpts;

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

	if(pos+stringlen > dp->dpos+dp->dlen) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, stringlen, DE_DBG_MAX_STRLEN, s,
		0, d->input_encoding);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
	return 1;
}

static int wmf_handler_DIBSTRETCHBLT_STRETCHDIB(deark *c, lctx *d, struct decoder_params *dp)
{
	de_int64 dib_pos;
	de_int64 dib_len;
	int hdrsize;
	int has_src_bitmap = 1;

	if(dp->rectype==0x41) { // DIBSTRETCHBLT
		has_src_bitmap = (dp->recsize_words != ((dp->recfunc>>8)+3));
		de_dbg(c, "has src bitmap: %d", has_src_bitmap);
	}

	if(!has_src_bitmap) goto done;
	if(dp->rectype==0x41) // DIBSTRETCHBLT
		hdrsize = 26;
	else
		hdrsize = 28;

	if(dp->recsize_bytes < hdrsize) goto done;
	dib_pos = dp->recpos + hdrsize;
	dib_len = dp->recsize_bytes - hdrsize;
	if(dib_len < 12) goto done;
	de_dbg(c, "DIB at %d, size=%d", (int)dib_pos, (int)dib_len);

	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "dib", NULL, c->infile, dib_pos, dib_len);
	de_dbg_indent(c, -1);

done:
	return 1;
}

static const struct wmf_func_info wmf_func_info_arr[] = {
	{ 0x00, 0, "EOF", NULL },
	{ 0x01, 0, "SETBKCOLOR", NULL },
	{ 0x02, 0, "SETBKMODE", NULL },
	{ 0x03, 0, "SETMAPMODE", NULL },
	{ 0x04, 0, "SETROP2", NULL },
	{ 0x05, 0, "SETRELABS", NULL },
	{ 0x06, 0, "SETPOLYFILLMODE", NULL },
	{ 0x07, 0, "SETSTRETCHBLTMODE", NULL },
	{ 0x08, 0, "SETTEXTCHAREXTRA", NULL },
	{ 0x09, 0, "SETTEXTCOLOR", NULL },
	{ 0x0a, 0, "SETTEXTJUSTIFICATION", NULL },
	{ 0x0b, 0, "SETWINDOWORG", NULL },
	{ 0x0c, 0, "SETWINDOWEXT", NULL },
	{ 0x0d, 0, "SETVIEWPORTORG", NULL },
	{ 0x0e, 0, "SETVIEWPORTEXT", NULL },
	{ 0x0f, 0, "OFFSETWINDOWORG", NULL },
	{ 0x10, 0, "SCALEWINDOWEXT", NULL },
	{ 0x11, 0, "OFFSETVIEWPORTORG", NULL },
	{ 0x12, 0, "SCALEVIEWPORTEXT", NULL },
	{ 0x13, 0, "LINETO", NULL },
	{ 0x14, 0, "MOVETO", NULL },
	{ 0x15, 0, "EXCLUDECLIPRECT", NULL },
	{ 0x16, 0, "INTERSECTCLIPRECT", NULL },
	{ 0x17, 0, "ARC", NULL },
	{ 0x18, 0, "ELLIPSE", NULL },
	{ 0x19, 0, "FLOODFILL", NULL },
	{ 0x1a, 0, "PIE", NULL },
	{ 0x1b, 0, "RECTANGLE", NULL },
	{ 0x1c, 0, "ROUNDRECT", NULL },
	{ 0x1d, 0, "PATBLT", NULL },
	{ 0x1e, 0, "SAVEDC", NULL },
	{ 0x1f, 0, "SETPIXEL", NULL },
	{ 0x20, 0, "OFFSETCLIPRGN", NULL },
	{ 0x21, 0, "TEXTOUT", wmf_handler_TEXTOUT },
	{ 0x22, 0, "BITBLT", wmf_handler_BITBLT_STRETCHBLT_DIBBITBLT },
	{ 0x23, 0, "STRETCHBLT", wmf_handler_BITBLT_STRETCHBLT_DIBBITBLT },
	{ 0x24, 0, "POLYGON", NULL },
	{ 0x25, 0, "POLYLINE", NULL },
	{ 0x26, 0, "ESCAPE", wmf_handler_ESCAPE },
	{ 0x27, 0, "RESTOREDC", NULL },
	{ 0x28, 0, "FILLREGION", NULL },
	{ 0x29, 0, "FRAMEREGION", NULL },
	{ 0x2a, 0, "INVERTREGION", NULL },
	{ 0x2b, 0, "PAINTREGION", NULL },
	{ 0x2c, 0, "SELECTCLIPREGION", NULL },
	{ 0x2d, 0, "SELECTOBJECT", NULL },
	{ 0x2e, 0, "SETTEXTALIGN", NULL },
	{ 0x30, 0, "CHORD", NULL },
	{ 0x31, 0, "SETMAPPERFLAGS", NULL },
	{ 0x32, 0, "EXTTEXTOUT", wmf_handler_EXTTEXTOUT },
	{ 0x33, 0, "SETDIBTODEV", NULL },
	{ 0x34, 0, "SELECTPALETTE", NULL },
	{ 0x35, 0, "REALIZEPALETTE", NULL },
	{ 0x36, 0, "ANIMATEPALETTE", NULL },
	{ 0x37, 0, "SETPALENTRIES", NULL },
	{ 0x38, 0, "POLYPOLYGON", NULL },
	{ 0x39, 0, "RESIZEPALETTE", NULL },
	{ 0x40, 0, "DIBBITBLT", wmf_handler_BITBLT_STRETCHBLT_DIBBITBLT },
	{ 0x41, 0, "DIBSTRETCHBLT", wmf_handler_DIBSTRETCHBLT_STRETCHDIB },
	{ 0x42, 0, "DIBCREATEPATTERNBRUSH", NULL },
	{ 0x43, 0, "STRETCHDIB", wmf_handler_DIBSTRETCHBLT_STRETCHDIB },
	{ 0x48, 0, "EXTFLOODFILL", NULL },
	{ 0x49, 0, "SETLAYOUT", NULL },
	{ 0xf0, 0, "DELETEOBJECT", NULL },
	{ 0xf7, 0, "CREATEPALETTE", NULL },
	{ 0xf9, 0, "CREATEPATTERNBRUSH", NULL },
	{ 0xfa, 0, "CREATEPENINDIRECT", NULL },
	{ 0xfb, 0, "CREATEFONTINDIRECT", NULL },
	{ 0xfc, 0, "CREATEBRUSHINDIRECT", NULL },
	{ 0xff, 0, "CREATEREGION", NULL }
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

static const struct wmf_func_info *find_wmf_func_info(de_uint16 recfunc)
{
	size_t i;
	de_byte rectype_wanted = (de_byte)(recfunc&0xff);

	for(i=0; i<DE_ITEMS_IN_ARRAY(wmf_func_info_arr); i++) {
		if(wmf_func_info_arr[i].rectype == rectype_wanted) {
			return &wmf_func_info_arr[i];
		}
	}
	return NULL;
}

// Returns 0 if EOF record was found.
static int do_wmf_record(deark *c, lctx *d, de_int64 recnum, de_int64 recpos,
	de_int64 recsize_bytes)
{
	const struct wmf_func_info *fnci;
	struct decoder_params dp;

	de_memset(&dp, 0, sizeof(struct decoder_params));
	dp.recpos = recpos;
	dp.recsize_words = recsize_bytes*2;
	dp.recsize_bytes = recsize_bytes;
	dp.dpos = recpos + 6;
	dp.dlen = recsize_bytes - 6;

	dp.recfunc = (de_uint16)de_getui16le(recpos+4);
	dp.rectype = (de_byte)(dp.recfunc&0xff);

	fnci = find_wmf_func_info(dp.recfunc);

	de_dbg(c, "record #%d at %d, type=0x%02x (%s), dpos=%d, dlen=%d", (int)recnum,
		(int)recpos, (unsigned int)dp.rectype,
		fnci ? fnci->name : "?",
		(int)dp.dpos, (int)dp.dlen);

	if(fnci && fnci->fn) {
		de_dbg_indent(c, 1);
		fnci->fn(c, d, &dp);
		de_dbg_indent(c, -1);
	}

	return (dp.rectype==0x00)?0:1;
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

	if(c->input_encoding==DE_ENCODING_UNKNOWN)
		d->input_encoding = DE_ENCODING_WINDOWS1252;
	else
		d->input_encoding = c->input_encoding;

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
