// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Windows Metafile (WMF)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_wmf);

typedef struct localctx_struct {
	int has_aldus_header;
	int input_encoding;
	i64 wmf_file_type;
	i64 wmf_windows_version;
	unsigned int num_objects;
	dbuf *embedded_emf;
	u8 *object_table;
} lctx;

struct escape_info {
	u16 escfn;
	const char *name;
	void *reserved1;
};

struct decoder_params {
	u16 recfunc;
	u8 rectype; // low byte of recfunc
	i64 recpos;
	i64 recsize_words; // total record size in 16-bit units
	i64 recsize_bytes; // total record size in bytes
	i64 dpos;
	i64 dlen;
};

// Handler functions return 0 on fatal error, otherwise 1.
typedef int (*record_decoder_fn)(deark *c, lctx *d, struct decoder_params *dp);

struct wmf_func_info {
	u8 rectype; // Low byte of the RecordFunction field
	// Flags:
	//  0x1: Creates an object
	u8 flags;
	const char *name;
	record_decoder_fn fn;
};

// Note: This is duplicated in emf.c
static u32 colorref_to_color(u32 colorref)
{
	u32 r,g,b;
	r = DE_COLOR_B(colorref);
	g = DE_COLOR_G(colorref);
	b = DE_COLOR_R(colorref);
	return DE_MAKE_RGB(r,g,b);
}

// Note: This is duplicated in emf.c
static void do_dbg_colorref(deark *c, lctx *d, struct decoder_params *dp, u32 colorref)
{
	u32 clr;
	char csamp[16];

	clr = colorref_to_color(colorref);
	de_get_colorsample_code(c, clr, csamp, sizeof(csamp));
	de_dbg(c, "colorref: 0x%08x%s", (unsigned int)colorref, csamp);
}

static int handler_colorref(deark *c, lctx *d, struct decoder_params *dp)
{
	u32 colorref;

	if(dp->dlen<4) goto done;
	colorref = (u32)de_getu32le(dp->dpos);
	do_dbg_colorref(c, d, dp, colorref);
done:
	return 1;
}

static int wmf_handler_TEXTOUT(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;
	i64 stringlen;
	de_ucstring *s = NULL;

	stringlen = de_getu16le(pos);
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
	i64 pos = dp->dpos;
	int has_src_bitmap;
	unsigned int RasterOperation;
	i64 XSrc, YSrc;
	i64 Width, Height;
	i64 YDest, XDest;

	has_src_bitmap = (dp->recsize_words != ((i64)(dp->recfunc>>8)+3));
	de_dbg(c, "has src bitmap: %d", has_src_bitmap);
	if(!has_src_bitmap) goto done;

	RasterOperation = (unsigned int)de_getu32le(pos);
	de_dbg(c, "RasterOperation: 0x%08x", RasterOperation);
	pos += 4;

	if(dp->rectype==0x23) { // STRETCHBLT
		i64 SrcWidth, SrcHeight;
		SrcHeight = de_geti16le_p(&pos);
		SrcWidth = de_geti16le_p(&pos);
		de_dbg(c, "SrcWidth, SrcHeight: %d"DE_CHAR_TIMES"%d",
			(int)SrcWidth, (int)SrcHeight);
	}

	YSrc = de_geti16le_p(&pos);
	XSrc = de_geti16le_p(&pos);
	de_dbg(c, "XSrc, YSrc: (%d, %d)", (int)XSrc, (int)YSrc);

	Height = de_geti16le_p(&pos);
	Width = de_geti16le_p(&pos);
	de_dbg_dimensions(c, Width, Height);

	YDest = de_geti16le_p(&pos);
	XDest = de_geti16le_p(&pos);
	de_dbg(c, "XDest, YDest: (%d, %d)", (int)XDest, (int)YDest);

	// TODO: Bitmap16 object (if BITBLT or STRETCHBLT)
	if(dp->rectype==0x40) { // DIBBITBLT
		i64 dib_pos, dib_len;

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
	{ 0x000f, "MFCOMMENT", NULL }, // a.k.a. META_ESCAPE_ENHANCED_METAFILE
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

static void do_ESCAPE_MFCOMMENT_EMF(deark *c, lctx *d, struct decoder_params *dp,
	i64 pos1, i64 bytecount)
{
	i64 pos = pos1;
	i64 endpos = dp->dpos + dp->dlen;
	unsigned int CommentId;
	i64 n;
	i64 CommentRecordCount, CurrentRecordSize;
	i64 RemainingBytes, EnhancedMetafileDataSize;

	if(pos+34>endpos) {
		de_dbg(c, "[bad/unsupported embedded EMF data (too short)]");
		goto done;
	}

	CommentId = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "CommentIdentifier: 0x%08x", CommentId);
	if(CommentId!=0x43464d57U) goto done;

	n = de_getu32le_p(&pos);
	de_dbg(c, "CommentType: 0x%08x", (unsigned int)n);
	if(n != 1) {
		de_dbg(c, "[bad/unsupported embedded EMF data (unsupported CommentType)]");
		goto done;
	}

	n = de_getu32le_p(&pos);
	de_dbg(c, "Version: 0x%08x", (unsigned int)n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "CheckSum (reported): 0x%04x", (unsigned int)n);
	n = de_getu32le_p(&pos);
	de_dbg(c, "Flags: 0x%08x", (unsigned int)n);
	CommentRecordCount = de_getu32le_p(&pos);
	de_dbg(c, "CommentRecordCount: %d", (int)CommentRecordCount);
	CurrentRecordSize = de_getu32le_p(&pos);
	de_dbg(c, "CurrentRecordSize: %d", (int)CurrentRecordSize);
	RemainingBytes = de_getu32le_p(&pos);
	de_dbg(c, "RemainingBytes: %d", (int)RemainingBytes);

	// The spec says that the ByteCount field must be 34 +
	// EnhancedMetafileDataSize, but that doesn't make sense to me.
	// Maybe it was supposed to be 34 + CurrentRecordSize?
	EnhancedMetafileDataSize = de_getu32le_p(&pos);
	de_dbg(c, "EnhancedMetafileDataSize: %d", (int)EnhancedMetafileDataSize);

	if(pos+CurrentRecordSize>endpos) goto done;
	de_dbg(c, "embedded EMF data at %d, len=%d", (int)pos, (int)CurrentRecordSize);

	if(!d->embedded_emf && (CurrentRecordSize+RemainingBytes==EnhancedMetafileDataSize)) {
		// Looks like the first record
		d->embedded_emf = dbuf_create_output_file(c, "emf", NULL, 0);
	}

	if(d->embedded_emf) {
		dbuf_copy(c->infile, pos, CurrentRecordSize, d->embedded_emf);
	}

	if(d->embedded_emf && RemainingBytes==0) {
		// Looks like the last record
		dbuf_close(d->embedded_emf);
		d->embedded_emf = NULL;
	}

done:
	;
}

static void do_ESCAPE_MFCOMMENT(deark *c, lctx *d, struct decoder_params *dp,
	i64 bytecount)
{
	i64 pos;
	i64 endpos;
	int commenttype = 0;
	const char *commenttype_name = "?";
	unsigned int sig;

	endpos = dp->dpos + dp->dlen;
	pos = dp->dpos+4; // Skip over EscapeFunction & ByteCount.
	if(pos+bytecount > endpos) goto done;

	if(bytecount>=4) {
		sig = (unsigned int)de_getu32le(pos);
		if(sig==0x43464d57U) {
			commenttype = 1;
			commenttype_name = "META_ESCAPE_ENHANCED_METAFILE";
		}
	}

	de_dbg(c, "identified as: %s", commenttype_name);
	if(commenttype==1) {
		do_ESCAPE_MFCOMMENT_EMF(c, d, dp, pos, bytecount);
	}
	else {
		de_dbg_hexdump(c, c->infile, pos, bytecount, 256, NULL, 0x1);
	}

done:
	;
}

static int wmf_handler_ESCAPE(deark *c, lctx *d, struct decoder_params *dp)
{
	u16 escfn;
	i64 bytecount = 0;
	const struct escape_info *einfo = NULL;
	const char *name;
	size_t k;

	escfn = (u16)de_getu16le(dp->dpos);

	// Find the name, etc. of this record type
	for(k=0; k<DE_ARRAYCOUNT(escape_info_arr); k++) {
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
		bytecount = de_getu16le(dp->dpos+2);
		de_dbg(c, "bytecount: %d (offset %d + %d = %d)", (int)bytecount,
			(int)(dp->dpos+4), (int)bytecount, (int)(dp->dpos+4+bytecount));
	}

	if(4+bytecount > dp->dlen) {
		goto done;
	}

	if(escfn==0x000f) {
		do_ESCAPE_MFCOMMENT(c, d, dp, bytecount);
	}

done:
	return 1;
}

static int wmf_handler_EXTTEXTOUT(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;
	i64 stringlen;
	de_ucstring *s = NULL;
	u32 fwOpts;

	pos += 4; // Y, X

	stringlen = de_getu16le(pos);
	pos += 2;

	fwOpts = (u32)de_getu16le(pos);
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
	i64 dib_pos;
	i64 dib_len;
	int hdrsize;
	int has_src_bitmap = 1;

	if(dp->rectype==0x41) { // DIBSTRETCHBLT
		has_src_bitmap = (dp->recsize_words != ((i64)(dp->recfunc>>8)+3));
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

static int handler_SELECTOBJECT(deark *c, lctx *d, struct decoder_params *dp)
{
	unsigned int oi;
	oi = (unsigned int)de_getu16le(dp->dpos);
	de_dbg(c, "object index: %u", oi);
	return 1;
}

static int handler_DELETEOBJECT(deark *c, lctx *d, struct decoder_params *dp)
{
	unsigned int oi;
	oi = (unsigned int)de_getu16le(dp->dpos);
	de_dbg(c, "object index: %u", oi);
	if(d->object_table && oi<d->num_objects) {
		d->object_table[oi] = 0; // Mark this index as available
	}
	return 1;
}

static const char* get_brushstyle_name(unsigned int n)
{
	static const char *names[7] = { "BS_SOLID", "BS_NULL", "BS_HATCHED", "BS_PATTERN",
		NULL, "BS_DIBPATTERN", "BS_DIBPATTERNPT"};
	const char *name = NULL;

	if(n<=6) {
		name = names[n];
	}
	return name?name:"?";
}

static int handler_CREATEBRUSHINDIRECT(deark *c, lctx *d, struct decoder_params *dp)
{
	unsigned int style;
	i64 pos = dp->dpos;

	if(dp->dlen<8) goto done;
	style = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "style: 0x%04x (%s)", style, get_brushstyle_name(style));

	if(style==0x0 || style==0x2) {
		u32 colorref;
		colorref = (u32)de_getu32le(pos);
		do_dbg_colorref(c, d, dp, colorref);
	}
	pos += 4;

	if(style==0x2) {
		unsigned int h;
		h = (unsigned int)de_getu16le(pos);
		de_dbg(c, "hatch: %u", h);
	}

done:
	return 1;
}

static const char *get_penbasestyle_name(unsigned int n)
{
	static const char *names[9] = { "PS_SOLID", "PS_DASH", "PS_DOT", "PS_DASHDOT",
		"PS_DASHDOTDOT", "PS_NULL", "PS_INSIDEFRAME", "PS_USERSTYLE", "PS_ALTERNATE" };
	const char *name = NULL;

	if(n<=8) {
		name = names[n];
	}
	return name?name:"?";
}

static int handler_CREATEPENINDIRECT(deark *c, lctx *d, struct decoder_params *dp)
{
	u32 colorref;
	i64 pos = dp->dpos;
	unsigned int width;
	unsigned int style;
	unsigned int base_style;
	de_ucstring *style_descr = NULL;

	if(dp->dlen<10) goto done;
	style = (unsigned int)de_getu16le_p(&pos);
	base_style = style&0x0f; // ?
	style_descr = ucstring_create(c);
	ucstring_append_flags_item(style_descr, get_penbasestyle_name(base_style));
	if((style&0x0f00)==0x0100) ucstring_append_flags_item(style_descr, "PS_ENDCAP_SQUARE");
	if((style&0x0f00)==0x0200) ucstring_append_flags_item(style_descr, "PS_ENDCAP_FLAG");
	if((style&0xf000)==0x1000) ucstring_append_flags_item(style_descr, "PS_JOIN_BEVEL");
	if((style&0xf000)==0x2000) ucstring_append_flags_item(style_descr, "PS_JOIN_MITER");
	de_dbg(c, "style: 0x%04x (%s)", style, ucstring_getpsz(style_descr));

	if(base_style!=0x5) {
		width = (unsigned int)de_getu32le(pos);
		width &= 0x0000ffffU;
		de_dbg(c, "width: %u", width);
	}
	pos += 4;

	if(base_style!=0x5) {
		colorref = (u32)de_getu32le(pos);
		do_dbg_colorref(c, d, dp, colorref);
	}

done:
	ucstring_destroy(style_descr);
	return 1;
}

static int handler_CREATEFONTINDIRECT(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 facename_size;
	i64 n, n2;
	u8 b;
	i64 pos = dp->dpos;

	n = de_geti16le_p(&pos);
	n2 = de_geti16le_p(&pos);
	de_dbg(c, "height,width: %d,%d", (int)n, (int)n2);
	pos += 9;
	b = de_getbyte_p(&pos);
	de_dbg(c, "charset: 0x%02x (%s)", (unsigned int)b,
		de_fmtutil_get_windows_charset_name(b));

	facename_size = dp->dlen-18;
	if(facename_size>32) facename_size=32;
	if(facename_size>=2) {
		de_ucstring *facename = NULL;
		facename = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, dp->dpos+18, facename_size, facename,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_WINDOWS1252);
		de_dbg(c, "facename: \"%s\"", ucstring_getpsz_d(facename));
		ucstring_destroy(facename);
	}
	return 1;
}

static int handler_FILLREGION(deark *c, lctx *d, struct decoder_params *dp)
{
	unsigned int oi;
	i64 pos = dp->dpos;

	oi = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "region object index: %u", oi);
	oi = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "brush object index: %u", oi);
	return 1;
}

static const struct wmf_func_info wmf_func_info_arr[] = {
	{ 0x00, 0, "EOF", NULL },
	{ 0x01, 0, "SETBKCOLOR",  handler_colorref },
	{ 0x02, 0, "SETBKMODE", NULL },
	{ 0x03, 0, "SETMAPMODE", NULL },
	{ 0x04, 0, "SETROP2", NULL },
	{ 0x05, 0, "SETRELABS", NULL },
	{ 0x06, 0, "SETPOLYFILLMODE", NULL },
	{ 0x07, 0, "SETSTRETCHBLTMODE", NULL },
	{ 0x08, 0, "SETTEXTCHAREXTRA", NULL },
	{ 0x09, 0, "SETTEXTCOLOR",  handler_colorref },
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
	{ 0x28, 0, "FILLREGION", handler_FILLREGION },
	{ 0x29, 0, "FRAMEREGION", NULL },
	{ 0x2a, 0, "INVERTREGION", NULL },
	{ 0x2b, 0, "PAINTREGION", NULL },
	{ 0x2c, 0, "SELECTCLIPREGION", handler_SELECTOBJECT },
	{ 0x2d, 0, "SELECTOBJECT", handler_SELECTOBJECT },
	{ 0x2e, 0, "SETTEXTALIGN", NULL },
	{ 0x30, 0, "CHORD", NULL },
	{ 0x31, 0, "SETMAPPERFLAGS", NULL },
	{ 0x32, 0, "EXTTEXTOUT", wmf_handler_EXTTEXTOUT },
	{ 0x33, 0, "SETDIBTODEV", NULL },
	{ 0x34, 0, "SELECTPALETTE", handler_SELECTOBJECT },
	{ 0x35, 0, "REALIZEPALETTE", NULL },
	{ 0x36, 0, "ANIMATEPALETTE", NULL },
	{ 0x37, 0, "SETPALENTRIES", NULL },
	{ 0x38, 0, "POLYPOLYGON", NULL },
	{ 0x39, 0, "RESIZEPALETTE", NULL },
	{ 0x40, 0, "DIBBITBLT", wmf_handler_BITBLT_STRETCHBLT_DIBBITBLT },
	{ 0x41, 0, "DIBSTRETCHBLT", wmf_handler_DIBSTRETCHBLT_STRETCHDIB },
	{ 0x42, 1, "DIBCREATEPATTERNBRUSH", NULL },
	{ 0x43, 0, "STRETCHDIB", wmf_handler_DIBSTRETCHBLT_STRETCHDIB },
	{ 0x48, 0, "EXTFLOODFILL", NULL },
	{ 0x49, 0, "SETLAYOUT", NULL },
	{ 0xf0, 0, "DELETEOBJECT", handler_DELETEOBJECT },
	{ 0xf7, 1, "CREATEPALETTE", NULL },
	{ 0xf9, 1, "CREATEPATTERNBRUSH", NULL },
	{ 0xfa, 1, "CREATEPENINDIRECT", handler_CREATEPENINDIRECT },
	{ 0xfb, 1, "CREATEFONTINDIRECT", handler_CREATEFONTINDIRECT },
	{ 0xfc, 1, "CREATEBRUSHINDIRECT", handler_CREATEBRUSHINDIRECT },
	{ 0xff, 1, "CREATEREGION", NULL }
};

static void do_read_aldus_header(deark *c, lctx *d)
{
	i64 left, top, right, bottom;
	i64 units_per_inch;

	de_dbg(c, "Aldus Placeable Metafile header at 0");
	de_dbg_indent(c, 1);
	left = de_geti16le(6);
	top = de_geti16le(8);
	right = de_geti16le(10);
	bottom = de_geti16le(12);
	de_dbg(c, "location: (%d,%d) - (%d,%d)", (int)left, (int)top,
		(int)right, (int)bottom);
	units_per_inch = de_getu16le(14);
	de_dbg(c, "metafile units per inch: %d", (int)units_per_inch);
	de_dbg_indent(c, -1);
}

static int do_read_wmf_header(deark *c, lctx *d, i64 pos)
{
	i64 hsize_words, maxrecsize_words, filesize_words;
	int retval = 0;

	de_dbg(c, "WMF header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->wmf_file_type = de_getu16le(pos);
	de_dbg(c, "file type: %d", (int)d->wmf_file_type);
	if(d->wmf_file_type!=1 && d->wmf_file_type!=2) {
		de_err(c, "Invalid or unsupported WMF file type (%d)", (int)d->wmf_file_type);
		goto done;
	}
	hsize_words = de_getu16le(pos+2);
	de_dbg(c, "header size: %d bytes", (int)(hsize_words*2));
	if(hsize_words != 9) {
		de_err(c, "Incorrect WMF header size (expected 9, is %d)", (int)hsize_words);
		goto done;
	}
	d->wmf_windows_version = de_getu16le(pos+4);
	de_dbg(c, "Windows version: %d.%d", (int)((d->wmf_windows_version&0xff00)>>8),
		(int)(d->wmf_windows_version&0x00ff));
	filesize_words = de_getu32le(pos+6);
	de_dbg(c, "reported file size: %d bytes", (int)(filesize_words*2));

	d->num_objects = (unsigned int)de_getu16le(pos+10);
	de_dbg(c, "number of objects: %u", d->num_objects);
	if(d->object_table) de_free(c, d->object_table);
	// d->num_objects is untrusted, but it can only be from 0 to 65535.
	d->object_table = de_malloc(c, d->num_objects);

	maxrecsize_words = de_getu32le(pos+12);
	de_dbg(c, "max record size: %d bytes", (int)(maxrecsize_words*2));
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static const struct wmf_func_info *find_wmf_func_info(u16 recfunc)
{
	size_t i;
	u8 rectype_wanted = (u8)(recfunc&0xff);

	for(i=0; i<DE_ARRAYCOUNT(wmf_func_info_arr); i++) {
		if(wmf_func_info_arr[i].rectype == rectype_wanted) {
			return &wmf_func_info_arr[i];
		}
	}
	return NULL;
}

static void on_create_object(deark *c, lctx *d, struct decoder_params *dp)
{
	unsigned int k;

	if(!d->object_table) return;
	// The CREATE* opcodes assign an object index to the new object.
	// Specifically, the first available index in the object table.
	// The encoder and decoder must be very careful to use exactly the same
	// algorithm for index assignment, or they could get out of sync.
	for(k=0; k<d->num_objects; k++) {
		if(d->object_table[k]==0) {
			d->object_table[k] = 1; // Mark this index as used
			de_dbg(c, "assigned object index: %u", k);
			return;
		}
	}
	de_warn(c, "Out of space in object table");
}


// Returns 0 if EOF record was found.
static int do_wmf_record(deark *c, lctx *d, i64 recnum, i64 recpos,
	i64 recsize_bytes)
{
	const struct wmf_func_info *fnci;
	struct decoder_params dp;

	de_zeromem(&dp, sizeof(struct decoder_params));
	dp.recpos = recpos;
	dp.recsize_words = recsize_bytes*2;
	dp.recsize_bytes = recsize_bytes;
	dp.dpos = recpos + 6;
	dp.dlen = recsize_bytes - 6;

	dp.recfunc = (u16)de_getu16le(recpos+4);
	dp.rectype = (u8)(dp.recfunc&0xff);

	fnci = find_wmf_func_info(dp.recfunc);

	de_dbg(c, "record #%d at %d, func=0x%04x (%s), dpos=%d, dlen=%d", (int)recnum,
		(int)recpos, (unsigned int)dp.recfunc,
		fnci ? fnci->name : "?",
		(int)dp.dpos, (int)dp.dlen);

	de_dbg_indent(c, 1);
	if(fnci && (fnci->flags&0x1)) {
		on_create_object(c, d, &dp);
	}
	if(fnci && fnci->fn) {
		fnci->fn(c, d, &dp);
	}
	de_dbg_indent(c, -1);

	return (dp.rectype==0x00)?0:1;
}

static void do_wmf_record_list(deark *c, lctx *d, i64 pos)
{
	i64 recpos;
	i64 recsize_words, recsize_bytes;
	i64 count;

	de_dbg(c, "record list at %d", (int)pos);
	de_dbg_indent(c, 1);

	count = 0;
	while(1) {
		recpos = pos;
		if(recpos >= c->infile->len) break; // Unexpected EOF

		recsize_words = de_getu32le(recpos);
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
	i64 pos = 0;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

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
	if(d) {
		if(d->embedded_emf) dbuf_close(d->embedded_emf);
		de_free(c, d->object_table);
		de_free(c, d);
	}
}

static int de_identify_wmf(deark *c)
{
	u8 buf[4];

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "\xd7\xcd\xc6\x9a", 4))
		return 100;

	if(de_input_file_has_ext(c, "wmf")) {
		i64 ftype, hsize;
		ftype = de_getu16le_direct(&buf[0]);
		hsize = de_getu16le_direct(&buf[2]);
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
