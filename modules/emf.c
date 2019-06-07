// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Enhanced Metafile (EMF)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_emf);

#define CODE_EMFPLUS   0x2b464d45U
#define CODE_GDIC      0x43494447U

typedef struct localctx_struct {
	int input_encoding;
	int is_emfplus;
	int emf_found_header;
	i64 emf_version;
	i64 emf_num_records;
} lctx;

struct decoder_params {
	u32 rectype;
	i64 recpos;
	i64 recsize_bytes;
	i64 dpos;
	i64 dlen;
};

// Handler functions return 0 on fatal error, otherwise 1.
typedef int (*record_decoder_fn)(deark *c, lctx *d, struct decoder_params *dp);

struct emf_func_info {
	u32 rectype;
	const char *name;
	record_decoder_fn fn;
};

struct emfplus_rec_info {
	u32 rectype;
	const char *name;
	void *reserved1;
};

// Note: This is duplicated in wmf.c
static u32 colorref_to_color(u32 colorref)
{
	u32 r,g,b;
	r = DE_COLOR_B(colorref);
	g = DE_COLOR_G(colorref);
	b = DE_COLOR_R(colorref);
	return DE_MAKE_RGB(r,g,b);
}

// Note: This is duplicated in wmf.c
static void do_dbg_colorref(deark *c, lctx *d, u32 colorref)
{
	u32 clr;
	char csamp[16];

	clr = colorref_to_color(colorref);
	de_get_colorsample_code(c, clr, csamp, sizeof(csamp));
	de_dbg(c, "colorref: 0x%08x%s", (unsigned int)colorref, csamp);
}

static void ucstring_strip_trailing_NULs(de_ucstring *s)
{
	while(s->len>=1 && s->str[s->len-1]==0x0000) {
		ucstring_truncate(s, s->len-1);
	}
}

// Header record
static int emf_handler_01(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos;
	i64 file_size;
	i64 handles;
	i64 desc_len;
	i64 desc_offs;
	i64 num_pal_entries;
	int retval = 0;
	de_ucstring *desc = NULL;

	if(d->emf_found_header) { retval = 1; goto done; }
	d->emf_found_header = 1;

	if(dp->recsize_bytes<88) {
		de_err(c, "Invalid EMF header size (is %d, must be at least 88)", (int)dp->recsize_bytes);
		goto done;
	}

	// 2.2.9 Header Object
	pos = dp->recpos + 8;
	d->emf_version = de_getu32le(pos+36);
	de_dbg(c, "version: 0x%08x", (unsigned int)d->emf_version);
	file_size = de_getu32le(pos+40);
	de_dbg(c, "reported file size: %d", (int)file_size);
	d->emf_num_records = de_getu32le(pos+44);
	de_dbg(c, "number of records in file: %d", (int)d->emf_num_records);
	handles = de_getu16le(pos+48);
	de_dbg(c, "handles: %d", (int)handles);
	desc_len = de_getu32le(pos+52);
	desc_offs = de_getu32le(pos+56);
	de_dbg(c, "description offset=%d, len=%d", (int)desc_offs, (int)desc_len);
	num_pal_entries = de_getu32le(pos+60);
	de_dbg(c, "num pal entries: %d", (int)num_pal_entries);

	if((desc_len>0) && (desc_offs+desc_len*2 <= dp->recsize_bytes)) {
		desc = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, dp->recpos+desc_offs, desc_len*2, DE_DBG_MAX_STRLEN*2,
			desc, 0, DE_ENCODING_UTF16LE);
		ucstring_strip_trailing_NULs(desc);
		de_dbg(c, "description: \"%s\"", ucstring_getpsz(desc));
	}

	retval = 1;
done:
	ucstring_destroy(desc);
	return retval;
}

static void do_identify_and_extract_compressed_bitmap(deark *c, lctx *d,
	i64 pos, i64 len)
{
	const char *ext = NULL;
	u8 buf[4];
	i64 nbytes_to_extract;
	i64 foundpos;

	if(len<=0) return;
	if(pos+len > c->infile->len) return;
	nbytes_to_extract = len; // default

	// Having dived six layers of abstraction deep into EMF+ format,
	// we finally come to an actual embedded image.
	// And we *still* don't know what format it's in! We apparently have to
	// sniff the data and make a guess.

	de_dbg(c, "bitmap at %d, padded_len=%d", (int)pos, (int)len);

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
		de_warn(c, "Unidentified bitmap format at %d", (int)pos);
		return;
	}

	if(nbytes_to_extract<=0) return;
	dbuf_create_file_from_slice(c->infile, pos, nbytes_to_extract, ext, NULL, 0);
}

// EmfPlusBitmap
static void do_emfplus_object_image_bitmap(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 w, h;
	i64 ty;
	i64 endpos;
	const char *name;

	if(len<=0) return;
	endpos = pos + len;

	w = de_getu32le(pos);
	h = de_getu32le(pos+4);
	de_dbg_dimensions(c, w, h);

	// 8 stride
	// 12 pixelformat
	ty = de_getu32le(pos+16); // BitmapDataType
	switch(ty) {
	case 0: name="Pixel"; break;
	case 1: name="Compressed"; break;
	default: name="?"; break;
	}
	de_dbg(c, "type: %d (%s)", (int)ty, name);

	if(ty==1) {
		do_identify_and_extract_compressed_bitmap(c, d, pos+20, endpos - (pos+20));
	}
}

// EmfPlusMetafile
static void do_emfplus_object_image_metafile(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 ty;
	i64 dlen;
	const char *name;
	const char *ext = NULL;

	if(len<8) return;

	ty = de_getu32le(pos);
	switch(ty) {
	case 1: name="Wmf"; break;
	case 2: name="WmfPlaceable"; break;
	case 3: name="Emf"; break;
	case 4: name="EmfPlusOnly"; break;
	case 5: name="EmfPlusDual"; break;
	default: name = "?";
	}
	de_dbg(c, "type: %d (%s)", (int)ty, name);

	dlen = de_getu32le(pos+4);
	de_dbg(c, "metafile data size: %d", (int)dlen);

	if(dlen<1 || dlen>len-8) return;

	if(ty==1 || ty==2) ext="wmf";
	else if(ty==3 || ty==4 || ty==5) ext="emf";
	else return;

	dbuf_create_file_from_slice(c->infile, pos+8, dlen, ext, NULL, 0);
}

// EmfPlusImage
static void do_emfplus_object_image(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 ver;
	i64 datatype;
	i64 pos = pos1;
	const char *name;

	ver = de_getu32le(pos);
	datatype = de_getu32le(pos+4);
	name = "?";

	switch(datatype) { // ImageDataType
	case 0: name="Unknown"; break;
	case 1: name="Bitmap"; break; // EmfPlusBitmap
	case 2: name="Metafile"; break; // EmfPlusMetafile
	default: name="?"; break;
	}

	de_dbg(c, "Image osver=0x%08x, type=%d (%s)", (unsigned int)ver,
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
static void do_emfplus_object(deark *c, lctx *d, i64 pos, i64 len,
	u32 flags)
{
	u32 object_id;
	u32 object_type;
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

	de_dbg(c, "EmfPlusObject type=%d (%s), id=%d", (int)object_type, name,
		(int)object_id);

	de_dbg_indent(c, 1);
	if(object_type==5) {
		do_emfplus_object_image(c, d, pos, len);
	}
	de_dbg_indent(c, -1);
}

// EMF+ Comment
static int emfplus_handler_4003(deark *c, lctx *d, i64 rectype, i64 pos, i64 len)
{
	if(c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, pos, len, 256, "comment", 0x1);
	}
	else {
		de_dbg(c, "[%d comment bytes at %d]", (int)len, (int)pos);
	}
	return 1;
}

// EMF+ DrawString
static int emfplus_handler_401c(deark *c, lctx *d, i64 rectype, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 nchars;
	de_ucstring *s = NULL;

	pos += 8; // brushid, formatid
	nchars = de_getu32le(pos);
	pos += 4;
	pos += 16; // layoutrect
	if(pos+nchars*2 > pos1+len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, nchars*2, DE_DBG_MAX_STRLEN*2,
		s, 0, DE_ENCODING_UTF16LE);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
	return 1;
}

static const struct emfplus_rec_info emfplus_rec_info_arr[] = {
	{ 0x4001, "Header", NULL },
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

static void do_one_emfplus_record(deark *c, lctx *d, i64 pos, i64 len,
	i64 *bytes_consumed, int *continuation_flag)
{
	u32 rectype;
	u32 flags;
	i64 size, datasize;
	i64 payload_pos;
	const struct emfplus_rec_info *epinfo = NULL;
	size_t k;
	int is_continued = 0;

	if(len<12) {
		*bytes_consumed = len;
		*continuation_flag = 0;
		return;
	}

	rectype = (u32)de_getu16le(pos);
	flags = (u32)de_getu16le(pos+2);
	size = de_getu32le(pos+4);

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
	datasize = de_getu32le(pos+8);
	payload_pos = pos+12;

	// Find the name, etc. of this record type
	for(k=0; k<DE_ITEMS_IN_ARRAY(emfplus_rec_info_arr); k++) {
		if(emfplus_rec_info_arr[k].rectype == rectype) {
			epinfo = &emfplus_rec_info_arr[k];
			break;
		}
	}

	de_dbg(c, "rectype 0x%04x (%s) at %d, flags=0x%04x, dpos=%d, dlen=%d",
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
	// TODO: Use handler function via epinfo
	if(rectype==0x4003) {
		emfplus_handler_4003(c, d, rectype, payload_pos, datasize);
	}
	else if(rectype==0x4008) {
		do_emfplus_object(c, d, payload_pos, datasize, flags);
	}
	else if(rectype==0x401c) {
		emfplus_handler_401c(c, d, rectype, payload_pos, datasize);
	}
	de_dbg_indent(c, -1);

done:
	if(size<12) size=12;
	*bytes_consumed = size;
	*continuation_flag = is_continued;
}

// Series of EMF+ records (from a single EMF comment)
static void do_comment_emfplus(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 bytes_consumed;
	int continuation_flag = 0;

	de_dbg(c, "EMF+ data at %d, len=%d", (int)pos1, (int)len);
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
static void do_comment_public(deark *c, lctx *d, i64 pos1, i64 len)
{
	u32 ty;
	const char *name;
	ty = (u32)de_getu32le(pos1);
	switch(ty) {
	case 0x80000001U: name = "WINDOWS_METAFILE"; break;
	case 0x00000002U: name = "BEGINGROUP"; break;
	case 0x00000003U: name = "ENDGROUP"; break;
	case 0x40000004U: name = "MULTIFORMATS"; break;
	case 0x00000040U: name = "UNICODE_STRING"; break;
	case 0x00000080U: name = "UNICODE_END"; break;
	default: name = "?";
	}
	de_dbg(c, "public comment record type: 0x%08x (%s)", (unsigned int)ty, name);
}

// Comment record
static int emf_handler_46(deark *c, lctx *d, struct decoder_params *dp)
{
	const char *name;
	i64 datasize;
	int handled = 0;
	enum cmtid_enum { CMTID_UNK, CMTID_EMFSPOOL, CMTID_EMFPLUS, CMTID_PUBLIC,
		CMTID_INKSCAPESCREEN, CMTID_INKSCAPEDRAWING };
	enum cmtid_enum cmtid;

	if(dp->recsize_bytes<16) goto done;

	// Datasize is measured from the beginning of the next field (CommentIdentifier).
	datasize = de_getu32le(dp->recpos+8);
	de_dbg(c, "datasize: %"I64_FMT, datasize);
	if(12+datasize > dp->recsize_bytes) goto done;

	cmtid = CMTID_UNK;
	name="?";

	if(datasize>=4) {
		struct de_fourcc id4cc;

		// The first 4 bytes of comment data might or might not be a signature.
		// The spec expects these bytes to be read as a little-endian int, which is
		// then interpreted as a FOURCC, most-significant byte first.
		// The standard FOURCC codes are designed backwards, so that in the
		// file they appear forward. E.g. the spec says a code is "+FME", but in
		// the file the bytes "EMF+" appear in that order. Our messages respect the
		// spec, though it looks strange.
		dbuf_read_fourcc(c->infile, dp->recpos+12, &id4cc, 4, 0x1);

		if(id4cc.id==0x00000000) {
			cmtid = CMTID_EMFSPOOL;
			name = "EMR_COMMENT_EMFSPOOL";
		}
		else if(id4cc.id==CODE_EMFPLUS) {
			cmtid = CMTID_EMFPLUS;
			name = "EMR_COMMENT_EMFPLUS";
		}
		else if(id4cc.id==CODE_GDIC) {
			cmtid = CMTID_PUBLIC;
			name = "EMR_COMMENT_PUBLIC";
		}

		de_dbg(c, "type: 0x%08x '%s' (%s)", (unsigned int)id4cc.id,
			id4cc.id_dbgstr, name);
	}

	if(cmtid==CMTID_UNK) {
		u8 buf[16];

		// FOURCC not recognized; try other methods
		de_read(buf, dp->recpos+12, 16);
		if(datasize>=7 && !de_memcmp(buf, "Screen=", 7)) {
			cmtid = CMTID_INKSCAPESCREEN;
			name = "Inkscape canvas size";
		}
		else if(datasize>=8 && !de_memcmp(buf, "Drawing=", 8)) {
			cmtid = CMTID_INKSCAPEDRAWING;
			name = "Inkscape image size";
		}

		de_dbg(c, "identified as: %s", name);
	}

	if(cmtid==CMTID_EMFPLUS) {
		do_comment_emfplus(c, d, dp->recpos+16, datasize-4);
		handled = 1;
	}
	else if(cmtid==CMTID_PUBLIC) {
		do_comment_public(c, d, dp->recpos+16, datasize-4);
		handled = 1;
	}

	if(!handled) {
		de_dbg_hexdump(c, c->infile, dp->recpos+12, datasize, 256, NULL, 0x1);
	}

done:
	return 1;
}

static void extract_dib(deark *c, lctx *d, i64 bmi_pos, i64 bmi_len,
	i64 bits_pos, i64 bits_len)
{
	struct de_bmpinfo bi;
	dbuf *outf = NULL;
	i64 real_height;

	if(bmi_len<12 || bmi_len>2048) goto done;
	if(bits_len<1 || bmi_len+bits_len>DE_MAX_SANE_OBJECT_SIZE) goto done;

	if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, bmi_pos, bmi_len, 0)) {
		de_warn(c, "Invalid bitmap");
		goto done;
	}

	real_height = bi.height;

	// Sometimes, only a portion of the image is present. In most cases, we
	// can compensate for that.
	if(bi.bitcount>0 && bi.rowspan>0) {
		i64 nscanlines_present;

		nscanlines_present = bits_len/bi.rowspan;
		if(nscanlines_present>0 && nscanlines_present<bi.height && bi.infohdrsize>=16) {
			real_height = nscanlines_present;
		}
	}

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	de_fmtutil_generate_bmpfileheader(c, outf, &bi, 14 + bmi_len + bits_len);

	if(real_height == bi.height) {
		// Copy the BITMAPINFO (headers & palette)
		dbuf_copy(c->infile, bmi_pos, bmi_len, outf);
	}
	else {
		u8 *tmp_bmi;

		// Make a copy of the BITMAPINFO data, for us to modify.
		tmp_bmi = de_malloc(c, bmi_len);
		de_read(tmp_bmi, bmi_pos, bmi_len);

		de_writeu32le_direct(&tmp_bmi[8], real_height); // Correct the biHeight field

		if(bmi_len>=24) {
			// Correct (or set) the biSizeImage field
			de_writeu32le_direct(&tmp_bmi[20], bits_len);
		}
		dbuf_write(outf, tmp_bmi, bmi_len);
		de_free(c, tmp_bmi);
	}

	// Copy the bitmap bits
	dbuf_copy(c->infile, bits_pos, bits_len, outf);

done:
	dbuf_close(outf);
}

static const char *get_stock_obj_name(unsigned int n)
{
	const char *names[20] = { "WHITE_BRUSH", "LTGRAY_BRUSH", "GRAY_BRUSH",
		"DKGRAY_BRUSH", "BLACK_BRUSH", "NULL_BRUSH", "WHITE_PEN", "BLACK_PEN",
		"NULL_PEN", NULL, "OEM_FIXED_FONT", "ANSI_FIXED_FONT", "ANSI_VAR_FONT",
		"SYSTEM_FONT", "DEVICE_DEFAULT_FONT", "DEFAULT_PALETTE",
		"SYSTEM_FIXED_FONT", "DEFAULT_GUI_FONT", "DC_BRUSH", "DC_PEN" };
	const char *name = NULL;

	if(n & 0x80000000U) {
		unsigned int idx;
		idx = n & 0x7fffffff;
		if(idx<20) name = names[idx];
	}
	return name ? name : "?";
}

static void read_object_index_p(deark *c, lctx *d, i64 *ppos)
{
	unsigned int n;
	n = (unsigned int)de_getu32le_p(ppos);
	if(n & 0x80000000U) {
		// A stock object
		de_dbg(c, "object index: 0x%08x (%s)", n, get_stock_obj_name(n));
	}
	else {
		de_dbg(c, "object index: %u", n);
	}
}

static void read_LogPen(deark *c, lctx *d, i64 pos)
{
	unsigned int style;
	i64 n;
	u32 colorref;

	style = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "style: 0x%08x", style);

	n = de_geti32le_p(&pos); // <PointL>.x = pen width
	de_dbg(c, "width: %d", (int)n);

	pos += 4; // <PointL>.y = unused

	colorref = (u32)de_getu32le_p(&pos);
	do_dbg_colorref(c, d, colorref);
}

static int handler_CREATEPEN(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;

	if(dp->dlen<20) return 1;
	read_object_index_p(c, d, &pos);
	read_LogPen(c, d, pos);
	return 1;
}

static void read_LogBrushEx(deark *c, lctx *d, i64 pos)
{
	unsigned int style;
	u32 colorref;

	style = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "style: 0x%08x", style);

	colorref = (u32)de_getu32le_p(&pos);
	do_dbg_colorref(c, d, colorref);

	// TODO: BrushHatch
}

static int handler_CREATEBRUSHINDIRECT(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;

	if(dp->dlen<16) return 1;
	read_object_index_p(c, d, &pos);
	read_LogBrushEx(c, d, pos);
	return 1;
}

static int handler_colorref(deark *c, lctx *d, struct decoder_params *dp)
{
	u32 colorref;
	colorref = (u32)de_getu32le(dp->dpos);
	do_dbg_colorref(c, d, colorref);
	return 1;
}

// Can handle any record that is, or begins with, and object index.
static int handler_object_index(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;

	if(dp->dlen<4) return 1;
	read_object_index_p(c, d, &pos);
	return 1;
}

// BITBLT
static int emf_handler_4c(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 rop;
	i64 bmi_offs;
	i64 bmi_len;
	i64 bits_offs;
	i64 bits_len;

	if(dp->recsize_bytes<100) return 1;

	rop = de_getu32le(dp->recpos+40);
	de_dbg(c, "raster operation: 0x%08x", (unsigned int)rop);

	bmi_offs = de_getu32le(dp->recpos+84);
	bmi_len = de_getu32le(dp->recpos+88);
	de_dbg(c, "bmi offset=%d, len=%d", (int)bmi_offs, (int)bmi_len);
	bits_offs = de_getu32le(dp->recpos+92);
	bits_len = de_getu32le(dp->recpos+96);
	de_dbg(c, "bits offset=%d, len=%d", (int)bits_offs, (int)bits_len);

	if(bmi_len<12) return 1;
	if(bmi_offs<100) return 1;
	if(bmi_offs+bmi_len>dp->recsize_bytes) return 1;
	if(bits_len<1) return 1;
	if(bits_offs<100) return 1;
	if(bits_offs+bits_len>dp->recsize_bytes) return 1;
	extract_dib(c, d, dp->recpos+bmi_offs, bmi_len, dp->recpos+bits_offs, bits_len);
	return 1;
}

// 0x50 = SetDIBitsToDevice
// 0x51 = StretchDIBits
static int emf_handler_50_51(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 rop;
	i64 bmi_offs;
	i64 bmi_len;
	i64 bits_offs;
	i64 bits_len;
	i64 fixed_header_len;
	i64 num_scans;

	if(dp->rectype==0x50)
		fixed_header_len = 76;
	else
		fixed_header_len = 80;

	if(dp->recsize_bytes<fixed_header_len) return 1;

	bmi_offs = de_getu32le(dp->recpos+48);
	bmi_len = de_getu32le(dp->recpos+52);
	de_dbg(c, "bmi offset=%d, len=%d", (int)bmi_offs, (int)bmi_len);
	bits_offs = de_getu32le(dp->recpos+56);
	bits_len = de_getu32le(dp->recpos+60);
	de_dbg(c, "bits offset=%d, len=%d", (int)bits_offs, (int)bits_len);

	if(dp->rectype==0x51) {
		rop = de_getu32le(dp->recpos+68);
		de_dbg(c, "raster operation: 0x%08x", (unsigned int)rop);
	}

	if(dp->rectype==0x50) {
		num_scans = de_getu32le(dp->recpos+72);
		de_dbg(c, "number of scanlines: %d", (int)num_scans);
	}

	if(bmi_len<12) return 1;
	if(bmi_offs<fixed_header_len) return 1;
	if(bmi_offs+bmi_len>dp->recsize_bytes) return 1;
	if(bits_len<1) return 1;
	if(bits_offs<fixed_header_len) return 1;
	if(bits_offs+bits_len>dp->recsize_bytes) return 1;
	extract_dib(c, d, dp->recpos+bmi_offs, bmi_len, dp->recpos+bits_offs, bits_len);

	return 1;
}

static void do_emf_xEmrText(deark *c, lctx *d, i64 recpos, i64 pos1, i64 len,
	i64 bytesperchar, de_encoding encoding)
{
	i64 pos = pos1;
	i64 nchars;
	i64 offstring;
	de_ucstring *s = NULL;

	pos += 8; // Reference
	nchars = de_getu32le(pos);
	pos += 4;
	offstring = de_getu32le(pos);
	if(recpos+offstring+nchars*bytesperchar > pos1+len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, recpos+offstring, nchars*bytesperchar,
		DE_DBG_MAX_STRLEN*bytesperchar, s, 0, encoding);
	ucstring_strip_trailing_NUL(s);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
}

static void do_emf_aEmrText(deark *c, lctx *d, i64 recpos, i64 pos1, i64 len)
{
	do_emf_xEmrText(c, d, recpos, pos1, len, 1, d->input_encoding);
}

static void do_emf_wEmrText(deark *c, lctx *d, i64 recpos, i64 pos1, i64 len)
{
	do_emf_xEmrText(c, d, recpos, pos1, len, 2, DE_ENCODING_UTF16LE);
}

// 0x53 = EMR_EXTTEXTOUTA
static int emf_handler_53(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->recpos;

	pos += 8; // type, size
	pos += 16; // bounds
	pos += 12; // iGraphicsMode, exScale, eyScale
	do_emf_aEmrText(c, d, dp->recpos, pos, dp->recpos+dp->recsize_bytes - pos);
	return 1;
}

// 0x54 = EMR_EXTTEXTOUTW
static int emf_handler_54(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->recpos;

	pos += 8; // type, size
	pos += 16; // bounds
	pos += 12; // iGraphicsMode, exScale, eyScale
	do_emf_wEmrText(c, d, dp->recpos, pos, dp->recpos+dp->recsize_bytes - pos);
	return 1;
}

static void do_LogFont(deark *c, lctx *d, struct decoder_params *dp, i64 pos1, i64 len)
{
	de_ucstring *facename = NULL;
	i64 pos = pos1;
	i64 n, n2;
	u8 b;

	if(len<92) goto done;

	n = de_geti32le_p(&pos);
	n2 = de_geti32le_p(&pos);
	de_dbg(c, "height,width: %d,%d", (int)n, (int)n2);
	pos += 15;
	b = de_getbyte_p(&pos);
	de_dbg(c, "charset: 0x%02x (%s)", (unsigned int)b,
		de_fmtutil_get_windows_charset_name(b));

	pos += 4;
	facename = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 32*2, facename, 0, DE_ENCODING_UTF16LE);
	ucstring_truncate_at_NUL(facename);
	de_dbg(c, "facename: \"%s\"", ucstring_getpsz_d(facename));

done:
	ucstring_destroy(facename);
}

static void do_LogFontEx(deark *c, lctx *d, struct decoder_params *dp, i64 pos1, i64 len)
{
	do_LogFont(c, d, dp, pos1, len);
	// TODO: FullName, Style, Script

}

static void do_LogFontExDv(deark *c, lctx *d, struct decoder_params *dp, i64 pos1, i64 len)
{
	do_LogFontEx(c, d, dp, pos1, len);
	// TODO: DesignVector
}

static int handler_EXTCREATEFONTINDIRECTW(deark *c, lctx *d, struct decoder_params *dp)
{
	i64 pos = dp->dpos;
	i64 elw_size;

	read_object_index_p(c, d, &pos); // ihFonts

	// "If the size of the elw field is equal to or less than the size of a
	// LogFontPanose object, elw MUST be treated as a fixed-length LogFont object.
	// [Else LogFontExDv.] The size of a LogFontPanose object is 320 decimal."
	elw_size = dp->dlen - 4;

	if(elw_size<=320) {
		do_LogFont(c, d, dp, pos, elw_size);
	}
	else {
		do_LogFontExDv(c, d, dp, pos, elw_size);
	}

	return 1;
}

static const struct emf_func_info emf_func_info_arr[] = {
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
	{ 0x10, "SETMAPPERFLAGS", NULL },
	{ 0x11, "SETMAPMODE", NULL },
	{ 0x12, "SETBKMODE", NULL },
	{ 0x13, "SETPOLYFILLMODE", NULL },
	{ 0x14, "SETROP2", NULL },
	{ 0x15, "SETSTRETCHBLTMODE", NULL },
	{ 0x16, "SETTEXTALIGN", NULL },
	{ 0x17, "SETCOLORADJUSTMENT", NULL },
	{ 0x18, "SETTEXTCOLOR", handler_colorref },
	{ 0x19, "SETBKCOLOR", handler_colorref },
	{ 0x1a, "OFFSETCLIPRGN", NULL },
	{ 0x1b, "MOVETOEX", NULL },
	{ 0x1c, "SETMETARGN", NULL },
	{ 0x1d, "EXCLUDECLIPRECT", NULL },
	{ 0x1e, "INTERSECTCLIPRECT", NULL },
	{ 0x1f, "SCALEVIEWPORTEXTEX", NULL },
	{ 0x20, "SCALEWINDOWEXTEX", NULL },
	{ 0x21, "SAVEDC", NULL },
	{ 0x22, "RESTOREDC", NULL },
	{ 0x23, "SETWORLDTRANSFORM", NULL },
	{ 0x24, "MODIFYWORLDTRANSFORM", NULL },
	{ 0x25, "SELECTOBJECT", handler_object_index },
	{ 0x26, "CREATEPEN", handler_CREATEPEN },
	{ 0x27, "CREATEBRUSHINDIRECT", handler_CREATEBRUSHINDIRECT },
	{ 0x28, "DELETEOBJECT", handler_object_index },
	{ 0x29, "ANGLEARC", NULL },
	{ 0x2a, "ELLIPSE", NULL },
	{ 0x2b, "RECTANGLE", NULL },
	{ 0x2c, "ROUNDRECT", NULL },
	{ 0x2d, "ARC", NULL },
	{ 0x2e, "CHORD", NULL },
	{ 0x2f, "PIE", NULL },
	{ 0x30, "SELECTPALETTE", handler_object_index },
	{ 0x31, "CREATEPALETTE", handler_object_index }, // TODO: A better handler
	{ 0x32, "SETPALETTEENTRIES", NULL },
	{ 0x33, "RESIZEPALETTE", NULL },
	{ 0x34, "REALIZEPALETTE", NULL },
	{ 0x35, "EXTFLOODFILL", NULL },
	{ 0x36, "LINETO", NULL },
	{ 0x37, "ARCTO", NULL },
	{ 0x38, "POLYDRAW", NULL },
	{ 0x39, "SETARCDIRECTION", NULL },
	{ 0x3a, "SETMITERLIMIT", NULL },
	{ 0x3b, "BEGINPATH", NULL },
	{ 0x3c, "ENDPATH", NULL },
	{ 0x3d, "CLOSEFIGURE", NULL },
	{ 0x3e, "FILLPATH", NULL },
	{ 0x3f, "STROKEANDFILLPATH", NULL },
	{ 0x40, "STROKEPATH", NULL },
	{ 0x41, "FLATTENPATH", NULL },
	{ 0x42, "WIDENPATH", NULL },
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
	{ 0x52, "EXTCREATEFONTINDIRECTW", handler_EXTCREATEFONTINDIRECTW },
	{ 0x53, "EXTTEXTOUTA", emf_handler_53 },
	{ 0x54, "EXTTEXTOUTW", emf_handler_54 },
	{ 0x55, "POLYBEZIER16", NULL },
	{ 0x56, "POLYGON16", NULL },
	{ 0x57, "POLYLINE16", NULL },
	{ 0x58, "POLYBEZIERTO16", NULL },
	{ 0x59, "POLYLINETO16", NULL },
	{ 0x5a, "POLYPOLYLINE16", NULL },
	{ 0x5b, "POLYPOLYGON16", NULL },
	{ 0x5c, "POLYDRAW16", NULL },
	{ 0x5d, "CREATEMONOBRUSH", handler_object_index }, // TODO: A better handler
	{ 0x5e, "CREATEDIBPATTERNBRUSHPT", handler_object_index }, // TODO: A better handler
	{ 0x5f, "EXTCREATEPEN", handler_object_index }, // TODO: A better handler
	{ 0x60, "POLYTEXTOUTA", NULL },
	{ 0x61, "POLYTEXTOUTW", NULL },
	{ 0x62, "SETICMMODE", NULL },
	{ 0x63, "CREATECOLORSPACE", handler_object_index }, // TODO: A better handler
	{ 0x64, "SETCOLORSPACE", handler_object_index },
	{ 0x65, "DELETECOLORSPACE", handler_object_index },
	{ 0x66, "GLSRECORD", NULL },
	{ 0x67, "GLSBOUNDEDRECORD", NULL },
	{ 0x68, "PIXELFORMAT", NULL },
	{ 0x69, "DRAWESCAPE", NULL },
	{ 0x6a, "EXTESCAPE", NULL },
	{ 0x6c, "SMALLTEXTOUT", NULL },
	{ 0x6d, "FORCEUFIMAPPING", NULL },
	{ 0x6e, "NAMEDESCAPE", NULL },
	{ 0x6f, "COLORCORRECTPALETTE", NULL },
	{ 0x70, "SETICMPROFILEA", NULL },
	{ 0x71, "SETICMPROFILEW", NULL },
	{ 0x72, "ALPHABLEND", NULL },
	{ 0x73, "SETLAYOUT", NULL },
	{ 0x74, "TRANSPARENTBLT", NULL },
	{ 0x76, "GRADIENTFILL", NULL },
	{ 0x77, "SETLINKEDUFIS", NULL },
	{ 0x78, "ETTEXTJUSTIFICATION", NULL },
	{ 0x79, "COLORMATCHTOTARGETW", NULL },
	{ 0x7a, "CREATECOLORSPACEW", handler_object_index } // TODO: A better handler
};

static const struct emf_func_info *find_emf_func_info(u32 rectype)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(emf_func_info_arr); i++) {
		if(emf_func_info_arr[i].rectype == rectype) {
			return &emf_func_info_arr[i];
		}
	}
	return NULL;
}

static int do_emf_record(deark *c, lctx *d, i64 recnum, i64 recpos,
	i64 recsize_bytes)
{
	int ret;
	const struct emf_func_info *fnci;
	struct decoder_params dp;

	de_zeromem(&dp, sizeof(struct decoder_params));
	dp.recpos = recpos;
	dp.recsize_bytes = recsize_bytes;
	dp.dpos = recpos+8;
	dp.dlen = recsize_bytes-8;
	if(dp.dlen<0) dp.dlen=0;

	dp.rectype = (u32)de_getu32le(recpos);

	fnci = find_emf_func_info(dp.rectype);

	de_dbg(c, "record #%d at %d, type=0x%02x (%s), dpos=%"I64_FMT", dlen=%"I64_FMT,
		(int)recnum, (int)recpos, (unsigned int)dp.rectype,
		fnci ? fnci->name : "?", dp.dpos, dp.dlen);

	if(fnci && fnci->fn) {
		de_dbg_indent(c, 1);
		ret = fnci->fn(c, d, &dp);
		de_dbg_indent(c, -1);
		if(!ret) return 0;
	}

	return (dp.rectype==0x0e) ? 0 : 1; // 0x0e = EOF record
}

static void do_emf_record_list(deark *c, lctx *d)
{
	i64 pos = 0;
	i64 recpos;
	i64 recsize_bytes;
	i64 count = 0;

	// The entire EMF file is a sequence of records. The header record
	// (type 0x01) is expected to appear first.

	while(1) {
		recpos = pos;

		if(recpos+8 > c->infile->len) {
			de_err(c, "Unexpected end of file (no EOF record found)");
			goto done;
		}

		recsize_bytes = de_getu32le(recpos+4);
		if(recpos+recsize_bytes > c->infile->len) {
			de_err(c, "Unexpected end of file in record %d", (int)count);
			goto done;
		}
		if(recsize_bytes<8) {
			de_err(c, "Bad record size (%d) at %d", (int)recsize_bytes, (int)recpos);
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

// Look ahead to figure out if this seem to be an EMF+ file.
// Sets d->is_emfplus.
static void detect_emfplus(deark *c, lctx *d)
{
	i64 nextpos;
	nextpos = de_getu32le(4);
	if(de_getu32le(nextpos)==0x46 &&
		de_getu32le(nextpos+12)==CODE_EMFPLUS)
	{
		d->is_emfplus = 1;
	}
}

static void de_run_emf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	detect_emfplus(c, d);

	if(d->is_emfplus)
		de_declare_fmt(c, "EMF+");
	else
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
	mi->desc = "Enhanced Windows Metafile";
	mi->desc2 = "extract bitmaps only";
	mi->run_fn = de_run_emf;
	mi->identify_fn = de_identify_emf;
}
