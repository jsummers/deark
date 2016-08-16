// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This module supports the "image resources" section of PSD files.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_psd);

#define CODE_8B64 0x38243634U
#define CODE_8BIM 0x3842494dU
#define CODE_Layr 0x4c617972U

typedef struct localctx_struct {
	int reserved;
} lctx;

struct rsrc_info;

typedef void (*rsrc_handler_fn)(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);

struct rsrc_info {
	de_uint16 id;

	// 0x4 = Item consists of a version number, followed by a "Descriptor structure".
	de_uint32 flags;

	const char *idname;
	rsrc_handler_fn hfn;
};

#define DECLARE_HRSRC(x) static void x(deark *c, lctx *d, const struct rsrc_info *ri, de_int64 pos, de_int64 len)

DECLARE_HRSRC(hrsrc_resolutioninfo);
DECLARE_HRSRC(hrsrc_iptc);
DECLARE_HRSRC(hrsrc_exif);
DECLARE_HRSRC(hrsrc_xmp);
DECLARE_HRSRC(hrsrc_iccprofile);
DECLARE_HRSRC(hrsrc_slices);
DECLARE_HRSRC(hrsrc_thumbnail);
DECLARE_HRSRC(hrsrc_unicodestring);
DECLARE_HRSRC(hrsrc_versioninfo);

static const struct rsrc_info rsrc_info_arr[] = {
	{ 0x03e8, 0, "channels/rows/columns/depth/mode", NULL },
	{ 0x03e9, 0, "Macintosh print manager print info", NULL },
	{ 0x03ea, 0, "Macintosh page format information", NULL },
	{ 0x03eb, 0, "Indexed color table", NULL },
	{ 0x03ed, 0, "Resolution info", hrsrc_resolutioninfo },
	{ 0x03ee, 0, "Names of the alpha channels", NULL },
	{ 0x03ef, 0, "Display information", NULL },
	{ 0x03f0, 0, "Caption", NULL },
	{ 0x03f1, 0, "Border information", NULL },
	{ 0x03f2, 0, "Background color", NULL },
	{ 0x03f3, 0, "Print flags", NULL },
	{ 0x03f4, 0, "Grayscale and multichannel halftoning information", NULL },
	{ 0x03f5, 0, "Color halftoning info", NULL },
	{ 0x03f6, 0, "Duotone halftoning information", NULL },
	{ 0x03f7, 0, "Grayscale and multichannel transfer function", NULL },
	{ 0x03f8, 0, "Color transfer functions", NULL },
	{ 0x03f9, 0, "Duotone transfer functions", NULL },
	{ 0x03fa, 0, "Duotone image information", NULL },
	{ 0x03fb, 0, "Effective black and white values", NULL },
	//{ 0x03fc, 0, "(Obsolete)", NULL },
	{ 0x03fd, 0, "EPS options", NULL },
	{ 0x03fe, 0, "Quick Mask information", NULL },
	//{ 0x03ff, 0, "(Obsolete)", NULL },
	{ 0x0400, 0, "Layer state information", NULL },
	{ 0x0401, 0, "Working path", NULL },
	{ 0x0402, 0, "Layers group information", NULL },
	//{ 0x0403, 0, "(Obsolete)", NULL },
	{ 0x0404, 0, "IPTC-NAA", hrsrc_iptc },
	{ 0x0405, 0, "Image mode for raw format files", NULL },
	{ 0x0406, 0, "JPEG quality", NULL },
	{ 0x0408, 0, "Grid and guides info", NULL },
	{ 0x0409, 0, "Thumbnail - Photoshop 4.0", hrsrc_thumbnail },
	{ 0x040a, 0, "Copyright flag", NULL },
	{ 0x040b, 0, "URL", NULL },
	{ 0x040c, 0, "Thumbnail", hrsrc_thumbnail },
	{ 0x040d, 0, "Global Angle", NULL },
	{ 0x040e, 0, "Color samplers resource (Photoshop 5.0)", NULL },
	{ 0x040f, 0, "ICC Profile", hrsrc_iccprofile },
	{ 0x0410, 0, "Watermark", NULL },
	{ 0x0411, 0, "ICC Untagged Profile", NULL },
	{ 0x0412, 0, "Effects visible", NULL },
	{ 0x0413, 0, "Spot Halftone", NULL },
	{ 0x0414, 0, "Document-specific IDs seed number", NULL },
	{ 0x0415, 0, "Unicode Alpha Names", hrsrc_unicodestring },
	{ 0x0416, 0, "Indexed Color Table Count", NULL },
	{ 0x0417, 0, "Transparency Index", NULL },
	{ 0x0419, 0, "Global Altitude", NULL },
	{ 0x041a, 0, "Slices", hrsrc_slices },
	{ 0x041b, 0, "Workflow URL", hrsrc_unicodestring },
	{ 0x041c, 0, "Jump To XPEP", NULL },
	{ 0x041d, 0, "Alpha Identifiers", NULL },
	{ 0x041e, 0, "URL List", NULL },
	{ 0x0421, 0, "Version Info", hrsrc_versioninfo },
	{ 0x0422, 0, "EXIF data 1", hrsrc_exif },
	{ 0x0423, 0, "EXIF data 3", NULL },
	{ 0x0424, 0, "XMP metadata", hrsrc_xmp },
	{ 0x0425, 0, "Caption digest", NULL },
	{ 0x0426, 0, "Print scale", NULL },
	{ 0x0428, 0, "Pixel Aspect Ratio", NULL },
	{ 0x0429, 0x0004, "Layer Comps", NULL },
	{ 0x042a, 0, "Alternate Duotone Colors", NULL },
	{ 0x042b, 0, "Alternate Spot Colors", NULL },
	{ 0x042d, 0, "Layer Selection ID(s)", NULL },
	{ 0x042e, 0, "HDR Toning information", NULL },
	{ 0x042f, 0, "Auto Save Format", NULL },
	{ 0x0430, 0, "Layer Group(s) Enabled ID", NULL },
	{ 0x0431, 0, "Color samplers resource", NULL },
	{ 0x0432, 0x0004, "Measurement Scale", NULL },
	{ 0x0433, 0x0004, "Timeline Information", NULL },
	{ 0x0434, 0x0004, "Sheet Disclosure", NULL },
	{ 0x0435, 0, "DisplayInfo", NULL },
	{ 0x0436, 0x0004, "Onion Skins", NULL },
	{ 0x0438, 0x0004, "Count Information", NULL },
	{ 0x043a, 0x0004, "Print Information", NULL },
	{ 0x043b, 0x0004, "Print Style", NULL },
	{ 0x043c, 0, "Macintosh NSPrintInfo", NULL },
	{ 0x043d, 0, "Windows DEVMODE", NULL },
	{ 0x043e, 0, "Auto Save File Path", hrsrc_unicodestring },
	{ 0x043f, 0, "Auto Save Format", hrsrc_unicodestring },
	{ 0x0440, 0x0004, "Path Selection State", NULL },
	// 0x07d0 to 0x0bb6: See lookup_rsrc() below
	{ 0x0bb7, 0, "Name of clipping path", NULL },
	{ 0x0bb8, 0x0004, "Origin Path Info", NULL },
	// 0x0fa0 to 0x1387: See lookup_rsrc() below
	{ 0x1b58, 0, "Image Ready variables", NULL },
	{ 0x1b59, 0, "Image Ready data sets", NULL },
	{ 0x1b5a, 0, "Image Ready default selected state", NULL },
	{ 0x1b5b, 0, "Image Ready 7 rollover expanded state", NULL },
	{ 0x1b5c, 0, "Image Ready rollover expanded state", NULL },
	{ 0x1b5d, 0, "Image Ready save layer settings", NULL },
	{ 0x1b5e, 0, "Image Ready version", NULL },
	{ 0x1f40, 0, "Lightroom workflow", NULL },
	{ 0x2710, 0, "Print flags info", NULL }
};

static de_int64 pad_to_2(de_int64 n)
{
	return (n&0x1) ? n+1 : n;
}

static de_int64 pad_to_4(de_int64 n)
{
	return ((n+3)/4)*4;
}

// Caller supplies ri_dst. This function will set its fields.
static int lookup_rsrc(de_uint16 n, struct rsrc_info *ri_dst)
{
	de_int64 i;
	int found = 0;

	de_memset(ri_dst, 0, sizeof(struct rsrc_info));

	for(i=0; i<DE_ITEMS_IN_ARRAY(rsrc_info_arr); i++) {
		if(rsrc_info_arr[i].id == n) {
			*ri_dst = rsrc_info_arr[i]; // struct copy
			if(!ri_dst->idname) ri_dst->idname = "?";
			return 1;
		}
	}

	ri_dst->id = n;
	ri_dst->idname = "?";

	// Handle pattern-based resources that don't fit nicely in our table.

	if(n>=0x07d0 && n<=0x0bb6) {
		found = 1;
		ri_dst->idname = "Path Information";
	}
	else if(n>=0x0fa0 && n<=0x1387) {
		found = 1;
		ri_dst->idname = "Plug-In resource";
	}

	return found;
}

static const char* units_name(de_int64 u)
{
	switch(u) {
	case 1: return "pixels/inch";
	case 2: return "pixels/cm";
	}
	return "?";
}

static void hrsrc_resolutioninfo(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	de_int64 xres_int, yres_int;
	double xres, yres;
	de_int64 xres_unit, yres_unit;

	if(len!=16) return;
	xres_int = de_getui32be(pos);
	xres_unit = de_getui16be(pos+4);
	//width_unit = de_getui16be(pos+6);
	yres_int = de_getui32be(pos+8);
	yres_unit = de_getui16be(pos+12);
	//height_unit = de_getui16be(pos+14);
	xres = ((double)xres_int)/65536.0;
	yres = ((double)yres_int)/65536.0;
	de_dbg(c, "xres=%.2f, units=%d (%s)\n", xres, (int)xres_unit, units_name(xres_unit));
	de_dbg(c, "yres=%.2f, units=%d (%s)\n", yres, (int)yres_unit, units_name(yres_unit));
}

static void hrsrc_exif(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	//de_dbg(c, "Exif segment at %d datasize=%d\n", (int)pos, (int)len);
	de_fmtutil_handle_exif(c, pos, len);
}

static void hrsrc_iptc(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	de_fmtutil_handle_iptc(c, pos, len);
}

static void hrsrc_xmp(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	dbuf_create_file_from_slice(c->infile, pos, len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void hrsrc_iccprofile(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	dbuf_create_file_from_slice(c->infile, pos, len, "icc", NULL, DE_CREATEFLAG_IS_AUX);
}

// Read a Photoshop-style "Unicode string" structure, and append it to s.
static void read_unicode_string(dbuf *f, de_ucstring *s, de_int64 pos,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_int64 num_code_units;

	if(bytes_avail<0) {
		*bytes_consumed = 0;
		return;
	}
	if(bytes_avail<4) {
		*bytes_consumed = bytes_avail;
		return;
	}

	num_code_units = dbuf_getui32be(f, pos);
	if(4+num_code_units*2 > bytes_avail) { // error
		*bytes_consumed = bytes_avail;
		return;
	}

	dbuf_read_to_ucstring_n(f, pos+4, num_code_units*2, 300*2, s, 0, DE_ENCODING_UTF16BE);

	// Photoshop "Unicode strings" don't usually seem to end with a U+0000 character.
	// However, some of them seem to consist just of a single U+0000.
	// I suspect that's because there are places where they can't have a length of
	// zero, because the first four bytes being zero is used as sentinel value for
	// something else.
	ucstring_truncate_at_NUL(s);

	*bytes_consumed = 4+num_code_units*2;
}

static int read_descriptor_with_version(deark *c, lctx *d, de_int64 pos1,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_ucstring *name_from_classid = NULL;
	de_ucstring *classid = NULL;
	de_int64 pos;
	de_int64 endpos;
	de_int64 dv;
	de_int64 field_len;
	de_int64 class_id_len;

	*bytes_consumed = 0;
	pos = pos1;
	endpos = pos1+bytes_avail;

	dv = de_getui32be(pos);
	pos += 4;
	if(dv!=16) {
		de_warn(c, "Unsupported descriptor version: %d\n", (int)dv);
		goto done;
	}

	name_from_classid = ucstring_create(c);
	read_unicode_string(c->infile, name_from_classid, pos, endpos-pos, &field_len);
	if(name_from_classid->len > 0) {
		de_dbg(c, "name from classID: \"%s\"\n", ucstring_get_printable_sz_n(name_from_classid, 300));
	}
	pos += field_len;

	classid = ucstring_create(c);
	class_id_len = de_getui32be(pos);
	pos += 4;
	if(class_id_len==0) {
		// Note: dbuf_read_fourcc() might be more appropriate, but I'm using
		// dbuf_read_to_ucstring() for consistency.
		dbuf_read_to_ucstring(c->infile, pos, 4, classid, 0, DE_ENCODING_ASCII);
		pos += 4;
	}
	else {
		dbuf_read_to_ucstring_n(c->infile, pos, class_id_len, 300, classid, 0, DE_ENCODING_ASCII);
		pos += class_id_len;
	}
	de_dbg(c, "classID: \"%s\"\n", ucstring_get_printable_sz(classid));

done:
	ucstring_destroy(classid);
	ucstring_destroy(name_from_classid);
	return 0;
}

static void hrsrc_descriptor_with_version(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	de_int64 bytes_consumed;

	read_descriptor_with_version(c, d, pos, len, &bytes_consumed);
}

static void do_slices_v6(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 bytes_consumed_name;
	de_ucstring *name_of_group_of_slices = NULL;

	name_of_group_of_slices = ucstring_create(c);

	read_unicode_string(c->infile, name_of_group_of_slices, pos1+20, len-20, &bytes_consumed_name);
	de_dbg(c, "name of group of slices: \"%s\"\n",
		ucstring_get_printable_sz_n(name_of_group_of_slices, 300));

	ucstring_destroy(name_of_group_of_slices);
}

static void do_slices_v7_8(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 bytes_consumed_dv;

	pos = pos1;
	endpos = pos1+len;
	pos += 4; // Skip version number (7 or 8), already read.

	if(!read_descriptor_with_version(c, d, pos, endpos-pos, &bytes_consumed_dv)) {
		goto done;
	}

done:
	;
}

static void hrsrc_slices(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	de_int64 sver;

	if(len<4) return;
	sver = de_getui32be(pos);
	de_dbg(c, "slices resource format version: %d\n", (int)sver);

	if(sver==6) {
		do_slices_v6(c, d, pos, len);
	}
	else if(sver==7 || sver==8) {
		do_slices_v7_8(c, d, pos, len);
	}
}

static void hrsrc_thumbnail(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 fmt;

	if(len<=28) return;
	pos = pos1;

	fmt = de_getui32be(pos);
	if(fmt != 1) {
		// fmt != kJpegRGB
		de_dbg(c, "thumbnail in unsupported format (%d) found\n", (int)fmt);
		return;
	}

	if(ri->id==0x0409) {
		de_msg(c, "Note: This Photoshop thumbnail uses nonstandard colors, and may not look right.\n");
	}
	dbuf_create_file_from_slice(c->infile, pos+28, len-28, "psdthumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
}

// Handler for any resource that consists of a single "Unicode string".
static void hrsrc_unicodestring(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;
	de_int64 bytes_consumed;

	s = ucstring_create(c);
	read_unicode_string(c->infile, s, pos, len, &bytes_consumed);
	de_dbg(c, "%s: \"%s\"\n", ri->idname, ucstring_get_printable_sz(s));
	ucstring_destroy(s);
}

static void hrsrc_versioninfo(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos1, de_int64 len)
{
	de_int64 ver, file_ver;
	de_byte b;
	de_ucstring *s = NULL;
	de_int64 bytes_consumed;
	de_int64 pos, endpos;

	endpos = pos1 + len;
	pos = pos1;

	ver = de_getui32be(pos);
	de_dbg(c, "version: %d\n", (int)ver);
	pos += 4;

	b = de_getbyte(pos++);
	de_dbg(c, "hasRealMergedData: %d\n", (int)b);

	s = ucstring_create(c);
	read_unicode_string(c->infile, s, pos, endpos-pos, &bytes_consumed);
	de_dbg(c, "writer name: \"%s\"\n", ucstring_get_printable_sz(s));
	pos += bytes_consumed;

	ucstring_truncate(s, 0);
	read_unicode_string(c->infile, s, pos, endpos-pos, &bytes_consumed);
	de_dbg(c, "reader name: \"%s\"\n", ucstring_get_printable_sz(s));
	pos += bytes_consumed;

	file_ver = de_getui32be(pos);
	de_dbg(c, "file version: %d\n", (int)file_ver);

	ucstring_destroy(s);
}

static void read_pascal_string_to_ucstring(dbuf *f, de_int64 pos, de_int64 bytes_avail,
	de_ucstring *s, de_int64 *bytes_consumed)
{
	de_int64 dlen;

	dlen = (de_int64)dbuf_getbyte(f, pos);
	if(dlen > bytes_avail-1) { // error
		*bytes_consumed = bytes_avail;
		return;
	}

	dbuf_read_to_ucstring(f, pos+1, dlen, s, 0, DE_ENCODING_ASCII);
	*bytes_consumed = 1 + dlen;
}

static int do_image_resource(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_byte buf[4];
	de_int64 resource_id;
	de_int64 blkname_len;
	de_int64 bytes_used_by_name_field;
	de_int64 block_data_len;
	de_int64 pos;
	struct rsrc_info ri;
	de_ucstring *blkname = NULL;
	const char *blkname_printable;
	int retval = 0;

	pos = pos1;
	*bytes_consumed = 0;

	// Check the "8BIM" signature
	de_read(buf, pos, 4);
	if(buf[0]!='8' || buf[1]!='B' || buf[2]!='I' || buf[3]!='M') {
		de_warn(c, "Bad Photoshop resource block signature at %d\n", (int)pos);
		goto done;
	}
	pos+=4;

	resource_id = de_getui16be(pos);
	pos+=2;

	// Read resource block name. It starts with a byte that gives its length.
	blkname_len = (de_int64)de_getbyte(pos);
	if(blkname_len==0) {
		// A fast path. Resource blocks rarely have names.
		blkname_printable = "";
		bytes_used_by_name_field = 1;
	}
	else {
		blkname = ucstring_create(c);
		read_pascal_string_to_ucstring(c->infile, pos, 256, blkname, &bytes_used_by_name_field);
		blkname_printable = ucstring_get_printable_sz(blkname);
	}
	bytes_used_by_name_field = pad_to_2(bytes_used_by_name_field);
	pos+=bytes_used_by_name_field;

	block_data_len = de_getui32be(pos);
	pos+=4;

	lookup_rsrc((de_uint16)resource_id, &ri);

	de_dbg(c, "Photoshop rsrc 0x%04x (%s) pos=%d blkname=\"%s\" dpos=%d dlen=%d\n",
		(int)resource_id, ri.idname, (int)pos1, blkname_printable,
		(int)pos, (int)block_data_len);

	de_dbg_indent(c, 1);
	if(ri.hfn) {
		ri.hfn(c, d, &ri, pos, block_data_len);
	}
	else if(ri.flags&0x0004) {
		hrsrc_descriptor_with_version(c, d, &ri, pos, block_data_len);
	}
	de_dbg_indent(c, -1);

	pos+=block_data_len;
	if(block_data_len&1) pos++; // padding byte

	*bytes_consumed = pos - pos1;

	retval = 1;

done:
	if(blkname) ucstring_destroy(blkname);
	return retval;
}

static void do_image_resource_blocks(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 bytes_consumed;

	pos = pos1;
	while(1) {
		if(pos>=pos1+len) break;
		if(!do_image_resource(c, d, pos, &bytes_consumed)) break;
		pos += bytes_consumed;
	}
}

// Layer mask / adjustment layer data
static void do_layer_mask_data(deark *c, lctx *d, de_int64 pos,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_int64 dlen;
	dlen = de_getui32be(pos);
	de_dbg(c, "layer mask data size: %d\n", (int)dlen);
	*bytes_consumed = 4 + dlen;
}

static void do_layer_blending_ranges(deark *c, lctx *d, de_int64 pos,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_int64 dlen;
	dlen = de_getui32be(pos);
	de_dbg(c, "layer blending ranges data size: %d\n", (int)dlen);
	*bytes_consumed = 4 + dlen;
}

static void do_layer_name(deark *c, lctx *d, de_int64 pos,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_ucstring *s = NULL;

	// "Pascal string, padded to a multiple of 4 bytes"
	s = ucstring_create(c);
	read_pascal_string_to_ucstring(c->infile, pos, bytes_avail, s, bytes_consumed);
	de_dbg(c, "layer name: \"%s\"\n", ucstring_get_printable_sz(s));
	*bytes_consumed = pad_to_4(*bytes_consumed);
	ucstring_destroy(s);
}

static int do_layer_record(deark *c, lctx *d, de_int64 pos1,
	de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 nchannels;
	de_int64 extra_data_len;
	de_int64 extra_data_endpos;
	struct de_fourcc tmp4cc;
	de_int64 bytes_consumed2;

	int retval = 0;

	endpos = pos1+bytes_avail;
	pos = pos1;

	pos += 16; // rectangle

	nchannels = de_getui16be(pos);
	de_dbg(c, "number of channels: %d\n", (int)nchannels);
	pos += 2;

	pos += 6*nchannels;

	dbuf_read_fourcc(c->infile, pos, &tmp4cc, 0);
	if(tmp4cc.id != CODE_8BIM) {
		de_warn(c, "Expected blend mode signature not found at %d\n", (int)pos);
		goto done;
	}
	pos += 4;

	dbuf_read_fourcc(c->infile, pos, &tmp4cc, 0);
	de_dbg(c, "blend mode: '%s'\n", tmp4cc.id_printable);
	pos += 4; // blend mode key

	pos += 1; // opacity
	pos += 1; // clipping
	pos += 1; // flags
	pos += 1; // filler

	extra_data_len = de_getui32be(pos);
	pos+=4;
	extra_data_endpos = pos + extra_data_len;

	do_layer_mask_data(c, d, pos, extra_data_endpos-pos, &bytes_consumed2);
	pos += bytes_consumed2;

	do_layer_blending_ranges(c, d, pos, extra_data_endpos-pos, &bytes_consumed2);
	pos += bytes_consumed2;

	do_layer_name(c, d, pos, extra_data_endpos-pos, &bytes_consumed2);
	pos += bytes_consumed2;

	if(pos < extra_data_endpos) {
		// TODO: The rest of the layer record data seems to be undocumented,
		// or unclearly documented.
		de_dbg(c, "[%d more bytes of layer record data at %d]\n",
			(int)(extra_data_endpos-pos), (int)pos);
	}

	pos = extra_data_endpos;

	if(pos>endpos) {
		de_warn(c, "Malformed layer record at %d\n", (int)pos1);
		*bytes_consumed = 0;
		goto done;
	}
	*bytes_consumed = pos - pos1;

	retval = 1;
done:
	return retval;
}

static int do_layer_info_section(deark *c, lctx *d, de_int64 pos1,
	de_int64 bytes_avail, int has_len_field, de_int64 *bytes_consumed)
{
	int retval = 0;
	de_int64 pos;
	de_int64 endpos;
	de_int64 layer_info_len;
	de_int64 layer_count_raw, layer_count;
	de_int64 bytes_consumed_layer;
	int indent_count = 0;
	int merged_result_flag;
	de_int64 layer_idx;

	*bytes_consumed = 0;
	endpos = pos1+bytes_avail;
	pos = pos1;
	if(bytes_avail<4) goto done;

	de_dbg(c, "layer info section at %d\n", (int)pos1);
	de_dbg_indent(c, 1);
	indent_count++;

	if(has_len_field) {
		layer_info_len = de_getui32be(pos);
		de_dbg(c, "length of layer info section: %d\n", (int)layer_info_len);
		pos += 4;
	}
	else {
		layer_info_len = bytes_avail;
	}

	layer_count_raw = dbuf_geti16be(c->infile, pos);
	pos += 2;
	if(layer_count_raw<0) {
		merged_result_flag = 1;
		layer_count = -layer_count_raw;
	}
	else {
		merged_result_flag = 0;
		layer_count = layer_count_raw;
	}
	de_dbg(c, "layer count: %d\n", (int)layer_count);
	de_dbg(c, "merged result flag: %d\n", (int)merged_result_flag);

	for(layer_idx=0; layer_idx<layer_count; layer_idx++) {
		de_dbg(c, "layer record[%d] at %d\n", (int)layer_idx, (int)pos);
		de_dbg_indent(c, 1);
		if(!do_layer_record(c, d, pos, endpos-pos, &bytes_consumed_layer)) goto done;
		pos += bytes_consumed_layer;
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "channel image data record(s) at %d\n", (int)pos);

	*bytes_consumed = 4 + layer_info_len;
	retval = 1;
done:
	de_dbg_indent(c, -indent_count);
	return retval;
}

static void do_Layr_block(deark *c, lctx *d, de_int64 pos, de_int64 len, const struct de_fourcc *blk4cc)
{
	de_int64 bytes_consumed;
	// "Layer info" section, but starting with the "Layer count" field
	do_layer_info_section(c, d, pos, len, 0, &bytes_consumed);
}

static int do_tagged_block(deark *c, lctx *d, de_int64 pos, de_int64 bytes_avail,
	de_int64 *bytes_consumed)
{
	de_int64 blklen;
	de_int64 padded_blklen;
	struct de_fourcc blk4cc;
	de_int64 sig;

	*bytes_consumed = 0;
	if(bytes_avail<12) return 0;

	sig = de_getui32be(pos);
	if(sig==CODE_8B64) {
		de_warn(c, "8B64 tagged block type not supported\n");
		return 0;
	}
	if(sig!=CODE_8BIM) {
		de_warn(c, "Expected tagged block signature not found at %d\n", (int)pos);
		return 0;
	}

	dbuf_read_fourcc(c->infile, pos+4, &blk4cc, 0);
	blklen = de_getui32be(pos+8);
	de_dbg(c, "tagged block '%s' at %d, dpos=%d, dlen=%d\n", blk4cc.id_printable,
		(int)pos, (int)(12+pos), (int)blklen);

	switch(blk4cc.id) {
	case CODE_Layr:
		do_Layr_block(c, d, pos+12, blklen, &blk4cc);
		break;
	}

	// Apparently, the data is padded to the next multiple of 4 bytes.
	// (This is not what the PSD spec says.)
	padded_blklen = pad_to_4(blklen);

	*bytes_consumed = 12 + padded_blklen;
	return 1;
}

// A "Series of tagged blocks" - part of the "Layer and Mask Information" section.
// Or, the payload data from a TIFF "ImageSourceData" tag.
static void do_tagged_blocks(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 bytes_consumed;
	de_int64 pos = pos1;

	while(1) {
		if(pos+12 > pos1+len) break;
		if(!do_tagged_block(c, d, pos, pos1+len-pos, &bytes_consumed)) break;
		pos += bytes_consumed;
	}
}

static int do_layer_and_mask_info_section(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos;
	de_int64 layer_and_mask_info_section_len; // The "Length" field. Whole section is 4 bytes longer.
	de_int64 layer_and_mask_info_section_endpos;
	de_int64 gl_layer_mask_info_len;
	de_int64 bytes_consumed2;
	int retval = 0;

	// The "layer and mask section" contains up to 3 sub-sections:
	// * layer info
	// * global layer mask info
	// * tagged blocks

	pos = pos1;
	*bytes_consumed = 0;

	de_dbg(c, "layer & mask info section at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	layer_and_mask_info_section_len = de_getui32be(pos);
	de_dbg(c, "layer & mask info section total data size: %d\n", (int)layer_and_mask_info_section_len);
	pos += 4;
	if(pos + layer_and_mask_info_section_len > c->infile->len) {
		de_err(c, "Unexpected end of PSD file\n");
		goto done;
	}
	layer_and_mask_info_section_endpos = pos + layer_and_mask_info_section_len;

	// Now that we know the size of this element, we can treat this function as "successful".
	*bytes_consumed = 4 + layer_and_mask_info_section_len;
	retval = 1;

	if(!do_layer_info_section(c, d, pos, layer_and_mask_info_section_endpos-pos, 1,
		&bytes_consumed2))
	{
		goto done;
	}
	if(pos + bytes_consumed2 > layer_and_mask_info_section_endpos) {
		de_warn(c, "Oversized Layer Info section\n");
		goto done;
	}
	pos += bytes_consumed2;
	if(pos>=layer_and_mask_info_section_endpos) {
		goto done;
	}

	de_dbg(c, "global layer mask info at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	gl_layer_mask_info_len = de_getui32be(pos);
	pos += 4;
	de_dbg(c, "length of global layer mask info section: %d\n", (int)gl_layer_mask_info_len);
	de_dbg_indent(c, -1);
	if(pos+gl_layer_mask_info_len > layer_and_mask_info_section_endpos) {
		de_warn(c, "Oversized Global Layer Mask Info section\n");
		goto done;
	}
	pos += gl_layer_mask_info_len;
	if(pos>=layer_and_mask_info_section_endpos) {
		goto done;
	}

	de_dbg(c, "tagged blocks at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "expected length of tagged blocks section: %d\n", (int)(layer_and_mask_info_section_endpos-pos));
	do_tagged_blocks(c, d, pos, layer_and_mask_info_section_endpos-pos);
	de_dbg_indent(c, -1);

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 psdver;
	de_int64 w, h;

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	psdver = de_getui16be(pos+4);
	de_dbg(c, "PSD version: %d\n", (int)psdver);
	if(psdver!=1) {
		de_err(c, "Unsupported PSD version: %d\n", (int)psdver);
		goto done;
	}

	h = de_getui32be(pos+14);
	w = de_getui32be(pos+18);
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);

done:
	de_dbg_indent(c, -1);
}

static void do_external_tagged_blocks(deark *c, lctx *d)
{
	de_uint32 code;

	if(c->infile->len<4) return;

	// Evidently, it is possible for this to use little-endian byte order. Weird.

	// Peek at the first 4 bytes
	code = (de_uint32)de_getui32le(0);
	if(code==CODE_8BIM || code==CODE_8B64) {
		de_warn(c, "ImageSourceData with little-endian byte order is not supported\n");
		return;
	}

	do_tagged_blocks(c, d, 0, c->infile->len);
}

static void de_run_psd(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 x;
	de_int64 pos;
	de_int64 bytes_consumed;
	de_int64 imgdata_len;

	if(c->module_nesting_level>1) de_dbg2(c, "in psd module\n");
	d = de_malloc(c, sizeof(lctx));

	if(mparams && mparams->codes) {
		if(de_strchr(mparams->codes, 'R')) { // Image resources
			do_image_resource_blocks(c, d, 0, c->infile->len);
			goto done;
		}
		if(de_strchr(mparams->codes, 'T')) { // Tagged blocks
			do_external_tagged_blocks(c, d);
			goto done;
		}
	}

	pos = 0;
	do_header(c, d, pos);
	pos += 26;

	de_dbg(c, "color mode data section at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	x = de_getui32be(pos);
	pos += 4;
	de_dbg(c, "color data at %d, len=%d\n", (int)pos, (int)x);
	pos += x;
	de_dbg_indent(c, -1);

	de_dbg(c, "image resources section at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	x = de_getui32be(pos); // Length of Image Resources
	pos += 4;
	// The PSD spec is ambiguous, but in practice the "length" field's value
	// does not include the size of the "length" field itself.
	de_dbg(c, "image resources data at %d, len=%d\n", (int)pos, (int)x);

	if(x>0) {
		de_dbg_indent(c, 1);
		do_image_resource_blocks(c, d, pos, x);
		de_dbg_indent(c, -1);
	}
	pos += x;
	de_dbg_indent(c, -1);

	if(!do_layer_and_mask_info_section(c, d, pos, &bytes_consumed)) goto done;
	pos += bytes_consumed;

	imgdata_len = c->infile->len - pos;
	if(imgdata_len>0) {
		de_dbg(c, "image data at %d, expected size=%d\n", (int)pos, (int)imgdata_len);
	}

done:
	de_free(c, d);
}

static int de_identify_psd(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "8BPS\x00\x01", 6)) return 100;
	return 0;
}

void de_module_psd(deark *c, struct deark_module_info *mi)
{
	mi->id = "psd";
	mi->desc = "Photoshop .PSD (resources only)";
	mi->run_fn = de_run_psd;
	mi->identify_fn = de_identify_psd;
}
