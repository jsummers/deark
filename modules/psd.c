// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This module supports the "image resources" section of PSD files.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_psd);

typedef struct localctx_struct {
	int reserved;
} lctx;

struct rsrc_info;

typedef void (*rsrc_handler_fn)(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);

struct rsrc_info {
	de_uint16 id;
	de_uint32 flags;
	const char *idname;
	rsrc_handler_fn hfn;
};

static void hrsrc_resolutioninfo(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);
static void hrsrc_iptc(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);
static void hrsrc_exif(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);
static void hrsrc_thumbnail(deark *c, lctx *d, const struct rsrc_info *ri,
	de_int64 pos, de_int64 len);

static const struct rsrc_info rsrc_info_arr[] = {
	{ 0x03e9, 0, "Macintosh print manager print info", NULL },
	{ 0x03ed, 0, "Resolution info", hrsrc_resolutioninfo },
	{ 0x03ee, 0, "Names of the alpha channels", NULL },
	{ 0x03f2, 0, "Background color", NULL },
	{ 0x03f3, 0, "Print flags", NULL },
	{ 0x03f5, 0, "Color halftoning info", NULL },
	{ 0x03f8, 0, "Color transfer functions", NULL },
	{ 0x03fd, 0, "EPS options", NULL },
	{ 0x0400, 0, "Layer state information", NULL },
	{ 0x0402, 0, "Layers group information", NULL },
	{ 0x0404, 0, "IPTC-NAA", hrsrc_iptc },
	{ 0x0406, 0, "JPEG quality", NULL },
	{ 0x0408, 0, "Grid and guides info", NULL },
	{ 0x0409, 0, "Thumbnail - Photoshop 4.0", hrsrc_thumbnail },
	{ 0x040a, 0, "Copyright flag", NULL },
	{ 0x040c, 0, "Thumbnail", hrsrc_thumbnail },
	{ 0x040d, 0, "Global Angle", NULL },
	{ 0x0411, 0, "ICC Untagged Profile", NULL },
	{ 0x0414, 0, "Document-specific IDs seed number", NULL },
	{ 0x0415, 0, "Unicode Alpha Names", NULL },
	{ 0x0419, 0, "Global Altitude", NULL },
	{ 0x041a, 0, "Slices", NULL },
	{ 0x041d, 0, "Alpha Identifiers", NULL },
	{ 0x041e, 0, "URL List", NULL },
	{ 0x0421, 0, "Version Info", NULL },
	{ 0x0422, 0, "EXIF data 1", hrsrc_exif },
	{ 0x0423, 0, "EXIF data 3", NULL },
	{ 0x0425, 0, "Caption digest", NULL },
	{ 0x0426, 0, "Print scale", NULL },
	{ 0x0428, 0, "Pixel Aspect Ratio", NULL },
	{ 0x042d, 0, "Layer Selection ID(s)", NULL },
	{ 0x042f, 0, "Auto Save Format", NULL },
	{ 0x0430, 0, "Layer Group(s) Enabled ID", NULL },
	{ 0x0433, 0, "Timeline Information", NULL },
	{ 0x0434, 0, "Sheet Disclosure", NULL },
	{ 0x0435, 0, "DisplayInfo", NULL },
	{ 0x0436, 0, "Onion Skins", NULL },
	{ 0x043a, 0, "Print Information", NULL },
	{ 0x043b, 0, "Print Style", NULL },
	{ 0x0bb7, 0, "Name of clipping path", NULL },
	{ 0x2710, 0, "Print flags info", NULL }
};

//static const char* rsrc_name(de_int64 n)
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
		ri_dst->idname = "Plug-In resources";
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
	if(c->extract_level>=2 && len>0) {
		dbuf_create_file_from_slice(c->infile, pos, len, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
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

static int do_image_resource(deark *c, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_byte buf[4];
	de_int64 resource_id;
	de_int64 name_len;
	de_int64 bytes_used_by_name_field;
	de_int64 block_data_len;
	de_int64 pos;
	struct rsrc_info ri;

	pos = pos1;
	*bytes_consumed = 0;

	// Check the "8BIM" signature
	de_read(buf, pos, 4);
	if(buf[0]!='8' || buf[1]!='B' || buf[2]!='I' || buf[3]!='M') {
		de_warn(c, "Bad Photoshop resource block signature at %d\n", (int)pos);
		return 0;
	}
	pos+=4;

	resource_id = de_getui16be(pos);
	pos+=2;

	// Read resource name. We don't care about this, but we have to read it
	// because it has a variable size, and determines where the next field
	// will be.
	name_len = (de_int64)de_getbyte(pos);
	bytes_used_by_name_field = 1 + name_len;
	if(bytes_used_by_name_field&1) bytes_used_by_name_field++; // padding byte

	pos+=bytes_used_by_name_field;

	block_data_len = de_getui32be(pos);
	pos+=4;

	lookup_rsrc((de_uint16)resource_id, &ri);

	de_dbg(c, "Photoshop rsrc 0x%04x (%s) pos=%d nlen=%d dpos=%d dlen=%d\n",
		(int)resource_id, ri.idname, (int)pos1, (int)name_len, (int)pos, (int)block_data_len);

	if(ri.hfn) {
		de_dbg_indent(c, 1);
		ri.hfn(c, NULL, &ri, pos, block_data_len);
		de_dbg_indent(c, -1);
	}

	pos+=block_data_len;
	if(block_data_len&1) pos++; // padding byte

	*bytes_consumed = pos - pos1;
	return 1;
}

static void do_image_resource_blocks(deark *c, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 bytes_consumed;

	pos = pos1;
	while(1) {
		if(pos>=pos1+len) break;
		if(!do_image_resource(c, pos, &bytes_consumed)) break;
		pos += bytes_consumed;
	}
}

static void de_run_psd(deark *c, de_module_params *mparams)
{
	de_int64 x;
	de_int64 pos;

	if(c->module_nesting_level>1) de_dbg2(c, "in psd module\n");

	if(mparams && mparams->codes && de_strchr(mparams->codes, 'R')) {
		do_image_resource_blocks(c, 0, c->infile->len);
		return;
	}

	// Header is 26 bytes. We don't care about it.
	// Color Mode data starts at offset 26.
	pos = 26;
	x = de_getui32be(pos); // Length of Color Mode data
	de_dbg(c, "Color Mode size: %d\n", (int)x);
	pos += 4 + x;

	x = de_getui32be(pos); // Length of Image Resources
	de_dbg(c, "Image Resources size: %d\n", (int)x);
	pos += 4;

	if(x>0) {
		do_image_resource_blocks(c, pos, x);
	}
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
