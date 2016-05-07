// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// This module supports the "image resources" section of PSD files.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_psd);

struct rsrc_info {
	de_uint16 id;
	const char *name;
};

static const struct rsrc_info rsrc_info_arr[] = {
	{ 0x03e9, "Macintosh print manager print info" },
	{ 0x03ed, "Resolution info" },
	{ 0x03ee, "Names of the alpha channels" },
	{ 0x03f2, "Background color" },
	{ 0x03f3, "Print flags" },
	{ 0x03f5, "Color halftoning info" },
	{ 0x03f8, "Color transfer functions" },
	{ 0x03fd, "EPS options" },
	{ 0x0400, "Layer state information" },
	{ 0x0402, "Layers group information" },
	{ 0x0404, "IPTC-NAA" },
	{ 0x0406, "JPEG quality" },
	{ 0x0408, "Grid and guides info" },
	{ 0x0409, "Thumbnail - Photoshop 4.0" },
	{ 0x040a, "Copyright flag" },
	{ 0x040c, "Thumbnail" },
	{ 0x040d, "Global Angle" },
	{ 0x0411, "ICC Untagged Profile" },
	{ 0x0414, "Document-specific IDs seed number" },
	{ 0x0415, "Unicode Alpha Names" },
	{ 0x0419, "Global Altitude" },
	{ 0x041a, "Slices" },
	{ 0x041d, "Alpha Identifiers" },
	{ 0x041e, "URL List" },
	{ 0x0421, "Version Info" },
	{ 0x0422, "EXIF data 1" },
	{ 0x0423, "EXIF data 3" },
	{ 0x0425, "Caption digest" },
	{ 0x0426, "Print scale" },
	{ 0x0428, "Pixel Aspect Ratio" },
	{ 0x042d, "Layer Selection ID(s)" },
	{ 0x042f, "Auto Save Format" },
	{ 0x0430, "Layer Group(s) Enabled ID" },
	{ 0x0433, "Timeline Information" },
	{ 0x0434, "Sheet Disclosure" },
	{ 0x0435, "DisplayInfo" },
	{ 0x0436, "Onion Skins" },
	{ 0x043a, "Print Information" },
	{ 0x043b, "Print Style" },
	{ 0x0bb7, "Name of clipping path" },
	{ 0x2710, "Print flags info" },
	{ 0, NULL }
};

static const char* rsrc_name(de_int64 n)
{
	const struct rsrc_info *ri = NULL;
	de_int64 i;

	for(i=0; rsrc_info_arr[i].id!=0; i++) {
		if(rsrc_info_arr[i].id == (de_uint16)n) {
			ri = &rsrc_info_arr[i];
			break;
		}
	}
	if(ri && ri->name)
		return ri->name;

	if(n>=0x07d0 && n<=0x0bb6) {
		return "Path Information";
	}
	if(n>=0x0fa0 && n<=0x1387) {
		return "Plug-In resources";
	}

	return "?";
}

static const char* units_name(de_int64 u)
{
	switch(u) {
	case 1: return "pixels/inch";
	case 2: return "pixels/cm";
	}
	return "?";
}

static void do_resolutioninfo_resource(deark *c, de_int64 pos, de_int64 len)
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

static void do_thumbnail_resource(deark *c, de_int64 resource_id,
	de_int64 startpos, de_int64 len)
{
	de_int64 pos;
	de_int64 fmt;

	if(len<=28) return;
	pos = startpos;

	fmt = de_getui32be(pos);
	if(fmt != 1) {
		// fmt != kJpegRGB
		de_dbg(c, "thumbnail in unsupported format (%d) found\n", (int)fmt);
		return;
	}

	if(resource_id==0x0409) {
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
	const char *idname;

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

	idname = rsrc_name(resource_id);

	de_dbg(c, "Photoshop rsrc 0x%04x (%s) pos=%d nlen=%d dpos=%d dlen=%d\n",
		(int)resource_id, idname, (int)pos1, (int)name_len, (int)pos, (int)block_data_len);

	switch(resource_id) {
	case 0x03ed: // ResolutionInfo
		de_dbg_indent(c, 1);
		do_resolutioninfo_resource(c, pos, block_data_len);
		de_dbg_indent(c, -1);
		break;
	case 0x0404: // IPTC
		if(c->extract_level>=2 && block_data_len>0) {
			dbuf_create_file_from_slice(c->infile, pos, block_data_len, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
		}
		break;
	case 0x0409: // PhotoshopThumbnail 4.0
	case 0x040c: // PhotoshopThumbnail
		do_thumbnail_resource(c, resource_id, pos, block_data_len);
		break;
	case 0x0422: // EXIFInfo
		de_dbg_indent(c, 1);
		de_dbg(c, "Exif segment at %d datasize=%d\n", (int)pos, (int)block_data_len);
		de_fmtutil_handle_exif(c, pos, block_data_len);
		de_dbg_indent(c, -1);
		break;
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
