// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// This module supports the "image resources" section of PSD files.

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

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
	dbuf_create_file_from_slice(c->infile, pos+28, len-28, "psdthumb.jpg", NULL);
}

static void do_image_resource_blocks(deark *c, de_int64 startpos, de_int64 len)
{
	de_byte buf[4];
	de_int64 pos;
	de_int64 resource_id;
	de_int64 resource_pos;
	de_int64 name_len;
	de_int64 bytes_used_by_name_field;
	de_int64 block_data_len;

	pos = startpos;

	while(1) {
		if(pos>=startpos+len) break;

		// Check the "8BIM" signature
		resource_pos = pos;
		de_read(buf, pos, 4);
		if(buf[0]!='8' || buf[1]!='B' || buf[2]!='I' || buf[3]!='M') {
			de_warn(c, "Bad Photoshop resource block signature at %d\n", (int)pos);
			break;
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
		// de_dbg(c, "name bytes: %d\n", (int)bytes_used_by_name_field);

		pos+=bytes_used_by_name_field;

		block_data_len = de_getui32be(pos);
		pos+=4;

		de_dbg(c, "Photoshop resource ID 0x%04x pos=%d data_len=%d\n", (int)resource_id,
			(int)resource_pos, (int)block_data_len);

		switch(resource_id) {
		case 0x0404: // IPTC
			if(c->extract_level>=2 && block_data_len>0) {
				dbuf_create_file_from_slice(c->infile, pos, block_data_len, "iptc", NULL);
			}
			break;
		case 0x0409: // PhotoshopThumbnail 4.0
		case 0x040c: // PhotoshopThumbnail
			do_thumbnail_resource(c, resource_id, pos, block_data_len);
			break;
		case 0x0422: // EXIFInfo
			de_dbg(c, "Exif segment at %d datasize=%d\n", (int)pos, (int)block_data_len);
			de_fmtutil_handle_exif(c, pos, block_data_len);
			break;
		}

		pos+=block_data_len;
		if(block_data_len&1) pos++; // padding byte
	}
}

static void de_run_psd(deark *c, const char *params)
{
	de_int64 x;
	de_int64 pos;

	de_dbg(c, "In psd module\n");

	if(params && de_strchr(params,'R')) {
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
	de_byte buf[6];
	de_read(buf, 0, 6);

	if(!de_memcmp(buf, "8BPS\x00\x01", 6)) return 100;
	return 0;
}

void de_module_psd(deark *c, struct deark_module_info *mi)
{
	mi->id = "psd";
	mi->run_fn = de_run_psd;
	mi->identify_fn = de_identify_psd;
}
