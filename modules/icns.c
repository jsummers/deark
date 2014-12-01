// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// icns - Apple Icon Image format

#include <deark-config.h>
#include <deark-modules.h>

#define IMGTYPE_EMBEDDED_FILE   1
#define IMGTYPE_MASK            2
#define IMGTYPE_IMAGE           3
#define IMGTYPE_IMAGE_AND_MASK  4

struct image_type_info {
	de_uint32 code;
	int width; // height is same as width
	int bpp; // bits per pixel. 0 = unspecified
	int image_type; // IMGTYPE_*
};
static const struct image_type_info image_type_info_arr[] = {
	{ 0x49434e23, 32,   1,  IMGTYPE_IMAGE_AND_MASK }, // ICN#
	{ 0x69637034, 16,   0,  IMGTYPE_EMBEDDED_FILE }, // icp4
	{ 0x69637035, 32,   0,  IMGTYPE_EMBEDDED_FILE }, // icp5
	{ 0x69637036, 64,   0,  IMGTYPE_EMBEDDED_FILE }, // icp6
	{ 0x69633037, 128,  0,  IMGTYPE_EMBEDDED_FILE }, // ic07
	{ 0x69633038, 256,  0,  IMGTYPE_EMBEDDED_FILE }, // ic08
	{ 0x69633039, 512,  0,  IMGTYPE_EMBEDDED_FILE }, // ic09
	{ 0x69633130, 1024, 0,  IMGTYPE_EMBEDDED_FILE }, // ic10
	{ 0x69633131, 32,   0,  IMGTYPE_EMBEDDED_FILE }, // ic11
	{ 0x69633132, 64,   0,  IMGTYPE_EMBEDDED_FILE }, // ic12
	{ 0x69633133, 256,  0,  IMGTYPE_EMBEDDED_FILE }, // ic13
	{ 0x69633134, 512,  0,  IMGTYPE_EMBEDDED_FILE }, // ic14
	{ 0, 0, 0, 0 }
};


typedef struct localctx_struct {
	de_int64 file_size;

	// Information about the segment currently being processed
	int image_num;
	de_int64 segment_pos;
	de_int64 segment_len;
	de_int64 image_pos;
	de_int64 image_len;
	const struct image_type_info *type_info;
	de_uint32 code;
	char code_printable[8];

	// Mask file offsets (0 = not present)
	de_int64 mkpos_s8mk;
	de_int64 mkpos_l8mk;
	de_int64 mkpos_h8mk;
} lctx;

static void do_decode_image(deark *c, lctx *d)
{
	if(d->code==0x49434e23) { // ICN#
		de_convert_and_write_image_bilevel(c->infile, d->image_pos, 32, 64, (32+7)/8,
			DE_CVTF_WHITEISZERO, NULL);
	}
}

static void do_extract_png_or_jp2(deark *c, lctx *d)
{
	de_byte buf[8];

	de_dbg(c, "Trying to extract file at %d\n", (int)d->image_pos);
	// Detect the format
	de_read(buf, d->image_pos, sizeof(buf));

	// TODO: Include the expected dimensions (etc.) in the filename.
	if(buf[4]=='j' && buf[5]=='P') {
		dbuf_create_file_from_slice(c->infile, d->image_pos, d->image_len, "jp2", NULL);
	}
	else if(buf[0]==0x89 && buf[1]==0x50) {
		dbuf_create_file_from_slice(c->infile, d->image_pos, d->image_len, "png", NULL);
	}
	else {
		de_err(c, "(Image #%d) Unidentified file format\n", d->image_num);
	}
}

static void do_icon(deark *c, lctx *d)
{
	if(!d->type_info) return; // Shouldn't happen.

	if(d->type_info->image_type==IMGTYPE_EMBEDDED_FILE) {
		do_extract_png_or_jp2(c, d);
		return;
	}

	switch(d->code) {
	case 0x49434e23: // ICN#
		do_decode_image(c, d);
		break;
	default:
		de_warn(c, "(Image #%d) Image type '%s' not supported\n", d->image_num, d->code_printable);
	}
}

static void de_run_icns_pass(deark *c, lctx *d, int pass)
{
	de_byte code_bytes[8];
	de_int64 i;

	d->segment_pos = 8;
	d->image_num = 0;
	while(1) {
		if(d->segment_pos+8 > d->file_size) break;

		de_read(code_bytes, d->segment_pos, 4);
		d->code = (de_uint32)de_getui32be_direct(code_bytes);
		de_make_printable_ascii(code_bytes, 4, d->code_printable, sizeof(d->code_printable), 0);

		d->segment_len = de_getui32be(d->segment_pos+4);

		d->image_pos = d->segment_pos + 8;
		d->image_len = d->segment_len - 8;

		if(pass==2) {
			de_dbg(c, "image #%d, type '%s', at %d, size=%d\n", d->image_num, d->code_printable,
				(int)d->image_pos, (int)d->image_len);
		}
		if(d->segment_len<8) break;
		if(d->segment_pos+d->segment_len > d->file_size) break;

		// Find this type code in the image_type_info array
		d->type_info = NULL;
		for(i=0; image_type_info_arr[i].code!=0; i++) {
			if(image_type_info_arr[i].code==d->code) {
				d->type_info = &image_type_info_arr[i];
				break;
			}
		}
		if(!d->type_info) {
			if(pass==2) {
				de_warn(c, "(Image #%d) Unknown image type '%s'\n", d->image_num, d->code_printable);
			}
		}

		if(pass==1) {
			switch(d->code) {
			case 0x73386d6b: // s8mk 16x16x8
				d->mkpos_s8mk = d->segment_pos;
				break;
			case 0x6c386d6b: // l8mk 32x32x8
				d->mkpos_l8mk = d->segment_pos;
				break;
			case 0x68386d6b: // h8mk 48x48x8
				d->mkpos_h8mk = d->segment_pos;
				break;
			}
		}
		else if(pass==2) {
			de_dbg_indent(c, 1);
			do_icon(c, d);
			de_dbg_indent(c, -1);
		}

		d->image_num++;
		d->segment_pos += d->segment_len;
	}
}

static void de_run_icns(deark *c, const char *params)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->file_size = de_getui32be(4);
	de_dbg(c, "reported file size: %d\n", (int)d->file_size);
	if(d->file_size > c->infile->len) d->file_size = c->infile->len;

	de_dbg(c, "pass 1: recording mask locations\n");
	de_run_icns_pass(c, d, 1);
	de_dbg(c, "pass 2: decoding/extracting icons\n");
	de_run_icns_pass(c, d, 2);

	de_free(c, d);
}

static int de_identify_icns(deark *c)
{
	de_int64 fsize;

	if(dbuf_memcmp(c->infile, 0, "icns", 4)) return 0;

	fsize = de_getui32be(4);
	if(fsize == c->infile->len) return 100;
	return 20;
}

void de_module_icns(deark *c, struct deark_module_info *mi)
{
	mi->id = "icns";
	mi->run_fn = de_run_icns;
	mi->identify_fn = de_identify_icns;
}
