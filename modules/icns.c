// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// icns - Apple Icon Image format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 file_size;
} lctx;

static void do_extract_png_or_jp2(deark *c, lctx *d, int image_num,
	de_int64 pos, de_int64 len)
{
	de_byte buf[8];

	de_dbg(c, "Trying to extract file at %d\n", (int)pos);
	// Detect the format
	de_read(buf, pos, sizeof(buf));

	// TODO: Include the expected dimensions (etc.) in the filename.
	if(buf[4]=='j' && buf[5]=='P') {
		dbuf_create_file_from_slice(c->infile, pos, len, "jp2", NULL);
	}
	else if(buf[0]==0x89 && buf[1]==0x50) {
		dbuf_create_file_from_slice(c->infile, pos, len, "png", NULL);
	}
	else {
		de_err(c, "(Image #%d) Unidentified file format\n", image_num);
	}
}

static void do_icon(deark *c, lctx *d, int image_num, de_int64 pos, de_int64 len)
{
	de_uint32 code;
	de_byte code_bytes[8];
	char code_printable[8];

	de_read(code_bytes, pos, 4);
	code = (de_uint32)de_getui32be_direct(code_bytes);
	de_make_printable_ascii(code_bytes, 4, code_printable, sizeof(code_printable), 0);

	de_dbg(c, "OSType: '%s'\n", code_printable);
	switch(code) {
	case 0x69637034: // icp4 
	case 0x69637035: // icp5
	case 0x69637036: // icp6
	case 0x69633037: // ic07
	case 0x69633038: // ic08
	case 0x69633039: // ic09
	case 0x69633130: // ic10
	case 0x69633131: // ic11
	case 0x69633132: // ic12
	case 0x69633133: // ic13
	case 0x69633134: // ic14
		do_extract_png_or_jp2(c, d, image_num, pos+8, len-8);
		break;

	default:
		de_warn(c, "(Image #%d) Image type '%s' not supported\n", image_num, code_printable);
	}
}

static void de_run_icns(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 segment_size;
	int image_count;

	d = de_malloc(c, sizeof(lctx));

	d->file_size = de_getui32be(4);
	de_dbg(c, "reported file size: %d\n", (int)d->file_size);
	if(d->file_size > c->infile->len) d->file_size = c->infile->len;

	pos = 8;
	image_count = 0;
	while(1) {
		if(pos+8 > d->file_size) break;
		segment_size = de_getui32be(pos+4);
		de_dbg(c, "image #%d at %d, size=%d\n", image_count, (int)pos, (int)(segment_size-8));
		if(pos<8) break;
		if(pos+segment_size > d->file_size) break;

		de_dbg_indent(c, 1);
		do_icon(c, d, image_count, pos, segment_size);
		de_dbg_indent(c, -1);

		image_count++;
		pos += segment_size;
	}

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
