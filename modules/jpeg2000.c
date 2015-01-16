// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG 2000 files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	int reserved;
} lctx;

static void do_box_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level);

// Caller supplies s.
static void render_uuid(deark *c, const de_byte *uuid, char *s, size_t s_len)
{
	de_snprintf(s, s_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int do_box(deark *c, lctx *d, de_int64 pos, de_int64 len, int level,
	de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_size;
	de_int64 payload_size;
	de_byte boxtype[4];
	char boxtype_printable[16];
	de_byte uuid[16];
	char uuid_string[50];
	int i;
	int is_uuid = 0;
	// TODO: Prune this list? We don't really need to know *all* superbox
	// types -- only those that could contain data we want to extract.
	static const char *superboxes[] = {
		"jp2h", "res ", "uinf", // JP2
		"jpch", "jplh", "cgrp", "ftbl", "comp", "asoc", "drep", // JPX
		"page", "lobj", "objc", "sdat", // JPM
		NULL };

	size32 = de_getui32be(pos);
	de_read(boxtype, pos+4, 4);

	if(size32>=8) {
		header_size = 8;
		payload_size = size32-8;
	}
	else if(size32==0) {
		header_size = 8;
		payload_size = len-8;
	}
	else if(size32==1) {
		header_size = 16;
		size64 = de_geti64be(pos+8);
		if(size64<16) return 0;
		payload_size = size64-16;
	}
	else {
		// Invalid or unsupported format.
		return 0;
	}

	if(payload_size>=16 && !de_memcmp(boxtype, "uuid", 4)) {
		is_uuid = 1;
		de_read(uuid, pos+header_size, 16);
	}

	if(c->debug_level>0) {
		de_make_printable_ascii(boxtype, 4, boxtype_printable, sizeof(boxtype_printable), 0);
		if(is_uuid) {
			render_uuid(c, uuid, uuid_string, sizeof(uuid_string));
			de_dbg(c, "box '%s'{%s} at %d, size=%d\n",
				boxtype_printable, uuid_string,
				(int)pos, (int)payload_size);
		}
		else {
			de_dbg(c, "box '%s' at %d, size=%d\n", boxtype_printable,
				(int)pos, (int)payload_size);
		}
	}

	if(is_uuid) {
		de_int64 upos, ulen;
		upos = pos+header_size+16;
		ulen = payload_size-16;

		if(!de_memcmp(uuid, "\xb1\x4b\xf8\xbd\x08\x3d\x4b\x43\xa5\xae\x8c\xd7\xd5\xa6\xce\x03", 16)) {
			de_dbg(c, "GeoTIFF data at %d, size=%d\n", (int)upos, (int)ulen);
			dbuf_create_file_from_slice(c->infile, upos, ulen, "geo.tif", NULL);
		}
		else if(!de_memcmp(uuid, "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac", 16)) {
			de_dbg(c, "XMP data at %d, size=%d\n", (int)upos, (int)ulen);
			dbuf_create_file_from_slice(c->infile, upos, ulen, "xmp", NULL);
		}
		else if(!de_memcmp(uuid, "\x2c\x4c\x01\x00\x85\x04\x40\xb9\xa0\x3e\x56\x21\x48\xd6\xdf\xeb", 16)) {
			de_dbg(c, "Photoshop resources at %d, size=%d\n", (int)upos, (int)ulen);
			de_fmtutil_handle_photoshop_rsrc(c, upos, ulen);
		}
		else if(!de_memcmp(uuid, "\x05\x37\xcd\xab\x9d\x0c\x44\x31\xa7\x2a\xfa\x56\x1f\x2a\x11\x3e", 16)) {
			de_dbg(c, "Exif data at %d, size=%d\n", (int)upos, (int)ulen);
			de_fmtutil_handle_exif(c, upos, ulen);
		}
	}
	else if(!de_memcmp(boxtype, "jp2c", 4)) { // Contiguous Codestream box
		dbuf_create_file_from_slice(c->infile, pos+header_size, payload_size, "j2c", NULL);
	}
	else if(!de_memcmp(boxtype, "xml ", 4)) { // XML box
		// TODO: Detect the specific XML format, and use it to choose a better
		// filename.
		dbuf_create_file_from_slice(c->infile, pos+header_size, payload_size, "xml", NULL);
	}
	else {
		// Check if this box type is known to contain other boxes that we might
		// want to recurse into.
		for(i=0; superboxes[i]; i++) {
			if(!de_memcmp(boxtype, superboxes[i], 4)) {
				de_dbg_indent(c, 1);
				do_box_sequence(c, d, pos+header_size, payload_size, level+1);
				de_dbg_indent(c, -1);
				break;
			}
		}
	}

	*pbytes_consumed = header_size + payload_size;
	return 1;
}

static void do_box_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level)
{
	de_int64 pos;
	de_int64 box_len;
	de_int64 endpos;
	int ret;

	if(level >= 32) { // An arbitrary recursion limit.
		return;
	}

	pos = pos1;
	endpos = pos1 + len;

	while(pos < endpos) {
		ret = do_box(c, d, pos, endpos-pos, level, &box_len);
		if(!ret) break;
		pos += box_len;
	}
}

static void de_run_jpeg2000(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In jpeg2000 module\n");

	d = de_malloc(c, sizeof(lctx));

	do_box_sequence(c, d, 0, c->infile->len, 0);

	de_free(c, d);
}

static int de_identify_jpeg2000(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a", 12))
		return 100;
	return 0;
}

void de_module_jpeg2000(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpeg2000";
	mi->run_fn = de_run_jpeg2000;
	mi->identify_fn = de_identify_jpeg2000;
}
