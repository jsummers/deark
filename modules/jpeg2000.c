// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG 2000 files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

struct de_boxesctx;

// return 0 to stop reading
typedef int (*de_handle_box_fn)(deark *c, struct de_boxesctx *bctx);

struct de_boxesctx {
	void *userdata;
	dbuf *f; // Input file
	de_handle_box_fn handle_box_fn;

	// Per-box info supplied to handle_box_fn:
	int level;
	de_uint32 boxtype;
	int is_uuid;
	de_byte uuid[16]; // Valid only if is_uuid is set.
	de_int64 box_pos;
	de_int64 box_len;
	// Note: for UUID boxes, payload does not include the UUID
	de_int64 payload_pos;
	de_int64 payload_len;

	// To be filled in by handle_box_fn:
	int is_superbox;
};

typedef struct localctx_struct {
	int reserved;
} lctx;

static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	de_int64 pos1, de_int64 len, int level);

// Caller supplies s.
static void render_uuid(deark *c, const de_byte *uuid, char *s, size_t s_len)
{
	de_snprintf(s, s_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int do_box(deark *c, struct de_boxesctx *bctx, de_int64 pos, de_int64 len,
	int level, de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_len;
	de_int64 payload_len;
	de_byte boxtype_buf[4];
	char boxtype_printable[16];
	char uuid_string[50];

	bctx->is_uuid = 0;
	size32 = de_getui32be(pos);
	de_read(boxtype_buf, pos+4, 4);
	bctx->boxtype = (de_uint32)de_getui32be_direct(boxtype_buf);

	if(size32>=8) {
		header_len = 8;
		payload_len = size32-8;
	}
	else if(size32==0) {
		header_len = 8;
		payload_len = len-8;
	}
	else if(size32==1) {
		header_len = 16;
		size64 = de_geti64be(pos+8);
		if(size64<16) return 0;
		payload_len = size64-16;
	}
	else {
		// Invalid or unsupported format.
		return 0;
	}

#define DE_BOX_uuid 0x75756964U

	if(bctx->boxtype==DE_BOX_uuid && payload_len>=16) {
		bctx->is_uuid = 1;
		de_read(bctx->uuid, pos+header_len, 16);
	}

	if(c->debug_level>0) {
		de_make_printable_ascii(boxtype_buf, 4, boxtype_printable, sizeof(boxtype_printable), 0);
		if(bctx->is_uuid) {
			render_uuid(c, bctx->uuid, uuid_string, sizeof(uuid_string));
			de_dbg(c, "box '%s'{%s} at %d, size=%d\n",
				boxtype_printable, uuid_string,
				(int)pos, (int)payload_len);
		}
		else {
			de_dbg(c, "box '%s' at %d, size=%d\n", boxtype_printable,
				(int)pos, (int)payload_len);
		}
	}

	bctx->level = level;
	bctx->is_superbox = 0; // Default value. Client can change it.
	bctx->box_pos = pos;
	bctx->box_len = header_len + payload_len;
	bctx->payload_pos = pos+header_len;
	bctx->payload_len = payload_len;
	if(bctx->is_uuid) {
		bctx->payload_pos += 16;
		bctx->payload_len -= 16;
	}
	if(!bctx->handle_box_fn(c, bctx)) {
		return 0;
	}

	if(bctx->is_superbox) {
		de_dbg_indent(c, 1);
		do_box_sequence(c, bctx, pos+header_len, payload_len, level+1);
		de_dbg_indent(c, -1);
	}

	*pbytes_consumed = header_len + payload_len;
	return 1;
}

static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	de_int64 pos1, de_int64 len, int level)
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
		ret = do_box(c, bctx, pos, endpos-pos, level, &box_len);
		if(!ret) break;
		pos += box_len;
	}
}

static void de_read_boxes_format(deark *c, struct de_boxesctx *bctx)
{
	do_box_sequence(c, bctx, 0, bctx->f->len, 0);
}


#define BOX_jp2c 0x6a703263U
#define BOX_xml  0x786d6c20U
// Superboxes:
#define BOX_jp2h 0x6a703268U // JP2
#define BOX_res  0x72657320U
#define BOX_uinf 0x75696e66U
#define BOX_jpch 0x6a706368U // JPX
#define BOX_jplh 0x6a706c68U
#define BOX_cgrp 0x63677270U
#define BOX_ftbl 0x6674626cU
#define BOX_comp 0x636f6d70U
#define BOX_asoc 0x61736f63U
#define BOX_drep 0x64726570U
#define BOX_page 0x70616765U // JPM
#define BOX_lobj 0x6c6f626aU
#define BOX_objc 0x6f626a63U
#define BOX_sdat 0x73646174U

static int my_box_handler(deark *c, struct de_boxesctx *bctx)
{
	static const de_uint32 superboxes[] = {
		BOX_jp2h, BOX_res , BOX_uinf, BOX_jpch, BOX_jplh, BOX_cgrp,
		BOX_ftbl, BOX_comp, BOX_asoc, BOX_drep, BOX_page, BOX_lobj,
		BOX_objc, BOX_sdat,
		0 };
	int i;

	if(bctx->is_uuid) {
		if(!de_memcmp(bctx->uuid, "\xb1\x4b\xf8\xbd\x08\x3d\x4b\x43\xa5\xae\x8c\xd7\xd5\xa6\xce\x03", 16)) {
			de_dbg(c, "GeoTIFF data at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "geo.tif", NULL);
		}
		else if(!de_memcmp(bctx->uuid, "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac", 16)) {
			de_dbg(c, "XMP data at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "xmp", NULL);
		}
		else if(!de_memcmp(bctx->uuid, "\x2c\x4c\x01\x00\x85\x04\x40\xb9\xa0\x3e\x56\x21\x48\xd6\xdf\xeb", 16)) {
			de_dbg(c, "Photoshop resources at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			de_fmtutil_handle_photoshop_rsrc(c, bctx->payload_pos, bctx->payload_len);
		}
		else if(!de_memcmp(bctx->uuid, "\x05\x37\xcd\xab\x9d\x0c\x44\x31\xa7\x2a\xfa\x56\x1f\x2a\x11\x3e", 16)) {
			de_dbg(c, "Exif data at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			de_fmtutil_handle_exif(c, bctx->payload_pos, bctx->payload_len);
		}
	}
	else if(bctx->boxtype==BOX_jp2c) { // Contiguous Codestream box
		dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "j2c", NULL);
	}
	else if(bctx->boxtype==BOX_xml) {
		// TODO: Detect the specific XML format, and use it to choose a better
		// filename.
		dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "xml", NULL);
	}
	else {
		// Check if this box type is known to contain other boxes that we might
		// want to recurse into.
		for(i=0; superboxes[i]; i++) {
			if(bctx->boxtype == superboxes[i]) {
				bctx->is_superbox = 1;
				break;
			}
		}
	}

	return 1;
}

static void de_run_jpeg2000(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_boxesctx *bctx = NULL;

	d = de_malloc(c, sizeof(lctx));
	bctx = de_malloc(c, sizeof(struct de_boxesctx));

	bctx->userdata = (void*)d;
	bctx->f = c->infile;
	bctx->handle_box_fn = my_box_handler;

	de_read_boxes_format(c, bctx);

	de_free(c, bctx);
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
	mi->desc = "JPEG 2000 formats (resources only)";
	mi->run_fn = de_run_jpeg2000;
	mi->identify_fn = de_identify_jpeg2000;
}
