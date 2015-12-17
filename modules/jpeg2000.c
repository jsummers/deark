// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG 2000 files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	int reserved;
} lctx;

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
		return de_fmtutil_default_box_handler(c, bctx);
	}
	else if(bctx->boxtype==BOX_jp2c) { // Contiguous Codestream box
		de_dbg(c, "JPEG 2000 codestream at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
		dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "j2c", NULL);
	}
	else if(bctx->boxtype==BOX_xml) {
		// TODO: Detect the specific XML format, and use it to choose a better
		// filename.
		de_dbg(c, "XML data at %d, size=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
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

	de_fmtutil_read_boxes_format(c, bctx);

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
