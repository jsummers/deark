// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG 2000, MP4, and similar files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	de_uint32 major_brand;
} lctx;

#define BOX_ftyp 0x66747970U
#define BOX_jp2c 0x6a703263U
#define BOX_xml  0x786d6c20U

// Superboxes:
//  JP2:
#define BOX_jp2h 0x6a703268U
#define BOX_res  0x72657320U
#define BOX_uinf 0x75696e66U
// JPX:
#define BOX_jpch 0x6a706368U
#define BOX_jplh 0x6a706c68U
#define BOX_cgrp 0x63677270U
#define BOX_ftbl 0x6674626cU
#define BOX_comp 0x636f6d70U
#define BOX_asoc 0x61736f63U
#define BOX_drep 0x64726570U
//  JPM:
#define BOX_page 0x70616765U
#define BOX_lobj 0x6c6f626aU
#define BOX_objc 0x6f626a63U
#define BOX_sdat 0x73646174U
//  BMFF, QuickTime, MP4, ...:
#define BOX_cinf 0x63696e66U
#define BOX_clip 0x636c6970U
#define BOX_dinf 0x64696e66U
#define BOX_edts 0x65647473U
//#define BOX_extr 0x65787472U // Irregular format?
#define BOX_fdsa 0x66647361U
#define BOX_fiin 0x6669696eU
#define BOX_hinf 0x68696e66U
#define BOX_hnti 0x686e7469U
#define BOX_matt 0x6d617474U
#define BOX_mdia 0x6d646961U
#define BOX_meco 0x6d65636fU
#define BOX_meta 0x6d657461U
#define BOX_minf 0x6d696e66U
#define BOX_mfra 0x6d667261U
#define BOX_moof 0x6d6f6f66U
#define BOX_moov 0x6d6f6f76U
#define BOX_mvex 0x6d766578U
#define BOX_paen 0x7061656eU
#define BOX_rinf 0x72696e66U
#define BOX_schi 0x73636869U
#define BOX_sinf 0x73696e66U
#define BOX_stbl 0x7374626cU
#define BOX_strd 0x73747264U
#define BOX_strk 0x7374726bU
#define BOX_traf 0x74726166U
#define BOX_trak 0x7472616bU
#define BOX_tref 0x74726566U
#define BOX_udta 0x75647461U

static void do_box_ftyp(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte brand_buf[4];
	char brand_printable[16];
	de_int64 i;
	de_int64 num_compat_brands;
	de_uint32 brand_id;

	if(bctx->payload_len<4) return;
	dbuf_read(bctx->f, brand_buf, bctx->payload_pos, 4);
	d->major_brand = (de_uint32)de_getui32be_direct(brand_buf);
	de_make_printable_ascii(brand_buf, 4, brand_printable, sizeof(brand_printable), 0);
	de_dbg(c, "major brand: '%s'\n", brand_printable);

	if(bctx->payload_len>=12)
		num_compat_brands = (bctx->payload_len - 8)/4;
	else
		num_compat_brands = 0;

	for(i=0; i<num_compat_brands; i++) {
		dbuf_read(bctx->f, brand_buf, bctx->payload_pos + 8 + i*4, 4);
		brand_id = (de_uint32)de_getui32be_direct(brand_buf);
		if(brand_id==0) continue; // Placeholder. Ignore.
		de_make_printable_ascii(brand_buf, 4, brand_printable, sizeof(brand_printable), 0);
		de_dbg(c, "compatible brand: '%s'\n", brand_printable);
	}
}

static int my_box_handler(deark *c, struct de_boxesctx *bctx)
{
	static const de_uint32 superboxes[] = {
		BOX_jp2h, BOX_res , BOX_uinf, BOX_jpch, BOX_jplh, BOX_cgrp,
		BOX_ftbl, BOX_comp, BOX_asoc, BOX_drep, BOX_page, BOX_lobj,
		BOX_objc, BOX_sdat,
		BOX_cinf, BOX_clip, BOX_dinf, BOX_edts, BOX_fdsa, BOX_fiin,
		BOX_hinf, BOX_hnti, BOX_matt, BOX_mdia, BOX_meco, BOX_meta,
		BOX_minf, BOX_mfra, BOX_moof, BOX_moov, BOX_mvex, BOX_paen,
		BOX_rinf, BOX_schi, BOX_sinf, BOX_stbl, BOX_strd, BOX_strk,
		BOX_traf, BOX_trak, BOX_tref, BOX_udta,
		0 };
	int i;
	lctx *d = (lctx*)bctx->userdata;

	if(bctx->is_uuid) {
		return de_fmtutil_default_box_handler(c, bctx);
	}
	else if(bctx->boxtype==BOX_ftyp) {
		do_box_ftyp(c, d, bctx);
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

		if(bctx->boxtype==BOX_meta) {
			bctx->has_version_and_flags = 1;
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

static int de_identify_mp4(deark *c)
{
	de_byte buf[4];

	de_read(buf, 4, 4);
	if(!de_memcmp(buf, "ftyp", 4)) return 20;
	if(!de_memcmp(buf, "mdat", 4)) return 15;
	if(!de_memcmp(buf, "moov", 4)) return 15;
	return 0;
}

void de_module_mp4(deark *c, struct deark_module_info *mi)
{
	mi->id = "mp4";
	mi->desc = "MP4, QuickTime, and similar formats (resources only)";
	mi->run_fn = de_run_jpeg2000;
	mi->identify_fn = de_identify_mp4;
}
