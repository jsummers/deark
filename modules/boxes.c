// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG 2000, MP4, and similar files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	de_uint32 major_brand;
	de_byte is_jpx;
} lctx;

#define BRAND_jpx  0x6a707820U

#define BOX_ftyp 0x66747970U
#define BOX_jp2c 0x6a703263U
#define BOX_mdhd 0x6d646864U
#define BOX_mvhd 0x6d766864U
#define BOX_stsd 0x73747364U
#define BOX_tkhd 0x746b6864U
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

// Called for each primary or compatible brand.
// Brand-specific setup can be done here.
static void apply_brand(deark *c, lctx *d, de_uint32 brand_id)
{
	if(brand_id==BRAND_jpx) {
		d->is_jpx = 1;
	}
}

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
	apply_brand(c, d, d->major_brand);

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
		apply_brand(c, d, brand_id);
	}
}

static void do_read_version_and_flags(deark *c, lctx *d, struct de_boxesctx *bctx,
	de_byte *version, de_uint32 *flags, int dbgflag)
{
	de_byte version1;
	de_uint32 flags1;
	de_uint32 n;

	n = (de_uint32)dbuf_getui32be(bctx->f, bctx->payload_pos);
	version1 = (de_byte)(n>>24);
	flags1 = n&0x00ffffff;
	if(dbgflag) {
		de_dbg(c, "version=%d, flags=0x%06x\n", (int)version1, (unsigned int)flags1);
	}
	if(version) *version = version1;
	if(flags) *flags = flags1;
}

static void do_box_tkhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	double w, h;
	de_int64 n;

	if(bctx->payload_len<4) return;

	pos = bctx->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(bctx->payload_len<96) return;
	}
	else {
		if(bctx->payload_len<84) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	n = dbuf_getui32be(bctx->f, pos);
	pos += 4;
	de_dbg(c, "track id: %d\n", (int)n);

	pos += 4; // reserved

	// duration
	if(version==1)
		pos += 8;
	else
		pos += 4;

	pos += 4*2; // reserved
	pos += 2; // layer
	pos += 2; // alternate group

	n = dbuf_getui16be(bctx->f, pos);
	pos += 2; // volume
	de_dbg(c, "volume: %.3f\n", ((double)n)/256.0);

	pos += 2; // reserved
	pos += 4*9; // matrix

	w = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	h = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	de_dbg(c, "dimensions: %.1fx%.1f\n", w, h);
}

static void do_box_mvhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 n;
	de_int64 timescale;
	double nd;

	if(bctx->payload_len<4) return;

	pos = bctx->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(bctx->payload_len<112) return;
	}
	else {
		if(bctx->payload_len<100) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	timescale = dbuf_getui32be(bctx->f, pos);
	pos += 4;
	de_dbg(c, "timescale: %d time units per second\n", (int)timescale);

	// duration
	if(version==1) {
		n = dbuf_geti64be(bctx->f, pos);
		pos += 8;
	}
	else {
		n = dbuf_getui32be(bctx->f, pos);
		pos += 4;
	}
	if(timescale>0)
		nd = (double)n / (double)timescale;
	else
		nd = 0.0;
	de_dbg(c, "duration: %d time units (%.2f seconds)\n", (int)n, nd);

	nd = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4; // rate
	de_dbg(c, "rate: %.3f\n", nd);

	n = dbuf_getui16be(bctx->f, pos);
	pos += 2; // volume
	de_dbg(c, "volume: %.3f\n", ((double)n)/256.0);

	pos += 2; // reserved
	pos += 4*2; // reserved
	pos += 4*9; // matrix
	pos += 4*6; // pre_defined

	n = dbuf_getui32be(bctx->f, pos);
	de_dbg(c, "next track id: %d\n", (int)n);
}

static void do_box_mdhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 n;
	de_int64 timescale;
	double nd;

	// TODO: Share code with do_box_mvhd()?
	if(bctx->payload_len<4) return;

	pos = bctx->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(bctx->payload_len<36) return;
	}
	else {
		if(bctx->payload_len<24) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	timescale = dbuf_getui32be(bctx->f, pos);
	pos += 4;
	de_dbg(c, "timescale: %d time units per second\n", (int)timescale);

	// duration
	if(version==1) {
		n = dbuf_geti64be(bctx->f, pos);
		pos += 8;
	}
	else {
		n = dbuf_getui32be(bctx->f, pos);
		pos += 4;
	}
	if(timescale>0)
		nd = (double)n / (double)timescale;
	else
		nd = 0.0;
	de_dbg(c, "duration: %d time units (%.2f seconds)\n", (int)n, nd);
}

static void do_box_stsd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 num_entries;
	de_int64 entry_size;
	de_byte data_format_buf[4];
	char data_format_printable[16];

	if(bctx->payload_len<8) return;

	pos = bctx->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0) return;

	num_entries = dbuf_getui32be(bctx->f, pos);
	de_dbg(c, "number of sample description entries: %d\n", (int)num_entries);
	pos += 4;

	while(1) {
		if(pos + 16 >= bctx->payload_pos + bctx->payload_len) break;
		entry_size = dbuf_getui32be(bctx->f, pos);
		de_dbg(c, "sample description at %d, len=%d\n", (int)pos, (int)entry_size);
		if(entry_size<16) break;

		de_dbg_indent(c, 1);
		dbuf_read(bctx->f, data_format_buf, pos+4, 4);
		de_make_printable_ascii(data_format_buf, 4, data_format_printable, sizeof(data_format_printable), 0);
		de_dbg(c, "data format: '%s'\n", data_format_printable);
		de_dbg_indent(c, -1);

		pos += entry_size;
	}
}

static int my_box_handler(deark *c, struct de_boxesctx *bctx)
{
	static const de_uint32 superboxes[] = {
		BOX_jp2h, BOX_res , BOX_uinf, BOX_jpch, BOX_jplh, BOX_cgrp,
		BOX_ftbl, BOX_comp, BOX_asoc, BOX_page, BOX_lobj,
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
	switch(bctx->boxtype) {
	case BOX_ftyp:
		do_box_ftyp(c, d, bctx);
		break;
	case BOX_jp2c: // Contiguous Codestream box
		de_dbg(c, "JPEG 2000 codestream at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
		dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "j2c", NULL, 0);
		break;
	case BOX_mdhd:
		do_box_mdhd(c, d, bctx);
		break;
	case BOX_mvhd:
		do_box_mvhd(c, d, bctx);
		break;
	case BOX_stsd:
		do_box_stsd(c, d, bctx);
		break;
	case BOX_tkhd:
		do_box_tkhd(c, d, bctx);
		break;
	case BOX_xml:
		// TODO: Detect the specific XML format, and use it to choose a better
		// filename.
		de_dbg(c, "XML data at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
		dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "xml", NULL, DE_CREATEFLAG_IS_AUX);
		break;
	default:
		// Check if this box type is known to contain other boxes that we might
		// want to recurse into.
		for(i=0; superboxes[i]; i++) {
			if(bctx->boxtype == superboxes[i]) {
				bctx->is_superbox = 1;
				break;
			}
		}

		if(d->is_jpx) {
			// 'drep' is a superbox in JPX format.
			// 'drep' exists in BMFF, but is not a superbox.
			// TODO: Need a more general way to decide if a box is a superbox.
			if(bctx->boxtype==BOX_drep) {
				bctx->is_superbox = 1;
			}
		}

		if(bctx->boxtype==BOX_meta) {
			do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
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
