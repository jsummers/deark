// This file is part of Deark.
// Copyright (C) 2016-2018 Jason Summers
// See the file COPYING for terms of use.

// ISO Base Media File Format, and related formats
// (JPEG 2000, MP4, QuickTime, etc.)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
// TODO: Rethink how to subdivide these formats into modules.
DE_DECLARE_MODULE(de_module_bmff);
DE_DECLARE_MODULE(de_module_jpeg2000);

typedef struct localctx_struct {
	de_uint32 major_brand;
	de_byte is_bmff;
	de_byte is_jp2_jpx_jpm;
	de_byte is_mj2;
} lctx;

typedef void (*handler_fn_type)(deark *c, lctx *d, struct de_boxesctx *bctx);

struct box_type_info {
	de_uint32 boxtype;
	// flags1 is intended to be used to indicate which formats/brands use this box.
	// 0x00000001 = Generic BMFF (isom brand, etc.)
	// 0x00000008 = MJ2
	// 0x00010000 = JP2/JPX/JPM
	de_uint32 flags1;
	// flags2: 0x1 = is_superbox
	// flags2: 0x2 = critical top-level box (used for format identification)
	de_uint32 flags2;
	const char *name;
	handler_fn_type hfn;
};

#define BRAND_isom 0x69736f6dU
#define BRAND_mp41 0x6d703431U
#define BRAND_mp42 0x6d703432U
#define BRAND_M4A  0x4d344120U
#define BRAND_jp2  0x6a703220U
#define BRAND_jpm  0x6a706d20U
#define BRAND_jpx  0x6a707820U
#define BRAND_mjp2 0x6d6a7032U
#define BRAND_mj2s 0x6d6a3273U
#define BRAND_qt   0x71742020U

#define BOX_ftyp 0x66747970U
#define BOX_jP   0x6a502020U
#define BOX_jp2c 0x6a703263U
#define BOX_mdhd 0x6d646864U
#define BOX_mvhd 0x6d766864U
#define BOX_stsd 0x73747364U
#define BOX_tkhd 0x746b6864U
#define BOX_xml  0x786d6c20U

// JP2:
#define BOX_colr 0x636f6c72U
#define BOX_jp2h 0x6a703268U
#define BOX_ihdr 0x69686472U
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
	switch(brand_id) {
	case BRAND_jp2:
	case BRAND_jpx:
	case BRAND_jpm:
		d->is_jp2_jpx_jpm = 1;
		break;
	case BRAND_isom:
	case BRAND_mp41:
	case BRAND_mp42:
	case BRAND_M4A:
	case BRAND_qt:
	case BRAND_mjp2:
	case BRAND_mj2s:
		d->is_bmff = 1;
		break;
	}
}

// JPEG 2000 signature box (presumably)
static void do_box_jP(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_uint32 n;
	if(bctx->level!=0) return;
	if(bctx->payload_len<4) return;
	n = (de_uint32)dbuf_getui32be(bctx->f, bctx->payload_pos);
	if(n==0x0d0a870a) {
		de_dbg(c, "found JPEG 2000 signature");
	}
}

static void do_box_ftyp(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 i;
	de_int64 num_compat_brands;
	struct de_fourcc brand4cc;

	if(bctx->payload_len<4) return;
	dbuf_read_fourcc(bctx->f, bctx->payload_pos, &brand4cc, 0);
	d->major_brand = brand4cc.id;
	de_dbg(c, "major brand: '%s'", brand4cc.id_printable);
	if(bctx->level==0)
		apply_brand(c, d, d->major_brand);

	if(bctx->payload_len>=12)
		num_compat_brands = (bctx->payload_len - 8)/4;
	else
		num_compat_brands = 0;

	for(i=0; i<num_compat_brands; i++) {
		dbuf_read_fourcc(bctx->f, bctx->payload_pos + 8 + i*4, &brand4cc, 0);
		if(brand4cc.id==0) continue; // Placeholder. Ignore.
		de_dbg(c, "compatible brand: '%s'", brand4cc.id_printable);
		if(bctx->level==0)
			apply_brand(c, d, brand4cc.id);
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
		de_dbg(c, "version=%d, flags=0x%06x", (int)version1, (unsigned int)flags1);
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
	de_dbg(c, "track id: %d", (int)n);

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
	de_dbg(c, "volume: %.3f", ((double)n)/256.0);

	pos += 2; // reserved
	pos += 4*9; // matrix

	w = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	h = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	de_dbg(c, "dimensions: %.1f"DE_CHAR_TIMES"%.1f", w, h);
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
	de_dbg(c, "timescale: %d time units per second", (int)timescale);

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
	de_dbg(c, "duration: %d time units (%.2f seconds)", (int)n, nd);

	nd = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4; // rate
	de_dbg(c, "rate: %.3f", nd);

	n = dbuf_getui16be(bctx->f, pos);
	pos += 2; // volume
	de_dbg(c, "volume: %.3f", ((double)n)/256.0);

	pos += 2; // reserved
	pos += 4*2; // reserved
	pos += 4*9; // matrix
	pos += 4*6; // pre_defined

	n = dbuf_getui32be(bctx->f, pos);
	de_dbg(c, "next track id: %d", (int)n);
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
	de_dbg(c, "timescale: %d time units per second", (int)timescale);

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
	de_dbg(c, "duration: %d time units (%.2f seconds)", (int)n, nd);
}

static void do_box_stsd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 num_entries;
	de_int64 entry_size;
	struct de_fourcc fmt4cc;

	if(bctx->payload_len<8) return;

	pos = bctx->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0) return;

	num_entries = dbuf_getui32be(bctx->f, pos);
	de_dbg(c, "number of sample description entries: %d", (int)num_entries);
	pos += 4;

	while(1) {
		if(pos + 16 >= bctx->payload_pos + bctx->payload_len) break;
		entry_size = dbuf_getui32be(bctx->f, pos);
		de_dbg(c, "sample description entry at %d, len=%d", (int)pos, (int)entry_size);
		if(entry_size<16) break;

		de_dbg_indent(c, 1);
		dbuf_read_fourcc(bctx->f, pos+4, &fmt4cc, 0);
		de_dbg(c, "data format: '%s'", fmt4cc.id_printable);
		de_dbg_indent(c, -1);

		pos += entry_size;
	}
}

static void do_box_meta(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
	bctx->has_version_and_flags = 1;
}

static void do_box_jp2c(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_dbg(c, "JPEG 2000 codestream at %d, len=%d", (int)bctx->payload_pos, (int)bctx->payload_len);
	dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "j2c", NULL, 0);
}

static void do_box_xml(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	// TODO: Detect the specific XML format, and use it to choose a better
	// filename.
	de_dbg(c, "XML data at %d, len=%d", (int)bctx->payload_pos, (int)bctx->payload_len);
	dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "xml", NULL, DE_CREATEFLAG_IS_AUX);
}

static const struct box_type_info box_type_info_arr[] = {
	{BOX_ftyp, 0x0001ffff, 0x00000002, "file type", do_box_ftyp},
	{BOX_jP  , 0x00010000, 0x00000002, NULL, do_box_jP},
	{BOX_stsd, 0x0000ffff, 0x00000000, "sample description", do_box_stsd},
	{BOX_mdhd, 0x0000ffff, 0x00000000, "media header", do_box_mdhd},
	{BOX_mvhd, 0x0000ffff, 0x00000000, "movie header", do_box_mvhd},
	{BOX_tkhd, 0x0000ffff, 0x00000000, "track header", do_box_tkhd},
	{BOX_cinf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_clip, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_dinf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_edts, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_fdsa, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_fiin, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_hinf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_hnti, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_matt, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_mdia, 0x0000ffff, 0x00000001, "media", NULL},
	{BOX_meco, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_meta, 0x0000ffff, 0x00000001, NULL, do_box_meta},
	{BOX_minf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_mfra, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_moof, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_moov, 0x0000ffff, 0x00000001, "movie", NULL},
	{BOX_mvex, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_paen, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_rinf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_schi, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_sinf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_stbl, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_strd, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_strk, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_traf, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_trak, 0x0000ffff, 0x00000001, "trak", NULL},
	{BOX_tref, 0x0000ffff, 0x00000001, NULL, NULL},
	{BOX_udta, 0x0000ffff, 0x00000001, "user data", NULL},
	{BOX_asoc, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_cgrp, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_colr, 0x00010000, 0x00000000, "colour specification", NULL},
	{BOX_comp, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_drep, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_ftbl, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_ihdr, 0x00010000, 0x00000000, "image header", NULL},
	{BOX_jp2c, 0x00010008, 0x00000000, "contiguous codestream", do_box_jp2c},
	{BOX_jp2h, 0x00010000, 0x00000001, "JP2 header", NULL},
	{BOX_jpch, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_jplh, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_lobj, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_objc, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_page, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_res , 0x00010000, 0x00000001, NULL, NULL},
	{BOX_sdat, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_uinf, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_xml , 0x00010008, 0x00000000, "XML", do_box_xml}
};

static const struct box_type_info *find_box_type_info(deark *c, lctx *d,
	de_uint32 boxtype, int level)
{
	size_t k;
	de_uint32 mask = 0;

	if(d->is_bmff) mask |= 0x00000001;
	if(d->is_jp2_jpx_jpm) mask |= 0x00010000;
	if(d->is_mj2) mask |= 0x000000080;

	for(k=0; k<DE_ITEMS_IN_ARRAY(box_type_info_arr); k++) {
		if(box_type_info_arr[k].boxtype != boxtype) continue;
		if(level==0 && (box_type_info_arr[k].flags2 & 0x2)) {
			// Critical box. Always match.
			return &box_type_info_arr[k];
		}
		if((box_type_info_arr[k].flags1 & mask)==0) continue;
		return &box_type_info_arr[k];
	}
	return NULL;
}

static void my_box_id_fn(deark *c, struct de_boxesctx *bctx)
{
	const struct box_type_info *bti;
	lctx *d = (lctx*)bctx->userdata;

	bti = find_box_type_info(c, d, bctx->boxtype, bctx->level);
	if(bti) {
		// So that we don't have to run "find" again in my_box_handler(),
		// record it here.
		bctx->box_userdata = (void*)bti;

		if(bti->name) {
			bctx->box_name = bti->name;
		}
	}
}

static int my_box_handler(deark *c, struct de_boxesctx *bctx)
{
	const struct box_type_info *bti;
	lctx *d = (lctx*)bctx->userdata;

	if(bctx->is_uuid) {
		return de_fmtutil_default_box_handler(c, bctx);
	}

	bti = (const struct box_type_info *)bctx->box_userdata;

	if(bti && (bti->flags2 & 0x1)) {
		bctx->is_superbox = 1;
	}

	if(bti && bti->hfn) {
		bti->hfn(c, d, bctx);
	}

	return 1;
}

static void de_run_bmff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_boxesctx *bctx = NULL;
	de_byte buf[4];

	d = de_malloc(c, sizeof(lctx));
	bctx = de_malloc(c, sizeof(struct de_boxesctx));

	// Try to detect old QuickTime files that don't have an ftyp box.
	de_read(buf, 4, 4);
	if(!de_memcmp(buf, "mdat", 4) ||
		!de_memcmp(buf, "moov", 4))
	{
		d->is_bmff = 1;
	}

	bctx->userdata = (void*)d;
	bctx->f = c->infile;
	bctx->identify_box_fn = my_box_id_fn;
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
	mi->desc = "JPEG 2000 image";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_bmff;
	mi->identify_fn = de_identify_jpeg2000;
}

static int de_identify_bmff(deark *c)
{
	de_byte buf[4];

	de_read(buf, 4, 4);
	if(!de_memcmp(buf, "ftyp", 4)) return 80;
	if(!de_memcmp(buf, "mdat", 4)) return 15;
	if(!de_memcmp(buf, "moov", 4)) return 15;
	return 0;
}

void de_module_bmff(deark *c, struct deark_module_info *mi)
{
	mi->id = "bmff";
	mi->desc = "ISO Base Media File Format";
	mi->desc2 = "MP4, QuickTime, etc.";
	mi->id_alias[0] = "mp4";
	mi->run_fn = de_run_bmff;
	mi->identify_fn = de_identify_bmff;
}
