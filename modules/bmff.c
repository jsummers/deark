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
	de_byte is_jp2_jpx_jpm, is_jpx, is_jpm;
	de_byte is_mj2;
	de_byte is_heif;
	de_byte is_jpegxt;
	de_int64 max_entries_to_print;
} lctx;

typedef void (*handler_fn_type)(deark *c, lctx *d, struct de_boxesctx *bctx);

struct box_type_info {
	de_uint32 boxtype;
	// flags1 is intended to be used to indicate which formats/brands use this box.
	// 0x00000001 = Generic BMFF (isom brand, etc.)
	// 0x00000008 = MJ2
	// 0x00010000 = JP2/JPX/JPM
	// 0x00040000 = JPEG XT
	// 0x00080000 = HEIF
	// 0x01000000 = Used in ilst boxes
	de_uint32 flags1;
	// flags2: 0x1 = is_superbox
	// flags2: 0x2 = critical top-level box (used for format identification)
	de_uint32 flags2;
	const char *name;
	handler_fn_type hfn;
};

#define BRAND_heic 0x68656963U
#define BRAND_isom 0x69736f6dU
#define BRAND_mif1 0x6d696631U
#define BRAND_mp41 0x6d703431U
#define BRAND_mp42 0x6d703432U
#define BRAND_M4A  0x4d344120U
#define BRAND_jp2  0x6a703220U
#define BRAND_jpm  0x6a706d20U
#define BRAND_jpx  0x6a707820U
#define BRAND_mjp2 0x6d6a7032U
#define BRAND_mj2s 0x6d6a3273U
#define BRAND_qt   0x71742020U

#define BOX_auxC 0x61757843U
#define BOX_co64 0x636f3634U
#define BOX_ctts 0x63747473U
#define BOX_data 0x64617461U
#define BOX_elst 0x656c7374U
#define BOX_ftyp 0x66747970U
#define BOX_grpl 0x6772706cU
#define BOX_hvcC 0x68766343U
#define BOX_idat 0x69646174U
#define BOX_iinf 0x69696e66U
#define BOX_iloc 0x696c6f63U
#define BOX_ilst 0x696c7374U
#define BOX_infe 0x696e6665U
#define BOX_ipco 0x6970636fU
#define BOX_ipma 0x69706d61U
#define BOX_ipro 0x6970726fU
#define BOX_iprp 0x69707270U
#define BOX_iref 0x69726566U
#define BOX_ispe 0x69737065U
#define BOX_jP   0x6a502020U
#define BOX_jp2c 0x6a703263U
#define BOX_mdat 0x6d646174U
#define BOX_mdhd 0x6d646864U
#define BOX_mvhd 0x6d766864U
#define BOX_name 0x6e616d65U
#define BOX_pitm 0x7069746dU
#define BOX_stsd 0x73747364U
#define BOX_tkhd 0x746b6864U
#define BOX_uuid 0x75756964U
#define BOX_wide 0x77696465U
#define BOX_xml  0x786d6c20U

#define BOX_blank 0x2d2d2d2dU // "----"
#define BOX_cpil 0x6370696cU
#define BOX_gnre 0x676e7265U
#define BOX_tmpo 0x746d706fU
#define BOX_a9ART 0xa9415254U
#define BOX_a9cmt 0xa9636d74U
#define BOX_a9nam 0xa96e616dU
#define BOX_a9too 0xa9746f6fU

// JP2:
#define BOX_cdef 0x63646566U
#define BOX_colr 0x636f6c72U
#define BOX_jp2h 0x6a703268U
#define BOX_ihdr 0x69686472U
#define BOX_res  0x72657320U
#define BOX_resc 0x72657363U
#define BOX_resd 0x72657364U
#define BOX_uinf 0x75696e66U
#define BOX_ulst 0x756c7374U
#define BOX_url  0x75726c20U
// JPX:
#define BOX_jpch 0x6a706368U
#define BOX_jplh 0x6a706c68U
#define BOX_cgrp 0x63677270U
#define BOX_ftbl 0x6674626cU
#define BOX_comp 0x636f6d70U
#define BOX_asoc 0x61736f63U
#define BOX_drep 0x64726570U
#define BOX_dtbl 0x6474626cU
#define BOX_flst 0x666c7374U
#define BOX_lbl  0x6c626c20U
#define BOX_nlst 0x6e6c7374U
#define BOX_rreq 0x72726571U
//  JPM:
#define BOX_page 0x70616765U
#define BOX_lobj 0x6c6f626aU
#define BOX_objc 0x6f626a63U
#define BOX_sdat 0x73646174U
#define BOX_mhdr 0x6d686472U
#define BOX_lhdr 0x6c686472U
#define BOX_ohdr 0x6f686472U
#define BOX_pagt 0x70616774U
#define BOX_pcol 0x70636f6cU
#define BOX_phdr 0x70686472U
#define BOX_scal 0x7363616cU
//  BMFF, QuickTime, MP4, ...:
#define BOX_cinf 0x63696e66U
#define BOX_clip 0x636c6970U
#define BOX_dinf 0x64696e66U
#define BOX_dref 0x64726566U
#define BOX_edts 0x65647473U
//#define BOX_extr 0x65787472U // Irregular format?
#define BOX_fdsa 0x66647361U
#define BOX_fiin 0x6669696eU
#define BOX_free 0x66726565U
#define BOX_hdlr 0x68646c72U
#define BOX_hinf 0x68696e66U
#define BOX_hmhd 0x686d6864U
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
#define BOX_nmhd 0x6e6d6864U
#define BOX_paen 0x7061656eU
#define BOX_rinf 0x72696e66U
#define BOX_schi 0x73636869U
#define BOX_sinf 0x73696e66U
#define BOX_skip 0x736b6970U
#define BOX_smhd 0x736d6864U
#define BOX_stbl 0x7374626cU
#define BOX_stco 0x7374636fU
#define BOX_strd 0x73747264U
#define BOX_strk 0x7374726bU
#define BOX_stsc 0x73747363U
#define BOX_stss 0x73747373U
#define BOX_stsz 0x7374737aU
#define BOX_stts 0x73747473U
#define BOX_stz2 0x73747a32U
#define BOX_traf 0x74726166U
#define BOX_trak 0x7472616bU
#define BOX_tref 0x74726566U
#define BOX_udta 0x75647461U
#define BOX_vmhd 0x766d6864U
// JPEG XT
#define BOX_LCHK 0x4c43484bU
#define BOX_RESI 0x52455349U
#define BOX_SPEC 0x53504543U

// Called for each primary or compatible brand.
// Brand-specific setup can be done here.
static void apply_brand(deark *c, lctx *d, de_uint32 brand_id)
{
	switch(brand_id) {
	case BRAND_jp2:
		d->is_jp2_jpx_jpm = 1;
		break;
	case BRAND_jpx:
		d->is_jpx = 1;
		d->is_jp2_jpx_jpm = 1;
		break;
	case BRAND_jpm:
		d->is_jpm = 1;
		d->is_jp2_jpx_jpm = 1;
		break;
	case BRAND_mjp2:
	case BRAND_mj2s:
		d->is_bmff = 1;
		d->is_mj2 = 1;
		break;
	case BRAND_isom:
	case BRAND_mp41:
	case BRAND_mp42:
	case BRAND_M4A:
	case BRAND_qt:
		d->is_bmff = 1;
		break;
	case BRAND_mif1:
	case BRAND_heic:
		d->is_heif = 1;
		break;
	}
}

// JPEG 2000 signature box (presumably)
static void do_box_jP(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_uint32 n;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->level!=0) return;
	if(curbox->payload_len<4) return;
	n = (de_uint32)dbuf_getui32be(bctx->f, curbox->payload_pos);
	if(n==0x0d0a870a) {
		de_dbg(c, "found JPEG 2000 signature");
	}
}

static void do_box_ftyp(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 i;
	de_int64 mver;
	de_int64 num_compat_brands;
	struct de_fourcc brand4cc;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->payload_len<4) goto done;
	dbuf_read_fourcc(bctx->f, curbox->payload_pos, &brand4cc, 4, 0x0);
	d->major_brand = brand4cc.id;
	de_dbg(c, "major brand: '%s'", brand4cc.id_dbgstr);
	if(curbox->level==0)
		apply_brand(c, d, d->major_brand);

	if(curbox->payload_len<8) goto done;
	mver = dbuf_getui32be(bctx->f, curbox->payload_pos+4);
	de_dbg(c, "minor version: %u", (unsigned int)mver);

	if(curbox->payload_len<12) goto done;
	num_compat_brands = (curbox->payload_len - 8)/4;

	for(i=0; i<num_compat_brands; i++) {
		dbuf_read_fourcc(bctx->f, curbox->payload_pos + 8 + i*4, &brand4cc, 4, 0x0);
		if(brand4cc.id==0) continue; // Placeholder. Ignore.
		de_dbg(c, "compatible brand: '%s'", brand4cc.id_dbgstr);
		if(curbox->level==0)
			apply_brand(c, d, brand4cc.id);
	}

done:
	;
}

static void do_read_version_and_flags(deark *c, lctx *d, struct de_boxesctx *bctx,
	de_byte *version, de_uint32 *flags, int dbgflag)
{
	de_byte version1;
	de_uint32 flags1;
	de_uint32 n;
	struct de_boxdata *curbox = bctx->curbox;

	n = (de_uint32)dbuf_getui32be(bctx->f, curbox->payload_pos);
	version1 = (de_byte)(n>>24);
	flags1 = n&0x00ffffff;
	if(dbgflag) {
		de_dbg(c, "version=%d, flags=0x%06x", (int)version1, (unsigned int)flags1);
	}
	if(version) *version = version1;
	if(flags) *flags = flags1;
}

// For any box whose entire contents are a UTF-8 text string.
static void do_box_justtext(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;
	de_ucstring *s = NULL;
	const char *name;

	name = curbox->box_name ? curbox->box_name : "value";
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(bctx->f, curbox->payload_pos, curbox->payload_len,
		DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static const char *get_ilst_type_name(unsigned int ns, unsigned int wkt)
{
	const char *name = NULL;

	if(ns!=0) goto done;

	switch(wkt) {
	case 0: name="binary"; break;
	case 1: name="UTF-8"; break;
	case 2: name="UTF-16"; break;
	case 3: name="S/JIS"; break;
	case 4: name="UTF-8 sort key"; break;
	case 5: name="UTF-16 sort key"; break;
	case 13: name="JPEG"; break;
	case 14: name="PNG"; break;
	case 21: name="signed int"; break;
	case 22: name="unsigned int"; break;
	case 23: name="float32"; break;
	case 24: name="float64"; break;
	case 27: name="BMP"; break;
	case 28: name="metadata atom"; break;
	}
done:
	if(!name) name="?";
	return name;
}

static void do_box_data(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	unsigned int type_field, type_namespace, wkt;
	unsigned int cntry, lang;
	de_int64 vlen;
	struct de_boxdata *curbox = bctx->curbox;
	struct de_boxdata *par;
	struct de_boxdata *gpar;
	de_int64 pos = curbox->payload_pos;
	de_ucstring *s = NULL;

	par = curbox->parent;
	if(!par) goto done;
	gpar = par->parent;
	if(!gpar) goto done;
	if(gpar->boxtype != BOX_ilst) goto done;

	if(curbox->payload_len<8) goto done;
	type_field = (unsigned int)dbuf_getui32be_p(bctx->f, &pos);
	type_namespace = type_field>>24;
	wkt = (type_field & 0x00ffffff); // well-known type (if namespace==0)
	de_dbg(c, "type: %u, %u (%s)", type_namespace, wkt,
		get_ilst_type_name(type_namespace, wkt));

	cntry = (unsigned int)dbuf_getui16be_p(bctx->f, &pos);
	lang = (unsigned int)dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "locale: %u, %u", cntry, lang);

	if(type_namespace!=0) goto done;
	vlen = curbox->payload_pos + curbox->payload_len - pos;

	if(wkt==1 || wkt==4) { // UTF-8
		s = ucstring_create(c);
		dbuf_read_to_ucstring_n(bctx->f, pos, vlen,
			DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
		de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));
	}
	else if(wkt==21 && vlen==1) { // 1-byte signed int
		int n;
		n = (int)(signed char)dbuf_getbyte(bctx->f, pos);
		de_dbg(c, "value: %d", n);
	}
	else if(wkt==21 && vlen==2) { // 2-byte BE signed int
		int n;
		n = (int)dbuf_geti16be(bctx->f, pos);
		de_dbg(c, "value: %d", n);
	}
	else if(wkt==0) {
		de_dbg_hexdump(c, bctx->f, pos, vlen, 256, "value", 0x1);
	}
	// TODO: There are lots more types

done:
	ucstring_destroy(s);
}

static void do_box_hdlr(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_ucstring *s = NULL;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	struct de_fourcc tmp4cc;

	if(curbox->payload_len<4) goto done;
	do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
	pos += 4;
	if(curbox->payload_len<24) goto done;
	pos += 4; // "Predefined"

	dbuf_read_fourcc(bctx->f, pos, &tmp4cc, 4, 0x0);
	de_dbg(c, "handler type: '%s'", tmp4cc.id_dbgstr);
	pos += 4;

	pos += 12; // reserved
	if(curbox->payload_len<25) goto done;
	if(dbuf_getbyte(bctx->f, pos) == 0x00) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(bctx->f, pos, curbox->payload_pos + curbox->payload_len - pos,
		DE_DBG_MAX_STRLEN, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_UTF8);
	de_dbg(c, "metadata type name: \"%s\"", ucstring_getpsz_d(s));

done:
	ucstring_destroy(s);
}

static void do_box_tkhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	double w, h;
	de_int64 n;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->payload_len<4) return;

	pos = curbox->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(curbox->payload_len<96) return;
	}
	else {
		if(curbox->payload_len<84) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	n = dbuf_getui32be_p(bctx->f, &pos);
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

	n = dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "volume: %.3f", ((double)n)/256.0);

	pos += 2; // reserved
	pos += 4*9; // matrix

	w = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	h = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4;
	de_dbg(c, "dimensions: %.1f"DE_CHAR_TIMES"%.1f", w, h);
}

static void do_box_vmhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	size_t k;
	unsigned int clr[3];
	unsigned int graphicsmode;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;

	if(curbox->payload_len<12) return;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0x1) return;

	graphicsmode = (unsigned int)dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "graphicsmode: %u", graphicsmode);

	for(k=0; k<3; k++) {
		clr[k] = (unsigned int)dbuf_getui16be_p(bctx->f, &pos);
	}
	de_dbg(c, "opcolor: (%d,%d,%d)", (int)clr[0], (int)clr[1], (int)clr[2]);
}

static void do_box_smhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	unsigned int n;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;

	if(curbox->payload_len<8) return;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0x0) return;

	n = (unsigned int)dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "balance: %u", n);
}

static void do_box_mvhd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 n;
	de_int64 timescale;
	double nd;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->payload_len<4) return;

	pos = curbox->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(curbox->payload_len<112) return;
	}
	else {
		if(curbox->payload_len<100) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	timescale = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "timescale: %d time units per second", (int)timescale);

	// duration
	if(version==1) {
		n = dbuf_geti64be(bctx->f, pos);
		pos += 8;
	}
	else {
		n = dbuf_getui32be_p(bctx->f, &pos);
	}
	if(timescale>0)
		nd = (double)n / (double)timescale;
	else
		nd = 0.0;
	de_dbg(c, "duration: %d time units (%.2f seconds)", (int)n, nd);

	nd = dbuf_fmtutil_read_fixed_16_16(bctx->f, pos);
	pos += 4; // rate
	de_dbg(c, "rate: %.3f", nd);

	n = dbuf_getui16be_p(bctx->f, &pos);
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
	struct de_boxdata *curbox = bctx->curbox;

	// TODO: Share code with do_box_mvhd()?
	if(curbox->payload_len<4) return;

	pos = curbox->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos+=4;

	if(version==1) {
		if(curbox->payload_len<36) return;
	}
	else {
		if(curbox->payload_len<24) return;
	}

	// creation time, mod time
	if(version==1)
		pos += 8 + 8;
	else
		pos += 4 + 4;

	timescale = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "timescale: %d time units per second", (int)timescale);

	// duration
	if(version==1) {
		n = dbuf_geti64be(bctx->f, pos);
		pos += 8;
	}
	else {
		n = dbuf_getui32be_p(bctx->f, &pos);
	}
	if(timescale>0)
		nd = (double)n / (double)timescale;
	else
		nd = 0.0;
	de_dbg(c, "duration: %d time units (%.2f seconds)", (int)n, nd);
}

static void do_box_stsc(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 e_count, e_to_print;
	de_int64 bytesleft;
	de_int64 k;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0) return;

	e_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "entry count: %u", (unsigned int)e_count);

	bytesleft = curbox->payload_pos + curbox->payload_len - pos;
	if(bytesleft/12 < e_count) return;

	e_to_print = e_count;
	if(e_to_print > d->max_entries_to_print) {
		e_to_print = d->max_entries_to_print;
	}

	for(k=0; k<e_to_print; k++) {
		de_int64 first_chunk, spc, sdi;
		first_chunk = dbuf_getui32be_p(bctx->f, &pos);
		spc = dbuf_getui32be_p(bctx->f, &pos);
		sdi = dbuf_getui32be_p(bctx->f, &pos);
		de_dbg(c, "entry[%d]: first chunk=%d, samples/chunk=%d, descr. index=%d",
			(int)k, (int)first_chunk, (int)spc, (int)sdi);
	}
	if(e_to_print < e_count) {
		de_dbg(c, "[%d more entry(s) omitted, starting at %"INT64_FMT"]",
			(int)(e_count-e_to_print), pos);
	}
}

static void do_box_stsd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	de_int64 pos;
	de_int64 num_entries;
	de_int64 entry_size;
	struct de_fourcc fmt4cc;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->payload_len<8) return;

	pos = curbox->payload_pos;
	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0) return;

	num_entries = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "number of sample description entries: %d", (int)num_entries);

	while(1) {
		if(pos + 16 >= curbox->payload_pos + curbox->payload_len) break;
		entry_size = dbuf_getui32be(bctx->f, pos);
		de_dbg(c, "sample description entry at %d, len=%d", (int)pos, (int)entry_size);
		if(entry_size<16) break;

		de_dbg_indent(c, 1);
		dbuf_read_fourcc(bctx->f, pos+4, &fmt4cc, 4, 0x0);
		de_dbg(c, "data format: '%s'", fmt4cc.id_dbgstr);
		de_dbg_indent(c, -1);

		pos += entry_size;
	}
}

// Decode a table of (4- or 8-byte) integers.
// Limit to d->max_entries_to_print.
static void do_simple_int_table(deark *c, lctx *d, struct de_boxesctx *bctx,
	de_int64 pos1, de_int64 e_count, de_int64 e_size,
	const char *s1, const char *s2)
{
	de_int64 bytesleft;
	de_int64 e_to_print;
	de_int64 k;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = pos1;

	if(e_count<=0) return;
	bytesleft = curbox->payload_pos + curbox->payload_len - pos;
	if(bytesleft < e_size*e_count) return;

	e_to_print = e_count;
	if(e_to_print > d->max_entries_to_print) {
		e_to_print = d->max_entries_to_print;
	}

	for(k=0; k<e_to_print; k++) {
		de_int64 n;

		if(e_size==8) {
			n = dbuf_geti64be(bctx->f, pos); pos += 8;
		}
		else {
			n = dbuf_getui32be_p(bctx->f, &pos);
		}

		de_dbg(c, "%s[%"INT64_FMT"]: %s=%"INT64_FMT, s1, k, s2, n);
	}
	if(e_to_print < e_count) {
		de_dbg(c, "[%"INT64_FMT" more %s(s) omitted, starting at %"INT64_FMT"]",
			e_count-e_to_print, s1, pos);
	}
}

static void do_box_stsz(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 s_size, s_count;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0) return;

	s_size = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "sample size: %u", (unsigned int)s_size);
	s_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "sample count: %u", (unsigned int)s_count);

	if(s_size!=0) goto done;

	do_simple_int_table(c, d, bctx, pos, s_count, 4, "sample", "entry size");

done:
	;
}

// stco and co64
static void do_box_stco(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 e_count;
	de_int64 e_size;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0) return;

	e_size = (bctx->curbox->boxtype == BOX_co64) ? 8 : 4;
	e_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "entry count: %u", (unsigned int)e_count);

	do_simple_int_table(c, d, bctx, pos, e_count, e_size, "entry", "chunk offset");
}

static void do_box_stss(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 e_count;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0) return;

	e_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "entry count: %u", (unsigned int)e_count);

	do_simple_int_table(c, d, bctx, pos, e_count, 4, "entry", "sample number");
}

static void do_box_stts(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 e_count, e_to_print;
	de_int64 bytesleft;
	de_int64 k;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version!=0 || flags!=0) return;

	e_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "entry count: %u", (unsigned int)e_count);

	bytesleft = curbox->payload_pos + curbox->payload_len - pos;
	if(bytesleft/8 < e_count) return;

	e_to_print = e_count;
	if(e_to_print > d->max_entries_to_print) {
		e_to_print = d->max_entries_to_print;
	}

	for(k=0; k<e_to_print; k++) {
		de_int64 s_count, s_delta;
		s_count = dbuf_getui32be_p(bctx->f, &pos);
		s_delta = dbuf_getui32be_p(bctx->f, &pos);
		de_dbg(c, "entry[%d]: sample count=%d, delta=%d", (int)k,
			(int)s_count, (int)s_delta);
	}
	if(e_to_print < e_count) {
		de_dbg(c, "[%d more entry(s) omitted, starting at %"INT64_FMT"]",
			(int)(e_count-e_to_print), pos);
	}
}

static void do_box_ctts(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte version;
	de_uint32 flags;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 e_count, e_to_print;
	de_int64 bytesleft;
	de_int64 k;

	do_read_version_and_flags(c, d, bctx, &version, &flags, 1);
	pos += 4;
	if(version>1 || flags!=0) return;

	e_count = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg(c, "entry count: %u", (unsigned int)e_count);

	bytesleft = curbox->payload_pos + curbox->payload_len - pos;
	if(bytesleft < e_count*8) return;

	e_to_print = e_count;
	if(e_to_print > d->max_entries_to_print) {
		e_to_print = d->max_entries_to_print;
	}

	for(k=0; k<e_to_print; k++) {
		de_int64 s_count, s_offset;
		s_count = dbuf_getui32be_p(bctx->f, &pos);
		if(version==0) {
			s_offset = dbuf_getui32be_p(bctx->f, &pos);
		}
		else {
			s_offset = dbuf_geti32be(bctx->f, pos); pos += 4;
		}
		de_dbg(c, "entry[%d]: sample count=%"INT64_FMT", offset=%"INT64_FMT,
			(int)k, s_count, s_offset);
	}
	if(e_to_print < e_count) {
		de_dbg(c, "[%d more entry(s) omitted, starting at %"INT64_FMT"]",
			(int)(e_count-e_to_print), pos);
	}
}

static void do_box_meta(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;

	do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
	curbox->extra_bytes_before_children = 4;
}

static void do_box_jp2c(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;

	de_dbg(c, "JPEG 2000 codestream at %d, len=%d",
		(int)curbox->payload_pos, (int)curbox->payload_len);
	dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len,
		"j2c", NULL, 0);
}

static void format_jp2_res(char *buf, size_t buflen,
	de_int64 num, de_int64 denom, int exponent)
{
	// TODO: Format this better
	de_snprintf(buf, buflen, "(%d/%d)"DE_CHAR_TIMES"10^%d points/meter",
		(int)num, (int)denom, exponent);
}

static void do_box_resc_resd(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 vn, vd, hn, hd;
	int ve, he;
	struct de_boxdata *curbox = bctx->curbox;
	const char *name;
	de_int64 pos = curbox->payload_pos;
	char res_buf[160];

	if(curbox->boxtype==BOX_resc)
		name = "capture";
	else
		name = "display";

	if(curbox->payload_len<10) return;
	vn = dbuf_getui16be_p(bctx->f, &pos);
	vd = dbuf_getui16be_p(bctx->f, &pos);
	hn = dbuf_getui16be_p(bctx->f, &pos);
	hd = dbuf_getui16be_p(bctx->f, &pos);
	ve = (int)(signed char)dbuf_getbyte_p(bctx->f, &pos);
	he = (int)(signed char)dbuf_getbyte_p(bctx->f, &pos);
	format_jp2_res(res_buf, sizeof(res_buf), vn, vd, ve);
	de_dbg(c, "vert. %s grid res.: %s", name, res_buf);
	format_jp2_res(res_buf, sizeof(res_buf), hn, hd, he);
	de_dbg(c, "horz. %s grid res.: %s", name, res_buf);
}

static const char *get_jpeg2000_cmpr_name(deark *c, lctx *d, de_byte ct)
{
	const char *name = NULL;

	if(ct==7) { name="JPEG 2000"; goto done; }
	if(d->is_jpx) {
		switch(ct) {
		case 0: name="uncompressed"; break;
		case 1: name="MH"; break;
		case 2: name="MR"; break;
		case 3: name="MMR"; break;
		case 4: name="JBIG bi-level"; break;
		case 5: name="JPEG"; break;
		case 6: name="JPEG-LS"; break;
		case 8: name="JBIG2"; break;
		case 9: name="JBIG"; break;
		}
	}
	// TODO: JPM
done:
	if(!name) name="?";
	return name;
}

static void do_box_ihdr(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 w, h, n;
	de_byte b;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	char tmps[80];

	if(curbox->payload_len<14) return;
	h = dbuf_getui32be_p(bctx->f, &pos);
	w = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg_dimensions(c, w, h);

	n = dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "number of components: %d", (int)n);

	b = dbuf_getbyte_p(bctx->f, &pos);
	if(b==255) {
		de_strlcpy(tmps, "various", sizeof(tmps));
	}
	else {
		de_snprintf(tmps, sizeof(tmps), "%u bits/comp., %ssigned",
			(unsigned int)(1+(b&0x7f)), (b&0x80)?"":"un");
	}
	de_dbg(c, "bits-per-component code: %u (%s)", (unsigned int)b, tmps);

	b = dbuf_getbyte_p(bctx->f, &pos);
	de_dbg(c, "compression type: %u (%s)", (unsigned int)b,
		get_jpeg2000_cmpr_name(c, d, b));

	b = dbuf_getbyte_p(bctx->f, &pos);
	de_dbg(c, "colorspace-is-unknown flag: %d", (int)b);
	b = dbuf_getbyte_p(bctx->f, &pos);
	de_dbg(c, "has-IPR: %d", (int)b);
}

static const char *get_channel_type_name(de_int64 t)
{
	const char *name;
	switch(t) {
	case 0: name = "colour image data for associated color"; break;
	case 1: name = "opacity"; break;
	case 2: name = "premultiplied opacity"; break;
	case 65535: name = "not specified"; break;
	default: name = "?";
	}
	return name;
}

static void do_box_cdef(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 ndescs;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 k;

	ndescs = dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "number of channel descriptions: %d", (int)ndescs);

	for(k=0; k<ndescs; k++) {
		de_int64 idx, typ, asoc;

		if(pos+6 > curbox->payload_pos + curbox->payload_len) break;
		de_dbg(c, "channel description[%d] at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		idx = dbuf_getui16be_p(bctx->f, &pos);
		de_dbg(c, "channel index: %d", (int)idx);
		typ = dbuf_getui16be_p(bctx->f, &pos);
		de_dbg(c, "channel type: %d (%s)", (int)typ, get_channel_type_name(typ));
		asoc = dbuf_getui16be_p(bctx->f, &pos);
		de_dbg(c, "index of associated color: %d", (int)asoc);
		de_dbg_indent(c, -1);
	}
}

static void do_box_colr(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_byte meth;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	const char *s;

	if(curbox->payload_len<3) goto done;
	meth = dbuf_getbyte_p(bctx->f, &pos);
	switch(meth) {
	case 1: s="enumerated"; break;
	case 2: s="ICC profile (restricted)"; break;
	case 3: s="ICC profile (any)"; break; // JPX only
	case 4: s="vendor"; break; // JPX only
	default: s="?";
	}
	de_dbg(c, "specification method: %d (%s)", (int)meth, s);

	pos++; // PREC
	pos++; // APPROX

	if(meth==1) {
		unsigned int enumcs;
		if(curbox->payload_len<7) goto done;
		enumcs = (unsigned int)dbuf_getui32be_p(bctx->f, &pos);
		switch(enumcs) {
			// TODO: There are lots more valid values for JPX.
		case 16: s="sRGB"; break;
		case 17: s="sRGB-like grayscale"; break;
		case 18: s="sYCC"; break;
		default: s="?";
		}
		de_dbg(c, "enumerated colourspace: %u (%s)", enumcs, s);
	}
	else if(meth==2 || meth==3) {
		dbuf_create_file_from_slice(bctx->f,
			curbox->payload_pos+3, curbox->payload_len-3,
			"icc", NULL, DE_CREATEFLAG_IS_AUX);
	}

done:
	;
}

static void do_box_ulst(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 nuuids;
	de_int64 k;
	de_byte ubuf[16];
	char uuid_string[50];

	nuuids = dbuf_getui16be_p(bctx->f, &pos);
	de_dbg(c, "number of UUIDs: %d", (int)nuuids);

	for(k=0; k<nuuids; k++) {
		if(pos+16 > curbox->payload_pos + curbox->payload_len) break;
		dbuf_read(bctx->f, ubuf, pos, 16);
		de_fmtutil_render_uuid(c, ubuf, uuid_string, sizeof(uuid_string));
		de_dbg(c, "UUID[%d]: {%s}", (int)k, uuid_string);
		pos += 16;
	}
}

static void do_box_url(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_ucstring *s = NULL;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;

	do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
	pos += 4;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(bctx->f,
		pos, curbox->payload_pos + curbox->payload_len - pos, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_UTF8);
	de_dbg(c, "URL: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_box_dtbl(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 ndr;
	struct de_boxdata *curbox = bctx->curbox;

	ndr = dbuf_getui16be(bctx->f, curbox->payload_pos);
	de_dbg(c, "number of data references: %d", (int)ndr);

	curbox->num_children_is_known = 1;
	curbox->num_children = ndr;
	curbox->extra_bytes_before_children = 2;
}

static void do_box_iinf(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	de_int64 nitems;
	de_byte version;
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;

	do_read_version_and_flags(c, d, bctx, &version, NULL, 1);
	pos += 4;

	if(version==0) {
		nitems = dbuf_getui16be_p(bctx->f, &pos);
	}
	else {
		nitems = dbuf_getui32be_p(bctx->f, &pos);
	}
	de_dbg(c, "number of items: %d", (int)nitems);

	curbox->num_children_is_known = 1;
	curbox->num_children = nitems;
	curbox->extra_bytes_before_children = pos - curbox->payload_pos;
}

static void do_box_ispe(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;
	de_int64 pos = curbox->payload_pos;
	de_int64 w, h;

	if(curbox->payload_len<12) return;
	do_read_version_and_flags(c, d, bctx, NULL, NULL, 1);
	pos += 4;
	w = dbuf_getui32be_p(bctx->f, &pos);
	h = dbuf_getui32be_p(bctx->f, &pos);
	de_dbg_dimensions(c, w, h);
}

static void do_box_xml(deark *c, lctx *d, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;

	// TODO: Detect the specific XML format, and use it to choose a better
	// filename.
	de_dbg(c, "XML data at %d, len=%d", (int)curbox->payload_pos, (int)curbox->payload_len);
	dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len,
		"xml", NULL, DE_CREATEFLAG_IS_AUX);
}

// The first line that matches will be used, so items related to more-specific
// formats/brands should be listed first.
static const struct box_type_info box_type_info_arr[] = {
	{BOX_ftyp, 0x00000000, 0x00000002, "file type", do_box_ftyp},
	{BOX_jP  , 0x00010008, 0x00000002, "JPEG 2000 signature", do_box_jP},
	{BOX_mdat, 0x00000008, 0x00000001, "media data", NULL},
	{BOX_mdat, 0x00080001, 0x00000000, "media data", NULL},
	{BOX_cinf, 0x00000001, 0x00000001, "complete track information", NULL},
	{BOX_clip, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_co64, 0x00000001, 0x00000000, "chunk offset", do_box_stco},
	{BOX_dinf, 0x00080001, 0x00000001, "data information", NULL},
	{BOX_dref, 0x00000001, 0x00000000, "data reference", NULL},
	{BOX_edts, 0x00000001, 0x00000001, "edit", NULL},
	{BOX_elst, 0x00000001, 0x00000000, "edit list", NULL},
	{BOX_fdsa, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_fiin, 0x00000001, 0x00000001, "FD item information", NULL},
	{BOX_free, 0x00090001, 0x00000000, "free space", NULL},
	{BOX_hdlr, 0x00080001, 0x00000000, "handler reference", do_box_hdlr},
	{BOX_hinf, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_hmhd, 0x00000001, 0x00000000, "hint media header", NULL},
	{BOX_hnti, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_ilst, 0x00000001, 0x00000001, "metadata item list", NULL},
	{BOX_matt, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_mdhd, 0x00000001, 0x00000000, "media header", do_box_mdhd},
	{BOX_mdia, 0x00000001, 0x00000001, "media", NULL},
	{BOX_meco, 0x00000001, 0x00000001, "additional metadata container", NULL},
	{BOX_meta, 0x00080001, 0x00000001, "metadata", do_box_meta},
	{BOX_minf, 0x00000001, 0x00000001, "media information", NULL},
	{BOX_mfra, 0x00000001, 0x00000001, "movie fragment random access", NULL},
	{BOX_moof, 0x00000001, 0x00000001, "movie fragment", NULL},
	{BOX_moov, 0x00000001, 0x00000001, "movie (metadata container)", NULL},
	{BOX_mvex, 0x00000001, 0x00000001, "movie extends", NULL},
	{BOX_mvhd, 0x00000001, 0x00000000, "movie header", do_box_mvhd},
	{BOX_nmhd, 0x00000001, 0x00000000, "null media header", NULL},
	{BOX_paen, 0x00000001, 0x00000001, NULL, NULL},
	{BOX_rinf, 0x00000001, 0x00000001, "restricted scheme information", NULL},
	{BOX_schi, 0x00000001, 0x00000001, "scheme information", NULL},
	{BOX_sinf, 0x00000001, 0x00000001, "protection scheme information", NULL},
	{BOX_skip, 0x00080001, 0x00000000, "user-data", NULL},
	{BOX_smhd, 0x00000001, 0x00000000, "sound media header", do_box_smhd},
	{BOX_stbl, 0x00000001, 0x00000001, "sample table", NULL},
	{BOX_stco, 0x00000001, 0x00000000, "chunk offset", do_box_stco},
	{BOX_strd, 0x00000001, 0x00000001, "sub track definition", NULL},
	{BOX_strk, 0x00000001, 0x00000001, "sub track", NULL},
	{BOX_stsc, 0x00000001, 0x00000000, "sample to chunk", do_box_stsc},
	{BOX_stsd, 0x00000001, 0x00000000, "sample description", do_box_stsd},
	{BOX_stss, 0x00000001, 0x00000000, "sync sample", do_box_stss},
	{BOX_stsz, 0x00000001, 0x00000000, "sample sizes", do_box_stsz},
	{BOX_stts, 0x00000001, 0x00000000, "decoding time to sample", do_box_stts},
	{BOX_ctts, 0x00000001, 0x00000000, "composition time to sample", do_box_ctts},
	{BOX_stz2, 0x00000001, 0x00000000, "compact sample size", NULL},
	{BOX_tkhd, 0x00000001, 0x00000000, "track header", do_box_tkhd},
	{BOX_traf, 0x00000001, 0x00000001, "track fragment", NULL},
	{BOX_trak, 0x00000001, 0x00000001, "track", NULL},
	{BOX_tref, 0x00000001, 0x00000001, "track reference", NULL},
	{BOX_udta, 0x00000001, 0x00000001, "user data", NULL},
	{BOX_vmhd, 0x00000001, 0x00000000, "video media header", do_box_vmhd},
	{BOX_wide, 0x00000001, 0x00000000, "reserved space", NULL},
	{BOX_asoc, 0x00010000, 0x00000001, "association", NULL},
	{BOX_cgrp, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_cdef, 0x00010000, 0x00000000, "channel definition", do_box_cdef},
	{BOX_colr, 0x00010000, 0x00000000, "colour specification", do_box_colr},
	{BOX_comp, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_drep, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_dtbl, 0x00010000, 0x00000001, "data reference", do_box_dtbl},
	{BOX_flst, 0x00010000, 0x00000000, "fragment list", NULL},
	{BOX_ftbl, 0x00010000, 0x00000001, "fragment table", NULL},
	{BOX_ihdr, 0x00010000, 0x00000000, "image header", do_box_ihdr},
	{BOX_jp2c, 0x00010008, 0x00000000, "contiguous codestream", do_box_jp2c},
	{BOX_jp2h, 0x00010000, 0x00000001, "JP2 header", NULL},
	{BOX_jpch, 0x00010000, 0x00000001, "codestream header", NULL},
	{BOX_jplh, 0x00010000, 0x00000001, "image header", NULL},
	{BOX_lhdr, 0x00010000, 0x00000000, "layout object header", NULL},
	{BOX_lbl , 0x00010000, 0x00000000, "label", do_box_justtext},
	{BOX_lobj, 0x00010000, 0x00000001, "layout object", NULL},
	{BOX_mhdr, 0x00010000, 0x00000000, "compound image header", NULL},
	{BOX_nlst, 0x00010000, 0x00000000, "number list", NULL},
	{BOX_objc, 0x00010000, 0x00000001, "object", NULL},
	{BOX_ohdr, 0x00010000, 0x00000000, "object header", NULL},
	{BOX_page, 0x00010000, 0x00000001, "page", NULL},
	{BOX_pagt, 0x00010000, 0x00000000, "page table", NULL},
	{BOX_pcol, 0x00010000, 0x00000001, "page collection", NULL},
	{BOX_phdr, 0x00010000, 0x00000000, "page header", NULL},
	{BOX_res , 0x00010000, 0x00000001, "resolution", NULL},
	{BOX_resc, 0x00010000, 0x00000000, "capture resolution", do_box_resc_resd},
	{BOX_resd, 0x00010000, 0x00000000, "default display resolution", do_box_resc_resd},
	{BOX_rreq, 0x00010000, 0x00000000, "reader requirements", NULL},
	{BOX_scal, 0x00010000, 0x00000000, "object scale", NULL},
	{BOX_sdat, 0x00010000, 0x00000001, NULL, NULL},
	{BOX_uinf, 0x00010000, 0x00000001, "UUID info", NULL},
	{BOX_ulst, 0x00010000, 0x00000000, "UUID list", do_box_ulst},
	{BOX_url , 0x00010000, 0x00000000, "URL", do_box_url},
	{BOX_xml , 0x00010008, 0x00000000, "XML", do_box_xml},
	{BOX_LCHK, 0x00040000, 0x00000000, "checksum", NULL},
	{BOX_RESI, 0x00040000, 0x00000000, "residual codestream", NULL},
	{BOX_SPEC, 0x00040000, 0x00000001, NULL, NULL},
	{BOX_auxC, 0x00080000, 0x00000000, "auxiliary type property", NULL},
	{BOX_grpl, 0x00080000, 0x00000000, "groups list", NULL},
	{BOX_idat, 0x00080000, 0x00000000, "item data", NULL},
	{BOX_iinf, 0x00080000, 0x00000001, "item info", do_box_iinf},
	{BOX_iloc, 0x00080000, 0x00000000, "item location", NULL},
	{BOX_infe, 0x00080000, 0x00000000, "item info entry", NULL},
	{BOX_ipco, 0x00080000, 0x00000001, "item property container", NULL},
	{BOX_ipma, 0x00080000, 0x00000000, "item property association", NULL},
	{BOX_ipro, 0x00080000, 0x00000000, "item protection", NULL},
	{BOX_iprp, 0x00080000, 0x00000001, "item properties", NULL},
	{BOX_iref, 0x00080000, 0x00000000, "item reference", NULL},
	{BOX_ispe, 0x00080000, 0x00000000, "image spatial extents", do_box_ispe},
	{BOX_hvcC, 0x00080000, 0x00000000, "HEVC configuration", NULL},
	{BOX_pitm, 0x00080000, 0x00000000, "primary item", NULL}
};

// TODO: These ilst (iTunes metadata?) boxes should probably go in the above
// list, but the logic for finding the right box will be complicated.
// Superboxes are not flagged in this list, because that determination
// is based on their location, not their type.
static const struct box_type_info ilst_box_type_info_arr[] = {
	{BOX_data,   0x01000000, 0x00000000, "value atom", do_box_data},
	{BOX_name,   0x01000000, 0x00000000, "name atom", NULL},
	{BOX_blank,  0x01000000, 0x00000000, "custom metadata item", NULL},
	{BOX_cpil,   0x01000000, 0x00000000, "compilation", NULL},
	{BOX_gnre,   0x01000000, 0x00000000, "genre (enumerated)", NULL},
	{BOX_tmpo,   0x01000000, 0x00000000, "tempo", NULL},
	{BOX_a9ART,  0x01000000, 0x00000000, "artist", NULL},
	{BOX_a9cmt,  0x01000000, 0x00000000, "comment", NULL},
	{BOX_a9nam,  0x01000000, 0x00000000, "name / title", NULL},
	{BOX_a9too,  0x01000000, 0x00000000, "encoder software", NULL}
};

static const struct box_type_info *find_box_type_info(deark *c, lctx *d,
	de_uint32 boxtype, int level)
{
	size_t k;
	de_uint32 mask = 0;

	if(d->is_bmff) mask |= 0x00000001;
	if(d->is_mj2) mask |= 0x000000008;
	if(d->is_jp2_jpx_jpm) mask |= 0x00010000;
	if(d->is_jpegxt) mask |= 0x00040000;
	if(d->is_heif) mask |= 0x00080000;

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

static const struct box_type_info *find_ilst_box_type_info(deark *c, lctx *d,
	de_uint32 boxtype)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(ilst_box_type_info_arr); k++) {
		if(ilst_box_type_info_arr[k].boxtype != boxtype) continue;
		return &ilst_box_type_info_arr[k];
	}
	return NULL;
}

static void my_box_identify_fn(deark *c, struct de_boxesctx *bctx)
{
	const struct box_type_info *bti;
	lctx *d = (lctx*)bctx->userdata;
	struct de_boxdata *curbox = bctx->curbox;
	struct de_boxdata *par = curbox->parent;
	struct de_boxdata *gpar = NULL;
	int is_ilst_child = 0;

	if(curbox->boxtype != BOX_uuid) {
		curbox->box_name = "?";
	}

	if(par) {
		gpar = par->parent;
	}

	if((par && (par->boxtype==BOX_ilst)) ||
		(gpar && (gpar->boxtype==BOX_ilst)) )
	{
		is_ilst_child = 1;
	}

	if(is_ilst_child) {
		bti = find_ilst_box_type_info(c, d, curbox->boxtype);
	}
	else {
		bti = find_box_type_info(c, d, curbox->boxtype, curbox->level);
	}

	if(bti) {
		// So that we don't have to run "find" again in my_box_handler(),
		// record it here.
		curbox->box_userdata = (void*)bti;

		if(bti->name) {
			curbox->box_name = bti->name;
		}
	}
	// TODO: Do we need special handling of 'data' boxes?
}

static int my_box_handler(deark *c, struct de_boxesctx *bctx)
{
	const struct box_type_info *bti;
	lctx *d = (lctx*)bctx->userdata;
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->is_uuid) {
		return de_fmtutil_default_box_handler(c, bctx);
	}

	bti = (const struct box_type_info *)curbox->box_userdata;

	if(bti && (bti->flags2 & 0x1)) {
		curbox->is_superbox = 1;
	}
	else if(d->is_bmff && curbox->parent && (curbox->parent->boxtype==BOX_ilst)) {
		curbox->is_superbox = 1;
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
	int skip_autodetect = 0;
	const char *s;
	de_byte buf[4];

	d = de_malloc(c, sizeof(lctx));
	bctx = de_malloc(c, sizeof(struct de_boxesctx));

	if(mparams && mparams->in_params.codes) {
		if(de_strchr(mparams->in_params.codes, 'T')) {
			d->is_jpegxt = 1;
			skip_autodetect = 1;
		}
		if(de_strchr(mparams->in_params.codes, 'X')) {
			d->is_jpx = 1;
			d->is_jp2_jpx_jpm = 1;
			skip_autodetect = 1;
		}
	}

	if(!skip_autodetect) {
		// Try to detect old QuickTime files that don't have an ftyp box.
		de_read(buf, 4, 4);
		if(!de_memcmp(buf, "mdat", 4) ||
			!de_memcmp(buf, "moov", 4))
		{
			d->is_bmff = 1;
		}
	}

	s = de_get_ext_option(c, "bmff:maxentries");
	if(s) {
		d->max_entries_to_print = de_atoi64(s);
	}
	else {
		d->max_entries_to_print = 32;
	}
	if(d->max_entries_to_print<0) {
		d->max_entries_to_print = 0;
	}

	bctx->userdata = (void*)d;
	bctx->f = c->infile;
	bctx->identify_box_fn = my_box_identify_fn;
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

static void de_help_bmff(deark *c)
{
	de_msg(c, "-opt bmff:maxentries=<n> : Number of sample table entries to print with -d");
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
	mi->help_fn = de_help_bmff;
}
