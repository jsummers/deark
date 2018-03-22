// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ICC Profile format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iccprofile);

struct tag_seen_type {
	de_int64 offset;
	de_int64 len;
};

typedef struct localctx_struct {
	unsigned int profile_ver_major;
	unsigned int profile_ver_minor;
	unsigned int profile_ver_bugfix;

	de_int64 num_tags;
	struct tag_seen_type *tags_seen;
} lctx;

typedef void (*datatype_decoder_fn_type)(deark *c, lctx *d, de_int64 pos, de_int64 len);

static void typedec_XYZ(deark *c, lctx *d, de_int64 pos, de_int64 len);
static void typedec_text(deark *c, lctx *d, de_int64 pos, de_int64 len);
static void typedec_desc(deark *c, lctx *d, de_int64 pos, de_int64 len);
static void typedec_mluc(deark *c, lctx *d, de_int64 pos, de_int64 len);

struct datatypeinfo {
	de_uint32 id;
	const char *name;
	datatype_decoder_fn_type dtdfn;
};
static const struct datatypeinfo datatypeinfo_arr[] = {
	{ 0x58595A20U, "XYZ", typedec_XYZ }, // XYZ
	{ 0x62666420U, "ucrbg", NULL }, // bfd
	{ 0x6368726DU, "chromaticity", NULL }, // chrm
	{ 0x636c726fU, "colorantOrder", NULL }, // clro
	{ 0x636C7274U, "colorantTable", NULL }, // clrt
	{ 0x63726469U, "crdInfo", NULL }, // crdi
	{ 0x64657673U, "deviceSettings", NULL }, // devs
	{ 0x6474696DU, "dateTime", NULL }, // dtim
	{ 0x63757276U, "curve", NULL }, // curv
	{ 0x64617461U, "data", NULL }, // data
	{ 0x64657363U, "textDescription", typedec_desc }, // desc
	{ 0x6D414220U, "lutAToB", NULL }, // mAB
	{ 0x6D424120U, "lutBToA", NULL }, // mBA
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x6D667431U, "lut8", NULL }, // mft1
	{ 0x6D667432U, "lut16", NULL }, // mft2
	{ 0x6D6C7563U, "multiLocalizedUnicode", typedec_mluc }, // mluc
	{ 0x6D706574U, "multiProcessElements", NULL }, // mpet
	{ 0x6E636C32U, "namedColor2", NULL }, // ncl2
	{ 0x6E636F6CU, "namedColor", NULL }, // ncol
	{ 0x70617261U, "parametricCurve", NULL }, // para
	{ 0x70736571U, "profileSequenceDesc", NULL }, // pseq
	{ 0x70736964U, "profileSequenceIdentifier", NULL }, // psid
	{ 0x72637332U, "responseCurveSet16", NULL }, // rcs2
	{ 0x73663332U, "s15Fixed16Array", NULL }, // sf32
	{ 0x7363726EU, "screening", NULL }, // scrn
	{ 0x73696720U, "signature", NULL }, // sig
	{ 0x74657874U, "text", typedec_text }, // text
	{ 0x75663332U, "u16Fixed16Array", NULL }, // uf32
	{ 0x75693038U, "uInt8Array", NULL }, // ui08
	{ 0x75693136U, "uInt16Array", NULL }, // ui16
	{ 0x75693332U, "uInt32Array", NULL }, // ui32
	{ 0x75693634U, "uInt64Array", NULL }, // ui64
	{ 0x76636774U, "Video Card Gamma Type", NULL }, // vcgt (Apple)
	{ 0x76696577U, "viewingConditions", NULL } // view
};

struct taginfo {
	de_uint32 id;
	const char *name;
	void *reserved;
};
static const struct taginfo taginfo_arr[] = {
	{ 0x41324230U, "AToB0", NULL }, // A2B0
	{ 0x41324231U, "AToB1", NULL }, // A2B1
	{ 0x41324232U, "AToB2", NULL }, // A2B2
	{ 0x42324130U, "BToA0", NULL }, // B2A0
	{ 0x42324131U, "BToA1", NULL }, // B2A1
	{ 0x42324132U, "BToA2", NULL }, // B2A2
	{ 0x42324430U, "BToD0", NULL }, // B2D0
	{ 0x42324431U, "BToD1", NULL }, // B2D1
	{ 0x42324432U, "BToD2", NULL }, // B2D2
	{ 0x42324433U, "BToD3", NULL }, // B2D3
	{ 0x44324230U, "DToB0", NULL }, // D2B0
	{ 0x44324231U, "DToB1", NULL }, // D2B1
	{ 0x44324232U, "DToB2", NULL }, // D2B2
	{ 0x44324233U, "DToB3", NULL }, // D2B3
	{ 0x62545243U, "blueTRC", NULL }, // bTRC
	{ 0x6258595AU, "blueColorant/blueMatrixColumn", NULL }, // bXYZ
	{ 0x62666420U, "ucrbg", NULL }, // bfd
	{ 0x626B7074U, "mediaBlackPoint", NULL }, // bkpt
	{ 0x63616C74U, "calibrationDateTime", NULL }, // calt
	{ 0x63686164U, "chromaticAdaptation", NULL }, // chad
	{ 0x6368726DU, "chromaticity", NULL }, // chrm
	{ 0x63696973U, "colorimetricIntentImageState", NULL }, // ciis
	{ 0x636C6F74U, "colorantTableOut", NULL }, // clot
	{ 0x636C726FU, "colorantOrder", NULL }, // clro
	{ 0x636C7274U, "colorantTable", NULL }, // clrt
	{ 0x63707274U, "copyright", NULL }, // cprt
	{ 0x63726469U, "crdInfo", NULL }, // crdi
	{ 0x64657363U, "profileDescription", NULL }, // desc
	{ 0x64657673U, "deviceSettings", NULL }, // devs
	{ 0x646D6464U, "deviceModelDesc", NULL }, // dmdd
	{ 0x646D6E64U, "deviceMfgDesc", NULL }, // dmnd
	{ 0x67616D74U, "gamut", NULL }, // gamt
	{ 0x67545243U, "greenTRC", NULL }, // gTRC
	{ 0x6758595AU, "greenColorant/greenMatrixColumn", NULL }, // gXYZ
	{ 0x6B545243U, "grayTRC", NULL }, // kTRC
	{ 0x6C756D69U, "luminance", NULL }, // lumi
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x6E636C32U, "namedColor2", NULL }, // ncl2
	{ 0x6E636F6CU, "namedColor", NULL }, // ncol
	{ 0x70726530U, "preview0", NULL }, // pre0
	{ 0x70726531U, "preview1", NULL }, // pre1
	{ 0x70726532U, "preview2", NULL }, // pre2
	{ 0x70733269U, "ps2RenderingIntent", NULL }, // ps2i
	{ 0x70733273U, "ps2CSA", NULL }, // ps2s
	{ 0x70736430U, "ps2CRD0", NULL }, // psd0
	{ 0x70736431U, "ps2CRD1", NULL }, // psd1
	{ 0x70736432U, "ps2CRD2", NULL }, // psd2
	{ 0x70736433U, "ps2CRD3", NULL }, // psd3
	{ 0x70736571U, "profileSequenceDesc", NULL }, // pseq
	{ 0x70736964U, "profileSequenceIdentifier", NULL }, // psid
	{ 0x72545243U, "redTRC", NULL }, // rTRC
	{ 0x7258595AU, "redColorant/redMatrixColumn", NULL }, // rXYZ
	{ 0x72657370U, "outputResponse", NULL }, // resp
	{ 0x72696730U, "perceptualRenderingIntentGamut", NULL }, // rig0
	{ 0x72696732U, "saturationRenderingIntentGamut", NULL }, // rig2
	{ 0x73637264U, "screeningDesc", NULL }, // scrd
	{ 0x7363726EU, "screening", NULL }, // scrn
	{ 0x74617267U, "charTarget", NULL }, // targ
	{ 0x74656368U, "technology", NULL }, // tech
	{ 0x76636774U, "Video Card Gamma Type", NULL }, // vcgt (Apple)
	{ 0x76696577U, "viewingConditions", NULL }, // view
	{ 0x76756564U, "viewingCondDesc", NULL }, // vued
	{ 0x77747074U, "mediaWhitePoint", NULL } // wtpt
};

// flag 0x1: Include the hex value
// flag 0x2: Interpret 0 as (none)
// Returns a copy of the buf pointer.
static const char *format_4cc(const struct de_fourcc *tmp4cc,
	char *buf, size_t buflen, unsigned int flags)
{
	char str[16];

	if((tmp4cc->id==0) && (flags&0x2))
		de_strlcpy(str, "(none)", sizeof(str));
	else
		de_snprintf(str, sizeof(str), "'%s'", tmp4cc->id_printable);

	if(flags&0x1)
		de_snprintf(buf, buflen, "0x%08x=%s", (unsigned int)tmp4cc->id, str);
	else
		de_strlcpy(buf, str, buflen);

	return buf;
}

static double read_s15Fixed16Number(dbuf *f, de_int64 pos)
{
	de_int64 n, frac;

	n = dbuf_geti16be(f, pos);
	frac = dbuf_getui16be(f, pos+2);
	return (double)n + ((double)frac)/65536.0;
}

static void typedec_XYZ(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 xyz_count;
	de_int64 k;
	double v[3];

	if(len<8) return;
	xyz_count = (len-8)/12;
	for(k=0; k<xyz_count; k++) {
		v[0] = read_s15Fixed16Number(c->infile, pos+8+12*k);
		v[1] = read_s15Fixed16Number(c->infile, pos+8+12*k+4);
		v[2] = read_s15Fixed16Number(c->infile, pos+8+12*k+8);
		de_dbg(c, "XYZ[%d]: %.5f, %.5f, %.5f", (int)k,
			v[0], v[1], v[2]);
	}
}

static void typedec_text(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;
	de_int64 textlen = len-8;

	if(textlen<0) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos+8, textlen, DE_DBG_MAX_STRLEN,
		s, 0, DE_ENCODING_ASCII);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
	return;
}

static void typedec_desc(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_ucstring *s = NULL;
	de_int64 invdesclen, uloclen;
	de_int64 langcode;
	de_int64 lstrstartpos;
	de_int64 bytes_to_read;
	int encoding;
	de_int64 pos = pos1;

	if(len<12) goto done;

	pos += 8;

	// ASCII invariant description
	invdesclen = de_getui32be(pos); // invariant desc. len, including NUL byte
	pos += 4;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, invdesclen, DE_DBG_MAX_STRLEN,
		s, 0, DE_ENCODING_ASCII);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "invariant desc.: \"%s\"", ucstring_getpsz(s));
	pos += invdesclen;
	if(pos >= pos1+len) goto done;

	// Unicode localizable description
	ucstring_empty(s);

	langcode = de_getui32be(pos);
	pos += 4;

	uloclen = de_getui32be(pos);
	pos += 4;

	if(uloclen>0) {
		// TODO: How to interpret the language code?
		de_dbg(c, "language code: %d", (int)langcode);
	}

	lstrstartpos = pos;
	bytes_to_read = uloclen*2;

	encoding = DE_ENCODING_UTF16BE;
	if(uloclen>=1) {
		de_int32 firstchar;
		// Check for a BOM. The spec doesn't say much about the format of
		// Unicode text in 'desc' tags. It does say that "All profile data must
		// be encoded as big-endian", so maybe that means UTF-16LE is not
		// allowed. In practice, some strings begin with a BOM.
		firstchar = (de_int32)de_getui16be(lstrstartpos);
		if(firstchar==0xfeff) { // UTF-16BE BOM
			lstrstartpos += 2;
			bytes_to_read -= 2;
		}
		else if(firstchar==0xffef) { // UTF-16LE BOM
			lstrstartpos += 2;
			bytes_to_read -= 2;
			encoding = DE_ENCODING_UTF16LE;
		}
	}

	dbuf_read_to_ucstring_n(c->infile, lstrstartpos, bytes_to_read, DE_DBG_MAX_STRLEN*2,
		s, 0, encoding);
	ucstring_truncate_at_NUL(s);
	if(s->len>0) {
		de_dbg(c, "localizable desc.: \"%s\"", ucstring_getpsz(s));
	}
	pos += uloclen*2;
	if(pos >= pos1+len) goto done;

	// Macintosh localizable description
	// (not implemented)

done:
	ucstring_destroy(s);
}

static void do_mluc_record(deark *c, lctx *d, de_int64 tagstartpos,
	de_int64 pos, de_int64 recsize)
{
	de_ucstring *s = NULL;
	de_int64 string_len;
	de_int64 string_offset;

	s = ucstring_create(c);

	dbuf_read_to_ucstring(c->infile, pos, 2, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "language code: '%s'", ucstring_getpsz(s));
	ucstring_empty(s);

	dbuf_read_to_ucstring(c->infile, pos+2, 2, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "country code: '%s'", ucstring_getpsz(s));
	ucstring_empty(s);

	string_len = de_getui32be(pos+4);
	string_offset = de_getui32be(pos+8);
	de_dbg(c, "string offset=%d+%d, len=%d bytes", (int)tagstartpos,
		(int)string_offset, (int)string_len);

	dbuf_read_to_ucstring_n(c->infile, tagstartpos+string_offset, string_len, DE_DBG_MAX_STRLEN*2,
		s, 0, DE_ENCODING_UTF16BE);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "string: \"%s\"", ucstring_getpsz(s));

	ucstring_destroy(s);
}

static void typedec_mluc(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 num_recs;
	de_int64 recsize;
	de_int64 rec_array_startpos;
	de_int64 rec;

	if(len<12) goto done;
	pos += 8;

	num_recs = de_getui32be(pos);
	de_dbg(c, "number of records: %d", (int)num_recs);
	pos += 4;

	recsize = de_getui32be(pos);
	de_dbg(c, "record size: %d", (int)recsize);
	if(recsize<12) goto done;
	pos += 4;

	rec_array_startpos = pos;

	for(rec=0; rec<num_recs; rec++) {
		if(rec_array_startpos+rec*recsize > pos1+len) break;

		de_dbg(c, "record #%d at %d", (int)rec, (int)pos);
		de_dbg_indent(c, 1);
		do_mluc_record(c, d, pos1, pos, recsize);
		de_dbg_indent(c, -1);
		pos += recsize;
	}

done:
	;
}

static void do_read_header(deark *c, lctx *d, de_int64 pos)
{
	de_uint32 profile_ver_raw;
	de_int64 x;
	struct de_fourcc tmp4cc;
	char tmpbuf[80];
	const char *name;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	x = de_getui32be(pos+0);
	de_dbg(c, "profile size: %d", (int)x);

	dbuf_read_fourcc(c->infile, pos+4, &tmp4cc, 0);
	de_dbg(c, "preferred CMM type: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x1));

	profile_ver_raw = (de_uint32)de_getui32be(pos+8);
	d->profile_ver_major = 10*((profile_ver_raw&0xf0000000U)>>28) +
		((profile_ver_raw&0x0f000000U)>>24);
	d->profile_ver_minor = (profile_ver_raw&0x00f00000U)>>20;
	d->profile_ver_bugfix = (profile_ver_raw&0x000f0000U)>>16;
	de_dbg(c, "profile version: %u.%u.%u", d->profile_ver_major,
		d->profile_ver_minor, d->profile_ver_bugfix);

	dbuf_read_fourcc(c->infile, pos+12, &tmp4cc, 0);
	de_dbg(c, "profile/device class: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x1));

	dbuf_read_fourcc(c->infile, pos+16, &tmp4cc, 0);
	de_dbg(c, "colour space: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x1));

	dbuf_read_fourcc(c->infile, pos+20, &tmp4cc, 0);
	de_dbg(c, "PCS: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x1));

	// TODO: pos=24-35 Date & time

	dbuf_read_fourcc(c->infile, pos+36, &tmp4cc, 0);
	de_dbg(c, "file signature: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x1));

	dbuf_read_fourcc(c->infile, pos+40, &tmp4cc, 0);
	de_dbg(c, "primary platform: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x3));

	// TODO: pos=44-47 Profile flags

	dbuf_read_fourcc(c->infile, pos+48, &tmp4cc, 0);
	de_dbg(c, "device manufacturer: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x3));

	dbuf_read_fourcc(c->infile, pos+52, &tmp4cc, 0);
	de_dbg(c, "device model: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x3));

	// TODO: pos=56-63 Device attributes

	x = de_getui32be(pos+64);
	switch(x) {
	case 0: name="perceptual"; break;
	case 1: name="relative colorimetric"; break;
	case 2: name="saturation"; break;
	case 3: name="absolute colorimetric"; break;
	default: name="?"; break;
	}
	de_dbg(c, "rendering intent: %d (%s)", (int)x, name);

	// TODO: pos=68-79 PCS illuminant

	dbuf_read_fourcc(c->infile, pos+80, &tmp4cc, 0);
	de_dbg(c, "profile creator: %s",
		format_4cc(&tmp4cc, tmpbuf, sizeof(tmpbuf), 0x3));

	// TODO: pos=84-99 Profile ID

	de_dbg_indent(c, -1);
}

static const struct datatypeinfo *lookup_datatypeinfo(de_uint32 id)
{
	size_t k;
	for(k=0; k<DE_ITEMS_IN_ARRAY(datatypeinfo_arr); k++) {
		if(datatypeinfo_arr[k].id == id) {
			return &datatypeinfo_arr[k];
		}
	}
	return NULL;
}

static const struct taginfo *lookup_taginfo(de_uint32 id)
{
	size_t k;
	for(k=0; k<DE_ITEMS_IN_ARRAY(taginfo_arr); k++) {
		if(taginfo_arr[k].id == id) {
			return &taginfo_arr[k];
		}
	}
	return NULL;
}

static int is_duplicate_data(deark *c, lctx *d, de_int64 tagindex,
	de_int64 tagdataoffset, de_int64 tagdatalen,
	de_int64 *idx_of_dup)
{
	de_int64 k;

	for(k=0; k<tagindex; k++) {
		if(d->tags_seen[k].offset==tagdataoffset &&
			d->tags_seen[k].len==tagdatalen)
		{
			*idx_of_dup = k;
			return 1;
		}
	}

	*idx_of_dup = -1;
	return 0;
}

static void do_tag_data(deark *c, lctx *d, de_int64 tagindex,
	const struct de_fourcc *tag4cc, const struct taginfo *ti,
	de_int64 tagdataoffset, de_int64 tagdatalen)
{
	struct de_fourcc tagtype4cc;
	const struct datatypeinfo *dti;
	const char *dtname;
	de_int64 idx_of_dup;
	char tmpbuf[80];

	if(tagdatalen<1) return;
	if(tagdataoffset+tagdatalen > c->infile->len) {
		de_err(c, "Tag #%d data goes beyond end of file", (int)tagindex);
		return;
	}
	if(is_duplicate_data(c, d, tagindex, tagdataoffset, tagdatalen, &idx_of_dup)) {
		de_dbg(c, "[data is a duplicate of tag #%d]", (int)idx_of_dup);
		return;
	}

	if(tagdatalen<4) return;

	dbuf_read_fourcc(c->infile, tagdataoffset, &tagtype4cc, 0);
	dti = lookup_datatypeinfo(tagtype4cc.id);
	if(dti && dti->name) dtname=dti->name;
	else dtname="?";
	de_dbg(c, "data type: %s (%s)",
		format_4cc(&tagtype4cc, tmpbuf, sizeof(tmpbuf), 0x0), dtname);

	if(!dti) return;

	if(dti->dtdfn) {
		dti->dtdfn(c, d, tagdataoffset, tagdatalen);
	}
}

static void do_tag(deark *c, lctx *d, de_int64 tagindex, de_int64 pos_in_tagtable)
{
	struct de_fourcc tag4cc;
	const struct taginfo *ti;
	const char *tname;
	de_int64 tagdataoffset;
	de_int64 tagdatalen;
	char tmpbuf[80];

	dbuf_read_fourcc(c->infile, pos_in_tagtable, &tag4cc, 0);
	tagdataoffset = de_getui32be(pos_in_tagtable+4);
	tagdatalen = de_getui32be(pos_in_tagtable+8);
	ti = lookup_taginfo(tag4cc.id);
	if(ti && ti->name)
		tname = ti->name;
	else
		tname = "?";
	de_dbg(c, "tag #%d %s (%s) offs=%d dlen=%d", (int)tagindex,
		format_4cc(&tag4cc, tmpbuf, sizeof(tmpbuf), 0x0), tname,
		(int)tagdataoffset, (int)tagdatalen);

	de_dbg_indent(c, 1);
	do_tag_data(c, d, tagindex, &tag4cc, ti, tagdataoffset, tagdatalen);
	de_dbg_indent(c, -1);

	d->tags_seen[tagindex].offset = tagdataoffset;
	d->tags_seen[tagindex].len = tagdatalen;
}

static void do_read_tags(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 tagindex;

	de_dbg(c, "tag table at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->num_tags = de_getui32be(pos1);
	de_dbg(c, "number of tags: %d", (int)d->num_tags);
	if(d->num_tags>500) {
		de_err(c, "Invalid or excessive number of tags: %d", (int)d->num_tags);
		goto done;
	}
	de_dbg(c, "expected start of data segment: %d", (int)(pos1+4+12*d->num_tags));

	// Make a place to record some information about each tag we encounter in the table.
	d->tags_seen = de_malloc(c, d->num_tags * sizeof(struct tag_seen_type));

	for(tagindex=0; tagindex<d->num_tags; tagindex++) {
		do_tag(c, d, tagindex, pos1+4+12*tagindex);
	}

done:
	de_free(c, d->tags_seen);
	de_dbg_indent(c, -1);
}

static void de_run_iccprofile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	de_msg(c, "Note: ICC profiles can be parsed, but no files can be extracted from them.");

	pos = 0;
	do_read_header(c, d, pos);
	pos += 128;
	do_read_tags(c, d, pos);

	de_free(c, d);
}

static int de_identify_iccprofile(deark *c)
{
	if(!dbuf_memcmp(c->infile, 36, "acsp", 4))
		return 85;
	return 0;
}

void de_module_iccprofile(deark *c, struct deark_module_info *mi)
{
	mi->id = "iccprofile";
	mi->desc = "ICC profile";
	mi->run_fn = de_run_iccprofile;
	mi->identify_fn = de_identify_iccprofile;
}
