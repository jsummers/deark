// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ICC Profile format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iccprofile);

#define MAX_TAGS_PER_TAGSET 500
#define MAX_NESTING_LEVEL 16

struct tag_seen_type {
	i64 offset; // relative to tagset_type::data_area_pos
	i64 len;
};

struct tagset_type {
	int nesting_level;
	i64 data_area_pos;
	i64 data_area_len;
	i64 num_tags;
	struct tag_seen_type *tags_seen;
};

struct XYZ_type {
	double v[3];
};

typedef struct localctx_struct {
	unsigned int profile_ver_major;
	unsigned int profile_ver_minor;
	unsigned int profile_ver_bugfix;
	i64 profile_size;
	char tmpbuf1[80];
	char tmpbuf2[80];
} lctx;

struct typedec_params {
	lctx *d;
	struct tagset_type *tgs;
	i64 pos1;
	i64 len;
	u32 type_id;
};
typedef void (*datatype_decoder_fn_type)(deark *c, struct typedec_params *p);

struct datatypeinfo {
	u32 id;
	u32 reserved;
	const char *name;
	datatype_decoder_fn_type dtdfn;
};

struct taginfo {
	u32 id;

	// 0x1 = ignore if version >= 4.0.0
	// 0x2 = ignore if version < 4.0.0
	u32 flags;

	const char *name;
	void *reserved2;
};

static double read_s15Fixed16Number(dbuf *f, i64 pos)
{
	i64 n, frac;

	n = dbuf_geti16be(f, pos);
	frac = dbuf_getu16be(f, pos+2);
	return (double)n + ((double)frac)/65536.0;
}

static void dbg_timestamp(deark *c, i64 pos1, const char *name)
{
	i64 n[6];
	i64 pos = pos1;
	i64 i;
	char timestamp_buf[64];

	for(i=0; i<6; i++) {
		n[i] = de_getu16be_p(&pos);
	}

	if(n[0]!=0) {
		struct de_timestamp ts;

		de_make_timestamp(&ts, n[0], n[1], n[2], n[3], n[4], n[5]);
		ts.tzcode = DE_TZCODE_UTC;
		de_dbg_timestamp_to_string(c, &ts, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_strlcpy(timestamp_buf, "(none)", sizeof(timestamp_buf));
	}

	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void read_XYZ(deark *c, i64 pos, struct XYZ_type *xyz)
{
	xyz->v[0] = read_s15Fixed16Number(c->infile, pos);
	xyz->v[1] = read_s15Fixed16Number(c->infile, pos+4);
	xyz->v[2] = read_s15Fixed16Number(c->infile, pos+8);
}

static void destroy_tagset(deark *c, struct tagset_type *tgs)
{
	if(!tgs) return;
	de_free(c, tgs->tags_seen);
	de_free(c, tgs);
}

// flag 0x1: Include the hex value
// flag 0x2: Interpret 0 as (none)
// Returns a copy of the buf pointer.
static const char *format_4cc_dbgstr(const struct de_fourcc *tmp4cc,
	char *buf, size_t buflen, unsigned int flags)
{
	char str[40];

	if((tmp4cc->id==0) && (flags&0x2))
		de_strlcpy(str, "(none)", sizeof(str));
	else
		de_snprintf(str, sizeof(str), "'%s'", tmp4cc->id_dbgstr);

	if(flags&0x1)
		de_snprintf(buf, buflen, "0x%08x=%s", (unsigned int)tmp4cc->id, str);
	else
		de_strlcpy(buf, str, buflen);

	return buf;
}

static void typedec_sf32(deark *c, struct typedec_params *p)
{
	i64 count;
	i64 i;
	i64 pos = p->pos1 + 8;
	double val;

	if(p->len<8) return;
	count = (p->len-8)/4;
	for(i=0; i<count && i<64; i++) {
		val = read_s15Fixed16Number(c->infile, pos);
		pos += 4;
		de_dbg(c, "arr[%d] = %.5f", (int)i, val);
	}
}

static void typedec_XYZ(deark *c, struct typedec_params *p)
{
	i64 xyz_count;
	i64 k;

	if(p->len<8) return;
	xyz_count = (p->len-8)/12;
	for(k=0; k<xyz_count; k++) {
		struct XYZ_type xyz;

		read_XYZ(c, p->pos1+8+12*k, &xyz);
		de_dbg(c, "XYZ[%d]: %.5f, %.5f, %.5f", (int)k,
			xyz.v[0], xyz.v[1], xyz.v[2]);
	}
}

static void typedec_text(deark *c, struct typedec_params *p)
{
	de_ucstring *s = NULL;
	i64 textlen = p->len-8;
	de_ext_encoding enc;

	if(textlen<0) goto done;

	if(p->type_id==0x75746638U) {
		enc = DE_ENCODING_UTF8;
	}
	else {
		enc = DE_ENCODING_ASCII;
	}

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, p->pos1+8, textlen, DE_DBG_MAX_STRLEN,
		s, 0, enc);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
	return;
}

static void typedec_desc(deark *c, struct typedec_params *p)
{
	de_ucstring *s = NULL;
	i64 invdesclen, uloclen;
	i64 langcode;
	i64 lstrstartpos;
	i64 bytes_to_read;
	de_encoding encoding;
	i64 pos = p->pos1;

	if(p->len<12) goto done;

	pos += 8;

	// ASCII invariant description
	invdesclen = de_getu32be(pos); // invariant desc. len, including NUL byte
	pos += 4;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, invdesclen, DE_DBG_MAX_STRLEN,
		s, 0, DE_ENCODING_ASCII);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "invariant desc.: \"%s\"", ucstring_getpsz(s));
	pos += invdesclen;
	if(pos >= p->pos1+p->len) goto done;

	// Unicode localizable description
	ucstring_empty(s);

	langcode = de_getu32be(pos);
	pos += 4;

	uloclen = de_getu32be(pos);
	pos += 4;

	if(uloclen>0) {
		// TODO: How to interpret the language code?
		de_dbg(c, "language code: %d", (int)langcode);
	}

	lstrstartpos = pos;
	bytes_to_read = uloclen*2;

	encoding = DE_ENCODING_UTF16BE;
	if(uloclen>=1) {
		i32 firstchar;
		// Check for a BOM. The spec doesn't say much about the format of
		// Unicode text in 'desc' tags. It does say that "All profile data must
		// be encoded as big-endian", so maybe that means UTF-16LE is not
		// allowed. In practice, some strings begin with a BOM.
		firstchar = (i32)de_getu16be(lstrstartpos);
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
	if(pos >= p->pos1+p->len) goto done;

	// Macintosh localizable description
	// (not implemented)

done:
	ucstring_destroy(s);
}

static void do_mluc_record(deark *c, lctx *d, i64 tagstartpos,
	i64 pos, i64 recsize)
{
	de_ucstring *s = NULL;
	i64 string_len;
	i64 string_offset;

	s = ucstring_create(c);

	dbuf_read_to_ucstring(c->infile, pos, 2, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "language code: '%s'", ucstring_getpsz(s));
	ucstring_empty(s);

	dbuf_read_to_ucstring(c->infile, pos+2, 2, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "country code: '%s'", ucstring_getpsz(s));
	ucstring_empty(s);

	string_len = de_getu32be(pos+4);
	string_offset = de_getu32be(pos+8);
	de_dbg(c, "string offset=%d+%d, len=%d bytes", (int)tagstartpos,
		(int)string_offset, (int)string_len);

	dbuf_read_to_ucstring_n(c->infile, tagstartpos+string_offset, string_len, DE_DBG_MAX_STRLEN*2,
		s, 0, DE_ENCODING_UTF16BE);
	ucstring_truncate_at_NUL(s);
	de_dbg(c, "string: \"%s\"", ucstring_getpsz(s));

	ucstring_destroy(s);
}

static void typedec_mluc(deark *c, struct typedec_params *p)
{
	i64 pos = p->pos1;
	i64 num_recs;
	i64 recsize;
	i64 rec_array_startpos;
	i64 rec;

	if(p->len<12) goto done;
	pos += 8;

	num_recs = de_getu32be(pos);
	de_dbg(c, "number of records: %d", (int)num_recs);
	pos += 4;

	recsize = de_getu32be(pos);
	de_dbg(c, "record size: %d", (int)recsize);
	if(recsize<12) goto done;
	pos += 4;

	rec_array_startpos = pos;

	for(rec=0; rec<num_recs; rec++) {
		if(rec_array_startpos+rec*recsize > p->pos1+p->len) break;

		de_dbg(c, "record #%d at %d", (int)rec, (int)pos);
		de_dbg_indent(c, 1);
		do_mluc_record(c, p->d, p->pos1, pos, recsize);
		de_dbg_indent(c, -1);
		pos += recsize;
	}

done:
	;
}

static void do_tag_data(deark *c, lctx *d, struct tagset_type *tgs, i64 tagindex,
	i64 tagdataoffset, i64 tagdatalen);

static void typedec_tagArray_tagStruct(deark *c, struct typedec_params *p)
{
	struct de_fourcc ty4cc;
	struct de_fourcc tmp4cc;
	lctx *d = p->d;
	struct tagset_type *tgs = NULL;
	i64 pos = p->pos1 + 8;
	i64 endpos = p->pos1 + p->len;
	int is_struct = (p->type_id == 0x74737472U);
	i64 array_item_size;
	i64 i;
	const char *struct_name;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_zeromem(&tmp4cc, sizeof(struct de_fourcc));

	tgs = de_malloc(c, sizeof(struct tagset_type));
	tgs->data_area_pos = p->pos1;
	tgs->data_area_len = p->len;
	tgs->nesting_level = p->tgs->nesting_level+1;
	if(tgs->nesting_level > MAX_NESTING_LEVEL) goto done;

	if(is_struct) {
		array_item_size = 12;
		struct_name = "struct";
	}
	else {
		array_item_size = 8;
		struct_name = "array";
	}

	dbuf_read_fourcc(c->infile, pos, &ty4cc, 4, 0x0);
	pos += 4;
	de_dbg(c, "%s type: %s", struct_name,
		format_4cc_dbgstr(&ty4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0));
	tgs->num_tags = de_getu32be_p(&pos);
	de_dbg(c, "number of elements: %"I64_FMT, tgs->num_tags);
	if(tgs->num_tags>MAX_TAGS_PER_TAGSET) {
		de_err(c, "Invalid or excessive number of elements: %u", (UI)tgs->num_tags);
		goto done;
	}

	tgs->tags_seen = de_mallocarray(c, tgs->num_tags, sizeof(struct tag_seen_type));

	for(i=0; i<tgs->num_tags; i++) {
		i64 elem_pos_rel, elem_pos_abs;
		i64 elem_dlen;
		i64 tpos = pos;

		if(pos+array_item_size > endpos) break;

		if(is_struct) {
			dbuf_read_fourcc(c->infile, pos, &tmp4cc, 4, 0x0);
			pos += 4;
		}

		elem_pos_rel = de_getu32be_p(&pos);
		elem_dlen = de_getu32be_p(&pos);
		elem_pos_abs = p->pos1 + elem_pos_rel;

		if(is_struct) {
			format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0);
			de_snprintf(d->tmpbuf2, sizeof(d->tmpbuf2), " %s", d->tmpbuf1);
		}
		else {
			d->tmpbuf2[0] = '\0';
		}
		de_dbg(c, "elem #%d%s tpos=%"I64_FMT" dpos=%"I64_FMT" (%"I64_FMT"+%"I64_FMT"), dlen=%"I64_FMT,
			(int)i, d->tmpbuf2, tpos, elem_pos_abs, p->pos1, elem_pos_rel, elem_dlen);

		de_dbg_indent(c, 1);
		do_tag_data(c, d, tgs, i, elem_pos_rel, elem_dlen);
		de_dbg_indent(c, -1);
	}

done:
	destroy_tagset(c, tgs);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_dict_string(deark *c, struct typedec_params *p, i64 itempos, const char *itemname)
{
	de_ucstring *s = NULL;
	i64 dpos_rel, dpos_abs, dlen;

	dpos_rel = de_getu32be(itempos);
	dpos_abs = p->pos1 + dpos_rel;
	dlen = de_getu32be(itempos+4);
	if(dpos_abs + dlen > p->pos1 + p->len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, dpos_abs, dlen, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF16BE);
	de_dbg(c, "%s: dpos=%"I64_FMT", dlen=%"I64_FMT", string=\"%s\"", itemname, dpos_abs, dlen,
		ucstring_getpsz_d(s));

done:
	ucstring_destroy(s);
}

static void typedec_dict(deark *c, struct typedec_params *p)
{
	i64 pos = p->pos1 + 8;
	i64 nrec;
	i64 reclen;
	i64 i;

	if(p->len<16) goto done;

	nrec = de_getu32be_p(&pos);
	de_dbg(c, "num records: %u", (UI)nrec);
	reclen = de_getu32be_p(&pos);
	de_dbg(c, "rec len: %u", (UI)reclen);
	if(reclen!=16 && reclen!=24 && reclen!=32) goto done;
	if(pos+nrec*reclen > p->pos1 + p->len) goto done;
	if(nrec>MAX_TAGS_PER_TAGSET) goto done;

	for(i=0; i<nrec; i++) {
		do_dict_string(c, p, pos, "name");
		pos += 8;
		do_dict_string(c, p, pos, "value");
		pos += 8;
		if(reclen>=24) {
			do_dict_string(c, p, pos, "display name");
			pos += 8;
		}
		if(reclen>=32) {
			do_dict_string(c, p, pos, "display value");
			pos += 8;
		}
	}

done:
	;
}

static void typedec_hexdump(deark *c, struct typedec_params *p)
{
	UI rsvd;

	if(p->len<8) return;
	rsvd = (UI)de_getu32be(p->pos1+4);
	de_dbg(c, "reserved/etc.: 0x%08x", rsvd);
	de_dbg_hexdump(c, c->infile, p->pos1+8, p->len-8, 256, NULL, 0x1);
}

static const struct datatypeinfo datatypeinfo_arr[] = {
	{ 0x58595a20U, 0, "XYZ", typedec_XYZ }, // XYZ
	{ 0x62666420U, 0, "ucrbg", NULL }, // bfd
	{ 0x6368726dU, 0, "chromaticity", NULL }, // chrm
	{ 0x636c726fU, 0, "colorantOrder", NULL }, // clro
	{ 0x636c7274U, 0, "colorantTable", NULL }, // clrt
	{ 0x63726469U, 0, "crdInfo", NULL }, // crdi
	{ 0x63757266U, 0, "segmentedCurve", NULL}, // curf
	{ 0x63757276U, 0, "curve", NULL }, // curv
	{ 0x64657363U, 0, "textDescription", typedec_desc }, // desc
	{ 0x64617461U, 0, "data", NULL }, // data
	{ 0x64657673U, 0, "deviceSettings", NULL }, // devs
	{ 0x64696374U, 0, "dictionary array", typedec_dict }, // dict
	{ 0x6474696dU, 0, "dateTime", NULL }, // dtim
	{ 0x666c3136U, 0, "float16Array", NULL }, // fl16
	{ 0x666c3332U, 0, "float32Array", NULL }, // fl32
	{ 0x666c3634U, 0, "float64Array", NULL }, // fl64
	{ 0x67626420U, 0, "gamutBoundaryDescription", NULL }, // gbd
	{ 0x6d414220U, 0, "lutAToB", NULL }, // mAB
	{ 0x6d424120U, 0, "lutBToA", NULL }, // mBA
	{ 0x6d656173U, 0, "measurement", NULL }, // meas
	{ 0x6d667431U, 0, "lut8", NULL }, // mft1
	{ 0x6d667432U, 0, "lut16", NULL }, // mft2
	{ 0x6d6c7563U, 0, "multiLocalizedUnicode", typedec_mluc }, // mluc
	{ 0x6d706574U, 0, "multiProcessElements", NULL }, // mpet
	{ 0x6e636c32U, 0, "namedColor2", NULL }, // ncl2
	{ 0x6e636f6cU, 0, "namedColor", NULL }, // ncol
	{ 0x70617261U, 0, "parametricCurve", NULL }, // para
	{ 0x70736571U, 0, "profileSequenceDesc", NULL }, // pseq
	{ 0x70736964U, 0, "profileSequenceIdentifier", NULL }, // psid
	{ 0x72637332U, 0, "responseCurveSet16", NULL }, // rcs2
	{ 0x73663332U, 0, "s15Fixed16Array", typedec_sf32 }, // sf32
	{ 0x7363726eU, 0, "screening", NULL }, // scrn
	{ 0x73696720U, 0, "signature", NULL }, // sig
	{ 0x7376636eU, 0, "spectralViewingConditions", NULL }, // svcn
	{ 0x74617279U, 0, "tagArray", typedec_tagArray_tagStruct }, // tary
	{ 0x74657874U, 0, "text", typedec_text }, // text
	{ 0x74737472U, 0, "tagStruct", typedec_tagArray_tagStruct }, // tstr
	{ 0x75663332U, 0, "u16Fixed16Array", NULL }, // uf32
	{ 0x75693038U, 0, "uInt8Array", NULL }, // ui08
	{ 0x75693136U, 0, "uInt16Array", NULL }, // ui16
	{ 0x75693332U, 0, "uInt32Array", NULL }, // ui32
	{ 0x75693634U, 0, "uInt64Array", NULL }, // ui64
	{ 0x75743136U, 0, "utf16", NULL }, // ut16
	{ 0x75746638U, 0, "utf8", typedec_text }, // utf8
	{ 0x76636774U, 0, "Video Card Gamma Type", NULL }, // vcgt (Apple)
	{ 0x76696577U, 0, "viewingConditions", NULL } // view
};

static const struct taginfo taginfo_arr[] = {
	{ 0x41324230U, 0, "AToB0", NULL }, // A2B0
	{ 0x41324231U, 0, "AToB1", NULL }, // A2B1
	{ 0x41324232U, 0, "AToB2", NULL }, // A2B2
	{ 0x41324233U, 0, "AToB3", NULL }, // A2B3
	{ 0x42324130U, 0, "BToA0", NULL }, // B2A0
	{ 0x42324131U, 0, "BToA1", NULL }, // B2A1
	{ 0x42324132U, 0, "BToA2", NULL }, // B2A2
	{ 0x42324133U, 0, "BToA3", NULL }, // B2A3
	{ 0x42324430U, 0, "BToD0", NULL }, // B2D0
	{ 0x42324431U, 0, "BToD1", NULL }, // B2D1
	{ 0x42324432U, 0, "BToD2", NULL }, // B2D2
	{ 0x42324433U, 0, "BToD3", NULL }, // B2D3
	{ 0x44324230U, 0, "DToB0", NULL }, // D2B0
	{ 0x44324231U, 0, "DToB1", NULL }, // D2B1
	{ 0x44324232U, 0, "DToB2", NULL }, // D2B2
	{ 0x44324233U, 0, "DToB3", NULL }, // D2B3
	{ 0x62545243U, 0, "blueTRC", NULL }, // bTRC
	{ 0x6258595aU, 0x1, "blueColorant", NULL }, // bXYZ
	{ 0x6258595aU, 0x2, "blueMatrixColumn", NULL }, // bXYZ
	{ 0x62666420U, 0, "ucrbg", NULL }, // bfd
	{ 0x626b7074U, 0, "mediaBlackPoint", NULL }, // bkpt
	{ 0x63327370U, 0, "customToStandardPcc", NULL }, // c2sp
	{ 0x63616c74U, 0, "calibrationDateTime", NULL }, // calt
	{ 0x63657074U, 0, "colorEncodingParams", NULL }, // cept
	{ 0x63686164U, 0, "chromaticAdaptation", NULL }, // chad
	{ 0x6368726dU, 0, "chromaticity", NULL }, // chrm
	{ 0x63696973U, 0, "colorimetricIntentImageState", NULL }, // ciis
	{ 0x636c6f74U, 0, "colorantTableOut", NULL }, // clot
	{ 0x636c726fU, 0, "colorantOrder", NULL }, // clro
	{ 0x636c7274U, 0, "colorantTable", NULL }, // clrt
	{ 0x63707274U, 0, "copyright", NULL }, // cprt
	{ 0x63726469U, 0, "crdInfo", NULL }, // crdi
	{ 0x63736e6dU, 0, "colorSpaceName", NULL }, // csnm
	{ 0x64657363U, 0, "profileDescription", NULL }, // desc
	{ 0x64657673U, 0, "deviceSettings", NULL }, // devs
	{ 0x646d6464U, 0, "deviceModelDesc", NULL }, // dmdd
	{ 0x646d6e64U, 0, "deviceMfgDesc", NULL }, // dmnd
	{ 0x67616d74U, 0, "gamut", NULL }, // gamt
	{ 0x67626431U, 0, "gamutBoundaryDescription1", NULL }, // gbd1
	{ 0x67545243U, 0, "greenTRC", NULL }, // gTRC
	{ 0x6758595aU, 0x1, "greenColorant", NULL }, // gXYZ
	{ 0x6758595aU, 0x2, "greenMatrixColumn", NULL }, // gXYZ
	{ 0x6b545243U, 0, "grayTRC", NULL }, // kTRC
	{ 0x6c756d69U, 0, "luminance", NULL }, // lumi
	{ 0x6d656173U, 0, "measurement", NULL }, // meas
	{ 0x6e636c32U, 0, "namedColor2", NULL }, // ncl2
	{ 0x6e636f6cU, 0, "namedColor", NULL }, // ncol
	{ 0x70726530U, 0, "preview0", NULL }, // pre0
	{ 0x70726531U, 0, "preview1", NULL }, // pre1
	{ 0x70726532U, 0, "preview2", NULL }, // pre2
	{ 0x70733269U, 0, "ps2RenderingIntent", NULL }, // ps2i
	{ 0x70733273U, 0, "ps2CSA", NULL }, // ps2s
	{ 0x70736430U, 0, "ps2CRD0", NULL }, // psd0
	{ 0x70736431U, 0, "ps2CRD1", NULL }, // psd1
	{ 0x70736432U, 0, "ps2CRD2", NULL }, // psd2
	{ 0x70736433U, 0, "ps2CRD3", NULL }, // psd3
	{ 0x70736571U, 0, "profileSequenceDesc", NULL }, // pseq
	{ 0x70736964U, 0, "profileSequenceIdentifier", NULL }, // psid
	{ 0x72545243U, 0, "redTRC", NULL }, // rTRC
	{ 0x7258595aU, 0x1, "redColorant", NULL }, // rXYZ
	{ 0x7258595aU, 0x2, "redMatrixColumn", NULL }, // rXYZ
	{ 0x72657370U, 0, "outputResponse", NULL }, // resp
	{ 0x72666e6dU, 0, "referenceName", NULL }, // rfnm
	{ 0x72696730U, 0, "perceptualRenderingIntentGamut", NULL }, // rig0
	{ 0x72696732U, 0, "saturationRenderingIntentGamut", NULL }, // rig2
	{ 0x73326370U, 0, "standardToCustomPcc", NULL }, // s2cp
	{ 0x73637264U, 0, "screeningDesc", NULL }, // scrd
	{ 0x7363726eU, 0, "screening", NULL }, // scrn
	{ 0x7376636eU, 0, "spectralViewingConditions", NULL }, // svcn
	{ 0x74617267U, 0, "charTarget", NULL }, // targ
	{ 0x74656368U, 0, "technology", NULL }, // tech
	{ 0x76636774U, 0, "Video Card Gamma Type", NULL }, // vcgt (Apple)
	{ 0x76696577U, 0, "viewingConditions", NULL }, // view
	{ 0x76756564U, 0, "viewingCondDesc", NULL }, // vued
	{ 0x77747074U, 0, "mediaWhitePoint", NULL } // wtpt
};

static void do_read_header(deark *c, lctx *d, i64 pos)
{
	u32 profile_ver_raw;
	i64 x;
	u64 xu;
	struct de_fourcc tmp4cc;
	UI tmpflags;
	const char *name;
	struct XYZ_type xyz;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->profile_size = de_getu32be(pos+0);
	de_dbg(c, "profile size: %"I64_FMT, d->profile_size);

	dbuf_read_fourcc(c->infile, pos+4, &tmp4cc, 4, 0x0);
	de_dbg(c, "preferred CMM type: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x3));

	profile_ver_raw = (u32)de_getu32be(pos+8);
	d->profile_ver_major = 10*((profile_ver_raw&0xf0000000U)>>28) +
		((profile_ver_raw&0x0f000000U)>>24);
	d->profile_ver_minor = (profile_ver_raw&0x00f00000U)>>20;
	d->profile_ver_bugfix = (profile_ver_raw&0x000f0000U)>>16;
	de_dbg(c, "profile version: %u.%u.%u", d->profile_ver_major,
		d->profile_ver_minor, d->profile_ver_bugfix);

	dbuf_read_fourcc(c->infile, pos+12, &tmp4cc, 4, 0x0);
	de_dbg(c, "profile/device class: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x1));

	dbuf_read_fourcc(c->infile, pos+16, &tmp4cc, 4, 0x0);
	tmpflags = 0x1;
	if(d->profile_ver_major>=5) tmpflags |= 0x2;
	de_dbg(c, "colour space: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), tmpflags));

	dbuf_read_fourcc(c->infile, pos+20, &tmp4cc, 4, 0x0);
	tmpflags = 0x1;
	if(d->profile_ver_major>=5) tmpflags |= 0x2;
	de_dbg(c, "PCS: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), tmpflags));

	dbg_timestamp(c, pos+24, "creation time");

	dbuf_read_fourcc(c->infile, pos+36, &tmp4cc, 4, 0x0);
	de_dbg(c, "file signature: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x1));

	dbuf_read_fourcc(c->infile, pos+40, &tmp4cc, 4, 0x0);
	de_dbg(c, "primary platform: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x3));

	// TODO: Decode profile flags
	x = de_getu32be(pos+44);
	de_dbg(c, "profile flags: 0x%08x", (UI)x);

	dbuf_read_fourcc(c->infile, pos+48, &tmp4cc, 4, 0x0);
	de_dbg(c, "device manufacturer: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x3));

	dbuf_read_fourcc(c->infile, pos+52, &tmp4cc, 4, 0x0);
	de_dbg(c, "device model: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x3));

	// TODO: Decode device attributes
	xu = dbuf_getu64be(c->infile, pos+56);
	de_dbg(c, "device attribs: 0x%016"U64_FMTx, xu);

	x = de_getu32be(pos+64);
	switch(x) {
	case 0: name="perceptual"; break;
	case 1: name="relative colorimetric"; break;
	case 2: name="saturation"; break;
	case 3: name="absolute colorimetric"; break;
	default: name="?"; break;
	}
	de_dbg(c, "rendering intent: %d (%s)", (int)x, name);

	read_XYZ(c, pos+68, &xyz);
	de_dbg(c, "illuminant: %.5f, %.5f, %.5f", xyz.v[0], xyz.v[1], xyz.v[2]);

	dbuf_read_fourcc(c->infile, pos+80, &tmp4cc, 4, 0x0);
	de_dbg(c, "profile creator: %s",
		format_4cc_dbgstr(&tmp4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x3));

	// TODO: pos=84-99 Profile ID

	de_dbg_indent(c, -1);
}

static const struct datatypeinfo *lookup_datatypeinfo(u32 id)
{
	size_t k;
	for(k=0; k<DE_ARRAYCOUNT(datatypeinfo_arr); k++) {
		if(datatypeinfo_arr[k].id == id) {
			return &datatypeinfo_arr[k];
		}
	}
	return NULL;
}

static const struct taginfo *lookup_taginfo(lctx *d, u32 id)
{
	size_t k;
	for(k=0; k<DE_ARRAYCOUNT(taginfo_arr); k++) {
		if((taginfo_arr[k].flags & 0x1) && d->profile_ver_major>=4) continue;
		if((taginfo_arr[k].flags & 0x2) && d->profile_ver_major<4) continue;
		if(taginfo_arr[k].id == id) {
			return &taginfo_arr[k];
		}
	}
	return NULL;
}

static int is_duplicate_data(deark *c, lctx *d, struct tagset_type *tgs,
	i64 tagindex, i64 tagdataoffset, i64 tagdatalen,
	i64 *idx_of_dup)
{
	i64 k;

	for(k=0; k<tagindex && k<tgs->num_tags; k++) {
		if(tgs->tags_seen[k].offset==tagdataoffset &&
			tgs->tags_seen[k].len==tagdatalen)
		{
			*idx_of_dup = k;
			return 1;
		}
	}

	*idx_of_dup = -1;
	return 0;
}

// tagdataoffset is relative to tgs->data_area_pos
static void do_tag_data(deark *c, lctx *d, struct tagset_type *tgs, i64 tagindex,
	i64 tagdataoffset, i64 tagdatalen)
{
	struct de_fourcc tagtype4cc;
	struct typedec_params tdp;
	const struct datatypeinfo *dti;
	const char *dtname;
	i64 idx_of_dup;

	if(tagindex >= tgs->num_tags) return;
	if(tagdatalen<1) goto done;
	if(tagdataoffset+tagdatalen > tgs->data_area_len) {
		de_err(c, "Tag #%d data exceeds its bounds", (int)tagindex);
		goto done;
	}
	if(is_duplicate_data(c, d, tgs, tagindex, tagdataoffset, tagdatalen, &idx_of_dup)) {
		de_dbg(c, "[data is a duplicate of tag #%d]", (int)idx_of_dup);
		goto done;
	}

	if(tagdatalen<4) goto done;

	dbuf_read_fourcc(c->infile, tgs->data_area_pos+tagdataoffset, &tagtype4cc, 4, 0x0);
	dti = lookup_datatypeinfo(tagtype4cc.id);
	if(dti && dti->name) dtname=dti->name;
	else dtname="?";
	de_dbg(c, "data type: %s (%s)",
		format_4cc_dbgstr(&tagtype4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x0), dtname);

	de_zeromem(&tdp, sizeof(struct typedec_params));
	tdp.d = d;
	tdp.tgs = tgs;
	tdp.pos1 = tgs->data_area_pos+tagdataoffset;
	tdp.len = tagdatalen;
	tdp.type_id = tagtype4cc.id;

	if(dti && dti->dtdfn) {
		dti->dtdfn(c, &tdp);
	}
	else if(c->debug_level>=2) {
		typedec_hexdump(c, &tdp);
	}

done:
	tgs->tags_seen[tagindex].offset = tagdataoffset;
	tgs->tags_seen[tagindex].len = tagdatalen;
}

static void do_main_tag(deark *c, lctx *d, struct tagset_type *tgs,
	i64 tagindex, i64 pos_in_tagtable)
{
	struct de_fourcc tag4cc;
	const struct taginfo *ti;
	const char *tname;
	i64 tagdataoffset;
	i64 tagdatalen;

	dbuf_read_fourcc(c->infile, pos_in_tagtable, &tag4cc, 4, 0x0);
	tagdataoffset = de_getu32be(pos_in_tagtable+4);
	tagdatalen = de_getu32be(pos_in_tagtable+8);
	ti = lookup_taginfo(d, tag4cc.id);
	if(ti && ti->name)
		tname = ti->name;
	else
		tname = "?";
	de_dbg(c, "tag #%d %s (%s) tpos=%"I64_FMT" dpos=%"I64_FMT" dlen=%"I64_FMT, (int)tagindex,
		format_4cc_dbgstr(&tag4cc, d->tmpbuf1, sizeof(d->tmpbuf1), 0x0), tname,
		pos_in_tagtable, tgs->data_area_pos+tagdataoffset, tagdatalen);

	de_dbg_indent(c, 1);
	do_tag_data(c, d, tgs, tagindex, tagdataoffset, tagdatalen);
	de_dbg_indent(c, -1);
}

static void do_read_main_tags(deark *c, lctx *d, i64 pos1)
{
	i64 tagindex;
	struct tagset_type *tgs = NULL;

	de_dbg(c, "tag table at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	tgs = de_malloc(c, sizeof(struct tagset_type));
	tgs->data_area_pos = 0;
	if(d->profile_size!=0) {
		tgs->data_area_len = de_min_int(d->profile_size, c->infile->len);
	}
	else {
		tgs->data_area_len = c->infile->len;
	}
	tgs->num_tags = de_getu32be(pos1);
	de_dbg(c, "number of tags: %d", (int)tgs->num_tags);
	if(tgs->num_tags>MAX_TAGS_PER_TAGSET) {
		de_err(c, "Invalid or excessive number of tags: %d", (int)tgs->num_tags);
		goto done;
	}
	de_dbg(c, "expected start of data segment: %d", (int)(pos1+4+12*tgs->num_tags));

	// Make a place to record some information about each tag we encounter in the table.
	tgs->tags_seen = de_mallocarray(c, tgs->num_tags, sizeof(struct tag_seen_type));

	for(tagindex=0; tagindex<tgs->num_tags; tagindex++) {
		do_main_tag(c, d, tgs, tagindex, pos1+4+12*tagindex);
	}

done:
	destroy_tagset(c, tgs);
	de_dbg_indent(c, -1);
}

static void de_run_iccprofile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	do_read_header(c, d, pos);
	pos += 128;
	do_read_main_tags(c, d, pos);

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
