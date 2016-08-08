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

#define ITEMS_IN_ARRAY(x) (sizeof(x)/sizeof(x[0]))

typedef void (*datatype_decoder_fn_type)(deark *c, lctx *d, de_int64 pos, de_int64 len);

static void typedec_text(deark *c, lctx *d, de_int64 pos, de_int64 len);
static void typedec_desc(deark *c, lctx *d, de_int64 pos, de_int64 len);
static void typedec_mluc(deark *c, lctx *d, de_int64 pos, de_int64 len);

struct datatypeinfo {
	de_uint32 id;
	const char *name;
	datatype_decoder_fn_type dtdfn;
};
static const struct datatypeinfo datatypeinfo_arr[] = {
	{ 0x58595A20U, "XYZ", NULL }, // XYZ
	{ 0x6368726DU, "chromaticity", NULL }, // chrm
	{ 0x636C7274U, "colorantTable", NULL }, // clrt
	{ 0x63757276U, "curve", NULL }, // curv
	{ 0x64617461U, "data", NULL }, // data
	{ 0x64657363U, "textDescription", typedec_desc }, // desc
	{ 0x6D414220U, "lutAToB", NULL }, // mAB
	{ 0x6D424120U, "lutBToA", NULL }, // mBA
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x6D667431U, "lut8", NULL }, // mft1
	{ 0x6D667432U, "lut16", NULL }, // mft2
	{ 0x6D6C7563U, "multiLocalizedUnicode", typedec_mluc }, // mluc
	{ 0x73663332U, "s15Fixed16Array", NULL }, // sf32
	{ 0x73696720U, "signature", NULL }, // sig
	{ 0x74657874U, "text", typedec_text }, // text
	{ 0x75693038U, "uInt8Array", NULL }, // ui08
	{ 0x75693332U, "uInt32Array", NULL }, // ui32
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
	{ 0x62545243U, "blueTRC", NULL }, // bTRC
	{ 0x6258595AU, "blueColorant", NULL }, // bXYZ
	{ 0x626B7074U, "mediaBlackPoint", NULL }, // bkpt
	{ 0x63686164U, "chromaticAdaptation", NULL }, // chad
	{ 0x6368726DU, "chromaticity", NULL }, // chrm
	{ 0x636C7274U, "colorantTable", NULL }, // clrt
	{ 0x63707274U, "copyright", NULL }, // cprt
	{ 0x64657363U, "profileDescription", NULL }, // desc
	{ 0x646D6464U, "deviceModelDesc", NULL }, // dmdd
	{ 0x646D6E64U, "deviceMfgDesc", NULL }, // dmnd
	{ 0x67616D74U, "gamut", NULL }, // gamt
	{ 0x67545243U, "greenTRC", NULL }, // gTRC
	{ 0x6758595AU, "greenColorant", NULL }, // gXYZ
	{ 0x6B545243U, "grayTRC", NULL }, // kTRC
	{ 0x6C756D69U, "luminance", NULL }, // lumi
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x72545243U, "redTRC", NULL }, // rTRC
	{ 0x7258595AU, "redColorant", NULL }, // rXYZ
	{ 0x72696730U, "perceptualRenderingIntentGamut", NULL }, // rig0
	{ 0x74617267U, "charTarget", NULL }, // targ
	{ 0x74656368U, "technology", NULL }, // tech
	{ 0x76696577U, "viewingConditions", NULL }, // view
	{ 0x76756564U, "viewingCondDesc", NULL }, // vued
	{ 0x77747074U, "mediaWhitePoint", NULL } // wtpt
};

static void fourcc_or_printable_or_none(const struct de_fourcc *tmp4cc,
	char *buf, size_t buflen)
{
	if(tmp4cc->id==0) de_strlcpy(buf, "(none)", buflen);
	else de_snprintf(buf, buflen, "'%s'", tmp4cc->id_printable);
}

static void typedec_text(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;
	char buf[300];
	de_int64 textlen = len-8;

	if(textlen<0) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+8, textlen, s, 0, DE_ENCODING_ASCII);
	ucstring_truncate_at_NUL(s);
	ucstring_to_printable_sz(s, buf, sizeof(buf));
	de_dbg(c, "text: \"%s\"\n", buf);

done:
	ucstring_destroy(s);
	return;
}

static void typedec_desc(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_ucstring *s = NULL;
	char buf[300];
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
	bytes_to_read = invdesclen;
	if(bytes_to_read>300) bytes_to_read=300;
	dbuf_read_to_ucstring(c->infile, pos, bytes_to_read, s, 0, DE_ENCODING_ASCII);
	ucstring_truncate_at_NUL(s);
	ucstring_to_printable_sz(s, buf, sizeof(buf));
	de_dbg(c, "invariant desc.: \"%s\"\n", buf);
	pos += invdesclen;
	if(pos >= pos1+len) goto done;

	// Unicode localizable description
	ucstring_truncate(s, 0);

	langcode = de_getui32be(pos);
	// The spec does not seem to say how to interpret this field.
	de_dbg(c, "language code: %d\n", (int)langcode);
	pos += 4;

	uloclen = de_getui32be(pos);
	pos += 4;

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

	if(bytes_to_read>300) bytes_to_read=300;
	dbuf_read_to_ucstring(c->infile, lstrstartpos, bytes_to_read, s, 0, encoding);
	ucstring_truncate_at_NUL(s);
	if(s->len>0) {
		ucstring_to_printable_sz(s, buf, sizeof(buf));
		de_dbg(c, "localizable desc.: \"%s\"\n", buf);
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
	de_int64 bytes_to_read;
	de_byte buf1[300];
	char buf2[300];

	dbuf_read(c->infile, buf1, pos, 2);
	de_bytes_to_printable_sz(buf1, 2, buf2, sizeof(buf2), 0, DE_ENCODING_ASCII);
	de_dbg(c, "language code: '%s'\n", buf2);

	dbuf_read(c->infile, buf1, pos+2, 2);
	de_bytes_to_printable_sz(buf1, 2, buf2, sizeof(buf2), 0, DE_ENCODING_ASCII);
	de_dbg(c, "country code: '%s'\n", buf2);

	string_len = de_getui32be(pos+4);
	string_offset = de_getui32be(pos+8);
	de_dbg(c, "string offset=%d+%d, len=%d bytes\n", (int)tagstartpos,
		(int)string_offset, (int)string_len);

	bytes_to_read = string_len;
	if(bytes_to_read>300) bytes_to_read=300;
	if(bytes_to_read%2) bytes_to_read--; // UTF-16 should have an even number of bytes

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, tagstartpos+string_offset, bytes_to_read,
		s, 0, DE_ENCODING_UTF16BE);
	ucstring_truncate_at_NUL(s);
	ucstring_to_printable_sz(s, buf2, sizeof(buf2));
	de_dbg(c, "string: \"%s\"\n", buf2);

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
	de_dbg(c, "number of records: %d\n", (int)num_recs);
	pos += 4;

	recsize = de_getui32be(pos);
	de_dbg(c, "record size: %d\n", (int)recsize);
	if(recsize<12) goto done;
	pos += 4;

	rec_array_startpos = pos;

	for(rec=0; rec<num_recs; rec++) {
		if(rec_array_startpos+rec*recsize > pos1+len) break;

		de_dbg(c, "record #%d at %d\n", (int)rec, (int)pos);
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
	char tmpbuf[16];
	const char *name;

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	x = de_getui32be(pos+0);
	de_dbg(c, "profile size: %d\n", (int)x);

	dbuf_read_fourcc(c->infile, pos+4, &tmp4cc, 0);
	de_dbg(c, "preferred CMM type: 0x%08x='%s'\n", (unsigned int)tmp4cc.id, tmp4cc.id_printable);

	profile_ver_raw = (de_uint32)de_getui32be(pos+8);
	d->profile_ver_major = 10*((profile_ver_raw&0xf0000000U)>>28) +
		((profile_ver_raw&0x0f000000U)>>24);
	d->profile_ver_minor = (profile_ver_raw&0x00f00000U)>>20;
	d->profile_ver_bugfix = (profile_ver_raw&0x000f0000U)>>16;
	de_dbg(c, "profile version: %u.%u.%u\n", d->profile_ver_major,
		d->profile_ver_minor, d->profile_ver_bugfix);

	dbuf_read_fourcc(c->infile, pos+12, &tmp4cc, 0);
	de_dbg(c, "profile/device class: '%s'\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+16, &tmp4cc, 0);
	de_dbg(c, "colour space: '%s'\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+20, &tmp4cc, 0);
	de_dbg(c, "PCS: '%s'\n", tmp4cc.id_printable);

	// TODO: pos=24-35 Date & time

	dbuf_read_fourcc(c->infile, pos+36, &tmp4cc, 0);
	de_dbg(c, "file signature: '%s'\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+40, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "primary platform: %s\n", tmpbuf);

	// TODO: pos=44-47 Profile flags

	dbuf_read_fourcc(c->infile, pos+48, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "device manufacturer: 0x%08x=%s\n", (unsigned int)tmp4cc.id, tmpbuf);

	dbuf_read_fourcc(c->infile, pos+52, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "device model: 0x%08x=%s\n", (unsigned int)tmp4cc.id, tmpbuf);

	// TODO: pos=56-63 Device attributes

	x = de_getui32be(pos+64);
	switch(x) {
	case 0: name="perceptual"; break;
	case 1: name="relative colorimetric"; break;
	case 2: name="saturation"; break;
	case 3: name="absolute colorimetric"; break;
	default: name="?"; break;
	}
	de_dbg(c, "rendering intent: %d (%s)\n", (int)x, name);

	// TODO: pos=68-79 PCS illuminant

	dbuf_read_fourcc(c->infile, pos+80, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "profile creator: %s\n", tmpbuf);

	// TODO: pos=84-99 Profile ID

	de_dbg_indent(c, -1);
}

static const struct datatypeinfo *lookup_datatypeinfo(de_uint32 id)
{
	de_int64 k;
	for(k=0; k<ITEMS_IN_ARRAY(datatypeinfo_arr); k++) {
		if(datatypeinfo_arr[k].id == id) {
			return &datatypeinfo_arr[k];
		}
	}
	return NULL;
}

static const struct taginfo *lookup_taginfo(de_uint32 id)
{
	de_int64 k;
	for(k=0; k<ITEMS_IN_ARRAY(taginfo_arr); k++) {
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

	if(tagdataoffset>=c->infile->len) return;
	if(tagdatalen<4) return;

	if(is_duplicate_data(c, d, tagindex, tagdataoffset, tagdatalen, &idx_of_dup)) {
		de_dbg(c, "[data is a duplicate of tag #%d]\n", (int)idx_of_dup);
		return;
	}

	dbuf_read_fourcc(c->infile, tagdataoffset, &tagtype4cc, 0);
	dti = lookup_datatypeinfo(tagtype4cc.id);
	if(dti && dti->name) dtname=dti->name;
	else dtname="?";
	de_dbg(c, "data type: '%s' (%s)\n", tagtype4cc.id_printable, dtname);

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

	dbuf_read_fourcc(c->infile, pos_in_tagtable, &tag4cc, 0);
	tagdataoffset = de_getui32be(pos_in_tagtable+4);
	tagdatalen = de_getui32be(pos_in_tagtable+8);
	ti = lookup_taginfo(tag4cc.id);
	if(ti && ti->name)
		tname = ti->name;
	else
		tname = "?";
	de_dbg(c, "tag #%d '%s' (%s) offset=%d dlen=%d\n", (int)tagindex,
		tag4cc.id_printable, tname,
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

	de_dbg(c, "tag table at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	d->num_tags = de_getui32be(pos1);
	de_dbg(c, "number of tags: %d\n", (int)d->num_tags);
	if(d->num_tags>500) {
		de_err(c, "Invalid or excessive number of tags: %d\n", (int)d->num_tags);
		goto done;
	}
	de_dbg(c, "expected start of data segment: %d\n", (int)(pos1+4+12*d->num_tags));

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
	de_msg(c, "Note: ICC profiles can be parsed, but no files can be extracted from them.\n");

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
	mi->flags |= DE_MODFLAG_HIDDEN;
}
