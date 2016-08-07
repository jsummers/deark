// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ICC Profile format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iccprofile);

typedef struct localctx_struct {
	unsigned int profile_ver_major;
	unsigned int profile_ver_minor;
	unsigned int profile_ver_bugfix;
} lctx;

#define ITEMS_IN_ARRAY(x) (sizeof(x)/sizeof(x[0]))

typedef void (*datatype_decoder_fn_type)(deark *c, lctx *d, de_int64 pos, de_int64 len);

static void typedec_text(deark *c, lctx *d, de_int64 pos, de_int64 len);

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
	{ 0x64657363U, "textDescription", NULL }, // desc
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x6D667431U, "lut8", NULL }, // mft1
	{ 0x6D667432U, "lut16", NULL }, // mft2
	{ 0x6D6C7563U, "multiLocalizedUnicode", NULL }, // mluc
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
	{ 0x62545243U, "blueTRC", NULL }, // bTRC
	{ 0x6258595AU, "blueColorant", NULL }, // bXYZ
	{ 0x626B7074U, "mediaBlackPoint", NULL }, // bkpt
	{ 0x63686164U, "chromaticAdaptation", NULL }, // chad
	{ 0x636C7274U, "colorantTable", NULL }, // clrt
	{ 0x63707274U, "copyright", NULL }, // cprt
	{ 0x64657363U, "profileDescription", NULL }, // desc
	{ 0x646D6464U, "deviceModelDesc", NULL }, // dmdd
	{ 0x646D6E64U, "deviceMfgDesc", NULL }, // dmnd
	{ 0x67545243U, "greenTRC", NULL }, // gTRC
	{ 0x6758595AU, "greenColorant", NULL }, // gXYZ
	{ 0x6C756D69U, "luminance", NULL }, // lumi
	{ 0x6D656173U, "measurement", NULL }, // meas
	{ 0x72545243U, "redTRC", NULL }, // rTRC
	{ 0x7258595AU, "redColorant", NULL }, // rXYZ
	{ 0x74617267U, "charTarget", NULL }, // targ
	{ 0x74656368U, "technology", NULL }, // tech
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

	if(len<0) goto done;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+8, textlen, s, 0, DE_ENCODING_ASCII);
	ucstring_to_printable_sz(s, buf, sizeof(buf));
	de_dbg(c, "text: \"%s\"\n", buf);

done:
	ucstring_destroy(s);
	return;
}

static void do_read_header(deark *c, lctx *d, de_int64 pos)
{
	de_uint32 profile_ver_raw;
	de_int64 x;
	struct de_fourcc tmp4cc;
	char tmpbuf[16];

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	x = de_getui32be(pos+0);
	de_dbg(c, "profile size: %d\n", (int)x);

	dbuf_read_fourcc(c->infile, pos+4, &tmp4cc, 0);
	de_dbg(c, "preferred CMM type: '%s'\n", tmp4cc.id_printable);

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
	de_dbg(c, "device manufacturer: %s\n", tmpbuf);

	dbuf_read_fourcc(c->infile, pos+52, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "device model: %s\n", tmpbuf);

	// TODO: pos=56-63 Device attributes

	x = de_getui32be(pos+64);
	de_dbg(c, "rendering intent: %d\n", (int)x);
	// TODO: name the rendering intent field

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

static void do_tag_data(deark *c, lctx *d, const struct de_fourcc *tag4cc,
	const struct taginfo *ti,
	de_int64 tagdataoffset, de_int64 tagdatalen)
{
	struct de_fourcc tagtype4cc;
	const struct datatypeinfo *dti;
	const char *dtname;

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
	do_tag_data(c, d, &tag4cc, ti, tagdataoffset, tagdatalen);
	de_dbg_indent(c, -1);
}

static void do_read_tags(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 tagindex;
	de_int64 num_tags;

	de_dbg(c, "tag table at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	num_tags = de_getui32be(pos1);
	de_dbg(c, "number of tags: %d\n", (int)num_tags);
	if(num_tags>500) {
		de_err(c, "Invalid or excessive number of tags: %d\n", (int)num_tags);
		goto done;
	}
	de_dbg(c, "expected offset of data segment: %d\n", (int)(pos1+4+12*num_tags));

	for(tagindex=0; tagindex<num_tags; tagindex++) {
		do_tag(c, d, tagindex, pos1+4+12*tagindex);
	}

done:
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
