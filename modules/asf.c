// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft ASF

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_asf);

typedef struct localctx_struct {
	int reserved;
} lctx;

struct object_info;

struct handler_params {
	de_int64 objpos;
	de_int64 objlen;
	de_int64 dpos;
	de_int64 dlen;
	int level;
	const struct object_info *uui;
};
typedef void (*handler_fn_type)(deark *c, lctx *d, struct handler_params *hp);

static int do_object_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level,
	int known_object_count, de_int64 num_objects_expected);

static void handler_Header(deark *c, lctx *d, struct handler_params *hp)
{
	de_int64 numhdrobj;

	if(hp->dlen<6) return;
	numhdrobj = de_getui32le(hp->dpos);
	de_dbg(c, "number of header objects: %u", (unsigned int)numhdrobj);
	do_object_sequence(c, d, hp->dpos+6, hp->dlen-6, hp->level+1, 1, numhdrobj);
}

static void handler_StreamProperties(deark *c, lctx *d, struct handler_params *hp)
{
	de_int64 pos = hp->dpos;
	de_byte stream_type[16];
	de_byte ec_type[16];
	char stream_type_string[50];
	char ec_type_string[50];

	if(hp->dlen<54) return;

	de_read(stream_type, pos, 16);
	de_fmtutil_guid_to_uuid(stream_type);
	de_fmtutil_render_uuid(c, stream_type, stream_type_string, sizeof(stream_type_string));
	// TODO: Decode the stream type and EC type
	de_dbg(c, "stream type: {%s}", stream_type_string);
	pos += 16;

	de_read(ec_type, pos, 16);
	de_fmtutil_guid_to_uuid(ec_type);
	de_fmtutil_render_uuid(c, ec_type, ec_type_string, sizeof(ec_type_string));
	de_dbg(c, "error correction type: {%s}", ec_type_string);
	pos += 16;

	// TODO: There are more fields here
}

static void handler_HeaderExtension(deark *c, lctx *d, struct handler_params *hp)
{
	de_int64 datasize;

	if(hp->dlen<22) return;
	datasize = de_getui32le(hp->dpos+18);
	de_dbg(c, "extension data size: %u", (unsigned int)datasize);
	if(datasize > hp->dlen-22) datasize = hp->dlen-22;
	do_object_sequence(c, d, hp->dpos+22, datasize, hp->level+1, 0, 0);
}

static int do_codec_entry(deark *c, lctx *d, de_int64 pos1, de_int64 len, de_int64 *bytes_consumed)
{
	de_ucstring *name = NULL;
	de_ucstring *descr = NULL;
	de_int64 type;
	de_int64 namelen, descrlen, infolen;
	de_int64 pos = pos1;
	int retval = 0;
	int saved_indent_level;

	*bytes_consumed = 0;
	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "codec entry at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(len<8) goto done;
	type = de_getui16le(pos);
	// TODO: Decode the type
	de_dbg(c, "type: %d", (int)type);
	pos += 2;

	namelen = de_getui16le(pos);
	pos += 2;
	name = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, namelen*2, DE_DBG_MAX_STRLEN*2, name,
		0, DE_ENCODING_UTF16LE);
	ucstring_truncate_at_NUL(name);
	de_dbg(c, "name: \"%s\"", ucstring_get_printable_sz(name));
	pos += namelen*2;

	descrlen = de_getui16le(pos);
	pos += 2;
	descr = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, descrlen*2, DE_DBG_MAX_STRLEN*2, descr,
		0, DE_ENCODING_UTF16LE);
	ucstring_truncate_at_NUL(descr);
	de_dbg(c, "description: \"%s\"", ucstring_get_printable_sz(descr));
	pos += descrlen*2;

	infolen = de_getui16le(pos);
	pos += 2;
	if(infolen>0) {
		de_dbg(c, "codec information (%d bytes)", (int)infolen);
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, c->infile, pos, infolen, 256, "data", 0x1);
		de_dbg_indent(c, -1);
	}
	pos += infolen;

	*bytes_consumed = pos-pos1;
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(name);
	ucstring_destroy(descr);
	return retval;
}

static void handler_CodecList(deark *c, lctx *d, struct handler_params *hp)
{
	de_int64 numentries;
	de_int64 k;
	de_int64 pos;

	if(hp->dlen<20) return;
	numentries = de_getui32le(hp->dpos+16);
	de_dbg(c, "number of codec entries: %d", (int)numentries);

	pos = hp->dpos+20;
	for(k=0; k<numentries; k++) {
		de_int64 bytes_consumed = 0;
		int ret;

		if(pos >= hp->dpos + hp->dlen) break;
		ret = do_codec_entry(c, d, pos, hp->dpos+hp->dlen-pos, &bytes_consumed);
		if(!ret || (bytes_consumed<8)) break;
		pos += bytes_consumed;
	}
}

struct object_info {
	de_uint32 short_id;
	de_uint32 flags;
	const de_byte uuid[16];
	const char *name;
	handler_fn_type hfn;
};
static const struct object_info object_info_arr[] = {
	{101, 0, {0x75,0xb2,0x26,0x30,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Header", handler_Header},
	{102, 0, {0x75,0xb2,0x26,0x36,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Data", NULL},
	{103, 0, {0x33,0x00,0x08,0x90,0xe5,0xb1,0x11,0xcf,0x89,0xf4,0x00,0xa0,0xc9,0x03,0x49,0xcb}, "Simple Index", NULL},
	{104, 0, {0xd6,0xe2,0x29,0xd3,0x35,0xda,0x11,0xd1,0x90,0x34,0x00,0xa0,0xc9,0x03,0x49,0xbe}, "Index", NULL},
	{105, 0, {0xfe,0xb1,0x03,0xf8,0x12,0xad,0x4c,0x64,0x84,0x0f,0x2a,0x1d,0x2f,0x7a,0xd4,0x8c}, "Media Object Index", NULL},
	{106, 0, {0x3c,0xb7,0x3f,0xd0,0x0c,0x4a,0x48,0x03,0x95,0x3d,0xed,0xf7,0xb6,0x22,0x8f,0x0c}, "Timecode Index", NULL},
	{201, 0, {0x8c,0xab,0xdc,0xa1,0xa9,0x47,0x11,0xcf,0x8e,0xe4,0x00,0xc0,0x0c,0x20,0x53,0x65}, "File Properties", NULL},
	{202, 0, {0xb7,0xdc,0x07,0x91,0xa9,0xb7,0x11,0xcf,0x8e,0xe6,0x00,0xc0,0x0c,0x20,0x53,0x65}, "Stream Properties", handler_StreamProperties},
	{203, 0, {0x5f,0xbf,0x03,0xb5,0xa9,0x2e,0x11,0xcf,0x8e,0xe3,0x00,0xc0,0x0c,0x20,0x53,0x65}, "Header Extension", handler_HeaderExtension},
	{204, 0, {0x86,0xd1,0x52,0x40,0x31,0x1d,0x11,0xd0,0xa3,0xa4,0x00,0xa0,0xc9,0x03,0x48,0xf6}, "Codec List", handler_CodecList},
	{205, 0, {0x1e,0xfb,0x1a,0x30,0x0b,0x62,0x11,0xd0,0xa3,0x9b,0x00,0xa0,0xc9,0x03,0x48,0xf6}, "Script Command", NULL},
	{206, 0, {0xf4,0x87,0xcd,0x01,0xa9,0x51,0x11,0xcf,0x8e,0xe6,0x00,0xc0,0x0c,0x20,0x53,0x65}, "Marker", NULL},
	{207, 0, {0xd6,0xe2,0x29,0xdc,0x35,0xda,0x11,0xd1,0x90,0x34,0x00,0xa0,0xc9,0x03,0x49,0xbe}, "Bitrate Mutual Exclusion", NULL},
	{208, 0, {0x75,0xb2,0x26,0x35,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Error Correction", NULL},
	{209, 0, {0x75,0xb2,0x26,0x33,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Content Description", NULL},
	{210, 0, {0xd2,0xd0,0xa4,0x40,0xe3,0x07,0x11,0xd2,0x97,0xf0,0x00,0xa0,0xc9,0x5e,0xa8,0x50}, "Extended Content Description", NULL},
	{211, 0, {0x22,0x11,0xb3,0xfa,0xbd,0x23,0x11,0xd2,0xb4,0xb7,0x00,0xa0,0xc9,0x55,0xfc,0x6e}, "Content Branding", NULL},
	{212, 0, {0x7b,0xf8,0x75,0xce,0x46,0x8d,0x11,0xd1,0x8d,0x82,0x00,0x60,0x97,0xc9,0xa2,0xb2}, "Stream Bitrate Properties", NULL},
	{213, 0, {0x22,0x11,0xb3,0xfb,0xbd,0x23,0x11,0xd2,0xb4,0xb7,0x00,0xa0,0xc9,0x55,0xfc,0x6e}, "Content Encryption", NULL},
	{214, 0, {0x29,0x8a,0xe6,0x14,0x26,0x22,0x4c,0x17,0xb9,0x35,0xda,0xe0,0x7e,0xe9,0x28,0x9c}, "Extended Content Encryption", NULL},
	{215, 0, {0x22,0x11,0xb3,0xfc,0xbd,0x23,0x11,0xd2,0xb4,0xb7,0x00,0xa0,0xc9,0x55,0xfc,0x6e}, "Digital Signature", NULL},
	{216, 0, {0x18,0x06,0xd4,0x74,0xca,0xdf,0x45,0x09,0xa4,0xba,0x9a,0xab,0xcb,0x96,0xaa,0xe8}, "Padding", NULL},
	{301, 0, {0x14,0xe6,0xa5,0xcb,0xc6,0x72,0x43,0x32,0x83,0x99,0xa9,0x69,0x52,0x06,0x5b,0x5a}, "Extended Stream Properties", NULL},
	{302, 0, {0xa0,0x86,0x49,0xcf,0x47,0x75,0x46,0x70,0x8a,0x16,0x6e,0x35,0x35,0x75,0x66,0xcd}, "Advanced Mutual Exclusion", NULL},
	{303, 0, {0xd1,0x46,0x5a,0x40,0x5a,0x79,0x43,0x38,0xb7,0x1b,0xe3,0x6b,0x8f,0xd6,0xc2,0x49}, "Group Mutual Exclusion", NULL},
	{304, 0, {0xd4,0xfe,0xd1,0x5b,0x88,0xd3,0x45,0x4f,0x81,0xf0,0xed,0x5c,0x45,0x99,0x9e,0x24}, "Stream Prioritization", NULL},
	{305, 0, {0xa6,0x96,0x09,0xe6,0x51,0x7b,0x11,0xd2,0xb6,0xaf,0x00,0xc0,0x4f,0xd9,0x08,0xe9}, "Bandwidth Sharing", NULL},
	{306, 0, {0x7c,0x43,0x46,0xa9,0xef,0xe0,0x4b,0xfc,0xb2,0x29,0x39,0x3e,0xde,0x41,0x5c,0x85}, "Language List", NULL},
	{307, 0, {0xc5,0xf8,0xcb,0xea,0x5b,0xaf,0x48,0x77,0x84,0x67,0xaa,0x8c,0x44,0xfa,0x4c,0xca}, "Metadata", NULL},
	{308, 0, {0x44,0x23,0x1c,0x94,0x94,0x98,0x49,0xd1,0xa1,0x41,0x1d,0x13,0x4e,0x45,0x70,0x54}, "Metadata Library", NULL},
	{309, 0, {0xd6,0xe2,0x29,0xdf,0x35,0xda,0x11,0xd1,0x90,0x34,0x00,0xa0,0xc9,0x03,0x49,0xbe}, "Index Parameters", NULL},
	{310, 0, {0x6b,0x20,0x3b,0xad,0x3f,0x11,0x48,0xe4,0xac,0xa8,0xd7,0x61,0x3d,0xe2,0xcf,0xa7}, "Media Object Index Parameters", NULL},
	{311, 0, {0xf5,0x5e,0x49,0x6d,0x97,0x97,0x4b,0x5d,0x8c,0x8b,0x60,0x4d,0xfe,0x9b,0xfb,0x24}, "Timecode Index Parameters", NULL},
	{312, 0, {0x26,0xf1,0x8b,0x5d,0x45,0x84,0x47,0xec,0x9f,0x5f,0x0e,0x65,0x1f,0x04,0x52,0xc9}, "Compatibility", NULL},
	{313, 0, {0x43,0x05,0x85,0x33,0x69,0x81,0x49,0xe6,0x9b,0x74,0xad,0x12,0xcb,0x86,0xd5,0x8c}, "Advanced Content Encryption", NULL},
	{330, 0, {0xd9,0xaa,0xde,0x20,0x7c,0x17,0x4f,0x9c,0xbc,0x28,0x85,0x55,0xdd,0x98,0xe2,0xa2}, "Index Placeholder", NULL}
};

static const struct object_info *find_object_info(const de_byte *uuid)
{
	size_t k;
	for(k=0; k<DE_ITEMS_IN_ARRAY(object_info_arr); k++) {
		if(!de_memcmp(uuid, object_info_arr[k].uuid, 16)) {
			return &object_info_arr[k];
		}
	}
	return NULL;
}

static int do_object(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	int level, de_int64 *pbytes_consumed)
{
	de_byte id[16];
	char id_string[50];
	const char *id_name = NULL;
	int retval = 0;
	int saved_indent_level;
	struct handler_params *hp = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	*pbytes_consumed = 0;
	if(len<24) goto done;

	de_dbg(c, "object at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);

	hp = de_malloc(c, sizeof(struct handler_params));
	hp->objpos = pos1;
	hp->level = level;

	de_read(id, pos1, 16);
	de_fmtutil_guid_to_uuid(id);
	de_fmtutil_render_uuid(c, id, id_string, sizeof(id_string));

	hp->uui = find_object_info(id);
	if(hp->uui) id_name = hp->uui->name;
	if(!id_name) id_name = "?";

	de_dbg(c, "guid: {%s} (%s)", id_string, id_name);

	hp->objlen = de_geti64le(pos1+16);
	hp->dpos = pos1 + 24;
	hp->dlen = hp->objlen - 24;
	de_dbg(c, "size: %"INT64_FMT", dpos=%"INT64_FMT", dlen=%"INT64_FMT,
		hp->objlen, hp->dpos, hp->dlen);
	if(hp->objlen<24) goto done;

	if(hp->objlen > len) {
		// TODO: Handle this differently depending on whether the problem was
		// an unexpected end of file.
		de_warn(c, "Object at %"INT64_FMT" (length %"INT64_FMT") exceeds its parent's bounds",
			pos1, hp->objlen);
		goto done;
	}

	if(hp->uui && hp->uui->hfn) {
		hp->uui->hfn(c, d, hp);
	}

	*pbytes_consumed = hp->objlen;
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, hp);
	return retval;
}

static int do_object_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level,
	int known_object_count, de_int64 num_objects_expected)
{
	int retval = 0;
	de_int64 pos = pos1;
	int saved_indent_level;
	de_int64 bytes_remaining;
	de_int64 objects_found = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	if(level >= 16) { // An arbitrary recursion limit
		goto done;
	}

	while(1) {
		int ret;
		de_int64 bytes_consumed = 0;

		bytes_remaining = pos1+len-pos;
		if(known_object_count && objects_found>=num_objects_expected) {
			break;
		}

		if(bytes_remaining<24) {
			break;
		}

		ret = do_object(c, d, pos, bytes_remaining, level, &bytes_consumed);
		if(!ret) goto done;
		if(bytes_consumed<24) goto done;

		objects_found++;
		pos += bytes_consumed;
	}

	bytes_remaining = pos1+len-pos;
	if(bytes_remaining>0) {
		de_dbg(c, "[%d extra bytes at %"INT64_FMT"]", (int)bytes_remaining, pos);
	}

	if(known_object_count && objects_found<num_objects_expected) {
		de_warn(c, "Expected %d objects at %"INT64_FMT", only found %d", (int)num_objects_expected,
			pos1, (int)objects_found);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_asf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	de_msg(c, "Note: ASF files can be parsed, but no files can be extracted from them.");

	do_object_sequence(c, d, 0, c->infile->len, 0, 0, 0);

	de_free(c, d);
}

static int de_identify_asf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0,
		"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c", 16))
	{
		return 100;
	}
	return 0;
}

void de_module_asf(deark *c, struct deark_module_info *mi)
{
	mi->id = "asf";
	mi->desc = "ASF/WMV (Microsoft multimedia format)";
	mi->run_fn = de_run_asf;
	mi->identify_fn = de_identify_asf;
}
