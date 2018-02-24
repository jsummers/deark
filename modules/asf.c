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

struct object_info {
	de_uint32 short_id;
	de_uint32 flags;
	const de_byte uuid[16];
	const char *name;
	void *reserved;
};
static const struct object_info object_info_arr[] = {
	{101, 0, {0x75,0xb2,0x26,0x30,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Header", NULL},
	{102, 0, {0x75,0xb2,0x26,0x36,0x66,0x8e,0x11,0xcf,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c}, "Data", NULL},
	{103, 0, {0x33,0x00,0x08,0x90,0xe5,0xb1,0x11,0xcf,0x89,0xf4,0x00,0xa0,0xc9,0x03,0x49,0xcb}, "Simple Index", NULL},
	{104, 0, {0xd6,0xe2,0x29,0xd3,0x35,0xda,0x11,0xd1,0x90,0x34,0x00,0xa0,0xc9,0x03,0x49,0xbe}, "Index", NULL},
	{201, 0, {0x8c,0xab,0xdc,0xa1,0xa9,0x47,0x11,0xcf,0x8e,0xe4,0x00,0xc0,0x0c,0x20,0x53,0x65}, "File Properties", NULL},
	{204, 0, {0x86,0xd1,0x52,0x40,0x31,0x1d,0x11,0xd0,0xa3,0xa4,0x00,0xa0,0xc9,0x03,0x48,0xf6}, "Codec List", NULL}
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

static int do_object_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level);

static int do_object(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	int level, de_int64 *pbytes_consumed)
{
	de_int64 objlen;
	de_int64 dlen;
	de_int64 dpos;
	de_byte id[16];
	char id_string[50];
	const struct object_info *uui;
	const char *id_name;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	*pbytes_consumed = 0;
	if(len<24) goto done;

	de_dbg(c, "object at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_read(id, pos1, 16);
	de_fmtutil_guid_to_uuid(id);
	de_fmtutil_render_uuid(c, id, id_string, sizeof(id_string));

	uui = find_object_info(id);
	if(uui) id_name = uui->name;
	else id_name = "?";

	de_dbg(c, "guid: {%s} (%s)", id_string, id_name);

	objlen = de_geti64le(pos1+16);
	dpos = pos1 + 24;
	dlen = objlen - 24;
	de_dbg(c, "size: %"INT64_FMT", dpos=%"INT64_FMT", dlen=%"INT64_FMT,
		objlen, dpos, dlen);
	if(objlen<24) goto done;

	if(objlen > len) {
		// TODO: Handle this differently depending on whether the problem was
		// an unexpected end of file.
		de_warn(c, "Object at %"INT64_FMT" (length %"INT64_FMT") exceeds its parent's bounds",
			pos1, objlen);
		goto done;
	}

	if(uui && (uui->short_id==101)) { // Header
		de_int64 numhdrobj;
		numhdrobj = de_getui32le(dpos);
		de_dbg(c, "number of header objects: %u", (unsigned int)numhdrobj);
		do_object_sequence(c, d, dpos+6, dlen-6, level+1);
	}

	*pbytes_consumed = objlen;
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_object_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level)
{
	int retval = 0;
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(level >= 16) { // An arbitrary recursion limit
		goto done;
	}

	while(1) {
		int ret;
		de_int64 bytes_consumed = 0;

		ret = do_object(c, d, pos, pos1+len-pos, level, &bytes_consumed);
		if(!ret) goto done;
		if(bytes_consumed<24) goto done;

		pos += bytes_consumed;
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

	do_object_sequence(c, d, 0, c->infile->len, 0);

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
