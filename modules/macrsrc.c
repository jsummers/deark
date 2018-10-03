// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Mac Resource [Manager] format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_macrsrc);

#define CODE_PICT 0x50494354U

typedef struct localctx_struct {
	de_int64 data_offs, map_offs;
	de_int64 data_size, map_size;

	de_int64 typeListOffset_abs;
	de_int64 nameListOffset_abs;
	dbuf *icns_stream;
} lctx;

struct rsrctypeinfo {
	struct de_fourcc fcc;
	int is_icns_type;
};

struct rsrcinstanceinfo {
	unsigned int id;
	de_byte attribs;
	de_int64 data_offset;
};

#define CODE_icns 0x69636e73U

#define CODE_ICN_ 0x49434e23U // ICN#
#define CODE_ICON 0x49434f4eU
#define CODE_icl4 0x69636c34U
#define CODE_icl8 0x69636c38U
#define CODE_icm_ 0x69636d23U // icm#
#define CODE_icm4 0x69636d34U
#define CODE_icm8 0x69636d38U
#define CODE_ics_ 0x69637323U // ics#
#define CODE_ics4 0x69637334U
#define CODE_ics8 0x69637338U

static int is_icns_icon(deark *c, lctx *d, struct rsrctypeinfo *rti)
{
	// TODO: There are many more icns icon types, but it's not clear
	// to me if any others are found in resource forks.
	switch(rti->fcc.id) {
	case CODE_icm_: case CODE_icm4: case CODE_icm8: // 16x12
	case CODE_ics_: case CODE_ics4: case CODE_ics8: // 16x16
	case CODE_ICN_: case CODE_ICON: case CODE_icl4: case CODE_icl8: // 32x32
		return 1;
	}
	return 0;
}

static void open_icns_stream(deark *c, lctx *d)
{
	if(d->icns_stream) return;

	d->icns_stream = dbuf_create_membuf(c, 0, 0);
}

// Construct an .icns file from the suitable icon resources found
// in this file.
static void finalize_icns_stream(deark *c, lctx *d)
{
	dbuf *outf = NULL;

	if(!d->icns_stream) return;

	outf = dbuf_create_output_file(c, "icns", NULL, 0);
	dbuf_writeui32be(outf, CODE_icns);
	dbuf_writeui32be(outf, 8+d->icns_stream->len);
	dbuf_copy(d->icns_stream, 0, d->icns_stream->len, outf);
	dbuf_close(outf);

	dbuf_close(d->icns_stream);
	d->icns_stream = NULL;
}

static int looks_like_pict(deark *c, lctx *d, struct rsrcinstanceinfo *rii,
	de_int64 pos, de_int64 len)
{
	if(len>=12 && !dbuf_memcmp(c->infile, pos+10, "\x11\x01", 2)) {
		return 1; // PICTv1
	}
	if(len>=16 && !dbuf_memcmp(c->infile, pos+10, "\x00\x11\x02\xff\x0c\x00", 6)) {
		return 1; // PICTv2
	}
	return 0;
}

static void do_resource_data(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii)
{
	de_int64 dpos, dlen;
	const char *ext = "bin";
	int extr_flag = 0;
	int is_pict = 0;
	dbuf *outf = NULL;

	de_dbg(c, "resource data at %d", (int)rii->data_offset);
	de_dbg_indent(c, 1);
	dlen = de_getui32be(rii->data_offset);
	dpos = rii->data_offset+4;
	de_dbg(c, "dpos: %d, dlen: %d", (int)dpos, (int)dlen);
	if(dpos+dlen > c->infile->len) goto done;

	if(c->extract_level>=2) {
		extr_flag = 1;
	}
	else if(rii->attribs&0x01) {
		// Compressed. Don't know how to handle this.
	}
	else if(rti->fcc.id==CODE_PICT && looks_like_pict(c, d, rii, dpos, dlen)) {
		ext = "pict";
		extr_flag = 1;
		is_pict = 1;
	}
	else if(rti->fcc.id==CODE_icns) {
		ext = "icns";
		extr_flag = 1;
	}
	else if(rti->is_icns_type) {
		de_dbg(c, "[icns resource]");
		open_icns_stream(c, d);
		dbuf_write(d->icns_stream, rti->fcc.bytes, 4);
		dbuf_writeui32be(d->icns_stream, 8+dlen);
		dbuf_copy(c->infile, dpos, dlen, d->icns_stream);
	}

	if(extr_flag) {
		outf = dbuf_create_output_file(c, ext, NULL, 0);
		if(is_pict) {
			dbuf_write_zeroes(outf, 512);
		}
		dbuf_copy(c->infile, dpos, dlen, outf);
	}

done:
	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

static void read_resource_name(deark *c, lctx *d, struct rsrcinstanceinfo *rii,
	de_int64 pos)
{
	de_int64 nlen;
	de_ucstring *rname = NULL;

	nlen = (de_int64)de_getbyte(pos);
	rname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+1, nlen, rname, 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(rname));
	ucstring_destroy(rname);
}

static void do_resource_record(deark *c, lctx *d, struct rsrctypeinfo *rti,
	de_int64 pos1)
{
	de_int64 dataOffset_rel;
	de_int64 nameOffset_rel;
	de_int64 pos = pos1;
	struct rsrcinstanceinfo rii;

	de_memset(&rii, 0, sizeof(struct rsrcinstanceinfo));
	rii.id = (unsigned int)de_getui16be_p(&pos);
	de_dbg(c, "id: %u", rii.id);
	nameOffset_rel = de_getui16be_p(&pos);
	if(nameOffset_rel!=0xffff) {
		de_dbg(c, "nameOffset: (%d+)%d", (int)d->nameListOffset_abs, (int)nameOffset_rel);
		read_resource_name(c, d, &rii, d->nameListOffset_abs+nameOffset_rel);
	}
	rii.attribs = de_getbyte_p(&pos);
	de_dbg(c, "attributes: 0x%02x", (unsigned int)rii.attribs);

	dataOffset_rel = dbuf_getint_ext(c->infile, pos, 3, 0, 0);
	rii.data_offset = d->data_offs + dataOffset_rel;
	pos += 3;
	de_dbg(c, "dataOffset: (%d+)%d", (int)d->data_offs, (int)dataOffset_rel);
	do_resource_data(c, d, rti, &rii);
}

static void do_resource_list(deark *c, lctx *d, struct rsrctypeinfo *rti,
	de_int64 rsrc_list_offs, de_int64 count)
{
	de_int64 k;
	de_int64 pos = rsrc_list_offs;

	de_dbg(c, "resource list at %d", (int)rsrc_list_offs);
	de_dbg_indent(c, 1);
	for(k=0; k<count; k++) {
		de_dbg(c, "resource record[%d] at %d", (int)k, (int)pos);
		de_dbg_indent(c, 1);
		do_resource_record(c, d, rti, pos);
		de_dbg_indent(c, -1);
		pos += 12;
	}
	de_dbg_indent(c, -1);
}

static void do_type_item(deark *c, lctx *d, de_int64 type_list_offs,
	de_int64 idx, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 count;
	de_int64 list_offs_rel;
	struct rsrctypeinfo rti;

	de_memset(&rti, 0, sizeof(struct rsrctypeinfo));
	dbuf_read_fourcc(c->infile, pos, &rti.fcc, 4, 0x0);
	de_dbg(c, "resource type: '%s'", rti.fcc.id_dbgstr);
	pos += 4;
	rti.is_icns_type = is_icns_icon(c, d, &rti);

	count = 1+de_getui16be_p(&pos);
	de_dbg(c, "count: %d", (int)count);
	list_offs_rel = de_getui16be_p(&pos);
	de_dbg(c, "list offset: (%d+)%d", (int)type_list_offs, (int)list_offs_rel);

	do_resource_list(c, d, &rti, type_list_offs+list_offs_rel, count);
}

static void do_type_list(deark *c, lctx *d)
{
	de_int64 pos1 = d->typeListOffset_abs;
	de_int64 pos = pos1;
	de_int64 type_count_raw;
	de_int64 type_count;
	de_int64 k;

	de_dbg(c, "type list at %d", (int)pos1);
	de_dbg_indent(c, 1);
	type_count_raw = de_getui16be_p(&pos);
	type_count = (type_count_raw==0xffff)?0:(type_count_raw+1);
	de_dbg(c, "count: %d", (int)type_count);

	for(k=0; k<type_count; k++) {
		de_dbg(c, "type record[%d] at %d", (int)k, (int)pos);
		de_dbg_indent(c, 1);
		do_type_item(c, d, pos1, k, pos);
		pos += 8;
		de_dbg_indent(c, -1);
	}
	de_dbg_indent(c, -1);
}

static void do_map(deark *c, lctx *d, de_int64 map_offs, de_int64 map_size)
{
	de_int64 pos = map_offs;
	de_int64 typeListOffset_rel, nameListOffset_rel;
	de_int64 n;

	n = de_getui32be(map_offs+4);
	if(n!=map_offs) {
		de_err(c, "Resource map section not found, expected to be at %d", (int)map_offs);
		return;
	}

	de_dbg(c, "resource map section at %d", (int)map_offs);
	de_dbg_indent(c, 1);

	pos += 16; // copy of header
	pos += 4; // nextResourceMap
	pos += 2; // fileRef
	pos += 2; // attributes

	typeListOffset_rel = de_getui16be_p(&pos);
	de_dbg(c, "type list offset: (%d+)%d", (int)map_offs,
		(int)typeListOffset_rel);
	d->typeListOffset_abs = map_offs + typeListOffset_rel;

	nameListOffset_rel = de_getui16be_p(&pos);
	de_dbg(c, "name list offset: (%d+)%d", (int)map_offs,
		(int)nameListOffset_rel);
	d->nameListOffset_abs = map_offs + nameListOffset_rel;

	if(typeListOffset_rel<28) {
		de_err(c, "Invalid typeListOffset");
		goto done;
	}

	do_type_list(c, d);

done:
	de_dbg_indent(c, 1);
}

static void de_run_macrsrc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	d->data_offs = de_getui32be_p(&pos);
	d->map_offs = de_getui32be_p(&pos);
	d->data_size = de_getui32be_p(&pos);
	d->map_size = de_getui32be_p(&pos);
	de_dbg(c, "data: pos=%"INT64_FMT", len=%"INT64_FMT, d->data_offs, d->data_size);
	de_dbg(c, "map: pos=%"INT64_FMT", len=%"INT64_FMT, d->map_offs, d->map_size);
	do_map(c, d, d->map_offs, d->map_size);
	finalize_icns_stream(c, d);
	de_free(c, d);
}

static int de_identify_macrsrc(deark *c)
{
	de_byte b[16];
	de_int64 n[4];
	size_t k;

	if(de_getui32be(0)!=256) return 0;
	de_read(b, 0, 16);
	for(k=0; k<4; k++) {
		n[k] = de_getui32be_direct(&b[4*k]);
	}
	if(n[0]+n[2]>n[1]) return 0; // data can't go past map start
	if(n[3]<30) return 0; // minimum map len
	if(n[1]+n[3]>c->infile->len) return 0; // map can't go past eof
	// map should start with a copy of the header
	if(dbuf_memcmp(c->infile, n[1], (const void*)b, 16)) return 0;
	return 75;
}

void de_module_macrsrc(deark *c, struct deark_module_info *mi)
{
	mi->id = "macrsrc";
	mi->desc = "Macintosh Resource Manager";
	mi->run_fn = de_run_macrsrc;
	mi->identify_fn = de_identify_macrsrc;
}
