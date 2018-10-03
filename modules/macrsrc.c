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
} lctx;

struct rsrctypeinfo {
	struct de_fourcc fcc;
};

struct rsrcinstanceinfo {
	unsigned int id;
	de_byte attribs;
	de_int64 data_offset;
};

static int looks_like_pict(deark *c, lctx *d, struct rsrcinstanceinfo *rii,
	de_int64 pos, de_int64 len)
{
	if(rii->attribs&0x01) return 0; // compressed
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
	else if(rti->fcc.id==CODE_PICT && looks_like_pict(c, d, rii, dpos, dlen)) {
		ext = "pict";
		extr_flag = 1;
		is_pict = 1;
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

static void do_resource_record(deark *c, lctx *d, struct rsrctypeinfo *rti,
	de_int64 pos1)
{
	de_int64 dataOffset_rel;
	de_int64 pos = pos1;
	struct rsrcinstanceinfo rii;

	de_memset(&rii, 0, sizeof(struct rsrcinstanceinfo));
	rii.id = (unsigned int)de_getui16be_p(&pos);
	de_dbg(c, "id: %u", rii.id);
	pos += 2; // nameOffset;
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

	count = 1+de_getui16be_p(&pos);
	de_dbg(c, "count: %d", (int)count);
	list_offs_rel = de_getui16be_p(&pos);
	de_dbg(c, "list offset: (%d+)%d", (int)type_list_offs, (int)list_offs_rel);

	do_resource_list(c, d, &rti, type_list_offs+list_offs_rel, count);
}

static void do_type_list(deark *c, lctx *d, de_int64 pos1)
{
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
	nameListOffset_rel = de_getui16be_p(&pos);
	de_dbg(c, "name list offset: (%d+)%d", (int)map_offs,
		(int)nameListOffset_rel);

	if(typeListOffset_rel<28) {
		de_err(c, "Invalid typeListOffset");
		goto done;
	}

	do_type_list(c, d, map_offs+typeListOffset_rel);

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
