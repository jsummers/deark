// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// RISC OS Draw / Acorn Draw / ArcDraw

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rodraw);

struct objinfo {
	u32 objtype;
	int hasbbox;
	i64 objsize;
	i64 objpos;
	i64 dpos;
	i64 dlen;
	const char *tyname;
};

typedef struct localctx_struct {
	unsigned int majver, minver;
	int nesting_level;
} lctx;

static void do_object_sprite(deark *c, lctx *d, struct objinfo *oi)
{
	i64 dpos, dlen;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

	fi = de_finfo_create(c);

	dpos = oi->dpos;
	dlen = oi->dlen;

	if(oi->objtype==13) {
		// Skip transformation matrix
		dpos += 24;
		dlen -= 24;
	}

	if(dlen>=16) {
		// Peek at the sprite name, to use in the output filename.
		de_ucstring *s = NULL;
		s = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, dpos+4, 12, s,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_RISCOS);
		de_finfo_set_name_from_ucstring(c, fi, s, 0);
		ucstring_destroy(s);
	}

	// An .acorn extension may be needed to open these files with XnView.
	outf = dbuf_create_output_file(c, "acorn", fi, 0x0);

	// Manufacture a sprite file, by adding a 12-byte header.
	dbuf_writeu32le(outf, 1); // number of sprites
	dbuf_writeu32le(outf, 12+4); // offset of sprite data (+4)
	dbuf_writeu32le(outf, 12+dlen+4); // file size (+4)
	dbuf_copy(c->infile, dpos, dlen, outf);

	dbuf_close(outf);
	de_finfo_destroy(c, fi);
}

// Caller sets oi->objtype.
// We set oi->tyname, oi->hasbbox.
static void get_objtype_info(struct objinfo *oi)
{
	switch(oi->objtype) {
	case 0: oi->tyname="font table"; break;
	case 1: oi->tyname="text"; oi->hasbbox=1; break;
	case 2: oi->tyname="path"; oi->hasbbox=1; break;
	case 5: oi->tyname="sprite"; oi->hasbbox=1; break;
	case 6: oi->tyname="group"; oi->hasbbox=1; break;
	case 7: oi->tyname="tagged object"; oi->hasbbox=1; break;
	case 9: oi->tyname="text area"; oi->hasbbox=1; break;
	case 10: oi->tyname="text column"; oi->hasbbox=1; break;
	case 11: oi->tyname="options"; oi->hasbbox=1; break;
	case 12: oi->tyname="transformed text"; oi->hasbbox=1; break;
	case 13: oi->tyname="transformed sprite"; oi->hasbbox=1; break;
	case 65637: oi->tyname="DrawPlus internal data"; break;
	}
	if(!oi->tyname) oi->tyname="?";
}

static int do_object_sequence(deark *c, lctx *d, i64 pos1, i64 len);

static int do_object(deark *c, lctx *d, struct objinfo *oi)
{
	if(oi->objtype==6) { // group
		// TODO: group name, 12 bytes
		do_object_sequence(c, d, oi->dpos+12, oi->dlen-12);
	}
	else if(oi->objtype==5) { // sprite
		do_object_sprite(c, d, oi);
	}
	else if(oi->objtype==13) { // transformed sprite
		do_object_sprite(c, d, oi);
	}
	// TODO: objtype 7 (tagged object)

	return 1;
}

static int do_object_sequence(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;

	d->nesting_level++;
	if(d->nesting_level>16) goto done;

	while(1) {
		struct objinfo oi;

		de_zeromem(&oi, sizeof(struct objinfo));
		oi.objpos = pos;
		if((oi.objpos+24) > (pos1+len)) break;
		oi.objtype = (u32)de_getu32le_p(&pos);
		oi.objsize = de_getu32le_p(&pos);
		if(oi.objsize<8 || (oi.objpos+oi.objsize)>(pos1+len)) {
			de_err(c, "Bad object size (%u) at %"I64_FMT, (unsigned int)oi.objsize, oi.objpos);
			goto done;
		}

		get_objtype_info(&oi);

		de_dbg(c, "object at %"I64_FMT", type=%u (%s), len=%"I64_FMT, oi.objpos,
			oi.objtype, oi.tyname, oi.objsize);

		if(oi.hasbbox) {
			pos += 16;
		}
		oi.dpos = pos;
		oi.dlen = oi.objpos+oi.objsize - oi.dpos;
		if(oi.dlen<0) goto done_obj;

		de_dbg_indent(c, 1);
		do_object(c, d, &oi);
		de_dbg_indent(c, -1);

done_obj:
		pos = oi.objpos + oi.objsize;
	}

done:
	d->nesting_level--;
	return 1;
}

static int do_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;

	de_dbg(c, "header at %d", (int)pos1);
	de_dbg_indent(c, 1);
	pos += 4; // file signature
	d->majver = (unsigned int)de_getu32le_p(&pos);
	d->minver = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "format version: %u,%u", d->majver, d->minver);
	pos += 12; // app name
	pos += 16; // bounding box
	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_rodraw(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_header(c, d, pos)) goto done;
	pos += 40;

	if(!do_object_sequence(c, d, pos, c->infile->len-pos)) goto done;

done:
	de_free(c, d);
}

static int de_identify_rodraw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Draw", 4)) {
		if(!dbuf_memcmp(c->infile, 4, "\xc9\0\0\0\0\0\0\0", 8)) {
			return 100;
		}
		return 49;
	}
	return 0;
}

void de_module_rodraw(deark *c, struct deark_module_info *mi)
{
	mi->id = "rodraw";
	mi->desc = "RISC OS Draw, Acorn Draw";
	mi->run_fn = de_run_rodraw;
	mi->identify_fn = de_identify_rodraw;
}
