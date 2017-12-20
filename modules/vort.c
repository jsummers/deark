// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// VORT pix image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_vort);

// The VORT software includes documentation about this file format, but to me
// it seems unclear and incomplete. Here are some of my notes about the format,
// using my own terminology.
//
// VLQ := a LENGTH byte, followed by an unsigned #LENGTH-byte integer.
//  (Longer-than-optimal LENGTHs are fine. A LENGTH of 0 is allowed, at least
//  in some contexts.)
//
// FULL_OBJECT := a FULL_TYPE byte, then a VLQ, then a #VLQ-byte OBJECT_LIST
//
// OBJECT_LIST := a sequence of PRIMITIVE_OBJECTs
//  (Note that, to parse an OBJECT_LIST, you need to know its size in bytes.
//  To do anything useful with it, you also need its parent's FULL_TYPE.)
//
// PRIMITIVE_OBJECT := a PRIMITIVE_TYPE byte, then a LENGTH byte, then #LENGTH
//   bytes of data
//  (Note that, to do anything useful with a PRIMITIVE_OBJECT, you need to
//  know its parent's FULL_TYPE.)
//  (Note that the data following the PRIMITIVE_TYPE byte is often, but not
//  always, in the form of a VLQ.)
//
// FULL_TYPE V_DIRECTORY w/ PRIMITIVE_TYPE D_OBJECT is a pointer to a
// FULL_OBJECT.
//
// The file can also contain unstructured data at arbitrary offsets, pointed to
// by certain PRIMITIVE_OBJECTs.
//
// At offset 6 is a VLQ giving the offset of the "root object" (a FULL_OBJECT).
// This is expected to be a directory object; otherwise I guess it has to be
// the only FULL_OBJECT in the file.
//
// All file offsets are measured from the beginning of the file.

// "Full object" types:
#define VORT_V_DIRECTORY 0
#define VORT_V_IMAGE     1
#define VORT_V_TEXT      2
#define VORT_V_COLORMAP  3

// Primitive object types for V_DIRECTORY:
#define VORT_D_OBJECT    2

// Primitive object types for V_IMAGE:
#define VORT_I_ADDR      0
#define VORT_I_IMWIDTH   1
#define VORT_I_IMHEIGHT  2
#define VORT_I_IMDEPTH   3

typedef struct localctx_struct {
	int nesting_level;
} lctx;

// Variable length integer/quantity (VLQ)
// fpos will be read and updated.
static de_int64 read_vlq(deark *c, de_int64 *fpos)
{
	de_int64 nlen;
	de_int64 k;
	de_int64 val;
	de_int64 pos = *fpos;

	nlen = (de_int64)de_getbyte(pos++);
	*fpos += 1+nlen;
	if(nlen>7) {
		return 0;
	}

	val = 0;
	for(k=0; k<nlen; k++) {
		val = (val<<8) | (de_int64)de_getbyte(pos++);
	}
	if(val<0) return 0;
	return val;
}

static int do_full_object(deark *c, lctx *d, de_int64 pos1,
	de_int64 *bytes_consumed);

static int do_primitive_object(deark *c, lctx *d, de_int64 pos1,
	de_byte obj_fulltype, de_int64 *bytes_consumed)
{
	de_byte obj_type;
	de_int64 obj_dlen;
	de_int64 pos = pos1;

	de_int64 value_as_vlq = 0;

	de_dbg(c, "primitive object at %d", (int)pos1);
	de_dbg_indent(c, 1);
	obj_type = de_getbyte(pos++);
	de_dbg(c, "type: %u", (unsigned int)obj_type);

	// The data is usually a VLQ, but sometimes it's not. For convenience,
	// we'll read the length byte, then go back and read the whole thing as a VLQ.
	obj_dlen = (de_int64)de_getbyte(pos);

	if(obj_dlen>=1 && obj_dlen<=8) {
		de_int64 tmppos = pos;
		value_as_vlq = read_vlq(c, &tmppos);
	}
	pos++; // For the length byte

	if(obj_fulltype==VORT_V_DIRECTORY && obj_type==VORT_D_OBJECT) {
		de_int64 bytes_consumed2 = 0;
		do_full_object(c, d, value_as_vlq, &bytes_consumed2);
	}
	else if(obj_fulltype==VORT_V_IMAGE && obj_type==VORT_I_ADDR) {
		de_dbg(c, "image data address: %d", (int)value_as_vlq);
	}
	else if(obj_fulltype==VORT_V_IMAGE && obj_type==VORT_I_IMWIDTH) {
		de_dbg(c, "image width: %d", (int)value_as_vlq);
	}
	else if(obj_fulltype==VORT_V_IMAGE && obj_type==VORT_I_IMHEIGHT) {
		de_dbg(c, "image height: %d", (int)value_as_vlq);
	}
	else if(obj_fulltype==VORT_V_IMAGE && obj_type==VORT_I_IMDEPTH) {
		de_dbg(c, "image depth: %d", (int)value_as_vlq);
	}

	pos += obj_dlen;

	de_dbg_indent(c, -1);
	*bytes_consumed = pos-pos1;
	return 1;
}

static int do_object_list(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	de_byte object_fulltype, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "object list at %d, len=%d (full type=%d)", (int)pos, (int)len, (int)object_fulltype);
	while(1) {
		de_int64 objsize;
		if(pos>=pos1+len) break;
		if(pos>=c->infile->len) goto done;

		de_dbg_indent(c, 1);
		if(!do_primitive_object(c, d, pos, object_fulltype, &objsize)) goto done;
		pos += objsize;
		de_dbg_indent(c, -1);
	}
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Process one "full object", given its address
static int do_full_object(deark *c, lctx *d, de_int64 pos1,
	de_int64 *bytes_consumed)
{
	de_byte obj_type;
	de_int64 obj_dlen;
	de_int64 pos = pos1;
	de_int64 bytes_consumed2 = 0;
	int retval = 0;

	d->nesting_level++;
	// Objects can't be nested without going through this code path, so doing
	// this check only here should be sufficient.
	if(d->nesting_level>8) goto done;

	de_dbg(c, "full object at %d", (int)pos);
	de_dbg_indent(c, 1);
	obj_type = de_getbyte(pos++);
	de_dbg(c, "full type: %u", (unsigned int)obj_type);

	obj_dlen = read_vlq(c, &pos);
	de_dbg(c, "data len: %"INT64_FMT, obj_dlen);

	if(!do_object_list(c, d, pos, obj_dlen, obj_type, &bytes_consumed2)) goto done;

	pos += obj_dlen;
	retval = 1;

done:
	d->nesting_level--;
	de_dbg_indent(c, -1);
	*bytes_consumed = pos-pos1;
	return retval;
}

static void de_run_vort(deark *c, de_module_params *mparams)
{
	de_int64 pos;
	de_int64 root_obj_offs;
	de_int64 bytes_consumed = 0;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 6; // signature
	root_obj_offs = read_vlq(c, &pos);
	de_dbg(c, "root object address: %d", (int)root_obj_offs);
	de_dbg_indent(c, -1);

	pos = root_obj_offs;
	do_full_object(c, d, root_obj_offs, &bytes_consumed);

	de_free(c, d);
}

static int de_identify_vort(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "VORT01", 6))
		return 100;
	return 0;
}

void de_module_vort(deark *c, struct deark_module_info *mi)
{
	mi->id = "vort";
	mi->desc = "VORT ray tracer PIX image";
	mi->run_fn = de_run_vort;
	mi->identify_fn = de_identify_vort;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
