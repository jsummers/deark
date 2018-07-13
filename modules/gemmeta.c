// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GEM VDI Metafile (.gem)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gemmeta);

typedef struct localctx_struct {
	int reserved;
} lctx;

struct opcode_data {
	de_int64 pos;
	de_int64 ptsin_pos;
	de_int64 intin_pos;
	de_int64 opcode;

	// "Function sub-ID". This is also confusingly called "sub-opcode", but
	// "sub-opcode" means something entirely different with respect to opcode 5.
	de_int64 func_id;

	de_int64 ptsin_count, intin_count;
};

typedef void (*record_decoder_fn)(deark *c, lctx *d, struct opcode_data *op);

struct opcode_info {
	de_uint16 opcode;
	const char *name;
	record_decoder_fn fn;
};

static void do_opcode_5(deark *c, lctx *d, struct opcode_data *op);
static void do_opcode_11(deark *c, lctx *d, struct opcode_data *op);

static const struct opcode_info opcode_info_arr[] = {
	// This list is not intended to be complete.
	{ 5, "Escape", do_opcode_5 },
	{ 6, "Polyline", NULL },
	{ 9, "Filled area", NULL },
	{ 11, "GDP", do_opcode_11 },
	{ 13, "Set character baseline vector", NULL },
	{ 15, "Set polyline linetype", NULL },
	{ 16, "Set polyline line width", NULL },
	{ 17, "Set polyline color index", NULL },
	{ 18, "Set polymarker type", NULL },
	{ 19, "Set polymarker height", NULL },
	{ 20, "Set polymarker color index", NULL },
	{ 21, "Set text face", NULL },
	{ 22, "Set graphic text color index", NULL },
	{ 23, "Set fill interior style", NULL },
	{ 24, "Set fill style index", NULL },
	{ 25, "Set fill color index", NULL },
	{ 32, "Set writing mode", NULL },
	{ 39, "Set graphic text alignment", NULL },
	{ 104, "Set fill perimeter visibility", NULL },
	{ 106, "Set graphic text special effects", NULL },
	{ 107, "Set character cell height, points mode", NULL },
	{ 108, "Set polyline end styles", NULL },
	{ 112, "Set user defined fill pattern", NULL },
	{ 0xffff, "EOF", NULL },
	{ 0x0000, NULL, NULL }
};

static void do_opcode_5(deark *c, lctx *d, struct opcode_data *op)
{
	de_int64 sub_opcode_id;
	const char *name;

	if(op->func_id!=99) return;
	if(op->intin_count<1) return;
	sub_opcode_id = de_getui16le(op->intin_pos);

	switch(sub_opcode_id) {
	case 10: name="Start Group"; break;
	case 11: name="End Group"; break;
	case 49: name="Set No Line Style"; break;
	case 50: name="Set Attribute Shadow On"; break;
	case 51: name="Set Attribute Shadow Off"; break;
	case 80: name="Start Draw Area Type Primitive"; break;
	case 81: name="End Draw Area Type Primitive"; break;
	default:
		if(sub_opcode_id>100) {
			name="for developer use";
		}
		else {
			name="?";
		}
	}

	de_dbg(c, "sub-opcode id: %d (%s)", (int)sub_opcode_id, name);
}

static void do_opcode_11(deark *c, lctx *d, struct opcode_data *op)
{
	const char *name;

	switch(op->func_id) {
	case 1: name="Bar"; break;
	case 2: name="Arc"; break;
	case 3: name="Pie"; break;
	case 4: name="Circle"; break;
	case 5: name="Ellipse"; break;
	case 6: name="Elliptical arc"; break;
	case 7: name="Elliptical Pie"; break;
	case 8: name="Rounded rectangle"; break;
	case 9: name="Filled rounded rectangle"; break;
	case 10: name="Jutified graphic text"; break;
	default: name="?"; break;
	}

	de_dbg(c, "function: %s", name);
}

static const struct opcode_info *find_opcode_info(de_int64 opcode)
{
	de_int64 i;

	for(i=0; opcode_info_arr[i].name!=NULL; i++) {
		if(opcode_info_arr[i].opcode == opcode) {
			return &opcode_info_arr[i];
		}
	}
	return NULL;
}

// Returns 0 if we should stop reading the file.
static int do_record(deark *c, lctx *d, de_int64 pos, de_int64 *bytesused)
{
	int retval = 0;
	struct opcode_data op;
	de_int64 ptsin_size_bytes;
	de_int64 intin_size_bytes;
	de_int64 data_size_bytes;
	const struct opcode_info *opinfo;
	const char *opcode_name;

	*bytesused = 0;
	de_memset(&op, 0, sizeof(struct opcode_data));

	de_dbg(c, "record at %d", (int)pos);
	de_dbg_indent(c, 1);

	op.opcode = de_getui16le(pos);
	op.ptsin_count = de_getui16le(pos+2);
	op.intin_count = de_getui16le(pos+4);
	op.func_id = de_getui16le(pos+6);

	ptsin_size_bytes = 4*op.ptsin_count;
	intin_size_bytes = 2*op.intin_count;
	data_size_bytes = ptsin_size_bytes + intin_size_bytes;

	op.ptsin_pos = pos + 8;
	op.intin_pos = pos + 8 + ptsin_size_bytes;

	opinfo = find_opcode_info(op.opcode);
	if(opinfo && opinfo->name)
		opcode_name = opinfo->name;
	else
		opcode_name = "?";

	de_dbg(c, "opcode=%d (%s), func_id=%d, #pts=%d, #int=%d (dlen=%d)",
		(int)op.opcode, opcode_name, (int)op.func_id,
		(int)op.ptsin_count, (int)op.intin_count,
		(int)data_size_bytes);

	*bytesused = 8 + data_size_bytes;

	if(opinfo && opinfo->fn) {
		opinfo->fn(c, d, &op);
	}

	if(op.opcode==65535) {
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_gemmeta(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 hdrlen_words;
	de_int64 version;
	de_int64 imgflag;
	de_int64 bytesused;

	d = de_malloc(c, sizeof(lctx));
	de_msg(c, "Note: GEM VDI Metafiles can be parsed, but no files can be extracted from them.");

	pos = 0;
	hdrlen_words = de_getui16le(pos+2);
	de_dbg(c, "header length: %d words", (int)hdrlen_words);
	version = de_getui16le(pos+4);
	de_dbg(c, "version number: %d", (int)version);
	// TODO: Read more header fields.
	imgflag = de_getui16le(pos+28);
	de_dbg(c, "image flag: %d", (int)imgflag);

	pos += hdrlen_words*2;

	while(1) {
		if(pos >= c->infile->len) break;
		if(!do_record(c, d, pos, &bytesused)) break;
		if(bytesused<=0) break;
		pos += bytesused;
	}
	de_free(c, d);
}

static int de_identify_gemmeta(deark *c)
{
	// FIXME: This will not identify all files.
	if(!dbuf_memcmp(c->infile, 0, "\xff\xff\x18\x00", 4))
		return 100;
	return 0;
}

void de_module_gemmeta(deark *c, struct deark_module_info *mi)
{
	mi->id = "gemmeta";
	mi->desc = "GEM VDI Metafile";
	mi->run_fn = de_run_gemmeta;
	mi->identify_fn = de_identify_gemmeta;
}
