// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Macintosh PICT graphics

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 w, h;
	int is_v2; // >0 if the file is known to be in v2 format
} lctx;

typedef int (*item_decoder_fn)(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos,
	de_int64 *bytes_used);

static int handler_11(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_bitsrect(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);

struct opcode_info {
	de_uint16 opcode;
#define SZCODE_SPECIAL 0
#define SZCODE_EXACT   1
#define SZCODE_REGION  2
	de_uint16 size_code;
	de_uint32 size; // Data size, not including opcode. Logic depends on size_code.
	const char *name;
	item_decoder_fn fn;
};
static const struct opcode_info opcode_info_arr[] = {
	// This list is not intended to be complete.
	{ 0x0000, SZCODE_EXACT,   0,  "NOP", NULL },
	{ 0x0001, SZCODE_REGION,  0,  "Clip", NULL },
	{ 0x0011, SZCODE_EXACT,   1,  "Version", handler_11 },
	{ 0x0098, SZCODE_SPECIAL, 0,  "PackBitsRect", handler_bitsrect },
	{ 0x009a, SZCODE_SPECIAL, 0,  "DirectBitsRect", handler_bitsrect },
	{ 0x00ff, SZCODE_EXACT,   2,  "opEndPic", NULL },
	{ 0x0c00, SZCODE_EXACT,   24, "HeaderOp", NULL },
	{ 0xffff, SZCODE_SPECIAL, 0,  NULL, NULL }
};

// Version
static int handler_11(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 ver;

	*bytes_used = 1;
	ver = de_getbyte(data_pos);
	de_dbg(c, "version: %d\n", (int)ver);

	if(ver==2) {
		d->is_v2 = 1;
	}
	else if(ver!=1) {
		de_err(c, "Unsupported PICT version: %d\n", (int)ver);
		return 0;
	}
	return 1;
}

static int handler_bitsrect(deark *c, lctx *d, de_int64 opcode, de_int64 pos, de_int64 *bytes_used)
{
	de_int64 top, left, bottom, right;

	top    = dbuf_geti16be(c->infile, pos+6);
	left   = dbuf_geti16be(c->infile, pos+8);
	bottom = dbuf_geti16be(c->infile, pos+10);
	right  = dbuf_geti16be(c->infile, pos+12);

	de_dbg(c, "rect: (%d,%d)-(%d,%d)\n", (int)left, (int)top,
		(int)right, (int)bottom);

	// TODO
	return 0;
}

static const struct opcode_info *find_opcode_info(de_int64 opcode)
{
	de_int64 i;

	for(i=0; opcode_info_arr[i].name; i++) {
		if(opcode_info_arr[i].opcode == opcode) {
			return &opcode_info_arr[i];
		}
	}
	return NULL;
}

static int do_handle_item(deark *c, lctx *d, de_int64 opcode_pos, de_int64 opcode,
						   de_int64 data_pos, de_int64 *data_bytes_used)
{
	const char *opcode_name;
	const struct opcode_info *opi;
	de_int64 n;
	int ret = 0;

	*data_bytes_used = 0;

	opi = find_opcode_info(opcode);
	if(opi && opi->name) opcode_name = opi->name;
	else opcode_name = "?";

	if(d->is_v2)
		de_dbg(c, "opcode 0x%04x (%s) at %d\n", (unsigned int)opcode, opcode_name, (int)opcode_pos);
	else
		de_dbg(c, "opcode 0x%02x (%s) at %d\n", (unsigned int)opcode, opcode_name, (int)opcode_pos);

	if(opi && opi->fn) {
		de_dbg_indent(c, 1);
		*data_bytes_used = opi->size; // Default to the size in the table.
		ret = opi->fn(c, d, opcode, data_pos, data_bytes_used);
		de_dbg_indent(c, -1);
	}
	else if(opi && opi->size_code==SZCODE_EXACT) {
		*data_bytes_used = opi->size;
		ret = 1;
	}
	else if(opi && opi->size_code==SZCODE_REGION) {
		n = de_getui16be(data_pos);
		de_dbg_indent(c, 1);
		de_dbg(c, "region, size=%d\n", (int)n);
		de_dbg_indent(c, -1);
		*data_bytes_used = n;
		ret = 1;
	}
	else {
		de_err(c, "Unsupported opcode: 0x%04x\n", (unsigned int)opcode);
	}

	return ret;
}

static void do_read_items(deark *c, lctx *d, de_int64 pos)
{
	de_int64 opcode;
	de_int64 opcode_pos;
	de_int64 bytes_used;
	int ret;

	while(1) {
		if(pos%2 && d->is_v2) {
			pos++; // 2-byte alignment
		}

		if(pos >= c->infile->len) break;

		opcode_pos = pos;

		if(d->is_v2) {
			opcode = de_getui16be(pos);
			pos+=2;
		}
		else {
			opcode = (de_int64)de_getbyte(pos);
			pos+=1;
		}

		ret = do_handle_item(c, d, opcode_pos, opcode, pos, &bytes_used);
		if(!ret) goto done;
		if(opcode==0x00ff) goto done; // End of image

		pos += bytes_used;
	}
done:
	;
}

static void de_run_pict(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 picsize;
	de_int64 top, left, bottom, right;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "PICT\n");
	pos = 512;

	picsize = de_getui16be(pos);
	de_dbg(c, "picSize: %d\n", (int)picsize);
	pos+=2;
	top    = dbuf_geti16be(c->infile, pos);
	left   = dbuf_geti16be(c->infile, pos+2);
	bottom = dbuf_geti16be(c->infile, pos+4);
	right  = dbuf_geti16be(c->infile, pos+6);
	de_dbg(c, "picFrame: (%d,%d)-(%d,%d)\n", (int)left, (int)top,
		(int)right, (int)bottom);
	pos+=8;

	do_read_items(c, d, pos);

	de_free(c, d);
}

static int de_identify_pict(deark *c)
{
	de_byte buf[6];

	if(c->infile->len<528) return 0;
	de_read(buf, 522, sizeof(buf));
	if(!de_memcmp(buf, "\x11\x01", 2)) return 5; // v1
	if(!de_memcmp(buf, "\x00\x11\x02\xff\x0c\x00", 2)) return 85; // v2
	return 0;
}

void de_module_pict(deark *c, struct deark_module_info *mi)
{
	mi->id = "pict";
	mi->desc = "Macintosh PICT";
	mi->run_fn = de_run_pict;
	mi->identify_fn = de_identify_pict;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
