// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Macintosh PICT graphics

#include <deark-config.h>
#include <deark-modules.h>

struct pict_rect {
	de_int64 t, l, b, r;
};

typedef struct localctx_struct {
	int is_v2; // >0 if the file is known to be in v2 format
	int is_extended_v2;
} lctx;

typedef int (*item_decoder_fn)(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos,
	de_int64 *bytes_used);

static int handler_11(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_28(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_DxText(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_2b(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_98(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_9a(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_a1(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_0c00(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);
static int handler_8200(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used);

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
	{ 0x0003, SZCODE_EXACT,   2,  "TxFont", NULL },
	{ 0x0004, SZCODE_EXACT,   1,  "TxFace", NULL },
	{ 0x0007, SZCODE_EXACT,   4,  "PnSize", NULL },
	{ 0x0008, SZCODE_EXACT,   2,  "PnMode", NULL },
	{ 0x0009, SZCODE_EXACT,   8,  "PnPat", NULL },
	{ 0x000d, SZCODE_EXACT,   2,  "TxSize", NULL },
	{ 0x0010, SZCODE_EXACT,   8,  "TxRatio", NULL },
	{ 0x0011, SZCODE_EXACT,   1,  "Version", handler_11 },
	{ 0x001a, SZCODE_EXACT,   6,  "RGBFgCol", NULL },
	{ 0x001e, SZCODE_EXACT,   0,  "DefHilite", NULL },
	{ 0x001f, SZCODE_EXACT,   6,  "OpColor", NULL },
	{ 0x0020, SZCODE_EXACT,   8,  "Line", NULL },
	{ 0x0021, SZCODE_EXACT,   4,  "LineFrom", NULL },
	{ 0x0022, SZCODE_EXACT,   6,  "ShortLine", NULL },
	{ 0x0023, SZCODE_EXACT,   2,  "ShortLineFrom", NULL },
	{ 0x0028, SZCODE_SPECIAL, 0,  "LongText", handler_28 },
	{ 0x0029, SZCODE_SPECIAL, 0,  "DHText", handler_DxText },
	{ 0x002a, SZCODE_SPECIAL, 0,  "DVText", handler_DxText },
	{ 0x002b, SZCODE_SPECIAL, 0,  "DHDVText", handler_2b },
	{ 0x0031, SZCODE_EXACT,   8,  "paintRect", NULL },
	{ 0x0050, SZCODE_EXACT,   8,  "frameOval", NULL },
	{ 0x0098, SZCODE_SPECIAL, 0,  "PackBitsRect", handler_98 },
	{ 0x009a, SZCODE_SPECIAL, 0,  "DirectBitsRect", handler_9a },
	{ 0x00a0, SZCODE_EXACT,   2,  "ShortComment", NULL },
	{ 0x00a1, SZCODE_SPECIAL, 0,  "LongComment", handler_a1 },
	{ 0x00ff, SZCODE_EXACT,   2,  "opEndPic", NULL },
	{ 0x0c00, SZCODE_EXACT,   24, "HeaderOp", handler_0c00 },
	{ 0x8200, SZCODE_SPECIAL, 0,  "CompressedQuickTime", handler_8200 },
	{ 0x8201, SZCODE_SPECIAL, 0,  "UncompressedQuickTime", NULL },
	{ 0xffff, SZCODE_SPECIAL, 0,  NULL, NULL }
};

static double pict_read_fixed(dbuf *f, de_int64 pos)
{
	de_int64 n;

	// I think QuickDraw's "Fixed point" numbers are signed, but I don't know
	// how negative numbers are handled.
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

// Read a QuickDraw Rectangle. Caller supplies rect struct.
static void pict_read_rect(dbuf *f, de_int64 pos,
	struct pict_rect *rect, const char *dbgname)
{
	rect->t = dbuf_geti16be(f, pos);
	rect->l = dbuf_geti16be(f, pos+2);
	rect->b = dbuf_geti16be(f, pos+4);
	rect->r = dbuf_geti16be(f, pos+6);

	if(dbgname) {
		de_dbg(f->c, "%s: (%d,%d)-(%d,%d)\n", dbgname, (int)rect->l, (int)rect->t,
			(int)rect->r, (int)rect->b);
	}
}

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

// LongText
static int handler_28(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 len;
	len = (de_int64)de_getbyte(data_pos+4);
	de_dbg(c, "text size: %d\n", (int)len);
	*bytes_used = 5+len;
	return 1;
}

// DVText
static int handler_DxText(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 len;
	len = (de_int64)de_getbyte(data_pos+1);
	de_dbg(c, "text size: %d\n", (int)len);
	*bytes_used = 2+len;
	return 1;
}

// DHDVText
static int handler_2b(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 len;
	len = (de_int64)de_getbyte(data_pos+2);
	de_dbg(c, "text size: %d\n", (int)len);
	*bytes_used = 3+len;
	return 1;
}

static int handler_98(deark *c, lctx *d, de_int64 opcode, de_int64 pos, de_int64 *bytes_used)
{
	struct pict_rect rect;
	de_int64 rowspan_code;
	de_int64 rowspan;
	de_int64 pixmap_version;
	//de_int64 packing_type;
	//de_int64 pack_size;
	de_int64 hdpi, vdpi;
	de_int64 pixeltype, pixelsize;
	de_int64 cmpcount, cmpsize;
	int pixmap_flag = 0;

	rowspan_code = de_getui16be(pos);
	rowspan = rowspan_code & 0x7fff;
	pixmap_flag = (rowspan_code & 0x8000)?1:0;

	de_dbg(c, "bytes/row: %d\n", (int)rowspan);
	de_dbg(c, "pixmap flag: %d\n", pixmap_flag);

	pict_read_rect(c->infile, pos+2, &rect, "rect");

	pixmap_version = de_getui16be(pos+10);
	de_dbg(c, "pixmap version: %d\n", (int)pixmap_version);

	//packing_type = de_getui16be(pos+12);
	//de_dbg(c, "packing type: %d\n", (int)packing_type);

	//pack_size = de_getui32be(pos+14);
	//de_dbg(c, "pixel data length: %d\n", (int)pack_size);

	hdpi = de_getui32be(pos+16); // spec says 18
	vdpi = de_getui32be(pos+20); // spec says 22
	de_dbg(c, "dpi: %dx%d\n", (int)hdpi, (int)vdpi);

	pixeltype = de_getui16be(pos+24);
	pixelsize = de_getui16be(pos+26);
	cmpcount = de_getui16be(pos+28);
	cmpsize = de_getui16be(pos+30);
	de_dbg(c, "pixel type=%d, bits/pixel=%d, components/pixel=%d, bits/comp=%d\n",
		(int)pixeltype, (int)pixelsize, (int)cmpcount, (int)cmpsize);

	// TODO
	return 0;
}

static int handler_9a(deark *c, lctx *d, de_int64 opcode, de_int64 pos, de_int64 *bytes_used)
{
	struct pict_rect rect;
	de_int64 rowspan_code;
	de_int64 rowspan;
	de_int64 pixmap_version;
	de_int64 packing_type;
	de_int64 pack_size;
	double hdpi, vdpi;
	de_int64 pixeltype, pixelsize;
	de_int64 cmpcount, cmpsize;
	de_int64 plane_bytes;
	int pixmap_flag = 0;
	de_int64 n;

	// 0-3: baseAddr (should be 000000ff)
	n = de_getui32be(pos);
	de_dbg(c, "baseAddr: 0x%08x\n", (unsigned int)n);
	pos += 4;

	rowspan_code = de_getui16be(pos);
	rowspan = rowspan_code & 0x7fff;
	pixmap_flag = (rowspan_code & 0x8000)?1:0;
	de_dbg(c, "bytes/row: %d\n", (int)rowspan);
	de_dbg(c, "pixmap flag: %d\n", pixmap_flag);
	pos += 2;

	pict_read_rect(c->infile, pos, &rect, "rect");
	pos += 8;

	pixmap_version = de_getui16be(pos);
	de_dbg(c, "pixmap version: %d\n", (int)pixmap_version);
	pos += 2;

	packing_type = de_getui16be(pos);
	de_dbg(c, "packing type: %d\n", (int)packing_type);
	pos += 2;

	pack_size = de_getui32be(pos);
	de_dbg(c, "pixel data length: %d\n", (int)pack_size);
	pos += 4;

	hdpi = pict_read_fixed(c->infile, pos);
	vdpi = pict_read_fixed(c->infile, pos+4);
	de_dbg(c, "dpi: %.2fx%.2f\n", hdpi, vdpi);
	pos += 8;

	pixeltype = de_getui16be(pos);
	pos += 2;
	pixelsize = de_getui16be(pos);
	pos += 2;
	cmpcount = de_getui16be(pos);
	pos += 2;
	cmpsize = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "pixel type=%d, bits/pixel=%d, components/pixel=%d, bits/comp=%d\n",
		(int)pixeltype, (int)pixelsize, (int)cmpcount, (int)cmpsize);

	plane_bytes = de_getui32be(pos);
	de_dbg(c, "plane bytes: %d\n", (int)plane_bytes);
	pos += 4;

	// CTabHandle pmTable;
	// long pmReserved

	// TODO
	return 0;
}

// LongComment
static int handler_a1(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 len;
	len = de_getui16be(data_pos+2);
	de_dbg(c, "comment size: %d\n", (int)len);
	*bytes_used = 4+len;
	return 1;
}

// HeaderOp
static int handler_0c00(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 hdrver;
	double hres, vres;
	struct pict_rect srcrect;

	hdrver = de_getui16be(data_pos);
	d->is_extended_v2 = (hdrver==0xfffe);

	de_dbg(c, "extended v2: %s\n", d->is_extended_v2?"yes":"no");
	if(d->is_extended_v2) {
		hres = pict_read_fixed(c->infile, data_pos+4);
		vres = pict_read_fixed(c->infile, data_pos+8);
		de_dbg(c, "dpi: %.2fx%.2f\n", hres, vres);
		pict_read_rect(c->infile, data_pos+12, &srcrect, "srcRect");
	}

	return 1;
}

// CompressedQuickTime
// TODO: Use the qtif decoder if possible.
static int handler_8200(deark *c, lctx *d, de_int64 opcode, de_int64 data_pos, de_int64 *bytes_used)
{
	de_int64 payload_len;
	de_int64 img_startpos;
	de_int64 img_len;
	de_byte cmpr_type[4];
	char cmpr_type_printable[8];

	payload_len = de_getui32be(data_pos);
	if(data_pos+4+payload_len > c->infile->len) return 0;
	*bytes_used = 4+payload_len;

	// Following the size field seems to be a 154-byte header.

	de_read(cmpr_type, data_pos+76, 4);
	de_make_printable_ascii(cmpr_type, 4, cmpr_type_printable,
		sizeof(cmpr_type_printable), 0);
	de_dbg(c, "compression type: \"%s\"\n", cmpr_type_printable);
	if(de_memcmp(cmpr_type, "jpeg", 4)) {
		de_warn(c, "Unsupported compression type: \"%s\"\n", cmpr_type_printable);
		goto done;
	}

	img_len = de_getui32be(data_pos+116);
	de_dbg(c, "image length: %d\n", (int)img_len);
	if(img_len<2) goto done;

	img_startpos = data_pos + 4 + 154;
	if(img_startpos + img_len > c->infile->len) goto done;
	if(dbuf_memcmp(c->infile, img_startpos, "\xff\xd8", 2)) {
		de_dbg(c, "image doesn't seem to be in jpeg format\n");
		goto done;
	}

	dbuf_create_file_from_slice(c->infile, img_startpos, img_len, "jpg", NULL);

done:
	return 1;
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
		de_dbg(c, "region size: %d\n", (int)n);
		de_dbg_indent(c, -1);
		*data_bytes_used = n;
		ret = 1;
	}
	else if((opcode>=0x2c && opcode<=0x2f)) {
		// Starts with 2-byte size, size does not include the "size" field.
		n = de_getui16be(data_pos);
		*data_bytes_used = 2+n;
		ret = 1;
	}
	else if((opcode>=0x8100 && opcode<=0xffff)) {
		// Starts with 4-byte size, size does not include the "size" field.
		n = de_getui32be(data_pos);
		*data_bytes_used = 4+n;
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
	struct pict_rect framerect;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "PICT\n");
	pos = 512;

	picsize = de_getui16be(pos);
	de_dbg(c, "picSize: %d\n", (int)picsize);
	pos+=2;
	pict_read_rect(c->infile, pos, &framerect, "picFrame");
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
