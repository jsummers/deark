// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int reserved;
} lctx;

static void do_box_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level);

static int do_box(deark *c, lctx *d, de_int64 pos, de_int64 len, int level,
	de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_size;
	de_int64 payload_size;
	de_byte boxtype[4];
	char boxtype_printable[16];

	size32 = de_getui32be(pos);
	de_read(boxtype, pos+4, 4);

	if(size32>=8) {
		header_size = 8;
		payload_size = size32-8;
	}
	else if(size32==0) {
		header_size = 8;
		payload_size = len-8;
	}
	else if(size32==1) {
		header_size = 16;
		size64 = de_geti64be(pos+8);
		if(size64<16) return 0;
		payload_size = size64-16;
	}
	else {
		// Invalid or unsupported format.
		return 0;
	}

	if(c->debug_level>0) {
		de_make_printable_ascii(boxtype, 4, boxtype_printable, sizeof(boxtype_printable), 0);
		de_dbg(c, "[%d] box type '%s' at %d, size=%d\n", level, boxtype_printable,
			(int)pos, (int)payload_size);
	}

	if(!de_memcmp(boxtype, "jp2h", 4)) { // JP2 Header box
		// Boxes known to contain other boxes.
		do_box_sequence(c, d, pos+header_size, payload_size, level+1);
	}
	else if(!de_memcmp(boxtype, "jp2c", 4)) { // Contiguous Codestream box
		dbuf_create_file_from_slice(c->infile, pos+header_size, payload_size, "j2c");
	}
	else if(!de_memcmp(boxtype, "xml ", 4)) { // XML box
		// TODO: Detect the specific XML format, and use it to choose a better
		// filename.
		dbuf_create_file_from_slice(c->infile, pos+header_size, payload_size, "xml");
	}

	*pbytes_consumed = header_size + payload_size;
	return 1;
}

static void do_box_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len, int level)
{
	de_int64 pos;
	de_int64 box_len;
	de_int64 endpos;
	int ret;

	pos = pos1;
	endpos = pos1 + len;

	while(pos < endpos) {
		ret = do_box(c, d, pos, endpos-pos, level, &box_len);
		if(!ret) break;
		pos += box_len;
	}
}

static void de_run_jpeg2000(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In jpeg2000 module\n");

	d = de_malloc(c, sizeof(lctx));

	do_box_sequence(c, d, 0, c->infile->len, 0);

	de_free(c, d);
}

static int de_identify_jpeg2000(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a", 12))
		return 100;
	return 0;
}

void de_module_jpeg2000(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpeg2000";
	mi->run_fn = de_run_jpeg2000;
	mi->identify_fn = de_identify_jpeg2000;
}
