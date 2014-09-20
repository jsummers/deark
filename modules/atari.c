// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int reserved;
} lctx;


static void do_cas(deark *c)
{
	de_int64 pos;
	de_byte chunk_id[4];
	de_int64 chunk_len;
	de_int64 chunk_extra;

	pos = 0;
	while(1) {
		if(pos >= c->infile->len-8) break; // Reached end of file

		de_read(chunk_id, pos, 4);
		chunk_len = de_getui16le(pos+4);
		chunk_extra = de_getui16le(pos+6);

		de_dbg(c, "chunk at %d, data_len=%d, extra=%d\n", (int)pos, (int)chunk_len,
			(int)chunk_extra);

		pos += 8;

		pos += chunk_len;
	}
}

static void de_run_cas(deark *c, const char *params)
{
	do_cas(c);
	de_err(c, "Atari CAS format is not supported\n");
}

static int de_identify_cas(deark *c)
{
	de_byte buf[16];
	de_read(buf, 0, 16);

	if(!de_memcmp(buf, "FUJI", 4)) {
		return 70;
	}
	return 0;
}

void de_module_atari_cas(deark *c, struct deark_module_info *mi)
{
	mi->id = "cas";
	mi->run_fn = de_run_cas;
	mi->identify_fn = de_identify_cas;
}


// --------------------------------------------

static void do_atr(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 image_size;
	de_int64 sector_size;
	de_byte x;

	pos = 0;

	image_size = de_getui16le(pos+2);
	sector_size = de_getui16le(pos+4);
	x = de_getbyte(pos+6); // high byte of 24-bit image_size field
	image_size += 65536*(de_int64)x;
	image_size *= 16;

	de_dbg(c, "image_size=%d, sector_size=%d\n", (int)image_size, (int)sector_size);
}

static void de_run_atr(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In ATR module\n");

	d = de_malloc(c, sizeof(lctx));

	do_atr(c, d);

	de_free(c, d);

}

static int de_identify_atr(deark *c)
{
	de_byte buf[16];
	de_read(buf, 0, 16);

	if(buf[0]==0x96 && buf[1]==0x02) {
		return 60;
	}
	return 0;
}

void de_module_atr(deark *c, struct deark_module_info *mi)
{
	mi->id = "atr";
	mi->run_fn = de_run_atr;
	mi->identify_fn = de_identify_atr;
}
