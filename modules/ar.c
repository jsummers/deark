// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int reserved;
} lctx;

static de_int64 read_decimal(deark *c, de_int64 pos, de_int64 len)
{
	de_byte b;
	de_int64 k;
	de_int64 val = 0;

	for(k=0; k<len; k++) {
		b = de_getbyte(pos+k);
		if(b<'0' || b>'9') break;
		val = 10*val + (b-'0');
	}
	return val;
}

static int do_ar_item(deark *c, lctx *d, de_int64 pos1, de_int64 *p_item_len)
{
	de_byte name_orig[16];
	char name_printable[32];
	de_int64 mod_time;
	de_int64 file_offset;
	de_int64 file_size;

	de_dbg(c, "archive member at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	de_read(name_orig, pos1, 16);
	de_make_printable_ascii(name_orig, 16,
		name_printable, sizeof(name_printable), 0);
	de_dbg(c, "member name: \"%s\"\n", name_printable);

	mod_time = read_decimal(c, pos1+16, 12);
	de_dbg(c, "mod time: %" INT64_FMT "\n", mod_time);

	file_offset = pos1 + 60;
	file_size = read_decimal(c, pos1+48, 10);
	de_dbg(c, "member data at %d, size: %d\n",
		(int)file_offset, (int)file_size);

	*p_item_len = 60 + file_size;
	if(*p_item_len % 2) (*p_item_len)++; // padding

	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_ar(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 item_len;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	pos = 8;
	while(1) {
		if(pos >= c->infile->len) break;
		ret = do_ar_item(c, d, pos, &item_len);
		if(!ret || item_len<1) break;
		pos += item_len;
	}

	de_free(c, d);

	de_err(c, "AR support is not implemented\n");
}

static int de_identify_ar(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "!<arch>\x0a", 8))
		return 100;
	return 0;
}

void de_module_ar(deark *c, struct deark_module_info *mi)
{
	mi->id = "ar";
	mi->run_fn = de_run_ar;
	mi->identify_fn = de_identify_ar;
}
