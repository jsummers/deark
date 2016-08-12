// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// IPTC metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iptc);

typedef struct localctx_struct {
	int reserved;
} lctx;

static int read_dflen(deark *c, dbuf *f, de_int64 pos,
	de_int64 *dflen, de_int64 *bytes_consumed)
{
	*dflen = dbuf_getui16be(f, pos);
	*bytes_consumed = 2;
	if(*dflen > 32767) {
		// TODO: Support larger lengths
		de_err(c, "Bad or unsupported IPTC data field length\n");
		return 0;
	}
	return 1;
}

static int do_dataset(deark *c, lctx *d, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_byte b;
	de_byte recnum, dsnum;
	int retval = 0;
	de_int64 pos = pos1;
	de_int64 dflen;
	de_int64 dflen_bytes_consumed;

	*bytes_consumed = 0;

	b = de_getbyte(pos);
	if(b!=0x1c) {
		de_err(c, "Bad IPTC tag marker (0x%02x) at %d\n", (int)b, (int)pos);
		goto done;
	}
	pos++;

	recnum = de_getbyte(pos++);
	dsnum = de_getbyte(pos++);

	if(!read_dflen(c, c->infile, pos, &dflen, &dflen_bytes_consumed)) goto done;
	pos += dflen_bytes_consumed;

	de_dbg(c, "IPTC dataset %d:%d dlen=%" INT64_FMT "\n", (int)recnum, (int)dsnum, dflen);

	pos += dflen;

	*bytes_consumed = pos - pos1;
	retval = 1;
done:
	return retval;
}

static void de_run_iptc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 bytes_consumed;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	while(1) {
		if(pos>=c->infile->len) break;
		if(!do_dataset(c, d, pos, &bytes_consumed)) break;
		if(bytes_consumed<=0) break;
		pos += bytes_consumed;
	}

	de_free(c, d);
}

void de_module_iptc(deark *c, struct deark_module_info *mi)
{
	mi->id = "iptc";
	mi->desc = "IPTC";
	mi->run_fn = de_run_iptc;
	mi->identify_fn = de_identify_none;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
