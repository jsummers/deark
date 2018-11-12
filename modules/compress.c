// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Legacy Unix "compress" (.Z) compressed file format

#include <deark-config.h>
#include <deark-private.h>

DE_DECLARE_MODULE(de_module_compress);

static void de_run_compress(deark *c, de_module_params *mparams)
{
	dbuf *f = NULL;
	de_byte buf[1024];
	de_int64 n;
	struct de_liblzwctx *lzw = NULL;

	lzw = de_liblzw_dbufopen(c->infile, 0x1, 0);
	if(!lzw) goto done;
	f = dbuf_create_output_file(c, "bin", NULL, 0);

	while(1) {
		n = de_liblzw_read(lzw, buf, sizeof(buf));
		if(n<1) break;
		dbuf_write(f, buf, n);
	}

done:
	if(lzw) de_liblzw_close(lzw);
	dbuf_close(f);
}

static int de_identify_compress(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1f\x9d", 2))
		return 100;
	return 0;
}

void de_module_compress(deark *c, struct deark_module_info *mi)
{
	mi->id = "compress";
	mi->desc = "Compress (.Z)";
	mi->run_fn = de_run_compress;
	mi->identify_fn = de_identify_compress;
}
