// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Legacy Unix "compress" (.Z) compressed file format

#include <deark-config.h>
#include <stdlib.h>
#include <deark-modules.h>

#include "../foreign/liblzw.h"

static void de_run_compress(deark *c, de_module_params *mparams)
{
	dbuf *f = NULL;
	de_byte buf[1024];
	de_int64 n;
	lzwFile *lzw = NULL;

	lzw = lzw_dbufopen(c->infile);
	if(!lzw) goto done;
	f = dbuf_create_output_file(c, "bin", NULL);

	while(1) {
		n = lzw_read(lzw, buf, sizeof(buf));
		if(n<1) break;
		dbuf_write(f, buf, n);
	}

done:
	if(lzw) lzw_close(lzw);
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
