// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// zlib module
//
// This module is for decompressing zlib-compressed files.
// It uses the deark-miniz.c utilities, which in turn use miniz.c.

#include <deark-config.h>

#include <deark-modules.h>

static void de_run_zlib(deark *c, const char *params)
{
	dbuf *f = NULL;

	de_dbg(c, "In zlib module\n");

	f = dbuf_create_output_file(c, "unc", NULL);
	de_uncompress_zlib(c->infile, 0, c->infile->len, f);
	dbuf_close(f);
}

static int de_identify_zlib(deark *c)
{
	de_byte b[2];
	de_read(b, 0, 2);

	if((b[0]&0x0f) != 8)
		return 0;

	if(b[0]<0x08 || b[0]>0x78)
		return 0;

	if(((((unsigned int)b[0])<<8)|b[1])%31 != 0)
		return 0;

	return 50;
}

void de_module_zlib(deark *c, struct deark_module_info *mi)
{
	mi->id = "zlib";
	mi->run_fn = de_run_zlib;
	mi->identify_fn = de_identify_zlib;
}
