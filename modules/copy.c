// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// copy module
//
// This is a trivial modules that makes a copy of the input file.

#include <deark-config.h>
#include <deark-modules.h>

static int de_identify_copy(deark *c)
{
	return 0;
}

static void de_run_copy(deark *c, const char *params)
{
	de_dbg(c, "In copy module\n");

	dbuf_create_file_from_slice(c->infile, 0, c->infile->len, "bin");
}

void de_module_copy(deark *c, struct deark_module_info *mi)
{
	mi->id = "copy";
	mi->run_fn = de_run_copy;
	mi->identify_fn = de_identify_copy;
}
