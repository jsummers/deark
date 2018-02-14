// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ZOO compressed archive format

#include <deark-config.h>
#include <deark-private.h>

#include "../foreign/unzoo.h"
#include "../foreign/zoo-lzd.h"

DE_DECLARE_MODULE(de_module_zoo);

static void de_run_zoo(deark *c, de_module_params *mparams)
{
	ExtrArch(c, c->infile);
}

static int de_identify_zoo(deark *c)
{
	if(!dbuf_memcmp(c->infile, 20, "\xdc\xa7\xc4\xfd", 4))
		return 100;
	return 0;
}

void de_module_zoo(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo";
	mi->desc = "ZOO compressed archive format";
	mi->run_fn = de_run_zoo;
	mi->identify_fn = de_identify_zoo;
}
