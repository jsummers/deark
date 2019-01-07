// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// SAUCE
// Special module that reads SAUCE metadata for other modules to use,
// and handles files with SAUCE records if they aren't otherwise handled.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_sauce);

static void de_run_sauce(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si = NULL;
	int ret;

	si = de_malloc(c, sizeof(struct de_SAUCE_info));
	ret = de_read_SAUCE(c, c->infile, si);
	if(ret && c->module_disposition==DE_MODDISP_AUTODETECT) {
		de_err(c, "This file has a SAUCE metadata record that identifies it as "
			"DataType %d, FileType %d, but it is not a supported format.",
			(int)si->data_type, (int)si->file_type);
	}
	if(!ret && c->module_disposition==DE_MODDISP_EXPLICIT) {
		de_err(c, "No SAUCE record found");
	}
	de_free_SAUCE(c, si);
}

static int de_identify_sauce(deark *c)
{
	if(de_detect_SAUCE(c, c->infile, &c->detection_data.sauce)) {
		// This module should have a very low priority, but other modules can use
		// the results of its detection.
		return 2;
	}
	return 0;
}

void de_module_sauce(deark *c, struct deark_module_info *mi)
{
	mi->id = "sauce";
	mi->desc = "SAUCE metadata";
	mi->run_fn = de_run_sauce;
	mi->identify_fn = de_identify_sauce;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_SHAREDDETECTION;
}
