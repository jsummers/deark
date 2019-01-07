// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// SAUCE
// Special module that reads SAUCE metadata for other modules to use,
// and handles files with SAUCE records if they aren't otherwise handled.
// SAUCE = Standard Architecture for Universal Comment Extensions

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_sauce);

// When running as a submodule, we assume the caller already detected the
// presence of SAUCE (probably using detect_SAUCE()), printed a header line
// (again probably using detect_SAUCE()), and indented as needed.
static void run_sauce_as_submodule(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si_local = NULL;
	struct de_SAUCE_info *si_to_use;

	if(mparams && mparams->out_params.obj1) {
		si_to_use = (struct de_SAUCE_info*)mparams->out_params.obj1;
	}
	else {
		si_local = de_fmtutil_create_SAUCE(c);
		si_to_use = si_local;
	}

	de_fmtutil_read_SAUCE(c, c->infile, si_to_use);

	de_fmtutil_free_SAUCE(c, si_local);
}

static void run_sauce_direct(deark *c, de_module_params *mparams)
{
	struct de_SAUCE_info *si = NULL;
	struct de_SAUCE_detection_data sdd;
	int ret;

	de_fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);
	if(!sdd.has_SAUCE) {
		if(c->module_disposition==DE_MODDISP_EXPLICIT) {
			de_err(c, "No SAUCE record found");
		}
		goto done;
	}

	si = de_fmtutil_create_SAUCE(c);
	de_dbg_indent(c, 1);
	ret = de_fmtutil_read_SAUCE(c, c->infile, si);
	de_dbg_indent(c, -1);
	if(ret && c->module_disposition==DE_MODDISP_AUTODETECT) {
		de_err(c, "This file has a SAUCE metadata record that identifies it as "
			"DataType %d, FileType %d, but it is not a supported format.",
			(int)si->data_type, (int)si->file_type);
	}

done:
	de_fmtutil_free_SAUCE(c, si);
}

static void de_run_sauce(deark *c, de_module_params *mparams)
{
	if(c->module_disposition==DE_MODDISP_INTERNAL) {
		run_sauce_as_submodule(c, mparams);
	}
	else {
		run_sauce_direct(c, mparams);
	}
}

static int de_identify_sauce(deark *c)
{
	c->detection_data.SAUCE_detection_attempted = 1;
	if(de_fmtutil_detect_SAUCE(c, c->infile, &c->detection_data.sauce, 0)) {
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
