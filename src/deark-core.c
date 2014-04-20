// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-core.c
//
// Functions in this file can be called by deark-cmd.c, but should not be called
// by anything in the library or modules (use deark-util.c instead).

#include "deark-config.h"
#include "deark-private.h"

static void identify_format(deark *c)
{
	int i;
	int result;
	int best_result = 0;
	struct deark_module_info *best_module = NULL;

	for(i=0; c->module_info[i].id!=NULL; i++) {
		if(c->module_info[i].identify_fn!=NULL) {
			result = c->module_info[i].identify_fn(c);
			if(result > best_result) {
				best_result = result;
				best_module = &c->module_info[i];
				if(best_result>=100) break;
			}
		}
	}

	if(best_module) {
		c->input_format = best_module->id;
	}
}

void de_run(deark *c)
{
	dbuf *orig_ifile = NULL;
	dbuf *subfile = NULL;
	de_int64 subfile_size;

	de_register_modules(c);

	if(c->slice_size_req_valid) {
		de_dbg(c, "Input file: %s[%d,%d]\n", c->input_filename,
			(int)c->slice_start_req, (int)c->slice_size_req);
	}
	else if(c->slice_start_req) {
		de_dbg(c, "Input file: %s[%d]\n", c->input_filename,
			(int)c->slice_start_req);
	}
	else {
		de_dbg(c, "Input file: %s\n", c->input_filename);
	}

	orig_ifile = dbuf_open_input_file(c, c->input_filename);
	if(!orig_ifile) {
		goto done;
	}

	c->infile = orig_ifile;

	// If we are only supposed to look at a segment of the original file,
	// do that by creating a child dbuf, using dbuf_open_input_subfile().
	if(c->slice_start_req>0 || c->slice_size_req_valid) {
		if(c->slice_size_req_valid)
			subfile_size = c->slice_size_req;
		else
			subfile_size = dbuf_get_length(c->infile) - c->slice_start_req;
		subfile = dbuf_open_input_subfile(c->infile, c->slice_start_req, subfile_size);
		c->infile = subfile;
	}

	if(!c->input_format) {
		identify_format(c);
		if(!c->input_format) {
			de_err(c, "Unknown or unsupported file format\n");
			goto done;
		}
	}

	de_msg(c, "Module: %s\n", c->input_format);
	de_dbg(c, "File size: %" INT64_FMT "\n", dbuf_get_length(c->infile));

	if(!de_run_module_by_id(c, c->input_format, NULL))
		goto done;

	if(c->file_count==0 && c->error_count==0) {
		de_msg(c, "No files found to extract!\n");
	}

done:
	if(subfile) dbuf_close(subfile);
	if(orig_ifile) dbuf_close(orig_ifile);
}
