// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-core.c
//
// Functions in this file can be called by deark-cmd.c, but should not be called
// by anything in the library or modules (use deark-util.c instead).

#include "deark-config.h"
#include <stdlib.h>
#include "deark-private.h"

// Returns the best module to use, by looking at the file contents, etc.
static struct deark_module_info *detect_module_for_file(deark *c)
{
	int i;
	int result;
	int best_result = 0;
	struct deark_module_info *best_module = NULL;

	// Check for a UTF-8 BOM just once. Any module can use this flag.
	if(!dbuf_memcmp(c->infile, 0, "\xef\xbb\xbf", 3)) {
		c->detection_data.has_utf8_bom = 1;
	}

	for(i=0; i<c->num_modules; i++) {
		if(c->module_info[i].identify_fn!=NULL) {
			result = c->module_info[i].identify_fn(c);
			if(result > best_result) {
				best_result = result;
				best_module = &c->module_info[i];
				if(best_result>=100) break;
			}
		}
	}

	return best_module;
}

struct sort_data_struct {
	deark *c;
	int module_index;
};

static int module_compare_fn(const void *a, const void *b)
{
	struct sort_data_struct *m1, *m2;
	deark *c;

	m1 = (struct sort_data_struct *)a;
	m2 = (struct sort_data_struct *)b;
	c = m1->c;
	return de_strcmp(c->module_info[m1->module_index].id,
		c->module_info[m2->module_index].id);
}

void de_print_module_list(deark *c)
{
	int i, k;
	struct sort_data_struct *sort_data = NULL;

	de_register_modules(c);

	// An index to the modules. Will be sorted by name.
	sort_data = de_malloc(c, c->num_modules * sizeof(struct sort_data_struct));

	for(k=0; k<c->num_modules; k++) {
		sort_data[k].c = c;
		sort_data[k].module_index = k;
	}

	qsort((void*)sort_data, (size_t)c->num_modules, sizeof(struct sort_data_struct),
		module_compare_fn);

	for(k=0; k<c->num_modules; k++) {
		i = sort_data[k].module_index;
		if(c->module_info[i].id &&
			!(c->module_info[i].flags&DE_MODFLAG_HIDDEN) &&
			!(c->module_info[i].flags&DE_MODFLAG_NONWORKING) )
		{
			if(c->module_info[i].desc)
				de_printf(c, DE_MSGTYPE_MESSAGE, "%-14s %s\n", c->module_info[i].id, c->module_info[i].desc);
			else
				de_printf(c, DE_MSGTYPE_MESSAGE, "%s\n", c->module_info[i].id);
		}
	}

	de_free(c, sort_data);
}

void de_run(deark *c)
{
	dbuf *orig_ifile = NULL;
	dbuf *subfile = NULL;
	de_int64 subfile_size;
	struct deark_module_info *module_to_use = NULL;

	if(!c->input_filename) {
		de_err(c, "Input file not set\n");
		de_fatalerror(c);
		return;
	}

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

	if(c->input_format_req) {
		module_to_use = de_get_module_by_id(c, c->input_format_req);
		if(!module_to_use) {
			de_err(c, "Unknown module \"%s\"\n", c->input_format_req);
			goto done;
		}
	}

	if(!module_to_use) {
		module_to_use = detect_module_for_file(c);
	}

	if(!module_to_use) {
		if(c->infile->len==0)
			de_err(c, "Unknown or unsupported file format (empty file)\n");
		else
			de_err(c, "Unknown or unsupported file format\n");
		goto done;
	}

	de_msg(c, "Module: %s\n", module_to_use->id);
	de_dbg(c, "File size: %" INT64_FMT "\n", dbuf_get_length(c->infile));

	if(!de_run_module(c, module_to_use, NULL)) {
		goto done;
	}

	// The DE_MODFLAG_NOEXTRACT flag means the module is not expected to extract
	// any files.
	if(c->file_count==0 && c->error_count==0 &&
		!(module_to_use->flags&DE_MODFLAG_NOEXTRACT))
	{
		de_msg(c, "No files found to extract!\n");
	}

done:
	if(subfile) dbuf_close(subfile);
	if(orig_ifile) dbuf_close(orig_ifile);
}
