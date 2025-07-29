// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-user.c
//
// Functions in this file can be called by deark-cmd.c, but should not be called
// by anything in the library or modules (use deark-util.c instead).

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-user.h"

#define DE_DEFAULT_MAX_FILE_SIZE 0x280000000LL // 10GiB
#define DE_DEFAULT_MAX_TOTAL_OUTPUT_SIZE 0x3c0000000LL // 15GiB
#define DE_DEFAULT_MAX_IMAGE_DIMENSION 10000
#define DE_DEFAULT_MAX_OUTPUT_FILES 1000 // Limit for direct output (not ZIP)
#define DE_MAX_OUTPUT_FILES_HARD_LIMIT 250000
#define DE_MAX_MP_FILES 2047

// Returns the best module to use, by looking at the file contents, etc.
static struct deark_module_info *detect_module_for_file(deark *c, int *errflag)
{
	int i;
	int result;
	int orig_errcount;
	struct deark_module_info *best_module = NULL;

	*errflag = 0;
	if(!c->detection_data) {
		c->detection_data = de_malloc(c, sizeof(struct de_detection_data_struct));
	}

	// This value is made available to modules' identification functions, so
	// that they can potentially skip expensive tests that cannot possibly return
	// a high enough confidence.
	c->detection_data->best_confidence_so_far = 0;

	orig_errcount = c->error_count;
	for(i=0; i<c->num_modules; i++) {
		if(c->module_info[i].identify_fn==NULL) continue;

		// If autodetect is disabled for this module, and its autodetect routine
		// doesn't do anything that may be needed by other modules, don't bother
		// to run this module's autodetection.
		if((c->module_info[i].flags & DE_MODFLAG_DISABLEDETECT) &&
			!(c->module_info[i].flags & DE_MODFLAG_SHAREDDETECTION))
		{
			continue;
		}

		result = c->module_info[i].identify_fn(c);

		if(c->error_count > orig_errcount) {
			// Detection routines don't normally produce errors. If one does,
			// it's probably an internal error, or other serious problem.
			*errflag = 1;
			return NULL;
		}

		if(c->module_info[i].flags & DE_MODFLAG_DISABLEDETECT) {
			// Ignore results of autodetection.
			continue;
		}

		if(result <= c->detection_data->best_confidence_so_far) continue;

		// This is the best result so far.
		c->detection_data->best_confidence_so_far = result;
		best_module = &c->module_info[i];
		if(c->detection_data->best_confidence_so_far>=100) break;
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
	return de_strcasecmp(c->module_info[m1->module_index].id,
		c->module_info[m2->module_index].id);
}

void de_print_module_list(deark *c)
{
	int i, k;
	struct sort_data_struct *sort_data = NULL;

	de_register_modules(c);

	// An index to the modules. Will be sorted by name.
	sort_data = de_mallocarray(c, c->num_modules, sizeof(struct sort_data_struct));

	for(k=0; k<c->num_modules; k++) {
		sort_data[k].c = c;
		sort_data[k].module_index = k;
	}

	qsort((void*)sort_data, (size_t)c->num_modules, sizeof(struct sort_data_struct),
		module_compare_fn);

	for(k=0; k<c->num_modules; k++) {
		const char *desc;
		i = sort_data[k].module_index;
		if(!c->module_info[i].id) continue;
		if(c->extract_level<2) {
			if(c->module_info[i].flags & (DE_MODFLAG_HIDDEN |
				DE_MODFLAG_NONWORKING | DE_MODFLAG_WARNPARSEONLY))
			{
				continue;
			}
		}
		desc = c->module_info[i].desc ? c->module_info[i].desc : "-";
		de_printf(c, DE_MSGTYPE_MESSAGE, "%-14s %s\n", c->module_info[i].id, desc);
	}

	de_free(c, sort_data);
}

static void do_modhelp_internal(deark *c, struct deark_module_info *module_to_use)
{
	int k;
	u8 printed_something = 0;
	u8 suppress_nohelpmsg = 0;

	if(!module_to_use) goto done;
	de_msg(c, "Module: %s", module_to_use->id);

	for(k=0; k<DE_MAX_MODULE_ALIASES; k++) {
		if(module_to_use->id_alias[k]) {
			de_msg(c, "Alias: %s", module_to_use->id_alias[k]);
		}
		else {
			break;
		}
	}

	if(module_to_use->desc) {
		de_msg(c, "Description: %s", module_to_use->desc);
	}
	if(module_to_use->desc2) {
		de_msg(c, "Other notes: %s", module_to_use->desc2);
		printed_something = 1;
	}

	if(module_to_use->flags&DE_MODFLAG_MULTIPART) {
		de_msg(c, "This module supports multiple input files; "
			"use the \"-mp\" option.");
		printed_something = 1;
	}

	if(module_to_use->flags&DE_MODFLAG_INTERNALONLY) {
		de_msg(c, "This module is intended for internal use only.");
		suppress_nohelpmsg = 1;
	}

	if(!module_to_use->help_fn) {
		if(!suppress_nohelpmsg) {
			de_msg(c, "No%s help available for module \"%s\".",
				(printed_something?" other":""), module_to_use->id);
		}
		goto done;
	}

	de_msg(c, "Help for module \"%s\":", module_to_use->id);
	module_to_use->help_fn(c);

done:
	;
}

static void do_modhelp(deark *c)
{
	struct deark_module_info *module_to_use = NULL;

	de_register_modules(c);
	module_to_use = de_get_module_by_id(c, c->input_format_req);
	if(!module_to_use) {
		de_err(c, "Unknown module \"%s\"", c->input_format_req);
		goto done;
	}

	if(de_strcmp(c->input_format_req, module_to_use->id)) {
		de_msg(c, "\"%s\" is an alias for module \"%s\"",
			c->input_format_req, module_to_use->id);
	}

	do_modhelp_internal(c, module_to_use);

done:
	;
}

void de_register_modules(deark *c)
{
	// The real register_modules function (de_register_modules_internal) is
	// only called indirectly, to help simplify dependencies.
	if(!c->module_register_fn) {
		de_internal_err_fatal(c, "module_register_fn not set");
		return;
	}
	c->module_register_fn(c);
}

static void open_extrlist(deark *c)
{
	unsigned int flags = 0;

	if(c->extrlist_dbuf || !c->extrlist_filename) return;

	if(de_get_ext_option(c, "extrlist:append")) {
		flags |= 0x1;
	}

	c->extrlist_dbuf = dbuf_create_unmanaged_file(c, c->extrlist_filename,
		DE_OVERWRITEMODE_STANDARD, flags);
}

// Modifies c->slice_start_req
static int do_special_overlay_startpos(deark *c)
{
	i64 lfb, nblocks;
	i64 overlay_pos, overlay_len;
	int retval = 0;
	u8 sig[2];

	// Maybe we should use fmtutil_collect_exe_info() here, but it's not
	// exactly what we want, and might add a dependency on fmtutil.
	dbuf_read(c->infile, sig, 0, 2);
	if((sig[0]=='M' && sig[1]=='Z') || (sig[0]=='Z' && sig[1]=='M')) {
		;
	}
	else {
		goto done;
	}
	lfb = dbuf_getu16le(c->infile, 2);
	nblocks = dbuf_getu16le(c->infile, 4);
	nblocks &= 0x7ff;
	if(lfb==0) {
		overlay_pos = 512*nblocks;
	}
	else if(lfb<512 && nblocks>0) {
		overlay_pos = 512*(nblocks-1) + lfb;
	}
	else {
		goto done;
	}
	overlay_len = c->infile->len - overlay_pos;
	if(overlay_len<0) goto done;
	de_dbg2(c, "overlay at %"I64_FMT", len=%"I64_FMT, overlay_pos, overlay_len);
	c->slice_start_req = overlay_pos;
	c->suppress_detection_by_filename = 1;
	retval = 1;

done:
	return retval;
}

// Returns 0 on "serious" error; e.g. input file not found.
int de_run(deark *c)
{
	dbuf *orig_ifile = NULL;
	dbuf *subfile = NULL;
	i64 subfile_size;
	struct deark_module_info *module_to_use = NULL;
	int module_was_autodetected = 0;
	int moddisp;
	int subdirs_opt;
	int keepdirentries_opt;
	int tmp_opt;
	de_module_params *mparams = NULL;
	de_ucstring *friendly_infn = NULL;

	if(c->serious_error_flag) goto done;

	if(c->modhelp_req && c->input_format_req) {
		do_modhelp(c);
		goto done;
	}

	if(c->extrlist_filename) {
		open_extrlist(c);
		if(c->serious_error_flag) goto done;
	}

	friendly_infn = ucstring_create(c);

	if(c->input_style==DE_INPUTSTYLE_STDIN) {
		ucstring_append_sz(friendly_infn, "[stdin]", DE_ENCODING_LATIN1);
	}
	else if(c->input_filename) {
		ucstring_append_sz(friendly_infn, c->input_filename, DE_ENCODING_UTF8);
	}
	else {
		de_internal_err_nonfatal(c, "Input file not set");
		c->serious_error_flag = 1;
		goto done;
	}

	de_register_modules(c);

	if(c->input_format_req) {
		module_to_use = de_get_module_by_id(c, c->input_format_req);
		if(!module_to_use) {
			de_err(c, "Unknown module \"%s\"", c->input_format_req);
			c->serious_error_flag = 1;
			goto done;
		}
	}

	if(c->slice_start_req_special!=0) {
		ucstring_append_sz(friendly_infn, "[special]", DE_ENCODING_LATIN1);
	}
	else if(c->slice_size_req_valid) {
		ucstring_printf(friendly_infn, DE_ENCODING_LATIN1, "[%"I64_FMT",%"I64_FMT"]",
			c->slice_start_req, c->slice_size_req);
	}
	else if(c->slice_start_req) {
		ucstring_printf(friendly_infn, DE_ENCODING_LATIN1, "[%"I64_FMT"]", c->slice_start_req);
	}
	if(c->mp_data && c->mp_data->count>0) {
		ucstring_printf(friendly_infn, DE_ENCODING_LATIN1, " (+%d more file%s)",
			c->mp_data->count, (c->mp_data->count==1 ? "" : "s"));
	}
	de_dbg(c, "Input file: %s", ucstring_getpsz_d(friendly_infn));

	if(c->input_style==DE_INPUTSTYLE_STDIN) {
		orig_ifile = dbuf_open_input_stdin(c);
	}
	else {
		orig_ifile = dbuf_open_input_file(c, c->input_filename);

		if(orig_ifile && orig_ifile->btype==DBUF_TYPE_FIFO) {
			// Only now do we know that the input "file" is a named pipe.
			// Set a flag to remember that the input filename does not
			// reflect the file format.
			c->suppress_detection_by_filename = 1;
		}
	}
	if(!orig_ifile) {
		goto done;
	}

	c->infile = orig_ifile;

	if(c->slice_start_req_special==1) {
		if(!do_special_overlay_startpos(c)) {
			de_err(c, "File not compatible with \"-start overlay\"");
			goto done;
		}
	}

	// If we are only supposed to look at a segment of the original file,
	// do that by creating a child dbuf, using dbuf_open_input_subfile().
	if(c->slice_start_req!=0 || c->slice_size_req_valid) {
		if(c->slice_start_req<0 || c->slice_size_req<0 ||
			(c->slice_start_req+c->slice_size_req > c->infile->len))
		{
			de_err(c, "File not compatible with given -start/-size options");
			goto done;
		}

		if(c->slice_size_req_valid)
			subfile_size = c->slice_size_req;
		else
			subfile_size = c->infile->len - c->slice_start_req;
		subfile = dbuf_open_input_subfile(c->infile, c->slice_start_req, subfile_size);
		c->infile = subfile;
	}

	if(!module_to_use) {
		int errflag;

		module_to_use = detect_module_for_file(c, &errflag);
		if(errflag) goto done;
		module_was_autodetected = 1;
	}

	if(!module_to_use) {
		if(c->infile->len==0)
			de_err(c, "Unknown or unsupported file format (empty file)");
		else
			de_err(c, "Unknown or unsupported file format");
		goto done;
	}

	if(c->modhelp_req && module_was_autodetected &&
		module_to_use->unique_id!=1) // id 1 == "unsupported"
	{
		do_modhelp_internal(c, module_to_use);
		goto done;
	}

	de_info(c, "Module: %s", module_to_use->id);

	if(c->mp_data && c->mp_data->count &&
		!(module_to_use->flags&DE_MODFLAG_MULTIPART))
	{
		de_err(c, "The %s module does not support multiple input files",
			module_to_use->id);
		c->serious_error_flag = 1;
		goto done;
	}

	if(module_was_autodetected && (module_to_use->flags&DE_MODFLAG_SECURITYWARNING)) {
		de_err(c, "The %s module has not been audited for security. There is a "
			"greater than average chance that it is unsafe to use with untrusted "
			"input files. Use \"-m %s\" to confirm that you want to use it.",
			module_to_use->id, module_to_use->id);
		c->serious_error_flag = 1;
		goto done;
	}

	if(module_was_autodetected && (module_to_use->flags&DE_MODFLAG_WARNPARSEONLY)) {
		de_warn(c, "The %s module can parse files, but does not generally support "
			"extracting data.", module_to_use->id);
	}
	if(module_to_use->flags&DE_MODFLAG_NONWORKING) {
		de_warn(c, "The %s module is considered to be incomplete, and may "
			"not work properly. Caveat emptor.",
			module_to_use->id);
	}

	if(c->identify_only) {
		// Stop here, unless we're using the "unsupported" module.
		if(module_to_use->unique_id!=1) {
			goto done;
		}
	}

	de_dbg2(c, "file size: %" I64_FMT "", c->infile->len);

	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
		subdirs_opt = de_get_ext_option_bool(c, "archive:subdirs", -1);
		if(subdirs_opt<0) {
			// By default, for archive output, enable subdirs unless -o was used.
			if(!c->base_output_filename) {
				c->allow_subdirs = 1;
			}
		}
		else {
			c->allow_subdirs = subdirs_opt?1:0;
		}
	}

	keepdirentries_opt = de_get_ext_option_bool(c, "keepdirentries", -1);
	if(keepdirentries_opt<0) {
		// By default, only keep dir entries if there is some way that
		// files can be present in such a subdir.
		c->keep_dir_entries = (u8)(
			(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) &&
			c->allow_subdirs &&
			(!c->base_output_filename));
	}
	else {
		c->keep_dir_entries = keepdirentries_opt?1:0;
	}

	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
		const char *s_opt;

		s_opt = de_get_ext_option(c, "archive:timestamp");
		if(s_opt) {
			c->reproducible_output = 1;
			de_unix_time_to_timestamp(de_atoi64(s_opt), &c->reproducible_timestamp, 0x1);
			if(!c->reproducible_timestamp.is_valid) {
				// Timestamp out of range? Note: Supported range is
				//  -11644473599 ( 1601-01-01 00:00:01) through
				//  910692730085 (30828-09-14 02:48:05)
				c->reproducible_output = 0;
			}
		}
		else {
			if(de_get_ext_option(c, "archive:repro")) {
				c->reproducible_output = 1;
			}
		}
	}

	if(c->output_style==DE_OUTPUTSTYLE_DIRECT &&
		c->max_output_files > DE_DEFAULT_MAX_OUTPUT_FILES &&
		!c->list_mode && !c->user_set_max_output_files)
	{
		c->max_output_files = DE_DEFAULT_MAX_OUTPUT_FILES;
	}

	if(de_get_ext_option_bool(c, "oinfo", 0)) {
		c->enable_oinfo = 1;
	}

	tmp_opt = de_get_ext_option_bool(c, "wbuffer", -1);
	if(tmp_opt>0) {
		// For testing(?), enable wbuffer feature automatically in some cases.
		c->enable_wbuffer_test = 1;
	}
	else if(tmp_opt==0) {
		// Always disable wbuffer, even if a module wants to use it.
		c->disable_wbuffer = 1;
	}

	// If we're writing to a zip file, we normally defer creating that zip file
	// until we find a file to extract, so that we never create a zip file with
	// no member files.
	// But if the zip "file" is going to stdout, we'll make sure we produce zip
	// output, even if it has no member files.
	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE && c->archive_to_stdout) {
		if(!de_archive_initialize(c)) {
			goto done;
		}
	}

	if(c->list_mode) {
		if(de_get_ext_option_bool(c, "list:fileid", 0)) {
			c->list_mode_include_file_id = 1;
		}
	}

	if(c->modcodes_req) {
		if(!mparams)
			mparams = de_malloc(c, sizeof(de_module_params));
		// This is a hack, mainly for developer use. It lets the user set the
		// "module codes" string from the command line, so that some modules
		// can be run in special modes. For example, you can run the psd module
		// in its "tagged blocks" mode. (If that turns out to be useful, though,
		// it would be better to make it available via an "-opt" option, or
		// even a new module.)
		mparams->in_params.codes = c->modcodes_req;
	}

	if(module_was_autodetected)
		moddisp = DE_MODDISP_AUTODETECT;
	else
		moddisp = DE_MODDISP_EXPLICIT;

	if(!de_run_module(c, module_to_use, mparams, moddisp)) {
		goto done;
	}

	// The DE_MODFLAG_NOEXTRACT flag means the module is not expected to extract
	// any files.
	if(c->num_files_extracted==0 && c->error_count==0 &&
		!(module_to_use->flags&DE_MODFLAG_NOEXTRACT))
	{
		de_info(c, "No files found to extract!");
	}

done:
	if(c->extrlist_dbuf) { dbuf_close(c->extrlist_dbuf); c->extrlist_dbuf=NULL; }
	ucstring_destroy(friendly_infn);
	if(subfile) dbuf_close(subfile);
	if(orig_ifile) dbuf_close(orig_ifile);
	c->infile = NULL;
	de_free(c, mparams);
	return c->serious_error_flag ? 0 : 1;
}

deark *de_create_internal(void)
{
	deark *c;
	c = de_malloc(NULL,sizeof(deark));
	c->show_infomessages = 1;
	c->show_warnings = 1;
	c->write_bom = 1;
	c->write_density = 1;
	c->filenames_from_file = 1;
	c->append_riscos_type = 0xff;
	c->preserve_file_times = 1;
	c->preserve_file_times_archives = 1;
	c->preserve_file_times_internal = 1;
	c->max_output_files = DE_MAX_OUTPUT_FILES_HARD_LIMIT;
	c->max_image_dimension = DE_DEFAULT_MAX_IMAGE_DIMENSION;
	c->max_output_file_size = DE_DEFAULT_MAX_FILE_SIZE;
	c->max_total_output_size = DE_DEFAULT_MAX_TOTAL_OUTPUT_SIZE;
	c->current_time.is_valid = 0;
	c->can_decode_fltpt = -1; // = unknown
	c->host_is_le = -1; // = unknown
	c->input_encoding = DE_ENCODING_UNKNOWN;
	return c;
}

void de_destroy(deark *c)
{
	int i;

	if(!c) return;
	if(c->zip_data) { de_zip_close_file(c); }
	if(c->tar_data) { de_tar_close_file(c); }
	if(c->extrlist_dbuf) { dbuf_close(c->extrlist_dbuf); }
	for(i=0; i<c->num_ext_options; i++) {
		de_free(c, c->ext_option[i].name);
		de_free(c, c->ext_option[i].val);
	}
	if(c->base_output_filename) { de_free(c, c->base_output_filename); }
	if(c->special_1st_filename) { de_free(c, c->special_1st_filename); }
	if(c->output_archive_filename) { de_free(c, c->output_archive_filename); }
	if(c->extrlist_filename) { de_free(c, c->extrlist_filename); }
	if(c->detection_data) { de_free(c, c->detection_data); }
	if(c->mp_data) {
		for(i=0; i<c->mp_data->count; i++) {
			dbuf_close(c->mp_data->item[i].f);
			// (The .fn field is owned by the caller (deark-cmd.c)).
		}
		de_free(c, c->mp_data->item);
		de_free(c, c->mp_data);
	}
	for(i=0; i<DE_NUM_PERSISTENT_MEM_ITEMS; i++) {
		if(c->persistent_item[i]) {
			de_free(c, c->persistent_item[i]);
		}
	}
	de_free(c, c->module_info);
	de_free(NULL,c);
}

void de_set_userdata(deark *c, void *x)
{
	c->userdata = x;
}

void *de_get_userdata(deark *c)
{
	return c->userdata;
}

void de_set_messages_callback(deark *c, de_msgfn_type fn)
{
	c->msgfn = fn;
}

void de_set_special_messages_callback(deark *c, de_specialmsgfn_type fn)
{
	c->specialmsgfn = fn;
}

void de_set_fatalerror_callback(deark *c, de_fatalerrorfn_type fn)
{
	c->fatalerrorfn = fn;
}

static int is_pathsep(de_rune ch)
{
	if(ch=='/') return 1;
#ifdef DE_WINDOWS
	if(ch=='\\') return 1;
#endif
	return 0;
}

#ifdef DE_WINDOWS
#define DE_PATHSEP '\\'
#else
#define DE_PATHSEP '/'
#endif

static const char *get_basename_ptr(const char *fn)
{
	size_t i;
	const char *basenameptr = fn;

	for(i=0; fn[i]; i++) {
		if(is_pathsep(fn[i])) {
			basenameptr = &fn[i+1];
		}
	}
	return basenameptr;
}

static de_rune ucstring_char_at(de_ucstring *s, i64 pos)
{
	if(!s) return 0;
	if(pos>=0 && pos<s->len) return s->str[pos];
	return 0;
}

#ifdef DE_WINDOWS
static void backslashes_to_slashes(de_ucstring *s)
{
	i64 i;

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='\\') {
			s->str[i] = '/';
		}
	}
}
#endif

#ifdef DE_WINDOWS
static int is_alpha_char(de_rune x)
{
	return (x>='A' && x<='Z') || (x>='a' && x<='z');
}
#endif

static void append_pathsep_if_needed(de_ucstring *s)
{
	de_rune lastchar;

	if(s->len<1) return;

	lastchar = ucstring_char_at(s, s->len-1);

#ifdef DE_WINDOWS
	if(s->len==2 && lastchar==':' &&
		is_alpha_char(ucstring_char_at(s, 0)))
	{
		// This is arguable, but we won't append a backslash to Windows
		// paths like "D:", so output files will go to that drive's
		// own "current directory".
		return;
	}
#endif

#if DE_BUILDFLAG_AMIGA
	if(lastchar==':') {
		// Assuming this is a device name, so putting a "/" after it is not
		// allowed.
		return;
	}
#endif

	if(!is_pathsep(lastchar)) {
		ucstring_append_char(s, DE_PATHSEP);
	}
}

// Construct a basename for output files, or a filename for archives.
// flags:
//  0x1 = use base filename only
//  0x2 = remove path separators
//  0x4 = this is an "internal" filename for a zip/tar archive
// Returns an allocated string, which the caller must eventually free.
// Returns NULL if it can't make a decent filename.
static char *make_output_filename(deark *c, const char *dirname, const char *fn,
	const char *suffix, unsigned int flags)
{
	char *newfn = NULL;
	const char *fn_part;
	size_t newfn_alloc;
	de_ucstring *tmps = NULL;
	i64 fnpartpos;

	tmps = ucstring_create(c);

	if(dirname && dirname[0]) {
		ucstring_append_sz(tmps, dirname, DE_ENCODING_UTF8);
		append_pathsep_if_needed(tmps);
	}

	fnpartpos = tmps->len;

	if(flags & 0x1) {
		// Use base filename only
		fn_part = get_basename_ptr(fn);
	}
	else {
		fn_part = fn;
	}
	if(fn_part) {
		ucstring_append_sz(tmps, fn_part, DE_ENCODING_UTF8);
	}

	if(tmps->len <= fnpartpos) {
		// Disallow empty filename
		ucstring_append_sz(tmps, "_", DE_ENCODING_LATIN1);
	}

	if(suffix) {
		ucstring_append_sz(tmps, suffix, DE_ENCODING_UTF8);
	}

	if(flags & 0x2) {
		// Remove path separators; sanitize
		i64 i;

		for(i=fnpartpos; i<tmps->len; i++) {
			if(is_pathsep(tmps->str[i])) {
				tmps->str[i] = '_';
			}

			if(i==fnpartpos && tmps->str[i]=='.') {
				tmps->str[i] = '_';
			}
		}
	}

#ifdef DE_WINDOWS
	if(flags & 0x4) {
		// When a filename-like option is supplied on the command line, there are
		// cases where we can't be agnostic about which characters are path
		// separators. One of them is when that name is written to an archive
		// (zip/tar) file.
		// Our rule is that, for Windows builds, both "\" and "/" are path
		// separators. For Unix builds, only "/" is, and "\" will be treated as
		// an ordinary filename character, if allowed by the archive format.
		// This difference in behavior on different platforms is unfortunate, but
		// I think it's the least bad thing to do.
		backslashes_to_slashes(tmps);
	}
#endif

	// Don't allow empty filename
	if(tmps->len<1) goto done;

	newfn_alloc = (size_t)ucstring_count_utf8_bytes(tmps) + 1;
	newfn = de_malloc(c, newfn_alloc);
	ucstring_to_sz(tmps, newfn, newfn_alloc, 0, DE_ENCODING_UTF8);

done:
	ucstring_destroy(tmps);
	return newfn;
}

// Must call de_set_output_style() before this, if at all.
// flags:
//  0x1 = use base filename only
//  0x2 = remove path separators
void de_set_output_filename_pattern(deark *c, const char *dirname, const char *fn,
	unsigned int flags)
{
	if(c->base_output_filename) de_free(c, c->base_output_filename);
	c->base_output_filename = NULL;
	if(!fn && !dirname) return;
	if(!fn) fn = "output";
	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
		flags |= 0x4;
	}
	c->base_output_filename = make_output_filename(c, dirname, fn, NULL, flags);
}

// Use exactly fn for the first output file (no ".000.")
// Must call de_set_output_style() before this, if at all.
void de_set_output_special_1st_filename(deark *c, const char *dirname, const char *fn)
{
	if(c->special_1st_filename) {
		de_free(c, c->special_1st_filename);
		c->special_1st_filename = NULL;
	}
	if(fn) {
		UI flags = 0;

		if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
			flags |= 0x4;
		}

		c->special_1st_filename = make_output_filename(c, dirname, fn, NULL, flags);
	}
}

// If flags&0x10, configure the archive file to be written to stdout.
// 0x20 = Append ".zip"/".tar" (must have already called de_set_output_style())
//  0x1 = use base filename only
//  0x2 = remove path separators
void de_set_output_archive_filename(deark *c, const char *dname, const char *fn,
	unsigned int flags)
{
	const char *suffix = NULL;
	if(c->output_archive_filename) de_free(c, c->output_archive_filename);

	if(flags&0x10) {
		c->archive_to_stdout = 1;
		return;
	}

	if((flags & 0x20) && c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
		if(c->archive_fmt==DE_ARCHIVEFMT_ZIP) {
			suffix = ".zip";
		}
		else if(c->archive_fmt==DE_ARCHIVEFMT_TAR) {
			suffix = ".tar";
		}
		else {
			suffix = ".err";
		}
	}

	c->output_archive_filename = make_output_filename(c, dname, fn, suffix, flags);
}

void de_set_extrlist_filename(deark *c, const char *fn)
{
	if(c->extrlist_filename) de_free(c, c->extrlist_filename);
	c->extrlist_filename = NULL;
	if(fn) {
		c->extrlist_filename = de_strdup(c, fn);
	}
}

void de_set_std_option_int(deark *c, enum de_stdoptions_enum o, int x)
{
	switch(o) {
	case DE_STDOPT_DEBUG_LEVEL:
		c->debug_level = x;
		break;
	case DE_STDOPT_EXTRACT_POLICY:
		c->extract_policy = x;
		break;
	case DE_STDOPT_EXTRACT_LEVEL:
		c->extract_level = x;
		break;
	case DE_STDOPT_LISTMODE:
		c->list_mode = x?1:0;
		break;
	case DE_STDOPT_WANT_MODHELP:
		c->modhelp_req = x?1:0;
		break;
	case DE_STDOPT_ID_MODE:
		c->identify_only = x?1:0;
		break;
	case DE_STDOPT_WARNINGS:
		c->show_warnings = x;
		break;
	case DE_STDOPT_INFOMESSAGES:
		c->show_infomessages = x;
		break;
	case DE_STDOPT_MP_OPT_USED:
		// We track this mainly so that modules can use it to construct better
		// error messages, and not tell the user to use "-mp" when they
		// already did.
		c->mp_opt_used = 1;
		break;
	case DE_STDOPT_WRITE_BOM:
		c->write_bom = (u8)x;
		break;
	case DE_STDOPT_WRITE_DENSITY:
		c->write_density = (u8)x;
		break;
	case DE_STDOPT_ASCII_HTML:
		c->ascii_html = (u8)x;
		break;
	case DE_STDOPT_FILENAMES_FROM_FILE:
		c->filenames_from_file = (u8)x;
		break;
	case DE_STDOPT_OVERWRITE_MODE:
		c->overwrite_mode = x;
		break;
	case DE_STDOPT_PADPIX:
		c->padpix = (u8)x;
		break;
	default:
		de_internal_err_fatal(c, "set_std_option");
	}
}

void de_set_input_style(deark *c, int x)
{
	c->input_style = x;
}

// Notes on the multipart input file feature:
// The module tests c->mp_data != NULL to see if there are additional
// input files after the first.
// The extra files are not opened automatically. The module must do that.
// The module should use dbuf_open_input_file() to open files as needed.
// dbuf_open_input_file() may fail, report an error, and return NULL, in
// which case the module should probably stop immediately.
// The module can use mp_data->item[].f, but is not required to. If the
// module leaves it set, it will be closed automatically.
// (Use de_mp_acquire/release_dbuf() to make this easier.)
// The first file is still c->infile, the same as for any other module.
// (It's unfortunate that the first file is such a special case, but that's
// the way it is for now.)
// Commmand-line options -start and -size apply only to the first file.
static void de_add_input_filename_mp(deark *c, const char *fn)
{
	int prev_count, new_count;
	int new_idx;

	if(!c->mp_data) {
		c->mp_data = de_malloc(c, sizeof(struct de_mp_data));
	}
	prev_count = c->mp_data->count;
	if(prev_count >= DE_MAX_MP_FILES) {
		de_err(c, "Too many input files");
		c->serious_error_flag = 1;
		return;
	}

	new_count = prev_count+1;
	if(new_count > c->mp_data->alloc) {
		int new_alloc;

		new_alloc = new_count+15;
		c->mp_data->item = de_reallocarray(c, c->mp_data->item,
			(i64)c->mp_data->count, sizeof(struct de_mp_item), (i64)new_alloc);

		c->mp_data->alloc = new_alloc;
	}

	new_idx = prev_count;
	c->mp_data->item[new_idx].fn = fn;
	c->mp_data->count = new_count;
}

// flags&0x1: Allow multiple input files. If this is the first time
//   this function has been called, this flag doesn't matter.
void de_set_input_filename(deark *c, const char *fn, UI flags)
{
	if(c->input_filename && (flags&0x1)) {
		de_add_input_filename_mp(c, fn);
	}
	else {
		c->input_filename = fn;
	}
}

int de_set_input_encoding(deark *c, const char *encname, int reserved)
{
	de_encoding enc;

	enc = de_encoding_name_to_code(encname);
	if(enc==DE_ENCODING_UNKNOWN) {
		return 0;
	}
	c->input_encoding = enc;
	return 1;
}

// A hint as to the timezone of local-time timestamps in input files.
// In hours east of UTC.
void de_set_input_timezone(deark *c, i64 tzoffs_seconds)
{
	c->input_tz_offs_seconds = tzoffs_seconds;
}

void de_set_input_file_slice_start(deark *c, i64 n)
{
	c->slice_start_req = n;
}

void de_set_input_file_special_slice_start(deark *c, u8 x)
{
	c->slice_start_req_special = x;
}

void de_set_input_file_slice_size(deark *c, i64 n)
{
	c->slice_size_req = n;
	c->slice_size_req_valid = 1;
}

void de_set_output_style(deark *c, int x, int subtype)
{
	c->output_style = x;
	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) {
		c->archive_fmt = subtype;
	}
	else {
		c->archive_fmt = 0;
	}
}

void de_set_dprefix(deark *c, const char *s)
{
	c->dprefix = s;
}

void de_set_first_output_file(deark *c, int x)
{
	c->first_output_file = x;
}

void de_set_max_output_files(deark *c, i64 n)
{
	if(n>DE_MAX_OUTPUT_FILES_HARD_LIMIT) {
		c->max_output_files = DE_MAX_OUTPUT_FILES_HARD_LIMIT;
	}
	else if(n<0) {
		c->max_output_files = 0;
	}
	else {
		c->max_output_files = (int)n;
	}
	c->user_set_max_output_files = 1;
}

void de_set_max_output_file_size(deark *c, i64 n)
{
	if(n<0) n=0;
	c->max_output_file_size = n;
	if(c->max_total_output_size < n) {
		c->max_total_output_size = n;
	}
}

void de_set_max_total_output_size(deark *c, i64 n)
{
	if(n<0) n=0;
	c->max_total_output_size = n;
}

void de_set_max_image_dimension(deark *c, i64 n)
{
	if(n<0) n=0;
	else if (n>0x7fffffff) n=0x7fffffff;
	c->max_image_dimension = n;
}

void de_set_preserve_file_times(deark *c, int setting, int x)
{
	if(setting==0) {
		// For files written directly to the filesystem.
		c->preserve_file_times = x?1:0;
	}
	else if(setting==1) {
		// For member files written to .zip/.tar files.
		// I can't think of a good reason why a user would want to disable
		// this, but it's allowed for consistency, and it doesn't hurt
		// anything.
		c->preserve_file_times_archives = x?1:0;
	}
	else if(setting==2) {
		// For the tIME chunk in PNG files we generate, and other internal timestamps.
		// (Not currently used.)
		// TODO: I'm undecided about whether this should be a user option, or
		// just always be on.
		// TODO: If we allow this setting to be turned off, it would be
		// consistent to rename it, and use it for all "converted" formats,
		// including e.g. the "Date" header item in ANSI Art files converted
		// to HTML.
		c->preserve_file_times_internal = x?1:0;
	}
}

void de_set_ext_option(deark *c, const char *name, const char *val)
{
	int n;

	n = c->num_ext_options;
	if(n>=DE_MAX_EXT_OPTIONS) return;
	if(!name || !val) return;

	c->ext_option[n].name = de_strdup(c, name);
	c->ext_option[n].val = de_strdup(c, val);
	c->num_ext_options++;
}

void de_set_input_format(deark *c, const char *fmtname)
{
	c->input_format_req = fmtname;
}

void de_set_module_init_codes(deark *c, const char *codes)
{
	c->modcodes_req = codes;
}

// invert=0: Disable the mods in the list
// invert=1: Disable all mods not in the list
void de_set_disable_mods(deark *c, const char *s, int invert)
{
	if(invert==0) {
		c->disablemods_string = s;
	}
	else {
		c->onlymods_string = s;
	}
}

// invert=0: Disable autodetection of the mods in the list
// invert=1: Disable autodetection of all mods not in the list
void de_set_disable_moddetect(deark *c, const char *s, int invert)
{
	if(invert==0) {
		c->nodetectmods_string = s;
	}
	else {
		c->onlydetectmods_string = s;
	}
}
