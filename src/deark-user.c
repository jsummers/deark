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

	// Check for a UTF-8 BOM just once. Any module can use this flag.
	if(dbuf_has_utf8_bom(c->infile, 0)) {
		c->detection_data->has_utf8_bom = 1;
	}

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
			if(c->module_info[i].flags & DE_MODFLAG_HIDDEN) continue;
			if(c->module_info[i].flags & DE_MODFLAG_NONWORKING) continue;
		}
		desc = c->module_info[i].desc ? c->module_info[i].desc : "-";
		de_printf(c, DE_MSGTYPE_MESSAGE, "%-14s %s\n", c->module_info[i].id, desc);
	}

	de_free(c, sort_data);
}

static void do_modhelp_internal(deark *c, struct deark_module_info *module_to_use)
{
	int k;

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
	}

	if(!module_to_use->help_fn) {
		de_msg(c, "No help available for module \"%s\"", module_to_use->id);
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
		de_err(c, "Internal: module_register_fn not set");
		de_fatalerror(c);
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
	de_module_params *mparams = NULL;
	de_ucstring *friendly_infn = NULL;

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
	else {
		if(!c->input_filename) {
			de_err(c, "Internal: Input file not set");
			c->serious_error_flag = 1;
			goto done;
		}
		ucstring_append_sz(friendly_infn, c->input_filename, DE_ENCODING_UTF8);
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

	if(c->slice_size_req_valid) {
		de_dbg(c, "Input file: %s[%d,%d]", ucstring_getpsz_d(friendly_infn),
			(int)c->slice_start_req, (int)c->slice_size_req);
	}
	else if(c->slice_start_req) {
		de_dbg(c, "Input file: %s[%d]", ucstring_getpsz_d(friendly_infn),
			(int)c->slice_start_req);
	}
	else {
		de_dbg(c, "Input file: %s", ucstring_getpsz_d(friendly_infn));
	}

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

	// If we are only supposed to look at a segment of the original file,
	// do that by creating a child dbuf, using dbuf_open_input_subfile().
	if(c->slice_start_req>0 || c->slice_size_req_valid) {
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

	if(module_was_autodetected && (module_to_use->flags&DE_MODFLAG_SECURITYWARNING)) {
		de_err(c, "The %s module has not been audited for security. There is a "
			"greater than average chance that it is unsafe to use with untrusted "
			"input files. Use \"-m %s\" to confirm that you want to use it.",
			module_to_use->id, module_to_use->id);
		c->serious_error_flag = 1;
		goto done;
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

	if(de_get_ext_option_bool(c, "list:fileid", 0)) {
		c->list_mode_include_file_id = 1;
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
	c->preserve_file_times = 1;
	c->preserve_file_times_archives = 1;
	c->preserve_file_times_internal = 1;
	c->max_output_files = -1;
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
	i64 i;

	if(!c) return;
	if(c->extrlist_dbuf) { dbuf_close(c->extrlist_dbuf); }
	for(i=0; i<c->num_ext_options; i++) {
		de_free(c, c->ext_option[i].name);
		de_free(c, c->ext_option[i].val);
	}
	if(c->zip_data) { de_zip_close_file(c); }
	if(c->tar_data) { de_tar_close_file(c); }
	if(c->base_output_filename) { de_free(c, c->base_output_filename); }
	if(c->output_archive_filename) { de_free(c, c->output_archive_filename); }
	if(c->extrlist_filename) { de_free(c, c->extrlist_filename); }
	if(c->detection_data) { de_free(c, c->detection_data); }
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

static int is_pathsep(i32 ch)
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

static i32 ucstring_char_at(de_ucstring *s, i64 pos)
{
	if(!s) return 0;
	if(pos>=0 && pos<s->len) return s->str[pos];
	return 0;
}

// Construct a basename for output files, or a filename for archives.
// flags:
//  0x1 = use base filename only
//  0x2 = remove path separators
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
		if(!is_pathsep(ucstring_char_at(tmps, tmps->len-1))) {
			ucstring_append_char(tmps, DE_PATHSEP);
		}
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

	// Don't allow empty filename
	if(tmps->len<1) goto done;

	newfn_alloc = (size_t)ucstring_count_utf8_bytes(tmps) + 1;
	newfn = de_malloc(c, newfn_alloc);
	ucstring_to_sz(tmps, newfn, newfn_alloc, 0, DE_ENCODING_UTF8);

done:
	ucstring_destroy(tmps);
	return newfn;
}

// flags:
//  0x1 = use base filename only
//  0x2 = remove path separators
void de_set_base_output_filename(deark *c, const char *dirname, const char *fn,
	unsigned int flags)
{
	if(c->base_output_filename) de_free(c, c->base_output_filename);
	c->base_output_filename = NULL;
	if(!fn && !dirname) return;
	if(!fn) fn = "output";
	c->base_output_filename = make_output_filename(c, dirname, fn, NULL, flags);
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

void de_set_input_style(deark *c, int x)
{
	c->input_style = x;
}

void de_set_input_filename(deark *c, const char *fn)
{
	c->input_filename = fn;
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

void de_set_debug_level(deark *c, int x)
{
	c->debug_level = x;
}

void de_set_dprefix(deark *c, const char *s)
{
	c->dprefix = s;
}

void de_set_extract_policy(deark *c, int x)
{
	c->extract_policy = x;
}

void de_set_extract_level(deark *c, int x)
{
	c->extract_level = x;
}

void de_set_listmode(deark *c, int x)
{
	c->list_mode = x?1:0;
}

void de_set_want_modhelp(deark *c, int x)
{
	c->modhelp_req = x?1:0;
}

void de_set_id_mode(deark *c, int x)
{
	c->identify_only = x?1:0;
}

void de_set_first_output_file(deark *c, int x)
{
	c->first_output_file = x;
}

void de_set_max_output_files(deark *c, int n)
{
	c->max_output_files = n;
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

void de_set_infomessages(deark *c, int x)
{
	c->show_infomessages = x;
}

void de_set_warnings(deark *c, int x)
{
	c->show_warnings = x;
}

void de_set_write_bom(deark *c, int x)
{
	c->write_bom = (u8)x;
}

void de_set_write_density(deark *c, int x)
{
	c->write_density = (u8)x;
}

void de_set_ascii_html(deark *c, int x)
{
	c->ascii_html = (u8)x;
}

void de_set_filenames_from_file(deark *c, int x)
{
	c->filenames_from_file = (u8)x;
}

// DE_OVERWRITEMODE_DEFAULT =
//   Overwrite, unless the filename is a symlink, in which case fail.
// DE_OVERWRITEMODE_NEVER =
//   Fail if the output file exists (or if the filename is a symlink).
// DE_OVERWRITEMODE_STANDARD =
//   Do whatever fopen() normally does (overwrite, and follow symlinks).
void de_set_overwrite_mode(deark *c, int x)
{
	c->overwrite_mode = x;
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
