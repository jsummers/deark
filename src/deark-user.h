// This file is part of Deark.
// Copyright (C) 2016-2018 Jason Summers
// See the file COPYING for terms of use.

// Definitions used by the command-line utility, and not visible to modules.

#ifndef DEARK_H_INC
#include "deark.h"
#endif

deark *de_create(void);
void de_destroy(deark *c);

void de_register_modules(deark *c);

void de_exitprocess(void);

#define DE_INPUTSTYLE_FILE    0
#define DE_INPUTSTYLE_STDIN   1
void de_set_input_style(deark *c, int x);

void de_set_input_filename(deark *c, const char *fn);
int de_set_input_encoding(deark *c, const char *encname, int reserved);
void de_set_input_file_slice_start(deark *c, de_int64 n);
void de_set_input_file_slice_size(deark *c, de_int64 n);

void de_run(deark *c);

void de_print_module_list(deark *c);

void de_set_userdata(deark *c, void *x);
void *de_get_userdata(deark *c);

// 0=off  1=normal  2=verbose
void de_set_debug_level(deark *c, int x);
void de_set_dprefix(deark *c, const char *s);

// See DE_EXTRACTPOLICY_ in deark.h
void de_set_extract_policy(deark *c, int x);

// 1=normal. 2=extract everything we can, no matter how useless
void de_set_extract_level(deark *c, int x);

void de_set_listmode(deark *c, int x);
void de_set_want_modhelp(deark *c, int x);
void de_set_first_output_file(deark *c, int x);
void de_set_max_output_files(deark *c, int n);
void de_set_max_image_dimension(deark *c, de_int64 n);
void de_set_messages(deark *c, int x);
void de_set_warnings(deark *c, int x);

// When we write a UTF-8 text file, should we start it with a BOM?
void de_set_write_bom(deark *c, int x);

void de_set_write_density(deark *c, int x);

// Use only ASCII in HTML documents.
void de_set_ascii_html(deark *c, int x);

// If a file contains a name that we can use as part of the output filename,
// should we use it?
void de_set_filenames_from_file(deark *c, int x);

void de_set_preserve_file_times(deark *c, int x);

void de_set_ext_option(deark *c, const char *name, const char *val);

void de_set_messages_callback(deark *c, de_msgfn_type fn);
void de_set_special_messages_callback(deark *c, de_specialmsgfn_type fn);

// The caller's fatalerror callback is not expected to return.
void de_set_fatalerror_callback(deark *c, de_fatalerrorfn_type fn);

void de_set_input_format(deark *c, const char *fmtname);
void de_set_module_init_codes(deark *c, const char *codes);

// See DE_OUTPUTSTYLE_ defs in deark.h
void de_set_output_style(deark *c, int x);

void de_set_base_output_filename(deark *c, const char *fn);

void de_set_output_archive_filename(deark *c, const char *fn);

void de_set_extrlist_filename(deark *c, const char *fn);

#ifdef DE_WINDOWS
void de_utf8_to_oem(deark *c, const char *src, char *dst, size_t dstlen);
char **de_convert_args_to_utf8(int argc, wchar_t **argvW);
void de_free_utf8_args(int argc, char **argv);
wchar_t *de_utf8_to_utf16_strdup(deark *c, const char *src);
void de_utf8_to_utf16_to_FILE(deark *c, const char *src, FILE *f);
void *de_winconsole_get_handle(int n);
int de_winconsole_is_console(void *h1);
int de_get_current_windows_attributes(void *handle, unsigned int *attrs);
void de_windows_highlight(void *handle1, unsigned int orig_attr, int x);
#endif
