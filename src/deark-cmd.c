// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Command-line interface

#include "deark-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DE_WINDOWS
#include <fcntl.h>
#include <io.h> // for _setmode
#endif

#include "deark.h"

struct cmdctx {
	const char *input_filename;
	int error_flag;
	int usage_error_flag;
#ifdef DE_WINDOWS
	int have_windows_console;
#endif
};

static void show_version(deark *c)
{
	char vbuf[80];
	de_printf(c, DE_MSGTYPE_MESSAGE, "Deark version %s\n",
		de_get_version_string(vbuf, sizeof(vbuf)));
}

static void show_usage(deark *c)
{
	show_version(c);
	de_puts(c, DE_MSGTYPE_MESSAGE, "usage: deark [options] <input-file>\n");
}

static void our_msgfn(deark *c, int msgtype, const char *s)
{
#ifdef DE_WINDOWS
	struct cmdctx *cc;

	cc = de_get_userdata(c);
	if(cc->have_windows_console) {
		wchar_t *s_w;
		s_w = de_utf8_to_utf16_strdup(c, s);
		fputws(s_w, stdout);
		de_free(c, s_w);
	}
	else {
		fputs(s, stdout);
	}
#else
	fputs(s, stdout);
#endif
}

static void our_fatalerrorfn(deark *c)
{
	de_puts(c, DE_MSGTYPE_MESSAGE, "exiting\n");
	exit(1);
}

static void set_option(deark *c, struct cmdctx *cc, const char *optionstring)
{
	char *tmp;
	char *eqpos;

	tmp = de_strdup(c, optionstring);
	if(!tmp) return;

	eqpos = strchr(tmp, '=');
	if(eqpos) {
		*eqpos = '\0';
		de_set_option(c, tmp, eqpos+1);
	}
	else {
		// No "=" symbol
		de_set_option(c, tmp, "");
	}
}

static void parse_cmdline(deark *c, struct cmdctx *cc, int argc, char **argv)
{
	int i;

	for(i=1;i<argc;i++) {
		if(argv[i][0]=='-') {
			if(!strcmp(argv[i]+1, "d")) {
				de_set_debug_level(c, 1);
			}
			else if(!strcmp(argv[i]+1, "d2")) {
				de_set_debug_level(c, 2);
			}
			else if(!strcmp(argv[i]+1, "l")) {
				de_set_listmode(c, 1);
			}
			else if(!strcmp(argv[i]+1, "noinfo")) {
				de_set_messages(c, 0);
			}
			else if(!strcmp(argv[i]+1, "nowarn")) {
				de_set_warnings(c, 0);
			}
			else if(!strcmp(argv[i]+1, "nobom")) {
				de_set_write_bom(c, 0);
			}
			else if(!strcmp(argv[i]+1, "q")) {
				de_set_messages(c, 0);
				de_set_warnings(c, 0);
			}
			else if(!strcmp(argv[i]+1, "version")) {
				show_version(c);
				cc->error_flag = 1;
				return;
			}
			else if(!strcmp(argv[i]+1, "extractall")) {
				de_set_extract_level(c, 2);
			}
			else if(!strcmp(argv[i]+1, "zip")) {
				de_set_output_style(c, DE_OUTPUTSTYLE_ZIP);
			}
			else if(!strcmp(argv[i]+1, "opt") && i<argc-1) {
				set_option(c, cc, argv[i+1]);
				i++; // skip past "name=val" argument
			}
			else if(!strcmp(argv[i]+1, "start") && i<argc-1) {
				de_set_input_file_slice_start(c, de_atoi64(argv[i+1]));
				i++;
			}
			else if(!strcmp(argv[i]+1, "size") && i<argc-1) {
				de_set_input_file_slice_size(c, de_atoi64(argv[i+1]));
				i++;
			}
			else if(!strcmp(argv[i]+1, "m") && i<argc-1) {
				de_set_input_format(c, argv[i+1]);
				i++;
			}
			else if(!strcmp(argv[i]+1, "basefn") && i<argc-1) {
				de_set_base_output_filename(c, argv[i+1]);
				i++;
			}
			else if(!strcmp(argv[i]+1, "arcfn") && i<argc-1) {
				// Relevant e.g. if the -zip option is used.
				de_set_output_archive_filename(c, argv[i+1]);
				i++;
			}
			else if(!strcmp(argv[i]+1, "get") && i<argc-1) {
				de_set_first_output_file(c, de_atoi(argv[i+1]));
				de_set_max_output_files(c, 1);
				i++;
			}
			else if(!strcmp(argv[i]+1, "firstfile") && i<argc-1) {
				de_set_first_output_file(c, de_atoi(argv[i+1]));
				i++;
			}
			else if(!strcmp(argv[i]+1, "maxfiles") && i<argc-1) {
				de_set_max_output_files(c, de_atoi(argv[i+1]));
				i++;
			}
			else {
				de_printf(c, DE_MSGTYPE_MESSAGE, "Unrecognized option: %s\n", argv[i]);
				cc->error_flag = 1;
				return;
			}
		}
		else {
			if(cc->input_filename) {
				cc->usage_error_flag = 1;
				return;
			}
			cc->input_filename = argv[i];
			de_set_input_filename(c, cc->input_filename);
		}
	}

	if(!cc->input_filename) {
		cc->usage_error_flag = 1;
		return;
	}
}

static void main2(int argc, char **argv)
{
	deark *c = NULL;
	struct cmdctx *cc = NULL;

	cc = de_malloc(NULL, sizeof(struct cmdctx));

#ifdef DE_WINDOWS
	cc->have_windows_console = de_stdout_is_windows_console();
	if(cc->have_windows_console) {
		// Call _setmode so that Unicode output to the console works correctly
		// (provided we use Unicode functions like fputws()).
		_setmode(_fileno(stdout), _O_U16TEXT);
	}
#endif

	c = de_create();
	de_set_userdata(c, (void*)cc);
	de_set_fatalerror_callback(c, our_fatalerrorfn);
	de_set_messages_callback(c, our_msgfn);

	parse_cmdline(c, cc, argc, argv);

	if(cc->usage_error_flag) {
		show_usage(c);
		goto done;
	}

	if(cc->error_flag) goto done;

	de_run(c);

done:
	de_destroy(c);

	de_free(NULL, cc);
}

#ifdef DE_WINDOWS

int wmain(int argc, wchar_t **argvW)
{
	char **argv;

	argv = de_convert_args_to_utf8(argc, argvW);
	main2(argc, argv);
	de_free_utf8_args(argc, argv);
	return 0;
}

#else

int main(int argc, char **argv)
{
	main2(argc, argv);
	return 0;
}

#endif
