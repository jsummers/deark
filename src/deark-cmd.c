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
	int special_command_flag;
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

static void set_ext_option(deark *c, struct cmdctx *cc, const char *optionstring)
{
	char *tmp;
	char *eqpos;

	tmp = de_strdup(c, optionstring);
	if(!tmp) return;

	eqpos = strchr(tmp, '=');
	if(eqpos) {
		*eqpos = '\0';
		de_set_ext_option(c, tmp, eqpos+1);
	}
	else {
		// No "=" symbol
		de_set_ext_option(c, tmp, "");
	}
}

enum opt_id_enum {
 DE_OPT_NULL=0, DE_OPT_D, DE_OPT_D2, DE_OPT_L, DE_OPT_NOINFO, DE_OPT_NOWARN,
 DE_OPT_NOBOM, DE_OPT_Q, DE_OPT_VERSION, DE_OPT_EXTRACTALL, DE_OPT_ZIP,
 DE_OPT_EXTOPT, DE_OPT_START, DE_OPT_SIZE, DE_OPT_M, DE_OPT_O,
 DE_OPT_ARCFN, DE_OPT_GET, DE_OPT_FIRSTFILE, DE_OPT_MAXFILES
};

struct opt_struct {
	const char *string;
	enum opt_id_enum id;
	int extra_args;
};

struct opt_struct option_array[] = {
	{ "d",            DE_OPT_D,            0 },
	{ "d2",           DE_OPT_D2,           0 },
	{ "l",            DE_OPT_L,            0 },
	{ "noinfo",       DE_OPT_NOINFO,       0 },
	{ "nowarn",       DE_OPT_NOWARN,       0 },
	{ "nobom",        DE_OPT_NOBOM,        0 },
	{ "q",            DE_OPT_Q,            0 },
	{ "version",      DE_OPT_VERSION,      0 },
	{ "extractall",   DE_OPT_EXTRACTALL,   0 },
	{ "zip",          DE_OPT_ZIP,          0 },
	{ "opt",          DE_OPT_EXTOPT,       1 },
	{ "start",        DE_OPT_START,        1 },
	{ "size",         DE_OPT_SIZE,         1 },
	{ "m",            DE_OPT_M,            1 },
	{ "o",            DE_OPT_O,            1 },
	{ "basefn",       DE_OPT_O,            1 }, // Deprecated
	{ "arcfn",        DE_OPT_ARCFN,        1 },
	{ "get",          DE_OPT_GET,          1 },
	{ "firstfile",    DE_OPT_FIRSTFILE,    1 },
	{ "maxfiles",     DE_OPT_MAXFILES,     1 },
	{ NULL,           DE_OPT_NULL,         0 }
};

static struct opt_struct *opt_string_to_opt_struct(const char *s)
{
	int k;

	for(k=0; option_array[k].id!=DE_OPT_NULL; k++) {
		if(!strcmp(s, option_array[k].string)) {
			return &option_array[k];
		}
	}
	return NULL;
}

static void parse_cmdline(deark *c, struct cmdctx *cc, int argc, char **argv)
{
	int i;
	const struct opt_struct *opt;

	for(i=1;i<argc;i++) {
		if(argv[i][0]=='-') {
			opt = opt_string_to_opt_struct(argv[i]+1);
			if(!opt) {
				de_printf(c, DE_MSGTYPE_MESSAGE, "Unrecognized option: %s\n", argv[i]);
				cc->error_flag = 1;
				return;
			}
			if(i>=argc-opt->extra_args) {
				de_printf(c, DE_MSGTYPE_MESSAGE, "Option %s needs an argument\n", argv[i]);
				cc->error_flag = 1;
				return;
			}

			switch(opt->id) {
			case DE_OPT_D:
				de_set_debug_level(c, 1);
				break;
			case DE_OPT_D2:
				de_set_debug_level(c, 2);
				break;
			case DE_OPT_L:
				de_set_listmode(c, 1);
				break;
			case DE_OPT_NOINFO:
				de_set_messages(c, 0);
				break;
			case DE_OPT_NOWARN:
				de_set_warnings(c, 0);
				break;
			case DE_OPT_NOBOM:
				de_set_write_bom(c, 0);
				break;
			case DE_OPT_Q:
				de_set_messages(c, 0);
				de_set_warnings(c, 0);
				break;
			case DE_OPT_VERSION:
				show_version(c);
				cc->error_flag = 1;
				break;
			case DE_OPT_EXTRACTALL:
				de_set_extract_level(c, 2);
				break;
			case DE_OPT_ZIP:
				de_set_output_style(c, DE_OUTPUTSTYLE_ZIP);
				break;
			case DE_OPT_EXTOPT:
				set_ext_option(c, cc, argv[i+1]);
				break;
			case DE_OPT_START:
				de_set_input_file_slice_start(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_SIZE:
				de_set_input_file_slice_size(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_M:
				de_set_input_format(c, argv[i+1]);
				break;
			case DE_OPT_O:
				de_set_base_output_filename(c, argv[i+1]);
				break;
			case DE_OPT_ARCFN:
				// Relevant e.g. if the -zip option is used.
				de_set_output_archive_filename(c, argv[i+1]);
				break;
			case DE_OPT_GET:
				de_set_first_output_file(c, de_atoi(argv[i+1]));
				de_set_max_output_files(c, 1);
				break;
			case DE_OPT_FIRSTFILE:
				de_set_first_output_file(c, de_atoi(argv[i+1]));
				break;
			case DE_OPT_MAXFILES:
				de_set_max_output_files(c, de_atoi(argv[i+1]));
				break;
			default:
				de_printf(c, DE_MSGTYPE_MESSAGE, "Unrecognized option: %s\n", argv[i]);
				cc->error_flag = 1;
				return;
			}

			i += opt->extra_args;
		}
		else {
			if(cc->input_filename) {
				cc->error_flag = 1;
				return;
			}
			cc->input_filename = argv[i];
			de_set_input_filename(c, cc->input_filename);
		}
	}

	if(!cc->input_filename && !cc->special_command_flag) {
		cc->error_flag = 1;
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

	if(argc<2) {
		show_version(c);
		show_usage(c);
		goto done;
	}

	parse_cmdline(c, cc, argc, argv);

	if(cc->error_flag) {
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
