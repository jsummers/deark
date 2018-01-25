// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Command-line interface

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-user.h"

#ifdef DE_WINDOWS
#include <fcntl.h>
#include <io.h> // for _setmode
#endif

struct cmdctx {
	const char *input_filename;
	int error_flag;
	int show_usage_message;
	int special_command_flag;
#define CMD_PRINTMODULES 2
	int special_command_code;
	int msgs_to_stderr;

	// Have we set msgs_FILE and have_windows_console, and called _setmode if needed?
	int have_initialized_output_stream;

	FILE *msgs_FILE; // Where to print (error, etc.) messages
#ifdef DE_WINDOWS
	void *msgs_HANDLE;
	int have_windows_console; // Is msgs_FILE a console?
	int use_fwputs;
	unsigned int orig_console_attribs;
#endif

	int to_stdout;
	int to_zip;
	int from_stdin;
	int to_ascii;
	int to_oem;
	int use_color_req;
	int color_method; // 0=no color, 1=ANSI codes, 2=Windows console commands
	char msgbuf[1000];
};

static void show_version(deark *c)
{
	char vbuf[80];
	de_printf(c, DE_MSGTYPE_MESSAGE, "Deark version %s\n",
		de_get_version_string(vbuf, sizeof(vbuf)));
}

static void show_usage_preamble(deark *c) {
	de_puts(c, DE_MSGTYPE_MESSAGE, "Usage: deark [options] <input-file> [options]\n");
}

static void show_usage_error(deark *c)
{
	show_usage_preamble(c);
	de_puts(c, DE_MSGTYPE_MESSAGE, "\"deark -h\" for help.\n");
}

static void show_help(deark *c)
{
	show_version(c);
	de_puts(c, DE_MSGTYPE_MESSAGE,
		"A utility for extracting data from various file formats\n\n");
	show_usage_preamble(c);
	de_puts(c, DE_MSGTYPE_MESSAGE,
		"\nCommonly used options:\n"
		" -l: Instead of extracting, list the files that would be extracted.\n"
		" -m <module>: Assume input file is this format, instead of autodetecting.\n"
		" -o <base-filename>: Start output filenames with this string.\n"
		" -zip: Write output files to a .zip file.\n"
		" -a: Extract more data than usual.\n"
		" -main: Extract less data than usual.\n"
		" -get <n>: Extract only file number <n>.\n"
		" -d, -d2, -d3: Print additional information about the file.\n"
		" -q, -noinfo, -nowarn: Print fewer messages than usual.\n"
		" -modules: Print the names of all available modules.\n"
		" -help, -h: Print this message.\n"
		" -version: Print the version number.\n"
		);
}

static void print_modules(deark *c)
{
	de_print_module_list(c);
}

static void initialize_output_stream(struct cmdctx *cc)
{
		if(cc->msgs_to_stderr) {
			cc->msgs_FILE = stderr;
		}
		else {
			cc->msgs_FILE = stdout;
		}

#ifdef DE_WINDOWS
		// If appropriate, call _setmode so that Unicode output to the console
		// works correctly (provided we use Unicode functions like fputws()).

		cc->msgs_HANDLE = de_winconsole_get_handle(cc->msgs_to_stderr ? 2 : 1);
		cc->have_windows_console = de_winconsole_is_console(cc->msgs_HANDLE);
		if(cc->have_windows_console && !cc->to_ascii && !cc->to_oem) {
			cc->use_fwputs = 1;
			_setmode(_fileno(cc->msgs_FILE), _O_U16TEXT);
		}
		if(cc->use_color_req) {
			if(cc->have_windows_console) {
				if(de_get_current_windows_attributes(cc->msgs_HANDLE, &cc->orig_console_attribs)) {
					cc->color_method = 2;
				}
			}
			else {
				cc->color_method = 1;
			}
		}
#else
		cc->color_method = cc->use_color_req ? 1 : 0;
#endif

		if(cc->color_method==1) {
			// If using ANSI codes, start by resetting all attributes
			fputs("\x1b[0m", cc->msgs_FILE);
		}

		cc->have_initialized_output_stream = 1;
}

static void our_specialmsgfn(deark *c, unsigned int flags, unsigned int code,
	de_uint32 param1)
{
	struct cmdctx *cc;

	cc = de_get_userdata(c);
	if(!cc->color_method) return;

	if(!cc->have_initialized_output_stream) {
		initialize_output_stream(cc);
	}

#ifdef DE_WINDOWS
	if(cc->have_windows_console) {
		if(code==DE_MSGCODE_HL) {
			de_windows_highlight(cc->msgs_HANDLE, cc->orig_console_attribs, 1);
		}
		else if(code==DE_MSGCODE_UNHL) {
			de_windows_highlight(cc->msgs_HANDLE, cc->orig_console_attribs, 0);
		}
		else if(code==DE_MSGCODE_RGBSAMPLE) {
			// TODO: Traditional Windows console only supports 16 colors,
			// so there's no good solution here. We could approximate the
			// color somehow, I guess. Though that is complicated, as I think
			// the color palette can be user-defined, and different editions of
			// Windows have different default color schemes.
			// As of 2016-10, Microsoft says they've added truecolor console
			// support to Windows 10, so we should investigate that.
			;
		}
		return;
	}
	else if(cc->use_fwputs) {
		return; // Shouldn't be possible
	}
#endif

	// TODO: Maybe move the DE_COLOR_* macros to deark.h.
#define X_DE_COLOR_R(x)  (unsigned int)(((x)>>16)&0xff)
#define X_DE_COLOR_G(x)  (unsigned int)(((x)>>8)&0xff)
#define X_DE_COLOR_B(x)  (unsigned int)((x)&0xff)
	if(code==DE_MSGCODE_HL) {
		fputs("\x1b[7m", cc->msgs_FILE);
	}
	else if(code==DE_MSGCODE_UNHL) {
		fputs("\x1b[27m", cc->msgs_FILE);
	}
	else if(code==DE_MSGCODE_RGBSAMPLE) {
		// Print two spaces with their background color set to the requested color.
		fprintf(cc->msgs_FILE, "\x1b[48;2;%u;%u;%um  \x1b[0m",
			X_DE_COLOR_R(param1), X_DE_COLOR_G(param1), X_DE_COLOR_B(param1));
	}
}

static void our_msgfn(deark *c, unsigned int flags, const char *s1)
{
	struct cmdctx *cc;
	const char *s;

	cc = de_get_userdata(c);

	if(!cc->have_initialized_output_stream) {
		initialize_output_stream(cc);
	}

	if(cc->to_ascii) {
		// Note - It doesn't seem quite right to have this functionality be separate
		// from the library's *to_printable* functions, but they don't quite have
		// the same purposes, and it would be tricky to combine them.
		// This is really just a quick and dirty way to deal with systems that don't
		// support Unicode, or don't support the Unicode characters we use.

		// TODO: It's inconsistent that the de_utf8_to_ascii() and de_utf8_to_oem()
		// code paths have a size limit, while the de_utf8_to_utf16_to_FILE() and
		// fputs() paths do not.
		de_utf8_to_ascii(s1, cc->msgbuf, sizeof(cc->msgbuf), 0);
		s = cc->msgbuf;
	}
#ifdef DE_WINDOWS
	else if(cc->to_oem) {
		de_utf8_to_oem(c, s1, cc->msgbuf, sizeof(cc->msgbuf));
		s = cc->msgbuf;
	}
#endif
	else {
		s = s1;
	}

#ifdef DE_WINDOWS
	if(cc->use_fwputs) {
		de_utf8_to_utf16_to_FILE(c, s, cc->msgs_FILE);
	}
	else {
		fputs(s, cc->msgs_FILE);
	}
#else
	fputs(s, cc->msgs_FILE);
#endif
}

static void our_fatalerrorfn(deark *c)
{
	de_puts(c, DE_MSGTYPE_MESSAGE, "Exiting\n");
	de_exitprocess();
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
	de_free(c, tmp);
}

static void set_encoding_option(deark *c, struct cmdctx *cc, const char *s)
{
	if(!strcmp(s, "ascii")) {
		cc->to_ascii = 1;
	}
	else if(!strcmp(s, "oem")) {
		cc->to_oem = 1;
	}
	else if(!strcmp(s, "utf8") || !strcmp(s, "unicode")) {
		cc->to_ascii = 0;
		cc->to_oem = 0;
	}
	else {
		de_puts(c, DE_MSGTYPE_MESSAGE, "Error: Unknown encoding\n");
		cc->error_flag = 1;
	}
}

enum opt_id_enum {
 DE_OPT_NULL=0, DE_OPT_D, DE_OPT_D2, DE_OPT_D3, DE_OPT_L,
 DE_OPT_NOINFO, DE_OPT_NOWARN,
 DE_OPT_NOBOM, DE_OPT_NODENS, DE_OPT_ASCIIHTML, DE_OPT_NONAMES, DE_OPT_MODTIME,
 DE_OPT_NOMODTIME,
 DE_OPT_Q, DE_OPT_VERSION, DE_OPT_HELP,
 DE_OPT_MAINONLY, DE_OPT_AUXONLY, DE_OPT_EXTRACTALL, DE_OPT_ZIP,
 DE_OPT_TOSTDOUT, DE_OPT_MSGSTOSTDERR, DE_OPT_FROMSTDIN, DE_OPT_COLOR,
 DE_OPT_ENCODING,
 DE_OPT_EXTOPT, DE_OPT_FILE, DE_OPT_FILE2, DE_OPT_INENC,
 DE_OPT_START, DE_OPT_SIZE, DE_OPT_M, DE_OPT_MODCODES, DE_OPT_O,
 DE_OPT_ARCFN, DE_OPT_GET, DE_OPT_FIRSTFILE, DE_OPT_MAXFILES, DE_OPT_MAXIMGDIM,
 DE_OPT_PRINTMODULES, DE_OPT_DPREFIX
};

struct opt_struct {
	const char *string;
	enum opt_id_enum id;
	int extra_args;
};

struct opt_struct option_array[] = {
	{ "d",            DE_OPT_D,            0 },
	{ "d2",           DE_OPT_D2,           0 },
	{ "d3",           DE_OPT_D3,           0 },
	{ "l",            DE_OPT_L,            0 },
	{ "noinfo",       DE_OPT_NOINFO,       0 },
	{ "nowarn",       DE_OPT_NOWARN,       0 },
	{ "nobom",        DE_OPT_NOBOM,        0 },
	{ "nodens",       DE_OPT_NODENS,       0 },
	{ "asciihtml",    DE_OPT_ASCIIHTML,    0 },
	{ "nonames",      DE_OPT_NONAMES,      0 },
	{ "modtime",      DE_OPT_MODTIME,      0 },
	{ "nomodtime",    DE_OPT_NOMODTIME,    0 },
	{ "q",            DE_OPT_Q,            0 },
	{ "version",      DE_OPT_VERSION,      0 },
	{ "h",            DE_OPT_HELP,         0 },
	{ "help",         DE_OPT_HELP,         0 },
	{ "?",            DE_OPT_HELP,         0 },
	{ "modules",      DE_OPT_PRINTMODULES, 0 },
	{ "main",         DE_OPT_MAINONLY,     0 },
	{ "aux",          DE_OPT_AUXONLY,      0 },
	{ "a",            DE_OPT_EXTRACTALL,   0 },
	{ "extractall",   DE_OPT_EXTRACTALL,   0 },
	{ "zip",          DE_OPT_ZIP,          0 },
	{ "tostdout",     DE_OPT_TOSTDOUT,     0 },
	{ "msgstostderr", DE_OPT_MSGSTOSTDERR, 0 },
	{ "fromstdin",    DE_OPT_FROMSTDIN,    0 },
	{ "color",        DE_OPT_COLOR,        0 },
	{ "enc",          DE_OPT_ENCODING,     1 },
	{ "opt",          DE_OPT_EXTOPT,       1 },
	{ "file",         DE_OPT_FILE,         1 },
	{ "file2",        DE_OPT_FILE2,        1 },
	{ "inenc",        DE_OPT_INENC,        1 },
	{ "start",        DE_OPT_START,        1 },
	{ "size",         DE_OPT_SIZE,         1 },
	{ "m",            DE_OPT_M,            1 },
	{ "modcodes",     DE_OPT_MODCODES,     1 },
	{ "o",            DE_OPT_O,            1 },
	{ "basefn",       DE_OPT_O,            1 }, // Deprecated
	{ "arcfn",        DE_OPT_ARCFN,        1 },
	{ "get",          DE_OPT_GET,          1 },
	{ "firstfile",    DE_OPT_FIRSTFILE,    1 },
	{ "maxfiles",     DE_OPT_MAXFILES,     1 },
	{ "maxdim",       DE_OPT_MAXIMGDIM,    1 },
	{ "dprefix",      DE_OPT_DPREFIX,      1 },
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

static void send_msgs_to_stderr(deark *c, struct cmdctx *cc)
{
	cc->msgs_to_stderr = 1;
	cc->have_initialized_output_stream = 0;
	cc->msgs_FILE = NULL;
#ifdef DE_WINDOWS
	cc->have_windows_console = 0;
#endif
}

static void parse_cmdline(deark *c, struct cmdctx *cc, int argc, char **argv)
{
	int i;
	int help_flag = 0;
	int module_flag = 0;
	const struct opt_struct *opt;

	for(i=1;i<argc;i++) {
		if(argv[i][0]=='-') {
			if(argv[i][1]=='-') // Allow a superfluous second '-'
				opt = opt_string_to_opt_struct(argv[i]+2);
			else
				opt = opt_string_to_opt_struct(argv[i]+1);

			if(!opt) {
				de_printf(c, DE_MSGTYPE_MESSAGE, "Unrecognized option: %s\n", argv[i]);
				if(!strcmp(argv[i], "-")) {
					// I don't want "-" to be an alias for "-fromstdin", because it
					// would have different syntax rules than it does in most programs.
					// (Question: Is "-" an *option*, or a kind of *filename*?)
					de_printf(c, DE_MSGTYPE_MESSAGE,
						"Note: To use stdin/stdout, use \"-fromstdin\"/\"-tostdout\".\n");
				}
				cc->error_flag = 1;
				cc->show_usage_message = 1;
				return;
			}
			if(i>=argc-opt->extra_args) {
				de_printf(c, DE_MSGTYPE_MESSAGE, "Option %s needs an argument\n", argv[i]);
				cc->error_flag = 1;
				cc->show_usage_message = 1;
				return;
			}

			switch(opt->id) {
			case DE_OPT_D:
				de_set_debug_level(c, 1);
				break;
			case DE_OPT_D2:
				de_set_debug_level(c, 2);
				break;
			case DE_OPT_D3:
				de_set_debug_level(c, 3);
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
			case DE_OPT_NODENS:
				de_set_write_density(c, 0);
				break;
			case DE_OPT_ASCIIHTML:
				de_set_ascii_html(c, 1);
				break;
			case DE_OPT_NONAMES:
				de_set_filenames_from_file(c, 0);
				break;
			case DE_OPT_MODTIME:
				de_set_preserve_file_times(c, 1);
				break;
			case DE_OPT_NOMODTIME:
				de_set_preserve_file_times(c, 0);
				break;
			case DE_OPT_Q:
				de_set_messages(c, 0);
				de_set_warnings(c, 0);
				break;
			case DE_OPT_VERSION:
				// TODO: Use ->special_command_code instead of calling show_version() here.
				show_version(c);
				cc->special_command_flag = 1;
				break;
			case DE_OPT_PRINTMODULES:
				cc->special_command_flag = 1;
				cc->special_command_code = CMD_PRINTMODULES;
				break;
			case DE_OPT_HELP:
				// TODO: Use ->special_command_code instead of help_flag.
				help_flag = 1;
				break;
			case DE_OPT_MAINONLY:
				de_set_extract_policy(c, DE_EXTRACTPOLICY_MAINONLY);
				break;
			case DE_OPT_AUXONLY:
				de_set_extract_policy(c, DE_EXTRACTPOLICY_AUXONLY);
				break;
			case DE_OPT_EXTRACTALL:
				de_set_extract_level(c, 2);
				break;
			case DE_OPT_ZIP:
				de_set_output_style(c, DE_OUTPUTSTYLE_ZIP);
				cc->to_zip = 1;
				break;
			case DE_OPT_TOSTDOUT:
				de_set_output_style(c, DE_OUTPUTSTYLE_STDOUT);
				send_msgs_to_stderr(c, cc);
				de_set_max_output_files(c, 1);
				cc->to_stdout = 1;
				break;
			case DE_OPT_MSGSTOSTDERR:
				send_msgs_to_stderr(c, cc);
				break;
			case DE_OPT_FROMSTDIN:
				de_set_input_style(c, DE_INPUTSTYLE_STDIN);
				cc->from_stdin = 1;
				break;
			case DE_OPT_COLOR:
				cc->use_color_req = 1;
				break;
			case DE_OPT_ENCODING:
				set_encoding_option(c, cc, argv[i+1]);
				if(cc->error_flag) return;
				break;
			case DE_OPT_EXTOPT:
				set_ext_option(c, cc, argv[i+1]);
				break;
			case DE_OPT_FILE:
				cc->input_filename = argv[i+1];
				de_set_input_filename(c, cc->input_filename);
				break;
			case DE_OPT_FILE2:
				de_set_ext_option(c, "file2", argv[i+1]);
				break;
			case DE_OPT_INENC:
				if(!de_set_input_encoding(c, argv[i+1], 0)) {
					de_printf(c, DE_MSGTYPE_MESSAGE,
						"Error: Unknown input encoding: %s\n", argv[i+1]);
					cc->error_flag = 1;
					return;
				}
				break;
			case DE_OPT_START:
				de_set_input_file_slice_start(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_SIZE:
				de_set_input_file_slice_size(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_M:
				module_flag = 1;
				de_set_input_format(c, argv[i+1]);
				break;
			case DE_OPT_MODCODES:
				de_set_module_init_codes(c, argv[i+1]);
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
			case DE_OPT_MAXIMGDIM:
				de_set_max_image_dimension(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_DPREFIX:
				de_set_dprefix(c, argv[i+1]);
				break;
			default:
				de_printf(c, DE_MSGTYPE_MESSAGE, "Unrecognized option: %s\n", argv[i]);
				cc->error_flag = 1;
				cc->show_usage_message = 1;
				return;
			}

			i += opt->extra_args;
		}
		else {
			if(cc->input_filename) {
				cc->error_flag = 1;
				cc->show_usage_message = 1;
				return;
			}
			cc->input_filename = argv[i];
			de_set_input_filename(c, cc->input_filename);
		}
	}

	if(help_flag) {
		if(module_flag) {
			de_set_want_modhelp(c, 1);
		}
		else {
			cc->special_command_flag = 1;
			show_help(c);
		}
		return;
	}

	if(!cc->input_filename && !cc->special_command_flag && !cc->from_stdin) {
		de_puts(c, DE_MSGTYPE_MESSAGE, "Error: Need an input filename\n");
		cc->error_flag = 1;
		cc->show_usage_message = 1;
		return;
	}

	if(cc->to_zip && cc->to_stdout) {
		de_puts(c, DE_MSGTYPE_MESSAGE, "Error: -tostdout and -zip are incompatible\n");
		cc->error_flag = 1;
		return;
	}
}

static void main2(int argc, char **argv)
{
	deark *c = NULL;
	struct cmdctx *cc = NULL;

	cc = de_malloc(NULL, sizeof(struct cmdctx));

	c = de_create();
	de_set_userdata(c, (void*)cc);
	de_set_fatalerror_callback(c, our_fatalerrorfn);
	de_set_messages_callback(c, our_msgfn);
	de_set_special_messages_callback(c, our_specialmsgfn);

	if(argc<2) { // Empty command line
		show_help(c);
		goto done;
	}

	parse_cmdline(c, cc, argc, argv);

	if(cc->error_flag) {
		if(cc->show_usage_message) {
			show_usage_error(c);
		}
		goto done;
	}

	if(cc->special_command_flag) {
		switch(cc->special_command_code) {
		case CMD_PRINTMODULES:
			print_modules(c);
			break;
		}
		goto done;
	}

#ifdef DE_WINDOWS
	if(cc->to_stdout) {
		_setmode(_fileno(stdout), _O_BINARY);
	}
	if(cc->from_stdin) {
		_setmode(_fileno(stdin), _O_BINARY);
	}
#endif

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
