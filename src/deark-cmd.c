// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Command-line interface

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-user.h"
#include "deark-version.h"

#ifdef DE_WINDOWS
#include <fcntl.h>
#include <io.h> // for _setmode
#endif

enum color_method_enum {
	CM_NOCOLOR=0,
	CM_AUTOCOLOR,
	CM_ANSI,
	CM_ANSI24,
	CM_WINCONSOLE
};

enum special_command_code_enum {
	CMD_NONE = 0, CMD_PRINTHELP, CMD_PRINTVERSION, CMD_PRINTLICENSE,
	CMD_PRINTMODULES
};

struct cmdctx {
	deark *c;
	struct de_platform_data *plctx;
	const char *input_filename;
	int error_flag;
	int show_usage_message;
	int special_command_flag;
	enum special_command_code_enum special_command_code;
	int msgs_to_stderr;

	// Have we set msgs_FILE and have_windows_console, and called _setmode if needed?
	int have_initialized_output_stream;

	FILE *msgs_FILE; // Where to print (error, etc.) messages
#ifdef DE_WINDOWS
	int have_windows_console; // Is msgs_FILE a console?
	int use_fwputs;
#endif

	const char *output_dirname;
	const char *base_output_filename;
	const char *archive_filename;
	int option_k_level; // Use input filename in output filenames
	int option_ka_level; // Use input filename in output archive filenames
	u8 set_MAXFILES;

	int to_stdout;
	int to_zip;
	int to_tar;
	int from_stdin;
	int to_ascii;
	int to_oem;
	int no_chcp;
	enum color_method_enum color_method_req;
	enum color_method_enum color_method;
	char msgbuf[1000];
};

// Low-level print function
static void emit_sz(struct cmdctx *cc, const char *sz)
{
#ifdef DE_WINDOWS
	if(cc->use_fwputs) {
		de_utf8_to_utf16_to_FILE(cc->c, sz, cc->msgs_FILE);
		return;
	}
#endif
	fputs(sz, cc->msgs_FILE);
}

static void print_version(deark *c, int verbose)
{
	char vbuf[80];

	de_printf(c, DE_MSGTYPE_MESSAGE, "Deark version: %s\n",
		de_get_version_string(vbuf, sizeof(vbuf)));
	if(!verbose) return;
	de_printf(c, DE_MSGTYPE_MESSAGE, "platform API: %s\n",
#ifdef DE_WINDOWS
		"Windows"
#else
		"Unix-like"
#endif
		);
	de_printf(c, DE_MSGTYPE_MESSAGE, "platform bits: %u\n",
		(unsigned int)(8*sizeof(void*)));
#ifdef _DEBUG
	de_printf(c, DE_MSGTYPE_MESSAGE, "build type: debug\n");
#endif
}

static void print_usage_oneline(deark *c) {
	de_puts(c, DE_MSGTYPE_MESSAGE, "Usage: deark [options] <input-file> [options]\n");
}

static void print_usage_error(deark *c)
{
	print_usage_oneline(c);
	de_puts(c, DE_MSGTYPE_MESSAGE, "\"deark -h\" for help.\n");
}

static void print_help(deark *c)
{
	print_version(c, 0);
	de_puts(c, DE_MSGTYPE_MESSAGE,
		"A utility for extracting data from various file formats\n\n");
	print_usage_oneline(c);
	de_puts(c, DE_MSGTYPE_MESSAGE,
		"\nCommonly used options:\n"
		" -l: Instead of extracting, list the files that would be extracted.\n"
		" -m <module>: Assume input file is this format, instead of autodetecting.\n"
		" -k: Start output filenames with the input filename.\n"
		" -o <base-filename>: Start output filenames with this string.\n"
		" -od <directory>: Write files to this directory.\n"
		" -zip: Write output files to a .zip file.\n"
		" -ka: Start the .zip filename with the input filename.\n"
		" -a: Extract more data than usual.\n"
		" -main: Extract less data than usual.\n"
		" -get <n>: Extract only file number <n>.\n"
		" -d, -d2, -d3: Print additional information about the file.\n"
		" -q, -noinfo, -nowarn: Print fewer messages than usual.\n"
		" -modules: Print the names of all available modules.\n"
		" -help, -h: Print this message.\n"
		" -license: Print the credits and terms of use.\n"
		" -version: Print version information.\n"
		);
}

static void print_license(deark *c)
{
	de_puts(c, DE_MSGTYPE_MESSAGE, "Deark\n"
	"Copyright (C) 2016-"DE_COPYRIGHT_YEAR_STRING" Jason Summers\n\n"
	"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
	"of this software and associated documentation files (the \"Software\"), to deal\n"
	"in the Software without restriction, including without limitation the rights\n"
	"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
	"copies of the Software, and to permit persons to whom the Software is\n"
	"furnished to do so, subject to the following conditions:\n\n"
	"The above copyright notice and this permission notice shall be included in\n"
	"all copies or substantial portions of the Software.\n\n"
	"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
	"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
	"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
	"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
	"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
	"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n"
	"THE SOFTWARE.\n\n"
	"----------\n"
	"The zlib and Deflate encoder and decoder use public domain code originally from\n"
	"miniz v1.16 beta r1, by Rich Geldreich.\n\n"
	"The ZIP Implode decoder is derived from public domain code by Mark Adler, from\n"
	"Info-ZIP UnZip v5.4.\n\n"
	"The X-Face decoder uses code from Compface, Copyright (c) 1990 James Ashton.\n\n"
	"The Stuffit Huffman decoder uses code by Allan G. Weber, from Unsit Version 1.\n\n"
	"The ZOO LZH decoder uses public domain code by Martin Schoenert et al., from\n"
	"unzoo.c v4.4.\n");
}

static void print_modules(deark *c)
{
	de_print_module_list(c);
}

static void initialize_output_stream(struct cmdctx *cc)
{
#ifdef DE_WINDOWS
	int ansi_is_enabled = 0;
#endif

	if(cc->msgs_to_stderr) {
		cc->msgs_FILE = stderr;
	}
	else {
		cc->msgs_FILE = stdout;
	}

	cc->color_method = CM_NOCOLOR; // start with default

#ifdef DE_WINDOWS
	de_winconsole_init_handle(cc->plctx, cc->msgs_to_stderr ? 2 : 1);
	cc->have_windows_console = de_winconsole_is_console(cc->plctx);

	// If appropriate, call _setmode so that Unicode output to the console
	// works correctly (provided we use Unicode functions like fputws()).
	if(cc->have_windows_console && !cc->to_ascii && !cc->to_oem) {
		cc->use_fwputs = 1;
		(void)_setmode(_fileno(cc->msgs_FILE), _O_U16TEXT);
	}

	if(!cc->have_windows_console && !cc->to_ascii && !cc->to_oem && !cc->no_chcp) {
		// There are some situations in which it helps to declare the code page
		// that our output uses.
		de_winconsole_set_UTF8_CP(cc->plctx);
	}

	switch(cc->color_method_req) {
	case CM_AUTOCOLOR:
		if(cc->have_windows_console) {
			if(de_winconsole_try_enable_ansi24(cc->plctx)) {
				cc->color_method = CM_ANSI24;
				ansi_is_enabled = 1;
			}
			else {
				cc->color_method = CM_WINCONSOLE;
			}
		}
		else {
			cc->color_method = CM_ANSI24;
		}
		break;
	case CM_WINCONSOLE:
		if(cc->have_windows_console) {
			cc->color_method = CM_WINCONSOLE;
		}
		break;
	case CM_ANSI:
		cc->color_method = CM_ANSI;
		break;
	case CM_ANSI24:
		cc->color_method = CM_ANSI24;
		break;
	default:
		; // leave at CM_NOCOLOR
	}

	if(cc->color_method==CM_WINCONSOLE) {
		de_winconsole_record_current_attributes(cc->plctx);
	}

	if((cc->color_method==CM_ANSI || cc->color_method==CM_ANSI24) && !ansi_is_enabled) {
		de_winconsole_enable_ansi(cc->plctx);
	}

#else
	switch(cc->color_method_req) {
	case CM_NOCOLOR:
	case CM_WINCONSOLE:
		cc->color_method = CM_NOCOLOR;
		break;
	case CM_ANSI:
		cc->color_method = CM_ANSI;
		break;
	default:
		cc->color_method = CM_ANSI24;
	}
#endif

	if(cc->color_method==CM_ANSI || cc->color_method==CM_ANSI24) {
		// If using ANSI codes, start by resetting all attributes
		emit_sz(cc, "\x1b[0m");
	}

	cc->have_initialized_output_stream = 1;
}

static void our_specialmsgfn(deark *c, unsigned int flags, unsigned int code,
	u32 param1)
{
	struct cmdctx *cc;

	cc = de_get_userdata(c);
	if(cc->color_method==CM_NOCOLOR) return;

	if(!cc->have_initialized_output_stream) {
		initialize_output_stream(cc);
	}

#ifdef DE_WINDOWS
	if(cc->color_method==CM_WINCONSOLE) {
		if(code==DE_MSGCODE_HL) {
			de_winconsole_highlight(cc->plctx, 1);
		}
		else if(code==DE_MSGCODE_UNHL) {
			de_winconsole_highlight(cc->plctx, 0);
		}
		else if(code==DE_MSGCODE_RGBSAMPLE) {
			// There's no way to get 24-bit color using Windows console
			// commands. Have to use ANSI24 instead.
			;
		}
		return;
	}
#endif

	// TODO: Maybe move the DE_COLOR_* macros to deark.h.
#define X_DE_COLOR_R(x)  (unsigned int)(((x)>>16)&0xff)
#define X_DE_COLOR_G(x)  (unsigned int)(((x)>>8)&0xff)
#define X_DE_COLOR_B(x)  (unsigned int)((x)&0xff)
	if(code==DE_MSGCODE_HL) {
		emit_sz(cc, "\x1b[7m");
	}
	else if(code==DE_MSGCODE_UNHL) {
		emit_sz(cc, "\x1b[27m");
	}
	else if(code==DE_MSGCODE_RGBSAMPLE && cc->color_method==CM_ANSI24) {
		char buf[64];

		de_snprintf(buf, sizeof(buf), "\x1b[48;2;%u;%u;%um  \x1b[0m",
			X_DE_COLOR_R(param1), X_DE_COLOR_G(param1), X_DE_COLOR_B(param1));
		emit_sz(cc, buf);
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

	emit_sz(cc, s);
}

static void our_fatalerrorfn(deark *c)
{
	de_puts(c, DE_MSGTYPE_MESSAGE, "Exiting\n");
	de_exitprocess(1);
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
 DE_OPT_NOBOM, DE_OPT_NODENS, DE_OPT_ASCIIHTML, DE_OPT_NONAMES,
 DE_OPT_NOOVERWRITE, DE_OPT_MODTIME, DE_OPT_NOMODTIME,
 DE_OPT_Q, DE_OPT_VERSION, DE_OPT_HELP, DE_OPT_LICENSE, DE_OPT_ID,
 DE_OPT_MAINONLY, DE_OPT_AUXONLY, DE_OPT_EXTRACTALL, DE_OPT_ZIP, DE_OPT_TAR,
 DE_OPT_TOSTDOUT, DE_OPT_MSGSTOSTDERR, DE_OPT_FROMSTDIN, DE_OPT_COLOR,
 DE_OPT_NOCHCP, DE_OPT_ENCODING,
 DE_OPT_EXTOPT, DE_OPT_FILE, DE_OPT_FILE2, DE_OPT_INENC, DE_OPT_INTZ,
 DE_OPT_START, DE_OPT_SIZE, DE_OPT_M, DE_OPT_MODCODES, DE_OPT_O, DE_OPT_OD,
 DE_OPT_K, DE_OPT_K2, DE_OPT_K3, DE_OPT_KA, DE_OPT_KA2, DE_OPT_KA3,
 DE_OPT_ARCFN, DE_OPT_GET, DE_OPT_FIRSTFILE, DE_OPT_MAXFILES,
 DE_OPT_MAXFILESIZE, DE_OPT_MAXTOTALSIZE, DE_OPT_MAXIMGDIM,
 DE_OPT_PRINTMODULES, DE_OPT_DPREFIX, DE_OPT_EXTRLIST,
 DE_OPT_ONLYMODS, DE_OPT_DISABLEMODS, DE_OPT_ONLYDETECT, DE_OPT_NODETECT,
 DE_OPT_COLORMODE
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
	{ "n",            DE_OPT_NOOVERWRITE,  0 },
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
	{ "tar",          DE_OPT_TAR,          0 },
	{ "tostdout",     DE_OPT_TOSTDOUT,     0 },
	{ "msgstostderr", DE_OPT_MSGSTOSTDERR, 0 },
	{ "fromstdin",    DE_OPT_FROMSTDIN,    0 },
	{ "color",        DE_OPT_COLOR,        0 },
	{ "k",            DE_OPT_K,            0 },
	{ "k2",           DE_OPT_K2,           0 },
	{ "k3",           DE_OPT_K3,           0 },
	{ "ka",           DE_OPT_KA,           0 },
	{ "ka2",          DE_OPT_KA2,          0 },
	{ "ka3",          DE_OPT_KA3,          0 },
	{ "license",      DE_OPT_LICENSE,      0 },
	{ "id",           DE_OPT_ID,           0 },
	{ "nochcp",       DE_OPT_NOCHCP,       0 },
	{ "enc",          DE_OPT_ENCODING,     1 },
	{ "opt",          DE_OPT_EXTOPT,       1 },
	{ "file",         DE_OPT_FILE,         1 },
	{ "file2",        DE_OPT_FILE2,        1 },
	{ "inenc",        DE_OPT_INENC,        1 },
	{ "intz",         DE_OPT_INTZ,         1 },
	{ "start",        DE_OPT_START,        1 },
	{ "size",         DE_OPT_SIZE,         1 },
	{ "m",            DE_OPT_M,            1 },
	{ "modcodes",     DE_OPT_MODCODES,     1 },
	{ "o",            DE_OPT_O,            1 },
	{ "basefn",       DE_OPT_O,            1 }, // Deprecated
	{ "od",           DE_OPT_OD,           1 },
	{ "arcfn",        DE_OPT_ARCFN,        1 },
	{ "get",          DE_OPT_GET,          1 },
	{ "firstfile",    DE_OPT_FIRSTFILE,    1 },
	{ "maxfiles",     DE_OPT_MAXFILES,     1 },
	{ "maxfilesize",  DE_OPT_MAXFILESIZE,  1 },
	{ "maxtotalsize", DE_OPT_MAXTOTALSIZE, 1 },
	{ "maxdim",       DE_OPT_MAXIMGDIM,    1 },
	{ "dprefix",      DE_OPT_DPREFIX,      1 },
	{ "extrlist",     DE_OPT_EXTRLIST,     1 },
	{ "onlymods",     DE_OPT_ONLYMODS,     1 },
	{ "disablemods",  DE_OPT_DISABLEMODS,  1 },
	{ "onlydetect",   DE_OPT_ONLYDETECT,   1 },
	{ "nodetect",     DE_OPT_NODETECT,     1 },
	{ "colormode",    DE_OPT_COLORMODE,    1 },
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

static void colormode_opt(struct cmdctx *cc, const char *modestr)
{
	if(!strcmp(modestr, "auto")) {
		cc->color_method_req = CM_AUTOCOLOR;
	}
	else if(!strcmp(modestr, "ansi")) {
		cc->color_method_req = CM_ANSI;
	}
	else if(!strcmp(modestr, "ansi24")) {
		cc->color_method_req = CM_ANSI24;
	}
	else if(!strcmp(modestr, "winconsole")) {
		cc->color_method_req = CM_WINCONSOLE;
	}
	else  if(!strcmp(modestr, "none")) {
		cc->color_method_req = CM_NOCOLOR;
	}
	else {
		de_printf(cc->c, DE_MSGTYPE_MESSAGE, "Invalid colormode: %s\n", modestr);
		cc->error_flag = 1;
		return;
	}
}

static void set_output_basename(struct cmdctx *cc)
{
	const char *outputbasefn = cc->base_output_filename; // default, could be NULL
	const char *outdirname;
	unsigned int flags = 0;

	if(cc->option_k_level && cc->input_filename) {
		if(cc->option_k_level==1) {
			// Use base input filename in output filenames.
			outputbasefn = cc->input_filename;
			flags |= 0x1;
		}
		else if(cc->option_k_level==2) {
			// Use full input filename path, but not as an actual path.
			outputbasefn = cc->input_filename;
			flags |= 0x2;
		}
		else if(cc->option_k_level==3) {
			// Use full input filename path, as-is.
			outputbasefn = cc->input_filename;
		}
	}

	if(cc->to_zip || cc->to_tar) {
		// In this case, -od refers to the archive filename, not to the base
		// filename that we're dealing with here.
		outdirname = NULL;
	}
	else if(cc->to_stdout) {
		// -od is incompatible with -tostdout
		outdirname = NULL;
	}
	else {
		outdirname = cc->output_dirname;
	}

	de_set_base_output_filename(cc->c, outdirname, outputbasefn, flags);
}

static void set_output_archive_name(struct cmdctx *cc)
{
	const char *arcfn = cc->archive_filename; // default, could be NULL
	unsigned int flags = 0;

	if(!cc->to_zip && !cc->to_tar) return;
	if(cc->to_stdout) return;

	if(cc->option_ka_level && cc->input_filename)
	{
		if(cc->option_ka_level==1) {
			// Use base input filename in output filenames.
			arcfn = cc->input_filename;
			flags |= 0x21;
		}
		else if(cc->option_ka_level==2) {
			// Use full input filename path, but not as an actual path.
			arcfn = cc->input_filename;
			flags |= 0x22;
		}
		else if(cc->option_ka_level==3) {
			// Use full input filename path, as-is.
			arcfn = cc->input_filename;
			flags |= 0x20;
		}
	}

	if(!arcfn) {
		arcfn = "output";
		flags |= 0x20;
	}

	de_set_output_archive_filename(cc->c, cc->output_dirname, arcfn, flags);
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
				de_set_infomessages(c, 0);
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
			case DE_OPT_NOOVERWRITE:
				de_set_overwrite_mode(c, DE_OVERWRITEMODE_NEVER);
				break;
			case DE_OPT_MODTIME:
				de_set_preserve_file_times(c, 0, 1);
				de_set_preserve_file_times(c, 1, 1);
				break;
			case DE_OPT_NOMODTIME:
				de_set_preserve_file_times(c, 0, 0);
				de_set_preserve_file_times(c, 1, 0);
				break;
			case DE_OPT_Q:
				de_set_infomessages(c, 0);
				de_set_warnings(c, 0);
				break;
			case DE_OPT_VERSION:
				cc->special_command_flag = 1;
				cc->special_command_code = CMD_PRINTVERSION;
				break;
			case DE_OPT_PRINTMODULES:
				cc->special_command_flag = 1;
				cc->special_command_code = CMD_PRINTMODULES;
				break;
			case DE_OPT_HELP:
				// At this point, we don't know whether this will be general help,
				// or module-specific help. So just set a flag for later.
				help_flag = 1;
				break;
			case DE_OPT_LICENSE:
				cc->special_command_flag = 1;
				cc->special_command_code = CMD_PRINTLICENSE;
				break;
			case DE_OPT_ID:
				de_set_id_mode(c, 1);
				break;
			case DE_OPT_NOCHCP:
				cc->no_chcp = 1;
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
				de_set_output_style(c, DE_OUTPUTSTYLE_ARCHIVE, DE_ARCHIVEFMT_ZIP);
				cc->to_zip = 1;
				break;
			case DE_OPT_TAR:
				de_set_output_style(c, DE_OUTPUTSTYLE_ARCHIVE, DE_ARCHIVEFMT_TAR);
				cc->to_tar = 1;
				break;
			case DE_OPT_TOSTDOUT:
				send_msgs_to_stderr(c, cc);
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
				colormode_opt(cc, "auto");
				break;
			case DE_OPT_K:
				cc->option_k_level = 1;
				break;
			case DE_OPT_K2:
				cc->option_k_level = 2;
				break;
			case DE_OPT_K3:
				cc->option_k_level = 3;
				break;
			case DE_OPT_KA:
				cc->option_ka_level = 1;
				break;
			case DE_OPT_KA2:
				cc->option_ka_level = 2;
				break;
			case DE_OPT_KA3:
				cc->option_ka_level = 3;
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
			case DE_OPT_INTZ:
				de_set_input_timezone(c, (i64)(3600.0*atof(argv[i+1])));
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
				cc->base_output_filename = argv[i+1];
				break;
			case DE_OPT_OD:
				cc->output_dirname = argv[i+1];
				break;
			case DE_OPT_ARCFN:
				// Relevant e.g. if the -zip option is used.
				cc->archive_filename = argv[i+1];
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
				cc->set_MAXFILES = 1;
				break;
			case DE_OPT_MAXFILESIZE:
				de_set_max_output_file_size(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_MAXTOTALSIZE:
				de_set_max_total_output_size(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_MAXIMGDIM:
				de_set_max_image_dimension(c, de_atoi64(argv[i+1]));
				break;
			case DE_OPT_DPREFIX:
				de_set_dprefix(c, argv[i+1]);
				break;
			case DE_OPT_EXTRLIST:
				de_set_extrlist_filename(c, argv[i+1]);
				break;
			case DE_OPT_ONLYMODS:
				de_set_disable_mods(c, argv[i+1], 1);
				break;
			case DE_OPT_DISABLEMODS:
				de_set_disable_mods(c, argv[i+1], 0);
				break;
			case DE_OPT_ONLYDETECT:
				de_set_disable_moddetect(c, argv[i+1], 1);
				break;
			case DE_OPT_NODETECT:
				de_set_disable_moddetect(c, argv[i+1], 0);
				break;
			case DE_OPT_COLORMODE:
				colormode_opt(cc, argv[i+1]);
				if(cc->error_flag) return;
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
		if(module_flag || cc->input_filename || cc->from_stdin) {
			de_set_want_modhelp(c, 1);
		}
		else {
			cc->special_command_flag = 1;
			cc->special_command_code = CMD_PRINTHELP;
		}
		return;
	}

	if(!cc->input_filename && !cc->special_command_flag && !cc->from_stdin) {
		de_puts(c, DE_MSGTYPE_MESSAGE, "Error: Need an input filename\n");
		cc->error_flag = 1;
		cc->show_usage_message = 1;
		return;
	}

	if(cc->to_stdout) {
		if(cc->to_zip || cc->to_tar) {
			de_set_output_archive_filename(c, NULL, NULL, 0x10);
		}
		else {
			de_set_output_style(c, DE_OUTPUTSTYLE_STDOUT, 0);
			if(!cc->set_MAXFILES) {
				de_set_max_output_files(c, 1);
			}
		}
	}

	set_output_basename(cc);
	set_output_archive_name(cc);
}

static int main2(int argc, char **argv)
{
	deark *c = NULL;
	struct cmdctx *cc = NULL;
	int ret;
	int exit_status = 0;

	cc = de_malloc(NULL, sizeof(struct cmdctx));
	c = de_create();
	cc->c = c;

	de_set_userdata(c, (void*)cc);
	de_set_fatalerror_callback(c, our_fatalerrorfn);
	de_set_messages_callback(c, our_msgfn);
	de_set_special_messages_callback(c, our_specialmsgfn);
	cc->plctx = de_platformdata_create();

	if(argc<2) { // Empty command line
		print_help(c);
		goto done;
	}

	parse_cmdline(c, cc, argc, argv);

	if(cc->error_flag) {
		if(cc->show_usage_message) {
			print_usage_error(c);
		}
		goto done;
	}

	if(cc->special_command_flag) {
		switch(cc->special_command_code) {
		case CMD_PRINTHELP:
			print_help(c);
			break;
		case CMD_PRINTVERSION:
			print_version(c, 1);
			break;
		case CMD_PRINTLICENSE:
			print_license(c);
			break;
		case CMD_PRINTMODULES:
			print_modules(c);
			break;
		default:
			break;
		}
		goto done;
	}

#ifdef DE_WINDOWS
	if(cc->to_stdout) {
		(void)_setmode(_fileno(stdout), _O_BINARY);
	}
	if(cc->from_stdin) {
		(void)_setmode(_fileno(stdin), _O_BINARY);
	}
#endif

	ret = de_run(c);
	if(!ret) {
		exit_status = 1;
	}

done:
	de_destroy(c);
	de_platformdata_destroy(cc->plctx);
	cc->plctx = NULL;
	if(cc->error_flag) exit_status = 1;
	de_free(NULL, cc);
	return exit_status;
}

#ifdef DE_WINDOWS

// This prototype is to silence a possible -Wmissing-prototypes warning.
int wmain(int argc, wchar_t **argvW);

int wmain(int argc, wchar_t **argvW)
{
	char **argv;
	int exit_status;

	argv = de_convert_args_to_utf8(argc, argvW);
	exit_status = main2(argc, argv);
	de_free_utf8_args(argc, argv);
	return exit_status;
}

#else

int main(int argc, char **argv)
{
	return main2(argc, argv);
}

#endif
