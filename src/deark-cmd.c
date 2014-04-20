// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "deark.h"

struct cmdctx {
	const char *input_filename;
	int error_flag;
	int usage_error_flag;
};

static void usage(void)
{
	fprintf(stderr, "usage: deark [options] <input-file>\n");
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
	char vbuf[80];

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
			else if(!strcmp(argv[i]+1, "version")) {
				printf("Deark version %s\n", de_get_version_string(vbuf, sizeof(vbuf)));
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
			else {
				fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
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

	c = de_create();

	parse_cmdline(c, cc, argc, argv);

	if(cc->usage_error_flag) {
		usage();
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
