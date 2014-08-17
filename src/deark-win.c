// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark-config.h"

#ifndef DE_WINDOWS
#error "This file is only for Windows builds"
#endif

#include <windows.h>

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "deark.h"

static char *de_utf16_to_utf8_strdup(deark *c, const WCHAR *src)
{
	char *dst;
	int dstlen;
	int ret;

	// Calculate the size required by the target string.
	ret = WideCharToMultiByte(CP_UTF8,0,src,-1,NULL,0,NULL,NULL);
	if(ret<1) return NULL;

	dstlen = ret;
	dst = (char*)de_malloc(c, dstlen*sizeof(char));
	if(!dst) return NULL;

	ret = WideCharToMultiByte(CP_UTF8,0,src,-1,dst,dstlen,NULL,NULL);
	if(ret<1) {
		de_free(c, dst);
		return NULL;
	}
	return dst;
}

wchar_t *de_utf8_to_utf16_strdup(deark *c, const char *src)
{
	WCHAR *dst;
	int dstlen;
	int ret;

	// Calculate the size required by the target string.
	ret = MultiByteToWideChar(CP_UTF8,0,src,-1,NULL,0);
	if(ret<1) return NULL;

	dstlen = ret;
	dst = (WCHAR*)de_malloc(c, dstlen*sizeof(WCHAR));
	if(!dst) return NULL;

	ret = MultiByteToWideChar(CP_UTF8,0,src,-1,dst,dstlen);
	if(ret<1) {
		de_free(c, dst);
		return NULL;
	}
	return dst;
}

FILE* de_fopen(deark *c, const char *fn, const char *mode,
	char *errmsg, size_t errmsg_len)
{
	FILE *f = NULL;
	errno_t errcode;
	WCHAR *fnW;
	WCHAR *modeW;

	fnW = de_utf8_to_utf16_strdup(c, fn);
	modeW = de_utf8_to_utf16_strdup(c, mode);

	errcode = _wfopen_s(&f,fnW,modeW);

	de_free(c, fnW);
	de_free(c, modeW);

	errmsg[0] = '\0';

	if(errcode!=0) {
		strerror_s(errmsg, (size_t)errmsg_len, (int)errcode);
		f=NULL;
	}
	return f;
}

int de_get_file_size(FILE *fp, de_int64 *pfsize)
{
	struct _stat stbuf;

	if(_fstat(_fileno(fp),&stbuf)==0) {
		*pfsize = stbuf.st_size;
		return 1;
	}
	*pfsize = 0;
	return 0;
}

char **de_convert_args_to_utf8(int argc, wchar_t **argvW)
{
	int i;
	char **argvUTF8;

	argvUTF8 = (char**)de_malloc(NULL, argc*sizeof(char*));

	// Convert parameters to UTF-8
	for(i=0;i<argc;i++) {
		argvUTF8[i] = de_utf16_to_utf8_strdup(NULL, argvW[i]);
	}

	return argvUTF8;
}

void de_free_utf8_args(int argc, char **argv)
{
	int i;

	for(i=0;i<argc;i++) {
		de_free(NULL, argv[i]);
	}
	de_free(NULL, argv);
}

// A helper function that returns nonzero if stdout seems to be a Windows console.
// 0 means that stdout is redirected.
int de_stdout_is_windows_console(void)
{
	DWORD consolemode=0;
	BOOL n;

	n=GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &consolemode);
	return n ? 1 : 0;
}
