// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-util.c: Most of the main library functions

#include "deark-config.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "deark-private.h"

char *de_get_version_string(char *buf, size_t bufsize)
{
	if((DE_VERSION_NUMBER&0xff) == 0) {
		de_snprintf(buf, bufsize, "%u.%u.%u",
			(DE_VERSION_NUMBER&0xff000000)>>24,
			(DE_VERSION_NUMBER&0x00ff0000)>>16,
			(DE_VERSION_NUMBER&0x0000ff00)>>8);
	}
	else {
		de_snprintf(buf, bufsize, "%u.%u.%u-%u",
			(DE_VERSION_NUMBER&0xff000000)>>24,
			(DE_VERSION_NUMBER&0x00ff0000)>>16,
			(DE_VERSION_NUMBER&0x0000ff00)>>8,
			DE_VERSION_NUMBER&0x000000ff);
	}
	return buf;
}

unsigned int de_get_version_int(void)
{
	return DE_VERSION_NUMBER;
}

void de_strlcpy(char *dst, const char *src, size_t dstlen)
{
	size_t n;
	n = strlen(src);
	if(n>dstlen-1) n=dstlen-1;
	memcpy(dst, src, n);
	dst[n]='\0';
}

// A wrapper for strchr().
char *de_strchr(const char *s, int c)
{
	if(!s) return NULL;
	return strchr(s, c);
}

void de_snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	de_vsnprintf(buf,buflen,fmt,ap);
	va_end(ap);
}

void de_puts(deark *c, int msgtype, const char *s)
{
	if(!c || !c->msgfn) {
		fputs(s, stderr);
		return;
	}
	c->msgfn(c, msgtype, s);
}

static void de_vprintf(deark *c, int msgtype, const char *fmt, va_list ap)
{
	char buf[1024];

	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	de_puts(c, msgtype, buf);
}

void de_printf(deark *c, int msgtype, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	de_vprintf(c, msgtype, fmt, ap);
	va_end(ap);
}

static void de_vdbg_internal(deark *c, const char *fmt, va_list ap)
{
	char spaces[51];
	int nspaces;

	if(c) {
		nspaces = c->dbg_indent_amount;
	}
	else {
		nspaces = 0;
	}

	if(nspaces<0) nspaces=0;
	if(nspaces>50) nspaces=50;

	if(nspaces>0)
		de_memset(spaces, ' ', nspaces);
	spaces[nspaces] = '\0';

	de_printf(c, DE_MSGTYPE_DEBUG, "DEBUG: %s", spaces);
	de_vprintf(c, DE_MSGTYPE_DEBUG, fmt, ap);
}

void de_dbg(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c && c->debug_level<1) return;
	va_start(ap, fmt);
	de_vdbg_internal(c, fmt, ap);
	va_end(ap);
}

void de_dbg2(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c && c->debug_level<2) return;
	va_start(ap, fmt);
	de_vdbg_internal(c, fmt, ap);
	va_end(ap);
}

void de_dbg3(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c && c->debug_level<3) return;
	va_start(ap, fmt);
	de_vdbg_internal(c, fmt, ap);
	va_end(ap);
}

void de_dbg_indent(deark *c, int n)
{
	c->dbg_indent_amount += n;
}

// Print debugging output for an 8-bit RGB palette entry.
void de_dbg_pal_entry(deark *c, de_int64 idx, de_uint32 clr)
{
	int r,g,b,a;

	if(c->debug_level<2) return;
	r = (int)DE_COLOR_R(clr);
	g = (int)DE_COLOR_G(clr);
	b = (int)DE_COLOR_B(clr);
	a = (int)DE_COLOR_A(clr);
	if(a!=0xff) {
		de_dbg2(c, "pal[%3d] = (%3d,%3d,%3d,A=%d)\n", (int)idx, r, g, b, a);
		return;
	}
	de_dbg2(c, "pal[%3d] = (%3d,%3d,%3d)\n", (int)idx, r, g, b);
}

// c can be NULL
void de_err(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c) {
		c->error_count++;
	}

	de_puts(c, DE_MSGTYPE_ERROR, "Error: ");
	va_start(ap, fmt);
	de_vprintf(c, DE_MSGTYPE_ERROR, fmt, ap);
	va_end(ap);
}

void de_warn(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_warnings) return;
	de_puts(c, DE_MSGTYPE_WARNING, "Warning: ");
	va_start(ap, fmt);
	de_vprintf(c, DE_MSGTYPE_WARNING, fmt, ap);
	va_end(ap);
}

void de_msg(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_messages) return;
	va_start(ap, fmt);
	de_vprintf(c, DE_MSGTYPE_MESSAGE, fmt, ap);
	va_end(ap);
}

// c can be NULL.
void de_fatalerror(deark *c)
{
	if(c && c->fatalerrorfn) {
		c->fatalerrorfn(c);
	}
	exit(1);
}

// Memory returned is always zeroed.
// c can be NULL.
// Always succeeds; never returns NULL.
void *de_malloc(deark *c, de_int64 n)
{
	void *m;
	if(n==0) n=1;
	if(n<0 || n>500000000) {
		de_err(c, "Out of memory (%d bytes requested)\n",(int)n);
		de_fatalerror(c);
	}

	m = calloc((size_t)n,1);
	if(!m) {
		de_err(c, "Memory allocation failed (%d bytes)\n",(int)n);
		de_fatalerror(c);
	}
	return m;
}

// If you know oldsize, you can provide it, and newly-allocated bytes will be zeroed.
// Otherwise, set oldsize==newsize, and newly-allocated bytes won't be zeroed.
// If oldmem is NULL, this behaves the same as de_malloc, and all bytes are zeroed.
void *de_realloc(deark *c, void *oldmem, de_int64 oldsize, de_int64 newsize)
{
	void *newmem;

	if(!oldmem) {
		return de_malloc(c, newsize);
	}

	newmem = realloc(oldmem, (size_t)newsize);
	if(!newmem) {
		de_err(c, "Memory reallocation failed (%d bytes)\n",(int)newsize);
		free(oldmem);
		de_fatalerror(c);
		return NULL;
	}

	if(oldsize<newsize) {
		// zero out any newly-allocated bytes
		de_memset(&((de_byte*)newmem)[oldsize], 0, (size_t)(newsize-oldsize));
	}

	return newmem;
}

void de_free(deark *c, void *m)
{
	free(m);
}

deark *de_create(void)
{
	deark *c;
	c = de_malloc(NULL,sizeof(deark));
	c->show_messages = 1;
	c->show_warnings = 1;
	c->write_bom = 1;
	c->write_density = 1;
	c->filenames_from_file = 1;
	c->preserve_file_times = 1;
	c->max_output_files = -1;
	c->max_image_dimension = DE_DEFAULT_MAX_IMAGE_DIMENSION;
	return c;
}

void de_destroy(deark *c)
{
	de_int64 i;

	if(!c) return;
	for(i=0; i<c->num_ext_options; i++) {
		de_free(c, c->ext_option[i].name);
		de_free(c, c->ext_option[i].val);
	}
	if(c->zip_file) { de_zip_close_file(c); }
	if(c->base_output_filename) { de_free(c, c->base_output_filename); }
	if(c->output_archive_filename) { de_free(c, c->output_archive_filename); }
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

void de_set_fatalerror_callback(deark *c, de_fatalerrorfn_type fn)
{
	c->fatalerrorfn = fn;
}

void de_set_base_output_filename(deark *c, const char *fn)
{
	if(c->base_output_filename) de_free(c, c->base_output_filename);
	c->base_output_filename = NULL;
	if(fn) {
		c->base_output_filename = de_strdup(c, fn);
	}
}

void de_set_output_archive_filename(deark *c, const char *fn)
{
	if(c->output_archive_filename) de_free(c, c->output_archive_filename);
	c->output_archive_filename = NULL;
	if(fn) {
		c->output_archive_filename = de_strdup(c, fn);
	}
}

void de_set_input_filename(deark *c, const char *fn)
{
	c->input_filename = fn;
}

void de_set_input_file_slice_start(deark *c, de_int64 n)
{
	c->slice_start_req = n;
}

void de_set_input_file_slice_size(deark *c, de_int64 n)
{
	c->slice_size_req = n;
	c->slice_size_req_valid = 1;
}

void de_set_output_style(deark *c, int x)
{
	c->output_style = x;
}

int de_identify_none(deark *c)
{
	return 0;
}

void de_set_debug_level(deark *c, int x)
{
	c->debug_level = x;
}

void de_set_extract_level(deark *c, int x)
{
	c->extract_level = x;
}

void de_set_listmode(deark *c, int x)
{
	c->list_mode = x;
}

void de_set_first_output_file(deark *c, int x)
{
	c->first_output_file = x;
}

void de_set_max_output_files(deark *c, int n)
{
	c->max_output_files = n;
}

void de_set_max_image_dimension(deark *c, de_int64 n)
{
	c->max_image_dimension = n;
}

void de_set_messages(deark *c, int x)
{
	c->show_messages = x;
}

void de_set_warnings(deark *c, int x)
{
	c->show_warnings = x;
}

void de_set_write_bom(deark *c, int x)
{
	c->write_bom = x;
}

void de_set_write_density(deark *c, int x)
{
	c->write_density = x;
}

void de_set_ascii_html(deark *c, int x)
{
	c->ascii_html = x;
}

void de_set_filenames_from_file(deark *c, int x)
{
	c->filenames_from_file = x;
}

void de_set_preserve_file_times(deark *c, int x)
{
	c->preserve_file_times = x;
}

struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id)
{
	int i;
	int k;

	if(!module_id) return NULL;

	for(i=0; i<c->num_modules; i++) {
		if(!de_strcmp(c->module_info[i].id, module_id)) {
			return &c->module_info[i];
		}
		for(k=0; k<DE_MAX_MODULE_ALIASES; k++) {
			if(!c->module_info[i].id_alias[k]) continue;
			if(!de_strcmp(c->module_info[i].id_alias[k], module_id)) {
				return &c->module_info[i];
			}
		}
	}
	return NULL;
}

int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams)
{
	if(!mi) return 0;
	if(!mi->run_fn) return 0;
	c->module_nesting_level++;
	mi->run_fn(c, mparams);
	c->module_nesting_level--;
	return 1;
}

int de_run_module_by_id(deark *c, const char *id, de_module_params *mparams)
{
	struct deark_module_info *module_to_use;

	module_to_use = de_get_module_by_id(c, id);
	if(!module_to_use) {
		de_err(c, "Unknown or unsupported format \"%s\"\n", id);
		return 0;
	}

	return de_run_module(c, module_to_use, mparams);
}

void de_run_module_by_id_on_slice(deark *c, const char *id, de_module_params *mparams,
	dbuf *f, de_int64 pos, de_int64 len)
{
	dbuf *old_ifile;

	old_ifile = c->infile;
	c->infile = dbuf_open_input_subfile(f, pos, len);
	de_run_module_by_id(c, id, mparams);
	dbuf_close(c->infile);
	c->infile = old_ifile;
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

const char *de_get_ext_option(deark *c, const char *name)
{
	int i;

	for(i=0; i<c->num_ext_options; i++) {
		if(!strcmp(c->ext_option[i].name, name)) {
			return c->ext_option[i].val;
		}
	}
	return NULL; // Option name not found.
}

void de_set_input_format(deark *c, const char *fmtname)
{
	c->input_format_req = fmtname;
}

int de_atoi(const char *string)
{
	return atoi(string);
}

de_int64 de_atoi64(const char *string)
{
	return de_strtoll(string, NULL, 10);
}

de_int64 de_log2_rounded_up(de_int64 n)
{
	de_int64 i;

	if(n<=2) return 1;
	for(i=2; i<32; i++) {
		if(n <= (((de_int64)1)<<i)) return i;
	}
	return 32;
}

const char *de_get_input_file_ext(deark *c)
{
	int len;
	int pos;

	if(!c->input_filename) return "";

	// If we skipped over the first part of the file, assume we're reading
	// an embedded format that's not indicated by the file extension.
	if(c->slice_start_req) return "";

	len = (int)strlen(c->input_filename);
	if(len<2) return "";

	// Find the position of the last ".", that's after the last "/"
	pos = len-2;

	while(pos>=0) {
		if(c->input_filename[pos]=='.') {
			return &c->input_filename[pos+1];
		}
		if(c->input_filename[pos]=='/' || c->input_filename[pos]=='\\')
			break;
		pos--;
	}
	return "";
}

int de_input_file_has_ext(deark *c, const char *ext)
{
	const char *e;

	e = de_get_input_file_ext(c);
	if(!de_strcasecmp(e, ext))
		return 1;
	return 0;
}


de_finfo *de_finfo_create(deark *c)
{
	de_finfo *fi;
	fi = de_malloc(c, sizeof(de_finfo));
	return fi;
}

void de_finfo_destroy(deark *c, de_finfo *fi)
{
	if(!fi) return;
	if(fi->file_name) de_free(c, fi->file_name);
	de_free(c, fi);
}

void de_finfo_set_name_from_slice(deark *c, de_finfo *fi, dbuf *f,
	de_int64 pos, de_int64 len, unsigned int conv_flags)
{
	de_byte *tmpbuf = NULL;

	tmpbuf = de_malloc(c, len);
	dbuf_read(f, tmpbuf, pos, len);
	de_finfo_set_name_from_bytes(c, fi, tmpbuf, len, conv_flags, DE_ENCODING_ASCII);
	de_free(c, tmpbuf);
}

void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1, int encoding)
{
	de_int64 name1_len;

	name1_len = (de_int64)de_strlen(name1);
	de_finfo_set_name_from_bytes(c, fi, (const de_byte*)name1, name1_len, 0, encoding);
}

void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s)
{
	de_int64 i;
	de_int32 ch;
	de_int64 fnlen;
	de_int64 utf8len;

	fi->file_name = de_malloc(c, 4*s->len+10);
	fnlen = 0;
	for(i=0; i<s->len; i++) {
		ch = de_char_to_valid_fn_char(c, s->str[i]);
		if(ch<128) {
			fi->file_name[fnlen++] = (char)(unsigned char)ch;
		}
		else {
			de_uchar_to_utf8(ch, (de_byte*)&fi->file_name[fnlen], &utf8len);
			fnlen += utf8len;
		}
	}

	// Strip trailing spaces
	while(fnlen>0 && fi->file_name[fnlen-1]==' ') {
		fnlen--;
	}

	// Don't allow empty filenames.
	if(fnlen<1) {
		fi->file_name[fnlen++] = '_';
		return;
	}

	fi->file_name[fnlen] = '\0';
}

// Caller allocates 'fname'.
// If it is not empty, filename will be appended to it.
static void de_bytes_to_filename_component_ucstring(deark *c,
	const de_byte *name1, de_int64 name1_len, de_ucstring *fname,
	unsigned int conv_flags, int encoding)
{
	de_int64 i;
	de_byte ch;
	de_int32 uchar;

	for(i=0; i<name1_len; i++) {
		ch = name1[i];
		if(ch==0 && (conv_flags & DE_CONVFLAG_STOP_AT_NUL)) {
			break;
		}

		if(encoding==DE_ENCODING_LATIN1) {
			uchar = (de_int32)ch;
		}
		else { // ASCII
			if(ch<=0x7f) uchar = (de_int32)ch;
			else uchar = '_';
		}
		ucstring_append_char(fname, uchar);
	}
}

// Supported encodings: ASCII, LATIN1
void de_finfo_set_name_from_bytes(deark *c, de_finfo *fi,
	const de_byte *name1, de_int64 name1_len,
	unsigned int conv_flags, int encoding)
{
	de_ucstring *fname = NULL;

	fname = ucstring_create(c);

	de_bytes_to_filename_component_ucstring(c, name1, name1_len,
		fname, conv_flags, encoding);

	de_finfo_set_name_from_ucstring(c, fi, fname);

	ucstring_destroy(fname);
}

void de_unix_time_to_timestamp(de_int64 ut, struct de_timestamp *ts)
{
	de_memset(ts, 0, sizeof(struct de_timestamp));
	ts->is_valid = 1;
	ts->unix_time = ut;
}

de_int64 de_timestamp_to_unix_time(const struct de_timestamp *ts)
{
	if(ts->is_valid)
		return ts->unix_time;
	return 0;
}

// [Adapted from Eric Raymond's public domain my_timegm().]
// Convert a UTC time (as individual fields) to a de_timestamp.
// Since de_timestamp currently uses time_t format internally,
// this is basically a UTC version of mktime().
// yr = full year
// mo = month: 1=Jan, ... 12=Dec
// da = day of month: 1=1, ... 31=31
void de_make_timestamp(struct de_timestamp *ts,
	de_int64 yr, de_int64 mo, de_int64 da,
	de_int64 hr, de_int64 mi, double se)
{
	de_int64 result;
	de_int64 tm_mon;
	static const int cumulative_days[12] =
		{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

	de_memset(ts, 0, sizeof(struct de_timestamp));
	tm_mon = mo-1;
	if(tm_mon<0 || tm_mon>11) tm_mon=0;
	result = (yr - 1970) * 365 + cumulative_days[tm_mon];
	result += (yr - 1968) / 4;
	result -= (yr - 1900) / 100;
	result += (yr - 1600) / 400;
	if ((yr%4)==0 && ((yr%100)!=0 || (yr%400)==0) && tm_mon<2) {
		result--;
	}
	result += da-1;
	result *= 24;
	result += hr;
	result *= 60;
	result += mi;
	result *= 60;
	result += (de_int64)se;

	ts->unix_time = result;
	ts->is_valid = 1;
}

void de_declare_fmt(deark *c, const char *fmtname)
{
	if(c->module_nesting_level > 1) {
		return; // Only allowed for the top-level module
	}
	if(c->format_declared) return;
	de_msg(c, "Format: %s\n", fmtname);
	c->format_declared = 1;
}

// Assumes dst starts out with only '0' bits
void de_copy_bits(const de_byte *src, de_int64 srcbitnum,
	de_byte *dst, de_int64 dstbitnum, de_int64 bitstocopy)
{
	de_int64 i;
	de_byte b;

	for(i=0; i<bitstocopy; i++) {
		b = src[(srcbitnum+i)/8];
		b = (b>>(7-(srcbitnum+i)%8))&0x1;
		if(b) {
			b = b<<(7-(dstbitnum+i)%8);
			dst[(dstbitnum+i)/8] |= b;
		}
	}
}
