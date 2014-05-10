// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark-config.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/stat.h>
#include <sys/types.h>
#ifndef DE_WINDOWS
#include <unistd.h>
#include <errno.h>
#endif

#include "deark-private.h"

char *de_get_version_string(char *buf, size_t bufsize)
{
	if((DE_VERSION_NUMBER&0xff) == 0) {
		de_snprintf(buf, bufsize, "%u.%u.%u",
			(DE_VERSION_NUMBER&0xff000000)>>24,
			(DE_VERSION_NUMBER&0x00ff0000)>>16,
			DE_VERSION_NUMBER&0x0000ff00>>8);
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

// Just a wrapper for strcmp().
// Modules aren't expected to use the C library directly.
int de_strcmp(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

// A wrapper for memcmp().
int de_memcmp(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

// A wrapper for strchr().
char *de_strchr(const char *s, int c)
{
	if(!s) return NULL;
	return strchr(s, c);
}

// A wrapper for strlen().
size_t de_strlen(const char *s)
{
	return strlen(s);
}

int de_strcasecmp(const char *a, const char *b)
{
#ifdef DE_WINDOWS
	return _stricmp(a, b);
#else
	return strcasecmp(a, b);
#endif
}

void de_memset(void *dst, int x, size_t len)
{
	memset(dst, x, len);
}

static void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
#ifdef DE_WINDOWS
	_vsnprintf_s(buf,buflen,_TRUNCATE,fmt,ap);
#else
	vsnprintf(buf,buflen,fmt,ap);
#endif
	buf[buflen-1]='\0';
}

void de_snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	de_vsnprintf(buf,buflen,fmt,ap);
	va_end(ap);
}

void de_dbg(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c && c->debug_level<1) return;

	fprintf(stderr,"DEBUG: ");
	va_start(ap, fmt);
	vfprintf(stderr,fmt,ap);
	fflush(stderr);
	va_end(ap);
}

void de_dbg2(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c && c->debug_level<2) return;

	fprintf(stderr,"DEBUG: ");
	va_start(ap, fmt);
	vfprintf(stderr,fmt,ap);
	fflush(stderr);
	va_end(ap);
}

// c can be NULL
void de_err(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(c) c->error_count++;
	fprintf(stderr,"Error: ");
	va_start(ap, fmt);
	vfprintf(stderr,fmt,ap);
	va_end(ap);
}

void de_warn(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_warnings) return;
	fprintf(stderr,"Warning: ");
	va_start(ap, fmt);
	vfprintf(stderr,fmt,ap);
	va_end(ap);
}

void de_msg(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_messages) return;
	va_start(ap, fmt);
	vfprintf(stderr,fmt,ap);
	va_end(ap);
}

// c can be NULL.
void de_fatalerror(deark *c)
{
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

char *de_strdup(deark *c, const char *s)
{
	char *s2;
#ifdef DE_WINDOWS
	s2 = _strdup(s);
#else
	s2 = strdup(s);
#endif
	if(!s2) {
		de_err(c, "Memory allocation failed\n");
		de_fatalerror(c);
	}
	return s2;
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
	return c;
}

void de_destroy(deark *c)
{
	if(!c) return;
	if(c->zip_file) { de_zip_close_file(c); }
	if(c->base_output_filename) { de_free(c, c->base_output_filename); }
	if(c->output_archive_filename) { de_free(c, c->output_archive_filename); }
	de_free(NULL,c);
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

// Read len bytes, starting at file position pos, into buf.
// Unread bytes will be set to 0.
void dbuf_read(dbuf *f, de_byte *buf, de_int64 pos, de_int64 len)
{
	de_int64 bytes_read = 0;
	de_int64 bytes_to_read;
	deark *c;

	c = f->c;

	bytes_to_read = len;
	if(pos >= f->len) {
		bytes_to_read = 0;
	}
	else if(pos + bytes_to_read > f->len) {
		bytes_to_read = f->len - pos;
	}

	if(bytes_to_read<1) {
		goto done_read;
	}

	switch(f->btype) {
	case DBUF_TYPE_IFILE:
		if(!f->fp) {
			de_err(c, "Internal: file not open\n");
			de_fatalerror(c);
			return;
		}

		fseek(f->fp, (long)(pos), SEEK_SET);
		bytes_read = fread(buf, 1, (size_t)bytes_to_read, f->fp);
		break;

	case DBUF_TYPE_DBUF:
		// Recursive call to the parent dbuf.
		dbuf_read(f->parent_dbuf, buf, f->offset_into_parent_dbuf+pos, bytes_to_read);

		// The parent dbuf always writes 'bytes_to_read' bytes.
		bytes_read = bytes_to_read;
		break;

	case DBUF_TYPE_MEMBUF:
		memcpy(buf, &f->membuf_buf[pos], (size_t)bytes_to_read);
		bytes_read = bytes_to_read;
		break;

	default:
		de_err(c, "Internal: getbytes from this I/O type not implemented\n");
		de_fatalerror(c);
		return;
	}

done_read:
	// Zero out any requested bytes that were not read.
	if(bytes_read < len) {
		de_memset(buf+bytes_read, 0, (size_t)(len - bytes_read));
	}
}

de_byte dbuf_getbyte(dbuf *f, de_int64 pos)
{
	switch(f->btype) {
	case DBUF_TYPE_MEMBUF:
		// Optimization for memory buffers
		if(pos>=0 && pos<f->len) {
			return f->membuf_buf[pos];
		}
		break;
	default:
		// A simple 1-byte cache, mainly to speed up de_convert_row_bilevel().
		if(f->cache_bytes_used>0 && pos==f->cache_pos) {
			return f->cache[0];
		}

		dbuf_read(f, &f->cache[0], pos, 1);
		f->cache_bytes_used = 1;
		f->cache_pos = pos;
		return f->cache[0];
	}
	return 0x00;
}

de_int64 de_getui16be_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[1]) | (((de_uint32)m[0])<<8));
}

de_int64 de_getui16le_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[0]) | (((de_uint32)m[1])<<8));
}

de_int64 de_getui32be_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[3]) | (((de_uint32)m[2])<<8) |
		(((de_uint32)m[1])<<16) | (((de_uint32)m[0])<<24));
}

de_int64 de_getui32le_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[0]) | (((de_uint32)m[1])<<8) |
		(((de_uint32)m[2])<<16) | (((de_uint32)m[3])<<24));
}

de_int64 de_geti64be_direct(const de_byte *m)
{
	return ((de_int64)m[7]) | (((de_int64)m[6])<<8) | (((de_int64)m[5])<<16) | (((de_int64)m[4])<<24) |
		(((de_int64)m[3])<<32) | (((de_int64)m[2])<<40) | (((de_int64)m[1])<<48) | (((de_int64)m[0])<<56);
}

de_int64 de_geti64le_direct(const de_byte *m)
{
	return ((de_int64)m[0]) | (((de_int64)m[1])<<8) | (((de_int64)m[2])<<16) | (((de_int64)m[3])<<24) |
		(((de_int64)m[4])<<32) | (((de_int64)m[5])<<40) | (((de_int64)m[6])<<48) | (((de_int64)m[7])<<56);
}

de_int64 dbuf_getui16be(dbuf *f, de_int64 pos)
{
	de_byte m[2];
	dbuf_read(f, m, pos, 2);
	return de_getui16be_direct(m);
}

de_int64 dbuf_getui16le(dbuf *f, de_int64 pos)
{
	de_byte m[2];
	dbuf_read(f, m, pos, 2);
	return de_getui16le_direct(m);
}

de_int64 dbuf_getui32be(dbuf *f, de_int64 pos)
{
	de_byte m[4];
	dbuf_read(f, m, pos, 4);
	return de_getui32be_direct(m);
}

de_int64 dbuf_getui32le(dbuf *f, de_int64 pos)
{
	de_byte m[4];
	dbuf_read(f, m, pos, 4);
	return de_getui32le_direct(m);
}

de_int64 dbuf_geti64be(dbuf *f, de_int64 pos)
{
	de_byte m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64be_direct(m);
}

de_int64 dbuf_geti64le(dbuf *f, de_int64 pos)
{
	de_byte m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64le_direct(m);
}

de_int64 dbuf_getui16(dbuf *f, de_int64 pos)
{
	if(f->is_little_endian) return dbuf_getui16le(f, pos);
	return dbuf_getui16be(f, pos);
}

de_int64 dbuf_getui32(dbuf *f, de_int64 pos)
{
	if(f->is_little_endian) return dbuf_getui32le(f, pos);
	return dbuf_getui32be(f, pos);
}

de_int64 dbuf_geti64(dbuf *f, de_int64 pos)
{
	if(f->is_little_endian) return dbuf_geti64le(f, pos);
	return dbuf_geti64be(f, pos);
}

void  dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf)
{
	de_byte buf[16384];
	de_int64 input_pos;
	de_int64 bytes_left;
	de_int64 bytes_to_read;

	// To do: fail if input data goes far beyond the end of the input file.
	if(input_len > DE_MAX_FILE_SIZE) {
		de_err(inf->c, "File %s too large (%" INT64_FMT ")\n",outf->name,input_len);
		return;
	}

	bytes_left = input_len;
	input_pos = input_offset;

	while(bytes_left>0) {
		bytes_to_read = bytes_left;
		if(bytes_to_read>sizeof(buf)) bytes_to_read=sizeof(buf);

		dbuf_read(inf, buf, input_pos, bytes_to_read);
		dbuf_write(outf, buf, bytes_to_read);
		bytes_left -= bytes_to_read;
		input_pos += bytes_to_read;
	}
}

int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size, const char *ext)
{
	dbuf *f;
	f = dbuf_create_output_file(inf->c, ext);
	if(!f) return 0;
	dbuf_copy(inf, pos, data_size, f);
	dbuf_close(f);
	return 1;
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

void de_set_messages(deark *c, int x)
{
	c->show_messages = x;
}

void de_set_warnings(deark *c, int x)
{
	c->show_warnings = x;
}

dbuf *dbuf_create_output_file(deark *c, const char *ext)
{
	char nbuf[500];
	char msgbuf[200];
	dbuf *f;
	const char *basefn;

	f = de_malloc(c, sizeof(dbuf));

	basefn = c->base_output_filename ? c->base_output_filename : "output";

	de_snprintf(nbuf, sizeof(nbuf), "%s.%03d.%s", basefn, c->file_count, ext);
	c->file_count++;

	f->name = de_strdup(c, nbuf);
	f->c = c;

	if(c->list_mode) {
		de_msg(c, "%s\n", f->name);
		return f;
	}

	if(c->output_style==DE_OUTPUTSTYLE_ZIP) {
		de_msg(c, "Adding %s to ZIP file\n", f->name);
		f->btype = DBUF_TYPE_MEMBUF;
		f->write_memfile_to_zip_archive = 1;

		// TODO: This is ugly, should be combined with dbuf_create_membuf's code.
		//f->file_data = dbuf_create_membuf(c, 2048);
		f->membuf_buf = de_malloc(c, 2048);
		f->membuf_alloc = 2048;
	}
	else {
		de_msg(c, "Writing %s\n", f->name);
		f->btype = DBUF_TYPE_OFILE;
		f->fp = de_fopen(c, f->name, "wb", msgbuf, sizeof(msgbuf));

		if(!f->fp) {
			de_err(c, "Failed to write %s: %s\n", f->name, msgbuf);
			dbuf_close(f);
			de_fatalerror(c);
		}
	}

	return f;
}

dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize)
{
	dbuf *f;
	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->btype = DBUF_TYPE_MEMBUF;

	if(initialsize>0) {
		f->membuf_buf = de_malloc(c, initialsize);
		f->membuf_alloc = initialsize;
	}
	return f;
}

struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id)
{
	int i;

	if(!module_id) return NULL;

	for(i=0; i<c->num_modules; i++) {
		if(!de_strcmp(c->module_info[i].id, module_id)) {
			return &c->module_info[i];
		}
	}
	return NULL;
}

int de_run_module(deark *c, struct deark_module_info *mi, const char *params)
{
	if(!mi) return 0;
	if(!mi->run_fn) return 0;
	mi->run_fn(c, params);
	return 1;
}

int de_run_module_by_id(deark *c, const char *id, const char *params)
{
	struct deark_module_info *module_to_use;

	module_to_use = de_get_module_by_id(c, id);
	if(!module_to_use) {
		de_err(c, "Unknown or unsupported format \"%s\"\n", id);
		return 0;
	}

	return de_run_module(c, module_to_use, params);
}

static void membuf_append(dbuf *f, const de_byte *m, de_int64 mlen)
{
	de_int64 new_alloc_size;

	if(mlen<1) return;

	if(mlen > f->membuf_alloc - f->len) {
		// Need to allocate more space
		new_alloc_size = (f->membuf_alloc + mlen)*2;
		// TODO: Guard against integer overflows.
		de_dbg2(f->c, "increasing membuf size %d -> %d\n", (int)f->membuf_alloc, (int)new_alloc_size);
		f->membuf_buf = de_realloc(f->c, f->membuf_buf, f->membuf_alloc, new_alloc_size);
		f->membuf_alloc = new_alloc_size;
	}

	memcpy(&f->membuf_buf[f->len], m, (size_t)mlen);
	f->len += mlen;
}

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len)
{
	if(f->btype==DBUF_TYPE_MEMBUF) {
		if(f->name) {
			de_dbg2(f->c, "Appending %d bytes to membuf %s\n", (int)len, f->name);
		}
		membuf_append(f, m, len);
		return;
	}

	if(!f->fp) return; // Presumably, we're in "list only" mode.

	de_dbg2(f->c, "Writing %d bytes to %s\n", (int)len, f->name);
	fwrite(m, 1, (size_t)len, f->fp);
}

void dbuf_writezeroes(dbuf *f, de_int64 len)
{
	de_byte *m;
	// TODO: This could be more efficient.
	m = de_malloc(f->c, len);
	dbuf_write(f, m, len);
	de_free(f->c, m);
}

void de_writeui16le_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)(n & 0x00ff);
	m[1] = (de_byte)((n & 0xff00)>>8);
}

void de_writeui32le_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)(n & 0x000000ff);
	m[1] = (de_byte)((n & 0x0000ff00)>>8);
	m[2] = (de_byte)((n & 0x00ff0000)>>16);
	m[3] = (de_byte)((n & 0xff000000)>>24);
}

void dbuf_writebyte(dbuf *f, de_byte n)
{
	dbuf_write(f, &n, 1);
}

void dbuf_writeui16le(dbuf *f, de_int64 n)
{
	de_byte buf[2];
	de_writeui16le_direct(buf, n);
	dbuf_write(f, buf, 2);
}

void dbuf_writeui32le(dbuf *f, de_int64 n)
{
	de_byte buf[4];
	de_writeui32le_direct(buf, n);
	dbuf_write(f, buf, 4);
}

void dbuf_fputs(dbuf *f, const char *sz)
{
	dbuf_write(f, (const de_byte*)sz, (de_int64)strlen(sz));
}

// TODO: Remove the buffer size limitation?
void dbuf_fprintf(dbuf *f, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	dbuf_fputs(f, buf);
}

void de_set_option(deark *c, const char *name, const char *val)
{
	int n;

	n = c->num_options;
	if(n>=DE_MAX_OPTIONS) return;

	c->option[n].name = name;
	c->option[n].val = val;
	c->num_options++;
}

const char *de_get_option(deark *c, const char *name)
{
	int i;

	for(i=0; i<c->num_options; i++) {
		if(!strcmp(c->option[i].name, name)) {
			return c->option[i].val;
		}
	}
	return NULL; // Option name not found.
}

void de_set_input_format(deark *c, const char *fmtname)
{
	c->input_format_req = fmtname;
}

dbuf *dbuf_open_input_file(deark *c, const char *fn)
{
	dbuf *f;
	char msgbuf[200];

	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_IFILE;
	f->c = c;

	f->fp = de_fopen(c, fn, "rb", msgbuf, sizeof(msgbuf));

	if(!f->fp) {
		de_err(c, "Can't read %s: %s\n", fn, msgbuf);
		de_free(c, f);
		return NULL;
	}

	// Record the file size.
	if(!de_get_file_size(f->fp, &f->len)) {
		de_err(c, "Can't determine file size of %s\n", fn);
		return NULL;
	}

	return f;
}

dbuf *dbuf_open_input_subfile(dbuf *parent, de_int64 offset, de_int64 size)
{
	dbuf *f;
	deark *c;

	c = parent->c;
	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_DBUF;
	f->c = c;
	f->parent_dbuf = parent;
	f->offset_into_parent_dbuf = offset;
	f->len = size;
	return f;
}

void dbuf_close(dbuf *f)
{
	deark *c;
	if(!f) return;
	c = f->c;

	if(f->write_memfile_to_zip_archive) {
		de_zip_add_file_to_archive(c, f);
		if(f->name) {
			de_dbg(c, "Closing memfile %s\n", f->name);
		}
	}

	if(f->fp) {
		if(f->name) {
			de_dbg(c, "Closing file %s\n", f->name);
		}
		fclose(f->fp);
	}
	f->fp = NULL;

	de_free(c, f->membuf_buf);
	de_free(c, f->name);
	de_free(c, f);
}

void dbuf_empty(dbuf *f)
{
	if(f->btype == DBUF_TYPE_MEMBUF) {
		f->len = 0;
	}
}

int de_atoi(const char *string)
{
	return atoi(string);
}

de_int64 de_strtoll(const char *string, char **endptr, int base)
{
#ifdef DE_WINDOWS
	return _strtoi64(string, endptr, base);
#else
	return strtoll(string, endptr, base);
#endif
}

de_int64 de_atoi64(const char *string)
{
	return de_strtoll(string, NULL, 10);
}

#ifndef DE_WINDOWS
// The Windows version of this function is in deark-win.c.
FILE* de_fopen(deark *c, const char *fn, const char *mode,
	char *errmsg, size_t errmsg_len)
{
	FILE *f;
	int errcode;

	f = fopen(fn, mode);
	if(!f) {
		errcode = errno;
		de_strlcpy(errmsg, strerror(errcode), errmsg_len);
	}
	return f;
}
#endif

int de_get_file_size(FILE *fp, de_int64 *pfsize)
{
#ifdef DE_WINDOWS
	struct _stat stbuf;

	if(_fstat(_fileno(fp),&stbuf)==0) {
		*pfsize = stbuf.st_size;
		return 1;
	}
	*pfsize = 0;
	return 0;
#else
	struct stat stbuf;

	if(fstat(fileno(fp),&stbuf)==0) {
		*pfsize = stbuf.st_size;
		return 1;
	}
	*pfsize = 0;
	return 0;
#endif
}

static void de_bitmap_alloc_pixels(struct deark_bitmap *img)
{
	if(img->bitmap) {
		de_free(img->c, img->bitmap);
	}
	img->bitmap_size = (img->width*img->bytes_per_pixel) * img->height;
	img->bitmap = de_malloc(img->c, img->bitmap_size);
}

void de_bitmap_write_to_file(struct deark_bitmap *img, const char *token)
{
	dbuf *f;
	char buf[80];

	if(!img) return;

	if(token==NULL || token[0]=='\0') {
		de_strlcpy(buf, "png", sizeof(buf));
	}
	else {
		de_snprintf(buf, sizeof(buf), "%s.png", token);
	}

	if(!img->bitmap) de_bitmap_alloc_pixels(img);

	f = dbuf_create_output_file(img->c, buf);
	de_write_png(img->c, img, f);
	dbuf_close(f);
}

void de_bitmap_setpixel_gray(struct deark_bitmap *img, de_int64 x, de_int64 y, de_byte v)
{
	de_int64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(x<0 || y<0 || x>=img->width || y>=img->height) return;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	img->bitmap[pos] = v;
	switch(img->bytes_per_pixel) {
	case 2: // gray+alpha
		img->bitmap[pos+1] = 255;
		break;
	case 3: // RGB
		img->bitmap[pos+1] = v;
		img->bitmap[pos+2] = v;
		break;
	case 4: // RGBA
		img->bitmap[pos+1] = v;
		img->bitmap[pos+2] = v;
		img->bitmap[pos+3] = 255;
		break;
	}
}

void de_bitmap_setpixel_rgb(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color)
{
	de_bitmap_setpixel_rgba(img, x, y, color);
}

void de_bitmap_setpixel_rgba(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color)
{
	de_int64 pos;

	if(!img->bitmap) de_bitmap_alloc_pixels(img);
	if(x<0 || y<0 || x>=img->width || y>=img->height) return;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	switch(img->bytes_per_pixel) {
	case 4:
		img->bitmap[pos]   = DE_COLOR_R(color);
		img->bitmap[pos+1] = DE_COLOR_G(color);
		img->bitmap[pos+2] = DE_COLOR_B(color);
		img->bitmap[pos+3] = DE_COLOR_A(color);
		break;
	case 3:
		img->bitmap[pos]   = DE_COLOR_R(color);
		img->bitmap[pos+1] = DE_COLOR_G(color);
		img->bitmap[pos+2] = DE_COLOR_B(color);
		break;
	case 2:
		img->bitmap[pos]   = DE_COLOR_G(color);
		img->bitmap[pos+1] = DE_COLOR_A(color);
		break;
	case 1:
		// TODO: We could to real grayscale conversion, but for now we
		// assume this won't happen, or that if it does the color given to
		// us is a gray shade.
		img->bitmap[pos]   = DE_COLOR_G(color);
		break;
	}
}

de_uint32 de_bitmap_getpixel(struct deark_bitmap *img, de_int64 x, de_int64 y)
{
	de_int64 pos;

	if(!img) return 0;
	if(!img->bitmap) return 0;
	if(x<0 || y<0 || x>=img->width || y>=img->height) return 0;
	pos = (img->width*img->bytes_per_pixel)*y + img->bytes_per_pixel*x;

	switch(img->bytes_per_pixel) {
	case 4:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos+1],
			img->bitmap[pos+2], img->bitmap[pos+3]);
	case 3:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos+1],
			img->bitmap[pos+2], 0xff);
		break;
	case 2:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos],
			img->bitmap[pos], img->bitmap[pos+1]);
		break;
	case 1:
		return DE_MAKE_RGBA(img->bitmap[pos], img->bitmap[pos],
			img->bitmap[pos], 0xff);
		break;
	}
	return 0;
}

de_int64 dbuf_get_length(dbuf *f)
{
	return f->len;
}

void dbuf_set_endianness(dbuf *f, int is_le)
{
	f->is_little_endian = is_le;
}

struct deark_bitmap *de_bitmap_create_noinit(deark *c)
{
	struct deark_bitmap *img;
	img = de_malloc(c, sizeof(struct deark_bitmap));
	img->c = c;
	return img;
}

struct deark_bitmap *de_bitmap_create(deark *c, de_int64 width, de_int64 height, int bypp)
{
	struct deark_bitmap *img;
	img = de_bitmap_create_noinit(c);
	img->width = width;
	img->height = height;
	img->bytes_per_pixel = bypp;
	//img->rowstride = img->width * img->bytes_per_pixel;
	return img;
}

void de_bitmap_destroy(struct deark_bitmap *b)
{
	if(b) {
		deark *c = b->c;
		if(b->bitmap) de_free(c, b->bitmap);
		de_free(c, b);
	}
}

de_byte de_get_bits_symbol(dbuf *f, int bps, de_int64 rowstart, de_int64 index)
{
	de_int64 byte_offset;
	de_byte b;
	de_byte x = 0;

	switch(bps) {
	case 1:
		byte_offset = rowstart + index/8;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (7 - index%8)) & 0x01;
		break;
	case 2:
		byte_offset = rowstart + index/4;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (2 * (3 - index%4))) & 0x03;
		break;
	case 4:
		byte_offset = rowstart + index/2;
		b = dbuf_getbyte(f, byte_offset);
		x = (b >> (4 * (1 - index%2))) & 0x0f;
		break;
	case 8:
		byte_offset = rowstart + index;
		x = dbuf_getbyte(f, byte_offset);
	}
	return x;
}

// Read a symbol (up to 8 bits) that starts at an arbitrary bit position.
// It may span (two) bytes.
de_byte de_get_bits_symbol2(dbuf *f, int nbits, de_int64 bytepos, de_int64 bitpos)
{
	de_byte b0, b1;
	int bits_in_first_byte;
	int bits_in_second_byte;

	bits_in_first_byte = 8-(bitpos%8);

	b0 = dbuf_getbyte(f, bytepos + bitpos/8);

	if(bits_in_first_byte<8) {
		b0 &= (0xff >> (8-bits_in_first_byte)); // Zero out insignificant bits
	}

	if(bits_in_first_byte == nbits) {
		// First byte has all the bits
		return b0;
	}
	else if(bits_in_first_byte >= nbits) {
		// First byte has all the bits
		return b0 >> (bits_in_first_byte - nbits);
	}

	bits_in_second_byte = nbits - bits_in_first_byte;
	b1 = dbuf_getbyte(f, bytepos + bitpos/8 +1);

	return (b0<<bits_in_second_byte) | (b1>>(8-bits_in_second_byte));
}

void de_convert_row_bilevel(dbuf *f, de_int64 fpos, struct deark_bitmap *img,
	de_int64 rownum, int invert)
{
	de_int64 i;
	de_byte x;
	de_byte black, white;

	if(invert) {
		white = 0; black = 255;
	}
	else {
		black = 0; white = 255;
	}

	for(i=0; i<img->width; i++) {
		x = de_get_bits_symbol(f, 1, fpos, i);
		de_bitmap_setpixel_gray(img, i, rownum, x ? white : black);
	}
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

void de_declare_fmt(deark *c, const char *fmtname)
{
	if(c->format_declared) return;
	de_msg(c, "Format: %s\n", fmtname);
	c->format_declared = 1;
}
