// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// deark-dbuf.c
//
// Functions related to the dbuf object.

#include "deark-config.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "deark-private.h"

#define DE_CACHE_SIZE 262144

// Fill the cache that remembers the first part of the file.
// TODO: We should probably use memory-mapped files instead when possible,
// but this is simple and portable, and does most of what we need.
// (It is surprising how slow repeatedly calling fseek/fread can be.)
static void populate_cache(dbuf *f)
{
	de_int64 bytes_to_read;
	de_int64 bytes_read;

	if(f->btype!=DBUF_TYPE_IFILE) return;

	bytes_to_read = DE_CACHE_SIZE;
	if(f->len < bytes_to_read) {
		bytes_to_read = f->len;
	}

	f->cache = de_malloc(f->c, DE_CACHE_SIZE);
	fseek(f->fp, 0, SEEK_SET);
	bytes_read = fread(f->cache, 1, (size_t)bytes_to_read, f->fp);
	f->cache_start_pos = 0;
	f->cache_bytes_used = bytes_read;
	f->file_pos_known = 0;
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

	if(!f->cache && f->cache_policy==DE_CACHE_POLICY_ENABLED) {
		populate_cache(f);
	}

	// If the data we need is all cached, get it from cache.
	if(f->cache &&
		pos >= f->cache_start_pos &&
		bytes_to_read <= f->cache_bytes_used - (pos - f->cache_start_pos) )
	{
		memcpy(buf, &f->cache[pos - f->cache_start_pos], (size_t)bytes_to_read);
		bytes_read = bytes_to_read;
		goto done_read;
	}

	switch(f->btype) {
	case DBUF_TYPE_IFILE:
		if(!f->fp) {
			de_err(c, "Internal: file not open\n");
			de_fatalerror(c);
			return;
		}

		// For performance reasons, don't call fseek if we're already at the
		// right position.
		if(!f->file_pos_known || f->file_pos!=pos) {
			fseek(f->fp, (long)(pos), SEEK_SET);
		}

		bytes_read = fread(buf, 1, (size_t)bytes_to_read, f->fp);

		f->file_pos = pos + bytes_read;
		f->file_pos_known = 1;
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
		if(f->cache2_bytes_used>0 && pos==f->cache2_start_pos) {
			return f->cache2[0];
		}

		dbuf_read(f, &f->cache2[0], pos, 1);
		f->cache2_bytes_used = 1;
		f->cache2_start_pos = pos;
		return f->cache2[0];
	}
	return 0x00;
}

de_int64 de_getui16be_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[1]) | (((de_uint32)m[0])<<8));
}

de_int64 dbuf_getui16be(dbuf *f, de_int64 pos)
{
	de_byte m[2];
	dbuf_read(f, m, pos, 2);
	return de_getui16be_direct(m);
}

de_int64 de_getui16le_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[0]) | (((de_uint32)m[1])<<8));
}

de_int64 dbuf_getui16le(dbuf *f, de_int64 pos)
{
	de_byte m[2];
	dbuf_read(f, m, pos, 2);
	return de_getui16le_direct(m);
}

de_int64 dbuf_geti16be(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_getui16be(f, pos);
	if(n>=32768) n -= 65536;
	return n;
}

de_int64 dbuf_geti16le(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_getui16le(f, pos);
	if(n>=32768) n -= 65536;
	return n;
}

de_int64 de_getui32be_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[3]) | (((de_uint32)m[2])<<8) |
		(((de_uint32)m[1])<<16) | (((de_uint32)m[0])<<24));
}

de_int64 dbuf_getui32be(dbuf *f, de_int64 pos)
{
	de_byte m[4];
	dbuf_read(f, m, pos, 4);
	return de_getui32be_direct(m);
}

de_int64 de_getui32le_direct(const de_byte *m)
{
	return (de_int64)(((de_uint32)m[0]) | (((de_uint32)m[1])<<8) |
		(((de_uint32)m[2])<<16) | (((de_uint32)m[3])<<24));
}

de_int64 dbuf_getui32le(dbuf *f, de_int64 pos)
{
	de_byte m[4];
	dbuf_read(f, m, pos, 4);
	return de_getui32le_direct(m);
}

de_int64 dbuf_geti32be(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_getui32be(f, pos);
	return (de_int64)(de_int32)(de_uint32)n;
}

de_int64 dbuf_geti32le(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_getui32le(f, pos);
	return (de_int64)(de_int32)(de_uint32)n;
}

de_int64 de_geti64be_direct(const de_byte *m)
{
	return ((de_int64)m[7]) | (((de_int64)m[6])<<8) | (((de_int64)m[5])<<16) | (((de_int64)m[4])<<24) |
		(((de_int64)m[3])<<32) | (((de_int64)m[2])<<40) | (((de_int64)m[1])<<48) | (((de_int64)m[0])<<56);
}

de_int64 dbuf_geti64be(dbuf *f, de_int64 pos)
{
	de_byte m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64be_direct(m);
}

de_int64 de_geti64le_direct(const de_byte *m)
{
	return ((de_int64)m[0]) | (((de_int64)m[1])<<8) | (((de_int64)m[2])<<16) | (((de_int64)m[3])<<24) |
		(((de_int64)m[4])<<32) | (((de_int64)m[5])<<40) | (((de_int64)m[6])<<48) | (((de_int64)m[7])<<56);
}

de_int64 dbuf_geti64le(dbuf *f, de_int64 pos)
{
	de_byte m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64le_direct(m);
}

de_int64 dbuf_getui16x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_getui16le(f, pos);
	return dbuf_getui16be(f, pos);
}

de_int64 dbuf_getui32x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_getui32le(f, pos);
	return dbuf_getui32be(f, pos);
}

de_int64 dbuf_geti32x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_geti32le(f, pos);
	return dbuf_geti32be(f, pos);
}

de_int64 dbuf_geti64x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_geti64le(f, pos);
	return dbuf_geti64be(f, pos);
}

de_uint32 dbuf_getRGB(dbuf *f, de_int64 pos, unsigned int flags)
{
	de_byte buf[3];
	dbuf_read(f, buf, pos, 3);
	if(flags&DE_GETRGBFLAG_BGR)
		return DE_MAKE_RGB(buf[2], buf[1], buf[0]);
	return DE_MAKE_RGB(buf[0], buf[1], buf[2]);
}

void dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf)
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
		if(bytes_to_read>(de_int64)sizeof(buf)) bytes_to_read=(de_int64)sizeof(buf);

		dbuf_read(inf, buf, input_pos, bytes_to_read);
		dbuf_write(outf, buf, bytes_to_read);
		bytes_left -= bytes_to_read;
		input_pos += bytes_to_read;
	}
}

void dbuf_read_sz(dbuf *f, de_int64 pos, char *dst, size_t dst_size)
{
	de_int64 i;
	de_int64 bytes_copied = 0;
	de_byte b;

	for(i=0; i<(de_int64)dst_size-1; i++) {
		b = dbuf_getbyte(f, pos+i);
		if(b==0x00) break;
		dst[i] = (char)b;
		bytes_copied++;
	}
	dst[bytes_copied] = '\0';
}

int dbuf_memcmp(dbuf *f, de_int64 pos, const void *s, size_t n)
{
	de_byte *buf;
	int ret;

	buf = de_malloc(f->c, n);
	dbuf_read(f, buf, pos, n);
	ret = memcmp(buf, s, n);
	de_free(f->c, buf);
	return ret;
}

int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size,
	const char *ext, de_finfo *fi)
{
	dbuf *f;
	f = dbuf_create_output_file(inf->c, ext, fi);
	if(!f) return 0;
	dbuf_copy(inf, pos, data_size, f);
	dbuf_close(f);
	return 1;
}

dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi)
{
	char nbuf[500];
	char msgbuf[200];
	dbuf *f;
	const char *basefn;
	int file_index;
	char fn_suffix[256];

	f = de_malloc(c, sizeof(dbuf));

	file_index = c->file_count;
	c->file_count++;

	basefn = c->base_output_filename ? c->base_output_filename : "output";

	if(ext && fi && fi->file_name) {
		de_snprintf(fn_suffix, sizeof(fn_suffix), "%s.%s", fi->file_name, ext);
	}
	else if(ext) {
		de_strlcpy(fn_suffix, ext, sizeof(fn_suffix));
	}
	else if(fi && fi->file_name) {
		de_strlcpy(fn_suffix, fi->file_name, sizeof(fn_suffix));
	}
	else {
		de_strlcpy(fn_suffix, "bin", sizeof(fn_suffix));
	}

	de_snprintf(nbuf, sizeof(nbuf), "%s.%03d.%s", basefn, file_index, fn_suffix);

	if(c->output_style==DE_OUTPUTSTYLE_ZIP && !c->base_output_filename &&
		fi && fi->original_filename_flag &&
		fi->file_name && fi->file_name[0])
	{
		// TODO: This is a "temporary" hack to allow us to, when both reading from
		// and writing to an archive format, use some semblance of the correct
		// filename (instead of "output.xxx.yyy").
		// There are some things that we don't handle optimally, such as
		// subdirectories.
		// A major redesign of the file naming logic would be good.
		de_strlcpy(nbuf, fi->file_name, sizeof(nbuf));
	}

	f->name = de_strdup(c, nbuf);
	f->c = c;

	if(fi && fi->mod_time_valid) {
		f->mod_time_valid = fi->mod_time_valid;
		f->mod_time = fi->mod_time;
	}

	if(file_index < c->first_output_file) {
		return f;
	}

	if(c->max_output_files>=0 &&
		file_index >= c->first_output_file + c->max_output_files)
	{
		return f;
	}

	if(c->list_mode) {
		de_msg(c, "%s\n", f->name);
		return f;
	}

	if(c->output_style==DE_OUTPUTSTYLE_ZIP) {
		de_msg(c, "Adding %s to ZIP file\n", f->name);
		f->btype = DBUF_TYPE_MEMBUF;
		f->write_memfile_to_zip_archive = 1;
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

static void membuf_append(dbuf *f, const de_byte *m, de_int64 mlen)
{
	de_int64 new_alloc_size;

	if(f->max_len>0) {
		if(f->len + mlen > f->max_len) {
			mlen = f->max_len - f->len;
		}
	}

	if(mlen<=0) return;

	if(mlen > f->membuf_alloc - f->len) {
		// Need to allocate more space
		new_alloc_size = (f->membuf_alloc + mlen)*2;
		if(new_alloc_size<1024) new_alloc_size=1024;
		// TODO: Guard against integer overflows.
		de_dbg3(f->c, "increasing membuf size %d -> %d\n", (int)f->membuf_alloc, (int)new_alloc_size);
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
			de_dbg3(f->c, "Appending %d bytes to membuf %s\n", (int)len, f->name);
		}
		membuf_append(f, m, len);
		return;
	}

	if(!f->fp) return; // Presumably, we're in "list only" mode.

	de_dbg3(f->c, "Writing %d bytes to %s\n", (int)len, f->name);
	fwrite(m, 1, (size_t)len, f->fp);
	f->len += len;
}

void dbuf_writebyte(dbuf *f, de_byte n)
{
	dbuf_write(f, &n, 1);
}

void dbuf_write_run(dbuf *f, de_byte n, de_int64 len)
{
	de_byte buf[1024];
	de_int64 amt_left;
	de_int64 amt_to_write;

	de_memset(buf, n, (size_t)len<sizeof(buf) ? (size_t)len : sizeof(buf));
	amt_left = len;
	while(amt_left > 0) {
		if((size_t)amt_left<sizeof(buf))
			amt_to_write = amt_left;
		else
			amt_to_write = sizeof(buf);
		dbuf_write(f, buf, amt_to_write);
		amt_left -= amt_to_write;
	}
}

void dbuf_write_zeroes(dbuf *f, de_int64 len)
{
	dbuf_write_run(f, 0, len);
}

// Make the membuf have exactly len bytes of content.
void dbuf_truncate(dbuf *f, de_int64 desired_len)
{
	if(desired_len<0) desired_len=0;
	if(desired_len>f->len) {
		dbuf_write_zeroes(f, desired_len - f->len);
	}
	else if(desired_len<f->len) {
		if(f->btype==DBUF_TYPE_MEMBUF) {
			f->len = desired_len;
		}
	}
}

void de_writeui16le_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)(n & 0x00ff);
	m[1] = (de_byte)((n & 0xff00)>>8);
}

void dbuf_writeui16le(dbuf *f, de_int64 n)
{
	de_byte buf[2];
	de_writeui16le_direct(buf, n);
	dbuf_write(f, buf, 2);
}

void de_writeui32be_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)((n & 0xff000000)>>24);
	m[1] = (de_byte)((n & 0x00ff0000)>>16);
	m[2] = (de_byte)((n & 0x0000ff00)>>8);
	m[3] = (de_byte)(n & 0x000000ff);
}

void de_writeui32le_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)(n & 0x000000ff);
	m[1] = (de_byte)((n & 0x0000ff00)>>8);
	m[2] = (de_byte)((n & 0x00ff0000)>>16);
	m[3] = (de_byte)((n & 0xff000000)>>24);
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

dbuf *dbuf_open_input_file(deark *c, const char *fn)
{
	dbuf *f;
	int ret;
	char msgbuf[200];

	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_IFILE;
	f->c = c;
	f->cache_policy = DE_CACHE_POLICY_ENABLED;

	ret = de_examine_file_by_name(c, fn, &f->len, msgbuf, sizeof(msgbuf));
	if(!ret) {
		de_err(c, "Can't read %s: %s\n", fn, msgbuf);
		de_free(c, f);
		return NULL;
	}

	f->fp = de_fopen(c, fn, "rb", msgbuf, sizeof(msgbuf));

	if(!f->fp) {
		de_err(c, "Can't read %s: %s\n", fn, msgbuf);
		de_free(c, f);
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
			de_dbg3(c, "Closing memfile %s\n", f->name);
		}
	}

	if(f->fp) {
		if(f->name) {
			de_dbg3(c, "Closing file %s\n", f->name);
		}
		de_fclose(f->fp);
		f->fp = NULL;

		if(f->btype==DBUF_TYPE_OFILE && c->preserve_file_times) {
			de_update_file_time(f);
		}
	}

	de_free(c, f->membuf_buf);
	de_free(c, f->name);
	de_free(c, f->cache);
	de_free(c, f);
}

void dbuf_empty(dbuf *f)
{
	if(f->btype == DBUF_TYPE_MEMBUF) {
		f->len = 0;
	}
}

// Search a section of a dbuf for a given byte.
// 'haystack_len' is the number of bytes to search.
// Returns 0 if not found.
// If found, sets *foundpos to the position in the file where it was found
// (not relative to startpos).
int dbuf_search_byte(dbuf *f, const de_byte b, de_int64 startpos,
	de_int64 haystack_len, de_int64 *foundpos)
{
	de_int64 i;

	for(i=0; i<haystack_len; i++) {
		if(b == dbuf_getbyte(f, startpos+i)) {
			*foundpos = startpos+i;
			return 1;
		}
	}
	return 0;
}

// Search a section of a dbuf for a given byte sequence.
// 'haystack_len' is the number of bytes to search in (the sequence must be completely
// within that range, not just start there).
// Returns 0 if not found.
// If found, sets *foundpos to the position in the file where it was found
// (not relative to startpos).
int dbuf_search(dbuf *f, const de_byte *needle, de_int64 needle_len,
	de_int64 startpos, de_int64 haystack_len, de_int64 *foundpos)
{
	de_byte *buf = NULL;
	int retval = 0;
	de_int64 i;

	*foundpos = 0;

	if(startpos > f->len) {
		goto done;
	}
	if(haystack_len > f->len - startpos) {
		haystack_len = f->len - startpos;
	}
	if(needle_len > haystack_len) {
		goto done;
	}
	if(needle_len<1) {
		retval = 1;
		*foundpos = startpos;
		goto done;
	}

	// TODO: Read memory in chunks (to support large files, and to be more efficient).
	// Don't read it all at once.

	buf = de_malloc(f->c, haystack_len);
	dbuf_read(f, buf, startpos, haystack_len);

	for(i=0; i<=haystack_len-needle_len; i++) {
		if(needle[0]==buf[i] && !de_memcmp(needle, &buf[i], (size_t)needle_len)) {
			retval = 1;
			*foundpos = startpos+i;
			goto done;
		}
	}

done:
	de_free(f->c, buf);
	return retval;
}

int dbuf_find_line(dbuf *f, de_int64 pos1, de_int64 *pcontent_len, de_int64 *ptotal_len)
{
	de_byte b0, b1;
	de_int64 pos;
	de_int64 eol_pos = 0;
	de_int64 eol_size = 0;

	*pcontent_len = 0;
	*ptotal_len = 0;
	if(pos1<0 || pos1>=f->len) {
		return 0;
	}

	pos = pos1;

	while(1) {
		if(pos>=f->len) {
			// No EOL.
			eol_pos = pos;
			eol_size = 0;
			break;
		}

		b0 = dbuf_getbyte(f, pos);

		if(b0==0x0d) {
			eol_pos = pos;
			// Look ahead at the next byte.
			b1 = dbuf_getbyte(f, pos+1);
			if(b1==0x0a) {
				// CR+LF
				eol_size = 2;
				break;
			}
			// LF
			eol_pos = pos;
			eol_size = 1;
			break;
		}
		else if(b0==0x0a) {
			eol_pos = pos;
			eol_size = 1;
			break;
		}

		pos++;
	}

	*pcontent_len = eol_pos - pos1;
	*ptotal_len = *pcontent_len + eol_size;

	return (*ptotal_len > 0);
}

de_int64 dbuf_get_length(dbuf *f)
{
	return f->len;
}

void dbuf_set_max_length(dbuf *f, de_int64 max_len)
{
	f->max_len = max_len;
}
