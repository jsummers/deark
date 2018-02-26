// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-dbuf.c
//
// Functions related to the dbuf object.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
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

// Read all data from stdin (or a named pipe) into memory.
static void populate_cache_from_pipe(dbuf *f)
{
	FILE *fp;
	de_int64 cache_bytes_alloc = 0;

	if(f->btype==DBUF_TYPE_STDIN) {
		fp = stdin;
	}
	else if(f->btype==DBUF_TYPE_FIFO) {
		fp = f->fp;
	}
	else {
		return;
	}

	f->cache_bytes_used = 0;

	while(1) {
		de_int64 bytes_to_read, bytes_read;

		if(f->cache_bytes_used >= cache_bytes_alloc) {
			de_int64 old_cache_size, new_cache_size;

			// Cache is full. Increase its size.
			old_cache_size = cache_bytes_alloc;
			new_cache_size = old_cache_size*2;
			if(new_cache_size<DE_CACHE_SIZE) new_cache_size = DE_CACHE_SIZE;
			f->cache = de_realloc(f->c, f->cache, old_cache_size, new_cache_size);
			cache_bytes_alloc = new_cache_size;
		}

		// Try to read as many bytes as it would take to fill the cache.
		bytes_to_read = cache_bytes_alloc - f->cache_bytes_used;
		if(bytes_to_read<1) break; // Shouldn't happen

		bytes_read = fread(&f->cache[f->cache_bytes_used], 1, (size_t)bytes_to_read, fp);
		if(bytes_read<1 || bytes_read>bytes_to_read) break;
		f->cache_bytes_used += bytes_read;
		if(feof(fp) || ferror(fp)) break;
	}

	f->len = f->cache_bytes_used;
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
		de_memcpy(buf, &f->cache[pos - f->cache_start_pos], (size_t)bytes_to_read);
		bytes_read = bytes_to_read;
		goto done_read;
	}

	switch(f->btype) {
	case DBUF_TYPE_IFILE:
		if(!f->fp) {
			de_err(c, "Internal: File not open");
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
		de_memcpy(buf, &f->membuf_buf[pos], (size_t)bytes_to_read);
		bytes_read = bytes_to_read;
		break;

	default:
		de_err(c, "Internal: getbytes from this I/O type not implemented");
		de_fatalerror(c);
		return;
	}

done_read:
	// Zero out any requested bytes that were not read.
	if(bytes_read < len) {
		de_memset(buf+bytes_read, 0, (size_t)(len - bytes_read));
	}
}

// A function that works a little more like a standard read/fread function than
// does dbuf_read. It returns the number of bytes read, won't read past end of
// file, and helps track the file position.
de_int64 dbuf_standard_read(dbuf *f, de_byte *buf, de_int64 n, de_int64 *fpos)
{
	de_int64 amt_to_read;

	if(*fpos < 0 || *fpos >= f->len) return 0;

	amt_to_read = n;
	if(*fpos + amt_to_read > f->len) amt_to_read = f->len - *fpos;
	dbuf_read(f, buf, *fpos, amt_to_read);
	*fpos += amt_to_read;
	return amt_to_read;
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
	unsigned int i;
	de_uint64 val = 0;

	for(i=0; i<8; i++) {
		val |= ((de_uint64)m[i])<<((7-i)*8);
	}
	return (de_int64)val;
}

de_int64 dbuf_geti64be(dbuf *f, de_int64 pos)
{
	de_byte m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64be_direct(m);
}

de_int64 de_geti64le_direct(const de_byte *m)
{
	unsigned int i;
	de_uint64 val = 0;

	for(i=0; i<8; i++) {
		val |= ((de_uint64)m[i])<<(i*8);
	}
	return (de_int64)val;
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

de_int64 dbuf_geti16x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_geti16le(f, pos);
	return dbuf_geti16be(f, pos);
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

static void init_fltpt_decoder(deark *c)
{
	unsigned int x = 1;
	char b = 0;

	c->can_decode_fltpt = 0;
	if(sizeof(float)!=4 || sizeof(double)!=8) return;
	c->can_decode_fltpt = 1;

	de_memcpy(&b, &x, 1);
	if(b==0)
		c->host_is_le = 0;
	else
		c->host_is_le = 1;
}

double de_getfloat32x_direct(deark *c, const de_byte *m, int is_le)
{
	char buf[4];
	float val = 0.0;

	if(c->can_decode_fltpt<0) {
		init_fltpt_decoder(c);
	}
	if(!c->can_decode_fltpt) return 0.0;

	// FIXME: This assumes that the native floating point format is
	// IEEE 754, but that does not have to be the case.

	de_memcpy(buf, m, 4);

	if(is_le != c->host_is_le) {
		int i;
		char tmpc;
		// Reverse order of bytes
		for(i=0; i<2; i++) {
			tmpc = buf[i]; buf[i] = buf[3-i]; buf[3-i] = tmpc;
		}
	}

	de_memcpy(&val, buf, 4);
	return (double)val;
}

double dbuf_getfloat32x(dbuf *f, de_int64 pos, int is_le)
{
	de_byte buf[4];
	dbuf_read(f, buf, pos, 4);
	return de_getfloat32x_direct(f->c, buf, is_le);
}

double de_getfloat64x_direct(deark *c, const de_byte *m, int is_le)
{
	char buf[8];
	double val = 0.0;

	if(c->can_decode_fltpt<0) {
		init_fltpt_decoder(c);
	}
	if(!c->can_decode_fltpt) return 0.0;

	de_memcpy(buf, m, 8);

	if(is_le != c->host_is_le) {
		int i;
		char tmpc;
		// Reverse order of bytes
		for(i=0; i<4; i++) {
			tmpc = buf[i]; buf[i] = buf[7-i]; buf[7-i] = tmpc;
		}
	}

	de_memcpy(&val, buf, 8);
	return (double)val;
}

double dbuf_getfloat64x(dbuf *f, de_int64 pos, int is_le)
{
	de_byte buf[8];
	dbuf_read(f, buf, pos, 8);
	return de_getfloat64x_direct(f->c, buf, is_le);
}

int dbuf_read_ascii_number(dbuf *f, de_int64 pos, de_int64 fieldsize,
	int base, de_int64 *value)
{
	char buf[32];

	*value = 0;
	if(fieldsize>(de_int64)(sizeof(buf)-1)) return 0;

	dbuf_read(f, (de_byte*)buf, pos, fieldsize);
	buf[fieldsize] = '\0';

	*value = de_strtoll(buf, NULL, base);
	return 1;
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
		de_err(inf->c, "File %s too large (%" INT64_FMT ")",outf->name,input_len);
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

void dbuf_copy_at(dbuf *inf, de_int64 input_offset, de_int64 input_len,
	dbuf *outf, de_int64 output_offset)
{
	de_byte b;
	de_int64 i;
	// TODO: Make this more efficient
	for(i=0; i<input_len; i++) {
		b = dbuf_getbyte(inf, input_offset+i);
		dbuf_writebyte_at(outf, output_offset+i, b);
	}
}

// An advanced function for reading a string from a file.
// The issue is that some strings are both human-readable and machine-readable.
// In such a case, we'd like to read some data from a file into a nice printable
// ucstring, while also making some or all of the raw bytes available, say for
// byte-for-byte string comparisons.
// Plus (for NUL-terminated/padded strings), we may need to know the actual length
// of the string in the file, so that it can be skipped over, even if we don't
// care about the whole string.
// Caller is responsible for calling destroy_stringreader() on the returned value.
//  max_bytes_to_scan: The maximum number of bytes to read from the file.
//  max_bytes_to_keep: The maximum (or in some cases the exact) number of bytes,
//   not counting any NUL terminator, to return in ->sz.
//   The ->str field is a Unicode version of ->sz, so this also affects ->str.
// If DE_CONVFLAG_STOP_AT_NUL is not set, it is assumed we are reading a string
// of known length, that may have internal NUL bytes. The caller must set
// max_bytes_to_scan and max_bytes_to_keep to the same value. The ->sz field will
// always be allocated with this many bytes, plus one more for an artificial NUL
// terminator.
// If DE_CONVFLAG_WANT_UTF8 is set, then the ->sz_utf8 field will be set to a
// UTF-8 version of ->str. This is mainly useful if the original string was
// UTF-16. sz_utf8 is not "printable" -- use ucstring_get_printable_sz_n(str) for
// that.
// Recognized flags:
//   - DE_CONVFLAG_STOP_AT_NUL
//   - DE_CONVFLAG_WANT_UTF8
struct de_stringreaderdata *dbuf_read_string(dbuf *f, de_int64 pos,
	de_int64 max_bytes_to_scan,
	de_int64 max_bytes_to_keep,
	unsigned int flags, int encoding)
{
	deark *c = f->c;
	struct de_stringreaderdata *srd;
	de_int64 foundpos = 0;
	int ret;
	de_int64 bytes_avail_to_read;
	de_int64 bytes_to_malloc;
	de_int64 x_strlen;

	srd = de_malloc(c, sizeof(struct de_stringreaderdata));
	srd->str = ucstring_create(c);

	bytes_avail_to_read = max_bytes_to_scan;
	if(bytes_avail_to_read > f->len-pos) {
		bytes_avail_to_read = f->len-pos;
	}

	srd->bytes_consumed = bytes_avail_to_read; // default

	// From here on, we can safely bail out ("goto done"). The
	// de_stringreaderdata struct is sufficiently valid.

	if(!(flags&DE_CONVFLAG_STOP_AT_NUL) &&
		(max_bytes_to_scan != max_bytes_to_keep))
	{
		// To reduce possible confusion, we require that
		// max_bytes_to_scan==max_bytes_to_keep in this case.
		srd->sz = de_malloc(c, max_bytes_to_keep);
		goto done;
	}

	if(flags&DE_CONVFLAG_STOP_AT_NUL) {
		ret = dbuf_search_byte(f, 0x00, pos, bytes_avail_to_read, &foundpos);
		if(ret) {
			srd->found_nul = 1;
		}
		else {
			// No NUL byte found. Could be an error in some formats, but in
			// others NUL is used as separator or as padding, not a terminator.
			foundpos = pos+bytes_avail_to_read;
		}

		x_strlen = foundpos-pos;
		srd->bytes_consumed = x_strlen+1;
	}
	else {
		x_strlen = max_bytes_to_keep;
		srd->bytes_consumed = x_strlen;
	}

	bytes_to_malloc = x_strlen+1;
	if(bytes_to_malloc>(max_bytes_to_keep+1)) {
		bytes_to_malloc = max_bytes_to_keep+1;
		srd->was_truncated = 1;
	}

	srd->sz = de_malloc(c, bytes_to_malloc);
	dbuf_read(f, srd->sz, pos, bytes_to_malloc-1); // The last byte remains NUL

	ucstring_append_bytes(srd->str, srd->sz, bytes_to_malloc-1, 0, encoding);

	if(flags&DE_CONVFLAG_WANT_UTF8) {
		srd->sz_utf8_strlen = (size_t)ucstring_count_utf8_bytes(srd->str);
		srd->sz_utf8 = de_malloc(c, srd->sz_utf8_strlen + 1);
		ucstring_to_sz(srd->str, srd->sz_utf8, srd->sz_utf8_strlen + 1, 0, DE_ENCODING_UTF8);
	}

done:
	if(!srd->sz) {
		// Always return a valid sz, even on failure.
		srd->sz = de_malloc(c, 1);
	}
	if((flags&DE_CONVFLAG_WANT_UTF8) && !srd->sz_utf8) {
		// Always return a valid sz_utf8 if it was requested, even on failure.
		srd->sz_utf8 = de_malloc(c, 1);
		srd->sz_utf8_strlen = 0;
	}
	return srd;
}

void de_destroy_stringreaderdata(deark *c, struct de_stringreaderdata *srd)
{
	if(!srd) return;
	de_free(c, srd->sz);
	de_free(c, srd->sz_utf8);
	ucstring_destroy(srd->str);
	de_free(c, srd);
}

// Read (up to) len bytes from f, translate them to characters, and append
// them to s.
void dbuf_read_to_ucstring(dbuf *f, de_int64 pos, de_int64 len,
	de_ucstring *s, unsigned int conv_flags, int encoding)
{
	de_byte *buf = NULL;
	deark *c = f->c;

	if(conv_flags & DE_CONVFLAG_STOP_AT_NUL) {
		de_int64 foundpos = 0;
		if(dbuf_search_byte(f, 0x00, pos, len, &foundpos)) {
			len = foundpos - pos;
		}
	}

	buf = de_malloc(c, len);
	dbuf_read(f, buf, pos, len);
	ucstring_append_bytes(s, buf, len, 0, encoding);
	de_free(c, buf);
}

void dbuf_read_to_ucstring_n(dbuf *f, de_int64 pos, de_int64 len, de_int64 max_len,
	de_ucstring *s, unsigned int conv_flags, int encoding)
{
	if(len>max_len) len=max_len;
	dbuf_read_to_ucstring(f, pos, len, s, conv_flags, encoding);
}

int dbuf_memcmp(dbuf *f, de_int64 pos, const void *s, size_t n)
{
	de_byte *buf;
	int ret;

	buf = de_malloc(f->c, n);
	dbuf_read(f, buf, pos, n);
	ret = de_memcmp(buf, s, n);
	de_free(f->c, buf);
	return ret;
}

int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size,
	const char *ext, de_finfo *fi, unsigned int createflags)
{
	dbuf *f;
	f = dbuf_create_output_file(inf->c, ext, fi, createflags);
	if(!f) return 0;
	dbuf_copy(inf, pos, data_size, f);
	dbuf_close(f);
	return 1;
}

// FIXME: If both ext and fi are set, there may be an inconsistency as to the
// final filename when using the -zip option.
dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi,
	unsigned int createflags)
{
	char nbuf[500];
	char msgbuf[200];
	dbuf *f;
	const char *basefn;
	int file_index;
	char fn_suffix[256];

	f = de_malloc(c, sizeof(dbuf));

	if(c->extract_policy==DE_EXTRACTPOLICY_MAINONLY) {
		if(createflags&DE_CREATEFLAG_IS_AUX) {
			de_dbg(c, "skipping 'auxiliary' file");
			f->btype = DBUF_TYPE_NULL;
			return f;
		}
	}
	else if(c->extract_policy==DE_EXTRACTPOLICY_AUXONLY) {
		if(!(createflags&DE_CREATEFLAG_IS_AUX)) {
			de_dbg(c, "skipping 'main' file");
			f->btype = DBUF_TYPE_NULL;
			return f;
		}
	}

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

	if(fi) {
		f->mod_time = fi->mod_time; // struct copy
		f->mode_flags = fi->mode_flags;
	}

	if(file_index < c->first_output_file) {
		f->btype = DBUF_TYPE_NULL;
		return f;
	}

	if(c->max_output_files>=0 &&
		file_index >= c->first_output_file + c->max_output_files)
	{
		f->btype = DBUF_TYPE_NULL;
		return f;
	}

	c->num_files_extracted++;

	if(c->list_mode) {
		f->btype = DBUF_TYPE_NULL;
		de_msg(c, "%s", f->name);
		return f;
	}

	if(c->output_style==DE_OUTPUTSTYLE_ZIP) {
		de_msg(c, "Adding %s to ZIP file", f->name);
		f->btype = DBUF_TYPE_MEMBUF;
		f->membuf_buf = de_malloc(c, 65536);
		f->membuf_alloc = 65536;
		f->write_memfile_to_zip_archive = 1;
	}
	else if(c->output_style==DE_OUTPUTSTYLE_STDOUT) {
		de_msg(c, "Writing %s to [stdout]", f->name);
		f->btype = DBUF_TYPE_STDOUT;
		f->fp = stdout;
	}
	else {
		de_msg(c, "Writing %s", f->name);
		f->btype = DBUF_TYPE_OFILE;
		f->fp = de_fopen_for_write(c, f->name, msgbuf, sizeof(msgbuf));

		if(!f->fp) {
			de_err(c, "Failed to write %s: %s", f->name, msgbuf);
			f->btype = DBUF_TYPE_NULL;
		}
	}

	return f;
}

dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize, unsigned int flags)
{
	dbuf *f;
	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->btype = DBUF_TYPE_MEMBUF;

	if(initialsize>0) {
		f->membuf_buf = de_malloc(c, initialsize);
		f->membuf_alloc = initialsize;
	}

	if(flags&0x01) {
		dbuf_set_max_length(f, initialsize);
	}

	return f;
}

static void membuf_append(dbuf *f, const de_byte *m, de_int64 mlen)
{
	de_int64 new_alloc_size;

	if(f->has_max_len) {
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
		de_dbg3(f->c, "increasing membuf size %d -> %d", (int)f->membuf_alloc, (int)new_alloc_size);
		f->membuf_buf = de_realloc(f->c, f->membuf_buf, f->membuf_alloc, new_alloc_size);
		f->membuf_alloc = new_alloc_size;
	}

	de_memcpy(&f->membuf_buf[f->len], m, (size_t)mlen);
	f->len += mlen;
}

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len)
{
	if(f->writecallback_fn) {
		f->writecallback_fn(f, m, len);
	}

	if(f->btype==DBUF_TYPE_NULL) {
		f->len += len;
		return;
	}
	else if(f->btype==DBUF_TYPE_OFILE || f->btype==DBUF_TYPE_STDOUT) {
		if(!f->fp) return;
		if(f->c->debug_level>=3) {
			de_dbg3(f->c, "writing %d bytes to %s", (int)len, f->name);
		}
		fwrite(m, 1, (size_t)len, f->fp);
		f->len += len;
		return;
	}
	else if(f->btype==DBUF_TYPE_MEMBUF) {
		if(f->c->debug_level>=3 && f->name) {
			de_dbg3(f->c, "appending %d bytes to membuf %s", (int)len, f->name);
		}
		membuf_append(f, m, len);
		return;
	}

	de_err(f->c, "Internal: Invalid output file type (%d)", f->btype);
}

void dbuf_writebyte(dbuf *f, de_byte n)
{
	dbuf_write(f, &n, 1);
}

void dbuf_writebyte_at(dbuf *f, de_int64 pos, de_byte n)
{
	if(f->btype!=DBUF_TYPE_MEMBUF) return;
	if(pos<0) return;
	if(f->has_max_len && pos>=f->max_len) return;

	if(pos>=f->len) {
		dbuf_write_zeroes(f, pos + 1 - f->len);
	}
	if(pos>=f->len) return; // Shouldn't happen
	f->membuf_buf[pos] = n;
}

void dbuf_write_at(dbuf *f, de_int64 pos, const de_byte *m, de_int64 len)
{
	de_int64 i;

	if(f->btype!=DBUF_TYPE_MEMBUF) return;
	// TODO: Make this more efficient
	for(i=0; i<len; i++) {
		dbuf_writebyte_at(f, pos+i, m[i]);
	}
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

void de_writeui16be_direct(de_byte *m, de_int64 n)
{
	m[0] = (de_byte)((n & 0xff00)>>8);
	m[1] = (de_byte)(n & 0x00ff);
}

void dbuf_writeui16le(dbuf *f, de_int64 n)
{
	de_byte buf[2];
	de_writeui16le_direct(buf, n);
	dbuf_write(f, buf, 2);
}

void dbuf_writeui16be(dbuf *f, de_int64 n)
{
	de_byte buf[2];
	de_writeui16be_direct(buf, n);
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

void dbuf_puts(dbuf *f, const char *sz)
{
	dbuf_write(f, (const de_byte*)sz, (de_int64)de_strlen(sz));
}

// TODO: Remove the buffer size limitation?
void dbuf_printf(dbuf *f, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	dbuf_puts(f, buf);
}

dbuf *dbuf_open_input_file(deark *c, const char *fn)
{
	dbuf *f;
	unsigned int returned_flags = 0;
	char msgbuf[200];

	if(!fn) return NULL;
	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_IFILE;
	f->c = c;
	f->cache_policy = DE_CACHE_POLICY_ENABLED;

	f->fp = de_fopen_for_read(c, fn, &f->len, msgbuf, sizeof(msgbuf), &returned_flags);

	if(!f->fp) {
		de_err(c, "Can't read %s: %s", fn, msgbuf);
		de_free(c, f);
		return NULL;
	}

	if(returned_flags & 0x1) {
		// This "file" is actually a pipe.
		f->btype = DBUF_TYPE_FIFO;
		f->cache_policy = DE_CACHE_POLICY_NONE;
		populate_cache_from_pipe(f);
	}

	return f;
}

dbuf *dbuf_open_input_stdin(deark *c)
{
	dbuf *f;

	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_STDIN;
	f->c = c;

	// Set to NONE, to make sure we don't try to auto-populate the cache later.
	f->cache_policy = DE_CACHE_POLICY_NONE;

	populate_cache_from_pipe(f);

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

	if(f->btype==DBUF_TYPE_MEMBUF && f->write_memfile_to_zip_archive) {
		de_zip_add_file_to_archive(c, f);
		if(f->name) {
			de_dbg3(c, "closing memfile %s", f->name);
		}
	}

	if(f->btype==DBUF_TYPE_IFILE || f->btype==DBUF_TYPE_OFILE) {
		if(f->name) {
			de_dbg3(c, "closing file %s", f->name);
		}
		de_fclose(f->fp);
		f->fp = NULL;

		if(f->btype==DBUF_TYPE_OFILE) {
			de_update_file_perms(f);
		}

		if(f->btype==DBUF_TYPE_OFILE && c->preserve_file_times) {
			de_update_file_time(f);
		}
	}
	else if(f->btype==DBUF_TYPE_FIFO) {
		de_fclose(f->fp);
		f->fp = NULL;
	}
	else if(f->btype==DBUF_TYPE_STDOUT) {
		if(f->name) {
			de_dbg3(c, "finished writing %s to stdout", f->name);
		}
		f->fp = NULL;
	}
	else if(f->btype==DBUF_TYPE_MEMBUF) {
	}
	else if(f->btype==DBUF_TYPE_DBUF) {
	}
	else if(f->btype==DBUF_TYPE_STDIN) {
	}
	else if(f->btype==DBUF_TYPE_NULL) {
	}
	else {
		de_err(c, "Internal: Don't know how to close this type of file (%d)", f->btype);
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

// Search for the aligned pair of 0x00 bytes that marks the end of a UTF-16 string.
// Endianness doesn't matter, because we're only looking for 0x00 0x00.
// The returned 'bytes_consumed' is in bytes, and includes the 2 bytes for the NUL
// terminator.
// Returns 0 if the NUL is not found, in which case *bytes_consumed is not
// meaningful.
int dbuf_get_utf16_NULterm_len(dbuf *f, de_int64 pos1, de_int64 bytes_avail,
	de_int64 *bytes_consumed)
{
	de_int64 x;
	de_int64 pos = pos1;

	*bytes_consumed = bytes_avail;
	while(1) {
		if(pos1+bytes_avail-pos < 2) {
			break;
		}
		x = dbuf_getui16le(f, pos);
		pos += 2;
		if(x==0) {
			*bytes_consumed = pos - pos1;
			return 1;
		}
	}
	return 0;
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
	f->has_max_len = 1;
	f->max_len = max_len;
}

int dbuf_has_utf8_bom(dbuf *f, de_int64 pos)
{
	return !dbuf_memcmp(f, pos, "\xef\xbb\xbf", 3);
}

// Write the contents of a dbuf to a file.
// This function intended for use in development/debugging.
int dbuf_dump_to_file(dbuf *inf, const char *fn)
{
	FILE *fp;
	char msgbuf[200];
	dbuf *tmpdbuf = NULL;
	deark *c = inf->c;

	fp = de_fopen_for_write(c, fn, msgbuf, sizeof(msgbuf));
	if(!fp) return 0;

	tmpdbuf = dbuf_create_membuf(c, inf->len, 1);
	dbuf_copy(inf, 0, inf->len, tmpdbuf);

	fwrite(tmpdbuf->membuf_buf, 1, (size_t)tmpdbuf->len, fp);
	de_fclose(fp);

	dbuf_close(tmpdbuf);
	return 1;
}

static void reverse_fourcc(de_byte *buf)
{
	de_byte tmpc;
	tmpc=buf[0]; buf[0]=buf[3]; buf[3]=tmpc;
	tmpc=buf[1]; buf[1]=buf[2]; buf[2]=tmpc;
}

void dbuf_read_fourcc(dbuf *f, de_int64 pos, struct de_fourcc *fcc, int is_reversed)
{
	dbuf_read(f, fcc->bytes, pos, 4);
	if(is_reversed) {
		reverse_fourcc(fcc->bytes);
	}
	fcc->id = (de_uint32)de_getui32be_direct(fcc->bytes);
	de_bytes_to_printable_sz(fcc->bytes, 4,
		fcc->id_printable, sizeof(fcc->id_printable),
		0, DE_ENCODING_ASCII);
}
