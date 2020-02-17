// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-dbuf.c
//
// Functions related to the dbuf object.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

#define DE_DUMMY_MAX_FILE_SIZE (1LL<<56)
#define DE_MAX_MEMBUF_SIZE 2000000000
#define DE_CACHE_SIZE 262144

// Fill the cache that remembers the first part of the file.
// TODO: We should probably use memory-mapped files instead when possible,
// but this is simple and portable, and does most of what we need.
static void populate_cache(dbuf *f)
{
	i64 bytes_to_read;
	i64 bytes_read;

	if(f->btype!=DBUF_TYPE_IFILE) return;

	bytes_to_read = DE_CACHE_SIZE;
	if(f->len < bytes_to_read) {
		bytes_to_read = f->len;
	}

	f->cache = de_malloc(f->c, DE_CACHE_SIZE);
	de_fseek(f->fp, 0, SEEK_SET);
	bytes_read = fread(f->cache, 1, (size_t)bytes_to_read, f->fp);
	f->cache_start_pos = 0;
	f->cache_bytes_used = bytes_read;
	f->file_pos_known = 0;
}

// Read all data from stdin (or a named pipe) into memory.
static void populate_cache_from_pipe(dbuf *f)
{
	FILE *fp;
	i64 cache_bytes_alloc = 0;

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
		i64 bytes_to_read, bytes_read;

		if(f->cache_bytes_used >= cache_bytes_alloc) {
			i64 old_cache_size, new_cache_size;

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
void dbuf_read(dbuf *f, u8 *buf, i64 pos, i64 len)
{
	i64 bytes_read = 0;
	i64 bytes_to_read;
	deark *c;

	c = f->c;

	if(pos < 0) {
		if((-pos) >= len) {
			// All requested bytes are before the beginning of the file
			de_zeromem(buf, (size_t)len);
			return;
		}
		// Some requested bytes are before the beginning of the file.
		// Zero out the ones that are:
		de_zeromem(buf, (size_t)(-pos));
		// And adjust the parameters:
		buf += (-pos);
		len -= (-pos);
		pos = 0;
	}

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
		pos + bytes_to_read <= f->cache_start_pos + f->cache_bytes_used)
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
			goto done_read;
		}

		// For performance reasons, don't call fseek if we're already at the
		// right position.
		if(!f->file_pos_known || f->file_pos!=pos) {
			de_fseek(f->fp, pos, SEEK_SET);
		}

		bytes_read = fread(buf, 1, (size_t)bytes_to_read, f->fp);

		f->file_pos = pos + bytes_read;
		f->file_pos_known = 1;
		break;

	case DBUF_TYPE_IDBUF:
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
		goto done_read;
	}

done_read:
	// Zero out any requested bytes that were not read.
	if(bytes_read < len) {
		de_zeromem(buf+bytes_read, (size_t)(len - bytes_read));
	}
}

// A function that works a little more like a standard read/fread function than
// does dbuf_read. It returns the number of bytes read, won't read past end of
// file, and helps track the file position.
i64 dbuf_standard_read(dbuf *f, u8 *buf, i64 n, i64 *fpos)
{
	i64 amt_to_read;

	if(*fpos < 0 || *fpos >= f->len) return 0;

	amt_to_read = n;
	if(*fpos + amt_to_read > f->len) amt_to_read = f->len - *fpos;
	dbuf_read(f, buf, *fpos, amt_to_read);
	*fpos += amt_to_read;
	return amt_to_read;
}

u8 dbuf_getbyte(dbuf *f, i64 pos)
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

i64 de_geti8_direct(const u8 *m)
{
	u8 b = m[0];

	if(b<=127) return (i64)b;
	return ((i64)b)-256;
}

i64 dbuf_geti8(dbuf *f, i64 pos)
{
	u8 b;

	b = dbuf_getbyte(f, pos);
	return de_geti8_direct(&b);
}

u8 dbuf_getbyte_p(dbuf *f, i64 *ppos)
{
	u8 b;
	b = dbuf_getbyte(f, *ppos);
	(*ppos)++;
	return b;
}

static i64 dbuf_getuint_ext_be_direct(const u8 *m, unsigned int nbytes)
{
	unsigned int k;
	u64 val = 0;

	for(k=0; k<nbytes; k++) {
		if(val>0x00ffffffffffffffULL) return 0;
		val = (val<<8) | (u64)m[k];
	}
	return (i64)val;
}

static i64 dbuf_getint_ext_be_direct(const u8 *m, unsigned int nbytes)
{
	unsigned int k;
	u64 val = 0;

	// We can handle up to 8 arbitrary bytes. Any more have to be 0xff.
	if(nbytes>8) {
		for(k=0; k<nbytes-8; k++) {
			if(m[k]!=0xff) return 0; // underflow
		}
	}

	// Process bytes in order of increasing significance
	for(k=0; k<8; k++) {
		u8 byteval;

		if(k<nbytes) {
			byteval = m[nbytes-1-k];
		}
		else {
			byteval = 0xff;
		}
		val |= ((u64)byteval) << (k*8);
	}
	return (i64)val;
}

static i64 dbuf_getuint_ext_le_direct(const u8 *m, unsigned int nbytes)
{
	unsigned int k;
	u64 val = 0;

	for(k=0; k<nbytes; k++) {
		if(m[k]!=0) {
			if(k>7) return 0;
			val |= ((u64)m[k])<<(k*8);
		}
	}
	return (i64)val;
}

static i64 dbuf_getuint_ext_x(dbuf *f, i64 pos, unsigned int nbytes,
	int is_le)
{
	u8 m[24];

	if(nbytes>(unsigned int)sizeof(m)) return 0;
	dbuf_read(f, m, pos, (i64)nbytes);
	if(is_le) {
		return dbuf_getuint_ext_le_direct(m, nbytes);
	}
	return dbuf_getuint_ext_be_direct(m, nbytes);
}

static i64 dbuf_getint_ext_x(dbuf *f, i64 pos, unsigned int nbytes, int is_le)
{
	u8 m[24];

	if(nbytes>(unsigned int)sizeof(m)) return 0;
	dbuf_read(f, m, pos, (i64)nbytes);
	if(is_le) {
		return 0; // TODO
	}
	return dbuf_getint_ext_be_direct(m, nbytes);
}

i64 de_getu16be_direct(const u8 *m)
{
	return (i64)(((u32)m[1]) | (((u32)m[0])<<8));
}

i64 dbuf_getu16be(dbuf *f, i64 pos)
{
	u8 m[2];
	dbuf_read(f, m, pos, 2);
	return de_getu16be_direct(m);
}

i64 dbuf_getu16be_p(dbuf *f, i64 *ppos)
{
	u8 m[2];
	dbuf_read(f, m, *ppos, 2);
	(*ppos) += 2;
	return de_getu16be_direct(m);
}

i64 de_getu16le_direct(const u8 *m)
{
	return (i64)(((u32)m[0]) | (((u32)m[1])<<8));
}

i64 dbuf_getu16le(dbuf *f, i64 pos)
{
	u8 m[2];
	dbuf_read(f, m, pos, 2);
	return de_getu16le_direct(m);
}

i64 dbuf_getu16le_p(dbuf *f, i64 *ppos)
{
	u8 m[2];
	dbuf_read(f, m, *ppos, 2);
	(*ppos) += 2;
	return de_getu16le_direct(m);
}

i64 dbuf_geti16be(dbuf *f, i64 pos)
{
	i64 n;
	n = dbuf_getu16be(f, pos);
	if(n>=32768) n -= 65536;
	return n;
}

i64 dbuf_geti16le(dbuf *f, i64 pos)
{
	i64 n;
	n = dbuf_getu16le(f, pos);
	if(n>=32768) n -= 65536;
	return n;
}

i64 dbuf_geti16be_p(dbuf *f, i64 *ppos)
{
	i64 n;
	n = dbuf_geti16be(f, *ppos);
	(*ppos) += 2;
	return n;
}

i64 dbuf_geti16le_p(dbuf *f, i64 *ppos)
{
	i64 n;
	n = dbuf_geti16le(f, *ppos);
	(*ppos) += 2;
	return n;
}

i64 de_getu32be_direct(const u8 *m)
{
	return (i64)(((u32)m[3]) | (((u32)m[2])<<8) |
		(((u32)m[1])<<16) | (((u32)m[0])<<24));
}

i64 dbuf_getu32be(dbuf *f, i64 pos)
{
	u8 m[4];
	dbuf_read(f, m, pos, 4);
	return de_getu32be_direct(m);
}

i64 dbuf_getu32be_p(dbuf *f, i64 *ppos)
{
	u8 m[4];
	dbuf_read(f, m, *ppos, 4);
	(*ppos) += 4;
	return de_getu32be_direct(m);
}

i64 de_getu32le_direct(const u8 *m)
{
	return (i64)(((u32)m[0]) | (((u32)m[1])<<8) |
		(((u32)m[2])<<16) | (((u32)m[3])<<24));
}

i64 dbuf_getu32le(dbuf *f, i64 pos)
{
	u8 m[4];
	dbuf_read(f, m, pos, 4);
	return de_getu32le_direct(m);
}

i64 dbuf_getu32le_p(dbuf *f, i64 *ppos)
{
	u8 m[4];
	dbuf_read(f, m, *ppos, 4);
	(*ppos) += 4;
	return de_getu32le_direct(m);
}

i64 dbuf_geti32be(dbuf *f, i64 pos)
{
	i64 n;
	n = dbuf_getu32be(f, pos);
	return (i64)(i32)(u32)n;
}

i64 dbuf_geti32le(dbuf *f, i64 pos)
{
	i64 n;
	n = dbuf_getu32le(f, pos);
	return (i64)(i32)(u32)n;
}

i64 dbuf_geti32be_p(dbuf *f, i64 *ppos)
{
	i64 n;
	n = dbuf_geti32be(f, *ppos);
	(*ppos) += 4;
	return n;
}

i64 dbuf_geti32le_p(dbuf *f, i64 *ppos)
{
	i64 n;
	n = dbuf_geti32le(f, *ppos);
	(*ppos) += 4;
	return n;
}

u64 de_getu64be_direct(const u8 *m)
{
	unsigned int i;
	u64 val = 0;

	for(i=0; i<8; i++) {
		val |= ((u64)m[i])<<((7-i)*8);
	}
	return val;
}

i64 de_geti64be_direct(const u8 *m)
{
	return (i64)de_getu64be_direct(m);
}

i64 dbuf_geti64be(dbuf *f, i64 pos)
{
	u8 m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64be_direct(m);
}

u64 de_getu64le_direct(const u8 *m)
{
	unsigned int i;
	u64 val = 0;

	for(i=0; i<8; i++) {
		val |= ((u64)m[i])<<(i*8);
	}
	return val;
}

i64 de_geti64le_direct(const u8 *m)
{
	return (i64)de_getu64le_direct(m);
}

i64 dbuf_geti64le(dbuf *f, i64 pos)
{
	u8 m[8];
	dbuf_read(f, m, pos, 8);
	return de_geti64le_direct(m);
}

i64 dbuf_getu16x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_getu16le(f, pos);
	return dbuf_getu16be(f, pos);
}

i64 dbuf_geti16x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_geti16le(f, pos);
	return dbuf_geti16be(f, pos);
}

i64 dbuf_getu32x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_getu32le(f, pos);
	return dbuf_getu32be(f, pos);
}

i64 dbuf_geti32x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_geti32le(f, pos);
	return dbuf_geti32be(f, pos);
}

i64 dbuf_geti64x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_geti64le(f, pos);
	return dbuf_geti64be(f, pos);
}

u64 dbuf_getu64be(dbuf *f, i64 pos)
{
	u8 m[8];
	dbuf_read(f, m, pos, 8);
	return de_getu64be_direct(m);
}

u64 dbuf_getu64le(dbuf *f, i64 pos)
{
	u8 m[8];
	dbuf_read(f, m, pos, 8);
	return de_getu64le_direct(m);
}

u64 dbuf_getu64x(dbuf *f, i64 pos, int is_le)
{
	if(is_le) return dbuf_getu64le(f, pos);
	return dbuf_getu64be(f, pos);
}

i64 dbuf_getint_ext(dbuf *f, i64 pos, unsigned int nbytes,
	int is_le, int is_signed)
{
	if(is_signed) {
		// TODO: Extend this to any number of bytes, 1-8.
		switch(nbytes) {
		case 1: return (i64)(signed char)dbuf_getbyte(f, pos); break;
		case 2: return dbuf_geti16x(f, pos, is_le); break;
		case 4: return dbuf_geti32x(f, pos, is_le); break;
		case 8: return dbuf_geti64x(f, pos, is_le); break;
		default:
			return dbuf_getint_ext_x(f, pos, nbytes, is_le);
		}
	}
	else {
		switch(nbytes) {
		case 1: return (i64)dbuf_getbyte(f, pos); break;
		case 2: return dbuf_getu16x(f, pos, is_le); break;
		case 4: return dbuf_getu32x(f, pos, is_le); break;
		case 8: return dbuf_geti64x(f, pos, is_le); break;
		default:
			return dbuf_getuint_ext_x(f, pos, nbytes, is_le);
		}
	}
	return 0;
}

static void init_fltpt_decoder(deark *c)
{
	unsigned int x = 1;
	char b = 0;

	c->can_decode_fltpt = 0;
	if(sizeof(float)!=4) return;
	if(sizeof(double)!=8) return;
	c->can_decode_fltpt = 1;

	de_memcpy(&b, &x, 1);
	if(b==0)
		c->host_is_le = 0;
	else
		c->host_is_le = 1;
}

double de_getfloat32x_direct(deark *c, const u8 *m, int is_le)
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

double dbuf_getfloat32x(dbuf *f, i64 pos, int is_le)
{
	u8 buf[4];
	dbuf_read(f, buf, pos, 4);
	return de_getfloat32x_direct(f->c, buf, is_le);
}

double de_getfloat64x_direct(deark *c, const u8 *m, int is_le)
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

double dbuf_getfloat64x(dbuf *f, i64 pos, int is_le)
{
	u8 buf[8];
	dbuf_read(f, buf, pos, 8);
	return de_getfloat64x_direct(f->c, buf, is_le);
}

int dbuf_read_ascii_number(dbuf *f, i64 pos, i64 fieldsize,
	int base, i64 *value)
{
	char buf[32];

	*value = 0;
	if(fieldsize>(i64)(sizeof(buf)-1)) return 0;

	dbuf_read(f, (u8*)buf, pos, fieldsize);
	buf[fieldsize] = '\0';

	*value = de_strtoll(buf, NULL, base);
	return 1;
}

u32 dbuf_getRGB(dbuf *f, i64 pos, unsigned int flags)
{
	u8 buf[3];
	dbuf_read(f, buf, pos, 3);
	if(flags&DE_GETRGBFLAG_BGR)
		return DE_MAKE_RGB(buf[2], buf[1], buf[0]);
	return DE_MAKE_RGB(buf[0], buf[1], buf[2]);
}

static int copy_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	dbuf *outf = (dbuf*)brctx->userdata;
	dbuf_write(outf, buf, buf_len);
	return 1;
}

void dbuf_copy(dbuf *inf, i64 input_offset, i64 input_len, dbuf *outf)
{
	u8 tmpbuf[256];

	if(inf->btype==DBUF_TYPE_MEMBUF &&
		(input_offset>=0) && (input_offset+input_len<=inf->len))
	{
		// Fast path if the data to copy is all in memory
		dbuf_write(outf, &inf->membuf_buf[input_offset], input_len);
		return;
	}

	if(input_len<=(i64)sizeof(tmpbuf)) {
		// Fast path for small sizes
		dbuf_read(inf, tmpbuf, input_offset, input_len);
		dbuf_write(outf, tmpbuf, input_len);
		return;
	}

	dbuf_buffered_read(inf, input_offset, input_len, copy_cbfn, (void*)outf);
}

struct copy_at_ctx {
	dbuf *outf;
	i64 outpos;
};

static int copy_at_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct copy_at_ctx *ctx = (struct copy_at_ctx*)brctx->userdata;

	dbuf_write_at(ctx->outf, ctx->outpos, buf, buf_len);
	ctx->outpos += buf_len;
	return 1;
}

void dbuf_copy_at(dbuf *inf, i64 input_offset, i64 input_len,
	dbuf *outf, i64 output_offset)
{
	struct copy_at_ctx ctx;

	ctx.outf = outf;
	ctx.outpos = output_offset;
	dbuf_buffered_read(inf, input_offset, input_len, copy_at_cbfn, (void*)&ctx);
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
// ->sz_strlen will equal strlen(->sz) if DE_CONVFLAG_STOP_AT_NUL is set, or
// the supplied value of max_bytes_to_(scan|keep) if not.
// Recognized flags:
//   - DE_CONVFLAG_STOP_AT_NUL
//   - DE_CONVFLAG_WANT_UTF8
struct de_stringreaderdata *dbuf_read_string(dbuf *f, i64 pos,
	i64 max_bytes_to_scan,
	i64 max_bytes_to_keep,
	unsigned int flags, de_encoding encoding)
{
	deark *c = f->c;
	struct de_stringreaderdata *srd;
	i64 foundpos = 0;
	int ret;
	i64 bytes_avail_to_read;
	i64 bytes_to_malloc;
	i64 x_strlen = 0;

	srd = de_malloc(c, sizeof(struct de_stringreaderdata));
	srd->str = ucstring_create(c);
	if(max_bytes_to_scan<0) max_bytes_to_scan = 0;
	if(max_bytes_to_keep<0) max_bytes_to_keep = 0;

	bytes_avail_to_read = max_bytes_to_scan;
	if(bytes_avail_to_read > f->len-pos) {
		bytes_avail_to_read = f->len-pos;
	}
	if(bytes_avail_to_read<0) bytes_avail_to_read = 0;

	srd->bytes_consumed = bytes_avail_to_read; // default

	// From here on, we can safely bail out ("goto done"). The
	// de_stringreaderdata struct is sufficiently valid.

	if(!(flags&DE_CONVFLAG_STOP_AT_NUL) &&
		(max_bytes_to_scan != max_bytes_to_keep))
	{
		// To reduce possible confusion, we require that
		// max_bytes_to_scan==max_bytes_to_keep in this case.
		srd->sz = de_malloc(c, max_bytes_to_keep+1);
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
	dbuf_read(f, (u8*)srd->sz, pos, bytes_to_malloc-1); // The last byte remains NUL

	ucstring_append_bytes(srd->str, (const u8*)srd->sz, bytes_to_malloc-1, 0, encoding);

	if(flags&DE_CONVFLAG_WANT_UTF8) {
		srd->sz_utf8_strlen = (size_t)ucstring_count_utf8_bytes(srd->str);
		srd->sz_utf8 = de_malloc(c, (i64)srd->sz_utf8_strlen + 1);
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
	srd->sz_strlen = (size_t)x_strlen;
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
void dbuf_read_to_ucstring(dbuf *f, i64 pos, i64 len,
	de_ucstring *s, unsigned int conv_flags, de_encoding encoding)
{
	u8 *buf = NULL;
	deark *c = f->c;

	if(conv_flags & DE_CONVFLAG_STOP_AT_NUL) {
		i64 foundpos = 0;
		if(dbuf_search_byte(f, 0x00, pos, len, &foundpos)) {
			len = foundpos - pos;
		}
	}

	buf = de_malloc(c, len);
	dbuf_read(f, buf, pos, len);
	ucstring_append_bytes(s, buf, len, 0, encoding);
	de_free(c, buf);
}

void dbuf_read_to_ucstring_n(dbuf *f, i64 pos, i64 len, i64 max_len,
	de_ucstring *s, unsigned int conv_flags, de_encoding encoding)
{
	if(len>max_len) len=max_len;
	dbuf_read_to_ucstring(f, pos, len, s, conv_flags, encoding);
}

static int dbufmemcmp_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	// Return 0 if there is a mismatch.
	return !de_memcmp(buf,
		&(((const u8*)brctx->userdata)[brctx->offset]),
		(size_t)buf_len);
}

int dbuf_memcmp(dbuf *f, i64 pos, const void *s, size_t n)
{
	u8 buf1[128];

	if(f->cache &&
		pos >= f->cache_start_pos &&
		pos + (i64)n <= f->cache_start_pos + f->cache_bytes_used)
	{
		// Fastest path: Compare directly to cache.
		return de_memcmp(s, &f->cache[pos - f->cache_start_pos], n);
	}

	if(n<=sizeof(buf1)) {
		// Use a stack buffer if small enough.
		dbuf_read(f, buf1, pos, n);
		return de_memcmp(buf1, s, n);
	}

	// Fallback method.
	return !dbuf_buffered_read(f, pos, n, dbufmemcmp_cbfn, (void*)s);
}

int dbuf_create_file_from_slice(dbuf *inf, i64 pos, i64 data_size,
	const char *ext, de_finfo *fi, unsigned int createflags)
{
	dbuf *f;
	f = dbuf_create_output_file(inf->c, ext, fi, createflags);
	if(!f) return 0;
	dbuf_copy(inf, pos, data_size, f);
	dbuf_close(f);
	return 1;
}

static void finfo_shallow_copy(deark *c, de_finfo *src, de_finfo *dst)
{
	dst->is_directory = src->is_directory;
	dst->mode_flags = src->mode_flags;
	dst->mod_time = src->mod_time;
	dst->image_mod_time = src->image_mod_time;
	dst->density = src->density;
	dst->has_hotspot = src->has_hotspot;
	dst->hotspot_x = src->hotspot_x;
	dst->hotspot_y = src->hotspot_y;
}

// Create or open a file for writing, that is *not* one of the usual
// "output.000.ext" files we extract from the input file.
//
// overwrite_mode, flags: Same as for de_fopen_for_write().
//
// On failure, prints an error message, and sets f->btype to DBUF_TYPE_NULL.
dbuf *dbuf_create_unmanaged_file(deark *c, const char *fname, int overwrite_mode,
	unsigned int flags)
{
	dbuf *f;
	char msgbuf[200];

	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->is_managed = 0;
	f->name = de_strdup(c, fname);

	f->btype = DBUF_TYPE_OFILE;
	f->max_len_hard = c->max_output_file_size;
	f->fp = de_fopen_for_write(c, f->name, msgbuf, sizeof(msgbuf),
		c->overwrite_mode, flags);

	if(!f->fp) {
		de_err(c, "Failed to write %s: %s", f->name, msgbuf);
		f->btype = DBUF_TYPE_NULL;
		c->serious_error_flag = 1;
	}

	return f;
}

dbuf *dbuf_create_unmanaged_file_stdout(deark *c, const char *name)
{
	dbuf *f;

	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->is_managed = 0;
	f->name = de_strdup(c, name);
	f->btype = DBUF_TYPE_STDOUT;
	f->max_len_hard = c->max_output_file_size;
	f->fp = stdout;
	return f;
}

static void sanitize_ext(const char *ext1, char *ext, size_t extlen)
{
	size_t k;

	de_strlcpy(ext, ext1, extlen);
	// This part of the filename should come from Deark, and should only
	// use a limited set of characters. Just to be sure:
	for(k=0; ext[k]; k++) {
		if((ext[k]>='0' && ext[k]<='9') ||
			(ext[k]>='A' && ext[k]<='Z') ||
			(ext[k]>='a' && ext[k]<='z') ||
			ext[k]=='.' || ext[k]=='_' || ext[k]=='-' || ext[k]=='+')
		{
			;
		}
		else {
			ext[k] = '_';
		}
	}
}

dbuf *dbuf_create_output_file(deark *c, const char *ext1, de_finfo *fi,
	unsigned int createflags)
{
	char nbuf[500];
	char msgbuf[200];
	char ext[128];
	int have_ext;
	dbuf *f;
	const char *basefn;
	int file_index;
	u8 is_directory = 0;
	char *name_from_finfo = NULL;
	i64 name_from_finfo_len = 0;

	if(ext1) {
		have_ext = 1;
		sanitize_ext(ext1, ext, sizeof(ext));
	}
	else {
		have_ext = 0;
		ext[0] = '\0';
	}

	if(have_ext && fi && fi->original_filename_flag) {
		de_dbg(c, "[internal warning: Incorrect use of create_output_file]");
	}

	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->max_len_hard = c->max_output_file_size;
	f->is_managed = 1;

	if(fi && fi->is_directory) {
		is_directory = 1;
	}

	if(is_directory && !c->keep_dir_entries) {
		de_dbg(c, "skipping 'directory' file");
		f->btype = DBUF_TYPE_NULL;
		goto done;
	}

	if(c->extract_policy==DE_EXTRACTPOLICY_MAINONLY) {
		if(createflags&DE_CREATEFLAG_IS_AUX) {
			de_dbg(c, "skipping 'auxiliary' file");
			f->btype = DBUF_TYPE_NULL;
			goto done;
		}
	}
	else if(c->extract_policy==DE_EXTRACTPOLICY_AUXONLY) {
		if(!(createflags&DE_CREATEFLAG_IS_AUX)) {
			de_dbg(c, "skipping 'main' file");
			f->btype = DBUF_TYPE_NULL;
			goto done;
		}
	}

	file_index = c->file_count;
	c->file_count++;

	basefn = c->base_output_filename ? c->base_output_filename : "output";

	if(fi && ucstring_isnonempty(fi->file_name_internal)) {
		name_from_finfo_len = 1 + ucstring_count_utf8_bytes(fi->file_name_internal);
		name_from_finfo = de_malloc(c, name_from_finfo_len);
		ucstring_to_sz(fi->file_name_internal, name_from_finfo, (size_t)name_from_finfo_len, 0,
			DE_ENCODING_UTF8);
	}

	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE && !c->base_output_filename &&
		fi && fi->is_directory &&
		(fi->is_root_dir || (fi->detect_root_dot_dir && fi->orig_name_was_dot)))
	{
		de_strlcpy(nbuf, ".", sizeof(nbuf));
	}
	else if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE && !c->base_output_filename &&
		fi && fi->original_filename_flag && name_from_finfo)
	{
		// TODO: This is a "temporary" hack to allow us to, when both reading from
		// and writing to an archive format, use some semblance of the correct
		// filename (instead of "output.xxx.yyy").
		// There are some things that we don't handle optimally, such as
		// subdirectories.
		// A major redesign of the file naming logic would be good.
		de_strlcpy(nbuf, name_from_finfo, sizeof(nbuf));
	}
	else {
		char fn_suffix[256];

		if(have_ext && name_from_finfo) {
			de_snprintf(fn_suffix, sizeof(fn_suffix), "%s.%s", name_from_finfo, ext);
		}
		else if(have_ext) {
			de_strlcpy(fn_suffix, ext, sizeof(fn_suffix));
		}
		else if(is_directory && name_from_finfo) {
			de_snprintf(fn_suffix, sizeof(fn_suffix), "%s.dir", name_from_finfo);
		}
		else if(name_from_finfo) {
			de_strlcpy(fn_suffix, name_from_finfo, sizeof(fn_suffix));
		}
		else if(is_directory) {
			de_strlcpy(fn_suffix, "dir", sizeof(fn_suffix));
		}
		else {
			de_strlcpy(fn_suffix, "bin", sizeof(fn_suffix));
		}

		de_snprintf(nbuf, sizeof(nbuf), "%s.%03d.%s", basefn, file_index, fn_suffix);
	}

	f->name = de_strdup(c, nbuf);

	if(fi) {
		// The finfo object passed to us at file creation is not required to
		// remain valid, so make a copy of anything in it that we might need
		// later.
		f->fi_copy = de_finfo_create(c);
		finfo_shallow_copy(c, fi, f->fi_copy);

		// Here's where we respect the -intz option, by using it to convert to
		// UTC in some cases.
		if(f->fi_copy->mod_time.is_valid && f->fi_copy->mod_time.tzcode==DE_TZCODE_LOCAL &&
			c->input_tz_offs_seconds!=0)
		{
			de_timestamp_cvt_to_utc(&f->fi_copy->mod_time, -c->input_tz_offs_seconds);
		}

		if(f->fi_copy->image_mod_time.is_valid && f->fi_copy->image_mod_time.tzcode==DE_TZCODE_LOCAL &&
			c->input_tz_offs_seconds!=0)
		{
			de_timestamp_cvt_to_utc(&f->fi_copy->image_mod_time, -c->input_tz_offs_seconds);
		}
	}

	if(file_index < c->first_output_file) {
		f->btype = DBUF_TYPE_NULL;
		goto done;
	}

	if(c->max_output_files>=0 &&
		file_index >= c->first_output_file + c->max_output_files)
	{
		f->btype = DBUF_TYPE_NULL;
		goto done;
	}

	c->num_files_extracted++;

	if(c->extrlist_dbuf) {
		dbuf_printf(c->extrlist_dbuf, "%s\n", f->name);
		dbuf_flush(c->extrlist_dbuf);
	}

	if(c->list_mode) {
		f->btype = DBUF_TYPE_NULL;
		if(c->list_mode_include_file_id) {
			de_msg(c, "%d:%s", file_index, f->name);
		}
		else {
			de_msg(c, "%s", f->name);
		}
		goto done;
	}

	if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE && c->archive_fmt==DE_ARCHIVEFMT_TAR) {
		de_info(c, "Adding %s to TAR file", f->name);
		f->btype = DBUF_TYPE_ODBUF;
		// A dummy max_len_hard value. The parent will do the checking.
		f->max_len_hard = DE_DUMMY_MAX_FILE_SIZE;
		f->writing_to_tar_archive = 1;
		de_tar_start_member_file(c, f);
	}
	else if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE) { // ZIP
		i64 initial_alloc;
		de_info(c, "Adding %s to ZIP file", f->name);
		f->btype = DBUF_TYPE_MEMBUF;
		f->max_len_hard = DE_MAX_MEMBUF_SIZE;
		if(is_directory) {
			// A directory entry is not expected to have any data associated
			// with it (besides the files it contains).
			initial_alloc = 16;
		}
		else {
			initial_alloc = 65536;
		}
		f->membuf_buf = de_malloc(c, initial_alloc);
		f->membuf_alloc = initial_alloc;
		f->write_memfile_to_zip_archive = 1;
	}
	else if(c->output_style==DE_OUTPUTSTYLE_STDOUT) {
		de_info(c, "Writing %s to [stdout]", f->name);
		f->btype = DBUF_TYPE_STDOUT;
		// TODO: Should we increase f->max_len_hard?
		f->fp = stdout;
	}
	else {
		de_info(c, "Writing %s", f->name);
		f->btype = DBUF_TYPE_OFILE;
		f->fp = de_fopen_for_write(c, f->name, msgbuf, sizeof(msgbuf),
			c->overwrite_mode, 0);

		if(!f->fp) {
			de_err(c, "Failed to write %s: %s", f->name, msgbuf);
			f->btype = DBUF_TYPE_NULL;
			c->serious_error_flag = 1;
		}
	}

done:
	de_free(c, name_from_finfo);
	return f;
}

static void do_on_dbuf_size_exceeded(dbuf *f)
{
	de_err(f->c, "Maximum %s size of %"I64_FMT" bytes exceeded",
		(f->btype==DBUF_TYPE_MEMBUF)?"membuf":"output file",
		f->max_len_hard);
	de_fatalerror(f->c);
}

dbuf *dbuf_create_membuf(deark *c, i64 initialsize, unsigned int flags)
{
	dbuf *f;
	f = de_malloc(c, sizeof(dbuf));
	f->c = c;
	f->btype = DBUF_TYPE_MEMBUF;
	f->max_len_hard = DE_MAX_MEMBUF_SIZE;

	if(initialsize>0) {
		if(initialsize > f->max_len_hard) {
			do_on_dbuf_size_exceeded(f);
		}
		f->membuf_buf = de_malloc(c, initialsize);
		f->membuf_alloc = initialsize;
	}

	if(flags&0x01) {
		dbuf_set_length_limit(f, initialsize);
	}

	return f;
}

static void membuf_append(dbuf *f, const u8 *m, i64 mlen)
{
	i64 new_alloc_size;

	if(f->has_len_limit) {
		if(f->len + mlen > f->len_limit) {
			mlen = f->len_limit - f->len;
		}
	}

	if(mlen<=0) return;

	if(mlen > f->membuf_alloc - f->len) {
		// Need to allocate more space
		new_alloc_size = (f->membuf_alloc + mlen)*2;
		if(new_alloc_size<1024) new_alloc_size=1024;
		if(new_alloc_size > f->max_len_hard) new_alloc_size = f->max_len_hard;
		de_dbg3(f->c, "increasing membuf size %"I64_FMT" -> %"I64_FMT,
			f->membuf_alloc, new_alloc_size);
		if(f->len + mlen > f->max_len_hard) {
			do_on_dbuf_size_exceeded(f);
		}
		f->membuf_buf = de_realloc(f->c, f->membuf_buf, f->membuf_alloc, new_alloc_size);
		f->membuf_alloc = new_alloc_size;
	}

	de_memcpy(&f->membuf_buf[f->len], m, (size_t)mlen);
	f->len += mlen;
}

void dbuf_write(dbuf *f, const u8 *m, i64 len)
{
	if(f->len + len > f->max_len_hard) {
		do_on_dbuf_size_exceeded(f);
	}

	if(f->writelistener_cb) {
		// Note that the callback function can be changed at any time, so if we
		// ever decide to buffer these calls, precautions will be needed.
		f->writelistener_cb(f, f->userdata_for_writelistener, m, len);
	}

	switch(f->btype) {
	case DBUF_TYPE_OFILE:
	case DBUF_TYPE_STDOUT:
		if(!f->fp) return;
		if(f->c->debug_level>=3) {
			de_dbg3(f->c, "writing %"I64_FMT" bytes to %s", len, f->name);
		}
		fwrite(m, 1, (size_t)len, f->fp);
		f->len += len;
		return;
	case DBUF_TYPE_MEMBUF:
		if(f->c->debug_level>=3 && f->name) {
			de_dbg3(f->c, "appending %"I64_FMT" bytes to membuf %s", len, f->name);
		}
		membuf_append(f, m, len);
		return;
	case DBUF_TYPE_ODBUF:
		dbuf_write(f->parent_dbuf, m, len);
		f->len += len;
		return;
	case DBUF_TYPE_CUSTOM:
		if(f->customwrite_fn) {
			f->customwrite_fn(f, f->userdata_for_customwrite, m, len);
		}
		f->len += len;
		return;
	case DBUF_TYPE_NULL:
		f->len += len;
		return;
	}

	de_err(f->c, "Internal: Invalid output file type (%d)", f->btype);
	de_fatalerror(f->c);
}

void dbuf_writebyte(dbuf *f, u8 n)
{
	dbuf_write(f, &n, 1);
}

// Allowed only for membufs, and unmanaged output files.
// For unmanaged output files, must be used with care, and should not be
// mixed with dbuf_write().
void dbuf_write_at(dbuf *f, i64 pos, const u8 *m, i64 len)
{
	if(len<1 || pos<0) return;

	if(pos + len > f->max_len_hard) {
		do_on_dbuf_size_exceeded(f);
	}

	if(f->btype==DBUF_TYPE_MEMBUF) {
		i64 amt_overwrite, amt_newzeroes, amt_append;

		if(pos+len <= f->len) { // entirely within the current file
			amt_overwrite = len;
			amt_newzeroes = 0;
			amt_append = 0;
		}
		else if(pos >= f->len) { // starts after the end of the current file
			amt_overwrite = 0;
			amt_newzeroes = pos - f->len;
			amt_append = len;
		}
		else { // overlaps the end of the current file
			amt_overwrite = f->len - pos;
			amt_newzeroes = 0;
			amt_append = len - amt_overwrite;
		}

		if(amt_overwrite>0) {
			de_memcpy(&f->membuf_buf[pos], m, (size_t)amt_overwrite);
		}
		if(amt_newzeroes>0) {
			dbuf_write_zeroes(f, amt_newzeroes);

		}
		if(amt_append>0) {
			membuf_append(f, &m[amt_overwrite], amt_append);
		}
	}
	else if(f->btype==DBUF_TYPE_OFILE && !f->is_managed) {
		i64 curpos = de_ftell(f->fp);
		if(pos != curpos) {
			de_fseek(f->fp, pos, SEEK_SET);
		}
		fwrite(m, 1, (size_t)len, f->fp);
		if(pos+len > f->len) {
			f->len = pos+len;
		}
	}
	else if(f->btype==DBUF_TYPE_NULL) {
		if(pos+len > f->len) {
			f->len = pos+len;
		}
	}
	else {
		de_err(f->c, "internal: Attempt to seek on non-seekable stream");
		de_fatalerror(f->c);
	}
}

void dbuf_writebyte_at(dbuf *f, i64 pos, u8 n)
{
	if(f->btype==DBUF_TYPE_MEMBUF && pos>=0 && pos<f->len) {
		// Fast path when overwriting a byte in a membuf
		f->membuf_buf[pos] = n;
		return;
	}

	dbuf_write_at(f, pos, &n, 1);
}

void dbuf_write_run(dbuf *f, u8 n, i64 len)
{
	u8 buf[1024];
	i64 amt_left;
	i64 amt_to_write;

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

void dbuf_write_zeroes(dbuf *f, i64 len)
{
	dbuf_write_run(f, 0, len);
}

// Make the membuf have exactly len bytes of content.
void dbuf_truncate(dbuf *f, i64 desired_len)
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

void de_writeu16le_direct(u8 *m, i64 n)
{
	m[0] = (u8)(n & 0x00ff);
	m[1] = (u8)((n & 0xff00)>>8);
}

void de_writeu16be_direct(u8 *m, i64 n)
{
	m[0] = (u8)((n & 0xff00)>>8);
	m[1] = (u8)(n & 0x00ff);
}

void dbuf_writeu16le(dbuf *f, i64 n)
{
	u8 buf[2];
	de_writeu16le_direct(buf, n);
	dbuf_write(f, buf, 2);
}

void dbuf_writeu16be(dbuf *f, i64 n)
{
	u8 buf[2];
	de_writeu16be_direct(buf, n);
	dbuf_write(f, buf, 2);
}

void dbuf_writei16le(dbuf *f, i64 n)
{
	if(n<0) {
		dbuf_writeu16le(f, n+65536);
	}
	else {
		dbuf_writeu16le(f, n);
	}
}

void dbuf_writei16be(dbuf *f, i64 n)
{
	if(n<0) {
		dbuf_writeu16be(f, n+65536);
	}
	else {
		dbuf_writeu16be(f, n);
	}
}

void de_writeu32be_direct(u8 *m, i64 n)
{
	m[0] = (u8)((n & 0xff000000)>>24);
	m[1] = (u8)((n & 0x00ff0000)>>16);
	m[2] = (u8)((n & 0x0000ff00)>>8);
	m[3] = (u8)(n & 0x000000ff);
}

void dbuf_writeu32be(dbuf *f, i64 n)
{
	u8 buf[4];
	de_writeu32be_direct(buf, n);
	dbuf_write(f, buf, 4);
}

void de_writeu32le_direct(u8 *m, i64 n)
{
	m[0] = (u8)(n & 0x000000ff);
	m[1] = (u8)((n & 0x0000ff00)>>8);
	m[2] = (u8)((n & 0x00ff0000)>>16);
	m[3] = (u8)((n & 0xff000000)>>24);
}

void dbuf_writeu32le(dbuf *f, i64 n)
{
	u8 buf[4];
	de_writeu32le_direct(buf, n);
	dbuf_write(f, buf, 4);
}

void dbuf_writei32le(dbuf *f, i64 n)
{
	if(n<0) {
		dbuf_writeu32le(f, n+0x100000000LL);
	}
	else {
		dbuf_writeu32le(f, n);
	}}

void dbuf_writei32be(dbuf *f, i64 n)
{
	if(n<0) {
		dbuf_writeu32be(f, n+0x100000000LL);
	}
	else {
		dbuf_writeu32be(f, n);
	}
}

void de_writeu64le_direct(u8 *m, u64 n)
{
	de_writeu32le_direct(&m[0], (i64)(u32)(n&0xffffffffULL));
	de_writeu32le_direct(&m[4], (i64)(u32)(n>>32));
}

void dbuf_writeu64le(dbuf *f, u64 n)
{
	u8 buf[8];
	de_writeu64le_direct(buf, n);
	dbuf_write(f, buf, 8);
}

void dbuf_puts(dbuf *f, const char *sz)
{
	dbuf_write(f, (const u8*)sz, (i64)de_strlen(sz));
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

void dbuf_flush(dbuf *f)
{
	if(f->btype==DBUF_TYPE_OFILE) {
		fflush(f->fp);
	}
}

dbuf *dbuf_open_input_file(deark *c, const char *fn)
{
	dbuf *f;
	unsigned int returned_flags = 0;
	char msgbuf[200];

	if(!fn) {
		c->serious_error_flag = 1;
		return NULL;
	}
	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_IFILE;
	f->c = c;
	f->cache_policy = DE_CACHE_POLICY_ENABLED;

	f->fp = de_fopen_for_read(c, fn, &f->len, msgbuf, sizeof(msgbuf), &returned_flags);

	if(!f->fp) {
		de_err(c, "Can't read %s: %s", fn, msgbuf);
		de_free(c, f);
		c->serious_error_flag = 1;
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

dbuf *dbuf_open_input_subfile(dbuf *parent, i64 offset, i64 size)
{
	dbuf *f;
	deark *c;

	c = parent->c;
	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_IDBUF;
	f->c = c;
	f->parent_dbuf = parent;
	f->offset_into_parent_dbuf = offset;
	f->len = size;
	return f;
}

dbuf *dbuf_create_custom_dbuf(deark *c, i64 apparent_size, unsigned int flags)
{
	dbuf *f;

	f = de_malloc(c, sizeof(dbuf));
	f->btype = DBUF_TYPE_CUSTOM;
	f->c = c;
	f->len = apparent_size;
	f->max_len_hard = DE_DUMMY_MAX_FILE_SIZE;
	return f;
}

void dbuf_set_writelistener(dbuf *f, de_writelistener_cb_type fn, void *userdata)
{
	f->userdata_for_writelistener = userdata;
	f->writelistener_cb = fn;
}

void dbuf_close(dbuf *f)
{
	deark *c;
	if(!f) return;
	c = f->c;

	if(f->btype==DBUF_TYPE_OFILE || f->btype==DBUF_TYPE_STDOUT) {
		c->total_output_size += f->len;
	}

	if(f->btype==DBUF_TYPE_MEMBUF && f->write_memfile_to_zip_archive) {
		de_zip_add_file_to_archive(c, f);
		if(f->name) {
			de_dbg3(c, "closing memfile %s", f->name);
		}
	}
	else if(f->writing_to_tar_archive) {
		de_tar_end_member_file(c, f);
	}

	switch(f->btype) {
	case DBUF_TYPE_IFILE:
	case DBUF_TYPE_OFILE:
		if(f->name) {
			de_dbg3(c, "closing file %s", f->name);
		}
		de_fclose(f->fp);
		f->fp = NULL;

		if(f->btype==DBUF_TYPE_OFILE && f->is_managed) {
			de_update_file_perms(f);
		}

		if(f->btype==DBUF_TYPE_OFILE && f->is_managed && c->preserve_file_times) {
			de_update_file_time(f);
		}
		break;
	case DBUF_TYPE_FIFO:
		de_fclose(f->fp);
		f->fp = NULL;
		break;
	case DBUF_TYPE_STDOUT:
		if(f->name && f->is_managed) {
			de_dbg3(c, "finished writing %s to stdout", f->name);
		}
		else if(!f->is_managed) {
			de_dbg3(c, "finished writing %s", f->name);
		}
		f->fp = NULL;
		break;
	case DBUF_TYPE_MEMBUF:
	case DBUF_TYPE_IDBUF:
	case DBUF_TYPE_ODBUF:
	case DBUF_TYPE_STDIN:
	case DBUF_TYPE_CUSTOM:
	case DBUF_TYPE_NULL:
		break;
	default:
		de_err(c, "Internal: Don't know how to close this type of file (%d)", f->btype);
	}

	de_free(c, f->membuf_buf);
	de_free(c, f->name);
	de_free(c, f->cache);
	if(f->fi_copy) de_finfo_destroy(c, f->fi_copy);
	de_free(c, f);

	if(c->total_output_size > c->max_total_output_size) {
		// FIXME: Since we only do this check when a file is closed, it can
		// potentially be subverted in the (rare) case that Deark has multiple
		// output files open simultanously.
		de_err(c, "Maximum total output size of %"I64_FMT" bytes exceeded",
			c->max_total_output_size);
		de_fatalerror(c);
	}
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
int dbuf_search_byte(dbuf *f, const u8 b, i64 startpos,
	i64 haystack_len, i64 *foundpos)
{
	i64 i;

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
int dbuf_search(dbuf *f, const u8 *needle, i64 needle_len,
	i64 startpos, i64 haystack_len, i64 *foundpos)
{
	u8 *buf = NULL;
	int retval = 0;
	i64 i;

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
int dbuf_get_utf16_NULterm_len(dbuf *f, i64 pos1, i64 bytes_avail,
	i64 *bytes_consumed)
{
	i64 x;
	i64 pos = pos1;

	*bytes_consumed = bytes_avail;
	while(1) {
		if(pos1+bytes_avail-pos < 2) {
			break;
		}
		x = dbuf_getu16le(f, pos);
		pos += 2;
		if(x==0) {
			*bytes_consumed = pos - pos1;
			return 1;
		}
	}
	return 0;
}

int dbuf_find_line(dbuf *f, i64 pos1, i64 *pcontent_len, i64 *ptotal_len)
{
	u8 b0, b1;
	i64 pos;
	i64 eol_pos = 0;
	i64 eol_size = 0;

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

// Enforce a maximum size when writing to a dbuf.
// Attempting to write more than this is a silent no-op.
// May be valid only for memory buffers.
void dbuf_set_length_limit(dbuf *f, i64 max_len)
{
	f->has_len_limit = 1;
	f->len_limit = max_len;
}

int dbuf_has_utf8_bom(dbuf *f, i64 pos)
{
	return !dbuf_memcmp(f, pos, "\xef\xbb\xbf", 3);
}

// Write the contents of a dbuf to a file.
// This function intended for use in development/debugging.
int dbuf_dump_to_file(dbuf *inf, const char *fn)
{
	dbuf *outf;
	deark *c = inf->c;

	outf = dbuf_create_unmanaged_file(c, fn, DE_OVERWRITEMODE_STANDARD, 0);
	dbuf_copy(inf, 0, inf->len, outf);
	dbuf_close(outf);
	return 1;
}

static void reverse_fourcc(u8 *buf, int nbytes)
{
	size_t k;

	for(k=0; k<((size_t)nbytes)/2; k++) {
		u8 tmpc;
		tmpc = buf[k];
		buf[k] = buf[(size_t)nbytes-1-k];
		buf[(size_t)nbytes-1-k] = tmpc;
	}
}

// Though we call it a "fourcc", we support 'nbytes' from 1 to 4.
void dbuf_read_fourcc(dbuf *f, i64 pos, struct de_fourcc *fcc,
	int nbytes, unsigned int flags)
{
	if(nbytes<1 || nbytes>4) return;

	de_zeromem(fcc->bytes, 4);
	dbuf_read(f, fcc->bytes, pos, (i64)nbytes);
	if(flags&DE_4CCFLAG_REVERSED) {
		reverse_fourcc(fcc->bytes, nbytes);
	}

	fcc->id = (u32)de_getu32be_direct(fcc->bytes);
	if(nbytes<4) {
		fcc->id >>= (4-(unsigned int)nbytes)*8;
	}

	de_bytes_to_printable_sz(fcc->bytes, (i64)nbytes,
		fcc->id_sanitized_sz, sizeof(fcc->id_sanitized_sz),
		0, DE_ENCODING_ASCII);
	de_bytes_to_printable_sz(fcc->bytes, (i64)nbytes,
		fcc->id_dbgstr, sizeof(fcc->id_dbgstr),
		DE_CONVFLAG_ALLOW_HL, DE_ENCODING_ASCII);
}

// dbuf_buffered_read:
// Read a slice of a dbuf, and pass its data to a callback function, one
// segment at a time.
// cbfn: Caller-implemented callback function.
//   - It is required to consume at least 1 byte.
//   - If it does not consume all bytes, it must set brctx->bytes_consumed.
//   - It must return nonzero normally, 0 to abort.
// We guarantee that:
//   - brctx->eof_flag will be nonzero if and only if there is no data after this.
//   - At least 1 byte will be provided.
//   - If eof_flag is not set, at least 1024 bytes will be provided.
// Return value: 1 normally, 0 if the callback function ever returned 0.
static int buffered_read_internal(struct de_bufferedreadctx *brctx,
	dbuf *f, i64 pos1, i64 len, de_buffered_read_cbfn cbfn)
{
	int retval = 0;
	i64 pos = pos1; // Absolute pos of next byte to read from f
	i64 offs_of_first_byte_in_buf; // Relative to pos1, where in f is buf[0]?
	i64 num_unconsumed_bytes_in_buf;
#define BRBUFLEN 4096
	u8 buf[BRBUFLEN];

	num_unconsumed_bytes_in_buf = 0;
	offs_of_first_byte_in_buf = 0;

	while(1) {
		i64 nbytes_avail_to_read;
		i64 bytestoread;
		int ret;

		nbytes_avail_to_read = pos1+len-pos;
		if(nbytes_avail_to_read<1 && num_unconsumed_bytes_in_buf<1) {
			break;
		}

		// max bytes that will fit in buf:
		bytestoread = BRBUFLEN-num_unconsumed_bytes_in_buf;

		// max bytes available to read:
		if(bytestoread >= nbytes_avail_to_read) {
			bytestoread = nbytes_avail_to_read;
			brctx->eof_flag = 1;
		}
		else {
			brctx->eof_flag = 0;
		}

		dbuf_read(f, &buf[num_unconsumed_bytes_in_buf], pos, bytestoread);
		pos += bytestoread;
		num_unconsumed_bytes_in_buf += bytestoread;

		brctx->offset = offs_of_first_byte_in_buf;
		brctx->bytes_consumed = num_unconsumed_bytes_in_buf;
		ret = cbfn(brctx, buf, num_unconsumed_bytes_in_buf);
		if(!ret) goto done;
		if(brctx->bytes_consumed<1 || brctx->bytes_consumed>num_unconsumed_bytes_in_buf) {
			goto done;
		}

		if(brctx->bytes_consumed < num_unconsumed_bytes_in_buf) {
			// cbfn didn't consume all bytes
			// TODO: For better efficiency, we could leave the buffer as it is until
			// the unconsumed byte count drops below 1024. But that is only useful if
			// some consumers consume only a small number of bytes.
			de_memmove(buf, &buf[brctx->bytes_consumed],
				(size_t)(num_unconsumed_bytes_in_buf-brctx->bytes_consumed));
			num_unconsumed_bytes_in_buf -= brctx->bytes_consumed;
		}
		else {
			num_unconsumed_bytes_in_buf = 0;
		}
		offs_of_first_byte_in_buf += brctx->bytes_consumed;
	}
	retval = 1;
done:
	return retval;
}

// Optimized version, just for type membuf
static int buffered_read_for_membuf(struct de_bufferedreadctx *brctx,
	dbuf *f, i64 pos1, i64 len, de_buffered_read_cbfn cbfn)
{
	int retval = 0;
	i64 total_nbytes_consumed = 0;

	while(1) {
		int ret;
		i64 nbytes_to_send;

		nbytes_to_send = len - total_nbytes_consumed;
		if(nbytes_to_send<1) break;
		brctx->bytes_consumed = nbytes_to_send;
		brctx->offset = total_nbytes_consumed;
		brctx->eof_flag = 1;

		ret = cbfn(brctx, &f->membuf_buf[pos1+total_nbytes_consumed],
			nbytes_to_send);
		if(!ret) goto done;
		if(brctx->bytes_consumed<1 || brctx->bytes_consumed>nbytes_to_send) {
			goto done;
		}
		total_nbytes_consumed += brctx->bytes_consumed;
	}
	retval = 1;
done:
	return retval;
}

int dbuf_buffered_read(dbuf *f, i64 pos1, i64 len,
	de_buffered_read_cbfn cbfn, void *userdata)
{
	struct de_bufferedreadctx brctx;

	brctx.c = f->c;
	brctx.userdata = userdata;

	if(f->btype==DBUF_TYPE_MEMBUF && (pos1>=0) && (pos1+len<=f->len)) {
		// Use an optimized routine if all the data we need to read is already
		// in memory.
		return buffered_read_for_membuf(&brctx, f, pos1, len, cbfn);
	}
	return buffered_read_internal(&brctx, f, pos1, len, cbfn);
}

int de_is_all_zeroes(const u8 *b, i64 n)
{
	i64 k;
	for(k=0; k<n; k++) {
		if(b[k]!=0) return 0;
	}
	return 1;
}

static int is_all_zeroes_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	return de_is_all_zeroes(buf, buf_len);
}

// Returns 1 if the given slice has only bytes with value 0.
int dbuf_is_all_zeroes(dbuf *f, i64 pos, i64 len)
{
	return dbuf_buffered_read(f, pos, len, is_all_zeroes_cbfn, NULL);
}
