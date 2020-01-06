// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-util.c: Most of the main library functions

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

char *de_get_version_string(char *buf, size_t bufsize)
{
	char extver[32];

	if((DE_VERSION_NUMBER&0x000000ffU) == 0)
		de_strlcpy(extver, "", sizeof(extver));
	else
		de_snprintf(extver, sizeof(extver), "-%u", DE_VERSION_NUMBER&0x000000ff);

	de_snprintf(buf, bufsize, "%u.%u.%u%s%s",
		(DE_VERSION_NUMBER&0xff000000U)>>24,
		(DE_VERSION_NUMBER&0x00ff0000U)>>16,
		(DE_VERSION_NUMBER&0x0000ff00U)>>8,
		extver, DE_VERSION_SUFFIX);

	return buf;
}

unsigned int de_get_version_int(void)
{
	return DE_VERSION_NUMBER;
}

void de_strlcpy(char *dst, const char *src, size_t dstlen)
{
	size_t n;
	n = de_strlen(src);
	if(n>dstlen-1) n=dstlen-1;
	de_memcpy(dst, src, n);
	dst[n]='\0';
}

// Compare two ASCII strings, as if all letters were lowercase.
// (Library functions like strcasecmp or _stricmp usually exist, but we roll
// our own for portability, and consistent behavior.)
static int de_strcasecmp_internal(const char *a, const char *b,
	int has_n, size_t n)
{
	size_t k = 0;

	while(1) {
		unsigned char a1, b1;

		if(has_n && (k>=n)) break;
		a1 = (unsigned char)a[k];
		b1 = (unsigned char)b[k];
		if(a1==0 && b1==0) break;
		if(a1>='A' && a1<='Z') a1 += 32;
		if(b1>='A' && b1<='Z') b1 += 32;
		if(a1<b1) return -1;
		if(a1>b1) return 1;
		k++;
	}
	return 0;
}

int de_strcasecmp(const char *a, const char *b)
{
	return de_strcasecmp_internal(a, b, 0, 0);
}

int de_strncasecmp(const char *a, const char *b, size_t n)
{
	return de_strcasecmp_internal(a, b, 1, n);
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

static void de_puts_advanced(deark *c, unsigned int flags, const char *s)
{
	size_t s_len;
	size_t s_pos = 0;
	char *tmps = NULL;
	size_t tmps_pos = 0;
	int hlmode = 0;
	unsigned int special_code;
	u32 param1 = 0;

	s_len = de_strlen(s);
	tmps = de_malloc(c, (i64)s_len+1);

	// Search for characters that enable/disable highlighting,
	// and split the string at them.
	while(s_pos < s_len) {
		if(s[s_pos]=='\x01' || s[s_pos]=='\x02' || s[s_pos]=='\x03') {
			// Found a special code

			if(s[s_pos]=='\x02' && s[s_pos+1]=='\x01' && hlmode) {
				// Optimization: UNHL followed immediately by HL is a no-op.
				special_code = 0;
			}
			else if(s[s_pos]=='\x01') {
				special_code = DE_MSGCODE_HL;
				hlmode = 1;
			}
			else if(s[s_pos]=='\x03') {
				special_code = DE_MSGCODE_RGBSAMPLE;
				if(s_pos + 7 <= s_len) {
					param1 = DE_MAKE_RGB(
						((s[s_pos+1]&0x0f)<<4) | (s[s_pos+2]&0x0f),
						((s[s_pos+3]&0x0f)<<4) | (s[s_pos+4]&0x0f),
						((s[s_pos+5]&0x0f)<<4) | (s[s_pos+6]&0x0f));
				}
			}
			else {
				special_code = DE_MSGCODE_UNHL;
				hlmode = 0;
			}

			// Print what we have of the string before the special code
			if(tmps_pos>0) {
				tmps[tmps_pos] = '\0';
				c->msgfn(c, flags, tmps);
			}
			tmps_pos = 0;

			// "Print" the special code
			if(special_code && c->specialmsgfn) {
				c->specialmsgfn(c, flags, special_code, param1);
			}

			// Advance past the special code
			if(special_code==0)
				s_pos += 2;
			else if(special_code==DE_MSGCODE_RGBSAMPLE)
				s_pos += 7;
			else
				s_pos += 1;
		}
		else {
			tmps[tmps_pos++] = s[s_pos++];
		}
	}

	// Unset highlight, if it somehow got left on.
	if(hlmode && c->specialmsgfn) {
		c->specialmsgfn(c, flags, DE_MSGCODE_UNHL, 0);
	}

	tmps[tmps_pos] = '\0';
	c->msgfn(c, flags, tmps);
	de_free(c, tmps);
}

void de_puts(deark *c, unsigned int flags, const char *s)
{
	size_t k;

	if(!c || !c->msgfn) {
		fputs(s, stderr);
		return;
	}

	// Scan the printable string for "magic" byte sequences that represent
	// text color changes, etc. It's admittedly a little ugly that we have to
	// do this.
	//
	// We could invent and use any byte sequences we want for this, as long as
	// they will not otherwise occur in "printable" output.
	// I.e., if it's valid UTF-8, it must contain a character we classify as
	// "nonprintable". We could even use actual ANSI escape sequences, since
	// Esc is a nonprintable character (but that would have little benefit,
	// and feel kinda wrong, since this part of the code isn't supposed to
	// know about ANSI escape sequences).
	// Short sequences are preferable, because they're simpler to detect, and
	// because these bytes count against some of our size limits.
	// Valid UTF-8 is probably best, because someday we might want this scheme
	// to be compatible with something else (such as ucstrings).
	// So, we're simply using:
	//   U+0001 : DE_CODEPOINT_HL
	//   U+0002 : DE_CODEPOINT_UNHL
	//   U+0003 : DE_CODEPOINT_RGBSAMPLE (followed by 6 bytes for the RGB color)

	for(k=0; s[k]; k++) {
		if(s[k]=='\x01' || s[k]=='\x02' || s[k]=='\x03') {
			de_puts_advanced(c, flags, s);
			return;
		}
	}

	c->msgfn(c, flags, s);
}

static void de_vprintf(deark *c, unsigned int flags, const char *fmt, va_list ap)
{
	char buf[1024];

	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	de_puts(c, flags, buf);
}

void de_printf(deark *c, unsigned int flags, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	de_vprintf(c, flags, fmt, ap);
	va_end(ap);
}

static void de_vdbg_internal(deark *c, const char *fmt, va_list ap)
{
	char bars_and_spaces[128];
	size_t bpos;
	int nspaces;
	int nbars;
	const char *dprefix = "DEBUG: ";

	if(c) {
		if(c->dprefix) dprefix = c->dprefix;

		nbars = c->module_nesting_level - 1;
		if(nbars>10) nbars=10;

		nspaces = c->dbg_indent_amount;
		if(nspaces>50) nspaces=50;
	}
	else {
		nbars = 0;
		nspaces = 0;
	}

	bpos = 0;
	while(nbars>0) {
		// One or more vertical lines, to indicate module nesting
		bars_and_spaces[bpos++] = '\xe2'; // U+2502 Box drawings light vertical
		bars_and_spaces[bpos++] = '\x94';
		bars_and_spaces[bpos++] = '\x82';
		nbars--;
	}
	while(nspaces>0) {
		bars_and_spaces[bpos++] = ' ';
		nspaces--;
	}
	bars_and_spaces[bpos] = '\0';

	de_printf(c, DE_MSGTYPE_DEBUG, "%s%s", dprefix, bars_and_spaces);
	de_vprintf(c, DE_MSGTYPE_DEBUG, fmt, ap);
	de_puts(c, DE_MSGTYPE_DEBUG, "\n");
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

void de_dbg_indent_save(deark *c, int *saved_indent_level)
{
	*saved_indent_level = c->dbg_indent_amount;
}

void de_dbg_indent_restore(deark *c, int saved_indent_level)
{
	c->dbg_indent_amount = saved_indent_level;
}

static int get_ndigits_for_offset(i64 n)
{
	int nd;

	if(n<10) nd=1;
	else if(n<100) nd=2;
	else if(n<1000) nd=3;
	else if(n<10000) nd=4;
	else nd=5;
	return nd;
}

struct hexdump_ctx;
typedef void (*hexdump_printline_fn)(deark *c, struct hexdump_ctx *hctx);

struct hexdump_ctx {
	// same for each row:
	const char *prefix;
	const char *prefix_sep; // ":"
	unsigned int flags;
	hexdump_printline_fn printlinefn;
	char offset_fmtstr[32];

	// per row
	i64 row_offset;
	i64 bytesthisrow; // num bytes used in .rowbuf
	u8 rowbuf[16];
	char outbuf_sz[200];
};

static void do_hexdump_row(deark *c, struct hexdump_ctx *hctx)
{
	char offset_formatted[32];
	char linebuf[3*16+32];
	char asciibuf[64];
	int asciibufpos;
	int linebufpos;
	i64 k;

	linebufpos = 0;
	asciibufpos = 0;
	asciibuf[asciibufpos++] = '\"';
	for(k=0; k<hctx->bytesthisrow; k++) {
		u8 b;
		b = hctx->rowbuf[k];
		linebuf[linebufpos++] = de_get_hexchar(b/16);
		linebuf[linebufpos++] = de_get_hexchar(b%16);
		linebuf[linebufpos++] = ' ';
		if(b>=32 && b<=126) {
			asciibuf[asciibufpos++] = (char)b;
		}
		else {
			asciibuf[asciibufpos++] = '\x01'; // DE_CODEPOINT_HL
			asciibuf[asciibufpos++] = '.';
			// We'll often turn off highlighting only to turn it back on
			// again for the next character. The OFF+ON sequences will be
			// optimized out later, though, so there's no reason to worry
			// about that here.
			asciibuf[asciibufpos++] = '\x02'; // DE_CODEPOINT_UNHL
		}
	}

	// Pad and terminate the hex values
	while(linebufpos<48) {
		linebuf[linebufpos++] = ' ';
	}
	linebuf[linebufpos] = '\0';

	// Terminate or erase the ASCII representation
	if(hctx->flags&0x1) {
		asciibuf[asciibufpos++] = '\"';
		asciibuf[asciibufpos++] = '\0';
	}
	else {
		asciibuf[0] = '\0';
	}

	// Careful: With a variable format string, the compiler won't be able to
	// detect errors.
	de_snprintf(offset_formatted, sizeof(offset_formatted), hctx->offset_fmtstr,
		(i64)hctx->row_offset);

	de_snprintf(hctx->outbuf_sz, sizeof(hctx->outbuf_sz), "%s%s%s: %s%s",
		hctx->prefix, hctx->prefix_sep, offset_formatted, linebuf, asciibuf);
	hctx->printlinefn(c, hctx);
}

// If prefix is NULL, a default will be used.
// flags:
//  0x1 = Include an ASCII representation
static void de_hexdump_internal(deark *c, struct hexdump_ctx *hctx,
	dbuf *f, i64 pos1,
	i64 nbytes_avail, i64 max_nbytes_to_dump)
{
	i64 pos = pos1;
	i64 len;
	int ndigits_for_offset;
	int was_truncated = 0;

	if(hctx->flags & 0x2) {
		// Don't print a prefix
		hctx->prefix = "";
		hctx->prefix_sep = "";
	}
	else {
		hctx->prefix_sep = ":";
	}

	if(nbytes_avail > max_nbytes_to_dump) {
		len = max_nbytes_to_dump;
		was_truncated = 1;
	}
	else {
		len = nbytes_avail;
	}

	// Construct a format string to use for byte offsets.
	if(was_truncated) {
		// If we're truncating, the highest offset we'll print is the number
		// of data bytes that we'll dump.
		ndigits_for_offset = get_ndigits_for_offset(len);
	}
	else {
		if(len<1) return;

		// If we're not truncating, the highest offset we'll print is the
		// highest byte offset that is a multiple of 16.
		ndigits_for_offset = get_ndigits_for_offset(((len-1)/16)*16);
	}
	de_snprintf(hctx->offset_fmtstr, sizeof(hctx->offset_fmtstr), "%%%d"I64_FMT, ndigits_for_offset);

	while(1) { // For each row...
		if(pos >= pos1+len) break;

		hctx->row_offset = pos-pos1;

		hctx->bytesthisrow = (pos1+len)-pos;
		if(hctx->bytesthisrow>16) hctx->bytesthisrow=16;

		dbuf_read(f, hctx->rowbuf, pos, hctx->bytesthisrow);

		do_hexdump_row(c, hctx);

		pos += hctx->bytesthisrow;
	}
	if(was_truncated) {
		de_snprintf(hctx->outbuf_sz, sizeof(hctx->outbuf_sz),
			"%s%s%"I64_FMT": ...", hctx->prefix, hctx->prefix_sep, len);
		hctx->printlinefn(c, hctx);
	}
}

static void hexdump_printline_dbg(deark *c, struct hexdump_ctx *hctx)
{
	de_dbg(c, "%s", hctx->outbuf_sz);
}

// If prefix is NULL (and the no_prefix flag is not set), a default will be used.
// flags:
//  0x1 = Include an ASCII representation
//  0x2 = No prefix
void de_dbg_hexdump(deark *c, dbuf *f, i64 pos1,
	i64 nbytes_avail, i64 max_nbytes_to_dump,
	const char *prefix1, unsigned int flags)
{
	struct hexdump_ctx hctx;

	hctx.flags = flags;
	hctx.prefix = (prefix1) ? prefix1 : "data";
	hctx.printlinefn = hexdump_printline_dbg;

	de_hexdump_internal(c, &hctx, f, pos1, nbytes_avail, max_nbytes_to_dump);
}

static void hexdump_printline_ext(deark *c, struct hexdump_ctx *hctx)
{
	de_printf(c, DE_MSGTYPE_MESSAGE, "%s\n", hctx->outbuf_sz);
}

// Print a hexdump in the style of the "hexdump" module.
void de_hexdump2(deark *c, dbuf *f, i64 pos1, i64 nbytes_avail,
	i64 max_nbytes_to_dump, unsigned int flags)
{
	struct hexdump_ctx hctx;

	hctx.flags = flags | 0x2;
	hctx.prefix = NULL;
	hctx.printlinefn = hexdump_printline_ext;
	de_hexdump_internal(c, &hctx, f, pos1, nbytes_avail, max_nbytes_to_dump);
}

// This is such a common thing to do, that it's worth having a function for it.
void de_dbg_dimensions(deark *c, i64 w, i64 h)
{
	de_dbg(c, "dimensions: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, w, h);
}

// Generates a "magic" code that, when included in the debug output, will
// (in some circumstances) display a small sample of the given color.
// Caller supplies csamp[16].
// Returns a pointer to csamp, for convenience.
char *de_get_colorsample_code(deark *c, u32 clr, char *csamp,
	size_t csamplen)
{
	unsigned int r, g, b;

	if(csamplen<8) {
		csamp[0]='\0';
		return csamp;
	}

	r = (unsigned int)DE_COLOR_R(clr);
	g = (unsigned int)DE_COLOR_G(clr);
	b = (unsigned int)DE_COLOR_B(clr);

	// Only the low 4 bits are significant. We add 16 so that the bits can't
	// all be 0; since we can't have NUL bytes in this NUL-terminated string.
	// Also, it's nice if the values are all <= 127, to make them UTF-8
	// compatible.
	csamp[0] = '\x03'; // refer to DE_CODEPOINT_RGBSAMPLE
	csamp[1] = 16 + (r>>4)%16;
	csamp[2] = 16 + r%16;
	csamp[3] = 16 + (g>>4)%16;
	csamp[4] = 16 + g%16;
	csamp[5] = 16 + (b>>4)%16;
	csamp[6] = 16 + b%16;
	csamp[7] = '\0';
	return csamp;
}

// Print debugging output for an 8-bit RGB palette entry.
void de_dbg_pal_entry2(deark *c, i64 idx, u32 clr,
	const char *txt_before, const char *txt_in, const char *txt_after)
{
	int r,g,b,a;
	char astr[32];
	char csamp[16];

	if(c->debug_level<2) return;
	if(!txt_before) txt_before="";
	if(!txt_in) txt_in="";
	if(!txt_after) txt_after="";
	r = (int)DE_COLOR_R(clr);
	g = (int)DE_COLOR_G(clr);
	b = (int)DE_COLOR_B(clr);
	a = (int)DE_COLOR_A(clr);
	if(a!=0xff) {
		de_snprintf(astr, sizeof(astr), ",A=%d", a);
	}
	else {
		astr[0] = '\0';
	}

	de_get_colorsample_code(c, clr, csamp, sizeof(csamp));
	de_dbg2(c, "pal[%3d] = %s(%3d,%3d,%3d%s%s)%s%s", (int)idx, txt_before,
		r, g, b, astr, txt_in, csamp, txt_after);
}

void de_dbg_pal_entry(deark *c, i64 idx, u32 clr)
{
	if(c->debug_level<2) return;
	de_dbg_pal_entry2(c, idx, clr, NULL, NULL, NULL);
}

void de_verr(deark *c, const char *fmt, va_list ap)
{
	if(c) {
		c->error_count++;
	}

	de_puts(c, DE_MSGTYPE_ERROR, "Error: ");
	de_vprintf(c, DE_MSGTYPE_ERROR, fmt, ap);
	de_puts(c, DE_MSGTYPE_ERROR, "\n");
}

// c can be NULL
void de_err(deark *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	de_verr(c, fmt, ap);
	va_end(ap);
}

void de_vwarn(deark *c, const char *fmt, va_list ap)
{
	if(!c->show_warnings) return;
	de_puts(c, DE_MSGTYPE_WARNING, "Warning: ");
	de_vprintf(c, DE_MSGTYPE_WARNING, fmt, ap);
	de_puts(c, DE_MSGTYPE_WARNING, "\n");
}

void de_warn(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_warnings) return;
	va_start(ap, fmt);
	de_vwarn(c, fmt, ap);
	va_end(ap);
}

// For "informational" messages: Those that will be suppressed by -noinfo.
void de_info(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_infomessages) return;
	va_start(ap, fmt);
	de_vprintf(c, DE_MSGTYPE_MESSAGE, fmt, ap);
	va_end(ap);
	de_puts(c, DE_MSGTYPE_MESSAGE, "\n");
}

// For "payload" messages, that won't be suppressed by options like -q.
// (Note that there is nothing wrong with using de_printf or de_puts instead of
// this.)
void de_msg(deark *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	de_vprintf(c, DE_MSGTYPE_MESSAGE, fmt, ap);
	va_end(ap);
	de_puts(c, DE_MSGTYPE_MESSAGE, "\n");
}

// c can be NULL.
void de_fatalerror(deark *c)
{
	if(c && c->fatalerrorfn) {
		c->fatalerrorfn(c);
	}
	de_exitprocess(1);
}

// TODO: Make de_malloc use de_mallocarray internally, instead of vice versa.
void *de_mallocarray(deark *c, i64 nmemb, size_t membsize)
{
	if(nmemb>500000000 || nmemb<0 || membsize>500000000) {
		de_err(c, "Out of memory");
		de_fatalerror(c);
		return NULL;
	}

	return de_malloc(c, nmemb*(i64)membsize);
}

// Memory returned is always zeroed.
// c can be NULL.
// Always succeeds; never returns NULL.
void *de_malloc(deark *c, i64 n)
{
	void *m;
	if(n==0) n=1;
	if(n<0 || n>500000000) {
		de_err(c, "Out of memory (%d bytes requested)",(int)n);
		de_fatalerror(c);
		return NULL;
	}

	m = calloc((size_t)n,1);
	if(!m) {
		de_err(c, "Memory allocation failed (%d bytes)",(int)n);
		de_fatalerror(c);
		return NULL;
	}
	return m;
}

// TODO: Make de_realloc use de_reallocarray internally, instead of vice versa.
void *de_reallocarray(deark *c, void *m, i64 oldnmemb, size_t membsize,
	i64 newnmemb)
{

	if(newnmemb>500000000 || newnmemb<0 || oldnmemb<0 || membsize>500000000) {
		de_err(c, "Out of memory");
		de_fatalerror(c);
		return NULL;
	}

	return de_realloc(c, m,
		oldnmemb*(i64)membsize,
		newnmemb*(i64)membsize);
}

// If you know oldsize, you can provide it, and newly-allocated bytes will be zeroed.
// Otherwise, set oldsize==newsize, and newly-allocated bytes won't be zeroed.
// If oldmem is NULL, this behaves the same as de_malloc, and all bytes are zeroed.
void *de_realloc(deark *c, void *oldmem, i64 oldsize, i64 newsize)
{
	void *newmem;

	if(!oldmem) {
		return de_malloc(c, newsize);
	}

	newmem = realloc(oldmem, (size_t)newsize);
	if(!newmem) {
		de_err(c, "Memory reallocation failed (%d bytes)",(int)newsize);
		free(oldmem);
		de_fatalerror(c);
		return NULL;
	}

	if(oldsize<newsize) {
		// zero out any newly-allocated bytes
		de_zeromem(&((u8*)newmem)[oldsize], (size_t)(newsize-oldsize));
	}

	return newmem;
}

void de_free(deark *c, void *m)
{
	free(m);
}

// Returns the index into c->module_info[], or -1 if no found.
int de_get_module_idx_by_id(deark *c, const char *module_id)
{
	int i;
	int k;

	if(!module_id) return -1;

	for(i=0; i<c->num_modules; i++) {
		if(!de_strcmp(c->module_info[i].id, module_id)) {
			return i;
		}
		for(k=0; k<DE_MAX_MODULE_ALIASES; k++) {
			if(!c->module_info[i].id_alias[k]) break;
			if(!de_strcmp(c->module_info[i].id_alias[k], module_id)) {
				return i;
			}
		}
	}
	return -1;
}

struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id)
{
	int idx;

	idx = de_get_module_idx_by_id(c, module_id);
	if(idx<0) return NULL;
	return &c->module_info[idx];
}

int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams,
	enum de_moddisp_enum moddisp)
{
	enum de_moddisp_enum old_moddisp;
	struct de_detection_data_struct *old_detection_data;

	if(!mi) return 0;
	if(!mi->run_fn) return 0;

	old_moddisp = c->module_disposition;
	c->module_disposition = moddisp;

	old_detection_data = c->detection_data;
	if(c->module_nesting_level > 0) {
		c->detection_data = NULL;
	}

	if(c->module_nesting_level>0 && c->debug_level>=3) {
		de_dbg3(c, "[using %s module]", mi->id);
	}
	c->module_nesting_level++;
	mi->run_fn(c, mparams);
	c->module_nesting_level--;
	c->module_disposition = old_moddisp;
	c->detection_data = old_detection_data;
	return 1;
}

int de_run_module_by_id(deark *c, const char *id, de_module_params *mparams)
{
	struct deark_module_info *module_to_use;

	module_to_use = de_get_module_by_id(c, id);
	if(!module_to_use) {
		de_err(c, "Unknown or unsupported format \"%s\"", id);
		return 0;
	}

	return de_run_module(c, module_to_use, mparams, DE_MODDISP_INTERNAL);
}

void de_run_module_by_id_on_slice(deark *c, const char *id, de_module_params *mparams,
	dbuf *f, i64 pos, i64 len)
{
	dbuf *old_ifile;

	old_ifile = c->infile;

	if(pos==0 && len==f->len) {
		// Optimization: We don't need a subfile in this case
		c->infile = f;
		de_run_module_by_id(c, id, mparams);
	}
	else {
		c->infile = dbuf_open_input_subfile(f, pos, len);
		de_run_module_by_id(c, id, mparams);
		dbuf_close(c->infile);
	}

	c->infile = old_ifile;
}

// Same as de_run_module_by_id_on_slice(), but takes just ->codes
// as a parameter, instead of a full de_module_params struct.
void de_run_module_by_id_on_slice2(deark *c, const char *id, const char *codes,
	dbuf *f, i64 pos, i64 len)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = codes;
	de_run_module_by_id_on_slice(c, id, mparams, f, pos, len);
	de_free(c, mparams);
}

const char *de_get_ext_option(deark *c, const char *name)
{
	int i;

	for(i=0; i<c->num_ext_options; i++) {
		if(!de_strcmp(c->ext_option[i].name, name)) {
			return c->ext_option[i].val;
		}
	}
	return NULL; // Option name not found.
}

// Returns
//  0 if false, ("0", "n...", "f...", etc.)
//  1 if true (empty value, "1", "y...", "t...", etc.)
//  defaultval (which can be any integer) if not set, or value is malformed.
int de_get_ext_option_bool(deark *c, const char *name, int defaultval)
{
	const char *val;

	val = de_get_ext_option(c, name);
	if(!val) return defaultval;
	if(val[0]=='\0' || val[0]=='1' || val[0]=='y' || val[0]=='Y' ||
		val[0]=='t' || val[0]=='T')
	{
		return 1;
	}
	if(val[0]=='0' || val[0]=='n' || val[0]=='N' || val[0]=='f' ||
		val[0]=='F')
	{
		return 0;
	}
	return defaultval;
}

int de_atoi(const char *string)
{
	return atoi(string);
}

i64 de_atoi64(const char *string)
{
	return de_strtoll(string, NULL, 10);
}

i64 de_min_int(i64 n1, i64 n2)
{
	return (n1<n2) ? n1 : n2;
}

i64 de_max_int(i64 n1, i64 n2)
{
	return (n1>n2) ? n1 : n2;
}

i64 de_pad_to_2(i64 x)
{
	return (x&0x1) ? x+1 : x;
}

i64 de_pad_to_4(i64 x)
{
	return ((x+3)/4)*4;
}

// Returns x^2.
// Valid for x=0 to 62. If x is invalid, returns 1 (=2^0).
i64 de_pow2(i64 x)
{
	if(x<0 || x>62) return 1;
	return (i64)1 << (unsigned int)x;
}

i64 de_pad_to_n(i64 x, i64 n)
{
	i64 r;
	if(n<2)
		return x;
	r = x%n;
	if(r==0)
		return x;
	return x - r + n;
}

i64 de_log2_rounded_up(i64 n)
{
	i64 i;

	if(n<=2) return 1;
	for(i=2; i<32; i++) {
		if(n <= (((i64)1)<<i)) return i;
	}
	return 32;
}

static const char g_empty_string[] = "";

const char *de_get_sz_ext(const char *sz)
{
	int len;
	int pos;

	if(!sz) return g_empty_string;

	len = (int)de_strlen(sz);
	if(len<2) return g_empty_string;

	// Find the position of the last ".", that's after the last "/"
	pos = len-2;

	while(pos>=0) {
		if(sz[pos]=='.') {
			return &sz[pos+1];
		}
		if(sz[pos]=='/' || sz[pos]=='\\')
			break;
		pos--;
	}
	return g_empty_string;
}

const char *de_get_input_file_ext(deark *c)
{
	if(c->suppress_detection_by_filename) return g_empty_string;

	if(!c->input_filename) return g_empty_string;

	// If we skipped over the first part of the file, assume we're reading
	// an embedded format that's not indicated by the file extension.
	if(c->slice_start_req) return g_empty_string;

	return de_get_sz_ext(c->input_filename);
}

int de_sz_has_ext(const char *sz, const char *ext)
{
	const char *e;

	e = de_get_sz_ext(sz);
	if(!de_strcasecmp(e, ext))
		return 1;
	return 0;
}

int de_input_file_has_ext(deark *c, const char *ext)
{
	const char *e;

	e = de_get_input_file_ext(c);
	if(!de_strcasecmp(e, ext))
		return 1;
	return 0;
}

int de_havemodcode(deark *c, de_module_params *mparams, int code)
{
	if(mparams &&
		mparams->in_params.codes &&
		de_strchr(mparams->in_params.codes, code))
	{
		return 1;
	}
	return 0;
}

// An finfo object holds metadata to be used when writing an output file.
// It is passed to dbuf_create_output_file(), and related functions.
// It does not have to remain valid after that function returns.
// It is allowed to be reused.
de_finfo *de_finfo_create(deark *c)
{
	de_finfo *fi;
	fi = de_malloc(c, sizeof(de_finfo));
	return fi;
}

void de_finfo_destroy(deark *c, de_finfo *fi)
{
	if(!fi) return;
	if(fi->file_name_internal) ucstring_destroy(fi->file_name_internal);
	if(fi->name_other) ucstring_destroy(fi->name_other);
	de_free(c, fi);
}

static i32 de_char_to_valid_fn_char(deark *c, i32 ch)
{
	if(ch>=32 && ch<=126 && ch!='/' && ch!='\\' && ch!=':'
		&& ch!='*' && ch!='?' && ch!='\"' && ch!='<' &&
		ch!='>' && ch!='|')
	{
		// These are the valid ASCII characters in Windows filenames.
		// TODO: We could behave differently on different platforms.
		return ch;
	}
	else if(ch>=160 && ch<=0x10ffff) {
		// TODO: A lot of Unicode characters probably don't belong in filenames.
		// Maybe we need a whitelist or blacklist.
		// (is_printable_uchar() exists, but isn't quite right.)
		return ch;
	}
	return '_';
}

// Sanitize a filename that is either also going to be processed by
// sanitize_filename2(), or is known to contain no slashes.
static void sanitize_filename1(deark *c, de_ucstring *s)
{
	// Don't allow "."
	if(s->len==1 && s->str[0]=='.') {
		s->str[0] = '_';
	}
	// Don't allow ".."
	if(s->len==2 && s->str[0]=='.' && s->str[1]=='.') {
		s->str[0] = '_';
	}
}

// Sanitize a filename that may contain slashes.
// Just some basic sanitization, not expected to be perfect.
// Note that this name will be written to a ZIP file, not used directly as a
// filename.
static void sanitize_filename2(deark *c, de_ucstring *s)
{
	i64 i;

	// Don't allow an initial "/"
	if(s->len>=1 && s->str[0]=='/') {
		s->str[0] = '_';
	}

	// Don't allow consecutive slashes
	for(i=0; i<s->len-1; i++) {
		if(s->str[i]=='/' && s->str[i+1]=='/') {
			s->str[i] = '_';
		}
	}

	// Don't allow a component to be ".."
	for(i=0; i<s->len-1; i++) {
		if(s->str[i]=='.' && s->str[i+1]=='.') {
			int test1 = 0; // Is ".." at the beginning of a component?
			int test2 = 0; // Is ".." at the end of a component?
			if(i==0 || s->str[i-1]=='/') {
				test1 = 1;
			}
			if(i>=s->len-2 || s->str[i+2]=='/') {
				test2 = 1;
			}
			if(test1 && test2) {
				s->str[i] = '_';
			}
		}
	}

	// Don't allow name to end with "/."
	if(s->len>=2 && s->str[s->len-2]=='/' && s->str[s->len-1]=='.') {
		s->str[s->len-1] = '_';
	}

	// Don't allow name to end with "/"
	if(s->len>=1 && s->str[s->len-1]=='/') {
		s->str[s->len-1] = '_';
	}
}

// Takes ownership of 's', and may modify it.
// flags:
//   DE_SNFLAG_FULLPATH = "/" characters in the name are path separators.
//   DE_SNFLAG_STRIPTRAILINGSLASH
static void de_finfo_set_name_internal(deark *c, de_finfo *fi, de_ucstring *s,
	unsigned int flags)
{
	i64 i;
	int allow_slashes;

	fi->orig_name_was_dot = 0;

	if(fi->file_name_internal) {
		ucstring_destroy(fi->file_name_internal);
		fi->file_name_internal = NULL;
	}
	if(!s) return;

	fi->file_name_internal = s;

	if((flags&DE_SNFLAG_STRIPTRAILINGSLASH) && s->len>0 && s->str[s->len-1]=='/') {
		ucstring_truncate(s, s->len-1);
	}

	allow_slashes = (c->allow_subdirs && (flags&DE_SNFLAG_FULLPATH));

	if(allow_slashes && s->len==1 && s->str[0]=='.') {
		// Remember if this file was named ".", which can be a valid subdir
		// name in some cases (but at this point we don't even know whether it
		// is a directory).
		fi->orig_name_was_dot = 1;
	}

	for(i=0; i<s->len; i++) {
		if(s->str[i]=='/' && allow_slashes) {
			continue;
		}
		s->str[i] = de_char_to_valid_fn_char(c, s->str[i]);
	}

	ucstring_strip_trailing_spaces(s);

	sanitize_filename1(c, s);

	if(allow_slashes) {
		sanitize_filename2(c, s);
	}

	// Don't allow empty filenames.
	if(s->len<1) {
		ucstring_append_sz(s, "_", DE_ENCODING_LATIN1);
	}
}

void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s,
	unsigned int flags)
{
	de_ucstring *s_copy;

	s_copy = ucstring_clone(s);
	de_finfo_set_name_internal(c, fi, s_copy, flags);
}

void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1,
	unsigned int flags, de_encoding encoding)
{
	de_ucstring *fname;

	if(!name1) {
		de_finfo_set_name_from_ucstring(c, fi, NULL, flags);
		return;
	}
	fname = ucstring_create(c);
	ucstring_append_sz(fname, name1, encoding);
	de_finfo_set_name_internal(c, fi, fname, flags);
}

// Sets the precision field to UNKNOWN.
// flags: Same as de_FILETIME_to_timestamp()
void de_unix_time_to_timestamp(i64 ut, struct de_timestamp *ts, unsigned int flags)
{
	de_FILETIME_to_timestamp(
		(ut + ((i64)86400)*(369*365 + 89)) * 10000000,
		ts, flags);
	ts->precision = DE_TSPREC_UNKNOWN;
}

// Sets the sub-second part of the timestamp to 'frac' seconds after
// (always forward in time) the whole-number second represented by the
// timestamp.
// 'frac' must be >=0.0 and <1.0.
// Sets the precision field to HIGH.
void de_timestamp_set_subsec(struct de_timestamp *ts, double frac)
{
	i64 subsec;

	if(!ts->is_valid) return;
	if(ts->ts_FILETIME<0) ts->ts_FILETIME=0;

	// Subtract off any existing fractional second.
	ts->ts_FILETIME -= (ts->ts_FILETIME%10000000);

	subsec = (i64)(0.5+frac*10000000.0);
	if(subsec>=10000000) subsec=9999999;
	if(subsec<0) subsec=0;
	ts->ts_FILETIME += subsec;
	ts->precision = DE_TSPREC_HIGH;
}

// Returns the number of ten-millionths of a second after the whole number
// of seconds (i.e. after the time returned by de_timestamp_to_unix_time).
// The returned value will be between 0 and 9999999, inclusive.
i64 de_timestamp_get_subsec(const struct de_timestamp *ts)
{
	return (de_timestamp_to_FILETIME(ts) % 10000000);
}

void de_mac_time_to_timestamp(i64 mt, struct de_timestamp *ts)
{
	de_unix_time_to_timestamp(mt - 2082844800, ts, 0);
}

// Convert a Windows FILETIME to a Deark timestamp.
// Always sets the precision field to HIGH.
// flags: 0x1 = set the UTC flag
void de_FILETIME_to_timestamp(i64 ft, struct de_timestamp *ts, unsigned int flags)
{
	de_zeromem(ts, sizeof(struct de_timestamp));
	if(ft<=0) return;
	ts->is_valid = 1;
	ts->ts_FILETIME = ft;
	ts->precision = DE_TSPREC_HIGH;
	if(flags&0x1) ts->tzcode = DE_TZCODE_UTC;
}

void de_dos_datetime_to_timestamp(struct de_timestamp *ts,
   i64 ddate, i64 dtime)
{
	i64 yr, mo, da, hr, mi, se;

	if(ddate==0) {
		de_zeromem(ts, sizeof(struct de_timestamp));
		ts->is_valid = 0;
		return;
	}
	yr = 1980+((ddate&0xfe00)>>9);
	mo = (ddate&0x01e0)>>5;
	da = (ddate&0x001f);
	hr = (dtime&0xf800)>>11;
	mi = (dtime&0x07e0)>>5;
	se = 2*(dtime&0x001f);
	de_make_timestamp(ts, yr, mo, da, hr, mi, se);
	ts->precision = DE_TSPREC_2SEC;
}

// Sets the DE_TZCODE_UTC flag.
void de_riscos_loadexec_to_timestamp(u32 load_addr,
	u32 exec_addr, struct de_timestamp *ts)
{
	i64 t;
	unsigned int centiseconds;

	de_zeromem(ts, sizeof(struct de_timestamp));
	if((load_addr&0xfff00000U)!=0xfff00000U) return;

	t = (((i64)(load_addr&0xff))<<32) | (i64)exec_addr;
	// t now = number of centiseconds since the beginning of 1900

	// Remember centiseconds.
	centiseconds = (unsigned int)(t%100);
	// Convert t to seconds.
	t = t/100;

	// Convert 1900 epoch to 1970 epoch.
	// (There were 17 leap days between Jan 1900 and Jan 1970.)
	t -= (365*70 + 17)*(i64)86400;

	if(t<=0 || t>=8000000000LL) return; // sanity check

	de_unix_time_to_timestamp(t, ts, 0);
	de_timestamp_set_subsec(ts, ((double)centiseconds)/100.0);
	ts->tzcode = DE_TZCODE_UTC;
}

// This always truncates down to a whole number of seconds.
// While an option to round might be useful for *something*, it could
// cause problems if you're not really careful. It invites double-rounding,
// and the creation of timestamps that are slightly in the future, both of
// which can be problematical.
i64 de_timestamp_to_unix_time(const struct de_timestamp *ts)
{
	if(!ts->is_valid) return 0;

	// There are 369 years between 1601 and 1970, with 89 leap days.
	return (de_timestamp_to_FILETIME(ts)/10000000) - ((i64)86400)*(369*365 + 89);
}

// Convert to Windows FILETIME.
// Returns 0 on error.
i64 de_timestamp_to_FILETIME(const struct de_timestamp *ts)
{
	if(!ts->is_valid) return 0;
	if(ts->ts_FILETIME<0) return 0;
	return ts->ts_FILETIME;
}

// [Adapted from Eric Raymond's public domain my_timegm().]
// Convert a time (as individual fields) to a de_timestamp.
// This is basically a UTC version of mktime().
// yr = full year
// mo = month: 1=Jan, ... 12=Dec
// da = day of month: 1=1, ... 31=31
void de_make_timestamp(struct de_timestamp *ts,
	i64 yr, i64 mo, i64 da,
	i64 hr, i64 mi, i64 se)
{
	i64 result;
	i64 tm_mon;
	static const int cumulative_days[12] =
		{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

	de_zeromem(ts, sizeof(struct de_timestamp));
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
	result += se;

	de_unix_time_to_timestamp(result, ts, 0);
}

// Adjust the timestamp, presumably to convert it from local time to UTC,
// and set the UTC flag.
// offset_seconds is number of seconds to add to the timestamp to get UTC,
// i.e. number of seconds west of UTC.
void de_timestamp_cvt_to_utc(struct de_timestamp *ts, i64 offset_seconds)
{
	if(!ts->is_valid) return;
	ts->ts_FILETIME += offset_seconds*10000000;
	ts->tzcode = DE_TZCODE_UTC;
}

// Our version of the standard gmtime() function.
// We roll our own, so that we can support a wide range of dates. We want to
// handle erroneous, and deliberately pathological, dates in the distant past
// and future. We also want Deark to work the same on all platforms.
//
// Converts a de_timestamp to a de_struct_tm, with separate fields
// for year, month, day, ...
// Uses the Gregorian calendar.
// Supports dates from about year 1601 to 30828.
void de_gmtime(const struct de_timestamp *ts, struct de_struct_tm *tm2)
{
	// Let's define an "eon" to be a 400-year period. Eons begin at the start
	// of the year 1601, 2001, 2401, etc.
	static const i64 secs_per_eon = 12622780800LL;
	i64 eon;
	i64 secs_since_start_of_1601;
	i64 secs_since_start_of_eon;
	i64 days_since_start_of_eon;
	i64 secs_since_start_of_day;
	i64 yr_tmp; // years, since start of eon, accounted for so far
	i64 days_tmp; // number of days not accounted for in yr_tmp
	i64 count;
	int is_leapyear;
	int k;

	de_zeromem(tm2, sizeof(struct de_struct_tm));
	if(!ts->is_valid || ts->ts_FILETIME<=0) {
		return;
	}

	secs_since_start_of_1601 = ts->ts_FILETIME / 10000000;
	tm2->tm_subsec = ts->ts_FILETIME % 10000000;
	eon = secs_since_start_of_1601 / secs_per_eon;
	secs_since_start_of_eon = secs_since_start_of_1601 % secs_per_eon;
	days_since_start_of_eon = secs_since_start_of_eon / 86400;
	secs_since_start_of_day = secs_since_start_of_eon % 86400;
	tm2->tm_hour = (int)(secs_since_start_of_day / 3600);
	tm2->tm_min = (int)((secs_since_start_of_day % 3600)/60);
	tm2->tm_sec = (int)(secs_since_start_of_day % 60);

	days_tmp = days_since_start_of_eon;
	yr_tmp = 0;

	// The first 3 100-year periods in this eon have
	// 100*365 + 24 days each.
	count = days_tmp / (100*365 + 24);
	if(count>3) count = 3;
	days_tmp -= (100*365 + 24)*count;
	yr_tmp += 100*count;

	// The first 24 4-year periods in this 100-year period have
	// 1 leap day each.
	count = days_tmp / (4*365 + 1);
	if(count>24) count = 24;
	days_tmp -= (4*365 + 1)*count;
	yr_tmp += 4*count;

	// The first 3 years in this 4-year period are not leap years.
	count = days_tmp / 365;
	if(count>3) count = 3;
	days_tmp -= 365*count;
	yr_tmp += count;

	tm2->tm_fullyear = (int)(1601 + eon*400 + yr_tmp);
	is_leapyear = ((yr_tmp%4)==3 &&
		yr_tmp!=99 && yr_tmp!=199 && yr_tmp!=299);

	for(k=0; k<11; k++) {
		static const u8 days_in_month[11] = // (Don't need December)
			{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30 };
		i64 days_in_this_month = (i64)days_in_month[k];
		if(k==1 && is_leapyear) days_in_this_month++;
		if(days_tmp >= days_in_this_month) {
			days_tmp -= days_in_this_month;
			tm2->tm_mon++;
		}
		else {
			break;
		}
	}

	tm2->tm_mday = (int)(1+days_tmp);
	tm2->is_valid = 1;
}

// Appends " UTC" if ts->tzcode==DE_TZCODE_UTC
// No flags are currently defined.
// Caller supplies buf (suggest it be at least size 64).
// Returns an extra pointer to buf.
char *de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags)
{
	const char *tzlabel;
	char subsec[16];
	struct de_struct_tm tm2;

	if(!ts->is_valid) {
		de_strlcpy(buf, "[invalid timestamp]", buf_len);
		goto done;
	}

	de_gmtime(ts, &tm2);
	if(!tm2.is_valid) {
		de_snprintf(buf, buf_len, "[timestamp out of range: %"I64_FMT"]",
			de_timestamp_to_unix_time(ts));
		goto done;
	}

	if(ts->precision>DE_TSPREC_1SEC) {
		unsigned int ms;
		ms = (unsigned int)(tm2.tm_subsec/10000);
		if(ms>=1000) ms=999;
		de_snprintf(subsec, sizeof(subsec), ".%03u", ms);
	}
	else {
		subsec[0] = '\0';
	}

	tzlabel = (ts->tzcode==DE_TZCODE_UTC)?" UTC":"";
	if(ts->precision!=DE_TSPREC_UNKNOWN && ts->precision<=DE_TSPREC_1DAY) { // date only
		de_snprintf(buf, buf_len, "%04d-%02d-%02d",
			tm2.tm_fullyear, 1+tm2.tm_mon, tm2.tm_mday);
		goto done;
	}
	de_snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d%s%s",
		tm2.tm_fullyear, 1+tm2.tm_mon, tm2.tm_mday,
		tm2.tm_hour, tm2.tm_min, tm2.tm_sec, subsec, tzlabel);
done:
	return buf;
}

// Same as de_timestamp_to_string(), except it assumes the output is only
// needed if debug output is enabled.
// If it is not, it just returns an empty string, to avoid the relatively
// slow date processing.
char *de_dbg_timestamp_to_string(deark *c, const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags)
{
	if(c->debug_level<1) {
		buf[0] = '\0';
		return buf;
	}
	return de_timestamp_to_string(ts, buf, buf_len, flags);
}

// Returns the same time if called multiple times.
void de_cached_current_time_to_timestamp(deark *c, struct de_timestamp *ts)
{
	if(!c->current_time.is_valid) {
		de_current_time_to_timestamp(&c->current_time);
	}
	*ts = c->current_time;
}

void de_declare_fmt(deark *c, const char *fmtname)
{
	if(c->module_nesting_level > 1) {
		return; // Only allowed for the top-level module
	}
	if(c->format_declared) return;
	de_info(c, "Format: %s", fmtname);
	c->format_declared = 1;
}

void de_declare_fmtf(deark *c, const char *fmt, ...)
{
	va_list ap;
	char buf[128];

	va_start(ap, fmt);
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	de_declare_fmt(c, buf);
	va_end(ap);
}

// Returns a suitable input encoding.
// If mparams.in_params.input_encoding exists and is not UNKNOWN,
// returns that.
// Else if c->input_encoding (the -inenc option) is not UNKNOWN, returns that.
// Else returns dflt.
de_encoding de_get_input_encoding(deark *c, de_module_params *mparams,
	de_encoding dflt)
{
	if(mparams && mparams->in_params.input_encoding!=DE_ENCODING_UNKNOWN) {
		return mparams->in_params.input_encoding;
	}
	if(c->input_encoding!=DE_ENCODING_UNKNOWN) {
		return c->input_encoding;
	}
	return dflt;
}

// Assumes dst starts out with only '0' bits
void de_copy_bits(const u8 *src, i64 srcbitnum,
	u8 *dst, i64 dstbitnum, i64 bitstocopy)
{
	i64 i;
	u8 b;

	for(i=0; i<bitstocopy; i++) {
		b = src[(srcbitnum+i)/8];
		b = (b>>(7-(srcbitnum+i)%8))&0x1;
		if(b) {
			b = b<<(7-(dstbitnum+i)%8);
			dst[(dstbitnum+i)/8] |= b;
		}
	}
}

// A very simple hash table implementation, with int64 keys.

#define DE_INTHASHTABLE_NBUCKETS 71

struct de_inthashtable_item {
	i64 key;
	void *value;
	struct de_inthashtable_item *next; // Next item in linked list
};

struct de_inthashtable_bucket {
	struct de_inthashtable_item *first_item;
};

struct de_inthashtable {
	struct de_inthashtable_bucket buckets[DE_INTHASHTABLE_NBUCKETS];
};

static struct de_inthashtable_bucket *inthashtable_find_bucket(struct de_inthashtable *ht,
	i64 key)
{
	i64 bkt_num;

	if(key>=0) bkt_num = key%DE_INTHASHTABLE_NBUCKETS;
	else bkt_num = (-key)%DE_INTHASHTABLE_NBUCKETS;

	return &ht->buckets[bkt_num];
}

struct de_inthashtable *de_inthashtable_create(deark *c)
{
	return de_mallocarray(c, DE_INTHASHTABLE_NBUCKETS, sizeof(struct de_inthashtable));
}

static void inthashtable_destroy_item(deark *c, struct de_inthashtable_item *item)
{
	de_free(c, item);
}

static void inthashtable_destroy_items_in_bucket(deark *c, struct de_inthashtable_bucket *bkt)
{
	struct de_inthashtable_item *next_item;

	while(bkt->first_item) {
		next_item = bkt->first_item->next;
		inthashtable_destroy_item(c, bkt->first_item);
		bkt->first_item = next_item;
	}
}

void de_inthashtable_destroy(deark *c, struct de_inthashtable *ht)
{
	i64 i;

	if(!ht) return;
	for(i=0; i<DE_INTHASHTABLE_NBUCKETS; i++) {
		if(ht->buckets[i].first_item)
			inthashtable_destroy_items_in_bucket(c, &ht->buckets[i]);
	}
	de_free(c, ht);
}

// Returns NULL if item does not exist in the given bucket
static struct de_inthashtable_item *inthashtable_find_item_in_bucket(struct de_inthashtable *ht,
	struct de_inthashtable_bucket *bkt, i64 key)
{
	struct de_inthashtable_item *p;

	p = bkt->first_item;
	while(p && (p->key != key)) {
		p = p->next;
	}
	return p;
}

// Returns NULL if item does not exist
static struct de_inthashtable_item *inthashtable_find_item(struct de_inthashtable *ht, i64 key)
{
	struct de_inthashtable_bucket *bkt;

	if(!ht) return NULL;
	bkt = inthashtable_find_bucket(ht, key);
	return inthashtable_find_item_in_bucket(ht, bkt, key);
}

// If key does not exist, sets *pvalue to NULL and returns 0.
int de_inthashtable_get_item(deark *c, struct de_inthashtable *ht, i64 key, void **pvalue)
{
	struct de_inthashtable_item *item;

	item = inthashtable_find_item(ht, key);
	if(item) {
		*pvalue = item->value;
		return 1;
	}
	*pvalue = NULL;
	return 0;
}

int de_inthashtable_item_exists(deark *c, struct de_inthashtable *ht, i64 key)
{
	return (inthashtable_find_item(ht, key) != NULL);
}

// Unconditionally adds an item to the given bucket (does not prevent duplicates)
static void inthashtable_add_item_to_bucket(struct de_inthashtable *ht,
	struct de_inthashtable_bucket *bkt, struct de_inthashtable_item *new_item)
{
	new_item->next = bkt->first_item;
	bkt->first_item = new_item;
}

// Returns 1 if the key has been newly-added,
// or 0 if the key already existed.
int de_inthashtable_add_item(deark *c, struct de_inthashtable *ht, i64 key, void *value)
{
	struct de_inthashtable_bucket *bkt;
	struct de_inthashtable_item *new_item;

	bkt = inthashtable_find_bucket(ht, key);
	if(inthashtable_find_item_in_bucket(ht, bkt, key)) {
		// Item already exist. Don't add it again.
		// TODO: This may eventually need to be changed to modify the existing item,
		// or delete-then-add the new item, instead of doing nothing.
		return 0;
	}

	new_item = de_malloc(c, sizeof(struct de_inthashtable_item));
	new_item->key = key;
	new_item->value = value;
	inthashtable_add_item_to_bucket(ht, bkt, new_item);
	return 1;
}

int de_inthashtable_remove_item(deark *c, struct de_inthashtable *ht, i64 key, void **pvalue)
{
	// TODO
	return 0;
}

// Select one item arbitrarily, return its key and value, and delete it from the
// hashtable.
int de_inthashtable_remove_any_item(deark *c, struct de_inthashtable *ht, i64 *pkey, void **pvalue)
{
	i64 i;

	for(i=0; i<DE_INTHASHTABLE_NBUCKETS; i++) {
		struct de_inthashtable_item *item;

		item = ht->buckets[i].first_item;
		if(!item) continue;

		// Found an item. Copy it, for the caller.
		if(pkey) *pkey = item->key;
		if(pvalue) *pvalue = item->value;

		// Delete our copy of it.
		ht->buckets[i].first_item = item->next;
		inthashtable_destroy_item(c, item);
		return 1;
	}

	// No items in hashtable.
	if(pkey) *pkey = 0;
	if(pvalue) *pvalue = NULL;
	return 0;
}

// crcobj: Functions for performing CRC calculations, and other checksum-like
// functions for which the result can fit in a 32-bit int.l

struct de_crcobj {
	u32 val;
	unsigned int crctype;
	deark *c;
	u16 *table16;
};

#define DE_CRC32_INIT 0

// crc32_calc() is based on public domain code by Jon Mayo, downloaded
// from <http://orangetide.com/code/crc.c>.
// It includes minor changes for Deark. I disclaim any copyright on these
// minor changes. -JS
// Note: I have found several other seemingly-independent implementations
// of the same algorithm, such as the one by Karl Malbrain, used in miniz.
// I don't know its origin.
static u32 crc32_calc(const u8 *ptr, size_t cnt, u32 crc)
{
	static const u32 crc32_tab[16] = {
		0x00000000U, 0x1db71064U, 0x3b6e20c8U, 0x26d930acU,
		0x76dc4190U, 0x6b6b51f4U, 0x4db26158U, 0x5005713cU,
		0xedb88320U, 0xf00f9344U, 0xd6d6a3e8U, 0xcb61b38cU,
		0x9b64c2b0U, 0x86d3d2d4U, 0xa00ae278U, 0xbdbdf21cU
	};

	if(cnt==0) return crc;
	crc = ~crc;
	while(cnt--) {
		crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (*ptr & 0xf)];
		crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (*ptr++ >> 4)];
	}
	return ~crc;
}

// For a one-shot CRC calculations, or the first part of a multi-part
// calculation.
// buf can be NULL (in which case buf_len should be 0, but is ignored)
static u32 de_crc32(const void *buf, i64 buf_len)
{
	if(!buf) return DE_CRC32_INIT;
	return (u32)crc32_calc((const u8*)buf, (size_t)buf_len, DE_CRC32_INIT);
}

static u32 de_crc32_continue(u32 prev_crc, const void *buf, i64 buf_len)
{
	return (u32)crc32_calc((const u8*)buf, (size_t)buf_len, prev_crc);
}

// This is the CRC-16 algorithm used in MacBinary.
// It is in the x^16 + x^12 + x^5 + 1 family.
// CRC-16-CCITT is probably the best name for it, though I'm not completely
// sure, and there are several algorithms that have been called "CRC-16-CCITT".
static void de_crc16ccitt_init(struct de_crcobj *crco)
{
	const unsigned int polynomial = 0x1021;
	unsigned int index;

	crco->table16 = de_mallocarray(crco->c, 256, sizeof(u16));
	crco->table16[0] = 0;
	for(index=0; index<128; index++) {
		unsigned int carry = crco->table16[index] & 0x8000;
		unsigned int temp = (crco->table16[index] << 1) & 0xffff;
		crco->table16[index * 2 + (carry ? 0 : 1)] = temp ^ polynomial;
		crco->table16[index * 2 + (carry ? 1 : 0)] = temp;
	}
}

static void de_crc16ccitt_continue(struct de_crcobj *crco, const u8 *buf, i64 buf_len)
{
	i64 k;

	if(!crco->table16) return;
	for(k=0; k<buf_len; k++) {
		crco->val = ((crco->val<<8)&0xffff) ^
			(u32)crco->table16[((crco->val>>8) ^ (u32)buf[k]) & 0xff];
	}
}

// This is the CRC-16 algorithm used in ARC, LHA, ZOO, etc.
// It is in the x^16 + x^15 + x^2 + 1 family.
// It's some variant of CRC-16-IBM, and sometimes simply called "CRC-16". But
// both these names are more ambiguous than I'd like, so I'm calling it "ARC".
static void de_crc16arc_init(struct de_crcobj *crco)
{
	u32 i, k;

	crco->table16 = de_mallocarray(crco->c, 256, sizeof(u16));
	for(i=0; i<256; i++) {
		crco->table16[i] = i;
		for(k=0; k<8; k++)
			crco->table16[i] = (crco->table16[i]>>1) ^ ((crco->table16[i] & 1) ? 0xa001 : 0);
	}
}

static void de_crc16arc_continue(struct de_crcobj *crco, const u8 *buf, i64 buf_len)
{
	i64 k;

	if(!crco->table16) return;
	for(k=0; k<buf_len; k++) {
		crco->val = ((crco->val>>8) ^
			(u32)crco->table16[(crco->val ^ buf[k]) & 0xff]);
	}
}

// Allocate, initializes, and resets a new object
struct de_crcobj *de_crcobj_create(deark *c, unsigned int flags)
{
	struct de_crcobj *crco;

	crco = de_malloc(c, sizeof(struct de_crcobj));
	crco->c = c;
	crco->crctype = flags;

	switch(crco->crctype) {
	case DE_CRCOBJ_CRC16_CCITT:
		de_crc16ccitt_init(crco);
		break;
	case DE_CRCOBJ_CRC16_ARC:
		de_crc16arc_init(crco);
		break;
	}

	de_crcobj_reset(crco);
	return crco;
}

void de_crcobj_destroy(struct de_crcobj *crco)
{
	deark *c;

	if(!crco) return;
	c = crco->c;
	de_free(c, crco->table16);
	de_free(c, crco);
}

void de_crcobj_reset(struct de_crcobj *crco)
{
	crco->val = 0;

	switch(crco->crctype) {
	case DE_CRCOBJ_CRC32_IEEE:
		crco->val = de_crc32(NULL, 0);
		break;
	}
}

u32 de_crcobj_getval(struct de_crcobj *crco)
{
	return crco->val;
}

void de_crcobj_addbuf(struct de_crcobj *crco, const u8 *buf, i64 buf_len)
{
	switch(crco->crctype) {
	case DE_CRCOBJ_CRC32_IEEE:
		crco->val = de_crc32_continue(crco->val, buf, buf_len);
		break;
	case DE_CRCOBJ_CRC16_CCITT:
		de_crc16ccitt_continue(crco, buf, buf_len);
		break;
	case DE_CRCOBJ_CRC16_ARC:
		de_crc16arc_continue(crco, buf, buf_len);
		break;
	}
}

void de_crcobj_addbyte(struct de_crcobj *crco, u8 b)
{
	de_crcobj_addbuf(crco, &b, 1);
}

static int addslice_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	de_crcobj_addbuf((struct de_crcobj*)brctx->userdata, buf, buf_len);
	return 1;
}

void de_crcobj_addslice(struct de_crcobj *crco, dbuf *f, i64 pos, i64 len)
{
	// Minor optimization for the case where the data is all in memory
	if(f->btype==DBUF_TYPE_MEMBUF && (pos>=0) && (pos+len<=f->len)) {
		de_crcobj_addbuf(crco, &f->membuf_buf[pos], len);
		return;
	}

	dbuf_buffered_read(f, pos, len, addslice_cbfn, (void*)crco);
}

void de_get_reproducible_timestamp(deark *c, struct de_timestamp *ts)
{
	if(c->reproducible_timestamp.is_valid) {
		*ts = c->reproducible_timestamp;
		return;
	}

	// An arbitrary timestamp
	// $ date -u --date='2010-09-08 07:06:05' '+%s'
	de_unix_time_to_timestamp(1283929565LL, ts, 0x1);
}

// Call this to ensure that a zip/tar file will be created, even if it has
// no member files.
int de_archive_initialize(deark *c)
{
	if(c->output_style!=DE_OUTPUTSTYLE_ARCHIVE) return 0;
	switch(c->archive_fmt) {
	case DE_ARCHIVEFMT_ZIP:
		return de_zip_create_file(c);
	case DE_ARCHIVEFMT_TAR:
		return de_tar_create_file(c);
	}
	return 0;
}
