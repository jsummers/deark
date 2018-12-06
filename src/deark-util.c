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
	de_uint32 param1 = 0;

	s_len = de_strlen(s);
	tmps = de_malloc(c, s_len+1);

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
	if(hlmode) {
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

static int get_ndigits_for_offset(de_int64 n)
{
	int nd;

	if(n<10) nd=1;
	else if(n<100) nd=2;
	else if(n<1000) nd=3;
	else if(n<10000) nd=4;
	else nd=5;
	return nd;
}

// If prefix is NULL, a default will be used.
// flags:
//  0x1 = Include an ASCII representation
void de_dbg_hexdump(deark *c, dbuf *f, de_int64 pos1,
	de_int64 nbytes_avail, de_int64 max_nbytes_to_dump,
	const char *prefix, unsigned int flags)
{
	char linebuf[3*16+32];
	char asciibuf[64];
	char offset_fmtstr[32];
	de_int64 pos = pos1;
	de_int64 k;
	de_int64 bytesthisrow;
	int asciibufpos;
	int linebufpos;
	de_byte b;
	de_int64 len;
	int ndigits_for_offset;
	int was_truncated = 0;

	if(!prefix) prefix="data";

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
	de_snprintf(offset_fmtstr, sizeof(offset_fmtstr), "%%%dd", ndigits_for_offset);

	while(1) { // For each row...
		char offset_formatted[32];

		if(pos >= pos1+len) break;

		bytesthisrow = (pos1+len)-pos;
		if(bytesthisrow>16) bytesthisrow=16;

		linebufpos = 0;
		asciibufpos = 0;
		asciibuf[asciibufpos++] = '\"';
		for(k=0; k<bytesthisrow; k++) {
			b = dbuf_getbyte(f, pos+k);
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
		if(flags&0x1) {
			asciibuf[asciibufpos++] = '\"';
			asciibuf[asciibufpos++] = '\0';
		}
		else {
			asciibuf[0] = '\0';
		}

		// Careful: With a variable format string, the compiler won't be able to
		// detect errors.
		de_snprintf(offset_formatted, sizeof(offset_formatted), offset_fmtstr, (int)(pos-pos1));

		de_dbg(c, "%s:%s: %s%s", prefix, offset_formatted, linebuf, asciibuf);
		pos += bytesthisrow;
	}
	if(was_truncated) {
		de_dbg(c, "%s:%d: ...", prefix, (int)len);
	}
}

// This is such a common thing to do, that it's worth having a function for it.
void de_dbg_dimensions(deark *c, de_int64 w, de_int64 h)
{
	de_dbg(c, "dimensions: %"INT64_FMT DE_CHAR_TIMES "%"INT64_FMT, w, h);
}

// Generates a "magic" code that, when included in the debug output, will
// (in some circumstances) display a small sample of the given color.
// Caller supplies csamp[16].
// Returns a pointer to csamp, for convenience.
char *de_get_colorsample_code(deark *c, de_uint32 clr, char *csamp,
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
void de_dbg_pal_entry2(deark *c, de_int64 idx, de_uint32 clr,
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

void de_dbg_pal_entry(deark *c, de_int64 idx, de_uint32 clr)
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

void de_msg(deark *c, const char *fmt, ...)
{
	va_list ap;

	if(!c->show_messages) return;
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
		de_err(c, "Memory reallocation failed (%d bytes)",(int)newsize);
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

int de_identify_none(deark *c)
{
	return 0;
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

int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams, int moddisp)
{
	int old_moddisp;
	if(!mi) return 0;
	if(!mi->run_fn) return 0;
	old_moddisp = c->module_disposition;
	c->module_disposition = moddisp;
	if(c->module_nesting_level>0 && c->debug_level>=3) {
		de_dbg3(c, "[using %s module]", mi->id);
	}
	c->module_nesting_level++;
	mi->run_fn(c, mparams);
	c->module_nesting_level--;
	c->module_disposition = old_moddisp;
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
	dbuf *f, de_int64 pos, de_int64 len)
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
	dbuf *f, de_int64 pos, de_int64 len)
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

de_int64 de_atoi64(const char *string)
{
	return de_strtoll(string, NULL, 10);
}

de_int64 de_pad_to_2(de_int64 x)
{
	return (x&0x1) ? x+1 : x;
}

de_int64 de_pad_to_4(de_int64 x)
{
	return ((x+3)/4)*4;
}

de_int64 de_pad_to_n(de_int64 x, de_int64 n)
{
	de_int64 r;
	if(n<2)
		return x;
	r = x%n;
	if(r==0)
		return x;
	return x - r + n;
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
	if(fi->file_name) ucstring_destroy(fi->file_name);
	de_free(c, fi);
}

// Takes ownership of 's', and may modify it.
static void de_finfo_set_name_internal(deark *c, de_finfo *fi, de_ucstring *s)
{
	de_int64 i;

	if(fi->file_name) {
		ucstring_destroy(fi->file_name);
		fi->file_name = NULL;
	}
	if(!s) return;

	fi->file_name = s;

	for(i=0; i<s->len; i++) {
		s->str[i] = de_char_to_valid_fn_char(c, s->str[i]);
	}

	ucstring_strip_trailing_spaces(s);

	// Don't allow empty filenames.
	if(s->len<1) {
		ucstring_append_sz(s, "_", DE_ENCODING_LATIN1);
	}
}

void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s)
{
	de_ucstring *s_copy;

	s_copy = ucstring_clone(s);
	de_finfo_set_name_internal(c, fi, s_copy);
}

void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1, int encoding)
{
	de_ucstring *fname;

	if(!name1) {
		de_finfo_set_name_from_ucstring(c, fi, NULL);
		return;
	}
	fname = ucstring_create(c);
	ucstring_append_sz(fname, name1, encoding);
	de_finfo_set_name_internal(c, fi, fname);
}

// flags: 0x1 = set the UTC flag
void de_unix_time_to_timestamp(de_int64 ut, struct de_timestamp *ts, unsigned int flags)
{
	de_memset(ts, 0, sizeof(struct de_timestamp));
	ts->is_valid = 1;
	ts->unix_time = ut;
	if(flags&0x1) ts->tzcode = DE_TZCODE_UTC;
}

void de_timestamp_set_ms(struct de_timestamp *ts, de_uint16 ms, de_uint16 prec)
{
	ts->ms = ms;
	ts->prec = prec;
}

void de_mac_time_to_timestamp(de_int64 mt, struct de_timestamp *ts)
{
	de_unix_time_to_timestamp(mt - 2082844800, ts, 0);
}

// Convert a Windows FILETIME to a Deark timestamp.
// flags: Same as de_unix_time_to_timestamp()
void de_FILETIME_to_timestamp(de_int64 ft, struct de_timestamp *ts, unsigned int flags)
{
	de_int64 t;
	de_int64 ms;
	t = ft/10000000 - ((de_int64)256)*45486225;
	ms = (ft%10000000)/10000;
	de_unix_time_to_timestamp(t, ts, flags);
	de_timestamp_set_ms(ts, (unsigned short)ms, 1);
}

void de_dos_datetime_to_timestamp(struct de_timestamp *ts,
   de_int64 ddate, de_int64 dtime)
{
	de_int64 yr, mo, da, hr, mi, se;

	yr = 1980+((ddate&0xfe00)>>9);
	mo = (ddate&0x01e0)>>5;
	da = (ddate&0x001f);
	hr = (dtime&0xf800)>>11;
	mi = (dtime&0x07e0)>>5;
	se = 2*(dtime&0x001f);
	de_make_timestamp(ts, yr, mo, da, hr, mi, se);
	de_timestamp_set_ms(ts, 0, 2000); // 2-second precision
}

void de_riscos_loadexec_to_timestamp(de_uint32 load_addr,
	de_uint32 exec_addr, struct de_timestamp *ts)
{
	de_int64 t;
	unsigned int centiseconds;

	de_memset(ts, 0, sizeof(struct de_timestamp));
	if((load_addr&0xfff00000U)!=0xfff00000U) return;

	t = (((de_int64)(load_addr&0xff))<<32) | (de_int64)exec_addr;
	// t now = number of centiseconds since the beginning of 1900

	// Remember centiseconds.
	centiseconds = (unsigned int)(t%100);
	// Convert t to seconds.
	t = t/100;

	// Convert 1900 epoch to 1970 epoch.
	// (There were 17 leap days between Jan 1900 and Jan 1970.)
	t -= (365*70 + 17)*(de_int64)86400;

	if(t<=0 || t>=8000000000LL) return; // sanity check

	// TODO: Are these timestamps always UTC?
	de_unix_time_to_timestamp(t, ts, 0);
	de_timestamp_set_ms(ts, (unsigned short)(centiseconds*10), 10);
}

// This always truncates down to a whole number of seconds.
// While an option to round might be useful for *something*, it could
// cause problems if you're not really careful. It invites double-rounding,
// and the creation of timestamps that are slightly in the future, both of
// which can be problematical.
de_int64 de_timestamp_to_unix_time(const struct de_timestamp *ts)
{
	if(ts->is_valid) {
		return ts->unix_time;
	}
	return 0;
}

// [Adapted from Eric Raymond's public domain my_timegm().]
// Convert a time (as individual fields) to a de_timestamp.
// Since de_timestamp currently uses time_t format internally,
// this is basically a UTC version of mktime().
// yr = full year
// mo = month: 1=Jan, ... 12=Dec
// da = day of month: 1=1, ... 31=31
void de_make_timestamp(struct de_timestamp *ts,
	de_int64 yr, de_int64 mo, de_int64 da,
	de_int64 hr, de_int64 mi, de_int64 se)
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
	result += se;

	de_unix_time_to_timestamp(result, ts, 0);
}

// Adjust the timestamp, presumably to convert it from local time to UTC,
// and set the UTC flag.
// offset_seconds is number of seconds to add to the timestamp to get UTC,
// i.e. number of seconds west of UTC.
void de_timestamp_cvt_to_utc(struct de_timestamp *ts, de_int64 offset_seconds)
{
	if(!ts->is_valid) return;
	ts->unix_time += offset_seconds;
	ts->tzcode = DE_TZCODE_UTC;
}

// Appends " UTC" if ts->tzcode==DE_TZCODE_UTC
// No flags are currently defined.
void de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags)
{
	const char *tzlabel;
	char subsec[16];
	struct de_struct_tm tm2;

	if(!ts->is_valid) {
		de_strlcpy(buf, "[invalid timestamp]", buf_len);
		return;
	}

	de_gmtime(ts, &tm2);
	if(!tm2.is_valid) {
		de_snprintf(buf, buf_len, "[timestamp out of range: %"INT64_FMT"]",
			de_timestamp_to_unix_time(ts));
		return;
	}

	if(ts->prec>0 && ts->prec<1000) {
		de_snprintf(subsec, sizeof(subsec), ".%03u", (unsigned int)tm2.tm_ms);
	}
	else {
		subsec[0] = '\0';
	}

	tzlabel = (ts->tzcode==DE_TZCODE_UTC)?" UTC":"";
	de_snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d%s%s",
		tm2.tm_fullyear, 1+tm2.tm_mon, tm2.tm_mday,
		tm2.tm_hour, tm2.tm_min, tm2.tm_sec, subsec, tzlabel);
}

void de_declare_fmt(deark *c, const char *fmtname)
{
	if(c->module_nesting_level > 1) {
		return; // Only allowed for the top-level module
	}
	if(c->format_declared) return;
	de_msg(c, "Format: %s", fmtname);
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

// A very simple hash table implementation, with int64 keys.

#define DE_INTHASHTABLE_NBUCKETS 71

struct de_inthashtable_item {
	de_int64 key;
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
	de_int64 key)
{
	de_int64 bkt_num;

	if(key>=0) bkt_num = key%DE_INTHASHTABLE_NBUCKETS;
	else bkt_num = (-key)%DE_INTHASHTABLE_NBUCKETS;

	return &ht->buckets[bkt_num];
}

struct de_inthashtable *de_inthashtable_create(deark *c)
{
	return de_malloc(c, DE_INTHASHTABLE_NBUCKETS*sizeof(struct de_inthashtable));
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
	de_int64 i;

	if(!ht) return;
	for(i=0; i<DE_INTHASHTABLE_NBUCKETS; i++) {
		if(ht->buckets[i].first_item)
			inthashtable_destroy_items_in_bucket(c, &ht->buckets[i]);
	}
	de_free(c, ht);
}

// Returns NULL if item does not exist in the given bucket
static struct de_inthashtable_item *inthashtable_find_item_in_bucket(struct de_inthashtable *ht,
	struct de_inthashtable_bucket *bkt, de_int64 key)
{
	struct de_inthashtable_item *p;

	p = bkt->first_item;
	while(p && (p->key != key)) {
		p = p->next;
	}
	return p;
}

// Returns NULL if item does not exist
static struct de_inthashtable_item *inthashtable_find_item(struct de_inthashtable *ht, de_int64 key)
{
	struct de_inthashtable_bucket *bkt;

	if(!ht) return NULL;
	bkt = inthashtable_find_bucket(ht, key);
	return inthashtable_find_item_in_bucket(ht, bkt, key);
}

// If key does not exist, sets *pvalue to NULL and returns 0.
int de_inthashtable_get_item(deark *c, struct de_inthashtable *ht, de_int64 key, void **pvalue)
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

int de_inthashtable_item_exists(deark *c, struct de_inthashtable *ht, de_int64 key)
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
int de_inthashtable_add_item(deark *c, struct de_inthashtable *ht, de_int64 key, void *value)
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

int de_inthashtable_remove_item(deark *c, struct de_inthashtable *ht, de_int64 key, void **pvalue)
{
	// TODO
	return 0;
}

// Select one item arbitrarily, return its key and value, and delete it from the
// hashtable.
int de_inthashtable_remove_any_item(deark *c, struct de_inthashtable *ht, de_int64 *pkey, void **pvalue)
{
	de_int64 i;

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
	de_uint32 val;
	unsigned int crctype;
	deark *c;
	de_uint16 *table16;
};

// This is the CRC-16 algorithm used in MacBinary.
// It is in the x^16 + x^12 + x^5 + 1 family.
// CRC-16-CCITT is probably the best name for it, though I'm not completely
// sure, and there are several algorithms that have been called "CRC-16-CCITT".
static void de_crc16ccitt_init(struct de_crcobj *crco)
{
	const unsigned int polynomial = 0x1021;
	unsigned int index;

	crco->table16 = de_malloc(crco->c, 256*sizeof(de_uint16));
	crco->table16[0] = 0;
	for(index=0; index<128; index++) {
		unsigned int carry = crco->table16[index] & 0x8000;
		unsigned int temp = (crco->table16[index] << 1) & 0xffff;
		crco->table16[index * 2 + (carry ? 0 : 1)] = temp ^ polynomial;
		crco->table16[index * 2 + (carry ? 1 : 0)] = temp;
	}
}

static void de_crc16ccitt_continue(struct de_crcobj *crco, const de_byte *buf, de_int64 buf_len)
{
	de_int64 k;

	if(!crco->table16) return;
	for(k=0; k<buf_len; k++) {
		crco->val = ((crco->val<<8)&0xffff) ^
			(de_uint32)crco->table16[((crco->val>>8) ^ (de_uint32)buf[k]) & 0xff];
	}
}

// This is the CRC-16 algorithm used in ARC, LHA, ZOO, etc.
// It is in the x^16 + x^15 + x^2 + 1 family.
// It's some variant of CRC-16-IBM, and sometimes simply called "CRC-16". But
// both these names are more ambiguous than I'd like, so I'm calling it "ARC".
static void de_crc16arc_init(struct de_crcobj *crco)
{
	de_uint32 i, k;

	crco->table16 = de_malloc(crco->c, 256*sizeof(de_uint16));
	for(i=0; i<256; i++) {
		crco->table16[i] = i;
		for(k=0; k<8; k++)
			crco->table16[i] = (crco->table16[i]>>1) ^ ((crco->table16[i] & 1) ? 0xa001 : 0);
	}
}

static void de_crc16arc_continue(struct de_crcobj *crco, const de_byte *buf, de_int64 buf_len)
{
	de_int64 k;

	if(!crco->table16) return;
	for(k=0; k<buf_len; k++) {
		crco->val = ((crco->val>>8) ^
			(de_uint32)crco->table16[(crco->val ^ buf[k]) & 0xff]);
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

de_uint32 de_crcobj_getval(struct de_crcobj *crco)
{
	return crco->val;
}

void de_crcobj_addbuf(struct de_crcobj *crco, const de_byte *buf, de_int64 buf_len)
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

void de_crcobj_addbyte(struct de_crcobj *crco, de_byte b)
{
	de_crcobj_addbuf(crco, &b, 1);
}

static int addslice_cbfn(deark *c, void *userdata, const de_byte *buf,
	de_int64 buf_len)
{
	de_crcobj_addbuf((struct de_crcobj*)userdata, buf, buf_len);
	return 1;
}

void de_crcobj_addslice(struct de_crcobj *crco, dbuf *f, de_int64 pos, de_int64 len)
{
	dbuf_buffered_read(f, pos, len, addslice_cbfn, (void*)crco);
}
