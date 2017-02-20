// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Implementation of de_ucstring Unicode string object

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#include "deark-private.h"

// de_ucstring is a Unicode (utf-32) string object.
de_ucstring *ucstring_create(deark *c)
{
	de_ucstring *s;
	s = de_malloc(c, sizeof(de_ucstring));
	s->c = c;
	return s;
}

void ucstring_empty(de_ucstring *s)
{
	ucstring_truncate(s, 0);
}

// Reduce the string's length to newlen, by deleting the characters after
// that point.
// 'newlen' is expected to be no larger than the string's current length.
void ucstring_truncate(de_ucstring *s, de_int64 newlen)
{
	if(!s) return;
	if(newlen<0) newlen=0;
	if(newlen<s->len) s->len = newlen;

	if(s->tmp_string) {
		// There's no requirement to free tmp_string here, but it's no
		// longer needed, and maybe it's nice to have a way to do it.
		de_free(s->c, s->tmp_string);
		s->tmp_string = NULL;
	}
}

// Delete the first U+0000 character, and everything after it.
void ucstring_truncate_at_NUL(de_ucstring *s)
{
	de_int64 i;

	for(i=0; i<s->len; i++) {
		if(s->str[i]==0x0000) {
			ucstring_truncate(s, i);
			return;
		}
	}
}

// If the string ends with U+0000, delete that character.
// If not, do nothing.
void ucstring_strip_trailing_NUL(de_ucstring *s)
{
	if(s->len>=1 && s->str[s->len-1]==0x0000) {
		ucstring_truncate(s, s->len-1);
	}
}

void ucstring_strip_trailing_spaces(de_ucstring *s)
{
	while(s->len>=1 && s->str[s->len-1]==' ') {
		ucstring_truncate(s, s->len-1);
	}
}

// Append s2 to s1
void ucstring_append_ucstring(de_ucstring *s1, const de_ucstring *s2)
{
	de_int64 i;

	if(!s2) return;
	// TODO: This could be done more efficiently.
	for(i=0; i<s2->len; i++) {
		ucstring_append_char(s1, s2->str[i]);
	}
}

static void ucstring_vprintf(de_ucstring *s, int encoding, const char *fmt, va_list ap)
{
	char buf[1024];
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	ucstring_append_sz(s, buf, encoding);
}

// Appends a formatted C-style string.
// (Unfortunately, there is no format specifier for a ucstring.)
// There is a limit to how many characters will be appended.
void ucstring_printf(de_ucstring *s, int encoding, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ucstring_vprintf(s, encoding, fmt, ap);
	va_end(ap);
}

de_ucstring *ucstring_clone(de_ucstring *src)
{
	de_ucstring *dst;

	if(!src) return NULL;
	dst = ucstring_create(src->c);
	ucstring_append_ucstring(dst, src);
	return dst;
}

void ucstring_destroy(de_ucstring *s)
{
	deark *c;
	if(s) {
		c = s->c;
		de_free(c, s->str);
		de_free(c, s->tmp_string);
		de_free(c, s);
	}
}

void ucstring_append_char(de_ucstring *s, de_int32 ch)
{
	de_int64 new_len;
	de_int64 new_alloc;

	if(s->len >= 100000000) {
		return;
	}
	new_len = s->len + 1;
	if(new_len > s->alloc) {
		new_alloc = s->alloc * 2;
		if(new_alloc<32) new_alloc=32;

		s->str = de_realloc(s->c, s->str, s->alloc * sizeof(de_int32), new_alloc * sizeof(de_int32));
		s->alloc = new_alloc;
	}

	s->str[s->len] = ch;
	s->len++;
}

void ucstring_append_bytes(de_ucstring *s, const de_byte *buf, de_int64 buflen,
	unsigned int conv_flags, int encoding)
{
	int ret;
	de_int64 pos = 0;
	de_int32 ch;
	de_int64 code_len;

	// Adjust buflen if necessary.
	if(conv_flags & DE_CONVFLAG_STOP_AT_NUL) {
		char *tmpp;
		tmpp = de_memchr(buf, 0, (size_t)buflen);
		if(tmpp) {
			buflen = (const de_byte*)tmpp - buf;
		}
	}

	while(pos<buflen) {
		if(encoding==DE_ENCODING_UTF8) {
			ret = de_utf8_to_uchar(&buf[pos], buflen-pos, &ch, &code_len);
			if(!ret) {
				ch = '_';
				code_len = 1;
			}
		}
		else if(encoding==DE_ENCODING_UTF16LE) {
			ret = de_utf16x_to_uchar(&buf[pos], buflen-pos, &ch, &code_len, 1);
			if(!ret) {
				ch = '_';
				code_len = 2;
			}
		}
		else if(encoding==DE_ENCODING_UTF16BE) {
			ret = de_utf16x_to_uchar(&buf[pos], buflen-pos, &ch, &code_len, 0);
			if(!ret) {
				ch = '_';
				code_len = 2;
			}
		}
		else {
			ch = de_char_to_unicode(s->c, buf[pos], encoding);
			if(ch==DE_INVALID_CODEPOINT) {
				ch = '_';
			}
			code_len = 1;
		}
		ucstring_append_char(s, ch);
		pos += code_len;
	}
}

void ucstring_append_sz(de_ucstring *s, const char *sz, int encoding)
{
	de_int64 len;
	len = (de_int64)de_strlen(sz);
	ucstring_append_bytes(s, (const de_byte*)sz, len, 0, encoding);
}

static int ucstring_is_ascii(const de_ucstring *s)
{
	de_int64 i;
	for(i=0; i<s->len; i++) {
		if(s->str[i]<0 || s->str[i]>=0x80)
			return 0;
	}
	return 1;
}

// If add_bom_if_needed is set, we'll prepend a BOM if the global c->write_bom
// option is enabled, 's' has any non-ASCII characters, and 's' doesn't already
// start with a BOM.
void ucstring_write_as_utf8(deark *c, de_ucstring *s, dbuf *outf, int add_bom_if_needed)
{
	de_int64 i;

	if(add_bom_if_needed &&
		c->write_bom &&
		(s->len>0 && s->str[0]!=0xfeff) &&
		!ucstring_is_ascii(s))
	{
		// Write a BOM
		dbuf_write_uchar_as_utf8(outf, 0xfeff);
	}

	for(i=0; i<s->len; i++) {
		dbuf_write_uchar_as_utf8(outf, s->str[i]);
	}
}

// Note: This function is similar to de_finfo_set_name_from_ucstring().
// Maybe they should be consolidated.
void ucstring_to_sz(de_ucstring *s, char *szbuf, size_t szbuf_len, int encoding)
{
	de_int64 i;
	de_int64 szpos = 0;
	de_byte utf8buf[4];
	de_int64 utf8codelen;

	if(szbuf_len<1) return;

	for(i=0; i<s->len; i++) {
		if(encoding==DE_ENCODING_UTF8) {
			de_uchar_to_utf8(s->str[i], utf8buf, &utf8codelen);
		}
		else { // DE_ENCODING_LATIN1 or DE_ENCODING_ASCII
			if(s->str[i]>=0 && s->str[i]<=(encoding==DE_ENCODING_LATIN1?255:127))
				utf8buf[0] = (de_byte)s->str[i];
			else
				utf8buf[0] = '_';
			utf8codelen = 1;
		}
		if(szpos + utf8codelen + 1 > (de_int64)szbuf_len) break;
		de_memcpy(&szbuf[szpos], utf8buf, (size_t)utf8codelen);
		szpos += utf8codelen;
	}

	szbuf[szpos] = '\0';
}

// If has_max!=0, uses no more than max_chars Unicode characters from s to create the
// printable string.
static void ucstring_to_printable_sz_internal(de_ucstring *s, char *szbuf, size_t szbuf_len,
	int has_max, de_int64 max_chars)
{
	de_ucstring *s2 = NULL;

	s2 = ucstring_clone(s);
	if(has_max) {
		// TODO: Maybe this should add an ellipsis, or something.
		ucstring_truncate(s2, max_chars);
	}
	ucstring_make_printable(s2);
	ucstring_to_sz(s2, szbuf, szbuf_len, DE_ENCODING_UTF8);
	ucstring_destroy(s2);
}

void ucstring_to_printable_sz(de_ucstring *s, char *szbuf, size_t szbuf_len)
{
	ucstring_to_printable_sz_internal(s, szbuf, szbuf_len, 0, 0);
}

int ucstring_strcmp(de_ucstring *s, const char *s2, int encoding)
{
	size_t s2len;
	char *tmpbuf;
	int ret;

	if(!s && !s2) return 0;
	if(!s || !s2) return 1;

	s2len = de_strlen(s2);
	tmpbuf = de_malloc(s->c, s2len+1);
	ucstring_to_sz(s, tmpbuf, s2len+1, encoding);
	ret = de_strcmp(tmpbuf, tmpbuf);
	de_free(s->c, tmpbuf);
	return ret;
}

// Try to determine if a Unicode codepoint (presumed to be from an untrusted source)
// is "safe" to print to a terminal.
// We try to ban control characters, formatting characters, private-use characters,
// and noncharacters.
// It would be good to also ban incorrectly-used "combining" and other context-
// sensitive characters, but that's too difficult.
static int is_printable_uchar(de_int32 ch)
{
	struct pr_range { de_int32 n1, n2; };
	static const struct pr_range ranges[] = {
		{ 0x0020, 0x007e },
		{ 0x00a0, 0x200d },
		{ 0x2010, 0x2027 },
		{ 0x202f, 0x2065 },
		{ 0x2070, 0xd7ff },
		{ 0xf900, 0xfdcf },
		{ 0xfdf0, 0xfdff },
		{ 0xfe10, 0xfefe },
		{ 0xff00, 0xffef },
		{ 0xfffd, 0xfffd },
		{ 0x10000, 0x101ff },
		{ 0x1f000, 0x1f9ff }
		// TODO: Whitelist more codepoints
	};
	size_t i;
	const size_t num_ranges = DE_ITEMS_IN_ARRAY(ranges);

	for(i=0; i<num_ranges; i++) {
		if(ch>=ranges[i].n1 && ch<=ranges[i].n2) return 1;
	}
	return 0;
}

void ucstring_make_printable(de_ucstring *s)
{
	de_int64 i;

	for(i=0; i<s->len; i++) {
		if(!is_printable_uchar(s->str[i])) {
			s->str[i] = '_';
		}
	}
}

static const char *ucstring_get_printable_sz_internal(de_ucstring *s,
	int has_max, de_int64 max_chars)
{
	de_int64 allocsize;

	if(!s) return "(null)";

	if(s->tmp_string)
		de_free(s->c, s->tmp_string);

	if(has_max)
		allocsize = max_chars * 4 + 1;
	else
		allocsize = s->len * 4 + 1;

	s->tmp_string = de_malloc(s->c, allocsize);

	ucstring_to_printable_sz_internal(s, s->tmp_string, (size_t)allocsize, has_max, max_chars);

	return s->tmp_string;
}

const char *ucstring_get_printable_sz(de_ucstring *s)
{
	return ucstring_get_printable_sz_internal(s, 0, 0);
}

const char *ucstring_get_printable_sz_n(de_ucstring *s, de_int64 max_chars)
{
	return ucstring_get_printable_sz_internal(s, 1, max_chars);
}
