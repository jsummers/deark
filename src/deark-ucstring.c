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
void ucstring_truncate(de_ucstring *s, i64 newlen)
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
	i64 i;

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
	i64 i;

	if(!s2) return;
	// TODO: This could be done more efficiently.
	for(i=0; i<s2->len; i++) {
		ucstring_append_char(s1, s2->str[i]);
	}
}

void ucstring_vprintf(de_ucstring *s, de_ext_encoding ee, const char *fmt, va_list ap)
{
	char buf[1024];
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	ucstring_append_sz(s, buf, ee);
}

// Appends a formatted C-style string.
// (Unfortunately, there is no format specifier for a ucstring.)
// There is a limit to how many characters will be appended.
void ucstring_printf(de_ucstring *s, de_ext_encoding ee, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ucstring_vprintf(s, ee, fmt, ap);
	va_end(ap);
}

de_ucstring *ucstring_clone(const de_ucstring *src)
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

int ucstring_isempty(const de_ucstring *s)
{
	if(!s) return 1;
	return (s->len == 0);
}

int ucstring_isnonempty(const de_ucstring *s)
{
	return (s && (s->len > 0));
}

void ucstring_append_char(de_ucstring *s, i32 ch)
{
	i64 new_len;
	i64 new_alloc;

	if(s->len >= 100000000) {
		return;
	}
	new_len = s->len + 1;
	if(new_len > s->alloc) {
		new_alloc = s->alloc * 2;
		if(new_alloc<32) new_alloc=32;
		s->str = de_reallocarray(s->c, s->str, s->alloc, sizeof(i32), new_alloc);
		s->alloc = new_alloc;
	}

	s->str[s->len] = ch;
	s->len++;
}

static void handle_invalid_byte(de_ucstring *s, u8 n)
{
	i32 ch;

	ch = DE_CODEPOINT_BYTE00 + (i32)n;
	ucstring_append_char(s, ch);
}

static void handle_invalid_bytes(de_ucstring *s, const u8 *buf, UI buflen)
{
	UI k;

	for(k=0; k<buflen; k++) {
		handle_invalid_byte(s, buf[k]);
	}
}

// This function does no error checking
static i32 decode_utf8_sequence(const u8 *b, UI seqlen)
{
	u32 ch;

	if(seqlen==2) { // 2-byte
		ch = b[0] & 0x1f;
		ch = (ch<<6) | (b[1] & 0x3f);
	}
	else if(seqlen==3) { // 3-byte
		ch = b[0] & 0x0f;
		ch = (ch<<6) | (b[1] & 0x3f);
		ch = (ch<<6) | (b[2] & 0x3f);
	}
	else if(seqlen==4) {
		ch = b[0] & 0x07;
		ch = (ch<<6) | (b[1] & 0x3f);
		ch = (ch<<6) | (b[2] & 0x3f);
		ch = (ch<<6) | (b[3] & 0x3f);
	}
	else {
		ch = b[0];
	}
	return (i32)ch;
}

#define UTF8_NBYTES_EXPECTED (es->buf[7])
#define UTF8_NBYTES_SAVED    (es->buf[6])

static void append_bytes_utf8(de_ucstring *s, const u8 *cbuf, i64 buflen,
	unsigned int conv_flags, struct de_encconv_state *es)
{
	i64 pos;

	for(pos=0; pos<buflen; pos++) {
		u8 n = cbuf[pos];

		if(n>=0x80 && n<=0xbf) { // continuation byte
			if(UTF8_NBYTES_EXPECTED==0) {
				handle_invalid_byte(s, n);
			}
			else { // valid continuation byte
				es->buf[UTF8_NBYTES_SAVED] = n;
				UTF8_NBYTES_SAVED++;
				UTF8_NBYTES_EXPECTED--;
				if(UTF8_NBYTES_EXPECTED==0) {
					ucstring_append_char(s,
						decode_utf8_sequence(es->buf, (UI)UTF8_NBYTES_SAVED));
				}
			}
		}
		else { // not a continuation byte
			// Should not be any pending bytes. If there are, they're invalid.
			if(UTF8_NBYTES_EXPECTED != 0) {
				handle_invalid_bytes(s, es->buf, (UI)UTF8_NBYTES_SAVED);
				UTF8_NBYTES_EXPECTED = 0;
			}

			if(n<=0x7f) {
				ucstring_append_char(s, (i32)n);
				UTF8_NBYTES_EXPECTED = 0; // number of additional continuation bytes expected
			}
			else if(n<=0xdf) { // 2-byte UTF-8 char
				es->buf[0] = n; // save this byte for later
				UTF8_NBYTES_SAVED = 1; // number of bytes saved in buf[0]...buf[3]
				UTF8_NBYTES_EXPECTED = 1; // 1 more byte expected in this sequence
			}
			else if(n<=0xef) { // 3-byte UTF-8 char
				es->buf[0] = n;
				UTF8_NBYTES_SAVED = 1;
				UTF8_NBYTES_EXPECTED = 2;
			}
			else if(n<=0xf7) { // 4-byte UTF-8 char
				es->buf[0] = n;
				UTF8_NBYTES_SAVED = 1;
				UTF8_NBYTES_EXPECTED = 3;
			}
			else {
				handle_invalid_byte(s, n);
				UTF8_NBYTES_EXPECTED = 0;
			}
		}
	}

	// Check if there are unprocessed bytes at the end of the string, when there
	// shouldn't be.
	if(UTF8_NBYTES_EXPECTED!=0 && !(conv_flags & DE_CONVFLAG_PARTIAL_DATA)) {
		handle_invalid_bytes(s, es->buf, (UI)UTF8_NBYTES_SAVED);
		UTF8_NBYTES_EXPECTED = 0;
	}
}

#undef UTF8_NBYTES_EXPECTED
#undef UTF8_NBYTES_SAVED

#define UTF16_NBYTES_SAVED    (es->buf[7])

static i64 getu16x_direct(const u8 *m, int is_le)
{
	if(is_le)
		return de_getu16le_direct(m);
	return de_getu16be_direct(m);
}

static void append_bytes_utf16(de_ucstring *s, const u8 *cbuf, i64 buflen,
	unsigned int conv_flags, struct de_encconv_state *es, int is_le)
{
	i64 pos = 0;
	i32 ch;

	for(pos=0; pos<buflen; pos++) {
		u8 n = cbuf[pos];

		es->buf[UTF16_NBYTES_SAVED] = n;
		UTF16_NBYTES_SAVED++;

		if(UTF16_NBYTES_SAVED==2) {
			ch = (i32)getu16x_direct(es->buf, is_le);
			if(ch>=0xd800 && ch<0xdc00) {
				; // lead surrogate; do nothing
			}
			else if(ch>=0xdc00 && ch<0xe000) {
				// trail surrogate, shouldn't be here
				ucstring_append_char(s, 0xfffd);
				UTF16_NBYTES_SAVED = 0;
			}
			else { // non-surrogate
				ucstring_append_char(s, ch);
				UTF16_NBYTES_SAVED = 0;
			}
		}
		else if(UTF16_NBYTES_SAVED>=4) { // >4 is impossible
			i32 ch2;

			ch = (i32)getu16x_direct(es->buf, is_le);
			ch2 = (i32)getu16x_direct(&es->buf[2], is_le);

			if(ch2>=0xd800 && ch2<0xdc00) {
				; // lead surrogate immediately following another lead surrogate
				ucstring_append_char(s, 0xfffd);
				es->buf[0] = es->buf[2];
				es->buf[1] = es->buf[3];
				UTF16_NBYTES_SAVED = 2;
			}
			else if(ch2>=0xdc00 && ch2<0xe000) {
				// well-formed surrogate pair
				ucstring_append_char(s, 0x10000 + (((ch-0xd800)<<10) | (ch2-0xdc00)));
				UTF16_NBYTES_SAVED = 0;
			}
			else { // non-surrogate immediately following a lead surrogate
				ucstring_append_char(s, 0xfffd);
				ucstring_append_char(s, ch2);
				UTF16_NBYTES_SAVED = 0;
			}

		}
	}

	// Check if there are unprocessed bytes at the end of the string, when there
	// shouldn't be.
	if(UTF16_NBYTES_SAVED!=0 && !(conv_flags & DE_CONVFLAG_PARTIAL_DATA)) {
		ucstring_append_char(s, 0xfffd);
		UTF16_NBYTES_SAVED = 0;
	}
}

#undef  UTF16_NBYTES_SAVED

// conv_flags:
//  DE_CONVFLAG_PARTIAL_DATA: There might be more data after this; if 'buf' ends
//   in a way it shouldn't, it's not necessarily an error.
void ucstring_append_bytes_ex(de_ucstring *s, const u8 *buf, i64 buflen,
	unsigned int conv_flags, struct de_encconv_state *es)
{
	de_encoding encoding = DE_EXTENC_GET_BASE(es->ee);

	// Adjust buflen if necessary.
	if(conv_flags & DE_CONVFLAG_STOP_AT_NUL) {
		char *tmpp;
		tmpp = de_memchr(buf, 0, (size_t)buflen);
		if(tmpp) {
			buflen = (const u8*)tmpp - buf;
		}
	}

	if(encoding==DE_ENCODING_UTF8) {
		append_bytes_utf8(s, buf, buflen, conv_flags, es);
	}
	else if(encoding==DE_ENCODING_UTF16LE || encoding==DE_ENCODING_UTF16BE) {
		append_bytes_utf16(s, buf, buflen, conv_flags, es, (encoding==DE_ENCODING_UTF16LE));
	}
	else {
		i64 pos;

		for(pos=0; pos<buflen; pos++) {
			i32 ch;

			ch = de_char_to_unicode(s->c, buf[pos], es->ee);
			if(ch==DE_CODEPOINT_INVALID) {
				handle_invalid_byte(s, buf[pos]);
			}
			else {
				ucstring_append_char(s, ch);
			}
		}
	}
}

void de_encconv_init(struct de_encconv_state *es, de_ext_encoding ee)
{
	de_zeromem(es, sizeof(struct de_encconv_state));
	es->ee = ee;
}

void ucstring_append_bytes(de_ucstring *s, const u8 *buf, i64 buflen,
	unsigned int conv_flags, de_ext_encoding ee)
{
	struct de_encconv_state es;

	de_encconv_init(&es, ee);
	ucstring_append_bytes_ex(s, buf, buflen, conv_flags, &es);
}

void ucstring_append_sz(de_ucstring *s, const char *sz, de_ext_encoding ee)
{
	i64 len;
	len = (i64)de_strlen(sz);
	ucstring_append_bytes(s, (const u8*)sz, len, 0, ee);
}

static int ucstring_is_ascii(const de_ucstring *s)
{
	i64 i;
	for(i=0; i<s->len; i++) {
		if(s->str[i]<0 || s->str[i]>=0x80)
			return 0;
	}
	return 1;
}

i64 ucstring_count_utf8_bytes(de_ucstring *s)
{
	i64 i;
	i64 n = 0;
	if(!s) return n;
	for(i=0; i<s->len; i++) {
		if(s->str[i]<0 || s->str[i]>0xffff) n+=4;
		else if(s->str[i]<=0x7f) n+=1;
		else if(s->str[i]<=0x7ff) n+=2;
		else n+=3;
	}
	return n;
}

// If add_bom_if_needed is set, we'll prepend a BOM if the global c->write_bom
// option is enabled, and 's' has any non-ASCII characters, and 's' doesn't already
// start with a BOM.
void ucstring_write_as_utf8(deark *c, de_ucstring *s, dbuf *outf, int add_bom_if_needed)
{
	i64 i;

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
// TODO: Should we remove the 'encoding' param, and always assume UTF-8?
void ucstring_to_sz(de_ucstring *s, char *szbuf, size_t szbuf_len,
	unsigned int flags, de_ext_encoding ee)
{
	i64 i;
	i64 szpos = 0;
	i32 ch;
	i64 charcodelen;
	de_encoding encoding = DE_EXTENC_GET_BASE(ee);
	static const char *sc1 = "\x01<"; // DE_CODEPOINT_HL in UTF-8
	static const char *sc2 = ">\x02"; // DE_CODEPOINT_UNHL
	u8 charcodebuf[32];

	if(szbuf_len<1) return;

	for(i=0; i<s->len; i++) {
		ch = s->str[i];
		if(encoding==DE_ENCODING_UTF8) {
			de_uchar_to_utf8(ch, charcodebuf, &charcodelen);
		}
		else { // DE_ENCODING_LATIN1 or DE_ENCODING_ASCII
			// TODO: This may not work right if DE_CONVFLAG_MAKE_PRINTABLE is used,
			// but currently that never happens.
			if(ch>=0 && ch<=(encoding==DE_ENCODING_LATIN1?255:127))
				charcodebuf[0] = (u8)ch;
			else
				charcodebuf[0] = '_';
			charcodelen = 1;
		}

		if(flags & DE_CONVFLAG_MAKE_PRINTABLE) {
			// TODO: This is slightly inefficient, because we're overwriting the
			// conversion we already did.
			if(!de_is_printable_uchar(ch)) {
				if(ch==0x0a) {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf),
						"%s\\n%s", sc1, sc2);
				}
				else if(ch==0x0d) {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf),
						"%s\\r%s", sc1, sc2);
				}
				else if(ch==0x09) {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf),
						"%s\\t%s", sc1, sc2);
				}
				else if(ch==0x00) {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf),
						"%s\\0%s", sc1, sc2);
				}
				else if(ch>=DE_CODEPOINT_BYTE00 && ch<=DE_CODEPOINT_BYTEFF) {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf), "%s%02X%s",
						sc1, (int)(ch-DE_CODEPOINT_BYTE00), sc2);
				}
				else {
					de_snprintf((char*)charcodebuf, sizeof(charcodebuf),
						"%sU+%04X%s", sc1, (unsigned int)ch, sc2);
				}
				charcodelen = (i64)de_strlen((const char*)charcodebuf);
			}
		}

		if(szpos + charcodelen + 1 > (i64)szbuf_len) break;
		if(charcodelen==1) {
			szbuf[szpos] = charcodebuf[0];
		}
		else {
			de_memcpy(&szbuf[szpos], charcodebuf, (size_t)charcodelen);
		}
		szpos += charcodelen;
	}

	szbuf[szpos] = '\0';
}

// Try to determine if a Unicode codepoint (presumed to be from an untrusted source)
// is "safe" to print to a terminal.
// We try to ban control characters, formatting characters, private-use characters,
// and noncharacters.
// It would be good to also ban incorrectly-used "combining" and other context-
// sensitive characters, but that's too difficult.
int de_is_printable_uchar(i32 ch)
{
	struct pr_range { i32 n1, n2; };
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
		{ 0x1f000, 0x1fbff }
		// TODO: Whitelist more codepoints
	};
	size_t i;
	const size_t num_ranges = DE_ARRAYCOUNT(ranges);

	for(i=0; i<num_ranges; i++) {
		if(ch>=ranges[i].n1 && ch<=ranges[i].n2) return 1;
	}
	return 0;
}

static const char *ucstring_getpsz_internal(de_ucstring *s,
	int has_max, i64 max_bytes)
{
	i64 allocsize;

	if(!s) {
		if(has_max && max_bytes<6) return "";
		return "(null)";
	}

	if(has_max) {
		allocsize = max_bytes + 1;
	}
	else {
		// TODO: Calculating the proper allocsize could be difficult,
		// depending on how DE_CONVFLAG_MAKE_PRINTABLE is implemented.
		allocsize = s->len * 4 + 1 + 100;
	}

	if(s->tmp_string)
		de_free(s->c, s->tmp_string);
	s->tmp_string = de_malloc(s->c, allocsize);

	ucstring_to_sz(s, s->tmp_string, (size_t)allocsize, DE_CONVFLAG_MAKE_PRINTABLE, DE_ENCODING_UTF8);

	return s->tmp_string;
}

const char *ucstring_getpsz(de_ucstring *s)
{
	return ucstring_getpsz_internal(s, 0, 0);
}

// It might make more sense to limit the number of visible characters, instead
// of the number of bytes in the encoded string, but that's too difficult.
const char *ucstring_getpsz_n(de_ucstring *s, i64 max_bytes)
{
	return ucstring_getpsz_internal(s, 1, max_bytes);
}

const char *ucstring_getpsz_d(de_ucstring *s)
{
	return ucstring_getpsz_internal(s, 1, DE_DBG_MAX_STRLEN);
}

void ucstring_append_flags_item(de_ucstring *s, const char *str)
{
	ucstring_printf(s, DE_ENCODING_UTF8, "%s%s", (s->len>0)?" | ":"", str);
}

void ucstring_append_flags_itemf(de_ucstring *s, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);
	de_vsnprintf(buf, sizeof(buf), fmt, ap);
	ucstring_append_flags_item(s, buf);
	va_end(ap);
}

// strarray: A mini library, intended mainly to help manage directory paths.

struct de_strarray {
	deark *c;
	size_t max_elems;
	size_t count;
	size_t num_alloc;
	de_ucstring **ss; // array of 'num_alloc' ucstring pointers
};

struct de_strarray *de_strarray_create(deark *c, size_t max_elems)
{
	struct de_strarray *sa;
	sa = de_malloc(c, sizeof(struct de_strarray));
	sa->c = c;
	sa->max_elems = max_elems;
	return sa;
}

void de_strarray_destroy(struct de_strarray *sa)
{
	deark *c;

	if(!sa) return;
	c = sa->c;
	while(sa->count>0) {
		de_strarray_pop(sa);
	}
	de_free(c, sa->ss);
	de_free(c, sa);
}

// This makes a copy of 's'. The caller still owns 's'.
int de_strarray_push(struct de_strarray *sa, de_ucstring *s)
{
	deark *c = sa->c;
	size_t newidx = sa->count;

	if(sa->count >= sa->max_elems) return 0;
	if(newidx >= sa->num_alloc) {
		size_t old_num_alloc = sa->num_alloc;
		sa->num_alloc *= 2;
		if(sa->num_alloc<8) sa->num_alloc=8;
		sa->ss = de_reallocarray(c, sa->ss, old_num_alloc, sizeof(de_ucstring*),
			sa->num_alloc);
	}
	sa->ss[newidx] = ucstring_clone(s);
	sa->count++;
	return 1;
}

int de_strarray_pop(struct de_strarray *sa)
{
	if(sa->count<1) return 0;
	ucstring_destroy(sa->ss[sa->count-1]);
	sa->ss[sa->count-1] = NULL;
	sa->count--;
	return 1;
}

// Replace slashes in a string, starting at the given position.
static void mp_squash_slashes(de_ucstring *s, i64 pos1)
{
	i64 i;

	for(i=pos1; i<s->len; i++) {
		if(s->str[i]=='/') {
			s->str[i] = '_';
		}
	}
}

// Caller allocates 'path' to receive the path.
void de_strarray_make_path(struct de_strarray *sa, de_ucstring *path, unsigned int flags)
{
	size_t i;

	for(i=0; i<sa->count; i++) {
		i64 oldlen = path->len;

		if(ucstring_isnonempty(sa->ss[i])) {
			ucstring_append_ucstring(path, sa->ss[i]);
		}
		else {
			ucstring_append_char(path, '_');
		}

		mp_squash_slashes(path, oldlen);
		if((i+1 < sa->count) || !(flags & DE_MPFLAG_NOTRAILINGSLASH)) {
			ucstring_append_char(path, '/');
		}
	}
}
