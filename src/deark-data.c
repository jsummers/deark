// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.
// The tables of data contained in this file are not necessarily public domain.

// deark-data.c
//
// Data lookup and conversion.

#include "deark-config.h"

#include "deark-private.h"

static const char *g_hexchars = "0123456789abcdef";

static int is_printable_uchar(de_int32 ch);

char de_get_hexchar(int n)
{
	if(n>=0 && n<16) return g_hexchars[n];
	return '0';
}

de_byte de_decode_hex_digit(de_byte x, int *errorflag)
{
	if(errorflag) *errorflag = 0;
	if(x>='0' && x<='9') return x-48;
	if(x>='A' && x<='F') return x-55;
	if(x>='a' && x<='f') return x-87;
	if(errorflag) *errorflag = 1;
	return 0;
}

static const de_uint16 cp437table[256] = {
	0x00a0,0x263a,0x263b,0x2665,0x2666,0x2663,0x2660,0x2022,0x25d8,0x25cb,0x25d9,0x2642,0x2640,0x266a,0x266b,0x263c,
	0x25ba,0x25c4,0x2195,0x203c,0x00b6,0x00a7,0x25ac,0x21a8,0x2191,0x2193,0x2192,0x2190,0x221f,0x2194,0x25b2,0x25bc,
	0x0020,0x0021,0x0022,0x0023,0x0024,0x0025,0x0026,0x0027,0x0028,0x0029,0x002a,0x002b,0x002c,0x002d,0x002e,0x002f,
	0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,0x0038,0x0039,0x003a,0x003b,0x003c,0x003d,0x003e,0x003f,
	0x0040,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,0x0049,0x004a,0x004b,0x004c,0x004d,0x004e,0x004f,
	0x0050,0x0051,0x0052,0x0053,0x0054,0x0055,0x0056,0x0057,0x0058,0x0059,0x005a,0x005b,0x005c,0x005d,0x005e,0x005f,
	0x0060,0x0061,0x0062,0x0063,0x0064,0x0065,0x0066,0x0067,0x0068,0x0069,0x006a,0x006b,0x006c,0x006d,0x006e,0x006f,
	0x0070,0x0071,0x0072,0x0073,0x0074,0x0075,0x0076,0x0077,0x0078,0x0079,0x007a,0x007b,0x007c,0x007d,0x007e,0x2302,
	0x00c7,0x00fc,0x00e9,0x00e2,0x00e4,0x00e0,0x00e5,0x00e7,0x00ea,0x00eb,0x00e8,0x00ef,0x00ee,0x00ec,0x00c4,0x00c5,
	0x00c9,0x00e6,0x00c6,0x00f4,0x00f6,0x00f2,0x00fb,0x00f9,0x00ff,0x00d6,0x00dc,0x00a2,0x00a3,0x00a5,0x20a7,0x0192,
	0x00e1,0x00ed,0x00f3,0x00fa,0x00f1,0x00d1,0x00aa,0x00ba,0x00bf,0x2310,0x00ac,0x00bd,0x00bc,0x00a1,0x00ab,0x00bb,
	0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255d,0x255c,0x255b,0x2510,
	0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x255e,0x255f,0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x2567,
	0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256b,0x256a,0x2518,0x250c,0x2588,0x2584,0x258c,0x2590,0x2580,
	0x03b1,0x00df,0x0393,0x03c0,0x03a3,0x03c3,0x00b5,0x03c4,0x03a6,0x0398,0x03a9,0x03b4,0x221e,0x03c6,0x03b5,0x2229,
	0x2261,0x00b1,0x2265,0x2264,0x2320,0x2321,0x00f7,0x2248,0x00b0,0x2219,0x00b7,0x221a,0x207f,0x00b2,0x25a0,0x00a0
};

static const de_uint16 windows1252table[32] = {
	0x20ac,0xffff,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0x02c6,0x2030,0x0160,0x2039,0x0152,0xffff,0x017d,0xffff,
	0xffff,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0x02dc,0x2122,0x0161,0x203a,0x0153,0xffff,0x017e,0x0178
};

static const de_uint16 petscii1table[256] = {
	0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x000d,0x000e,0xffff,
	0xffff,0xffff,0xffff,0xffff,0x007f,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,
	0x0020,0x0021,0x0022,0x0023,0x0024,0x0025,0x0026,0x0027,0x0028,0x0029,0x002a,0x002b,0x002c,0x002d,0x002e,0x002f,
	0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,0x0038,0x0039,0x003a,0x003b,0x003c,0x003d,0x003e,0x003f,
	0x0040,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,0x0049,0x004a,0x004b,0x004c,0x004d,0x004e,0x004f,
	0x0050,0x0051,0x0052,0x0053,0x0054,0x0055,0x0056,0x0057,0x0058,0x0059,0x005a,0x005b,0x00a3,0x005d,0x2191,0x2190,
	0x2500,0x2660,0x2502,0x2500,0xffff,0xffff,0xffff,0xffff,0xffff,0x256e,0x2570,0x256f,0xffff,0x2572,0x2571,0xffff,
	0xffff,0x25cf,0xffff,0x2665,0xffff,0x256d,0x2573,0x25cb,0x2663,0xffff,0x2666,0x253c,0xffff,0x2502,0x03c0,0x25e5,
	0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x000a,0x000f,0xffff,
	0xffff,0xffff,0xffff,0x000c,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x0008,0xffff,0xffff,
	0x00a0,0x258c,0x2584,0x2594,0x2581,0x258e,0x2592,0xffff,0xffff,0x25e4,0xffff,0x251c,0x2597,0x2514,0x2510,0x2582,
	0x250c,0x2534,0x252c,0x2524,0x258e,0x258d,0xffff,0xffff,0xffff,0x2583,0xffff,0x2596,0x259d,0x2518,0x2598,0x259a,
	0x2500,0x2660,0x2502,0x2500,0xffff,0xffff,0xffff,0xffff,0xffff,0x256e,0x2570,0x256f,0xffff,0x2572,0x2571,0xffff,
	0xffff,0x25cf,0xffff,0x2665,0xffff,0x256d,0x2573,0x25cb,0x2663,0xffff,0x2666,0x253c,0xffff,0x2502,0x03c0,0x25e5,
	0x00a0,0x258c,0x2584,0x2594,0x2581,0x258e,0x2592,0xffff,0xffff,0x25e4,0xffff,0x251c,0x2597,0x2514,0x2510,0x2582,
	0x250c,0x2534,0x252c,0x2524,0x258e,0x258d,0xffff,0xffff,0xffff,0x2583,0xffff,0x2596,0x259d,0x2518,0x2598,0x03c0
};

// Derived from VT100 Series Technical manual, Table A-9: Special Graphics Characters (p. A-12)
static const de_uint16 decspecialgraphicstable[32] = {
	0x00a0,0x25c6,0x2592,0x2409,0x240c,0x240d,0x240a,0x00b0,0x00b1,0x2424,0x240b,0x2518,0x2510,0x250c,0x2514,0x253c,
	0x23ba,0x23bb,0x2500,0x23bc,0x23bd,0x251c,0x2524,0x2534,0x252c,0x2502,0x2264,0x2265,0x03c0,0x2260,0x00a3,0x00b7
};

// Code page 437, with screen code graphics characters.
static de_int32 de_cp437g_to_unicode(de_int32 a)
{
	de_int32 n;
	if(a<=0xff) n = (de_int32)cp437table[a];
	else n = DE_INVALID_CODEPOINT;
	if(n==0xffff) n = DE_INVALID_CODEPOINT;
	return n;
}

// Code page 437, with control characters.
static de_int32 de_cp437c_to_unicode(de_int32 a)
{
	de_int32 n;
	if(a<=0x7f) n = a;
	else if(a>=0x080 && a<=0xff) n = (de_int32)cp437table[a];
	else n = DE_INVALID_CODEPOINT;
	if(n==0xffff) n = DE_INVALID_CODEPOINT;
	return n;
}

static de_int32 de_windows1252_to_unicode(de_int32 a)
{
	de_int32 n;
	if(a>=0x80 && a<=0x9f) n = (de_int32)windows1252table[a-0x80];
	else if(a<=0xff) n = a;
	else n = DE_INVALID_CODEPOINT;
	if(n==0xffff) n = DE_INVALID_CODEPOINT;
	return n;
}

static de_int32 de_petscii_to_unicode(de_int32 a)
{
	de_int32 n;
	if(a<=0xff) n = (de_int32)petscii1table[a];
	else n = DE_INVALID_CODEPOINT;
	if(n==0xffff) n = DE_INVALID_CODEPOINT;
	return n;
}

static de_int32 de_decspecialgraphics_to_unicode(de_int32 a)
{
	de_int32 n;
	if(a>=95 && a<=126) n = (de_int32)decspecialgraphicstable[a-95];
	else n = DE_INVALID_CODEPOINT;
	if(n==0xffff) n = DE_INVALID_CODEPOINT;
	return n;
}

de_int32 de_char_to_unicode(deark *c, de_int32 a, int encoding)
{
	if(a<0) return DE_INVALID_CODEPOINT;

	switch(encoding) {
	case DE_ENCODING_ASCII:
		return (a<128)?a:DE_INVALID_CODEPOINT;
	case DE_ENCODING_LATIN1:
		return (a<256)?a:DE_INVALID_CODEPOINT;
	case DE_ENCODING_CP437_G:
		return de_cp437g_to_unicode(a);
	case DE_ENCODING_CP437_C:
		return de_cp437c_to_unicode(a);
	case DE_ENCODING_PETSCII:
		return de_petscii_to_unicode(a);
	case DE_ENCODING_WINDOWS1252:
		return de_windows1252_to_unicode(a);
	case DE_ENCODING_DEC_SPECIAL_GRAPHICS:
		return de_decspecialgraphics_to_unicode(a);
	}
	return a;
}

// Encode a Unicode char in UTF-8.
// Caller supplies utf8buf[4].
// Sets *p_utf8len to the number of bytes used (1-4).
void de_uchar_to_utf8(de_int32 u1, de_byte *utf8buf, de_int64 *p_utf8len)
{
	de_uint32 u = (de_uint32)u1;

	if(u>0x10ffff || u1==DE_INVALID_CODEPOINT) u=0xfffd;

	if(u<=0x7f) {
		*p_utf8len = 1;
		utf8buf[0] = (de_byte)u;
	}
	else if(u>=0x80 && u<=0x7ff) {
		*p_utf8len = 2;
		utf8buf[0] = 0xc0 | (u>>6);
		utf8buf[1] = 0x80 | (u&0x3f);
	}
	else if(u>=0x800 && u<=0xffff) {
		*p_utf8len = 3;
		utf8buf[0] = 0xe0 | (u>>12);
		utf8buf[1] = 0x80 | ((u>>6)&0x3f);
		utf8buf[2] = 0x80 | (u&0x3f);
	}
	else {
		*p_utf8len = 4;
		utf8buf[0] = 0xf0 | (u>>18);
		utf8buf[1] = 0x80 | ((u>>12)&0x3f);
		utf8buf[2] = 0x80 | ((u>>6)&0x3f);
		utf8buf[3] = 0x80 | (u&0x3f);
	}
}

// Write a unicode code point to a file, encoded as UTF-8.
void dbuf_write_uchar_as_utf8(dbuf *outf, de_int32 u)
{
	de_byte utf8buf[4];
	de_int64 utf8len;

	de_uchar_to_utf8(u, utf8buf, &utf8len);
	dbuf_write(outf, utf8buf, utf8len);
}

// Convert a UTF-8 character to UTF-32.
// Returns 1 if a valid character was converted, 0 otherwise.
int de_utf8_to_uchar(const de_byte *utf8buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf8len)
{
	de_int32 u0=0;
	de_int32 u1=0;
	de_int32 u2=0;
	de_int32 u3=0;

	if(buflen<1) return 0;
	u0 = (de_int32)utf8buf[0];
	if(u0<=0x7f) { // 1-byte UTF-8 char
		*p_utf8len = 1;
		*p_uchar = u0;
		return 1;
	}
	if(buflen<2) return 0;
	if((utf8buf[1]&0xc0)!=0x80) return 0;
	u1 = (de_int32)utf8buf[1];
	if(u0<=0xdf) { // 2-byte UTF-8 char
		*p_utf8len = 2;
		*p_uchar = ((u0&0x1f)<<6) | (u1&0x3f);
		return 1;
	}
	if(buflen<3) return 0;
	if((utf8buf[2]&0xc0)!=0x80) return 0;
	u2 = (de_int32)utf8buf[2];
	if(u0<=0xef) { // 3-byte UTF-8 char
		*p_utf8len = 3;
		*p_uchar = ((u0&0x0f)<<12) | ((u1&0x3f)<<6) | (u2&0x3f);
		return 1;
	}
	if(buflen<4) return 0;
	if((utf8buf[3]&0xc0)!=0x80) return 0;
	u3 = (de_int32)utf8buf[3];
	if(u0<=0xf7) { // 4-byte UTF-8 char
		*p_utf8len = 4;
		*p_uchar = ((u0&0x07)<<18) | ((u1&0x3f)<<12) | ((u2&0x3f)<<6) | (u3&0x3f);
		return 1;
	}
	return 0;
}

// Convert a UTF-16LE character to UTF-32.
// Similar to de_utf8_to_uchar().
// Returns 1 if a valid character was converted, 0 otherwise.
int de_utf16le_to_uchar(const de_byte *utf16buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf16len)
{
	de_int32 u0, u1;

	// Read the first code unit
	if(buflen<2) return 0;
	u0 = (de_int32)de_getui16le_direct(&utf16buf[0]);

	if(u0>=0xd800 && u0<=0xdbff) { // It's a lead surrogate
		// Read the trail surrogate
		if(buflen<4) return 0;
		u1 = (de_int32)de_getui16le_direct(&utf16buf[2]);
		if(u1>=0xdc00 && u1<=0xdfff) { // valid trail surrogate
			*p_uchar = 0x10000 + (((u0-0xd800)<<10) | (u1-0xdc00));
			*p_utf16len = 4;
			return 1;
		}
		return 0; // invalid trail surrogate
	}
	else if(u0>=0xdc00 && u0<=0xdfff) {
		// First code unit is not allowed to be a trail surrogate
		return 0;
	}
	// Not a surrogate
	*p_uchar = u0;
	*p_utf16len = 2;
	return 1;
}

// Given a buffer, return 1 if it has no bytes 0x80 or higher.
int de_is_ascii(const de_byte *buf, de_int64 buflen)
{
	de_int64 i;

	for(i=0; i<buflen; i++) {
		if(buf[i]>=128) return 0;
	}
	return 1;
}

static const de_uint32 vga256pal[256] = {
	0x000000,0x0000aa,0x00aa00,0x00aaaa,0xaa0000,0xaa00aa,0xaa5500,0xaaaaaa,
	0x555555,0x5555ff,0x55ff55,0x55ffff,0xff5555,0xff55ff,0xffff55,0xffffff,
	0x000000,0x141414,0x202020,0x2d2d2d,0x393939,0x454545,0x515151,0x616161,
	0x717171,0x828282,0x929292,0xa2a2a2,0xb6b6b6,0xcacaca,0xe3e3e3,0xffffff,
	0x0000ff,0x4100ff,0x7d00ff,0xbe00ff,0xff00ff,0xff00be,0xff007d,0xff0041,
	0xff0000,0xff4100,0xff7d00,0xffbe00,0xffff00,0xbeff00,0x7dff00,0x41ff00,
	0x00ff00,0x00ff41,0x00ff7d,0x00ffbe,0x00ffff,0x00beff,0x007dff,0x0041ff,
	0x7d7dff,0x9e7dff,0xbe7dff,0xdf7dff,0xff7dff,0xff7ddf,0xff7dbe,0xff7d9e,
	0xff7d7d,0xff9e7d,0xffbe7d,0xffdf7d,0xffff7d,0xdfff7d,0xbeff7d,0x9eff7d,
	0x7dff7d,0x7dff9e,0x7dffbe,0x7dffdf,0x7dffff,0x7ddfff,0x7dbeff,0x7d9eff,
	0xb6b6ff,0xc6b6ff,0xdbb6ff,0xebb6ff,0xffb6ff,0xffb6eb,0xffb6db,0xffb6c6,
	0xffb6b6,0xffc6b6,0xffdbb6,0xffebb6,0xffffb6,0xebffb6,0xdbffb6,0xc6ffb6,
	0xb6ffb6,0xb6ffc6,0xb6ffdb,0xb6ffeb,0xb6ffff,0xb6ebff,0xb6dbff,0xb6c6ff,
	0x000071,0x1c0071,0x390071,0x550071,0x710071,0x710055,0x710039,0x71001c,
	0x710000,0x711c00,0x713900,0x715500,0x717100,0x557100,0x397100,0x1c7100,
	0x007100,0x00711c,0x007139,0x007155,0x007171,0x005571,0x003971,0x001c71,
	0x393971,0x453971,0x553971,0x613971,0x713971,0x713961,0x713955,0x713945,
	0x713939,0x714539,0x715539,0x716139,0x717139,0x617139,0x557139,0x457139,
	0x397139,0x397145,0x397155,0x397161,0x397171,0x396171,0x395571,0x394571,
	0x515171,0x595171,0x615171,0x695171,0x715171,0x715169,0x715161,0x715159,
	0x715151,0x715951,0x716151,0x716951,0x717151,0x697151,0x617151,0x597151,
	0x517151,0x517159,0x517161,0x517169,0x517171,0x516971,0x516171,0x515971,
	0x000041,0x100041,0x200041,0x310041,0x410041,0x410031,0x410020,0x410010,
	0x410000,0x411000,0x412000,0x413100,0x414100,0x314100,0x204100,0x104100,
	0x004100,0x004110,0x004120,0x004131,0x004141,0x003141,0x002041,0x001041,
	0x202041,0x282041,0x312041,0x392041,0x412041,0x412039,0x412031,0x412028,
	0x412020,0x412820,0x413120,0x413920,0x414120,0x394120,0x314120,0x284120,
	0x204120,0x204128,0x204131,0x204139,0x204141,0x203941,0x203141,0x202841,
	0x2d2d41,0x312d41,0x352d41,0x3d2d41,0x412d41,0x412d3d,0x412d35,0x412d31,
	0x412d2d,0x41312d,0x41352d,0x413d2d,0x41412d,0x3d412d,0x35412d,0x31412d,
	0x2d412d,0x2d4131,0x2d4135,0x2d413d,0x2d4141,0x2d3d41,0x2d3541,0x2d3141,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000
};

static const de_uint32 ega64pal[64] = {
	0x000000,0x0000aa,0x00aa00,0x00aaaa,0xaa0000,0xaa00aa,0xaaaa00,0xaaaaaa,
	0x000055,0x0000ff,0x00aa55,0x00aaff,0xaa0055,0xaa00ff,0xaaaa55,0xaaaaff,
	0x005500,0x0055aa,0x00ff00,0x00ffaa,0xaa5500,0xaa55aa,0xaaff00,0xaaffaa,
	0x005555,0x0055ff,0x00ff55,0x00ffff,0xaa5555,0xaa55ff,0xaaff55,0xaaffff,
	0x550000,0x5500aa,0x55aa00,0x55aaaa,0xff0000,0xff00aa,0xffaa00,0xffaaaa,
	0x550055,0x5500ff,0x55aa55,0x55aaff,0xff0055,0xff00ff,0xffaa55,0xffaaff,
	0x555500,0x5555aa,0x55ff00,0x55ffaa,0xff5500,0xff55aa,0xffff00,0xffffaa,
	0x555555,0x5555ff,0x55ff55,0x55ffff,0xff5555,0xff55ff,0xffff55,0xffffff
};

static const de_uint32 pc16pal[16] = {
	0x000000,0x0000aa,0x00aa00,0x00aaaa,0xaa0000,0xaa00aa,0xaa5500,0xaaaaaa,
	0x555555,0x5555ff,0x55ff55,0x55ffff,0xff5555,0xff55ff,0xffff55,0xffffff
};


de_uint32 de_palette_vga256(int index)
{
	if(index>=0 && index<256) {
		return vga256pal[index];
	}
	return 0;
}

de_uint32 de_palette_ega64(int index)
{

	if(index>=0 && index<64) {
		return ega64pal[index];
	}
	return 0;
}

de_uint32 de_palette_pc16(int index)
{
	if(index>=0 && index<16) {
		return pc16pal[index];
	}
	return 0;
}

static const de_uint32 pcpaint_cga_pals[6][4] = {
	{ 0x000000, 0x00aaaa, 0xaa00aa, 0xaaaaaa }, // palette 1 low
	{ 0x000000, 0x00aa00, 0xaa0000, 0xaa5500 }, // palette 0 low
	{ 0x000000, 0x00aaaa, 0xaa0000, 0xaaaaaa }, // 3rd palette low
	{ 0x000000, 0x55ffff, 0xff55ff, 0xffffff }, // palette 1 high
	{ 0x000000, 0x55ff55, 0xff5555, 0xffff55 }, // palette 0 high
	{ 0x000000, 0x55ffff, 0xff5555, 0xffffff }  // 3rd palette high
};

de_uint32 de_palette_pcpaint_cga4(int palnum, int index)
{
	if(palnum<0 || palnum>5) palnum=2;
	if(index>=0 && index<4) {
		return pcpaint_cga_pals[palnum][index];
	}
	return 0;
}

static const de_byte vga_cp437_font_data[256*16] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,126,129,165,129,129,189,153,129,129,126,0,0,0,0,
	0,0,126,255,219,255,255,195,231,255,255,126,0,0,0,0,
	0,0,0,0,108,254,254,254,254,124,56,16,0,0,0,0,
	0,0,0,0,16,56,124,254,124,56,16,0,0,0,0,0,
	0,0,0,24,60,60,231,231,231,24,24,60,0,0,0,0,
	0,0,0,24,60,126,255,255,126,24,24,60,0,0,0,0,
	0,0,0,0,0,0,24,60,60,24,0,0,0,0,0,0,
	255,255,255,255,255,255,231,195,195,231,255,255,255,255,255,255,
	0,0,0,0,0,60,102,66,66,102,60,0,0,0,0,0,
	255,255,255,255,255,195,153,189,189,153,195,255,255,255,255,255,
	0,0,30,14,26,50,120,204,204,204,204,120,0,0,0,0,
	0,0,60,102,102,102,102,60,24,126,24,24,0,0,0,0,
	0,0,63,51,63,48,48,48,48,112,240,224,0,0,0,0,
	0,0,127,99,127,99,99,99,99,103,231,230,192,0,0,0,
	0,0,0,24,24,219,60,231,60,219,24,24,0,0,0,0,
	0,128,192,224,240,248,254,248,240,224,192,128,0,0,0,0,
	0,2,6,14,30,62,254,62,30,14,6,2,0,0,0,0,
	0,0,24,60,126,24,24,24,126,60,24,0,0,0,0,0,
	0,0,102,102,102,102,102,102,102,0,102,102,0,0,0,0,
	0,0,127,219,219,219,123,27,27,27,27,27,0,0,0,0,
	0,124,198,96,56,108,198,198,108,56,12,198,124,0,0,0,
	0,0,0,0,0,0,0,0,254,254,254,254,0,0,0,0,
	0,0,24,60,126,24,24,24,126,60,24,126,0,0,0,0,
	0,0,24,60,126,24,24,24,24,24,24,24,0,0,0,0,
	0,0,24,24,24,24,24,24,24,126,60,24,0,0,0,0,
	0,0,0,0,0,24,12,254,12,24,0,0,0,0,0,0,
	0,0,0,0,0,48,96,254,96,48,0,0,0,0,0,0,
	0,0,0,0,0,0,192,192,192,254,0,0,0,0,0,0,
	0,0,0,0,0,40,108,254,108,40,0,0,0,0,0,0,
	0,0,0,0,16,56,56,124,124,254,254,0,0,0,0,0,
	0,0,0,0,254,254,124,124,56,56,16,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,24,60,60,60,24,24,24,0,24,24,0,0,0,0,
	0,102,102,102,36,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,108,108,254,108,108,108,254,108,108,0,0,0,0,
	24,24,124,198,194,192,124,6,6,134,198,124,24,24,0,0,
	0,0,0,0,194,198,12,24,48,96,198,134,0,0,0,0,
	0,0,56,108,108,56,118,220,204,204,204,118,0,0,0,0,
	0,48,48,48,96,0,0,0,0,0,0,0,0,0,0,0,
	0,0,12,24,48,48,48,48,48,48,24,12,0,0,0,0,
	0,0,48,24,12,12,12,12,12,12,24,48,0,0,0,0,
	0,0,0,0,0,102,60,255,60,102,0,0,0,0,0,0,
	0,0,0,0,0,24,24,126,24,24,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,24,24,24,48,0,0,0,
	0,0,0,0,0,0,0,254,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,24,24,0,0,0,0,
	0,0,0,0,2,6,12,24,48,96,192,128,0,0,0,0,
	0,0,56,108,198,198,214,214,198,198,108,56,0,0,0,0,
	0,0,24,56,120,24,24,24,24,24,24,126,0,0,0,0,
	0,0,124,198,6,12,24,48,96,192,198,254,0,0,0,0,
	0,0,124,198,6,6,60,6,6,6,198,124,0,0,0,0,
	0,0,12,28,60,108,204,254,12,12,12,30,0,0,0,0,
	0,0,254,192,192,192,252,6,6,6,198,124,0,0,0,0,
	0,0,56,96,192,192,252,198,198,198,198,124,0,0,0,0,
	0,0,254,198,6,6,12,24,48,48,48,48,0,0,0,0,
	0,0,124,198,198,198,124,198,198,198,198,124,0,0,0,0,
	0,0,124,198,198,198,126,6,6,6,12,120,0,0,0,0,
	0,0,0,0,24,24,0,0,0,24,24,0,0,0,0,0,
	0,0,0,0,24,24,0,0,0,24,24,48,0,0,0,0,
	0,0,0,6,12,24,48,96,48,24,12,6,0,0,0,0,
	0,0,0,0,0,126,0,0,126,0,0,0,0,0,0,0,
	0,0,0,96,48,24,12,6,12,24,48,96,0,0,0,0,
	0,0,124,198,198,12,24,24,24,0,24,24,0,0,0,0,
	0,0,0,124,198,198,222,222,222,220,192,124,0,0,0,0,
	0,0,16,56,108,198,198,254,198,198,198,198,0,0,0,0,
	0,0,252,102,102,102,124,102,102,102,102,252,0,0,0,0,
	0,0,60,102,194,192,192,192,192,194,102,60,0,0,0,0,
	0,0,248,108,102,102,102,102,102,102,108,248,0,0,0,0,
	0,0,254,102,98,104,120,104,96,98,102,254,0,0,0,0,
	0,0,254,102,98,104,120,104,96,96,96,240,0,0,0,0,
	0,0,60,102,194,192,192,222,198,198,102,58,0,0,0,0,
	0,0,198,198,198,198,254,198,198,198,198,198,0,0,0,0,
	0,0,60,24,24,24,24,24,24,24,24,60,0,0,0,0,
	0,0,30,12,12,12,12,12,204,204,204,120,0,0,0,0,
	0,0,230,102,102,108,120,120,108,102,102,230,0,0,0,0,
	0,0,240,96,96,96,96,96,96,98,102,254,0,0,0,0,
	0,0,198,238,254,254,214,198,198,198,198,198,0,0,0,0,
	0,0,198,230,246,254,222,206,198,198,198,198,0,0,0,0,
	0,0,124,198,198,198,198,198,198,198,198,124,0,0,0,0,
	0,0,252,102,102,102,124,96,96,96,96,240,0,0,0,0,
	0,0,124,198,198,198,198,198,198,214,222,124,12,14,0,0,
	0,0,252,102,102,102,124,108,102,102,102,230,0,0,0,0,
	0,0,124,198,198,96,56,12,6,198,198,124,0,0,0,0,
	0,0,126,126,90,24,24,24,24,24,24,60,0,0,0,0,
	0,0,198,198,198,198,198,198,198,198,198,124,0,0,0,0,
	0,0,198,198,198,198,198,198,198,108,56,16,0,0,0,0,
	0,0,198,198,198,198,214,214,214,254,238,108,0,0,0,0,
	0,0,198,198,108,124,56,56,124,108,198,198,0,0,0,0,
	0,0,102,102,102,102,60,24,24,24,24,60,0,0,0,0,
	0,0,254,198,134,12,24,48,96,194,198,254,0,0,0,0,
	0,0,60,48,48,48,48,48,48,48,48,60,0,0,0,0,
	0,0,0,128,192,224,112,56,28,14,6,2,0,0,0,0,
	0,0,60,12,12,12,12,12,12,12,12,60,0,0,0,0,
	16,56,108,198,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,255,0,0,
	0,48,24,12,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,120,12,124,204,204,204,118,0,0,0,0,
	0,0,224,96,96,120,108,102,102,102,102,124,0,0,0,0,
	0,0,0,0,0,124,198,192,192,192,198,124,0,0,0,0,
	0,0,28,12,12,60,108,204,204,204,204,118,0,0,0,0,
	0,0,0,0,0,124,198,254,192,192,198,124,0,0,0,0,
	0,0,28,54,50,48,120,48,48,48,48,120,0,0,0,0,
	0,0,0,0,0,118,204,204,204,204,204,124,12,204,120,0,
	0,0,224,96,96,108,118,102,102,102,102,230,0,0,0,0,
	0,0,24,24,0,56,24,24,24,24,24,60,0,0,0,0,
	0,0,6,6,0,14,6,6,6,6,6,6,102,102,60,0,
	0,0,224,96,96,102,108,120,120,108,102,230,0,0,0,0,
	0,0,56,24,24,24,24,24,24,24,24,60,0,0,0,0,
	0,0,0,0,0,236,254,214,214,214,214,198,0,0,0,0,
	0,0,0,0,0,220,102,102,102,102,102,102,0,0,0,0,
	0,0,0,0,0,124,198,198,198,198,198,124,0,0,0,0,
	0,0,0,0,0,220,102,102,102,102,102,124,96,96,240,0,
	0,0,0,0,0,118,204,204,204,204,204,124,12,12,30,0,
	0,0,0,0,0,220,118,102,96,96,96,240,0,0,0,0,
	0,0,0,0,0,124,198,96,56,12,198,124,0,0,0,0,
	0,0,16,48,48,252,48,48,48,48,54,28,0,0,0,0,
	0,0,0,0,0,204,204,204,204,204,204,118,0,0,0,0,
	0,0,0,0,0,198,198,198,198,198,108,56,0,0,0,0,
	0,0,0,0,0,198,198,214,214,214,254,108,0,0,0,0,
	0,0,0,0,0,198,108,56,56,56,108,198,0,0,0,0,
	0,0,0,0,0,198,198,198,198,198,198,126,6,12,248,0,
	0,0,0,0,0,254,204,24,48,96,198,254,0,0,0,0,
	0,0,14,24,24,24,112,24,24,24,24,14,0,0,0,0,
	0,0,24,24,24,24,24,24,24,24,24,24,0,0,0,0,
	0,0,112,24,24,24,14,24,24,24,24,112,0,0,0,0,
	0,118,220,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,16,56,108,198,198,198,254,0,0,0,0,0,
	0,0,60,102,194,192,192,192,192,194,102,60,24,112,0,0,
	0,0,204,0,0,204,204,204,204,204,204,118,0,0,0,0,
	0,12,24,48,0,124,198,254,192,192,198,124,0,0,0,0,
	0,16,56,108,0,120,12,124,204,204,204,118,0,0,0,0,
	0,0,204,0,0,120,12,124,204,204,204,118,0,0,0,0,
	0,96,48,24,0,120,12,124,204,204,204,118,0,0,0,0,
	0,56,108,56,0,120,12,124,204,204,204,118,0,0,0,0,
	0,0,0,0,0,124,198,192,192,192,198,124,24,112,0,0,
	0,16,56,108,0,124,198,254,192,192,198,124,0,0,0,0,
	0,0,198,0,0,124,198,254,192,192,198,124,0,0,0,0,
	0,96,48,24,0,124,198,254,192,192,198,124,0,0,0,0,
	0,0,102,0,0,56,24,24,24,24,24,60,0,0,0,0,
	0,24,60,102,0,56,24,24,24,24,24,60,0,0,0,0,
	0,96,48,24,0,56,24,24,24,24,24,60,0,0,0,0,
	0,198,0,16,56,108,198,198,254,198,198,198,0,0,0,0,
	56,108,56,16,56,108,198,254,198,198,198,198,0,0,0,0,
	12,24,0,254,102,98,104,120,104,98,102,254,0,0,0,0,
	0,0,0,0,0,236,54,54,126,216,216,110,0,0,0,0,
	0,0,62,108,204,204,254,204,204,204,204,206,0,0,0,0,
	0,16,56,108,0,124,198,198,198,198,198,124,0,0,0,0,
	0,0,198,0,0,124,198,198,198,198,198,124,0,0,0,0,
	0,96,48,24,0,124,198,198,198,198,198,124,0,0,0,0,
	0,48,120,204,0,204,204,204,204,204,204,118,0,0,0,0,
	0,96,48,24,0,204,204,204,204,204,204,118,0,0,0,0,
	0,0,198,0,0,198,198,198,198,198,198,126,6,12,120,0,
	0,198,0,124,198,198,198,198,198,198,198,124,0,0,0,0,
	0,198,0,198,198,198,198,198,198,198,198,124,0,0,0,0,
	0,24,24,124,198,192,192,192,198,124,24,24,0,0,0,0,
	0,56,108,100,96,240,96,96,96,96,230,252,0,0,0,0,
	0,0,102,102,60,24,126,24,126,24,24,24,0,0,0,0,
	0,248,204,204,248,196,204,222,204,204,204,198,0,0,0,0,
	0,14,27,24,24,24,126,24,24,24,216,112,0,0,0,0,
	0,24,48,96,0,120,12,124,204,204,204,118,0,0,0,0,
	0,12,24,48,0,56,24,24,24,24,24,60,0,0,0,0,
	0,24,48,96,0,124,198,198,198,198,198,124,0,0,0,0,
	0,24,48,96,0,204,204,204,204,204,204,118,0,0,0,0,
	0,0,118,220,0,220,102,102,102,102,102,102,0,0,0,0,
	118,220,0,198,230,246,254,222,206,198,198,198,0,0,0,0,
	0,0,60,108,108,62,0,126,0,0,0,0,0,0,0,0,
	0,0,56,108,108,56,0,124,0,0,0,0,0,0,0,0,
	0,0,48,48,0,48,48,96,192,198,198,124,0,0,0,0,
	0,0,0,0,0,0,254,192,192,192,192,0,0,0,0,0,
	0,0,0,0,0,0,254,6,6,6,6,0,0,0,0,0,
	0,96,224,98,102,108,24,48,96,220,134,12,24,62,0,0,
	0,96,224,98,102,108,24,48,102,206,154,63,6,6,0,0,
	0,0,24,24,0,24,24,24,60,60,60,24,0,0,0,0,
	0,0,0,0,0,54,108,216,108,54,0,0,0,0,0,0,
	0,0,0,0,0,216,108,54,108,216,0,0,0,0,0,0,
	17,68,17,68,17,68,17,68,17,68,17,68,17,68,17,68,
	85,170,85,170,85,170,85,170,85,170,85,170,85,170,85,170,
	221,119,221,119,221,119,221,119,221,119,221,119,221,119,221,119,
	24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,
	24,24,24,24,24,24,24,248,24,24,24,24,24,24,24,24,
	24,24,24,24,24,248,24,248,24,24,24,24,24,24,24,24,
	54,54,54,54,54,54,54,246,54,54,54,54,54,54,54,54,
	0,0,0,0,0,0,0,254,54,54,54,54,54,54,54,54,
	0,0,0,0,0,248,24,248,24,24,24,24,24,24,24,24,
	54,54,54,54,54,246,6,246,54,54,54,54,54,54,54,54,
	54,54,54,54,54,54,54,54,54,54,54,54,54,54,54,54,
	0,0,0,0,0,254,6,246,54,54,54,54,54,54,54,54,
	54,54,54,54,54,246,6,254,0,0,0,0,0,0,0,0,
	54,54,54,54,54,54,54,254,0,0,0,0,0,0,0,0,
	24,24,24,24,24,248,24,248,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,248,24,24,24,24,24,24,24,24,
	24,24,24,24,24,24,24,31,0,0,0,0,0,0,0,0,
	24,24,24,24,24,24,24,255,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,255,24,24,24,24,24,24,24,24,
	24,24,24,24,24,24,24,31,24,24,24,24,24,24,24,24,
	0,0,0,0,0,0,0,255,0,0,0,0,0,0,0,0,
	24,24,24,24,24,24,24,255,24,24,24,24,24,24,24,24,
	24,24,24,24,24,31,24,31,24,24,24,24,24,24,24,24,
	54,54,54,54,54,54,54,55,54,54,54,54,54,54,54,54,
	54,54,54,54,54,55,48,63,0,0,0,0,0,0,0,0,
	0,0,0,0,0,63,48,55,54,54,54,54,54,54,54,54,
	54,54,54,54,54,247,0,255,0,0,0,0,0,0,0,0,
	0,0,0,0,0,255,0,247,54,54,54,54,54,54,54,54,
	54,54,54,54,54,55,48,55,54,54,54,54,54,54,54,54,
	0,0,0,0,0,255,0,255,0,0,0,0,0,0,0,0,
	54,54,54,54,54,247,0,247,54,54,54,54,54,54,54,54,
	24,24,24,24,24,255,0,255,0,0,0,0,0,0,0,0,
	54,54,54,54,54,54,54,255,0,0,0,0,0,0,0,0,
	0,0,0,0,0,255,0,255,24,24,24,24,24,24,24,24,
	0,0,0,0,0,0,0,255,54,54,54,54,54,54,54,54,
	54,54,54,54,54,54,54,63,0,0,0,0,0,0,0,0,
	24,24,24,24,24,31,24,31,0,0,0,0,0,0,0,0,
	0,0,0,0,0,31,24,31,24,24,24,24,24,24,24,24,
	0,0,0,0,0,0,0,63,54,54,54,54,54,54,54,54,
	54,54,54,54,54,54,54,255,54,54,54,54,54,54,54,54,
	24,24,24,24,24,255,24,255,24,24,24,24,24,24,24,24,
	24,24,24,24,24,24,24,248,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,31,24,24,24,24,24,24,24,24,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,
	240,240,240,240,240,240,240,240,240,240,240,240,240,240,240,240,
	15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
	255,255,255,255,255,255,255,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,118,220,216,216,216,220,118,0,0,0,0,
	0,0,120,204,204,204,216,204,198,198,198,204,0,0,0,0,
	0,0,254,198,198,192,192,192,192,192,192,192,0,0,0,0,
	0,0,0,0,0,254,108,108,108,108,108,108,0,0,0,0,
	0,0,254,198,96,48,24,24,48,96,198,254,0,0,0,0,
	0,0,0,0,0,126,216,216,216,216,216,112,0,0,0,0,
	0,0,0,0,0,102,102,102,102,102,102,124,96,96,192,0,
	0,0,0,0,118,220,24,24,24,24,24,24,0,0,0,0,
	0,0,126,24,60,102,102,102,102,60,24,126,0,0,0,0,
	0,0,56,108,198,198,254,198,198,198,108,56,0,0,0,0,
	0,0,56,108,198,198,198,108,108,108,108,238,0,0,0,0,
	0,0,30,48,24,12,62,102,102,102,102,60,0,0,0,0,
	0,0,0,0,0,126,219,219,219,126,0,0,0,0,0,0,
	0,0,0,3,6,126,219,219,243,126,96,192,0,0,0,0,
	0,0,28,48,96,96,124,96,96,96,48,28,0,0,0,0,
	0,0,0,124,198,198,198,198,198,198,198,198,0,0,0,0,
	0,0,0,0,254,0,0,254,0,0,254,0,0,0,0,0,
	0,0,0,0,24,24,126,24,24,0,0,126,0,0,0,0,
	0,0,0,48,24,12,6,12,24,48,0,126,0,0,0,0,
	0,0,0,12,24,48,96,48,24,12,0,126,0,0,0,0,
	0,0,14,27,27,24,24,24,24,24,24,24,24,24,24,24,
	24,24,24,24,24,24,24,24,24,216,216,216,112,0,0,0,
	0,0,0,0,0,24,0,126,0,24,0,0,0,0,0,0,
	0,0,0,0,0,118,220,0,118,220,0,0,0,0,0,0,
	0,56,108,108,56,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,24,24,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,24,0,0,0,0,0,0,0,0,
	0,15,12,12,12,12,12,236,108,108,60,28,0,0,0,0,
	0,108,54,54,54,54,54,0,0,0,0,0,0,0,0,0,
	0,60,102,12,24,50,126,0,0,0,0,0,0,0,0,0,
	0,0,0,0,126,126,126,126,126,126,126,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

const de_byte *de_get_vga_cp437_font_ptr(void)
{
	return vga_cp437_font_data;
}

void de_color_to_css(de_uint32 color, char *buf, int buflen)
{
	de_byte r, g, b;

	buf[0] = '#';
	r = DE_COLOR_R(color);
	g = DE_COLOR_G(color);
	b = DE_COLOR_B(color);

	if(r%17==0 && g%17==0 && b%17==0) {
		// Can use short form.
		buf[1] = g_hexchars[r/17];
		buf[2] = g_hexchars[g/17];
		buf[3] = g_hexchars[b/17];
		buf[4] = '\0';
		return;
	}

	buf[1] = g_hexchars[r/16];
	buf[2] = g_hexchars[r%16];
	buf[3] = g_hexchars[g/16];
	buf[4] = g_hexchars[g%16];
	buf[5] = g_hexchars[b/16];
	buf[6] = g_hexchars[b%16];
	buf[7] = '\0';
}

de_byte de_sample_nbit_to_8bit(de_int64 n, unsigned int x)
{
	unsigned int maxval;

	if(x==0) return 0;
	if(n<1 || n>16) return 0;
	maxval = (1<<n)-1;
	if(x>=maxval) return 255;
	return (de_byte)(0.5+((((double)x)/(double)maxval)*255.0));
}

de_byte de_scale_63_to_255(de_byte x)
{
	if(x>=63) return 255;
	return (de_byte)(0.5+(((double)x)*(255.0/63.0)));
}

de_byte de_scale_1000_to_255(de_int64 x)
{
	if(x>=1000) return 255;
	if(x<=0) return 0;
	return (de_byte)(0.5+(((double)x)*(255.0/1000.0)));
}

de_uint32 de_rgb565_to_888(de_uint32 x)
{
	de_byte cr, cg, cb;
	cr = (de_byte)(x>>11);
	cg = (de_byte)((x>>5)&0x3f);
	cb = (de_byte)(x&0x1f);
	cr = (de_byte)(0.5+((double)cr)*(255.0/31.0));
	cg = (de_byte)(0.5+((double)cg)*(255.0/63.0));
	cb = (de_byte)(0.5+((double)cb)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

de_uint32 de_bgr555_to_888(de_uint32 x)
{
	de_byte cr, cg, cb;
	cb = (de_byte)((x>>10)&0x1f);
	cg = (de_byte)((x>>5)&0x1f);
	cr = (de_byte)(x&0x1f);
	cb = (de_byte)(0.5+((double)cb)*(255.0/31.0));
	cg = (de_byte)(0.5+((double)cg)*(255.0/31.0));
	cr = (de_byte)(0.5+((double)cr)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

de_uint32 de_rgb555_to_888(de_uint32 x)
{
	de_byte cr, cg, cb;
	cr = (de_byte)((x>>10)&0x1f);
	cg = (de_byte)((x>>5)&0x1f);
	cb = (de_byte)(x&0x1f);
	cr = (de_byte)(0.5+((double)cr)*(255.0/31.0));
	cg = (de_byte)(0.5+((double)cg)*(255.0/31.0));
	cb = (de_byte)(0.5+((double)cb)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

// s1 is not NUL terminated, but s2 will be.
// s2_size includes the NUL terminator.
void de_bytes_to_printable_sz(const de_byte *s1, de_int64 s1_len,
	char *s2, de_int64 s2_size, unsigned int conv_flags, int src_encoding)
{
	de_int64 i;
	de_int64 s2_pos = 0;
	char ch;

	if(src_encoding!=DE_ENCODING_ASCII) {
		// TODO: Implement other encodings
		s2[0] = '\0';
		return;
	}

	for(i=0; i<s1_len; i++) {
		if(s1[i]=='\0' && (conv_flags & DE_CONVFLAG_STOP_AT_NUL)) {
			break;
		}

		if(s1[i]>=32 && s1[i]<=126) {
			ch = (char)s1[i];
		}
		else {
			ch = '_';
		}

		if(s2_pos < s2_size-1) {
			s2[s2_pos++] = ch;
		}
	}

	s2[s2_pos] = '\0';
}

de_int32 de_char_to_valid_fn_char(deark *c, de_int32 ch)
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

// de_ucstring is a Unicode (utf-32) string object.
de_ucstring *ucstring_create(deark *c)
{
	de_ucstring *s;
	s = de_malloc(c, sizeof(de_ucstring));
	s->c = c;
	return s;
}

// Reduce the string's length to newlen, by deleting the characters after
// that point.
// 'newlen' is expected to be no larger than the string's current length.
void ucstring_truncate(de_ucstring *s, de_int64 newlen)
{
	if(!s && newlen==0) return;
	if(newlen<0) newlen=0;
	if(newlen<s->len) s->len = newlen;
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
			ret = de_utf16le_to_uchar(&buf[pos], buflen-pos, &ch, &code_len);
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

void ucstring_to_printable_sz(de_ucstring *s, char *szbuf, size_t szbuf_len)
{
	de_ucstring *s2 = NULL;

	s2 = ucstring_clone(s);
	ucstring_make_printable(s2);
	ucstring_to_sz(s2, szbuf, szbuf_len, DE_ENCODING_UTF8);
	ucstring_destroy(s2);
}

// Try to determine if a Unicode codepoint (presumed to be from an untrusted source)
// is "safe" to print to a terminal.
// We try to ban control characters, formatting characters, private-use characters,
// and noncharacters.
// It would be be good to also ban incorrectly-used "combining" and other context-
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
		{ 0xfe10, 0xffef },
		{ 0xfffd, 0xfffd },
		{ 0x10000, 0x101ff },
		{ 0x1f000, 0x1f9ff }
		// TODO: Whitelist more codepoints
	};
	size_t i;
	const size_t num_ranges = sizeof(ranges)/sizeof(ranges[0]);

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

void de_write_codepoint_to_html(deark *c, dbuf *f, de_int32 ch)
{
	int e; // How to encode this codepoint

	if(ch<0 || ch>0x10ffff || ch==DE_INVALID_CODEPOINT) ch=0xfffd;

	if(ch=='&' || ch=='<' || ch=='>') {
		e = 1; // HTML entity
	}
	else if(ch>=32 && ch<=126) {
		e = 2; // raw byte
	}
	else if(c->ascii_html) {
		e = 1; // HTML entity
	}
	else {
		e = 3; // UTF-8
	}

	if(e==2) {
		dbuf_writebyte(f, (de_byte)ch);
	}
	else if(e==3) {
		dbuf_write_uchar_as_utf8(f, ch);
	}
	else {
		dbuf_printf(f, "&#%d;", (int)ch);
	}
}
