// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// deark-data.c
//
// Data lookup and conversion.

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#include "deark-private.h"

static const char *g_hexchars = "0123456789abcdef";

char de_get_hexchar(int n)
{
	if(n>=0 && n<16) return g_hexchars[n];
	return '0';
}

static char de_get_hexcharUC(int n)
{
	static const char *hexcharsUC = "0123456789ABCDEF";
	if(n>=0 && n<16) return hexcharsUC[n];
	return '0';
}

u8 de_decode_hex_digit(u8 x, int *errorflag)
{
	if(errorflag) *errorflag = 0;
	if(x>='0' && x<='9') return x-48;
	if(x>='A' && x<='F') return x-55;
	if(x>='a' && x<='f') return x-87;
	if(errorflag) *errorflag = 1;
	return 0;
}

struct ext_ascii_pvt_data {
	const u16 *tbl; // array[128]
};

static const u16 cp437table[256] = {
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

static const u16 latin2table[32] = { // 0xa0 to 0xbf
	0x00a0,0x0104,0x02d8,0x0141,0x00a4,0x013d,0x015a,0x00a7,0x00a8,0x0160,0x015e,0x0164,0x0179,0x00ad,0x017d,0x017b,
	0x00b0,0x0105,0x02db,0x0142,0x00b4,0x013e,0x015b,0x02c7,0x00b8,0x0161,0x015f,0x0165,0x017a,0x02dd,0x017e,0x017c
};

static const u16 windows1250table[128] = {
	0x20ac,0xffff,0x201a,0xffff,0x201e,0x2026,0x2020,0x2021,0xffff,0x2030,0x0160,0x2039,0x015a,0x0164,0x017d,0x0179,
	0xffff,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0xffff,0x2122,0x0161,0x203a,0x015b,0x0165,0x017e,0x017a,
	0x00a0,0x02c7,0x02d8,0x0141,0x00a4,0x0104,0x00a6,0x00a7,0x00a8,0x00a9,0x015e,0x00ab,0x00ac,0x00ad,0x00ae,0x017b,
	0x00b0,0x00b1,0x02db,0x0142,0x00b4,0x00b5,0x00b6,0x00b7,0x00b8,0x0105,0x015f,0x00bb,0x013d,0x02dd,0x013e,0x017c,
	0x0154,0x00c1,0x00c2,0x0102,0x00c4,0x0139,0x0106,0x00c7,0x010c,0x00c9,0x0118,0x00cb,0x011a,0x00cd,0x00ce,0x010e,
	0x0110,0x0143,0x0147,0x00d3,0x00d4,0x0150,0x00d6,0x00d7,0x0158,0x016e,0x00da,0x0170,0x00dc,0x00dd,0x0162,0x00df,
	0x0155,0x00e1,0x00e2,0x0103,0x00e4,0x013a,0x0107,0x00e7,0x010d,0x00e9,0x0119,0x00eb,0x011b,0x00ed,0x00ee,0x010f,
	0x0111,0x0144,0x0148,0x00f3,0x00f4,0x0151,0x00f6,0x00f7,0x0159,0x016f,0x00fa,0x0171,0x00fc,0x00fd,0x0163,0x02d9
};
static const struct ext_ascii_pvt_data windows1250_pvt_data = { windows1250table };

static const u16 windows1251table[128] = {
	0x0402,0x0403,0x201a,0x0453,0x201e,0x2026,0x2020,0x2021,0x20ac,0x2030,0x0409,0x2039,0x040a,0x040c,0x040b,0x040f,
	0x0452,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0xffff,0x2122,0x0459,0x203a,0x045a,0x045c,0x045b,0x045f,
	0x00a0,0x040e,0x045e,0x0408,0x00a4,0x0490,0x00a6,0x00a7,0x0401,0x00a9,0x0404,0x00ab,0x00ac,0x00ad,0x00ae,0x0407,
	0x00b0,0x00b1,0x0406,0x0456,0x0491,0x00b5,0x00b6,0x00b7,0x0451,0x2116,0x0454,0x00bb,0x0458,0x0405,0x0455,0x0457,
	0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,0x041f,
	0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042a,0x042b,0x042c,0x042d,0x042e,0x042f,
	0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,0x043f,
	0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044a,0x044b,0x044c,0x044d,0x044e,0x044f
};
static const struct ext_ascii_pvt_data windows1251_pvt_data = { windows1251table };

static const u16 windows1252table[32] = {
	0x20ac,0xffff,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0x02c6,0x2030,0x0160,0x2039,0x0152,0xffff,0x017d,0xffff,
	0xffff,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0x02dc,0x2122,0x0161,0x203a,0x0153,0xffff,0x017e,0x0178
};

static const u16 windows1253table[128] = {
	0x20ac,0xffff,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0xffff,0x2030,0xffff,0x2039,0xffff,0xffff,0xffff,0xffff,
	0xffff,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0xffff,0x2122,0xffff,0x203a,0xffff,0xffff,0xffff,0xffff,
	0x00a0,0x0385,0x0386,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0xffff,0x00ab,0x00ac,0x00ad,0x00ae,0x2015,
	0x00b0,0x00b1,0x00b2,0x00b3,0x0384,0x00b5,0x00b6,0x00b7,0x0388,0x0389,0x038a,0x00bb,0x038c,0x00bd,0x038e,0x038f,
	0x0390,0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039a,0x039b,0x039c,0x039d,0x039e,0x039f,
	0x03a0,0x03a1,0xffff,0x03a3,0x03a4,0x03a5,0x03a6,0x03a7,0x03a8,0x03a9,0x03aa,0x03ab,0x03ac,0x03ad,0x03ae,0x03af,
	0x03b0,0x03b1,0x03b2,0x03b3,0x03b4,0x03b5,0x03b6,0x03b7,0x03b8,0x03b9,0x03ba,0x03bb,0x03bc,0x03bd,0x03be,0x03bf,
	0x03c0,0x03c1,0x03c2,0x03c3,0x03c4,0x03c5,0x03c6,0x03c7,0x03c8,0x03c9,0x03ca,0x03cb,0x03cc,0x03cd,0x03ce,0xffff
};
static const struct ext_ascii_pvt_data windows1253_pvt_data = { windows1253table };

static const u16 windows1254table[128] = {
	0x20ac,0xffff,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0x02c6,0x2030,0x0160,0x2039,0x0152,0xffff,0xffff,0xffff,
	0xffff,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0x02dc,0x2122,0x0161,0x203a,0x0153,0xffff,0xffff,0x0178,
	0x00a0,0x00a1,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
	0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,0x00b8,0x00b9,0x00ba,0x00bb,0x00bc,0x00bd,0x00be,0x00bf,
	0x00c0,0x00c1,0x00c2,0x00c3,0x00c4,0x00c5,0x00c6,0x00c7,0x00c8,0x00c9,0x00ca,0x00cb,0x00cc,0x00cd,0x00ce,0x00cf,
	0x011e,0x00d1,0x00d2,0x00d3,0x00d4,0x00d5,0x00d6,0x00d7,0x00d8,0x00d9,0x00da,0x00db,0x00dc,0x0130,0x015e,0x00df,
	0x00e0,0x00e1,0x00e2,0x00e3,0x00e4,0x00e5,0x00e6,0x00e7,0x00e8,0x00e9,0x00ea,0x00eb,0x00ec,0x00ed,0x00ee,0x00ef,
	0x011f,0x00f1,0x00f2,0x00f3,0x00f4,0x00f5,0x00f6,0x00f7,0x00f8,0x00f9,0x00fa,0x00fb,0x00fc,0x0131,0x015f,0x00ff
};
static const struct ext_ascii_pvt_data windows1254_pvt_data = { windows1254table };

static const i32 atarist_table_lo[32] = { // [0..31]
	 0x0000, 0x21e7, 0x21e9, 0x21e8, 0x21e6,0x1fbbd,0x1fbbe,0x1fbbf,
	 0x2713,0x1f552,0x1f514, 0x266a, 0x240c, 0x240d, 0xffff, 0xffff,
	0x1fbf0,0x1fbf1,0x1fbf2,0x1fbf3,0x1fbf4,0x1fbf5,0x1fbf6,0x1fbf7,
	0x1fbf8,0x1fbf9, 0x0259, 0x241b, 0xffff, 0xffff, 0xffff, 0xffff
};

static const u16 atarist_table_hi[80] = { // [176..255]
	0x00e3,0x00f5,0x00d8,0x00f8,0x0153,0x0152,0x00c0,0x00c3,0x00d5,0x00a8,0x00b4,0x2020,0x00b6,0x00a9,0x00ae,0x2122,
	0x0133,0x0132,0x05d0,0x05d1,0x05d2,0x05d3,0x05d4,0x05d5,0x05d6,0x05d7,0x05d8,0x05d9,0x05db,0x05dc,0x05de,0x05e0,
	0x05e1,0x05e2,0x05e4,0x05e6,0x05e7,0x05e8,0x05e9,0x05ea,0x05df,0x05da,0x05dd,0x05e3,0x05e5,0x00a7,0x2227,0x221e,
	0x03b1,0x03b2,0x0393,0x03c0,0x03a3,0x03c3,0x00b5,0x03c4,0x03a6,0x0398,0x03a9,0x03b4,0x222e,0x03d5,0x2208,0x2229,
	0x2261,0x00b1,0x2265,0x2264,0x2320,0x2321,0x00f7,0x2248,0x00b0,0x2022,0x00b7,0x221a,0x207f,0x00b2,0x00b3,0x00af
};

// Trivia: This table maps the heart and diamond suits to the BLACK Unicode
// characters. Some sources map them to the WHITE characters instead.
static const u16 palmcstable[4] = {
	0x2666,0x2663,0x2665,0x2660
};

static const u16 riscostable[32] = {
	0x20ac,0x0174,0x0175,0xffff,0xffff,0x0176,0x0177,0xffff,0xffff,0xffff,0xffff,0xffff,0x2026,0x2122,0x2030,0x2022,
	0x2018,0x2019,0x2039,0x203a,0x201c,0x201d,0x201e,0x2013,0x2014,0x2212,0x0152,0x0153,0x2020,0x2021,0xfb01,0xfb02
};

// MacRoman, a.k.a "Mac OS Roman", "Macintosh"
static const u16 macromantable[128] = {
	0x00c4,0x00c5,0x00c7,0x00c9,0x00d1,0x00d6,0x00dc,0x00e1,0x00e0,0x00e2,0x00e4,0x00e3,0x00e5,0x00e7,0x00e9,0x00e8,
	0x00ea,0x00eb,0x00ed,0x00ec,0x00ee,0x00ef,0x00f1,0x00f3,0x00f2,0x00f4,0x00f6,0x00f5,0x00fa,0x00f9,0x00fb,0x00fc,
	0x2020,0x00b0,0x00a2,0x00a3,0x00a7,0x2022,0x00b6,0x00df,0x00ae,0x00a9,0x2122,0x00b4,0x00a8,0x2260,0x00c6,0x00d8,
	0x221e,0x00b1,0x2264,0x2265,0x00a5,0x00b5,0x2202,0x2211,0x220f,0x03c0,0x222b,0x00aa,0x00ba,0x03a9,0x00e6,0x00f8,
	0x00bf,0x00a1,0x00ac,0x221a,0x0192,0x2248,0x2206,0x00ab,0x00bb,0x2026,0x00a0,0x00c0,0x00c3,0x00d5,0x0152,0x0153,
	0x2013,0x2014,0x201c,0x201d,0x2018,0x2019,0x00f7,0x25ca,0x00ff,0x0178,0x2044,0x20ac,0x2039,0x203a,0xfb01,0xfb02,
	0x2021,0x00b7,0x201a,0x201e,0x2030,0x00c2,0x00ca,0x00c1,0x00cb,0x00c8,0x00cd,0x00ce,0x00cf,0x00cc,0x00d3,0x00d4,
	0xf8ff,0x00d2,0x00da,0x00db,0x00d9,0x0131,0x02c6,0x02dc,0x00af,0x02d8,0x02d9,0x02da,0x00b8,0x02dd,0x02db,0x02c7
};
static const struct ext_ascii_pvt_data macroman_pvt_data = { macromantable };

// Note: This is not an official or canonical mapping.
static const i32 petscii1table[256] = {
	0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x000d,0x000e,0xffff,
	0xffff,0xffff,0xffff,0xffff,0x007f,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,
	0x0020,0x0021,0x0022,0x0023,0x0024,0x0025,0x0026,0x0027,0x0028,0x0029,0x002a,0x002b,0x002c,0x002d,0x002e,0x002f,
	0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,0x0038,0x0039,0x003a,0x003b,0x003c,0x003d,0x003e,0x003f,
	0x0040,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,0x0049,0x004a,0x004b,0x004c,0x004d,0x004e,0x004f,
	0x0050,0x0051,0x0052,0x0053,0x0054,0x0055,0x0056,0x0057,0x0058,0x0059,0x005a,0x005b,0x00a3,0x005d,0x2191,0x2190,
	0x2500,0x2660,0x2502,0x2500,0x1fb77,0x1fb76,0x1fb7a,0x1fb71,0x1fb74,0x256e,0x2570,0x256f,0x1fb7c,0x2572,0x2571,0x1fb7d,
	0x1fb7e,0x25cf,0x1fb7b,0x2665,0x1fb70,0x256d,0x2573,0x25cb,0x2663,0x1fb75,0x2666,0x253c,0x1fb8c,0x2502,0x03c0,0x25e5,
	0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x000a,0x000f,0xffff,
	0xffff,0xffff,0xffff,0x000c,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x0008,0xffff,0xffff,
	0x00a0,0x258c,0x2584,0x2594,0x2581,0x258e,0x2592,0x2595,0x1fb8f,0x25e4,0x1fb87,0x251c,0x2597,0x2514,0x2510,0x2582,
	0x250c,0x2534,0x252c,0x2524,0x258e,0x258d,0x1fb88,0x1fb82,0x1fb83,0x2583,0x1fb7f,0x2596,0x259d,0x2518,0x2598,0x259a,
	0x2500,0x2660,0x2502,0x2500,0x1fb77,0x1fb76,0x1fb7a,0x1fb71,0x1fb74,0x256e,0x2570,0x256f,0x1fb7c,0x2572,0x2571,0x1fb7d,
	0x1fb7e,0x25cf,0x1fb7b,0x2665,0x1fb70,0x256d,0x2573,0x25cb,0x2663,0x1fb75,0x2666,0x253c,0x1fb8c,0x2502,0x03c0,0x25e5,
	0x00a0,0x258c,0x2584,0x2594,0x2581,0x258e,0x2592,0x2595,0x1fb8f,0x25e4,0x1fb87,0x251c,0x2597,0x2514,0x2510,0x2582,
	0x250c,0x2534,0x252c,0x2524,0x258e,0x258d,0x1fb88,0x1fb82,0x1fb83,0x2583,0x1fb7f,0x2596,0x259d,0x2518,0x2598,0x03c0
};

// Derived from VT100 Series Technical manual, Table A-9: Special Graphics Characters (p. A-12)
static const u16 decspecialgraphicstable[32] = {
	0x00a0,0x25c6,0x2592,0x2409,0x240c,0x240d,0x240a,0x00b0,0x00b1,0x2424,0x240b,0x2518,0x2510,0x250c,0x2514,0x253c,
	0x23ba,0x23bb,0x2500,0x23bc,0x23bd,0x251c,0x2524,0x2534,0x252c,0x2502,0x2264,0x2265,0x03c0,0x2260,0x00a3,0x00b7
};

// Code page 437, with screen code graphics characters.
static de_rune de_cp437g_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a<=0xff) n = (de_rune)cp437table[a];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

// Code page 437, with control characters.
static de_rune de_cp437c_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a<=0x7f) n = a;
	else if(a>=0x80 && a<=0xff) n = (de_rune)cp437table[a];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

// Code page 437, with only selected control characters.
static de_rune de_cp437h_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;

	if(a==0 || a==9 || a==10 || a==13) n = a;
	else n = de_cp437g_to_unicode(NULL, a);
	return n;
}

static de_rune de_latin2_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a<=0x9f) n = a;
	else if(a>=0xa0 && a<=0xbf) n = (de_rune)latin2table[a-0xa0];
	else if(a>=0x0c0 && a<=0xff) n = (de_rune)windows1250table[a-0x80];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_windows1252_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a>=0x80 && a<=0x9f) n = (de_rune)windows1252table[a-0x80];
	else if(a<=0xff) n = a;
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_windows874_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n = 0xffff;
	if(a<=0x7f || a==0xa0) n = a;
	else if(a==0x80 || a==0x85 || (a>=0x91 && a<=0x97)) n = (de_rune)windows1252table[a-0x80];
	else if((a>=0xa1 && a<=0xda) || (a>=0xdf && a<=0xfb)) n = a + (0xe01 - 0xa1);
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_atarist_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a<=0x1f) n = atarist_table_lo[a];
	else if(a>=0xb0 && a<=0xff) n = (de_rune)atarist_table_hi[a-0xb0];
	else if(a==0x7f) n = 0x0394;
	else if(a==0x9e) n = 0x00df;
	else n = de_cp437g_to_unicode(NULL, a);
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_palmcs_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	// This is not perfect, but the diamond/club/heart/spade characters seem to
	// be about the only printable characters common to all versions of this
	// encoding, that differ from Windows-1252.
	if(a>=0x8d && a<=0x90) n = (de_rune)palmcstable[a-0x8d];
	else n = de_windows1252_to_unicode(NULL, a);
	return n;
}

static de_rune de_riscos_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a>=0x80 && a<=0x9f) n = (de_rune)riscostable[a-0x80];
	else if(a<=0xff) n = a;
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_petscii_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a<=0xff) n = petscii1table[a];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

static de_rune de_decspecialgraphics_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;
	if(a>=95 && a<=126) n = (de_rune)decspecialgraphicstable[a-95];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

// For any charset that uses 128 ASCII chars + 128 custom chars.
static de_rune de_ext_ascii_to_unicode(struct de_encconv_state *es, i32 a)
{
	de_rune n;

	if(a<=0x7f) n = a;
	else if(a>=0x80 && a<=0xff) n = (de_rune)((struct ext_ascii_pvt_data*)es->fn_pvt_data)->tbl[a-0x80];
	else n = DE_CODEPOINT_INVALID;
	if(n==0xffff) n = DE_CODEPOINT_INVALID;
	return n;
}

void de_encconv_init(struct de_encconv_state *es, de_ext_encoding ee)
{
	de_encoding enc = DE_EXTENC_GET_BASE(ee);

	de_zeromem(es, sizeof(struct de_encconv_state));
	es->ee = ee;

	if(enc==DE_ENCODING_LATIN1 || enc==DE_ENCODING_UTF8 ||
		enc==DE_ENCODING_ASCII)
	{
		return;
	}

	switch(enc) {
	case DE_ENCODING_LATIN2:
		es->fn = de_latin2_to_unicode;
		break;
	case DE_ENCODING_CP437:
		switch(DE_EXTENC_GET_SUBTYPE(es->ee)) {
		case DE_ENCSUBTYPE_CONTROLS:
			es->fn = de_cp437c_to_unicode;
			break;
		case DE_ENCSUBTYPE_HYBRID:
			es->fn = de_cp437h_to_unicode;
			break;
		default:
			es->fn = de_cp437g_to_unicode;
		}
		break;
	case DE_ENCODING_PETSCII:
		es->fn = de_petscii_to_unicode;
		break;
	case DE_ENCODING_WINDOWS1252:
		es->fn = de_windows1252_to_unicode;
		break;
	case DE_ENCODING_MACROMAN:
		es->fn = de_ext_ascii_to_unicode;
		es->fn_pvt_data = (const void*)&macroman_pvt_data;
		break;
	case DE_ENCODING_WINDOWS1250:
		es->fn = de_ext_ascii_to_unicode;
		es->fn_pvt_data = (const void*)&windows1250_pvt_data;
		break;
	case DE_ENCODING_WINDOWS1251:
		es->fn = de_ext_ascii_to_unicode;
		es->fn_pvt_data = (const void*)&windows1251_pvt_data;
		break;
	case DE_ENCODING_WINDOWS1253:
		es->fn = de_ext_ascii_to_unicode;
		es->fn_pvt_data = (const void*)&windows1253_pvt_data;
		break;
	case DE_ENCODING_WINDOWS1254:
		es->fn = de_ext_ascii_to_unicode;
		es->fn_pvt_data = (const void*)&windows1254_pvt_data;
		break;
	case DE_ENCODING_WINDOWS874:
		es->fn = de_windows874_to_unicode;
		break;
	case DE_ENCODING_ATARIST:
		es->fn = de_atarist_to_unicode;
		break;
	case DE_ENCODING_PALM:
		es->fn = de_palmcs_to_unicode;
		break;
	case DE_ENCODING_RISCOS:
		es->fn = de_riscos_to_unicode;
		break;
	case DE_ENCODING_DEC_SPECIAL_GRAPHICS:
		es->fn = de_decspecialgraphics_to_unicode;
	default:
		break;
	}
}

de_rune de_char_to_unicode_ex(i32 a, struct de_encconv_state *es)
{
	if(a<0) return DE_CODEPOINT_INVALID;
	if(es->fn) {
		return es->fn(es, a);
	}

	switch(DE_EXTENC_GET_BASE(es->ee)) {
	case DE_ENCODING_ASCII:
		if(DE_EXTENC_GET_SUBTYPE(es->ee)==DE_ENCSUBTYPE_PRINTABLE) {
			return (a>=32 && a<=126)?a:DE_CODEPOINT_INVALID;
		}
		return (a<128)?a:DE_CODEPOINT_INVALID;
	case DE_ENCODING_LATIN1:
		return (a<256)?a:DE_CODEPOINT_INVALID;
	default:
		break;
	}
	return a;
}

de_rune de_char_to_unicode(deark *c, i32 a, de_ext_encoding ee)
{
	struct de_encconv_state es;

	de_encconv_init(&es, ee);
	return de_char_to_unicode_ex(a, &es);
}

// Encode a Unicode char in UTF-8.
// Caller supplies utf8buf[4].
// Sets *p_utf8len to the number of bytes used (1-4).
void de_uchar_to_utf8(de_rune u1, u8 *utf8buf, i64 *p_utf8len)
{
	u32 u = (u32)u1;

	// TODO: Maybe there should be a flag to tell what to do with
	// our special codepoints (DE_CODEPOINT_BYTE00, ...).
	if(u1<0 || u1>0x10ffff)	{
		u=0xfffd;
	}

	if(u<=0x7f) {
		*p_utf8len = 1;
		utf8buf[0] = (u8)u;
	}
	else if(u>=0x80 && u<=0x7ff) {
		*p_utf8len = 2;
		utf8buf[0] = 0xc0 | (u8)(u>>6);
		utf8buf[1] = 0x80 | (u&0x3f);
	}
	else if(u>=0x800 && u<=0xffff) {
		*p_utf8len = 3;
		utf8buf[0] = 0xe0 | (u8)(u>>12);
		utf8buf[1] = 0x80 | ((u>>6)&0x3f);
		utf8buf[2] = 0x80 | (u&0x3f);
	}
	else {
		*p_utf8len = 4;
		utf8buf[0] = 0xf0 | (u8)(u>>18);
		utf8buf[1] = 0x80 | ((u>>12)&0x3f);
		utf8buf[2] = 0x80 | ((u>>6)&0x3f);
		utf8buf[3] = 0x80 | (u&0x3f);
	}
}

// Write a unicode code point to a file, encoded as UTF-8.
void dbuf_write_uchar_as_utf8(dbuf *outf, de_rune u)
{
	u8 utf8buf[4];
	i64 utf8len;

	de_uchar_to_utf8(u, utf8buf, &utf8len);
	dbuf_write(outf, utf8buf, utf8len);
}

// Convert a UTF-8 character to UTF-32.
// Returns 1 if a valid character was converted, 0 otherwise.
// buflen = the max number of bytes to read (but regardless of buflen, this
// will not read past a byte whose value is < 0x80).
//
// TODO?: There is another UTF-8 decoder in ucstring_append_bytes_ex(). Maybe
// should be consolidated in some way.
int de_utf8_to_uchar(const u8 *utf8buf, i64 buflen,
	de_rune *p_uchar, i64 *p_utf8len)
{
	i32 u0=0;
	i32 u1=0;
	i32 u2=0;
	i32 u3=0;

	if(buflen<1) return 0;
	u0 = (i32)utf8buf[0];
	if(u0<=0x7f) { // 1-byte UTF-8 char
		*p_utf8len = 1;
		*p_uchar = u0;
		return 1;
	}
	if(buflen<2) return 0;
	if((utf8buf[1]&0xc0)!=0x80) return 0;
	u1 = (i32)utf8buf[1];
	if(u0<=0xdf) { // 2-byte UTF-8 char
		*p_utf8len = 2;
		*p_uchar = ((u0&0x1f)<<6) | (u1&0x3f);
		return 1;
	}
	if(buflen<3) return 0;
	if((utf8buf[2]&0xc0)!=0x80) return 0;
	u2 = (i32)utf8buf[2];
	if(u0<=0xef) { // 3-byte UTF-8 char
		*p_utf8len = 3;
		*p_uchar = ((u0&0x0f)<<12) | ((u1&0x3f)<<6) | (u2&0x3f);
		return 1;
	}
	if(buflen<4) return 0;
	if((utf8buf[3]&0xc0)!=0x80) return 0;
	u3 = (i32)utf8buf[3];
	if(u0<=0xf7) { // 4-byte UTF-8 char
		*p_utf8len = 4;
		*p_uchar = ((u0&0x07)<<18) | ((u1&0x3f)<<12) | ((u2&0x3f)<<6) | (u3&0x3f);
		return 1;
	}
	return 0;
}

// Copy a string, converting from UTF-8 to ASCII.
// Non-ASCII characters will be replaced, one way or another.
void de_utf8_to_ascii(const char *src, char *dst, size_t dstlen, unsigned int flags)
{
	size_t srcpos = 0;
	size_t dstpos = 0;
	unsigned char ch;
	i32 uchar;
	i64 code_len;
	int ret;

	while(1) {
		char sc; // substitution character 1
		char sc2 = 0; // substitution character 2

		if(dstpos >= dstlen-1) {
			dst[dstlen-1] = '\0';
			break;
		}

		ch = (unsigned char)src[srcpos];
		if(ch<0x80) {
			dst[dstpos++] = src[srcpos++];
			if(ch=='\0')
				break;
		}
		else { // Start of a multi-byte UTF8 char

			ret = de_utf8_to_uchar((const u8*)&src[srcpos], 4, &uchar, &code_len);
			if(ret) {
				srcpos += (size_t)code_len;
				switch(uchar) {
				case 0x00d7: sc='x'; break; // Multiplication sign
				case 0x2018: case 0x2019: sc='\''; break; // single quotes
				case 0x201c: case 0x201d: sc='"'; break; // double quotes
				case 0x2192: sc='-'; sc2='>'; break; // Rightwards arrow
				case 0x2264: sc='<'; sc2='='; break;
				case 0x2265: sc='>'; sc2='='; break;
				case 0x2502: sc='|'; break; // Box drawings light vertical
				default: sc = '_';
				}
			}
			else {
				srcpos += 1;
				sc = '?';
			}
			dst[dstpos++] = sc;
			if(sc2 && dstpos<dstlen-1) dst[dstpos++] = sc2;
		}
	}
}

// Given a buffer, return 1 if it has no bytes 0x80 or higher.
int de_is_ascii(const u8 *buf, i64 buflen)
{
	i64 i;

	for(i=0; i<buflen; i++) {
		if(buf[i]>=128) return 0;
	}
	return 1;
}

static const u32 vga256pal[256] = {
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

static const u32 ega64pal[64] = {
	0x000000,0x0000aa,0x00aa00,0x00aaaa,0xaa0000,0xaa00aa,0xaaaa00,0xaaaaaa,
	0x000055,0x0000ff,0x00aa55,0x00aaff,0xaa0055,0xaa00ff,0xaaaa55,0xaaaaff,
	0x005500,0x0055aa,0x00ff00,0x00ffaa,0xaa5500,0xaa55aa,0xaaff00,0xaaffaa,
	0x005555,0x0055ff,0x00ff55,0x00ffff,0xaa5555,0xaa55ff,0xaaff55,0xaaffff,
	0x550000,0x5500aa,0x55aa00,0x55aaaa,0xff0000,0xff00aa,0xffaa00,0xffaaaa,
	0x550055,0x5500ff,0x55aa55,0x55aaff,0xff0055,0xff00ff,0xffaa55,0xffaaff,
	0x555500,0x5555aa,0x55ff00,0x55ffaa,0xff5500,0xff55aa,0xffff00,0xffffaa,
	0x555555,0x5555ff,0x55ff55,0x55ffff,0xff5555,0xff55ff,0xffff55,0xffffff
};

static const u32 pc16pal[16] = {
	0x000000,0x0000aa,0x00aa00,0x00aaaa,0xaa0000,0xaa00aa,0xaa5500,0xaaaaaa,
	0x555555,0x5555ff,0x55ff55,0x55ffff,0xff5555,0xff55ff,0xffff55,0xffffff
};


de_color de_palette_vga256(int index)
{
	if(index>=0 && index<256) {
		return vga256pal[index];
	}
	return 0;
}

de_color de_palette_ega64(int index)
{

	if(index>=0 && index<64) {
		return DE_MAKE_OPAQUE(ega64pal[index]);
	}
	return 0;
}

de_color de_palette_pc16(int index)
{
	if(index>=0 && index<16) {
		return pc16pal[index];
	}
	return 0;
}

static const de_color pcpaint_cga_pals[6][4] = {
	{ 0x000000, 0x00aaaa, 0xaa00aa, 0xaaaaaa }, // palette 1 low
	{ 0x000000, 0x00aa00, 0xaa0000, 0xaa5500 }, // palette 0 low
	{ 0x000000, 0x00aaaa, 0xaa0000, 0xaaaaaa }, // 3rd palette low
	{ 0x000000, 0x55ffff, 0xff55ff, 0xffffff }, // palette 1 high
	{ 0x000000, 0x55ff55, 0xff5555, 0xffff55 }, // palette 0 high
	{ 0x000000, 0x55ffff, 0xff5555, 0xffffff }  // 3rd palette high
};

de_color de_palette_pcpaint_cga4(int palnum, int index)
{
	if(palnum<0 || palnum>5) palnum=2;
	if(index>=0 && index<4) {
		return pcpaint_cga_pals[palnum][index];
	}
	return 0;
}

// Only codepoints 32-127 are included here.
static const u8 cga_8x8_font_data[96*8] = {
	0,0,0,0,0,0,0,0,
	48,120,120,48,48,0,48,0,
	108,108,108,0,0,0,0,0,
	108,108,254,108,254,108,108,0,
	48,124,192,120,12,248,48,0,
	0,198,204,24,48,102,198,0,
	56,108,56,118,220,204,118,0,
	96,96,192,0,0,0,0,0,
	24,48,96,96,96,48,24,0,
	96,48,24,24,24,48,96,0,
	0,102,60,255,60,102,0,0,
	0,48,48,252,48,48,0,0,
	0,0,0,0,0,48,48,96,
	0,0,0,252,0,0,0,0,
	0,0,0,0,0,48,48,0,
	6,12,24,48,96,192,128,0,
	124,198,206,222,246,230,124,0,
	48,112,48,48,48,48,252,0,
	120,204,12,56,96,204,252,0,
	120,204,12,56,12,204,120,0,
	28,60,108,204,254,12,30,0,
	252,192,248,12,12,204,120,0,
	56,96,192,248,204,204,120,0,
	252,204,12,24,48,48,48,0,
	120,204,204,120,204,204,120,0,
	120,204,204,124,12,24,112,0,
	0,48,48,0,0,48,48,0,
	0,48,48,0,0,48,48,96,
	24,48,96,192,96,48,24,0,
	0,0,252,0,0,252,0,0,
	96,48,24,12,24,48,96,0,
	120,204,12,24,48,0,48,0,
	124,198,222,222,222,192,120,0,
	48,120,204,204,252,204,204,0,
	252,102,102,124,102,102,252,0,
	60,102,192,192,192,102,60,0,
	248,108,102,102,102,108,248,0,
	254,98,104,120,104,98,254,0,
	254,98,104,120,104,96,240,0,
	60,102,192,192,206,102,62,0,
	204,204,204,252,204,204,204,0,
	120,48,48,48,48,48,120,0,
	30,12,12,12,204,204,120,0,
	230,102,108,120,108,102,230,0,
	240,96,96,96,98,102,254,0,
	198,238,254,254,214,198,198,0,
	198,230,246,222,206,198,198,0,
	56,108,198,198,198,108,56,0,
	252,102,102,124,96,96,240,0,
	120,204,204,204,220,120,28,0,
	252,102,102,124,108,102,230,0,
	120,204,96,48,24,204,120,0,
	252,180,48,48,48,48,120,0,
	204,204,204,204,204,204,252,0,
	204,204,204,204,204,120,48,0,
	198,198,198,214,254,238,198,0,
	198,198,108,56,56,108,198,0,
	204,204,204,120,48,48,120,0,
	254,198,140,24,50,102,254,0,
	120,96,96,96,96,96,120,0,
	192,96,48,24,12,6,2,0,
	120,24,24,24,24,24,120,0,
	16,56,108,198,0,0,0,0,
	0,0,0,0,0,0,0,255,
	48,48,24,0,0,0,0,0,
	0,0,120,12,124,204,118,0,
	224,96,96,124,102,102,220,0,
	0,0,120,204,192,204,120,0,
	28,12,12,124,204,204,118,0,
	0,0,120,204,252,192,120,0,
	56,108,96,240,96,96,240,0,
	0,0,118,204,204,124,12,248,
	224,96,108,118,102,102,230,0,
	48,0,112,48,48,48,120,0,
	12,0,12,12,12,204,204,120,
	224,96,102,108,120,108,230,0,
	112,48,48,48,48,48,120,0,
	0,0,204,254,254,214,198,0,
	0,0,248,204,204,204,204,0,
	0,0,120,204,204,204,120,0,
	0,0,220,102,102,124,96,240,
	0,0,118,204,204,124,12,30,
	0,0,220,118,102,96,240,0,
	0,0,124,192,120,12,248,0,
	16,48,124,48,48,52,24,0,
	0,0,204,204,204,204,118,0,
	0,0,204,204,204,120,48,0,
	0,0,198,214,254,254,108,0,
	0,0,198,108,56,108,198,0,
	0,0,204,204,204,124,12,248,
	0,0,252,152,48,100,252,0,
	28,48,48,224,48,48,28,0,
	24,24,24,0,24,24,24,0,
	224,48,48,28,48,48,224,0,
	118,220,0,0,0,0,0,0,
	0,16,56,108,198,198,254,0
};

const u8 *de_get_8x8ascii_font_ptr(void)
{
	return cga_8x8_font_data;
}

static const u8 vga_cp437_font_data[256*16] = {
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

const u8 *de_get_vga_cp437_font_ptr(void)
{
	return vga_cp437_font_data;
}

void de_color_to_css(de_color color, char *buf, int buflen)
{
	u8 r, g, b;

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

u8 de_sample_nbit_to_8bit(i64 n, unsigned int x)
{
	unsigned int maxval;

	if(x==0) return 0;
	if(n<1 || n>16) return 0;
	maxval = (1<<n)-1;
	if(x>=maxval) return 255;
	return (u8)(0.5+((((double)x)/(double)maxval)*255.0));
}

u8 de_scale_63_to_255(u8 x)
{
	if(x>=63) return 255;
	return (u8)(0.5+(((double)x)*(255.0/63.0)));
}

u8 de_scale_1000_to_255(i64 x)
{
	if(x>=1000) return 255;
	if(x<=0) return 0;
	return (u8)(0.5+(((double)x)*(255.0/1000.0)));
}

u8 de_scale_n_to_255(i64 n, i64 x)
{
	if(x>=n) return 255;
	if(x<=0) return 0;
	return (u8)(0.5+(((double)x)*(255.0/(double)n)));
}

de_color de_rgb565_to_888(u32 x)
{
	u8 cr, cg, cb;
	cr = (u8)(x>>11);
	cg = (u8)((x>>5)&0x3f);
	cb = (u8)(x&0x1f);
	cr = (u8)(0.5+((double)cr)*(255.0/31.0));
	cg = (u8)(0.5+((double)cg)*(255.0/63.0));
	cb = (u8)(0.5+((double)cb)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

de_color de_bgr555_to_888(u32 x)
{
	u8 cr, cg, cb;
	cb = (u8)((x>>10)&0x1f);
	cg = (u8)((x>>5)&0x1f);
	cr = (u8)(x&0x1f);
	cb = (u8)(0.5+((double)cb)*(255.0/31.0));
	cg = (u8)(0.5+((double)cg)*(255.0/31.0));
	cr = (u8)(0.5+((double)cr)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

de_color de_rgb555_to_888(u32 x)
{
	u8 cr, cg, cb;
	cr = (u8)((x>>10)&0x1f);
	cg = (u8)((x>>5)&0x1f);
	cb = (u8)(x&0x1f);
	cr = (u8)(0.5+((double)cr)*(255.0/31.0));
	cg = (u8)(0.5+((double)cg)*(255.0/31.0));
	cb = (u8)(0.5+((double)cb)*(255.0/31.0));
	return DE_MAKE_RGB(cr, cg, cb);
}

char de_byte_to_printable_char(u8 b)
{
	if(b>=32 && b<=126) return (char)b;
	return '_';
}

// This function has been largely replaced by other functions, and should
// rarely be used. See the comment in the header file.
// s1 is not NUL terminated, but s2 will be.
// s2_size includes the NUL terminator.
// Supported conv_flags: DE_CONVFLAG_STOP_AT_NUL, DE_CONVFLAG_ALLOW_HL
// src_encoding: Only DE_ENCODING_ASCII is supported.
void de_bytes_to_printable_sz(const u8 *s1, i64 s1_len,
	char *s2, i64 s2_size, unsigned int conv_flags, de_ext_encoding src_ee)
{
	i64 i;
	i64 s2_pos = 0;
	de_ext_encoding src_encoding = DE_EXTENC_GET_BASE(src_ee);

	if(src_encoding!=DE_ENCODING_ASCII) {
		s2[0] = '\0';
		return;
	}

	for(i=0; i<s1_len; i++) {
		int is_printable = 0;

		if(s1[i]=='\0' && (conv_flags & DE_CONVFLAG_STOP_AT_NUL)) {
			break;
		}

		if(s1[i]>=32 && s1[i]<=126) {
			is_printable = 1;
		}

		if(is_printable) {
			if(s2_pos < s2_size-1) {
				s2[s2_pos++] = (char)s1[i];
			}
		}
		else if(conv_flags & DE_CONVFLAG_ALLOW_HL) {
			if(s2_pos < s2_size-6) {
				s2[s2_pos++] = 0x01; // DE_CODEPOINT_HL
				s2[s2_pos++] = '<';
				s2[s2_pos++] = de_get_hexcharUC((int)(s1[i]/16));
				s2[s2_pos++] = de_get_hexcharUC((int)(s1[i]%16));
				s2[s2_pos++] = '>';
				s2[s2_pos++] = 0x02; // DE_CODEPOINT_UNHL
			}
		}
		else {
			if(s2_pos < s2_size-1) {
				s2[s2_pos++] = '_';
			}
		}
	}

	s2[s2_pos] = '\0';
}

void de_write_codepoint_to_html(deark *c, dbuf *f, de_rune ch)
{
	int e; // How to encode this codepoint

	if(ch<0 || ch>0x10ffff || ch==DE_CODEPOINT_INVALID) ch=0xfffd;

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
		dbuf_writebyte(f, (u8)ch);
	}
	else if(e==3) {
		dbuf_write_uchar_as_utf8(f, ch);
	}
	else {
		dbuf_printf(f, "&#%d;", (int)ch);
	}
}

struct de_encmap_item {
	unsigned int reserved;
	int n;
	const char *encname;
};

static const struct de_encmap_item de_encmap_arr[] = {
	{ 0x01, DE_ENCODING_ASCII, "ascii" },
	{ 0x01, DE_ENCODING_UTF8, "utf8" },
	{ 0x01, DE_ENCODING_LATIN1, "latin1" },
	{ 0x01, DE_ENCODING_LATIN2, "latin2" },
	{ 0x01, DE_ENCODING_CP437, "cp437" },
	{ 0x01, DE_ENCODING_WINDOWS1250, "windows1250" },
	{ 0x01, DE_ENCODING_WINDOWS1251, "windows1251" },
	{ 0x01, DE_ENCODING_WINDOWS1252, "windows1252" },
	{ 0x01, DE_ENCODING_WINDOWS1253, "windows1253" },
	{ 0x01, DE_ENCODING_WINDOWS1254, "windows1254" },
	{ 0x01, DE_ENCODING_WINDOWS874, "windows874" },
	{ 0x01, DE_ENCODING_MACROMAN, "macroman" },
	{ 0x01, DE_ENCODING_PALM, "palm" },
	{ 0x01, DE_ENCODING_RISCOS, "riscos" },
	{ 0x01, DE_ENCODING_PETSCII, "petscii" },
	{ 0x01, DE_ENCODING_ATARIST, "atarist" },
	{ 0x01, DE_ENCODING_UTF16BE, "utf16be" },
	{ 0x01, DE_ENCODING_UTF16LE, "utf16le" }
};

de_encoding de_encoding_name_to_code(const char *encname)
{
	size_t k;

	for(k=0; k<DE_ARRAYCOUNT(de_encmap_arr); k++) {
		if(!de_strcasecmp(encname, de_encmap_arr[k].encname)) {
			return de_encmap_arr[k].n;
		}
	}
	return DE_ENCODING_UNKNOWN;
}

struct de_encmapwin_item {
	unsigned int flags; // 0x1=supported
	int wincodepage;
	de_encoding enc;
	const char *encname;
	const char *encname_note;
};

static const struct de_encmapwin_item de_encmapwin_arr[] = {
	{ 0x01, 1200, DE_ENCODING_UTF16LE, "UTF-16LE", NULL },
	{ 0x01, 1250, DE_ENCODING_WINDOWS1250, "Windows-1250", "Central/Eastern European" },
	{ 0x01, 1251, DE_ENCODING_WINDOWS1251, "Windows-1251", "Cyrillic" },
	{ 0x01, 1252, DE_ENCODING_WINDOWS1252, "Windows-1252", NULL },
	{ 0x01, 1253, DE_ENCODING_WINDOWS1253, "Windows-1253", "Greek" },
	{ 0x01, 1254, DE_ENCODING_WINDOWS1254, "Windows-1254", "Turkish" },
	{ 0x01, 10000, DE_ENCODING_MACROMAN, "MacRoman", NULL },
	{ 0x01, 65001, DE_ENCODING_UTF8, "UTF-8", NULL },
	{ 0x01, 874, DE_ENCODING_WINDOWS874, "Windows-874", "Thai" },
	{ 0x00, 932, DE_ENCODING_UNKNOWN, "Windows-932", "Japanese" },
	{ 0x00, 936, DE_ENCODING_UNKNOWN, "Windows-936", "simplified Chinese" },
	{ 0x00, 1255, DE_ENCODING_UNKNOWN, "Windows-1255", "Hebrew" },
	{ 0x00, 1256, DE_ENCODING_UNKNOWN, "Windows-1256", "Arabic" },
	{ 0x00, 1257, DE_ENCODING_UNKNOWN, "Windows-1257", "Baltic" },
	{ 0x00, 1258, DE_ENCODING_UNKNOWN, "Windows-1258", "Vietnamese" }
};

// Returns a DE_ENCODING_* code.
// Returns DE_ENCODING_UNKNOWN if unsupported or unknown.
// encname can be NULL.
// flags:
//  0x1: If encoding is known but unsupported, append "(unsupported)" to the
//    description.
de_encoding de_windows_codepage_to_encoding(deark *c, int wincodepage,
	char *encname, size_t encname_len, unsigned int flags)
{
	size_t k;
	const struct de_encmapwin_item *cpinfo = NULL;

	for(k=0; k<DE_ARRAYCOUNT(de_encmapwin_arr); k++) {
		if(de_encmapwin_arr[k].wincodepage == wincodepage) {
			cpinfo = &de_encmapwin_arr[k];
			break;
		}
	}

	if(cpinfo) {
		// Code page is known, though not necessarily supported.
		if(encname) {
			char note_tmp[80];
			if(cpinfo->encname_note) {
				de_snprintf(note_tmp, sizeof(note_tmp), " (%s)", cpinfo->encname_note);
			}
			else {
				note_tmp[0] = '\0';
			}
			de_snprintf(encname, encname_len, "%s%s%s", cpinfo->encname, note_tmp,
				((cpinfo->flags&0x1)==0 && (flags&0x1)!=0)?" (unsupported)":"");
		}
		return (cpinfo->flags&0x1) ? cpinfo->enc : DE_ENCODING_UNKNOWN;
	}

	if(encname) {
		de_strlcpy(encname, "?", encname_len);
	}
	return DE_ENCODING_UNKNOWN;
}

void de_decode_base16(deark *c, dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, unsigned int flags)
{
	i64 pos = pos1;
	u8 b;
	int bad_warned = 0;
	struct base16_ctx {
		int cbuf_count;
		u8 cbuf[5];
	};
	struct base16_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct base16_ctx));
	pos = pos1;
	d->cbuf_count = 0;
	while(pos<pos1+len) {
		b = dbuf_getbyte_p(inf, &pos);
		if(b>='0' && b<='9') {
			d->cbuf[d->cbuf_count++] = b-48;
		}
		else if(b>='A' && b<='F') {
			d->cbuf[d->cbuf_count++] = b-55;
		}
		else if(b>='a' && b<='f') {
			d->cbuf[d->cbuf_count++] = b-87;
		}
		else if(b==9 || b==10 || b==13 || b==32) {
			; // ignore whitespace
		}
		else {
			if(!bad_warned) {
				de_warn(c, "Bad hex character(s) found (offset %d)", (int)pos);
				bad_warned = 1;
			}
		}

		if(d->cbuf_count>=2) {
			dbuf_writebyte(outf, (d->cbuf[0]<<4)|(d->cbuf[1]));
			d->cbuf_count=0;
		}
	}

	if(d->cbuf_count>0) {
		de_warn(c, "Unexpected end of hex data");
	}

	de_free(c, d);
}
