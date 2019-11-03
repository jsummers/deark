// See the file readme-compface.txt for more information about this file.
// Modifications for Deark are Copyright (C) 2017 Jason Summers.
//
// This file contains portions of the original files compface_private.h,
// compface.h, data.h, file.c, arith.c, gen.c, compress.c, uncompface.c, and
// uncmain.c.
// --------------------------------------------------------------------------

/*
 *  Compface - 48x48x1 image compression and decompression
 *
 *  Copyright (c) James Ashton - Sydney University - June 1990.
 *
 *  Written 11th November 1989.
 *
 *  Permission is given to distribute these sources, as long as the
 *  copyright messages are not removed, and no monies are exchanged.
 *
 *  No responsibility is taken for any errors on inaccuracies inherent
 *  either to the comments or the code of this program, but if reported
 *  to me, then an attempt will be made to fix them.
 */

//========================= compface_private.h begin =========================

//========================= compface.h begin =========================

/* define the face size - 48x48x1 */
#define XFACE_WIDTH 48
#define XFACE_HEIGHT XFACE_WIDTH

/* total number of pixels */
#define PIXELS (XFACE_WIDTH * XFACE_HEIGHT)

/* compressed output uses the full range of printable characters.
 * in ascii these are in a contiguous block so we just need to know
 * the first and last.  The total number of printables is needed too */
#define FIRSTPRINT '!'
#define LASTPRINT '~'
#define NUMPRINTS (LASTPRINT - FIRSTPRINT + 1)

/* Portable, very large unsigned integer arithmetic is needed.
 * Implementation uses arrays of WORDs.  COMPs must have at least
 * twice as many bits as WORDs to handle intermediate results */
#define XFACE_WORD unsigned char
#define XFACE_COMP u32
#define BITSPERWORD 8
#define WORDCARRY (1 << BITSPERWORD)
#define WORDMASK (WORDCARRY - 1)
#define MAXWORDS ((PIXELS * 2 + BITSPERWORD - 1) / BITSPERWORD)

typedef struct bigint
{
	int b_words;
	XFACE_WORD b_word[MAXWORDS];
} BigInt;

/* This is the guess the next pixel table.  Normally there are 12 neighbour
 * pixels used to give 1<<12 cases but in the upper left corner lesser
 * numbers of neighbours are available, leading to 6231 different guesses */
typedef struct guesses
{
	const u8 g_00[/*1<<12*/ 1<<9];
	const u8 g_01[/*1<<7 */ 1<<4];
	const u8 g_02[/*1<<2 */ 1   ];
	const u8 g_10[/*1<<9 */ 1<<6];
	const u8 g_20[/*1<<6 */ 1<<3];
#if 0 // See comment for Gen(), below.
	const u8 g_30[/*1<<8 */ 1<<5];
#endif
	const u8 g_40[/*1<<10*/ 1<<7];
	const u8 g_11[/*1<<5 */ 1<<2];
	const u8 g_21[/*1<<3 */ 1<<0];
#if 0
	const u8 g_31[/*1<<5 */ 1<<2];
#endif
	const u8 g_41[/*1<<6 */ 1<<3];
	const u8 g_12[/*1<<1 */ 1   ];
	const u8 g_22[/*1<<0 */ 1   ];
#if 0
	const u8 g_32[/*1<<2 */ 1   ];
#endif
	const u8 g_42[/*1<<2 */ 1   ];
} Guesses;

/* Data of varying probabilities are encoded by a value in the range 0 - 255.
 * The probability of the data determines the range of possible encodings.
 * Offset gives the first possible encoding of the range */
typedef struct prob
{
	XFACE_WORD p_range;
	XFACE_WORD p_offset;
} Prob;

/* Each face is encoded using 9 octrees of 16x16 each.  Each level of the
 * trees has varying probabilities of being white, grey or black.
 * The table below is based on sampling many faces */

#define BLACK 0
#define GREY 1
#define WHITE 2

//========================= compface.h end =========================

/* data.h was established by sampling over 1000 faces and icons */
static const Guesses gg_G
=
//========================= data.h begin =========================
{
	{ // 00
		0x00,0x00,0x01,0x01,0x00,0x00,0xe3,0xdf,0x05,0x17,0x05,0x0f,0x00,0x1b,0x0f,0xdf,
		0x00,0x04,0x00,0x00,0x0d,0x0f,0x03,0x7f,0x00,0x00,0x00,0x01,0x00,0x1d,0x45,0x2f,
		0x00,0x00,0x00,0x0d,0x00,0x0a,0xff,0xff,0x00,0x04,0x00,0x05,0x01,0x3f,0xcf,0xff,
		0x10,0x01,0x80,0xc9,0x0f,0x0f,0xff,0xff,0x00,0x00,0x00,0x00,0x1b,0x1f,0xff,0xff,
		0x4f,0x54,0x07,0x1f,0x57,0x47,0xd7,0x3d,0xff,0xff,0x5f,0x1f,0x7f,0xff,0x7f,0x7f,
		0x05,0x0f,0x01,0x0f,0x0f,0x5f,0x9b,0xdf,0x7f,0xff,0x5f,0x1d,0x5f,0xff,0x0f,0x1f,
		0x0f,0x5f,0x03,0x1f,0x4f,0x5f,0xf7,0x7f,0x7f,0xff,0x0d,0x0f,0xfb,0xff,0xf7,0xbf,
		0x0f,0x4f,0xd7,0x3f,0x4f,0x7f,0xff,0xff,0x67,0xbf,0x56,0x25,0x1f,0x7f,0x9f,0xff,
		0x00,0x00,0x00,0x05,0x5f,0x7f,0x01,0xdf,0x14,0x00,0x05,0x0f,0x07,0xa2,0x09,0x0f,
		0x00,0x00,0x00,0x00,0x0f,0x5f,0x18,0xd7,0x94,0x71,0x00,0x05,0x1f,0xb7,0x0c,0x07,
		0x0f,0x0f,0x00,0x0f,0x0f,0x1f,0x84,0x8f,0x05,0x15,0x05,0x0f,0x4f,0xff,0x87,0xdf,
		0x05,0x01,0x10,0x00,0x0f,0x0f,0x00,0x08,0x05,0x04,0x04,0x01,0x4f,0xff,0x9f,0x8f,
		0x4a,0x40,0x5f,0x5f,0xff,0xfe,0xdf,0xff,0x7f,0xf7,0xff,0x7f,0xff,0xff,0x7b,0xff,
		0x0f,0xfd,0xd7,0x5f,0x4f,0x7f,0x7f,0xdf,0xff,0xff,0xff,0xff,0xff,0x77,0xdf,0x7f,
		0x4f,0xef,0xff,0xff,0x77,0xff,0xff,0xff,0x6f,0xff,0x0f,0x4f,0xff,0xff,0x9d,0xff,
		0x0f,0xef,0xff,0xdf,0x6f,0xff,0xff,0xff,0x4f,0xff,0xcd,0x0f,0x4f,0xff,0xff,0xdf,
		0x00,0x00,0x00,0x0b,0x05,0x02,0x02,0x0f,0x04,0x00,0x00,0x0c,0x01,0x06,0x00,0x0f,
		0x20,0x03,0x00,0x00,0x05,0x0f,0x40,0x08,0x00,0x00,0x00,0x01,0x00,0x01,0x0c,0x0f,
		0x01,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x00,0x14,0x01,0x05,0x01,0x15,0xaf,0x0f,
		0x00,0x01,0x10,0x00,0x08,0x00,0x46,0x0c,0x20,0x00,0x88,0x00,0x0f,0x15,0xff,0xdf,
		0x02,0x00,0x00,0x0f,0x7f,0x5f,0xdb,0xff,0x4f,0x3e,0x05,0x0f,0x7f,0xf7,0x95,0x4f,
		0x0d,0x0f,0x01,0x0f,0x4f,0x5f,0x9f,0xdf,0x25,0x0e,0x0d,0x0d,0x4f,0x7f,0x8f,0x0f,
		0x0f,0xfa,0x04,0x4f,0x4f,0xff,0xf7,0x77,0x47,0xed,0x05,0x0f,0xff,0xff,0xdf,0xff,
		0x4f,0x6f,0xd8,0x5f,0x0f,0x7f,0xdf,0x5f,0x07,0x0f,0x94,0x0d,0x1f,0xff,0xff,0xff,
		0x00,0x02,0x00,0x03,0x46,0x57,0x01,0x0d,0x01,0x08,0x01,0x0f,0x47,0x6c,0x0d,0x0f,
		0x02,0x00,0x00,0x00,0x0b,0x4f,0x00,0x08,0x05,0x00,0x95,0x01,0x0f,0x7f,0x0c,0x0f,
		0x01,0x0e,0x00,0x00,0x0f,0x41,0x00,0x00,0x04,0x24,0x0d,0x0f,0x0f,0x7f,0xcf,0xdf,
		0x00,0x00,0x00,0x00,0x04,0x40,0x00,0x00,0x06,0x26,0xcf,0x05,0xcf,0x7f,0xdf,0xdf,
		0x00,0x00,0x17,0x5f,0xff,0xfd,0xff,0xff,0x46,0x09,0x4f,0x5f,0x7f,0xfd,0xdf,0xff,
		0x0a,0x88,0xa7,0x7f,0x7f,0xff,0xff,0xff,0x0f,0x04,0xdf,0x7f,0x4f,0xff,0x9f,0xff,
		0x0e,0xe6,0xdf,0xff,0x7f,0xff,0xff,0xff,0x0f,0xec,0x8f,0x4f,0x7f,0xff,0xdf,0xff,
		0x0f,0xcf,0xdf,0xff,0x6f,0x7f,0xff,0xff,0x03,0x0c,0x9d,0x0f,0x7f,0xff,0xff,0xff
	},
	{ // 01
		0x37,0x73,0x00,0x19,0x57,0x7f,0xf5,0xfb,0x70,0x33,0xf0,0xf9,0x7f,0xff,0xff,0xff
	},
	{ // 02
		0x50
	},
	{ // 10
		0x00,0x00,0x00,0x00,0x50,0x00,0xf3,0x5f,0x84,0x04,0x17,0x9f,0x04,0x23,0x05,0xff,
		0x00,0x00,0x00,0x02,0x03,0x03,0x33,0xd7,0x05,0x03,0x5f,0x3f,0x17,0x33,0xff,0xff,
		0x00,0x80,0x02,0x04,0x12,0x00,0x11,0x57,0x05,0x25,0x05,0x03,0x35,0xbf,0x9f,0xff,
		0x07,0x6f,0x20,0x40,0x17,0x06,0xfa,0xe8,0x01,0x07,0x1f,0x9f,0x1f,0xff,0xff,0xff
	},
	{ // 20
		0x04,0x00,0x01,0x01,0x43,0x2e,0xff,0x3f
	},
#if 0 // See comment for Gen(), below.
	{ // 30
		0x11,0x11,0x11,0x11,0x51,0x11,0x13,0x11,0x11,0x11,0x13,0x11,0x11,0x11,0x33,0x11,
		0x13,0x11,0x13,0x13,0x13,0x13,0x31,0x31,0x11,0x01,0x11,0x11,0x71,0x11,0x11,0x75
	},
#endif
	{ // 40
		0x00,0x0f,0x00,0x09,0x00,0x0d,0x00,0x0d,0x00,0x0f,0x00,0x4e,0xe4,0x0d,0x10,0x0f,
		0x00,0x0f,0x44,0x4f,0x00,0x1e,0x0f,0x0f,0xae,0xaf,0x45,0x7f,0xef,0xff,0x0f,0xff,
		0x00,0x09,0x01,0x11,0x00,0x01,0x1c,0xdd,0x00,0x15,0x00,0xff,0x00,0x10,0x00,0xfd,
		0x00,0x0f,0x4f,0x5f,0x3d,0xff,0xff,0xff,0x4f,0xff,0x1c,0xff,0xdf,0xff,0x8f,0xff,
		0x00,0x0d,0x00,0x00,0x00,0x15,0x01,0x07,0x00,0x01,0x02,0x1f,0x01,0x11,0x05,0x7f,
		0x00,0x1f,0x41,0x57,0x1f,0xff,0x05,0x77,0x0d,0x5f,0x4d,0xff,0x4f,0xff,0x0f,0xff,
		0x00,0x00,0x02,0x05,0x00,0x11,0x05,0x7d,0x10,0x15,0x2f,0xff,0x40,0x50,0x0d,0xfd,
		0x04,0x0f,0x07,0x1f,0x07,0x7f,0x0f,0xbf,0x0d,0x7f,0x0f,0xff,0x4d,0x7d,0x0f,0xff
	},
	{ // 11
		0x01,0x13,0x03,0x7f
	},
	{ // 21
		0x17
	},
#if 0
	{ // 31
		0x55,0x57,0x57,0x7f
	},
#endif
	{ // 41
		0x01,0x01,0x01,0x1f,0x03,0x1f,0x3f,0xff
	},
	{ // 12
		0x40
	},
	{ // 22
		0x00
	},
#if 0
	{ // 32
		0x10
	},
#endif
	{ // 42
		0x40
	}
}
//========================= data.h end =========================
;

/* A stack of probability values */

static const Prob gg_levels[4][3]
=
{
	{{1, 255},	{251, 0},	{4, 251}},	/* Top of tree almost always grey */
	{{1, 255},	{200, 0},	{55, 200}},
	{{33, 223},	{159, 0},	{64, 159}},
	{{131, 0},	{0, 0}, 	{125, 131}}	/* Grey disallowed at bottom */
}
;

/* At the bottom of the octree 2x2 elements are considered black if any
 * pixel is black.  The probabilities below give the distribution of the
 * 16 possible 2x2 patterns.  All white is not really a possibility and
 * has a probability range of zero.  Again, experimentally derived data */

static const Prob gg_freqs[16]
=
{
	{0, 0}, 	{38, 0},	{38, 38},	{13, 152},
	{38, 76},	{13, 165},	{13, 178},	{6, 230},
	{38, 114},	{13, 191},	{13, 204},	{6, 236},
	{13, 217},	{6, 242},	{5, 248},	{3, 253}
}
;

//========================= compface_private.h end =========================

struct xfacectx {
	deark *c;
	int errflag;

	dbuf *inf;
	i64 inf_fpos;

	BigInt gg_B;

	/* internal face representation - 1 char per pixel is faster */
	char gg_F[PIXELS];

	// fbuf stores the contents of the source file, plus a NUL terminator.
	// (Originally, fbuf was overloaded and used for other things as well.)
	/* the buffer is longer than needed to handle sparse input formats */
#define FACEBUFLEN 2048
	char gg_fbuf[FACEBUFLEN];
};

static int BigPop(struct xfacectx *ctx, const Prob *);
static void ReadBuf(struct xfacectx *ctx);
static void uncompface(struct xfacectx *ctx);
static void BigAdd(struct xfacectx *ctx, unsigned char);
static void BigClear(struct xfacectx *ctx);
static void BigRSH(struct xfacectx *ctx, XFACE_WORD *r);
static void BigMul(struct xfacectx *ctx, unsigned char);
static void BigRead(struct xfacectx *ctx, const char *);
static void PopGreys(struct xfacectx *ctx, char *, int, int);
static void UnCompAll(struct xfacectx *ctx);
static void UnCompress(struct xfacectx *ctx, char *, int, int, int);
static void WriteFace(struct xfacectx *ctx);

//========================= file.c begin =========================

// Reads ctx->gg_fbuf into gg_B, as a big int.
static void
BigRead(struct xfacectx *ctx, const char *fbuf)
{
	int c;

	while (*fbuf != '\0')
	{
		c = *(fbuf++);
		if ((c < FIRSTPRINT) || (c > LASTPRINT))
			continue;
		BigMul(ctx, NUMPRINTS);
		if(ctx->errflag) return;
		BigAdd(ctx, (XFACE_WORD)(c - FIRSTPRINT));
		if(ctx->errflag) return;
	}
}

// Create an image file using the raw data in gg_F.
// (Originally, this wrote a text file to gg_fbuf.)
static void
WriteFace(struct xfacectx *ctx)
{
	i64 i, j;
	de_bitmap *img = NULL;

	img = de_bitmap_create(ctx->c, XFACE_WIDTH, XFACE_HEIGHT, 1);

	for(j=0; j<XFACE_HEIGHT; j++) {
		for(i=0; i<XFACE_WIDTH; i++) {
			if(ctx->gg_F[j*XFACE_WIDTH + i] == 0) {
				de_bitmap_setpixel_gray(img, i, j, 255);
			}
		}
	}

	de_bitmap_write_to_file_finfo(img, NULL, 0);
	de_bitmap_destroy(img);
}

//========================= file.c end =========================

//========================= arith.c begin =========================

static int
BigPop(struct xfacectx *ctx, const Prob *p)
{
	XFACE_WORD tmp = 0;
	int i;

	BigRSH(ctx, &tmp);
	i = 0;
	while ((tmp < p->p_offset) || (tmp >= p->p_range + p->p_offset))
	{
		p++;
		i++;
	}
	BigMul(ctx, p->p_range);
	if(ctx->errflag) return 0;
	BigAdd(ctx, tmp - p->p_offset);
	if(ctx->errflag) return 0;
	return i;
}

// This is what's left of the original BigDiv() function.
// It's only needed for the right-shift operation.
// (Stores the remainder in the word pointed to by r)
static void
BigRSH(struct xfacectx *ctx, XFACE_WORD *r)
{
	int i;
	XFACE_WORD *w;

	if (ctx->gg_B.b_words == 0)
	{
		*r = 0;
		return;
	}

	{
		i = --ctx->gg_B.b_words;
		w = ctx->gg_B.b_word;
		*r = *w;
		while (i--)
		{
			*w = *(w + 1);
			w++;
		}
		*w = 0;
	}
}

/* Multiply a by ctx->gg_B storing the result in ctx->gg_B
 */
static void
BigMul(struct xfacectx *ctx, XFACE_WORD a)
{
	int i;
	XFACE_WORD *w;
	XFACE_COMP c;

	a &= WORDMASK;
	if ((a == 1) || (ctx->gg_B.b_words == 0))
		return;
	if (a == 0)	/* treat this as a == WORDCARRY */
	{			/* and just shift everything left a XFACE_WORD */
		if ((i = ctx->gg_B.b_words++) >= MAXWORDS - 1) {
			de_err(ctx->c, "xface: Internal error (1)");
			ctx->errflag = 1;
			return;
		}
		w = ctx->gg_B.b_word + i;
		while (i--)
		{
			*w = *(w - 1);
			w--;
		}
		*w = 0;
		return;
	}
	i = ctx->gg_B.b_words;
	w = ctx->gg_B.b_word;
	c = 0;
	while (i--)
	{
		c += (XFACE_COMP)*w * (XFACE_COMP)a;
		*(w++) = (XFACE_WORD)(c & WORDMASK);
		c >>= BITSPERWORD;
	}
	if (c)
	{
		if (ctx->gg_B.b_words++ >= MAXWORDS) {
			de_err(ctx->c, "Invalid or oversized X-Face image");
			ctx->errflag = 1;
			return;
		}
		*w = (XFACE_COMP)(c & WORDMASK);
	}
}

/* Add to a to ctx->gg_B storing the result in ctx->gg_B
 */
static void
BigAdd(struct xfacectx *ctx, XFACE_WORD a)
{
	int i;
	XFACE_WORD *w;
	XFACE_COMP c;

	a &= WORDMASK;
	if (a == 0)
		return;
	i = 0;
	w = ctx->gg_B.b_word;
	c = a;
	while ((i < ctx->gg_B.b_words) && c)
	{
		c += (XFACE_COMP)*w;
		*w++ = (XFACE_WORD)(c & WORDMASK);
		c >>= BITSPERWORD;
		i++;
	}
	if ((i == ctx->gg_B.b_words) && c)
	{
		if (ctx->gg_B.b_words++ >= MAXWORDS) {
			de_err(ctx->c, "xface: Internal error (3)");
			ctx->errflag = 1;
			return;
		}
		*w = (XFACE_COMP)(c & WORDMASK);
	}
}

static void
BigClear(struct xfacectx *ctx)
{
	ctx->gg_B.b_words = 0;
}

//========================= arith.c end =========================

//========================= gen.c begin =========================

static void gen_helper(struct xfacectx *ctx, const u8 *arr, size_t arr_len,
	int h, int k)
{
	size_t arr_idx = 0;

	if(k<0 || h<0 || h>=(int)sizeof(ctx->gg_F)) {
		return;
	}
	arr_idx = (size_t)(k/8);
	if(arr_idx>=arr_len) {
		return;
	}
	if((arr[arr_idx]>>(7-(k%8)))&0x1) {
		ctx->gg_F[h] ^= 1;
	}
}

// I guess that Gen() is where prediction is done.
// It has what appears to be a programming error, considering that the
// "case XFACE_WIDTH" code cannot be reached, because i is never larger
// than XFACE_WIDTH-1. I suspect that, in fact, all of the "cases" are off by
// 1. But it's not like I can "fix" it, because that would change the format
// in an incompatible way. -JS

static void
Gen(struct xfacectx *ctx, char *f, size_t f_len)
{
	int m, l, k, j, i, h;

#define XFACE_GEN(g) gen_helper(ctx, gg_G.g, sizeof(gg_G.g), h, k); break

	for (j = 0; j < XFACE_HEIGHT;  j++)
	{
		for (i = 0; i < XFACE_WIDTH;  i++)
		{
			h = i + j * XFACE_WIDTH;
			k = 0;
			for (l = i - 2; l <= i + 2; l++)
				for (m = j - 2; m <= j; m++)
				{
					if ((l >= i) && (m == j))
						continue;
					if ((l > 0) && (l <= XFACE_WIDTH) && (m > 0)) {
						if((l + m * XFACE_WIDTH < 0) || (l + m * XFACE_WIDTH >= (int)f_len)) {
							de_err(ctx->c, "xface: Internal error (4)");
							ctx->errflag = 1;
							return;
						}
						k = f[l + m * XFACE_WIDTH] ? k * 2 + 1 : k * 2;
					}
				}
			switch (i)
			{
				case 1 :
					switch (j)
					{
						case 1 : XFACE_GEN(g_22);
						case 2 : XFACE_GEN(g_21);
						default : XFACE_GEN(g_20);
					}
					break;
				case 2 :
					switch (j)
					{
						case 1 : XFACE_GEN(g_12);
						case 2 : XFACE_GEN(g_11);
						default : XFACE_GEN(g_10);
					}
					break;
				case XFACE_WIDTH - 1 :
					switch (j)
					{
						case 1 : XFACE_GEN(g_42);
						case 2 : XFACE_GEN(g_41);
						default : XFACE_GEN(g_40);
					}
					break;
#if 0
				case XFACE_WIDTH :
					switch (j)
					{
						case 1 : XFACE_GEN(g_32);
						case 2 : XFACE_GEN(g_31);
						default : XFACE_GEN(g_30);
					}
					break;
#endif
				default :
					switch (j)
					{
						case 1 : XFACE_GEN(g_02);
						case 2 : XFACE_GEN(g_01);
						default : XFACE_GEN(g_00);
					}
					break;
			}
		}
	}

#undef XFACE_GEN
}

//========================= gen.c end =========================

//========================= compress.c begin =========================

static void
PopGreys(struct xfacectx *ctx, char *f, int wid, int hei)
{
	if (wid > 3)
	{
		wid /= 2;
		hei /= 2;
		PopGreys(ctx, f, wid, hei);
		if(ctx->errflag) return;
		PopGreys(ctx, &f[wid], wid, hei);
		if(ctx->errflag) return;
		PopGreys(ctx, &f[XFACE_WIDTH * hei], wid, hei);
		if(ctx->errflag) return;
		PopGreys(ctx, &f[XFACE_WIDTH * hei + wid], wid, hei);
		if(ctx->errflag) return;
	}
	else
	{
		wid = BigPop(ctx, gg_freqs);
		if(ctx->errflag) return;
		if (wid & 1)
			f[0] = 1;
		if (wid & 2)
			f[1] = 1;
		if (wid & 4)
			f[XFACE_WIDTH] = 1;
		if (wid & 8)
			f[XFACE_WIDTH + 1] = 1;
	}
}

static void
UnCompress(struct xfacectx *ctx, char *f, int wid, int hei, int lev)
{
	int ret;

	ret = BigPop(ctx, &gg_levels[lev][0]);
	if(ctx->errflag) return;

	switch (ret)
	{
		case WHITE :
			return;
		case BLACK :
			PopGreys(ctx, f, wid, hei);
			return;
		default :
			wid /= 2;
			hei /= 2;
			lev++;
			UnCompress(ctx, f, wid, hei, lev);
			if(ctx->errflag) return;
			UnCompress(ctx, &f[wid], wid, hei, lev);
			if(ctx->errflag) return;
			UnCompress(ctx, &f[hei * XFACE_WIDTH], wid, hei, lev);
			if(ctx->errflag) return;
			UnCompress(ctx, &f[wid + hei * XFACE_WIDTH], wid, hei, lev);
			return;
	}
}

// Decompresses image from ctx->gg_fbuf to ctx->gg_F.
// Assumes ctx->gg_F is initialized to all zero bytes.
static void
UnCompAll(struct xfacectx *ctx)
{
	BigClear(ctx);
	BigRead(ctx, ctx->gg_fbuf);

	UnCompress(ctx, ctx->gg_F, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + 16, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + 32, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 16, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 16 + 16, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 16 + 32, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 32, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 32 + 16, 16, 16, 0);
	if(ctx->errflag) return;
	UnCompress(ctx, ctx->gg_F + XFACE_WIDTH * 32 + 32, 16, 16, 0);
	if(ctx->errflag) return;
}

//========================= compress.c end =========================

//========================= uncompface.c begin =========================

static void
uncompface(struct xfacectx *ctx)
{
	UnCompAll(ctx);
	if(ctx->errflag) return;
	Gen(ctx, ctx->gg_F, sizeof(ctx->gg_F));
	if(ctx->errflag) return;
	WriteFace(ctx);
}

//========================= uncompface.c end =========================

//========================= uncmain.c begin =========================

static void
uncompface_main(deark *c)
{
  struct xfacectx *ctx = NULL;

  ctx = de_malloc(c, sizeof(struct xfacectx));
  ctx->c = c;
  ctx->inf = c->infile;

  ReadBuf(ctx);
  uncompface(ctx);

  de_free(c, ctx);
}

// Read the file into ctx->gg_fbuf.
static void
ReadBuf(struct xfacectx *ctx)
{
	i64 amt_to_read;
	i64 startpos;

	startpos = 0;
	amt_to_read = ctx->inf->len;
	if(amt_to_read > FACEBUFLEN-1)
		amt_to_read = FACEBUFLEN-1;

	// Handle a possible "X-Face:" prefix.
	if(amt_to_read>=8 && has_x_header(ctx->inf)) {
		de_dbg(ctx->c, "found X-Face prefix");
		startpos += 8;
		amt_to_read -= 8;
	}

	dbuf_read(ctx->inf, (u8*)ctx->gg_fbuf, startpos, amt_to_read);

	ctx->gg_fbuf[amt_to_read] = '\0';
}

//========================= uncmain.c end =========================
