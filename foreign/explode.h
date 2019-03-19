// ZIP type 6 "implode" decompression.
// Based on Mark Adler's public domain code from Info-ZIP UnZip v5.4.
// See the file readme-explode.txt for more information.
// The code has been heavily modified for Deark (2019-03).
// This file (explode.h) is hereby left in the public domain; or it may, at
// your option, be distributed under the same terms as the main Deark software.
// -JS

//========================= unzip.h begin =========================

typedef unsigned char   uch;    /* code assumes unsigned bytes; these type-  */
typedef u16   ush;    /*  defs replace byte/UWORD/ULONG (which are */
typedef u32   ulg;    /*  predefined on some systems) & match zip  */

#define IZI_OK   0
#define IZI_ERR1 1
#define IZI_ERR2 2
#define IZI_ERR3 3
#define IZI_ERR4 4

//========================= unzpriv.h begin =========================

#define WSIZE 0x8000  /* window size--must be a power of two, and */
                      /* at least 8K for zip's implode method */
                      /* (at least 32K for zip's deflate method) */

typedef struct local_file_header {                 /* LOCAL */
    ush general_purpose_bit_flag;
} local_file_hdr;

struct huft {
    uch e;                /* number of extra bits or operation */
    uch b;                /* number of bits in this code or subcode */

    ush n;            /* literal, length base, or distance base */
    struct huft *t;   /* pointer to next level of table */
};

//========================= globals.h begin =========================

typedef struct Globals {
    i64 csize;           /* used by decompr. (NEXTBYTE): must be signed */
    i64 ucsize;          /* used by unReduce(), explode() */
	uch Slide[WSIZE];
    local_file_hdr  lrec;          /* used in unzip.c, extract.c */
	deark *c;
	dbuf *inf;
	i64 inf_curpos;
	i64 inf_endpos;
	dbuf *outf;
} Uz_Globs;  /* end of struct Globals */

//========================= globals.h end =========================

static void   huft_free(Uz_Globs *pG, struct huft *t);
static int    huft_build(Uz_Globs *pG, const unsigned *b, unsigned n,
    unsigned s, const ush *d, const ush *e, struct huft **t, int *m);

#define NEXTBYTE  izi_readbyte(pG)

//========================= unzpriv.h end =========================

//========================= unzip.h end =========================

//========================= fileio.c begin =========================

static void izi_flush(Uz_Globs *pG, uch *rawbuf, ulg size)
{
	dbuf_write(pG->outf, rawbuf, size);
}

// Originally:
/* refill inbuf and return a byte if available, else EOF */
// Currently, we don't bother with pG->inbuf, though that would be more
// efficient. The NEXTBYTE macro has been modified to not use inbuf.
static int izi_readbyte(Uz_Globs *pG)
{
	if(pG->inf_curpos >= pG->inf_endpos) {
		return EOF;
	}
	return (int)dbuf_getbyte(pG->inf, pG->inf_curpos++);
}

//========================= fileio.c end =========================

//========================= consts.h begin =========================

/* And'ing with mask_bits[n] masks the lower n bits */
static const ush mask_bits[] = {
    0x0000,
    0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
    0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

//========================= consts.h end =========================

//========================= explode.c begin =========================

/* explode.c -- put in the public domain by Mark Adler
   version c15, 6 July 1996 */


/* You can do whatever you like with this source file, though I would
   prefer that if you modify it and redistribute it that you include
   comments to that effect with your name and the date.  Thank you.

   [...]
 */


/*
   Explode imploded (PKZIP method 6 compressed) data.  This compression
   method searches for as much of the current string of bytes (up to a length
   of ~320) in the previous 4K or 8K bytes.  If it doesn't find any matches
   (of at least length 2 or 3), it codes the next byte.  Otherwise, it codes
   the length of the matched string and its distance backwards from the
   current position.  Single bytes ("literals") are preceded by a one (a
   single bit) and are either uncoded (the eight bits go directly into the
   compressed stream for a total of nine bits) or Huffman coded with a
   supplied literal code tree.  If literals are coded, then the minimum match
   length is three, otherwise it is two.

   There are therefore four kinds of imploded streams: 8K search with coded
   literals (min match = 3), 4K search with coded literals (min match = 3),
   8K with uncoded literals (min match = 2), and 4K with uncoded literals
   (min match = 2).  The kind of stream is identified in two bits of a
   general purpose bit flag that is outside of the compressed stream.

   Distance-length pairs for matched strings are preceded by a zero bit (to
   distinguish them from literals) and are always coded.  The distance comes
   first and is either the low six (4K) or low seven (8K) bits of the
   distance (uncoded), followed by the high six bits of the distance coded.
   Then the length is six bits coded (0..63 + min match length), and if the
   maximum such length is coded, then it's followed by another eight bits
   (uncoded) to be added to the coded length.  This gives a match length
   range of 2..320 or 3..321 bytes.

   The literal, length, and distance codes are all represented in a slightly
   compressed form themselves.  What is sent are the lengths of the codes for
   each value, which is sufficient to construct the codes.  Each byte of the
   code representation is the code length (the low four bits representing
   1..16), and the number of values sequentially with that length (the high
   four bits also representing 1..16).  There are 256 literal code values (if
   literals are coded), 64 length code values, and 64 distance code values,
   in that order at the beginning of the compressed stream.  Each set of code
   values is preceded (redundantly) with a byte indicating how many bytes are
   in the code description that follows, in the range 1..256.

   The codes themselves are decoded using tables made by huft_build() from
   the bit lengths.  That routine and its comments are in the inflate.c
   module.
 */

#define wsize WSIZE

/* The implode algorithm uses a sliding 4K or 8K byte window on the
   uncompressed stream to find repeated byte strings.  This is implemented
   here as a circular buffer.  The index is updated simply by incrementing
   and then and'ing with 0x0fff (4K-1) or 0x1fff (8K-1).  Here, the 32K
   buffer of inflate is used, and it works just as well to always have
   a 32K circular buffer, so the index is anded with 0x7fff.  This is
   done to allow the window to also be used as the output buffer. */
/* This must be supplied in an external module useable like "uch slide[8192];"
   or "uch *slide;", where the latter would be malloc'ed.  In unzip, slide[]
   is actually a 32K area for use by inflate, which uses a 32K sliding window.
 */

/* Tables for length and distance */
static const ush cplen2[] =
        {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65};
static const ush cplen3[] =
        {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66};
static const ush extra[] =
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        8};
static const ush cpdist4[] =
        {1, 65, 129, 193, 257, 321, 385, 449, 513, 577, 641, 705,
        769, 833, 897, 961, 1025, 1089, 1153, 1217, 1281, 1345, 1409, 1473,
        1537, 1601, 1665, 1729, 1793, 1857, 1921, 1985, 2049, 2113, 2177,
        2241, 2305, 2369, 2433, 2497, 2561, 2625, 2689, 2753, 2817, 2881,
        2945, 3009, 3073, 3137, 3201, 3265, 3329, 3393, 3457, 3521, 3585,
        3649, 3713, 3777, 3841, 3905, 3969, 4033};
static const ush cpdist8[] =
        {1, 129, 257, 385, 513, 641, 769, 897, 1025, 1153, 1281,
        1409, 1537, 1665, 1793, 1921, 2049, 2177, 2305, 2433, 2561, 2689,
        2817, 2945, 3073, 3201, 3329, 3457, 3585, 3713, 3841, 3969, 4097,
        4225, 4353, 4481, 4609, 4737, 4865, 4993, 5121, 5249, 5377, 5505,
        5633, 5761, 5889, 6017, 6145, 6273, 6401, 6529, 6657, 6785, 6913,
        7041, 7169, 7297, 7425, 7553, 7681, 7809, 7937, 8065};

/* Macros for inflate() bit peeking and grabbing.
   The usage is:

        NEEDBITS(j);
        x = b & mask_bits[j];
        DUMPBITS(j);

   where NEEDBITS makes sure that b has at least j bits in it, and
   DUMPBITS removes the bits from b.  The macros use the variable k
   for the number of bits in b.  Normally, b and k are register
   variables for speed.
 */

#define NEEDBITS(n) do {while(k<(n)){b|=((ulg)NEXTBYTE)<<k;k+=8;}} while(0)
#define DUMPBITS(n) do {b>>=(n);k-=(n);} while(0)

/* Get the bit lengths for a code representation from the compressed
   stream.  If get_tree() returns 4, then there is an error in the data.
   Otherwise zero is returned. */
// l: bit lengths
// n: number expected
static int get_tree(Uz_Globs *pG, unsigned *l, unsigned n)
{
  unsigned i;           /* bytes remaining in list */
  unsigned k;           /* lengths entered */
  unsigned j;           /* number of codes */
  unsigned b;           /* bit length for those codes */

  /* get bit lengths */
  i = NEXTBYTE + 1;                     /* length/count pairs to read */
  k = 0;                                /* next code */
  do {
    b = ((j = NEXTBYTE) & 0xf) + 1;     /* bits in code (1..16) */
    j = ((j & 0xf0) >> 4) + 1;          /* codes with those bits (1..16) */
    if (k + j > n)
      return IZI_ERR4;                         /* don't overflow l[] */
    do {
      l[k++] = b;
    } while (--j);
  } while (--i);
  return k != n ? IZI_ERR4 : IZI_OK;                /* should have read n of them */
}

// tb, tl, td: literal, length, and distance tables
//  Uses literals if tb!=NULL.
// bb, bl, bd: number of bits decoded by those
static int explode_internal(Uz_Globs *pG, unsigned window_k,
	struct huft *tb, struct huft *tl, struct huft *td,
	int bb, int bl, int bd)
{
  i64 s;               /* bytes to decompress */
  unsigned e;  /* table entry flag/number of extra bits */
  unsigned n, d;        /* length and index for copy */
  unsigned w;           /* current window position */
  struct huft *t;       /* pointer to table entry */
  unsigned mb, ml, md;  /* masks for bb, bl, and bd bits */
  ulg b;       /* bit buffer */
  unsigned k;  /* number of bits in bit buffer */
  unsigned u;           /* true if unflushed */

  /* explode the coded data */
  b = k = w = 0;                /* initialize bit buffer, window */
  u = 1;                        /* buffer unflushed */
  mb = mask_bits[bb];           /* precompute masks for speed */
  ml = mask_bits[bl];
  md = mask_bits[bd];
  s = pG->ucsize;
  while (s > 0)                 /* do until ucsize bytes uncompressed */
  {
    NEEDBITS(1);
    if (b & 1)                  /* then literal--decode it */
    {
      DUMPBITS(1);
      s--;
      if(tb) {
        NEEDBITS((unsigned)bb);    /* get coded literal */
        if ((e = (t = tb + ((~(unsigned)b) & mb))->e) > 16) {
          do {
            if (e == 99)
              return 1;
            DUMPBITS(t->b);
            e -= 16;
            NEEDBITS(e);
          } while ((e = (t = t->t + ((~(unsigned)b) & mask_bits[e]))->e) > 16);
        }
        DUMPBITS(t->b);
        pG->Slide[w++] = (uch)t->n;
      }
      else {
        NEEDBITS(8);
        pG->Slide[w++] = (uch)b;
      }
      if (w == wsize)
      {
        izi_flush(pG, pG->Slide, (ulg)w);
        w = u = 0;
      }
      if(!tb) {
        DUMPBITS(8);
      }
    }
    else                        /* else distance/length */
    {
      DUMPBITS(1);

      if(window_k==8) {
        NEEDBITS(7);               /* get distance low bits */
        d = (unsigned)b & 0x7f;
        DUMPBITS(7);
      }
      else {
        NEEDBITS(6);               /* get distance low bits */
        d = (unsigned)b & 0x3f;
        DUMPBITS(6);
      }

      NEEDBITS((unsigned)bd);    /* get coded distance high bits */
	  if ((e = (t = td + ((~(unsigned)b) & md))->e) > 16) {
        do {
          if (e == 99)
            return 1;
          DUMPBITS(t->b);
          e -= 16;
          NEEDBITS(e);
        } while ((e = (t = t->t + ((~(unsigned)b) & mask_bits[e]))->e) > 16);
      }
      DUMPBITS(t->b);
      d = w - d - t->n;       /* construct offset */
      NEEDBITS((unsigned)bl);    /* get coded length */
	  if ((e = (t = tl + ((~(unsigned)b) & ml))->e) > 16) {
        do {
          if (e == 99)
            return 1;
          DUMPBITS(t->b);
          e -= 16;
          NEEDBITS(e);
        } while ((e = (t = t->t + ((~(unsigned)b) & mask_bits[e]))->e) > 16);
      }
      DUMPBITS(t->b);
      n = t->n;
      if (e)                    /* get length extra bits */
      {
        NEEDBITS(8);
        n += (unsigned)b & 0xff;
        DUMPBITS(8);
      }

      /* do the copy */
      s -= n;
      do {
        d &= (wsize-1);
		e = wsize - (d > w ? d : w);
        if(e>n) { e = n; }
        n -= e;
        if (u && w <= d)
        {
          de_zeromem(&pG->Slide[w], e);
          w += e;
          d += e;
        }
        else {
          if (w - d >= e)       /* (this test assumes unsigned comparison) */
          {
            de_memcpy(&pG->Slide[w], &pG->Slide[d], e);
            w += e;
            d += e;
          }
          else {                 /* do it slow to avoid memcpy() overlap */
            do {
              pG->Slide[w++] = pG->Slide[d++];
            } while (--e);
          }
        }
        if (w == wsize)
        {
          izi_flush(pG, pG->Slide, (ulg)w);
          w = u = 0;
        }
      } while (n);
    }
  }

  /* flush out pG->Slide */
  izi_flush(pG, pG->Slide, (ulg)w);
  return 0;
}

/* Explode an imploded compressed stream.  Based on the general purpose
   bit flag, decide on coded or uncoded literals, and an 8K or 4K sliding
   window.  Construct the literal (if any), length, and distance codes and
   the tables needed to decode them (using huft_build() from inflate.c),
   and call the appropriate routine for the type of data in the remainder
   of the stream.  The four routines are nearly identical, differing only
   in whether the literal is decoded or simply read in, and in how many
   bits are read in, uncoded, for the low distance bits. */
static int explode(Uz_Globs *pG)
{
  unsigned r;           /* return codes */
  struct huft *tb;      /* literal code table */
  struct huft *tl;      /* length code table */
  struct huft *td;      /* distance code table */
  int bb;               /* bits for tb */
  int bl;               /* bits for tl */
  int bd;               /* bits for td */
  unsigned l[256];      /* bit lengths for codes */


  /* Tune base table sizes.  Note: I thought that to truly optimize speed,
     I would have to select different bl, bd, and bb values for different
     compressed file sizes.  I was surprised to find out that the values of
     7, 7, and 9 worked best over a very wide range of sizes, except that
     bd = 8 worked marginally better for large compressed sizes. */
  bl = 7;
  bd = pG->csize > 200000L ? 8 : 7;

  /* With literal tree--minimum match length is 3 */
  if (pG->lrec.general_purpose_bit_flag & 4)
  {
    bb = 9;                     /* base table size for literals */
    if ((r = get_tree(pG, l, 256)) != IZI_OK)
      return (int)r;
    if ((r = huft_build(pG, l, 256, 256, NULL, NULL, &tb, &bb)) != IZI_OK)
    {
      if (r == IZI_ERR1)
        huft_free(pG, tb);
      return (int)r;
    }
    if ((r = get_tree(pG, l, 64)) != IZI_OK)
      return (int)r;
    if ((r = huft_build(pG, l, 64, 0, cplen3, extra, &tl, &bl)) != IZI_OK)
    {
      if (r == IZI_ERR1)
        huft_free(pG, tl);
      huft_free(pG, tb);
      return (int)r;
    }
    if ((r = get_tree(pG, l, 64)) != IZI_OK)
      return (int)r;
    if (pG->lrec.general_purpose_bit_flag & 2)      /* true if 8K */
    {
      if ((r = huft_build(pG, l, 64, 0, cpdist8, extra, &td, &bd)) != IZI_OK)
      {
        if (r == 1)
          huft_free(pG, td);
        huft_free(pG, tl);
        huft_free(pG, tb);
        return (int)r;
      }
      r = explode_internal(pG, 8, tb, tl, td, bb, bl, bd);
    }
    else                                        /* else 4K */
    {
      if ((r = huft_build(pG, l, 64, 0, cpdist4, extra, &td, &bd)) != IZI_OK)
      {
        if (r == IZI_ERR1)
          huft_free(pG, td);
        huft_free(pG, tl);
        huft_free(pG, tb);
        return (int)r;
      }
      r = explode_internal(pG, 4, tb, tl, td, bb, bl, bd);
    }
    huft_free(pG, td);
    huft_free(pG, tl);
    huft_free(pG, tb);
  }
  else
  /* No literal tree--minimum match length is 2 */
  {
    if ((r = get_tree(pG, l, 64)) != IZI_OK)
      return (int)r;
    if ((r = huft_build(pG, l, 64, 0, cplen2, extra, &tl, &bl)) != IZI_OK)
    {
      if (r == IZI_ERR1)
        huft_free(pG, tl);
      return (int)r;
    }
    if ((r = get_tree(pG, l, 64)) != IZI_OK)
      return (int)r;
    if (pG->lrec.general_purpose_bit_flag & 2)      /* true if 8K */
    {
      if ((r = huft_build(pG, l, 64, 0, cpdist8, extra, &td, &bd)) != IZI_OK)
      {
        if (r == IZI_ERR1)
          huft_free(pG, td);
        huft_free(pG, tl);
        return (int)r;
      }
      r = explode_internal(pG, 8, NULL, tl, td, 0, bl, bd);
    }
    else                                        /* else 4K */
    {
      if ((r = huft_build(pG, l, 64, 0, cpdist4, extra, &td, &bd)) != IZI_OK)
      {
        if (r == IZI_ERR1)
          huft_free(pG, td);
        huft_free(pG, tl);
        return (int)r;
      }
      r = explode_internal(pG, 4, NULL, tl, td, 0, bl, bd);
    }
    huft_free(pG, td);
    huft_free(pG, tl);
  }
  return (int)r;
}

/* so explode.c and inflate.c can be compiled together into one object: */
#undef NEXTBYTE
#undef NEEDBITS
#undef DUMPBITS

//========================= explode.c end =========================

//========================= inflate.c begin =========================

/* inflate.c -- put in the public domain by Mark Adler
   version c16b, 29 March 1998 */


/* If BMAX needs to be larger than 16, then h and x[] should be ulg. */
#define BMAX 16         /* maximum bit length of any code (16 for explode) */
#define N_MAX 288       /* maximum number of codes in any set */

/* Given a list of code lengths and a maximum table size, make a set of
   tables to decode that set of codes.  Return zero on success, one if
   the given code set is incomplete (the tables are still built in this
   case), two if the input is invalid (all zero length codes or an
   oversubscribed set of lengths), and three if not enough memory.
   The code with value 256 is special, and the tables are constructed
   so that no bits beyond that code are fetched when that code is
   decoded. */
// b: code lengths in bits (all assumed <= BMAX)
// n: number of codes (assumed <= N_MAX)
// s: number of simple-valued codes (0..s-1)
// d: list of base values for non-simple codes
// e: list of extra bits for non-simple codes
// t: result: starting table
// m: maximum lookup bits, returns actual
static int huft_build(Uz_Globs *pG, const unsigned *b, unsigned n, unsigned s,
	const ush *d, const ush *e, struct huft **t, int *m)
{
  unsigned a;                   /* counter for codes of length k */
  unsigned c[BMAX+1];           /* bit length count table */
  unsigned el;                  /* length of EOB code (value 256) */
  unsigned f;                   /* i repeats in table every f entries */
  int g;                        /* maximum code length */
  int h;                        /* table level */
  unsigned i;          /* counter, current code */
  unsigned j;          /* counter */
  int k;               /* number of bits in current code */
  int lx[BMAX+1];               /* memory for l[-1..BMAX-1] */
  int *l = lx+1;                /* stack of bits per table */
  const unsigned *p;   /* pointer into c[], b[], or v[] */
  struct huft *q;      /* points to current table */
  struct huft r;                /* table entry for structure assignment */
  struct huft *u[BMAX];         /* table stack */
  unsigned v[N_MAX];            /* values in order of bit length */
  int w;               /* bits before this table == (l * h) */
  unsigned x[BMAX+1];           /* bit offsets, then code stack */
  unsigned *xp;                 /* pointer into x */
  int y;                        /* number of dummy codes added */
  unsigned z;                   /* number of entries in current table */

  /* Generate counts for each bit length */
  el = n > 256 ? b[256] : BMAX; /* set length of EOB code, if any */
  de_zeromem(c, sizeof(c));
  p = b;  i = n;
  do {
    c[*p]++; p++;               /* assume all entries <= BMAX */
  } while (--i);
  if (c[0] == n)                /* null input--all zero length codes */
  {
    *t = NULL;
    *m = 0;
    return IZI_OK;
  }

  /* Find minimum and maximum length, bound *m by those */
  for (j = 1; j <= BMAX; j++)
    if (c[j])
      break;
  k = j;                        /* minimum code length */
  if ((unsigned)*m < j)
    *m = j;
  for (i = BMAX; i; i--)
    if (c[i])
      break;
  g = i;                        /* maximum code length */
  if ((unsigned)*m > i)
    *m = i;

  /* Adjust last length count to fill out codes, if needed */
  for (y = 1 << j; j < i; j++, y <<= 1)
    if ((y -= c[j]) < 0)
      return IZI_ERR2;                 /* bad input: more codes than bits */
  if ((y -= c[i]) < 0)
    return IZI_ERR2;
  c[i] += y;

  /* Generate starting offsets into the value table for each length */
  x[1] = j = 0;
  p = c + 1;  xp = x + 2;
  while (--i) {                 /* note that i == g from above */
    *xp++ = (j += *p++);
  }

  /* Make a table of values in order of bit lengths */
  de_zeromem(v, sizeof(v));
  p = b;  i = 0;
  do {
    if ((j = *p++) != 0)
      v[x[j]++] = i;
  } while (++i < n);
  n = x[g];                     /* set n to length of v */

  /* Generate the Huffman codes and for each, make the table entries */
  x[0] = i = 0;                 /* first Huffman code is zero */
  p = v;                        /* grab values in bit order */
  h = -1;                       /* no tables yet--level -1 */
  w = l[-1] = 0;                /* no bits decoded yet */
  u[0] = NULL;                  /* just to keep compilers happy */
  q = NULL;                     /* ditto */
  z = 0;                        /* ditto */

  /* go through the bit lengths (k already is bits in shortest code) */
  for (; k <= g; k++)
  {
    a = c[k];
    while (a--)
    {
      /* here i is the Huffman code of length k bits for value *p */
      /* make tables up to required level */
      while (k > w + l[h])
      {
        w += l[h++];            /* add bits already decoded */

        /* compute minimum size table less than or equal to *m bits */
        z = (z = g - w) > (unsigned)*m ? ((unsigned)*m) : z;        /* upper limit */
        if ((f = 1 << (j = k - w)) > a + 1)     /* try a k-w bit table */
        {                       /* too few codes for k-w bit table */
          f -= a + 1;           /* deduct codes from patterns left */
          xp = c + k;
          while (++j < z)       /* try smaller tables up to z bits */
          {
            if ((f <<= 1) <= *++xp)
              break;            /* enough codes to use up j bits */
            f -= *xp;           /* else deduct codes from patterns */
          }
        }
        if ((unsigned)w + j > el && (unsigned)w < el)
          j = el - w;           /* make EOB code end at table */
        z = 1 << j;             /* table entries for j-bit table */
        l[h] = j;               /* set table size in stack */

        /* allocate and link in new table */
        q = de_malloc(pG->c, (z + 1)*sizeof(struct huft));
        *t = q + 1;             /* link to list for huft_free() */
        *(t = &(q->t)) = NULL;
        u[h] = ++q;             /* table starts after link */

        /* connect to last table, if there is one */
        if (h)
        {
          x[h] = i;             /* save pattern for backing up */
          r.b = (uch)l[h-1];    /* bits to dump before this table */
          r.e = (uch)(16 + j);  /* bits in this table */
          r.t = q;            /* pointer to this table */
          j = (i & ((1 << w) - 1)) >> (w - l[h-1]);
          u[h-1][j] = r;        /* connect to last table */
        }
      }

      /* set up table entry in r */
      r.b = (uch)(k - w);
      if (p >= v + n)
        r.e = 99;               /* out of values--invalid code */
      else if (*p < s)
      {
        r.e = (uch)(*p < 256 ? 16 : 15);  /* 256 is end-of-block code */
        r.n = (ush)*p++;                /* simple code is just the value */
      }
      else
      {
        r.e = (uch)e[*p - s];   /* non-simple--look up in lists */
        r.n = d[*p++ - s];
      }

      /* fill code-like entries with r */
      f = 1 << (k - w);
      for (j = i >> w; j < z; j += f)
        q[j] = r;

      /* backwards increment the k-bit code i */
      for (j = 1 << (k - 1); i & j; j >>= 1)
        i ^= j;
      i ^= j;

      /* backup over finished tables */
      while ((i & ((1 << w) - 1)) != x[h])
        w -= l[--h];            /* don't need to update q */
    }
  }

  /* return actual size of base table */
  *m = l[0];

  /* Return true (1) if we were given an incomplete table */
  if(y != 0 && g != 1)
    return IZI_ERR1;
  else
    return IZI_OK;
}

/* Free the malloc'ed tables built by huft_build(), which makes a linked
   list of the tables it made, with the links in a dummy first entry of
   each table. */
// t: table to free
static void huft_free(Uz_Globs *pG, struct huft *t)
{
  struct huft *p, *q;

  /* Go through linked list, freeing from the malloced (t[-1]) address. */
  p = t;
  while (p != NULL)
  {
    q = (--p)->t;
    de_free(pG->c, p);
    p = q;
  }
}

//========================= inflate.c end =========================

//========================= globals.c begin =========================

static Uz_Globs *globalsCtor(deark *c)
{
    Uz_Globs *pG = de_malloc(c, sizeof(Uz_Globs));
    return pG;
}

// New function, replaces the DESTROYGLOBALS() macro
static void globalsDtor(Uz_Globs *pG)
{
	deark *c;
	if(!pG) return;
	c = pG->c;
	de_free(c, pG);
}

//========================= globals.c end =========================
