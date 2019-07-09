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

struct hmain_struct {
	uch e;                /* number of extra bits or operation */
	uch b;                /* number of bits in this code or subcode */

	ush n;            /* literal, length base, or distance base */
	struct huft *t;   /* pointer to next level of table */
};

struct izi_htable;

struct huft {
	struct hmain_struct hmain;
	// # of remaining items in this array, starting with this one and
	// including this one.
	unsigned int num_alloc;
};

struct izi_htable {
	struct huft *t;
	int b; /* bits for this table */
};

struct izi_htables {
	struct izi_htable b; /* literal code table */
	struct izi_htable l; /* length code table */
	struct izi_htable d; /* distance code table */
};

//========================= globals.h begin =========================

typedef struct Globals {
	i64 csize;           /* used by decompr. (NEXTBYTE): must be signed */
	i64 ucsize;          /* used by unReduce(), explode() */
	uch Slide[WSIZE];
	ush lrec_general_purpose_bit_flag;
	deark *c;
	dbuf *inf;
	i64 inf_curpos;
	i64 inf_endpos;
	dbuf *outf;
	int dumptrees;
} Uz_Globs;  /* end of struct Globals */

//========================= globals.h end =========================

typedef ush (*izi_len_or_dist_getter)(unsigned int i);

static void huft_free(Uz_Globs *pG, struct huft *t, const char *name);
static int huft_build(Uz_Globs *pG, const unsigned *b, unsigned n,
	unsigned s, izi_len_or_dist_getter d_fn, izi_len_or_dist_getter e_fn,
	struct izi_htable *tbl);

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

static ush izi_get_mask_bits(unsigned int n)
{
	if(n>=17) return 0;
	return (ush)(0xffffU >> (16-n));
}

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


/* (virtual) Tables for length and distance */

static ush izi_get_cplen2(unsigned int i)
{
	if(i>=64) return 0;
	return i+2;
}

static ush izi_get_cplen3(unsigned int i)
{
	if(i>=64) return 0;
	return i+3;
}

static ush izi_get_extra(unsigned int i)
{
	return (i==63) ? 8 : 0;
}

static ush izi_get_cpdist4(unsigned int i)
{
	if(i>=64) return 0;
	return 1 + i*64;
}

static ush izi_get_cpdist8(unsigned int i)
{
	if(i>=64) return 0;
	return 1 + i*128;
}

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

static void izi_fatal(void)
{
	de_err(NULL, "zip/implode internal error");
	de_fatalerror(NULL);
}

static unsigned int get_u_arr(const unsigned int *arr, unsigned int arr_len,
	unsigned int idx)
{
	if(idx >= arr_len) {
		izi_fatal();
		return 0;
	}
	return arr[idx];
}

static unsigned int set_u_arr(unsigned int *arr, unsigned int arr_len,
	unsigned int idx, unsigned int val)
{
	if(idx >= arr_len) {
		izi_fatal();
		return 0;
	}
	arr[idx] = val;
	return val;
}

static int get_i_arr(const int *arr, unsigned int arr_len,
	unsigned int idx)
{
	if(idx >= arr_len) {
		izi_fatal();
		return 0;
	}
	return arr[idx];
}

static int set_i_arr(int *arr, unsigned int arr_len,
	unsigned int idx, int val)
{
	if(idx >= arr_len) {
		izi_fatal();
		return 0;
	}
	arr[idx] = val;
	return val;
}

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

static struct huft *huft_plus_offset(struct huft *h1, ulg offset)
{
	if(h1->num_alloc < offset+1) {
		return NULL;
	}
	return h1 + offset;
}

// tb, tl, td: literal, length, and distance tables
//  Uses literals if tbls->b.t!=NULL.
// bb, bl, bd: number of bits decoded by those
static int explode_internal(Uz_Globs *pG, unsigned window_k,
	struct izi_htables *tbls)
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
	mb = izi_get_mask_bits(tbls->b.b);           /* precompute masks for speed */
	ml = izi_get_mask_bits(tbls->l.b);
	md = izi_get_mask_bits(tbls->d.b);
	s = pG->ucsize;
	while (s > 0) {               /* do until ucsize bytes uncompressed */
		NEEDBITS(1);
		if (b & 1) {                /* then literal--decode it */
			DUMPBITS(1);
			s--;
			if(tbls->b.t) {
				NEEDBITS((unsigned)tbls->b.b);    /* get coded literal */
				t = huft_plus_offset(tbls->b.t, ((~(unsigned)b) & mb));
				if(!t) goto done;
				e = t->hmain.e;
				if (e > 16) {
					do {
						if (e == 99)
							return 1;
						DUMPBITS(t->hmain.b);
						e -= 16;
						NEEDBITS(e);
						t = huft_plus_offset(t->hmain.t,
							((~(unsigned)b) & izi_get_mask_bits(e)));
						if(!t) goto done;
						e = t->hmain.e;
					} while (e > 16);
				}
				DUMPBITS(t->hmain.b);
				pG->Slide[w++] = (uch)t->hmain.n;
			}
			else {
				NEEDBITS(8);
				pG->Slide[w++] = (uch)b;
			}
			if (w == wsize) {
				izi_flush(pG, pG->Slide, (ulg)w);
				w = u = 0;
			}
			if(!tbls->b.t) {
				DUMPBITS(8);
			}
		}
		else {                      /* else distance/length */
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

			NEEDBITS((unsigned)tbls->d.b);    /* get coded distance high bits */
			t = huft_plus_offset(tbls->d.t, ((~(unsigned)b) & md));
			if(!t) goto done;
			e = t->hmain.e;
			if (e > 16) {
				do {
					if (e == 99)
						return 1;
					DUMPBITS(t->hmain.b);
					e -= 16;
					NEEDBITS(e);
					t = huft_plus_offset(t->hmain.t, ((~(unsigned)b) & izi_get_mask_bits(e)));
					if(!t) goto done;
					e = t->hmain.e;
				} while (e > 16);
			}
			DUMPBITS(t->hmain.b);
			d = w - d - t->hmain.n;       /* construct offset */
			NEEDBITS((unsigned)tbls->l.b);    /* get coded length */
			t = huft_plus_offset(tbls->l.t, ((~(unsigned)b) & ml));
			if(!t) goto done;
			e = t->hmain.e;
			if (e > 16) {
				do {
					if (e == 99)
						return 1;
					DUMPBITS(t->hmain.b);
					e -= 16;
					NEEDBITS(e);
					t = huft_plus_offset(t->hmain.t, ((~(unsigned)b) & izi_get_mask_bits(e)));
					if(!t) goto done;
					e = t->hmain.e;
				} while (e > 16);
			}
			DUMPBITS(t->hmain.b);
			n = t->hmain.n;
			if (e) {                  /* get length extra bits */
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
				if (u && w <= d) {
					if(w+e > wsize) goto done;
					de_zeromem(&pG->Slide[w], e);
					w += e;
					d += e;
				}
				else {
					if (w - d >= e) {     /* (this test assumes unsigned comparison) */
						if(w+e > wsize) goto done;
						if(d+e > wsize) goto done;
						de_memcpy(&pG->Slide[w], &pG->Slide[d], e);
						w += e;
						d += e;
					}
					else {                 /* do it slow to avoid memcpy() overlap */
						do {
							if(w >= wsize) goto done;
							if(d >= wsize) goto done;
							pG->Slide[w++] = pG->Slide[d++];
						} while (--e);
					}
				}
				if (w == wsize) {
					izi_flush(pG, pG->Slide, (ulg)w);
					w = u = 0;
				}
			} while (n);
		}
	}

	/* flush out pG->Slide */
	izi_flush(pG, pG->Slide, (ulg)w);
done:
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
	unsigned r = 1;           /* return codes */
	struct izi_htables tbls;
	unsigned l[256];      /* bit lengths for codes */

	de_zeromem(&tbls, sizeof(struct izi_htables));

	/* Tune base table sizes.  Note: I thought that to truly optimize speed,
	   I would have to select different bl, bd, and bb values for different
	   compressed file sizes.  I was surprised to find out that the values of
	   7, 7, and 9 worked best over a very wide range of sizes, except that
	   bd = 8 worked marginally better for large compressed sizes. */
	tbls.l.b = 7;
	tbls.d.b = pG->csize > 200000L ? 8 : 7;

	/* With literal tree--minimum match length is 3 */
	if (pG->lrec_general_purpose_bit_flag & 4) {
		tbls.b.b = 9;                     /* base table size for literals */
		if ((r = get_tree(pG, l, 256)) != IZI_OK)
			goto done;
		if ((r = huft_build(pG, l, 256, 256, NULL, NULL, &tbls.b)) != IZI_OK)
			goto done;
		if ((r = get_tree(pG, l, 64)) != IZI_OK)
			goto done;
		if ((r = huft_build(pG, l, 64, 0, izi_get_cplen3, izi_get_extra, &tbls.l)) != IZI_OK)
			goto done;
		if ((r = get_tree(pG, l, 64)) != IZI_OK)
			goto done;
		if (pG->lrec_general_purpose_bit_flag & 2) {    /* true if 8K */
			if ((r = huft_build(pG, l, 64, 0, izi_get_cpdist8, izi_get_extra, &tbls.d)) != IZI_OK)
				goto done;
			r = explode_internal(pG, 8, &tbls);
		}
		else {                                      /* else 4K */
			if ((r = huft_build(pG, l, 64, 0, izi_get_cpdist4, izi_get_extra, &tbls.d)) != IZI_OK)
				goto done;
			r = explode_internal(pG, 4, &tbls);
		}
	}
	else {  /* No literal tree--minimum match length is 2 */
		if ((r = get_tree(pG, l, 64)) != IZI_OK)
			goto done;
		if ((r = huft_build(pG, l, 64, 0, izi_get_cplen2, izi_get_extra, &tbls.l)) != IZI_OK)
			goto done;
		if ((r = get_tree(pG, l, 64)) != IZI_OK)
			goto done;
		if (pG->lrec_general_purpose_bit_flag & 2) {    /* true if 8K */
			if ((r = huft_build(pG, l, 64, 0, izi_get_cpdist8, izi_get_extra, &tbls.d)) != IZI_OK)
				goto done;
			tbls.b.t = NULL;
			r = explode_internal(pG, 8, &tbls);
		}
		else {                                      /* else 4K */
			if ((r = huft_build(pG, l, 64, 0, izi_get_cpdist4, izi_get_extra, &tbls.d)) != IZI_OK)
				goto done;
			tbls.b.t = NULL;
			r = explode_internal(pG, 4, &tbls);
		}
	}

done:
	huft_free(pG, tbls.d.t, "d");
	huft_free(pG, tbls.l.t, "l");
	huft_free(pG, tbls.b.t, "b");
	return (int)r;
}

/* so explode.c and inflate.c can be compiled together into one object: */
#undef NEXTBYTE
#undef NEEDBITS
#undef DUMPBITS

//========================= explode.c end =========================

//========================= inflate.c begin =========================

#define DE_DUMPTREES 1
#if DE_DUMPTREES
static void huft_dump1(Uz_Globs *pG, struct huft *t, unsigned int idx)
{
	de_dbg(pG->c, "[%u:%p] e=%u b=%u n=%u alloc=%u t=%p",
		idx, (void*)t, (unsigned int)t->hmain.e, (unsigned int)t->hmain.b,
		(unsigned int)t->hmain.n, t->num_alloc,
		(void*)t->hmain.t);
}

static void huft_dump(Uz_Globs *pG, struct huft *t, const char *name)
{
	deark *c = pG->c;
	struct huft *p = t;

	de_dbg(c, "huffman [%s] table list %p", name, (void*)t);

	de_dbg_indent(c, 1);
	while(1) {
		struct huft *q;
		unsigned int k;

		if(!p) {
			de_dbg(c, "table ref: NULL");
			break;
		}
		de_dbg(c, "table ref: %p", (void*)p);

		p--;
		q = p->hmain.t;

		de_dbg_indent(c, 1);
		de_dbg(c, "count=%u, next=%p", p->num_alloc, (void*)q);
		for(k=0; k<p->num_alloc; k++) {
			huft_dump1(pG, &p[k], k);
		}
		de_dbg_indent(c, -1);


		p = q;
	}

	de_dbg_indent(c, -1);
}
#endif

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
// tbl->t: result: starting table
// tbl->b: maximum lookup bits, returns actual
static int huft_build(Uz_Globs *pG, const unsigned *b, unsigned n, unsigned s,
	izi_len_or_dist_getter d_fn, izi_len_or_dist_getter e_fn,
	struct izi_htable *tbl)
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
	                              /* &lx[1] = stack of bits per table */
	struct huft *q;      /* points to current table */
	struct hmain_struct r;        /* table entry for structure assignment */
	struct huft *u[BMAX];         /* table stack */
	unsigned v[N_MAX];            /* values in order of bit length */
	int w;               /* bits before this table == (l * h) */
	unsigned x[BMAX+1];           /* bit offsets, then code stack */
	int y;                        /* number of dummy codes added */
	unsigned z;                   /* number of entries in current table */
	unsigned int tmpn;
	unsigned int c_idx;
	unsigned int v_idx;
	unsigned int x_idx;
	int retval = IZI_ERR2;
	struct huft **loc_of_prev_next_ptr = &tbl->t;

	*loc_of_prev_next_ptr = NULL;
	if(n>256) goto done;

	/* Generate counts for each bit length */
	el = BMAX; /* set length of EOB code, if any */
	de_zeromem(c, sizeof(c));

	for(i=0; i<n; i++) {
		if(b[i] >= BMAX+1) goto done;
		c[b[i]]++;               /* assume all entries <= BMAX */
	}

	if (c[0] == n) {              /* null input--all zero length codes */
		tbl->b = 0;
		return IZI_OK;
	}

	/* Find minimum and maximum length, bound *m by those */
	for (j = 1; j <= BMAX; j++) {
		if (c[j])
			break;
	}
	k = j;                        /* minimum code length */
	if ((unsigned)tbl->b < j)
		tbl->b = j;
	for (i = BMAX; i; i--) {
		if (c[i])
			break;
	}
	g = i;                        /* maximum code length */
	if ((unsigned)tbl->b > i)
		tbl->b = i;

	/* Adjust last length count to fill out codes, if needed */
	for (y = 1 << j; j < i; j++, y <<= 1) {
		y -= get_u_arr(c, BMAX+1, j);
		if (y < 0)
			return IZI_ERR2;                 /* bad input: more codes than bits */
	}
	y -= get_u_arr(c, BMAX+1, i);
	if (y < 0)
		return IZI_ERR2;
	set_u_arr(c, BMAX+1, i, get_u_arr(c, BMAX+1, i) + y);

	/* Generate starting offsets into the value table for each length */
	j = 0;
	x[1] = 0;
	c_idx = 1;
	x_idx = 2;
	while (--i) {                 /* note that i == g from above */
		j += get_u_arr(c, BMAX+1, c_idx);
		c_idx++;
		set_u_arr(x, BMAX+1, x_idx, j);
		x_idx++;
	}

	/* Make a table of values in order of bit lengths */
	de_zeromem(v, sizeof(v));
	for(i=0; i<n; i++) {
		j = b[i];
		if (j != 0) {
			set_u_arr(v, N_MAX, get_u_arr(x, BMAX+1, j), i);
			set_u_arr(x, BMAX+1, j, get_u_arr(x, BMAX+1, j) + 1);
		}
	}
	n = get_u_arr(x, BMAX+1, g);                     /* set n to length of v */

	/* Generate the Huffman codes and for each, make the table entries */
	i = 0;                        /* first Huffman code is zero */
	x[0] = 0;
	v_idx = 0;                    /* grab values in bit order */
	h = -1;                       /* no tables yet--level -1 */
	lx[0] = 0;                    /* no bits decoded yet */
	w = 0;
	u[0] = NULL;                  /* just to keep compilers happy */
	q = NULL;                     /* ditto */
	z = 0;                        /* ditto */

	/* go through the bit lengths (k already is bits in shortest code) */
	for (; k <= g; k++) {
		a = get_u_arr(c, BMAX+1, k);
		while (a--) {
			/* here i is the Huffman code of length k bits for value *p */
			/* make tables up to required level */
			while (k > w + get_i_arr(lx, BMAX+1, 1+ h)) {
				w += get_i_arr(lx, BMAX+1, 1+ h);            /* add bits already decoded */
				h++;

				/* compute minimum size table less than or equal to *m bits */
				z = g - w;
				z = (z > (unsigned)tbl->b) ? ((unsigned)tbl->b) : z;        /* upper limit */
				j = k - w;
				f = 1 << j;
				if (f > a + 1) {   /* try a k-w bit table */
				                   /* too few codes for k-w bit table */
					f -= a + 1;           /* deduct codes from patterns left */

					c_idx = k;
					while (++j < z) {     /* try smaller tables up to z bits */
						c_idx++;
						f <<= 1;
						if (f <= get_u_arr(c, BMAX+1, c_idx))
							break;            /* enough codes to use up j bits */
						f -= get_u_arr(c, BMAX+1, c_idx);        /* else deduct codes from patterns */
					}
				}
				if ((unsigned)w + j > el && (unsigned)w < el)
					j = el - w;           /* make EOB code end at table */
				z = 1 << j;             /* table entries for j-bit table */
				set_i_arr(lx, BMAX+1, 1+ h, j);               /* set table size in stack */

				/* allocate and link in new table */
				q = de_mallocarray(pG->c, (i64)z + 1, sizeof(struct huft));
				for(tmpn=0; tmpn<(z + 1); tmpn++) {
					q[tmpn].num_alloc = z + 1 - tmpn;
				}
				*loc_of_prev_next_ptr = q + 1;             /* link to list for huft_free() */
				loc_of_prev_next_ptr = &(q->hmain.t);
				*loc_of_prev_next_ptr = NULL;
				++q;
				if(h<0 || h>=BMAX) goto done;
				u[h] = q;             /* table starts after link */

				/* connect to last table, if there is one */
				if (h) {
					de_zeromem(&r, sizeof(struct hmain_struct));
					set_u_arr(x, BMAX+1, h, i);             /* save pattern for backing up */
					r.b = (uch)get_i_arr(lx, BMAX+1, 1+ h-1);    /* bits to dump before this table */
					r.e = (uch)(16 + j);  /* bits in this table */
					r.t = q;            /* pointer to this table */
					j = (i & ((1 << w) - 1)) >> (w - get_i_arr(lx, BMAX+1, 1+ h-1));
					if((h-1 < 0) || (h-1 >= BMAX)) goto done;
					u[h-1][j].hmain = r;        /* connect to last table */
				}
			}

			/* set up table entry in r */
			de_zeromem(&r, sizeof(struct hmain_struct));
			r.b = (uch)(k - w);
			if (v_idx >= n) {
				r.e = 99;               /* out of values--invalid code */
			}
			else if (get_u_arr(v, N_MAX, v_idx) < s) {
				r.e = (uch)(get_u_arr(v, N_MAX, v_idx) < 256 ? 16 : 15);  /* 256 is end-of-block code */
				r.n = (ush)get_u_arr(v, N_MAX, v_idx);                /* simple code is just the value */
				v_idx++;
			}
			else {
				r.e = (uch)e_fn(get_u_arr(v, N_MAX, v_idx) - s);   /* non-simple--look up in lists */
				r.n = d_fn(get_u_arr(v, N_MAX, v_idx) - s);
				v_idx++;
			}

			/* fill code-like entries with r */
			f = 1 << (k - w);
			for (j = i >> w; j < z; j += f) {
				q[j].hmain = r;
			}

			/* backwards increment the k-bit code i */
			for (j = 1 << (k - 1); i & j; j >>= 1) {
				i ^= j;
			}
			i ^= j;

			/* backup over finished tables */
			while ((i & ((1 << w) - 1)) != get_u_arr(x, BMAX+1, h)) {
				--h;
				w -= get_i_arr(lx, BMAX+1, 1+ h);            /* don't need to update q */
			}
		}
	}

	/* return actual size of base table */
	tbl->b = get_i_arr(lx, BMAX+1, 1+ 0);

	/* Return true (1) if we were given an incomplete table */
	if(y != 0 && g != 1)
		retval = IZI_ERR1;
	else
		retval = IZI_OK;

done:
	return retval;
}

/* Free the malloc'ed tables built by huft_build(), which makes a linked
   list of the tables it made, with the links in a dummy first entry of
   each table. */
// t: table to free
static void huft_free(Uz_Globs *pG, struct huft *t, const char *name)
{
	struct huft *p, *q;

#if DE_DUMPTREES
	if(pG->dumptrees) {
		huft_dump(pG, t, name);
	}
#endif

	/* Go through linked list, freeing from the malloced (t[-1]) address. */
	p = t;
	while (p != NULL) {
		--p;
		q = p->hmain.t;
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
