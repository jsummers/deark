// ZIP type 6 "implode" decompression.
// Based on Mark Adler's public domain code from Info-ZIP UnZip v5.4.
// See the file readme-explode.txt for more information.
// The code has been heavily modified for Deark (2019-03).
// This file (explode.h) is hereby left in the public domain; or it may, at
// your option, be distributed under the same terms as the main Deark software.
// -JS

#ifndef UI6A_CALLOC
#define UI6A_CALLOC(u, nmemb, size) calloc(nmemb, size)
#endif
#ifndef UI6A_FREE
#define UI6A_FREE(u, ptr) free(ptr)
#endif

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

#define HUFT_ARRAY_OFFSET 0

struct huftarray;

struct huft {
	uch e;                /* number of extra bits or operation */
	uch b;                /* number of bits in this code or subcode */
	ush n;            /* literal, length base, or distance base */
	struct huftarray *t_arr;   /* pointer to next level of table */
};

struct huftarray {
	unsigned int num_alloc_h;
	struct huft *h;
	struct huftarray *next_array;
};

struct izi_htable {
	struct huftarray *first_array;
	int b; /* bits for this table */
	const char *tblname;
};

struct izi_htables {
	struct izi_htable b; /* literal code table */
	struct izi_htable l; /* length code table */
	struct izi_htable d; /* distance code table */
};

//========================= globals.h begin =========================

struct ui6a_Globals;
typedef struct ui6a_Globals Uz_Globs;

typedef void (*ui6a_cb_post_read_trees_type)(Uz_Globs *pG, struct izi_htables *tbls);

struct ui6a_Globals {
	i64 csize;           /* used by decompr. (NEXTBYTE): must be signed */
	i64 ucsize;          /* used by unReduce(), explode() */
	ush lrec_general_purpose_bit_flag;
	void *userdata;
	dbuf *inf;
	i64 inf_curpos;
	i64 inf_endpos;
	dbuf *outf;
	ui6a_cb_post_read_trees_type cb_post_read_trees;
	uch Slide[WSIZE];
};  /* end of struct ui6a_Globals */

//========================= globals.h end =========================

typedef ush (*izi_len_or_dist_getter)(unsigned int i);

static void huft_free(Uz_Globs *pG, struct izi_htable *tbl);
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

struct iarray {
	size_t count;
	int *data;
	Uz_Globs *pG;
};

struct uarray {
	size_t count;
	unsigned int *data;
	Uz_Globs *pG;
};

static void iarray_init(Uz_Globs *pG, struct iarray *a, int *data, size_t count)
{
	de_zeromem(data, count * sizeof(int));
	a->data = data;
	a->count = count;
	a->pG = pG;
}

static void uarray_init(Uz_Globs *pG, struct uarray *a, unsigned int *data, size_t count)
{
	de_zeromem(data, count * sizeof(unsigned int));
	a->data = data;
	a->count = count;
	a->pG = pG;
}

static void iarray_setval(struct iarray *a, size_t idx, int val)
{
	if(idx<a->count) {
		a->data[idx] = val;
	}
}

static void uarray_setval(struct uarray *a, size_t idx, unsigned int val)
{
	if(idx<a->count) {
		a->data[idx] = val;
	}
}

static int iarray_getval(struct iarray *a, size_t idx)
{
	if(idx<a->count) {
		return a->data[idx];
	}
	return 0;
}

static unsigned int uarray_getval(struct uarray *a, size_t idx)
{
	if(idx<a->count) {
		return a->data[idx];
	}
	return 0;
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

static struct huft *huftarr_plus_offset(struct huftarray *ha, ulg offset)
{
	ulg real_offset;

	real_offset = HUFT_ARRAY_OFFSET+offset;
	if(real_offset >= ha->num_alloc_h) {
		return NULL;
	}
	return &(ha->h[real_offset]);
}

static struct huft *follow_huft_ptr(struct huft *h1, ulg offset)
{
	return huftarr_plus_offset(h1->t_arr, offset);
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
			if(tbls->b.first_array) {
				NEEDBITS((unsigned)tbls->b.b);    /* get coded literal */
				t = huftarr_plus_offset(tbls->b.first_array, ((~(unsigned)b) & mb));
				if(!t) goto done;
				e = t->e;
				if (e > 16) {
					do {
						if (e == 99)
							return 1;
						DUMPBITS(t->b);
						e -= 16;
						NEEDBITS(e);
						t = follow_huft_ptr(t, ((~(unsigned)b) & izi_get_mask_bits(e)));
						if(!t) goto done;
						e = t->e;
					} while (e > 16);
				}
				DUMPBITS(t->b);
				pG->Slide[w++] = (uch)t->n;
			}
			else {
				NEEDBITS(8);
				pG->Slide[w++] = (uch)b;
			}
			if (w == wsize) {
				izi_flush(pG, pG->Slide, (ulg)w);
				w = u = 0;
			}
			if(!tbls->b.first_array) {
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
			t = huftarr_plus_offset(tbls->d.first_array, ((~(unsigned)b) & md));
			if(!t) goto done;
			e = t->e;
			if (e > 16) {
				do {
					if (e == 99)
						return 1;
					DUMPBITS(t->b);
					e -= 16;
					NEEDBITS(e);
					t = follow_huft_ptr(t, ((~(unsigned)b) & izi_get_mask_bits(e)));
					if(!t) goto done;
					e = t->e;
				} while (e > 16);
			}
			DUMPBITS(t->b);
			d = w - d - t->n;       /* construct offset */
			NEEDBITS((unsigned)tbls->l.b);    /* get coded length */
			t = huftarr_plus_offset(tbls->l.first_array, ((~(unsigned)b) & ml));
			if(!t) goto done;
			e = t->e;
			if (e > 16) {
				do {
					if (e == 99)
						return 1;
					DUMPBITS(t->b);
					e -= 16;
					NEEDBITS(e);
					t = follow_huft_ptr(t, ((~(unsigned)b) & izi_get_mask_bits(e)));
					if(!t) goto done;
					e = t->e;
				} while (e > 16);
			}
			DUMPBITS(t->b);
			n = t->n;
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
	int has_literal_tree;
	int has_8k_window;

	de_zeromem(&tbls, sizeof(struct izi_htables));
	tbls.b.tblname = "B";
	tbls.l.tblname = "L";
	tbls.d.tblname = "D";

	has_8k_window = (pG->lrec_general_purpose_bit_flag & 2) ? 1 : 0;
	has_literal_tree = (pG->lrec_general_purpose_bit_flag & 4) ? 1 : 0;

	/* Tune base table sizes.  Note: I thought that to truly optimize speed,
	   I would have to select different bl, bd, and bb values for different
	   compressed file sizes.  I was surprised to find out that the values of
	   7, 7, and 9 worked best over a very wide range of sizes, except that
	   bd = 8 worked marginally better for large compressed sizes. */
	tbls.l.b = 7;
	tbls.d.b = pG->csize > 200000L ? 8 : 7;

	if (has_literal_tree) { /* With literal tree--minimum match length is 3 */
		tbls.b.b = 9;                     /* base table size for literals */
		if ((r = get_tree(pG, l, 256)) != IZI_OK)
			goto done;
		if ((r = huft_build(pG, l, 256, 256, NULL, NULL, &tbls.b)) != IZI_OK)
			goto done;
	}
	else {  /* No literal tree--minimum match length is 2 */
		tbls.b.first_array = NULL;
	}

	if ((r = get_tree(pG, l, 64)) != IZI_OK)
		goto done;
	if ((r = huft_build(pG, l, 64, 0, (has_literal_tree ? izi_get_cplen3 : izi_get_cplen2),
		izi_get_extra, &tbls.l)) != IZI_OK)
	{
		goto done;
	}

	if ((r = get_tree(pG, l, 64)) != IZI_OK)
		goto done;
	if ((r = huft_build(pG, l, 64, 0, (has_8k_window ? izi_get_cpdist8 : izi_get_cpdist4),
		izi_get_extra, &tbls.d)) != IZI_OK)
	{
		goto done;
	}

	if(pG->cb_post_read_trees) {
		pG->cb_post_read_trees(pG, &tbls);
	}

	r = explode_internal(pG, (has_8k_window ? 8 : 4), &tbls);

done:
	huft_free(pG, &tbls.d);
	huft_free(pG, &tbls.l);
	huft_free(pG, &tbls.b);
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
// tbl->t: result: starting table
// tbl->b: maximum lookup bits, returns actual
static int huft_build(Uz_Globs *pG, const unsigned *b, unsigned n, unsigned s,
	izi_len_or_dist_getter d_fn, izi_len_or_dist_getter e_fn,
	struct izi_htable *tbl)
{
	unsigned a;                   /* counter for codes of length k */
	struct uarray c_arr;           /* bit length count table */
	unsigned c_data[BMAX+1];
	unsigned el;                  /* length of EOB code (value 256) */
	unsigned f;                   /* i repeats in table every f entries */
	int g;                        /* maximum code length */
	int h;                        /* table level */
	unsigned i;          /* counter, current code */
	unsigned j;          /* counter */
	int k;               /* number of bits in current code */
	struct iarray lx_arr;         /* memory for l[-1..BMAX-1] */
	int lx_data[BMAX+1];          /* &lx[1] = stack of bits per table */
	struct huft *q;      /* points to current table */
	struct huft r;        /* table entry for structure assignment */
	struct huftarray *u[BMAX];  /* table stack */
	struct uarray v_arr;            /* values in order of bit length */
	unsigned v_data[N_MAX];
	int w;               /* bits before this table == (l * h) */
	struct uarray x_arr;           /* bit offsets, then code stack */
	unsigned x_data[BMAX+1];
	int y;                        /* number of dummy codes added */
	unsigned z;                   /* number of entries in current table */
	unsigned int c_idx;
	unsigned int v_idx;
	unsigned int x_idx;
	int retval = IZI_ERR2;
	struct huftarray **loc_of_prev_next_ha_ptr = &tbl->first_array;

	*loc_of_prev_next_ha_ptr = NULL;
	if(n>256) goto done;

	/* Generate counts for each bit length */
	el = BMAX; /* set length of EOB code, if any */
	uarray_init(pG, &c_arr, c_data, DE_ITEMS_IN_ARRAY(c_data));

	for(i=0; i<n; i++) {
		if(b[i] >= BMAX+1) goto done;
		/* assume all entries <= BMAX */
		uarray_setval(&c_arr, b[i], uarray_getval(&c_arr, b[i])+1);
	}

	if (uarray_getval(&c_arr, 0) == n) {              /* null input--all zero length codes */
		tbl->b = 0;
		return IZI_OK;
	}

	/* Find minimum and maximum length, bound *m by those */
	for (j = 1; j <= BMAX; j++) {
		if (uarray_getval(&c_arr, j))
			break;
	}
	k = j;                        /* minimum code length */
	if ((unsigned)tbl->b < j)
		tbl->b = j;
	for (i = BMAX; i; i--) {
		if (uarray_getval(&c_arr, i))
			break;
	}
	g = i;                        /* maximum code length */
	if ((unsigned)tbl->b > i)
		tbl->b = i;

	/* Adjust last length count to fill out codes, if needed */
	for (y = 1 << j; j < i; j++, y <<= 1) {
		y -= uarray_getval(&c_arr, j);
		if (y < 0)
			return IZI_ERR2;                 /* bad input: more codes than bits */
	}
	y -= uarray_getval(&c_arr, i);
	if (y < 0)
		return IZI_ERR2;
	uarray_setval(&c_arr, i, uarray_getval(&c_arr, i) + y);

	/* Generate starting offsets into the value table for each length */
	j = 0;
	uarray_init(pG, &x_arr, x_data, DE_ITEMS_IN_ARRAY(x_data));
	uarray_setval(&x_arr, 1, 0);
	c_idx = 1;
	x_idx = 2;
	while (--i) {                 /* note that i == g from above */
		j += uarray_getval(&c_arr, c_idx);
		c_idx++;
		uarray_setval(&x_arr, x_idx, j);
		x_idx++;
	}

	/* Make a table of values in order of bit lengths */
	uarray_init(pG, &v_arr, v_data, DE_ITEMS_IN_ARRAY(v_data));
	//v_arr = uarray_create(pG, N_MAX);
	for(i=0; i<n; i++) {
		j = b[i];
		if (j != 0) {
			uarray_setval(&v_arr, uarray_getval(&x_arr, j), i);
			uarray_setval(&x_arr, j, uarray_getval(&x_arr, j) + 1);
		}
	}
	n = uarray_getval(&x_arr, g);                     /* set n to length of v */

	/* Generate the Huffman codes and for each, make the table entries */
	i = 0;                        /* first Huffman code is zero */
	uarray_setval(&x_arr, 0, 0);
	v_idx = 0;                    /* grab values in bit order */
	h = -1;                       /* no tables yet--level -1 */
	iarray_init(pG, &lx_arr, lx_data, DE_ITEMS_IN_ARRAY(lx_data));
	iarray_setval(&lx_arr, 0, 0);                    /* no bits decoded yet */
	w = 0;
	u[0] = NULL;                  /* just to keep compilers happy */
	q = NULL;                     /* ditto */
	z = 0;                        /* ditto */

	/* go through the bit lengths (k already is bits in shortest code) */
	for (; k <= g; k++) {
		a = uarray_getval(&c_arr, k);
		while (a--) {
			/* here i is the Huffman code of length k bits for value *p */
			/* make tables up to required level */
			while (k > w + iarray_getval(&lx_arr, 1+ (size_t)h)) {
				struct huftarray *ha;

				w += iarray_getval(&lx_arr, 1+ (size_t)h);            /* add bits already decoded */
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
						if (f <= uarray_getval(&c_arr, c_idx))
							break;            /* enough codes to use up j bits */
						f -= uarray_getval(&c_arr, c_idx);        /* else deduct codes from patterns */
					}
				}
				if ((unsigned)w + j > el && (unsigned)w < el)
					j = el - w;           /* make EOB code end at table */
				z = 1 << j;             /* table entries for j-bit table */
				iarray_setval(&lx_arr, 1+ (size_t)h, j);               /* set table size in stack */

				/* allocate and link in new table */
				ha = UI6A_CALLOC(pG->userdata, 1, sizeof(struct huftarray));
				if(!ha) {
					retval = IZI_ERR3;
					goto done;
				}
				ha->h = UI6A_CALLOC(pG->userdata, (size_t)((i64)z + HUFT_ARRAY_OFFSET), sizeof(struct huft));
				if(!ha->h) {
					UI6A_FREE(pG->userdata, ha);
					retval = IZI_ERR3;
					goto done;
				}
				ha->num_alloc_h = z + HUFT_ARRAY_OFFSET;
				q = ha->h;
				*loc_of_prev_next_ha_ptr = ha;             /* link to list for huft_free() */
				loc_of_prev_next_ha_ptr = &ha->next_array;
				*loc_of_prev_next_ha_ptr = NULL;
				q += HUFT_ARRAY_OFFSET;
				if(h<0 || h>=BMAX) goto done;
				u[h] = ha;

				/* connect to last table, if there is one */
				if (h) {
					de_zeromem(&r, sizeof(struct huft));
					uarray_setval(&x_arr, h, i);             /* save pattern for backing up */
					r.b = (uch)iarray_getval(&lx_arr, 1+ (size_t)h-1);    /* bits to dump before this table */
					r.e = (uch)(16 + j);  /* bits in this table */
					r.t_arr = ha;            /* pointer to this table */
					j = (i & ((1 << w) - 1)) >> (w - iarray_getval(&lx_arr, 1+ (size_t)h-1));
					if((h-1 < 0) || (h-1 >= BMAX)) goto done;
					u[h-1]->h[HUFT_ARRAY_OFFSET+j] = r;        /* connect to last table */
				}
			}

			/* set up table entry in r */
			de_zeromem(&r, sizeof(struct huft));
			r.b = (uch)(k - w);
			if (v_idx >= n) {
				r.e = 99;               /* out of values--invalid code */
			}
			else if (uarray_getval(&v_arr, v_idx) < s) {
				r.e = (uch)(uarray_getval(&v_arr, v_idx) < 256 ? 16 : 15);  /* 256 is end-of-block code */
				r.n = (ush)uarray_getval(&v_arr, v_idx);                /* simple code is just the value */
				v_idx++;
			}
			else {
				r.e = (uch)e_fn(uarray_getval(&v_arr, v_idx) - s);   /* non-simple--look up in lists */
				r.n = d_fn(uarray_getval(&v_arr, v_idx) - s);
				v_idx++;
			}

			/* fill code-like entries with r */
			f = 1 << (k - w);
			for (j = i >> w; j < z; j += f) {
				q[j] = r;
			}

			/* backwards increment the k-bit code i */
			for (j = 1 << (k - 1); i & j; j >>= 1) {
				i ^= j;
			}
			i ^= j;

			/* backup over finished tables */
			while ((i & ((1 << w) - 1)) != uarray_getval(&x_arr, h)) {
				--h;
				w -= iarray_getval(&lx_arr, 1+ (size_t)h);            /* don't need to update q */
			}
		}
	}

	/* return actual size of base table */
	tbl->b = iarray_getval(&lx_arr, 1+ 0);

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
static void huft_free(Uz_Globs *pG, struct izi_htable *tbl)
{
	struct huftarray *p, *q;

	p = tbl->first_array;
	while(p) {
		q = p->next_array;

		UI6A_FREE(pG->userdata, p->h);
		UI6A_FREE(pG->userdata, p);
		p = q;
	}
}

//========================= inflate.c end =========================

//========================= globals.c begin =========================

static Uz_Globs *globalsCtor(void *userdata)
{
	Uz_Globs *pG = UI6A_CALLOC(userdata, 1, sizeof(Uz_Globs));
	if(!pG) return NULL;
	pG->userdata = userdata;
	return pG;
}

// New function, replaces the DESTROYGLOBALS() macro
static void globalsDtor(Uz_Globs *pG)
{
	UI6A_FREE(pG->userdata, pG);
}

//========================= globals.c end =========================
