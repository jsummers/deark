// Huffman decompression code for StuffIt format.
// Based on unsit.c by Allan G. Weber.

// See the file readme-unsit.txt for more information about this file.
// Modifications for Deark are Copyright (C) 2019 Jason Summers.

// Selected comments from the original unsit.c:

/*
                unsit - Macintosh StuffIt file extractor

                        Version 1, for StuffIt 1.31

[...]

        Author: Allan G. Weber
                weber%brand.usc.edu@oberon.usc.edu
                ...sdcrdcf!usc-oberon!brand!weber
        Date:   January 15, 1988

*/

#define HUFF_NODECODE 0
#define HUFF_DECODE   1

struct huff_node {
	int flag;
	u8 byte;
	struct huff_node *one, *zero;
};

struct huffctx {
	deark *c;
	dbuf *inf;
	i64 cmpr_pos;
	i64 cmpr_len;
	dbuf *outf;
	i64 unc_len;

	i64 in_pos;
	int error_flag;

	unsigned int bit;
	unsigned int b;
	size_t nodeptr_idx;
	// Originally 512, but changed to 515 because that's what macutil does.
#define HUFF_NODELISTSIZE 515
	struct huff_node nodelist[HUFF_NODELISTSIZE];
};

static u8 huff_getc(struct huffctx *hctx)
{
	u8 ch;

	if(hctx->in_pos >= hctx->cmpr_pos + hctx->cmpr_len) {
		// No more input data
		hctx->error_flag = 1;
		return 0;
	}

	ch = dbuf_getbyte(hctx->c->infile, hctx->in_pos);
	hctx->in_pos++;
	return ch;
}

/* This routine returns the next bit in the input stream (MSB first) */

static unsigned int huff_getbit(struct huffctx *hctx)
{
	if (hctx->bit == 0) {
		hctx->b = (unsigned int)huff_getc(hctx);
		hctx->bit = 8;
	}
	hctx->bit--;
	return((hctx->b >> hctx->bit) & 1);
}

/* This routine returns the next 8 bits.  If decoding is on, it finds the
byte in the decoding tree based on the bits from the input stream.  If
decoding is not on, it either gets it directly from the input stream or
puts it together from 8 calls to getbit(), depending on whether or not we
are currently on a byte boundary
*/
static u8 huff_gethuffbyte(struct huffctx *hctx, int decode)
{
	struct huff_node *np;
	int i;
	unsigned int b;

	if (decode == HUFF_DECODE) {
		np = hctx->nodelist;
		while (np->flag == 0)
			np = (huff_getbit(hctx)) ? np->one : np->zero;
		b = (unsigned int)np->byte;
	}
	else {
		if (hctx->bit == 0)	/* on byte boundary? */
			b = (unsigned int)huff_getc(hctx);
		else {		/* no, put a byte together */
			b = 0;
			for (i = 8; i > 0; i--) {
				b = (b << 1) + huff_getbit(hctx);
			}
		}
	}
	return (u8)b;
}

/* This routine recursively reads the Huffman encoding table and builds
   and decoding tree. */

static struct huff_node *huff_read_tree(struct huffctx *hctx, int depth)
{
	struct huff_node *np;

	if(hctx->error_flag) {
		return NULL;
	}

	if(hctx->nodeptr_idx >= HUFF_NODELISTSIZE) {
		hctx->error_flag = 1;
		return NULL;
	}

	if(depth>64) {
		// I don't know what the limit should be. Highest I've seen is 16.
		hctx->error_flag = 1;
		return NULL;
	}

	np = &hctx->nodelist[hctx->nodeptr_idx++];

	if (huff_getbit(hctx) == 1) {
		np->flag = 1;
		np->byte = huff_gethuffbyte(hctx, HUFF_NODECODE);
	}
	else {
		np->flag = 0;
		np->zero = huff_read_tree(hctx, depth+1);
		np->one  = huff_read_tree(hctx, depth+1);
	}
	return(np);
}

static int huff_main(struct huffctx *hctx)
{
	i64 obytes;

	hctx->in_pos = hctx->cmpr_pos;

	hctx->nodeptr_idx = 0;
	hctx->bit = 0;		/* put us on a byte boundary */
	huff_read_tree(hctx, 0);
	if(hctx->error_flag) return 0;

	obytes = hctx->unc_len;
	while (obytes > 0 && !hctx->error_flag) {
		u8 ch;

		ch = huff_gethuffbyte(hctx, HUFF_DECODE);
		dbuf_writebyte(hctx->outf, ch);
		obytes -= 1;
	}

	return hctx->error_flag ? 0 : 1;
}
