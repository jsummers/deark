/* This file is an edited version of the lzw.c and lzw.h files from liblzw.
 * Modified for Deark. */

/* Original header from lwz.c: */

/*
 * Original code was ripped from ncompress-4.2.4.tar.gz,
 * and it is all public domain code, so have fun you wh0res.
 *
 * Librarification by Mike Frysinger <vapier@gmail.com>
 *
 * http://www.dogma.net/markn/articles/lzw/lzw.htm
 *
 * (N)compress42.c - File compression ala IEEE Computer, Mar 1992.
 *
 * Authors:
 *   Spencer W. Thomas   (decvax!harpo!utah-cs!utah-gr!thomas)
 *   Jim McKie           (decvax!mcvax!jim)
 *   Steve Davies        (decvax!vax135!petsd!peora!srd)
 *   Ken Turkowski       (decvax!decwrl!turtlevax!ken)
 *   James A. Woods      (decvax!ihnp4!ames!jaw)
 *   Joe Orost           (decvax!vax135!petsd!joe)
 *   Dave Mack           (csu@alembic.acs.com)
 *   Peter Jannesen, Network Communication Systems
 *                       (peter@ncs.nl)
 */

/*************** from lzw.h ***************/

#define LZW_MAGIC_1 0x1F
#define LZW_MAGIC_2 0x9D

#define LZW_MAXMAXBITS  16
#define LZW_MAX_NCODES  65536

#define BUFSIZE      4096
#define IN_BUFSIZE   (BUFSIZE + 64)
#define OUT_BUFSIZE  (BUFSIZE + 2048)

struct de_liblzwctx;
typedef size_t (*liblzw_cb_read_type)(struct de_liblzwctx *lzw, u8 *buf, size_t size);
typedef void (*liblzw_cb_write_type)(struct de_liblzwctx *lzw, const u8 *buf, size_t size);

struct de_liblzwctx {
	void *userdata;
	deark *c;
	liblzw_cb_read_type cb_read;
	liblzw_cb_write_type cb_write;
	int arcfs_mode;

	int eof;

	unsigned char *stackp;
	size_t unread_amt;
	size_t stackp_diff;
	size_t insize, outpos;
	i64 rsize;

	int maxbits, block_mode;

	unsigned char valuetab[LZW_MAX_NCODES];
	u16 parenttab[LZW_MAX_NCODES];
	unsigned char stackdata[LZW_MAX_NCODES];

	int n_bits, posbits, inbits, bitmask, finchar;
	i32 maxcode, oldcode, incode, code, free_ent;

	int errcode;
	char errmsg[80];
	unsigned char inbuf[IN_BUFSIZE];
	unsigned char outbuf[OUT_BUFSIZE];
};

/******************************************/

#define INIT_BITS    9			/* initial number of bits/code */
#define LZW_NBITS_TO_NCODES(n)   (1L << (n))
#define FIRST        257					/* first free entry */
#define CLEAR        256					/* table clear output code */

static void liblzw_set_errorf(struct de_liblzwctx *lzw, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

static void liblzw_set_errorf(struct de_liblzwctx *lzw, const char *fmt, ...)
{
	va_list ap;

	if(lzw->errcode != 0) return; // Only record the first error
	lzw->errcode = 1;

	va_start(ap, fmt);
	de_vsnprintf(lzw->errmsg, sizeof(lzw->errmsg), fmt, ap);
	va_end(ap);
}

static void liblzw_set_coded_error(struct de_liblzwctx *lzw, int code)
{
	liblzw_set_errorf(lzw, "LZW decompression error (%d)", code);
}

static struct de_liblzwctx *de_liblzw_create(deark *c, void *userdata)
{
	struct de_liblzwctx *lzw = NULL;

	lzw = de_malloc(c, sizeof(struct de_liblzwctx));
	lzw->c = c;
	lzw->userdata = userdata;
	return lzw;
}

static void de_liblzw_destroy(struct de_liblzwctx *lzw)
{
	if(!lzw) return;
	de_free(lzw->c, lzw);
}

/*
 * Initialize decompression
 */
static int de_liblzw_init(struct de_liblzwctx *lzw, unsigned int flags, u8 lzwmode)
{
	lzw->arcfs_mode = (flags&0x2)?1:0;
	lzw->eof = 0;
	lzw->stackp = NULL;
	lzw->insize = 0;
	lzw->outpos = 0;
	lzw->rsize = 0;

	lzw->maxbits = lzwmode & 0x1f;    /* Mask for 'number of compression bits' */
	lzw->block_mode = lzwmode & 0x80;

	lzw->n_bits = INIT_BITS;
	lzw->maxcode = LZW_NBITS_TO_NCODES(INIT_BITS) - 1;
	lzw->bitmask = (1<<INIT_BITS)-1;
	lzw->oldcode = -1;
	lzw->finchar = 0;
	lzw->posbits = 3<<3;
	lzw->free_ent = ((lzw->block_mode) ? FIRST : 256);

	/* initialize the first 256 entries in the table */
	for (lzw->code = 255; lzw->code >= 0; --lzw->code)
		lzw->valuetab[lzw->code] = (unsigned char)lzw->code;

	if (lzw->maxbits > LZW_MAXMAXBITS) {
		liblzw_set_errorf(lzw, "Unsupported number of bits (%d)", lzw->maxbits);
		goto err_out_free;
	}

	return 1;

err_out_free:
	return 0;
}

static void lzw_input(struct de_liblzwctx *lzw)
{
	unsigned char *p = &(lzw->inbuf)[(lzw->posbits)>>3];

	lzw->code = ((((i32)(p[0]))|((i32)(p[1])<<8) |
	       ((i32)(p[2])<<16))>>((lzw->posbits)&0x7))&(lzw->bitmask);
	lzw->posbits += lzw->n_bits;
}

#define lzw_de_stack  (&(lzw->stackdata[sizeof(lzw->stackdata)-1]))

static void lzw_empty_stack(struct de_liblzwctx *lzw)
{
	lzw->stackp = lzw_de_stack;
}

static void lzw_push(struct de_liblzwctx *lzw, unsigned char x)
{
	if(lzw->stackp == &lzw->stackdata[0]) {
		liblzw_set_coded_error(lzw, 3);
		return;
	}
	--lzw->stackp;
	*lzw->stackp = x;
}

static void lzw_empty_existing_buffer(struct de_liblzwctx *lzw, size_t outbuf_startpos,
	size_t count_left)
{
	lzw->outpos -= count_left;
	lzw->cb_write(lzw, &lzw->outbuf[outbuf_startpos], count_left);
	lzw->unread_amt =  outbuf_startpos + count_left;
}

/*
 * Read LZW file
 */
static i64 de_liblzw_read(struct de_liblzwctx *lzw, size_t count)
{
	size_t count_left = count;
	size_t outbuf_startpos = 0;
	i64 retval = 0;
	i32 maxmaxcode = LZW_NBITS_TO_NCODES(lzw->maxbits);

	if (!count || lzw->eof)
		return 0;

	if (lzw->stackp != NULL) {
		if (lzw->outpos) {
			if (lzw->outpos >= count) {
				outbuf_startpos = lzw->unread_amt;
				lzw_empty_existing_buffer(lzw, outbuf_startpos, count_left);
				retval = count;
				goto done;
			} else /*if (lzw->outpos < count)*/ {
				lzw->cb_write(lzw, &lzw->outbuf[lzw->unread_amt], lzw->outpos);
				goto resume_partial_reading;
			}
		}
		goto resume_reading;
	}

	do {
resetbuf:
		{
			size_t i, e, o;
			o = lzw->posbits >> 3;
			e = o <= lzw->insize ? lzw->insize - o : 0;

			for (i = 0; i < e; ++i)
				lzw->inbuf[i] = lzw->inbuf[i+o];

			lzw->insize = e;
			lzw->posbits = 0;
		}

		if (lzw->insize < IN_BUFSIZE-BUFSIZE) {
			lzw->rsize = lzw->cb_read(lzw, lzw->inbuf+lzw->insize, BUFSIZE);
			lzw->insize += (size_t)lzw->rsize;
		}

		lzw->inbits = (int)( ((lzw->rsize > 0) ? (lzw->insize - lzw->insize%lzw->n_bits)<<3 :
		               (lzw->insize<<3) - ((size_t)lzw->n_bits-1)) );

		while (lzw->inbits > lzw->posbits) {
			if (lzw->free_ent > lzw->maxcode) {
				lzw->posbits = ((lzw->posbits-1) + ((lzw->n_bits<<3) -
				                (lzw->posbits-1 + (lzw->n_bits<<3)) % (lzw->n_bits<<3)));

				++lzw->n_bits;
				if (lzw->n_bits == lzw->maxbits)
					lzw->maxcode = maxmaxcode;
				else
					lzw->maxcode = LZW_NBITS_TO_NCODES(lzw->n_bits)-1;

				lzw->bitmask = (1 << lzw->n_bits) - 1;
				goto resetbuf;
			}

			lzw_input(lzw); // Sets lzw->code
			if(lzw->code>=LZW_MAX_NCODES || lzw->code<0) {
				liblzw_set_coded_error(lzw, 1);
				return -1;
			}

			if (lzw->oldcode == -1) {
				if (lzw->code >= 256) {
					liblzw_set_coded_error(lzw, 1);
					return -1;
				}
				lzw->oldcode = lzw->code;
				lzw->finchar = (unsigned char)lzw->code;
				lzw->outbuf[outbuf_startpos + lzw->outpos] = (unsigned char)lzw->code;
				lzw->outpos++;
				continue;
			}

			if (lzw->code == CLEAR && lzw->block_mode) {
				de_zeromem(lzw->parenttab, sizeof(lzw->parenttab));
				lzw->free_ent = FIRST - 1;
				lzw->posbits = ((lzw->posbits-1) + ((lzw->n_bits<<3) -
				                (lzw->posbits-1 + (lzw->n_bits<<3)) % (lzw->n_bits<<3)));
				lzw->n_bits = INIT_BITS;
				lzw->maxcode = LZW_NBITS_TO_NCODES(lzw->n_bits)-1;
				lzw->bitmask = (1 << lzw->n_bits) - 1;
				goto resetbuf;
			}

			lzw->incode = lzw->code;
			lzw_empty_stack(lzw);

			/* Special case for KwKwK string.*/
			if (lzw->code >= lzw->free_ent) {
				if ((lzw->code > lzw->free_ent) && !lzw->arcfs_mode) {
					liblzw_set_coded_error(lzw, 2);
					return -1;
				}

				lzw_push(lzw, lzw->finchar);
				if(lzw->errcode) return -1;
				lzw->code = lzw->oldcode;
			}

			/* Generate output characters in reverse order */
			while (lzw->code >= 256) {
				lzw_push(lzw, lzw->valuetab[lzw->code]);
				if(lzw->errcode) return -1;
				lzw->code = lzw->parenttab[lzw->code];
			}

			lzw->finchar = lzw->valuetab[lzw->code];
			lzw_push(lzw, lzw->finchar);
			if(lzw->errcode) return -1;

			/* And put them out in forward order */
			{
				lzw->stackp_diff = lzw_de_stack - lzw->stackp;

				if (lzw->outpos+lzw->stackp_diff >= BUFSIZE) {
					do {
						if (lzw->stackp_diff > BUFSIZE-lzw->outpos)
							lzw->stackp_diff = BUFSIZE-lzw->outpos;

						if (lzw->stackp_diff > 0) {
							de_memcpy(&lzw->outbuf[outbuf_startpos+lzw->outpos], lzw->stackp, lzw->stackp_diff);
							lzw->outpos += lzw->stackp_diff;
						}

						if (lzw->outpos >= BUFSIZE) {
							if (lzw->outpos < count_left) {
								lzw->cb_write(lzw, &lzw->outbuf[outbuf_startpos], lzw->outpos);
resume_partial_reading:
								count_left -= lzw->outpos;
							} else {
								lzw_empty_existing_buffer(lzw, outbuf_startpos, count_left);
								retval = count;
								goto done;
							}
resume_reading:
							lzw->outpos = 0;
						}
						lzw->stackp += lzw->stackp_diff;
					} while ((lzw->stackp_diff = (lzw_de_stack-lzw->stackp)) > 0);
				} else {
					de_memcpy(&lzw->outbuf[outbuf_startpos + lzw->outpos], lzw->stackp, lzw->stackp_diff);
					lzw->outpos += lzw->stackp_diff;
				}
			}

			/* Generate the new entry. */
			if ((lzw->code = lzw->free_ent) < maxmaxcode) {
				lzw->parenttab[lzw->code] = lzw->oldcode;
				lzw->valuetab[lzw->code] = lzw->finchar;
				lzw->free_ent = lzw->code+1;
			}

			lzw->oldcode = lzw->incode;	/* Remember previous code. */
		}
    } while (lzw->rsize != 0);

	if (lzw->outpos < count_left) {
		lzw->eof = 1;
		lzw->cb_write(lzw, &lzw->outbuf[outbuf_startpos], lzw->outpos);
		count_left -= lzw->outpos;
		retval = ((i64)count - (i64)count_left);
		goto done;
	} else {
		lzw_empty_existing_buffer(lzw, outbuf_startpos, count_left);
		retval = count;
		goto done;
	}

done:
	return retval;
}
