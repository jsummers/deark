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

#define HBITS   17			/* 50% occupancy */
#define HSIZE   (1<<HBITS)

struct de_liblzwctx {
	deark *c;
	dbuf *inf;
	i64 inf_fpos;
	int arcfs_mode;

	int eof;

	unsigned char *inbuf, *outbuf, *stackp;
	unsigned char *unreadbuf;
	size_t stackp_diff;
	size_t insize, outpos;
	i64 rsize;

	unsigned char flags;
	int maxbits, block_mode;

	u32 htab[HSIZE];
	u16 codetab[HSIZE];

	int n_bits, posbits, inbits, bitmask, finchar;
	i32 maxcode, oldcode, incode, code, free_ent;
};

/******************************************/


/*
 * Misc common define cruft
 */
#define BUFSIZE      4096
#define IN_BUFSIZE   (BUFSIZE + 64)
#define OUT_BUFSIZE  (BUFSIZE + 2048)
#define BITS         16
#define INIT_BITS    9			/* initial number of bits/code */
#define MAXCODE(n)   (1L << (n))
#define FIRST        257					/* first free entry */
#define CLEAR        256					/* table clear output code */


/*
 * Open LZW file
 */
static struct de_liblzwctx *de_liblzw_dbufopen(dbuf *inf, unsigned int dflags, u8 lzwmode)
{
	struct de_liblzwctx *ret = NULL;
	i64 inf_fpos = 0;
	int has_header;

	has_header = (dflags&0x1)?1:0;

	if(has_header) {
		unsigned char buf[3];

		if (dbuf_standard_read(inf, buf, 3, &inf_fpos) != 3) {
			de_err(inf->c, "Not in compress format");
			goto err_out;
		}

		if (buf[0] != LZW_MAGIC_1 || buf[1] != LZW_MAGIC_2 || buf[2] & 0x60) {
			de_err(inf->c, "Not in compress format");
			goto err_out;
		}
		lzwmode = buf[2];
	}

	ret = de_malloc(inf->c, sizeof(*ret));

	ret->c = inf->c;
	ret->inf = inf;
	ret->inf_fpos = inf_fpos;
	ret->arcfs_mode = (dflags&0x2)?1:0;

	ret->eof = 0;
	ret->inbuf = de_malloc(ret->c, sizeof(unsigned char) * IN_BUFSIZE);
	ret->outbuf = de_malloc(ret->c, sizeof(unsigned char) * OUT_BUFSIZE);
	ret->stackp = NULL;
	if(has_header) {
		ret->insize = 3; /* we read three bytes above */
	}
	else {
		ret->insize = 0;
	}
	ret->outpos = 0;
	ret->rsize = 0;

	ret->flags = lzwmode;
	ret->maxbits = ret->flags & 0x1f;    /* Mask for 'number of compresssion bits' */
	ret->block_mode = ret->flags & 0x80;

	ret->n_bits = INIT_BITS;
	ret->maxcode = MAXCODE(INIT_BITS) - 1;
	ret->bitmask = (1<<INIT_BITS)-1;
	ret->oldcode = -1;
	ret->finchar = 0;
	ret->posbits = 3<<3;
	ret->free_ent = ((ret->block_mode) ? FIRST : 256);

	/* initialize the first 256 entries in the table */
	for (ret->code = 255; ret->code >= 0; --ret->code)
		ret->htab[ret->code] = ret->code;

	if (ret->maxbits > BITS) {
		de_err(ret->c, "Unsupported number of bits (%d)", ret->maxbits);
		goto err_out_free;
	}

	return ret;

err_out:
	return NULL;

err_out_free:
	if(ret) {
		de_free(inf->c, ret->inbuf);
		de_free(inf->c, ret->outbuf);
		de_free(inf->c, ret);
	}
	return NULL;
}


/*
 * Close LZW file
 */
static int de_liblzw_close(struct de_liblzwctx *lzw)
{
	int ret;
	if (lzw == NULL)
		return -1;
	ret = 0;
	de_free(lzw->c, lzw->inbuf);
	de_free(lzw->c, lzw->outbuf);
	de_free(lzw->c, lzw);
	return ret;
}


/*
 * Misc read-specific define cruft
 */

#define lzw_input(b,o,c,n,m) \
	do { \
		unsigned char *p = &(b)[(o)>>3]; \
		(c) = ((((i32)(p[0]))|((i32)(p[1])<<8)| \
		       ((i32)(p[2])<<16))>>((o)&0x7))&(m); \
		(o) += (n); \
	} while (0)

#define lzw_de_stack				((unsigned char *)&(lzw->htab[HSIZE-1]))

/*
 * Read LZW file
 */
static i64 de_liblzw_read(struct de_liblzwctx *lzw, u8 *readbuf, size_t count)
{
	size_t count_left = count;
	unsigned char *inbuf = lzw->inbuf;
	unsigned char *outbuf = lzw->outbuf;

	i32 maxmaxcode = MAXCODE(lzw->maxbits);

	if (!count || lzw->eof)
		return 0;

	if (lzw->stackp != NULL) {
		if (lzw->outpos) {
			if (lzw->outpos >= count) {
				outbuf = lzw->unreadbuf;
				goto empty_existing_buffer;
			} else /*if (lzw->outpos < count)*/ {
				memcpy(readbuf, lzw->unreadbuf, lzw->outpos);
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
				inbuf[i] = inbuf[i+o];

			lzw->insize = e;
			lzw->posbits = 0;
		}

		if (lzw->insize < IN_BUFSIZE-BUFSIZE) {
			lzw->rsize = dbuf_standard_read(lzw->inf, inbuf+lzw->insize, BUFSIZE, &lzw->inf_fpos);
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
					lzw->maxcode = MAXCODE(lzw->n_bits)-1;

				lzw->bitmask = (1 << lzw->n_bits) - 1;
				goto resetbuf;
			}

			lzw_input(inbuf,lzw->posbits,lzw->code,lzw->n_bits,lzw->bitmask);

			if (lzw->oldcode == -1) {
				if (lzw->code >= 256) {
					de_err(lzw->c, "LZW decompression error");
					return -1;
				}
				outbuf[lzw->outpos++] = lzw->finchar = lzw->oldcode = lzw->code;
				continue;
			}

			if (lzw->code == CLEAR && lzw->block_mode) {
				de_zeromem(lzw->codetab, sizeof(lzw->codetab));
				lzw->free_ent = FIRST - 1;
				lzw->posbits = ((lzw->posbits-1) + ((lzw->n_bits<<3) -
				                (lzw->posbits-1 + (lzw->n_bits<<3)) % (lzw->n_bits<<3)));
				lzw->maxcode = MAXCODE(lzw->n_bits = INIT_BITS)-1;
				lzw->bitmask = (1 << lzw->n_bits) - 1;
				goto resetbuf;
			}

			lzw->incode = lzw->code;
			lzw->stackp = lzw_de_stack;

			/* Special case for KwKwK string.*/
			if (lzw->code >= lzw->free_ent) {
				if ((lzw->code > lzw->free_ent) && !lzw->arcfs_mode) {
					de_err(lzw->c, "LZW decompression error");
					return -1;
				}

				*--lzw->stackp = lzw->finchar;
				lzw->code = lzw->oldcode;
			}

			/* Generate output characters in reverse order */
			while (lzw->code >= 256) {
				if(lzw->stackp==(unsigned char*)&lzw->htab[0]) {
					de_err(lzw->c, "LZW decompression error");
					return -1;
				}
				*--lzw->stackp = (unsigned char)lzw->htab[lzw->code];
				lzw->code = lzw->codetab[lzw->code];
			}

			if(lzw->stackp==(unsigned char*)&lzw->htab[0]) {
				de_err(lzw->c, "LZW decompression error");
				return -1;
			}
			*--lzw->stackp = (lzw->finchar = lzw->htab[lzw->code]);

			/* And put them out in forward order */
			{
				lzw->stackp_diff = lzw_de_stack - lzw->stackp;

				if (lzw->outpos+lzw->stackp_diff >= BUFSIZE) {
					do {
						if (lzw->stackp_diff > BUFSIZE-lzw->outpos)
							lzw->stackp_diff = BUFSIZE-lzw->outpos;

						if (lzw->stackp_diff > 0) {
							memcpy(outbuf+lzw->outpos, lzw->stackp, lzw->stackp_diff);
							lzw->outpos += lzw->stackp_diff;
						}

						if (lzw->outpos >= BUFSIZE) {
							if (lzw->outpos < count_left) {
								memcpy(readbuf, outbuf, lzw->outpos);
resume_partial_reading:
								readbuf += lzw->outpos;
								count_left -= lzw->outpos;
							} else {
empty_existing_buffer:
								lzw->outpos -= count_left;
								memcpy(readbuf, outbuf, count_left);
								lzw->unreadbuf = outbuf + count_left;
								return count;
							}
resume_reading:
							lzw->outpos = 0;
						}
						lzw->stackp += lzw->stackp_diff;
					} while ((lzw->stackp_diff = (lzw_de_stack-lzw->stackp)) > 0);
				} else {
					memcpy(outbuf+lzw->outpos, lzw->stackp, lzw->stackp_diff);
					lzw->outpos += lzw->stackp_diff;
				}
			}

			/* Generate the new entry. */
			if ((lzw->code = lzw->free_ent) < maxmaxcode) {
				lzw->codetab[lzw->code] = lzw->oldcode;
				lzw->htab[lzw->code] = lzw->finchar;
				lzw->free_ent = lzw->code+1;
			}

			lzw->oldcode = lzw->incode;	/* Remember previous code. */
		}
    } while (lzw->rsize != 0);

	if (lzw->outpos < count_left) {
		lzw->eof = 1;
		memcpy(readbuf, outbuf, lzw->outpos);
		count_left -= lzw->outpos;
		return (count - count_left);
	} else {
		goto empty_existing_buffer;
	}
}
