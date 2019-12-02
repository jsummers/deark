/* This file is a heavily edited version of the lzw.c and lzw.h files from liblzw.
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
	struct de_dfilter_out_params *dcmpro;

	int arcfs_mode;
	int input_eof_flag;
	int errcode;

	i64 nbytes_written;
	int output_len_known;
	i64 output_expected_len;

	unsigned char *stackp;
	size_t stackp_diff;

	int maxbits, block_mode;

	unsigned int bitreader_buf;
	unsigned int bitreader_nbits_in_buf;
	i64 bitcount_for_this_group;

	int n_bits;
	int finchar;
	i32 maxcode, oldcode, incode, code, free_ent;

	unsigned char valuetab[LZW_MAX_NCODES];
	u16 parenttab[LZW_MAX_NCODES];
	unsigned char stackdata[LZW_MAX_NCODES];
	char errmsg[80];
};

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

static void lzw_write(struct de_liblzwctx *lzw, const u8 *buf, size_t size)
{
	i64 amt_to_write = (i64)size;

	if(lzw->dcmpro->len_known) {
		if(lzw->nbytes_written + amt_to_write > lzw->dcmpro->expected_len) {
			amt_to_write = lzw->dcmpro->expected_len - lzw->nbytes_written;
		}
	}
	if(amt_to_write<1) return;

	dbuf_write(lzw->dcmpro->f, buf, amt_to_write);
	lzw->nbytes_written += amt_to_write;
}

static void lzw_writebyte(struct de_liblzwctx *lzw, const u8 b)
{
	lzw_write(lzw, &b, 1);
}

static u8 lzw_getnextbyte(struct de_liblzwctx *lzw)
{
	u8 buf[1];
	size_t nread;

	if(lzw->errcode || lzw->input_eof_flag) return 0;

	nread = lzw->cb_read(lzw, buf, 1);
	if(nread!=1) {
		lzw->input_eof_flag = 1;
		return 0;
	}

	return buf[0];
}

static i32 lzw_getbits(struct de_liblzwctx *lzw, unsigned int nbits)
{
	unsigned int n;

	if(lzw->errcode || lzw->input_eof_flag) return 0;
	while(lzw->bitreader_nbits_in_buf < nbits) {
		u8 b;

		b = lzw_getnextbyte(lzw);
		if(lzw->errcode || lzw->input_eof_flag) return 0;
		lzw->bitreader_buf |= ((unsigned int)b)<<lzw->bitreader_nbits_in_buf;
		lzw->bitreader_nbits_in_buf += 8;
	}

	n = lzw->bitreader_buf & ((1U<<nbits)-1U);
	lzw->bitreader_buf >>= nbits;
	lzw->bitreader_nbits_in_buf -= nbits;
	lzw->bitcount_for_this_group += (i64)nbits;
	return (i32)n;
}

static i32 lzw_getnextcode(struct de_liblzwctx *lzw)
{
	return lzw_getbits(lzw, (unsigned int)lzw->n_bits);
}

static void lzw_skipbits(struct de_liblzwctx *lzw, unsigned int nbits)
{
	while(nbits > 0) {
		unsigned int n;

		if(nbits <= 16) {
			n = nbits;
		}
		else {
			n = 16;
		}

		(void)lzw_getbits(lzw, n);
		nbits -= n;
	}
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

	lzw->maxbits = lzwmode & 0x1f;    /* Mask for 'number of compression bits' */
	lzw->block_mode = lzwmode & 0x80;

	lzw->n_bits = INIT_BITS;
	lzw->maxcode = LZW_NBITS_TO_NCODES(INIT_BITS) - 1;
	lzw->oldcode = -1;
	lzw->finchar = 0;
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

static void lzw_end_bitgroup(struct de_liblzwctx *lzw)
{
	// To the best of my understanding, this is a silly bug that somehow became part of
	// the standard 'compress' format. -JS
	lzw_skipbits(lzw, (unsigned int)(de_pad_to_n(lzw->bitcount_for_this_group, 8*(i64)lzw->n_bits) -
		lzw->bitcount_for_this_group));
	lzw->bitcount_for_this_group = 0;
}

/*
 * Read LZW file
 */
static void de_liblzw_run(struct de_liblzwctx *lzw)
{
	i32 maxmaxcode = LZW_NBITS_TO_NCODES(lzw->maxbits);

	while (1) {
		if(lzw->dcmpro->len_known) {
			if(lzw->nbytes_written >= lzw->dcmpro->expected_len) goto done;
		}
		if(lzw->input_eof_flag) goto done;
		if(lzw->errcode) goto done;

		if (lzw->free_ent > lzw->maxcode) {
			lzw_end_bitgroup(lzw);
			++lzw->n_bits;
			if (lzw->n_bits == lzw->maxbits)
				lzw->maxcode = maxmaxcode;
			else
				lzw->maxcode = LZW_NBITS_TO_NCODES(lzw->n_bits)-1;
		}

		lzw->code = lzw_getnextcode(lzw);
		if(lzw->input_eof_flag || lzw->errcode) goto done;

		if(lzw->code>=LZW_MAX_NCODES || lzw->code<0) {
			liblzw_set_coded_error(lzw, 1);
			return;
		}

		if (lzw->oldcode == -1) {
			if (lzw->code >= 256) {
				liblzw_set_coded_error(lzw, 1);
				return;
			}
			lzw->oldcode = lzw->code;
			lzw->finchar = (unsigned char)lzw->code;
			lzw_writebyte(lzw, (unsigned char)lzw->code);
			continue;
		}

		if (lzw->code == CLEAR && lzw->block_mode) {
			lzw_end_bitgroup(lzw);

			de_zeromem(lzw->parenttab, sizeof(lzw->parenttab));
			// ?? Why is this FIRST-1, instead of FIRST?
			// My best guess is that it's a hack to handle the special case
			// of the first code after a CLEAR. It causes a code to be
			// written to table[256], where it will never get used. -JS
			lzw->free_ent = FIRST - 1;

			lzw->n_bits = INIT_BITS;
			lzw->maxcode = LZW_NBITS_TO_NCODES(lzw->n_bits)-1;
			continue;
		}

		lzw->incode = lzw->code;
		lzw_empty_stack(lzw);

		/* Special case for KwKwK string.*/
		if (lzw->code >= lzw->free_ent) {
			if ((lzw->code > lzw->free_ent) && !lzw->arcfs_mode) {
				liblzw_set_coded_error(lzw, 2);
				return;
			}

			lzw_push(lzw, lzw->finchar);
			if(lzw->errcode) return;
			lzw->code = lzw->oldcode;
		}

		/* Generate output characters in reverse order */
		while (lzw->code >= 256) {
			lzw_push(lzw, lzw->valuetab[lzw->code]);
			if(lzw->errcode) return;
			lzw->code = lzw->parenttab[lzw->code];
		}

		lzw->finchar = lzw->valuetab[lzw->code];
		lzw_push(lzw, lzw->finchar);
		if(lzw->errcode) return;

		/* And put them out in forward order */
		lzw->stackp_diff = lzw_de_stack - lzw->stackp;
		lzw_write(lzw, lzw->stackp, lzw->stackp_diff);

		/* Generate the new entry. */
		if ((lzw->code = lzw->free_ent) < maxmaxcode) {
			if(lzw->code < LZW_MAX_NCODES) {
				lzw->parenttab[lzw->code] = lzw->oldcode;
				lzw->valuetab[lzw->code] = lzw->finchar;
			}
			lzw->free_ent = lzw->code+1;
		}

		lzw->oldcode = lzw->incode;	/* Remember previous code. */
	}

done:
	;
}
