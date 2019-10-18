// This ZOO/"LZD" decompression code is derived from code from the "zoo"
// software (zoo-2.10pl1.tar.gz) by Rahul Dhesi, primarily the SLOW_LZD code
// in lzd.c.
// [Which is very similar to the relevant code in the "Booz" (Barebones Ooz)
// software by Dhesi.]
//
// It has been heavily modified for Deark.
//
// The "zoo" software says:
//
//    Currently, all extract-only programs, and all supporting utili-
//    ties, are fully in the public domain and are expected to remain so
//    for the forseeable future.

// This file (zoo-lzd.h) is hereby left in the public domain; or it may, at
// your option, be distributed under the same terms as the main Deark software.

// Comments from the original lzd.c:

/*********************************************************************/
/* Original slower lzd().                                            */
/*********************************************************************/

/*
Lempel-Ziv decompression.  Mostly based on Tom Pfau's assembly language
code.  The contents of this file are hereby released to the public domain.
                                 -- Rahul Dhesi 1986/11/14
*/

#define lzd_debug(x)

#define  LZD_IN_BUF_SIZE       8192
#define  LZD_OUT_BUF_SIZE      8192

#define  LZD_INBUFSIZ    (LZD_IN_BUF_SIZE - 10)   /* avoid obo errors */
#define  LZD_OUTBUFSIZ   (LZD_OUT_BUF_SIZE - 10)
#define  LZD_MAXMAXBITS  16
#define  LZD_CLEAR       256         /* clear code */
#define  LZD_Z_EOF       257         /* end of file marker */
#define  LZD_FIRST_FREE  258         /* first free code */
#define  LZD_MAXMAX      (1<<LZD_MAXMAXBITS) /* max code + 1 */

#define  LZD_STACKSIZE   4000

struct lzd_tabentry {
   unsigned int next;
   u8 z_ch;
};

struct lzdctx {
	deark *c;
	struct de_dfilter_results *dres;
	const char *modname;
	dbuf *inf;
	dbuf *outf;
	i64 inf_pos;
	i64 inf_endpos;
	int inf_eof_count;
	i64 outf_nbyteswritten;
	int maxbits;
	struct lzd_tabentry *table;

	unsigned int cur_code;
	unsigned int old_code;
	unsigned int in_code;

	unsigned int free_code;
	int nbits;
	unsigned int max_code;

	u8 fin_char;
	u8 k;
	unsigned int bit_offset;
	unsigned int output_offset;

	unsigned int stack_pointer;
	u8 *stack;

	u8 in_buf_adr[LZD_IN_BUF_SIZE]; /* memory allocated for input buffer */
	u8 out_buf_adr[LZD_OUT_BUF_SIZE]; /* memory allocated for output buffer(s) */
};

static void lzd_init_dtab(struct lzdctx *lc);
static unsigned int lzd_rd_dcode(struct lzdctx *lc);
static void lzd_wr_dchar(struct lzdctx *lc, u8 ch);
static void lzd_ad_dcode(struct lzdctx *lc);

// On failure, sets an error in lc->dres.
static void lzd_push(struct lzdctx *lc, u8 x)
{
	if(lc->stack_pointer<LZD_STACKSIZE) {
		lc->stack[lc->stack_pointer] = x;
	}
	lc->stack_pointer++;
	if (lc->stack_pointer >= LZD_STACKSIZE) {
		lc->stack_pointer = LZD_STACKSIZE-1;
		de_dfilter_set_errorf(lc->c, lc->dres, lc->modname, "Stack overflow");
	}
}

static u8 lzd_pop(struct lzdctx *lc)
{
	if(lc->stack_pointer>0) {
		lc->stack_pointer--;
	}
	return lc->stack[lc->stack_pointer];
}

static void lzd_zoowrite(struct lzdctx *lc, const u8 *buffer, unsigned int count)
{
	dbuf_write(lc->outf, buffer, (i64)count);
	lc->outf_nbyteswritten += (i64)count;
}

static void lzd_zooread(struct lzdctx *lc, u8 *buffer, unsigned int count)
{
	i64 amt_avail;
	i64 amt_to_read;

	amt_to_read = (i64)count;
	amt_avail = lc->inf_endpos - lc->inf_pos;
	if(amt_to_read > amt_avail) {
		amt_to_read = amt_avail;
		lc->inf_eof_count++;
	}
	if(amt_to_read < 0) amt_to_read = 0;
	if(amt_to_read != (i64)count) {
		de_zeromem(buffer, (i64)count);
	}
	dbuf_read(lc->inf, buffer, lc->inf_pos, amt_to_read);
	lc->inf_pos += amt_to_read;
}

static int lzd_check_nbits(struct lzdctx *lc)
{
	if(lc->nbits >= 9 && lc->nbits <= lc->maxbits) {
		return 1;
	}
	de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
	return 0;
}

/****************************************************************************
**
*F  DecodeLzd() . . . . . . . . . . . . . . .  extract a LZ compressed member
**
*/
void de_fmtutil_decompress_zoo_lzd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, int maxbits)
{
	struct lzdctx *lc = NULL;

	lc = de_malloc(c, sizeof(struct lzdctx));
	lc->c = c;
	lc->dres = dres;
	lc->modname = "zoo-lzd";

	lc->maxbits = maxbits;
	if(lc->maxbits < 12 || lc->nbits > LZD_MAXMAXBITS) {
		de_dfilter_set_generic_error(c, dres, lc->modname);
		goto done;
	}
	lc->inf = dcmpri->f;                 /* make it avail to other fns */
	lc->inf_pos = dcmpri->pos;
	lc->inf_endpos = dcmpri->pos + dcmpri->len;
	lc->outf = dcmpro->f;               /* ditto */
	lc->nbits = 9;
	lc->max_code = 512;
	lc->free_code = LZD_FIRST_FREE;
	lc->stack_pointer = 0;
	lc->bit_offset = 0;
	lc->output_offset = 0;

	lzd_zooread (lc, lc->in_buf_adr, LZD_INBUFSIZ);

	lc->table = de_malloc(c, (LZD_MAXMAX+10) * sizeof(struct lzd_tabentry));
	lc->stack = de_malloc(c, LZD_STACKSIZE + 20);

	lzd_init_dtab(lc);             /* initialize table */

loop:
	if(dcmpro->len_known && lc->outf_nbyteswritten>=dcmpro->expected_len) {
		goto done; // Have enough output
	}
	if(lc->inf_eof_count > 2) {
		// An emergency brake. This is not the ideal way to detect if we ran out
		// of input data. But the original lzd code doesn't seem to make any
		// attempt to do that, and I just want to be sure that infinite loops
		// are impossible.
		de_dfilter_set_errorf(lc->c, lc->dres, lc->modname, "Not enough input data");
		goto done;
	}

	lc->cur_code = lzd_rd_dcode(lc);
	if(lc->dres->errcode) goto done;

goteof: /* special case for CLEAR then Z_EOF, for 0-length files */
	if (lc->cur_code == LZD_Z_EOF) {
		lzd_debug((printf ("lzd: Z_EOF\n")))
		if (lc->output_offset != 0) {
			lzd_zoowrite (lc, lc->out_buf_adr, lc->output_offset);
		}
		goto done;
	}

	if(!lzd_check_nbits(lc)) goto done;

	if (lc->cur_code == LZD_CLEAR) {
		lzd_debug((printf ("lzd: CLEAR\n")))
		lzd_init_dtab(lc);
		lc->fin_char = lc->k = lc->old_code = lc->cur_code = lzd_rd_dcode(lc);
		if(lc->dres->errcode) goto done;
		if (lc->cur_code == LZD_Z_EOF)		/* special case for 0-length files */
			goto goteof;
		lzd_wr_dchar(lc, lc->k);
		if(lc->dres->errcode) goto done;
		goto loop;
	}

	lc->in_code = lc->cur_code;
	if (lc->cur_code >= lc->free_code) {        /* if code not in table (k<w>k<w>k) */
		lc->cur_code = lc->old_code;             /* previous code becomes current */
		lzd_push(lc, lc->fin_char);
		if(lc->dres->errcode) goto done;
	}

	while (lc->cur_code > 255) {               /* if code, not character */
		if(!(lc->cur_code < LZD_MAXMAX+10)) {
			de_dfilter_set_generic_error(c, dres, lc->modname);
			goto done;
		}
		lzd_push(lc, lc->table[lc->cur_code].z_ch);         /* push suffix char */
		if(lc->dres->errcode) goto done;
		lc->cur_code = lc->table[lc->cur_code].next;    /* <w> := <w>.code */
	}

	if(!lzd_check_nbits(lc)) goto done;

	lc->k = lc->fin_char = lc->cur_code;
	lzd_push(lc, lc->k);
	if(lc->dres->errcode) goto done;
	while (lc->stack_pointer != 0) {
		lzd_wr_dchar(lc, lzd_pop(lc));
		if(lc->dres->errcode) goto done;
	}
	if(!lzd_check_nbits(lc)) goto done;
	lzd_ad_dcode(lc);
	if(lc->dres->errcode) goto done;
	lc->old_code = lc->in_code;

	if(!lzd_check_nbits(lc)) goto done;

	goto loop;

done:
	if(lc) {
		de_free(c, lc->table);
		de_free(c, lc->stack);
		de_free(c, lc);
	}
} /* lzd() */

/* lzd_rd_dcode() reads a code from the input (compressed) file and returns
its value. */
// On failure, sets an error in lc->dres.
static unsigned int lzd_rd_dcode(struct lzdctx *lc)
{
	unsigned int a_idx; // index in lc->in_buf_adr
	unsigned int word;                     /* first 16 bits in buffer */
	unsigned int byte_offset;
	u8 nextch;                           /* next 8 bits in buffer */
	unsigned int ofs_inbyte;               /* offset within byte */
	static const unsigned int masks[LZD_MAXMAXBITS+1] = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff };

	ofs_inbyte = lc->bit_offset % 8;
	byte_offset = lc->bit_offset / 8;
	lc->bit_offset = lc->bit_offset + lc->nbits;

	if(!lzd_check_nbits(lc)) return 0;

	if (byte_offset >= LZD_INBUFSIZ - 5) {
		int space_left;

		if(!(byte_offset >= LZD_INBUFSIZ - 5)) {
			de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
			return 0;
		}
		lzd_debug((printf ("lzd: byte_offset near end of buffer\n")))

		lc->bit_offset = ofs_inbyte + lc->nbits;
		space_left = LZD_INBUFSIZ - byte_offset;
		a_idx = 0;
		/* we now move the remaining characters down buffer beginning */
		lzd_debug((printf ("lzd_rd_dcode: space_left = %d\n", space_left)))
		if(!(a_idx + byte_offset <= LZD_OUT_BUF_SIZE)) {
			de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
			return 0;
		}
		de_memmove(&lc->in_buf_adr[a_idx], &lc->in_buf_adr[byte_offset], (size_t)space_left);
		a_idx += space_left;
		lzd_zooread(lc, &lc->in_buf_adr[a_idx], byte_offset);
		byte_offset = 0;
	}
	a_idx = byte_offset;
	if(!(a_idx <= LZD_OUT_BUF_SIZE-3)) {
		de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
		return 0;
	}
	word = lc->in_buf_adr[a_idx];
	a_idx++;
	word = word | ( ((unsigned int) lc->in_buf_adr[a_idx]) << 8 );
	a_idx++;

	nextch = lc->in_buf_adr[a_idx];
	if (ofs_inbyte != 0) {
		/* shift nextch right by ofs_inbyte bits */
		/* and shift those bits right into word; */
		word = (word >> ofs_inbyte) | (((unsigned int)nextch) << (16-ofs_inbyte));
	}
	return (word & masks[lc->nbits]);
} /* lzd_rd_dcode() */

static void lzd_init_dtab(struct lzdctx *lc)
{
	lc->nbits = 9;
	lc->max_code = 512;
	lc->free_code = LZD_FIRST_FREE;
}

// On failure, sets an error in lc->dres.
static void lzd_wr_dchar(struct lzdctx *lc, u8 ch)
{
	if (lc->output_offset >= LZD_OUTBUFSIZ) {      /* if buffer full */
		lzd_zoowrite(lc, lc->out_buf_adr, lc->output_offset);
		lc->output_offset = 0;                  /* restore empty buffer */
	}
	if(!(lc->output_offset < LZD_OUTBUFSIZ)) {
		de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
		return;
	}
	if(lc->output_offset < LZD_OUTBUFSIZ) {
		lc->out_buf_adr[lc->output_offset++] = ch;        /* store character */
	}
} /* lzd_wr_dchar() */

/* adds a code to table */
// On failure, sets an error in lc->dres.
static void lzd_ad_dcode(struct lzdctx *lc)
{
	if(!lzd_check_nbits(lc)) return;
	if(!(lc->free_code <= LZD_MAXMAX+1)) {
		de_dfilter_set_errorf(lc->c, lc->dres, lc->modname, "Decode error");
		return;
	}
	if(!(lc->free_code <= LZD_MAXMAX+1)) {
		de_dfilter_set_generic_error(lc->c, lc->dres, lc->modname);
		return;
	}
	lc->table[lc->free_code].z_ch = lc->k;                /* save suffix char */
	lc->table[lc->free_code].next = lc->old_code;         /* save prefix code */
	lc->free_code++;
	if(!lzd_check_nbits(lc)) return;
	if (lc->free_code >= lc->max_code) {
		if (lc->nbits < lc->maxbits) {
			lzd_debug((printf("lzd: nbits was %d\n", nbits)))
			lc->nbits++;
			if(!lzd_check_nbits(lc)) return;

			lzd_debug((printf("lzd: nbits now %d\n", nbits)))
			lc->max_code = lc->max_code << 1;        /* double max_code */
			lzd_debug((printf("lzd: max_code now %d\n", max_code)))
		}
	}
}
