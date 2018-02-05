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
#define lzd_assert(E) if(!(E)) lzd_on_assert_fail(uz);

#define  LZD_IN_BUF_SIZE       8192
#define  LZD_OUT_BUF_SIZE      8192

#define  LZD_INBUFSIZ    (LZD_IN_BUF_SIZE - 10)   /* avoid obo errors */
#define  LZD_OUTBUFSIZ   (LZD_OUT_BUF_SIZE - 10)
#define  LZD_MEMERR      2
#define  LZD_IOERR       1
#define  LZD_MAXBITS     13
#define  LZD_CLEAR       256         /* clear code */
#define  LZD_Z_EOF       257         /* end of file marker */
#define  LZD_FIRST_FREE  258         /* first free code */
#define  LZD_MAXMAX      8192        /* max code + 1 */

#define  LZD_STACKSIZE   4000

struct lzd_tabentry {
   unsigned int next;
   de_byte z_ch;
};

struct lzdctx {
	dbuf *in_f;
	dbuf *out_f;
	struct lzd_tabentry *table;
	de_uint16 crccode;

	unsigned int cur_code;
	unsigned int old_code;
	unsigned int in_code;

	unsigned int free_code;
	int nbits;
	unsigned int max_code;

	de_byte fin_char;
	de_byte k;
	unsigned int bit_offset;
	unsigned int output_offset;

	unsigned int stack_pointer;
	de_byte *stack;

	de_byte in_buf_adr[LZD_IN_BUF_SIZE]; /* memory allocated for input buffer */
	de_byte out_buf_adr[LZD_OUT_BUF_SIZE]; /* memory allocated for output buffer(s) */
};

static void lzd_init_dtab(struct lzdctx *lc);
static unsigned int lzd_rd_dcode(struct unzooctx *uz, struct lzdctx *lc);
static void lzd_wr_dchar(struct unzooctx *uz, struct lzdctx *lc, de_byte ch);
static void lzd_ad_dcode(struct unzooctx *uz, struct lzdctx *lc);

static void lzd_on_assert_fail(struct unzooctx *uz)
{
	de_err(uz->c, "lzd_assert failed");
	de_fatalerror(uz->c);
}

static void lzd_prterror(struct unzooctx *uz, int level, const char *msg)
{
	de_err(uz->c, "%s", msg);
	// TODO: Some of these errors shouldn't be fatal.
	de_fatalerror(uz->c);
}

static void lzd_push(struct unzooctx *uz, struct lzdctx *lc, de_byte x)
{
	if(lc->stack_pointer<LZD_STACKSIZE) {
		lc->stack[lc->stack_pointer] = x;
	}
	lc->stack_pointer++;
	if (lc->stack_pointer >= LZD_STACKSIZE) {
		lc->stack_pointer = LZD_STACKSIZE-1;
		lzd_prterror (uz, 'f', "Stack overflow in lzd().");
	}
}

static de_byte lzd_pop(struct lzdctx *lc)
{
	if(lc->stack_pointer>0) {
		lc->stack_pointer--;
	}
	return lc->stack[lc->stack_pointer];
}

static void lzd_addbfcrc(struct unzooctx *uz, struct lzdctx *lc, const de_byte *buffer, int count)
{
	de_uint16 localcrc;
	localcrc = lc->crccode;

	for (; count--; ) {
		localcrc = CRC_BYTE(uz, localcrc, (*buffer++));
	}
	lc->crccode = localcrc;
}

static unsigned int lzd_zoowrite (struct unzooctx *uz, dbuf *file, const de_byte *buffer, int count)
{
	dbuf_write(file, buffer, count);
	return (unsigned int)count;
}

static int lzd_zooread(struct unzooctx *uz, dbuf *file, de_byte *buffer, int count)
{
	return (int)dbuf_standard_read(file, buffer, count, &uz->ReadArch_fpos);
}

static int lzd(struct unzooctx *uz, struct entryctx *ze)
{
	struct lzdctx *lc = NULL;
	int retval = -1;

	lc = de_malloc(uz->c, sizeof(struct lzdctx));

	lc->in_f = uz->ReadArch;                 /* make it avail to other fns */
	lc->out_f = ze->WritBinr;               /* ditto */
	lc->nbits = 9;
	lc->max_code = 512;
	lc->free_code = LZD_FIRST_FREE;
	lc->stack_pointer = 0;
	lc->bit_offset = 0;
	lc->output_offset = 0;

	if (lzd_zooread (uz, lc->in_f, lc->in_buf_adr, LZD_INBUFSIZ) == -1) {
		retval = LZD_IOERR;
		goto done;
	}
	lc->table = de_malloc(uz->c, (LZD_MAXMAX+10) * sizeof(struct lzd_tabentry));
	lc->stack = de_malloc(uz->c, LZD_STACKSIZE + 20);

	lzd_init_dtab(lc);             /* initialize table */

loop:
	lc->cur_code = lzd_rd_dcode(uz, lc);
goteof: /* special case for CLEAR then Z_EOF, for 0-length files */
	if (lc->cur_code == LZD_Z_EOF) {
		lzd_debug((printf ("lzd: Z_EOF\n")))
		if (lc->output_offset != 0) {
			if (lzd_zoowrite (uz, lc->out_f, lc->out_buf_adr, lc->output_offset) != lc->output_offset)
				lzd_prterror (uz, 'f', "Output error in lzd().");
			lzd_addbfcrc(uz, lc, lc->out_buf_adr, lc->output_offset);
		}
		retval = 0;
		goto done;
	}

	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);

	if (lc->cur_code == LZD_CLEAR) {
		lzd_debug((printf ("lzd: CLEAR\n")))
		lzd_init_dtab(lc);
		lc->fin_char = lc->k = lc->old_code = lc->cur_code = lzd_rd_dcode(uz, lc);
		if (lc->cur_code == LZD_Z_EOF)		/* special case for 0-length files */
			goto goteof;
		lzd_wr_dchar(uz, lc, lc->k);
		goto loop;
	}

	lc->in_code = lc->cur_code;
	if (lc->cur_code >= lc->free_code) {        /* if code not in table (k<w>k<w>k) */
		lc->cur_code = lc->old_code;             /* previous code becomes current */
		lzd_push(uz, lc, lc->fin_char);
	}

	while (lc->cur_code > 255) {               /* if code, not character */
		lzd_assert(lc->cur_code < LZD_MAXMAX+10);
		lzd_push(uz, lc, lc->table[lc->cur_code].z_ch);         /* push suffix char */
		lc->cur_code = lc->table[lc->cur_code].next;    /* <w> := <w>.code */
	}

	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);

	lc->k = lc->fin_char = lc->cur_code;
	lzd_push(uz, lc, lc->k);
	while (lc->stack_pointer != 0) {
		lzd_wr_dchar(uz, lc, lzd_pop(lc));
	}
	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);
	lzd_ad_dcode(uz, lc);
	lc->old_code = lc->in_code;

	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);

	goto loop;

done:
	ze->Crc = lc->crccode;
	if(lc) {
		de_free(uz->c, lc->table);
		de_free(uz->c, lc->stack);
		de_free(uz->c, lc);
	}
	return retval;
} /* lzd() */

/* lzd_rd_dcode() reads a code from the input (compressed) file and returns
its value. */
static unsigned int lzd_rd_dcode(struct unzooctx *uz, struct lzdctx *lc)
{
	unsigned int a_idx; // index in lc->in_buf_adr
	unsigned int word;                     /* first 16 bits in buffer */
	unsigned int byte_offset;
	de_byte nextch;                           /* next 8 bits in buffer */
	unsigned int ofs_inbyte;               /* offset within byte */
	static const unsigned int masks[14] = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff };

	ofs_inbyte = lc->bit_offset % 8;
	byte_offset = lc->bit_offset / 8;
	lc->bit_offset = lc->bit_offset + lc->nbits;

	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);

	if (byte_offset >= LZD_INBUFSIZ - 5) {
		int space_left;

		lzd_assert(byte_offset >= LZD_INBUFSIZ - 5);
		lzd_debug((printf ("lzd: byte_offset near end of buffer\n")))

		lc->bit_offset = ofs_inbyte + lc->nbits;
		space_left = LZD_INBUFSIZ - byte_offset;
		a_idx = 0;
		/* we now move the remaining characters down buffer beginning */
		lzd_debug((printf ("lzd_rd_dcode: space_left = %d\n", space_left)))
		lzd_assert(a_idx + byte_offset <= LZD_OUT_BUF_SIZE);
		de_memmove(&lc->in_buf_adr[a_idx], &lc->in_buf_adr[byte_offset], (size_t)space_left);
		a_idx += space_left;
		if (lzd_zooread (uz, lc->in_f, &lc->in_buf_adr[a_idx], (int)byte_offset) == -1)
			lzd_prterror (uz, 'f', "I/O error in lzd_rd_dcode.");
		byte_offset = 0;
	}
	a_idx = byte_offset;
	lzd_assert(a_idx <= LZD_OUT_BUF_SIZE-3);
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

static void lzd_wr_dchar(struct unzooctx *uz, struct lzdctx *lc, de_byte ch)
{
	if (lc->output_offset >= LZD_OUTBUFSIZ) {      /* if buffer full */
		if (lzd_zoowrite (uz, lc->out_f, lc->out_buf_adr, lc->output_offset) != lc->output_offset)
			lzd_prterror (uz, 'f', "Write error in lzd:wr_dchar.");
		lzd_addbfcrc(uz, lc, lc->out_buf_adr, lc->output_offset);     /* update CRC */
		lc->output_offset = 0;                  /* restore empty buffer */
	}
	lzd_assert(lc->output_offset < LZD_OUTBUFSIZ);
	if(lc->output_offset < LZD_OUTBUFSIZ) {
		lc->out_buf_adr[lc->output_offset++] = ch;        /* store character */
	}
} /* lzd_wr_dchar() */

/* adds a code to table */
static void lzd_ad_dcode(struct unzooctx *uz, struct lzdctx *lc)
{
	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);
	lzd_assert(lc->free_code <= LZD_MAXMAX+1);
	lc->table[lc->free_code].z_ch = lc->k;                /* save suffix char */
	lc->table[lc->free_code].next = lc->old_code;         /* save prefix code */
	lc->free_code++;
	lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);
	if (lc->free_code >= lc->max_code) {
		if (lc->nbits < LZD_MAXBITS) {
			lzd_debug((printf("lzd: nbits was %d\n", nbits)))
			lc->nbits++;
			lzd_assert(lc->nbits >= 9 && lc->nbits <= 13);
			lzd_debug((printf("lzd: nbits now %d\n", nbits)))
			lc->max_code = lc->max_code << 1;        /* double max_code */
			lzd_debug((printf("lzd: max_code now %d\n", max_code)))
		}
	}
}
