// See the file readme-lzhuf.txt for more information about this file.
// Modifications for Deark are Copyright (C) 2021 Jason Summers, and have the
// same terms of use as the main part of Deark.
// Alternatively, at your option, the modifications for Deark may be treated
// as public domain.

// Intro from the original software:

/**************************************************************
		lzhuf.c
		written by Haruyasu Yoshizaki 11/20/1988
		some minor changes 4/6/1989
		comments translated by Haruhiko Okumura 4/7/1989
**************************************************************/


#define LZHUF_N               4096    /* buffer size */
#define LZHUF_F               60      /* lookahead buffer size */
#define LZHUF_THRESHOLD       2
#define LZHUF_N_CHAR          (256 - LZHUF_THRESHOLD + LZHUF_F)
							/* kinds of characters (character code = 0..N_CHAR-1) */
#define LZHUF_T               (LZHUF_N_CHAR * 2 - 1)        /* size of table */
#define LZHUF_R               (LZHUF_T - 1)                 /* position of root */
#define LZHUF_MAX_FREQ        0x8000		/* updates tree when the */
									/* root frequency comes to this value. */

struct lzahuf_ctx {
	deark *c;
	const char *modname;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	int errflag;
	i64 nbytes_written;
	struct de_lz77buffer *ringbuf;
	struct de_bitreader bitrd;

	u16 freq[LZHUF_T + 1];   /* frequency table */

	i16 prnt[LZHUF_T + LZHUF_N_CHAR];   /* pointers to parent nodes, except for the */
							/* elements [T..T + N_CHAR - 1] which are used to get */
							/* the positions of leaves corresponding to the codes. */

	i16 son[LZHUF_T];             /* pointers to child nodes (son[], son[] + 1) */
};


/* initialization of tree */

static void lzhuf_StartHuff(struct lzahuf_ctx *cctx)
{
	int i, j;

	for (i = 0; i < LZHUF_N_CHAR; i++) {
		cctx->freq[i] = 1;
		cctx->son[i] = i + LZHUF_T;
		cctx->prnt[i + LZHUF_T] = i;
	}
	i = 0;
	j = LZHUF_N_CHAR;
	while (j <= LZHUF_R) {
		cctx->freq[j] = cctx->freq[i] + cctx->freq[i + 1];
		cctx->son[j] = i;
		cctx->prnt[i] = j;
		cctx->prnt[i + 1] = j;
		i += 2;
		j++;
	}
	cctx->freq[LZHUF_T] = 0xffff;
	cctx->prnt[LZHUF_R] = 0;
}


/* reconstruction of tree */

static void lzhuf_reconst(struct lzahuf_ctx *cctx)
{
	int i, j, k;
	UI f, l;

	/* collect leaf nodes in the first half of the table */
	/* and replace the freq by (freq + 1) / 2. */
	j = 0;
	for (i = 0; i < LZHUF_T; i++) {
		if (cctx->son[i] >= LZHUF_T) {
			cctx->freq[j] = (cctx->freq[i] + 1) / 2;
			cctx->son[j] = cctx->son[i];
			j++;
		}
	}
	/* begin constructing tree by connecting sons */
	for (i = 0, j = LZHUF_N_CHAR; j < LZHUF_T; i += 2, j++) {
		k = i + 1;
		cctx->freq[j] = cctx->freq[i] + cctx->freq[k];
		f = cctx->freq[j];

		k = j - 1;
		while(f < cctx->freq[k]) {
			k--;
		}

		k++;
		l = (j - k);
		de_memmove(&cctx->freq[k + 1], &cctx->freq[k], l*sizeof(cctx->freq[0]));
		cctx->freq[k] = f;
		de_memmove(&cctx->son[k + 1], &cctx->son[k], l*sizeof(cctx->son[0]));
		cctx->son[k] = i;
	}
	/* connect prnt */
	for (i = 0; i < LZHUF_T; i++) {
		k = cctx->son[i];
		if (k >= LZHUF_T) {
			cctx->prnt[k] = i;
		} else {
			cctx->prnt[k] = i;
			cctx->prnt[k + 1] = i;
		}
	}
}


/* increment frequency of given code by one, and update tree */

static void lzhuf_update(struct lzahuf_ctx *cctx, int c)
{
	int i, j, l;
	UI k;
	UI counter = 0;

	if(cctx->freq[LZHUF_R] > LZHUF_MAX_FREQ) {
		cctx->errflag = 1;
		return;
	}
	if (cctx->freq[LZHUF_R] == LZHUF_MAX_FREQ) {
		lzhuf_reconst(cctx);
	}
	c = cctx->prnt[c + LZHUF_T];
	do {
		if(counter > (UI)DE_ARRAYCOUNT(cctx->prnt)) { // infinite loop?
			cctx->errflag = 1;
			return;
		}
		counter++;

		cctx->freq[c]++;
		k = cctx->freq[c];

		/* if the order is disturbed, exchange nodes */
		l = c + 1;
		if (k > cctx->freq[l]) {

			do {
				l++;
			} while(k > cctx->freq[l]);

			l--;
			cctx->freq[c] = cctx->freq[l];
			cctx->freq[l] = k;

			i = cctx->son[c];
			cctx->prnt[i] = l;
			if (i < LZHUF_T) cctx->prnt[i + 1] = l;

			j = cctx->son[l];
			cctx->son[l] = i;

			cctx->prnt[j] = c;
			if (j < LZHUF_T) cctx->prnt[j + 1] = c;
			cctx->son[c] = j;

			c = l;
		}
		c = cctx->prnt[c];
	} while (c != 0);   /* repeat up to root */
}

static int lzhuf_DecodeChar(struct lzahuf_ctx *cctx)
{
	UI c;
	UI counter = 0;

	c = cctx->son[LZHUF_R];

	/* travel from root to leaf, */
	/* choosing the smaller child node (son[]) if the read bit is 0, */
	/* the bigger (son[]+1) if 1 */
	while (c < LZHUF_T) {
		if(counter > (UI)DE_ARRAYCOUNT(cctx->son)) { // infinite loop?
			cctx->errflag = 1;
			return 0;
		}
		counter++;

		c += (UI)de_bitreader_getbits(&cctx->bitrd, 1);
		c = cctx->son[c];
	}
	c -= LZHUF_T;
	lzhuf_update(cctx, c);
	return c;
}

static int lzhuf_DecodePosition(struct lzahuf_ctx *cctx)
{
	UI i, j, c;

	/* recover upper 6 bits from table */
	i = (UI)de_bitreader_getbits(&cctx->bitrd, 8);
	c = (UI)fmtutil_get_lzhuf_d_code(i) << 6;
	j = fmtutil_get_lzhuf_d_len(i);

	/* read lower 6 bits verbatim */
	j -= 2;
	i = (i<<j) | (UI)de_bitreader_getbits(&cctx->bitrd, j);
	return c | (i & 0x3f);
}

static int lzah_have_enough_output(struct lzahuf_ctx *cctx)
{
	if(cctx->dcmpro->len_known) {
		if(cctx->nbytes_written >= cctx->dcmpro->expected_len) {
			return 1;
		}
	}
	return 0;
}

static void lzah_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	struct lzahuf_ctx *cctx = (struct lzahuf_ctx*)rb->userdata;

	if(lzah_have_enough_output(cctx)) {
		return;
	}
	dbuf_writebyte(cctx->dcmpro->f, n);
	cctx->nbytes_written++;
}

static void lzhuf_Decode(struct lzahuf_ctx *cctx)  /* recover */
{
	int i, j, c;

	lzhuf_StartHuff(cctx);

	cctx->ringbuf = de_lz77buffer_create(cctx->c, LZHUF_N);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzah_lz77buf_writebytecb;
	de_lz77buffer_clear(cctx->ringbuf, 0x20);

	while(1) {
		if(cctx->errflag) goto done;
		if(lzah_have_enough_output(cctx)) {
			goto done;
		}
		if(cctx->bitrd.eof_flag) {
			goto done;
		}

		c = lzhuf_DecodeChar(cctx);
		if(cctx->errflag) goto done;
		if (c < 256) {
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)c);
		}
		else {
			// i is the distance back
			i = lzhuf_DecodePosition(cctx);
			if(cctx->errflag) goto done;

			// j is the match length
			j = c - (255 - LZHUF_THRESHOLD);

			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos - (UI)i - 1), j);
		}
	}

done:
	if(cctx->errflag) {
		de_dfilter_set_generic_error(cctx->c, cctx->dres, cctx->modname);
	}
	de_lz77buffer_destroy(cctx->c, cctx->ringbuf);
	cctx->ringbuf = NULL;
}
