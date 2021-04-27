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


#define LZHUF_F               60      /* lookahead buffer size */
#define LZHUF_THRESHOLD       2
#define LZHUF_MAX_NUM_SPECIAL_CODES  1
#define LZHUF_MAX_N_CHAR      (256 + LZHUF_MAX_NUM_SPECIAL_CODES - LZHUF_THRESHOLD + LZHUF_F)
#define LZHUF_MAX_T           (LZHUF_MAX_N_CHAR * 2 - 1)        /* size of table */
#define LZHUF_MAX_FREQ        0x8000		/* updates tree when the */
									/* root frequency comes to this value. */

struct lzahuf_ctx {
	deark *c;
	const char *modname;
	struct de_lh1_params lh1p;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;

	UI lzhuf_N_CHAR; /* kinds of characters (character code = 0..N_CHAR-1) */
	UI lzhuf_T;
	UI lzhuf_R; /* position of root */ /* (LZHUF_T - 1) */
	UI num_special_codes;

	int errflag;
	i64 nbytes_written;
	struct de_lz77buffer *ringbuf;
	struct de_bitreader bitrd;

	u16 freq[LZHUF_MAX_T + 1];   /* frequency table */

	u16 prnt[LZHUF_MAX_T + LZHUF_MAX_N_CHAR];   /* pointers to parent nodes, except for the */
							/* elements [T..T + N_CHAR - 1] which are used to get */
							/* the positions of leaves corresponding to the codes. */

	u16 son[LZHUF_MAX_T];             /* pointers to child nodes (son[], son[] + 1) */
};

// These getters/setters are ugly, but it's too difficult for me to follow the
// dancing variables in the lzhuf code, and convince myself that there are no
// array overruns.
// Assuming the code is safe, these functions can be replaced by simple macros.

static u16 get_freq(struct lzahuf_ctx *cctx, UI idx)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->freq)) return cctx->freq[idx];
	cctx->errflag = 1;
	return 0;
}

static void set_freq(struct lzahuf_ctx *cctx, UI idx, u16 val)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->freq)) cctx->freq[idx] = val;
	else cctx->errflag = 1;
}

static u16 get_son(struct lzahuf_ctx *cctx, UI idx)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->son)) return cctx->son[idx];
	cctx->errflag = 1;
	return 0;
}

static void set_son(struct lzahuf_ctx *cctx, UI idx, u16 val)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->son)) cctx->son[idx] = val;
	else cctx->errflag = 1;
}

static u16 get_prnt(struct lzahuf_ctx *cctx, UI idx)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->prnt)) return cctx->prnt[idx];
	cctx->errflag = 1;
	return 0;
}

static void set_prnt(struct lzahuf_ctx *cctx, UI idx, u16 val)
{
	if(idx < (UI)DE_ARRAYCOUNT(cctx->prnt)) cctx->prnt[idx] = val;
	else cctx->errflag = 1;
}


/* initialization of tree */

static void lzhuf_StartHuff(struct lzahuf_ctx *cctx)
{
	UI i, j;

	for (i = 0; i < cctx->lzhuf_N_CHAR; i++) {
		set_freq(cctx, i, 1);
		set_son(cctx, i, i + cctx->lzhuf_T);
		set_prnt(cctx, i + cctx->lzhuf_T, i);
	}
	i = 0;
	j = cctx->lzhuf_N_CHAR;
	while (j <= cctx->lzhuf_R) {
		set_freq(cctx, j, get_freq(cctx, i) + get_freq(cctx, i + 1));
		set_son(cctx, j, i);
		set_prnt(cctx, i, j);
		set_prnt(cctx, i + 1, j);
		i += 2;
		j++;
	}
	set_freq(cctx, cctx->lzhuf_T, 0xffff);
	set_prnt(cctx, cctx->lzhuf_R, 0);
}


/* reconstruction of tree */

static void lzhuf_reconst(struct lzahuf_ctx *cctx)
{
	UI i, j, k;
	UI f, l;

	/* collect leaf nodes in the first half of the table */
	/* and replace the freq by (freq + 1) / 2. */
	j = 0;
	for (i = 0; i < cctx->lzhuf_T; i++) {
		if (get_son(cctx, i) >= cctx->lzhuf_T) {
			set_freq(cctx, j, (get_freq(cctx, i) + 1) / 2);
			set_son(cctx, j, get_son(cctx, i));
			j++;
		}
	}
	/* begin constructing tree by connecting sons */
	for (i = 0, j = cctx->lzhuf_N_CHAR; j < cctx->lzhuf_T; i += 2, j++) {
		k = i + 1;
		set_freq(cctx, j, get_freq(cctx, i) + get_freq(cctx, k));
		f = get_freq(cctx, j);

		k = j - 1;
		while(f < get_freq(cctx, k)) {
			k--;
		}

		k++;

		l = (j - k);
		// son[] is smaller than freq[], so bounds check uses son[].
		if(l > (UI)DE_ARRAYCOUNT(cctx->son) ||
			k+1+l > (UI)DE_ARRAYCOUNT(cctx->son))
		{
			cctx->errflag = 1;
			return;
		}

		de_memmove(&cctx->freq[k + 1], &cctx->freq[k], l*sizeof(cctx->freq[0]));
		set_freq(cctx, k, f);
		de_memmove(&cctx->son[k + 1], &cctx->son[k], l*sizeof(cctx->son[0]));
		set_son(cctx, k, i);
	}
	/* connect prnt */
	for (i = 0; i < cctx->lzhuf_T; i++) {
		k = get_son(cctx, i);
		if (k >= cctx->lzhuf_T) {
			set_prnt(cctx, k, i);
		} else {
			set_prnt(cctx, k, i);
			set_prnt(cctx, k + 1, i);
		}
	}
}


/* increment frequency of given code by one, and update tree */

static void lzhuf_update(struct lzahuf_ctx *cctx, UI c)
{
	UI i, j, l;
	UI k;
	UI counter = 0;
	UI r_freq;

	r_freq = get_freq(cctx, cctx->lzhuf_R);
	if(r_freq > LZHUF_MAX_FREQ) {
		cctx->errflag = 1;
		return;
	}
	if (r_freq == LZHUF_MAX_FREQ) {
		lzhuf_reconst(cctx);
		if(cctx->errflag) return;
	}
	c = get_prnt(cctx, c + cctx->lzhuf_T);
	do {
		if(counter > (UI)DE_ARRAYCOUNT(cctx->prnt)) { // infinite loop?
			cctx->errflag = 1;
			return;
		}
		counter++;

		set_freq(cctx, c, get_freq(cctx, c)+1);
		k = get_freq(cctx, c);

		/* if the order is disturbed, exchange nodes */
		l = c + 1;
		if (k > get_freq(cctx, l)) {

			do {
				l++;
			} while(k > get_freq(cctx, l));

			l--;
			set_freq(cctx, c, get_freq(cctx, l));
			set_freq(cctx, l, k);

			i = get_son(cctx, c);
			set_prnt(cctx, i, l);
			if (i < cctx->lzhuf_T) set_prnt(cctx, i + 1, l);

			j = get_son(cctx, l);
			set_son(cctx, l, i);

			set_prnt(cctx, j, c);
			if (j < cctx->lzhuf_T) set_prnt(cctx, j + 1, c);
			set_son(cctx, c, j);

			c = l;
		}
		c = get_prnt(cctx, c);
	} while (c != 0);   /* repeat up to root */
}

static UI lzhuf_DecodeChar(struct lzahuf_ctx *cctx)
{
	UI c;
	UI counter = 0;

	c = get_son(cctx, cctx->lzhuf_R);

	/* travel from root to leaf, */
	/* choosing the smaller child node (son[]) if the read bit is 0, */
	/* the bigger (son[]+1) if 1 */
	while (c < cctx->lzhuf_T) {
		if(counter > (UI)DE_ARRAYCOUNT(cctx->son)) { // infinite loop?
			cctx->errflag = 1;
			return 0;
		}
		counter++;

		c += (UI)de_bitreader_getbits(&cctx->bitrd, 1);
		c = get_son(cctx, c);
	}
	c -= cctx->lzhuf_T;
	lzhuf_update(cctx, c);
	return c;
}

static UI lzhuf_DecodePosition(struct lzahuf_ctx *cctx)
{
	UI i, j, c;

	/* recover upper bits from table */
	i = (UI)de_bitreader_getbits(&cctx->bitrd, 8);
	c = (UI)fmtutil_get_lzhuf_d_code(i);
	c <<= (cctx->lh1p.is_crlzh20 ? 5 : 6);
	j = fmtutil_get_lzhuf_d_len(i);

	/* read lower bits verbatim */
	j -= (cctx->lh1p.is_crlzh20 ? 3 : 2);
	i = (i<<j) | (UI)de_bitreader_getbits(&cctx->bitrd, j);
	i &= (cctx->lh1p.is_crlzh20 ? 0x1f : 0x3f);
	return c | i;
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
	UI i, j, c;
	UI rb_size; // LZHUF_N

	if(cctx->lh1p.is_crlzh11 || cctx->lh1p.is_crlzh20) {
		cctx->num_special_codes = 1;
		rb_size = 2048;
	}
	else {
		rb_size = 4096;
	}

	cctx->lzhuf_N_CHAR = 256 + cctx->num_special_codes - LZHUF_THRESHOLD + LZHUF_F;
	cctx->lzhuf_T = cctx->lzhuf_N_CHAR * 2 - 1;
	cctx->lzhuf_R = cctx->lzhuf_T  - 1;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzah_lz77buf_writebytecb;
	if(cctx->lh1p.history_fill_val!=0) {
		de_lz77buffer_clear(cctx->ringbuf, cctx->lh1p.history_fill_val);
	}

	lzhuf_StartHuff(cctx);

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
		if(c==256 && cctx->num_special_codes>=1) goto done;
		if (c < 256) {
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)c);
		}
		else {
			// i is the distance back
			i = lzhuf_DecodePosition(cctx);
			if(cctx->errflag) goto done;

			// j is the match length
			j = c - (255 + cctx->num_special_codes - LZHUF_THRESHOLD);

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
