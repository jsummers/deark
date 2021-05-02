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

// Max of #literals + #special_codes + #match_lengths.
// Must be at least 256+59 (lh1:58, CRLZH:59)
#define LZHUF_MAX_N_CHAR      (256 + 60)

#define LZHUF_MAX_T           (LZHUF_MAX_N_CHAR * 2 - 1)        /* size of table */
#define LZHUF_MAX_FREQ        0x8000		/* updates tree when the */
									/* root frequency comes to this value. */

struct lzahuf_ctx {
	deark *c;
	const char *modname;
	u8 dbg_mode;
	struct de_lh1_params lh1p;
	struct de_dfilter_ctx *dfctx;
	struct de_dfilter_out_params *dcmpro; // same as dfctx->dcmpro
	struct de_dfilter_results *dres; // same as dfctx->dres

	UI num_length_codes;
	UI match_length_bias;
	UI lzhuf_N_CHAR; /* kinds of characters (character code = 0..N_CHAR-1) */
	UI lzhuf_T;
	UI lzhuf_R; /* position of root */ /* (LZHUF_T - 1) */
	UI num_special_codes;
	u8 crlzh20_style_positions;

	int errflag;
	i64 total_nbytes_processed;
	i64 nbytes_written;

	struct de_lz77buffer *ringbuf;
	struct de_bitbuf_lowlevel bbll;

	u16 freq[LZHUF_MAX_T + 1];   /* frequency table */

	u16 prnt[LZHUF_MAX_T + LZHUF_MAX_N_CHAR];   /* pointers to parent nodes, except for the */
							/* elements [T..T + N_CHAR - 1] which are used to get */
							/* the positions of leaves corresponding to the codes. */

	u16 son[LZHUF_MAX_T];             /* pointers to child nodes (son[], son[] + 1) */

	// ibuf1 contains unprocessed leftover bytes from last time.
	// It's to help make the decoder "pushable". We won't start to decode an
	// "instruction" unless we're sure all the bits we might need are in memory.
	// 30 to 40 bits should be sufficient.
#define LZHUF_IBUF_LOW_WATER_MARK 8 // Can leave up to this many bytes in ibuf1
	size_t ibuf1_curpos;
	size_t ibuf1_len;
	u8 ibuf1[LZHUF_IBUF_LOW_WATER_MARK];

	size_t ibuf2_curpos;
	size_t ibuf2_len;
	const u8 *ibuf2;
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

static char *bbll_describe_curpos(struct de_bitbuf_lowlevel *bbll, i64 pos1, char *buf, size_t buf_len)
{
	i64 curpos;
	UI nwholebytes;
	UI nbits;

	nwholebytes = (i64)(bbll->nbits_in_bitbuf / 8);
	nbits = bbll->nbits_in_bitbuf % 8;
	curpos = pos1 - (i64)nwholebytes;

	if(nbits==0) {
		de_snprintf(buf, buf_len, "%"I64_FMT, curpos);
	}
	else {
		de_snprintf(buf, buf_len, "%"I64_FMT"+%ubits", curpos-1, (UI)(8-nbits));
	}
	return buf;
}

static UI lzhuf_getbits(struct lzahuf_ctx *cctx, UI nbits)
{
	while(cctx->bbll.nbits_in_bitbuf < nbits) {
		// Need another byte
		if(cctx->ibuf1_curpos < cctx->ibuf1_len) { // Can we get it from ibuf1?
			de_bitbuf_lowlevel_add_byte(&cctx->bbll, cctx->ibuf1[cctx->ibuf1_curpos]);
			cctx->ibuf1_curpos++;
		}
		else if(cctx->ibuf2_curpos < cctx->ibuf2_len) { // Or from ibuf2?
			de_bitbuf_lowlevel_add_byte(&cctx->bbll, cctx->ibuf2[cctx->ibuf2_curpos]);
			cctx->ibuf2_curpos++;
		}
		else {
			de_dfilter_set_errorf(cctx->c, cctx->dres, cctx->modname,
				"Unexpected end of compressed data");
			cctx->errflag = 1;
			return 0;
		}

		cctx->total_nbytes_processed++;
	}

	return (UI)de_bitbuf_lowlevel_get_bits(&cctx->bbll, nbits);
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

		c += lzhuf_getbits(cctx, 1);
		c = get_son(cctx, c);
	}
	c -= cctx->lzhuf_T;
	lzhuf_update(cctx, c);
	return c;
}

static UI lzhuf_DecodePosition(struct lzahuf_ctx *cctx)
{
	UI i, j, c;
	UI d_code, d_len;

	/* recover upper bits from table */
	i = lzhuf_getbits(cctx, 8);
	fmtutil_get_lzhuf_d_code_and_len(i, &d_code, &d_len);
	c = d_code << (cctx->crlzh20_style_positions ? 5 : 6);

	/* read lower bits verbatim */
	j = d_len - (cctx->crlzh20_style_positions ? 3 : 2);
	i = (i<<j) | lzhuf_getbits(cctx, j);
	i &= (cctx->crlzh20_style_positions ? 0x1f : 0x3f);
	return c | i;
}

static int lzah_have_enough_output(struct lzahuf_ctx *cctx)
{
	if(cctx->dcmpro->len_known) {
		if(cctx->nbytes_written >= cctx->dcmpro->expected_len) {
			cctx->dfctx->finished_flag = 1;
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

static void lzhuf_decodesubtree_nodepair(struct lzahuf_ctx *cctx, UI p1, u64 val, UI val_nbits,
	char *b2buf, size_t b2buf_len);

static void lzhuf_decodesubtree_node(struct lzahuf_ctx *cctx, UI p1, u64 val, UI val_nbits,
	char *b2buf, size_t b2buf_len)
{
	if(cctx->son[p1] < cctx->lzhuf_T) { // [pointer node]
		lzhuf_decodesubtree_nodepair(cctx, cctx->son[p1], val, val_nbits, b2buf, b2buf_len);
	}
	else { // [leaf node]
		de_dbg(cctx->c, "code: \"%s\" = %d [%u]",
			de_print_base2_fixed(b2buf, b2buf_len, val, val_nbits),
			(int)cctx->son[p1], (UI)(cctx->son[p1]-cctx->lzhuf_T));
	}
}

// Interpret son[p1] and son[p1+1]
static void lzhuf_decodesubtree_nodepair(struct lzahuf_ctx *cctx, UI p1, u64 val, UI val_nbits,
	char *b2buf, size_t b2buf_len)
{
	if(p1 >= cctx->lzhuf_T) return; // error
	lzhuf_decodesubtree_node(cctx, p1, (val<<1), val_nbits+1, b2buf, b2buf_len);
	lzhuf_decodesubtree_node(cctx, p1+1, (val<<1)|1, val_nbits+1, b2buf, b2buf_len);
}

static void lzhuf_dumptree(struct lzahuf_ctx *cctx)
{
	UI i;
	char b2buf[72];

	de_dbg(cctx->c, "R: %u", (UI)cctx->lzhuf_R);
	de_dbg(cctx->c, "T: %u", (UI)cctx->lzhuf_T);
	lzhuf_decodesubtree_node(cctx, cctx->lzhuf_R, 0, 0, b2buf, sizeof(b2buf));
	for(i=0; i<DE_ARRAYCOUNT(cctx->son); i++) {
		de_dbg(cctx->c, "son[%u]: %u", i, (UI)cctx->son[i]);
	}
}

static void lzhuf_Decode_init(struct lzahuf_ctx *cctx)
{
	UI rb_size; // LZHUF_N

	// Defaults, for standard LHarc -lh1-:
	// codes 0-255 = literals 0x00-0xff
	// codes 256-313 = match lengths 3-60
	cctx->num_special_codes = 0;
	cctx->num_length_codes = 58;
	cctx->match_length_bias = 253;
	rb_size = 4096;

	if(cctx->lh1p.is_crlzh11 || cctx->lh1p.is_crlzh20) {
		// codes 0-255 = literals 0x00-0xff
		// code 256 = "stop"
		// codes 257-314 = match lengths 3-60
		cctx->num_special_codes = 1;
		cctx->num_length_codes = 58;
		cctx->match_length_bias = 254;
		rb_size = 2048;
		if(cctx->lh1p.is_crlzh20) {
			cctx->crlzh20_style_positions = 1;
		}
	}
	else if(cctx->lh1p.is_arc_trimmed) {
		// codes 0-255 = literals 0x00-0xff
		// code 256 = "stop"
		// codes 257-313 = match lengths 3-59
		cctx->num_special_codes = 1;
		cctx->num_length_codes = 57;
		cctx->match_length_bias = 254;
	}

	cctx->lzhuf_N_CHAR = 256 + cctx->num_special_codes + cctx->num_length_codes;
	if(cctx->lzhuf_N_CHAR > LZHUF_MAX_N_CHAR) {
		cctx->errflag = 1;
		goto done;
	}
	cctx->lzhuf_T = cctx->lzhuf_N_CHAR * 2 - 1;
	cctx->lzhuf_R = cctx->lzhuf_T  - 1;

	cctx->ringbuf = de_lz77buffer_create(cctx->c, rb_size);
	cctx->ringbuf->userdata = (void*)cctx;
	cctx->ringbuf->writebyte_cb = lzah_lz77buf_writebytecb;
	if(cctx->lh1p.history_fill_val!=0) {
		de_lz77buffer_clear(cctx->ringbuf, cctx->lh1p.history_fill_val);
	}

	cctx->bbll.is_lsb = 0;
	de_bitbuf_lowlevel_empty(&cctx->bbll);

	lzhuf_StartHuff(cctx);

	if(cctx->dbg_mode) {
		lzhuf_dumptree(cctx);
	}

done:
	;
}

// Caller sets cctx->ibuf2 and ibuf2_len to refer to the new bytes to be processed.
static void lzhuf_Decode_continue(struct lzahuf_ctx *cctx, int flush)
{
	UI i, j, c;
	char pos_descr[32];

	pos_descr[0] = '\0';
	cctx->ibuf2_curpos = 0;
	if(cctx->dfctx->finished_flag) goto done;

	while(1) {
		size_t left_in_ibuf1; // # of remaining unprocessed bytes
		size_t left_in_ibuf2;

		if(cctx->errflag) goto done;
		if(lzah_have_enough_output(cctx)) {
			goto done;
		}

		left_in_ibuf1 = cctx->ibuf1_len - cctx->ibuf1_curpos;
		left_in_ibuf2 = cctx->ibuf2_len - cctx->ibuf2_curpos;
		if(!flush && left_in_ibuf1==0 && left_in_ibuf2 <= LZHUF_IBUF_LOW_WATER_MARK) {
			// Not enough bits remaining to be sure we can decode the next
			// Char+Position. Suspend operations, and wait to be called again with
			// more input bytes.
			// Save leftover bytes in cctx->ibuf1
			de_memcpy(&cctx->ibuf1, &cctx->ibuf2[cctx->ibuf2_curpos], left_in_ibuf2);
			cctx->ibuf1_len = left_in_ibuf2;
			cctx->ibuf1_curpos = 0;
			// (caller is responsible for ibuf2)

			goto done;
		}

		if(cctx->c->debug_level>=4) {
			bbll_describe_curpos(&cctx->bbll, cctx->total_nbytes_processed,
				pos_descr, sizeof(pos_descr));
		}

		c = lzhuf_DecodeChar(cctx);
		if(cctx->errflag) goto done;

		if(c==256 && cctx->num_special_codes>=1) {
			cctx->dfctx->finished_flag = 1;
			goto done;
		}
		if (c < 256) {
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)c);
		}
		else {
			// i is the distance back
			i = lzhuf_DecodePosition(cctx);
			if(cctx->errflag) goto done;

			// j is the match length
			j = c - cctx->match_length_bias;

			if(cctx->c->debug_level>=4) {
				de_dbg(cctx->c, "match @%s dist=%u len=%u", pos_descr, i, j);
			}

			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos - (UI)i - 1), j);
		}
	}

done:
	;
}
