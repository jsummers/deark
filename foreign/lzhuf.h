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
	UI dpparam_dcode_shift;
	UI dpparam_dlen_bias;
	UI dpparam_mask;

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

static UI lzhuf_getbits(struct lzahuf_ctx *cctx, UI nbits)
{
	if(cctx->bbll.nbits_in_bitbuf < nbits) {
		cctx->errflag = 1;
		return 0;
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
		UI srcidx, dstidx;

		k = i + 1;
		set_freq(cctx, j, get_freq(cctx, i) + get_freq(cctx, k));
		f = get_freq(cctx, j);

		k = j - 1;
		while(f < get_freq(cctx, k)) {
			k--;
		}

		k++;

		l = (j - k);
		srcidx = k;
		dstidx = k + 1;

		if((l > (UI)DE_ARRAYCOUNT(cctx->freq)) ||
			(srcidx+l > (UI)DE_ARRAYCOUNT(cctx->freq)) ||
			(dstidx+l > (UI)DE_ARRAYCOUNT(cctx->freq)))
		{
			cctx->errflag = 1;
			return;
		}

		de_memmove(&cctx->freq[dstidx], &cctx->freq[srcidx], l*sizeof(cctx->freq[0]));
		set_freq(cctx, k, f);

		if((l > (UI)DE_ARRAYCOUNT(cctx->son)) ||
			(srcidx+l > (UI)DE_ARRAYCOUNT(cctx->son)) ||
			(dstidx+l > (UI)DE_ARRAYCOUNT(cctx->son)))
		{
			cctx->errflag = 1;
			return;
		}

		de_memmove(&cctx->son[dstidx], &cctx->son[srcidx], l*sizeof(cctx->son[0]));
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

	c = get_son(cctx, cctx->lzhuf_R);

	/* travel from root to leaf, */
	/* choosing the smaller child node (son[]) if the read bit is 0, */
	/* the bigger (son[]+1) if 1 */
	while (c < cctx->lzhuf_T) {
		c += lzhuf_getbits(cctx, 1);
		// There will never be more than 64 bits available, so a hypothetical
		// infinite loop would be caught here.
		if(cctx->errflag) return 0;
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
	if(cctx->errflag) return 0;
	fmtutil_get_lzhuf_d_code_and_len(i, &d_code, &d_len);
	c = d_code << cctx->dpparam_dcode_shift;

	/* read lower bits verbatim */
	j = d_len - cctx->dpparam_dlen_bias;
	i = (i<<j) | lzhuf_getbits(cctx, j);
	if(cctx->errflag) return 0;
	i &= cctx->dpparam_mask;
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
	cctx->dpparam_dcode_shift = 6;
	cctx->dpparam_dlen_bias = 2;
	cctx->dpparam_mask = 0x3f;
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
			cctx->dpparam_dcode_shift = 5;
			cctx->dpparam_dlen_bias = 3;
			cctx->dpparam_mask = 0x1f;
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
	else if(cctx->lh1p.is_dms_deep) {
		rb_size = 16*1024;
		cctx->dpparam_dcode_shift = 8;
		cctx->dpparam_dlen_bias = 0;
		cctx->dpparam_mask = 0xff;
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

static void lzhuf_Decode_continue(struct lzahuf_ctx *cctx, const u8 *buf, i64 buf_len, int flush)
{
	UI i, j, c;
	i64 bufpos = 0;
	char pos_descr[32];

	pos_descr[0] = '\0';
	if(cctx->dfctx->finished_flag) goto done;

	while(1) {
		if(cctx->errflag) goto done;
		if(lzah_have_enough_output(cctx)) {
			goto done;
		}

		// We're relying on the assumption that a compression instruction can
		// never be more than 57 bits in size.
		// The Huffman-encoded "character" maxes out, I think, at around 15 or
		// 16 bits -- this follows indirectly from MAX_FREQ, which reduces the
		// tree depth perdiodically.
		// For a "match" instruction, an 8-bit code is then read.
		// Then, some additional bits are read -- the most possible for the
		// supported formats is 8, for DMS-Deep.
		// So, about 16+8+8 = 32 bits should be sufficient.

		// Top off the bitbuf, if possible.
		while(bufpos<buf_len && cctx->bbll.nbits_in_bitbuf<=(64-8)) {
			de_bitbuf_lowlevel_add_byte(&cctx->bbll, buf[bufpos++]);
			cctx->total_nbytes_processed++;
		}

		if(!flush && cctx->bbll.nbits_in_bitbuf<=(64-8)) {
			// Wait for more data before trying to continue
			goto done;
		}

		if(cctx->c->debug_level>=4) {
			de_bitbuf_describe_curpos(&cctx->bbll,
				cctx->dfctx->input_file_offset+cctx->total_nbytes_processed,
				pos_descr, sizeof(pos_descr));
		}

		c = lzhuf_DecodeChar(cctx);
		if(cctx->errflag) goto done;

		if(c==256 && cctx->num_special_codes>=1) {
			if(cctx->c->debug_level>=4) {
				de_dbg(cctx->c, "special @%s =%u", pos_descr, c);
			}
			cctx->dfctx->finished_flag = 1;
			goto done;
		}
		if (c < 256) {
			if(cctx->c->debug_level>=4) {
				de_dbg(cctx->c, "lit @%s =%u", pos_descr, c);
			}
			de_lz77buffer_add_literal_byte(cctx->ringbuf, (u8)c);
		}
		else {
			// i is the distance back
			i = lzhuf_DecodePosition(cctx);
			if(cctx->errflag) goto done;

			// j is the match length
			j = c - cctx->match_length_bias;

			if(cctx->c->debug_level>=4) {
				de_dbg(cctx->c, "match @%s dist=%u len=%u", pos_descr, i+1, j);
			}

			de_lz77buffer_copy_from_hist(cctx->ringbuf,
				(UI)(cctx->ringbuf->curpos - (UI)i - 1), j);
		}
	}

done:
	if(!cctx->dfctx->finished_flag && !cctx->errflag) {
		if(bufpos<buf_len) {
			// It shouldn't be possible to get here. If we do, it means some input
			// bytes will be lost.
			de_dfilter_set_generic_error(cctx->dfctx->c, cctx->dres, cctx->modname);
			cctx->errflag = 1;
		}
	}
}
