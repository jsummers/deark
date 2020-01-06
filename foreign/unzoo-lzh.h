// This file is an edited version of the LZH decompression routine from
// unzoo.c v4.4 by Martin Schoenert.
// It has been heavily modified for Deark.

// The original file had this notice:

/*
*A  unzoo.c                     Tools                        Martin Schoenert
**
*H  @(#)$Id: unzoo.c,v 4.4 2000/05/29 08:56:57 sal Exp $
**
*Y  This file is in the Public Domain.
*/

// This file (unzoo-lzh.h) is hereby left in the public domain; or it may, at
// your option, be distributed under the same terms as the main Deark software.

struct lzh_lookuptable {
	unsigned int tablebits;
	size_t ncodes;
	size_t nlengths;
	u16 *Tab;
	u8 *Len;
};

struct lzh_table {
#define LZH_MAX_LIT     255     /* maximal literal code            */
#define LZH_MIN_LEN     3       /* minimal length of match         */
#define LZH_MAX_LEN     256     /* maximal length of match         */
#define LZH_MAX_CODE    (LZH_MAX_LIT+1 + LZH_MAX_LEN+1 - LZH_MIN_LEN)
#define LZH_BITS_CODE   9       /* 2^LZH_BITS_CODE > LZH_MAX_CODE (+1?)    */
#define LZH_MAX_OFF     8192    /* 13 bit sliding directory        */
#define LZH_MAX_LOG     13      /* maximal log_2 of offset         */
#define LZH_BITS_LOG    4       /* 2^LZH_BITS_LOG > LZH_MAX_LOG (+1?)      */
#define LZH_MAX_PRE     18      /* maximal pre code                */
#define LZH_BITS_PRE    5       /* 2^LZH_BITS_PRE > LZH_MAX_PRE (+1?)      */

	u16       TreeLeft [2*LZH_MAX_CODE+1];/* tree for codes   (upper half)   */
	u16       TreeRight[2*LZH_MAX_CODE+1];/* and  for offsets (lower half)   */

	struct lzh_lookuptable CodeTbl; /* table for fast lookup of codes  */
	struct lzh_lookuptable LogTbl; /* table for fast lookup of logs   */
	struct lzh_lookuptable PreTbl; /* table for fast lookup of pres   */
};

static void SetLookupTblLen(struct lzh_lookuptable *lookuptbl, size_t idx, u8 val)
{
	if(idx < lookuptbl->nlengths) {
		lookuptbl->Len[idx] = val;
	}
}

/****************************************************************************
**
*F  DecodeLzh() . . . . . . . . . . . . . . . extract a LZH compressed member
**
**  'DecodeLzh'  decodes  a LZH  (Lempel-Ziv 77  with dynamic Huffman coding)
**  encoded member from the archive to the output file.
**
**  Each member is encoded as a  series of blocks.  Each  block starts with a
**  16  bit field that contains the  number of codes  in this block <number>.
**  The member is terminated by a block with 0 codes.
**
**  Next each block contains the  description of three Huffman codes,  called
**  pre code, literal/length code, and log code.  The purpose of the pre code
**  is to encode the description of  the literal/length code.  The purpose of
**  the literal/length code and the  log code is   to encode the  appropriate
**  fields in the LZ code.   I am too stupid to  understand the format of the
**  description.
**
**  Then   each block contains  <number>  codewords.  There  are two kinds of
**  codewords, *literals* and *copy instructions*.
**
**  A literal represents a certain byte.  For  the moment imaging the literal
**  as having 9 bits.   The first bit  is zero, the other  8 bits contain the
**  byte.
**
**      +--+----------------+
**      | 0|     <byte>     |
**      +--+----------------+
**
**  When a  literal is  encountered, the byte  <byte> that  it represents  is
**  appended to the output.
**
**  A copy  instruction represents a certain  sequence of bytes that appeared
**  already  earlier in the output.  The  copy instruction  consists of three
**  parts, the length, the offset logarithm, and the offset mantissa.
**
**      +--+----------------+--------+--------------------+
**      | 1|   <length>-3   |  <log> |     <mantissa>     |
**      +--+----------------+--------+--------------------+
**
**  <length>  is  the  length  of the sequence   which  this copy instruction
**  represents.  We store '<length>-3', because <length> is never 0, 1, or 2;
**  such sequences are better represented by 0, 1, or  2 literals.  <log> and
**  <mantissa>  together represent the offset at  which the sequence of bytes
**  already  appeared.  '<log>-1'  is  the number of   bits in the <mantissa>
**  field, and the offset is $2^{<log>-1} + <mantissa>$.  For example
**
**      +--+----------------+--------+----------+
**      | 1|        9       |    6   | 0 1 1 0 1|
**      +--+----------------+--------+----------+
**
**  represents the sequence of 12 bytes that appeared $2^5 + 8 + 4  + 1 = 45$
**  bytes earlier in the output (so those 18 bits of input represent 12 bytes
**  of output).
**
**  When a copy instruction  is encountered, the  sequence of  <length> bytes
**  that appeared   <offset> bytes earlier  in the  output  is again appended
**  (copied) to   the output.   For this  purpose  the last  <max>  bytes are
**  remembered,  where  <max>  is the   maximal  used offset.   In 'zoo' this
**  maximal offset is $2^{13} =  8192$.  The buffer in  which those bytes are
**  remembered is  called   a sliding  window for   reasons  that  should  be
**  obvious.
**
**  To save even  more space the first 9  bits of each code, which  represent
**  the type of code and either the literal value or  the length, are encoded
**  using  a Huffman code  called the literal/length  code.   Also the next 4
**  bits in  copy instructions, which represent  the logarithm of the offset,
**  are encoded using a second Huffman code called the log code.
**
**  Those  codes  are fixed, i.e.,  not  adaptive, but  may  vary between the
**  blocks, i.e., in each block  literals/lengths and logs  may be encoded by
**  different codes.  The codes are described at the beginning of each block.
**
**  Haruhiko Okumura  wrote the  LZH code (originally for his 'ar' archiver).
*/
static int MakeTablLzh (struct lzh_table *lzhtbl, struct lzh_lookuptable *lookuptbl)
{
	u16           count[17], weight[17], start[18];
	unsigned int        i, len, ch, jutbits, avail, mask;

	de_zeromem(count, sizeof(count));
	de_zeromem(weight, sizeof(weight));
	de_zeromem(start, sizeof(start));
	for (i = 0; i < (unsigned int)lookuptbl->nlengths; i++) {
		if(lookuptbl->Len[i]<17) count[lookuptbl->Len[i]]++;
	}

	start[1] = 0;
	for (i = 1; i <= 16; i++)
		start[i + 1] = start[i] + (count[i] << (16 - i));
	if (start[17] != (u16)((unsigned int) 1 << 16))
		return 0;

	jutbits = 16 - lookuptbl->tablebits; // jutbits = either 4 or 8
	for (i = 1; i <= lookuptbl->tablebits; i++) {
		start[i] >>= jutbits;
		weight[i] = (unsigned int) 1 << (lookuptbl->tablebits - i);
	}
	while (i <= 16) {
		weight[i] = (unsigned int) 1 << (16 - i);
		i++;
	}

	i = start[lookuptbl->tablebits + 1] >> jutbits;
	if (i != (u16)((unsigned int) 1 << 16)) {
		unsigned int k;
		k = 1 << lookuptbl->tablebits;
		while (i != k) lookuptbl->Tab[i++] = 0;
	}

	avail = (unsigned int)lookuptbl->nlengths;
	mask = (unsigned int) 1 << (15 - lookuptbl->tablebits);
	for (ch = 0; ch < (unsigned int)lookuptbl->nlengths; ch++) {
		if ((len = lookuptbl->Len[ch]) == 0) continue;
		if (len <= lookuptbl->tablebits) {
			for ( i = 0; i < weight[len]; i++ ) {
				if((size_t)i+(size_t)start[len] < lookuptbl->ncodes)
					lookuptbl->Tab[i+start[len]] = ch;
			}
		}
		else {
			unsigned int k;
			// p can point into lookuptbl->Tab [len lookuptbl->ncodes]
			//    or into lzhtbl->TreeLeft  [2*LZH_MAX_CODE+1]
			//    or into lzhtbl->TreeRight [2*LZH_MAX_CODE+1]
			u16 *p;

			if(len>=18) return 0;
			k = start[len];

			if((k >> jutbits) >= lookuptbl->ncodes) return 0;
			p = &lookuptbl->Tab[k >> jutbits];

			if(lookuptbl->tablebits > len) return 0;
			i = len - lookuptbl->tablebits;

			while (i != 0) {
				if (*p == 0) {
					if(avail >= (2*LZH_MAX_CODE+1)) return 0;
					lzhtbl->TreeRight[avail] = lzhtbl->TreeLeft[avail] = 0;
					*p = avail++;
				}

				if(*p >= (2*LZH_MAX_CODE+1)) return 0;
				if (k & mask) p = &lzhtbl->TreeRight[*p];
				else          p = &lzhtbl->TreeLeft[*p];

				k <<= 1;
				i--;
			}
			*p = ch;
		}
		if(len>=17) return 0;
		start[len] += weight[len];
	}

	/* indicate success                                                    */
	return 1;
}

struct lzhctx_struct {
	deark *c;
	dbuf *inf;
	dbuf *outf;
	i64 inf_startpos;
	i64 inf_endpos;
	i64 inf_pos;
	i64 outf_nbyteswritten;
	u32 bits;           /* the bits we are looking at      */
	u32 bitc;           /* number of bits that are valid   */
	struct lzh_table lzhtbl;
	u8             BufFile [8192];         /* at least LZH_MAX_OFF   */
};

static u32 lzh_peek_bits_(struct lzhctx_struct *lzhctx, u32 n)
{
	if(n<1 || n>31 || n>lzhctx->bitc) return 0;
	return ((lzhctx->bits >> (lzhctx->bitc-n)) & ((1U<<n)-1));
}

static void lzh_flsh_bits_(struct lzhctx_struct *lzhctx, u32 n)
{
	if(n>lzhctx->bitc) return;
	lzhctx->bitc -= n;
	if (lzhctx->bitc < 16) {
		u32 x;

		if(lzhctx->inf_pos < lzhctx->inf_endpos) {
			x = (u32)dbuf_getu16be_p(lzhctx->inf, &lzhctx->inf_pos);
		}
		else {
			x = 0;
		}
		lzhctx->bits  = (lzhctx->bits<<16) + x;
		lzhctx->bitc += 16;
	}
}

static u8 BufFile_getbyte(struct lzhctx_struct *lzhctx, unsigned int idx)
{
	if(idx<LZH_MAX_OFF) return lzhctx->BufFile[idx];
	return 0;
}

static void BufFile_setbyte(struct lzhctx_struct *lzhctx, unsigned int idx, u8 n)
{
	if(idx<LZH_MAX_OFF) {
		lzhctx->BufFile[idx] = n;
	}
}

static void zoolzh_BlckWritFile(struct lzhctx_struct *lzhctx, const u8 *blk, i64 len)
{
	dbuf_write(lzhctx->outf, blk, len);
	lzhctx->outf_nbyteswritten += len;
}

static void init_lzh_lookuptable(deark *c, struct lzh_lookuptable *lookuptbl,
	unsigned int tablebits, size_t nlengths);

void de_fmtutil_decompress_zoo_lzh(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	u32 cnt;            /* number of codes in block        */
	u32 cnt2;           /* number of stuff in pre code     */
	u32 code;           /* code from the Archive           */
	u32 len;            /* length of match                 */
	u32 log_;           /* log_2 of offset of match        */
	u32 off;            /* offset of match                 */
	u32 pre;            /* pre code                        */
	unsigned int cur_idx;     // current index in BufFile
	unsigned int end_idx;     // index to the end of BufFile
	u32 i;              /* loop variable                   */
	struct lzhctx_struct *lzhctx = NULL;
	struct lzh_table *lzhtbl = NULL; // = &lzhctx->lzhtbl
	static const char *modname = "zoo-lzh";

#define LZH_PEEK_BITS(N)  lzh_peek_bits_(lzhctx, N)
#define LZH_FLSH_BITS(N)  lzh_flsh_bits_(lzhctx, N)

	lzhctx = de_malloc(c, sizeof(struct lzhctx_struct));
	lzhctx->c = c;
	lzhctx->inf = dcmpri->f;
	lzhctx->inf_startpos = dcmpri->pos;
	lzhctx->inf_pos = dcmpri->pos;
	lzhctx->inf_endpos = dcmpri->pos + dcmpri->len;
	lzhctx->outf = dcmpro->f;

	init_lzh_lookuptable(c, &lzhctx->lzhtbl.CodeTbl, 12, LZH_MAX_CODE+1);
	init_lzh_lookuptable(c, &lzhctx->lzhtbl.LogTbl, 8, LZH_MAX_LOG+1);
	init_lzh_lookuptable(c, &lzhctx->lzhtbl.PreTbl, 8, LZH_MAX_PRE+1);
	lzhtbl = &lzhctx->lzhtbl;

	/* initialize bit source, output pointer, and crc                      */
	lzhctx->bits = 0;  lzhctx->bitc = 0;  LZH_FLSH_BITS(0);
	cur_idx = 0;
	end_idx = LZH_MAX_OFF;

	/* loop until all blocks have been read                                */
	cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	while ( cnt != 0 ) {
		if(lzhctx->outf_nbyteswritten >= dcmpro->expected_len) break;

		/* read the pre code                                               */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_PRE );  LZH_FLSH_BITS( LZH_BITS_PRE );
		if ( cnt2 == 0 ) {
			pre = LZH_PEEK_BITS( LZH_BITS_PRE );  LZH_FLSH_BITS( LZH_BITS_PRE );
			for ( i = 0; i <      256; i++ )  lzhtbl->PreTbl.Tab[i] = pre;
			for ( i = 0; i <= LZH_MAX_PRE; i++ )  lzhtbl->PreTbl.Len[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = LZH_PEEK_BITS( 3 );  LZH_FLSH_BITS( 3 );
				if ( len == 7 ) {
					while ( LZH_PEEK_BITS( 1 ) ) { len++; LZH_FLSH_BITS( 1 ); }
					LZH_FLSH_BITS( 1 );
				}
				SetLookupTblLen(&lzhtbl->PreTbl, i++, len);
				if ( i == 3 ) {
					len = LZH_PEEK_BITS( 2 );  LZH_FLSH_BITS( 2 );
					while ( 0 < len-- )  SetLookupTblLen(&lzhtbl->PreTbl, i++, 0);
				}
			}
			while ( i <= LZH_MAX_PRE )  lzhtbl->PreTbl.Len[i++] = 0;
			if ( ! MakeTablLzh(lzhtbl, &lzhtbl->PreTbl) ) {
				de_dfilter_set_errorf(c, dres, modname, "Pre code description corrupted");
				goto done;
			}
		}

		/* read the code (using the pre code)                              */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_CODE );  LZH_FLSH_BITS( LZH_BITS_CODE );
		if ( cnt2 == 0 ) {
			code = LZH_PEEK_BITS( LZH_BITS_CODE );  LZH_FLSH_BITS( LZH_BITS_CODE );
			for ( i = 0; i <      4096; i++ )  lzhtbl->CodeTbl.Tab[i] = code;
			for ( i = 0; i <= LZH_MAX_CODE; i++ )  lzhtbl->CodeTbl.Len[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = lzhtbl->PreTbl.Tab[ LZH_PEEK_BITS( 8 ) ];
				if ( len <= LZH_MAX_PRE ) {
					LZH_FLSH_BITS( lzhtbl->PreTbl.Len[len] );
				}
				else {
					LZH_FLSH_BITS( 8 );
					do {
						if ( LZH_PEEK_BITS( 1 ) )  len = lzhtbl->TreeRight[len];
						else                   len = lzhtbl->TreeLeft [len];
						LZH_FLSH_BITS( 1 );
					} while ( LZH_MAX_PRE < len );
				}
				if ( len <= 2 ) {
					if      ( len == 0 ) {
						len = 1;
					}
					else if ( len == 1 ) {
						len = LZH_PEEK_BITS(4)+3;  LZH_FLSH_BITS(4);
					}
					else {
						len = LZH_PEEK_BITS(LZH_BITS_CODE)+20; LZH_FLSH_BITS(LZH_BITS_CODE);
					}
					while ( 0 < len-- ) {
						SetLookupTblLen(&lzhtbl->CodeTbl, i++, 0);
					}
				}
				else {
					SetLookupTblLen(&lzhtbl->CodeTbl, i++, len - 2);
				}
			}
			while ( i <= LZH_MAX_CODE )  lzhtbl->CodeTbl.Len[i++] = 0;
			if ( ! MakeTablLzh(lzhtbl, &lzhtbl->CodeTbl) ) {
				de_dfilter_set_errorf(c, dres, modname, "Literal/length code description corrupted");
				goto done;
			}
		}

		/* read the log_2 of offsets                                       */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_LOG );  LZH_FLSH_BITS( LZH_BITS_LOG );
		if ( cnt2 == 0 ) {
			log_ = LZH_PEEK_BITS( LZH_BITS_LOG );  LZH_FLSH_BITS( LZH_BITS_LOG );
			for ( i = 0; i <      256; i++ )  lzhtbl->LogTbl.Tab[i] = log_;
			for ( i = 0; i <= LZH_MAX_LOG; i++ )  lzhtbl->LogTbl.Len[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = LZH_PEEK_BITS( 3 );  LZH_FLSH_BITS( 3 );
				if ( len == 7 ) {
					while ( LZH_PEEK_BITS( 1 ) ) { len++; LZH_FLSH_BITS( 1 ); }
					LZH_FLSH_BITS( 1 );
				}
				SetLookupTblLen(&lzhtbl->LogTbl, i++, len);
			}
			while ( i <= LZH_MAX_LOG )  lzhtbl->LogTbl.Len[i++] = 0;
			if ( ! MakeTablLzh(lzhtbl, &lzhtbl->LogTbl) ) {
				de_dfilter_set_errorf(c, dres, modname, "Log code description corrupted");
				goto done;
			}
		}

		/* read the codes                                                  */
		while ( 0 < cnt-- ) {

			/* try to decode the code the fast way                         */
			code = lzhtbl->CodeTbl.Tab[ LZH_PEEK_BITS( 12 ) ];

			/* if this code needs more than 12 bits look it up in the tree */
			if ( code <= LZH_MAX_CODE ) {
				LZH_FLSH_BITS( lzhtbl->CodeTbl.Len[code] );
			}
			else {
				LZH_FLSH_BITS( 12 );
				do {
					if ( LZH_PEEK_BITS( 1 ) )  code = lzhtbl->TreeRight[code];
					else                   code = lzhtbl->TreeLeft [code];
					LZH_FLSH_BITS( 1 );
				} while ( LZH_MAX_CODE < code );
			}

			/* if the code is a literal, stuff it into the buffer          */
			if ( code <= LZH_MAX_LIT ) {
				BufFile_setbyte(lzhctx, cur_idx++, code);
				if ( cur_idx == end_idx ) {
					zoolzh_BlckWritFile(lzhctx, lzhctx->BufFile, cur_idx);
					cur_idx = 0;
				}
			}

			/* otherwise compute match length and offset and copy          */
			else {
				unsigned int pos_idx;     // index of match

				len = code - (LZH_MAX_LIT+1) + LZH_MIN_LEN;

				/* try to decodes the log_2 of the offset the fast way     */
				log_ = lzhtbl->LogTbl.Tab[ LZH_PEEK_BITS( 8 ) ];
				/* if this log_2 needs more than 8 bits look in the tree   */
				if ( log_ <= LZH_MAX_LOG ) {
					LZH_FLSH_BITS( lzhtbl->LogTbl.Len[log_] );
				}
				else {
					LZH_FLSH_BITS( 8 );
					do {
						if ( LZH_PEEK_BITS( 1 ) )  log_ = lzhtbl->TreeRight[log_];
						else                   log_ = lzhtbl->TreeLeft [log_];
						LZH_FLSH_BITS( 1 );
					} while ( LZH_MAX_LOG < log_ );
				}

				/* compute the offset                                      */
				if ( log_ == 0 ) {
					off = 0;
				}
				else {
					off = ((unsigned int)1 << (log_-1)) + LZH_PEEK_BITS( log_-1 );
					LZH_FLSH_BITS( log_-1 );
				}

				/* copy the match (this accounts for ~ 50% of the time)    */
				pos_idx = ((cur_idx - off - 1) & (LZH_MAX_OFF - 1));
				if ( cur_idx < end_idx-len && pos_idx < end_idx-len ) {
					unsigned int stp_idx;     // stop index during copy
					stp_idx = cur_idx + len;
					do {
						code = BufFile_getbyte(lzhctx, pos_idx++);
						BufFile_setbyte(lzhctx, cur_idx++, code);
					} while ( cur_idx < stp_idx );
				}
				else {
					while ( 0 < len-- ) {
						code = BufFile_getbyte(lzhctx, pos_idx++);
						BufFile_setbyte(lzhctx, cur_idx++, code);
						if ( pos_idx == end_idx ) {
							pos_idx = 0;
						}
						if ( cur_idx == end_idx ) {
							zoolzh_BlckWritFile(lzhctx, lzhctx->BufFile, cur_idx);
							cur_idx = 0;
						}
					}
				}
			}
		}

		cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	}

	/* write out the rest of the buffer                                    */
	if(cur_idx>=LZH_MAX_OFF) {
		de_dfilter_set_generic_error(c, dres, modname);
		goto done;
	}
	zoolzh_BlckWritFile(lzhctx, lzhctx->BufFile, cur_idx);

done:
	if(lzhctx) {
		de_free(c, lzhctx->lzhtbl.CodeTbl.Tab);
		de_free(c, lzhctx->lzhtbl.CodeTbl.Len);
		de_free(c, lzhctx->lzhtbl.LogTbl.Tab);
		de_free(c, lzhctx->lzhtbl.LogTbl.Len);
		de_free(c, lzhctx->lzhtbl.PreTbl.Tab);
		de_free(c, lzhctx->lzhtbl.PreTbl.Len);
		de_free(c, lzhctx);
	}
}

static void init_lzh_lookuptable(deark *c, struct lzh_lookuptable *lookuptbl,
	unsigned int tablebits, size_t nlengths)
{
	lookuptbl->tablebits = tablebits;
	lookuptbl->ncodes = ((size_t)1)<<lookuptbl->tablebits;
	lookuptbl->nlengths = nlengths;
	lookuptbl->Tab = de_mallocarray(c, (i64)lookuptbl->ncodes, sizeof(u16));
	lookuptbl->Len = de_malloc(c, lookuptbl->nlengths);
}
