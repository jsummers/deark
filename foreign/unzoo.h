// This file is an edited version of unzoo.c v4.4 by Martin Schoenert.
// It has been heavily modified for Deark, with unneeded portions removed.

// This file (unzoo.h) is hereby left in the public domain; or it may, at your
// option, be distributed under the same terms as the main Deark software.

// Selected comments from the original unzoo.c:

/****************************************************************************
**
*A  unzoo.c                     Tools                        Martin Schoenert
**
*H  @(#)$Id: unzoo.c,v 4.4 2000/05/29 08:56:57 sal Exp $
**
*Y  This file is in the Public Domain.

...

**  'unzoo'  is based heavily on the 'booz' archive extractor by Rahul Dhesi.
**  I basically stuffed everything in one file (so  no 'Makefile' is needed),
**  cleaned it up (so that it is now more portable and  a little bit faster),
**  and added the  support for  long file names,  directories,  and comments.

...

**  'unzoo' cannot handle  members compressed with  the old method, only with
**  the new  high method or  not compressed  at all.   'zoo' and  'booz' also
**  handle members compress with the old method.

...

**  ACKNOWLEDGMENTS
**
**  Rahul Dhesi  wrote the  'zoo' archiver and the  'booz' archive extractor.
**  Haruhiko Okumura  wrote the  LZH code (originally for his 'ar' archiver).
**  David Schwaderer provided the CRC-16 calculation in PC Tech Journal 4/85.
**  Jeff Damens  wrote the name match code in 'booz' (originally for Kermit).
**  Harald Boegeholz  ported 'unzoo' to OS/2 with the emx development system.
**  Dave Bayer ported 'unzoo' to the Macintosh,  including Macbinary support.

*/


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

	de_uint16       TreeLeft [2*LZH_MAX_CODE+1];/* tree for codes   (upper half)   */
	de_uint16       TreeRight[2*LZH_MAX_CODE+1];/* and  for offsets (lower half)   */
	de_uint16       TabCode  [4096];        /* table for fast lookup of codes  */
	de_byte         LenCode  [LZH_MAX_CODE+1];  /* number of bits used for code    */
	de_uint16       TabLog   [256];         /* table for fast lookup of logs   */
	de_byte         LenLog   [LZH_MAX_LOG+1];   /* number of bits used for logs    */
	de_uint16       TabPre   [256];         /* table for fast lookup of pres   */
	de_byte         LenPre   [LZH_MAX_PRE+1];   /* number of bits used for pres    */
};

// Data associated with one ZOO file Entry
struct entryctx {
	de_finfo *fi;
	dbuf *WritBinr;
	de_uint16 Crc;

	// Original "Entry":
	de_uint32           magic;          /* magic word 0xfdc4a7dc           */
	de_byte             type;           /* type of current member (1)      */
	de_byte             method;         /* packing method of member (0..2) */
	de_uint32           posnxt;         /* position of next member         */
	de_uint32           posdat;         /* position of data                */
	de_uint16           datdos;         /* date (in DOS format)            */
	de_uint16           timdos;         /* time (in DOS format)            */
	de_uint16           crcdat;         /* crc value of member             */
	de_uint32           sizorg;         /* uncompressed size of member     */
	de_uint32           siznow;         /*   compressed size of member     */
	de_byte             majver;         /* major version needed to extract */
	de_byte             minver;         /* minor version needed to extract */
	de_byte             delete_;        /* 1 if member is deleted, 0 else  */
	de_byte             spared;         /* spare entry to pad entry        */
	de_uint32           poscmt;         /* position of comment, 0 if none  */
	de_uint16           sizcmt;         /* length   of comment, 0 if none  */
	char                nams [14];      /* short name of member or archive */
	de_uint16           lvar;           /* length of variable part         */
	de_byte             timzon;         /* time zone                       */
	de_uint16           crcent;         /* crc value of entry              */
	de_byte             lnamu;          /* length of long name             */
	de_byte             ldiru;          /* length of directory             */
	char                namu [256];     /* univ. name of member of archive */
	char                diru [256];     /* univ. name of directory         */
	de_uint16           system;         /* system identifier               */
	de_uint32           permis;         /* file permissions                */
	de_byte             modgen;         /* gens. on, last gen., gen. limit */
	de_uint16           ver;            /* version number of member        */

	struct lzh_table lzhtbl;

	de_byte             BufFile [8192];         /* at least LZH_MAX_OFF   */
};

struct unzooctx {
	deark *c;
	dbuf *ReadArch;
	de_int64 ReadArch_fpos;

	// Original "Descript":
	char                text[21];       /* "ZOO 2.10 Archive.<ctr>Z"       */
	de_uint32           magic;          /* magic word 0xfdc4a7dc           */
	de_uint32           posent;         /* position of first directory ent.*/
	de_uint32           klhvmh;         /* two's complement of posent      */
	de_byte             majver;         /* major version needed to extract */
	de_byte             minver;         /* minor version needed to extract */
	de_byte             type;           /* type of current member (0,1)    */
	de_uint32           poscmt;         /* position of comment, 0 if none  */
	de_uint16           sizcmt;         /* length   of comment, 0 if none  */
	de_byte             modgen;         /* gens. on, gen. limit            */
	/* the following are not in the archive file and are computed          */
	de_uint32           sizorg;         /* uncompressed size of members    */
	de_uint32           siznow;         /*   compressed size of members    */
	de_uint32           number;         /* number of members               */

	/****************************************************************************
	**
	*V  ErrMsg  . . . . . . . . . . . . . . . . . . . . . . . . . . error message
	**
	**  'ErrMsg' is used by the  decode functions to communicate  the cause of an
	**  error to the calling function.
	*/
	char *          ErrMsg;

	de_uint16   CrcTab [256];
};

static int GotoReadArch (struct unzooctx *uz, de_int64 pos)
{
	uz->ReadArch_fpos = pos;
	return 1;
}

static int ByteReadArch(struct unzooctx *uz)
{
	de_byte ch;
	ch = dbuf_getbyte(uz->ReadArch, uz->ReadArch_fpos);
	uz->ReadArch_fpos++;
	return (int)ch;
}

static de_uint32 HalfReadArch (struct unzooctx *uz)
{
	de_uint32       result;
	result  = ((de_uint32)ByteReadArch(uz));
	result += ((de_uint32)ByteReadArch(uz)) << 8;
	return result;
}

static de_uint32 FlahReadArch (struct unzooctx *uz)
{
	de_uint32       result;
	result  = ((de_uint32)ByteReadArch(uz)) << 8;
	result += ((de_uint32)ByteReadArch(uz));
	return result;
}

static de_uint32 TripReadArch (struct unzooctx *uz)
{
	de_uint32       result;
	result  = ((de_uint32)ByteReadArch(uz));
	result += ((de_uint32)ByteReadArch(uz)) << 8;
	result += ((de_uint32)ByteReadArch(uz)) << 16;
	return result;
}

static de_uint32   WordReadArch (struct unzooctx *uz)
{
	de_uint32       result;
	result  = ((de_uint32)ByteReadArch(uz));
	result += ((de_uint32)ByteReadArch(uz)) << 8;
	result += ((de_uint32)ByteReadArch(uz)) << 16;
	result += ((de_uint32)ByteReadArch(uz)) << 24;
	return result;
}

static de_uint32 BlckReadArch (struct unzooctx *uz, de_byte *blk, de_uint32 len )
{
	int                 ch;             /* character read                  */
	de_uint32       i;              /* loop variable                   */
	for ( i = 0; i < len; i++ ) {
		if ( (ch = ByteReadArch(uz)) == EOF )
			return i;
		else
			*blk++ = ch;
	}
	return len;
}

static int DescReadArch (struct unzooctx *uz)
{
	deark *c = uz->c;
	int retval = 0;

	de_dbg(c, "header at %d\n", 0);
	de_dbg_indent(c, 1);

	/* read the text at the beginning                                      */
	BlckReadArch(uz, (de_byte*)uz->text, 20L);  uz->text[20] = '\0';

	/* try to read the magic words                                         */
	if ( (uz->magic = WordReadArch(uz)) != (de_uint32)0xfdc4a7dcL ) {
		goto done;
	}

	/* read the old part of the description                                */
	uz->posent = WordReadArch(uz);
	de_dbg(c, "first entry offset: %d\n", (int)uz->posent);

	uz->klhvmh = WordReadArch(uz);
	uz->majver = ByteReadArch(uz);
	uz->minver = ByteReadArch(uz);
	de_dbg(c, "version: %d.%d\n", (int)uz->majver, (int)uz->minver);

	/* read the new part of the description if present                     */
	uz->type   = (34 < uz->posent ? ByteReadArch(uz) : 0);
	uz->poscmt = (34 < uz->posent ? WordReadArch(uz) : 0);
	uz->sizcmt = (34 < uz->posent ? HalfReadArch(uz) : 0);
	uz->modgen = (34 < uz->posent ? ByteReadArch(uz) : 0);

	/* initialize the fake entries                                         */
	uz->sizorg = 0;
	uz->siznow = 0;
	uz->number = 0;

	retval = 1;

	/* indicate success                                                    */
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int EntrReadArch (struct unzooctx *uz, struct entryctx *ze)
{
	de_uint32           l;              /* 'Entry.lnamu+Entry.ldiru'       */
	deark *c = uz->c;
	de_ucstring *shortname_ucstring = NULL;
	de_ucstring *longname_ucstring = NULL;
	de_ucstring *dirname_ucstring = NULL;
	de_ucstring *fullname_ucstring = NULL;
	int retval = 0;
	de_int64 pos1 = uz->ReadArch_fpos;

	/* try to read the magic words                                         */
	if ( (ze->magic = WordReadArch(uz)) != (de_uint32)0xfdc4a7dcL ) {
		de_err(c, "Malformed ZOO file, bad magic number at %d\n", (int)pos1);
		goto done;
	}

	/* read the fixed part of the directory entry                          */
	ze->type   = ByteReadArch(uz);
	de_dbg(c, "type: %d\n", (int)ze->type);
	ze->method = ByteReadArch(uz);
	de_dbg(c, "compression method: %d\n", (int)ze->method);
	ze->posnxt = WordReadArch(uz);
	de_dbg(c, "next entry pos: %d\n", (int)ze->posnxt);
	ze->posdat = WordReadArch(uz);
	de_dbg(c, "pos of file data: %u\n", (unsigned int)ze->posdat);
	ze->datdos = HalfReadArch(uz);
	ze->timdos = HalfReadArch(uz);
	ze->crcdat = HalfReadArch(uz);
	de_dbg(c, "reported file crc: 0x%04x\n", (unsigned int)ze->crcdat);
	ze->sizorg = WordReadArch(uz);
	de_dbg(c, "original size: %u\n", (unsigned int)ze->sizorg);
	ze->siznow = WordReadArch(uz);
	de_dbg(c, "compressed size: %u\n", (unsigned int)ze->siznow);
	ze->majver = ByteReadArch(uz);
	ze->minver = ByteReadArch(uz);
	de_dbg(c, "version: %d.%d\n", (int)ze->majver, (int)ze->minver);
	ze->delete_ = ByteReadArch(uz);
	ze->spared = ByteReadArch(uz);
	ze->poscmt = WordReadArch(uz);
	ze->sizcmt = HalfReadArch(uz);
	// TODO: Read comment

	BlckReadArch(uz, (de_byte*)ze->nams, 13L);  ze->nams[13] = '\0';
	shortname_ucstring = ucstring_create(c);
	ucstring_append_bytes(shortname_ucstring, (const de_byte*)ze->nams, sizeof(ze->nams),
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "short name: \"%s\"\n", ucstring_get_printable_sz(shortname_ucstring));

	/* handle the long name and the directory in the variable part         */
	ze->lvar   = (ze->type == 2  ? HalfReadArch(uz) : 0);
	ze->timzon = (ze->type == 2  ? ByteReadArch(uz) : 127);
	ze->crcent = (ze->type == 2  ? HalfReadArch(uz) : 0);
	ze->lnamu  = (0 < ze->lvar   ? ByteReadArch(uz) : 0);
	ze->ldiru  = (1 < ze->lvar   ? ByteReadArch(uz) : 0);

	BlckReadArch(uz, (de_byte*)ze->namu, (de_uint32)ze->lnamu);
	ze->namu[ze->lnamu] = '\0';
	longname_ucstring = ucstring_create(c);
	if(ze->lnamu>0) {
		ucstring_append_bytes(longname_ucstring, (const de_byte*)ze->namu, sizeof(ze->namu),
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "long name: \"%s\"\n", ucstring_get_printable_sz(longname_ucstring));
	}

	BlckReadArch(uz, (de_byte*)ze->diru, (de_uint32)ze->ldiru);
	ze->diru[ze->ldiru] = '\0';
	dirname_ucstring = ucstring_create(c);
	if(ze->ldiru>0) {
		ucstring_append_bytes(dirname_ucstring, (const de_byte*)ze->diru, sizeof(ze->diru),
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "dir name: \"%s\"\n", ucstring_get_printable_sz(dirname_ucstring));
	}

	l = ze->lnamu + ze->ldiru;
	ze->system = (l+2 < ze->lvar ? HalfReadArch(uz) : 0);

	ze->permis = (l+4 < ze->lvar ? TripReadArch(uz) : 0);
	if(l+4 < ze->lvar) {
		de_dbg(c, "perms: octal(%o)\n", (unsigned int)ze->permis);
		if((ze->permis & 0111) != 0) {
			ze->fi->is_executable = 1;
		}
	}

	ze->modgen = (l+7 < ze->lvar ? ByteReadArch(uz) : 0);
	ze->ver    = (l+7 < ze->lvar ? HalfReadArch(uz) : 0);

	// Figure out the best filename to use
	if(longname_ucstring->len>0 || shortname_ucstring->len) {
		fullname_ucstring = ucstring_create(c);

		if(dirname_ucstring->len>0) {
			ucstring_append_ucstring(fullname_ucstring, dirname_ucstring);
			ucstring_append_sz(fullname_ucstring, "/", DE_ENCODING_ASCII);
		}
		if(longname_ucstring->len>0) {
			ucstring_append_ucstring(fullname_ucstring, longname_ucstring);
		}
		else if(shortname_ucstring->len>0) {
			ucstring_append_ucstring(fullname_ucstring, shortname_ucstring);
		}

		de_finfo_set_name_from_ucstring(c, ze->fi, fullname_ucstring);
		ze->fi->original_filename_flag = 1;
	}

	retval = 1;

done:
	ucstring_destroy(shortname_ucstring);
	ucstring_destroy(longname_ucstring);
	ucstring_destroy(dirname_ucstring);
	ucstring_destroy(fullname_ucstring);
	return retval;
}

/****************************************************************************
**
*F  OpenWritFile(<patl>,<bin>)  . . . . . . . . . . . open a file for writing
*F  ClosWritFile()  . . . . . . . . . . . . . . . . . . .  close a file again
*F  BlckWritFile(<blk>,<len>) . . . . . . .  write a block of bytes to a file
**
**  'OpenWritFile' tries to open the archive  with local path name <patl> (as
**  converted by 'CONV_NAME'  and 'CONV_DIRE') for writing  and returns  1 to
**  indicate success  and 0 to indicate  that the file cannot  be opened.  If
**  <bin> is  0, the file  is opened as a text   file, otherwise the  file is
**  opened as a binary file.
**
**  'ClosWritFile' closes the file again.
**
**  'BlckWritFile' writes <len>  bytes from the  buffer <blk> to the file and
**  returns the number  of bytes actually written,  which is less than  <len>
**  only when a write error happened.  If no file is open 'BlckWritFile' only
**  returns <len>.
*/
static int OpenWritFile(struct unzooctx *uz, struct entryctx *ze)
{
	const char *ext;
	if(ze->WritBinr) return 1;

	if(ze->fi && ze->fi->original_filename_flag) {
		ext = NULL;
	}
	else {
		ext = "bin";
	}

	ze->WritBinr = dbuf_create_output_file(uz->c, ext, ze->fi, 0);
	return 1;
}

static int ClosWritFile (struct unzooctx *uz, struct entryctx *ze)
{
	if(!ze->WritBinr) return 0;
	dbuf_close(ze->WritBinr);
	ze->WritBinr = NULL;
	return 1;
}

static de_int64 BlckWritFile (struct unzooctx *uz, struct entryctx *ze, const de_byte *blk, de_int64 len )
{
	if(!ze->WritBinr) return 0;
	dbuf_write(ze->WritBinr, blk, len);
	return len;
}

static de_uint16 CRC_BYTE(struct unzooctx *uz, de_uint16 crc, de_byte byte)
{
	return (((crc)>>8) ^ uz->CrcTab[ ((crc)^(byte))&0xff ]);
}

static int InitCrc (struct unzooctx *uz)
{
	de_uint32       i, k;           /* loop variables                  */
	for ( i = 0; i < 256; i++ ) {
		uz->CrcTab[i] = i;
		for ( k = 0; k < 8; k++ )
			uz->CrcTab[i] = (uz->CrcTab[i]>>1) ^ ((uz->CrcTab[i] & 1) ? 0xa001 : 0);
	}
	return 1;
}

/****************************************************************************
**
*F  DecodeCopy(<size>). . . . . . . . . . . .  extract an uncompressed member
**
**  'DecodeCopy' simply  copies <size> bytes  from the  archive to the output
**  file.
*/
static int DecodeCopy (struct unzooctx *uz, struct entryctx *ze, de_uint32 size )
{
	de_uint32       siz;            /* size of current block           */
	de_uint32       crc;            /* CRC-16 value                    */
	de_uint32       i;              /* loop variable                   */

	/* initialize the crc value                                            */
	crc = 0;

	/* loop until everything has been copied                               */
	while ( 0 < size ) {

		/* read as many bytes as possible in one go                        */
		siz = (sizeof(ze->BufFile) < size ? sizeof(ze->BufFile) : size);
		if ( BlckReadArch(uz, ze->BufFile, siz ) != siz ) {
			uz->ErrMsg = "Unexpected <eof> in the archive";
			return 0;
		}

		/* write them                                                      */
		if ( BlckWritFile(uz, ze, ze->BufFile, siz ) != siz ) {
			uz->ErrMsg = "Cannot write output file";
			return 0;
		}

		/* compute the crc                                                 */
		for ( i = 0; i < siz; i++ )
			crc = CRC_BYTE(uz, crc, ze->BufFile[i] );

		/* on to the next block                                            */
		size -= siz;
	}

	/* store the crc and indicate success                                  */
	ze->Crc = crc;
	return 1;
}

// Forward declaration of a function in zoo-lzd.h
static int lzd(struct unzooctx *uz, struct entryctx *ze);

/****************************************************************************
**
*F  DecodeLzd() . . . . . . . . . . . . . . .  extract a LZ compressed member
**
*/
static int DecodeLzd (struct unzooctx *uz, struct entryctx *ze)
{
	return !lzd(uz, ze);
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
static int MakeTablLzh (struct unzooctx *uz, struct entryctx *ze,
	int                 nchar,
	de_byte             bitlen[],
	int                 tablebits,
	de_uint16           table[])
{
	de_uint16           count[17], weight[17], start[18], *p;
	unsigned int        i, k, len, ch, jutbits, avail, mask;
	struct lzh_table *lzhtbl = &ze->lzhtbl;

	for (i = 1; i <= 16; i++) count[i] = 0;
	for (i = 0; i < (unsigned int)nchar; i++) count[bitlen[i]]++;

	start[1] = 0;
	for (i = 1; i <= 16; i++)
		start[i + 1] = start[i] + (count[i] << (16 - i));
	if (start[17] != (de_uint16)((unsigned) 1 << 16))
		return 0;

	jutbits = 16 - tablebits;
	for (i = 1; i <= (unsigned int)tablebits; i++) {
		start[i] >>= jutbits;
		weight[i] = (unsigned) 1 << (tablebits - i);
	}
	while (i <= 16) {
		weight[i] = (unsigned) 1 << (16 - i);
		i++;
	}

	i = start[tablebits + 1] >> jutbits;
	if (i != (de_uint16)((unsigned) 1 << 16)) {
		k = 1 << tablebits;
		while (i != k) table[i++] = 0;
	}

	avail = nchar;
	mask = (unsigned) 1 << (15 - tablebits);
	for (ch = 0; ch < (unsigned int)nchar; ch++) {
		if ((len = bitlen[ch]) == 0) continue;
		if (len <= (unsigned int)tablebits) {
			for ( i = 0; i < weight[len]; i++ )  table[i+start[len]] = ch;
		}
		else {
			k = start[len];
			p = &table[k >> jutbits];
			i = len - tablebits;
			while (i != 0) {
				if (*p == 0) {
					lzhtbl->TreeRight[avail] = lzhtbl->TreeLeft[avail] = 0;
					*p = avail++;
				}
				if (k & mask) p = &lzhtbl->TreeRight[*p];
				else          p = &lzhtbl->TreeLeft[*p];
				k <<= 1;  i--;
			}
			*p = ch;
		}
		start[len] += weight[len];
	}

	/* indicate success                                                    */
	return 1;
}

static int DecodeLzh (struct unzooctx *uz, struct entryctx *ze)
{
	de_uint32 cnt;            /* number of codes in block        */
	de_uint32 cnt2;           /* number of stuff in pre code     */
	de_uint32 code;           /* code from the Archive           */
	de_uint32 len;            /* length of match                 */
	de_uint32 log;            /* log_2 of offset of match        */
	de_uint32 off;            /* offset of match                 */
	de_uint32 pre;            /* pre code                        */
	de_byte *    cur;            /* current position in BufFile     */
	de_byte *    pos;            /* position of match               */
	de_byte *    end;            /* pointer to the end of BufFile   */
	de_byte *    stp;            /* stop pointer during copy        */
	de_uint32 crc;            /* cyclic redundancy check value   */
	de_uint32 i;              /* loop variable                   */
	de_uint32 bits;           /* the bits we are looking at      */
	de_uint32 bitc;           /* number of bits that are valid   */
	struct lzh_table *lzhtbl = &ze->lzhtbl;

#define LZH_PEEK_BITS(N)  ((bits >> (bitc-(N))) & ((1L<<(N))-1))
#define LZH_FLSH_BITS(N)  if ( (bitc -= (N)) < 16 ) { bits  = (bits<<16) + FlahReadArch(uz); bitc += 16; }

	/* initialize bit source, output pointer, and crc                      */
	bits = 0;  bitc = 0;  LZH_FLSH_BITS(0);
	cur = ze->BufFile;  end = ze->BufFile + LZH_MAX_OFF;
	crc = 0;

	/* loop until all blocks have been read                                */
	cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	while ( cnt != 0 ) {

		/* read the pre code                                               */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_PRE );  LZH_FLSH_BITS( LZH_BITS_PRE );
		if ( cnt2 == 0 ) {
			pre = LZH_PEEK_BITS( LZH_BITS_PRE );  LZH_FLSH_BITS( LZH_BITS_PRE );
			for ( i = 0; i <      256; i++ )  lzhtbl->TabPre[i] = pre;
			for ( i = 0; i <= LZH_MAX_PRE; i++ )  lzhtbl->LenPre[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = LZH_PEEK_BITS( 3 );  LZH_FLSH_BITS( 3 );
				if ( len == 7 ) {
					while ( LZH_PEEK_BITS( 1 ) ) { len++; LZH_FLSH_BITS( 1 ); }
					LZH_FLSH_BITS( 1 );
				}
				lzhtbl->LenPre[i++] = len;
				if ( i == 3 ) {
					len = LZH_PEEK_BITS( 2 );  LZH_FLSH_BITS( 2 );
					while ( 0 < len-- )  lzhtbl->LenPre[i++] = 0;
				}
			}
			while ( i <= LZH_MAX_PRE )  lzhtbl->LenPre[i++] = 0;
			if ( ! MakeTablLzh(uz, ze, LZH_MAX_PRE+1, lzhtbl->LenPre, 8, lzhtbl->TabPre ) ) {
				uz->ErrMsg = "Pre code description corrupted";
				return 0;
			}
		}

		/* read the code (using the pre code)                              */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_CODE );  LZH_FLSH_BITS( LZH_BITS_CODE );
		if ( cnt2 == 0 ) {
			code = LZH_PEEK_BITS( LZH_BITS_CODE );  LZH_FLSH_BITS( LZH_BITS_CODE );
			for ( i = 0; i <      4096; i++ )  lzhtbl->TabCode[i] = code;
			for ( i = 0; i <= LZH_MAX_CODE; i++ )  lzhtbl->LenCode[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = lzhtbl->TabPre[ LZH_PEEK_BITS( 8 ) ];
				if ( len <= LZH_MAX_PRE ) {
					LZH_FLSH_BITS( lzhtbl->LenPre[len] );
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
					while ( 0 < len-- )  lzhtbl->LenCode[i++] = 0;
				}
				else {
					lzhtbl->LenCode[i++] = len - 2;
				}
			}
			while ( i <= LZH_MAX_CODE )  lzhtbl->LenCode[i++] = 0;
			if ( ! MakeTablLzh(uz, ze, LZH_MAX_CODE+1, lzhtbl->LenCode, 12, lzhtbl->TabCode ) ) {
				uz->ErrMsg = "Literal/length code description corrupted";
				return 0;
			}
		}

		/* read the log_2 of offsets                                       */
		cnt2 = LZH_PEEK_BITS( LZH_BITS_LOG );  LZH_FLSH_BITS( LZH_BITS_LOG );
		if ( cnt2 == 0 ) {
			log = LZH_PEEK_BITS( LZH_BITS_LOG );  LZH_FLSH_BITS( LZH_BITS_LOG );
			for ( i = 0; i <      256; i++ )  lzhtbl->TabLog[i] = log;
			for ( i = 0; i <= LZH_MAX_LOG; i++ )  lzhtbl->LenLog[i] = 0;
		}
		else {
			i = 0;
			while ( i < cnt2 ) {
				len = LZH_PEEK_BITS( 3 );  LZH_FLSH_BITS( 3 );
				if ( len == 7 ) {
					while ( LZH_PEEK_BITS( 1 ) ) { len++; LZH_FLSH_BITS( 1 ); }
					LZH_FLSH_BITS( 1 );
				}
				lzhtbl->LenLog[i++] = len;
			}
			while ( i <= LZH_MAX_LOG )  lzhtbl->LenLog[i++] = 0;
			if ( ! MakeTablLzh(uz, ze, LZH_MAX_LOG+1, lzhtbl->LenLog, 8, lzhtbl->TabLog ) ) {
				uz->ErrMsg = "Log code description corrupted";
				return 0;
			}
		}

		/* read the codes                                                  */
		while ( 0 < cnt-- ) {

			/* try to decode the code the fast way                         */
			code = lzhtbl->TabCode[ LZH_PEEK_BITS( 12 ) ];

			/* if this code needs more than 12 bits look it up in the tree */
			if ( code <= LZH_MAX_CODE ) {
				LZH_FLSH_BITS( lzhtbl->LenCode[code] );
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
				*cur++ = code;
				crc = CRC_BYTE(uz, crc, code );
				if ( cur == end ) {
					if ( BlckWritFile(uz, ze, ze->BufFile,cur-ze->BufFile) != cur-ze->BufFile ) {
						uz->ErrMsg = "Cannot write output file";
						return 0;
					}
					cur = ze->BufFile;
				}
			}

			/* otherwise compute match length and offset and copy          */
			else {
				len = code - (LZH_MAX_LIT+1) + LZH_MIN_LEN;

				/* try to decodes the log_2 of the offset the fast way     */
				log = lzhtbl->TabLog[ LZH_PEEK_BITS( 8 ) ];
				/* if this log_2 needs more than 8 bits look in the tree   */
				if ( log <= LZH_MAX_LOG ) {
					LZH_FLSH_BITS( lzhtbl->LenLog[log] );
				}
				else {
					LZH_FLSH_BITS( 8 );
					do {
						if ( LZH_PEEK_BITS( 1 ) )  log = lzhtbl->TreeRight[log];
						else                   log = lzhtbl->TreeLeft [log];
						LZH_FLSH_BITS( 1 );
					} while ( LZH_MAX_LOG < log );
				}

				/* compute the offset                                      */
				if ( log == 0 ) {
					off = 0;
				}
				else {
					off = ((unsigned)1 << (log-1)) + LZH_PEEK_BITS( log-1 );
					LZH_FLSH_BITS( log-1 );
				}

				/* copy the match (this accounts for ~ 50% of the time)    */
				pos = ze->BufFile + (((cur-ze->BufFile) - off - 1) & (LZH_MAX_OFF - 1));
				if ( cur < end-len && pos < end-len ) {
					stp = cur + len;
					do {
						code = *pos++;
						crc = CRC_BYTE(uz, crc, code );
						*cur++ = code;
					} while ( cur < stp );
				}
				else {
					while ( 0 < len-- ) {
						code = *pos++;
						crc = CRC_BYTE(uz, crc, code );
						*cur++ = code;
						if ( pos == end ) {
							pos = ze->BufFile;
						}
						if ( cur == end ) {
							if ( BlckWritFile(uz, ze, ze->BufFile,cur-ze->BufFile)
								 != cur-ze->BufFile ) {
								uz->ErrMsg = "Cannot write output file";
								return 0;
							}
							cur = ze->BufFile;
						}
					}
				}
			}
		}

		cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	}

	/* write out the rest of the buffer                                    */
	if ( BlckWritFile(uz, ze, ze->BufFile,cur-ze->BufFile) != cur-ze->BufFile ) {
		uz->ErrMsg = "Cannot write output file";
		return 0;
	}

	/* indicate success                                                    */
	ze->Crc = crc;
	return 1;
}

static const de_uint32 BeginMonth [12] = {
	0,    31,   59,   90,  120,  151,  181,  212,  243,  273,  304,  334
};

static void ExtrEntry(struct unzooctx *uz, de_int64 pos1, de_int64 *next_entry_pos)
{
	de_uint32       res;            /* status of decoding              */
	struct entryctx *ze = NULL;
	deark *c = uz->c;
	de_int64 timestamp_offset;
	char timestamp_buf[64];

	ze = de_malloc(c, sizeof(struct entryctx));
	ze->fi = de_finfo_create(c);

	/* read the directory entry for the next member                    */
	if ( ! GotoReadArch(uz, pos1) || ! EntrReadArch(uz, ze) ) {
		de_err(c, "Found bad directory entry in archive\n");
		goto done;
	}

	*next_entry_pos = ze->posnxt;

	// TODO: How does this work, exactly?
	// One would think the last valid entry would have a NULL "next" pointer.
	if ( ! ze->posnxt ) {
		de_dbg(c, "ignoring entry because posnxt=0\n");
		goto done;
	}

	/* skip members we don't care about                                */
	if (  ze->delete_ == 1 ) {
		de_dbg(c, "ignoring deleted entry\n");
		goto done;
	}

	/* check that we can decode this file                              */
	if ( (2 < ze->majver) || (2 == ze->majver && 1 < ze->minver) ) {
		de_err(c, "Unsupported format version: %d.%d\n",
			(int)ze->majver, (int)ze->minver);
		goto done;
	}

	if(ze->method!=0 && ze->method!=1 && ze->method!=2) {
		de_err(c, "Unsupported compression method: %d\n", (int)ze->method);
		goto done;
	}

	timestamp_offset = 0;
	if      ( ze->timzon < 127 )  timestamp_offset = 15*60*(ze->timzon      );
	else if ( 127 < ze->timzon )  timestamp_offset = 15*60*(ze->timzon - 256);

	de_dos_datetime_to_timestamp(&ze->fi->mod_time, ze->datdos, ze->timdos, timestamp_offset);
	de_timestamp_to_string(&ze->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %s\n", timestamp_buf);

	/* open the file for creation                                      */
	if ( ! OpenWritFile(uz, ze) ) {
		goto done;
	}

	/* decode the file                                                 */
	if ( ! GotoReadArch(uz,  ze->posdat ) ) {
		de_err(c, "Cannot find data in archive\n");
		goto done;
	}
	res = 0;
	uz->ErrMsg = "Internal error";

	switch(ze->method) {
	case 0:
		res = DecodeCopy(uz, ze, ze->siznow );
		break;
	case 1:
		res = DecodeLzd(uz, ze);
		break;
	case 2:
		res = DecodeLzh(uz, ze);
		break;
	default:
		goto done;
	}

	de_dbg(c, "calculated crc: 0x%04x\n", (unsigned int)ze->Crc);

	/* check that everything went ok                                   */
	if      ( res == 0 ) {
		de_err(c, "%s\n", uz->ErrMsg);
	}
	else if ( ze->Crc != ze->crcdat ) {
		de_err(c, "CRC failed\n");
	}

done:
	if(ze) {
		ClosWritFile(uz, ze);
		de_finfo_destroy(c, ze->fi);
		de_free(c, ze);
	}
}

static int ExtrArch (deark *c, dbuf *inf)
{
	int retval = 0;
	struct unzooctx *uz = NULL;
	de_int64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	uz = de_malloc(c, sizeof(struct unzooctx));
	uz->c = c;
	uz->ReadArch = inf;
	uz->ReadArch_fpos = 0;

	InitCrc(uz);

	if(!DescReadArch(uz)) {
		de_err(uz->c, "Found bad description in archive\n");
		goto done;
	}

	/* loop over the members of the archive                                */
	pos = uz->posent;
	while ( 1 ) {
		de_int64 next_entry_pos;

		de_dbg_indent_restore(c, saved_indent_level);

		// TODO: Prevent infinite loops
		if(pos==0) break;

		de_dbg(c, "entry at %d\n", (int)pos);
		de_dbg_indent(c, 1);

		next_entry_pos = 0;
		ExtrEntry(uz, pos, &next_entry_pos);
		pos = next_entry_pos;
	}

	retval = 1;
done:
	de_free(c, uz);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}
