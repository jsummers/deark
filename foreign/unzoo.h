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

#define ZOOCMPR_STORED  0
#define ZOOCMPR_LZD     1
#define ZOOCMPR_LZH     2

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

struct unzooctx;

// Data associated with one ZOO file Entry
struct entryctx {
	struct unzooctx *uz;
	de_finfo *fi;
	dbuf *WritBinr;
	u32 crc_calculated;

	// Original "Entry":
	u32           magic;          /* magic word 0xfdc4a7dc           */
	u8             type;           /* type of current member (1)      */
	u8             method;         /* packing method of member (0..2) */
	u32           posnxt;         /* position of next member         */
	u32           posdat;         /* position of data                */
	u16           datdos;         /* date (in DOS format)            */
	u16           timdos;         /* time (in DOS format)            */
	u32           crcdat;         /* crc value of member             */
	u32           sizorg;         /* uncompressed size of member     */
	u32           siznow;         /*   compressed size of member     */
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8             delete_;        /* 1 if member is deleted, 0 else  */
	u8             spared;         /* spare entry to pad entry        */
	u32           poscmt;         /* position of comment, 0 if none  */
	u16           sizcmt;         /* length   of comment, 0 if none  */
	char                nams [14];      /* short name of member or archive */
	u16           lvar;           /* length of variable part         */
	u8             timzon;         /* time zone                       */
	u16           crcent;         /* crc value of entry              */
	u8             lnamu;          /* length of long name             */
	u8             ldiru;          /* length of directory             */
	char                namu [256];     /* univ. name of member of archive */
	char                diru [256];     /* univ. name of directory         */
	u16           system;         /* system identifier               */
	u32           permis;         /* file permissions                */
	u8             modgen;         /* gens. on, last gen., gen. limit */
	u16           ver;            /* version number of member        */

	struct lzh_table lzhtbl;

	u8             BufFile [8192];         /* at least LZH_MAX_OFF   */
};

struct unzooctx {
	deark *c;
	dbuf *ReadArch; // Input file, owned by the caller
	i64 ReadArch_fpos;
	struct de_inthashtable *offsets_seen;

	// Original "Descript":
	char                text[21];       /* "ZOO 2.10 Archive.<ctr>Z"       */
	u32           magic;          /* magic word 0xfdc4a7dc           */
	u32           posent;         /* position of first directory ent.*/
	u32           klhvmh;         /* two's complement of posent      */
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8             type;           /* type of current member (0,1)    */
	u32           poscmt;         /* position of comment, 0 if none  */
	u16           sizcmt;         /* length   of comment, 0 if none  */
	u8             modgen;         /* gens. on, gen. limit            */

	/****************************************************************************
	**
	*V  ErrMsg  . . . . . . . . . . . . . . . . . . . . . . . . . . error message
	**
	**  'ErrMsg' is used by the  decode functions to communicate  the cause of an
	**  error to the calling function.
	*/
	const char *ErrMsg;

	// Shared by all member files, so we don't have to recalculate the CRC table
	// for each member file.
	struct de_crcobj *crco;
};

static int GotoReadArch (struct unzooctx *uz, i64 pos)
{
	uz->ReadArch_fpos = pos;
	return 1;
}

static int ByteReadArch(struct unzooctx *uz)
{
	u8 ch;
	ch = dbuf_getbyte(uz->ReadArch, uz->ReadArch_fpos);
	uz->ReadArch_fpos++;
	return (int)ch;
}

static u32 HalfReadArch (struct unzooctx *uz)
{
	u32 result;
	result = (u32)dbuf_getu16le(uz->ReadArch, uz->ReadArch_fpos);
	uz->ReadArch_fpos += 2;
	return result;
}

static u32 FlahReadArch (struct unzooctx *uz)
{
	u32 result;
	result = (u32)dbuf_getu16be(uz->ReadArch, uz->ReadArch_fpos);
	uz->ReadArch_fpos += 2;
	return result;
}

static u32 TripReadArch (struct unzooctx *uz)
{
	u32       result;
	result  = ((u32)ByteReadArch(uz));
	result += ((u32)ByteReadArch(uz)) << 8;
	result += ((u32)ByteReadArch(uz)) << 16;
	return result;
}

static u32 WordReadArch (struct unzooctx *uz)
{
	u32 result;
	result = (u32)dbuf_getu32le(uz->ReadArch, uz->ReadArch_fpos);
	uz->ReadArch_fpos += 4;
	return result;
}

static u32 BlckReadArch (struct unzooctx *uz, u8 *blk, u32 len )
{
	i64 amt_to_read = (i64)len;

	if(uz->ReadArch_fpos + amt_to_read > uz->ReadArch->len) {
		// This read would go past EOF
		amt_to_read = uz->ReadArch->len - uz->ReadArch_fpos;
		if(amt_to_read > (i64)len) amt_to_read = (i64)len;
	}

	dbuf_read(uz->ReadArch, blk, uz->ReadArch_fpos, amt_to_read);
	uz->ReadArch_fpos += amt_to_read;
	return (u32)amt_to_read;
}

static void do_extract_comment(struct unzooctx *uz, i64 pos, i64 len, int is_main)
{
	dbuf_create_file_from_slice(uz->ReadArch, pos, len, "comment.txt",
		NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_dbg_comment(struct unzooctx *uz, i64 pos, i64 len, int is_main)
{
	de_ucstring *s = NULL;

	if(uz->c->debug_level<1) return;
	s = ucstring_create(uz->c);
	dbuf_read_to_ucstring_n(uz->ReadArch, pos, len, DE_DBG_MAX_STRLEN, s,
		0, DE_ENCODING_ASCII);
	de_dbg(uz->c, "%scomment: \"%s\"", is_main?"(global) ":"",
		ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment(struct unzooctx *uz, i64 pos, i64 len, int is_main)
{
	if(len<1) return;
	if(pos<0 || pos+len>uz->ReadArch->len) return;
	if(uz->c->extract_level>=2) {
		do_extract_comment(uz, pos, len, is_main);
	}
	else {
		do_dbg_comment(uz, pos, len, is_main);
	}
}

// Read the main file header
static int DescReadArch (struct unzooctx *uz)
{
	deark *c = uz->c;
	int retval = 0;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	/* read the text at the beginning                                      */
	BlckReadArch(uz, (u8*)uz->text, 20L);  uz->text[20] = '\0';

	/* try to read the magic words                                         */
	if ( (uz->magic = WordReadArch(uz)) != (u32)0xfdc4a7dcL ) {
		goto done;
	}

	/* read the old part of the description                                */
	uz->posent = WordReadArch(uz);
	de_dbg(c, "first entry offset: %u", (unsigned int)uz->posent);

	uz->klhvmh = WordReadArch(uz);
	de_dbg2(c, "2's complement of offset: %u (%d)", (unsigned int)uz->klhvmh,
		(int)(unsigned int)uz->klhvmh);
	uz->majver = ByteReadArch(uz);
	uz->minver = ByteReadArch(uz);
	de_dbg(c, "(global) version needed to extract: %d.%d", (int)uz->majver, (int)uz->minver);

	/* read the new part of the description if present                     */
	if(uz->posent > 34) {
		uz->type   = ByteReadArch(uz);
		de_dbg2(c, "(global) type: %u", (unsigned int)uz->type);

		uz->poscmt = WordReadArch(uz);
		uz->sizcmt = HalfReadArch(uz);
		de_dbg(c, "(global) comment size: %d, pos=%d", (int)uz->sizcmt, (int)uz->poscmt);
		do_comment(uz, uz->poscmt, uz->sizcmt, 1);

		uz->modgen = ByteReadArch(uz);
		de_dbg2(c, "(global) modgen: %u", (unsigned int)uz->modgen);
	}
	else {
		uz->type   = 0;
		uz->poscmt = 0;
		uz->sizcmt = 0;
		uz->modgen = 0;
	}

	/* indicate success                                                    */
	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static const char *get_cmpr_meth_name(u8 t)
{
	const char *name = NULL;
	switch(t) {
	case 0: name="stored"; break;
	case 1: name="lzd"; break;
	case 2: name="lzh"; break;
	}
	return name?name:"?";
}

// Read the header of a single member file.
static int EntrReadArch (struct unzooctx *uz, struct entryctx *ze)
{
	u32           l;              /* 'Entry.lnamu+Entry.ldiru'       */
	deark *c = uz->c;
	de_ucstring *shortname_ucstring = NULL;
	de_ucstring *longname_ucstring = NULL;
	de_ucstring *dirname_ucstring = NULL;
	de_ucstring *fullname_ucstring = NULL;
	int retval = 0;
	i64 pos1 = uz->ReadArch_fpos;
	i64 timestamp_offset;
	char timestamp_buf[64];

	/* try to read the magic words                                         */
	if ( (ze->magic = WordReadArch(uz)) != (u32)0xfdc4a7dcL ) {
		de_err(c, "Malformed ZOO file, bad magic number at %d", (int)pos1);
		goto done;
	}

	/* read the fixed part of the directory entry                          */
	ze->type   = ByteReadArch(uz);
	ze->method = ByteReadArch(uz);
	ze->posnxt = WordReadArch(uz);

	if(ze->posnxt == 0) {
		// I guess that end of file is marked by a dummy member file entry
		// having posnxt=0.
		de_dbg(c, "next entry pos: %d (eof)", (int)ze->posnxt);
		retval = 1;
		goto done;
	}

	de_dbg(c, "type: %d", (int)ze->type);
	de_dbg(c, "compression method: %d (%s)", (int)ze->method, get_cmpr_meth_name(ze->method));
	de_dbg(c, "next entry pos: %d", (int)ze->posnxt);

	ze->posdat = WordReadArch(uz);
	de_dbg(c, "pos of file data: %u", (unsigned int)ze->posdat);

	ze->datdos = HalfReadArch(uz);
	ze->timdos = HalfReadArch(uz);
	de_dbg2(c, "dos date,time: %d,%d", (int)ze->datdos, (int)ze->timdos);
	ze->crcdat = (u32)HalfReadArch(uz);
	de_dbg(c, "file data crc (reported): 0x%04x", (unsigned int)ze->crcdat);
	ze->sizorg = WordReadArch(uz);
	de_dbg(c, "original size: %u", (unsigned int)ze->sizorg);
	ze->siznow = WordReadArch(uz);
	de_dbg(c, "compressed size: %u", (unsigned int)ze->siznow);
	ze->majver = ByteReadArch(uz);
	ze->minver = ByteReadArch(uz);
	de_dbg(c, "version needed to extract: %d.%d", (int)ze->majver, (int)ze->minver);
	ze->delete_ = ByteReadArch(uz);
	ze->spared = ByteReadArch(uz);
	ze->poscmt = WordReadArch(uz);
	ze->sizcmt = HalfReadArch(uz);
	de_dbg(c, "comment size: %d, pos=%d", (int)ze->sizcmt, (int)ze->poscmt);
	if((ze->posnxt!=0) && (ze->delete_ != 1)) {
		do_comment(uz, ze->poscmt, ze->sizcmt, 0);
	}

	BlckReadArch(uz, (u8*)ze->nams, 13L);  ze->nams[13] = '\0';
	shortname_ucstring = ucstring_create(c);
	ucstring_append_bytes(shortname_ucstring, (const u8*)ze->nams, sizeof(ze->nams),
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "short name: \"%s\"", ucstring_getpsz(shortname_ucstring));

	/* handle the long name and the directory in the variable part         */

	if(ze->type == 2) {
		ze->lvar   = HalfReadArch(uz);
		de_dbg(c, "length of variable part: %d", (int)ze->lvar);
	}
	else {
		ze->lvar   = 0;
	}

	if(ze->type == 2) {
		char namebuf[80];

		ze->timzon = ByteReadArch(uz);

		// Note: The timezone field is definitely a signed byte that is the
		// number of 15-minute units from UTC, but it is unknown to me whether
		// a positive number means west, or east. Under either interpretation,
		// I have multiple sample files with highly implausible timezones. The
		// interpretation used here is based on the preponderance of evidence.
		if(ze->timzon==127) {
			de_strlcpy(namebuf, "unknown", sizeof(namebuf));
		}
		else if(ze->timzon>127) {
			de_snprintf(namebuf, sizeof(namebuf), "%.2f hours east of UTC",
				((double)ze->timzon - 256.0)/-4.0);
		}
		else {
			de_snprintf(namebuf, sizeof(namebuf), "%.2f hours west of UTC",
				((double)ze->timzon)/4.0);
		}
		de_dbg(c, "time zone: %d (%s)", (int)ze->timzon, namebuf);

	}
	else {
		ze->timzon = 127;
	}

	// Now that we know the timezone, finish reporting the mod time, and set
	// ze->fi->mod_time.
	timestamp_offset = 0;
	if      ( ze->timzon < 127 )  timestamp_offset = 15*60*((i64)ze->timzon      );
	else if ( 127 < ze->timzon )  timestamp_offset = 15*60*((i64)ze->timzon - 256);

	de_dos_datetime_to_timestamp(&ze->fi->mod_time, ze->datdos, ze->timdos);
	de_timestamp_to_string(&ze->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
	if(ze->timzon == 127) {
		ze->fi->mod_time.tzcode = DE_TZCODE_LOCAL;
	}
	else {
		de_timestamp_cvt_to_utc(&ze->fi->mod_time, timestamp_offset);
		de_timestamp_to_string(&ze->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "mod time (UTC): %s", timestamp_buf);
	}

	if(ze->type == 2) {
		ze->crcent = HalfReadArch(uz);
		de_dbg(c, "entry crc (reported): 0x%04x", (unsigned int)ze->crcent);
	}
	else {
		ze->crcent = 0;
	}

	ze->lnamu  = (0 < ze->lvar   ? ByteReadArch(uz) : 0);
	de_dbg2(c, "long name len: %d", (int)ze->lnamu);
	ze->ldiru  = (1 < ze->lvar   ? ByteReadArch(uz) : 0);
	de_dbg2(c, "dir name len: %d", (int)ze->ldiru);

	BlckReadArch(uz, (u8*)ze->namu, (u32)ze->lnamu);
	ze->namu[ze->lnamu] = '\0';
	longname_ucstring = ucstring_create(c);
	if(ze->lnamu>0) {
		ucstring_append_bytes(longname_ucstring, (const u8*)ze->namu, sizeof(ze->namu),
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "long name: \"%s\"", ucstring_getpsz(longname_ucstring));
	}

	BlckReadArch(uz, (u8*)ze->diru, (u32)ze->ldiru);
	ze->diru[ze->ldiru] = '\0';
	dirname_ucstring = ucstring_create(c);
	if(ze->ldiru>0) {
		ucstring_append_bytes(dirname_ucstring, (const u8*)ze->diru, sizeof(ze->diru),
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "dir name: \"%s\"", ucstring_getpsz(dirname_ucstring));
	}

	l = ze->lnamu + ze->ldiru;
	ze->system = (l+2 < ze->lvar ? HalfReadArch(uz) : 0);

	ze->permis = (l+4 < ze->lvar ? TripReadArch(uz) : 0);
	if(l+4 < ze->lvar) {
		de_dbg(c, "perms: octal(%o)", (unsigned int)ze->permis);
		if((ze->permis & 0111) != 0) {
			ze->fi->mode_flags |= DE_MODEFLAG_EXE;
		}
		else {
			ze->fi->mode_flags |= DE_MODEFLAG_NONEXE;
		}
	}

	if(l+7 < ze->lvar) {
		ze->modgen = ByteReadArch(uz);
		de_dbg(c, "modgen: %u", (unsigned int)ze->modgen);
	}
	else {
		ze->modgen = 0;
	}

	if(l+9 < ze->lvar) {
		ze->ver = HalfReadArch(uz);
		de_dbg(c, "member version: %u", (unsigned int)ze->ver);
	}
	else {
		ze->ver = 0;
	}

	// Note: Typically, there is a 5-byte "file leader" ("@)#(\0") here, between
	// the member header and the member data, so uz->ReadArch_fpos is not
	// expected to equal ze->posdat.

	// Figure out the best filename to use
	if(ucstring_isnonempty(longname_ucstring) || ucstring_isnonempty(shortname_ucstring)) {
		fullname_ucstring = ucstring_create(c);

		if(ucstring_isnonempty(dirname_ucstring)) {
			ucstring_append_ucstring(fullname_ucstring, dirname_ucstring);
			ucstring_append_sz(fullname_ucstring, "/", DE_ENCODING_ASCII);
		}
		if(ucstring_isnonempty(longname_ucstring)) {
			ucstring_append_ucstring(fullname_ucstring, longname_ucstring);
		}
		else if(ucstring_isnonempty(shortname_ucstring)) {
			ucstring_append_ucstring(fullname_ucstring, shortname_ucstring);
		}

		de_finfo_set_name_from_ucstring(c, ze->fi, fullname_ucstring, DE_SNFLAG_FULLPATH);
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

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct entryctx *ze = (struct entryctx *)f->userdata;

	de_crcobj_addbuf(ze->uz->crco, buf, buf_len);
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
	ze->WritBinr->writecallback_fn = our_writecallback;
	ze->WritBinr->userdata = (void*)ze;
	de_crcobj_reset(uz->crco);
	return 1;
}

static int ClosWritFile (struct unzooctx *uz, struct entryctx *ze)
{
	if(!ze->WritBinr) return 0;
	dbuf_close(ze->WritBinr);
	ze->WritBinr = NULL;
	return 1;
}

static i64 BlckWritFile (struct unzooctx *uz, struct entryctx *ze, const u8 *blk, i64 len )
{
	if(!ze->WritBinr) return 0;
	dbuf_write(ze->WritBinr, blk, len);
	return len;
}

/****************************************************************************
**
*F  DecodeCopy(<size>). . . . . . . . . . . .  extract an uncompressed member
**
**  'DecodeCopy' simply  copies <size> bytes  from the  archive to the output
**  file.
*/
static int DecodeCopy (struct unzooctx *uz, struct entryctx *ze, u32 size )
{
	if(uz->ReadArch_fpos + size > uz->ReadArch->len) {
		uz->ErrMsg = "Unexpected <eof> in the archive";
		return 0;
	}

	dbuf_copy(uz->ReadArch, uz->ReadArch_fpos, (i64)size, ze->WritBinr);
	uz->ReadArch_fpos += size;

	/* indicate success                                                    */
	return 1;
}

// Forward declaration of a function in zoo-lzd.h
static int lzd(struct unzooctx *uz, i64 in_len, dbuf *out_f, int maxbits);

/****************************************************************************
**
*F  DecodeLzd() . . . . . . . . . . . . . . .  extract a LZ compressed member
**
*/
static int DecodeLzd (struct unzooctx *uz, struct entryctx *ze)
{
	return !lzd(uz, ze->siznow, ze->WritBinr, 13);
}

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
static int MakeTablLzh (struct unzooctx *uz, struct entryctx *ze,
	struct lzh_lookuptable *lookuptbl)
{
	u16           count[17], weight[17], start[18];
	unsigned int        i, len, ch, jutbits, avail, mask;
	struct lzh_table *lzhtbl = &ze->lzhtbl;

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
	struct unzooctx *uz;
	u32 bits;           /* the bits we are looking at      */
	u32 bitc;           /* number of bits that are valid   */
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
		lzhctx->bits  = (lzhctx->bits<<16) + FlahReadArch(lzhctx->uz);
		lzhctx->bitc += 16;
	}
}

static u8 BufFile_getbyte(struct entryctx *ze, unsigned int idx)
{
	if(idx<LZH_MAX_OFF) return ze->BufFile[idx];
	return 0;
}

static void BufFile_setbyte(struct entryctx *ze, unsigned int idx, u8 n)
{
	if(idx<LZH_MAX_OFF) {
		ze->BufFile[idx] = n;
	}
}

static int DecodeLzh (struct unzooctx *uz, struct entryctx *ze)
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
	struct lzhctx_struct lzhctx;
	struct lzh_table *lzhtbl = &ze->lzhtbl;

#define LZH_PEEK_BITS(N)  lzh_peek_bits_(&lzhctx, N)
#define LZH_FLSH_BITS(N)  lzh_flsh_bits_(&lzhctx, N)

	/* initialize bit source, output pointer, and crc                      */
	lzhctx.uz = uz;
	lzhctx.bits = 0;  lzhctx.bitc = 0;  LZH_FLSH_BITS(0);
	cur_idx = 0;
	end_idx = LZH_MAX_OFF;

	/* loop until all blocks have been read                                */
	cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	while ( cnt != 0 ) {

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
			if ( ! MakeTablLzh(uz, ze, &lzhtbl->PreTbl) ) {
				uz->ErrMsg = "Pre code description corrupted";
				return 0;
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
			if ( ! MakeTablLzh(uz, ze, &lzhtbl->CodeTbl) ) {
				uz->ErrMsg = "Literal/length code description corrupted";
				return 0;
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
			if ( ! MakeTablLzh(uz, ze, &lzhtbl->LogTbl) ) {
				uz->ErrMsg = "Log code description corrupted";
				return 0;
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
				BufFile_setbyte(ze, cur_idx++, code);
				if ( cur_idx == end_idx ) {
					if ( BlckWritFile(uz, ze, ze->BufFile, cur_idx) != cur_idx ) {
						uz->ErrMsg = "Cannot write output file";
						return 0;
					}
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
						code = BufFile_getbyte(ze, pos_idx++);
						BufFile_setbyte(ze, cur_idx++, code);
					} while ( cur_idx < stp_idx );
				}
				else {
					while ( 0 < len-- ) {
						code = BufFile_getbyte(ze, pos_idx++);
						BufFile_setbyte(ze, cur_idx++, code);
						if ( pos_idx == end_idx ) {
							pos_idx = 0;
						}
						if ( cur_idx == end_idx ) {
							if ( BlckWritFile(uz, ze, ze->BufFile, cur_idx)
								 != cur_idx )
							{
								uz->ErrMsg = "Cannot write output file";
								return 0;
							}
							cur_idx = 0;
						}
					}
				}
			}
		}

		cnt = LZH_PEEK_BITS( 16 );  LZH_FLSH_BITS( 16 );
	}

	/* write out the rest of the buffer                                    */
	if(cur_idx>=LZH_MAX_OFF) return 0;
	if ( BlckWritFile(uz, ze, ze->BufFile, cur_idx) != cur_idx ) {
		uz->ErrMsg = "Cannot write output file";
		return 0;
	}

	/* indicate success                                                    */
	return 1;
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

// Process a single member file
static void ExtrEntry(struct unzooctx *uz, i64 pos1, i64 *next_entry_pos)
{
	u32       res;            /* status of decoding              */
	struct entryctx *ze = NULL;
	deark *c = uz->c;

	ze = de_malloc(c, sizeof(struct entryctx));
	ze->uz = uz;

	init_lzh_lookuptable(c, &ze->lzhtbl.CodeTbl, 12, LZH_MAX_CODE+1);
	init_lzh_lookuptable(c, &ze->lzhtbl.LogTbl, 8, LZH_MAX_LOG+1);
	init_lzh_lookuptable(c, &ze->lzhtbl.PreTbl, 8, LZH_MAX_PRE+1);

	ze->fi = de_finfo_create(c);

	/* read the directory entry for the next member                    */
	if ( ! GotoReadArch(uz, pos1) || ! EntrReadArch(uz, ze) ) {
		de_err(c, "Found bad directory entry in archive");
		goto done;
	}

	*next_entry_pos = ze->posnxt;

	if ( ! ze->posnxt ) {
		goto done;
	}

	/* skip members we don't care about                                */
	if (  ze->delete_ == 1 ) {
		de_dbg(c, "ignoring deleted entry");
		goto done;
	}

	/* check that we can decode this file                              */
	if ( (2 < ze->majver) || (2 == ze->majver && 1 < ze->minver) ) {
		de_err(c, "Unsupported format version: %d.%d",
			(int)ze->majver, (int)ze->minver);
		goto done;
	}

	if(ze->method!=ZOOCMPR_STORED && ze->method!=ZOOCMPR_LZD && ze->method!=ZOOCMPR_LZH) {
		de_err(c, "Unsupported compression method: %d", (int)ze->method);
		goto done;
	}

	de_dbg(c, "compressed data at %u, len=%u", (unsigned int)ze->posdat,
		(unsigned int)ze->siznow);

	/* open the file for creation                                      */
	if ( ! OpenWritFile(uz, ze) ) {
		goto done;
	}

	/* decode the file                                                 */
	if ( ! GotoReadArch(uz,  ze->posdat ) ) {
		de_err(c, "Cannot find data in archive");
		goto done;
	}
	res = 0;
	uz->ErrMsg = "Internal error";

	switch(ze->method) {
	case ZOOCMPR_STORED:
		res = DecodeCopy(uz, ze, ze->siznow );
		break;
	case ZOOCMPR_LZD:
		res = DecodeLzd(uz, ze);
		break;
	case ZOOCMPR_LZH:
		res = DecodeLzh(uz, ze);
		break;
	default:
		goto done;
	}

	ze->crc_calculated = de_crcobj_getval(uz->crco);
	de_dbg(c, "file data crc (calculated): 0x%04x", (unsigned int)ze->crc_calculated);

	/* check that everything went ok                                   */
	if      ( res == 0 ) {
		de_err(c, "%s", uz->ErrMsg);
	}
	else if ( ze->crc_calculated != ze->crcdat ) {
		de_err(c, "CRC failed");
	}

done:
	if(ze) {
		ClosWritFile(uz, ze);
		de_finfo_destroy(c, ze->fi);

		de_free(c, ze->lzhtbl.CodeTbl.Tab);
		de_free(c, ze->lzhtbl.CodeTbl.Len);
		de_free(c, ze->lzhtbl.LogTbl.Tab);
		de_free(c, ze->lzhtbl.LogTbl.Len);
		de_free(c, ze->lzhtbl.PreTbl.Tab);
		de_free(c, ze->lzhtbl.PreTbl.Len);

		de_free(c, ze);
	}
}

// The main function: process a ZOO file
static int ExtrArch (deark *c, dbuf *inf)
{
	int retval = 0;
	struct unzooctx *uz = NULL;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	uz = de_malloc(c, sizeof(struct unzooctx));
	uz->c = c;
	uz->ReadArch = inf;
	uz->ReadArch_fpos = 0;

	uz->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	if(!DescReadArch(uz)) {
		de_err(uz->c, "Found bad description in archive");
		goto done;
	}

	/* loop over the members of the archive                                */
	uz->offsets_seen = de_inthashtable_create(c); // For protection against infinite loops
	pos = uz->posent;
	while ( 1 ) {
		i64 next_entry_pos;

		de_dbg_indent_restore(c, saved_indent_level);

		if(pos==0) break;

		if(!de_inthashtable_add_item(c, uz->offsets_seen, pos, NULL)) {
			de_err(c, "Loop detected");
			goto done;
		}

		de_dbg(c, "entry at %d", (int)pos);
		de_dbg_indent(c, 1);

		next_entry_pos = 0;
		ExtrEntry(uz, pos, &next_entry_pos);
		pos = next_entry_pos;
	}

	retval = 1;
done:
	if(uz) {
		de_inthashtable_destroy(c, uz->offsets_seen);
		de_crcobj_destroy(uz->crco);
		de_free(c, uz);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}
