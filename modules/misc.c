// This file is part of Deark.
// Copyright (C) 2016-2021 Jason Summers
// See the file COPYING for terms of use.

// This file is for miscellaneous formats that are easy to support.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_copy);
DE_DECLARE_MODULE(de_module_null);
DE_DECLARE_MODULE(de_module_split);
DE_DECLARE_MODULE(de_module_plaintext);
DE_DECLARE_MODULE(de_module_cp437);
DE_DECLARE_MODULE(de_module_crc);
DE_DECLARE_MODULE(de_module_hexdump);
DE_DECLARE_MODULE(de_module_bytefreq);
DE_DECLARE_MODULE(de_module_zlib);
DE_DECLARE_MODULE(de_module_winzle);
DE_DECLARE_MODULE(de_module_mrw);
DE_DECLARE_MODULE(de_module_vgafont);
DE_DECLARE_MODULE(de_module_zbr);
DE_DECLARE_MODULE(de_module_compress);
DE_DECLARE_MODULE(de_module_hpi);
DE_DECLARE_MODULE(de_module_dclimplode);
DE_DECLARE_MODULE(de_module_lzss_oku);
DE_DECLARE_MODULE(de_module_lzhuf);

// **************************************************************************
// "copy" module
//
// This is a trivial module that makes a copy of the input file.
// **************************************************************************

static void de_run_copy(deark *c, de_module_params *mparams)
{
	dbuf_create_file_from_slice(c->infile, 0, c->infile->len, "bin", NULL, 0);
}

void de_module_copy(deark *c, struct deark_module_info *mi)
{
	mi->id = "copy";
	mi->desc = "Copy the file unchanged";
	mi->run_fn = de_run_copy;
}

// **************************************************************************
// "null" module
//
// This is a trivial module that does nothing.
// **************************************************************************

static void de_run_null(deark *c, de_module_params *mparams)
{
	;
}

void de_module_null(deark *c, struct deark_module_info *mi)
{
	mi->id = "null";
	mi->desc = "Do nothing";
	mi->run_fn = de_run_null;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// split
// Split the input file into equal-sized chunks.
// **************************************************************************

static void do_split_onechunk(deark *c, i64 chunknum, i64 offset, i64 size)
{
	dbuf *outf = NULL;
	char ext[32];

	de_snprintf(ext, sizeof(ext), "part%"I64_FMT, chunknum);
	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(c->infile, offset, size, outf);
	dbuf_close(outf);
}

static void de_run_split(deark *c, de_module_params *mparams)
{
	const char *s;
	i64 pos;
	i64 chunknum;
	i64 chunksize, chunkstride;
	i64 chunkcount;

	s = de_get_ext_option(c, "split:size");
	if(!s) {
		de_err(c, "\"-opt split:size=<n>\" is required.");
		goto done;
	}
	chunksize = de_atoi64(s);
	if(chunksize<1) {
		de_err(c, "Invalid chunk size");
		goto done;
	}

	s = de_get_ext_option(c, "split:stride");
	if(s) {
		chunkstride = de_atoi64(s);
		if(chunkstride<chunksize) {
			de_err(c, "Stride must be "DE_CHAR_GEQ" size");
			goto done;
		}
	}
	else {
		chunkstride = chunksize;
	}

	chunkcount = (c->infile->len + (chunkstride-1)) / chunkstride;

	if((chunkcount>256) && (!c->user_set_max_output_files)) {
		de_err(c, "Large number of chunks; use \"-maxfiles %"I64_FMT"\" if you "
			"really want to do this.", chunkcount);
		goto done;
	}

	pos = 0;
	for(chunknum = 0; chunknum<chunkcount; chunknum++) {
		i64 this_chunk_size;

		this_chunk_size = de_min_int(chunksize, c->infile->len-pos);
		do_split_onechunk(c, chunknum, pos, this_chunk_size);

		pos += chunkstride;
	}

done:
	;
}

static void de_help_split(deark *c)
{
	de_msg(c, "-opt split:size=<n> : The size of each chunk, in bytes");
	de_msg(c, "-opt split:stride=<n> : Source distance between chunks");
}

void de_module_split(deark *c, struct deark_module_info *mi)
{
	mi->id = "split";
	mi->desc = "Split the file into equal-sized chunks";
	mi->run_fn = de_run_split;
	mi->help_fn = de_help_split;
}

// **************************************************************************
// plaintext
// Convert text files to UTF-8.
// **************************************************************************

struct plaintextctx_struct {
	dbuf *outf;
	de_ucstring *tmpstr;
	struct de_encconv_state es;
};

static int plaintext_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct plaintextctx_struct *ptctx = (struct plaintextctx_struct*)brctx->userdata;
	UI conv_flags;

	// There's no limit to how much data dbuf_buffered_read() could send us
	// at once, so we won't try to put it all in a ucstring at once.
	brctx->bytes_consumed = de_min_int(buf_len, 4096);

	// For best results, ucstring_append_bytes_ex() needs to be told whether there will
	// be any more bytes after this.
	if(brctx->eof_flag && brctx->bytes_consumed==buf_len)
		conv_flags = 0;
	else
		conv_flags = DE_CONVFLAG_PARTIAL_DATA;

	ucstring_empty(ptctx->tmpstr);
	ucstring_append_bytes_ex(ptctx->tmpstr, buf, brctx->bytes_consumed, conv_flags,
		&ptctx->es);
	ucstring_write_as_utf8(brctx->c, ptctx->tmpstr, ptctx->outf, 0);
	return 1;
}

static de_encoding get_bom_enc(deark *c, UI *blen)
{
	u8 buf[3];

	de_read(buf, 0, 3);
	if(buf[0]==0xef && buf[1]==0xbb && buf[2]==0xbf) {
		*blen = 3;
		return DE_ENCODING_UTF8;
	}
	else if(buf[0]==0xfe && buf[1]==0xff) {
		*blen = 2;
		return DE_ENCODING_UTF16BE;
	}
	else if(buf[0]==0xff && buf[1]==0xfe) {
		*blen = 2;
		return DE_ENCODING_UTF16LE;
	}
	*blen = 0;
	return DE_ENCODING_UNKNOWN;
}

static void de_run_plaintext(deark *c, de_module_params *mparams)
{
	struct plaintextctx_struct ptctx;
	de_encoding input_encoding;
	de_encoding enc_from_bom;
	UI existing_bom_len = 0;
	i64 dpos, dlen;

	enc_from_bom = get_bom_enc(c, &existing_bom_len);
	input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_UNKNOWN);
	if(input_encoding==DE_ENCODING_UNKNOWN) {
		if(enc_from_bom!=DE_ENCODING_UNKNOWN) {
			input_encoding = enc_from_bom;
		}
		else {
			input_encoding = DE_ENCODING_UTF8;
		}
	}
	if(input_encoding!=enc_from_bom) {
		// Even if there was something that looked like a BOM, ignore it.
		existing_bom_len = 0;
	}

	dpos = (i64)existing_bom_len;
	dlen = c->infile->len - dpos;

	de_encconv_init(&ptctx.es, DE_EXTENC_MAKE(input_encoding, DE_ENCSUBTYPE_HYBRID));
	ptctx.tmpstr = ucstring_create(c);
	ptctx.outf = dbuf_create_output_file(c, "txt", NULL, 0);

	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(ptctx.outf, 0xfeff);
	}

	dbuf_buffered_read(c->infile, dpos, dlen, plaintext_cbfn, (void*)&ptctx);
	dbuf_close(ptctx.outf);
	ucstring_destroy(ptctx.tmpstr);
}

void de_module_plaintext(deark *c, struct deark_module_info *mi)
{
	mi->id = "plaintext";
	mi->desc = "Plain text";
	mi->desc2 = "Convert to UTF-8";
	mi->run_fn = de_run_plaintext;
}

// **************************************************************************
// CP437
// Convert CP437 text files to UTF-8.
// **************************************************************************

struct cp437ctx_struct {
	dbuf *outf;
	struct de_encconv_state es;
};

static int cp437_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i32 u;
	i64 i;
	u8 ch;
	struct cp437ctx_struct *cp437ctx = (struct cp437ctx_struct*)brctx->userdata;

	for(i=0; i<buf_len; i++) {
		ch = buf[i];
		if(ch==0x09 || ch==0x0a || ch==0x0c || ch==0x0d) {
			// Leave HT, NL, FF, CR as-is.
			u = (i32)ch;
		}
		else if(ch==0x1a) {
			// Lots of CP437 files end with a Ctrl+Z character, but modern files
			// don't use any in-band character to signify end-of-file.
			// I don't just want to delete the character, though, so I guess I'll
			// change it to U+2404 SYMBOL FOR END OF TRANSMISSION.
			u = 0x2404;
		}
		else {
			u = de_char_to_unicode_ex((i32)ch, &cp437ctx->es);
		}
		dbuf_write_uchar_as_utf8(cp437ctx->outf, u);
	}

	return 1;
}

static void de_run_cp437(deark *c, de_module_params *mparams)
{
	struct cp437ctx_struct cp437ctx;

	cp437ctx.outf = dbuf_create_output_file(c, "txt", NULL, 0);
	de_encconv_init(&cp437ctx.es, DE_ENCODING_CP437_G);
	if(c->write_bom) {
		dbuf_write_uchar_as_utf8(cp437ctx.outf, 0xfeff);
	}
	dbuf_buffered_read(c->infile, 0, c->infile->len, cp437_cbfn, (void*)&cp437ctx);
	dbuf_close(cp437ctx.outf);
}

void de_module_cp437(deark *c, struct deark_module_info *mi)
{
	mi->id = "cp437";
	mi->desc = "Code Page 437 text";
	mi->run_fn = de_run_cp437;
}

// **************************************************************************
// crc
// Prints various CRCs and checksums. Does not create any files.
// **************************************************************************

struct crcctx_struct {
	struct de_crcobj *crco_32ieee;
	struct de_crcobj *crco_16arc;
	struct de_crcobj *crco_16ccitt;
	u64 sum_of_bytes;
};

static int crc_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct crcctx_struct *crcctx = (struct crcctx_struct*)brctx->userdata;
	i64 i;

	de_crcobj_addbuf(crcctx->crco_32ieee, buf, buf_len);
	de_crcobj_addbuf(crcctx->crco_16arc, buf, buf_len);
	de_crcobj_addbuf(crcctx->crco_16ccitt, buf, buf_len);
	for(i=0; i<buf_len; i++) {
		crcctx->sum_of_bytes += buf[i];
	}
	return 1;
}

static void de_run_crc(deark *c, de_module_params *mparams)
{
	struct crcctx_struct crcctx;

	de_zeromem(&crcctx, sizeof(struct crcctx_struct));
	crcctx.crco_32ieee = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	crcctx.crco_16arc = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	crcctx.crco_16ccitt = de_crcobj_create(c, DE_CRCOBJ_CRC16_XMODEM);

	dbuf_buffered_read(c->infile, 0, c->infile->len, crc_cbfn, (void*)&crcctx);

	de_msg(c, "CRC-32-IEEE: 0x%08x",
		(unsigned int)de_crcobj_getval(crcctx.crco_32ieee));
	de_msg(c, "CRC-16-IBM/ARC: 0x%04x",
		(unsigned int)de_crcobj_getval(crcctx.crco_16arc));
	de_msg(c, "CRC-16-CCITT: 0x%04x",
		(unsigned int)de_crcobj_getval(crcctx.crco_16ccitt));
	de_msg(c, "Sum of bytes: 0x%"U64_FMTx, crcctx.sum_of_bytes);

	de_crcobj_destroy(crcctx.crco_32ieee);
	de_crcobj_destroy(crcctx.crco_16arc);
	de_crcobj_destroy(crcctx.crco_16ccitt);
}

void de_module_crc(deark *c, struct deark_module_info *mi)
{
	mi->id = "crc";
	mi->id_alias[0] = "crc32";
	mi->desc = "Calculate various CRCs";
	mi->run_fn = de_run_crc;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// hexdump
// Prints a hex dump. Does not create any files.
// **************************************************************************

static void de_run_hexdump(deark *c, de_module_params *mparams)
{
	de_hexdump2(c, c->infile, 0, c->infile->len,
		c->infile->len, 0x3);
}

void de_module_hexdump(deark *c, struct deark_module_info *mi)
{
	mi->id = "hexdump";
	mi->desc = "Print a hex dump";
	mi->run_fn = de_run_hexdump;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// bytefreq
// Prints a summary of how many times each byte value occurs.
// **************************************************************************

struct bytefreqentry {
	i64 count;
#define DE_BYTEFREQ_NUMLOC 3
	i64 locations[DE_BYTEFREQ_NUMLOC];
};

struct bytefreqctx_struct {
	struct bytefreqentry e[256];
};

static int bytefreq_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 k;
	struct bytefreqctx_struct *bfctx = (struct bytefreqctx_struct*)brctx->userdata;

	for(k=0; k<buf_len; k++) {
		struct bytefreqentry *bf = &bfctx->e[(unsigned int)buf[k]];

		// Save the location of the first few occurrences of this byte value.
		if(bf->count<DE_BYTEFREQ_NUMLOC) {
			bf->locations[bf->count] = brctx->offset + k;
		}
		bf->count++;
	}
	return 1;
}

static void de_run_bytefreq(deark *c, de_module_params *mparams)
{
	struct bytefreqctx_struct *bfctx = NULL;
	de_ucstring *s = NULL;
	unsigned int k;
	de_encoding input_encoding;
	struct de_encconv_state es;

	bfctx = de_malloc(c, sizeof(struct bytefreqctx_struct));
	input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	if(input_encoding==DE_ENCODING_UTF8) {
		input_encoding=DE_ENCODING_ASCII;
	}
	de_encconv_init(&es, input_encoding);

	dbuf_buffered_read(c->infile, 0, c->infile->len, bytefreq_cbfn, (void*)bfctx);

	de_msg(c, "====Byte==== ===Count=== ==Locations==");
	s = ucstring_create(c);
	for(k=0; k<256; k++) {
		i32 ch;
		int cflag;
		unsigned int z;
		struct bytefreqentry *bf = &bfctx->e[k];

		if(bf->count==0) continue;
		ucstring_empty(s);

		ucstring_printf(s, DE_ENCODING_LATIN1, "%3u 0x%02x ", k, k);

		ch = de_char_to_unicode_ex((i32)k, &es);
		if(ch==DE_CODEPOINT_INVALID) {
			cflag = 0;
		}
		else {
			cflag = de_is_printable_uchar(ch);
		}

		if(cflag) {
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
			ucstring_append_char(s, ch);
			ucstring_append_sz(s, "'", DE_ENCODING_LATIN1);
		}
		else {
			ucstring_append_sz(s, "   ", DE_ENCODING_LATIN1);
		}

		ucstring_printf(s, DE_ENCODING_LATIN1, " %11"I64_FMT" ", bf->count);

		for(z=0; z<DE_BYTEFREQ_NUMLOC && z<bf->count; z++) {
			ucstring_printf(s, DE_ENCODING_LATIN1, "%"I64_FMT, bf->locations[z]);
			if(z<bf->count-1) {
				ucstring_append_sz(s, ",", DE_ENCODING_LATIN1);
			}
		}
		if(bf->count>DE_BYTEFREQ_NUMLOC) {
			ucstring_append_sz(s, "...", DE_ENCODING_LATIN1);
		}

		de_msg(c, "%s", ucstring_getpsz(s));
	}
	de_msg(c, "      Total: %11"I64_FMT, c->infile->len);
	ucstring_destroy(s);
	de_free(c, bfctx);
}

void de_module_bytefreq(deark *c, struct deark_module_info *mi)
{
	mi->id = "bytefreq";
	mi->desc = "Print a byte frequence analysis";
	mi->run_fn = de_run_bytefreq;
	mi->flags |= DE_MODFLAG_NOEXTRACT;
}

// **************************************************************************
// zlib module
//
// This module is for decompressing zlib-compressed files.
// **************************************************************************

static void de_run_zlib(deark *c, de_module_params *mparams)
{
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "unc", NULL, 0);
	fmtutil_decompress_deflate(c->infile, 0, c->infile->len, f, 0, NULL, DE_DEFLATEFLAG_ISZLIB);
	dbuf_close(f);
}

static int de_identify_zlib(deark *c)
{
	u8 b[2];
	de_read(b, 0, 2);

	if((b[0]&0x0f) != 8)
		return 0;

	if(b[0]<0x08 || b[0]>0x78)
		return 0;

	if(((((unsigned int)b[0])<<8)|b[1])%31 != 0)
		return 0;

	return 50;
}

void de_module_zlib(deark *c, struct deark_module_info *mi)
{
	mi->id = "zlib";
	mi->desc = "Raw zlib compressed data";
	mi->run_fn = de_run_zlib;
	mi->identify_fn = de_identify_zlib;
}

// **************************************************************************
// Winzle! puzzle image
// **************************************************************************

static void de_run_winzle(deark *c, de_module_params *mparams)
{
	u8 buf[256];
	i64 xorsize;
	i64 i;
	dbuf *f = NULL;

	xorsize = c->infile->len >= 256 ? 256 : c->infile->len;
	de_read(buf, 0, xorsize);
	for(i=0; i<xorsize; i++) {
		buf[i] ^= 0x0d;
	}

	f = dbuf_create_output_file(c, "bmp", NULL, 0);
	dbuf_write(f, buf, xorsize);
	if(c->infile->len > 256) {
		dbuf_copy(c->infile, 256, c->infile->len - 256, f);
	}
	dbuf_close(f);
}

static int de_identify_winzle(deark *c)
{
	u8 b[18];
	de_read(b, 0, sizeof(b));

	if(b[0]==0x4f && b[1]==0x40) {
		if(b[14]==0x25 && b[15]==0x0d && b[16]==0x0d && b[17]==0x0d) {
			return 95;
		}
		return 40;
	}
	return 0;
}

void de_module_winzle(deark *c, struct deark_module_info *mi)
{
	mi->id = "winzle";
	mi->desc = "Winzle! puzzle image";
	mi->run_fn = de_run_winzle;
	mi->identify_fn = de_identify_winzle;
}

// **************************************************************************
// Minolta RAW (MRW)
// **************************************************************************

static void do_mrw_seg_list(deark *c, i64 pos1, i64 len)
{
	i64 pos;
	u8 seg_id[4];
	i64 data_len;

	pos = pos1;
	while(pos < pos1+len) {
		de_read(seg_id, pos, 4);
		data_len = de_getu32be(pos+4);
		pos+=8;
		if(pos+data_len > pos1+len) break;
		if(!de_memcmp(seg_id, "\0TTW", 4)) { // Exif
			fmtutil_handle_exif(c, pos, data_len);
		}
		pos+=data_len;
	}
}

static void de_run_mrw(deark *c, de_module_params *mparams)
{
	i64 mrw_seg_size;

	mrw_seg_size = de_getu32be(4);
	do_mrw_seg_list(c, 8, mrw_seg_size);
}

static int de_identify_mrw(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x00\x4d\x52\x4d", 4))
		return 100;
	return 0;
}

void de_module_mrw(deark *c, struct deark_module_info *mi)
{
	mi->id = "mrw";
	mi->desc = "Minolta RAW";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_mrw;
	mi->identify_fn = de_identify_mrw;
}

// **************************************************************************
// VGA font (intended for development/debugging use)
// **************************************************************************

static void de_run_vgafont(deark *c, de_module_params *mparams)
{
	u8 *fontdata = NULL;
	struct de_bitmap_font *font = NULL;
	i64 i;
	i64 height;

	if(c->infile->len==16*256) {
		height = 16;
	}
	else if(c->infile->len==14*256) {
		height = 14;
	}
	else {
		de_err(c, "Bad file size");
		goto done;
	}

	fontdata = de_malloc(c, height*256);
	de_read(fontdata, 0, height*256);

	if(de_get_ext_option(c, "vgafont:c")) {
		dbuf *ff;
		ff = dbuf_create_output_file(c, "h", NULL, 0);
		for(i=0; i<(height*256); i++) {
			if(i%height==0) dbuf_puts(ff, "\t");
			dbuf_printf(ff, "%d", (int)fontdata[i]);
			if(i!=(height*256-1)) dbuf_puts(ff, ",");
			if(i%height==(height-1)) dbuf_puts(ff, "\n");
		}
		dbuf_close(ff);
		goto done;
	}

	font = de_create_bitmap_font(c);
	font->num_chars = 256;
	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints = 0;
	font->prefer_unicode = 0;
	font->nominal_width = 8;
	font->nominal_height = (int)height;
	font->char_array = de_mallocarray(c, font->num_chars, sizeof(struct de_bitmap_font_char));

	for(i=0; i<font->num_chars; i++) {
		font->char_array[i].codepoint_nonunicode = (i32)i;
		font->char_array[i].width = font->nominal_width;
		font->char_array[i].height = font->nominal_height;
		font->char_array[i].rowspan = 1;
		font->char_array[i].bitmap = &fontdata[i*font->nominal_height];
	}

	de_font_bitmap_font_to_image(c, font, NULL, 0);

done:
	if(font) {
		de_free(c, font->char_array);
		de_destroy_bitmap_font(c, font);
	}
	de_free(c, fontdata);
}

static void de_help_vgafont(deark *c)
{
	de_msg(c, "-opt vgafont:c : Emit C code");
}

void de_module_vgafont(deark *c, struct deark_module_info *mi)
{
	mi->id = "vgafont";
	mi->desc = "Raw 8x16 or 8x14 VGA font";
	mi->run_fn = de_run_vgafont;
	mi->help_fn = de_help_vgafont;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

// **************************************************************************
// ZBR (Zoner Zebra Metafile)
// **************************************************************************

static void de_run_zbr(deark *c, de_module_params *mparams)
{
	i64 pos = 0;
	dbuf *outf = NULL;
	static const u8 hdrs[54] = {
		0x42,0x4d,0xc6,0x14,0,0,0,0,0,0,0x76,0,0,0, // FILEHEADER
		0x28,0,0,0,0x64,0,0,0,0x64,0,0,0,0x01,0,0x04,0, // INFOHEADER...
		0,0,0,0,0x50,0x14,0,0,0,0,0,0,0,0,0,0,
		0x10,0,0,0,0,0,0,0 };

	pos += 4; // signature, version
	pos += 100; // comment

	de_dbg(c, "preview image at %d", (int)pos);
	// By design, this image is formatted as a headerless BMP/DIB. We'll just
	// add the 54 bytes of headers needed to make it a BMP, and call it done.
	outf = dbuf_create_output_file(c, "preview.bmp", NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_write(outf, hdrs, 54);
	dbuf_copy(c->infile, pos, 16*4 + 100*52, outf);
	dbuf_close(outf);
}

static int de_identify_zbr(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x9a\x02", 2)) {
		if(de_input_file_has_ext(c, "zbr")) return 100;
		return 25;
	}
	return 0;
}

void de_module_zbr(deark *c, struct deark_module_info *mi)
{
	mi->id = "zbr";
	mi->desc = "ZBR (Zebra Metafile)";
	mi->desc2 = "extract preview image";
	mi->run_fn = de_run_zbr;
	mi->identify_fn = de_identify_zbr;
}

// **************************************************************************
// compress (.Z)
// **************************************************************************

static void de_run_compress(deark *c, de_module_params *mparams)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_lzw_params delzwp;
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "bin", NULL, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = f;
	dcmpro.len_known = 0;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_UNIXCOMPRESS;
	delzwp.flags |= DE_LZWFLAG_HAS3BYTEHEADER;

	fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);
	if(dres.errcode!=0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
	}
	dbuf_close(f);
}

static int de_identify_compress(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1f\x9d", 2))
		return 100;
	return 0;
}

void de_module_compress(deark *c, struct deark_module_info *mi)
{
	mi->id = "compress";
	mi->desc = "Compress (.Z)";
	mi->run_fn = de_run_compress;
	mi->identify_fn = de_identify_compress;
}

// **************************************************************************
// Hemera Photo-Object image (.hpi)
// **************************************************************************

static void de_run_hpi(deark *c, de_module_params *mparams)
{
	i64 jpgpos, pngpos;
	i64 jpglen, pnglen;
	i64 pos;

	pos = 12;
	jpgpos = de_getu32le_p(&pos);
	jpglen = de_getu32le_p(&pos);
	de_dbg(c, "jpeg: pos=%"I64_FMT", len=%"I64_FMT, jpgpos, jpglen);
	pngpos = de_getu32le_p(&pos);
	pnglen = de_getu32le_p(&pos);
	de_dbg(c, "png: pos=%"I64_FMT", len=%"I64_FMT, pngpos, pnglen);

	if(jpglen>0 && jpgpos+jpglen<=c->infile->len && de_getbyte(jpgpos)==0xff) {
		const char *ext;

		if(pnglen==0) ext="jpg";
		else ext="foreground.jpg";
		dbuf_create_file_from_slice(c->infile, jpgpos, jpglen, ext, NULL, 0);
	}
	if(pnglen>0 && pngpos+pnglen<=c->infile->len && de_getbyte(pngpos)==0x89) {
		dbuf_create_file_from_slice(c->infile, pngpos, pnglen, "mask.png", NULL, 0);
	}
}

static int de_identify_hpi(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x89\x48\x50\x49\x0d\x0a\x1a\x0a", 8)) return 100;
	return 0;
}

void de_module_hpi(deark *c, struct deark_module_info *mi)
{
	mi->id = "hpi";
	mi->desc = "Hemera Photo-Object image";
	mi->run_fn = de_run_hpi;
	mi->identify_fn = de_identify_hpi;
}

// **************************************************************************
// PKWARE DCL Implode compressed file
// **************************************************************************

static void de_run_dclimplode(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = outf;

	fmtutil_dclimplode_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}

	dbuf_close(outf);
}

static int de_identify_dclimplode(deark *c)
{
	u8 b0, b1;
	int i;
	u32 x;

	if(c->infile->len<5) return 0;
	b0 = de_getbyte(0);
	if(b0>1) return 0;
	b1 = de_getbyte(1);
	if(b1<4 || b1>6) return 0;

	// Look for the end-of-data code in the last 2 or 3 bytes.
	// Assumes the last byte is padded with '0' bits, and there are
	// no extraneous bytes after that.
	x = (u32)de_getu32le(c->infile->len-4);
	for(i=0; i<8; i++) {
		if((x & 0xfffffc00U)==0x01fe0000U) {
			if(b0==0 && b1==6) return 40;
			return 10;
		}
		x >>= 1;
	}
	return 0;
}

void de_module_dclimplode(deark *c, struct deark_module_info *mi)
{
	mi->id = "dclimplode";
	mi->id_alias[0] = "ttcomp";
	mi->desc = "PKWARE DCL Implode compressed file";
	mi->run_fn = de_run_dclimplode;
	mi->identify_fn = de_identify_dclimplode;
}

// **************************************************************************
// LZSS (Haruhiko Okumura) compressed file
// **************************************************************************

static void de_run_lzss_oku(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 0;
	dcmpri.len = c->infile->len;
	dcmpro.f = outf;

	fmtutil_decompress_szdd(c, &dcmpri, &dcmpro, &dres, 0x1);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}

	dbuf_close(outf);
}

void de_module_lzss_oku(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzss_oku";
	mi->desc = "LZSS.C by Haruhiko Okumura";
	mi->run_fn = de_run_lzss_oku;
}

// **************************************************************************
// LZHUF (Haruyasu Yoshizaki) compressed file
// **************************************************************************

static void de_run_lzhuf(deark *c, de_module_params *mparams)
{
	i64 unc_filesize;
	dbuf *outf = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	// We're assuming the size field is 4 bytes, little-endian. (But it could
	// be platform-specific.)
#define LZHUF_HDRSIZE 4
#define LZHUF_IS_LE   1

	if(c->infile->len<LZHUF_HDRSIZE) goto done;
	unc_filesize = dbuf_getint_ext(c->infile, 0, LZHUF_HDRSIZE, LZHUF_IS_LE, 0);
	de_dbg(c, "orig filesize: %"I64_FMT, unc_filesize);

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = LZHUF_HDRSIZE;
	dcmpri.len = c->infile->len-LZHUF_HDRSIZE;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = unc_filesize;

	fmtutil_lh1_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}
done:
	dbuf_close(outf);
}

void de_module_lzhuf(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzhuf";
	mi->desc = "LZHUF compressed file";
	mi->run_fn = de_run_lzhuf;
}
