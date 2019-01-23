// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// BinHex (.hqx)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_binhex);

typedef struct localctx_struct {
	dbuf *decoded;
	dbuf *decompressed;
	struct de_crcobj *crco;
} lctx;

// Returns 0-63 if successful, 255 for invalid character.
static u8 get_char_value(u8 b)
{
	int k;
	static const u8 binhexchars[] =
		"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

	for(k=0; k<64; k++) {
		if(b==binhexchars[k]) return (u8)k;
	}
	return 255;
}

// Decode the base-64 data, and write to d->decoded.
// Returns 0 if there was an error.
static int do_decode_main(deark *c, lctx *d, i64 pos)
{
	u8 b;
	u8 x;
	u8 pending_byte = 0;
	unsigned int pending_bits_used = 0;

	while(1) {
		if(pos >= c->infile->len) return 0; // unexpected end of file
		b = de_getbyte(pos);
		pos++;
		if(b==':') {
			break;
		}
		else if(b=='\x0a' || b=='\x0d' || b==' ' || b=='\t') {
			// Ignore whitespace
			continue;
		}

		x = get_char_value(b);
		if(x>=64) {
			de_err(c, "Invalid BinHex data at %d", (int)(pos-1));
			return 0;
		}

		// TODO: Simplify this code
		if(pending_bits_used==0) {
			pending_byte = x;
			pending_bits_used = 6;
		}
		else if(pending_bits_used==2) {
			pending_byte = (pending_byte<<(8-pending_bits_used))|x;
			dbuf_writebyte(d->decoded, pending_byte);
			pending_bits_used -= 2;
		}
		else if(pending_bits_used==4) {
			pending_byte = (pending_byte<<(8-pending_bits_used))|(x>>(pending_bits_used-2));
			dbuf_writebyte(d->decoded, pending_byte);
			pending_byte = x&0x03;
			pending_bits_used -= 2;
		}
		else if(pending_bits_used==6) {
			pending_byte = (pending_byte<<(8-pending_bits_used))|(x>>(pending_bits_used-2));
			dbuf_writebyte(d->decoded, pending_byte);
			pending_byte = x&0x0f;
			pending_bits_used -= 2;
		}
	}

	de_dbg(c, "size after decoding: %d", (int)d->decoded->len);
	return 1;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)f->userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

// Returns 0 on fatal error.
static int do_extract_one_file(deark *c, lctx *d, dbuf *inf, i64 pos,
	i64 len, de_finfo *fi, const char *forkname)
{
	u32 crc_reported;
	u32 crc_calc;
	dbuf *outf = NULL;

	if(len==0) return 1;
	if(len<0) return 0;
	if(pos+len > inf->len) {
		de_err(c, "%s fork goes beyond end of file", forkname);
		return 0;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;
	de_crcobj_reset(d->crco);

	dbuf_copy(inf, pos, len, outf);

	dbuf_close(outf);

	// Here, the BinHex spec says we should feed two 0x00 bytes to the CRC
	// calculation, to account for the CRC field itself. However, if I do
	// that, none of files I've tested have the correct CRC. If I don't,
	// all of them have the correct CRC.
	//de_crcobj_addbuf(d->crco, (const u8*)"\0\0", 2);

	crc_reported = (u32)dbuf_getu16be(inf, pos+len);
	de_dbg(c, "%s fork crc (reported): 0x%04x", forkname,
		(unsigned int)crc_reported);

	crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "%s fork crc (calculated): 0x%04x", forkname,
		(unsigned int)crc_calc);

	if(crc_calc != crc_reported) {
		de_err(c, "CRC check failed for %s fork", forkname);
	}

	return 1;
}

static void do_extract_files(deark *c, lctx *d)
{
	i64 name_len;
	dbuf *f;
	de_finfo *fi_r = NULL;
	de_finfo *fi_d = NULL;
	i64 pos;
	i64 dlen, rlen;
	u32 hc; // Header CRC
	de_ucstring *fname = NULL;

	f = d->decompressed;
	pos = 0;

	// Read the header

	name_len = (i64)dbuf_getbyte(f, pos);
	pos+=1;
	de_dbg(c, "name len: %d", (int)name_len);

	fi_r = de_finfo_create(c);
	fi_d = de_finfo_create(c);
	if(name_len > 0) {
		fname = ucstring_create(c);
		dbuf_read_to_ucstring(f, pos, name_len, fname, 0, DE_ENCODING_MACROMAN);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz(fname));
		de_finfo_set_name_from_ucstring(c, fi_d, fname, 0);
		fi_d->original_filename_flag = 1;
		ucstring_append_sz(fname, ".rsrc", DE_ENCODING_LATIN1);
		de_finfo_set_name_from_ucstring(c, fi_r, fname, 0);
	}
	else {
		de_finfo_set_name_from_sz(c, fi_r, "rsrc", 0, DE_ENCODING_LATIN1);
		de_finfo_set_name_from_sz(c, fi_d, "data", 0, DE_ENCODING_LATIN1);
	}

	pos+=name_len;
	pos+=1; // Skip the 0x00 byte after the name.

	// The next (& last) 20 bytes of the header have predictable positions.

	dlen = dbuf_getu32be(f, pos+10);
	rlen = dbuf_getu32be(f, pos+14);
	hc = (u32)dbuf_getu16be(f, pos+18);

	de_dbg(c, "data fork len: %d", (int)dlen);
	de_dbg(c, "resource fork len: %d", (int)rlen);
	de_dbg(c, "header crc (reported): 0x%04x", (unsigned int)hc);

	// TODO: Verify header CRC

	pos+=20;

	// Data fork

	if(!do_extract_one_file(c, d, f, pos, dlen, fi_d, "data")) goto done;
	pos += dlen;
	pos += 2; // for the CRC

	// Resource fork

	if(!do_extract_one_file(c, d, f, pos, rlen, fi_r, "resource")) goto done;
	pos += rlen;
	pos += 2; // for the CRC

done:
	de_finfo_destroy(c, fi_r);
	de_finfo_destroy(c, fi_d);
	ucstring_destroy(fname);
}

static void do_binhex(deark *c, lctx *d, i64 pos)
{
	int ret;

	de_dbg(c, "BinHex data starts at %d", (int)pos);

	d->decoded = dbuf_create_membuf(c, 65536, 0);
	d->decompressed = dbuf_create_membuf(c, 65536, 0);

	ret = do_decode_main(c, d, pos);
	if(!ret) goto done;

	ret = de_fmtutil_decompress_rle90(d->decoded, 0, d->decoded->len, d->decompressed,
		0, 0, 0);
	if(!ret) goto done;
	de_dbg(c, "size after decompression: %d", (int)d->decompressed->len);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);

	do_extract_files(c, d);

done:
	dbuf_close(d->decompressed);
	d->decompressed = NULL;
	dbuf_close(d->decoded);
	d->decoded = NULL;
	de_crcobj_destroy(d->crco);
	d->crco = NULL;
}

static int find_start(deark *c, i64 *foundpos)
{
	i64 pos;
	u8 b;
	int ret;

	*foundpos = 0;

	ret = dbuf_search(c->infile,
		(const u8*)"(This file must be converted with BinHex", 40,
		0, 8192, &pos);
	if(!ret) return 0;

	pos += 40;

	// Find the next CR/LF byte
	while(1) {
		b = de_getbyte(pos);
		pos++;
		if(b=='\x0a' || b=='\x0d') {
			break;
		}
	}

	// Skip any number of additional whitespace
	while(1) {
		b = de_getbyte(pos);
		if(b=='\x0a' || b=='\x0d' || b==' ' || b=='\t') {
			pos++;
		}
		else {
			break;
		}
	}

	// Current byte should be a colon (:)
	b = de_getbyte(pos);
	if(b==':') {
		*foundpos = pos+1;
		return 1;
	}

	return 0;
}

static void de_run_binhex(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	ret = find_start(c, &pos);
	if(!ret) {
		de_err(c, "Not a BinHex file");
		goto done;
	}

	do_binhex(c, d, pos);

done:
	de_free(c, d);
}

static int de_identify_binhex(deark *c)
{
	int ret;
	i64 foundpos;

	if(!dbuf_memcmp(c->infile, 0,
		"(This file must be converted with BinHex", 40))
	{
		return 100;
	}

	if(!de_input_file_has_ext(c, "hqx")) return 0;

	// File has .hqx extension. Try harder to identify it.
	ret = find_start(c, &foundpos);
	if(ret) return 100;

	return 0;
}

void de_module_binhex(deark *c, struct deark_module_info *mi)
{
	mi->id = "binhex";
	mi->desc = "Macintosh BinHex (.hqx) archive";
	mi->run_fn = de_run_binhex;
	mi->identify_fn = de_identify_binhex;
}
