// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// BinHex (.hqx)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_binhex);

typedef struct localctx_struct {
	dbuf *decoded;
	dbuf *decompressed;
} lctx;

// Returns 0-63 if successful, 255 for invalid character.
static de_byte get_char_value(de_byte b)
{
	int k;
	static const de_byte binhexchars[] =
		"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

	for(k=0; k<64; k++) {
		if(b==binhexchars[k]) return (de_byte)k;
	}
	return 255;
}

// Decode the base-64 data, and write to d->decoded.
// Returns 0 if there was an error.
static int do_decode_main(deark *c, lctx *d, de_int64 pos)
{
	de_byte b;
	de_byte x;
	de_byte pending_byte = 0;
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

// Decompress d->decoded, write to d->decompressed
static int do_decompress(deark *c, lctx *d)
{
	de_int64 pos;
	de_byte b;
	de_byte lastbyte = 0x00;
	de_byte countcode;

	pos = 0;
	while(pos < d->decoded->len) {
		b = dbuf_getbyte(d->decoded, pos);
		pos++;
		if(b!=0x90) {
			dbuf_writebyte(d->decompressed, b);
			lastbyte = b;
			continue;
		}

		// b = 0x90, which is a special code.
		countcode = dbuf_getbyte(d->decoded, pos);
		pos++;

		if(countcode==0x00) {
			// Not RLE, just an escaped 0x90 byte.
			dbuf_writebyte(d->decompressed, 0x90);
			lastbyte = 0x90;
			continue;
		}

		// RLE. We already emitted one byte (because the byte to repeat
		// comes before the repeat count), so write countcode-1 bytes.
		dbuf_write_run(d->decompressed, lastbyte, countcode-1);
	}

	de_dbg(c, "size after decompression: %d", (int)d->decompressed->len);
	return 1;
}

static void do_extract_files(deark *c, lctx *d)
{
	de_int64 name_len;
	dbuf *f;
	de_finfo *fi_r = NULL;
	de_finfo *fi_d = NULL;
	de_int64 pos;
	de_int64 dlen, rlen;
	de_int64 hc, dc, rc; // Checksums
	char *filename_buf = NULL;

	f = d->decompressed;
	pos = 0;

	// Read the header

	name_len = (de_int64)dbuf_getbyte(f, pos);
	pos+=1;
	de_dbg(c, "name len: %d", (int)name_len);

	// TODO: What encoding does the name use? Can we convert it?
	fi_r = de_finfo_create(c);
	fi_d = de_finfo_create(c);
	filename_buf = de_malloc(c, 5 + name_len +1);
	dbuf_read(f, (de_byte*)(filename_buf+5), pos, name_len);
	filename_buf[5+name_len] = '\0';
	de_memcpy(filename_buf, "rsrc.", 5);
	de_finfo_set_name_from_sz(c, fi_r, filename_buf, DE_ENCODING_ASCII);
	de_memcpy(filename_buf, "data.", 5);
	de_finfo_set_name_from_sz(c, fi_d, filename_buf, DE_ENCODING_ASCII);

	pos+=name_len;
	pos+=1; // Skip the 0x00 byte after the name.

	// The next (& last) 20 bytes of the header have predictable positions.

	dlen = dbuf_getui32be(f, pos+10);
	rlen = dbuf_getui32be(f, pos+14);
	hc = dbuf_getui16be(f, pos+18);

	de_dbg(c, "data fork len = %d", (int)dlen);
	de_dbg(c, "resource fork len = %d", (int)rlen);
	de_dbg(c, "header checksum = 0x%04x", (unsigned int)hc);

	// TODO: Verify checksums

	pos+=20;

	// Data fork

	if(pos+dlen > f->len) {
		de_err(c, "Data fork goes beyond end of file");
		goto done;
	}

	if(dlen>0)
		dbuf_create_file_from_slice(f, pos, dlen, NULL, fi_d, 0);
	pos += dlen;

	dc = dbuf_getui16be(f, pos);
	pos += 2;
	de_dbg(c, "data fork checksum = 0x%04x", (unsigned int)dc);

	// Resource fork

	if(pos+rlen > f->len) {
		de_err(c, "Resource fork goes beyond end of file");
		goto done;
	}

	if(rlen>0)
		dbuf_create_file_from_slice(f, pos, rlen, NULL, fi_r, 0);
	pos += rlen;

	rc = dbuf_getui16be(f, pos);
	pos += 2;
	de_dbg(c, "resource fork checksum = 0x%04x", (unsigned int)rc);

done:
	de_finfo_destroy(c, fi_r);
	de_finfo_destroy(c, fi_d);
	de_free(c, filename_buf);
}

static void do_binhex(deark *c, lctx *d, de_int64 pos)
{
	int ret;

	de_dbg(c, "BinHex data starts at %d", (int)pos);

	d->decoded = dbuf_create_membuf(c, 65536, 0);
	d->decompressed = dbuf_create_membuf(c, 65536, 0);

	ret = do_decode_main(c, d, pos);
	if(!ret) goto done;

	ret = do_decompress(c, d);
	if(!ret) goto done;

	do_extract_files(c, d);

done:
	dbuf_close(d->decompressed);
	dbuf_close(d->decoded);
	d->decoded = NULL;
}

static int find_start(deark *c, de_int64 *foundpos)
{
	de_int64 pos;
	de_byte b;
	int ret;

	*foundpos = 0;

	ret = dbuf_search(c->infile,
		(const de_byte*)"(This file must be converted with BinHex", 40,
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
	de_int64 pos;
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
	de_int64 foundpos;

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
