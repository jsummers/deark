// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// BinHex (.hqx)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_binhex);

struct binhex_forkinfo {
	i64 pos; // position in d->decompressed
	i64 len;
	u32 crc_reported;
	struct de_crcobj *crco;
	const char *forkname;
};

typedef struct localctx_struct {
	int input_encoding;
	dbuf *decoded;
	dbuf *decompressed;
	struct de_advfile *advf;
	struct binhex_forkinfo fki_data;
	struct binhex_forkinfo fki_rsrc;
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

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	lctx *d = (lctx*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		dbuf_copy(d->decompressed, d->fki_data.pos, advf->mainfork.fork_len, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		dbuf_copy(d->decompressed, d->fki_rsrc.pos, advf->rsrcfork.fork_len, afp->outf);
	}

	return 1;
}

// Returns 0 if there is a serious error with this fork.
static int do_pre_extract_fork(deark *c, lctx *d, dbuf *inf, struct binhex_forkinfo *fki,
	struct de_advfile_forkinfo *advfki)
{
	fki->crc_reported = (u32)dbuf_getu16be(inf, fki->pos + fki->len);
	de_dbg(c, "%s fork crc (reported): 0x%04x", fki->forkname,
		(unsigned int)fki->crc_reported);

	advfki->writelistener_cb = our_writelistener_cb;
	advfki->userdata_for_writelistener = (void*)fki->crco;

	if((fki->pos + fki->len > inf->len) && fki->len!=0) {
		de_err(c, "%s fork goes beyond end of file", fki->forkname);
		fki->len = 0;
		return 0;
	}
	return 1;
}

static void do_post_extract_fork(deark *c, lctx *d, struct binhex_forkinfo *fki)
{
	u32 crc_calc;

	// Here, the BinHex spec says we should feed two 0x00 bytes to the CRC
	// calculation, to account for the CRC field itself. However, if I do
	// that, none of files I've tested have the correct CRC. If I don't,
	// all of them have the correct CRC.
	//de_crcobj_addbuf(fki->crco, (const u8*)"\0\0", 2);

	crc_calc = de_crcobj_getval(fki->crco);
	de_dbg(c, "%s fork crc (calculated): 0x%04x", fki->forkname,
		(unsigned int)crc_calc);
	if(crc_calc != fki->crc_reported) {
		de_err(c, "CRC check failed for %s fork", fki->forkname);
	}
}

static void do_extract_forks(deark *c, lctx *d)
{
	i64 name_len;
	dbuf *inf;
	i64 pos;
	u32 hc; // Header CRC
	struct de_stringreaderdata *fname = NULL;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	inf = d->decompressed;
	pos = 0;

	// Read the header

	name_len = (i64)dbuf_getbyte(inf, pos);
	pos+=1;
	de_dbg(c, "name len: %d", (int)name_len);

	if(name_len > 0) {
		fname = dbuf_read_string(inf, pos, name_len, name_len, 0, d->input_encoding);
		ucstring_append_ucstring(d->advf->filename, fname->str);
		d->advf->original_filename_flag = 1;
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(fname->str));
		de_advfile_set_orig_filename(d->advf, fname->sz, fname->sz_strlen);
	}
	else {
		ucstring_append_sz(d->advf->filename, "bin", DE_ENCODING_LATIN1);
	}

	pos+=name_len;
	pos+=1; // Skip the 0x00 byte after the name.

	dbuf_read_fourcc(inf, pos, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	de_memcpy(d->advf->typecode, filetype.bytes, 4);
	d->advf->has_typecode = 1;
	pos += 4;
	dbuf_read_fourcc(inf, pos, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);
	de_memcpy(d->advf->creatorcode, creator.bytes, 4);
	d->advf->has_creatorcode = 1;
	pos += 4;

	d->advf->finderflags = (u16)dbuf_getu16be_p(inf, &pos);
	d->advf->has_finderflags = 1;
	de_dbg(c, "flags: 0x%04x", (unsigned int)d->advf->finderflags);

	d->fki_data.len = dbuf_getu32be_p(inf, &pos);
	de_dbg(c, "data fork len: %d", (int)d->fki_data.len);
	d->fki_rsrc.len = dbuf_getu32be_p(inf, &pos);
	de_dbg(c, "resource fork len: %d", (int)d->fki_rsrc.len);

	hc = (u32)dbuf_getu16be_p(inf, &pos);
	de_dbg(c, "header crc (reported): 0x%04x", (unsigned int)hc);
	// TODO: Verify header CRC

	d->fki_data.forkname = "data";
	d->fki_rsrc.forkname = "rsrc";

	// Walk through the file, and record some offsets
	d->fki_data.pos = pos;
	pos += d->fki_data.len;
	pos += 2; // for the CRC

	d->fki_rsrc.pos = pos;
	// [d->fki_rsrc.len bytes here]
	// [2 bytes here, for the CRC]

	d->fki_data.crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
	d->fki_rsrc.crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);

	if(!do_pre_extract_fork(c, d, inf, &d->fki_data, &d->advf->mainfork)) {
		goto done;
	}
	(void)do_pre_extract_fork(c, d, inf, &d->fki_rsrc, &d->advf->rsrcfork);

	d->advf->mainfork.fork_exists = (d->fki_data.len > 0);
	d->advf->mainfork.fork_len = d->fki_data.len;
	d->advf->rsrcfork.fork_exists = (d->fki_rsrc.len > 0);
	d->advf->rsrcfork.fork_len = d->fki_rsrc.len;
	d->advf->userdata = (void*)d;
	d->advf->writefork_cbfn = my_advfile_cbfn;

	de_advfile_run(d->advf);

	do_post_extract_fork(c, d, &d->fki_data);
	do_post_extract_fork(c, d, &d->fki_rsrc);

done:
	de_destroy_stringreaderdata(c, fname);
	de_crcobj_destroy(d->fki_data.crco);
	d->fki_data.crco = NULL;
	de_crcobj_destroy(d->fki_rsrc.crco);
	d->fki_rsrc.crco = NULL;
}

static void do_binhex(deark *c, lctx *d, i64 pos)
{
	int ret;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg(c, "BinHex data starts at %d", (int)pos);

	d->decoded = dbuf_create_membuf(c, 65536, 0);
	d->decompressed = dbuf_create_membuf(c, 65536, 0);

	ret = do_decode_main(c, d, pos);
	if(!ret) goto done;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = d->decoded;
	dcmpri.pos = 0;
	dcmpri.len = d->decoded->len;
	dcmpro.f = d->decompressed;
	de_fmtutil_decompress_rle90_ex(c, &dcmpri, &dcmpro, &dres, 0);
	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}
	de_dbg(c, "size after decompression: %d", (int)d->decompressed->len);

	d->advf = de_advfile_create(c);

	do_extract_forks(c, d);

done:
	de_advfile_destroy(d->advf);
	d->advf = NULL;
	dbuf_close(d->decompressed);
	d->decompressed = NULL;
	dbuf_close(d->decoded);
	d->decoded = NULL;
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
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);

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
