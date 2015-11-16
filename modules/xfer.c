// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Transfer encodings.
// Base64, etc.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int cbuf_count;
	de_byte cbuf[4];
} lctx;

// **************************************************************************
// Base16 / Hex encoding
// **************************************************************************

static void de_run_base16(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	dbuf *f = NULL;
	de_byte b;
	int bad_warned = 0;

	d = de_malloc(c, sizeof(lctx));

	f = dbuf_create_output_file(c, "bin", NULL);

	pos = 0;
	d->cbuf_count = 0;
	while(pos<c->infile->len) {
		b = de_getbyte(pos++);
		if(b>='0' && b<='9') {
			d->cbuf[d->cbuf_count++] = b-48;
		}
		else if(b>='A' && b<='F') {
			d->cbuf[d->cbuf_count++] = b-55;
		}
		else if(b>='a' && b<='f') {
			d->cbuf[d->cbuf_count++] = b-87;
		}
		else if(b==9 || b==10 || b==13 || b==32) {
			; // ignore whitespace
		}
		else {
			if(!bad_warned) {
				de_warn(c, "Bad hex character(s) found (offset %d)\n", (int)pos);
				bad_warned = 1;
			}
		}

		if(d->cbuf_count>=2) {
			dbuf_writebyte(f, (d->cbuf[0]<<4)|(d->cbuf[1]));
			d->cbuf_count=0;
		}
	}

	if(d->cbuf_count>0) {
		de_warn(c, "Unexpected end of hex data\n");
	}

	dbuf_close(f);
	de_free(c, d);
}

void de_module_base16(deark *c, struct deark_module_info *mi)
{
	mi->id = "base16";
	mi->id_alias[0] = "hex";
	mi->desc = "Base16";
	mi->run_fn = de_run_base16;
	mi->identify_fn = de_identify_none;
}

// **************************************************************************
// Base64
// **************************************************************************

static void do_base64_flush(deark *c, lctx *d, dbuf *f)
{
	if(d->cbuf_count>=2)
		dbuf_writebyte(f, (d->cbuf[0]<<2)|(d->cbuf[1]>>4));
	if(d->cbuf_count>=3)
		dbuf_writebyte(f, (d->cbuf[1]<<4)|(d->cbuf[2]>>2));
	if(d->cbuf_count>=4)
		dbuf_writebyte(f, (d->cbuf[2]<<6)|(d->cbuf[3]));
	d->cbuf_count=0;
}

static void de_run_base64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	dbuf *f = NULL;
	de_byte b;
	int found_terminator = 0;
	int bad_warned = 0;

	d = de_malloc(c, sizeof(lctx));

	f = dbuf_create_output_file(c, "bin", NULL);

	pos = 0;
	d->cbuf_count = 0;
	while(pos<c->infile->len) {
		b = de_getbyte(pos++);
		if(b>='A' && b<='Z') {
			d->cbuf[d->cbuf_count++] = b-65;
		}
		else if(b>='a' && b<='z') {
			d->cbuf[d->cbuf_count++] = b-71;
		}
		else if(b>='0' && b<='9') {
			d->cbuf[d->cbuf_count++] = b+4;
		}
		else if(b=='+') {
			d->cbuf[d->cbuf_count++] = 62;
		}
		else if(b=='/') {
			d->cbuf[d->cbuf_count++] = 63;
		}
		else if(b=='=') {
			found_terminator = 1;
			break;
		}
		else if(b==9 || b==10 || b==13 || b==32) {
			; // ignore whitespace
		}
		else {
			if(!bad_warned) {
				de_warn(c, "Bad Base64 character(s) found (offset %d)\n", (int)pos);
				bad_warned = 1;
			}
		}

		if(d->cbuf_count>=4) {
			do_base64_flush(c, d, f);
		}
	}

	if(d->cbuf_count>0) {
		if(!found_terminator || d->cbuf_count==1) {
			de_warn(c, "Unexpected end of Base64 data\n");
		}
		do_base64_flush(c, d, f);
	}

	dbuf_close(f);
	de_free(c, d);
}

void de_module_base64(deark *c, struct deark_module_info *mi)
{
	mi->id = "base64";
	mi->desc = "Base64";
	mi->run_fn = de_run_base64;
	mi->identify_fn = de_identify_none;
}
