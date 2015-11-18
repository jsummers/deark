// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Transfer encodings.
// Base64, etc.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int cbuf_count;
	de_byte cbuf[4];
	de_int64 header_size;
	int fmt;
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

// Returns number of bytes written
static de_int64 do_base64_flush(deark *c, lctx *d, dbuf *f, de_int64 max_to_write)
{
	de_int64 bytes_written = 0;

	if(d->cbuf_count>=2 && bytes_written<max_to_write) {
		dbuf_writebyte(f, (d->cbuf[0]<<2)|(d->cbuf[1]>>4));
		bytes_written++;
	}
	if(d->cbuf_count>=3 && bytes_written<max_to_write) {
		dbuf_writebyte(f, (d->cbuf[1]<<4)|(d->cbuf[2]>>2));
		bytes_written++;
	}
	if(d->cbuf_count>=4 && bytes_written<max_to_write) {
		dbuf_writebyte(f, (d->cbuf[2]<<6)|(d->cbuf[3]));
		bytes_written++;
	}
	d->cbuf_count=0;
	return bytes_written;
}

// Read base64 from c->infile starting at offset 'pos'.
static void do_base64_internal(deark *c, lctx *d, de_int64 pos, dbuf *outf)
{
	de_byte b;
	int found_terminator = 0;
	int bad_warned = 0;

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
			do_base64_flush(c, d, outf, 3);
		}
	}

	if(d->cbuf_count>0) {
		if(!found_terminator || d->cbuf_count==1) {
			de_warn(c, "Unexpected end of Base64 data\n");
		}
		do_base64_flush(c, d, outf, 3);
	}
}

static void de_run_base64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *f = NULL;

	d = de_malloc(c, sizeof(lctx));

	f = dbuf_create_output_file(c, "bin", NULL);
	do_base64_internal(c, d, 0, f);

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

// **************************************************************************
// UUEncoded
// Base-64 UUEncoded
// **************************************************************************

static int uuencode_read_header(deark *c, lctx *d)
{
	int ret;
	de_int64 content_len;

	ret = dbuf_find_line(c->infile, 0, &content_len, &d->header_size);
	if(!ret) return 0;
	if(content_len > 1000) return 0;

	if(!dbuf_memcmp(c->infile, 0, "begin ", 6)) {
		d->fmt = 1;
		return 1;
	}

	if(!dbuf_memcmp(c->infile, 0, "begin-base64 ", 13)) {
		d->fmt = 2;
		return 1;
	}

	de_err(c, "Unrecognized file format\n");
	return 0;
}

static void do_uudecode_main(deark *c, lctx *d, dbuf *outf)
{
	de_int64 pos;
	de_byte b;
	de_byte x;
	int bad_warned = 0;
	int start_of_line_flag;
	de_int64 decoded_bytes_this_line;
	de_int64 expected_decoded_bytes_this_line;

	pos = d->header_size;
	d->cbuf_count = 0;
	decoded_bytes_this_line = 0;
	expected_decoded_bytes_this_line = 0;
	start_of_line_flag = 1;
	d->cbuf_count = 0;

	while(pos<c->infile->len) {
		b = de_getbyte(pos++);

		if(start_of_line_flag && (b==10 || b==13)) {
			continue;
		}

		if(start_of_line_flag) {
			start_of_line_flag = 0;
			if(b==96) {
				expected_decoded_bytes_this_line = 0;
			}
			else if(b>=32 && b<=95) {
				expected_decoded_bytes_this_line = (de_int64)b - 32;
			}
			else if(b=='e') {
				// Maybe the first character of "end"?
				de_warn(c, "Premature end of data\n");
				goto done;
			}

			if(expected_decoded_bytes_this_line==0) {
				// Data is terminated by a line with 0 bytes of data.
				goto done;
			}
			continue;
		}

		if(b==10 || b==13) {
			// End of line
			decoded_bytes_this_line += do_base64_flush(c, d, outf,
				expected_decoded_bytes_this_line-decoded_bytes_this_line);

			if(decoded_bytes_this_line != expected_decoded_bytes_this_line) {
				de_warn(c, "Expected %d bytes on line, got %d\n",
					(int)expected_decoded_bytes_this_line, (int)decoded_bytes_this_line);
			}

			decoded_bytes_this_line = 0;
			start_of_line_flag = 1;
			continue;
		}
		else if(b>=32 && b<=96) {

			x = (b-32)%64;
			d->cbuf[d->cbuf_count++] = x;
			if(d->cbuf_count>=4) {
				decoded_bytes_this_line += do_base64_flush(c, d, outf,
					expected_decoded_bytes_this_line-decoded_bytes_this_line);
			}
		}
		else {
			if(!bad_warned) {
				de_warn(c, "Bad uuencode character (offset %d)\n", (int)pos);
				bad_warned = 1;
			}
		}
	}

done:
	;
}

static void de_run_uuencode(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *f = NULL;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	ret = uuencode_read_header(c, d);
	if(!ret) goto done;
	// TODO: Parse and use the filename

	if(d->fmt==2) {
		de_declare_fmt(c, "Base64 with uuencode wrapper");
		f = dbuf_create_output_file(c, "bin", NULL);
		do_base64_internal(c, d, d->header_size, f);
	}
	else {
		de_declare_fmt(c, "Uuencoded");
		f = dbuf_create_output_file(c, "bin", NULL);
		do_uudecode_main(c, d, f);
	}

done:
	dbuf_close(f);
	de_free(c, d);
}

static int de_isdigit(de_byte x)
{
	return (x>='0' && x<='9');
}

static int de_identify_uuencode(deark *c)
{
	de_byte b[17];

	de_read(b, 0, sizeof(b));

	if(!de_memcmp(b, "begin-base64 ", 13)) {
		return 100;
	}
	if(!de_memcmp(b, "begin nnn ", 6)) {
		if(b[9]==' ' && de_isdigit(b[6]) && de_isdigit(b[7]) &&
			de_isdigit(b[8]))
		{
			return 100;
		}
	}
	return 0;
}

void de_module_uuencode(deark *c, struct deark_module_info *mi)
{
	mi->id = "uuencode";
	mi->desc = "Uuencode";
	mi->run_fn = de_run_uuencode;
	mi->identify_fn = de_identify_uuencode;
}
