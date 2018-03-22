// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Transfer encodings.
// Base64, etc.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_base16);
DE_DECLARE_MODULE(de_module_base64);
DE_DECLARE_MODULE(de_module_uuencode);
DE_DECLARE_MODULE(de_module_xxencode);
DE_DECLARE_MODULE(de_module_ascii85);

typedef struct localctx_struct {
	int cbuf_count;
	de_byte cbuf[5];

#define FMT_BASE64    1
#define FMT_UUENCODE  2
#define FMT_XXENCODE  3
	int data_fmt;

#define HDR_UUENCODE_OR_XXENCODE  11
#define HDR_UUENCODE_BASE64       12
	int hdr_line_type;
	de_int64 hdr_line_startpos;
	de_int64 hdr_line_len;
	de_int64 data_startpos;

#define ASCII85_FMT_BTOA_OLD  21
#define ASCII85_FMT_BTOA_NEW  22
#define ASCII85_FMT_STANDARD  23
	int ascii85_fmt;

	de_int64 bytes_written;
	de_int64 output_filesize;
	int output_filesize_known;
	de_finfo *fi;
} lctx;

static de_int64 bom_length(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xef\xbb\xbf", 3))
		return 3;
	return 0;
}

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

	f = dbuf_create_output_file(c, "bin", NULL, 0);

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
				de_warn(c, "Bad hex character(s) found (offset %d)", (int)pos);
				bad_warned = 1;
			}
		}

		if(d->cbuf_count>=2) {
			dbuf_writebyte(f, (d->cbuf[0]<<4)|(d->cbuf[1]));
			d->cbuf_count=0;
		}
	}

	if(d->cbuf_count>0) {
		de_warn(c, "Unexpected end of hex data");
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
				de_warn(c, "Bad Base64 character(s) found (offset %d)", (int)pos);
				bad_warned = 1;
			}
		}

		if(d->cbuf_count>=4) {
			do_base64_flush(c, d, outf, 3);
		}
	}

	if(d->cbuf_count>0) {
		if(!found_terminator || d->cbuf_count==1) {
			de_warn(c, "Unexpected end of Base64 data");
		}
		do_base64_flush(c, d, outf, 3);
	}
}

static void de_run_base64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *f = NULL;

	d = de_malloc(c, sizeof(lctx));

	f = dbuf_create_output_file(c, "bin", NULL, 0);
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

// Caller passes buf (not NUL terminated) to us.
static void parse_begin_line(deark *c, lctx *d, const de_byte *buf, de_int64 buf_len)
{
	de_int64 beginsize;
	de_ucstring *fn = NULL;
	de_int64 mode;
	size_t nbytes_to_copy;
	char tmpbuf[32];

	if(!d->fi) goto done;

	if(d->hdr_line_type==HDR_UUENCODE_OR_XXENCODE) {
		beginsize = 5; // "begin" has 5 letters
	}
	else if(d->hdr_line_type==HDR_UUENCODE_BASE64) {
		beginsize = 12; // "begin-base64"
	}
	else {
		goto done;
	}

	if(buf_len<beginsize+6 || buf[beginsize]!=' ' || buf[beginsize+4]!=' ') {
		goto done;
	}

	// Make a NUL-terminated copy of the file permissions mode.
	nbytes_to_copy = (size_t)(buf_len - (beginsize+1));
	if(nbytes_to_copy>sizeof(tmpbuf)) nbytes_to_copy = sizeof(tmpbuf);
	de_strlcpy(tmpbuf, (const char*)&buf[beginsize+1], nbytes_to_copy);
	mode = de_strtoll(tmpbuf, NULL, 8);
	de_dbg(c, "mode: %03o", (unsigned int)mode);
	if((mode & 0111)!=0) {
		d->fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else {
		d->fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	fn = ucstring_create(c);
	ucstring_append_bytes(fn, &buf[beginsize+5], buf_len-(beginsize+5), 0, DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(fn));
	de_finfo_set_name_from_ucstring(c, d->fi, fn);
	d->fi->original_filename_flag = 1;

done:
	ucstring_destroy(fn);
}

static int uuencode_read_header(deark *c, lctx *d)
{
	int ret;
	de_int64 total_len;
	de_int64 line_count;
	de_byte linebuf[500];
	de_int64 nbytes_in_linebuf;

	d->hdr_line_startpos = bom_length(c);
	line_count=0;
	while(line_count<100) {
		ret = dbuf_find_line(c->infile, d->hdr_line_startpos,
			&d->hdr_line_len, &total_len);
		if(!ret) return 0;
		if(d->hdr_line_len > 1000) return 0;

		nbytes_in_linebuf = (de_int64)sizeof(linebuf);
		if(d->hdr_line_len < nbytes_in_linebuf)
			nbytes_in_linebuf = d->hdr_line_len;
		de_read(linebuf, d->hdr_line_startpos, nbytes_in_linebuf);

		d->data_startpos = d->hdr_line_startpos + total_len;

		if(nbytes_in_linebuf>=9 && !de_memcmp(linebuf, "begin ", 6)) {
			d->hdr_line_type = HDR_UUENCODE_OR_XXENCODE;
			parse_begin_line(c, d, linebuf, nbytes_in_linebuf);
			return 1;
		}

		if(nbytes_in_linebuf>=16 && !de_memcmp(linebuf, "begin-base64 ", 13)) {
			d->hdr_line_type = HDR_UUENCODE_BASE64;
			parse_begin_line(c, d, linebuf, nbytes_in_linebuf);
			return 1;
		}

		d->hdr_line_startpos += total_len;
		line_count++;
	}

	de_err(c, "Unrecognized file format");
	d->hdr_line_type = 0;
	return 0;
}

static int get_uu_byte_value(deark *c, lctx *d, de_byte b, de_byte *val)
{
	if(d->data_fmt==FMT_XXENCODE) {
		if(b>='0' && b<='9') *val = b-46;
		else if(b>='A' && b<='Z') *val = b-53;
		else if(b>='a' && b<='z') *val = b-59;
		else if(b=='+') *val = 0;
		else if(b=='-') *val = 1;
		else {
			*val = 0;
			return 0;
		}
		return 1;
	}

	// Standard UUEncoding
	if(b>=32 && b<=96) {
		*val = (b-32)%64;
		return 1;
	}
	*val = 0;
	return 0;
}

// Data is decoded from c->infile, starting at d->data_startpos.
static void do_uudecode_internal(deark *c, lctx *d, dbuf *outf)
{
	de_int64 pos;
	int ret;
	de_byte b;
	de_byte x;
	int bad_warned = 0;
	int start_of_line_flag;
	de_int64 decoded_bytes_this_line;
	de_int64 expected_decoded_bytes_this_line;

	pos = d->data_startpos;
	d->cbuf_count = 0;
	decoded_bytes_this_line = 0;
	expected_decoded_bytes_this_line = 0;
	start_of_line_flag = 1;
	d->cbuf_count = 0;

	while(pos<c->infile->len) {
		b = de_getbyte(pos++);

		if(start_of_line_flag && (b==10 || b==13)) {
			// Multi-byte EOL sequence, or blank line
			continue;
		}

		if(start_of_line_flag) {
			start_of_line_flag = 0;

			ret = get_uu_byte_value(c, d, b, &x);
			if(!ret) {
				if(b=='e' && d->data_fmt==FMT_UUENCODE) {
					// Assume this is the "end" footer line.
					goto done;
				}
				de_err(c, "Bad uuencoded data (offset %d)", (int)pos);
				goto done;
			}

			expected_decoded_bytes_this_line = x;
			if(expected_decoded_bytes_this_line==0) {
				goto done;
			}
			continue;
		}

		if(b==10 || b==13) {
			// End of line
			decoded_bytes_this_line += do_base64_flush(c, d, outf,
				expected_decoded_bytes_this_line-decoded_bytes_this_line);

			if(decoded_bytes_this_line != expected_decoded_bytes_this_line) {
				de_warn(c, "Expected %d bytes on line, got %d",
					(int)expected_decoded_bytes_this_line, (int)decoded_bytes_this_line);
			}

			if(decoded_bytes_this_line<45 &&
				decoded_bytes_this_line==expected_decoded_bytes_this_line)
			{
				// Assume a short line means end of data.
				goto done;
			}

			decoded_bytes_this_line = 0;
			start_of_line_flag = 1;
			continue;
		}

		// Expecting a regular data byte
		ret = get_uu_byte_value(c, d, b, &x);
		if(ret) {
			d->cbuf[d->cbuf_count++] = x;
			if(d->cbuf_count>=4) {
				decoded_bytes_this_line += do_base64_flush(c, d, outf,
					expected_decoded_bytes_this_line-decoded_bytes_this_line);
			}
		}
		else {
			if(!bad_warned) {
				de_warn(c, "Bad uuencode character (offset %d)", (int)pos);
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

	d->fi = de_finfo_create(c);
	ret = uuencode_read_header(c, d);
	if(!ret) goto done;

	if(d->hdr_line_type==HDR_UUENCODE_BASE64) {
		de_declare_fmt(c, "Base64 with uuencode wrapper");
		d->data_fmt = FMT_BASE64;
		f = dbuf_create_output_file(c, NULL, d->fi, 0);
		do_base64_internal(c, d, d->data_startpos, f);
	}
	else {
		de_declare_fmt(c, "Uuencoded");
		d->data_fmt = FMT_UUENCODE;
		f = dbuf_create_output_file(c, NULL, d->fi, 0);
		do_uudecode_internal(c, d, f);
	}

done:
	dbuf_close(f);
	de_finfo_destroy(c, d->fi);
	de_free(c, d);
}

static int de_is_digit(de_byte x)
{
	return (x>='0' && x<='9');
}

static int de_is_digit_string(const de_byte *s, de_int64 len)
{
	de_int64 i;
	for(i=0; i<len; i++) {
		if(!de_is_digit(s[i])) return 0;
	}
	return 1;
}

static int de_identify_uuencode(deark *c)
{
	de_byte b[17];
	de_int64 pos;

	pos = c->detection_data.has_utf8_bom?3:0;
	de_read(b, pos, sizeof(b));

	if(!de_memcmp(b, "begin-base64 ", 13)) {
		return 100;
	}
	if(!de_memcmp(b, "begin ", 6)) {
		if(b[9]==' ' && de_is_digit_string(&b[6], 3)) {
			// This needs to be lower than XXEncode.
			return 85;
		}
	}
	return 0;
}

void de_module_uuencode(deark *c, struct deark_module_info *mi)
{
	mi->id = "uuencode";
	mi->desc = "UUEncode";
	mi->run_fn = de_run_uuencode;
	mi->identify_fn = de_identify_uuencode;
}

// **************************************************************************
// XXEncoded
// **************************************************************************

static void de_run_xxencode(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *f = NULL;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	d->fi = de_finfo_create(c);
	ret = uuencode_read_header(c, d);
	if(!ret) goto done;
	if(d->hdr_line_type!=HDR_UUENCODE_OR_XXENCODE) goto done;

	de_declare_fmt(c, "XXEncoded");
	f = dbuf_create_output_file(c, NULL, d->fi, 0);
	d->data_fmt = FMT_XXENCODE;
	do_uudecode_internal(c, d, f);

done:
	dbuf_close(f);
	de_finfo_destroy(c, d->fi);
	de_free(c, d);
}

static int de_identify_xxencode(deark *c)
{
	de_byte b[10];
	de_int64 pos;

	// XXEncode is hard to distinguish from UUEncode, so we rely on the
	// filename.
	if(!de_input_file_has_ext(c, "xxe") &&
		!de_input_file_has_ext(c, "xx"))
	{
		return 0;
	}

	pos = c->detection_data.has_utf8_bom?3:0;
	de_read(b, pos, 10);

	if(!de_memcmp(b, "begin ", 6)) {
		if(b[9]==' ' && de_is_digit_string(&b[6], 3)) {
			return 90;
		}
	}
	else if(!de_memcmp(b, "\x0a---------", 10)) {
		// At least one xxencode utility creates files that starts this way.
		return 80;
	}

	return 0;
}

void de_module_xxencode(deark *c, struct deark_module_info *mi)
{
	mi->id = "xxencode";
	mi->desc = "XXEncode";
	mi->run_fn = de_run_xxencode;
	mi->identify_fn = de_identify_xxencode;
}

// **************************************************************************
// Ascii85 / btoa
// **************************************************************************

static void do_ascii85_flush(deark *c, lctx *d, dbuf *f)
{
	de_int64 i;
	de_uint32 code;

	if(d->cbuf_count<1) return;

	code = (de_uint32)d->cbuf[0];
	for(i=1; i<5; i++) {
		if(i<d->cbuf_count)
			code = code*85 + (de_uint32)d->cbuf[i];
		else
			code = code*85 + 84; // (This shouldn't happen with btoa format)
	}

	// TODO: Simplify this code
	if(d->cbuf_count>=2) {
		dbuf_writebyte(f, (de_byte)((code>>24)&0xff));
		d->bytes_written++;
		if(d->output_filesize_known && d->bytes_written>=d->output_filesize) goto done;
	}
	if(d->cbuf_count>=3) {
		dbuf_writebyte(f, (de_byte)((code>>16)&0xff));
		d->bytes_written++;
		if(d->output_filesize_known && d->bytes_written>=d->output_filesize) goto done;
	}
	if(d->cbuf_count>=4) {
		dbuf_writebyte(f, (de_byte)((code>>8)&0xff));
		d->bytes_written++;
		if(d->output_filesize_known && d->bytes_written>=d->output_filesize) goto done;
	}
	if(d->cbuf_count>=5) {
		dbuf_writebyte(f, (de_byte)(code&0xff));
		d->bytes_written++;
		if(d->output_filesize_known && d->bytes_written>=d->output_filesize) goto done;
	}

done:
	d->cbuf_count = 0;
}

static void do_ascii85_data_char_processed(deark *c, lctx *d, dbuf *f, de_int64 linenum,
	 de_byte x)
{
	// Write to the output file immediately before we empty cbuf, instead of
	// immediately after we fill it.
	// This is necessary because (in old btoa format at least) we don't yet
	// know the file size.
	// Until we know that, we don't know how many bytes need to be written for
	// the very last group.
	if(d->cbuf_count>=5) {
		do_ascii85_flush(c, d, f);
	}

	d->cbuf[d->cbuf_count] = x;
	d->cbuf_count++;
}

static void do_ascii85_data_char_raw(deark *c, lctx *d, dbuf *f, de_int64 linenum,
	 const de_byte x)
{
	de_int64 k;

	if(x>='!' && x<='u') {
		do_ascii85_data_char_processed(c, d, f, linenum, x-33);
	}
	else if(x=='z') {
		// 'z' represents four 0x00 bytes, which encodes to five 0 values
		// (not including the +33 bias).
		for(k=0; k<5; k++)
			do_ascii85_data_char_processed(c, d, f, linenum, 0);
	}
	else if(x=='y' && d->ascii85_fmt==ASCII85_FMT_BTOA_NEW) {
		// This is what four spaces encodes to (not including the +33 bias).
		do_ascii85_data_char_processed(c, d, f, linenum, 0x0a);
		do_ascii85_data_char_processed(c, d, f, linenum, 0x1b);
		do_ascii85_data_char_processed(c, d, f, linenum, 0x35);
		do_ascii85_data_char_processed(c, d, f, linenum, 0x43);
		do_ascii85_data_char_processed(c, d, f, linenum, 0x2b);
	}
}

static void do_ascii85_data_line(deark *c, lctx *d, dbuf *f, de_int64 linenum,
	 const de_byte *linebuf, de_int64 line_len)
{
	de_int64 i;
	de_int64 num_data_chars;

	if(line_len<1) return;

	if(d->ascii85_fmt==ASCII85_FMT_BTOA_NEW)
		num_data_chars = line_len-1; // The last character is a checksum
	else
		num_data_chars = line_len;

	for(i=0; i<num_data_chars; i++) {
		do_ascii85_data_char_raw(c, d, f, linenum, linebuf[i]);
	}

	// TODO: Verify the checksum character, if present.
}

static int do_ascii85_read_btoa_end_line(deark *c, lctx *d, de_int64 linenum,
	const de_byte *linebuf, de_int64 line_len)
{
	long filesize1 = 0;

	de_dbg(c, "btoa footer at line %d", (int)linenum);
	if(de_sscanf((const char *)linebuf, "xbtoa End N %ld ", &filesize1) != 1) {
		de_err(c, "Bad btoa End line");
		return 0;
	}

	d->output_filesize = (de_int64)filesize1;
	d->output_filesize_known = 1;
	de_dbg(c, "reported file size: %d", (int)d->output_filesize);
	return 1;
}

static void do_ascii85_btoa(deark *c, lctx *d, dbuf *f)
{
	de_int64 pos;
	de_int64 content_len;
	de_int64 total_len;
	de_byte linebuf[1024];
	de_int64 linenum;

	pos = 0;
	d->cbuf_count = 0;
	linenum = 0;

	while(1) {
		if(!dbuf_find_line(c->infile, pos, &content_len, &total_len)) {
			de_err(c, "Bad Ascii85 format at line %d", (int)linenum);
			goto done;
		}
		linenum++;

		if(content_len > (de_int64)(sizeof(linebuf)-1)) {
			de_err(c, "Line %d too long", (int)linenum);
			goto done;
		}
		de_read(linebuf, pos, content_len);
		linebuf[content_len] = '\0'; // NUL terminate, in case we run sscanf
		pos += total_len;

		if(content_len<1) continue;

		if(linebuf[0]=='x') {
			if(content_len>=7 && !de_memcmp(linebuf, "xbtoa5 ", 7)) {
				de_dbg(c, "btoa new format header at line %d", (int)linenum);
				d->ascii85_fmt = ASCII85_FMT_BTOA_NEW;
			}
			else if(content_len>=11 && !de_memcmp(linebuf, "xbtoa Begin", 11)) {
				de_dbg(c, "btoa old format header at line %d", (int)linenum);
			}
			else if(content_len>=9 && !de_memcmp(linebuf, "xbtoa End", 9)) {
				if(!do_ascii85_read_btoa_end_line(c, d, linenum, linebuf, content_len)) {
					goto done;
				}
				break;
			}

			continue;
		}

		do_ascii85_data_line(c, d, f, linenum, linebuf, content_len);
	}

	do_ascii85_flush(c, d, f);

	if(d->output_filesize_known && (d->bytes_written != d->output_filesize)) {
		de_err(c, "Expected output file size=%d, actual size=%d", (int)d->output_filesize,
			(int)d->bytes_written);
	}

done:
	;
}

static void do_ascii85_standard(deark *c, lctx *d, dbuf *f, de_int64 pos)
{
	de_byte x;

	d->cbuf_count = 0;

	while(1) {
		if(pos >= c->infile->len) break;
		x = de_getbyte(pos++);
		if(x=='~') {
			break;
		}
		do_ascii85_data_char_raw(c, d, f, 0, x);
	}

	do_ascii85_flush(c, d, f);
}

static int ascii85_detect_fmt(deark *c)
{
	de_byte buf[11];

	de_read(buf, 0, 11);

	if(!de_memcmp(buf, "xbtoa Begin", 11)) {
		return ASCII85_FMT_BTOA_OLD;
	}
	else if(!dbuf_memcmp(c->infile, 0, "xbtoa5 ", 7)) {
		return ASCII85_FMT_BTOA_NEW;
	}
	else if(!dbuf_memcmp(c->infile, 0, "<~", 2)) {
		return ASCII85_FMT_STANDARD;
	}
	return 0;
}

static void de_run_ascii85(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	dbuf *f = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->ascii85_fmt = ascii85_detect_fmt(c);
	if(d->ascii85_fmt==0) {
		// TODO: Scan the file to try to detect the format.
		de_err(c, "Unknown Ascii85 format");
		goto done;
	}

	f = dbuf_create_output_file(c, "bin", NULL, 0);

	if(d->ascii85_fmt==ASCII85_FMT_BTOA_OLD ||
		d->ascii85_fmt==ASCII85_FMT_BTOA_NEW)
	{
		do_ascii85_btoa(c, d, f);
	}
	else if(d->ascii85_fmt==ASCII85_FMT_STANDARD) {
		do_ascii85_standard(c, d, f, 2);
	}

done:
	dbuf_close(f);
	de_free(c, d);
}

static int de_identify_ascii85(deark *c)
{
	int fmt;

	fmt = ascii85_detect_fmt(c);

	if(fmt==ASCII85_FMT_BTOA_OLD) {
		return 100;
	}
	else if(fmt==ASCII85_FMT_BTOA_NEW) {
		return 100;
	}
	else if(fmt==ASCII85_FMT_STANDARD) {
		return 10;
	}

	return 0;
}

void de_module_ascii85(deark *c, struct deark_module_info *mi)
{
	mi->id = "ascii85";
	mi->desc = "Ascii85";
	mi->run_fn = de_run_ascii85;
	mi->identify_fn = de_identify_ascii85;
}
