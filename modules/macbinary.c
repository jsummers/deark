// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// MacBinary

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_macbinary);

typedef struct localctx_struct {
	de_byte extract_files;
	de_byte oldver;
	de_byte ver2;
	de_byte ver2_minneeded;
	de_int64 dflen, rflen;
	de_ucstring *filename;
	struct de_timestamp create_date;
	struct de_timestamp mod_date;
} lctx;

static void do_header(deark *c, lctx *d)
{
	de_byte b;
	de_byte fflags;
	de_int64 namelen;
	de_int64 pos = 0;
	de_int64 n, n2;
	struct de_fourcc type4cc;
	struct de_fourcc creator4cc;
	char timestamp_buf[64];

	d->oldver = de_getbyte_p(&pos);
	de_dbg(c, "original version: %u", (unsigned int)d->oldver);
	if(d->oldver!=0) {
		de_warn(c, "Unsupported MacBinary version");
		goto done;
	}

	d->ver2 = de_getbyte(122);
	de_dbg(c, "MacBinary II version: %u", (unsigned int)d->ver2);
	if(d->ver2 >= 129) {
		d->ver2_minneeded = de_getbyte(123);
		de_dbg(c, "MacBinary II version, min needed: %u", (unsigned int)d->ver2_minneeded);
	}

	namelen = (de_int64)de_getbyte_p(&pos);
	if(namelen>=1 && namelen<=63) {
		// Required to be 1-63 by MacBinary II spec.
		// Original spec has no written requirements.
		d->filename = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, namelen, d->filename, 0, DE_ENCODING_MACROMAN);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz(d->filename));
	}
	else {
		de_warn(c, "Bad MacBinary filename length (%d)", (int)namelen);
	}
	pos += 63;

	de_dbg(c, "finder info:");
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos, &type4cc, 4, 0x0);
	de_dbg(c, "type: '%s'", type4cc.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator4cc, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator4cc.id_dbgstr);
	pos += 4;

	fflags = de_getbyte_p(&pos);
	de_dbg(c, "finder flags: 0x%02x", (unsigned int)fflags);

	pos++;

	n = de_geti16be_p(&pos);
	n2 = de_geti16be_p(&pos);
	de_dbg(c, "position in window: %d,%d", (int)n2, (int)n);

	n = de_getui16be_p(&pos);
	de_dbg(c, "window/folder id: %d", (int)n);
	de_dbg_indent(c, -1);

	b = de_getbyte_p(&pos);
	de_dbg(c, "protected: 0x%02x", (unsigned int)b);

	pos++;

	d->dflen = de_getui32be_p(&pos);
	de_dbg(c, "data fork len: %u", (unsigned int)d->dflen);
	d->rflen = de_getui32be_p(&pos);
	de_dbg(c, "resource fork len: %u", (unsigned int)d->rflen);

	n = de_getui32be_p(&pos);
	de_mac_time_to_timestamp(n, &d->create_date);
	de_timestamp_to_string(&d->create_date, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "create date: %"INT64_FMT" (%s)", n, timestamp_buf);
	if(n==0) d->create_date.is_valid = 0;

	n = de_getui32be_p(&pos);
	de_mac_time_to_timestamp(n, &d->mod_date);
	de_timestamp_to_string(&d->mod_date, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod date: %"INT64_FMT" (%s)", n, timestamp_buf);
	if(n==0) d->mod_date.is_valid = 0;

	pos += 2; // length of Get Info comment

	if(d->ver2 >= 129) {
		b = de_getbyte(pos);
		de_dbg(c, "finder flags, bits 0-7: 0x%02x", (unsigned int)b);
	}
	pos += 1;

	pos += 14; // unused
	pos += 4; // unpacked total length

	if(d->ver2 >= 129) {
		n = de_getui16be(pos);
		de_dbg(c, "length of secondary header: %u", (unsigned int)n);
	}
	pos += 2;

	pos += 1; // version number, already read
	pos += 1; // version number, already read

	if(d->ver2 >= 129) {
		n = de_getui16be(pos);
		de_dbg(c, "CRC of header (reported): 0x%04x", (unsigned int)n);
	}
	pos += 2;

	pos += 2; // Reserved for computer type and OS ID
done:
	;
}

static void do_extract_one_file(deark *c, lctx *d, de_int64 pos, de_int64 len,
	int is_rsrc)
{
	de_finfo *fi = NULL;
	const char *ext = NULL;

	if(pos+len>c->infile->len) goto done;
	fi = de_finfo_create(c);

	if(d->mod_date.is_valid) {
		fi->mod_time = d->mod_date; // struct copy
	}

	if(is_rsrc) {
		de_finfo_set_name_from_ucstring(c, fi, d->filename);
		ext = "rsrc";
	}
	else {
		if(d->filename) {
			de_finfo_set_name_from_ucstring(c, fi, d->filename);
			fi->original_filename_flag = 1;
		}
		else {
			ext = "data";
		}
	}

	dbuf_create_file_from_slice(c->infile, pos, len, ext, fi, 0x0);

done:
	de_finfo_destroy(c, fi);
}

static void do_extract_files(deark *c, lctx *d)
{
	de_int64 pos = 128;

	if(d->dflen>0) {
		do_extract_one_file(c, d, pos, d->dflen, 0);
		pos += de_pad_to_n(d->dflen, 128);
	}

	if(d->rflen>0) {
		do_extract_one_file(c, d, pos, d->rflen, 1);
	}
}

static void run_macbinary_internal(deark *c, lctx *d)
{
	do_header(c, d);
	if(d->extract_files) {
		do_extract_files(c, d);
	}
}

static void de_run_macbinary(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->extract_files = 1;
	if(de_havemodcode(c, mparams, 'D')) {
		d->extract_files = 0;
	}

	run_macbinary_internal(c, d);

	if(d) {
		ucstring_destroy(d->filename);
		de_free(c, d);
	}
}

static int de_identify_macbinary(deark *c)
{
	// TODO
	return 0;
}

void de_module_macbinary(deark *c, struct deark_module_info *mi)
{
	mi->id = "macbinary";
	mi->desc = "MacBinary";
	mi->run_fn = de_run_macbinary;
	mi->identify_fn = de_identify_macbinary;
}
