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
	i64 dfpos, rfpos;
	i64 dflen, rflen;
	de_ucstring *filename;
	struct de_timestamp create_time;
	struct de_timestamp mod_time;
} lctx;

static void do_header(deark *c, lctx *d)
{
	de_byte b;
	de_byte fflags;
	i64 namelen;
	i64 pos = 0;
	i64 n, n2;
	i64 mod_time_raw;
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

	namelen = (i64)de_getbyte_p(&pos);
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
	if(n==0) {
		d->create_time.is_valid = 0;
		de_strlcpy(timestamp_buf, "unknown", sizeof(timestamp_buf));
	}
	else {
		de_mac_time_to_timestamp(n, &d->create_time);
		d->create_time.tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(&d->create_time, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	de_dbg(c, "create date: %"INT64_FMT" (%s)", n, timestamp_buf);

	mod_time_raw = de_getui32be_p(&pos);
	if(mod_time_raw==0) {
		d->mod_time.is_valid = 0;
		de_strlcpy(timestamp_buf, "unknown", sizeof(timestamp_buf));
	}
	else {
		de_mac_time_to_timestamp(mod_time_raw, &d->mod_time);
		d->mod_time.tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(&d->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	de_dbg(c, "mod date: %"INT64_FMT" (%s)", n, timestamp_buf);

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
		struct de_crcobj *crco = NULL;
		de_uint32 crc_calc;
		n = de_getui16be(pos);
		de_dbg(c, "CRC of header (reported): 0x%04x", (unsigned int)n);

		crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
		de_crcobj_addslice(crco, c->infile, 0, 124);
		crc_calc = de_crcobj_getval(crco);
		de_crcobj_destroy(crco);
		de_dbg(c, "CRC of header (calculated): 0x%04x", (unsigned int)crc_calc);
	}
	pos += 2;

	pos += 2; // Reserved for computer type and OS ID
done:
	;
}

static void do_extract_one_file(deark *c, lctx *d, i64 pos, i64 len,
	int is_rsrc)
{
	de_finfo *fi = NULL;
	const char *ext = NULL;

	if(pos+len>c->infile->len) goto done;
	fi = de_finfo_create(c);

	if(d->mod_time.is_valid) {
		fi->mod_time = d->mod_time; // struct copy
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

static void run_macbinary_internal(deark *c, lctx *d)
{
	i64 pos = 128;

	do_header(c, d);

	if(d->dflen>0) {
		d->dfpos = pos;
		if(d->extract_files) {
			do_extract_one_file(c, d, d->dfpos, d->dflen, 0);
		}
		pos += de_pad_to_n(d->dflen, 128);
	}

	if(d->rflen>0) {
		d->rfpos = pos;
		if(d->extract_files) {
			do_extract_one_file(c, d, pos, d->rflen, 1);
		}
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

	if(mparams) {
		mparams->out_params.uint1 = (de_uint32)d->dfpos;
		mparams->out_params.uint2 = (de_uint32)d->dflen;

		if(mparams->out_params.fi) {
			// If caller created out_params.fi for us, save the mod time to it.
			mparams->out_params.fi->mod_time = d->mod_time;

			// If caller created .fi->name_other, copy the filename to it.
			if(d->filename && d->filename->len>0 && mparams->out_params.fi->name_other) {
				ucstring_append_ucstring(mparams->out_params.fi->name_other, d->filename);
			}
		}
	}

	if(d) {
		ucstring_destroy(d->filename);
		de_free(c, d);
	}
}

// The goal is to identify MacBinary and MacBinary II files that are
// valid, and not too pathological.
// Note: This must be coordinated with the macpaint detection routine.
static int de_identify_macbinary(deark *c)
{
	int conf = 0;
	int k;
	de_byte ver2;
	i64 n;
	i64 dflen, rflen;
	i64 min_expected_len;
	de_byte b[128];

	// "old" version number is always 0.
	b[0] = de_getbyte(0);
	if(b[0]!=0) goto done;

	// filename length
	b[1] = de_getbyte(1);
	if(b[1]<1 || b[1]>63) goto done;

	de_read(&b[2], 2, sizeof(b)-2);

	// Extended version number
	ver2 = b[122];
	// ?? Do versions over 129 exist?
	if(ver2!=0 && ver2!=129) goto done;

	// Check if filename characters are sensible
	for(k=0; k<(int)b[1]; k++) {
		if(b[2+k]<32) goto done;
	}

	// File type code. Expect ASCII.
	for(k=65; k<=68; k++) {
		if(b[k]<32 || b[k]>127) goto done;
	}

	if(b[74]!=0) goto done;
	if(b[82]!=0) goto done;

	dflen = de_getui32be_direct(&b[83]);
	rflen = de_getui32be_direct(&b[87]);

	if(ver2>=129) {
		// Most MacBinary II specific checks go here

		if(!de_is_all_zeroes(&b[102], 14)) goto done;

		// Min. ext. version needed to read file (??)
		if(b[123]!=0 && b[123]!=129) goto done;

		// Secondary header length.
		n = de_getui16be_direct(&b[120]);
		if(n!=0) goto done;

		// TODO: checking the CRC would be the most robust check.
	}
	else {
		// Most Original MacBinary format checks go here

		// An empty file is not illegal, but we need more checks that don't
		// allow all 0 bytes.
		if(dflen==0 && rflen==0) goto done;

		if(!de_is_all_zeroes(&b[99], 27)) goto done;
	}

	// Check the file size.
	if(rflen>0) {
		min_expected_len = 128 + de_pad_to_n(dflen, 128) + rflen;
	}
	else {
		min_expected_len = 128 + dflen;
	}
	// The file size really should be exactly min_expected_len, or that
	// number padded to the next multiple of 128. But I'm not bold
	// enough to require it.
	if(c->infile->len < min_expected_len) goto done;

	conf = (ver2>=129)?74:49;
	c->detection_data.is_macbinary = 1;

done:
	return conf;
}

void de_module_macbinary(deark *c, struct deark_module_info *mi)
{
	mi->id = "macbinary";
	mi->desc = "MacBinary";
	mi->run_fn = de_run_macbinary;
	mi->identify_fn = de_identify_macbinary;
}
