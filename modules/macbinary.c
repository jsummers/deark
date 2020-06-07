// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// MacBinary

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_macbinary);

typedef struct localctx_struct {
	u8 extract_files;
	u8 oldver;
	u8 extver;
	u8 extver_minneeded;
	int is_v23;
	i64 dfpos, rfpos;
	i64 dflen, rflen;
	struct de_stringreaderdata *filename_srd;
	struct de_timestamp create_time;
	struct de_timestamp mod_time;
} lctx;

struct fork_info {
	u8 is_rsrc;
	u8 extract_error_flag;
	i64 pos;
};

struct extract_ctx {
	lctx *d;
	struct fork_info fki_data;
	struct fork_info fki_rsrc;
};

static const char *fork_name(int is_rsrc, int capitalize)
{
	if(is_rsrc) {
		return capitalize?"Resource":"resource";
	}
	return capitalize?"Data":"data";
}

static void do_header(deark *c, lctx *d, struct de_advfile *advf)
{
	u8 b;
	i64 namelen;
	i64 pos = 0;
	i64 n, n2;
	i64 mod_time_raw;
	u32 crc_reported, crc_calc;
	struct de_fourcc type4cc;
	struct de_fourcc creator4cc;
	char timestamp_buf[64];

	d->oldver = de_getbyte_p(&pos);
	de_dbg(c, "original version: %u", (unsigned int)d->oldver);
	if(d->oldver!=0) {
		de_warn(c, "Unsupported MacBinary version");
		goto done;
	}

	d->extver = de_getbyte(122);
	de_dbg(c, "extended version: %u", (unsigned int)d->extver);
	if(d->extver==129 || d->extver==130) {
		d->is_v23 = 1;
	}
	if(d->extver >= 129) {
		d->extver_minneeded = de_getbyte(123);
		de_dbg(c, "extended version, min needed: %u", (unsigned int)d->extver_minneeded);
	}

	namelen = (i64)de_getbyte_p(&pos);
	if(namelen>=1 && namelen<=63) {
		// Required to be 1-63 by MacBinary II spec.
		// Original spec has no written requirements.
		// Not supposed to be NUL terminated, but such files exist.
		d->filename_srd = dbuf_read_string(c->infile, pos, namelen, namelen,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_MACROMAN);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz(d->filename_srd->str));
	}
	else {
		de_warn(c, "Bad MacBinary filename length (%d)", (int)namelen);
	}
	pos += 63;

	de_dbg(c, "finder info:");
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos, &type4cc, 4, 0x0);
	de_dbg(c, "type: '%s'", type4cc.id_dbgstr);
	de_memcpy(advf->typecode, type4cc.bytes, 4);
	advf->has_typecode = 1;
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator4cc, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator4cc.id_dbgstr);
	de_memcpy(advf->creatorcode, creator4cc.bytes, 4);
	advf->has_creatorcode = 1;
	pos += 4;

	advf->has_finderflags = 1;
	if(d->is_v23) {
		u8 fflags_hibyte;

		fflags_hibyte = de_getbyte_p(&pos);
		de_dbg(c, "finder flags (high byte): 0x%02x__", (unsigned int)fflags_hibyte);
		pos++;
		advf->finderflags = (u16)fflags_hibyte << 8;
	}
	else {
		advf->finderflags = (u16)de_getu16be_p(&pos);
		de_dbg(c, "finder flags: 0x%04x", (unsigned int)advf->finderflags);
	}

	n = de_geti16be_p(&pos);
	n2 = de_geti16be_p(&pos);
	de_dbg(c, "position in window: %d,%d", (int)n2, (int)n);

	n = de_getu16be_p(&pos);
	de_dbg(c, "window/folder id: %d", (int)n);
	de_dbg_indent(c, -1);

	b = de_getbyte_p(&pos);
	de_dbg(c, "protected: 0x%02x", (unsigned int)b);

	pos++;

	d->dflen = de_getu32be_p(&pos);
	de_dbg(c, "data fork len: %u", (unsigned int)d->dflen);
	d->rflen = de_getu32be_p(&pos);
	de_dbg(c, "resource fork len: %u", (unsigned int)d->rflen);

	n = de_getu32be_p(&pos);
	if(n==0) {
		d->create_time.is_valid = 0;
		de_strlcpy(timestamp_buf, "unknown", sizeof(timestamp_buf));
	}
	else {
		de_mac_time_to_timestamp(n, &d->create_time);
		d->create_time.tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(&d->create_time, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	de_dbg(c, "create date: %"I64_FMT" (%s)", n, timestamp_buf);

	mod_time_raw = de_getu32be_p(&pos);
	if(mod_time_raw==0) {
		d->mod_time.is_valid = 0;
		de_strlcpy(timestamp_buf, "unknown", sizeof(timestamp_buf));
	}
	else {
		de_mac_time_to_timestamp(mod_time_raw, &d->mod_time);
		d->mod_time.tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(&d->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	de_dbg(c, "mod date: %"I64_FMT" (%s)", mod_time_raw, timestamp_buf);

	pos += 2; // length of Get Info comment

	if(d->is_v23) {
		u8 fflags_lobyte;

		fflags_lobyte = de_getbyte(pos);
		de_dbg(c, "finder flags (low byte): 0x__%02x", (unsigned int)fflags_lobyte);
		advf->finderflags |= (u16)fflags_lobyte;
	}
	pos += 1;

	pos += 14; // unused
	pos += 4; // unpacked total length

	if(d->is_v23) {
		n = de_getu16be(pos);
		de_dbg(c, "length of secondary header: %u", (unsigned int)n);
	}
	pos += 2;

	pos += 1; // version number, already read
	pos += 1; // version number, already read

	crc_reported = (u32)de_getu16be_p(&pos);
	if(d->is_v23 || crc_reported!=0) {
		struct de_crcobj *crco;

		de_dbg(c, "crc of header (reported%s): 0x%04x",
			(d->is_v23)?"":", hypothetical", (unsigned int)crc_reported);
		crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
		de_crcobj_addslice(crco, c->infile, 0, 124);
		crc_calc = de_crcobj_getval(crco);
		de_crcobj_destroy(crco);
		de_dbg(c, "crc of header (calculated): 0x%04x", (unsigned int)crc_calc);

		if(d->is_v23 && crc_reported!=0 && crc_calc!=crc_reported) {
			de_warn(c, "MacBinary header CRC check failed");
		}
	}

	pos += 2; // Reserved for computer type and OS ID
done:
	;
}

// If a fork is going to be extracted, call this to set up some things.
// Caller must first set advfki->fork_len, among other things.
// Sets fki->extract_error_flag if there was a problem that would prevent the
// fork from being extracted.
static void do_prepare_one_fork(deark *c, lctx *d, struct de_advfile_forkinfo *advfki,
	struct fork_info *fki)
{
	de_dbg(c, "%s fork at %"I64_FMT", len=%"I64_FMT, fork_name(fki->is_rsrc, 0),
		fki->pos, advfki->fork_len);

	if(fki->pos+advfki->fork_len>c->infile->len) {
		de_err(c, "%s fork at %"I64_FMT" goes beyond end of file.",
			fork_name(fki->is_rsrc, 1), fki->pos);
		if(fki->pos+advfki->fork_len > c->infile->len+1024) {
			fki->extract_error_flag = 1;
			goto done;
		}
	}

done:
	;
}

static int my_advfile_cbfn(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp)
{
	struct extract_ctx *ectx = (struct extract_ctx*)advf->userdata;

	if(afp->whattodo == DE_ADVFILE_WRITEMAIN) {
		dbuf_copy(c->infile, ectx->fki_data.pos, advf->mainfork.fork_len, afp->outf);
	}
	else if(afp->whattodo == DE_ADVFILE_WRITERSRC) {
		dbuf_copy(c->infile, ectx->fki_rsrc.pos, advf->rsrcfork.fork_len, afp->outf);
	}
	return 1;
}

static void run_macbinary_internal(deark *c, lctx *d)
{
	i64 pos = 128;
	struct de_advfile *advf = NULL;
	struct extract_ctx *ectx = NULL;

	ectx = de_malloc(c, sizeof(struct extract_ctx));
	advf = de_advfile_create(c);

	do_header(c, d, advf);
	if(d->filename_srd && ucstring_isnonempty(d->filename_srd->str)) {
		ucstring_append_ucstring(advf->filename, d->filename_srd->str);
		advf->original_filename_flag = 1;
	}
	if(d->filename_srd) {
		de_advfile_set_orig_filename(advf, d->filename_srd->sz,
			d->filename_srd->sz_strlen);
	}
	advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = d->mod_time;
	advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE] = d->create_time;

	if(d->dflen>0) {
		d->dfpos = pos;
		ectx->fki_data.pos = d->dfpos;
		advf->mainfork.fork_len = d->dflen;

		if(d->extract_files) {
			do_prepare_one_fork(c, d, &advf->mainfork, &ectx->fki_data);
			if(!ectx->fki_data.extract_error_flag) {
				advf->mainfork.fork_exists = 1;
			}
		}

		pos += de_pad_to_n(d->dflen, 128);
	}

	if(d->rflen>0) {
		d->rfpos = pos;

		ectx->fki_rsrc.is_rsrc = 1;
		ectx->fki_rsrc.pos = d->rfpos;
		advf->rsrcfork.fork_len = d->rflen;

		if(d->extract_files) {
			do_prepare_one_fork(c, d, &advf->rsrcfork, &ectx->fki_rsrc);
			if(!ectx->fki_rsrc.extract_error_flag) {
				advf->rsrcfork.fork_exists = 1;
			}
		}
	}

	if(d->extract_files) {
		advf->userdata = (void*)ectx;
		advf->writefork_cbfn = my_advfile_cbfn;
		de_advfile_run(advf);
	}

	de_advfile_destroy(advf);
	de_free(c, ectx);
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
		mparams->out_params.uint1 = (u32)d->dfpos;
		mparams->out_params.uint2 = (u32)d->dflen;
		mparams->out_params.uint3 = (u32)d->rfpos;
		mparams->out_params.uint4 = (u32)d->rflen;

		if(mparams->out_params.fi) {
			// If caller created out_params.fi for us, save the mod time to it.
			mparams->out_params.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = d->mod_time;

			// If caller created .fi->name_other, copy the filename to it.
			if(d->filename_srd && d->filename_srd->str->len>0 && mparams->out_params.fi->name_other) {
				ucstring_append_ucstring(mparams->out_params.fi->name_other, d->filename_srd->str);
			}
		}
	}

	if(d) {
		de_destroy_stringreaderdata(c, d->filename_srd);
		de_free(c, d);
	}
}

// Detecting MacBinary format is important, but also very difficult.
// Note: This must be coordinated with the macpaint detection routine.
// It should never set the confidence to 100, because macpaint and
// maybe other formats need to be able to have higher confidence.
static int de_identify_macbinary(deark *c)
{
	int conf = 0;
	int k;
	int has_sig;
	int is_v23 = 0; // v2 or v3
	int good_file_len = 0;
	int good_cc = 0;
	int bad_crc = 0;
	i64 n;
	i64 dflen, rflen;
	i64 min_expected_len;
	u32 crc_reported, crc_calc;
	u8 b[128];

	// "old" version number is always 0.
	b[0] = de_getbyte(0);
	if(b[0]!=0) goto done;

	// filename length
	b[1] = de_getbyte(1);
	if(b[1]<1 || b[1]>63) goto done;

	de_read(&b[2], 2, sizeof(b)-2);

	if(b[2]==0) goto done; // First filename byte
	if(b[74]!=0) goto done;
	if(b[82]!=0) goto done;

	// Extended version number
	if(b[122]==129 && b[123]==129) {
		// v2
		is_v23 = 1;
	}
	else if(b[122]==130 && (b[123]==129 || b[123]==130)) {
		// v3
		is_v23 = 1;
	}
	// else v1.
	// Some v1 files have garbage in the last 29 bytes of the file,
	// so we can't assume the extended version number is 0.

	// Ver.III signature, but possibly used in some files that have earlier
	// version numbers.
	has_sig = !de_memcmp(&b[102], (const void*)"mBIN", 4);
	if(has_sig) {
		conf = 90;
		goto done;
	}

	// Check if filename characters are sensible
	for(k=0; k<(int)b[1]; k++) {
		if(b[2+k]>0 && b[2+k]<32) goto done;
	}

	// File type code. Expect ASCII.
	good_cc = 1;
	for(k=65; k<=68; k++) {
		if(b[k]<32 || b[k]>127) good_cc = 0;
	}

	dflen = de_getu32be_direct(&b[83]);
	rflen = de_getu32be_direct(&b[87]);

	crc_reported = (u32)de_getu16be_direct(&b[124]);

	// Check the file size.

	// Resource forks that go beyond the end of file are too common to
	// disallow.
	if(128 + dflen > c->infile->len) goto done;
	if(128 + rflen + dflen > c->infile->len + 4096) goto done;

	if(rflen>0) {
		min_expected_len = 128 + de_pad_to_n(dflen, 128) + rflen;
	}
	else {
		min_expected_len = 128 + dflen;
	}

	// The file size really should be exactly min_expected_len, or that
	// number padded to the next multiple of 128. But I'm not bold
	// enough to require it.
	if((c->infile->len == min_expected_len) ||
		(c->infile->len == de_pad_to_n(min_expected_len, 128)))
	{
		good_file_len = 1;
	}

	if(is_v23) {
		// Most MacBinary II specific checks go here

		if(!de_is_all_zeroes(&b[102], 14)) {
			if(!good_file_len) goto done;
		}

		// Secondary header length. We don't support this.
		n = de_getu16be_direct(&b[120]);
		if(n!=0) goto done;
	}
	else {
		// Most Original MacBinary format checks go here

		// An empty file is not illegal, but we need as many checks as possible
		// that won't be passed by all 0 bytes.
		if(dflen==0 && rflen==0) goto done;

		// Unused fields in this version should be all 0, though we'll allow
		// nonzero values in some cases.
		if(!de_is_all_zeroes(&b[99], 25)) {
			if(!good_file_len) goto done;
		}
	}

	if(crc_reported!=0 || is_v23) {
		struct de_crcobj *crco;

		crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
		de_crcobj_addbuf(crco, b, 124);
		crc_calc = de_crcobj_getval(crco);
		de_crcobj_destroy(crco);
		if(crc_calc!=crc_reported && is_v23 && crc_reported!=0) {
			bad_crc = 1;
		}
	}

	if(is_v23 && good_file_len && good_cc) {
		if(bad_crc) {
			conf = 19;
		}
		else {
			conf = 90;
		}
	}
	else if(bad_crc) {
		goto done;
	}
	else if(is_v23) {
		conf = 49;
	}
	else if(good_cc) {
		conf = 29;
	}
	else {
		conf = 19;
	}

done:
	if(conf>0) {
		c->detection_data->is_macbinary = 1;
	}
	return conf;
}

void de_module_macbinary(deark *c, struct deark_module_info *mi)
{
	mi->id = "macbinary";
	mi->desc = "MacBinary";
	mi->run_fn = de_run_macbinary;
	mi->identify_fn = de_identify_macbinary;
	mi->flags = DE_MODFLAG_SHAREDDETECTION;
}
