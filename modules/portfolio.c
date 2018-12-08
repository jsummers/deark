// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Portfolio graphics formats:
// * PGF
// * PGC
// * PGX (Portfolio animation)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pgx);
DE_DECLARE_MODULE(de_module_pf_pgf);
DE_DECLARE_MODULE(de_module_pgc);

typedef struct localctx_struct {
	u8 version;
} lctx;

static void do_pgc_in_pgx(deark *c, lctx *d, i64 pos, i64 len)
{
	dbuf *f = NULL;

	f = dbuf_create_output_file(c, "pgc", NULL, 0);

	// Embedded PGC files don't include the 3-byte PGC header, so we have to add that.
	dbuf_write(f, (const unsigned char*)"PG\x01", 3);

	// Copy the rest of the PGC file.
	dbuf_copy(c->infile, pos, len, f);

	dbuf_close(f);
}

static int do_process_frame(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 pos;
	u8 frame_type;
	i64 frame_payload_size;
	int retval = 1;

	*bytes_consumed = 0;
	pos = pos1;

	de_dbg(c, "frame at %d", (int)pos1);
	de_dbg_indent(c, 1);

	// 8-byte frame header
	frame_type = de_getbyte(pos);
	de_dbg(c, "type: %d", (int)frame_type);

	frame_payload_size = de_getu16le(pos+1);
	de_dbg(c, "reported payload size: %d", (int)frame_payload_size);

	*bytes_consumed += 8;
	pos += 8;
	if(pos + frame_payload_size > c->infile->len) {
		de_err(c, "Frame goes beyond end of file");
		retval = 0;
		goto done;
	}

	switch(frame_type) {
	case 0x00: // PGC
		do_pgc_in_pgx(c, d, pos, frame_payload_size);
		*bytes_consumed += frame_payload_size;
		break;

	case 0x01:
		de_warn(c, "PGT frames (text screen dumps) are not supported");

		// The spec contradicts itself about how to figure out the frame
		// payload size of PGT frames. First it says the size field is not
		// used. The it says it *is* used, and is expected to always be 320.
		// In the only example file I have, it is 317, though the actual size
		// of the frame in that file is 320.
		*bytes_consumed += 320;

		break;

	case 0xfe: // APPS
		*bytes_consumed += frame_payload_size;
		break;

	case 0xff: // EOF
		retval = 0;
		break;

	default:
		de_err(c, "Unknown frame type (%d)", (int)frame_type);
		retval = 0;
		break;
	}

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_pgx(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 frame_size;
	int ret;
	int executable = 0;

	if(dbuf_memcmp(c->infile, 0, "PGX", 3)) {
		// Some "PGX" files are actually .COM files with an embedded PGX file.
		// The ones I've seen always have the PGX file at offset 1248, so look
		// for it there.
		if(dbuf_memcmp(c->infile, 0, "PGX", 1248)) {
			executable = 1;
		}
	}

	if(executable) {
		de_declare_fmt(c, "PGX (Portfolio Animation, executable)");
		pos = 1248;
	}
	else{
		de_declare_fmt(c, "PGX (Portfolio Animation)");
		pos = 0;
	}

	d = de_malloc(c, sizeof(lctx));

	d->version = de_getbyte(pos+3);
	de_dbg(c, "Version: %d", (int)d->version);

	pos += 8;
	while(1) {
		if(pos >= c->infile->len) break;
		ret = do_process_frame(c, d, pos, &frame_size);
		if(!ret || !frame_size) break;
		pos += frame_size;
	}

	de_free(c, d);
}

static int de_identify_pgx(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PGX", 3))
		return 100;
	return 0;
}

void de_module_pgx(deark *c, struct deark_module_info *mi)
{
	mi->id = "pgx";
	mi->desc = "Atari Portfolio animation";
	mi->run_fn = de_run_pgx;
	mi->identify_fn = de_identify_pgx;
}

// **************************************************************************
// Portfolio PGF
// **************************************************************************

static void de_run_pf_pgf(deark *c, de_module_params *mparams)
{
	de_declare_fmt(c, "PGF (Portfolio graphics)");
	de_convert_and_write_image_bilevel(c->infile, 0, 240, 64, 240/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
}

static int de_identify_pf_pgf(deark *c)
{
	if(c->infile->len != 1920) return 0;
	if(!de_input_file_has_ext(c, "pgf")) return 0;
	return 90;
}

void de_module_pf_pgf(deark *c, struct deark_module_info *mi)
{
	mi->id = "pf_pgf";
	mi->desc = "Atari Portfolio Graphics - uncompressed";
	mi->run_fn = de_run_pf_pgf;
	mi->identify_fn = de_identify_pf_pgf;
}

// **************************************************************************
// PGC - Portfolio graphics compressed
// **************************************************************************

static void de_run_pgc(deark *c, de_module_params *mparams)
{
	dbuf *unc_pixels = NULL;
	i64 pos;
	i64 count;
	u8 b, b2;

	de_declare_fmt(c, "PGC (Portfolio graphics compressed)");
	unc_pixels = dbuf_create_membuf(c, 1920, 1);

	pos = 3;
	while(pos<c->infile->len) {
		b = de_getbyte(pos);
		pos++;
		count = (i64)(b & 0x7f);
		if(b & 0x80) {
			// compressed run
			b2 = de_getbyte(pos);
			pos++;
			dbuf_write_run(unc_pixels, b2, count);
		}
		else {
			// uncompressed run
			dbuf_copy(c->infile, pos, count, unc_pixels);
			pos += count;
		}
	}

	de_convert_and_write_image_bilevel(unc_pixels, 0, 240, 64, 240/8,
		DE_CVTF_WHITEISZERO, NULL, 0);
	dbuf_close(unc_pixels);
}

static int de_identify_pgc(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "PG\x01", 3)) {
		return 100;
	}
	return 0;
}

void de_module_pgc(deark *c, struct deark_module_info *mi)
{
	mi->id = "pgc";
	mi->desc = "Atari Portfolio Graphics - compressed";
	mi->run_fn = de_run_pgc;
	mi->identify_fn = de_identify_pgc;
}
