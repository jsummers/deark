// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// Decompress EXEPACK executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_exepack);

struct ohdr_struct {
	i64 regSS;
	i64 regSP;
	i64 regCS;
	i64 regIP;
	i64 exepack_size;
	i64 dest_len;
	i64 skip_len;
};

typedef struct localctx_EXEPACK {
	int errflag;
	int errmsg_handled;
	struct fmtutil_exe_info *ei; // For the original, compressed, file

	i64 hdrpos; // Start of exepack header (i.e. the IP field)
	i64 decoder_len;
	i64 epilog_pos;
	u32 decoder_fingerprint;

	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	// Fields from EXEPACK header. Some will be written to the reconstructed
	// decompressed file.
	struct ohdr_struct ohdr;
} lctx;

static void do_read_reloc_tbl(deark *c, lctx *d)
{
	i64 reloc_pos;
	i64 reloc_endpos;

	reloc_pos = d->ei->entry_point + d->decoder_len;
	reloc_endpos = d->hdrpos + d->ohdr.exepack_size;

	if(!fmtutil_decompress_exepack_reloc_tbl(c, reloc_pos, reloc_endpos, d->o_reloc_table)) {
		d->errflag = 1;
	}
}

static void do_decompress_code(deark *c, lctx *d)
{
	i64 compressed_len;
	i64 uncompressed_len;
	u8 *buf = NULL;
	i64 buf_alloc;
	i64 src, dst;

	compressed_len = 16*(d->ei->regCS - d->ohdr.skip_len + 1);
	uncompressed_len = 16*(d->ohdr.dest_len - d->ohdr.skip_len + 1);
	de_dbg(c, "compressed data: pos=%"I64_FMT", len=%"I64_FMT", end=%"I64_FMT,
		d->ei->start_of_dos_code, compressed_len,
		d->ei->start_of_dos_code + compressed_len);
	de_dbg(c, "uncompressed len: %"I64_FMT, uncompressed_len);
	if(compressed_len<0 || uncompressed_len<0 ||
		(d->ei->start_of_dos_code+compressed_len > c->infile->len))
	{
		d->errflag = 1; goto done;
	};

	// TODO: It would be safer to do all the work inside a membuf, but the nature
	// of the EXEPACK algorithm could make that inefficient.
	buf_alloc = de_max_int(compressed_len, uncompressed_len);
	// Though the size is untrusted, it's impossible for it to be more than about 1MB.
	buf = de_malloc(c, buf_alloc);
	de_read(buf, d->ei->start_of_dos_code, compressed_len);

	src = compressed_len;
	dst = uncompressed_len;

	while(1) {
		u8 opcode;

		if(src<1) { d->errflag = 1; goto done; };
		opcode = buf[--src];

		if(opcode>=0xb0 && opcode<=0xb3) { // opcodes followed by a count
			UI i;
			UI count;

			if(src<2) { d->errflag = 1; goto done; };
			count = (UI)buf[--src];
			count = (count<<8) | buf[--src];
			if(dst<(i64)count) { d->errflag = 1; goto done; };

			if(opcode==0xb0 || opcode==0xb1) { // (run)
				u8 n;

				if(src<1) { d->errflag = 1; goto done; };
				n = buf[--src];
				for(i=0; i<count; i++) {
					buf[--dst] = n;
				}
			}
			else { // 0xb2 or 0xb3 (noncompressed bytes)
				if(src<(i64)count) { d->errflag = 1; goto done; };
				for(i=0; i<count; i++) {
					buf[--dst] = buf[--src];
				}
			}
		}
		else if(opcode==0xff && dst==uncompressed_len) {
			; // Filler byte(s) at the end of compressed data
		}
		else {
			d->errflag = 1;
			goto done;
		}

		if(opcode==0xb1 || opcode==0xb3) {
			break; // Normal completion
		}
	}

	dbuf_write(d->o_dcmpr_code, buf, uncompressed_len);
done:
	de_free(c, buf);
}

// The "decoder length" is the distance from the end of the "RB" signature,
// to the start of the compressed relocation table (which normally starts
// right after the 22-byte error message).
static void find_decoder_len(deark *c, lctx *d)
{
	int ret;
	int method = 0;
	i64 foundpos = 0;
	i64 haystack_pos;
	i64 haystack_len;
	i64 n;

	// Something to consider: We could simply have a lookup table of
	// known decoder_fingerprints to decoder lengths.
	// It is safe (barring CRC collisions), because the fingerprinted bytes
	// include the pointer to the compressed relocation table.
	// But hardcoding CRC values is a maintenance hassle, and the other
	// methods will always work for all known EXEPACK variants.

	// Look for the pattern that usually follows the pointer to the compressed
	// relocation table.
	// Known offsets range from ep+135 to ep+148
	haystack_pos = d->ei->entry_point+100;
	haystack_len = 100;
	ret = dbuf_search(c->infile, (const u8*)"\x0e\x1f\x8b\x1e\x04\x00\xfc\x33", 8,
		haystack_pos, haystack_len, &foundpos);
	if(ret) {
		n = de_getu16le(foundpos-2);
		d->decoder_len = n - d->ei->regIP;
		method = 1;
		goto done;
	}

	// If that failed (which it will for some unusual or patched variants),
	// use the error-message-pointer that we believe is always right before
	// the "epilog". We assume the "Packed file is corrupt" error message
	// size is always 22 bytes, and that the compressed relocation table
	// follows. (The error message size does appear in the file, but not at
	// a consistent location. And if it's less than 22 bytes, it wouldn't
	// help us anyway.)
	// I know of no files for which this method fails, but it's possible
	// that some exist. Let's hope the first method works in such cases.
	n = de_getu16le(d->epilog_pos - 2);
	d->decoder_len = n + 22 - d->ei->regIP;
	method = 2;

done:
	if(d->decoder_len) {
		// Check that decoder_len is sane.
		// Known decoder lengths are from 256 to 291.
		if(d->decoder_len<180 || d->decoder_len>400) {
			d->decoder_len = 0;
		}
	}

	if(d->decoder_len) {
		de_dbg(c, "decoder len: %"I64_FMT" (found by method %d)", d->decoder_len, method);
	}
	else {
		de_err(c, "Could not find relocation table");
		d->errmsg_handled = 1;
		d->errflag = 1;
	}
}

static void do_read_header(deark *c, lctx *d)
{
	i64 hdrsize;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d->hdrpos = d->ei->start_of_dos_code + d->ei->regCS * 16;
	hdrsize = d->ei->regIP;
	de_dbg(c, "exepack header at %"I64_FMT", len=%d", d->hdrpos, (int)hdrsize);
	if(hdrsize!=16 && hdrsize!=18) {
		d->errflag = 1;
		goto done;
	}
	pos = d->hdrpos;
	de_dbg_indent(c, 1);
	d->ohdr.regIP = de_getu16le_p(&pos);
	de_dbg(c, "ip: %u", (UI)d->ohdr.regIP);
	d->ohdr.regCS = de_geti16le_p(&pos);
	de_dbg(c, "cs: %d", (int)d->ohdr.regCS);
	pos += 2; // "mem_start", just a placeholder
	d->ohdr.exepack_size = de_getu16le_p(&pos);
	de_dbg(c, "exepack size: %u", (UI)d->ohdr.exepack_size);
	d->ohdr.regSP = de_getu16le_p(&pos);
	de_dbg(c, "sp: %u", (UI)d->ohdr.regSP);
	d->ohdr.regSS = de_geti16le_p(&pos);
	de_dbg(c, "ss: %d", (int)d->ohdr.regSS);
	d->ohdr.dest_len = de_getu16le_p(&pos);
	de_dbg(c, "dest len: %u", (UI)d->ohdr.dest_len);
	if(hdrsize>=18) {
		d->ohdr.skip_len = de_getu16le_p(&pos);
		de_dbg(c, "skip len: %u", (UI)d->ohdr.skip_len);
	}
	else {
		d->ohdr.skip_len = 1;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_write_dcmpr(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 ihdr_minmem, ihdr_maxmem;
	i64 o_minmem;
	i64 o_start_of_code; // o_ means output
	i64 o_reloc_pos; // Where we actually write the reloc table
	i64 o_reloc_pos_field; // What we write to the header
	i64 o_file_size; // not including overlay
	i64 cmprprog_mem_tot; // total memory consumed+reserved by the exepacked program
	u8 have_reloc_pos;
	i64 elided_bytes_pos = 28;
	i64 elided_bytes_len = 0;

	outf = dbuf_create_output_file(c, "exe", NULL, 0);

	if(d->ei->reloc_table_pos<28 || d->ei->reloc_table_pos>d->ei->start_of_dos_code) {
		have_reloc_pos = 0;
	}
	else if (d->o_reloc_table->len==0) {
		// EXEPACK behaves differently if an empty reloc table has an offset <=28,
		// versus >28.
		// That's why this is ">28", when it seems like it should be ">=28".
		// (TODO: Test different EXEPACK versions.)
		have_reloc_pos = (d->ei->reloc_table_pos>28);
	}
	else {
		have_reloc_pos = 1;
	}

	if(d->o_reloc_table->len==0 && !have_reloc_pos) {
		// In this case, EXEPACK retains everything up to start_of_code,
		// so we ought to keep it.
		o_reloc_pos_field = d->ei->reloc_table_pos;
		o_reloc_pos = d->ei->start_of_dos_code;
		o_start_of_code = d->ei->start_of_dos_code;
	}
	else {
		if(have_reloc_pos) {
			o_reloc_pos = d->ei->reloc_table_pos;
		}
		else {
			o_reloc_pos = 28;
		}
		o_reloc_pos_field = o_reloc_pos;
		o_start_of_code = de_pad_to_n(o_reloc_pos + d->o_reloc_table->len, 16);

		elided_bytes_pos = o_reloc_pos;
		elided_bytes_len = d->ei->start_of_dos_code - elided_bytes_pos;
	}

	o_file_size = o_start_of_code + d->o_dcmpr_code->len;

	ihdr_minmem = de_getu16le(10);
	ihdr_maxmem = de_getu16le(12);

	cmprprog_mem_tot = (d->ei->end_of_dos_code - d->ei->start_of_dos_code) + ihdr_minmem*16;
	cmprprog_mem_tot = de_pad_to_n(cmprprog_mem_tot, 16);

	// Try to set minmem so that the total memory is the same, or at least does
	// not decrease.
	if(cmprprog_mem_tot >= d->o_dcmpr_code->len) {
		// This could be an overestimate, for small programs.
		o_minmem = de_pad_to_n(cmprprog_mem_tot - d->o_dcmpr_code->len, 16)/16;
	}
	else {
		o_minmem = 0;
	}

	// Generate 28-byte header
	dbuf_writeu16le(outf, 0x5a4d); // 0  signature
	dbuf_writeu16le(outf, o_file_size%512); // 2  # of bytes in last page
	dbuf_writeu16le(outf, (o_file_size+511)/512); // 4  # of pages
	dbuf_writeu16le(outf, d->o_reloc_table->len/4); // 6  # of reloc tbl entries
	dbuf_writeu16le(outf, o_start_of_code / 16); // 8  hdrsize/16
	dbuf_writeu16le(outf, o_minmem);
	dbuf_writeu16le(outf, ihdr_maxmem);
	dbuf_writei16le(outf, d->ohdr.regSS); // 14  ss
	dbuf_writeu16le(outf, d->ohdr.regSP); // 16  sp
	dbuf_writeu16le(outf, 0); // 18  checksum
	dbuf_writeu16le(outf, d->ohdr.regIP); // 20  ip
	dbuf_writei16le(outf, d->ohdr.regCS); // 22  cs
	dbuf_writeu16le(outf, o_reloc_pos_field); // 24  reloc_tbl_pos
	dbuf_writeu16le(outf, 0); // 26  overlay indicator

	// Copy extra data between header and reloc table
	dbuf_copy(c->infile, 28, o_reloc_pos-28, outf);

	// Write the relocation table
	dbuf_truncate(outf, o_reloc_pos);
	dbuf_copy(d->o_reloc_table, 0, d->o_reloc_table->len, outf);

	// Write the decompressed code
	dbuf_truncate(outf, o_start_of_code);
	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	// Copy overlay data
	if(d->ei->overlay_len>0) {
		de_dbg(c, "overlay data at %"I64_FMT", len=%"I64_FMT, d->ei->end_of_dos_code,
			d->ei->overlay_len);
		dbuf_copy(c->infile, d->ei->end_of_dos_code, d->ei->overlay_len, outf);
	}

	dbuf_close(outf);

	if(elided_bytes_len>0) {
		// Microsoft has created (hacked?) files like this, that have data where
		// they shouldn't.
		if(!dbuf_is_all_zeroes(c->infile, elided_bytes_pos, elided_bytes_len)) {
			de_warn(c, "Some unexpected data (%"I64_FMT" bytes at %"I64_FMT") was not "
				"preserved. This file might not run properly.",
				elided_bytes_len, elided_bytes_pos);
		}
	}

	if(!d->errflag) {
		de_stdwarn_execomp(c);
	}
}

static void calc_decoder_fingerprint(deark *c, lctx *d)
{
	i64 fp_start, fp_len;
	struct de_crcobj *crco = NULL;

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	fp_start = d->ei->entry_point;
	// The point of "- 15" is to exclude the error handler, particularly the
	// length of the error message. The error handler is not exactly 15 bytes
	// in all variants, but that should be okay, and this is the best logic
	// that I can figure out.
	fp_len = d->epilog_pos - 15 - fp_start;
	de_crcobj_addslice(crco, c->infile, fp_start, fp_len);
	d->decoder_fingerprint = de_crcobj_getval(crco);
	de_crcobj_destroy(crco);
}

static void report_exepack_version(deark *c, lctx *d)
{
	const char *name = "?";

	// Not intended to be a complete list.
	// I know of some more variants, but they're rare.
	switch(d->decoder_fingerprint) {
	case 0x77dc4e4aU: name = "common258 (EXEPACK 3.00/4.00/etc.)"; break;
	case 0x7b0bb610U: name = "common277 (LINK 3.60/etc.)"; break;
	case 0xae58e006U: name = "common279 (EXEPACK 4.03)"; break;
	case 0xa6a446acU: name = "common283 (EXEPACK 4.05/4.06)"; break;
	case 0x1797940cU: name = "common290 (LINK 5.60/etc.)"; break;
	}

	de_dbg(c, "decoder fingerprint: 0x%08x", (UI)d->decoder_fingerprint);
	de_dbg(c, "variant: %s", name);
}

static void de_run_exepack(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));
	d->o_reloc_table = dbuf_create_membuf(c, 0, 0);
	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);
	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, c->infile, d->ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_EXEPACK;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(edd.detected_fmt != DE_SPECIALEXEFMT_EXEPACK) {
		de_err(c, "Not an EXEPACK-compressed file");
		goto done;
	}
	de_declare_fmt(c, "EXEPACK-compressed EXE");

	d->epilog_pos = edd.special_pos_1;
	de_dbg(c, "epilog pos: %"I64_FMT, d->epilog_pos);

	calc_decoder_fingerprint(c, d);

	do_read_header(c, d);
	if(d->errflag) goto done;
	find_decoder_len(c, d);
	if(d->errflag) goto done;

	report_exepack_version(c, d);

	do_read_reloc_tbl(c, d);
	if(d->errflag) goto done;

	do_decompress_code(c, d);
	if(d->errflag) goto done;

	do_write_dcmpr(c, d);

done:
	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "EXEPACK decompression failed");
		}
		dbuf_close(d->o_reloc_table);
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d->ei);
		de_free(c, d);
	}
}

void de_module_exepack(deark *c, struct deark_module_info *mi)
{
	mi->id = "exepack";
	mi->desc = "EXEPACK-compressed EXE";
	mi->run_fn = de_run_exepack;
}
