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

typedef struct localctx_struct {
	int errflag;
	int errmsg_handled;
	struct fmtutil_exe_info *ei;

	u8 detected_subfmt;
	i64 hdrpos; // Start of exepack header (i.e. the IP field)
	i64 decoder_len;

	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	// Fields from EXEPACK header. Some will be written to the reconstructed
	// decompressed file.
	struct ohdr_struct ohdr;
} lctx;

// TODO: This is the same format as LZEXE v090. Maybe the code should be shared.
static void do_read_reloc_tbl_internal(deark *c, lctx *d, i64 pos1, i64 endpos)
{
	i64 pos = pos1;
	i64 seg = 0;
	int reloc_count = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "compressed reloc table: pos=%"I64_FMT", end=%"I64_FMT, pos1, endpos);

	if(endpos > c->infile->len) {
		d->errflag = 1;
		goto done;
	}

	de_dbg_indent(c, 1);

	for(seg=0; seg<0x10000; seg+=0x1000) {
		i64 count;
		i64 i;

		if(pos>=endpos) {
			d->errflag = 1;
			goto done;
		}
		count = de_getu16le_p(&pos);
		de_dbg2(c, "seg %04x count: %u", (UI)seg, (UI)count);

		de_dbg_indent(c, 1);
		for(i=0; i<count; i++) {
			i64 offs;

			if(pos>=endpos || reloc_count>=65535) {
				d->errflag = 1;
				goto done;
			}
			offs = de_getu16le_p(&pos);
			de_dbg2(c, "reloc: %04x:%04x", (UI)seg, (UI)offs);
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
			reloc_count++;
		}
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "reloc count: %d", (int)reloc_count);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_read_reloc_tbl(deark *c, lctx *d)
{
	i64 reloc_pos;
	i64 reloc_endpos;

	reloc_pos = d->ei->entry_point + d->decoder_len;
	reloc_endpos = d->hdrpos + d->ohdr.exepack_size;

	do_read_reloc_tbl_internal(c, d, reloc_pos, reloc_endpos);
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

static void find_decoder_len(deark *c, lctx *d)
{
	int ret;
	int method = 0;
	i64 foundpos = 0;
	i64 haystack_pos;
	i64 haystack_len;

	haystack_pos = d->ei->entry_point+220;
	haystack_len = 100;

	// Look for the error message.
	ret = dbuf_search(c->infile, (const u8*)"Packed file is corrupt", 22,
		haystack_pos, haystack_len, &foundpos);
	if(ret) {
		d->decoder_len = foundpos+22 - d->ei->entry_point;
		method = 1;
		goto done;
	}

	// If that fails, look for the byte pattern that immediately precedes the
	// error message.
	ret = dbuf_search(c->infile, (const u8*)"\xcd\x21\xb8\xff\x4c\xcd\x21", 7,
		haystack_pos, haystack_len, &foundpos);
	if(ret) {
		d->decoder_len = foundpos+7+22 - d->ei->entry_point;
		method = 2;
		goto done;
	}

	// Last resort: Guess the length.
	switch(d->detected_subfmt) {
	case 1: d->decoder_len = 258; break;
	case 2: d->decoder_len = 279; break;
	case 3: d->decoder_len = 277; break;
	case 4: case 10: d->decoder_len = 283; break;
	case 5: d->decoder_len = 290; break;
	}
	method = 3;

done:
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
	i64 o_start_of_code;
	i64 o_reloc_pos;
	i64 o_file_size; // not including overlay
	i64 overlay_len;
	i64 cmprprog_mem_tot; // total memory consumed+reserved by the exepacked program

	outf = dbuf_create_output_file(c, "exe", NULL, 0);

	if(d->ei->reloc_table_pos>=28 &&
		d->ei->reloc_table_pos<=d->ei->start_of_dos_code)
	{
		o_reloc_pos = d->ei->reloc_table_pos;
	}
	else {
		o_reloc_pos = 28;
	}

	o_start_of_code = de_pad_to_n(o_reloc_pos + d->o_reloc_table->len, 16);
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
	dbuf_writeu16le(outf, o_reloc_pos); // 24  reloc_tbl_pos
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
	overlay_len = c->infile->len - d->ei->end_of_dos_code;
	if(overlay_len>0) {
		de_dbg(c, "overlay data at %"I64_FMT", len=%"I64_FMT, d->ei->end_of_dos_code,
			overlay_len);
		dbuf_copy(c->infile, d->ei->end_of_dos_code, overlay_len, outf);
	}

	dbuf_close(outf);
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

	d->detected_subfmt = edd.detected_subfmt;
	de_dbg(c, "variant id: %u", (UI)d->detected_subfmt);

	do_read_header(c, d);
	if(d->errflag) goto done;
	find_decoder_len(c, d);
	if(d->errflag) goto done;

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
