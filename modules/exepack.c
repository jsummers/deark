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
	i64 decoder_len;

	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	// Fields from EXEPACK header. Some will be written to the reconstructed
	// decompressed file.
	struct ohdr_struct ohdr;
} lctx;

// TODO: This is the same format as LZEXE v090. Maybe the code should be shared.
static void do_read_reloc_tbl(deark *c, lctx *d, i64 ipos1)
{
	i64 ipos;
	i64 seg = 0;
	int reloc_count = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	ipos = ipos1;

	de_dbg(c, "decompressing reloc table at %"I64_FMT, ipos);
	de_dbg_indent(c, 1);

	for(seg=0; seg<0x10000; seg+=0x1000) {
		i64 count;
		i64 i;

		if(ipos>=c->infile->len) {
			d->errflag = 1;
			goto done;
		}

		count = de_getu16le_p(&ipos);
		de_dbg2(c, "seg %04x count: %u", (UI)seg, (UI)count);

		de_dbg_indent(c, 1);
		for(i=0; i<count; i++) {
			i64 offs;

			if(ipos>=c->infile->len || reloc_count>=65535) {
				d->errflag = 1;
				goto done;
			}

			offs = de_getu16le_p(&ipos);
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

static void do_decompress_code(deark *c, lctx *d)
{
	i64 mem_start;
	i64 compressed_len;
	i64 uncompressed_len;
	u8 *buf = NULL;
	i64 buf_alloc;
	i64 src, dst;

	mem_start = d->ei->start_of_dos_code;
	compressed_len = 16*(d->ei->regCS - d->ohdr.skip_len + 1);
	uncompressed_len = 16*(d->ohdr.dest_len - d->ohdr.skip_len + 1);
	de_dbg(c, "mem_start: %"I64_FMT, mem_start);
	de_dbg(c, "compressed_len: %"I64_FMT, compressed_len);
	de_dbg(c, "uncompressed_len: %"I64_FMT, uncompressed_len);

	buf_alloc = de_max_int(compressed_len, uncompressed_len);
	buf = de_malloc(c, buf_alloc);

	de_read(buf, mem_start, compressed_len);

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
	if(d->errflag) {
		de_err(c, "EXEPACK decompression failed");
		d->errmsg_handled =1;
	}
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
	ret = dbuf_search(c->infile, (const u8*)"Packed file is corrupt", 22,
		haystack_pos, haystack_len, &foundpos);
	if(ret) {
		d->decoder_len = foundpos+22 - d->ei->entry_point;
		method = 1;
		goto done;
	}

	// Look for the byte pattern that immediately precedes the error message.
	ret = dbuf_search(c->infile, (const u8*)"\xcd\x21\xb8\xff\x4c\xcd\x21", 7,
		haystack_pos, haystack_len, &foundpos);
	if(ret) {
		d->decoder_len = foundpos+7+22 - d->ei->entry_point;
		method = 2;
		goto done;
	}

	switch(d->detected_subfmt) {
	case 1: d->decoder_len = 258; break;
	case 2: d->decoder_len = 279; break;
	case 3: d->decoder_len = 277; break;
	case 4: case 10: d->decoder_len = 258; break;
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
	i64 hdrpos;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	hdrpos = 512 + d->ei->regCS * 16;
	hdrsize = d->ei->regIP;
	de_dbg(c, "exepack header at %"I64_FMT", len=%d", hdrpos, (int)hdrsize);
	if(hdrsize!=16 && hdrsize!=18) {
		d->errflag = 1;
		goto done;
	}
	pos = hdrpos;
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

	do_read_reloc_tbl(c, d, d->ei->entry_point + d->decoder_len);
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
	mi->flags |= DE_MODFLAG_NONWORKING;
}
