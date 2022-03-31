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
	i64 mem_start;
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

	// Fields from EXEPACK header. Some will be written to the reconstructed
	// decompressed file.
	struct ohdr_struct ohdr;
} lctx;

static void find_decoder_len(deark *c, lctx *d)
{
	int ret;
	i64 foundpos = 0;

	// 258 = minimum known distance from entry_point to *end* of message.
	// 290 = maximum known distance
	ret = dbuf_search(c->infile, (const u8*)"Packed file is corrupt", 22,
		d->ei->entry_point+(258-22), 290-(258-22), &foundpos);
	if(ret) {
		d->decoder_len = foundpos+22 - d->ei->entry_point;
		goto done;
	}

	de_dbg(c, "[could not find error string]");
	switch(d->detected_subfmt) {
	case 1: d->decoder_len = 258; break;
	case 2: d->decoder_len = 279; break;
	case 3: d->decoder_len = 277; break;
	case 4: case 10: d->decoder_len = 258; break;
	case 5: d->decoder_len = 290; break;
	}

done:
	if(d->decoder_len) {
		de_dbg(c, "decoder len: %"I64_FMT, d->decoder_len);
	}
	else {
		d->errflag = 1;
	}
}

static void do_read_header(deark *c, lctx *d)
{
	i64 hdrsize;
	i64 hdrpos;
	i64 pos;

	hdrpos = 512 + d->ei->regCS * 16;
	de_dbg(c, "header pos: %"I64_FMT, hdrpos);

	hdrsize = d->ei->regIP;
	de_dbg(c, "header size: %d", (int)hdrsize);
	if(hdrsize!=16 && hdrsize!=18) {
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "header at %"I64_FMT, hdrpos);
	pos = hdrpos;
	de_dbg_indent(c, 1);
	d->ohdr.regIP = de_getu16le_p(&pos);
	de_dbg(c, "ip: %u", (UI)d->ohdr.regIP);
	d->ohdr.regCS = de_geti16le_p(&pos);
	de_dbg(c, "cs: %d", (int)d->ohdr.regCS);
	d->ohdr.mem_start = de_getu16le_p(&pos);
	de_dbg(c, "mem start: %u", (UI)d->ohdr.mem_start);
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
	de_dbg_indent(c, -1);

done:
	;
}

static void de_run_exepack(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));
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
	de_dbg(c, "cmpr reloc tbl pos: %"I64_FMT, d->ei->entry_point + d->decoder_len);

done:
	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "EXEPACK decompression failed");
		}
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
