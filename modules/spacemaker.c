// This file is part of Deark.
// Copyright (C) 2026 Jason Summers
// See the file COPYING for terms of use.

// Realia Spacemaker executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_spacemaker);

#define SM_PREAMBLE_SIZE 25

typedef struct localctx_spacemaker {
	u8 errflag;
	u8 need_errmsg;
	u8 raw_mode; // 0xff = not set
	u8 original_was_exe;
	u8 host_is_exe;
	i64 code_pos;
	i64 orig_len;
	i64 part1_pos, part1_len; // first 25 bytes
	i64 part2_pos, part2_endpos, part2_len; // rest of file
	i64 part3_pos, part3_len; // reloc. table(?)
	i64 decoder_pos1, decoder_pos2;
	dbuf *dcmpr_code;
	struct fmtutil_exe_info *host_ei;
} lctx;

static void sm_decompress(deark *c, lctx *d)
{
	i64 ipos; // in c->infile
	i64 istartpos;
	i64 opos; // in d->dcmpr_code
	u8 b[2];
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "[decompressing]");
	de_dbg_indent(c, 1);

	de_zeromem(b, sizeof(b));
	dbuf_truncate(d->dcmpr_code, d->orig_len);

	opos = d->orig_len;
	ipos = d->code_pos+d->part2_endpos;
	istartpos = d->code_pos+SM_PREAMBLE_SIZE;

	while(1) {
		i64 count;
#define CT_U 1 // An uncompressed segment
#define CT_R 2 // A run of 0-valued bytes
		u8 code_type;

		if(ipos<=istartpos) goto done;

		code_type = 0;
		count = 0;

		ipos--;
		b[0] = de_getbyte(ipos);
		if(b[0] & 0x01) {
			// ... xxxxxxx1
			ipos--;
			b[1] = de_getbyte(ipos);
			if(b[1] & 0x01) {
				//   b[1]     b[0]
				// rrrrrrr1 rrrrrrr1
				code_type = CT_R;
				count = ((b[0]&0xfe)<<6) | (b[1]>>1);
			}
			else {
				//   b[1]     b[0]
				// uuuuuuu0 uuuuuuu1
				code_type = CT_U;
				count = ((b[0]&0xfe)<<6) | (b[1]>>1);
			}
		}
		else if(b[0] & 0x02) {
			// rrrrrr10
			code_type = CT_R;
			count = b[0]>>2;
		}
		else {
			// uuuuuu00
			code_type = CT_U;
			count = b[0]>>2;
		}

		if(count==0 && code_type==CT_U) {
			// All remaining data is uncompressed.
			count = ipos - istartpos;
		}

		if(code_type==CT_R) {
			de_dbg3(c, "i=%"I64_FMT" o=%"I64_FMT" rle %"I64_FMT, ipos, opos, count);
		}
		else {
			de_dbg3(c, "i=%"I64_FMT" o=%"I64_FMT" unc %"I64_FMT, ipos, opos, count);
		}

		// For CT_R, this is all we need to do. The part of the file we skip
		// over was initialized to 0, so just leave it that way.
		opos -= count;
		if(opos<SM_PREAMBLE_SIZE) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		if(code_type==CT_U) {
			ipos -= count;
			if(ipos<istartpos) {
				d->errflag = 1;
				d->need_errmsg = 1;
				goto done;
			}
			dbuf_copy_at(c->infile, ipos, count, d->dcmpr_code, opos);
		}
	}

done:
	if(!d->errflag) {
		if(ipos!=istartpos || opos!=SM_PREAMBLE_SIZE) {
			d->errflag = 1;
			d->need_errmsg = 1;
		}
	}
	if(!d->errflag) {
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, d->part2_len,
			(i64)(d->dcmpr_code->len-SM_PREAMBLE_SIZE));
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void spacemaker_main(deark *c, lctx *d)
{
	i64 jmppos;
	i64 tmp_seg, tmp_offs;
	UI x;
	UI ver;
	const char *ext;
	dbuf *outf = NULL;
	i64 code_pos = d->code_pos;

	de_dbg(c, "host fmt: %s", (d->host_is_exe?"EXE":"COM"));

	tmp_seg = de_getu16le(code_pos+10);
	tmp_offs = de_getu16le(code_pos+14);
	jmppos = 16*tmp_seg + tmp_offs;
	de_dbg(c, "jmp pos: c+%"I64_FMT, jmppos);

	x = (UI)de_getu16be(code_pos+jmppos);
	if(x!=0x5751) {
		de_err(c, "Bad file or unknown version");
		d->errflag = 1;
		goto done;
	}
	d->decoder_pos1 = jmppos;

	x = (UI)de_getu16be(code_pos+jmppos+13);
	if(x==0xd78c) {
		ver = 103;
		d->decoder_pos2 = d->decoder_pos1+7+44;
	}
	else if(x==0x8ec5) {
		ver = 106;
		d->decoder_pos2 = d->decoder_pos1+7;
	}
	else {
		de_err(c, "Unknown version");
		d->errflag = 1;
		goto done;
	}
	de_dbg(c, "version: %u.%02u", ver/100, ver%100);

	// apparently part2 endpos, minus 1
	tmp_seg = de_getu16le(code_pos+d->decoder_pos2+114);
	tmp_offs = de_getu16le(code_pos+d->decoder_pos2+119);
	d->part2_endpos = tmp_seg*16 + tmp_offs + 1;
	de_dbg(c, "part2 endpos: c+%"I64_FMT, d->part2_endpos);

	// apparently original size, minus 1
	tmp_seg = de_getu16le(code_pos+d->decoder_pos2+123);
	tmp_offs = de_getu16le(code_pos+d->decoder_pos2+128);
	d->orig_len = tmp_seg*16 + tmp_offs + 1;
	de_dbg(c, "orig len: %"I64_FMT, d->orig_len);

	d->part1_pos = d->part2_endpos;
	d->part2_pos = SM_PREAMBLE_SIZE;
	d->part3_pos = d->part1_pos + SM_PREAMBLE_SIZE;
	d->part3_len = d->decoder_pos1 - d->part3_pos;
	d->part1_len = de_min_int(d->orig_len, SM_PREAMBLE_SIZE);
	d->part2_len = d->part2_endpos - d->part2_pos;

	de_dbg(c, "part1 at c+%"I64_FMT", len=%"I64_FMT, d->part1_pos, d->part1_len);
	de_dbg(c, "part2 at c+%"I64_FMT", len=%"I64_FMT, d->part2_pos, d->part2_len);
	de_dbg(c, "part3 at c+%"I64_FMT", len=%"I64_FMT, d->part3_pos, d->part3_len);

	if(d->host_is_exe) {
		// SM doesn't allow COM->EXE, so this must be EXE->EXE.
		d->original_was_exe = 1;
	}

	if(d->part3_len!=0) {
		d->original_was_exe = 1;
	}

	x = (UI)de_getu32be(code_pos+d->decoder_pos2+26);
	if(x==0x8bc4050aU) {
		;
	}
	else if(x==0x90909090U) {
		d->original_was_exe = 1;
	}
	else {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	de_dbg(c, "orig fmt: %s", (d->original_was_exe?"EXE":"COM"));
	if(d->original_was_exe && d->raw_mode!=1) {
		de_err(c, "File was converted from EXE (not supported%s)",
			((d->raw_mode==0xff) ? ", or use \"-opt spacemaker:raw\"" : ""));
		d->errflag = 1;
		goto done;
	}

	d->dcmpr_code = dbuf_create_membuf(c, d->orig_len, 0x1);
	dbuf_copy(c->infile, d->code_pos+d->part1_pos, d->part1_len, d->dcmpr_code);

	if(d->orig_len > SM_PREAMBLE_SIZE) {
		sm_decompress(c, d);
	}
	if(d->errflag) goto done;

	ext = d->original_was_exe ? "bin" : "com";
	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(d->dcmpr_code, 0, d->dcmpr_code->len, outf);

done:
	if(outf) {
		dbuf_close(outf);
		if(!d->errflag) {
			de_stdwarn_execomp(c);
		}
	}
}

static void spacemaker_exe_main(deark *c, lctx *d)
{
	de_dbg(c, "exe"); // fixme
	fmtutil_collect_exe_info(c, c->infile, d->host_ei);
	d->host_is_exe = 1;
	d->code_pos = d->host_ei->start_of_dos_code;
	de_dbg(c, "code pos: %"I64_FMT, d->code_pos);
	spacemaker_main(c, d);
}

static void spacemaker_com_main(deark *c, lctx *d)
{
	d->host_is_exe = 0;
	d->code_pos = 0;
	spacemaker_main(c, d);
}

static void de_run_spacemaker(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI sig;

	// TODO: Support EXE->COM and EXE->EXE compression.
	d = de_malloc(c, sizeof(lctx));
	d->host_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	d->raw_mode = (u8)de_get_ext_option_bool(c, "spacemaker:raw", 0xff);
	sig = (UI)de_getu16be(0);
	if(sig==0x4d5a || sig==0x5a4d) {
		spacemaker_exe_main(c, d);
	}
	else {
		spacemaker_com_main(c, d);
	}

	dbuf_close(d->dcmpr_code);
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported Spacemaker file");
	}
	de_free(c, d->host_ei);
	de_free(c, d);
}

static int de_identify_spacemaker(deark *c)
{
	u8 x;

	// Note that we tolerate oversized COM files. Spacemaker will create
	// them, and we can decompress them.

	if(dbuf_memcmp(c->infile, 0,
		(const void*)"\x9c\x55\x56\x8c\xcd\x83\xc5\x10\x8d\xb6", 10))
	{
		return 0;
	}
	x = !(u8)dbuf_memcmp(c->infile, 18, (const void*)"MEMORY$", 7);
	return x?100:85;
}

static void de_help_spacemaker(deark *c)
{
	de_msg(c, "-opt spacemaker:raw : Write raw decompressed data");
}

void de_module_spacemaker(deark *c, struct deark_module_info *mi)
{
	mi->id = "spacemaker";
	mi->desc = "Realia Spacemaker";
	mi->run_fn = de_run_spacemaker;
	mi->identify_fn = de_identify_spacemaker;
	mi->help_fn = de_help_spacemaker;
}
