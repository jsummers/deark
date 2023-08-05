// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress LZEXE executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_lzexe);

struct ohdr_struct {
	i64 regSS;
	i64 regSP;
	i64 regCS;
	i64 regIP;
	i64 cmpr_len_para;
	i64 field5;
	i64 field6;
	i64 field7;
	i64 field8;
};

typedef struct localctx_struct {
	int ver; // 1=0.90, 2=0.91, 3=0.91e
	int errflag;
	int errmsg_handled;
	int o_code_alignment;
	struct fmtutil_exe_info *ei;

	UI ihdr_minmem;
	UI ihdr_maxmem;

	i64 special_hdr_pos;
	i64 end_of_reloc_tbl;
	struct ohdr_struct ohdr;

	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;
} lctx;

// Read what we need from the 28-byte DOS header
static void do_read_header(deark *c, lctx *d)
{
	d->ihdr_minmem = (UI)de_getu16le(10);
	d->ihdr_maxmem = (UI)de_getu16le(12);

	if(d->ei->regCS < 0) {
		// CS is signed. If it's ever negative in an LZEXE'd file, I'm not sure
		// how to handle that.
		d->errflag = 1;
	}
}

static void read_special_hdr(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;

	de_dbg(c, "LZEXE private info at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	d->ohdr.regIP = de_getu16le_p(&pos);
	de_dbg(c, "ip: %u", (UI)d->ohdr.regIP);
	d->ohdr.regCS = de_geti16le_p(&pos);
	de_dbg(c, "cs: %d", (int)d->ohdr.regCS);
	d->ohdr.regSP = de_getu16le_p(&pos);
	de_dbg(c, "sp: %u", (UI)d->ohdr.regSP);
	d->ohdr.regSS = de_geti16le_p(&pos);
	de_dbg(c, "ss: %d", (int)d->ohdr.regSS);
	d->ohdr.cmpr_len_para = de_getu16le_p(&pos);
	de_dbg(c, "cmpr len: %u ("DE_CHAR_TIMES"16=%"I64_FMT")", (int)d->ohdr.cmpr_len_para,
		(i64)(d->ohdr.cmpr_len_para*16));

	// TODO: These fields could be named better
	d->ohdr.field5 = de_getu16le_p(&pos);
	de_dbg(c, "field5: %u", (UI)d->ohdr.field5);
	d->ohdr.field6 = de_getu16le_p(&pos);
	de_dbg(c, "field6: %u", (UI)d->ohdr.field6);
	if(d->ver==1) {
		d->ohdr.field7 = de_getu16le_p(&pos);
		de_dbg(c, "field7: %u", (UI)d->ohdr.field7);
		d->ohdr.field8 = de_getu16le_p(&pos);
		de_dbg(c, "field8: %u", (UI)d->ohdr.field8);
	}

	de_dbg_indent(c, -1);
}

static void do_decode_reloc_tbl_v090(deark *c, lctx *d)
{
	i64 pos;
	i64 endpos;

	pos = d->special_hdr_pos + 413;
	endpos = d->end_of_reloc_tbl;
	if(!fmtutil_decompress_exepack_reloc_tbl(c, pos, endpos, d->o_reloc_table)) {
		d->errflag = 1;
	}
}

static void do_decode_reloc_tbl_v091(deark *c, lctx *d)
{
	i64 ipos;
	int reloc_count = 0;
	UI reloc = 0;

	ipos = d->special_hdr_pos + 344;
	de_dbg(c, "compressed reloc table: pos=%"I64_FMT, ipos);
	de_dbg_indent(c, 1);

	while(1) {
		u8 x;

		if(ipos>=d->end_of_reloc_tbl || reloc_count>65535) {
			d->errflag = 1;
			goto done;
		}

		x = (UI)de_getbyte_p(&ipos);
		if(x==0) {
			UI x2;

			x2 = (UI)de_getu16le_p(&ipos);
			if(x2==0) {
				reloc += 0xfff0;
				continue;
			}
			else if(x2==1) {
				break;
			}
			else {
				reloc += x2;
			}
		}
		else {
			reloc += (UI)x;
		}

		de_dbg2(c, "reloc: %05x", reloc);
		dbuf_writeu16le(d->o_reloc_table, (i64)(reloc&0x0f));
		dbuf_writeu16le(d->o_reloc_table, (i64)(reloc>>4));
		reloc_count++;
	}
	de_dbg(c, "reloc count: %d", (int)reloc_count);

done:
	de_dbg_indent(c, -1);
}

static void fill_bitbuf(deark *c, lctx *d)
{
	UI i;

	if(d->errflag) return;
	if(d->dcmpr_cur_ipos+2 > d->special_hdr_pos)
	{
		d->errflag = 1;
		return;
	}

	for(i=0; i<2; i++) {
		u8 b;
		b = de_getbyte_p(&d->dcmpr_cur_ipos);
		de_bitbuf_lowlevel_add_byte(&d->bbll, b);
	}
}

static u8 lzexe_getbit(deark *c, lctx *d)
{
	u8 v;

	if(d->errflag) return 0;

	if(d->bbll.nbits_in_bitbuf==0) {
		fill_bitbuf(c, d);
	}

	v = (u8)de_bitbuf_lowlevel_get_bits(&d->bbll, 1);

	if(d->bbll.nbits_in_bitbuf==0) {
		fill_bitbuf(c, d);
	}

	return v;
}

static void my_lz77buf_writebytecb(struct de_lz77buffer *rb, u8 n)
{
	lctx *d = (lctx*)rb->userdata;

	dbuf_writebyte(d->o_dcmpr_code, n);
}

static void do_decompress_code(deark *c, lctx *d)
{
	i64 ipos1;
	struct de_lz77buffer *ringbuf = NULL;

	// (I'd expect ipos1 to always equal d->ei->start_of_dos_code, but anyway...)
	ipos1 = d->special_hdr_pos -  d->ohdr.cmpr_len_para*16;
	de_dbg(c, "decompressing cmpr code at %"I64_FMT, ipos1);
	de_dbg_indent(c, 1);

	ringbuf = de_lz77buffer_create(c, 8192);
	ringbuf->userdata = (void*)d;
	ringbuf->writebyte_cb = my_lz77buf_writebytecb;

	d->dcmpr_cur_ipos = ipos1;
	d->bbll.is_lsb = 1;
	de_bitbuf_lowlevel_empty(&d->bbll);

	while(1) {
		u8 x, x2, x3;
		UI matchpos;
		UI matchlen;
		u8 matchtype = 1;

		if(d->errflag) goto done;

		x = lzexe_getbit(c, d);
		if(x) { // 1...
			u8 b;

			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			de_lz77buffer_add_literal_byte(ringbuf, (u8)b);
			continue;
		}

		x = lzexe_getbit(c, d);
		if(x==0) { // 00...
			x2 = lzexe_getbit(c, d);
			x3 = lzexe_getbit(c, d);
			matchlen = ((UI)x2<<1) + (UI)x3 + 2;
			matchpos = 0xffU-(UI)de_getbyte_p(&d->dcmpr_cur_ipos);
		}
		else { // 01...
			u8 lb, hb;

			lb = de_getbyte_p(&d->dcmpr_cur_ipos);
			hb = de_getbyte_p(&d->dcmpr_cur_ipos);

			matchpos = 0x1fffU - ((((UI)(hb & 0xf8))<<5) | (UI)lb);

			if((hb & 0x07)==0) {
				u8 xb;

				matchtype = 3;
				xb = de_getbyte_p(&d->dcmpr_cur_ipos);

				if(xb==0) {
					de_dbg3(c, "eof code");
					goto after_decompress;
				}
				else if(xb==1) {
					continue; // something about segments...
				}
				else {
					matchlen = (UI)xb + 1;
				}
			}
			else {
				matchtype = 2;
				matchlen = (UI)(hb & 0x07) + 2;
			}
		}

		if(c->debug_level>=3) {
			de_dbg3(c, "match (%u) pos=%u len=%u", (UI)matchtype, matchpos+1, matchlen);
		}
		de_lz77buffer_copy_from_hist(ringbuf,
				(UI)(ringbuf->curpos-1-matchpos), matchlen);
	}

after_decompress:
	dbuf_flush(d->o_dcmpr_code);
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT, (d->dcmpr_cur_ipos-ipos1),
		d->o_dcmpr_code->len);

done:
	de_lz77buffer_destroy(c, ringbuf);
	de_dbg_indent(c, -1);
}

// Generate the decompressed file
static void do_write_dcmpr(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 o_file_size;
	i64 o_start_of_code;
	UI minmem, maxmem;

	de_dbg(c, "generating output file");
	de_dbg_indent(c, 1);

	outf = dbuf_create_output_file(c, "exe", NULL, 0);

#define O_RELOC_POS 28
	o_start_of_code = de_pad_to_n(O_RELOC_POS + d->o_reloc_table->len, (i64)d->o_code_alignment);

	// Generate 28-byte header
	dbuf_writeu16le(outf, 0x5a4d); // 0  signature

	o_file_size = o_start_of_code + d->o_dcmpr_code->len;
	dbuf_writeu16le(outf, o_file_size%512); // 2  # of bytes in last page
	dbuf_writeu16le(outf, (o_file_size+511)/512); // 4  # of pages

	dbuf_writeu16le(outf, d->o_reloc_table->len/4); // 6  # of reloc tbl entries
	dbuf_writeu16le(outf, o_start_of_code / 16); // 8  hdrsize/16

	// This logic is from unlzexe v0.7+ (A. Modra).
	minmem = d->ihdr_minmem;
	maxmem = d->ihdr_maxmem;
	if(d->ihdr_maxmem!=0) {
		minmem -= (UI)d->ohdr.field5 + (((UI)d->ohdr.field6+15)/16) + 9;
		minmem &= 0xffff;
		if(d->ihdr_maxmem != 0xffff) {
			maxmem -= (d->ihdr_minmem-minmem);
			maxmem &= 0xffff;
		}
	}
	dbuf_writeu16le(outf, (i64)minmem); // 10  # of paragraphs required
	dbuf_writeu16le(outf, (i64)maxmem); // 12  # of paragraphs requested

	dbuf_writei16le(outf, d->ohdr.regSS); // 14
	dbuf_writeu16le(outf, d->ohdr.regSP); // 16
	dbuf_writeu16le(outf, 0); // 18  checksum
	dbuf_writeu16le(outf, d->ohdr.regIP); // 20
	dbuf_writei16le(outf, d->ohdr.regCS); // 22
	dbuf_writeu16le(outf, O_RELOC_POS); // 24  reloc_tbl_pos
	dbuf_writeu16le(outf, 0); // 26  overlay indicator

	// Write the relocation table
	dbuf_truncate(outf, O_RELOC_POS);
	dbuf_copy(d->o_reloc_table, 0, d->o_reloc_table->len, outf);

	// Write the decompressed code
	dbuf_truncate(outf, o_start_of_code);
	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	// Copy the overlay segment.
	// Normal LZEXE files never have such a thing, but some third-party utilities
	// construct such files.
	if(d->ei->overlay_len>0) {
		de_dbg(c, "overlay data at %"I64_FMT", len=%"I64_FMT, d->ei->end_of_dos_code,
			d->ei->overlay_len);
		dbuf_copy(c->infile, d->ei->end_of_dos_code, d->ei->overlay_len, outf);
	}

	dbuf_close(outf);
	de_dbg_indent(c, -1);
	if(!d->errflag) {
		de_stdwarn_execomp(c);
	}
}

// Don't change this, unless it's also changed in fmtutil.c.
#define LZEXE_VER_LHARK_SFX 102

// Refer to detect_execomp_lzexe() (in another file).
static const char *get_lzexe_subfmt_name(int n)
{
	const char *name = NULL;

	switch(n) {
	case 1: name = "v0.90"; break;
	case 2: name = "v0.91"; break;
	case 3: name = "v0.91e"; break;
	case LZEXE_VER_LHARK_SFX: name = "v0.91-LHARK-SFX"; break;
	}
	return name?name:"?";
}

static void de_run_lzexe(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));

	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	s = de_get_ext_option(c, "execomp:align");
	if(s) {
		d->o_code_alignment = de_atoi(s);
	}
	if(d->o_code_alignment != 512) {
		d->o_code_alignment = 16;
	}

	fmtutil_collect_exe_info(c, c->infile, d->ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_LZEXE;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(edd.detected_fmt!=DE_SPECIALEXEFMT_LZEXE) {
		de_err(c, "Not an LZEXE-compressed file");
		goto done;
	}
	de_declare_fmt(c, "LZEXE-compressed EXE");
	d->ver = (int)edd.detected_subfmt;
	de_dbg(c, "LZEXE variant: %s", get_lzexe_subfmt_name(d->ver));

	d->o_reloc_table = dbuf_create_membuf(c, 0, 0);
	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);
	dbuf_enable_wbuffer(d->o_dcmpr_code);

	do_read_header(c, d);
	if(d->errflag) goto done;

	if(d->ver==LZEXE_VER_LHARK_SFX) {
		// The special header should be 14 bytes before the original entry point.
		// LHARK changes the entry point to be 338 bytes after the original.
		d->special_hdr_pos = d->ei->entry_point - 338 - 14;
	}
	else {
		d->special_hdr_pos = d->ei->start_of_dos_code + d->ei->regCS*16;
	}
	if(d->special_hdr_pos > c->infile->len) {
		d->errflag = 1;
		return;
	}
	read_special_hdr(c, d, d->special_hdr_pos);
	if(d->errflag) goto done;

	d->end_of_reloc_tbl = d->special_hdr_pos + d->ohdr.field6;
	if(d->end_of_reloc_tbl > c->infile->len) {
		d->errflag = 1;
		goto done;
	}
	if(d->ver==1) {
		do_decode_reloc_tbl_v090(c, d);
	}
	else {
		do_decode_reloc_tbl_v091(c, d);
	}
	if(d->errflag) goto done;

	do_decompress_code(c, d);
	dbuf_flush(d->o_dcmpr_code);
	if(d->errflag) goto done;

	if(d->ver > 3) {
		// LHARK-SFX has some extra code outside of the compressed code.
		// We don't want to throw away that code and pretend everything's okay.
		de_err(c, "This modified LZEXE format is not supported");
		goto done;
	}

	do_write_dcmpr(c, d);

done:

	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "LZEXE decompression failed");
		}

		dbuf_close(d->o_reloc_table);
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d->ei);
		de_free(c, d);
	}
}

static void de_help_lzexe(deark *c)
{
	de_msg(c, "-opt execomp:align=<16|512> : Alignment of code segment "
		"(in output file)");
}

void de_module_lzexe(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzexe";
	mi->desc = "LZEXE-compressed EXE";
	mi->run_fn = de_run_lzexe;
	mi->help_fn = de_help_lzexe;
}
