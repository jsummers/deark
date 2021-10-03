// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress LZEXE executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_lzexe);

typedef struct localctx_struct {
	int ver;
	int errflag;
	int errmsg_handled;

	i64 ihdr_hdrsize;
	UI ihdr_minmem;
	UI ihdr_maxmem;
	i64 ihdr_CS;

	i64 special_hdr[8];

	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;
} lctx;

// Read what we need from the 28-byte DOS header
static void do_read_header(deark *c, lctx *d)
{
	d->ihdr_hdrsize = de_getu16le(8);
	d->ihdr_minmem = (UI)de_getu16le(10);
	d->ihdr_maxmem = (UI)de_getu16le(12);

	d->ihdr_CS = de_getu16le(22);
	if(d->ihdr_CS >= 0x8000) {
		// CS is signed. If it's ever negative in an LZEXE'd file, I'm not sure
		// how to handle that.
		d->errflag = 1;
	}
}

static void read_special_hdr(deark *c, lctx *d, i64 ipos1)
{
	i64 ipos = ipos1;
	UI i;

	de_dbg(c, "LZEXE private info at %"I64_FMT, ipos1);
	de_dbg_indent(c, 1);
	for(i=0; i<8; i++) {
		d->special_hdr[i] = de_getu16le_p(&ipos);
		de_dbg(c, "special hdr[%u]: 0x%04x (%u)", i, (UI)d->special_hdr[i],
			(UI)d->special_hdr[i]);
	}
	de_dbg_indent(c, -1);
}

#define MAX_RELOCS (320*1024)

static void do_decode_reloc_tbl_v090(deark *c, lctx *d, i64 ipos1)
{
	i64 ipos;
	i64 seg = 0;
	int reloc_count = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	ipos = ipos1 + 413;

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

			if(ipos>=c->infile->len || reloc_count>MAX_RELOCS) {
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

static void do_decode_reloc_tbl_v091(deark *c, lctx *d, i64 ipos1)
{
	i64 ipos;
	int reloc_count = 0;
	UI reloc = 0;

	ipos = ipos1 + 344;
	de_dbg(c, "decompressing reloc table at %"I64_FMT, ipos);
	de_dbg_indent(c, 1);

	while(1) {
		u8 x;

		if(ipos>=c->infile->len || reloc_count>MAX_RELOCS) {
			d->errflag = 1;
			goto done;
		}

		x = (UI)de_getbyte_p(&ipos);
		if(x==0) {
			UI x2;

			x2 = (UI)de_getu16le_p(&ipos);
			if(x2==0) {
				reloc += 0xfff; // TODO: test this
				continue;
			}
			else if(x2==1) {
				break;
			}
			else {
				reloc += x2; // TODO: test this
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
	if(d->dcmpr_cur_ipos+2 > c->infile->len) {
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

	ipos1 = (d->ihdr_CS - d->special_hdr[4] + d->ihdr_hdrsize) * 16;
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
#define O_CODE_ALIGNMENT 512 // Multiple of 16. Sensible values are 16 and 512.

	o_start_of_code = de_pad_to_n(O_RELOC_POS + d->o_reloc_table->len, O_CODE_ALIGNMENT);

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
		minmem -= (UI)d->special_hdr[5] + (((UI)d->special_hdr[6]+15)/16) + 9;
		minmem &= 0xffff;
		if(d->ihdr_maxmem != 0xffff) {
			maxmem -= (d->ihdr_minmem-minmem);
			maxmem &= 0xffff;
		}
	}
	dbuf_writeu16le(outf, (i64)minmem); // 10  # of paragraphs required
	dbuf_writeu16le(outf, (i64)maxmem); // 12  # of paragraphs requested

	dbuf_writeu16le(outf, d->special_hdr[3]); // 14 ss
	dbuf_writeu16le(outf, d->special_hdr[2]); // 16  sp
	dbuf_writeu16le(outf, 0); // 18  checksum
	dbuf_writeu16le(outf, d->special_hdr[0]); // 20  ip
	dbuf_writeu16le(outf, d->special_hdr[1]); // 22  cs
	dbuf_writeu16le(outf, O_RELOC_POS); // 24  reloc_tbl_pos
	dbuf_writeu16le(outf, 0); // 26  overlay indicator

	// Write the relocation table
	dbuf_truncate(outf, O_RELOC_POS);
	dbuf_copy(d->o_reloc_table, 0, d->o_reloc_table->len, outf);

	// Write the decompressed code
	dbuf_truncate(outf, o_start_of_code);
	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

static void de_run_lzexe(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct fmtutil_exe_info *ei = NULL;
	i64 ipos1;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));

	ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, c->infile, ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_LZEXE;
	fmtutil_detect_execomp(c, ei, &edd);
	d->ver = (int)edd.detected_subfmt;
	if(d->ver==0) {
		de_err(c, "Not an LZEXE file");
		goto done;
	}
	de_declare_fmt(c, edd.detected_fmt_name);

	d->o_reloc_table = dbuf_create_membuf(c, 0, 0);
	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);

	do_read_header(c, d);
	if(d->errflag) goto done;
	ipos1 = (d->ihdr_hdrsize + d->ihdr_CS) * 16;
	read_special_hdr(c, d, ipos1);
	if(d->errflag) goto done;
	if(d->ver==1) {
		do_decode_reloc_tbl_v090(c, d, ipos1);
	}
	else {
		do_decode_reloc_tbl_v091(c, d, ipos1);
	}
	if(d->errflag) goto done;
	do_decompress_code(c, d);
	if(d->errflag) goto done;

	do_write_dcmpr(c, d);

done:

	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "LZEXE decompression failed");
		}

		dbuf_close(d->o_reloc_table);
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d);
	}
	de_free(c, ei);
}

void de_module_lzexe(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzexe";
	mi->desc = "LZEXE executable compression";
	mi->run_fn = de_run_lzexe;
}
