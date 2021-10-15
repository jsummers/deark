// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decompress PKLITE executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pklite);

typedef struct localctx_struct {
	UI pklver; // e.g. 0x103 = 1.03
	u8 extra_cmpr;
	u8 large_cmpr;

	struct fmtutil_exe_info *ei;
	struct fmtutil_exe_info *o_ei;
	i64 orig_hdr_pos; // position of original header in the PKLITE'd file
	i64 orig_hdr_len;
	i64 cmpr_data_pos;
	i64 cmpr_data_endpos;

	int errflag;
	int errmsg_handled;
	dbuf *o_orig_header;
	dbuf *o_reloc_table;
	dbuf *o_dcmpr_code;

	i64 dcmpr_cur_ipos;
	struct de_bitbuf_lowlevel bbll;

	struct fmtutil_huffman_decoder *lengths_tree;
	struct fmtutil_huffman_decoder *offsets_tree;
	char pklver_str[12];
} lctx;

static void find_cmprdata_pos(deark *c, lctx *d)
{
	// TODO: This is incomplete

	if(d->pklver<0x100 || d->pklver>0x10f) goto done;

	if(!d->extra_cmpr && !d->large_cmpr) {
		d->cmpr_data_pos = d->ei->entry_point + 0x1d0;
	}
	else if(!d->extra_cmpr && d->large_cmpr) {
		d->cmpr_data_pos = d->ei->entry_point + 0x290;
	}
	else if(d->extra_cmpr && !d->large_cmpr) {
		if(d->pklver>=0x10e) {
			d->cmpr_data_pos = d->ei->entry_point + 0x200;
		}
		else {
			d->cmpr_data_pos = d->ei->entry_point + 0x1e0;
		}
	}
	else {
		if(d->pklver>=0x10e) {
			d->cmpr_data_pos = d->ei->entry_point + 0x2c0;
		}
		else if(d->pklver>=0x10c) {
			d->cmpr_data_pos = d->ei->entry_point + 0x290;
		}
		else {
			d->cmpr_data_pos = d->ei->entry_point + 0x2a0;
		}
	}

done:
	if(d->cmpr_data_pos!=0) {
		de_dbg(c, "cmpr data pos: %"I64_FMT, d->cmpr_data_pos);
	}
	else {
		de_err(c, "PKLITE version %s not supported", d->pklver_str);
		d->errflag = 1;
		d->errmsg_handled = 1;
	}
}

// Read what we need, before we can decompress
static void do_read_header(deark *c, lctx *d)
{
	UI n;

	// Start to reconstruct the original header
	d->o_orig_header = dbuf_create_membuf(c, 0, 0);
	dbuf_writeu16le(d->o_orig_header, 0x5a4d); // "MZ"

	n = (UI)de_getu16le(28);
	d->pklver = n & 0x0fff;
	de_snprintf(d->pklver_str, sizeof(d->pklver_str), "%u.%02u",
		(UI)(d->pklver>>8), (UI)(d->pklver&0xff));
	d->extra_cmpr = (n&0x1000)?1:0;
	d->large_cmpr = (n&0x2000)?1:0;
	de_dbg(c, "reported PKLITE version: %s", d->pklver_str);
	de_dbg(c, "'extra' compression: %u", (UI)d->extra_cmpr);
	de_dbg(c, "'large' compression: %u", (UI)d->large_cmpr);

	if(d->extra_cmpr) {
		de_err(c, "PKLITE 'extra' compression not supported");
		d->errflag = 1;
		d->errmsg_handled = 1;
		goto done;
	}

	d->orig_hdr_pos = d->ei->reloc_table_pos + 4*d->ei->num_relocs;
	d->orig_hdr_len = d->ei->start_of_dos_code - d->orig_hdr_pos;
	de_dbg(c, "orig. hdr: at %"I64_FMT", len=%"I64_FMT, d->orig_hdr_pos, d->orig_hdr_len);
	if(d->orig_hdr_len<26) {
		d->errflag = 1;
		goto done;
	}

	// This is expected to also copy some PKLITE-specific data after the
	// original header, that we may not need.
	dbuf_copy(c->infile, d->orig_hdr_pos, d->orig_hdr_len, d->o_orig_header);

	d->o_ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, d->o_orig_header, d->o_ei);

	find_cmprdata_pos(c, d);

done:
	;
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

static u8 pklite_getbit(deark *c, lctx *d)
{
	u8 v;

	if(d->errflag) return 0;
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

static void make_matchlengths_tree(deark *c, lctx *d)
{
	static const u8 matchlength_codelengths_lg[24] = {
		2, 2, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8,
		8, 9, 9, 9, 9, 9, 9, 6
	};
	static const u8 matchlength_codes_lg[24] = {
		2,3,0,2,3,4,10,11,12,26,27,58,59,60,122,123,
		124,250,251,252,253,254,255,28
	};
	static const u8 matchlength_codelengths_sm[9] = {
		3, 2, 3, 3, 4, 4, 4, 4, 3
	};
	static const u8 matchlength_codes_sm[9] = {
		2, 0, 4, 5, 12, 13, 14, 15, 3
	};
	static const u8 *ml_codelengths;
	static const u8 *ml_codes;
	i64 i;
	i64 num_codes;

	if(d->lengths_tree) return;
	if(d->large_cmpr) {
		num_codes = (i64)DE_ARRAYCOUNT(matchlength_codelengths_lg);
		ml_codelengths = matchlength_codelengths_lg;
		ml_codes = matchlength_codes_lg;
	}
	else {
		num_codes = (i64)DE_ARRAYCOUNT(matchlength_codelengths_sm);
		ml_codelengths = matchlength_codelengths_sm;
		ml_codes = matchlength_codes_sm;
	}

	d->lengths_tree = fmtutil_huffman_create_decoder(c, num_codes, num_codes);

	for(i=0; i<num_codes; i++) {
		fmtutil_huffman_add_code(c, d->lengths_tree->bk, ml_codes[i], ml_codelengths[i],
			(fmtutil_huffman_valtype)i);
	}
}

static void make_offsets_tree(deark *c, lctx *d)
{
	i64 i;
	UI curr_len = 1;
	fmtutil_huffman_valtype curr_code = 1;

	if(d->offsets_tree) return;
	d->offsets_tree = fmtutil_huffman_create_decoder(c, 32, 32);

	for(i=0; i<32; i++) {
		// Are we at a place where we adjust our counters?
		if(i==1) {
			curr_len = 4;
			curr_code = 0;
		}
		else if(i==3) {
			curr_len++;
			curr_code = 4;
		}
		else if(i==7) {
			curr_len++;
			curr_code = 16;
		}
		else if(i==14) {
			curr_len++;
			curr_code = 46;
		}

		fmtutil_huffman_add_code(c, d->offsets_tree->bk, curr_code, curr_len,
			(fmtutil_huffman_valtype)i);
		curr_code++;
	}
}

static UI read_pklite_code_using_tree(deark *c, lctx *d, struct fmtutil_huffman_decoder *ht)
{
	int ret;
	fmtutil_huffman_valtype val = 0;

	while(1) {
		u8 b;

		b = pklite_getbit(c, d);
		if(d->errflag) goto done;

		ret = fmtutil_huffman_decode_bit(ht->bk, ht->cursor, b, &val);
		if(ret==1) goto done; // finished the code
		if(ret!=2) {
			d->errflag = 1;
			goto done;
		}
	}
done:
	return val;
}

static void do_decompress(deark *c, lctx *d)
{
	struct de_lz77buffer *ringbuf = NULL;
	u8 b;

	de_dbg(c, "decompressing cmpr code at %"I64_FMT, d->cmpr_data_pos);
	de_dbg_indent(c, 1);

	make_matchlengths_tree(c, d);
	make_offsets_tree(c, d);

	d->o_dcmpr_code = dbuf_create_membuf(c, 0, 0);

	ringbuf = de_lz77buffer_create(c, 8192);
	ringbuf->userdata = (void*)d;
	ringbuf->writebyte_cb = my_lz77buf_writebytecb;

	d->dcmpr_cur_ipos = d->cmpr_data_pos;
	d->bbll.is_lsb = 1;
	de_bitbuf_lowlevel_empty(&d->bbll);

	fill_bitbuf(c, d);

	while(1) {
		u8 x;
		UI len_raw;
		UI matchlen;
		UI offs_hi_bits;
		u8 offs_lo_byte;
		UI matchpos;

		if(d->errflag) goto done;

		x = pklite_getbit(c, d);
		if(x==0) {
			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			if(c->debug_level>=3) {
				de_dbg3(c, "lit 0x%02x", (UI)b);
			}
			de_lz77buffer_add_literal_byte(ringbuf, b);
			continue;
		}

		len_raw = read_pklite_code_using_tree(c, d, d->lengths_tree);
		if(d->errflag) goto done;

		if((len_raw==23 && d->large_cmpr) || (len_raw==8 && !d->large_cmpr)) {
			b = de_getbyte_p(&d->dcmpr_cur_ipos);
			if(b==0xfe) {
				// TODO - Do we have to do anything here?
				de_dbg3(c, "code 0xfe");
				continue;
			}
			if(b==0xff) {
				de_dbg3(c, "stop code");
				goto done; // Normal completion
			}
			matchlen = (UI)b+(d->large_cmpr?25:10);
		}
		else {
			matchlen = len_raw+2;
		}

		if(matchlen==2) {
			offs_hi_bits = 0;
		}
		else {
			offs_hi_bits = read_pklite_code_using_tree(c, d, d->offsets_tree);
		}

		offs_lo_byte = de_getbyte_p(&d->dcmpr_cur_ipos);
		if(d->errflag) goto done;

		// Weird. Usually with LZ77, a matchpos of "0" means the most recently
		// written byte.
		// In PKLITE, "1" means the most recently written byte, and "0" means...
		// I don't know. (TODO)
		matchpos = (offs_hi_bits<<8) | (UI)offs_lo_byte;

		if(c->debug_level>=3) {
			de_dbg3(c, "match pos=%u len=%u", matchpos, matchlen);
		}
		de_lz77buffer_copy_from_hist(ringbuf,
				(UI)(ringbuf->curpos-matchpos), matchlen);
	}

done:
	if(!d->errflag && d->o_dcmpr_code) {
		d->cmpr_data_endpos = d->dcmpr_cur_ipos;
		de_dbg(c, "cmpr data end: %"I64_FMT, d->cmpr_data_endpos);
		de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT,
			d->cmpr_data_endpos-d->cmpr_data_pos, d->o_dcmpr_code->len);
	}
	de_dbg_indent(c, -1);
}

static void do_read_reloc_table_short(deark *c, lctx *d)
{
	i64 reloc_count = 0;
	i64 pos = d->cmpr_data_endpos;

	while(1) {
		UI i;
		UI count;
		i64 seg, offs;

		count = (UI)de_getbyte_p(&pos);
		if(count==0) goto done; // normal completion

		seg = de_getu16le_p(&pos);
		for(i=0; i<count; i++) {
			if(reloc_count>=d->o_ei->num_relocs) {
				d->errflag = 1;
				goto done;
			}
			offs = de_getu16le_p(&pos);
			dbuf_writeu16le(d->o_reloc_table, offs);
			dbuf_writeu16le(d->o_reloc_table, seg);
			reloc_count++;
		}
	}

done:
	if(reloc_count !=d->o_ei->num_relocs) {
		d->errflag = 1;
	}
}

static void do_read_reloc_table_long(deark *c, lctx *d)
{
	// TODO: Implement this
	d->errflag = 1;
}

static void do_read_reloc_table(deark *c, lctx *d)
{
	d->o_reloc_table = dbuf_create_membuf(c, d->o_ei->num_relocs*4, 0x1);

	if(d->extra_cmpr && d->pklver>=0x112) {
		do_read_reloc_table_long(c, d);
	}
	else {
		do_read_reloc_table_short(c, d);
	}
}

// Generate the decompressed file
static void do_write_dcmpr(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 amt_to_copy;

	if(d->errflag || !d->o_ei || !d->o_orig_header || !d->o_dcmpr_code || !d->o_reloc_table) return;
	de_dbg(c, "generating output file");
	de_dbg_indent(c, 1);

	outf = dbuf_create_output_file(c, "exe", NULL, 0);

	// Write the original header, up to the relocation table
	amt_to_copy = de_min_int(d->orig_hdr_len, d->o_ei->reloc_table_pos);
	dbuf_copy(d->o_orig_header, 0, amt_to_copy, outf);
	dbuf_truncate(outf, d->o_ei->reloc_table_pos);

	// Write the relocation table
	dbuf_copy(d->o_reloc_table, 0, d->o_reloc_table->len, outf);

	// Pad up to the start of DOS code.
	// (Note that PKLITE does not record data between the end of the relocation
	// table, and the start of DOS code, so we can't reconstruct that.)
	dbuf_truncate(outf, d->o_ei->start_of_dos_code);

	dbuf_copy(d->o_dcmpr_code, 0, d->o_dcmpr_code->len, outf);

	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

static void de_run_pklite(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct fmtutil_specialexe_detection_data edd;

	d = de_malloc(c, sizeof(lctx));

	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, c->infile, d->ei);

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.restrict_to_fmt = DE_SPECIALEXEFMT_PKLITE;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(edd.detected_fmt!=DE_SPECIALEXEFMT_PKLITE) {
		de_err(c, "Not a PKLITE file");
		goto done;
	}
	de_declare_fmt(c, edd.detected_fmt_name);

	do_read_header(c, d);
	if(d->errflag) goto done;
	do_decompress(c, d);
	if(d->errflag) goto done;

	do_read_reloc_table(c, d);
	if(d->errflag) goto done;

	do_write_dcmpr(c, d);

done:

	if(d) {
		if(d->errflag && !d->errmsg_handled) {
			de_err(c, "PKLITE decompression failed");
		}

		dbuf_close(d->o_orig_header);
		dbuf_close(d->o_reloc_table);
		dbuf_close(d->o_dcmpr_code);
		de_free(c, d->o_ei);
		de_free(c, d->ei);
		fmtutil_huffman_destroy_decoder(c, d->lengths_tree);
		fmtutil_huffman_destroy_decoder(c, d->offsets_tree);
		de_free(c, d);
	}
}

void de_module_pklite(deark *c, struct deark_module_info *mi)
{
	mi->id = "pklite";
	mi->desc = "PKLITE executable compression";
	mi->run_fn = de_run_pklite;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
