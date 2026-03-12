// This file is part of Deark.
// Copyright (C) 2026 Jason Summers
// See the file COPYING for terms of use.

// Realia Spacemaker executable compression

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_spacemaker);

#define SM_PREAMBLE_SIZE 25

struct reloc_item {
	u32 cmpr_pos;
	u32 dcmpr_pos;
	u8 val_bytes[2];
};

struct sm_exe_output_info {
	UI regSS;
	UI regSP;
	UI regCS;
	UI regIP;
	i64 minalloc;
	i64 code_pos;
	i64 num_relocs;
	i64 relocs_capacity;
	struct reloc_item *relocs; // array[relocs_capacity]
	i64 final_start_of_code;
	i64 final_file_size; // not including overlay
};

typedef struct localctx_spacemaker {
	u8 errflag;
	u8 need_errmsg;
	u8 raw_mode; // 0xff = not set
	u8 original_was_exe;
	u8 host_is_exe;
	i64 code_pos; // host EXE code segment pos (0 for COM)
	i64 orig_len;
	i64 cmpr_len; // = part1_len + part2_len
	i64 part1_pos, part1_len; // first 25 bytes
	i64 part2_pos, part2_endpos, part2_len; // rest of file
	i64 part3_pos, part3_len; // reloc. table(?)
	i64 decoder_pos1, decoder_pos2;
	i64 num_reloc_chains;
	dbuf *cmpr_code;
	dbuf *dcmpr_code;
	struct fmtutil_exe_info *host_ei;
	struct sm_exe_output_info gst;
} lctx;

static void sm_decompress(deark *c, lctx *d)
{
	i64 ipos; // in d->cmpr_code
	i64 istartpos;
	i64 opos; // in d->dcmpr_code
	i64 i;
	i64 nrelocs_left;
	u8 b[2];
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "[decompressing]");
	de_dbg_indent(c, 1);

	// Relocs in the noncompressed "preamble" can be copied unchanged.
	for(i=0; i<d->gst.num_relocs; i++) {
		if(d->gst.relocs[i].cmpr_pos >= SM_PREAMBLE_SIZE) break;
		d->gst.relocs[i].dcmpr_pos = d->gst.relocs[i].cmpr_pos;
	}

	dbuf_copy(d->cmpr_code, 0, d->part1_len, d->dcmpr_code);
	de_dbg(c, "copied %"I64_FMT" bytes", d->part1_len);

	de_zeromem(b, sizeof(b));
	dbuf_truncate(d->dcmpr_code, d->orig_len);

	opos = d->orig_len;
	ipos = d->cmpr_len;
	istartpos = SM_PREAMBLE_SIZE;

	if(d->orig_len <= SM_PREAMBLE_SIZE) {
		goto done;
	}

	nrelocs_left = d->gst.num_relocs;

	while(1) {
		i64 count;
#define CT_U 1 // An uncompressed segment
#define CT_R 2 // A run of 0-valued bytes
		u8 code_type;

		if(ipos<=istartpos) goto done;

		code_type = 0;
		count = 0;

		ipos--;
		b[0] = dbuf_getbyte(d->cmpr_code, ipos);
		if(b[0] & 0x01) {
			// ... xxxxxxx1
			ipos--;
			b[1] = dbuf_getbyte(d->cmpr_code, ipos);
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

			// This is a delicate operation. We have to identify the relocations in this
			// uncompressed segment of the compressed data, and translate them to the
			// correct position in the decompressed data.
			while(1) {
				if(nrelocs_left<=0) break;
				if(d->gst.relocs[nrelocs_left-1].cmpr_pos < (u32)ipos) break;
				d->gst.relocs[nrelocs_left-1].dcmpr_pos =
					(u32)opos + (d->gst.relocs[nrelocs_left-1].cmpr_pos-(u32)ipos);
				nrelocs_left--;
			}

			dbuf_copy_at(d->cmpr_code, ipos, count, d->dcmpr_code, opos);
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

#define SM_MAX_RELOCS_TOTAL     65535
#define SM_MAX_RELOCS_PER_CHAIN 65535

static void sm_record_reloc(deark *c, lctx *d, const struct reloc_item *ri)
{

	if(d->gst.num_relocs >= SM_MAX_RELOCS_TOTAL) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(d->gst.num_relocs >= d->gst.relocs_capacity) {
		i64 old_capacity, new_capacity;

		old_capacity = d->gst.relocs_capacity;
		new_capacity = old_capacity*2;

		if(new_capacity<256) {
			new_capacity = 256;
		}
		d->gst.relocs = de_reallocarray(c, d->gst.relocs,
			old_capacity, sizeof(struct reloc_item), new_capacity);
		d->gst.relocs_capacity = new_capacity;
	}

	d->gst.relocs[d->gst.num_relocs] = *ri; // struct copy
	d->gst.num_relocs++;

done:
	;
}

static void sm_dump_reloc_tbl(deark *c, lctx *d)
{
	i64 i;

	de_dbg(c, "relocations");
	de_dbg_indent(c, 1);
	for(i=0; i<d->gst.num_relocs; i++) {
		de_dbg(c, "r[%d]: c=%u u=%u v=[%02x %02x]",
			(int)i, (UI)d->gst.relocs[i].cmpr_pos,
			(UI)d->gst.relocs[i].dcmpr_pos,
			(UI)d->gst.relocs[i].val_bytes[0],
			(UI)d->gst.relocs[i].val_bytes[1]);
	}
	de_dbg_indent(c, -1);
}

static int reloc_compare_fn(const void *a, const void *b)
{
	struct reloc_item *m1, *m2;

	m1 = (struct reloc_item *)a;
	m2 = (struct reloc_item *)b;
	if(m1->cmpr_pos > m2->cmpr_pos) return 1;
	else if(m1->cmpr_pos < m2->cmpr_pos) return -1;
	return 0;
}

static void sm_sort_reloc_tbl(deark *c, lctx *d)
{
	qsort((void*)d->gst.relocs,
		(size_t)d->gst.num_relocs, sizeof(struct reloc_item),
		reloc_compare_fn);
}

// Purpose is to find duplicate or overlapping relocations, and
// internal errors.
static void sm_check_reloc_tbl(deark *c, lctx *d)
{
	i64 i;

	for(i=0; i<d->gst.num_relocs; i++) {
		if(d->gst.relocs[i].dcmpr_pos > 0xfffff) {
			de_err(c, "Reloc error at %d", (int)i);
			d->errflag = 1;
			goto done;
		}
		if(i>=1) {
			if(d->gst.relocs[i].dcmpr_pos - d->gst.relocs[i-1].dcmpr_pos < 2) {
				de_err(c, "Reloc error at %d", (int)i);
				d->errflag = 1;
				goto done;
			}
		}
	}
done:
	;
}

static void sm_read_relocs(deark *c, lctx *d)
{
	i64 cha;
	i64 reloc_count_total = 0;
	struct reloc_item tmp_reloc_item;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_zeromem(&tmp_reloc_item, sizeof(struct reloc_item));
	de_dbg(c, "[relocations]");
	de_dbg_indent(c, 1);

	if(d->part3_len != d->num_reloc_chains*5) {
		d->errflag = 1;
		goto done;
	}

	d->num_reloc_chains = d->part3_len / 5;
	de_dbg(c, "num chains: %"I64_FMT, d->num_reloc_chains);
	if(d->num_reloc_chains<1) goto done;
	for(cha=0; cha<d->num_reloc_chains; cha++) {
		i64 reloc_count_this_chain = 0;
		i64 chain_info_pos;
		u8 val_bytes[2];
		UI val_int;
		UI h_high;
		UI h_low;
		UI cur_low;
		i64 base_addr;
		i64 head;

		chain_info_pos = d->code_pos + d->part3_pos + 5*cha;
		de_dbg(c, "chain at %"I64_FMT, chain_info_pos);
		de_dbg_indent(c, 1);
		h_high = (UI)de_getbyte(chain_info_pos);
		base_addr = (i64)h_high*4096;
		de_dbg(c, "base: %"I64_FMT, base_addr);
		dbuf_read(c->infile, val_bytes, chain_info_pos+1, 2);
		val_int = (UI)de_getu16le_direct(val_bytes);
		h_low = (UI)de_getu16le(chain_info_pos+3);
		de_dbg(c, "value: 0x%04x", val_int);
		head = base_addr + (i64)h_low;
		de_dbg2(c, "head: %"I64_FMT" + %u = %"I64_FMT, base_addr, h_low, head);

		de_dbg2(c, "[walking chain]");
		de_dbg_indent(c, 1);
		cur_low = h_low;
		while(cur_low!=0xffff) {
			UI new_low;
			i64 cur_addr;

			if(reloc_count_total>=SM_MAX_RELOCS_TOTAL ||
				reloc_count_this_chain >= SM_MAX_RELOCS_PER_CHAIN)
			{
				d->errflag = 1;
				goto done;
			}

			cur_addr = base_addr+(i64)cur_low;
			if(cur_addr > d->cmpr_len) {
				d->errflag = 1;
				goto done;
			}

			new_low = (UI)dbuf_getu16le(d->cmpr_code, cur_addr);
			de_dbg2(c, "at 0x%04x read 0x%04x", cur_low, new_low);

			reloc_count_this_chain++;
			reloc_count_total++;

			if(new_low==0xffff) {
				;
			}
			else if(new_low+2 > cur_low) {
				// AFAICT, relocations in a chain always decrease.
				d->errflag = 1;
				goto done;
			}

			tmp_reloc_item.cmpr_pos = (UI)cur_addr;
			de_memcpy(tmp_reloc_item.val_bytes, val_bytes, 2);
			sm_record_reloc(c, d, &tmp_reloc_item);
			if(d->errflag) goto done;

			cur_low = new_low;
		}

		de_dbg_indent(c, -1);
		de_dbg(c, "relocs in chain: %"I64_FMT, reloc_count_this_chain);
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "total relocs: %"I64_FMT, reloc_count_total);

done:
	if(d->errflag) {
		de_err(c, "Failed to decode relocations");
		d->need_errmsg = 0;
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// Modify the compressed(!) data to restore the original values at
// the positions of the relocations.
// We could just as easily do this to the decompressed data instead, but
// (1) this is how Spacemaker does it (!), and (2) this way should make it
// more obvious if something goes wrong.
static void sm_restore_relocs(deark *c, lctx *d)
{
	i64 i;

	for(i=0; i<d->gst.num_relocs; i++) {
		dbuf_write_at(d->cmpr_code, (i64)d->gst.relocs[i].cmpr_pos,
			d->gst.relocs[i].val_bytes, 2);
	}
}

static void sm_write_com_or_raw(deark *c, lctx *d)
{
	const char *ext;
	dbuf *outf = NULL;

	ext = d->original_was_exe ? "bin" : "com";
	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(d->dcmpr_code, 0, d->dcmpr_code->len, outf);

	if(outf) {
		dbuf_close(outf);
		if(!d->errflag) {
			de_stdwarn_execomp(c);
		}
	}
}

// Sets d->gst.minalloc
static void sm_calc_gst_minalloc(deark *c, lctx *d)
{
	i64 host_minalloc_para;
	i64 host_codesize_bytes;
	i64 guest_codesize_bytes;

	if(!d->host_is_exe) {
		d->gst.minalloc = 0x1000; // TODO: Can this be improved?
		goto done;
	}

	host_minalloc_para = de_getu16le(10);
	host_codesize_bytes = d->host_ei->end_of_dos_code - d->host_ei->start_of_dos_code;
	guest_codesize_bytes = d->orig_len;

	if(host_codesize_bytes >= guest_codesize_bytes) {
		d->gst.minalloc = host_minalloc_para;
		goto done;
	}

	d->gst.minalloc = host_minalloc_para;
	d->gst.minalloc -= de_pad_to_n(guest_codesize_bytes-host_codesize_bytes, 16)/16;
	if(d->gst.minalloc<0) d->gst.minalloc = 0;
done:
	;
}

static void sm_write_exe(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	i64 final_reloc_pos = 28;
	i64 final_reloc_size;
	i64 i;

	outf = dbuf_create_output_file(c, "exe", NULL, 0);
	final_reloc_size = d->gst.num_relocs * 4;
	d->gst.final_start_of_code = de_pad_to_n(final_reloc_pos +
		final_reloc_size, 16);
	d->gst.final_file_size = d->gst.final_start_of_code + d->orig_len;

	// Generate 28-byte header
	dbuf_writeu16le(outf, 0x5a4d); // 0  signature
	dbuf_writeu16le(outf, d->gst.final_file_size%512); // 2  # of bytes in last page
	dbuf_writeu16le(outf, (d->gst.final_file_size+511)/512); // 4  # of pages
	dbuf_writeu16le(outf, d->gst.num_relocs); // 6  # of reloc tbl entries
	dbuf_writeu16le(outf, d->gst.final_start_of_code / 16); // 8  hdrsize/16

	sm_calc_gst_minalloc(c, d);
	dbuf_writeu16le(outf, d->gst.minalloc);

	// SM only compresses files with maxmem=0xffff, so...
	dbuf_writeu16le(outf, 0xffff); // 12 maxmem

	dbuf_writeu16le(outf, d->gst.regSS); // 14  ss
	dbuf_writeu16le(outf, d->gst.regSP); // 16  sp
	dbuf_writeu16le(outf, 0); // 18  checksum
	dbuf_writeu16le(outf, d->gst.regIP); // 20  ip
	dbuf_writeu16le(outf, d->gst.regCS); // 22  cs
	dbuf_writeu16le(outf, final_reloc_pos); // 24  reloc_tbl_pos
	dbuf_writeu16le(outf, 0); // 26  overlay indicator

	// Write the relocation table
	dbuf_truncate(outf, final_reloc_pos);
	for(i=0; i<d->gst.num_relocs; i++) {
		UI seg, offs;

		seg = (d->gst.relocs[i].dcmpr_pos&0x000ff000)>>4;
		offs = d->gst.relocs[i].dcmpr_pos & 0x0fff;
		dbuf_writeu16le(outf, offs);
		dbuf_writeu16le(outf, seg);
	}

	dbuf_truncate(outf, d->gst.final_start_of_code);
	dbuf_copy(d->dcmpr_code, 0, d->dcmpr_code->len, outf);

	// Copy overlay data (sometimes).
	// Spacemaker doesn't do overlays, but it does add its own, in the form of
	// some 0-valued bytes appended to the EXE file. We won't copy the overlay
	// unless it seems to have been modified.
	if(d->host_is_exe && d->host_ei->overlay_len>0) {
		if(!dbuf_is_all_zeroes(c->infile, d->host_ei->end_of_dos_code,
			d->host_ei->overlay_len))
		{
			de_dbg(c, "overlay data at %"I64_FMT", len=%"I64_FMT, d->host_ei->end_of_dos_code,
				d->host_ei->overlay_len);
			dbuf_copy(c->infile, d->host_ei->end_of_dos_code, d->host_ei->overlay_len, outf);
		}
	}

	if(outf) {
		dbuf_close(outf);
		if(!d->errflag) {
			de_stdwarn_execomp(c);
		}
	}
}

static void spacemaker_main(deark *c, lctx *d)
{
	i64 jmppos;
	i64 tmp_seg, tmp_offs;
	UI x;
	UI ver;
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

	d->num_reloc_chains = de_getu16le(code_pos+d->decoder_pos2+63);

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

	d->gst.regSS = (UI)de_getu16le(code_pos+d->decoder_pos2+194);
	d->gst.regSP = (UI)de_getu16le(code_pos+d->decoder_pos2+199);
	d->gst.regIP = (UI)de_getu16le(code_pos+d->decoder_pos2+205);
	d->gst.regCS = (UI)de_getu16le(code_pos+d->decoder_pos2+207);

	d->part1_pos = d->part2_endpos;
	d->part2_pos = SM_PREAMBLE_SIZE;
	d->part3_pos = d->part1_pos + SM_PREAMBLE_SIZE;
	d->part3_len = d->decoder_pos1 - d->part3_pos;
	d->part1_len = de_min_int(d->orig_len, SM_PREAMBLE_SIZE);
	d->part2_len = d->part2_endpos - d->part2_pos;
	d->cmpr_len = d->part1_len + d->part2_len;

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

	// Make a copy of the compressed code, so that it's contiguous, and
	// so we can modify it.
	d->cmpr_code = dbuf_create_membuf(c, d->cmpr_len, 0x1);
	dbuf_copy(c->infile, d->code_pos+d->part1_pos, d->part1_len, d->cmpr_code);
	if(d->part2_len>0) {
		dbuf_copy_at(c->infile, d->code_pos+d->part2_pos, d->part2_len,
			d->cmpr_code, SM_PREAMBLE_SIZE);
	}

	if(d->original_was_exe) {
		sm_read_relocs(c, d);
	}
	if(d->errflag) goto done;

	sm_sort_reloc_tbl(c, d);

	// TODO: In raw mode, maybe there should be an option to not do this.
	sm_restore_relocs(c, d);
	if(d->errflag) goto done;

	d->dcmpr_code = dbuf_create_membuf(c, d->orig_len, 0x1);
	sm_decompress(c, d);
	if(d->errflag) goto done;

	sm_check_reloc_tbl(c, d);
	if(d->errflag) goto done;

	if(c->debug_level>=2) {
		sm_dump_reloc_tbl(c, d);
	}

	if(d->original_was_exe && d->raw_mode!=1) {
		sm_write_exe(c, d);
	}
	else {
		sm_write_com_or_raw(c, d);
	}

done:
	;
}

static void spacemaker_exe_main(deark *c, lctx *d)
{
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

	dbuf_close(d->cmpr_code);
	dbuf_close(d->dcmpr_code);
	if(d->need_errmsg) {
		de_err(c, "Bad or unsupported Spacemaker file");
	}
	de_free(c, d->host_ei);
	de_free(c, d->gst.relocs);
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
