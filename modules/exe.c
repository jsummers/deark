// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// EXE executable formats

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_exe);

#define EXE_FMT_DOS    1
#define EXE_FMT_NE     2
#define EXE_FMT_PE     3
#define EXE_SUBFMT_PE32      1
#define EXE_SUBFMT_PE32PLUS  2
#define EXE_FMT_LX     5
#define EXE_FMT_LE     6

#define MAX_RESOURCES 10000

#define DE_RT_CURSOR        1
#define DE_RT_BITMAP        2
#define DE_RT_ICON          3
#define DE_RT_FONTDIR       7
#define DE_RT_FONT          8
#define DE_RT_GROUP_CURSOR  12
#define DE_RT_GROUP_ICON    14
#define DE_RT_ANICURSOR     21
#define DE_RT_ANIICON       22
#define DE_RT_MANIFEST      24

struct rsrc_type_info_struct;

typedef struct localctx_struct {
	u8 fmt;
	u8 subfmt;
	u8 execomp_mode; // 0 or 1; 0xff=unspecified
	u8 sfx_only_mode;
	u8 extract_std_resources;
	u8 check_checksum;
	u8 rsrc_errflag;
	struct fmtutil_exe_info *ei;

	i64 reloc_tbl_offset;
	i64 reloc_tbl_endpos;
	i64 file_hdr_size;
	i64 num_relocs;
	i64 end_of_dos_code;
	i64 ext_header_offset;
	UI checksum_reported;

	i64 ne_number_of_segments;
	i64 ne_segment_tbl_offset;
	i64 ne_rsrc_tbl_offset;
	UI ne_header_flags;
	UI ne_filealign_shift;
	UI ne_rcalign_shift;
	int ne_have_type;
	u32 ne_rsrc_type_id;
	const struct rsrc_type_info_struct *ne_rsrc_type_info;
	u8 might_be_ishield_sfx_ne;
	i64 ishield_sfx_ne_rsrc_pos;
	i64 ishield_sfx_ne_rsrc_len;

	i64 lx_page_offset_shift;
	i64 lx_object_tbl_offset;
	i64 lx_object_tbl_entries;
	i64 lx_object_page_tbl_offset;
	i64 lx_rsrc_tbl_offset;
	i64 lx_rsrc_tbl_entries;
	i64 lx_data_pages_offset;

	i64 pe_opt_hdr_size;
	i64 pe_sections_offset;
	i64 pe_number_of_sections;

	// File offset where the resources start. Some addresses are relative
	// to this.
	i64 pe_cur_base_addr;

	i64 pe_cur_section_virt_addr;
	i64 pe_cur_section_data_offset;

	i64 pe_cur_name_offset; // 0 if no name

	u32 cur_rsrc_type;
	const struct rsrc_type_info_struct *cur_rsrc_type_info;

	i64 rsrc_item_count;
} lctx;

struct rsrc_type_info_struct;

typedef void (*rsrc_decoder_fn)(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi);

struct rsrc_type_info_struct {
	u32 id;
	u8 flags;
	const char *name;
	rsrc_decoder_fn decoder_fn;
};

static void do_certificate(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 dlen;
	i64 revision;
	i64 certtype;

	// This is a WIN_CERTIFICATE structure.
	if(pos1<1 || len<=8 || (pos1+len > c->infile->len)) return;

	de_dbg(c, "certificate data at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	dlen = de_getu32le(pos1);
	de_dbg(c, "length: %"I64_FMT, dlen); // Includes the 8-byte header
	revision = de_getu16le(pos1+4);
	de_dbg(c, "revision: 0x%04x", (UI)revision);
	certtype = de_getu16le(pos1+6);
	de_dbg(c, "cert type: %d", (int)certtype);
	if(dlen<=8 || dlen > len) goto done;
	if(d->extract_std_resources && c->extract_level>=2) {
		const char *ext;
		if(certtype==2) ext="p7b";
		else ext="crt";
		dbuf_create_file_from_slice(c->infile, pos1+8, dlen-8, ext, NULL, 0);
	}
done:
	de_dbg_indent(c, -1);

}

static void do_opt_coff_data_dirs(deark *c, lctx *d, i64 pos)
{
	i64 rsrc_tbl_rva;
	i64 rsrc_tbl_size;
	i64 pe_security_pos;
	i64 pe_security_size;

	de_dbg(c, "COFF/PE optional header (data directories) at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	rsrc_tbl_rva = de_getu32le(pos+16);
	// I don't know if rsrc_tbl_rva will be needed for anything. It seems redundant.
	rsrc_tbl_size = de_getu32le(pos+20);
	de_dbg(c, "resource table RVA=0x%08x, size=%"I64_FMT, (UI)rsrc_tbl_rva,
		rsrc_tbl_size);

	pe_security_pos = de_getu32le(pos+32);
	pe_security_size = de_getu32le(pos+36);
	de_dbg(c, "security pos=0x%08x, size=%"I64_FMT, (UI)pe_security_pos,
		pe_security_size);
	if(pe_security_pos>0) {
		de_dbg_indent(c, 1);
		do_certificate(c, d, pe_security_pos, pe_security_size);
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static const char *get_subsys_desc(i64 subsystem)
{
	switch(subsystem) {
	case 2: return " (Windows GUI)";
	case 3: return " (console)";
	}
	return "";
}

static void do_opt_coff_nt_header(deark *c, lctx *d, i64 pos)
{
	i64 x;
	i64 subsystem;

	de_dbg(c, "COFF/PE optional header (Windows NT) at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	x = de_getu32le(pos);
	de_dbg(c, "image base offset: 0x%08x", (UI)x);

	subsystem = de_getu16le(pos+40);
	de_dbg(c, "subsystem: %d%s", (int)subsystem, get_subsys_desc(subsystem));

	de_dbg_indent(c, -1);
}

static void do_opt_coff_nt_header_64(deark *c, lctx *d, i64 pos)
{
	i64 base_offset;
	i64 subsystem;

	de_dbg(c, "COFF/PE32+ optional header (Windows NT) at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	base_offset = de_geti64le(pos);
	de_dbg(c, "image base offset: 0x%016" U64_FMTx "", (u64)base_offset);

	subsystem = de_getu16le(pos+44);
	de_dbg(c, "subsystem: %d%s", (int)subsystem, get_subsys_desc(subsystem));

	de_dbg_indent(c, -1);
}

static void do_opt_coff_header(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 sig;
	i64 coff_opt_hdr_size;

	de_dbg(c, "COFF/PE optional header at %"I64_FMT", size=%"I64_FMT, pos, len);
	de_dbg_indent(c, 1);

	sig = de_getu16le(pos);
	de_dbg(c, "signature: 0x%04x", (int)sig);

	if(sig==0x010b)
		coff_opt_hdr_size = 28;
	else
		coff_opt_hdr_size = 24;

	if(sig==0x010b) {
		d->subfmt = EXE_SUBFMT_PE32;
		de_declare_fmt(c, "PE32");
		do_opt_coff_nt_header(c, d, pos+coff_opt_hdr_size);
		do_opt_coff_data_dirs(c, d, pos+coff_opt_hdr_size+68);
	}
	else if(sig==0x020b) {
		d->subfmt = EXE_SUBFMT_PE32PLUS;
		de_declare_fmt(c, "PE32+");
		do_opt_coff_nt_header_64(c, d, pos+coff_opt_hdr_size);
		do_opt_coff_data_dirs(c, d, pos+coff_opt_hdr_size+88);
	}
	else if(sig==0x0107) {
		de_declare_fmt(c, "PE ROM image");
	}
	else {
		de_declare_fmt(c, "Unknown PE file type");
	}

	de_dbg_indent(c, -1);
}

static void do_pe_characteristics(deark *c, lctx *d, UI v)
{
	de_ucstring *s = NULL;
	s = ucstring_create(c);

	if(v&0x0001) ucstring_append_flags_item(s, "relocs_stripped");
	if(v&0x0002) ucstring_append_flags_item(s, "valid_executable");
	if(v&0x0004) ucstring_append_flags_item(s, "COFF_line_numbers_stripped");
	if(v&0x0008) ucstring_append_flags_item(s, "COFF_local_stripped");
	if(v&0x0020) ucstring_append_flags_item(s, "large_address_aware");
	if(v&0x0100) ucstring_append_flags_item(s, "32-bit");
	if(v&0x0200) ucstring_append_flags_item(s, "stripped");
	if(v&0x2000) ucstring_append_flags_item(s, "DLL");
	// TODO: There are more flags than this.
	de_dbg(c, "characteristics: 0x%04x (%s)", v, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static const char *get_machine_type_name(UI n)
{
	size_t i;
	struct mtn_struct { UI id; const char *name; };
	static const struct mtn_struct mtn_arr[] = {
		{ 0x0000, "neutral" },
		{ 0x014c, "386+" },
		{ 0x0166, "MIPS LE" },
		{ 0x0169, "MIPS LE WCE v2" },
		{ 0x01a2, "Hitachi SH3" },
		{ 0x01a3, "Hitachi SH3 DSP" },
		{ 0x01a6, "Hitachi SH4" },
		{ 0x01a8, "Hitachi SH5" },
		{ 0x01c0, "ARM LE" },
		{ 0x01c2, "ARM or Thumb" },
		{ 0x01c4, "ARMv7+ Thumb" },
		{ 0x01d3, "Matsushita AM33" },
		{ 0x01f0, "Power PC LE" },
		{ 0x01f1, "Power PC w/FP" },
		{ 0x0200, "Itanium" },
		{ 0x0266, "MIPS16" },
		{ 0x0366, "MIPS with FPU" },
		{ 0x0466, "MIPS16 with FPU" },
		{ 0x0ebc, "EFI byte code" },
		{ 0x8664, "x64" },
		{ 0x9041, "Mitsubishi M32R LE" },
		{ 0xaa64, "ARMv8 64-bit" }
	};

	for(i=0; i<DE_ARRAYCOUNT(mtn_arr); i++) {
		if(mtn_arr[i].id == n) {
			return mtn_arr[i].name;
		}
	}
	return "?";
}

static void do_Rich_segment(deark *c, lctx *d)
{
	i64 segment_start;
	i64 segment_end;
	i64 sig_pos;
	i64 pos;
	i64 p;
	i64 k;
	u32 n;
	u32 key;
	i64 num_entries;

	segment_start = 128;
	segment_end = d->ext_header_offset;
	if(segment_end%8) segment_end -= segment_end%8;
	if(segment_end - segment_start < 24) return; // No place for a Rich segment

	// Try to find the "Rich" signature", which starts 8 bytes from the end of
	// the Rich segment.
	// Based on limited research, the Rich signature usually starts 16, 24, or 32
	// bytes before the "PE" signature.
	sig_pos = 0;
	for(p = segment_end-8; p >= segment_start+16; p -= 8 ) {
		n = (u32)de_getu32le(p);
		if(n==0x68636952U) { // "Rich"
			sig_pos = p;
			break;
		}
	}
	if(sig_pos==0) {
		return; // Rich segment not found
	}

	// Likely "Rich" signature found at sig_pos

	key = (u32)de_getu32le(sig_pos+4);

	// Decode and verify the "start" signature
	n = (u32)de_getu32le(segment_start);
	if((n ^ key) != 0x536e6144U) { // "Dans"
		// False positive? Or maybe our detection logic isn't perfect?
		return;
	}

	de_dbg(c, "\"Rich\" segment detected at %"I64_FMT", sig at %"I64_FMT", len=%"I64_FMT,
		segment_start, sig_pos,
		(i64)(sig_pos+8 - segment_start));

	de_dbg_indent(c, 1);

	pos = segment_start + 16;
	num_entries  = (sig_pos - pos)/8;
	for(k=0; k<num_entries; k++) {
		u32 id_and_value;
		u32 id;
		u32 value;
		u32 use_count;

		id_and_value = (u32)de_getu32le(pos+8*k);
		use_count = (u32)de_getu32le(pos+8*k+4);
		id_and_value ^= key;
		use_count ^= key;
		id = (id_and_value&0xffff0000U)>>16;
		value = id_and_value&0x0000ffffU;
		// TODO: Provide additional information, based on the 'type' and 'build'?
		de_dbg(c, "entry[%d]: type=%u, build=%u, use_count=%u",
			(int)k, (UI)id, (UI)value, (UI)use_count);
	}

	de_dbg_indent(c, -1);
}

// 'pos' is the start of the 4-byte PE signature.
// Following it is a 20-byte COFF header.
static void do_pe_coff_header(deark *c, lctx *d, i64 pos)
{
	UI arch;
	i64 n;

	de_dbg(c, "PE header at %"I64_FMT, d->ext_header_offset);
	de_dbg_indent(c, 1);

	// a.k.a. "Machine". TODO: Decode this.
	arch = (UI)de_getu16le(pos+4+0);
	de_dbg(c, "target architecture: 0x%04x (%s)", arch,
		get_machine_type_name(arch));

	d->pe_number_of_sections = de_getu16le(pos+4+2);
	de_dbg(c, "number of sections: %d", (int)d->pe_number_of_sections);

	d->pe_opt_hdr_size = de_getu16le(pos+4+16);
	de_dbg(c, "optional header size: %"I64_FMT, d->pe_opt_hdr_size);

	n = de_getu16le(pos+4+18);
	do_pe_characteristics(c, d, (UI)n);

	if(d->pe_opt_hdr_size>0) {
		do_opt_coff_header(c, d, pos+4+20, d->pe_opt_hdr_size);
		d->pe_sections_offset = pos+4+20+d->pe_opt_hdr_size;
	}

	de_dbg_indent(c, -1);
}

static void do_ne_header_flags(deark *c, lctx *d)
{
	de_ucstring *s = NULL;
	UI flags = d->ne_header_flags;
	UI n;

	s = ucstring_create(c);

	// TODO: Need better information about these flags.
	// (And do they depend on other fields, such as target_os?)

	n = flags & 0x0003;
	ucstring_append_flags_itemf(s, "dgroup=%u", n);
	flags -= n;

	if(flags & 0x0004) {
		ucstring_append_flags_item(s, "real mode");
		flags -= 0x0004;
	}
	if(flags & 0x0008) {
		ucstring_append_flags_item(s, "protected mode");
		flags -= 0x0008;
	}

	if(flags & 0x8000) {
		ucstring_append_flags_item(s, "DLL");
		flags -= 0x8000;
	}

	if(flags) {
		ucstring_append_flags_itemf(s, "0x%04x", flags);
	}

	de_dbg(c, "NE header flags: 0x%04x (%s)", d->ne_header_flags,
		ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_ne_ext_header(deark *c, lctx *d, i64 pos1)
{
	u8 target_os;
	const char *desc;
	u8 b1, b2;

	de_dbg(c, "NE extended header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	b1 = de_getbyte(pos1+2);
	b2 = de_getbyte(pos1+3);
	de_dbg(c, "linker version: %d.%d", (int)b1,(int)b2);

	// 4-5: Offset of entry table
	// 6-7: length of entry table
	// 8-11: file load CRC

	d->ne_header_flags = (UI)de_getu16le(pos1+12);
	do_ne_header_flags(c, d);

	d->ne_number_of_segments = de_getu16le(pos1+28);
	de_dbg(c, "number of segments: %d", (int)d->ne_number_of_segments);

	if(d->ne_number_of_segments) {
		d->ne_segment_tbl_offset = de_getu16le(pos1+34);
		d->ne_segment_tbl_offset += pos1;
		de_dbg(c, "offset of segment table: %"I64_FMT, d->ne_segment_tbl_offset);
	}

	d->ne_rsrc_tbl_offset = de_getu16le(pos1+36);
	d->ne_rsrc_tbl_offset += pos1;
	de_dbg(c, "offset of resource table: %"I64_FMT, d->ne_rsrc_tbl_offset);

	d->ne_filealign_shift = (UI)de_getu16le(pos1+50);
	if(d->ne_filealign_shift==0) d->ne_filealign_shift = 9;
	de_dbg(c, "align shift: %u", d->ne_filealign_shift);

	target_os = de_getbyte(pos1+54);
	switch(target_os) {
	case 1: desc="OS/2"; break;
	case 2: desc="Windows"; break;
	case 3: desc="European MS-DOS 4.x"; break;
	case 4: desc="Windows 386"; break;
	case 5: desc="Borland Operating System Services"; break;
	default: desc="?";
	}
	de_dbg(c, "target OS: %d (%s)", (int)target_os, desc);

	de_dbg_indent(c, -1);
}

static void do_lx_or_le_ext_header(deark *c, lctx *d, i64 pos)
{
	i64 x1, x2;

	de_dbg(c, "%s header at %"I64_FMT, d->fmt==EXE_FMT_LE?"LE":"LX", pos);
	x1 = (u8)de_getbyte(pos+2);
	x2 = (u8)de_getbyte(pos+3);
	de_dbg(c, "byte order, word order: %d, %d", (int)x1, (int)x2);
	if(x1!=0 || x2!=0) {
		de_err(c, "Unsupported byte order.");
		return;
	}

	if(d->fmt==EXE_FMT_LE) {
		x1 = de_getu32le(pos+0x2c);
		de_dbg(c, "bytes on last page: %d", (int)x1);
	}
	else {
		d->lx_page_offset_shift = de_getu32le(pos+0x2c);
		de_dbg(c, "page offset shift: %d", (int)d->lx_page_offset_shift);
	}

	x1 = de_getu32le(pos+0x40);
	d->lx_object_tbl_offset = pos + x1;
	d->lx_object_tbl_entries = de_getu32le(pos+0x44);
	de_dbg(c, "object table offset=%"I64_FMT", entries=%d", d->lx_object_tbl_offset,
		(int)d->lx_object_tbl_entries);

	x1 = de_getu32le(pos+0x48);
	d->lx_object_page_tbl_offset = pos + x1;
	de_dbg(c, "object page table offset=%"I64_FMT, d->lx_object_page_tbl_offset);

	x1 = de_getu32le(pos+0x50);
	d->lx_rsrc_tbl_offset = pos + x1;
	d->lx_rsrc_tbl_entries = de_getu32le(pos+0x54);
	de_dbg(c, "resource table offset=%"I64_FMT" entries=%d", d->lx_rsrc_tbl_offset,
		(int)d->lx_rsrc_tbl_entries);

	d->lx_data_pages_offset = de_getu32le(pos+0x80);
	de_dbg(c, "data pages offset=%"I64_FMT, d->lx_data_pages_offset);
}

static void identify_as_dos(deark *c, lctx *d)
{
	d->fmt = EXE_FMT_DOS;
	de_declare_fmt(c, "DOS EXE");
}

static void do_identify_exe_format(deark *c, lctx *d)
{
	u8 buf[4];

	if(d->ext_header_offset < 64 || d->ext_header_offset >= c->infile->len) {
		// Give up if ext_header_offset is obviously bad.
		identify_as_dos(c, d);
		goto done;
	}

	// TODO: Can we assume a real ext_header_offset is a multiple of 2? 4? 16?

	// If the ext hdr pointer overlaps another segment, assume DOS format.
	if(d->file_hdr_size<=60 && d->end_of_dos_code>60) {
		identify_as_dos(c, d);
		goto done;
	}
	if(d->reloc_tbl_offset>=61 && d->reloc_tbl_offset<=63) {
		identify_as_dos(c, d);
		goto done;
	}
	if(d->num_relocs>0 && d->reloc_tbl_offset<64 && d->reloc_tbl_endpos>60) {
		identify_as_dos(c, d);
		goto done;
	}

	de_read(buf, d->ext_header_offset, 4);
	if(!de_memcmp(buf, "PE\0\0", 4)) {
		d->fmt = EXE_FMT_PE;
		goto done;
	}

	if(!de_memcmp(buf, "NE", 2)) {
		// TODO: I've heard that d->ext_header_offset can be at most 64K for
		// (at least) NE format.
		d->fmt = EXE_FMT_NE;
		goto done;
	}

	if(!de_memcmp(buf, "LX", 2)) {
		d->fmt = EXE_FMT_LX;
		goto done;
	}

	if(!de_memcmp(buf, "LE", 2)) {
		d->fmt = EXE_FMT_LE;
		goto done;
	}

	if((buf[0]>='A' && buf[0]<='Z') &&
		((buf[1]>='0' && buf[1]<='9') || (buf[1]>='A' && buf[1]<='Z')))
	{
		// An unrecognized ext hdr signature that looks vaguely real...
		de_declare_fmt(c, "Unknown EXE format (maybe DOS)");
		goto done;
	}

	identify_as_dos(c, d);

done:
	;
}

static void do_ext_header(deark *c, lctx *d)
{
	switch(d->fmt) {
	case EXE_FMT_PE:
		do_Rich_segment(c, d);
		do_pe_coff_header(c, d, d->ext_header_offset);
		// If do_pe_coff_header didn't figure out the (sub)format...
		de_declare_fmt(c, "PE");
		break;
	case EXE_FMT_NE:
		de_declare_fmt(c, "NE");
		// TODO: Do "Rich" segments ever exist in files that are not PE files?
		do_ne_ext_header(c, d, d->ext_header_offset);
		break;
	case EXE_FMT_LX:
		de_declare_fmt(c, "LX Linear Executable");
		do_lx_or_le_ext_header(c, d, d->ext_header_offset);
		break;
	case EXE_FMT_LE:
		de_declare_fmt(c, "LE Linear Executable");
		do_lx_or_le_ext_header(c, d, d->ext_header_offset);
		break;
	}
}

static void do_reloc_table(deark *c, lctx *d)
{
	if(d->num_relocs<1) goto done;
	if(d->num_relocs > (i64)320*1024) goto done;
	if(d->reloc_tbl_offset<1) goto done;
	d->reloc_tbl_endpos = d->reloc_tbl_offset + d->num_relocs*4;
	if(d->reloc_tbl_endpos > d->file_hdr_size) goto done;
	if(d->reloc_tbl_endpos > c->infile->len) goto done;

	de_dbg(c, "reloc table at %"I64_FMT, d->reloc_tbl_offset);
	de_dbg_indent(c, 1);
	de_dbg(c, "%u entries, ends at %"I64_FMT, (UI)d->num_relocs, d->reloc_tbl_endpos);

	if(c->debug_level>=2) {
		i64 i;
		i64 pos = d->reloc_tbl_offset;
		i64 num_to_dbg = d->num_relocs;

		if(num_to_dbg > 5000) num_to_dbg = 5000;

		for(i=0; i<num_to_dbg; i++) {
			i64 offs, para;

			offs = de_getu16le_p(&pos);
			para = de_getu16le_p(&pos);
			de_dbg(c, "reloc[%u]: %04x:%04x (0x%05x)", (UI)i, (UI)para, (UI)offs,
				(UI)(para*16+offs));
		}
	}

	de_dbg_indent(c, -1);
done:
	;
}

static void do_checksum(deark *c, lctx *d)
{
	struct de_crcobj *crco = NULL;
	UI checksum_calc1;
	UI checksum_calc2;

	if(d->end_of_dos_code>c->infile->len) goto done;

	crco = de_crcobj_create(c, DE_CRCOBJ_SUM_U16LE);
	de_crcobj_addslice(crco, c->infile, 0, 18);
	de_crcobj_addslice(crco, c->infile, 20, d->end_of_dos_code-20);

	checksum_calc1 = de_crcobj_getval(crco);
	checksum_calc1 &= 0xffff;
	checksum_calc1 ^= 0xffff;

	// I don't know if the overlay is supposed to be included in the checksummed
	// bytes (best guess is no). But some EXE files do it one way, and some do
	// it the other way, and that's reason enough to calculate it both ways.

	de_crcobj_addslice(crco, c->infile, d->end_of_dos_code,
		c->infile->len - d->end_of_dos_code);
	checksum_calc2 = de_crcobj_getval(crco);
	checksum_calc2 &= 0xffff;
	checksum_calc2 ^= 0xffff;

	de_dbg(c, "checksum (calculated): 0x%04x", checksum_calc1);
	if(checksum_calc2 != checksum_calc1) {
		de_dbg(c, "checksum (calculated, including overlay): 0x%04x", checksum_calc2);
	}

done:
	de_crcobj_destroy(crco);
}

// Returns 0 only if this is not an EXE file.
static int do_mz_fileheader(deark *c, lctx *d)
{
	i64 n;
	i64 lfb_1, lfb;
	i64 nblocks_1, nblocks;
	i64 pos1 = 0;
	i64 pos = pos1;
	i64 regCS, regIP;
	int retval = 0;
	int saved_indent_level;
	struct de_fourcc sig;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "DOS file header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos, &sig, 2, 0x0);
	de_dbg(c, "signature: '%s'", sig.id_dbgstr);
	if(sig.id!=0x4d5aU && sig.id!=0x5a4dU) {
		de_err(c, "Not an EXE file");
		goto done;
	}
	pos += 2;
	retval = 1;

	lfb_1 = de_getu16le_p(&pos);
	lfb = lfb_1 & 511;
	if(lfb_1>=512) {
		de_warn(c, "Bad 'length of final block' field (0x%x, truncating to 0x%x)",
			(UI)lfb_1, (UI)lfb);
	}
	de_dbg(c, "length of final block: %u%s", (UI)lfb, ((lfb==0)?" (=512)":""));

	nblocks_1 = de_getu16le_p(&pos);
	nblocks = nblocks_1;
	if(nblocks_1 > 0x7ff) {
		// In case of overflow, do what DOSBox does
		// (src/dos/dos_execute.cpp, head.pages&=0x07ff).
		nblocks = nblocks_1 & 0x7ff;
		de_warn(c, "Bad 'number of blocks' field (0x%x, truncating to 0x%x)",
			(UI)nblocks_1, (UI)nblocks);
	}
	de_dbg(c, "num blocks: %u", (UI)nblocks);

	d->end_of_dos_code = nblocks*512;
	if(lfb) {
		d->end_of_dos_code = d->end_of_dos_code - 512 + lfb;
	}
	if(d->end_of_dos_code > c->infile->len) {
		de_warn(c, "Reported file size (%"I64_FMT") is larger than actual "
			"size (%"I64_FMT")", d->end_of_dos_code, c->infile->len);
	}

	d->num_relocs = de_getu16le_p(&pos);
	de_dbg(c, "num reloc table entries: %u", (UI)d->num_relocs);
	n = de_getu16le_p(&pos);
	d->file_hdr_size = n*16;
	de_dbg(c, "file hdr size: %u ("DE_CHAR_TIMES"16=%"I64_FMT")", (UI)n, d->file_hdr_size);

	n = de_getu16le_p(&pos);
	de_dbg(c, "min mem: %u ("DE_CHAR_TIMES"16=%"I64_FMT")", (UI)n, (i64)n*16);
	n = de_getu16le_p(&pos);
	de_dbg(c, "max mem: %u ("DE_CHAR_TIMES"16=%"I64_FMT")", (UI)n, (i64)n*16);

	n = de_geti16le_p(&pos);
	de_dbg(c, "regSS: %d", (int)n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "regSP: %u", (UI)n);

	d->checksum_reported = (UI)de_getu16le_p(&pos);
	de_dbg(c, "checksum (reported): 0x%04x", d->checksum_reported);
	if(d->check_checksum) {
		do_checksum(c, d);
	}

	regIP = de_getu16le_p(&pos);
	de_dbg(c, "regIP: %u", (UI)regIP);
	regCS = de_geti16le_p(&pos);
	de_dbg(c, "regCS: %d ("DE_CHAR_TIMES"16=%d)", (int)regCS, (int)(16*regCS));

	d->reloc_tbl_offset = de_getu16le_p(&pos);
	de_dbg(c, "reloc table offset: %"I64_FMT"%s", d->reloc_tbl_offset,
		(d->num_relocs==0)?" (no entries)":"");

	n = de_getu16le_p(&pos);
	de_dbg(c, "overlay indicator: %u", (UI)n);

	de_dbg(c, "DOS executable code: start=%"I64_FMT", len=%"I64_FMT", end=%"I64_FMT"",
		d->file_hdr_size, d->end_of_dos_code-d->file_hdr_size, d->end_of_dos_code);
	de_dbg(c, "DOS entry point: %"I64_FMT, d->file_hdr_size + 16*regCS + regIP);
	if(d->end_of_dos_code < c->infile->len) {
		de_dbg(c, "bytes after DOS executable code: %"I64_FMT, c->infile->len - d->end_of_dos_code);
	}

	de_dbg_indent(c, -1);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Returns 0 only if this is not an EXE file.
// This function is not expected to extract any files. In execomp mode, it
// definitely should not extract anything.
static int do_all_headers(deark *c, lctx *d)
{
	int retval;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	retval = do_mz_fileheader(c, d);
	if(!retval) goto done;

	do_reloc_table(c, d);

	d->ext_header_offset = de_getu32le(60);
	do_identify_exe_format(c, d);

	if(d->fmt!=EXE_FMT_DOS) {
		de_dbg(c, "extended header offset: %"I64_FMT, d->ext_header_offset);
		do_ext_header(c, d);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_decode_ddb(deark *c, lctx *d, i64 pos1, i64 len, de_finfo *fi)
{
	de_module_params *mparams = NULL;

	de_dbg(c, "BITMAP16 at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.fi = fi;
	de_run_module_by_id_on_slice(c, "ddb", mparams, c->infile, pos1, len);
	de_dbg_indent(c, -1);
	de_free(c, mparams);
}

// Extract a raw DIB, and write it to a file as a BMP.
static void do_extract_BITMAP(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	if(len<12) return;

	if((d->fmt==EXE_FMT_NE) && (de_getbyte(pos)==0x02)) {
		do_decode_ddb(c, d, pos, len, fi);
		return;
	}

	de_dbg(c, "BITMAP at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "dib", "X", c->infile, pos, len);
	de_dbg_indent(c, -1);
}

static void do_extract_ico_cur(deark *c, lctx *d, i64 pos, i64 len,
	int is_cur, i64 hotspot_x, i64 hotspot_y, de_finfo *fi)
{
	dbuf *f;
	i64 w, h;
	i64 ncolors;
	struct de_bmpinfo bi;

	// I guess we have to manufacture an ICO/CUR header?
	// There's usually a GROUP_ICON resource that seems to contain (most of) an
	// ICO header, but I don't know exactly how it's connected to the icon image(s).

	if(!fmtutil_get_bmpinfo(c, c->infile, &bi, pos, len, DE_BMPINFO_ICO_FORMAT)) {
		de_err(c, "Invalid bitmap");
		return;
	}

	if(bi.file_format==DE_BMPINFO_FMT_PNG) {
		dbuf_create_file_from_slice(c->infile, pos, len, "png", fi, 0);
		return;
	}

	f = dbuf_create_output_file(c, is_cur?"cur":"ico", fi, 0);

	// Write the 6-byte file header.
	dbuf_writeu16le(f, 0); // Reserved
	dbuf_writeu16le(f, is_cur?2:1); // Resource ID
	dbuf_writeu16le(f, 1); // Number of icons/cursors

	w = bi.width;
	if(w>255) w=0;
	h = bi.height;
	if(h>255) h=0;
	ncolors = bi.num_colors;
	if(ncolors>255) ncolors = 0;

	if(bi.total_size < len) {
		// Strip off useless padding at the end of the image.
		len = bi.total_size;
	}

	// Write the 16-byte index entry for the one icon/cursor.
	dbuf_writebyte(f, (u8)w);
	dbuf_writebyte(f, (u8)h);
	dbuf_writebyte(f, (u8)ncolors);
	if(is_cur) {
		dbuf_writebyte(f, 0);
		dbuf_writeu16le(f, hotspot_x);
		dbuf_writeu16le(f, hotspot_y);
	}
	else {
		dbuf_write_zeroes(f, 5);
	}
	dbuf_writeu32le(f, len); // Icon/cursor size
	dbuf_writeu32le(f, (i64)6+16); // Icon/cursor file offset

	// Write the non-manufactured part of the file.
	dbuf_copy(c->infile, pos, len, f);
	dbuf_close(f);
}

static void do_extract_CURSOR(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	UI firstword;
	i64 hotspot_x, hotspot_y;

	if(len<8) return;
	firstword = (UI)de_getu16le(pos);

	// For Win3 icons, the first word is the x hotspot.
	// For Win1 icons, it is one of the type codes below.
	if(d->fmt==EXE_FMT_NE && (firstword==0x0003 || firstword==0x0103 ||
		firstword==0x0203))
	{
		UI fourthword;
		// For Win3 icons, the 4th word is the high word of the
		// bitmap-info-header-size (definitely 0).
		// For Win1 icons, it is the width (definitely not 0).
		fourthword = (UI)de_getu16le(pos+6);
		if(fourthword!=0) {
			dbuf_create_file_from_slice(c->infile, pos, len, "win1.cur", fi, 0);
			return;
		}
	}

	hotspot_x = (i64)firstword;
	hotspot_y = de_getu16le(pos+2);
	de_dbg(c, "hotspot: %d,%d", (int)hotspot_x, (int)hotspot_y);
	do_extract_ico_cur(c, d, pos+4, len-4, 1, hotspot_x, hotspot_y, fi);
}

static void do_extract_ICON(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	if(d->fmt==EXE_FMT_NE && len>14) {
		UI firstword;

		firstword = (UI)de_getu16le(pos);
		// For Win3 icons, the first word is the low word of bitmap-info-header-size
		// (usually 40, definitely not one of the Win1 type codes).
		// For Win1 icons, it is one of the type codes below.
		if(firstword==0x0001 || firstword==0x0101 || firstword==0x0201) {
			dbuf_create_file_from_slice(c->infile, pos, len, "win1.ico", fi, 0);
			return;
		}
	}

	do_extract_ico_cur(c, d, pos, len, 0, 0, 0, fi);
}

// Try to get the face name and 'points' from a font resource. If successful,
// set the filename of the 'fi' object accordingly.
// This code is somewhat duplicated in fnt.c, but it's not worth consolidating.
static void get_font_facename(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	UI fnt_version;
	UI dfPoints;
	i64 dfFace;
	de_ucstring *s = NULL;

	if(!fi) goto done;
	if(len<109) goto done;
	fnt_version = (UI)de_getu16le(pos);
	if(fnt_version < 0x0200) goto done;
	dfPoints = (UI)de_getu16le(pos+68);
	dfFace = de_getu32le(pos+105);
	if(dfFace>=len) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos+dfFace, 64, len-dfFace, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	if(s->len<1) goto done;
	ucstring_printf(s, DE_ENCODING_LATIN1, "-%u", dfPoints);
	de_finfo_set_name_from_ucstring(c, fi, s, 0);

done:
	ucstring_destroy(s);
}

static void do_extract_FONT(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	i64 fntlen;

	if(len<6) return;
	// The "file size" is stored at offset 2. Respect it if possible.
	fntlen = de_getu32le(pos+2);
	if(fntlen<6 || fntlen>len) {
		fntlen = len;
	}

	get_font_facename(c, d, pos, fntlen, fi);

	dbuf_create_file_from_slice(c->infile, pos, fntlen, "fnt", fi, 0);
}

static void do_extract_MANIFEST(deark *c, lctx *d, i64 pos, i64 len, de_finfo *fi)
{
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, pos, len, "manifest", fi, DE_CREATEFLAG_IS_AUX);
	}
}

static const struct rsrc_type_info_struct rsrc_type_info_arr[] = {
	{ DE_RT_CURSOR,       0, "RT_CURSOR",       do_extract_CURSOR },
	{ DE_RT_BITMAP,       0, "RT_BITMAP",       do_extract_BITMAP },
	{ DE_RT_ICON,         0, "RT_ICON",         do_extract_ICON },
	{ 4,                  0, "RT_MENU",         NULL },
	{ 5,                  0, "RT_DIALOG",       NULL },
	{ 6,                  0, "RT_STRING",       NULL },
	{ DE_RT_FONTDIR,      0, "RT_FONTDIR",      NULL },
	{ DE_RT_FONT,         0, "RT_FONT",         do_extract_FONT },
	{ 9,                  0, "RT_ACCELERATOR",  NULL },
	{ 10,                 0, "RT_RCDATA",       NULL },
	{ 11,                 0, "RT_MESSAGETABLE", NULL },
	{ DE_RT_GROUP_CURSOR, 0, "RT_GROUP_CURSOR", NULL },
	{ DE_RT_GROUP_ICON,   0, "RT_GROUP_ICON",   NULL },
	{ 16,                 0, "RT_VERSION",      NULL },
	{ DE_RT_ANICURSOR,    0, "RT_ANICURSOR",    NULL },
	{ DE_RT_ANIICON,      0, "RT_ANIICON",      NULL },
	{ DE_RT_MANIFEST,     0, "RT_MANIFEST",     do_extract_MANIFEST }
};

static const struct rsrc_type_info_struct *get_rsrc_type_info(u32 id)
{
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(rsrc_type_info_arr); i++) {
		if(id == rsrc_type_info_arr[i].id) {
			return &rsrc_type_info_arr[i];
		}
	}
	return NULL;
}

static int ne_pe_resource_type_is_supported(deark *c, lctx *d, u32 type_id)
{
	switch(type_id) {
	case DE_RT_CURSOR:
	case DE_RT_BITMAP:
	case DE_RT_ICON:
	case DE_RT_FONT:
	case DE_RT_MANIFEST:
		return 1;
	}
	return 0;
}

static void do_ne_pe_extract_resource(deark *c, lctx *d,
	u32 type_id, const struct rsrc_type_info_struct *rsrci,
	i64 pos, i64 len, de_finfo *fi)
{
	if(!d->extract_std_resources) return;
	if(len<1 || len>DE_MAX_SANE_OBJECT_SIZE) return;

	if(rsrci && rsrci->decoder_fn) {
		rsrci->decoder_fn(c, d, pos, len, fi);
		return;
	}
}

static void de_finfo_set_name_from_pe_string(deark *c, de_finfo *fi, dbuf *f,
	i64 pos)
{
	i64 nlen; // in UTF-16 code units (2 bytes each)
	de_ucstring *fname = NULL;

	if(!c->filenames_from_file) goto done;

	// The string length is stored in a two-byte prefix.
	nlen = de_getu16le(pos);
	if(nlen<1) goto done;

	fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+2, nlen*2, fname, 0, DE_ENCODING_UTF16LE);
	de_finfo_set_name_from_ucstring(c, fi, fname, 0);

done:
	ucstring_destroy(fname);
}

static void do_pe_resource_data_entry(deark *c, lctx *d, i64 rel_pos)
{
	i64 data_size;
	i64 data_virt_addr;
	i64 data_real_offset;
	u32 type_id;
	de_finfo *fi = NULL;
	const char *rsrcname;

	type_id = d->cur_rsrc_type;
	if(d->cur_rsrc_type_info && d->cur_rsrc_type_info->name)
		rsrcname = d->cur_rsrc_type_info->name;
	else
		rsrcname = "?";

	de_dbg(c, "resource data entry at %"I64_FMT"(%"I64_FMT") rsrc_type=%d (%s)",
		(i64)(d->pe_cur_base_addr+rel_pos), rel_pos, (int)type_id, rsrcname);
	de_dbg_indent(c, 1);

	data_virt_addr = de_getu32le(d->pe_cur_base_addr+rel_pos);
	data_size = de_getu32le(d->pe_cur_base_addr+rel_pos+4);
	de_dbg(c, "resource data virt. addr=%"I64_FMT" (0x%08x), size=%"I64_FMT,
		data_virt_addr, (UI)data_virt_addr, data_size);

	data_real_offset = data_virt_addr - d->pe_cur_section_virt_addr + d->pe_cur_section_data_offset;
	de_dbg(c, "data offset in file: %"I64_FMT, data_real_offset);

	fi = de_finfo_create(c);

	if(d->pe_cur_name_offset) {
		de_finfo_set_name_from_pe_string(c, fi, c->infile, d->pe_cur_name_offset);
	}

	do_ne_pe_extract_resource(c, d, type_id, d->cur_rsrc_type_info, data_real_offset, data_size, fi);

	de_finfo_destroy(c, fi);
	de_dbg_indent(c, -1);
}

static void do_pe_resource_dir_table(deark *c, lctx *d, i64 rel_pos, int level);

static void do_pe_resource_node(deark *c, lctx *d, i64 rel_pos, int level)
{
	u32 name_or_id;
	i64 next_offset;
	int has_name, is_branch_node;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d->rsrc_item_count++;
	if(d->rsrc_item_count>MAX_RESOURCES) {
		de_err(c, "Too many resources");
		d->rsrc_errflag = 1;
		goto done;
	}

	has_name = 0;
	is_branch_node = 0;

	name_or_id = (u32)de_getu32le(d->pe_cur_base_addr+rel_pos);
	if(name_or_id & 0x80000000U) {
		has_name = 1;
		name_or_id -= 0x80000000U;
	}
	next_offset = de_getu32le(d->pe_cur_base_addr+rel_pos+4);
	if(next_offset & 0x80000000U) {
		is_branch_node = 1;
		next_offset -= 0x80000000U;
	}

	if(level==1) {
		d->cur_rsrc_type = name_or_id;
		d->cur_rsrc_type_info = get_rsrc_type_info((u32)d->cur_rsrc_type);
	}

	de_dbg(c, "level %d node at %"I64_FMT"(%"I64_FMT") id=%d next-offset=%"I64_FMT" is-named=%d is-branch=%d",
		level, (i64)(d->pe_cur_base_addr+rel_pos), rel_pos,
		(int)name_or_id, next_offset, has_name, is_branch_node);
	if(d->pe_cur_base_addr+rel_pos > c->infile->len) {
		d->rsrc_errflag = 1;
		goto done;
	}
	de_dbg_indent(c, 1);

	if(!ne_pe_resource_type_is_supported(c, d, d->cur_rsrc_type)) {
		const char *rsrcname;
		if(d->cur_rsrc_type_info && d->cur_rsrc_type_info->name)
			rsrcname = d->cur_rsrc_type_info->name;
		else
			rsrcname = "?";

		// We don't support this type of resource, so don't go down this path.
		de_dbg(c, "resource type %d (%s) not supported", (int)d->cur_rsrc_type, rsrcname);
		goto done;
	}

	// If a resource has a name (at level 2), keep track of it so we can
	// use it in the filename.
	if(level==2) {
		if(has_name) {
			d->pe_cur_name_offset = d->pe_cur_section_data_offset + name_or_id;
			de_dbg(c, "resource name at %"I64_FMT, d->pe_cur_name_offset);
		}
		else {
			d->pe_cur_name_offset = 0;
		}
	}
	else if(level<2) {
		d->pe_cur_name_offset = 0;
	}

	// If high bit is 1, we need to go deeper.
	if(is_branch_node) {
		do_pe_resource_dir_table(c, d, next_offset, level+1);
	}
	else {
		do_pe_resource_data_entry(c, d, next_offset);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_pe_resource_dir_table(deark *c, lctx *d, i64 rel_pos, int level)
{
	i64 named_node_count;
	i64 unnamed_node_count;
	i64 node_count;
	i64 i;

	// 16-byte "Resource node header" a.k.a "Resource directory table"

	if(d->rsrc_errflag) goto done;

	if(level>3) {
		de_warn(c, "Resource tree too deep");
		goto done;
	}

	de_dbg(c, "resource directory table at %"I64_FMT"(%"I64_FMT"), level=%d",
		(i64)(d->pe_cur_base_addr+rel_pos), rel_pos, level);

	named_node_count = de_getu16le(d->pe_cur_base_addr+rel_pos+12);
	unnamed_node_count = de_getu16le(d->pe_cur_base_addr+rel_pos+14);
	de_dbg(c, "number of node entries: named=%u, unnamed=%u", (UI)named_node_count,
		(UI)unnamed_node_count);

	node_count = named_node_count + unnamed_node_count;

	// An array of 8-byte "Resource node entries" follows the Resource node header.
	for(i=0; i<node_count; i++) {
		if(d->rsrc_errflag) goto done;
		do_pe_resource_node(c, d, rel_pos+16+8*i, level);
	}

done:
	;
}

static void do_pe_resource_section(deark *c, lctx *d, i64 pos, i64 len)
{
	if(d->rsrc_errflag) return;
	d->pe_cur_base_addr = pos;
	d->rsrc_item_count = 0;
	do_pe_resource_dir_table(c, d, 0, 1);
}

static void do_pe_section_header(deark *c, lctx *d, i64 section_index, i64 pos)
{
	i64 section_data_size;
	struct de_stringreaderdata *srd = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "section[%d] header at %"I64_FMT, (int)section_index, pos);
	de_dbg_indent(c, 1);

	// Section name: "An 8-byte, null-padded UTF-8 encoded string"
	srd = dbuf_read_string(c->infile, pos, 8, 8, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_UTF8);
	de_dbg(c, "section name: \"%s\"", ucstring_getpsz(srd->str));

	d->pe_cur_section_virt_addr = de_getu32le(pos+12);
	section_data_size = de_getu32le(pos+16);
	d->pe_cur_section_data_offset = de_getu32le(pos+20);

	de_dbg(c, "section virt. addr=%"I64_FMT" (0x%08x)", d->pe_cur_section_virt_addr, (UI)d->pe_cur_section_virt_addr);
	de_dbg(c, "section data offset=%"I64_FMT", size=%"I64_FMT, d->pe_cur_section_data_offset, section_data_size);

	if(!de_strcmp(srd->sz, ".rsrc")) {
		do_pe_resource_section(c, d, d->pe_cur_section_data_offset, section_data_size);
	}

	de_destroy_stringreaderdata(c, srd);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_pe_section_table(deark *c, lctx *d)
{
	i64 pos;
	i64 i;

	pos = d->pe_sections_offset;
	de_dbg(c, "section table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	for(i=0; i<d->pe_number_of_sections; i++) {
#define PE_MAX_SECTIONS 100
		if(i>=PE_MAX_SECTIONS) goto done;
		if(d->rsrc_errflag) goto done;
		do_pe_section_header(c, d, i, pos + 40*i);
	}

done:
	de_dbg_indent(c, -1);
}

static void do_ne_one_nameinfo(deark *c, lctx *d, i64 npos)
{
	i64 rsrc_offset;
	i64 rsrc_size;
	i64 is_named;
	i64 rnID;
	i64 rnNameOffset;
	i64 x;
	u8 looks_like_ishield_sfx_ne = 0;
	de_finfo *fi = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	rsrc_offset = de_getu16le(npos);
	if(d->ne_rcalign_shift>0) rsrc_offset <<= d->ne_rcalign_shift;
	rsrc_size = de_getu16le(npos+2);
	if(d->ne_rcalign_shift>0) rsrc_size <<= d->ne_rcalign_shift;

	de_dbg(c, "NAMEINFO at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT, npos,
		rsrc_offset, rsrc_size);
	de_dbg_indent(c, 1);

	rnID = 0;
	rnNameOffset = 0;
	x = de_getu16le(npos+6);
	if(x&0x8000) {
		is_named = 0;
		rnID = x-0x8000;
	}
	else {
		is_named = 1;
		rnNameOffset = d->ne_rsrc_tbl_offset + x;
	}

	if(is_named) {
		de_dbg(c, "id name offset: %"I64_FMT, rnNameOffset);
	}
	else {
		de_dbg(c, "id number: %d", (int)rnID);
	}

	if(!d->ne_have_type) goto done;

	fi = de_finfo_create(c);

	if(is_named) {
		// Names are prefixed with a single-byte length.
		x = (i64)de_getbyte(rnNameOffset);
		if(x>0) {
			struct de_stringreaderdata *rname_srd = NULL;

			rname_srd = dbuf_read_string(c->infile, rnNameOffset+1, x, x, 0, DE_ENCODING_ASCII);
			de_dbg(c, "resource name: \"%s\"", ucstring_getpsz(rname_srd->str));
			if(c->filenames_from_file)
				de_finfo_set_name_from_ucstring(c, fi, rname_srd->str, 0);

			if(d->ne_rsrc_type_id==1024 && rsrc_size>=20 &&
				!de_strcmp(rname_srd->sz, "MYRESOURCE"))
			{
				looks_like_ishield_sfx_ne = 1;
			}

			de_destroy_stringreaderdata(c, rname_srd);
		}
	}

	if(looks_like_ishield_sfx_ne) {
		d->might_be_ishield_sfx_ne = 1;
		d->ishield_sfx_ne_rsrc_pos = rsrc_offset;
		d->ishield_sfx_ne_rsrc_len = rsrc_size;
	}

	if(rsrc_size>0) {
		const char *rsrcname;

		if(d->ne_rsrc_type_info && d->ne_rsrc_type_info->name)
			rsrcname = d->ne_rsrc_type_info->name;
		else
			rsrcname = "?";

		de_dbg(c, "resource at %"I64_FMT", len=%"I64_FMT", type_id=%u (%s)", rsrc_offset,
			rsrc_size, (UI)d->ne_rsrc_type_id, rsrcname);
		de_dbg_indent(c, 1);
		if(looks_like_ishield_sfx_ne) {
			de_dbg(c, "[InstallShield SFX data]");
		}
		do_ne_pe_extract_resource(c, d, d->ne_rsrc_type_id, d->ne_rsrc_type_info,
			rsrc_offset, rsrc_size, fi);
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_finfo_destroy(c, fi);
}

static void do_ne_segment_table(deark *c, lctx *d)
{
	int saved_indent_level;
	i64 i;
	i64 pos;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->ne_number_of_segments<1) goto done;
	if(d->ne_rcalign_shift>24) goto done;

	de_dbg(c, "segment table at %"I64_FMT, d->ne_segment_tbl_offset);
	de_dbg_indent(c, 1);

#define NE_MAX_SECTIONS 500
	pos = d->ne_segment_tbl_offset;
	for(i=0; i<d->ne_number_of_segments; i++) {
		i64 seg_offset;
		i64 seg_len;
		UI seg_flags;

		if(pos>=c->infile->len) goto done;
		if(i>=NE_MAX_SECTIONS) goto done;
		de_dbg(c, "segment #%d", (int)(i+1));
		de_dbg_indent(c, 1);
		seg_offset = de_getu16le(pos);
		seg_offset <<= d->ne_filealign_shift;
		de_dbg(c, "offset: %"I64_FMT, seg_offset);
		seg_len = de_getu16le(pos+2);
		if(seg_len==0) seg_len = 65536;
		de_dbg(c, "len: %"I64_FMT, seg_len);
		seg_flags = (UI)de_getu16le(pos+4);
		de_dbg(c, "flags: 0x%04x", seg_flags);
		de_dbg_indent(c, -1);
		pos += 8;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_ne_rsrc_tbl(deark *c, lctx *d)
{
	i64 pos;
	i64 npos;
	i64 x;
	i64 i;
	i64 j;
	i64 rsrc_count;
	i64 tot_resources = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = d->ne_rsrc_tbl_offset;

	de_dbg(c, "resource table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->ne_rcalign_shift = (UI)de_getu16le(pos);
	de_dbg(c, "rscAlignShift: %u", d->ne_rcalign_shift);
	pos += 2;
	if(d->ne_rcalign_shift>24) {
		de_dbg(c, "[Unknown resource format or bad rscAlignShift; "
			"can't decode this resource table]");
		goto done;
	}

	i = 0;
	while(1) {
		x = de_getu16le(pos);
		if(x==0) {
			// A "type_id" of 0 marks the end of the array
			de_dbg(c, "end of TYPEINFO array found at %"I64_FMT, pos);
			goto done;
		}
		de_dbg(c, "TYPEINFO #%d at %"I64_FMT, (int)i, pos);
		de_dbg_indent(c, 1);

		if(x & 0x8000) {
			d->ne_rsrc_type_id = (u32)(x-0x8000);
			d->ne_rsrc_type_info = get_rsrc_type_info(d->ne_rsrc_type_id);
			d->ne_have_type = 1;
		}
		else {
			// x represents a relative offset to a name in rscResourceNames.
			// TODO: Could the name ever be a standard type (e.g. "ICON"), that
			// we ought to support?
			d->ne_rsrc_type_id = 0;
			d->ne_rsrc_type_info = NULL;
			d->ne_have_type = 0;
			// name_offset = d->ne_rsrc_tbl_offset + x;
		}

		rsrc_count = de_getu16le(pos+2);
		if(d->ne_have_type)
			de_dbg(c, "resource type=%d, count=%d", (int)d->ne_rsrc_type_id, (int)rsrc_count);
		else
			de_dbg(c, "resource type=?, count=%d", (int)rsrc_count);

		tot_resources += rsrc_count;

		if(tot_resources>MAX_RESOURCES) {
			de_err(c, "Too many resources, or invalid resource table.");
			goto done;
		}

		// Read the array of NAMEINFO structures.
		// (NAMEINFO seems like a misnomer to me. It contains data, not names.)
		for(j=0; j<rsrc_count; j++) {
			npos = pos+8 + j*12;
			do_ne_one_nameinfo(c, d, npos);
		}

		de_dbg_indent(c, -1);
		pos += 8 + 12*rsrc_count;
		i++;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Sniff the resource data, and return a suitable filename extension.
// Or NULL, if unidentified.
static const char *identify_lx_rsrc(deark *c, lctx *d, i64 pos, i64 len)
{
	u8 buf[2];
	int is_ba = 0;

	if(len<16) return NULL;
	de_read(buf, pos, 2);
	if(!de_memcmp(buf, "BA", 2)) {
		// Bitmap Array container format. Read the real type.
		de_read(buf, pos+14, 2);
		is_ba = 1;
	}

	if(!de_memcmp(buf, "BM", 2)) {
		return is_ba ? "ba.bmp" : "bmp";
	}
	if(!de_memcmp(buf, "CI", 2) || !de_memcmp(buf, "IC", 2)) {
		return is_ba ? "ba.os2.ico" : "os2.ico";
	}
	if(!de_memcmp(buf, "CP", 2) || !de_memcmp(buf, "PT", 2)) {
		return is_ba ? "ba.ptr" : "ptr";
	}
	return NULL;
}

// Extract a resource from an LX file, given the information from an Object Table
// entry.
static void do_lx_rsrc(deark *c, lctx *d,
	i64 obj_num, i64 rsrc_offset, i64 rsrc_size, i64 rsrc_type)
{
	i64 lpos;
	i64 vsize;
	i64 reloc_base_addr;
	i64 flags;
	i64 page_table_index;
	i64 page_table_entries;
	i64 rsrc_offset_real;
	i64 pg_data_offset_raw;
	const char *ext;
	//i64 data_size;

	if(obj_num<1 || obj_num>d->lx_object_tbl_entries) {
		de_err(c, "Invalid object number (%d).", (int)obj_num);
		return;
	}

	// Read the Object Table
	lpos = d->lx_object_tbl_offset + 24*(obj_num-1);
	de_dbg(c, "LX object table entry at %"I64_FMT, lpos);

	vsize = de_getu32le(lpos);
	reloc_base_addr = de_getu32le(lpos+4);
	flags = de_getu32le(lpos+8);
	page_table_index = de_getu32le(lpos+12);
	page_table_entries = de_getu32le(lpos+16);
	de_dbg(c, "object #%d: vsize=%"I64_FMT" raddr=%"I64_FMT" flags=0x%x pti=%d pte=%d",
		(int)obj_num,
		vsize, reloc_base_addr, (UI)flags, (int)page_table_index,
		(int)page_table_entries);

	if(page_table_index<1) return;

	// Now read the Object Page table
	lpos = d->lx_object_page_tbl_offset + 8*(page_table_index-1);
	de_dbg(c, "LX page table entry at %"I64_FMT, lpos);

	pg_data_offset_raw = de_getu32le(lpos);
	//data_size = de_getu16le(lpos+4);

	rsrc_offset_real = pg_data_offset_raw;
	if(d->lx_page_offset_shift > 0 ) {
		rsrc_offset_real <<= (UI)d->lx_page_offset_shift;
	}
	rsrc_offset_real += d->lx_data_pages_offset;
	rsrc_offset_real += rsrc_offset;
	de_dbg(c, "resource offset: %"I64_FMT, rsrc_offset_real);

	switch(rsrc_type) {
		// TODO: Support other types of resources.
	case 1: // Icon or cursor (?)
	case 2: // Bitmap (?)
		ext = identify_lx_rsrc(c, d, rsrc_offset_real, rsrc_size);
		if(!ext) break;
		// TODO: This assumes the resource is stored contiguously in the file, but
		// for all I know that isn't always the case.

		// Unlike in NE and PE format, it seems that image resources in LX files
		// include the BITMAPFILEHEADER. That makes it easy.
		if(d->extract_std_resources) {
			dbuf_create_file_from_slice(c->infile, rsrc_offset_real, rsrc_size,
				ext, NULL, 0);
		}
		break;
	}
}

static void do_lx_or_le_rsrc_tbl(deark *c, lctx *d)
{
	i64 i;
	i64 lpos;
	i64 type_id;
	i64 name_id;
	i64 rsrc_size;
	i64 rsrc_object;
	i64 rsrc_offset;

	de_dbg(c, "%s resource table at %"I64_FMT, d->fmt==EXE_FMT_LE?"LE":"LX", d->lx_rsrc_tbl_offset);
	if(d->lx_rsrc_tbl_entries>MAX_RESOURCES) {
		de_err(c, "Too many resources.");
		return;
	}

	for(i=0; i<d->lx_rsrc_tbl_entries; i++) {
		lpos = d->lx_rsrc_tbl_offset + 14*i;

		type_id = de_getu16le(lpos);
		name_id = de_getu16le(lpos+2);
		rsrc_size = de_getu32le(lpos+4);
		rsrc_object = de_getu16le(lpos+8);
		rsrc_offset = de_getu32le(lpos+10);

		de_dbg(c, "resource #%d: type=%d name=%d size=%"I64_FMT" obj=%d offset=%"I64_FMT, (int)i,
			(int)type_id, (int)name_id, rsrc_size, (int)rsrc_object, rsrc_offset);

		de_dbg_indent(c, 1);
		do_lx_rsrc(c, d, rsrc_object, rsrc_offset, rsrc_size, type_id);
		de_dbg_indent(c, -1);
	}
}

static void extract_zip_from_sfx(deark *c, lctx *d,
	struct fmtutil_specialexe_detection_data *edd)
{
	de_module_params *mparams = NULL;

	if(!d->ei) return;
	de_dbg(c, "attempting zip extraction");
	de_dbg_indent(c, 1);

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "R";
	mparams->in_params.obj1 = (void*)edd;

	de_run_module_by_id_on_slice(c, "zip", mparams, d->ei->f, 0, d->ei->f->len);

	if(!(mparams->out_params.flags & 0x1)) {
		de_warn(c, "This look like a self-extracting ZIP file, but an attempt to "
			"extract the plain ZIP file failed.");
	}
	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void extract_arj_from_sfx(deark *c, lctx *d,
	struct fmtutil_specialexe_detection_data *edd)
{
	de_module_params *mparams = NULL;

	if(!d->ei) return;
	de_dbg(c, "attempting ARJ extraction, pos=%"I64_FMT, edd->payload_pos);
	de_dbg_indent(c, 1);

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "R";
	if(edd->payload_valid) {
		mparams->in_params.obj1 = (void*)edd;
	}

	de_run_module_by_id_on_slice(c, "arj", mparams, d->ei->f, 0, d->ei->f->len);

	if(!(mparams->out_params.flags & 0x1)) {
		de_warn(c, "This look like a self-extracting ARJ file, but an attempt to "
			"extract the plain ARJ file failed.");
	}
	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void extract_pak16_from_sfx(deark *c, lctx *d,
	struct fmtutil_specialexe_detection_data *edd)
{
	de_module_params *mparams = NULL;

	if(!d->ei) return;
	de_dbg(c, "attempting PAKv1.6 extraction, pos=%"I64_FMT, edd->payload_pos);
	de_dbg_indent(c, 1);

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "6";

	de_run_module_by_id_on_slice(c, "arc", mparams, d->ei->f,
		d->ei->end_of_dos_code, d->ei->overlay_len);

	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void extract_ishieldsfx_ne(deark *c, lctx *d,
	struct fmtutil_specialexe_detection_data *edd)
{
	de_module_params *mparams = NULL;

	de_dbg(c, "[extracting InstallShield SFX NE]");

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.uint1 = (UI)d->ishield_sfx_ne_rsrc_pos;
	mparams->in_params.uint2 = (UI)d->ishield_sfx_ne_rsrc_len;

	de_dbg_indent(c, 1);
	de_run_module_by_id(c, "is_sfx", mparams);
	de_dbg_indent(c, -1);

	de_free(c, mparams);
}

static void do_exesfx(deark *c, lctx *d)
{
	u8 suggest_opt_sfx = 0;
	struct fmtutil_specialexe_detection_data edd;

	if(!d->ei) return;
	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.flags_in |= 0x1;
	if(d->might_be_ishield_sfx_ne) {
		edd.detected_fmt = DE_SPECIALEXEFMT_ISHIELDNE;
		de_strlcpy(edd.detected_fmt_name, "InstallShield (NE)",
			sizeof(edd.detected_fmt_name));
	}
	else {
		fmtutil_detect_exesfx(c, d->ei, &edd);
	}

	if(edd.zip_eocd_found && !edd.detected_fmt) {
		// Probably a ZIP SFX, but maybe not, or maybe one we can't handle.
		// TODO?: Maybe we should just try to extract it anyway.
		de_info(c, "Note: This might be a self-extracting ZIP file "
			"(try \"-m zip -opt zip:reloc\").");
		goto done;
	}

	if(!edd.detected_fmt) goto done;

	de_dbg(c, "detected self-extracting exe: %s", edd.detected_fmt_name);
	if(edd.detected_fmt==DE_SPECIALEXEFMT_ZIPSFX) {
		// ZIP SFX generally needs special processing
		extract_zip_from_sfx(c, d, &edd);
	}
	else if(edd.detected_fmt==DE_SPECIALEXEFMT_ARJSFX) {
		// ARJ SFX generally needs special processing
		extract_arj_from_sfx(c, d, &edd);
	}
	else if(edd.detected_fmt==DE_SPECIALEXEFMT_PAK16SFX) {
		extract_pak16_from_sfx(c, d, &edd);
	}
	else if(edd.detected_fmt==DE_SPECIALEXEFMT_ISHIELDNE) {
		if(d->sfx_only_mode) {
			extract_ishieldsfx_ne(c, d, &edd);
		}
		else {
			suggest_opt_sfx = 1;
		}
	}
	else if(edd.payload_valid) {
		dbuf_create_file_from_slice(d->ei->f, edd.payload_pos, edd.payload_len,
			edd.payload_file_ext, NULL, 0);
	}
	else {
		de_info(c, "Note: This might be a self-extracting %s archive, but it's "
			"not a supported format or version.", edd.detected_fmt_name);
	}

	if(suggest_opt_sfx) {
		de_info(c, "Note: This looks like a self-extracting %s archive. Use "
			"\"-opt exe:sfx\" to attempt extraction.", edd.detected_fmt_name);
	}

done:
	;
}

static void do_specialexe(deark *c, lctx *d)
{
	struct fmtutil_specialexe_detection_data edd;

	if(!d->ei) return;
	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.flags_in |= 0x1;
	fmtutil_detect_specialexe(c, d->ei, &edd);
	if(!edd.detected_fmt) goto done;

	de_dbg(c, "detected special exe: %s", edd.detected_fmt_name);

	if(edd.modname) {
		de_dbg(c, "attempting to decode %s", edd.modname);
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice2(c, edd.modname, NULL, c->infile, 0, c->infile->len);
		de_dbg_indent(c, -1);
	}

done:
	;
}

// Used in execomp mode.
static void try_execomp_decompress(deark *c, lctx *d, struct fmtutil_specialexe_detection_data *edd)
{
	if(edd->detected_fmt==0) return;
	if(!edd->modname) {
		de_info(c, "Note: File seems to be compressed with %s, but that's "
			"not a supported format.", edd->detected_fmt_name);
		return;
	}

	de_dbg(c, "attempting %s decompression", edd->modname);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, edd->modname, NULL, c->infile, 0, c->infile->len);
	de_dbg_indent(c, -1);
}

// Based on d->execomp_mode, either just check for executable compression,
// or try to decompress.
static void do_execomp(deark *c, lctx *d)
{
	struct fmtutil_specialexe_detection_data edd;

	if(d->execomp_mode!=1) {
		if(d->sfx_only_mode) return;
		if((!c->show_infomessages) && (c->debug_level<1)) return;
	}

	if(!d->ei) {
		d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
		fmtutil_collect_exe_info(c, c->infile, d->ei);
	}

	de_zeromem(&edd, sizeof(struct fmtutil_specialexe_detection_data));
	edd.flags_in |= 0x1;
	fmtutil_detect_execomp(c, d->ei, &edd);
	if(!edd.detected_fmt) return;
	de_dbg(c, "detected executable compression: %s", edd.detected_fmt_name);

	if(d->execomp_mode==1) {
		try_execomp_decompress(c, d, &edd);
	}
	else if(d->execomp_mode!=0) {
		if(edd.modname) {
			de_info(c, "Note: File seems to be compressed with %s. Use \"-m %s\" "
				"or \"-opt execomp\" to attempt decompression.",
				edd.detected_fmt_name, edd.modname);
		}
	}
}

static void de_run_exe(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(c->debug_level!=0) {
		d->check_checksum = (u8)de_get_ext_option_bool(c, "exe:checksum", 0xff);
		if(d->check_checksum==0xff) {
			d->check_checksum = (c->debug_level>=2);
		}
	}
	d->extract_std_resources = 1;
	d->execomp_mode = (u8)de_get_ext_option_bool(c, "execomp", 0xff);
	d->sfx_only_mode = (u8)de_get_ext_option_bool(c, "exe:sfx", 0);
	if(d->sfx_only_mode) {
		d->extract_std_resources = 0;
	}

	if(!do_all_headers(c, d)) goto done;

	if(d->execomp_mode==1) {
		do_execomp(c, d);
		goto done;
	}

	if(d->subfmt==EXE_SUBFMT_PE32 || d->subfmt==EXE_SUBFMT_PE32PLUS) {
		if(d->pe_sections_offset>0) {
			do_pe_section_table(c, d);
		}
	}
	else if(d->fmt==EXE_FMT_NE) {
		do_ne_segment_table(c, d);
		if(d->ne_rsrc_tbl_offset>0) {
			do_ne_rsrc_tbl(c, d);
		}
	}
	else if(d->fmt==EXE_FMT_LX || d->fmt==EXE_FMT_LE) {
		if(d->lx_rsrc_tbl_offset>0) {
			do_lx_or_le_rsrc_tbl(c, d);
		}
	}

	if(!d->ei) {
		d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
		fmtutil_collect_exe_info(c, c->infile, d->ei);
	}
	do_exesfx(c, d);
	do_specialexe(c, d);
	do_execomp(c, d);

done:
	if(d) {
		de_free(c, d->ei);
		de_free(c, d);
	}
}

// Note - This needs to be coordinated with de_identify_zip, so that self-extracting
// ZIP files are identified as exe and not zip (assuming all modules are enabled).
static int de_identify_exe(deark *c)
{
	UI sig;
	UI lfb;
	int exe_ext;
	u8 sigMZ;

	sig = (UI)de_getu16be(0);
	if(sig==0x4d5aU) { sigMZ = 1; }
	else if(sig==0x5a4d) { sigMZ = 0; }
	else { return 0; }
	lfb = (UI)de_getu16le(2); // lenFinal

	exe_ext = de_input_file_has_ext(c, "exe");
	if(lfb>511) {
		return exe_ext ? 15 : 0;
	}
	if(exe_ext) return 80;
	return sigMZ ? 80 : 50;
}

static void de_help_exe(deark *c)
{
	de_msg(c, "-opt exe:checksum : Calculate the correct checksum");
	de_msg(c, "-opt exe:sfx : Hint: Decode self-extracting archive");
	de_msg(c, "-opt execomp : Try to decompress compressed files");
}

void de_module_exe(deark *c, struct deark_module_info *mi)
{
	mi->id = "exe";
	mi->desc = "EXE executable (PE, NE, etc.)";
	mi->run_fn = de_run_exe;
	mi->identify_fn = de_identify_exe;
	mi->help_fn = de_help_exe;
}
