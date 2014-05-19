// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Microsoft EXE executable formats.

#include <deark-config.h>
#include <deark-modules.h>
#include "bmputil.h"

#define EXE_FMT_DOS    1
#define EXE_FMT_NE     2
#define EXE_FMT_PE32   3
#define EXE_FMT_PE32PLUS 4
#define EXE_FMT_LX     5
#define EXE_FMT_LE     6

#define MAX_RESOURCES 10000

#define DE_RT_CURSOR        1
#define DE_RT_BITMAP        2
#define DE_RT_ICON          3
#define DE_RT_GROUP_CURSOR  12
#define DE_RT_GROUP_ICON    14
#define DE_RT_ANICURSOR     21
#define DE_RT_ANIICON       22
#define DE_RT_MANIFEST      24

typedef struct localctx_struct {
	int fmt;
	de_int64 ext_header_offset;

	de_int64 ne_rsrc_tbl_offset;

	de_int64 lx_page_offset_shift;
	de_int64 lx_object_tbl_offset;
	de_int64 lx_object_tbl_entries;
	de_int64 lx_object_page_tbl_offset;
	de_int64 lx_rsrc_tbl_offset;
	de_int64 lx_rsrc_tbl_entries;
	de_int64 lx_data_pages_offset;

	de_int64 pe_sections_offset;
	de_int64 pe_number_of_sections;

	// File offset where the resources start. Some addresses are relative
	// to this.
	de_int64 pe_cur_base_addr;

	de_int64 pe_cur_section_virt_addr;
	de_int64 pe_cur_section_data_offset;

	de_int64 cur_rsrc_type;
	de_int64 rsrc_item_count;
} lctx;

static void do_opt_coff_data_dirs(deark *c, lctx *d, de_int64 pos)
{
	de_int64 rsrc_tbl_rva;
	de_int64 rsrc_tbl_size;

	de_dbg(c, "COFF/PE optional header (data directories) at %d\n", (int)pos);
	rsrc_tbl_rva = de_getui32le(pos+16);
	// I don't know if rsrc_tbl_rva will be needed for anything. It seems redundant.
	rsrc_tbl_size = de_getui32le(pos+20);
	de_dbg(c, "resource table RVA=0x%08x, size=%d\n", (unsigned int)rsrc_tbl_rva,
		(int)rsrc_tbl_size);
}

static const char *get_subsys_desc(de_int64 subsystem)
{
	switch(subsystem) {
	case 2: return " (Windows GUI)";
	case 3: return " (console)";
	}
	return "";
}

static void do_opt_coff_nt_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x;
	de_int64 subsystem;

	de_dbg(c, "COFF/PE optional header (Windows NT) at %d\n", (int)pos);
	x = de_getui32le(pos);
	de_dbg(c, "image base offset: 0x%08x\n", (unsigned int)x);

	subsystem = de_getui16le(pos+40);
	de_dbg(c, "subsystem: %d%s\n", (int)subsystem, get_subsys_desc(subsystem));
}

static void do_opt_coff_nt_header_64(deark *c, lctx *d, de_int64 pos)
{
	de_int64 base_offset;
	de_int64 subsystem;

	de_dbg(c, "COFF/PE32+ optional header (Windows NT) at %d\n", (int)pos);
	base_offset = de_geti64le(pos);
	de_dbg(c, "image base offset: 0x%016" INT64_FMTx "\n", base_offset);

	subsystem = de_getui16le(pos+44);
	de_dbg(c, "subsystem: %d%s\n", (int)subsystem, get_subsys_desc(subsystem));
}

static void do_opt_coff_header(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 sig;
	de_int64 coff_opt_hdr_size;

	de_dbg(c, "COFF/PE optional header at %d, size=%d\n", (int)pos, (int)len);

	sig = de_getui16le(pos);
	de_dbg(c, "signature: 0x%04x\n", (int)sig);

	if(sig==0x010b)
		coff_opt_hdr_size = 28;
	else
		coff_opt_hdr_size = 24;

	if(sig==0x010b) {
		d->fmt = EXE_FMT_PE32;
		de_declare_fmt(c, "PE32");
		do_opt_coff_nt_header(c, d, pos+coff_opt_hdr_size);
		do_opt_coff_data_dirs(c, d, pos+coff_opt_hdr_size+68);
	}
	else if(sig==0x020b) {
		d->fmt = EXE_FMT_PE32PLUS;
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
}

// 'pos' is the start of the 4-byte PE signature.
// Following it is a 20-byte COFF header.
static void do_pe_coff_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 arch;
	de_int64 opt_hdr_size;

	arch = de_getui16le(pos+4+0);
	de_dbg(c, "target architecture: 0x%04x\n", (int)arch);

	d->pe_number_of_sections = de_getui16le(pos+4+2);
	de_dbg(c, "number of sections: %d\n", (int)d->pe_number_of_sections);

	opt_hdr_size = de_getui16le(pos+4+16);
	de_dbg(c, "optional header size: %d\n", (int)opt_hdr_size);
	if(opt_hdr_size>0) {
		do_opt_coff_header(c, d, pos+4+20, opt_hdr_size);
		d->pe_sections_offset = pos+4+20+opt_hdr_size;
	}
}

static void do_ne_ext_header(deark *c, lctx *d, de_int64 pos)
{
	de_byte target_os;
	const char *desc;

	d->ne_rsrc_tbl_offset = de_getui16le(pos+36);
	d->ne_rsrc_tbl_offset += pos;
	de_dbg(c, "offset of resource table: %d\n", (int)d->ne_rsrc_tbl_offset);

	target_os = de_getbyte(pos+54);
	switch(target_os) {
	case 1: desc=" (OS/2)"; break;
	case 2: desc=" (Windows)"; break;
	case 3: desc=" (European MS-DOS 4.x)"; break;
	case 4: desc=" (Windows 386)"; break;
	case 5: desc=" (Borland Operating System Services)"; break;
	default: desc="";
	}
	de_dbg(c, "target OS: %d%s\n", (int)target_os, desc);
}

static void do_lx_ext_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x1, x2;

	de_dbg(c, "LX header at %d\n", (int)pos);
	x1 = de_getbyte(pos+2);
	x2 = de_getbyte(pos+2);
	de_dbg(c, "byte order, word order: %d, %d\n", (int)x1, (int)x2);
	if(x1!=0 || x2!=0) {
		de_err(c, "Unsupported byte order.\n");
		return;
	}

	d->lx_page_offset_shift = de_getui32le(pos+0x2c);
	de_dbg(c, "page offset shift: %d\n", (int)d->lx_page_offset_shift);

	x1 = de_getui32le(pos+0x40);
	d->lx_object_tbl_offset = pos + x1;
	d->lx_object_tbl_entries = de_getui32le(pos+0x44);
	de_dbg(c, "object table offset=%d, entries=%d\n", (int)d->lx_object_tbl_offset, (int)d->lx_object_tbl_entries);

	x1 = de_getui32le(pos+0x48);
	d->lx_object_page_tbl_offset = pos + x1;
	de_dbg(c, "object page table offset=%d\n", (int)d->lx_object_page_tbl_offset);

	x1 = de_getui32le(pos+0x50);
	d->lx_rsrc_tbl_offset = pos + x1;
	d->lx_rsrc_tbl_entries = de_getui32le(pos+0x54);
	de_dbg(c, "resource table offset=%d entries=%d\n", (int)d->lx_rsrc_tbl_offset, (int)d->lx_rsrc_tbl_entries);

	d->lx_data_pages_offset = de_getui32le(pos+0x80);
	de_dbg(c, "data pages offset=%d\n", (int)d->lx_data_pages_offset);
}

static void do_ext_header(deark *c, lctx *d)
{
	de_byte buf[4];

	if(d->ext_header_offset == 0 || d->ext_header_offset >= c->infile->len) {
		// Give up if ext_header_offset is obviously bad.
		goto done;
	}

	de_read(buf, d->ext_header_offset, 4);
	if(!de_memcmp(buf, "PE\0\0", 4)) {
		de_dbg(c, "PE header at %d\n", (int)d->ext_header_offset);
		do_pe_coff_header(c, d, d->ext_header_offset);
		// If do_pe_coff_header didn't figure out the format...
		de_declare_fmt(c, "PE");
	}
	else if(!de_memcmp(buf, "NE", 2)) {
		de_declare_fmt(c, "NE");
		d->fmt = EXE_FMT_NE;
		do_ne_ext_header(c, d, d->ext_header_offset);
	}
	else if(!de_memcmp(buf, "LX", 2)) {
		de_declare_fmt(c, "LX Linear Executable");
		d->fmt = EXE_FMT_LX;
		do_lx_ext_header(c, d, d->ext_header_offset);
	}
	else if(!de_memcmp(buf, "LE", 2)) {
		de_declare_fmt(c, "LE Linear Executable");
		d->fmt = EXE_FMT_LE;
		// TODO: Support LE format.
		de_err(c, "LE format not supported.\n");
	}

done:
	// If we still don't know the format...
	de_declare_fmt(c, "Unknown EXE format (maybe MS-DOS)");
}

static void do_fileheader(deark *c, lctx *d)
{
	de_int64 reloc_tbl_offset;

	reloc_tbl_offset = de_getui16le(24);
	de_dbg(c, "relocation table offset: %d\n", (int)reloc_tbl_offset);

	if(reloc_tbl_offset>=28 && reloc_tbl_offset<64) {
		de_declare_fmt(c, "MS-DOS EXE");
		d->fmt = EXE_FMT_DOS;
	}
	else {
		d->ext_header_offset = de_getui32le(60);
		de_dbg(c, "extended header offset: %d\n", (int)d->ext_header_offset);
		do_ext_header(c, d);
	}
}

// Extract a raw DIB, and write it to a file as a BMP.
static void de_DIB_to_BMP(deark *c, dbuf *inf, de_int64 pos, de_int64 len, dbuf *outf)
{
	struct de_bmpinfo bi;

	if(!de_bmputil_get_bmpinfo(c, c->infile, &bi, pos, len, 0)) {
		de_err(c, "Invalid bitmap\n");
		return;
	}

	// Manufacture a BITMAPFILEHEADER.
	dbuf_write(outf, (const de_byte*)"BM", 2);
	dbuf_writeui32le(outf, 14+bi.total_size); // File size
	dbuf_writezeroes(outf, 4);
	dbuf_writeui32le(outf, 14+bi.size_of_headers_and_pal); // "Bits offset"

	dbuf_copy(inf, pos, bi.total_size, outf); // Copy the rest of the data.
}

static void do_extract_BITMAP(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	dbuf *f;
	if(len<12) return;

	f = dbuf_create_output_file(c, "bmp");
	de_DIB_to_BMP(c, c->infile, pos, len, f);
	dbuf_close(f);
}

static void do_extract_ico_cur(deark *c, lctx *d, de_int64 pos, de_int64 len,
	int is_cur, de_int64 hotspot_x, de_int64 hotspot_y)
{
	dbuf *f;
	de_int64 w, h;
	de_int64 ncolors;
	struct de_bmpinfo bi;

	// I guess we have to manufacture an ICO/CUR header?
	// There's usually a GROUP_ICON resource that seems to contain (most of) an
	// ICO header, but I don't know exactly how it's connected to the icon image(s).

	if(!de_bmputil_get_bmpinfo(c, c->infile, &bi, pos, len, DE_BMPINFO_ICO_FORMAT)) {
		de_err(c, "Invalid bitmap\n");
		return;
	}

	if(bi.file_format==DE_BMPINFO_FMT_PNG) {
		dbuf_create_file_from_slice(c->infile, pos, len, "png");
		return;
	}

	f = dbuf_create_output_file(c, is_cur?"cur":"ico");

	// Write the 6-byte file header.
	dbuf_writeui16le(f, 0); // Reserved
	dbuf_writeui16le(f, is_cur?2:1); // Resource ID
	dbuf_writeui16le(f, 1); // Number of icons/cursors

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
	dbuf_writebyte(f, (de_byte)w);
	dbuf_writebyte(f, (de_byte)h);
	dbuf_writebyte(f, (de_byte)ncolors);
	if(is_cur) {
		dbuf_writebyte(f, 0);
		dbuf_writeui16le(f, hotspot_x);
		dbuf_writeui16le(f, hotspot_y);
	}
	else {
		dbuf_writezeroes(f, 5);
	}
	dbuf_writeui32le(f, len); // Icon/cursor size
	dbuf_writeui32le(f, 6+16); // Icon/cursor file offset

	// Write the non-manufactured part of the file.
	dbuf_copy(c->infile, pos, len, f);
	dbuf_close(f);
}

static void do_extract_CURSOR(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 hotspot_x, hotspot_y;

	if(len<4) return;
	hotspot_x = de_getui16le(pos);
	hotspot_y = de_getui16le(pos+2);
	do_extract_ico_cur(c, d, pos+4, len-4, 1, hotspot_x, hotspot_y);
}

static void do_extract_ICON(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	do_extract_ico_cur(c, d, pos, len, 0, 0, 0);
}

static void do_extract_MANIFEST(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(c->infile, pos, len, "manifest");
	}
}

static void do_ne_pe_extract_resource(deark *c, lctx *d, de_int64 type_id,
	de_int64 pos, de_int64 len)
{
	if(len<1 || len>DE_MAX_FILE_SIZE) return;

	switch(type_id) {
	case DE_RT_CURSOR:
		do_extract_CURSOR(c, d, pos, len);
		break;
	case DE_RT_BITMAP:
		do_extract_BITMAP(c, d, pos, len);
		break;
	case DE_RT_ICON:
		do_extract_ICON(c, d, pos, len);
		break;
	case DE_RT_MANIFEST:
		do_extract_MANIFEST(c, d, pos, len);
		break;
	}
}

static void do_pe_resource_data_entry(deark *c, lctx *d, de_int64 rel_pos)
{
	de_int64 data_size;
	de_int64 data_virt_addr;
	de_int64 data_real_offset;
	de_int64 type_id;

	type_id = d->cur_rsrc_type;

	de_dbg(c, " resource data entry at %d(%d) rsrc_type=%d\n",
		(int)(d->pe_cur_base_addr+rel_pos), (int)rel_pos, (int)type_id);

	data_virt_addr = de_getui32le(d->pe_cur_base_addr+rel_pos);
	data_size = de_getui32le(d->pe_cur_base_addr+rel_pos+4);
	de_dbg(c, " resource data virt. addr=%d (0x%08x), size=%d\n",
		(int)data_virt_addr, (unsigned int)data_virt_addr, (int)data_size);

	data_real_offset = data_virt_addr - d->pe_cur_section_virt_addr + d->pe_cur_section_data_offset;
	de_dbg(c, " data offset in file: %d\n",
		(int)data_real_offset);

	do_ne_pe_extract_resource(c, d, type_id, data_real_offset, data_size);
}

static void do_pe_resource_dir_table(deark *c, lctx *d, de_int64 rel_pos, int level);

static void do_pe_resource_node(deark *c, lctx *d, de_int64 rel_pos, int level)
{
	de_int64 name_or_id;
	de_int64 next_offset;
	int has_name, is_branch_node;

	d->rsrc_item_count++;
	if(d->rsrc_item_count>MAX_RESOURCES) {
		de_err(c, "Too many resources.\n");
		return;
	}

	has_name = 0;
	is_branch_node = 0;

	name_or_id = de_getui32le(d->pe_cur_base_addr+rel_pos);
	if(name_or_id & 0x80000000) {
		has_name = 1;
		name_or_id -= 0x80000000;
	}
	next_offset = de_getui32le(d->pe_cur_base_addr+rel_pos+4);
	if(next_offset & 0x80000000) {
		is_branch_node = 1;
		next_offset -= 0x80000000;
	}

	if(level==1) {
		d->cur_rsrc_type = name_or_id;
	}

	// TODO: If a resource has a name (at level 2), we should read it so we
	// can use it for the filename.

	de_dbg(c, "level %d node at %d(%d) id=%d next-offset=%d is-named=%d is-branch=%d\n",
		level, (int)(d->pe_cur_base_addr+rel_pos), (int)rel_pos,
		(int)name_or_id, (int)next_offset, has_name, is_branch_node);

	// If high bit is 1, we need to go deeper.
	if(is_branch_node) {
		do_pe_resource_dir_table(c, d, next_offset, level+1);
	}
	else {
		do_pe_resource_data_entry(c, d, next_offset);
	}
}

static void do_pe_resource_dir_table(deark *c, lctx *d, de_int64 rel_pos, int level)
{
	de_int64 named_node_count;
	de_int64 unnamed_node_count;
	de_int64 node_count;
	de_int64 i;

	// 16-byte "Resource node header" a.k.a "Resource directory table"

	if(level>3) {
		de_warn(c, "Resource tree too deep\n");
		return;
	}

	de_dbg(c, "resource directory table at %d(%d), level=%d\n",
		(unsigned int)(d->pe_cur_base_addr+rel_pos), (unsigned int)rel_pos, level);

	named_node_count = de_getui16le(d->pe_cur_base_addr+rel_pos+12);
	unnamed_node_count = de_getui16le(d->pe_cur_base_addr+rel_pos+14);
	de_dbg(c, "number of node entries: named=%d, unnamed=%d\n", (unsigned int)named_node_count,
		(unsigned int)unnamed_node_count);

	node_count = named_node_count + unnamed_node_count;
	
	// An array of 8-byte "Resource node entries" follows the Resource node header.
	for(i=0; i<node_count; i++) {
		do_pe_resource_node(c, d, rel_pos+16+8*i, level);
	}
}

static void do_pe_resource_section(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	d->pe_cur_base_addr = pos;
	d->rsrc_item_count = 0;
	do_pe_resource_dir_table(c, d, 0, 1);
}

static void do_pe_section_header(deark *c, lctx *d, de_int64 pos)
{
	de_byte name_raw[8];
	char name[9];
	de_int64 i;
	de_int64 section_data_size;

	de_dbg(c, "section header at %d\n", (unsigned int)pos);

	de_read(name_raw, pos, 8); // Section name

	if(c->debug_level>0) {
		for(i=0; i<8; i++) {
			if(name_raw[i]==0 || (name_raw[i]>=32 && name_raw[i]<=126))
				name[i] = (char)name_raw[i];
			else
				name[i] = '_';
		}
		name[8] = '\0';
		de_dbg(c, "section name: \"%s\"\n", name);
	}

	d->pe_cur_section_virt_addr = de_getui32le(pos+12);
	section_data_size = de_getui32le(pos+16);
	d->pe_cur_section_data_offset = de_getui32le(pos+20);

	de_dbg(c, "section virt. addr=%d (0x%08x)\n", (int)d->pe_cur_section_virt_addr, (unsigned int)d->pe_cur_section_virt_addr);
	de_dbg(c, "section data offset=%d, size=%d\n", (int)d->pe_cur_section_data_offset, (int)section_data_size);

	if(!de_memcmp(name_raw, ".rsrc\0", 5)) {
		do_pe_resource_section(c, d, d->pe_cur_section_data_offset, section_data_size);
	}
}

static void do_pe_section_table(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 i;

	pos = d->pe_sections_offset;
	de_dbg(c, "section table at %d\n", (int)pos);
	for(i=0; i<d->pe_number_of_sections; i++) {
		do_pe_section_header(c, d, pos + 40*i);
	}
}

static void do_ne_rsrc_tbl(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 npos;
	de_int64 x;
	de_int64 i;
	de_int64 j;
	de_int64 rsrc_type_id;
	de_int64 rsrc_count;
	de_int64 rsrc_offset;
	de_int64 rsrc_size;
	de_int64 tot_resources = 0;
	unsigned int align_shift;
	int have_type;

	pos = d->ne_rsrc_tbl_offset;

	de_dbg(c, "resource table at %d\n", (int)pos);

	align_shift = (unsigned int)de_getui16le(pos);
	de_dbg(c, "rscAlignShift: %u\n", align_shift);
	pos += 2;
	if(align_shift>24) {
		de_err(c, "Unrealistic rscAlignShift setting\n");
		return;
	}

	i = 0;
	while(1) {
		x = de_getui16le(pos);
		if(x==0) {
			// A "type_id" of 0 marks the end of the array
			de_dbg(c, "end of TYPEINFO array found at %d\n", (int)pos);
			break;
		}
		de_dbg(c, "TYPEINFO #%d at %d\n", (int)i, (int)pos);

		if(x & 0x8000) {
			rsrc_type_id = x-0x8000;
			have_type = 1;
		}
		else {
			// x represents a relative offset to a name in rscResourceNames.
			// TODO: Could the name ever be a standard type (e.g. "ICON"), that
			// we ought to support?
			rsrc_type_id = 0;
			have_type = 0;
			// name_offset = d->ne_rsrc_tbl_offset + x;
		}

		rsrc_count = de_getui16le(pos+2);
		if(have_type)
			de_dbg(c, " resource type=%d, count=%d\n", (int)rsrc_type_id, (int)rsrc_count);
		else
			de_dbg(c, " resource type=?, count=%d\n", (int)rsrc_count);

		tot_resources += rsrc_count;

		if(tot_resources>MAX_RESOURCES) {
			de_err(c, "Too many resources, or invalid resource table.\n");
			break;
		}

		// Read the array of NAMEINFO structures.
		// (NAMEINFO seems like a misnomer to me. It contains data, not names.)
		for(j=0; j<rsrc_count; j++) {
			npos = pos+8 + j*12;
			rsrc_offset = de_getui16le(npos);
			if(align_shift>0) rsrc_offset <<= align_shift;
			rsrc_size = de_getui16le(npos+2);
			if(align_shift>0) rsrc_size <<= align_shift;
			de_dbg(c, " offset = %d, length = %d\n", (int)rsrc_offset, (int)rsrc_size);

			if(have_type)
				do_ne_pe_extract_resource(c, d, rsrc_type_id, rsrc_offset, rsrc_size);
		}

		pos += 8 + 12*rsrc_count;
		i++;
	}
}

// Sniff the resource data, and return a suitable filename extension.
// Or NULL, if unidentified.
static const char *identify_lx_rsrc(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_byte buf[2];
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
	if(!de_memcmp(buf, "CI", 2) || !de_memcmp(buf, "IC", 2)) return "os2.ico";
	if(!de_memcmp(buf, "CP", 2) || !de_memcmp(buf, "PT", 2)) return "ptr";
	return NULL;
}

// Extract a resource from an LX file, given the information from an Object Table
// entry.
static void do_lx_rsrc(deark *c, lctx *d,
	de_int64 obj_num, de_int64 rsrc_offset, de_int64 rsrc_size, de_int64 rsrc_type)
{
	de_int64 lpos;
	de_int64 vsize;
	de_int64 reloc_base_addr;
	de_int64 flags;
	de_int64 page_table_index;
	de_int64 page_table_entries;
	de_int64 rsrc_offset_real;
	de_int64 pg_data_offset_raw;
	const char *ext;
	//de_int64 data_size;

	if(obj_num<1 || obj_num>d->lx_object_tbl_entries) {
		de_err(c, "Invalid object number (%d).\n", (int)obj_num);
		return;
	}

	// Read the Object Table
	lpos = d->lx_object_tbl_offset + 24*(obj_num-1);
	de_dbg(c, " LX object table entry at %d\n", (int)lpos);

	vsize = de_getui32le(lpos);
	reloc_base_addr = de_getui32le(lpos+4);
	flags = de_getui32le(lpos+8);
	page_table_index = de_getui32le(lpos+12);
	page_table_entries = de_getui32le(lpos+16);
	de_dbg(c, " object #%d: vsize=%d raddr=%d flags=0x%x pti=%d pte=%d\n", (int)obj_num,
		(int)vsize, (int)reloc_base_addr, (unsigned int)flags, (int)page_table_index,
		(int)page_table_entries);

	if(page_table_index<1) return;

	// Now read the Object Page table
	lpos = d->lx_object_page_tbl_offset + 8*(page_table_index-1);
	de_dbg(c, " LX page table entry at %d\n", (int)lpos);

	pg_data_offset_raw = de_getui32le(lpos);
	//data_size = de_getui16le(lpos+4);
	
	rsrc_offset_real = pg_data_offset_raw;
	if(d->lx_page_offset_shift > 0 ) {
		rsrc_offset_real <<= (unsigned int)d->lx_page_offset_shift;
	}
	rsrc_offset_real += d->lx_data_pages_offset;
	rsrc_offset_real += rsrc_offset;
	de_dbg(c, " resource offset: %d\n", (int)rsrc_offset_real);

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
		dbuf_create_file_from_slice(c->infile, rsrc_offset_real, rsrc_size, ext);
		break;
	}
}

static void do_lx_rsrc_tbl(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 lpos;
	de_int64 type_id;
	de_int64 name_id;
	de_int64 rsrc_size;
	de_int64 rsrc_object;
	de_int64 rsrc_offset;

	de_dbg(c, "LX resource table at %d\n", (int)d->lx_rsrc_tbl_offset);
	if(d->lx_rsrc_tbl_entries>MAX_RESOURCES) {
		de_err(c, "Too many resources.\n");
		return;
	}

	for(i=0; i<d->lx_rsrc_tbl_entries; i++) {
		lpos = d->lx_rsrc_tbl_offset + 14*i;

		type_id = de_getui16le(lpos);
		name_id = de_getui16le(lpos+2);
		rsrc_size = de_getui32le(lpos+4);
		rsrc_object = de_getui16le(lpos+8);
		rsrc_offset = de_getui32le(lpos+10);

		de_dbg(c, "resource #%d: type=%d name=%d size=%d obj=%d offset=%d\n", (int)i,
			(int)type_id, (int)name_id, (int)rsrc_size, (int)rsrc_object, (int)rsrc_offset);

		do_lx_rsrc(c, d, rsrc_object, rsrc_offset, rsrc_size, type_id);
	}
}

static void de_run_exe(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In EXE module\n");
	d = de_malloc(c, sizeof(lctx));

	do_fileheader(c, d);

	if((d->fmt==EXE_FMT_PE32 || d->fmt==EXE_FMT_PE32PLUS) && d->pe_sections_offset>0) {
		do_pe_section_table(c, d);
	}
	else if(d->fmt==EXE_FMT_NE && d->ne_rsrc_tbl_offset>0) {
		do_ne_rsrc_tbl(c, d);
	}
	else if(d->fmt==EXE_FMT_LX && d->lx_rsrc_tbl_offset>0) {
		do_lx_rsrc_tbl(c, d);
	}

	de_free(c, d);
}

static int de_identify_exe(deark *c)
{
	de_byte buf[2];
	de_read(buf, 0, 2);

	if(buf[0]=='M' && buf[1]=='Z') return 80;
	return 0;
}

void de_module_exe(deark *c, struct deark_module_info *mi)
{
	mi->id = "exe";
	mi->run_fn = de_run_exe;
	mi->identify_fn = de_identify_exe;
}
