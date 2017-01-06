// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Windows HLP

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_hlp);

#define FILETYPE_SYSTEM 1
#define FILETYPE_BM     10

struct bptree {
	unsigned int flags;
	de_int64 pagesize;
	de_int64 root_page;
	de_int64 num_levels;
	de_int64 num_pages;
	de_int64 num_entries;
	de_int64 pagesdata_pos;
};

typedef struct localctx_struct {
	de_int64 internal_dir_FILEHEADER_offs;
	struct bptree bpt;
} lctx;

static void do_SYSTEMREC(deark *c, lctx *d, unsigned int recordtype,
	de_int64 pos1, de_int64 len)
{
	if(recordtype==5) { // Icon
		dbuf_create_file_from_slice(c->infile, pos1, len, "ico", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void do_file_SYSTEM(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 magic;
	int saved_indent_level;
	de_int64 ver_major, ver_minor;
	de_int64 gen_date;
	unsigned int flags;
	int is_compressed;

	de_dbg_indent_save(c, &saved_indent_level);

	magic = de_getui16le(pos);
	if(magic!=0x036c) {
		de_err(c, "Expected SYSTEM data at %d not found\n", (int)pos1);
		goto done;
	}
	pos += 2;

	de_dbg(c, "SYSTEM file at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	ver_minor = de_getui16le(pos);
	pos += 2;
	ver_major = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "help format version: %d.%d\n", (int)ver_major, (int)ver_minor);

	if(ver_major!=1) {
		de_err(c, "Unsupported file version: %d.%d\n", (int)ver_major, (int)ver_minor);
		goto done;
	}

	gen_date = de_geti32le(pos);
	de_dbg(c, "GenDate: %d\n", (int)gen_date);
	pos += 4;

	flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x\n", flags);
	pos += 2;

	if(ver_minor>=16 && ((flags&0x4) || (flags&0x8))) {
		is_compressed = 1;
	}
	else {
		is_compressed = 0;
	}
	de_dbg(c, "compressed: %d\n", is_compressed);

	if(ver_minor<16) {
		// TODO: HelpFileTitle
	}
	else {
		// A sequence of variable-sized SYSTEMRECs

		while((pos1+len)-pos >=4) {
			unsigned int recordtype;
			de_int64 datasize;
			de_int64 systemrec_startpos;

			systemrec_startpos = pos;

			recordtype = (unsigned int)de_getui16le(pos);
			pos += 2;
			datasize = de_getui16le(pos);
			pos += 2;

			de_dbg(c, "SYSTEMREC type %u at %d, dpos=%d, dlen=%d\n",
				recordtype, (int)systemrec_startpos,
				(int)pos, (int)datasize);

			if(pos+datasize > pos1+len) break; // bad data
			de_dbg_indent(c, 1);
			do_SYSTEMREC(c, d, recordtype, pos, datasize);
			de_dbg_indent(c, -1);
			pos += datasize;
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file(deark *c, lctx *d, de_int64 pos1, int file_fmt)
{
	de_int64 reserved_space;
	de_int64 used_space;
	de_int64 pos = pos1;
	unsigned int fileflags;

	de_dbg(c, "file at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	// FILEHEADER
	reserved_space = de_getui32le(pos);
	de_dbg(c, "ReservedSpace: %d\n", (int)reserved_space);
	pos += 4;

	used_space = de_getui32le(pos);
	de_dbg(c, "UsedSpace: %d\n", (int)used_space);
	pos += 4;

	fileflags = (unsigned int)de_getbyte(pos);
	de_dbg(c, "FileFlags: 0x%02x\n", fileflags);
	pos += 1;

	if(pos+used_space > c->infile->len) {
		de_err(c, "Bad file size\n");
		goto done;
	}

	//
	switch(file_fmt) {
	case FILETYPE_SYSTEM:
		do_file_SYSTEM(c, d, pos, used_space);
		break;

	case FILETYPE_BM:
		{
			de_int64 num_images;
			de_int64 sig;
			const char *ext;
			dbuf *outf = NULL;

			// Ignore the file SHG vs. MRB file type signature, and replace it with
			// the correct one based on the number of images in the file.
			num_images = de_getui16le(pos+2);
			if(num_images>1) {
				ext="mrb";
				sig = 0x706c;
			}
			else {
				ext="shg";
				sig = 0x506c;
			}

			outf = dbuf_create_output_file(c, ext, NULL, 0);
			dbuf_writeui16le(outf, sig);
			dbuf_copy(c->infile, pos+2, used_space-2, outf);
			dbuf_close(outf);
		}
		break;
	}

done:
	de_dbg_indent(c, -1);
}

static void do_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 n;

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->internal_dir_FILEHEADER_offs = de_geti32le(4);
	de_dbg(c, "internal dir FILEHEADER pos: %d\n", (int)d->internal_dir_FILEHEADER_offs);

	n = de_geti32le(8);
	de_dbg(c, "FREEHEADER pos: %d\n", (int)n);

	n = de_geti32le(12);
	de_dbg(c, "reported file size: %d\n", (int)n);

	de_dbg_indent(c, -1);
}

static void do_index_page(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 n;
	de_int64 pos = pos1;

	de_dbg(c, "index page at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	pos += 2; // Unused

	n = de_geti16le(pos);
	de_dbg(c, "NEntries: %d\n", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "PreviousPage: %d\n", (int)n);
	pos += 2;

	de_dbg_indent(c, -1);
}

static int filename_to_filetype(deark *c, lctx *d, const char *fn)
{
	if(!de_strcmp(fn, "|SYSTEM")) return FILETYPE_SYSTEM;
	if(!de_strncmp(fn, "|bm", 3)) return FILETYPE_BM;
	if(!de_strncmp(fn, "bm", 2)) return FILETYPE_BM;
	return 0;
}

static void do_leaf_page(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 n;
	de_int64 pos = pos1;
	de_int64 foundpos;
	de_int64 num_entries;
	de_int64 file_offset;
	de_ucstring *s = NULL;
	char filename_raw[300];
	de_int64 k;
	int file_type;

	de_dbg(c, "leaf page at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	n = de_getui16le(pos); // "Unused"
	de_dbg(c, "free bytes at end of this page: %d\n", (int)n);
	pos += 2;

	num_entries = de_geti16le(pos);
	de_dbg(c, "NEntries: %d\n", (int)num_entries);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "PreviousPage: %d\n", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "NextPage: %d\n", (int)n);
	pos += 2;

	for(k=0; k<num_entries; k++) {
		// TODO: Verify that pos is sane.

		if(!dbuf_search_byte(c->infile, 0x00, pos, 260, &foundpos)) {
			de_err(c, "Malformed leaf page at %d\n", (int)pos1);
			goto done;
		}

		de_read((de_byte*)filename_raw, pos, foundpos+1-pos);
		s = ucstring_create(c);
		ucstring_append_sz(s, filename_raw, DE_ENCODING_WINDOWS1252);
		de_dbg(c, "FileName: \"%s\"\n", ucstring_get_printable_sz(s));
		pos = foundpos + 1;

		file_offset = de_geti32le(pos);
		de_dbg(c, "FileOffset: %d\n", (int)file_offset);
		pos += 4;


		file_type = filename_to_filetype(c, d, filename_raw);

		do_file(c, d, file_offset, file_type);
	}

done:
	ucstring_destroy(s);
	de_dbg_indent(c, -1);
}

static void do_bplustree(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	de_int64 n;
	int saved_indent_level;
	char structure_string[17];
	de_ucstring *structure_string_u = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	n = de_getui16le(pos);
	if(n != 0x293b) {
		de_err(c, "Expected B+ tree structure at %d not found\n", (int)pos1);
		goto done;
	}
	pos += 2;

	de_dbg(c, "B+ tree at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	d->bpt.flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x\n", d->bpt.flags);
	pos += 2;

	d->bpt.pagesize = de_getui16le(pos);
	de_dbg(c, "PageSize: %d\n", (int)d->bpt.pagesize);
	pos += 2;

	de_read((de_byte*)structure_string, pos, 16);
	structure_string[16] = '\0';
	structure_string_u = ucstring_create(c);
	ucstring_append_sz(structure_string_u, structure_string, DE_ENCODING_ASCII);
	de_dbg(c, "Structure: \"%s\"\n", ucstring_get_printable_sz(structure_string_u));
	pos += 16;

	pos += 2; // MustBeZero
	pos += 2; // PageSplits

	d->bpt.root_page = de_geti16le(pos);
	de_dbg(c, "RootPage: %d\n", (int)d->bpt.root_page);
	pos += 2;

	pos += 2; // MustBeNegOne

	d->bpt.num_pages = de_geti16le(pos);
	de_dbg(c, "TotalPages: %d\n", (int)d->bpt.num_pages);
	pos += 2;

	d->bpt.num_levels = de_geti16le(pos);
	de_dbg(c, "NLevels: %d\n", (int)d->bpt.num_levels);
	pos += 2;

	d->bpt.num_entries = de_geti32le(pos);
	de_dbg(c, "TotalBtreeEntries: %d\n", (int)d->bpt.num_entries);
	pos += 4;

	d->bpt.pagesdata_pos = pos;
	de_dbg(c, "%d page(s), %d bytes each, at %d (total size=%d)\n",
		(int)d->bpt.num_pages, (int)d->bpt.pagesize, (int)d->bpt.pagesdata_pos,
		(int)(d->bpt.num_pages * d->bpt.pagesize));

	if(d->bpt.num_levels>1) {
		if(d->bpt.root_page>=0) {
			do_index_page(c, d,
				d->bpt.pagesdata_pos + d->bpt.root_page*d->bpt.pagesize);
		}
	}
	else {
		do_leaf_page(c, d,
			d->bpt.pagesdata_pos + d->bpt.root_page*d->bpt.pagesize);
	}

done:
	ucstring_destroy(structure_string_u);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_internal_dir_FILEHEADER(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 usedspace;
	de_int64 n;
	de_byte b;

	pos = d->internal_dir_FILEHEADER_offs;
	if(pos<16) goto done;

	de_dbg(c, "internal dir at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	// TODO: Consolidate this code with the code in do_file().
	n = de_geti32le(pos);
	de_dbg(c, "ReservedSpace: %d\n", (int)n);
	usedspace = de_geti32le(pos+4);
	de_dbg(c, "UsedSpace: %d\n", (int)usedspace);
	b = de_getbyte(pos+8);
	de_dbg(c, "FileFlags: 0x%02x\n", (unsigned int)b);
	pos += 9;

	do_bplustree(c, d, pos, usedspace);

	de_dbg_indent(c, -1);
done:
	;
}

static void de_run_hlp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	do_header(c, d, pos);

	do_internal_dir_FILEHEADER(c, d);

	de_free(c, d);
}

static int de_identify_hlp(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x3f\x5f\x03\x00", 4))
		return 100;
	return 0;
}

void de_module_hlp(deark *c, struct deark_module_info *mi)
{
	mi->id = "hlp";
	mi->desc = "HLP";
	mi->run_fn = de_run_hlp;
	mi->identify_fn = de_identify_hlp;
}
