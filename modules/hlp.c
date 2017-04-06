// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Windows HLP

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_hlp);

#define FILETYPE_INTERNALDIR  1
#define FILETYPE_SYSTEM       2
#define FILETYPE_TOPIC        10
#define FILETYPE_SHG          11

struct bptree {
	unsigned int flags;
	de_int64 pagesize;
	de_int64 root_page;
	de_int64 num_levels;
	de_int64 num_pages;
	de_int64 num_entries;
	de_int64 pagesdata_pos;
	de_int64 first_leaf_page;
};

typedef struct localctx_struct {
	de_int64 internal_dir_FILEHEADER_offs;
	struct bptree bpt;
	int found_system_file;
	de_int64 ver_minor;
	de_int64 topic_block_size;
	int is_compressed;
} lctx;

static void do_file(deark *c, lctx *d, de_int64 pos1, int file_fmt);

static void do_SYSTEMREC(deark *c, lctx *d, unsigned int recordtype,
	de_int64 pos1, de_int64 len, const char *recordtypename)
{
	if(recordtype==5) { // Icon
		dbuf_create_file_from_slice(c->infile, pos1, len, "ico", NULL, DE_CREATEFLAG_IS_AUX);
	}
}

static void hlptime_to_timestamp(de_int64 ht, struct de_timestamp *ts)
{
	if(ht!=0) {
		// This appears to be a Unix-style timestamp, though some documentation
		// says otherwise.
		de_unix_time_to_timestamp(ht, ts);
	}
	else {
		de_memset(ts, 0, sizeof(struct de_timestamp));
	}
}

static const char *sysrec_type_to_type_name(unsigned int t)
{
	const char *name = "?";
	switch(t) {
	case 1: name="title"; break;
	case 2: name="copyright"; break;
	case 3: name="contents"; break;
	case 4: name="macro"; break;
	case 5: name="icon"; break;
	case 6: name="window"; break;
	case 9: name="language ID"; break;
	case 10: name="CNT file name"; break;
	case 11: name="charset"; break;
	}
	return name;
}

static int do_file_SYSTEM_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 magic;
	de_int64 ver_major;
	de_int64 gen_date;
	unsigned int flags;
	struct de_timestamp ts;
	char timestamp_buf[64];
	int retval = 0;

	magic = de_getui16le(pos);
	if(magic!=0x036c) {
		de_err(c, "Expected SYSTEM data at %d not found\n", (int)pos1);
		goto done;
	}
	pos += 2;

	de_dbg(c, "SYSTEM file data at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	d->ver_minor = de_getui16le(pos);
	pos += 2;
	ver_major = de_getui16le(pos);
	pos += 2;
	de_dbg(c, "help format version: %d.%d\n", (int)ver_major, (int)d->ver_minor);

	if(ver_major!=1) {
		de_err(c, "Unsupported file version: %d.%d\n", (int)ver_major, (int)d->ver_minor);
		goto done;
	}

	gen_date = de_geti32le(pos);
	hlptime_to_timestamp(gen_date, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "GenDate: %d (%s)\n", (int)gen_date, timestamp_buf);
	pos += 4;

	flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x\n", flags);
	pos += 2;

	if(d->ver_minor>=16) {
		if(flags==8) {
			d->is_compressed = 1;
			d->topic_block_size = 2048;
		}
		else if(flags==4) {
			d->is_compressed = 1;
			d->topic_block_size = 4096;
		}
		else {
			d->is_compressed = 0;
			d->topic_block_size = 4096;
		}
	}
	else {
		d->is_compressed = 0;
		d->topic_block_size = 2048;
	}
	de_dbg(c, "compressed: %d\n", d->is_compressed);
	de_dbg(c, "topic block size: %d\n", (int)d->topic_block_size);

	retval = 1;
done:
	return retval;
}

static void do_file_SYSTEM_SYSTEMRECS(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;

	while((pos1+len)-pos >=4) {
		unsigned int recordtype;
		de_int64 datasize;
		de_int64 systemrec_startpos;
		const char *recordtypename;

		systemrec_startpos = pos;

		recordtype = (unsigned int)de_getui16le(pos);
		pos += 2;
		datasize = de_getui16le(pos);
		pos += 2;

		recordtypename = sysrec_type_to_type_name(recordtype);
		de_dbg(c, "SYSTEMREC type %u (%s) at %d, dpos=%d, dlen=%d\n",
			recordtype, recordtypename,
			(int)systemrec_startpos, (int)pos, (int)datasize);

		if(pos+datasize > pos1+len) break; // bad data
		de_dbg_indent(c, 1);
		do_SYSTEMREC(c, d, recordtype, pos, datasize, recordtypename);
		de_dbg_indent(c, -1);
		pos += datasize;
	}
}

static void do_file_SYSTEM(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->found_system_file) goto done;
	d->found_system_file = 1;

	if(!do_file_SYSTEM_header(c, d, pos)) goto done;
	pos += 12;

	if(d->ver_minor<16) {
		// TODO: HelpFileTitle
	}
	else {
		// A sequence of variable-sized SYSTEMRECs
		do_file_SYSTEM_SYSTEMRECS(c, d, pos, (pos1+len)-pos);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file_SHG(deark *c, lctx *d, de_int64 pos1, de_int64 used_space)
{
	de_int64 num_images;
	de_int64 sig;
	const char *ext;
	dbuf *outf = NULL;

	// Ignore the file SHG vs. MRB file type signature, and replace it with
	// the correct one based on the number of images in the file.
	num_images = de_getui16le(pos1+2);
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
	dbuf_copy(c->infile, pos1+2, used_space-2, outf);
	dbuf_close(outf);
}

static void do_file_TOPIC(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "TOPIC at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	if(!d->found_system_file || d->topic_block_size<2048) {
		de_err(c, "SYSTEM file not found\n");
		goto done;
	}

	// A series of blocks, each with a 12-byte header
	while(1) {
		de_int64 lastlink, firstlink, lastheader;
		de_int64 blklen;
		de_int64 blk_dpos;
		de_int64 blk_dlen;

		blklen = (pos1+len)-pos;
		if(blklen<12) break;
		if(blklen > d->topic_block_size) blklen = d->topic_block_size;
		blk_dpos = pos+12;
		blk_dlen = blklen-12;

		de_dbg(c, "TOPIC block at %d, dpos=%d, dlen=%d\n", (int)pos,
			(int)blk_dpos, (int)blk_dlen);
		de_dbg_indent(c, 1);
		lastlink = de_geti32le(pos);
		firstlink = de_geti32le(pos+4);
		lastheader = de_geti32le(pos+8);
		de_dbg(c, "LastLink=%d, FirstLink=%d, LastHeader=%d\n",
			(int)lastlink, (int)firstlink, (int)lastheader);

		de_dbg_indent(c, -1);
		pos += blklen;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);

}
static void do_index_page(deark *c, lctx *d, de_int64 pos1, de_int64 *prev_page)
{
	*prev_page = de_geti16le(pos1+4);
	de_dbg(c, "PreviousPage: %d\n", (int)*prev_page);
}

static int de_is_digit(char x)
{
	return (x>='0' && x<='9');
}

static int filename_to_filetype(deark *c, lctx *d, const char *fn)
{
	if(!de_strcmp(fn, "|TOPIC")) return FILETYPE_TOPIC;
	if(!de_strcmp(fn, "|SYSTEM")) return FILETYPE_SYSTEM;
	if(!de_strncmp(fn, "|bm", 3) && de_is_digit(fn[3])) return FILETYPE_SHG;
	if(!de_strncmp(fn, "bm", 2) && de_is_digit(fn[2])) return FILETYPE_SHG;
	return 0;
}

static void do_leaf_page(deark *c, lctx *d, de_int64 pos1, int pass, de_int64 *pnext_page)
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
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
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
	if(pnext_page) *pnext_page = n;
	pos += 2;

	s = ucstring_create(c);

	for(k=0; k<num_entries; k++) {
		de_dbg(c, "entry[%d]\n", (int)k);
		de_dbg_indent(c, 1);

		if(!dbuf_search_byte(c->infile, 0x00, pos, 260, &foundpos)) {
			de_err(c, "Malformed leaf page at %d\n", (int)pos1);
			goto done;
		}

		de_read((de_byte*)filename_raw, pos, foundpos+1-pos);
		ucstring_truncate(s, 0);
		ucstring_append_sz(s, filename_raw, DE_ENCODING_WINDOWS1252);
		de_dbg(c, "FileName: \"%s\"\n", ucstring_get_printable_sz(s));
		pos = foundpos + 1;

		file_offset = de_geti32le(pos);
		de_dbg(c, "FileOffset: %d\n", (int)file_offset);
		pos += 4;

		file_type = filename_to_filetype(c, d, filename_raw);

		if((pass==1 && file_type==FILETYPE_SYSTEM) ||
			(pass==2 && file_type!=FILETYPE_SYSTEM))
		{
			do_file(c, d, file_offset, file_type);
		}

		de_dbg_indent(c, -1);

		// All we do in pass 1 is read the SYSTEM file, so we can stop if we've
		// done that.
		if(pass==1 && d->found_system_file) break;
	}

done:
	ucstring_destroy(s);
	de_dbg_indent_restore(c, saved_indent_level);
}

// Sets d->bpt.first_leaf_page
static int find_first_leaf_page(deark *c, lctx *d)
{
	de_int64 curr_page;
	de_int64 curr_level;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	curr_page = d->bpt.root_page;
	curr_level = d->bpt.num_levels;

	de_dbg(c, "looking for first leaf page\n");
	de_dbg_indent(c, 1);

	while(curr_level>1) {
		de_int64 prev_page;
		de_int64 page_pos;

		if(curr_page<0) goto done;
		page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

		de_dbg(c, "page %d is an index page, level=%d\n", (int)curr_page, (int)curr_level);

		prev_page = -1;
		de_dbg_indent(c, 1);
		do_index_page(c, d, page_pos, &prev_page);
		de_dbg_indent(c, -1);

		curr_page = prev_page;
		curr_level--;
	}

	de_dbg(c, "page %d is the first leaf page\n", (int)curr_page);
	d->bpt.first_leaf_page = curr_page;

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// This function is only for the "internal directory" tree.
// There are other data objects in HLP files that use the same kind of data
// structure. If we ever want to parse them, this function will have to be
// genericized.
static void do_bplustree(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	int pass;
	de_int64 pos = pos1;
	de_int64 n;
	int saved_indent_level;
	de_byte *page_seen = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	n = de_getui16le(pos);
	if(n != 0x293b) {
		de_err(c, "Expected B+ tree structure at %d not found\n", (int)pos1);
		goto done;
	}
	pos += 2;

	//de_dbg(c, "B+ tree at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	d->bpt.flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x\n", d->bpt.flags);
	pos += 2;

	d->bpt.pagesize = de_getui16le(pos);
	de_dbg(c, "PageSize: %d\n", (int)d->bpt.pagesize);
	pos += 2;

	// TODO: Understand the Structure field
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
	de_dbg(c, "num pages: %d, %d bytes each, at %d (total size=%d)\n",
		(int)d->bpt.num_pages, (int)d->bpt.pagesize, (int)d->bpt.pagesdata_pos,
		(int)(d->bpt.num_pages * d->bpt.pagesize));

	if(!find_first_leaf_page(c, d)) goto done;

	page_seen = de_malloc(c, d->bpt.num_pages); // For loop detection

	for(pass=1; pass<=2; pass++) {
		de_int64 curr_page;

		de_memset(page_seen, 0, (size_t)d->bpt.num_pages);

		de_dbg(c, "pass %d\n", pass);
		de_dbg_indent(c, 1);

		curr_page = d->bpt.first_leaf_page;

		while(1) {
			de_int64 page_pos;
			de_int64 next_page;

			if(curr_page<0) break;
			if(curr_page>d->bpt.num_pages) goto done;

			if(pass==1 && page_seen[curr_page]) {
				de_err(c, "Page loop detected\n");
				goto done;
			}
			page_seen[curr_page] = 1;

			page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

			de_dbg(c, "page[%d] at %d (leaf page)\n", (int)curr_page, (int)page_pos);

			next_page = -1;
			de_dbg_indent(c, 1);
			do_leaf_page(c, d, page_pos, pass, &next_page);
			de_dbg_indent(c, -1);

			if(pass==1 && d->found_system_file) {
				de_dbg(c, "[found SYSTEM file, so stopping pass 1]\n");
				break;
			}

			curr_page = next_page;
		}

		de_dbg_indent(c, -1);
	}

done:
	de_free(c, page_seen);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_file_INTERNALDIR(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_dbg(c, "internal dir data at %d\n", (int)pos1);
	do_bplustree(c, d, pos1, len);
}

static const char* file_type_to_type_name(int file_fmt)
{
	const char *name = "unspecified";
	switch(file_fmt) {
	case FILETYPE_SYSTEM: name="system"; break;
	case FILETYPE_TOPIC: name="topic"; break;
	case FILETYPE_SHG: name="SHG/MRB"; break;
	case FILETYPE_INTERNALDIR: name="directory"; break;
	}
	return name;
}

static void do_file(deark *c, lctx *d, de_int64 pos1, int file_fmt)
{
	de_int64 reserved_space;
	de_int64 used_space;
	de_int64 pos = pos1;
	unsigned int fileflags;

	de_dbg(c, "file at %d, type=%s\n", (int)pos1, file_type_to_type_name(file_fmt));
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
	case FILETYPE_INTERNALDIR:
		do_file_INTERNALDIR(c, d, pos, used_space);
		break;

	case FILETYPE_TOPIC:
		do_file_TOPIC(c, d, pos, used_space);
		break;

	case FILETYPE_SYSTEM:
		do_file_SYSTEM(c, d, pos, used_space);
		break;

	case FILETYPE_SHG:
		do_file_SHG(c, d, pos, used_space);
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

static void de_run_hlp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	do_header(c, d, pos);

	do_file(c, d, d->internal_dir_FILEHEADER_offs, FILETYPE_INTERNALDIR);

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
