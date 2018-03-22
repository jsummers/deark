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
#define FILETYPE_BMP          20

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
	int ver_major;
	int ver_minor;
	de_int64 topic_block_size;
	int is_compressed;
	int pass;
	int has_shg, has_ico, has_bmp;
	de_int64 internal_dir_num_levels;
} lctx;

static void do_file(deark *c, lctx *d, de_int64 pos1, int file_fmt);

struct systemrec_info {
	unsigned int rectype;

	// low 8 bits = version info
	// 0x0010 = STRINGZ type
	unsigned int flags;

	const char *name;
	void *reserved;
};
static const struct systemrec_info systemrec_info_arr[] = {
	{ 1,  0x0010, "Title", NULL },
	{ 2,  0x0010, "Copyright", NULL },
	{ 3,  0x0000, "Contents", NULL },
	{ 4,  0x0010, "Macro", NULL },
	{ 5,  0x0000, "Icon", NULL },
	{ 6,  0x0000, "Window", NULL },
	{ 8,  0x0010, "Citation", NULL },
	{ 9,  0x0000, "Language ID", NULL },
	{ 10, 0x0010, "CNT file name", NULL },
	{ 11, 0x0000, "Charset", NULL },
	{ 12, 0x0000, "Default dialog font", NULL },
	{ 13, 0x0010, "Defined GROUPs", NULL },
	{ 14, 0x0011, "IndexSeparators separators", NULL },
	{ 14, 0x0002, "Multimedia Help Files", NULL },
	{ 18, 0x0010, "Defined language", NULL },
	{ 19, 0x0000, "Defined DLLMAPS", NULL }
};
static const struct systemrec_info systemrec_info_default =
	{ 0, 0x0000, "?", NULL };

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

static void do_display_STRINGZ(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	const char *name)
{
	de_ucstring *s = NULL;

	if(len<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile,
		pos1, len, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_SYSTEMREC_STRINGZ(deark *c, lctx *d, unsigned int recordtype,
	de_int64 pos1, de_int64 len, const struct systemrec_info *sti)
{
	// TODO: Can we figure out the encoding?
	do_display_STRINGZ(c, d, pos1, len, sti->name);
}

static void do_SYSTEMREC(deark *c, lctx *d, unsigned int recordtype,
	de_int64 pos1, de_int64 len, const struct systemrec_info *sti)
{
	if(recordtype==5) { // Icon
		d->has_ico = 1;
		dbuf_create_file_from_slice(c->infile, pos1, len, "ico", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(sti->flags&0x10) {
		do_SYSTEMREC_STRINGZ(c, d, recordtype, pos1, len, sti);
	}
}

static const struct systemrec_info *find_sysrec_info(deark *c, lctx *d, unsigned int t)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(systemrec_info_arr); i++) {
		const struct systemrec_info *sti;
		sti = &systemrec_info_arr[i];
		if(sti->rectype==t &&
			(sti->flags&0x0f)==0)
		{
			return sti;
		}
	}
	return &systemrec_info_default;
}

static int do_file_SYSTEM_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 magic;
	de_int64 gen_date;
	unsigned int flags;
	struct de_timestamp ts;
	char timestamp_buf[64];
	int retval = 0;

	magic = de_getui16le(pos);
	if(magic!=0x036c) {
		de_err(c, "Expected SYSTEM data at %d not found", (int)pos1);
		goto done;
	}
	pos += 2;

	de_dbg(c, "SYSTEM file data at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->ver_minor = (int)de_getui16le(pos);
	pos += 2;
	d->ver_major = (int)de_getui16le(pos);
	pos += 2;
	de_dbg(c, "help format version: %d.%d", d->ver_major, d->ver_minor);

	if(d->ver_major!=1) {
		de_err(c, "Unsupported file version: %d.%d", d->ver_major, d->ver_minor);
		goto done;
	}

	gen_date = de_geti32le(pos);
	hlptime_to_timestamp(gen_date, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "GenDate: %d (%s)", (int)gen_date, timestamp_buf);
	pos += 4;

	flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x", flags);
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
	de_dbg(c, "compressed: %d", d->is_compressed);
	de_dbg(c, "topic block size: %d", (int)d->topic_block_size);

	retval = 1;
done:
	return retval;
}

static void do_file_SYSTEM_SYSTEMRECS(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	int systemrecs_pass)
{
	de_int64 pos = pos1;

	while((pos1+len)-pos >=4) {
		unsigned int recordtype;
		de_int64 datasize;
		de_int64 systemrec_startpos;
		const struct systemrec_info *sti;

		systemrec_startpos = pos;

		recordtype = (unsigned int)de_getui16le(pos);
		pos += 2;
		datasize = de_getui16le(pos);
		pos += 2;

		sti = find_sysrec_info(c, d, recordtype);
		de_dbg(c, "SYSTEMREC type %u (%s) at %d, dpos=%d, dlen=%d",
			recordtype, sti->name,
			(int)systemrec_startpos, (int)pos, (int)datasize);

		if(pos+datasize > pos1+len) break; // bad data
		de_dbg_indent(c, 1);
		do_SYSTEMREC(c, d, recordtype, pos, datasize, sti);
		de_dbg_indent(c, -1);
		pos += datasize;
	}
}

static void do_file_SYSTEM(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	// We'll read the SYSTEM "file" only in pass 1, most importantly to record
	// the format version information.
	//
	// The SYSTEM file may contain a series of SYSTEMREC records that we want
	// to parse. We might [someday] have to make two (sub)passes over the
	// SYSTEMREC records, the first pass to collect "charset" setting, so it
	// can be used when parsing the other SYSTEMREC records.
	// (We can do it this way because there doesn't seem to be anything in the
	// SYSTEM header that would require knowing the charset.)

	if(d->pass!=1) goto done;
	d->found_system_file = 1;

	if(!do_file_SYSTEM_header(c, d, pos)) goto done;
	pos += 12;

	if(d->ver_minor<16) {
		do_display_STRINGZ(c, d, pos, (pos1+len)-pos, "HelpFileTitle");
	}
	else {
		// A sequence of variable-sized SYSTEMRECs
		do_file_SYSTEM_SYSTEMRECS(c, d, pos, (pos1+len)-pos, 1);
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
	de_dbg(c, "TOPIC at %d", (int)pos1);
	de_dbg_indent(c, 1);

	if(!d->found_system_file || d->topic_block_size<2048) {
		de_err(c, "SYSTEM file not found");
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

		de_dbg(c, "TOPIC block at %d, dpos=%d, dlen=%d", (int)pos,
			(int)blk_dpos, (int)blk_dlen);
		de_dbg_indent(c, 1);
		lastlink = de_geti32le(pos);
		firstlink = de_geti32le(pos+4);
		lastheader = de_geti32le(pos+8);
		de_dbg(c, "LastLink=%d, FirstLink=%d, LastHeader=%d",
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
	de_dbg(c, "PreviousPage: %d", (int)*prev_page);
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
	if(de_sz_has_ext(fn, "bmp")) return FILETYPE_BMP;
	return 0;
}

static void do_leaf_page(deark *c, lctx *d, de_int64 pos1, de_int64 *pnext_page)
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
	de_dbg(c, "free bytes at end of this page: %d", (int)n);
	pos += 2;

	num_entries = de_geti16le(pos);
	de_dbg(c, "NEntries: %d", (int)num_entries);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "PreviousPage: %d", (int)n);
	pos += 2;

	n = de_geti16le(pos);
	de_dbg(c, "NextPage: %d", (int)n);
	if(pnext_page) *pnext_page = n;
	pos += 2;

	s = ucstring_create(c);

	for(k=0; k<num_entries; k++) {
		de_dbg(c, "entry[%d]", (int)k);
		de_dbg_indent(c, 1);

		if(!dbuf_search_byte(c->infile, 0x00, pos, 260, &foundpos)) {
			de_err(c, "Malformed leaf page at %d", (int)pos1);
			goto done;
		}

		de_read((de_byte*)filename_raw, pos, foundpos+1-pos);
		ucstring_truncate(s, 0);
		ucstring_append_sz(s, filename_raw, DE_ENCODING_WINDOWS1252);
		de_dbg(c, "FileName: \"%s\"", ucstring_getpsz_d(s));
		pos = foundpos + 1;

		file_offset = de_geti32le(pos);
		de_dbg(c, "FileOffset: %d", (int)file_offset);
		pos += 4;

		file_type = filename_to_filetype(c, d, filename_raw);

		if((d->pass==1 && file_type==FILETYPE_SYSTEM) ||
			(d->pass==2 && file_type!=FILETYPE_SYSTEM))
		{
			do_file(c, d, file_offset, file_type);
		}

		de_dbg_indent(c, -1);

		// All we do in pass 1 is read the SYSTEM file, so we can stop if we've
		// done that.
		if(d->pass==1 && d->found_system_file) break;
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

	de_dbg(c, "looking for first leaf page");
	de_dbg_indent(c, 1);

	while(curr_level>1) {
		de_int64 prev_page;
		de_int64 page_pos;

		if(curr_page<0) goto done;
		page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

		de_dbg(c, "page %d is an index page, level=%d", (int)curr_page, (int)curr_level);

		prev_page = -1;
		de_dbg_indent(c, 1);
		do_index_page(c, d, page_pos, &prev_page);
		de_dbg_indent(c, -1);

		curr_page = prev_page;
		curr_level--;
	}

	de_dbg(c, "page %d is the first leaf page", (int)curr_page);
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
static void do_bplustree(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	int is_internaldir)
{
	de_int64 pos = pos1;
	de_int64 n;
	int saved_indent_level;
	de_byte *page_seen = NULL;

	if(!is_internaldir) return;

	de_dbg_indent_save(c, &saved_indent_level);

	n = de_getui16le(pos);
	if(n != 0x293b) {
		de_err(c, "Expected B+ tree structure at %d not found", (int)pos1);
		goto done;
	}
	pos += 2;

	//de_dbg(c, "B+ tree at %d", (int)pos1);
	de_dbg_indent(c, 1);

	d->bpt.flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x", d->bpt.flags);
	pos += 2;

	d->bpt.pagesize = de_getui16le(pos);
	de_dbg(c, "PageSize: %d", (int)d->bpt.pagesize);
	pos += 2;

	// TODO: Understand the Structure field
	pos += 16;

	pos += 2; // MustBeZero
	pos += 2; // PageSplits

	d->bpt.root_page = de_geti16le(pos);
	de_dbg(c, "RootPage: %d", (int)d->bpt.root_page);
	pos += 2;

	pos += 2; // MustBeNegOne

	d->bpt.num_pages = de_geti16le(pos);
	de_dbg(c, "TotalPages: %d", (int)d->bpt.num_pages);
	pos += 2;

	d->bpt.num_levels = de_geti16le(pos);
	de_dbg(c, "NLevels: %d", (int)d->bpt.num_levels);
	if(is_internaldir) d->internal_dir_num_levels = d->bpt.num_levels;
	pos += 2;

	d->bpt.num_entries = de_geti32le(pos);
	de_dbg(c, "TotalBtreeEntries: %d", (int)d->bpt.num_entries);
	pos += 4;

	d->bpt.pagesdata_pos = pos;
	de_dbg(c, "num pages: %d, %d bytes each, at %d (total size=%d)",
		(int)d->bpt.num_pages, (int)d->bpt.pagesize, (int)d->bpt.pagesdata_pos,
		(int)(d->bpt.num_pages * d->bpt.pagesize));

	if(!find_first_leaf_page(c, d)) goto done;

	page_seen = de_malloc(c, d->bpt.num_pages); // For loop detection

	for(d->pass=1; d->pass<=2; d->pass++) {
		de_int64 curr_page;

		de_memset(page_seen, 0, (size_t)d->bpt.num_pages);

		de_dbg(c, "pass %d", d->pass);
		de_dbg_indent(c, 1);

		curr_page = d->bpt.first_leaf_page;

		while(1) {
			de_int64 page_pos;
			de_int64 next_page;

			if(curr_page<0) break;
			if(curr_page>d->bpt.num_pages) goto done;

			if(d->pass==1 && page_seen[curr_page]) {
				de_err(c, "Page loop detected");
				goto done;
			}
			page_seen[curr_page] = 1;

			page_pos = d->bpt.pagesdata_pos + curr_page*d->bpt.pagesize;

			de_dbg(c, "page[%d] at %d (leaf page)", (int)curr_page, (int)page_pos);

			next_page = -1;
			de_dbg_indent(c, 1);
			do_leaf_page(c, d, page_pos, &next_page);
			de_dbg_indent(c, -1);

			if(d->pass==1 && d->found_system_file) {
				de_dbg(c, "[found SYSTEM file, so stopping pass 1]");
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
	de_dbg(c, "internal dir data at %d", (int)pos1);
	do_bplustree(c, d, pos1, len, 1);
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

	de_dbg(c, "file at %d, type=%s", (int)pos1, file_type_to_type_name(file_fmt));
	de_dbg_indent(c, 1);

	// FILEHEADER
	reserved_space = de_getui32le(pos);
	de_dbg(c, "ReservedSpace: %d", (int)reserved_space);
	pos += 4;

	used_space = de_getui32le(pos);
	de_dbg(c, "UsedSpace: %d", (int)used_space);
	pos += 4;

	fileflags = (unsigned int)de_getbyte(pos);
	de_dbg(c, "FileFlags: 0x%02x", fileflags);
	pos += 1;

	if(pos+used_space > c->infile->len) {
		de_err(c, "Bad file size");
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
		d->has_shg = 1;
		do_file_SHG(c, d, pos, used_space);
		break;

	case FILETYPE_BMP:
		d->has_bmp = 1;
		break;
	}

done:
	de_dbg_indent(c, -1);
}

static void do_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 n;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->internal_dir_FILEHEADER_offs = de_geti32le(4);
	de_dbg(c, "internal dir FILEHEADER pos: %d", (int)d->internal_dir_FILEHEADER_offs);

	n = de_geti32le(8);
	de_dbg(c, "FREEHEADER pos: %d", (int)n);

	n = de_geti32le(12);
	de_dbg(c, "reported file size: %d", (int)n);

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

	de_dbg(c, "summary: v%d.%d cmpr=%s blksize=%d levels=%d%s%s%s",
		d->ver_major, d->ver_minor,
		d->is_compressed?"lz77":"none",
		(int)d->topic_block_size,
		(int)d->internal_dir_num_levels,
		d->has_shg?" has-shg":"",
		d->has_ico?" has-ico":"",
		d->has_bmp?" has-bmp":"");

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
