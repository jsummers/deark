// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Compound File Binary File Format
// a.k.a. "OLE Compound Document Format", and a million other names

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_cfb);

#define OBJTYPE_EMPTY        0x00
#define OBJTYPE_STORAGE      0x01
#define OBJTYPE_STREAM       0x02
#define OBJTYPE_ROOT_STORAGE 0x05

static const char *thumbsdb_catalog_streamname = "Catalog";
static const char *summaryinformation_streamname = "\x05" "SummaryInformation";

struct dir_entry_info {
	de_byte entry_type;
	int is_mini_stream;
	de_int64 stream_size;
	de_int64 normal_sec_id; // First SecID, valid if is_mini_stream==0
	de_int64 minisec_id; // First MiniSecID, valid if is_mini_stream==1
	struct de_stringreaderdata *fname_srd;
	de_byte clsid[16];
	struct de_timestamp mod_time;
};

struct dir_entry_extra_info_struct {
	de_byte entry_type;
	de_int32 child_id;
	de_int32 sibling_id[2];
	de_int32 parent_id; // If parent_id==0, entry is in root dir.
	de_ucstring *fname; // Used by non-root STORAGE objects.
	de_ucstring *path; // Full dir path. Used by non-root STORAGE objects.
};

struct catalog_entry {
	de_uint32 id;
	de_ucstring *fname;
	struct de_timestamp mod_time;
};

typedef struct localctx_struct {
#define SUBFMT_AUTO       0
#define SUBFMT_RAW        1
#define SUBFMT_THUMBSDB   2
	int subformat_req;
	int subformat_final;
	de_int64 minor_ver, major_ver;
	de_int64 sec_size;
	//de_int64 num_dir_sectors;
	de_int64 num_fat_sectors;
	de_int64 first_dir_sec_id;
	de_int64 std_stream_min_size;
	de_int64 first_minifat_sec_id;
	de_int64 num_minifat_sectors;
	de_int64 mini_sector_size;
	de_int64 first_difat_sec_id;
	de_int64 num_difat_sectors;
	de_int64 num_fat_entries;
	de_int64 num_dir_entries;

	// The DIFAT is an array of the secIDs that contain the FAT.
	// It is stored in a linked list of sectors, except that the first
	// 109 array entries are stored in the header.
	// After that, the last 4 bytes of each sector are the SecID of the
	// sector containing the next part of the DIFAT, and the remaining
	// bytes are the payload data.
	dbuf *difat;

	// The FAT is an array of "next sectors". Given a SecID, it will tell you
	// the "next" SecID in the stream that uses that sector, or it may have
	// a special code that means "end of chain", etc.
	// All the bytes of a FAT sector are used for payload data.
	dbuf *fat;

	dbuf *minifat; // mini sector allocation table
	dbuf *dir;
	struct dir_entry_extra_info_struct *dir_entry_extra_info; // array[num_dir_entries]
	dbuf *mini_sector_stream;

	de_int64 thumbsdb_catalog_num_entries;
	struct catalog_entry *thumbsdb_catalog;

	int could_be_thumbsdb;
	int thumbsdb_old_names_found;
	int thumbsdb_new_names_found;
	int thumbsdb_catalog_found;
} lctx;

struct clsid_id_struct {
	const de_byte clsid[16];
	const char *name;
};
static const struct clsid_id_struct known_clsids[] = {
	{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, "n/a"}, // This must be first.
	{{0x00,0x02,0x08,0x10,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "Excel?" },
	{{0x00,0x02,0x08,0x20,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "Excel?" },
	{{0x00,0x02,0x09,0x06,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "MS Word?"},
	{{0x00,0x02,0x0d,0x0b,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "Outlook item?"},
	{{0x00,0x06,0xf0,0x46,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "Outlook item?"},
	{{0x00,0x0c,0x10,0x84,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}, "MSI?"},
	{{0x1c,0xdd,0x8c,0x7b,0x81,0xc0,0x45,0xa0,0x9f,0xed,0x04,0x14,0x31,0x44,0xcc,0x1e}, "3ds Max?"},
	{{0x56,0x61,0x67,0x00,0xc1,0x54,0x11,0xce,0x85,0x53,0x00,0xaa,0x00,0xa1,0xf9,0x5b}, "FlashPix?"},
	{{0x64,0x81,0x8d,0x10,0x4f,0x9b,0x11,0xcf,0x86,0xea,0x00,0xaa,0x00,0xb9,0x29,0xe8}, "PowerPoint?"}
};
#define EMPTY_CLSID (known_clsids[0].clsid)

static de_int64 sec_id_to_offset(deark *c, lctx *d, de_int64 sec_id)
{
	if(sec_id<0) return 0;
	return d->sec_size + sec_id * d->sec_size;
}

static de_int64 get_next_sec_id(deark *c, lctx *d, de_int64 cur_sec_id)
{
	de_int64 next_sec_id;

	if(cur_sec_id < 0) return -2;
	if(!d->fat) return -2;
	next_sec_id = dbuf_geti32le(d->fat, cur_sec_id*4);
	return next_sec_id;
}

static de_int64 get_next_minisec_id(deark *c, lctx *d, de_int64 cur_minisec_id)
{
	de_int64 next_minisec_id;

	if(cur_minisec_id < 0) return -2;
	if(!d->minifat) return -2;
	next_minisec_id = dbuf_geti32le(d->minifat, cur_minisec_id*4);
	return next_minisec_id;
}

static void describe_sec_id(deark *c, lctx *d, de_int64 sec_id,
	char *buf, size_t buf_len)
{
	de_int64 sec_offset;

	if(sec_id >= 0) {
		sec_offset = sec_id_to_offset(c, d, sec_id);
		de_snprintf(buf, buf_len, "offs=%d", (int)sec_offset);
	}
	else if(sec_id == -1) {
		de_strlcpy(buf, "free", buf_len);
	}
	else if(sec_id == -2) {
		de_strlcpy(buf, "end of chain", buf_len);
	}
	else if(sec_id == -3) {
		de_strlcpy(buf, "FAT SecID", buf_len);
	}
	else if(sec_id == -4) {
		de_strlcpy(buf, "DIFAT SecID", buf_len);
	}
	else {
		de_strlcpy(buf, "?", buf_len);
	}
}

// Copy a stream (with a known byte size) to a dbuf.
static void copy_normal_stream_to_dbuf(deark *c, lctx *d, de_int64 first_sec_id,
	de_int64 stream_startpos, de_int64 stream_size,
	dbuf *outf)
{
	de_int64 sec_id;
	de_int64 bytes_left_to_copy;
	de_int64 bytes_left_to_skip;

	if(stream_size<=0 || stream_size>c->infile->len) return;

	bytes_left_to_copy = stream_size;
	bytes_left_to_skip = stream_startpos;
	sec_id = first_sec_id;
	while(bytes_left_to_copy > 0) {
		de_int64 sec_offs;
		de_int64 bytes_to_copy;
		de_int64 bytes_to_skip;

		if(sec_id<0) break;
		sec_offs = sec_id_to_offset(c, d, sec_id);

		bytes_to_skip = bytes_left_to_skip;
		if(bytes_to_skip > d->sec_size) bytes_to_skip = d->sec_size;

		bytes_to_copy = d->sec_size - bytes_to_skip;
		if(bytes_to_copy > bytes_left_to_copy) bytes_to_copy = bytes_left_to_copy;

		dbuf_copy(c->infile, sec_offs + bytes_to_skip, bytes_to_copy, outf);

		bytes_left_to_copy -= bytes_to_copy;
		bytes_left_to_skip -= bytes_to_skip;
		sec_id = get_next_sec_id(c, d, sec_id);
	}
}

// Same as copy_normal_stream_to_dbuf(), but for mini streams.
static void copy_mini_stream_to_dbuf(deark *c, lctx *d, de_int64 first_minisec_id,
	de_int64 stream_startpos, de_int64 stream_size,
	dbuf *outf)
{
	de_int64 minisec_id;
	de_int64 bytes_left_to_copy;
	de_int64 bytes_left_to_skip;

	if(!d->mini_sector_stream) return;
	if(stream_size<=0 || stream_size>c->infile->len ||
		stream_size>d->mini_sector_stream->len)
	{
		return;
	}

	bytes_left_to_copy = stream_size;
	bytes_left_to_skip = stream_startpos;
	minisec_id = first_minisec_id;
	while(bytes_left_to_copy > 0) {
		de_int64 minisec_offs;
		de_int64 bytes_to_copy;
		de_int64 bytes_to_skip;

		if(minisec_id<0) break;
		minisec_offs = minisec_id * d->mini_sector_size;

		bytes_to_skip = bytes_left_to_skip;
		if(bytes_to_skip > d->mini_sector_size) bytes_to_skip = d->mini_sector_size;

		bytes_to_copy = d->mini_sector_size - bytes_to_skip;
		if(bytes_to_copy > bytes_left_to_copy) bytes_to_copy = bytes_left_to_copy;

		dbuf_copy(d->mini_sector_stream, minisec_offs + bytes_to_skip, bytes_to_copy, outf);

		bytes_left_to_copy -= bytes_to_copy;
		bytes_left_to_skip -= bytes_to_skip;
		minisec_id = get_next_minisec_id(c, d, minisec_id);
	}
}

static void copy_any_stream_to_dbuf(deark *c, lctx *d, struct dir_entry_info *dei,
	de_int64 stream_startpos, de_int64 stream_size,
	dbuf *outf)
{
	if(dei->is_mini_stream) {
		copy_mini_stream_to_dbuf(c, d, dei->minisec_id, stream_startpos, stream_size, outf);
	}
	else {
		copy_normal_stream_to_dbuf(c, d, dei->normal_sec_id, stream_startpos, stream_size, outf);
	}
}

static int do_header(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_int64 byte_order_code;
	de_int64 sector_shift;
	de_int64 mini_sector_shift;
	char buf[80];
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	// offset 0-7: signature
	// offset 8-23: CLSID

	d->minor_ver = de_getui16le(pos+24);
	d->major_ver = de_getui16le(pos+26);
	de_dbg(c, "format version: %d.%d", (int)d->major_ver, (int)d->minor_ver);
	if(d->major_ver!=3 && d->major_ver!=4) {
		de_err(c, "Unsupported format version: %d", (int)d->major_ver);
		goto done;
	}

	byte_order_code = de_getui16le(pos+28);
	if(byte_order_code != 0xfffe) {
		de_err(c, "Unsupported byte order code: 0x%04x", (unsigned int)byte_order_code);
		goto done;
	}

	sector_shift = de_getui16le(pos+30); // aka ssz
	d->sec_size = (de_int64)(1<<(unsigned int)sector_shift);
	de_dbg(c, "sector size: 2^%d (%d bytes)", (int)sector_shift,
		(int)d->sec_size);
	if(d->sec_size!=512 && d->sec_size!=4096) {
		de_err(c, "Unsupported sector size: %d", (int)d->sec_size);
		goto done;
	}

	mini_sector_shift = de_getui16le(pos+32); // aka sssz
	d->mini_sector_size = (de_int64)(1<<(unsigned int)mini_sector_shift);
	de_dbg(c, "mini sector size: 2^%d (%d bytes)", (int)mini_sector_shift,
		(int)d->mini_sector_size);
	if(d->mini_sector_size!=64) {
		de_err(c, "Unsupported mini sector size: %d", (int)d->mini_sector_size);
		goto done;
	}

	// offset 34: 6 reserved bytes

	//d->num_dir_sectors = de_getui32le(pos+40);
	//de_dbg(c, "number of directory sectors: %u", (unsigned int)d->num_dir_sectors);
	// Should be 0 if major_ver==3

	// Number of sectors used by sector allocation table (FAT)
	d->num_fat_sectors = de_getui32le(pos+44);
	de_dbg(c, "number of FAT sectors: %d", (int)d->num_fat_sectors);

	d->first_dir_sec_id = de_geti32le(pos+48);
	describe_sec_id(c, d, d->first_dir_sec_id, buf, sizeof(buf));
	de_dbg(c, "first directory sector: %d (%s)", (int)d->first_dir_sec_id, buf);

	// offset 52, transaction signature number

	d->std_stream_min_size = de_getui32le(pos+56);
	de_dbg(c, "min size of a standard stream: %d", (int)d->std_stream_min_size);

	// First sector of mini sector allocation table (MiniFAT)
	d->first_minifat_sec_id = de_geti32le(pos+60);
	describe_sec_id(c, d, d->first_minifat_sec_id, buf, sizeof(buf));
	de_dbg(c, "first MiniFAT sector: %d (%s)", (int)d->first_minifat_sec_id, buf);

	// Number of sectors used by MiniFAT
	d->num_minifat_sectors = de_getui32le(pos+64);
	de_dbg(c, "number of MiniFAT sectors: %d", (int)d->num_minifat_sectors);

	// SecID of first (extra??) sector of the DIFAT
	// (also called the Master Sector Allocation Table (MSAT))
	d->first_difat_sec_id = de_geti32le(pos+68);
	describe_sec_id(c, d, d->first_difat_sec_id, buf, sizeof(buf));
	de_dbg(c, "first extended DIFAT sector: %d (%s)", (int)d->first_difat_sec_id, buf);

	// Number of (extra??) sectors used by the DIFAT
	d->num_difat_sectors = de_getui32le(pos+72);
	de_dbg(c, "number of extended DIFAT sectors: %d", (int)d->num_difat_sectors);

	// offset 76: 436 bytes of DIFAT data
	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

// Read the locations of the FAT sectors
static void read_difat(deark *c, lctx *d)
{
	de_int64 num_to_read;
	de_int64 still_to_read;
	de_int64 difat_sec_id;
	de_int64 difat_sec_offs;


	de_dbg(c, "reading DIFAT (total number of entries=%d)", (int)d->num_fat_sectors);
	de_dbg_indent(c, 1);

	if(d->num_fat_sectors > 1000000) {
		// TODO: Decide what limits to enforce.
		d->num_fat_sectors = 1000000;
	}

	// Expecting d->num_fat_sectors in the DIFAT table
	d->difat = dbuf_create_membuf(c, d->num_fat_sectors * 4, 1);

	still_to_read = d->num_fat_sectors;

	// Copy the part of the DIFAT that is in the header
	num_to_read = still_to_read;
	if(num_to_read>109) num_to_read = 109;
	de_dbg(c, "reading %d DIFAT entries from header, at 76", (int)num_to_read);
	dbuf_copy(c->infile, 76, num_to_read*4, d->difat);
	still_to_read -= num_to_read;

	difat_sec_id = d->first_difat_sec_id;
	while(still_to_read>0) {
		if(difat_sec_id<0) break;

		difat_sec_offs = sec_id_to_offset(c, d, difat_sec_id);
		de_dbg(c, "reading DIFAT sector at %d", (int)difat_sec_offs);
		num_to_read = (d->sec_size - 4)/4;

		dbuf_copy(c->infile, difat_sec_offs, num_to_read*4, d->difat);
		still_to_read -= num_to_read;
		difat_sec_id = de_geti32le(difat_sec_offs + num_to_read*4);
	}

	de_dbg_indent(c, -1);
}

static void dump_fat(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sec_id;
	char buf[80];

	if(c->debug_level<2) return;

	de_dbg2(c, "dumping FAT contents (%d entries)", (int)d->num_fat_entries);

	de_dbg_indent(c, 1);
	for(i=0; i<d->num_fat_entries; i++) {
		sec_id = dbuf_geti32le(d->fat, i*4);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg2(c, "FAT[%d]: next_SecID=%d (%s)", (int)i, (int)sec_id, buf);
	}
	de_dbg_indent(c, -1);
}

// Read the contents of the FAT sectors
static void read_fat(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sec_id;
	de_int64 sec_offset;
	char buf[80];

	d->fat = dbuf_create_membuf(c, d->num_fat_sectors * d->sec_size, 1);

	de_dbg(c, "reading FAT contents (%d sectors)", (int)d->num_fat_sectors);
	de_dbg_indent(c, 1);
	for(i=0; i<d->num_fat_sectors; i++) {
		sec_id = dbuf_geti32le(d->difat, i*4);
		sec_offset = sec_id_to_offset(c, d, sec_id);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg(c, "reading sector: DIFAT_idx=%d, SecID=%d (%s)",
			(int)i, (int)sec_id, buf);
		dbuf_copy(c->infile, sec_offset, d->sec_size, d->fat);
	}
	de_dbg_indent(c, -1);

	d->num_fat_entries = d->fat->len/4;
	dump_fat(c, d);
}

static void dump_minifat(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sec_id;
	de_int64 num_minifat_entries;

	if(c->debug_level<2) return;
	if(!d->minifat) return;

	num_minifat_entries = d->minifat->len / 4;
	de_dbg2(c, "dumping MiniFAT contents (%d entries)", (int)num_minifat_entries);

	de_dbg_indent(c, 1);
	for(i=0; i<num_minifat_entries; i++) {
		sec_id = dbuf_geti32le(d->minifat, i*4);
		de_dbg2(c, "MiniFAT[%d]: next_MiniSecID=%d", (int)i, (int)sec_id);
	}
	de_dbg_indent(c, -1);
}

// Read the contents of the MiniFAT sectors into d->minifat
static void read_minifat(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sec_id;
	de_int64 sec_offset;
	char buf[80];

	if(d->num_minifat_sectors > 1000000) {
		// TODO: Decide what limits to enforce.
		d->num_minifat_sectors = 1000000;
	}

	d->minifat = dbuf_create_membuf(c, d->num_minifat_sectors * d->sec_size, 1);

	// TODO: Use copy_normal_stream_to_dbuf
	de_dbg(c, "reading MiniFAT contents (%d sectors)", (int)d->num_minifat_sectors);
	de_dbg_indent(c, 1);

	sec_id = d->first_minifat_sec_id;

	for(i=0; i<d->num_minifat_sectors; i++) {
		if(sec_id<0) break;

		sec_offset = sec_id_to_offset(c, d, sec_id);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg(c, "reading MiniFAT sector #%d, SecID=%d (%s), MiniSecIDs %d-%d",
			(int)i, (int)sec_id, buf,
			(int)(i*(d->sec_size/4)), (int)((i+1)*(d->sec_size/4)-1));
		dbuf_copy(c->infile, sec_offset, d->sec_size, d->minifat);

		sec_id = get_next_sec_id(c, d, sec_id);
	}
	de_dbg_indent(c, -1);

	dump_minifat(c, d);
}

// Returns -1 if not a valid name
static de_int64 stream_name_to_catalog_id(deark *c, lctx *d, struct dir_entry_info *dei)
{
	char buf[16];
	size_t nlen;
	size_t i;

	nlen = dei->fname_srd->sz_utf8_strlen;
	if(nlen>sizeof(buf)-1) return -1;

	for(i=0; i<nlen; i++) {
		// Name should contain only digits
		if(dei->fname_srd->sz_utf8[i]<'0' || dei->fname_srd->sz_utf8[i]>'9') return -1;

		// The stream name is the *reversed* string form of the ID number.
		// (I assume this is to try to keep the directory tree structure balanced.)
		buf[nlen-1-i] = dei->fname_srd->sz_utf8[i];
	}
	buf[nlen] = '\0';

	return de_atoi64(buf);
}

// Returns an index into d->thumbsdb_catalog.
// Returns -1 if not found.
static de_int64 lookup_catalog_entry(deark *c, lctx *d, struct dir_entry_info *dei)
{
	de_int64 i;
	de_int64 id;

	if(d->thumbsdb_catalog_num_entries<1 || !d->thumbsdb_catalog) return -1;
	if(!dei->fname_srd || !dei->fname_srd->str) return -1;

	id = stream_name_to_catalog_id(c, d, dei);
	if(id<0) return -1;

	for(i=0; i<d->thumbsdb_catalog_num_entries; i++) {
		if(d->thumbsdb_catalog[i].id == id)
			return i;
	}
	return -1;
}

static void extract_stream_to_file(deark *c, lctx *d, de_int64 dir_entry_idx, struct dir_entry_info *dei)
{
	de_int64 startpos;
	de_int64 final_streamsize;
	de_int64 ver;
	de_int64 reported_size;
	int saved_indent_level;
	dbuf *outf = NULL;
	dbuf *tmpdbuf = NULL;
	de_finfo *fi = NULL;
	de_ucstring *tmpfn = NULL;
	struct dir_entry_extra_info_struct *de_ei;

	de_dbg_indent_save(c, &saved_indent_level);
	startpos = 0;
	de_ei = &d->dir_entry_extra_info[dir_entry_idx];
	final_streamsize = dei->stream_size;

	// By default, use the "stream name" as the filename.
	tmpfn = ucstring_create(c);

	if(de_ei->parent_id>0 && d->dir_entry_extra_info[de_ei->parent_id].path) {
		ucstring_append_ucstring(tmpfn, d->dir_entry_extra_info[de_ei->parent_id].path);
		ucstring_append_sz(tmpfn, "/", DE_ENCODING_ASCII);
	}

	ucstring_append_ucstring(tmpfn, dei->fname_srd->str);

	fi = de_finfo_create(c);

	// By default, use the mod time from the directory entry.
	if(dei->mod_time.is_valid) {
		fi->mod_time = dei->mod_time; // struct copy
	}

	if(d->subformat_final==SUBFMT_THUMBSDB) {
		de_int64 hdrsize;
		de_int64 catalog_idx;
		const char *ext;

		// Special handling of Thumbs.db files.

		if(!de_strcmp(dei->fname_srd->sz_utf8, thumbsdb_catalog_streamname)) {
			// We've already read the catalog.
			goto done;
		}

		de_dbg(c, "reading Thumbs.db stream");
		de_dbg_indent(c, 1);

		// A Thumbs.db stream typically has a header, followed by an embedded JPEG
		// (or something) file.

		catalog_idx = lookup_catalog_entry(c, d, dei);

		if(catalog_idx>=0) {
			if(d->thumbsdb_catalog[catalog_idx].mod_time.is_valid) {
				fi->mod_time = d->thumbsdb_catalog[catalog_idx].mod_time; // struct copy
			}
		}

		// Read the first part of the stream. 32 bytes should be enough to get
		// the header, and enough of the payload to choose a file extension.
		tmpdbuf = dbuf_create_membuf(c, 64, 0);
		copy_any_stream_to_dbuf(c, d, dei, 0, 64, tmpdbuf);

		hdrsize = dbuf_getui32le(tmpdbuf, 0);
		de_dbg(c, "header size: %d", (int)hdrsize);

		ver = dbuf_getui32le(tmpdbuf, 4);
		de_dbg(c, "version: %d", (int)ver);

		// 0x0c = "Original format" Thumbs.db
		// 0x18 = "Windows 7 format"

		if((hdrsize==0x0c || hdrsize==0x18) && dei->stream_size>hdrsize) {
			de_byte sig1[4];
			de_byte sig2[4];

			reported_size = dbuf_getui32le(tmpdbuf, 8);
			de_dbg(c, "reported size: %d", (int)reported_size);

			startpos = hdrsize;
			final_streamsize -= hdrsize;
			de_dbg(c, "calculated size: %d", (int)final_streamsize);

			if(catalog_idx>=0 && c->filenames_from_file) {
				de_dbg(c, "name from catalog: \"%s\"",
					ucstring_getpsz(d->thumbsdb_catalog[catalog_idx].fname));

				// Replace the default name with the name from the catalog.
				ucstring_empty(tmpfn);
				ucstring_append_ucstring(tmpfn, d->thumbsdb_catalog[catalog_idx].fname);
			}

			dbuf_read(tmpdbuf, sig1, hdrsize, 4);
			dbuf_read(tmpdbuf, sig2, hdrsize+16, 4);

			if(sig1[0]==0xff && sig1[1]==0xd8) ext = "jpg";
			else if(sig1[0]==0x89 && sig1[1]==0x50) ext = "png";
			else if(sig1[0]==0x01 && sig1[1]==0x00 &&
				sig2[0]==0xff && sig2[1]==0xd8)
			{
				// Looks like a nonstandard Microsoft RGBA JPEG.
				// These seem to have an additional 16-byte header, before the
				// JPEG data starts. I'm not sure if I should keep it, but it
				// doesn't look like it contains any vital information, so
				// I'll strip if off.
				ext = "msrgbajpg";
				startpos += 16;
				final_streamsize -= 16;
			}
			else ext = "bin";

			ucstring_printf(tmpfn, DE_ENCODING_ASCII, ".thumb.%s", ext);
		}
		else {
			de_warn(c, "Unidentified Thumbs.db stream \"%s\"",
				ucstring_getpsz(dei->fname_srd->str));
		}

		de_dbg_indent(c, -1);
	}

	de_finfo_set_name_from_ucstring(c, fi, tmpfn);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	copy_any_stream_to_dbuf(c, d, dei, startpos, final_streamsize, outf);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(tmpdbuf);
	dbuf_close(outf);
	ucstring_destroy(tmpfn);
	de_finfo_destroy(c, fi);
}

static void read_timestamp(deark *c, lctx *d, dbuf *f, de_int64 pos,
	struct de_timestamp *ts, const char *field_name)
{
	de_int64 ts_as_FILETIME;
	char timestamp_buf[64];

	de_memset(ts, 0, sizeof(struct de_timestamp));
	ts_as_FILETIME = dbuf_geti64le(f, pos);
	if(ts_as_FILETIME!=0) {
		de_FILETIME_to_timestamp(ts_as_FILETIME, ts);
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 1);
		de_dbg(c, "%s: %s", field_name, timestamp_buf);
	}
}

static int read_thumbsdb_catalog(deark *c, lctx *d, struct dir_entry_info *dei)
{
	de_int64 item_len;
	de_int64 n;
	de_int64 i;
	de_int64 pos;
	int retval = 0;
	dbuf *catf = NULL;

	if(d->thumbsdb_catalog) return 0; // Already read a catalog

	de_dbg(c, "reading thumbsdb catalog");
	de_dbg_indent(c, 1);

	catf = dbuf_create_membuf(c, dei->stream_size, 0);
	copy_any_stream_to_dbuf(c, d, dei, 0, dei->stream_size, catf);

	item_len = dbuf_getui16le(catf, 0);
	de_dbg(c, "header size: %d", (int)item_len); // (?)
	if(item_len!=16) goto done;

	n = dbuf_getui16le(catf, 2);
	de_dbg(c, "catalog version: %d", (int)n); // (?)
	if(n!=5 && n!=6 && n!=7) {
		de_warn(c, "Unsupported Catalog version: %d", (int)n);
		goto done;
	}

	d->thumbsdb_catalog_num_entries = dbuf_getui16le(catf, 4); // This might really be a 4 byte int.
	de_dbg(c, "num entries: %d", (int)d->thumbsdb_catalog_num_entries);
	if(d->thumbsdb_catalog_num_entries>2048)
		d->thumbsdb_catalog_num_entries = 2048;

	d->thumbsdb_catalog = de_malloc(c, d->thumbsdb_catalog_num_entries * sizeof(struct catalog_entry));

	pos = item_len;

	for(i=0; i<d->thumbsdb_catalog_num_entries; i++) {
		if(pos >= catf->len) goto done;
		item_len = dbuf_getui32le(catf, pos);
		de_dbg(c, "catalog entry #%d, len=%d", (int)i, (int)item_len);
		if(item_len<20) goto done;

		de_dbg_indent(c, 1);

		d->thumbsdb_catalog[i].id = (de_uint32)dbuf_getui32le(catf, pos+4);
		de_dbg(c, "id: %u", (unsigned int)d->thumbsdb_catalog[i].id);

		read_timestamp(c, d, catf, pos+8, &d->thumbsdb_catalog[i].mod_time, "timestamp");

		d->thumbsdb_catalog[i].fname = ucstring_create(c);

		dbuf_read_to_ucstring(catf, pos+16, item_len-20, d->thumbsdb_catalog[i].fname,
			0, DE_ENCODING_UTF16LE);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz(d->thumbsdb_catalog[i].fname));

		de_dbg_indent(c, -1);

		pos += item_len;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	dbuf_close(catf);
	if(!retval) {
		d->thumbsdb_catalog_num_entries = 0; // Make sure we don't use a bad catalog.
	}
	return retval;
}

struct summaryinfo_struct {
	dbuf *f; // The full data stream
	de_int64 tbloffset;
	int encoding;
};

struct prop_info_struct {
	de_int64 type;
	const char *name;
	de_int64 data_offs;
	de_int64 data_type;
};

// Sets pinfo->name based on pinfo->type.
static void get_prop_name(deark *c, lctx *d, struct prop_info_struct *pinfo)
{
#define PINFO_EDITING_TIME 10
	static const char *names[20] = {
		"", "Code page", "Title", "Subject",
		"Author", "Keywords", "Comments", "Template",
		"Last saved by", "Revision number", "Editing time", "Last printed",
		"Create time", "Saved time", "Number of pages", "Number of words",
		"Number of chars", "Thumbnail", "App name", "Security" };

	if(pinfo->type>=1 && pinfo->type<=19) {
		pinfo->name = names[pinfo->type];
	}
	else {
		pinfo->name = "?";
	}
}

static void do_prop_clipboard(deark *c, lctx *d, struct summaryinfo_struct *si,
	struct prop_info_struct *pinfo)
{
	de_uint32 cbtype;
	de_int64 cbsize_reported;
	de_int64 cbsize_payload;
	de_int64 cbdatapos;

	cbsize_reported = dbuf_getui32le(si->f, si->tbloffset+pinfo->data_offs+4);
	de_dbg(c, "clipboard data size: %d", (int)cbsize_reported);

	cbtype = (de_uint32)dbuf_getui32le(si->f, si->tbloffset+pinfo->data_offs+12);
	de_dbg(c, "clipboard data type: 0x%08x", (unsigned int)cbtype);

	cbdatapos = si->tbloffset+pinfo->data_offs+16;
	cbsize_payload = cbsize_reported-8;
	if(cbdatapos + cbsize_payload > si->f->len) goto done;

	if(cbtype==3) { // CF_METAFILEPICT
		dbuf_create_file_from_slice(si->f, cbdatapos+8, cbsize_payload-8,
			"wmf", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(cbtype==8) { // CF_DIB
		de_run_module_by_id_on_slice2(c, "dib", "X", si->f,
			cbdatapos, cbsize_payload);
	}
	else if(cbtype==0x54434950U) { // "PICT"
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "pict", NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_write_zeroes(outf, 512);
		dbuf_copy(si->f, cbdatapos, cbsize_payload, outf);
		dbuf_close(outf);
	}

done:
	;
}

static int do_prop_FILETIME(deark *c, lctx *d, struct summaryinfo_struct *si,
	struct prop_info_struct *pinfo)
{
	struct de_timestamp ts;

	if(pinfo->type==PINFO_EDITING_TIME) {
		// The "Editing time" property typically has a data type of FILETIME,
		// but it is not actually a FILETIME (I assume it's an *amount* of time).
		return 0;
	}

	read_timestamp(c, d, si->f, si->tbloffset+pinfo->data_offs+4, &ts, pinfo->name);
	return 1;
}

// Read the value for one property.
static void do_prop_data(deark *c, lctx *d, struct summaryinfo_struct *si,
	struct prop_info_struct *pinfo)
{
	de_int64 n;
	de_ucstring *s = NULL;

	pinfo->data_type = dbuf_getui32le(si->f, si->tbloffset+pinfo->data_offs);

	switch(pinfo->data_type) {
	case 0x02: // int16
		n = dbuf_geti16le(si->f, si->tbloffset+pinfo->data_offs+4);
		de_dbg(c, "%s: %d", pinfo->name, (int)n);

		if(pinfo->type==0x01) { // code page
			// I've seen some files in which the Code Page property appears
			// *after* some string properties. I don't know how to interpret
			// that, but for now, I'm not going to apply it retroactively.

			// AFAICT this is a *signed* 16-bit int, which means the maximum
			// value is 32767, even though code pages can go up to 65535.
			// Apparently, code pages over 32767 are stored as negative numbers.
			switch(n) {
			case 1252: si->encoding = DE_ENCODING_WINDOWS1252; break;
			case 10000: si->encoding = DE_ENCODING_MACROMAN; break;
			case -535: si->encoding = DE_ENCODING_UTF8; break;
			default: si->encoding = DE_ENCODING_ASCII;
			}
		}

		break;
	case 0x03: // int32
		n = dbuf_geti32le(si->f, si->tbloffset+pinfo->data_offs+4);
		de_dbg(c, "%s: %d", pinfo->name, (int)n);
		break;
	case 0x1e: // string with length prefix
		s = ucstring_create(c);
		n = dbuf_geti32le(si->f, si->tbloffset+pinfo->data_offs+4);
		dbuf_read_to_ucstring_n(si->f, si->tbloffset+pinfo->data_offs+8, n, DE_DBG_MAX_STRLEN, s,
			DE_CONVFLAG_STOP_AT_NUL, si->encoding);
		de_dbg(c, "%s: \"%s\"", pinfo->name, ucstring_getpsz(s));
		break;
	case 0x40:
		do_prop_FILETIME(c, d, si, pinfo);
		break;
	case 0x47:
		do_prop_clipboard(c, d, si, pinfo);
		break;
	default:
		de_dbg(c, "[data type 0x%04x not supported]", (unsigned int)pinfo->data_type);
	}

	ucstring_destroy(s);
}

static void do_SummaryInformation(deark *c, lctx *d, struct dir_entry_info *dei, int is_root)
{
	struct summaryinfo_struct si;
	de_int64 n;
	de_int64 nproperties;
	int saved_indent_level;
	struct prop_info_struct pinfo;
	int i;

	de_memset(&si, 0, sizeof(struct summaryinfo_struct));
	si.encoding = DE_ENCODING_ASCII;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "SummaryInformation (%s)", is_root?"root":"non-root");
	de_dbg_indent(c, 1);
	if(dei->stream_size>1000000) goto done;

	si.f = dbuf_create_membuf(c, dei->stream_size, 1);
	copy_any_stream_to_dbuf(c, d, dei, 0, dei->stream_size, si.f);

	// expecting 48 (or more?) bytes of header info.
	n = dbuf_getui16le(si.f, 0);
	de_dbg(c, "byte order code: 0x%04x", (unsigned int)n);
	if(n != 0xfffe) goto done;
	n = dbuf_getui16le(si.f, 4);
	de_dbg(c, "OS ver: 0x%04x", (unsigned int)n);
	n = dbuf_getui16le(si.f, 6);
	de_dbg(c, "OS: 0x%04x", (unsigned int)n);

	si.tbloffset = dbuf_getui32le(si.f, 44);
	de_dbg(c, "table offset: %d", (int)si.tbloffset);

	// I think this is the length of the data section
	n = dbuf_getui32le(si.f, si.tbloffset);
	de_dbg(c, "property data length: %d", (int)n);

	nproperties = dbuf_getui32le(si.f, si.tbloffset+4);
	de_dbg(c, "number of properties: %d", (int)nproperties);
	if(nproperties>200) goto done;

	for(i=0; i<nproperties; i++) {
		de_memset(&pinfo, 0, sizeof(struct prop_info_struct));

		pinfo.type = dbuf_getui32le(si.f, si.tbloffset+8 + 8*i);
		pinfo.data_offs = dbuf_getui32le(si.f, si.tbloffset+8 + 8*i + 4);
		get_prop_name(c, d, &pinfo);

		de_dbg(c, "prop[%d]: type=0x%04x (%s), data_offs=%d", (int)i,
			(unsigned int)pinfo.type, pinfo.name,
			(int)pinfo.data_offs);
		de_dbg_indent(c, 1);
		do_prop_data(c, d, &si, &pinfo);
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(si.f);
}

static void read_mini_sector_stream(deark *c, lctx *d, de_int64 first_sec_id, de_int64 stream_size)
{
	if(d->mini_sector_stream) return; // Already done

	de_dbg(c, "reading mini sector stream (%d bytes)", (int)stream_size);
	d->mini_sector_stream = dbuf_create_membuf(c, 0, 0);
	copy_normal_stream_to_dbuf(c, d, first_sec_id, 0, stream_size, d->mini_sector_stream);
}

// Reads the directory stream into d->dir, and sets d->num_dir_entries.
static void read_directory_stream(deark *c, lctx *d)
{
	de_int64 dir_sec_id;
	de_int64 dir_sector_offs;
	de_int64 num_entries_per_sector;
	de_int64 dir_sector_count = 0;

	de_dbg(c, "reading directory stream");
	de_dbg_indent(c, 1);

	d->dir = dbuf_create_membuf(c, 0, 0);

	dir_sec_id = d->first_dir_sec_id;

	num_entries_per_sector = d->sec_size / 128;
	d->num_dir_entries = 0;

	// TODO: Use copy_normal_stream_to_dbuf
	while(1) {
		if(dir_sec_id<0) break;
		if(d->dir->len > c->infile->len) break;

		dir_sector_offs = sec_id_to_offset(c, d, dir_sec_id);

		de_dbg(c, "directory sector #%d SecID=%d (offs=%d), entries %d-%d",
			(int)dir_sector_count,
			(int)dir_sec_id, (int)dir_sector_offs,
			(int)d->num_dir_entries, (int)(d->num_dir_entries + num_entries_per_sector - 1));

		dbuf_copy(c->infile, dir_sector_offs, d->sec_size, d->dir);

		d->num_dir_entries += num_entries_per_sector;

		dir_sec_id = get_next_sec_id(c, d, dir_sec_id);
		dir_sector_count++;
	}

	de_dbg(c, "number of directory entries: %d", (int)d->num_dir_entries);

	de_dbg_indent(c, -1);
}

static void do_init_format_detection(deark *c, lctx *d)
{
	if(d->subformat_req!=SUBFMT_AUTO) return;
	d->could_be_thumbsdb = 1;
}

static void do_finalize_format_detection(deark *c, lctx *d)
{
	d->subformat_final = SUBFMT_RAW; // default

	if(d->subformat_req!=SUBFMT_AUTO) {
		d->subformat_final = d->subformat_req;
		goto done;
	}

	if(!d->could_be_thumbsdb) goto done;

	if(d->thumbsdb_old_names_found>0 && !d->thumbsdb_catalog_found)
	{
		d->could_be_thumbsdb = 0;
	}
	else if(d->thumbsdb_old_names_found + d->thumbsdb_new_names_found +
		d->thumbsdb_catalog_found < 1)
	{
		d->could_be_thumbsdb = 0;
	}

	if(d->could_be_thumbsdb) {
		d->subformat_final = SUBFMT_THUMBSDB;
	}

done:
	switch(d->subformat_final) {
	case SUBFMT_THUMBSDB:
		de_declare_fmt(c, "Thumbs.db");
		break;
	}
}

#if 0
static void do_dump_dir_structure(deark *c, lctx *d)
{
	de_int64 i;
	for(i=0; i<d->num_dir_entries; i++) {
		de_dbg(c, "[%d] t=%d p=%d c=%d s=%d,%d", (int)i,
			(int)d->dir_entry_extra_info[i].entry_type,
			(int)d->dir_entry_extra_info[i].parent_id,
			(int)d->dir_entry_extra_info[i].child_id,
			(int)d->dir_entry_extra_info[i].sibling_id[0],
			(int)d->dir_entry_extra_info[i].sibling_id[1]);
		if(d->dir_entry_extra_info[i].fname) {
			de_dbg(c, "  fname: \"%s\"",
				ucstring_getpsz(d->dir_entry_extra_info[i].fname));
		}
		if(d->dir_entry_extra_info[i].path) {
			de_dbg(c, "  path: \"%s\"",
				ucstring_getpsz(d->dir_entry_extra_info[i].path));
		}
	}
}
#endif

static void do_mark_dir_entries_recursively(deark *c, lctx *d, de_int32 parent_id,
	de_int32 dir_entry_idx, int level)
{
	struct dir_entry_extra_info_struct *e;
	int k;

	if(dir_entry_idx<0 || (de_int64)dir_entry_idx>=d->num_dir_entries) return;

	e = &d->dir_entry_extra_info[dir_entry_idx];

	if(e->entry_type!=OBJTYPE_STORAGE && e->entry_type!=OBJTYPE_STREAM) return;

	e->parent_id = parent_id;

	if(e->entry_type==OBJTYPE_STORAGE && e->fname && !e->path) {
		// Set the full pathname
		e->path = ucstring_create(c);
		if(parent_id>0 && d->dir_entry_extra_info[parent_id].path) {
			ucstring_append_ucstring(e->path, d->dir_entry_extra_info[parent_id].path);
			ucstring_append_sz(e->path, "/", DE_ENCODING_ASCII);
		}
		ucstring_append_ucstring(e->path, e->fname);
	}

	if(level>50) return;
	for(k=0; k<2; k++) {
		do_mark_dir_entries_recursively(c, d, parent_id, e->sibling_id[k], level+1);
	}

	if(e->entry_type==OBJTYPE_STORAGE) {
		// This is a "subdirectory" entry, so examine its children (starting with the
		// one that we know about).
		do_mark_dir_entries_recursively(c, d, dir_entry_idx, e->child_id, level+1);
	}
}

// Figure out which entries are in the root directory.
static void do_analyze_dir_structure(deark *c, lctx *d)
{
	//do_dump_dir_structure(c, d);

	if(d->num_dir_entries<1) goto done;

	// The first entry should be the root entry.
	if(d->dir_entry_extra_info[0].entry_type!=OBJTYPE_ROOT_STORAGE) goto done;

	// Its child is one of the entries in the root directory. Start with it.
	do_mark_dir_entries_recursively(c, d, 0, d->dir_entry_extra_info[0].child_id, 0);

	//do_dump_dir_structure(c, d);
done:
	;
}

// Things to do after we've read the directory stream into memory, and
// know how many entries there are.
static void do_before_pass_1(deark *c, lctx *d)
{
	de_int64 i;

	// Stores some extra information for each directory entry, and a copy of
	// some information for convenience.
	// (The original entry is still available at d->dir[128*n].)
	d->dir_entry_extra_info = de_malloc(c, d->num_dir_entries * sizeof(struct dir_entry_extra_info_struct));

	// Set defaults for each entry
	for(i=0; i<d->num_dir_entries; i++) {
		d->dir_entry_extra_info[i].child_id = -1;
		d->dir_entry_extra_info[i].sibling_id[0] = -1;
		d->dir_entry_extra_info[i].sibling_id[1] = -1;
	}
}

static void do_after_pass_1(deark *c, lctx *d)
{
	do_analyze_dir_structure(c, d);
	do_finalize_format_detection(c, d);
}

static int is_thumbsdb_orig_name(deark *c, lctx *d, const char *name, size_t nlen)
{
	size_t i;

	if(nlen<1 || nlen>6) return 0;
	for(i=0; i<nlen; i++) {
		if(name[i]<'0' || name[i]>'9') return 0;
	}
	return 1;
}

static int is_thumbsdb_new_name(deark *c, lctx *d, const char *name, size_t nlen)
{
	size_t i;
	int count1 = 0;
	int found_underscore = 0;
	int count2 = 0;

	if(nlen<4 || nlen>22) return 0;
	for(i=0; i<nlen; i++) {
		if(!found_underscore && name[i]=='_') {
			found_underscore = 1;
		}
		else if(!found_underscore) {
			// pre-underscore (pixel dimension)
			if(name[i]>='0' && name[i]<='9')
				count1++;
			else
				return 0;
		}
		else {
			// post-underscore (hash?)
			if((name[i]>='0' && name[i]<='9') ||
				(name[i]>='a' && name[i]<='f'))
			{
				count2++;
			}
			else
			{
				return 0;
			}
		}
	}
	if(!found_underscore) return 0;
	if(count1<1 || count1>5) return 0;
	if(count2<1 || count2>16) return 0;
	return 1;
}

static void do_per_dir_entry_format_detection(deark *c, lctx *d, struct dir_entry_info *dei)
{
	size_t nlen;

	if(d->subformat_req!=SUBFMT_AUTO) return;
	if(!d->could_be_thumbsdb) return;

	if(dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		if(de_memcmp(dei->clsid, EMPTY_CLSID, 16)) {
			d->could_be_thumbsdb = 0;
			return;
		}
	}

	if(dei->entry_type==OBJTYPE_STORAGE) {
		// Thumbs.db files aren't expected to have any Storage objects.
		d->could_be_thumbsdb = 0;
		return;
	}
	if(dei->entry_type!=OBJTYPE_STREAM) {
		return;
	}

	nlen = dei->fname_srd->sz_utf8_strlen;
	if(nlen<1 || nlen>21) {
		d->could_be_thumbsdb = 0;
		return;
	}

	if(!de_strcmp(dei->fname_srd->sz_utf8, thumbsdb_catalog_streamname)) {
		d->thumbsdb_catalog_found++;
		return;
	}

	if(is_thumbsdb_orig_name(c, d, dei->fname_srd->sz_utf8, nlen)) {
		d->thumbsdb_old_names_found++;
		return;
	}

	if(is_thumbsdb_new_name(c, d, dei->fname_srd->sz_utf8, nlen)) {
		d->thumbsdb_new_names_found++;
		return;
	}
}

// Caller supplies and initializes buf
static void identify_clsid(deark *c, lctx *d, const de_byte *clsid, char *buf, size_t buflen)
{
	const char *name = NULL;
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(known_clsids); k++) {
		if(!de_memcmp(clsid, known_clsids[k].clsid, 16)) {
			name = known_clsids[k].name;
			break;
		}
	}
	if(!name) return; // Not found

	de_snprintf(buf, buflen, " (%s)", name);
}

// Read and process a directory entry from the d->dir stream
static void do_dir_entry(deark *c, lctx *d, de_int64 dir_entry_idx, de_int64 dir_entry_offs,
	int pass)
{
	de_int64 name_len_raw;
	de_int64 name_len_bytes;
	de_int64 raw_sec_id;
	struct dir_entry_info *dei = NULL;
	int is_thumbsdb_catalog = 0;
	const char *tname;
	de_int64 node_color;
	char clsid_string[50];
	char buf[80];

	dei = de_malloc(c, sizeof(struct dir_entry_info));

	dei->entry_type = dbuf_getbyte(d->dir, dir_entry_offs+66);
	switch(dei->entry_type) {
	case OBJTYPE_EMPTY: tname="empty"; break;
	case OBJTYPE_STORAGE: tname="storage object"; break;
	case OBJTYPE_STREAM: tname="stream"; break;
	case OBJTYPE_ROOT_STORAGE: tname="root storage object"; break;
	default: tname="?";
	}
	de_dbg(c, "type: 0x%02x (%s)", (unsigned int)dei->entry_type, tname);

	if(pass==1) d->dir_entry_extra_info[dir_entry_idx].entry_type = dei->entry_type;

	if(dei->entry_type==OBJTYPE_EMPTY) goto done;

	if(pass==2 && dei->entry_type==OBJTYPE_ROOT_STORAGE) goto done;

	name_len_raw = dbuf_getui16le(d->dir, dir_entry_offs+64);
	de_dbg2(c, "name len: %d bytes", (int)name_len_raw);
	name_len_bytes = name_len_raw-2; // Ignore the trailing U+0000
	if(name_len_bytes<0) name_len_bytes = 0;

	dei->fname_srd = dbuf_read_string(d->dir, dir_entry_offs, name_len_bytes, name_len_bytes,
		DE_CONVFLAG_WANT_UTF8, DE_ENCODING_UTF16LE);

	de_dbg(c, "name: \"%s\"", ucstring_getpsz(dei->fname_srd->str));
	if(pass==1 && dei->entry_type==OBJTYPE_STORAGE &&
		!d->dir_entry_extra_info[dir_entry_idx].fname)
	{
		// Save a copy of directory names, so we can construct the path later.
		d->dir_entry_extra_info[dir_entry_idx].fname = ucstring_clone(dei->fname_srd->str);
	}

	if(pass==2) {
		de_dbg(c, "parent: %d",
			(int)d->dir_entry_extra_info[dir_entry_idx].parent_id);
	}

	node_color = dbuf_getbyte(d->dir, dir_entry_offs+67);
	de_dbg(c, "node color: %u", (unsigned int)node_color);

	if(dei->entry_type==OBJTYPE_STORAGE || dei->entry_type==OBJTYPE_STREAM) {
		de_int32 sibling_id[2];
		sibling_id[0] = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+68);
		sibling_id[1] = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+72);
		de_dbg(c, "sibling StreamIDs: %d, %d", (int)sibling_id[0], (int)sibling_id[1]);
		if(pass==1) {
			d->dir_entry_extra_info[dir_entry_idx].sibling_id[0] = sibling_id[0];
			d->dir_entry_extra_info[dir_entry_idx].sibling_id[1] = sibling_id[1];
		}
	}

	if(dei->entry_type==OBJTYPE_STORAGE || dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		de_int32 child_id;
		child_id = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+76);
		de_dbg(c, "child StreamID: %d", (int)child_id);
		if(pass==1) d->dir_entry_extra_info[dir_entry_idx].child_id = child_id;
	}

	if(dei->entry_type==OBJTYPE_STORAGE || dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		dbuf_read(d->dir, dei->clsid, dir_entry_offs+80, 16);
		de_fmtutil_guid_to_uuid(dei->clsid);

		buf[0] = '\0';
		if(dei->entry_type==OBJTYPE_ROOT_STORAGE) {
			identify_clsid(c, d, dei->clsid, buf, sizeof(buf));
		}

		de_fmtutil_render_uuid(c, dei->clsid, clsid_string, sizeof(clsid_string));
		de_dbg(c, "%sclsid: {%s}%s", (dei->entry_type==OBJTYPE_ROOT_STORAGE)?"root ":"",
			clsid_string, buf);
	}

	read_timestamp(c, d, d->dir, dir_entry_offs+108, &dei->mod_time, "mod time");

	raw_sec_id = dbuf_geti32le(d->dir, dir_entry_offs+116);

	if(d->major_ver<=3) {
		dei->stream_size = dbuf_getui32le(d->dir, dir_entry_offs+120);
	}
	else {
		dei->stream_size = dbuf_geti64le(d->dir, dir_entry_offs+120);
	}

	de_dbg(c, "stream size: %"INT64_FMT"", dei->stream_size);
	dei->is_mini_stream = (dei->entry_type==OBJTYPE_STREAM) && (dei->stream_size < d->std_stream_min_size);

	if(dei->is_mini_stream) {
		dei->minisec_id = raw_sec_id;
		de_dbg(c, "first MiniSecID: %d", (int)dei->minisec_id);
	}
	else {
		dei->normal_sec_id = raw_sec_id;
		describe_sec_id(c, d, dei->normal_sec_id, buf, sizeof(buf));
		de_dbg(c, "first SecID: %d (%s)", (int)dei->normal_sec_id, buf);
	}

	if(pass==1) {
		do_per_dir_entry_format_detection(c, d, dei);
	}

	if((d->subformat_req==SUBFMT_THUMBSDB || d->subformat_req==SUBFMT_AUTO) &&
		!de_strcmp(dei->fname_srd->sz_utf8, thumbsdb_catalog_streamname))
	{
		is_thumbsdb_catalog = 1;
	}

	if(pass==2 && dei->entry_type==OBJTYPE_STREAM) {
		extract_stream_to_file(c, d, dir_entry_idx, dei);

		// It's against our ground rules to both extract a file, and also analyze it,
		// but there's no good alternative in this case.

		if(!de_strcmp(dei->fname_srd->sz_utf8, summaryinformation_streamname)) {
			do_SummaryInformation(c, d, dei, (d->dir_entry_extra_info[dir_entry_idx].parent_id==0));
		}
	}
	else if(pass==1 && is_thumbsdb_catalog) {
		read_thumbsdb_catalog(c, d, dei);
	}
	else if(pass==1 && dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		read_mini_sector_stream(c, d, dei->normal_sec_id, dei->stream_size);
	}

done:
	if(dei) {
		de_destroy_stringreaderdata(c, dei->fname_srd);
		de_free(c, dei);
	}
}

// Pass 1: Detect the file format, and read the mini sector stream.
// Pass 2: Extract files.
static void do_directory(deark *c, lctx *d, int pass)
{
	de_int64 dir_entry_offs; // Offset in d->dir
	de_int64 i;

	de_dbg(c, "scanning directory, pass %d", pass);
	de_dbg_indent(c, 1);

	for(i=0; i<d->num_dir_entries; i++) {
		dir_entry_offs = 128*i;
		de_dbg(c, "directory entry, StreamID=%d", (int)i);

		de_dbg_indent(c, 1);
		do_dir_entry(c, d, i, dir_entry_offs, pass);
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static void de_run_cfb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *cfbfmt_opt;

	d = de_malloc(c, sizeof(lctx));

	cfbfmt_opt = de_get_ext_option(c, "cfb:fmt");
	if(cfbfmt_opt) {
		if(!de_strcmp(cfbfmt_opt, "auto")) {
			d->subformat_req = SUBFMT_AUTO;
		}
		else if(!de_strcmp(cfbfmt_opt, "thumbsdb")) {
			d->subformat_req = SUBFMT_THUMBSDB;
		}
		else { // "raw"
			d->subformat_req = SUBFMT_RAW;
		}
	}

	do_init_format_detection(c, d);

	if(!do_header(c, d)) {
		goto done;
	}

	read_difat(c, d);

	read_fat(c, d);

	read_minifat(c, d);

	read_directory_stream(c, d);

	do_before_pass_1(c, d);

	do_directory(c, d, 1);

	do_after_pass_1(c, d);

	do_directory(c, d, 2);

done:
	if(d) {
		dbuf_close(d->difat);
		dbuf_close(d->fat);
		dbuf_close(d->minifat);
		dbuf_close(d->dir);
		if(d->dir_entry_extra_info) {
			de_int64 k;
			for(k=0; k<d->num_dir_entries; k++) {
				ucstring_destroy(d->dir_entry_extra_info[k].fname);
				ucstring_destroy(d->dir_entry_extra_info[k].path);
			}
			de_free(c, d->dir_entry_extra_info);
		}
		dbuf_close(d->mini_sector_stream);
		if(d->thumbsdb_catalog) {
			de_int64 k;
			for(k=0; k<d->thumbsdb_catalog_num_entries; k++) {
				ucstring_destroy(d->thumbsdb_catalog[k].fname);
			}
			de_free(c, d->thumbsdb_catalog);
			d->thumbsdb_catalog = NULL;
		}
		de_free(c, d);
	}
}

static int de_identify_cfb(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8))
		return 100;
	return 0;
}

static void de_help_cfb(deark *c)
{
	de_msg(c, "-opt cfb:fmt=raw : Do not try to detect the document type");
	de_msg(c, "-opt cfb:fmt=thumbsdb : Assume Thumbs.db format");
}

void de_module_cfb(deark *c, struct deark_module_info *mi)
{
	mi->id = "cfb";
	mi->desc = "Microsoft Compound File Binary File";
	mi->run_fn = de_run_cfb;
	mi->identify_fn = de_identify_cfb;
	mi->help_fn = de_help_cfb;
}
