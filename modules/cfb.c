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

struct dir_entry_info {
	de_byte entry_type;

	int is_mini_stream;
	de_int64 stream_size;
	de_int64 normal_sec_id; // First SecID, valid if is_mini_stream==0
	de_int64 minisec_id; // First MiniSecID, valid if is_mini_stream==1
	struct de_stringreaderdata *fname_srd;
	de_byte clsid[16];
	struct de_timestamp mod_time;

	const char *entry_type_name;
	de_int64 name_len_raw;
	de_byte node_color;

	de_int32 child_id;
	de_int32 sibling_id[2];
	de_int32 parent_id; // If parent_id==0, entry is in root dir.
	de_ucstring *path; // Full dir path. Used by non-root STORAGE objects.

	de_byte is_thumbsdb_catalog;
};

struct thumbsdb_catalog_entry {
	de_uint32 id;
	struct de_stringreaderdata *fname_srd;
	struct de_timestamp mod_time;
};

typedef struct localctx_struct {
#define SUBFMT_AUTO       0
#define SUBFMT_RAW        1
#define SUBFMT_THUMBSDB   2
#define SUBFMT_TIFF37680  3
	int subformat_req;
	int subformat_final;
	int extract_raw_streams;
	int decode_streams;
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
	struct dir_entry_info *dir_entry; // array[num_dir_entries]
	dbuf *mini_sector_stream;

	de_int64 thumbsdb_catalog_num_entries;
	struct thumbsdb_catalog_entry *thumbsdb_catalog;

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
	{{0x00,0x02,0x12,0x01,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x46}, "MS Publisher?" },
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
static de_int64 lookup_thumbsdb_catalog_entry(deark *c, lctx *d, struct dir_entry_info *dei)
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

// Special handling of Thumbs.db files.
// Caller sets fi and tmpfn to default values. This function may modify them.
// firstpart = caller-supplied dbuf containing the first 256 or so bytes of the stream
static void do_extract_stream_to_file_thumbsdb(deark *c, lctx *d, struct dir_entry_info *dei,
	de_finfo *fi, de_ucstring *tmpfn, dbuf *firstpart)
{
	de_int64 hdrsize;
	de_int64 catalog_idx;
	const char *ext;
	dbuf *outf = NULL;
	de_int64 ver;
	de_int64 reported_size;
	de_int64 startpos;
	de_int64 final_streamsize;

	if(dei->is_thumbsdb_catalog) {
		// We've already read the catalog.
		goto done;
	}

	de_dbg(c, "reading Thumbs.db stream");
	de_dbg_indent(c, 1);

	startpos = 0;
	final_streamsize = dei->stream_size;

	// A Thumbs.db stream typically has a header, followed by an embedded JPEG
	// (or something) file.

	catalog_idx = lookup_thumbsdb_catalog_entry(c, d, dei);

	if(catalog_idx>=0) {
		if(d->thumbsdb_catalog[catalog_idx].mod_time.is_valid) {
			fi->mod_time = d->thumbsdb_catalog[catalog_idx].mod_time; // struct copy
		}
	}

	hdrsize = dbuf_getui32le(firstpart, 0);
	de_dbg(c, "header size: %d", (int)hdrsize);

	ver = dbuf_getui32le(firstpart, 4);
	de_dbg(c, "version: %d", (int)ver);

	// 0x0c = "Original format" Thumbs.db
	// 0x18 = "Windows 7 format"

	if((hdrsize==0x0c || hdrsize==0x18) && dei->stream_size>hdrsize) {
		de_byte sig1[4];
		de_byte sig2[4];

		reported_size = dbuf_getui32le(firstpart, 8);
		de_dbg(c, "reported size: %d", (int)reported_size);

		startpos = hdrsize;
		final_streamsize -= hdrsize;
		de_dbg(c, "calculated size: %d", (int)final_streamsize);

		if(catalog_idx>=0 && c->filenames_from_file) {
			de_dbg(c, "name from catalog: \"%s\"",
				ucstring_getpsz(d->thumbsdb_catalog[catalog_idx].fname_srd->str));

			// Replace the default name with the name from the catalog.
			ucstring_empty(tmpfn);

			if(!de_strcasecmp(d->thumbsdb_catalog[catalog_idx].fname_srd->sz_utf8,
				"{A42CD7B6-E9B9-4D02-B7A6-288B71AD28BA}"))
			{
				ucstring_append_sz(tmpfn, "_folder", DE_ENCODING_LATIN1);
			}
			else {
				ucstring_append_ucstring(tmpfn, d->thumbsdb_catalog[catalog_idx].fname_srd->str);
			}
		}

		dbuf_read(firstpart, sig1, hdrsize, 4);
		dbuf_read(firstpart, sig2, hdrsize+16, 4);

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

	de_finfo_set_name_from_ucstring(c, fi, tmpfn);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	copy_any_stream_to_dbuf(c, d, dei, startpos, final_streamsize, outf);

done:
	dbuf_close(outf);
}

struct officeart_rectype {
	de_uint16 rectype;
	de_uint16 flags;
	const char *name;
	void *reserved;
};

static const struct officeart_rectype officeart_rectype_arr[] = {
	{ 0xf000, 0, "DggContainer", NULL },
	{ 0xf001, 0, "BStoreContainer", NULL },
	{ 0xf006, 0, "FDGGBlock", NULL },
	{ 0xf007, 0, "FBSE", NULL },
	{ 0xf00b, 0, "FOPT", NULL },
	{ 0xf01a, 0, "BlipEMF", NULL },
	{ 0xf01b, 0, "BlipWMF", NULL },
	{ 0xf01c, 0, "BlipPICT", NULL },
	{ 0xf01d, 0, "BlipJPEG", NULL },
	{ 0xf01e, 0, "BlipPNG", NULL },
	{ 0xf01f, 0, "BlipDIB", NULL },
	{ 0xf029, 0, "BlipTIFF", NULL },
	{ 0xf02a, 0, "BlipJPEG", NULL },
	{ 0xf11a, 0, "ColorMRUContainer", NULL },
	{ 0xf11e, 0, "SplitMenuColorContainer", NULL },
	{ 0xf122, 0, "TertiaryFOPT", NULL }
};

static const char *get_officeart_rectype_name(unsigned int t)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(officeart_rectype_arr); k++) {
		if((unsigned int)officeart_rectype_arr[k].rectype == t) {
			return officeart_rectype_arr[k].name;
		}
	}
	return "?";
}

struct officeartctx {
#define OACTX_STACKSIZE 10
	de_int64 container_end_stack[OACTX_STACKSIZE];
	size_t container_end_stackptr;

	// Passed to do_OfficeArtStream_record():
	de_int64 record_pos;

	// Returned from do_OfficeArtStream_record():
	de_int64 record_bytes_consumed;
	int is_container;
	de_int64 container_endpos; // valid if (is_container)
};

static int do_OfficeArtStream_record(deark *c, lctx *d, struct officeartctx *oactx,
	struct dir_entry_info *dei)
{
	unsigned int rectype;
	unsigned int recinstance;
	unsigned int recver;
	unsigned int n;
	de_int64 reclen;
	de_int64 pos = 0; // relative to the beginning of firstpart
	de_int64 nbytes_to_copy;
	de_int64 extra_bytes = 0;
	dbuf *firstpart = NULL;
	dbuf *outf = NULL;
	const char *ext = "bin";
	int has_metafileHeader = 0;
	int has_zlib_cmpr = 0;
	int is_dib = 0;
	int is_pict = 0;
	int retval = 0;
	int is_blip = 0;
	int saved_indent_level;
	de_int64 pos1 = oactx->record_pos;

	oactx->record_bytes_consumed = 0;
	oactx->is_container = 0;
	oactx->container_endpos = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	firstpart = dbuf_create_membuf(c, 128, 0x1);

	nbytes_to_copy = 128;
	if(pos1+128 > dei->stream_size) nbytes_to_copy = dei->stream_size - pos1;
	copy_any_stream_to_dbuf(c, d, dei, pos1, nbytes_to_copy, firstpart);

	n = (unsigned int)dbuf_getui16le_p(firstpart, &pos);
	recver = n&0x0f;
	if(recver==0x0f) oactx->is_container = 1;
	recinstance = n>>4;

	rectype = (unsigned int)dbuf_getui16le_p(firstpart, &pos);
	if((rectype&0xf000)!=0xf000) {
		// Assume this is the end of data, not necessarily an error.
		goto done;
	}

	reclen = dbuf_getui32le_p(firstpart, &pos);

	de_dbg(c, "record at [%"INT64_FMT"], ver=0x%x, inst=0x%03x, type=0x%04x (%s), dlen=%"INT64_FMT,
		pos1, recver, recinstance,
		rectype, get_officeart_rectype_name(rectype), reclen);
	de_dbg_indent(c, 1);

	if(pos1 + pos + reclen > dei->stream_size) goto done;
	if(oactx->is_container) {
		// A container is described as *being* its header record. It does have
		// a recLen, but it should be safe to ignore it if all we care about is
		// reading the records at a low level.
		oactx->record_bytes_consumed = 8;
		oactx->container_endpos = oactx->record_pos + 8 + reclen;
	}
	else {
		oactx->record_bytes_consumed = pos + reclen;
	}
	retval = 1;

	if(rectype>=0xf018 && rectype<=0xf117) is_blip = 1;
	if(!is_blip) goto done;

	if(rectype==0xf01a) {
		ext = "emf";
		if(recinstance==0x3d4) extra_bytes=50;
		else if(recinstance==0x3d5) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
	}
	else if(rectype==0xf01b) {
		ext = "wmf";
		if(recinstance==0x216) extra_bytes=50;
		else if(recinstance==0x217) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
	}
	else if(rectype==0xf01c) {
		ext = "pict";
		if(recinstance==0x542) extra_bytes=50;
		else if(recinstance==0x543) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
		is_pict = 1;
	}
	else if(rectype==0xf01d) {
		ext = "jpg";
		if(recinstance==0x46a || recinstance==0x6e2) extra_bytes = 17;
		else if(recinstance==0x46b || recinstance==0x6e3) extra_bytes = 33;
	}
	else if(rectype==0xf01e) {
		ext = "png";
		if(recinstance==0x6e0) extra_bytes = 17;
		else if(recinstance==0x6e1) extra_bytes = 33;
	}
	else if(rectype==0xf01f) {
		ext = "dib";
		if(recinstance==0x7a8) extra_bytes = 17;
		else if(recinstance==0x7a9) extra_bytes = 33;
		if(extra_bytes) is_dib=1;
	}
	else if(rectype==0xf029) {
		ext = "tif";
		if(recinstance==0x6e4) extra_bytes = 17;
		else if(recinstance==0x6e5) extra_bytes = 33;
	}

	if(extra_bytes==0) {
		de_warn(c, "Unsupported OfficeArtBlip format (recInstance=0x%03x, recType=0x%04x)",
			recinstance, rectype);
		goto done;
	}

	if(has_metafileHeader) {
		// metafileHeader starts at pos+extra_bytes-34
		de_byte cmpr = dbuf_getbyte(firstpart, pos+extra_bytes-2);
		// 0=DEFLATE, 0xfe=NONE
		de_dbg(c, "compression type: %u", (unsigned int)cmpr);
		has_zlib_cmpr = (cmpr==0);
	}

	pos += extra_bytes;

	if(is_dib) {
		dbuf *raw_stream;
		raw_stream = dbuf_create_membuf(c, 0, 0);
		copy_any_stream_to_dbuf(c, d, dei, pos1+pos, reclen-extra_bytes, raw_stream);
		de_run_module_by_id_on_slice2(c, "dib", "X", raw_stream, 0, raw_stream->len);
		dbuf_close(raw_stream);
		goto done;
	}

	outf = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
	if(is_pict) {
		dbuf_write_zeroes(outf, 512);
	}

	if(has_zlib_cmpr) {
		dbuf *raw_stream;
		raw_stream = dbuf_create_membuf(c, 0, 0);
		copy_any_stream_to_dbuf(c, d, dei, pos1+pos, reclen-extra_bytes, raw_stream);
		de_uncompress_zlib(raw_stream, 0, raw_stream->len, outf);
		dbuf_close(raw_stream);
	}
	else {
		copy_any_stream_to_dbuf(c, d, dei, pos1+pos, reclen-extra_bytes, outf);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(outf);
	dbuf_close(firstpart);
	return retval;
}

// Refer to Microsoft's "[MS-ODRAW]" document.
static void do_OfficeArtStream(deark *c, lctx *d, struct dir_entry_info *dei)
{
	struct officeartctx * oactx = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	oactx = de_malloc(c, sizeof(struct officeartctx));
	de_dbg(c, "OfficeArt stream, len=%"INT64_FMT, dei->stream_size);

	oactx->record_pos = 0;
	while(1) {
		de_int64 ret;

		if(oactx->record_pos >= dei->stream_size-8) break;

		// Have we reached the end of any containers?
		while(oactx->container_end_stackptr>0 &&
			oactx->record_pos>=oactx->container_end_stack[oactx->container_end_stackptr-1])
		{
			oactx->container_end_stackptr--;
			de_dbg_indent(c, -1);
		}

		ret = do_OfficeArtStream_record(c, d, oactx, dei);
		if(!ret || oactx->record_bytes_consumed<=0) break;

		oactx->record_pos += oactx->record_bytes_consumed;

		// Is a new container open?
		if(oactx->is_container && oactx->container_end_stackptr<OACTX_STACKSIZE) {
			oactx->container_end_stack[oactx->container_end_stackptr++] = oactx->container_endpos;
			de_dbg_indent(c, 1);
		}
	}

	de_free(c, oactx);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *field_name)
{
	char timestamp_buf[64];

	if(ts->is_valid) {
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 1);
		de_dbg(c, "%s: %s", field_name, timestamp_buf);
	}
}

static void read_and_cvt_and_dbg_timestamp(deark *c, dbuf *f, de_int64 pos,
	struct de_timestamp *ts, const char *field_name)
{
	de_int64 ts_as_FILETIME;

	de_memset(ts, 0, sizeof(struct de_timestamp));
	ts_as_FILETIME = dbuf_geti64le(f, pos);
	if(ts_as_FILETIME!=0) {
		de_FILETIME_to_timestamp(ts_as_FILETIME, ts);
		dbg_timestamp(c, ts, field_name);
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

	d->thumbsdb_catalog = de_malloc(c, d->thumbsdb_catalog_num_entries *
		sizeof(struct thumbsdb_catalog_entry));

	pos = item_len;

	for(i=0; i<d->thumbsdb_catalog_num_entries; i++) {
		if(pos >= catf->len) goto done;
		item_len = dbuf_getui32le(catf, pos);
		de_dbg(c, "catalog entry #%d, len=%d", (int)i, (int)item_len);
		if(item_len<20) goto done;

		de_dbg_indent(c, 1);

		d->thumbsdb_catalog[i].id = (de_uint32)dbuf_getui32le(catf, pos+4);
		de_dbg(c, "id: %u", (unsigned int)d->thumbsdb_catalog[i].id);

		read_and_cvt_and_dbg_timestamp(c, catf, pos+8, &d->thumbsdb_catalog[i].mod_time, "timestamp");

		d->thumbsdb_catalog[i].fname_srd = dbuf_read_string(catf, pos+16, item_len-20, item_len-20,
			DE_CONVFLAG_WANT_UTF8, DE_ENCODING_UTF16LE);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz(d->thumbsdb_catalog[i].fname_srd->str));

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

static void do_cfb_olepropertyset(deark *c, lctx *d, struct dir_entry_info *dei,
	int is_summaryinfo, int is_root)
{
	dbuf *f = NULL;
	int saved_indent_level;

	if(dei->stream_size>1000000) goto done;
	f = dbuf_create_membuf(c, dei->stream_size, 1);
	copy_any_stream_to_dbuf(c, d, dei, 0, dei->stream_size, f);

	de_dbg_indent_save(c, &saved_indent_level);
	if(is_summaryinfo) {
		de_dbg(c, "SummaryInformation (%s)", is_root?"root":"non-root");
	}
	else {
		de_dbg(c, "property set stream");
	}

	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "olepropset", NULL, f, 0, f->len);
	de_dbg_indent(c, -1);

done:
	dbuf_close(f);
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
			(int)d->dir_entry[i].entry_type,
			(int)d->dir_entry[i].parent_id,
			(int)d->dir_entry[i].child_id,
			(int)d->dir_entry[i].sibling_id[0],
			(int)d->dir_entry[i].sibling_id[1]);
		if(d->dir_entry[i].fname_srd && d->dir_entry[i].fname_srd->str) {
			de_dbg(c, "  fname: \"%s\"",
				ucstring_getpsz(d->dir_entry[i].fname_srd->str));
		}
		if(d->dir_entry[i].path) {
			de_dbg(c, "  path: \"%s\"",
				ucstring_getpsz(d->dir_entry[i].path));
		}
	}
}
#endif

static void do_mark_dir_entries_recursively(deark *c, lctx *d, de_int32 parent_id,
	de_int32 dir_entry_idx, int level)
{
	struct dir_entry_info *dei;
	int k;

	if(dir_entry_idx<0 || (de_int64)dir_entry_idx>=d->num_dir_entries) return;

	dei = &d->dir_entry[dir_entry_idx];

	if(dei->entry_type!=OBJTYPE_STORAGE && dei->entry_type!=OBJTYPE_STREAM) return;

	dei->parent_id = parent_id;

	if(dei->entry_type==OBJTYPE_STORAGE && dei->fname_srd && dei->fname_srd->str && !dei->path) {
		// Set the full pathname
		dei->path = ucstring_create(c);
		if(parent_id>0 && d->dir_entry[parent_id].path) {
			ucstring_append_ucstring(dei->path, d->dir_entry[parent_id].path);
			ucstring_append_sz(dei->path, "/", DE_ENCODING_ASCII);
		}
		ucstring_append_ucstring(dei->path, dei->fname_srd->str);
	}

	if(level>50) return;
	for(k=0; k<2; k++) {
		do_mark_dir_entries_recursively(c, d, parent_id, dei->sibling_id[k], level+1);
	}

	if(dei->entry_type==OBJTYPE_STORAGE) {
		// This is a "subdirectory" entry, so examine its children (starting with the
		// one that we know about).
		do_mark_dir_entries_recursively(c, d, dir_entry_idx, dei->child_id, level+1);
	}
}

// Figure out which entries are in the root directory.
static void do_analyze_dir_structure(deark *c, lctx *d)
{
	//do_dump_dir_structure(c, d);

	if(d->num_dir_entries<1) goto done;

	// The first entry should be the root entry.
	if(d->dir_entry[0].entry_type!=OBJTYPE_ROOT_STORAGE) goto done;

	// Its child is one of the entries in the root directory. Start with it.
	do_mark_dir_entries_recursively(c, d, 0, d->dir_entry[0].child_id, 0);

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
	d->dir_entry = de_malloc(c, d->num_dir_entries * sizeof(struct dir_entry_info));

	// Set defaults for each entry
	for(i=0; i<d->num_dir_entries; i++) {
		d->dir_entry[i].child_id = -1;
		d->dir_entry[i].sibling_id[0] = -1;
		d->dir_entry[i].sibling_id[1] = -1;
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

	if(dei->is_thumbsdb_catalog) {
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

static void do_process_stream(deark *c, lctx *d, struct dir_entry_info *dei)
{
	int saved_indent_level;
	de_finfo *fi_raw = NULL; // Use this if we extract the raw stream
	de_finfo *fi_tmp = NULL; // Can be used by format-specific code
	de_ucstring *fn_raw = NULL; // Use this if we extract the raw stream
	de_ucstring *fn_tmp = NULL; // Can be used by format-specific code
	dbuf *firstpart = NULL;
	int is_thumbsdb_stream = 0;
	int is_OfficeArtStream = 0;
	int is_summaryinfo = 0;
	int is_propset = 0;
	int is_root = (dei->parent_id==0);

	de_dbg_indent_save(c, &saved_indent_level);

	// By default, use the "stream name" as the filename.
	fn_raw = ucstring_create(c);

	if(dei->parent_id>0 && d->dir_entry[dei->parent_id].path) {
		ucstring_append_ucstring(fn_raw, d->dir_entry[dei->parent_id].path);
		ucstring_append_sz(fn_raw, "/", DE_ENCODING_ASCII);
	}

	ucstring_append_ucstring(fn_raw, dei->fname_srd->str);
	fn_tmp = ucstring_clone(fn_raw);

	fi_raw = de_finfo_create(c);
	fi_tmp = de_finfo_create(c);

	// By default, use the mod time from the directory entry.
	if(dei->mod_time.is_valid) {
		fi_raw->mod_time = dei->mod_time; // struct copy
		fi_tmp->mod_time = dei->mod_time; // struct copy
	}

	if(d->extract_raw_streams) {
		dbuf *outf = NULL;

		de_finfo_set_name_from_ucstring(c, fi_raw, fn_raw);
		fi_raw->original_filename_flag = 1;

		outf = dbuf_create_output_file(c, NULL, fi_raw, 0);
		copy_any_stream_to_dbuf(c, d, dei, 0, dei->stream_size, outf);
		dbuf_close(outf);
	}

	if(!d->decode_streams) goto done;

	// Read the first part of the stream, to use for format detection.
	firstpart = dbuf_create_membuf(c, 256, 0x1);
	copy_any_stream_to_dbuf(c, d, dei, 0,
		(dei->stream_size>256)?256:dei->stream_size, firstpart);


	// Stream type detection

	// FIXME? The stream detection happens even if d->subformat_req==SUBFMT_RAW.
	// We probably should have different detection logic in that case.

	if(!de_strcasecmp(dei->fname_srd->sz_utf8, "\x05" "SummaryInformation")) {
		is_propset = 1;
		is_summaryinfo = 1;
	}
	else if(!de_strncmp(dei->fname_srd->sz_utf8, "\x05", 1)) {
		// TODO: Is there a good way to tell whether a stream is a property set?
		is_propset = 1;
	}
	else if(d->subformat_final==SUBFMT_TIFF37680 &&
		!de_strcasecmp(dei->fname_srd->sz_utf8, "CONTENTS"))
	{
		// TODO: This is not the only place to find a "CONTENTS" stream.
		is_propset = 1;
	}
	else if(d->subformat_final==SUBFMT_THUMBSDB) {
		is_thumbsdb_stream = 1;
	}
	else if(!de_strcasecmp(dei->fname_srd->sz_utf8, "Pictures")) {
		// This stream often appears in PPT documents.
		is_OfficeArtStream = 1;
	}
	else if(!de_strcasecmp(dei->fname_srd->sz_utf8, "EscherStm")) {
		is_OfficeArtStream = 1;
	}
	else if(!de_strcasecmp(dei->fname_srd->sz_utf8, "EscherDelayStm")) {
		// Found in MS Publisher, and probably other formats.
		is_OfficeArtStream = 1;
	}

	if(is_OfficeArtStream) {
		unsigned int rectype;
		rectype = (unsigned int)dbuf_getui16le(firstpart, 2);
		if((rectype&0xf000)!=0xf000) {
			is_OfficeArtStream = 0;
		}
	}

	// End of stream type detection

	if(is_propset) {
		do_cfb_olepropertyset(c, d, dei, is_summaryinfo, is_root);
	}
	else if(is_thumbsdb_stream) {
		do_extract_stream_to_file_thumbsdb(c, d, dei, fi_tmp, fn_tmp, firstpart);
	}
	else if(is_OfficeArtStream) {
		do_OfficeArtStream(c, d, dei);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(firstpart);
	ucstring_destroy(fn_raw);
	ucstring_destroy(fn_tmp);
	de_finfo_destroy(c, fi_raw);
	de_finfo_destroy(c, fi_tmp);
}

// Read and process a directory entry from the d->dir stream
// Pass 1:
//  Collect information about the streams.
//  Read the Root Object.
//  Read the minisec stream.
//  Process some other special streams (e.g. Thumbsdb Catalog).
//  Do some things related to format detection.
static void do_dir_entry_pass1(deark *c, lctx *d, de_int64 dir_entry_idx, de_int64 dir_entry_offs)
{
	de_int64 raw_sec_id;
	de_int64 name_len_bytes;
	struct dir_entry_info *dei = NULL;
	char clsid_string[50];
	char buf[80];

	if(!d->dir_entry) return; // error
	dei = &d->dir_entry[dir_entry_idx];

	dei->entry_type = dbuf_getbyte(d->dir, dir_entry_offs+66);
	switch(dei->entry_type) {
	case OBJTYPE_EMPTY: dei->entry_type_name="empty"; break;
	case OBJTYPE_STORAGE: dei->entry_type_name="storage object"; break;
	case OBJTYPE_STREAM: dei->entry_type_name="stream"; break;
	case OBJTYPE_ROOT_STORAGE: dei->entry_type_name="root storage object"; break;
	default: dei->entry_type_name="?";
	}
	de_dbg(c, "type: 0x%02x (%s)", (unsigned int)dei->entry_type, dei->entry_type_name);

	if(dei->entry_type==OBJTYPE_EMPTY) goto done;

	dei->name_len_raw = dbuf_getui16le(d->dir, dir_entry_offs+64);
	de_dbg2(c, "name len: %d bytes", (int)dei->name_len_raw);

	name_len_bytes = dei->name_len_raw-2; // Ignore the trailing U+0000
	if(name_len_bytes<0) name_len_bytes = 0;

	dei->fname_srd = dbuf_read_string(d->dir, dir_entry_offs, name_len_bytes, name_len_bytes,
		DE_CONVFLAG_WANT_UTF8, DE_ENCODING_UTF16LE);

	de_dbg(c, "name: \"%s\"", ucstring_getpsz(dei->fname_srd->str));

	dei->node_color = dbuf_getbyte(d->dir, dir_entry_offs+67);
	de_dbg(c, "node color: %u", (unsigned int)dei->node_color);

	if(dei->entry_type==OBJTYPE_STORAGE || dei->entry_type==OBJTYPE_STREAM) {
		dei->sibling_id[0] = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+68);
		dei->sibling_id[1] = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+72);
		de_dbg(c, "sibling StreamIDs: %d, %d", (int)dei->sibling_id[0], (int)dei->sibling_id[1]);
	}

	if(dei->entry_type==OBJTYPE_STORAGE || dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		dei->child_id = (de_int32)dbuf_geti32le(d->dir, dir_entry_offs+76);
		de_dbg(c, "child StreamID: %d", (int)dei->child_id);
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

	read_and_cvt_and_dbg_timestamp(c, d->dir, dir_entry_offs+108, &dei->mod_time, "mod time");

	raw_sec_id = dbuf_geti32le(d->dir, dir_entry_offs+116);

	if(d->major_ver<=3) {
		dei->stream_size = dbuf_getui32le(d->dir, dir_entry_offs+120);
	}
	else {
		dei->stream_size = dbuf_geti64le(d->dir, dir_entry_offs+120);
	}
	de_dbg(c, "stream size: %"INT64_FMT, dei->stream_size);

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

	if((d->subformat_req==SUBFMT_THUMBSDB || d->subformat_req==SUBFMT_AUTO) &&
		!de_strcmp(dei->fname_srd->sz_utf8, "Catalog"))
	{
		dei->is_thumbsdb_catalog = 1;
	}

	do_per_dir_entry_format_detection(c, d, dei);

	if(dei->is_thumbsdb_catalog && d->decode_streams) {
		read_thumbsdb_catalog(c, d, dei);
	}
	else if(dei->entry_type==OBJTYPE_ROOT_STORAGE) {
		// Note: The Root Storage object is required to be the first entry, so we
		// don't need an extra pass to process it.
		read_mini_sector_stream(c, d, dei->normal_sec_id, dei->stream_size);
	}

done:
	;
}

// Pass 2: Process most of the streams.
static void do_dir_entry_pass2(deark *c, lctx *d, de_int64 dir_entry_idx)
{
	struct dir_entry_info *dei = NULL;

	if(!d->dir_entry) return; // error
	dei = &d->dir_entry[dir_entry_idx];

	de_dbg(c, "type: 0x%02x (%s)", (unsigned int)dei->entry_type, dei->entry_type_name);

	if(dei->entry_type==OBJTYPE_EMPTY) goto done;
	if(dei->entry_type==OBJTYPE_ROOT_STORAGE) goto done;

	if(dei->fname_srd)
		de_dbg(c, "name: \"%s\"", ucstring_getpsz(dei->fname_srd->str));

	// In pass 1, we didn't know the parent yet, so print it now.
	de_dbg(c, "parent: %d", (int)dei->parent_id);

	if(dei->entry_type==OBJTYPE_STREAM) {
		do_process_stream(c, d, dei);
	}

done:
	;
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
		if(pass==1) {
			do_dir_entry_pass1(c, d, i, dir_entry_offs);
		}
		else {
			do_dir_entry_pass2(c, d, i);
		}
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static void de_run_cfb_internal(deark *c, lctx *d)
{
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
	dbuf_close(d->difat);
	dbuf_close(d->fat);
	dbuf_close(d->minifat);
	dbuf_close(d->dir);
	if(d->dir_entry) {
		de_int64 k;
		for(k=0; k<d->num_dir_entries; k++) {
			de_destroy_stringreaderdata(c, d->dir_entry[k].fname_srd);
			ucstring_destroy(d->dir_entry[k].path);
		}
		de_free(c, d->dir_entry);
	}
	dbuf_close(d->mini_sector_stream);
	if(d->thumbsdb_catalog) {
		de_int64 k;
		for(k=0; k<d->thumbsdb_catalog_num_entries; k++) {
			de_destroy_stringreaderdata(c, d->thumbsdb_catalog[k].fname_srd);
		}
		de_free(c, d->thumbsdb_catalog);
		d->thumbsdb_catalog = NULL;
	}
}

static void de_run_cfb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *cfbfmt_opt;

	d = de_malloc(c, sizeof(lctx));
	d->decode_streams = 1;
	d->subformat_req = SUBFMT_AUTO;

	if(de_get_ext_option(c, "cfb:extractstreams")) {
		d->extract_raw_streams = 1;
		d->decode_streams = 0;
	}

	if(mparams && mparams->in_params.codes) {
		if(de_strchr(mparams->in_params.codes, 'T')) { // TIFF tag 37680 mode
			d->subformat_req = SUBFMT_TIFF37680;
		}
	}

	if(d->subformat_req == SUBFMT_AUTO) {
		// If we haven't set subformat_req yet, look at the command-line option

		cfbfmt_opt = de_get_ext_option(c, "cfb:fmt");
		if(cfbfmt_opt) {
			if(!de_strcmp(cfbfmt_opt, "auto")) {
				d->subformat_req = SUBFMT_AUTO;
			}
			else if(!de_strcmp(cfbfmt_opt, "raw")) {
				d->subformat_req = SUBFMT_RAW;
			}
			else if(!de_strcmp(cfbfmt_opt, "thumbsdb")) {
				d->subformat_req = SUBFMT_THUMBSDB;
			}
		}
	}

	de_run_cfb_internal(c, d);

	de_free(c, d);
}

static int de_identify_cfb(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8))
		return 100;
	return 0;
}

static void de_help_cfb(deark *c)
{
	de_msg(c, "-opt cfb:extractstreams : Extract raw streams, instead of decoding");
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
