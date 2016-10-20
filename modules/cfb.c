// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Microsoft Compound File Binary File Format
// a.k.a. "OLE Compound Document Format", and a million other names

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_cfb);

#define OBJTYPE_EMPTY        0x00
#define OBJTYPE_STORAGE      0x01
#define OBJTYPE_STREAM       0x02
#define OBJTYPE_ROOT_STORAGE 0x05

typedef struct localctx_struct {
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

	dbuf *mini_sector_stream;
} lctx;

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
static void copy_stream_to_dbuf(deark *c, lctx *d,
	de_int64 first_sec_id, de_int64 stream_size,
	dbuf *outf)
{
	de_int64 bytes_left;
	de_int64 sec_id;
	de_int64 sec_offs;
	de_int64 bytes_to_copy;

	if(stream_size<0 || stream_size>c->infile->len) return;

	bytes_left = stream_size;
	sec_id = first_sec_id;
	while(bytes_left > 0) {
		if(sec_id<0) break;
		sec_offs = sec_id_to_offset(c, d, sec_id);

		bytes_to_copy = d->sec_size;
		if(bytes_to_copy > bytes_left) bytes_to_copy = bytes_left;
		dbuf_copy(c->infile, sec_offs, bytes_to_copy, outf);
		bytes_left -= bytes_to_copy;
		sec_id = get_next_sec_id(c, d, sec_id);
	}
}

static void copy_mini_stream_to_dbuf(deark *c, lctx *d,
	de_int64 first_minisec_id, de_int64 stream_size,
	dbuf *outf)
{
	de_int64 bytes_left;
	de_int64 bytes_to_copy;
	de_int64 minisec_id;
	de_int64 minisec_offs;

	if(!d->mini_sector_stream) return;
	if(stream_size<0 || stream_size>d->mini_sector_stream->len) return;

	bytes_left = stream_size;
	minisec_id = first_minisec_id;
	while(bytes_left > 0) {
		if(minisec_id<0) break;
		minisec_offs = minisec_id * d->mini_sector_size;

		bytes_to_copy = d->mini_sector_size;
		if(bytes_to_copy > bytes_left) bytes_to_copy = bytes_left;
		dbuf_copy(d->mini_sector_stream, minisec_offs, bytes_to_copy, outf);
		bytes_left -= bytes_to_copy;
		minisec_id = get_next_minisec_id(c, d, minisec_id);
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

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	// offset 0-7: signature
	// offset 8-23: CLSID

	d->minor_ver = de_getui16le(pos+24);
	d->major_ver = de_getui16le(pos+26);
	de_dbg(c, "format version: %d.%d\n", (int)d->major_ver, (int)d->minor_ver);
	if(d->major_ver!=3 && d->major_ver!=4) {
		de_err(c, "Unsupported format version: %d\n", (int)d->major_ver);
		goto done;
	}

	byte_order_code = de_getui16le(pos+28);
	if(byte_order_code != 0xfffe) {
		de_err(c, "Unsupported byte order code: 0x%04x\n", (unsigned int)byte_order_code);
		goto done;
	}

	sector_shift = de_getui16le(pos+30); // aka ssz
	d->sec_size = (de_int64)(1<<(unsigned int)sector_shift);
	de_dbg(c, "sector size: 2^%d (%d bytes)\n", (int)sector_shift,
		(int)d->sec_size);
	if(d->sec_size!=512 && d->sec_size!=4096) {
		de_err(c, "Unsupported sector size: %d\n", (int)d->sec_size);
		goto done;
	}

	mini_sector_shift = de_getui16le(pos+32); // aka sssz
	d->mini_sector_size = (de_int64)(1<<(unsigned int)mini_sector_shift);
	de_dbg(c, "mini sector size: 2^%d (%d bytes)\n", (int)mini_sector_shift,
		(int)d->mini_sector_size);
	if(d->mini_sector_size!=64) {
		de_err(c, "Unsupported mini sector size: %d\n", (int)d->mini_sector_size);
		goto done;
	}

	// offset 34: 6 reserved bytes

	//d->num_dir_sectors = de_getui32le(pos+40);
	//de_dbg(c, "number of directory sectors: %u\n", (unsigned int)d->num_dir_sectors);
	// Should be 0 if major_ver==3

	// Number of sectors used by sector allocation table (FAT)
	d->num_fat_sectors = de_getui32le(pos+44);
	de_dbg(c, "number of FAT sectors: %d\n", (int)d->num_fat_sectors);

	d->first_dir_sec_id = dbuf_geti32le(c->infile, pos+48);
	describe_sec_id(c, d, d->first_dir_sec_id, buf, sizeof(buf));
	de_dbg(c, "first directory sector: %d (%s)\n", (int)d->first_dir_sec_id, buf);

	// offset 52, transaction signature number

	d->std_stream_min_size = de_getui32le(pos+56);
	de_dbg(c, "min size of a standard stream: %d\n", (int)d->std_stream_min_size);

	// First sector of mini sector allocation table (MiniFAT)
	d->first_minifat_sec_id = dbuf_geti32le(c->infile, pos+60);
	describe_sec_id(c, d, d->first_minifat_sec_id, buf, sizeof(buf));
	de_dbg(c, "first MiniFAT sector: %d (%s)\n", (int)d->first_minifat_sec_id, buf);

	// Number of sectors used by MiniFAT
	d->num_minifat_sectors = de_getui32le(pos+64);
	de_dbg(c, "number of MiniFAT sectors: %d\n", (int)d->num_minifat_sectors);

	// SecID of first (extra??) sector of the DIFAT
	// (also called the Master Sector Allocation Table (MSAT))
	d->first_difat_sec_id = dbuf_geti32le(c->infile, pos+68);
	describe_sec_id(c, d, d->first_difat_sec_id, buf, sizeof(buf));
	de_dbg(c, "first extended DIFAT sector: %d (%s)\n", (int)d->first_difat_sec_id, buf);

	// Number of (extra??) sectors used by the DIFAT
	d->num_difat_sectors = de_getui32le(pos+72);
	de_dbg(c, "number of extended DIFAT sectors: %d\n", (int)d->num_difat_sectors);

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


	de_dbg(c, "reading DIFAT (total number of entries=%d)\n", (int)d->num_fat_sectors);
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
	de_dbg(c, "reading %d DIFAT entries from header, at 76\n", (int)num_to_read);
	dbuf_copy(c->infile, 76, num_to_read*4, d->difat);
	still_to_read -= num_to_read;

	difat_sec_id = d->first_difat_sec_id;
	while(still_to_read>0) {
		if(difat_sec_id<0) break;

		difat_sec_offs = sec_id_to_offset(c, d, difat_sec_id);
		de_dbg(c, "reading DIFAT sector at %d\n", (int)difat_sec_offs);
		num_to_read = (d->sec_size - 4)/4;

		dbuf_copy(c->infile, difat_sec_offs, num_to_read*4, d->difat);
		still_to_read -= num_to_read;
		difat_sec_id = (de_int64)dbuf_geti32le(c->infile, difat_sec_offs + num_to_read*4);
	}

	de_dbg_indent(c, -1);
}

static void dump_fat(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sec_id;
	char buf[80];

	if(c->debug_level<2) return;

	de_dbg2(c, "dumping FAT contents (%d entries)\n", (int)d->num_fat_entries);

	de_dbg_indent(c, 1);
	for(i=0; i<d->num_fat_entries; i++) {
		sec_id = dbuf_geti32le(d->fat, i*4);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg2(c, "FAT[%d]: next_SecID=%d (%s)\n", (int)i, (int)sec_id, buf);
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

	de_dbg(c, "reading FAT contents (%d sectors)\n", (int)d->num_fat_sectors);
	de_dbg_indent(c, 1);
	for(i=0; i<d->num_fat_sectors; i++) {
		sec_id = dbuf_geti32le(d->difat, i*4);
		sec_offset = sec_id_to_offset(c, d, sec_id);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg(c, "reading sector: DIFAT_idx=%d, SecID=%d (%s)\n",
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
	de_dbg2(c, "dumping MiniFAT contents (%d entries)\n", (int)num_minifat_entries);

	de_dbg_indent(c, 1);
	for(i=0; i<num_minifat_entries; i++) {
		sec_id = dbuf_geti32le(d->minifat, i*4);
		//describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg2(c, "MiniFAT[%d]: next_MiniSecID=%d\n", (int)i, (int)sec_id);
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

	// TODO: Use copy_stream_to_dbuf
	de_dbg(c, "reading MiniFAT contents (%d sectors)\n", (int)d->num_minifat_sectors);
	de_dbg_indent(c, 1);

	sec_id = d->first_minifat_sec_id;

	for(i=0; i<d->num_minifat_sectors; i++) {
		if(sec_id<0) break;

		sec_offset = sec_id_to_offset(c, d, sec_id);
		describe_sec_id(c, d, sec_id, buf, sizeof(buf));
		de_dbg(c, "reading MiniFAT sector #%d, SecID=%d (%s)\n",
			(int)i, (int)sec_id, buf);
		dbuf_copy(c->infile, sec_offset, d->sec_size, d->minifat);

		sec_id = get_next_sec_id(c, d, sec_id);
	}
	de_dbg_indent(c, -1);

	dump_minifat(c, d);
}

// Write a stream to a file.
static void extract_stream(deark *c, lctx *d, de_int64 first_sec_id, de_int64 stream_size)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "bin", NULL, 0);
	copy_stream_to_dbuf(c, d, first_sec_id, stream_size, outf);
	dbuf_close(outf);
}

static void extract_mini_stream(deark *c, lctx *d, de_int64 first_minisec_id, de_int64 stream_size)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "bin", NULL, 0);
	copy_mini_stream_to_dbuf(c, d, first_minisec_id, stream_size, outf);
	dbuf_close(outf);
}

static void read_mini_sector_stream(deark *c, lctx *d, de_int64 first_sec_id, de_int64 stream_size)
{
	if(d->mini_sector_stream) return; // Already done

	de_dbg(c, "reading mini sector stream (%d bytes)\n", (int)stream_size);
	d->mini_sector_stream = dbuf_create_membuf(c, 0, 0);
	copy_stream_to_dbuf(c, d, first_sec_id, stream_size, d->mini_sector_stream);
}

// Reads the directory stream into d->dir, and sets d->num_dir_entries.
static void read_directory_stream(deark *c, lctx *d)
{
	de_int64 dir_sec_id;
	de_int64 dir_sector_offs;
	de_int64 num_entries_per_sector;
	de_int64 dir_sector_count = 0;

	de_dbg(c, "reading directory stream\n");
	de_dbg_indent(c, 1);

	d->dir = dbuf_create_membuf(c, 0, 0);

	dir_sec_id = d->first_dir_sec_id;

	num_entries_per_sector = d->sec_size / 128;
	d->num_dir_entries = 0;

	// TODO: Use copy_stream_to_dbuf
	while(1) {
		if(dir_sec_id<0) break;

		dir_sector_offs = sec_id_to_offset(c, d, dir_sec_id);

		de_dbg(c, "directory sector #%d SecID=%d (offs=%d), entries %d-%d\n",
			(int)dir_sector_count,
			(int)dir_sec_id, (int)dir_sector_offs,
			(int)d->num_dir_entries, (int)(d->num_dir_entries + num_entries_per_sector - 1));

		dbuf_copy(c->infile, dir_sector_offs, d->sec_size, d->dir);

		d->num_dir_entries += num_entries_per_sector;

		dir_sec_id = get_next_sec_id(c, d, dir_sec_id);
		dir_sector_count++;
	}

	de_dbg(c, "number of directory entries: %d\n", (int)d->num_dir_entries);

	de_dbg_indent(c, -1);
}

// Read and process a directory entry from the d->dir stream
static void do_dir_entry(deark *c, lctx *d, de_int64 dir_entry_idx, de_int64 dir_entry_offs,
	int pass)
{
	de_int64 name_len_raw;
	de_int64 name_len_bytes;
	de_ucstring *s = NULL;
	de_byte entry_type;
	de_int64 stream_sec_id;
	de_int64 stream_size;
	int is_mini_stream;
	int need_to_read_stream_info = 0;
	const char *name;
	de_byte clsid[16];
	char clsid_string[50];
	char buf[80];

	entry_type = dbuf_getbyte(d->dir, dir_entry_offs+66);
	switch(entry_type) {
	case OBJTYPE_EMPTY: name="empty"; break;
	case OBJTYPE_STORAGE: name="storage object"; break;
	case OBJTYPE_STREAM: name="stream"; break;
	case OBJTYPE_ROOT_STORAGE: name="root storage object"; break;
	default: name="?";
	}
	de_dbg(c, "type: 0x%02x (%s)\n", (unsigned int)entry_type, name);
	if(entry_type==0x00) goto done;

	name_len_raw = dbuf_getui16le(d->dir, dir_entry_offs+64);
	de_dbg2(c, "name len: %d bytes\n", (int)name_len_raw);
	name_len_bytes = name_len_raw-2; // Ignore the trailing U+0000
	if(name_len_bytes<0) name_len_bytes = 0;

	s = ucstring_create(c);
	dbuf_read_to_ucstring(d->dir, dir_entry_offs, name_len_bytes, s,
		0, DE_ENCODING_UTF16LE);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(s));

	if(entry_type==OBJTYPE_STORAGE || entry_type==OBJTYPE_ROOT_STORAGE) {
		dbuf_read(d->dir, clsid, dir_entry_offs+80, 16);
		de_fmtutil_guid_to_uuid(clsid);
		de_fmtutil_render_uuid(c, clsid, clsid_string, sizeof(clsid_string));
		de_dbg(c, "clsid: {%s}\n", clsid_string);
	}

	if(entry_type==OBJTYPE_ROOT_STORAGE)
		need_to_read_stream_info = (pass==1);
	else
		need_to_read_stream_info = (pass==2);

	if(need_to_read_stream_info) {
		// TODO: dir_entry_offs+108 modification time

		stream_sec_id = dbuf_geti32le(d->dir, dir_entry_offs+116);

		if(d->major_ver<=3) {
			stream_size = dbuf_getui32le(d->dir, dir_entry_offs+120);
		}
		else {
			stream_size = dbuf_geti64le(d->dir, dir_entry_offs+120);
		}

		de_dbg(c, "stream size: %"INT64_FMT"\n", stream_size);
		is_mini_stream = (entry_type==OBJTYPE_STREAM) && (stream_size < d->std_stream_min_size);

		if(is_mini_stream) {
			de_dbg(c, "MiniSecID: %d\n", (int)stream_sec_id);

			if(entry_type==OBJTYPE_STREAM) {
				extract_mini_stream(c, d, stream_sec_id, stream_size);
			}
		}
		else {
			describe_sec_id(c, d, stream_sec_id, buf, sizeof(buf));
			de_dbg(c, "SecID: %d (%s)\n", (int)stream_sec_id, buf);

			if(entry_type==OBJTYPE_STREAM) {
				extract_stream(c, d, stream_sec_id, stream_size);
			}

			if(pass==1 && entry_type==OBJTYPE_ROOT_STORAGE) {
				read_mini_sector_stream(c, d, stream_sec_id, stream_size);
			}
		}
	}

done:
	ucstring_destroy(s);
}

// Pass 1: Detect the file format, and read the mini sector stream.
// Pass 2: Extract files.
static void do_directory(deark *c, lctx *d, int pass)
{
	de_int64 dir_entry_offs; // Offset in d->dir
	de_int64 i;

	de_dbg(c, "scanning directory, pass %d\n", pass);
	de_dbg_indent(c, 1);

	for(i=0; i<d->num_dir_entries; i++) {
		dir_entry_offs = 128*i;
		de_dbg(c, "directory entry #%d\n", (int)i);

		de_dbg_indent(c, 1);
		do_dir_entry(c, d, i, dir_entry_offs, pass);
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static void de_run_cfb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_header(c, d)) {
		goto done;
	}

	read_difat(c, d);

	read_fat(c, d);

	read_minifat(c, d);

	read_directory_stream(c, d);

	do_directory(c, d, 1);

	do_directory(c, d, 2);

done:
	if(d) {
		dbuf_close(d->difat);
		dbuf_close(d->fat);
		dbuf_close(d->minifat);
		dbuf_close(d->dir);
		dbuf_close(d->mini_sector_stream);
		de_free(c, d);
	}
}

static int de_identify_cfb(deark *c)
{
#if 0
	if(!dbuf_memcmp(c->infile, 0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8))
		return 100;
#endif
	return 0;
}

void de_module_cfb(deark *c, struct deark_module_info *mi)
{
	mi->id = "cfb";
	mi->desc = "Microsoft Compound File Binary File";
	mi->run_fn = de_run_cfb;
	mi->identify_fn = de_identify_cfb;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
