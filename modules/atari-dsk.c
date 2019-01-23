// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_atari_cas);
DE_DECLARE_MODULE(de_module_atr);

typedef struct localctx_struct {
	i64 sector_size;
} lctx;

static void do_cas(deark *c)
{
	i64 pos;
	u8 chunk_id[4];
	i64 chunk_len;
	i64 chunk_extra;

	pos = 0;
	while(1) {
		if(pos >= c->infile->len-8) break; // Reached end of file

		de_read(chunk_id, pos, 4);
		chunk_len = de_getu16le(pos+4);
		chunk_extra = de_getu16le(pos+6);

		de_dbg(c, "chunk at %d, data_len=%d, extra=%d", (int)pos, (int)chunk_len,
			(int)chunk_extra);

		pos += 8;

		pos += chunk_len;
	}
}

static void de_run_cas(deark *c, de_module_params *mparams)
{
	do_cas(c);
	de_err(c, "Atari CAS format is not supported");
}

static int de_identify_cas(deark *c)
{
	u8 buf[16];
	de_read(buf, 0, 16);

	if(!de_memcmp(buf, "FUJI", 4)) {
		// Note - Make sure Fujifilm RAF has higher confidence.
		return 70;
	}
	return 0;
}

void de_module_atari_cas(deark *c, struct deark_module_info *mi)
{
	mi->id = "cas";
	mi->desc = "Atari CAS tape image format";
	mi->run_fn = de_run_cas;
	mi->identify_fn = de_identify_cas;
	mi->flags |= DE_MODFLAG_NONWORKING;
}

// --------------------------------------------

static int get_sector_offset_and_size(deark *c, lctx *d,
	i64 sector_num, i64 *sector_offset, i64 *sector_size)
{
	if(sector_num<1) return 0;

	*sector_size = d->sector_size;
	*sector_offset = (sector_num-1) * d->sector_size;

	if(d->sector_size==256) {
		// The first 3 sectors are 128 bytes
		if(sector_num<=3) {
			*sector_size = 128;
			*sector_offset = (sector_num-1) * 128;
		}
		else {
			*sector_offset -= 3*128;
		}
	}

	return 1;
}

static void do_extract_file_contents(deark *c, lctx *d, dbuf *inf, dbuf *outf,
	i64 starting_sector, i64 sector_count)
{
	i64 sectors_extracted = 0;
	i64 sector_pos = 0;
	i64 sector_size = 0;
	i64 cur_sector;
	i64 next_sector;
	u8 mdata[3];
	i64 nbytes;

	cur_sector = starting_sector;
	while(sectors_extracted < sector_count) {
		get_sector_offset_and_size(c, d, cur_sector, &sector_pos, &sector_size);
		de_dbg(c, "sector %d, #%d, at %d", (int)sectors_extracted, (int)cur_sector, (int)sector_pos);
		de_dbg_indent(c, 1);

		dbuf_read(inf, mdata, sector_pos + sector_size-3, 3);
		next_sector = ((mdata[0]&0x3) << 8) | mdata[1];

		// TODO: Some documentation says the high bit of mdata[2] is a
		// "short flag" that indicates that the other bits are valid. But I haven't
		// found any files that use it. And it can't work with sectors > 128 bytes.
		nbytes = (i64)mdata[2];
		if(sector_size<=128)
			nbytes = nbytes & 0x7f;

		de_dbg(c, "byte count: %d, next sector: %d", (int)nbytes, (int)next_sector);

		dbuf_copy(inf, sector_pos, nbytes, outf);

		de_dbg_indent(c, -1);
		sectors_extracted++;
		cur_sector = next_sector;
		if(next_sector<1) break;
	}
}

static void do_directory_entry(deark *c, lctx *d, dbuf *f, i64 pos)
{
	u8 flags;
	i64 sector_count;
	i64 starting_sector;
	de_ucstring *fn_u = NULL;
	de_ucstring *fn_ext = NULL;
	de_finfo *fi = NULL;
	dbuf *outf = NULL;

	flags = dbuf_getbyte(f, pos);
	de_dbg(c, "flags: 0x%02x", (unsigned int)flags);
	if((flags&0x40)==0) {
		// Unused or deleted directory entry
		return;
	}

	sector_count = dbuf_getu16le(f, pos+1);
	starting_sector = dbuf_getu16le(f, pos+3);
	de_dbg(c, "sector start: %d, count: %d", (int)starting_sector, (int)sector_count);

	if(starting_sector<1) goto done;

	if(starting_sector > 720) {
		de_err(c, "Bad starting sector: %d", (int)starting_sector);
		goto done;
	}
	if(sector_count > 720) {
		de_err(c, "Bad file size: %d blocks", (int)sector_count);
		goto done;
	}

	fn_u = ucstring_create(c);
	fn_ext = ucstring_create(c);

	// TODO: Use correct Atari encoding.
	dbuf_read_to_ucstring(f, pos+5, 8, fn_u, 0, DE_ENCODING_PRINTABLEASCII);
	dbuf_read_to_ucstring(f, pos+13, 3, fn_ext, 0, DE_ENCODING_PRINTABLEASCII);
	de_dbg(c, "filename: \"%s.%s\"",
		ucstring_getpsz(fn_u), ucstring_getpsz(fn_ext));
	ucstring_strip_trailing_spaces(fn_u);
	ucstring_strip_trailing_spaces(fn_ext);
	if(fn_u->len==0) {
		ucstring_append_char(fn_u, '_');
	}
	if(ucstring_isnonempty(fn_ext)) {
		ucstring_append_char(fn_u, '.');
		ucstring_append_ucstring(fn_u, fn_ext);
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, fn_u, 0);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	do_extract_file_contents(c, d, f, outf, starting_sector, sector_count);

done:
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn_u);
	ucstring_destroy(fn_ext);
	dbuf_close(outf);
}

static void do_disk_image(deark *c, lctx *d, dbuf *f)
{
	i64 sector_pos;
	i64 entrypos;
	i64 sector_size;
	i64 sector_index;
	i64 entry_index;
	i64 entries_per_sector;
	u8 flags;

	if(d->sector_size!=128 && d->sector_size!=256) {
		de_err(c, "Unsupported sector size: %d", (int)d->sector_size);
		return;
	}
	entries_per_sector = d->sector_size / 16;

	for(sector_index=0; sector_index<8; sector_index++) {
		get_sector_offset_and_size(c, d, 361+sector_index, &sector_pos, &sector_size);
		if(sector_pos + sector_size > f->len) break;
		de_dbg(c, "directory sector %d at %d", (int)sector_index, (int)sector_pos);
		de_dbg_indent(c, 1);
		for(entry_index=0; entry_index<entries_per_sector; entry_index++) {
			entrypos = sector_pos + 16*entry_index;

			// Peek at the flags byte, just to avoid printing debugging info
			// about nonexistent files
			flags = dbuf_getbyte(f, entrypos);
			if(flags==0x00) continue;

			de_dbg(c, "directory sector %d entry %d at %d", (int)sector_index,
				(int)entry_index, (int)entrypos);
			de_dbg_indent(c, 1);
			do_directory_entry(c, d, f, entrypos);
			de_dbg_indent(c, -1);
		}
		de_dbg_indent(c, -1);
	}
}

static void do_atr(deark *c, lctx *d)
{
	i64 pos;
	i64 image_size_hi, image_size_lo; // In 16-byte "paragraphs"
	i64 image_size_bytes;
	dbuf *diskimg = NULL;

	pos = 0;

	image_size_lo = de_getu16le(pos+2);
	d->sector_size = de_getu16le(pos+4);
	image_size_hi = de_getu16le(pos+6);
	image_size_bytes = 16*(image_size_lo + 65536*image_size_hi);

	de_dbg(c, "image size=%d bytes, sector size=%d", (int)image_size_bytes, (int)d->sector_size);

	diskimg = dbuf_open_input_subfile(c->infile, 16, c->infile->len-16);

	do_disk_image(c, d, diskimg);

	dbuf_close(diskimg);
}

static void de_run_atr(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	do_atr(c, d);

	de_free(c, d);
}

static int de_identify_atr(deark *c)
{
	u8 buf[16];
	de_read(buf, 0, 16);

	if(buf[0]==0x96 && buf[1]==0x02) {
		return 60;
	}
	return 0;
}

void de_module_atr(deark *c, struct deark_module_info *mi)
{
	mi->id = "atr";
	mi->desc = "ATR Atari floppy disk image format";
	mi->run_fn = de_run_atr;
	mi->identify_fn = de_identify_atr;
}
