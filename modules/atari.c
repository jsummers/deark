// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 sector_size;
} lctx;

static void do_cas(deark *c)
{
	de_int64 pos;
	de_byte chunk_id[4];
	de_int64 chunk_len;
	de_int64 chunk_extra;

	pos = 0;
	while(1) {
		if(pos >= c->infile->len-8) break; // Reached end of file

		de_read(chunk_id, pos, 4);
		chunk_len = de_getui16le(pos+4);
		chunk_extra = de_getui16le(pos+6);

		de_dbg(c, "chunk at %d, data_len=%d, extra=%d\n", (int)pos, (int)chunk_len,
			(int)chunk_extra);

		pos += 8;

		pos += chunk_len;
	}
}

static void de_run_cas(deark *c, de_module_params *mparams)
{
	do_cas(c);
	de_err(c, "Atari CAS format is not supported\n");
}

static int de_identify_cas(deark *c)
{
	de_byte buf[16];
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
	mi->run_fn = de_run_cas;
	mi->identify_fn = de_identify_cas;
	mi->flags |= DE_MODFLAG_NONWORKING;
}


// --------------------------------------------
static de_int64 space_padded_length(const de_byte *buf, de_int64 len)
{
	de_int64 i;
	de_int64 last_nonspace = -1;

	for(i=len-1; i>=0; i--) {
		if(buf[i]!=0x20) {
			last_nonspace = i;
			break;
		}
	}
	return last_nonspace+1;
}

static void do_extract_file_contents(deark *c, lctx *d, dbuf *inf, dbuf *outf,
	de_int64 starting_sector, de_int64 sector_count)
{
	de_int64 sectors_extracted = 0;
	de_int64 sectorpos;
	de_int64 cur_sector;
	de_int64 next_sector;
	de_byte mdata[3];
	de_int64 nbytes;
	int short_flag;

	cur_sector = starting_sector;
	while(sectors_extracted < sector_count) {
		sectorpos = (cur_sector-1) * d->sector_size;
		de_dbg(c, "sector %d, #%d, at %d\n", (int)sectors_extracted, (int)cur_sector, (int)sectorpos);
		de_dbg_indent(c, 1);

		dbuf_read(inf, mdata, sectorpos + 125, 3);
		next_sector = ((mdata[0]&0x3) << 8) | mdata[1];

		// This flag doesn't appear to be used as advertised.
		short_flag = (mdata[2] & 0x80)?1:0;

		nbytes = (de_int64)(mdata[2]&0x7f);
		de_dbg(c, "byte count: %d, S: %d, next sector: %d\n", (int)nbytes, short_flag,
			(int)next_sector);

		dbuf_copy(inf, sectorpos, nbytes, outf);

		de_dbg_indent(c, -1);
		sectors_extracted++;
		cur_sector = next_sector;
		if(next_sector<1) break;
	}
}

static void do_directory_entry(deark *c, lctx *d, dbuf *f, de_int64 pos)
{
	de_byte flags;
	de_int64 sector_count;
	de_int64 starting_sector;
	de_int64 i;
	de_byte fn_raw[11];
	de_int64 fnbase_len, fnext_len;
	de_ucstring *fn_u = NULL;
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	de_int32 ch;

	flags = dbuf_getbyte(f, pos);
	de_dbg(c, "flags: 0x%02x\n", (unsigned int)flags);
	if((flags&0x40)==0) {
		// Unused or deleted directory entry
		return;
	}

	sector_count = dbuf_getui16le(f, pos+1);
	starting_sector = dbuf_getui16le(f, pos+3);
	de_dbg(c, "sector start: %d, count: %d\n", (int)starting_sector, (int)sector_count);

	if(sector_count > 720) {
		de_err(c, "Bad file size\n");
		goto done;
	}
	if(starting_sector > 720) {
		de_err(c, "Bad starting sector\n");
		goto done;
	}

	// Read filename
	dbuf_read(f, fn_raw, pos+5, 11);

	fnbase_len = space_padded_length(fn_raw, 8);
	// Not sure what to do with an empty filename
	if(fnbase_len<1) {
		fn_raw[0] = '_';
		fnbase_len=1;
	}
	fnext_len = space_padded_length(fn_raw+8, 3);

	fn_u = ucstring_create(c);
	for(i=0; i<(8+fnext_len); i++) {
		if(i<8 && i>=fnbase_len) continue;
		if(i==8) {
			ucstring_append_char(fn_u, '.');
		}

		// TODO: Use correct Atari encoding.
		ch = (de_int32)fn_raw[i];

		if(ch<32 || ch>126) ch='_';
		ch = de_char_to_valid_fn_char(c, ch);
		ucstring_append_char(fn_u, ch);
	}

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, fn_u);

	outf = dbuf_create_output_file(c, NULL, fi);

	do_extract_file_contents(c, d, f, outf, starting_sector, sector_count);

done:
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn_u);
	dbuf_close(outf);
}

static void do_disk_image(deark *c, lctx *d, dbuf *f)
{
	de_int64 dirpos;
	de_int64 entrypos;
	de_int64 sector_index;
	de_int64 entry_index;
	de_byte flags;

	if(d->sector_size != 128) return;

	for(sector_index=0; sector_index<8; sector_index++) {
		dirpos = (360 + sector_index) * d->sector_size;
		de_dbg(c, "directory sector %d at %d\n", (int)sector_index, (int)dirpos);
		de_dbg_indent(c, 1);
		for(entry_index=0; entry_index<8; entry_index++) {
			entrypos = dirpos + 16*entry_index;

			// Peek at the flags byte, just to avoid printing debugging info
			// about nonexistent files
			flags = dbuf_getbyte(f, entrypos);
			if(flags==0x00) continue;

			de_dbg(c, "directory sector %d entry %d at %d\n", (int)sector_index,
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
	de_int64 pos;
	de_int64 image_size_hi, image_size_lo; // In 16-byte "paragraphs"
	de_int64 image_size_bytes;
	dbuf *diskimg = NULL;

	pos = 0;

	image_size_lo = de_getui16le(pos+2);
	d->sector_size = de_getui16le(pos+4);
	image_size_hi = de_getui16le(pos+6);
	image_size_bytes = 16*(image_size_lo + 65536*image_size_hi);

	de_dbg(c, "image size=%d bytes, sector size=%d\n", (int)image_size_bytes, (int)d->sector_size);

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
	de_byte buf[16];
	de_read(buf, 0, 16);

	if(buf[0]==0x96 && buf[1]==0x02) {
		return 60;
	}
	return 0;
}

void de_module_atr(deark *c, struct deark_module_info *mi)
{
	mi->id = "atr";
	mi->run_fn = de_run_atr;
	mi->identify_fn = de_identify_atr;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
