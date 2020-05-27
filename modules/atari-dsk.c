// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_atari_cas);
DE_DECLARE_MODULE(de_module_atr);
DE_DECLARE_MODULE(de_module_msa);
DE_DECLARE_MODULE(de_module_pasti);

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
	de_ext_encoding fn_encoding;

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
	fn_encoding = DE_EXTENC_MAKE(DE_ENCODING_ASCII, DE_ENCSUBTYPE_PRINTABLE);
	dbuf_read_to_ucstring(f, pos+5, 8, fn_u, 0,fn_encoding);
	dbuf_read_to_ucstring(f, pos+13, 3, fn_ext, 0, fn_encoding);
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

////////////////////////////////////////////////////////
// MSA - Magic Shadow Archiver - Atari ST disk image

enum atarist_outfmt {
	ATARIST_OUTFMT_FILES = 0,
	ATARIST_OUTFMT_ST,
	ATARIST_OUTFMT_UNCMSA
};

struct msactx {
	de_encoding input_encoding;
	enum atarist_outfmt outfmt;
	i64 sectors_per_track;
	i64 sides;
	i64 first_track;
	i64 last_track;
	i64 num_tracks_per_side;
	i64 num_tracks_total;
	i64 track_size; // bytes per track per side
	i64 disk_size;
	i64 total_track_sides;
	i64 total_track_sides_cmpr;
	i64 total_cmpr_bytes;
	i64 total_uncmpr_bytes;
};

// Decompress one track
static int msa_decompress_rle(deark *c, struct msactx *d, i64 pos1, i64 dlen,
	dbuf *outf)
{
	i64 endpos = pos1+dlen;
	i64 pos = pos1;
	i64 outcount = 0;
	int retval = 0;

	while(1) {
		u8 b;
		i64 count;

		if(outcount >= d->track_size) {
			retval = 1;
			goto done; // Have enough output
		}

		if(pos >= endpos) {
			goto done;
		}

		b = de_getbyte_p(&pos);
		if(b != 0xe5) {
			dbuf_writebyte(outf, b);
			outcount++;
			continue;
		}

		if(pos+3 > endpos) {
			goto done;
		}
		b = de_getbyte_p(&pos);
		count = de_getu16be_p(&pos);
		if(outcount+count > d->track_size) {
			count = d->track_size - outcount;
		}
		dbuf_write_run(outf, b, count);
		outcount += count;
	}

done:
	if(!retval) {
		de_err(c, "Decompression failed");
	}
	return retval;
}

static int do_msa_track(deark *c, struct msactx *d, i64 tk, i64 sd, i64 pos1, i64 dlen, dbuf *outf)
{
	int is_compressed;
	int retval = 0;
	i64 outf_startsize = outf->len;

	de_dbg2(c, "track (t=%d, s=%d) at %"I64_FMT", dlen=%"I64_FMT, (int)tk, (int)sd, pos1, dlen);
	de_dbg_indent(c, 1);
	if(dlen > d->track_size) {
		de_err(c, "Invalid compressed track size");
		goto done;
	}
	is_compressed = (dlen!=d->track_size);
	de_dbg2(c, "compressed: %d", is_compressed);

	if(is_compressed) {
		if(!msa_decompress_rle(c, d, pos1+2, dlen, outf)) goto done;
		d->total_track_sides_cmpr++;
	}
	else {
		dbuf_copy(c->infile, pos1+2, dlen, outf);
	}
	d->total_cmpr_bytes += dlen;
	d->total_track_sides++;

	dbuf_truncate(outf, outf_startsize + d->track_size);
	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_msa_header(deark *c, struct msactx *d, i64 pos1)
{
	i64 pos;
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1+2;
	d->sectors_per_track = de_getu16be_p(&pos);
	de_dbg(c, "sectors/track: %d", (int)d->sectors_per_track);
	d->sides = 1 + de_getu16be_p(&pos);
	de_dbg(c, "sides: %d", (int)d->sides);
	d->first_track = de_getu16be_p(&pos);
	de_dbg(c, "first track: %d", (int)d->first_track);
	d->last_track = de_getu16be_p(&pos);
	de_dbg(c, "last track: %d", (int)d->last_track);

	d->num_tracks_per_side = d->last_track - d->first_track + 1;
	if(d->sides<1 || d->sides>2) goto done;
	if(d->sectors_per_track<1 || d->sectors_per_track>30) goto done;
	d->num_tracks_total = d->num_tracks_per_side * d->sides;
	if(d->num_tracks_total<1 || d->num_tracks_total>200) goto done;
	d->track_size = d->sectors_per_track * 512;
	d->disk_size = d->track_size * d->num_tracks_total;
	retval = 1;

done:
	if(!retval) {
		de_err(c, "Bad or unsupported disk layout");
	}
	de_dbg_indent(c, -1);
	return retval;
}

static int do_msa_tracks(deark *c, struct msactx *d, i64 pos1, dbuf *diskbuf)
{
	i64 tk, sd;
	i64 pos = pos1;
	int retval = 0;

	de_dbg(c, "tracks at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	for(tk=d->first_track; tk<=d->last_track; tk++) {
		for(sd=0; sd<d->sides; sd++) {
			i64 dlen;
			i64 tkpos = pos;

			if(pos+2 >= c->infile->len) {
				de_err(c, "Unexpected end of file");
				goto after_decompress;
			}

			dlen = de_getu16be_p(&pos);
			if(!do_msa_track(c, d, tk, sd, tkpos, dlen, diskbuf)) goto done;
			pos += dlen;
		}
	}
after_decompress:
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void msa_decode_fat(deark *c, struct msactx *d, dbuf *diskbuf)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	de_dbg(c, "decoding as FAT");
	de_dbg_indent(c, 1);
	mparams->in_params.codes = "A";
	mparams->in_params.input_encoding = d->input_encoding;
	de_run_module_by_id_on_slice(c, "fat", mparams, diskbuf, 0, diskbuf->len);
	if(mparams->out_params.flags & 0x1) {
		de_info(c, "Note: Use \"-opt msa:toraw\" to decompress to a raw .ST file");
	}
	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void msa_extract_to_raw(deark *c, struct msactx *d, dbuf *diskbuf)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "st", NULL, 0);
	dbuf_copy(diskbuf, 0, d->disk_size, outf);
	dbuf_close(outf);
}

static void msa_extract_to_uncmsa(deark *c, struct msactx *d, dbuf *diskbuf)
{
	dbuf *outf = NULL;
	i64 i;

	outf = dbuf_create_output_file(c, "msa", NULL, 0);
	dbuf_copy(c->infile, 0, 10, outf);

	for(i=0; i<d->num_tracks_total; i++) {
		dbuf_writeu16be(outf, d->track_size);
		dbuf_copy(diskbuf, i*d->track_size, d->track_size, outf);
	}

	dbuf_close(outf);
}

static void de_run_msa(deark *c, de_module_params *mparams)
{
	struct msactx *d = NULL;
	dbuf *diskbuf = NULL;

	d = de_malloc(c, sizeof(struct msactx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ATARIST);

	if(de_get_ext_option_bool(c, "msa:touncmsa", 0)) {
		d->outfmt = ATARIST_OUTFMT_UNCMSA;
	}
	else if(de_get_ext_option_bool(c, "msa:toraw", 0)) {
		d->outfmt = ATARIST_OUTFMT_ST;
	}
	else {
		d->outfmt = ATARIST_OUTFMT_FILES;
	}

	if(!do_msa_header(c, d, 0)) goto done;

	diskbuf = dbuf_create_membuf(c, d->disk_size, 0x1);

	if(!do_msa_tracks(c, d, 10, diskbuf)) goto done;

	d->total_uncmpr_bytes = diskbuf->len;
	de_dbg(c, "totals: %u track-sides, %u compressed",
		(UI)d->total_track_sides, (UI)d->total_track_sides_cmpr);
	de_dbg(c, "totals: decompressed %"I64_FMT" bytes to %"I64_FMT,
		d->total_cmpr_bytes, d->total_uncmpr_bytes);

	if(d->outfmt==ATARIST_OUTFMT_ST) {
		msa_extract_to_raw(c, d, diskbuf);
	}
	else if(d->outfmt==ATARIST_OUTFMT_UNCMSA) {
		msa_extract_to_uncmsa(c, d, diskbuf);
	}
	else {
		msa_decode_fat(c, d, diskbuf);
	}

done:
	de_free(c, d);
}

static int de_identify_msa(deark *c)
{
	i64 sig;
	int has_ext;

	sig = de_getu16be(0);
	if(sig != 0x0e0f) return 0;
	has_ext = de_input_file_has_ext(c, "msa");
	if(has_ext) return 100;
	return 45;
}

static void de_help_msa(deark *c)
{
	de_msg(c, "-opt msa:toraw : Extract to raw .ST format");
	de_msg(c, "-opt msa:touncmsa : Convert to uncompressed MSA");
}

void de_module_msa(deark *c, struct deark_module_info *mi)
{
	mi->id = "msa";
	mi->desc = "MSA - Atari ST floppy disk image format";
	mi->run_fn = de_run_msa;
	mi->identify_fn = de_identify_msa;
	mi->help_fn = de_help_msa;
}

////////////////////////////////////////////////////////
// Pasti / (.STX) - Atari ST disk image

#define PASTI_MAX_SECTORS_PER_TRACK 100
#define PASTI_MAX_TRACK_NUM 255

struct pasti_sector_ctx {
	i64 data_offset_abs;
	i64 size_in_bytes;
	i64 n_track, n_head, n_secnum; // The sector's self-reported data
	u8 fdcFlags;
	u32 crc_reported;
};

struct pasti_track_ctx {
	i64 track_num;
	i64 side_num;

	i64 fuzzy_count;
	i64 sector_count;

#define TRK_SYNC    0x0080
#define TRK_IMAGE   0x0040
#define TRK_PROT    0x0020
#define TRK_SECT    0x0001
	UI track_flags;

	i64 track_length;
	i64 sector_descriptors_pos;
	i64 track_data_record_pos;
};

struct pastictx {
	de_encoding input_encoding;
	enum atarist_outfmt outfmt;

	UI version;
	UI revision;
	i64 track_count;

	i64 fat_bytes_per_sector;
	i64 fat_sectors_per_track;
	i64 fat_num_heads;

	// Set if we can't convert the format to FAT, but maybe can continue decoding
	// the Pasti structure.
	int convert_errflag;

	i64 num_nonempty_sectors_found;
	i64 oob_sector_count;

	dbuf *diskbuf;
};

static void pasti_save_sector_data(deark *c, struct pastictx *d,
	struct pasti_sector_ctx *secctx, i64 trknum, i64 sidenum)
{
	i64 dstpos;
	i64 len_to_copy;

	if(d->convert_errflag || secctx->size_in_bytes<=0) goto done;
	de_dbg2(c, "[recording sector %d,%d,%d]", (int)trknum, (int)sidenum,
		(int)secctx->n_secnum);

	d->num_nonempty_sectors_found++;
	if(trknum<0 || trknum>PASTI_MAX_TRACK_NUM ||
		sidenum<0 || sidenum>=d->fat_num_heads ||
		secctx->n_secnum<1 || secctx->n_secnum>d->fat_sectors_per_track)
	{
		de_dbg2(c, "[sector out of bounds]");
		d->oob_sector_count++;
		goto done;
	}

	if(!d->diskbuf) {
		d->diskbuf = dbuf_create_membuf(c, 0, 0);
	}

	dstpos =
		(d->fat_bytes_per_sector * d->fat_sectors_per_track * d->fat_num_heads) * trknum +
		(d->fat_bytes_per_sector * d->fat_sectors_per_track) * sidenum +
		(d->fat_bytes_per_sector) * (secctx->n_secnum-1);

	if(secctx->size_in_bytes > d->fat_bytes_per_sector) {
		de_warn(c, "Oversized sector");
		len_to_copy = d->fat_bytes_per_sector;
	}
	else {
		len_to_copy = secctx->size_in_bytes;
	}

	dbuf_copy_at(c->infile, secctx->data_offset_abs, len_to_copy, d->diskbuf, dstpos);

done:
	;
}

static int do_pasti_sectors(deark *c, struct pastictx *d, struct pasti_track_ctx *tctx)
{
	int saved_indent_level;
	int retval = 0;
	i64 secnum;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "[%d sector descriptors at %"I64_FMT"]", (int)tctx->sector_count,
		tctx->sector_descriptors_pos);
	de_dbg_indent(c, 1);

	for(secnum=0; secnum<tctx->sector_count; secnum++) {
		i64 data_offset_rel;
		u8 size_code;
		i64 pos = tctx->sector_descriptors_pos + secnum*16;
		struct pasti_sector_ctx secctx;

		de_dbg2(c, "sector[%d] descriptor at %"I64_FMT, (int)secnum, pos);
		de_dbg_indent(c, 1);
		de_zeromem(&secctx, sizeof(struct pasti_sector_ctx));
		data_offset_rel = de_getu32le_p(&pos);
		secctx.data_offset_abs = tctx->track_data_record_pos + data_offset_rel;
		de_dbg2(c, "dataOffset: %"I64_FMT" (+%"I64_FMT"=%"I64_FMT")", data_offset_rel,
			tctx->track_data_record_pos, secctx.data_offset_abs);
		pos += 2; // bitPosition
		pos += 2; // readTime

		secctx.n_track = (i64)de_getbyte_p(&pos);
		secctx.n_head = (i64)de_getbyte_p(&pos);
		secctx.n_secnum = (i64)de_getbyte_p(&pos);
		de_dbg2(c, "track %d, side %d, sector %d", (int)secctx.n_track,
			(int)secctx.n_head, (int)secctx.n_secnum);
		// TODO: What should we do if the track and head are not the expected values?
		// Who do we trust?

		size_code = de_getbyte_p(&pos);
		if(size_code>4) goto done;
		secctx.size_in_bytes = ((i64)128)<<(UI)size_code;
		de_dbg2(c, "size: 0x%02x (%"I64_FMT" bytes)", (UI)size_code, secctx.size_in_bytes);

		secctx.crc_reported = (u32)de_getu16le_p(&pos);
		de_dbg2(c, "sector crc (reported): 0x%04x", (UI)secctx.crc_reported);
		secctx.fdcFlags = de_getbyte_p(&pos);
		de_dbg2(c, "fdcFlags: 0x%02x", (UI)secctx.fdcFlags);
		pos += 1; // reserved

		pasti_save_sector_data(c, d, &secctx, tctx->track_num, tctx->side_num);
		de_dbg_indent(c, -1);
	}

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// There's a chicken-and-egg problem, as we need information contained
// in the boot sector (especially the number of sectors per track),
// before we can effectively process the sectors.
// This function looks ahead to get the information. It duplicates some of
// the code in this module, and in the "fat" module.
static void pasti_find_and_read_boot_sector(deark *c, struct pastictx *d,
	struct pasti_track_ctx *tctx)
{
	i64 secnum;
	i64 s1pos = 0; // sector 1 abs pos, 0 if unknown

	for(secnum=0; secnum<tctx->sector_count; secnum++) {
		i64 data_offset_rel;
		i64 n_secnum;
		i64 pos = tctx->sector_descriptors_pos + secnum*16;

		n_secnum = (i64)de_getbyte(pos + 10);
		if(n_secnum == 1) {
			data_offset_rel = de_getu32le(pos);
			s1pos = tctx->track_data_record_pos + data_offset_rel;
			break;
		}
	}

	if(s1pos==0) {
		de_err(c, "Could not find boot sector");
		d->convert_errflag = 1;
		goto done;
	}

	de_dbg(c, "found boot sector; data at %"I64_FMT, s1pos);
	de_dbg_indent(c, 1);
	d->fat_bytes_per_sector = de_getu16le(s1pos+11);
	de_dbg(c, "bytes per sector: %d", (int)d->fat_bytes_per_sector);
	d->fat_sectors_per_track = de_getu16le(s1pos+24);
	de_dbg(c, "sectors per track: %d", (int)d->fat_sectors_per_track);
	d->fat_num_heads = de_getu16le(s1pos+26);
	de_dbg(c, "number of heads: %d", (int)d->fat_num_heads);

	de_dbg_indent(c, -1);

	if(d->fat_bytes_per_sector<128 || d->fat_bytes_per_sector>2048 ||
		d->fat_sectors_per_track<1 || d->fat_sectors_per_track>32 ||
		d->fat_num_heads<1 || d->fat_num_heads>2)
	{
		de_err(c, "Invalid or unsupported disk geometry (%d sectors/track, "
			"%d heads, %d bytes/sector)", (int)d->fat_sectors_per_track,
			(int)d->fat_num_heads, (int)d->fat_bytes_per_sector);
		d->convert_errflag = 1;
		goto done;
	}

done:
	;
}

static int do_pasti_track(deark *c, struct pastictx *d, i64 trkidx, i64 pos1, i64 len)
{
	i64 pos = pos1;
	u8 track_number_raw;
	struct pasti_track_ctx *tctx = NULL;
	int retval = 0;

	de_dbg(c, "track record[%d] at %"I64_FMT", len=%"I64_FMT, (int)trkidx, pos1, len);
	de_dbg_indent(c, 1);

	tctx = de_malloc(c, sizeof(struct pasti_track_ctx));
	pos = pos1;
	pos += 4; // record size, already read

	tctx->fuzzy_count = de_getu32le_p(&pos);
	de_dbg(c, "fuzzyCount: %"I64_FMT, tctx->fuzzy_count);
	tctx->sector_count = de_getu16le_p(&pos);
	de_dbg(c, "sectorCount: %"I64_FMT, tctx->sector_count);
	if(tctx->sector_count > PASTI_MAX_SECTORS_PER_TRACK) {
		goto done;
	}

	tctx->track_flags = (UI)de_getu16le_p(&pos);
	de_dbg(c, "trackFlags: 0x%02x", tctx->track_flags);

	tctx->track_length = de_getu16le_p(&pos);
	de_dbg(c, "trackLength: %"I64_FMT, tctx->track_length);

	track_number_raw = de_getbyte_p(&pos);
	tctx->track_num = (i64)(track_number_raw & 0x7f);
	tctx->side_num = (i64)(track_number_raw>>7);
	de_dbg(c, "trackNumber: 0x%02x (track %u, side %u)", (UI)track_number_raw,
		(UI)tctx->track_num, (UI)tctx->side_num);

	pos += 1; // trackType, unused

	if(tctx->track_flags & TRK_SECT) {
		tctx->sector_descriptors_pos = pos;
		pos += 16 * tctx->sector_count;
	}

	pos += tctx->fuzzy_count;

	tctx->track_data_record_pos = pos;

	if(!(tctx->track_flags & TRK_SECT)) {
		// TODO: Support this
		de_err(c, "Pasti files without sector descriptors are not supported");
		goto done;
	}

	if(trkidx==0) {
		// Special handling for the first track in the file

		if(track_number_raw == 0x00) {
			pasti_find_and_read_boot_sector(c, d, tctx);
		}
		else {
			de_err(c, "First track in file is not track 0/side 0; can't convert this file");
			d->convert_errflag = 1;
		}
	}

	if(tctx->sector_count>0) {
		if(!do_pasti_sectors(c, d, tctx)) goto done;
	}

	retval = 1;
done:
	if(tctx) {
		de_free(c, tctx);
	}
	de_dbg_indent(c, -1);
	return retval;
}

static int do_pasti_tracks(deark *c, struct pastictx *d, i64 pos1)
{
	i64 trkidx;
	i64 pos = pos1;
	int retval = 0;

	for(trkidx=0; trkidx<d->track_count; trkidx++) {
		i64 recsize;

		if(pos+16 > c->infile->len) goto done;
		recsize = de_getu32le(pos);
		if(recsize<16) goto done;
		if(!do_pasti_track(c, d, trkidx, pos, recsize)) goto done;
		pos += recsize;
	}
	retval = 1;
done:
	if(!retval) {
		de_err(c, "Bad data or unexpected end of file");
	}
	return retval;
}

static int do_pasti_header(deark *c, struct pastictx *d, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;

	de_dbg(c, "file descriptor at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos += 4; // signature
	d->version = (UI)de_getu16le_p(&pos);
	de_dbg(c, "version: %u", d->version);
	pos += 2; // tool
	pos += 2; // reserved_1
	d->track_count = (i64)de_getbyte_p(&pos);
	de_dbg(c, "track count: %d", (int)d->track_count);
	d->revision = (UI)de_getbyte_p(&pos);
	de_dbg(c, "revision: %u", d->revision);
	if(d->version!=3 || d->revision!=2) {
		de_err(c, "Unsupported format version: %ur%u", d->version, d->revision);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void pasti_decode_fat(deark *c, struct pastictx *d)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	de_dbg(c, "decoding as FAT");
	de_dbg_indent(c, 1);
	mparams->in_params.codes = "A";
	mparams->in_params.input_encoding = d->input_encoding;
	de_run_module_by_id_on_slice(c, "fat", mparams, d->diskbuf, 0, d->diskbuf->len);
	if(mparams->out_params.flags & 0x1) {
		de_info(c, "Note: Use \"-opt pasti:toraw\" to decompress to a raw .ST file");
	}
	de_free(c, mparams);
	de_dbg_indent(c, -1);
}

static void pasti_extract_to_raw(deark *c, struct pastictx *d)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "st", NULL, 0);
	dbuf_copy(d->diskbuf, 0, d->diskbuf->len, outf);
	dbuf_close(outf);
}

static void de_run_pasti(deark *c, de_module_params *mparams)
{
	struct pastictx *d = NULL;

	d = de_malloc(c, sizeof(struct pastictx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ATARIST);

	if(de_get_ext_option_bool(c, "pasti:toraw", 0)) {
		d->outfmt = ATARIST_OUTFMT_ST;
	}
	else {
		d->outfmt = ATARIST_OUTFMT_FILES;
	}

	if(!do_pasti_header(c, d, 0)) goto done;

	if(!do_pasti_tracks(c, d, 16)) goto done;
	if(!d->diskbuf) goto done;

	if(d->oob_sector_count>0) {
		de_warn(c, "%d of %d sectors are outside the bounds of the disk geometry, and will "
			"be ignored.", (int)d->oob_sector_count, (int)d->num_nonempty_sectors_found);
	}

	if(d->num_nonempty_sectors_found<=0) goto done;

	if(d->outfmt==ATARIST_OUTFMT_ST) {
		pasti_extract_to_raw(c, d);
	}
	else {
		pasti_decode_fat(c, d);
	}

done:
	if(d) {
		dbuf_close(d->diskbuf);
		de_free(c, d);
	}
}

static int de_identify_pasti(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "RSY\0", 4))
		return 100;
	return 0;
}

static void de_help_pasti(deark *c)
{
	de_msg(c, "-opt pasti:toraw : Extract to raw .ST format");
}

void de_module_pasti(deark *c, struct deark_module_info *mi)
{
	mi->id = "pasti";
	mi->desc = "Pasti - Atari ST floppy disk image format";
	mi->run_fn = de_run_pasti;
	mi->identify_fn = de_identify_pasti;
	mi->help_fn = de_help_pasti;
}
