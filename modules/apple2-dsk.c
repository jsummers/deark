// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Apple II disk image formats, etc.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_apple2_dsk);
DE_DECLARE_MODULE(de_module_woz);

struct trksec_pair {
	u8 tr;
	u8 se;
};

struct member_data {
	UI first_sec_list_tr;
	UI first_sec_list_se;
	i64 len_in_sectors;
	i64 num_data_sectors;
	u8 file_type_and_flags;
	de_ucstring *fn;
	de_finfo *fi;
	struct trksec_pair *sector_list; // array[len_in_sectors]
};

typedef struct localctx_struct {
	i64 secsize;
	i64 ntracks;
	i64 sectors_per_track;
	UI catalog_tr;
	UI catalog_se;
	UI sector_list_sector_capacity;
	u8 *sector_used_flags; // array[ntracks * sectors_per_track]
} lctx;

static i64 trksec_to_offset(lctx *d, UI tr, UI se)
{
	return (((i64)tr * d->sectors_per_track) + (i64)se) * d->secsize;
}

static int claim_sector(deark *c, lctx *d, UI tr, UI se)
{
	i64 idx;

	if((i64)tr>d->ntracks || (i64)se>d->sectors_per_track) {
		de_err(c, "Bad sector ID: %u,%u", tr, se);
		return 0;
	}
	idx = (i64)tr * d->sectors_per_track + (i64)se;
	if(d->sector_used_flags[idx]) {
		de_err(c, "Attempt to reuse sector: %u,%u", tr, se);
		return 0;
	}
	d->sector_used_flags[idx] = 1;
	return 1;
}

static void do_read_VTOC(deark *c, lctx *d, UI tr, UI se)
{
	i64 pos1 = trksec_to_offset(d, tr, se);
	i64 pos = pos1;
	int n;

	de_dbg(c, "VTOC at %u,%u (%"I64_FMT")", tr, se, pos1);
	de_dbg_indent(c, 1);
	pos++;
	d->catalog_tr = (UI)de_getbyte_p(&pos);
	d->catalog_se = (UI)de_getbyte_p(&pos);
	de_dbg(c, "catalog trk,sec: %u,%u", d->catalog_tr, d->catalog_se);
	n = (int)de_getbyte_p(&pos);
	de_dbg(c, "created by DOS ver: %d", n);
	pos += 2; // unused
	n = (int)de_getbyte_p(&pos);
	de_dbg(c, "volume num: %d", n);
	// 7-38  unused
	pos = pos1 + 39;
	n = (int)de_getbyte_p(&pos);
	de_dbg(c, "items per sector list sector: %d", n);
	// 40-47 unused
	pos = pos1 + 48;
	pos++; // last track with allocated sectors
	pos++; // direction of allocation
	pos += 2; // unused
	n = (int)de_getbyte_p(&pos);
	de_dbg(c, "num tracks: %d", n);
	n = (int)de_getbyte_p(&pos);
	de_dbg(c, "sectors/track: %d", n);
	n = (int)de_getu16le_p(&pos);
	de_dbg(c, "bytes/sector: %d", n);
	de_dbg_indent(c, -1);
}

static void a2_read_filename(lctx *d, dbuf *inf, i64 pos, de_ucstring *fn)
{
	UI i;
	u8 namebuf[30];

	dbuf_read(inf, namebuf, pos, 30);
	for(i=0; i<30; i++) {
		namebuf[i] &= 63;
		if(namebuf[i] < 32) namebuf[i] += 64;
	}
	ucstring_append_bytes(fn, namebuf, 30, 0x0, DE_ENCODING_LATIN1);
	ucstring_strip_trailing_spaces(fn);
}

static int read_sector_list(deark *c, lctx *d, struct member_data *md)
{
	int retval = 0;
	UI seclist_tr = 0;
	UI seclist_se = 0;
	UI next_seclist_tr, next_seclist_se;
	UI items_left_in_this_seclist_sector;
	i64 dsidx = 0; // Data sector index (# of data sectors found)
	i64 curpos = 0;
	i64 num_sectors_remaining;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(md->len_in_sectors > d->ntracks * d->secsize) {
		de_err(c, "Bad file size");
		goto done;
	}

	// We alloc enough space for all sectors, but only the *data* sectors will actually
	// be stored in sector_list.
	md->sector_list = de_mallocarray(c, md->len_in_sectors, sizeof(struct trksec_pair));

	next_seclist_tr = md->first_sec_list_tr;
	next_seclist_se = md->first_sec_list_se;
	items_left_in_this_seclist_sector = 0;

	// Note that, apparently, len_in_sectors includes the sector_list sectors.
	num_sectors_remaining = md->len_in_sectors;

	de_dbg_indent(c, 1);
	while(num_sectors_remaining>0) {
		if(items_left_in_this_seclist_sector==0) {
			seclist_tr = next_seclist_tr;
			seclist_se = next_seclist_se;
			curpos = trksec_to_offset(d, seclist_tr, seclist_se);
			de_dbg_indent(c, -1);
			de_dbg(c, "sector list sector: %u,%u (%"I64_FMT")", seclist_tr, seclist_se,
				curpos);
			de_dbg_indent(c, 1);
			if(seclist_tr==0) {
				de_err(c, "Bad sector list");
				goto done;
			}
			if(!claim_sector(c, d, seclist_tr, seclist_se)) goto done;
			num_sectors_remaining--;
			curpos++;
			next_seclist_tr = de_getbyte_p(&curpos);
			next_seclist_se = de_getbyte_p(&curpos);
			de_dbg(c, "next sector list sector: %u,%u", (UI)next_seclist_tr, (UI)next_seclist_se);
			curpos += 2; // unused
			curpos += 2; // first sector described by this list (?)
			curpos += 5; // unused

			items_left_in_this_seclist_sector = d->sector_list_sector_capacity;
		}
		if(num_sectors_remaining<1) break;

		md->sector_list[dsidx].tr = de_getbyte_p(&curpos);
		md->sector_list[dsidx].se = de_getbyte_p(&curpos);
		de_dbg2(c, "found data sector: %u,%u",
			md->sector_list[dsidx].tr, md->sector_list[dsidx].se);
		items_left_in_this_seclist_sector--;

		if(md->sector_list[dsidx].tr==0 && md->sector_list[dsidx].se==0) {
			// TODO: How to determine the expected file size
			de_warn(c, "%s: Expected more data sectors than were found. "
				"This may or may not indicate a problem.", ucstring_getpsz_d(md->fn));
			break;
		}

		if(!claim_sector(c, d, md->sector_list[dsidx].tr, md->sector_list[dsidx].se)) {
			goto done;
		}
		dsidx++;
		num_sectors_remaining--;
	}

	de_dbg_indent_restore(c, saved_indent_level);
	md->num_data_sectors = dsidx;
	de_dbg(c, "data sectors found: %"I64_FMT, md->num_data_sectors);
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	i64 i;

	if(!read_sector_list(c, d, md)) goto done;
	if(!md->sector_list) goto done;

	de_finfo_set_name_from_ucstring(c, md->fi, md->fn, 0);
	md->fi->original_filename_flag = 1;
	outf = dbuf_create_output_file(c, NULL, md->fi, 0);

	for(i=0; i<md->num_data_sectors; i++) {
		i64 secpos;

		secpos = trksec_to_offset(d, md->sector_list[i].tr, md->sector_list[i].se);
		de_dbg2(c, "extracting data sector: %u,%u (%"I64_FMT")",
			md->sector_list[i].tr, md->sector_list[i].se, secpos);
		dbuf_copy(c->infile, secpos, 256, outf);
	}

done:
	dbuf_close(outf);
}

static void do_file_entry(deark *c, lctx *d, i64 pos1)
{
	int saved_indent_level;
	i64 pos = pos1;
	struct member_data *md = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	md = de_malloc(c, sizeof(struct member_data));
	de_dbg(c, "file entry at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md->fi = de_finfo_create(c);

	md->first_sec_list_tr = (UI)de_getbyte_p(&pos);
	if(md->first_sec_list_tr==0) {
		de_dbg(c, "unused");
		goto done;
	}
	else if(md->first_sec_list_tr==0xff) {
		de_dbg(c, "deleted");
		goto done;
	}

	md->first_sec_list_se = (UI)de_getbyte_p(&pos);
	de_dbg(c, "sector list start: %u,%u",
		md->first_sec_list_tr, md->first_sec_list_se);

	md->file_type_and_flags = de_getbyte_p(&pos);
	de_dbg(c, "file type/flags: 0x%02x", (UI)md->file_type_and_flags);

	md->fn = ucstring_create(c);
	a2_read_filename(d, c->infile, pos, md->fn);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->fn));
	pos += 30;

	md->len_in_sectors = de_getu16le_p(&pos);
	de_dbg(c, "number of sectors: %"I64_FMT, md->len_in_sectors);

	do_extract_file(c, d, md);
done:
	if(md) {
		de_finfo_destroy(c, md->fi);
		ucstring_destroy(md->fn);
		de_free(c, md->sector_list);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_catalog_sector(deark *c, lctx *d, UI tr, UI se, UI *pnext_tr, UI *pnext_se)
{
	i64 pos1;
	i64 i;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	pos1 = trksec_to_offset(d, tr, se);
	de_dbg(c, "catalog sector: %u,%u (%"I64_FMT")", tr, se, pos1);
	de_dbg_indent(c, 1);
	if(!claim_sector(c, d, tr, se)) goto done;
	*pnext_tr = (UI)de_getbyte(pos1+1);
	*pnext_se = (UI)de_getbyte(pos1+2);
	de_dbg(c, "next sector: %u,%u", *pnext_tr, *pnext_se);

	for(i=0; i<7; i++) {
		do_file_entry(c, d, pos1+11+i*35);
	}

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_read_catalog(deark *c, lctx *d)
{
	UI tr, se;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	tr = d->catalog_tr;
	se = d->catalog_se;

	de_dbg(c, "catalog");
	de_dbg_indent(c, 1);

	while(1) {
		UI next_tr = 0;
		UI next_se = 0;

		if(!do_catalog_sector(c, d, tr, se, &next_tr, &next_se)) goto done;
		if(next_tr==0 && next_se==0) goto done;
		tr = next_tr;
		se = next_se;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_apple2_dsk(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->secsize = 256;
	d->ntracks = 35;
	d->sectors_per_track = 16;
	d->sector_list_sector_capacity = 122;

	do_read_VTOC(c, d, 17, 0);
	d->sector_used_flags = de_malloc(c, d->ntracks * d->sectors_per_track);
	do_read_catalog(c, d);

	if(d) {
		de_free(c, d->sector_used_flags);
		de_free(c, d);
	}
}

static int de_identify_apple2_dsk(deark *c)
{
	i64 vtocpos;
	u8 x;
	UI n;

	if(c->infile->len != 143360) return 0;
	if(dbuf_memcmp(c->infile, 0, (const u8*)"\x01\xa5\x27\xc9\x09\xd0", 6)) {
		return 0;
	}

	vtocpos = 17*16*256;
	x = de_getbyte(vtocpos+52); // #tracks
	if(x != 35) return 0;
	x = de_getbyte(vtocpos+53); // sec/track
	if(x != 16) return 0;
	n = (UI)de_getu16le(vtocpos+54); // bytes/sec
	if(n != 256) return 0;

	return 100;
}

void de_module_apple2_dsk(deark *c, struct deark_module_info *mi)
{
	mi->id = "apple2_dsk";
	mi->desc = "Apple II floppy disk image";
	mi->run_fn = de_run_apple2_dsk;
	mi->identify_fn = de_identify_apple2_dsk;
}

/////////////////////// WOZ

#define CODE_INFO 0x494e464fU
#define CODE_META 0x4d455441U
#define CODE_TMAP 0x544d4150U
#define CODE_TRKS 0x54524b53U
#define CODE_WRIT 0x57524954U

struct wozctx_struct {
	u8 wozver;
};

static const char *get_woz_disk_type_name(u8 t)
{
	switch(t) {
	case 1: return "5.25";
	case 2: return "3.5";
	}
	return "?";
}

static void do_woz_INFO(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	u8 b;
	i64 n;
	i64 pos = chunkctx->dpos;
	struct wozctx_struct *d = ictx->userdata;
	de_ucstring *s = NULL;

	if(chunkctx->dlen<37) return;
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "INFO chunk version: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "disk type: %d (%s)", (int)b, get_woz_disk_type_name(b));
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "write protected: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "synchronized: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "cleaned: %d", (int)b);

	s = ucstring_create(c);
	dbuf_read_to_ucstring(ictx->f, pos, 32, s, 0, DE_ENCODING_UTF8);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "creator: \"%s\"", ucstring_getpsz(s));
	pos += 32;

	if(d->wozver<'2') goto done;

	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "disk sides: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "boot sector format: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "optimal bit timing: %d", (int)b);
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "compatible hardware: %d", (int)n);
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "required RAM: %dK", (int)n);
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "largest track: %d blocks", (int)n);

done:
	ucstring_destroy(s);
}

static void do_woz_print_metadata_item(deark *c, de_ucstring *name, de_ucstring *val)
{
	if(name->len==0 && val->len==0) return;
	de_dbg(c, "item: \"%s\" = \"%s\"",
		ucstring_getpsz_d(name),
		ucstring_getpsz_d(val));
}

static void do_woz_META(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	i64 k;
	int reading_val;
	de_ucstring *s = NULL;
	de_ucstring *name = NULL;
	de_ucstring *val = NULL;

	// Read the entire metadata string.
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(ictx->f, chunkctx->dpos, chunkctx->dlen,
		65536, s, 0, DE_ENCODING_UTF8);

	// Parse out the individual metadata items
	name = ucstring_create(c);
	val = ucstring_create(c);
	reading_val = 0;

	for(k=0; k<s->len; k++) {
		i32 ch = s->str[k];

		if(ch==0x0a) { // End of item
			do_woz_print_metadata_item(c, name, val);
			ucstring_empty(name);
			ucstring_empty(val);
			reading_val = 0;
		}
		else if(ch==0x09 && !reading_val) { // Name/value separator
			reading_val = 1;
		}
		else { // A non-special character
			if(reading_val) {
				ucstring_append_char(val, ch);
			}
			else {
				ucstring_append_char(name, ch);
			}
		}
	}
	do_woz_print_metadata_item(c, name, val);

	ucstring_destroy(s);
	ucstring_destroy(name);
	ucstring_destroy(val);
}

static int my_preprocess_woz_chunk_fn(struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_TMAP: name = "track map"; break;
	case CODE_TRKS: name = "data for tracks"; break;
	case CODE_META: name = "metadata"; break;
	case CODE_WRIT: name = "disk writing instructions"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	return 1;
}

static int my_woz_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_INFO:
		ictx->handled = 1;
		do_woz_INFO(c, ictx, ictx->chunkctx);
		break;
	case CODE_META:
		ictx->handled = 1;
		do_woz_META(c, ictx, ictx->chunkctx);
		break;
	}

	return 1;
}

static void de_run_woz(deark *c, de_module_params *mparams)
{
	struct wozctx_struct *d = NULL;
	struct de_iffctx *ictx = NULL;
	u32 crc;
	i64 pos = 0;

	// WOZ has a 12-byte header, then sequence of chunks that are basically the
	// same format as RIFF.
	d = de_malloc(c, sizeof(struct wozctx_struct));
	ictx = fmtutil_create_iff_decoder(c);

	ictx->userdata = (void*)d;
	ictx->preprocess_chunk_fn = my_preprocess_woz_chunk_fn;
	ictx->handle_chunk_fn = my_woz_chunk_handler;
	ictx->f = c->infile;
	ictx->is_le = 1;
	ictx->reversed_4cc = 0;

	if(ictx->f->len<12) goto done;
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 3; // "WOZ" part of signature
	d->wozver = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "format version: '%c'", de_byte_to_printable_char(d->wozver));
	if(d->wozver<'1' || d->wozver>'2') {
		de_err(c, "Unsupported WOZ format version");
		goto done;
	}
	pos += 4; // rest of signature
	crc = (u32)dbuf_getu32le_p(ictx->f, &pos);
	de_dbg(c, "crc: 0x%08x", (unsigned int)crc);
	de_dbg_indent(c, -1);

	fmtutil_read_iff_format(ictx, pos, ictx->f->len-pos);

done:
	fmtutil_destroy_iff_decoder(ictx);
	de_free(c, d);
}

static int de_identify_woz(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "WOZ", 3))
		return 0;
	if(dbuf_memcmp(c->infile, 4, "\xff\x0a\x0d\x0a", 4))
		return 0;
	return 100;
}

void de_module_woz(deark *c, struct deark_module_info *mi)
{
	mi->id = "woz";
	mi->desc = "WOZ floppy disk image";
	mi->desc2 = "metadata only";
	mi->run_fn = de_run_woz;
	mi->identify_fn = de_identify_woz;
}
