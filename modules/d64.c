// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// D64 (Commodore 64 disk image)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_d64);

#define FTYPE_DEL 0x0
#define FTYPE_SEQ 0x1
#define FTYPE_PRG 0x2
#define FTYPE_USR 0x3
#define FTYPE_REL 0x4

typedef struct localctx_struct {
	int reserved;
} lctx;

// Calculate the byte offset of a sector, given its logical track and
// sector numbers.
// Sectors range from 0 to 20
// Tracks range from 1 to (usually) 35
static de_int64 sector_offset(de_int64 track, de_int64 sector)
{
	de_int64 global_sector_index;
	de_int64 t;

	global_sector_index = 0;
	for(t=1; t<track; t++) {
		if(t<=17) global_sector_index+=21;
		else if(t<=24) global_sector_index+=19;
		else if(t<=30) global_sector_index+=18;
		else global_sector_index+=17;
	}
	global_sector_index += sector;

	return 256*(global_sector_index);
}

static void do_extract_file(deark *c, lctx *d, de_int64 dir_entry_pos,
	de_byte file_type, de_int64 ftrack, de_int64 fsector, de_int64 nsectors)
{
	de_int64 nsectors_written = 0;
	de_int64 curtrack, cursector;
	de_int64 nexttrack, nextsector;
	const char *ext;
	dbuf *f = NULL;
	de_finfo *fi = NULL;
	de_ucstring *fname = NULL;
	de_int64 fname_len;
	de_int64 i;
	de_byte z;

	de_dbg(c, "extracting file: t=%d,s=%d,sectors=%d", (int)ftrack, (int)fsector,
		(int)nsectors);

	// Figure out the filename

	// Find the length of the filename.
	fname_len = 0;
	for(i=15; i>=0; i--) {
		z = de_getbyte(dir_entry_pos+5+i);
		// TODO: Filenames are padded with 0xa0 bytes. I'm not sure if the
		// filename length is determined by the first 0xa0 byte, or the
		// last non-0xa0 byte. This assumes it's the last non-0xa0 byte.
		if(z!=0xa0) {
			fname_len = i+1;
			break;
		}
	}
	de_dbg2(c, "filename length: %d", (int)fname_len);
	fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, dir_entry_pos+5, fname_len, fname, 0, DE_ENCODING_PETSCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(fname));

	switch(file_type) {
	case FTYPE_SEQ: ext="seq"; break;
	case FTYPE_PRG: ext="prg"; break;
	case FTYPE_USR: ext="usr"; break;
	default: ext="bin"; break;
	}
	ucstring_append_sz(fname, ".", DE_ENCODING_ASCII);
	ucstring_append_sz(fname, ext, DE_ENCODING_ASCII);
	///////

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, fname);
	fi->original_filename_flag = 1;

	f = dbuf_create_output_file(c, NULL, fi, 0);

	curtrack = ftrack;
	cursector = fsector;
	while(1) {
		de_int64 pos;
		de_int64 amt_to_copy;

		if(nsectors_written>=nsectors) break;

		pos = sector_offset(curtrack, cursector);

		nexttrack = (de_int64)de_getbyte(pos+0);
		nextsector = (de_int64)de_getbyte(pos+1);
		de_dbg2(c, "next sector: t=%d,s=%d", (int)nexttrack, (int)nextsector);

		if(nexttrack==0 && nextsector>=1) amt_to_copy = (de_int64)nextsector-1;
		else amt_to_copy = 254;

		dbuf_copy(c->infile, pos+2, amt_to_copy, f);
		nsectors_written++;

		if(nexttrack<1) break;
		curtrack = nexttrack;
		cursector = nextsector;
	}

	dbuf_close(f);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fname);
}

static void do_dir_entry(deark *c, lctx *d, de_int64 pos)
{
	de_byte file_type1, file_type;
	de_int64 ftrack, fsector;
	de_int64 nsectors;
	const char *file_type_str;
	char tmps[100];

	de_dbg(c, "directory entry at %d", (int)pos);
	de_dbg_indent(c, 1);

	file_type1 = de_getbyte(pos+2);
	file_type = file_type1 & 0x7;
	switch(file_type) {
	case FTYPE_DEL:
		if((file_type1&0x80)==0) {
			file_type_str = "scratched";
		}
		else {
			file_type_str = "DEL";
		}
		break;
	case FTYPE_SEQ: file_type_str = "SEQ"; break;
	case FTYPE_PRG: file_type_str = "PRG"; break;
	case FTYPE_USR: file_type_str = "USR"; break;
	case FTYPE_REL: file_type_str = "REL"; break;
	default: file_type_str = "unknown"; break;
	}

	de_dbg(c, "file type: 0x%02x (%s)", (unsigned int)file_type1, file_type_str);

	if(file_type==FTYPE_REL) {
		de_warn(c, "REL files are not supported");
		goto done;
	}
	if(file_type!=FTYPE_SEQ && file_type!=FTYPE_PRG && file_type!=FTYPE_USR) {
		goto done;
	}

	ftrack = (de_int64)de_getbyte(pos+3);
	fsector = (de_int64)de_getbyte(pos+4);
	de_dbg(c, "file starts at t=%d,s=%d", (int)ftrack, (int)fsector);

	nsectors = de_getui16le(pos+30);
	if(nsectors>0) {
		de_snprintf(tmps, sizeof(tmps), "%d to %d",
			(int)((nsectors-1)*254+1),
			(int)(nsectors*254));
	}
	else {
		de_strlcpy(tmps, "0", sizeof(tmps));
	}
	de_dbg(c, "number of sectors used: %d (expected file size=%s)",
		(int)nsectors, tmps);

	do_extract_file(c, d, pos, file_type, ftrack, fsector, nsectors);

done:
	de_dbg_indent(c, -1);
}

static void do_directory_sector(deark *c, lctx *d, de_int64 track, de_int64 sector,
	de_int64 *nexttrack, de_int64 *nextsector)
{
	de_int64 pos;
	de_int64 i;

	pos = sector_offset(track, sector);
	de_dbg(c, "directory sector at t=%d,s=%d pos=%d", (int)track, (int)sector,
		(int)pos);
	de_dbg_indent(c, 1);

	*nexttrack = (de_int64)de_getbyte(pos);
	*nextsector = (de_int64)de_getbyte(pos+1);
	de_dbg(c, "next dir sector: t=%d,s=%d", (int)*nexttrack, (int)*nextsector);

	for(i=0; i<8; i++) {
		do_dir_entry(c, d, pos+i*32);
	}

	de_dbg_indent(c, -1);
}

static void do_directory(deark *c, lctx *d, de_int64 track, de_int64 sector)
{
	de_int64 pos;
	de_int64 sectorcount;
	de_int64 nexttrack, nextsector;
	de_int64 curtrack, cursector;

	pos = sector_offset(track, sector);
	de_dbg(c, "directory at t=%d,s=%d pos=%d", (int)track, (int)sector,
		(int)pos);

	curtrack = track;
	cursector = sector;
	sectorcount = 0;
	while(1) {
		do_directory_sector(c, d, curtrack, cursector, &nexttrack, &nextsector);
		if(nexttrack==0) break;
		sectorcount++;
		if(sectorcount>1000) break;
		curtrack = nexttrack;
		cursector = nextsector;
	}
}

static void de_run_d64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	do_directory(c, d, 18, 1);

	de_free(c, d);
}

static int de_identify_d64(deark *c)
{
	if(!de_input_file_has_ext(c, "d64")) return 0;
	if(!dbuf_memcmp(c->infile, 357*256, "\x12\x01\x41\x00", 4)) {
		return 100;
	}
	if(c->infile->len==683*256) return 30;
	if(c->infile->len==683*256+683) return 30;
	return 0;
}

void de_module_d64(deark *c, struct deark_module_info *mi)
{
	mi->id = "d64";
	mi->desc = "D64 (C64 disk image)";
	mi->run_fn = de_run_d64;
	mi->identify_fn = de_identify_d64;
}
