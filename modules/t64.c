// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// T64 (Commodore 64 "tape"-like format)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_t64);

typedef struct localctx_struct {
	i64 version;
	i64 max_dir_entries;
	i64 used_dir_entries;
} lctx;

static void do_extract_file(deark *c, lctx *d, i64 dir_pos,
	u8 filetype_c64s, u8 filetype)
{
	i64 load_addr;
	i64 end_addr;
	i64 offset;
	dbuf *f = NULL;
	i64 payload_size; // = file_size-2
	de_ucstring *fname = NULL;
	i64 fname_len;
	i64 i;
	i64 fnpos;
	de_finfo *fi = NULL;

	load_addr = de_getu16le(dir_pos+2);
	end_addr = de_getu16le(dir_pos+4);
	offset = de_getu32le(dir_pos+8);
	de_dbg(c, "load_addr=%d end_addr=%d offset=%d", (int)load_addr,
		(int)end_addr, (int)offset);

	// File name at pos+16

	fnpos = dir_pos+16;

	// Find the length of the (space-padded) filename.
	fname_len = 0;
	for(i=15; i>=0; i--) {
		if(de_getbyte(fnpos+i)!=' ') {
			fname_len = i+1;
			break;
		}
	}
	de_dbg2(c, "filename length: %d", (int)fname_len);

	fname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, fnpos, fname_len, fname, 0, DE_ENCODING_PETSCII);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz(fname));

	ucstring_append_sz(fname, ".prg", DE_ENCODING_ASCII);

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, fname, 0);
	fi->original_filename_flag = 1;

	payload_size = end_addr - load_addr;
	if(payload_size < 0) {
		// TODO: Try to support files that don't have end_addr set properly.
		de_err(c, "This type of T64 file is not supported.");
		goto done;
	}

	f = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_copy(c->infile, dir_pos+2, 2, f);
	dbuf_copy(c->infile, offset, payload_size, f);

done:
	dbuf_close(f);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fname);
}

static void do_dir_entry(deark *c, lctx *d, i64 entry_num, i64 pos)
{
	u8 filetype_c64s;
	u8 filetype;

	filetype_c64s = de_getbyte(pos);
	if(filetype_c64s==0) {
		de_dbg2(c, "unused entry #%d at %d", (int)entry_num, (int)pos);
		return;
	}
	de_dbg(c, "entry #%d at %d", (int)entry_num, (int)pos);

	de_dbg_indent(c, 1);

	filetype = de_getbyte(pos+1);
	de_dbg(c, "c64s filetype=%d, filetype=0x%02x", (int)filetype_c64s, (int)filetype);

	if(filetype==0x00) {
		de_err(c, "Unsupported file type (0x%02x)", (int)filetype);
	}
	else {
		do_extract_file(c, d, pos, filetype_c64s, filetype);
	}

	de_dbg_indent(c, -1);
}

static void de_run_t64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 i;

	d = de_malloc(c, sizeof(lctx));

	pos = 32;
	d->version = de_getu16le(pos);
	de_dbg(c, "version: 0x%04x", (int)d->version);
	if(d->version!=0x100 && d->version!=0x101) {
		de_warn(c, "Unexpected version number. This might not be a T64 file.");
	}

	d->max_dir_entries = de_getu16le(pos+2);
	d->used_dir_entries = de_getu16le(pos+4);
	de_dbg(c, "max dir entries = %d, files = %d", (int)d->max_dir_entries, (int)d->used_dir_entries);

	pos += 32;
	for(i=0; i<d->max_dir_entries; i++) {
		do_dir_entry(c, d, i, pos+32*i);
	}

	de_free(c, d);
}

static int de_identify_t64(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "C64", 3)) return 80;
	return 0;
}

void de_module_t64(deark *c, struct deark_module_info *mi)
{
	mi->id = "t64";
	mi->desc = "T64 (C64 tape format)";
	mi->run_fn = de_run_t64;
	mi->identify_fn = de_identify_t64;
}
