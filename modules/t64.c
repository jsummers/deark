// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 version;
	de_int64 max_dir_entries;
	de_int64 used_dir_entries;
} lctx;

static void do_extract_file(deark *c, lctx *d, de_int64 dir_pos,
	de_byte filetype_c64s, de_byte filetype)
{
	de_int64 load_addr;
	de_int64 end_addr;
	de_int64 offset;
	dbuf *f = NULL;
	de_int64 payload_size; // = file_size-2

	load_addr = de_getui16le(dir_pos+2);
	end_addr = de_getui16le(dir_pos+4);
	offset = de_getui32le(dir_pos+8);
	de_dbg(c, "load_addr=%d end_addr=%d offset=%d\n", (int)load_addr,
		(int)end_addr, (int)offset);

	// TODO: File name at pos+16

	payload_size = end_addr - load_addr;
	if(payload_size < 0) {
		// TODO: Try to support files that don't have end_addr set properly.
		de_err(c, "This type of T64 file is not supported.\n");
		goto done;
	}

	f = dbuf_create_output_file(c, "prg", NULL);
	dbuf_copy(c->infile, dir_pos+2, 2, f);
	dbuf_copy(c->infile, offset, payload_size, f);

done:
	dbuf_close(f);
}

static void do_dir_entry(deark *c, lctx *d, de_int64 entry_num, de_int64 pos)
{
	de_byte filetype_c64s;
	de_byte filetype;

	filetype_c64s = de_getbyte(pos);
	if(filetype_c64s==0) {
		de_dbg(c, "unused entry #%d at %d\n", (int)entry_num, (int)pos);
		return;
	}
	de_dbg(c, "entry #%d at %d\n", (int)entry_num, (int)pos);

	de_dbg_indent(c, 1);

	filetype = de_getbyte(pos+1);
	de_dbg(c, "c64s filetype=%d, filetype=0x%02x\n", (int)filetype_c64s, (int)filetype);

	if(filetype==0x00) {
		de_err(c, "Unsupported file type (0x%02x)\n", (int)filetype);
	}
	else {
		do_extract_file(c, d, pos, filetype_c64s, filetype);
	}

	de_dbg_indent(c, -1);
}

static void de_run_t64(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 i;

	de_dbg(c, "In t64 module\n");

	d = de_malloc(c, sizeof(lctx));

	pos = 32;
	d->version = de_getui16le(pos);
	de_dbg(c, "version: 0x%04x\n", (int)d->version);
	if(d->version!=0x100 && d->version!=0x101) {
		de_warn(c, "Unexpected version number. This might not be a T64 file.\n");
	}

	d->max_dir_entries = de_getui16le(pos+2);
	d->used_dir_entries = de_getui16le(pos+4);
	de_dbg(c, "max dir entries = %d, files = %d\n", (int)d->max_dir_entries, (int)d->used_dir_entries);

	pos += 32;
	for(i=0; i<d->max_dir_entries; i++) {
		do_dir_entry(c, d, i, pos+32*i);
	}

	de_free(c, d);
}

static int de_identify_t64(deark *c)
{
	de_byte buf[8];
	de_read(buf, 0, 8);

	if(!de_memcmp(buf, "C64", 3)) return 80;
	return 0;
}

void de_module_t64(deark *c, struct deark_module_info *mi)
{
	mi->id = "t64";
	mi->run_fn = de_run_t64;
	mi->identify_fn = de_identify_t64;
}
