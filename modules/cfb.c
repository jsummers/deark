// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Microsoft Compound File Binary File Format
// a.k.a " OLE Compound Document Format" and a million other names.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cfb);

typedef struct localctx_struct {
	de_int64 minor_ver, major_ver;
	de_int64 sec_size;
	//de_int64 num_dir_sectors;
	de_int64 num_fat_sectors;
	de_int64 first_dir_sector_loc;
	de_int64 std_stream_min_size;
	de_int64 first_mini_fat_sector_loc;
	de_int64 num_mini_fat_sectors;
	de_int64 first_difat_sector_loc;
	de_int64 num_difat_sectors;
} lctx;

static int do_header(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_int64 byte_order_code;
	de_int64 sector_shift;
	de_int64 mini_sector_shift;
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
	de_dbg(c, "sector shift: %d (%d bytes)\n", (int)sector_shift,
		(int)d->sec_size);

	mini_sector_shift = de_getui16le(pos+32); // aka sssz
	de_dbg(c, "mini sector shift: %d\n", (int)mini_sector_shift);
	if(mini_sector_shift != 6) {
		de_err(c, "Unsupported mini sector shift: %d\n", (int)mini_sector_shift);
		goto done;
	}

	// offset 34: 6 reserved bytes

	//d->num_dir_sectors = de_getui32le(pos+40);
	//de_dbg(c, "number of directory sectors: %u\n", (unsigned int)d->num_dir_sectors);
	// Should be 0 if major_ver==3

	// Number of sectors used by sector allocation table (SAT)
	d->num_fat_sectors = de_getui32le(pos+44);
	de_dbg(c, "number of FAT sectors: %d\n", (int)d->num_fat_sectors);

	d->first_dir_sector_loc = dbuf_geti32le(c->infile, pos+48);
	de_dbg(c, "first directory sector: %d\n", (int)d->first_dir_sector_loc);

	// offset 52, transaction signature number

	d->std_stream_min_size = de_getui32le(pos+56);
	de_dbg(c, "min size of a standard stream: %d\n", (int)d->std_stream_min_size);

	// First sector of short-sector allocation table (SSAT)
	d->first_mini_fat_sector_loc = dbuf_geti32le(c->infile, pos+60);
	de_dbg(c, "first mini FAT sector: %d\n", (int)d->first_mini_fat_sector_loc);

	// Number of sectors used by SSAT
	d->num_mini_fat_sectors = de_getui32le(pos+64);
	de_dbg(c, "number of mini FAT sectors: %d\n", (int)d->num_mini_fat_sectors);

	// SecID of first (extra??) sector of Master Sector Allocation Table (MSAT)
	d->first_difat_sector_loc = dbuf_geti32le(c->infile, pos+68);
	de_dbg(c, "first DIFAT sector: %d\n", (int)d->first_difat_sector_loc);

	// Number of (extra??) sectors used by MSAT
	d->num_difat_sectors = de_getui32le(pos+72);
	de_dbg(c, "number of DIFAT sectors: %d\n", (int)d->num_difat_sectors);

	// offset 76: 436 bytes of DIFAT data

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_cfb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_header(c, d)) {
		goto done;
	}

done:
	de_free(c, d);
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
