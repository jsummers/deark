// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// FAT disk image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_fat);

struct member_data {
	u8 fn_base[8];
	u8 fn_ext[3];
	u8 attribs;
	i64 fn_base_len, fn_ext_len;
	i64 filesize;
	i64 first_cluster;
	de_ucstring *fn_u;
};

typedef struct localctx_struct {
	int input_encoding;
#define FAT_PLATFORM_UNKNOWN   0
#define FAT_PLATFORM_PC        1
#define FAT_PLATFORM_ATARIST   2
	int platform;
	u8 has_atarist_checksum;
	u8 found_vfat;
	i64 sector_size;
	i64 num_sectors_old;
	i64 num_rsvd_sectors;
	i64 num_fats;
	i64 num_sectors_per_fat;
	i64 max_root_dir_entries;
} lctx;

static i64 sectornum_to_offset(deark *c, lctx *d, i64 secnum)
{
	return secnum * d->sector_size;
}

static i64 get_unpadded_len(const u8 *s, i64 len)
{
	i64 i;
	for(i=len; i>0; i--) {
		if(s[i-1]!=' ') {
			return i;
		}
	}
	return 0;
}

// Returns 0 if this is the end-of-directory marker.
static int do_dir_entry(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;
	struct member_data *md = NULL;

	md = de_malloc(c, sizeof(struct member_data));

	de_dbg(c, "dir entry at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	de_read(md->fn_base, pos, 8);
	pos += 8;
	if(md->fn_base[0]==0x00) {
		de_dbg(c, "[end of dir marker]");
		goto done;
	}
	retval = 1;

	de_read(md->fn_ext, pos, 3);
	pos += 3;

	md->attribs = de_getbyte_p(&pos);

	if(md->attribs==0x0f) {
		de_dbg(c, "[VFAT entry]");
		if(!d->found_vfat) {
			de_warn(c, "This disk uses VFAT extended filenames, which are not supported");
			d->found_vfat = 1;
		}
		goto done;
	}
	if(md->fn_base[0]==0xe5) {
		de_dbg(c, "[deleted]");
		goto done;
	}
	if(md->fn_base[0]=='.') {
		de_dbg(c, "[. or .. directory]");
		goto done;
	}

	if(md->fn_base[0]==0x05) {
		md->fn_base[0] = 0xe5;
	}

	md->fn_base_len = get_unpadded_len(md->fn_base, 8);
	md->fn_ext_len = get_unpadded_len(md->fn_ext, 3);

	md->fn_u = ucstring_create(c);
	if(md->fn_base_len>0) {
		ucstring_append_bytes(md->fn_u, md->fn_base, md->fn_base_len, 0, d->input_encoding);
	}
	else {
		ucstring_append_char(md->fn_u, '_');
	}
	if(md->fn_ext_len>0) {
		ucstring_append_char(md->fn_u, '.');
		ucstring_append_bytes(md->fn_u, md->fn_ext, md->fn_ext_len, 0, d->input_encoding);
	}

	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn_u));

	// TODO: This is wrong for FAT32.
	md->first_cluster = de_getu16le(pos1+26);
	de_dbg(c, "first cluster: %"I64_FMT, md->first_cluster);

	md->filesize = de_getu32le(pos1+28);
	de_dbg(c, "file size: %"I64_FMT, md->filesize);

done:
	if(md) {
		ucstring_destroy(md->fn_u);
	}
	de_dbg_indent(c, -1);
	return retval;
}

// Process a contiguous block of directory entries
static void do_dir_entries(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 num_entries;
	i64 i;

	num_entries = d->max_root_dir_entries;
	de_dbg(c, "num entries: %"I64_FMT, num_entries);

	for(i=0; i<num_entries; i++) {
		if(!do_dir_entry(c, d, pos1+32*i)) {
			break;
		}
	}
}

static void do_dir(deark *c, lctx *d, i64 secnum, int is_root)
{
	i64 pos1;

	pos1 = sectornum_to_offset(c, d, secnum);
	de_dbg(c, "dir at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	if(pos1<d->sector_size) goto done;
	if(!is_root) goto done;
	do_dir_entries(c, d, pos1, d->max_root_dir_entries * 32);
done:
	de_dbg_indent(c, -1);
}

static void do_atarist_boot_checksum(deark *c, lctx *d, i64 pos1)
{
	i64 i;
	UI ck = 0;

	for(i=0; i<256; i++) {
		ck += (UI)de_getu16be(pos1+i*2);
		ck &= 0xffff;
	}

	de_dbg(c, "Atari ST checksum: 0x%04x", ck);
	if(ck==0x1234) {
		d->has_atarist_checksum = 1;
	}
}

static int do_boot_sector(deark *c, lctx *d, i64 pos1)
{
	i64 pos;
	i64 n;
	u8 b;
	u8 cksum_sig[2];

	de_dbg(c, "boot sector at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// BIOS parameter block
	pos = pos1+11;
	n = de_getu16le_p(&pos);
	de_dbg(c, "bytes per sector: %d", (int)n);
	n = (i64)de_getbyte_p(&pos);
	de_dbg(c, "sectors per cluster: %d", (int)n);
	d->num_rsvd_sectors = de_getu16le_p(&pos);
	de_dbg(c, "reserved sectors: %d", (int)d->num_rsvd_sectors);
	d->num_fats = (i64)de_getbyte_p(&pos);
	de_dbg(c, "number of FATs: %d", (int)d->num_fats);
	d->max_root_dir_entries = de_getu16le_p(&pos);
	de_dbg(c, "max number of root dir entries (if FAT12/16): %d", (int)d->max_root_dir_entries);
	d->num_sectors_old = de_getu16le_p(&pos);
	de_dbg(c, "number of sectors (if FAT12/16): %d", (int)d->num_sectors_old);
	b = de_getbyte_p(&pos);
	de_dbg(c, "media descriptor: 0x%02x", (UI)b);
	d->num_sectors_per_fat = de_getu16le_p(&pos);
	de_dbg(c, "sectors per FAT (if FAT12/16): %d", (int)d->num_sectors_per_fat);

	pos = pos1+0x1fe;
	de_read(cksum_sig, pos, 2);
	de_dbg(c, "boot sector signature: 0x%02x 0x%02x", (UI)cksum_sig[0], (UI)cksum_sig[1]);

	do_atarist_boot_checksum(c, d, pos1);
	if(d->has_atarist_checksum) {
		d->platform = FAT_PLATFORM_ATARIST;
		de_dbg(c, "[This is probably a bootable Atari ST disk.]");
	}
	else if(cksum_sig[0]==0x55 && cksum_sig[1]==0xaa) {
		d->platform = FAT_PLATFORM_PC;
		de_dbg(c, "[Disk has PC-compatible boot code.]");
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void de_run_fat(deark *c, de_module_params *mparams)
{
	i64 root_dir_sector;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	// TODO: Detect MBR?
	d->sector_size = 512;
	d->input_encoding = DE_ENCODING_CP437_G;
	if(!do_boot_sector(c, d, 0)) goto done;

	switch(d->platform) {
	case FAT_PLATFORM_PC:
		de_declare_fmt(c, "FAT / PC");
		break;
	case FAT_PLATFORM_ATARIST:
		de_declare_fmt(c, "FAT / Atari ST");
		break;
	}

	if(d->num_sectors_old==0) {
		goto done; // FAT32?
	}

	root_dir_sector = d->num_rsvd_sectors + d->num_sectors_per_fat * d->num_fats;
	do_dir(c, d, root_dir_sector, 1);

done:
	de_free(c, d);
}

static int de_identify_fat(deark *c)
{
	return 0;
}

void de_module_fat(deark *c, struct deark_module_info *mi)
{
	mi->id = "fat";
	mi->desc = "FAT disk image";
	mi->run_fn = de_run_fat;
	mi->identify_fn = de_identify_fat;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
