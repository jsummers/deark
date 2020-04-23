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
	u8 is_subdir;
	u8 is_special;
	UI attribs;
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
	u8 num_fat_bits; // 12, 16, or 32. 0 if unknown.
	u8 has_atarist_checksum;
	u8 found_vfat;
	i64 bytes_per_sector;
	i64 sectors_per_cluster;
	i64 bytes_per_cluster;
	i64 num_sectors_old;
	i64 num_sectors;
	i64 data_region_sector;
	i64 data_region_pos;
	i64 num_data_region_clusters;
	i64 num_rsvd_sectors;
	i64 num_fats;
	i64 num_sectors_per_fat;
	i64 max_root_dir_entries;
	i64 root_dir_sector;
	i64 num_cluster_identifiers;

	i64 num_fat_entries;
	u32 *fat_nextcluster; // array[num_fat_entries]
	u8 *cluster_used_flags; // array[num_fat_entries]
} lctx;

static i64 sectornum_to_offset(deark *c, lctx *d, i64 secnum)
{
	return secnum * d->bytes_per_sector;
}

static i64 clusternum_to_offset(deark *c, lctx *d, i64 cnum)
{
	return d->data_region_pos + (cnum-2) * d->bytes_per_cluster;
}

static i64 get_unpadded_len(const u8 *s, i64 len1)
{
	i64 i;
	i64 len = len1;

	// Stop at NUL, I guess.
	for(i=0; i<len1; i++) {
		if(s[i]==0x00) {
			len = i;
			break;
		}
	}

	for(i=len; i>0; i--) {
		if(s[i-1]!=' ') {
			return i;
		}
	}
	return 0;
}

static void do_extract_file(deark *c, lctx *d, struct member_data *md)
{
	dbuf *outf = NULL;
	de_finfo *fi = NULL;
	i64 cur_cluster;
	i64 nbytes_remaining;

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, md->fn_u, 0);
	fi->original_filename_flag = 1;
	outf = dbuf_create_output_file(c, NULL, fi, 0);

	cur_cluster = md->first_cluster;
	nbytes_remaining = md->filesize;

	while(1) {
		i64 dpos;
		i64 nbytes_to_copy;

		if(nbytes_remaining <= 0) break;
		if(cur_cluster<2 || cur_cluster>=d->num_cluster_identifiers) break;
		if(d->cluster_used_flags[cur_cluster]) break;
		d->cluster_used_flags[cur_cluster] = 1;
		if(c->debug_level>=3) de_dbg3(c, "cluster: %d", (int)cur_cluster);
		dpos = clusternum_to_offset(c, d, cur_cluster);
		nbytes_to_copy = de_min_int(d->bytes_per_cluster, nbytes_remaining);
		dbuf_copy(c->infile, dpos, nbytes_to_copy, outf);
		nbytes_remaining -= nbytes_to_copy;
		cur_cluster = (i64)d->fat_nextcluster[cur_cluster];
	}

	if(nbytes_remaining>0) {
		de_err(c, "%s: File extraction failed", ucstring_getpsz_d(md->fn_u));
	}

	dbuf_close(outf);
	de_finfo_destroy(c, fi);
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

	if(md->fn_base[0]==0xe5) {
		de_dbg(c, "[deleted]");
		goto done;
	}
	if(md->fn_base[0]==0x05) {
		md->fn_base[0] = 0xe5;
	}

	de_read(md->fn_ext, pos, 3);
	pos += 3;

	md->attribs = (UI)de_getbyte_p(&pos);
	de_dbg(c, "attribs: 0x%02x", md->attribs);

	if(md->attribs==0x0f) {
		de_dbg(c, "[VFAT entry]");
		if(!d->found_vfat) {
			de_warn(c, "This disk uses VFAT extended filenames, which are not supported");
			d->found_vfat = 1;
		}
		goto done;
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

	if(md->attribs & 0x40) {
		de_dbg(c, "[device]");
		md->is_special = 1;
	}
	else if(md->attribs & 0x08) {
		de_dbg(c, "[volume label]");
		md->is_special = 1;
	}
	else if(md->attribs & 0x10) {
		de_dbg(c, "[subdirectory]");
		md->is_subdir = 1;
		// TODO: special "." and ".." dirs
	}

	// TODO: This is wrong for FAT32.
	md->first_cluster = de_getu16le(pos1+26);
	de_dbg(c, "first cluster: %"I64_FMT, md->first_cluster);

	md->filesize = de_getu32le(pos1+28);
	de_dbg(c, "file size: %"I64_FMT, md->filesize);

	if(!md->is_subdir && !md->is_special) {
		do_extract_file(c, d, md);
	}

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
	if(pos1<d->bytes_per_sector) goto done;
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
	i64 num_root_dir_sectors;
	i64 num_data_region_sectors;
	u8 b;
	u8 cksum_sig[2];
	int retval = 0;

	de_dbg(c, "boot sector at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// BIOS parameter block
	pos = pos1+11;
	d->bytes_per_sector = de_getu16le_p(&pos);
	de_dbg(c, "bytes per sector: %d", (int)d->bytes_per_sector);
	d->sectors_per_cluster = (i64)de_getbyte_p(&pos);
	de_dbg(c, "sectors per cluster: %d", (int)d->sectors_per_cluster);
	d->num_rsvd_sectors = de_getu16le_p(&pos);
	de_dbg(c, "reserved sectors: %d", (int)d->num_rsvd_sectors);
	d->num_fats = (i64)de_getbyte_p(&pos);
	de_dbg(c, "number of FATs: %d", (int)d->num_fats);
	d->max_root_dir_entries = de_getu16le_p(&pos);
	de_dbg(c, "max number of root dir entries (if FAT12/16): %d", (int)d->max_root_dir_entries);
	d->num_sectors_old = de_getu16le_p(&pos);
	if(d->num_sectors_old!=0) {
		d->num_sectors = d->num_sectors_old;
	}
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

	if(d->num_sectors_old==0) {
		d->num_fat_bits = 32;
		d->num_sectors = de_getu32le(pos1+32);
		de_dbg(c, "num sectors: %"I64_FMT, d->num_sectors);
	}

	if(d->sectors_per_cluster<1) goto done;
	if(d->bytes_per_sector<32) goto done;
	d->bytes_per_cluster = d->bytes_per_sector * d->sectors_per_cluster;
	d->root_dir_sector = d->num_rsvd_sectors + d->num_sectors_per_fat * d->num_fats;
	num_root_dir_sectors = (d->max_root_dir_entries*32 + d->bytes_per_sector -1)/d->bytes_per_sector;
	d->data_region_sector = d->root_dir_sector + num_root_dir_sectors;
	d->data_region_pos = d->data_region_sector * d->bytes_per_sector;
	de_dbg(c, "data region pos (calculated): %"I64_FMT" (sector %"I64_FMT")", d->data_region_pos,
		d->data_region_sector);
	num_data_region_sectors = d->num_sectors - d->data_region_sector;
	if(num_data_region_sectors<0) goto done;
	d->num_data_region_clusters = (num_data_region_sectors + d->sectors_per_cluster - 1) /
		d->sectors_per_cluster;
	de_dbg(c, "num clusters (calculated): %"I64_FMT, d->num_data_region_clusters);
	// (The first cluster is numbered "2".)
	d->num_cluster_identifiers = d->num_data_region_clusters + 2;
	if(d->num_fat_bits==0) {
		// TODO: This might not be quite correct.
		if(d->num_cluster_identifiers <= 4095) {
			d->num_fat_bits = 12;
		}
		else if(d->num_cluster_identifiers <= 65535) {
			d->num_fat_bits = 16;
		}
		else {
			goto done;
		}
	}

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_read_fat(deark *c, lctx *d)
{
	i64 pos1;
	i64 pos;
	i64 fat_idx_to_read = 0;
	int retval = 0;
	i64 i;

	pos1 = sectornum_to_offset(c, d, d->num_rsvd_sectors + fat_idx_to_read*d->num_sectors_per_fat);
	de_dbg(c, "FAT#%d at %"I64_FMT, (int)fat_idx_to_read, pos1);
	de_dbg_indent(c, 1);

	if(d->num_cluster_identifiers > (i64)(DE_MAX_SANE_OBJECT_SIZE/sizeof(u32))) goto done;
	d->num_fat_entries = d->num_cluster_identifiers;
	d->fat_nextcluster = de_mallocarray(c, d->num_fat_entries, sizeof(u32));
	d->cluster_used_flags = de_malloc(c, d->num_fat_entries);

	pos = pos1;
	if(d->num_fat_bits==12) {
		for(i=0; i<d->num_fat_entries+1; i+=2) {
			UI val;

			val = (UI)dbuf_getint_ext(c->infile, pos, 3, 1, 0);
			pos += 3;
			if(i < d->num_fat_entries) {
				d->fat_nextcluster[i] = (u32)(val & 0xfff);
			}
			if(i+1 < d->num_fat_entries) {
				d->fat_nextcluster[i+1] = (u32)(val >> 12);
			}
		}
	}
	else {
		goto done;
	}

	if(c->debug_level>=3) {
		for(i=0; i<d->num_fat_entries; i++) {
			de_dbg3(c, "fat[%"I64_FMT"]: %"I64_FMT, i, (i64)d->fat_nextcluster[i]);
		}
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_fat(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	// TODO: Detect MBR?
	d->input_encoding = DE_ENCODING_CP437_G;
	if(!do_boot_sector(c, d, 0)) goto done;
	if(d->num_fat_bits==0) goto done;

	switch(d->platform) {
	case FAT_PLATFORM_PC:
		de_declare_fmtf(c, "FAT%d / PC", d->num_fat_bits);
		break;
	case FAT_PLATFORM_ATARIST:
		de_declare_fmtf(c, "FAT%d / Atari ST", d->num_fat_bits);
		break;
	}

	if(!do_read_fat(c, d)) goto done;

	do_dir(c, d, d->root_dir_sector, 1);

done:
	if(d) {
		de_free(c, d->fat_nextcluster);
		de_free(c, d->cluster_used_flags);
		de_free(c, d);
	}
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
