// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// Disk Express floppy disk image
// by Albert J. Shan

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_dskexp);

#define DXP_AS_HDR_SIZE 512
#define DXP_SECTOR_SIZE 512
#define DXP_MAX_TRACKS  200

typedef struct localctx_DXP {
	u8 errflag;
	u8 need_errmsg;
	u8 is_exe;
	u8 major_ver, minor_ver;
	u8 disk_type;
	u8 cmpr_meth;
	u8 last_cyl;
	u8 last_head;
	u8 hdrflags;
	u8 is_ibm_licensed;
	i64 as_hdr_pos;
	i64 data_pos;
	u32 data_crc_reported;
	u32 mainhdr_crc_reported;
	u32 descr_crc_reported;

	// dt_ items are the standards for this disk type
	i64 dt_num_cyl;
	i64 dt_tracks_per_cyl; // or "heads"
	i64 dt_sectors_per_track;
	i64 dt_num_tracks;
	i64 dt_track_size_in_bytes;
	i64 dt_total_size_in_bytes;

	i64 num_tracks_stored_reported;
	de_finfo *fi;
	dbuf *diskbuf;
	dbuf *trkbuf;
	struct de_crcobj *crco1;
	struct de_crcobj *crco2;
	struct fmtutil_exe_info ei;
	struct fmtutil_specialexe_detection_data edd;
} lctx;

static void decompress_trk_any(deark *c, lctx *d, i64 pos1, i64 len,
	de_codectype1_type codecfn, void *codec_private_params)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = d->trkbuf;
	dcmpro.expected_len = d->dt_track_size_in_bytes;
	dcmpro.len_known = 1;

	codecfn(c, &dcmpri, &dcmpro, &dres, codec_private_params);
	dbuf_flush(d->trkbuf);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		d->errflag = 1;
		goto done;
	}

	if(d->trkbuf->len != d->dt_track_size_in_bytes) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(!dres.bytes_consumed_valid ||
		dres.bytes_consumed!=len)
	{
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

done:
	;
}

static void decompress_trk_lh1(deark *c, lctx *d, i64 pos1, i64 len)
{
	decompress_trk_any(c, d, pos1, len, fmtutil_lh1_codectype1, NULL);
}

static void decompress_trk_lh5(deark *c, lctx *d, i64 pos1, i64 len)
{
	struct de_lh5x_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lh5x_params));
	lzhparams.fmt = DE_LH5X_FMT_LH5;
	lzhparams.zero_codes_block_behavior = DE_LH5X_ZCB_ERROR;
	decompress_trk_any(c, d, pos1, len, fmtutil_lh5x_codectype1,
		(void*)&lzhparams);
}

static void decode_disk_type(deark *c, lctx *d)
{
	switch(d->disk_type) {
	case 3: // 360k
		d->dt_tracks_per_cyl = 2;
		d->dt_sectors_per_track = 9;
		d->dt_num_cyl = 40;
		break;
	case 4: // 720K
		d->dt_tracks_per_cyl = 2;
		d->dt_sectors_per_track = 9;
		d->dt_num_cyl = 80;
		break;
	case 5: // 1.2M
		d->dt_tracks_per_cyl = 2;
		d->dt_sectors_per_track = 15;
		d->dt_num_cyl = 80;
		break;
	case 6: // 1.4M
		d->dt_tracks_per_cyl = 2;
		d->dt_sectors_per_track = 18;
		d->dt_num_cyl = 80;
		break;
	case 7: // 2.8M
		d->dt_tracks_per_cyl = 2;
		d->dt_sectors_per_track = 36;
		d->dt_num_cyl = 80;
		break;
	default:
		de_err(c, "Unsupported disk type: %u", (UI)d->disk_type);
		d->errflag = 1;
		// TODO?: 0 = 160k, 1=180k, 2=320k
		goto done;
	}

	d->dt_num_tracks = d->dt_num_cyl * d->dt_tracks_per_cyl;
	d->dt_track_size_in_bytes = DXP_SECTOR_SIZE * d->dt_sectors_per_track;
	d->dt_total_size_in_bytes = d->dt_track_size_in_bytes * d->dt_num_tracks;
done:
	;
}

static void dxp_decode_uncompressed(deark *c, lctx *d)
{
	i64 pos;
	i64 len;

	pos = d->data_pos;
	len = de_min_int(c->infile->len-pos,
		d->num_tracks_stored_reported*d->dt_track_size_in_bytes);
	dbuf_copy(c->infile, pos, len, d->diskbuf);
}

enum dxp_trkcmp_enum {
	DXP_TRKCMPR_NORMAL, DXP_TRKCMPR_1BYTE, DXP_TRKCMPR_UNC
};

static void dxp_decode_compressed(deark *c, lctx *d)
{
	i64 pos;
	i64 cyl = 0;
	i64 head = 0;
	int saved_indent_level;
	u8 compute_crc; // Do we need to compute the CRC before decompression?
	u32 crc1_calc, crc2_calc;
	i64 num_tracks_found = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	d->trkbuf = dbuf_create_membuf(c, d->dt_track_size_in_bytes, 0x1);
	dbuf_enable_wbuffer(d->trkbuf);

	compute_crc = (d->major_ver<=1);
	if(compute_crc) {
		de_crcobj_reset(d->crco1);
		de_crcobj_setval(d->crco1, 0x0000059dU);
		de_crcobj_reset(d->crco2);
		de_crcobj_setval(d->crco2, 0x0000031eU);
	}

	pos = d->data_pos;
	while(1) {
		i64 trk_pos;
		i64 trk_cmpr_size;
		enum dxp_trkcmp_enum trkcmpr;
		const char *trkcmprname;

		if(d->errflag) goto done;
		// I'm not sure if our way of calculating num_tracks_stored_reported is
		// 100% trustworthy, but I haven't seen any problems with it yet.
		if(num_tracks_found >= d->num_tracks_stored_reported) goto done;

		dbuf_empty(d->trkbuf);
		trk_pos = pos;
		if(pos+2 > c->infile->len) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		de_dbg(c, "cmpr track[%d] (cyl %d head %d) data at %"I64_FMT,
			(int)num_tracks_found, (int)cyl, (int)head, trk_pos);
		de_dbg_indent(c, 1);

		trk_cmpr_size = de_getu16le_p(&pos);
		de_dbg(c, "track cmpr size: %"I64_FMT, trk_cmpr_size);
		if(trk_cmpr_size==0) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		else if(trk_cmpr_size==1) {
			trkcmpr = DXP_TRKCMPR_1BYTE;
			trkcmprname = "one byte val";
		}
		else if(trk_cmpr_size == d->dt_track_size_in_bytes) {
			trkcmpr = DXP_TRKCMPR_UNC;
			trkcmprname = "uncompressed";
		}
		else {
			trkcmpr = DXP_TRKCMPR_NORMAL;
			trkcmprname = "normal compressed";
		}
		de_dbg(c, "track cmpr meth: %s", trkcmprname);

		if(compute_crc) {
			de_crcobj_addslice(d->crco1, c->infile, pos, trk_cmpr_size);
			de_crcobj_addslice(d->crco2, c->infile, pos, trk_cmpr_size);
		}

		if(trkcmpr==DXP_TRKCMPR_1BYTE) {
			u8 v;

			v = de_getbyte(pos);
			dbuf_write_run(d->trkbuf, v, d->dt_track_size_in_bytes);
		}
		else if(trkcmpr==DXP_TRKCMPR_UNC) {
			dbuf_copy(c->infile, pos, trk_cmpr_size, d->trkbuf);
		}
		else {
			if(d->cmpr_meth==1) {
				decompress_trk_lh1(c, d, pos, trk_cmpr_size);
			}
			else {
				decompress_trk_lh5(c, d, pos, trk_cmpr_size);
			}
		}
		if(d->errflag) goto done;

		dbuf_flush(d->trkbuf);
		dbuf_copy(d->trkbuf, 0, d->trkbuf->len, d->diskbuf);
		num_tracks_found++;
		dbuf_truncate(d->diskbuf, num_tracks_found*d->dt_track_size_in_bytes);

		pos += trk_cmpr_size;
		head++;
		if(head >= d->dt_tracks_per_cyl) {
			head = 0;
			cyl++;
		}
		de_dbg_indent(c, -1);
	}
done:
	if(d->need_errmsg) {
		de_err(c, "Decompression failed");
		d->need_errmsg = 0;
		d->errflag = 1;
	}

	if(compute_crc && !d->errflag) {
		crc1_calc = de_crcobj_getval(d->crco1);
		crc2_calc = de_crcobj_getval(d->crco2);
		de_dbg(c, "cmpr. data crc [1] (calculated): 0x%08x", (UI)crc1_calc);
		de_dbg(c, "cmpr. data crc [2] (calculated): 0x%08x", (UI)crc2_calc);
		if(crc1_calc!=d->data_crc_reported && crc2_calc==d->data_crc_reported) {
			d->is_ibm_licensed = 1;
		}
		if(crc1_calc!=d->data_crc_reported && crc2_calc!=d->data_crc_reported) {
			de_warn(c, "CRC check failed");
		}
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

static void dxp_check_data_crc(deark *c, lctx *d)
{
	i64 nbytes_to_check;
	u32 crc1_calc;
	u32 crc2_calc = 0;

	if(d->major_ver<2 && d->cmpr_meth!=0) goto done;
	nbytes_to_check = d->num_tracks_stored_reported * d->dt_track_size_in_bytes;
	de_crcobj_reset(d->crco1);
	de_crcobj_setval(d->crco1, 0x0000059dU);
	de_crcobj_addslice(d->crco1, d->diskbuf, 0, nbytes_to_check);
	crc1_calc = de_crcobj_getval(d->crco1);
	de_dbg(c, "data crc [1] (calculated): 0x%08x", (UI)crc1_calc);

	if(crc1_calc!=d->data_crc_reported) {
		de_crcobj_reset(d->crco2);
		de_crcobj_setval(d->crco2, 0x0000031eU); // IBM
		de_crcobj_addslice(d->crco2, d->diskbuf, 0, nbytes_to_check);
		crc2_calc = de_crcobj_getval(d->crco2);
		de_dbg(c, "data crc [2] (calculated): 0x%08x", (UI)crc2_calc);
		if(crc2_calc==d->data_crc_reported) {
			d->is_ibm_licensed = 1;
		}
	}

	if(crc1_calc!=d->data_crc_reported && crc2_calc!=d->data_crc_reported)
	{
		de_warn(c, "CRC check failed");
	}

done:
	;
}

static void dxp_decode(deark *c, lctx *d)
{
	dbuf *outf = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "disk data at %"I64_FMT, d->data_pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "expected disk image size: %"I64_FMT, d->dt_total_size_in_bytes);
	d->fi = de_finfo_create(c);
	d->diskbuf = dbuf_create_membuf(c, d->dt_total_size_in_bytes, 0);
	dbuf_set_length_limit(d->diskbuf, 3*1048576);

	if(d->cmpr_meth==0) {
		dxp_decode_uncompressed(c, d);
	}
	else {
		dxp_decode_compressed(c, d);
	}

	dbuf_flush(d->diskbuf);
	if(d->errflag) goto done;

	// Pad to normal size for this disk size
	if(d->diskbuf->len < d->dt_total_size_in_bytes) {
		dbuf_truncate(d->diskbuf, d->dt_total_size_in_bytes);
	}

	dxp_check_data_crc(c, d);
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "ima", d->fi, 0);
	dbuf_copy(d->diskbuf, 0, d->diskbuf->len, outf);

done:
	dbuf_close(outf);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void dxp_main(deark *c, lctx *d)
{
	i64 pos;
	int saved_indent_level;
	i64 last_head_adj;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "DXP header at %"I64_FMT, d->as_hdr_pos);
	de_dbg_indent(c, 1);

	pos = d->as_hdr_pos+2;
	d->data_pos = d->as_hdr_pos + DXP_AS_HDR_SIZE;
	d->major_ver = de_getbyte_p(&pos);
	d->minor_ver = de_getbyte_p(&pos);
	de_dbg(c, "ver needed: %u.%02u", (UI)d->major_ver, (UI)d->minor_ver);
	pos++;
	d->disk_type = de_getbyte_p(&pos);
	de_dbg(c, "disk type: %u", (UI)d->disk_type);
	d->data_crc_reported = (u32)de_getu32le_p(&pos);
	de_dbg(c, "data crc (reported): 0x%08x", (UI)d->data_crc_reported);
	d->cmpr_meth = de_getbyte_p(&pos);
	de_dbg(c, "cmpr meth: %u", (UI)d->cmpr_meth);
	d->last_cyl = de_getbyte_p(&pos);
	de_dbg(c, "last cylinder imaged: %u", (UI)d->last_cyl);
	d->last_head = de_getbyte_p(&pos);
	de_dbg(c, "last head imaged: %u", (UI)d->last_head);
	pos++;
	d->hdrflags = de_getbyte_p(&pos);
	de_dbg(c, "flags: 0x%02x", (UI)d->hdrflags);
	de_dbg_indent(c, -1);

	// TODO: The description field
	// TODO?: Validate more CRCs

	decode_disk_type(c, d);
	if(d->errflag) goto done;

	last_head_adj = d->last_head;
	if(last_head_adj >= d->dt_tracks_per_cyl) {
		last_head_adj = d->dt_tracks_per_cyl-1;
	}
	d->num_tracks_stored_reported = d->last_cyl * d->dt_tracks_per_cyl +
		(last_head_adj+1);
	de_dbg(c, "num tracks stored (calculated): %"I64_FMT,
		d->num_tracks_stored_reported);
	if(d->num_tracks_stored_reported > DXP_MAX_TRACKS) {
		d->need_errmsg = 1;
		goto done;
	}

	if((d->hdrflags & 0xfe) != 0) {
		d->errflag = 1;
		if(d->hdrflags & 0x02) {
			de_err(c, "Encrypted disk images are not supported");
		}
		else {
			de_err(c, "This type of disk image is not supported");
		}
		goto done;
	}

	dxp_decode(c, d);

done:
	if(d->is_ibm_licensed) {
		de_dbg(c, "[IBM licensed]");
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_dskexp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	UI sig;

	d = de_malloc(c, sizeof(lctx));
	d->crco1 = de_crcobj_create(c, DE_CRCOBJ_CRC32_JAMCRC);
	d->crco2 = de_crcobj_create(c, DE_CRCOBJ_CRC32_JAMCRC);

	sig = (UI)de_getu16be(0);
	if(sig==0x4d5a || sig==0x5a4d) {
		d->is_exe = 1;
	}
	else if(sig==0x4153) {
		;
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}

	if(d->is_exe) {
		fmtutil_collect_exe_info(c, c->infile, &d->ei);
		d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_DSKEXP;
		fmtutil_detect_specialexe(c, &d->ei, &d->edd);
		if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_DSKEXP) {
			de_err(c, "Not a known Disk Express format");
			goto done;
		}

		d->as_hdr_pos = d->ei.end_of_dos_code + 4;
	}
	else {
		d->as_hdr_pos = 0;
	}

	dxp_main(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported DXP file");
		}
		dbuf_close(d->trkbuf);
		dbuf_close(d->diskbuf);
		de_finfo_destroy(c, d->fi);
		de_crcobj_destroy(d->crco1);
		de_crcobj_destroy(d->crco2);
		de_free(c, d);
	}
}

static int de_identify_dskexp(deark *c)
{
	UI n;
	u8 major_ver, minor_ver, rel;
	u8 cmpr_meth;

	if(c->infile->len<515) return 0;
	// [A lot of this is duplicated in detect_specialexe_dskexp().]
	n = (UI)de_getu16be(0);
	if(n!=0x4153) return 0; // "AS"
	major_ver = de_getbyte(2);
	// v1 non-executable files will never be created by the software,
	// but we allow them.
	if(major_ver!=1 && major_ver!=2) return 0;
	minor_ver = de_getbyte(3);
	if(major_ver==1) {
		// v1.04 is used in some IBM-licensed files
		if(minor_ver!=1 && minor_ver!=4) return 0;
	}
	else if(major_ver==2) {
		if(minor_ver!=0 && minor_ver!=30) return 0;
	}
	// TODO: Research this field. It's possibly for, e.g., the "a" in
	// version "2.10a", but I don't know if it was ever used. It's always(?)
	// a space.
	rel = de_getbyte(4); // "release"
	if(rel!=0x20 && rel!='A' && rel!='a') return 0;
	cmpr_meth = de_getbyte(10);
	if(cmpr_meth!=0 && cmpr_meth!=major_ver) return 0;

	return (major_ver==2)?95:45;
}

void de_module_dskexp(deark *c, struct deark_module_info *mi)
{
	mi->id = "dskexp";
	mi->desc = "Disk Express";
	mi->run_fn = de_run_dskexp;
	mi->identify_fn = de_identify_dskexp;
}
