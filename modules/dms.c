// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Amiga DMS (Disk Masher System) disk image

// The DMS module was developed with the help of information from xDMS -
// public domain(-ish) software by Andre Rodrigues de la Rocha.

#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_amiga_dms);

////////////////////////// DMS //////////////////////////

// Used as both the maximum number of physical tracks in the file, and (one more
// than) the highest logical track number allowed for a "real" track.
#define DMS_MAX_TRACKS 200

#define DMS_FILE_HDR_LEN 56
#define DMS_TRACK_HDR_LEN 20

struct dms_track_info {
	i64 track_num; // The reported (logical) track number
	i64 dpos;
	i64 cmpr_len;
	i64 intermediate_len;
	i64 uncmpr_len;
	UI track_flags;
	UI cmpr_type;
	u8 is_real;
	u32 cksum_reported;
	u32 crc_cmprdata_reported;
	u32 crc_header_reported;
	u32 cksum_calc;
	char shortname[80];
};

struct dms_tracks_by_file_order_entry {
	i64 file_pos;
	u32 track_num;
	u8 is_real;
};

struct dms_tracks_by_track_num_entry {
	u32 order_in_file;
	u8 in_use;
};

struct dmsctx {
	UI info_bits;
	UI cmpr_type;
	i64 first_track, last_track;
	i64 num_tracks_in_file;

	// Entries in use: 0 <= n < .num_tracks_in_file
	struct dms_tracks_by_file_order_entry tracks_by_file_order[DMS_MAX_TRACKS];

	// Entries potentially in use: .first_track <= n <= .last_track
	struct dms_tracks_by_track_num_entry tracks_by_track_num[DMS_MAX_TRACKS];
};

static const char *dms_get_cmprtype_name(UI n)
{
	const char *name = NULL;
	switch(n) {
	case 0: name="uncompressed"; break;
	case 1: name="simple (RLE)"; break;
	case 2: name="quick"; break;
	case 3: name="medium"; break;
	case 4: name="deep (LZ+dynamic_huffman + RLE)"; break;
	case 5: name="heavy1"; break;
	case 6: name="heavy2"; break;
	}
	return name?name:"?";
}

static void read_unix_timestamp(deark *c, i64 pos, struct de_timestamp *ts, const char *name)
{
	i64 t;
	char timestamp_buf[64];

	t = de_geti32be(pos);
	de_unix_time_to_timestamp(t, ts, 0x1);
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, t, timestamp_buf);
}

// DMS RLE:
// n1     n2          n3  n4  n5
// ---------------------------------------------------------
// 0x90   0x00                     emit 0x90
// 0x90   0x01..0xfe  n3           emit n2 copies of n3
// 0x90   0xff        n3  n4  n5   emit (n4#n5) copies of n3
// !0x90                           emit n1

enum dmsrle_state {
	DMSRLE_STATE_NEUTRAL = 0,
	DMSRLE_STATE_90,
	DMSRLE_STATE_90_N2,
	DMSRLE_STATE_90_FF_N3,
	DMSRLE_STATE_90_FF_N3_N4
};

struct dmsrle_ctx {
	enum dmsrle_state state;
	u8 n2, n3, n4;
};

static void dmsrle_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	i64 i;
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(!rctx) goto done;

	for(i=0; i<buf_len; i++) {
		u8 n;
		i64 count;

		n = buf[i];

		switch(rctx->state) {
		case DMSRLE_STATE_NEUTRAL:
			if(n==0x90) {
				rctx->state = DMSRLE_STATE_90;
			}
			else {
				dbuf_writebyte(dfctx->dcmpro->f, n);
			}
			break;
		case DMSRLE_STATE_90:
			if(n==0x00) {
				dbuf_writebyte(dfctx->dcmpro->f, 0x90);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			else {
				rctx->n2 = n;
				rctx->state = DMSRLE_STATE_90_N2;
			}
			break;
		case DMSRLE_STATE_90_N2:
			if(rctx->n2==0xff) {
				rctx->n3 = n;
				rctx->state = DMSRLE_STATE_90_FF_N3;
			}
			else {
				count = (i64)rctx->n2;
				dbuf_write_run(dfctx->dcmpro->f, n, count);
				rctx->state = DMSRLE_STATE_NEUTRAL;
			}
			break;
		case DMSRLE_STATE_90_FF_N3:
			rctx->n4 = n;
			rctx->state = DMSRLE_STATE_90_FF_N3_N4;
			break;
		case DMSRLE_STATE_90_FF_N3_N4:
			count = (i64)(((UI)rctx->n4 << 8) | n);
			dbuf_write_run(dfctx->dcmpro->f, rctx->n3, count);
			rctx->state = DMSRLE_STATE_NEUTRAL;
			break;
		}
	}
done:
	;
}

static void dmsrle_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct dmsrle_ctx *rctx = (struct dmsrle_ctx*)dfctx->codec_private;

	if(rctx) {
		de_free(dfctx->c, rctx);
	}
	dfctx->codec_private = NULL;
}

// codec_private_params: Unused, should be NULL.
static void dmsrle_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct dmsrle_ctx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct dmsrle_ctx));
	rctx->state = DMSRLE_STATE_NEUTRAL;
	dfctx->codec_private = (void*)rctx;
	dfctx->codec_addbuf_fn = dmsrle_codec_addbuf;
	dfctx->codec_finish_fn = NULL;
	dfctx->codec_destroy_fn = dmsrle_codec_destroy;
}

static void do_decompress_heavy_lzh_rle(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres, struct de_lzh_params *lzhparams)
{
	struct de_dcmpr_two_layer_params tlp;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_type1 = fmtutil_lzh_codectype1;
	tlp.codec1_private_params = (void*)lzhparams;
	tlp.codec2 = dmsrle_codec;
	tlp.dcmpri = dcmpri;
	tlp.dcmpro = dcmpro;
	tlp.dres = dres;
	tlp.intermed_expected_len = tri->intermediate_len;
	tlp.intermed_len_known = 1;
	de_dfilter_decompress_two_layer(c, &tlp);
}

static void do_decompress_heavy(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct de_lzh_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lzh_params));
	lzhparams.fmt = DE_LZH_FMT_DMS_HEAVY;
	if(tri->cmpr_type==5) {
		lzhparams.subfmt = 1; // heavy1
	}
	else {
		lzhparams.subfmt = 2; // heavy2
	}
	lzhparams.dms_track_flags = tri->track_flags;

	if(tri->track_flags & 0x04) {
		do_decompress_heavy_lzh_rle(c, d, tri, dcmpri, dcmpro, dres, &lzhparams);
	}
	else {
		// LZH, no RLE
		fmtutil_decompress_lzh(c, dcmpri, dcmpro, dres, &lzhparams);
	}
}

static int dms_decompress_track(deark *c, struct dmsctx *d, struct dms_track_info *tri,
	dbuf *outf)
{
	int retval = 0;
	i64 unc_nbytes;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(outf->len!=0) goto done;

	if(tri->dpos + tri->cmpr_len > c->infile->len) {
		de_err(c, "Track goes beyond end of file");
		goto done;
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = tri->dpos;
	dcmpri.len = tri->cmpr_len;
	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = tri->uncmpr_len;

	tri->cksum_calc = 0;

	switch(tri->cmpr_type) {
	case 0:
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case 1:
		de_dfilter_decompress_oneshot(c, dmsrle_codec, NULL,
			&dcmpri, &dcmpro, &dres);
		break;
	case 5: // heavy1
	case 6: // heavy2
		do_decompress_heavy(c, d, tri, &dcmpri, &dcmpro, &dres);
		break;
	default:
		de_err(c, "[%s] Unsupported compression method: %u (%s)",
			tri->shortname, tri->cmpr_type,
			dms_get_cmprtype_name(tri->cmpr_type));
		goto done;
	}

	if(dres.errcode) {
		de_err(c, "[%s] Decompression failed: %s", tri->shortname,
			de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	unc_nbytes = outf->len;

	dbuf_truncate(outf, tri->uncmpr_len);

	if(unc_nbytes < tri->uncmpr_len) {
		de_err(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
		goto done;
	}
	if(unc_nbytes > tri->uncmpr_len) {
		de_warn(c, "[%s] Expected %"I64_FMT" decompressed bytes, got %"I64_FMT,
			tri->shortname, tri->uncmpr_len, unc_nbytes);
	}

	retval = 1;

done:
	return retval;
}


static int dms_checksum_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	u32 *cksum = (u32*)brctx->userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		*cksum += (u32)buf[i];
	}
	return 1;
}

// outf is presumed to be membuf containing one track, and nothing else.
static u32 dms_calc_checksum(deark *c, dbuf *outf)
{
	u32 cksum = 0;

	dbuf_buffered_read(outf, 0, outf->len, dms_checksum_cbfn, (void*)&cksum);
	cksum &= 0xffff;
	return cksum;
}

// Read track and decompress to outf (which caller supplies as an empty membuf).
// track_idx: the index into d->tracks_by_file_order
// Returns nonzero if successfully decompressed.
static int dms_read_and_decompress_track(deark *c, struct dmsctx *d,
	i64 track_idx, dbuf *outf)
{
	i64 pos1, pos;
	struct dms_track_info *tri = NULL;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	tri = de_malloc(c, sizeof(struct dms_track_info));
	pos1 = d->tracks_by_file_order[track_idx].file_pos;
	tri->track_num = (i64)d->tracks_by_file_order[track_idx].track_num;
	tri->is_real = d->tracks_by_file_order[track_idx].is_real;
	de_snprintf(tri->shortname, sizeof(tri->shortname), "%strack %d",
		(tri->is_real?"":"extra "), (int)tri->track_num);

	de_dbg(c, "%s at %"I64_FMT, tri->shortname, pos1);
	de_dbg_indent(c, 1);
	pos = pos1;
	pos += 2; // signature, already checked
	pos += 2; // reported track number, already read
	pos += 2; // Unknown field
	tri->cmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "cmpr len: %"I64_FMT, tri->cmpr_len);
	tri->intermediate_len = de_getu16be_p(&pos);
	de_dbg(c, "intermediate len: %"I64_FMT, tri->intermediate_len);
	tri->uncmpr_len = de_getu16be_p(&pos);
	de_dbg(c, "uncmpr len: %"I64_FMT, tri->uncmpr_len);

	tri->track_flags = (UI)de_getbyte_p(&pos);
	de_dbg(c, "track flags: 0x%02x", tri->track_flags);
	tri->cmpr_type = (UI)de_getbyte_p(&pos);
	de_dbg(c, "track cmpr type: %u (%s)", tri->cmpr_type, dms_get_cmprtype_name(tri->cmpr_type));
	tri->cksum_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "checksum (reported): 0x%04x", (UI)tri->cksum_reported);
	tri->crc_cmprdata_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "crc of cmpr data (reported): 0x%04x", (UI)tri->crc_cmprdata_reported);
	tri->crc_header_reported = (u32)de_getu16be_p(&pos);
	de_dbg(c, "crc of header (reported): 0x%04x", (UI)tri->crc_header_reported);

	tri->dpos = pos1 + DMS_TRACK_HDR_LEN;
	de_dbg(c, "cmpr data pos: %"I64_FMT, tri->dpos);

	if(!dms_decompress_track(c, d, tri, outf)) goto done;

	tri->cksum_calc = dms_calc_checksum(c, outf);
	de_dbg(c, "checksum (calculated): 0x%04x", (UI)tri->cksum_calc);
	if(tri->cksum_calc != tri->cksum_reported) {
		de_err(c, "Checksum check failed");
		goto done;
	}
	retval = 1;

done:
	de_free(c, tri);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_dms_real_tracks(deark *c, struct dmsctx *d)
{
	i64 i;
	dbuf *outf = NULL;
	dbuf *trackbuf = NULL;

	trackbuf = dbuf_create_membuf(c, 11264, 0);

	for(i=d->first_track; i<=d->last_track; i++) {
		int ret;
		u32 file_idx;

		if(!d->tracks_by_track_num[i].in_use) {
			continue;
		}

		file_idx = d->tracks_by_track_num[i].order_in_file;

		dbuf_truncate(trackbuf, 0);
		ret = dms_read_and_decompress_track(c, d, file_idx, trackbuf);
		if(!ret) goto done;

		if(!outf) {
			outf = dbuf_create_output_file(c, "adf", NULL, 0);
		}
		dbuf_copy(trackbuf, 0, trackbuf->len, outf);
	}

done:
	dbuf_close(outf);
	dbuf_close(trackbuf);
}

static void do_dms_extra_tracks(deark *c, struct dmsctx *d)
{
	i64 i;
	dbuf *trackbuf = NULL;

	for(i=0; i<d->num_tracks_in_file; i++) {
		int ret;
		dbuf *outf = NULL;
		char ext[80];

		if(d->tracks_by_file_order[i].is_real) continue;

		if(!trackbuf) {
			trackbuf = dbuf_create_membuf(c, 11264, 0);
		}

		dbuf_truncate(trackbuf, 0);
		ret = dms_read_and_decompress_track(c, d, i, trackbuf);
		if(!ret) continue;

		de_snprintf(ext, sizeof(ext), "extratrack%d.bin",
			(int)d->tracks_by_file_order[i].track_num);
		outf = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
		dbuf_copy(trackbuf, 0, trackbuf->len, outf);
		dbuf_close(outf);
		outf = NULL;
	}

	dbuf_close(trackbuf);
}

static int do_dms_header(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 n;
	i64 pos = pos1;
	struct de_timestamp cr_time;
	int retval = 0;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// [0..3] = signature
	pos = pos1+8;
	d->info_bits = (UI)de_getu32be_p(&pos); // [8..11] = info bits
	de_dbg(c, "infobits: 0x%08x", d->info_bits);

	de_zeromem(&cr_time, sizeof(struct de_timestamp));
	read_unix_timestamp(c, pos, &cr_time, "creation time");
	pos += 4;

	d->first_track = de_getu16be_p(&pos); // [16..17] = firsttrack
	de_dbg(c, "first track: %d", (int)d->first_track);
	if(d->first_track >= DMS_MAX_TRACKS) goto done;
	d->last_track = de_getu16be_p(&pos); // [18..19] = lasttrack
	de_dbg(c, "last track: %u", (int)d->last_track);
	if(d->last_track < d->first_track) goto done;
	if(d->last_track >= DMS_MAX_TRACKS) goto done;

	n = de_getu32be_p(&pos); // [20..23] = packed len
	de_dbg(c, "compressed len: %"I64_FMT, n);

	n = de_getu32be_p(&pos); // [24..27] = unpacked len
	de_dbg(c, "decompressed len: %"I64_FMT, n);

	// [46..47] = creating software version
	pos = pos1+50;
	n = de_getu16be_p(&pos); // [50..51] = disk type
	de_dbg(c, "disk type: %u", (UI)n);

	d->cmpr_type = (UI)de_getu16be_p(&pos); // [52..53] = compression mode
	de_dbg(c, "compression type: %u (%s)", d->cmpr_type,
		dms_get_cmprtype_name(d->cmpr_type));

	n = de_getu16be_p(&pos); // [54..55] = crc
	de_dbg(c, "crc (reported): 0x%04x", (UI)n);

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static int dms_scan_file(deark *c, struct dmsctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 i;
	int retval = 0;

	de_dbg(c, "scanning file");
	de_dbg_indent(c, 1);

	d->num_tracks_in_file = 0;

	while(1) {
		i64 track_num_reported;
		i64 cmpr_len;
		i64 uncmpr_len;
		u8 track_flags;
		u8 cmpr_type;

		if(pos+DMS_TRACK_HDR_LEN > c->infile->len) break;

		if(dbuf_memcmp(c->infile, pos, "TR", 2)) {
			de_dbg(c, "[track not found at %"I64_FMT"; assuming disk image ends here]", pos);
			break;
		}
		if(d->num_tracks_in_file >= DMS_MAX_TRACKS) {
			de_err(c, "Too many tracks in file");
			break;
		}

		track_num_reported = de_getu16be(pos+2);
		cmpr_len = de_getu16be(pos+6);
		uncmpr_len = de_getu16be(pos+10);
		track_flags = de_getbyte(pos+12);
		cmpr_type = de_getbyte(pos+13);

		de_dbg(c, "track[%d] at %"I64_FMT", #%d, len=%"I64_FMT"/%"I64_FMT", cmpr=%u, flags=0x%02x",
			(int)d->num_tracks_in_file, pos, (int)track_num_reported, cmpr_len, uncmpr_len,
			(UI)cmpr_type, (UI)track_flags);

		d->tracks_by_file_order[d->num_tracks_in_file].file_pos = pos;
		d->tracks_by_file_order[d->num_tracks_in_file].track_num = (u32)track_num_reported;

		if(track_num_reported>=d->first_track && track_num_reported<=d->last_track) {
			d->tracks_by_track_num[track_num_reported].order_in_file = (u32)d->num_tracks_in_file;
			d->tracks_by_track_num[track_num_reported].in_use = 1;
		}

		d->num_tracks_in_file++;
		pos += DMS_TRACK_HDR_LEN + cmpr_len;
	}

	// Make sure all expected tracks are present, and mark the "real" tracks in
	// tracks_by_file_order[].
	// One reason for doing it this way is that there may be two tracks numbered 0,
	// with the second one being the real one.
	for(i=d->first_track; i<=d->last_track; i++) {
		if(!d->tracks_by_track_num[i].in_use) {
			de_err(c, "Could not find track #%d", (int)i);
			goto done;
		}

		d->tracks_by_file_order[d->tracks_by_track_num[i].order_in_file].is_real = 1;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_amiga_dms(deark *c, de_module_params *mparams)
{
	struct dmsctx *d = NULL;

	d = de_malloc(c, sizeof(struct dmsctx));
	if(!do_dms_header(c, d, 0)) goto done;
	if(!dms_scan_file(c, d, DMS_FILE_HDR_LEN)) goto done;
	do_dms_real_tracks(c, d);
	do_dms_extra_tracks(c, d);

done:
	de_free(c, d);
}

static int de_identify_amiga_dms(deark *c)
{
	i64 dcmpr_size;

	if(dbuf_memcmp(c->infile, 0, "DMS!", 4)) return 0;
	dcmpr_size = de_getu32be(24);
	if(dcmpr_size==901120) return 100;
	return 85;
}

void de_module_amiga_dms(deark *c, struct deark_module_info *mi)
{
	mi->id = "amiga_dms";
	mi->desc = "Amiga DMS disk image";
	mi->run_fn = de_run_amiga_dms;
	mi->identify_fn = de_identify_amiga_dms;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
