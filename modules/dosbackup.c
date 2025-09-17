// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// MS-DOS BACKUP/RESTORE format
// - Not all versions are supported.

#include <deark-private.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_dosbackup33);
DE_DECLARE_MODULE(de_module_dosbackup20);

#define DOSBK_VER_DOS20   2  // MS-DOS 2.0-3.2
#define DOSBK_VER_DOS33   3  // MS-DOS 3.3-5.x

#define DOSBK33_MAX_VOLS 255

struct logical_member_ctx {
	dbuf *outf;
	i64 nbytes_written;
	i64 v33_nbytes_expected;
	de_ucstring *fullfn;
};

struct fragment_ctx {
	// (Many of these fields are used with v33 only.)
	u8 fragment_flags;
	int fragment_num;
	i64 pos_in_datafile;
	i64 len_in_datafile;
	i64 orig_size;
	i64 dosdt, dostm;
	u8 v20_fnlen;
	UI attribs;
	// We use stringreaderdata instead of ucstring, to allow for the
	// possibility of doing byte-for-byte comparisons of filenames, to
	// ensure we have the right fragment.
	struct de_stringreaderdata *filename_srd;
	struct de_timestamp mod_time;
};

typedef struct localctx_dosbackup33 {
	de_encoding input_encoding;
	UI fmtver;
	u8 errflag;
	u8 need_errmsg;
	int v33_num_volumes;
	int num_input_files_tot;
	int v33_num_control_files_found;
	int v33_num_data_files_found;

	// We define "xidx" to be a reference to an input file, such that
	// 0 is the main file (c->infile), 1...num_volumes are the MP files
	// 0...[num_volumes-1], and -1 is invalid.

	int *v33_control_file_xidxs; // array[num_volumes] of xidx

	// v20: array[num_input_files_tot] of xidx
	// v33: array[num_volumes] of xidx
	int *data_file_xidxs;

	struct logical_member_ctx *clm; // "current logical member"
	de_ucstring *v33_cur_dir_name;

#define V20_FSIG_LEN 79
	u8 *v20_fsig_expected;
} lctx;

static void dbg_timestamp(deark *c, struct de_timestamp *ts)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static int v33_looks_like_control_file(dbuf *f)
{
	int has_sig1;
	UI sig2;

	has_sig1 = !dbuf_memcmp(f, 0, "\x8b" "BACKUP", 7);
	if(!has_sig1) return 0;

	// Found a compressed variant format where the next two bytes are
	// different, but no plans to support it.
	sig2 = (UI)dbuf_getu16be(f, 7);
	if(sig2!=0x2020) {
		return 0;
	}
	return 1;
}

static void logical_member_finish_and_free(deark *c, lctx *d)
{
	if(!d->clm) return;

	if(d->fmtver==DOSBK_VER_DOS33 && d->clm->nbytes_written!=d->clm->v33_nbytes_expected) {
		de_err(c, "%s: Expected %"I64_FMT" bytes, got %"I64_FMT,
			ucstring_getpsz_d(d->clm->fullfn), d->clm->v33_nbytes_expected,
			d->clm->nbytes_written);
	}
	dbuf_close(d->clm->outf);
	ucstring_destroy(d->clm->fullfn);
	de_free(c, d->clm);
	d->clm = NULL;
}

static void v33_logical_member_create(deark *c, lctx *d, struct fragment_ctx *fr,
	dbuf *data_inf)
{
	de_finfo *fi = NULL;

	logical_member_finish_and_free(c, d);
	d->clm = de_malloc(c, sizeof(struct logical_member_ctx));
	d->clm->fullfn = ucstring_create(c);
	d->clm->v33_nbytes_expected = fr->orig_size;

	fi = de_finfo_create(c);

	ucstring_append_ucstring(d->clm->fullfn, d->v33_cur_dir_name);
	ucstring_append_ucstring(d->clm->fullfn, fr->filename_srd->str);

	de_finfo_set_name_from_ucstring(c, fi, d->clm->fullfn,
		DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;

	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = fr->mod_time;

	if((fr->attribs & 0x18) == 0x08) {
		fi->is_volume_label = 1;
	}

	d->clm->outf = dbuf_create_output_file(c, NULL, fi, 0);
	if(fr->pos_in_datafile + fr->len_in_datafile > data_inf->len) {
		d->errflag = 1;
		d->need_errmsg = 1;
	}

	de_finfo_destroy(c, fi);
}

static void v33_scan_one_input_file(deark *c, lctx *d, dbuf *inf, int xidx)
{
	u8 is_control_file = 0;
	u8 last_disk_marker = 0;
	int control_file_seq = 0;

	de_dbg(c, "[input file %d]", xidx);
	de_dbg_indent(c, 1);

	if(d->v33_num_control_files_found < d->v33_num_volumes) {
		is_control_file = v33_looks_like_control_file(inf);
	}
	de_dbg(c, "is control file: %u", (UI)is_control_file);
	if(is_control_file) {
		control_file_seq = (int)dbuf_getbyte(inf, 9);
		de_dbg(c, "seq num: %d", control_file_seq);

		last_disk_marker = dbuf_getbyte(inf, 0x8a);
		de_dbg(c, "last disk marker: 0x%02x", (UI)last_disk_marker);
		if((last_disk_marker==0 && control_file_seq==d->v33_num_volumes) ||
			(last_disk_marker!=0 && control_file_seq!=d->v33_num_volumes))
		{
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		// We could pretty easily support out-of-order control files, but
		// that's probably a bad idea if we're not also supporting out-of-order
		// data files.
		if(control_file_seq != d->v33_num_control_files_found+1) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		d->v33_control_file_xidxs[control_file_seq - 1] = xidx;
		d->v33_num_control_files_found++;
	}
	else {
		if(d->v33_num_data_files_found >= d->v33_num_volumes) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		d->data_file_xidxs[d->v33_num_data_files_found] = xidx;
		d->v33_num_data_files_found++;
	}

done:
	de_dbg_indent(c, -1);
}

static void scan_input_files33(deark *c, lctx *d)
{
	int xidx;
	dbuf *inf = NULL;

	de_dbg(c, "[scanning input files]");
	de_dbg_indent(c, 1);

	for(xidx=0; xidx<d->num_input_files_tot; xidx++) {
		if(d->errflag) goto done;
		inf = de_mp_acquire_dbuf(c, xidx);
		if(!inf) {
			d->errflag = 1;
			goto done;
		}

		v33_scan_one_input_file(c, d, inf, xidx);

		de_mp_release_dbuf(c, xidx, &inf);
	}

done:
	de_dbg_indent(c, -1);
}

static void destroy_fragment_ctx(deark *c, struct fragment_ctx *fr)
{
	if(!fr) return;
	de_destroy_stringreaderdata(c, fr->filename_srd);
	de_free(c, fr);
}

static void v33_extract_fragment(deark *c, lctx *d, struct fragment_ctx *fr,
	dbuf *data_inf)
{
	// TODO? There are a lot more things we could check, to make sure
	// things seem ok.
	if(fr->fragment_num<2 || !d->clm) {
		v33_logical_member_create(c, d, fr, data_inf);
	}
	if(d->errflag || !d->clm) goto done;

	dbuf_copy(data_inf, fr->pos_in_datafile, fr->len_in_datafile, d->clm->outf);
	d->clm->nbytes_written += fr->len_in_datafile;

done:
	;
}

static void fixup_filename(de_ucstring *s)
{
	i64 k;

	for(k=0; k<s->len; k++) {
		if(s->str[k]=='/' || s->str[k]=='\\') {
			s->str[k] = '_';
		}
	}

	if(ucstring_isempty(s)) {
		ucstring_append_char(s, '_');
	}
}

static void dbg_attribs(deark *c, UI x)
{
	de_ucstring *descr;

	descr = ucstring_create(c);
	de_describe_dos_attribs(c, x, descr, 0);
	de_dbg(c, "attribs: 0x%02x (%s)", x, ucstring_getpsz_d(descr));
	ucstring_destroy(descr);
}

static void do_one_volume33(deark *c, lctx *d, int vol,
	dbuf *ctrl_inf, dbuf *data_inf)
{
	i64 ctrl_pos;
	int saved_indent_level;
	struct fragment_ctx *fr = NULL;
	int num_file_items_remaining = 0;
	u8 expecting_another_dir_item = 1;
	char tmps[20];

	de_dbg_indent_save(c, &saved_indent_level);
	ctrl_pos = (i64)dbuf_getbyte(ctrl_inf, 0); // Expecting 139 (0x8b)

	while(1) {
		i64 item_pos;
		i64 item_len;
		u8 item_is_dir;

		if(num_file_items_remaining>0) {
			item_is_dir = 0;
		}
		else if(expecting_another_dir_item) {
			item_is_dir = 1;
		}
		else {
			goto done;
		}

		item_pos = ctrl_pos;
		if(item_pos >= ctrl_inf->len) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		if(item_is_dir) {
			de_dbg(c, "dir item at %"I64_FMT, item_pos);
		}
		else {
			de_dbg(c, "file item at %"I64_FMT, item_pos);
		}

		de_dbg_indent(c, 1);

		item_len = dbuf_getbyte_p(ctrl_inf, &ctrl_pos);
		de_dbg(c, "item len: %"I64_FMT, item_len);

		if(item_is_dir) {
			i64 next_dir_pos;

			if(item_len!=70) {
				d->errflag = 1;
				d->need_errmsg = 1;
				goto done;
			}

			ucstring_empty(d->v33_cur_dir_name);
			dbuf_read_to_ucstring(ctrl_inf, ctrl_pos, 63, d->v33_cur_dir_name,
				DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
			ctrl_pos += 63;
			de_dbg(c, "dir name: \"%s\"", ucstring_getpsz_d(d->v33_cur_dir_name));
			de_arch_fixup_path(d->v33_cur_dir_name, 0x1);

			num_file_items_remaining = (int)dbuf_getu16le_p(ctrl_inf, &ctrl_pos);
			de_dbg(c, "num entries: %d", num_file_items_remaining);

			next_dir_pos = dbuf_getu32le_p(ctrl_inf, &ctrl_pos);
			if(next_dir_pos==0xffffffffLL) {
				de_strlcpy(tmps, "(none)", sizeof(tmps));
				expecting_another_dir_item = 0;
			}
			else {
				de_snprintf(tmps, sizeof(tmps), "%"I64_FMT, next_dir_pos);
				expecting_another_dir_item = 1;
			}
			de_dbg(c, "next dir pos: %s", tmps);
		}
		else { // "file" item
			if(item_len!=34) {
				d->errflag = 1;
				d->need_errmsg = 1;
				goto done;
			}

			if(fr) {
				destroy_fragment_ctx(c, fr);
			}
			fr = de_malloc(c, sizeof(struct fragment_ctx));
			fr->filename_srd = dbuf_read_string(ctrl_inf, ctrl_pos, 12, 12,
				DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
			ctrl_pos += 12;
			de_dbg(c, "file name: \"%s\"", ucstring_getpsz_d(fr->filename_srd->str));
			fixup_filename(fr->filename_srd->str);

			fr->fragment_flags = dbuf_getbyte_p(ctrl_inf, &ctrl_pos);
			// 0x01=last frg; 0x02=backed up OK; 0x04=has ext. attr.
			de_dbg(c, "frg flags: 0x%02x", (UI)fr->fragment_flags);
			fr->orig_size = dbuf_getu32le_p(ctrl_inf, &ctrl_pos);
			de_dbg(c, "total file size: %"I64_FMT, fr->orig_size);
			fr->fragment_num = (int)dbuf_getu16le_p(ctrl_inf, &ctrl_pos);
			de_dbg(c, "frg num: %d", fr->fragment_num);
			fr->pos_in_datafile = dbuf_getu32le_p(ctrl_inf, &ctrl_pos);
			de_dbg(c, "pos in data file: %"I64_FMT, fr->pos_in_datafile);
			fr->len_in_datafile = dbuf_getu32le_p(ctrl_inf, &ctrl_pos);
			de_dbg(c, "len in data file: %"I64_FMT, fr->len_in_datafile);
			fr->attribs = (UI)dbuf_getu16le_p(ctrl_inf, &ctrl_pos);
			dbg_attribs(c, fr->attribs);

			fr->dostm = dbuf_getu16le_p(ctrl_inf, &ctrl_pos);
			fr->dosdt = dbuf_getu16le_p(ctrl_inf, &ctrl_pos);
			de_dos_datetime_to_timestamp(&fr->mod_time, fr->dosdt, fr->dostm);
			fr->mod_time.tzcode = DE_TZCODE_LOCAL;
			dbg_timestamp(c, &fr->mod_time);

			v33_extract_fragment(c, d, fr, data_inf);

			num_file_items_remaining--;
		}

		ctrl_pos = item_pos + item_len;
		de_dbg_indent(c, -1);
	}
done:
	destroy_fragment_ctx(c, fr);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void dosbackup33_main(deark *c, lctx *d)
{
	int v;
	dbuf *ctrl_inf = NULL;
	dbuf *data_inf = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	d->v33_cur_dir_name = ucstring_create(c);

	for(v=0; v<d->v33_num_volumes; v++) {
		if(d->errflag) goto done;
		de_dbg(c, "[volume %03d]", v+1);
		de_dbg_indent(c, 1);

		ctrl_inf = de_mp_acquire_dbuf(c, d->v33_control_file_xidxs[v]);
		if(!ctrl_inf) {
			d->errflag = 1;
			goto done;
		}
		data_inf = de_mp_acquire_dbuf(c, d->data_file_xidxs[v]);
		if(!data_inf) {
			d->errflag = 1;
			goto done;
		}

		do_one_volume33(c, d, v, ctrl_inf, data_inf);

		de_mp_release_dbuf(c, d->v33_control_file_xidxs[v], &ctrl_inf);
		de_mp_release_dbuf(c, d->data_file_xidxs[v], &data_inf);
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void dbk_destroy_lctx(deark *c, lctx *d)
{
	if(!d) return;

	logical_member_finish_and_free(c, d);

	if(d->need_errmsg) {
		de_err(c, "Failed to process this MS-DOS BACKUP set");
	}
	ucstring_destroy(d->v33_cur_dir_name);
	de_free(c, d->v33_control_file_xidxs);
	de_free(c, d->data_file_xidxs);
	de_free(c, d->v20_fsig_expected);
	de_free(c, d);
}

static void de_run_dosbackup33(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int v;

	d = de_malloc(c, sizeof(lctx));
	d->fmtver = DOSBK_VER_DOS33;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	de_declare_fmt(c, "MS-DOS BACKUP (MS-DOS 3.3-5.x)");

	if(!c->mp_data || ((c->mp_data->count%2)!=1)) {
		// (Need an odd number of *extra* files.)
		de_err(c, "Incomplete DOS BACKUP");
		de_info(c, "Note: Must use \"-mp\" option, and list all CONTROL and "
			"BACKUP files");
		goto done;
	}

	d->num_input_files_tot = 1+c->mp_data->count;

	d->v33_num_volumes = d->num_input_files_tot/2;
	if(d->v33_num_volumes<1 || d->v33_num_volumes>DOSBK33_MAX_VOLS) {
		d->need_errmsg = 1;
		goto done;
	}

	d->v33_control_file_xidxs = de_mallocarray(c, d->v33_num_volumes, sizeof(int));
	d->data_file_xidxs = de_mallocarray(c, d->v33_num_volumes, sizeof(int));
	for(v=0; v<d->v33_num_volumes; v++) {
		d->v33_control_file_xidxs[v] = -1;
		d->data_file_xidxs[v] = -1;
	}

	de_dbg(c, "num vols: %d", d->v33_num_volumes);
	scan_input_files33(c, d);
	if(d->errflag) goto done;

	// Verify that we have all the needed files.
	for(v=0; v<d->v33_num_volumes; v++) {
		de_dbg2(c, "ctrl file_idxs[%d] = %d", v, d->v33_control_file_xidxs[v]);
		de_dbg2(c, "data file idx[%d] = %d", v, d->data_file_xidxs[v]);
		if(d->v33_control_file_xidxs[v]<0 || d->data_file_xidxs[v]<0) {
			d->need_errmsg = 1;
			goto done;
		}
	}

	dosbackup33_main(c, d);

done:
	dbk_destroy_lctx(c, d);
}

static int de_identify_dosbackup33(deark *c)
{
	if(v33_looks_like_control_file(c->infile))
		return 100;
	return 0;
}

void de_module_dosbackup33(deark *c, struct deark_module_info *mi)
{
	mi->id = "dosbackup33";
	mi->desc = "MS-DOS BACKUP (v3.3+)";
	mi->run_fn = de_run_dosbackup33;
	mi->identify_fn = de_identify_dosbackup33;
	mi->flags |= DE_MODFLAG_MULTIPART;
}

// **************************************************************************

static void dbk20_scan_one_input_file(deark *c, lctx *d,
	dbuf *inf, int xidx)
{
	u8 last_frg_marker;
	int file_seq;
	u8 *fsig_actual = NULL;

	de_dbg(c, "[input file %d]", xidx);
	de_dbg_indent(c, 1);

	last_frg_marker = dbuf_getbyte(inf, 0);
	de_dbg(c, "last frg marker: 0x%02x", (UI)last_frg_marker);
	file_seq = (int)dbuf_getu16le(inf, 1);
	de_dbg(c, "seq num: %d", file_seq);

	if(d->num_input_files_tot==1 && (file_seq!=1 || last_frg_marker==0)) {
		de_err(c, "This is one fragment of a fragmented file.");
		de_info(c, "Note: Use \"-mp\" option, and list all fragments.");
		d->errflag = 1;
		goto done;
	}

	if(file_seq<1 || file_seq>d->num_input_files_tot) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
	if((last_frg_marker==0 && file_seq==d->num_input_files_tot) ||
		(last_frg_marker!=0 && file_seq!=d->num_input_files_tot))
	{
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	fsig_actual = de_malloc(c, V20_FSIG_LEN);
	dbuf_read(inf, fsig_actual, 5, V20_FSIG_LEN);
	if(d->v20_fsig_expected) {
		if(de_memcmp(d->v20_fsig_expected, fsig_actual, V20_FSIG_LEN)) {
			// We were given fragments of different files
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
	}
	else {
		// First fragment. Don't compare, but save for next time
		d->v20_fsig_expected = fsig_actual;
		fsig_actual = NULL;
	}

	d->data_file_xidxs[file_seq - 1] = xidx;

done:
	de_free(c, fsig_actual);
	de_dbg_indent(c, -1);
}

static void scan_input_files20(deark *c, lctx *d)
{
	int xidx;
	dbuf *inf = NULL;

	de_dbg(c, "[scanning input files]");
	de_dbg_indent(c, 1);

	for(xidx=0; xidx<d->num_input_files_tot; xidx++) {
		if(d->errflag) goto done;
		inf = de_mp_acquire_dbuf(c, xidx);
		if(!inf) {
			d->errflag = 1;
			goto done;
		}

		dbk20_scan_one_input_file(c, d, inf, xidx);

		de_mp_release_dbuf(c, xidx, &inf);
	}

done:
	de_dbg_indent(c, -1);
}

static void v20_logical_member_create(deark *c, lctx *d, struct fragment_ctx *fr,
	dbuf *data_inf)
{
	de_finfo *fi = NULL;

	if(d->clm) {
		d->errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}
	fi = de_finfo_create(c);
	d->clm = de_malloc(c, sizeof(struct logical_member_ctx));
	d->clm->fullfn = ucstring_clone(fr->filename_srd->str);
	de_arch_fixup_path(d->clm->fullfn, 0);
	if(ucstring_isempty(d->clm->fullfn)) {
		ucstring_append_char(d->clm->fullfn, '_');
	}

	de_finfo_set_name_from_ucstring(c, fi, d->clm->fullfn,
		DE_SNFLAG_FULLPATH);
	fi->original_filename_flag = 1;

	d->clm->outf = dbuf_create_output_file(c, NULL, fi, 0);

done:
	de_finfo_destroy(c, fi);
}

static void dosbackup20_main(deark *c, lctx *d)
{
	dbuf *inf = NULL;
	int saved_indent_level;
	int v;
	struct fragment_ctx *fr = NULL;

	de_dbg_indent_save(c, &saved_indent_level);

	for(v=0; v<d->num_input_files_tot; v++) {
		if(d->errflag) goto done;

		de_dbg(c, "[fragment %d - input file #%d]", v+1, d->data_file_xidxs[v]);
		de_dbg_indent(c, 1);
		inf = de_mp_acquire_dbuf(c, d->data_file_xidxs[v]);
		if(!inf) {
			d->errflag = 1;
			goto done;
		}
		if(fr) {
			destroy_fragment_ctx(c, fr);
		}
		fr = de_malloc(c, sizeof(struct fragment_ctx));

		fr->v20_fnlen = dbuf_getbyte(inf, 83);
		if(fr->v20_fnlen<1 || fr->v20_fnlen>78) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		fr->filename_srd = dbuf_read_string(inf, 5, (i64)fr->v20_fnlen, (i64)fr->v20_fnlen,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(fr->filename_srd->str));

		if(!d->clm) {
			v20_logical_member_create(c, d, fr, inf);
			if(d->errflag) goto done;
		}

		fr->pos_in_datafile = 128;
		fr->len_in_datafile = inf->len - fr->pos_in_datafile;
		de_dbg(c, "len in data file: %"I64_FMT, fr->len_in_datafile);
		if(fr->len_in_datafile<0) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		dbuf_copy(inf, fr->pos_in_datafile, fr->len_in_datafile, d->clm->outf);
		d->clm->nbytes_written += fr->len_in_datafile;

		de_mp_release_dbuf(c, d->data_file_xidxs[v], &inf);
		de_dbg_indent(c, -1);
	}

done:
	logical_member_finish_and_free(c, d);
	destroy_fragment_ctx(c, fr);
	de_dbg_indent_restore(c, saved_indent_level);

}

static void de_run_dosbackup20(deark *c, de_module_params *mparams)
{
	int v;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->fmtver = DOSBK_VER_DOS20;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);
	de_declare_fmt(c, "MS-DOS BACKUP (MS-DOS 2.0-3.2)");

	d->num_input_files_tot = 1;
	if(c->mp_data) d->num_input_files_tot += c->mp_data->count;

	d->data_file_xidxs = de_mallocarray(c, d->num_input_files_tot, sizeof(int));
	for(v=0; v<d->num_input_files_tot; v++) {
		d->data_file_xidxs[v] = -1;
	}

	scan_input_files20(c, d);
	if(d->errflag) goto done;

	// Verify that we have all the needed files.
	for(v=0; v<d->num_input_files_tot; v++) {
		de_dbg2(c, "data file idx[%d] = %d", v, d->data_file_xidxs[v]);
		if(d->data_file_xidxs[v]<0) {
			d->need_errmsg = 1;
			goto done;
		}
	}

	dosbackup20_main(c, d);

done:
	dbk_destroy_lctx(c, d);
}

static int de_identify_dosbackup20(deark *c)
{
	u8 b0;
	u8 b;
	u8 fnlen;
	UI seq_num;
	UI n;
	i64 nulpos;

	if(c->infile->len<128) return 0;
	b0 = de_getbyte(0);
	if(b0!=0 && b0!=0xff) return 0;

	// first letter of filename
	b = de_getbyte(5);
	if(b!='\\' && b!='/') return 0;

	seq_num = (UI)de_getu16le(1);
	if(seq_num==0 || seq_num>255) return 0;

	n = (UI)de_getu16le(3); // unknown bytes, expecting 0
	if(n!=0) return 0;

	// len seems to include the trailing NUL
	fnlen = de_getbyte(83);
	if(fnlen<3 || fnlen>78) return 0;
	nulpos = 5+(i64)fnlen-1;

	// last letter of filename
	b = de_getbyte(nulpos-1);
	if(b<33) return 0;

	// Expecting zeros from the filename trailing NUL, until the fn
	// length byte.
	if(!dbuf_is_all_zeroes(c->infile, nulpos, 83-nulpos)) return 0;

	// Expecting zeroes to fill out the 128-byte header.
	if(!dbuf_is_all_zeroes(c->infile, 84, 44)) return 0;

	return (b0==0xff && seq_num==1) ? 45 : 29;
}

void de_module_dosbackup20(deark *c, struct deark_module_info *mi)
{
	mi->id = "dosbackup20";
	mi->desc = "MS-DOS BACKUP (v2.0-3.2)";
	mi->run_fn = de_run_dosbackup20;
	mi->identify_fn = de_identify_dosbackup20;
	mi->flags |= DE_MODFLAG_MULTIPART;
}
