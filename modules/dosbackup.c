// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// MS-DOS BACKUP/RESTORE format
// - Not all versions are supported.

#include <deark-private.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_dosbackup33);

#define DOSBK_VER_DOS33   3  // MS-DOS 3.3-5.x

#define DOSBK_MAX_VOLS 255

struct input_file_ctx {
	u8 is_control_file;
	u8 last_disk_marker;
	int control_file_seq;
};

struct logical_member_ctx {
	dbuf *outf;
	i64 nbytes_written;
	i64 nbytes_expected;
	de_ucstring *fullfn;
};

struct fragment_ctx {
	u8 fragment_flags;
	int fragment_num;
	i64 pos_in_datafile;
	i64 len_in_datafile;
	i64 orig_size;
	i64 dosdt, dostm;
	UI attribs;
	struct de_stringreaderdata *filename_srd;
	struct de_timestamp mod_time;
};

typedef struct localctx_dosbackup33 {
	de_encoding input_encoding;
	UI fmtver;
	u8 errflag;
	u8 need_errmsg;
	int num_volumes;
	int num_input_files_tot;
	int num_control_files_found;
	int num_data_files_found;

	// We define "xidx" to be a reference to an input file, such that
	// 0 is the main file (c->infile), 1...num_volumes are the MP files
	// 0...[num_volumes-1], and -1 is invalid.
	// input_files is indexed by "xidx".
	struct input_file_ctx *input_files; // array[num_input_files_tot]

	int *control_file_xidxs; // array[num_volumes] of xidx
	int *data_file_xidxs; // array[num_volumes] of xidx

	struct logical_member_ctx *clm; // "current logical member"
	de_ucstring *cur_dir_name;
} lctx;

static void dbg_timestamp(deark *c, struct de_timestamp *ts)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
}

static int looks_like_33control_file(dbuf *f, UI *pfmtver)
{
	int has_sig1;
	UI sig2;

	if(pfmtver) *pfmtver = 0;
	has_sig1 = !dbuf_memcmp(f, 0, "\x8b" "BACKUP", 7);
	if(!has_sig1) return 0;

	sig2 = (UI)dbuf_getu16be(f, 7);
	if(sig2==0x2020) {
		if(pfmtver) *pfmtver = DOSBK_VER_DOS33;
	}
	else {
		return 0;
	}
	return 1;
}

static dbuf *dbk_acquire_dbuf(deark *c, lctx *d, int xidx)
{
	int mpidx;

	if(xidx==0) return c->infile;
	mpidx = xidx-1;
	if(mpidx<0 || mpidx>=c->mp_data->count) return NULL;
	if(!c->mp_data->item[mpidx].f) {
		c->mp_data->item[mpidx].f = dbuf_open_input_file(c, c->mp_data->item[mpidx].fn);
		if(!c->mp_data->item[mpidx].f) {
			d->errflag = 1;
		}
	}
	return c->mp_data->item[mpidx].f;
}

static void dbk_release_dbuf(deark *c, lctx *d, int xidx)
{
	int mpidx;

	if(xidx==0) return;
	mpidx = xidx-1;
	if(mpidx<0 || mpidx>=c->mp_data->count) return;
	if(c->mp_data->item[mpidx].f) {
		dbuf_close(c->mp_data->item[mpidx].f);
		c->mp_data->item[mpidx].f = NULL;
	}
}

static void logical_member_finish_and_free(deark *c, lctx *d)
{
	if(!d->clm) return;

	if(d->clm->nbytes_written != d->clm->nbytes_expected) {
		de_err(c, "%s: Expected %"I64_FMT" bytes, got %"I64_FMT,
			ucstring_getpsz_d(d->clm->fullfn), d->clm->nbytes_expected,
			d->clm->nbytes_written);
	}
	dbuf_close(d->clm->outf);
	ucstring_destroy(d->clm->fullfn);
	de_free(c, d->clm);
	d->clm = NULL;
}

static void logical_member_create(deark *c, lctx *d, struct fragment_ctx *fr,
	dbuf *data_inf)
{
	de_finfo *fi = NULL;

	logical_member_finish_and_free(c, d);
	d->clm = de_malloc(c, sizeof(struct logical_member_ctx));
	d->clm->fullfn = ucstring_create(c);
	d->clm->nbytes_expected = fr->orig_size;

	fi = de_finfo_create(c);

	ucstring_append_ucstring(d->clm->fullfn, d->cur_dir_name);
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

static void scan_one_input_file(deark *c, lctx *d, dbuf *inf, int xidx)
{
	struct input_file_ctx *ii = &d->input_files[xidx];
	UI fmtver = 0;

	de_dbg(c, "[input file %d]", xidx);
	de_dbg_indent(c, 1);

	if(d->num_control_files_found < d->num_volumes) {
		ii->is_control_file = looks_like_33control_file(inf, &fmtver);
	}
	de_dbg(c, "is control file: %u", (UI)ii->is_control_file);
	if(ii->is_control_file) {
		if(d->fmtver==0) {
			d->fmtver = fmtver;
		}

		ii->control_file_seq = (int)dbuf_getbyte(inf, 9);
		de_dbg(c, "seq num: %d", ii->control_file_seq);

		ii->last_disk_marker = dbuf_getbyte(inf, 0x8a);
		de_dbg(c, "last disk marker: 0x%02x", (UI)ii->last_disk_marker);
		if((ii->last_disk_marker==0 && ii->control_file_seq==d->num_volumes) ||
			(ii->last_disk_marker!=0 && ii->control_file_seq!=d->num_volumes))
		{
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}

		// We could pretty easily support out-of-order control files, but
		// that's probably a bad idea if we're not also supporting out-of-order
		// data files.
		if(ii->control_file_seq != d->num_control_files_found+1) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		d->control_file_xidxs[ii->control_file_seq - 1] = xidx;
		d->num_control_files_found++;
	}
	else {
		if(d->num_data_files_found >= d->num_volumes) {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		d->data_file_xidxs[d->num_data_files_found] = xidx;
		d->num_data_files_found++;
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
		inf = dbk_acquire_dbuf(c, d, xidx);
		if(!inf) goto done;

		scan_one_input_file(c, d, inf, xidx);

		dbk_release_dbuf(c, d, xidx);
		inf = NULL;
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

static void extract_fragment(deark *c, lctx *d, struct fragment_ctx *fr,
	dbuf *data_inf)
{
	// TODO? There are a lot more things we could check, to make sure
	// things seem ok.
	if(fr->fragment_num<2 || !d->clm) {
		logical_member_create(c, d, fr, data_inf);
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

	de_dbg_indent_save(c, &saved_indent_level);
	ctrl_pos = 0x8b;
	while(1) {
		i64 item_pos;
		i64 item_len;
#define ITEMTYPE_DIR   1
#define ITEMTYPE_FILE  2
#define ITEMTYPE_EOF   3
		u8 itemtype = 0;

		item_pos = ctrl_pos;
		if(item_pos >= ctrl_inf->len) goto done;
		de_dbg(c, "ctrl item at %"I64_FMT, item_pos);
		de_dbg_indent(c, 1);
		item_len = dbuf_getbyte_p(ctrl_inf, &ctrl_pos);
		de_dbg(c, "item len: %"I64_FMT, item_len);

		// TODO?: This is not really the right way to determine the item
		// type. It's something like, the first item is always a DIR, and
		// each DIR contains a pointer to the next DIR.
		if(item_len==0) {
			itemtype = ITEMTYPE_EOF;
		}
		else if(d->fmtver==DOSBK_VER_DOS33 && item_len==0x46) {
			itemtype = ITEMTYPE_DIR;
		}
		else if(d->fmtver==DOSBK_VER_DOS33 && item_len==0x22) {
			itemtype = ITEMTYPE_FILE;
		}

		if(itemtype==ITEMTYPE_DIR) {
			ucstring_empty(d->cur_dir_name);
			dbuf_read_to_ucstring(ctrl_inf, ctrl_pos, 63, d->cur_dir_name,
				DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
			ctrl_pos += 63;
			de_dbg(c, "dir name: \"%s\"", ucstring_getpsz_d(d->cur_dir_name));
			de_arch_fixup_path(d->cur_dir_name, 0x1);
		}
		else if(itemtype==ITEMTYPE_FILE) {
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

			extract_fragment(c, d, fr, data_inf);
		}
		else if(itemtype==ITEMTYPE_EOF) {
			goto done;
		}
		else {
			d->errflag = 1;
			d->need_errmsg = 1;
			goto done;
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

	d->cur_dir_name = ucstring_create(c);

	for(v=0; v<d->num_volumes; v++) {
		if(d->errflag) goto done;
		de_dbg(c, "[volume %03d]", v+1);
		de_dbg_indent(c, 1);

		ctrl_inf = dbk_acquire_dbuf(c, d, d->control_file_xidxs[v]);
		if(!ctrl_inf) goto done;
		data_inf = dbk_acquire_dbuf(c, d, d->data_file_xidxs[v]);
		if(!data_inf) goto done;

		do_one_volume33(c, d, v, ctrl_inf, data_inf);

		dbk_release_dbuf(c, d, d->control_file_xidxs[v]);
		dbk_release_dbuf(c, d, d->data_file_xidxs[v]);
		ctrl_inf = NULL;
		data_inf = NULL;
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_dosbackup33(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int v;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	if(!c->mp_data || ((c->mp_data->count%2)!=1)) {
		// (Need an odd number of *extra* files.)
		de_err(c, "Incomplete DOS BACKUP");
		de_info(c, "Note: Must use \"-mp\" option, and list all CONTROL and "
			"BACKUP files");
		goto done;
	}

	d->num_input_files_tot = 1+c->mp_data->count;

	d->num_volumes = d->num_input_files_tot/2;
	if(d->num_volumes<1 || d->num_volumes>DOSBK_MAX_VOLS) {
		d->need_errmsg = 1;
		goto done;
	}

	d->input_files = de_mallocarray(c, d->num_input_files_tot,
		sizeof(struct input_file_ctx));

	d->control_file_xidxs = de_mallocarray(c, d->num_volumes, sizeof(int));
	d->data_file_xidxs = de_mallocarray(c, d->num_volumes, sizeof(int));
	for(v=0; v<d->num_volumes; v++) {
		d->control_file_xidxs[v] = -1;
		d->data_file_xidxs[v] = -1;
	}

	de_dbg(c, "num vols: %d", d->num_volumes);
	scan_input_files33(c, d);
	if(d->fmtver==DOSBK_VER_DOS33) {
		de_declare_fmt(c, "MS-DOS BACKUP (MS-DOS 3.3-5.x)");
	}
	if(d->errflag) goto done;

	// Verify that we have all the needed files.
	for(v=0; v<d->num_volumes; v++) {
		de_dbg2(c, "ctrl file_idxs[%d] = %d", v, d->control_file_xidxs[v]);
		de_dbg2(c, "data file idx[%d] = %d", v, d->data_file_xidxs[v]);
		if(d->control_file_xidxs[v]<0 || d->data_file_xidxs[v]<0) {
			d->need_errmsg = 1;
			goto done;
		}
	}

	dosbackup33_main(c, d);

done:
	if(d) {
		logical_member_finish_and_free(c, d);

		if(d->need_errmsg) {
			de_err(c, "Failed to process this MS-DOS BACKUP set");
		}
		de_free(c, d->input_files);
		ucstring_destroy(d->cur_dir_name);
		de_free(c, d);
	}
}

static int de_identify_dosbackup33(deark *c)
{
	if(looks_like_33control_file(c->infile, NULL))
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
