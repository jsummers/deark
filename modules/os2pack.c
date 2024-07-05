// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// OS/2 PACK, and PACK2 (FTCOMP)

#include <deark-private.h>
#include <deark-fmtutil.h>
#include <deark-fmtutil-arch.h>
DE_DECLARE_MODULE(de_module_os2pack);
DE_DECLARE_MODULE(de_module_os2pack2);

#define OS2PACK_MINHEADERLEN 10

static UI os2pack_is_member_at(dbuf *f, i64 pos)
{
	UI sig;

	sig = (UI)dbuf_getu32be(f, pos);
	return (sig==0xa596feffU || sig==0xa596ffffU ||
		sig==0xa5960014U || sig==0xa596140aU) ? 1 : 0;
}

static UI os2pack2_is_member_at(dbuf *f, i64 pos)
{
	UI sig;

	sig = (UI)dbuf_getu32be(f, pos);
	if(sig!=0xa596fdffU) return 0;
	if(dbuf_memcmp(f, pos+24, (const void*)"FTCOMP", 6)) return 0;
	return 1;
}

static UI os2pack12_is_member_at(de_arch_lctx *d, i64 pos)
{
	if(d->fmtcode==0xfffd) {
		return os2pack2_is_member_at(d->inf, pos);
	}
	return os2pack_is_member_at(d->inf, pos);
}

static void os2pack_decompressor_fn(struct de_arch_member_data *md)
{
	fmtutil_ibmlzw_codectype1(md->c, md->dcmpri, md->dcmpro, md->dres, NULL);
}

static void os2pack2_read_cmpr_method(deark *c, i64 pos, i64 len)
{
	struct de_fourcc cmpr4cc;

	if(len<8) return;
	dbuf_read_fourcc(c->infile, pos+4, &cmpr4cc, 4, 0x0);
	de_dbg(c, "cmpr meth: '%s'", cmpr4cc.id_dbgstr); // Usually "fT19"
}

static void do_os2pack1_ea(deark *c, de_arch_lctx *d, struct de_arch_member_data *md,
	i64 ea_pos, i64 ea_len)
{
	int saved_indent_level;
	dbuf *attr_data = NULL;
	de_module_params *mparams = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "ext. attr. at %"I64_FMT, ea_pos);
	de_dbg_indent(c, 1);
	attr_data = dbuf_create_membuf(c, 0, 0);
	dbuf_set_length_limit(attr_data, 1024*1024);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = ea_pos;
	dcmpri.len = ea_len;
	dcmpro.f = attr_data;
	fmtutil_ibmlzw_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(attr_data);
	if(dres.errcode) {
		de_warn(c, "Failed to decompress ext. attr. data");
		goto done;
	}
	de_dbg(c, "decompressed len: %"I64_FMT, attr_data->len);

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "R";
	if(ucstring_isnonempty(md->filename)) {
		mparams->in_params.str1 = md->filename;
		mparams->in_params.flags |= 0x8;
	}
	de_run_module_by_id_on_slice(c, "ea_data", mparams, attr_data, 0, attr_data->len);

done:
	dbuf_close(attr_data);
	de_free(c, mparams);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_os2pack12_member(deark *c, de_arch_lctx *d, struct de_arch_member_data *md)
{
	i64 pos;
	i64 fnlen;
	i64 ea_pos = 0;
	i64 ea_len = 0;
	i64 member_endpos;
	i64 unk2, unk3, unk4;
	UI attribs;
	u8 flag_unsupp = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "member at %"I64_FMT, md->member_hdr_pos);
	de_dbg_indent(c, 1);

	pos = md->member_hdr_pos + 4;

	de_arch_read_field_dttm_p(d, &md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], "mod",
		DE_ARCH_TSTYPE_DOS_DT, &pos);

	// Apparently a file attributes field, but don't know if it's 1, 2, or 4 bytes.
	attribs = (UI)de_getbyte_p(&pos);
	de_arch_handle_field_dos_attr(md, attribs);

	if(d->fmtcode==0x1400 || d->fmtcode==0x0a14) {
		pos += 1;
	}
	else if(d->fmtcode==0xffff) {
		pos += 6; // ?
	}
	else {
		pos += 3;
		ea_pos = de_getu32le_p(&pos);
		de_dbg(c, "ext. attr. pos: %"I64_FMT, ea_pos);

		de_arch_read_field_orig_len_p(md, &pos);
		// TODO: Figure out why some files have 1 here, and others have the original
		// file size.
		if(d->fmtcode==0xfffe && md->orig_len==1) {
			md->orig_len = 0;
			md->orig_len_known = 0;
		}

		md->next_member_pos = de_getu32le_p(&pos);
		de_dbg(c, "next member pos: %"I64_FMT, md->next_member_pos);
		if(md->next_member_pos!=0) {
			md->next_member_exists = 1;
		}
	}

	if(d->fmtcode==0xfffd) {
		pos += 7; // "FTCOMP\0"

		unk2 = de_getu16le_p(&pos);
		de_dbg(c, "unk2: %u", (UI)unk2);

		unk3 = de_getu16le_p(&pos);
		de_dbg(c, "unk3: %u", (UI)unk3);

		unk4 = de_getu32le_p(&pos);
		de_dbg(c, "unk4: %"I64_FMT, unk4);
	}

	if(d->fmtcode==0x1400 || d->fmtcode==0x0a14) {
		fnlen = 13;
	}
	else if(d->fmtcode==0xffff) {
		i64 foundpos = 0;

		if(dbuf_search_byte(c->infile, 0, pos, 260, &foundpos)) {
			fnlen = foundpos + 1 - pos;
		}
		else {
			d->need_errmsg = 1;
			goto done;
		}
	}
	else {
		fnlen = de_getu16le_p(&pos);
	}

	dbuf_read_to_ucstring_n(c->infile, pos, fnlen, 512, md->filename,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->filename));
	pos += fnlen;
	de_arch_fixup_path(md->filename, 0);
	md->set_name_flags |= DE_SNFLAG_FULLPATH;

	md->cmpr_pos = pos;

	if(md->next_member_exists) {
		member_endpos = md->next_member_pos;
	}
	else {
		member_endpos = c->infile->len;
	}

	if(member_endpos > c->infile->len) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	md->cmpr_len = member_endpos - md->cmpr_pos;
	// if ea_pos is set, adjust cmpr_len downward
	if(ea_pos != 0) {
		if(ea_pos<md->cmpr_pos || ea_pos>member_endpos) {
			d->fatalerrflag = 1;
			d->need_errmsg = 1;
			goto done;
		}
		md->cmpr_len = ea_pos - md->cmpr_pos;
		ea_len = member_endpos - ea_pos;
	}

	if(md->cmpr_len<0) {
		d->fatalerrflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	if(ea_len>0) {
		de_dbg(c, "cmpr ext. attr. at %"I64_FMT", len=%"I64_FMT, ea_pos, ea_len);
		de_dbg_indent(c, 1);
		if(d->fmtcode==0xfffd) {
			os2pack2_read_cmpr_method(c, ea_pos, ea_len);
		}
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "cmpr data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos, md->cmpr_len);

	de_dbg_indent(c, 1);
	if(d->fmtcode==0xfffd) {
		// Most likely, the compressed data is considered to start after the
		// filename field.
		// It seems to have a compression header that we can peek at.
		os2pack2_read_cmpr_method(c, md->cmpr_pos, md->cmpr_len);
	}

	if(d->fmtcode==0x1400 || d->fmtcode==0x0a14 || d->fmtcode==0xffff ||
		d->fmtcode==0xfffe)
	{
		md->dfn = os2pack_decompressor_fn;
		de_arch_extract_member_file(md);
		if(ea_pos>0 && ea_len>0) {
			do_os2pack1_ea(c, d, md, ea_pos, ea_len);
		}
	}

	de_dbg_indent(c, -1);

	// TODO: There may be a few more bytes at the end of a member, purpose unknown.
	// If so, we should adjust md->cmpr_len or ea_len accordingly.

done:
	if(flag_unsupp) {
		de_err(c, "Unsupported member file format");
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_run_os2pack12(deark *c, de_module_params *mparams, UI ver)
{
	de_arch_lctx *d = NULL;
	struct de_arch_member_data *md = NULL;
	i64 pos;
	const char *pname = "PACK";

	d = de_arch_create_lctx(c);
	d->is_le = 1;

	if(ver==2) {
		d->fmtcode = 0xfffd;
	}
	else {
		d->fmtcode = (UI)de_getu16le(2);
		if(d->fmtcode!=0x1400 && d->fmtcode!=0x0a14 && d->fmtcode!=0xffff &&
			d->fmtcode!=0xfffe)
		{
			d->need_errmsg = 1;
			goto done;
		}
	}

	if(d->fmtcode==0xfffd) {
		pname = "PACK2";
		de_declare_fmt(c, "OS/2 PACK2 archive");
	}
	else {
		de_declare_fmtf(c, "OS/2 PACK archive (type 0x%04x)", d->fmtcode);
	}

	// TODO: What encoding to use?
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	pos = 0;

	while(1) {
		if(pos+OS2PACK_MINHEADERLEN > c->infile->len) {
			d->need_errmsg = 1;
			goto done;
		}

		if(!os2pack12_is_member_at(d, pos)) {
			d->need_errmsg = 1;
			goto done;
		}

		if(md) {
			de_arch_destroy_md(c, md);
			md = NULL;
		}
		md = de_arch_create_md(c, d);
		md->member_hdr_pos = pos;

		do_os2pack12_member(c, d, md);

		if(d->fatalerrflag) goto done;
		if(!md->next_member_exists) goto done;
		if(md->next_member_pos <= pos) {
			d->need_errmsg = 1;
			goto done;
		}
		pos = md->next_member_pos;
	}

done:
	if(md) {
		de_arch_destroy_md(c, md);
		md = NULL;
	}
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported OS/2 %s archive", pname);
		}
		de_arch_destroy_lctx(c, d);
	}
}

static void de_run_os2pack(deark *c, de_module_params *mparams)
{
	do_run_os2pack12(c, mparams, 1);
}

static void de_run_os2pack2(deark *c, de_module_params *mparams)
{
	do_run_os2pack12(c, mparams, 2);
}

static int de_identify_os2pack(deark *c)
{
	return (os2pack_is_member_at(c->infile, 0)) ? 100 : 0;
}

void de_module_os2pack(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2pack";
	mi->desc = "OS/2 PACK archive";
	mi->run_fn = de_run_os2pack;
	mi->identify_fn = de_identify_os2pack;
}

static int de_identify_os2pack2(deark *c)
{
	return (os2pack2_is_member_at(c->infile, 0)) ? 100 : 0;
}

void de_module_os2pack2(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2pack2";
	mi->desc = "OS/2 PACK2 archive";
	mi->run_fn = de_run_os2pack2;
	mi->flags |= DE_MODFLAG_WARNPARSEONLY;
	mi->identify_fn = de_identify_os2pack2;
}
