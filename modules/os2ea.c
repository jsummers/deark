// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// OS Extended Attributes, including "EA DATA. SF" files

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ea_data);

struct easector_ctx {
	i64 ea_data_len;
};

struct eadata_ctx {
	de_encoding input_encoding;
	UI createflags_for_icons;
	i64 bytes_per_cluster;
};

static int eadata_is_ea_sector_at_offset(deark *c, struct eadata_ctx *d, i64 pos, int strictmode)
{
	u8 b;

	if((UI)de_getu16be(pos)!=0x4541) return 0;
	if(strictmode) {
		if((UI)de_getu32be(pos+4)!=0) return 0;
		b = de_getbyte(pos+8);
		if(b<32) return 0;
		if((UI)de_getu32be(pos+22)!=0) return 0;
	}
	return 1;
}

static const char *eadata_get_data_type_name(UI t)
{
	const char *name = NULL;
	switch(t) {
	case 0xffde: name ="multi-val/single-type"; break;
	case 0xffdf: name ="multi-val/multi-type"; break;
	case 0xfffe: name ="binary"; break;
	case 0xfffd: name ="text"; break;
	case 0xfff9: name ="icon"; break;
	}

	return name?name:"?";
}

static void eadata_extract_icon(deark *c, struct eadata_ctx *d, i64 pos, i64 len)
{
	dbuf_create_file_from_slice(c->infile, pos, len, "os2.ico", NULL, d->createflags_for_icons);
}

static void eadata_do_text_attrib(deark *c, struct eadata_ctx *d, i64 pos, i64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	// Documented as "ASCII text" -- but I wonder if the actual encoding might
	// depend on the attribute name.
	dbuf_read_to_ucstring_n(c->infile, pos, len, 2048, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "text: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static int eadata_do_attribute_lowlevel_singleval(deark *c, struct eadata_ctx *d,
	UI attr_dtype, i64 pos1, i64 maxlen, i64 *pbytes_consumed)
{
	i64 attr_dlen;
	i64 dpos;
	int retval = 0;

	attr_dlen = de_getu16le(pos1);
	de_dbg(c, "inner data len: %"I64_FMT, attr_dlen);
	if(attr_dlen<2 || attr_dlen>maxlen) goto done;
	*pbytes_consumed = 2 + attr_dlen;
	retval = 1;
	dpos = pos1+2;

	switch(attr_dtype) {
	case 0xfff9:
		eadata_extract_icon(c, d, dpos, attr_dlen);
		break;
	case 0xfffd:
		eadata_do_text_attrib(c, d, dpos, attr_dlen);
		break;
	default:
		de_dbg_hexdump(c, c->infile, dpos, attr_dlen, 256, NULL, 0x1);
	}

done:
	return retval;
}

static int eadata_do_attribute_lowlevel(deark *c, struct eadata_ctx *d,
	UI attr_dtype, i64 pos1, i64 nbytes_avail, i64 *pbytes_consumed, int nesting_level);

// multi-val, multi-type container attribute
static int eadata_do_MVMT(deark *c, struct eadata_ctx *d,
	i64 pos1, i64 nbytes_avail, i64 *pbytes_consumed, int nesting_level)
{
	UI codepage;
	i64 num_entries;
	i64 pos = pos1;
	int retval = 0;
	int ret;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	codepage = (UI)de_getu16le_p(&pos);
	de_dbg(c, "code page: %u", codepage);

	num_entries = de_getu16le_p(&pos);
	de_dbg(c, "num entries: %d", (int)num_entries);
	for(i=0; i<num_entries; i++) {
		UI attr_dtype;
		i64 bytes_consumed2 = 0;

		if(pos > pos1+nbytes_avail) goto done;
		de_dbg(c, "entry %d at %"I64_FMT, (int)i, pos);
		de_dbg_indent(c, 1);
		attr_dtype = (UI)de_getu16le_p(&pos);
		de_dbg(c, "data type: 0x%04x (%s)", attr_dtype, eadata_get_data_type_name(attr_dtype));

		ret = eadata_do_attribute_lowlevel(c, d, attr_dtype, pos, pos1+nbytes_avail-pos,
			&bytes_consumed2, nesting_level+1);
		if(!ret) goto done;
		pos += bytes_consumed2;
		de_dbg_indent(c, -1);
	}

	*pbytes_consumed = pos - pos1;
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int eadata_do_attribute_lowlevel(deark *c, struct eadata_ctx *d,
	UI attr_dtype, i64 pos1, i64 nbytes_avail, i64 *pbytes_consumed, int nesting_level)
{
	int retval = 0;

	*pbytes_consumed = 0;

	// I don't know if multi-val attributes are allowed to contain other multi-val attributes.
	if(nesting_level>5) goto done;

	switch(attr_dtype) {
	case 0xffdf:
		if(!eadata_do_MVMT(c, d, pos1, nbytes_avail, pbytes_consumed, nesting_level)) goto done;
		break;
	case 0xffde: // MVST (TODO)
	case 0xffdd: // ASN1
		goto done;
	default:
		if(!eadata_do_attribute_lowlevel_singleval(c, d, attr_dtype, pos1, nbytes_avail,
			pbytes_consumed))
		{
			goto done;
		}
		break;
	}

	retval = 1;

done:
	return retval;
}

// FEA2 structure, starting at the 'fEA' field (1 byte before the name-length byte).
static int eadata_do_attribute(deark *c, struct eadata_ctx *d, i64 pos1, i64 maxlen,
	de_ucstring *tmps, i64 *pbytes_consumed)
{
	i64 namelen;
	i64 attr_dpos;
	i64 attr_dlen;
	i64 tmpbc;
	UI attr_dtype;
	i64 pos = pos1;
	int retval = 0;

	pos++; // fEA
	namelen = (i64)de_getbyte_p(&pos);

	attr_dlen = (i64)de_getu16le_p(&pos);
	ucstring_empty(tmps);
	dbuf_read_to_ucstring(c->infile, pos, namelen, tmps, 0, DE_ENCODING_ASCII);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(tmps));
	pos += namelen + 1;
	attr_dpos = pos;
	de_dbg(c, "outer data len: %"I64_FMT, attr_dlen);
	if(attr_dpos + attr_dlen > pos1+maxlen) goto done;

	attr_dtype = (UI)de_getu16le_p(&pos);
	de_dbg(c, "data type: 0x%04x (%s)", attr_dtype, eadata_get_data_type_name(attr_dtype));

	tmpbc = 0;
	eadata_do_attribute_lowlevel(c, d, attr_dtype, attr_dpos+2, attr_dlen-2, &tmpbc, 0);

	pos = attr_dpos + attr_dlen;
	*pbytes_consumed = pos - pos1;
	retval = 1;
done:
	return retval;
}

// Sets md->ea_data_len.
static void eadata_do_ea_data(deark *c, struct eadata_ctx *d, struct easector_ctx *md,
	i64 pos1)
{
	i64 pos = pos1;
	i64 endpos;
	int saved_indent_level;
	de_ucstring *s = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "EA data at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	md->ea_data_len = de_getu16le_p(&pos); // TODO: Is this actually a 4-byte field?
	de_dbg(c, "data len: %"I64_FMT, md->ea_data_len);

	pos += 2; // ?
	endpos = pos1 + md->ea_data_len;
	s = ucstring_create(c);

	while(pos < endpos-4) {
		int ret;
		i64 bytes_consumed = 0;

		de_dbg(c, "attribute at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = eadata_do_attribute(c, d, pos, endpos-pos, s, &bytes_consumed);
		de_dbg_indent(c, -1);
		if(!ret || bytes_consumed<1) goto done;
		pos += bytes_consumed;
	}

done:
	ucstring_destroy(s);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void eadata_do_FEA2LIST(deark *c, struct eadata_ctx *d)
{
	i64 fea2list_len;
	i64 pos1 = 0;
	i64 pos = pos1;
	i64 endpos;
	de_ucstring *tmps = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	tmps = ucstring_create(c);

	de_dbg(c, "FEA2LIST at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	fea2list_len = de_getu32le_p(&pos);
	endpos = pos1 + fea2list_len;

	de_dbg(c, "list len: %"I64_FMT, fea2list_len);
	while(1) {
		int ret;
		i64 bytes_consumed = 0;
		i64 offset_to_next_attr;
		i64 attr_pos;

		if(pos >= endpos) goto done;

		attr_pos = pos;
		de_dbg(c, "attribute at %"I64_FMT, attr_pos);
		de_dbg_indent(c, 1);
		offset_to_next_attr = de_getu32le_p(&pos);
		de_dbg(c, "offset to next attr: %"I64_FMT, offset_to_next_attr);

		ret = eadata_do_attribute(c, d, pos, endpos-pos, tmps, &bytes_consumed);
		if(!ret || bytes_consumed<1) goto done;
		if(offset_to_next_attr==0) goto done;
		pos = attr_pos + offset_to_next_attr;
		de_dbg_indent(c, -1);
	}

done:
	ucstring_destroy(tmps);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void eadata_do_ea_sector_by_offset(deark *c, struct eadata_ctx *d, i64 pos1,
	i64 *pbytes_consumed1)
{
	i64 n;
	i64 pos;
	de_ucstring *fn = NULL;
	struct easector_ctx *md = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(pbytes_consumed1) {
		*pbytes_consumed1 = 0;
	}
	md = de_malloc(c, sizeof(struct easector_ctx));

	if(!eadata_is_ea_sector_at_offset(c, d, pos1, 0)) {
		de_err(c, "EA sector not found at %"I64_FMT, pos1);
		goto done;
	}

	de_dbg(c, "EA sector at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	pos = pos1+2;
	n = de_getu16le_p(&pos);
	de_dbg(c, "sector number (consistency check): %u", (UI)n);

	pos += 4;

	fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 12, fn, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "file name: \"%s\"", ucstring_getpsz_d(fn));
	pos += 12;

	pos += 2;
	pos += 4;

	eadata_do_ea_data(c, d, md, pos);
	pos += md->ea_data_len;

	if(pbytes_consumed1) {
		*pbytes_consumed1 = pos - pos1;
	}

done:
	ucstring_destroy(fn);
	de_free(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int eadata_id_to_offset(deark *c, struct eadata_ctx *d, UI id, i64 *poffset)
{
	int retval = 0;
	UI a_idx;
	UI a_val;
	UI b_val;
	i64 cluster_num;

	*poffset = 0;

	a_idx = id>>7;
	if(a_idx>=240) goto done;
	a_val = (UI)de_getu16le(32+2*(i64)a_idx);
	b_val = (UI)de_getu16le(512+2*(i64)id);
	if(b_val==0xffff) goto done;

	cluster_num = (i64)b_val + (i64)a_val;
	*poffset = d->bytes_per_cluster * cluster_num;

	if(eadata_is_ea_sector_at_offset(c, d, *poffset, 0)) {
		retval = 1;
	}

done:
	return retval;
}

static void eadata_scan_file(deark *c, struct eadata_ctx *d)
{
	i64 pos = 1024;

	while(pos < c->infile->len) {
		if(eadata_is_ea_sector_at_offset(c, d, pos, 1)) {
			i64 bytes_consumed;

			eadata_do_ea_sector_by_offset(c, d, pos, &bytes_consumed);

			if(bytes_consumed<1) bytes_consumed = 1;
			pos = de_pad_to_n(pos+bytes_consumed, 512);
		}
		else {
			pos += 512;
		}
	}
}

static void de_run_eadata(deark *c, de_module_params *mparams)
{
	int ret;
	UI ea_id = 0;
	i64 pos;
	const char *s;
	struct eadata_ctx *d = NULL;

	de_declare_fmt(c, "OS/2 extended attributes data");

	d = de_malloc(c, sizeof(struct eadata_ctx));

	if(de_havemodcode(c, mparams, 'L')) {
		d->createflags_for_icons = DE_CREATEFLAG_IS_AUX;
		eadata_do_FEA2LIST(c, d);
	}
	else if(mparams && (mparams->in_params.flags & 0x1)) {
		// We're being used by another module, to handle a specific ea_id.
		ea_id = (UI)mparams->in_params.uint1;
		if(ea_id==0) goto done;
		d->createflags_for_icons = DE_CREATEFLAG_IS_AUX;
	}
	else {
		s = de_get_ext_option(c, "ea_data:handle");
		if(s) {
			ea_id = (UI)de_atoi(s);
		}
	}

	d->input_encoding = de_get_input_encoding(c, mparams, DE_ENCODING_CP437);
	d->bytes_per_cluster = 512;

	if(ea_id==0) {
		eadata_scan_file(c, d);
	}
	else {
		ret = eadata_id_to_offset(c, d, ea_id, &pos);
		if(!ret) goto done;
		eadata_do_ea_sector_by_offset(c, d, pos, NULL);
	}

done:
	de_free(c, d);
}

static int de_identify_eadata(deark *c)
{
	if(de_getu16be(0)!=0x4544) return 0;
	if(de_input_file_has_ext(c, " sf")) return 100;
	if(dbuf_is_all_zeroes(c->infile, 2, 30)) {
		return 20;
	}
	return 0;
}

static void de_help_eadata(deark *c)
{
	de_msg(c, "-opt ea_data:handle=<n> : Decode only EA handle/pointer <n>");
}

void de_module_ea_data(deark *c, struct deark_module_info *mi)
{
	mi->id = "ea_data";
	mi->desc = "EA DATA (OS/2 extended attributes)";
	mi->run_fn = de_run_eadata;
	mi->identify_fn = de_identify_eadata;
	mi->help_fn = de_help_eadata;
}
