// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// AFCP metadata
// (AXS File Concatenation Protocol)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_afcp);

#define CODE_IPTC 0x49505443U
#define CODE_Nail 0x4e61696cU
#define CODE_PrVw 0x50725677U

struct afcpctx {
	int is_le;
	u8 endian_code;
	i64 endpos;
	i64 start_tag_offs;
	i64 record_count;
};

struct afcprecord {
	i64 dlen;
	i64 dpos;
	struct de_fourcc id4cc;
};

static int do_afcprec_thumbnail(deark *c, struct afcpctx *d, struct afcprecord *ar)
{
	unsigned int recver;
	i64 pos = ar->dpos;
	i64 w, h;
	i64 foundpos = 0;
	struct de_fourcc imgtype;
	const char *ext;
	int ret;
	int retval = 0;

	if(ar->dlen<10) goto done;
	recver = (unsigned int)dbuf_getu16x(c->infile, pos, d->is_le);
	pos += 2;
	de_dbg(c, "record version: %u", recver);
	if(recver!=1) goto done;

	w = dbuf_getu16x(c->infile, pos, d->is_le);
	pos += 2;
	h = dbuf_getu16x(c->infile, pos, d->is_le);
	pos += 2;
	de_dbg(c, "reported dimensions: %d"DE_CHAR_TIMES"%d", (int)w, (int)h);
	// Nothing after this point is adequately documented in the spec.

	dbuf_read_fourcc(c->infile, pos, &imgtype, 4, 0);
	pos += 4;
	de_dbg(c, "image type: '%s'", imgtype.id_dbgstr);

	ret = dbuf_search(c->infile, (const u8*)"\xff\xd8\xff", 3, pos,
		ar->dpos + ar->dlen - pos, &foundpos);
	if(!ret) {
		de_dbg(c, "[failed to find thumbnail image data]");
		goto done;
	}
	if(ar->id4cc.id==CODE_PrVw) ext = "afcppreview.jpg";
	else ext = "afcpthumb.jpg";
	dbuf_create_file_from_slice(c->infile, foundpos, ar->dpos + ar->dlen - foundpos, ext,
		NULL, DE_CREATEFLAG_IS_AUX);

	retval = 1;
done:
	return retval;
}

static void do_afcp_record(deark *c, struct afcpctx *d, i64 pos)
{
	struct afcprecord *ar = NULL;

	ar = de_malloc(c, sizeof(struct afcprecord));
	dbuf_read_fourcc(c->infile, pos, &ar->id4cc, 4, 0);
	de_dbg(c, "id: '%s'", ar->id4cc.id_dbgstr);
	ar->dlen = dbuf_getu32x(c->infile, pos+4, d->is_le);
	de_dbg(c, "dlen: %"I64_FMT, ar->dlen);
	ar->dpos = dbuf_getu32x(c->infile, pos+8, d->is_le);
	de_dbg(c, "dpos: %"I64_FMT, ar->dpos);
	if(ar->dpos<d->start_tag_offs || ar->dpos+ar->dlen>d->endpos) goto done;

	if(ar->id4cc.id==CODE_IPTC) {
		de_dbg(c, "IPTC data");
		de_dbg_indent(c, 1);
		de_fmtutil_handle_iptc(c, c->infile, ar->dpos, ar->dlen, 0x0);
		de_dbg_indent(c, -1);
	}
	else if(ar->id4cc.id==CODE_Nail || ar->id4cc.id==CODE_PrVw) {
		do_afcprec_thumbnail(c, d, ar);
	}
	else {
		if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, ar->dpos, ar->dlen, 256, NULL, 0x1);
		}
	}
done:
	de_free(c, ar);
}

static void do_afcp_recordlist(deark *c, struct afcpctx *d)
{
	int saved_indent_level;
	i64 pos;
	i64 i;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = d->start_tag_offs + 12;
	de_dbg(c, "record list at %"I64_FMT, pos);

	de_dbg_indent(c, 1);
	for(i=0; i<d->record_count; i++) {
		if(i+12 > d->endpos) goto done;
		de_dbg(c, "record[%d] at %"I64_FMT, (int)i, pos);
		de_dbg_indent(c, 1);
		do_afcp_record(c, d, pos);
		de_dbg_indent(c, -1);
		pos += 12;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_afcp_starttagrec(deark *c, struct afcpctx *d)
{
	int retval = 0;
	int saved_indent_level;
	unsigned int version;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "start tag record at %"I64_FMT, d->start_tag_offs);
	de_dbg_indent(c, 1);
	if(de_getbyte(d->start_tag_offs+3)!=d->endian_code) {
		de_err(c, "AFCP start tag not found at %"I64_FMT, d->start_tag_offs);
		goto done;
	}
	version = (unsigned int)dbuf_getu16x(c->infile, d->start_tag_offs+4, d->is_le);
	de_dbg(c, "version: %u", version);
	d->record_count = dbuf_getu16x(c->infile, d->start_tag_offs+6, d->is_le);
	de_dbg(c, "record count: %d", (int)d->record_count);

	if(version>1) {
		de_warn(c, "Unexpected AFCP version number: %u", version);
	}

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_afcp_eofrec(deark *c, struct afcpctx *d)
{
	i64 eofrecpos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	eofrecpos = d->endpos - 12;
	de_dbg(c, "EOF record at %"I64_FMT, eofrecpos);
	de_dbg_indent(c, 1);
	d->endian_code = de_getbyte(eofrecpos+3);
	if(d->endian_code=='*') d->is_le = 1;
	else if(d->endian_code=='!') d->is_le = 0;
	else {
		de_err(c, "Invalid AFCP format");
		goto done;
	}
	de_dbg(c, "is-little-endian: %d", d->is_le);

	d->start_tag_offs = dbuf_getu32x(c->infile, eofrecpos+4, d->is_le);
	de_dbg(c, "start tag offset: %"I64_FMT, d->start_tag_offs);

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_afcp(deark *c, de_module_params *mparams)
{
	struct afcpctx *d = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct afcpctx));
	d->endpos = c->infile->len;
	de_dbg(c, "AFCP data, ending at %"I64_FMT, d->endpos);
	de_dbg_indent(c, 1);

	if(!do_afcp_eofrec(c, d)) goto done;
	if(!do_afcp_starttagrec(c, d)) goto done;
	do_afcp_recordlist(c, d);

done:
	de_free(c, d);
	de_dbg_indent_restore(c, saved_indent_level);
}

void de_module_afcp(deark *c, struct deark_module_info *mi)
{
	mi->id = "afcp";
	mi->desc = "AXS File Concatenation Protocol";
	mi->run_fn = de_run_afcp;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
