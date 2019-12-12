// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Interface to liblzw

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"
#include "../foreign/liblzw.h"

struct liblzw_userdata_type {
	dbuf *inf;
	i64 inf_pos;
	i64 inf_endpos;
};

static size_t my_liblzw_read(struct de_liblzwctx *lzw, u8 *buf, size_t size)
{
	struct liblzw_userdata_type *lu = (struct liblzw_userdata_type*)lzw->userdata;
	i64 amt_to_read = (i64)size;

	if(amt_to_read > (lu->inf_endpos - lu->inf_pos)) {
		amt_to_read = lu->inf_endpos - lu->inf_pos;
	}
	if(amt_to_read<0) amt_to_read = 0;
	dbuf_read(lu->inf, buf, lu->inf_pos, amt_to_read);
	lu->inf_pos += amt_to_read;
	return (size_t)amt_to_read;
}

// flags:
//  DE_LIBLZWFLAG_HAS3BYTEHEADER = has "compress" style header
//  DE_LIBLZWFLAG_HAS1BYTEHEADER = 1-byte header, containing maxbits
//  DE_LIBLZWFLAG_ARCFSMODE = arcfs mode
// lzwmode: Like compress format. Used if there's no header.
static void de_fmtutil_decompress_liblzw_ex_internal(deark *c,
	struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, u8 lzwmode)
{
	struct de_liblzwctx *lzw = NULL;
	int retval = 0;
	int ret;
	struct liblzw_userdata_type lu;
	const char *modname = "liblzw";

	de_zeromem(&lu, sizeof(struct liblzw_userdata_type));
	lu.inf = dcmpri->f;
	lu.inf_pos = dcmpri->pos;
	lu.inf_endpos = dcmpri->pos + dcmpri->len;
	if(lu.inf_endpos > dcmpri->f->len) {
		lu.inf_endpos = dcmpri->f->len;
	}
	if(lu.inf_pos > lu.inf_endpos) {
		lu.inf_pos = lu.inf_endpos;
	}

	if(flags & DE_LIBLZWFLAG_HAS3BYTEHEADER) {
		u8 buf1[3];

		if(lu.inf_endpos - lu.inf_pos < 3) {
			de_dfilter_set_errorf(c, dres, modname, "Not in compress format");
			goto done;
		}

		dbuf_read(lu.inf, buf1, lu.inf_pos, 3);
		lu.inf_pos += 3;

		if (buf1[0] != LZW_MAGIC_1 || buf1[1] != LZW_MAGIC_2 || (buf1[2] & 0x60)) {
			de_dfilter_set_errorf(c, dres, modname, "Not in compress format");
			goto done;
		}
		lzwmode = buf1[2];
		de_dbg(c, "lzw mode: 0x%02x", (unsigned int)lzwmode);
		de_dbg_indent(c, 1);
		de_dbg(c, "lzw maxbits: %u", (unsigned int)(lzwmode & 0x1f));
		de_dbg_indent(c, -1);
		flags -= DE_LIBLZWFLAG_HAS3BYTEHEADER;
	}
	else if(flags & DE_LIBLZWFLAG_HAS1BYTEHEADER) {
		u8 buf1[1];

		if(lu.inf_endpos - lu.inf_pos < 1) {
			de_dfilter_set_generic_error(c, dres, modname);
			goto done;
		}

		buf1[0] = dbuf_getbyte(lu.inf, lu.inf_pos);
		lu.inf_pos += 1;

		de_dbg(c, "lzw maxbits: %u", (unsigned int)buf1[0]);
		lzwmode = 0x80 | buf1[0];
		flags -= DE_LIBLZWFLAG_HAS1BYTEHEADER;
	}

	lzw = de_liblzw_create(c, (void*)&lu);
	lzw->cb_read = my_liblzw_read;
	lzw->dcmpro = dcmpro;

	ret = de_liblzw_init(lzw, flags, lzwmode);
	if(!ret) goto done;

	de_liblzw_run(lzw);
	retval = 1;

done:
	if(lzw) {
		if(lzw->errcode) {
			de_dfilter_set_errorf(c, dres, modname, "%s", lzw->errmsg);
		}
		de_liblzw_destroy(lzw);
	}
	if(!retval) {
		// In case we somehow got here without recording an error
		de_dfilter_set_generic_error(c, dres, modname);
	}
}

void de_fmtutil_decompress_liblzw_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, u8 lzwmode)
{
	struct delzw_params delzwp;

	if(c->lzwcodec==0) {
		if(de_get_ext_option(c, "newlzw")) {
			c->lzwcodec = 2;
		}
		else {
			c->lzwcodec = 1;
		}
	}

	if(c->lzwcodec!=2) {
		// Use liblzw-based LZW decompressor
		de_fmtutil_decompress_liblzw_ex_internal(c, dcmpri, dcmpro, dres,
			flags, lzwmode);
		return;
	}

	// Use new LZW decompressor
	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.basefmt = DELZW_BASEFMT_UNIXCOMPRESS;
	delzwp.unixcompress_flags = flags;
	delzwp.unixcompress_lzwmode = lzwmode;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

// Old API, semi-deprecated
int de_fmtutil_decompress_liblzw(dbuf *inf1, i64 pos1, i64 len,
	dbuf *outf, unsigned int has_maxlen, i64 max_out_len,
	unsigned int flags, u8 lzwmode)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	deark *c = inf1->c;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = outf;
	dcmpro.len_known = (u8)has_maxlen;
	dcmpro.expected_len = max_out_len;
	de_fmtutil_decompress_liblzw_ex(c, &dcmpri, &dcmpro, &dres, flags, lzwmode);
	if(dres.errcode!=0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		return 0;
	}
	return 1;
}
