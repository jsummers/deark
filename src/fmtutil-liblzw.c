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
void de_fmtutil_decompress_liblzw_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, u8 lzwmode)
{
	u8 buf[1024];
	i64 n;
	struct de_liblzwctx *lzw = NULL;
	i64 nbytes_still_to_write;
	int retval = 0;
	int ret;
	struct liblzw_userdata_type lu;
	const char *modname = "liblzw";

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
		if(lu.inf_endpos - lu.inf_pos < 3) {
			de_dfilter_set_errorf(c, dres, modname, "Not in compress format");
			goto done;
		}

		dbuf_read(lu.inf, buf, lu.inf_pos, 3);
		lu.inf_pos += 3;

		if (buf[0] != LZW_MAGIC_1 || buf[1] != LZW_MAGIC_2 || (buf[2] & 0x60)) {
			de_dfilter_set_errorf(c, dres, modname, "Not in compress format");
			goto done;
		}
		lzwmode = buf[2];
		de_dbg(c, "lzw mode: 0x%02x", (unsigned int)lzwmode);
		de_dbg_indent(c, 1);
		de_dbg(c, "lzw maxbits: %u", (unsigned int)(lzwmode & 0x1f));
		de_dbg_indent(c, -1);
		flags -= DE_LIBLZWFLAG_HAS3BYTEHEADER;
	}
	else if(flags & DE_LIBLZWFLAG_HAS1BYTEHEADER) {
		if(lu.inf_endpos - lu.inf_pos < 1) {
			de_dfilter_set_generic_error(c, dres, modname);
			goto done;
		}

		buf[0] = dbuf_getbyte(lu.inf, lu.inf_pos);
		lu.inf_pos += 1;

		de_dbg(c, "lzw maxbits: %u", (unsigned int)buf[0]);
		lzwmode = 0x80 | buf[0];
		flags -= DE_LIBLZWFLAG_HAS1BYTEHEADER;
	}

	lzw = de_liblzw_create(c, (void*)&lu);
	lzw->cb_read = my_liblzw_read;

	ret = de_liblzw_init(lzw, flags, lzwmode);
	if(!ret) goto done;

	nbytes_still_to_write = dcmpro->len_known ? dcmpro->expected_len : 0;

	while(1) {
		if(dcmpro->len_known && (nbytes_still_to_write<1)) break;
		n = de_liblzw_read(lzw, buf, sizeof(buf));
		if(n<0) {
			goto done;
		}
		if(n<1) break;

		if(dcmpro->len_known && (n > nbytes_still_to_write)) {
			// Make sure we don't write more bytes than expected.
			n = nbytes_still_to_write;
		}

		dbuf_write(dcmpro->f, buf, n);
		nbytes_still_to_write -= n;
	}
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

// Old API, semi-deprecated
int de_fmtutil_decompress_liblzw(dbuf *inf1, i64 pos1, i64 len,
	dbuf *outf, unsigned int has_maxlen, i64 max_out_len,
	unsigned int flags, u8 lzwmode)
{
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	deark *c = inf1->c;

	de_zeromem(&dcmpri, sizeof(struct de_dfilter_in_params));
	de_zeromem(&dcmpro, sizeof(struct de_dfilter_out_params));
	de_dfilter_results_clear(c, &dres);

	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = len;
	dcmpro.f = outf;
	dcmpro.len_known = (u8)has_maxlen;
	dcmpro.expected_len = max_out_len;
	de_fmtutil_decompress_liblzw_ex(c, &dcmpri, &dcmpro, &dres, flags, lzwmode);
	if(dres.errcode!=0) {
		de_err(c, "%s", dres.errmsg);
		return 0;
	}
	return 1;
}
