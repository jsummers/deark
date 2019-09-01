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
//  DE_LIBLZWFLAG_ARCFSMODE = arcfs mode
// lzwmode: Like compress format. Used if there's no header.
int de_fmtutil_decompress_liblzw(dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, unsigned int has_maxlen, i64 max_out_len,
	unsigned int flags, u8 lzwmode)
{
	u8 buf[1024];
	i64 n;
	struct de_liblzwctx *lzw = NULL;
	i64 nbytes_still_to_write;
	int retval = 0;
	int ret;
	deark *c = inf->c;
	struct liblzw_userdata_type lu;

	lu.inf = inf;
	lu.inf_pos = pos1;
	lu.inf_endpos = pos1 + len;
	if(lu.inf_endpos > inf->len) {
		lu.inf_endpos = inf->len;
	}
	if(lu.inf_pos > lu.inf_endpos) {
		lu.inf_pos = lu.inf_endpos;
	}

	lzw = de_liblzw_create(c, (void*)&lu);
	lzw->cb_read = my_liblzw_read;

	ret = de_liblzw_init(lzw, flags, lzwmode);
	if(!ret) goto done;

	nbytes_still_to_write = has_maxlen ? max_out_len : 0;

	while(1) {
		if(has_maxlen && (nbytes_still_to_write<1)) break;
		n = de_liblzw_read(lzw, buf, sizeof(buf));
		if(n<0) {
			goto done;
		}
		if(n<1) break;

		if(has_maxlen && (n > nbytes_still_to_write)) {
			// Make sure we don't write more bytes than expected.
			n = nbytes_still_to_write;
		}

		dbuf_write(outf, buf, n);
		nbytes_still_to_write -= n;
	}
	retval = 1;

done:
	if(lzw) {
		if(lzw->errcode) {
			de_err(c, "[liblzw] %s", lzw->errmsg);
		}
		de_liblzw_destroy(lzw);
	}

	return retval;
}
