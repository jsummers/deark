// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Compression formats related to Zoo archive format

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#include "../foreign/unzoo-lzh.h"
#include "../foreign/zoo-lzd.h"

static void de_fmtutil_decompress_zoo_lzd_newlzw(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, int maxbits)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_ZOOLZD;
	delzwp.max_code_size = (unsigned int)maxbits;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

void de_fmtutil_decompress_zoo_lzd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, int maxbits)
{
	if(c->lzwcodec==0) {
		if(de_get_ext_option(c, "newlzw")) {
			c->lzwcodec = 2;
		}
		else {
			c->lzwcodec = 1;
		}
	}
	if(c->lzwcodec==2) {
		de_fmtutil_decompress_zoo_lzd_newlzw(c, dcmpri, dcmpro, dres, maxbits);
	}
	else {
		de_fmtutil_decompress_zoo_lzd_internal(c, dcmpri, dcmpro, dres, maxbits);
	}
}
