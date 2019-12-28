// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Compression formats related to Zoo archive format

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#include "../foreign/unzoo-lzh.h"

void de_fmtutil_decompress_zoo_lzd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, int maxbits)
{
	struct delzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct delzw_params));
	delzwp.fmt = DE_LZWFMT_ZOOLZD;
	delzwp.max_code_size = (unsigned int)maxbits;
	de_fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}
