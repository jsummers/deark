// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Decompression, etc.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

// Initialize or reset a dfilter results struct
void de_dfilter_results_clear(deark *c, struct de_dfilter_results *dres)
{
	dres->errcode = 0;
	de_strlcpy(dres->errmsg, "Unspecified error", sizeof(dres->errmsg));
}

void de_dfilter_set_errorf(deark *c, struct de_dfilter_results *dres,
	const char *fmt, ...)
{
	va_list ap;

	if(dres->errcode != 0) return; // Only record the first error
	dres->errcode = 1;

	va_start(ap, fmt);
	de_vsnprintf(dres->errmsg, sizeof(dres->errmsg), fmt, ap);
	va_end(ap);
}

void de_dfilter_set_generic_error(deark *c, struct de_dfilter_results *dres)
{
	if(dres->errcode != 0) return;
	de_dfilter_set_errorf(c, dres, "Unspecified error");
}
