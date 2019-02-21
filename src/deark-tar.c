// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// TAR format output

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

struct tar_ctx {
	const char *filename;
	dbuf *outf;
};

int de_tar_create_file(deark *c)
{
	struct tar_ctx *tctx = NULL;
	int retval = 0;

	if(c->tar_data) return 1;

	tctx = de_malloc(c, sizeof(struct tar_ctx));
	c->tar_data = (void*)tctx;

	if(c->archive_to_stdout) {
		tctx->filename = "[stdout]";
		de_err(c, "TAR to stdout is not implemented");
		de_fatalerror(c);
		goto done;
	}


	if(c->output_archive_filename) {
		tctx->filename = c->output_archive_filename;
	}
	else {
		tctx->filename = "output.tar";
	}

	de_info(c, "Creating %s", tctx->filename);
	tctx->outf = dbuf_create_unmanaged_file(c, tctx->filename,
		c->overwrite_mode, 0);

	if(tctx->outf->btype==DBUF_TYPE_NULL) {
		de_fatalerror(c);
		goto done;
	}

	retval = 1;

done:
	return retval;
}

void de_tar_close_file(deark *c)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;

	if(!tctx) return;
	dbuf_close(tctx->outf);
	de_free(c, tctx);
	c->tar_data = NULL;
}

// f is type DBUF_TYPE_ODBUF, in the process of being created.
// We are responsible for setting f->parent_dbuf and
// f->offset_into_parent_dbuf.
void de_tar_start_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = NULL;

	if(!c->tar_data) {
		de_tar_create_file(c);
	}
	tctx = (struct tar_ctx *)c->tar_data;
	if(!tctx) return;

	f->parent_dbuf = tctx->outf;

	dbuf_write(tctx->outf, (const u8*)"[begin]", 7);

	f->offset_into_parent_dbuf = tctx->outf->len;
}

void de_tar_end_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;

	dbuf_write(tctx->outf, (const u8*)"[end]", 5);
}
