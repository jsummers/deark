// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Cabinent (CAB) format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cab);

typedef struct localctx_struct {
	de_byte versionMinor, versionMajor;
	unsigned int header_flags;
	de_int64 cbCabinet;
	de_int64 coffFiles;
	de_int64 cFolders;
	de_int64 cFiles;
} lctx;

static void do_CFFILEs(deark *c, lctx *d)
{
	de_int64 pos = d->coffFiles;

	if(d->cFiles<1) goto done;
	de_dbg(c, "CFFILE section at %d, %d files", (int)pos, (int)d->cFiles);
	de_dbg_indent(c, 1);
	de_dbg_indent(c, -1);

done:
	;
}

static int do_CFHEADER(deark *c, lctx *d)
{
	int retval = 0;
	de_int64 pos = 0;

	de_dbg(c, "CFHEADER at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 8; // signature, reserved1
	d->cbCabinet = de_getui32le(pos);
	de_dbg(c, "cbCabinet: %"INT64_FMT, d->cbCabinet);
	pos += 4;
	pos += 4; // reserved2
	d->coffFiles = de_getui32le(pos);
	de_dbg(c, "coffFiles: %"INT64_FMT, d->coffFiles);
	pos += 4;
	pos += 4; // reserved3
	d->versionMinor = de_getbyte(pos++);
	d->versionMajor = de_getbyte(pos++);
	de_dbg(c, "file format version: %u.%u", (unsigned int)d->versionMajor,
		(unsigned int)d->versionMinor);

	d->cFolders = de_getui16le(pos);
	de_dbg(c, "cFolders: %d", (int)d->cFolders);
	pos += 2;

	d->cFiles = de_getui16le(pos);
	de_dbg(c, "cFiles: %d", (int)d->cFiles);
	pos += 2;

	d->header_flags = (unsigned int)de_getui16le(pos);
	de_dbg(c, "flags: 0x%04x", d->header_flags);
	pos += 2;

	pos += 2; // setID
	pos += 4; // iCabinet

	// TODO: Additional fields may be here

	de_dbg_indent(c, -1);

	if(d->versionMajor!=1 || d->versionMinor!=3) {
		de_err(c, "Unsupported CAB format version: %u.%u",
			(unsigned int)d->versionMajor, (unsigned int)d->versionMinor);
		goto done;
	}
	retval = 1;
done:
	return retval;
}

static void de_run_cab(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!do_CFHEADER(c, d)) goto done;
	// TODO: CFFOLDER
	do_CFFILEs(c, d);

done:
	de_free(c, d);
}

static int de_identify_cab(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "MSCF", 4))
		return 100;
	return 0;
}

void de_module_cab(deark *c, struct deark_module_info *mi)
{
	mi->id = "cab";
	mi->desc = "Microsoft Cabinet (CAB)";
	mi->run_fn = de_run_cab;
	mi->identify_fn = de_identify_cab;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
