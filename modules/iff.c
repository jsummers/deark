// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// IFF (Interchange File Format)

// TODO: This module might eventually become general enough that it
// can share most of its code with other modules that parse IFF-like
// formats (ilbm, amigaicon, nokia, riff).

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_iff);

#define FMT_FORM   1
#define FMT_FOR4   4

#define CODE_ANNO  0x414e4e4fU
#define CODE_CAT   0x43415420U
#define CODE_CAT4  0x43415434U
#define CODE_FOR4  0x464f5234U
#define CODE_FORM  0x464f524dU
#define CODE_LIS4  0x4c495334U
#define CODE_LIST  0x4c495354U

typedef struct localctx_struct {
	int fmt; // FMT_*
	de_int64 alignment;

	int level;
	de_uint32 main_formtype;
	de_uint32 curr_formtype;
} lctx;

static int is_container_chunk(deark *c, lctx *d, de_uint32 ct)
{
	if(d->fmt==FMT_FOR4) {
		if(ct==CODE_FOR4 || ct==CODE_LIS4 || ct==CODE_CAT4) return 1;
	}
	else {
		if(ct==CODE_FORM || ct==CODE_LIST || ct==CODE_CAT) return 1;
	}
	return 0;
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len);

// Returns 0 if we can't continue
static int do_chunk(deark *c, lctx *d, de_int64 pos, de_int64 bytes_avail,
	de_int64 *bytes_consumed)
{
	int ret;
	de_int64 chunk_dpos;
	de_int64 chunk_dlen;
	de_int64 chunk_dlen_padded;
	de_int64 data_bytes_avail;
	struct de_fourcc chunk4cc;
	struct de_fourcc formtype4cc;
	de_uint32 saved_formtype;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	if(bytes_avail<8) {
		de_err(c, "Invalid chunk size (at %d, size=%d)\n", (int)pos, (int)bytes_avail);
		goto done;
	}
	data_bytes_avail = bytes_avail-8;

	dbuf_read_fourcc(c->infile, pos, &chunk4cc, 0);
	chunk_dlen = de_getui32be(pos+4);
	chunk_dpos = pos+8;

	de_dbg(c, "Chunk '%s' at %d, dpos=%d, dlen=%d\n", chunk4cc.id_printable, (int)pos,
		(int)chunk_dpos, (int)chunk_dlen);
	de_dbg_indent(c, 1);

	if(chunk_dlen > data_bytes_avail) {
		de_warn(c, "Invalid chunk size at %d (chunk '%s', bytes_needed=%"INT64_FMT", "
			"bytes_avail=%"INT64_FMT")\n",
			(int)pos, chunk4cc.id_printable, chunk_dlen, data_bytes_avail);
		chunk_dlen = data_bytes_avail; // Try to continue
	}

	chunk_dlen_padded = de_pad_to_n(chunk_dlen, d->alignment);
	*bytes_consumed = 8 + chunk_dlen_padded;

	// We've set *bytes_consumed, so we can return "success"
	retval = 1;

	if(is_container_chunk(c, d, chunk4cc.id)) {
		// First 4 bytes of payload are the "contents type" or "FORM type"
		dbuf_read_fourcc(c->infile, pos+8, &formtype4cc, 0);
		d->curr_formtype = formtype4cc.id;
		if(d->level==0) {
			d->main_formtype = formtype4cc.id;
		}
		de_dbg(c, "contents type: '%s'\n", formtype4cc.id_printable);

		// The rest is a sequence of chunks.
		saved_formtype = d->curr_formtype;
		d->level++;
		ret = do_chunk_sequence(c, d, chunk_dpos+4, chunk_dlen-4);
		d->level--;
		d->curr_formtype = saved_formtype;
		if(!ret) {
			goto done;
		}
	}
	else {
		switch(chunk4cc.id) {
		case CODE_ANNO:
			de_fmtutil_handle_standard_iff_chunk(c, c->infile, chunk_dpos, chunk_dlen, chunk4cc.id);
			break;
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 chunk_len;
	int ret;

	if(d->level >= 10) { // An arbitrary recursion limit.
		return 0;
	}

	endpos = pos1+len;

	pos = pos1;
	while(pos < endpos) {
		ret = do_chunk(c, d, pos, endpos-pos, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	return 1;
}

static int identify_internal(deark *c)
{
	de_byte buf[4];

	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, (const de_byte*)"FORM", 4)) {
		return FMT_FORM;
	}
	if(!de_memcmp(buf, (const de_byte*)"FOR4", 4)) {
		return FMT_FOR4;
	}

	return 0;
}

static void de_run_iff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *s;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->alignment = 2; // default

	d->fmt = identify_internal(c);

	if(d->fmt==FMT_FOR4) {
		d->alignment = 4;
	}

	s = de_get_ext_option(c, "iff:align");
	if(s) {
		d->alignment = de_atoi(s);
	}

	pos = 0;
	do_chunk_sequence(c, d, pos, c->infile->len);

	de_free(c, d);
}

static int de_identify_iff(deark *c)
{
	int fmt = identify_internal(c);
	if(fmt!=0) {
		return 9;
	}
	// TODO: LIST, CAT formats?
	return 0;
}

static void de_help_iff(deark *c)
{
	de_msg(c, "-opt iff:align=<n> : Assume chunks are padded to an n-byte boundary\n");
}
void de_module_iff(deark *c, struct deark_module_info *mi)
{
	mi->id = "iff";
	mi->desc = "IFF (Interchange File Format)";
	mi->run_fn = de_run_iff;
	mi->identify_fn = de_identify_iff;
	mi->help_fn = de_help_iff;
}
