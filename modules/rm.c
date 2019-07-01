// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// RealMedia

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rm);

typedef struct localctx_struct {
	int reserved;
} lctx;

static int do_rm_chunk(deark *c, lctx *d, i64 pos1, i64 maxlen,
	i64 *bytes_consumed)
{
	struct de_fourcc chunk4cc;
	i64 chunklen;
	i64 pos = pos1;
	i64 dpos;
	i64 dlen;
	int retval = 0;

	dbuf_read_fourcc(c->infile, pos, &chunk4cc, 4, 0x0);
	de_dbg(c, "chunk type: '%s'", chunk4cc.id_dbgstr);
	pos += 4;
	chunklen = de_getu32be_p(&pos);
	de_dbg(c, "chunk len: %"I64_FMT, chunklen);
	if(chunklen < 8) goto done;
	if(chunklen > maxlen) {
		de_warn(c, "Chunk at %"I64_FMT" exceeds its parents bounds", pos1);
		chunklen = maxlen;
	}

	*bytes_consumed = chunklen;
	retval = 1;

	dpos = pos;
	dlen = chunklen - 8;
	de_dbg(c, "dpos: %"I64_FMT", dlen: %"I64_FMT, dpos, dlen);
	if(c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, dpos, dlen, 256, NULL, 0x1);
	}

done:
	return retval;
}

static int do_rm_chunk_sequence(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;

	while(1) {
		int ret;
		i64 bytes_consumed = 0;

		if(pos >= pos1+len) break;
		de_dbg(c, "chunk at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		ret = do_rm_chunk(c, d, pos, pos1+len-pos, &bytes_consumed);
		de_dbg_indent(c, -1);
		if((!ret) || (bytes_consumed<1)) goto done;
		pos += bytes_consumed;
	}

done:
	return 1;
}

static void de_run_rm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	do_rm_chunk_sequence(c, d, 0, c->infile->len);
	de_free(c, d);
}

static int de_identify_rm(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, ".RMF\0", 5))
		return 100;
	return 0;
}

void de_module_rm(deark *c, struct deark_module_info *mi)
{
	mi->id = "rm";
	mi->desc = "RealMedia";
	mi->run_fn = de_run_rm;
	mi->identify_fn = de_identify_rm;
}
