// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// RealMedia

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rm);

#define CODE_CONT 0x434f4e54U
#define CODE_MDPR 0x4d445052U
#define CODE_PROP 0x50524f50U

struct chunkinfo {
	struct de_fourcc chunk4cc;
	i64 pos;
	i64 dpos;
	i64 dlen;
	unsigned int version;
};

typedef struct localctx_struct {
	int input_encoding;
} lctx;

static void read_chunk_version_p(deark *c, lctx *d, struct chunkinfo *ci, i64 *ppos)
{
	ci->version = (unsigned int)de_getu16be_p(ppos);
	de_dbg(c, "object version: %u", ci->version);
}

static void do_chunk_PROP(deark *c, lctx *d, struct chunkinfo *ci)
{
	i64 pos = ci->dpos;
	i64 n;

	read_chunk_version_p(c, d, ci, &pos);
	if(ci->version!=0 || ci->dlen<42) goto done;

	pos += 7*4; // TODO: other fields

	n = de_getu32be_p(&pos);
	de_dbg(c, "index offset: %"I64_FMT, n);
	n = de_getu32be_p(&pos);
	de_dbg(c, "data offset: %"I64_FMT, n);
	n = de_getu16be_p(&pos);
	de_dbg(c, "num streams: %d", (int)n);
	n = de_getu16be_p(&pos);
	de_dbg(c, "flags: 0x%04x", (unsigned int)n);
done:
	;
}

static void do_chunk_CONT(deark *c, lctx *d, struct chunkinfo *ci)
{
	i64 pos = ci->dpos;
	de_ucstring *s = NULL;
	i64 slen;

	read_chunk_version_p(c, d, ci, &pos);
	if(ci->version != 0) goto done;

	s = ucstring_create(c);
	slen = de_getu16be_p(&pos);
	dbuf_read_to_ucstring(c->infile, pos, slen, s, 0, d->input_encoding);
	de_dbg(c, "title: \"%s\"", ucstring_getpsz_d(s));
	pos += slen;

	ucstring_empty(s);
	slen = de_getu16be_p(&pos);
	dbuf_read_to_ucstring(c->infile, pos, slen, s, 0, d->input_encoding);
	de_dbg(c, "author: \"%s\"", ucstring_getpsz_d(s));
	pos += slen;

	ucstring_empty(s);
	slen = de_getu16be_p(&pos);
	dbuf_read_to_ucstring(c->infile, pos, slen, s, 0, d->input_encoding);
	de_dbg(c, "copyright: \"%s\"", ucstring_getpsz_d(s));
	pos += slen;

done:
	ucstring_destroy(s);
}

static void do_chunk_MDPR(deark *c, lctx *d, struct chunkinfo *ci)
{
	i64 pos = ci->dpos;
	de_ucstring *s = NULL;
	i64 slen;
	i64 n;

	read_chunk_version_p(c, d, ci, &pos);
	if(ci->version != 0) goto done;

	n = de_getu16be_p(&pos);
	de_dbg(c, "stream number: %d", (int)n);

	pos += 7*4; // TODO: other fields

	slen = (i64)de_getbyte_p(&pos);
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, slen, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "stream name: \"%s\"", ucstring_getpsz_d(s));
	pos += slen;

	slen = (i64)de_getbyte_p(&pos);
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, slen, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "mime type: \"%s\"", ucstring_getpsz_d(s));
	pos += slen;

	if(pos+4 > ci->dpos + ci->dlen) goto done;
	n = de_getu32be_p(&pos);
	if(n == 0) goto done;
	de_dbg(c, "type specific data at %"I64_FMT", len=%"I64_FMT, pos, n);
	if(pos+n > ci->dpos + ci->dlen) goto done;
	de_dbg_indent(c, 1);
	de_dbg_hexdump(c, c->infile, pos, n, 256, NULL, 0x1);
	de_dbg_indent(c, -1);

done:
	;
}

static int do_rm_chunk(deark *c, lctx *d, i64 pos1, i64 maxlen,
	i64 *bytes_consumed)
{
	i64 chunklen;
	i64 pos = pos1;
	int retval = 0;
	int hexdump_flag = 0;
	struct chunkinfo *ci = NULL;

	ci = de_malloc(c, sizeof(struct chunkinfo));
	ci->pos = pos1;
	dbuf_read_fourcc(c->infile, pos, &ci->chunk4cc, 4, 0x0);
	de_dbg(c, "chunk type: '%s'", ci->chunk4cc.id_dbgstr);
	pos += 4;
	chunklen = de_getu32be_p(&pos);
	de_dbg(c, "chunk len: %"I64_FMT, chunklen);
	if(chunklen < 8) goto done;
	if(chunklen > maxlen) {
		de_warn(c, "Chunk at %"I64_FMT" exceeds its parent's bounds", pos1);
		chunklen = maxlen;
	}

	*bytes_consumed = chunklen;
	retval = 1;

	ci->dpos = pos;
	ci->dlen = chunklen - 8;
	de_dbg(c, "dpos: %"I64_FMT", dlen: %"I64_FMT, ci->dpos, ci->dlen);

	switch(ci->chunk4cc.id) {
	case CODE_CONT:
		do_chunk_CONT(c, d, ci);
		break;
	case CODE_MDPR:
		do_chunk_MDPR(c, d, ci);
		break;
	case CODE_PROP:
		do_chunk_PROP(c, d, ci);
		break;
	default:
		hexdump_flag = 1;
	}

	if(hexdump_flag && c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, ci->dpos, ci->dlen, 256, NULL, 0x1);
	}

done:
	de_free(c, ci);
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
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
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
