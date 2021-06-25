// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Decoder for IFF, RIFF, and similar formats

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

#define CODE__c_   0x28632920U // "(c) "
#define CODE_ANNO  0x414e4e4fU
#define CODE_AUTH  0x41555448U
#define CODE_NAME  0x4e414d45U
#define CODE_TEXT  0x54455854U
#define CODE_RIFF  0x52494646U

struct iff_parser_data {
	char name_str[80];
};

struct de_iffctx *fmtutil_create_iff_decoder(deark *c)
{
	struct de_iffctx *ictx;

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->c = c;
	return ictx;
}

void fmtutil_destroy_iff_decoder(struct de_iffctx *ictx)
{
	if(!ictx) return;
	de_free(ictx->c, ictx);
}

static void do_iff_text_chunk(deark *c, struct de_iffctx *ictx, i64 dpos, i64 dlen,
	const char *name)
{
	de_ucstring *s = NULL;

	if(dlen<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(ictx->f,
		dpos, dlen, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_iff_anno(deark *c, struct de_iffctx *ictx, i64 pos, i64 len)
{
	i64 foundpos;

	if(len<1) return;

	// Some ANNO chunks seem to be padded with one or more NUL bytes. Probably
	// best not to save them.
	if(dbuf_search_byte(ictx->f, 0x00, pos, len, &foundpos)) {
		len = foundpos - pos;
	}
	if(len<1) return;
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(ictx->f, pos, len, "anno.txt", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		de_ucstring *s = NULL;
		s = ucstring_create(c);
		dbuf_read_to_ucstring_n(ictx->f, pos, len, DE_DBG_MAX_STRLEN, s, 0, ictx->input_encoding);
		de_dbg(c, "annotation: \"%s\"", ucstring_getpsz(s));
		ucstring_destroy(s);
	}
}

void fmtutil_default_iff_chunk_identify(struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE__c_ : name="copyright"; break;
	case CODE_ANNO: name="annotation"; break;
	case CODE_AUTH: name="author"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
}

// Note that some of these chunks are *not* defined in the generic IFF
// specification.
// They might be defined in the 8SVX specification. They seem to have
// become unofficial standard chunks.
static int de_fmtutil_default_iff_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	i64 dpos = ictx->chunkctx->dpos;
	i64 dlen = ictx->chunkctx->dlen;
	u32 chunktype = ictx->chunkctx->chunk4cc.id;

	switch(chunktype) {
		// Note that chunks appearing here should also be listed below,
		// in de_fmtutil_is_standard_iff_chunk().
	case CODE__c_:
		do_iff_text_chunk(c, ictx, dpos, dlen, "copyright");
		break;
	case CODE_ANNO:
		do_iff_anno(c, ictx, dpos, dlen);
		break;
	case CODE_AUTH:
		do_iff_text_chunk(c, ictx, dpos, dlen, "author");
		break;
	case CODE_NAME:
		do_iff_text_chunk(c, ictx, dpos, dlen, "name");
		break;
	case CODE_TEXT:
		do_iff_text_chunk(c, ictx, dpos, dlen, "text");
		break;
	}

	// Note we do not set ictx->handled. The caller is responsible for that.
	return 1;
}

// ictx can be NULL
int fmtutil_is_standard_iff_chunk(struct de_iffctx *ictx,
	u32 ct)
{
	switch(ct) {
	case CODE__c_:
	case CODE_ANNO:
	case CODE_AUTH:
	case CODE_NAME:
	case CODE_TEXT:
		return 1;
	}
	return 0;
}

static void fourcc_clear(struct de_fourcc *fourcc)
{
	de_zeromem(fourcc, sizeof(struct de_fourcc));
}

static int do_iff_chunk_sequence(deark *c, struct de_iffctx *ictx,
	struct de_iffchunkctx *parent, i64 pos1, i64 len, int level);

// Returns 0 if we can't continue
static int do_iff_chunk(deark *c, struct de_iffctx *ictx,
	struct de_iffchunkctx *parent,
	i64 pos, i64 bytes_avail, int level, i64 *pbytes_consumed)
{
	int ret;
	i64 chunk_dlen_raw;
	i64 chunk_dlen_padded;
	i64 data_bytes_avail;
	i64 hdrsize;
	struct de_iffchunkctx chunkctx;
	int saved_indent_level;
	int retval = 0;
	struct iff_parser_data *pctx = (struct iff_parser_data*)ictx->private_data;

	de_dbg_indent_save(c, &saved_indent_level);
	de_zeromem(&chunkctx, sizeof(struct de_iffchunkctx));
	chunkctx.parent = parent;

	hdrsize = 4+ictx->sizeof_len;
	if(bytes_avail<hdrsize) {
		de_warn(c, "Ignoring %"I64_FMT" bytes at %"I64_FMT"; too small "
			"to be a chunk", bytes_avail, pos);
		goto done;
	}
	data_bytes_avail = bytes_avail-hdrsize;

	dbuf_read_fourcc(ictx->f, pos, &chunkctx.chunk4cc, 4,
		ictx->reversed_4cc ? DE_4CCFLAG_REVERSED : 0x0);
	if(chunkctx.chunk4cc.id==0 && level==0) {
		de_warn(c, "Chunk ID not found at %"I64_FMT"; assuming the data ends "
			"here", pos);
		goto done;
	}

	if(ictx->sizeof_len==2) {
		chunk_dlen_raw = dbuf_getu16x(ictx->f, pos+4, ictx->is_le);
	}
	else {
		chunk_dlen_raw = dbuf_getu32x(ictx->f, pos+4, ictx->is_le);
	}
	chunkctx.dlen = chunk_dlen_raw;
	chunkctx.dpos = pos+hdrsize;

	// TODO: Setting these fields (prior to the identify function) is enough
	// for now, but we should also set the other fields here if we can.
	ictx->level = level;
	ictx->chunkctx = &chunkctx;

	if(ictx->preprocess_chunk_fn) {
		ictx->preprocess_chunk_fn(ictx);
	}

	if(chunkctx.chunk_name) {
		de_snprintf(pctx->name_str, sizeof(pctx->name_str), " (%s)", chunkctx.chunk_name);
	}
	else {
		pctx->name_str[0] = '\0';
	}

	de_dbg(c, "chunk '%s'%s at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
		chunkctx.chunk4cc.id_dbgstr, pctx->name_str, pos,
		chunkctx.dpos, chunkctx.dlen);
	de_dbg_indent(c, 1);

	if(chunkctx.dlen > data_bytes_avail) {
		int should_warn = 1;

		if(chunkctx.chunk4cc.id==CODE_RIFF && pos==0 && bytes_avail==ictx->f->len) {
			// Hack:
			// This apparent error, in which the RIFF chunk's length field gives the
			// length of the entire file, is too common (particularly in .ani files)
			// to warn about.
			should_warn = 0;
		}

		if(should_warn) {
			de_warn(c, "Invalid oversized chunk, or unexpected end of file "
				"(chunk at %d ends at %" I64_FMT ", "
				"parent ends at %" I64_FMT ")",
				(int)pos, chunkctx.dlen+chunkctx.dpos, pos+bytes_avail);
		}

		chunkctx.dlen = data_bytes_avail; // Try to continue
		de_dbg(c, "adjusting chunk data len to %"I64_FMT, chunkctx.dlen);
	}

	chunk_dlen_padded = de_pad_to_n(chunkctx.dlen, ictx->alignment);
	*pbytes_consumed = hdrsize + chunk_dlen_padded;

	// We've set *pbytes_consumed, so we can return "success"
	retval = 1;

	// Set ictx fields, prior to calling the handler
	chunkctx.pos = pos;
	chunkctx.len = bytes_avail;
	ictx->handled = 0;
	ictx->is_std_container = 0;
	ictx->is_raw_container = 0;

	ret = ictx->handle_chunk_fn(ictx);
	if(!ret) {
		retval = 0;
		goto done;
	}

	if(ictx->is_std_container || ictx->is_raw_container) {
		i64 contents_dpos, contents_dlen;

		ictx->chunkctx = NULL;
		ictx->curr_container_fmt4cc = chunkctx.chunk4cc;
		fourcc_clear(&ictx->curr_container_contentstype4cc);

		if(ictx->is_std_container) {
			contents_dpos = chunkctx.dpos+4;
			contents_dlen = chunkctx.dlen-4;

			// First 4 bytes of payload are the "contents type" or "FORM type"
			dbuf_read_fourcc(ictx->f, chunkctx.dpos, &ictx->curr_container_contentstype4cc, 4,
				ictx->reversed_4cc ? DE_4CCFLAG_REVERSED : 0);

			if(level==0) {
				ictx->main_fmt4cc = ictx->curr_container_fmt4cc;
				ictx->main_contentstype4cc = ictx->curr_container_contentstype4cc; // struct copy
			}
			de_dbg(c, "contents type: '%s'", ictx->curr_container_contentstype4cc.id_dbgstr);

			if(ictx->on_std_container_start_fn) {
				// Call only for standard-format containers.
				ret = ictx->on_std_container_start_fn(ictx);
				if(!ret) goto done;
			}
		}
		else { // ictx->is_raw_container
			contents_dpos = chunkctx.dpos;
			contents_dlen = chunkctx.dlen;
		}

		ret = do_iff_chunk_sequence(c, ictx, &chunkctx, contents_dpos, contents_dlen, level+1);
		if(!ret) {
			retval = 0;
			goto done;
		}

		if(ictx->on_container_end_fn) {
			// Call for all containers (not just standard-format containers).

			// TODO: Decide exactly what ictx->* fields to set here.
			ictx->level = level;

			ictx->chunkctx = NULL;
			ret = ictx->on_container_end_fn(ictx);
			if(!ret) {
				retval = 0;
				goto done;
			}
		}
	}
	else if(!ictx->handled) {
		de_fmtutil_default_iff_chunk_handler(ictx);
	}

done:
	fourcc_clear(&ictx->curr_container_fmt4cc);
	fourcc_clear(&ictx->curr_container_contentstype4cc);

	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_iff_chunk_sequence(deark *c, struct de_iffctx *ictx,
	struct de_iffchunkctx *parent, i64 pos1, i64 len, int level)
{
	i64 pos;
	i64 endpos;
	i64 chunk_len;
	struct de_fourcc saved_container_fmt4cc;
	struct de_fourcc saved_container_contentstype4cc;
	int ret;

	if(level >= 16) { // An arbitrary recursion limit.
		return 0;
	}

	endpos = pos1+len;
	saved_container_fmt4cc = ictx->curr_container_fmt4cc;
	saved_container_contentstype4cc = ictx->curr_container_contentstype4cc;

	pos = pos1;
	while(pos < endpos) {
		ictx->curr_container_fmt4cc = saved_container_fmt4cc;
		ictx->curr_container_contentstype4cc = saved_container_contentstype4cc;

		if(ictx->handle_nonchunk_data_fn) {
			i64 skip_len = 0;
			ictx->level = level;
			ret = ictx->handle_nonchunk_data_fn(ictx, pos, &skip_len);
			if(ret && skip_len>0) {
				pos += de_pad_to_n(skip_len, ictx->alignment);
				continue;
			}
		}

		ret = do_iff_chunk(c, ictx, parent, pos, endpos-pos, level, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	ictx->curr_container_fmt4cc = saved_container_fmt4cc;
	ictx->curr_container_contentstype4cc = saved_container_contentstype4cc;

	return 1;
}

void fmtutil_read_iff_format(struct de_iffctx *ictx, i64 pos, i64 len)
{
	deark *c = ictx->c;
	struct iff_parser_data *pctx = NULL;

	if(!ictx->f || !ictx->handle_chunk_fn) return; // Internal error

	ictx->level = 0;
	fourcc_clear(&ictx->main_fmt4cc);
	fourcc_clear(&ictx->main_contentstype4cc);
	fourcc_clear(&ictx->curr_container_fmt4cc);
	fourcc_clear(&ictx->curr_container_contentstype4cc);
	if(ictx->alignment==0) {
		ictx->alignment = 2;
	}
	if(ictx->sizeof_len==0) {
		ictx->sizeof_len = 4;
	}

	if(ictx->input_encoding==DE_ENCODING_UNKNOWN) {
		ictx->input_encoding = DE_ENCODING_ASCII;
	}

	pctx = de_malloc(c, sizeof(struct iff_parser_data));
	ictx->private_data = (void*)pctx;
	do_iff_chunk_sequence(c, ictx, NULL, pos, len, 0);
	ictx->private_data = NULL;
	de_free(c, pctx);
}
