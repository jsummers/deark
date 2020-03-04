// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// FLI/FLC animation

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_fli);

#define CHUNKTYPE_FLI        0xaf11
#define CHUNKTYPE_FLC        0xaf12
#define CHUNKTYPE_FRAME      0xf1fa

struct chunk_info_type {
	UI chunktype;
	int level;
	i64 pos;
	i64 len;
};

typedef struct localctx_struct {
	UI main_chunktype;
	i64 scr_width, scr_height;
	int depth;
	i64 frame_count;
} lctx;

static const char *get_chunk_type_name(lctx *d, struct chunk_info_type *parent_ci, UI t)
{
	const char *name = NULL;
	switch(t) {
	case 0x0004: name="color map 256"; break; // FLC only
	case 0x0007: name="delta compressed data"; break; // FLC only
	case 0x000b: name="color map 64"; break; // FLI only
	case 0x000c: name="delta compressed data"; break; // FLI only
	case 0x000d: name="clear screen"; break;
	case 0x000f: name="RLE compressed data"; break;
	case 0x0010: name="uncompressed data"; break;
	case 0x0012: name="thumbnail image"; break; // FLC only
	case CHUNKTYPE_FLI: name="FLI"; break;
	case CHUNKTYPE_FLC: name="FLC"; break;
	case 0xf100: name="prefix"; break;
	case CHUNKTYPE_FRAME: name="frame"; break;
	}
	return name?name:"?";
}

static void do_sequence_of_chunks(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 max_nchunks);

static void do_chunk_FLI_FLC(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 pos = ci->pos + 6;
	i64 n;

	d->main_chunktype = ci->chunktype;
	n = de_getu16le_p(&pos);
	de_dbg(c, "num frames: %d", (int)n);
	d->scr_width = de_getu16le_p(&pos);
	de_dbg(c, "screen width: %d", (int)d->scr_width);
	d->scr_height = de_getu16le_p(&pos);
	de_dbg(c, "screen height: %d", (int)d->scr_height);
	d->depth = (int)de_getu16le_p(&pos);
	de_dbg(c, "depth: %d", d->depth);
	pos += 2;
	n = (int)de_getu16le_p(&pos);
	de_dbg(c, "speed: %d ticks/frame", (int)n);

	pos = ci->pos + 128;
	do_sequence_of_chunks(c, d, ci, pos, -1);
}

static void do_chunk_frame(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 num_subchunks;

	num_subchunks = de_getu16le(ci->pos+6);
	de_dbg(c, "num subchunks: %"I64_FMT, num_subchunks);
	do_sequence_of_chunks(c, d, ci, ci->pos+16, num_subchunks);
}

static int do_chunk(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 bytes_avail, int level, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	int saved_indent_level;
	int retval = 0;
	struct chunk_info_type *ci = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(bytes_avail<6) goto done;

	ci = de_malloc(c, sizeof(struct chunk_info_type));
	ci->level = level;
	ci->pos = pos1;

	de_dbg(c, "chunk at %"I64_FMT, ci->pos);
	de_dbg_indent(c, 1);

	ci->len = de_getu32le_p(&pos);
	de_dbg(c, "chunk len: %"I64_FMT, ci->len);
	if(ci->len==0) {
		goto done;
	}
	if(ci->len<6) {
		de_err(c, "Bad chunk header at %"I64_FMT, ci->pos);
		goto done;
	}
	if(ci->len > bytes_avail) {
		de_warn(c, "Chunk at %"I64_FMT" exceeds its parent's bounds", ci->pos);
		ci->len = bytes_avail;
	}

	*pbytes_consumed = ci->len;
	retval = 1;

	ci->chunktype = (UI)de_getu16le_p(&pos);
	de_dbg(c, "chunk type: 0x%04x (%s)", ci->chunktype,
		get_chunk_type_name(d, parent_ci, ci->chunktype));

	if(level==0) {
		if(ci->chunktype==CHUNKTYPE_FLI || ci->chunktype==CHUNKTYPE_FLC) {
			do_chunk_FLI_FLC(c, d, ci);
		}
		else {
			de_err(c, "Not a FLI/FLC file");
		}
		goto done;
	}

	if(ci->chunktype==CHUNKTYPE_FRAME) {
		do_chunk_frame(c, d, ci);
	}

done:
	de_free(c, ci);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// if max_nchunks==-1, no maximum
static void do_sequence_of_chunks(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 max_nchunks)
{
	i64 pos = pos1;
	i64 endpos = parent_ci->pos + parent_ci->len;
	i64 chunk_idx = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(pos+6 >= endpos) goto done;
	de_dbg(c, "sequence of chunks at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		i64 bytes_avail;
		i64 bytes_consumed = 0;
		int ret;

		if(max_nchunks>=0 && chunk_idx>=max_nchunks) break;
		bytes_avail = endpos - pos;
		if(bytes_avail<6) break;

		ret = do_chunk(c, d, parent_ci, pos, bytes_avail, parent_ci->level+1, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;
		pos += bytes_consumed;
		chunk_idx++;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_fli(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 bytes_consumed = 0;

	d = de_malloc(c, sizeof(lctx));

	(void)do_chunk(c, d, NULL, 0, c->infile->len, 0, &bytes_consumed);

	de_free(c, d);
}

static int de_identify_fli(deark *c)
{
	UI ct;
	int has_ext;

	ct = (UI)de_getu16le(4);
	if(ct!=CHUNKTYPE_FLI && ct!=CHUNKTYPE_FLC) return 0;
	has_ext = de_input_file_has_ext(c, "fli") ||
		de_input_file_has_ext(c, "flc");
	if(has_ext) return 90;
	return 15;
}

void de_module_fli(deark *c, struct deark_module_info *mi)
{
	mi->id = "fli";
	mi->desc = "FLI/FLC animation";
	mi->run_fn = de_run_fli;
	mi->identify_fn = de_identify_fli;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
