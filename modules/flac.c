// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// FLAC audio

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_flac);

typedef struct localctx_struct {
	int reserved;
} lctx;

static const char *get_mdblk_name(u8 blktype)
{
	const char *name = NULL;
	switch(blktype) {
	case 0: name="STREAMINFO"; break;
	case 1: name="PADDING"; break;
	case 2: name="APPLICATION"; break;
	case 3: name="SEEKTABLE"; break;
	case 4: name="VORBIS_COMMENT"; break;
	case 5: name="CUESHEET"; break;
	case 6: name="PICTURE"; break;
	}
	return name?name:"?";
}

static void do_metadata_block_vorbiscomment(deark *c, lctx *d, i64 pos1, i64 len)
{
	de_dbg(c, "vorbis comment block at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "ogg", "C", c->infile, pos1, len);
	de_dbg_indent(c, -1);
}

static void do_metadata_block_picture(deark *c, lctx *d, i64 pos1, i64 len)
{
	de_dbg(c, "picture at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "id3", "F", c->infile, pos1, len);
	de_dbg_indent(c, -1);
}

static void do_metadata_block(deark *c, lctx *d, u8 blktype, i64 pos1, i64 len)
{
	switch(blktype) {
	case 4:
		do_metadata_block_vorbiscomment(c, d, pos1, len);
		break;
	case 6:
		do_metadata_block_picture(c, d, pos1, len);
		break;
	}
}

static void run_flac_internal(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg(c, "signature at %"I64_FMT, pos);
	pos += 4;

	de_dbg_indent_save(c, &saved_indent_level);
	while(1) {
		u8 b;
		i64 blklen;
		u8 blktype;
		const char *blkname;
		u8 is_last;

		if(pos >= pos1+len) goto done;
		de_dbg(c, "metadata block at %"I64_FMT, pos);
		de_dbg_indent(c, 1);
		b = de_getbyte_p(&pos);
		is_last = (b&0x80)!=0;
		de_dbg(c, "is-last: %u", (unsigned int)is_last);
		blktype = (b&0x7f);
		blkname = get_mdblk_name(blktype);
		de_dbg(c, "block type: %u (%s)", (unsigned int)blktype, blkname);
		blklen = dbuf_getint_ext(c->infile, pos, 3, 0, 0);
		pos += 3;
		de_dbg(c, "block len: %u", (unsigned int)blklen);
		do_metadata_block(c, d, blktype, pos, blklen);
		pos += blklen;
		de_dbg_indent(c, -1);
		if(is_last) break;
	}

	de_dbg(c, "frames start at %"I64_FMT, pos);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_flac(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_id3info id3i;

	d = de_malloc(c, sizeof(lctx));
	de_fmtutil_handle_id3(c, c->infile, &id3i, 0);
	run_flac_internal(c, d, id3i.main_start, id3i.main_end-id3i.main_start);
	de_free(c, d);
}

static int de_identify_flac(deark *c)
{
	i64 pos = 0;

	if(!c->detection_data.id3.detection_attempted) {
		de_err(c, "flac detection requires id3 module");
		return 0;
	}

	if(c->detection_data.id3.has_id3v2) {
		pos = (i64)c->detection_data.id3.bytes_at_start;
	}

	if(!dbuf_memcmp(c->infile, pos, "fLaC", 4))
		return 100;

	return 0;
}

void de_module_flac(deark *c, struct deark_module_info *mi)
{
	mi->id = "flac";
	mi->desc = "FLAC";
	mi->run_fn = de_run_flac;
	mi->identify_fn = de_identify_flac;
}
