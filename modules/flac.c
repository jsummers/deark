// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// FLAC audio

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_flac);

typedef struct localctx_struct {
	int reserved;
} lctx;

static const char *get_mdblk_name(de_byte blktype)
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

static void do_metadata_block_vorbiscomment(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_dbg(c, "vorbis comment block at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "ogg", "C", c->infile, pos1, len);
	de_dbg_indent(c, -1);
}

static void do_metadata_block(deark *c, lctx *d, de_byte blktype, de_int64 pos1, de_int64 len)
{
	if(blktype==4) {
		do_metadata_block_vorbiscomment(c, d, pos1, len);
	}
}

static void run_flac_internal(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;
	int saved_indent_level;

	de_dbg(c, "signature at %"INT64_FMT, pos);
	pos += 4;

	de_dbg_indent_save(c, &saved_indent_level);
	while(1) {
		de_byte b;
		de_int64 blklen;
		de_byte blktype;
		const char *blkname;
		de_byte is_last;

		if(pos >= pos1+len) goto done;
		de_dbg(c, "metadata block at %"INT64_FMT, pos);
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

	de_dbg(c, "frames start at %"INT64_FMT, pos);

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_flac(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos = 0;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	run_flac_internal(c, d, pos, c->infile->len);
	de_free(c, d);
}

static int de_identify_flac(deark *c)
{
	de_int64 pos = 0;

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
