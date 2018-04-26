// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Apple II disk image formats, etc.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_woz);

#define CODE_INFO 0x494e464fU
#define CODE_META 0x4d455441U

typedef struct localctx_struct {
	int reserved;
} lctx;

static const char *get_woz_disk_type_name(de_byte t)
{
	switch(t) {
	case 1: return "5.25";
	case 2: return "3.5";
	}
	return "?";
}

static void do_woz_INFO(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	de_byte b;
	de_int64 pos = chunkctx->chunk_dpos;
	de_ucstring *s = NULL;

	if(chunkctx->chunk_dlen<37) return;
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "INFO chunk version: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "disk type: %d (%s)", (int)b, get_woz_disk_type_name(b));
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "write protected: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "synchronized: %d", (int)b);
	b = dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "cleaned: %d", (int)b);

	s = ucstring_create(c);
	dbuf_read_to_ucstring(ictx->f, pos, 32, s, 0, DE_ENCODING_UTF8);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "creator: \"%s\"", ucstring_getpsz(s));

	ucstring_destroy(s);
}

static void do_woz_META(deark *c, struct de_iffctx *ictx,
	const struct de_iffchunkctx *chunkctx)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	// TODO: Parse out the individual items?
	dbuf_read_to_ucstring_n(ictx->f, chunkctx->chunk_dpos, chunkctx->chunk_dlen,
		DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_UTF8);
	de_dbg(c, "metadata string: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);
}

static int my_woz_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	// Always set this, because we never want the IFF parser to try to handle
	// a chunk itself.
	ictx->handled = 1;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_INFO:
		do_woz_INFO(c, ictx, ictx->chunkctx);
		break;
	case CODE_META:
		do_woz_META(c, ictx, ictx->chunkctx);
	}

	return 1;
}

static void de_run_woz(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	de_uint32 crc;
	de_int64 pos = 0;

	// WOZ has a 12-byte header, then sequence of chunks that are basically the
	// same format as RIFF.
	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_woz_chunk_handler;
	ictx->f = c->infile;
	ictx->is_le = 1;
	ictx->reversed_4cc = 0;

	if(ictx->f->len<12) goto done;
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 8; // signature
	crc = (de_uint32)dbuf_getui32le_p(ictx->f, &pos);
	de_dbg(c, "crc: 0x%08x", (unsigned int)crc);
	de_dbg_indent(c, -1);

	de_fmtutil_read_iff_format(c, ictx, pos, ictx->f->len-pos);

done:
	de_free(c, ictx);
	de_free(c, d);
}

static int de_identify_woz(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x57\x4f\x5a\x31\xff\x0a\x0d\x0a", 8))
		return 100;
	return 0;
}

void de_module_woz(deark *c, struct deark_module_info *mi)
{
	mi->id = "woz";
	mi->desc = "WOZ floppy disk image format";
	mi->desc2 = "metadata only";
	mi->run_fn = de_run_woz;
	mi->identify_fn = de_identify_woz;
}
