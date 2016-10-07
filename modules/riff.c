// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Generic RIFF format
// Windows animated cursor format

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_riff);
DE_DECLARE_MODULE(de_module_ani);

#define CODE_ACON  0x41434f4eU
#define CODE_INFO  0x494e464fU
#define CODE_PAL   0x50414c20U
#define CODE_RMID  0x524d4944U
#define CODE_WAVE  0x57415645U
#define CODE_cmpr  0x636d7072U

#define CHUNK_DISP 0x44495350U
#define CHUNK_LIST 0x4c495354U
#define CHUNK_RIFF 0x52494646U
#define CHUNK_RIFX 0x52494658U
#define CHUNK_data 0x64617461U
#define CHUNK_fact 0x66616374U
#define CHUNK_fmt  0x666d7420U
#define CHUNK_icon 0x69636f6eU

typedef struct localctx_struct {
	de_uint32 riff_type;
	int level;
	int is_le;
	int char_codes_are_reversed;
	int is_cdr;
} lctx;

static void do_extract_raw(deark *c, lctx *d, de_int64 pos, de_int64 len, const char *ext,
	unsigned int createflags)
{
	dbuf_create_file_from_slice(c->infile, pos, len, ext, NULL, createflags);
}

static void do_INFO_item(deark *c, lctx *d, de_int64 pos, de_int64 len, de_uint32 chunk_id)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	// TODO: Decode the chunk_id (e.g. ICRD = Creation date).

	// TODO: Support the CSET chunk
	dbuf_read_to_ucstring_n(c->infile, pos, len, 300, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "value: \"%s\"\n", ucstring_get_printable_sz(s));

	ucstring_destroy(s);
}

static void extract_ani_frame(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_byte buf[4];
	const char *ext;

	de_dbg(c, "frame at %d, len=%d\n", (int)pos, (int)len);

	de_read(buf, pos, 4);

	// Try to identify the format of this frame.
	if(!de_memcmp(buf, "\x00\x00\x01\x00", 4)) {
		ext = "ico";
	}
	else if(!de_memcmp(buf, "\x00\x00\x02\x00", 4)) {
		ext = "cur";
	}
	else {
		ext = "bin";
	}

	// TODO: Most embedded CUR files don't seem to have a meaningful "hotspot"
	// set. Can we patch that up? Maybe we should even convert ICO files to CUR
	// files, so that we can give them a hotspot.

	dbuf_create_file_from_slice(c->infile, pos, len, ext, NULL, 0);
}

static void do_wav_fmt(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 n;

	if(!d->is_le) return;
	if(len<14) return;

	n = de_getui16le(pos);
	de_dbg(c, "FormatTag: 0x%04x\n", (unsigned int)n);
	pos += 2;

	n = de_getui16le(pos);
	de_dbg(c, "Channels: %d\n", (int)n);
	pos += 2;

	n = de_getui32le(pos);
	de_dbg(c, "SamplesPerSec: %d\n", (int)n);
	pos += 4;

	n = de_getui32le(pos);
	de_dbg(c, "AvgBytesPerSec: %d\n", (int)n);
	pos += 4;

	n = de_getui16le(pos);
	de_dbg(c, "BlockAlign: %d\n", (int)n);
	pos += 2;
}

static void do_wav_fact(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 n;

	if(!d->is_le) return;
	if(len<4) return;
	n = de_getui32le(pos);
	de_dbg(c, "number of samples: %u\n", (unsigned int)n);
}

static void do_palette(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 ver;
	de_int64 n;
	de_int64 i;
	de_byte r,g,b,flags;

	if(!d->is_le) return;
	ver = de_getui16le(pos);
	de_dbg(c, "version: 0x%04x\n", (unsigned int)ver);
	pos += 2;
	n = de_getui16le(pos);
	de_dbg(c, "number of entries: %d\n", (int)n);
	pos += 2;
	if(n>(len-4)/4) n=(len-4)/4;
	if(n>1024) n=1024;
	if(n<1) return;

	de_dbg(c, "palette entries at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	for(i=0; i<n; i++) {
		r = de_getbyte(pos);
		g = de_getbyte(pos+1);
		b = de_getbyte(pos+2);
		flags = de_getbyte(pos+3);
		pos += 4;
		de_dbg(c, "pal[%d] = (%3d,%3d,%3d) flags=0x%02x\n", (int)i,
			(int)r, (int)g, (int)b, (unsigned int)flags);
	}
	de_dbg_indent(c, -1);
}

static void do_DISP_DIB(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_module_params *mparams = NULL;

	if(len<12) return;
	mparams = de_malloc(c, sizeof(de_module_params));

	// Tell the dib module to mark the output file as "auxiliary".
	mparams->codes = "X";

	de_run_module_by_id_on_slice(c, "dib", mparams, c->infile, pos, len);
	de_free(c, mparams);
}

static void do_DISP_TEXT(deark *c, lctx *d, de_int64 pos, de_int64 len1)
{
	de_int64 foundpos;
	de_int64 len = len1;

	// Stop at NUL
	if(dbuf_search_byte(c->infile, 0x00, pos, len1, &foundpos)) {
		len = foundpos - pos;
	}
	if(len<1) return;

	do_extract_raw(c, d, pos, len, "disp.txt", DE_CREATEFLAG_IS_AUX);
}

static const char *get_cb_data_type_name(de_int64 ty)
{
	const char *name = "?";

	switch(ty) {
	case 1: name="CF_TEXT"; break;
	case 2: name="CF_BITMAP"; break;
	case 3: name="CF_METAFILEPICT"; break;
	case 6: name="CF_TIFF"; break;
	case 7: name="CF_OEMTEXT"; break;
	case 8: name="CF_DIB"; break;
	case 11: name="CF_RIFF"; break;
	case 12: name="CF_WAVE"; break;
	case 13: name="CF_UNICODETEXT"; break;
	case 14: name="CF_ENHMETAFILE"; break;
	case 17: name="CF_DIBV5"; break;
	}
	return name;
}

static void do_DISP(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 ty;
	de_int64 dpos, dlen;

	if(!d->is_le) return;
	if(len<4) return;
	ty = de_getui32le(pos);
	de_dbg(c, "data type: %u (%s)\n", (unsigned int)ty,
		get_cb_data_type_name(ty));

	dpos = pos+4;
	dlen = len-4;
	switch(ty) {
	case 1:
	case 7:
		do_DISP_TEXT(c, d, dpos, dlen);
		break;
	case 8:
	case 17:
		do_DISP_DIB(c, d, dpos, dlen);
		break;
	}
}

static void process_riff_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len1, de_uint32 list_type)
{
	de_int64 chunk_pos;
	de_int64 chunk_data_pos;
	de_int64 chunk_data_len;
	de_int64 endpos;
	struct de_fourcc chunk4cc;
	struct de_fourcc listid4cc;

	if(d->level >= 16) { // An arbitrary recursion limit
		return;
	}

	if(d->is_cdr && list_type==CODE_cmpr) {
		// 'cmpr' LISTs in CorelDraw files are not correctly formed.
		de_dbg(c, "[not decoding CDR cmpr list]\n");
		return;
	}

	endpos = pos+len1;

	while((endpos-pos) >= 8) {
		chunk_pos = pos;
		dbuf_read_fourcc(c->infile, pos, &chunk4cc, d->char_codes_are_reversed);
		pos+=4;
		chunk_data_len = dbuf_getui32x(c->infile, pos, d->is_le);
		pos+=4;
		chunk_data_pos = pos;

		de_dbg(c, "chunk '%s' at %d, dpos=%d, dlen=%d\n", chunk4cc.id_printable, (int)chunk_pos,
			(int)chunk_data_pos, (int)chunk_data_len);

		if(chunk_data_pos + chunk_data_len > endpos) {
			if(chunk4cc.id==CHUNK_RIFF && chunk_pos==0 && chunk_data_len==endpos) {
				// This apparent error, in which the RIFF chunk's length field gives the
				// length of the entire file, is too common (particularly in .ani files)
				// to warn about.
				;
			}
			else if(chunk_data_pos+chunk_data_len > c->infile->len) {
				de_warn(c, "Chunk '%s' at offset %d goes beyond end of file.\n", chunk4cc.id_printable,
					(int)chunk_pos);
			}
			else {
				de_warn(c, "Chunk '%s' at offset %d exceeds its bounds.\n", chunk4cc.id_printable,
					(int)chunk_pos);
			}

			chunk_data_len = endpos - chunk_data_pos; // Fixup bad chunk length
			de_dbg(c, "adjusting chunk data len to %d\n", (int)chunk_data_len);
		}

		de_dbg_indent(c, 1);

		if(list_type==CODE_INFO) {
			do_INFO_item(c, d, pos, chunk_data_len, chunk4cc.id);
			goto chunk_handled;
		}

		switch(chunk4cc.id) {
		case CHUNK_RIFF:
		case CHUNK_RIFX:
		case CHUNK_LIST:
			dbuf_read_fourcc(c->infile, pos, &listid4cc, d->char_codes_are_reversed);
			if(d->level==0) {
				d->riff_type = listid4cc.id; // Remember the file type for later

				// Special check for CorelDraw formats.
				if(!de_memcmp(listid4cc.bytes, (const void*)"CDR", 3)) {
					d->is_cdr = 1;
				}
			}
			de_dbg(c, "%s type: '%s'\n", chunk4cc.id_printable, listid4cc.id_printable);

			d->level++;
			process_riff_sequence(c, d, pos+4, chunk_data_len-4, listid4cc.id);
			d->level--;
			break;

		case CHUNK_DISP:
			do_DISP(c, d, pos, chunk_data_len);
			break;

		case CHUNK_icon:
			if(d->riff_type==CODE_ACON) {
				extract_ani_frame(c, d, pos, chunk_data_len);
			}
			break;

		case CHUNK_data:
			if(list_type==CODE_RMID) {
				do_extract_raw(c, d, pos, chunk_data_len, "mid", 0);
			}
			else if(list_type==CODE_PAL) {
				do_palette(c, d, pos, chunk_data_len);
			}
			break;

		case CHUNK_fmt:
			if(d->riff_type==CODE_WAVE) {
				do_wav_fmt(c, d, pos, chunk_data_len);
			}
			break;

		case CHUNK_fact:
			if(d->riff_type==CODE_WAVE) {
				do_wav_fact(c, d, pos, chunk_data_len);
			}
			break;
		}

chunk_handled:
		de_dbg_indent(c, -1);

		pos += chunk_data_len;
		if(chunk_data_len%2) pos++; // Padding byte
	}
}

static void de_run_riff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte buf[4];

	d = de_malloc(c, sizeof(lctx));

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "RIFF", 4)) {
		d->is_le = 1;
		d->char_codes_are_reversed = 0;
	}
	else if(!de_memcmp(buf, "RIFX", 4)) {
		d->is_le = 0;
		d->char_codes_are_reversed = 0;
	}
	else if(!de_memcmp(buf, "XFIR", 4)) {
		d->is_le = 1;
		d->char_codes_are_reversed = 1;
	}
	else {
		de_warn(c, "This is probably not a RIFF file.\n");
		d->is_le = 1;
		d->char_codes_are_reversed = 0;
	}

	process_riff_sequence(c, d, 0, c->infile->len, 0);

	de_free(c, d);
}

static int de_identify_ani(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "RIFF", 4) && !de_memcmp(&buf[8], "ACON", 4))
		return 100;
	return 0;
}

void de_module_ani(deark *c, struct deark_module_info *mi)
{
	mi->id = "ani";
	mi->desc = "Windows animated cursor";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_ani;
}

static int de_identify_riff(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "RIFF", 4))
		return 50;
	if(!dbuf_memcmp(c->infile, 0, "XFIR", 4))
		return 50;
	if(!dbuf_memcmp(c->infile, 0, "RIFX", 4))
		return 50;
	return 0;
}

void de_module_riff(deark *c, struct deark_module_info *mi)
{
	mi->id = "riff";
	mi->desc = "RIFF metaformat";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_riff;
}
