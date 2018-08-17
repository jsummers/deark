// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Generic RIFF format
// Windows animated cursor format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_riff);

#define CODE_ACON  0x41434f4eU
#define CODE_AVI   0x41564920U
#define CODE_INFO  0x494e464fU
#define CODE_PAL   0x50414c20U
#define CODE_RMID  0x524d4944U
#define CODE_WAVE  0x57415645U
#define CODE_WEBP  0x57454250U
#define CODE_auds  0x61756473U
#define CODE_cmpr  0x636d7072U
#define CODE_movi  0x6d6f7669U
#define CODE_vids  0x76696473U

#define CHUNK_DISP 0x44495350U
#define CHUNK_EXIF 0x45584946U
#define CHUNK_IART 0x49415254U
#define CHUNK_ICOP 0x49434f50U
#define CHUNK_ICCP 0x49434350U
#define CHUNK_ICMT 0x49434d54U
#define CHUNK_IKEY 0x494b4559U
#define CHUNK_ISBJ 0x4953424aU
#define CHUNK_JUNK 0x4a554e4bU
#define CHUNK_LIST 0x4c495354U
#define CHUNK_RIFF 0x52494646U
#define CHUNK_RIFX 0x52494658U
#define CHUNK_XMP  0x584d5020U
#define CHUNK__PMX 0x5f504d58U
#define CHUNK_avih 0x61766968U
#define CHUNK_data 0x64617461U
#define CHUNK_fact 0x66616374U
#define CHUNK_fmt  0x666d7420U
#define CHUNK_icon 0x69636f6eU
#define CHUNK_strf 0x73747266U
#define CHUNK_strh 0x73747268U

typedef struct localctx_struct {
	int is_cdr;
	de_uint32 curr_avi_stream_type;
} lctx;

static void do_extract_raw(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len, const char *ext,
	unsigned int createflags)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, ext, NULL, createflags);
}

static void do_INFO_item(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len, de_uint32 chunk_id)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	// TODO: Decode the chunk_id (e.g. ICRD = Creation date).

	// TODO: Support the CSET chunk
	dbuf_read_to_ucstring_n(ictx->f, pos, len, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_LATIN1);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz(s));

	ucstring_destroy(s);
}

static void extract_ani_frame(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	de_byte buf[4];
	const char *ext;

	de_dbg(c, "frame at %d, len=%d", (int)pos, (int)len);

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

	dbuf_create_file_from_slice(ictx->f, pos, len, ext, NULL, 0);
}

static const char *get_wav_fmt_name(unsigned int n)
{
	const char *name = NULL;
	switch(n) {
	case 0x0001: name="PCM"; break;
	case 0x0002: name="ADPCM"; break;
	case 0x0050: name="MPEG"; break;
	case 0x0055: name="MPEGLAYER3"; break;
	case 0xFFFE: name="EXTENSIBLE"; break;
		// TODO: There are lots more formats.
	}

	return name?name:"?";
}

static void decode_WAVEFORMATEX(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos1, de_int64 len)
{
	unsigned int formattag;
	de_int64 n;
	de_int64 pos = pos1;

	if(!ictx->is_le) goto done;
	if(len<14) goto done;

	formattag = (unsigned int)dbuf_getui16le_p(ictx->f, &pos);
	de_dbg(c, "FormatTag: 0x%04x (%s)", formattag, get_wav_fmt_name(formattag));
	n = dbuf_getui16le_p(ictx->f, &pos);
	de_dbg(c, "Channels: %u", (unsigned int)n);
	n = dbuf_getui32le_p(ictx->f, &pos);
	de_dbg(c, "SamplesPerSec: %u", (unsigned int)n);
	n = dbuf_getui32le_p(ictx->f, &pos);
	de_dbg(c, "AvgBytesPerSec: %u", (unsigned int)n);
	n = dbuf_getui16le_p(ictx->f, &pos);
	de_dbg(c, "BlockAlign: %u", (unsigned int)n);
	if(len<16) goto done;
	n = dbuf_getui16le_p(ictx->f, &pos);
	de_dbg(c, "BitsPerSample: %u", (unsigned int)n);
	if(len<18) goto done;
	n = dbuf_getui16le_p(ictx->f, &pos);
	de_dbg(c, "cbSize: %u", (unsigned int)n);

done:
	;
}

static void do_wav_fmt(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	decode_WAVEFORMATEX(c, d, ictx, pos, len);
}

static void do_wav_fact(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	de_int64 n;

	if(!ictx->is_le) return;
	if(len<4) return;
	n = de_getui32le(pos);
	de_dbg(c, "number of samples: %u", (unsigned int)n);
}

static void do_avi_avih(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	de_int64 n, n2;

	if(len<40) return;
	n = de_getui32le(pos);
	de_dbg(c, "microseconds/frame: %u", (unsigned int)n);
	n = de_getui32le(pos+12);
	de_dbg(c, "flags: 0x%08x", (unsigned int)n);
	n = de_getui32le(pos+16);
	de_dbg(c, "number of frames: %u", (unsigned int)n);
	n = de_getui32le(pos+24);
	de_dbg(c, "number of streams: %u", (unsigned int)n);
	n = de_getui32le(pos+32);
	n2 = de_getui32le(pos+36);
	de_dbg_dimensions(c, n, n2);
	// TODO: There are more fields in this chunk.
}

static void do_avi_strh(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	struct de_fourcc type4cc;
	struct de_fourcc codec4cc;

	if(len<8) return;

	dbuf_read_fourcc(ictx->f, pos, &type4cc, 4, 0x0);
	de_dbg(c, "stream type: '%s'", type4cc.id_dbgstr);
	// Hack. TODO: Need a better way to track state.
	d->curr_avi_stream_type = type4cc.id;

	dbuf_read_fourcc(ictx->f, pos+4, &codec4cc, 4, 0x0);
	de_dbg(c, "codec: '%s'", codec4cc.id_dbgstr);

	// TODO: There are more fields here.
}

static void do_avi_strf(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	if(d->curr_avi_stream_type==CODE_vids) {
		struct de_bmpinfo bi;
		// For video streams, this is a BITMAPINFO.
		de_fmtutil_get_bmpinfo(c, ictx->f, &bi, pos, len, DE_BMPINFO_CMPR_IS_4CC);
		// This chunk contains just a bitmap header, so we can't extract a bitmap.
	}
	else if(d->curr_avi_stream_type==CODE_auds) {
		// For audio streams, this is a WAVEFORMATEX.
		decode_WAVEFORMATEX(c, d, ictx, pos, len);
	}
}

static void do_palette(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	de_int64 ver;
	de_int64 n;
	de_int64 i;
	de_byte r,g,b,flags;
	de_uint32 clr;
	char tmps[32];

	if(!ictx->is_le) return;
	ver = de_getui16le(pos);
	de_dbg(c, "version: 0x%04x", (unsigned int)ver);
	pos += 2;
	n = de_getui16le(pos);
	de_dbg(c, "number of entries: %d", (int)n);
	pos += 2;
	if(n>(len-4)/4) n=(len-4)/4;
	if(n>1024) n=1024;
	if(n<1) return;

	de_dbg(c, "palette entries at %d", (int)pos);
	de_dbg_indent(c, 1);
	for(i=0; i<n; i++) {
		r = de_getbyte(pos);
		g = de_getbyte(pos+1);
		b = de_getbyte(pos+2);
		flags = de_getbyte(pos+3);
		pos += 4;
		clr = DE_MAKE_RGB(r, g, b);
		de_snprintf(tmps, sizeof(tmps), " flags=0x%02x", (unsigned int)flags);
		de_dbg_pal_entry2(c, i, clr, NULL, NULL, tmps);
	}
	de_dbg_indent(c, -1);
}

static void do_DISP_DIB(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	if(len<12) return;
	// "X" = Tell the dib module to mark the output file as "auxiliary".
	de_run_module_by_id_on_slice2(c, "dib", "X", ictx->f, pos, len);
}

static void do_DISP_TEXT(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len1)
{
	de_int64 foundpos;
	de_int64 len = len1;

	// Stop at NUL
	if(dbuf_search_byte(ictx->f, 0x00, pos, len1, &foundpos)) {
		len = foundpos - pos;
	}
	de_dbg(c, "text length: %d", (int)len);
	if(len<1) return;

	do_extract_raw(c, d, ictx, pos, len, "disp.txt", DE_CREATEFLAG_IS_AUX);
}

static void do_ICCP(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, "icc", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_EXIF(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	de_fmtutil_handle_exif(c, pos, len);
}

static void do_XMP(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_DISP(deark *c, lctx *d, struct de_iffctx *ictx, de_int64 pos, de_int64 len)
{
	unsigned int ty;
	de_int64 dpos, dlen;

	if(!ictx->is_le) return;
	if(len<4) return;
	ty = (unsigned int)de_getui32le(pos);
	de_dbg(c, "data type: %u (%s)", ty,
		de_fmtutil_get_windows_cb_data_type_name(ty));

	dpos = pos+4;
	dlen = len-4;
	switch(ty) {
	case 1:
	case 7:
		do_DISP_TEXT(c, d, ictx, dpos, dlen);
		break;
	case 8:
	case 17:
		do_DISP_DIB(c, d, ictx, dpos, dlen);
		break;
	}
}

static int my_on_std_container_start_fn(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->level==0) {
		const char *fmtname = NULL;

		// Special check for CorelDraw formats.
		if(!de_memcmp(ictx->main_contentstype4cc.bytes, (const void*)"CDR", 3)) {
			d->is_cdr = 1;
			fmtname = "CorelDRAW (RIFF-based)";
		}
		else {
			switch(ictx->main_contentstype4cc.id) {
			case CODE_ACON: fmtname = "Windows animated cursor"; break;
			case CODE_AVI: fmtname = "AVI"; break;
			case CODE_WAVE: fmtname = "WAVE"; break;
			case CODE_WEBP: fmtname = "WebP"; break;
			}
		}
		if(fmtname) {
			de_declare_fmt(c, fmtname);
		}
	}

	if(d->is_cdr && ictx->curr_container_fmt4cc.id==CHUNK_LIST) {
		// 'cmpr' LISTs in CorelDraw files are not correctly formed.
		// Tell the parser not to process them.
		if(ictx->curr_container_contentstype4cc.id==CODE_cmpr) {
			de_dbg(c, "[not decoding CDR cmpr list]");
			return 0;
		}
	}

	if(ictx->main_contentstype4cc.id==CODE_AVI &&
		ictx->curr_container_contentstype4cc.id==CODE_movi &&
		c->debug_level<2)
	{
		// There are often a huge number of these chunks, and we can't do
		// anything interesting with them, so skip them by default.
		de_dbg(c, "[not decoding movi chunks]");
		return 0;
	}

	return 1;
}

static int my_preprocess_riff_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	// TODO: Need a better way to do this.
	switch(ictx->chunkctx->chunk4cc.id) {
	case CHUNK_DISP: name="display"; break;
	case CHUNK_IART: name="artist"; break;
	case CHUNK_ICOP: name="copyright"; break;
	case CHUNK_ICMT: name="comments"; break;
	case CHUNK_IKEY: name="keywords"; break;
	case CHUNK_ISBJ: name="subject"; break;
	case CHUNK_JUNK: name="filler"; break;
	case CHUNK_LIST: name="subchunk container"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	return 1;
}

static int my_riff_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	de_int64 dpos, dlen;
	de_uint32 list_type;
	lctx *d = (lctx*)ictx->userdata;

	// We should always set this flag for formats (like RIFF) that aren't standard IFF.
	ictx->handled = 1;

	list_type = ictx->curr_container_contentstype4cc.id;
	dpos = ictx->chunkctx->dpos;
	dlen = ictx->chunkctx->dlen;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CHUNK_RIFF:
	case CHUNK_RIFX:
	case CHUNK_LIST:
		ictx->is_std_container = 1;
		return 1;
	}

	if(list_type==CODE_INFO) {
		do_INFO_item(c, d, ictx, dpos, dlen, ictx->chunkctx->chunk4cc.id);
		goto chunk_handled;
	}

	switch(ictx->chunkctx->chunk4cc.id) {

	case CHUNK_DISP:
		do_DISP(c, d, ictx, dpos, dlen);
		break;

	case CHUNK_ICCP: // Used by WebP
		do_ICCP(c, d, ictx, dpos, dlen);
		break;

	case CHUNK_EXIF: // Used by WebP
		do_EXIF(c, d, ictx, dpos, dlen);
		break;

	case CHUNK_XMP: // Used by WebP
	case CHUNK__PMX: // Used by WAVE, AVI
		do_XMP(c, d, ictx, dpos, dlen);
		break;

	case CHUNK_icon:
		if(ictx->main_contentstype4cc.id==CODE_ACON) {
			extract_ani_frame(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_data:
		if(list_type==CODE_RMID) {
			do_extract_raw(c, d, ictx, dpos, dlen, "mid", 0);
		}
		else if(list_type==CODE_PAL) {
			do_palette(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_fmt:
		if(ictx->main_contentstype4cc.id==CODE_WAVE) {
			do_wav_fmt(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_fact:
		if(ictx->main_contentstype4cc.id==CODE_WAVE) {
			do_wav_fact(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_avih:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_avih(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_strh:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_strh(c, d, ictx, dpos, dlen);
		}
		break;

	case CHUNK_strf:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_strf(c, d, ictx, dpos, dlen);
		}
		break;
	}

chunk_handled:
	return 1;
}

static void de_run_riff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	de_byte buf[4];

	d = de_malloc(c, sizeof(lctx));
	ictx = de_malloc(c, sizeof(struct de_iffctx));

	ictx->userdata = (void*)d;
	ictx->preprocess_chunk_fn = my_preprocess_riff_chunk_fn;
	ictx->handle_chunk_fn = my_riff_chunk_handler;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->f = c->infile;

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "RIFF", 4)) {
		ictx->is_le = 1;
		ictx->reversed_4cc = 0;
	}
	else if(!de_memcmp(buf, "RIFX", 4)) {
		ictx->is_le = 0;
		ictx->reversed_4cc = 0;
	}
	else if(!de_memcmp(buf, "XFIR", 4)) {
		ictx->is_le = 1;
		ictx->reversed_4cc = 1;
	}
	else {
		de_warn(c, "This is probably not a RIFF file.");
		ictx->is_le = 1;
		ictx->reversed_4cc = 0;
	}

	de_fmtutil_read_iff_format(c, ictx, 0, ictx->f->len);

	de_free(c, ictx);
	de_free(c, d);
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
	mi->desc = "RIFF-based formats";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_riff;
}
