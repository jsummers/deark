// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Generic RIFF format
// Windows animated cursor format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_riff);
DE_DECLARE_MODULE(de_module_mmm);

#define CODE_ACON  0x41434f4eU
#define CODE_AVI   0x41564920U
#define CODE_CDRX  0x43445258U
#define CODE_CMX1  0x434d5831U
#define CODE_INFO  0x494e464fU
#define CODE_PAL   0x50414c20U
#define CODE_RDIB  0x52444942U
#define CODE_RMID  0x524d4944U
#define CODE_WAVE  0x57415645U
#define CODE_WEBP  0x57454250U
#define CODE_auds  0x61756473U
#define CODE_bmpt  0x626d7074U
#define CODE_cmov  0x636d6f76U
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
#define CHUNK_INAM 0x494e414dU
#define CHUNK_ISBJ 0x4953424aU
#define CHUNK_JUNK 0x4a554e4bU
#define CHUNK_LIST 0x4c495354U
#define CHUNK_RIFF 0x52494646U
#define CHUNK_RIFX 0x52494658U
#define CHUNK_XMP  0x584d5020U
#define CHUNK__PMX 0x5f504d58U
#define CHUNK_avih 0x61766968U
#define CHUNK_bmhd 0x626d6864U
#define CHUNK_bmp  0x626d7020U
#define CHUNK_data 0x64617461U
#define CHUNK_fact 0x66616374U
#define CHUNK_fmt  0x666d7420U
#define CHUNK_icon 0x69636f6eU
#define CHUNK_strf 0x73747266U
#define CHUNK_strh 0x73747268U

typedef struct localctx_struct {
	UI top_level_chunk_count;
	int is_cdr;
	u32 curr_avi_stream_type;
	u8 cmx_parse_hack;
	u8 cmv_parse_hack;
	u8 in_movi;
	int in_movi_level;
	de_ucstring *INAM_data;
} lctx;

static void do_extract_raw(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len, const char *ext,
	de_finfo *fi, unsigned int createflags)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, ext, fi, createflags);
}

static void do_INFO_item(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len, u32 chunk_id)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	// TODO: Decode the chunk_id (e.g. ICRD = Creation date).

	// TODO: Support the CSET chunk
	dbuf_read_to_ucstring_n(ictx->f, pos, len, 500, s,
		DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));

	if(chunk_id==CHUNK_INAM) { // Save for possible later use
		if(d->INAM_data) {
			ucstring_empty(d->INAM_data);
		}
		else {
			d->INAM_data = ucstring_create(c);
		}
		if(s->len>64) {
			ucstring_truncate(s, 64);
		}
		ucstring_append_ucstring(d->INAM_data, s);
	}

	ucstring_destroy(s);
}

static void extract_ani_frame(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	u8 buf[4];
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

static void decode_WAVEFORMATEX(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	unsigned int formattag;
	i64 n;
	i64 pos = pos1;

	if(!ictx->is_le) goto done;
	if(len<14) goto done;

	formattag = (unsigned int)dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "FormatTag: 0x%04x (%s)", formattag, get_wav_fmt_name(formattag));
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "Channels: %u", (unsigned int)n);
	n = dbuf_getu32le_p(ictx->f, &pos);
	de_dbg(c, "SamplesPerSec: %u", (unsigned int)n);
	n = dbuf_getu32le_p(ictx->f, &pos);
	de_dbg(c, "AvgBytesPerSec: %u", (unsigned int)n);
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "BlockAlign: %u", (unsigned int)n);
	if(len<16) goto done;
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "BitsPerSample: %u", (unsigned int)n);
	if(len<18) goto done;
	n = dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "cbSize: %u", (unsigned int)n);

done:
	;
}

static void do_wav_fmt(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	decode_WAVEFORMATEX(c, d, ictx, pos, len);
}

static void do_wav_fact(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	i64 n;

	if(!ictx->is_le) return;
	if(len<4) return;
	n = de_getu32le(pos);
	de_dbg(c, "number of samples: %u", (unsigned int)n);
}

static void do_avi_avih(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	i64 n, n2;

	if(len<40) return;
	n = de_getu32le(pos);
	de_dbg(c, "microseconds/frame: %u", (unsigned int)n);
	n = de_getu32le(pos+12);
	de_dbg(c, "flags: 0x%08x", (unsigned int)n);
	n = de_getu32le(pos+16);
	de_dbg(c, "number of frames: %u", (unsigned int)n);
	n = de_getu32le(pos+24);
	de_dbg(c, "number of streams: %u", (unsigned int)n);
	n = de_getu32le(pos+32);
	n2 = de_getu32le(pos+36);
	de_dbg_dimensions(c, n, n2);
	// TODO: There are more fields in this chunk.
}

static void do_avi_strh(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
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

static void do_avi_strf(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	if(d->curr_avi_stream_type==CODE_vids) {
		struct de_bmpinfo bi;
		// For video streams, this is a BITMAPINFO.
		fmtutil_get_bmpinfo(c, ictx->f, &bi, pos, len,
			DE_BMPINFO_CMPR_IS_4CC | DE_BMPINFO_NOERR);
		// This chunk contains just a bitmap header, so we can't extract a bitmap.
	}
	else if(d->curr_avi_stream_type==CODE_auds) {
		// For audio streams, this is a WAVEFORMATEX.
		decode_WAVEFORMATEX(c, d, ictx, pos, len);
	}
}

static void do_cdr_bmp(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	if(len<20) return;
	// The first 2 bytes are an index, or something. BMP starts at offset 2.
	dbuf_create_file_from_slice(ictx->f, pos+2, len-2, "bmp", NULL, 0);
}

static void do_palette(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	i64 ver;
	i64 n;
	i64 i;
	u8 r,g,b,flags;
	u32 clr;
	char tmps[32];

	if(!ictx->is_le) return;
	ver = de_getu16le(pos);
	de_dbg(c, "version: 0x%04x", (unsigned int)ver);
	pos += 2;
	n = de_getu16le(pos);
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

static void do_DISP_DIB(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	de_module_params *mparams = NULL;

	if(len<12) return;

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "X"; // "auxiliary"
	mparams->in_params.flags = 0x80; // ".preview.bmp"
	de_run_module_by_id_on_slice(c, "dib", mparams, ictx->f, pos, len);
	de_free(c, mparams);
}

static void do_DISP_TEXT(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len1)
{
	i64 foundpos;
	i64 len = len1;

	// Stop at NUL
	if(dbuf_search_byte(ictx->f, 0x00, pos, len1, &foundpos)) {
		len = foundpos - pos;
	}
	de_dbg(c, "text length: %d", (int)len);
	if(len<1) return;

	do_extract_raw(c, d, ictx, pos, len, "disp.txt", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_ICCP(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, "icc", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_EXIF(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	fmtutil_handle_exif(c, pos, len);
}

static void do_XMP(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	dbuf_create_file_from_slice(ictx->f, pos, len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_RDIB_data(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	de_finfo *fi = NULL;

	if(!ictx->chunkctx->parent) goto done;
	if(ictx->chunkctx->parent->user_flags & 0x1) goto done; // Extraction suppressed, or already done
	ictx->chunkctx->parent->user_flags |= 0x1;

	fi = de_finfo_create(c);
	if(ucstring_isnonempty(d->INAM_data)) {
		// In CorelMOVE format, at least, the INAM chunk seems to have a usable
		// name for the RDIB bitmap.
		de_finfo_set_name_from_ucstring(c, fi, d->INAM_data, 0);
		ucstring_empty(d->INAM_data);
	}
	do_extract_raw(c, d, ictx, pos, len, "bmp", fi, 0);
done:
	de_finfo_destroy(c, fi);
}

static void do_RDIB_bmhd(deark *c, lctx *d, struct de_iffctx *ictx)
{
	if(!ictx->chunkctx->parent) return;
	// AFAICT, a 'bmhd' chunk means we're dealing with "extended RDIB", which we
	// don't support. There may still be a 'data' chunk after this, but it will presumably
	// be in a format we can't handle. Set a flag to remember that.
	ictx->chunkctx->parent->user_flags |= 0x1;
}

static void do_DISP(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 len)
{
	unsigned int ty;
	i64 dpos, dlen;

	if(!ictx->is_le) return;
	if(len<4) return;
	ty = (unsigned int)de_getu32le(pos);
	de_dbg(c, "data type: %u (%s)", ty,
		fmtutil_get_windows_cb_data_type_name(ty));

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

static int is_fourcc_at(deark *c, struct de_iffctx *ictx, i64 pos)
{
	u8 b[4];
	size_t i;

	dbuf_read(ictx->f, b, pos, 4);
	for(i=0; i<4; i++) {
		if(b[i]<32 || b[i]>126) return 0;
	}
	return 1;
}

static int do_cmx_parse_hack(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 *plen)
{
	i64 n, n_padded;

	// Some CMX chunks seem to be followed by a non-RIFF segment starting with either
	// 04 00 (4 bytes) or 10 00 (16 bytes). I'm just guessing how to parse them.
	n = dbuf_getu16le(ictx->f, pos);
	if(n>256 || n==0) return 0;

	n_padded = de_pad_to_2(n);
	if(is_fourcc_at(c, ictx, pos + n_padded)) {
		de_dbg(c, "[%d non-RIFF bytes at %"I64_FMT"]", (int)n_padded, pos);
		*plen = n_padded;
		return 1;
	}
	return 0;
}

// CMV files seem to consist of two RIFF chunks, separated by four 0x00 bytes.
// (Maybe some sort of scan-for-the-next-RIFF-chunk logic should happen by
// default, but it's hard to be sure we won't break something.)
static int do_cmv_parse_hack(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos, i64 *plen)
{
	if(ictx->level!=0) return 0;
	if(dbuf_getu32be(ictx->f, pos)!=0) return 0;
	if(dbuf_getu32be(ictx->f, pos+4)!=CHUNK_RIFF) return 0;
	de_dbg(c, "[%d non-RIFF bytes at %"I64_FMT"]", 4, pos);
	*plen = 4;
	return 1;
}

static int my_handle_nonchunk_riff_data_fn(struct de_iffctx *ictx,
	i64 pos, i64 *plen)
{
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;

	if(d->cmx_parse_hack) {
		return do_cmx_parse_hack(c, d, ictx, pos, plen);
	}
	else if(d->cmv_parse_hack) {
		return do_cmv_parse_hack(c, d, ictx, pos, plen);
	}
	return 0;
}

static int my_on_std_container_start_fn(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;
	u32 chunktype = ictx->curr_container_fmt4cc.id;
	u32 formtype = ictx->curr_container_contentstype4cc.id;
	int suppress_decoding = 0;

	if(ictx->level==0 && (chunktype==CHUNK_RIFF || chunktype==CHUNK_RIFX) &&
		d->top_level_chunk_count==0)
	{
		const char *fmtname = NULL;

		switch(formtype) {
		case CODE_ACON: fmtname = "Windows animated cursor"; break;
		case CODE_AVI: fmtname = "AVI"; break;
		case CODE_CDRX: fmtname = "Corel CCX"; break;
		case CODE_CMX1:
			fmtname = "Corel CMX";
			ictx->handle_nonchunk_data_fn = my_handle_nonchunk_riff_data_fn;
			d->cmx_parse_hack = 1;
			break;
		case CODE_cmov:
			fmtname = "CorelMOVE";
			ictx->handle_nonchunk_data_fn = my_handle_nonchunk_riff_data_fn;
			d->cmv_parse_hack = 1;
			break;
		case CODE_WAVE: fmtname = "WAVE"; break;
		case CODE_WEBP: fmtname = "WebP"; break;
		}

		// Special check for CorelDraw formats.
		if(!fmtname && (formtype>>8 == 0x434452U) /* "CDR" */) {
			d->is_cdr = 1;
			fmtname = "CorelDRAW (RIFF-based)";
		}

		if(fmtname) {
			de_declare_fmt(c, fmtname);
		}
	}

	if(d->is_cdr && chunktype==CHUNK_LIST) {
		// 'cmpr' LISTs in CorelDraw files are not correctly formed.
		// Tell the parser not to process them.
		if(formtype==CODE_cmpr) {
			de_dbg(c, "[not decoding CDR cmpr list]");
			suppress_decoding = 1;
			goto done;
		}
	}

	if(chunktype==CHUNK_RIFF || chunktype==CHUNK_RIFX) {
		// TODO: INAM data is probably not scoped entirely correctly.
		if(d->INAM_data) {
			ucstring_empty(d->INAM_data);
		}
	}

	if(ictx->main_contentstype4cc.id==CODE_AVI && chunktype==CHUNK_LIST &&
		formtype==CODE_movi)
	{
		// There are often a huge number of these chunks, and we can't do
		// anything interesting with them, so skip them by default.
		if(c->debug_level<2) {
			de_dbg(c, "[not decoding movi chunks]");
			suppress_decoding = 1;
			goto done;
		}

		if(!d->in_movi) {
			// Keep track of when we are inside a 'movi' container.
			d->in_movi = 1;
			d->in_movi_level = ictx->level;
		}
	}

done:
	if(ictx->level==0) {
		d->top_level_chunk_count++;
	}
	return !suppress_decoding;
}

static int my_on_container_end_fn(struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->curr_container_contentstype4cc.id==CODE_movi &&
		d->in_movi && ictx->level==d->in_movi_level)
	{
		d->in_movi = 0;
	}

	return 1;
}

static int my_preprocess_riff_chunk_fn(struct de_iffctx *ictx)
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

static int my_riff_chunk_handler(struct de_iffctx *ictx)
{
	i64 dpos, dlen;
	u32 list_type;
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;

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
		ictx->handled = 1;
		goto done;
	}

	switch(ictx->chunkctx->chunk4cc.id) {

	case CHUNK_DISP:
		do_DISP(c, d, ictx, dpos, dlen);
		ictx->handled = 1;
		break;

	case CHUNK_ICCP: // Used by WebP
		do_ICCP(c, d, ictx, dpos, dlen);
		ictx->handled = 1;
		break;

	case CHUNK_EXIF: // Used by WebP
		do_EXIF(c, d, ictx, dpos, dlen);
		ictx->handled = 1;
		break;

	case CHUNK_XMP: // Used by WebP
	case CHUNK__PMX: // Used by WAVE, AVI
		do_XMP(c, d, ictx, dpos, dlen);
		ictx->handled = 1;
		break;

	case CHUNK_bmhd:
		if(list_type==CODE_RDIB) {
			do_RDIB_bmhd(c, d, ictx);
			ictx->handled = 1;
		}
		break;

	case CHUNK_icon:
		if(ictx->main_contentstype4cc.id==CODE_ACON) {
			extract_ani_frame(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_data:
		if(list_type==CODE_RMID) {
			do_extract_raw(c, d, ictx, dpos, dlen, "mid", NULL, 0);
			ictx->handled = 1;
		}
		else if(list_type==CODE_PAL) {
			do_palette(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		else if(list_type==CODE_RDIB) {
			do_RDIB_data(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_fmt:
		if(ictx->main_contentstype4cc.id==CODE_WAVE) {
			do_wav_fmt(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_fact:
		if(ictx->main_contentstype4cc.id==CODE_WAVE) {
			do_wav_fact(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_avih:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_avih(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_strh:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_strh(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_strf:
		if(ictx->main_contentstype4cc.id==CODE_AVI) {
			do_avi_strf(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;

	case CHUNK_bmp:
		if(d->is_cdr && ictx->curr_container_contentstype4cc.id==CODE_bmpt) {
			do_cdr_bmp(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
		}
		break;
	}

done:
	return 1;
}

static void de_run_riff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	u8 buf[4];

	d = de_malloc(c, sizeof(lctx));

	ictx = fmtutil_create_iff_decoder(c);
	ictx->userdata = (void*)d;
	ictx->preprocess_chunk_fn = my_preprocess_riff_chunk_fn;
	ictx->handle_chunk_fn = my_riff_chunk_handler;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->on_container_end_fn = my_on_container_end_fn;
	ictx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
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

	fmtutil_read_iff_format(ictx, 0, ictx->f->len);

	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		ucstring_destroy(d->INAM_data);
		de_free(c, d);
	}
}

static int de_identify_riff(deark *c)
{
	u8 buf[4];
	int has_sig;
	i64 dlen;

	de_read(buf, 0, 4);
	has_sig = (!de_memcmp(buf, "RIFF", 4)) ||
		(!de_memcmp(buf, "XFIR", 4)) ||
		(!de_memcmp(buf, "RIFX", 4));
	if(!has_sig) return 0;

	dlen = de_getu32le(4);
	// This check screens out .AMV format, for example.
	if(dlen==0 && c->infile->len!=8) return 0;

	return 50;
}

void de_module_riff(deark *c, struct deark_module_info *mi)
{
	mi->id = "riff";
	mi->desc = "RIFF-based formats";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_riff;
}

// **************************************************************************
// RIFF Multimedia Movie / RMMP / .MMM
// **************************************************************************
// TODO: Maybe move this to its own file.

#define CODE_RMMP  0x524d4d50U
#define CODE_DIB   0x44494220U
#define CODE_dib   0x64696220U
#define CODE_CLUT  0x434c5554U
#define CODE_clut  0x636c7574U
#define CODE_Ver_  0x5665722eU // "Ver."
#define CODE_ver   0x76657220U // "ver "

struct mmm_ctx {
	u8 errflag;
	u8 opt_allowbad;
	int clut_count;
	int dib_count;
	int pass;
	u8 have_pal;
	de_ucstring *tmpstr;
	de_color pal1[2];
	de_color pal[256];
};

static void mmm_default_pal256(deark *c, struct mmm_ctx *d)
{
	UI i, j, k;
	static const u8 v[6] = {0, 48, 100, 152, 204, 252};

	de_warn(c, "Using a default color table. Colors might be wrong.");

	// Note: This sets pal[40], but it will be corrected later.
	for(i=0; i<6; i++) {
		for(j=0; j<6; j++) {
			for(k=0; k<6; k++) {
				d->pal[40 + i*36 + j*6 + k] = DE_MAKE_RGB(v[i], v[j], v[k]);
			}
		}
	}

	for(i=0; i<=10; i++) {
		d->pal[i] = DE_MAKE_GRAY(i*24);
	}

	for(i=0; i<10; i++) {
		UI t;

		t = 16+24*i;
		if(t>=128) t += 4;
		d->pal[11+i] = DE_MAKE_RGB(0, 0, t);
		d->pal[21+i] = DE_MAKE_RGB(0, t, 0);
		d->pal[31+i] = DE_MAKE_RGB(t, 0, 0);
	}

	d->have_pal = 1;
}

static void mmm_allowbad_note(deark *c)
{
	de_info(c, "Note: Use \"-opt mmm:allowbad\" to extract anyway.");
}


static void mmm_default_pal16(deark *c, struct mmm_ctx *d)
{
	de_make_grayscale_palette(d->pal, 16, 0);
	d->have_pal = 1;

	// TODO: Figure out if there is a default 16-color palette.
	if(d->opt_allowbad) {
		de_warn(c, "No color table found. Colors will be wrong.");
	}
	else {
		de_err(c, "No color table found");
		mmm_allowbad_note(c);
		d->errflag = 1;
	}
}

static void mmm_read_name_p(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 *ppos)
{
	i64 pos = *ppos;
	i64 namelen;

	namelen = (i64)dbuf_getbyte(ictx->f, pos);
	if(namelen) {
		ucstring_empty(d->tmpstr);
		dbuf_read_to_ucstring(ictx->f, pos+1, namelen, d->tmpstr, 0, DE_ENCODING_ASCII);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	}
	*ppos += de_pad_to_2(1+namelen);
}

static void hexdump_chunk(deark *c, struct de_iffctx *ictx, const char *name, UI flags)
{
	de_dbg_hexdump(c, ictx->f, ictx->chunkctx->dpos, ictx->chunkctx->dlen,
		256, name, flags);
}

static void do_mmm_dib(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	i64 pos;
	i64 i_infohdr_pos;
	i64 i_bits_pos;
	i64 infosize;
	i64 i_bits_size;
	i64 o_bits_size;
	i64 i_rowspan;
	i64 k;
	i64 j;
	u8 special_1bpp = 0;
	int ret;
	dbuf *outf = NULL;
	struct de_bmpinfo bi;

	de_dbg_hexdump(c, ictx->f, pos1, 4, 4, "dibdata", 0);
	pos = pos1 + 4;
	mmm_read_name_p(c, d, ictx, &pos);
	i_infohdr_pos = pos;

	infosize = dbuf_getu32le(ictx->f, i_infohdr_pos);
	if(infosize<40 || infosize>124) goto done;
	i_bits_pos = i_infohdr_pos + infosize;
	i_bits_size = pos+len-i_bits_pos;

	ret = fmtutil_get_bmpinfo(c, ictx->f, &bi, i_infohdr_pos, infosize, 0);
	if(!ret) goto done;
	if(bi.num_colors > 256) goto done;

	if(bi.bitcount==1) {
		special_1bpp = 1;
	}

	if(special_1bpp) {
		i_rowspan = de_pad_to_n(bi.bitcount*bi.width, 16) / 8;
	}
	else {
		i_rowspan = bi.rowspan;
	}

	if(bi.compression_field==0) {
		o_bits_size = bi.foreground_size;
	}
	else {
		o_bits_size = i_bits_size;
	}

	// color table
	if(bi.bitcount==4 && !d->have_pal) {
		mmm_default_pal16(c, d);
	}
	if(bi.bitcount==8 && !d->have_pal) {
		mmm_default_pal256(c, d);
	}
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// file header
	fmtutil_generate_bmpfileheader(c, outf, &bi,
		14 + infosize + bi.num_colors*4 + o_bits_size);

	// info header
	dbuf_copy(ictx->f, i_infohdr_pos, 20, outf);
	if(special_1bpp) {
		// She biSizeImage field may be wrong, so zero it out.
		dbuf_write_zeroes(outf, 4);
	}
	else {
		dbuf_copy(ictx->f, i_infohdr_pos+20, 4, outf);
	}
	dbuf_copy(ictx->f, i_infohdr_pos+24, infosize-24, outf);

	// color table

	if(bi.bitcount==1) {
		for(k=0; k<2; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal1[k]));
			dbuf_writebyte(outf, 0);
		}
	}
	else if(bi.bitcount<=8) {
		if(bi.num_colors>256) goto done;
		for(k=0; k<bi.num_colors; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal[k]));
			dbuf_writebyte(outf, 0);
		}
	}

	// bits
	if(special_1bpp) {
		for(j=0; j<bi.height; j++) {
			dbuf_copy(ictx->f, i_bits_pos+(bi.height-1-j)*i_rowspan, bi.rowspan, outf);
		}
	}
	else {
		dbuf_copy(ictx->f, i_bits_pos, i_bits_size, outf);
	}

done:
	dbuf_close(outf);
}

static void do_mmm_clut(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 pos1, i64 len)
{
	i64 pos;
	i64 num_entries;
	i64 i;

	de_dbg_hexdump(c, ictx->f, pos1, 4, 4, "clutdata", 0);
	pos = pos1+4;
	mmm_read_name_p(c, d, ictx, &pos);

	num_entries = (pos1+len-pos)/6;

	de_dbg(c, "color table at %"I64_FMT", %u entries", pos, (UI)num_entries);

	if(num_entries!=16 && num_entries!=256) {
		de_warn(c, "Unsupported type of color table");
		goto done;
	}

	// TODO: This probably won't work. We should index the clut chunks, and read
	// them later.
	de_dbg_indent(c, 1);
	for(i=0; i<num_entries; i++) {
		UI samp[3];
		de_color clr;
		i64 idx;
		UI k;

		idx = num_entries-1-i;

		for(k=0; k<3; k++) {
			samp[k] = (UI)dbuf_getu16be_p(ictx->f, &pos);
			samp[k] = (UI)de_sample_nbit_to_8bit(16, samp[k]);
		}
		clr = DE_MAKE_RGB(samp[0], samp[1], samp[2]);
		de_dbg_pal_entry(c, idx, clr);

		if(d->clut_count==0) {
			d->pal[idx] = clr;
		}
	}
	de_dbg_indent(c, -1);
	d->have_pal = 1;

done:
	d->clut_count++;
}

static int my_mmm_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct mmm_ctx *d = (struct mmm_ctx*)ictx->userdata;
	i64 dpos, dlen;

	dpos = ictx->chunkctx->dpos;
	dlen = ictx->chunkctx->dlen;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CHUNK_RIFF:
		ictx->is_std_container = 1;
		goto done;
	}

	if(ictx->level != 1) goto done;

	if(d->pass==1) {
		switch(ictx->chunkctx->chunk4cc.id) {
		case CODE_Ver_:
		case CODE_ver:
			hexdump_chunk(c, ictx, "verdata", 0);
			break;
		case CODE_CLUT:
		case CODE_clut:
			do_mmm_clut(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
			break;
		case CODE_DIB:
		case CODE_dib:
			d->dib_count++;
			break;
		}
	}

	if(d->pass==2) {
		switch(ictx->chunkctx->chunk4cc.id) {
		case CODE_DIB:
		case CODE_dib:
			do_mmm_dib(c, d, ictx, dpos, dlen);
			ictx->handled = 1;
			break;
		}
	}

done:
	if(d->errflag) return 0;
	return 1;
}

static int my_mmm_handle_nonchunk_data_fn(struct de_iffctx *ictx,
		i64 pos, i64 *plen)
{
	u8 x;

	x = dbuf_getbyte(ictx->f, pos);
	if(x==0) {
		*plen = 2;
		de_dbg(ictx->c, "[%"I64_FMT" non-RIFF bytes at %"I64_FMT"]", *plen, pos);
		return 1;
	}

	return 0;
}

static void de_run_mmm(deark *c, de_module_params *mparams)
{
	struct mmm_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct mmm_ctx));
	d->opt_allowbad = (u8)de_get_ext_option_bool(c, "mmm:allowbad", 0);
	d->tmpstr = ucstring_create(c);

	ictx = fmtutil_create_iff_decoder(c);
	ictx->userdata = (void*)d;
	ictx->is_le = 1;
	ictx->handle_chunk_fn = my_mmm_chunk_handler;
	ictx->handle_nonchunk_data_fn = my_mmm_handle_nonchunk_data_fn;
	ictx->f = c->infile;

	d->pal1[0] = DE_STOCKCOLOR_BLACK;
	d->pal1[1] = DE_STOCKCOLOR_WHITE;

	d->pass = 1;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);
	if(d->errflag) goto done;

	if(d->clut_count>1 && d->dib_count>0 && !d->opt_allowbad) {
		de_warn(c, "Multiple color tables found (not supported).");
		mmm_allowbad_note(c);
		goto done;
	}

	d->pass = 2;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);

done:
	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		de_dbg2(c, "dib count: %d", d->dib_count);
		de_dbg2(c, "clut count: %d", d->clut_count);
		ucstring_destroy(d->tmpstr);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_mmm(deark *c)
{
	if((u32)de_getu32be(0)!=CHUNK_RIFF) return 0;
	if((u32)de_getu32be(8)!=CODE_RMMP) return 0;
	return 100;
}

void de_module_mmm(deark *c, struct deark_module_info *mi)
{
	mi->id = "mmm";
	mi->desc = "RIFF Multimedia Movie";
	mi->run_fn = de_run_mmm;
	mi->identify_fn = de_identify_mmm;
	// Status: Many images work correctly. Others have the wrong colors.
	// Improvements are probably possible, but only up to a point. This
	// is just a resource format; the correct color table might, for
	// example, be in a different file.
	mi->flags |= DE_MODFLAG_NONWORKING;
}
