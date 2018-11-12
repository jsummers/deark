// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// MP3, and other MPEG audio

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mpegaudio);

typedef struct mp3ctx_struct {
	// Settings are for the current frame.
	unsigned int version_id, layer_desc, has_crc;
	unsigned int bitrate_idx, samprate_idx;
	unsigned int has_padding, channel_mode;
	unsigned int mode_extension;
	unsigned int copyright_flag, orig_media_flag;
	unsigned int emphasis;
	int frame_count;
} mp3ctx;

struct ape_tag_header_footer {
	de_uint32 ape_ver, ape_flags;
	de_int64 tag_size_raw, item_count;
	de_int64 tag_startpos;
	de_int64 tag_size_total;
	de_int64 items_startpos;
	de_int64 items_size;
	int has_header;
};

static const char *get_ape_item_type_name(unsigned int t)
{
	const char *name;

	switch(t) {
	case 0: name = "UTF-8 text"; break;
	case 1: name = "binary"; break;
	case 2: name = "locator"; break;
	default: name = "?";
	}
	return name;
}

static void do_ape_text_item(deark *c, struct ape_tag_header_footer *ah,
   de_int64 pos, de_int64 len)
{
	int encoding;
	de_ucstring *s = NULL;

	encoding = (ah->ape_ver>=2000)?DE_ENCODING_UTF8:DE_ENCODING_ASCII;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN,
		s, 0, encoding);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);
}

static int do_ape_item(deark *c, struct ape_tag_header_footer *ah,
   de_int64 pos1, de_int64 bytes_avail, de_int64 *bytes_consumed)
{
	de_int64 item_value_len;
	de_int64 pos = pos1;
	de_uint32 flags;
	unsigned int item_type;
	struct de_stringreaderdata *key = NULL;
	int retval = 0;

	de_dbg(c, "APE item at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);

	item_value_len = de_getui32le(pos);
	pos += 4;

	flags = (de_uint32)de_getui32le(pos);
	de_dbg(c, "flags: 0x%08x", (unsigned int)flags);
	if(ah->ape_ver>=2000) {
		de_dbg_indent(c, 1);
		item_type = (flags&0x00000006)>>1;
		de_dbg(c, "type: %u (%s)", item_type, get_ape_item_type_name(item_type));
		de_dbg_indent(c, -1);
	}
	else {
		item_type = 0;
	}
	pos += 4;

	key = dbuf_read_string(c->infile, pos, 256, 256, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	if(!key->found_nul) goto done;
	de_dbg(c, "key: \"%s\"", ucstring_getpsz(key->str));
	pos += key->bytes_consumed;

	de_dbg(c, "item data at %"INT64_FMT", len=%"INT64_FMT, pos, item_value_len);
	de_dbg_indent(c, 1);
	if(item_type==0 || item_type==2) {
		do_ape_text_item(c, ah, pos, item_value_len);
	}
	else if(c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, pos, item_value_len, 256, NULL, 0x1);
	}
	de_dbg_indent(c, -1);

	pos += item_value_len;
	*bytes_consumed = pos - pos1;
	retval = 1;

done:
	de_dbg_indent(c, -1);
	de_destroy_stringreaderdata(c, key);
	return retval;
}
static void do_ape_item_list(deark *c, struct ape_tag_header_footer *ah,
	de_int64 pos1, de_int64 len)
{
	de_int64 pos = pos1;

	de_dbg(c, "APE items at %"INT64_FMT", len=%"INT64_FMT, pos1, len);
	de_dbg_indent(c, 1);
	while(1) {
		de_int64 bytes_consumed = 0;

		if(pos >= pos1+len) break;
		if(!do_ape_item(c, ah, pos, pos1+len-pos, &bytes_consumed)) {
			goto done;
		}
		if(bytes_consumed<1) goto done;

		pos += bytes_consumed;
	}
done:
	de_dbg_indent(c, -1);
}

static int do_ape_tag_header_or_footer(deark *c, struct ape_tag_header_footer *ah,
	de_int64 pos1, int is_footer)
{
	int retval = 0;

	ah->ape_ver = (de_uint32)de_getui32le(pos1+8);
	de_dbg(c, "version: %u", (unsigned int)ah->ape_ver);
	ah->tag_size_raw = de_getui32le(pos1+12);
	de_dbg(c, "tag size: %d", (int)ah->tag_size_raw);
	if(is_footer) {
		ah->items_startpos = pos1 + 32 - ah->tag_size_raw;
		ah->items_size = pos1 - ah->items_startpos;
	}
	ah->item_count = de_getui32le(pos1+16);
	de_dbg(c, "item count: %d", (int)ah->item_count);
	ah->ape_flags = (de_uint32)de_getui32le(pos1+20);
	de_dbg(c, "flags: 0x%08x", (unsigned int)ah->ape_flags);
	if(ah->ape_ver>=2000) {
		ah->has_header = (ah->ape_flags&0x80000000U) ? 1 : 0;
	}

	ah->tag_size_total = ah->tag_size_raw;
	if(ah->has_header)
		ah->tag_size_total += 32;

	if(ah->ape_ver<1000 || ah->ape_ver>=3000) {
		de_warn(c, "Unrecognized APE tag version: %u", (unsigned int)ah->ape_ver);
		goto done;
	}

	if(is_footer) {
		ah->tag_startpos = pos1 + 32 - ah->tag_size_total;
		de_dbg(c, "calculated start of APE tag: %"INT64_FMT, ah->tag_startpos);
	}
	retval = 1;
done:
	return retval;
}

static int do_ape_tag(deark *c, de_int64 endpos, de_int64 *ape_tag_bytes_consumed)
{
	struct ape_tag_header_footer *af = NULL;
	int saved_indent_level;
	int retval = 0;

	de_int64 footer_startpos;

	de_dbg_indent_save(c, &saved_indent_level);
	*ape_tag_bytes_consumed = 0;

	footer_startpos = endpos-32;
	if(dbuf_memcmp(c->infile, footer_startpos, "APETAGEX", 8))
		goto done;

	af = de_malloc(c, sizeof(struct ape_tag_header_footer));

	de_dbg(c, "APE tag found, ending at %"INT64_FMT, endpos);

	de_dbg_indent(c, 1);
	if(!do_ape_tag_header_or_footer(c, af, footer_startpos, 1)) goto done;
	*ape_tag_bytes_consumed = af->tag_size_total;

	do_ape_item_list(c, af, af->items_startpos, af->tag_size_raw - 32);

	de_dbg_indent(c, -1);
	retval = 1;

done:
	de_free(c, af);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static const char *get_mp3_ver_id_name(unsigned int n)
{
	const char *name;
	switch(n) {
	case 0: name = "MPEG v2.5"; break;
	case 2: name = "MPEG v2"; break;
	case 3: name = "MPEG v1"; break;
	default: name = "?";
	}
	return name;
}

static const char *get_mp3_layer_desc_name(unsigned int n)
{
	const char *name;
	switch(n) {
	case 1: name = "Layer III"; break;
	case 2: name = "Layer II"; break;
	case 3: name = "Layer I"; break;
	default: name = "?";
	}
	return name;
}

static const char *get_mp3_channel_mode_name(unsigned int n)
{
	const char *name;
	switch(n) {
	case 0: name = "Stereo"; break;
	case 1: name = "Joint stereo"; break;
	case 2: name = "Dual channel"; break;
	case 3: name = "Single channel"; break;
	default: name = "?";
	}
	return name;
}

// Returns a copy of the buf ptr
static char *get_bitrate_name(char *buf, size_t buflen,
	unsigned int bitrate_idx, unsigned int version_id, unsigned int layer_desc)
{
	static const de_uint16 tbl[5][16] = {
		{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
		{0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
		{0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 0},
		{0, 32, 48, 56,  64,  80,  96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
		{0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160, 0}};
	unsigned int tbl_to_use = 0;
	unsigned int br = 0;

	if(version_id==0x03) { // v1
		if(layer_desc==0x03) tbl_to_use=0; // Layer 1
		else if(layer_desc==0x02) tbl_to_use=1; // Layer 2
		else if(layer_desc==0x01) tbl_to_use=2; // Layer 3
		else goto done;
	}
	else if(version_id==0x02 || version_id==0x00) { // v2, v2.5
		if(layer_desc==0x03) tbl_to_use=3; // Layer 1
		else if(layer_desc==0x02 || layer_desc==0x01) tbl_to_use=4; // Layer 2,3
		else goto done;
	}
	else {
		goto done;
	}

	if(bitrate_idx>15) goto done;
	br = (unsigned int)tbl[tbl_to_use][bitrate_idx];

done:
	if(br>0)
		de_snprintf(buf, buflen, "%u kbps", br);
	else
		de_strlcpy(buf, "?", buflen);
	return buf;
}

static char *get_sampling_rate_name(char *buf, size_t buflen,
	unsigned int sr_idx, unsigned int version_id, unsigned int layer_desc)
{
	static const de_uint32 tbl[3][4] = {
		{44100, 48000, 32000, 0},
		{22050, 24000, 16000, 0},
		{11025, 12000,  8000, 0}};
	unsigned int tbl_to_use = 0;
	unsigned int sr = 0;

	if(layer_desc<1 || layer_desc>3) goto done;

	if(version_id==0x03) { // v1
		tbl_to_use = 0;
	}
	else if(version_id==0x02) { // v2
		tbl_to_use = 1;
	}
	else if(version_id==0x00) { // v2.5
		tbl_to_use = 2;
	}
	else {
		goto done;
	}

	if(sr_idx>3) goto done;
	sr = (unsigned int)tbl[tbl_to_use][sr_idx];

done:
	if(sr>0)
		de_snprintf(buf, buflen, "%u Hz", sr);
	else
		de_strlcpy(buf, "?", buflen);
	return buf;
}

static int find_mp3_frame_header(deark *c, mp3ctx *d, de_int64 pos1, de_int64 nbytes_avail,
	de_int64 *skip_this_many_bytes)
{
	de_byte *buf = NULL;
	de_int64 nbytes_in_buf;
	de_int64 bpos = 0;
	int retval = 0;

	*skip_this_many_bytes = 0;
	nbytes_in_buf = 65536;
	if(nbytes_avail < nbytes_in_buf) nbytes_in_buf = nbytes_avail;
	buf = de_malloc(c, nbytes_in_buf);
	de_read(buf, pos1, nbytes_in_buf);
	for(bpos=0; bpos<nbytes_in_buf-1; bpos++) {
		if(buf[bpos]==0xff) {
			if((buf[bpos+1]&0xe0) == 0xe0) {
				*skip_this_many_bytes = bpos;
				retval = 1;
				goto done;
			}
		}
	}

done:
	de_free(c, buf);
	return retval;
}

static void do_mp3_frame(deark *c, mp3ctx *d, de_int64 pos1, de_int64 len)
{
	de_uint32 x;
	de_int64 pos = pos1;
	int saved_indent_level;
	char buf[32];

	de_dbg_indent_save(c, &saved_indent_level);
	x = (de_uint32)de_getui32be(pos);
	if((x & 0xffe00000U) != 0xffe00000U) {
		int ret;
		de_int64 num_bytes_to_skip = 0;
		de_msg(c, "Note: MP3/MPA frame header not found at %"INT64_FMT". Scanning for frame header.", pos);
		ret = find_mp3_frame_header(c, d, pos1, len, &num_bytes_to_skip);
		if(!ret) {
			de_err(c, "MP3/MPA frame header not found");
			goto done;
		}
		pos += num_bytes_to_skip;
		de_msg(c, "Note: Possible MP3 frame header found at %"INT64_FMT".", pos);
		x = (de_uint32)de_getui32be(pos);
	}

	de_dbg(c, "frame at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "frame header: 0x%08x", (unsigned int)x);
	de_dbg_indent(c, 1);
	d->version_id = (x&0x00180000U)>>19;
	de_dbg(c, "audio version id: %u (%s)", d->version_id, get_mp3_ver_id_name(d->version_id));
	d->layer_desc = (x&0x00060000U)>>17;
	de_dbg(c, "layer description: %u (%s)", d->layer_desc, get_mp3_layer_desc_name(d->layer_desc));
	if(d->frame_count==0) {
		if(d->layer_desc==1) {
			de_declare_fmt(c, "MP3");
		}
		else if(d->layer_desc==2) {
			de_declare_fmt(c, "MP2 audio");
		}
		else if(d->layer_desc==3) {
			de_declare_fmt(c, "MP1 audio");
		}
	}
	d->has_crc = (x&0x00010000U)>>16;
	de_dbg(c, "has crc: %u", d->has_crc);
	d->bitrate_idx =  (x&0x0000f000U)>>12;
	de_dbg(c, "bitrate id: %u (%s)", d->bitrate_idx,
		get_bitrate_name(buf, sizeof(buf), d->bitrate_idx, d->version_id, d->layer_desc));
	d->samprate_idx = (x&0x00000c00U)>>10;
	de_dbg(c, "sampling rate frequency id: %u (%s)", d->samprate_idx,
		get_sampling_rate_name(buf, sizeof(buf), d->samprate_idx, d->version_id, d->layer_desc));
	d->has_padding =  (x&0x00000200U)>>9;
	de_dbg(c, "has padding: %u", d->has_padding);
	d->channel_mode = (x&0x000000c0U)>>6;
	de_dbg(c, "channel mode: %u (%s)", d->channel_mode, get_mp3_channel_mode_name(d->channel_mode));
	if(d->channel_mode==1) {
		d->mode_extension = (x&0x00000030U)>>4;
		de_dbg(c, "mode extension: %u", d->mode_extension);
	}
	d->copyright_flag = (x&0x00000008U)>>3;
	de_dbg(c, "copyright flag: %u", d->has_padding);
	d->orig_media_flag = (x&0x00000004U)>>2;
	de_dbg(c, "original media flag: %u", d->has_padding);
	d->emphasis = (x&0x00000003U);
	de_dbg(c, "emphasis: %u", d->emphasis);
	pos += 4;
	d->frame_count++;

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_mp3_data(deark *c, mp3ctx *d, de_int64 pos1, de_int64 len)
{

	de_dbg(c, "MP3/MPA data at %"INT64_FMT", len=%"INT64_FMT, pos1, len);
	de_dbg_indent(c, 1);
	do_mp3_frame(c, d, pos1, len);
	// TODO: There are probably many frames. Should we look for more frames
	// (in some cases?)?
	de_dbg_indent(c, -1);
}

static void de_run_mpegaudio(deark *c, de_module_params *mparams)
{
	mp3ctx *d = NULL;
	de_int64 pos;
	de_int64 endpos;
	de_int64 ape_tag_len;
	struct de_id3info id3i;

	d = de_malloc(c, sizeof(mp3ctx));
	pos = 0;
	endpos = c->infile->len;

	de_fmtutil_handle_id3(c, c->infile, &id3i, 0);
	pos = id3i.main_start;
	endpos = id3i.main_end;

	if(!id3i.has_id3v2) {
		if(!dbuf_memcmp(c->infile, endpos-10, "3DI", 3)) {
			de_warn(c, "Possible ID3v2 tag found at end of file (footer at %"INT64_FMT"). "
				"This is not supported.", endpos-10);
		}
	}

	do_ape_tag(c, endpos, &ape_tag_len);
	endpos -= ape_tag_len;

	do_mp3_data(c, d, pos, endpos-pos);

	de_free(c, d);
}

static int de_identify_mpegaudio(deark *c)
{
	unsigned int x;
	unsigned int ver_id, lyr_id;
	int has_mp1_ext = 0;
	int has_mp2_ext = 0;
	int has_mp3_ext = 0;
	int has_any_ext;
	int looks_valid = 0;
	de_byte has_id3v2;
	de_int64 pos;

	if(!c->detection_data.id3.detection_attempted) {
		de_err(c, "mp3 internal");
		de_fatalerror(c);
	}


	if(de_input_file_has_ext(c, "mp3")) {
		has_mp3_ext = 1;
	}
	if(de_input_file_has_ext(c, "mp2")) {
		has_mp2_ext = 1;
	}
	if(de_input_file_has_ext(c, "mp1")) {
		has_mp1_ext = 1;
	}
	else if(de_input_file_has_ext(c, "mpa")) {
		has_mp1_ext = 1;
		has_mp2_ext = 1;
		has_mp3_ext = 1;
	}
	has_any_ext = has_mp3_ext || has_mp2_ext || has_mp1_ext;

	has_id3v2 = c->detection_data.id3.has_id3v2;

	if(!has_id3v2 && !has_any_ext) {
		// TODO: We could try harder to identify MP3.
		return 0;
	}

	if(has_id3v2) {
		pos = (de_int64)c->detection_data.id3.bytes_at_start;
	}
	else {
		pos = 0;
	}

	x = (unsigned int)de_getui16be(pos);
	if((x&0xffe0) == 0xffe0) {
		ver_id = (x&0x0018)>>3;
		lyr_id = (x&0x0006)>>1;

		if(has_mp3_ext) {
			if((lyr_id==1) && (ver_id!=1)) looks_valid = 1;
		}
		if(has_mp2_ext) {
			if((lyr_id==2) && (ver_id==2 || ver_id==3)) looks_valid = 1;
		}
		if(has_mp1_ext) {
			if((lyr_id==3) && (ver_id==2 || ver_id==3)) looks_valid = 1;
		}
	}

	if(has_id3v2 && looks_valid) return 100;
	if(has_id3v2 && !looks_valid) {
		// This must be lower than the corresponding confidence for other
		// audio formats that might start with ID3v2, like Ogg.
		return 80;
	}
	if(looks_valid) {
		return 100;
	}

	return 0;
}

void de_module_mpegaudio(deark *c, struct deark_module_info *mi)
{
	mi->id = "mpegaudio";
	mi->id_alias[0] = "mp3";
	mi->desc = "MP3 / MPEG audio";
	mi->run_fn = de_run_mpegaudio;
	mi->identify_fn = de_identify_mpegaudio;
}
