// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// MP3, and other MPEG audio
// APE tag
// Monkey's Audio (.ape)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mpegaudio);
DE_DECLARE_MODULE(de_module_apetag);
DE_DECLARE_MODULE(de_module_monkeys_audio);

typedef struct mp3ctx_struct {
	int has_id3v2;
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
	u32 ape_ver, ape_flags;
	i64 tag_size_raw, item_count;
	i64 tag_startpos;
	i64 tag_size_total;
	i64 items_startpos;
	i64 items_size;
	int has_header;
};

static int is_apetag_sig_at(dbuf *f, i64 pos)
{
	return !dbuf_memcmp(f, pos, "APETAGEX", 8);
}

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
   i64 pos, i64 len)
{
	de_encoding encoding;
	de_ucstring *s = NULL;

	encoding = (ah->ape_ver>=2000)?DE_ENCODING_UTF8:DE_ENCODING_ASCII;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN,
		s, 0, encoding);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);
}

static int do_ape_binary_item(deark *c, struct ape_tag_header_footer *ah,
   i64 pos, i64 len, struct de_stringreaderdata *key)
{
	struct de_stringreaderdata *name = NULL;
	i64 nbytes_to_scan;
	i64 img_pos, img_len;
	de_finfo *fi = NULL;
	char *ext = NULL;
	int retval = 0;

	if(de_strncasecmp(key->sz, "cover art", 9)) {
		goto done;
	}

	nbytes_to_scan = len;
	if(nbytes_to_scan>256) nbytes_to_scan=256;
	name = dbuf_read_string(c->infile, pos, nbytes_to_scan, nbytes_to_scan,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	if(!name->found_nul) goto done;

	img_pos = pos + name->bytes_consumed;
	img_len = len - name->bytes_consumed;
	if(len < 16) goto done;

	fi = de_finfo_create(c);
	if(c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, name->str, 0);
	}
	else {
		u8 sig[2];

		de_finfo_set_name_from_sz(c, fi, "cover_art", 0, DE_ENCODING_LATIN1);

		de_read(sig, img_pos, 2);
		if(sig[0]==0x89 && sig[1]==0x50) ext="png";
		else if(sig[0]==0xff && sig[1]==0xd8) ext="jpg";
		else ext="bin";
	}
	dbuf_create_file_from_slice(c->infile, img_pos, img_len, ext,
		fi, DE_CREATEFLAG_IS_AUX);
	retval = 1;

done:
	de_finfo_destroy(c, fi);
	de_destroy_stringreaderdata(c, name);
	return retval;
}

static int do_ape_item(deark *c, struct ape_tag_header_footer *ah,
   i64 pos1, i64 bytes_avail, i64 *bytes_consumed)
{
	i64 item_value_len;
	i64 pos = pos1;
	u32 flags;
	unsigned int item_type;
	struct de_stringreaderdata *key = NULL;
	int handled = 0;
	int retval = 0;

	de_dbg(c, "APE item at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	item_value_len = de_getu32le(pos);
	pos += 4;

	flags = (u32)de_getu32le(pos);
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

	de_dbg(c, "item data at %"I64_FMT", len=%"I64_FMT, pos, item_value_len);
	de_dbg_indent(c, 1);
	if(item_type==0 || item_type==2) {
		do_ape_text_item(c, ah, pos, item_value_len);
		handled = 1;
	}
	else if(item_type==1) { // binary
		handled = do_ape_binary_item(c, ah, pos, item_value_len, key);
	}

	if(!handled && c->debug_level>=2) {
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
	i64 pos1, i64 len)
{
	i64 pos = pos1;

	de_dbg(c, "APE items at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);
	while(1) {
		i64 bytes_consumed = 0;

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
	i64 pos1, int is_footer)
{
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "APE tag %s at %"I64_FMT, (is_footer?"footer":"header"), pos1);
	de_dbg_indent(c, 1);

	ah->ape_ver = (u32)de_getu32le(pos1+8);
	de_dbg(c, "version: %u", (unsigned int)ah->ape_ver);
	ah->tag_size_raw = de_getu32le(pos1+12);
	de_dbg(c, "tag size: %d", (int)ah->tag_size_raw);
	if(is_footer) {
		ah->items_startpos = pos1 + 32 - ah->tag_size_raw;
		ah->items_size = pos1 - ah->items_startpos;
	}
	ah->item_count = de_getu32le(pos1+16);
	de_dbg(c, "item count: %d", (int)ah->item_count);
	ah->ape_flags = (u32)de_getu32le(pos1+20);
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
		de_dbg(c, "calculated start of APE tag: %"I64_FMT, ah->tag_startpos);
	}
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_ape_tag_internal(deark *c, i64 endpos, i64 *ape_tag_bytes_consumed)
{
	struct ape_tag_header_footer *af = NULL;
	i64 footer_startpos = endpos - 32;
	int retval = 0;

	if(!is_apetag_sig_at(c->infile, footer_startpos)) {
		de_warn(c, "Expected APE tag footer not found at %"I64_FMT, footer_startpos);
		goto done;
	}
	af = de_malloc(c, sizeof(struct ape_tag_header_footer));
	if(!do_ape_tag_header_or_footer(c, af, footer_startpos, 1)) goto done;
	*ape_tag_bytes_consumed = af->tag_size_total;

	do_ape_item_list(c, af, af->items_startpos, af->tag_size_raw - 32);

	retval = 1;
done:
	de_free(c, af);
	return retval;
}

static void de_run_apetag(deark *c, de_module_params *mparams)
{
	i64 endpos;
	i64 bytes_consumed = 0;

	// The calling module should provide a slice that starts at the beginning
	// of the file, and ends at the end of the APE tag (which is often, but
	// not always, the end of the file).
	// This does not very flexible, but it can be improved if need be.

	// If we successfully process an APE tag, we set the
	// 0x1 bit of mparams->out_params.flags, and set
	// mparams->out_params.int64_1 to the total size of the APE tag.

	endpos = c->infile->len;

	if(!do_ape_tag_internal(c, endpos, &bytes_consumed)) goto done;
	if(mparams) {
		mparams->out_params.flags = 0x1;
		mparams->out_params.int64_1 = bytes_consumed;
	}
done:
	;
}

void de_module_apetag(deark *c, struct deark_module_info *mi)
{
	mi->id = "apetag";
	mi->desc = "APE tag";
	mi->run_fn = de_run_apetag;
	mi->identify_fn = NULL;
	mi->flags |= DE_MODFLAG_HIDDEN;
}

static int do_ape_tag_if_exists(deark *c, i64 endpos, i64 *ape_tag_bytes_consumed)
{
	i64 footer_startpos;
	de_module_params *mparams = NULL;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	*ape_tag_bytes_consumed = 0;

	footer_startpos = endpos-32;
	if(!is_apetag_sig_at(c->infile, footer_startpos)) {
		goto done;
	}

	de_dbg(c, "APE tag found, ending at %"I64_FMT, endpos);
	de_dbg_indent(c, 1);
	mparams = de_malloc(c, sizeof(de_module_params));
	de_run_module_by_id_on_slice(c, "apetag", mparams, c->infile, 0, endpos);
	if(mparams->out_params.flags & 0x1) {
		// apetag module told us the size of the APE tag data.
		*ape_tag_bytes_consumed = mparams->out_params.int64_1;
	}
	else {
		goto done;
	}
	de_dbg_indent(c, -1);

	retval = 1;
done:
	de_free(c, mparams);
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
	static const u16 tbl[5][16] = {
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
	static const u32 tbl[3][4] = {
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

static int find_mp3_frame_header(deark *c, mp3ctx *d, i64 pos1, i64 nbytes_avail,
	i64 *skip_this_many_bytes)
{
	u8 *buf = NULL;
	i64 nbytes_in_buf;
	i64 bpos = 0;
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

static void do_mp3_frame(deark *c, mp3ctx *d, i64 pos1, i64 len)
{
	u32 x;
	i64 pos = pos1;
	int saved_indent_level;
	char buf[32];

	de_dbg_indent_save(c, &saved_indent_level);
	x = (u32)de_getu32be(pos);
	if((x & 0xffe00000U) != 0xffe00000U) {
		int ret;
		i64 num_bytes_to_skip = 0;
		de_info(c, "Note: MP3/MPA frame header not found at %"I64_FMT". Scanning for frame header.", pos);
		if(d->frame_count==0 && c->module_disposition==DE_MODDISP_AUTODETECT &&
			d->has_id3v2)
		{
			// Format was presumably autodetected solely based on the existence
			// of ID3v2 data.
			de_warn(c, "This might not be an MPEG audio file. It might be an unrecognized "
				"audio format.");
		}
		ret = find_mp3_frame_header(c, d, pos1, len, &num_bytes_to_skip);
		if(!ret) {
			de_err(c, "MP3/MPA frame header not found");
			goto done;
		}
		pos += num_bytes_to_skip;
		de_info(c, "Note: Possible MP3 frame header found at %"I64_FMT".", pos);
		x = (u32)de_getu32be(pos);
	}

	de_dbg(c, "frame at %"I64_FMT, pos);
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
	//pos += 4;
	d->frame_count++;

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_mp3_data(deark *c, mp3ctx *d, i64 pos1, i64 len)
{
	de_dbg(c, "MP3/MPA data at %"I64_FMT", len=%"I64_FMT, pos1, len);
	de_dbg_indent(c, 1);
	do_mp3_frame(c, d, pos1, len);
	// TODO: There are probably many frames. Should we look for more frames
	// (in some cases?)?
	de_dbg_indent(c, -1);
}

static void de_run_mpegaudio(deark *c, de_module_params *mparams)
{
	mp3ctx *d = NULL;
	i64 pos;
	i64 endpos;
	i64 ape_tag_len;
	struct de_id3info id3i;

	d = de_malloc(c, sizeof(mp3ctx));

	de_fmtutil_handle_id3(c, c->infile, &id3i, 0);
	d->has_id3v2 = id3i.has_id3v2;
	pos = id3i.main_start;
	endpos = id3i.main_end;

	if(!id3i.has_id3v2) {
		if(!dbuf_memcmp(c->infile, endpos-10, "3DI", 3)) {
			de_warn(c, "Possible ID3v2 tag found at end of file (footer at %"I64_FMT"). "
				"This is not supported.", endpos-10);
		}
	}

	do_ape_tag_if_exists(c, endpos, &ape_tag_len);
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
	u8 has_id3v2;
	i64 pos;

	if(!c->detection_data->id3.detection_attempted) {
		de_err(c, "mpegaudio detection requires id3 module");
		return 0;
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

	has_id3v2 = c->detection_data->id3.has_id3v2;

	if(!has_id3v2 && !has_any_ext) {
		// TODO: We could try harder to identify MP3.
		return 0;
	}

	if(has_id3v2) {
		pos = (i64)c->detection_data->id3.bytes_at_start;
	}
	else {
		pos = 0;
	}

	x = (unsigned int)de_getu16be(pos);
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

//// Monkey's Audio

static void de_run_monkeys_audio(deark *c, de_module_params *mparams)
{
	i64 endpos = c->infile->len;

	if(is_apetag_sig_at(c->infile, endpos-32)) {
		de_dbg(c, "APE tag found, ending at %"I64_FMT, endpos);
		de_dbg_indent(c, 1);
		de_run_module_by_id_on_slice2(c, "apetag", NULL, c->infile, 0, endpos);
		de_dbg_indent(c, -1);
	}
}

static int ma_is_known_cmpr(unsigned int n)
{
	if(n<1000 || n>5000) return 0;
	if(n%1000) return 0;
	return 1;
}

static int de_identify_monkeys_audio(deark *c)
{
	unsigned int n;

	if(dbuf_memcmp(c->infile, 0, "MAC ", 4)) return 0;
	n = (unsigned int)de_getu16le(6);
	if(ma_is_known_cmpr(n)) return 100;
	n = (unsigned int)de_getu16le(52);
	if(ma_is_known_cmpr(n)) return 100;
	return 0;
}

void de_module_monkeys_audio(deark *c, struct deark_module_info *mi)
{
	mi->id = "monkeys_audio";
	mi->desc = "Monkey's Audio (.ape)";
	mi->run_fn = de_run_monkeys_audio;
	mi->identify_fn = de_identify_monkeys_audio;
}
