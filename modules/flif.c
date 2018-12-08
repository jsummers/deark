// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// FLIF

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_flif);

typedef struct localctx_struct {
	int is_interlaced;
	int is_animated;
	i64 num_channels;
	i64 bytes_per_channel;
	i64 width, height;
	i64 nb_frames;
} lctx;

static int read_varint(deark *c, i64 pos1, i64 *result, i64 *bytes_consumed)
{
	i64 val = 0;
	u8 b;
	i64 pos = pos1;
	int retval = 0;

	*result = 0;

	while(1) {
		b = de_getbyte(pos++);
		val = (val<<7)|(b&0x7f);
		if((b&0x80)==0) break;
		if(pos - pos1 >= 8) {
			// We allow varints up to 8 bytes (8*7=56 bits).
			// If we've read 8 bytes without finding the terminating byte,
			// give up.
			// (Note that if we were to allow 63 bits, we could have int64
			// overflow when we convert from a physical value to a logical
			// value.)
			de_err(c, "Excessively large varint at %d", (int)pos1);
			goto done;
		}
	}

	*result = val;
	retval = 1;
done:
	*bytes_consumed = pos - pos1;
	return retval;
}

static int do_read_header(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed)
{
	i64 pos = pos1;
	u8 b;
	u8 intl_anim_code;
	u8 bytes_per_channel_code;
	i64 tmpcode;
	i64 bytes_consumed2;
	int retval = 0;
	char tmps[80];

	de_dbg(c, "header at %d", (int)pos1);
	de_dbg_indent(c, 1);

	pos += 4; // Magic

	b = de_getbyte(pos++);

	intl_anim_code = (b&0xf0)>>4;
	switch(intl_anim_code) {
	case 3: break;
	case 4: d->is_interlaced = 1; break;
	case 5: d->is_animated = 1; break;
	case 6: d->is_interlaced = 1; d->is_animated = 1; break;
	default:
		de_warn(c, "Unknown interlace/animation code: %d", (int)intl_anim_code);
	}
	de_dbg(c, "interlaced: %d", d->is_interlaced);
	de_dbg(c, "animated: %d", d->is_animated);

	d->num_channels = (i64)(b&0x0f);
	de_dbg(c, "number of channels: %d", (int)d->num_channels);

	bytes_per_channel_code = de_getbyte(pos++);
	if(bytes_per_channel_code=='0') {
		de_strlcpy(tmps, "custom", sizeof(tmps));
	}
	else if(bytes_per_channel_code=='1' || bytes_per_channel_code=='2') {
		d->bytes_per_channel = (i64)(bytes_per_channel_code-'0');
		de_snprintf(tmps, sizeof(tmps), "%d", (int)(d->bytes_per_channel));
	}
	else {
		de_strlcpy(tmps, "?", sizeof(tmps));
	}
	de_dbg(c, "bytes per channel: 0x%02x (%s)",
		(unsigned int)bytes_per_channel_code, tmps);

	if(!read_varint(c, pos, &tmpcode, &bytes_consumed2)) goto done;
	d->width = tmpcode+1;
	pos += bytes_consumed2;

	if(!read_varint(c, pos, &tmpcode, &bytes_consumed2)) goto done;
	d->height = tmpcode+1;
	pos += bytes_consumed2;

	de_dbg_dimensions(c, d->width, d->height);

	if(d->is_animated) {
		if(!read_varint(c, pos, &tmpcode, &bytes_consumed2)) goto done;
		d->nb_frames = tmpcode+2;
		pos += bytes_consumed2;
		de_dbg(c, "number of frames: %d", (int)d->nb_frames);
	}
	else {
		d->nb_frames = 1;
	}

	retval = 1;
done:
	*bytes_consumed = pos - pos1;
	de_dbg_indent(c, -1);
	return retval;
}

static int do_read_metadata(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed)
{
	u8 b;
	i64 pos = pos1;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	*bytes_consumed = 0;

	// peek at the next byte, to see if there is a metadata segment.
	b = de_getbyte(pos);
	if(b<32) {
		de_dbg(c, "[metadata segment not present]");
		retval = 1;
		goto done;
	}

	de_dbg(c, "metadata segment at %d", (int)pos1);
	de_err(c, "not implemented");

	// TODO (need samples)

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_second_header(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed)
{
	u8 ct;
	i64 pos = pos1;

	de_dbg(c, "second header segment at %d", (int)pos1);
	de_dbg_indent(c, 1);

	ct = de_getbyte(pos++);
	de_dbg(c, "chunk type: 0x%02x", (unsigned int)ct);

	if(ct!=0x00) {
		de_err(c, "unsupported chunk type: 0x%02x", (unsigned int)ct);
		goto done;
	}

done:
	de_dbg_indent(c, -1);
	return 0;
}

static void de_run_flif(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 bytes_consumed;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;

	if(!do_read_header(c, d, pos, &bytes_consumed)) goto done;
	pos += bytes_consumed;


	if(!do_read_metadata(c, d, pos, &bytes_consumed)) goto done;
	pos += bytes_consumed;

	if(!do_second_header(c, d, pos, &bytes_consumed)) goto done;

done:
	de_free(c, d);
}

static int de_identify_flif(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "FLIF", 4))
		return 90;
	return 0;
}

void de_module_flif(deark *c, struct deark_module_info *mi)
{
	mi->id = "flif";
	mi->desc = "FLIF image format";
	mi->run_fn = de_run_flif;
	mi->identify_fn = de_identify_flif;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
