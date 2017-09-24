// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// BPG

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_bpg);

typedef struct localctx_struct {
	de_int64 width, height;

	de_byte pixel_format;
	de_byte alpha_flag;
	de_int64 bit_depth;

	de_byte color_space;
	de_byte extension_present_flag;
	de_byte alpha2_flag;
	de_byte limited_range_flag;

	de_int64 picture_data_len;
	de_int64 extension_data_len;

} lctx;

static de_int64 get_ue7(deark *c, de_int64 *pos)
{
	de_byte b;
	de_int64 val = 0;
	int bytecount = 0;

	// TODO: Better error handling
	while(1) {
		b = de_getbyte(*pos);
		(*pos)++;
		bytecount++;

		// A quick hack to prevent 64-bit integer overflow.
		// 5 bytes are enough for 35 bits, and none of the fields in
		// BPG v0.9.4.1 require more than 32.
		if(bytecount<=5)
			val = (val<<7)|(b&0x7f);

		if(b<0x80) {
			break;
		}
	}
	return val;
}

static void do_exif(deark *c, lctx *d, de_int64 pos1, de_int64 len1)
{
	de_byte buf[3];
	de_int64 pos = pos1;
	de_int64 len = len1;

	if(len1<8) return;
	de_read(buf, pos1, 3);
	if(buf[0]==0 && (buf[1]=='M' || buf[1]=='I') && buf[2]==buf[1]) {
		de_warn(c, "Ignoring initial NUL byte in Exif data (libbpg bug?)");
		pos++;
		len--;
	}
	de_fmtutil_handle_exif(c, pos, len);
}

static void do_extensions(deark *c, lctx *d, de_int64 pos)
{
	de_int64 endpos;
	de_int64 tag;
	de_int64 payload_len;

	endpos = pos + d->extension_data_len;

	while(pos < endpos) {
		tag = get_ue7(c, &pos);
		payload_len = get_ue7(c, &pos);
		if(pos+payload_len>endpos) break;

		switch(tag) {
		case 1: // Exif
			do_exif(c, d, pos, payload_len);
			break;
		case 2: // ICC profile
			dbuf_create_file_from_slice(c->infile, pos, payload_len, "icc", NULL, DE_CREATEFLAG_IS_AUX);
			break;
		case 3: // XMP
			dbuf_create_file_from_slice(c->infile, pos, payload_len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
			break;
		case 4: // Thumbnail
			dbuf_create_file_from_slice(c->infile, pos, payload_len, "thumb.bpg", NULL, DE_CREATEFLAG_IS_AUX);
			break;
		default:
			de_dbg(c, "unrecognized extension type: %d", (int)tag);
		}

		pos += payload_len;
	}
}

static void do_hevc_file(deark *c, lctx *d)
{
	de_int64 pos;
	de_byte b;

	pos = 4;
	b = de_getbyte(pos);
	pos++;
	d->pixel_format = b>>5;
	d->alpha_flag = (b>>4)&0x01;
	d->bit_depth = (de_int64)(b&0x0f) +8;
	de_dbg(c, "pixel format: %d", (int)d->pixel_format);
	de_dbg(c, "alpha flag: %d", (int)d->alpha_flag);
	de_dbg(c, "bit depth: %d", (int)d->bit_depth);

	b = de_getbyte(pos);
	pos++;
	d->color_space = b>>4;
	d->extension_present_flag = (b>>3)&0x01;
	d->alpha2_flag = (b>>2)&0x01;
	d->limited_range_flag = (b>>1)&0x01;
	de_dbg(c, "color_space: %d", (int)d->color_space);
	de_dbg(c, "extension_present_flag: %d", (int)d->extension_present_flag);
	de_dbg(c, "alpha2_flag: %d", (int)d->alpha2_flag);
	de_dbg(c, "limited_range_flag: %d", (int)d->limited_range_flag);

	d->width = get_ue7(c, &pos);
	d->height = get_ue7(c, &pos);
	de_dbg(c, "dimensions: %dx%d", (int)d->width, (int)d->height);


	d->picture_data_len = get_ue7(c, &pos);
	de_dbg(c, "picture_data_len: %d%s", (int)d->picture_data_len,
		(d->picture_data_len==0)?" (= to EOF)":"");

	if(d->extension_present_flag) {
		d->extension_data_len = get_ue7(c, &pos);
		de_dbg(c, "extension data len: %d", (int)d->extension_data_len);
	}

	if(d->extension_present_flag) {
		do_extensions(c, d, pos);
		pos += d->extension_data_len;
	}

	de_dbg(c, "hevc_header_and_data begins at %d", (int)pos);
}

static void de_run_bpg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	do_hevc_file(c, d);

	de_free(c, d);
}

static int de_identify_bpg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x42\x50\x47\xfb", 4)) {
		return 100;
	}
	return 0;
}

void de_module_bpg(deark *c, struct deark_module_info *mi)
{
	mi->id = "bpg";
	mi->desc = "BPG (Better Portable Graphics)";
	mi->desc2 = "resources only";
	mi->run_fn = de_run_bpg;
	mi->identify_fn = de_identify_bpg;
}
