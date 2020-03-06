// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// FLI/FLC animation

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_fli);

#define CHUNKTYPE_COLORMAP256 0x0004
#define CHUNKTYPE_DELTA_FLC  0x0007
#define CHUNKTYPE_COLORMAP64 0x000b
#define CHUNKTYPE_DELTA_FLI  0x000c
#define CHUNKTYPE_BLACK      0x000d
#define CHUNKTYPE_RLE        0x000f
#define CHUNKTYPE_COPY       0x0010
#define CHUNKTYPE_THUMBNAIL  0x0012
#define CHUNKTYPE_FLI        0xaf11
#define CHUNKTYPE_FLC        0xaf12
#define CHUNKTYPE_PREFIX     0xf100
#define CHUNKTYPE_FRAME      0xf1fa
#define CHUNKTYPE_NONE      0x10000

struct image_ctx_type {
	i64 w;
	i64 h;
	int use_count;
	int error_flag;
	struct de_density_info density;
	de_bitmap *img;
	u32 pal[256];
};

struct chunk_info_type {
	UI chunktype;
	int level;
	i64 pos;
	i64 len;

	// Current image context. Can be NULL. Do not free this directly.
	struct image_ctx_type *ictx;
};

typedef struct localctx_struct {
	UI main_chunktype;
	i64 frame_count;
	struct de_timestamp create_timestamp;
	struct de_timestamp mod_timestamp;
} lctx;

static const char *get_chunk_type_name(lctx *d, struct chunk_info_type *parent_ci, UI t)
{
	const char *name = NULL;
	UI parent_ct;

	parent_ct = parent_ci ? parent_ci->chunktype : CHUNKTYPE_NONE;

	switch(t) {
	case 0x0004: name="color map 256"; break; // FLC only
	case 0x0007: name="delta compressed data (new)"; break; // FLC only
	case 0x000b: name="color map 64"; break; // FLI only
	case 0x000c: name="delta compressed data (old)"; break;
	case 0x000d: name="clear screen"; break;
	case 0x000f: name="RLE compressed data"; break;
	case 0x0010: name="uncompressed data"; break;
	case 0x0012:
		if(parent_ct==CHUNKTYPE_THUMBNAIL) {
			name="color translation table";
		}
		else {
			name="thumbnail image";
		}
		break;
	case CHUNKTYPE_FLI: name="FLI"; break;
	case CHUNKTYPE_FLC: name="FLC"; break;
	case 0xf100: name="prefix"; break;
	case CHUNKTYPE_FRAME: name="frame"; break;
	}
	return name?name:"?";
}

// Caller supplies pal[256]
static void make_6cube_pal(u32 *pal)
{
	UI r, g, b;
	UI k;

	for(k=0; k<216; k++) {
		b = (k%6) * 51;
		g = ((k/6)%6) * 51;
		r = (k/36) * 51;
		pal[k] = DE_MAKE_RGB(r, g, b);
	}
}

static struct image_ctx_type *create_image_ctx(deark *c, lctx *d, i64 w, i64 h)
{
	struct image_ctx_type *ictx;

	ictx = de_malloc(c, sizeof(struct image_ctx_type));
	ictx->w = w;
	ictx->h = h;
	ictx->img = de_bitmap_create(c, w, h, 3);
	return ictx;
}

static void destroy_image_ctx(deark *c, struct image_ctx_type *ictx)
{
	if(!ictx) return;
	if(ictx->img) {
		de_bitmap_destroy(ictx->img);
	}
	de_free(c, ictx);
}

static void do_sequence_of_chunks(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 max_nchunks);

static void do_chunk_rle(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 xpos = 0;
	i64 ypos = 0;
	i64 pos = ci->pos + 6;
	struct image_ctx_type *ictx;

	if(!ci->ictx) goto done;
	de_dbg(c, "doing RLE decompression");
	ictx = ci->ictx;
	ictx->use_count++;
	pos++; // First byte of each line is a packet count (not needed)

	while(1) {
		UI clridx;
		u8 code;
		i64 count;
		i64 k;

		if(pos >= ci->pos + ci->len) break;

		code = de_getbyte_p(&pos); // packet type/size
		if(code >= 128) { // "negative" = run of uncompressed pixels
			count = (i64)256 - (i64)code;
			for(k=0; k<count; k++) {
				clridx = (UI)de_getbyte_p(&pos);
				de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
				xpos++;
			}
		}
		else { // "positive" = RLE
			count = (i64)code;
			clridx = (UI)de_getbyte_p(&pos);
			for(k=0; k<count; k++) {
				de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
				xpos++;
			}
		}

		if(xpos >= ictx->w) {
			xpos = 0;
			ypos++;
			pos++; // packet count
			if(ypos>=ictx->h) break;
		}
	}

done:
	;
}

static void do_chunk_delta_fli(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 ypos;
	i64 num_encoded_lines;
	i64 line_idx;
	i64 pos = ci->pos + 6;
	struct image_ctx_type *ictx;

	if(!ci->ictx) goto done;
	de_dbg(c, "doing delta (FLI-style) decompression");
	ictx = ci->ictx;
	ictx->use_count++;

	ypos = de_getu16le_p(&pos);
	num_encoded_lines = de_getu16le_p(&pos);

	for(line_idx=0; line_idx<num_encoded_lines; line_idx++) {
		UI npackets;
		UI pkidx;
		i64 xpos = 0;

		if(pos >= ci->pos + ci->len) goto done;

		npackets = (UI)de_getbyte_p(&pos);

		for(pkidx=0; pkidx<npackets; pkidx++) {
			UI clridx;
			u8 code;
			i64 count;
			i64 k;
			i64 skip_count;

			if(pos >= ci->pos + ci->len) goto done;
			skip_count = (i64)de_getbyte_p(&pos);
			xpos += skip_count;
			code = de_getbyte_p(&pos);
			if(code<128) { // "positive" = run of uncompressed pixels
				count = (i64)code;
				for(k=0; k<count; k++) {
					clridx = (UI)de_getbyte_p(&pos);
					de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
					xpos++;
				}
			}
			else { // "negative" = RLE
				clridx = (UI)de_getbyte_p(&pos);
				count = (i64)256 - (i64)code;
				for(k=0; k<count; k++) {
					de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
					xpos++;
				}
			}
		}

		ypos++;
	}

done:
	;
}

static void do_chunk_delta_flc(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 ypos = 0;
	i64 num_encoded_lines;
	i64 line_idx;
	i64 pos = ci->pos + 6;
	struct image_ctx_type *ictx;

	if(!ci->ictx) goto done;
	de_dbg(c, "doing delta (FLC-style) decompression");
	ictx = ci->ictx;
	ictx->use_count++;

	num_encoded_lines = de_getu16le_p(&pos);

	for(line_idx=0; line_idx<num_encoded_lines; line_idx++) {
		UI npackets = 0;
		UI pkidx;
		UI wcode, wcode_hi;
		i64 xpos = 0;

		// Read code words until we find one the high 2 bits == 0.
		while(1) {
			if(pos >= ci->pos + ci->len) goto done;

			wcode = (UI)de_getu16le_p(&pos);
			wcode_hi = wcode>>14;

			if(wcode_hi==0) {
				npackets = wcode;
				break;
			}
			else if(wcode_hi==3) {
				ypos += (i64)65536 - (i64)wcode;
			}
			else if(wcode_hi==2) {
				// Set the "last byte of current line".
				// (UNTESTED) This feature is only expected to be used if the
				// screen width is odd, and I haven't found such a file.
				de_bitmap_setpixel_rgb(ictx->img, ictx->w-1, ypos, ictx->pal[wcode & 0x00ff]);
			}
		}

		for(pkidx=0; pkidx<npackets; pkidx++) {
			UI clridx, clridx2;
			u8 code;
			i64 count;
			i64 k;
			i64 skip_count;

			if(pos >= ci->pos + ci->len) goto done;
			skip_count = (i64)de_getbyte_p(&pos);
			xpos += skip_count;
			code = de_getbyte_p(&pos);
			if(code<128) { // "positive" = run of uncompressed pixels
				count = 2 * (i64)code;
				for(k=0; k<count; k++) {
					clridx = (UI)de_getbyte_p(&pos);
					de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
					xpos++;
				}
			}
			else { // "negative" = RLE
				count = (i64)256 - (i64)code;
				clridx = (UI)de_getbyte_p(&pos);
				clridx2 = (UI)de_getbyte_p(&pos);
				for(k=0; k<count; k++) {
					de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx]);
					xpos++;
					de_bitmap_setpixel_rgb(ictx->img, xpos, ypos, ictx->pal[clridx2]);
					xpos++;
				}
			}
		}

		ypos++;
	}

done:
	;
}

// (UNTESTED)
static void do_chunk_copy(deark *c, lctx *d, struct chunk_info_type *ci)
{
	if(!ci->ictx) return;
	ci->ictx->use_count++;
	de_convert_image_paletted(c->infile, ci->pos, 8, ci->ictx->w, ci->ictx->pal,
		ci->ictx->img, 0);
}

// (UNTESTED)
static void do_chunk_black(deark *c, lctx *d, struct chunk_info_type *ci)
{
	if(!ci->ictx) return;
	de_bitmap_rect(ci->ictx->img, 0, 0, ci->ictx->w, ci->ictx->h,
		ci->ictx->pal[0], 0);
}

// bps = bits/sample: 6 or 8
static void do_chunk_colormap(deark *c, lctx *d, struct chunk_info_type *ci, int bps)
{
	i64 npackets;
	i64 pknum;
	i64 pos = ci->pos + 6;
	UI next_idx = 0;

	if(!ci->ictx) return;
	npackets = de_getu16le_p(&pos);

	for(pknum=0; pknum<npackets; pknum++) {
		UI num_entries_to_skip;
		UI num_entries_to_set;
		UI k;

		if(pos >= ci->pos + ci->len)  goto done;
		num_entries_to_skip = (UI)de_getbyte_p(&pos);
		next_idx += num_entries_to_skip;
		num_entries_to_set = (UI)de_getbyte_p(&pos);
		if(num_entries_to_set==0) num_entries_to_set = 256;

		for(k=0; k<num_entries_to_set; k++) {
			u8 samp[3];
			u32 clr;
			UI z;

			for(z=0; z<3; z++) {
				samp[z] = de_getbyte_p(&pos);
				if(bps==6) {
					samp[z] = de_scale_63_to_255(samp[z]);
				}
			}

			clr = DE_MAKE_RGB(samp[0], samp[1], samp[2]);
			if(next_idx < 256) {
				ci->ictx->pal[next_idx] = clr;
				de_dbg_pal_entry(c, (i64)next_idx, clr);
			}
			next_idx++;
		}
	}
done:
	;
}

#if 0
static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	if(ts->is_valid) {
		de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	}
	else {
		de_strlcpy(timestamp_buf, "(not set)", sizeof(timestamp_buf));
	}
	de_dbg(c, "%s: %s", name, timestamp_buf);
}
#endif

static void do_chunk_FLI_FLC(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 pos = ci->pos + 6;
	i64 scr_width, scr_height;
	int depth;
	i64 n;
	i64 aspect_x = 0;
	i64 aspect_y = 0;
	struct image_ctx_type *ictx = NULL;
	double fps = 0.0;

	d->main_chunktype = ci->chunktype;
	if(d->main_chunktype==CHUNKTYPE_FLI) {
		de_declare_fmt(c, "FLI");
	}
	else if(d->main_chunktype==CHUNKTYPE_FLC) {
		de_declare_fmt(c, "FLC");
	}

	n = de_getu16le_p(&pos);
	de_dbg(c, "num frames: %d", (int)n);
	scr_width = de_getu16le_p(&pos);
	de_dbg(c, "screen width: %d", (int)scr_width);
	scr_height = de_getu16le_p(&pos);
	de_dbg(c, "screen height: %d", (int)scr_height);
	depth = (int)de_getu16le_p(&pos);
	de_dbg(c, "depth: %d", depth);
	pos += 2; // flags

	n = de_getu32le_p(&pos);
	if(ci->chunktype==CHUNKTYPE_FLI && n!=0) {
		fps = 70.0/(double)n;
	}
	else if(ci->chunktype==CHUNKTYPE_FLC && n!=0) {
		fps = 1000.0/(double)n;
	}
	de_dbg(c, "speed: %"I64_FMT" (%.4f frames/sec)", n, fps);

	pos += 2; // reserved

	if(ci->chunktype==CHUNKTYPE_FLI) {
		if(scr_width==320 && scr_height==200) {
			aspect_x = 6;
			aspect_y = 5;
		}
	}

	if(ci->chunktype==CHUNKTYPE_FLC) {
		i64 time_raw;
#if 0
		i64 date_raw;
#endif

		// TODO: Figure out the timestamp format.
#if 0
		time_raw = de_getu16le_p(&pos);
		date_raw = de_getu16le_p(&pos);
		de_dos_datetime_to_timestamp(&d->create_timestamp, date_raw, time_raw);
		d->create_timestamp.tzcode = DE_TZCODE_LOCAL;
		dbg_timestamp(c, &d->create_timestamp, "create time");
#else
		time_raw = de_getu32le_p(&pos);
		de_dbg(c, "create time: %"I64_FMT, time_raw);
#endif
		pos += 4; // creator ID

#if 0
		time_raw = de_getu16le_p(&pos);
		date_raw = de_getu16le_p(&pos);
		de_dos_datetime_to_timestamp(&d->mod_timestamp, date_raw, time_raw);
		d->mod_timestamp.tzcode = DE_TZCODE_LOCAL;
		dbg_timestamp(c, &d->mod_timestamp, "mod time");
#else
		time_raw = de_getu32le_p(&pos);
		de_dbg(c, "mod time: %"I64_FMT, time_raw);
#endif
		pos += 4; // updater ID

		aspect_x = de_getu16le_p(&pos);
		aspect_y = de_getu16le_p(&pos);
		de_dbg(c, "aspect ratio: %d,%d", (int)aspect_x, (int)aspect_y);
	}

	ictx = create_image_ctx(c, d, scr_width, scr_height);
	ci->ictx = ictx;
	if(aspect_x && aspect_y) {
		ictx->density.code = DE_DENSITY_UNK_UNITS;
		ictx->density.xdens = (double)aspect_x;
		ictx->density.ydens = (double)aspect_y;
	}

	pos = ci->pos + 128;
	do_sequence_of_chunks(c, d, ci, pos, -1);

	destroy_image_ctx(c, ictx);
	ci->ictx = NULL;
}

static void do_chunk_frame(deark *c, lctx *d, struct chunk_info_type *ci)
{
	i64 num_subchunks;
	i64 prev_use_count = 0;
	de_finfo *fi = NULL;

	num_subchunks = de_getu16le(ci->pos+6);
	de_dbg(c, "num subchunks: %"I64_FMT, num_subchunks);

	if(ci->ictx) {
		prev_use_count = ci->ictx->use_count;
	}

	do_sequence_of_chunks(c, d, ci, ci->pos+16, num_subchunks);

	if(ci->ictx) {
		if(ci->ictx->use_count > prev_use_count && !ci->ictx->error_flag) {
			fi = de_finfo_create(c);
			fi->density = ci->ictx->density;
			fi->image_mod_time = d->mod_timestamp;
			de_bitmap_write_to_file_finfo(ci->ictx->img, fi, 0);
		}
	}

	de_finfo_destroy(c, fi);
}

static void do_chunk_thumbnail(deark *c, lctx *d, struct chunk_info_type *ci)
{
	UI colortype;
	i64 w, h;
	struct image_ctx_type *ictx = NULL;
	i64 pos = ci->pos + 6;
	de_finfo *fi = NULL;

	h = de_getu16le_p(&pos);
	w = de_getu16le_p(&pos);
	de_dbg_dimensions(c, w, h);
	colortype = (UI)de_getu16le_p(&pos);
	de_dbg(c, "color type: %u", colortype);

	ictx = create_image_ctx(c, d, w, h);
	ci->ictx = ictx;
	make_6cube_pal(ictx->pal);
	do_sequence_of_chunks(c, d, ci, pos, -1);

	fi = de_finfo_create(c);
	fi->image_mod_time = d->mod_timestamp;
	// TODO: density?
	de_finfo_set_name_from_sz(c, fi, "thumb", 0, DE_ENCODING_LATIN1);

	if(ictx->use_count>0 && !ictx->error_flag) {
		de_bitmap_write_to_file_finfo(ictx->img, fi, DE_CREATEFLAG_IS_AUX);
	}
	destroy_image_ctx(c, ictx);
	ci->ictx = NULL;
	de_finfo_destroy(c, fi);
}

static int do_chunk(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 bytes_avail, int level, i64 *pbytes_consumed)
{
	i64 pos = pos1;
	int saved_indent_level;
	int retval = 0;
	struct chunk_info_type *ci = NULL;
	UI parent_ct;

	de_dbg_indent_save(c, &saved_indent_level);
	if(bytes_avail<6) goto done;
	parent_ct = parent_ci ? parent_ci->chunktype : CHUNKTYPE_NONE;

	ci = de_malloc(c, sizeof(struct chunk_info_type));
	ci->level = level;
	ci->pos = pos1;

	// Inherit the image context.
	if(parent_ci) {
		ci->ictx = parent_ci->ictx;
	}

	de_dbg(c, "chunk at %"I64_FMT, ci->pos);
	de_dbg_indent(c, 1);

	ci->len = de_getu32le_p(&pos);
	de_dbg(c, "chunk len: %"I64_FMT, ci->len);
	if(ci->len==0 && level==0) {
		ci->len = c->infile->len;
	}
	if(ci->len==0) {
		goto done;
	}
	if(ci->len<6) {
		de_err(c, "Bad chunk header at %"I64_FMT, ci->pos);
		goto done;
	}
	if(ci->len > bytes_avail) {
		de_warn(c, "Chunk at %"I64_FMT" exceeds its parent's bounds (ends at %"I64_FMT
			", parent ends at %"I64_FMT")", ci->pos, ci->pos+ci->len, ci->pos+bytes_avail);
		ci->len = bytes_avail;
	}

	*pbytes_consumed = ci->len;
	retval = 1;

	ci->chunktype = (UI)de_getu16le_p(&pos);
	de_dbg(c, "chunk type: 0x%04x (%s)", ci->chunktype,
		get_chunk_type_name(d, parent_ci, ci->chunktype));

	if(level==0) {
		if(ci->chunktype==CHUNKTYPE_FLI || ci->chunktype==CHUNKTYPE_FLC) {
			do_chunk_FLI_FLC(c, d, ci);
		}
		else {
			de_err(c, "Not a FLI/FLC file");
		}
		goto done;
	}

	switch(ci->chunktype) {
	case CHUNKTYPE_FRAME:
		do_chunk_frame(c, d, ci);
		break;
	case CHUNKTYPE_DELTA_FLI:
		do_chunk_delta_fli(c, d, ci);
		break;
	case CHUNKTYPE_DELTA_FLC:
		do_chunk_delta_flc(c, d, ci);
		break;
	case CHUNKTYPE_RLE:
		do_chunk_rle(c, d, ci);
		break;
	case CHUNKTYPE_COPY:
		do_chunk_copy(c, d, ci);
		break;
	case CHUNKTYPE_BLACK:
		do_chunk_black(c, d, ci);
		break;
	case CHUNKTYPE_COLORMAP64:
		do_chunk_colormap(c, d, ci, 6);
		break;
	case CHUNKTYPE_COLORMAP256:
		do_chunk_colormap(c, d, ci, 8);
		break;
	case CHUNKTYPE_THUMBNAIL:
		if(parent_ct==CHUNKTYPE_FRAME) {
			do_chunk_thumbnail(c, d, ci);
		}
		break;
	case CHUNKTYPE_PREFIX:
		// TODO: There might be interesting things here.
		break;
	default:
		if(parent_ct==CHUNKTYPE_FLI || parent_ct==CHUNKTYPE_FLC || parent_ct==CHUNKTYPE_FRAME) {
			de_warn(c, "Unknown chunk type 0x%04x at %"I64_FMT, ci->chunktype, ci->pos);
		}
	}

done:
	de_free(c, ci);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// if max_nchunks==-1, no maximum
static void do_sequence_of_chunks(deark *c, lctx *d, struct chunk_info_type *parent_ci,
	i64 pos1, i64 max_nchunks)
{
	i64 pos = pos1;
	i64 endpos = parent_ci->pos + parent_ci->len;
	i64 chunk_idx = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(pos+6 >= endpos) goto done;
	de_dbg(c, "sequence of chunks at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	while(1) {
		i64 bytes_avail;
		i64 bytes_consumed = 0;
		int ret;

		if(max_nchunks>=0 && chunk_idx>=max_nchunks) break;
		bytes_avail = endpos - pos;
		if(bytes_avail<6) break;

		ret = do_chunk(c, d, parent_ci, pos, bytes_avail, parent_ci->level+1, &bytes_consumed);
		if(!ret || bytes_consumed<1) break;
		pos += bytes_consumed;
		chunk_idx++;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_fli(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 bytes_consumed = 0;

	d = de_malloc(c, sizeof(lctx));

	(void)do_chunk(c, d, NULL, 0, c->infile->len, 0, &bytes_consumed);

	if(d) {
		de_free(c, d);
	}
}

static int de_identify_fli(deark *c)
{
	UI ct;
	int has_ext;

	ct = (UI)de_getu16le(4);
	if(ct!=CHUNKTYPE_FLI && ct!=CHUNKTYPE_FLC) return 0;
	has_ext = de_input_file_has_ext(c, "fli") ||
		de_input_file_has_ext(c, "flc");
	if(has_ext) return 90;
	return 15;
}

void de_module_fli(deark *c, struct deark_module_info *mi)
{
	mi->id = "fli";
	mi->desc = "FLI/FLC animation";
	mi->run_fn = de_run_fli;
	mi->identify_fn = de_identify_fli;
}
