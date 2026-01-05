// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GIF image

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_gif);

#define DISPOSE_LEAVE     1
#define DISPOSE_BKGD      2
#define DISPOSE_PREVIOUS  3

struct gceinfo {
	u8 disposal_method;
	u8 trns_color_idx_valid;
	u8 trns_color_idx;
};

typedef struct localctx_struct {
	int compose;
	int bad_screen_flag;
	int dump_screen;
	int dump_plaintext_ext;
	u8 unexpected_eof_flag;

	i64 screen_w, screen_h;
	int has_global_color_table;
	i64 global_color_table_size; // Number of colors stored in the file
	de_color global_ct[256];

	de_bitmap *screen_img;
	struct gceinfo *gce; // The Graphic Control Ext. in effect for the next image
	de_finfo *fi; // Reused for each image
} lctx;

// Data about a single image
struct gif_image_data {
	de_bitmap *img;
	i64 xpos, ypos;
	i64 width, height;
	i64 pixels_set;
	int interlaced;
	int has_local_color_table;
	int failure_flag;
	struct de_dfilter_ctx *dfctx;
	i64 local_color_table_size;
	u16 *interlace_map;
	de_color local_ct[256];
};

struct subblock_reader_data {
	void *userdata;
	i64 subblock_idx;
	dbuf *inf;
	i64 subblkpos;
	i64 reported_dlen;
	i64 dpos;
	i64 dlen;
};

typedef void (*subblock_callback_fn_type)(deark *c, lctx *d, struct subblock_reader_data *sbrd);

static void on_unexpected_eof(deark *c, lctx *d)
{
	if(!d->unexpected_eof_flag) {
		de_err(c, "Unexpected end of file");
		d->unexpected_eof_flag = 1;
	}
}

// Call cbfn once for each subblock.
// For the block terminator, will be called with .dlen=0.
// On unexpected EOF, supplies any bytes that are present (with .dlen>0 &&
// .dlen!=.reported_dlen), calls on_unexpected_eof(), and sets *ppos to point
// to EOF.
static void do_read_subblocks_p(deark *c, lctx *d, dbuf *inf,
	subblock_callback_fn_type cbfn, void *userdata, i64 *ppos)
{
	struct subblock_reader_data sbrd;
	int eof_flag = 0;

	de_zeromem(&sbrd, sizeof(struct subblock_reader_data));
	sbrd.userdata = userdata;
	sbrd.inf = inf;

	while(1) {
		sbrd.subblkpos = *ppos;

		if(*ppos >= inf->len) {
			on_unexpected_eof(c, d);
			*ppos = inf->len;
			return;
		}
		sbrd.reported_dlen = (i64)de_getbyte_p(ppos);

		sbrd.dpos = *ppos;

		if(sbrd.dpos + sbrd.reported_dlen > inf->len) {
			eof_flag = 1;
			sbrd.dlen = inf->len - sbrd.dpos;
		}
		else {
			sbrd.dlen = sbrd.reported_dlen;
		}

		*ppos += sbrd.dlen;

		if(sbrd.dlen>0 || !eof_flag) {
			cbfn(c, d, &sbrd);
		}

		if(eof_flag) {
			on_unexpected_eof(c, d);
			*ppos = inf->len;
			return;
		}

		if(sbrd.reported_dlen==0) break;
		sbrd.subblock_idx++;
	}
}

static void do_record_pixel(deark *c, lctx *d, struct gif_image_data *gi, unsigned int coloridx,
	i64 offset)
{
	i64 pixnum;
	i64 xi, yi;
	i64 yi1;
	de_color clr;

	if(coloridx>255) return;

	pixnum = gi->pixels_set + offset;
	xi = pixnum%gi->width;
	yi1 = pixnum/gi->width;
	if(gi->interlace_map && yi1<gi->height) {
		yi = gi->interlace_map[yi1];
	}
	else {
		yi = yi1;
	}

	if(gi->has_local_color_table && coloridx<gi->local_color_table_size) {
		clr = gi->local_ct[coloridx];
	}
	else {
		clr = d->global_ct[coloridx];
	}

	if(d->gce && d->gce->trns_color_idx_valid &&
		(d->gce->trns_color_idx == coloridx))
	{
		// Make this pixel transparent
		clr = DE_SET_ALPHA(clr, 0);
	}
	else {
		clr = DE_SET_ALPHA(clr, 0xff);
	}

	de_bitmap_setpixel_rgb(gi->img, xi, yi, clr);
}

static int do_read_header(deark *c, lctx *d, i64 pos)
{
	de_ucstring *ver = NULL;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	ver = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+3, 3, ver, 0, DE_ENCODING_ASCII);
	de_dbg(c, "version: \"%s\"", ucstring_getpsz(ver));
	de_dbg_indent(c, -1);
	ucstring_destroy(ver);
	return 1;
}

static int do_read_screen_descriptor(deark *c, lctx *d, i64 pos)
{
	i64 bgcol_index;
	u8 packed_fields;
	u8 aspect_ratio_code;
	unsigned int n;
	unsigned int global_color_table_size_code;

	de_dbg(c, "screen descriptor at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->screen_w = de_getu16le(pos);
	d->screen_h = de_getu16le(pos+2);
	de_dbg(c, "screen dimensions: %d"DE_CHAR_TIMES"%d", (int)d->screen_w, (int)d->screen_h);

	packed_fields = de_getbyte(pos+4);
	de_dbg(c, "packed fields: 0x%02x", (unsigned int)packed_fields);
	de_dbg_indent(c, 1);
	d->has_global_color_table = (packed_fields&0x80)?1:0;
	de_dbg(c, "global color table flag: %d", d->has_global_color_table);

	n = (packed_fields&0x70)>>4;
	de_dbg(c, "color resolution: %u (%u bit%s)", n, n+1U, n?"s":"");

	if(d->has_global_color_table) {
		unsigned int sf;
		sf = (packed_fields&0x08)?1:0;
		de_dbg(c, "global color table sorted: %u", sf);
	}

	if(d->has_global_color_table) {
		global_color_table_size_code = (unsigned int)(packed_fields&0x07);
		d->global_color_table_size = de_pow2((i64)global_color_table_size_code+1);
		de_dbg(c, "global color table size: %u (%d colors)",
			global_color_table_size_code, (int)d->global_color_table_size);
	}

	de_dbg_indent(c, -1);

	// We don't care about the background color, because we always assume the
	// background is transparent.
	// TODO: If we ever support writing background-color chunks to PNG files,
	// then we should look up this color and use it.
	bgcol_index = (i64)de_getbyte(pos+5);
	de_dbg(c, "background color index: %d", (int)bgcol_index);

	aspect_ratio_code = de_getbyte(pos+6);
	de_dbg(c, "aspect ratio code: %d", (int)aspect_ratio_code);
	if(aspect_ratio_code!=0 && aspect_ratio_code!=49) {
		d->fi->density.code = DE_DENSITY_UNK_UNITS;
		d->fi->density.xdens = 64.0;
		d->fi->density.ydens = 15.0 + (double)aspect_ratio_code;
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_color_table(deark *c, lctx *d, i64 pos, i64 ncolors,
	de_color *ct)
{
	de_read_palette_rgb(c->infile, pos, ncolors, 3, ct, 256, 0);
}

static int do_read_global_color_table(deark *c, lctx *d, i64 pos, i64 *bytesused)
{
	if(!d->has_global_color_table) return 1;
	de_dbg(c, "global color table at %d", (int)pos);

	de_dbg_indent(c, 1);
	do_read_color_table(c, d, pos, d->global_color_table_size, d->global_ct);
	de_dbg_indent(c, -1);

	*bytesused = 3*d->global_color_table_size;
	return 1;
}

static void callback_for_skip_subblocks(deark *c, lctx *d, struct subblock_reader_data *sbrd)
{
}

static void do_skip_subblocks(deark *c, lctx *d, i64 pos1, i64 *bytesused)
{
	i64 pos = pos1;

	do_read_subblocks_p(c, d, c->infile, callback_for_skip_subblocks, NULL, &pos);
	*bytesused = pos - pos1;
}

struct copy_subblocks_ctx {
	dbuf *outf;
	int has_max;
	i64 maxlen;
	i64 nbytes_copied;
};

static void callback_for_copy_subblocks(deark *c, lctx *d, struct subblock_reader_data *sbrd)
{
	struct copy_subblocks_ctx *ctx = (struct copy_subblocks_ctx*)sbrd->userdata;
	i64 nbytes_to_copy;

	if(ctx->has_max && (ctx->nbytes_copied >= ctx->maxlen)) return;
	if(sbrd->dlen<1) return;

	nbytes_to_copy = sbrd->dlen;
	if(ctx->has_max) {
		if(ctx->nbytes_copied + nbytes_to_copy > ctx->maxlen) {
			nbytes_to_copy = ctx->maxlen - ctx->nbytes_copied;
		}
	}
	dbuf_copy(sbrd->inf, sbrd->dpos, nbytes_to_copy, ctx->outf);
	ctx->nbytes_copied += nbytes_to_copy;
}

static void do_copy_subblocks_to_dbuf(deark *c, lctx *d, dbuf *outf,
	i64 pos1, int has_max, i64 maxlen)
{
	i64 pos = pos1;
	struct copy_subblocks_ctx ctx;

	ctx.outf = outf;
	ctx.has_max = has_max;
	ctx.maxlen = maxlen;
	ctx.nbytes_copied = 0;
	do_read_subblocks_p(c, d, c->infile, callback_for_copy_subblocks, (void*)&ctx, &pos);
}

static void discard_current_gce_data(deark *c, lctx *d)
{
	if(d->gce) {
		de_free(c, d->gce);
		d->gce = NULL;
	}
}

static void do_graphic_control_extension(deark *c, lctx *d, i64 pos)
{
	i64 n;
	u8 packed_fields;
	u8 user_input_flag;
	i64 delay_time_raw;
	double delay_time;
	const char *name;

	discard_current_gce_data(c, d);

	n = (i64)de_getbyte(pos);
	if(n!=4) {
		de_warn(c, "Wrong graphic control ext. block size (expected 4, is %d)",
			(int)n);
		if(n<4) return;
	}

	d->gce = de_malloc(c, sizeof(struct gceinfo));

	packed_fields = de_getbyte(pos+1);
	de_dbg(c, "packed fields: 0x%02x", (unsigned int)packed_fields);
	de_dbg_indent(c, 1);
	d->gce->trns_color_idx_valid = packed_fields&0x01;
	de_dbg(c, "has transparency: %d", (int)d->gce->trns_color_idx_valid);

	user_input_flag = (packed_fields>>1)&0x1;
	de_dbg(c, "user input flag: %d", (int)user_input_flag);

	d->gce->disposal_method = (packed_fields>>2)&0x7;
	switch(d->gce->disposal_method) {
	case 0: name="unspecified"; break;
	case DISPOSE_LEAVE: name="leave in place"; break;
	case DISPOSE_BKGD: name="restore to background"; break;
	case DISPOSE_PREVIOUS: name="restore to previous"; break;
	default: name="?";
	}
	de_dbg(c, "disposal method: %d (%s)", (int)d->gce->disposal_method, name);
	de_dbg_indent(c, -1);

	delay_time_raw = de_getu16le(pos+2);
	delay_time = ((double)delay_time_raw)/100.0;
	de_dbg(c, "delay time: %d (%.02f sec)", (int)delay_time_raw, delay_time);

	if(d->gce->trns_color_idx_valid) {
		d->gce->trns_color_idx = de_getbyte(pos+4);
		de_dbg(c, "transparent color index: %d", (int)d->gce->trns_color_idx);
	}
}

struct comment_ext_ctx {
	de_ucstring *s;
	dbuf *outf;
};

// Used for comments and frame names
static void callback_for_comment_ext(deark *c, lctx *d, struct subblock_reader_data *sbrd)
{
	struct comment_ext_ctx *ctx = (struct comment_ext_ctx*)sbrd->userdata;

	if(sbrd->dlen<1) return;

	if(ctx->outf) {
		// GIF comments are supposed to be 7-bit ASCII, so just copy them as-is.
		dbuf_copy(sbrd->inf, sbrd->dpos, sbrd->dlen, ctx->outf);
	}

	if(ctx->s->len<DE_DBG_MAX_STRLEN) {
		dbuf_read_to_ucstring(sbrd->inf, sbrd->dpos, sbrd->dlen, ctx->s, 0, DE_ENCODING_ASCII);
	}
}

static void do_comment_extension(deark *c, lctx *d, i64 pos1)
{
	struct comment_ext_ctx ctx;
	i64 pos = pos1;

	de_zeromem(&ctx, sizeof(struct comment_ext_ctx));
	ctx.s = ucstring_create(c);
	if(c->extract_level>=2) {
		ctx.outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
	}

	do_read_subblocks_p(c, d, c->infile, callback_for_comment_ext, (void*)&ctx, &pos);

	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(ctx.s));

	dbuf_close(ctx.outf);
	ucstring_destroy(ctx.s);
}

// Used by Gifsicle
static void do_framename_extension(deark *c, lctx *d, i64 pos1)
{
	struct comment_ext_ctx ctx;
	i64 pos = pos1;

	de_zeromem(&ctx, sizeof(struct comment_ext_ctx));
	ctx.s = ucstring_create(c);

	do_read_subblocks_p(c, d, c->infile, callback_for_comment_ext, (void*)&ctx, &pos);

	de_dbg(c, "frame name: \"%s\"", ucstring_getpsz_d(ctx.s));
	ucstring_destroy(ctx.s);
}

static void decode_text_color(deark *c, lctx *d, const char *name, u8 clr_idx,
	de_color *pclr)
{
	de_color clr;
	const char *alphastr;
	char csamp[32];

	clr = d->global_ct[(unsigned int)clr_idx];
	*pclr = clr;

	if(d->gce && d->gce->trns_color_idx_valid && d->gce->trns_color_idx==clr_idx) {
		alphastr = ",A=0";
		*pclr = DE_SET_ALPHA(*pclr, 0);
	}
	else {
		alphastr = "";
	}
	de_get_colorsample_code(c, clr, csamp, sizeof(csamp));
	de_dbg(c, "%s color: idx=%3u (%3u,%3u,%3u%s)%s", name,
		(unsigned int)clr_idx, (unsigned int)DE_COLOR_R(clr),
		(unsigned int)DE_COLOR_G(clr), (unsigned int)DE_COLOR_B(clr),
		alphastr, csamp);
}

static void render_plaintext_char(deark *c, lctx *d, u8 ch,
	i64 pos_x, i64 pos_y, i64 size_x, i64 size_y,
	de_color fgclr, de_color bgclr)
{
	i64 i, j;
	const u8 *fontdata;
	const u8 *chardata;

	fontdata = de_get_8x8ascii_font_ptr();

	if(ch<32 || ch>127) ch=32;
	chardata = &fontdata[8 * ((unsigned int)ch - 32)];

	for(j=0; j<size_y; j++) {
		for(i=0; i<size_x; i++) {
			unsigned int x2, y2;
			int isbg;
			de_color clr;

			// TODO: Better character-rendering facilities.
			// de_font_paint_character_idx() doesn't quite do what we need.

			x2 = (unsigned int)(0.5+(((double)i)*(8.0/(double)size_x)));
			y2 = (unsigned int)(0.5+(((double)j)*(8.0/(double)size_y)));

			if(x2<8 && y2<8 && (chardata[y2]&(1<<(7-x2)))) {
				isbg = 0;
			}
			else {
				isbg = 1;
			}
			clr = isbg ? bgclr : fgclr;
			if(DE_COLOR_A(clr)>0) {
				de_bitmap_setpixel_rgb(d->screen_img, pos_x+i, pos_y+j, clr);
			}
		}
	}
}

struct plaintext_ext_ctx {
	int header_ok;
	int ok_to_render; // If 0, something's wrong, and we shouldn't draw the pixels
	i64 textarea_xpos_in_pixels, textarea_ypos_in_pixels;
	i64 textarea_xsize_in_pixels, textarea_ysize_in_pixels;
	i64 text_width_in_chars;
	i64 char_width, char_height;
	i64 cur_xpos_in_chars, cur_ypos_in_chars;
	de_color fgclr, bgclr;
	unsigned char disposal_method;
	de_bitmap *prev_img;
	dbuf *outf_txt;
};

static void do_plaintext_ext_header(deark *c, lctx *d, struct plaintext_ext_ctx *ctx,
	dbuf *inf, i64 pos1, i64 len)
{
	u8 fgclr_idx, bgclr_idx;
	i64 pos = pos1;

	if(len<12) goto done;

	if(d->gce) {
		ctx->disposal_method = d->gce->disposal_method;
	}

	ctx->textarea_xpos_in_pixels = dbuf_getu16le(inf, pos);
	ctx->textarea_ypos_in_pixels = dbuf_getu16le(inf, pos+2);
	ctx->textarea_xsize_in_pixels = dbuf_getu16le(inf, pos+4);
	ctx->textarea_ysize_in_pixels = dbuf_getu16le(inf, pos+6);
	ctx->char_width = (i64)dbuf_getbyte(inf, pos+8);
	ctx->char_height = (i64)dbuf_getbyte(inf, pos+9);
	de_dbg(c, "text-area pos: %d,%d pixels", (int)ctx->textarea_xpos_in_pixels,
		(int)ctx->textarea_ypos_in_pixels);
	de_dbg(c, "text-area size: %d"DE_CHAR_TIMES"%d pixels", (int)ctx->textarea_xsize_in_pixels,
		(int)ctx->textarea_ysize_in_pixels);
	de_dbg(c, "character size: %d"DE_CHAR_TIMES"%d pixels", (int)ctx->char_width, (int)ctx->char_height);

	if(ctx->char_width<3 || ctx->char_height<3) {
		ctx->ok_to_render = 0;
	}

	if(ctx->char_width>0) {
		ctx->text_width_in_chars = ctx->textarea_xsize_in_pixels / ctx->char_width;
		if(ctx->text_width_in_chars<1) {
			ctx->ok_to_render = 0;
			ctx->text_width_in_chars = 1;
		}
	}
	else {
		ctx->text_width_in_chars = 80;
	}
	de_dbg(c, "calculated chars/line: %d", (int)ctx->text_width_in_chars);

	fgclr_idx = dbuf_getbyte(inf, pos+10);
	decode_text_color(c, d, "fg", fgclr_idx, &ctx->fgclr);
	bgclr_idx = dbuf_getbyte(inf, pos+11);
	decode_text_color(c, d, "bg", bgclr_idx, &ctx->bgclr);

	if(d->dump_plaintext_ext) {
		ctx->outf_txt = dbuf_create_output_file(c, "plaintext.txt", NULL, 0);
	}

	if(ctx->ok_to_render && (ctx->disposal_method==DISPOSE_PREVIOUS)) {
		i64 tmpw, tmph;
		// We need to save a copy of the pixels that may be overwritten.
		tmpw = ctx->textarea_xsize_in_pixels;
		if(tmpw>d->screen_w) tmpw = d->screen_w;
		tmph = ctx->textarea_ysize_in_pixels;
		if(tmph>d->screen_h) tmph = d->screen_h;
		ctx->prev_img = de_bitmap_create(c, tmpw, tmph, 4);
		de_bitmap_copy_rect(d->screen_img, ctx->prev_img,
			ctx->textarea_xpos_in_pixels, ctx->textarea_ypos_in_pixels,
			tmpw, tmph, 0, 0, 0);
	}

	ctx->cur_xpos_in_chars = 0;
	ctx->cur_ypos_in_chars = 0;

	ctx->header_ok = 1;
done:
	;
}

static void do_plaintext_ext_textsubblock(deark *c, lctx *d, struct plaintext_ext_ctx *ctx,
	dbuf *inf, i64 pos1, i64 len)
{
	i64 k;

	for(k=0; k<len; k++) {
		u8 b;

		b = dbuf_getbyte(inf, pos1+k);
		if(ctx->outf_txt) dbuf_writebyte(ctx->outf_txt, b);

		if(ctx->ok_to_render &&
			((ctx->cur_ypos_in_chars+1)*ctx->char_height <= ctx->textarea_ysize_in_pixels))
		{
			render_plaintext_char(c, d, b,
				ctx->textarea_xpos_in_pixels + ctx->cur_xpos_in_chars*ctx->char_width,
				ctx->textarea_ypos_in_pixels + ctx->cur_ypos_in_chars*ctx->char_height,
				ctx->char_width, ctx->char_height, ctx->fgclr, ctx->bgclr);
		}

		ctx->cur_xpos_in_chars++;
		if(ctx->cur_xpos_in_chars >= ctx->text_width_in_chars) {
			ctx->cur_ypos_in_chars++;
			ctx->cur_xpos_in_chars = 0;

			if(ctx->outf_txt) {
				// Insert newlines in appropriate places.
				dbuf_writebyte(ctx->outf_txt, '\n');
			}
		}
	}
}

static void callback_for_plaintext_ext(deark *c, lctx *d, struct subblock_reader_data *sbrd)
{
	struct plaintext_ext_ctx *ctx = (struct plaintext_ext_ctx*)sbrd->userdata;

	if(sbrd->subblock_idx==0) {
		// The first sub-block is the header
		do_plaintext_ext_header(c, d, ctx, sbrd->inf, sbrd->dpos, sbrd->dlen);
	}
	else {
		if(ctx->header_ok && sbrd->dlen>0) {
			do_plaintext_ext_textsubblock(c, d, ctx, sbrd->inf, sbrd->dpos, sbrd->dlen);
		}
	}
}

static void do_plaintext_extension(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	struct plaintext_ext_ctx *ctx = NULL;

	ctx = de_malloc(c, sizeof(struct plaintext_ext_ctx));
	ctx->disposal_method = 0;
	ctx->ok_to_render = 1;

	if(!d->compose) {
		ctx->ok_to_render = 0;
	}

	do_read_subblocks_p(c, d, c->infile, callback_for_plaintext_ext, (void*)ctx, &pos);
	if(!ctx->header_ok) goto done;

	if(d->compose) {
		de_bitmap_write_to_file_finfo(d->screen_img, d->fi, 0);

		// TODO: Too much code is duplicated with do_image().
		if(ctx->disposal_method==DISPOSE_BKGD) {
			de_bitmap_rect(d->screen_img, ctx->textarea_xpos_in_pixels, ctx->textarea_ypos_in_pixels,
				ctx->textarea_xsize_in_pixels, ctx->textarea_ysize_in_pixels,
				DE_STOCKCOLOR_TRANSPARENT, 0);
		}
		else if(ctx->disposal_method==DISPOSE_PREVIOUS && ctx->prev_img) {
			de_bitmap_copy_rect(ctx->prev_img, d->screen_img,
				0, 0, ctx->prev_img->width, ctx->prev_img->height,
				ctx->textarea_xpos_in_pixels, ctx->textarea_ypos_in_pixels, 0);
		}
	}

done:
	discard_current_gce_data(c, d);
	if(ctx) {
		dbuf_close(ctx->outf_txt);
		de_bitmap_destroy(ctx->prev_img);
		de_free(c, ctx);
	}
}

static void do_animation_extension(deark *c, lctx *d, i64 pos)
{
	i64 sub_block_len;
	u8 sub_block_id;
	const char *name;

	sub_block_len = (i64)de_getbyte(pos++);
	if(sub_block_len<1) return;

	sub_block_id = de_getbyte(pos++);
	switch(sub_block_id) {
	case 1: name="looping"; break;
	case 2: name="buffering"; break;
	default: name="?";
	}
	de_dbg(c, "netscape extension type: %d (%s)", (int)sub_block_id, name);

	if(sub_block_id==1 && sub_block_len>=3) {
		i64 loop_count;
		loop_count = de_getu16le(pos);
		de_dbg(c, "loop count: %d%s", (int)loop_count,
			(loop_count==0)?" (infinite)":"");
	}
}

static void do_xmp_extension(deark *c, lctx *d, i64 pos)
{
	i64 nbytes_tot, nbytes_payload;

	// XMP abuses GIF's subblock structure. Instead of being split into
	// subblocks as GIF expects, XMP is stored as a single blob of bytes,
	// followed by 258 "magic" bytes that re-sync the GIF decoder.

	// Calculate the total number of bytes used in this series of subblocks.
	do_skip_subblocks(c, d, pos, &nbytes_tot);
	if(nbytes_tot<=258) return;
	nbytes_payload = nbytes_tot-258;
	dbuf_create_file_from_slice(c->infile, pos, nbytes_payload, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_iccprofile_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "icc", NULL, DE_CREATEFLAG_IS_AUX);
	do_copy_subblocks_to_dbuf(c, d, outf, pos, 0, 0);
	dbuf_close(outf);
}

static void do_imagemagick_extension(deark *c, lctx *d, i64 pos)
{
	i64 sub_block_len;
	de_ucstring *s = NULL;

	sub_block_len = (i64)de_getbyte_p(&pos);
	if(sub_block_len<1) goto done;
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, sub_block_len, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "ImageMagick extension data: \"%s\"", ucstring_getpsz_d(s));
done:
	ucstring_destroy(s);
}

static void do_mgk8bim_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *tmpf = NULL;
	tmpf = dbuf_create_membuf(c, 0, 0);
	do_copy_subblocks_to_dbuf(c, d, tmpf, pos, 1, 4*1048576);
	de_dbg(c, "photoshop data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	fmtutil_handle_photoshop_rsrc(c, tmpf, 0, tmpf->len, 0x0);
	de_dbg_indent(c, -1);
	dbuf_close(tmpf);
}

static void do_mgkiptc_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *tmpf = NULL;
	tmpf = dbuf_create_membuf(c, 0, 0);
	do_copy_subblocks_to_dbuf(c, d, tmpf, pos, 1, 4*1048576);
	de_dbg(c, "IPTC-IIM data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	fmtutil_handle_iptc(c, tmpf, 0, tmpf->len, 0x0);
	de_dbg_indent(c, -1);
	dbuf_close(tmpf);
}

static void do_giflite_extension(deark *c, lctx *d, i64 pos1)
{
	i64 sub_block_len;
	i64 pos = pos1;
	UI vmajor, vminor;
	i64 olen;

	sub_block_len = (i64)de_getbyte_p(&pos);
	if(sub_block_len<2) return;
	vmajor = (UI)de_getbyte_p(&pos);
	vminor = (UI)de_getbyte_p(&pos);
	de_dbg(c, "GIFLITE ver: %u.%02u", vmajor, vminor);
	if(sub_block_len<6) return;
	olen = de_getu32le_p(&pos);
	de_dbg(c, "orig file size: %"I64_FMT, olen);
}

static void do_unknown_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *tmpf = NULL;
	tmpf = dbuf_create_membuf(c, 0, 0);
	do_copy_subblocks_to_dbuf(c, d, tmpf, pos, 1, 256);
	de_dbg_hexdump(c, tmpf, 0, tmpf->len, 256, NULL, 0x1);
	dbuf_close(tmpf);
}

static void do_application_extension(deark *c, lctx *d, i64 pos)
{
	de_ucstring *s = NULL;
	u8 app_id[11];
	i64 n;

	n = (i64)de_getbyte(pos++);
	if(n<11) return;

	de_read(app_id, pos, 11);
	pos += n;

	s = ucstring_create(c);
	ucstring_append_bytes(s, app_id, 11, 0, DE_ENCODING_ASCII);
	de_dbg(c, "app id: \"%s\"", ucstring_getpsz(s));
	ucstring_destroy(s);

	if(!de_memcmp(app_id, "NETSCAPE2.0", 11) ||
		!de_memcmp(app_id, "ANIMEXTS1.0", 11))
	{
		do_animation_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "XMP DataXMP", 11)) {
		do_xmp_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "ICCRGBG1012", 11)) {
		do_iccprofile_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "ImageMagick", 11)) {
		do_imagemagick_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "MGK8BIM0000", 11)) {
		do_mgk8bim_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "MGKIPTC0000", 11)) {
		do_mgkiptc_extension(c, d, pos);
	}
	else if(!de_memcmp(app_id, "GIFLITE    ", 11)) {
		do_giflite_extension(c, d, pos);
	}
	else {
		do_unknown_extension(c, d, pos);
	}
}

static int do_read_extension(deark *c, lctx *d, i64 pos1, i64 *bytesused)
{
	i64 bytesused2 = 0;
	u8 ext_type;
	i64 pos;
	const char *ext_name;

	de_dbg_indent(c, 1);
	pos = pos1;
	*bytesused = 0;
	ext_type = de_getbyte(pos);

	switch(ext_type) {
	case 0x01: ext_name="plain text"; break;
	case 0xf9: ext_name="graphic control"; break;
	case 0xce: ext_name="frame name"; break;
	case 0xfe: ext_name="comment"; break;
	case 0xff: ext_name="application"; break;
	default: ext_name="?";
	}

	de_dbg(c, "extension type 0x%02x (%s) at %d", (unsigned int)ext_type, ext_name, (int)pos);
	pos++;

	de_dbg_indent(c, 1);
	switch(ext_type) {
	case 0x01:
		do_plaintext_extension(c, d, pos);
		break;
	case 0xf9:
		do_graphic_control_extension(c, d, pos);
		break;
	case 0xfe:
		do_comment_extension(c, d, pos);
		break;
	case 0xff:
		do_application_extension(c, d, pos);
		break;
	case 0xce:
		do_framename_extension(c, d, pos);
		break;
	}
	de_dbg_indent(c, -1);

	// TODO?: It's inefficient to do this unconditionally, since we usually have
	// already figured out where the extension ends.
	do_skip_subblocks(c, d, pos, &bytesused2);
	pos += bytesused2;

	*bytesused = pos - pos1;
	de_dbg_indent(c, -1);

	return 1;
}

// Read 9-byte image header
static void do_read_image_header(deark *c, lctx *d, struct gif_image_data *gi, i64 pos)
{
	u8 packed_fields;
	unsigned int local_color_table_size_code;

	de_dbg(c, "image descriptor at %d", (int)pos);
	de_dbg_indent(c, 1);

	gi->xpos = de_getu16le(pos);
	gi->ypos = de_getu16le(pos+2);
	de_dbg(c, "image position: (%d,%d)", (int)gi->xpos, (int)gi->ypos);
	gi->width = de_getu16le(pos+4);
	gi->height = de_getu16le(pos+6);
	de_dbg(c, "image dimensions: %d"DE_CHAR_TIMES"%d", (int)gi->width, (int)gi->height);

	packed_fields = de_getbyte(pos+8);
	de_dbg(c, "packed fields: 0x%02x", (unsigned int)packed_fields);
	de_dbg_indent(c, 1);
	gi->has_local_color_table = (packed_fields&0x80)?1:0;
	de_dbg(c, "local color table flag: %d", (int)gi->has_local_color_table);

	gi->interlaced = (packed_fields&0x40)?1:0;
	de_dbg(c, "interlaced: %d", (int)gi->interlaced);

	if(gi->has_local_color_table) {
		unsigned int sf;
		sf = (packed_fields&0x08)?1:0;
		de_dbg(c, "local color table sorted: %u", sf);
	}

	if(gi->has_local_color_table) {
		local_color_table_size_code = (unsigned int)(packed_fields&0x07);
		gi->local_color_table_size = de_pow2((i64)local_color_table_size_code+1);
		de_dbg(c, "local color table size: %u (%d colors)",
			local_color_table_size_code, (int)gi->local_color_table_size);
	}
	de_dbg_indent(c, -1);

	de_dbg_indent(c, -1);
}

static void do_create_interlace_map(deark *c, lctx *d, struct gif_image_data *gi)
{
	int pass;
	i64 startrow, rowskip;
	i64 row;
	i64 rowcount = 0;

	if(!gi->interlaced) return;
	gi->interlace_map = de_mallocarray(c, gi->height, sizeof(u16));

	for(pass=1; pass<=4; pass++) {
		if(pass==1) { startrow=0; rowskip=8; }
		else if(pass==2) { startrow=4; rowskip=8; }
		else if(pass==3) { startrow=2; rowskip=4; }
		else { startrow=1; rowskip=2; }

		for(row=startrow; row<gi->height; row+=rowskip) {
			gi->interlace_map[rowcount] = (u16)row;
			rowcount++;
		}
	}
}

struct my_giflzw_userdata {
	deark *c;
	lctx *d;
	struct gif_image_data *gi;
};

static void my_giflzw_write_cb(dbuf *f, void *userdata,
	const u8 *buf, i64 size)
{
	i64 i;
	struct my_giflzw_userdata *u = (struct my_giflzw_userdata*)userdata;

	for(i=0; i<(i64)size; i++) {
		do_record_pixel(u->c, u->d, u->gi,
			buf[i], i);
	}
	u->gi->pixels_set += (i64)size;
}

static void callback_for_image_subblock(deark *c, lctx *d, struct subblock_reader_data *sbrd)
{
	struct gif_image_data *gi = (struct gif_image_data*)sbrd->userdata;

	if(sbrd->reported_dlen==0) {
		de_dbg(c, "block terminator at %"I64_FMT, sbrd->subblkpos);
		return;
	}
	de_dbg2(c, "sub-block at %"I64_FMT", size=%"I64_FMT, sbrd->subblkpos, sbrd->reported_dlen);

	if(!gi->failure_flag && !gi->dfctx->finished_flag) {
		de_dfilter_addslice(gi->dfctx, sbrd->inf, sbrd->dpos, sbrd->dlen);
	}
}

// Returns nonzero if parsing can continue.
// If an image was successfully decoded, also sets gi->img.
static int do_image_internal(deark *c, lctx *d,
	struct gif_image_data *gi, i64 pos1, i64 *bytesused)
{
	int retval = 0;
	i64 pos;
	int bypp;
	int saved_indent_level;
	unsigned int lzw_min_code_size;
	i64 npixels_total;
	dbuf *custom_outf = NULL;
	struct de_lzw_params delzwp;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct my_giflzw_userdata u;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = pos1;
	*bytesused = 0;
	gi->failure_flag = 0;
	gi->dfctx = NULL;

	do_read_image_header(c, d, gi, pos);
	pos += 9;

	if(gi->has_local_color_table) {
		de_dbg(c, "local color table at %d", (int)pos);
		de_dbg_indent(c, 1);
		do_read_color_table(c, d, pos, gi->local_color_table_size, gi->local_ct);
		de_dbg_indent(c, -1);
		pos += 3*gi->local_color_table_size;
	}

	if(c->infile->len-pos < 1) {
		on_unexpected_eof(c, d);
		goto done;
	}
	de_dbg(c, "image data at %d", (int)pos);
	de_dbg_indent(c, 1);
	lzw_min_code_size = (unsigned int)de_getbyte(pos++);
	de_dbg(c, "lzw min code size: %u", lzw_min_code_size);

	// Using a failure_flag variable like this is ugly, but I don't like any
	// of the other options either, short of a major redesign of this module.
	// We have to continue to parse the image segment, even after most errors,
	// so that we know where it ends.

	if(gi->width==0 || gi->height==0) {
		// This doesn't seem to be forbidden by the spec.
		de_warn(c, "Image has zero size (%d"DE_CHAR_TIMES"%d)", (int)gi->width, (int)gi->height);
		gi->failure_flag = 1;
	}
	else if(!de_good_image_dimensions(c, gi->width, gi->height)) {
		gi->failure_flag = 1;
	}

	if(d->gce && d->gce->trns_color_idx_valid)
		bypp = 4;
	else
		bypp = 3;

	if(gi->failure_flag) {
		gi->img = de_bitmap_create(c, 1, 1, 1);
	}
	else {
		gi->img = de_bitmap_create(c, gi->width, gi->height, bypp);
	}

	if(gi->interlaced && !gi->failure_flag) {
		do_create_interlace_map(c, d, gi);
	}

	npixels_total = gi->width * gi->height;

	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);
	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	de_zeromem(&u, sizeof(struct my_giflzw_userdata));
	custom_outf = dbuf_create_custom_dbuf(c, 0, 0);
	dbuf_enable_wbuffer(custom_outf);
	u.c = c;
	u.d = d;
	u.gi = gi;
	custom_outf->userdata_for_customwrite = (void*)&u;
	custom_outf->customwrite_fn = my_giflzw_write_cb;
	delzwp.fmt = DE_LZWFMT_GIF;
	delzwp.gif_root_code_size = lzw_min_code_size;
	dcmpro.f = custom_outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = npixels_total;

	gi->dfctx = de_dfilter_create(c, dfilter_lzw_codec, &delzwp, &dcmpro, &dres);

	do_read_subblocks_p(c, d, c->infile, callback_for_image_subblock, (void*)gi, &pos);
	*bytesused = pos - pos1;
	retval = 1;

	if(gi->failure_flag) {
		goto done;
	}

	de_dfilter_finish(gi->dfctx);
	dbuf_flush(custom_outf);

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(gi->pixels_set < npixels_total) {
		de_warn(c, "Expected %"I64_FMT" pixels, only found %"I64_FMT, npixels_total, gi->pixels_set);
	}

done:
	if(gi->failure_flag) {
		de_bitmap_destroy(gi->img);
		gi->img = NULL;
	}
	if(gi->dfctx) {
		de_dfilter_destroy(gi->dfctx);
		gi->dfctx = NULL;
	}
	dbuf_close(custom_outf);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_image(deark *c, lctx *d, i64 pos1, i64 *bytesused)
{
	int retval = 0;
	struct gif_image_data *gi = NULL;
	de_bitmap *prev_img = NULL;
	u8 disposal_method = 0;

	de_dbg_indent(c, 1);
	gi = de_malloc(c, sizeof(struct gif_image_data));

	retval = do_image_internal(c, d, gi, pos1, bytesused);

	if(!retval) goto done;
	if(d->bad_screen_flag || !gi->img) {
		de_warn(c, "Skipping image due to errors");
		retval = 1;
		goto done;
	}

	if(d->compose) {
		if(d->gce) {
			disposal_method = d->gce->disposal_method;
		}

		if(disposal_method == DISPOSE_PREVIOUS) {
			// In this case, we need to save a copy of the pixels that may
			// be overwritten
			prev_img = de_bitmap_create(c, gi->width, gi->height, 4);
			de_bitmap_copy_rect(d->screen_img, prev_img,
				gi->xpos, gi->ypos, gi->width, gi->height,
				0, 0, 0);
		}

		de_bitmap_copy_rect(gi->img, d->screen_img,
			0, 0, d->screen_img->width, d->screen_img->height,
			gi->xpos, gi->ypos, DE_BITMAPFLAG_MERGE);

		de_bitmap_write_to_file_finfo(d->screen_img, d->fi, 0);

		if(disposal_method == DISPOSE_BKGD) {
			de_bitmap_rect(d->screen_img, gi->xpos, gi->ypos, gi->width, gi->height,
				DE_STOCKCOLOR_TRANSPARENT, 0);
		}
		else if(disposal_method == DISPOSE_PREVIOUS && prev_img) {
			de_bitmap_copy_rect(prev_img, d->screen_img,
				0, 0, gi->width, gi->height,
				gi->xpos, gi->ypos, 0);
		}
	}
	else {
		de_bitmap_write_to_file_finfo(gi->img, d->fi, 0);
	}

done:
	de_bitmap_destroy(prev_img);
	if(gi) {
		de_bitmap_destroy(gi->img);
		de_free(c, gi->interlace_map);
		de_free(c, gi);
	}

	// A Graphic Control Extension applies only to the next image (or plaintext
	// extension), so if there was one, delete it now that we've used it up.
	discard_current_gce_data(c, d);

	de_dbg_indent(c, -1);
	return retval;
}

static void do_after_trailer(deark *c, lctx *d, i64 pos1)
{
	i64 extra_bytes_at_eof;
	u8 first_byte;

	extra_bytes_at_eof = c->infile->len - pos1;
	if(extra_bytes_at_eof<=0) return;

	// If all extra bytes are 0x00, or all are 0x1a, don't report it.
	first_byte = de_getbyte(pos1);
	if(first_byte==0x00 || first_byte==0x1a) {
		i64 i;
		u8 flag = 0;

		for(i=1; i<extra_bytes_at_eof; i++) {
			if(de_getbyte(pos1+i)!=first_byte) {
				flag = 1;
				break;
			}
		}
		if(!flag) return;
	}

	de_info(c, "Note: %"I64_FMT" bytes of unidentified data found at end "
		"of file (starting at %"I64_FMT").", extra_bytes_at_eof, pos1);
}

static void de_run_gif(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	i64 bytesused = 0;
	u8 block_type;
	const char *blk_name;

	d = de_malloc(c, sizeof(lctx));
	d->compose = 1;
	d->fi = de_finfo_create(c);

	if(de_get_ext_option(c, "gif:raw")) {
		d->compose = 0;
		// TODO: It would be more consistent to extract an *image* of each
		// plain text extension, but we don't support that, so extract them
		// as text files instead.
		d->dump_plaintext_ext = 1;
	}
	if(de_get_ext_option(c, "gif:dumpplaintext")) {
		d->dump_plaintext_ext = 1;
	}
	if(de_get_ext_option(c, "gif:dumpscreen")) {
		// This lets the user see what the screen looks like after the last
		// "graphic rendering block" has been disposed of.
		d->dump_screen = 1;
	}

	pos = 0;
	if(!do_read_header(c, d, pos)) goto done;
	pos += 6;
	if(!do_read_screen_descriptor(c, d, pos)) goto done;
	pos += 7;
	if(!do_read_global_color_table(c, d, pos, &bytesused)) goto done;
	pos += bytesused;

	// If we're fully rendering the frames, create a "screen" image to
	// track the current state of the animation.
	if(d->compose) {
		if(!de_good_image_dimensions(c, d->screen_w, d->screen_h)) {
			// Try to continue. There could be other interesting things in the file.
			d->bad_screen_flag = 1;
			d->screen_w = 1;
			d->screen_h = 1;
		}
		d->screen_img = de_bitmap_create(c, d->screen_w, d->screen_h, 4);
	}

	while(1) {
		if(pos >= c->infile->len) {
			on_unexpected_eof(c, d);
			goto done;
		}
		block_type = de_getbyte(pos);

		switch(block_type) {
		case 0x2c: blk_name="image"; break;
		case 0x3b: blk_name="trailer"; break;
		case 0x21: blk_name="extension"; break;
		default: blk_name="?"; break;
		}

		de_dbg(c, "block type 0x%02x (%s) at %"I64_FMT, (UI)block_type, blk_name, pos);
		pos++;

		switch(block_type) {
		case 0x3b:
			goto found_trailer;
		case 0x21:
			if(!do_read_extension(c, d, pos, &bytesused)) goto done;
			pos += bytesused;
			break;
		case 0x2c:
			if(!do_image(c, d, pos, &bytesused)) goto done;
			pos += bytesused;
			break;
		default:
			de_err(c, "Unknown block type: 0x%02x", (unsigned int)block_type);
			goto done;
		}
	}

found_trailer:
	do_after_trailer(c, d, pos);

done:
	if(d) {
		if(d->screen_img) {
			if(d->dump_screen) {
				de_finfo_set_name_from_sz(c, d->fi, "screen", 0, DE_ENCODING_LATIN1);
				de_bitmap_write_to_file_finfo(d->screen_img, d->fi, 0);
				de_finfo_set_name_from_sz(c, d->fi, NULL, 0, DE_ENCODING_LATIN1);
			}
			de_bitmap_destroy(d->screen_img);
		}
		discard_current_gce_data(c, d);
		de_finfo_destroy(c, d->fi);
		de_free(c, d);
	}
}

static int de_identify_gif(deark *c)
{
	u8 buf[6];

	de_read(buf, 0, 6);
	if(!de_memcmp(buf, "GIF87a", 6)) return 100;
	if(!de_memcmp(buf, "GIF89a", 6)) return 100;
	return 0;
}

static void de_help_gif(deark *c)
{
	de_msg(c, "-opt gif:raw : Extract individual component images");
	de_msg(c, "-opt gif:dumpplaintext : Also extract plain text extensions to text files");
	de_msg(c, "-opt gif:dumpscreen : Also extract the final \"screen\" contents");
}

void de_module_gif(deark *c, struct deark_module_info *mi)
{
	mi->id = "gif";
	mi->desc = "GIF image";
	mi->run_fn = de_run_gif;
	mi->identify_fn = de_identify_gif;
	mi->help_fn = de_help_gif;
}
