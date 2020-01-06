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

	i64 screen_w, screen_h;
	int has_global_color_table;
	i64 global_color_table_size; // Number of colors stored in the file
	u32 global_ct[256];

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
	i64 local_color_table_size;
	u16 *interlace_map;
	u32 local_ct[256];
};

static void do_record_pixel(deark *c, lctx *d, struct gif_image_data *gi, unsigned int coloridx,
	i64 offset)
{
	i64 pixnum;
	i64 xi, yi;
	i64 yi1;
	u32 clr;

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
	u32 *ct)
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

static void do_skip_subblocks(deark *c, lctx *d, i64 pos1, i64 *bytesused)
{
	i64 pos;
	i64 n;

	pos = pos1;
	while(1) {
		if(pos >= c->infile->len) break;
		n = (i64)de_getbyte(pos++);
		if(n==0) break;
		pos += n;
	}
	*bytesused = pos - pos1;
	return;
}

static void do_copy_subblocks_to_dbuf(deark *c, lctx *d, dbuf *outf,
	i64 pos1, int has_max, i64 maxlen)
{
	i64 pos = pos1;
	i64 nbytes_copied = 0;

	while(1) {
		i64 n;
		i64 nbytes_to_copy;

		if(pos >= c->infile->len) break;
		if(has_max && (nbytes_copied >= maxlen)) break;
		n = (i64)de_getbyte_p(&pos);
		if(n==0) break;
		nbytes_to_copy = n;
		if(has_max) {
			if(nbytes_copied + nbytes_to_copy > maxlen) {
				nbytes_to_copy = maxlen - nbytes_copied;
			}
		}
		dbuf_copy(c->infile, pos, nbytes_to_copy, outf);
		nbytes_copied += nbytes_to_copy;
		pos += n;
	}
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

static void do_comment_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *f = NULL;
	de_ucstring *s = NULL;
	i64 n;

	// Either write the comment to a file, or store it in a string.
	if(c->extract_level>=2) {
		f = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		s = ucstring_create(c);
	}

	while(1) {
		if(pos >= c->infile->len) break;
		n = (i64)de_getbyte(pos++);
		if(n==0) break;

		if(f) {
			// GIF comments are supposed to be 7-bit ASCII, so just copy them as-is.
			dbuf_copy(c->infile, pos, n, f);
		}
		if(s && s->len<DE_DBG_MAX_STRLEN) {
			dbuf_read_to_ucstring(c->infile, pos, n, s, 0, DE_ENCODING_ASCII);
		}

		pos += n;
	}

	if(s) {
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(s));
	}
	dbuf_close(f);
}

static void decode_text_color(deark *c, lctx *d, const char *name, u8 clr_idx,
	u32 *pclr)
{
	u32 clr;
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
	u32 fgclr, u32 bgclr)
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
			u32 clr;

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

static void do_plaintext_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *f = NULL;
	i64 n;
	i64 text_pos_x, text_pos_y; // In pixels
	i64 text_size_x, text_size_y; // In pixels
	i64 text_width_in_chars;
	i64 char_width, char_height;
	i64 char_count;
	i64 k;
	u32 fgclr, bgclr;
	u8 fgclr_idx, bgclr_idx;
	u8 b;
	unsigned char disposal_method = 0;
	int ok_to_render = 1;
	de_bitmap *prev_img = NULL;

	// The first sub-block is the header
	n = (i64)de_getbyte(pos++);
	if(n<12) goto done;

	if(d->gce) {
		disposal_method = d->gce->disposal_method;
	}

	if(!d->compose) {
		ok_to_render = 0;
	}

	text_pos_x = de_getu16le(pos);
	text_pos_y = de_getu16le(pos+2);
	text_size_x = de_getu16le(pos+4);
	text_size_y = de_getu16le(pos+6);
	char_width = (i64)de_getbyte(pos+8);
	char_height = (i64)de_getbyte(pos+9);
	de_dbg(c, "text-area pos: %d,%d pixels", (int)text_pos_x, (int)text_pos_y);
	de_dbg(c, "text-area size: %d"DE_CHAR_TIMES"%d pixels", (int)text_size_x, (int)text_size_y);
	de_dbg(c, "character size: %d"DE_CHAR_TIMES"%d pixels", (int)char_width, (int)char_height);

	if(char_width<3 || char_height<3) {
		ok_to_render = 0;
	}

	if(char_width>0) {
		text_width_in_chars = text_size_x / char_width;
		if(text_width_in_chars<1) text_width_in_chars = 1;
	}
	else {
		text_width_in_chars = 80;
	}
	de_dbg(c, "calculated chars/line: %d", (int)text_width_in_chars);

	fgclr_idx = de_getbyte(pos+10);
	decode_text_color(c, d, "fg", fgclr_idx, &fgclr);
	bgclr_idx = de_getbyte(pos+11);
	decode_text_color(c, d, "bg", bgclr_idx, &bgclr);

	pos += n;

	if(d->dump_plaintext_ext) {
		f = dbuf_create_output_file(c, "plaintext.txt", NULL, 0);
	}

	if(ok_to_render && (disposal_method==DISPOSE_PREVIOUS)) {
		i64 tmpw, tmph;
		// We need to save a copy of the pixels that may be overwritten.
		tmpw = text_size_x;
		if(tmpw>d->screen_w) tmpw = d->screen_w;
		tmph = text_size_y;
		if(tmph>d->screen_h) tmph = d->screen_h;
		prev_img = de_bitmap_create(c, tmpw, tmph, 4);
		de_bitmap_copy_rect(d->screen_img, prev_img,
			text_pos_x, text_pos_y, text_size_x, text_size_y,
			0, 0, 0);
	}

	char_count = 0;
	while(1) {
		if(pos >= c->infile->len) break;
		n = (i64)de_getbyte(pos++);
		if(n==0) break;

		for(k=0; k<n; k++) {
			b = dbuf_getbyte(c->infile, pos+k);
			if(f) dbuf_writebyte(f, b);

			if(ok_to_render) {
				render_plaintext_char(c, d, b,
					text_pos_x + (char_count%text_width_in_chars)*char_width,
					text_pos_y + (char_count/text_width_in_chars)*char_height,
					char_width, char_height, fgclr, bgclr);
			}

			char_count++;

			// Insert newlines in appropriate places.
			if(f) {
				if(char_count%text_width_in_chars == 0) {
					dbuf_writebyte(f, '\n');
				}
			}
		}
		pos += n;
	}

	if(d->compose) {
		de_bitmap_write_to_file_finfo(d->screen_img, d->fi, DE_CREATEFLAG_OPT_IMAGE);

		// TODO: Too much code is duplicated with do_image().
		if(disposal_method==DISPOSE_BKGD) {
			de_bitmap_rect(d->screen_img, text_pos_x, text_pos_y, text_size_x, text_size_y,
				DE_STOCKCOLOR_TRANSPARENT, 0);
		}
		else if(disposal_method==DISPOSE_PREVIOUS && prev_img) {
			de_bitmap_copy_rect(prev_img, d->screen_img,
				0, 0, text_size_x, text_size_y,
				text_pos_x, text_pos_y, 0);
		}
	}

done:
	dbuf_close(f);
	de_bitmap_destroy(prev_img);
	discard_current_gce_data(c, d);
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
	de_fmtutil_handle_photoshop_rsrc(c, tmpf, 0, tmpf->len, 0x0);
	dbuf_close(tmpf);
}

static void do_mgkiptc_extension(deark *c, lctx *d, i64 pos)
{
	dbuf *tmpf = NULL;
	tmpf = dbuf_create_membuf(c, 0, 0);
	do_copy_subblocks_to_dbuf(c, d, tmpf, pos, 1, 4*1048576);
	de_fmtutil_handle_iptc(c, tmpf, 0, tmpf->len, 0x0);
	dbuf_close(tmpf);
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
	}
	de_dbg_indent(c, -1);

	do_skip_subblocks(c, d, pos, &bytesused2);
	pos += bytesused2;

	*bytesused = pos - pos1;
	de_dbg_indent(c, -1);

	return 1;
}

// Read 9-byte image header
static void do_read_image_descriptor(deark *c, lctx *d, struct gif_image_data *gi, i64 pos)
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

// Returns nonzero if parsing can continue.
// If an image was successfully decoded, also sets gi->img.
static int do_image_internal(deark *c, lctx *d,
	struct gif_image_data *gi, i64 pos1, i64 *bytesused)
{
	int retval = 0;
	i64 pos;
	i64 n;
	int bypp;
	int failure_flag = 0;
	int saved_indent_level;
	unsigned int lzw_min_code_size;
	i64 npixels_total;
	dbuf *custom_outf = NULL;
	struct de_dfilter_ctx *dfctx = NULL;
	struct delzw_params delzwp;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct my_giflzw_userdata u;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = pos1;
	*bytesused = 0;

	do_read_image_descriptor(c, d, gi, pos);
	pos += 9;

	if(gi->has_local_color_table) {
		de_dbg(c, "local color table at %d", (int)pos);
		de_dbg_indent(c, 1);
		do_read_color_table(c, d, pos, gi->local_color_table_size, gi->local_ct);
		de_dbg_indent(c, -1);
		pos += 3*gi->local_color_table_size;
	}

	if(c->infile->len-pos < 1) {
		de_err(c, "Unexpected end of file");
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
		failure_flag = 1;
	}
	else if(!de_good_image_dimensions(c, gi->width, gi->height)) {
		failure_flag = 1;
	}

	if(d->gce && d->gce->trns_color_idx_valid)
		bypp = 4;
	else
		bypp = 3;

	if(failure_flag) {
		gi->img = de_bitmap_create(c, 1, 1, 1);
	}
	else {
		gi->img = de_bitmap_create(c, gi->width, gi->height, bypp);
	}

	if(gi->interlaced && !failure_flag) {
		do_create_interlace_map(c, d, gi);
	}

	npixels_total = gi->width * gi->height;

	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);
	de_zeromem(&delzwp, sizeof(struct delzw_params));
	de_zeromem(&u, sizeof(struct my_giflzw_userdata));
	custom_outf = dbuf_create_custom_dbuf(c, 0, 0);
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

	dfctx = de_dfilter_create_delzw(c, &delzwp, &dcmpro, &dres);

	while(1) {
		if(pos >= c->infile->len) goto done;
		n = (i64)de_getbyte(pos);
		if(n==0)
			de_dbg(c, "block terminator at %d", (int)pos);
		else
			de_dbg2(c, "sub-block at %d, size=%d", (int)pos, (int)n);
		pos++;
		if(n==0) break;

		if(!failure_flag && !dfctx->finished_flag) {
			u8 buf[255];

			de_read(buf, pos, n);
			de_dfilter_addbuf(dfctx, buf, n);
		}

		pos += n;
	}

	*bytesused = pos - pos1;
	retval = 1;

	if(failure_flag) {
		goto done;
	}

	de_dfilter_finish(dfctx);

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(gi->pixels_set < npixels_total) {
		de_warn(c, "Expected %"I64_FMT" pixels, only found %"I64_FMT, npixels_total, gi->pixels_set);
	}

done:
	if(failure_flag) {
		de_bitmap_destroy(gi->img);
		gi->img = NULL;
	}
	de_dfilter_destroy(dfctx);
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

		de_bitmap_write_to_file_finfo(d->screen_img, d->fi, DE_CREATEFLAG_OPT_IMAGE);

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
			de_err(c, "Unexpected end of file");
			break;
		}
		block_type = de_getbyte(pos);

		switch(block_type) {
		case 0x2c: blk_name="image"; break;
		case 0x3b: blk_name="trailer"; break;
		case 0x21: blk_name="extension"; break;
		default: blk_name="?"; break;
		}

		de_dbg(c, "block type 0x%02x (%s) at %d", (unsigned int)block_type, blk_name, (int)pos);
		pos++;

		if(block_type==0x3b) {
			break; // Trailer
		}

		switch(block_type) {
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

done:
	if(d) {
		if(d->screen_img) {
			if(d->dump_screen) {
				de_finfo_set_name_from_sz(c, d->fi, "screen", 0, DE_ENCODING_LATIN1);
				de_bitmap_write_to_file_finfo(d->screen_img, d->fi, DE_CREATEFLAG_OPT_IMAGE);
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
	de_msg(c, "-opt gif:dumpscreen : Also extact the final \"screen\" contents");
}

void de_module_gif(deark *c, struct deark_module_info *mi)
{
	mi->id = "gif";
	mi->desc = "GIF image";
	mi->run_fn = de_run_gif;
	mi->identify_fn = de_identify_gif;
	mi->help_fn = de_help_gif;
}
