// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// GIF image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_gif);

#define DISPOSE_LEAVE     1
#define DISPOSE_BKGD      2
#define DISPOSE_PREVIOUS  3

struct gceinfo {
	de_byte disposal_method;
};

typedef struct localctx_struct {
	int compose;

	de_int64 screen_w, screen_h;
	int has_global_color_table;
	de_byte aspect_ratio_code;
	de_int64 global_color_table_size; // Number of colors stored in the file
	de_uint32 global_ct[256];

	// This should really be in a separate struct (or maybe in gif_image_data),
	// but it's not worth it for just one field.
	int graphic_control_ext_data_valid;
	int trns_color_idx_valid;
	de_byte trns_color_idx;

	struct deark_bitmap *screen_img;
	struct gceinfo *gce; // The Graphic Control Ext. in effect for the next image
} lctx;

// Data about a single image
struct gif_image_data {
	struct deark_bitmap *img;
	de_int64 xpos, ypos;
	de_int64 width, height;
	de_int64 pixels_set;
	int interlaced;
	int has_local_color_table;
	de_int64 local_color_table_size;
	de_uint16 *interlace_map;
	de_uint32 local_ct[256];
};

static void do_record_pixel(deark *c, lctx *d, struct gif_image_data *gi, unsigned int coloridx,
	int offset)
{
	de_int64 pixnum;
	de_int64 xi, yi;
	de_int64 yi1;
	de_uint32 clr;

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

	if(d->graphic_control_ext_data_valid && d->trns_color_idx_valid &&
		(d->trns_color_idx == coloridx))
	{
		// Make this pixel transparent
		clr = DE_SET_ALPHA(clr, 0);
	}
	else {
		clr = DE_SET_ALPHA(clr, 0xff);
	}

	de_bitmap_setpixel_rgb(gi->img, xi, yi, clr);
}

////////////////////////////////////////////////////////
//                    LZW decoder
////////////////////////////////////////////////////////

struct lzw_tableentry {
	de_uint16 parent; // pointer to previous table entry (if not a root code)
	de_uint16 length;
	de_byte firstchar;
	de_byte lastchar;
};

struct lzwdeccontext {
	unsigned int root_codesize;
	unsigned int current_codesize;
	int eoi_flag;
	unsigned int oldcode;
	unsigned int pending_code;
	unsigned int bits_in_pending_code;
	unsigned int num_root_codes;
	int ncodes_since_clear;

	unsigned int clear_code;
	unsigned int eoi_code;
	unsigned int last_code_added;

	unsigned int ct_used; // Number of items used in the code table
	struct lzw_tableentry ct[4096]; // Code table
};

static int lzw_init(deark *c, struct lzwdeccontext *lz, unsigned int root_codesize)
{
	unsigned int i;

	de_memset(lz, 0, sizeof(struct lzwdeccontext));

	if(root_codesize<2 || root_codesize>11) {
		de_err(c, "Invalid LZW root codesize (%u)\n", root_codesize);
		return 0;
	}

	lz->root_codesize = root_codesize;
	lz->num_root_codes = 1<<lz->root_codesize;
	lz->clear_code = lz->num_root_codes;
	lz->eoi_code = lz->num_root_codes+1;
	for(i=0; i<lz->num_root_codes; i++) {
		lz->ct[i].parent = 0;
		lz->ct[i].length = 1;
		lz->ct[i].lastchar = (de_byte)i;
		lz->ct[i].firstchar = (de_byte)i;
	}

	return 1;
}

static void lzw_clear(struct lzwdeccontext *lz)
{
	lz->ct_used = lz->num_root_codes+2;
	lz->current_codesize = lz->root_codesize+1;
	lz->ncodes_since_clear=0;
	lz->oldcode=0;
}

// Decode an LZW code to one or more pixels, and record it in the image.
static void lzw_emit_code(deark *c, lctx *d, struct gif_image_data *gi, struct lzwdeccontext *lz,
		unsigned int first_code)
{
	unsigned int code;
	code = first_code;

	// An LZW code may decode to more than one pixel. Note that the pixels for
	// an LZW code are decoded in reverse order (right to left).

	while(1) {
		do_record_pixel(c, d, gi, (unsigned int)lz->ct[code].lastchar, (int)(lz->ct[code].length-1));
		if(lz->ct[code].length<=1) break;
		// The codes are structured as a "forest" (multiple trees).
		// Go to the parent code, which will have a length 1 less than this one.
		code = (unsigned int)lz->ct[code].parent;
	}

	// Track the total number of pixels decoded in this image.
	gi->pixels_set += lz->ct[first_code].length;
}

// Add a code to the dictionary.
// Sets d->last_code_added to the position where it was added.
// Returns 1 if successful, 2 if table is full, 0 on error.
static int lzw_add_to_dict(deark *c, struct lzwdeccontext *lz, unsigned int oldcode, de_byte val)
{
	static const unsigned int last_code_of_size[] = {
		// The first 3 values are unused.
		0,0,0,7,15,31,63,127,255,511,1023,2047,4095
	};
	unsigned int newpos;

	if(lz->ct_used>=4096) {
		lz->last_code_added = 0;
		return 2;
	}

	newpos = lz->ct_used;

	if(oldcode >= newpos) {
		de_err(c, "GIF decoding error\n");
		return 0;
	}

	lz->ct_used++;

	lz->ct[newpos].parent = (de_uint16)oldcode;
	lz->ct[newpos].length = lz->ct[oldcode].length + 1;
	lz->ct[newpos].firstchar = lz->ct[oldcode].firstchar;
	lz->ct[newpos].lastchar = val;

	// If we've used the last code of this size, we need to increase the codesize.
	if(newpos == last_code_of_size[lz->current_codesize]) {
		if(lz->current_codesize<12) {
			lz->current_codesize++;
		}
	}

	lz->last_code_added = newpos;

	return 1;
}

// Process a single LZW code that was read from the input stream.
static int lzw_process_code(deark *c, lctx *d, struct gif_image_data *gi, struct lzwdeccontext *lz,
		unsigned int code)
{
	int ret;

	if(code==lz->eoi_code) {
		lz->eoi_flag=1;
		return 1;
	}

	if(code==lz->clear_code) {
		lzw_clear(lz);
		return 1;
	}

	lz->ncodes_since_clear++;

	if(lz->ncodes_since_clear==1) {
		// Special case for the first code.
		lzw_emit_code(c, d, gi, lz, code);
		lz->oldcode = code;
		return 1;
	}

	// Is code in code table?
	if(code < lz->ct_used) {
		// Yes, code is in table.
		lzw_emit_code(c, d, gi, lz, code);

		// Let k = the first character of the translation of the code.
		// Add <oldcode>k to the dictionary.
		ret = lzw_add_to_dict(c, lz,lz->oldcode,lz->ct[code].firstchar);
		if(ret==0) return 0;
	}
	else {
		// No, code is not in table.
		if(lz->oldcode>=lz->ct_used) {
			de_err(c, "GIF decoding error\n");
			return 0;
		}

		// Let k = the first char of the translation of oldcode.
		// Add <oldcode>k to the dictionary.
		ret = lzw_add_to_dict(c, lz,lz->oldcode,lz->ct[lz->oldcode].firstchar);
		if(ret==0) return 0;
		if(ret==1) {
			// Write <oldcode>k to the output stream.
			lzw_emit_code(c, d, gi, lz, lz->last_code_added);
		}
	}
	lz->oldcode = code;

	return 1;
}

// Decode as much as possible of the provided LZW-encoded data.
// Any unfinished business is recorded, to be continued the next time
// this function is called.
static int lzw_process_bytes(deark *c, lctx *d, struct gif_image_data *gi, struct lzwdeccontext *lz,
	de_byte *data, de_int64 data_size)
{
	de_int64 i;
	int b;
	int retval=0;

	for(i=0;i<data_size;i++) {
		// Look at the bits one at a time.
		for(b=0;b<8;b++) {
			if(lz->eoi_flag) { // Stop if we've seen an EOI (end of image) code.
				retval=1;
				goto done;
			}

			if(data[i]&(1<<b))
				lz->pending_code |= 1<<lz->bits_in_pending_code;
			lz->bits_in_pending_code++;

			// When we get enough bits to form a complete LZW code, process it.
			if(lz->bits_in_pending_code >= lz->current_codesize) {
				if(!lzw_process_code(c, d, gi, lz, lz->pending_code)) goto done;
				lz->pending_code=0;
				lz->bits_in_pending_code=0;
			}
		}
	}
	retval=1;

done:
	return retval;
}

////////////////////////////////////////////////////////

static int do_read_screen_descriptor(deark *c, lctx *d, de_int64 pos)
{
	de_int64 bgcol_index;
	de_byte packed_fields;
	unsigned int global_color_table_size_code;

	de_dbg(c, "screen descriptor at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->screen_w = de_getui16le(pos);
	d->screen_h = de_getui16le(pos+2);
	de_dbg(c, "screen dimensions: %dx%d\n", (int)d->screen_w, (int)d->screen_h);

	packed_fields = de_getbyte(pos+4);
	d->has_global_color_table = (packed_fields&0x80)?1:0;
	de_dbg(c, "global color table flag: %d\n", d->has_global_color_table);
	if(d->has_global_color_table) {
		global_color_table_size_code = (unsigned int)(packed_fields&0x07);
		d->global_color_table_size = (de_int64)(1<<(global_color_table_size_code+1));
		de_dbg(c, "global color table size: %d colors\n", (int)d->global_color_table_size);
	}

	// We don't care about the background color, because we always assume the
	// background is transparent.
	// TODO: If we ever support writing background-color chunks to PNG files,
	// then we should look up this color and use it.
	bgcol_index = (de_int64)de_getbyte(pos+5);
	de_dbg(c, "background color index: %d\n", (int)bgcol_index);

	d->aspect_ratio_code = de_getbyte(pos+6);
	de_dbg(c, "aspect ratio code: %d\n", (int)d->aspect_ratio_code);

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_color_table(deark *c, lctx *d, de_int64 pos, de_int64 ncolors,
	de_uint32 *ct)
{
	de_read_palette_rgb(c->infile, pos, ncolors, 3, ct, 256, 0);
}

static int do_read_global_color_table(deark *c, lctx *d, de_int64 pos, de_int64 *bytesused)
{

	if(!d->has_global_color_table) return 1;
	de_dbg(c, "global color table at %d\n", (int)pos);

	de_dbg_indent(c, 1);
	do_read_color_table(c, d, pos, d->global_color_table_size, d->global_ct);
	de_dbg_indent(c, -1);

	*bytesused = 3*d->global_color_table_size;
	return 1;
}

static void do_skip_subblocks(deark *c, lctx *d, de_int64 pos1, de_int64 *bytesused)
{
	de_int64 pos;
	de_int64 n;

	pos = pos1;
	while(1) {
		if(pos >= c->infile->len) break;
		n = (de_int64)de_getbyte(pos);
		pos++;
		if(n==0) break;
		pos += n;
	}
	*bytesused = pos - pos1;
	return;
}

static void do_graphic_control_extension(deark *c, lctx *d, de_int64 pos)
{
	de_byte packed_fields;
	de_byte user_input_flag;
	de_int64 delay_time_raw;
	double delay_time;
	const char *name;

	if(d->gce) {
		de_free(c, d->gce);
		d->gce = NULL;
	}
	d->gce = de_malloc(c, sizeof(struct gceinfo));
	d->graphic_control_ext_data_valid = 1;
	d->trns_color_idx_valid = 0;

	// 0 = block size (we assume this is 4 or more)
	packed_fields = de_getbyte(pos+1);
	d->trns_color_idx_valid = packed_fields&0x01;
	de_dbg(c, "has transparency: %d\n", d->trns_color_idx_valid);

	user_input_flag = (packed_fields>>1)&0x1;
	de_dbg(c, "user input flag: %d\n", (int)user_input_flag);

	d->gce->disposal_method = (packed_fields>>2)&0x7;
	switch(d->gce->disposal_method) {
	case 0: name="unspecified"; break;
	case DISPOSE_LEAVE: name="leave in place"; break;
	case DISPOSE_BKGD: name="restore to background"; break;
	case DISPOSE_PREVIOUS: name="restore to previous"; break;
	default: name="?";
	}
	de_dbg(c, "disposal method: %d (%s)\n", (int)d->gce->disposal_method, name);

	delay_time_raw = de_getui16le(pos+2);
	delay_time = ((double)delay_time_raw)/100.0;
	de_dbg(c, "delay time: %.02f sec\n", delay_time);

	if(d->trns_color_idx_valid) {
		d->trns_color_idx = de_getbyte(pos+4);
		de_dbg(c, "transparent color index: %d\n", (int)d->trns_color_idx);
	}
}

static void do_comment_extension(deark *c, lctx *d, de_int64 pos)
{
	dbuf *f = NULL;
	de_int64 n;

	if(c->extract_level<2) return;

	f = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);

	while(1) {
		if(pos >= c->infile->len) break;
		n = (de_int64)de_getbyte(pos);
		pos++;
		if(n==0) break;

		// GIF comments are supposed to be 7-bit ASCII, so just copy them as-is.
		dbuf_copy(c->infile, pos, n, f);
		pos += n;
	}

	dbuf_close(f);
}

static void do_plaintext_extension(deark *c, lctx *d, de_int64 pos)
{
	dbuf *f = NULL;
	de_int64 n;
	de_int64 text_width_in_pixels;
	de_int64 text_width_in_chars;
	de_int64 char_width;
	de_int64 char_count;
	de_int64 k;
	de_byte b;

	if(c->extract_level<2) return;

	// The first sub-block is the header
	n = (de_int64)de_getbyte(pos);
	pos++;
	if(n<12) return;

	text_width_in_pixels = de_getui16le(pos+4);
	char_width = (de_int64)de_getbyte(pos+8);
	de_dbg(c, "text-area width: %d pixels\n", (int)text_width_in_pixels);
	de_dbg(c, "character width: %d pixels\n", (int)char_width);

	if(char_width>0) {
		text_width_in_chars = text_width_in_pixels / char_width;
		if(text_width_in_chars<1) text_width_in_chars = 1;
	}
	else {
		text_width_in_chars = 80;
	}
	de_dbg(c, "calculated chars/line: %d\n", (int)text_width_in_chars);

	pos += n;

	f = dbuf_create_output_file(c, "plaintext.txt", NULL, DE_CREATEFLAG_IS_AUX);

	char_count = 0;
	while(1) {
		if(pos >= c->infile->len) break;
		n = (de_int64)de_getbyte(pos);
		pos++;
		if(n==0) break;

		for(k=0; k<n; k++) {
			b = dbuf_getbyte(c->infile, pos+k);
			dbuf_writebyte(f, b);
			char_count++;
			// Insert newlines in appropriate places.
			if(char_count%text_width_in_chars == 0) {
				dbuf_writebyte(f, '\n');
			}
		}
		pos += n;
	}

	dbuf_close(f);
}

static void do_animation_extension(deark *c, lctx *d, de_int64 pos)
{
	de_int64 sub_block_len;
	de_byte sub_block_id;
	const char *name;

	sub_block_len = (de_int64)de_getbyte(pos++);
	if(sub_block_len<1) return;

	sub_block_id = de_getbyte(pos++);
	switch(sub_block_id) {
	case 1: name="looping"; break;
	case 2: name="buffering"; break;
	default: name="?";
	}
	de_dbg(c, "netscape extension type: %d (%s)\n", (int)sub_block_id, name);

	if(sub_block_id==1 && sub_block_len>=3) {
		de_int64 loop_count;
		loop_count = de_getui16le(pos);
		de_dbg(c, "loop count: %d%s\n", (int)loop_count,
			(loop_count==0)?" (infinite)":"");
	}
}

static void do_application_extension(deark *c, lctx *d, de_int64 pos)
{
	de_ucstring *s = NULL;
	de_byte app_id[11];
	de_int64 n;

	n = (de_int64)de_getbyte(pos);
	pos++;
	if(n<11) return;

	de_read(app_id, pos, 11);
	pos += n;

	s = ucstring_create(c);
	ucstring_append_bytes(s, app_id, 11, 0, DE_ENCODING_ASCII);
	de_dbg(c, "app id: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_destroy(s);

	if(!de_memcmp(app_id, "NETSCAPE2.0", 11) ||
		!de_memcmp(app_id, "ANIMEXTS1.0", 11))
	{
		do_animation_extension(c, d, pos);
	}
}

static int do_read_extension(deark *c, lctx *d, de_int64 pos1, de_int64 *bytesused)
{
	de_int64 bytesused2 = 0;
	de_byte ext_type;
	de_int64 pos;
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

	de_dbg(c, "extension type 0x%02x (%s) at %d\n", (unsigned int)ext_type, ext_name, (int)pos);
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
static void do_read_image_descriptor(deark *c, lctx *d, struct gif_image_data *gi, de_int64 pos)
{
	de_byte packed_fields;
	unsigned int local_color_table_size_code;

	de_dbg(c, "image descriptor at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	gi->xpos = de_getui16le(pos);
	gi->ypos = de_getui16le(pos+2);
	de_dbg(c, "image position: (%d,%d)\n", (int)gi->xpos, (int)gi->ypos);
	gi->width = de_getui16le(pos+4);
	gi->height = de_getui16le(pos+6);
	de_dbg(c, "image dimensions: %dx%d\n", (int)gi->width, (int)gi->height);

	packed_fields = de_getbyte(pos+8);
	gi->has_local_color_table = (packed_fields&0x80)?1:0;
	de_dbg(c, "local color table flag: %d\n", (int)gi->has_local_color_table);
	if(gi->has_local_color_table) {
		local_color_table_size_code = (unsigned int)(packed_fields&0x07);
		gi->local_color_table_size = (de_int64)(1<<(local_color_table_size_code+1));
		de_dbg(c, "local color table size: %d colors\n", (int)gi->local_color_table_size);
	}
	gi->interlaced = (packed_fields&0x40)?1:0;
	de_dbg(c, "interlaced: %d\n", (int)gi->interlaced);

	de_dbg_indent(c, -1);
}

static void do_create_interlace_map(deark *c, lctx *d, struct gif_image_data *gi)
{
	int pass;
	de_int64 startrow, rowskip;
	de_int64 row;
	de_int64 rowcount = 0;

	if(!gi->interlaced) return;
	gi->interlace_map = de_malloc(c, gi->height * sizeof(de_uint16));

	for(pass=1; pass<=4; pass++) {
		if(pass==1) { startrow=0; rowskip=8; }
		else if(pass==2) { startrow=4; rowskip=8; }
		else if(pass==3) { startrow=2; rowskip=4; }
		else { startrow=1; rowskip=2; }

		for(row=startrow; row<gi->height; row+=rowskip) {
			gi->interlace_map[rowcount] = (de_uint16)row;
			rowcount++;
		}
	}
}

static int do_image_internal(deark *c, lctx *d,
	struct gif_image_data *gi, de_int64 pos1, de_int64 *bytesused)
{
	int retval = 0;
	de_int64 pos;
	de_int64 n;
	int bypp;
	int saved_indent_level;
	unsigned int lzw_min_code_size;
	struct lzwdeccontext *lz = NULL;
	de_byte buf[256];

	de_dbg_indent_save(c, &saved_indent_level);
	pos = pos1;
	*bytesused = 0;

	do_read_image_descriptor(c, d, gi, pos);
	pos += 9;

	if(gi->has_local_color_table) {
		de_dbg(c, "local color table at %d\n", (int)pos);
		de_dbg_indent(c, 1);
		do_read_color_table(c, d, pos, gi->local_color_table_size, gi->local_ct);
		de_dbg_indent(c, -1);
		pos += 3*gi->local_color_table_size;
	}

	de_dbg(c, "image data at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	lzw_min_code_size = (unsigned int)de_getbyte(pos++);
	de_dbg(c, "lzw min code size: %u\n", lzw_min_code_size);

	if(!de_good_image_dimensions(c, gi->width, gi->height)) goto done;
	if(d->graphic_control_ext_data_valid && d->trns_color_idx_valid)
		bypp = 4;
	else
		bypp = 3;

	gi->img = de_bitmap_create(c, gi->width, gi->height, bypp);

	if(d->aspect_ratio_code!=0 && d->aspect_ratio_code!=49) {
		gi->img->density_code = DE_DENSITY_UNK_UNITS;
		gi->img->xdens = 64.0;
		gi->img->ydens = 15.0 + (double)d->aspect_ratio_code;
	}

	lz = de_malloc(c, sizeof(struct lzwdeccontext));
	if(!lzw_init(c, lz, lzw_min_code_size)) goto done;
	lzw_clear(lz);

	if(gi->interlaced) {
		do_create_interlace_map(c, d, gi);
	}

	while(1) {
		if(pos >= c->infile->len) break;
		n = (de_int64)de_getbyte(pos);
		if(n==0)
			de_dbg(c, "block terminator at %d\n", (int)pos);
		else
			de_dbg2(c, "sub-block at %d, size=%d\n", (int)pos, (int)n);
		pos++;
		if(n==0) break;

		de_read(buf, pos, n);

		if(!lz->eoi_flag) {
			if(!lzw_process_bytes(c, d, gi, lz, buf, n)) {
				goto done;
			}
		}

		pos += n;
	}
	de_dbg_indent(c, -1);

	*bytesused = pos - pos1;

	// Graphic control extensions are only valid for one image, so invalidate
	// any previous extension.
	d->graphic_control_ext_data_valid = 0;

	retval = 1;
done:
	de_free(c, lz);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_image(deark *c, lctx *d, de_int64 pos1, de_int64 *bytesused)
{
	int retval = 0;
	struct gif_image_data *gi = NULL;
	de_byte disposal_method = 0;

	de_dbg_indent(c, 1);
	gi = de_malloc(c, sizeof(struct gif_image_data));
	retval = do_image_internal(c, d, gi, pos1, bytesused);
	if(!retval) goto done;

	if(d->compose) {
		de_bitmap_paint_bitmap(d->screen_img, gi->img, gi->xpos, gi->ypos, 0);
		de_bitmap_write_to_file(d->screen_img, NULL, 0);

		if(d->gce) {
			disposal_method = d->gce->disposal_method;
		}

		if(disposal_method == DISPOSE_BKGD) {
			de_bitmap_rect(d->screen_img, gi->xpos, gi->ypos, gi->width, gi->height,
				DE_STOCKCOLOR_TRANSPARENT, 0);
		}
		// TODO: Support DISPOSE_PREVIOUS
	}
	else {
		de_bitmap_write_to_file(gi->img, NULL, 0);
	}

done:
	if(gi) {
		de_bitmap_destroy(gi->img);
		de_free(c, gi->interlace_map);
		de_free(c, gi);
	}

	if(d->gce) {
		// A Graphic Control Extension applies only to the next image, so
		// if there was one, delete it now that we've used it up.
		de_free(c, d->gce);
		d->gce = NULL;
	}

	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_gif(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 bytesused = 0;
	de_byte block_type;
	const char *blk_name;

	d = de_malloc(c, sizeof(lctx));

	if(de_get_ext_option(c, "gif:test")) {
		d->compose = 1;
	}

	pos = 6;
	if(!do_read_screen_descriptor(c, d, pos)) goto done;
	pos += 7;
	if(!do_read_global_color_table(c, d, pos, &bytesused)) goto done;
	pos += bytesused;

	// If we're fully rendering the frames, create a "screen" image to
	// track the current state of the animation.
	if(d->compose) {
		if(!de_good_image_dimensions(c, d->screen_w, d->screen_h)) {
			goto done;
		}
		d->screen_img = de_bitmap_create(c, d->screen_w, d->screen_h, 4);
	}

	while(1) {
		if(pos >= c->infile->len) break;
		block_type = de_getbyte(pos);

		switch(block_type) {
		case 0x2c: blk_name="image"; break;
		case 0x3b: blk_name="trailer"; break;
		case 0x21: blk_name="extension"; break;
		default: blk_name="?"; break;
		}

		de_dbg(c, "block type 0x%02x (%s) at %d\n", (unsigned int)block_type, blk_name, (int)pos);
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
			de_err(c, "Unknown block type: 0x%02x\n", (unsigned int)block_type);
			goto done;
		}
	}

done:
	if(d) {
		de_bitmap_destroy(d->screen_img);
		de_free(c, d->gce);
		de_free(c, d);
	}
}

static int de_identify_gif(deark *c)
{
	de_byte buf[6];

	de_read(buf, 0, 6);
	if(!de_memcmp(buf, "GIF87a", 6)) return 100;
	if(!de_memcmp(buf, "GIF89a", 6)) return 100;
	return 0;
}

void de_module_gif(deark *c, struct deark_module_info *mi)
{
	mi->id = "gif";
	mi->desc = "GIF image";
	mi->run_fn = de_run_gif;
	mi->identify_fn = de_identify_gif;
}
