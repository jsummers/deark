// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// GIF image

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int has_global_color_table;
	de_int64 global_color_table_size; // number of colors
	de_uint32 global_ct[256];

	// This should really be a separate struct, but it's not worth it for just
	// one field.
	int graphic_control_ext_data_valid;
	int trns_color_idx_valid;
	de_byte trns_color_idx;
} lctx;

struct gif_image_data {
	de_int64 width, height;
	int interlaced;
	int has_local_color_table;
	de_int64 local_color_table_size;
	de_uint32 local_ct[256];
};


static int do_read_screen_descriptor(deark *c, lctx *d, de_int64 pos)
{
	de_int64 sw, sh;
	de_int64 bgcol_index;
	de_byte packed_fields;
	de_byte aspect_ratio_code;
	unsigned int global_color_table_size_code;

	de_dbg(c, "screen descriptor at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	sw = de_getui16le(pos);
	sh = de_getui16le(pos+2);
	de_dbg(c, "screen dimensions: %dx%d\n", (int)sw, (int)sh);

	packed_fields = de_getbyte(pos+4);
	d->has_global_color_table = (packed_fields&0x80)?1:0;
	de_dbg(c, "global color table flag: %d\n", d->has_global_color_table);
	if(d->has_global_color_table) {
		global_color_table_size_code = (unsigned int)(packed_fields&0x07);
		d->global_color_table_size = (de_int64)(1<<(global_color_table_size_code+1));
		de_dbg(c, "global color table size: %d colors\n", (int)d->global_color_table_size);
	}

	bgcol_index = (de_int64)de_getbyte(pos+5);
	de_dbg(c, "background color index: %d\n", (int)bgcol_index);

	aspect_ratio_code = de_getbyte(pos+6);
	de_dbg(c, "aspect ratio code: %d\n", (int)aspect_ratio_code); // TODO

	de_dbg_indent(c, -1);
	return 1;
}

static void do_read_color_table(deark *c, lctx *d, de_int64 pos, de_int64 ncolors,
	de_uint32 *ct)
{
	de_int64 k;

	for(k=0; k<ncolors; k++) {
		ct[k] = dbuf_getRGB(c->infile, pos + 3*k, 0);
		de_dbg_pal_entry(c, k, ct[k]);
	}
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

	d->graphic_control_ext_data_valid = 1;
	d->trns_color_idx_valid = 0;

	// 0 = block size (we assume this is 4 or more)
	packed_fields = de_getbyte(pos+1);
	d->trns_color_idx_valid = (packed_fields&0x01)?1:0;
	de_dbg(c, "has transparency: %d\n", d->trns_color_idx_valid);

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

	f = dbuf_create_output_file(c, "comment.txt", NULL);

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
	case 0xf9:
		do_graphic_control_extension(c, d, pos);
		break;
	case 0xfe:
		do_comment_extension(c, d, pos);
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

static int do_read_image(deark *c, lctx *d, de_int64 pos1, de_int64 *bytesused)
{
	struct gif_image_data *gi = NULL;
	int retval = 0;
	de_int64 pos;
	de_int64 n;
	unsigned int lzw_min_code_size;

	de_dbg_indent(c, 1);
	pos = pos1;
	*bytesused = 0;
	gi = de_malloc(c, sizeof(struct gif_image_data));

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

	while(1) {
		if(pos >= c->infile->len) break;
		n = (de_int64)de_getbyte(pos);
		if(n==0)
			de_dbg(c, "block terminator at %d\n", (int)pos);
		else
			de_dbg2(c, "sub-block at %d, size=%d\n", (int)pos, (int)n);
		pos++;
		if(n==0) break;
		pos += n;
	}
	de_dbg_indent(c, -1);

	de_free(c, gi);
	de_dbg_indent(c, -1);
	*bytesused = pos - pos1;

	// Graphic control extensions are only valid for one image, so invalidate
	// any previous extension.
	d->graphic_control_ext_data_valid = 0;

	retval = 1;
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

	pos = 6;
	if(!do_read_screen_descriptor(c, d, pos)) goto done;
	pos += 7;
	if(!do_read_global_color_table(c, d, pos, &bytesused)) goto done;
	pos += bytesused;

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

		switch(block_type) {
		case 0x21:
			if(!do_read_extension(c, d, pos, &bytesused)) goto done;
			pos += bytesused;
			break;
		case 0x2c:
			if(!do_read_image(c, d, pos, &bytesused)) goto done;
			pos += bytesused;
			break;
		case 0x3b:
			goto done; // Trailer
		default:
			de_err(c, "Unknown block type: 0x%02x\n", (unsigned int)block_type);
			goto done;
		}
	}

done:
	de_free(c, d);
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
	mi->flags |= DE_MODFLAG_HIDDEN;
}
