// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// VORT pix image

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_vort);

// The VORT software includes documentation about this file format, but to me
// it seems unclear and incomplete. Here are some of my notes about the format,
// using my own terminology.
//
// VLQ := a LENGTH byte, followed by an unsigned #LENGTH-byte integer.
//  (Longer-than-optimal LENGTHs are fine. A LENGTH of 0 is allowed, at least
//  in some contexts.)
//
// FULL_OBJECT := a FULL_TYPE byte, then a VLQ, then a #VLQ-byte OBJECT_LIST
//
// OBJECT_LIST := a sequence of PRIMITIVE_OBJECTs
//  (Note that, to parse an OBJECT_LIST, you need to know its size in bytes.
//  To do anything useful with it, you also need its parent's FULL_TYPE.)
//
// PRIMITIVE_OBJECT := a PRIMITIVE_TYPE byte, then a LENGTH byte, then #LENGTH
//   bytes of data
//  (Note that, to do anything useful with a PRIMITIVE_OBJECT, you need to
//  know its parent's FULL_TYPE.)
//  (Note that the data following the PRIMITIVE_TYPE byte is often, but not
//  always, in the form of a VLQ.)
//
// FULL_TYPE V_DIRECTORY w/ PRIMITIVE_TYPE D_OBJECT is a pointer to a
// FULL_OBJECT.
//
// The file can also contain unstructured data at arbitrary offsets, pointed to
// by certain PRIMITIVE_OBJECTs.
//
// At offset 6 is a VLQ giving the offset of the "root object" (a FULL_OBJECT).
// This is expected to be a directory object; otherwise I guess it has to be
// the only FULL_OBJECT in the file.
//
// All file offsets are measured from the beginning of the file.

// "Full object" types:
#define VORT_V_DIRECTORY 0
#define VORT_V_IMAGE     1
#define VORT_V_TEXT      2
#define VORT_V_COLORMAP  3

// Primitive object types for V_DIRECTORY:
#define VORT_D_OBJECT    2

// Primitive object types for V_IMAGE:
#define VORT_I_ADDR      0
#define VORT_I_IMWIDTH   1
#define VORT_I_IMHEIGHT  2
#define VORT_I_IMDEPTH   3
#define VORT_I_RLE_CODED 11

// Primitive object types for V_COLORMAP:
#define VORT_C_ADDR      0
#define VORT_C_SIZE      1

typedef struct localctx_struct {
	int nesting_level;

	// A file can potentially contain multiple images and/or multiple colormaps.
	// But I'm just going to cross my fingers and hope it doesn't.
	i64 image_data_pos;
	i64 image_width, image_height;
	i64 image_depth;
	i64 colormap_pos;
	i64 colormap_size;
	u8 rle_flag;

	u32 pal[256];
} lctx;

struct obj_type_info_struct;

typedef void (*obj_decoder_fn)(deark *c, lctx *d,
	const struct obj_type_info_struct *oti,
	i64 pos, i64 dlen, i64 value_as_vlq);

struct obj_type_info_struct {
	// 0x01: is a VLQ
	// 0x02: Print decoded value, even if decoder_fn exists
	u32 flags;

	u8 full_type;
	u8 primitive_type;
	const char *name;
	obj_decoder_fn decoder_fn;
};

static const char *get_fulltype_name(u8 t)
{
	const char *name;
	switch(t) {
	case VORT_V_DIRECTORY: name="directory"; break;
	case VORT_V_IMAGE: name="image"; break;
	case VORT_V_TEXT: name="text"; break;
	case VORT_V_COLORMAP: name="colormap"; break;
	default: name="?";
	}
	return name;
}

// Variable length integer/quantity (VLQ)
// fpos will be read and updated.
static i64 read_vlq(deark *c, i64 *fpos)
{
	i64 nlen;
	i64 k;
	i64 val;
	i64 pos = *fpos;

	nlen = (i64)de_getbyte(pos++);
	*fpos += 1+nlen;
	if(nlen>7) {
		return 0;
	}

	val = 0;
	for(k=0; k<nlen; k++) {
		val = (val<<8) | (i64)de_getbyte(pos++);
	}
	if(val<0) return 0;
	return val;
}

static int do_full_object(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed);

static void decode_object_addr(deark *c, lctx *d,
	const struct obj_type_info_struct *oti,
	i64 pos, i64 dlen, i64 value_as_vlq)
{
	i64 bytes_consumed = 0;
	do_full_object(c, d, value_as_vlq, &bytes_consumed);
}

static void decode_date(deark *c, lctx *d,
	const struct obj_type_info_struct *oti,
	i64 pos, i64 dlen, i64 value_as_vlq)
{
	char timestamp_buf[64];
	struct de_timestamp timestamp;

	de_unix_time_to_timestamp(value_as_vlq, &timestamp, 0x1);
	de_timestamp_to_string(&timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %"I64_FMT" (%s)", oti->name, value_as_vlq, timestamp_buf);
}

static void decode_simple_item(deark *c, lctx *d,
	const struct obj_type_info_struct *oti,
	i64 pos, i64 dlen, i64 val)
{
	if(oti->full_type==VORT_V_IMAGE) {
		switch(oti->primitive_type) {
		case VORT_I_ADDR: d->image_data_pos = val; break;
		case VORT_I_IMWIDTH: d->image_width = val; break;
		case VORT_I_IMHEIGHT: d->image_height = val; break;
		case VORT_I_IMDEPTH: d->image_depth = val; break;
		case VORT_I_RLE_CODED: d->rle_flag = 1; break;
		}
	}
	else if(oti->full_type==VORT_V_COLORMAP) {
		switch(oti->primitive_type) {
		case VORT_C_ADDR: d->colormap_pos = val; break;
		case VORT_C_SIZE: d->colormap_size = val; break;
		}
	}
}

static const struct obj_type_info_struct obj_type_info_arr[] = {
	{ 0x03, VORT_V_DIRECTORY, 0 /* VORT_D_PARENT */, "address of parent dir", NULL },
	{ 0x00, VORT_V_DIRECTORY, 1 /* VORT_D_NULL */, "empty", NULL },
	{ 0x03, VORT_V_DIRECTORY, VORT_D_OBJECT, "address of child object", decode_object_addr },
	{ 0x03, VORT_V_IMAGE, VORT_I_ADDR, "address of image data", decode_simple_item },
	{ 0x03, VORT_V_IMAGE, VORT_I_IMWIDTH, "image width", decode_simple_item },
	{ 0x03, VORT_V_IMAGE, VORT_I_IMHEIGHT, "image height", decode_simple_item },
	{ 0x03, VORT_V_IMAGE, VORT_I_IMDEPTH, "bits per pixel", decode_simple_item },
	{ 0x03, VORT_V_IMAGE, 4  /* I_RED */, "red channel flag", NULL },
	{ 0x03, VORT_V_IMAGE, 5  /* I_GREEN */, "green channel flag", NULL },
	{ 0x03, VORT_V_IMAGE, 6  /* I_BLUE */, "blue channel flag", NULL },
	{ 0x03, VORT_V_IMAGE, 7  /* I_ALPHA */, "alpha channel flag", NULL },
	{ 0x03, VORT_V_IMAGE, 8  /* I_BACKGND */, "background color", NULL },
	{ 0x01, VORT_V_IMAGE, 9  /* I_DATE */, "creation date", decode_date },
	{ 0x03, VORT_V_IMAGE, 10 /* I_COLORMAP */, "address of colormap object", NULL },
	{ 0x03, VORT_V_IMAGE, VORT_I_RLE_CODED, "run length encoded flag", decode_simple_item },
	{ 0x03, VORT_V_IMAGE, 12 /* I_XADDR */, "x coord if fragment", NULL },
	{ 0x03, VORT_V_IMAGE, 13 /* I_YADDR */, "y coord if fragment", NULL },
	{ 0x03, VORT_V_IMAGE, 14 /* I_ORIGWIDTH */, "whole width if fragment", NULL },
	{ 0x03, VORT_V_IMAGE, 15 /* I_ORIGHEIGHT */, "whole height if fragment", NULL },
	{ 0x03, VORT_V_TEXT, 0 /* T_ADDR */, "address of text data", NULL },
	{ 0x03, VORT_V_TEXT, 1 /* T_LENGTH */, "size of text data", NULL },
	{ 0x03, VORT_V_COLORMAP, VORT_C_ADDR, "address of colormap data", decode_simple_item },
	{ 0x03, VORT_V_COLORMAP, VORT_C_SIZE, "size of colormap data", decode_simple_item },
	{ 0x03, VORT_V_COLORMAP, 2 /* C_RED */, "red channel flag", NULL },
	{ 0x03, VORT_V_COLORMAP, 3 /* C_GREEN */, "green channel flag", NULL },
	{ 0x03, VORT_V_COLORMAP, 4 /* C_BLUE */, "blue channel flag", NULL }
};

static const struct obj_type_info_struct *find_obj_type_info(u8 full_type, u8 primitive_type)
{
	size_t i;

	for(i=0; i<DE_ITEMS_IN_ARRAY(obj_type_info_arr); i++) {
		if(obj_type_info_arr[i].primitive_type==primitive_type &&
			obj_type_info_arr[i].full_type==full_type)
		{
			return &obj_type_info_arr[i];
		}
	}
	return NULL;
}

static int do_primitive_object(deark *c, lctx *d, i64 pos1,
	u8 obj_fulltype, i64 *bytes_consumed)
{
	u8 obj_type;
	i64 obj_dlen;
	i64 pos = pos1;
	const struct obj_type_info_struct *oti;
	const char *name;

	i64 value_as_vlq = 0;

	de_dbg(c, "primitive object at %d", (int)pos1);
	de_dbg_indent(c, 1);
	obj_type = de_getbyte(pos++);
	oti = find_obj_type_info(obj_fulltype, obj_type);
	if(oti && oti->name) name = oti->name;
	else name = "?";
	de_dbg(c, "primitive type: %u (%s)", (unsigned int)obj_type, name);

	// The data is usually a VLQ, but sometimes it's not. For convenience,
	// we'll read the length byte, then go back and read the whole thing as a VLQ.
	obj_dlen = (i64)de_getbyte(pos);

	if(obj_dlen>=1 && obj_dlen<=8) {
		i64 tmppos = pos;
		value_as_vlq = read_vlq(c, &tmppos);
	}
	pos++; // For the length byte

	if(oti && oti->flags&0x01 && (!oti->decoder_fn || (oti->flags&0x2))) {
		if(obj_dlen==0) {
			de_dbg(c, "%s: (field is present)", name);
		}
		else {
			de_dbg(c, "%s: %"I64_FMT, name, value_as_vlq);
		}
	}

	if(oti && oti->decoder_fn) {
		oti->decoder_fn(c, d, oti, pos, obj_dlen, value_as_vlq);
	}

	pos += obj_dlen;

	de_dbg_indent(c, -1);
	*bytes_consumed = pos-pos1;
	return 1;
}

static int do_object_list(deark *c, lctx *d, i64 pos1, i64 len,
	u8 object_fulltype, i64 *bytes_consumed)
{
	i64 pos = pos1;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "object list at %d, len=%d", (int)pos, (int)len);
	while(1) {
		i64 objsize;
		if(pos>=pos1+len) break;
		if(pos>=c->infile->len) goto done;

		de_dbg_indent(c, 1);
		if(!do_primitive_object(c, d, pos, object_fulltype, &objsize)) goto done;
		pos += objsize;
		de_dbg_indent(c, -1);
	}
	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Process one "full object", given its address
static int do_full_object(deark *c, lctx *d, i64 pos1,
	i64 *bytes_consumed)
{
	u8 obj_type;
	i64 obj_dlen;
	i64 pos = pos1;
	i64 bytes_consumed2 = 0;
	int retval = 0;

	d->nesting_level++;
	// Objects can't be nested without going through this code path, so doing
	// this check only here should be sufficient.
	if(d->nesting_level>8) goto done;

	de_dbg(c, "full object at %d", (int)pos);
	de_dbg_indent(c, 1);
	obj_type = de_getbyte(pos++);
	de_dbg(c, "full type: %u (%s)", (unsigned int)obj_type, get_fulltype_name(obj_type));

	obj_dlen = read_vlq(c, &pos);
	de_dbg(c, "data len: %"I64_FMT, obj_dlen);

	if(!do_object_list(c, d, pos, obj_dlen, obj_type, &bytes_consumed2)) goto done;

	pos += obj_dlen;
	retval = 1;

done:
	d->nesting_level--;
	de_dbg_indent(c, -1);
	*bytes_consumed = pos-pos1;
	return retval;
}

static void do_colormap(deark *c, lctx *d)
{
	i64 k;

	if(d->colormap_pos==0 || d->colormap_size==0) return;
	de_dbg(c, "colormap at %d, %d entries", (int)d->colormap_pos, (int)d->colormap_size);

	de_dbg_indent(c, 1);
	for(k=0; k<d->colormap_size && k<256; k++) {
		u8 cr, cg, cb;
		cr = de_getbyte(d->colormap_pos + k);
		cg = de_getbyte(d->colormap_pos + d->colormap_size + k);
		cb = de_getbyte(d->colormap_pos + d->colormap_size*2 + k);
		d->pal[k] = DE_MAKE_RGB(cr, cg, cb);
		de_dbg_pal_entry(c, k, d->pal[k]);
	}
	de_dbg_indent(c, -1);
}

static void do_decompress(deark *c, lctx *d, i64 pos1, dbuf *unc_pixels,
	i64 num_pixels, i64 bytes_per_pixel)
{
	i64 pos = pos1;
	i64 pixel_count = 0;

	while(1) {
		u8 b;
		i64 count;

		if(pos>c->infile->len) break;
		if(pixel_count>=num_pixels) break;

		b = de_getbyte(pos);
		pos++;
		if(b>=128) { // uncompressed run
			count = (i64)(b-128);
			dbuf_copy(c->infile, pos, count*bytes_per_pixel, unc_pixels);
			pos += count*bytes_per_pixel;
			pixel_count += count;
		}
		else { // compressed run
			i64 k;
			u8 pixel_buf[4];

			count = 1+(i64)b;
			de_read(pixel_buf, pos, bytes_per_pixel);
			pos += bytes_per_pixel;
			for(k=0; k<count; k++) {
				dbuf_write(unc_pixels, pixel_buf, bytes_per_pixel);
			}
			pixel_count += count;
		}
	}
}

static void do_image(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	dbuf *unc_pixels = NULL;
	i64 i, j;
	i64 bytes_per_pixel;

	if(d->image_data_pos==0) return;

	de_dbg(c, "image data at %d", (int)d->image_data_pos);
	de_dbg_indent(c, 1);

	if(!de_good_image_dimensions(c, d->image_width, d->image_height)) goto done;

	img = de_bitmap_create(c, d->image_width, d->image_height, 3);

	if(d->image_depth!=8 && d->image_depth!=24) {
		de_err(c, "Unsupported bits/pixel: %d", (int)d->image_depth);
		goto done;
	}
	bytes_per_pixel = d->image_depth/8;

	if(d->image_depth==8 && d->colormap_pos==0) {
		de_err(c, "Missing colormap");
		goto done;
	}

	if(d->rle_flag) {
		unc_pixels = dbuf_create_membuf(c, 0, 0);
		do_decompress(c, d, d->image_data_pos, unc_pixels,
			d->image_width*d->image_height, bytes_per_pixel);
	}
	else {
		unc_pixels = dbuf_open_input_subfile(c->infile,
			d->image_data_pos, c->infile->len-d->image_data_pos);
	}

	for(j=0; j<d->image_height; j++) {
		for(i=0; i<d->image_width; i++) {
			if(d->image_depth==8) {
				u8 b;
				b = dbuf_getbyte(unc_pixels, j*d->image_width + i);
				de_bitmap_setpixel_rgb(img, i, j, d->pal[(unsigned int)b]);
			}
			else if(d->image_depth==24) {
				u32 clr;
				clr = dbuf_getRGB(unc_pixels, (j*d->image_width + i)*bytes_per_pixel, 0);
				de_bitmap_setpixel_rgb(img, i, j, clr);
			}
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);

done:
	de_dbg_indent(c, -1);
	dbuf_close(unc_pixels);
	de_bitmap_destroy(img);
}

static void de_run_vort(deark *c, de_module_params *mparams)
{
	i64 pos;
	i64 root_obj_offs;
	i64 bytes_consumed = 0;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	pos = 0;
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 6; // signature
	root_obj_offs = read_vlq(c, &pos);
	de_dbg(c, "root object address: %d", (int)root_obj_offs);
	de_dbg_indent(c, -1);

	pos = root_obj_offs;
	if(!do_full_object(c, d, root_obj_offs, &bytes_consumed)) goto done;
	do_colormap(c, d);
	do_image(c, d);

done:
	de_free(c, d);
}

static int de_identify_vort(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "VORT01", 6))
		return 100;
	return 0;
}

void de_module_vort(deark *c, struct deark_module_info *mi)
{
	mi->id = "vort";
	mi->desc = "VORT ray tracer PIX image";
	mi->run_fn = de_run_vort;
	mi->identify_fn = de_identify_vort;
}
