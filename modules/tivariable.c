// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 w, h;
#define DE_FMT_TI92  1
#define DE_FMT_TI89  2
#define DE_FMT_TI92P 3
#define DE_FMT_TI83  4
#define DE_FMT_TI83F 5
#define DE_FMT_TI82  6
#define DE_FMT_TI73  7
#define DE_FMT_TI85  8
#define DE_FMT_TI86  9
#define DE_FMT_TI_UNKNOWN 100
	int fmt;
} lctx;

static int identify_internal(deark *c)
{
	de_byte buf[8];

	de_read(buf, 0, 8);
	if(!de_memcmp(buf, "**TI73**", 8)) return DE_FMT_TI73;
	if(!de_memcmp(buf, "**TI82**", 8)) return DE_FMT_TI82;
	if(!de_memcmp(buf, "**TI83**", 8)) return DE_FMT_TI83;
	if(!de_memcmp(buf, "**TI83F*", 8)) return DE_FMT_TI83F;
	if(!de_memcmp(buf, "**TI85**", 8)) return DE_FMT_TI85;
	if(!de_memcmp(buf, "**TI86**", 8)) return DE_FMT_TI86;
	if(!de_memcmp(buf, "**TI89**", 8)) return DE_FMT_TI89;
	if(!de_memcmp(buf, "**TI92**", 8)) return DE_FMT_TI92;
	if(!de_memcmp(buf, "**TI92P*", 8)) return DE_FMT_TI92P;
	if(!de_memcmp(buf, "**TI", 4)) return DE_FMT_TI_UNKNOWN;
	return 0;
}

static int do_bitmap(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 j;
	de_int64 rowspan;
	int retval = 0;

	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);
	rowspan = (d->w+7)/8;

	if(pos+rowspan*d->h > c->infile->len) {
		de_err(c, "Unexpected end of file\n");
		goto done;
	}
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	img = de_bitmap_create(c, d->w, d->h, 1);

	for(j=0; j<d->h; j++) {
		de_convert_row_bilevel(c->infile, pos+j*rowspan, img, j, DE_CVTR_WHITEISZERO);
	}

	de_bitmap_write_to_file(img, NULL);
	retval = 1;
done:
	de_bitmap_destroy(img);
	return retval;
}

static int do_color_bitmap(deark *c, lctx *d, de_int64 pos)
{
	struct deark_bitmap *img = NULL;
	de_int64 i;
	de_int64 j;
	de_int64 rowspan;
	int retval = 0;
	de_byte b0, b1;
	de_uint32 clr;

	de_dbg(c, "dimensions: %dx%d\n", (int)d->w, (int)d->h);

	rowspan = (((d->w * 16)+31)/32)*4; // Uses 4-byte alignment, apparently

	if(pos+rowspan*d->h > c->infile->len) {
		de_err(c, "Unexpected end of file\n");
		goto done;
	}
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	img = de_bitmap_create(c, d->w, d->h, 3);
	img->flipped = 1;

	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			b0 = de_getbyte(pos + j*rowspan + i*2);
			b1 = de_getbyte(pos + j*rowspan + i*2 + 1);
			clr = (((de_uint32)b1)<<8) | b0;
			clr = de_rgb565_to_888(clr);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}

	}

	de_bitmap_write_to_file(img, NULL);
	retval = 1;
done:
	de_bitmap_destroy(img);
	return retval;
}

static int do_ti83_picture_var(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x;

	de_dbg(c, "picture at %d\n", (int)pos);
	x = de_getui16le(pos);
	de_dbg(c, "picture size: %d\n", (int)x);
	d->w = 95;
	d->h = 63;
	return do_bitmap(c, d, pos+2);
}

static int do_ti83c_picture_var(deark *c, lctx *d, de_int64 pos)
{
	// Try to support a type of color image (.8ca).
	// This code may not be correct.
	de_dbg(c, "picture at %d\n", (int)pos);
	d->w = 133;
	d->h = 83;
	return do_color_bitmap(c, d, pos+3);
}

static int do_ti85_picture_var(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x;

	de_dbg(c, "picture at %d\n", (int)pos);
	x = de_getui16le(pos);
	de_dbg(c, "picture size: %d\n", (int)x);
	d->w = 128;
	d->h = 63;
	return do_bitmap(c, d, pos+2);
}

static int do_ti92_picture_var(deark *c, lctx *d, de_int64 pos)
{
	de_int64 x;

	de_dbg(c, "picture at %d\n", (int)pos);
	pos+=4;

	x = de_getui16be(pos);
	de_dbg(c, "picture size: %d\n", (int)x);
	d->h = de_getui16be(pos+2);
	d->w = de_getui16be(pos+4);
	return do_bitmap(c, d, pos+6);
}

static void do_ti92_var_table_entry(deark *c, lctx *d, de_int64 pos)
{
	de_int64 data_offset;
	de_byte type_id;

	de_dbg(c, "var table entry at %d\n", (int)pos);
	data_offset = de_getui32le(pos);

	type_id = de_getbyte(pos+12);
	de_dbg(c, "var type: 0x%02x\n", (unsigned int)type_id);
	if(type_id!=0x10) {
		// Not a picture
		return;
	}
	de_dbg(c, "data offset: %d\n", (int)data_offset);
	do_ti92_picture_var(c, d, data_offset);
}

static void do_ti83(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 data_section_size;
	de_int64 data_section_end;
	de_int64 var_data_size;
	de_byte type_id;

	// 0-7: signature
	// 8-10: 0x1a 0x0a 0x00
	// 11-52: comment

	data_section_size = de_getui16le(53);
	de_dbg(c, "data section size: %d\n", (int)data_section_size);
	data_section_end = 55+data_section_size;
	if(data_section_end > c->infile->len) {
		de_err(c, "Data section goes beyond end of file\n");
		goto done;
	}

	// Read the variables
	pos = 55;
	while(pos < data_section_end) {
		var_data_size = de_getui16le(pos+2);
		type_id = de_getbyte(pos+4);
		pos += 15;
		if(d->fmt==DE_FMT_TI83F)
			pos += 2;
		de_dbg(c, "var type=0x%02x pos=%d len=%d\n", (unsigned int)type_id,
			(int)pos, (int)var_data_size);

		if(type_id==0x07) { // guess
			do_ti83_picture_var(c, d, pos);
		}
		else if(type_id==0x1a) {
			do_ti83c_picture_var(c, d, pos);
		}

		pos += var_data_size;
	}

done:
	;
}

static void do_ti85(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 data_section_size;
	de_int64 data_section_end;
	de_int64 var_data_size;
	de_int64 name_len_reported;
	de_int64 name_field_len;
	de_byte type_id;
	de_int64 x1, x2;
	int warned = 0;

	// 0-7: signature
	// 8-10: 0x1a 0x0a 0x00
	// 11-52: comment

	data_section_size = de_getui16le(53);
	de_dbg(c, "data section size: %d\n", (int)data_section_size);
	data_section_end = 55+data_section_size;
	if(data_section_end > c->infile->len) {
		de_err(c, "Data section goes beyond end of file\n");
		goto done;
	}

	// Read the variables
	pos = 55;
	while(pos < data_section_end) {
		if(data_section_end - pos < 8) {
			de_warn(c, "Invalid variable entry size. This file may not have been processed correctly.\n");
			break;
		}

		var_data_size = de_getui16le(pos+2);
		type_id = de_getbyte(pos+4);
		name_len_reported = (de_int64)de_getbyte(pos+5);
		de_dbg(c, "reported var name length: %d\n", (int)name_len_reported);
		if(d->fmt==DE_FMT_TI86) {
			name_field_len = 8; // Initial default

			// The TI86 name field length *should* always be 8, but some files do not
			// do it that way.
			if(name_len_reported!=8) {
				// There are two "variable data length" fields that should contain the
				// same value. Although this is bad design, we can exploit it to help
				// guess the correct length of the variable name field.

				x1 = de_getui16le(pos+14);
				x2 = de_getui16le(pos+6+name_len_reported);
				if(x1!=var_data_size && x2==var_data_size) {
					if(!warned) {
						de_warn(c, "This TI86 file appears to use TI85 variable name format "
							"instead of TI86 format. Trying to continue.\n");
						warned = 1;
					}
					name_field_len = name_len_reported;
				}
			}
		}
		else {
			// TI85 format
			name_field_len = name_len_reported;
		}

		pos += 6+name_field_len;

		x1 = de_getui16le(pos);
		if(x1!=var_data_size) {
			de_warn(c, "Inconsistent variable-data-length fields. "
				"This file may not be processed correctly.\n");
		}
		pos += 2;

		de_dbg(c, "var type=0x%02x pos=%d len=%d\n", (unsigned int)type_id,
			(int)pos, (int)var_data_size);

		if(type_id==0x11) { // guess
			do_ti85_picture_var(c, d, pos);
		}

		pos += var_data_size;
	}

done:
	;
}

static void do_ti92(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 numvars;
	de_int64 x;
	de_int64 i;

	// 0-7: signature
	// 8-9: 0x01 0x00
	// 10-17: default folder name
	// 18-57: comment

	numvars = de_getui16le(58);
	de_dbg(c, "number of variables/folders: %d\n", (int)numvars);
	if(numvars>DE_MAX_IMAGES_PER_FILE) goto done;

	pos = 60;
	for(i=0; i<numvars; i++) {
		do_ti92_var_table_entry(c, d, pos);
		pos+=16;
	}

	// Data section
	x = de_getui32le(pos);
	de_dbg(c, "reported file size: %d\n", (int)x);

done:
	;
}

static void de_run_tivariable(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In tivariable module\n");
	d = de_malloc(c, sizeof(lctx));
	d->fmt = identify_internal(c);
	switch(d->fmt) {
	case DE_FMT_TI73:
		de_declare_fmt(c, "TI73 variable file");
		do_ti83(c, d);
		break;
	case DE_FMT_TI82:
		de_declare_fmt(c, "TI82 variable file");
		do_ti83(c, d);
		break;
	case DE_FMT_TI83:
		de_declare_fmt(c, "TI83 variable file");
		do_ti83(c, d);
		break;
	case DE_FMT_TI83F:
		de_declare_fmt(c, "TI83F variable file");
		do_ti83(c, d);
		break;
	case DE_FMT_TI85:
		de_declare_fmt(c, "TI85 variable file");
		do_ti85(c, d);
		break;
	case DE_FMT_TI86:
		de_declare_fmt(c, "TI86 variable file");
		do_ti85(c, d);
		break;
	case DE_FMT_TI89:
		de_declare_fmt(c, "TI89 variable file");
		do_ti92(c, d);
		break;
	case DE_FMT_TI92:
		de_declare_fmt(c, "TI92 variable file");
		do_ti92(c, d);
		break;
	case DE_FMT_TI92P:
		de_declare_fmt(c, "TI92P variable file");
		do_ti92(c, d);
		break;
	default:
		de_err(c, "Unknown or unsupported TI variable file version\n");
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_tivariable(deark *c)
{
	int fmt;
	fmt = identify_internal(c);
	if(fmt==DE_FMT_TI_UNKNOWN) return 10;
	if(fmt!=0) return 100;
	return 0;
}

void de_module_tivariable(deark *c, struct deark_module_info *mi)
{
	mi->id = "tivariable";
	mi->run_fn = de_run_tivariable;
	mi->identify_fn = de_identify_tivariable;
}
