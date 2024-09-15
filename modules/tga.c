// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_tga);

#define CODE_IGCH 0x49474348U

struct tgaimginfo {
	i64 width, height;
	i64 img_size_in_bytes;
	int is_thumb;
	int respect_alpha_channel;
};

typedef struct localctx_structTGA {
	i64 id_field_len;
	de_encoding input_encoding;
#define FMT_TGA 0
#define FMT_VST 1
	int file_format;
#define TRANS_AUTO     100
#define TRANS_REMOVE   101
#define TRANS_RESPECT  102
#define TRANS_ASSOC    103
	u8 trans_setting;
	u8 color_map_type;
	u8 img_type;
	struct tgaimginfo main_image;
	struct tgaimginfo thumbnail_image;
	i64 cmap_start;
	i64 cmap_length;
	i64 cmap_depth;
	i64 pixel_depth;
	u8 image_descriptor;
	i64 num_attribute_bits;
	u8 attributes_type;
	u8 alpha_is_premultiplied;
	u8 top_down, right_to_left;
	u8 interleave_mode;
	i64 v2_footer_pos;
	int has_v2_signature;
	int has_ext_area_attribs_type;
#define TGA_CMPR_UNKNOWN 0
#define TGA_CMPR_NONE    1
#define TGA_CMPR_RLE     2
	int cmpr_type;
#define TGA_CLRTYPE_UNKNOWN   0
#define TGA_CLRTYPE_PALETTE   1
#define TGA_CLRTYPE_TRUECOLOR 2
#define TGA_CLRTYPE_GRAYSCALE 3
	int color_type;
	const char *cmpr_name;
	const char *clrtype_name;
	i64 bytes_per_pixel; // May be meaningless if pixel_depth is not a multiple of 8
	i64 bytes_per_pal_entry;
	i64 pal_size_in_bytes;
	i64 aspect_ratio_num, aspect_ratio_den;
	i64 thumbnail_offset;
	u32 pal[256];
	struct de_timestamp mod_time;
} lctx;

// Figure out if the image has transparency, and emit a warning or other message if
// appropriate.
// TGA transparency is kind of a mess. Multiple ways of labeling it, some of
// which are ambiguous... Files that have inconsistent labels... Files that
// claim to have transparency but don't, or that claim not to but do...
static int should_use_alpha_channel(deark *c, lctx *d, struct tgaimginfo *imginfo,
	int has_alpha_0, int has_alpha_partial, int has_alpha_255)
{
	const char *prefix = "";

	if(imginfo->is_thumb) {
		prefix = "[thumbnail] ";
	}

	if(d->trans_setting==TRANS_REMOVE) return 0;

	if(d->has_ext_area_attribs_type) {
		// attributes_type==0 technically also means there is no transparency,
		// but this cannot be trusted.
		if(d->attributes_type!=0 && d->attributes_type!=3 &&
			d->attributes_type!=4)
		{
			return 0;
		}
	}

	if(d->pixel_depth!=32 || d->color_type!=TGA_CLRTYPE_TRUECOLOR) {
		return 0;
	}

	if(d->num_attribute_bits!=0 && d->num_attribute_bits!=8) {
		if(!imginfo->is_thumb) { // Hack to suppress duplicate warning
			de_warn(c, "%d-bit attribute channel not supported. Transparency disabled.",
				(int)d->num_attribute_bits);
		}
		return 0;
	}

	if(d->trans_setting==TRANS_RESPECT || d->trans_setting==TRANS_ASSOC) {
		return 1;
	}

	if(d->has_ext_area_attribs_type) {
		if(d->attributes_type==3 && d->num_attribute_bits==8) {
			// Alpha channel seems to be labeled correctly.
			// Trust it.
			return 1;
		}
		else if(d->attributes_type==4 && d->num_attribute_bits==8) {
			// Premultiplied alpha
			return 1;
		}
	}

	if(has_alpha_partial || (has_alpha_0 && has_alpha_255)) {
		if(d->num_attribute_bits==0) {
			de_warn(c, "%sDetected likely alpha channel. Enabling transparency, even though "
				"the image is labeled as non-transparent.", prefix);
		}
		return 1;
	}
	else if(has_alpha_0) { // All 0x00
		if(d->num_attribute_bits!=0) {
			de_warn(c, "%sNon-visible image detected. Disabling transparency.", prefix);
		}
		else {
			de_dbg(c, "potential alpha channel ignored: all 0 bits");
		}
		return 0;
	}
	else { // All 0xff
		de_dbg(c, "potential alpha channel is moot: all 1 bits");
		return 0;
	}
}

static void bitmap_unpremultiply_alpha(de_bitmap *img)
{
	i64 i, j;

	if(img->bytes_per_pixel!=2 && img->bytes_per_pixel!=4) return;

	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			de_color clr;

			clr = de_bitmap_getpixel(img, i, j);
			clr = de_unpremultiply_alpha_clr(clr);
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}
}

static void do_decode_image(deark *c, lctx *d, struct tgaimginfo *imginfo, dbuf *unc_pixels,
	const char *token, UI createflags1)
{
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	i64 i, j;
	i64 pdwidth;
	u8 b;
	u32 clr;
	u8 a;
	i64 rowspan;
	int output_bypp;
	UI getrgbflags;
	i64 interleave_stride;
	i64 interleave_pass;
	i64 cur_rownum; // 0-based, does not account for bottom-up orientation
	int has_alpha_0 = 0;
	int has_alpha_partial = 0;
	int has_alpha_255 = 0;
	UI createflags = createflags1;

	fi = de_finfo_create(c);

	if(token) {
		de_finfo_set_name_from_sz(c, fi, token, 0, DE_ENCODING_LATIN1);
	}
	if(d->mod_time.is_valid) {
		fi->internal_mod_time = d->mod_time;
	}

	pdwidth = imginfo->width;
	if(d->pixel_depth==1) {
		de_warn(c, "1-bit TGA images are not portable, and may not be decoded correctly");
		pdwidth = de_pad_to_n(imginfo->width, 8);
		rowspan = pdwidth/8;
	}
	else {
		rowspan = imginfo->width*d->bytes_per_pixel;
	}

	if(d->color_type==TGA_CLRTYPE_GRAYSCALE || d->pixel_depth==1)
		output_bypp=1;
	else if(d->pixel_depth==32)
		output_bypp=4;
	else
		output_bypp=3;

	if(d->file_format==FMT_VST)
		getrgbflags = 0;
	else
		getrgbflags = DE_GETRGBFLAG_BGR;

	img = de_bitmap_create2(c, imginfo->width, pdwidth, imginfo->height, output_bypp);

	switch(d->interleave_mode) {
	case 1: interleave_stride = 2; break;
	case 2: interleave_stride = 4; break;
	default: interleave_stride = 1;
	}

	cur_rownum = 0;
	interleave_pass = 0;

	for(j=0; j<imginfo->height; j++) {
		i64 j_adj;

		j_adj = cur_rownum;

		// Update the row number for next time
		cur_rownum += interleave_stride;
		if(cur_rownum >= imginfo->height) {
			// Went past the end of the image; move back to near the start.
			interleave_pass++;
			cur_rownum = interleave_pass;
		}

		if(d->pixel_depth==1) {
			de_convert_row_bilevel(unc_pixels, j*rowspan, img, j_adj, 0);
			continue;
		}

		for(i=0; i<pdwidth; i++) {
			if(d->color_type==TGA_CLRTYPE_TRUECOLOR && (d->pixel_depth==15 || d->pixel_depth==16)) {
				clr = (u32)dbuf_getu16le(unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				clr = de_rgb555_to_888(clr);
				de_bitmap_setpixel_rgb(img, i, j_adj, clr);
			}
			else if(d->color_type==TGA_CLRTYPE_TRUECOLOR) {
				clr = dbuf_getRGB(unc_pixels, j*rowspan + i*d->bytes_per_pixel, getrgbflags);
				if(d->pixel_depth==32) {
					a = dbuf_getbyte(unc_pixels, j*rowspan + i*d->bytes_per_pixel+3);
					de_bitmap_setpixel_rgba(img, i, j_adj, DE_SET_ALPHA(clr, a));

					// Collect metrics that we may need, to decide whether to keep the
					// might-be-alpha channel.
					if(a==0) {
						has_alpha_0 = 1;
					}
					else if(a==0xff) {
						has_alpha_255 = 1;
					}
					else {
						has_alpha_partial = 1;
					}
				}
				else {
					de_bitmap_setpixel_rgb(img, i, j_adj, clr);
				}
			}
			else if(d->color_type==TGA_CLRTYPE_GRAYSCALE) {
				b = dbuf_getbyte(unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				de_bitmap_setpixel_gray(img, i, j_adj, b);
			}
			else if(d->color_type==TGA_CLRTYPE_PALETTE) {
				b = dbuf_getbyte(unc_pixels, j*rowspan + i*d->bytes_per_pixel);
				de_bitmap_setpixel_rgb(img, i, j_adj, d->pal[(UI)b]);
			}
		}
	}

	// TODO: 16-bit images could theoretically have a transparency bit, but I don't
	// know how to detect that.
	if(d->pixel_depth==32) {
		// TODO: The transparency logic is a bit messy. It probably ought to be
		// redesigned from scratch.

		imginfo->respect_alpha_channel = should_use_alpha_channel(c, d, imginfo,
			has_alpha_0, has_alpha_partial, has_alpha_255);

		if(!imginfo->is_thumb) {
			de_dbg(c, "using alpha channel: %s", imginfo->respect_alpha_channel?"yes":"no");
		}

		if(!imginfo->respect_alpha_channel || (!has_alpha_0 && !has_alpha_partial)) {
			de_bitmap_remove_alpha(img);
		}

		if(imginfo->respect_alpha_channel && d->alpha_is_premultiplied) {
			bitmap_unpremultiply_alpha(img);
		}
	}

	if(d->right_to_left) {
		de_bitmap_mirror(img);
	}
	if(!d->top_down) {
		createflags |= DE_CREATEFLAG_FLIP_IMAGE;
	}

	createflags |= DE_CREATEFLAG_OPT_IMAGE;
	de_bitmap_write_to_file_finfo(img, fi, createflags);

	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

static void do_decode_rle_internal(deark *c1, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	i64 bytes_per_pixel)
{
	u8 b;
	i64 count;
	i64 k;
	u8 buf[8];
	i64 pos = dcmpri->pos;
	i64 nbytes_written = 0;

	if(bytes_per_pixel<1 || bytes_per_pixel>8) return;

	while(1) {
		if(pos >= dcmpri->pos + dcmpri->len) break;
		if(nbytes_written >= dcmpro->expected_len) break;

		b = dbuf_getbyte(dcmpri->f, pos);
		pos++;

		if(b & 0x80) { // RLE block
			count = (i64)(b - 0x80) + 1;
			dbuf_read(dcmpri->f, buf, pos, bytes_per_pixel);
			pos += bytes_per_pixel;
			for(k=0; k<count; k++) {
				dbuf_write(dcmpro->f, buf, bytes_per_pixel);
			}
			nbytes_written += count * bytes_per_pixel;
		}
		else { // uncompressed block
			count = (i64)(b) + 1;
			dbuf_copy(dcmpri->f, pos, count * bytes_per_pixel, dcmpro->f);
			pos += count * bytes_per_pixel;
			nbytes_written += count * bytes_per_pixel;
		}
	}
	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

static int do_decode_rle(deark *c, lctx *d, i64 pos1, dbuf *unc_pixels)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = c->infile->len - pos1;
	dcmpro.f = unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = d->main_image.img_size_in_bytes;

	do_decode_rle_internal(c, &dcmpri, &dcmpro, &dres, d->bytes_per_pixel);
	dbuf_flush(dcmpro.f);

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		return 0;
	}
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT" bytes",
		dres.bytes_consumed, unc_pixels->len);
	return 1;
}

static void do_decode_thumbnail(deark *c, lctx *d)
{
	dbuf *unc_pixels = NULL;
	i64 hdrsize = 2;

	de_dbg(c, "thumbnail image at %"I64_FMT, d->thumbnail_offset);
	de_dbg_indent(c, 1);

	// The thumbnail image is supposed to use the same format as the main image,
	// except without compression. (And the dimensions are obviously different.)
	// Presumably this means the origin, palette, etc. will be the same.
	// But based on the few TGA thumbnails we've seen, nobody reads the spec, and
	// it's anybody's guess what format the thumbnail will use.

	// TGA 2.0 spec says the dimensions are one *byte* each.
	d->thumbnail_image.width = (i64)de_getbyte(d->thumbnail_offset);
	d->thumbnail_image.height = (i64)de_getbyte(d->thumbnail_offset+1);
	de_dbg(c, "thumbnail dimensions: %d"DE_CHAR_TIMES"%d", (int)d->thumbnail_image.width, (int)d->thumbnail_image.height);

	if(d->thumbnail_image.width!=0 && d->thumbnail_image.height==0) {
		de_warn(c, "Thumbnail image height is 0. Assuming the file incorrectly uses "
			"16-bit thumbnail dimensions, instead of 8.");
		d->thumbnail_image.width = de_getu16le(d->thumbnail_offset);
		d->thumbnail_image.height = de_getu16le(d->thumbnail_offset+2);
		de_dbg(c, "revised thumbnail dimensions: %d"DE_CHAR_TIMES"%d", (int)d->thumbnail_image.width, (int)d->thumbnail_image.height);
		hdrsize = 4;
	}
	if(!de_good_image_dimensions(c, d->thumbnail_image.width, d->thumbnail_image.height)) goto done;

	d->thumbnail_image.img_size_in_bytes = d->thumbnail_image.height * d->thumbnail_image.width * d->bytes_per_pixel;
	unc_pixels = dbuf_open_input_subfile(c->infile, d->thumbnail_offset+hdrsize, d->thumbnail_image.img_size_in_bytes);

	do_decode_image(c, d, &d->thumbnail_image, unc_pixels, "thumb", DE_CREATEFLAG_IS_AUX);

done:
	dbuf_close(unc_pixels);
	de_dbg_indent(c, -1);
}

static int do_read_palette(deark *c, lctx *d, i64 pos)
{
	i64 i;
	i64 idx;
	UI getrgbflags;

	if(d->color_type != TGA_CLRTYPE_PALETTE) {
		return 1; // don't care about the palette
	}

	if(d->cmap_depth != 24) {
		de_err(c, "Palettes with depth=%d are not supported.", (int)d->cmap_depth);
		return 0;
	}
	if(d->pixel_depth != 8) {
		de_err(c, "Paletted images with depth=%d are not supported.", (int)d->pixel_depth);
		return 0;
	}

	if(d->file_format==FMT_VST)
		getrgbflags = 0;
	else
		getrgbflags = DE_GETRGBFLAG_BGR;

	for(i=0; i<d->cmap_length; i++) {
		idx = d->cmap_start + i;
		if(idx<0 || idx>255) continue;
		d->pal[idx] = dbuf_getRGB(c->infile, pos + i*d->bytes_per_pal_entry, getrgbflags);
		de_dbg_pal_entry(c, idx, d->pal[idx]);
	}
	return 1;
}

static void do_read_extension_area(deark *c, lctx *d, i64 pos1)
{
	i64 ext_area_size;
	i64 endpos;
	i64 k;
	int has_date;
	de_ucstring *s = NULL;
	i64 pos = pos1;
	i64 val[6];

	de_dbg(c, "extension area at %"I64_FMT, pos1);
	if(pos1 > c->infile->len - 2) {
		de_warn(c, "Bad extension area offset: %"I64_FMT, pos1);
		return;
	}

	de_dbg_indent(c, 1);

	s = ucstring_create(c);

	ext_area_size = de_getu16le_p(&pos);
	de_dbg(c, "extension area size: %"I64_FMT, ext_area_size);
	endpos = pos1+ext_area_size;

	if(pos+41>endpos) goto done;
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 41, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "author: \"%s\"", ucstring_getpsz_d(s));
	pos += 41;

	for(k=0; k<4; k++) {
		if(pos+81>endpos) goto done;
		ucstring_empty(s);
		dbuf_read_to_ucstring(c->infile, pos, 81, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		ucstring_strip_trailing_spaces(s);
		de_dbg(c, "comment line %d: \"%s\"", (int)k, ucstring_getpsz_d(s));
		pos += 81;
	}

	// date/time: pos=367, size=12
	if(pos+12>endpos) goto done;
	has_date = 0;
	for(k=0; k<6; k++) {
		val[k] = de_getu16le_p(&pos);
		if(val[k]!=0) has_date = 1;
	}
	if(has_date) {
		char timestamp_buf[64];

		de_make_timestamp(&d->mod_time, val[2], val[0], val[1], val[3], val[4], val[5]);
		d->mod_time.tzcode = DE_TZCODE_LOCAL;
		de_timestamp_to_string(&d->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "timestamp: %s", timestamp_buf);
	}

	// Job name: pos=379, size=41 (not implemented)
	pos += 41;
	// Job time: pos=420, size=6 (not implemented)
	pos += 6;

	if(pos+41>endpos) goto done;
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, pos, 41, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	ucstring_strip_trailing_spaces(s);
	de_dbg(c, "software id: \"%s\"", ucstring_getpsz_d(s));
	pos += 41;

	if(pos+3>endpos) goto done;
	val[0] = de_getu16le_p(&pos);
	val[1] = (i64)de_getbyte_p(&pos);
	if(val[0]!=0 || val[1]!=32) {
		de_dbg(c, "software version: %u,%u,%u",
			(UI)(val[0]/100), (UI)(val[0]%100),
			(UI)val[1]);
	}

	if(pos+4>endpos) goto done;
	val[0] = de_getu32le_p(&pos);
	if(val[0]!=0) {
		de_dbg(c, "background color: 0x%08x", (UI)val[0]);
	}

	// TODO: Retain the aspect ratio. (Need sample files. Nobody seems to use this field.)
	if(pos+4>endpos) goto done;
	d->aspect_ratio_num = de_getu16le_p(&pos);
	d->aspect_ratio_den = de_getu16le_p(&pos);
	if(d->aspect_ratio_den!=0) {
		de_dbg(c, "aspect ratio: %d/%d", (int)d->aspect_ratio_num, (int)d->aspect_ratio_den);
	}

	// Gamma: pos=478, size=4 (not implemented)
	pos += 4;
	// Color correction table offset: pos=482, size=4 (not implemented)
	pos += 4;

	if(pos+4>endpos) goto done;
	d->thumbnail_offset = de_getu32le_p(&pos);
	de_dbg(c, "thumbnail image offset: %"I64_FMT, d->thumbnail_offset);

	if(pos+4>endpos) goto done;
	val[0] = de_getu32le_p(&pos);
	de_dbg(c, "scan line table offset: %"I64_FMT, val[0]);

	if(pos+1>endpos) goto done;
	d->attributes_type = de_getbyte_p(&pos);
	d->has_ext_area_attribs_type = 1;
	de_dbg(c, "attributes type: %u", (UI)d->attributes_type);
	if(d->attributes_type==4) {
		d->alpha_is_premultiplied = 1;
	}
	if(d->attributes_type==0 && d->num_attribute_bits!=0) {
		de_warn(c, "Incompatible \"number of attribute bits\" (%d) and \"attributes type\" "
			"(%u) fields. Transparency may not be handled correctly.",
			(int)d->num_attribute_bits, (UI)d->attributes_type);
	}

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}

static void do_read_developer_area(deark *c, lctx *d, i64 pos)
{
	i64 num_tags;
	i64 i;
	i64 tag_id, tag_data_pos, tag_data_size;

	de_dbg(c, "developer area at %"I64_FMT, pos);
	if(pos > c->infile->len - 2) {
		de_warn(c, "Bad developer area offset: %"I64_FMT, pos);
		return;
	}

	de_dbg_indent(c, 1);
	num_tags = de_getu16le(pos);
	de_dbg(c, "number of tags: %d", (int)num_tags);
	for(i=0; i<num_tags; i++) {
		if(i>=200) break;
		tag_id = de_getu16le(pos + 2 + 10*i);
		tag_data_pos = de_getu32le(pos + 2 + 10*i + 2);
		tag_data_size = de_getu32le(pos + 2 + 10*i + 6);
		de_dbg(c, "tag #%d: id=%d, pos=%"I64_FMT", size=%"I64_FMT, (int)i, (int)tag_id,
			tag_data_pos, tag_data_size);

		if(tag_id==20) {
			// Tag 20 seems to contain Photoshop resources, though this is unconfirmed.
			de_dbg_indent(c, 1);
			// TODO: We could retrieve the pixel density settings from the Photoshop data,
			// but it's not clear whether they are ever useful.
			fmtutil_handle_photoshop_rsrc(c, c->infile, tag_data_pos, tag_data_size, 0x0);
			de_dbg_indent(c, -1);
		}
	}
	de_dbg_indent(c, -1);
}

static void do_read_footer(deark *c, lctx *d)
{
	i64 ext_offset, dev_offset;
	i64 pos = d->v2_footer_pos;

	de_dbg(c, "v2 footer at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	ext_offset = de_getu32le_p(&pos);
	de_dbg(c, "extension area offset: %"I64_FMT, ext_offset);
	dev_offset = de_getu32le_p(&pos);
	de_dbg(c, "developer area offset: %"I64_FMT, dev_offset);
	de_dbg_indent(c, -1);

	if(ext_offset!=0) {
		do_read_extension_area(c, d, ext_offset);
	}

	if(dev_offset!=0) {
		do_read_developer_area(c, d, dev_offset);
	}
}

static void do_read_image_descriptor(deark *c, lctx *d)
{
	d->image_descriptor = de_getbyte(17);
	de_dbg(c, "descriptor: 0x%02x", (UI)d->image_descriptor);

	de_dbg_indent(c, 1);
	d->num_attribute_bits = (i64)(d->image_descriptor & 0x0f);
	de_dbg(c, "number of %s bits: %d",
		d->file_format==FMT_VST?"alpha channel":"attribute",
		(int)d->num_attribute_bits);

	d->right_to_left = (d->image_descriptor>>4)&0x01;
	d->top_down = (d->image_descriptor>>5)&0x01;
	de_dbg(c, "right-to-left flag: %d", (int)d->right_to_left);
	de_dbg(c, "top-down flag: %d", (int)d->top_down);

	d->interleave_mode = d->image_descriptor >> 6;
	if(d->interleave_mode != 0) {
		de_dbg(c, "interleaving: %d", (int)d->interleave_mode);
	}
	de_dbg_indent(c, -1);
}

static int do_read_tga_headers(deark *c, lctx *d)
{
	int retval = 0;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	d->id_field_len = (i64)de_getbyte(0);
	de_dbg(c, "image ID len: %"I64_FMT, d->id_field_len);
	d->color_map_type = de_getbyte(1);
	de_dbg(c, "color map type: %d", (int)d->color_map_type);
	d->img_type = de_getbyte(2);
	de_dbg(c, "image type: %d", (int)d->img_type);

	switch(d->img_type) {
	case 0:
		d->color_type = TGA_CLRTYPE_UNKNOWN;
		d->clrtype_name = "no image";
		break;
	case 1: case 9:
	case 32: case 33:
		d->color_type = TGA_CLRTYPE_PALETTE;
		d->clrtype_name = "palette";
		break;
	case 2: case 10:
		d->color_type = TGA_CLRTYPE_TRUECOLOR;
		d->clrtype_name = "truecolor";
		break;
	case 3: case 11:
		d->color_type = TGA_CLRTYPE_GRAYSCALE;
		d->clrtype_name = "grayscale";
		break;
	default:
		d->color_type = TGA_CLRTYPE_UNKNOWN;
		d->clrtype_name = "unknown";
	}

	switch(d->img_type) {
	case 1: case 2: case 3:
		d->cmpr_type = TGA_CMPR_NONE;
		d->cmpr_name = "none";
		break;
	case 9: case 10: case 11:
		d->cmpr_type = TGA_CMPR_RLE;
		d->cmpr_name = "RLE";
		break;
	default:
		d->cmpr_type = TGA_CMPR_UNKNOWN;
		d->cmpr_name = "unknown";
	}

	de_dbg_indent(c, 1);
	de_dbg(c, "color type: %s", d->clrtype_name);
	de_dbg(c, "compression: %s", d->cmpr_name);
	de_dbg_indent(c, -1);

	if(d->color_map_type != 0) {
		d->cmap_start = de_getu16le(3);
		d->cmap_length = de_getu16le(5);
		d->cmap_depth = (i64)de_getbyte(7);
		de_dbg(c, "color map spec. at 3");
		de_dbg_indent(c, 1);
		de_dbg(c, "starting idx: %u", (UI)d->cmap_start);
		de_dbg(c, "num entries: %u", (UI)d->cmap_length);
		de_dbg(c, "bits/entry: %u", (UI)d->cmap_depth);
		de_dbg_indent(c, -1);
	}

	d->main_image.width = de_getu16le(12);
	d->main_image.height = de_getu16le(14);
	de_dbg_dimensions(c, d->main_image.width, d->main_image.height);

	d->pixel_depth = (i64)de_getbyte(16);
	de_dbg(c, "pixel depth: %d", (int)d->pixel_depth);

	do_read_image_descriptor(c, d);

	de_dbg_indent(c, -1);

	if(d->has_v2_signature) {
		do_read_footer(c, d);
	}

	if(!de_good_image_dimensions(c, d->main_image.width, d->main_image.height)) goto done;

	retval = 1;
done:
	return retval;
}

// This .vst (TrueVista) decoder is based on guesswork, on the limited information
// in the TGA spec, and on the behavior of XnView. It may not be correct.
static int do_read_vst_headers(deark *c, lctx *d)
{
	int retval = 0;

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	d->id_field_len = (i64)de_getbyte(0);

	if(d->id_field_len==0) {
		// ??? XnView seems to do something like this.
		d->id_field_len=18;
	}

	d->cmpr_type = TGA_CMPR_NONE;
	d->cmpr_name = "none";

	d->main_image.width = de_getu16le(12);
	d->main_image.height = de_getu16le(14);
	de_dbg_dimensions(c, d->main_image.width, d->main_image.height);

	d->pixel_depth = (i64)de_getbyte(16);
	de_dbg(c, "pixel depth: %d", (int)d->pixel_depth);
	if(d->pixel_depth==8) {
		d->color_map_type = 1;
		d->color_type = TGA_CLRTYPE_PALETTE;
		d->clrtype_name = "palette";
	}
	else {
		d->color_type = TGA_CLRTYPE_TRUECOLOR;
		d->clrtype_name = "truecolor";
	}

	if(d->color_type==TGA_CLRTYPE_PALETTE) {
		d->cmap_start = 0;
		d->cmap_length = 256;
		d->cmap_depth = 24;
	}

	do_read_image_descriptor(c, d);

	de_dbg_indent(c, -1);

	if(!de_good_image_dimensions(c, d->main_image.width, d->main_image.height)) goto done;

	retval = 1;
done:
	return retval;
}

// A v2 TGA file should end with the signature, but I've seen some that are padded
// with NUL bytes. This function helps find the signature in such a case.
static i64 find_last_nonNUL_byte_for_sig_search(deark *c)
{
	i64 i;
	i64 searchstartpos;
	u8 buf[2048+18];

	// (It's OK if this is negative; de_read tolerates that.)
	searchstartpos = c->infile->len-(i64)sizeof(buf);
	de_read(buf, searchstartpos, (i64)sizeof(buf));
	for(i=(i64)sizeof(buf)-1; i>=0; i--) {
		if(buf[i]!=0x00) {
			if(buf[i]=='.') return searchstartpos+i;
			return 0;
		}
	}
	return 0;
}

// If found, returns 1 and sets *pfooterpos
static int look_for_v2_signature(deark *c, int idmode, i64 *pfooterpos)
{
	i64 x;
	i64 possible_sig_pos;
	static const u8 v2sig[18] = "TRUEVISION-XFILE."; // size 18 includes trailing NUL

	if(c->infile->len<18+26) return 0;
	if(de_getbyte(c->infile->len-1) != 0x00) return 0;
	possible_sig_pos = c->infile->len-18;
	if(!dbuf_memcmp(c->infile, possible_sig_pos, v2sig, 18)) {
		*pfooterpos = possible_sig_pos-8;
		return 1;
	}
	if(idmode) return 0;

	x = find_last_nonNUL_byte_for_sig_search(c);
	if(x<=0) return 0;
	possible_sig_pos = x-16;
	if(!dbuf_memcmp(c->infile, possible_sig_pos, v2sig, 18)) {
		de_warn(c, "v2 signature found at %"I64_FMT"; ignoring %"I64_FMT" extra "
			"bytes at end of file",
			possible_sig_pos, c->infile->len-(possible_sig_pos+18));
		*pfooterpos = possible_sig_pos-8;
		return 1;
	}

	return 0;
}

// Sets d->file_format and d->has_signature
static void detect_file_format(deark *c, lctx *d)
{
	int has_igch;
	u8 img_type;

	d->has_v2_signature = look_for_v2_signature(c, 0, &d->v2_footer_pos);
	de_dbg(c, "has v2 signature: %s", d->has_v2_signature?"yes":"no");
	if(d->has_v2_signature) {
		d->file_format = FMT_TGA;
		return;
	}

	img_type = de_getbyte(2);
	if(img_type==0) {
		has_igch = (de_getu32be(20)==CODE_IGCH);
		if(has_igch) {
			d->file_format = FMT_VST;
			return;
		}
	}

	d->file_format = FMT_TGA;
}

static void read_image_id(deark *c, lctx *d, i64 pos)
{
	de_ucstring *s = NULL;

	if(d->id_field_len<1) return;
	if(d->file_format!=FMT_TGA) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, d->id_field_len, s, 0, d->input_encoding);
	de_dbg(c, "image ID: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void de_run_tga(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	dbuf *unc_pixels = NULL;
	int saved_indent_level;
	i64 rowspan_tmp;
	const char *opt_trans_str;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	d->trans_setting = TRANS_AUTO;

	opt_trans_str = de_get_ext_option(c, "tga:trans");
	if(opt_trans_str) {
		if(!de_strcmp(opt_trans_str, "auto")) {
			d->trans_setting = TRANS_AUTO;
		}
		else if(!de_strcmp(opt_trans_str, "0")) {
			d->trans_setting = TRANS_REMOVE;
		}
		else if(!de_strcmp(opt_trans_str, "1")) {
			d->trans_setting = TRANS_RESPECT;
		}
		else if(!de_strcmp(opt_trans_str, "2")) {
			d->trans_setting = TRANS_ASSOC;
		}
	}

	detect_file_format(c, d);

	if(d->file_format==FMT_VST) {
		de_declare_fmt(c, "TrueVista");
	}
	else {
		de_declare_fmt(c, "TGA");
	}

	d->thumbnail_image.is_thumb = 1;

	pos = 0;

	if(d->file_format==FMT_VST) {
		if(!do_read_vst_headers(c, d)) goto done;
	}
	else {
		if(!do_read_tga_headers(c, d)) goto done;
	}

	if(d->trans_setting==TRANS_ASSOC) {
		d->alpha_is_premultiplied = 1;
	}

	pos += 18;

	de_dbg(c, "image/color data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	read_image_id(c, d, pos);
	pos += d->id_field_len;

	if(d->color_map_type!=0) {
		d->bytes_per_pal_entry = (d->cmap_depth+7)/8;
		d->pal_size_in_bytes = d->cmap_length * d->bytes_per_pal_entry;
		de_dbg(c, "color map at %"I64_FMT" (%d colors, %d bytes)", pos,
			(int)d->cmap_length, (int)d->pal_size_in_bytes);

		de_dbg_indent(c, 1);
		if(!do_read_palette(c, d, pos)) goto done;
		de_dbg_indent(c, -1);

		pos += d->pal_size_in_bytes;
	}

	de_dbg(c, "bitmap at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->bytes_per_pixel = ((d->pixel_depth+7)/8);
	if(d->pixel_depth==1) {
		rowspan_tmp = (d->main_image.width+7)/8;
	}
	else {
		rowspan_tmp = d->main_image.width * d->bytes_per_pixel;
	}
	d->main_image.img_size_in_bytes = d->main_image.height * rowspan_tmp;

	if(d->color_type!=TGA_CLRTYPE_PALETTE && d->color_type!=TGA_CLRTYPE_TRUECOLOR &&
		d->color_type!=TGA_CLRTYPE_GRAYSCALE)
	{
		de_err(c, "Unsupported color type (%d: %s)", (int)d->color_type, d->clrtype_name);
		goto done;
	}

	if( (d->color_type==TGA_CLRTYPE_PALETTE && d->pixel_depth==8) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==15) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==16) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==24) ||
		(d->color_type==TGA_CLRTYPE_TRUECOLOR && d->pixel_depth==32) ||
		(d->color_type==TGA_CLRTYPE_GRAYSCALE && d->pixel_depth==1) ||
		(d->color_type==TGA_CLRTYPE_GRAYSCALE && d->pixel_depth==8) )
	{
		;
	}
	else {
		de_err(c, "Unsupported TGA image type (%s, depth=%d)", d->clrtype_name,
			(int)d->pixel_depth);
		goto done;
	}

	if(d->cmpr_type==TGA_CMPR_RLE) {
		if(d->pixel_depth<8) {
			de_err(c, "RLE compression not supported when depth (%d) is less than 8",
				(int)d->pixel_depth);
			goto done;
		}
		unc_pixels = dbuf_create_membuf(c, d->main_image.img_size_in_bytes, 1);
		dbuf_enable_wbuffer(unc_pixels);
		if(!do_decode_rle(c, d, pos, unc_pixels)) goto done;
	}
	else if(d->cmpr_type==TGA_CMPR_NONE) {
		unc_pixels = dbuf_open_input_subfile(c->infile, pos, d->main_image.img_size_in_bytes);
	}
	else {
		de_err(c, "Unsupported image or compression type");
		goto done;
	}

	do_decode_image(c, d, &d->main_image, unc_pixels, NULL, 0);

	de_dbg_indent(c, -2);

	if(d->thumbnail_offset!=0) {
		do_decode_thumbnail(c, d);
	}

done:
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, d);
}

static int de_identify_tga(deark *c)
{
	u8 b[18];
	u8 x;
	int has_tga_ext;
	i64 v2_footer_pos = 0;

	// TGA v1 format has no signature, but there are only a few common types of
	// it. We'll at least try to identify anything that we support.
	de_read(b, 0, 18);

	if(b[1]>1) return 0; // Color map type should be 0 or 1.

	if(b[12]==0 && b[13]==0) return 0; // Width can't be 0.
	if(b[14]==0 && b[15]==0) return 0; // Height can't be 0.

	if(look_for_v2_signature(c, 1, &v2_footer_pos)) {
		return 100;
	}

	// 0 is valid here, but it means "no image", and we need all the
	// can't-be-0 bytes we can find...
	if(b[2]==0) {
		// ...except that we have to allow 0 in .vst format.
		// TODO: .vst should maybe be a separate module.
		if((UI)de_getu32be(20)!=CODE_IGCH) {
			return 0;
		}
	}
	else if(b[2]==1 || b[2]==2 || b[2]==3 ||
		b[2]==9 || b[2]==10 || b[2]==11 || b[2]==32 || b[2]==33)
	{
		;
	}
	else {
		return 0; // Unknown image type
	}

	// bits/pixel:
	if(b[16]!=1 && b[16]!=8 && b[16]!=15 && b[16]!=16 && b[16]!=24 && b[16]!=32) return 0;

	// Bits per palette entry. Supposed to be 0 if there is no palette, but
	// in practice it may be 24 instead.
	if((b[1]==0 && b[7]==0) || b[7]==15 || b[7]==16 || b[7]==24 || b[7]==32) {
		;
	}
	else {
		return 0;
	}

	has_tga_ext = de_input_file_has_ext(c, "tga");

	x = b[17]&0x0f; // Number of attribute bits
	if(x!=0 && x!=1 && x!=8 && !has_tga_ext) return 0;

	if(has_tga_ext) {
		return 100;
	}
	if(de_input_file_has_ext(c, "vst")) {
		return 40;
	}
	return 8;
}

static void de_help_tga(deark *c)
{
	de_msg(c, "-opt tga:trans=<0|1|2|auto> : Transparency: 0=remove, 1=respect, "
		"2=premultiplied");
}

void de_module_tga(deark *c, struct deark_module_info *mi)
{
	mi->id = "tga";
	mi->desc = "Truevision TGA, a.k.a. TARGA";
	mi->run_fn = de_run_tga;
	mi->identify_fn = de_identify_tga;
	mi->help_fn = de_help_tga;
}
