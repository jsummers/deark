// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// PCF font

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pcf);

#define TBLTYPE_PROPERTIES  0x1
#define TBLTYPE_METRICS     0x4
#define TBLTYPE_BITMAPS     0x8
#define TBLTYPE_BDF_ENCODINGS 0x20

#define GFMT_DEFAULT 0
#define GFMT_COMPRESSED_METRICS  0x00000100

struct table_entry;
struct localctx_struct;
typedef struct localctx_struct lctx;

typedef void (*table_entry_handler_fn)(deark *c, lctx *d, struct table_entry *te);

struct char_info {
	unsigned int bitmap_offset;
	de_int32 codepoint;
	int width_raw, height_raw; // Dimensions of the bitmap stored in the file
};

struct format_struct {
	de_uint32 raw_format;
	unsigned int gross_format; // GFMT_*
	unsigned int glyph_padding_code;
	unsigned int glyph_padding_value;
	int is_le;
	int msbit_first;
	unsigned int scan_unit_code;
	unsigned int scan_unit_value;
};

struct table_entry {
	struct format_struct fmt;
	de_uint32 type;
	de_int64 size;
	de_int64 offset;

	const char *type_name;
	table_entry_handler_fn handler_fn;
};

struct localctx_struct {
	de_int64 table_count;
	struct table_entry *tables;

	// AFAICT: In a PCF file, each "character" has a natural index, implicitly
	// used by the metrics table, bitmaps table, glyph names table, etc.
	// This chars[] array is indexed in the same way. It is allocated when we
	// read the metrics table.
	// (The encodings table is different: It maps codepoints to these indices.)
	de_int64 num_chars;
	struct char_info *chars;

	de_int64 bitmaps_data_len;
	de_byte *bitmaps_data;

	struct format_struct bitmaps_fmt;

	de_byte has_encodings_table;
};

// Read a 'format' field, populate caller-supplied 'fmt'.
static void read_format_field(deark *c, lctx *d, struct table_entry *te,
	de_int64 pos, struct format_struct *fmt)
{
	const char *name;

	fmt->raw_format = (unsigned int)de_getui32le(pos);
	de_dbg(c, "format: 0x%08x", fmt->raw_format);
	de_dbg_indent(c, 1);

	fmt->gross_format = fmt->raw_format&0xffffff00U;
	if(fmt->gross_format==GFMT_DEFAULT) {
		name="DEFAULT";
	}
	else if(fmt->gross_format==0x100 && (te->type==0x02 || te->type==0x100)) {
		name="ACCEL_W_INKBOUNDS";
	}
	else if(fmt->gross_format==0x100 && (te->type==0x04 || te->type==0x10)) {
		name="COMPRESSED_METRICS";
	}
	else if(fmt->gross_format==0x200) {
		name="INKBOUNDS";
	}
	else {
		name="?";
	}
	de_dbg(c, "gross format: 0x%08x (%s)", fmt->gross_format, name);

	fmt->glyph_padding_code = fmt->raw_format&0x03;
	fmt->glyph_padding_value = 1U<<(fmt->glyph_padding_code);
	de_dbg(c, "glyph padding: %u (= to %u-byte boundary)",fmt->glyph_padding_code,
		fmt->glyph_padding_value);
	fmt->is_le = !((fmt->raw_format>>2)&0x1);
	de_dbg(c, "byte order: %s", fmt->is_le?"LE":"BE");
	fmt->msbit_first = ((fmt->raw_format>>3)&0x1)?1:0;
	de_dbg(c, "bit order: %s first", fmt->msbit_first?"msb":"lsb");

	fmt->scan_unit_code = (fmt->raw_format>>4)&0x03;
	fmt->scan_unit_value = 1U<<fmt->scan_unit_code;
	de_dbg(c, "scan unit: %u (= %u-byte units)", fmt->scan_unit_code,
		fmt->scan_unit_value);
	de_dbg_indent(c, -1);
}

static int read_and_check_format_field(deark *c, lctx *d, struct table_entry *te, de_int64 pos)
{
	de_uint32 format;

	format = (de_uint32)de_getui32le_p(&pos);
	de_dbg(c, "format: 0x%08x", (unsigned int)format);
	if(format != te->fmt.raw_format) {
		de_err(c, "Can't handle conflicting \"format\" fields");
		return 0;
	}
	return 1;
}

static void read_prop_string(deark *c, lctx *d, struct table_entry *te,
	 de_int64 pos, const char *name)
{
	de_ucstring *str = NULL;

	str = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos,
		te->offset+te->size-pos,
		DE_DBG_MAX_STRLEN, str, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(str));
	ucstring_destroy(str);
}

static void handler_properties(deark *c, lctx *d, struct table_entry *te)
{
	de_int64 pos = te->offset;
	de_int64 nprops;
	int saved_indent_level;
	de_int64 props_idx_pos;
	de_int64 props_idx_size_padded;
	de_int64 string_data_area_pos;
	de_int64 string_data_area_size;
	de_int64 k;

	de_dbg(c, "properties table at %"INT64_FMT, pos);
	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg_indent(c, 1);

	if(!read_and_check_format_field(c, d, te, pos)) goto done;
	pos += 4;

	nprops = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
	pos += 4;
	de_dbg(c, "nprops: %d", (int)nprops);

	props_idx_pos = pos;
	props_idx_size_padded = de_pad_to_4(nprops*9);
	de_dbg(c, "properties index at %"INT64_FMT, props_idx_pos);

	pos += props_idx_size_padded;

	string_data_area_size = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
	pos += 4;
	string_data_area_pos = pos;
	de_dbg(c, "string data area at %"INT64_FMT", len=%d", string_data_area_pos,
		(int)string_data_area_size);

	// Go back and read the properties table
	pos = props_idx_pos;
	for(k=0; k<nprops; k++) {
		de_byte isstringprop;
		de_int64 name_offset;

		if(pos+9 > te->offset + te->size) break;
		de_dbg(c, "property[%d] index entry at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);

		name_offset = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
		de_dbg(c, "name offset: %"INT64_FMT" (abs=%"INT64_FMT")", name_offset,
			string_data_area_pos+name_offset);
		pos += 4;
		read_prop_string(c, d, te, string_data_area_pos+name_offset, "name");

		isstringprop = de_getbyte_p(&pos);
		de_dbg(c, "isStringProp: %u", (unsigned int)isstringprop);

		if(isstringprop) {
			de_int64 value_offset;

			value_offset = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
			de_dbg(c, "value offset: %"INT64_FMT" (abs=%"INT64_FMT")", value_offset,
				string_data_area_pos+value_offset);
			read_prop_string(c, d, te, string_data_area_pos+value_offset, "value");
		}
		else {
			de_int64 value;

			value = dbuf_geti32x(c->infile, pos, te->fmt.is_le);
			de_dbg(c, "value: %"INT64_FMT, value);
		}
		pos += 4;

		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void handler_metrics(deark *c, lctx *d, struct table_entry *te)
{
	de_int64 pos = te->offset;
	int saved_indent_level;
	de_int64 nmetrics;
	de_int64 k;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "metrics table at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);

	if(!read_and_check_format_field(c, d, te, pos)) goto done;
	pos += 4;

	nmetrics = dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	pos += 2;
	de_dbg(c, "number of metrics: %d", (int)nmetrics);

	d->num_chars = nmetrics;

	// Allocate chars array, and set defaults
	d->chars = de_malloc(c, sizeof(struct char_info)*d->num_chars);
	for(k=0; k<d->num_chars; k++) {
		d->chars[k].codepoint = DE_CODEPOINT_INVALID;
	}

	for(k=0; k<d->num_chars; k++) {
		int leftsb, rightsb;
		int char_width;
		int char_asc, char_desc;
		unsigned int char_attr;
		struct char_info *ci;

		de_dbg2(c, "char[%d]", (int)k);
		de_dbg_indent(c, 1);
		ci = &d->chars[k];

		if(te->fmt.gross_format==GFMT_COMPRESSED_METRICS) {
			leftsb = (int)de_getbyte_p(&pos) - 0x80;
			rightsb = (int)de_getbyte_p(&pos) - 0x80;
			char_width = (int)de_getbyte_p(&pos) - 0x80;
			char_asc = (int)de_getbyte_p(&pos) - 0x80;
			char_desc = (int)de_getbyte_p(&pos) - 0x80;
			char_attr = 0;
		}
		else {
			leftsb = (int)dbuf_geti16x(c->infile, pos, te->fmt.is_le); pos += 2;
			rightsb = (int)dbuf_geti16x(c->infile, pos, te->fmt.is_le); pos += 2;
			char_width = (int)dbuf_geti16x(c->infile, pos, te->fmt.is_le); pos += 2;
			char_asc = (int)dbuf_geti16x(c->infile, pos, te->fmt.is_le); pos += 2;
			char_desc = (int)dbuf_geti16x(c->infile, pos, te->fmt.is_le); pos += 2;
			char_attr = (int)dbuf_getui16x(c->infile, pos, te->fmt.is_le); pos += 2;
		}

		if(c->debug_level>=2) {
			de_dbg2(c, "bearing (l, r): %d, %d", leftsb, rightsb);
			de_dbg2(c, "width: %d", char_width);
			de_dbg2(c, "ascent, descent: %d, %d", char_asc, char_desc);
			de_dbg2(c, "attributes: %u", char_attr);
		}
		ci->width_raw = rightsb - leftsb;
		ci->height_raw = char_asc + char_desc;
		if(c->debug_level>=2) {
			de_dbg(c, "raw bitmap dimensions: %d"DE_CHAR_TIMES"%d",
				ci->width_raw,ci->height_raw);
		}

		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void handler_bdf_encodings(deark *c, lctx *d, struct table_entry *te)
{
	de_int64 pos = te->offset;
	int saved_indent_level;
	unsigned int min_char_or_byte2, max_char_or_byte2;
	unsigned int min_byte1, max_byte1;
	unsigned int default_char;
	unsigned int byte1_count, byte2_count;
	int is_singlebyte_encoding;
	de_int64 ncodepoints;
	de_int64 k;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "BDF encodings table at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);

	if(!read_and_check_format_field(c, d, te, pos)) goto done;
	pos += 4;
	if(te->fmt.gross_format != GFMT_DEFAULT) goto done;

	min_char_or_byte2 = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	de_dbg(c, "min_char_or_byte2: %u", min_char_or_byte2);
	pos += 2;
	max_char_or_byte2 = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	de_dbg(c, "max_char_or_byte2: %u", max_char_or_byte2);
	pos += 2;
	min_byte1 = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	de_dbg(c, "min_byte1: %u", min_byte1);
	pos += 2;
	max_byte1 = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	de_dbg(c, "max_byte1: %u", max_byte1);
	pos += 2;
	default_char = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);
	de_dbg(c, "default_char: %u", default_char);
	pos += 2;

	if(min_char_or_byte2>max_char_or_byte2) goto done;
	if(min_byte1>max_byte1) goto done;

	is_singlebyte_encoding = (min_byte1==0 && max_byte1==0);
	de_dbg(c, "encoding type: %s", is_singlebyte_encoding?"single byte":"double byte");

	byte1_count = max_byte1-min_byte1+1;
	byte2_count = max_char_or_byte2-min_char_or_byte2+1;
	ncodepoints = byte1_count * byte2_count;
	de_dbg(c, "number of codepoints in table: %"INT64_FMT, ncodepoints);

	d->has_encodings_table = 1;

	for(k=0; k<ncodepoints; k++) {
		unsigned int glyph_number;
		de_int32 codepoint;

		if(pos+2 > te->offset+te->size) break;
		glyph_number = (unsigned int)dbuf_getui16x(c->infile, pos, te->fmt.is_le);

		if(is_singlebyte_encoding) {
			codepoint = (de_int32)k + (de_int32)min_char_or_byte2;
		}
		else {
			unsigned int tmp_hi, tmp_lo;
			tmp_hi = ((unsigned int)k)/byte2_count;
			tmp_lo = ((unsigned int)k)%byte2_count;
			codepoint = (de_int32)(((min_char_or_byte2+tmp_hi)<<8) |
				(min_byte1+tmp_lo));
		}

		if(glyph_number!=0xffff && glyph_number<d->num_chars) {
			d->chars[glyph_number].codepoint = codepoint;
		}

		if(c->debug_level>=2) {
			char gstr[40];
			if(glyph_number==0xffff) {
				de_strlcpy(gstr, "no char", sizeof(gstr));
			}
			else {
				de_snprintf(gstr, sizeof(gstr), "char[%u]", glyph_number);
			}
			de_dbg2(c, "[%d]: codepoint[%d] = %s", (int)k, (int)codepoint, gstr);
		}

		pos += 2;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void reverse_bit_order(de_byte *m, de_int64 m_len)
{
	de_int64 k;
	static const de_byte tbl[16] = {
		0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
		0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf };

	for(k=0; k<m_len; k++) {
		m[k] = (tbl[m[k]&0x0f]<<4) | tbl[(m[k]&0xf0)>>4];
	}
}

static void handler_bitmaps(deark *c, lctx *d, struct table_entry *te)
{
	de_int64 pos = te->offset;
	de_int64 nglyphs;
	de_int64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "bitmap table at %"INT64_FMT, pos);
	de_dbg_indent(c, 1);

	if(!read_and_check_format_field(c, d, te, pos)) goto done;
	pos += 4;
	d->bitmaps_fmt = te->fmt; // struct copy

	nglyphs = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
	pos += 4;
	de_dbg(c, "glyph count: %d", (int)nglyphs);

	if(nglyphs != d->num_chars) {
		de_warn(c, "Expected %d bitmaps, found %d", (int)d->num_chars, (int)nglyphs);
	}
	if(nglyphs < d->num_chars) {
		d->num_chars = nglyphs;
	}

	for(k=0; k<d->num_chars; k++) {
		d->chars[k].bitmap_offset = (unsigned int)dbuf_getui32x(c->infile, pos, te->fmt.is_le);
		pos += 4;
		if(c->debug_level>=2)
			de_dbg2(c, "char[%d] glyph offset: %u", (int)k, d->chars[k].bitmap_offset);
	}

	for(k=0; k<4; k++) {
		de_int64 bitmapsize;
		int use_this_one;

		bitmapsize = dbuf_getui32x(c->infile, pos, te->fmt.is_le);
		pos += 4;
		use_this_one = (((unsigned int)k)==te->fmt.glyph_padding_code);
		de_dbg(c, "bitmapsize[if padding=%d]: %u%s", (int)k, (unsigned int)bitmapsize,
			use_this_one?" *":"");
		if(use_this_one) {
			d->bitmaps_data_len = bitmapsize;
		}
	}

	if(pos + d->bitmaps_data_len > te->offset+te->size) {
		// error
		d->bitmaps_data_len = 0;
		goto done;
	}

	if(te->fmt.is_le && te->fmt.scan_unit_value>1) {
		// TODO: Support this
		de_err(c, "Little-endian byte order is not supported");
		goto done;
	}

	de_dbg(c, "bitmaps data at %"INT64_FMT", len=%"INT64_FMT, pos, d->bitmaps_data_len);
	d->bitmaps_data = de_malloc(c, d->bitmaps_data_len);
	de_read(d->bitmaps_data, pos, d->bitmaps_data_len);
	if(!te->fmt.msbit_first) {
		reverse_bit_order(d->bitmaps_data, d->bitmaps_data_len);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Caller sets te->type.
// This function sets: ->type_name, ->handler_fn
static void lookup_table_entry_type_info(deark *c, lctx *d, struct table_entry *te)
{
	switch(te->type) {
	case TBLTYPE_PROPERTIES:
		te->type_name = "properties";
		te->handler_fn = handler_properties;
		break;
	case 0x2:
		te->type_name = "accelerators";
		break;
	case TBLTYPE_METRICS:
		te->type_name = "metrics";
		te->handler_fn = handler_metrics;
		break;
	case TBLTYPE_BITMAPS:
		te->type_name = "bitmaps";
		te->handler_fn = handler_bitmaps;
		break;
	case 0x10:
		te->type_name = "ink metrics";
		break;
	case TBLTYPE_BDF_ENCODINGS:
		te->type_name = "BDF encodings";
		te->handler_fn = handler_bdf_encodings;
		break;
	case 0x40:
		te->type_name = "swidths";
		break;
	case 0x80:
		te->type_name = "glyph names";
		break;
	case 0x100:
		te->type_name = "BDF accelerators";
		break;
	default:
		te->type_name = "?";
	}
}

static int do_read_table_entry(deark *c, lctx *d, struct table_entry *te, de_int64 pos1)
{
	int retval = 0;
	de_int64 pos = pos1;

	if(pos1+16 > c->infile->len) goto done;

	te->type = (unsigned int)de_getui32le_p(&pos);
	lookup_table_entry_type_info(c, d, te);
	de_dbg(c, "type: 0x%08x (%s)", te->type, te->type_name);

	read_format_field(c, d, te, pos, &te->fmt);
	pos += 4;

	te->size = de_getui32le_p(&pos);
	te->offset = de_getui32le_p(&pos);
	de_dbg(c, "offset: %"INT64_FMT", size: %"INT64_FMT, te->offset, te->size);
	if(te->offset+te->size > c->infile->len) {
		de_warn(c, "table entry goes beyond end of file");
	}
	if(te->offset > c->infile->len) {
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void do_make_font_image(deark *c, lctx *d)
{
	struct de_bitmap_font *font = NULL;
	de_int64 k;
	int max_char_width = 1;
	int max_char_height = 1;

	if(!d->chars) goto done;
	if(!d->bitmaps_data) goto done;

	font = de_create_bitmap_font(c);

	font->num_chars = d->num_chars;
	font->has_nonunicode_codepoints = 1;
	font->has_unicode_codepoints = 0;
	font->prefer_unicode = 0;

	font->char_array = de_malloc(c, d->num_chars * sizeof(struct de_bitmap_font_char));

	for(k=0; k<font->num_chars; k++) {
		struct de_bitmap_font_char *ch = &font->char_array[k];
		struct char_info *ci = &d->chars[k];
		de_int64 bitmap_len;

		ch->codepoint_nonunicode = (de_int32)ci->codepoint;

		ch->width = ci->width_raw;
		ch->height = ci->height_raw;
		if(ch->width<1) ch->width=1;
		if(ch->height<1) ch->height=1;

		ch->rowspan = de_pad_to_n((de_int64)((ci->width_raw+7)/8), (de_int64)d->bitmaps_fmt.glyph_padding_value);
		bitmap_len = ch->rowspan * ci->height_raw;
		if(ci->bitmap_offset + bitmap_len <= d->bitmaps_data_len) {
			ch->bitmap = &d->bitmaps_data[ci->bitmap_offset];
		}
		else {
			ch->bitmap = NULL;
			continue;
		}

		if(ch->width > max_char_width) max_char_width = ch->width;
		if(ch->height > max_char_height) max_char_height = ch->height;
	}

	font->nominal_width = max_char_width;
	font->nominal_height = max_char_height;

	de_font_bitmap_font_to_image(c, font, NULL, 0);

done:
	if(font) {
		de_free(c, font->char_array);
		de_destroy_bitmap_font(c, font);
	}
}

// If a table of type tbltype exists in d->tables[], process it.
// Processes at most one table.
static int process_table_by_type(deark *c, lctx *d, de_uint32 tbltype)
{
	de_int64 k;
	struct table_entry *te;

	for(k=0; k<d->table_count; k++) {
		te = &d->tables[k];
		if(te->type == tbltype) {
			if(te->handler_fn) {
				te->handler_fn(c, d, te);
			}
			return 1;
		}
	}
	return 0;
}

static void de_run_pcf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	pos += 4; // signature

	d->table_count = de_getui32le_p(&pos);
	de_dbg(c, "table count: %u", (unsigned int)d->table_count);
	if(d->table_count>256) goto done;

	// We don't necessarily want to process the tables in the order they are
	// listed in the index, so first read the tables index into memory.
	d->tables = de_malloc(c, d->table_count*sizeof(struct table_entry));

	for(k=0; k<d->table_count; k++) {
		de_dbg(c, "table entry[%d] at %"INT64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		if(!do_read_table_entry(c, d, &d->tables[k], pos)) goto done;
		de_dbg_indent(c, -1);
		pos += 16;
	}

	// Now process the tables in the order we choose.

	process_table_by_type(c, d, TBLTYPE_PROPERTIES);
	if(!process_table_by_type(c, d, TBLTYPE_METRICS)) {
		de_err(c, "Missing metrics table");
		goto done;
	}

	process_table_by_type(c, d, TBLTYPE_BDF_ENCODINGS);

	if(!d->has_encodings_table) {
		for(k=0; k<d->num_chars; k++) {
			d->chars[k].codepoint = (de_int32)k;
		}
	}

	if(!process_table_by_type(c, d, TBLTYPE_BITMAPS)) {
		de_err(c, "Missing bitmaps table");
		goto done;
	}

	do_make_font_image(c, d);

done:
	if(d) {
		de_free(c, d->tables);
		de_free(c, d->chars);
		de_free(c, d->bitmaps_data);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_pcf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x01" "fcp", 4))
		return 100;
	return 0;
}

void de_module_pcf(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcf";
	mi->desc = "PCF font";
	mi->run_fn = de_run_pcf;
	mi->identify_fn = de_identify_pcf;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
