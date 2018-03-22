// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// IPTC metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iptc);

typedef struct localctx_struct {
	// The coded character set defined in 1:90.
	// This applied to records 2-6, and sometimes 8.
	int charset;
} lctx;

struct ds_info;

typedef void (*ds_handler_fn)(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);

struct ds_info {
	de_byte recnum;
	de_byte dsnum;

	// 0x1 = A field consisting entirely of text ("graphic characters",
	//       "alphabetic characters", "numeric characters, "spaces", etc.)
	de_uint32 flags;

	const char *dsname;
	ds_handler_fn hfn;
};

static void handle_text(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);
static void handle_uint16(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);
static void handle_1_90(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);
static void handle_2_120(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);
static void handle_2_125(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len);

static const struct ds_info ds_info_arr[] = {
	{ 1, 0,   0,      "Model Version", handle_uint16 },
	{ 1, 5,   0x0001, "Destination", NULL },
	{ 1, 20,  0,      "File Format", handle_uint16 },
	{ 1, 22,  0,      "File Format Version", handle_uint16 },
	{ 1, 30,  0x0001, "Service Identifier", NULL },
	{ 1, 40,  0x0001, "Envelope Number", NULL },
	{ 1, 50,  0x0001, "Product I.D.", NULL },
	{ 1, 60,  0x0001, "Envelope Priority", NULL },
	{ 1, 70,  0x0001, "Date Sent", NULL },
	{ 1, 80,  0x0001, "Time Sent", NULL },
	{ 1, 90,  0,      "Coded Character Set", handle_1_90 },
	{ 1, 100, 0x0001, "UNO", NULL },
	{ 1, 120, 0,      "ARM Identifier", handle_uint16 },
	{ 1, 122, 0,      "ARM Version", handle_uint16 },
	{ 2, 0,   0,      "Record Version", handle_uint16 },
	{ 2, 3,   0x0001, "Object Type Reference", NULL },
	{ 2, 4,   0x0001, "Object Attribute Reference", NULL },
	{ 2, 5,   0x0001, "Object Name", NULL },
	{ 2, 7,   0x0001, "Edit Status", NULL },
	{ 2, 8,   0x0001, "Editorial Update", NULL },
	{ 2, 10,  0x0001, "Urgency", NULL },
	{ 2, 12,  0x0001, "Subject Reference", NULL },
	{ 2, 15,  0x0001, "Category", NULL },
	{ 2, 20,  0x0001, "Supplemental Category", NULL },
	{ 2, 22,  0x0001, "Fixture Identifier", NULL },
	{ 2, 25,  0x0001, "Keywords", NULL },
	{ 2, 26,  0x0001, "Content Location Code", NULL },
	{ 2, 27,  0x0001, "Content Location Name", NULL },
	{ 2, 30,  0x0001, "Release Date", NULL },
	{ 2, 35,  0x0001, "Release Time", NULL },
	{ 2, 37,  0x0001, "Expiration Date", NULL },
	{ 2, 38,  0x0001, "Expiration Time", NULL },
	{ 2, 40,  0x0001, "Special Instructions", NULL },
	{ 2, 42,  0x0001, "Action Advised", NULL },
	{ 2, 45,  0x0001, "Reference Service", NULL },
	{ 2, 47,  0x0001, "Reference Date", NULL },
	{ 2, 50,  0x0001, "Reference Number", NULL },
	{ 2, 55,  0x0001, "Date Created", NULL },
	{ 2, 60,  0x0001, "Time Created", NULL },
	{ 2, 62,  0x0001, "Digital Creation Date", NULL },
	{ 2, 63,  0x0001, "Digital Creation Time", NULL },
	{ 2, 65,  0x0001, "Originating Program", NULL },
	{ 2, 70,  0x0001, "Program Version", NULL },
	{ 2, 75,  0x0001, "Object Cycle", NULL },
	{ 2, 80,  0x0001, "By-line", NULL },
	{ 2, 85,  0x0001, "By-line Title", NULL },
	{ 2, 90,  0x0001, "City", NULL },
	{ 2, 92,  0x0001, "Sub-location", NULL },
	{ 2, 95,  0x0001, "Province/State", NULL },
	{ 2, 100, 0x0001, "Country/Primary Location Code", NULL },
	{ 2, 101, 0x0001, "Country/Primary Location Name", NULL },
	{ 2, 103, 0x0001, "Original Transmission Reference", NULL },
	{ 2, 105, 0x0001, "Headline", NULL },
	{ 2, 110, 0x0001, "Credit", NULL },
	{ 2, 115, 0x0001, "Source", NULL },
	{ 2, 116, 0x0001, "Copyright Notice", NULL },
	{ 2, 118, 0x0001, "Contact", NULL },
	{ 2, 120, 0x0001, "Caption/Abstract", handle_2_120 },
	{ 2, 122, 0x0001, "Writer/Editor", NULL },
	{ 2, 125, 0,      "Rasterized Caption", handle_2_125 },
	{ 2, 130, 0x0001, "Image Type", NULL },
	{ 2, 131, 0x0001, "Image Orientation", NULL },
	{ 2, 135, 0x0001, "Language Identifier", NULL },
	{ 2, 150, 0x0001, "Audio Type", NULL },
	{ 2, 151, 0x0001, "Audio Sampling Rate", NULL },
	{ 2, 152, 0x0001, "Audio Sampling Resolution", NULL },
	{ 2, 153, 0x0001, "Audio Duration", NULL },
	{ 2, 154, 0x0001, "Audio Outcue", NULL },
	{ 2, 200, 0,      "ObjectData Preview File Format", handle_uint16 },
	{ 2, 201, 0,      "ObjectData Preview File Format Version", handle_uint16 },
	{ 2, 202, 0,      "ObjectData Preview Data", NULL },
	// TODO: record 3
	// TODO: record 6
	{ 7, 10,  0,      "Size Mode", NULL },
	{ 7, 20,  0,      "Max Subfile Size", NULL },
	{ 7, 90,  0,      "ObjectData Size Announced", NULL },
	{ 7, 95,  0,      "Maximum ObjectData Size", NULL },
	{ 8, 10,  0,      "Subfile", NULL },
	{ 9, 10,  0,      "Confirmed ObjectData Size", NULL }
};

static int get_ds_encoding(deark *c, lctx *d, de_byte recnum)
{
	if(recnum>=2 && recnum<=6) {
		return d->charset;
	}
	return DE_ENCODING_UNKNOWN;
}

static void handle_1_90(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	const char *csname;

	d->charset = DE_ENCODING_UNKNOWN;

	// TODO: Fully interpret this field.

	if(len>=3 && !dbuf_memcmp(c->infile, pos, "\x1b\x25\x47", 3)) {
		d->charset = DE_ENCODING_UTF8;
	}

	if(d->charset==DE_ENCODING_UTF8)
		csname="utf-8";
	else
		csname="unknown";

	de_dbg(c, "charset: %s", csname);
}

// Caption/abstract
static void handle_2_120(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;
	dbuf *outf = NULL;
	int encoding;
	const char *fntoken;

	if(c->extract_level<2) {
		handle_text(c, d, dsi, pos, len);
		goto done;
	}

	// FIXME: There is currently no way to extract IPTC captions to files,
	// except when reading a raw IPTC file. If IPTC is embedded in some other
	// file (as it usually is), then the -a option will extract the entire
	// IPTC data, and we will never get here.

	fntoken = "caption.txt";

	encoding = get_ds_encoding(c, d, dsi->recnum);
	if(encoding==DE_ENCODING_UNKNOWN) {
		// If the encoding is unknown, copy the raw bytes.
		dbuf_create_file_from_slice(c->infile, pos, len, fntoken,
			NULL, DE_CREATEFLAG_IS_AUX);
		goto done;
	}

	// If the encoding is known, convert to UTF-8.
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	outf = dbuf_create_output_file(c, fntoken, NULL, DE_CREATEFLAG_IS_AUX);
	ucstring_write_as_utf8(c, s, outf, 1);

done:
	if(outf) dbuf_close(outf);
	if(s) ucstring_destroy(s);
}

// Rasterized caption
static void handle_2_125(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	de_int64 i, j;
	de_byte b;
	de_int64 rowspan;
	de_int64 width, height;

	// I can't find any examples of this field, so this may not be correct.
	// The format seems to be well-documented, though the pixels are in an
	// unusual order.

	unc_pixels = dbuf_open_input_subfile(c->infile, pos, len);
	width = 460;
	height = 128;
	img = de_bitmap_create(c, width, height, 1);
	rowspan = height/8;

	for(j=0; j<width; j++) {
		for(i=0; i<height; i++) {
			b = de_get_bits_symbol(unc_pixels, 1, rowspan*j, i);
			de_bitmap_setpixel_gray(img, j, (height-1-i), b?0:255);
		}
	}

	de_bitmap_write_to_file(img, "caption", DE_CREATEFLAG_IS_AUX);
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
}

// Caller supplies dsi. This function will set its fields.
static int lookup_ds_info(de_byte recnum, de_byte dsnum, struct ds_info *dsi)
{
	size_t i;

	de_memset(dsi, 0, sizeof(struct ds_info));

	for(i=0; i<DE_ITEMS_IN_ARRAY(ds_info_arr); i++) {
		if(ds_info_arr[i].recnum==recnum && ds_info_arr[i].dsnum==dsnum) {
			*dsi = ds_info_arr[i]; // struct copy
			return 1;
		}
	}

	// Not found
	dsi->recnum = recnum;
	dsi->dsnum = dsnum;
	dsi->dsname = "?";
	return 0;
}

static int read_dflen(deark *c, dbuf *f, de_int64 pos,
	de_int64 *dflen, de_int64 *bytes_consumed)
{
	de_int64 x;

	x = dbuf_getui16be(f, pos);
	if(x<32768) { // "Standard DataSet" format
		*dflen = x;
		*bytes_consumed = 2;
	}
	else { // "Extended DataSet" format
		de_int64 length_of_length;
		de_int64 i;

		length_of_length = x - 32768;
		*dflen = 0;
		*bytes_consumed = 2 + length_of_length;

		for(i=0; i<length_of_length; i++) {
			*dflen = ((*dflen)<<8) | dbuf_getbyte(f, pos+2+i);

			// IPTC seems to support fields up to (2^262136)-1 bytes.
			// We arbitrarily limit it (2^48)-1.
			if((*dflen)>=0x1000000000000LL) {
				de_err(c, "Bad or unsupported IPTC data field length");
				return 0;
			}
		}
	}

	return 1;
}

static void handle_text(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	int encoding;
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	encoding = get_ds_encoding(c, d, dsi->recnum);
	if(encoding==DE_ENCODING_UNKNOWN)
		encoding = DE_ENCODING_ASCII;
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, encoding);
	de_dbg(c, "%s: \"%s\"", dsi->dsname, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void handle_uint16(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	de_int64 x;
	if(len!=2) return;
	x = de_getui16be(pos);
	de_dbg(c, "%s: %d", dsi->dsname, (int)x);
}

static int do_dataset(deark *c, lctx *d, de_int64 ds_idx, de_int64 pos1,
	de_int64 *bytes_consumed)
{
	de_byte b;
	de_byte recnum, dsnum;
	int retval = 0;
	de_int64 pos = pos1;
	de_int64 dflen;
	de_int64 dflen_bytes_consumed;
	struct ds_info dsi;
	int ds_known;

	*bytes_consumed = 0;

	b = de_getbyte(pos);
	if(b!=0x1c) {
		if(b==0x00 && ds_idx>0) {
			// Extraneous padding at the end of data?
			de_warn(c, "Expected %d bytes of IPTC data, only found %d",
				(int)c->infile->len, (int)pos);
		}
		else {
			de_err(c, "Bad IPTC tag marker (0x%02x) at %d", (int)b, (int)pos);
		}
		goto done;
	}
	pos++;

	recnum = de_getbyte(pos++);
	dsnum = de_getbyte(pos++);

	ds_known = lookup_ds_info(recnum, dsnum, &dsi);

	if(!read_dflen(c, c->infile, pos, &dflen, &dflen_bytes_consumed)) goto done;
	pos += dflen_bytes_consumed;

	de_dbg(c, "IPTC dataset %d:%02d (%s) dpos=%" INT64_FMT " dlen=%" INT64_FMT "",
		(int)recnum, (int)dsnum, dsi.dsname, pos, dflen);

	// Decode the value
	de_dbg_indent(c, 1);

	if(dsi.hfn) {
		dsi.hfn(c, d, &dsi, pos, dflen);
	}
	else if(dsi.flags&0x1) {
		handle_text(c, d, &dsi, pos, dflen);
	}
	else if(dsi.recnum==2 && !ds_known) {
		// Unknown record-2 datasets often contain readable text.
		handle_text(c, d, &dsi, pos, dflen);
	}
	pos += dflen;

	de_dbg_indent(c, -1);
	//

	*bytes_consumed = pos - pos1;
	retval = 1;
done:
	return retval;
}

static void de_run_iptc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 bytes_consumed;
	de_int64 ds_count;

	d = de_malloc(c, sizeof(lctx));
	d->charset = DE_ENCODING_UNKNOWN;

	pos = 0;
	ds_count = 0;
	while(1) {
		if(pos>=c->infile->len) break;
		if(!do_dataset(c, d, ds_count, pos, &bytes_consumed)) break;
		if(bytes_consumed<=0) break;
		ds_count++;
		pos += bytes_consumed;
	}

	de_free(c, d);
}

static int de_identify_iptc(deark *c)
{
	de_byte b;

	// First byte of each dataset is 0x1c.
	if(de_getbyte(0)!=0x1c) return 0;

	// Check the record number. Record numbers 1-9 are known.
	b = de_getbyte(1);
	if(b<1 || b>15) return 0;

	// This is not meant to imply that .iptc is an official file extension for
	// IPTC data. It's just that it's used by Deark when extracting IPTC data
	// to a file.
	if(!de_input_file_has_ext(c, "iptc")) return 0;

	return 60;
}

void de_module_iptc(deark *c, struct deark_module_info *mi)
{
	mi->id = "iptc";
	mi->desc = "IPTC metadata";
	mi->run_fn = de_run_iptc;
	mi->identify_fn = de_identify_iptc;
}
