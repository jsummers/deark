// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// IPTC metadata

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iptc);

typedef struct localctx_struct {
	int reserved;
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

static const struct ds_info ds_info_arr[] = {
	{ 1, 0,   0,      "Model Version", NULL },
	{ 1, 5,   0x0001, "Destination", NULL },
	{ 1, 20,  0,      "File Format", NULL },
	{ 1, 22,  0,      "File Format Version", NULL },
	{ 1, 30,  0x0001, "Service Identifier", NULL },
	{ 1, 40,  0x0001, "Envelope Number", NULL },
	{ 1, 50,  0x0001, "Product I.D.", NULL },
	{ 1, 60,  0x0001, "Envelope Priority", NULL },
	{ 1, 70,  0x0001, "Date Sent", NULL },
	{ 1, 80,  0x0001, "Time Sent", NULL },
	{ 1, 90,  0,      "Coded Character Set", NULL },
	{ 1, 100, 0x0001, "UNO", NULL },
	{ 1, 120, 0,      "ARM Identifier", NULL },
	{ 1, 122, 0,      "ARM Version", NULL },
	{ 2, 0,   0,      "Record Version", NULL },
	{ 2, 3,   0x0001, "Object Type Reference", NULL },
	{ 2, 4,   0x0001, "Object Atribute Reference", NULL },
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
	{ 2, 120, 0x0001, "Caption/Abstract", NULL },
	{ 2, 122, 0x0001, "Writer/Editor", NULL },
	{ 2, 125, 0,      "Rasterized Caption", NULL },
	{ 2, 130, 0x0001, "Image Type", NULL },
	{ 2, 131, 0x0001, "Image Orientation", NULL },
	{ 2, 135, 0x0001, "Language Identifier", NULL },
	{ 2, 150, 0x0001, "Audio Type", NULL },
	{ 2, 151, 0x0001, "Audio Sampling Rate", NULL },
	{ 2, 152, 0x0001, "Audio Sampling Resolution", NULL },
	{ 2, 153, 0x0001, "Audio Duration", NULL },
	{ 2, 154, 0x0001, "Audio Outcue", NULL },
	{ 2, 200, 0,      "ObjectData Preview File Format", NULL },
	{ 2, 201, 0,      "ObjectData Preview File Format Version", NULL },
	{ 2, 202, 0,      "ObjectData Preview Data", NULL },
	// TODO: record 3
	// TODO: record 6
	{ 7, 10,  0,      "Size Mode", NULL },
	{ 7, 20,  0,      "Max Subfile Size", NULL },
	{ 7, 90,  0,      "ObjectData Size Announced", NULL },
	{ 7, 95,  0,      "Maxium ObjectData Size", NULL },
	{ 8, 10,  0,      "Subfile", NULL },
	{ 9, 10,  0,      "Confirmed ObjectData Size", NULL }
};

// Caller supplies dsi. This function will set its fields.
static int lookup_ds_info(de_byte recnum, de_byte dsnum, struct ds_info *dsi)
{
	de_int64 i;

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
	*dflen = dbuf_getui16be(f, pos);
	*bytes_consumed = 2;
	if(*dflen > 32767) {
		// TODO: Support larger lengths
		de_err(c, "Bad or unsupported IPTC data field length\n");
		return 0;
	}
	return 1;
}

static void do_print_text_value(deark *c, lctx *d, const struct ds_info *dsi,
	de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	// TODO: Support other encodings when appropriate.
	dbuf_read_to_ucstring(c->infile, pos, len, s, 0, DE_ENCODING_ASCII);

	de_dbg(c, "%s: \"%s\"\n", dsi->dsname, ucstring_get_printable_sz(s));

	ucstring_destroy(s);
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

	*bytes_consumed = 0;

	b = de_getbyte(pos);
	if(b!=0x1c) {
		if(b==0x00 && ds_idx>0) {
			// Extraneous padding at the end of data?
			de_warn(c, "Expected %d bytes of IPTC data, only found %d\n",
				(int)c->infile->len, (int)pos);
		}
		else {
			de_err(c, "Bad IPTC tag marker (0x%02x) at %d\n", (int)b, (int)pos);
		}
		goto done;
	}
	pos++;

	recnum = de_getbyte(pos++);
	dsnum = de_getbyte(pos++);

	lookup_ds_info(recnum, dsnum, &dsi);

	if(!read_dflen(c, c->infile, pos, &dflen, &dflen_bytes_consumed)) goto done;
	pos += dflen_bytes_consumed;

	de_dbg(c, "IPTC dataset %d:%02d (%s) dlen=%" INT64_FMT "\n",
		(int)recnum, (int)dsnum, dsi.dsname, dflen);

	// Decode the value
	de_dbg_indent(c, 1);

	if(dsi.flags&0x1) {
		do_print_text_value(c, d, &dsi, pos, dflen);
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
