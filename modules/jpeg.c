// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG files.
// Extract embedded JPEG files from arbitrary files.

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	dbuf *iccprofile_file;
} lctx;

static void do_icc_profile_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte b1, b2;

	if(data_size<2) return; // bogus data
	b1 = de_getbyte(pos);
	b2 = de_getbyte(pos+1);
	de_dbg(c, "icc profile segment at %d datasize=%d part %d of %d\n", (int)pos, (int)(data_size-2), b1, b2);

	if(!d->iccprofile_file) {
		d->iccprofile_file = dbuf_create_output_file(c, "icc", NULL);
	}
	dbuf_copy(c->infile, pos+2, data_size-2, d->iccprofile_file);

	if(b1==b2) {
		// If this is the final piece of the ICC profile, close the file.
		// That way, if for some reason there's another profile in the file, we'll put
		// it in a separate file.
		dbuf_close(d->iccprofile_file);
		d->iccprofile_file = NULL;
	}
}

static void do_jfif_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte ver_h, ver_l;
	de_byte units;
	const char *units_name;
	de_int64 xdens, ydens;

	if(data_size<9) return;
	ver_h = de_getbyte(pos);
	ver_l = de_getbyte(pos+1);
	de_dbg(c, "JFIF version: %d.%02d\n", (int)ver_h, (int)ver_l);
	units = de_getbyte(pos+2);
	xdens = de_getui16be(pos+3);
	ydens = de_getui16be(pos+5);
	if(units==1) units_name="dpi";
	else if(units==2) units_name="dots/cm";
	else units_name="(unspecified units)";
	de_dbg(c, "density: %dx%d %s\n", (int)xdens, (int)ydens, units_name);
}

static void do_jfxx_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte t;

	de_dbg(c, "jfxx segment at %d datasize=%d\n", (int)pos, (int)data_size);
	if(data_size<2) return;

	// The first byte indicates the type of thumbnail.
	t = de_getbyte(pos);

	if(t==16) { // thumbnail coded using JPEG
		// TODO: JPEG-formatted thumbnails are forbidden from containing JFIF segments.
		// They essentially inherit them from their parent.
		// So, maybe, when we extract a thumbnail, we should insert an artificial JFIF
		// segment into it. We currently don't do that.
		// (However, this is not at all important.)
		dbuf_create_file_from_slice(c->infile, pos+1, data_size-1, "jfxxthumb.jpg", NULL);
	}
}

static void do_adobeapp14_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte transform;
	const char *tname;

	if(data_size<7) return;
	transform = de_getbyte(pos+6);
	if(transform==0) tname="RGB or CMYK";
	else if(transform==1) tname="YCbCr";
	else if(transform==2) tname="YCCK";
	else tname="unknown";
	de_dbg(c, "color transform: %d (%s)\n", (int)transform, tname);
}

// ITU-T Rec. T.86 says nothing about canonicalizing the APP ID, but in
// practice, some apps are sloppy about capitalization, and trailing spaces.
static void normalize_app_id(const char *app_id_orig, char *app_id_normalized,
	size_t app_id_normalized_len)
{
	de_int64 id_strlen;
	de_int64 i;

	de_strlcpy(app_id_normalized, app_id_orig, app_id_normalized_len);
	id_strlen = (de_int64)de_strlen(app_id_normalized);

	// Strip trailing spaces.
	while(id_strlen>0 && app_id_normalized[id_strlen-1]==' ') {
		app_id_normalized[id_strlen-1] = '\0';
		id_strlen--;
	}

	for(i=0; i<id_strlen; i++) {
		if(app_id_normalized[i]>='a' && app_id_normalized[i]<='z') {
			app_id_normalized[i] -= 32;
		}
	}
}

// seg_size is the data size, excluding the marker and length fields.
static void do_app_segment(deark *c, lctx *d, de_byte seg_type, de_int64 pos, de_int64 seg_size)
{
	char app_id_orig[64]; // This just needs to be large enough for any ID we recognize.
	char app_id_normalized[64];
	char app_id_printable[64];
	de_int64 app_id_orig_strlen;
	de_int64 app_id_orig_size;
	de_int64 payload_pos;
	de_int64 payload_size;

	de_dbg_indent(c, 1);
	if(seg_size<3) goto done;

	// Read the first few bytes of the segment, so we can tell what kind of segment it is.
	if(seg_size+1 < (de_int64)sizeof(app_id_orig))
		dbuf_read_sz(c->infile, pos, app_id_orig, (size_t)(seg_size+1));
	else
		dbuf_read_sz(c->infile, pos, app_id_orig, sizeof(app_id_orig));

	// APP ID is the string before the first NUL byte.
	// app_id_orig_size includes the NUL byte
	app_id_orig_strlen = (de_int64)de_strlen(app_id_orig);
	app_id_orig_size = app_id_orig_strlen + 1;

	de_make_printable_ascii((const de_byte*)app_id_orig, app_id_orig_strlen,
		app_id_printable, sizeof(app_id_printable), 0);

	de_dbg(c, "app id: \"%s\"\n", app_id_printable);

	normalize_app_id(app_id_orig, app_id_normalized, sizeof(app_id_normalized));

	// The payload data size is usually everything after the first NUL byte.
	payload_pos = pos + app_id_orig_size;
	payload_size = seg_size - app_id_orig_size;
	if(payload_size<1) goto done;

	if(seg_type==0xe0 && !de_strcmp(app_id_normalized, "JFIF")) {
		do_jfif_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xe0 && !de_strcmp(app_id_normalized, "JFXX")) {
		do_jfxx_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xee && app_id_orig_strlen>=5 && !de_memcmp(app_id_normalized, "ADOBE", 5)) {
		// libjpeg implies that the "Adobe" string is *not* NUL-terminated. That the byte
		// that is usually 0 is actually the high byte of a version number.
		do_adobeapp14_segment(c, d, pos+5, seg_size-5);
	}
	else if(seg_type==0xe1 && !de_strcmp(app_id_normalized, "EXIF")) {
		// Note that Exif has an additional padding byte after the APP ID NUL terminator.
		de_dbg(c, "Exif data at %d, size=%d\n", (int)(payload_pos+1), (int)(payload_size-1));
		de_dbg_indent(c, 1);
		de_fmtutil_handle_exif(c, payload_pos+1, payload_size-1);
		de_dbg_indent(c, -1);
	}
	else if(seg_type==0xe2 && !de_strcmp(app_id_normalized, "ICC_PROFILE")) {
		do_icc_profile_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xed && !de_strcmp(app_id_normalized, "PHOTOSHOP 3.0")) {
		de_dbg(c, "photoshop data at %d, size=%d\n", (int)(payload_pos), (int)(payload_size));
		de_dbg_indent(c, 1);
		de_fmtutil_handle_photoshop_rsrc(c, payload_pos, payload_size);
		de_dbg_indent(c, -1);
	}
	else if(seg_type==0xe1 && !de_strcmp(app_id_normalized, "HTTP://NS.ADOBE.COM/XAP/1.0/")) {
		de_dbg(c, "XMP data at %d, size=%d\n", (int)(payload_pos), (int)(payload_size));
		dbuf_create_file_from_slice(c->infile, payload_pos, payload_size, "xmp", NULL);
	}

done:
	de_dbg_indent(c, -1);
}

static void do_sof_segment(deark *c, lctx *d, de_byte seg_type,
	de_int64 pos, de_int64 data_size)
{
	de_int64 w, h;
	de_int64 b;

	if(data_size<6) return;
	de_dbg_indent(c, 1);
	b = de_getbyte(pos);
	de_dbg(c, "precision: %d\n", (int)b);
	h = de_getui16be(pos+1);
	w = de_getui16be(pos+3);
	de_dbg(c, "dimensions: %dx%d\n", (int)w, (int)h);
	b = de_getbyte(pos+5);
	de_dbg(c, "number of components: %d\n", (int)b);
	de_dbg_indent(c, -1);
}

struct marker_info {
	char name[12];
#define FLAG_NO_DATA 0x01
#define FLAG_IS_SOF  0x02
#define FLAG_IS_APP  0x04
	unsigned int flags;
};

// Caller allocates mi
static int get_marker_info(deark *c, lctx *d, de_byte seg_type,
	struct marker_info *mi)
{
	const char *name = NULL;

	de_memset(mi, 0, sizeof(struct marker_info));

	switch(seg_type) {
	case 0x01: name = "TEM"; mi->flags |= FLAG_NO_DATA; break;
	case 0xc4: name = "DHT"; break;
	case 0xc8: name = "JPG"; break;
	case 0xd8: name = "SOI"; mi->flags |= FLAG_NO_DATA; break;
	case 0xd9: name = "EOI"; mi->flags |= FLAG_NO_DATA; break;
	case 0xda: name = "SOS"; break;
	case 0xdb: name = "DQT"; break;
	case 0xdc: name = "DNL"; break;
	case 0xdd: name = "DRI"; break;
	case 0xde: name = "DHP"; break;
	case 0xdf: name = "EXP"; break;
	case 0xfe: name = "COM"; break;
	}

	if(name) {
		de_strlcpy(mi->name, name, sizeof(mi->name));
		goto done;
	}

	// Handle some pattern-based markers.
	if(seg_type>=0xe0 && seg_type<=0xef) {
		de_snprintf(mi->name, sizeof(mi->name), "APP%d", (int)(seg_type-0xe0));
		mi->flags |= FLAG_IS_APP;
		goto done;
	}

	if(seg_type>=0xc0 && seg_type<=0xcf) {
		de_snprintf(mi->name, sizeof(mi->name), "SOF%d", (int)(seg_type-0xc0));
		mi->flags |= FLAG_IS_SOF;
		goto done;
	}

	if(seg_type>=0xd0 && seg_type<=0xd7) {
		de_snprintf(mi->name, sizeof(mi->name), "RST%d", (int)(seg_type-0xd0));
		mi->flags |= FLAG_NO_DATA;
		goto done;
	}

	de_strlcpy(mi->name, "???", sizeof(mi->name));
	return 0;

done:
	return 1;
}

static void do_segment(deark *c, lctx *d, de_byte seg_type,
	const struct marker_info *mi,
	de_int64 payload_pos, de_int64 payload_size)
{

	if(c->debug_level<2 && !(mi->flags & FLAG_IS_APP)) {
		// Non-APP segments are only analyzed if we want the debug output from them.
		return;
	}

	de_dbg(c, "segment %s (0x%02x) at %d, data_len=%d\n",
		mi->name, (unsigned int)seg_type, (int)(payload_pos-4), (int)payload_size);

	if(mi->flags & FLAG_IS_APP) {
		do_app_segment(c, d, seg_type, payload_pos, payload_size);
	}
	else if(mi->flags & FLAG_IS_SOF) {
		do_sof_segment(c, d, seg_type, payload_pos, payload_size);
	}
}

static void de_run_jpeg(deark *c, de_module_params *mparams)
{
	de_byte b;
	de_int64 pos;
	de_int64 seg_size;
	de_byte seg_type;
	lctx *d = NULL;
	int found_marker;
	struct marker_info mi;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	found_marker = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte(pos);
		pos++;
		if(b==0xff) {
			found_marker = 1;
			continue;
		}

		if(!found_marker) {
			// Not an 0xff byte, and not preceded by an 0xff byte. Just ignore it.
			continue;
		}

		found_marker = 0; // Reset this flag.

		if(b==0x00) {
			continue; // Escaped 0xff
		}

		seg_type = b;
		get_marker_info(c, d, seg_type, &mi);

		if(mi.flags & FLAG_NO_DATA) {
			de_dbg2(c, "marker %s (0x%02x) at %d\n", mi.name, (unsigned int)seg_type,
				(int)(pos-2));

			if(seg_type==0xd9) {
				// EOI - Normally this won't happen, because we stop at SOS.
				break;
			}

			continue;
		}

		// If we get here, we're reading a segment that has a size field.
		seg_size = de_getui16be(pos);
		if(pos<2) break; // bogus size

		do_segment(c, d, seg_type, &mi, pos+2, seg_size-2);

		pos += seg_size;

		if(seg_type==0xda) {
			// Stop if we read an SOS marker.
			// TODO: Some files contain multiple JPEG images. To support them,
			// we can't just quit here.
			// NOTE: In order to continue from here, we need to identify JPEG-LS
			// and handle it correctly.
			break;
		}
	}

	dbuf_close(d->iccprofile_file);

	de_free(c, d);
}

typedef struct scanctx_struct {
	de_int64 len;
	int is_jpegls;
} scanctx;

static int detect_jpeg_len(deark *c, scanctx *d, de_int64 pos1, de_int64 len)
{
	de_byte b0, b1;
	de_int64 pos;
	de_int64 seg_size;
	int in_scan = 0;

	d->len = 0;
	d->is_jpegls = 0;
	pos = pos1;

	while(1) {
		if(pos>=pos1+len)
			break;
		b0 = de_getbyte(pos);

		if(b0!=0xff) {
			pos++;
			continue;
		}

		// Peek at the next byte (after this 0xff byte).
		b1 = de_getbyte(pos+1);

		if(b1==0xff) {
			// A "fill byte", not a marker.
			pos++;
			continue;
		}
		else if(b1==0x00 || (d->is_jpegls && b1<0x80 && in_scan)) {
			// An escape sequence, not a marker.
			pos+=2;
			continue;
		}
		else if(b1==0xd9) { // EOI. That's what we're looking for.
			pos+=2;
			d->len = pos-pos1;
			return 1;
		}
		else if(b1==0xf7) {
			de_dbg(c, "Looks like a JPEG-LS file.\n");
			d->is_jpegls = 1;
		}

		if(b1==0xda) { // SOS - Start of scan
			in_scan = 1;
		}
		else if(b1>=0xd0 && b1<=0xd7) {
			// RSTn markers don't change the in_scan state.
			;
		}
		else {
			in_scan = 0;
		}

		if((b1>=0xd0 && b1<=0xda) || b1==0x01) {
			// Markers that have no content.
			pos+=2;
			continue;
		}

		// Everything else should be a marker segment, with a length field.
		seg_size = de_getui16be(pos+2);
		if(seg_size<2) break; // bogus size

		pos += seg_size+2;
	}

	return 0;
}

static void de_run_jpegscan(deark *c, de_module_params *mparams)
{
	de_int64 pos = 0;
	de_int64 foundpos = 0;
	scanctx *d = NULL;
	int ret;

	d = de_malloc(c, sizeof(*d));

	while(1) {
		if(pos >= c->infile->len) break;

		ret = dbuf_search(c->infile, (const de_byte*)"\xff\xd8\xff", 3,
			pos, c->infile->len-pos, &foundpos);
		if(!ret) break; // No more JPEGs in file.

		de_dbg(c, "Found likely JPEG file at %d\n", (int)foundpos);

		pos = foundpos;

		if(detect_jpeg_len(c, d, pos, c->infile->len-pos)) {
			de_dbg(c, "length=%d\n", (int)d->len);
			dbuf_create_file_from_slice(c->infile, pos, d->len,
				d->is_jpegls ? "jls" : "jpg", NULL);
			pos += d->len;
		}
		else {
			de_dbg(c, "Doesn't seem to be a valid JPEG.\n");
			pos++;
		}
	}

	de_free(c, d);
}

static int de_identify_jpeg(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xff\xd8\xff", 3)) {
		return 100;
	}
	return 0;
}

void de_module_jpeg(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpeg";
	mi->desc = "JPEG image (resources only)";
	mi->run_fn = de_run_jpeg;
	mi->identify_fn = de_identify_jpeg;
}

void de_module_jpegscan(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpegscan";
	mi->desc = "Extract embedded JPEG images from arbitrary files";
	mi->run_fn = de_run_jpegscan;
	mi->identify_fn = de_identify_none;
}
