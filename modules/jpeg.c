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

static void do_jfxx_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte t;

	// The first byte indicates the type of thumbnail.

	de_dbg(c, "jfxx segment at %d datasize=%d\n", (int)pos, (int)data_size);
	if(data_size<2) return;

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

// seg_size is the data size, excluding the marker and length fields.
static void do_app_segment(deark *c, lctx *d, de_byte seg_type, de_int64 pos, de_int64 seg_size)
{
	char buf[64]; // This just needs to be large enough for any ID we recognize.
	size_t id_strlen;
	de_int64 id_size;
	de_int64 payload_pos;
	de_int64 payload_size;

	de_dbg(c, "APP%d segment at %d, size=%d\n", (int)seg_type-0xe0, (int)pos, (int)seg_size);
	de_dbg_indent(c, 1);
	if(seg_size<3) goto done;

	// Read the first few bytes of the segment, so we can tell what kind of segment it is.
	if(seg_size+1 < (de_int64)sizeof(buf))
		dbuf_read_sz(c->infile, pos, buf, (size_t)(seg_size+1));
	else
		dbuf_read_sz(c->infile, pos, buf, sizeof(buf));

	// APP ID is the string before the first NUL byte.
	id_strlen = de_strlen(buf);
	id_size = id_strlen + 1;

	// Tolerate APP IDs that have trailing spaces.
	while(id_strlen>0 && buf[id_strlen-1]==' ') {
		buf[id_strlen-1] = '\0';
		id_strlen--;
	}

	// The payload data size is usually everything after the first NUL byte.
	payload_pos = pos + id_size;
	payload_size = seg_size - id_size;
	if(payload_size<1) goto done;

	if(seg_type==0xe0 && !de_strcmp(buf, "JFXX")) {
		do_jfxx_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xe1 && !de_strcmp(buf, "Exif")) {
		de_dbg(c, "Exif segment at %d datasize=%d\n", (int)(payload_pos+1), (int)(payload_size-1));
		de_fmtutil_handle_exif(c, payload_pos+1, payload_size-1);
	}
	else if(seg_type==0xe2 && !de_strcmp(buf, "ICC_PROFILE")) {
		do_icc_profile_segment(c, d, payload_pos, payload_size);
	}
	else if(seg_type==0xed && !de_strcmp(buf, "Photoshop 3.0")) {
		de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)(payload_pos), (int)(payload_size));
		de_fmtutil_handle_photoshop_rsrc(c, payload_pos, payload_size);
	}
	else if(seg_type==0xe1 && !de_strcmp(buf, "http://ns.adobe.com/xap/1.0/")) {
		dbuf_create_file_from_slice(c->infile, payload_pos, payload_size, "xmp", NULL);
	}

done:
	de_dbg_indent(c, -1);
}

static void de_run_jpeg(deark *c, de_module_params *mparams)
{
	de_byte b;
	de_int64 pos;
	de_int64 seg_size;
	lctx *d = NULL;
	int found_marker;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	found_marker = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte(pos);
		if(b==0xff) {
			found_marker = 1;
			pos++;
			continue;
		}

		if(!found_marker) {
			// Not an 0xff byte, and not preceded by an 0xff byte. Just ignore it.
			pos++;
			continue;
		}

		found_marker = 0; // Reset this flag.

		if(b==0xd8 || b==0x01) {
			// SOI (or TMP) marker. These have no content.
			pos++;
			continue;
		}
		if((b>=0xd0 && b<=0xda) || b==0x00) {
			// An RSTx or EOI or SOS or escaped 0xff.
			// If we encounter one of these, we've gone far enough.
			// (TODO: Some files contain multiple JPEG images. To support them,
			// we can't just quit here.)
			break;
		}

		pos++;
		seg_size = de_getui16be(pos);
		if(pos<2) break; // bogus size

		if(b>=0xe0 && b<=0xef)
			do_app_segment(c, d, b, pos+2, seg_size-2);

		pos += seg_size;
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
