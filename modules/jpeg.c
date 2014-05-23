// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from JPEG files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	dbuf *iccprofile_file;
} lctx;

static void process_icc_profile_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
{
	de_byte b1, b2;

	if(data_size<2) return; // bogus data
	b1 = de_getbyte(pos);
	b2 = de_getbyte(pos+1);
	de_dbg(c, "icc profile segment at %d datasize=%d part %d of %d\n", (int)pos, (int)(data_size-2), b1, b2);

	if(!d->iccprofile_file) {
		d->iccprofile_file = dbuf_create_output_file(c, "icc");
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

static void process_jfxx_segment(deark *c, lctx *d, de_int64 pos, de_int64 data_size)
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
		dbuf_create_file_from_slice(c->infile, pos+1, data_size-1, "jfxxthumb.jpg");
	}
}

static void process_segment(deark *c, lctx *d, de_byte seg_type, de_int64 pos, de_int64 seg_size)
{
	de_byte buf[64];
	int pos_of_first_nul;
	int i;
	de_int64 payload_size;

	de_dbg(c, "jpeg segment type 0x%02x at %d datasize=%d\n", seg_type, (int)pos, (int)seg_size);

	// Read the first few bytes of the segment, so we can tell what kind of segment it is.
	de_read(buf, pos, sizeof(buf));

	// If segment identifiers were always perfectly uniform, we could just compare them
	// exactly, but we've seen some that have extra spaces after them and whatnot...
	// So we'll do some analysis.

	// Find the segment identifier.
	pos_of_first_nul = -1;
	for(i=0; i<sizeof(buf); i++) {
		if(buf[i]==0) { pos_of_first_nul=i; break; }
	}
	if(pos_of_first_nul<0) return;

	// The payload data size is usually everything after the first NUL byte.
	payload_size = seg_size - (pos_of_first_nul+1);

	if(seg_type==0xe0 && seg_size>5 && !de_memcmp(buf, "JFXX\0", 5)) {
		process_jfxx_segment(c, d, pos+5, seg_size-5);
	}
	else if(seg_type==0xe1 && seg_size>6 && !de_memcmp(buf, "Exif\0",5)) {
		de_dbg(c, "Exif segment at %d datasize=%d\n", (int)(pos+6), (int)(seg_size-6));
		de_fmtutil_handle_exif(c, pos+6, seg_size-6);
	}
	else if(seg_type==0xe2 && seg_size>12 && !de_memcmp(buf, "ICC_PROFILE\0", 12)) {
		process_icc_profile_segment(c, d, pos+12, seg_size-12);
	}
	else if(seg_type==0xed && seg_size>14 && !de_memcmp(buf, "Photoshop 3.0\0", 14)) {
		de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)(pos+14), (int)(seg_size-14));
		de_fmtutil_handle_photoshop_rsrc(c, pos+14, seg_size-14);
	}
	else if(seg_type==0xe1 && seg_size>28 && !de_memcmp(buf, "http://ns.adobe.com/xap/1.0/", 28)) {
		dbuf_create_file_from_slice(c->infile, pos+pos_of_first_nul+1, payload_size, "xmp");
	}
}

static void de_run_jpeg(deark *c, const char *params)
{
	de_byte b;
	de_int64 pos;
	de_int64 seg_size;
	lctx *d = NULL;

	de_dbg(c, "In jpeg module\n");

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	while(1) {
		if(pos>=c->infile->len)
			break;
		b = de_getbyte(pos);
		if(b==0xff) {
			pos++;
			continue;
		}
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

		process_segment(c, d, b, pos+2, seg_size-2);

		pos += seg_size;
	}

	dbuf_close(d->iccprofile_file);

	de_free(c, d);
}

static int de_identify_jpeg(deark *c)
{
	de_byte b[3];
	de_read(b, 0, 3);

	if(b[0]==0xff && b[1]==0xd8 && b[2]==0xff)
		return 100;
	return 0;
}

void de_module_jpeg(deark *c, struct deark_module_info *mi)
{
	mi->id = "jpeg";
	mi->run_fn = de_run_jpeg;
	mi->identify_fn = de_identify_jpeg;
}
