// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from TIFF image files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

#define MAX_IFDS 1000

#define TAGTYPE_UINT32 4

struct ifdstack_item {
	de_int64 offset;
};

typedef struct localctx_struct {
	int is_le;
	int is_bigtiff;

	struct ifdstack_item *ifdstack;
	int ifdstack_capacity;
	int ifdstack_numused;

	de_int64 *ifdlist;
	de_int64 ifd_count;

	de_int64 fpos_size; // Number of bytes in a file offset
	const char *params;
} lctx;

// Returns 0 if stack is empty.
static de_int64 pop_ifd(deark *c, lctx *d)
{
	de_int64 ifdpos;
	if(!d->ifdstack) return 0;
	if(d->ifdstack_numused<1) return 0;
	ifdpos = d->ifdstack[d->ifdstack_numused-1].offset;
	d->ifdstack_numused--;
	return ifdpos;
}

static void push_ifd(deark *c, lctx *d, de_int64 ifdpos)
{
	int i;

	if(ifdpos==0) return;

	// Append to the IFD list (of all IFDs). This is only used for loop detection.
	if(!d->ifdlist) {
		d->ifdlist = de_malloc(c, MAX_IFDS * sizeof(de_int64));
	}
	if(d->ifd_count >= MAX_IFDS) {
		de_warn(c, "Too many TIFF IFDs\n");
		return;
	}
	for(i=0; i<d->ifd_count; i++) {
		if(ifdpos == d->ifdlist[i]) {
			de_err(c, "IFD loop detected\n");
			return;
		}
	}
	d->ifdlist[d->ifd_count] = ifdpos;
	d->ifd_count++;

	// Add to the IFD stack (of unprocessed IFDs).
	if(!d->ifdstack) {
		d->ifdstack_capacity = 200;
		d->ifdstack = de_malloc(c, d->ifdstack_capacity * sizeof(struct ifdstack_item));
		d->ifdstack_numused = 0;
	}
	if(d->ifdstack_numused >= d->ifdstack_capacity) {
		de_warn(c, "Too many TIFF IFDs\n");
		return;
	}
	d->ifdstack[d->ifdstack_numused].offset = ifdpos;
	d->ifdstack_numused++;

}

static int size_of_tiff_type(int tt)
{
	switch(tt) {
	case 1: case 2:	case 6:	case 7: return 1;
	case 3: case 8: return 2;
	case 4: case 9:	case 11: case 13: return 4;
	case 5: case 10: case 12: case 15: case 16:
	case 17: case 18: return 8;
	}
	return 0;
}

static de_int64 getfpos(deark *c, lctx *d, de_int64 pos)
{
	if(d->is_bigtiff) {
		return de_geti64(pos);
	}
	return de_getui32(pos);
}

static void do_oldjpeg(deark *c, lctx *d, de_int64 jpegoffset, de_int64 jpeglength)
{
	const char *extension;

	if(jpeglength<0) {
		// Missing JPEGInterchangeFormatLength tag. Assume it goes to the end
		// of the file.
		jpeglength = c->infile->len - jpegoffset;
	}

	// Found an embedded JPEG image or thumbnail that we can extract.
	if(d->params && de_strchr(d->params,'E')) {
		extension = "exifthumb.jpg";
	}
	else {
		extension = "jpg";
	}
	dbuf_create_file_from_slice(c->infile, jpegoffset, jpeglength, extension, NULL);
}

static void do_leaf_metadata(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_byte buf[4];
	de_byte segtype[40];
	de_int64 data_len;

	if(len<1) return;
	if(pos1+len > c->infile->len) return;
	de_dbg(c, "leaf metadata at %d size=%d\n", (int)pos1, (int)len);

	// This format appears to be hierarchical, but for now we only care about
	// the top level.

	pos = pos1;
	while(pos < pos1+len) {
		de_read(buf, pos, 4);
		if(de_memcmp(buf, "PKTS", 4)) {
			break;
		}
		pos+=4;
		
		pos+=4; // Don't know what these 4 bytes are for.

		de_read(segtype, pos, 40);
		pos+=40;

		// TODO: Is this always big-endian?
		data_len = de_getui32be(pos);
		pos+=4;

		if(!de_memcmp(segtype, "JPEG_preview_data\0", 18)) {
			de_dbg(c, "jpeg preview at %d len=%d\n", (int)pos, (int)data_len);
			dbuf_create_file_from_slice(c->infile, pos, data_len, "leafthumb.jpg", NULL);
		}
		pos += data_len;
	}
}

static void process_ifd(deark *c, lctx *d, de_int64 ifdpos)
{
	int num_tags;
	int i, j;
	int tagnum;
	int tagtype;
	de_int64 valcount;
	de_int64 val_offset;
	de_int64 unit_size;
	de_int64 total_size;
	de_int64 jpegoffset = 0;
	de_int64 jpeglength = -1;
	de_int64 ifdhdrsize;
	de_int64 ifditemsize;
	de_int64 offsetoffset;
	de_int64 offsetsize;

	de_dbg(c, "processing TIFF IFD at %d\n", (int)ifdpos);

	if(d->is_bigtiff) {
		ifdhdrsize = 8;
		ifditemsize = 20;
		offsetoffset = 12;
		offsetsize = 8;
	}
	else {
		ifdhdrsize = 2;
		ifditemsize = 12;
		offsetoffset = 8;
		offsetsize = 4;
	}

	if(d->is_bigtiff) {
		num_tags = (int)de_geti64(ifdpos);
	}
	else {
		num_tags = (int)de_getui16(ifdpos);
	}

	de_dbg(c, "number of tags: %d\n", num_tags);
	if(num_tags<1 || num_tags>200) {
		de_warn(c, "Invalid or excessive number of TIFF tags (%d)\n", num_tags);
		return;
	}

	// Record the next IFD in the main list.
	push_ifd(c, d, de_getui32(ifdpos+ifdhdrsize+num_tags*ifditemsize));

	for(i=0; i<num_tags; i++) {
		tagnum = (int)de_getui16(ifdpos+ifdhdrsize+i*ifditemsize);
		tagtype = (int)de_getui16(ifdpos+ifdhdrsize+i*ifditemsize+2);
		// Not a file pos, but getfpos() does the right thing.
		valcount = getfpos(c, d, ifdpos+ifdhdrsize+i*ifditemsize+4);

		unit_size = size_of_tiff_type(tagtype);
		total_size = unit_size * valcount;
		if(total_size <= offsetsize) {
			val_offset = ifdpos+ifdhdrsize+i*ifditemsize+offsetoffset;
		}
		else {
			val_offset = getfpos(c, d, ifdpos+ifdhdrsize+i*ifditemsize+offsetoffset);
		}

		switch(tagnum) {
		case 34665: // Exif IFD
		case 34853: // GPS IFD
		case 40965: // Interoperability IFD
			if(unit_size!=offsetsize) break;
			for(j=0; j<valcount;j++) {
				push_ifd(c, d, getfpos(c, d, val_offset+unit_size*j));
			}
			break;

		case 513: // JPEGInterchangeFormat
			if(unit_size!=offsetsize || valcount<1) break;
			jpegoffset = getfpos(c, d, val_offset);
			break;

		case 514: // JPEGInterchangeFormatLength
			if(unit_size!=offsetsize || valcount<1) break;
			jpeglength = getfpos(c, d, val_offset);
			break;

		case 700: // XMP
			dbuf_create_file_from_slice(c->infile, val_offset, total_size, "xmp", NULL);
			break;

		case 33723: // IPTC
			if(c->extract_level>=2 && total_size>0) {
				dbuf_create_file_from_slice(c->infile, val_offset, total_size, "iptc", NULL);
			}
			break;

		case 34310: // Leaf MOS metadata / "PKTS"
			do_leaf_metadata(c, d, val_offset, total_size);
			break;

		case 34377: // Photoshop
			de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)val_offset, (int)total_size);
			de_fmtutil_handle_photoshop_rsrc(c, val_offset, total_size);
			break;

		case 34675: // ICC Profile
			dbuf_create_file_from_slice(c->infile, val_offset, total_size, "icc", NULL);
			break;
		}
	}

	if(jpegoffset>0 && jpeglength!=0) {
		do_oldjpeg(c, d, jpegoffset, jpeglength);
	}
}

static void do_tiff(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 ifdoffs;

	// Read the first IFD offset
	if(d->is_bigtiff) {
		d->fpos_size = 8;
		pos = 8;
	}
	else {
		d->fpos_size = 4;
		pos = 4;
	}
	ifdoffs = getfpos(c, d, pos);
	de_dbg(c, "first TIFF ifd at %d\n", (int)ifdoffs);
	push_ifd(c, d, ifdoffs);

	// Process IFDs until we run out of them.
	while(1) {
		ifdoffs = pop_ifd(c, d);
		if(ifdoffs==0) break;
		process_ifd(c, d, ifdoffs);
	}
}

static void de_run_tiff(deark *c, const char *params)
{
	de_byte b0, b1;
	lctx *d = NULL;

	de_dbg(c, "In tiff module\n");
	d = de_malloc(c, sizeof(lctx));

	d->params = params;

	b0 = de_getbyte(2);
	b1 = de_getbyte(3);

	if(b0==0x2a) { d->is_le = 1; }
	else if(b0==0x2b) { d->is_le = 1; d->is_bigtiff = 1; }
	else if(b1==0x2b) { d->is_bigtiff = 1; }

	dbuf_set_endianness(c->infile, d->is_le);

	do_tiff(c, d);

	if(d) {
		de_free(c, d->ifdstack);
		de_free(c, d->ifdlist);
		de_free(c, d);
	}
}

static int de_identify_tiff(deark *c)
{
	de_byte b[8];
	de_read(b, 0, 8);

	if(!de_memcmp(b, "MM\x00\x2a", 4)) // big-endian
		return 100;
	if(!de_memcmp(b, "II\x2a\x00", 4)) // little-endian
		return 100;
	if(!de_memcmp(b, "MM\x00\x2b\x00\x08\x00\x00", 8)) // big-endian bigtiff
		return 100;
	if(!de_memcmp(b, "II\x2b\x00\x08\x00\x00\x00", 8)) // little-endian bigtiff
		return 100;
	return 0;
}

void de_module_tiff(deark *c, struct deark_module_info *mi)
{
	mi->id = "tiff";
	mi->run_fn = de_run_tiff;
	mi->identify_fn = de_identify_tiff;
}
