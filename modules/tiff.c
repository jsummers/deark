// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from TIFF image files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

#define MAX_IFDS 1000

#define TAGTYPE_UINT32 4

#define DE_TIFFFMT_TIFF       1
#define DE_TIFFFMT_BIGTIFF    2
#define DE_TIFFFMT_PANASONIC  3 // Panasonic RAW / RW2
#define DE_TIFFFMT_ORF        4 // Olympus RAW
#define DE_TIFFFMT_DCP        5 // DNG Camera Profile (DCP)
#define DE_TIFFFMT_MDI        6 // Microsoft Office Document Imaging

struct ifdstack_item {
	de_int64 offset;
};

typedef struct localctx_struct {
	int is_le;
	int is_bigtiff;
	int fmt;

	struct ifdstack_item *ifdstack;
	int ifdstack_capacity;
	int ifdstack_numused;

	de_int64 *ifdlist;
	de_int64 ifd_count;

	de_int64 fpos_size; // Number of bytes in a file offset
	de_module_params *mparams;
} lctx;

static de_int64 getui16x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_getui16le(f, pos);
	return dbuf_getui16be(f, pos);
}

static de_int64 getui32x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_getui32le(f, pos);
	return dbuf_getui32be(f, pos);
}

static de_int64 geti64x(dbuf *f, de_int64 pos, int is_le)
{
	if(is_le) return dbuf_geti64le(f, pos);
	return dbuf_geti64be(f, pos);
}

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
		return geti64x(c->infile, pos, d->is_le);
	}
	return getui32x(c->infile, pos, d->is_le);
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
	if(d->mparams && d->mparams->codes && de_strchr(d->mparams->codes, 'E')) {
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

	if(ifdpos >= c->infile->len || ifdpos<8) {
		de_warn(c, "Invalid IFD offset (%d)\n", (int)ifdpos);
		return;
	}

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
		num_tags = (int)geti64x(c->infile, ifdpos, d->is_le);
	}
	else {
		num_tags = (int)getui16x(c->infile, ifdpos, d->is_le);
	}

	de_dbg(c, "number of tags: %d\n", num_tags);
	if(num_tags<1 || num_tags>200) {
		de_warn(c, "Invalid or excessive number of TIFF tags (%d)\n", num_tags);
		return;
	}

	// Record the next IFD in the main list.
	push_ifd(c, d, getui32x(c->infile, ifdpos+ifdhdrsize+num_tags*ifditemsize, d->is_le));

	for(i=0; i<num_tags; i++) {
		tagnum = (int)getui16x(c->infile, ifdpos+ifdhdrsize+i*ifditemsize, d->is_le);
		tagtype = (int)getui16x(c->infile, ifdpos+ifdhdrsize+i*ifditemsize+2, d->is_le);
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

		case 46:
			if(d->fmt==DE_TIFFFMT_PANASONIC) {
				// Some Panasonic RAW files have a JPEG file in tag 46.
				dbuf_create_file_from_slice(c->infile, val_offset, total_size, "thumb.jpg", NULL);
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

static int de_identify_tiff_internal(deark *c, int *is_le)
{
	de_int64 byte_order_sig;
	de_int64 magic;
	int fmt = 0;

	byte_order_sig = de_getui16be(0);
	*is_le = (byte_order_sig == 0x4d4d) ? 0 : 1;

	if(*is_le)
		magic = de_getui16le(2);
	else
		magic = de_getui16be(2);

	if(byte_order_sig==0x4550 && magic==0x002a) {
		fmt = DE_TIFFFMT_MDI;
	}
	else if(byte_order_sig==0x4d4d || byte_order_sig==0x4949) {

		switch(magic) {
		case 0x002a: // Standard TIFF
			fmt = DE_TIFFFMT_TIFF;
			break;
		case 0x002b:
			fmt = DE_TIFFFMT_BIGTIFF;
			break;
		case 0x0055:
			fmt = DE_TIFFFMT_PANASONIC;
			break;

		//case 0x01bc: // JPEG-XR
		//case 0x314e: // NIFF

		case 0x4352:
			fmt = DE_TIFFFMT_DCP;
			break;
		case 0x4f52:
		case 0x5352:
			fmt = DE_TIFFFMT_ORF;
			break;
		}
	}

	return fmt;
}

static void de_run_tiff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	if(c->module_nesting_level>1) de_dbg(c, "in tiff module\n");
	d = de_malloc(c, sizeof(lctx));

	d->mparams = mparams;

	d->fmt = de_identify_tiff_internal(c, &d->is_le);

	switch(d->fmt) {
	case DE_TIFFFMT_TIFF:
		de_declare_fmt(c, "TIFF");
		break;
	case DE_TIFFFMT_BIGTIFF:
		de_declare_fmt(c, "BigTIFF");
		d->is_bigtiff = 1;
		break;
	case DE_TIFFFMT_PANASONIC:
		de_declare_fmt(c, "Panasonic RAW/RW2");
		break;
	case DE_TIFFFMT_ORF:
		de_declare_fmt(c, "Olympus RAW");
		break;
	case DE_TIFFFMT_DCP:
		de_declare_fmt(c, "DNG Camera Profile");
		break;
	case DE_TIFFFMT_MDI:
		de_declare_fmt(c, "MDI");
		break;
	}

	if(d->fmt==0) {
		de_warn(c, "This is not a known/supported TIFF or TIFF-like format.\n");
	}

	do_tiff(c, d);

	if(d) {
		de_free(c, d->ifdstack);
		de_free(c, d->ifdlist);
		de_free(c, d);
	}
}

static int de_identify_tiff(deark *c)
{
	int fmt;
	int is_le;

	fmt = de_identify_tiff_internal(c, &is_le);
	if(fmt!=0) return 100;
	return 0;
}

void de_module_tiff(deark *c, struct deark_module_info *mi)
{
	mi->id = "tiff";
	mi->desc = "TIFF image (resources only)";
	mi->run_fn = de_run_tiff;
	mi->identify_fn = de_identify_tiff;
}
