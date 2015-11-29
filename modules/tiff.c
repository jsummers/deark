// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from TIFF image files

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

#define MAX_IFDS 1000

#define TAGTYPE_UINT16    3
#define TAGTYPE_UINT32    4
#define TAGTYPE_RATIONAL  5

#define DE_TIFFFMT_TIFF       1
#define DE_TIFFFMT_BIGTIFF    2
#define DE_TIFFFMT_PANASONIC  3 // Panasonic RAW / RW2
#define DE_TIFFFMT_ORF        4 // Olympus RAW
#define DE_TIFFFMT_DCP        5 // DNG Camera Profile (DCP)
#define DE_TIFFFMT_MDI        6 // Microsoft Office Document Imaging

struct ifdstack_item {
	de_int64 offset;
};

struct taginfo {
	int tagnum;
	int tagtype;
	de_int64 valcount;
	de_int64 val_offset;
	de_int64 unit_size;
	de_int64 total_size;
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

	de_int64 ifdhdrsize;
	de_int64 ifditemsize;
	de_int64 offsetoffset;
	de_int64 offsetsize; // Number of bytes in a file offset

	de_module_params *mparams;
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

static int read_rational_as_double(deark *c, lctx *d, const struct taginfo *tg, double *n)
{
	de_int64 num, den;

	*n = 0.0;
	if(tg->valcount<1) return 0;
	num = dbuf_getui32x(c->infile, tg->val_offset, d->is_le);
	den = dbuf_getui32x(c->infile, tg->val_offset+4, d->is_le);
	if(den==0) return 0;
	*n = (double)num/(double)den;
	return 1;
}

static int read_tag_value_as_int64(deark *c, lctx *d, const struct taginfo *tg, de_int64 *n)
{
	*n = 0;
	if(tg->valcount<1) return 0;
	if(tg->tagtype==TAGTYPE_UINT16) {
		*n = dbuf_getui16x(c->infile, tg->val_offset, d->is_le);
		return 1;
	}
	else if(tg->tagtype==TAGTYPE_UINT32) {
		*n = dbuf_getui32x(c->infile, tg->val_offset, d->is_le);
		return 1;
	}
	return 0;
}

static int read_tag_value_as_double(deark *c, lctx *d, const struct taginfo *tg, double *n)
{
	*n = 0.0;
	if(tg->tagtype==TAGTYPE_RATIONAL) {
		return read_rational_as_double(c, d, tg, n);
	}
	return 0;
}

static de_int64 getfpos(deark *c, lctx *d, de_int64 pos)
{
	if(d->is_bigtiff) {
		return dbuf_geti64x(c->infile, pos, d->is_le);
	}
	return dbuf_getui32x(c->infile, pos, d->is_le);
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

static void do_resolution(deark *c, lctx *d, const struct taginfo *tg)
{
	const char *name;
	double n;

	if(tg->tagnum==283) name="Y";
	else name="X";

	if(!read_tag_value_as_double(c, d, tg, &n))
		return;

	de_dbg2(c, "%sResolution: %.3f\n", name, n);
}

static void do_resolutionunit(deark *c, lctx *d, const struct taginfo *tg)
{
	de_int64 n;
	const char *s;

	if(!read_tag_value_as_int64(c, d, tg, &n))
		return;

	if(n==1) s="unspecified";
	else if(n==2) s="pixels/inch";
	else if(n==3) s="pixels/cm";
	else s="?";
	de_dbg2(c, "ResolutionUnit: %d (%s)\n", (int)n, s);
}

static void do_display_int_tag(deark *c, lctx *d, const struct taginfo *tg, const char *name)
{
	de_int64 n;
	if(!read_tag_value_as_int64(c, d, tg, &n))
		return;
	de_dbg2(c, "%s: %d\n", name, (int)n);
}

static void do_subifd(deark *c, lctx *d, const struct taginfo *tg)
{
	de_int64 j;
	de_int64 tmpoffset;
	const char *name;

	if(tg->unit_size!=d->offsetsize) return;

	switch(tg->tagnum) {
	case 34665: name = "Exif IFD"; break;
	case 34853: name = "GPS IFD"; break;
	case 40965: name = "Interoperability IFD"; break;
	default: name="sub-IFD";
	}

	for(j=0; j<tg->valcount;j++) {
		tmpoffset = getfpos(c, d, tg->val_offset+tg->unit_size*j);
		de_dbg2(c, "offset of %s: %d\n", name, (int)tmpoffset);
		push_ifd(c, d, tmpoffset);
	}
}

static void process_ifd(deark *c, lctx *d, de_int64 ifdpos)
{
	int num_tags;
	int i;
	de_int64 jpegoffset = 0;
	de_int64 jpeglength = -1;
	de_int64 tmpoffset;
	struct taginfo tg;

	de_dbg(c, "IFD at %d\n", (int)ifdpos);
	de_dbg_indent(c, 1);

	if(ifdpos >= c->infile->len || ifdpos<8) {
		de_warn(c, "Invalid IFD offset (%d)\n", (int)ifdpos);
		goto done;
	}

	if(d->is_bigtiff) {
		num_tags = (int)dbuf_geti64x(c->infile, ifdpos, d->is_le);
	}
	else {
		num_tags = (int)dbuf_getui16x(c->infile, ifdpos, d->is_le);
	}

	de_dbg(c, "number of tags: %d\n", num_tags);
	if(num_tags>200) {
		de_warn(c, "Invalid or excessive number of TIFF tags (%d)\n", num_tags);
		goto done;
	}

	// Record the next IFD in the main list.
	tmpoffset = dbuf_getui32x(c->infile, ifdpos+d->ifdhdrsize+num_tags*d->ifditemsize, d->is_le);
	if(tmpoffset!=0) {
		de_dbg(c, "offset of next IFD: %d\n", (int)tmpoffset);
		push_ifd(c, d, tmpoffset);
	}

	for(i=0; i<num_tags; i++) {
		de_memset(&tg, 0, sizeof(struct taginfo));

		tg.tagnum = (int)dbuf_getui16x(c->infile, ifdpos+d->ifdhdrsize+i*d->ifditemsize, d->is_le);
		tg.tagtype = (int)dbuf_getui16x(c->infile, ifdpos+d->ifdhdrsize+i*d->ifditemsize+2, d->is_le);
		// Not a file pos, but getfpos() does the right thing.
		tg.valcount = getfpos(c, d, ifdpos+d->ifdhdrsize+i*d->ifditemsize+4);

		tg.unit_size = size_of_tiff_type(tg.tagtype);
		tg.total_size = tg.unit_size * tg.valcount;
		if(tg.total_size <= d->offsetsize) {
			tg.val_offset = ifdpos+d->ifdhdrsize+i*d->ifditemsize+d->offsetoffset;
		}
		else {
			tg.val_offset = getfpos(c, d, ifdpos+d->ifdhdrsize+i*d->ifditemsize+d->offsetoffset);
		}

		de_dbg2(c, "tag %d type=%d count=%d size=%d offset=%" INT64_FMT "\n",
			tg.tagnum, tg.tagtype, (int)tg.valcount, (int)tg.total_size,
			tg.val_offset);
		de_dbg_indent(c, 1);

		switch(tg.tagnum) {
		case 330: // SubIFD
		case 34665: // Exif IFD
		case 34853: // GPS IFD
		case 40965: // Interoperability IFD
			do_subifd(c, d, &tg);
			break;

		case 46:
			if(d->fmt==DE_TIFFFMT_PANASONIC) {
				// Some Panasonic RAW files have a JPEG file in tag 46.
				dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "thumb.jpg", NULL);
			}
			break;

		case 256:
			do_display_int_tag(c, d, &tg, "ImageWidth");
			break;

		case 257:
			do_display_int_tag(c, d, &tg, "ImageLength");
			break;

		case 282:
		case 283:
			do_resolution(c, d, &tg);
			break;

		case 296:
			do_resolutionunit(c, d, &tg);
			break;

		case 513: // JPEGInterchangeFormat
			if(tg.unit_size!=d->offsetsize || tg.valcount<1) break;
			jpegoffset = getfpos(c, d, tg.val_offset);
			break;

		case 514: // JPEGInterchangeFormatLength
			if(tg.unit_size!=d->offsetsize || tg.valcount<1) break;
			jpeglength = getfpos(c, d, tg.val_offset);
			break;

		case 700: // XMP
			dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "xmp", NULL);
			break;

		case 33723: // IPTC
			if(c->extract_level>=2 && tg.total_size>0) {
				dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "iptc", NULL);
			}
			break;

		case 34310: // Leaf MOS metadata / "PKTS"
			do_leaf_metadata(c, d, tg.val_offset, tg.total_size);
			break;

		case 34377: // Photoshop
			de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)tg.val_offset, (int)tg.total_size);
			de_fmtutil_handle_photoshop_rsrc(c, tg.val_offset, tg.total_size);
			break;

		case 34675: // ICC Profile
			dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "icc", NULL);
			break;
		}

		de_dbg_indent(c, -1);
	}

	if(jpegoffset>0 && jpeglength!=0) {
		do_oldjpeg(c, d, jpegoffset, jpeglength);
	}

done:
	de_dbg_indent(c, -1);
}

static void do_tiff(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 ifdoffs;

	pos = 0;
	de_dbg(c, "TIFF file header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	// Skip over the signature
	if(d->is_bigtiff) {
		pos += 8;
	}
	else {
		pos += 4;
	}

	// Read the first IFD offset
	ifdoffs = getfpos(c, d, pos);
	de_dbg(c, "offset of first IFD: %d\n", (int)ifdoffs);
	push_ifd(c, d, ifdoffs);

	de_dbg_indent(c, -1);

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

	if(c->module_nesting_level>1) de_dbg2(c, "in tiff module\n");
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

	if(d->is_bigtiff) {
		d->ifdhdrsize = 8;
		d->ifditemsize = 20;
		d->offsetoffset = 12;
		d->offsetsize = 8;
	}
	else {
		d->ifdhdrsize = 2;
		d->ifditemsize = 12;
		d->offsetoffset = 8;
		d->offsetsize = 4;
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
