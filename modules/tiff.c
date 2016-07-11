// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract various things from TIFF (and similar) image files

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"
DE_DECLARE_MODULE(de_module_tiff);

#define MAX_IFDS 1000

#define TAGTYPE_BYTE      1
#define TAGTYPE_ASCII     2
#define TAGTYPE_UINT16    3
#define TAGTYPE_UINT32    4
#define TAGTYPE_RATIONAL  5
#define TAGTYPE_SBYTE     6
#define TAGTYPE_UNDEF     7
#define TAGTYPE_SINT16    8
#define TAGTYPE_SINT32    9
#define TAGTYPE_SRATIONAL 10
#define TAGTYPE_FLOAT     11
#define TAGTYPE_DOUBLE    12
#define TAGTYPE_IFD32     13
#define TAGTYPE_UINT64    16
#define TAGTYPE_SINT64    17
#define TAGTYPE_IFD64     18

#define DE_TIFFFMT_TIFF       1
#define DE_TIFFFMT_BIGTIFF    2
#define DE_TIFFFMT_PANASONIC  3 // Panasonic RAW / RW2
#define DE_TIFFFMT_ORF        4 // Olympus RAW
#define DE_TIFFFMT_DCP        5 // DNG Camera Profile (DCP)
#define DE_TIFFFMT_MDI        6 // Microsoft Office Document Imaging

struct localctx_struct;
typedef struct localctx_struct lctx;
struct taginfo;
struct tagtypeinfo;

struct ifdstack_item {
	de_int64 offset;
};

typedef void (*handler_fn_type)(deark *c, lctx *d, const struct taginfo *tg,
	const struct tagtypeinfo *tti);

typedef int (*val_decoder_fn_type)(deark *c, lctx *d, const struct taginfo *tg,
	const struct tagtypeinfo *tti);

static void handler_resolutionunit(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti);
static void handler_colormap(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti);
static void handler_subifd(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti);

struct tagtypeinfo {
	int tagnum;

	// 0x08=suppress auto display of values
	unsigned int flags;

	const char *tagname;
	handler_fn_type hfn;
	val_decoder_fn_type vdfn;
};
static const struct tagtypeinfo tagtypeinfo_arr[] = {
	{ 254, 0x00, "NewSubfileType", NULL, NULL },
	{ 256, 0x00, "ImageWidth", NULL, NULL },
	{ 257, 0x00, "ImageLength", NULL, NULL },
	{ 258, 0x00, "BitsPerSample", NULL, NULL },
	{ 259, 0x00, "Compression", NULL, NULL },
	{ 262, 0x00, "PhotometricInterpretation", NULL, NULL },
	{ 266, 0x00, "FillOrder", NULL, NULL },
	{ 269, 0x00, "DocumentName", NULL, NULL },
	{ 270, 0x00, "ImageDescription", NULL, NULL },
	{ 271, 0x00, "Make", NULL, NULL },
	{ 272, 0x00, "Model", NULL, NULL },
	{ 273, 0x00, "StripOffsets", NULL, NULL },
	{ 274, 0x00, "Orientation", NULL, NULL },
	{ 277, 0x00, "SamplesPerPixel", NULL, NULL },
	{ 278, 0x00, "RowsPerStrip", NULL, NULL },
	{ 279, 0x00, "StripByteCounts", NULL, NULL },
	{ 282, 0x00, "XResolution", NULL, NULL },
	{ 283, 0x00, "YResolution", NULL, NULL },
	{ 284, 0x00, "PlanarConfiguration", NULL, NULL },
	{ 296, 0x00, "ResolutionUnit", handler_resolutionunit, NULL },
	{ 297, 0x00, "PageNumber", NULL, NULL },
	{ 305, 0x00, "Software", NULL, NULL },
	{ 306, 0x00, "DateTime", NULL, NULL },
	{ 320, 0x08, "ColorMap", handler_colormap, NULL },
	{ 330, 0x00, "SubIFD", NULL, NULL },
#define TAG_JPEGINTERCHANGEFORMAT 513
	{ TAG_JPEGINTERCHANGEFORMAT, 0x00, "JPEGInterchangeFormat", NULL, NULL },
#define TAG_JPEGINTERCHANGEFORMATLENGTH 514
	{ TAG_JPEGINTERCHANGEFORMATLENGTH, 0x00, "JPEGInterchangeFormatLength", NULL, NULL },
#define TAG_XMP               700
	{ TAG_XMP, 0x00, "XMP", NULL, NULL },
#define TAG_IPTC              33723
	{ TAG_IPTC, 0x00, "IPTC", NULL, NULL },
#define TAG_PHOTOSHOPRESOURCES 34377
	{ TAG_PHOTOSHOPRESOURCES, 0x00, "PhotoshopImageResources", NULL, NULL },
	{ 34665, 0x00, "Exif IFD", handler_subifd, NULL },
#define TAG_ICCPROFILE        34675
	{ TAG_ICCPROFILE, 0x00, "ICC Profile", NULL, NULL },
	{ 34853, 0x00, "GPS IFD", handler_subifd, NULL },
	{ 40965, 0x00, "Interoperability IFD", handler_subifd, NULL },
	{ 0, 0, NULL, NULL, NULL }
};

// Data associated with an actual tag in an IFD in the file
struct taginfo {
	int tagnum;
	int tagtype;
	int tag_known;
	de_int64 valcount;
	de_int64 val_offset;
	de_int64 unit_size;
	de_int64 total_size;
};

struct localctx_struct {
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
};

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
	case TAGTYPE_BYTE: case TAGTYPE_SBYTE:
	case TAGTYPE_ASCII:
	case TAGTYPE_UNDEF:
		return 1;
	case TAGTYPE_UINT16: case TAGTYPE_SINT16:
		return 2;
	case TAGTYPE_UINT32: case TAGTYPE_SINT32:
	case TAGTYPE_FLOAT:
	case TAGTYPE_IFD32:
		return 4;
	case TAGTYPE_RATIONAL: case TAGTYPE_SRATIONAL:
	case TAGTYPE_DOUBLE:
	case TAGTYPE_UINT64: case TAGTYPE_SINT64:
	case TAGTYPE_IFD64:
		return 8;
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

static int read_tag_value_as_int64(deark *c, lctx *d, const struct taginfo *tg,
	de_int64 value_index, de_int64 *n)
{
	*n = 0;
	if(tg->valcount<1) return 0;
	if(value_index<0 || value_index>=tg->valcount) return 0;
	if(tg->tagtype==TAGTYPE_UINT16) {
		*n = dbuf_getui16x(c->infile, tg->val_offset + value_index*tg->unit_size, d->is_le);
		return 1;
	}
	else if(tg->tagtype==TAGTYPE_UINT32 || tg->tagtype==TAGTYPE_IFD32) {
		*n = dbuf_getui32x(c->infile, tg->val_offset + value_index*tg->unit_size, d->is_le);
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
	unsigned int createflags;

	if(jpeglength<0) {
		// Missing JPEGInterchangeFormatLength tag. Assume it goes to the end
		// of the file.
		jpeglength = c->infile->len - jpegoffset;
	}

	// Found an embedded JPEG image or thumbnail that we can extract.
	if(d->mparams && d->mparams->codes && de_strchr(d->mparams->codes, 'E')) {
		extension = "exifthumb.jpg";
		createflags = DE_CREATEFLAG_IS_AUX;
	}
	else {
		extension = "jpg";
		// TODO: Should createflags be set to DE_CREATEFLAG_IS_AUX in some cases?
		createflags = 0;
	}
	dbuf_create_file_from_slice(c->infile, jpegoffset, jpeglength, extension, NULL, createflags);
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
			dbuf_create_file_from_slice(c->infile, pos, data_len, "leafthumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
		}
		pos += data_len;
	}
}

static void handler_resolutionunit(deark *c, lctx *d, const struct taginfo *tg,
	const struct tagtypeinfo *tti)
{
	de_int64 n;
	const char *s;

	if(!read_tag_value_as_int64(c, d, tg, 0, &n))
		return;

	if(n==1) s="unspecified";
	else if(n==2) s="pixels/inch";
	else if(n==3) s="pixels/cm";
	else s="?";
	de_dbg(c, "%s: %d (%s)\n", tti->tagname, (int)n, s);
}

static void do_display_int_tag(deark *c, lctx *d, const struct taginfo *tg,
	const struct tagtypeinfo *tti)
{
	de_int64 n;

	if(tg->valcount>1) return;
	if(!read_tag_value_as_int64(c, d, tg, 0, &n))
		return;
	if(tg->tag_known) {
		de_dbg(c, "%s: %d\n", tti->tagname, (int)n);
	}
	else {
		de_dbg(c, "tag_%d value: %d\n", tg->tagnum, (int)n);
	}
}

static void handler_colormap(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti)
{
	de_int64 num_entries;
	de_int64 r1, g1, b1;
	de_byte r2, g2, b2;
	de_int64 i;

	num_entries = tg->valcount / 3;
	de_dbg(c, "ColorMap with %d entries\n", (int)num_entries);
	if(c->debug_level<2) return;
	for(i=0; i<num_entries; i++) {
		read_tag_value_as_int64(c, d, tg, num_entries*0 + i, &r1);
		read_tag_value_as_int64(c, d, tg, num_entries*1 + i, &g1);
		read_tag_value_as_int64(c, d, tg, num_entries*2 + i, &b1);
		r2 = (de_byte)(r1>>8);
		g2 = (de_byte)(g1>>8);
		b2 = (de_byte)(b1>>8);
		de_dbg2(c, "pal[%3d] = (%5d,%5d,%5d) -> (%3d,%3d,%3d)\n", (int)i,
			(int)r1, (int)g1, (int)b1,
			(int)r2, (int)g2, (int)b2);
	}
}

static void handler_subifd(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti)
{
	de_int64 j;
	de_int64 tmpoffset;

	if(tg->unit_size!=d->offsetsize) return;

	for(j=0; j<tg->valcount;j++) {
		tmpoffset = getfpos(c, d, tg->val_offset+tg->unit_size*j);
		de_dbg(c, "offset of %s: %d\n", tti->tagname, (int)tmpoffset);
		push_ifd(c, d, tmpoffset);
	}
}

static void do_dbg_print_values(deark *c, lctx *d, const struct taginfo *tg, const struct tagtypeinfo *tti,
	dbuf *dbglinedbuf)
{
	de_int64 i;
	de_int64 v_int64;
	double v_double;

	if(c->debug_level<1) return;
	if(tti->flags&0x08) return; // Auto-display of values is suppressed for this tag.
	if(tg->valcount<1) return;
	dbuf_puts(dbglinedbuf, " {");

#define DE_TIFF_MAX_VALUES_TO_PRINT 100

	for(i=0; i<tg->valcount && i<DE_TIFF_MAX_VALUES_TO_PRINT; i++) {
		int val_printed = 0;

		switch(tg->tagtype) {
		case TAGTYPE_UINT16: case TAGTYPE_UINT32: case TAGTYPE_IFD32:
			if(read_tag_value_as_int64(c, d, tg, i, &v_int64)) {
				dbuf_printf(dbglinedbuf, "%" INT64_FMT, v_int64);
				val_printed = 1;
			}
			break;
		case TAGTYPE_RATIONAL:
			if(i>0) break; // FIXME: Fix read_tag_value_as_double()
			if(read_tag_value_as_double(c, d, tg, &v_double)) {
				dbuf_printf(dbglinedbuf, "%.4f", v_double);
				val_printed = 1;
			}
			break;
		}

		if(!val_printed) {
			dbuf_puts(dbglinedbuf, "?");
		}

		if(i<tg->valcount-1) {
			dbuf_puts(dbglinedbuf, ",");
		}
	}
	if(tg->valcount>DE_TIFF_MAX_VALUES_TO_PRINT) {
		dbuf_puts(dbglinedbuf, "...");
	}
	dbuf_puts(dbglinedbuf, "}");
}

static const struct tagtypeinfo *find_tagtypeinfo(int tagnum)
{
	de_int64 i;

	for(i=0; tagtypeinfo_arr[i].tagnum!=0; i++) {
		if(tagtypeinfo_arr[i].tagnum==tagnum) {
			return &tagtypeinfo_arr[i];
		}
	}
	return NULL;
}

static void process_ifd(deark *c, lctx *d, de_int64 ifdpos)
{
	int num_tags;
	int i;
	de_int64 jpegoffset = 0;
	de_int64 jpeglength = -1;
	de_int64 tmpoffset;
	dbuf *dbglinedbuf = NULL;
	char tmpbuf[512];
	struct taginfo tg;
	static const struct tagtypeinfo default_tti = { 0, 0x00, "?", NULL, NULL };

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

	dbglinedbuf = dbuf_create_membuf(c, 256, 1);

	for(i=0; i<num_tags; i++) {
		const struct tagtypeinfo *tti;

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

		tti = find_tagtypeinfo(tg.tagnum);
		if(tti) {
			tg.tag_known = 1;
		}
		else {
			tti = &default_tti; // Make sure tti is not NULL.
		}

		dbuf_empty(dbglinedbuf);
		dbuf_printf(dbglinedbuf, "tag %d (%s) ty=%d #=%d offs=%" INT64_FMT,
			tg.tagnum, tti->tagname,
			tg.tagtype, (int)tg.valcount,
			tg.val_offset);

		do_dbg_print_values(c, d, &tg, tti, dbglinedbuf);

		dbuf_copy_all_to_sz(dbglinedbuf, tmpbuf, sizeof(tmpbuf));
		de_dbg(c, "%s\n", tmpbuf);
		de_dbg_indent(c, 1);
		switch(tg.tagnum) {

		case 46:
			if(d->fmt==DE_TIFFFMT_PANASONIC) {
				// Some Panasonic RAW files have a JPEG file in tag 46.
				dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "thumb.jpg", NULL, DE_CREATEFLAG_IS_AUX);
			}
			break;

		case TAG_JPEGINTERCHANGEFORMAT:
			do_display_int_tag(c, d, &tg, tti);
			if(tg.unit_size!=d->offsetsize || tg.valcount<1) break;
			jpegoffset = getfpos(c, d, tg.val_offset);
			break;

		case TAG_JPEGINTERCHANGEFORMATLENGTH:
			do_display_int_tag(c, d, &tg, tti);
			if(tg.unit_size!=d->offsetsize || tg.valcount<1) break;
			jpeglength = getfpos(c, d, tg.val_offset);
			break;

		case TAG_XMP:
			dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
			break;

		case TAG_IPTC:
			if(c->extract_level>=2 && tg.total_size>0) {
				dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
			}
			break;

		case 34310: // Leaf MOS metadata / "PKTS"
			do_leaf_metadata(c, d, tg.val_offset, tg.total_size);
			break;

		case TAG_PHOTOSHOPRESOURCES:
			de_dbg(c, "photoshop segment at %d datasize=%d\n", (int)tg.val_offset, (int)tg.total_size);
			de_fmtutil_handle_photoshop_rsrc(c, tg.val_offset, tg.total_size);
			break;

		case TAG_ICCPROFILE: // ICC Profile
			dbuf_create_file_from_slice(c->infile, tg.val_offset, tg.total_size, "icc", NULL, DE_CREATEFLAG_IS_AUX);
			break;

		default:
			if(tti->hfn) {
				tti->hfn(c, d, &tg, tti);
			}
		}

		de_dbg_indent(c, -1);
	}

	if(jpegoffset>0 && jpeglength!=0) {
		do_oldjpeg(c, d, jpegoffset, jpeglength);
	}

done:
	de_dbg_indent(c, -1);
	dbuf_close(dbglinedbuf);
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
