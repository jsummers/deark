// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Mac Resource [Manager] format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_macrsrc);

#define CODE_8BIM 0x3842494dU
#define CODE_ANPA 0x414e5041U
#define CODE_CURS 0x43555253U
#define CODE_MeSa 0x4d655361U
#define CODE_PICT 0x50494354U
#define CODE_SICN 0x5349434eU
#define CODE_cicn 0x6369636eU
#define CODE_crsr 0x63727372U
#define CODE_icns 0x69636e73U
#define CODE_moov 0x6d6f6f76U

typedef struct localctx_struct {
	u8 extract_raw;
	i64 data_offs, map_offs;
	i64 data_size, map_size;

	i64 typeListOffset_abs;
	i64 nameListOffset_abs;
	dbuf *icns_stream;
	dbuf *psrc_stream;
	const char *errmsgprefix;
} lctx;

struct rsrctypeinfo {
	struct de_fourcc fcc;
	int is_icns_type;
	int is_psrc_type;
};

struct rsrcinstanceinfo {
	int id;
	u8 attribs;
	u8 has_name;
	i64 data_offset;
	i64 name_offset;
	i64 name_raw_len;
	de_ucstring *name;
};

#define CODE_ICN_ 0x49434e23U // ICN#
#define CODE_ICON 0x49434f4eU
#define CODE_icl4 0x69636c34U
#define CODE_icl8 0x69636c38U
#define CODE_icm_ 0x69636d23U // icm#
#define CODE_icm4 0x69636d34U
#define CODE_icm8 0x69636d38U
#define CODE_ics_ 0x69637323U // ics#
#define CODE_ics4 0x69637334U
#define CODE_ics8 0x69637338U

// Helper function to set the filename of an finfo.
static void set_resource_filename(deark *c, lctx *d, de_finfo *fi,
	struct rsrctypeinfo *rti, struct rsrcinstanceinfo *rii, const char *token)
{
	de_ucstring *tmpname = NULL;

	tmpname = ucstring_create(c);
	if(c->filenames_from_file && ucstring_isnonempty(rii->name)) {
		ucstring_append_ucstring(tmpname, rii->name);
		ucstring_append_sz(tmpname, ".", DE_ENCODING_LATIN1);
	}

	if(token) {
		ucstring_append_sz(tmpname, token, DE_ENCODING_LATIN1);
	}
	else {
		ucstring_append_sz(tmpname, rti->fcc.id_sanitized_sz, DE_ENCODING_ASCII);
	}
	de_finfo_set_name_from_ucstring(c, fi, tmpname, 0);
	ucstring_destroy(tmpname);
}

static int is_icns_icon(deark *c, lctx *d, struct rsrctypeinfo *rti)
{
	// TODO: There are many more icns icon types, but it's not clear
	// to me if any others are found in resource forks.
	switch(rti->fcc.id) {
	case CODE_icm_: case CODE_icm4: case CODE_icm8: // 16x12
	case CODE_ics_: case CODE_ics4: case CODE_ics8: // 16x16
	case CODE_ICN_: case CODE_ICON: case CODE_icl4: case CODE_icl8: // 32x32
		return 1;
	}
	return 0;
}

static void open_icns_stream(deark *c, lctx *d)
{
	if(d->icns_stream) return;
	d->icns_stream = dbuf_create_membuf(c, 0, 0);
}

// Construct an .icns file from the suitable icon resources found
// in this file.
static void finalize_icns_stream(deark *c, lctx *d)
{
	dbuf *outf = NULL;

	if(!d->icns_stream) return;

	outf = dbuf_create_output_file(c, "icns", NULL, 0);
	dbuf_writeu32be(outf, CODE_icns);
	dbuf_writeu32be(outf, 8+d->icns_stream->len);
	dbuf_copy(d->icns_stream, 0, d->icns_stream->len, outf);
	dbuf_close(outf);

	dbuf_close(d->icns_stream);
	d->icns_stream = NULL;
}

static void open_psrc_stream(deark *c, lctx *d)
{
	if(d->psrc_stream) return;
	d->psrc_stream = dbuf_create_membuf(c, 0, 0);
}

static void finalize_psrc_stream(deark *c, lctx *d)
{
	if(!d->psrc_stream) return;
	de_fmtutil_handle_photoshop_rsrc(c, d->psrc_stream, 0, d->psrc_stream->len, 0x1);
	dbuf_close(d->psrc_stream);
	d->psrc_stream = NULL;
}

static void do_psrc_resource(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii, i64 dpos, i64 dlen)
{
	if(!d->psrc_stream) {
		open_psrc_stream(c, d);
	}

	// Convert this exploded format to the normal Photoshop Resources format,
	// which we will eventually write to a file.
	// It would be messy to implement a way to directly use the decoder in the
	// psd module. And even if we did that, the option to do this conversion
	// might still be useful.

	de_dbg(c, "[Photoshop resource]");
	dbuf_write(d->psrc_stream, rti->fcc.bytes, 4);
	dbuf_writei16be(d->psrc_stream, (i64)rii->id);
	if(rii->has_name) {
		dbuf_copy(c->infile, rii->name_offset, rii->name_raw_len, d->psrc_stream);
		if(rii->name_raw_len%2) {
			dbuf_writebyte(d->psrc_stream, 0); // padding byte for name
		}
	}
	else {
		dbuf_write_zeroes(d->psrc_stream, 2);
	}
	dbuf_writeu32be(d->psrc_stream, dlen);
	dbuf_copy(c->infile, dpos, dlen, d->psrc_stream);
	if(dlen%2) {
		dbuf_writebyte(d->psrc_stream, 0); // padding byte for data
	}
}

// Handle 'crsr' and 'CURS' cursors.
// The documentation of 'crsr' in ImagingWithQuickDraw seems to have only
// the vaguest resemblance to reality. The code here is partly based on
// reverse engineering.
static void do_crsr_CURS_resource(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii, i64 pos1, i64 dlen)
{
	struct fmtutil_macbitmap_info *bi = NULL;
	de_bitmap *img_color = NULL;
	de_bitmap *img_bw = NULL;
	de_bitmap *img_mask = NULL;
	de_finfo *fi = NULL;
	i64 pos = pos1;
	i64 pixmap_offs = 0;
	i64 pixdata_offs = 0;
	i64 n;
	i64 colortable_size = 0;
	int is_crsr = (rti->fcc.id==CODE_crsr);

	if(dlen<68) goto done;
	fi = de_finfo_create(c);

	if(is_crsr) {
		// TODO: Do we need special handling for type=0x8000 (b/w cursor)?
		n = de_getu16be_p(&pos);
		de_dbg(c, "cursor type: 0x%04x", (unsigned int)n);
		if(n!=0x8000 && n!=0x8001) {
			de_err(c, "Invalid or unsupported 'crsr' cursor type");;
			goto done;
		}
		pixmap_offs = de_getu32be_p(&pos);
		de_dbg(c, "offset to pixel map: %d", (int)pixmap_offs);
		pixdata_offs = de_getu32be_p(&pos);
		de_dbg(c, "offset to pixel data: %d", (int)pixdata_offs);
		pos += 10; // other fields
	}

	de_dbg(c, "b/w foreground at %"I64_FMT, pos);
	img_bw = de_bitmap_create(c, 16, 16, 2);
	de_convert_image_bilevel(c->infile, pos, 2, img_bw, DE_CVTF_WHITEISZERO);
	pos += 32;

	de_dbg(c, "mask at %"I64_FMT, pos);
	img_mask = de_bitmap_create(c, 16, 16, 1);
	de_convert_image_bilevel(c->infile, pos, 2, img_mask, 0);
	pos += 32;

	// I'm assuming the hotspot is a QuickDraw Point structure.
	fi->hotspot_y = (int)de_geti16be_p(&pos);
	fi->hotspot_x = (int)de_geti16be_p(&pos);
	fi->has_hotspot = 1;
	de_dbg(c, "hotspot: (%d,%d)", fi->hotspot_x, fi->hotspot_y);

	de_bitmap_apply_mask(img_bw, img_mask, 0);
	set_resource_filename(c, d, fi, rti, rii, (is_crsr?"crsr_bw":NULL));
	de_bitmap_write_to_file_finfo(img_bw, fi, 0);
	if(!is_crsr) goto done;

	bi = de_malloc(c, sizeof(struct fmtutil_macbitmap_info));
	if(pixmap_offs >= dlen) goto done;
	pos = pos1+pixmap_offs;
	fmtutil_macbitmap_read_baseaddr(c, c->infile, bi, pos);
	pos += 4;
	fmtutil_macbitmap_read_rowbytes_and_bounds(c, c->infile, bi, pos);
	pos += 10;
	fmtutil_macbitmap_read_pixmap_only_fields(c, c->infile, bi, pos);
	pos += 36;
	if(!de_good_image_dimensions(c, bi->width, bi->height)) goto done;

	if((i64)bi->pmTable != pixdata_offs + bi->rowbytes * bi->height) {
		de_warn(c, "Unexpected color table offset. "
			"Cursor might not be decoded correctly.");
	}
	if(bi->pmTable>0 && bi->pmTable<dlen) {
		pos = pos1 + (i64)bi->pmTable;
	}
	else {
		pos = pos1 + pixdata_offs + bi->rowbytes * bi->height;
	}
	if(!fmtutil_macbitmap_read_colortable(c, c->infile, bi, pos, &colortable_size)) {
		goto done;
	}

	img_color = de_bitmap_create(c, bi->width, bi->height, 4);

	if(pixdata_offs >= dlen) goto done;
	pos = pos1 + pixdata_offs;
	de_dbg(c, "color pixels at %"I64_FMT, pos);
	de_convert_image_paletted(c->infile, pos, bi->pixelsize, bi->rowbytes,
		bi->pal, img_color, 0);
	de_bitmap_apply_mask(img_color, img_mask, 0);

	set_resource_filename(c, d, fi, rti, rii, NULL);
	if(bi->hdpi>=1.0 && bi->vdpi>=1.0) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = bi->hdpi;
		fi->density.ydens = bi->vdpi;
	}
	de_bitmap_write_to_file_finfo(img_color, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_free(c, bi);
	de_bitmap_destroy(img_color);
	de_bitmap_destroy(img_bw);
	de_bitmap_destroy(img_mask);
	de_finfo_destroy(c, fi);
}

// SICN - Small icons - One or more 16x16 images
static void do_SICN_resource(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii, i64 pos1, i64 len)
{
	de_finfo *fi = NULL;
	i64 numicons;
	i64 i;

	numicons = len/32;
	fi = de_finfo_create(c);
	set_resource_filename(c, d, fi, rti, rii, NULL);

	for(i=0; i<numicons; i++) {
		de_bitmap *img = NULL;

		img = de_bitmap_create(c, 16, 16, 1);
		de_convert_image_bilevel(c->infile, pos1+32*i, 2, img, DE_CVTF_WHITEISZERO);
		de_bitmap_write_to_file_finfo(img, fi, 0);
		de_bitmap_destroy(img);
	}
}

static void do_cicn_resource(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii, i64 dpos, i64 dlen)
{
	struct fmtutil_macbitmap_info *bi_fgcolor = NULL;
	struct fmtutil_macbitmap_info *bi_mask = NULL;
	struct fmtutil_macbitmap_info *bi_bw = NULL;
	de_bitmap *img_fgcolor = NULL;
	de_bitmap *img_mask = NULL;
	de_bitmap *img_bw = NULL;
	de_finfo *fi = NULL;
	i64 fgcolor_bitssize;
	i64 mask_bitssize;
	i64 bw_bitssize = 0;
	int bw_exists = 0;
	i64 colortable_size = 0;
	i64 pos = dpos;
	int needmsg = 1;
	int ok = 0;

	bi_fgcolor = de_malloc(c, sizeof(struct fmtutil_macbitmap_info));
	bi_mask = de_malloc(c, sizeof(struct fmtutil_macbitmap_info));
	bi_bw = de_malloc(c, sizeof(struct fmtutil_macbitmap_info));
	fi = de_finfo_create(c);

	de_dbg(c, "[color pixmap header]");
	de_dbg_indent(c, 1);
	fmtutil_macbitmap_read_baseaddr(c, c->infile, bi_fgcolor, pos);
	pos += 4;
	fmtutil_macbitmap_read_rowbytes_and_bounds(c, c->infile, bi_fgcolor, pos);
	if(!bi_fgcolor->pixmap_flag) goto done;
	pos += 10;
	fmtutil_macbitmap_read_pixmap_only_fields(c, c->infile, bi_fgcolor, pos);
	pos += 36;
	de_dbg_indent(c, -1);

	de_dbg(c, "[mask bitmap header]");
	de_dbg_indent(c, 1);
	fmtutil_macbitmap_read_baseaddr(c, c->infile, bi_mask, pos);
	pos += 4;
	fmtutil_macbitmap_read_rowbytes_and_bounds(c, c->infile, bi_mask, pos);
	pos += 10;
	de_dbg_indent(c, -1);

	de_dbg(c, "[b/w bitmap header]");
	de_dbg_indent(c, 1);
	fmtutil_macbitmap_read_baseaddr(c, c->infile, bi_bw, pos);
	pos += 4;
	fmtutil_macbitmap_read_rowbytes_and_bounds(c, c->infile, bi_bw, pos);
	pos += 10;
	de_dbg_indent(c, -1);

	pos += 4; // "icon data"

	// This is said to be optional, but I don't know how to tell if it exists.
	if(bi_bw->rowbytes && bi_bw->height && bi_bw->width) {
		bw_exists = 1;
	}

	if(!de_good_image_dimensions_noerr(c, bi_fgcolor->width, bi_fgcolor->height)) goto done;
	if(!de_good_image_dimensions_noerr(c, bi_mask->width, bi_mask->height)) goto done;
	if(bw_exists && !de_good_image_dimensions_noerr(c, bi_bw->width, bi_bw->height)) goto done;

	if(bi_fgcolor->pixeltype!=0) goto done;
	if(bi_fgcolor->pixelsize!=bi_fgcolor->cmpsize) goto done;
	if(bi_fgcolor->cmpcount!=1) goto done;
	if(bi_fgcolor->pixelsize!=1 && bi_fgcolor->pixelsize!=2 &&
		bi_fgcolor->pixelsize!=4 && bi_fgcolor->pixelsize!=8)
	{
		goto done;
	}

	mask_bitssize = bi_mask->rowbytes * bi_mask->height;
	if(bw_exists) bw_bitssize = bi_bw->rowbytes * bi_bw->height;
	fgcolor_bitssize =  bi_fgcolor->rowbytes * bi_fgcolor->height;

	if(pos+mask_bitssize > dpos+dlen) goto done;
	de_dbg(c, "mask bitmap at %"I64_FMT", len=%"I64_FMT, pos, mask_bitssize);
	img_mask = de_bitmap_create(c, bi_mask->width, bi_mask->height, 1);
	de_convert_image_bilevel(c->infile, pos, bi_mask->rowbytes, img_mask, 0);
	pos += mask_bitssize;

	if(bw_exists) {
		if(pos+bw_bitssize > dpos+dlen) goto done;
		de_dbg(c, "bw bitmap at %"I64_FMT", len=%"I64_FMT, pos, bw_bitssize);
		img_bw = de_bitmap_create(c, bi_bw->width, bi_bw->height, 2);
		de_convert_image_bilevel(c->infile, pos, bi_bw->rowbytes, img_bw,
			DE_CVTF_WHITEISZERO);
		de_bitmap_apply_mask(img_bw, img_mask, 0);
		set_resource_filename(c, d, fi, rti, rii, "cicn_bw");
		de_bitmap_write_to_file_finfo(img_bw, fi, DE_CREATEFLAG_OPT_IMAGE);
		pos += bw_bitssize;
	}
	else {
		de_dbg(c, "[assuming there is no bw bitmap]");
	}

	if(!fmtutil_macbitmap_read_colortable(c, c->infile, bi_fgcolor,
		pos, &colortable_size))
	{
		goto done;
	}
	pos += colortable_size;

	if(pos+fgcolor_bitssize > dpos+dlen) goto done;
	de_dbg(c, "color bitmap at %"I64_FMT", len=%"I64_FMT, pos, fgcolor_bitssize);
	img_fgcolor = de_bitmap_create(c, bi_fgcolor->width, bi_fgcolor->height, 4);
	de_convert_image_paletted(c->infile, pos, bi_fgcolor->pixelsize, bi_fgcolor->rowbytes,
		bi_fgcolor->pal, img_fgcolor, 0);
	de_bitmap_apply_mask(img_fgcolor, img_mask, 0);
	if(bi_fgcolor->hdpi>=1.0 && bi_fgcolor->vdpi>=1.0) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = bi_fgcolor->hdpi;
		fi->density.ydens = bi_fgcolor->vdpi;
	}
	set_resource_filename(c, d, fi, rti, rii, NULL);
	de_bitmap_write_to_file_finfo(img_fgcolor, fi, DE_CREATEFLAG_OPT_IMAGE);
	//pos += fgcolor_bitssize;
	ok = 1;

done:
	if(!ok && needmsg) {
		// TODO: There are a small but significant number of 'cicn' resources that
		// appear to use a completely different format than the one I know about.
		// (Or it could be some sort of systematic corruption.)
		de_err(c, "Failed to parse 'cicn' icon resource at %"I64_FMT, dpos);
	}
	de_bitmap_destroy(img_fgcolor);
	de_bitmap_destroy(img_mask);
	de_bitmap_destroy(img_bw);
	de_free(c, bi_fgcolor);
	de_free(c, bi_mask);
	de_free(c, bi_bw);
	de_finfo_destroy(c, fi);
}

static int looks_like_pict(deark *c, lctx *d, struct rsrcinstanceinfo *rii,
	i64 pos, i64 len)
{
	if(len>=12 && !dbuf_memcmp(c->infile, pos+10, "\x11\x01", 2)) {
		return 1; // PICTv1
	}
	if(len>=16 && !dbuf_memcmp(c->infile, pos+10, "\x00\x11\x02\xff\x0c\x00", 6)) {
		return 1; // PICTv2
	}
	return 0;
}

static void extract_raw_rsrc(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii, i64 dpos, i64 dlen)
{
	de_finfo *fi = NULL;
	de_ucstring *s = NULL;

	fi = de_finfo_create(c);
	s = ucstring_create(c);

	ucstring_append_sz(s, rti->fcc.id_sanitized_sz, DE_ENCODING_ASCII);
	ucstring_strip_trailing_spaces(s);
	if(rii->attribs&0x01) {
		ucstring_append_sz(s, ".cmpr", DE_ENCODING_LATIN1);
	}
	else {
		ucstring_append_sz(s, ".bin", DE_ENCODING_LATIN1);
	}
	de_finfo_set_name_from_ucstring(c, fi, s, 0);
	dbuf_create_file_from_slice(c->infile, dpos, dlen, NULL, fi, 0x0);

	de_finfo_destroy(c, fi);
	ucstring_destroy(s);
}

static void do_resource_data(deark *c, lctx *d, struct rsrctypeinfo *rti,
	struct rsrcinstanceinfo *rii)
{
	i64 dpos, dlen;
	const char *ext = "bin";
	int extr_flag = 0;
	int is_pict = 0;
	int handled = 0;

	de_dbg(c, "resource data at %d", (int)rii->data_offset);
	de_dbg_indent(c, 1);
	dlen = de_getu32be(rii->data_offset);
	dpos = rii->data_offset+4;
	de_dbg(c, "dpos: %d, dlen: %d", (int)dpos, (int)dlen);
	if(dpos+dlen > c->infile->len) goto done;

	if(d->extract_raw) {
		extract_raw_rsrc(c, d, rti, rii, dpos, dlen);
		goto done;
	}

	if(rii->attribs&0x01) {
		; // Compressed. Don't know how to handle this.
	}
	else if(rti->fcc.id==CODE_PICT && looks_like_pict(c, d, rii, dpos, dlen)) {
		ext = "pict";
		extr_flag = 1;
		is_pict = 1;
	}
	else if(rti->fcc.id==CODE_icns) {
		ext = "icns";
		extr_flag = 1;
	}
	else if(rti->fcc.id==CODE_moov) {
		ext = "mov";
		extr_flag = 1;
	}
	else if(rti->fcc.id==CODE_ANPA && rii->id==10000) {
		de_dbg(c, "IPTC data at %"I64_FMT, dpos);
		de_dbg_indent(c, 1);
		de_fmtutil_handle_iptc(c, c->infile, dpos, dlen, 0x0);
		de_dbg_indent(c, -1);
		handled = 1;
	}
	else if(rti->is_icns_type) {
		de_dbg(c, "[icns resource]");
		open_icns_stream(c, d);
		dbuf_write(d->icns_stream, rti->fcc.bytes, 4);
		dbuf_writeu32be(d->icns_stream, 8+dlen);
		dbuf_copy(c->infile, dpos, dlen, d->icns_stream);
		handled = 1;
	}
	else if(rti->is_psrc_type) {
		do_psrc_resource(c, d, rti, rii, dpos, dlen);
		handled = 1;
	}
	else if(rti->fcc.id==CODE_CURS || rti->fcc.id==CODE_crsr) {
		do_crsr_CURS_resource(c, d, rti, rii, dpos, dlen);
		handled = 1;
	}
	else if(rti->fcc.id==CODE_cicn) {
		do_cicn_resource(c, d, rti, rii, dpos, dlen);
		handled = 1;
	}
	else if(rti->fcc.id==CODE_SICN) {
		do_SICN_resource(c, d, rti, rii, dpos, dlen);
		handled = 1;
	}

	if(extr_flag) {
		dbuf *outf = NULL;
		de_finfo *fi = NULL;

		fi = de_finfo_create(c);
		set_resource_filename(c, d, fi, rti, rii, ext);
		outf = dbuf_create_output_file(c, NULL, fi, 0);
		de_finfo_destroy(c, fi);
		if(is_pict) {
			dbuf_write_zeroes(outf, 512);
		}
		dbuf_copy(c->infile, dpos, dlen, outf);
		dbuf_close(outf);
		handled = 1;
	}

	if(!handled && c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, dpos, dlen, 256, NULL, 0x1);
	}

done:
	de_dbg_indent(c, -1);
}

// Sets rii->name_raw_len.
// Sets rii->name.
static void do_resource_name(deark *c, lctx *d, struct rsrcinstanceinfo *rii)
{
	i64 nlen;

	nlen = (i64)de_getbyte(rii->name_offset);
	rii->name_raw_len = 1+nlen;
	rii->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, rii->name_offset+1, nlen, rii->name , 0, DE_ENCODING_MACROMAN);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(rii->name ));
}

static void do_resource_record(deark *c, lctx *d, struct rsrctypeinfo *rti,
	i64 pos1)
{
	i64 dataOffset_rel;
	i64 nameOffset_rel;
	i64 pos = pos1;
	struct rsrcinstanceinfo rii;

	de_zeromem(&rii, sizeof(struct rsrcinstanceinfo));
	rii.id = (int)de_geti16be_p(&pos);
	de_dbg(c, "id: %d", rii.id);
	nameOffset_rel = de_getu16be_p(&pos);
	if(nameOffset_rel!=0xffff) {
		rii.has_name = 1;
		de_dbg(c, "nameOffset: (%d+)%d", (int)d->nameListOffset_abs, (int)nameOffset_rel);
		rii.name_offset = d->nameListOffset_abs+nameOffset_rel;
		do_resource_name(c, d, &rii);
	}
	rii.attribs = de_getbyte_p(&pos);
	if(rii.attribs==0) {
		de_dbg(c, "attributes: 0x%02x", (unsigned int)rii.attribs);
	}
	else {
		de_ucstring *flags_str;
		flags_str = ucstring_create(c);
		if(rii.attribs & 0x40) ucstring_append_flags_item(flags_str, "system heap");
		if(rii.attribs & 0x20) ucstring_append_flags_item(flags_str, "purgeable");
		if(rii.attribs & 0x10) ucstring_append_flags_item(flags_str, "locked");
		if(rii.attribs & 0x08) ucstring_append_flags_item(flags_str, "read-only");
		if(rii.attribs & 0x04) ucstring_append_flags_item(flags_str, "preload");
		if(rii.attribs & 0x01) ucstring_append_flags_item(flags_str, "compressed");
		de_dbg(c, "attributes: 0x%02x (%s)", (unsigned int)rii.attribs, ucstring_getpsz_d(flags_str));
		ucstring_destroy(flags_str);
	}

	dataOffset_rel = dbuf_getint_ext(c->infile, pos, 3, 0, 0);
	rii.data_offset = d->data_offs + dataOffset_rel;
	pos += 3;
	de_dbg(c, "dataOffset: (%d+)%d", (int)d->data_offs, (int)dataOffset_rel);
	do_resource_data(c, d, rti, &rii);

	if(rii.name) ucstring_destroy(rii.name);
}

static void do_resource_list(deark *c, lctx *d, struct rsrctypeinfo *rti,
	i64 rsrc_list_offs, i64 count)
{
	i64 k;
	i64 pos = rsrc_list_offs;

	de_dbg(c, "resource list at %d", (int)rsrc_list_offs);
	de_dbg_indent(c, 1);
	for(k=0; k<count; k++) {
		de_dbg(c, "resource record[%d] at %"I64_FMT" (type '%s')", (int)k, pos,
			rti->fcc.id_dbgstr);
		de_dbg_indent(c, 1);
		do_resource_record(c, d, rti, pos);
		de_dbg_indent(c, -1);
		pos += 12;
	}
	de_dbg_indent(c, -1);
}

static void do_type_item(deark *c, lctx *d, i64 type_list_offs,
	i64 idx, i64 pos1)
{
	i64 pos = pos1;
	i64 count;
	i64 list_offs_rel;
	struct rsrctypeinfo rti;

	de_zeromem(&rti, sizeof(struct rsrctypeinfo));
	dbuf_read_fourcc(c->infile, pos, &rti.fcc, 4, 0x0);
	de_dbg(c, "resource type: '%s'", rti.fcc.id_dbgstr);
	pos += 4;
	rti.is_icns_type = is_icns_icon(c, d, &rti);

	// TODO: What other signatures should we include?
	if(rti.fcc.id==CODE_8BIM || rti.fcc.id==CODE_MeSa) {
		rti.is_psrc_type = 1;
	}

	count = 1+de_getu16be_p(&pos);
	de_dbg(c, "count: %d", (int)count);
	list_offs_rel = de_getu16be_p(&pos);
	de_dbg(c, "list offset: (%d+)%d", (int)type_list_offs, (int)list_offs_rel);

	do_resource_list(c, d, &rti, type_list_offs+list_offs_rel, count);
}

static void do_type_list(deark *c, lctx *d)
{
	i64 pos1 = d->typeListOffset_abs;
	i64 pos = pos1;
	i64 type_count_raw;
	i64 type_count;
	i64 k;

	de_dbg(c, "type list at %d", (int)pos1);
	de_dbg_indent(c, 1);
	type_count_raw = de_getu16be_p(&pos);
	type_count = (type_count_raw==0xffff)?0:(type_count_raw+1);
	de_dbg(c, "count: %d", (int)type_count);

	for(k=0; k<type_count; k++) {
		de_dbg(c, "type record[%d] at %d", (int)k, (int)pos);
		de_dbg_indent(c, 1);
		do_type_item(c, d, pos1, k, pos);
		pos += 8;
		de_dbg_indent(c, -1);
	}
	de_dbg_indent(c, -1);
}

static void do_map(deark *c, lctx *d, i64 map_offs, i64 map_size)
{
	i64 pos = map_offs;
	i64 typeListOffset_rel, nameListOffset_rel;
	i64 n;

	n = de_getu32be(map_offs+4);
	if(n!=map_offs) {
		de_err(c, "%sResource map section not found, expected to be at %"I64_FMT,
			d->errmsgprefix, map_offs);
		return;
	}

	de_dbg(c, "resource map section at %d", (int)map_offs);
	de_dbg_indent(c, 1);

	pos += 16; // copy of header
	pos += 4; // nextResourceMap
	pos += 2; // fileRef
	pos += 2; // attributes

	typeListOffset_rel = de_getu16be_p(&pos);
	de_dbg(c, "type list offset: (%d+)%d", (int)map_offs,
		(int)typeListOffset_rel);
	d->typeListOffset_abs = map_offs + typeListOffset_rel;

	nameListOffset_rel = de_getu16be_p(&pos);
	de_dbg(c, "name list offset: (%d+)%d", (int)map_offs,
		(int)nameListOffset_rel);
	d->nameListOffset_abs = map_offs + nameListOffset_rel;

	if(typeListOffset_rel<28) {
		de_err(c, "%sInvalid typeListOffset", d->errmsgprefix);
		goto done;
	}

	do_type_list(c, d);

done:
	de_dbg_indent(c, 1);
}

static void de_run_macrsrc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));
	if(c->module_disposition==DE_MODDISP_INTERNAL) {
		d->errmsgprefix = "[Resource format] ";
	}
	else {
		d->errmsgprefix = "";
	}

	if(de_get_ext_option(c, "macrsrc:extractraw")) {
		d->extract_raw = 1;
	}

	if(c->infile->len<16) {
		de_err(c, "%sFile too small to be a valid Resource file", d->errmsgprefix);
		goto done;
	}

	pos = 0;
	d->data_offs = de_getu32be_p(&pos);
	d->map_offs = de_getu32be_p(&pos);
	d->data_size = de_getu32be_p(&pos);
	d->map_size = de_getu32be_p(&pos);
	de_dbg(c, "data: pos=%"I64_FMT", len=%"I64_FMT, d->data_offs, d->data_size);
	de_dbg(c, "map: pos=%"I64_FMT", len=%"I64_FMT, d->map_offs, d->map_size);
	do_map(c, d, d->map_offs, d->map_size);

done:
	finalize_icns_stream(c, d);
	finalize_psrc_stream(c, d);
	de_free(c, d);
}

static int de_identify_macrsrc(deark *c)
{
	u8 b[16];
	i64 n[4];
	size_t k;

	if(de_getu32be(0)!=256) return 0;
	de_read(b, 0, 16);
	for(k=0; k<4; k++) {
		n[k] = de_getu32be_direct(&b[4*k]);
	}
	if(n[0]+n[2]>n[1]) return 0; // data can't go past map start
	if(n[3]<30) return 0; // minimum map len
	if(n[1]+n[3]>c->infile->len) return 0; // map can't go past eof
	// map should start with a copy of the header
	if(dbuf_memcmp(c->infile, n[1], (const void*)b, 16)) return 0;
	if(n[1]+n[3]==c->infile->len) return 100;
	return 75;
}

static void de_help_macrsrc(deark *c)
{
	de_msg(c, "-opt macrsrc:extractraw : Extract all resources to files");
}

void de_module_macrsrc(deark *c, struct deark_module_info *mi)
{
	mi->id = "macrsrc";
	mi->desc = "Macintosh Resource Manager";
	mi->run_fn = de_run_macrsrc;
	mi->identify_fn = de_identify_macrsrc;
	mi->help_fn = de_help_macrsrc;
}
