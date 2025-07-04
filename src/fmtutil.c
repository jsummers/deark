// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This file is for format-specific functions that are used by multiple modules.

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

void fmtutil_get_bmp_compression_name(u32 code, char *s, size_t s_len,
	int is_os2v2)
{
	const char *name1 = "?";
	switch(code) {
	case 0: name1 = "BI_RGB, uncompressed"; break;
	case 1: name1 = "BI_RLE8"; break;
	case 2: name1 = "BI_RLE4"; break;
	case 3:
		if(is_os2v2)
			name1 = "Huffman 1D";
		else
			name1 = "BI_BITFIELDS, uncompressed";
		break;
	case 4:
		if(is_os2v2)
			name1 = "RLE24";
		else
			name1 = "BI_JPEG";
		break;
	case 5: name1 = "BI_PNG"; break;
	}
	de_strlcpy(s, name1, s_len);
}

// Gathers information about a DIB.
// If DE_BMPINFO_HAS_FILEHEADER flag is set, pos points to the BITMAPFILEHEADER.
// Otherwise, it points to the BITMAPINFOHEADER.
// Caller allocates bi.
// Returns 0 if BMP is invalid.
// If DE_BMPINFO_NOERR is set, will not report errors, but may still return 0.
int fmtutil_get_bmpinfo(deark *c, dbuf *f, struct de_bmpinfo *bi, i64 pos,
	i64 len, unsigned int flags)
{
	i64 fhs; // file header size
	i64 bmih_pos;
	struct de_fourcc cmpr4cc;
	char cmprname_dbgstr[80];

	de_zeromem(bi, sizeof(struct de_bmpinfo));
	de_zeromem(&cmpr4cc, sizeof(struct de_fourcc));

	fhs = (flags & DE_BMPINFO_HAS_FILEHEADER) ? 14 : 0;

	if(fhs+len < 16) return 0;

	if(fhs) {
		if(flags & DE_BMPINFO_HAS_HOTSPOT) {
			bi->hotspot_x = (int)dbuf_getu16le(f, pos+6);
			bi->hotspot_y = (int)dbuf_getu16le(f, pos+8);
			de_dbg(c, "hotspot: (%d,%d)", bi->hotspot_x, bi->hotspot_y);
		}

		bi->bitsoffset = dbuf_getu32le(f, pos+10);
		de_dbg(c, "bits offset: %d", (int)bi->bitsoffset);
	}

	bmih_pos = pos + fhs;

	bi->infohdrsize = dbuf_getu32le(f, bmih_pos);

	if(bi->infohdrsize==0x474e5089 && (flags & DE_BMPINFO_ICO_FORMAT)) {
		// We don't examine PNG-formatted icons, but we can identify them.
		bi->infohdrsize = 0;
		bi->file_format = DE_BMPINFO_FMT_PNG;
		return 1;
	}

	de_dbg(c, "info header size: %d", (int)bi->infohdrsize);

	if(bi->infohdrsize==12) {
		bi->bytes_per_pal_entry = 3;
		bi->width = dbuf_getu16le(f, bmih_pos+4);
		bi->height = dbuf_getu16le(f, bmih_pos+6);
		bi->bitcount = dbuf_getu16le(f, bmih_pos+10);
	}
	else if(bi->infohdrsize>=16 && bi->infohdrsize<=124) {
		bi->bytes_per_pal_entry = 4;
		bi->width = dbuf_getu32le(f, bmih_pos+4);
		bi->height = dbuf_geti32le(f, bmih_pos+8);
		if(bi->height<0) {
			bi->is_topdown = 1;
			bi->height = -bi->height;
		}
		bi->bitcount = dbuf_getu16le(f, bmih_pos+14);
		if(bi->infohdrsize>=20) {
			bi->compression_field = (u32)dbuf_getu32le(f, bmih_pos+16);
			if(flags & DE_BMPINFO_CMPR_IS_4CC) {
				dbuf_read_fourcc(f, bmih_pos+16, &cmpr4cc, 4, 0x0);
			}
		}
		if(bi->infohdrsize>=24) {
			bi->sizeImage_field = dbuf_getu32le(f, bmih_pos+20);
		}
		if(bi->infohdrsize>=36) {
			bi->pal_entries = dbuf_getu32le(f, bmih_pos+32);
		}
	}
	else {
		return 0;
	}

	if(flags & DE_BMPINFO_ICO_FORMAT) bi->height /= 2;

	if(bi->bitcount>=1 && bi->bitcount<=8) {
		if(bi->pal_entries==0) {
			bi->pal_entries = de_pow2(bi->bitcount);
		}
		// I think the NumColors field (in icons) is supposed to be the maximum number of
		// colors implied by the bit depth, not the number of colors in the palette.
		bi->num_colors = de_pow2(bi->bitcount);
	}
	else {
		// An arbitrary value. All that matters is that it's >=256.
		bi->num_colors = 16777216;
	}

	de_dbg_dimensions(c, bi->width, bi->height);
	de_dbg(c, "bit count: %d", (int)bi->bitcount);

	if((flags & DE_BMPINFO_CMPR_IS_4CC) && (bi->compression_field>0xffff)) {
		de_snprintf(cmprname_dbgstr, sizeof(cmprname_dbgstr), "'%s'", cmpr4cc.id_dbgstr);
	}
	else {
		fmtutil_get_bmp_compression_name(bi->compression_field,
			cmprname_dbgstr, sizeof(cmprname_dbgstr), 0);
	}
	de_dbg(c, "compression: %u (%s)", (unsigned int)bi->compression_field, cmprname_dbgstr);

	if(bi->sizeImage_field!=0) {
		de_dbg(c, "sizeImage: %u", (unsigned int)bi->sizeImage_field);
	}

	de_dbg(c, "palette entries: %u", (unsigned int)bi->pal_entries);
	if(bi->pal_entries>256 && bi->bitcount>8) {
		de_warn(c, "Ignoring bad palette size (%u entries)", (unsigned int)bi->pal_entries);
		bi->pal_entries = 0;
	}

	bi->pal_bytes = bi->bytes_per_pal_entry*bi->pal_entries;
	bi->size_of_headers_and_pal = fhs + bi->infohdrsize + bi->pal_bytes;

	// FIXME: cmpr type 3 doesn't always mean BITFIELDS
	if(bi->compression_field==3) {
		bi->size_of_headers_and_pal += 12; // BITFIELDS
	}

	bi->is_compressed = !((bi->compression_field==0) ||
		(bi->compression_field==3 && bi->bitcount>1));

	if(flags & DE_BMPINFO_NOERR) {
		if(!de_good_image_dimensions_noerr(c, bi->width, bi->height)) {
			return 0;
		}
	}
	else {
		if(!de_good_image_dimensions(c, bi->width, bi->height)) {
			return 0;
		}
	}

	// TODO: This needs work, to decide how to handle compressed images.
	// TODO: What about BI_BITFIELDS images?
	if(bi->compression_field==0) {
		// Try to figure out the true size of the resource, minus any padding.

		bi->rowspan = ((bi->bitcount*bi->width +31)/32)*4;
		bi->foreground_size = bi->rowspan * bi->height;
		de_dbg(c, "foreground size: %d", (int)bi->foreground_size);

		if(flags & DE_BMPINFO_ICO_FORMAT) {
			bi->mask_rowspan = ((bi->width +31)/32)*4;
			bi->mask_size = bi->mask_rowspan * bi->height;
			de_dbg(c, "mask size: %d", (int)bi->mask_size);
		}
		else {
			bi->mask_size = 0;
		}

		bi->total_size = bi->size_of_headers_and_pal + bi->foreground_size + bi->mask_size;
	}
	else {
		// Don't try to figure out the true size of compressed or other unusual images.
		bi->total_size = len;
	}

	return 1;
}

// TODO: Document and review whether the bi->total_size and
// bi->size_of_headers_and_pal fields include the 14-byte fileheader.
void fmtutil_generate_bmpfileheader(deark *c, dbuf *outf, const struct de_bmpinfo *bi,
	i64 file_size_override)
{
	i64 file_size_to_write;

	dbuf_write(outf, (const u8*)"BM", 2);

	if(file_size_override)
		file_size_to_write = file_size_override;
	else
		file_size_to_write = 14 + bi->total_size;
	dbuf_writeu32le(outf, file_size_to_write);

	dbuf_write_zeroes(outf, 4);
	dbuf_writeu32le(outf, 14 + bi->size_of_headers_and_pal);
}

// Extracts Exif if extract_level>=2, or "extractexif" option is set.
// Otherwise decodes.
void fmtutil_handle_exif2(deark *c, i64 pos, i64 len,
	u32 *returned_flags, u32 *orientation, u32 *exifversion)
{
	int user_opt;
	de_module_params *mparams = NULL;

	if(returned_flags) {
		*returned_flags = 0;
	}

	user_opt = de_get_ext_option_bool(c, "extractexif", -1);
	if(user_opt==1 || (c->extract_level>=2 && user_opt!=0)) {
		// Writing raw Exif data isn't very useful, but do so if requested.
		dbuf_create_file_from_slice(c->infile, pos, len, "exif.tif", NULL, DE_CREATEFLAG_IS_AUX);

		// Caller will have to reprocess the Exif file to extract anything from it.
		return;
	}

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "E";

	de_run_module_by_id_on_slice(c, "tiff", mparams, c->infile, pos, len);
	if(returned_flags) {
		// FIXME: It's an unfortunate bug that returned_flags does not work if
		// extract_level>=2, but for now there's no reasonable way to fix it.
		// We have to process -- not extract -- the Exif chunk if we want to
		// know what's in it.
		*returned_flags = mparams->out_params.flags;
		if((mparams->out_params.flags & 0x20) && orientation) {
			*orientation = mparams->out_params.uint1;
		}

		if((mparams->out_params.flags & 0x40) && exifversion) {
			*exifversion = mparams->out_params.uint2;
		}
	}

	de_free(c, mparams);
}

void fmtutil_handle_exif(deark *c, i64 pos, i64 len)
{
	fmtutil_handle_exif2(c, pos, len, NULL, NULL, NULL);
}

static void wrap_in_tiff(deark *c, dbuf *f, i64 dpos, i64 dlen,
	const char *swstring, unsigned int tag, const char *ext, unsigned int createflags);

// Either extract IPTC-IIM data to a file, or drill down into it.
// flags:
//  0 = default behavior (currently: depends on c->extract_level and options)
//  2 = this came from our TIFF-encapsulated format
void fmtutil_handle_iptc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags)
{
	int should_decode;
	int should_extract;
	int user_opt;
	int extract_fmt = 1; // 0=raw, 1=TIFF-wrapped

	if(len<1) return;

	user_opt = de_get_ext_option_bool(c, "extractiptc", -1);

	if(user_opt==1 || (c->extract_level>=2 && user_opt!=0)) {
		should_decode = 0;
		should_extract = 1;
		if(flags&0x2) {
			// Avoid "extracting" in a way that would just recreate the exact same file.
			extract_fmt = 0;
		}
	}
	else {
		should_decode = 1;
		should_extract = 0;
	}

	if(should_decode) {
		de_run_module_by_id_on_slice(c, "iptc", NULL, f, pos, len);
	}

	if(should_extract && extract_fmt==0) {
		dbuf_create_file_from_slice(f, pos, len, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(should_extract && extract_fmt==1) {
		wrap_in_tiff(c, f, pos, len, "Deark extracted IPTC", 33723, "iptctiff",
			DE_CREATEFLAG_IS_AUX);
	}
}

// If oparams is not NULL, if must be initialized by the caller. If the data is
// decoded, oparams will be used by the submodule, and values may be returned in
// it.
// flags:
//  0 = default behavior (currently: always decode)
//  1 = always write to file
//  2 = this came from our TIFF-encapsulated format
void fmtutil_handle_photoshop_rsrc2(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags, struct de_module_out_params *oparams)
{
	int should_decode;
	int should_extract;
	int extract_fmt = 1; // 0=raw, 1=TIFF-wrapped

	if(flags&0x1) {
		should_decode = 0;
		should_extract = 1;
	}
	else if(de_get_ext_option_bool(c, "extract8bim", 0)) {
		should_extract = 1;
		should_decode = 0;
		if(flags&0x2) {
			// Avoid "extracting" in a way that would just recreate the exact same file.
			extract_fmt = 0;
		}
	}
	else {
		should_decode = 1;
		should_extract = 0;
	}

	if(should_decode) {
		de_module_params *mparams = NULL;

		mparams = de_malloc(c, sizeof(de_module_params));
		mparams->in_params.codes = "R";
		if(oparams) {
			// Since mparams->out_params is an embedded struct, not a pointer,
			// we have to copy oparam's fields to and from it.
			mparams->out_params = *oparams; // struct copy
		}
		de_run_module_by_id_on_slice(c, "psd", mparams, f, pos, len);
		if(oparams) {
			*oparams = mparams->out_params; // struct copy
		}
		de_free(c, mparams);
	}

	if(should_extract && extract_fmt==0) {
		dbuf_create_file_from_slice(f, pos, len, "8bim", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else if(should_extract && extract_fmt==1) {
		wrap_in_tiff(c, f, pos, len, "Deark extracted 8BIM", 34377, "8bimtiff",
			DE_CREATEFLAG_IS_AUX);
	}
}

void fmtutil_handle_photoshop_rsrc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags)
{
	fmtutil_handle_photoshop_rsrc2(c, f, pos, len, flags, NULL);
}

// flags:
//  0 = default behavior (currently: decode unless -opt extractplist was used)
void fmtutil_handle_plist(deark *c, dbuf *f, i64 pos, i64 len,
	de_finfo *fi, unsigned int flags)
{
	if(de_get_ext_option_bool(c, "extractplist", 0)) {
		dbuf_create_file_from_slice(f, pos, len,
			fi?NULL:"plist", fi, DE_CREATEFLAG_IS_AUX);
		return;
	}

	de_run_module_by_id_on_slice(c, "plist", NULL, f, pos, len);
}

// Caller allocates sdd. It does not need to be initialized.
// flags: 0x1 = Print a debug message if signature is found.
int fmtutil_detect_SAUCE(deark *c, dbuf *f, struct de_SAUCE_detection_data *sdd,
	unsigned int flags)
{
	de_zeromem(sdd, sizeof(struct de_SAUCE_detection_data));
	if(f->len<128) return 0;
	if(dbuf_memcmp(f, f->len-128, "SAUCE00", 7)) return 0;
	if(flags & 0x1) {
		de_dbg(c, "SAUCE metadata, signature at %"I64_FMT, f->len-128);
	}
	sdd->has_SAUCE = 1;
	sdd->data_type = dbuf_getbyte(f, f->len-128+94);
	sdd->file_type = dbuf_getbyte(f, f->len-128+95);
	return (int)sdd->has_SAUCE;
}

void fmtutil_handle_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si)
{
	de_module_params mparams;

	de_zeromem(&mparams, sizeof(de_module_params));
	mparams.out_params.obj1 = (void*)si;
	de_run_module_by_id_on_slice(c, "sauce", &mparams, f, 0, f->len);
}

struct de_SAUCE_info *fmtutil_create_SAUCE(deark *c)
{
	return de_malloc(c, sizeof(struct de_SAUCE_info));
}

void fmtutil_free_SAUCE(deark *c, struct de_SAUCE_info *si)
{
	if(!si) return;
	ucstring_destroy(si->title);
	ucstring_destroy(si->artist);
	ucstring_destroy(si->organization);
	ucstring_destroy(si->comment);
	de_free(c, si);
}

// Helper functions for the "boxes" (or "atoms") format used by MP4, JPEG 2000, etc.

double dbuf_fmtutil_read_fixed_16_16(dbuf *f, i64 pos)
{
	i64 n;
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

struct boxes_parser_data {
	char name_str[80];
	char uuid_string[50];
};

static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	i64 pos1, i64 len, i64 max_nboxes, int level);

// Make a printable version of a UUID (or a big-endian GUID).
// Caller supplies s.
void fmtutil_render_uuid(deark *c, const u8 *uuid, char *s, size_t s_len)
{
	de_snprintf(s, s_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

// Swap some bytes to convert a (little-endian) GUID to a UUID, in-place
void fmtutil_guid_to_uuid(u8 *id)
{
	u8 tmp[16];
	de_memcpy(tmp, id, 16);
	id[0] = tmp[3]; id[1] = tmp[2]; id[2] = tmp[1]; id[3] = tmp[0];
	id[4] = tmp[5]; id[5] = tmp[4];
	id[6] = tmp[7]; id[7] = tmp[6];
}

#define DE_BOX_uuid 0x75756964U

static int do_box(deark *c, struct de_boxesctx *bctx, i64 pos, i64 len,
	int level, i64 *pbytes_consumed)
{
	i64 size32, size64;
	i64 header_len; // Not including UUIDs
	i64 payload_len; // Including UUIDs
	i64 total_len;
	struct de_fourcc box4cc;
	int ret;
	int retval = 0;
	struct de_boxdata *parentbox;
	struct de_boxdata *curbox;
	struct boxes_parser_data *pctx = (struct boxes_parser_data*)bctx->private_data;

	parentbox = bctx->curbox;
	bctx->curbox = de_malloc(c, sizeof(struct de_boxdata));
	curbox = bctx->curbox;
	curbox->parent = parentbox;

	if(len<8) {
		de_dbg(c, "(ignoring %d extra bytes at %"I64_FMT")", (int)len, pos);
		goto done;
	}

	size32 = dbuf_getu32be(bctx->f, pos);
	dbuf_read_fourcc(bctx->f, pos+4, &box4cc, 4, 0x0);
	curbox->boxtype = box4cc.id;

	if(size32>=8) {
		header_len = 8;
		payload_len = size32-8;
	}
	else if(size32==0) {
		header_len = 8;
		payload_len = len-8;
	}
	else if(size32==1) {
		if(len<16) {
			de_dbg(c, "(ignoring %d extra bytes at %"I64_FMT")", (int)len, pos);
			goto done;
		}
		header_len = 16;
		size64 = dbuf_geti64be(bctx->f, pos+8);
		de_sanitize_length(&size64);
		if(size64<16) goto done;
		payload_len = size64-16;
	}
	else {
		de_err(c, "Invalid or unsupported box format");
		goto done;
	}

	total_len = header_len + payload_len;

	if(curbox->boxtype==DE_BOX_uuid && payload_len>=16) {
		curbox->is_uuid = 1;
		dbuf_read(bctx->f, curbox->uuid, pos+header_len, 16);
	}

	curbox->level = level;
	curbox->box_pos = pos;
	curbox->box_len = total_len;
	curbox->payload_pos = pos+header_len;
	curbox->payload_len = payload_len;
	if(curbox->is_uuid) {
		curbox->payload_pos += 16;
		curbox->payload_len -= 16;
	}

	if(bctx->identify_box_fn) {
		bctx->identify_box_fn(c, bctx);
	}

	if(c->debug_level>0) {
		if(curbox->box_name) {
			de_snprintf(pctx->name_str, sizeof(pctx->name_str), " (%s)", curbox->box_name);
		}
		else {
			pctx->name_str[0] = '\0';
		}

		if(curbox->is_uuid) {
			fmtutil_render_uuid(c, curbox->uuid, pctx->uuid_string, sizeof(pctx->uuid_string));
			de_dbg(c, "box '%s'{%s}%s at %"I64_FMT", len=%"I64_FMT,
				box4cc.id_dbgstr, pctx->uuid_string, pctx->name_str,
				pos, total_len);
		}
		else {
			de_dbg(c, "box '%s'%s at %"I64_FMT", len=%"I64_FMT", dlen=%"I64_FMT,
				box4cc.id_dbgstr, pctx->name_str, pos,
				total_len, payload_len);
		}
	}

	if(total_len > len) {
		de_err(c, "Invalid oversized box, or unexpected end of file "
			"(box at %"I64_FMT" ends at %"I64_FMT", "
			"parent ends at %"I64_FMT")",
			pos, pos+total_len, pos+len);
		goto done;
	}

	de_dbg_indent(c, 1);
	ret = bctx->handle_box_fn(c, bctx);
	de_dbg_indent(c, -1);
	if(!ret) goto done;

	if(curbox->is_superbox) {
		i64 children_pos, children_len;
		i64 max_nchildren;

		de_dbg_indent(c, 1);
		children_pos = curbox->payload_pos + curbox->extra_bytes_before_children;
		children_len = curbox->payload_len - curbox->extra_bytes_before_children;
		max_nchildren = (curbox->num_children_is_known) ? curbox->num_children : -1;
		do_box_sequence(c, bctx, children_pos, children_len, max_nchildren, level+1);
		de_dbg_indent(c, -1);
	}

	*pbytes_consumed = total_len;
	retval = 1;

done:
	de_free(c, bctx->curbox);
	bctx->curbox = parentbox; // Restore the curbox pointer
	return retval;
}

// max_nboxes: -1 = no maximum
static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	i64 pos1, i64 len, i64 max_nboxes, int level)
{
	i64 pos;
	i64 box_len;
	i64 endpos;
	int ret;
	i64 box_count = 0;

	if(level >= 32) { // An arbitrary recursion limit.
		return;
	}

	pos = pos1;
	endpos = pos1 + len;

	while(pos < endpos) {
		if(max_nboxes>=0 && box_count>=max_nboxes) break;
		ret = do_box(c, bctx, pos, endpos-pos, level, &box_len);
		if(!ret) break;
		box_count++;
		pos += box_len;
	}
}

// Handle some box types that might be common to multiple formats.
// This function should be called as needed by the client's box handler function.
// TODO: A way to identify (name) the boxes that we handle here.
int fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->is_uuid) {
		if(!de_memcmp(curbox->uuid, "\xb1\x4b\xf8\xbd\x08\x3d\x4b\x43\xa5\xae\x8c\xd7\xd5\xa6\xce\x03", 16)) {
			de_dbg(c, "GeoTIFF data at %"I64_FMT", len=%"I64_FMT, curbox->payload_pos, curbox->payload_len);
			dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len, "geo.tif", NULL, DE_CREATEFLAG_IS_AUX);
		}
		else if(!de_memcmp(curbox->uuid, "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac", 16)) {
			de_dbg(c, "XMP data at %"I64_FMT", len=%"I64_FMT, curbox->payload_pos, curbox->payload_len);
			dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
		}
		else if(!de_memcmp(curbox->uuid, "\x2c\x4c\x01\x00\x85\x04\x40\xb9\xa0\x3e\x56\x21\x48\xd6\xdf\xeb", 16)) {
			de_dbg(c, "Photoshop resources at %"I64_FMT", len=%"I64_FMT, curbox->payload_pos, curbox->payload_len);
			de_dbg_indent(c, 1);
			fmtutil_handle_photoshop_rsrc(c, bctx->f, curbox->payload_pos, curbox->payload_len, 0x0);
			de_dbg_indent(c, -1);
		}
		else if(!de_memcmp(curbox->uuid, "\x05\x37\xcd\xab\x9d\x0c\x44\x31\xa7\x2a\xfa\x56\x1f\x2a\x11\x3e", 16) ||
			!de_memcmp(curbox->uuid, "JpgTiffExif->JP2", 16))
		{
			de_dbg(c, "Exif data at %"I64_FMT", len=%"I64_FMT, curbox->payload_pos, curbox->payload_len);
			de_dbg_indent(c, 1);
			fmtutil_handle_exif(c, curbox->payload_pos, curbox->payload_len);
			de_dbg_indent(c, -1);
		}
	}
	return 1;
}

void fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx)
{
	struct boxes_parser_data *pctx = NULL;

	if(!bctx->f || !bctx->handle_box_fn) return; // Internal error
	if(bctx->curbox) return; // Internal error

	pctx = de_malloc(c, sizeof(struct boxes_parser_data));
	bctx->private_data = (void*)pctx;
	do_box_sequence(c, bctx, 0, bctx->f->len, -1, 0);
	bctx->private_data = NULL;
	de_free(c, pctx);
}

static u8 scale_7_to_255(u8 x)
{
	return (u8)(0.5+(((double)x)*(255.0/7.0)));
}

static u8 scale_15_to_255(u8 x)
{
	return x*17;
}

void fmtutil_read_atari_palette(deark *c, dbuf *f, i64 pos,
	de_color *dstpal, i64 ncolors_to_read, i64 ncolors_used, unsigned int flags)
{
	i64 i;
	unsigned int n;
	int pal_bits = 0; // 9, 12, or 15. 0 = not yet determined
	u8 cr, cg, cb;
	u8 cr1, cg1, cb1;
	char cbuf[32];
	char tmps[64];
	const char *s;

	s = de_get_ext_option(c, "atari:palbits");
	if(s) {
		pal_bits = de_atoi(s);
	}

	if(pal_bits==0 && (flags&DE_FLAG_ATARI_15BIT_PAL)) {
		pal_bits = 15;
	}

	if(pal_bits==0) {
		// Pre-scan the palette, and try to guess whether Atari STE-style 12-bit
		// colors are used, instead of the usual 9-bit colors.
		// I don't know the best way to do this. Sometimes the 4th bit in each
		// nibble is used for extra color detail, and sometimes it just seems to
		// contain garbage. Maybe the logic should also depend on the file
		// format, or the number of colors.
		int bit_3_used = 0;
		int nibble_3_used = 0;

		for(i=0; i<ncolors_to_read; i++) {
			n = (unsigned int)dbuf_getu16be(f, pos + i*2);
			if(n&0xf000) {
				nibble_3_used = 1;
			}
			if(n&0x0888) {
				bit_3_used = 1;
			}
		}

		if(bit_3_used && !nibble_3_used) {
			de_dbg(c, "12-bit palette colors detected");
			pal_bits = 12;
		}
	}

	if(pal_bits<12) { // Default to 9 if <12
		pal_bits = 9;
	}
	else if(pal_bits<15) {
		pal_bits = 12;
	}
	else {
		pal_bits = 15;
	}

	for(i=0; i<ncolors_to_read; i++) {
		n = (unsigned int)dbuf_getu16be(f, pos + 2*i);

		if(pal_bits==15) {
			cr1 = (u8)((n>>6)&0x1c);
			if(n&0x0800) cr1+=2;
			if(n&0x8000) cr1++;
			cg1 = (u8)((n>>2)&0x1c);
			if(n&0x0080) cg1+=2;
			if(n&0x4000) cg1++;
			cb1 = (u8)((n<<2)&0x1c);
			if(n&0x0008) cb1+=2;
			if(n&0x2000) cb1++;
			cr = de_scale_n_to_255(31, cr1);
			cg = de_scale_n_to_255(31, cg1);
			cb = de_scale_n_to_255(31, cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%2d,%2d,%2d",
				(int)cr1, (int)cg1, (int)cb1);
		}
		else if(pal_bits==12) {
			cr1 = (u8)((n>>7)&0x0e);
			if(n&0x800) cr1++;
			cg1 = (u8)((n>>3)&0x0e);
			if(n&0x080) cg1++;
			cb1 = (u8)((n<<1)&0x0e);
			if(n&0x008) cb1++;
			cr = scale_15_to_255(cr1);
			cg = scale_15_to_255(cg1);
			cb = scale_15_to_255(cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%2d,%2d,%2d",
				(int)cr1, (int)cg1, (int)cb1);
		}
		else {
			cr1 = (u8)((n>>8)&0x07);
			cg1 = (u8)((n>>4)&0x07);
			cb1 = (u8)(n&0x07);
			cr = scale_7_to_255(cr1);
			cg = scale_7_to_255(cg1);
			cb = scale_7_to_255(cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%d,%d,%d",
				(int)cr1, (int)cg1, (int)cb1);
		}

		dstpal[i] = DE_MAKE_RGB(cr, cg, cb);
		de_snprintf(tmps, sizeof(tmps), "0x%04x (%s) "DE_CHAR_RIGHTARROW" ", n, cbuf);
		de_dbg_pal_entry2(c, i, dstpal[i], tmps, NULL,
			(i>=ncolors_used)?" [unused]":"");
	}
}

/*
 *  Given an x-coordinate and a color index, returns the corresponding
 *  Spectrum palette index.
 *
 *  by Steve Belczyk; placed in the public domain December, 1990.
 *  [Adapted for Deark.]
 */
static unsigned int spectrum512_FindIndex(i64 x, unsigned int c)
{
	i64 x1;

	x1 = 10 * (i64)c;

	if (c & 1)  /* If c is odd */
		x1 = x1 - 5;
	else        /* If c is even */
		x1 = x1 + 1;

	if (x >= x1 && x < x1+160)
		c = c + 16;
	else if (x >= x1+160)
		c = c + 32;

	return c;
}

static int decode_atari_image_paletted(deark *c, struct atari_img_decode_data *adata)
{
	i64 i, j;
	i64 plane;
	i64 rowspan;
	u8 b;
	u32 v;
	i64 planespan;
	i64 ncolors;

	planespan = 2*((adata->w+15)/16);
	rowspan = planespan*adata->bpp;
	if(adata->ncolors>0)
		ncolors = adata->ncolors;
	else
		ncolors = ((i64)1)<<adata->bpp;

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = 0;

			for(plane=0; plane<adata->bpp; plane++) {
				if(adata->was_compressed==0) {
					// TODO: Simplify this.
					if(adata->bpp==1) {
						b = de_get_bits_symbol(adata->unc_pixels, 1, j*rowspan, i);
					}
					else if(adata->bpp==2) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i/16)*2, i);
					}
					else if(adata->bpp==4) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i/2-(i/2)%16)+8*((i%32)/16), i%16);
					}
					else if(adata->bpp==8) {
						b = de_get_bits_symbol(adata->unc_pixels, 1,
							j*rowspan + 2*plane + (i-i%16), i%16);
					}
					else {
						b = 0;
					}
				}
				else {
					b = de_get_bits_symbol(adata->unc_pixels, 1, j*rowspan + plane*planespan, i);
				}
				if(b) v |= 1<<plane;
			}

			if(adata->is_spectrum512) {
				v = spectrum512_FindIndex(i, v);
				if(j>0) {
					v += (unsigned int)(48*(j));
				}
			}
			if(v>=(unsigned int)ncolors) v=(unsigned int)(ncolors-1);

			de_bitmap_setpixel_rgb(adata->img, i, j, adata->pal[v]);
		}
	}
	return 1;
}

static int decode_atari_image_16(deark *c, struct atari_img_decode_data *adata)
{
	i64 i, j;
	i64 rowspan;
	u32 v;

	rowspan = adata->w * 2;

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = (u32)dbuf_getu16be(adata->unc_pixels, j*rowspan + 2*i);
			v = de_rgb565_to_888(v);
			de_bitmap_setpixel_rgb(adata->img, i, j,v);
		}
	}
	return 1;
}

int fmtutil_atari_decode_image(deark *c, struct atari_img_decode_data *adata)
{
	switch(adata->bpp) {
	case 16:
		return decode_atari_image_16(c, adata);
	case 8: case 4: case 2: case 1:
		return decode_atari_image_paletted(c, adata);
	}

	de_err(c, "Unsupported bits/pixel (%d)", (int)adata->bpp);
	return 0;
}

void fmtutil_atari_set_standard_density(deark *c, struct atari_img_decode_data *adata,
	de_finfo *fi)
{
	switch(adata->bpp) {
	case 4:
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 240.0;
		fi->density.ydens = 200.0;
		break;
	case 2:
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 480.0;
		fi->density.ydens = 200.0;
		break;
	case 1:
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.xdens = 480.0;
		fi->density.ydens = 400.0;
		break;
	}
}

void fmtutil_atari_help_palbits(deark *c)
{
	de_msg(c, "-opt atari:palbits=<9|12|15> : Number of significant bits "
		"per palette color");
}

const char *fmtutil_tiff_orientation_name(i64 n)
{
	static const char *names[9] = {
		"?", "top-left", "top-right", "bottom-right", "bottom-left",
		"left-top", "right-top", "right-bottom", "left-bottom"
	};
	if(n>=1 && n<=8) return names[n];
	return names[0];
}

const char *fmtutil_get_windows_charset_name(u8 cs)
{
	struct csname_struct { u8 id; const char *name; };
	static const struct csname_struct csname_arr[] = {
		{0x00, "ANSI"},
		{0x01, "default"},
		{0x02, "symbol"},
		{0x4d, "Mac"},
		{0x80, "Shift-JIS"},
		{0x81, "Hangul"},
		{0x82, "Johab"},
		{0x86, "GB2312"},
		{0x88, "BIG5"},
		{0xa1, "Greek"},
		{0xa2, "Turkish"},
		{0xa3, "Vietnamese"},
		{0xb1, "Hebrew"},
		{0xb2, "Arabic"},
		{0xba, "Baltic"},
		{0xcc, "Russian"},
		{0xde, "Thai"},
		{0xee, "Eastern Europe"},
		{0xff, "OEM"}
	};
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(csname_arr); i++) {
		if(cs==csname_arr[i].id) return csname_arr[i].name;
	}
	return "?";
}

const char *fmtutil_get_windows_cb_data_type_name(unsigned int ty)
{
	const char *name = "?";

	switch(ty) {
	case 1: name="CF_TEXT"; break;
	case 2: name="CF_BITMAP"; break;
	case 3: name="CF_METAFILEPICT"; break;
	case 6: name="CF_TIFF"; break;
	case 7: name="CF_OEMTEXT"; break;
	case 8: name="CF_DIB"; break;
	case 11: name="CF_RIFF"; break;
	case 12: name="CF_WAVE"; break;
	case 13: name="CF_UNICODETEXT"; break;
	case 14: name="CF_ENHMETAFILE"; break;
	case 17: name="CF_DIBV5"; break;
	}
	return name;
}

#define CODE_PK36 0x504b0306U // RESOF
#define CODE_PK56 0x504b0506U
#define CODE_PK67 0x504b0607U

// We're don't really want to validate the EOCD, we just want to figure out
// if this probably *is* an EOCD, and not a false positive.
// Unfortunately, this has turned out to be messy to do.
// TODO: Maybe this should accept a byte array, instead of a dbuf
// (at this time, we really need both).
static int is_sane_zip_eocd(dbuf *f, i64 pos)
{
	i64 this_disk_num;
	i64 disk_num_with_central_dir_start;
	i64 central_dir_num_entries;
	i64 central_dir_byte_size;
	i64 central_dir_offset;

	// Validating Zip64 would take more work.
	if(dbuf_getu32be(f, pos-20) == CODE_PK67) return 1;

	this_disk_num = dbuf_getu16le(f, pos+4);
	disk_num_with_central_dir_start = dbuf_getu16le(f, pos+6);

	if(this_disk_num > 100) return 0;
	if(disk_num_with_central_dir_start > this_disk_num) return 0;
	if(disk_num_with_central_dir_start < this_disk_num-1) return 0;

	central_dir_num_entries = dbuf_getu16le(f, pos+10);
	central_dir_byte_size = dbuf_getu32le(f, pos+12);

	if(central_dir_byte_size < 46*central_dir_num_entries) return 0;

	if(this_disk_num==disk_num_with_central_dir_start) {
		if(central_dir_byte_size > f->len) return 0;
		central_dir_offset = dbuf_getu32le(f, pos+16);
		if(central_dir_offset > f->len) return 0;
	}

	return 1;
}

// Search for the ZIP "end of central directory" object.
// Also useful for detecting hybrid ZIP files, such as self-extracting EXE.
// flags:
//   0x1 - Only do minimal "fast" tests
int fmtutil_find_zip_eocd(deark *c, dbuf *f, UI flags, i64 *foundpos)
{
	u32 bof_sig;
	u32 sig;
	int skip_sanity_check = 0;
	u8 *buf = NULL;
	int retval = 0;
	i64 buf_offset;
	i64 buf_size;
	i64 pos;
	i64 i;

	*foundpos = 0;
	if(f->len < 22) goto done;

	bof_sig = (u32)dbuf_getu32be(f, 0);
	if(bof_sig==CODE_PK36) {
		skip_sanity_check = 1;
	}

	// End-of-central-dir record usually starts 22 bytes from EOF. Try that first.
	pos = f->len - 22;
	sig = (u32)dbuf_getu32be(f, pos);
	if(sig==CODE_PK56 && (skip_sanity_check || is_sane_zip_eocd(f, pos))) {
		*foundpos = pos;
		retval = 1;
		goto done;
	}

	if(flags & 0x1) goto done;

	// Search for the signature.
	// The end-of-central-directory record could theoretically appear anywhere
	// in the file. We'll follow Info-Zip/UnZip's lead and search the last 66000
	// bytes.
#define MAX_ZIP_EOCD_SEARCH 66000
	buf_size = f->len;
	if(buf_size > MAX_ZIP_EOCD_SEARCH) buf_size = MAX_ZIP_EOCD_SEARCH;

	buf = de_malloc(c, buf_size);
	buf_offset = f->len - buf_size;
	dbuf_read(f, buf, buf_offset, buf_size);

	for(i=buf_size-22; i>=0; i--) {
		if(buf[i]=='P' && buf[i+1]=='K' && buf[i+2]==5 && buf[i+3]==6 &&
			(skip_sanity_check || is_sane_zip_eocd(f, buf_offset+i)))
		{
			*foundpos = buf_offset + i;
			retval = 1;
			goto done;
		}
	}

done:
	de_free(c, buf);
	return retval;
}

// Quick & dirty encoder that can wrap some formats in a TIFF container.
static void wrap_in_tiff(deark *c, dbuf *f, i64 dpos, i64 dlen,
	const char *swstring, unsigned int tag, const char *ext, unsigned int createflags)
{
	dbuf *outf = NULL;
	i64 ifdoffs;
	i64 sw_len, sw_len_padded;
	i64 data_len_padded;

	sw_len = 1+(i64)de_strlen(swstring);
	if(sw_len<=4) return;
	sw_len_padded = de_pad_to_2(sw_len);

	if(dlen>4) {
		data_len_padded = de_pad_to_2(dlen);
	}
	else {
		data_len_padded = 0;
	}

	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_write(outf, (const u8*)"\x4d\x4d\x00\x2a", 4);
	ifdoffs = 8 + sw_len_padded + data_len_padded;
	dbuf_writeu32be(outf, ifdoffs);
	dbuf_write(outf, (const u8*)swstring, sw_len);
	if(sw_len%2) dbuf_writebyte(outf, 0);
	if(dlen>4) {
		dbuf_copy(f, dpos, dlen, outf);
		if(dlen%2) dbuf_writebyte(outf, 0);
	}

	dbuf_writeu16be(outf, 2); // number of dir entries;

	dbuf_writeu16be(outf, 305); // Software tag
	dbuf_writeu16be(outf, 2); // type=ASCII
	dbuf_writeu32be(outf, sw_len);
	dbuf_writeu32be(outf, 8); // offset

	dbuf_writeu16be(outf, (i64)tag);
	dbuf_writeu16be(outf, 1);
	dbuf_writeu32be(outf, dlen);
	if(dlen>4) {
		dbuf_writeu32be(outf, 8+sw_len_padded);
	}
	else {
		dbuf_copy(f, dpos, dlen, outf);
		dbuf_write_zeroes(outf, 4-dlen);
	}

	dbuf_writeu32be(outf, 0); // end of IFD
	dbuf_close(outf);
}

// Find ID3 tag data at the beginning and end of file, process it, and return
// information about its location.
// Caller allocates id3i.
void fmtutil_handle_id3(deark *c, dbuf *f, struct de_id3info *id3i,
	unsigned int flags)
{
	i64 id3v1pos = 0;
	int look_for_id3v1;

	de_zeromem(id3i, sizeof(struct de_id3info));
	id3i->main_start = 0;
	id3i->main_end = f->len;

	id3i->has_id3v2 = !dbuf_memcmp(f, 0, "ID3", 3);
	if(id3i->has_id3v2) {
		de_module_params id3v2mparams;

		de_dbg(c, "ID3v2 data at %d", 0);
		de_dbg_indent(c, 1);
		de_zeromem(&id3v2mparams, sizeof(de_module_params));
		id3v2mparams.in_params.codes = "I";
		de_run_module_by_id_on_slice(c, "id3", &id3v2mparams, f, 0, f->len);
		de_dbg_indent(c, -1);
		id3i->main_start += id3v2mparams.out_params.int64_1;
	}

	look_for_id3v1 = 1;
	if(look_for_id3v1) {
		id3v1pos = f->len-128;
		if(!dbuf_memcmp(f, id3v1pos, "TAG", 3)) {
			id3i->has_id3v1 = 1;
		}
	}

	if(id3i->has_id3v1) {
		de_module_params id3v1mparams;

		de_dbg(c, "ID3v1 data at %"I64_FMT, id3v1pos);
		de_dbg_indent(c, 1);
		de_zeromem(&id3v1mparams, sizeof(de_module_params));
		id3v1mparams.in_params.codes = "1";
		de_run_module_by_id_on_slice(c, "id3", &id3v1mparams, f, id3v1pos, 128);
		de_dbg_indent(c, -1);
		id3i->main_end = id3v1pos;
	}
}

static void dbg_timestamp(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

void fmtutil_riscos_read_load_exec(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa, i64 pos1)
{
	i64 pos = pos1;

	rfa->load_addr = (u32)dbuf_getu32le_p(f, &pos);
	rfa->exec_addr = (u32)dbuf_getu32le_p(f, &pos);
	de_dbg(c, "load/exec addrs: 0x%08x, 0x%08x", (unsigned int)rfa->load_addr,
		(unsigned int)rfa->exec_addr);
	de_dbg_indent(c, 1);
	if((rfa->load_addr&0xfff00000U)==0xfff00000U) {
		rfa->file_type = (unsigned int)((rfa->load_addr&0xfff00)>>8);
		rfa->file_type_known = 1;
		de_dbg(c, "file type: %03X", rfa->file_type);

		de_riscos_loadexec_to_timestamp(rfa->load_addr, rfa->exec_addr, &rfa->mod_time);
		dbg_timestamp(c, &rfa->mod_time, "timestamp");
	}
	de_dbg_indent(c, -1);
}

void fmtutil_riscos_read_attribs_field(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa,
	i64 pos, unsigned int flags)
{
	rfa->attribs = (u32)dbuf_getu32le(f, pos);
	de_dbg(c, "attribs: 0x%08x", (unsigned int)rfa->attribs);
	de_dbg_indent(c, 1);
	rfa->crc_from_attribs = rfa->attribs>>16;
	if(flags & DE_RISCOS_FLAG_HAS_CRC) {
		de_dbg(c, "crc (reported): 0x%04x", (unsigned int)rfa->crc_from_attribs);
	}
	if(flags & DE_RISCOS_FLAG_HAS_LZWMAXBITS) {
		rfa->lzwmaxbits = (unsigned int)((rfa->attribs&0xff00)>>8);
		de_dbg(c, "lzw maxbits: %u", rfa->lzwmaxbits);
	}
	de_dbg_indent(c, -1);
}

// This function probably shouldn't exist, as this could be done automatically
// when an output file is created. But our file naming logic makes it too
// difficult to do that without major changes.
//
// The 'fi' param is used only as a place to record whether we appended the type.
void fmtutil_riscos_append_type_to_filename(deark *c, de_finfo *fi, de_ucstring *fn,
	struct de_riscos_file_attrs *rfa, int is_dir, int enabled_by_default)
{
	if(is_dir || !rfa->file_type_known) return;
	if(ucstring_isempty(fn)) return;

	// 0xff = Haven't looked for this opt
	// 0xfe = We looked, it's not there
	// 0 = Requested to be off
	// 1 = Requested to be on
	if(c->append_riscos_type==0xff) {
		c->append_riscos_type = (u8)de_get_ext_option_bool(c, "riscos:appendtype", 0xfe);
	}
	if(c->append_riscos_type==0) return;
	if(c->append_riscos_type==0xfe) {
		if(!enabled_by_default) return;
		if(!c->filenames_from_file) return;

		// By default, with ZIP output, we'll use extended fields instead of
		// mangling the filename.
		if(c->output_style==DE_OUTPUTSTYLE_ARCHIVE && c->archive_fmt==DE_ARCHIVEFMT_ZIP)
			return;
	}

	ucstring_printf(fn, DE_ENCODING_LATIN1, ",%03X", rfa->file_type);
	fi->riscos_appended_type = 1;
}

struct pict_rect {
	i64 t, l, b, r;
};

// Note: Code duplicated in pict.c
static double pict_read_fixed(dbuf *f, i64 pos)
{
	i64 n;

	// I think QuickDraw's "Fixed point" numbers are signed, but I don't know
	// how negative numbers are handled.
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

// Read a QuickDraw Rectangle. Caller supplies rect struct.
// Note: Code duplicated in pict.c
static void pict_read_rect(dbuf *f, i64 pos,
	struct pict_rect *rect, const char *dbgname)
{
	rect->t = dbuf_geti16be(f, pos);
	rect->l = dbuf_geti16be(f, pos+2);
	rect->b = dbuf_geti16be(f, pos+4);
	rect->r = dbuf_geti16be(f, pos+6);

	if(dbgname) {
		de_dbg(f->c, "%s: (%d,%d)-(%d,%d)", dbgname, (int)rect->l, (int)rect->t,
			(int)rect->r, (int)rect->b);
	}
}

// Sometimes-present baseAddr field (4 bytes)
void fmtutil_macbitmap_read_baseaddr(deark *c, dbuf *f, struct fmtutil_macbitmap_info *bi, i64 pos)
{
	i64 n;
	de_dbg(c, "baseAddr part of PixMap, at %d", (int)pos);
	de_dbg_indent(c, 1);
	n = dbuf_getu32be(f, pos);
	de_dbg(c, "baseAddr: 0x%08x", (unsigned int)n);
	de_dbg_indent(c, -1);
}

void fmtutil_macbitmap_read_rowbytes_and_bounds(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos)
{
	struct pict_rect tmprect;
	i64 rowbytes_code;

	de_dbg(c, "rowBytes/bounds part of bitmap/PixMap header, at %d", (int)pos);
	de_dbg_indent(c, 1);
	rowbytes_code = dbuf_getu16be(f, pos);
	bi->rowbytes = rowbytes_code & 0x7fff;
	bi->pixmap_flag = (rowbytes_code & 0x8000)?1:0;
	de_dbg(c, "rowBytes: %d", (int)bi->rowbytes);
	de_dbg(c, "pixmap flag: %d", bi->pixmap_flag);

	pict_read_rect(f, pos+2, &tmprect, "rect");
	bi->npwidth = tmprect.r - tmprect.l;
	bi->pdwidth = bi->npwidth; // default
	bi->height = tmprect.b - tmprect.t;

	de_dbg_indent(c, -1);
}

// Pixmap fields that aren't read by read_baseaddr or read_rowbytes_and_bounds
// (36 bytes)
void fmtutil_macbitmap_read_pixmap_only_fields(deark *c, dbuf *f, struct fmtutil_macbitmap_info *bi,
	i64 pos)
{
	i64 pixmap_version;
	i64 pack_size;
	i64 plane_bytes;
	i64 n;

	de_dbg(c, "additional PixMap header fields, at %d", (int)pos);
	de_dbg_indent(c, 1);

	pixmap_version = dbuf_getu16be(f, pos+0);
	de_dbg(c, "pixmap version: %d", (int)pixmap_version);

	bi->packing_type = dbuf_getu16be(f, pos+2);
	de_dbg(c, "packing type: %d", (int)bi->packing_type);

	pack_size = dbuf_getu32be(f, pos+4);
	de_dbg(c, "pixel data length: %d", (int)pack_size);

	bi->hdpi = pict_read_fixed(f, pos+8);
	bi->vdpi = pict_read_fixed(f, pos+12);
	de_dbg(c, "dpi: %.2f"DE_CHAR_TIMES"%.2f", bi->hdpi, bi->vdpi);

	bi->pixeltype = dbuf_getu16be(f, pos+16);
	bi->pixelsize = dbuf_getu16be(f, pos+18);
	bi->cmpcount = dbuf_getu16be(f, pos+20);
	bi->cmpsize = dbuf_getu16be(f, pos+22);
	de_dbg(c, "pixel type=%d, bits/pixel=%d, components/pixel=%d, bits/comp=%d",
		(int)bi->pixeltype, (int)bi->pixelsize, (int)bi->cmpcount, (int)bi->cmpsize);

	if(bi->pixelsize>0) {
		bi->pdwidth = (bi->rowbytes*8)/bi->pixelsize;
	}
	if(bi->pdwidth < bi->npwidth) {
		bi->pdwidth = bi->npwidth;
	}

	plane_bytes = dbuf_getu32be(f, pos+24);
	de_dbg(c, "plane bytes: %d", (int)plane_bytes);

	bi->pmTable = (u32)dbuf_getu32be(f, pos+28);
	de_dbg(c, "pmTable: 0x%08x", (unsigned int)bi->pmTable);

	n = dbuf_getu32be(f, pos+32);
	de_dbg(c, "pmReserved: 0x%08x", (unsigned int)n);

	de_dbg_indent(c, -1);
}

int fmtutil_macbitmap_read_colortable(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos, i64 *bytes_used)
{
	i64 ct_id;
	u32 ct_flags;
	i64 ct_size;
	i64 k, z;
	u32 s[4];
	u8 cr, cg, cb;
	u32 clr;
	char tmps[64];

	*bytes_used = 0;
	de_dbg(c, "color table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	ct_id = dbuf_getu32be(f, pos);
	ct_flags = (u32)dbuf_getu16be(f, pos+4); // a.k.a. transIndex
	ct_size = dbuf_getu16be(f, pos+6);
	bi->num_pal_entries = ct_size+1;
	de_dbg(c, "color table id=0x%08x, flags=0x%04x, colors=%d", (unsigned int)ct_id,
		(unsigned int)ct_flags, (int)bi->num_pal_entries);

	for(k=0; k<bi->num_pal_entries; k++) {
		for(z=0; z<4; z++) {
			s[z] = (u32)dbuf_getu16be(f, pos+8+8*k+2*z);
		}
		cr = (u8)(s[1]>>8);
		cg = (u8)(s[2]>>8);
		cb = (u8)(s[3]>>8);
		clr = DE_MAKE_RGB(cr,cg,cb);
		de_snprintf(tmps, sizeof(tmps), "(%5d,%5d,%5d,idx=%3d) "DE_CHAR_RIGHTARROW" ",
			(int)s[1], (int)s[2], (int)s[3], (int)s[0]);
		de_dbg_pal_entry2(c, k, clr, tmps, NULL, NULL);

		// Some files don't have the palette indices set. Most PICT decoders ignore
		// the indices if the "device" flag of ct_flags is set, and that seems to
		// work (though it's not clearly documented).
		if(ct_flags & 0x8000U) {
			s[0] = (u32)k;
		}

		if(s[0]<=255) {
			bi->pal[s[0]] = clr;
		}
	}

	de_dbg_indent(c, -1);
	*bytes_used = 8 + 8*bi->num_pal_entries;
	return 1;
}

// "compressed unsigned short" - a variable-length integer format
// TODO: This is duplicated in shg.c
i64 fmtutil_hlp_get_cus_p(dbuf *f, i64 *ppos)
{
	i64 x1, x2;

	x1 = (i64)dbuf_getbyte_p(f, ppos);
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 128 times the value of
	// the next byte.
	x2 = (i64)dbuf_getbyte_p(f, ppos);
	return (x1>>1) | (x2<<7);
}

// "compressed signed short"
i64 fmtutil_hlp_get_css_p(dbuf *f, i64 *ppos)
{
	i64 x1, x2;

	x1 = (i64)dbuf_getbyte_p(f, ppos);
	if(x1%2 == 0) {
		// If it's even, divide by two, and subtract 64
		return (x1>>1) - 64;
	}
	// If it's odd, divide by two, add 128 times the value of
	// the next byte, and subtract 16384.
	x1 >>= 1;
	x2 = (i64)dbuf_getbyte_p(f, ppos);
	x1 += x2 * 128;
	x1 -= 16384;
	return x1;
}

// "compressed unsigned long"
i64 fmtutil_hlp_get_cul_p(dbuf *f, i64 *ppos)
{
	i64 x1, x2;
	x1 = dbuf_getu16le_p(f, ppos);
	if(x1%2 == 0) {
		// If it's even, divide by two.
		return x1>>1;
	}
	// If it's odd, divide by two, and add 32768 times the value of
	// the next two bytes.
	x2 = dbuf_getu16le_p(f, ppos);
	return (x1>>1) | (x2<<15);
}

// "compressed signed long"
i64 fmtutil_hlp_get_csl_p(dbuf *f, i64 *ppos)
{
	i64 x1, x2;

	x1 = dbuf_getu16le_p(f, ppos);

	if(x1%2 == 0) {
		// If it's even, divide by two, and subtract 16384
		return (x1>>1) - 16384;
	}
	// If it's odd, divide by two, add 32768 times the value of
	// the next two bytes, and subtract 67108864.
	x1 >>= 1;
	x2 = dbuf_getu16le_p(f, ppos);
	x1 += x2*32768;
	x1 -= 67108864;
	return x1;
}

#define ARJ_MIN_BASIC_HEADER_SIZE 30
#define ARJ_MAX_BASIC_HEADER_SIZE 2600 // From the ARJ TECHNOTE file
#define ARJ_MIN_FILE_SIZE 84

// Caller supplies an initialized crcobj to use.
static int is_arj_data_at1(dbuf *f, i64 pos1, struct de_crcobj *crco)
{
	i64 basic_hdr_size;
	int retval = 0;
	u32 crc_calc, crc_reported;

	basic_hdr_size = dbuf_getu16le(f, pos1+2);
	if(basic_hdr_size>ARJ_MAX_BASIC_HEADER_SIZE || basic_hdr_size<ARJ_MIN_BASIC_HEADER_SIZE) goto done;
	if(dbuf_getbyte(f, pos1+10) != 2) goto done; // "file type"
	de_crcobj_addslice(crco, f, pos1+4, basic_hdr_size);
	crc_calc = de_crcobj_getval(crco);
	crc_reported = (u32)dbuf_getu32le(f, pos1+4+basic_hdr_size);
	if(crc_calc!=crc_reported) goto done;
	retval = 1;

done:
	return retval;
}

// This is a strict ARJ search, which checks the CRC.
// It may not always be appropriate.
int fmtutil_scan_for_arj_data(dbuf *f, i64 startpos, i64 max_skip,
	UI flags, i64 *pfoundpos)
{
	struct de_crcobj *crco = NULL;
	i64 curpos, endpos;
	int retval = 0;

	curpos = startpos;
	endpos = startpos + max_skip + 2; // Search space includes the 2-byte signature
	if(endpos-2 > f->len-ARJ_MIN_FILE_SIZE) endpos = (f->len-ARJ_MIN_FILE_SIZE)+2;

	while(curpos<=(endpos-2)) {
		int ret;

		ret = dbuf_search(f, (const u8*)"\x60\xea", 2, curpos, endpos-curpos,
			pfoundpos);
		if(!ret) goto done;

		if(crco) {
			de_crcobj_reset(crco);
		}
		else {
			crco = de_crcobj_create(f->c, DE_CRCOBJ_CRC32_IEEE);
		}
		if(is_arj_data_at1(f, *pfoundpos, crco)) {
			retval = 1;
			goto done;
		}
		curpos = *pfoundpos+2; // Continue the search here
	}

done:
	de_crcobj_destroy(crco);
	return retval;
}

static const u8 example_dqt_data0[] = {
	0x10,0x0b,0x0c,0x0e,0x0c,0x0a,0x10,0x0e,
	0x0d,0x0e,0x12,0x11,0x10,0x13,0x18,0x28,
	0x1a,0x18,0x16,0x16,0x18,0x31,0x23,0x25,
	0x1d,0x28,0x3a,0x33,0x3d,0x3c,0x39,0x33,
	0x38,0x37,0x40,0x48,0x5c,0x4e,0x40,0x44,
	0x57,0x45,0x37,0x38,0x50,0x6d,0x51,0x57,
	0x5f,0x62,0x67,0x68,0x67,0x3e,0x4d,0x71,
	0x79,0x70,0x64,0x78,0x5c,0x65,0x67,0x63
};

static const u8 example_dqt_data1[] = {
	0x11,0x12,0x12,0x18,0x15,0x18,0x2f,0x1a,
	0x1a,0x2f,0x63,0x42,0x38,0x42,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,
	0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63
};

static const u8 jpegtbl_dht0[] = {
	// counts:
	0x00,0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	// 12 data bytes:
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
};

static const u8 jpegtbl_dht1[] = {
	// counts:
	0x00,0x02,0x01,0x03,0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7d,
	// 162 data bytes:
	0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,
	0x22,0x71,0x14,0x32,0x81,0x91,0xa1,0x08,0x23,0x42,0xb1,0xc1,0x15,0x52,0xd1,0xf0,
	0x24,0x33,0x62,0x72,0x82,0x09,0x0a,0x16,0x17,0x18,0x19,0x1a,0x25,0x26,0x27,0x28,
	0x29,0x2a,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
	0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
	0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x83,0x84,0x85,0x86,0x87,0x88,0x89,
	0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
	0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,0xc4,0xc5,
	0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xe1,0xe2,
	0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
	0xf9,0xfa
};

static const u8 jpegtbl_dht2[] = {
	// counts:
	0x00,0x03,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,
	// 12 data bytes:
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
};

static const u8 jpegtbl_dht3[] = {
	// counts:
	0x00,0x02,0x01,0x02,0x04,0x04,0x03,0x04,0x07,0x05,0x04,0x04,0x00,0x01,0x02,0x77,
	// 162 data bytes:
	0x00,0x01,0x02,0x03,0x11,0x04,0x05,0x21,0x31,0x06,0x12,0x41,0x51,0x07,0x61,0x71,
	0x13,0x22,0x32,0x81,0x08,0x14,0x42,0x91,0xa1,0xb1,0xc1,0x09,0x23,0x33,0x52,0xf0,
	0x15,0x62,0x72,0xd1,0x0a,0x16,0x24,0x34,0xe1,0x25,0xf1,0x17,0x18,0x19,0x1a,0x26,
	0x27,0x28,0x29,0x2a,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,0x48,
	0x49,0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,0x68,
	0x69,0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x82,0x83,0x84,0x85,0x86,0x87,
	0x88,0x89,0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,
	0xa6,0xa7,0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,
	0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,
	0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
	0xf9,0xfa
};

void fmtutil_get_std_jpeg_qtable(UI tbl_id, u8 tbl[64])
{
	const u8 *src_tbl;

	switch(tbl_id) {
	case 0:
		src_tbl = example_dqt_data0;
		break;
	case 1:
		src_tbl = example_dqt_data1;
		break;
	default:
		de_zeromem(tbl, 64);
		return;
	}
	de_memcpy(tbl, src_tbl, 64);
}

void fmtutil_write_std_jpeg_dht(dbuf *outf, UI tbl_id)
{
	const u8 *tbl_data;
	UI tbl_len;

	switch(tbl_id) {
	case 0:
		tbl_data = jpegtbl_dht0;
		tbl_len = 16+12;
		break;
	case 1:
		tbl_data = jpegtbl_dht1;
		tbl_len = 16+162;
		break;
	case 2:
		tbl_data = jpegtbl_dht2;
		tbl_len = 16+12;
		break;
	case 3:
		tbl_data = jpegtbl_dht3;
		tbl_len = 16+162;
		break;
	default:
		return;
	}

	dbuf_write(outf, tbl_data, tbl_len);
}

// A simplified character graphics (or screen dump) API that should suffice for most
// single-image PC formats.
// Caller must create/free charctx (de_create_charctx/de_free_charctx)
// and csctx (de_malloc).
// Caller must set some fields in csctx, and optionally may set some fields
// in charctx.
void fmtutil_char_simple_run(deark *c, struct fmtutil_char_simplectx *csctx,
	struct de_char_context *charctx)
{
	i64 i, j;
	i64 inf_endpos;
	i64 fg_stride;
	i64 attr_offset;
	u8 ccode, acode;
	u8 fgcol, bgcol;
	struct de_char_screen *screen;
	de_encoding encoding;
	struct de_encconv_state es;

	inf_endpos = csctx->inf_pos + csctx->inf_len;
	if(csctx->use_default_pal) {
		de_copy_std_palette(DE_PALID_PC16, 0, 0, charctx->pal, 16, 0);
	}
	charctx->nscreens = 1;
	charctx->screens = de_mallocarray(c, charctx->nscreens, sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];
	screen->width = csctx->width_in_chars;
	screen->height = csctx->height_in_chars;
	screen->cell_rows = de_mallocarray(c, csctx->height_in_chars, sizeof(struct de_char_cell*));

	if(csctx->input_encoding==DE_ENCODING_UNKNOWN) {
		encoding = DE_ENCODING_CP437;
	}
	else {
		encoding = csctx->input_encoding;
	}
	de_encconv_init(&es, DE_EXTENC_MAKE(encoding, DE_ENCSUBTYPE_PRINTABLE));

	if(csctx->fg_stride) {
		fg_stride = csctx->fg_stride;
		attr_offset = csctx->attr_offset;
	}
	else {
		fg_stride = 2;
		attr_offset = 1;
	}

	for(j=0; j<csctx->height_in_chars; j++) {
		screen->cell_rows[j] = de_mallocarray(c, csctx->width_in_chars, sizeof(struct de_char_cell));

		for(i=0; i<csctx->width_in_chars; i++) {
			i64 pos;

			pos = csctx->inf_pos + j*csctx->width_in_chars*fg_stride + i*fg_stride;
			if(pos < inf_endpos)
				ccode = dbuf_getbyte(csctx->inf, pos);
			else
				ccode = 0;
			if(pos < inf_endpos)
				acode = dbuf_getbyte(csctx->inf, pos+attr_offset);
			else
				acode = 0;

			if((acode&0x80) && !csctx->nonblink) {
				screen->cell_rows[j][i].blink = 1;
				acode -= 0x80;
			}

			fgcol = (acode & 0x0f);
			bgcol = (acode & 0xf0) >> 4;

			screen->cell_rows[j][i].fgcol = (u32)fgcol;
			screen->cell_rows[j][i].bgcol = (u32)bgcol;
			screen->cell_rows[j][i].codepoint = (i32)ccode;
			screen->cell_rows[j][i].codepoint_unicode = de_char_to_unicode_ex((i32)ccode, &es);
		}
	}

	de_char_output_to_file(c, charctx);
}

// **************************************************************************

static int fmtid_is_dll(deark *c, struct fmtutil_fmtid_ctx *idctx)
{
	int retval = 0;
	dbuf *tmpf = NULL;
	struct fmtutil_exe_info *ei = NULL;

	if(!idctx->inf) goto done;
	if(de_getu32le_direct(&idctx->bof64bytes[60]) == 0) goto done;

	tmpf = dbuf_open_input_subfile(idctx->inf, idctx->inf_pos, idctx->inf_len);
	ei = de_malloc(c, sizeof(struct fmtutil_exe_info));
	fmtutil_collect_exe_info(c, tmpf, ei);
	if(ei->is_dll) {
		retval = 1;
	}

done:
	de_free(c, ei);
	dbuf_close(tmpf);
	return retval;
}

// Caller allocs idctx, and sets some fields.
// [Do not use the same idctx more than once, without clearing it.]
// Return value is ->fmtid and ->ext_sz.
void fmtutil_fmtid(deark *c, struct fmtutil_fmtid_ctx *idctx)
{
	const char *ext = NULL;
	UI m0;
	u8 img_only = 0;

	if(!idctx->have_bof64bytes) {
		if(idctx->inf) {
			dbuf_read(idctx->inf, idctx->bof64bytes, idctx->inf_pos,
				de_min_int(64, idctx->inf_len));
			idctx->have_bof64bytes = 1;
		}
	}

	if(!idctx->have_bof64bytes) {
		goto done;
	}

	if(idctx->mode==FMTUTIL_FMTIDMODE_ALL_IMG) {
		img_only = 1;
	}

	m0 = (UI)de_getu32be_direct(&idctx->bof64bytes[0]);

#define MAGIC_PK34     0x504b0304U
#define MAGIC_JPEG     0xffd8ff00U
#define MAGIC_PNG      0x89504e47U
#define MAGIC_BMP      0x424d0000U
#define MAGIC_GIF      0x47494638U
#define MAGIC_MZ       0x4d5a0000U
#define MAGIC_ISH_Z    0x135d658cU
#define MAGIC_ISH_IA   0x2aab79d8U
#define MAGIC_ISH_INS1 0xffff0c00U
#define MAGIC_ISH_INS2 0xb8c90c00U
#define MAGIC_ISH_INI1 0x5b537461U
#define MAGIC_ISH_PKG  0x4aa30000U
#define MAGIC_TIFF1    0x49492a00U
#define MAGIC_TIFF2    0x4d4d002aU
#define MAGIC_8BPS     0x38425053U
#define MAGIC_PDF      0x25504446U

	if((m0&0xffffff00)==MAGIC_JPEG) {
		idctx->fmtid = FMTUTIL_FMTID_JPEG;
		ext = "jpg";
		goto done;
	}

	if(m0==MAGIC_PNG) {
		idctx->fmtid = FMTUTIL_FMTID_PNG;
		ext = "png";
		goto done;
	}

	if(m0==MAGIC_GIF) {
		idctx->fmtid = FMTUTIL_FMTID_GIF;
		ext = "gif";
		goto done;
	}

	if(m0==MAGIC_TIFF1 || m0==MAGIC_TIFF2) {
		idctx->fmtid = FMTUTIL_FMTID_TIFF;
		ext = "tif";
		goto done;
	}

	if(m0==MAGIC_8BPS) {
		if(idctx->bof64bytes[5]==0x01) {
			ext = "psd";
			goto done;
		}
		if(idctx->bof64bytes[5]==0x02) {
			ext = "psb";
			goto done;
		}
	}

	if(!img_only && m0==MAGIC_PK34) {
		idctx->fmtid = FMTUTIL_FMTID_ZIP;
		ext = "zip";
		goto done;
	}

	if(!img_only && m0==MAGIC_PDF) {
		ext = "pdf";
		goto done;
	}

	if((m0&0xffff0000U)==MAGIC_BMP && idctx->bof64bytes[15]==0) {
		idctx->fmtid = FMTUTIL_FMTID_BMP;
		ext = "bmp";
		goto done;
	}

	if(!img_only && (m0&0xffff0000U)==MAGIC_MZ) {
		if(fmtid_is_dll(c, idctx)) {
			ext = "dll";
		}
		else {
			ext = "exe";
		}
		goto done;
	}

	if(!img_only && m0==MAGIC_ISH_Z) {
		ext = "z";
		goto done;
	}

	if(!img_only && m0==MAGIC_ISH_IA) {
		ext = "ex_";
		goto done;
	}

	if(idctx->mode==FMTUTIL_FMTIDMODE_ISH_SFX) {
		if(m0==MAGIC_ISH_INS1 || m0==MAGIC_ISH_INS2) {
			ext = "ins";
			goto done;
		}
		if((m0&0xffff0000)==MAGIC_ISH_PKG) {
			ext = "pkg";
			goto done;
		}
		if(m0==MAGIC_ISH_INI1) {
			ext = "ini";
			goto done;
		}
	}

done:
	if(ext && (idctx->fmtid==0)) {
		idctx->fmtid = FMTUTIL_FMTID_OTHER;
	}

	if(!ext) {
		ext = idctx->default_ext;
	}
	if(!ext) {
		ext = "bin";
	}
	de_strlcpy(idctx->ext_sz, ext, sizeof(idctx->ext_sz));
}
