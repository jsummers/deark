// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This file is for format-specific functions that are used by multiple modules.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
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

	if(!de_good_image_dimensions(c, bi->width, bi->height)) {
		return 0;
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
	de_msg(c, "-opt atari:palbits=<9|12|15> : Numer of significant bits "
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

// Search for the ZIP "end of central directory" object.
// Also useful for detecting hybrid ZIP files, such as self-extracting EXE.
int fmtutil_find_zip_eocd(deark *c, dbuf *f, i64 *foundpos)
{
	u32 sig;
	u8 *buf = NULL;
	int retval = 0;
	i64 buf_offset;
	i64 buf_size;
	i64 i;

	*foundpos = 0;
	if(f->len < 22) goto done;

	// End-of-central-dir record usually starts 22 bytes from EOF. Try that first.
	sig = (u32)dbuf_getu32le(f, f->len - 22);
	if(sig == 0x06054b50U) {
		*foundpos = f->len - 22;
		retval = 1;
		goto done;
	}

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
		if(buf[i]=='P' && buf[i+1]=='K' && buf[i+2]==5 && buf[i+3]==6) {
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

struct execomp_ctx {
	u8 devmode;
	char shortname[40];
	char verstr[40];
};

static void calc_entrypoint_crc(deark *c, struct execomp_ctx *ectx, struct fmtutil_exe_info *ei)
{
	struct de_crcobj *crco = NULL;
	u32 crc1, crc2;

	if(ei->entrypoint_crcs!=0) return;

	// Sniff some bytes, starting at the code entry point.
	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(crco, ei->f, ei->entry_point, 32);
	crc1 = de_crcobj_getval(crco);
	de_crcobj_reset(crco);
	de_crcobj_addslice(crco, ei->f, ei->entry_point+32, 32);
	crc2 = de_crcobj_getval(crco);
	ei->entrypoint_crcs = ((u64)crc1 << 32) | crc2;
	if(ectx->devmode) {
		de_dbg(c, "execomp crc: %016"U64_FMTx, ei->entrypoint_crcs);
	}

	de_crcobj_destroy(crco);
}

static void detect_execomp_pklite(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int has_sig = 0;
	UI maj_ver = 0;
	UI min_ver = 0;
	u8 is_beta = 0;
	u8 flag_e = 0;
	u8 flag_large = 0;
	u8 sb[8];

	if(ei->num_relocs > 1) return;
	dbuf_read(ei->f, sb, 28, sizeof(sb));

	// This is equivalent to what CHK4LITE does. Only the P must be capitalized.
	if((sb[2]=='P') && (sb[3]=='K' || sb[3]=='k') &&
		(sb[4]=='L' || sb[4]=='l') && (sb[5]=='I' || sb[5]=='i'))
	{
		has_sig = 1;
	}

	if(has_sig) {
		maj_ver = sb[1] & 0x0f;
		min_ver = sb[0];
		if(min_ver>99 || maj_ver<1 || maj_ver>2) {
			has_sig = 0;
		}
	}

	if(has_sig) {
		if(sb[1] & 0x10) flag_e = 1;
		if(sb[1] & 0x20) flag_large = 1;
	}

	if(has_sig && ei->num_relocs==0 && maj_ver==1 && min_ver==0) {
		edd->detected_fmt = DE_SPECIALEXEFMT_PKLITE;
		is_beta = 1;
		goto done;
	}

	if(ei->regIP != 256) goto done;
	if(ei->regCS != -16) goto done;

	if(!has_sig) { // If signature is present, that's good enough. Otherwise...
		u8 cb[8];

		// TODO: Find a stricter way to do fingerprinting

		dbuf_read(ei->f, cb, ei->entry_point, sizeof(cb));
		if(cb[0]==0xb8 && cb[3]==0xba) {
			;
		}
		else if(cb[0]==0x50 && cb[1]==0xb8 && cb[4]==0xba) {
			; // v2.01
		}
		else {
			goto done;
		}
	}

	edd->detected_fmt = DE_SPECIALEXEFMT_PKLITE;

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_PKLITE) {
		de_strlcpy(ectx->shortname, "PKLITE", sizeof(ectx->shortname));
		if(has_sig) {
			// TODO: A better way to deal with this info. This function probably
			// shouldn't emit dbg messages unconditionally.
			de_dbg2(c, "PKLITE vers: %u.%02u%s%s%s",
				maj_ver, min_ver, (is_beta?"beta":""),
				(flag_e?"/e":""), (flag_large?"/large":""));
		}
	}
}

static void detect_execomp_lzexe(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	const char *vs = NULL;

	if(ei->entrypoint_crcs==0x4b6802c9cf419437LLU) {
		edd->detected_subfmt = 1;
		vs = "0.90";
	}
	else if(ei->entrypoint_crcs==0x246655c50ae99574LLU) {
		edd->detected_subfmt = 2;
		vs = "0.91";
	}
	else if(ei->entrypoint_crcs==0xd8a60f138f680f0cLLU) {
		edd->detected_subfmt = 3;
		vs = "0.91e";
	}

	if(vs) {
		edd->detected_fmt = DE_SPECIALEXEFMT_LZEXE;
		de_strlcpy(ectx->shortname, "LZEXE", sizeof(ectx->shortname));
		de_strlcpy(ectx->verstr, vs, sizeof(ectx->verstr));
		edd->modname = "lzexe";
	}
}

static void detect_execomp_exepack(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int has_RB = 0;

	if(ei->num_relocs!=0) goto done;
	if(ei->regIP!=16 && ei->regIP!=18) goto done;

	if(dbuf_getu16be(ei->f, ei->entry_point-2) == 0x5242) {
		has_RB = 1;
	}

	if(ei->entrypoint_crcs==0xa6ea214e6c16ee72LLU) {
		edd->detected_subfmt = 1;
		goto done;
	}
	else if(ei->entrypoint_crcs==0x4e04abaac5d3b465LLU) {
		edd->detected_subfmt = 2;
		goto done;
	}
	else if(ei->entrypoint_crcs==0x1f449ca73852e197LLU) {
		edd->detected_subfmt = 3;
		goto done;
	}
	// (There are probably more EXEPACK variants.)

	// TODO: Is SP always 128?
	if(ei->regSP==128 && has_RB) {
		edd->detected_fmt = DE_SPECIALEXEFMT_EXEPACK;
		goto done;
	}

done:
	if(edd->detected_subfmt!=0) {
		edd->detected_fmt = DE_SPECIALEXEFMT_EXEPACK;
	}

	if(edd->detected_fmt==DE_SPECIALEXEFMT_EXEPACK) {
		if(ectx->devmode) {
			de_dbg(c, "epvar: %u", (UI)edd->detected_subfmt);
		}
		de_strlcpy(ectx->shortname, "EXEPACK", sizeof(ectx->shortname));
	}
}

static void detect_execomp_tinyprog(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	i64 pos;
	i64 j;
	u8 x;

	if(ei->num_relocs!=0) goto done;
	pos = ei->entry_point;
	x = dbuf_getbyte(ei->f, pos);
	if(x!=0xe9) goto done;
	j = dbuf_getu16le(ei->f, pos+1);
	pos += 3+j; // Jump over user data

	x = dbuf_getbyte(ei->f, pos);
	if(x != 0xeb) goto done;
	j = dbuf_geti8(ei->f, pos+1);
	pos += 2+j; // Jump over (some sort of) data

	// This part seems consistent, but I'm really just guessing. Need to test more versions.
	if(dbuf_memcmp(ei->f, pos,
		(const void*)"\x83\xec\x10\x83\xe4\xe0\x8b\xec\x50\xbe\x05\x01\x03\x36\x01\x01", 16))
	{
		goto done;
	}

	edd->detected_fmt = DE_SPECIALEXEFMT_TINYPROG;
	de_strlcpy(ectx->shortname, "TINYPROG", sizeof(ectx->shortname));
done:
	;
}

static int execomp_diet_check_fingerprint(dbuf *f, i64 pos)
{
	return !dbuf_memcmp(f, pos,
		(const u8*)"\x8e\xdb\x8e\xc0\x33\xf6\x33\xff\xb9\x08\x00\xf3\xa5\x4b\x48\x4a", 16);
}

static void detect_execomp_diet(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	static const u8 offsets[] = {20, 40, 45};
	i64 foundpos = 0;
	size_t i;

	if(ei->regCS!=0) goto done;
	if(ei->regIP!=0 && ei->regIP!=3) goto done;
	if(ei->num_relocs>1) goto done;

	// Haven't figured out a good way to detect DIET. More research needed.
	for(i=0; i<DE_ARRAYCOUNT(offsets); i++) {
		if(execomp_diet_check_fingerprint(ei->f, ei->entry_point+(i64)offsets[i])) {
			foundpos = (i64)offsets[i];
			break;
		}
	}
	if(foundpos==0) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_DIET;
	de_strlcpy(ectx->shortname, "DIET", sizeof(ectx->shortname));
done:
	;
}

// Caller initializes ei (to zeroes).
// Records some basic information about an EXE file, to be used by routines that
// detect special EXE formats.
// The input file (f) must stay open after this. The detection routines will need
// to read more of it.
void fmtutil_collect_exe_info(deark *c, dbuf *f, struct fmtutil_exe_info *ei)
{
	i64 hdrsize; // in 16-byte units
	i64 lfb, nblocks;

	ei->f = f;
	lfb = dbuf_getu16le(f, 2);
	nblocks = dbuf_getu16le(f, 4);
	ei->num_relocs = dbuf_getu16le(f, 6);
	hdrsize = dbuf_getu16le(f, 8);
	ei->regSS = dbuf_geti16le(f, 14);
	ei->regSP = dbuf_getu16le(f, 16);
	ei->regIP = dbuf_getu16le(f, 20);
	ei->regCS = dbuf_geti16le(f, 22);
	ei->entry_point = (hdrsize + ei->regCS)*16 + ei->regIP;

	ei->end_of_dos_code = nblocks*512;
	if(lfb>=1 && lfb<=511) {
		ei->end_of_dos_code = ei->end_of_dos_code - 512 + lfb;
	}
}

// Caller supplies ei -- must call fmtutil_collect_exe_info() first.
// Caller initializes edd, to receive the results.
// If success, sets edd->detected_fmt to nonzero.
// Always sets edd->detected_fmt_name to something, even if "unknown".
// If we think we can decompress the format, sets edd->modname.
void fmtutil_detect_execomp(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	struct execomp_ctx ectx;

	de_zeromem(&ectx, sizeof(struct execomp_ctx));
	edd->detected_fmt = 0;
	edd->detected_subfmt = 0;

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_PKLITE) {
		detect_execomp_pklite(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_TINYPROG) {
		detect_execomp_tinyprog(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_DIET) {
		detect_execomp_diet(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	calc_entrypoint_crc(c, &ectx, ei);

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_LZEXE) {
		detect_execomp_lzexe(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_EXEPACK) {
		detect_execomp_exepack(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

done:
	if(ectx.shortname[0] && ectx.verstr[0]) {
		de_snprintf(edd->detected_fmt_name, sizeof(edd->detected_fmt_name), "%s %s",
			ectx.shortname, ectx.verstr);
	}
	else {
		de_strlcpy(edd->detected_fmt_name, (ectx.shortname[0]?ectx.shortname:"unknown"),
			sizeof(edd->detected_fmt_name));
	}
}

// If found, writes a copy of pos to *pfoundpos.
static int is_lha_data_at(struct fmtutil_exe_info *ei, i64 pos, i64 *pfoundpos)
{
	u8 b2[8];

	if(pos+21 > ei->f->len) return 0;
	dbuf_read(ei->f, b2, pos, sizeof(b2));
	if(b2[2]!='-' || b2[6]!='-') return 0;
	if(b2[3]=='l' && b2[4]=='h') {
		*pfoundpos = pos;
		return 1;
	}
	return 0;
}

// Detect LHA/LHarc self-extracting DOS EXE formats.
// TODO: This is a work in progress.
static void detect_exesfx_lha(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	u8 b[16];
	int found;
	i64 foundpos = 0;

	if(ei->regSS != -16) goto done;
	if(ei->regSP != 256) goto done;
	if(ei->regCS != -16) goto done;
	if(ei->regIP != 256) goto done;

	dbuf_read(ei->f, b, 28, sizeof(b));
	if(b[4]!=0xeb && b[4]!=0xe9) goto done;
	if(b[8]=='L' && b[9]=='H') {
		;
	}
	else if(b[9]=='L' && b[10]=='H') {
		;
	}
	else if(b[10]=='L' && b[11]=='H') {
		;
	}
	else if(b[10]=='S' && b[11]=='F') { // v1.00
		;
	}
	else {
		goto done;
	}

	found =
		is_lha_data_at(ei, ei->end_of_dos_code, &foundpos) ||
		is_lha_data_at(ei, ei->end_of_dos_code+1, &foundpos) ||
		is_lha_data_at(ei, ei->end_of_dos_code+3, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1292-32, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1295-32, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1322-32, &foundpos);
	if(!found) goto done;

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<21) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "lha";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "LHA", sizeof(ectx->shortname));
	}
}

static int is_arc_data_at(struct fmtutil_exe_info *ei, i64 pos)
{
	u8 b[2];

	dbuf_read(ei->f, b, pos, 2);
	if(b[0]!=0x1a) return 0;
	if(b[1]>30) return 0;
	return 1;
}

// Detect some ARC self-extracting DOS EXE formats.
// TODO: This is pretty fragile. It only detects files made by known versions of
// MKSARC (from the ARC distribution).
static void detect_exesfx_arc(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int found = 0;
	i64 foundpos = 0;

	calc_entrypoint_crc(c, ectx, ei);
	if(ei->entrypoint_crcs==0x057db6d8be3c4895ULL) { // MKSARC v1.00 from ARC v6.01
		found = 1;
		foundpos = ei->end_of_dos_code;
	}
	else if(ei->entrypoint_crcs==0x8542182a98613fe0ULL ||
		ei->entrypoint_crcs==0x6bd653c8edd98eedULL)
	{
		// MKSARC v1.01 from ARC v6.02
		// (Found two different versions with the same version number.)
		// This version of MKSARC has a bug. Compared to the v1.00, the start of DOS
		// code was reduced by 480, from 512 to 32. But the *end* of DOS code was not
		// adjusted accordingly, leaving it 480 higher than it should be. This is
		// important, because the end of DOS code is where we expect the ARC data to
		// start.
		found = 1;
		foundpos = ei->end_of_dos_code - 480;
		if(!is_arc_data_at(ei, foundpos)) {
			foundpos = ei->end_of_dos_code; // In case there's a version without the bug
		}
	}
	else if(ei->entrypoint_crcs==0x3230b4d5fca84644ULL) { // MKSARC v7.12, from ARC v7.12
		found = 1;
		foundpos = ei->end_of_dos_code;
	}
	// TODO: Detect MKSARC v7.12 with the /P option (OS/2 protected mode).
	// Extraction would work, if we could detect it.

	if(!found) goto done;
	if(!is_arc_data_at(ei, foundpos)) {
		goto done;
	}

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<2) goto done;
	// TODO: It would be nice to strip any padding from the end of the extracted ARC
	// file, but that could be more trouble than it's worth.

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "arc";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "ARC", sizeof(ectx->shortname));
	}
}

void fmtutil_detect_exesfx(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	struct execomp_ctx ectx;

	de_zeromem(&ectx, sizeof(struct execomp_ctx));

	detect_exesfx_lha(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_arc(c, &ectx, ei, edd);

done:
	if(ectx.shortname[0] && ectx.verstr[0]) {
		de_snprintf(edd->detected_fmt_name, sizeof(edd->detected_fmt_name), "%s %s",
			ectx.shortname, ectx.verstr);
	}
	else {
		de_strlcpy(edd->detected_fmt_name, (ectx.shortname[0]?ectx.shortname:"unknown"),
			sizeof(edd->detected_fmt_name));
	}
}
