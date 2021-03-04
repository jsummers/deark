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
	char uuid_string[50];
	int ret;
	int retval = 0;
	struct de_boxdata *parentbox;
	struct de_boxdata *curbox;

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
		char name_str[80];

		if(curbox->box_name) {
			de_snprintf(name_str, sizeof(name_str), " (%s)", curbox->box_name);
		}
		else {
			name_str[0] = '\0';
		}

		if(curbox->is_uuid) {
			fmtutil_render_uuid(c, curbox->uuid, uuid_string, sizeof(uuid_string));
			de_dbg(c, "box '%s'{%s}%s at %"I64_FMT", len=%"I64_FMT,
				box4cc.id_dbgstr, uuid_string, name_str,
				pos, total_len);
		}
		else {
			de_dbg(c, "box '%s'%s at %"I64_FMT", len=%"I64_FMT", dlen=%"I64_FMT,
				box4cc.id_dbgstr, name_str, pos,
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
	if(!bctx->f || !bctx->handle_box_fn) return; // Internal error
	if(bctx->curbox) return; // Internal error
	do_box_sequence(c, bctx, 0, bctx->f->len, -1, 0);
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

#define CODE__c_   0x28632920U // "(c) "
#define CODE_ANNO  0x414e4e4fU
#define CODE_AUTH  0x41555448U
#define CODE_NAME  0x4e414d45U
#define CODE_TEXT  0x54455854U
#define CODE_RIFF  0x52494646U

static void do_iff_text_chunk(deark *c, struct de_iffctx *ictx, i64 dpos, i64 dlen,
	const char *name)
{
	de_ucstring *s = NULL;

	if(dlen<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(ictx->f,
		dpos, dlen, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, ictx->input_encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_iff_anno(deark *c, struct de_iffctx *ictx, i64 pos, i64 len)
{
	i64 foundpos;

	if(len<1) return;

	// Some ANNO chunks seem to be padded with one or more NUL bytes. Probably
	// best not to save them.
	if(dbuf_search_byte(ictx->f, 0x00, pos, len, &foundpos)) {
		len = foundpos - pos;
	}
	if(len<1) return;
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(ictx->f, pos, len, "anno.txt", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		de_ucstring *s = NULL;
		s = ucstring_create(c);
		dbuf_read_to_ucstring_n(ictx->f, pos, len, DE_DBG_MAX_STRLEN, s, 0, ictx->input_encoding);
		de_dbg(c, "annotation: \"%s\"", ucstring_getpsz(s));
		ucstring_destroy(s);
	}
}

void fmtutil_default_iff_chunk_identify(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE__c_ : name="copyright"; break;
	case CODE_ANNO: name="annotation"; break;
	case CODE_AUTH: name="author"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
}

// Note that some of these chunks are *not* defined in the generic IFF
// specification.
// They might be defined in the 8SVX specification. They seem to have
// become unofficial standard chunks.
static int de_fmtutil_default_iff_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	i64 dpos = ictx->chunkctx->dpos;
	i64 dlen = ictx->chunkctx->dlen;
	u32 chunktype = ictx->chunkctx->chunk4cc.id;

	switch(chunktype) {
		// Note that chunks appearing here should also be listed below,
		// in de_fmtutil_is_standard_iff_chunk().
	case CODE__c_:
		do_iff_text_chunk(c, ictx, dpos, dlen, "copyright");
		break;
	case CODE_ANNO:
		do_iff_anno(c, ictx, dpos, dlen);
		break;
	case CODE_AUTH:
		do_iff_text_chunk(c, ictx, dpos, dlen, "author");
		break;
	case CODE_NAME:
		do_iff_text_chunk(c, ictx, dpos, dlen, "name");
		break;
	case CODE_TEXT:
		do_iff_text_chunk(c, ictx, dpos, dlen, "text");
		break;
	}

	// Note we do not set ictx->handled. The caller is responsible for that.
	return 1;
}

// ictx can be NULL
int fmtutil_is_standard_iff_chunk(deark *c, struct de_iffctx *ictx,
	u32 ct)
{
	switch(ct) {
	case CODE__c_:
	case CODE_ANNO:
	case CODE_AUTH:
	case CODE_NAME:
	case CODE_TEXT:
		return 1;
	}
	return 0;
}

static void fourcc_clear(struct de_fourcc *fourcc)
{
	de_zeromem(fourcc, sizeof(struct de_fourcc));
}

static int do_iff_chunk_sequence(deark *c, struct de_iffctx *ictx,
	i64 pos1, i64 len, int level);

// Returns 0 if we can't continue
static int do_iff_chunk(deark *c, struct de_iffctx *ictx, i64 pos, i64 bytes_avail,
	int level, i64 *pbytes_consumed)
{
	int ret;
	i64 chunk_dlen_raw;
	i64 chunk_dlen_padded;
	i64 data_bytes_avail;
	i64 hdrsize;
	struct de_iffchunkctx chunkctx;
	int saved_indent_level;
	int retval = 0;
	char name_str[80];

	de_zeromem(&chunkctx, sizeof(struct de_iffchunkctx));

	de_dbg_indent_save(c, &saved_indent_level);

	hdrsize = 4+ictx->sizeof_len;
	if(bytes_avail<hdrsize) {
		de_warn(c, "Ignoring %"I64_FMT" bytes at %"I64_FMT"; too small "
			"to be a chunk", bytes_avail, pos);
		goto done;
	}
	data_bytes_avail = bytes_avail-hdrsize;

	dbuf_read_fourcc(ictx->f, pos, &chunkctx.chunk4cc, 4,
		ictx->reversed_4cc ? DE_4CCFLAG_REVERSED : 0x0);
	if(chunkctx.chunk4cc.id==0 && level==0) {
		de_warn(c, "Chunk ID not found at %"I64_FMT"; assuming the data ends "
			"here", pos);
		goto done;
	}

	if(ictx->sizeof_len==2) {
		chunk_dlen_raw = dbuf_getu16x(ictx->f, pos+4, ictx->is_le);
	}
	else {
		chunk_dlen_raw = dbuf_getu32x(ictx->f, pos+4, ictx->is_le);
	}
	chunkctx.dlen = chunk_dlen_raw;
	chunkctx.dpos = pos+hdrsize;

	// TODO: Setting these fields (prior to the identify function) is enough
	// for now, but we should also set the other fields here if we can.
	ictx->level = level;
	ictx->chunkctx = &chunkctx;

	if(ictx->preprocess_chunk_fn) {
		ictx->preprocess_chunk_fn(c, ictx);
	}

	if(chunkctx.chunk_name) {
		de_snprintf(name_str, sizeof(name_str), " (%s)", chunkctx.chunk_name);
	}
	else {
		name_str[0] = '\0';
	}

	de_dbg(c, "chunk '%s'%s at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
		chunkctx.chunk4cc.id_dbgstr, name_str, pos,
		chunkctx.dpos, chunkctx.dlen);
	de_dbg_indent(c, 1);

	if(chunkctx.dlen > data_bytes_avail) {
		int should_warn = 1;

		if(chunkctx.chunk4cc.id==CODE_RIFF && pos==0 && bytes_avail==ictx->f->len) {
			// Hack:
			// This apparent error, in which the RIFF chunk's length field gives the
			// length of the entire file, is too common (particularly in .ani files)
			// to warn about.
			should_warn = 0;
		}

		if(should_warn) {
			de_warn(c, "Invalid oversized chunk, or unexpected end of file "
				"(chunk at %d ends at %" I64_FMT ", "
				"parent ends at %" I64_FMT ")",
				(int)pos, chunkctx.dlen+chunkctx.dpos, pos+bytes_avail);
		}

		chunkctx.dlen = data_bytes_avail; // Try to continue
		de_dbg(c, "adjusting chunk data len to %"I64_FMT, chunkctx.dlen);
	}

	chunk_dlen_padded = de_pad_to_n(chunkctx.dlen, ictx->alignment);
	*pbytes_consumed = hdrsize + chunk_dlen_padded;

	// We've set *pbytes_consumed, so we can return "success"
	retval = 1;

	// Set ictx fields, prior to calling the handler
	chunkctx.pos = pos;
	chunkctx.len = bytes_avail;
	ictx->handled = 0;
	ictx->is_std_container = 0;
	ictx->is_raw_container = 0;

	ret = ictx->handle_chunk_fn(c, ictx);
	if(!ret) {
		retval = 0;
		goto done;
	}

	if(ictx->is_std_container || ictx->is_raw_container) {
		i64 contents_dpos, contents_dlen;

		ictx->chunkctx = NULL;
		ictx->curr_container_fmt4cc = chunkctx.chunk4cc;
		fourcc_clear(&ictx->curr_container_contentstype4cc);

		if(ictx->is_std_container) {
			contents_dpos = chunkctx.dpos+4;
			contents_dlen = chunkctx.dlen-4;

			// First 4 bytes of payload are the "contents type" or "FORM type"
			dbuf_read_fourcc(ictx->f, chunkctx.dpos, &ictx->curr_container_contentstype4cc, 4,
				ictx->reversed_4cc ? DE_4CCFLAG_REVERSED : 0);

			if(level==0) {
				ictx->main_fmt4cc = ictx->curr_container_fmt4cc;
				ictx->main_contentstype4cc = ictx->curr_container_contentstype4cc; // struct copy
			}
			de_dbg(c, "contents type: '%s'", ictx->curr_container_contentstype4cc.id_dbgstr);

			if(ictx->on_std_container_start_fn) {
				// Call only for standard-format containers.
				ret = ictx->on_std_container_start_fn(c, ictx);
				if(!ret) goto done;
			}
		}
		else { // ictx->is_raw_container
			contents_dpos = chunkctx.dpos;
			contents_dlen = chunkctx.dlen;
		}

		ret = do_iff_chunk_sequence(c, ictx, contents_dpos, contents_dlen, level+1);
		if(!ret) {
			retval = 0;
			goto done;
		}

		if(ictx->on_container_end_fn) {
			// Call for all containers (not just standard-format containers).

			// TODO: Decide exactly what ictx->* fields to set here.
			ictx->level = level;

			ictx->chunkctx = NULL;
			ret = ictx->on_container_end_fn(c, ictx);
			if(!ret) {
				retval = 0;
				goto done;
			}
		}
	}
	else if(!ictx->handled) {
		de_fmtutil_default_iff_chunk_handler(c, ictx);
	}

done:
	fourcc_clear(&ictx->curr_container_fmt4cc);
	fourcc_clear(&ictx->curr_container_contentstype4cc);

	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_iff_chunk_sequence(deark *c, struct de_iffctx *ictx,
	i64 pos1, i64 len, int level)
{
	i64 pos;
	i64 endpos;
	i64 chunk_len;
	struct de_fourcc saved_container_fmt4cc;
	struct de_fourcc saved_container_contentstype4cc;
	int ret;

	if(level >= 16) { // An arbitrary recursion limit.
		return 0;
	}

	endpos = pos1+len;
	saved_container_fmt4cc = ictx->curr_container_fmt4cc;
	saved_container_contentstype4cc = ictx->curr_container_contentstype4cc;

	pos = pos1;
	while(pos < endpos) {
		ictx->curr_container_fmt4cc = saved_container_fmt4cc;
		ictx->curr_container_contentstype4cc = saved_container_contentstype4cc;

		if(ictx->handle_nonchunk_data_fn) {
			i64 skip_len = 0;
			ret = ictx->handle_nonchunk_data_fn(c, ictx, pos, &skip_len);
			if(ret && skip_len>0) {
				pos += de_pad_to_n(skip_len, ictx->alignment);
				continue;
			}
		}

		ret = do_iff_chunk(c, ictx, pos, endpos-pos, level, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	ictx->curr_container_fmt4cc = saved_container_fmt4cc;
	ictx->curr_container_contentstype4cc = saved_container_contentstype4cc;

	return 1;
}

void fmtutil_read_iff_format(deark *c, struct de_iffctx *ictx,
	i64 pos, i64 len)
{
	if(!ictx->f || !ictx->handle_chunk_fn) return; // Internal error

	ictx->level = 0;
	fourcc_clear(&ictx->main_fmt4cc);
	fourcc_clear(&ictx->main_contentstype4cc);
	fourcc_clear(&ictx->curr_container_fmt4cc);
	fourcc_clear(&ictx->curr_container_contentstype4cc);
	if(ictx->alignment==0) {
		ictx->alignment = 2;
	}
	if(ictx->sizeof_len==0) {
		ictx->sizeof_len = 4;
	}

	if(ictx->input_encoding==DE_ENCODING_UNKNOWN) {
		ictx->input_encoding = DE_ENCODING_ASCII;
	}

	do_iff_chunk_sequence(c, ictx, pos, len, 0);
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

	bi->pdwidth = (bi->rowbytes*8)/bi->pixelsize;
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
