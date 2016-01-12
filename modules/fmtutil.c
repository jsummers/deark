// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// This file is for format-specific functions that are used by multiple modules.

#include <deark-config.h>
#include <deark-private.h>
#include "fmtutil.h"

// Gathers information about a DIB.
// If DE_BMPINFO_HAS_FILEHEADER flag is set, pos points to the BITMAPFILEHEADER.
// Otherwise, it points to the BITMAPINFOHEADER.
// Caller allocates bi.
// Returns 0 if BMP is invalid.
int de_fmtutil_get_bmpinfo(deark *c, dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags)
{
	de_int64 fhs; // file header size
	de_int64 bmih_pos;

	de_memset(bi, 0, sizeof(struct de_bmpinfo));

	fhs = (flags & DE_BMPINFO_HAS_FILEHEADER) ? 14 : 0;

	if(fhs+len < 16) return 0;

	if(fhs) {
		if(flags & DE_BMPINFO_HAS_HOTSPOT) {
			bi->hotspot_x = dbuf_getui16le(f, pos+6);
			bi->hotspot_y = dbuf_getui16le(f, pos+8);
			de_dbg(c, "hotspot: (%d,%d)\n", (int)bi->hotspot_x, (int)bi->hotspot_y);
		}

		bi->bitsoffset = dbuf_getui32le(f, pos+10);
		de_dbg(c, "bits offset: %d\n", (int)bi->bitsoffset);
	}

	bmih_pos = pos + fhs;

	bi->infohdrsize = dbuf_getui32le(f, bmih_pos);

	if(bi->infohdrsize==0x474e5089 && (flags & DE_BMPINFO_ICO_FORMAT)) {
		// We don't examine PNG-formatted icons, but we can identify them.
		bi->infohdrsize = 0;
		bi->file_format = DE_BMPINFO_FMT_PNG;
		return 1;
	}

	de_dbg(c, "info header size: %d\n", (int)bi->infohdrsize);

	if(bi->infohdrsize==12) {
		bi->bytes_per_pal_entry = 3;
		bi->width = dbuf_getui16le(f, bmih_pos+4);
		bi->height = dbuf_getui16le(f, bmih_pos+6);
		bi->bitcount = dbuf_getui16le(f, bmih_pos+10);
	}
	else if(bi->infohdrsize>=16 && bi->infohdrsize<=124) {
		bi->bytes_per_pal_entry = 4;
		bi->width = dbuf_getui32le(f, bmih_pos+4);
		bi->height = dbuf_getui32le(f, bmih_pos+8);
		if(bi->height<0) {
			bi->is_topdown = 1;
			bi->height = -bi->height;
		}
		bi->bitcount = dbuf_getui16le(f, bmih_pos+14);
		if(bi->infohdrsize>=20) {
			bi->compression_field = dbuf_getui32le(f, bmih_pos+16);
		}
		if(bi->infohdrsize>=36) {
			bi->pal_entries = dbuf_getui32le(f, bmih_pos+32);
		}
	}
	else {
		return 0;
	}

	if(flags & DE_BMPINFO_ICO_FORMAT) bi->height /= 2;

	if(bi->bitcount>=1 && bi->bitcount<=8) {
		if(bi->pal_entries==0) {
			bi->pal_entries = (de_int64)(1<<(unsigned int)bi->bitcount);
		}
		// I think the NumColors field (in icons) is supposed to be the maximum number of
		// colors implied by the bit depth, not the number of colors in the palette.
		bi->num_colors = (de_int64)(1<<(unsigned int)bi->bitcount);
	}
	else {
		// An arbitrary value. All that matters is that it's >=256.
		bi->num_colors = 16777216;
	}

	de_dbg(c, "image size: %dx%d\n", (int)bi->width, (int)bi->height);
	de_dbg(c, "bit count: %d\n", (int)bi->bitcount);
	de_dbg(c, "palette entries: %d\n", (int)bi->pal_entries);

	bi->pal_bytes = bi->bytes_per_pal_entry*bi->pal_entries;
	bi->size_of_headers_and_pal = fhs + bi->infohdrsize + bi->pal_bytes;
	if(bi->compression_field==3) {
		bi->size_of_headers_and_pal += 12; // BITFIELDS
	}

	if(bi->compression_field==0) {
		// Try to figure out the true size of the resource, minus any padding.

		bi->rowspan = ((bi->bitcount*bi->width +31)/32)*4;
		bi->foreground_size = bi->rowspan * bi->height;

		if(flags & DE_BMPINFO_ICO_FORMAT) {
			bi->mask_rowspan = ((bi->width +31)/32)*4;
			bi->mask_size = bi->mask_rowspan * bi->height;
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

void de_fmtutil_handle_exif(deark *c, de_int64 pos, de_int64 len)
{
	de_module_params *mparams = NULL;

	if(c->extract_level>=2) {
		// Writing raw Exif data isn't very useful, but do so if requested.
		dbuf_create_file_from_slice(c->infile, pos, len, "exif.tif", NULL);

		// Caller will have to reprocess the Exif file to extract anything from it.
		return;
	}

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->codes = "E";
	de_run_module_by_id_on_slice(c, "tiff", mparams, c->infile, pos, len);
	de_free(c, mparams);
}

void de_fmtutil_handle_photoshop_rsrc(deark *c, de_int64 pos, de_int64 len)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->codes = "R";
	de_run_module_by_id_on_slice(c, "psd", mparams, c->infile, pos, len);
	de_free(c, mparams);
}

// Returns 0 on failure (currently impossible).
int de_fmtutil_uncompress_packbits(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels, de_int64 *cmpr_bytes_consumed)
{
	de_int64 pos;
	de_byte b, b2;
	de_int64 count;
	de_int64 endpos;

	pos = pos1;
	endpos = pos1+len;

	while(1) {
		if(unc_pixels->max_len>0 && unc_pixels->len>=unc_pixels->max_len) {
			break; // Decompressed the requested amount of dst data.
		}

		if(pos>=endpos) {
			break; // Reached the end of source data
		}
		b = dbuf_getbyte(f, pos++);

		if(b>128) { // A compressed run
			count = 257 - (de_int64)b;
			b2 = dbuf_getbyte(f, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(f, pos, count, unc_pixels);
			pos += count;
		}
		// Else b==128. No-op.
		// TODO: Some (but not most) ILBM specs say that code 128 is used to
		// mark the end of compressed data, so maybe there should be options to
		// tell us what to do when code 128 is encountered.
	}

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = pos - pos1;
	return 1;
}

static de_int64 space_padded_length(const de_byte *buf, de_int64 len)
{
	de_int64 i;
	de_int64 last_nonspace = -1;

	for(i=len-1; i>=0; i--) {
		// Spec says to use spaces for padding, and for nonexistent data.
		// But some files use NUL bytes.
		if(buf[i]!=0x20 && buf[i]!=0x00) {
			last_nonspace = i;
			break;
		}
	}
	return last_nonspace+1;
}

static void bytes_to_ucstring(deark *c, const de_byte *buf, de_int64 len,
	de_ucstring *s, int encoding, int date_fmt_flag)
{
	de_int32 u;
	de_int64 i;

	for(i=0; i<len; i++) {
		if(date_fmt_flag && (i==4 || i==6)) {
			ucstring_append_char(s, '-');
		}
		u = de_char_to_unicode(c, (de_int32)buf[i], encoding);
		if(date_fmt_flag && u==32) u=48; // Change space to 0 in dates.
		ucstring_append_char(s, u);
	}
}

static int is_valid_date_string(const de_byte *buf, de_int64 len)
{
	de_int64 i;

	for(i=0; i<len; i++) {
		if(buf[i]>='0' && buf[i]<='9') continue;
		// Spaces aren't allowed, but some files use them.
		if(buf[i]==' ' && (i==4 || i==6)) continue;
		return 0;
	}
	return 1;
}

int de_has_SAUCE(deark *c, dbuf *f, de_int64 pos)
{
	de_byte buf[7];
	dbuf_read(f, buf, pos, 7);
	if(de_memcmp(buf, "SAUCE", 5)) return 0;
	if(buf[5]<'0' || buf[5]>'9') return 0;
	if(buf[6]<'0' || buf[6]>'9') return 0;
	return 1;
}

// SAUCE = Standard Architecture for Universal Comment Extensions
// Caller allocates si.
// This function may allocate si->title, artist, organization, creation_date.
int de_read_SAUCE(deark *c, dbuf *f, de_int64 pos, struct de_SAUCE_info *si)
{
	de_uint32 t;
	de_byte tmpbuf[40];
	de_int64 tmpbuf_len;

	if(!si) return 0;
	de_memset(si, 0, sizeof(struct de_SAUCE_info));

	if(dbuf_memcmp(f, pos+0, "SAUCE00", 7)) {
		return 0;
	}

	de_dbg(c, "SAUCE metadata at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	// Title
	dbuf_read(f, tmpbuf, pos+7, 35);
	tmpbuf_len = space_padded_length(tmpbuf, 35);
	if(tmpbuf_len>0) {
		si->title = ucstring_create(c);
		bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->title, DE_ENCODING_CP437_G, 0);
	}

	// Artist / Creator
	dbuf_read(f, tmpbuf, pos+42, 20);
	tmpbuf_len = space_padded_length(tmpbuf, 20);
	if(tmpbuf_len>0) {
		si->artist = ucstring_create(c);
		bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->artist, DE_ENCODING_CP437_G, 0);
	}

	// Organization
	dbuf_read(f, tmpbuf, pos+62, 20);
	tmpbuf_len = space_padded_length(tmpbuf, 20);
	if(tmpbuf_len>0) {
		si->organization = ucstring_create(c);
		bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->organization, DE_ENCODING_CP437_G, 0);
	}

	// Creation date
	dbuf_read(f, tmpbuf, pos+82, 8);
	if(is_valid_date_string(tmpbuf, 8)) {
		tmpbuf_len = 8;
		si->creation_date = ucstring_create(c);
		bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->creation_date, DE_ENCODING_CP437_G, 1);
	}

	si->original_file_size = dbuf_getui32le(f, pos+90);
	de_dbg(c, "original file size: %d\n", (int)si->original_file_size);

	si->data_type = dbuf_getbyte(f, pos+94);
	de_dbg(c, "data type: %d\n", (int)si->data_type);
	si->file_type = dbuf_getbyte(f, pos+95);
	de_dbg(c, "file type: %d\n", (int)si->file_type);

	t = 256*(de_uint32)si->data_type + si->file_type;

	if(t==0x0100 || t==0x0101 || t==0x0102 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->width_in_chars = dbuf_getui16le(f, pos+96);
		de_dbg(c, "width in chars: %d\n", (int)si->width_in_chars);
	}
	if(t==0x0100 || t==0x0101 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->number_of_lines = dbuf_getui16le(f, pos+98);
		de_dbg(c, "number of lines: %d\n", (int)si->number_of_lines);
	}

	de_dbg_indent(c, -1);
	return 1;
}

void de_free_SAUCE(deark *c, struct de_SAUCE_info *si)
{
	if(!si) return;
	ucstring_destroy(si->title);
	ucstring_destroy(si->artist);
	ucstring_destroy(si->organization);
	ucstring_destroy(si->creation_date);
	de_free(c, si);
}

// Helper functions for the "boxes" (or "atoms") format used by MP4, JPEG 2000, etc.

double dbuf_fmtutil_read_fixed_16_16(dbuf *f, de_int64 pos)
{
	de_int64 n;
	n = dbuf_geti32be(f, pos);
	return ((double)n)/65536.0;
}

static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	de_int64 pos1, de_int64 len, int level);

// Caller supplies s.
static void render_uuid(deark *c, const de_byte *uuid, char *s, size_t s_len)
{
	de_snprintf(s, s_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

#define DE_BOX_uuid 0x75756964U

static int do_box(deark *c, struct de_boxesctx *bctx, de_int64 pos, de_int64 len,
	int level, de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_len; // Not including UUIDs
	de_int64 payload_len; // Including UUIDs
	de_int64 total_len;
	de_byte boxtype_buf[4];
	char boxtype_printable[16];
	char uuid_string[50];
	int ret;

	if(len<8) {
		de_dbg(c, "(ignoring %d extra bytes at %d)\n", (int)len, (int)pos);
		return 0;
	}

	bctx->is_uuid = 0;
	size32 = dbuf_getui32be(bctx->f, pos);
	dbuf_read(bctx->f, boxtype_buf, pos+4, 4);
	bctx->boxtype = (de_uint32)de_getui32be_direct(boxtype_buf);

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
			de_dbg(c, "(ignoring %d extra bytes at %d)\n", (int)len, (int)pos);
			return 0;
		}
		header_len = 16;
		size64 = dbuf_geti64be(bctx->f, pos+8);
		if(size64<16) return 0;
		payload_len = size64-16;
	}
	else {
		de_err(c, "Invalid or unsupported box format\n");
		return 0;
	}

	total_len = header_len + payload_len;

	if(bctx->boxtype==DE_BOX_uuid && payload_len>=16) {
		bctx->is_uuid = 1;
		dbuf_read(bctx->f, bctx->uuid, pos+header_len, 16);
	}

	if(c->debug_level>0) {
		de_make_printable_ascii(boxtype_buf, 4, boxtype_printable, sizeof(boxtype_printable), 0);
		if(bctx->is_uuid) {
			render_uuid(c, bctx->uuid, uuid_string, sizeof(uuid_string));
			de_dbg(c, "box '%s'{%s} at %d, len=%" INT64_FMT "\n",
				boxtype_printable, uuid_string,
				(int)pos, total_len);
		}
		else {
			de_dbg(c, "box '%s' at %d, len=%" INT64_FMT ", dlen=%d\n", boxtype_printable,
				(int)pos, total_len, (int)payload_len);
		}
	}

	if(total_len > len) {
		de_err(c, "Invalid oversized box, or unexpected end of file "
			"(box at %d ends at %" INT64_FMT ", "
			"parent ends at %" INT64_FMT ")\n",
			(int)pos, pos+total_len, pos+len);
		return 0;
	}

	bctx->level = level;
	bctx->is_superbox = 0; // Default value. Client can change it.
	bctx->has_version_and_flags = 0; // Default value. Client can change it.
	bctx->box_pos = pos;
	bctx->box_len = total_len;
	bctx->payload_pos = pos+header_len;
	bctx->payload_len = payload_len;
	if(bctx->is_uuid) {
		bctx->payload_pos += 16;
		bctx->payload_len -= 16;
	}

	de_dbg_indent(c, 1);
	ret = bctx->handle_box_fn(c, bctx);
	de_dbg_indent(c, -1);
	if(!ret) return 0;

	if(bctx->is_superbox) {
		de_int64 extra_bytes = 0;

		de_dbg_indent(c, 1);

		if(bctx->has_version_and_flags) {
			extra_bytes = 4;
			// TODO: Print the version number and flags?
		}

		do_box_sequence(c, bctx,
			pos+header_len + extra_bytes,
			payload_len - extra_bytes, level+1);
		de_dbg_indent(c, -1);
	}

	*pbytes_consumed = total_len;
	return 1;
}

static void do_box_sequence(deark *c, struct de_boxesctx *bctx,
	de_int64 pos1, de_int64 len, int level)
{
	de_int64 pos;
	de_int64 box_len;
	de_int64 endpos;
	int ret;

	if(level >= 32) { // An arbitrary recursion limit.
		return;
	}

	pos = pos1;
	endpos = pos1 + len;

	while(pos < endpos) {
		ret = do_box(c, bctx, pos, endpos-pos, level, &box_len);
		if(!ret) break;
		pos += box_len;
	}
}

// Handle some box types that might be common to multiple formats.
// This function should be called as needed by the client's box handler function.
int de_fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx)
{
	if(bctx->is_uuid) {
		if(!de_memcmp(bctx->uuid, "\xb1\x4b\xf8\xbd\x08\x3d\x4b\x43\xa5\xae\x8c\xd7\xd5\xa6\xce\x03", 16)) {
			de_dbg(c, "GeoTIFF data at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "geo.tif", NULL);
		}
		else if(!de_memcmp(bctx->uuid, "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac", 16)) {
			de_dbg(c, "XMP data at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			dbuf_create_file_from_slice(bctx->f, bctx->payload_pos, bctx->payload_len, "xmp", NULL);
		}
		else if(!de_memcmp(bctx->uuid, "\x2c\x4c\x01\x00\x85\x04\x40\xb9\xa0\x3e\x56\x21\x48\xd6\xdf\xeb", 16)) {
			de_dbg(c, "Photoshop resources at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			de_fmtutil_handle_photoshop_rsrc(c, bctx->payload_pos, bctx->payload_len);
		}
		else if(!de_memcmp(bctx->uuid, "\x05\x37\xcd\xab\x9d\x0c\x44\x31\xa7\x2a\xfa\x56\x1f\x2a\x11\x3e", 16)) {
			de_dbg(c, "Exif data at %d, len=%d\n", (int)bctx->payload_pos, (int)bctx->payload_len);
			de_fmtutil_handle_exif(c, bctx->payload_pos, bctx->payload_len);
		}
	}
	return 1;
}

void de_fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx)
{
	if(!bctx->f || !bctx->handle_box_fn) return; // Internal error
	do_box_sequence(c, bctx, 0, bctx->f->len, 0);
}

static de_byte scale7to255(de_byte n)
{
	return (de_byte)(0.5+(255.0/7.0)*(double)n);
}

void de_fmtutil_read_atari_palette(deark *c, dbuf *f, de_int64 pos,
	de_uint32 *dstpal, de_int64 ncolors_to_read, de_int64 ncolors_used)
{
	de_int64 i;
	unsigned int n;
	int has_12bit_pal = 0;
	de_byte cr, cg, cb;
	de_byte cr1, cg1, cb1;
	char cbuf[32];
	const char *s;
	int detect_pal_bits = 1;

	s = de_get_ext_option(c, "atari:palbits");
	if(s) {
		int palbits_req = de_atoi(s);
		if(palbits_req>0) {
			detect_pal_bits = 0;
			if(palbits_req>=12) {
				has_12bit_pal = 1;
			}
		}
	}

	if(detect_pal_bits) {
		// Pre-scan the palette, and try to guess whether Atari STE-style 12-bit
		// colors are used, instead of the usual 9-bit colors.
		// I don't know the best way to do this. Sometimes the 4th bit in each
		// nibble is used for extra color detail, and sometimes it just seems to
		// contain garbage. Maybe the logic should also depend on the file
		// format, or the number of colors.
		int bit_3_used = 0;
		int nibble_3_used = 0;

		for(i=0; i<ncolors_to_read; i++) {
			n = (unsigned int)dbuf_getui16be(f, pos + i*2);
			if(n&0xf000) {
				nibble_3_used = 1;
			}
			if(n&0x0888) {
				bit_3_used = 1;
			}
		}

		if(bit_3_used && !nibble_3_used) {
			de_dbg(c, "12-bit palette colors detected\n");
			has_12bit_pal = 1;
		}
	}

	for(i=0; i<ncolors_to_read; i++) {
		n = (unsigned int)dbuf_getui16be(f, pos + 2*i);

		if(has_12bit_pal) {
			cr1 = (de_byte)((n>>7)&14);
			if(n&0x800) cr1++;
			cg1 = (de_byte)((n>>3)&14);
			if(n&0x080) cg1++;
			cb1 = (de_byte)((n<<1)&14);
			if(n&0x008) cb1++;
			cr = cr1*17;
			cg = cg1*17;
			cb = cb1*17;
			de_snprintf(cbuf, sizeof(cbuf), "%2d,%2d,%2d",
				(int)cr1, (int)cg1, (int)cb1);
		}
		else {
			cr1 = (de_byte)((n>>8)&7);
			cg1 = (de_byte)((n>>4)&7);
			cb1 = (de_byte)(n&7);
			cr = scale7to255(cr1);
			cg = scale7to255(cg1);
			cb = scale7to255(cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%d,%d,%d",
				(int)cr1, (int)cg1, (int)cb1);
		}

		de_dbg2(c, "pal[%2d] = 0x%04x (%s) -> (%3d,%3d,%3d)%s\n", (int)i, n, cbuf,
			(int)cr, (int)cg, (int)cb,
			(i>=ncolors_used)?" [unused]":"");

		dstpal[i] = DE_MAKE_RGB(cr, cg, cb);
	}
}
