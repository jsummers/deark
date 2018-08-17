// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This file is for format-specific functions that are used by multiple modules.

#define DE_NOT_IN_MODULE
#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

void de_fmtutil_get_bmp_compression_name(de_uint32 code, char *s, size_t s_len,
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
int de_fmtutil_get_bmpinfo(deark *c, dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags)
{
	de_int64 fhs; // file header size
	de_int64 bmih_pos;
	struct de_fourcc cmpr4cc;
	char cmprname_dbgstr[80];

	de_memset(bi, 0, sizeof(struct de_bmpinfo));
	de_memset(&cmpr4cc, 0, sizeof(struct de_fourcc));

	fhs = (flags & DE_BMPINFO_HAS_FILEHEADER) ? 14 : 0;

	if(fhs+len < 16) return 0;

	if(fhs) {
		if(flags & DE_BMPINFO_HAS_HOTSPOT) {
			bi->hotspot_x = dbuf_getui16le(f, pos+6);
			bi->hotspot_y = dbuf_getui16le(f, pos+8);
			de_dbg(c, "hotspot: (%d,%d)", (int)bi->hotspot_x, (int)bi->hotspot_y);
		}

		bi->bitsoffset = dbuf_getui32le(f, pos+10);
		de_dbg(c, "bits offset: %d", (int)bi->bitsoffset);
	}

	bmih_pos = pos + fhs;

	bi->infohdrsize = dbuf_getui32le(f, bmih_pos);

	if(bi->infohdrsize==0x474e5089 && (flags & DE_BMPINFO_ICO_FORMAT)) {
		// We don't examine PNG-formatted icons, but we can identify them.
		bi->infohdrsize = 0;
		bi->file_format = DE_BMPINFO_FMT_PNG;
		return 1;
	}

	de_dbg(c, "info header size: %d", (int)bi->infohdrsize);

	if(bi->infohdrsize==12) {
		bi->bytes_per_pal_entry = 3;
		bi->width = dbuf_getui16le(f, bmih_pos+4);
		bi->height = dbuf_getui16le(f, bmih_pos+6);
		bi->bitcount = dbuf_getui16le(f, bmih_pos+10);
	}
	else if(bi->infohdrsize>=16 && bi->infohdrsize<=124) {
		bi->bytes_per_pal_entry = 4;
		bi->width = dbuf_getui32le(f, bmih_pos+4);
		bi->height = dbuf_geti32le(f, bmih_pos+8);
		if(bi->height<0) {
			bi->is_topdown = 1;
			bi->height = -bi->height;
		}
		bi->bitcount = dbuf_getui16le(f, bmih_pos+14);
		if(bi->infohdrsize>=20) {
			bi->compression_field = (de_uint32)dbuf_getui32le(f, bmih_pos+16);
			if(flags & DE_BMPINFO_CMPR_IS_4CC) {
				dbuf_read_fourcc(f, bmih_pos+16, &cmpr4cc, 4, 0x0);
			}
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

	de_dbg_dimensions(c, bi->width, bi->height);
	de_dbg(c, "bit count: %d", (int)bi->bitcount);

	if((flags & DE_BMPINFO_CMPR_IS_4CC) && (bi->compression_field>0xffff)) {
		de_snprintf(cmprname_dbgstr, sizeof(cmprname_dbgstr), "'%s'", cmpr4cc.id_dbgstr);
	}
	else {
		de_fmtutil_get_bmp_compression_name(bi->compression_field,
			cmprname_dbgstr, sizeof(cmprname_dbgstr), 0);
	}
	de_dbg(c, "compression: %u (%s)", (unsigned int)bi->compression_field, cmprname_dbgstr);

	de_dbg(c, "palette entries: %u", (unsigned int)bi->pal_entries);
	if(bi->pal_entries>256 && bi->bitcount>8) {
		de_warn(c, "Ignoring bad palette size (%u entries)", (unsigned int)bi->pal_entries);
		bi->pal_entries = 0;
	}

	bi->pal_bytes = bi->bytes_per_pal_entry*bi->pal_entries;
	bi->size_of_headers_and_pal = fhs + bi->infohdrsize + bi->pal_bytes;
	if(bi->compression_field==3) {
		bi->size_of_headers_and_pal += 12; // BITFIELDS
	}

	if(!de_good_image_dimensions(c, bi->width, bi->height)) {
		return 0;
	}

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
void de_fmtutil_generate_bmpfileheader(deark *c, dbuf *outf, const struct de_bmpinfo *bi,
	de_int64 file_size_override)
{
	de_int64 file_size_to_write;

	dbuf_write(outf, (const de_byte*)"BM", 2);

	if(file_size_override)
		file_size_to_write = file_size_override;
	else
		file_size_to_write = 14 + bi->total_size;
	dbuf_writeui32le(outf, file_size_to_write);

	dbuf_write_zeroes(outf, 4);
	dbuf_writeui32le(outf, 14 + bi->size_of_headers_and_pal);
}

void de_fmtutil_handle_exif2(deark *c, de_int64 pos, de_int64 len,
	de_uint32 *returned_flags, de_uint32 *orientation, de_uint32 *exifversion)
{
	de_module_params *mparams = NULL;

	if(returned_flags) {
		*returned_flags = 0;
	}

	if(c->extract_level>=2) {
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

void de_fmtutil_handle_exif(deark *c, de_int64 pos, de_int64 len)
{
	de_fmtutil_handle_exif2(c, pos, len, NULL, NULL, NULL);
}

// Either extract the IPTC data to a file, or drill down into it,
// depending on the value of c->extract_level.
void de_fmtutil_handle_iptc(deark *c, dbuf *f, de_int64 pos, de_int64 len)
{
	if(len<1) return;

	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(f, pos, len, "iptc", NULL, DE_CREATEFLAG_IS_AUX);
		return;
	}

	de_run_module_by_id_on_slice(c, "iptc", NULL, f, pos, len);
}

void de_fmtutil_handle_photoshop_rsrc2(deark *c, dbuf *f, de_int64 pos, de_int64 len,
	de_uint32 *returned_flags)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "R";
	de_run_module_by_id_on_slice(c, "psd", mparams, f, pos, len);
	if(returned_flags) {
		*returned_flags = mparams->out_params.flags;
	}
	de_free(c, mparams);
}

void de_fmtutil_handle_photoshop_rsrc(deark *c, dbuf *f, de_int64 pos, de_int64 len)
{
	de_fmtutil_handle_photoshop_rsrc2(c, f, pos, len, NULL);
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

// A 16-bit variant of de_fmtutil_uncompress_packbits().
int de_fmtutil_uncompress_packbits16(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels, de_int64 *cmpr_bytes_consumed)
{
	de_int64 pos;
	de_byte b, b1, b2;
	de_int64 k;
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
			b1 = dbuf_getbyte(f, pos++);
			b2 = dbuf_getbyte(f, pos++);
			for(k=0; k<count; k++) {
				dbuf_writebyte(unc_pixels, b1);
				dbuf_writebyte(unc_pixels, b2);
			}
		}
		else if(b<128) { // An uncompressed run
			count = 1 + (de_int64)b;
			dbuf_copy(f, pos, count*2, unc_pixels);
			pos += count*2;
		}
		// Else b==128. No-op.
	}

	if(cmpr_bytes_consumed) *cmpr_bytes_consumed = pos - pos1;
	return 1;
}

static de_int64 sauce_space_padded_length(const de_byte *buf, de_int64 len)
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

// TODO: I don't think there's any reason we couldn't read SAUCE strings
// directly to ucstrings, without doing it via a temporary buffer.

// flags: 0x01: Interpret string as a date
// flags: 0x02: Interpret 0x0a as newline, regardless of encoding
static void sauce_bytes_to_ucstring(deark *c, const de_byte *buf, de_int64 len,
	de_ucstring *s, int encoding, unsigned int flags)
{
	de_int32 u;
	de_int64 i;

	for(i=0; i<len; i++) {
		if((flags&0x01) && (i==4 || i==6)) {
			ucstring_append_char(s, '-');
		}
		if((flags&0x02) && buf[i]==0x0a) {
			u = 0x000a;
		}
		else {
			u = de_char_to_unicode(c, (de_int32)buf[i], encoding);
		}
		if((flags&0x01) && u==32) u=48; // Change space to 0 in dates.
		ucstring_append_char(s, u);
	}
}

static int sauce_is_valid_date_string(const de_byte *buf, de_int64 len)
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

int de_detect_SAUCE(deark *c, dbuf *f, struct de_SAUCE_detection_data *sdd)
{
	if(!sdd->detection_attempted) {
		sdd->detection_attempted = 1;
		if(f->len<128) return 0;
		if(dbuf_memcmp(f, f->len-128, "SAUCE00", 7)) return 0;
		sdd->has_SAUCE = 1;
		sdd->data_type = dbuf_getbyte(f, f->len-128+94);
		sdd->file_type = dbuf_getbyte(f, f->len-128+95);
	}
	return (int)sdd->has_SAUCE;
}

static const char *get_sauce_datatype_name(de_byte dt)
{
	const char *n = "?";

	switch(dt) {
	case 0: n="undefined"; break;
	case 1: n="character"; break;
	case 2: n="bitmap graphics"; break;
	case 3: n="vector graphics"; break;
	case 4: n="audio"; break;
	case 5: n="BinaryText"; break;
	case 6: n="XBIN"; break;
	case 7: n="archive"; break;
	case 8: n="executable"; break;
	}
	return n;
}

static const char *get_sauce_filetype_name(de_byte dt, unsigned int t)
{
	const char *n = "?";

	if(dt==5) return "=width/2";
	switch(t) {
	case 0x0100: n="ASCII"; break;
	case 0x0101: n="ANSI"; break;
	case 0x0102: n="ANSiMation"; break;
	case 0x0103: n="RIP script"; break;
	case 0x0104: n="PCBoard"; break;
	case 0x0105: n="Avatar"; break;
	case 0x0106: n="HTML"; break;
	case 0x0108: n="TundraDraw"; break;
	case 0x0200: n="GIF"; break;
	case 0x0206: n="BMP"; break;
	case 0x020a: n="PNG"; break;
	case 0x020b: n="JPEG"; break;
	case 0x0600: n="XBIN"; break;
	case 0x0800: n="executable"; break;
	}
	// There are many more SAUCE file types defined, but it's not clear how
	// many have actually been used.

	return n;
}

// Write a buffer to a file, converting the encoding to UTF-8.
static void write_buffer_as_utf8(deark *c, const de_byte *buf, de_int64 len,
	dbuf *outf, int from_encoding)
{
	de_int32 u;
	de_int64 i;

	for(i=0; i<len; i++) {
		u = de_char_to_unicode(c, (de_int32)buf[i], from_encoding);
		dbuf_write_uchar_as_utf8(outf, u);
	}
}

// This may modify si->num_comments.
static void sauce_read_comments(deark *c, dbuf *inf, struct de_SAUCE_info *si)
{
	de_int64 cmnt_blk_start;
	de_int64 k;
	de_int64 cmnt_pos;
	de_int64 cmnt_len;
	de_byte buf[64];

	if(si->num_comments<1) goto done;
	cmnt_blk_start = inf->len - 128 - (5 + si->num_comments*64);

	if(dbuf_memcmp(inf, cmnt_blk_start, "COMNT", 5)) {
		de_dbg(c, "invalid SAUCE comment, not found at %d", (int)cmnt_blk_start);
		si->num_comments = 0;
		goto done;
	}

	de_dbg(c, "SAUCE comment block at %d", (int)cmnt_blk_start);

	si->comments = de_malloc(c, si->num_comments * sizeof(struct de_char_comment));

	de_dbg_indent(c, 1);
	for(k=0; k<si->num_comments; k++) {
		cmnt_pos = cmnt_blk_start+5+k*64;
		dbuf_read(inf, buf, cmnt_pos, 64);
		cmnt_len = sauce_space_padded_length(buf, 64);

		si->comments[k].s = ucstring_create(c);
		sauce_bytes_to_ucstring(c, buf, cmnt_len, si->comments[k].s, DE_ENCODING_CP437_G, 0x02);

		de_dbg(c, "comment at %d, len=%d", (int)cmnt_pos, (int)cmnt_len);

		if(c->extract_level>=2) {
			dbuf *outf = NULL;
			outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
			if(c->write_bom && !de_is_ascii(buf, cmnt_len)) {
				dbuf_write_uchar_as_utf8(outf, 0xfeff);
			}
			write_buffer_as_utf8(c, buf, cmnt_len, outf, DE_ENCODING_CP437_G);
			dbuf_close(outf);
		}
		else {
			de_dbg_indent(c, 1);
			de_dbg(c, "comment: \"%s\"", ucstring_getpsz(si->comments[k].s));
			de_dbg_indent(c, -1);
		}
	}
	de_dbg_indent(c, -1);

done:
	;
}

// SAUCE = Standard Architecture for Universal Comment Extensions
// Caller allocates si.
// This function may allocate si->title, artist, organization, creation_date.
int de_read_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si)
{
	unsigned int t;
	de_byte tmpbuf[40];
	de_int64 tmpbuf_len;
	de_int64 pos;
	const char *name;
	de_ucstring *tflags_descr = NULL;

	if(!si) return 0;
	de_memset(si, 0, sizeof(struct de_SAUCE_info));

	pos = f->len - 128;
	if(dbuf_memcmp(f, pos+0, "SAUCE00", 7)) {
		return 0;
	}

	de_dbg(c, "SAUCE metadata at %d", (int)pos);
	de_dbg_indent(c, 1);

	// Title
	dbuf_read(f, tmpbuf, pos+7, 35);
	tmpbuf_len = sauce_space_padded_length(tmpbuf, 35);
	if(tmpbuf_len>0) {
		si->title = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->title, DE_ENCODING_CP437_G, 0);
	}

	// Artist / Creator
	dbuf_read(f, tmpbuf, pos+42, 20);
	tmpbuf_len = sauce_space_padded_length(tmpbuf, 20);
	if(tmpbuf_len>0) {
		si->artist = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->artist, DE_ENCODING_CP437_G, 0);
	}

	// Organization
	dbuf_read(f, tmpbuf, pos+62, 20);
	tmpbuf_len = sauce_space_padded_length(tmpbuf, 20);
	if(tmpbuf_len>0) {
		si->organization = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->organization, DE_ENCODING_CP437_G, 0);
	}

	// Creation date
	dbuf_read(f, tmpbuf, pos+82, 8);
	if(sauce_is_valid_date_string(tmpbuf, 8)) {
		tmpbuf_len = 8;
		si->creation_date = ucstring_create(c);
		sauce_bytes_to_ucstring(c, tmpbuf, tmpbuf_len, si->creation_date, DE_ENCODING_CP437_G, 0x01);
	}

	si->original_file_size = dbuf_getui32le(f, pos+90);
	de_dbg(c, "original file size: %d", (int)si->original_file_size);

	si->data_type = dbuf_getbyte(f, pos+94);
	name = get_sauce_datatype_name(si->data_type);
	de_dbg(c, "data type: %d (%s)", (int)si->data_type, name);

	si->file_type = dbuf_getbyte(f, pos+95);
	t = 256*(unsigned int)si->data_type + si->file_type;
	name = get_sauce_filetype_name(si->data_type, t);
	de_dbg(c, "file type: %d (%s)", (int)si->file_type, name);

	if(t==0x0100 || t==0x0101 || t==0x0102 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->width_in_chars = dbuf_getui16le(f, pos+96);
		de_dbg(c, "width in chars: %d", (int)si->width_in_chars);
	}
	if(t==0x0100 || t==0x0101 || t==0x0104 || t==0x0105 || t==0x0108 || t==0x0600) {
		si->number_of_lines = dbuf_getui16le(f, pos+98);
		de_dbg(c, "number of lines: %d", (int)si->number_of_lines);
	}

	si->num_comments = (de_int64)dbuf_getbyte(f, pos+104);
	de_dbg(c, "num comments: %d", (int)si->num_comments);
	if(si->num_comments>0) {
		sauce_read_comments(c, f, si);
	}

	si->tflags = dbuf_getbyte(f, pos+105);
	if(si->tflags!=0) {
		tflags_descr = ucstring_create(c);
		if(t==0x0100 || t==0x0101 || t==0x0102 || si->data_type==5) {
			// ANSiFlags
			if(si->tflags&0x01) {
				ucstring_append_flags_item(tflags_descr, "non-blink mode");
			}
			if((si->tflags & 0x06)>>1 == 1) {
				ucstring_append_flags_item(tflags_descr, "8-pixel font");
			}
			else if((si->tflags & 0x06)>>1 == 2) {
				ucstring_append_flags_item(tflags_descr, "9-pixel font");
			}
			if((si->tflags & 0x18)>>3 == 1) {
				ucstring_append_flags_item(tflags_descr, "non-square pixels");
			}
			else if((si->tflags & 0x18)>>3 == 2) {
				ucstring_append_flags_item(tflags_descr, "square pixels");
			}

		}
		de_dbg(c, "tflags: 0x%02x (%s)", (unsigned int)si->tflags,
			ucstring_getpsz(tflags_descr));
	}

	if(si->original_file_size==0 || si->original_file_size>f->len-128) {
		// If this field seems bad, try to correct it.
		si->original_file_size = f->len-128-(5+si->num_comments*64);
	}

	de_dbg_indent(c, -1);
	ucstring_destroy(tflags_descr);
	return 1;
}

void de_free_SAUCE(deark *c, struct de_SAUCE_info *si)
{
	if(!si) return;
	ucstring_destroy(si->title);
	ucstring_destroy(si->artist);
	ucstring_destroy(si->organization);
	ucstring_destroy(si->creation_date);
	if(si->comments) {
		de_int64 k;
		for(k=0; k<si->num_comments; k++) {
			ucstring_destroy(si->comments[k].s);
		}
		de_free(c, si->comments);
	}
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
	de_int64 pos1, de_int64 len, de_int64 max_nboxes, int level);

// Make a printable version of a UUID (or a big-endian GUID).
// Caller supplies s.
void de_fmtutil_render_uuid(deark *c, const de_byte *uuid, char *s, size_t s_len)
{
	de_snprintf(s, s_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

// Swap some bytes to convert a (little-endian) GUID to a UUID, in-place
void de_fmtutil_guid_to_uuid(de_byte *id)
{
	de_byte tmp[16];
	de_memcpy(tmp, id, 16);
	id[0] = tmp[3]; id[1] = tmp[2]; id[2] = tmp[1]; id[3] = tmp[0];
	id[4] = tmp[5]; id[5] = tmp[4];
	id[6] = tmp[7]; id[7] = tmp[6];
}

#define DE_BOX_uuid 0x75756964U

static int do_box(deark *c, struct de_boxesctx *bctx, de_int64 pos, de_int64 len,
	int level, de_int64 *pbytes_consumed)
{
	de_int64 size32, size64;
	de_int64 header_len; // Not including UUIDs
	de_int64 payload_len; // Including UUIDs
	de_int64 total_len;
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
		de_dbg(c, "(ignoring %d extra bytes at %"INT64_FMT")", (int)len, pos);
		goto done;
	}

	size32 = dbuf_getui32be(bctx->f, pos);
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
			de_dbg(c, "(ignoring %d extra bytes at %"INT64_FMT")", (int)len, pos);
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
			de_fmtutil_render_uuid(c, curbox->uuid, uuid_string, sizeof(uuid_string));
			de_dbg(c, "box '%s'{%s}%s at %"INT64_FMT", len=%"INT64_FMT,
				box4cc.id_dbgstr, uuid_string, name_str,
				pos, total_len);
		}
		else {
			de_dbg(c, "box '%s'%s at %"INT64_FMT", len=%"INT64_FMT", dlen=%"INT64_FMT,
				box4cc.id_dbgstr, name_str, pos,
				total_len, payload_len);
		}
	}

	if(total_len > len) {
		de_err(c, "Invalid oversized box, or unexpected end of file "
			"(box at %"INT64_FMT" ends at %"INT64_FMT", "
			"parent ends at %"INT64_FMT")",
			pos, pos+total_len, pos+len);
		goto done;
	}

	de_dbg_indent(c, 1);
	ret = bctx->handle_box_fn(c, bctx);
	de_dbg_indent(c, -1);
	if(!ret) goto done;

	if(curbox->is_superbox) {
		de_int64 children_pos, children_len;
		de_int64 max_nchildren;

		de_dbg_indent(c, 1);
		children_pos = pos+header_len + curbox->extra_bytes_before_children;
		children_len = payload_len - curbox->extra_bytes_before_children;
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
	de_int64 pos1, de_int64 len, de_int64 max_nboxes, int level)
{
	de_int64 pos;
	de_int64 box_len;
	de_int64 endpos;
	int ret;
	de_int64 box_count = 0;

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
int de_fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx)
{
	struct de_boxdata *curbox = bctx->curbox;

	if(curbox->is_uuid) {
		if(!de_memcmp(curbox->uuid, "\xb1\x4b\xf8\xbd\x08\x3d\x4b\x43\xa5\xae\x8c\xd7\xd5\xa6\xce\x03", 16)) {
			de_dbg(c, "GeoTIFF data at %d, len=%d", (int)curbox->payload_pos, (int)curbox->payload_len);
			dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len, "geo.tif", NULL, DE_CREATEFLAG_IS_AUX);
		}
		else if(!de_memcmp(curbox->uuid, "\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac", 16)) {
			de_dbg(c, "XMP data at %d, len=%d", (int)curbox->payload_pos, (int)curbox->payload_len);
			dbuf_create_file_from_slice(bctx->f, curbox->payload_pos, curbox->payload_len, "xmp", NULL, DE_CREATEFLAG_IS_AUX);
		}
		else if(!de_memcmp(curbox->uuid, "\x2c\x4c\x01\x00\x85\x04\x40\xb9\xa0\x3e\x56\x21\x48\xd6\xdf\xeb", 16)) {
			de_dbg(c, "Photoshop resources at %d, len=%d", (int)curbox->payload_pos, (int)curbox->payload_len);
			de_fmtutil_handle_photoshop_rsrc(c, bctx->f, curbox->payload_pos, curbox->payload_len);
		}
		else if(!de_memcmp(curbox->uuid, "\x05\x37\xcd\xab\x9d\x0c\x44\x31\xa7\x2a\xfa\x56\x1f\x2a\x11\x3e", 16)) {
			de_dbg(c, "Exif data at %d, len=%d", (int)curbox->payload_pos, (int)curbox->payload_len);
			de_fmtutil_handle_exif(c, curbox->payload_pos, curbox->payload_len);
		}
	}
	return 1;
}

void de_fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx)
{
	if(!bctx->f || !bctx->handle_box_fn) return; // Internal error
	if(bctx->curbox) return; // Internal error
	do_box_sequence(c, bctx, 0, bctx->f->len, -1, 0);
}

static de_byte scale_7_to_255(de_byte x)
{
	return (de_byte)(0.5+(((double)x)*(255.0/7.0)));
}

static de_byte scale_15_to_255(de_byte x)
{
	return x*17;
}

void de_fmtutil_read_atari_palette(deark *c, dbuf *f, de_int64 pos,
	de_uint32 *dstpal, de_int64 ncolors_to_read, de_int64 ncolors_used, unsigned int flags)
{
	de_int64 i;
	unsigned int n;
	int pal_bits = 0; // 9, 12, or 15. 0 = not yet determined
	de_byte cr, cg, cb;
	de_byte cr1, cg1, cb1;
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
			n = (unsigned int)dbuf_getui16be(f, pos + i*2);
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
		n = (unsigned int)dbuf_getui16be(f, pos + 2*i);

		if(pal_bits==15) {
			cr1 = (de_byte)((n>>6)&0x1c);
			if(n&0x0800) cr1+=2;
			if(n&0x8000) cr1++;
			cg1 = (de_byte)((n>>2)&0x1c);
			if(n&0x0080) cg1+=2;
			if(n&0x4000) cg1++;
			cb1 = (de_byte)((n<<2)&0x1c);
			if(n&0x0008) cb1+=2;
			if(n&0x2000) cb1++;
			cr = de_scale_n_to_255(31, cr1);
			cg = de_scale_n_to_255(31, cg1);
			cb = de_scale_n_to_255(31, cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%2d,%2d,%2d",
				(int)cr1, (int)cg1, (int)cb1);
		}
		else if(pal_bits==12) {
			cr1 = (de_byte)((n>>7)&0x0e);
			if(n&0x800) cr1++;
			cg1 = (de_byte)((n>>3)&0x0e);
			if(n&0x080) cg1++;
			cb1 = (de_byte)((n<<1)&0x0e);
			if(n&0x008) cb1++;
			cr = scale_15_to_255(cr1);
			cg = scale_15_to_255(cg1);
			cb = scale_15_to_255(cb1);
			de_snprintf(cbuf, sizeof(cbuf), "%2d,%2d,%2d",
				(int)cr1, (int)cg1, (int)cb1);
		}
		else {
			cr1 = (de_byte)((n>>8)&0x07);
			cg1 = (de_byte)((n>>4)&0x07);
			cb1 = (de_byte)(n&0x07);
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
static unsigned int spectrum512_FindIndex(de_int64 x, unsigned int c)
{
	int x1;

	x1 = 10 * c;

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
	de_int64 i, j;
	de_int64 plane;
	de_int64 rowspan;
	de_byte b;
	de_uint32 v;
	de_int64 planespan;
	de_int64 ncolors;

	planespan = 2*((adata->w+15)/16);
	rowspan = planespan*adata->bpp;
	if(adata->ncolors>0)
		ncolors = adata->ncolors;
	else
		ncolors = ((de_int64)1)<<adata->bpp;

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
	de_int64 i, j;
	de_int64 rowspan;
	de_uint32 v;

	rowspan = adata->w * 2;

	for(j=0; j<adata->h; j++) {
		for(i=0; i<adata->w; i++) {
			v = (de_uint32)dbuf_getui16be(adata->unc_pixels, j*rowspan + 2*i);
			v = de_rgb565_to_888(v);
			de_bitmap_setpixel_rgb(adata->img, i, j,v);
		}
	}
	return 1;
}

int de_fmtutil_atari_decode_image(deark *c, struct atari_img_decode_data *adata)
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

void de_fmtutil_atari_set_standard_density(deark *c, struct atari_img_decode_data *adata)
{
	switch(adata->bpp) {
	case 4:
		adata->img->density_code = DE_DENSITY_UNK_UNITS;
		adata->img->xdens = 240.0;
		adata->img->ydens = 200.0;
		break;
	case 2:
		adata->img->density_code = DE_DENSITY_UNK_UNITS;
		adata->img->xdens = 480.0;
		adata->img->ydens = 200.0;
		break;
	case 1:
		adata->img->density_code = DE_DENSITY_UNK_UNITS;
		adata->img->xdens = 480.0;
		adata->img->ydens = 400.0;
		break;
	}
}

#define CODE__c_   0x28632920U // "(c) "
#define CODE_ANNO  0x414e4e4fU
#define CODE_AUTH  0x41555448U
#define CODE_NAME  0x4e414d45U
#define CODE_TEXT  0x54455854U
#define CODE_RIFF  0x52494646U

static void do_iff_text_chunk(deark *c, dbuf *f, de_int64 dpos, de_int64 dlen,
	const char *name)
{
	de_ucstring *s = NULL;

	if(dlen<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(f,
		dpos, dlen, DE_DBG_MAX_STRLEN,
		s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_iff_anno(deark *c, dbuf *f, de_int64 pos, de_int64 len)
{
	de_int64 foundpos;

	if(len<1) return;

	// Some ANNO chunks seem to be padded with one or more NUL bytes. Probably
	// best not to save them.
	if(dbuf_search_byte(f, 0x00, pos, len, &foundpos)) {
		len = foundpos - pos;
	}
	if(len<1) return;
	if(c->extract_level>=2) {
		dbuf_create_file_from_slice(f, pos, len, "anno.txt", NULL, DE_CREATEFLAG_IS_AUX);
	}
	else {
		de_ucstring *s = NULL;
		s = ucstring_create(c);
		dbuf_read_to_ucstring_n(f, pos, len, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_ASCII);
		de_dbg(c, "annotation: \"%s\"", ucstring_getpsz(s));
		ucstring_destroy(s);
	}
}

void de_fmtutil_default_iff_chunk_identify(deark *c, struct de_iffctx *ictx)
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

// TODO: This function used to be exported, but it's probably no longer
// needed for that. It should be refactored to at least have a
// "struct de_iffctx *ictx" param.
//
// Note that some of these chunks are *not* defined in the generic IFF
// specification.
// They might be defined in the 8SVX specification. They seem to have
// become unofficial standard chunks.
static void de_fmtutil_handle_standard_iff_chunk(deark *c, dbuf *f, de_int64 dpos, de_int64 dlen,
	de_uint32 chunktype)
{
	switch(chunktype) {
		// Note that chunks appearing here should also be listed below,
		// in de_fmtutil_is_standard_iff_chunk().
	case CODE__c_:
		do_iff_text_chunk(c, f, dpos, dlen, "copyright");
		break;
	case CODE_ANNO:
		do_iff_anno(c, f, dpos, dlen);
		break;
	case CODE_AUTH:
		do_iff_text_chunk(c, f, dpos, dlen, "author");
		break;
	case CODE_NAME:
		do_iff_text_chunk(c, f, dpos, dlen, "name");
		break;
	case CODE_TEXT:
		do_iff_text_chunk(c, f, dpos, dlen, "text");
		break;
	}
}

// ictx can be NULL
int de_fmtutil_is_standard_iff_chunk(deark *c, struct de_iffctx *ictx,
	de_uint32 ct)
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

static int de_fmtutil_default_iff_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	de_fmtutil_handle_standard_iff_chunk(c, ictx->f,
		ictx->chunkctx->dpos, ictx->chunkctx->dlen,
		ictx->chunkctx->chunk4cc.id);
	// Note we do not set ictx->handled. The caller is responsible for that.
	return 1;
}

static void fourcc_clear(struct de_fourcc *fourcc)
{
	de_memset(fourcc, 0, sizeof(struct de_fourcc));
}

static int do_iff_chunk_sequence(deark *c, struct de_iffctx *ictx,
	de_int64 pos1, de_int64 len, int level);

// Returns 0 if we can't continue
static int do_iff_chunk(deark *c, struct de_iffctx *ictx, de_int64 pos, de_int64 bytes_avail,
	int level, de_int64 *pbytes_consumed)
{
	int ret;
	de_int64 chunk_dlen_raw;
	de_int64 chunk_dlen_padded;
	de_int64 data_bytes_avail;
	de_int64 hdrsize;
	struct de_iffchunkctx chunkctx;
	int saved_indent_level;
	int retval = 0;
	char name_str[80];

	de_memset(&chunkctx, 0, sizeof(struct de_iffchunkctx));

	de_dbg_indent_save(c, &saved_indent_level);

	hdrsize = 4+ictx->sizeof_len;
	if(bytes_avail<hdrsize) {
		de_warn(c, "Ignoring %"INT64_FMT" bytes at %"INT64_FMT"; too small "
			"to be a chunk", bytes_avail, pos);
		goto done;
	}
	data_bytes_avail = bytes_avail-hdrsize;

	dbuf_read_fourcc(ictx->f, pos, &chunkctx.chunk4cc, 4,
		ictx->reversed_4cc ? DE_4CCFLAG_REVERSED : 0x0);
	if(chunkctx.chunk4cc.id==0 && level==0) {
		de_warn(c, "Chunk ID not found at %"INT64_FMT"; assuming the data ends "
			"here", pos);
		goto done;
	}

	if(ictx->sizeof_len==2) {
		chunk_dlen_raw = dbuf_getui16x(ictx->f, pos+4, ictx->is_le);
	}
	else {
		chunk_dlen_raw = dbuf_getui32x(ictx->f, pos+4, ictx->is_le);
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

	de_dbg(c, "chunk '%s'%s at %"INT64_FMT", dpos=%"INT64_FMT", dlen=%"INT64_FMT,
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
				"(chunk at %d ends at %" INT64_FMT ", "
				"parent ends at %" INT64_FMT ")",
				(int)pos, chunkctx.dlen+chunkctx.dpos, pos+bytes_avail);
		}

		chunkctx.dlen = data_bytes_avail; // Try to continue
		de_dbg(c, "adjusting chunk data len to %"INT64_FMT, chunkctx.dlen);
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
		de_int64 contents_dpos, contents_dlen;

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
	de_int64 pos1, de_int64 len, int level)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 chunk_len;
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

		ret = do_iff_chunk(c, ictx, pos, endpos-pos, level, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	ictx->curr_container_fmt4cc = saved_container_fmt4cc;
	ictx->curr_container_contentstype4cc = saved_container_contentstype4cc;

	return 1;
}

void de_fmtutil_read_iff_format(deark *c, struct de_iffctx *ictx,
	de_int64 pos, de_int64 len)
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

	do_iff_chunk_sequence(c, ictx, pos, len, 0);
}

const char *de_fmtutil_tiff_orientation_name(de_int64 n)
{
	static const char *names[9] = {
		"?", "top-left", "top-right", "bottom-right", "bottom-left",
		"left-top", "right-top", "right-bottom", "left-bottom"
	};
	if(n>=1 && n<=8) return names[n];
	return names[0];
}

const char *de_fmtutil_get_windows_charset_name(de_byte cs)
{
	struct csname_struct { de_byte id; const char *name; };
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

	for(i=0; i<DE_ITEMS_IN_ARRAY(csname_arr); i++) {
		if(cs==csname_arr[i].id) return csname_arr[i].name;
	}
	return "?";
}

const char *de_fmtutil_get_windows_cb_data_type_name(unsigned int ty)
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
int de_fmtutil_find_zip_eocd(deark *c, dbuf *f, de_int64 *foundpos)
{
	de_uint32 sig;
	de_byte *buf = NULL;
	int retval = 0;
	de_int64 buf_offset;
	de_int64 buf_size;
	de_int64 i;

	*foundpos = 0;
	if(f->len < 22) goto done;

	// End-of-central-dir record usually starts 22 bytes from EOF. Try that first.
	sig = (de_uint32)dbuf_getui32le(f, f->len - 22);
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
