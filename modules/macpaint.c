// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// MacPaint image format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_macpaint);

#define MACPAINT_WIDTH 576
#define MACPAINT_WIDTH_BYTES (MACPAINT_WIDTH/8)
#define MACPAINT_HEIGHT 720
#define MACPAINT_IMAGE_BYTES (MACPAINT_WIDTH_BYTES*MACPAINT_HEIGHT)

typedef struct localctx_struct {
	int has_macbinary_header;
	u8 is_fmac2com;
	u8 df_known, rf_known;
	u8 row_issue_flag;
	i64 expected_dfpos, expected_rfpos;
	i64 expected_dflen, expected_rflen;
	de_ucstring *filename;
	struct de_timestamp mod_time_from_macbinary;
	i64 hdr_pos;
	i64 img_data_pos;
} lctx;

// We'd like to use fmtutil_decompress_packbits_ex() instead of this custom
// decompressor, but it would make it difficult to test for row boundary
// violations.
// Alternatively, merging this and test_valid_image() is something to consider,
// but probably not worth it.
static void decompress_packbits_for_macpaint(deark *c, lctx *d,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	i64 pos;
	u8 b, b2;
	i64 count;
	i64 endpos;
	i64 xpos_b = 0;
	i64 nbytes_written = 0;

	pos = dcmpri->pos;
	endpos = dcmpri->pos + dcmpri->len;
	d->row_issue_flag = 0;

	while(1) {
		if(dcmpro->len_known && nbytes_written >= dcmpro->expected_len) {
			goto done; // Decompressed the requested amount of dst data.
		}
		if(pos+2 > endpos) { // Min item size is 2 bytes
			goto done; // Reached the end of source data
		}

		b = dbuf_getbyte_p(dcmpri->f, &pos);

		if(b<=127) { // An uncompressed run
			count = 1 + (i64)b;
			if(pos+count > endpos) {
				pos--;
				goto done;
			}

			xpos_b += count;
			dbuf_copy(dcmpri->f, pos, count, dcmpro->f);
			pos += count;
			nbytes_written += count;
		}
		else if(b>=129) { // A compressed run
			count = 257 - (i64)b;
			xpos_b += count;
			b2 = dbuf_getbyte_p(dcmpri->f, &pos);
			dbuf_write_run(dcmpro->f, b2, count);
			nbytes_written += count;
		}

		if(xpos_b==MACPAINT_WIDTH_BYTES) {
			xpos_b = 0;
		}
		else if(xpos_b > MACPAINT_WIDTH_BYTES) {
			d->row_issue_flag = 1;
			xpos_b = xpos_b % MACPAINT_WIDTH_BYTES;
		}
	}

done:
	dbuf_flush(dcmpro->f);
	dres->bytes_consumed = pos - dcmpri->pos;
	dres->bytes_consumed_valid = 1;
}

static void do_read_bitmap(deark *c, lctx *d)
{
	i64 cmpr_bytes_consumed = 0;
	dbuf *unc_pixels = NULL;
	de_finfo *fi = NULL;
	int saved_indent_level;
	i64 ipos;
	struct de_packbits_params *pbparams = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!d->is_fmac2com) {
		i64 ver_num;

		de_dbg(c, "header at %"I64_FMT, d->hdr_pos);
		de_dbg_indent(c, 1);
		ver_num = de_getu32be(d->hdr_pos);
		de_dbg(c, "version number: %u", (unsigned int)ver_num);
		if(ver_num!=0 && ver_num!=2 && ver_num!=3) {
			de_warn(c, "Unrecognized version number: %u", (unsigned int)ver_num);
		}

		// We wait until later to read the brush patterns, only so that the patterns
		// won't be the first file extracted.

		de_dbg_indent(c, -1);
	}

	ipos = d->img_data_pos;
	de_dbg(c, "image data at %"I64_FMT, ipos);
	de_dbg_indent(c, 1);
	unc_pixels = dbuf_create_membuf(c, MACPAINT_IMAGE_BYTES, 1);
	dbuf_enable_wbuffer(unc_pixels);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = ipos;
	dcmpri.len = c->infile->len - ipos;
	dcmpro.f = unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = MACPAINT_IMAGE_BYTES;
	pbparams = de_malloc(c, sizeof(struct de_packbits_params));

	decompress_packbits_for_macpaint(c, d, &dcmpri, &dcmpro, &dres);
	dbuf_flush(unc_pixels);

	cmpr_bytes_consumed = dres.bytes_consumed;
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", cmpr_bytes_consumed,
		unc_pixels->len);

	if(d->df_known) {
		if(ipos+cmpr_bytes_consumed > d->expected_dfpos+d->expected_dflen) {
			de_warn(c, "Image (ends at %"I64_FMT") goes beyond end of "
				"MacBinary data fork (ends at %"I64_FMT")",
				ipos+cmpr_bytes_consumed, d->expected_dfpos+d->expected_dflen);
		}
	}

	if(unc_pixels->len < MACPAINT_IMAGE_BYTES) {
		de_warn(c, "Image decompressed to %"I64_FMT" bytes, expected %u.",
			unc_pixels->len, (UI)MACPAINT_IMAGE_BYTES);
	}
	else if(d->row_issue_flag) {
		de_warn(c, "Rows not compressed independently. Decompression may have failed.");
	}

	fi = de_finfo_create(c);
	if(d->filename && c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, d->filename, 0);
	}

	if(d->mod_time_from_macbinary.is_valid) {
		fi->internal_mod_time = d->mod_time_from_macbinary;
	}

	de_convert_and_write_image_bilevel(unc_pixels, 0,
		MACPAINT_WIDTH, MACPAINT_HEIGHT, MACPAINT_WIDTH/8,
		DE_CVTF_WHITEISZERO, fi, 0);

	dbuf_close(unc_pixels);
	de_finfo_destroy(c, fi);
	de_free(c, pbparams);
	de_dbg_indent_restore(c, saved_indent_level);
}

struct validity_info {
	i64 pos;
	int retval;
	char msg[80];
};

// A function to help determine if the file has a MacBinary header.
// Each row is RLE-compressed independently, so once we assume one possibility
// or the other, we can do sanity checks to see if any code crosses a row
// boundary, or the image is too small to be a MacPaint image.
// It's inefficient to decompress whole image -- twice -- just to try to
// figure this out, but hopefully it's pretty reliable.
// Returns an integer (0, 1, 2...) reflecting the likelihood that this is the
// correct position.
// The special 'struct validity_info' is overkill, but it makes it easier to
// try different things.
static void test_valid_image(deark *c, lctx *d, struct validity_info *vi)
{
	u8 b;
	i64 count;
	i64 pos;
	i64 imgstart;
	i64 xpos_b = 0;
	i64 ypos = 0;
	int v = 0;

	imgstart = vi->pos+512;
	de_dbg(c, "checking for image at offset %d", (int)imgstart);
	de_dbg_indent(c, 1);

	// Minimum bytes per row is 2.
	// For a valid (non-truncated) file, file size must be at least
	// pos1 + 512 + 2*MACPAINT_HEIGHT. But we want to tolerate truncated
	// files as well.
	if(c->infile->len < imgstart + 4) {
		de_strlcpy(vi->msg, "file too small", sizeof(vi->msg));
		vi->retval = 0;
		goto done;
	}

	// Look for a boundary between all-0 bytes, and not-all-0 bytes.
	if(dbuf_is_all_zeroes(c->infile, imgstart-16, 16) &&
		!dbuf_is_all_zeroes(c->infile, imgstart, 8))
	{
		v++;
	}

	pos = imgstart;

	while(pos < c->infile->len) {
		if(ypos>=MACPAINT_HEIGHT) {
			break;
		}

		b = de_getbyte_p(&pos);

		if(b<=127) {
			count = 1+(i64)b;
			pos += count;
			xpos_b += count;
			if(xpos_b==MACPAINT_WIDTH_BYTES) {
				xpos_b = 0;
				ypos++;
			}
			else if(xpos_b > MACPAINT_WIDTH_BYTES) {
				de_strlcpy(vi->msg, "literal too long", sizeof(vi->msg));
				vi->retval = v+0;
				goto done;
			}
		}
		else if(b>=129) {
			count = 257 - (i64)b;
			pos++;
			xpos_b += count;
			if(xpos_b == MACPAINT_WIDTH_BYTES) {
				xpos_b = 0;
				ypos++;
			}
			else if(xpos_b > MACPAINT_WIDTH_BYTES) {
				de_strlcpy(vi->msg, "run too long", sizeof(vi->msg));
				vi->retval = v+0;
				goto done;
			}
		}
	}

	if(xpos_b==0 && ypos==MACPAINT_HEIGHT) {
		de_strlcpy(vi->msg, "decodes okay", sizeof(vi->msg));
		vi->retval = v+2;
		goto done;
	}

	de_snprintf(vi->msg, sizeof(vi->msg), "premature end of file (x=%d, y=%d)",
		(int)(xpos_b*8), (int)ypos);
	vi->retval = v+1;

done:
	de_dbg(c, "image at offset %d: %s", (int)(vi->pos+512), vi->msg);
	de_dbg_indent(c, -1);
}

static const char *get_pattern_set_info(u32 patcrc, int *is_blank)
{
	*is_blank = 0;
	switch(patcrc) {
	case 0x284a7a15: return "variant 1";
	case 0x33d2d8d6: return "standard";
	case 0x47514647: *is_blank = 1; return "blank";
	case 0xb5348fd2: *is_blank = 1; return "blank variant 1";
	}
	return "unrecognized";
}

// Some MacPaint files contain a collection of brush patterns.
// Essentially, MacPaint saves workspace settings inside image files.
// (But these patterns are the only setting.)
static void do_read_patterns(deark *c, lctx *d)
{
	i64 pos1;
	i64 cell;
	i64 i, j;
	const i64 dispwidth = 19;
	const i64 dispheight = 17;
	i64 xpos, ypos;
	int is_blank;
	de_bitmap *gallery = NULL;
	de_bitmap *rawimg = NULL;
	u32 patcrc;
	const char *patsetname;
	de_finfo *fi = NULL;
	de_ucstring *tmpname = NULL;
	struct de_crcobj *crc32o;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "header (continued)");
	de_dbg_indent(c, 1);
	pos1 = d->hdr_pos + 4;

	de_dbg(c, "brush patterns at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	crc32o = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addslice(crc32o, c->infile, pos1, 38*8);
	patcrc = de_crcobj_getval(crc32o);
	de_crcobj_destroy(crc32o);
	patsetname = get_pattern_set_info(patcrc, &is_blank);
	de_dbg(c, "brush patterns crc: 0x%08x (%s)", (unsigned int)patcrc, patsetname);

	rawimg = de_bitmap_create(c, 8, 38*8, 1);
	rawimg->is_internal = 1;
	de_convert_image_bilevel(c->infile, pos1, 1, rawimg, DE_CVTF_WHITEISZERO);

	if(c->extract_level<2) {
		goto done;
	}

	if(is_blank) {
		de_dbg(c, "brush patterns are blank: not extracting");
		goto done;
	}

	gallery = de_bitmap_create(c, (dispwidth+1)*19+1, (dispheight+1)*2+1, 1);

	for(cell=0; cell<38; cell++) {
		xpos = (dispwidth+1)*(cell%19)+1;
		ypos = (dispheight+1)*(cell/19)+1;

		for(j=0; j<dispheight; j++) {
			for(i=0; i<dispwidth; i++) {
				de_colorsample x;

				// TODO: Figure out the proper "brush origin" of these patterns.
				// Some of them may be shifted differently than MacPaint displays them.
				x = DE_COLOR_K(de_bitmap_getpixel(rawimg, i%8, 8*cell + j%8));
				de_bitmap_setpixel_gray(gallery, xpos+i, ypos+j, x);
			}
		}
	}

	tmpname = ucstring_create(c);
	if(d->filename && c->filenames_from_file) {
		ucstring_append_ucstring(tmpname, d->filename);
		ucstring_append_sz(tmpname, ".", DE_ENCODING_LATIN1);
	}
	ucstring_append_sz(tmpname, "pat", DE_ENCODING_LATIN1);
	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, tmpname, 0);
	de_bitmap_write_to_file_finfo(gallery, fi, DE_CREATEFLAG_IS_AUX|DE_CREATEFLAG_IS_BWIMG);

done:
	de_bitmap_destroy(gallery);
	de_bitmap_destroy(rawimg);
	de_finfo_destroy(c, fi);
	ucstring_destroy(tmpname);
	de_dbg_indent_restore(c, saved_indent_level);
}

// Not many MacPaint-in-MacBinary files have a resource fork, but a few do.
static void do_decode_rsrc(deark *c, lctx *d)
{
	if(!d->rf_known) return;
	if(d->expected_rflen<1) return;
	if(d->expected_rfpos+d->expected_rflen > c->infile->len) {
		return;
	}
	de_dbg(c, "resource fork at %"I64_FMT", len=%"I64_FMT, d->expected_rfpos, d->expected_rflen);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "macrsrc", NULL, c->infile,
		d->expected_rfpos, d->expected_rflen);
	de_dbg_indent(c, -1);
}

static void do_macbinary(deark *c, lctx *d)
{
	u8 b0, b1;
	de_module_params *mparams = NULL;

	b0 = de_getbyte(0);
	b1 = de_getbyte(1);

	// Instead of a real MacBinary header, a few macpaint files just have
	// 128 NUL bytes, or something like that. So we'll skip MacBinary parsing
	// in some cases.
	if(b0!=0) goto done;
	if(b1<1 || b1>63) goto done;

	de_dbg(c, "MacBinary header");
	de_dbg_indent(c, 1);
	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "D"; // = decode only, don't extract
	mparams->out_params.fi = de_finfo_create(c); // A temporary finfo object
	mparams->out_params.fi->name_other = ucstring_create(c);
	de_run_module_by_id_on_slice(c, "macbinary", mparams, c->infile, 0, c->infile->len);
	de_dbg_indent(c, -1);

	if(mparams->out_params.uint1>0) {
		d->df_known = 1;
		d->expected_dfpos = (i64)mparams->out_params.uint1;
		d->expected_dflen = (i64)mparams->out_params.uint2;
	}
	if(mparams->out_params.uint3>0) {
		d->rf_known = 1;
		d->expected_rfpos = (i64)mparams->out_params.uint3;
		d->expected_rflen = (i64)mparams->out_params.uint4;
	}

	if(mparams->out_params.fi->timestamp[DE_TIMESTAMPIDX_MODIFY].is_valid) {
		d->mod_time_from_macbinary = mparams->out_params.fi->timestamp[DE_TIMESTAMPIDX_MODIFY];
	}

	if(d->df_known) {
		if(d->expected_dfpos+d->expected_dflen>c->infile->len) {
			de_warn(c, "MacBinary data fork (ends at %"I64_FMT") "
				"goes past end of file (%"I64_FMT")",
			d->expected_dfpos+d->expected_dflen, c->infile->len);
			d->df_known = 0;
		}
	}

	if(ucstring_isnonempty(mparams->out_params.fi->name_other) && !d->filename) {
		d->filename = ucstring_clone(mparams->out_params.fi->name_other);
	}

	if(d->rf_known) {
		do_decode_rsrc(c, d);
	}

done:
	if(mparams) {
		de_finfo_destroy(c, mparams->out_params.fi);
		de_free(c, mparams);
	}
}

static u8 is_fmac2com(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, (const void*)"\xeb\x79\x90", 3)) return 0;
	if(dbuf_memcmp(c->infile, 608,
		(const void*)"\x80\x03\x83\xc3\x0f\xb1\x04\xd3\xeb\xb4\x4a\xcd\x21\xb4\x48\xbb", 16))
	{
		return 0;
	}
	return 1;
}

static void de_run_macpaint(deark *c, de_module_params *mparams)
{
	lctx *d;
	struct validity_info *vi1 = NULL;
	struct validity_info *vi2 = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->has_macbinary_header = de_get_ext_option_bool(c, "macpaint:macbinary", -1);

	if(d->has_macbinary_header == -1) {
		d->is_fmac2com = is_fmac2com(c);
	}

	if(d->is_fmac2com) {
		d->has_macbinary_header = 1;
	}

	if(d->has_macbinary_header == -1) {
		int v512;
		int v640;

		de_dbg(c, "trying to determine if file has a MacBinary header");
		de_dbg_indent(c, 1);

		vi1 = de_malloc(c, sizeof(struct validity_info));
		vi1->pos = 0;
		test_valid_image(c, d, vi1);
		v512 = vi1->retval;

		vi2 = de_malloc(c, sizeof(struct validity_info));
		vi2->pos = 128;
		test_valid_image(c, d, vi2);
		v640 = vi2->retval;

		de_dbg_indent(c, -1);

		if(v512 > v640) {
			de_dbg(c, "assuming it has no MacBinary header");
			d->has_macbinary_header = 0;
		}
		else if(v640 > v512) {
			de_dbg(c, "assuming it has a MacBinary header");
			d->has_macbinary_header = 1;
		}
		else if(v512 && v640) {
			de_warn(c, "Can't determine if this file has a MacBinary header. "
				"Try \"-opt macpaint:macbinary=0\".");
			d->has_macbinary_header = 1;
		}
		else {
			de_warn(c, "This is probably not a MacPaint file.");
			d->has_macbinary_header = 1;
		}
	}

	if(d->is_fmac2com)
		de_declare_fmt(c, "FMAC2COM self-displaying MacPaint");
	else if(d->has_macbinary_header)
		de_declare_fmt(c, "MacPaint with MacBinary header");
	else
		de_declare_fmt(c, "MacPaint without MacBinary header");

	if(d->has_macbinary_header) {
		d->hdr_pos = 128;
	}
	else {
		d->hdr_pos = 0;
	}
	d->img_data_pos = d->hdr_pos + 512;

	if(d->has_macbinary_header) {
		do_macbinary(c, d);
	}

	do_read_bitmap(c, d);

	if(!d->is_fmac2com) {
		do_read_patterns(c, d);
	}

	if(d) {
		ucstring_destroy(d->filename);
		de_free(c, d);
	}
	de_free(c, vi1);
	de_free(c, vi2);
}

// Note: This must be coordinated with the macbinary detection routine.
static int de_identify_macpaint(deark *c)
{
	u8 buf[8];

	if(is_fmac2com(c)) return 85;
	de_read(buf, 65, 8);

	// Not all MacPaint files can be easily identified, but this will work
	// for some of them.
	if(!de_memcmp(buf, "PNTG", 4)) {
		if(c->detection_data->is_macbinary) return 100;
		if(!de_memcmp(&buf[4], "MPNT", 4)) return 80;
		return 70;
	}

	if(de_input_file_has_ext(c, "mac")) return 10;
	if(de_input_file_has_ext(c, "macp")) return 15;
	if(de_input_file_has_ext(c, "pntg")) return 15;
	return 0;
}

static void de_help_macpaint(deark *c)
{
	de_msg(c, "-opt macpaint:macbinary=<0|1> : Assume file doesn't/does have "
		"a MacBinary header");
	de_msg(c, "-m macbinary : Extract from MacBinary container, instead of "
		"decoding");
}

void de_module_macpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "macpaint";
	mi->desc = "MacPaint image";
	mi->run_fn = de_run_macpaint;
	mi->identify_fn = de_identify_macpaint;
	mi->help_fn = de_help_macpaint;
}
