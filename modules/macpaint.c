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

#define CODE_PNTG 0x504e5447U
#define CODE_MPNT 0x4d504e54U

// Object representing one interpretation of the file -- either with, or
// without, a MacBinary header.
struct macp_interp_ctx {
	i64 hlen; // 0 or 128
	i64 pixels_pos; // 512+hlen
	i64 pixels_len;
	u8 idmode;
	UI ver_num;
	u8 known_ver;
	u8 known_macbinary;
	u8 file_ext_strength;
	u8 invalid_image;
	u8 image_pos_seems_correct;
	u8 unused_bytes_are_0;
	u8 pat_strength;
	u8 typecodes_strength;
	u8 cmpr_strength1;
	u8 row_issue_lit, row_issue_run;
	u8 inefficient_cmpr_flag;
	u8 uses_128;
	u8 unexp_eof_flag;
	u8 decompressed_ok;
	u8 skip_part2;
	UI final_xpos_b;
	UI final_ypos;
	int idmode_confidence;
	int runmode_confidence;
#define MACP_MSG_LEN 80
	char *msg;
	dbuf *unc_pixels;
	i64 bytes_consumed;
};

typedef struct localctx_MACP {
	int has_macbinary_header;
	u8 is_fmac2com;
	u8 df_known, rf_known;
	i64 expected_dfpos, expected_rfpos;
	i64 expected_dflen, expected_rflen;
	de_ucstring *filename;
	struct de_timestamp mod_time_from_macbinary;
} lctx;

static void decompress_main(deark *c, struct macp_interp_ctx *ic)
{
	u8 b;
	i64 count;
	i64 pos;
	i64 endpos;
	i64 xpos_b = 0;
	i64 ypos = 0;
	u8 prev_item_type = 0; // 0=none, 1=lit, 2=run
	u8 prev_run_val = 0;
	u8 run_val = 0;
	i64 nbytes_written = 0;
	i64 nrows_to_decode;

	endpos = ic->pixels_pos + ic->pixels_len;

	nrows_to_decode = ic->idmode ? 2 : MACPAINT_HEIGHT;
	pos = ic->pixels_pos;

	while(pos < endpos) {
		u8 this_item_type;

		if(ypos >= nrows_to_decode) {
			goto after_image;
		}
		if(pos+2 > endpos) { // Min item size is 2 bytes
			ic->unexp_eof_flag = 1;
			goto after_image; // Reached the end of source data
		}

		b = de_getbyte_p(&pos);

		if(b<=127) { // literal bytes
			this_item_type = 1;
		}
		else if(b>=129) {
			this_item_type = 2;
		}
		else {
			this_item_type = 0;
			ic->uses_128 = 1;
			if(ic->idmode) {
				goto after_image;
			}
			continue;
		}

		if(this_item_type==1) { // literal bytes
			count = 1+(i64)b;
			if(pos+count > endpos) {
				ic->unexp_eof_flag = 1;
				pos--;
				goto after_image;
			}
			if(ic->unc_pixels) {
				dbuf_copy(c->infile, pos, count, ic->unc_pixels);
			}
			pos += count;
		}
		else {
			count = 257 - (i64)b;
			run_val = de_getbyte_p(&pos);
			if(ic->unc_pixels) {
				dbuf_write_run(ic->unc_pixels, run_val, count);
			}
		}

#if 0
		if(ic->hlen==0 && ic->idmode) {
			if(this_item_type==1) {
				de_dbg3(c, "lit y=%u x=%u count=%u", (UI)ypos, (UI)xpos_b,
					(UI)count);
			}
			else if(this_item_type==2) {
				de_dbg3(c, "run y=%u x=%u count=%u v=%u", (UI)ypos, (UI)xpos_b,
					(UI)count, (UI)run_val);
			}
		}
#endif

		xpos_b += count;
		nbytes_written += count;

		if(xpos_b > MACPAINT_WIDTH_BYTES) {
			if(this_item_type==1) {
				ic->row_issue_lit = 1;
			}
			else {
				ic->row_issue_run = 1;
			}
		}

		while(xpos_b >= MACPAINT_WIDTH_BYTES) {
			xpos_b -= MACPAINT_WIDTH_BYTES;
			ypos++;
		}

		if(this_item_type==2 && prev_item_type==2 &&
			run_val == prev_run_val)
		{
			ic->inefficient_cmpr_flag = 1;
		}

		if(this_item_type==1 && prev_item_type==1) {
			ic->inefficient_cmpr_flag = 1;
		}

		prev_item_type = this_item_type;
		if(this_item_type==2) {
			prev_run_val = run_val;
		}
		if(xpos_b==0) {
			prev_item_type = 0;
		}
	}

after_image:
	if(ic->unc_pixels) {
		dbuf_flush(ic->unc_pixels);
	}

	ic->final_xpos_b = (UI)xpos_b;
	ic->final_ypos = (UI)ypos;
	ic->bytes_consumed = pos - ic->pixels_pos;

	if(!ic->row_issue_lit && !ic->row_issue_run && !ic->uses_128 && !ic->unexp_eof_flag) {
		ic->decompressed_ok = 1;
	}
}

static void do_read_bitmap(deark *c, lctx *d, struct macp_interp_ctx *ic)
{
	i64 cmpr_bytes_consumed = 0;
	de_finfo *fi = NULL;
	int saved_indent_level;
	i64 ipos;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!d->is_fmac2com) {
		de_dbg(c, "header at %"I64_FMT, ic->hlen);
		de_dbg_indent(c, 1);
		de_dbg(c, "version number: %u", (UI)ic->ver_num);
		if(!ic->known_ver) {
			de_warn(c, "Unrecognized version number: %u", (UI)ic->ver_num);
		}

		// We wait until later to read the brush patterns, only so that the patterns
		// won't be the first file extracted.

		de_dbg_indent(c, -1);
	}

	ipos = ic->pixels_pos;
	de_dbg(c, "image data at %"I64_FMT, ipos);
	de_dbg_indent(c, 1);

	cmpr_bytes_consumed = ic->bytes_consumed;
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", cmpr_bytes_consumed,
		ic->unc_pixels->len);

	if(d->df_known) {
		if(ipos+cmpr_bytes_consumed > d->expected_dfpos+d->expected_dflen) {
			de_warn(c, "Image (ends at %"I64_FMT") goes beyond end of "
				"MacBinary data fork (ends at %"I64_FMT")",
				ipos+cmpr_bytes_consumed, d->expected_dfpos+d->expected_dflen);
		}
	}

	if(ic->unc_pixels->len < MACPAINT_IMAGE_BYTES) {
		de_warn(c, "Image decompressed to %"I64_FMT" bytes, expected %u.",
			ic->unc_pixels->len, (UI)MACPAINT_IMAGE_BYTES);
	}
	else if(ic->row_issue_lit || ic->row_issue_run) {
		de_warn(c, "Rows not compressed independently. Decompression may have failed.");
	}

	fi = de_finfo_create(c);
	if(d->filename && c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, d->filename, 0);
	}

	if(d->mod_time_from_macbinary.is_valid) {
		fi->internal_mod_time = d->mod_time_from_macbinary;
	}

	de_convert_and_write_image_bilevel(ic->unc_pixels, 0,
		MACPAINT_WIDTH, MACPAINT_HEIGHT, MACPAINT_WIDTH/8,
		DE_CVTF_WHITEISZERO, fi, 0);

	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void check_pat_strength(deark *c, struct macp_interp_ctx *ic)
{
	u64 pat0, pat8, pat33;

	ic->ver_num = (UI)de_getu32be(ic->hlen);
	if(ic->ver_num==0 || ic->ver_num==2 || ic->ver_num==3) {
		ic->known_ver = 1;
	}

	pat0  = dbuf_getu64be(c->infile, ic->hlen+4);
	pat8  = dbuf_getu64be(c->infile, ic->hlen+4+8*8);
	pat33 = dbuf_getu64be(c->infile, ic->hlen+4+8*33);

	if(pat8==0xb130031bd8c00c8dULL || pat33==0x038448300c020101ULL) {
		ic->pat_strength = 3;
	}
	else if(pat0==0xffffffffffffffffULL) {
		if(dbuf_is_all_zeroes(c->infile, ic->hlen+4+8, 37*8)) {
			ic->pat_strength = 2;
		}
	}
	else if(ic->ver_num==0 && pat0==0) {
		ic->pat_strength = 1;
	}
}

static void set_min_idmode_confidence(struct macp_interp_ctx *ic, int x)
{
	if(x>100) x = 100;
	if(ic->idmode_confidence<x) {
		ic->idmode_confidence = x;
	}
}

static void macp_detect_and_decompr_part1(deark *c, struct macp_interp_ctx *ic)
{
	UI cr, ty;
	i64 imgstart;

	imgstart = ic->pixels_pos;

	// Minimum bytes per row is 2.
	// For a valid (non-truncated) file, file size must be at least
	// pos1 + 512 + 2*MACPAINT_HEIGHT. But we want to tolerate truncated
	// files as well.
	if(c->infile->len < imgstart + 4) {
		if(ic->msg) {
			de_strlcpy(ic->msg, "file too small", MACP_MSG_LEN);
		}
		ic->invalid_image = 0;
		ic->skip_part2 = 1;
		goto done;
	}

	if(ic->hlen==128) {
		ty = (UI)de_getu32be(65);
		if(ty==CODE_PNTG) {
			ic->typecodes_strength++;
			if(ic->idmode && ic->known_macbinary) {
				// If this file was already identified as macbinary, and it has
				// type PNTG, we don't need to go any farther. We definitely want
				// to run the macpaint module, not the macbinary module.
				goto done;
			}

			cr = (UI)de_getu32be(69);
			if(cr==CODE_MPNT) {
				ic->typecodes_strength++;
			}
		}
	}

	check_pat_strength(c, ic);

	if(ic->pat_strength==1) {
		UI x1;

		x1 = (UI)de_getu32be(ic->pixels_pos);
		// Common compressed byte patterns
		if(x1==0xb900b900U || x1==0xb9ffb9ffU) {
			ic->cmpr_strength1 += 2;
		}
		else if((x1>>16)==0xb900 || (x1>>16)==0xb9ff) {
			ic->cmpr_strength1 += 1;
		}
	}

done:
	if(ic->idmode) {
		if(ic->known_macbinary && ic->typecodes_strength>=1) {
			ic->idmode_confidence = 100;
			ic->skip_part2 = 1;
		}
		else if(ic->typecodes_strength>=2) {
			ic->idmode_confidence = 100;
		}
		else if(ic->pat_strength>=3 && ic->typecodes_strength>=1) {
			ic->idmode_confidence = 100;
		}
	}

	if(ic->invalid_image) {
		ic->idmode_confidence = 0;
		ic->runmode_confidence = 0;
	}
}

static void macp_detect_and_decompr_part2(deark *c, struct macp_interp_ctx *ic)
{
	i64 tmppos;

	if(ic->skip_part2) goto done;

	// Look for a boundary between all-0 bytes, and not-all-0 bytes.
	if(dbuf_is_all_zeroes(c->infile, ic->pixels_pos-16, 16) &&
		!dbuf_is_all_zeroes(c->infile, ic->pixels_pos, 8))
	{
		ic->image_pos_seems_correct = 1;
	}

	if(ic->known_ver) {
		if(ic->ver_num==0) {
			tmppos = ic->hlen+4;
		}
		else {
			tmppos = ic->hlen + 4 + 38*8;
		}
		if(dbuf_is_all_zeroes(c->infile, tmppos, ic->pixels_pos - tmppos)) {
			ic->unused_bytes_are_0 = 1;
		}
	}

	decompress_main(c, ic);

	if(ic->msg) {
		if(ic->msg[0]==0 && ic->row_issue_lit) {
			de_strlcpy(ic->msg, "literal too long", MACP_MSG_LEN);
		}

		if(ic->msg[0]==0 && ic->row_issue_run) {
			de_strlcpy(ic->msg, "run too long", MACP_MSG_LEN);
		}

		if(ic->msg[0]==0) {
			if(ic->unexp_eof_flag) {
				de_snprintf(ic->msg, MACP_MSG_LEN, "premature end of file (x=%u, y=%u)",
					(ic->final_xpos_b*8), ic->final_ypos);
			}
		}

		if(ic->msg[0]==0 && ic->inefficient_cmpr_flag) {
			de_strlcpy(ic->msg, "inefficient compression", MACP_MSG_LEN);
		}

		if(ic->msg[0]==0) {
			de_strlcpy(ic->msg, "decodes okay", MACP_MSG_LEN);
		}
	}

	if(ic->invalid_image) {
		ic->idmode_confidence = 0;
		ic->runmode_confidence = 0;
		goto done;
	}

	// FIXME: These calculations are a mess.
	// We've collected the info we think we need, but it's hard to figure out
	// how best to use it.

	if(ic->idmode && ic->file_ext_strength>0 && ic->image_pos_seems_correct)
	{
		if(ic->decompressed_ok) {
			set_min_idmode_confidence(ic, 15);
		}
		else if(!ic->uses_128 && !ic->unexp_eof_flag && ic->unused_bytes_are_0) {
			set_min_idmode_confidence(ic, 10);
		}
	}

	if(ic->idmode) {
		if(ic->pat_strength>=3) {
			set_min_idmode_confidence(ic, 35);
		}
		else if(ic->pat_strength>=2 && ic->known_ver) {
			if(ic->image_pos_seems_correct && ic->decompressed_ok) {
				set_min_idmode_confidence(ic, 15);
			}
		}
		else if(ic->cmpr_strength1 && ic->decompressed_ok) {
			if(dbuf_is_all_zeroes(c->infile, 0, ic->hlen+512)) {
				if(ic->hlen==0) {
					set_min_idmode_confidence(ic, 15);
				}
				else {
					set_min_idmode_confidence(ic, 13);
				}
			}
		}
	}

	if(!ic->idmode) {
		ic->runmode_confidence += ic->image_pos_seems_correct ? 2 : 0;
		if(ic->decompressed_ok) {
			ic->runmode_confidence += 3;
		}
		if(!ic->unexp_eof_flag) {
			ic->runmode_confidence += 1;
		}
		if(!ic->inefficient_cmpr_flag) {
			ic->runmode_confidence += 1;
		}
	}

	if(!ic->idmode) {
		ic->runmode_confidence += ic->typecodes_strength*5;
		if(ic->pat_strength>=3) {
			ic->runmode_confidence += 3;
		}
		else if(ic->pat_strength==2) {
			ic->runmode_confidence += 1;
		}
	}

done:
	;
}

// ic->unc_pixels can be NULL.
// ic->msg can be NULL. If not NULL, it should initially be an empty string.
static void macp_detect_and_decompr(deark *c, struct macp_interp_ctx *ic)
{
	if(!ic->idmode) {
		de_dbg(c, "checking for image at offset %"I64_FMT, ic->pixels_pos);
		de_dbg_indent(c, 1);
	}

	macp_detect_and_decompr_part1(c, ic);
	macp_detect_and_decompr_part2(c, ic);

	if(!ic->idmode) {
		if(ic->msg) {
			de_dbg(c, "image at offset %d: %s", (int)(ic->pixels_pos), ic->msg);
		}
		de_dbg_indent(c, -1);
	}
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
static void do_read_patterns(deark *c, lctx *d, struct macp_interp_ctx *ic)
{
	i64 pos1;
	i64 cell_idx;
	i64 i, j;
	const i64 cell_width = 19;
	const i64 cell_height = 16;
	const i64 cells_per_row = 19;
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
	pos1 = ic->hlen + 4;

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

	gallery = de_bitmap_create(c, (cell_width+1)*19+1, (cell_height+1)*2+1, 1);

	for(cell_idx=0; cell_idx<38; cell_idx++) {
		i64 cell_x, cell_y; // dst cell pos in cells
		i64 cell_xpos, cell_ypos; // dst cell pos in pixels

		cell_x = cell_idx%cells_per_row;
		cell_y = cell_idx/cells_per_row;

		cell_xpos = (cell_width+1)*cell_x+1;
		cell_ypos = (cell_height+1)*cell_y+1;

		for(j=0; j<cell_height; j++) {
			i64 yoffs;

			// The cell sizes and "brush origin" are believed to be correct for
			// at least one version of MacPaint, under some conditions.
			yoffs = (cell_ypos+j+4)%8;

			for(i=0; i<cell_width; i++) {
				de_colorsample x;
				i64 xoffs;

				xoffs = (cell_xpos+i+7)%8;

				x = DE_COLOR_K(de_bitmap_getpixel(rawimg, xoffs, 8*cell_idx + yoffs));
				de_bitmap_setpixel_gray(gallery, cell_xpos+i, cell_ypos+j, x);
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

// (Not intended to be used in the ID phase.)
static void destroy_ic(deark *c, struct macp_interp_ctx *ic)
{
	if(!ic) return;
	de_free(c, ic->msg);
	dbuf_close(ic->unc_pixels);
	de_free(c, ic);
}

static void de_run_macpaint(deark *c, de_module_params *mparams)
{
	lctx *d;
	struct macp_interp_ctx *ic1 = NULL;
	struct macp_interp_ctx *ic2 = NULL;
	struct macp_interp_ctx *ic_to_use;
	u8 need_ic1 = 0;
	u8 need_ic2 = 0;

	d = de_malloc(c, sizeof(lctx));
	d->has_macbinary_header = de_get_ext_option_bool(c, "macpaint:macbinary", -1);

	if(d->has_macbinary_header == -1) {
		d->is_fmac2com = is_fmac2com(c);
	}

	if(d->is_fmac2com) {
		d->has_macbinary_header = 1;
	}

	if(d->has_macbinary_header == -1) {
		need_ic1 = 1;
		need_ic2 = 1;
	}
	else if(d->has_macbinary_header==0) {
		need_ic1 = 1;
	}
	else {
		need_ic2 = 1;
	}

	de_dbg(c, "[analyzing file]");
	de_dbg_indent(c, 1);

	// We normally decompress the image using both possible interpretations, save
	// both images, then use the one that seems best.
	// This works, though it does cause difficulties if we want to print useful
	// dbg info -- We can't easily go back in time and only print info about the
	// image we chose.

	if(need_ic1) {
		ic1 = de_malloc(c, sizeof(struct macp_interp_ctx));
		ic1->msg = de_malloc(c, MACP_MSG_LEN);
		ic1->unc_pixels = dbuf_create_membuf(c, MACPAINT_IMAGE_BYTES, 1);
		dbuf_enable_wbuffer(ic1->unc_pixels);
		ic1->hlen = 0;
		ic1->pixels_pos = ic1->hlen + 512;
		ic1->pixels_len = c->infile->len - ic1->pixels_pos;
		macp_detect_and_decompr(c, ic1);
	}

	if(need_ic2) {
		ic2 = de_malloc(c, sizeof(struct macp_interp_ctx));
		ic2->msg = de_malloc(c, MACP_MSG_LEN);
		ic2->unc_pixels = dbuf_create_membuf(c, MACPAINT_IMAGE_BYTES, 1);
		dbuf_enable_wbuffer(ic2->unc_pixels);
		ic2->hlen = 128;
		ic2->pixels_pos = ic2->hlen + 512;
		ic2->pixels_len = c->infile->len - ic2->pixels_pos;
		macp_detect_and_decompr(c, ic2);
	}

	de_dbg_indent(c, -1);

	if(d->has_macbinary_header == -1 && ic1 && ic2) {
		int v512;
		int v640;

		v512 = ic1->runmode_confidence;
		v640 = ic2->runmode_confidence;

		if(v512 > v640) {
			de_dbg(c, "assuming it has no MacBinary header");
			d->has_macbinary_header = 0;
		}
		else if(v640 > v512) {
			de_dbg(c, "assuming it has a MacBinary header");
			d->has_macbinary_header = 1;
		}
		else if(v512>0 && v640>0) {
			de_warn(c, "Can't determine if this file has a MacBinary header. "
				"Try \"-opt macpaint:macbinary=0\".");
			d->has_macbinary_header = 1;
		}
		else {
			de_err(c, "Not a MacPaint file");
			goto done;
		}
	}

	if(d->has_macbinary_header) {
		ic_to_use = ic2;
	}
	else {
		ic_to_use = ic1;
	}

	if(!ic_to_use) {
		de_internal_err_fatal(c, "macpaint logic error");
		goto done;
	}

	if(d->is_fmac2com)
		de_declare_fmt(c, "FMAC2COM self-displaying MacPaint");
	else if(d->has_macbinary_header)
		de_declare_fmt(c, "MacPaint with MacBinary header");
	else
		de_declare_fmt(c, "MacPaint without MacBinary header");

	if(d->has_macbinary_header) {
		do_macbinary(c, d);
	}

	do_read_bitmap(c, d, ic_to_use);

	if(!d->is_fmac2com) {
		do_read_patterns(c, d, ic_to_use);
	}

done:
	if(d) {
		ucstring_destroy(d->filename);
		de_free(c, d);
	}
	destroy_ic(c, ic1);
	destroy_ic(c, ic2);
}

// Note: This must be coordinated with the macbinary detection routine.
static int de_identify_macpaint(deark *c)
{
	struct macp_interp_ctx ic1;
	struct macp_interp_ctx ic2;

	if(c->infile->len < 512+2*256) return 0;
	if(is_fmac2com(c)) return 100;

	de_zeromem(&ic2, sizeof(struct macp_interp_ctx));

	if(de_input_file_has_ext(c, "mac"))
	{
		ic2.file_ext_strength = 1;
	}
	else if (de_input_file_has_ext(c, "macp") ||
		de_input_file_has_ext(c, "pntg"))
	{
		ic2.file_ext_strength = 2;
	}

	ic2.known_macbinary = c->detection_data->is_macbinary;
	ic2.idmode = 1;
	ic2.hlen = 128;
	ic2.pixels_pos = ic2.hlen + 512;
	ic2.pixels_len = c->infile->len - ic2.pixels_pos;
	macp_detect_and_decompr_part1(c, &ic2);
	if(ic2.idmode_confidence==100) {
		return 100;
	}

	de_zeromem(&ic1, sizeof(struct macp_interp_ctx));
	ic1.idmode = 1;
	ic1.file_ext_strength = ic2.file_ext_strength;
	ic1.pixels_pos = ic1.hlen + 512;
	ic1.pixels_len = c->infile->len - ic1.pixels_pos;
	macp_detect_and_decompr_part1(c, &ic1);
	if(ic1.idmode_confidence==100) {
		return 100;
	}

	if(!ic1.file_ext_strength && c->detection_data->best_confidence_so_far>50) {
		return 0;
	}

	if(!ic1.file_ext_strength &&
		!ic2.typecodes_strength &&
		ic1.pat_strength<2 && ic2.pat_strength<2 &&
		!ic1.cmpr_strength1 && !ic2.cmpr_strength1)
	{
		return 0;
	}

	// The more expensive tests start here.
	macp_detect_and_decompr_part2(c, &ic2);
	macp_detect_and_decompr_part2(c, &ic1);

	if(ic1.idmode_confidence > ic2.idmode_confidence)
		return ic1.idmode_confidence;
	return ic2.idmode_confidence;
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
