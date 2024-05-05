// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// MS Comic Chat .AVB, .BGB

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_comicchat);

typedef struct localctx_comicchat {
	u8 errflag;
	u8 stopflag;
	UI fmt_code;
	UI major_ver;
	struct de_inthashtable *images_seen;
	struct de_inthashtable *masks_seen; // Might be unused
	i64 last_chunklen;
	i64 img_ptr_bias;
} lctx;

struct chunk_ctx {
	UI ck_type;
	i64 ck_pos; // everything; starting from start of type field
	i64 ck_len; // total length
	i64 internal_dlen; // length minus 4-byte header; applies to some chunks
	i64 internal_dpos;
};

struct image_extract_ctx {
	struct de_bmpinfo bi;
	int itype;
	i64 ihpos;
	dbuf *unc_pixels;
	i64 pal_num_entries;
	de_color pal[256];
};

struct image_highlevel_ctx {
	u8 have_fg;
	i64 fg_w, fg_h;
};

static void write_palette(deark *c, lctx *d, dbuf *outf,
	de_color *pal, i64 num_entries)
{
	i64 i;

	for(i=0; i<num_entries; i++) {
		dbuf_writebyte(outf, DE_COLOR_B(pal[i]));
		dbuf_writebyte(outf, DE_COLOR_G(pal[i]));
		dbuf_writebyte(outf, DE_COLOR_R(pal[i]));
		dbuf_writebyte(outf, 0);
	}
}

static void reconstruct_bmp(deark *c, lctx *d, struct image_extract_ctx *ic)
{
	dbuf *outf = NULL;
	const char *ext;

	// TODO: Masks need to be applied, not written to separate files.
	if(ic->itype==1) ext = "sm_mask.bmp";
	else if(ic->itype==2) ext = "lg_mask.bmp";
	else ext = "bmp";

	outf = dbuf_create_output_file(c, ext, NULL,
		((ic->itype!=0)?DE_CREATEFLAG_IS_AUX:0));

	fmtutil_generate_bmpfileheader(c, outf, &ic->bi, 0);
	dbuf_copy(c->infile, ic->ihpos, ic->bi.infohdrsize, outf);
	write_palette(c, d, outf, ic->pal, ic->bi.pal_entries);
	dbuf_copy(ic->unc_pixels, 0, ic->unc_pixels->len, outf);
	dbuf_close(outf);
}

static void decode_2bpp_dib(deark *c, lctx *d, struct image_extract_ctx *ic)
{
	de_bitmap *img = NULL;

	ic->pal[0] = DE_STOCKCOLOR_TRANSPARENT;
	// Sometimes pal[1] is used for the halo around the character, so it might
	// be interesting to make it partially transparent or something.
	// But unfortunately, other times the halo is pal[2].
	ic->pal[1] = DE_MAKE_GRAY(254); // alternate white foreground
	ic->pal[2] = DE_STOCKCOLOR_WHITE; // normal white foregreound
	ic->pal[3] = DE_STOCKCOLOR_BLACK; // normal black foreground

	img = de_bitmap_create(c, ic->bi.width, ic->bi.height, 2);
	de_convert_image_paletted(ic->unc_pixels, 0, 2, ic->bi.rowspan, ic->pal,
		img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);
	de_bitmap_destroy(img);
}

static void process_imgcomponent_dimensions(deark *c, struct image_highlevel_ctx *ih,
	int itype, i64 w, i64 h)
{
	if(itype==0) {
		ih->fg_w = w;
		ih->fg_h = h;
		ih->have_fg = 1;
	}
	else {
		if(ih->have_fg && (w!=ih->fg_w || h!=ih->fg_h)) {
			de_warn(c, "Mask dimensions are different from foreground dimensions");
		}
	}
}

// Extract an image from a "dib" segment, which can optionally start with a palette
static void extract_dib(deark *c, lctx *d, struct image_highlevel_ctx *ih,
	i64 pos1, UI magic, int itype)
{
	int ret;
	i64 pos;
	i64 cmpr_pos;
	i64 orig_len, cmpr_len;
	UI magic2;
	int saved_indent_level;
	struct image_extract_ctx *ic = NULL;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_deflate_params deflateparams;

	de_dbg_indent_save(c, &saved_indent_level);
	ic = de_malloc(c, sizeof(struct image_extract_ctx));
	ic->itype = itype;
	de_zeromem(&deflateparams, sizeof(struct de_deflate_params));
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	if(d->errflag) goto done;

	pos = pos1;
	if(magic==0x0101) {
		i64 ck_len;

		// The palette is formatted like a standard chunk.
		// TODO: Ideally, we'd use shared chunk-reading code here.
		de_dbg(c, "palette chunk at %"I64_FMT, pos1);
		de_dbg_indent(c, 1);
		pos += 2; // 0x0101 tag, already read
		ck_len = de_getu16le_p(&pos);
		ic->pal_num_entries = de_getu16le_p(&pos);
		de_dbg(c, "num entries: %"I64_FMT, ic->pal_num_entries);
		if(ic->pal_num_entries>256) goto done;

		// Note that palette is RGB, not BGR as might be expected.
		if(ic->pal_num_entries>0) {
			de_read_simple_palette(c, c->infile, pos, ic->pal_num_entries, 3, ic->pal,
				256, DE_RDPALTYPE_24BIT, 0);
		}
		pos = pos1 + 4 + ck_len;
		de_dbg_indent(c, -1);
	}

	ic->ihpos = pos;
	magic2 = (UI)de_getu16be(ic->ihpos);
	if(magic2 != 0x2800) {
		de_err(c, "Image not found at %"I64_FMT, ic->ihpos);
		goto done;
	}

	de_dbg(c, "infoheader at %"I64_FMT, ic->ihpos);
	de_dbg_indent(c, 1);
	ret = fmtutil_get_bmpinfo(c, c->infile, &ic->bi, ic->ihpos,
		c->infile->len - ic->ihpos, 0);
	de_dbg_indent(c, -1);
	if(!ret) goto done;
	if(ic->bi.infohdrsize != 40) goto done;
	if(ic->bi.pal_entries > 256) goto done;
	if(ic->bi.is_compressed) goto done;
	if(!de_good_image_dimensions(c, ic->bi.width, ic->bi.height)) goto done;
	process_imgcomponent_dimensions(c, ih, itype, ic->bi.width, ic->bi.height);

	if(ic->bi.bitcount==1 && ic->bi.pal_entries==2 && ic->pal_num_entries==0) {
		ic->pal_num_entries = 2;
		de_make_grayscale_palette(ic->pal, ic->pal_num_entries, 0);
	}

	pos = ic->ihpos + ic->bi.infohdrsize;
	orig_len = de_getu32le_p(&pos);
	de_dbg(c, "orig len: %"I64_FMT, orig_len);
	cmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "cmpr len: %"I64_FMT, cmpr_len);
	cmpr_pos = pos;
	de_dbg(c, "cmpr data at %"I64_FMT, cmpr_pos);
	if(cmpr_pos + cmpr_len > c->infile->len) goto done;

	ic->unc_pixels = dbuf_create_membuf(c, 0, 0);
	dcmpri.f = c->infile;
	dcmpri.pos = cmpr_pos;
	dcmpri.len = cmpr_len;
	dcmpro.f = ic->unc_pixels;
	dcmpro.expected_len = de_min_int(orig_len, ic->bi.foreground_size);
	dcmpro.len_known = 1;
	deflateparams.flags = DE_DEFLATEFLAG_ISZLIB;
	de_dbg(c, "[decompressing]");
	de_dbg_indent(c, 1);
	fmtutil_deflate_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&deflateparams);
	de_dbg_indent(c, -1);
	dbuf_flush(ic->unc_pixels);
	if(dres.errcode != 0) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(ic->bi.bitcount==2) {
		decode_2bpp_dib(c, d, ic);
		goto done;
	}

	reconstruct_bmp(c, d, ic);

done:
	if(ic) {
		dbuf_close(ic->unc_pixels);
		de_free(c, ic);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static void extract_bmp(deark *c, lctx *d, struct image_highlevel_ctx *ih,
	i64 pos1, int itype)
{
	UI bitcount, cmpr;
	i64 bmplen;
	i64 w, h;
	const char *ext;

	bmplen = de_getu32le(pos1+2);

	if(pos1+bmplen > c->infile->len) goto done;
	if(bmplen < 54) goto done;

	w = de_geti32le(pos1+14+4);
	h = de_geti32le(pos1+14+8);
	de_dbg_dimensions(c, w, h);
	process_imgcomponent_dimensions(c, ih, itype, w, h);
	bitcount = (UI)de_getu16le(pos1+14+14);
	de_dbg(c, "bit count: %u", bitcount);
	cmpr = (UI)de_getu32le(pos1+14+16);
	de_dbg(c, "compression: %u", cmpr);

	if(itype==1) ext = "sm_mask.bmp";
	else if(itype==2) ext = "lg_mask.bmp";
	else ext = "bmp";

	// TODO: Masks need to be applied, not written to separate files.
	dbuf_create_file_from_slice(c->infile, pos1, bmplen, ext, NULL,
		((itype!=0)?DE_CREATEFLAG_IS_AUX:0));
done:
	;
}

// itype=0:foreground 1:mask1 2:mask2
static void extract_image_lowlevel(deark *c, lctx *d,
	struct image_highlevel_ctx *ih, i64 pos1, int itype)
{
	UI magic;
	int saved_indent_level;
	de_dbg_indent_save(c, &saved_indent_level);

	if(pos1==0) goto done;

	de_dbg(c, "[image component at %"I64_FMT"]", pos1);
	de_dbg_indent(c, 1);

	magic = (UI)de_getu16be(pos1);
	de_dbg(c, "sig: 0x%04x", magic);
	if(magic!=0x0101 && magic!=0x2800 && magic!=0x424d) {
		de_err(c, "Image not found at %"I64_FMT, pos1);
		goto done;
	}

	if(magic==0x424d) {
		extract_bmp(c, d, ih, pos1, itype);
	}
	else {
		extract_dib(c, d, ih, pos1, magic, itype);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void extract_image_highlevel(deark *c, lctx *d, i64 imgpos, i64 m1pos, i64 m2pos)
{
	struct image_highlevel_ctx *ih = NULL;

	ih = de_malloc(c, sizeof(struct image_highlevel_ctx));
	de_dbg(c, "[extracting image at %"I64_FMT", %"I64_FMT", %"I64_FMT"]",
		imgpos, m1pos, m2pos);
	de_dbg_indent(c, 1);
	extract_image_lowlevel(c, d, ih, imgpos, 0);
	extract_image_lowlevel(c, d, ih, m1pos, 1);
	extract_image_lowlevel(c, d, ih, m2pos, 2);
	de_dbg_indent(c, -1);
	de_free(c, ih);
}

static int found_image(deark *c, lctx *d, i64 imgpos, i64 m1pos, i64 m2pos)
{
	int retval = 0;
	int ret;

	if(imgpos) imgpos += d->img_ptr_bias;
	if(m1pos) m1pos += d->img_ptr_bias;
	if(m2pos) m2pos += d->img_ptr_bias;
	de_dbg(c, "pointer: image at %"I64_FMT", mask1 at %"I64_FMT", mask2 at %"I64_FMT,
		imgpos, m1pos, m2pos);
	if(m1pos==m2pos) m1pos = 0;
	if(imgpos==0 || imgpos>=c->infile->len || m1pos>=c->infile->len ||
		m2pos>=c->infile->len)
	{
		goto done;
	}
	retval = 1;

	ret = de_inthashtable_add_item(c, d->images_seen, imgpos, NULL);
	if(m1pos) de_inthashtable_add_item(c, d->masks_seen, m1pos, NULL);
	if(m2pos) de_inthashtable_add_item(c, d->masks_seen, m2pos, NULL);
	if(!ret) {
		de_dbg(c, "[already handled this image]");
		goto done;
	}

	extract_image_highlevel(c, d, imgpos, m1pos, m2pos);

done:
	return retval;
}

static void handle_chunk_1imageptr(deark *c, lctx *d, struct chunk_ctx *cctx, i64 offset)
{
	i64 n;

	n = de_getu32le(cctx->ck_pos + offset);
	found_image(c, d, n, 0, 0);
}

static void handle_chunk_multiimageptr(deark *c, lctx *d, struct chunk_ctx *cctx,
	i64 offset, i64 item_size, i64 item_count)
{
	i64 pos;
	i64 i;

	de_dbg(c, "item count: %"I64_FMT, item_count);
	pos = cctx->ck_pos + offset;

	for(i=0; i<item_count; i++) {
		i64 n, m1, m2;

		n = de_getu32le(pos);
		m1 = de_getu32le(pos+4);
		m2 = de_getu32le(pos+8);
		if(!found_image(c, d, n, m1, m2)) goto done;
		pos += item_size;
	}

done:
	;
}

// sets d->last_chunklen (=total size)
// may set d->stopflag, d->errflag
static void comicchat_read_chunk(deark *c, lctx *d, i64 pos1)
{
	struct chunk_ctx *cctx = NULL;
	int ret;
	i64 foundpos = 0;
	i64 n;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	cctx = de_malloc(c, sizeof(struct chunk_ctx));
	cctx->ck_pos = pos1;
	d->last_chunklen = 0;
	if(cctx->ck_pos+2 > c->infile->len) goto done;
	cctx->ck_type = (UI)de_getu16le(cctx->ck_pos);
	de_dbg(c, "chunk at %"I64_FMT", type=0x%04x", cctx->ck_pos, (UI)cctx->ck_type);
	de_dbg_indent(c, 1);

	if(cctx->ck_type==0x0001) {
		ret = dbuf_search_byte(c->infile, 0x00, cctx->ck_pos+2, 4096, &foundpos);
		if(!ret) goto done;
		cctx->ck_len = foundpos + 1 - cctx->ck_pos;
	}
	else if(cctx->ck_type==0x0002) {
		cctx->ck_len = 4;
	}
	else if(cctx->ck_type==0x0003) {
		cctx->ck_len = 6;
		handle_chunk_1imageptr(c, d, cctx, 2);
	}
	else if(cctx->ck_type==0x0004) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 43*n;
		handle_chunk_multiimageptr(c, d, cctx, 4, 43, n);
	}
	else if(cctx->ck_type==0x0005 || cctx->ck_type==0x0009) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 35*n;
		handle_chunk_multiimageptr(c, d, cctx, 4, 35, n);
	}
	else if(cctx->ck_type==0x0006 || cctx->ck_type==0x0007) {
		cctx->ck_len = 2;
		d->stopflag = 1;
		goto done;
	}
	else if(cctx->ck_type==0x0008) {
		cctx->ck_len = 4;
	}
	else if(cctx->ck_type==0x000a) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 33*n;
		handle_chunk_multiimageptr(c, d, cctx, 4, 33, n);
	}
	else if(cctx->ck_type==0x000b || cctx->ck_type==0x000c) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 25*n;
		handle_chunk_multiimageptr(c, d, cctx, 4, 25, n);
	}
	else if(cctx->ck_type>=0x0100 && cctx->ck_type<=0x01ff) {
		cctx->internal_dlen = de_getu16le(cctx->ck_pos+2);
		cctx->internal_dpos = cctx->ck_pos + 4;
		cctx->ck_len = 4 + cctx->internal_dlen;

		if(cctx->ck_type==0x0104) {
			u8 b1, b2;

			// hack to handle seemingly-bad files
			b1 = de_getbyte(cctx->ck_pos+cctx->ck_len-1);
			b2 = de_getbyte(cctx->ck_pos+cctx->ck_len);
			if(b1!=0 && b2==0) {
				cctx->ck_len++;
				de_dbg(c, "adjusting chunk len to %"I64_FMT, cctx->ck_len);
			}
		}

		if(cctx->ck_type==0x0100) {
			handle_chunk_1imageptr(c, d, cctx, 4);
		}
		else if(cctx->ck_type==0x0102) {
			handle_chunk_1imageptr(c, d, cctx, 4);
		}
		else if(cctx->ck_type==0x0107) {
			// This is weird.
			n = de_getu32le(cctx->internal_dpos);
			d->img_ptr_bias += n;
			de_sanitize_offset(&d->img_ptr_bias);
			de_dbg(c, "image pointer bias: %"I64_FMT, d->img_ptr_bias);
		}
	}

	if(cctx->ck_len<2) {
		de_err(c, "Unsupported chunk (0x%04x); can't continue", cctx->ck_type);
		d->errflag = 1;
		goto done;
	}

	de_dbg(c, "chunk len: %"I64_FMT, cctx->ck_len);
	if(c->debug_level>=3) {
		de_dbg_hexdump(c, c->infile, cctx->ck_pos, cctx->ck_len, 256, NULL, 0x1);
	}
	d->last_chunklen = cctx->ck_len;

done:
	de_free(c, cctx);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_comicchat(deark *c, de_module_params *mparams)
{
	i64 pos = 0;
	lctx *d = NULL;
	const char *tstr;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 2;
	d->fmt_code = (UI)de_getu16le_p(&pos);
	d->major_ver = (UI)de_getu16le_p(&pos);
	if(d->major_ver==1) tstr = "v1.0-2.1";
	else if(d->major_ver==2) tstr = "v2.5";
	else tstr = "?";
	de_dbg(c, "fmt ver: %u (%s)", d->major_ver, tstr);
	if(d->major_ver==2 && d->fmt_code==3) tstr = " (BGB?)";
	else tstr = "";
	de_dbg(c, "fmt code: %u%s", d->fmt_code, tstr);
	de_dbg_indent(c, -1);

	d->images_seen = de_inthashtable_create(c);
	d->masks_seen = de_inthashtable_create(c);
	while(1) {
		comicchat_read_chunk(c, d, pos);
		if(d->errflag || d->stopflag || d->last_chunklen==0) goto done;
		pos += d->last_chunklen;
	}

done:
	if(d) {
		de_inthashtable_destroy(c, d->images_seen);
		de_inthashtable_destroy(c, d->masks_seen);
		de_free(c, d);
	}
}

static int de_identify_comicchat(deark *c)
{
	u8 has_ext, has_hdr, has_endtag;
	UI n0, n2, n4;

	n0 = (UI)de_getu16be(0);
	if(n0!=0x8100 && n0!=0x8181) return 0;
	n2 = (UI)de_getu16le(2);
	n4 = (UI)de_getu16le(4);

	has_hdr = 0;
	if(n0==0x8100) {
		if(n4==1 && (n2==1 || n2==2)) has_hdr = 1;
	}
	else { // 0x8181
		if(n4==2 && (n2>=1 && n2<=3)) has_hdr = 1;
	}
	if(!has_hdr) return 0;

	has_endtag = (de_getu16le(c->infile->len - 2) == 0x0007);
	has_ext = (de_input_file_has_ext(c, "avb") ||
		de_input_file_has_ext(c, "bgb"));
	if(has_endtag && has_ext) return 100;
	if(has_endtag || has_ext) return 55;
	return 35;
}

void de_module_comicchat(deark *c, struct deark_module_info *mi)
{
	mi->id = "comicchat";
	mi->desc = "Microsoft Comic Chat";
	mi->run_fn = de_run_comicchat;
	mi->identify_fn = de_identify_comicchat;
}
