// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// MS Comic Chat .AVB, .BGB

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_comicchat);

typedef struct localctx_comicchat {
	de_encoding input_encoding;
	u8 stopflag;
	u8 opt_applymasks;
	u8 prefer_bmp_output;
	UI fmt_code;
	UI major_ver;
	struct de_inthashtable *images_seen;
	i64 last_chunklen;
	i64 img_ptr_bias;
	de_ucstring *char_name;
	de_ucstring *tmpstr;
} lctx;

struct chunk_ctx {
	UI ck_type;
	i64 ck_pos; // everything; starting from start of type field
	i64 ck_len; // total length from ck_pos
};

struct image_lowlevel_ctx {
	de_bitmap *img;
	de_finfo *fi;
	UI createflags;
};

struct image_highlevel_ctx {
	u8 special_2bpp_transparency;
	u8 is_icon;
	u8 is_bkgd;
	// [0] is the foreground image.
	// [1] and [2] are optional transparency masks.
	// Sometimes the fg image has transparency, in which case we wouldn't expect
	// the masks to exist.
	struct image_lowlevel_ctx llimg[3];
};

struct image_extract_ctx {
	struct de_bmpinfo bi;
	i64 ihpos;
	dbuf *unc_pixels;
	i64 pal_num_entries;
	de_color pal[256];
};

static void fixup_2bpp_transparency(deark *c, lctx *d, struct image_highlevel_ctx *ih)
{
	de_bitmap *oldimg;
	de_bitmap *newimg;
	i64 i, j;

	oldimg = ih->llimg[0].img;
	if(!oldimg) return;
	newimg = de_bitmap_create(c, oldimg->width, oldimg->height, 2);
	for(j=0; j<oldimg->height; j++) {
		for(i=0; i<oldimg->width; i++) {
			de_color clr;

			clr = de_bitmap_getpixel(oldimg, i, j);
			if(clr==DE_MAKE_GRAY(128)) clr = DE_MAKE_RGBA(128,128,128,0);
			de_bitmap_setpixel_rgba(newimg, i, j, clr);
		}
	}

	de_bitmap_destroy(ih->llimg[0].img);
	ih->llimg[0].img = newimg;
}

static void extract_whole_bmp(deark *c, lctx *d, dbuf *inf, i64 pos1,
	struct image_highlevel_ctx *ih)
{
	i64 bmplen;
	dbuf *outf = NULL;
	const char *ext;

	bmplen = dbuf_getu32le(inf, pos1+2);
	if(pos1+bmplen > inf->len) goto done;
	if(bmplen < 54) goto done;

	if(ih->is_icon) {
		ext = "icon.bmp";
	}
	else {
		ext = "bmp";
	}
	outf = dbuf_create_output_file(c, ext, NULL, 0);
	dbuf_copy(inf, pos1, bmplen, outf);

done:
	dbuf_close(outf);
}

static void read_bmp_to_img(deark *c, lctx *d, dbuf *inf, i64 pos1,
	struct image_highlevel_ctx *ih, int itype)
{
	de_module_params *mparams = NULL;
	struct fmtutil_bmp_mparams_indata *idata = NULL;
	i64 bmplen;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	bmplen = dbuf_getu32le(inf, pos1+2);
	if(pos1+bmplen > inf->len) goto done;
	if(bmplen < 54) goto done;

	de_dbg(c, "decoding BMP");
	de_dbg_indent(c, 1);
	mparams = de_malloc(c, sizeof(de_module_params));
	idata = de_malloc(c, sizeof(struct fmtutil_bmp_mparams_indata));
	mparams->in_params.flags = 0x2;
	mparams->in_params.obj1 = (void*)idata;
	de_run_module_by_id_on_slice(c, "bmp", mparams, inf, pos1, bmplen);
	if(idata->img) {
		ih->llimg[itype].img = idata->img;
		idata->img = NULL;
		ih->llimg[itype].fi = idata->fi;
		idata->fi = NULL;
		ih->llimg[itype].createflags = idata->createflags;
	}
	else {
		de_err(c, "Failed to decode BMP image");
		goto done;
	}

	if(itype==0 && ih->special_2bpp_transparency) {
		fixup_2bpp_transparency(c, d, ih);
	}

done:
	if(idata) {
		de_bitmap_destroy(idata->img);
		de_finfo_destroy(c, idata->fi);
		de_free(c, idata);
	}
	if(mparams) {
		de_free(c, mparams);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

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

static void reconstruct_bmp_and_cvt_to_img(deark *c, lctx *d,
	struct image_extract_ctx *ic, struct image_highlevel_ctx *ih, int itype,
	u8 direct_to_bmp)
{
	dbuf *tmpbmp = NULL;

	tmpbmp = dbuf_create_membuf(c, 0, 0);
	fmtutil_generate_bmpfileheader(c, tmpbmp, &ic->bi, 0);
	dbuf_copy(c->infile, ic->ihpos, ic->bi.infohdrsize, tmpbmp);
	write_palette(c, d, tmpbmp, ic->pal, ic->bi.pal_entries);
	dbuf_copy(ic->unc_pixels, 0, ic->unc_pixels->len, tmpbmp);
	dbuf_flush(tmpbmp);
	if(direct_to_bmp) {
		extract_whole_bmp(c, d, tmpbmp, 0, ih);
	}
	else {
		read_bmp_to_img(c, d, tmpbmp, 0, ih, itype);
	}
	dbuf_close(tmpbmp);
}

static void read_dib_to_img(deark *c, lctx *d, i64 pos1, UI magic,
	struct image_highlevel_ctx *ih, int itype, u8 direct_to_bmp)
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
	de_zeromem(&deflateparams, sizeof(struct de_deflate_params));
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

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
			de_read_simple_palette(c, c->infile, pos, ic->pal_num_entries, 3,
				ic->pal, 256, DE_RDPALTYPE_24BIT, 0);
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
	// We don't expect the zlib decompression to result in an image that is still
	// (RLE) compressed. We could support it, but we probably need samples.
	if(ic->bi.is_compressed) goto done;
	if(!de_good_image_dimensions(c, ic->bi.width, ic->bi.height)) goto done;

	if(ic->bi.bitcount==1 && itype>0) {
		ic->pal_num_entries = 2;
		// 0 is transparent, and the palette is undefined.
		// It'd be logical to make 0 black, but we make it white, so that masks
		// from all format versions are white-is-transparent.
		de_make_grayscale_palette(ic->pal, ic->pal_num_entries, 0x1);
	}
	else if(ic->bi.bitcount==2 && itype==0 && ic->pal_num_entries==0) {
		ih->special_2bpp_transparency = 1;
		ic->pal_num_entries = 4;
		ic->pal[0] = DE_MAKE_GRAY(128); // Arbitrary key color. Will be made transparent.
		// Sometimes pal[1] is used for the halo around the character, so it might
		// be interesting to make it partially transparent or something.
		// But unfortunately, other times the halo is pal[2].
		ic->pal[1] = DE_MAKE_GRAY(254); // alternate white foreground
		ic->pal[2] = DE_STOCKCOLOR_WHITE; // normal white foregreound
		ic->pal[3] = DE_STOCKCOLOR_BLACK; // normal black foreground
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

	// This will ultimately result in the BMP header & palette being read
	// again (by the bmp module this time), dbg info printed again, etc.
	// It's messy, but it will do.
	reconstruct_bmp_and_cvt_to_img(c, d, ic, ih, itype, direct_to_bmp);

done:
	if(ic) {
		dbuf_close(ic->unc_pixels);
		de_free(c, ic);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// Read an image component, decode it in whatever way required,
// and store it at ih->llimg[itype].
static void read_image_lowlevel(deark *c, lctx *d, i64 pos1,
	struct image_highlevel_ctx *ih, int itype, u8 direct_to_bmp)
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
		if(direct_to_bmp) {
			extract_whole_bmp(c, d, c->infile, pos1, ih);
		}
		else {
			read_bmp_to_img(c, d, c->infile, pos1, ih, itype);
		}
	}
	else {
		read_dib_to_img(c, d, pos1, magic, ih, itype, direct_to_bmp);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void emit_images_highlevel_separate(deark *c, lctx *d,
	struct image_highlevel_ctx *ih)
{
	size_t k;

	if(ih->llimg[0].img) {
		if(ih->is_icon) {
			de_finfo_set_name_from_sz(c, ih->llimg[0].fi,
				"icon", 0, DE_ENCODING_LATIN1);
		}
		de_bitmap_write_to_file_finfo(ih->llimg[0].img, ih->llimg[0].fi,
			ih->llimg[0].createflags);
	}
	for(k=1; k<=2; k++) {
		if(ih->llimg[k].img) {
			de_finfo_set_name_from_sz(c, ih->llimg[k].fi,
				(k==1?"sm_mask":"lg_mask"), 0, DE_ENCODING_LATIN1);
			de_bitmap_write_to_file_finfo(ih->llimg[k].img, ih->llimg[k].fi,
				(ih->llimg[k].createflags | DE_CREATEFLAG_IS_AUX));
		}
	}
}

static void emit_images_highlevel_applymasks(deark *c, lctx *d,
	struct image_highlevel_ctx *ih)
{
	de_bitmap *tmpimg = NULL;
	i64 w, h;
	size_t k;

	if(!ih->llimg[0].img) goto done; // should be impossible
	w = ih->llimg[0].img->width;
	h = ih->llimg[0].img->height;

	if(!ih->llimg[1].img && !ih->llimg[2].img) { // should be impossible
		emit_images_highlevel_separate(c, d, ih);
		goto done;
	}

	for(k=1; k<=2; k++) {
		if(!ih->llimg[k].img) continue;
		if(tmpimg) {
			de_bitmap_destroy(tmpimg);
		}
		tmpimg = de_bitmap_create(c, w, h, 4);
		de_bitmap_copy_rect(ih->llimg[0].img, tmpimg, 0, 0, w, h, 0, 0, 0);
		de_bitmap_apply_mask(tmpimg, ih->llimg[k].img, DE_BITMAPFLAG_WHITEISTRNS);
		de_bitmap_write_to_file_finfo(tmpimg, ih->llimg[0].fi,
			ih->llimg[0].createflags);
	}

done:
	de_bitmap_destroy(tmpimg);
}

// We can either extract the foreground and masks to individual files, or
// apply the masks. For us to apply the masks, certain conditions must be met.
static int should_apply_masks(deark *c, lctx *d, struct image_highlevel_ctx *ih)
{
	size_t k;

	if(!d->opt_applymasks) return 0;
	if(ih->special_2bpp_transparency) return 0;
	if(!ih->llimg[0].img) return 0;
	if(!ih->llimg[1].img && !ih->llimg[2].img) return 0;

	for(k=1; k<=2; k++) {
		if(ih->llimg[k].img) {
			if(ih->llimg[k].img->width != ih->llimg[0].img->width) return 0;
			if(ih->llimg[k].img->height != ih->llimg[0].img->height) return 0;
		}
	}
	return 1;
}

static void extract_image_highlevel(deark *c, lctx *d, i64 imgpos, i64 m1pos, i64 m2pos,
	u8 is_icon, u8 is_bkgd)
{
	struct image_highlevel_ctx *ih = NULL;
	size_t k;
	u8 direct_to_bmp = 0;

	ih = de_malloc(c, sizeof(struct image_highlevel_ctx));
	ih->is_icon = is_icon;
	ih->is_bkgd = is_bkgd;

	de_dbg(c, "[extracting image at %"I64_FMT" : %"I64_FMT" : %"I64_FMT"]",
		imgpos, m1pos, m2pos);
	de_dbg_indent(c, 1);

	if(d->prefer_bmp_output) {
		// The direct_to_bmp flag is a bit of a hack, but I don't see any
		// elegant way to do it.
		if((ih->is_icon || ih->is_bkgd) && m1pos==0 && m2pos==0) {
			direct_to_bmp = 1;
		}
	}

	read_image_lowlevel(c, d, imgpos, ih, 0, direct_to_bmp);
	if(direct_to_bmp) goto done;

	read_image_lowlevel(c, d, m1pos, ih, 1, 0);
	read_image_lowlevel(c, d, m2pos, ih, 2, 0);

	for(k=0; k<3; k++) {
		if(!ih->llimg[k].fi) {
			ih->llimg[k].fi = de_finfo_create(c);
		}
		ih->llimg[k].createflags |= DE_CREATEFLAG_OPT_IMAGE;
	}

	if(should_apply_masks(c, d, ih)) {
		emit_images_highlevel_applymasks(c, d, ih);
	}
	else {
		emit_images_highlevel_separate(c, d, ih);
	}

done:
	if(ih) {
		for(k=0; k<3; k++) {
			de_bitmap_destroy(ih->llimg[k].img);
			de_finfo_destroy(c, ih->llimg[k].fi);
		}
		de_free(c, ih);
	}
	de_dbg_indent(c, -1);
}

static int found_image(deark *c, lctx *d, struct chunk_ctx *cctx,
	i64 imgpos, i64 m1pos, i64 m2pos)
{
	int retval = 0;
	int ret;
	u8 is_icon;
	u8 is_bkgd;

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
	if(!ret) {
		de_dbg(c, "[already handled this image]");
		goto done;
	}

	is_icon = (cctx->ck_type==0x0003 || cctx->ck_type==0x0100);
	is_bkgd = (cctx->ck_type==0x0102);
	extract_image_highlevel(c, d, imgpos, m1pos, m2pos, is_icon, is_bkgd);

done:
	return retval;
}

static void handle_chunk_1imageptr(deark *c, lctx *d, struct chunk_ctx *cctx, i64 offset)
{
	i64 n;

	n = de_getu32le(cctx->ck_pos + offset);
	found_image(c, d, cctx, n, 0, 0);
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
		if(!found_image(c, d, cctx, n, m1, m2)) goto done;
		pos += item_size;
	}

done:
	;
}

static void handle_chunk_string(deark *c, lctx *d, i64 pos, i64 len,
	de_ucstring *s, const char *name)
{
	ucstring_empty(s);
	dbuf_read_to_ucstring_n(c->infile, pos, len, 512, s,
		DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
}

static const char *get_chunk_type_name(UI t)
{
	const char *name = NULL;

	switch(t) {
	case 0x1: name = "char name"; break;
		// 0x2 = ?
	case 0x3: case 0x100: name = "icon ref"; break;
	case 0x4: case 0x5: case 0x9: case 0xa: case 0xb: case 0xc:
		name = "image refs";
		break;
	case 0x6: name = "start of img data"; break;
		// 0x7 = end of img data (but we won't find it)
		// 0x8 = ?
	case 0x102: name = "bkgd img ref"; break;
	case 0x103: name = "copyright/author"; break;
	case 0x104: name = "url1"; break; // URL for what?
	case 0x105: name = "url2"; break; // URL for what?
	case 0x106: name = "dl prot data"; break;
	case 0x107: name = "img ptr bias"; break;
	}
	return name?name:"?";
}

// sets d->last_chunklen (=total size)
// may set d->stopflag, ...
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
	de_dbg(c, "chunk at %"I64_FMT", type=0x%04x (%s)", cctx->ck_pos, (UI)cctx->ck_type,
		get_chunk_type_name(cctx->ck_type));
	de_dbg_indent(c, 1);

	if(cctx->ck_type==0x0001) {
		ret = dbuf_search_byte(c->infile, 0x00, cctx->ck_pos+2, 4096, &foundpos);
		if(ret) {
			cctx->ck_len = foundpos + 1 - cctx->ck_pos;
			handle_chunk_string(c, d, cctx->ck_pos+2, cctx->ck_len-2,
				d->char_name, "char name");
		}
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
		i64 dlen_field;

		dlen_field = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = dlen_field + 4;

		if(cctx->ck_type==0x0100 || cctx->ck_type==0x0102) {
			handle_chunk_1imageptr(c, d, cctx, 4);
		}
		else if(cctx->ck_type==0x0103) {
			handle_chunk_string(c, d, cctx->ck_pos+4, cctx->ck_len-4, d->tmpstr,
				"copyright/author");
		}
		else if(cctx->ck_type==0x0104) {
			handle_chunk_string(c, d, cctx->ck_pos+4, cctx->ck_len-4, d->tmpstr, "url1");
		}
		else if(cctx->ck_type==0x0105) {
			handle_chunk_string(c, d, cctx->ck_pos+4, cctx->ck_len-4, d->tmpstr, "url2");
		}
		else if(cctx->ck_type==0x0107) {
			n = de_getu32le(cctx->ck_pos+4);
			d->img_ptr_bias += n;
			de_sanitize_offset(&d->img_ptr_bias);
			de_dbg(c, "image pointer bias: %"I64_FMT, n);
		}
	}

	if(cctx->ck_len<2) {
		de_err(c, "Invalid file or unsupported chunk (0x%04x); can't continue",
			cctx->ck_type);
		d->stopflag = 1;
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
	d->char_name = ucstring_create(c);
	d->tmpstr = ucstring_create(c);
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	d->opt_applymasks = de_get_ext_option_bool(c, "comicchat:applymasks", 1);
	d->prefer_bmp_output = (u8)de_get_ext_option_bool(c, "comicchat:tobmp", 0);

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	pos += 2;
	d->fmt_code = (UI)de_getu16le_p(&pos);
	d->major_ver = (UI)de_getu16le_p(&pos);
	if(d->major_ver==1) tstr = "v1.0-2.1";
	else if(d->major_ver==2) tstr = "v2.5";
	else tstr = "?";
	de_dbg(c, "fmt ver: %u (%s)", d->major_ver, tstr);
	if(d->major_ver==2 && d->fmt_code==3) tstr = " (BGB)";
	else tstr = "";
	de_dbg(c, "fmt subtype: %u%s", d->fmt_code, tstr);
	de_dbg_indent(c, -1);

	d->images_seen = de_inthashtable_create(c);
	while(1) {
		comicchat_read_chunk(c, d, pos);
		if(d->stopflag || d->last_chunklen==0) goto done;
		pos += d->last_chunklen;
	}

done:
	if(d) {
		ucstring_destroy(d->char_name);
		ucstring_destroy(d->tmpstr);
		de_inthashtable_destroy(c, d->images_seen);
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

static void de_help_comicchat(deark *c)
{
	de_msg(c, "-opt comicchat:tobmp : Write icons and backgrounds to BMP format");
	de_msg(c, "-opt comicchat:applymasks=0 : Write masks to separate files");
}

void de_module_comicchat(deark *c, struct deark_module_info *mi)
{
	mi->id = "comicchat";
	mi->desc = "Microsoft Comic Chat AVB or BGB";
	mi->run_fn = de_run_comicchat;
	mi->identify_fn = de_identify_comicchat;
	mi->help_fn = de_help_comicchat;
}
