// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// MS Comic Chat .AVB, .BGB

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_comicchat);

typedef struct localctx_comicchat {
	u8 errflag;
	u8 has_gestures;
	u8 found_pal;
	u8 found_0006;
	u8 stopflag;
	UI fmt_code;
	UI major_ver;
	i64 last_chunklen;
	i64 num_gestures;
	i64 pal_num_entries; // Reflects most recent palette written to .pal
	de_color pal[256];
	de_color tmppal[256];
} lctx;

struct chunk_ctx {
	UI ck_type;
	i64 ck_pos; // everything; starting from start of type field
	i64 ck_len; // total length
	i64 internal_dlen; // length minus 4-byte header; applies to some chunks
	i64 internal_dpos;
};

static void read_palette(deark *c, lctx *d, struct chunk_ctx *cctx)
{
	i64 num_entries;
	i64 pos = cctx->internal_dpos;

	d->found_pal = 1;
	num_entries = de_getu16le_p(&pos);
	de_dbg(c, "num entries: %"I64_FMT, num_entries);
	if(num_entries>256) return;

	if(num_entries>0) {
		de_read_simple_palette(c, c->infile, pos, num_entries, 3, d->pal,
			256, DE_RDPALTYPE_24BIT, 0);
		d->pal_num_entries = num_entries;
	}
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

struct image_extract_ctx {
	struct de_bmpinfo bi;
	i64 ihpos;
	u8 is_mask;
	dbuf *unc_pixels;
};

static void handle_chunk_bmp(deark *c, lctx *d, struct chunk_ctx *cctx)
{
	UI bitcount, cmpr;

	if(cctx->ck_pos+cctx->ck_len > c->infile->len) goto done;
	if(cctx->ck_len < 54) goto done;

	bitcount = (UI)de_getu16le(cctx->ck_pos+14+14);
	de_dbg(c, "bit count: %u", bitcount);
	cmpr = (UI)de_getu32le(cctx->ck_pos+14+16);
	de_dbg(c, "compression: %u", cmpr);

	// TODO: Masks need to be applied, not written to separate files.
	dbuf_create_file_from_slice(c->infile, cctx->ck_pos, cctx->ck_len,
		"bmp", NULL, 0);
done:
	;
}

static void reconstruct_bmp(deark *c, lctx *d, struct image_extract_ctx *ic)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "bmp", NULL,
		(ic->is_mask?DE_CREATEFLAG_IS_AUX:0));

	fmtutil_generate_bmpfileheader(c, outf, &ic->bi, 0);
	dbuf_copy(c->infile, ic->ihpos, ic->bi.infohdrsize, outf);

	// TODO: Masks need to be applied, not written to separate files.
	if(ic->is_mask) {
		dbuf_write(outf, (const u8*)"\0\0\0\0\xff\xff\xff\0", 8);
	}
	else if(ic->bi.bitcount<=8) {
		write_palette(c, d, outf, d->pal, ic->bi.pal_entries);
	}

	dbuf_copy(ic->unc_pixels, 0, ic->unc_pixels->len, outf);
	dbuf_close(outf);
}

static void decode_2bpp_dib(deark *c, lctx *d, struct image_extract_ctx *ic)
{
	de_bitmap *img = NULL;

	d->tmppal[0] = DE_STOCKCOLOR_TRANSPARENT;
	d->tmppal[1] = DE_MAKE_GRAY(254);
	d->tmppal[2] = DE_STOCKCOLOR_WHITE;
	d->tmppal[3] = DE_STOCKCOLOR_BLACK;

	img = de_bitmap_create(c, ic->bi.width, ic->bi.height, 2);
	de_convert_image_paletted(ic->unc_pixels, 0, 2, ic->bi.rowspan, d->tmppal,
		img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);
	de_bitmap_destroy(img);
}

static void handle_chunk_dib(deark *c, lctx *d, struct chunk_ctx *cctx)
{
	int ret;
	i64 pos;
	i64 cmpr_pos;
	i64 orig_len, cmpr_len;
	struct image_extract_ctx *ic = NULL;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_deflate_params deflateparams;

	ic = de_malloc(c, sizeof(struct image_extract_ctx));
	de_zeromem(&deflateparams, sizeof(struct de_deflate_params));
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	if(d->errflag) goto done;
	if(!d->found_pal) goto done;

	ic->ihpos = cctx->ck_pos;
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

	ic->is_mask = (ic->bi.bitcount==1 && ic->bi.pal_entries==2);

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
	de_dbg(c, "chunk at %"I64_FMT, cctx->ck_pos);
	de_dbg_indent(c, 1);
	cctx->ck_type = (UI)de_getu16le(cctx->ck_pos);
	de_dbg(c, "chunk type: 0x%04x", cctx->ck_type);

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
	}
	else if(cctx->ck_type==0x0004) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 43*n;
	}
	else if(cctx->ck_type==0x0005 || cctx->ck_type==0x0009) {
		n = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 35*n;
	}
	else if(cctx->ck_type==0x0006) {
		d->found_0006 = 1;
		cctx->ck_len = 2;
	}
	else if(cctx->ck_type==0x0007) {
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
	}
	else if(cctx->ck_type==0x000b || cctx->ck_type==0x000c) {
		d->has_gestures = 1;
		d->num_gestures = de_getu16le(cctx->ck_pos+2);
		cctx->ck_len = 4 + 25*d->num_gestures;
	}
	// As a hack, treat 0x0028 and 0x4d42 as if they were chunk IDs.
	// TODO: Various chunks prior to 0x0006 presumably point to all of the
	// images. We should stop reading at 0x0006, and use the pointers instead.
	else if(cctx->ck_type==0x0028 && d->found_0006) {
		n = de_getu32le(cctx->ck_pos+40+4); // cmpr len
		cctx->ck_len = n + 40 + 8;
		handle_chunk_dib(c, d, cctx);
	}
	else if(cctx->ck_type==0x4d42 && d->found_0006) {
		cctx->ck_len = de_getu32le(cctx->ck_pos+2);
		handle_chunk_bmp(c, d, cctx);
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

		if(cctx->ck_type==0x0101) {
			read_palette(c, d, cctx);
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
	de_dbg_indent(c, -1);
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

	while(1) {
		comicchat_read_chunk(c, d, pos);
		if(d->errflag || d->stopflag || d->last_chunklen==0) goto done;
		pos += d->last_chunklen;
	}

done:
	if(d) {
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
	mi->flags |= DE_MODFLAG_NONWORKING;
}
