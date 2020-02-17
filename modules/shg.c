// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Segmented Hypergraphics (SHG) and Multiple Resolution Bitmap (MRB)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_shg);

struct picture_ctx {
	u8 picture_type;
	u8 packing_method;

	i64 xdpi, ydpi;
	i64 planes;
	i64 bitcount; // per plane
	i64 rowspan; // per plane
	i64 width, height;
	i64 pal_size_in_colors;
	i64 pal_size_in_bytes;
	i64 final_image_size;
	i64 colors_used;
	i64 colors_important;
	i64 pal_offset;
};

typedef struct localctx_struct {
	i64 signature;

	i64 shg_startpos;
	i64 num_pictures;
} lctx;

struct rlectx {
	dbuf *outf;
	int compressed_run_pending;
	i64 compressed_run_count;
	i64 uncompressed_run_bytes_left;
	i64 nbytes_consumed;
};

static void  my_shgrle_codec_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len)
{
	i64 k;
	struct rlectx *rctx = (struct rlectx*)dfctx->codec_private;

	for(k=0; k<buf_len; k++) {
		if(rctx->uncompressed_run_bytes_left>0) {
			dbuf_writebyte(rctx->outf, buf[k]);
			rctx->uncompressed_run_bytes_left--;
			rctx->nbytes_consumed++;
			continue;
		}

		if(rctx->compressed_run_pending) {
			dbuf_write_run(rctx->outf, buf[k], rctx->compressed_run_count);
			rctx->compressed_run_pending = 0;
			rctx->nbytes_consumed += 2;
			continue;
		}

		if(buf[k] & 0x80) { // beginning of uncompressed run
			rctx->uncompressed_run_bytes_left = (i64)(buf[k] & 0x7f);
			rctx->nbytes_consumed++;
			continue;
		}

		rctx->compressed_run_count = (i64)buf[k];
		rctx->compressed_run_pending = 1;
	}
}

static void my_shgrle_codec_finish(struct de_dfilter_ctx *dfctx)
{
	struct rlectx *rctx = (struct rlectx*)dfctx->codec_private;

	dfctx->dres->bytes_consumed_valid = 1;
	dfctx->dres->bytes_consumed = rctx->nbytes_consumed;
}

static void my_shgrle_codec_destroy(struct de_dfilter_ctx *dfctx)
{
	struct rlectx *rctx = (struct rlectx*)dfctx->codec_private;

	de_free(dfctx->c, rctx);
}

static void dfilter_shgrle_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params)
{
	struct rlectx *rctx = NULL;

	rctx = de_malloc(dfctx->c, sizeof(struct rlectx));
	rctx->outf = dfctx->dcmpro->f;

	dfctx->codec_private = (void*)rctx;
	dfctx->codec_finish_fn = my_shgrle_codec_finish;
	dfctx->codec_destroy_fn = my_shgrle_codec_destroy;
	dfctx->codec_addbuf_fn = my_shgrle_codec_addbuf;
}

// RunLength
static void do_decompress_type_1(deark *c, lctx *d,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	de_dbg(c, "doing RLE decompression");
	de_dfilter_decompress_oneshot(c, dfilter_shgrle_codec, NULL,
		dcmpri, dcmpro, dres);
}

// LZ77
static void do_decompress_type_2(deark *c, lctx *d,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	de_dbg(c, "doing LZ77 decompression");
	fmtutil_decompress_hlp_lz77(c, dcmpri, dcmpro, dres);
}

// LZ77 + RLE
static void do_decompress_type_3(deark *c, lctx *d,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	de_dbg(c, "doing LZ77+RLE decompression");
	de_dfilter_decompress_two_layer(c, dfilter_hlp_lz77_codec, NULL,
		dfilter_shgrle_codec, NULL, dcmpri, dcmpro, dres);
}

static int do_uncompress_picture_data(deark *c, lctx *d,
	struct picture_ctx *pctx,
	i64 compressed_offset, i64 compressed_size,
	dbuf *pixels_final, i64 final_image_size)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(pctx->packing_method>3) {
		de_err(c, "Unsupported compression type: %d", (int)pctx->packing_method);
		goto done;
	}

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = compressed_offset;
	dcmpri.len = compressed_size;
	dcmpro.f = pixels_final;
	dcmpro.len_known = 1;
	dcmpro.expected_len = final_image_size;

	switch(pctx->packing_method) {
	case 1:
		do_decompress_type_1(c, d, &dcmpri, &dcmpro, &dres);
		break;
	case 2:
		do_decompress_type_2(c, d, &dcmpri, &dcmpro, &dres);
		break;
	case 3:
		do_decompress_type_3(c, d, &dcmpri, &dcmpro, &dres);
		break;
	default: // 0, uncompressed
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
	}

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(pixels_final->len < final_image_size) {
		de_warn(c, "Expected %"I64_FMT" bytes after decompression, only got %"I64_FMT,
			final_image_size, pixels_final->len);
	}

	retval = 1;

done:
	return retval;
}

static i64 per_inch_to_per_meter(i64 dpi)
{
	return (i64)(0.5 + (100.0/2.54)*(double)dpi);
}

// Translate the picture into a BMP for output.
static void reconstruct_bmp(deark *c, lctx *d, struct picture_ctx *pctx,
	dbuf *pixels_final)
{
	dbuf *outf = NULL;
	struct de_bmpinfo bi;

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// Write fileheader
	de_zeromem(&bi, sizeof(struct de_bmpinfo));
	bi.size_of_headers_and_pal = 40 + pctx->pal_size_in_bytes;
	bi.total_size = bi.size_of_headers_and_pal + pctx->final_image_size;
	de_fmtutil_generate_bmpfileheader(c, outf, &bi, 0);

	// Write infoheader
	dbuf_writeu32le(outf, 40);
	dbuf_writeu32le(outf, pctx->width);
	dbuf_writeu32le(outf, pctx->height);
	dbuf_writeu16le(outf, pctx->planes);
	dbuf_writeu16le(outf, pctx->bitcount);
	dbuf_writeu32le(outf, 0); // compression
	dbuf_writeu32le(outf, 0); // SizeImage
	dbuf_writeu32le(outf, per_inch_to_per_meter(pctx->xdpi));
	dbuf_writeu32le(outf, per_inch_to_per_meter(pctx->ydpi));
	dbuf_writeu32le(outf, pctx->colors_used);
	dbuf_writeu32le(outf, pctx->colors_important);

	// Write color table
	dbuf_copy(c->infile, pctx->pal_offset, pctx->pal_size_in_bytes, outf);

	// Write pixels
	dbuf_copy(pixels_final, 0, pctx->final_image_size, outf);

	dbuf_close(outf);
}

// Translate the picture into a DDB, then call the ddb module.
static void reconstruct_ddb(deark *c, lctx *d, struct picture_ctx *pctx,
	dbuf *pixels_final)
{
	dbuf *tmpf = NULL;
	de_finfo *fi = NULL;
	de_module_params *mparams = NULL;

	tmpf = dbuf_create_membuf(c, 14+pctx->final_image_size, 0);

	// DDB header
	dbuf_writeu16le(tmpf, 0);                 // bmType
	dbuf_writeu16le(tmpf, pctx->width);       // bmWidth
	dbuf_writeu16le(tmpf, pctx->height);      // bmHeight
	dbuf_writeu16le(tmpf, pctx->rowspan);     // bmWidthBytes
	dbuf_writebyte(tmpf, (u8)pctx->planes);   // bmPlanes
	dbuf_writebyte(tmpf, (u8)pctx->bitcount); // bmBitsPixel
	dbuf_writeu32le(tmpf, 0);                 // bmBits

	dbuf_copy(pixels_final, 0, pctx->final_image_size, tmpf);

	de_dbg(c, "processing decompressed DDB");
	de_dbg_indent(c, 1);
	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_DPI;
	fi->density.xdens = (double)pctx->xdpi;
	fi->density.ydens = (double)pctx->ydpi;
	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.codes = "N";
	mparams->in_params.fi = fi;
	de_run_module_by_id_on_slice(c, "ddb", mparams, tmpf, 0, tmpf->len);
	de_free(c, mparams);
	de_dbg_indent(c, -1);

	dbuf_close(tmpf);
	de_finfo_destroy(c, fi);
}

// Handle a picture of type DIB or DDB.
static int do_dib_ddb(deark *c, lctx *d, struct picture_ctx *pctx, i64 pos1)
{
	i64 compressed_size;
	i64 hotspot_size;
	i64 compressed_offset_rel, compressed_offset_abs;
	i64 hotspot_offset_rel, hotspot_offset_abs;
	i64 pos;
	dbuf *pixels_final = NULL;
	int retval = 0;

	pos = pos1 + 2;

	pctx->xdpi = fmtutil_hlp_get_cul_p(c->infile, &pos);
	pctx->ydpi = fmtutil_hlp_get_cul_p(c->infile, &pos);
	de_dbg(c, "dpi: %d"DE_CHAR_TIMES"%d", (int)pctx->xdpi, (int)pctx->ydpi);
	if(pctx->xdpi<10 || pctx->ydpi<10 || pctx->xdpi>30000 || pctx->ydpi>30000) {
		pctx->xdpi = 0;
		pctx->ydpi = 0;
	}

	pctx->planes = fmtutil_hlp_get_cus_p(c->infile, &pos);
	de_dbg(c, "planes: %d", (int)pctx->planes);
	pctx->bitcount = fmtutil_hlp_get_cus_p(c->infile, &pos);
	de_dbg(c, "bitcount: %d", (int)pctx->bitcount);
	pctx->width = fmtutil_hlp_get_cul_p(c->infile, &pos);
	pctx->height = fmtutil_hlp_get_cul_p(c->infile, &pos);
	de_dbg_dimensions(c, pctx->width, pctx->height);

	pctx->colors_used = fmtutil_hlp_get_cul_p(c->infile, &pos);
	pctx->colors_important = fmtutil_hlp_get_cul_p(c->infile, &pos);
	de_dbg(c, "colors used=%d, important=%d", (int)pctx->colors_used,
		(int)pctx->colors_important);
	if(pctx->colors_important==1) {
		de_warn(c, "This image might have transparency, which is not supported");
		pctx->colors_important = 0;
	}

	compressed_size = fmtutil_hlp_get_cul_p(c->infile, &pos);
	hotspot_size = fmtutil_hlp_get_cul_p(c->infile, &pos);
	compressed_offset_rel = de_getu32le_p(&pos);
	compressed_offset_abs = pos1 + compressed_offset_rel;
	hotspot_offset_rel = de_getu32le_p(&pos);
	hotspot_offset_abs = pos1 + hotspot_offset_rel;
	de_dbg(c, "bits offset=%"I64_FMT" (+%"I64_FMT"=%"I64_FMT"), size=%"I64_FMT,
		compressed_offset_rel, pos1, compressed_offset_abs, compressed_size);
	de_dbg(c, "hotspot offset=%"I64_FMT" (+%"I64_FMT"=%"I64_FMT"), size=%"I64_FMT,
		hotspot_offset_rel, pos1, hotspot_offset_abs, hotspot_size);

	if(pctx->picture_type==5) {
		if(pctx->bitcount!=1 && pctx->bitcount!=4 &&pctx-> bitcount!=8)
		{
			de_err(c, "Unsupported bit count: %d", (int)pctx->bitcount);
			goto done;
		}

		if(pctx->planes<1 || pctx->planes>8) {
			de_err(c, "Unsupported planes: %d", (int)pctx->planes);
			goto done;
		}
	}
	else if(pctx->picture_type==6) {
		if(pctx->bitcount!=1 && pctx->bitcount!=4 &&pctx-> bitcount!=8 &&
			pctx->bitcount!=16 && pctx->bitcount!=24)
		{
			de_err(c, "Unsupported bit count: %d", (int)pctx->bitcount);
			goto done;
		}

		if(pctx->planes!=1) {
			de_err(c, "Unsupported planes: %d", (int)pctx->planes);
			goto done;
		}
	}

	if(!de_good_image_dimensions(c, pctx->width, pctx->height)) goto done;

	if(compressed_offset_abs + compressed_size > c->infile->len) {
		de_err(c, "Image goes beyond end of file");
		goto done;
	}

	pctx->pal_offset = pos;

	if(pctx->picture_type==5) {
		pctx->pal_size_in_colors = 0;
	}
	else if(pctx->bitcount>8) {
		pctx->pal_size_in_colors = 0;
	}
	else if(pctx->colors_used==0) {
		pctx->pal_size_in_colors = ((i64)1)<<pctx->bitcount;
	}
	else {
		pctx->pal_size_in_colors = pctx->colors_used;
		if(pctx->pal_size_in_colors<1 ||
			pctx->pal_size_in_colors>(((i64)1)<<pctx->bitcount))
		{
			goto done;
		}
	}

	de_dbg(c, "image data at %"I64_FMT", len=%"I64_FMT, compressed_offset_abs,
		compressed_size);

	pctx->pal_size_in_bytes = 4*pctx->pal_size_in_colors;

	if(pctx->picture_type==5) {
		pctx->rowspan = (((pctx->width*pctx->bitcount +15)/16)*2);
	}
	else {
		pctx->rowspan = (((pctx->width*pctx->bitcount +31)/32)*4);
	}
	pctx->final_image_size = pctx->height * pctx->planes * pctx->rowspan;

	pixels_final = dbuf_create_membuf(c, 0, 0);
	if(!do_uncompress_picture_data(c, d, pctx,
		compressed_offset_abs, compressed_size,
		pixels_final, pctx->final_image_size))
	{
		goto done;
	}

	if(pctx->picture_type==5) {
		reconstruct_ddb(c, d, pctx, pixels_final);
	}
	else if(pctx->picture_type==6) {
		reconstruct_bmp(c, d, pctx, pixels_final);
	}

	retval = 1;
done:
	dbuf_close(pixels_final);
	return retval;
}

static int do_wmf(deark *c, lctx *d, struct picture_ctx *pctx, i64 pos1)
{
	i64 pos;
	i64 mapping_mode;
	i64 width, height;
	i64 decompressed_size;
	i64 compressed_size;
	i64 hotspot_size;
	i64 compressed_offset;
	i64 hotspot_offset;
	dbuf *pixels_final = NULL;
	dbuf *outf = NULL;
	int retval = 0;

	pos = pos1 + 2;

	mapping_mode = fmtutil_hlp_get_cus_p(c->infile, &pos);
	width = de_getu16le(pos);
	pos+=2;
	height = de_getu16le(pos);
	pos+=2;
	de_dbg(c, "mapping mode: %d, nominal dimensions: %d"DE_CHAR_TIMES"%d",
		(int)mapping_mode, (int)width, (int)height);
	decompressed_size = fmtutil_hlp_get_cul_p(c->infile, &pos);
	compressed_size = fmtutil_hlp_get_cul_p(c->infile, &pos);
	hotspot_size = fmtutil_hlp_get_cul_p(c->infile, &pos);
	compressed_offset = de_getu32le(pos);
	pos+=4;
	compressed_offset += pos1;
	hotspot_offset = de_getu32le(pos);
	pos+=4;
	hotspot_offset += pos1;

	de_dbg(c, "wmf offset=%d, size=%d", (int)compressed_offset,
		(int)compressed_size);
	de_dbg(c, "hotspot offset=%d, size=%d", (int)hotspot_offset,
		(int)hotspot_size);
	if(compressed_offset+compressed_size>c->infile->len) {
		de_err(c, "WMF data goes beyond end of file");
		goto done;
	}

	pixels_final = dbuf_create_membuf(c, decompressed_size, 0x1);
	if(!do_uncompress_picture_data(c, d, pctx, compressed_offset, compressed_size,
		pixels_final, decompressed_size))
	{
		goto done;
	}

	if(pixels_final->len != decompressed_size) {
		de_warn(c, "Expected %d bytes after decompression, got %d",
			(int)decompressed_size, (int)pixels_final->len);
	}

	outf = dbuf_create_output_file(c, "wmf", NULL, 0);
	dbuf_copy(pixels_final, 0, pixels_final->len, outf);

	retval = 1;
done:
	dbuf_close(outf);
	dbuf_close(pixels_final);
	return retval;
}

static int do_picture(deark *c, lctx *d, i64 pic_index)
{
	i64 pic_offset;
	const char *ptname;
	struct picture_ctx *pctx = NULL;
	int retval = 0;

	pctx = de_malloc(c, sizeof(struct picture_ctx));
	de_dbg(c, "picture #%d", (int)pic_index);
	de_dbg_indent(c, 1);

	pic_offset = de_getu32le(d->shg_startpos + 4 + 4*pic_index);
	pic_offset += d->shg_startpos;
	de_dbg(c, "picture data at %d", (int)pic_offset);
	if(pic_offset >= c->infile->len) {
		goto done;
	}

	pctx->picture_type = de_getbyte(pic_offset);
	pctx->packing_method = de_getbyte(pic_offset+1);

	switch(pctx->picture_type) {
	case 5: ptname="DDB"; break;
	case 6: ptname="DIB"; break;
	case 8: ptname="metafile"; break;
	default: ptname="?";
	}
	de_dbg(c, "picture type: %d (%s)", (int)pctx->picture_type, ptname);
	de_dbg(c, "packing method: %d", (int)pctx->packing_method);

	if(pctx->picture_type==5 || pctx->picture_type==6) { // DDB or DIB
		do_dib_ddb(c, d, pctx, pic_offset);
	}
	else if(pctx->picture_type==8) { // WMF
		do_wmf(c, d, pctx, pic_offset);
	}
	else {
		de_warn(c, "Unsupported picture type: %d", (int)pctx->picture_type);
	}

	retval = 1;
done:
	de_free(c, pctx);
	de_dbg_indent(c, -1);
	return retval;
}

static void do_shg(deark *c, lctx *d)
{
	i64 k;

	d->num_pictures = de_getu16le(d->shg_startpos+2);
	de_dbg(c, "number of pictures in file: %d", (int)d->num_pictures);
	if(!de_good_image_count(c, d->num_pictures)) {
		goto done;
	}

	for(k=0; k<d->num_pictures; k++) {
		if(!do_picture(c, d, k)) {
			goto done;
		}
	}

done:
	;
}

static void de_run_shg(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->shg_startpos = 0;
	d->signature = de_getu16le(d->shg_startpos);
	if(d->signature==0x506c) {
		de_declare_fmt(c, "SHG");
	}
	else if(d->signature==0x706c) {
		de_declare_fmt(c, "MRB");
	}
	else {
		de_warn(c, "This is probably not an SHG/MRB file.");
	}

	do_shg(c, d);

	de_free(c, d);
}

static int de_identify_shg(deark *c)
{
	u8 buf[2];
	de_read(buf, 0, 2);
	if(buf[0]==0x6c && (buf[1]==0x50 || buf[1]==0x70)) {
		return 50;
	}
	return 0;
}

void de_module_shg(deark *c, struct deark_module_info *mi)
{
	mi->id = "shg";
	mi->desc = "SHG (Segmented Hypergraphics), MRB (Multiple Resolution Bitmap)";
	mi->run_fn = de_run_shg;
	mi->identify_fn = de_identify_shg;
}
