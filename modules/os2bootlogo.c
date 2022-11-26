// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// OS/2 Boot Logo

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_os2bootlogo);

#define IMG_WIDTH      640
#define IMG_MAX_HEIGHT 480
#define NUM_PLANES     4

struct plane_struct {
	i64 offset;
	i64 len;
	i64 dcmpr_nbytes;
};

typedef struct localctx_struct {
	struct plane_struct pl[4];
	i64 max_bytes_per_plane;
	u8 uses_lzss;

	// Contains all planes, at intervals of ->max_bytes_per_plane
	dbuf *unc_pixels;
} lctx;

struct exepack2_ctx {
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_lz77buffer *ringbuf;
	i64 cur_ipos;
	i64 endpos;
	i64 nbytes_written;
};

static void exepack2_lz77buf_writebytecb(struct de_lz77buffer *rb, const u8 n)
{
	struct exepack2_ctx *ectx = (struct  exepack2_ctx*)rb->userdata;

	dbuf_writebyte(ectx->dcmpro->f, n);
	ectx->nbytes_written++;
}

static void decompress_exepack2(deark *c, lctx *d,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres)
{
	struct exepack2_ctx *ectx = NULL;

	ectx = de_malloc(c, sizeof(struct exepack2_ctx));
	ectx->dcmpri = dcmpri;
	ectx->dcmpro = dcmpro;
	ectx->cur_ipos = dcmpri->pos;
	ectx->endpos = dcmpri->pos + dcmpri->len;

	ectx->ringbuf = de_lz77buffer_create(c, 4096);
	ectx->ringbuf->writebyte_cb = exepack2_lz77buf_writebytecb;
	ectx->ringbuf->userdata = (void*)ectx;

	while(1) {
		i64 code_startpos;
		UI i;
		UI matchpos;
		UI matchlen;
		UI unc_count;
		u8 b0, b1, b2;
		u8 opcode0;
		const char *optype = "";

		if(ectx->cur_ipos >= ectx->endpos) goto after_dcmpr;
		if(ectx->nbytes_written >= dcmpro->expected_len) goto after_dcmpr;
		code_startpos = ectx->cur_ipos;
		b0 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);

		if(b0==0x00) { // stop code or RLE compressed data
			b1 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			if(b1==0) {
				de_dbg2(c, "stop code at %"I64_FMT, code_startpos);
				goto after_dcmpr;
			}
			else {
				UI run_len;

				run_len = (UI)b1;
				b2 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
				if(c->debug_level>=4) {
					de_dbg(c, "op=R val=%u count=%u", (UI)b2, run_len);
				}
				for(i=0; i<run_len; i++) {
					de_lz77buffer_add_literal_byte(ectx->ringbuf, b2);
				}
			}
			continue;
		}

		opcode0 = b0 & 0x3;
		if(opcode0!=0) d->uses_lzss = 1;

		switch(opcode0) {
		case 0: // nRoots token (uncompressed bytes only)
			optype = "U";
			unc_count = (UI)(b0>>2);
			matchlen = 0;
			matchpos = 0;
			break;
		case 1: // Short String token
			optype = "S";
			b1 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			unc_count = (UI)((b0>>2)&0x3);
			matchlen = 3+(UI)((b0>>4)&0x7);
			matchpos = ((UI)b1<<1) | (b0>>7);
			break;
		case 2: // Mid String token
			optype = "M";
			b1 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			unc_count = 0;
			matchlen = 3+(UI)((b0>>2)&0x3);
			matchpos = ((UI)b1<<4) | (b0>>4);
			break;
		default: // (3) Long String token
			optype = "L";
			b1 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			b2 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			unc_count = (UI)((b0>>2)&0xf);
			matchlen = ((UI)(b1&0xf)<<2) | (b0>>6);
			matchpos = ((UI)b2<<4) | (b1>>4);
			break;
		}

		if(c->debug_level>=4) {
			de_dbg(c, "op=%s u=%u d=%u l=%u", optype, unc_count, matchpos, matchlen);
			de_dbg_indent(c, 1);
		}

		for(i=0; i<unc_count; i++) {
			b2 = dbuf_getbyte_p(dcmpri->f, &ectx->cur_ipos);
			if(c->debug_level>=4) {
				de_dbg(c, "lit %u", (UI)b2);
			}
			de_lz77buffer_add_literal_byte(ectx->ringbuf, b2);
		}

		if(c->debug_level>=4) {
			de_dbg_indent(c, -1);
		}

		if(matchlen!=0) {
			de_lz77buffer_copy_from_hist(ectx->ringbuf,
				(UI)(ectx->ringbuf->curpos-matchpos), matchlen);
		}
	}

after_dcmpr:
	dbuf_flush(dcmpro->f);
	dres->bytes_consumed_valid = 1;
	dres->bytes_consumed = ectx->cur_ipos - dcmpri->pos;
	de_lz77buffer_destroy(c, ectx->ringbuf);
	de_free(c, ectx);
}

static int do_decompress_plane(deark *c, lctx *d, int pn)
{
	struct plane_struct *pli;
	int retval = 0;
	i64 orig_len;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	pli = &d->pl[pn];
	de_dbg(c, "decompressing plane %d at %"I64_FMT, pn, pli->offset);
	de_dbg_indent(c, 1);

	dbuf_truncate(d->unc_pixels, (i64)pn*d->max_bytes_per_plane);
	dbuf_flush(d->unc_pixels);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pli->offset;
	dcmpri.len = pli->len;
	dcmpro.f = d->unc_pixels;
	dcmpro.expected_len = d->max_bytes_per_plane;
	dcmpro.len_known = 1;

	orig_len = d->unc_pixels->len;
	decompress_exepack2(c, d, &dcmpri, &dcmpro, &dres);

	if(dres.errcode) {
		de_err(c, "Decompression failed (plane %d): %s",
			pn, de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	pli->dcmpr_nbytes = d->unc_pixels->len - orig_len;
	de_dbg(c, "decompressed to %"I64_FMT" bytes", pli->dcmpr_nbytes);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_write_image(deark *c, lctx *d)
{
	i64 rowspan;
	i64 height;
	UI pn;
	de_bitmap *img = NULL;
	static const de_color pal[16] = {
		0xff000000U,0xff000080U,0xff008000U,0xff008080U,
		0xff800000U,0xff800080U,0xff808000U,0xff808080U,
		0xffccccccU,0xff0000ffU,0xff00ff00U,0xff00ffffU,
		0xffff0000U,0xffff00ffU,0xffffff00U,0xffffffffU
	};

	rowspan = IMG_WIDTH/8;
	height = 400;
	for(pn=0; pn<NUM_PLANES; pn++) {
		if(d->pl[pn].dcmpr_nbytes > rowspan*400) {
			height = 480;
			break;
		}
	}

	de_dbg_dimensions(c, IMG_WIDTH, height);
	img = de_bitmap_create(c, IMG_WIDTH, height, 3);

	de_convert_image_paletted_planar(d->unc_pixels, 0, NUM_PLANES, rowspan,
		d->max_bytes_per_plane, pal, img, 0x02);

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_read_header(deark *c, lctx *d, i64 pos)
{
	int k;

	de_dbg(c, "header at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	for(k=0; k<NUM_PLANES; k++) {
		d->pl[k].offset = de_getu32le_p(&pos);
		d->pl[k].len = de_getu32le_p(&pos);
		de_dbg(c, "plane %d: pos=%"I64_FMT", len=%"I64_FMT, k, d->pl[k].offset,
			d->pl[k].len);
	}

	de_dbg_indent(c, -1);
}

static void de_run_os2bootlogo(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	int k;

	d = de_malloc(c, sizeof(lctx));

	d->max_bytes_per_plane = IMG_WIDTH*IMG_MAX_HEIGHT/8;
	do_read_header(c, d, 0);

	d->unc_pixels = dbuf_create_membuf(c, d->max_bytes_per_plane*NUM_PLANES, 0x1);
	dbuf_enable_wbuffer(d->unc_pixels);
	for(k=0; k<NUM_PLANES; k++) {
		if(!do_decompress_plane(c, d, k)) goto done;
	}

	// There's a program that makes files that only use RLE compression.
	// Out of curiosity, I want to identify such files.
	de_dbg(c, "cmpr uses lzss: %u", (UI)d->uses_lzss);

	do_write_image(c, d);

done:
	if(d) {
		dbuf_close(d->unc_pixels);
		de_free(c, d);
	}
}

static int de_identify_os2bootlogo(deark *c)
{
	UI offs;
	UI len;
	UI i;
	UI next_expected_offs = 32;
	i64 pos = 0;

	for(i=0; i<4; i++) {
		offs = (UI)de_getu32le_p(&pos);
		if(offs!=next_expected_offs) return 0;
		len = (UI)de_getu32le_p(&pos);
		if(len<2) return 0;
		next_expected_offs = offs+len;
	}
	if(next_expected_offs!=c->infile->len) return 0;
	return 55;
}

void de_module_os2bootlogo(deark *c, struct deark_module_info *mi)
{
	mi->id = "os2bootlogo";
	mi->desc = "OS/2 boot logo";
	mi->run_fn = de_run_os2bootlogo;
	mi->identify_fn = de_identify_os2bootlogo;
}
