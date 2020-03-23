// This file is part of Deark.
// Copyright (C) 2017-2020 Jason Summers
// See the file COPYING for terms of use.

// IFF-ANIM animation format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_anim);

// TODO: This code might eventually replace the current ilbm module.
// Until then, expect a lot of duplicated code.

#define ANIM_MAX_FRAMES 10000

#define CODE_ANHD 0x414e4844U
#define CODE_ANIM 0x414e494dU
#define CODE_BMHD 0x424d4844U
#define CODE_BODY 0x424f4459U
#define CODE_CAMG 0x43414d47U
#define CODE_CMAP 0x434d4150U
#define CODE_CRNG 0x43524e47U
#define CODE_DLTA 0x444c5441U
#define CODE_DPI  0x44504920U
#define CODE_DRNG 0x44524e47U
#define CODE_FORM 0x464f524dU
#define CODE_GRAB 0x47524142U
#define CODE_ILBM 0x494c424dU
#define CODE_TINY 0x54494e59U

#define ANIM_OP_XOR 1

struct bmhd_info {
	i64 width, height;
	u8 compression;
	u8 masking_code;
	i64 planes;
	i64 transparent_color;
	i64 x_aspect, y_aspect;
	//i64 planes_total;
	//i64 rowspan;
	//i64 planespan;
	i64 bits_per_row_per_plane;
	i64 bytes_per_row_per_plane;
	i64 frame_buffer_rowspan;
	i64 frame_buffer_size;
	//u8 has_hotspot;
	//int hotspot_x, hotspot_y;
	//int is_thumb;
	//const char *filename_token;
};

struct frame_ctx {
	u32 formtype;
	int frame_idx;
	int done_flag; // Have we processed the image (BODY/DLTA/etc. chunk)?
	u8 op;
	UI bits;
	dbuf *frame_buffer;
};

typedef struct localctx_struct {
	int FORM_level; // nesting level of the frames' FORM chunks
	int errflag;
	int num_frames_started;
	int num_frames_finished;
	int debug_frame_buffer;
	u8 found_bmhd;
	u8 found_cmap;
	u8 has_camg;
	u8 ham_flag; // "hold and modify"
	u8 is_ham6;
	u8 is_ham8;
	u8 ehb_flag; // "extra halfbrite"
	UI camg_mode;
	struct frame_ctx *frctx; // Non-NULL means we're inside a frame
	struct frame_ctx *oldfrctx[2];
	struct bmhd_info main_img;
	i64 pal_ncolors; // Number of colors we read from the file
	u32 pal[256];
} lctx;

static const char *anim_get_op_name(u8 op)
{
	const char *name = NULL;

	switch(op) {
	case 0: name="direct"; break;
	case ANIM_OP_XOR: name="XOR"; break;
	case 2: name="long delta"; break;
	case 3: name="short delta"; break;
	case 4: name="short/long delta"; break;
	case 5: name="byte vert. delta"; break;
	case 7: name="short/long vert. delta"; break;
	}
	return name?name:"?";
}

static void destroy_frame(deark *c, lctx *d, struct frame_ctx *frctx)
{
	if(!frctx) return;
	dbuf_close(frctx->frame_buffer);
	de_free(c, frctx);
}

static void do_cmap(deark *c, lctx *d, i64 pos, i64 len)
{
	d->found_cmap = 1;
	d->pal_ncolors = len/3;
	de_dbg(c, "number of palette colors: %d", (int)d->pal_ncolors);
	if(d->pal_ncolors>256) d->pal_ncolors=256;

	de_read_palette_rgb(c->infile, pos, d->pal_ncolors, 3, d->pal, 256, 0);
}

static int do_bmhd(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int retval = 0;
	const char *masking_name;
	struct frame_ctx *frctx = d->frctx;

	if(!frctx) goto done;
	if(len<20) {
		de_err(c, "Bad BMHD chunk");
		goto done;
	}

	d->found_bmhd = 1;
	d->main_img.width = de_getu16be_p(&pos);
	d->main_img.height = de_getu16be_p(&pos);
	de_dbg_dimensions(c, d->main_img.width, d->main_img.height);
	pos += 4;
	d->main_img.planes = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)d->main_img.planes);
	d->main_img.masking_code = de_getbyte_p(&pos);
	switch(d->main_img.masking_code) {
	case 0: masking_name = "no transparency"; break;
	case 1: masking_name = "1-bit transparency mask"; break;
	case 2: masking_name = "color-key transparency"; break;
	case 3: masking_name = "lasso"; break;
	default: masking_name = "unknown"; break;
	}

	d->main_img.compression = de_getbyte_p(&pos);
	de_dbg(c, "compression: %d", (int)d->main_img.compression);

	pos++;
	d->main_img.transparent_color = de_getu16be_p(&pos);
	de_dbg(c, "masking: %d (%s)", (int)d->main_img.masking_code, masking_name);
	if(d->main_img.masking_code==2 || d->main_img.masking_code==3) {
		de_dbg(c, " color key: %d", (int)d->main_img.transparent_color);
	}

	d->main_img.x_aspect = (i64)de_getbyte_p(&pos);
	d->main_img.y_aspect = (i64)de_getbyte_p(&pos);
	de_dbg(c, "apect ratio: %d, %d", (int)d->main_img.x_aspect, (int)d->main_img.y_aspect);

	retval = 1;
done:
	return retval;
}

// Decompress into frctx->frame_buffer, at dstpos1
static void decompress_plane_delta_op5(deark *c, lctx *d, struct frame_ctx *frctx, i64 pos1, i64 maxlen,
	i64 dstpos1, i64 dststride)
{
	i64 num_columns;
	i64 col;
	i64 pos = pos1;

	de_dbg(c, "delta5 plane at %"I64_FMT", maxlen=%"I64_FMT, pos1, maxlen);
	num_columns = de_pad_to_n(d->main_img.width, 8)/8;
	for(col=0; col<num_columns; col++) {
		i64 opcount;
		i64 opidx;
		i64 k;
		u8 op;
		i64 dstpos = dstpos1 + col;

		opcount = de_getbyte_p(&pos);
		de_dbg2(c, "col %d opt count: %d at %"I64_FMT, (int)col, (int)opcount, pos);
		for(opidx=0; opidx<opcount; opidx++) {
			i64 count;
			u8 val;

			if(pos >= pos1+maxlen) goto done;
			op = de_getbyte_p(&pos);
			if(op==0) { // RLE
				count = (i64)de_getbyte_p(&pos);
				val = de_getbyte_p(&pos);
				for(k=0; k<count; k++) {
					dbuf_writebyte_at(frctx->frame_buffer, dstpos, val);
					dstpos += dststride;
				}
			}
			else if(op<0x80) { // skip
				dstpos += (i64)op * dststride;
			}
			else { // uncompressed
				count = (i64)(op & 0x7f);
				for(k=0; k<count; k++) {
					val = de_getbyte_p(&pos);
					dbuf_writebyte_at(frctx->frame_buffer, dstpos, val);
					dstpos += dststride;
				}
			}
		}
	}

done:
	;
}

// Decompress into frctx->frame_buffer, at dstpos1
static void decompress_delta_op5(deark *c, lctx *d, struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 planedata_offs[16];
	i64 pos = pos1;
	int i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frctx->frame_buffer) goto done;

	de_dbg(c, "delta5 %"I64_FMT", len=%"I64_FMT, pos1, len);

	if(frctx->bits != 0) {
		de_err(c, "Unsupported ANHD options");
		d->errflag = 1;
		goto done;
	}

	for(i=0; i<16; i++) {
		planedata_offs[i] = de_getu32be_p(&pos);
		if(i<d->main_img.planes) {
			de_dbg(c, "plane[%d] offs: %"I64_FMT, i, planedata_offs[i]);
			if(planedata_offs[i]>0) {
				decompress_plane_delta_op5(c, d, frctx, pos1+planedata_offs[i], len-planedata_offs[i],
					i * d->main_img.bytes_per_row_per_plane,
					d->main_img.frame_buffer_rowspan);
			}
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_dlta(deark *c, lctx *d, i64 pos1, i64 len)
{
	struct frame_ctx *frctx = d->frctx;
	struct frame_ctx *reference_frctx = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->errflag) goto done;
	if(!d->found_bmhd) goto done;
	if(!frctx) goto done;
	if(frctx->done_flag) goto done;
	frctx->done_flag = 1;

	// Find the reference frame
	if(frctx->frame_idx==1) {
		reference_frctx = d->oldfrctx[0];
	}
	else if(frctx->frame_idx>=2) {
		reference_frctx = d->oldfrctx[frctx->frame_idx%2];
	}

	if(d->main_img.masking_code != 0) {
		de_err(c, "Transparency not supported");
		d->errflag = 1;
		goto done;
	}
	if(d->main_img.planes<1 || d->main_img.planes>8) {
		de_err(c, "Bad or unsupported number of planes (%d)", (int)d->main_img.planes);
		d->errflag = 1;
		goto done;
	}

	if(!frctx->frame_buffer) {
		frctx->frame_buffer = dbuf_create_membuf(c, d->main_img.frame_buffer_size, 0x1);
	}

	if(reference_frctx && reference_frctx->frame_buffer) {
		dbuf_copy(reference_frctx->frame_buffer, 0, reference_frctx->frame_buffer->len,
			frctx->frame_buffer);
	}

	switch(frctx->op) {
	case 5:
		decompress_delta_op5(c, d, frctx, pos1, len);
		break;
	default:
		de_err(c, "Unsupported DLTA operation: %d", (int)frctx->op);
		d->errflag = 1;
		goto done;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int decompress_method1(deark *c, lctx *d, i64 pos, i64 len, dbuf *unc_pixels,
	i64 expected_len)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = expected_len;

	de_fmtutil_decompress_packbits_ex(c, &dcmpri, &dcmpro, &dres);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", dres.errmsg);
		goto done;
	}
	retval = 1;
done:
	return retval;
}

static void do_body(deark *c, lctx *d, i64 pos1, i64 len)
{
	struct frame_ctx *frctx = d->frctx;
	int ok = 0;

	if(d->errflag) goto done;
	if(!d->found_bmhd) goto done;
	if(!frctx) goto done;
	if(frctx->done_flag) goto done;
	frctx->done_flag = 1;

	if(d->main_img.compression!=1) {
		de_err(c, "Unsupported compression method (%d)", (int)d->main_img.compression);
		goto done;
	}

	d->main_img.bits_per_row_per_plane = de_pad_to_n(d->main_img.width, 16);
	d->main_img.bytes_per_row_per_plane = d->main_img.bits_per_row_per_plane/8;
	d->main_img.frame_buffer_rowspan = d->main_img.bytes_per_row_per_plane * d->main_img.planes;
	d->main_img.frame_buffer_size = d->main_img.frame_buffer_rowspan * d->main_img.height;

	if(!frctx->frame_buffer) {
		frctx->frame_buffer = dbuf_create_membuf(c, d->main_img.frame_buffer_size, 0x1);
	}

	if(!decompress_method1(c, d, pos1, len, frctx->frame_buffer, d->main_img.frame_buffer_size)) goto done;
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", len, frctx->frame_buffer->len);
	if(frctx->frame_buffer->len != d->main_img.frame_buffer_size) {
		de_warn(c, "Expected %"I64_FMT" decompressed bytes, got %"I64_FMT, d->main_img.frame_buffer_size,
			frctx->frame_buffer->len);
	}

	ok = 1;

done:
	if(!ok) {
		d->errflag = 1;
	}
}

static void do_anim_anhd(deark *c, lctx *d, i64 pos, i64 len)
{
	u8 ileave;
	i64 tmp;
	struct frame_ctx *frctx = d->frctx;

	if(!frctx) return;
	if(len<24) return;

	frctx->op = de_getbyte(pos++);
	de_dbg(c, "operation: %d (%s)", (int)frctx->op, anim_get_op_name(frctx->op));

	if(frctx->op==ANIM_OP_XOR) {
		pos++; // Mask
		pos += 2; // w
		pos += 2; // h
		pos += 2; // x
		pos += 2; // y
	}
	else {
		pos += 9;
	}
	pos += 4; // abstime

	tmp = de_getu32be_p(&pos); // reltime
	de_dbg(c, "reltime: %.5f sec", ((double)tmp)/60.0);

	ileave = de_getbyte_p(&pos); // interleave
	de_dbg(c, "interleave: %d", (int)ileave);
	if(ileave!=0 && ileave!=2) {
		de_err(c, "Unsupported interleave");
		d->errflag = 1;
	}

	pos++; // pad0

	frctx->bits = (UI)de_getu32be_p(&pos);
	de_dbg(c, "flags: 0x%08u", frctx->bits);
}

static void do_camg(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len<4) return;
	d->has_camg = 1;

	d->ham_flag = 0;
	d->is_ham6 = 0;
	d->is_ham8 = 0;
	d->ehb_flag = 0;

	d->camg_mode = (UI)de_getu32be(pos);
	de_dbg(c, "CAMG mode: 0x%x", d->camg_mode);

	if(d->camg_mode & 0x0800)
		d->ham_flag = 1;
	if(d->camg_mode & 0x0080)
		d->ehb_flag = 1;

	de_dbg_indent(c, 1);
	de_dbg(c, "HAM: %d", (int)d->ham_flag);
	de_dbg(c, "EHB: %d", (int)d->ehb_flag);
	de_dbg_indent(c, -1);

	if(d->ham_flag) {
		if(d->main_img.planes==6 || d->main_img.planes==5) {
			d->is_ham6 = 1;
		}
		else if(d->main_img.planes==8 || d->main_img.planes==7) {
			d->is_ham8 = 1;
		}
		else {
			de_warn(c, "Invalid bit depth (%d) for HAM image.", (int)d->main_img.planes);
		}
	}

	if(d->ehb_flag) {
		de_err(c, "EHB images are not supported");
		d->errflag = 1;
	}
}

static void render_pixel_row_ham6(deark *c, lctx *d, i64 rownum, const u8 *rowbuf,
	UI rowbuf_size, de_bitmap *img)
{
	UI i;
	u8 cr, cg, cb;

	// At the beginning of each row, the color accumulators are
	// initialized to palette entry 0.
	cr = DE_COLOR_R(d->pal[0]);
	cg = DE_COLOR_G(d->pal[0]);
	cb = DE_COLOR_B(d->pal[0]);

	for(i=0; i<rowbuf_size; i++) {
		u32 clr;
		u8 val = rowbuf[i];

		switch((val>>4)&0x3) {
		case 0x1: // Modify blue value
			cb = 17*(val&0x0f);
			break;
		case 0x2: // Modify red value
			cr = 17*(val&0x0f);
			break;
		case 0x3: // Modify green value
			cg = 17*(val&0x0f);
			break;
		default: // 0: Use colormap value
			clr = d->pal[(UI)val];
			cr = DE_COLOR_R(clr);
			cg = DE_COLOR_G(clr);
			cb = DE_COLOR_B(clr);
			break;
		}

		de_bitmap_setpixel_rgb(img, (i64)i, rownum, DE_MAKE_RGB(cr, cg, cb));
	}
}

static void render_pixel_row_ham8(deark *c, lctx *d, i64 rownum, const u8 *rowbuf,
	UI rowbuf_size, de_bitmap *img)
{
	UI i;
	u8 cr, cg, cb;

	// At the beginning of each row, the color accumulators are
	// initialized to palette entry 0.
	cr = DE_COLOR_R(d->pal[0]);
	cg = DE_COLOR_G(d->pal[0]);
	cb = DE_COLOR_B(d->pal[0]);

	for(i=0; i<rowbuf_size; i++) {
		u32 clr;
		u8 val = rowbuf[i];

		switch((val>>6)&0x3) {
		case 0x1:
			cb = ((val&0x3f)<<2)|((val&0x3f)>>4);
			break;
		case 0x2:
			cr = ((val&0x3f)<<2)|((val&0x3f)>>4);
			break;
		case 0x3:
			cg = ((val&0x3f)<<2)|((val&0x3f)>>4);
			break;
		default:
			clr = d->pal[(UI)val];
			cr = DE_COLOR_R(clr);
			cg = DE_COLOR_G(clr);
			cb = DE_COLOR_B(clr);
			break;
		}

		de_bitmap_setpixel_rgb(img, (i64)i, rownum, DE_MAKE_RGB(cr, cg, cb));
	}
}

static void render_pixel_row_normal(deark *c, lctx *d, i64 rownum, const u8 *rowbuf,
	UI rowbuf_size, de_bitmap *img)
{
	UI k;

	for(k=0; k<rowbuf_size; k++) {
		de_bitmap_setpixel_rgb(img, (i64)k, rownum, d->pal[(UI)rowbuf[k]]);
	}
}

// Generate the final image and write it to a file.
static void write_frame(deark *c, lctx *d, struct frame_ctx *frctx)
{
	de_bitmap *img = NULL;
	i64 j;
	u8 pixelval[8];
	u8 *rowbuf = NULL; // The current row of pixel (palette) value
	UI rowbuf_size;

	if(d->errflag) goto done;
	if(!frctx) goto done;
	if(!frctx->frame_buffer) {
		d->errflag = 1;
		goto done;
	}
	if(d->main_img.planes<1 || d->main_img.planes>8) goto done;

	if(d->debug_frame_buffer) {
		de_convert_and_write_image_bilevel(frctx->frame_buffer, 0,
			d->main_img.bits_per_row_per_plane * d->main_img.planes,
			d->main_img.height, d->main_img.frame_buffer_rowspan, 0, NULL, 0);
	}

	rowbuf_size = (UI)d->main_img.width;
	rowbuf = de_malloc(c, rowbuf_size);

	img = de_bitmap_create(c, d->main_img.width, d->main_img.height, 3);
	for(j=0; j<d->main_img.height; j++) {
		i64 z;
		i64 plane;
		UI k;

		// Process 8 pixels at a time
		for(z=0; z<d->main_img.bytes_per_row_per_plane; z++) {
			de_zeromem(pixelval, sizeof(pixelval));

			// Read the zth byte in each plane
			for(plane=0; plane<d->main_img.planes; plane++) {
				u8 b;

				b = dbuf_getbyte(frctx->frame_buffer,
					j*d->main_img.frame_buffer_rowspan +
					plane*d->main_img.bytes_per_row_per_plane + z);

				for(k=0; k<8; k++) {
					if(b & (1U<<(7-k))) {
						pixelval[k] |= 1U<<(UI)plane;
					}
				}
			}

			for(k=0; k<8; k++) {
				UI idx;

				idx = (UI)z*8+k;
				if(idx < rowbuf_size) {
					rowbuf[idx] = pixelval[k];
				}
			}
		}

		if(d->is_ham6) {
			render_pixel_row_ham6(c, d, j, rowbuf, rowbuf_size, img);
		}
		else if(d->is_ham8) {
			render_pixel_row_ham8(c, d, j, rowbuf, rowbuf_size, img);
		}
		else {
			render_pixel_row_normal(c, d, j, rowbuf, rowbuf_size, img);
		}
	}

	de_bitmap_write_to_file_finfo(img, NULL, 0);

done:
	de_bitmap_destroy(img);
	de_free(c, rowbuf);
}

static void anim_on_frame_begin(deark *c, lctx *d, u32 formtype)
{
	if(d->frctx) return;
	d->num_frames_started++;
	d->frctx = de_malloc(c, sizeof(struct frame_ctx));
	d->frctx->formtype = formtype;
	d->frctx->frame_idx = d->num_frames_finished;
	de_dbg(c, "[frame #%d begin]", d->frctx->frame_idx);
}

static void anim_on_frame_end(deark *c, lctx *d)
{
	int where_to_save_this_frame;
	if(!d->frctx) return;

	de_dbg(c, "[frame #%d end]", d->frctx->frame_idx);

	write_frame(c, d, d->frctx);

	where_to_save_this_frame = d->frctx->frame_idx % 2;

	destroy_frame(c, d, d->oldfrctx[where_to_save_this_frame]);
	d->oldfrctx[where_to_save_this_frame] = d->frctx;
	d->frctx = NULL;
	d->num_frames_finished++;
}

static int my_anim_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	int quitflag = 0;
	int saved_indent_level;
	lctx *d = (lctx*)ictx->userdata;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->num_frames_finished >= ANIM_MAX_FRAMES) {
		quitflag = 1;
		goto done;
	}

	// Pretend we can handle all nonstandard chunks
	if(!de_fmtutil_is_standard_iff_chunk(c, ictx, ictx->chunkctx->chunk4cc.id)) {
		ictx->handled = 1;
	}

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		if(ictx->level>d->FORM_level) break;
		ictx->is_std_container = 1;
		break;

	case CODE_BMHD:
		if(!d->frctx) goto done;
		if(!do_bmhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen)) {
			d->errflag = 1;
			goto done;
		}
		break;

	case CODE_DLTA:
		if(ictx->curr_container_contentstype4cc.id != CODE_ILBM) {
			d->errflag = 1;
			goto done;
		}
		if(!d->frctx) goto done;
		do_dlta(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_ANHD:
		if(!d->frctx) goto done;
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CMAP:
		do_cmap(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_BODY:
		if(ictx->curr_container_contentstype4cc.id != CODE_ILBM) {
			de_err(c, "Unsupported ILBM-like format");
			d->errflag = 1;
			goto done;
		}
		do_body(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CAMG:
		do_camg(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static int my_preprocess_ilbm_chunk_fn(deark *c, struct de_iffctx *ictx)
{
	const char *name = NULL;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_ANHD: name="animation header"; break;
	case CODE_BMHD: name="bitmap header"; break;
	case CODE_BODY: name="image data"; break;
	case CODE_CAMG: name="Amiga viewport mode"; break;
	case CODE_CMAP: name="color map"; break;
	case CODE_CRNG: name="color register range info"; break;
	case CODE_DLTA: name="delta-compressed data"; break;
	case CODE_DPI : name="dots/inch"; break;
	case CODE_DRNG: name="color cycle"; break;
	case CODE_GRAB: name="hotspot"; break;
	case CODE_TINY: name="thumbnail"; break;
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	else {
		de_fmtutil_default_iff_chunk_identify(c, ictx);
	}
	return 1;
}

static int my_on_std_container_start_fn(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->level==d->FORM_level) {
		if(d->frctx) {
			anim_on_frame_end(c, d);
		}
		anim_on_frame_begin(c, d, ictx->curr_container_contentstype4cc.id);
	}
	return 1;
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	u32 id;
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) {
		de_err(c, "Not an IFF file");
		goto done;
	}
	id = (u32)de_getu32be(8);
	switch(id) {
	case CODE_ANIM:
		d->FORM_level = 1;
		break;
	case CODE_ILBM:
		d->FORM_level = 0;
		break;
	default:
		de_err(c, "Not a supported IFF format");
		goto done;
	}

	if(id==CODE_ANIM) {
		de_declare_fmt(c, "IFF-ANIM");
	}

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_anim_chunk_handler;
	ictx->preprocess_chunk_fn = my_preprocess_ilbm_chunk_fn;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

done:
	de_free(c, ictx);
	if(d) {
		if(d->frctx) {
			anim_on_frame_end(c, d);
		}
		destroy_frame(c, d, d->frctx);
		destroy_frame(c, d, d->oldfrctx[0]);
		destroy_frame(c, d, d->oldfrctx[1]);
		de_free(c, d);
	}
}

static int de_identify_anim(deark *c)
{
	u32 id;

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) return 0;
	id = (u32)de_getu32be(8);
	if(id==CODE_ANIM) return 100;
	return 0;
}

void de_module_anim(deark *c, struct deark_module_info *mi)
{
	mi->id = "anim";
	mi->desc = "IFF-ANIM animation";
	mi->run_fn = de_run_anim;
	mi->identify_fn = de_identify_anim;
}
