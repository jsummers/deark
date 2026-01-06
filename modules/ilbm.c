// This file is part of Deark.
// Copyright (C) 2016-2020 Jason Summers
// See the file COPYING for terms of use.

// IFF-ILBM and related image formats
// IFF-ANIM animation format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_ilbm);
DE_DECLARE_MODULE(de_module_anim);
DE_DECLARE_MODULE(de_module_deep);

#define ANIM_MAX_FRAMES 10000

#define CODE_8SVX 0x38535658U
#define CODE_ABIT 0x41424954U
#define CODE_ACBM 0x4143424dU
#define CODE_ANHD 0x414e4844U
#define CODE_ANIM 0x414e494dU
#define CODE_ANSQ 0x414e5351U
#define CODE_BEAM 0x4245414dU
#define CODE_BMHD 0x424d4844U
#define CODE_BODY 0x424f4459U
#define CODE_CAMG 0x43414d47U
#define CODE_CCRT 0x43435254U
#define CODE_CLUT 0x434c5554U
#define CODE_CMAP 0x434d4150U
#define CODE_CRNG 0x43524e47U
#define CODE_CTBL 0x4354424cU
#define CODE_DLTA 0x444c5441U
#define CODE_DPAN 0x4450414eU
#define CODE_DPI  0x44504920U
#define CODE_DRNG 0x44524e47U
#define CODE_FORM 0x464f524dU
#define CODE_GRAB 0x47524142U
#define CODE_ILBM 0x494c424dU
#define CODE_PBM  0x50424d20U
#define CODE_PCHG 0x50434847U
#define CODE_RGB8 0x52474238U
#define CODE_RGBN 0x5247424eU
#define CODE_SBDY 0x53424459U
#define CODE_SHAM 0x5348414dU
#define CODE_TINY 0x54494e59U
#define CODE_VDAT 0x56444154U
#define CODE_XS24 0x58533234U

#define ANIM_OP_XOR 1

#define MASKINGTYPE_NONE      0
#define MASKINGTYPE_1BITMASK  1
#define MASKINGTYPE_COLORKEY  2
#define MASKINGTYPE_LASSO     3

enum colortype_enum {
	COLORTYPE_DEFAULT = 0,
	COLORTYPE_RGB24
};

// Parameters for a single image, derived from a combination of the global
// state and the image context.
struct imgbody_info {
	i64 width, height;
	i64 planes_fg;
	i64 planes_total; // Different from planes_fg if MASKINGTYPE_1BITMASK.
	u8 compression;
	u8 masking_code;
	u8 use_colorkey_transparency;
	UI transparent_color;
	i64 x_aspect, y_aspect;
	i64 bits_per_row_per_plane;
	i64 bytes_per_row_per_plane;
	i64 frame_buffer_rowspan;
	i64 frame_buffer_size;
	enum colortype_enum colortype;
	int is_thumb;
	u8 is_pbm; // frame buffer is PBM pixel format
	u8 is_rgb24; // frame buffer is RGB24 pixel format
};

struct frame_ctx {
	u32 formtype;
	int frame_idx;
	int done_flag; // Have we processed the image (BODY/DLTA/etc. chunk)?
	int change_flag; // Is this frame different from the previous one?
	u8 op;
	UI interleave;
	UI bits;
	dbuf *frame_buffer;
};

typedef struct localctx_ilbm {
	int is_anim;
	u32 formtype;
	char formtype_sanitized_sz[8];
	i64 main_chunk_endpos;
	int FORM_level; // nesting level of the frames' FORM chunks
	int errflag;
	int num_frames_started;
	int num_frames_finished;
	int debug_frame_buffer;
#define TRANS_REMOVE   0
#define TRANS_RESPECT  1
#define TRANS_AUTO     2
	u8 trans_setting;
	u8 fixpal_setting;
	u8 opt_allowsham;
	u8 opt_allowdctv;
	u8 opt_allowhame;
	u8 opt_anim_includedups;
	u8 found_bmhd;
	u8 found_cmap;
	u8 cmap_changed_flag;
	u8 bmhd_changed_flag;
	u8 camg_changed_flag;
	u8 has_camg;
	u8 ham_flag; // "hold and modify"
	u8 is_ham6;
	u8 is_ham8;
	u8 ehb_flag; // "extra halfbrite"
	u8 uses_color_cycling;
	u8 color_cycling_warned;
	u8 is_sham;
	u8 is_ctbl;
	u8 is_pchg;
	u8 is_beam;
	u8 found_clut;
	u8 found_rast;
	u8 found_audio;
	u8 uses_anim4_5_xor_mode;
	u8 uses_anim_long_data;
	u8 multipalette_warned;
	u8 extra_content_warned;
	u8 is_hame;
	u8 is_dctv;
	UI camg_mode;

	i64 width, height;
	i64 planes_raw;
	u8 compression;
	u8 masking_code;
	UI transparent_color;
	i64 x_aspect, y_aspect;
	i64 x_dpi, y_dpi;
	i64 thumb_width, thumb_height;
	u8 has_hotspot;
	int hotspot_x, hotspot_y;

	struct frame_ctx *frctx; // Non-NULL means we're inside a frame
	struct frame_ctx *oldfrctx[2];
	i64 pal_ncolors; // Number of colors we read from the file
	int pal_is_grayscale;
	u32 pal_raw[256]; // Palette as read from the file
	u32 pal[256]; // Palette that we will use
	u8 delta_ops_used[256];
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
	case 7: name="short/long vert. delta, separated"; break;
	case 8: name="short/long vert. delta, contiguous"; break;
	case 74: name="ANIM-J (Eric Graham)"; break;
	case 100: name="ANIM32"; break;
	case 101: name="ANIM16"; break;
	case 108: name="ANIM-l (Eric Graham)"; break;
	}
	return name?name:"?";
}

static const char *get_maskingtype_name(u8 n)
{
	const char *name = NULL;

	switch(n) {
	case MASKINGTYPE_NONE: name = "no transparency"; break;
	case MASKINGTYPE_1BITMASK: name = "1-bit transparency mask"; break;
	case MASKINGTYPE_COLORKEY: name = "color-key transparency"; break;
	case MASKINGTYPE_LASSO: name = "lasso"; break;
	}
	return name?name:"?";
}

static const char *get_cmprtype_name(lctx *d, u8 n)
{
	const char *name = NULL;

	if(d->formtype==CODE_ACBM) return "n/a";

	switch(n) {
	case 0: name = "uncompressed"; break;
	case 1: name = "PackBits"; break;
	case 2: name = "VDAT"; break;
	case 3: case 4:
		if(d->formtype==CODE_RGBN || d->formtype==CODE_RGB8) {
			name = "RGBN/RGB8";
		}
		break;
	}
	return name?name:"?";
}

static void on_color_cycling_enabled(deark *c, lctx *d)
{
	d->uses_color_cycling = 1;
	if(d->color_cycling_warned) return;
	de_warn(c, "This image uses color cycling animation, which is not supported.");
	d->color_cycling_warned = 1;
}

static void on_multipalette_enabled(deark *c, lctx *d)
{
	if(!d->opt_allowsham) {
		d->errflag = 1;
	}
	if(d->multipalette_warned) return;
	if(d->opt_allowsham) {
		de_warn(c, "This is a multi-palette image, which is not correctly supported.");
	}
	else {
		de_err(c, "Multi-palette ILBM images are not supported. "
			"(\"-opt ilbm:allowspecial\" to decode anyway)");
	}
}

static struct frame_ctx *create_frame(deark *c, lctx *d)
{
	struct frame_ctx *frctx;
	frctx = de_malloc(c, sizeof(struct frame_ctx));
	return frctx;
}

static void destroy_frame(deark *c, lctx *d, struct frame_ctx *frctx)
{
	if(!frctx) return;
	dbuf_close(frctx->frame_buffer);
	de_free(c, frctx);
}

static void do_cmap(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 ncolors;

	d->found_cmap = 1;
	d->cmap_changed_flag = 1;
	ncolors = len/3;
	de_dbg(c, "number of palette colors: %d", (int)ncolors);
	if(ncolors>256) ncolors=256;

	de_read_palette_rgb(c->infile, pos, ncolors, 3, d->pal_raw, 256, 0);
	if(ncolors > d->pal_ncolors) {
		d->pal_ncolors = ncolors;
	}
}

static int do_bmhd(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	int retval = 0;
	const char *masking_name;

	d->bmhd_changed_flag = 1;
	if(len<20) {
		de_err(c, "Bad BMHD chunk");
		goto done;
	}

	d->found_bmhd = 1;
	d->width = de_getu16be_p(&pos);
	d->height = de_getu16be_p(&pos);
	de_dbg_dimensions(c, d->width, d->height);
	pos += 4;

	d->planes_raw = (i64)de_getbyte_p(&pos);
	de_dbg(c, "planes: %d", (int)d->planes_raw);
	d->masking_code = de_getbyte_p(&pos);
	masking_name = get_maskingtype_name(d->masking_code);

	d->compression = de_getbyte_p(&pos);
	de_dbg(c, "compression: %d (%s)", (int)d->compression, get_cmprtype_name(d, d->compression));

	pos++;
	d->transparent_color = (UI)de_getu16be_p(&pos);
	de_dbg(c, "masking: %d (%s)", (int)d->masking_code, masking_name);
	if(d->masking_code==MASKINGTYPE_COLORKEY || d->masking_code==MASKINGTYPE_LASSO) {
		de_dbg_indent(c, 1);
		de_dbg(c, "color key: %u", d->transparent_color);
		de_dbg_indent(c, -1);
	}

	d->x_aspect = (i64)de_getbyte_p(&pos);
	d->y_aspect = (i64)de_getbyte_p(&pos);
	de_dbg(c, "aspect ratio: %d, %d", (int)d->x_aspect, (int)d->y_aspect);

	retval = 1;
done:
	return retval;
}

static i64 delta3_calc_elem_pos(i64 elemnum, i64 elemsize, i64 elems_per_row, i64 plane_offset,
	i64 frame_buffer_rowspan)
{
	i64 row, col;

	row = elemnum / elems_per_row;
	col = elemnum % elems_per_row;
	return row * frame_buffer_rowspan + plane_offset + elemsize * col;
}

// Note - It should be easy to modify this to work for DLTA#2 compression as well
// (need a sample file).
static void decompress_plane_delta_op3(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 plane, i64 pos1, i64 maxlen)
{
	i64 endpos = pos1+maxlen;
	i64 pos = pos1;
	i64 elemnum = 0;
	i64 elemsize = 2;
	i64 elems_per_row;
	i64 elems_total;
	i64 plane_offset;
	i64 dstpos;
	u8 elembuf[2];

	de_dbg2(c, "delta3 plane at %"I64_FMT", maxlen=%"I64_FMT, pos1, maxlen);

	elems_per_row = (ibi->bytes_per_row_per_plane + (elemsize-1) ) / elemsize;
	if(elems_per_row<1) goto done;
	elems_total = elems_per_row * ibi->height;
	plane_offset = plane * ibi->bytes_per_row_per_plane;

	while(1) {
		i64 code;
		i64 offset;

		if(elemnum >= elems_total) break;
		if(pos+2 >= endpos) goto done;
		code = de_geti16be_p(&pos);

		if(code == -1) { // Stop.
			break;
		}
		else if(code >= 0) { // Skip some number of elements, then write one element.
			frctx->change_flag = 1;
			offset = code;
			elemnum += offset;
			de_read(elembuf, pos, elemsize);
			pos += elemsize;
			dstpos = delta3_calc_elem_pos(elemnum, elemsize, elems_per_row, plane_offset,
				ibi->frame_buffer_rowspan);
			dbuf_write_at(frctx->frame_buffer, dstpos, elembuf, elemsize);
		}
		else { // Skip some number of elements, then write multiple elements.
			i64 count;
			i64 k;

			offset = -(code+2);
			elemnum += offset;
			count = de_getu16be_p(&pos);
			if(count>0) {
				frctx->change_flag = 1;
			}
			for(k=0; k<count; k++) {
				de_read(elembuf, pos, elemsize);
				pos += elemsize;
				elemnum++;
				dstpos = delta3_calc_elem_pos(elemnum, elemsize, elems_per_row, plane_offset,
					ibi->frame_buffer_rowspan);
				dbuf_write_at(frctx->frame_buffer, dstpos, elembuf, elemsize);
			}
		}
	}

done:
	;
}

// "Short Delta" mode
// Decompress into frctx->frame_buffer
static void decompress_delta_op3(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 i;
	i64 pos = pos1;
	i64 planedata_offs[8];

	de_dbg(c, "[delta3 data]");

	for(i=0; i<8; i++) {
		planedata_offs[i] = de_getu32be_p(&pos);
		if(i<ibi->planes_total) {
			de_dbg2(c, "plane[%d] offs: %"I64_FMT, (int)i, planedata_offs[i]);
			if(planedata_offs[i]>0) {
				decompress_plane_delta_op3(c, d, ibi, frctx, i,
					pos1+planedata_offs[i], len-planedata_offs[i]);
			}
		}
	}
}

static i64 get_elem_as_int_p(dbuf *f, i64 *ppos, i64 elem_size)
{
	if(elem_size==1) {
		return (i64)dbuf_getbyte_p(f, ppos);
	}
	if(elem_size==2) {
		return dbuf_getu16be_p(f, ppos);
	}
	return dbuf_getu32be_p(f, ppos);
}

// This routine decompresses most frame types used in DLTA#5, #7, and #8.
// For #7, the codestream and datastream are stored separately, and have different
// element sizes.
// For #5 and #8, datapos1 is not used.
static void decompress_plane_vdelta(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 plane_idx,
	dbuf *inf, i64 codepos1, i64 datapos1, i64 endpos,
	i64 code_size, i64 dataelem_size, int separate_data_stream, u8 xor_mode)
{
	i64 pos = codepos1; // If !separate_data_stream, this is for code and data
	i64 datapos = datapos1;
	i64 num_columns;
	i64 col;
	i64 dststride = ibi->frame_buffer_rowspan;
	UI unc_threshold;
	u8 last_col_quirk = 0;
	int baddata_flag = 0;

	if(separate_data_stream) {
		de_dbg2(c, "vdelta(%d,%d) plane %d at (%"I64_FMT",%"I64_FMT")", (int)code_size,
			(int)dataelem_size, (int)plane_idx, codepos1, datapos1);
	}
	else {
		de_dbg2(c, "vdelta(%d) plane at (%"I64_FMT")", (int)code_size, codepos1);
	}
	if(code_size!=1 && code_size!=2 && code_size!=4) goto done;
	if(dataelem_size!=1 && dataelem_size!=2 && dataelem_size!=4) goto done;
	if(xor_mode && dataelem_size!=1) goto done;

	if(code_size==1) {
		unc_threshold = 0x80;
	}
	else if(code_size==2) {
		unc_threshold = 0x8000;
	}
	else {
		unc_threshold = 0x80000000U;
	}

	if(dataelem_size==1) {
		num_columns = (ibi->width+7)/8;
	}
	else if(dataelem_size==2) {
		num_columns = (ibi->width+15)/16;
	}
	else {
		num_columns = (ibi->width+31)/32;
	}

	if(frctx->op==8 && dataelem_size==4) {
		i64 num_columns_if_size2;

		num_columns_if_size2 = (ibi->width+15)/16;
		if(num_columns*2 != num_columns_if_size2) {
			// A dumb quirk of ANIM-8: The last column may use "word" mode,
			// even when when all other columns use "long" mode.
			last_col_quirk = 1;
		}
	}

	for(col=0; col<num_columns; col++) {
		i64 opcount;
		i64 opidx;
		i64 elem_bytes_to_write;
		i64 ypos = 0;
		i64 col_start_dstpos;
		i64 dataelem_size_thiscol;
		i64 code_size_thiscol;
		UI unc_threshold_thiscol;
		u8 is_last_col;

		if(c->debug_level>=3) {
			de_dbg3(c, "col %u at %"I64_FMT, (UI)col, pos);
		}

		is_last_col = (col+1 == num_columns);
		code_size_thiscol = code_size;
		dataelem_size_thiscol = dataelem_size;
		unc_threshold_thiscol = unc_threshold;
		if(is_last_col && last_col_quirk) {
			code_size_thiscol = 2;
			dataelem_size_thiscol = 2;
			unc_threshold_thiscol = 0x8000;
		}

		if(pos>=endpos) {
			baddata_flag = 1;
			goto done;
		}

		// Defend against writing beyond the right edge of this plane
		if(is_last_col && (dataelem_size_thiscol==4) && (ibi->bytes_per_row_per_plane%4)) {
			elem_bytes_to_write = 2;
		}
		else {
			elem_bytes_to_write = dataelem_size_thiscol;
		}

		col_start_dstpos = plane_idx * ibi->bytes_per_row_per_plane + dataelem_size*col;

		opcount = get_elem_as_int_p(inf, &pos, code_size_thiscol);
		if(c->debug_level>=3) {
			de_dbg3(c, "col %d op count: %"I64_FMT, (int)col, opcount);
		}

		for(opidx=0; opidx<opcount; opidx++) {
			i64 dstpos;
			i64 count;
			i64 k;
			UI op;
			u8 valbuf[4];

			if(pos>=endpos) {
				baddata_flag = 1;
				goto done;
			}
			op = (UI)get_elem_as_int_p(inf, &pos, code_size_thiscol);

			if(op==0) { // RLE
				count = get_elem_as_int_p(inf, &pos, code_size_thiscol);
				if(ypos+count > ibi->height) {
					// TODO: Should we tolerate this, and set count = 0?
					baddata_flag = 1;
					goto done;
				}

				if(count>0) {
					frctx->change_flag = 1;
				}

				if(separate_data_stream) {
					if(datapos>=endpos) {
						baddata_flag = 1;
						goto done;
					}
					dbuf_read(inf, valbuf, datapos, dataelem_size_thiscol);
					datapos += dataelem_size_thiscol;
				}
				else {
					dbuf_read(inf, valbuf, pos, dataelem_size_thiscol);
					pos += dataelem_size_thiscol;
				}

				for(k=0; k<count; k++) {
					dstpos = col_start_dstpos + ypos*dststride;
					if(xor_mode) {
						u8 val;

						val = valbuf[0] ^ dbuf_getbyte(frctx->frame_buffer, dstpos);
						dbuf_writebyte_at(frctx->frame_buffer, dstpos, val);
					}
					else {
						dbuf_write_at(frctx->frame_buffer, dstpos, valbuf, elem_bytes_to_write);
					}
					ypos++;
				}
			}
			else if(op < unc_threshold_thiscol) { // skip
				ypos += (i64)op;
			}
			else { // uncompressed run
				count = (i64)(op - unc_threshold_thiscol);
				if(ypos+count > ibi->height) {
					baddata_flag = 1;
					goto done;
				}

				if(count>0) {
					frctx->change_flag = 1;
				}

				for(k=0; k<count; k++) {
					if(separate_data_stream) {
						if(datapos>=endpos) {
							baddata_flag = 1;
							goto done;
						}
						dbuf_read(inf, valbuf, datapos, dataelem_size_thiscol);
						datapos += dataelem_size_thiscol;
					}
					else {
						dbuf_read(inf, valbuf, pos, dataelem_size_thiscol);
						pos += dataelem_size_thiscol;
					}

					dstpos = col_start_dstpos + ypos*dststride;
					if(xor_mode) {
						valbuf[0] ^= dbuf_getbyte(frctx->frame_buffer, dstpos);
					}
					dbuf_write_at(frctx->frame_buffer, dstpos, valbuf, elem_bytes_to_write);
					ypos++;
				}
			}
		}
	}

done:
	if(baddata_flag && !d->errflag) {
		de_err(c, "Delta decompression failed");
		d->errflag = 1;
	}
}

// Decompress into frctx->frame_buffer
static void decompress_delta_op5(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 planedata_offs[16];
	i64 pos = pos1;
	int i;
	int saved_indent_level;
	u8 delta4_5_xor_mode = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frctx->frame_buffer) goto done;

	de_dbg(c, "[delta5 data]");

	// Note that we ignore the 0x8 bit ("RLC - run length coded").
	// I don't know what this option is for. *All* ANIM4/5 frames use run length
	// coding, but they almost never have have this bit set.
	// The rare files that do set this bit don't seem to be any different from
	// those that don't.
	if((frctx->bits & 0xfffffff5U) != 0) {
		de_err(c, "Unsupported ANHD options");
		d->errflag = 1;
		goto done;
	}

	if(frctx->bits & 0x2) {
		delta4_5_xor_mode = 1;
	}

	for(i=0; i<16; i++) {
		if(d->errflag) goto done;
		planedata_offs[i] = de_getu32be_p(&pos);
		if(i<ibi->planes_total) {
			de_dbg2(c, "plane[%d] offs: %"I64_FMT, i, planedata_offs[i]);
			if(planedata_offs[i]>0) {
				decompress_plane_vdelta(c, d, ibi, frctx, i, c->infile,
					pos1+planedata_offs[i], 0, pos1+len, 1, 1,
					0, delta4_5_xor_mode);
			}
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// Decompress into frctx->frame_buffer
static void decompress_delta_op7(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 opcodelist_offs[8];
	i64 datalist_offs[8];
	i64 infpos;
	int i;
	int saved_indent_level;
	i64 dataelem_size;
	dbuf *inf = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frctx->frame_buffer) goto done;

	de_dbg(c, "[delta7 data]");

	if(frctx->bits & 0xfffffffeU) {
		de_err(c, "Unsupported ANHD options");
		d->errflag = 1;
		goto done;
	}
	if(frctx->bits & 0x00000001) {
		dataelem_size = 4;
	}
	else {
		dataelem_size = 2;
	}

	// We'll have to interleave lots of short reads between two different segments of
	// the file, with no way to know how big either segment is.
	// I see no good way to process this DLTA#7 format, except by first reading the
	// entire chunk into memory.
	if(len > DE_MAX_SANE_OBJECT_SIZE) {
		d->errflag = 1;
		goto done;
	}
	inf = dbuf_create_membuf(c, len, 0);
	dbuf_copy(c->infile, pos1, len, inf);
	infpos = 0;

	for(i=0; i<8; i++) {
		opcodelist_offs[i] = dbuf_getu32be_p(inf, &infpos);
	}

	for(i=0; i<8; i++) {
		datalist_offs[i] = dbuf_getu32be_p(inf, &infpos);
	}

	for(i=0; i<8; i++) {
		if(d->errflag) goto done;
		if(i<ibi->planes_total) {
			de_dbg2(c, "opcode_list[%d] offs: %"I64_FMT, i, opcodelist_offs[i]);
			de_dbg2(c, "data_list[%d] offs: %"I64_FMT, i, datalist_offs[i]);
			if(opcodelist_offs[i]>0) {
				decompress_plane_vdelta(c, d, ibi, frctx, i, inf,
					opcodelist_offs[i], datalist_offs[i], len,
					1, dataelem_size, 1, 0);
			}
		}
	}

done:
	dbuf_close(inf);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void decompress_delta_op8(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 planedata_offs[16];
	i64 pos = pos1;
	i64 elem_size;
	int i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frctx->frame_buffer) goto done;

	de_dbg(c, "[delta8 data]");

	if(frctx->bits & 0xfffffffeU) {
		de_err(c, "Unsupported ANHD options");
		d->errflag = 1;
		goto done;
	}
	if(frctx->bits & 0x00000001) {
		elem_size = 4;
	}
	else {
		elem_size = 2;
	}

	for(i=0; i<16; i++) {
		if(d->errflag) goto done;
		planedata_offs[i] = de_getu32be_p(&pos);
		if(i<ibi->planes_total) {
			de_dbg2(c, "plane[%d] offs: %"I64_FMT, i, planedata_offs[i]);
			if(planedata_offs[i]>0) {
				decompress_plane_vdelta(c, d, ibi, frctx, i, c->infile,
					pos1+planedata_offs[i], 0, pos1+len, elem_size, elem_size, 0, 0);
			}
		}
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

struct d74state {
	struct imgbody_info *ibi;
	struct frame_ctx *frctx;
	i64 pos;
	i64 endpos;

	// Temporary use:
	UI op;
	i64 nblocks;
	i64 nrows; // block height in rows
	i64 nbytes; // block width in bytes per plane
};

static void do_delta74_blocks(deark *c, struct d74state *d74s)
{
	i64 blkidx, rowidx, planeidx, byteidx;
	i64 d74_bytes_per_row_per_plane;

	// Reportedly, the 'offset' field assumes a potentially-different measuring
	// system than one would expect.
	d74_bytes_per_row_per_plane = (d74s->ibi->width + 7)/8;

	for(blkidx=0; blkidx<d74s->nblocks; blkidx++) {
		i64 offset;
		i64 block_srcpos = d74s->pos;
		i64 block_dstpos;

		if(d74s->pos+2 >= d74s->endpos) goto done;
		offset = de_getu16be_p(&d74s->pos);

		block_dstpos = (offset / d74_bytes_per_row_per_plane) * d74s->ibi->frame_buffer_rowspan +
			(offset % d74_bytes_per_row_per_plane);

		for(rowidx=0; rowidx<d74s->nrows; rowidx++) {
			for(planeidx=0; planeidx<d74s->ibi->planes_total; planeidx++) {
				i64 dstpos;

				// Calculate the offset in our frame buffer.
				dstpos = block_dstpos + (rowidx * d74s->ibi->frame_buffer_rowspan) +
					planeidx * d74s->ibi->bytes_per_row_per_plane;

				for(byteidx=0; byteidx<d74s->nbytes; byteidx++) {
					u8 val;

					val = de_getbyte_p(&d74s->pos);
					if(d74s->op) val ^= dbuf_getbyte(d74s->frctx->frame_buffer, dstpos);
					dbuf_writebyte_at(d74s->frctx->frame_buffer, dstpos, val);
					dstpos++;
				}
			}
		}

		if((d74s->pos - block_srcpos) & 0x1) {
			d74s->pos++; // padding byte
		}
	}

done:
	;
}

static void decompress_delta_op74(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	struct d74state d74s;

	de_zeromem(&d74s, sizeof(struct d74state));
	d74s.ibi = ibi;
	d74s.frctx = frctx;
	d74s.pos = pos1;
	d74s.endpos = pos1+len;

	if(!d->delta_ops_used[74]) { // If this is the first DLTA#7 chunk...
		if(ibi->width < 320) {
			// The XAnim code says this is a special case, but I haven't found any
			// sample files. (TODO)
			de_warn(c, "ANIM-J with width < 320 might not be supported correctly");
		}
	}

	while(1) {
		UI code;

		if(d74s.pos+2 >= d74s.endpos) goto done;
		code = (UI)de_getu16be_p(&d74s.pos);
		if(code==1) {
			frctx->change_flag = 1;
			d74s.op = (UI)de_getu16be_p(&d74s.pos);
			d74s.nrows = de_getu16be_p(&d74s.pos);
			d74s.nbytes = 1;
			d74s.nblocks = de_getu16be_p(&d74s.pos);
			do_delta74_blocks(c, &d74s);
		}
		else if(code==2) {
			frctx->change_flag = 1;
			d74s.op = (UI)de_getu16be_p(&d74s.pos);
			d74s.nrows = de_getu16be_p(&d74s.pos);
			d74s.nbytes = de_getu16be_p(&d74s.pos);
			d74s.nblocks = de_getu16be_p(&d74s.pos);
			do_delta74_blocks(c, &d74s);
		}
		else if(code==0) {
			break;
		}
		else {
			de_warn(c, "Bad or unsupported ANIM-J compression code: %u", code);
			goto done;
		}
	}

done:
	;
}

// ANIM-l
// Similar to op3, but different in enough ways that it probably isn't worth
// combining into one function.
static void decompress_plane_delta_op108(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 plane_idx, dbuf *inf, i64 codepos1, i64 datapos1,
	i64 endpos)
{
	i64 codepos = codepos1;
	i64 datapos = datapos1;
	const i64 code_size = 2;
	const i64 dataelem_size = 2;
	i64 elems_per_row;
	i64 plane_offset;
	u8 elembuf[2];
	int baddata_flag = 0;

	de_dbg2(c, "delta108 plane %d at (%"I64_FMT",%"I64_FMT")", (int)plane_idx,
		codepos1, datapos1);

	elems_per_row = (ibi->bytes_per_row_per_plane + (dataelem_size-1) ) / dataelem_size;
	if(elems_per_row<1) goto done;
	plane_offset = plane_idx * ibi->bytes_per_row_per_plane;

	while(1) {
		i64 elemnum;
		i64 count_code;
		i64 xpos, ypos;
		i64 dstpos;

		if(codepos+code_size > endpos) goto done;
		elemnum = dbuf_getu16be_p(inf, &codepos);

		if(elemnum == 0xffff) { // Stop.
			goto done;
		}

		ypos = elemnum / elems_per_row;
		xpos = elemnum % elems_per_row;
		dstpos = plane_offset + ypos * ibi->frame_buffer_rowspan + dataelem_size*xpos;

		if(codepos+code_size > endpos) goto done;
		count_code = dbuf_geti16be_p(inf, &codepos);

		if(count_code < 0) { // an uncompressed run
			i64 count = -count_code;
			i64 k;

			frctx->change_flag = 1;

			if(datapos + dataelem_size > endpos) {
				baddata_flag = 1;
				goto done;
			}
			dbuf_read(inf, elembuf, datapos, dataelem_size);
			datapos += dataelem_size;

			for(k=0; k<count; k++) {
				if(ypos >= ibi->height) {
					baddata_flag = 1;
					goto done;
				}

				dbuf_write_at(frctx->frame_buffer, dstpos, elembuf, dataelem_size);
				ypos++;
				dstpos += ibi->frame_buffer_rowspan;
			}
		}
		else { // an RLE run
			i64 count = count_code;
			i64 k;

			if(count > 0) frctx->change_flag = 1;

			for(k=0; k<count; k++) {
				if(ypos >= ibi->height) {
					baddata_flag = 1;
					goto done;
				}
				if(datapos + dataelem_size > endpos) {
					baddata_flag = 1;
					goto done;
				}
				dbuf_read(inf, elembuf, datapos, dataelem_size);
				datapos += dataelem_size;

				dbuf_write_at(frctx->frame_buffer, dstpos, elembuf, dataelem_size);
				ypos++;
				dstpos += ibi->frame_buffer_rowspan;
			}
		}
	}

done:
	if(baddata_flag && !d->errflag) {
		de_err(c, "Delta decompression failed");
		d->errflag = 1;
	}
}

static void decompress_delta_op108(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx, i64 pos1, i64 len)
{
	i64 opcodelist_offs[8];
	i64 datalist_offs[8];
	i64 infpos;
	int i;
	int saved_indent_level;
	dbuf *inf = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(!frctx->frame_buffer) goto done;

	de_dbg(c, "[delta108 data]");

	// Read the entire chunk into memory, so that the random-access reads will be
	// faster.
	if(len > DE_MAX_SANE_OBJECT_SIZE) {
		d->errflag = 1;
		goto done;
	}
	inf = dbuf_create_membuf(c, len, 0);
	dbuf_copy(c->infile, pos1, len, inf);
	infpos = 0;

	for(i=0; i<8; i++) {
		datalist_offs[i] = dbuf_getu32be_p(inf, &infpos);
	}

	for(i=0; i<8; i++) {
		opcodelist_offs[i] = dbuf_getu32be_p(inf, &infpos);
	}

	for(i=0; i<8; i++) {
		if(d->errflag) goto done;
		if(i<ibi->planes_total) {
			de_dbg2(c, "opcode_list[%d] offs: %"I64_FMT, i, opcodelist_offs[i]);
			de_dbg2(c, "data_list[%d] offs: %"I64_FMT, i, datalist_offs[i]);
			if(opcodelist_offs[i]>0) {
				decompress_plane_delta_op108(c, d, ibi, frctx, i, inf,
					2*opcodelist_offs[i], 2*datalist_offs[i], len);
			}
		}
	}

done:
	dbuf_close(inf);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void pal_fixup4(deark *c, lctx *d)
{
	i64 k;
	u8 cr, cg, cb;

	for(k=0; k<d->pal_ncolors; k++) {
		cr = DE_COLOR_R(d->pal[k]);
		cg = DE_COLOR_G(d->pal[k]);
		cb = DE_COLOR_B(d->pal[k]);
		cr = 17*(cr>>4);
		cg = 17*(cg>>4);
		cb = 17*(cb>>4);
		d->pal[k] = DE_MAKE_RGB(cr, cg, cb);
	}
}

static void pal_fixup6(deark *c, lctx *d)
{
	i64 k;
	u8 cr, cg, cb;

	for(k=0; k<d->pal_ncolors; k++) {
		cr = DE_COLOR_R(d->pal[k]);
		cg = DE_COLOR_G(d->pal[k]);
		cb = DE_COLOR_B(d->pal[k]);
		cr = (cr&0xfc)|(cr>>6);
		cg = (cg&0xfc)|(cg>>6);
		cb = (cb&0xfc)|(cb>>6);
		d->pal[k] = DE_MAKE_RGB(cr, cg, cb);
	}
}

// It's clear that some ILBM images have palette colors with only 4 bits of
// precision (the low bits often being set to 0), while others have 8, or
// something in between.
// What's not clear is how to tell them apart.
// We'll guess that
// * HAM6 images always have 4.
// * HAM8 images always have 6.
// * For anything else, assume 4 if the low 4 bits are all 0.
// * Otherwise, 8.
// TODO: It may be safe to assume that 8-plane images always have 8, but
// more research is needed.
static void fixup_palette(deark *c, lctx *d)
{
	i64 k;
	u8 cr, cg, cb;

	if(d->pal_ncolors<1) return;
	if(d->formtype==CODE_RGBN || d->formtype==CODE_RGB8) return;

	if(d->is_ham8) {
		pal_fixup6(c, d);
		return;
	}
	if(d->is_ham6) {
		pal_fixup4(c, d);
		return;
	}

	for(k=0; k<d->pal_ncolors; k++) {
		cr = DE_COLOR_R(d->pal[k]);
		cg = DE_COLOR_G(d->pal[k]);
		cb = DE_COLOR_B(d->pal[k]);
		if((cr&0x0f) != 0) return;
		if((cg&0x0f) != 0) return;
		if((cb&0x0f) != 0) return;
	}
	de_dbg(c, "Palette seems to have 4 bits of precision. Rescaling palette.");
	pal_fixup4(c, d);
}

// Called when we encounter a BODY or DLTA or TINY chunk
static void do_before_image_chunk(deark *c, lctx *d)
{
	if(d->bmhd_changed_flag || d->camg_changed_flag) {
		if(d->ham_flag) {
			if(d->planes_raw==6 || d->planes_raw==5) {
				d->is_ham6 = 1;
			}
			else if(d->planes_raw==8 || d->planes_raw==7) {
				d->is_ham8 = 1;
			}
			else {
				de_warn(c, "Invalid bit depth (%d) for HAM image.", (int)d->planes_raw);
			}
		}

		if(!d->found_cmap && d->planes_raw<=8) {
			de_make_grayscale_palette(d->pal, (i64)1<<(UI)d->planes_raw, 0);
		}

		if(d->planes_raw==6 && d->pal_ncolors==32 && !d->ehb_flag && !d->ham_flag) {
			de_warn(c, "Assuming this is an EHB image");
			d->ehb_flag = 1;
		}
	}

	if(d->cmap_changed_flag) {
		de_memcpy(d->pal, d->pal_raw, (size_t)d->pal_ncolors * sizeof(d->pal_raw[0]));
	}

	if(d->cmap_changed_flag && d->ehb_flag && d->planes_raw==6) {
		UI k;

		// TODO: Should we still do this if the palette already has 64 colors
		// (as it often does)?
		for(k=0; k<32; k++) {
			u8 cr, cg, cb;

			cr = DE_COLOR_R(d->pal[k]);
			cg = DE_COLOR_G(d->pal[k]);
			cb = DE_COLOR_B(d->pal[k]);
			d->pal[k+32] = DE_MAKE_RGB(cr/2, cg/2, cb/2);
		}
	}

	if(d->fixpal_setting && d->cmap_changed_flag) {
		fixup_palette(c, d);
	}

	if(d->cmap_changed_flag) {
		d->pal_is_grayscale = de_is_grayscale_palette(d->pal, 256);
	}

	d->cmap_changed_flag = 0;
	d->bmhd_changed_flag = 0;
	d->camg_changed_flag = 0;
}

static int init_imgbody_info(deark *c, lctx *d, struct imgbody_info *ibi, int is_thumb)
{
	int retval = 0;

	ibi->is_thumb = is_thumb;

	// Unlike ACBM, it would be messy and slow to convert PBM to the standard ILBM
	// frame buffer format (and back). So we support a special frame buffer format
	// just for PBM.
	ibi->is_pbm = (d->formtype==CODE_PBM);
	// We also have a special nonplanar RGB24 format (is_rgb24).

	if(d->formtype==CODE_RGBN || d->formtype==CODE_RGB8) {
		ibi->is_rgb24 = 1;
		if(((d->formtype==CODE_RGBN && d->planes_raw==13) ||
			(d->formtype==CODE_RGB8 && d->planes_raw==25)) &&
			(d->compression==3 || d->compression==4) &&
			d->masking_code==MASKINGTYPE_NONE)
		{
			;
		}
		else {
			de_err(c, "Unsupported RGBN/RGB8 format");
			goto done;
		}
	}

	if(is_thumb) {
		ibi->width = d->thumb_width;
		ibi->height = d->thumb_height;
	}
	else {
		ibi->width = d->width;
		ibi->height = d->height;
	}

	// Quick & dirty support for -padpix.
	// TODO: Some of these conditions could be removed, with care.
	if(c->padpix && (d->width%16) && !is_thumb && !d->is_anim && d->formtype==CODE_ILBM &&
		!d->ham_flag)
	{
		ibi->width = de_pad_to_n(ibi->width, 16);
	}

	ibi->compression = d->compression;

	ibi->masking_code = d->masking_code;
	// Based on what little data I have, it seems that TINY images do not have
	// a transparency mask, even if the main image does.
	if(is_thumb && ibi->masking_code==MASKINGTYPE_1BITMASK) {
		ibi->masking_code = MASKINGTYPE_NONE;
	}

	if(d->planes_raw==24) {
		ibi->colortype = COLORTYPE_RGB24;
	}
	else {
		ibi->colortype = COLORTYPE_DEFAULT;
	}

	if(ibi->is_pbm || ibi->is_rgb24) {
		ibi->planes_fg = 1;
		ibi->planes_total = 1;
	}
	else {
		ibi->planes_fg = d->planes_raw;
		ibi->planes_total = d->planes_raw;
		if(ibi->masking_code==MASKINGTYPE_1BITMASK) {
			ibi->planes_total++;
		}
	}
	ibi->transparent_color = d->transparent_color;
	ibi->x_aspect = d->x_aspect;
	ibi->y_aspect = d->y_aspect;

	if(ibi->is_pbm) {
		if(d->planes_raw!=8 || d->masking_code==MASKINGTYPE_1BITMASK) {
			de_err(c, "Not a supported PBM format");
			goto done;
		}
	}

	if(ibi->is_pbm) {
		ibi->bytes_per_row_per_plane = ibi->width;
		if(ibi->bytes_per_row_per_plane%2) {
			ibi->bytes_per_row_per_plane++;
		}
		ibi->bits_per_row_per_plane = ibi->bytes_per_row_per_plane * 8;
		// Note: The PBM row size might be adjusted later, after decompression.
	}
	else if(ibi->is_rgb24) {
		ibi->bytes_per_row_per_plane = ibi->width*3;
		ibi->bits_per_row_per_plane = ibi->bytes_per_row_per_plane * 8;
	}
	else {
		ibi->bits_per_row_per_plane = de_pad_to_n(ibi->width, 16);
		ibi->bytes_per_row_per_plane = ibi->bits_per_row_per_plane/8;
	}
	ibi->frame_buffer_rowspan = ibi->bytes_per_row_per_plane * ibi->planes_total;
	ibi->frame_buffer_size = ibi->frame_buffer_rowspan * ibi->height;

	if(ibi->masking_code==MASKINGTYPE_NONE) {
		;
	}
	else if(ibi->masking_code==MASKINGTYPE_COLORKEY) {
		if(ibi->planes_fg<=8 && !d->ham_flag) {
			ibi->use_colorkey_transparency = 1;
		}
	}
	else if(ibi->masking_code==MASKINGTYPE_1BITMASK) {
		;
	}
	else {
		de_warn(c, "This type of transparency is not supported");
	}

	if(ibi->use_colorkey_transparency && ibi->transparent_color<=255) {
		d->pal[ibi->transparent_color] = DE_SET_ALPHA(d->pal[ibi->transparent_color], 0);
	}

	if(ibi->colortype==COLORTYPE_RGB24) {
		;
	}
	else if(ibi->planes_fg<1 || ibi->planes_fg>8) {
		de_err(c, "Bad or unsupported number of planes: %d", (int)ibi->planes_fg);
		goto done;
	}
	retval = 1;

done:
	return retval;
}

static void write_frame(deark *c, lctx *d, struct imgbody_info *ibi, struct frame_ctx *frctx);

static void do_dlta(deark *c, lctx *d, i64 pos1, i64 len)
{
	struct frame_ctx *frctx = d->frctx;
	struct frame_ctx *reference_frctx = NULL;
	struct imgbody_info *ibi = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(d->errflag) goto done;
	if(!d->found_bmhd) goto done;
	if(!frctx) goto done;
	if(frctx->done_flag) goto done;
	frctx->done_flag = 1;

	// TODO: Should the imgbody_info be saved somewhere, or recalculated for every frame?
	ibi = de_malloc(c, sizeof(struct imgbody_info));

	do_before_image_chunk(c, d);

	if(!init_imgbody_info(c, d, ibi, 0)) {
		d->errflag = 1;
		goto done;
	}

	// Find the reference frame (if it exists).
	// It is the highest numbered oldfrctx[] item whose index is at most
	// frctx->interleave-1, and which is non-NULL.
	if(frctx->interleave>=2) {
		reference_frctx = d->oldfrctx[1];
		if(!reference_frctx) {
			reference_frctx = d->oldfrctx[0];
		}
	}
	else {
		reference_frctx = d->oldfrctx[0];
	}

	// Allocate buffer for this frame
	if(!frctx->frame_buffer) {
		frctx->frame_buffer = dbuf_create_membuf(c, ibi->frame_buffer_size, 0x1);
	}

	// Start by copying the reference frame to this frame. The decompress function
	// will then modify this frame.
	if(reference_frctx && reference_frctx->frame_buffer) {
		dbuf_copy(reference_frctx->frame_buffer, 0, reference_frctx->frame_buffer->len,
			frctx->frame_buffer);
	}

	switch(frctx->op) {
	case 3:
		decompress_delta_op3(c, d, ibi, frctx, pos1, len);
		break;
	case 5:
		decompress_delta_op5(c, d, ibi, frctx, pos1, len);
		break;
	case 7:
		decompress_delta_op7(c, d, ibi, frctx, pos1, len);
		break;
	case 8:
		decompress_delta_op8(c, d, ibi, frctx, pos1, len);
		break;
	case 74:
		decompress_delta_op74(c, d, ibi, frctx, pos1, len);
		break;
	case 108:
		decompress_delta_op108(c, d, ibi, frctx, pos1, len);
		break;
	default:
		de_err(c, "Unsupported DLTA operation: %d", (int)frctx->op);
		d->errflag = 1;
	}
	if(d->errflag) goto done;

	if(frctx->change_flag || d->opt_anim_includedups) {
		write_frame(c, d, ibi, frctx);
	}
	else {
		de_dbg(c, "[suppressing duplicate frame]");
	}

done:
	// For the summary line, and so we can know when encountering an op for the
	// first time.
	if(frctx) {
		d->delta_ops_used[(size_t)frctx->op] = 1;
	}

	de_free(c, ibi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static int decompress_method0(deark *c, lctx *d, i64 pos, i64 len, dbuf *unc_pixels,
	i64 expected_len)
{
	i64 amt_to_copy;

	amt_to_copy = de_min_int(len, expected_len);
	dbuf_copy(c->infile, pos, amt_to_copy, unc_pixels);
	return 1;
}

static int decompress_rgbn8(deark *c, lctx *d, struct imgbody_info *ibi,
	i64 pos1, i64 len, dbuf *unc_pixels)
{
	int retval = 0;
	i64 pos = pos1;
	i64 endpos = pos1+len;
	i64 npixels = 0;
	i64 npixels_expected;
	u8 is_rgb8 = (d->formtype==CODE_RGB8);

	npixels_expected = ibi->width * ibi->height;

	while(1) {
		i64 i;
		u32 n;
		i64 count;
		u8 cbuf[3];

		if(npixels >= npixels_expected) {
			retval = 1;
			goto done;
		}
		if(pos >= endpos) {
			goto done;
		}


		if(is_rgb8) {
			n = (u32)de_getu32be_p(&pos);
			cbuf[0] = (u8)(n>>24);
			cbuf[1] = (u8)((n&0x00ff0000U)>>16);
			cbuf[2] = (u8)((n&0x0000ff00U)>>8);
			// TODO?: There's also a "genlock" bit that's sort of a transparency mask.
			count = (i64)(n & 0x7f);
		}
		else {
			n = (u32)de_getu16be_p(&pos);
			cbuf[0] = (u8)(n>>12);
			cbuf[1] = (u8)((n&0x0f00)>>8);
			cbuf[2] = (u8)((n&0x00f0)>>4);
			for(i=0; i<3; i++) {
				cbuf[i] *= 17;
			}
			count = (i64)(n & 0x07);
		}

		if(count==0) {
			u8 c2raw;

			c2raw = de_getbyte_p(&pos);
			if(c2raw!=0) {
				count = (i64)c2raw;
			}
			else {
				count = de_getu16be_p(&pos);
			}
		}

		for(i=0; i<count; i++) {
			dbuf_write(unc_pixels, cbuf, 3);
		}
		npixels += count;
	}

done:
	if(!retval) {
		de_err(c, "RGBN/RGB8 decompression failed");
	}
	return retval;
}

static int decompress_ilbm_packbits(deark *c, dbuf *inf, i64 pos, i64 len,
	dbuf *unc_pixels, i64 expected_len, UI nbytes_per_unit)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_packbits_params pbparams;

	de_zeromem(&pbparams, sizeof(struct de_packbits_params));
	pbparams.nbytes_per_unit = nbytes_per_unit;
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = inf;
	dcmpri.pos = pos;
	dcmpri.len = len;
	dcmpro.f = unc_pixels;
	dcmpro.len_known = 1;
	dcmpro.expected_len = expected_len;

	fmtutil_decompress_packbits_ex(c, &dcmpri, &dcmpro, &dres, &pbparams);
	dbuf_flush(dcmpro.f);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}
	de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", len, unc_pixels->len);
	retval = 1;
done:
	return retval;
}

struct vdat_ctx {
	lctx *d;
	struct imgbody_info *ibi;
	dbuf *unc_pixels;
	i64 vdat_chunk_count; // (the plane number)
	i64 cur_col;
	i64 ypos;
};

static void vdat_write_element(deark *c, struct vdat_ctx *vdctx, const u8 *elembuf)
{
	i64 dstpos;

	dstpos = vdctx->ibi->bytes_per_row_per_plane * vdctx->vdat_chunk_count;
	dstpos += 2*vdctx->cur_col;
	dstpos += vdctx->ypos * vdctx->ibi->frame_buffer_rowspan;

	dbuf_write_at(vdctx->unc_pixels, dstpos, elembuf, 2);
	vdctx->ypos++;
	if(vdctx->ypos >= vdctx->ibi->height) {
		vdctx->ypos = 0;
		vdctx->cur_col++;
	}
}

static void do_vdat_chunk(deark *c, struct vdat_ctx *vdctx, i64 pos1, i64 len)
{
	i64 pos;
	i64 endpos;
	i64 count;
	i64 cmd_cnt;
	i64 i, k;
	u8 cmd;
	u8 *cmds = NULL;
	u8 elembuf[2];

	vdctx->cur_col = 0;
	vdctx->ypos = 0;
	pos = pos1;
	endpos = pos1+len;

	cmd_cnt = de_getu16be(pos); // command count + 2
	pos+=2;
	cmd_cnt -= 2;
	de_dbg(c, "number of command bytes: %d", (int)cmd_cnt);
	if(cmd_cnt<1) goto done;

	cmds = de_mallocarray(c, cmd_cnt, sizeof(u8));

	// Read commands
	de_read(cmds, pos, cmd_cnt);
	pos += cmd_cnt;

	// Read data
	for(i=0; i<cmd_cnt; i++) {
		if(pos>=endpos) {
			break;
		}

		cmd = cmds[i];

		if(cmd==0x00) {
			count = de_getu16be(pos);
			pos += 2;
			for(k=0; k<count; k++) {
				de_read(elembuf, pos, 2);
				pos += 2;
				vdat_write_element(c, vdctx, elembuf);
			}
		}
		else if(cmd==0x01) {
			count = de_getu16be(pos);
			pos += 2;
			de_read(elembuf, pos, 2);
			pos += 2;
			for(k=0; k<count; k++) {
				vdat_write_element(c, vdctx, elembuf);
			}
		}
		else if(cmd>=0x80) {
			count = (128-(i64)(cmd&0x7f));
			for(k=0; k<count; k++) {
				de_read(elembuf, pos, 2);
				pos += 2;
				vdat_write_element(c, vdctx, elembuf);
			}
		}
		else { // cmd is from 0x02 to 0x7f
			de_read(elembuf, pos, 2);
			pos += 2;
			count = (i64)cmd;
			for(k=0; k<count; k++) {
				vdat_write_element(c, vdctx, elembuf);
			}
		}
	}

done:
	de_free(c, cmds);
}

static int my_vdat_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct vdat_ctx *vdctx = (struct vdat_ctx*)ictx->userdata;

	if(ictx->chunkctx->chunk4cc.id != CODE_VDAT) {
		goto done;
	}
	ictx->handled = 1;

	if(vdctx->vdat_chunk_count >= vdctx->ibi->planes_total) goto done;
	do_vdat_chunk(c, vdctx, ictx->chunkctx->dpos, ictx->chunkctx->dlen);

done:
	if(ictx->chunkctx->chunk4cc.id == CODE_VDAT) {
		vdctx->vdat_chunk_count++;
	}
	return 1;
}

static int decompress_method2(deark *c, lctx *d, struct imgbody_info *ibi,
	i64 pos, i64 len, dbuf *unc_pixels, i64 expected_len)
{
	struct vdat_ctx vdctx;
	struct de_iffctx *ictx_vdat = NULL;

	// For sanity, we'll use a separate IFF decoder for the contents of this BODY chunk.
	de_zeromem(&vdctx, sizeof(struct vdat_ctx));
	vdctx.d = d;
	vdctx.ibi = ibi;
	vdctx.unc_pixels = unc_pixels;

	ictx_vdat = fmtutil_create_iff_decoder(c);
	ictx_vdat->userdata = (void*)&vdctx;
	ictx_vdat->handle_chunk_fn = my_vdat_chunk_handler;
	ictx_vdat->f = c->infile;
	fmtutil_read_iff_format(ictx_vdat, pos, len);

	fmtutil_destroy_iff_decoder(ictx_vdat);
	return 1;
}

// Convert ACBM ABIT image to standard ILBM frame buffer format.
static int convert_abit(deark *c, lctx *d, struct imgbody_info *ibi,
	i64 pos, i64 len, dbuf *frame_buffer)
{
	i64 plane, j;
	i64 planespan;

	planespan = ibi->height * ibi->bytes_per_row_per_plane;

	for(plane=0; plane<ibi->planes_total; plane++) {
		for(j=0; j<ibi->height; j++) {
			dbuf_copy_at(c->infile, pos + plane*planespan + j*ibi->bytes_per_row_per_plane,
				ibi->bytes_per_row_per_plane, frame_buffer,
				j*ibi->frame_buffer_rowspan + plane*ibi->bytes_per_row_per_plane);
		}
	}
	return 1;
}

// Detect and warn about HAM-E, which we don't support.
static void detect_hame(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx)
{
	i64 plane;
	i64 k;
	UI firstword[4];
	u8 pixelval[16];
	static const u8 sig[15] = { 0xa, 0x2, 0xf, 0x5, 0x8, 0x4, 0xd, 0xc,
		0x6, 0xd, 0xb, 0x0, 0x7, 0xf, 0x1 };

	if(d->is_hame) return;
	if(d->ham_flag) return;
	if(!d->found_cmap) return;
	if(ibi->width<640) return;
	if(ibi->planes_fg!=4 || ibi->planes_total!=4) return;
	if(ibi->is_thumb) return;
	if(frctx->formtype!=CODE_ILBM && frctx->formtype!=CODE_ACBM) return;
	if(!frctx || !frctx->frame_buffer) return;

	// Note: This is quite possibly not the right way to detect HAM-E.
	// RECOIL does it by looking up the palette color of each pixel, and using
	// certain bits in the palette entry. In all the HAM-E images I have, the
	// palette is constructed so as to make that process a no-op.

	// Need to examine the values of the first 16 pixels, so need the first 2
	// bytes of each of the 4 planes of row 0.
	for(plane=0; plane<4; plane++) {
		firstword[plane] = (UI)dbuf_getu16be(frctx->frame_buffer,
			plane * ibi->bytes_per_row_per_plane);
	}

	for(k=0; k<16; k++) {
		pixelval[k] = 0;
		for(plane=0; plane<4; plane++) {
			if(firstword[plane] & (1U<<(15-(UI)k))) {
				pixelval[k] |= 1U<<(UI)plane;
			}
		}
	}

	if(de_memcmp(pixelval, sig, 15)) return;
	if(pixelval[15]!=0x4 && pixelval[15]!=0x8) return;

	if(d->opt_allowhame) {
		de_warn(c, "This is probably a HAM-E image, which is not supported correctly.");
	}
	else {
		de_err(c, "HAM-E images are not supported. "
			"(\"-opt ilbm:allowspecial\" to decode anyway)");
		d->errflag = 1;
	}

	d->is_hame = 1;
}

static int is_dctv_sig_at(dbuf *f, i64 pos)
{
	u8 x;

	static const u8 sig[31] = {
		0x49, 0x87, 0x28, 0xde, 0x11, 0x0b, 0xef, 0xd2, 0x0c, 0x8e, 0x8b, 0x35, 0x5b, 0x75, 0xec, 0xb8,
		0x29, 0x6b, 0x03, 0xf9, 0x2b, 0xb4, 0x34, 0xee, 0x67, 0x1e, 0x7c, 0x4f, 0x53, 0x63, 0x15 };

	x = dbuf_getbyte(f, pos);
	if(x != sig[0]) return 0;
	if(dbuf_memcmp(f, pos, sig, 31)) return 0;
	return 1;
}

// Detect and warn about DCTV, which we don't support.
static void detect_dctv(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx)
{
	i64 pos;
	int result;

	// As far as I can tell, in DCTV images, the last plane of the first row is
	// as follows:
	//   <00> <31-byte signature> <00 fill> <31-byte signature> <00>
	// (Sometimes, the last plane of the *second* row is the same.)
	// (But I have a 2-plane image in which it's the *first* plane of the first
	// two rows that are special. TODO: Figure this out.)
	//
	// Unknowns:
	// * Is DCTV possible if there are fewer than 64 bytes per row per plane (i.e. width < 512)?
	// * Can a DCTV image have transparency?
	// * If a DCTV image has a thumbnail image, what format does the thumbnail use?

	if(d->is_dctv) return;
	if(!frctx || !frctx->frame_buffer) return;
	if(ibi->is_thumb) return;
	if(frctx->formtype!=CODE_ILBM && frctx->formtype!=CODE_ACBM) return;
	if(ibi->bytes_per_row_per_plane<64) return;

	// Test end of last plane of first row
	pos = d->planes_raw * ibi->bytes_per_row_per_plane - 32;
	result = is_dctv_sig_at(frctx->frame_buffer, pos);

	if(!result) {
		// Test end of first plane of first row
		pos = ibi->bytes_per_row_per_plane - 32;
		result = is_dctv_sig_at(frctx->frame_buffer, pos);
	}

	if(!result) return;

	if(d->opt_allowdctv) {
		de_warn(c, "This is probably a DCTV image, which is not supported correctly.");
	}
	else {
		de_err(c, "DCTV images are not supported. "
			"(\"-opt ilbm:allowspecial\" to decode anyway)");
		d->errflag = 1;
	}

	d->is_dctv = 1;
}

// BODY/ABIT/TINY
static int do_image_chunk_internal(deark *c, lctx *d, struct frame_ctx *frctx, i64 pos1, i64 len, int is_thumb)
{
	struct imgbody_info *ibi = NULL;
	int ret;
	int retval = 0;

	if(d->errflag) goto done;
	if(!d->found_bmhd) goto done;
	if(!frctx) goto done;
	if(frctx->done_flag) goto done;
	frctx->done_flag = 1;

	ibi = de_malloc(c, sizeof(struct imgbody_info));

	do_before_image_chunk(c, d);

	if(!init_imgbody_info(c, d, ibi, is_thumb)) {
		goto done;
	}

	if(!frctx->frame_buffer) {
		frctx->frame_buffer = dbuf_create_membuf(c, ibi->frame_buffer_size, 0x1);
	}

	if(d->formtype==CODE_ACBM) {
		// Note: I don't think ABIT images are ever compressed.
		if(!convert_abit(c, d, ibi, pos1, len, frctx->frame_buffer)) goto done;
	}
	else if(d->formtype==CODE_RGBN || d->formtype==CODE_RGB8) {
		if(!decompress_rgbn8(c, d, ibi, pos1, len, frctx->frame_buffer)) goto done;
	}
	else if(ibi->compression==0) {
		if(!decompress_method0(c, d, pos1, len, frctx->frame_buffer, ibi->frame_buffer_size)) goto done;
	}
	else if(ibi->compression==1) {
		dbuf_enable_wbuffer(frctx->frame_buffer);
		ret = decompress_ilbm_packbits(c, c->infile, pos1, len,
			frctx->frame_buffer, ibi->frame_buffer_size, 1);
		dbuf_disable_wbuffer(frctx->frame_buffer);
		if(!ret) goto done;
	}
	else if(ibi->compression==2) {
		if(!decompress_method2(c, d, ibi, pos1, len, frctx->frame_buffer, ibi->frame_buffer_size)) goto done;
	}
	else {
		de_err(c, "Unsupported compression method: %d", (int)ibi->compression);
		goto done;
	}

	if(ibi->is_pbm && (frctx->frame_buffer->len != ibi->frame_buffer_size) && (ibi->width%2)) {
		if(frctx->frame_buffer->len == ibi->width*ibi->height) {
			// Hack: I have some PBM images (e.g. BBM thumbnails) that aren't row-padded.
			de_dbg(c, "[assuming rows are not 16-bit padded]");
			ibi->bytes_per_row_per_plane = ibi->width;
			ibi->bits_per_row_per_plane = ibi->bytes_per_row_per_plane * 8;
			ibi->frame_buffer_rowspan = ibi->bytes_per_row_per_plane * ibi->planes_total;
			ibi->frame_buffer_size = ibi->frame_buffer_rowspan * ibi->height;
		}
	}

	if(frctx->frame_buffer->len != ibi->frame_buffer_size) {
		de_warn(c, "Expected %"I64_FMT" decompressed bytes, got %"I64_FMT, ibi->frame_buffer_size,
			frctx->frame_buffer->len);
	}

	detect_dctv(c, d, ibi, frctx);
	detect_hame(c, d, ibi, frctx);

	write_frame(c, d, ibi, frctx);

	retval = 1;

done:
	de_free(c, ibi);
	return retval;
}

static void do_body_or_abit(deark *c, lctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	if(!de_good_image_dimensions(c, d->width, d->height)) {
		d->errflag = 1;
		goto done;
	}
	if(!do_image_chunk_internal(c, d, d->frctx, pos1, len, 0)) {
		d->errflag = 1;
		goto done;
	}
done:
	;
}

static void do_tiny(deark *c, lctx *d, i64 pos1, i64 len)
{
	struct frame_ctx *frctx = NULL;
	i64 pos = pos1;

	if(len<=4) goto done;

	d->thumb_width = de_getu16be_p(&pos);
	d->thumb_height = de_getu16be_p(&pos);
	de_dbg(c, "thumbnail image, dimensions: %d"DE_CHAR_TIMES"%d", (int)d->thumb_width, (int)d->thumb_height);
	if(!de_good_image_dimensions_noerr(c, d->thumb_width, d->thumb_height)) {
		de_warn(c, "Bad thumbnail image dimensions");
		goto done;
	}

	frctx = create_frame(c, d);
	(void)do_image_chunk_internal(c, d, frctx, pos, pos1+len-pos, 1);

done:
	destroy_frame(c, d, frctx);
}

// A few ILBM files with extension ".iff24" have this chunk, as
// do some DEEP files.
static void do_xs24(deark *c, dbuf *f, i64 pos1, i64 len)
{
	i64 w, h, rowspan;
	i64 pos = pos1;
	de_bitmap *img = NULL;

	w = de_getu16be_p(&pos);
	rowspan = w*3;
	h = de_getu16be_p(&pos);
	de_dbg(c, "24-bit thumbnail image, dimensions: %u"DE_CHAR_TIMES"%u", (UI)w, (UI)h);
	if(!de_good_image_dimensions_noerr(c, w, h)) goto done;
	if(rowspan*h+6 != len) goto done;
	pos += 2; // unknown field

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_rgb(f, pos, rowspan, 3, img, 0);
	de_bitmap_write_to_file(img, "thumb", DE_CREATEFLAG_IS_AUX);
done:
	de_bitmap_destroy(img);
}

static void get_bits_descr(deark *c, lctx *d, struct frame_ctx *frctx, de_ucstring *s)
{
	UI bits = frctx->bits;

	if(frctx->op==4 || frctx->op==5 || frctx->op==7 || frctx->op==8) {
		if(bits & 0x1) {
			ucstring_append_flags_item(s, "long data");
			bits -= 0x1;
			d->uses_anim_long_data = 1;
		}
	}
	if(frctx->op==4 || frctx->op==5) {
		if(bits & 0x2) {
			ucstring_append_flags_item(s, "XOR");
			bits -= 0x2;
			d->uses_anim4_5_xor_mode = 1;
		}
		if(bits & 0x4) {
			ucstring_append_flags_item(s, "one info list");
			bits -= 0x4;
		}
		if(bits & 0x8) {
			ucstring_append_flags_item(s, "RLC");
			bits -= 0x8;
		}
		if(bits & 0x10) {
			ucstring_append_flags_item(s, "vertical");
			bits -= 0x10;
		}
		if(bits & 0x20) {
			ucstring_append_flags_item(s, "long info offsets");
			bits -= 0x20;
		}
	}

	if(bits!=0) {
		ucstring_append_flags_itemf(s, "0x%08x", bits);
	}
}

static void do_anim_anhd(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 tmp;
	u8 ileave_raw;
	de_ucstring *bits_descr = NULL;
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

	ileave_raw = de_getbyte_p(&pos);
	de_dbg(c, "interleave: %d", (int)ileave_raw);
	if(ileave_raw==0) {
		frctx->interleave = 2;
	}
	else {
		frctx->interleave = (UI)ileave_raw;
	}
	if(frctx->interleave>2 && !d->errflag) {
		de_err(c, "Unsupported interleave");
		d->errflag = 1;
	}

	pos++; // pad0

	frctx->bits = (UI)de_getu32be_p(&pos);
	bits_descr = ucstring_create(c);
	get_bits_descr(c, d, frctx, bits_descr);
	de_dbg(c, "bits: 0x%08x (%s)", frctx->bits, ucstring_getpsz_d(bits_descr));

	ucstring_destroy(bits_descr);
}

static void do_camg(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len<4) return;
	d->has_camg = 1;
	d->camg_changed_flag = 1;

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

	if(d->formtype==CODE_RGBN || d->formtype==CODE_RGB8) {
		d->ham_flag = 0;
		d->ehb_flag = 0;
	}

	de_dbg_indent(c, 1);
	de_dbg(c, "HAM: %d", (int)d->ham_flag);
	de_dbg(c, "EHB: %d", (int)d->ehb_flag);
	de_dbg_indent(c, -1);
}

static void do_dpi(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len<4) return;
	d->x_dpi = de_getu16be(pos);
	d->y_dpi = de_getu16be(pos+2);
	de_dbg(c, "dpi: %d"DE_CHAR_TIMES"%d", (int)d->x_dpi, (int)d->y_dpi);
}

static void do_grab(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len<4) return;
	d->has_hotspot = 1;
	d->hotspot_x = (int)de_getu16be(pos);
	d->hotspot_y = (int)de_getu16be(pos+2);
	de_dbg(c, "hotspot: (%d, %d)", d->hotspot_x, d->hotspot_y);
}

static void do_dpan(deark *c, lctx *d, i64 pos, i64 len)
{
	i64 nframes;

	if(!d->is_anim) return;
	if(len<4) return;
	nframes = de_getu16be(pos+2);
	de_dbg(c, "number of frames: %d", (int)nframes);
}

static void do_crng(deark *c, lctx *d, i64 pos1, i64 len)
{
	UI tmp1, tmp2;

	if(len<8) return;
	tmp1 = (UI)de_getu16be(pos1+2);
	tmp2 = (UI)de_getu16be(pos1+4);
	de_dbg(c, "CRNG flags: 0x%04x", tmp2);
	if(tmp2&0x1) {
		de_dbg(c, "rate: %.2f fps", (double)(((double)tmp1)*(60.0/16384.0)));
		on_color_cycling_enabled(c, d);
	}
}

static void do_drng(deark *c, lctx *d, i64 pos1, i64 len)
{
	UI tmp2;

	tmp2 = (UI)de_getu16be(pos1+4);
	de_dbg(c, "DRNG flags: 0x%04x", tmp2);
	if(tmp2&0x1) {
		on_color_cycling_enabled(c, d);
	}
}

// Graphicraft Color Cycling Range and Timing
static void do_ccrt(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 tmp1;

	tmp1 = de_geti16be(pos1);
	de_dbg(c, "cycling direction: %d", (int)tmp1);
	if(tmp1!=0) {
		d->uses_color_cycling = 1;
	}
}

// Frame sequencing chunk used in ANIM-J
static void do_ansq(deark *c, lctx *d, i64 pos1, i64 len)
{
	i64 num_items;
	i64 i;

	// TODO: Figure out how critical this ANSQ info is.
	// If deltas are supposed to be applied out of sequence, we could at least
	// emit a warning.

	num_items = len / 4;
	de_dbg(c, "number of frames in sequence: %d", (int)num_items);
	if(c->debug_level<2) return;
	de_dbg_indent(c, 1);
	for(i=0; i<num_items && i<2000; i++) {
		i64 frnum, dur;

		frnum = de_getu16be(pos1+i*4);
		dur = de_getu16be(pos1+i*4+2);
		de_dbg2(c, "item[%d]: frame=%d, dur=%d", (int)i, (int)frnum, (int)dur);
	}
	de_dbg_indent(c, -1);
}

static void render_pixel_row_ham6(deark *c, lctx *d, i64 rownum, const u32 *rowbuf,
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
		u8 val = rowbuf[i] & 0xff;

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

static void render_pixel_row_ham8(deark *c, lctx *d, i64 rownum, const u32 *rowbuf,
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
		u8 val = rowbuf[i] & 0xff;

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

static void render_pixel_row_normal(deark *c, lctx *d, struct imgbody_info *ibi,
	i64 rownum, const u32 *rowbuf, UI rowbuf_size, de_bitmap *img)
{
	UI k;

	for(k=0; k<rowbuf_size; k++) {
		de_bitmap_setpixel_rgb(img, (i64)k, rownum, d->pal[(UI)rowbuf[k] & 0xff]);
	}
}

static void render_pixel_row_rgb24(deark *c, lctx *d, struct imgbody_info *ibi,
	i64 rownum, const u32 *rowbuf, UI rowbuf_size, de_bitmap *img)
{
	UI k;

	for(k=0; k<rowbuf_size; k++) {
		UI r, g, b;

		r = (rowbuf[k] & 0x0000ff);
		g = (rowbuf[k] & 0x00ff00)>>8;
		b = (rowbuf[k] & 0xff0000)>>16;
		de_bitmap_setpixel_rgb(img, (i64)k, rownum, DE_MAKE_RGB(r, g, b));
	}
}

static void set_finfo_data(deark *c, lctx *d, struct imgbody_info *ibi, de_finfo *fi)
{
	int has_aspect = 0;
	int has_dpi = 0;

	if(ibi->is_thumb) {
		de_finfo_set_name_from_sz(c, fi, "thumb", 0, DE_ENCODING_LATIN1);
	}

	if(d->x_aspect>0 && d->y_aspect>0) {
		has_aspect = 1;
	}
	if(!ibi->is_thumb && d->x_dpi>0 && d->y_dpi>0) {
		has_dpi = 1;
	}

	if(has_dpi) {
		fi->density.code = DE_DENSITY_DPI;
		fi->density.xdens = (double)d->x_dpi;
		fi->density.ydens = (double)d->y_dpi;
	}
	else if(has_aspect) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.ydens = (double)d->x_aspect;
		fi->density.xdens = (double)d->y_aspect;
	}

	if(!ibi->is_thumb && d->has_hotspot) {
		fi->has_hotspot = 1;
		fi->hotspot_x = d->hotspot_x;
		fi->hotspot_y = d->hotspot_y;
	}
}

// Generate the final image and write it to a file.
static void write_frame(deark *c, lctx *d, struct imgbody_info *ibi, struct frame_ctx *frctx)
{
	de_bitmap *img = NULL;
	i64 j;
	u32 *rowbuf = NULL; // The current row of pixel (palette or RGB) values
	u8 *rowbuf_trns = NULL; // The current row's 1-bit transparency mask values
	UI rowbuf_size;
	int bypp;
	de_finfo *fi = NULL;
	UI createflags = 0;
	u32 pixelval[8];
	u8 pixeltrnsval[8];

	if(d->errflag) goto done;
	if(!frctx) goto done;
	if(!frctx->frame_buffer) {
		d->errflag = 1;
		goto done;
	}
	if(ibi->colortype==COLORTYPE_RGB24) {
		if(ibi->planes_fg!=24) goto done;
	}
	else if(ibi->planes_fg<1 || ibi->planes_fg>8) {
		goto done;
	}

	if(d->debug_frame_buffer) {
		de_finfo *fi_fb;

		fi_fb = de_finfo_create(c);
		de_finfo_set_name_from_sz(c, fi_fb, "fb", 0, DE_ENCODING_LATIN1);
		de_convert_and_write_image_bilevel(frctx->frame_buffer, 0,
			ibi->bits_per_row_per_plane * ibi->planes_total,
			ibi->height, ibi->frame_buffer_rowspan, 0, fi_fb, 0);
		de_finfo_destroy(c, fi_fb);
	}

	rowbuf_size = (UI)ibi->width;
	rowbuf = de_mallocarray(c, rowbuf_size, sizeof(rowbuf[0]));
	rowbuf_trns = de_mallocarray(c, rowbuf_size, sizeof(rowbuf_trns[0]));

	if(ibi->is_rgb24) {
		bypp = 3;
	}
	else if(d->found_cmap && d->pal_is_grayscale && d->planes_raw<=8 && !d->is_ham6 && !d->is_ham8) {
		bypp = 1;
	}
	else {
		bypp = 3;
	}

	if(ibi->use_colorkey_transparency || ibi->masking_code==MASKINGTYPE_1BITMASK) {
		bypp++;
	}

	img = de_bitmap_create(c, ibi->width, ibi->height, bypp);

	if(ibi->is_pbm) {
		de_convert_image_paletted(frctx->frame_buffer, 0, 8, ibi->frame_buffer_rowspan,
			d->pal, img, 0);
		goto after_render;
	}
	else if(ibi->is_rgb24) {
		de_convert_image_rgb(frctx->frame_buffer, 0, ibi->bytes_per_row_per_plane, 3,
			img, 0);
		goto after_render;
	}

	for(j=0; j<ibi->height; j++) {
		i64 z;
		i64 plane;
		UI k;

		// Process 8 pixels at a time
		for(z=0; z<ibi->bytes_per_row_per_plane; z++) {
			de_zeromem(pixelval, sizeof(pixelval));
			de_zeromem(pixeltrnsval, sizeof(pixeltrnsval));

			// Read the zth byte in each plane
			for(plane=0; plane<ibi->planes_total; plane++) {
				u8 b;

				b = dbuf_getbyte(frctx->frame_buffer,
					j*ibi->frame_buffer_rowspan +
					plane*ibi->bytes_per_row_per_plane + z);

				for(k=0; k<8; k++) {
					if(b & (1U<<(7-k))) {
						if(plane < ibi->planes_fg) {
							pixelval[k] |= 1U<<(UI)plane;
						}
						else {
							// The only way this can happen is if this plane is a
							// 1-bit transparency mask.
							pixeltrnsval[k] = 1;
						}
					}
				}
			}

			for(k=0; k<8; k++) {
				UI idx;

				idx = (UI)z*8+k;
				if(idx < rowbuf_size) {
					rowbuf[idx] = pixelval[k];
					rowbuf_trns[idx] = pixeltrnsval[k];
				}
			}
		}

		if(ibi->colortype==COLORTYPE_RGB24) {
			render_pixel_row_rgb24(c, d, ibi, j, rowbuf, rowbuf_size, img);
		}
		else if(d->is_ham6) {
			render_pixel_row_ham6(c, d, j, rowbuf, rowbuf_size, img);
		}
		else if(d->is_ham8) {
			render_pixel_row_ham8(c, d, j, rowbuf, rowbuf_size, img);
		}
		else {
			render_pixel_row_normal(c, d, ibi, j, rowbuf, rowbuf_size, img);
		}

		// Handle 1-bit transparency masks here, for all color types.
		if(ibi->masking_code==MASKINGTYPE_1BITMASK) {
			i64 i;

			for(i=0; i<rowbuf_size; i++) {
				u32 clr;

				if(rowbuf_trns[i]==0) {
					clr = de_bitmap_getpixel(img, i, j);
					clr = DE_SET_ALPHA(clr, 0);
					de_bitmap_setpixel_rgba(img, i, j, clr);
				}
			}
		}
	}

after_render:
	if(d->trans_setting==TRANS_AUTO) {
		if(ibi->masking_code==MASKINGTYPE_1BITMASK) {
			de_bitmap_optimize_alpha(img, 0x2|0x4);
		}
	}
	else if(d->trans_setting==TRANS_REMOVE) {
		de_bitmap_remove_alpha(img);
	}

	fi = de_finfo_create(c);
	set_finfo_data(c, d, ibi, fi);
	if(ibi->is_thumb) {
		createflags |= DE_CREATEFLAG_IS_AUX;
	}

	de_bitmap_write_to_file_finfo(img, fi, createflags);

done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
	de_free(c, rowbuf);
	de_free(c, rowbuf_trns);
}

static void on_frame_begin(deark *c, lctx *d, u32 formtype)
{
	if(d->frctx) return;
	d->num_frames_started++;
	d->frctx = create_frame(c, d);
	d->frctx->formtype = formtype;
	d->frctx->frame_idx = d->num_frames_finished;
	if(d->is_anim) de_dbg(c, "[frame #%d begin]", d->frctx->frame_idx);
}

static void on_frame_end(deark *c, lctx *d)
{
	if(!d->frctx) return;

	if(d->is_anim) de_dbg(c, "[frame #%d end]", d->frctx->frame_idx);

	destroy_frame(c, d, d->oldfrctx[1]); // Destroy the frame that's aged out
	d->oldfrctx[1] = d->oldfrctx[0]; // Make room for the new frame
	d->oldfrctx[0] = d->frctx; // Save the new frame
	d->frctx = NULL;
	d->num_frames_finished++;
}

static int my_iff_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	int quitflag = 0;
	lctx *d = (lctx*)ictx->userdata;

	if(d->num_frames_finished >= ANIM_MAX_FRAMES) {
		quitflag = 1;
		goto done;
	}

	// Chunks that we support even if they are not in FORM:ILBM, FORM:PBM, etc. chunk.

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		if(ictx->level==0) {
			// Remember this for later
			d->main_chunk_endpos = ictx->chunkctx->dpos + ictx->chunkctx->dlen;
		}
		if(ictx->level>d->FORM_level) break;
		ictx->is_std_container = 1;
		goto done;
	}

	// Chunks that we process only inside a FORM:ILBM, etc. chunk.

	if(!d->frctx) goto done;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_BMHD:
		ictx->handled = 1;
		if(!do_bmhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen)) {
			d->errflag = 1;
			goto done;
		}
		break;

	case CODE_ANHD:
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;

	case CODE_CMAP:
		do_cmap(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;

	case CODE_CAMG:
		do_camg(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;

	case CODE_BODY:
	case CODE_ABIT:
		ictx->handled = 1;
		do_body_or_abit(c, d, ictx, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_DLTA:
		ictx->handled = 1;
		if(ictx->curr_container_contentstype4cc.id != CODE_ILBM) {
			d->errflag = 1;
			goto done;
		}
		do_dlta(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_TINY:
		do_tiny(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_XS24:
		do_xs24(c, ictx->f, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;

	case CODE_DPI:
		do_dpi(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_GRAB:
		do_grab(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_DPAN:
		do_dpan(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_CRNG:
		do_crng(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_DRNG:
		do_drng(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_CCRT:
		do_ccrt(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_SHAM:
		d->is_sham = 1;
		on_multipalette_enabled(c, d);
		break;
	case CODE_PCHG:
		d->is_pchg = 1;
		on_multipalette_enabled(c, d);
		break;
	case CODE_CTBL:
		d->is_ctbl = 1;
		on_multipalette_enabled(c, d);
		break;
	case CODE_BEAM:
		d->is_beam = 1;
		on_multipalette_enabled(c, d);
		break;
	case CODE_CLUT:
		d->found_clut = 1;
		break;
	case CODE_ANSQ:
		do_ansq(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_SBDY:
		if(d->is_anim && !d->found_audio) {
			de_info(c, "Note: This file includes AnimFX-style audio, which is "
				"not supported.");
			d->found_audio = 1;
		}
		break;
	}

done:
	return (quitflag) ? 0 : 1;
}

static int my_preprocess_iff_chunk_fn(struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;
	const char *name = NULL;

	// frctx will be set if we're in an "image" container, such as FORM:ILBM.
	// It is possible, e.g., for an ANIM file to contain FORM:8SVX containers
	// which contain BODY chunks that are not "image data".
	if(d->frctx) {
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
	}

	if(name) {
		ictx->chunkctx->chunk_name = name;
	}
	return 1;
}

static int my_on_std_container_start_fn(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	lctx *d = (lctx*)ictx->userdata;

	if(ictx->level==d->FORM_level) {
		if(d->frctx) {
			on_frame_end(c, d);
		}
		if((ictx->curr_container_contentstype4cc.id == CODE_ILBM) ||
			(ictx->curr_container_contentstype4cc.id == CODE_PBM) ||
			(ictx->curr_container_contentstype4cc.id == CODE_ACBM) ||
			(ictx->curr_container_contentstype4cc.id == CODE_RGBN) ||
			(ictx->curr_container_contentstype4cc.id == CODE_RGB8))
		{
			on_frame_begin(c, d, ictx->curr_container_contentstype4cc.id);
		}
		else {
			if(d->is_anim) {
				if(ictx->curr_container_contentstype4cc.id == CODE_8SVX) {
					d->found_audio = 1;
				}
				if(!d->extra_content_warned) {
					de_warn(c, "File includes unsupported content of type '%s'",
						ictx->curr_container_contentstype4cc.id_sanitized_sz);
					d->extra_content_warned = 1;
				}
			}
			else {
				de_err(c, "Unsupported ILBM-like format");
				d->errflag = 1;
			}
		}
	}
	return 1;
}

static void look_for_RAST(deark *c, lctx *d, i64 pos)
{
	if(d->found_rast) return;
	if(!dbuf_memcmp(c->infile, pos, "RAST", 4)) {
		d->found_rast = 1;
	}
}

static void do_eof_stuff(deark *c, lctx *d)
{
	i64 endpos, endpos_padded;
	i64 extra_bytes;

	endpos = d->main_chunk_endpos;
	if(endpos<1) return;
	endpos_padded = de_pad_to_2(endpos);
	extra_bytes = c->infile->len - endpos_padded;
	if(extra_bytes<1) return;
	de_dbg(c, "[found %"I64_FMT" extra bytes at end of file, starting at %"I64_FMT"]",
		extra_bytes, endpos_padded);

	look_for_RAST(c, d, endpos);
	if(endpos_padded!=endpos) {
		look_for_RAST(c, d, endpos_padded);
	}
	if(d->found_rast) {
		de_warn(c, "Possible RAST data found, which is not supported. "
			"Image might not be decoded correctly.");
	}
}

static int my_on_container_end_fn(struct de_iffctx *ictx)
{
	if(ictx->level==0) {
		// Stop after the first top-level chunk (the FORM chunk).
		return 0;
	}
	return 1;
}

static void summary_append(de_ucstring *s, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 2, 3)));

static void summary_append(de_ucstring *s, const char *fmt, ...)
{
	va_list ap;

	ucstring_append_char(s, ' ');
	va_start(ap, fmt);
	ucstring_vprintf(s, DE_ENCODING_LATIN1, fmt, ap);
	va_end(ap);
}

// Print a summary line indicating the main characteristics of this file.
static void print_summary(deark *c, lctx *d)
{
	de_ucstring *s = NULL;
	size_t k;

	if(c->debug_level<1) goto done;
	if(!d->found_bmhd) goto done;

	s = ucstring_create(c);

	summary_append(s,"%s", d->formtype_sanitized_sz);
	summary_append(s, "planes=%d", (int)d->planes_raw);
	if(d->masking_code!=0) summary_append(s, "masking=%d", (int)d->masking_code);
	summary_append(s, "cmpr=%d", (int)d->compression);
	for(k=0; k<256; k++) {
		if(d->delta_ops_used[k]) {
			summary_append(s, "delta%u", (UI)k);
		}
	}
	if(d->uses_anim_long_data) summary_append(s, "long_data");
	if(d->uses_anim4_5_xor_mode) summary_append(s, "xor_mode");

	if(d->ham_flag) summary_append(s, "HAM");
	if(d->ehb_flag) summary_append(s, "EHB");
	if(d->is_sham) summary_append(s, "SHAM");
	if(d->is_pchg) summary_append(s, "PCHG");
	if(d->is_ctbl) summary_append(s, "CTBL");
	if(d->is_beam) summary_append(s, "BEAM");
	if(d->is_hame) summary_append(s, "HAM-E");
	if(d->is_dctv) summary_append(s, "DCTV");
	if(d->found_rast) summary_append(s, "RAST");
	if(d->uses_color_cycling) summary_append(s, "color-cycling");
	if(d->found_clut) summary_append(s, "CLUT");
	if(d->found_audio) summary_append(s, "audio");
	if(!d->found_cmap) summary_append(s, "no-CMAP");

	de_dbg(c, "summary:%s", ucstring_getpsz(s));

done:
	ucstring_destroy(s);
}

static void strip_trailing_space_sz(char *sz)
{
	size_t n;

	n = de_strlen(sz);
	if(n>1 && sz[n-1]==0x20) {
		sz[n-1] = '\0';
	}
}

static void de_run_ilbm_or_anim(deark *c, de_module_params *mparams)
{
	u32 id;
	u8 opt_notrans = 0;
	u8 opt_fixpal;
	int opt;
	const char *opt_trans_str;
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	struct de_fourcc formtype_4cc;

	d = de_malloc(c, sizeof(lctx));
	opt_fixpal = (u8)de_get_ext_option_bool(c, "ilbm:fixpal", 0xff);

	opt_trans_str = de_get_ext_option(c, "ilbm:trans");

	if(!opt_trans_str) {
		if(de_get_ext_option(c, "ilbm:notrans")) { // Deprecated option
			opt_notrans = 1;
		}
	}

	if(de_get_ext_option_bool(c, "ilbm:allowspecial", 0)) {
		d->opt_allowsham = 1;
		d->opt_allowdctv = 1;
		d->opt_allowhame = 1;
	}
	// allowsham is deprecated
	opt = de_get_ext_option_bool(c, "ilbm:allowsham", -1);
	if(opt==0) d->opt_allowsham = 0;
	else if(opt>0) d->opt_allowsham = 1;

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) {
		de_err(c, "Not an IFF file");
		goto done;
	}

	dbuf_read_fourcc(c->infile, 8, &formtype_4cc, 4, 0);
	d->formtype = formtype_4cc.id;
	de_strlcpy(d->formtype_sanitized_sz, formtype_4cc.id_sanitized_sz, sizeof(d->formtype_sanitized_sz));

	// A quick hack, so we have "PBM" instead of "PBM ".
	// TODO: Maybe dbuf_read_fourcc should do this, or have an option to.
	strip_trailing_space_sz(d->formtype_sanitized_sz);

	switch(d->formtype) {
	case CODE_ANIM:
		d->is_anim = 1;
		break;
	case CODE_ILBM:
	case CODE_ACBM:
	case CODE_PBM:
	case CODE_RGBN:
	case CODE_RGB8:
		break;
	default:
		de_err(c, "Not a supported ILBM-like format (%s)", d->formtype_sanitized_sz);
		goto done;
	}
	de_declare_fmtf(c, "IFF-%s", d->formtype_sanitized_sz);

	if(d->is_anim) {
		d->opt_anim_includedups = (u8)de_get_ext_option_bool(c, "anim:includedups", 0);
	}

	if(opt_fixpal==0xff) {
		// Fixpal option defaults to No for ANIM format, othersize Yes.
		// (The concern with ANIM is that we don't want frame 1's colors
		// to fail to match frame 2's colors.)
		d->fixpal_setting = (d->is_anim ? 0 : 1);
	}
	else {
		d->fixpal_setting = opt_fixpal;
	}

	// Default for d->trans_setting
	if(d->is_anim) {
		// I don't think AUTO makes sense for ANIM.
		d->trans_setting = TRANS_RESPECT;
	}
	else {
		d->trans_setting = TRANS_AUTO;
	}

	if(opt_trans_str) {
		if(!de_strcmp(opt_trans_str, "auto")) {
			d->trans_setting = TRANS_AUTO;
		}
		else if(!de_strcmp(opt_trans_str, "")) {
			d->trans_setting = TRANS_RESPECT;
		}
		else {
			int opt_trans_n;

			opt_trans_n = de_atoi(opt_trans_str);
			if(opt_trans_n==0) {
				d->trans_setting = TRANS_REMOVE;
			}
			else if(opt_trans_n>0) {
				d->trans_setting = TRANS_RESPECT;
			}
		}
	}
	else if(opt_notrans) {
		d->trans_setting = TRANS_REMOVE;
	}

	d->FORM_level = d->is_anim ? 1 : 0;

	ictx = fmtutil_create_iff_decoder(c);
	ictx->has_standard_iff_chunks = 1;
	ictx->userdata = (void*)d;
	ictx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	ictx->handle_chunk_fn = my_iff_chunk_handler;
	ictx->preprocess_chunk_fn = my_preprocess_iff_chunk_fn;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->on_container_end_fn = my_on_container_end_fn;
	ictx->f = c->infile;
	fmtutil_read_iff_format(ictx, 0, c->infile->len);

	if(d->frctx) {
		on_frame_end(c, d);
	}
	do_eof_stuff(c, d);
	print_summary(c, d);

done:
	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		destroy_frame(c, d, d->frctx);
		destroy_frame(c, d, d->oldfrctx[0]);
		destroy_frame(c, d, d->oldfrctx[1]);
		de_free(c, d);
	}
}

static void de_run_ilbm(deark *c, de_module_params *mparams)
{
	de_run_ilbm_or_anim(c, mparams);
}

static void de_run_anim(deark *c, de_module_params *mparams)
{
	de_run_ilbm_or_anim(c, mparams);
}

static int de_identify_ilbm(deark *c)
{
	u32 id;

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) return 0;
	id = (u32)de_getu32be(8);
	switch(id) {
	case CODE_ILBM:
	case CODE_PBM:
	case CODE_ACBM:
	case CODE_RGBN:
	case CODE_RGB8:
		return 100;
	}
	return 0;
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

static void do_help_ilbm_anim(deark *c, int is_anim)
{
	de_msg(c, "-opt ilbm:trans=<0|1|auto> : Always remove (0) or respect (1) "
		"transparency");
	de_msg(c, "-opt ilbm:fixpal=<0|1> : Don't/Do try to fix palettes that are "
		"slightly too dark");
	de_msg(c, "-opt ilbm:allowspecial : Suppress an error on some images");
	if(is_anim) {
		de_msg(c, "-opt anim:includedups : Do not suppress duplicate frames");
	}
}

static void de_help_ilbm(deark *c)
{
	do_help_ilbm_anim(c, 0);
}

static void de_help_anim(deark *c)
{
	do_help_ilbm_anim(c, 1);
}

void de_module_ilbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ilbm";
	mi->desc = "IFF-ILBM and related image formats";
	mi->run_fn = de_run_ilbm;
	mi->identify_fn = de_identify_ilbm;
	mi->help_fn = de_help_ilbm;
}

void de_module_anim(deark *c, struct deark_module_info *mi)
{
	mi->id = "anim";
	mi->desc = "IFF-ANIM animation";
	mi->run_fn = de_run_anim;
	mi->identify_fn = de_identify_anim;
	mi->help_fn = de_help_anim;
}

///// IFF-DEEP

#define CODE_DBOD 0x44424f44U
#define CODE_DEEP 0x44454550U
#define CODE_DGBL 0x4447424cU
#define CODE_DLOC 0x444c4f43U
#define CODE_DPEL 0x4450454cU
#define CODE_MPIC 0x4d504943U
#define CODE_TVDC 0x54564443U
#define CODE_TVPP 0x54565050U

#define DEEP_MAX_COMPONENTS 8

struct deep_ctx {
	UI cmpr_meth;
	int DBOD_count;
	u8 trans_setting; // TRANS_*
	u8 found_DLOC;
	u8 found_TVDC;
	u8 found_DPEL;
	i64 dspw, dsph;
	i64 width, height;
	i64 x_aspect, y_aspect;
	i64 expected_image_size;
	i64 num_components;
	u8 have_alpha;
	u8 have_alpha_hint; // Preliminary, set while reading DPEL
	u8 is_assoc_alpha;
	UI cmp_nbits[DEEP_MAX_COMPONENTS];
	UI cmp_type[DEEP_MAX_COMPONENTS];
	UI sample_map[DEEP_MAX_COMPONENTS];
	u8 tvdc_data[32];
};

static void do_deep_DGBL(deark *c, struct deep_ctx *d, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;

	d->dspw = dbuf_getu16be_p(ictx->f, &pos);
	d->dsph = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "display size: %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, d->dspw, d->dsph);
	if(!d->found_DLOC) {
		d->width = d->dspw;
		d->height = d->dsph;
	}
	d->cmpr_meth = (UI)dbuf_getu16be_p(ictx->f, &pos);
	de_dbg(c, "cmpr meth: %u", d->cmpr_meth);
	d->x_aspect = (i64)dbuf_getbyte_p(ictx->f, &pos);
	d->y_aspect = (i64)dbuf_getbyte_p(ictx->f, &pos);
	de_dbg(c, "aspect ratio: %d, %d", (int)d->x_aspect, (int)d->y_aspect);
}

static void do_deep_DLOC(deark *c, struct deep_ctx *d, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;
	i64 pixpos_x, pixpos_y;

	d->found_DLOC = 1;
	d->width = dbuf_getu16be_p(ictx->f, &pos);
	d->height = dbuf_getu16be_p(ictx->f, &pos);
	de_dbg_dimensions(c, d->width, d->height);
	pixpos_x = dbuf_geti16be_p(ictx->f, &pos);
	pixpos_y = dbuf_geti16be_p(ictx->f, &pos);
	de_dbg(c, "position: %"I64_FMT", %"I64_FMT, pixpos_x, pixpos_y);
}

static void do_deep_DPEL(deark *c, struct deep_ctx *d, struct de_iffctx *ictx)
{
	i64 pos = ictx->chunkctx->dpos;
	i64 endpos = ictx->chunkctx->dpos + ictx->chunkctx->dlen;
	UI i;

	d->found_DPEL = 1;
	d->num_components = (UI)dbuf_getu32be_p(ictx->f, &pos);
	de_dbg(c, "num cmpts: %u", (UI)d->num_components);
	if(d->num_components>DEEP_MAX_COMPONENTS) {
		d->num_components = 0;
		goto done;
	}
	for(i=0; i<d->num_components; i++) {
		if(pos+4 > endpos) break;
		d->cmp_type[i] = (UI)dbuf_getu16be_p(ictx->f, &pos);
		if(d->cmp_type[i]==4 || d->cmp_type[i]==17) {
			d->have_alpha_hint = 1;
		}
		d->cmp_nbits[i] = (UI)dbuf_getu16be_p(ictx->f, &pos);
		de_dbg(c, "cmpt[%u]: type=%u depth=%u", i, d->cmp_type[i], d->cmp_nbits[i]);
	}
done:
	;
}

// Sets d->sample_map[], d->have_alpha...
// If unsupported image type, reports an error and returns 0.
static int deep_make_sample_map(deark *c, struct deep_ctx *d)
{
	UI k;
	u8 flags[5] = {0,0,0,0,0};
	int retval = 0;

	de_zeromem(d->sample_map, sizeof(d->sample_map));
	d->have_alpha = 0;
	d->is_assoc_alpha = 0;

	if(d->num_components<3 || d->num_components>DEEP_MAX_COMPONENTS) {
		goto done;
	}

	for(k=0; k<(UI)d->num_components; k++) {
		switch(d->cmp_type[k]) {
		case 1:
			d->sample_map[k] = 0;
			break;
		case 2:
			d->sample_map[k] = 1;
			break;
		case 3:
			d->sample_map[k] = 2;
			break;
		case 4:
			d->sample_map[k] = 3;
			d->have_alpha = 1;
			d->is_assoc_alpha = 0;
			break;
		case 17: // Undocumented type 17 used in Video Toaster "Brushes" files.
			d->sample_map[k] = 3;
			d->have_alpha = 1;
			d->is_assoc_alpha = 1;
			break;
		default:
			d->sample_map[k] = 4;
		}

		flags[d->sample_map[k]] = 1;
	}

	if(!flags[0] || !flags[1] || !flags[2]) { // Need R, G, B
		goto done;
	}
	if(flags[4]) { // Found an unsupported sample type
		de_warn(c, "Image type not fully supported");
	}
	retval = 1;

done:
	if(!retval) {
		de_err(c, "Unsupported image type");
	}
	return retval;
}

static void deep_decode_image_unc(deark *c, struct deep_ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	i64 i, j;
	i64 pos = pos1;
	UI k;
	UI dst_samples_per_pixel;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	u8 s[5] = {0,0,0,0,0};

	fi = de_finfo_create(c);
	if(d->x_aspect && d->y_aspect) {
		fi->density.code = DE_DENSITY_UNK_UNITS;
		fi->density.ydens = (double)d->x_aspect;
		fi->density.xdens = (double)d->y_aspect;
	}

	dst_samples_per_pixel = d->have_alpha ? 4 : 3;
	img = de_bitmap_create(c, d->width, d->height, dst_samples_per_pixel);

	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			de_color clr;

			if(pos > pos1+len) {
				de_warn(c, "Premature end of image");
				goto after_image;
			}

			for(k=0; k<(UI)d->num_components; k++) {
				s[d->sample_map[k]] =  dbuf_getbyte_p(f, &pos);
			}
			if(d->have_alpha) {
				clr = DE_MAKE_RGBA(s[0], s[1], s[2], s[3]);
				if(d->is_assoc_alpha) {
					clr = de_unpremultiply_alpha_clr(clr);
				}
			}
			else {
				clr = DE_MAKE_RGB(s[0], s[1], s[2]);
			}
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}

after_image:
	if(d->trans_setting==TRANS_AUTO) {
		de_bitmap_optimize_alpha(img, (0x4|0x02));
	}
	else if(d->trans_setting==TRANS_REMOVE) {
		de_bitmap_remove_alpha(img);
	}
	de_bitmap_write_to_file_finfo(img, fi, 0);

	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

static int decompress_deep_5(deark *c, struct deep_ctx *d, dbuf *inf,
	i64 pos1, i64 len, dbuf *unc_pixels)
{
	i64 xpos = 0;
	i64 ypos = 0;
	i64 output_pos = 0;
	i64 curr_component = 0;
	u8 v = 0;
	int retval = 0;
	struct de_bitreader bitrd;

	de_zeromem(&bitrd, sizeof(struct de_bitreader));
	bitrd.f = inf;
	bitrd.curpos = pos1;
	bitrd.endpos = pos1+len;
	bitrd.bbll.is_lsb = 0;
	dbuf_disable_wbuffer(unc_pixels);

	if(!d->found_TVDC) {
		de_err(c, "Missing TVDC chunk");
		goto done;
	}
	retval = 1;

	while(1) {
		UI n;
		UI k;
		UI count;

		n = (UI)de_bitreader_getbits(&bitrd, 4);
		if(bitrd.eof_flag) goto done;

		if(d->tvdc_data[n*2+1]!=0 || d->tvdc_data[n*2]!=0) {
			v += (u8)(d->tvdc_data[n*2+1]);
			count = 1;
		}
		else {
			n = (UI)de_bitreader_getbits(&bitrd, 4);
			count = n+1;
		}

		for(k=0; k<count; k++) {
			dbuf_writebyte_at(unc_pixels, output_pos, v);
			output_pos += d->num_components;
			xpos++;
			if(xpos >= d->width) break;
		}

		if(xpos >= d->width) {
			de_bitreader_skip_to_byte_boundary(&bitrd);
			xpos = 0;
			v = 0;
			curr_component++;
			if(curr_component >= d->num_components) {
				ypos++;
				if(ypos >= d->height) goto done;
				curr_component = 0;
			}
			output_pos = ypos*(d->width * d->num_components) + curr_component;
		}
	}

done:
	return retval;
}

static void deep_decompress_and_decode_image(deark *c, struct deep_ctx *d,
	dbuf *f, i64 pos1, i64 len)
{
	int ret;
	dbuf *unc_pixels = NULL;

	unc_pixels = dbuf_create_membuf(c, d->expected_image_size, 0x1);
	if(d->cmpr_meth!=5) {
		dbuf_enable_wbuffer(unc_pixels);
	}
	if(d->cmpr_meth==5) {
		ret = decompress_deep_5(c, d, f, pos1, len, unc_pixels);
	}
	else {
		ret = decompress_ilbm_packbits(c, f, pos1, len, unc_pixels, d->expected_image_size,
			(UI)d->num_components);
	}
	dbuf_flush(unc_pixels);
	if(!ret) goto done;

	deep_decode_image_unc(c, d, unc_pixels, 0, unc_pixels->len);
done:
	dbuf_close(unc_pixels);
}

static void do_deep_DBOD(deark *c, struct deep_ctx *d, struct de_iffctx *ictx)
{
	if(d->cmpr_meth!=0 && d->cmpr_meth!=1 && d->cmpr_meth!=5) {
		de_err(c, "Unsupported compression type: %u", d->cmpr_meth);
		goto done;
	}

	if(!deep_make_sample_map(c, d)) goto done;

	if(!de_good_image_dimensions(c, d->width, d->height)) {
		goto done;
	}

	d->expected_image_size = d->width * d->height * d->num_components;

	if(d->cmpr_meth==0) {
		deep_decode_image_unc(c, d, ictx->f, ictx->chunkctx->dpos,
			ictx->chunkctx->dlen);
	}
	else {
		deep_decompress_and_decode_image(c, d, ictx->f, ictx->chunkctx->dpos,
			ictx->chunkctx->dlen);
	}

done:
	;
}

static void convert_image_rgba(dbuf *f, i64 fpos,
	de_bitmap *img)
{
	i64 i, j;
	de_color clr;
	i64 pos;
	u8 buf[4];

	pos = fpos;
	for(j=0; j<img->height; j++) {
		for(i=0; i<img->width; i++) {
			dbuf_read(f, buf, pos, 4);
			pos += 4;
			clr = DE_MAKE_RGBA(buf[0], buf[1], buf[2], buf[3]);
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}
}

static void do_deep_mpic(deark *c, struct deep_ctx *d, dbuf *f, i64 pos1, i64 len)
{
	i64 w, h, rowspan;
	i64 pos = pos1;
	UI n;
	u8 ok = 0;
	de_bitmap *img = NULL;

	w = de_getu16be_p(&pos);
	rowspan = w*4;
	h = de_getu16be_p(&pos);
	de_dbg(c, "32-bit thumbnail image, dimensions: %u"DE_CHAR_TIMES"%u", (UI)w, (UI)h);

	// I have no documentation for MPIC.
	// I'm guessing that it's always RGBA or RGBx, and doesn't depend on DPEL.
	// I have some images where DBOD has 3 components, and MPIC has 4 components.
	// So I'm guessing that MPIC is *not* defined to be "the same format as DBOD".

	// Not sure what these fields are. First one might be sample count.
	n = (UI)de_getu32be_p(&pos);
	if(n != 0x00040002) goto done;

	if(pos + rowspan*h > pos1+len) goto done;

	img = de_bitmap_create(c, w, h, 4);
	convert_image_rgba(f, pos, img);

	// If the main image doesn't have an alpha channel, we assume the MPIC
	// thumbnail doesn't have transparency.
	if(d->trans_setting==TRANS_REMOVE || (d->found_DPEL && d->have_alpha_hint==0)) {
		de_bitmap_remove_alpha(img);
	}
	else if(d->trans_setting==TRANS_AUTO) {
		de_bitmap_optimize_alpha(img, 0x1);
	}

	de_bitmap_write_to_file(img, "thumb", DE_CREATEFLAG_IS_AUX);
	ok = 1;

done:
	if(!ok) {
		de_warn(c, "Unsupported MPIC thumbnail");
	}
	de_bitmap_destroy(img);
}


static int my_deep_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct deep_ctx *d = (struct deep_ctx*)ictx->userdata;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FORM:
		ictx->is_std_container = 1;
		goto done;
	}

	if(ictx->level != 1) goto done;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_DGBL:
		do_deep_DGBL(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_DLOC:
		do_deep_DLOC(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_DPEL:
		do_deep_DPEL(c, d, ictx);
		ictx->handled = 1;
		break;
	case CODE_DBOD:
		do_deep_DBOD(c, d, ictx);
		d->DBOD_count++;
		ictx->handled = 1;
		break;
	case CODE_TVDC:
		d->found_TVDC = 1;
		dbuf_read(ictx->f, d->tvdc_data, ictx->chunkctx->dpos, sizeof(d->tvdc_data));
		// Don't set ictx->handled, since we don't emit dbg info.
		break;
	case CODE_MPIC:
		do_deep_mpic(c, d, ictx->f, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	case CODE_XS24:
		do_xs24(c, ictx->f, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		ictx->handled = 1;
		break;
	}

done:
	return 1;
}

static void de_run_deep(deark *c, de_module_params *mparams)
{
	struct deep_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *opt_trans_str;

	d = de_malloc(c, sizeof(struct deep_ctx));

	d->trans_setting = TRANS_AUTO; // default
	opt_trans_str = de_get_ext_option(c, "deep:trans");
	if(opt_trans_str) {
		if(!de_strcmp(opt_trans_str, "auto")) {
			d->trans_setting = TRANS_AUTO;
		}
		else if(!de_strcmp(opt_trans_str, "")) {
			d->trans_setting = TRANS_RESPECT;
		}
		else {
			int opt_trans_n;

			opt_trans_n = de_atoi(opt_trans_str);
			if(opt_trans_n==0) {
				d->trans_setting = TRANS_REMOVE;
			}
			else if(opt_trans_n>0) {
				d->trans_setting = TRANS_RESPECT;
			}
		}
	}

	de_declare_fmt(c, "IFF-DEEP");

	ictx = fmtutil_create_iff_decoder(c);
	ictx->has_standard_iff_chunks = 1;
	ictx->alignment = 2;
	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_deep_chunk_handler;
	ictx->f = c->infile;

	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg(c, "image count: %d", d->DBOD_count);

	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		de_free(c, d);
	}
}

static int de_identify_deep(deark *c)
{
	UI n;

	if((UI)de_getu32be(0)!=CODE_FORM) return 0;
	n = (UI)de_getu32be(8);
	if(n==CODE_DEEP || n==CODE_TVPP) return 100;
	return 0;
}

static void de_help_deep(deark *c)
{
	de_msg(c, "-opt deep:trans=<0|1|auto> : Always remove (0) or respect (1) "
		"transparency");
}

void de_module_deep(deark *c, struct deark_module_info *mi)
{
	mi->id = "deep";
	mi->desc = "IFF-DEEP";
	mi->run_fn = de_run_deep;
	mi->identify_fn = de_identify_deep;
	mi->help_fn = de_help_deep;
}
