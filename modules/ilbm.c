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
#define CODE_SBDY 0x53424459U
#define CODE_SHAM 0x5348414dU
#define CODE_TINY 0x54494e59U
#define CODE_VDAT 0x56444154U

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
	int is_pbm; // frame buffer is PBM pixel format
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

typedef struct localctx_struct {
	int is_anim;
	u32 formtype;
	i64 main_chunk_endpos;
	int FORM_level; // nesting level of the frames' FORM chunks
	int errflag;
	int num_frames_started;
	int num_frames_finished;
	int debug_frame_buffer;
	u8 opt_notrans;
	u8 opt_fixpal;
	u8 opt_allowsham;
	u8 opt_anim_includedups;
	u8 found_bmhd;
	u8 found_cmap;
	u8 cmap_changed_flag;
	u8 bmhd_changed_flag;
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
			"(\"-opt ilbm:allowsham\" to decode anyway)");
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

	for(col=0; col<num_columns; col++) {
		i64 opcount;
		i64 opidx;
		i64 elem_bytes_to_write;
		i64 ypos = 0;
		i64 col_start_dstpos;

		if(pos>=endpos) {
			baddata_flag = 1;
			goto done;
		}

		// Defend against writing beyond the right edge of this plane
		if((dataelem_size==4) && (col+1 == num_columns) && (ibi->bytes_per_row_per_plane%4)) {
			elem_bytes_to_write = 2;
		}
		else {
			elem_bytes_to_write = dataelem_size;
		}

		col_start_dstpos = plane_idx * ibi->bytes_per_row_per_plane + dataelem_size*col;

		opcount = get_elem_as_int_p(inf, &pos, code_size);
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
			op = (UI)get_elem_as_int_p(inf, &pos, code_size);

			if(op==0) { // RLE
				count = get_elem_as_int_p(inf, &pos, code_size);
				if(ypos+count > ibi->height) {
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
					dbuf_read(inf, valbuf, datapos, dataelem_size);
					datapos += dataelem_size;
				}
				else {
					dbuf_read(inf, valbuf, pos, dataelem_size);
					pos += dataelem_size;
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
			else if(op < unc_threshold) { // skip
				ypos += (i64)op;
			}
			else { // uncompressed run
				count = (i64)(op - unc_threshold);
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
						dbuf_read(inf, valbuf, datapos, dataelem_size);
						datapos += dataelem_size;
					}
					else {
						dbuf_read(inf, valbuf, pos, dataelem_size);
						pos += dataelem_size;
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
			de_warn(c, "Bad or unsupported ANIM-J compression code (%u)", code);
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
	if(d->bmhd_changed_flag) {
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


	if(d->opt_fixpal && !d->is_anim && d->cmap_changed_flag) {
		fixup_palette(c, d);
	}

	if(d->cmap_changed_flag) {
		d->pal_is_grayscale = de_is_grayscale_palette(d->pal, 256);
	}

	d->cmap_changed_flag = 0;
	d->bmhd_changed_flag = 0;
}

static int init_imgbody_info(deark *c, lctx *d, struct imgbody_info *ibi, int is_thumb)
{
	int retval = 0;

	ibi->is_thumb = is_thumb;

	// Unlike ACBM, it would be messy and slow to convert PBM to the standard ILBM
	// frame buffer format (and back). So we support a special frame buffer format
	// just for PBM.
	ibi->is_pbm = (d->formtype==CODE_PBM);

	if(is_thumb) {
		ibi->width = d->thumb_width;
		ibi->height = d->thumb_height;
	}
	else {
		ibi->width = d->width;
		ibi->height = d->height;
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

	if(ibi->is_pbm) {
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
		if(!d->opt_notrans && ibi->planes_fg<=8 && !d->ham_flag) {
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
		de_err(c, "Bad or unsupported number of planes (%d)", (int)ibi->planes_fg);
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

static int my_vdat_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	struct vdat_ctx *vdctx = (struct vdat_ctx*)ictx->userdata;

	ictx->handled = 1;
	if(ictx->chunkctx->chunk4cc.id != CODE_VDAT) {
		goto done;
	}

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

	ictx_vdat = de_malloc(c, sizeof(struct de_iffctx));
	ictx_vdat->userdata = (void*)&vdctx;
	ictx_vdat->handle_chunk_fn = my_vdat_chunk_handler;
	ictx_vdat->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx_vdat, pos, len);

	de_free(c, ictx_vdat);
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
	de_warn(c, "This is probably a HAM-E image, which is not supported correctly.");
	d->is_hame = 1;
}

// Detect and warn about DCTV, which we don't support.
static void detect_dctv(deark *c, lctx *d, struct imgbody_info *ibi,
	struct frame_ctx *frctx)
{
	static const u8 sig[31] = {
		0x49, 0x87, 0x28, 0xde, 0x11, 0x0b, 0xef, 0xd2, 0x0c, 0x8e, 0x8b, 0x35, 0x5b, 0x75, 0xec, 0xb8,
		0x29, 0x6b, 0x03, 0xf9, 0x2b, 0xb4, 0x34, 0xee, 0x67, 0x1e, 0x7c, 0x4f, 0x53, 0x63, 0x15 };
	i64 pos;

	// As far as I can tell, in DCTV images, the last plane of the first row is
	// as follows:
	//   <00> <31-byte signature> <00 fill> <31-byte signature> <00>
	// (Sometimes, the last plane of the *second* row is the same.)
	// Unknowns:
	// * Is DCTV possible if there are fewer than 64 bytes per row per plane (i.e. width < 512)?
	// * Can a DCTV image have transparency?
	// * If a DCTV image has a thumbnail image, what format does the thumbnail use?

	if(d->is_dctv) return;
	if(!frctx || !frctx->frame_buffer) return;
	if(ibi->is_thumb) return;
	if(frctx->formtype!=CODE_ILBM && frctx->formtype!=CODE_ACBM) return;
	if(ibi->bytes_per_row_per_plane<64) return;
	pos = d->planes_raw * ibi->bytes_per_row_per_plane - 32;
	if(dbuf_getbyte(frctx->frame_buffer, pos) != sig[0]) return;
	if(dbuf_memcmp(frctx->frame_buffer, pos, sig, 31)) return;
	de_warn(c, "This is probably a DCTV image, which is not supported correctly.");
	d->is_dctv = 1;
}

// BODY/ABIT/TINY
static int do_image_chunk_internal(deark *c, lctx *d, struct frame_ctx *frctx, i64 pos1, i64 len, int is_thumb)
{
	struct imgbody_info *ibi = NULL;
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
	else if(ibi->compression==0) {
		if(!decompress_method0(c, d, pos1, len, frctx->frame_buffer, ibi->frame_buffer_size)) goto done;
	}
	else if(ibi->compression==1) {
		if(!decompress_method1(c, d, pos1, len, frctx->frame_buffer, ibi->frame_buffer_size)) goto done;
	}
	else if(ibi->compression==2) {
		if(!decompress_method2(c, d, ibi, pos1, len, frctx->frame_buffer, ibi->frame_buffer_size)) goto done;
	}
	else {
		de_err(c, "Unsupported compression method (%d)", (int)ibi->compression);
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

	if(d->found_cmap && d->pal_is_grayscale && d->planes_raw<=8 && !d->is_ham6 && !d->is_ham8) {
		bypp = 1;
	}
	else {
		bypp = 3;
	}

	if(ibi->use_colorkey_transparency || ibi->masking_code==MASKINGTYPE_1BITMASK) {
		if(!d->opt_notrans) {
			bypp++;
		}
	}

	img = de_bitmap_create(c, ibi->width, ibi->height, bypp);

	if(ibi->is_pbm) {
		de_convert_image_paletted(frctx->frame_buffer, 0, 8, ibi->frame_buffer_rowspan,
			d->pal, img, 0);
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
		if(ibi->masking_code==MASKINGTYPE_1BITMASK && !d->opt_notrans) {
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
	fi = de_finfo_create(c);
	set_finfo_data(c, d, ibi, fi);
	if(ibi->is_thumb) {
		createflags |= DE_CREATEFLAG_IS_AUX;
	}
	if(!d->is_anim) {
		createflags |= DE_CREATEFLAG_OPT_IMAGE;
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

static int my_iff_chunk_handler(deark *c, struct de_iffctx *ictx)
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
		if(!do_bmhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen)) {
			d->errflag = 1;
			goto done;
		}
		break;

	case CODE_ANHD:
		do_anim_anhd(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CMAP:
		do_cmap(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_CAMG:
		do_camg(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_BODY:
	case CODE_ABIT:
		do_body_or_abit(c, d, ictx, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_DLTA:
		if(ictx->curr_container_contentstype4cc.id != CODE_ILBM) {
			d->errflag = 1;
			goto done;
		}
		do_dlta(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_TINY:
		do_tiny(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;

	case CODE_DPI:
		do_dpi(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	case CODE_GRAB:
		do_grab(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	case CODE_DPAN:
		do_dpan(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	case CODE_CRNG:
		do_crng(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	case CODE_DRNG:
		do_drng(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
		break;
	case CODE_CCRT:
		do_ccrt(c, d, ictx->chunkctx->dpos, ictx->chunkctx->dlen);
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
	de_dbg_indent_restore(c, saved_indent_level);
	return (quitflag) ? 0 : 1;
}

static int my_preprocess_iff_chunk_fn(deark *c, struct de_iffctx *ictx)
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
			on_frame_end(c, d);
		}
		if((ictx->curr_container_contentstype4cc.id == CODE_ILBM) ||
			(ictx->curr_container_contentstype4cc.id == CODE_PBM) ||
			(ictx->curr_container_contentstype4cc.id == CODE_ACBM))
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

static int my_on_container_end_fn(deark *c, struct de_iffctx *ictx)
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

	switch(d->formtype) {
	case CODE_ANIM: summary_append(s, "ANIM"); break;
	case CODE_ILBM: summary_append(s, "ILBM"); break;
	case CODE_PBM:  summary_append(s, "PBM"); break;
	case CODE_ACBM: summary_append(s, "ACBM"); break;
	default: summary_append(s, "???"); break;
	}

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
	if(d->is_ctbl) summary_append(s, "CBTL");
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

static void de_run_ilbm_or_anim(deark *c, de_module_params *mparams)
{
	u32 id;
	lctx *d = NULL;
	struct de_iffctx *ictx = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->opt_fixpal = (u8)de_get_ext_option_bool(c, "ilbm:fixpal", 1);
	if(de_get_ext_option(c, "ilbm:notrans")) {
		d->opt_notrans = 1;
	}
	if(de_get_ext_option(c, "ilbm:allowsham")) {
		d->opt_allowsham = 1;
	}

	id = (u32)de_getu32be(0);
	if(id!=CODE_FORM) {
		de_err(c, "Not an IFF file");
		goto done;
	}
	d->formtype = (u32)de_getu32be(8);
	switch(d->formtype) {
	case CODE_ANIM:
		de_declare_fmt(c, "IFF-ANIM");
		d->is_anim = 1;
		break;
	case CODE_ILBM:
		de_declare_fmt(c, "IFF-ILBM");
		break;
	case CODE_ACBM:
		de_declare_fmt(c, "IFF-ACBM");
		break;
	case CODE_PBM:
		de_declare_fmt(c, "IFF-PBM");
		break;
	default:
		de_err(c, "Not a supported IFF format");
		goto done;
	}

	if(d->is_anim) {
		d->opt_anim_includedups = (u8)de_get_ext_option_bool(c, "anim:includedups", 0);
	}

	d->FORM_level = d->is_anim ? 1 : 0;

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	ictx->userdata = (void*)d;
	ictx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	ictx->handle_chunk_fn = my_iff_chunk_handler;
	ictx->preprocess_chunk_fn = my_preprocess_iff_chunk_fn;
	ictx->on_std_container_start_fn = my_on_std_container_start_fn;
	ictx->on_container_end_fn = my_on_container_end_fn;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, 0, c->infile->len);

	if(d->frctx) {
		on_frame_end(c, d);
	}
	do_eof_stuff(c, d);
	print_summary(c, d);

done:
	de_free(c, ictx);
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
	if(id==CODE_ILBM) return 100;
	if(id==CODE_PBM ) return 100;
	if(id==CODE_ACBM) return 100;
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
	de_msg(c, "-opt ilbm:notrans : Disable support for transparency");
	if(!is_anim) {
		de_msg(c, "-opt ilbm:fixpal=<0|1> : Don't/Do try to fix palettes that are "
			"slightly too dark");
	}
	de_msg(c, "-opt ilbm:allowsham : Suppress an error on some images");
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
