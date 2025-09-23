// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// "MMFW" resource file (mainly the Picture formats)

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mmfw);

#define MMFW_TYPE_FIRST     2
#define MMFW_TYPE_BLOBS     2
#define MMFW_TYPE_PICTURES  3
#define MMFW_TYPE_SOUNDS    4
#define MMFW_TYPE_MOVIES    5
#define MMFW_TYPE_FILMS     6
#define MMFW_TYPE_SCRIPT    7
#define MMFW_TYPE_SCRIPTS   8
#define MMFW_TYPE_3SCRIPT   9
#define MMFW_TYPE_LAST      9

// Wish we could set a sane limit, but files with over 15000 images exist.
#define MMFW_MAX_RESOURCES 65535

#define PICFMT_UNC_PAL8              1
#define PICFMT_UNC_PAL8_LOCAL_PAL    2
#define PICFMT_RGB                   3
#define PICFMT_CMPR1_PAL8            4
#define PICFMT_UNC_8BIT_NO_PAL       5
#define PICFMT_CMPR2                 6
#define PICFMT_CMPR2_LOCAL_PAL       7

static const char *g_picfmt_names[] = { "?",
	"unc pal8", "unc pal8 w/local pal",
	"unc rgb", "cmpr1 pal8", "8bit no pal",
	"cmpr2", "cmpr2 w/local pal" };

struct mmfw_item {
	i64 idx;
	i64 dpos;
	i64 dlen;
	u8 handled;

	u8 pic_flags1;
	u8 pic_flags2;
	// width/height from the index. (Some formats also store it elsewhere.)
	i64 width0, height0;
	UI pal_id;

	de_ucstring *name;
	de_finfo *fi;
	char msgpfx[32];

	// inf_to_use points to c->infile or d->intermedf.
	dbuf *inf_to_use; // This is a copy; do not free.
	i64 inf_dpos;
	i64 inf_dlen;
};

// Collect some fields together, for convenience. We might want
// to clear them and start over.
// A value of 0 generally means the item is not present.
struct mmfw_file_structure_etc {
	i64 pos_of_rsrc_count;
	i64 pos_of_rsrc_offsets_table;
	i64 pos_of_rsrc_names_table;
	i64 pos_of_flags1_table;
	i64 pos_of_flags2_table;
	i64 pos_of_flags3_table;
	i64 pos_of_dimensions_table;
	i64 pos_of_pal_ids_table;
	i64 pos_of_pal_ids16_table;
	i64 pos_of_palette_seg;
	i64 pos_of_1st_palette;
	UI num_palettes;
	u8 can_decode; // Flag: We can decode, beyond extracting the raw data?
};

typedef struct localctxMMFW {
	deark *c;
	int is_le;
	de_encoding input_encoding;
	u8 extract_all;
	u8 extract_all_raw;
	UI fmtver;
	u8 mmfw_type;
	u8 is_a_script_type;
	const char *mmfw_type_name;
	u8 need_errmsg;
	u8 fatal_errflag;

	struct mmfw_file_structure_etc fs;
	i64 num_resources;
	i64 num_offsets_in_table;
	u32 *rsrc_offsets; // array[num_offsets_in_table]

	dbuf *item_rowbuf;
	dbuf *item_unc_image;
	dbuf *intermedf;
	u8 have_pal;
	UI pal_id;
	de_color pal[256];
} lctx;

static i64 mmfw_dbuf_getu16(lctx *d, dbuf *f, i64 pos)
{
	return dbuf_getu16x(f, pos, d->is_le);
}

static i64 mmfw_dbuf_getu16_p(lctx *d, dbuf *f, i64 *ppos)
{
	i64 n;

	n = mmfw_dbuf_getu16(d, f, *ppos);
	*ppos += 2;
	return n;
}

static i64 mmfw_getu16(lctx *d, i64 pos)
{
	return mmfw_dbuf_getu16(d, d->c->infile, pos);
}

static i64 mmfw_getu16_p(lctx *d, i64 *ppos)
{
	return mmfw_dbuf_getu16_p(d, d->c->infile, ppos);
}

static i64 mmfw_dbuf_getu32(lctx *d, dbuf *f, i64 pos)
{
	return dbuf_getu32x(f, pos, d->is_le);
}

static i64 mmfw_dbuf_getu32_p(lctx *d, dbuf *f, i64 *ppos)
{
	i64 n;

	n = mmfw_dbuf_getu32(d, f, *ppos);
	*ppos += 4;
	return n;
}

static i64 mmfw_getu32(lctx *d, i64 pos)
{
	return mmfw_dbuf_getu32(d, d->c->infile, pos);
}

static i64 mmfw_getu32_p(lctx *d, i64 *ppos)
{
	return mmfw_dbuf_getu32_p(d, d->c->infile, ppos);
}

static const char *g_mmfw_tnames[] = {
	"Blobs", "Pictures", "Sounds", "Movies",
	"Films", "Script", "Scripts", "3 Script"
};

static const u8 *mmfw_type_to_signature(u8 t)
{
	if(t>=MMFW_TYPE_FIRST && t<=MMFW_TYPE_LAST) {
		return (const u8*)g_mmfw_tnames[t-MMFW_TYPE_FIRST];
	}
	return (const u8*)"?";
}

static const char *get_mmfw_type_readable_name(u8 t)
{
	if(t==MMFW_TYPE_SCRIPT || t==MMFW_TYPE_SCRIPTS ||
		t==MMFW_TYPE_3SCRIPT)
	{
		return g_mmfw_tnames[MMFW_TYPE_SCRIPTS-MMFW_TYPE_FIRST];
	}
	if(t>=MMFW_TYPE_FIRST && t<=MMFW_TYPE_LAST) {
		return g_mmfw_tnames[t-MMFW_TYPE_FIRST];
	}
	return "data";
}

// Decompresses to md->intermedf
static int try_decompress_lzss(deark *c, lctx *d, struct mmfw_item *md)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int retval = 0;

	if(!d->intermedf) {
		d->intermedf = dbuf_create_membuf(c, 0, 0);
		dbuf_set_length_limit(d->intermedf, 10*1048576);
		dbuf_enable_wbuffer(d->intermedf);
	}
	dbuf_empty(d->intermedf);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	dcmpri.f = c->infile;
	dcmpri.pos = md->dpos;
	dcmpri.len = md->dlen;
	dcmpro.f = d->intermedf;
	dcmpro.len_known = 0;
	fmtutil_lzssmmfw_codectype1(c, &dcmpri, &dcmpro, &dres, NULL);
	dbuf_flush(d->intermedf);
	if(!dres.errcode) {
		de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", md->dlen,
			d->intermedf->len);
		retval = 1;
	}

	return retval;
}

// Returns 0 on failure
static int cmpr1_decompress_bytes(deark *c, lctx *d,
	dbuf *inf, i64 ipos1, i64 ilen,
	i64 max_olen, dbuf *outf)
{
	i64 ipos = ipos1;
	i64 iendpos = ipos1+ilen;
	i64 nbytes_written = 0;
	u8 errflag = 0;

	while(1) {
		u8 b0;
		u8 b1;
		i64 count;

		if(nbytes_written > max_olen) goto done;
		if(ipos >= iendpos) goto done;

		b0 = dbuf_getbyte_p(inf, &ipos);
		if(b0<=0x7f) {
			b1 = dbuf_getbyte_p(inf, &ipos);
			count = (i64)b0 + 1;
			dbuf_write_run(outf, b1, count);
			nbytes_written += count;
		}
		else if(b0>=0x80 && b0<=0xfe) {
			count = (i64)b0 - 126;
			dbuf_copy(inf, ipos, count, outf);
			ipos += count;
			nbytes_written += count;
		}
		else {
			// Opcode 0xff is unknown or unused.
			errflag = 1;
			goto done;
		}
	}

done:
	return errflag ? 0 : 1;
}

static void create_item_fi(deark *c, lctx *d, struct mmfw_item *md)
{
	if(!md->fi) {
		md->fi = de_finfo_create(c);
	}

	if(c->filenames_from_file && ucstring_isnonempty(md->name)) {
		de_finfo_set_name_from_ucstring(c, md->fi, md->name, 0);
	}
}

static void mmfw_load_local_palette(deark *c, lctx *d, dbuf *inf, i64 pos1)
{
	de_read_simple_palette(c, inf, pos1+1, 256, 4,
		d->pal, 256, DE_RDPALTYPE_24BIT, 0);
	d->have_pal = 0;
	d->pal_id = 0;
}

// Loads palette md->pal_id, or reports an error and returns 0
static int mmfw_load_palette(deark *c, lctx *d, struct mmfw_item *md)
{
	i64 pos;

	if(d->have_pal && d->pal_id==md->pal_id) return 1;

	if(md->pal_id >= d->fs.num_palettes) {
		de_err(c, "%sInvalid palette: %u", md->msgpfx, md->pal_id);
		return 0;
	}

	pos = d->fs.pos_of_1st_palette + 1024*(i64)md->pal_id;
	de_read_simple_palette(c, c->infile, pos+1, 256, 4,
		d->pal, 256, DE_RDPALTYPE_24BIT, 0);

	d->have_pal = 1;
	d->pal_id = md->pal_id;
	return 1;
}

static void decode_pic_raw_unc_pal8(deark *c, lctx *d, struct mmfw_item *md,
	UI picfmt)
{
	i64 rowspan;
	i64 w, h;
	i64 local_pal_len = 0;
	de_bitmap *img = NULL;

	w = md->width0;
	h = md->height0;

	if(!de_good_image_dimensions(c, w, h)) goto done;
	create_item_fi(c, d, md);

	rowspan = de_pad_to_4(w);

	if(picfmt==PICFMT_UNC_PAL8_LOCAL_PAL) {
		local_pal_len = 1024;
		mmfw_load_local_palette(c, d, md->inf_to_use, md->inf_dpos);
	}
	else if(picfmt==PICFMT_UNC_8BIT_NO_PAL) {
		// This is likely wrong, but I haven't found any images that
		// look wrong.
		de_make_grayscale_palette(d->pal, 256, 0x1);
		d->have_pal = 0;
	}
	else {
		if(!mmfw_load_palette(c, d, md)) goto done;
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(md->inf_to_use, md->inf_dpos+local_pal_len, 8, rowspan,
		d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, md->fi, DE_CREATEFLAG_OPT_IMAGE);
	md->handled = 1;

done:
	de_bitmap_destroy(img);
}

static void decode_pic_raw_unc_rgb32(deark *c, lctx *d, struct mmfw_item *md)
{
	i64 rowspan;
	i64 w, h;
	de_bitmap *img = NULL;

	w = md->width0;
	h = md->height0;

	if(!de_good_image_dimensions(c, w, h)) goto done;
	create_item_fi(c, d, md);

	rowspan = w*4;
	if(rowspan*h != md->inf_dlen) {
		de_err(c, "%sFailed to decode picture", md->msgpfx);
		goto done;
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_rgb(md->inf_to_use, md->inf_dpos+1, rowspan, 4, img, 0);

	de_bitmap_write_to_file_finfo(img, md->fi, DE_CREATEFLAG_OPT_IMAGE);
	md->handled = 1;

done:
	de_bitmap_destroy(img);
}

static void decode_pic_cmpr1_pal(deark *c, lctx *d, struct mmfw_item *md)
{
	i64 *rowoffsets = NULL;
	i64 *rowlengths = NULL;
	de_bitmap *img = NULL;
	i64 w1, h1;
	i64 w, h;
	i64 pos;
	i64 j;

	pos = md->inf_dpos;
	w1 = mmfw_dbuf_getu16_p(d, md->inf_to_use, &pos);
	h1 = mmfw_dbuf_getu16_p(d, md->inf_to_use, &pos);
	de_dbg(c, "dimensions (internal): %"I64_FMT DE_CHAR_TIMES "%"I64_FMT, w1, h1);
	w = w1;
	h = h1;

	if(!de_good_image_dimensions(c, w, h)) goto done;

	create_item_fi(c, d, md);

	if(!mmfw_load_palette(c, d, md)) goto done;

	rowoffsets = de_mallocarray(c, h, sizeof(i64));
	rowlengths = de_mallocarray(c, h, sizeof(i64));

	pos = md->inf_dpos + 8;
	for(j=0; j<h; j++) {
		rowoffsets[j] = mmfw_dbuf_getu32_p(d, md->inf_to_use, &pos);
	}
	de_dbg(c, "after row table: %"I64_FMT, pos);

	for(j=0; j<h; j++) {
		if(j<(h-1)) {
			rowlengths[j] = rowoffsets[j+1] - rowoffsets[j];
		}
		else {
			rowlengths[j] = md->dlen - rowoffsets[j];
		}
	}

	if(c->debug_level>=3) {
		for(j=0; j<h; j++) {
			de_dbg(c, "offs[%d]: %"I64_FMT" (%"I64_FMT") len=%"I64_FMT,
				(int)j, rowoffsets[j], (i64)(md->inf_dpos+rowoffsets[j]),
				rowlengths[j]);
		}
	}

	if(!d->item_rowbuf) {
		d->item_rowbuf = dbuf_create_membuf(c, 0, 0);
	}
	if(!d->item_unc_image) {
		d->item_unc_image = dbuf_create_membuf(c, 65535, 0);
	}
	dbuf_empty(d->item_unc_image);

	img = de_bitmap_create(c, w, h, 3);
	for(j=0; j<h; j++) {
		int ret;

		pos = md->inf_dpos+rowoffsets[j];

		// Decompress one row
		dbuf_empty(d->item_rowbuf);
		ret = cmpr1_decompress_bytes(c, d, md->inf_to_use, pos, rowlengths[j], w, d->item_rowbuf);
		if(!ret) {
			de_err(c, "%sDecompression failed", md->msgpfx);
			de_dbg(c, "row %d, %d bytes", (int)j, (int)d->item_rowbuf->len);
			goto done;
		}

		// Append decompressed row to the decompressed image bytes
		dbuf_copy(d->item_rowbuf, 0, w, d->item_unc_image);
	}

	de_convert_image_paletted(d->item_unc_image, 0, 8, w, d->pal, img, 0);

	de_bitmap_write_to_file_finfo(img, md->fi, DE_CREATEFLAG_OPT_IMAGE);
	md->handled = 1;

done:
	de_bitmap_destroy(img);
	de_free(c, rowoffsets);
	de_free(c, rowlengths);
}

// A very crude picture-type detector routine.
// (I think there's a right way to do it, but I haven't figured it out.)
static UI detect_picfmt(deark *c, lctx *d, struct mmfw_item *md,
	dbuf *inf, i64 dpos, i64 dlen)
{
	i64 w1, h1;
	i64 n;
	i64 imgsize_if_pal8;

	if(!d->fs.can_decode) return 0;

	imgsize_if_pal8 = de_pad_to_4(md->width0) * md->height0;

	if(dlen == 1024+imgsize_if_pal8) {
		if(md->pal_id >= d->fs.num_palettes) {
			return PICFMT_UNC_PAL8_LOCAL_PAL;
		}
	}

	// These maybe-dimensions fields help us guess the format.
	w1 = mmfw_dbuf_getu16(d, inf, dpos);
	h1 = mmfw_dbuf_getu16(d, inf, dpos+2);

	if(w1==md->width0 && h1==md->height0) {
		// Test the first row pointer. We expect it to equal the header
		// size (8) + the size of the row pointer table (4 bytes for each
		// row).
		n = mmfw_dbuf_getu32(d, inf, dpos+8);
		if(n == 8 + 4*md->height0) {
			return PICFMT_CMPR1_PAL8;
		}
	}

	if(dlen == imgsize_if_pal8) {
		if(md->pal_id < d->fs.num_palettes) {
			return PICFMT_UNC_PAL8;
		}
		else {
			return PICFMT_UNC_8BIT_NO_PAL;
		}
	}

	if(dlen == md->width0*md->height0*4) {
		return PICFMT_RGB;
	}

	n = mmfw_dbuf_getu16(d, inf, dpos);
	if(n == 4*md->height0 + 2) {
		return PICFMT_CMPR2;
	}

	n = mmfw_dbuf_getu16(d, inf, dpos+1024);
	if(n == 4*md->height0 + 2) {
		return PICFMT_CMPR2_LOCAL_PAL;
	}

	return 0;
}

// Try to figure out the picture format, and call the right decoder.
static void do_pic_internal(deark *c, lctx *d, struct mmfw_item *md)
{
	UI picfmt = 0;
	u8 lzss_layer = 0;

	if(!d->fs.can_decode) {
		goto done;
	}

	if(d->fs.pos_of_flags3_table) {
		md->pic_flags1 = de_getbyte(d->fs.pos_of_flags3_table+md->idx*2);
		md->pic_flags2 = de_getbyte(d->fs.pos_of_flags3_table+md->idx*2+1);
	}
	else {
		md->pic_flags1 = de_getbyte(d->fs.pos_of_flags1_table+md->idx);
		if(d->fs.pos_of_flags2_table) {
			md->pic_flags2 = de_getbyte(d->fs.pos_of_flags2_table+md->idx);
		}
	}

	de_dbg(c, "pic flags1: 0x%02x", (UI)md->pic_flags1);
	de_dbg(c, "pic flags2: 0x%02x", (UI)md->pic_flags2);

	md->height0 = mmfw_getu16(d, d->fs.pos_of_dimensions_table + 4*md->idx);
	md->width0 = mmfw_getu16(d, d->fs.pos_of_dimensions_table + 4*md->idx+2);
	de_dbg(c, "dimensions (from index): %"I64_FMT DE_CHAR_TIMES "%"I64_FMT,
		md->width0, md->height0);

	if(d->fs.pos_of_pal_ids16_table) {
		md->pal_id = (UI)mmfw_getu16(d, d->fs.pos_of_pal_ids16_table+md->idx*2);
	}
	else {
		md->pal_id = (UI)de_getbyte(d->fs.pos_of_pal_ids_table+md->idx);
	}
	de_dbg(c, "pal id: %u", (UI)md->pal_id);

	md->inf_to_use = c->infile;
	md->inf_dpos = md->dpos;
	md->inf_dlen = md->dlen;
	picfmt = detect_picfmt(c, d, md, c->infile, md->dpos, md->dlen);
	if(picfmt==0) {
		int ret;

		de_dbg(c, "[picfmt not detected, trying lzss decompression]");
		// TODO: This is an expensive test. We should try to screen out more files
		// before doing this.
		ret = try_decompress_lzss(c, d, md);
		if(ret && d->intermedf) {
			if(c->debug_level>=2) {
				i64 hlen;

				hlen = de_min_int(d->intermedf->len, 48);
				de_dbg_hexdump(c, d->intermedf, 0, hlen, hlen, "udata", 0x0);
			}
			de_dbg(c, "[redetecting picfmt]");
			picfmt = detect_picfmt(c, d, md, d->intermedf, 0, d->intermedf->len);
			if(picfmt) {
				lzss_layer = 1;
				md->inf_to_use = d->intermedf;
				md->inf_dpos = 0;
				md->inf_dlen = d->intermedf->len;
			}
		}
	}

	de_dbg(c, "detected pic format: %s%s", (lzss_layer?"LZSS + ":""), g_picfmt_names[picfmt]);

	switch(picfmt) {
	case PICFMT_UNC_PAL8:
	case PICFMT_UNC_PAL8_LOCAL_PAL:
	case PICFMT_UNC_8BIT_NO_PAL:
		decode_pic_raw_unc_pal8(c, d, md, picfmt);
		break;
	case PICFMT_RGB:
		decode_pic_raw_unc_rgb32(c, d, md);
		break;
	case PICFMT_CMPR1_PAL8:
		decode_pic_cmpr1_pal(c, d, md);
		break;
	default:
		// TODO: Other picture/compression formats exist.
		// - There's a compressed format that starts with a table of
		//   {height*2+1} 2-byte row(?) pointers. (Guess it could be a
		//   foreground image, then an alpha channel.)
		// - Same as above, but with a local palette.
		// - There's a compressed format that usually (not always) starts
		//   with 15 ff 00 00 00.
		// - ...
		if(d->extract_all) {
			de_warn(c, "%sUunsupported picture format", md->msgpfx);
		}
		else {
			de_err(c, "%sUnknown or unsupported picture format (flags=0x%02x 0x%02x)",
				md->msgpfx, (UI)md->pic_flags1, (UI)md->pic_flags2);
		}
		goto done;
	}

done:
	;
}

static void extract_raw_resource(deark *c, lctx *d, struct mmfw_item *md)
{
	dbuf *outf = NULL;

	create_item_fi(c, d, md);
	md->fi->original_filename_flag = 1;
	outf = dbuf_create_output_file(c, NULL, md->fi, 0);
	md->handled = 1;
	dbuf_copy(c->infile, md->dpos, md->dlen, outf);
	dbuf_close(outf);
}

static void do_one_resource(deark *c, lctx *d, i64 idx)
{
	struct mmfw_item *md = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "resource[%"I64_FMT"]", idx);
	de_dbg_indent(c, 1);

	md = de_malloc(c, sizeof(struct mmfw_item));
	md->idx = idx;
	de_snprintf(md->msgpfx, sizeof(md->msgpfx), "[resource %"I64_FMT"] ", md->idx);
	md->dpos = (i64)d->rsrc_offsets[idx];
	md->dlen = (i64)(d->rsrc_offsets[idx+1] - d->rsrc_offsets[idx]);
	de_dbg(c, "dpos: %"I64_FMT, md->dpos);
	de_dbg(c, "dlen: %"I64_FMT, md->dlen);
	if(md->dpos + md->dlen > c->infile->len) {
		de_err(c, "%sItem goes beyond end of file", md->msgpfx);
		d->fatal_errflag = 1;
		goto done;
	}

	md->name = ucstring_create(c);

	if(d->fs.pos_of_rsrc_names_table) {
		i64 npos;

		npos = d->fs.pos_of_rsrc_names_table + 32*idx;
		de_dbg(c, "name record pos: %"I64_FMT, npos);
		dbuf_read_to_ucstring(c->infile, npos, 32, md->name, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->name));
	}

	if(c->debug_level>=2) {
		i64 hlen;

		hlen = de_min_int(md->dlen, 48);
		de_dbg_hexdump(c, c->infile, md->dpos, hlen, hlen, NULL, 0x0);
	}

	if(md->dlen<1) {
		;
	}
	else if(d->extract_all_raw) {
		extract_raw_resource(c, d, md);
	}
	if(!md->handled && d->fs.can_decode && d->mmfw_type==MMFW_TYPE_PICTURES) {
		do_pic_internal(c, d, md);
	}
	if(!md->handled && d->extract_all) {
		extract_raw_resource(c, d, md);
	}

done:
	if(md) {
		ucstring_destroy(md->name);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// Read the offsets table, and check some things to try to tell if
// we've gone off the rails.
// Call after setting:
//   d->fs.num_resources
//   d->fs.pos_of_rsrc_offsets_table.
// Sets d->num_offsets_in_table.
// (Re)allocates d->rsrc_offsets.
// Returns 0 if table seems invalid.
// Does not report errors (because we may want to try again).
// May tolerate truncated files.
static int read_offsets_tbl(deark *c, lctx *d)
{
	i64 i;
	i64 pos;
	i64 offsets_table_endpos;
	int retval = 0;

	if(d->rsrc_offsets) {
		de_free(c, d->rsrc_offsets);
		d->num_offsets_in_table = 0;
	}

	if(d->num_resources>MMFW_MAX_RESOURCES) {
		goto done;
	}
	if(d->num_resources<1) goto done;

	d->num_offsets_in_table = d->num_resources+1;
	d->rsrc_offsets = de_mallocarray(c, d->num_offsets_in_table, sizeof(u32));

	pos = d->fs.pos_of_rsrc_offsets_table;
	offsets_table_endpos = d->fs.pos_of_rsrc_offsets_table + 4*d->num_offsets_in_table;

	for(i=0; i<d->num_offsets_in_table; i++) {
		d->rsrc_offsets[i] = (u32)mmfw_getu32_p(d, &pos);
	}

	if((i64)d->rsrc_offsets[0] < offsets_table_endpos) {
		goto done;
	}

	// Check some things
	for(i=0; i<d->num_resources; i++) {
		i64 rlen;

		rlen = (i64)d->rsrc_offsets[i+1] - (i64)d->rsrc_offsets[i];
		if(rlen<0) {
			goto done;
		}
	}

	retval = 1;

done:
	return retval;
}

static void mmfw_dbg_file_structure(deark *c, lctx *d)
{
	struct mmfw_file_structure_etc *ly = &d->fs;

	de_dbg(c, "pos of rsrc count: %"I64_FMT, ly->pos_of_rsrc_count);
	de_dbg(c, "num resources: %"I64_FMT, d->num_resources);
	de_dbg(c, "offsets table pos: %"I64_FMT, ly->pos_of_rsrc_offsets_table);
	de_dbg(c, "names table pos: %"I64_FMT, ly->pos_of_rsrc_names_table);
	if(d->fs.can_decode) {
		de_dbg(c, "dimensions table at %"I64_FMT, ly->pos_of_dimensions_table);
		if(ly->pos_of_flags1_table) {
			de_dbg(c, "flags1 table at %"I64_FMT, ly->pos_of_flags1_table);
		}
		if(ly->pos_of_flags2_table) {
			de_dbg(c, "flags2 table at %"I64_FMT, ly->pos_of_flags2_table);
		}
		if(ly->pos_of_flags3_table) {
			de_dbg(c, "flags3 table at %"I64_FMT, ly->pos_of_flags3_table);
		}
		de_dbg(c, "pal IDs table at %"I64_FMT,
			(ly->pos_of_pal_ids16_table ? ly->pos_of_pal_ids16_table :
			d->fs.pos_of_pal_ids_table));
		de_dbg(c, "palettes segment at %"I64_FMT, d->fs.pos_of_palette_seg);
		de_dbg(c, "num palettes: %u", d->fs.num_palettes);
	}
}

// (Inventing a "format descriptor" seems like a lot of trouble to go to,
// but MMFW format is so quirky that it's the best way.)
// dscrp format descriptor string:
//  c = 2-byte resource count
//  o = offsets table
//  n = names table
//  d = dimensions (array of 4-byte items)
//  b[digit] = 1-9 undecoded bytes
//  a[digit] = undecoded array, 1-9 bytes/item
//  f = flags1 (array of 1-byte items)
//  g = flags2 (array of 1-byte items)
//  h = flags3 (array of 2-byte items)
//  p = palette IDs (array of 1-byte items)
//  q = palette IDs (.. 2-byte items) [wild guess -- there might be no such thing]
//  P = palette segment: 2-byte 'count', then 'count' 1024-byte palettes
//  . = data segment expected here
//  ' ' = ignored
static int mmfw_try_format(deark *c, lctx *d, i64 startpos,
	const char *dscrp)
{
	i64 pos = startpos;
	const char *p;
	int retval = 0;
	i64 count;
	i64 first_offset = 0;

	de_zeromem(&d->fs, sizeof(struct mmfw_file_structure_etc));
	if(d->rsrc_offsets) {
		de_free(c, d->rsrc_offsets);
		d->rsrc_offsets = NULL;
	}
	d->num_resources = 0;

	if(startpos==0) goto done;

	p = &dscrp[0];
	while(*p) {
		switch(*p) {
		case ' ':
			break;
		case '.': // data segment
			if(pos==first_offset) {
				d->fs.can_decode = 1;
			}
			break;
		case 'a': // undecoded array
			p++;
			count = (*p)-'0';
			pos += d->num_resources * count;
			break;
		case 'b': // undecoded bytes
			p++;
			count = (*p)-'0';
			pos += count;
			break;
		case 'd':
			d->fs.pos_of_dimensions_table = pos;
			pos += d->num_resources*4;
			break;
		case 'c':
			d->fs.pos_of_rsrc_count = pos;
			d->num_resources = mmfw_getu16_p(d, &pos);
			if(d->num_resources<1) goto done;
			break;
		case 'f':
			d->fs.pos_of_flags1_table = pos;
			pos += d->num_resources;
			break;
		case 'g':
			d->fs.pos_of_flags2_table = pos;
			pos += d->num_resources;
			break;
		case 'h':
			d->fs.pos_of_flags3_table = pos;
			pos += d->num_resources*2;
			break;
		case 'o':
			d->fs.pos_of_rsrc_offsets_table = pos;
			first_offset = mmfw_getu32(d, pos);
			pos += 4*(d->num_resources+1);
			break;
		case 'n':
			d->fs.pos_of_rsrc_names_table = pos;
			pos += 32*d->num_resources;
			break;
		case 'p': // palette IDs
			d->fs.pos_of_pal_ids_table = pos;
			pos += d->num_resources;
			break;
		case 'q': // palette IDs (2 byte??)
			d->fs.pos_of_pal_ids16_table = pos;
			pos += d->num_resources*2;
			break;
		case 'P':
			d->fs.pos_of_palette_seg = pos;
			d->fs.num_palettes = (UI)mmfw_getu16_p(d, &pos);
			d->fs.pos_of_1st_palette = pos;
			pos += d->fs.num_palettes*1024;
			break;
		default:
			de_internal_err_nonfatal(c, "Bad code (%c)", (int)(*p));
			d->fatal_errflag = 1;
			goto done;
		}

		p++;
	}

	if(!read_offsets_tbl(c, d)) {
		goto done;
	}

	retval = 1;

done:
	return retval;
}

static void do_mmfw_part1(deark *c, lctx *d)
{
	int ret = 0;
	const char *dscrp_v0_pic = "codhna4a4qP.";
	const char *dscrp_v1_pic = "cob2na4b2fgda4pP.";
	const char *dscrp_v2_26_pic = "cona4hda4qP.";
	const char *dscrp_v2_26_script = "cb2o";
	const char *dscrp_v3_26_pic = "cona4fda4pP.";
	const char *dscrp_v1_default = "cob2n";
	const char *dscrp_26_default = "con";
	const char *dscrp_nonames = "co";
	i64 rcpos = 0;

	if(d->fmtver==0) {
		rcpos = 102;
	}
	else if(d->fmtver==1) {
		rcpos = 30;
	}
	else {
		u8 b;

		// I don't know how to tell whether this field is at offset 26,
		// or 34. Testing the byte at offset 21 works for the files I've
		// tested (at least the big-endian ones?).
		b = de_getbyte(21);
		if(b==0) {
			rcpos = 26;
		}
		else {
			rcpos = 34;
		}
	}

	if(d->mmfw_type==MMFW_TYPE_PICTURES) {
		if(d->fmtver==0) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v0_pic);
		}
		else if(d->fmtver==1) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v1_pic);
		}
		else if(d->fmtver==2 && rcpos==26) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v2_26_pic);
		}
		else if(d->fmtver==2 && rcpos==34) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v1_pic);
		}
		else if(d->fmtver==3 && rcpos==26) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v3_26_pic);
		}
		else if(d->fmtver==3 && rcpos==34) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v1_pic);
		}
	}
	else if(d->mmfw_type==MMFW_TYPE_SCRIPT) {
		if(d->fmtver==1 && !d->is_le) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_nonames);
		}
		else if(d->fmtver==1 && d->is_le) {
			rcpos = 26;
			ret = mmfw_try_format(c, d, rcpos, dscrp_v2_26_script);
		}
		else if(d->fmtver==2 && rcpos==26) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v2_26_script);
		}
	}
	else if(d->mmfw_type==MMFW_TYPE_3SCRIPT) {
		if(d->fmtver==2 && d->is_le) {
			rcpos = 34;
			ret = mmfw_try_format(c, d, rcpos, dscrp_nonames);
		}
	}
	else if(d->mmfw_type==MMFW_TYPE_SCRIPTS) {
		if(d->fmtver==3 && d->is_le) {
			rcpos = 34;
			ret = mmfw_try_format(c, d, rcpos, dscrp_nonames);
		}
		else if(d->fmtver==3 && rcpos==34) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_nonames);
		}
	}
	else if(d->fmtver>=1 && !d->is_a_script_type) {
		if(rcpos==26) {
			ret = mmfw_try_format(c, d, rcpos, dscrp_26_default);
		}
		else {
			ret = mmfw_try_format(c, d, rcpos, dscrp_v1_default);
		}
	}

	if(!ret) {
		d->fatal_errflag = 1;
		d->need_errmsg = 1;
		goto done;
	}

	mmfw_dbg_file_structure(c, d);

done:
	;
}

static u8 mmfw_detect_type(deark *c)
{
	u8 buf[11];
	u8 t;
	UI en;

	if(dbuf_memcmp(c->infile, 0, (const void*)"MMFW ", 5)) {
		return 0;
	}
	en = (UI)de_getu16be(16);
	if(en!=0x4d4d && en!=0x4949) {
		return 0;
	}

	de_read(buf, 5, sizeof(buf));

	for(t=MMFW_TYPE_FIRST; t<=MMFW_TYPE_LAST; t++) {
		const u8 *sig;

		// The only little-endian files I've seen are script files.
		if(en==0x4949 && (t!=MMFW_TYPE_SCRIPT && t!=MMFW_TYPE_SCRIPTS &&
			t!=MMFW_TYPE_3SCRIPT))
		{
			continue;
		}
		sig = mmfw_type_to_signature(t);
		if(!de_memcmp(sig, buf, (size_t)(1+de_strlen((const char*)sig)))) {
			return t;
		}
	}
	return 0;
}

static void de_run_mmfw(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 i;

	d = de_malloc(c, sizeof(lctx));
	d->c = c;

	d->extract_all_raw = (u8)de_get_ext_option_bool(c, "mmfw:extractallraw", 0);
	if(!d->extract_all_raw) {
		d->extract_all = (u8)de_get_ext_option_bool(c, "mmfw:extractall",
			((c->extract_level>=2) ? 1 : 0));
	}
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	d->mmfw_type = mmfw_detect_type(c);
	if(!d->mmfw_type) {
		d->need_errmsg = 1;
		goto done;
	}

	if(d->mmfw_type==MMFW_TYPE_SCRIPT || d->mmfw_type==MMFW_TYPE_SCRIPTS ||
		d->mmfw_type==MMFW_TYPE_3SCRIPT)
	{
		d->is_a_script_type = 1;
	}
	d->mmfw_type_name = get_mmfw_type_readable_name(d->mmfw_type);
	de_declare_fmtf(c, "MMFW resource file (%s)", d->mmfw_type_name);

	d->is_le = (de_getbyte(16)=='I');
	de_dbg(c, "endian: %s", (d->is_le ? "le" : "be"));

	d->fmtver = (UI)mmfw_getu16(d, 18);
	de_dbg(c, "fmt ver: %u", d->fmtver);
	if(d->fmtver>3) {
		de_err(c, "Unsupported format version: %u", d->fmtver);
		goto done;
	}

	do_mmfw_part1(c, d);
	if(d->fatal_errflag) goto done;

	for(i=0; i<d->num_resources; i++) {
		do_one_resource(c, d, i);
		if(d->fatal_errflag) goto done;
	}

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported MMFW file");
		}
		de_free(c, d->rsrc_offsets);
		dbuf_close(d->item_rowbuf);
		dbuf_close(d->item_unc_image);
		dbuf_close(d->intermedf);
		de_free(c, d);
	}
}

static int de_identify_mmfw(deark *c)
{
	u8 t;

	t = mmfw_detect_type(c);
	return t?100:0;
}

static void de_help_mmfw(deark *c)
{
	de_msg(c, "-opt mmfw:extractall : Also extract undecoded resources, in raw form");
	de_msg(c, "-opt mmfw:extractallraw : Extract all resources in raw form");
}

void de_module_mmfw(deark *c, struct deark_module_info *mi)
{
	mi->id = "mmfw";
	mi->desc = "MMFW resource file";
	mi->run_fn = de_run_mmfw;
	mi->identify_fn = de_identify_mmfw;
	mi->help_fn = de_help_mmfw;
}
