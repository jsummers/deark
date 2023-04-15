// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// ColoRIX .SCI, .SCR, etc.

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_colorix);

#define RIX_MIN_FILE_SIZE 36
#define RIX_UNC_SCR_FILE_SIZE 112016
#define RIX_MIN_OLD_SEGMENT_DLEN 220

struct colorix_ctx {
#define RIXFMT_OLD_U 1
#define RIXFMT_OLD_C 2
#define RIXFMT_RIX3  3
	int fmtver;
	u8 paltype;
	u8 stgtype;
	u8 imgtype;
	u8 is_compressed;
	u8 is_encrypted;
	u8 has_extension_block;
	i64 width, height;
	i64 rowspan;
	i64 known_segment_size;
	i64 pal_nbytes;
	i64 unc_image_size;
	de_color pal[256];
};

enum rle_state_type {
	RIX_RLESTATE_NEUTRAL = 0,
	RIX_RLESTATE_WAITING_FOR_REPEAT_COUNT
};

struct de_rixdecomp_params {
	i64 known_segment_size; // Set either this or rowspan
	i64 rowspan;
	u8 imgtype;
};

struct rixdecomp_ctx {
	deark *c;
	struct de_rixdecomp_params *private_params;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	const char *modname;
	u8 errflag;
	u8 use_xor_filter;
	i64 nbytes_written;
	i64 nodetable_pos;
	i64 first_cmpr_segment_pos;
	struct fmtutil_huffman_decoder *ht;
	struct de_bitreader bitrd;

	i64 nodetable_dpos;
	i64 nodetable_item_count;

	enum rle_state_type rle_state;
	u8 rle_curr_color;
	u8 rle_byte_to_repeat;
};

static void rixdecomp_interpret_nodetable_item(struct rixdecomp_ctx *rhctx,
	i64 itemnum, u64 currcode, UI currcode_nbits)
{
	u16 dval;

	if(rhctx->errflag) return;
	if(itemnum<0 || itemnum>=rhctx->nodetable_item_count) {
		rhctx->errflag = 1;
		return;
	}
	if(currcode_nbits>=FMTUTIL_HUFFMAN_MAX_CODE_LENGTH) return;

	dval = (u16)dbuf_getu16le(rhctx->dcmpri->f, rhctx->nodetable_dpos + 2*itemnum);
	de_dbg2(rhctx->c, "item[%d]: 0x%04x", (int)itemnum, (UI)dval);

	if(dval>=2 && dval<0x1000 && (dval%2==0)) { // a "pointer" item
		// The very next item is the start of the "1" subtree.
		rixdecomp_interpret_nodetable_item(rhctx, itemnum+1, ((currcode<<1) | 1), currcode_nbits+1);
		if(rhctx->errflag) goto done;

		// The pointer item tells how many bytes are between the pointer item
		// and the start of the "0" subtree.
		rixdecomp_interpret_nodetable_item(rhctx, itemnum+1+(dval/2), currcode<<1, currcode_nbits+1);

		if(rhctx->errflag) goto done;
	}
	else if(dval>=0x1000 && dval<=0x10ff) { // a leaf item
		fmtutil_huffman_valtype adj_value;
		char b2buf[72];

		adj_value = (fmtutil_huffman_valtype)(dval-0x1000);
		if(rhctx->c->debug_level>=3) {
			de_dbg3(rhctx->c, "code: \"%s\" = %d",
				de_print_base2_fixed(b2buf, sizeof(b2buf), currcode, currcode_nbits),
				(int)adj_value);
		}
		if(!fmtutil_huffman_add_code(rhctx->c, rhctx->ht->bk, currcode, currcode_nbits, adj_value)) {
			rhctx->errflag = 1;
		}

	}
	else {
		rhctx->errflag = 1;
		goto done;
	}

done:
	;
}

// Read node table, construct Huffman codebook.
// Uses rhctx->nodetable_pos.
// Sets rhctx->first_cmpr_segment_pos.
static int rixdecomp_read_nodetable(deark *c, struct rixdecomp_ctx *rhctx)
{
	i64 pos1;
	i64 pos;
	int retval = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pos1 = rhctx->nodetable_pos;
	pos = pos1;
	de_dbg(c, "huffman node table segment at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	rhctx->nodetable_item_count = dbuf_getu16le_p(rhctx->dcmpri->f, &pos);
	de_dbg(c, "item count: %u", (UI)rhctx->nodetable_item_count);
	rhctx->nodetable_dpos = pos;
	rhctx->first_cmpr_segment_pos = rhctx->nodetable_dpos + 2*rhctx->nodetable_item_count;

	rhctx->ht = fmtutil_huffman_create_decoder(c, 256, 256);

	// We expect a maximum of 513: 256 leaf entries, + 255 pointer entries,
	// + up to 2 extra zero-valued entries at the end.
	if(rhctx->nodetable_item_count < 1) {
		de_dfilter_set_generic_error(c, rhctx->dres, rhctx->modname);
		goto done;
	}

	de_dbg2(c, "node table nodes at %"I64_FMT, rhctx->nodetable_dpos);
	de_dbg_indent(c, 1);
	rixdecomp_interpret_nodetable_item(rhctx, 0, 0, 0);
	de_dbg_indent(c, -1);

	if(c->debug_level>=4) {
		fmtutil_huffman_dump(c, rhctx->ht);
	}

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void rixdecomp_process_rle_byte(deark *c, struct rixdecomp_ctx *rhctx, u8 n)
{
	i64 count = 0;
	i64 k;
	u8 val;

	if(rhctx->nbytes_written >= rhctx->dcmpro->expected_len) {
		goto done;
	}

	switch(rhctx->rle_state) {
	case RIX_RLESTATE_NEUTRAL:
		if(n==0x00 || n==0xff) {
			rhctx->rle_state = RIX_RLESTATE_WAITING_FOR_REPEAT_COUNT;
			rhctx->rle_byte_to_repeat = n;
			goto done;
		}
		else {
			count = 1;
			val = n;
		}
		break;
	case RIX_RLESTATE_WAITING_FOR_REPEAT_COUNT:
		count = (i64)n + 1;
		val = rhctx->rle_byte_to_repeat;
		rhctx->rle_state = RIX_RLESTATE_NEUTRAL;
		break;
	}

	for(k = 0; k<count; k++) {
		if(rhctx->use_xor_filter) {
			rhctx->rle_curr_color ^= val;
		}
		else {
			rhctx->rle_curr_color = val;
		}
		dbuf_writebyte(rhctx->dcmpro->f, rhctx->rle_curr_color);
	}
	rhctx->nbytes_written += count;
done:
	;
}

static void rixdecomp_process_codes_segment(deark *c, struct rixdecomp_ctx *rhctx, i64 dpos1, i64 dlen)
{
	de_zeromem(&rhctx->bitrd, sizeof(struct de_bitreader));
	rhctx->bitrd.bbll.is_lsb = 0;
	rhctx->bitrd.f = rhctx->dcmpri->f;
	rhctx->bitrd.curpos = dpos1;
	rhctx->bitrd.endpos = dpos1 + dlen;
	de_bitbuf_lowlevel_empty(&rhctx->bitrd.bbll);
	fmtutil_huffman_reset_cursor(rhctx->ht->cursor);

	rhctx->rle_state = RIX_RLESTATE_NEUTRAL;
	rhctx->rle_curr_color = 0x00;

	while(1) {
		int ret;
		fmtutil_huffman_valtype val = 0;

		ret = fmtutil_huffman_read_next_value(rhctx->ht->bk, &rhctx->bitrd, &val, NULL);
		if(!ret || val<0 || val>255) {
			// We don't always know exactly where the data stops, so don't report
			// errors here.
			goto done;
		}

		rixdecomp_process_rle_byte(c, rhctx, (u8)val);
	}

done:
	;
}

static void rixdecomp_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct rixdecomp_ctx *rhctx = NULL;
	i64 pos;
	i64 endpos;
	i64 seg_count;
	int ok = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	rhctx = de_malloc(c, sizeof(struct rixdecomp_ctx));
	rhctx->c = c;
	rhctx->private_params = (struct de_rixdecomp_params*)codec_private_params;
	rhctx->modname = "rixdecomp";
	rhctx->dcmpri = dcmpri;
	rhctx->dcmpro = dcmpro;
	rhctx->dres = dres;
	endpos = dcmpri->pos + rhctx->dcmpri->len;
	rhctx->use_xor_filter = (rhctx->private_params->imgtype==0);

	// Currently, we have some restrictions on the output dbuf.
	if(dcmpro->f->btype!=DBUF_TYPE_MEMBUF || dcmpro->f->len!=0 ||
		!dcmpro->len_known)
	{
		goto done;
	}

	if(rhctx->private_params->rowspan<1) goto done;

	rhctx->nodetable_pos = dcmpri->pos;
	if(!rixdecomp_read_nodetable(c, rhctx)) goto done;

	seg_count = 0;
	pos = rhctx->first_cmpr_segment_pos;
	while(1) {
		i64 saved_len;
		i64 seg_dcmpr_len;
		i64 seg_pos;
		i64 seg_dpos;
		i64 seg_dlen;
		i64 num_extra_bytes;

		if(pos+2 >= endpos) break;
		rhctx->nbytes_written = rhctx->dcmpro->f->len;
		if(rhctx->nbytes_written >= rhctx->dcmpro->expected_len) {
			break;
		}

		seg_pos = pos;
		seg_dlen = dbuf_getu16le_p(dcmpri->f, &pos);
		if(seg_dlen==0) break;
		seg_dpos = pos;

		de_dbg(c, "compressed segment at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
			seg_pos, seg_dpos, seg_dlen);
		de_dbg_indent(c, 1);

		saved_len = rhctx->dcmpro->f->len;
		dbuf_enable_wbuffer(rhctx->dcmpro->f);
		rixdecomp_process_codes_segment(c, rhctx, seg_dpos, seg_dlen);
		dbuf_disable_wbuffer(rhctx->dcmpro->f);

		seg_dcmpr_len = rhctx->dcmpro->f->len - saved_len;
		de_dbg(c, "decompressed size: %"I64_FMT, seg_dcmpr_len);

		if(seg_dcmpr_len < rhctx->private_params->rowspan) {
			de_dfilter_set_generic_error(c, dres, rhctx->modname);
			goto done;
		}

		de_dbg(c, "number of rows: %"I64_FMT, (i64)(seg_dcmpr_len/rhctx->private_params->rowspan));

		if(rhctx->private_params->known_segment_size) {
			rhctx->nbytes_written = (seg_count+1) * rhctx->private_params->known_segment_size;
			dbuf_truncate(rhctx->dcmpro->f, rhctx->nbytes_written);
		}
		else if(rhctx->dcmpro->f->len < rhctx->dcmpro->expected_len) {
			// For non-final segments, there is a potential problem.
			// For a compressed segment, we know neither the (bit-exact) size of the
			// compressed data, nor the size of the decompressed data. The padding
			// bits in the final byte can be misinterpreted as compressed data, so
			// we may have mistakenly decompressed them into garbage pixels that
			// will mess up the rest of the image.
			// It's possible that there is a formula that would tell us the size
			// of the decompressed data. But I don't know what it is.
			// Anyway, this is a quick and dirty attempt to work around the problem
			// by detecting and deleting such garbage pixels. It's not foolproof, and
			// better heuristics are possible.
			num_extra_bytes = rhctx->dcmpro->f->len % rhctx->private_params->rowspan;
			if(num_extra_bytes>0) {
				de_dbg(c, "[ignoring %"I64_FMT" bytes -- assuming garbage caused by padding bits]",
					num_extra_bytes);
				rhctx->nbytes_written = rhctx->dcmpro->f->len - num_extra_bytes;
				dbuf_truncate(rhctx->dcmpro->f, rhctx->nbytes_written);
			}
		}

		pos += seg_dlen;
		seg_count++;
		de_dbg_indent(c, -1);
	}

	ok = 1;

done:
	if(rhctx) {
		if(!ok || dres->errcode) {
			de_dfilter_set_generic_error(c, dres, rhctx->modname);
		}

		fmtutil_huffman_destroy_decoder(c, rhctx->ht);
		de_free(c, rhctx);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_colorix_decompress(deark *c, struct colorix_ctx *d, i64 pos1,
	dbuf *unc_pixels)
{
	int retval = 0;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_rixdecomp_params params;

	de_zeromem(&params, sizeof(struct de_rixdecomp_params));
	params.known_segment_size = d->known_segment_size;
	params.rowspan = d->rowspan;
	params.imgtype = d->imgtype;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos1;
	dcmpri.len = c->infile->len - pos1;
	dcmpro.f = unc_pixels;
	dcmpro.expected_len = d->unc_image_size;
	dcmpro.len_known = 1;

	rixdecomp_codectype1(c, &dcmpri, &dcmpro, &dres, (void*)&params);
	dbuf_flush(dcmpro.f);

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static void do_colorix_image_RIX3(deark *c, struct colorix_ctx *d, i64 pos1)
{
	de_bitmap *img = NULL;
	dbuf *unc_pixels = 0;
	dbuf *final_pixels_dbuf; // copy of pointer; do not free
	i64 final_pixels_pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "image at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	if(d->imgtype==4) {
		d->rowspan = de_pad_to_n(d->width, 8) / 2;
	}
	else {
		d->rowspan = d->width;
	}
	if(d->rowspan<1) goto done;

	d->unc_image_size = d->rowspan * d->height;
	img = de_bitmap_create(c, d->width, d->height, 3);

	if(d->is_compressed) {
		unc_pixels = dbuf_create_membuf(c, d->unc_image_size+256, 0);
		if(!do_colorix_decompress(c, d, pos1, unc_pixels)) {
			goto done;
		}
		final_pixels_dbuf = unc_pixels;
		final_pixels_pos = 0;
	}
	else {
		final_pixels_dbuf = c->infile;
		final_pixels_pos = pos1;
	}

	if(d->imgtype==4) {
		de_convert_image_paletted_planar(final_pixels_dbuf, final_pixels_pos, 4,
			d->rowspan, d->rowspan/4, d->pal, img, 0x2);
	}
	else { // assume 0
		de_convert_image_paletted(final_pixels_dbuf, final_pixels_pos, 8,
			d->rowspan, d->pal, img, 0);
	}

	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	de_dbg_indent_restore(c, saved_indent_level);
}

// Sets d->pal_nbytes
static void read_colorix_palette(deark *c, struct colorix_ctx *d, i64 pos1)
{
	if(d->paltype==0xab) {
		de_read_simple_palette(c, c->infile, pos1, 16, 3, d->pal, 16, DE_RDPALTYPE_VGA18BIT, 0);
		d->pal_nbytes = 48;
	}
	else { // assume 0xaf
		de_read_simple_palette(c, c->infile, pos1, 256, 3, d->pal, 256, DE_RDPALTYPE_VGA18BIT, 0);
		d->pal_nbytes = 768;
	}
}

static void declare_colorix_fmt(deark *c, struct colorix_ctx *d)
{
	de_declare_fmtf(c, "ColoRIX - %s, %scompressed",
		(d->fmtver==RIXFMT_RIX3 ? "new" : "old"),
		(d->is_compressed ? "" : "un"));
}

static void do_colorix_RIX3(deark *c, struct colorix_ctx *d)
{
	i64 pos;

	pos = 4;
	d->width = de_getu16le_p(&pos);
	d->height = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->width, d->height);

	d->paltype = de_getbyte_p(&pos);
	de_dbg(c, "palette type: 0x%02x", (UI)d->paltype);
	if(d->paltype!=0xab && d->paltype!=0xaf) {
		de_err(c, "Unsupported palette type: 0x%02x", (UI)d->paltype);
	}

	d->stgtype = de_getbyte_p(&pos);
	de_dbg(c, "storage type: 0x%02x", (UI)d->stgtype);

	if(d->stgtype & 0x80) d->is_compressed = 1;
	if(d->stgtype & 0x40) d->has_extension_block = 1;
	if(d->stgtype & 0x20) d->is_encrypted = 1;
	d->imgtype = d->stgtype & 0x0f; // I guess?
	declare_colorix_fmt(c, d);

	if(d->is_encrypted) {
		de_err(c, "Encrypted files not supported");
		goto done;
	}
	if(d->has_extension_block) {
		// TODO: We could tolerate this.
		de_err(c, "Extension blocks not supported");
		goto done;
	}

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;
	read_colorix_palette(c, d, pos);
	pos += d->pal_nbytes;

	if(d->imgtype==0 || d->imgtype==4) {
		;
	}
	else {
		de_err(c, "Unsupported image type: 0x%02x", (UI)d->stgtype);
		goto done;
	}

	do_colorix_image_RIX3(c, d, pos);
done:
	;
}

static void acquire_palette_ega64idx(deark *c, struct colorix_ctx *d, i64 pos1)
{
	i64 k;
	i64 pos = pos1;
	char tmps[32];

	for(k=0; k<16; k++) {
		int index;

		index = (int)de_getbyte_p(&pos);
		index &= 0x3f;
		d->pal[k] = de_get_std_palette_entry(DE_PALID_EGA64, 0, index);
		de_snprintf(tmps, sizeof(tmps), "%2d ", index);
		de_dbg_pal_entry2(c, k, d->pal[k], tmps, NULL, NULL);
	}
}

static void do_colorix_old_SCR(deark *c, struct colorix_ctx *d)
{
	de_bitmap *img = NULL;
	i64 planespan;
	dbuf *unc_pixels = NULL;
	dbuf *tmpbuf = NULL;
	dbuf *final_pixels_dbuf; // copy of pointer; do not free
	i64 final_pixels_pos;
	de_finfo *fi = NULL;

	d->imgtype = 1;
	d->width = 640;
	d->height = 350;
	d->unc_image_size = (d->width*d->height)/2;
	planespan = d->unc_image_size/4;
	d->known_segment_size = planespan;
	d->rowspan = d->width/8;
	declare_colorix_fmt(c, d);

	acquire_palette_ega64idx(c, d, 0);

	if(d->is_compressed) {
		unc_pixels = dbuf_create_membuf(c, d->unc_image_size+256, 0);
		if(!do_colorix_decompress(c, d, 16, unc_pixels)) goto done;
		final_pixels_dbuf = unc_pixels;
		final_pixels_pos = 0;
	}
	else {
		final_pixels_dbuf = c->infile;
		final_pixels_pos = 16;
	}

	// TODO?: Improve de_convert_image_paletted_planar to support this plane order.
	tmpbuf = dbuf_create_membuf(c, d->unc_image_size, 0);
	dbuf_copy(final_pixels_dbuf, final_pixels_pos+planespan*0, planespan, tmpbuf);
	dbuf_copy(final_pixels_dbuf, final_pixels_pos+planespan*2, planespan, tmpbuf);
	dbuf_copy(final_pixels_dbuf, final_pixels_pos+planespan*1, planespan, tmpbuf);
	dbuf_copy(final_pixels_dbuf, final_pixels_pos+planespan*3, planespan, tmpbuf);

	img = de_bitmap_create(c, d->width, d->height, 3);
	de_convert_image_paletted_planar(tmpbuf, 0, 4,
		d->rowspan, planespan, d->pal, img, 2);

	fi = de_finfo_create(c);
	fi->density.code = DE_DENSITY_UNK_UNITS;
	fi->density.xdens = 480.0;
	fi->density.ydens = (double)d->height;
	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	dbuf_close(tmpbuf);
	de_finfo_destroy(c, fi);
}

static int is_RIX3(dbuf *f)
{
	if(!dbuf_memcmp(f, 0, (const void*)"RIX3", 4)) {
		return 1;
	}
	return 0;
}

// It's a pain to detect old compressed format, but I guess it's worth
// the trouble.
static int looks_like_compressed_data(dbuf *f, i64 pos1)
{
	i64 pos = pos1;
	i64 first_image_seg_pos;
	int retval = 0;
	i64 i;
	i64 num_codebook_items;
	i64 num_items_to_check;

	// Validate the codebook size, and some of the items
	num_codebook_items = dbuf_getu16le_p(f, &pos);
	if(num_codebook_items<3 || num_codebook_items>513) goto done;
	first_image_seg_pos = pos + num_codebook_items*2;
	if(first_image_seg_pos > f->len) goto done;

	num_items_to_check = de_min_int(num_codebook_items-2, 16);
	for(i=0; i<num_items_to_check; i++) {
		UI item;

		item = (UI)dbuf_getu16le_p(f, &pos);
		if(item<0x1000) {
			if((item&0x1)!=0) goto done;
			if(pos+item >= first_image_seg_pos) goto done;
		}
		else if(item<=0x10ff) {
			;
		}
		else {
			goto done;
		}
	}

	// Validate the image segment sizes
	pos = first_image_seg_pos;
	for(i=0; i<4; i++) {
		i64 seg_len;

		if(pos+3 > f->len) goto done;
		seg_len = dbuf_getu16le_p(f, &pos);
		if(seg_len<RIX_MIN_OLD_SEGMENT_DLEN) goto done;

		pos += seg_len;
	}

	if(pos==f->len) {
		retval = 1;
	}

done:
	return retval;
}

// Returns RIXFMT_OLD_U, RIXFMT_OLD_C, or 0.
static int detect_old_fmt(dbuf *f, u8 strict)
{
	size_t i;
	u8 cmpr_flag = 0;
	u8 buf[16];

	if(f->len<RIX_MIN_FILE_SIZE) return 0;

	// Check the palette
	dbuf_read(f, buf, 0, 16);
	for(i=0; i<16; i++) {
		if(i==0) {
			if((buf[i] & 0x80)!=0) {
				cmpr_flag = 1;
				buf[i] -= 0x80;
			}
			else {
				if(f->len!=RIX_UNC_SCR_FILE_SIZE) return 0;
			}
		}

		if(buf[i]>0x3f) return 0;
	}
	if(!cmpr_flag) return RIXFMT_OLD_U;
	if(!strict) return RIXFMT_OLD_C;

	if(looks_like_compressed_data(f, 16)) {
		return RIXFMT_OLD_C;
	}

	return 0;
}

static void de_run_colorix(deark *c, de_module_params *mparams)
{
	struct colorix_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct colorix_ctx));

	if(is_RIX3(c->infile)) {
		d->fmtver = RIXFMT_RIX3;
	}
	else {
		d->fmtver = detect_old_fmt(c->infile, 0);
		if(d->fmtver==RIXFMT_OLD_C) {
			d->is_compressed = 1;
		}
	}

	if(d->fmtver==RIXFMT_RIX3) {
		do_colorix_RIX3(c, d);
	}
	else if(d->fmtver==RIXFMT_OLD_U || d->fmtver==RIXFMT_OLD_C) {
		do_colorix_old_SCR(c, d);
	}
	else {
		de_err(c, "Unknown or unsupported RIX format");
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_colorix(deark *c)
{
	if(c->infile->len < RIX_MIN_FILE_SIZE) return 0;

	if(is_RIX3(c->infile)) {
		return 95;
	}

	if(c->detection_data->best_confidence_so_far >= 55) return 0;

	if(de_input_file_has_ext(c, "scr")) {
		int fmt;

		fmt = detect_old_fmt(c->infile, 1);
		if(fmt==RIXFMT_OLD_U) {
			return 35;
		}
		else if(fmt==RIXFMT_OLD_C) {
			return 55;
		}
	}
	// TODO: There is supposedly also an old ".SCP" format, 640x480x16.
	// But I can't find any samples.

	return 0;
}

void de_module_colorix(deark *c, struct deark_module_info *mi)
{
	mi->id = "colorix";
	mi->desc = "ColoRIX";
	mi->run_fn = de_run_colorix;
	mi->identify_fn = de_identify_colorix;
}
