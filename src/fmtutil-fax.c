// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Fax3/Fax4/etc. decompressor

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

struct fax34_huffman_tree {
	struct fmtutil_huffman_decoder *htwb[2]; // [0]=white, [1]=black
	struct fmtutil_huffman_decoder *_2d_codes;
};

struct fax_ctx {
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	const char *modname;
	struct de_fax34_params *fax34params;
	u8 has_eol_codes;
	u8 rows_padded_to_next_byte;
	u8 is_2d;
	i64 image_width, image_height;

	i64 nbytes_written;
	struct de_bitreader bitrd;

	u8 *curr_row; // array[image_width]
	u8 *prev_row; // array[image_width]

	i64 rowspan_final;
	u8 *tmp_row_packed; // array[rowspan_final]

	i64 pending_run_len;
	UI f2d_h_codes_remaining;

	i64 ypos; // Row of the next pixel to be decoded
	i64 a0; // Next output pixel x-position. Can be -1; the 2-d decoder sometimes
	// needs -1 and 0 to be distinct "reference pixel positions".

	u8 a0_color;
	u8 have_read_tag_bit;
	u8 tag_bit;
	i64 b1;
	i64 b2;
};

#define FAX2D_7ZEROES    0
#define FAX2D_P          1
#define FAX2D_H          2
#define FAX2D_EXTENSION  3
#define FAX2D_V_BIAS     100

static const u8 fax34_2dvals[11] = {
	FAX2D_7ZEROES, // EOFB, etc...
	FAX2D_EXTENSION, // Extension...
	FAX2D_V_BIAS-3, // VL3
	FAX2D_V_BIAS+3, // VR3
	FAX2D_V_BIAS-2, // VL2
	FAX2D_V_BIAS+2, // VR2
	FAX2D_P, // P
	FAX2D_H, // H...
	FAX2D_V_BIAS-1, // VL1
	FAX2D_V_BIAS+1, // VR1
	FAX2D_V_BIAS // V0
};

static const u8 fax34_2dcodes[11] = {
	0x00, // 0000000
	0x01, // 0000001
	0x02, // 0000010
	0x03, // 0000011
	0x02, // 000010
	0x03, // 000011
	0x1,  // 0001
	0x1,  // 001
	0x2,  // 010
	0x3,  // 011
	0x1   // 1
};

static const u8 fax34_2dcodelengths[11] = {
	7, 7, 7, 7, 6, 6, 4, 3, 3, 3, 1
};

static void create_fax34_huffman_tree2d(deark *c, struct fax34_huffman_tree *f34ht)
{
	size_t i;

	f34ht->_2d_codes = fmtutil_huffman_create_decoder(c, 11, 11);

	// Note that this tree could be constructed using
	//  fmtutil_huffman_make_canonical_tree(..., FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES),
	// so we don't actually need the fax34_2dcodes table. But it's not worth it, to
	// get rid of an 11-byte table.

	for(i=0; i<DE_ARRAYCOUNT(fax34_2dcodes); i++) {
		fmtutil_huffman_add_code(c, f34ht->_2d_codes->bk, (u64)fax34_2dcodes[i],
			(UI)fax34_2dcodelengths[i], (fmtutil_huffman_valtype)fax34_2dvals[i]);
	}
}

// To make a well-formed Huffman tree, we need to account for all the codes
// beginning with 8 zeroes. Generally, this will be the start of an EOL or sync
// code, the remainder of which will be handled with special logic.
#define FAX1D_8ZEROES (-1)

// Same for both white & black codes. 0 <= i <= 104
static fmtutil_huffman_valtype getfax34val(size_t i)
{
	if(i<=64) {
		return (fmtutil_huffman_valtype)i;
	}
	else if(i<=103) {
		return (fmtutil_huffman_valtype)((i-63)*64);
	}
	return FAX1D_8ZEROES; // i==104, presumably
}

// Some codes in the next two tables are up to 13 bits in size, but bits before the
// last 8 are always 0, so we can use an 8-bit integer type.
static const u8 fax34whitecodes[105] = {
	0x35,0x7,0x7,0x8,0xb,0xc,0xe,0xf,0x13,0x14,0x7,0x8,0x8,0x3,0x34,0x35,0x2a,0x2b,0x27,
	0xc,0x8,0x17,0x3,0x4,0x28,0x2b,0x13,0x24,0x18,0x2,0x3,0x1a,0x1b,0x12,0x13,0x14,0x15,
	0x16,0x17,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x4,0x5,0xa,0xb,0x52,0x53,0x54,0x55,0x24,0x25,
	0x58,0x59,0x5a,0x5b,0x4a,0x4b,0x32,0x33,0x34,0x1b,0x12,0x17,0x37,0x36,0x37,0x64,0x65,
	0x68,0x67,0xcc,0xcd,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0x98,0x99,0x9a,
	0x18,0x9b,0x8,0xc,0xd,0x12,0x13,0x14,0x15,0x16,0x17,0x1c,0x1d,0x1e,0x1f,0
};
static const u8 fax34blackcodes[105] = {
	0x37,0x2,0x3,0x2,0x3,0x3,0x2,0x3,0x5,0x4,0x4,0x5,0x7,0x4,0x7,0x18,0x17,0x18,0x8,0x67,
	0x68,0x6c,0x37,0x28,0x17,0x18,0xca,0xcb,0xcc,0xcd,0x68,0x69,0x6a,0x6b,0xd2,0xd3,0xd4,
	0xd5,0xd6,0xd7,0x6c,0x6d,0xda,0xdb,0x54,0x55,0x56,0x57,0x64,0x65,0x52,0x53,0x24,0x37,
	0x38,0x27,0x28,0x58,0x59,0x2b,0x2c,0x5a,0x66,0x67,0xf,0xc8,0xc9,0x5b,0x33,0x34,0x35,
	0x6c,0x6d,0x4a,0x4b,0x4c,0x4d,0x72,0x73,0x74,0x75,0x76,0x77,0x52,0x53,0x54,0x55,0x5a,
	0x5b,0x64,0x65,0x8,0xc,0xd,0x12,0x13,0x14,0x15,0x16,0x17,0x1c,0x1d,0x1e,0x1f,0
};

// High 4 bits is the length of the white code.
// Low 4 bits is the length of the black code.
static const u8 fax34codelengths[105] = {
	0x8a,0x63,0x42,0x42,0x43,0x44,0x44,0x45,0x56,0x56,0x57,0x57,0x67,0x68,0x68,0x69,
	0x6a,0x6a,0x7a,0x7b,0x7b,0x7b,0x7b,0x7b,0x7b,0x7b,0x7c,0x7c,0x7c,0x8c,0x8c,0x8c,
	0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,
	0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,0x8c,
	0x5a,0x5c,0x6c,0x7c,0x8c,0x8c,0x8c,0x8d,0x8d,0x8d,0x9d,0x9d,0x9d,0x9d,0x9d,0x9d,
	0x9d,0x9d,0x9d,0x9d,0x9d,0x9d,0x9d,0x9d,0x9d,0x6d,0x9d,0xbb,0xbb,0xbb,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x88
};

static UI getfax34codelength(UI isblack, size_t i)
{
	if(i<105) {
		if(isblack)
			return (UI)(fax34codelengths[i] & 0x0f);
		return (UI)(fax34codelengths[i] >> 4);
	}
	return 0;
}

static struct fax34_huffman_tree *create_fax34_huffman_tree(deark *c, int need_2d)
{
	struct fax34_huffman_tree *f34ht;
	size_t i;
	static const size_t num_white_codes = DE_ARRAYCOUNT(fax34whitecodes);
	static const size_t num_black_codes = DE_ARRAYCOUNT(fax34blackcodes);

	f34ht = de_malloc(c, sizeof(struct fax34_huffman_tree));
	f34ht->htwb[0] = fmtutil_huffman_create_decoder(c, (i64)num_white_codes+10, 0);
	f34ht->htwb[1] = fmtutil_huffman_create_decoder(c, (i64)num_black_codes+10, 0);

	if(need_2d) {
		create_fax34_huffman_tree2d(c, f34ht);
	}

	for(i=0; i<num_white_codes; i++) {
		fmtutil_huffman_add_code(c, f34ht->htwb[0]->bk, (u64)fax34whitecodes[i],
			getfax34codelength(0, i), getfax34val(i));
	}
	for(i=0; i<num_black_codes; i++) {
		fmtutil_huffman_add_code(c, f34ht->htwb[1]->bk, (u64)fax34blackcodes[i],
			getfax34codelength(1, i), getfax34val(i));
	}

	return f34ht;
}

static void destroy_fax34_huffman_tree(deark *c, struct fax34_huffman_tree *f34ht)
{
	if(!f34ht) return;
	fmtutil_huffman_destroy_decoder(c, f34ht->htwb[0]);
	fmtutil_huffman_destroy_decoder(c, f34ht->htwb[1]);
	if(f34ht->_2d_codes) fmtutil_huffman_destroy_decoder(c, f34ht->_2d_codes);
	de_free(c, f34ht);
}

static void fax34_on_eol(deark *c, struct fax_ctx *fc, int is_real)
{
	i64 i;

	de_dbg3(c, "%sEOL", is_real?"":"implicit ");

	if(fc->ypos >= fc->image_height) goto done;

	// [Pack curr_row into bits (tmp_row_packed)]
	de_zeromem(fc->tmp_row_packed, (size_t)fc->rowspan_final);
	for(i=0; i<fc->image_width; i++) {
		if(fc->curr_row[i]) {
			fc->tmp_row_packed[i/8] |= 1U<<(7-i%8);
		}
	}

	// [Write tmp_row_packed to fc->dcmpro]
	dbuf_write(fc->dcmpro->f, fc->tmp_row_packed, fc->rowspan_final);
	fc->nbytes_written += fc->rowspan_final;

	if(fc->is_2d) {
		de_memcpy(fc->prev_row, fc->curr_row, (size_t)fc->image_width);
	}

	// initialize curr_row
	de_zeromem(fc->curr_row, (size_t)fc->image_width);

	fc->ypos++;
done:
	fc->a0 = -1;
	fc->a0_color = 0;
	fc->pending_run_len = 0;
	fc->f2d_h_codes_remaining = 0;
	fc->have_read_tag_bit = 0;
}

// Record run_len pixels as fc0->a0_color, updating fc->a0.
// respect_negative_a0==0: If fc->a0 == -1, sets it to 0 first.
// respect_negative_a0==1: If fc->a0 == -1, only sets rec_len-1 pixels.
static void fax34_record_run(deark *c, struct fax_ctx *fc, i64 run_len,
	int respect_negative_a0)
{
	i64 i;
	u8 color = fc->a0_color;

	de_dbg3(c, "run c=%u len=%d", (UI)color, (int)run_len);

	if(fc->a0<0) {
		if(respect_negative_a0) {
			run_len += fc->a0;
		}
		fc->a0 = 0;
	}

	if(color==0) { // Pixels are initialized to 0, don't need to set them.
		fc->a0 += run_len;
	}
	else {
		for(i=0; (i<run_len) && (fc->a0 < fc->image_width); i++) {
			fc->curr_row[fc->a0++] = color;
		}
	}

	if(fc->a0 > fc->image_width) {
		fc->a0 = fc->image_width;
	}
}

static void init_fax34_bitreader(deark *c, struct fax_ctx *fc)
{
	de_zeromem(&fc->bitrd, sizeof(struct de_bitreader));
	fc->bitrd.f = fc->dcmpri->f;
	fc->bitrd.curpos = fc->dcmpri->pos;
	fc->bitrd.endpos = fc->dcmpri->pos + fc->dcmpri->len;
	fc->bitrd.bbll.is_lsb = fc->fax34params->is_lsb;
}

// Read up to and including the next '1' bit
static int fax34_finish_sync(deark *c, struct fax_ctx *fc, i64 max_bits_to_search,
	i64 *pnbits_read)
{
	i64 nbits_searched = 0;
	int retval = 0;

	while(1) {
		u64 n;

		if(nbits_searched >= max_bits_to_search) {
			goto done;
		}

		n = de_bitreader_getbits(&fc->bitrd, 1);
		if(fc->bitrd.eof_flag) goto done;
		nbits_searched++;
		if(n!=0) {
			retval = 1;
			goto done;
		}
	}
done:
	if(pnbits_read) *pnbits_read = nbits_searched;
	return retval;
}

// Read up to and including run of 8 or more '0' bits, followed by a '1' bit.
static int fax34_full_sync(deark *c, struct fax_ctx *fc, i64 max_bits_to_search)
{
	i64 nbits_searched = 0;
	UI zcount = 0;
	int retval = 0;

	while(1) {
		u64 n;

		if(nbits_searched >= max_bits_to_search) {
			goto done;
		}
		n = de_bitreader_getbits(&fc->bitrd, 1);
		if(fc->bitrd.eof_flag) goto done;
		nbits_searched++;

		if(n!=0) {
			zcount = 0;
			continue;
		}
		zcount++;
		if(zcount>=8) {
			break;
		}
	}

	retval = fax34_finish_sync(c, fc, max_bits_to_search-nbits_searched, NULL);

done:
	return retval;
}

// Sets fc->b1 appropriately, according to fc->a0 and fc->prev_row and
// fc->image_width.
static void find_b1(struct fax_ctx *fc)
{
	i64 i;

	for(i=fc->a0+1; i<fc->image_width; i++) {
		if(i<0) continue;

		// first prev_row pixel to the right of a0, of opposite color to a0_color
		if(fc->prev_row[i]==fc->a0_color) continue;

		// Looking for a "changing element". I.e. if both it and the pixel to the left
		// exist, they must have different colors.
		if(i==0) {
			// Leftmost pixel is "changing" if it is black
			if(fc->prev_row[i]==0) continue;
		}
		else {
			if(fc->prev_row[i-1] == fc->prev_row[i]) continue;
		}

		fc->b1 = i;
		return;
	}
	fc->b1 = fc->image_width;
}

static void find_b1_and_b2(struct fax_ctx *fc)
{
	i64 i;

	find_b1(fc);

	for(i=fc->b1+1; i<fc->image_width; i++) {
		// Looking for a "changing element", i.e. one having a different color from
		// the pixel to its left.
		if(fc->prev_row[i-1] == fc->prev_row[i]) continue;
		fc->b2 = i;
		return;
	}
	fc->b2 = fc->image_width;
}

static void do_decompress_fax34(deark *c, struct fax_ctx *fc,
	struct fax34_huffman_tree *f34ht)
{
	char errmsg[100];
	static const char errmsg_UNEXPECTEDEOD[] = "Unexpected end of compressed data";
	static const char errmsg_HUFFDECODEERR[] = "Huffman decode error";
	static const char errmsg_NOEOL[] = "Failed to find EOL mark";
	static const char errmsg_UNSUPPEXT[] = "Decoding error or unsupported Fax extension";

	errmsg[0] = '\0';
	init_fax34_bitreader(c, fc);

	if(fc->has_eol_codes) {
		if(!fax34_full_sync(c, fc, 1024)) {
			if(fc->fax34params->tiff_cmpr_meth==3 && fc->dcmpri->len>0) {
				de_dbg(c, "[no sync mark found, trying to compensate]");
				fc->has_eol_codes = 0;
				fc->rows_padded_to_next_byte = 0;
				init_fax34_bitreader(c, fc);
			}
			else {
				de_strlcpy(errmsg, "Failed to find sync mark", sizeof(errmsg));
				goto done;
			}
		}
	}

	fc->pending_run_len = 0;
	fc->f2d_h_codes_remaining = 0;
	fc->ypos = 0;
	fc->a0 = -1;
	fc->a0_color = 0;
	fc->have_read_tag_bit = 0;

	while(1) {
		int ret;
		int in_2d_mode;
		fmtutil_huffman_valtype val = 0;

		if(fc->ypos >= fc->image_height ||
			((fc->ypos == fc->image_height-1) && (fc->a0 >= fc->image_width)))
		{
			goto done; // Normal completion
		}
		if(fc->dcmpro->len_known && fc->nbytes_written>fc->dcmpro->expected_len) {
			goto done; // Sufficient output
		}

		if(fc->bitrd.eof_flag) {
			de_strlcpy(errmsg, errmsg_UNEXPECTEDEOD, sizeof(errmsg));
			goto done;
		}

		if(!fc->has_eol_codes && (fc->a0 >= fc->image_width) && fc->f2d_h_codes_remaining==0) {
			if(fc->rows_padded_to_next_byte) {
				de_bitbuf_lowlevel_empty(&fc->bitrd.bbll);
			}
			fax34_on_eol(c, fc, 0);
		}

		if(fc->is_2d && fc->fax34params->tiff_cmpr_meth==3 && !fc->have_read_tag_bit) {
			fc->tag_bit = (u8)de_bitreader_getbits(&fc->bitrd, 1);
			fc->have_read_tag_bit = 1;
		}

		in_2d_mode = 0;
		if(fc->is_2d) {
			if(fc->f2d_h_codes_remaining == 0) {
				if(fc->fax34params->tiff_cmpr_meth==3) {
					if(fc->tag_bit==0) {
						in_2d_mode = 1;
					}
				}
				else { // (Fax4)
					in_2d_mode = 1;
				}
			}
		}

		if(in_2d_mode) {
			ret = fmtutil_huffman_read_next_value(f34ht->_2d_codes->bk, &fc->bitrd, &val, NULL);
			if(!ret) {
				if(fc->bitrd.eof_flag) {
					de_strlcpy(errmsg, errmsg_UNEXPECTEDEOD, sizeof(errmsg));
				}
				else {
					de_strlcpy(errmsg, errmsg_HUFFDECODEERR, sizeof(errmsg));
				}
				goto done;
			}
			de_dbg3(c, "val: %d", (int)val);

			if(val>=FAX2D_V_BIAS-3 && val<=FAX2D_V_BIAS+3) { // VL(3), ..., V(0), ..., VR(3)
				i64 run_len;

				find_b1(fc);
				de_dbg3(c, "at %d b1=%d", (int)fc->a0, (int)fc->b1);
				run_len = fc->b1 - fc->a0 + ((i64)val-FAX2D_V_BIAS);

				fax34_record_run(c, fc, run_len, 1);
				fc->a0_color = fc->a0_color?0:1;
			}
			else if(val==FAX2D_P) {
				find_b1_and_b2(fc);
				fax34_record_run(c, fc, fc->b2 - fc->a0, 1);
			}
			else if(val==FAX2D_H) {
				fc->f2d_h_codes_remaining = 2;
			}
			else if(val==FAX2D_7ZEROES) {
				if(fc->has_eol_codes) {
					if(!fax34_finish_sync(c, fc, 64, NULL)) {
						de_strlcpy(errmsg, errmsg_NOEOL, sizeof(errmsg));
						goto done;
					}
					fax34_on_eol(c, fc, 1);
				}
				else {
					// Full EOFB should be 000000000001000000000001
					de_dbg3(c, "EOFB");
					goto done;
				}
			}
			else if(val==FAX2D_EXTENSION) {
				UI extnum;

				extnum = (UI)de_bitreader_getbits(&fc->bitrd, 3);
				// TODO?: Support uncompressed mode
				de_snprintf(errmsg, sizeof(errmsg), "%s (%u)", errmsg_UNSUPPEXT, extnum);
				goto done;
			}
			else {
				goto done; // Should be impossible
			}
		}
		else {
			ret = fmtutil_huffman_read_next_value(f34ht->htwb[(UI)fc->a0_color]->bk, &fc->bitrd, &val, NULL);
			if(!ret) {
				if(fc->bitrd.eof_flag) {
					de_strlcpy(errmsg, errmsg_UNEXPECTEDEOD, sizeof(errmsg));
				}
				else {
					de_strlcpy(errmsg, errmsg_HUFFDECODEERR, sizeof(errmsg));
				}
				goto done;
			}

			if(val==FAX1D_8ZEROES) {
				if(!fc->has_eol_codes || fc->f2d_h_codes_remaining!=0) {
					de_strlcpy(errmsg, errmsg_HUFFDECODEERR, sizeof(errmsg));
					goto done;
				}

				i64 nbits_read;
				if(!fax34_finish_sync(c, fc, 64, &nbits_read)) {
					de_strlcpy(errmsg, errmsg_NOEOL, sizeof(errmsg));
					goto done;
				}
				if(nbits_read<4) {
					de_strlcpy(errmsg, errmsg_UNSUPPEXT, sizeof(errmsg));
					// TODO: Attempt error recovery?
					goto done;
				}
				// TODO: Check for premature EOL?
				fax34_on_eol(c, fc, 1);
			}
			else if(val<64) {
				fc->pending_run_len += (i64)val;
				fax34_record_run(c, fc, fc->pending_run_len, 0);
				fc->pending_run_len = 0;
				fc->a0_color = fc->a0_color?0:1;
				if(fc->f2d_h_codes_remaining>0) {
					fc->f2d_h_codes_remaining--;
				}
			}
			else { // make-up code
				fc->pending_run_len += (i64)val;
			}
		}
	}

done:
	if(fc->a0>0) {
		fax34_on_eol(c, fc, 0); // Make sure we emit the last row
	}

	if(errmsg[0]) {
		if(fc->ypos>0) {
			de_warn(c, "[%s] Failed to decode entire strip: %s", fc->modname, errmsg);
		}
		else {
			de_dfilter_set_errorf(c, fc->dres, fc->modname, "%s", errmsg);
		}
	}
}

// Note - This always decodes white pixels to bit value 0, and black to 1.
void fmtutil_fax34_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params)
{
	struct fax_ctx *fc = NULL;
	struct fax34_huffman_tree *f34ht = NULL;

	fc = de_malloc(c, sizeof(struct fax_ctx));
	fc->modname = "fax_decode";
	fc->fax34params = (struct de_fax34_params*)codec_private_params;
	fc->dcmpri = dcmpri;
	fc->dcmpro = dcmpro;
	fc->dres = dres;
	fc->image_width = fc->fax34params->image_width;
	fc->image_height = fc->fax34params->image_height;

	if((fc->fax34params->tiff_cmpr_meth==3 && (fc->fax34params->t4options & 0x1)) ||
		(fc->fax34params->tiff_cmpr_meth==4))
	{
		fc->is_2d = 1;
	}

	if(fc->fax34params->tiff_cmpr_meth==2) {
		fc->has_eol_codes = 0;
		fc->rows_padded_to_next_byte = 1;
	}
	else if(fc->fax34params->tiff_cmpr_meth==3) {
		fc->has_eol_codes = 1;
	}

	if(fc->image_width < 1 ||
		fc->image_width > c->max_image_dimension)
	{
		goto done;
	}

	fc->rowspan_final = (fc->image_width+7)/8;
	if(fc->rowspan_final < fc->fax34params->out_rowspan) {
		fc->rowspan_final = fc->fax34params->out_rowspan;
	}

	fc->curr_row = de_malloc(c, fc->image_width);
	fc->prev_row = de_malloc(c, fc->image_width);
	fc->tmp_row_packed = de_malloc(c, fc->rowspan_final);

	f34ht = create_fax34_huffman_tree(c, (int)fc->is_2d);
	do_decompress_fax34(c, fc, f34ht);

done:
	destroy_fax34_huffman_tree(c, f34ht);
	if(fc) {
		de_free(c, fc->curr_row);
		de_free(c, fc->prev_row);
		de_free(c, fc->tmp_row_packed);
		de_free(c, fc);
	}
}
