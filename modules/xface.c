// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// X-Face, and "Compface intermediate format"

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_xface);
DE_DECLARE_MODULE(de_module_compfacei);

typedef struct localctx_struct {
	int reserved;
} lctx;

static void de_run_xface(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	de_free(c, d);
}

static int de_identify_xface(deark *c)
{
	return 0;
}

void de_module_xface(deark *c, struct deark_module_info *mi)
{
	mi->id = "xface";
	mi->desc = "X-Face";
	mi->run_fn = de_run_xface;
	mi->identify_fn = de_identify_xface;
	mi->flags |= DE_MODFLAG_NONWORKING;
}

// **************************************************************************
// Compface intermediate format
// **************************************************************************

struct compfacei_ctx {
	struct deark_bitmap *img;
	de_int64 imgpos_x, imgpos_y;

	de_int64 input_parse_pos;
	size_t tokenbuf_strlen;
	int token_numdigits;
	unsigned int token_val;
#define CFI_TOKENBUFLEN 32
	de_byte tokenbuf[CFI_TOKENBUFLEN];
};

static int cfi_is_whitespace(de_byte ch)
{
	return (ch==9 || ch==10 || ch==13 || ch==' ');
}
static int cfi_is_alnum(de_byte ch)
{
	return ((ch>='0' && ch<='9') ||
		(ch>='A' && ch<='Z') ||
		(ch>='a' && ch<='z'));
}

// On success, returns nonzero and
//  - Writes a NUL-terminated string to cfictx->tokenbuf
//  - Sets cfictx->tokenbuf_strlen
//  - Updates cfictx->input_parse_pos
static int cfi_get_next_token_lowlevel(deark *c, struct compfacei_ctx *cfictx)
{
	int retval = 0;
	de_byte ch;

	cfictx->tokenbuf_strlen = 0;

	// Read [whitespace][1 or more alphanumerics][whitespace][comma].
	// Save the alphanumerics in tokenbuf.

	ch = de_getbyte(cfictx->input_parse_pos++);

	// Skip whitespace
	// (Note that de_getbyte returns NUL bytes after the end of file,
	// which we don't count as whitespace, so this loop will definitely
	// end eventually.)
	while(cfi_is_whitespace(ch)) {
		ch = de_getbyte(cfictx->input_parse_pos++);
	}

	// Copy alphanumerics to tokenbuf
	while(cfi_is_alnum(ch)) {
		if(cfictx->tokenbuf_strlen >= CFI_TOKENBUFLEN-1) {
			goto done;
		}
		cfictx->tokenbuf[cfictx->tokenbuf_strlen++] = ch;
		ch = de_getbyte(cfictx->input_parse_pos++);
	}
	cfictx->tokenbuf[cfictx->tokenbuf_strlen] = '\0';
	if(cfictx->tokenbuf_strlen<4) {
		goto done;
	}

	// Skip whitespace
	while(cfi_is_whitespace(ch)) {
		ch = de_getbyte(cfictx->input_parse_pos++);
	}

	// Check for the terminating comma
	if(ch != ',') {
		goto done;
	}

	retval = 1;
done:
	if(!retval) {
		de_err(c, "Error parsing Compface format\n");
	}
	return retval;
}

// On success, returns nonzero and
//  - Sets cfictx->token_val, cfictx->token_numdigits
//  - [Does whatever cfi_get_next_token_lowlevel() does]
static int cfi_get_next_token(deark *c, struct compfacei_ctx *cfictx)
{
	int ret;

	ret = cfi_get_next_token_lowlevel(c, cfictx);
	if(!ret) return 0;

	// TODO: Make sure the format is correct.
	// Should be "0[Xx][2 or 4 hex digits]".

	// Most files have two bytes per token (0X????,0X????...), but some
	// have just one (0X??,0X??,...)
	if(cfictx->tokenbuf_strlen<=4)
		cfictx->token_numdigits = 2;
	else
		cfictx->token_numdigits = 4;

	cfictx->token_val = (unsigned int)de_strtoll((const char*)cfictx->tokenbuf, NULL, 0);
	return 1;
}

static void cfi_set_image_byte(deark *c, struct compfacei_ctx *cfictx, de_byte ch)
{
	unsigned int k;
	for(k=0; k<8; k++) {
		if(((ch>>(7-k))&0x1)==0) {
			de_bitmap_setpixel_gray(cfictx->img,
				cfictx->imgpos_x+(de_int64)k, cfictx->imgpos_y, 255);
		}
	}
	cfictx->imgpos_x += 8;
	if(cfictx->imgpos_x>=48) {
		cfictx->imgpos_x=0;
		cfictx->imgpos_y++;
	}
}

static void de_run_compfacei(deark *c, de_module_params *mparams)
{
	de_int64 image_bytes_processed = 0;
	struct compfacei_ctx *cfictx = NULL;

	cfictx = de_malloc(c, sizeof(struct compfacei_ctx));
	cfictx->img = de_bitmap_create(c, 48, 48, 1);

	while(1) {
		if(image_bytes_processed>=(48*48)/8) break;
		if(!cfi_get_next_token(c, cfictx)) {
			goto done;
		}
		if(cfictx->token_numdigits==2) {
			cfi_set_image_byte(c, cfictx, (de_byte)cfictx->token_val);
		}
		else { // Assume numdigits==4
			cfi_set_image_byte(c, cfictx, (de_byte)(cfictx->token_val>>8));
			cfi_set_image_byte(c, cfictx, (de_byte)(cfictx->token_val&0xff));
		}
		image_bytes_processed += cfictx->token_numdigits/2;
	}

	de_bitmap_write_to_file_finfo(cfictx->img, NULL, 0);
done:
	de_bitmap_destroy(cfictx->img);
	de_free(c, cfictx);
}

void de_module_compfacei(deark *c, struct deark_module_info *mi)
{
	mi->id = "compfacei";
	mi->desc = "Compface intermediate format";
	mi->run_fn = de_run_compfacei;
	mi->identify_fn = de_identify_none;
}
