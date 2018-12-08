// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// X-Face, and "Compface intermediate format"

#include <deark-config.h>
#include <deark-private.h>

DE_DECLARE_MODULE(de_module_xface);
DE_DECLARE_MODULE(de_module_compfacei);

// **************************************************************************
// X-Face format
// **************************************************************************

static int has_x_header(dbuf *f)
{
	char b[8];

	dbuf_read(f, (u8*)b, 0, 8);
	if((b[0]=='X' || b[0]=='x') &&
		(b[1]=='-') &&
		(b[2]=='F' || b[2]=='f') &&
		(b[3]=='A' || b[3]=='a') &&
		(b[4]=='C' || b[4]=='c') &&
		(b[5]=='E' || b[5]=='e') &&
		(b[6]==':') &&
		(b[7]==' ' || b[7]=='\t'))
	{
		return 1;
	}
	return 0;
}

#include "../foreign/uncompface.h"

static void de_run_xface(deark *c, de_module_params *mparams)
{
	uncompface_main(c);
}

static int de_identify_xface(deark *c)
{
	int has_ext;
	int has_hdr;

	has_hdr = has_x_header(c->infile);
	has_ext = de_input_file_has_ext(c, "xface");
	if(has_hdr && has_ext) return 100;
	if(has_hdr) return 80;
	if(has_ext) return 5;
	return 0;
}

void de_module_xface(deark *c, struct deark_module_info *mi)
{
	mi->id = "xface";
	mi->desc = "X-Face icon/avatar";
	mi->run_fn = de_run_xface;
	mi->identify_fn = de_identify_xface;
}

// **************************************************************************
// Compface intermediate format
// **************************************************************************

struct compfacei_ctx {
	de_bitmap *img;
	i64 imgpos_x, imgpos_y;

	i64 input_parse_pos;
	size_t tokenbuf_strlen;
	int token_numdigits;
	unsigned int token_val;
#define CFI_TOKENBUFLEN 32
	u8 tokenbuf[CFI_TOKENBUFLEN];
};

static int cfi_is_whitespace(u8 ch)
{
	return (ch==9 || ch==10 || ch==13 || ch==' ');
}
static int cfi_is_alnum(u8 ch)
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
	u8 ch;

	cfictx->tokenbuf_strlen = 0;

	// Read [whitespace][1 or more alphanumerics][whitespace][comma].
	// Save the alphanumerics in tokenbuf.

	ch = de_getbyte(cfictx->input_parse_pos++);

	// Skip whitespace
	// (Note that de_getbyte returns NUL bytes after the end of file,
	// and NUL doesn't count as whitespace, so this loop will definitely
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
		de_err(c, "Error parsing Compface format");
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

static void cfi_set_image_byte(deark *c, struct compfacei_ctx *cfictx, u8 ch)
{
	unsigned int k;
	for(k=0; k<8; k++) {
		if(((ch>>(7-k))&0x1)==0) {
			de_bitmap_setpixel_gray(cfictx->img,
				cfictx->imgpos_x+(i64)k, cfictx->imgpos_y, 255);
		}
	}
	cfictx->imgpos_x += 8;
	if(cfictx->imgpos_x>=XFACE_WIDTH) {
		cfictx->imgpos_x=0;
		cfictx->imgpos_y++;
	}
}

static void de_run_compfacei(deark *c, de_module_params *mparams)
{
	i64 image_bytes_processed = 0;
	struct compfacei_ctx *cfictx = NULL;

	cfictx = de_malloc(c, sizeof(struct compfacei_ctx));
	cfictx->img = de_bitmap_create(c, XFACE_WIDTH, XFACE_HEIGHT, 1);

	while(1) {
		if(image_bytes_processed>=(XFACE_WIDTH*XFACE_HEIGHT)/8) break;
		if(!cfi_get_next_token(c, cfictx)) {
			goto done;
		}
		if(cfictx->token_numdigits==2) {
			cfi_set_image_byte(c, cfictx, (u8)cfictx->token_val);
		}
		else { // Assume numdigits==4
			cfi_set_image_byte(c, cfictx, (u8)(cfictx->token_val>>8));
			cfi_set_image_byte(c, cfictx, (u8)(cfictx->token_val&0xff));
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
}
