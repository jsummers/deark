// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// PCPaint PIC and CLP format

#include <deark-config.h>
#include <deark-modules.h>

struct pal_info {
	de_int64 edesc;
	de_int64 esize;
	de_byte *data;
};

struct localctx_struct;
typedef struct localctx_struct lctx;

typedef int (*decoder_fn_type)(deark *c, lctx *d);

struct localctx_struct {
#define FMT_PIC 1
#define FMT_CLP 2
	int file_fmt;
	int ver;
	struct deark_bitmap *img;
	de_int64 header_size;
	de_byte plane_info;
	de_byte palette_flag;
	de_byte video_mode; // 0 = unknown
	struct pal_info pal_info_mainfile;
	struct pal_info pal_info_palfile;
	struct pal_info *pal_info_to_use; // Points to _mainfile or _palfile
	de_int64 num_rle_blocks;
	dbuf *unc_pixels;
	decoder_fn_type decoder_fn;
};

static void set_density(deark *c, lctx *d)
{
	switch(d->video_mode) {
	case 'A': // 320x200
	case 'B':
	case 'I':
	case 'J':
	case 'L':
		d->img->density_code = DE_DENSITY_UNK_UNITS;
		d->img->xdens = 240.0;
		d->img->ydens = 200.0;
		break;
	case 'H': // 720x348 (Hercules)
	case 'N':
		d->img->density_code = DE_DENSITY_UNK_UNITS;
		// Various sources suggest aspect ratios of 1.46, 1.55, 1.59, ...
		d->img->xdens = 155.0;
		d->img->ydens = 100.0;
		break;
	case 'E': // 640x350
	case 'F':
	case 'G':
		d->img->density_code = DE_DENSITY_UNK_UNITS;
		d->img->xdens = 480.0;
		d->img->ydens = 350.0;
		break;
	case 'K':
	case 'R':
		d->img->density_code = DE_DENSITY_UNK_UNITS;
		d->img->xdens = 480.0;
		d->img->ydens = 400.0;
		break;
	case 'C':
	case 'D':
		d->img->density_code = DE_DENSITY_UNK_UNITS;
		d->img->xdens = 480.0;
		d->img->ydens = 200.0;
		break;
	}
}

static int decode_text(deark *c, lctx *d)
{
	de_int64 width_in_chars;
	struct de_char_context *charctx = NULL;
	struct de_char_screen *screen;
	de_int64 i, j, k;
	de_byte ch, attr;
	int retval = 0;

	// TODO: This might not work for monochrome text mode (d->video_mode==0x32).

	width_in_chars = d->img->width / 2;

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->no_density = 1;
	charctx->nscreens = 1;
	charctx->screens = de_malloc(c, charctx->nscreens*sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));
	screen = charctx->screens[0];

	screen->width = width_in_chars;
	screen->height = d->img->height;

	de_dbg(c, "dimensions: %dx%d characters\n", (int)screen->width, (int)screen->height);

	if(screen->height<1) goto done;

	screen->cell_rows = de_malloc(c, screen->height * sizeof(struct de_char_cell*));

	for(j=0; j<screen->height; j++) {
		de_int64 j2;

		j2 = screen->height-1-j;
		screen->cell_rows[j2] = de_malloc(c, screen->width * sizeof(struct de_char_cell));

		for(i=0; i<screen->width; i++) {
			ch = dbuf_getbyte(d->unc_pixels, j*d->img->width + i*2);
			attr = dbuf_getbyte(d->unc_pixels, j*d->img->width + i*2 + 1);

			screen->cell_rows[j2][i].fgcol = (attr & 0x0f);
			screen->cell_rows[j2][i].bgcol = (attr & 0xf0) >> 4;
			screen->cell_rows[j2][i].codepoint = (de_int32)ch;
			screen->cell_rows[j2][i].codepoint_unicode = de_char_to_unicode(c, (de_int32)ch, DE_ENCODING_CP437_G);
		}
	}

	for(k=0; k<16; k++) {
		// TODO: Is this always the right palette? Maybe we can't ignore ->edesc
		charctx->pal[k] = de_palette_pc16((int)k);
	}

	de_char_output_to_file(c, charctx);

done:
	de_free_charctx(c, charctx);
	return retval;
}

static int decode_egavga16(deark *c, lctx *d)
{
	de_uint32 pal[16];
	de_int64 i, j;
	de_int64 k;
	de_int64 plane;
	de_byte z[4];
	de_int64 src_rowspan;
	de_int64 src_planespan;
	int palent;
	de_byte cr, cg, cb;

	de_dbg(c, "16-color EGA/VGA\n");
	de_memset(pal, 0, sizeof(pal));

	// Read the palette
	if(d->pal_info_to_use->edesc==0) {
		de_dbg(c, "No palette in file. Using standard 16-color palette.\n");
		for(k=0; k<16; k++) {
			pal[k] = de_palette_pc16((int)k);
		}
	}
	else if(d->pal_info_to_use->edesc==3) {
		// An EGA palette. Indexes into the standard EGA
		// 64-color palette.
		de_dbg(c, "Palette is 16 indices into standard EGA 64-color palette.\n");
		for(k=0; k<16; k++) {
			if(k >= d->pal_info_to_use->esize) break;
			pal[k] = de_palette_ega64(d->pal_info_to_use->data[k]);
			de_dbg2(c, "pal[%2d] = %2d (%3d,%3d,%3d)\n", (int)k, (int)d->pal_info_to_use->data[k],
				(int)DE_COLOR_R(pal[k]), (int)DE_COLOR_G(pal[k]), (int)DE_COLOR_B(pal[k]));
		}
	}
	else { // assuming edesc==5
		de_dbg(c, "Reading 16-color palette from file.\n");
		for(k=0; k<16; k++) {
			if(3*k+2 >= d->pal_info_to_use->esize) break;
			cr = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+0]);
			cg = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+1]);
			cb = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+2]);
			pal[k] = DE_MAKE_RGB(cr, cg, cb);
			de_dbg2(c, "pal[%2d] = (%3d,%3d,%3d)\n", (int)k, (int)cr, (int)cg, (int)cb);
		}
	}

	if(d->plane_info==0x31) {
		src_rowspan = (d->img->width +7)/8;
		src_planespan = src_rowspan*d->img->height;
	}
	else {
		src_rowspan = (d->img->width +1)/2;
		src_planespan = 0;
	}

	d->img->bytes_per_pixel = 3;
	d->img->flipped = 1;

	for(j=0; j<d->img->height; j++) {
		for(i=0; i<d->img->width; i++) {
			if(d->plane_info==0x31) {
				for(plane=0; plane<4; plane++) {
					z[plane] = de_get_bits_symbol(d->unc_pixels, 1, plane*src_planespan + j*src_rowspan, i);
				}
				palent = z[0] + 2*z[1] + 4*z[2] + 8*z[3];
			}
			else {
				palent = de_get_bits_symbol(d->unc_pixels, 4, j*src_rowspan, i);
			}
			de_bitmap_setpixel_rgb(d->img, i, j, pal[palent]);
		}
	}

	de_bitmap_write_to_file(d->img, NULL);
	return 1;
}

static int decode_vga256(deark *c, lctx *d)
{
	de_uint32 pal[256];
	de_int64 i, j;
	de_int64 k;
	de_byte b;
	de_byte cr, cg, cb;

	de_dbg(c, "256-color image\n");
	de_memset(pal, 0, sizeof(pal));

	// Read the palette
	if(d->pal_info_to_use->edesc==0) {
		de_dbg(c, "No palette in file. Using standard 256-color palette.\n");
		for(i=0; i<256; i++) {
			pal[i] = de_palette_vga256((int)i);
		}
	}
	else {
		de_dbg(c, "Reading palette.\n");
		for(k=0; k<256; k++) {
			if(3*k+2 >= d->pal_info_to_use->esize) break;
			cr = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+0]);
			cg = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+1]);
			cb = de_palette_sample_6_to_8bit(d->pal_info_to_use->data[3*k+2]);
			pal[k] = DE_MAKE_RGB(cr, cg, cb);
		}
	}

	d->img->bytes_per_pixel = 3;
	d->img->flipped = 1;

	for(j=0; j<d->img->height; j++) {
		for(i=0; i<d->img->width; i++) {
			b = dbuf_getbyte(d->unc_pixels, j*d->img->width + i);
			de_bitmap_setpixel_rgb(d->img, i, j, pal[b]);
		}
	}

	de_bitmap_write_to_file(d->img, NULL);
	return 1;
}

static int decode_bilevel(deark *c, lctx *d)
{
	de_int64 i, j;
	de_byte b;
	de_int64 src_rowspan;
	de_byte grayshade1;

	de_dbg(c, "bilevel image\n");

	if(!d->unc_pixels) return 0;

	// PCPaint's CGA and EGA 2-color modes used gray shade 170 instead of
	// white (255). Maybe they should be interpreted as white, but for
	// historical accuracy I'll go with gray170.
	if(d->video_mode==0x43 || d->video_mode==0x45) {
		grayshade1 = 170;
	}
	else {
		grayshade1 = 255;
	}

	d->img->bytes_per_pixel = 1;
	d->img->flipped = 1;

	src_rowspan = (d->img->width +7)/8;
	for(j=0; j<d->img->height; j++) {
		for(i=0; i<d->img->width; i++) {
			b = de_get_bits_symbol(d->unc_pixels, 1, j*src_rowspan, i);
			de_bitmap_setpixel_gray(d->img, i, j, b?grayshade1:0);
		}
	}

	de_bitmap_write_to_file(d->img, NULL);
	return 1;
}

static int decode_cga4(deark *c, lctx *d)
{
	de_int64 i, j;
	de_int64 k;
	de_byte b;
	de_int64 src_rowspan;
	de_uint32 pal[4];
	de_byte pal_id = 0;
	de_byte border_col = 0;

	de_dbg(c, "CGA 4-color\n");

	if(!d->unc_pixels) return 0;

	if(d->pal_info_to_use->edesc==1) {
		// Image includes information about which CGA 4-color palette it uses.

		// This assumes PIC format. That should be the case, since edesc will
		// be zero for CLP format (unless we are reading the palette from a separate
		// PIC file).
		if(d->pal_info_to_use->esize >= 1)
			pal_id = d->pal_info_to_use->data[0];
		if(d->pal_info_to_use->esize >= 2)
			border_col = d->pal_info_to_use->data[1];
		de_dbg(c, "pal_id=0x%02x border=0x%02x\n", pal_id, border_col);

		for(k=0; k<4; k++) {
			pal[k] = de_palette_pcpaint_cga4(pal_id, (int)k);
		}

		// Replace the first palette color with the border/background color.
		pal[0] = de_palette_pc16(border_col);
	}
	else {
		// No palette specified in the file. Use palette #2 by default.
		for(k=0; k<4; k++) {
			pal[k] = de_palette_pcpaint_cga4(2, (int)k);
		}
	}

	d->img->bytes_per_pixel = 3;
	d->img->flipped = 1;

	src_rowspan = (d->img->width +3)/4;
	for(j=0; j<d->img->height; j++) {
		for(i=0; i<d->img->width; i++) {
			b = de_get_bits_symbol(d->unc_pixels, 2, j*src_rowspan, i);
			de_bitmap_setpixel_rgb(d->img, i, j, pal[b]);
		}
	}

	de_bitmap_write_to_file(d->img, NULL);
	return 1;
}

// decompress one block
// Writes uncompressed bytes to d->unc_pixels.
// packed_data_size does not include header size.
// Returns 0 on error.
static int uncompress_block(deark *c, lctx *d,
	de_int64 pos, de_int64 packed_data_size, de_byte run_marker)
{
	de_int64 end_of_this_block;
	de_byte x;
	de_int64 run_length;

	end_of_this_block = pos + packed_data_size;

	while(pos<end_of_this_block) {
		x = de_getbyte(pos);
		pos++;
		if(x!=run_marker) {
			// An uncompressed part of the image
			dbuf_writebyte(d->unc_pixels, x);
			continue;
		}

		// A compressed run.
		x = de_getbyte(pos);
		pos++;
		if(x!=0) {
			// If nonzero, this byte is the run length.
			run_length = (de_int64)x;
		}
		else {
			// If zero, it is followed by a 16-bit run length
			run_length = de_getui16le(pos);
			pos+=2;
		}

		// Read the byte value to repeat (run_length) times.
		x = de_getbyte(pos);
		pos++;
		//de_dbg(c, "run of length %d (value 0x%02x)\n", (int)run_length, (int)x);
		dbuf_write_run(d->unc_pixels, x, run_length);
	}

	return 1;
}

// Decompress multiple blocks of compressed pixels.
// This is for PIC format only.
static int uncompress_pixels(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 n;
	de_int64 packed_block_size;
	de_int64 unpacked_block_size;
	de_byte run_marker;
	int retval = 1;
	de_int64 end_of_this_block;

	if(d->num_rle_blocks<1) {
		// Not compressed
		return 1;
	}

	d->unc_pixels = dbuf_create_membuf(c, 16384);
	dbuf_set_max_length(d->unc_pixels, d->img->width * d->img->height);

	de_dbg(c, "uncompressing image\n");
	pos = d->header_size;

	for(n=0; n<d->num_rle_blocks; n++) {
		de_dbg3(c, "-- block %d --\n", (int)n);
		// start_of_this_block = pos;
		packed_block_size = de_getui16le(pos);
		// block size includes the 5-byte header, so it can't be < 5.
		if(packed_block_size<5) packed_block_size=5;
		end_of_this_block = pos + packed_block_size; // Remember where this block ends
		unpacked_block_size = de_getui16le(pos+2);
		run_marker = de_getbyte(pos+4);
		pos+=5;

		de_dbg3(c, "packed block size (+5)=%d\n", (int)packed_block_size);
		de_dbg3(c, "unpacked block size=%d\n", (int)unpacked_block_size);
		de_dbg3(c, "run marker=0x%02x\n", (int)run_marker);

		if(!uncompress_block(c, d, pos, packed_block_size-5, run_marker)) {
			goto done;
		}

		pos = end_of_this_block;
	}

	de_dbg(c, "uncompressed to %d bytes\n", (int)d->unc_pixels->len);
	retval = 1;

done:
	return retval;
}

static int do_read_palette_data(deark *c, lctx *d, dbuf *f, struct pal_info *palinfo)
{
	palinfo->edesc = dbuf_getui16le(f, 13);
	palinfo->esize = dbuf_getui16le(f, 15);
	palinfo->data = de_malloc(c, palinfo->esize);
	dbuf_read(f, palinfo->data, 17, palinfo->esize);
	return 1;
}

// Figure out if we're supposed to read the palette from an alternate file.
// If so, open it and read a few fields from it. Modify settings so that
// we will read the palette from the alternate file.
// The palette file is assumed to be in PIC format.
static int do_read_alt_palette_file(deark *c, lctx *d)
{
	const char *palfn;
	dbuf *palfile = NULL;
	int retval = 0;
	de_int64 magic;

	palfn = de_get_ext_option(c, "palfile");
	if(!palfn) palfn = de_get_ext_option(c, "file2");
	if(!palfn) {
		retval = 1;
		goto done;
	}

	de_dbg(c, "reading palette file %s\n", palfn);

	palfile = dbuf_open_input_file(c, palfn);
	if(!palfile) {
		goto done;
	}

	magic = dbuf_getui16le(palfile, 0);
	if(magic!=0x1234) {
		de_err(c, "Palette file is not in PIC format.\n");
		goto done;
	}

	do_read_palette_data(c, d, palfile, &d->pal_info_palfile);

	if(d->pal_info_palfile.edesc==0) {
		de_warn(c, "Palette file does not contain palette information.\n");
		retval = 1;
		goto done;
	}

	d->pal_info_to_use = &d->pal_info_palfile;
	retval = 1;

done:
	dbuf_close(palfile);
	return retval;
}

// Determine if we can decode this type of image.
// Sets d->decoder_fn.
// If image can't be decoded, prints an error and returns 0.
static int do_set_up_decoder(deark *c, lctx *d)
{
	de_int64 edesc;

	edesc = d->pal_info_to_use->edesc; // For brevity

	if(d->video_mode>='0' && d->video_mode<='3') {
		d->decoder_fn = decode_text;
	}
	else if(d->plane_info==0x01 && edesc==0) {
		// Expected video mode(s): 0x43, 0x45, 0x4f
		// CGA or EGA or VGA 2-color
		d->decoder_fn = decode_bilevel;
	}
	else if(d->plane_info==0x02 && (edesc==0 || edesc==1)) {
		// Expected video mode(s): 0x41
		d->decoder_fn = decode_cga4;
	}
	else if(d->plane_info==0x04 && edesc==3) {
		d->decoder_fn = decode_egavga16;
	}
	else if((d->plane_info==0x04 || d->plane_info==0x31) &&
		(edesc==0 || edesc==3 || edesc==5))
	{
		// Expected video mode(s): 0x4d, 0x47
		d->decoder_fn = decode_egavga16;
	}
	else if(d->plane_info==0x08 && (edesc==0 || edesc==4)) {
		// Expected video mode(s): 0x4c
		d->decoder_fn = decode_vga256;
	}

	if(d->decoder_fn) {
		return 1;
	}

	de_err(c, "This type of PCPaint %s is not supported (evideo=0x%02x, bitsinf=0x%02x, edesc=%d)\n",
		(d->file_fmt==FMT_CLP) ? "CLP" : "PIC",
		d->video_mode, d->plane_info, (int)edesc);

	return 0;
}

static void de_run_pcpaint_pic(deark *c, lctx *d, de_module_params *mparams)
{
	de_declare_fmt(c, "PCPaint PIC");

	// Note that this bitmap will not be rendered in the case of character
	// graphics, but it's still needed to store the width and height.
	d->img = de_bitmap_create_noinit(c);

	d->img->width = de_getui16le(2);
	d->img->height = de_getui16le(4);
	de_dbg(c, "dimensions = %dx%d\n", (int)d->img->width, (int)d->img->height);

	d->plane_info = de_getbyte(10);
	d->palette_flag = de_getbyte(11);

	de_dbg(c, "plane info: 0x%02x\n",(int)d->plane_info);
	de_dbg(c, "palette flag: 0x%02x\n",(int)d->palette_flag);

	if(d->palette_flag==0xff) {
		d->ver = 2;
	}

	if(d->ver!=2) {
		de_err(c, "This version of PCPaint PIC is not supported\n");
		goto done;
	}

	d->video_mode = de_getbyte(12);
	do_read_palette_data(c, d, c->infile, &d->pal_info_mainfile);

	de_dbg(c, "video_mode: 0x%02x\n",(int)d->video_mode);
	de_dbg(c, "edesc: %d\n",(int)d->pal_info_mainfile.edesc);
	de_dbg(c, "esize: %d\n",(int)d->pal_info_mainfile.esize);

	set_density(c, d);

	d->pal_info_to_use = &d->pal_info_mainfile; // tentative
	if(!do_read_alt_palette_file(c, d)) goto done;

	d->num_rle_blocks = de_getui16le(17+d->pal_info_mainfile.esize);

	d->header_size = 17 + d->pal_info_mainfile.esize + 2;

	de_dbg(c, "rle blocks: %d\n", (int)d->num_rle_blocks);

	if(!do_set_up_decoder(c, d)) goto done;

	if(d->num_rle_blocks>0) {
		// Image is compressed.
		uncompress_pixels(c, d);
	}
	else {
		// Image is uncompressed.
		d->unc_pixels = dbuf_open_input_subfile(c->infile, d->header_size,
			c->infile->len-d->header_size);
	}

	d->decoder_fn(c, d);

done:
	;
}

static void de_run_pcpaint_clp(deark *c, lctx *d, de_module_params *mparams)
{
	de_int64 file_size;
	de_byte run_marker;
	int is_compressed;

	de_declare_fmt(c, "PCPaint CLP");

	d = de_malloc(c, sizeof(lctx));

	d->img = de_bitmap_create_noinit(c);

	file_size = de_getui16le(0);
	d->img->width = de_getui16le(2);
	d->img->height = de_getui16le(4);
	d->plane_info = de_getbyte(10);

	if(file_size != c->infile->len) {
		if(file_size==0x1234) {
			de_warn(c, "This is probably a .PIC file, not a CLIP file.\n");
		}
		else {
			de_warn(c, "Reported file size (%d) does not equal actual file size (%d). "
				"Format may not be correct.\n", (int)file_size, (int)c->infile->len);
		}
	}

	is_compressed = (d->plane_info==0xff);

	if(is_compressed) {
		d->header_size = 13;
		d->plane_info = de_getbyte(11);
	}
	else {
		d->header_size = 11;
	}

	de_dbg(c, "reported file size=%d, width=%d, height=%d, compressed=%d, bits/planes=0x%02x\n",
		(int)file_size, (int)d->img->width, (int)d->img->height, (int)is_compressed, (int)d->plane_info);


	// The colors probably won't be right, but we have no way to tell what palette
	// is used by a CLP image.
	d->video_mode = 0;
	d->pal_info_mainfile.edesc = 0;
	d->pal_info_mainfile.esize = 0;

	d->pal_info_to_use = &d->pal_info_mainfile; // tentative
	if(!do_read_alt_palette_file(c, d)) goto done;

	if(!do_set_up_decoder(c, d)) goto done;

	if(is_compressed) {
		run_marker = de_getbyte(12);
		d->unc_pixels = dbuf_create_membuf(c, 16384);
		dbuf_set_max_length(d->unc_pixels, d->img->width * d->img->height);

		if(!uncompress_block(c, d, d->header_size,
			c->infile->len - d->header_size, run_marker))
		{
			goto done;
		}
	}
	else {
		// Uncompressed.
		d->unc_pixels = dbuf_open_input_subfile(c->infile, 11, c->infile->len-11);
	}

	d->decoder_fn(c, d);

done:
	;
}

// Dispatch to either pcpaint_pic or pcpaint_clp.
static void de_run_pcpaint(deark *c, de_module_params *mparams)
{
	// 0=unknown, 1=pic, 2=clp
	const char *pcpaintfmt;
	de_byte buf[16];
	lctx *d;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "In pcpaint module\n");

	pcpaintfmt = de_get_ext_option(c, "pcpaint:fmt");
	if(pcpaintfmt) {
		if(!de_strcmp(pcpaintfmt, "pic")) {
			d->file_fmt = FMT_PIC;
		}
		else if(!de_strcmp(pcpaintfmt, "clp")) {
			d->file_fmt = FMT_CLP;
		}
		else if(!de_strcmp(pcpaintfmt, "clip")) {
			d->file_fmt = FMT_CLP;
		}
	}

	if(!d->file_fmt) {
		// File subtype not given by user. Try to detect it.
		de_read(buf, 0, 16);
		if(buf[0]==0x34 && buf[1]==0x12) {
			if(c->infile->len==0x1234) {
				// Pathological case where both formats could start with 0x1234.
				if(buf[10]==0xff) { // definitely a compressed CLP
					d->file_fmt = FMT_CLP;
				}
				else {
					de_warn(c, "Format can't be reliably identified. Try \"-opt pcpaint:fmt=clp\" if necessary.\n");
					d->file_fmt = FMT_PIC;
				}
			}
			else {
				d->file_fmt = FMT_PIC;
			}
		}
		else {
			d->file_fmt = FMT_CLP;
		}
	}

	if(d->file_fmt==FMT_CLP) {
		de_run_pcpaint_clp(c, d, mparams);
	}
	else {
		de_run_pcpaint_pic(c, d, mparams);
	}

	if(d->unc_pixels) dbuf_close(d->unc_pixels);
	de_bitmap_destroy(d->img);
	de_free(c, d);
}

static int de_identify_pcpaint(deark *c)
{
	de_byte buf[12];
	int pic_ext, clp_ext;
	de_int64 x;

	pic_ext = de_input_file_has_ext(c, "pic");

	de_read(buf, 0, 12);
	if(buf[0]==0x34 && buf[1]==0x12 && buf[11]==0xff) {
		return pic_ext ? 100 : 50;
	}

	clp_ext = de_input_file_has_ext(c, "clp");
	if(clp_ext) {
		x = de_getui16le_direct(&buf[0]);
		if(x==c->infile->len) {
			return 50;
		}
	}

	return 0;
}

void de_module_pcpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcpaint";
	mi->run_fn = de_run_pcpaint;
	mi->identify_fn = de_identify_pcpaint;
}
