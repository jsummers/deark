// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// PCPaint PIC and CLP format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int ver;
	struct deark_bitmap *img;
	de_int64 header_size;
	de_byte plane_info;
	de_byte palette_flag;
	de_byte video_mode;
	de_int64 edesc_orig;
	de_int64 edesc; // Equals either edesc_orig or edesc_palfile
	de_int64 esize_orig;
	de_int64 num_rle_blocks;
	de_int64 max_unc_bytes;
	dbuf *unc_pixels;

	dbuf *palfile;
	dbuf *read_pal_from_me; // Points to either c->infile or to palfile
	de_int64 edesc_palfile;
	de_int64 esize_palfile;
} lctx;

static int decode_egavga16(deark *c, lctx *d)
{
	de_byte tmpbuf[768];
	de_uint32 pal[16];
	de_int64 i, j;
	de_int64 k;
	de_int64 plane;
	de_byte z[4];
	de_int64 src_rowspan;
	de_int64 src_planespan;
	int palent;
	de_byte cr, cg, cb;

	// Read the palette
	if(d->edesc==0) {
		// No palette in file. Use standard palette.
		for(k=0; k<16; k++) {
			pal[k] = de_palette_pc16((int)k);
		}
	}
	else if(d->edesc==3) {
		// An EGA palette. Indexes into the standard EGA
		// 64-color palette.
		dbuf_read(d->read_pal_from_me, tmpbuf, 17, 16);
		for(k=0; k<16; k++) {
			pal[k] = de_palette_ega64(tmpbuf[k]);
		}
	}
	else { // assuming edesc==5
		dbuf_read(d->read_pal_from_me, tmpbuf, 17, 16*3);
		for(k=0; k<16; k++) {
			cr = de_palette_sample_6_to_8bit(tmpbuf[3*k+0]);
			cg = de_palette_sample_6_to_8bit(tmpbuf[3*k+1]);
			cb = de_palette_sample_6_to_8bit(tmpbuf[3*k+2]);
			pal[k] = DE_MAKE_RGB(cr, cg, cb);
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
	de_byte tmpbuf[768];
	de_uint32 pal[256];
	de_int64 i, j;
	de_int64 k;
	de_byte b;
	de_byte cr, cg, cb;

	de_dbg(c, "256-color image\n");

	// Read the palette
	if(d->edesc==0) {
		// No palette in file. Use standard palette.
		de_dbg(c, "No palette in file. Using standard palette.\n");

		for(i=0; i<256; i++) {
			pal[i] = de_palette_vga256((int)i);
		}
	}
	else {
		de_dbg(c, "Reading palette.\n");
		dbuf_read(d->read_pal_from_me, tmpbuf, 17, 768);
		for(k=0; k<256; k++) {
			cr = de_palette_sample_6_to_8bit(tmpbuf[3*k+0]);
			cg = de_palette_sample_6_to_8bit(tmpbuf[3*k+1]);
			cb = de_palette_sample_6_to_8bit(tmpbuf[3*k+2]);
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

	de_dbg(c, "pcpaint bilevel\n");

	if(!d->unc_pixels) return 0;

	// PC Paint's CGA and EGA 2-color modes used gray shade 170 instead of
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
	de_byte pal_id;
	de_byte border_col;

	de_dbg(c, "pcpaint cga4\n");

	if(!d->unc_pixels) return 0;

	if(d->edesc==1) {
		// Image includes information about which CGA 4-color palette it uses.

		// This assumes PIC format. That should be the case, since edesc will
		// be zero for CLP format (unless we are reading the palette from a separate
		// PIC file).
		pal_id = dbuf_getbyte(d->read_pal_from_me, 17);
		border_col = dbuf_getbyte(d->read_pal_from_me, 18);
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
	de_int64 k;

	end_of_this_block = pos + packed_data_size;

	while(pos<end_of_this_block) {
		x = de_getbyte(pos);
		pos++;
		if(x!=run_marker) {
			// An uncompressed part of the image
			dbuf_write(d->unc_pixels, &x, 1);
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
		for(k=0; k<run_length; k++) {
			dbuf_write(d->unc_pixels, &x, 1);
		}

		if(d->unc_pixels->len > d->max_unc_bytes) {
			de_err(c, "Too many uncompressed pixels\n");
			return 0;
		}
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

	// An emergency brake:
	d->max_unc_bytes = d->img->width * d->img->height;

	d->unc_pixels = dbuf_create_membuf(c, 16384);

	de_dbg(c, "pcpaint uncompress\n");
	pos = d->header_size;

	for(n=0; n<d->num_rle_blocks; n++) {
		de_dbg(c, "-- block %d --\n", (int)n);
		// start_of_this_block = pos;
		packed_block_size = de_getui16le(pos);
		// block size includes the 5-byte header, so it can't be < 5.
		if(packed_block_size<5) packed_block_size=5;
		end_of_this_block = pos + packed_block_size; // Remember where this block ends
		unpacked_block_size = de_getui16le(pos+2);
		run_marker = de_getbyte(pos+4);
		pos+=5;

		de_dbg(c, "packed block size (+5)=%d\n", (int)packed_block_size);
		de_dbg(c, "unpacked block size=%d\n", (int)unpacked_block_size);
		de_dbg(c, "run marker=0x%02x\n", (int)run_marker);

		if(!uncompress_block(c, d, pos, packed_block_size-5, run_marker)) {
			goto done;
		}

		pos = end_of_this_block;
	}
	retval = 1;

done:
	return retval;
}

// Figure out if we're supposed to read the palette from an alternate file.
// If so, open it and read a few fields from it. Modify settings so that
// we will read the palette from the alternate file.
// The palette file is assumed to be in PIC format.
static int do_read_alt_palette_file(deark *c, lctx *d)
{
	const char *palfn;

	palfn = de_get_option(c, "palfile");
	if(!palfn) return 1;

	de_dbg(c, "reading palette file %s\n", palfn);

	d->palfile = dbuf_open_input_file(c, palfn);
	if(!d->palfile) {
		return 0;
	}

	d->edesc_palfile = dbuf_getui16le(d->palfile, 13);
	d->esize_palfile = dbuf_getui16le(d->palfile, 15);

	if(d->edesc_palfile==0) {
		de_warn(c, "Palette file does not contain palette information.\n");
		dbuf_close(d->palfile);
		d->palfile = NULL;
		return 1;
	}

	d->edesc = d->edesc_palfile;
	d->read_pal_from_me = d->palfile;
	return 1;
}

static void de_run_pcpaint_pic(deark *c, lctx *d, const char *params)
{
	de_declare_fmt(c, "PCPaint PIC");

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
		de_err(c, "This version of PC Paint PIC is not supported\n");
		goto done;
	}

	d->video_mode = de_getbyte(12);
	d->edesc_orig = de_getui16le(13);
	d->esize_orig = de_getui16le(15);
	d->edesc = d->edesc_orig; // default

	de_dbg(c, "video_mode: 0x%02x\n",(int)d->video_mode);
	de_dbg(c, "edesc: %d\n",(int)d->edesc_orig);
	de_dbg(c, "esize: %d\n",(int)d->esize_orig);

	// extra data may be at position 17 (if esize>0)

	if(!do_read_alt_palette_file(c, d));

	d->num_rle_blocks = de_getui16le(17+d->esize_orig);

	d->header_size = 17 + d->esize_orig + 2;

	de_dbg(c, "rle blocks: %d\n", (int)d->num_rle_blocks);

	if(d->num_rle_blocks>0) {
		// Image is compressed.
		// TODO: It would be nice if we figured out whether we support this format
		// *before* we go to the trouble of uncompressing the pixels.
		uncompress_pixels(c, d);
	}
	else {
		d->unc_pixels = dbuf_open_input_subfile(c->infile, d->header_size,
			c->infile->len-d->header_size);
	}

	if(d->plane_info==0x01 && d->edesc==0) {
		// Expected video mode(s): 0x43, 0x45, 0x4f
		// CGA or EGA or VGA 2-color
		decode_bilevel(c, d);
	}
	else if(d->plane_info==0x02 && (d->edesc==0 || d->edesc==1)) {
		// Expected video mode(s): 0x41
		decode_cga4(c, d);
	}
	else if(d->plane_info==0x04 && d->edesc==3) {
		decode_egavga16(c, d);
	}
	else if(d->plane_info==0x08 && (d->edesc==0 || d->edesc==4)) {
		// Expected video mode(s): 0x4c
		decode_vga256(c, d);
	}
	else if((d->plane_info==0x04 || d->plane_info==0x31) &&
		(d->edesc==0 || d->edesc==3 || d->edesc==5))
	{
		// Expected video mode(s): 0x4d, 0x47
		decode_egavga16(c, d);
	}
	else {
		de_err(c, "This type of PC Paint PIC is not supported (evideo=0x%02x, bitsinf=0x%02x, edesc=%d)\n",
			d->video_mode, d->plane_info, (int)d->edesc);
		goto done;
	}

done:
	;
}

static void de_run_pcpaint_clp(deark *c, lctx *d, const char *params)
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
	d->edesc_orig = 0;
	d->edesc = 0;
	d->esize_orig = 0;

	if(!do_read_alt_palette_file(c, d)) goto done;

	if(is_compressed) {
		run_marker = de_getbyte(12);
		d->unc_pixels = dbuf_create_membuf(c, 16384);

		d->max_unc_bytes = d->img->width * d->img->height;

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

	// Documentation says bit_depth is simply the number of bits per pixel, but I've seen
	// files where it's 0x31, suggesting it uses "bitsinf"/"PlaneInfo" format.
	switch(d->plane_info) {
	case 1:
		decode_bilevel(c, d);
		break;
	case 2:
		decode_cga4(c, d);
		break;
	case 4:
	case 0x31:
		decode_egavga16(c, d);
		break;
	case 8:
		decode_vga256(c, d);
		break;
	default:
		de_err(c, "Unsupported bit depth (0x%02x)\n", (int)d->plane_info);
		goto done;
	}

done:
	;
}

// Dispatch to either pcpaint_pic or pcpaint_clp.
static void de_run_pcpaint(deark *c, const char *params)
{
	// 0=unknown, 1=pic, 2=clp
	int id = 0;
	const char *pcpaintfmt;
	de_byte buf[16];
	lctx *d;

	d = de_malloc(c, sizeof(lctx));

	de_dbg(c, "In pcpaint module\n");

	pcpaintfmt = de_get_option(c, "pcpaint:fmt");
	if(pcpaintfmt) {
		if(!de_strcmp(pcpaintfmt, "pic")) {
			id = 1;
		}
		else if(!de_strcmp(pcpaintfmt, "clp")) {
			id = 2;
		}
		else if(!de_strcmp(pcpaintfmt, "clip")) {
			id = 2;
		}
	}

	if(!id) {
		// File subtype not given by user. Try to detect it.
		de_read(buf, 0, 16);
		if(buf[0]==0x34 && buf[1]==0x12) {
			if(c->infile->len==0x1234) {
				// Pathological case where both formats could start with 0x1234.
				if(buf[10]==0xff) { // definitely a compressed CLP
					id = 2;
				}
				else {
					de_warn(c, "Format can't be reliably identified. Try \"-opt pcpaint:fmt=clp\" if necessary.\n");
					id = 1;
				}
			}
			else {
				id = 1;
			}
		}
		else {
			id = 2;
		}
	}

	// By default, read the palette from the main file. This may be overridden in
	// do_read_palette_file().
	d->read_pal_from_me = c->infile;

	if(id==2) {
		de_run_pcpaint_clp(c, d, params);
	}
	else {
		de_run_pcpaint_pic(c, d, params);
	}

	if(d->unc_pixels) dbuf_close(d->unc_pixels);
	if(d->palfile) dbuf_close(d->palfile);
	de_bitmap_destroy(d->img);
	de_free(c, d);
}

static int de_identify_pcpaint(deark *c)
{
	de_byte buf[12];

	de_read(buf, 0, 12);
	if(buf[0]==0x34 && buf[1]==0x12 && buf[11]==0xff) {
		return 90;
	}
	return 0;
}

void de_module_pcpaint(deark *c, struct deark_module_info *mi)
{
	mi->id = "pcpaint";
	mi->run_fn = de_run_pcpaint;
	mi->identify_fn = de_identify_pcpaint;
}
