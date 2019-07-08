// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Amiga Workbench icons, including "Newicons" and "Glowicons" formats

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_amigaicon);

typedef struct localctx_struct {
	i64 icon_revision;
	u8 icon_type;
	int has_drawerdata;
	int has_toolwindow;
	int has_defaulttool;
	int has_tooltypes;

	i64 num_main_icons;
	i64 main_icon_pos[2];

	// Newicons-specific data
	int has_newicons;
	dbuf *newicons_data[2];
	u8 pending_data;
	int pending_data_bits_used;
	int newicons_bits_per_pixel;
	int newicons_line_count;

	// Glowicons-specific data
	int has_glowicons;
	i64 glowicons_pos;
	i64 glowicons_width, glowicons_height;
	u32 glowicons_palette[256];
} lctx;

static const u32 rev1pal[4] = { 0x55aaff,0x000000,0xffffff,0xff8800 }; // http://krashan.ppa.pl/articles/amigaicons/
//static const u32 rev1pal[4] = { 0x0055aa,0x000020,0xffffff,0xff8a00 }; // Netpbm

static const u32 rev2pal[4] = { 0x959595,0xffffff,0x000000,0x3b67a2 }; // http://krashan.ppa.pl/articles/amigaicons/
//static const u32 rev2pal[4] = { 0xaaaaaa,0xffffff,0x000000,0x556699 }; // XnView

static const u32 magicwbpal[8] = {
	0x959595,0x7b7b7b,0xffffff,0xaa907c,0x000000,0xafafaf,0x3b67a2,0xffa997 // http://krashan.ppa.pl/articles/amigaicons/ fixed? (& Wikipedia)
	//0xaaaaaa,0x999999,0xffffff,0xbbaa99,0x000000,0xbbbbbb,0x556699,0xffbbaa // XnView
};

static void do_newicons_append_bit(deark *c, lctx *d, dbuf *f, u8 b)
{
	if(d->pending_data_bits_used==0) {
		d->pending_data = 0;
	}
	d->pending_data = (d->pending_data<<1) | b;
	d->pending_data_bits_used++;

	if(d->newicons_line_count==0) {
		// We're still reading palette samples, which are always 8 bits.
		if(d->pending_data_bits_used==8) {
			dbuf_writebyte(f, d->pending_data);
			d->pending_data_bits_used=0;
		}
		return;
	}

	if(d->pending_data_bits_used >= d->newicons_bits_per_pixel) {
		dbuf_writebyte(f, d->pending_data);
		d->pending_data_bits_used=0;
	}
}

// Decode one NewIcons image. (There are usually two such images per file.)
// The raw data from the relevant ToolTypes table items must first be
// written to 'f'.
static void do_decode_newicons(deark *c, lctx *d,
	dbuf *f, int newicons_num)
{
	u8 trns_code, width_code, height_code;
	u8 b0, b1, tmpb;
	de_bitmap *img = NULL;
	int has_trns;
	i64 ncolors;
	dbuf *decoded = NULL;
	i64 srcpos;
	i64 bitmap_start_pos = 0;
	i64 i;
	i64 rle_len;
	u32 pal[256];

	de_dbg(c, "decoding NewIcons[%d], len=%"I64_FMT, newicons_num, f->len);
	de_dbg_indent(c, 1);

	trns_code = dbuf_getbyte(f, 0);
	has_trns = (trns_code=='B');
	width_code = dbuf_getbyte(f, 1);
	height_code = dbuf_getbyte(f, 2);

	b0 = dbuf_getbyte(f, 3);
	b1 = dbuf_getbyte(f, 4);
	ncolors = ((((i64)b0)-0x21)<<6) + (((i64)b1)-0x21);
	if(ncolors<1) ncolors=1;
	if(ncolors>256) ncolors=256;

	img = de_bitmap_create_noinit(c);
	img->width = (i64)width_code - 0x21;
	img->height = (i64)height_code - 0x21;
	img->bytes_per_pixel = 4;

	de_dbg_dimensions(c, img->width, img->height);
	de_dbg(c, "transparency: %d", has_trns);
	de_dbg(c, "colors: %d", (int)ncolors);

	decoded = dbuf_create_membuf(c, 2048, 0);

	d->pending_data = 0;
	d->pending_data_bits_used = 0;

	d->newicons_bits_per_pixel = (int)de_log2_rounded_up(ncolors);

	// We decode both the palette and the bitmap into the same buffer, and
	// keep track of where in the buffer the bitmap starts.

	// Count the number of lines (EOL represented by 0x00 byte).
	// This is only needed because the bitmap starts on the second line.
	d->newicons_line_count=0;

	for(srcpos=5; srcpos<f->len; srcpos++) {
		b0 = f->membuf_buf[srcpos];
		if((b0>=0x20 && b0<=0x6f) || (b0>=0xa1 && b0<=0xd0)) {
			if(b0<=0x6f) b1 = b0-0x20;
			else b1 = 0x50 + (b0-0xa1);

			for(i=0; i<7; i++) {
				tmpb = (b1>>(6-i))&0x01;
				do_newicons_append_bit(c, d, decoded, tmpb);
			}
		}
		else if(b0>=0xd1) {
			// RLE compression for "0" bits
			tmpb = 0;
			rle_len = 7*(i64)(b0-0xd0);
			for(i=0; i<rle_len; i++) {
				do_newicons_append_bit(c, d, decoded, tmpb);
			}
		}
		else if(b0==0x00) {
			// End of a line.
			// Throw away any bits we've decoded that haven't been used yet.
			d->pending_data_bits_used = 0;

			if(d->newicons_line_count==0) {
				// The bitmap will start at this position. Remember that.
				bitmap_start_pos = decoded->len;
			}
			d->newicons_line_count++;
		}
	}

	de_dbg(c, "decompressed to %d bytes", (int)decoded->len);

	// The first ncolors*3 bytes are the palette
	de_dbg2(c, "NewIcons palette");
	de_dbg_indent(c, 1);
	for(i=0; i<ncolors; i++) {
		if(i>255) break;
		pal[i] = dbuf_getRGB(decoded, i*3, 0);

		// Educated guess: If the transparency flag is set, it means
		// palette entry 0 is transparent.
		if(i==0 && has_trns)
			pal[i] = DE_SET_ALPHA(pal[i], 0x00);

		de_dbg_pal_entry(c, i, pal[i]);
	}
	de_dbg_indent(c, -1);

	de_convert_image_paletted(decoded, bitmap_start_pos,
		8, img->width, pal, img, 0);
	de_bitmap_write_to_file(img, c->filenames_from_file?"n":NULL,
		d->has_glowicons?DE_CREATEFLAG_IS_AUX:0);

	if(decoded) dbuf_close(decoded);
	if(img) de_bitmap_destroy(img);
	de_dbg_indent(c, -1);
}

// Read enough of a main icon's header to determine how many bytes it uses.
static void get_main_icon_size(deark *c, lctx *d, i64 pos, i64 *pbytesused)
{
	i64 width, height;
	i64 depth;
	i64 src_rowspan, src_planespan;

	width = de_getu16be(pos+4);
	height = de_getu16be(pos+6);
	depth = de_getu16be(pos+8);
	src_rowspan = ((width+15)/16)*2;
	src_planespan = src_rowspan * height;

	*pbytesused = 20 + src_planespan * depth;
}

static int do_read_main_icon(deark *c, lctx *d,
	i64 pos, i64 icon_index)
{
	i64 width, height;
	i64 depth;
	i64 src_rowspan, src_planespan;
	i64 i, j, plane;
	int retval = 0;
	de_bitmap *img = NULL;
	u8 b, b1;
	u32 pal[256];

	de_dbg(c, "main icon #%d at %"I64_FMT, (int)icon_index, pos);
	de_dbg_indent(c, 1);

	// 20-byte header, followed by one or more bitmap "planes".
	width = de_getu16be(pos+4);
	height = de_getu16be(pos+6);
	depth = de_getu16be(pos+8);
	de_dbg_dimensions(c, width, height);
	de_dbg(c, "depth: %d", (int)depth);

	if(depth<1 || depth>8) {
		de_err(c, "Unsupported bit depth (%d)", (int)depth);
		goto done;
	}

	src_rowspan = ((width+15)/16)*2;
	src_planespan = src_rowspan * height;

	img = de_bitmap_create(c, width, height, 3);

	// Figure out what palette to use

	// Start with a meaningless grayscale palette.
	de_make_grayscale_palette(pal, 256, 0x0);

	if(depth==1) {
		// The only 1-bit images I've seen are dummy images.
		// I don't know how they're supposed to be handled, but this should do.
		pal[0] = DE_STOCKCOLOR_BLACK;
		pal[1] = DE_STOCKCOLOR_WHITE;
		if(!d->has_newicons && !d->has_glowicons) {
			de_warn(c, "Don't know how to handle 1-bit images");
		}
	}
	else if(d->icon_revision==0 && depth==2) {
		for(i=0; i<4; i++) pal[i] = rev1pal[i];
	}
	else if(depth==2) {
		for(i=0; i<4; i++) pal[i] = rev2pal[i];
	}
	else if(depth==3) {
		for(i=0; i<8; i++) pal[i] = magicwbpal[i];
	}
	else if(depth==4) {
		// ???
		for(i=0; i<16; i++) pal[i] = magicwbpal[i>>1];
	}
	else if(depth==8) {
		// Don't ask me. Just doing what other apps seem to do.
		for(i=0; i<256; i++) pal[i] = magicwbpal[i>>5];
	}
	else {
		de_warn(c, "Don't know how to handle images with bit depth %d", (int)depth);
	}

	pos += 20;

	for(j=0; j<height; j++) {
		for(i=0; i<width; i++) {
			b = 0x00;
			for(plane=0; plane<depth; plane++) {
				b1 = de_get_bits_symbol(c->infile, 1, pos+plane*src_planespan + j*src_rowspan, i);
				b = (b<<1) | b1;
			}
			de_bitmap_setpixel_rgb(img, i, j, pal[b]);
		}
	}

	de_bitmap_write_to_file(img, NULL, (d->has_newicons||d->has_glowicons)?DE_CREATEFLAG_IS_AUX:0);

	retval = 1;

done:
	de_bitmap_destroy(img);
	de_dbg_indent(c, -1);
	return retval;
}

static void do_one_tooltype(deark *c, lctx *d, i64 tpos, i64 tlen)
{
	int newicons_num;
	i64 n;
	struct de_stringreaderdata *ttstr = NULL;

	n = de_min_int(tlen, 64);
	ttstr = dbuf_read_string(c->infile, tpos, n, n, 0, DE_ENCODING_ASCII);
	de_dbg(c, "data: \"%s\"", ucstring_getpsz_d(ttstr->str));

	// The rest of this function is for identifying and recording NewIcons data.

	if(tlen<5) {
		// Too small to contain NewIcons data.
		goto done;
	}

	newicons_num = -1;

	if(ttstr->sz[0]=='I' && ttstr->sz[1]=='M' && ttstr->sz[3]=='=') {
		if(ttstr->sz[2]=='1') newicons_num = 0;
		else if(ttstr->sz[2]=='2') newicons_num = 1;
	}
	if(newicons_num == -1) {
		goto done;
	}

	d->has_newicons = 1;

	// Write NewIcons data to membufs, for later decoding.

	if(!d->newicons_data[newicons_num]) {
		de_dbg(c, "NewIcons data [%d] starts at %"I64_FMT, newicons_num, tpos);
		d->newicons_data[newicons_num] = dbuf_create_membuf(c, 2048, 0);
		// The data we copy includes the terminating NUL.
	}
	else {
		de_dbg2(c, "NewIcons data [%d] continues at %"I64_FMT, newicons_num, tpos);
	}
	dbuf_copy(c->infile, tpos+4, tlen-4, d->newicons_data[newicons_num]);

done:
	de_destroy_stringreaderdata(c, ttstr);
}

static int do_read_tooltypes_table(deark *c, lctx *d,
	i64 pos1, i64 *pbytesused)
{
	i64 num_entries_raw;
	i64 num_entries;
	int retval = 0;
	i64 i;
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "tool types table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	num_entries_raw = de_getu32be_p(&pos);
	num_entries = num_entries_raw/4 - 1;
	de_dbg(c, "number of tool types: %d", (int)num_entries);
	if(num_entries<0 || num_entries>1000) {
		goto done;
	}

	for(i=0; i<num_entries; i++) {
		i64 entry_pos;
		i64 tpos;
		i64 tlen;

		entry_pos = pos;
		tlen = de_getu32be_p(&pos);
		tpos = pos;
		de_dbg(c, "tooltype[%d] at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
			(int)i, entry_pos, tpos, tlen);
		if(tlen>10000) {
			de_err(c, "Bad ToolTypes data");
			goto done;
		}

		de_dbg_indent(c, 1);
		do_one_tooltype(c, d, tpos, tlen);
		de_dbg_indent(c, -1);

		pos += tlen;
	}

	retval = 1;
done:
	*pbytesused = pos - pos1;
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// Uncompress a slice of f, and append to outf.
// The algorithm is the same as PackBits, except that the data elements may
// be less than 8 bits.
static void glowdata_uncompress(dbuf *f, i64 pos, i64 len,
	dbuf *outf, int bits_per_pixel)
{
	i64 x;
	i64 i;
	u8 b, b2;
	i64 bitpos;

	bitpos = 0;

	// Continue as long as at least 8 bits remain.
	while(bitpos <= (len-1)*8) {
		b = de_get_bits_symbol2(f, 8, pos, bitpos);
		bitpos+=8;

		if(b<=127) {
			// 1+b literal pixels
			x = 1+(i64)b;
			for(i=0; i<x; i++) {
				b2 = de_get_bits_symbol2(f, bits_per_pixel, pos, bitpos);
				bitpos += bits_per_pixel;
				dbuf_writebyte(outf, b2);
			}
		}
		else if(b>=129) {
			// 257-b repeated pixels
			x = 257 - (i64)b;
			b2 = de_get_bits_symbol2(f, bits_per_pixel, pos, bitpos);
			bitpos += bits_per_pixel;
			for(i=0; i<x; i++) {
				dbuf_writebyte(outf, b2);
			}
		}
	}
}

static void do_glowicons_IMAG(deark *c, lctx *d,
	i64 pos, i64 len)
{
	de_bitmap *img = NULL;
	u8 trns_color;
	i64 num_colors;
	u8 flags;
	int has_trns;
	int has_palette;
	u8 cmpr_type;
	u8 pal_cmpr_type = 0;
	i64 bits_per_pixel;
	i64 image_size_in_bytes;
	i64 pal_size_in_bytes;
	i64 image_pos;
	i64 pal_pos;
	i64 k;
	dbuf *tmpbuf = NULL;

	if(d->glowicons_width<1) {
		// We must not have found a FACE chunk yet.
		de_err(c, "Invalid GlowIcons data");
		goto done;
	}

	trns_color = de_getbyte(pos);
	de_dbg(c, "transparent color: 0x%02x", (int)trns_color);
	num_colors = 1+(i64)de_getbyte(pos+1);
	de_dbg(c, "number of colors: %d", (int)num_colors);
	flags = de_getbyte(pos+2);
	has_trns = (flags & 0x01)?1:0;
	has_palette = (flags & 0x02)?1:0;
	de_dbg(c, "has transparency: %d", has_trns);
	de_dbg(c, "has palette: %d", has_palette);

	cmpr_type = de_getbyte(pos+3);
	de_dbg(c, "compression type: %d", cmpr_type);
	if(cmpr_type!=0 && cmpr_type!=1) {
		de_err(c, "Unsupported compression type");
		goto done;
	}

	if(cmpr_type!=1) {
		// TODO uncompressed images (Need sample files. I don't know how
		// they are structured.)
		de_err(c, "Uncompressed images are not supported");
		goto done;
	}

	if(has_palette) {
		pal_cmpr_type = de_getbyte(pos+4);
		de_dbg(c, "palette compression type: %d", pal_cmpr_type);
		if(pal_cmpr_type!=0 && pal_cmpr_type!=1) {
			de_err(c, "Unsupported palette compression type");
			goto done;
		}
	}

	bits_per_pixel = (i64)de_getbyte(pos+5);
	de_dbg(c, "bits per pixel: %d", (int)bits_per_pixel);

	if(bits_per_pixel<1 || bits_per_pixel>8) {
		de_err(c, "Invalid or unsupported bits per pixel (%d)", (int)bits_per_pixel);
		goto done;
	}

	image_size_in_bytes = 1+de_getu16be(pos+6);
	pal_size_in_bytes = 1+de_getu16be(pos+8);
	pos+=10;

	tmpbuf = dbuf_create_membuf(c, 10240, 0);

	image_pos = pos;
	pal_pos = image_pos+image_size_in_bytes;
	de_dbg(c, "image data at %d, len=%d", (int)image_pos, (int)image_size_in_bytes);

	if(has_palette) {
		de_dbg(c, "palette data at %d, len=%d", (int)pal_pos, (int)pal_size_in_bytes);
		de_dbg_indent(c, 1);

		if(pal_cmpr_type==1) {
			glowdata_uncompress(c->infile, pal_pos, pal_size_in_bytes, tmpbuf, 8);
		}
		else {
			dbuf_copy(c->infile, pal_pos, pal_size_in_bytes, tmpbuf);
		}

		for(k=0; k<256; k++) {
			if(k<num_colors) {
				d->glowicons_palette[k] = dbuf_getRGB(tmpbuf, k*3, 0);
				if(has_trns && k==(i64)trns_color) {
					d->glowicons_palette[k] = DE_SET_ALPHA(d->glowicons_palette[k], 0x00);
				}
				de_dbg_pal_entry(c, k, d->glowicons_palette[k]);
			}
			else {
				d->glowicons_palette[k] = DE_STOCKCOLOR_BLACK;
			}
		}

		de_dbg_indent(c, -1);
	}

	// Uncompress the pixels
	dbuf_empty(tmpbuf);
	glowdata_uncompress(c->infile, image_pos, image_size_in_bytes, tmpbuf, (int)bits_per_pixel);

	img = de_bitmap_create(c, d->glowicons_width, d->glowicons_height, has_trns?4:3);

	de_convert_image_paletted(tmpbuf, 0,
		8, d->glowicons_width, d->glowicons_palette, img, 0);

	de_bitmap_write_to_file(img, c->filenames_from_file?"g":NULL, 0);

done:
	if(tmpbuf) dbuf_close(tmpbuf);
	if(img) de_bitmap_destroy(img);
}

// GlowIcons chunk types:
#define CODE_FORM 0x464f524dU
#define CODE_FACE 0x46414345U
#define CODE_IMAG 0x494d4147U
// FORM types:
#define CODE_ICON 0x49434f4eU

static int do_detect_glowicons(deark *c, lctx *d, i64 pos)
{
	i64 gsize;
	u32 chunk_id;
	u32 form_type;

	gsize = c->infile->len - pos;
	if(gsize<=0) return 0;

	if(gsize>=24) {
		chunk_id = (u32)de_getu32be(pos);
		form_type = (u32)de_getu32be(pos+8);
		if(chunk_id==CODE_FORM && form_type==CODE_ICON) {
			de_dbg(c, "GlowIcons data found at %d", (int)pos);
			return 1;
		}
	}

	de_warn(c, "Extra data found at end of file, but not identified as GlowIcons format.");
	return 0;
}

static int my_iff_chunk_handler(deark *c, struct de_iffctx *ictx)
{
	lctx *d = (lctx*)ictx->userdata;
	i64 dpos, dlen;

	if(ictx->chunkctx->chunk4cc.id == CODE_FORM) {
		ictx->is_std_container = 1;
		return 1;
	}

	ictx->handled = 1;

	if(ictx->level!=1) {
		return 1;
	}

	if(ictx->curr_container_contentstype4cc.id != CODE_ICON) {
		return 1;
	}

	dpos = ictx->chunkctx->dpos;
	dlen = ictx->chunkctx->dlen;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_FACE: // FACE (parameters)
		d->glowicons_width = 1+(i64)de_getbyte(dpos);
		d->glowicons_height = 1+(i64)de_getbyte(dpos+1);
		de_dbg_dimensions(c, d->glowicons_width, d->glowicons_height);
		break;
	case CODE_IMAG: // IMAG (one of the images that make up this icon)
		do_glowicons_IMAG(c, d, dpos, dlen);
		break;
	}

	return 1;
}

static void do_glowicons(deark *c, lctx *d, i64 pos1)
{
	struct de_iffctx *ictx = NULL;
	int saved_indent_level;

	ictx = de_malloc(c, sizeof(struct de_iffctx));
	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "GlowIcons data at offset %d", (int)pos1);
	de_dbg_indent(c, 1);

	ictx->userdata = (void*)d;
	ictx->handle_chunk_fn = my_iff_chunk_handler;
	ictx->f = c->infile;
	de_fmtutil_read_iff_format(c, ictx, pos1, c->infile->len - pos1);

	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, ictx);
}

static const char *get_icon_type_name(u8 t)
{
	const char *tn = NULL;

	switch(t) {
	case 1: tn="disk"; break;
	case 2: tn="drawer"; break;
	case 3: tn="tool"; break;
	case 4: tn="project"; break;
	case 6: tn="device"; break;
	case 7: tn="kick"; break;
	}
	return tn?tn:"?";
}

static void do_scan_file(deark *c, lctx *d)
{
	i64 main_width;
	i64 main_height;
	i64 pos;
	i64 i;
	i64 x;
	i64 bytesused;
	i64 version;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "DiskObject at %d, len=%d", 0, 78);
	de_dbg_indent(c, 1);

	version = de_getu16be(2);
	de_dbg(c, "version: %d", (int)version);

	de_dbg(c, "Gadget at %d, len=%d", 4, 44);
	de_dbg_indent(c, 1);

	main_width = de_getu16be(12);
	main_height = de_getu16be(14);
	de_dbg(c, "main canvas size: %d"DE_CHAR_TIMES"%d", (int)main_width, (int)main_height);

	x = de_getu32be(26);
	de_dbg(c, "SelectRender: 0x%08x", (unsigned int)x);
	d->num_main_icons = (x==0) ? 1 : 2;
	de_dbg_indent(c, 1);
	de_dbg(c, "number of (original) icons: %d", (int)d->num_main_icons);
	de_dbg_indent(c, -1);

	d->icon_revision = de_getu32be(44) & 0xff;
	de_dbg(c, "icon revision: %d", (int)d->icon_revision);

	de_dbg_indent(c, -1); // end of embedded "Gadget" object

	d->icon_type = de_getbyte(48);
	de_dbg(c, "icon type: %d (%s)", (int)d->icon_type, get_icon_type_name(d->icon_type));

	x = de_getu32be(50);
	d->has_defaulttool = (x!=0);
	de_dbg(c, "defaulttool: 0x%08x", (unsigned int)x);

	x = de_getu32be(54);
	d->has_tooltypes = (x!=0);
	de_dbg(c, "tooltypes: 0x%08x", (unsigned int)x);

	x = de_getu32be(66);
	d->has_drawerdata = (x!=0);
	de_dbg(c, "drawerdata: 0x%08x", (unsigned int)x);

	x = de_getu32be(70);
	d->has_toolwindow = (x!=0);
	de_dbg(c, "toolwindow: 0x%08x", (unsigned int)x);

	de_dbg_indent(c, -1);

	pos = 78;

	// DrawerData segment
	if(d->has_drawerdata) {
		const i64 ddlen = 56;
		de_dbg(c, "DrawerData at %"I64_FMT", len=%"I64_FMT, pos, ddlen);
		if(c->debug_level>=2) {
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, pos, ddlen, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
		}
		pos += ddlen;
	}

	// Record the location of the main (original-style) icons
	for(i=0; i<d->num_main_icons; i++) {
		d->main_icon_pos[i] = pos;
		get_main_icon_size(c, d, pos, &bytesused);
		de_dbg(c, "main icon #%d data at %"I64_FMT", len=%"I64_FMT, (int)i,
			d->main_icon_pos[i], bytesused);
		pos += bytesused;
	}

	// DefaultTool segment
	if(d->has_defaulttool) {
		x = de_getu32be(pos);
		de_dbg(c, "DefaultTool at %"I64_FMT", dpos=%"I64_FMT", dlen=%"I64_FMT,
			pos, pos+4, x);
		pos += 4;
		if(c->debug_level>=2) {
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, pos, x, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
		}
		pos += x;
	}

	if(d->has_tooltypes) {
		// This will also read NewIcons-style icons.
		if(!do_read_tooltypes_table(c, d, pos, &bytesused))
			goto done;
		pos += bytesused;
	}

	// Skip the ToolWindow segment (untested)
	if(d->has_toolwindow) {
		x = de_getu32be(pos);
		de_dbg(c, "ToolWindow: %d bytes at %d", (int)(4+x), (int)pos);
		pos += 4+x;
	}

	// DrawerData2
	if(d->has_drawerdata && d->icon_revision==1) {
		const i64 dd2len = 6;
		de_dbg(c, "DrawerData2 at %"I64_FMT", len=%"I64_FMT, pos, dd2len);
		if(c->debug_level>=2) {
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, pos, dd2len, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
		}
		pos += dd2len;
	}

	if(do_detect_glowicons(c, d, pos)) {
		d->has_glowicons = 1;
		d->glowicons_pos = pos;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_amigaicon(deark *c, de_module_params *mparams)
{
	lctx *d;
	i64 i;

	d = de_malloc(c, sizeof(lctx));

	do_scan_file(c, d);

	if(d->has_glowicons) {
		de_declare_fmt(c, "Amiga Workbench Icon, GlowIcons");
	}
	else if(d->has_newicons) {
		de_declare_fmt(c, "Amiga Workbench Icon, NewIcons");
	}
	else {
		de_declare_fmt(c, "Amiga Workbench Icon");
	}

	de_dbg(c, "finished scanning file, now extracting icons");

	// Original format icons
	for(i=0; i<d->num_main_icons; i++) {
		do_read_main_icon(c, d, d->main_icon_pos[i], i);
	}

	// NewIcons
	for(i=0; i<2; i++) {
		if(d->newicons_data[i]) {
			do_decode_newicons(c, d, d->newicons_data[i], (int)i);
		}
	}

	// GlowIcons
	if(d->has_glowicons) {
		do_glowicons(c, d, d->glowicons_pos);
	}

	if(d->newicons_data[0]) dbuf_close(d->newicons_data[0]);
	if(d->newicons_data[1]) dbuf_close(d->newicons_data[1]);
	de_free(c, d);
}

static int de_identify_amigaicon(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xe3\x10", 2))
		return 90;
	return 0;
}

void de_module_amigaicon(deark *c, struct deark_module_info *mi)
{
	mi->id = "amigaicon";
	mi->desc = "Amiga Workbench icon (.info), NewIcons, GlowIcons";
	mi->run_fn = de_run_amigaicon;
	mi->identify_fn = de_identify_amigaicon;
}
