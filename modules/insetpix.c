// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Inset .PIX

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 item_count;
	de_byte hmode;
	de_byte htype;
	de_byte graphics_type; // 0=character, 1=bitmap
	de_byte board_type;
	de_int64 width, height;
	de_int64 gfore; // Foreground color bits
	de_int64 num_pal_bits[4]; // 0=intens, 1=red, 2=green, 3=blue

	de_int64 page_rows, page_cols;
	de_int64 stp_rows, stp_cols;

	de_uint32 pal[256];
} lctx;

static de_byte scale_color(de_byte clr1, de_int64 num_bits)
{
	if(num_bits==4) {
		if(clr1>15) return 255;
		return clr1*17;
	}
	return clr1;
}

static int do_palette(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_int64 num_pal_entries; 
	de_int64 i;
	de_byte cr1, cg1, cb1;
	de_byte cr2, cg2, cb2;

	de_dbg(c, "palette at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	num_pal_entries = len/4;
	de_dbg(c, "number of palette colors: %d\n", (int)num_pal_entries);
	for(i=0; i<num_pal_entries; i++) {
		if(i>255) break;
		//ci = de_getbyte(pos+4*i);
		cr1 = de_getbyte(pos+4*i+1);
		cg1 = de_getbyte(pos+4*i+2);
		cb1 = de_getbyte(pos+4*i+3);
		cr2 = scale_color(cr1, d->num_pal_bits[1]);
		cg2 = scale_color(cg1, d->num_pal_bits[2]);
		cb2 = scale_color(cb1, d->num_pal_bits[3]);
		de_dbg(c, "pal[%3d] = (%d,%d,%d) -> (%d,%d,%d)\n", (int)i,
			(int)cr1, (int)cg1, (int)cb1,
			(int)cr2, (int)cg2, (int)cb2 );
		d->pal[i] = DE_MAKE_RGB(cr2,cg2,cb2);
	}
	de_dbg_indent(c, -1);
	return 1;
}

static int do_image_info(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	int retval = 0;

	de_dbg(c, "image information at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	if(len<32) {
		de_err(c, "Image Information data too small\n");
		goto done;
	}

	d->hmode = de_getbyte(pos);
	de_dbg(c, "hardware mode: %d\n", (int)d->hmode);

	d->htype = de_getbyte(pos+1);
	d->graphics_type = d->htype & 0x01;
	d->board_type = d->htype & 0xfe;

	de_dbg(c, "graphics type: %d (%s)\n", (int)d->graphics_type,
		d->graphics_type?"bitmap":"character");
	de_dbg(c, "board type: %d\n", (int)d->board_type);

	d->width = de_getui16le(pos+18);
	d->height = de_getui16le(pos+20);
	de_dbg(c, "dimensions: %dx%d\n", (int)d->width, (int)d->height);

	d->gfore = (de_int64)de_getbyte(pos+22);
	de_dbg(c, "foreground color bits: %d\n", (int)d->gfore);


	d->num_pal_bits[0] = (de_int64)de_getbyte(pos+25);
	d->num_pal_bits[1] = (de_int64)de_getbyte(pos+26);
	d->num_pal_bits[2] = (de_int64)de_getbyte(pos+27);
	d->num_pal_bits[3] = (de_int64)de_getbyte(pos+28);
	de_dbg(c, "palette bits (IRGB): %d,%d,%d,%d\n",
		(int)d->num_pal_bits[0], (int)d->num_pal_bits[1],
		(int)d->num_pal_bits[2], (int)d->num_pal_bits[3] );

	// TODO: Aspect ratio

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_tileinfo(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	int retval = 0;

	de_dbg(c, "tile information at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	if(len<8) {
		de_err(c, "Tile Information data too small\n");
		goto done;
	}

	d->page_rows = de_getui16le(pos+0);
	d->page_cols = de_getui16le(pos+2);
	d->stp_rows = de_getui16le(pos+4);
	d->stp_cols = de_getui16le(pos+6);

	de_dbg(c, "page_rows=%d, page_cols=%d\n", (int)d->page_rows, (int)d->page_cols);
	de_dbg(c, "strip_rows=%d, strip_cols=%d\n", (int)d->stp_rows, (int)d->stp_cols);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_bitmap(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 item;
	de_int64 app_id;
	de_int64 tile_loc, tile_len;
	de_int64 tile_num;
	struct deark_bitmap *img = NULL;

	de_dbg(c, "reading image data\n");
	de_dbg_indent(c, 1);

	if(!de_good_image_dimensions(c, d->width, d->height)) goto done;

	img = de_bitmap_create(c, d->width, d->height, 3);

	for(item=0; item<d->item_count; item++) {
		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) break;

		app_id = de_getui16le(pos);
		if(app_id<0x8000) continue;

		tile_len = de_getui16le(pos+2);
		tile_loc = de_getui32le(pos+4);

		tile_num = app_id-0x8000;
		de_dbg(c, "item #%d: tile #%d: loc=%d, len=%d\n", (int)item, (int)tile_num,
			(int)tile_loc, (int)tile_len);
	}

	de_bitmap_write_to_file(img, NULL);

done:
	de_bitmap_destroy(img);
	de_dbg_indent(c, -1);
}

static void de_run_insetpix(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pix_version;
	de_int64 item;
	de_int64 app_id;
	de_int64 app_loc, app_len;
	de_int64 pos;
	de_int64 imginfo_pos=0, imginfo_len=0;
	de_int64 pal_pos=0, pal_len=0;
	de_int64 tileinfo_pos=0, tileinfo_len=0;
	int indent_flag = 0;

	d = de_malloc(c, sizeof(lctx));

	pix_version = de_getui16le(0);
	d->item_count = de_getui16le(2);
	de_dbg(c, "version: %d\n", (int)pix_version);
	de_dbg(c, "index at 4, %d items\n", (int)d->item_count);

	// Scan the index, and record the location of items we care about.
	// (The index will be read again when converting the image bitmap.)
	de_dbg_indent(c, 1);
	indent_flag = 1;
	for(item=0; item<d->item_count; item++) {
		pos = 4 + 8*item;
		if(pos+8 > c->infile->len) break;

		app_id = de_getui16le(pos);
		if(app_id>=0x8000) continue; // Skip "tile" items for now

		app_len = de_getui16le(pos+2);
		app_loc = de_getui32le(pos+4);
		de_dbg(c, "item #%d: id=%d, loc=%d, len=%d\n", (int)item,
			(int)app_id, (int)app_loc, (int)app_len);

		if(app_loc + app_len > c->infile->len) {
			de_err(c, "Item #%d (ID %d) goes beyond end of file\n",
				(int)item, (int)app_id);
			goto done;
		}

		switch(app_id) {
		case 0:
			imginfo_pos = app_loc;
			imginfo_len = app_len;
			break;
		case 1:
			if(!pal_pos) {
				pal_pos = app_loc;
				pal_len = app_len;
			}
			break;
		case 2:
			tileinfo_pos = app_loc;
			tileinfo_len = app_len;
			break;
		case 17: // Printing Options
			break;
		default:
			de_dbg(c, "unknown item type %d\n", (int)app_id);
		}
	}
	de_dbg_indent(c, -1);
	indent_flag = 0;

	if(!imginfo_pos) {
		de_err(c, "Missing Image Information data\n");
		goto done;
	}
	if(!do_image_info(c, d, imginfo_pos, imginfo_len)) goto done;

	if(d->graphics_type==0) {
		de_err(c, "Inset PIX character graphics not supported\n");
		goto done;
	}

	if(!pal_pos) {
		de_err(c, "Missing palette\n");
		goto done;
	}

	if(!do_palette(c, d, pal_pos, pal_len)) goto done;

	if(!tileinfo_pos) {
		de_err(c, "Missing Tile Information data\n");
		goto done;
	}

	if(!do_tileinfo(c, d, tileinfo_pos, tileinfo_len)) goto done;

	do_bitmap(c, d);

done:
	if(indent_flag) de_dbg_indent(c, -1);

	de_free(c, d);
}

static int de_identify_insetpix(deark *c)
{
	// TODO
	return 0;
}

void de_module_insetpix(deark *c, struct deark_module_info *mi)
{
	mi->id = "insetpix";
	mi->run_fn = de_run_insetpix;
	mi->identify_fn = de_identify_insetpix;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
