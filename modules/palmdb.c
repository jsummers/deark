// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm Database (PDB)
// Palm Resource (PRC)
// Palm BitmapType

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_palmdb);
DE_DECLARE_MODULE(de_module_palmrc);
DE_DECLARE_MODULE(de_module_palmbitmap);

#define CODE_Tbmp 0x54626d70U
#define CODE_View 0x56696577U
#define CODE_appl 0x6170706cU
#define CODE_clpr 0x636c7072U
#define CODE_lnch 0x6c6e6368U
#define CODE_pqa  0x70716120U
#define CODE_tAIB 0x74414942U
#define CODE_vIMG 0x76494d47U

#define PALMBMPFLAG_COMPRESSED     0x8000U
#define PALMBMPFLAG_HASCOLORTABLE  0x4000U
#define PALMBMPFLAG_HASTRNS        0x2000U
#define PALMBMPFLAG_DIRECTCOLOR    0x0400U

static const de_uint32 palm256pal[256] = {
	0xffffff,0xffccff,0xff99ff,0xff66ff,0xff33ff,0xff00ff,0xffffcc,0xffcccc,
	0xff99cc,0xff66cc,0xff33cc,0xff00cc,0xffff99,0xffcc99,0xff9999,0xff6699,
	0xff3399,0xff0099,0xccffff,0xccccff,0xcc99ff,0xcc66ff,0xcc33ff,0xcc00ff,
	0xccffcc,0xcccccc,0xcc99cc,0xcc66cc,0xcc33cc,0xcc00cc,0xccff99,0xcccc99,
	0xcc9999,0xcc6699,0xcc3399,0xcc0099,0x99ffff,0x99ccff,0x9999ff,0x9966ff,
	0x9933ff,0x9900ff,0x99ffcc,0x99cccc,0x9999cc,0x9966cc,0x9933cc,0x9900cc,
	0x99ff99,0x99cc99,0x999999,0x996699,0x993399,0x990099,0x66ffff,0x66ccff,
	0x6699ff,0x6666ff,0x6633ff,0x6600ff,0x66ffcc,0x66cccc,0x6699cc,0x6666cc,
	0x6633cc,0x6600cc,0x66ff99,0x66cc99,0x669999,0x666699,0x663399,0x660099,
	0x33ffff,0x33ccff,0x3399ff,0x3366ff,0x3333ff,0x3300ff,0x33ffcc,0x33cccc,
	0x3399cc,0x3366cc,0x3333cc,0x3300cc,0x33ff99,0x33cc99,0x339999,0x336699,
	0x333399,0x330099,0x00ffff,0x00ccff,0x0099ff,0x0066ff,0x0033ff,0x0000ff,
	0x00ffcc,0x00cccc,0x0099cc,0x0066cc,0x0033cc,0x0000cc,0x00ff99,0x00cc99,
	0x009999,0x006699,0x003399,0x000099,0xffff66,0xffcc66,0xff9966,0xff6666,
	0xff3366,0xff0066,0xffff33,0xffcc33,0xff9933,0xff6633,0xff3333,0xff0033,
	0xffff00,0xffcc00,0xff9900,0xff6600,0xff3300,0xff0000,0xccff66,0xcccc66,
	0xcc9966,0xcc6666,0xcc3366,0xcc0066,0xccff33,0xcccc33,0xcc9933,0xcc6633,
	0xcc3333,0xcc0033,0xccff00,0xcccc00,0xcc9900,0xcc6600,0xcc3300,0xcc0000,
	0x99ff66,0x99cc66,0x999966,0x996666,0x993366,0x990066,0x99ff33,0x99cc33,
	0x999933,0x996633,0x993333,0x990033,0x99ff00,0x99cc00,0x999900,0x996600,
	0x993300,0x990000,0x66ff66,0x66cc66,0x669966,0x666666,0x663366,0x660066,
	0x66ff33,0x66cc33,0x669933,0x666633,0x663333,0x660033,0x66ff00,0x66cc00,
	0x669900,0x666600,0x663300,0x660000,0x33ff66,0x33cc66,0x339966,0x336666,
	0x333366,0x330066,0x33ff33,0x33cc33,0x339933,0x336633,0x333333,0x330033,
	0x33ff00,0x33cc00,0x339900,0x336600,0x333300,0x330000,0x00ff66,0x00cc66,
	0x009966,0x006666,0x003366,0x000066,0x00ff33,0x00cc33,0x009933,0x006633,
	0x003333,0x000033,0x00ff00,0x00cc00,0x009900,0x006600,0x003300,0x111111,
	0x222222,0x444444,0x555555,0x777777,0x888888,0xaaaaaa,0xbbbbbb,0xdddddd,
	0xeeeeee,0xc0c0c0,0x800000,0x800080,0x008000,0x008080,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,
	0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000,0x000000
};

// Our compression code scheme is an extension of the standard BitmapType codes.
// Codes 0x100 and higher are not standard.
#define CMPR_SCANLINE 0
#define CMPR_RLE      1
#define CMPR_PACKBITS 2
#define CMPR_NONE     0xff
#define CMPR_IMGVIEWER 0x100

struct rec_data_struct {
	de_uint32 offset;
};

struct rec_list_struct {
	de_int64 num_recs;
	struct rec_data_struct *rec_data;
};

struct img_gen_info {
	de_int64 w, h;
	de_int64 bitsperpixel;
	de_int64 rowbytes;
	de_finfo *fi;
	unsigned int createflags;
	int has_trns;
	de_uint32 trns_value;
	int is_rgb;
	int has_custom_pal;
	de_uint32 custom_pal[256];
};

typedef struct localctx_struct {
#define FMT_PDB     1
#define FMT_PRC     2
	int file_fmt;
#define SUBFMT_NONE 0
#define SUBFMT_PQA  1
	int file_subfmt;
	int rawbitmaps;
	int ignore_color_table_flag;
	int has_nonzero_ids;
	const char *fmt_shortname;
	de_int64 rec_size; // bytes per record
	struct de_fourcc dtype4cc;
	struct de_fourcc creator4cc;
	de_int64 appinfo_offs;
	de_int64 sortinfo_offs;
	struct rec_list_struct rec_list;
} lctx;

static void handle_palm_timestamp(deark *c, lctx *d, de_int64 pos, const char *name)
{
	struct de_timestamp ts;
	char timestamp_buf[64];
	de_int64 ts_int;

	ts_int = de_getui32be(pos);
	if(ts_int==0) {
		de_dbg(c, "%s: 0 (not set)\n", name);
		return;
	}

	de_dbg(c, "%s: ...\n", name);
	de_dbg_indent(c, 1);

	// I've seen three different ways to interpret this 32-bit timestamp, and
	// I don't know how to guess the correct one.

	de_mac_time_to_timestamp(ts_int, &ts);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "... if Mac-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);

	ts_int = de_geti32be(pos);
	if(ts_int>0) { // Assume dates before 1970 are wrong
		de_unix_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0x1);
		de_dbg(c, "... if Unix-BE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	ts_int = de_getui32le(pos);
	if(ts_int>2082844800) {
		de_mac_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Mac-LE: %"INT64_FMT" (%s)\n", ts_int, timestamp_buf);
	}

	de_dbg_indent(c, -1);
}

static int do_read_header(deark *c, lctx *d)
{
	de_int64 pos1 = 0;
	de_ucstring *dname = NULL;
	de_uint32 attribs;
	de_uint32 version;
	de_int64 x;
	int retval = 0;

	de_dbg(c, "header at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	dname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos1, 32, dname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(dname));

	attribs = (de_uint32)de_getui16be(pos1+32);
	de_dbg(c, "attributes: 0x%04x\n", (unsigned int)attribs);

	version = (de_uint32)de_getui16be(pos1+34);
	de_dbg(c, "version: 0x%04x\n", (unsigned int)version);

	handle_palm_timestamp(c, d, pos1+36, "create date");
	handle_palm_timestamp(c, d, pos1+40, "mod date");
	handle_palm_timestamp(c, d, pos1+44, "backup date");

	x = de_getui32be(pos1+48);
	de_dbg(c, "mod number: %d\n", (int)x);
	d->appinfo_offs = de_getui32be(pos1+52);
	de_dbg(c, "app info pos: %d\n", (int)d->appinfo_offs);
	d->sortinfo_offs = de_getui32be(pos1+56);
	de_dbg(c, "sort info pos: %d\n", (int)d->sortinfo_offs);

	dbuf_read_fourcc(c->infile, pos1+60, &d->dtype4cc, 0);
	de_dbg(c, "type: \"%s\"\n", d->dtype4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos1+64, &d->creator4cc, 0);
	de_dbg(c, "creator: \"%s\"\n", d->creator4cc.id_printable);

	if(d->file_fmt==FMT_PDB) {
		if(d->dtype4cc.id==CODE_pqa && d->creator4cc.id==CODE_clpr) {
			d->file_subfmt = SUBFMT_PQA;
			d->fmt_shortname = "PQA";
			de_declare_fmt(c, "Palm PQA");
		}
		else {
			d->fmt_shortname = "PDB";
			de_declare_fmt(c, "Palm PDB");
		}
	}
	else if(d->file_fmt==FMT_PRC) {
		d->fmt_shortname = "PRC";
		de_declare_fmt(c, "Palm PRC");
	}
	else {
		goto done;
	}

	x = de_getui32be(68);
	de_dbg(c, "uniqueIDseed: %d\n", (int)x);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	ucstring_destroy(dname);
	return retval;
}

static de_int64 calc_rec_len(deark *c, lctx *d, de_int64 rec_idx)
{
	de_int64 len;
	if(rec_idx+1 < d->rec_list.num_recs) {
		len = (de_int64)(d->rec_list.rec_data[rec_idx+1].offset - d->rec_list.rec_data[rec_idx].offset);
	}
	else {
		len = c->infile->len - (de_int64)d->rec_list.rec_data[rec_idx].offset;
	}
	return len;
}

static void extract_item(deark *c, lctx *d, de_int64 data_offs, de_int64 data_len,
	const char *ext, unsigned int createflags, int always_extract)
{
	de_finfo *fi = NULL;

	if(c->extract_level<2 && !always_extract) goto done;
	if(data_offs<0 || data_len<0) goto done;
	if(data_offs+data_len > c->infile->len) goto done;
	fi = de_finfo_create(c);
	de_finfo_set_name_from_sz(c, fi, ext, DE_ENCODING_ASCII);
	dbuf_create_file_from_slice(c->infile, data_offs, data_len, NULL, fi, createflags);
done:
	de_finfo_destroy(c, fi);
}

static int do_decompress_imgview_image(deark *c, lctx *d, dbuf *inf,
	de_int64 pos1, de_int64 len, dbuf *unc_pixels)
{
	de_int64 pos = pos1;
	de_byte b1, b2;
	de_int64 count;

	while(pos < pos1+len) {
		b1 = dbuf_getbyte(inf, pos++);
		if(b1>128) {
			count = (de_int64)b1-127;
			b2 = dbuf_getbyte(inf, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else {
			count = (de_int64)b1+1;
			dbuf_copy(inf, pos, count, unc_pixels);
			pos += count;
		}
	}
	return 1;
}

static int do_decompress_scanline_compression(deark *c, lctx *d, dbuf *inf,
	de_int64 pos1, de_int64 len, dbuf *unc_pixels, struct img_gen_info *igi)
{
	de_int64 srcpos = pos1;
	de_int64 j;
	de_int64 blocknum;
	de_int64 blocksperrow;
	de_byte bf;
	de_byte dstb;
	unsigned int k;
	de_int64 x;

	blocksperrow = (igi->rowbytes+7)/8;

	x = dbuf_getui16be(inf, srcpos);
	// TODO: Find documentation for this field, and maybe do something with it.
	// It apparently includes the 2 bytes for itself.
	de_dbg2(c, "cmpr len: %d\n", (int)x);
	srcpos += 2;

	for(j=0; j<igi->h; j++) {
		de_int64 bytes_written_this_row = 0;

		for(blocknum=0; blocknum<blocksperrow; blocknum++) {
			// For each byte-per-row, we expect a lead byte, which is a
			// bitfield that tells us which of the next 8 bytes are stored
			// in the file, versus being copied from the previous row.
			bf = dbuf_getbyte(inf, srcpos++);
			for(k=0; k<8; k++) {
				if(bytes_written_this_row>=igi->rowbytes) break;

				if(bf&(1<<(7-k))) {
					// byte is present
					dstb = dbuf_getbyte(inf, srcpos++);
				}
				else {
					// copy from previous row
					dstb = dbuf_getbyte(unc_pixels, unc_pixels->len - igi->rowbytes);
				}
				dbuf_writebyte(unc_pixels, dstb);

				bytes_written_this_row++;
			}
		}
	}

	return 1;
}

static void do_generate_unc_image(deark *c, lctx *d, dbuf *unc_pixels,
	struct img_gen_info *igi)
{
	de_int64 i, j;
	de_byte b;
	de_byte b_adj;
	de_uint32 clr;
	int has_color;
	struct deark_bitmap *img = NULL;

	has_color = (igi->bitsperpixel>4 || igi->has_custom_pal);

	if(igi->bitsperpixel==1 && !has_color) {
		de_convert_and_write_image_bilevel(unc_pixels, 0, igi->w, igi->h, igi->rowbytes,
			DE_CVTF_WHITEISZERO, igi->fi, igi->createflags);
		goto done;
	}

	img = de_bitmap_create(c, igi->w, igi->h,
		(has_color?3:1) + (igi->has_trns?1:0));

	for(j=0; j<igi->h; j++) {
		for(i=0; i<igi->w; i++) {
			if(igi->bitsperpixel==16) {
				clr = (de_uint32)dbuf_getui16be(unc_pixels, igi->rowbytes*j + 2*i);
				clr = de_rgb565_to_888(clr);
				de_bitmap_setpixel_rgb(img, i, j, clr);
				// TODO: Transparency
			}
			else {
				b = de_get_bits_symbol(unc_pixels, igi->bitsperpixel, igi->rowbytes*j, i);
				if(has_color) {
					if(igi->has_custom_pal)
						clr = igi->custom_pal[(unsigned int)b];
					else
						clr = DE_MAKE_OPAQUE(palm256pal[(unsigned int)b]);
				}
				else {
					// TODO: What are the correct colors (esp. for 4bpp)?
					b_adj = 255 - de_sample_nbit_to_8bit(igi->bitsperpixel, (unsigned int)b);
					clr = DE_MAKE_GRAY(b_adj);
				}

				de_bitmap_setpixel_rgb(img, i, j, clr);

				if(igi->has_trns && (de_uint32)b==igi->trns_value) {
					de_bitmap_setsample(img, i, j, 3, 0);
				}
			}
		}
	}

	de_bitmap_write_to_file_finfo(img, igi->fi, igi->createflags);

done:
	de_bitmap_destroy(img);
}

// A wrapper that decompresses the image if necessary, then calls do_generate_unc_image().
static void do_generate_image(deark *c, lctx *d,
	dbuf *inf, de_int64 pos, de_int64 len, unsigned int cmpr_type,
	struct img_gen_info *igi)
{
	dbuf *unc_pixels = NULL;
	de_int64 expected_num_uncmpr_image_bytes;

	expected_num_uncmpr_image_bytes = igi->rowbytes*igi->h;

	if(cmpr_type==CMPR_NONE) {
		if(expected_num_uncmpr_image_bytes > len) {
			de_warn(c, "Not enough data for image\n");
		}
		unc_pixels = dbuf_open_input_subfile(inf, pos, len);
	}
	else {
		unc_pixels = dbuf_create_membuf(c, expected_num_uncmpr_image_bytes, 1);

		if(cmpr_type==CMPR_IMGVIEWER) {
			do_decompress_imgview_image(c, d, inf, pos, len, unc_pixels);
		}
		else if(cmpr_type==CMPR_SCANLINE) {
			do_decompress_scanline_compression(c, d, inf, pos, len, unc_pixels, igi);
		}
		else {
			de_err(c, "Unsupported compression type: %u\n", cmpr_type);
			goto done;
		}

		// TODO: The byte counts in this message are not very accurate.
		de_dbg(c, "decompressed %d bytes to %d bytes\n", (int)len,
			(int)unc_pixels->len);
	}

	do_generate_unc_image(c, d, unc_pixels, igi);

done:
	dbuf_close(unc_pixels);
}

static const char *get_cmpr_type_name(unsigned int cmpr_type)
{
	const char *name;

	switch(cmpr_type) {
	case 0: name = "ScanLine"; break;
	case 1: name = "RLE"; break;
	case 2: name = "PackBits"; break;
	case 0xff: name = "none"; break;
	default: name = "?"; break;
	}
	return name;
}

static int read_colortable(deark *c, lctx *d, struct img_gen_info *igi,
	de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 num_entries;
	de_int64 k;
	de_int64 pos = pos1;
	unsigned int idx;
	char tmps[32];

	de_dbg(c, "color table at %d\n", (int)pos1);
	de_dbg_indent(c, 1);
	igi->has_custom_pal = 1;

	num_entries = de_getui16be(pos1);
	de_dbg(c, "number of entries: %d\n", (int)num_entries);
	// TODO: Documentation says "High bits (numEntries > 256) reserved."
	// What exactly does that mean?
	if(num_entries>256) {
		de_warn(c, "Invalid or unsupported type of color table\n");
	}
	pos += 2;

	*bytes_consumed = 2+4*num_entries;

	// The first byte of each entry is an index, which I think we can ignore.
	// We're pretending the palette starts at offset 3 (the offset of the
	// red sample of the first entry), when it really starts at offset 2.
	//de_read_palette_rgb(c->infile, pos1+3, num_entries, 4,
	//	igi->custom_pal, 256, 0);

	for(k=0; k<num_entries && k<256; k++) {
		idx = (unsigned int)de_getbyte(pos);
		de_snprintf(tmps, sizeof(tmps), ",idx=%u", idx);
		// Not entirely sure if we should set entry #k, or entry #idx.
		// idx is documented as "The index of this color in the color table."
		igi->custom_pal[idx] = dbuf_getRGB(c->infile, pos+1, 0);
		de_dbg_pal_entry(c, k, igi->custom_pal[idx], tmps, NULL);
		pos += 4;
	}

	de_dbg_indent(c, -1);
	return 1;
}

static void do_palm_BitmapType_internal(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	const char *token, unsigned int createflags,
	de_int64 *pnextbitmapoffset)
{
	de_int64 x;
	de_int64 pos;
	de_uint32 bitmapflags;
	de_byte pixelsize_raw;
	de_byte bitmapversion;
	de_int64 headersize;
	de_int64 bytes_consumed;
	de_int64 nextbitmapoffs_in_bytes = 0;
	unsigned int cmpr_type;
	const char *cmpr_type_src_name = "";
	const char *bpp_src_name = "";
	struct img_gen_info *igi = NULL;
	int saved_indent_level;
	de_ucstring *flagsdescr;
	char tmps[80];

	de_dbg_indent_save(c, &saved_indent_level);
	igi = de_malloc(c, sizeof(struct img_gen_info));
	igi->createflags = createflags;

	de_dbg(c, "BitmapType at %d, len<=%d\n", (int)pos1, (int)len);
	de_dbg_indent(c, 1);
	de_dbg(c, "bitmap header at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	// Look ahead to get the version
	bitmapversion = de_getbyte(pos1+9);
	de_dbg(c, "bitmap version: %d\n", (int)bitmapversion);

	if(bitmapversion>3) {
		// Note that V3 allows the high bit of the version field to
		// be set (to mean little-endian), but we don't support that.
		de_err(c, "Unsupported bitmap version: %d\n", (int)bitmapversion);
		goto done;
	}

	igi->w = de_geti16be(pos1);
	igi->h = de_geti16be(pos1+2);
	de_dbg(c, "dimensions: %dx%d\n", (int)igi->w, (int)igi->h);

	igi->rowbytes = de_getui16be(pos1+4);
	de_dbg(c, "rowBytes: %d\n", (int)igi->rowbytes);

	bitmapflags = (de_uint32)de_getui16be(pos1+6);
	flagsdescr = ucstring_create(c);
	if(bitmapflags&PALMBMPFLAG_COMPRESSED) ucstring_append_flags_item(flagsdescr, "compressed");
	if(bitmapflags&PALMBMPFLAG_HASCOLORTABLE) ucstring_append_flags_item(flagsdescr, "hasColorTable");
	if(bitmapflags&PALMBMPFLAG_HASTRNS) ucstring_append_flags_item(flagsdescr, "hasTransparency");
	if(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) ucstring_append_flags_item(flagsdescr, "directColor");
	if(bitmapflags==0) ucstring_append_flags_item(flagsdescr, "none");
	de_dbg(c, "bitmap flags: 0x%04x (%s)\n", (unsigned int)bitmapflags,
		ucstring_get_printable_sz(flagsdescr));
	ucstring_destroy(flagsdescr);
	if((bitmapflags&PALMBMPFLAG_HASCOLORTABLE) && d->ignore_color_table_flag) {
		bitmapflags -= PALMBMPFLAG_HASCOLORTABLE;
	}
	if((bitmapflags&PALMBMPFLAG_HASCOLORTABLE) && bitmapversion<1) {
		de_warn(c, "BitmapTypeV%d with a color table is not standard\n", (int)bitmapversion);
	}

	if(bitmapversion>=1) {
		pixelsize_raw = de_getbyte(pos1+8);
		de_dbg(c, "pixelSize: %d\n", (int)pixelsize_raw);
		bpp_src_name = "based on pixelSize field";
		if(bitmapversion<2 && pixelsize_raw==8) {
			de_warn(c, "BitmapTypeV%d with pixelSize=%d is not standard\n",
				(int)bitmapversion, (int)pixelsize_raw);
		}
	}
	else {
		pixelsize_raw = 0;
	}
	if(pixelsize_raw==0) {
		igi->bitsperpixel = 1;
		bpp_src_name = "default";
	}
	else igi->bitsperpixel = (de_int64)pixelsize_raw;
	de_dbg(c, "bits/pixel: %d (%s)\n", (int)igi->bitsperpixel, bpp_src_name);

	if(bitmapversion==1 || bitmapversion==2) {
		x = de_getui16be(pos1+10);
		nextbitmapoffs_in_bytes = 4*x;
		if(x==0) {
			de_snprintf(tmps, sizeof(tmps), "none");
		}
		else {
			de_snprintf(tmps, sizeof(tmps), "%d + 4*%d = %d", (int)pos1, (int)x, (int)(pos1+nextbitmapoffs_in_bytes));
		}
		de_dbg(c, "nextDepthOffset: %d (%s)\n", (int)x, tmps);
	}

	if(bitmapversion<3) {
		headersize = 16;
	}
	else {
		headersize = (de_int64)de_getbyte(pos1+10);
		de_dbg(c, "header size: %d\n", (int)headersize);
	}

	if(bitmapversion==3) {
		de_byte pixfmt = de_getbyte(pos1+11);
		de_dbg(c, "pixel format: %d\n", (int)pixfmt);
		// TODO: Do something with this
	}

	if(bitmapversion==2 && (bitmapflags&PALMBMPFLAG_HASTRNS)) {
		igi->has_trns = 1;
		igi->trns_value = (de_uint32)de_getbyte(pos1+12);
		de_dbg(c, "transparent color: %u\n", (unsigned int)igi->trns_value);
	}

	cmpr_type_src_name = "flags";
	if(bitmapflags&PALMBMPFLAG_COMPRESSED) {
		if(bitmapversion>=2) {
			cmpr_type = (unsigned int)de_getbyte(pos1+13);
			cmpr_type_src_name = "compression type field";
			de_dbg(c, "compression type field: 0x%02x\n", cmpr_type);
		}
		else {
			// V1 & V2 have no cmpr_type field, but can still be compressed.
			cmpr_type = CMPR_SCANLINE;
		}
	}
	else {
		cmpr_type = CMPR_NONE;
	}

	de_dbg(c, "compression type: %s (based on %s)\n", get_cmpr_type_name(cmpr_type), cmpr_type_src_name);

	// TODO: [14] density (V3)

	if(bitmapversion==3 && (bitmapflags&PALMBMPFLAG_HASTRNS) && headersize>=20) {
		// I'm assuming the flag affects this field. The spec is ambiguous.
		igi->has_trns = 1;
		igi->trns_value = (de_uint32)de_getui32be(pos1+16);
		de_dbg(c, "transparent color: %u\n", (unsigned int)igi->trns_value);
	}

	if(bitmapversion==3 && headersize>=24) {
		// Documented as the "number of bytes to the next bitmap", but it doesn't
		// say where it is measured *from*. I'll assume it's the same logic as
		// the "nextDepthOffset" field.
		nextbitmapoffs_in_bytes = de_getui32be(pos1+20);
		if(nextbitmapoffs_in_bytes==0) {
			de_snprintf(tmps, sizeof(tmps), "none");
		}
		else {
			de_snprintf(tmps, sizeof(tmps), "%u + %u = %u", (unsigned int)pos1,
				(unsigned int)nextbitmapoffs_in_bytes, (unsigned int)(pos1+nextbitmapoffs_in_bytes));
		}
		de_dbg(c, "nextBitmapOffset: %u (%s)\n", (unsigned int)nextbitmapoffs_in_bytes, tmps);
	}

	// Now that we've read the nextBitmapOffset fields, we can stop processing this
	// image if it's invalid or unsupported.
	if(!de_good_image_dimensions(c, igi->w, igi->h)) goto done;

	de_dbg_indent(c, -1);

	if(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) {
		igi->is_rgb = 1;
		if(bitmapversion<2) {
			de_warn(c, "BitmapTypeV%d with RGB color is not standard\n", (int)bitmapversion);
		}
	}

	if(igi->bitsperpixel!=1 && igi->bitsperpixel!=2 && igi->bitsperpixel!=4 &&
		igi->bitsperpixel!=8 && igi->bitsperpixel!=16)
	{
		de_err(c, "Unsupported bits/pixel: %d\n", (int)igi->bitsperpixel);
		goto done;
	}

	if((igi->is_rgb && igi->bitsperpixel!=16) ||
		(!igi->is_rgb && igi->bitsperpixel>8))
	{
		de_err(c, "This type of image is not supported\n");
		goto done;
	}

	pos = pos1;
	pos += headersize;
	if(pos >= pos1+len) goto done;

	if(bitmapflags&PALMBMPFLAG_HASCOLORTABLE) {
		if(!read_colortable(c, d, igi, pos, &bytes_consumed)) goto done;
		pos += bytes_consumed;
	}

	if(bitmapflags&PALMBMPFLAG_DIRECTCOLOR) {
		de_dbg(c, "BitmapDirectInfoType structure at %d\n", (int)pos);
		// TODO: Read this struct, at least to support transparency
		pos += 8;
		if(bitmapflags&PALMBMPFLAG_HASTRNS) {
			de_warn(c, "Transparency is not supported for RGB bitmaps\n");
		}
	}

	if(pos >= pos1+len) {
		de_err(c, "Unexpected end of file\n");
		goto done;
	}

	igi->fi = de_finfo_create(c);
	if(token) {
		de_finfo_set_name_from_sz(c, igi->fi, token, DE_ENCODING_UTF8);
	}

	de_dbg(c, "image data at %d\n", (int)pos);
	do_generate_image(c, d, c->infile, pos, pos1+len-pos, cmpr_type, igi);

done:
	*pnextbitmapoffset = nextbitmapoffs_in_bytes;
	de_dbg_indent_restore(c, saved_indent_level);
	if(igi) {
		de_finfo_destroy(c, igi->fi);
		de_free(c, igi);
	}
}

static void do_palm_BitmapType(deark *c, lctx *d, de_int64 pos1, de_int64 len,
	const char *token, unsigned int createflags)
{
	de_int64 nextbitmapoffs = 0;
	de_int64 pos = pos1;

	while(1) {
		if(pos > pos1+len-16) {
			de_err(c, "Bitmap exceeds its bounds\n");
			break;
		}
		do_palm_BitmapType_internal(c, d, pos, pos1+len-pos, token, createflags, &nextbitmapoffs);
		if(nextbitmapoffs<=0) break;
		pos += nextbitmapoffs;
	}
}

static void do_imgview_image(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_byte imgver;
	de_byte imgtype;
	unsigned int cmpr_meth;
	de_int64 x0, x1;
	de_int64 pos = pos1;
	de_int64 num_raw_image_bytes;
	de_ucstring *iname = NULL;
	struct img_gen_info *igi = NULL;

	igi = de_malloc(c, sizeof(struct img_gen_info));

	de_dbg(c, "image record at %d\n", (int)pos1);
	de_dbg_indent(c, 1);

	iname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 32, iname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "name: \"%s\"\n", ucstring_get_printable_sz(iname));
	// TODO: Use this in the filename?
	pos += 32;

	imgver = de_getbyte(pos++);
	de_dbg(c, "version: 0x%02x\n", (unsigned int)imgver);
	cmpr_meth = (unsigned int)(imgver&0x07);
	de_dbg_indent(c, 1);
	de_dbg(c, "compression method: %u\n", cmpr_meth);
	de_dbg_indent(c, -1);

	imgtype = de_getbyte(pos++);
	de_dbg(c, "type: 0x%02x\n", (unsigned int)imgtype);
	de_dbg_indent(c, 1);
	switch(imgtype) {
	case 0: igi->bitsperpixel = 2; break;
	case 2: igi->bitsperpixel = 4; break;
	default: igi->bitsperpixel = 1;
	}
	de_dbg(c, "bits/pixel: %d\n", (int)igi->bitsperpixel);
	de_dbg_indent(c, -1);

	pos += 4; // reserved
	pos += 4; // note

	x0 = de_getui16be(pos);
	pos += 2;
	x1 = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "last: (%d,%d)\n", (int)x0, (int)x1);

	pos += 4; // reserved

	x0 = de_getui16be(pos);
	pos += 2;
	x1 = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "anchor: (%d,%d)\n", (int)x0, (int)x1);

	igi->w = de_getui16be(pos);
	pos += 2;
	igi->h = de_getui16be(pos);
	pos += 2;
	de_dbg(c, "dimensions: %dx%d\n", (int)igi->w, (int)igi->h);
	if(!de_good_image_dimensions(c, igi->w, igi->h)) goto done;

	igi->rowbytes = (igi->w*igi->bitsperpixel + 7)/8;
	num_raw_image_bytes = pos1+len-pos;

	do_generate_image(c, d, c->infile, pos, num_raw_image_bytes,
		(cmpr_meth==0)?CMPR_NONE:CMPR_IMGVIEWER, igi);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(iname);
	if(igi) {
		de_free(c, igi);
	}
}

static void do_imgview_text(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_ucstring *s = NULL;

	if(len<1) return;

	// (I'm pretty much just guessing the format of this record.)
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);

	// TODO: Decide when to write the text record to a file.
	// Problem is that we're already using -a to mean "write all raw records to files".
	{
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}

	ucstring_destroy(s);
}

// For PDB or PQA format
static int do_read_pdb_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_int64 data_offs;
	de_byte attribs;
	de_uint32 id;
	de_int64 data_len;
	char extfull[80];

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	data_offs = (int)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);

	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	de_snprintf(extfull, sizeof(extfull), "rec%d.bin", (int)rec_idx); // May be overridden

	if(d->file_subfmt!=SUBFMT_PQA) {
		const char *idname = NULL;
		char tmpstr[80];

		attribs = de_getbyte(pos1+4);
		de_dbg(c, "attributes: 0x%02x\n", (unsigned int)attribs);

		id = (de_getbyte(pos1+5)<<16) |
			(de_getbyte(pos1+6)<<8) |
			(de_getbyte(pos1+7));

		if(d->dtype4cc.id==CODE_vIMG && d->creator4cc.id==CODE_View) {
			if(id==0x6f8000) idname = "image record";
			else if(id==0x6f8001) idname = "text record";
			else idname = "?";
		}
		if(idname)
			de_snprintf(tmpstr, sizeof(tmpstr), " (%s)", idname);
		else
			tmpstr[0] = '\0';

		de_dbg(c, "id: %u (0x%06x)%s\n", (unsigned int)id, (unsigned int)id, tmpstr);

		if(d->has_nonzero_ids) {
			de_snprintf(extfull, sizeof(extfull), "%06x.bin", (unsigned int)id);
		}

		if(d->dtype4cc.id==CODE_vIMG && d->creator4cc.id==CODE_View) {
			if(id==0x6f8000) do_imgview_image(c, d, data_offs, data_len);
			else if(id==0x6f8001) do_imgview_text(c, d, data_offs, data_len);
		}
	}

	extract_item(c, d, data_offs, data_len, extfull, 0, 0);

	de_dbg_indent(c, -1);
	return 1;
}

static int do_read_prc_record(deark *c, lctx *d, de_int64 rec_idx, de_int64 pos1)
{
	de_uint32 id;
	struct de_fourcc name4cc;
	de_int64 data_offs;
	de_int64 data_len;
	int always_extract = 0;
	int extracted_flag;
	const char *ext1 = "bin";
	char extfull[80];

	de_dbg(c, "record[%d] at %d\n", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos1, &name4cc, 0);
	de_dbg(c, "name: \"%s\"\n", name4cc.id_printable);

	id = (de_uint32)de_getui16be(pos1+4);
	de_dbg(c, "id: %d\n", (int)id);

	data_offs = (de_int64)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d\n", (int)data_offs);
	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d\n", (int)data_len);

	extracted_flag = 0;
	switch(name4cc.id) {
	case CODE_Tbmp:
	case CODE_tAIB:
		ext1 = "palm";
		if(d->rawbitmaps) {
			always_extract = 1;
		}
		else {
			do_palm_BitmapType(c, d, data_offs, data_len,
				name4cc.id_printable, 0);
			extracted_flag = 1;
		}
		break;
	}

	de_snprintf(extfull, sizeof(extfull), "%s.%s", name4cc.id_printable, ext1);
	if(!extracted_flag) {
		extract_item(c, d, data_offs, data_len, extfull, 0, always_extract);
	}

	de_dbg_indent(c, -1);
	return 1;
}

// Allocates and populates the d->rec_data array.
// Tests for sanity, and returns 0 if there is a problem.
static int do_prescan_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;

	if(d->rec_list.num_recs<1) return 1;
	// num_recs is untrusted, but it is a 16-bit int that can be at most 65535.
	d->rec_list.rec_data = de_malloc(c, sizeof(struct rec_data_struct)*d->rec_list.num_recs);
	for(i=0; i<d->rec_list.num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			d->rec_list.rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i + 6);
		}
		else {
			de_uint32 id;
			d->rec_list.rec_data[i].offset = (de_uint32)de_getui32be(pos1 + d->rec_size*i);
			if(!d->has_nonzero_ids) {
				id = (de_getbyte(pos1+d->rec_size*i+5)<<16) |
					(de_getbyte(pos1+d->rec_size*i+6)<<8) |
					(de_getbyte(pos1+d->rec_size*i+7));
				if(id!=0) d->has_nonzero_ids = 1;
			}
		}

		// Record data must not start beyond the end of file.
		if((de_int64)d->rec_list.rec_data[i].offset > c->infile->len) {
			de_err(c, "Record %d (at %d) starts after end of file (%d)\n",
				(int)i, (int)d->rec_list.rec_data[i].offset, (int)c->infile->len);
			return 0;
		}

		// Record data must not start before the previous record's data.
		if(i>0) {
			if(d->rec_list.rec_data[i].offset < d->rec_list.rec_data[i-1].offset) {
				de_err(c, "Record %d (at %d) starts before previous record (at %d)\n",
					(int)i, (int)d->rec_list.rec_data[i].offset, (int)d->rec_list.rec_data[i-1].offset);
				return 0;
			}
		}
	}
	return 1;
}

// Read "Palm Database record list", and the data it refers to
static int do_read_records(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 i;
	de_int64 x;
	int retval = 0;

	de_dbg(c, "%s record list at %d\n", d->fmt_shortname, (int)pos1);
	de_dbg_indent(c, 1);

	// 6-byte header

	x = de_getui32be(pos1);
	de_dbg(c, "nextRecordListID: %d\n", (int)x);
	if(x!=0) {
		de_warn(c, "This file contains multiple record lists, which is not supported.\n");
	}

	d->rec_list.num_recs = de_getui16be(pos1+4);
	de_dbg(c, "number of records: %d\n", (int)d->rec_list.num_recs);

	/////

	if(d->file_fmt==FMT_PRC) d->rec_size = 10;
	else d->rec_size = 8;

	if(!do_prescan_records(c, d, pos1+6)) goto done;

	for(i=0; i<d->rec_list.num_recs; i++) {
		if(d->file_fmt==FMT_PRC) {
			if(!do_read_prc_record(c, d, i, pos1+6+d->rec_size*i))
				goto done;
		}
		else {
			if(!do_read_pdb_record(c, d, i, pos1+6+d->rec_size*i))
				goto done;
		}
	}
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_pqa_app_info_block(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_uint32 sig;
	de_uint32 ux;
	de_ucstring *s = NULL;
	de_int64 pos = pos1;
	int extracted_flag;

	sig = (de_uint32)de_getui32be(pos);
	if(sig!=CODE_lnch) return; // Apparently not a PQA appinfo block
	de_dbg(c, "PQA sig: 0x%08x\n", (unsigned int)sig);
	pos += 4;

	ux = (de_uint32)de_getui16be(pos);
	de_dbg(c, "hdrVersion: 0x%04x\n", (unsigned int)ux);
	pos += 2;
	ux = (de_uint32)de_getui16be(pos);
	de_dbg(c, "encVersion: 0x%04x\n", (unsigned int)ux);
	pos += 2;

	s = ucstring_create(c);

	ux = (de_uint32)de_getui16be(pos);
	pos += 2;
	dbuf_read_to_ucstring_n(c->infile, pos, ux*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "verStr: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_empty(s);
	pos += 2*ux;

	ux = (de_uint32)de_getui16be(pos);
	pos += 2;
	dbuf_read_to_ucstring_n(c->infile, pos, ux*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "pqaTitle: \"%s\"\n", ucstring_get_printable_sz(s));
	ucstring_empty(s);
	pos += 2*ux;

	de_dbg(c, "icon\n");
	de_dbg_indent(c, 1);
	ux = (de_uint32)de_getui16be(pos); // iconWords (length prefix)
	pos += 2;
	// TODO: The logic as to which things to extract is a mess...
	extracted_flag = 0;
	if(!d->rawbitmaps) {
		do_palm_BitmapType(c, d, pos, 2*ux, "icon", DE_CREATEFLAG_IS_AUX);
		extracted_flag = 1;
	}
	if(!extracted_flag) {
		extract_item(c, d, pos, 2*ux, "icon.palm", DE_CREATEFLAG_IS_AUX, d->rawbitmaps?1:0);
	}
	pos += 2*ux;
	de_dbg_indent(c, -1);

	de_dbg(c, "smIcon\n");
	de_dbg_indent(c, 1);
	ux = (de_uint32)de_getui16be(pos); // smIconWords
	pos += 2;
	extracted_flag = 0;
	if(!d->rawbitmaps) {
		do_palm_BitmapType(c, d, pos, 2*ux, "smicon", DE_CREATEFLAG_IS_AUX);
		extracted_flag = 1;
	}
	if(!extracted_flag) {
		extract_item(c, d, pos, 2*ux, "smicon.palm", DE_CREATEFLAG_IS_AUX, d->rawbitmaps?1:0);
	}
	pos += 2*ux;
	de_dbg_indent(c, -1);

	ucstring_destroy(s);
}

static void do_app_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->appinfo_offs==0) return;
	de_dbg(c, "app info block at %d\n", (int)d->appinfo_offs);

	de_dbg_indent(c, 1);
	if(d->sortinfo_offs) {
		len = d->sortinfo_offs - d->appinfo_offs;
	}
	else if(d->rec_list.num_recs>0) {
		len = (de_int64)d->rec_list.rec_data[0].offset - d->appinfo_offs;
	}
	else {
		len = c->infile->len - d->appinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		// TODO: Decide exactly when to extract this, and when to decode it.
		extract_item(c, d, d->appinfo_offs, len, "appinfo.bin", DE_CREATEFLAG_IS_AUX, 0);

		if(d->file_subfmt==SUBFMT_PQA) {
			do_pqa_app_info_block(c, d, d->appinfo_offs, len);
		}
	}

	de_dbg_indent(c, -1);
}

static void do_sort_info_block(deark *c, lctx *d)
{
	de_int64 len;

	if(d->sortinfo_offs==0) return;
	de_dbg(c, "sort info block at %d\n", (int)d->sortinfo_offs);

	de_dbg_indent(c, 1);
	if(d->rec_list.num_recs>0) {
		len = (de_int64)d->rec_list.rec_data[0].offset - d->sortinfo_offs;
	}
	else {
		len = c->infile->len - d->sortinfo_offs;
	}
	de_dbg(c, "calculated len: %d\n", (int)len);

	if(len>0) {
		extract_item(c, d, d->sortinfo_offs, len, "sortinfo.bin", DE_CREATEFLAG_IS_AUX, 0);
	}

	de_dbg_indent(c, -1);
}

static void free_lctx(deark *c, lctx *d)
{
	if(d) {
		de_free(c, d->rec_list.rec_data);
		de_free(c, d);
	}
}

static void do_common_opts(deark *c, lctx *d)
{
	if(de_get_ext_option(c, "palm:nocolortable")) {
		// Enables a hack, for files that apparently set the hasColorTable flag
		// incorrectly
		d->ignore_color_table_flag = 1;
	}
}

static void de_run_pdb_or_prc(deark *c, lctx *d, de_module_params *mparams)
{
	do_common_opts(c, d);
	if(de_get_ext_option(c, "palm:rawbitmaps")) {
		// Hard to decide if this should be the default, or even the only, setting.
		d->rawbitmaps = 1;
	}

	if(!do_read_header(c, d)) goto done;
	if(!do_read_records(c, d, 72)) goto done;
	do_app_info_block(c, d);
	do_sort_info_block(c, d);
done:
	;
}

static void de_run_palmdb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	d = de_malloc(c, sizeof(lctx));
	d->file_fmt = FMT_PDB;
	de_run_pdb_or_prc(c, d, mparams);
	free_lctx(c, d);
}

static void de_run_palmrc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	d = de_malloc(c, sizeof(lctx));
	d->file_fmt = FMT_PRC;
	de_run_pdb_or_prc(c, d, mparams);
	free_lctx(c, d);
}

static void de_run_palmbitmap(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	d = de_malloc(c, sizeof(lctx));
	do_common_opts(c, d);
	do_palm_BitmapType(c, d, 0, c->infile->len, NULL, 0);
	free_lctx(c, d);
}

static int de_identify_palmdb(deark *c)
{
	int has_ext = 0;
	de_byte id[8];
	static const char *exts[] = {"pdb", "prc", "pqa", "mobi"};
	static const char *ids[] = {"vIMGView", "TEXtREAd", "pqa clpr", "BOOKMOBI"};
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}
	if(!has_ext) return 0;

	de_read(id, 60, 8);

	if(!de_memcmp(id, "appl", 4)) return 0; // PRC, not PDB

	for(k=0; k<DE_ITEMS_IN_ARRAY(ids); k++) {
		if(!de_memcmp(id, ids[k], 8)) return 100;
	}

	// TODO: More work is needed here.
	return 0;
}

static int de_identify_palmrc(deark *c)
{
	de_byte id[8];

	// TODO: Improve this ID algorithm
	if(!de_input_file_has_ext(c, "prc")) return 0;
	de_read(id, 60, 8);
	if(!de_memcmp(id, "appl", 4)) return 100;
	return 0;
}

static int de_identify_palmbitmap(deark *c)
{
	if(de_input_file_has_ext(c, "palm")) {
		return 15;
	}
	return 0;
}

static void de_help_common(deark *c)
{
	de_msg(c, "-opt palm:nocolortable : Ignore the hasColorTable flag, if set\n");
}

static void de_help_pdb_prc(deark *c)
{
	de_msg(c, "-opt palm:rawbitmaps : Leave BitmapType images in that format\n");
	de_help_common(c);
}

void de_module_palmdb(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmdb";
	mi->desc = "Palm OS PDB, PQA";
	mi->run_fn = de_run_palmdb;
	mi->identify_fn = de_identify_palmdb;
	mi->help_fn = de_help_pdb_prc;
}

void de_module_palmrc(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmrc";
	mi->desc = "Palm OS PRC";
	mi->run_fn = de_run_palmrc;
	mi->identify_fn = de_identify_palmrc;
	mi->help_fn = de_help_pdb_prc;
}

void de_module_palmbitmap(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmbitmap";
	mi->desc = "Palm BitmapType";
	mi->run_fn = de_run_palmbitmap;
	mi->identify_fn = de_identify_palmbitmap;
	mi->help_fn = de_help_common;
}
