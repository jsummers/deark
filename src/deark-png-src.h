// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// PNG encoding
// (This file is #included by deark-miniz.c.)

#define CODE_IDAT 0x49444154U
#define CODE_IEND 0x49454e44U
#define CODE_IHDR 0x49484452U
#define CODE_htSP 0x68745350U
#define CODE_pHYs 0x70485973U
#define CODE_tEXt 0x74455874U
#define CODE_tIME 0x74494d45U

struct deark_png_encode_info {
	int width, height;
	int num_chans;
	int flip;
	unsigned int level;
	int has_phys;
	mz_uint32 xdens;
	mz_uint32 ydens;
	mz_uint8 phys_units;
	deark *c;
	dbuf *outf;
	struct de_timestamp image_mod_time;
	u8 include_text_chunk_software;
	u8 has_hotspot;
	int hotspot_x, hotspot_y;
};

static void write_png_chunk_raw(dbuf *outf, const u8 *src, i64 src_len,
	u32 chunktype)
{
	u32 crc;
	u8 buf[4];

	// length field
	dbuf_writeu32be(outf, src_len);

	// chunk type field
	de_writeu32be_direct(buf, (i64)chunktype);
	crc = de_crc32(buf, 4);
	dbuf_write(outf, buf, 4);

	// data field
	crc = de_crc32_continue(crc, src, src_len);
	dbuf_write(outf, src, src_len);

	// CRC field
	dbuf_writeu32be(outf, (i64)crc);
}

static void write_png_chunk_from_cdbuf(dbuf *outf, dbuf *cdbuf, u32 chunktype)
{
	// We really shouldn't access ->membuf_buf directly, but we'll allow it
	// here as a performance optimization.
	write_png_chunk_raw(outf, cdbuf->membuf_buf, cdbuf->len, chunktype);
}

static void write_png_chunk_IHDR(struct deark_png_encode_info *pei,
	dbuf *cdbuf)
{
	static const u8 color_type_code[] = {0x00, 0x00, 0x04, 0x02, 0x06};

	dbuf_writeu32be(cdbuf, (i64)pei->width);
	dbuf_writeu32be(cdbuf, (i64)pei->height);
	dbuf_writebyte(cdbuf, 8); // bit depth
	dbuf_writebyte(cdbuf, color_type_code[pei->num_chans]);
	dbuf_truncate(cdbuf, 13); // rest of chunk is zeroes
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_IHDR);
}

static void write_png_chunk_pHYs(struct deark_png_encode_info *pei,
	dbuf *cdbuf)
{
	dbuf_writeu32be(cdbuf, (i64)pei->xdens);
	dbuf_writeu32be(cdbuf, (i64)pei->ydens);
	dbuf_writebyte(cdbuf, pei->phys_units);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_pHYs);
}

static void write_png_chunk_tIME(struct deark_png_encode_info *pei,
	dbuf *cdbuf)
{
	struct de_struct_tm tm2;

	de_gmtime(&pei->image_mod_time, &tm2);
	if(!tm2.is_valid) return;

	dbuf_writeu16be(cdbuf, (i64)tm2.tm_fullyear);
	dbuf_writebyte(cdbuf, (u8)(1+tm2.tm_mon));
	dbuf_writebyte(cdbuf, (u8)tm2.tm_mday);
	dbuf_writebyte(cdbuf, (u8)tm2.tm_hour);
	dbuf_writebyte(cdbuf, (u8)tm2.tm_min);
	dbuf_writebyte(cdbuf, (u8)tm2.tm_sec);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_tIME);
}

static void write_png_chunk_htSP(struct deark_png_encode_info *pei,
	dbuf *cdbuf)
{
	// This is the UUID b9fe4f3d-8f32-456f-aa02-dcd79cce0e24
	static const u8 uuid[16] = {0xb9,0xfe,0x4f,0x3d,0x8f,0x32,0x45,0x6f,
		0xaa,0x02,0xdc,0xd7,0x9c,0xce,0x0e,0x24};

	dbuf_write(cdbuf, uuid, 16);
	dbuf_writei32be(cdbuf, (i64)pei->hotspot_x);
	dbuf_writei32be(cdbuf, (i64)pei->hotspot_y);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_htSP);
}

static void write_png_chunk_tEXt(struct deark_png_encode_info *pei,
	dbuf *cdbuf, const char *keyword, const char *value)
{
	i64 kwlen, vlen;
	kwlen = (i64)de_strlen(keyword);
	vlen = (i64)de_strlen(value);
	dbuf_write(cdbuf, (const u8*)keyword, kwlen);
	dbuf_writebyte(cdbuf, 0);
	dbuf_write(cdbuf, (const u8*)value, vlen);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_tEXt);
}

#define MY_MZ_MIN(a,b) (((a)<(b))?(a):(b))

static int write_png_chunk_IDAT(struct deark_png_encode_info *pei, dbuf *cdbuf,
	const mz_uint8 *src_pixels)
{
	int bpl = pei->width * pei->num_chans; // bytes per row in src_pixels
	int y;
	static const char nulbyte = '\0';
	int retval = 0;
	deark *c = pei->c;
	struct fmtutil_tdefl_ctx *tdctx = NULL;
	static const mz_uint my_s_tdefl_num_probes[11] = { 0, 1, 6, 32,  16, 32, 128, 256,  512, 768, 1500 };

	// compress image data
	tdctx = fmtutil_tdefl_create(c, cdbuf,
		my_s_tdefl_num_probes[MY_MZ_MIN(10, pei->level)] | TDEFL_WRITE_ZLIB_HEADER);

	for (y = 0; y < pei->height; ++y) {
		fmtutil_tdefl_compress_buffer(tdctx, &nulbyte, 1, TDEFL_NO_FLUSH);
		fmtutil_tdefl_compress_buffer(tdctx, &src_pixels[(pei->flip ? (pei->height - 1 - y) : y) * bpl],
			bpl, FMTUTIL_TDEFL_NO_FLUSH);
	}
	if (fmtutil_tdefl_compress_buffer(tdctx, NULL, 0, FMTUTIL_TDEFL_FINISH) !=
		FMTUTIL_TDEFL_STATUS_DONE)
	{
		goto done;
	}

	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_IDAT);

	retval = 1;

done:
	fmtutil_tdefl_destroy(tdctx);
	return retval;
}

static int do_generate_png(struct deark_png_encode_info *pei, const mz_uint8 *src_pixels)
{
	static const u8 pngsig[8] = { 0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a };
	dbuf *cdbuf = NULL;
	int retval = 0;

	// A membuf that we'll use and reuse for each chunk's data
	cdbuf = dbuf_create_membuf(pei->c, 64, 0);

	dbuf_write(pei->outf, pngsig, 8);

	write_png_chunk_IHDR(pei, cdbuf);

	if(pei->has_phys) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_pHYs(pei, cdbuf);
	}

	if(pei->image_mod_time.is_valid && pei->c->preserve_file_times_images) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_tIME(pei, cdbuf);
	}

	if(pei->has_hotspot) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_htSP(pei, cdbuf);
	}

	if(pei->include_text_chunk_software) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_tEXt(pei, cdbuf, "Software", "Deark");
	}

	dbuf_truncate(cdbuf, 0);
	if(!write_png_chunk_IDAT(pei, cdbuf, src_pixels)) goto done;

	dbuf_truncate(cdbuf, 0);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_IEND);
	retval = 1;

done:
	dbuf_close(cdbuf);
	return retval;
}

int de_write_png(deark *c, de_bitmap *img, dbuf *f)
{
	const char *opt_level;
	struct deark_png_encode_info pei;

	de_zeromem(&pei, sizeof(struct deark_png_encode_info));

	if(img->invalid_image_flag) {
		return 0;
	}
	if(!de_good_image_dimensions(c, img->width, img->height)) {
		return 0;
	}

	if(f->btype==DBUF_TYPE_NULL) {
		return 0;
	}

	if(f->fi_copy && f->fi_copy->density.code>0 && c->write_density) {
		pei.has_phys = 1;
		if(f->fi_copy->density.code==1) { // unspecified units
			pei.phys_units = 0;
			pei.xdens = (mz_uint32)(f->fi_copy->density.xdens+0.5);
			pei.ydens = (mz_uint32)(f->fi_copy->density.ydens+0.5);
		}
		else if(f->fi_copy->density.code==2) { // dpi
			pei.phys_units = 1; // pixels/meter
			pei.xdens = (mz_uint32)(0.5+f->fi_copy->density.xdens/0.0254);
			pei.ydens = (mz_uint32)(0.5+f->fi_copy->density.ydens/0.0254);
		}
	}

	if(pei.has_phys && pei.xdens==pei.ydens && pei.phys_units==0) {
		// Useless density information. Don't bother to write it.
		pei.has_phys = 0;
	}

	// Detect likely-bogus density settings.
	if(pei.has_phys) {
		if(pei.xdens<=0 || pei.ydens<=0 ||
			(pei.xdens > pei.ydens*5) || (pei.ydens > pei.xdens*5))
		{
			pei.has_phys = 0;
		}
	}

	pei.c = c;
	pei.outf = f;
	pei.width = (int)img->width;
	pei.height = (int)img->height;
	pei.flip = img->flipped;
	pei.num_chans = img->bytes_per_pixel;
	pei.include_text_chunk_software = 0;

	if(!c->pngcprlevel_valid) {
		c->pngcmprlevel = 9; // default
		c->pngcprlevel_valid = 1;

		opt_level = de_get_ext_option(c, "pngcmprlevel");
		if(opt_level) {
			i64 opt_level_n = de_atoi64(opt_level);
			if(opt_level_n>10) {
				c->pngcmprlevel = 10;
			}
			else if(opt_level_n<0) {
				c->pngcmprlevel = 6;
			}
			else {
				c->pngcmprlevel = (unsigned int)opt_level_n;
			}
		}
	}
	pei.level = c->pngcmprlevel;

	if(f->fi_copy && f->fi_copy->image_mod_time.is_valid) {
		pei.image_mod_time = f->fi_copy->image_mod_time;
	}

	if(f->fi_copy && f->fi_copy->has_hotspot) {
		pei.has_hotspot = 1;
		pei.hotspot_x = f->fi_copy->hotspot_x;
		pei.hotspot_y = f->fi_copy->hotspot_y;
		// Leave a hint as to where our custom Hotspot chunk came from.
		pei.include_text_chunk_software = 1;
	}

	if(!do_generate_png(&pei, img->bitmap)) {
		de_err(c, "PNG write failed");
		return 0;
	}

	return 1;
}
