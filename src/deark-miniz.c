// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Interface to miniz

#include "deark-config.h"

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "miniz.h"

#include "deark-private.h"


// A copy of tdefl_write_image_to_png_file_in_memory_ex from miniz,
// hacked to support pHYs chunks.
static void *my_tdefl_write_image_to_png_file_in_memory_ex(const void *pImage, int w, int h, int num_chans,
	size_t *pLen_out, mz_uint level, mz_bool flip,
	mz_uint32 xdens, mz_uint32 ydens, mz_uint8 phys_units)
{
	// Using a local copy of this array here in case MINIZ_NO_ZLIB_APIS was defined.
	static const mz_uint s_tdefl_png_num_probes[11] = { 0, 1, 6, 32,  16, 32, 128, 256,  512, 768, 1500 };
	tdefl_compressor *pComp = (tdefl_compressor *)MZ_MALLOC(sizeof(tdefl_compressor));
	tdefl_output_buffer out_buf;
	int i, bpl = w * num_chans, y, z;
	mz_uint32 c;
	size_t idat_data_offset;
	size_t curpos;
	int has_phys;

	has_phys = (xdens>0);

	*pLen_out = 0;
	if (!pComp) return NULL;
	memset(pComp,0,sizeof(tdefl_compressor));
	idat_data_offset = 41;
	if(has_phys) idat_data_offset += 21;

	MZ_CLEAR_OBJ(out_buf);
	out_buf.m_expandable = MZ_TRUE;
	out_buf.m_capacity = 57+MZ_MAX(64, (1+bpl)*h);
	if(has_phys) out_buf.m_capacity += 21;
	if (NULL == (out_buf.m_pBuf = (mz_uint8*)MZ_MALLOC(out_buf.m_capacity))) { MZ_FREE(pComp); return NULL; }

	// write dummy header
	for (z = (int)idat_data_offset; z; --z) tdefl_output_buffer_putter(&z, 1, &out_buf);

	// compress image data
	tdefl_init(pComp, tdefl_output_buffer_putter, &out_buf, s_tdefl_png_num_probes[MZ_MIN(10, level)] | TDEFL_WRITE_ZLIB_HEADER);

	for (y = 0; y < h; ++y) {
		tdefl_compress_buffer(pComp, &z, 1, TDEFL_NO_FLUSH);
		tdefl_compress_buffer(pComp, (mz_uint8*)pImage + (flip ? (h - 1 - y) : y) * bpl, bpl, TDEFL_NO_FLUSH);
	}
	if (tdefl_compress_buffer(pComp, NULL, 0, TDEFL_FINISH) != TDEFL_STATUS_DONE) { MZ_FREE(pComp); MZ_FREE(out_buf.m_pBuf); return NULL; }

	// write real header
	*pLen_out = out_buf.m_size-idat_data_offset;

	{
		static const mz_uint8 chans[] = {0x00, 0x00, 0x04, 0x02, 0x06};
		mz_uint8 pnghdr[33]={
			0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a, // 8-byte signature
			0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52, // IHDR length, type
			0,0,(mz_uint8)(w>>8),(mz_uint8)w,0,0,(mz_uint8)(h>>8),(mz_uint8)h,8,chans[num_chans],0,0,0, // 13 bytes of IHDR data
			0,0,0,0 // IHDR CRC
		};
		c=(mz_uint32)mz_crc32(MZ_CRC32_INIT,pnghdr+12,17);
		for (i=0; i<4; ++i, c<<=8) ((mz_uint8*)(pnghdr+29))[i]=(mz_uint8)(c>>24); // Set IHDR CRC
		memcpy(out_buf.m_pBuf, pnghdr, 33);
	}

	if(has_phys) {
		curpos = 33;
		de_writeui32be_direct(out_buf.m_pBuf+curpos+0, 9); // pHYs chunk data length (always 9)
		out_buf.m_pBuf[curpos+4] = 'p';
		out_buf.m_pBuf[curpos+5] = 'H';
		out_buf.m_pBuf[curpos+6] = 'Y';
		out_buf.m_pBuf[curpos+7] = 's';
		de_writeui32be_direct(out_buf.m_pBuf+curpos+8, (de_int64)xdens);
		de_writeui32be_direct(out_buf.m_pBuf+curpos+12, (de_int64)ydens);
		out_buf.m_pBuf[curpos+16] = phys_units;
		c=(mz_uint32)mz_crc32(MZ_CRC32_INIT,out_buf.m_pBuf+curpos+4,13);
		de_writeui32be_direct(out_buf.m_pBuf+curpos+17, (de_int64)c);
	}

	{
		mz_uint8 idathdr[8]={
			(mz_uint8)(*pLen_out>>24),(mz_uint8)(*pLen_out>>16),(mz_uint8)(*pLen_out>>8),(mz_uint8)*pLen_out, // IDAT len,
			0x49,0x44,0x41,0x54 // IDAT type
		};
		memcpy(out_buf.m_pBuf+(idat_data_offset-8), idathdr, 8);
	}

	// write footer (IDAT CRC-32, followed by IEND chunk)
	if (!tdefl_output_buffer_putter("\0\0\0\0\0\0\0\0\x49\x45\x4e\x44\xae\x42\x60\x82", 16, &out_buf)) {
		*pLen_out = 0; MZ_FREE(pComp); MZ_FREE(out_buf.m_pBuf); return NULL;
	}
	c = (mz_uint32)mz_crc32(MZ_CRC32_INIT,out_buf.m_pBuf+idat_data_offset-4, *pLen_out+4);
	for (i=0; i<4; ++i, c<<=8) (out_buf.m_pBuf+out_buf.m_size-16)[i] = (mz_uint8)(c >> 24);

	// compute final size of file, grab compressed data buffer and return
	*pLen_out += 16 + idat_data_offset;
	MZ_FREE(pComp);
	return out_buf.m_pBuf;
}

int de_write_png(deark *c, struct deark_bitmap *img, dbuf *f)
{
	size_t len_out = 0;
	de_byte *memblk = NULL;
	mz_uint8 phys_units=0;
	mz_uint32 xdens=0;
	mz_uint32 ydens=0;

	if(!de_good_image_dimensions(c, img->width, img->height)) {
		return 0;
	}

	if(img->density_code>0 && c->write_density) {
		if(img->density_code==1) { // unspecified units
			phys_units = 0;
			xdens = (mz_uint32)(img->xdens+0.5);
			ydens = (mz_uint32)(img->ydens+0.5);
		}
		else if(img->density_code==2) { // dpi
			phys_units = 1; // pixels/meter
			xdens = (mz_uint32)(0.5+img->xdens/0.0254);
			ydens = (mz_uint32)(0.5+img->ydens/0.0254);
		}
	}

	if(xdens && xdens==ydens && img->density_code==1) {
		// Useless density information. Don't bother to write it.
		xdens=0;
	}

	// Detect likely-bogus density settings.
	// Note: Density is considered to be valid if xdens>0.
	if(xdens>0) {
		if(xdens > ydens*5 || ydens > xdens*5) {
			xdens=0;
		}
	}

	memblk = my_tdefl_write_image_to_png_file_in_memory_ex(img->bitmap,
		(int)img->width, (int)img->height, img->bytes_per_pixel, &len_out, 9, img->flipped,
		xdens, ydens, phys_units);

	if(!memblk) {
		de_err(c, "PNG write failed\n");
		return 0;
	}

	dbuf_write(f, memblk, len_out);

	mz_free(memblk);
	return 1;
}

int de_uncompress_zlib(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf)
{
	mz_stream strm;
	int ret;
	int retval = 0;
	de_byte inbuf[2048];
	de_byte outbuf[4096];
	de_int64 input_cur_pos;
	de_int64 input_remaining;
	de_int64 input_bytes_this_time;
	de_int64 output_bytes_this_time;
	deark *c;
	int stream_open_flag = 0;

	c = inf->c;

	de_memset(&strm,0,sizeof(strm));
	ret = mz_inflateInit(&strm);
	if(ret!=MZ_OK) {
		de_err(c, "Inflate error\n");
		goto done;
	}

	stream_open_flag = 1;

	input_cur_pos = inputstart;
	input_remaining = inputsize;

	de_dbg(c, "inflating %d bytes\n", (int)input_remaining);

	while(1) {

		de_dbg2(c, "input remaining: %d\n", (int)input_remaining);
		if(input_remaining<=0) break;

		// fill input buffer
		input_bytes_this_time = sizeof(inbuf);
		if(input_bytes_this_time>input_remaining) input_bytes_this_time=input_remaining;

		if(input_bytes_this_time<=0) break;
		de_dbg2(c, "processing %d input bytes\n", (int)input_bytes_this_time);

		dbuf_read(inf, inbuf, input_cur_pos, input_bytes_this_time);
		input_remaining -= input_bytes_this_time;
		input_cur_pos += input_bytes_this_time;

		strm.next_in = inbuf;
		strm.avail_in = (unsigned int)input_bytes_this_time;

		// run inflate() on input until output buffer not full
		while(1) {
			strm.avail_out = sizeof(outbuf);
			strm.next_out = outbuf;

			ret = mz_inflate(&strm, MZ_NO_FLUSH);
			if(ret!=MZ_STREAM_END && ret!=MZ_OK) {
				de_err(c, "Inflate error\n");
				goto done;
			}

			output_bytes_this_time = sizeof(outbuf) - strm.avail_out;
			de_dbg2(c, "got %d output bytes\n", (int)output_bytes_this_time);

			dbuf_write(outf, outbuf, output_bytes_this_time);

			if(ret==MZ_STREAM_END) {
				de_dbg(c, "inflate finished normally\n");
				retval = 1;
				goto done;
			}

			if(strm.avail_out!=0) break;
		}
	}
	retval = 1;

done:
	if(retval) {
		de_dbg(c, "inflated to %d bytes\n", (int)strm.total_out);
	}
	if(stream_open_flag) {
		mz_inflateEnd(&strm);
	}
	return retval;
}

int de_zip_create_file(deark *c)
{
	mz_zip_archive *zip;
	mz_bool b;
	const char *arcfn;

	if(c->zip_file) return 1; // Already created. Shouldn't happen.

	zip = de_malloc(c, sizeof(mz_zip_archive));

	arcfn = c->output_archive_filename;
	if(!arcfn) arcfn = "output.zip";

	b = mz_zip_writer_init_file(zip, arcfn, 0);
	if(!b) {
		de_err(c, "Failed to initialize ZIP file\n");
		de_free(c, zip);
		return 0;
	}
	de_msg(c, "Creating %s\n", arcfn);

	c->zip_file = (void*)zip;
	return 1;
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
	mz_zip_archive *zip;

	if(!c->zip_file) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
		}
	}

	zip = (mz_zip_archive*)c->zip_file;

	de_dbg(c, "adding to zip: name:%s len:%d\n", f->name, (int)dbuf_get_length(f));
	//mz_bool res;
	mz_zip_writer_add_mem(zip, f->name, f->membuf_buf, (size_t)dbuf_get_length(f), MZ_BEST_COMPRESSION);
}

void de_zip_close_file(deark *c)
{
	mz_zip_archive *zip;

	if(!c->zip_file) return;
	de_dbg(c, "closing zip file\n");

	zip = (mz_zip_archive*)c->zip_file;

	mz_zip_writer_finalize_archive(zip);
	mz_zip_writer_end(zip);
	de_dbg(c, "zip file closed\n");

	de_free(c, c->zip_file);
	c->zip_file = NULL;
}
