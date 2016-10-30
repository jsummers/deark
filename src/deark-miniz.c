// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Interface to miniz

#include "deark-config.h"
#include "deark-private.h"

struct deark_file_attribs {
	de_int64 modtime; // Unix time_t format
	int modtime_valid;
	de_byte is_executable;
	de_uint16 extra_data_central_size;
	de_uint16 extra_data_local_size;
	de_byte *extra_data_central;
	de_byte *extra_data_local;
};

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "../foreign/miniz.h"

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

	if(img->invalid_image_flag) {
		return 0;
	}
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

static int de_deflate_internal(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf,
	int is_zlib, de_int64 *bytes_consumed)
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

	*bytes_consumed = 0;
	c = inf->c;
	if(inputsize<0) {
		de_err(c, "Internal error\n");
		goto done;
	}

	de_memset(&strm,0,sizeof(strm));
	if(is_zlib) {
		ret = mz_inflateInit(&strm);
	}
	else {
		ret = mz_inflateInit2(&strm, -MZ_DEFAULT_WINDOW_BITS);
	}
	if(ret!=MZ_OK) {
		de_err(c, "Inflate error\n");
		goto done;
	}

	stream_open_flag = 1;

	input_cur_pos = inputstart;
	input_remaining = inputsize;

	de_dbg2(c, "inflating up to %d bytes\n", (int)input_remaining);

	while(1) {

		de_dbg3(c, "input remaining: %d\n", (int)input_remaining);
		if(input_remaining<=0) break;

		// fill input buffer
		input_bytes_this_time = sizeof(inbuf);
		if(input_bytes_this_time>input_remaining) input_bytes_this_time=input_remaining;

		if(input_bytes_this_time<=0) break;
		de_dbg3(c, "processing %d input bytes\n", (int)input_bytes_this_time);

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
			de_dbg3(c, "got %d output bytes\n", (int)output_bytes_this_time);

			dbuf_write(outf, outbuf, output_bytes_this_time);

			if(ret==MZ_STREAM_END) {
				de_dbg2(c, "inflate finished normally\n");
				retval = 1;
				goto done;
			}

			if(strm.avail_out!=0) break;
		}
	}
	retval = 1;

done:
	if(retval) {
		*bytes_consumed = (de_int64)strm.total_in;
		de_dbg2(c, "inflated %u to %u bytes\n", (unsigned int)strm.total_in,
			(unsigned int)strm.total_out);
	}
	if(stream_open_flag) {
		mz_inflateEnd(&strm);
	}
	return retval;
}

int de_uncompress_zlib(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf)
{
	de_int64 bytes_consumed;
	return de_deflate_internal(inf, inputstart, inputsize, outf, 1, &bytes_consumed);
}

int de_uncompress_deflate(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf,
	de_int64 *bytes_consumed)
{
	return de_deflate_internal(inf, inputstart, inputsize, outf, 0, bytes_consumed);
}

// A customized copy of mz_zip_writer_init_file().
// Customized to support Unicode filenames (on Windows), and to better
// report errors.
static mz_bool my_mz_zip_writer_init_file(deark *c, mz_zip_archive *pZip, const char *pFilename)
{
  MZ_FILE *pFile;
  mz_uint64 size_to_reserve_at_beginning = 0;
  char msgbuf[200];

  pZip->m_pWrite = mz_zip_file_write_func;
  pZip->m_pIO_opaque = pZip;
  if (!mz_zip_writer_init(pZip, size_to_reserve_at_beginning))
  {
    de_err(c, "Failed to initialize ZIP file\n");
    return MZ_FALSE;
  }
  if (NULL == (pFile = de_fopen(c, pFilename, "wb", msgbuf, sizeof(msgbuf))))
  {
    de_err(c, "Failed to write %s: %s\n", pFilename, msgbuf);
    mz_zip_writer_end(pZip);
    return MZ_FALSE;
  }
  pZip->m_pState->m_pFile = pFile;
  return MZ_TRUE;
}

int de_zip_create_file(deark *c)
{
	mz_zip_archive *zip;
	mz_bool b;
	const char *arcfn;
	const char *s;

	if(c->zip_file) return 1; // Already created. Shouldn't happen.

	zip = de_malloc(c, sizeof(mz_zip_archive));

	arcfn = c->output_archive_filename;
	if(!arcfn) arcfn = "output.zip";

	b = my_mz_zip_writer_init_file(c, zip, arcfn);
	if(!b) {
		de_free(c, zip);
		return 0;
	}
	de_msg(c, "Creating %s\n", arcfn);

	c->zip_file = (void*)zip;

	s = de_get_ext_option(c, "archive:repro");
	if(s) {
		c->reproducible_output = 1;
	}

	return 1;
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
	mz_zip_archive *zip;
	struct deark_file_attribs dfa;

	de_memset(&dfa, 0, sizeof(struct deark_file_attribs));

	if(!c->zip_file) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
			return;
		}
	}

	zip = (mz_zip_archive*)c->zip_file;

	de_dbg(c, "adding to zip: name:%s len:%d\n", f->name, (int)dbuf_get_length(f));

	if(c->preserve_file_times && f->mod_time.is_valid) {
		dfa.modtime = de_timestamp_to_unix_time(&f->mod_time);
		dfa.modtime_valid = 1;
	}
	else if(c->reproducible_output) {
		// An arbitrary timestamp (2010-09-08 07:06:05)
		dfa.modtime = 1283929565LL;
		dfa.modtime_valid = 1;
	}
	else {
		if(!c->current_time.is_valid) {
			// Get/record the current time. (We'll use the same "current time"
			// for all files in this archive.)
			de_current_time_to_timestamp(&c->current_time);
		}

		dfa.modtime = de_timestamp_to_unix_time(&c->current_time);
		dfa.modtime_valid = 1;
	}

	dfa.is_executable = f->is_executable;

	// Create ZIP "extra data" "Extended Timestamp" fields, containing the
	// UTC timestamp.
	// Note: Although our central and local extra data fields happen to be
	// identical, that is not usually the case for tag 0x5455.
	dfa.extra_data_local_size = 4 + 5;
	dfa.extra_data_central_size = 4 + 5;
	dfa.extra_data_local = de_malloc(c, (de_int64)dfa.extra_data_local_size);
	dfa.extra_data_central = de_malloc(c, (de_int64)dfa.extra_data_central_size);

	de_writeui16le_direct(&dfa.extra_data_local[0], 0x5455);
	de_writeui16le_direct(&dfa.extra_data_local[2], (de_int64)(dfa.extra_data_local_size-4));
	de_writeui16le_direct(&dfa.extra_data_central[0], 0x5455);
	de_writeui16le_direct(&dfa.extra_data_central[2], (de_int64)(dfa.extra_data_central_size-4));

	dfa.extra_data_local[4] = 0x01; // has-modtime flag
	de_writeui32le_direct(&dfa.extra_data_local[5], dfa.modtime);
	dfa.extra_data_central[4] = dfa.extra_data_local[4];
	de_writeui32le_direct(&dfa.extra_data_central[5], dfa.modtime);

	mz_zip_writer_add_mem(zip, f->name, f->membuf_buf, (size_t)dbuf_get_length(f),
		MZ_BEST_COMPRESSION, &dfa);

	de_free(c, dfa.extra_data_local);
	de_free(c, dfa.extra_data_central);
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

de_uint32 de_crc32(const void *buf, de_int64 buf_len)
{
	return (de_uint32)mz_crc32(MZ_CRC32_INIT, (const mz_uint8*)buf, (size_t)buf_len);
}
