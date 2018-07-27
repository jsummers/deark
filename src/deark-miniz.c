// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Interface to miniz

#define DE_NOT_IN_MODULE
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

// Our custom version of mz_zip_archive
struct zip_data_struct {
	deark *c;
	mz_zip_archive *pZip;
};

struct deark_png_encode_info {
	int has_phys;
	mz_uint32 xdens;
	mz_uint32 ydens;
	mz_uint8 phys_units;
};

// A copy of tdefl_write_image_to_png_file_in_memory_ex from miniz,
// hacked to support pHYs chunks.
static void *my_tdefl_write_image_to_png_file_in_memory_ex(const void *pImage, int w, int h, int num_chans,
	size_t *pLen_out, mz_uint level, mz_bool flip, const struct deark_png_encode_info *pei)
{
	tdefl_compressor *pComp = (tdefl_compressor *)MZ_MALLOC(sizeof(tdefl_compressor));
	tdefl_output_buffer out_buf;
	int bpl = w * num_chans, y, z;
	mz_uint32 c;
	size_t idat_data_offset;
	size_t size_of_extra_chunks = 0;
	size_t curpos = 0;
	static const char nulbyte = '\0';

	*pLen_out = 0;
	if (!pComp) return NULL;
	de_memset(pComp,0,sizeof(tdefl_compressor));

	if(pei->has_phys) size_of_extra_chunks += 21;

	idat_data_offset = 41 + size_of_extra_chunks;

	MZ_CLEAR_OBJ(out_buf);
	out_buf.m_expandable = MZ_TRUE;
	out_buf.m_capacity = 57+MZ_MAX(64, (1+bpl)*h) + size_of_extra_chunks;
	if (NULL == (out_buf.m_pBuf = (mz_uint8*)MZ_MALLOC(out_buf.m_capacity))) { MZ_FREE(pComp); return NULL; }

	// write dummy header
	for (z = (int)idat_data_offset; z; --z) tdefl_output_buffer_putter(&nulbyte, 1, &out_buf);

	// compress image data
	// TODO: It seems illogical to do this before writing the things that precede IDAT,
	// though I guess it does ensure that out_buf.m_pBuf has enough bytes allocated.
	tdefl_init(pComp, tdefl_output_buffer_putter, &out_buf, s_tdefl_num_probes[MZ_MIN(10, level)] | TDEFL_WRITE_ZLIB_HEADER);

	for (y = 0; y < h; ++y) {
		tdefl_compress_buffer(pComp, &nulbyte, 1, TDEFL_NO_FLUSH);
		tdefl_compress_buffer(pComp, (mz_uint8*)pImage + (flip ? (h - 1 - y) : y) * bpl, bpl, TDEFL_NO_FLUSH);
	}
	if (tdefl_compress_buffer(pComp, NULL, 0, TDEFL_FINISH) != TDEFL_STATUS_DONE) { MZ_FREE(pComp); MZ_FREE(out_buf.m_pBuf); return NULL; }

	// write real header
	// (signature, and entire IHDR chunk)
	*pLen_out = out_buf.m_size-idat_data_offset;

	{
		static const mz_uint8 chans[] = {0x00, 0x00, 0x04, 0x02, 0x06};
		mz_uint8 pnghdr[33]={
			0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a, // 8-byte signature
			0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52, // IHDR length, type
			0,0,0,0,0,0,0,0,8,0,0,0,0, // 13 bytes of IHDR data
			0,0,0,0 // IHDR CRC
		};
		de_writeui32be_direct(&pnghdr[8+8+0], w);
		de_writeui32be_direct(&pnghdr[8+8+4], h);
		pnghdr[25] = chans[num_chans];
		c=(mz_uint32)mz_crc32(MZ_CRC32_INIT,pnghdr+12,17);
		de_writeui32be_direct(&pnghdr[8+8+13], (de_int64)c); // Set IHDR CRC
		de_memcpy(out_buf.m_pBuf, pnghdr, 33);
		curpos += 8+8+13+4;
	}

	if(pei->has_phys) {
		de_writeui32be_direct(out_buf.m_pBuf+curpos+0, 9); // pHYs chunk data length (always 9)
		de_memcpy(&out_buf.m_pBuf[curpos+4], "pHYs", 4);
		de_writeui32be_direct(out_buf.m_pBuf+curpos+8, (de_int64)pei->xdens);
		de_writeui32be_direct(out_buf.m_pBuf+curpos+12, (de_int64)pei->ydens);
		out_buf.m_pBuf[curpos+16] = pei->phys_units;
		c=(mz_uint32)mz_crc32(MZ_CRC32_INIT,out_buf.m_pBuf+curpos+4,13);
		de_writeui32be_direct(out_buf.m_pBuf+curpos+17, (de_int64)c);
		curpos += 8+9+4;
	}

	// Write IDAT header (chunk length and type)
	{
		mz_uint8 idathdr[8]={
			0, 0, 0, 0, // IDAT len,
			0x49,0x44,0x41,0x54 // IDAT type
		};
		de_writeui32be_direct(&idathdr[0], (de_int64)(*pLen_out));
		de_memcpy(out_buf.m_pBuf+(idat_data_offset-8), idathdr, 8);
	}

	// write footer (IDAT CRC-32, followed by IEND chunk)
	if (!tdefl_output_buffer_putter("\0\0\0\0\0\0\0\0\x49\x45\x4e\x44\xae\x42\x60\x82", 16, &out_buf)) {
		*pLen_out = 0; MZ_FREE(pComp); MZ_FREE(out_buf.m_pBuf); return NULL;
	}
	c = (mz_uint32)mz_crc32(MZ_CRC32_INIT,out_buf.m_pBuf+idat_data_offset-4, *pLen_out+4);
	de_writeui32be_direct(out_buf.m_pBuf+out_buf.m_size-16, (de_int64)c);

	// compute final size of file, grab compressed data buffer and return
	*pLen_out += 16 + idat_data_offset;
	MZ_FREE(pComp);
	return out_buf.m_pBuf;
}

int de_write_png(deark *c, de_bitmap *img, dbuf *f)
{
	size_t len_out = 0;
	de_byte *memblk = NULL;
	struct deark_png_encode_info pei;

	de_memset(&pei, 0, sizeof(struct deark_png_encode_info));

	if(img->invalid_image_flag) {
		return 0;
	}
	if(!de_good_image_dimensions(c, img->width, img->height)) {
		return 0;
	}

	if(f->btype==DBUF_TYPE_NULL) {
		return 0;
	}

	if(img->density_code>0 && c->write_density) {
		pei.has_phys = 1;
		if(img->density_code==1) { // unspecified units
			pei.phys_units = 0;
			pei.xdens = (mz_uint32)(img->xdens+0.5);
			pei.ydens = (mz_uint32)(img->ydens+0.5);
		}
		else if(img->density_code==2) { // dpi
			pei.phys_units = 1; // pixels/meter
			pei.xdens = (mz_uint32)(0.5+img->xdens/0.0254);
			pei.ydens = (mz_uint32)(0.5+img->ydens/0.0254);
		}
	}

	if(pei.has_phys && pei.xdens==pei.ydens && img->density_code==1) {
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

	memblk = my_tdefl_write_image_to_png_file_in_memory_ex(img->bitmap,
		(int)img->width, (int)img->height, img->bytes_per_pixel, &len_out, 9, img->flipped,
		&pei);

	if(!memblk) {
		de_err(c, "PNG write failed");
		return 0;
	}

	dbuf_write(f, memblk, len_out);

	mz_free(memblk);
	return 1;
}

static int de_inflate_internal(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf,
	int is_zlib, de_int64 *bytes_consumed)
{
	mz_stream strm;
	int ret;
	int retval = 0;
#define DE_DFL_INBUF_SIZE   32768
#define DE_DFL_OUTBUF_SIZE  (DE_DFL_INBUF_SIZE*4)
	de_byte *inbuf = NULL;
	de_byte *outbuf = NULL;
	de_int64 inbuf_num_valid_bytes; // Number of valid bytes in inbuf, starting with [0].
	de_int64 inbuf_num_consumed_bytes; // Of inbuf_num_valid_bytes, the number that have been consumed.
	de_int64 inbuf_num_consumed_bytes_this_time;

	unsigned int orig_avail_in;
	de_int64 input_cur_pos;
	de_int64 output_bytes_this_time;
	de_int64 nbytes_to_read;
	deark *c;
	int stream_open_flag = 0;

	*bytes_consumed = 0;
	c = inf->c;
	if(inputsize<0) {
		de_err(c, "Internal error");
		goto done;
	}

	inbuf = de_malloc(c, DE_DFL_INBUF_SIZE);
	outbuf = de_malloc(c, DE_DFL_OUTBUF_SIZE);

	de_memset(&strm,0,sizeof(strm));
	if(is_zlib) {
		ret = mz_inflateInit(&strm);
	}
	else {
		ret = mz_inflateInit2(&strm, -MZ_DEFAULT_WINDOW_BITS);
	}
	if(ret!=MZ_OK) {
		de_err(c, "Inflate error");
		goto done;
	}

	stream_open_flag = 1;

	input_cur_pos = inputstart;

	inbuf_num_valid_bytes = 0;
	inbuf_num_consumed_bytes = 0;

	de_dbg2(c, "inflating up to %d bytes", (int)inputsize);

	while(1) {
		de_dbg3(c, "input remaining: %d", (int)(inputstart+inputsize-input_cur_pos));

		// If we have read all the available bytes from the file,
		// and all bytes in inbuf are consumed, then stop.
		if((inbuf_num_consumed_bytes>=inbuf_num_valid_bytes) && (input_cur_pos-inputstart)>=inputsize) break;

		if(inbuf_num_consumed_bytes>0) {
			if(inbuf_num_valid_bytes>inbuf_num_consumed_bytes) {
				// Move unconsumed bytes to the beginning of the input buffer
				de_memmove(inbuf, &inbuf[inbuf_num_consumed_bytes], (size_t)(inbuf_num_valid_bytes-inbuf_num_consumed_bytes));
				inbuf_num_valid_bytes -= inbuf_num_consumed_bytes;
				inbuf_num_consumed_bytes = 0;
			}
			else {
				inbuf_num_valid_bytes = 0;
				inbuf_num_consumed_bytes = 0;
			}
		}

		nbytes_to_read = inputstart+inputsize-input_cur_pos;
		if(nbytes_to_read>DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes) {
			nbytes_to_read = DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes;
		}

		// top off input buffer
		dbuf_read(inf, &inbuf[inbuf_num_valid_bytes], input_cur_pos, nbytes_to_read);
		input_cur_pos += nbytes_to_read;
		inbuf_num_valid_bytes += nbytes_to_read;

		strm.next_in = inbuf;
		strm.avail_in = (unsigned int)inbuf_num_valid_bytes;
		orig_avail_in = strm.avail_in;

		strm.next_out = outbuf;
		strm.avail_out = DE_DFL_OUTBUF_SIZE;

		ret = mz_inflate(&strm, MZ_SYNC_FLUSH);
		if(ret!=MZ_STREAM_END && ret!=MZ_OK) {
			de_err(c, "Inflate error (%d)", (int)ret);
			goto done;
		}

		output_bytes_this_time = DE_DFL_OUTBUF_SIZE - strm.avail_out;
		de_dbg3(c, "got %d output bytes", (int)output_bytes_this_time);

		dbuf_write(outf, outbuf, output_bytes_this_time);

		if(ret==MZ_STREAM_END) {
			de_dbg2(c, "inflate finished normally");
			retval = 1;
			goto done;
		}

		inbuf_num_consumed_bytes_this_time = (de_int64)(orig_avail_in - strm.avail_in);
		if(inbuf_num_consumed_bytes_this_time<1 && output_bytes_this_time<1) {
			de_err(c, "Inflate error");
			goto done;
		}
		inbuf_num_consumed_bytes += inbuf_num_consumed_bytes_this_time;
	}

	retval = 1;

done:
	if(retval) {
		*bytes_consumed = (de_int64)strm.total_in;
		de_dbg2(c, "inflated %u to %u bytes", (unsigned int)strm.total_in,
			(unsigned int)strm.total_out);
	}
	if(stream_open_flag) {
		mz_inflateEnd(&strm);
	}
	de_free(c, inbuf);
	de_free(c, outbuf);
	return retval;
}

int de_uncompress_zlib(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf)
{
	de_int64 bytes_consumed;
	return de_inflate_internal(inf, inputstart, inputsize, outf, 1, &bytes_consumed);
}

int de_uncompress_deflate(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf,
	de_int64 *bytes_consumed)
{
	return de_inflate_internal(inf, inputstart, inputsize, outf, 0, bytes_consumed);
}

// TODO: We'd like to us a dbuf for ZIP output, both to make our I/O functions
// consistent, and with the idea that we could write a ZIP file to stdout (via
// a membuf). That will take a lot of work, though. For one thing, file-output
// dbufs don't even support seeking yet.
static size_t my_mz_zip_file_write_func(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
  struct zip_data_struct *zzz = (struct zip_data_struct*)pOpaque;
  mz_zip_archive *pZip = zzz->pZip;
  mz_int64 cur_ofs = MZ_FTELL64(pZip->m_pState->m_pFile);
  if (((mz_int64)file_ofs < 0) || (((cur_ofs != (mz_int64)file_ofs)) && (MZ_FSEEK64(pZip->m_pState->m_pFile, (mz_int64)file_ofs, SEEK_SET))))
    return 0;
  return MZ_FWRITE(pBuf, 1, n, pZip->m_pState->m_pFile);
}

// A customized copy of mz_zip_writer_init_file().
// Customized to support Unicode filenames (on Windows), and to better
// report errors.
static mz_bool my_mz_zip_writer_init_file(deark *c, mz_zip_archive *pZip, const char *pFilename)
{
  MZ_FILE *pFile;
  mz_uint64 size_to_reserve_at_beginning = 0;
  char msgbuf[200];

  pZip->m_pWrite = my_mz_zip_file_write_func;
  if (!mz_zip_writer_init(pZip, size_to_reserve_at_beginning))
  {
    de_err(c, "Failed to initialize ZIP file");
    return MZ_FALSE;
  }
  if (NULL == (pFile = de_fopen_for_write(c, pFilename, msgbuf, sizeof(msgbuf), 0)))
  {
    de_err(c, "Failed to write %s: %s", pFilename, msgbuf);
    mz_zip_writer_end(pZip);
    return MZ_FALSE;
  }
  pZip->m_pState->m_pFile = pFile;
  return MZ_TRUE;
}

static void init_reproducible_archive_settings(deark *c)
{
	const char *s;

	s = de_get_ext_option(c, "archive:timestamp");
	if(s) {
		c->reproducible_output = 1;
		de_unix_time_to_timestamp(de_atoi64(s), &c->reproducible_timestamp);
	}
	else {
		if(de_get_ext_option(c, "archive:repro")) {
			c->reproducible_output = 1;
		}
	}
}

int de_zip_create_file(deark *c)
{
	struct zip_data_struct *zzz;
	mz_bool b;
	const char *arcfn;

	if(c->zip_data) return 1; // Already created. Shouldn't happen.

	init_reproducible_archive_settings(c);

	zzz = de_malloc(c, sizeof(struct zip_data_struct));
	zzz->pZip = de_malloc(c, sizeof(mz_zip_archive));
	zzz->c = c;
	zzz->pZip->m_pIO_opaque = (void*)zzz;
	c->zip_data = (void*)zzz;

	arcfn = c->output_archive_filename;
	if(!arcfn) arcfn = "output.zip";

	b = my_mz_zip_writer_init_file(c, zzz->pZip, arcfn);
	if(!b) {
		de_free(c, zzz->pZip);
		de_free(c, zzz);
		c->zip_data = NULL;
		return 0;
	}
	de_msg(c, "Creating %s", arcfn);

	return 1;
}

static de_int64 de_get_reproducible_unix_timestamp(deark *c)
{
	if(c->reproducible_timestamp.is_valid) {
		return de_timestamp_to_unix_time(&c->reproducible_timestamp);
	}

	// An arbitrary timestamp
	// $ date -u --date='2010-09-08 07:06:05' '+%s'
	return 1283929565LL;
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
	struct zip_data_struct *zzz;
	struct deark_file_attribs dfa;

	de_memset(&dfa, 0, sizeof(struct deark_file_attribs));

	if(!c->zip_data) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
			return;
		}
	}

	zzz = (struct zip_data_struct*)c->zip_data;
	if(!zzz) { de_err(c, "asdf"); de_fatalerror(c); }

	de_dbg(c, "adding to zip: name:%s len:%d", f->name, (int)dbuf_get_length(f));

	if(c->preserve_file_times && f->mod_time.is_valid) {
		dfa.modtime = de_timestamp_to_unix_time(&f->mod_time);
		dfa.modtime_valid = 1;
	}
	else if(c->reproducible_output) {
		dfa.modtime = de_get_reproducible_unix_timestamp(c);
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

	dfa.is_executable = (f->mode_flags&DE_MODEFLAG_EXE)?1:0;

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

	mz_zip_writer_add_mem(zzz->pZip, f->name, f->membuf_buf, (size_t)dbuf_get_length(f),
		MZ_BEST_COMPRESSION, &dfa);

	de_free(c, dfa.extra_data_local);
	de_free(c, dfa.extra_data_central);
}

void de_zip_close_file(deark *c)
{
	struct zip_data_struct *zzz;

	if(!c->zip_data) return;
	de_dbg(c, "closing zip file");

	zzz = (struct zip_data_struct*)c->zip_data;

	mz_zip_writer_finalize_archive(zzz->pZip);
	mz_zip_writer_end(zzz->pZip);
	de_dbg(c, "zip file closed");

	de_free(c, zzz->pZip);
	de_free(c, zzz);
	c->zip_data = NULL;
}

// For a one-shot CRC calculations, or the first part of a multi-part
// calculation.
// buf can be NULL (in which case buf_len should be 0, but is ignored)
de_uint32 de_crc32(const void *buf, de_int64 buf_len)
{
	return (de_uint32)mz_crc32(MZ_CRC32_INIT, (const mz_uint8*)buf, (size_t)buf_len);
}

de_uint32 de_crc32_continue(de_uint32 prev_crc, const void *buf, de_int64 buf_len)
{
	return (de_uint32)mz_crc32(prev_crc, (const mz_uint8*)buf, (size_t)buf_len);
}
