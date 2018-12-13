// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Interface to miniz

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

struct deark_file_attribs {
	i64 modtime; // Unix time_t format
	int modtime_valid;
	i64 modtime_as_FILETIME; // valid if nonzero
	u8 is_executable;
	u16 extra_data_central_size;
	u16 extra_data_local_size;
	u8 *extra_data_central;
	u8 *extra_data_local;
};

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "../foreign/miniz.h"

// Our custom version of mz_zip_archive
struct zip_data_struct {
	deark *c;
	mz_zip_archive *pZip;
};

#define CODE_IDAT 0x49444154U
#define CODE_IEND 0x49454e44U
#define CODE_IHDR 0x49484452U
#define CODE_pHYs 0x70485973U
#define CODE_tIME 0x74494d45U

struct deark_png_encode_info {
	int width, height;
	int num_chans;
	int flip;
	int level;
	int has_phys;
	mz_uint32 xdens;
	mz_uint32 ydens;
	mz_uint8 phys_units;
	deark *c;
	dbuf *outf;
	struct de_timestamp image_mod_time;
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

static int write_png_chunk_IDAT(struct deark_png_encode_info *pei, const mz_uint8 *src_pixels)
{
	tdefl_compressor *pComp = NULL;
	tdefl_output_buffer out_buf;
	int bpl = pei->width * pei->num_chans; // bytes per row in src_pixels
	int y;
	static const char nulbyte = '\0';
	int retval = 0;

	de_zeromem(&out_buf, sizeof(tdefl_output_buffer));

	pComp = MZ_MALLOC(sizeof(tdefl_compressor));
	if (!pComp) goto done;
	de_zeromem(pComp, sizeof(tdefl_compressor));

	out_buf.m_expandable = MZ_TRUE;
	out_buf.m_capacity = 16+MZ_MAX(64, (1+bpl)*pei->height);
	out_buf.m_pBuf = MZ_MALLOC(out_buf.m_capacity);
	if (!out_buf.m_pBuf) { goto done; }

	// compress image data
	tdefl_init(pComp, tdefl_output_buffer_putter, &out_buf,
		s_tdefl_num_probes[MZ_MIN(10, pei->level)] | TDEFL_WRITE_ZLIB_HEADER);

	for (y = 0; y < pei->height; ++y) {
		tdefl_compress_buffer(pComp, &nulbyte, 1, TDEFL_NO_FLUSH);
		tdefl_compress_buffer(pComp, &src_pixels[(pei->flip ? (pei->height - 1 - y) : y) * bpl],
			bpl, TDEFL_NO_FLUSH);
	}
	if (tdefl_compress_buffer(pComp, NULL, 0, TDEFL_FINISH) != TDEFL_STATUS_DONE) { goto done; }

	write_png_chunk_raw(pei->outf, (const u8*)out_buf.m_pBuf, (i64)out_buf.m_size, CODE_IDAT);
	retval = 1;

done:

	if(pComp) MZ_FREE(pComp);
	if(out_buf.m_pBuf) MZ_FREE(out_buf.m_pBuf);
	return retval;
}

static int do_generate_png(struct deark_png_encode_info *pei, const mz_uint8 *src_pixels)
{
	static const u8 pngsig[8] = { 0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a };
	dbuf *cdbuf = NULL;
	int retval = 0;

	// A membuf that we'll use and reuse for each chunk's data...
	// except for the IDAT chunk. miniz has its own 'tdefl_output_buffer'
	// resizable memory object, that we have to use with it.
	cdbuf = dbuf_create_membuf(pei->c, 64, 0);

	dbuf_write(pei->outf, pngsig, 8);

	write_png_chunk_IHDR(pei, cdbuf);

	if(pei->has_phys) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_pHYs(pei, cdbuf);
	}

	// TODO: Maybe this should be a separate command-line option, instead
	// of overloading ->preserve_file_times.
	if(pei->image_mod_time.is_valid && pei->c->preserve_file_times) {
		dbuf_truncate(cdbuf, 0);
		write_png_chunk_tIME(pei, cdbuf);
	}

	if(!write_png_chunk_IDAT(pei, src_pixels)) goto done;

	dbuf_truncate(cdbuf, 0);
	write_png_chunk_from_cdbuf(pei->outf, cdbuf, CODE_IEND);
	retval = 1;

done:
	dbuf_close(cdbuf);
	return retval;
}

int de_write_png(deark *c, de_bitmap *img, dbuf *f)
{
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
	pei.level = 9;

	if(f->fi_copy && f->fi_copy->image_mod_time.is_valid) {
		pei.image_mod_time = f->fi_copy->image_mod_time;
	}

	if(!do_generate_png(&pei, img->bitmap)) {
		de_err(c, "PNG write failed");
		return 0;
	}

	return 1;
}

static int de_inflate_internal(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	int is_zlib, i64 *bytes_consumed)
{
	mz_stream strm;
	int ret;
	int retval = 0;
#define DE_DFL_INBUF_SIZE   32768
#define DE_DFL_OUTBUF_SIZE  (DE_DFL_INBUF_SIZE*4)
	u8 *inbuf = NULL;
	u8 *outbuf = NULL;
	i64 inbuf_num_valid_bytes; // Number of valid bytes in inbuf, starting with [0].
	i64 inbuf_num_consumed_bytes; // Of inbuf_num_valid_bytes, the number that have been consumed.
	i64 inbuf_num_consumed_bytes_this_time;

	unsigned int orig_avail_in;
	i64 input_cur_pos;
	i64 output_bytes_this_time;
	i64 nbytes_to_read;
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

	de_zeromem(&strm, sizeof(strm));
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

		inbuf_num_consumed_bytes_this_time = (i64)(orig_avail_in - strm.avail_in);
		if(inbuf_num_consumed_bytes_this_time<1 && output_bytes_this_time<1) {
			de_err(c, "Inflate error");
			goto done;
		}
		inbuf_num_consumed_bytes += inbuf_num_consumed_bytes_this_time;
	}

	retval = 1;

done:
	if(retval) {
		*bytes_consumed = (i64)strm.total_in;
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

int de_uncompress_zlib(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf)
{
	i64 bytes_consumed;
	return de_inflate_internal(inf, inputstart, inputsize, outf, 1, &bytes_consumed);
}

int de_uncompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 *bytes_consumed)
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
		de_unix_time_to_timestamp(de_atoi64(s), &c->reproducible_timestamp, 0x1);
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

static i64 de_get_reproducible_unix_timestamp(deark *c)
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
	dbuf *eflocal = NULL;
	dbuf *efcentral = NULL;
	int write_ntfs_times;

	de_zeromem(&dfa, sizeof(struct deark_file_attribs));

	if(!c->zip_data) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
			return;
		}
	}

	zzz = (struct zip_data_struct*)c->zip_data;
	if(!zzz) { de_err(c, "asdf"); de_fatalerror(c); }

	de_dbg(c, "adding to zip: name=%s len=%"I64_FMT, f->name, f->len);

	if(c->preserve_file_times && f->fi_copy && f->fi_copy->mod_time.is_valid) {
		dfa.modtime = de_timestamp_to_unix_time(&f->fi_copy->mod_time);
		if(f->fi_copy->mod_time.prec>0 && f->fi_copy->mod_time.prec<1000) {
			dfa.modtime_as_FILETIME = de_timestamp_to_FILETIME(&f->fi_copy->mod_time);
		}
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

		// We only write the current time because ZIP format leaves us little
		// choice.
		// Although c->current_time is high precision, we deliberately treat
		// it as low precision, so as not to write an NTFS extra field.
		dfa.modtime_as_FILETIME = 0;
	}

	if(f->fi_copy && (f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) {
		dfa.is_executable = 1;
	}

	// Create ZIP "extra data" "Extended Timestamp" and "NTFS" fields,
	// containing the UTC timestamp.

	// Note: Although our 0x5455 central and local extra data fields happen to
	// be identical, that is not generally the case.

	write_ntfs_times = (dfa.modtime_as_FILETIME!=0);

	// Use temporary dbufs to help construct the extra field data.
	eflocal = dbuf_create_membuf(c, 64, 0);
	efcentral = dbuf_create_membuf(c, 64, 0);

	dbuf_writeu16le(eflocal, 0x5455);
	dbuf_writeu16le(eflocal, (i64)5);
	dbuf_writeu16le(efcentral, 0x5455);
	dbuf_writeu16le(efcentral, (i64)5);

	dbuf_writebyte(eflocal, 0x01); // has-modtime flag
	dbuf_writeu32le(eflocal, dfa.modtime);
	dbuf_writebyte(efcentral, 0x01);
	dbuf_writeu32le(efcentral, dfa.modtime);

	if(write_ntfs_times) {
		// We only write the NTFS field to the local header, not the central
		// header.
		// Note: Info-ZIP says: "In the current implementations, this field [...]
		// is only stored as local extra field.
		// Rebuttal: 7-Zip, as of this writing, seems to write it *only* as a
		// *central* extra field.

		dbuf_writeu16le(eflocal, 0x000a); // = NTFS
		dbuf_writeu16le(eflocal, 32); // data size
		dbuf_write_zeroes(eflocal, 4);
		dbuf_writeu16le(eflocal, 0x0001); // file times element
		dbuf_writeu16le(eflocal, 24); // element data size
		// We only know the mod time, but we are forced to make up something for
		// the other timestamps.
		dbuf_writeu64le(eflocal, (u64)dfa.modtime_as_FILETIME); // mod time
		dbuf_writeu64le(eflocal, (u64)dfa.modtime_as_FILETIME); // access time
		dbuf_writeu64le(eflocal, (u64)dfa.modtime_as_FILETIME); // create time
	}

	dfa.extra_data_local_size = (u16)eflocal->len;
	dfa.extra_data_local = de_malloc(c, eflocal->len);
	dbuf_read(eflocal, dfa.extra_data_local, 0, eflocal->len);

	dfa.extra_data_central_size = (u16)efcentral->len;
	dfa.extra_data_central = de_malloc(c, efcentral->len);
	dbuf_read(efcentral, dfa.extra_data_central, 0, efcentral->len);

	dbuf_close(eflocal);
	eflocal = NULL;
	dbuf_close(efcentral);
	efcentral = NULL;

	mz_zip_writer_add_mem(zzz->pZip, f->name, f->membuf_buf, (size_t)f->len,
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
u32 de_crc32(const void *buf, i64 buf_len)
{
	return (u32)mz_crc32(MZ_CRC32_INIT, (const mz_uint8*)buf, (size_t)buf_len);
}

u32 de_crc32_continue(u32 prev_crc, const void *buf, i64 buf_len)
{
	return (u32)mz_crc32(prev_crc, (const mz_uint8*)buf, (size_t)buf_len);
}
