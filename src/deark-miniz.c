// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Interface to miniz
// ZIP encoding
// PNG encoding

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

struct deark_file_attribs {
	struct de_timestamp modtime;
	i64 modtime_unix;
	unsigned int modtime_dosdate;
	unsigned int modtime_dostime;
	i64 modtime_as_FILETIME; // valid if nonzero
	u8 is_executable;
	u8 is_directory;
	u16 extra_data_central_size;
	u16 extra_data_local_size;
	const u8 *extra_data_central;
	const u8 *extra_data_local;
};

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_STDIO
#include "../foreign/miniz.h"

// Our custom version of mz_zip_archive
struct zip_data_struct {
	deark *c;
	const char *pFilename;
	dbuf *outf; // Using this instead of pZip->m_pState->m_pFile
	mz_zip_archive *pZip;
	mz_uint cmprlevel;
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
	unsigned int level;
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
	out_buf.m_capacity = 16+(size_t)MZ_MAX(64, (1+bpl)*pei->height);
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

	if(pei->image_mod_time.is_valid && pei->c->preserve_file_times_images) {
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

	if(!do_generate_png(&pei, img->bitmap)) {
		de_err(c, "PNG write failed");
		return 0;
	}

	return 1;
}

static int de_inflate_internal(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags)
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
	i64 nbytes_to_write;
	i64 nbytes_written_total = 0;
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
	if(flags&DE_DEFLATEFLAG_ISZLIB) {
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

		// If we have written enough bytes, stop.
		if((flags&DE_DEFLATEFLAG_USEMAXUNCMPRSIZE) && (nbytes_written_total >= maxuncmprsize)) {
			break;
		}

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

		nbytes_to_write = output_bytes_this_time;
		if((flags&DE_DEFLATEFLAG_USEMAXUNCMPRSIZE) &&
			(nbytes_to_write > maxuncmprsize - nbytes_written_total))
		{
			nbytes_to_write = maxuncmprsize - nbytes_written_total;
		}
		dbuf_write(outf, outbuf, nbytes_to_write);
		nbytes_written_total += nbytes_to_write;

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

int de_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags)
{
	i64 bc2 = 0;
	return de_inflate_internal(inf, inputstart, inputsize, outf, maxuncmprsize,
		bytes_consumed?bytes_consumed:(&bc2), flags);
}

static size_t my_mz_zip_file_write_func(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
	struct zip_data_struct *zzz = (struct zip_data_struct*)pOpaque;

	if((i64)file_ofs < 0) return 0;
	dbuf_write_at(zzz->outf, (i64)file_ofs, pBuf, (i64)n);
	return n;
}

// A customized copy of mz_zip_writer_init_file().
// Customized to support Unicode filenames (on Windows), and to better
// report errors.
static mz_bool my_mz_zip_writer_init_file(deark *c, struct zip_data_struct *zzz,
	mz_zip_archive *pZip)
{
  dbuf *pFile_dbuf;
  mz_uint64 size_to_reserve_at_beginning = 0;

  pZip->m_pWrite = my_mz_zip_file_write_func;
  if (!mz_zip_writer_init(pZip, size_to_reserve_at_beginning))
  {
    de_err(c, "Failed to initialize ZIP file");
    return MZ_FALSE;
  }

  if(c->archive_to_stdout) {
    pFile_dbuf = dbuf_create_membuf(c, 4096, 0);
  }
  else{
    pFile_dbuf = dbuf_create_unmanaged_file(c, zzz->pFilename, c->overwrite_mode, 0);
  }

  if (pFile_dbuf->btype==DBUF_TYPE_NULL)
  {
    dbuf_close(pFile_dbuf);
    mz_zip_writer_end(pZip);
    return MZ_FALSE;
  }
  zzz->outf = pFile_dbuf;
  return MZ_TRUE;
}

int de_zip_create_file(deark *c)
{
	struct zip_data_struct *zzz;
	const char *opt_level;
	mz_bool b;

	if(c->zip_data) return 1; // Already created. Shouldn't happen.

	zzz = de_malloc(c, sizeof(struct zip_data_struct));
	zzz->pZip = de_malloc(c, sizeof(mz_zip_archive));
	zzz->c = c;
	zzz->pZip->m_pIO_opaque = (void*)zzz;
	c->zip_data = (void*)zzz;

	zzz->cmprlevel = MZ_BEST_COMPRESSION; // default
	opt_level = de_get_ext_option(c, "archive:zipcmprlevel");
	if(opt_level) {
		i64 opt_level_n = de_atoi64(opt_level);
		if(opt_level_n>9) {
			zzz->cmprlevel = 9;
		}
		else if(opt_level_n<0) {
			zzz->cmprlevel = MZ_DEFAULT_LEVEL;
		}
		else {
			zzz->cmprlevel = (mz_uint)opt_level_n;
		}
	}

	if(c->archive_to_stdout) {
		zzz->pFilename = "[stdout]";
	}
	else {
		if(c->output_archive_filename) {
			zzz->pFilename = c->output_archive_filename;
		}
		else {
			zzz->pFilename = "output.zip";
		}
	}

	b = my_mz_zip_writer_init_file(c, zzz, zzz->pZip);
	if(!b) {
		de_free(c, zzz->pZip);
		de_free(c, zzz);
		c->zip_data = NULL;
		return 0;
	}

	if(!c->archive_to_stdout) {
		de_info(c, "Creating %s", zzz->pFilename);
	}

	return 1;
}

static void set_dos_modtime(struct deark_file_attribs *dfa)
{
	struct de_timestamp tmpts;
	struct de_struct_tm tm2;

	// Clamp to the range of times supported
	if(dfa->modtime_unix < 315532800) { // 1 Jan 1980 00:00:00
		de_unix_time_to_timestamp(315532800, &tmpts, 0x0);
		de_gmtime(&tmpts, &tm2);
	}
	else if(dfa->modtime_unix > 4354819198LL) { // 31 Dec 2107 23:59:58
		de_unix_time_to_timestamp(4354819198LL, &tmpts, 0x0);
		de_gmtime(&tmpts, &tm2);
	}
	else {
		de_gmtime(&dfa->modtime, &tm2);
	}

	dfa->modtime_dostime = (unsigned int)(((tm2.tm_hour) << 11) +
		((tm2.tm_min) << 5) + ((tm2.tm_sec) >> 1));
	dfa->modtime_dosdate = (unsigned int)(((tm2.tm_fullyear - 1980) << 9) +
		((tm2.tm_mon + 1) << 5) + tm2.tm_mday);
}

static void writei32le(dbuf *f, i64 n)
{
	if(n<0) {
		dbuf_writeu32le(f, n+0x100000000LL);
	}
	else {
		dbuf_writeu32le(f, n);
	}
}

static void do_UT_times(deark *c, struct deark_file_attribs *dfa,
	dbuf *ef, int is_central)
{
	// Note: Although our 0x5455 central and local extra data fields happen to
	// be identical, that is not generally the case.

	dbuf_writeu16le(ef, 0x5455);
	dbuf_writeu16le(ef, (i64)5);
	dbuf_writebyte(ef, 0x01); // has-modtime flag
	writei32le(ef, dfa->modtime_unix);
}

static void do_ntfs_times(deark *c, struct deark_file_attribs *dfa,
	dbuf *ef, int is_central)
{
	dbuf_writeu16le(ef, 0x000a); // = NTFS
	dbuf_writeu16le(ef, 32); // data size
	dbuf_write_zeroes(ef, 4);
	dbuf_writeu16le(ef, 0x0001); // file times element
	dbuf_writeu16le(ef, 24); // element data size
	// We only know the mod time, but we are forced to make up something for
	// the other timestamps.
	dbuf_writeu64le(ef, (u64)dfa->modtime_as_FILETIME); // mod time
	dbuf_writeu64le(ef, (u64)dfa->modtime_as_FILETIME); // access time
	dbuf_writeu64le(ef, (u64)dfa->modtime_as_FILETIME); // create time
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
	struct zip_data_struct *zzz;
	struct deark_file_attribs dfa;
	dbuf *eflocal = NULL;
	dbuf *efcentral = NULL;
	int write_ntfs_times = 0;
	int write_UT_time = 0;

	de_zeromem(&dfa, sizeof(struct deark_file_attribs));

	if(!c->zip_data) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
			return;
		}
	}

	zzz = (struct zip_data_struct*)c->zip_data;

	de_dbg(c, "adding to zip: name=%s len=%"I64_FMT, f->name, f->len);

	if(f->fi_copy && f->fi_copy->is_directory) {
		dfa.is_directory = 1;
	}

	if(f->fi_copy && (f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) {
		dfa.is_executable = 1;
	}

	if(c->preserve_file_times_archives && f->fi_copy && f->fi_copy->mod_time.is_valid) {
		dfa.modtime = f->fi_copy->mod_time;
		if(dfa.modtime.precision>DE_TSPREC_1SEC) {
			write_ntfs_times = 1;
		}
	}
	else if(c->reproducible_output) {
		de_get_reproducible_timestamp(c, &dfa.modtime);
	}
	else {
		de_cached_current_time_to_timestamp(c, &dfa.modtime);

		// We only write the current time because ZIP format leaves us little
		// choice.
		// Note that although c->current_time is probably high precision,
		// we don't consider that good enough reason to force NTFS timestamps
		// to be written.
	}

	dfa.modtime_unix = de_timestamp_to_unix_time(&dfa.modtime);
	set_dos_modtime(&dfa);

	if((dfa.modtime_unix >= -0x80000000LL) && (dfa.modtime_unix <= 0x7fffffffLL)) {
		// Always write a Unix timestamp if we can.
		write_UT_time = 1;

		if(dfa.modtime_unix < 0) {
			// This negative Unix time is in range, but problematical,
			// so write NTFS times as well.
			write_ntfs_times = 1;
		}
	}
	else { // Out of range of ZIP's (signed int32) Unix style timestamps
		write_ntfs_times = 1;
	}

	if(write_ntfs_times) {
		dfa.modtime_as_FILETIME = de_timestamp_to_FILETIME(&dfa.modtime);
		if(dfa.modtime_as_FILETIME == 0) {
			write_ntfs_times = 0;
		}
	}

	// Create ZIP "extra data" "Extended Timestamp" and "NTFS" fields,
	// containing the UTC timestamp.

	// Use temporary dbufs to help construct the extra field data.
	eflocal = dbuf_create_membuf(c, 256, 0);
	efcentral = dbuf_create_membuf(c, 256, 0);

	if(write_UT_time) {
		do_UT_times(c, &dfa, eflocal, 0);
		do_UT_times(c, &dfa, efcentral, 1);
	}

	if(write_ntfs_times) {
		// Note: Info-ZIP says: "In the current implementations, this field [...]
		// is only stored as local extra field.
		// But 7-Zip supports it *only* as a central extra field.
		// So we'll write both.
		do_ntfs_times(c, &dfa, eflocal, 0);
		do_ntfs_times(c, &dfa, efcentral, 1);
	}

	dfa.extra_data_local_size = (u16)eflocal->len;
	dfa.extra_data_local = eflocal->membuf_buf;

	dfa.extra_data_central_size = (u16)efcentral->len;
	dfa.extra_data_central = efcentral->membuf_buf;

	if(dfa.is_directory) {
		size_t nlen;
		char *name2;

		// Append a "/" to the name
		nlen = de_strlen(f->name);
		name2 = de_malloc(c, (i64)nlen+2);
		de_snprintf(name2, nlen+2, "%s/", f->name);

		mz_zip_writer_add_mem(zzz->pZip, name2, f->membuf_buf, 0,
			MZ_NO_COMPRESSION, &dfa);

		de_free(c, name2);
	}
	else {
		mz_zip_writer_add_mem(zzz->pZip, f->name, f->membuf_buf, (size_t)f->len,
			zzz->cmprlevel, &dfa);
	}

	dbuf_close(eflocal);
	dbuf_close(efcentral);
}

static int copy_to_FILE_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	size_t ret;
	ret = fwrite(buf, 1, (size_t)buf_len, (FILE*)brctx->userdata);
	return (ret==(size_t)buf_len);
}

static void dbuf_copy_to_FILE(dbuf *inf, i64 input_offset, i64 input_len, FILE *outfile)
{
	dbuf_buffered_read(inf, input_offset, input_len, copy_to_FILE_cbfn, (void*)outfile);
}

void de_zip_close_file(deark *c)
{
	struct zip_data_struct *zzz;

	if(!c->zip_data) return;
	de_dbg(c, "closing zip file");

	zzz = (struct zip_data_struct*)c->zip_data;

	mz_zip_writer_finalize_archive(zzz->pZip);
	mz_zip_writer_end(zzz->pZip);

	if(c->archive_to_stdout && zzz->outf && zzz->outf->btype==DBUF_TYPE_MEMBUF) {
		dbuf_copy_to_FILE(zzz->outf, 0, zzz->outf->len, stdout);
	}

	if(zzz->outf) {
		dbuf_close(zzz->outf);
	}

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
