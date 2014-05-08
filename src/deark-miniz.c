// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark-config.h"

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "miniz.h"

#include "deark-private.h"

int de_write_png(deark *c, struct deark_bitmap *img, dbuf *f)
{
	size_t len_out = 0;
	de_byte *memblk = NULL;

	if(img->width<1 || img->height<1 || img->width>DE_MAX_IMAGE_DIMENSION ||
		img->width>DE_MAX_IMAGE_DIMENSION)
	{
		de_err(c, "Invalid or unsupported image dimensions (%dx%d)\n",
			(int)img->width, (int)img->height);
		return 0;
	}

	memblk = tdefl_write_image_to_png_file_in_memory_ex(img->bitmap,
		(int)img->width, (int)img->height, img->bytes_per_pixel, &len_out, 9, img->flipped);

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

	memset(&strm,0,sizeof(strm));
	ret = mz_inflateInit(&strm);
	if(ret!=MZ_OK) {
		de_err(c, "Inflate error\n");
		goto done;
	}

	stream_open_flag = 1;

	input_cur_pos = inputstart;
	input_remaining = inputsize;

	while(1) {

		de_dbg(c, "input remaining: %d\n", (int)input_remaining);
		if(input_remaining<=0) break;

		// fill input buffer
		input_bytes_this_time = sizeof(inbuf);
		if(input_bytes_this_time>input_remaining) input_bytes_this_time=input_remaining;

		if(input_bytes_this_time<=0) break;
		de_dbg(c, "processing %d input bytes\n", (int)input_bytes_this_time);

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
			de_dbg(c, "got %d input output bytes\n", (int)output_bytes_this_time);

			dbuf_write(outf, outbuf, output_bytes_this_time);

			if(ret==MZ_STREAM_END) {
				de_dbg(c, "inflate finished normally\n");
				retval = 1;
				goto done;
			}

			if(strm.avail_out!=0) break;
		}
	}

done:
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
