// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// Decompression of Deflate and zlib
// (This file is #included by deark-miniz.c.)

static void de_inflate_internal(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	mz_stream strm;
	int ret;
	int ok = 0;
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
	int stream_open_flag = 0;
	static const char *modname = "inflate";

	dres->bytes_consumed = 0;
	if(dcmpri->len<0) {
		de_dfilter_set_errorf(c, dres, modname, "Internal error");
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
		de_dfilter_set_errorf(c, dres, modname, "Inflate error");
		goto done;
	}

	stream_open_flag = 1;

	input_cur_pos = dcmpri->pos;

	inbuf_num_valid_bytes = 0;
	inbuf_num_consumed_bytes = 0;

	de_dbg2(c, "inflating up to %d bytes", (int)dcmpri->len);

	while(1) {
		de_dbg3(c, "input remaining: %d", (int)(dcmpri->pos+dcmpri->len-input_cur_pos));

		// If we have written enough bytes, stop.
		if((dcmpro->len_known) && (nbytes_written_total >= dcmpro->expected_len)) {
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

		nbytes_to_read = dcmpri->pos+dcmpri->len-input_cur_pos;
		if(nbytes_to_read>DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes) {
			nbytes_to_read = DE_DFL_INBUF_SIZE-inbuf_num_valid_bytes;
		}

		// top off input buffer
		dbuf_read(dcmpri->f, &inbuf[inbuf_num_valid_bytes], input_cur_pos, nbytes_to_read);
		input_cur_pos += nbytes_to_read;
		inbuf_num_valid_bytes += nbytes_to_read;

		strm.next_in = inbuf;
		strm.avail_in = (unsigned int)inbuf_num_valid_bytes;
		orig_avail_in = strm.avail_in;

		strm.next_out = outbuf;
		strm.avail_out = DE_DFL_OUTBUF_SIZE;

		ret = mz_inflate(&strm, MZ_SYNC_FLUSH);
		if(ret!=MZ_STREAM_END && ret!=MZ_OK) {
			de_dfilter_set_errorf(c, dres, modname, "Inflate error (%d)", (int)ret);
			goto done;
		}

		output_bytes_this_time = DE_DFL_OUTBUF_SIZE - strm.avail_out;
		de_dbg3(c, "got %d output bytes", (int)output_bytes_this_time);

		nbytes_to_write = output_bytes_this_time;
		if((dcmpro->len_known) &&
			(nbytes_to_write > dcmpro->expected_len - nbytes_written_total))
		{
			nbytes_to_write = dcmpro->expected_len - nbytes_written_total;
		}
		dbuf_write(dcmpro->f, outbuf, nbytes_to_write);
		nbytes_written_total += nbytes_to_write;

		if(ret==MZ_STREAM_END) {
			de_dbg2(c, "inflate finished normally");
			ok = 1;
			goto done;
		}

		inbuf_num_consumed_bytes_this_time = (i64)(orig_avail_in - strm.avail_in);
		if(inbuf_num_consumed_bytes_this_time<1 && output_bytes_this_time<1) {
			de_dfilter_set_errorf(c, dres, modname, "Inflate error");
			goto done;
		}
		inbuf_num_consumed_bytes += inbuf_num_consumed_bytes_this_time;
	}

done:
	if(ok) {
		dres->bytes_consumed = (i64)strm.total_in;
		dres->bytes_consumed_valid = 1;
		de_dbg2(c, "inflated %u to %u bytes", (unsigned int)strm.total_in,
			(unsigned int)strm.total_out);
	}
	if(stream_open_flag) {
		mz_inflateEnd(&strm);
	}
	de_free(c, inbuf);
	de_free(c, outbuf);
}

int de_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags)
{
	deark *c = inf->c;
	struct de_dfilter_results dres;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;

	de_zeromem(&dcmpri, sizeof(struct de_dfilter_in_params));
	de_zeromem(&dcmpro, sizeof(struct de_dfilter_out_params));
	de_dfilter_results_clear(c, &dres);
	if(bytes_consumed) *bytes_consumed = 0;

	dcmpri.f = inf;
	dcmpri.pos = inputstart;
	dcmpri.len = inputsize;

	dcmpro.f = outf;
	if(flags & DE_DEFLATEFLAG_USEMAXUNCMPRSIZE) {
		dcmpro.len_known = 1;
		dcmpro.expected_len = maxuncmprsize;
		flags -= DE_DEFLATEFLAG_USEMAXUNCMPRSIZE;
	}

	de_inflate_internal(c, &dcmpri, &dcmpro, &dres, flags);

	if(bytes_consumed && dres.bytes_consumed_valid) {
		*bytes_consumed = dres.bytes_consumed;
	}

	if(dres.errcode != 0) {
		de_err(c, "%s", dres.errmsg);
		return 0;
	}
	return 1;
}

void de_decompress_deflate2(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags)
{
	de_inflate_internal(c, dcmpri, dcmpro, dres, flags);
}
