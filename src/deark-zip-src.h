// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// ZIP encoding
// (This file is #included by deark-miniz.c.)

// Our custom version of mz_zip_archive
struct zip_data_struct {
	deark *c;
	const char *pFilename;
	dbuf *outf; // Using this instead of pZip->m_pState->m_pFile
	mz_zip_archive *pZip;
	mz_uint cmprlevel;
};

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
	if(!mz_zip_writer_init(pZip, size_to_reserve_at_beginning)) {
		de_err(c, "Failed to initialize ZIP file");
		return MZ_FALSE;
	}

	if(c->archive_to_stdout) {
		pFile_dbuf = dbuf_create_membuf(c, 4096, 0);
	}
	else {
		pFile_dbuf = dbuf_create_unmanaged_file(c, zzz->pFilename, c->overwrite_mode, 0);
	}

	if(pFile_dbuf->btype==DBUF_TYPE_NULL) {
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

static void do_UT_times(deark *c, struct deark_file_attribs *dfa,
	dbuf *ef, int is_central)
{
	// Note: Although our 0x5455 central and local extra data fields happen to
	// be identical, that is not generally the case.

	dbuf_writeu16le(ef, 0x5455);
	dbuf_writeu16le(ef, (i64)5);
	dbuf_writebyte(ef, 0x01); // has-modtime flag
	dbuf_writei32le(ef, dfa->modtime_unix);
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
