// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// ZIP encoding

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

// TODO: Finish removing the "mz" symbols, and other miniz things.
#define MZ_NO_COMPRESSION   0
#define MZ_BEST_COMPRESSION 9
#define MZ_DEFAULT_LEVEL    6
#define MZ_DEFAULT_STRATEGY 0

#define CODE_PK12 0x02014b50U
#define CODE_PK34 0x04034b50U
#define CODE_PK56 0x06054b50U

struct zipw_md {
	struct de_timestamp modtime;
	struct de_timestamp actime;
	struct de_timestamp crtime;
	i64 modtime_unix;
	unsigned int modtime_dosdate;
	unsigned int modtime_dostime;
	i64 modtime_as_FILETIME; // valid if nonzero
	i64 actime_as_FILETIME;
	i64 crtime_as_FILETIME;
	u8 is_executable;
	u8 is_directory;
	dbuf *eflocal;
	dbuf *efcentral;
};

struct zipw_ctx {
	deark *c;
	const char *pFilename;
	unsigned int cmprlevel;
	i64 membercount;
	dbuf *outf;
	dbuf *cdir; // central directory
	struct de_crcobj *crc32o;
};

static int is_valid_32bit_unix_time(i64 ut)
{
	return (ut >= -0x80000000LL) && (ut <= 0x7fffffffLL);
}

// Create and initialize the main ZIP archive
int de_zip_create_file(deark *c)
{
	struct zipw_ctx *zzz;
	const char *opt_level;

	if(c->zip_data) return 1; // Already created. Shouldn't happen.

	zzz = de_malloc(c, sizeof(struct zipw_ctx));
	zzz->c = c;
	c->zip_data = (void*)zzz;
	zzz->crc32o = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);

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
			zzz->cmprlevel = (unsigned int)opt_level_n;
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

	if(c->archive_to_stdout) {
		zzz->outf = dbuf_create_unmanaged_file_stdout(c, "[ZIP stdout stream]");
	}
	else {
		de_info(c, "Creating %s", zzz->pFilename);
		zzz->outf = dbuf_create_unmanaged_file(c, zzz->pFilename, c->overwrite_mode, 0);
	}

	zzz->cdir = dbuf_create_membuf(c, 1024, 0);

	if(zzz->outf->btype==DBUF_TYPE_NULL) {
		de_err(c, "Failed to create ZIP file");
		dbuf_close(zzz->outf);
		zzz->outf = NULL;
		return 0;
	}

	return 1;
}

static void set_dos_modtime(struct zipw_md *md)
{
	struct de_timestamp tmpts;
	struct de_struct_tm tm2;

	// Clamp to the range of times supported
	if(md->modtime_unix < 315532800) { // 1 Jan 1980 00:00:00
		de_unix_time_to_timestamp(315532800, &tmpts, 0x0);
		de_gmtime(&tmpts, &tm2);
	}
	else if(md->modtime_unix > 4354819198LL) { // 31 Dec 2107 23:59:58
		de_unix_time_to_timestamp(4354819198LL, &tmpts, 0x0);
		de_gmtime(&tmpts, &tm2);
	}
	else {
		de_gmtime(&md->modtime, &tm2);
	}

	md->modtime_dostime = (unsigned int)(((tm2.tm_hour) << 11) +
		((tm2.tm_min) << 5) + ((tm2.tm_sec) >> 1));
	md->modtime_dosdate = (unsigned int)(((tm2.tm_fullyear - 1980) << 9) +
		((tm2.tm_mon + 1) << 5) + tm2.tm_mday);
}


static void do_UT_times(deark *c, struct zipw_md *md,
	dbuf *ef, int is_central)
{
	int write_crtime = 0;
	int write_actime = 0;
	i64 num_timestamps = 0;
	i64 actime_unix = 0;
	i64 crtime_unix = 0;
	u8 flags = 0;
	// Note: Although our 0x5455 central and local extra data fields happen to
	// be identical, that is not generally the case.

	if(!is_central) {
		if(md->actime.is_valid) {
			actime_unix = de_timestamp_to_unix_time(&md->actime);
			if(is_valid_32bit_unix_time(actime_unix)) {
				write_actime = 1;
			}
		}

		if(md->crtime.is_valid) {
			crtime_unix = de_timestamp_to_unix_time(&md->crtime);
			if(is_valid_32bit_unix_time(crtime_unix)) {
				write_crtime = 1;
			}
		}
	}

	// Always write mod time
	num_timestamps++;
	flags |= 0x01;

	if(write_actime) {
		num_timestamps++;
		flags |= 0x02;
	}

	if(write_crtime) {
		num_timestamps++;
		flags |= 0x04;
	}

	dbuf_writeu16le(ef, 0x5455);
	dbuf_writeu16le(ef, (i64)(1+4*num_timestamps));
	dbuf_writebyte(ef, flags); // tells which fields are present
	dbuf_writei32le(ef, md->modtime_unix);
	if(write_actime) {
		dbuf_writei32le(ef, actime_unix);
	}
	if(write_crtime) {
		dbuf_writei32le(ef, crtime_unix);
	}
}

static void do_ntfs_times(deark *c, struct zipw_md *md,
	dbuf *ef, int is_central)
{
	u64 modtm, actm, crtm;

	dbuf_writeu16le(ef, 0x000a); // = NTFS
	dbuf_writeu16le(ef, 32); // data size
	dbuf_write_zeroes(ef, 4);
	dbuf_writeu16le(ef, 0x0001); // file times element
	dbuf_writeu16le(ef, 24); // element data size
	// We only necessarily know the mod time, but we have to write something for
	// the others.
	modtm = (u64)md->modtime_as_FILETIME;
	actm = (md->actime_as_FILETIME>0) ? (u64)md->actime_as_FILETIME : modtm;
	crtm = (md->crtime_as_FILETIME>0) ? (u64)md->crtime_as_FILETIME : modtm;
	dbuf_writeu64le(ef, modtm);
	dbuf_writeu64le(ef, actm);
	dbuf_writeu64le(ef, crtm);
}

static int zipw_deflate(deark *c, struct zipw_ctx *zzz, dbuf *uncmpr_data,
	dbuf *cmpr_data, unsigned int level)
{
	int retval = 0;
	enum fmtutil_tdefl_status ret;
	struct fmtutil_tdefl_ctx *tdctx = NULL;

	tdctx = fmtutil_tdefl_create(c, cmpr_data,
		fmtutil_tdefl_create_comp_flags_from_zip_params(level, -15, MZ_DEFAULT_STRATEGY));

	ret = fmtutil_tdefl_compress_buffer(tdctx, uncmpr_data->membuf_buf,
		(size_t)uncmpr_data->len, FMTUTIL_TDEFL_FINISH);
	if(ret != FMTUTIL_TDEFL_STATUS_DONE) {
		de_err(c, "Deflate compression error");
		goto done;
	}
	retval = 1;

done:
	fmtutil_tdefl_destroy(tdctx);
	return retval;
}

static void zipw_add_memberfile(deark *c, struct zipw_ctx *zzz, struct zipw_md *md,
	dbuf *f, const char *name, unsigned int level_and_flags)
{
	i64 ldir_offset;
	i64 fnlen;
	u32 crc;
	int try_compression = 0;
	int using_compression = 0;
	dbuf *cmpr_data = NULL;
	i64 cmpr_len;
	unsigned int bit_flags = 0;
	unsigned int ext_attributes;
	unsigned int ver_needed;

	if(zzz->membercount >= 0xffff) {
		de_err(c, "Maximum number of ZIP member files exceeded");
		goto done;
	}

	de_crcobj_reset(zzz->crc32o);
	de_crcobj_addslice(zzz->crc32o, f, 0, f->len);
	crc = de_crcobj_getval(zzz->crc32o);

	ldir_offset = zzz->outf->len;
	if(ldir_offset > 0xffffffffLL) {
		de_err(c, "Maximum ZIP file size exceeded");
		goto done;
	}
	if(f->len > 0xffffffffLL) {
		de_err(c, "Maximum ZIP member file size exceeded");
		goto done;
	}
	cmpr_len = f->len; // default

	if(f->len>5 && !md->is_directory) {
		try_compression = 1;
	}

	if(try_compression) {
		unsigned int level;

		cmpr_data = dbuf_create_membuf(c, 0, 0);

		if ((int)level_and_flags < 0)
			level_and_flags = MZ_DEFAULT_LEVEL;
		level = level_and_flags & 0xF;

		zipw_deflate(c, zzz, f, cmpr_data, level);

		if(cmpr_data->len < f->len) {
			using_compression = 1;
			cmpr_len = cmpr_data->len;

			// This is the logic used by Info-Zip
			if(level<=2) bit_flags |= 4;
			else if(level>=8) bit_flags |= 2;
		}
		else { // No savings - Discard compressed data
			dbuf_close(cmpr_data);
			cmpr_data = NULL;
		}
	}

	bit_flags |= 0x0800; // Use UTF-8 filenames

	dbuf_writeu32le(zzz->cdir, CODE_PK12);
	dbuf_writeu32le(zzz->outf, CODE_PK34);

	// 03xx = Unix
	// 63 decimal = ZIP spec v6.3 (first version to document the UTF-8 flag)
	dbuf_writeu16le(zzz->cdir, (3<<8) | 63); // version made by

	if(using_compression) ver_needed = 20;
	else if(md->is_directory) ver_needed = 20;
	else ver_needed = 10;

	dbuf_writeu16le(zzz->cdir, ver_needed);
	dbuf_writeu16le(zzz->outf, ver_needed);

	dbuf_writeu16le(zzz->cdir, bit_flags);
	dbuf_writeu16le(zzz->outf, bit_flags);

	dbuf_writeu16le(zzz->cdir, using_compression?8:0); // cmpr method
	dbuf_writeu16le(zzz->outf, using_compression?8:0);

	dbuf_writeu16le(zzz->cdir, md->modtime_dostime);
	dbuf_writeu16le(zzz->outf, md->modtime_dostime);
	dbuf_writeu16le(zzz->cdir, md->modtime_dosdate);
	dbuf_writeu16le(zzz->outf, md->modtime_dosdate);

	dbuf_writeu32le(zzz->cdir, crc); // crc
	dbuf_writeu32le(zzz->outf, crc);

	dbuf_writeu32le(zzz->cdir, cmpr_len); // cmpr size
	dbuf_writeu32le(zzz->outf, cmpr_len);
	dbuf_writeu32le(zzz->cdir, f->len); // uncmpr size
	dbuf_writeu32le(zzz->outf, f->len);

	fnlen = de_strlen(name);
	dbuf_writeu16le(zzz->cdir, fnlen);
	dbuf_writeu16le(zzz->outf, fnlen);

	dbuf_writeu16le(zzz->cdir, md->efcentral->len); // eflen
	dbuf_writeu16le(zzz->outf, md->eflocal->len);

	dbuf_writeu16le(zzz->cdir, 0); // file comment len
	dbuf_writeu16le(zzz->cdir, 0); // disk number start

	dbuf_writeu16le(zzz->cdir, 0); // int attrib

	// Set the Unix (etc.) file attributes to "-rw-r--r--" or
	// "-rwxr-xr-x", etc.
	if(md->is_directory)
		ext_attributes = (0040755U << 16) | 0x10;
	else if(md->is_executable)
		ext_attributes = (0100755U << 16);
	else
		ext_attributes = (0100644U << 16);

	dbuf_writeu32le(zzz->cdir, (i64)ext_attributes); // ext attrib

	dbuf_writeu32le(zzz->cdir, ldir_offset);

	dbuf_write(zzz->cdir, (const u8*)name, fnlen);
	dbuf_write(zzz->outf, (const u8*)name, fnlen);

	dbuf_copy(md->efcentral, 0, md->efcentral->len, zzz->cdir);
	dbuf_copy(md->eflocal, 0, md->eflocal->len, zzz->outf);

	if(using_compression) {
		if(cmpr_data) {
			dbuf_copy(cmpr_data, 0, cmpr_data->len, zzz->outf);
		}
	}
	else {
		dbuf_copy(f, 0, f->len, zzz->outf);
	}

	zzz->membercount++;

done:
	if(cmpr_data) dbuf_close(cmpr_data);
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
	struct zipw_ctx *zzz;
	struct zipw_md *md = NULL;
	int write_ntfs_times = 0;
	int write_UT_time = 0;

	md = de_malloc(c, sizeof(struct zipw_md));

	if(!c->zip_data) {
		// ZIP file hasn't been created yet
		if(!de_zip_create_file(c)) {
			de_fatalerror(c);
			goto done;
		}
	}

	zzz = (struct zipw_ctx*)c->zip_data;

	de_dbg(c, "adding to zip: name=%s len=%"I64_FMT, f->name, f->len);

	if(f->fi_copy && f->fi_copy->is_directory) {
		md->is_directory = 1;
	}

	if(f->fi_copy && (f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) {
		md->is_executable = 1;
	}

	if(c->preserve_file_times_archives && f->fi_copy && f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY].is_valid) {
		md->modtime = f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY];
		if(md->modtime.precision>DE_TSPREC_1SEC) {
			write_ntfs_times = 1;
		}
	}
	else if(c->reproducible_output) {
		de_get_reproducible_timestamp(c, &md->modtime);
	}
	else {
		de_cached_current_time_to_timestamp(c, &md->modtime);

		// We only write the current time because ZIP format leaves us little
		// choice.
		// Note that although c->current_time is probably high precision,
		// we don't consider that good enough reason to force NTFS timestamps
		// to be written.
	}

	// Note: Timestamps other than the modification time are a low priority.
	// We'll write them in some cases, when it is easy to do so.
	if(c->preserve_file_times_archives && f->fi_copy) {
		md->actime = f->fi_copy->timestamp[DE_TIMESTAMPIDX_ACCESS];
		md->crtime = f->fi_copy->timestamp[DE_TIMESTAMPIDX_CREATE];
	}

	md->modtime_unix = de_timestamp_to_unix_time(&md->modtime);
	set_dos_modtime(md);

	if(is_valid_32bit_unix_time(md->modtime_unix)) {
		// Always write a Unix timestamp if we can.
		write_UT_time = 1;

		if(md->modtime_unix < 0) {
			// This negative Unix time is in range, but problematic,
			// so write NTFS times as well.
			write_ntfs_times = 1;
		}
	}
	else { // Out of range of ZIP's (signed int32) Unix style timestamps
		write_ntfs_times = 1;
	}

	if(write_ntfs_times) {
		md->modtime_as_FILETIME = de_timestamp_to_FILETIME(&md->modtime);
		if(md->modtime_as_FILETIME == 0) {
			write_ntfs_times = 0;
		}
		else {
			md->actime_as_FILETIME = de_timestamp_to_FILETIME(&md->actime);
			md->crtime_as_FILETIME = de_timestamp_to_FILETIME(&md->crtime);
		}
	}

	// Create ZIP "extra data" "Extended Timestamp" and "NTFS" fields,
	// containing the UTC timestamp.

	// Use temporary dbufs to help construct the extra field data.
	md->eflocal = dbuf_create_membuf(c, 256, 0);
	md->efcentral = dbuf_create_membuf(c, 256, 0);

	if(write_UT_time) {
		do_UT_times(c, md, md->eflocal, 0);
		do_UT_times(c, md, md->efcentral, 1);
	}

	if(write_ntfs_times) {
		// Note: Info-ZIP says: "In the current implementations, this field [...]
		// is only stored as local extra field.
		// But 7-Zip supports it *only* as a central extra field.
		// So we'll write both.
		do_ntfs_times(c, md, md->eflocal, 0);
		do_ntfs_times(c, md, md->efcentral, 1);
	}

	if(md->is_directory) {
		size_t nlen;
		char *name2;

		// Append a "/" to the name
		nlen = de_strlen(f->name);
		name2 = de_malloc(c, (i64)nlen+2);
		de_snprintf(name2, nlen+2, "%s/", f->name);

		zipw_add_memberfile(c, zzz, md, f, name2, MZ_NO_COMPRESSION);

		de_free(c, name2);
	}
	else {
		zipw_add_memberfile(c, zzz, md, f, f->name, zzz->cmprlevel);
	}

done:
	if(md) {
		dbuf_close(md->eflocal);
		dbuf_close(md->efcentral);
		de_free(c, md);
	}
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

static void zipw_finalize(deark *c, struct zipw_ctx *zzz)
{
	i64 cdir_start;

	cdir_start = zzz->outf->len;
	if((cdir_start > 0xffffffffLL) || (zzz->cdir->len > 0xffffffffLL)) {
		de_err(c, "Maximum ZIP file size exceeded");
		goto done;
	}

	dbuf_copy(zzz->cdir, 0, zzz->cdir->len, zzz->outf);

	// Write 22-byte EOCD record
	dbuf_writeu32le(zzz->outf, CODE_PK56);
	dbuf_writeu16le(zzz->outf, 0); // this disk num
	dbuf_writeu16le(zzz->outf, 0); // central dir disk
	dbuf_writeu16le(zzz->outf, zzz->membercount); // num files this disk
	dbuf_writeu16le(zzz->outf, zzz->membercount); // num files total
	dbuf_writeu32le(zzz->outf, zzz->cdir->len); // central dir size
	dbuf_writeu32le(zzz->outf, cdir_start);
	dbuf_writeu16le(zzz->outf, 0); // ZIP comment length
done:
	;
}

void de_zip_close_file(deark *c)
{
	struct zipw_ctx *zzz;

	if(!c->zip_data) return;
	de_dbg(c, "closing zip file");

	zzz = (struct zipw_ctx*)c->zip_data;

	zipw_finalize(c, zzz);

	if(c->archive_to_stdout && zzz->outf && zzz->outf->btype==DBUF_TYPE_MEMBUF) {
		dbuf_copy_to_FILE(zzz->outf, 0, zzz->outf->len, stdout);
	}

	dbuf_close(zzz->cdir);
	dbuf_close(zzz->outf);
	de_crcobj_destroy(zzz->crc32o);

	de_free(c, zzz);
	c->zip_data = NULL;
}
