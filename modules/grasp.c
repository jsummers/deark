// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// GRASP GL animation format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 dir_header_nbytes;
} lctx;

// Returns 0 if there are no more files.
static int do_extract_file(deark *c, lctx *d, de_int64 fnum)
{
	de_int64 pos;
	de_int64 file_info_offset;
	de_int64 file_data_offset;
	de_int64 file_size;
	de_finfo *fi = NULL;
	int retval = 1;

	pos = 2+17*fnum;
	file_info_offset = de_getui32le(pos);

	// The last "file" is usually not a file, but a "NULL terminator" with
	// an offset of 0. This is worse than useless, since we already know
	// how long the list is.
	if(file_info_offset==0) {
		de_dbg(c, "end-of-file-list marker found\n");
		retval = 0;
		goto done;
	}

	de_dbg(c, "file #%d offset: %d\n", (int)fnum, (int)file_info_offset);

	if(file_info_offset < d->dir_header_nbytes) {
		de_warn(c, "Bad file offset (%d)\n", (int)file_info_offset);
		goto done;
	}

	if(de_getbyte(pos+4)==0x00) {
		de_warn(c, "Missing file name\n");
		goto done;
	}

	fi = de_finfo_create(c);
	// In a Grasp GL file, filenames are 13 bytes, NUL-padded.
	de_finfo_set_name_from_slice(c, fi, c->infile, pos+4, 13, DE_CONVFLAG_STOP_AT_NUL);

	file_size = de_getui32le(file_info_offset);
	de_dbg(c, "file size: %d\n", (int)file_size);

	file_data_offset = file_info_offset+4;
	if(file_data_offset > dbuf_get_length(c->infile)) goto done;
	if(file_size > DE_MAX_FILE_SIZE) goto done;

	de_dbg(c, "extracting %s\n", fi->file_name);

	dbuf_create_file_from_slice(c->infile, file_data_offset, file_size, NULL, fi);

done:
	de_finfo_destroy(c, fi);
	return retval;
}


static void de_run_graspgl(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 num_files;
	de_int64 pos;
	de_int64 i;

	de_dbg(c, "In graspgl module\n");
	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	d->dir_header_nbytes = de_getui16le(pos);
	de_dbg(c, "header bytes: %d\n", (int)d->dir_header_nbytes);

	// 17 bytes per file entry
	num_files = (d->dir_header_nbytes+16)/17;
	de_dbg(c, "number of files: %d\n", (int)num_files);

	for(i=0; i<num_files; i++) {
		if(!do_extract_file(c, d, i))
			break;
	}

	de_free(c, d);
}

static int de_identify_graspgl(deark *c)
{
	de_int64 dir_header_nbytes;
	de_int64 first_offset;
	int gl_ext;

	dir_header_nbytes = de_getui16le(0);

	// Header should be a nonzero multiple of 17 bytes.
	if(dir_header_nbytes==0 || (dir_header_nbytes%17 != 0)) return 0;

	gl_ext = de_input_file_has_ext(c, "gl");

	// Most likely, the first embedded file immediately follows
	// the header. If so, it's pretty good evidence this is a
	// grasp_gl file.
	first_offset = de_getui32le(2);
	if(first_offset == dir_header_nbytes + 2)
		return gl_ext ? 100 : 70;

	if(gl_ext) return 5;

	return 0;
}

void de_module_graspgl(deark *c, struct deark_module_info *mi)
{
	mi->id = "graspgl";
	mi->run_fn = de_run_graspgl;
	mi->identify_fn = de_identify_graspgl;
}
