// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// GRASP GL animation format

#include <deark-config.h>
#include <deark-modules.h>

// Read (sanitized) filename from the file, at offset pos.
static char *get_filename(deark *c, de_int64 pos)
{
	char *fn;
	de_int64 i;

	fn = de_malloc(c, 14);

	de_read((de_byte*)fn, pos, 13);

	// Sanitize the filename.
	// In a Grasp GL file, filenames are 13 bytes, NUL-padded.
	// TODO: This sort of thing should be done by common library functions.
	for(i=0; i<13; i++) {
		if(fn[i]=='\0') break;
		if((fn[i]>='0' && fn[i]<='9') ||
			(fn[i]>='A' && fn[i]<='Z') ||
			(fn[i]>='a' && fn[i]<='z') ||
			fn[i]=='.' || fn[i]=='_' || fn[i]=='-' || fn[i]=='+')
		{
			;
		}
		else {
			fn[i]='_';
		}
	}
	return fn;
}

static void de_run_graspgl(deark *c, const char *params)
{
	de_int64 dir_header_nbytes;
	de_int64 num_files;
	de_int64 file_info_offset;
	de_int64 file_data_offset;
	de_int64 file_size;
	de_int64 pos;
	de_int64 i;
	char *file_name;

	de_dbg(c, "In graspgl module\n");

	pos = 0;
	dir_header_nbytes = de_getui16le(pos);
	de_dbg(c, "header bytes: %d\n", (int)dir_header_nbytes);

	// 17 bytes per file entry
	num_files = (dir_header_nbytes+16)/17;
	de_dbg(c, "number of files: %d\n", (int)num_files);

	for(i=0; i<num_files; i++) {
		pos = 2+17*i;
		file_info_offset = de_getui32le(pos);
		de_dbg(c, "file #%d offset: %d\n", (int)i, (int)file_info_offset);

		// The last "file" is usually not a file, but a "NULL terminator" with
		// an offset of 0. This is worse than useless, since we already know
		// how long the list is.
		if(file_info_offset==0)
			break;

		if(file_info_offset < dir_header_nbytes) {
			de_warn(c, "Bad file offset (%d)\n", (int)file_info_offset);
			continue;
		}

		file_name = get_filename(c, pos+4);

		if(de_strlen(file_name)<1) {
			de_warn(c, "Missing file name\n");
			continue;
		}

		file_size = de_getui32le(file_info_offset);
		de_dbg(c, "file size: %d\n", (int)file_size);

		file_data_offset = file_info_offset+4;
		if(file_data_offset > dbuf_get_length(c->infile)) continue;
		if(file_size > DE_MAX_FILE_SIZE) continue;

		de_dbg(c, "extracting %s\n", file_name);
		dbuf_create_file_from_slice(c->infile, file_data_offset, file_size, file_name);

		de_free(c, file_name);
	}
}

static int de_identify_graspgl(deark *c)
{
	de_int64 dir_header_nbytes;
	de_int64 first_offset;

	dir_header_nbytes = de_getui16le(0);

	// Header should be a nonzero multiple of 17 bytes.
	if(dir_header_nbytes==0 || (dir_header_nbytes%17 != 0)) return 0;

	// Most likely, the first embedded file immediately follows
	// the header. If so, it's pretty good evidence this is a
	// grasp_gl file.
	first_offset = de_getui32le(2);
	if(first_offset == dir_header_nbytes + 2)
		return 90;

	return 0;
}

void de_module_graspgl(deark *c, struct deark_module_info *mi)
{
	mi->id = "graspgl";
	mi->run_fn = de_run_graspgl;
	mi->identify_fn = de_identify_graspgl;
}
