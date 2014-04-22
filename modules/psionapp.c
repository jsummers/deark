// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Psion APP/IMG

#include <deark-config.h>
#include <deark-modules.h>

static void de_run_psionapp(deark *c, const char *params)
{
	de_int64 i;
	de_int64 offset;
	de_int64 len;
	de_byte buf[16];
	const char *ext;
	int extract_this_file;
	int convert_images = 0; // 0=extract PIC, 1=convert PIC
	int is_pic;
	const char *s;
	dbuf *old_infile;

	s = de_get_option(c, "psionapp:convertpic");
	if(s) {
		convert_images = 1;
	}

	for(i=0; i<4; i++) {
		offset = de_getui16le(40 + 4*i);
		len = de_getui16le(40 + 4*i + 2);
		if(offset==0) break;

		de_dbg(c, "embedded file at %d, len=%d\n", (int)offset, (int)len);

		is_pic = 0;
		ext = "bin";
		extract_this_file = 0;

		if(len>0 && c->extract_level>=2)
			extract_this_file = 1;

		// As far as I can tell, there's no way to tell the type of an
		// embedded file, except by sniffing it.
		de_read(buf, offset, 16);
		if(len>=8) {
			if(!de_memcmp(buf, "PIC\xdc\x30\x30", 6)) {
				// Looks like a PIC file
				is_pic = 1;
				ext = "pic";
				extract_this_file = 1;
			}
		}

		if(extract_this_file) {
			if(is_pic && convert_images) {
				// Convert PIC to PNG.
				// For consistency, this option shouldn't exist. But I'm not sure that
				// PIC files embedded in APP files are really the same as PIC files on
				// their own. They might need special handling. Until I'm sure they don't,
				// I'll leave this option here.
				old_infile = c->infile;
				c->infile = dbuf_open_input_subfile(old_infile, offset, len);
				de_run_module_by_id(c, "psionpic", NULL);
				dbuf_close(c->infile);
				c->infile = old_infile;
			}
			else {
				// Just extract the file
				dbuf_create_file_from_slice(c->infile, offset, len, ext);
			}
		}
	}
}

static int de_identify_psionapp(deark *c)
{
	de_byte b[16];
	de_read(b, 0, 16);
	if(!de_memcmp(b, "ImageFileType**\0", 16))
		return 100;
	return 0;
}

void de_module_psionapp(deark *c, struct deark_module_info *mi)
{
	mi->id = "psionapp";
	mi->run_fn = de_run_psionapp;
	mi->identify_fn = de_identify_psionapp;
}
