// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// File types we recognize but don't support.
// The point is to print a better error message than "unknown format".
// This is most useful for file types that might be mistaken for one we
// do support.

#include <deark-config.h>
#include <deark-modules.h>

struct fmtinfo_struct {
	int confidence;
	const char *descr;
};

// Windows icons and cursors don't have a distinctive signature. This
// function tries to screen out other formats.
static int is_windows_ico_or_cur(deark *c, int rsrc_id)
{
	de_int64 numicons;
	de_int64 i;
	de_int64 size, offset;

	numicons = de_getui16le(4);

	// Each icon must use at least 16 bytes for the directory, 40 for the
	// info header, 4 for the foreground, and 4 for the mask.
	if(numicons<1 || (6+numicons*64)>c->infile->len) return 0;

	// Examine the first few icon index entries.
	for(i=0; i<numicons && i<8; i++) {
		size = de_getui32le(6+16*i+8);
		offset = de_getui32le(6+16*i+12);
		if(size<48) return 0;
		if(offset < 6+numicons*16) return 0;
		if(offset+size > c->infile->len) return 0;
	}
	return 1;
}

// fmti is allocated by the caller.
// get_fmt initializes it. If a format is unidentified,
// it sets ->confidence to 0.
static void get_fmt(deark *c, struct fmtinfo_struct *fmti)
{
	de_byte b[32];

	fmti->confidence = 0;
	fmti->descr = NULL;

	de_read(b, 0, sizeof(b));

	if(!de_memcmp(b, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8)) {
		fmti->confidence = 90;
		fmti->descr = "a PNG image file";
		return;
	}

	if(!de_memcmp(b, "GIF87a", 6) || !de_memcmp(b, "GIF89a", 6)) {
		fmti->confidence = 50;
		fmti->descr = "a GIF image file";
		return;
	}

	if(!de_memcmp(b, "\x1f\x8b\x08", 3)) {
		fmti->confidence = 80;
		fmti->descr = "a gzip-compressed file";
		return;
	}

	if(!de_memcmp(b, "\x42\x5a\x68", 3) &&
		!de_memcmp(&b[4], "\x31\x41\x59\x26\x53\x59", 6) )
	{
		fmti->confidence = 90;
		fmti->descr = "a bzip2-compressed file";
		return;
	}

	if(!de_memcmp(b, "7z\xbc\xaf\x27\x1c", 6)) {
		fmti->confidence = 90;
		fmti->descr = "a 7z file";
		return;
	}

	if(!de_memcmp(b, "\xff\x4f\xff\x51", 4)) {
		fmti->confidence = 90;
		fmti->descr = "a JPEG 2000 codestream";
		return;
	}

	if(b[0]=='H' && b[1]=='P' && b[2]=='H' && b[3]=='P' &&
		b[4]=='4' && (b[5]=='8' || b[5]=='9'))
	{
		fmti->confidence = 90;
		fmti->descr = "a non-GROB HP-48/49 file";
		return;
	}

	if(b[0]=='B' && b[1]=='M') {
		fmti->confidence = 20;
		fmti->descr = "a BMP image file";
		return;
	}

	if(!de_memcmp(b, "\x00\x00\x01\x00", 4)) {
		if(is_windows_ico_or_cur(c, 1)) {
			fmti->confidence = 20;
			fmti->descr = "a Windows icon";
			return;
		}
	}

	if(!de_memcmp(b, "\x00\x00\x02\x00", 4)) {
		if(is_windows_ico_or_cur(c, 2)) {
			fmti->confidence = 20;
			fmti->descr = "a Windows cursor";
			return;
		}
	}

	// Without this, RAF would be mis-identified as Atari CAS.
	if(!de_memcmp(b, "FUJIFILMCCD-RAW", 15)) {
		fmti->confidence = 100;
		fmti->descr = "a Fujifilm RAF file";
		return;
	}
}

static void de_run_unsupported(deark *c, const char *params)
{
	struct fmtinfo_struct fmti;
	get_fmt(c, &fmti);
	if(fmti.confidence>0 && fmti.descr) {
		de_err(c, "This looks like %s, which is not a supported format.\n", fmti.descr);
	}
}

static int de_identify_unsupported(deark *c)
{
	struct fmtinfo_struct fmti;
	get_fmt(c, &fmti);
	return fmti.confidence;
}

void de_module_unsupported(deark *c, struct deark_module_info *mi)
{
	mi->id = "unsupported";
	mi->run_fn = de_run_unsupported;
	mi->identify_fn = de_identify_unsupported;
}
