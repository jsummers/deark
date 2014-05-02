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

	if(!de_memcmp(b, "PK\x03\x04", 4)) {
		fmti->confidence = 90;
		fmti->descr = "a ZIP file";
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

	if(!de_memcmp(b, "%!PS-Adobe-", 11) &&
		!de_memcmp(&b[14], " EPSF-", 6) )
	{
		fmti->confidence = 80;
		fmti->descr = "a plain EPS or EPSI file (not EPS binary)";
		return;
	}

	if(b[0]=='B' && b[1]=='M') {
		fmti->confidence = 20;
		fmti->descr = "a BMP image file";
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
