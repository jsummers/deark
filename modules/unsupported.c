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
	int special_message;
	const char *descr;
};

// fmti is allocated by the caller.
// get_fmt initializes it. If a format is unidentified,
// it sets ->confidence to 0.
static void get_fmt(deark *c, struct fmtinfo_struct *fmti)
{
	de_byte b[32];

	de_memset(fmti, 0, sizeof(struct fmtinfo_struct));

	de_read(b, 0, sizeof(b));

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

	// Note - Make sure BSAVE has lower confidence.
	if(!de_memcmp(b, "\xfd\x37\x7a\x58\x5a\x00", 6)) {
		fmti->confidence = 90;
		fmti->descr = "an xz-compressed file";
		return;
	}

	if(!de_memcmp(b, "LZIP", 4)) {
		fmti->confidence = 50;
		fmti->descr = "an lzip-compressed file";
		return;
	}

	if(b[2]=='-' && b[3]=='l' && b[6]=='-' && (b[4]=='h' || b[4]=='z')) {
		fmti->confidence = 10;
		fmti->descr = "an LHA file";
		return;
	}

	if(b[0]==0x1f && b[1]==0x9d) {
		fmti->confidence = 10;
		fmti->descr = "a 'compress' (.Z) file";
		return;
	}

	if(b[0]=='H' && b[1]=='P' && b[2]=='H' && b[3]=='P' &&
		b[4]=='4' && (b[5]=='8' || b[5]=='9'))
	{
		fmti->confidence = 90;
		fmti->descr = "a non-GROB HP-48/49 file";
		return;
	}

	if(b[0]=='P' && b[2]=='\n') {
		switch(b[1]) {
		case '1': case '4':
			fmti->confidence = 50;
			fmti->descr = "a PBM file";
			return;
		case '2': case '5':
			fmti->confidence = 50;
			fmti->descr = "a PGM file";
			return;
		case '3': case '6':
			fmti->confidence = 50;
			fmti->descr = "a PPM file";
			return;
		case '7':
			fmti->confidence = 50;
			fmti->descr = "a PAM file";
			return;
		}
	}

	if(!de_memcmp(b, "RIFF", 4)) {
		fmti->confidence = 2;
		fmti->special_message = 1;
		fmti->descr = "a RIFF file, but it is not one of the supported RIFF subformats.";
		return;
	}

	if(!de_memcmp(b, "FORM", 4)) {
		fmti->confidence = 2;
		fmti->special_message = 1;
		fmti->descr = "an IFF file, but it is not one of the supported IFF subformats.";
		return;
	}

	if(!de_memcmp(b, "ICE!", 4) ||
		!de_memcmp(b, "Ice!", 4))
	{
		fmti->confidence = 75;
		fmti->descr = "a Pack-Ice compressed file";
		return;
	}

	// Note - Make sure VBM has higher confidence.
	if(b[0]=='B' && b[1]=='M') {
		fmti->confidence = 20;
		fmti->descr = "a BMP image file";
		return;
	}

	// Note - Make sure Atari CAS has lower confidence.
	if(!de_memcmp(b, "FUJIFILMCCD-RAW", 15)) {
		fmti->confidence = 100;
		fmti->descr = "a Fujifilm RAF file";
		return;
	}
}

static void de_run_unsupported(deark *c, de_module_params *mparams)
{
	struct fmtinfo_struct fmti;
	get_fmt(c, &fmti);
	if(fmti.confidence>0 && fmti.descr) {
		if(fmti.special_message) {
			de_err(c, "This looks like %s\n", fmti.descr);
		}
		else {
			de_err(c, "This looks like %s, which is not a supported format.\n", fmti.descr);
		}
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
	mi->flags |= DE_MODFLAG_HIDDEN;
}
