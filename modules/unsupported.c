// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// File types we recognize but don't support.
// The point is to print a better error message than "unknown format".
// This is most useful for file types that might be mistaken for one we
// do support.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_unsupported);

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
	u8 b[32];

	de_zeromem(fmti, sizeof(struct fmtinfo_struct));

	de_read(b, 0, sizeof(b));

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

	if(!de_memcmp(b, "<?xpacket", 9)) {
		fmti->confidence = 20;
		fmti->descr = "an XMP file";
		return;
	}

	if(!de_memcmp(b, "ISc(", 4)) {
		fmti->confidence = 40;
		fmti->descr = "an InstallShield CAB file";
		return;
	}

	if(b[0]=='H' && b[1]=='P' && b[2]=='H' && b[3]=='P' &&
		b[4]=='4' && (b[5]=='8' || b[5]=='9'))
	{
		fmti->confidence = 90;
		fmti->descr = "a non-GROB HP-48/49 file";
		return;
	}

	if(!de_memcmp(b, "%PDF-", 5)) {
		fmti->confidence = 90;
		fmti->descr = "a PDF file";
		return;
	}

	if(!de_memcmp(b, "\x7f" "ELF", 4)) {
		fmti->confidence = 40;
		fmti->descr = "an ELF binary";
		return;
	}

	if(!de_memcmp(b, "\xff" "WPC", 4)) {
		fmti->confidence = 40;
		fmti->descr = "a WordPerfect document";
		return;
	}

	if(!de_memcmp(b, "Rar!\x1a\x07", 6)) {
		fmti->confidence = 90;
		fmti->descr = "a RAR archive";
		return;
	}

	if((!de_memcmp(b, "StuffIt", 7)) && (b[7]=='!' || b[7]=='?')) {
		fmti->confidence = 90;
		fmti->descr = "a StuffIt X archive";
		return;
	}

	if(!de_memcmp(b, "\x60\xea", 2)) {
		fmti->confidence = 9;
		fmti->descr = "an ARJ archive";
		return;
	}

	if(!de_memcmp(b, "ICE!", 4) ||
		!de_memcmp(b, "Ice!", 4))
	{
		fmti->confidence = 75;
		fmti->descr = "a Pack-Ice compressed file";
		return;
	}

	// Note - Make sure Atari CAS has lower confidence.
	if(!de_memcmp(b, "FUJIFILMCCD-RAW", 15)) {
		fmti->confidence = 100;
		fmti->descr = "a Fujifilm RAF file";
		return;
	}

	if(!de_memcmp(b, "AutoCAD Slide\r\n\x1a", 16)) {
		fmti->confidence = 100;
		fmti->descr = "an AutoCAD Slide file";
		return;
	}

	if(!de_memcmp(b, "Top!", 4)) {
		// A format often found alongside RISC OS Draw files
		fmti->confidence = 9;
		fmti->descr = "an ArtWorks image";
		return;
	}

	if(!de_memcmp(b, "CPT", 3) &&
		(b[3]>='7' && b[3]<='9') &&
		!de_memcmp(&b[4], "FILE", 4))
	{
		fmti->confidence = 91;
		fmti->descr = "a Corel Photo-Paint image";
		return;
	}

	// We're not trying to detect every HTML file, but we want to make sure
	// we can detect the ones we generate.
	if(!de_memcmp(b, "<!DOCTYPE html", 14) ||
		!de_memcmp(b, "\xef\xbb\xbf<!DOCTYPE html", 17) ||
		!de_memcmp(b, "<html", 5))
	{
		fmti->confidence = 20;
		fmti->descr = "an HTML file";
		return;
	}
}

static void de_run_unsupported(deark *c, de_module_params *mparams)
{
	struct fmtinfo_struct fmti;
	get_fmt(c, &fmti);
	if(fmti.confidence>0 && fmti.descr) {
		if(fmti.special_message) {
			de_err(c, "This looks like %s", fmti.descr);
		}
		else {
			de_err(c, "This looks like %s, which is not a supported format.", fmti.descr);
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
	mi->desc = "Identify some unsupported formats";
	mi->run_fn = de_run_unsupported;
	mi->identify_fn = de_identify_unsupported;
	mi->flags |= DE_MODFLAG_HIDDEN | DE_MODFLAG_NOEXTRACT;
	mi->unique_id = 1;
}
