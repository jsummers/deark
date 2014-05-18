// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int reserved;
} lctx;

static void extract_frame(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_byte buf[4];
	const char *ext;

	de_dbg(c, "frame at %d, len=%d\n", (int)pos, (int)len);

	de_read(buf, pos, 4);

	// Try to identify the format of this frame.
	if(!de_memcmp(buf, "\x00\x00\x01\x00", 4)) {
		ext = "ico";
	}
	else if(!de_memcmp(buf, "\x00\x00\x02\x00", 4)) {
		ext = "cur";
	}
	else {
		ext = "bin";
	}

	// TODO: Most embedded CUR files don't seem to have a meaningful "hotspot"
	// set. Can we patch that up? Maybe we should even convert ICO files to CUR
	// files, so that we can give them a hotspot.

	dbuf_create_file_from_slice(c->infile, pos, len, ext);
}

static void process_riff_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len1)
{
	de_byte t[4];
	de_int64 len;
	de_int64 endpos;
	char pbuf[16];

	endpos = pos+len1;
	if(endpos > c->infile->len) {
		// Don't read past the end of file.

		// There seems to be some confusion about whether the "length" field
		// of the main RIFF chunk represents the full length of the file, or
		// the length of the data inside the RIFF chunk. Logically it should
		// be the latter, but the documentation is inconsistent, and we've seen
		// both types of files.

		// We'll assume it should be the length of the data inside the RIFF
		// chunk, and correct "errors" here.
		endpos = c->infile->len;
	}

	while(pos < endpos) {
		// Read chunk type
		de_read(t, pos, 4);

		if(c->debug_level>0) {
			de_make_printable_ascii(t, 4, pbuf, sizeof(pbuf));
			de_dbg(c, "chunk '%s' at %d\n", pbuf, (int)pos);
		}

		pos+=4;

		if(!de_memcmp(t, "ACON", 4) ||
			!de_memcmp(t, "fram", 4))
		{
			// Chunk without a length field
			continue;
		}

		len = de_getui32le(pos);
		pos+=4;

		if(!de_memcmp(t, "icon", 4)) {
			extract_frame(c, d, pos, len);
		}
		else if(!de_memcmp(t, "RIFF", 4) ||
			!de_memcmp(t, "LIST", 4))
		{
			process_riff_sequence(c, d, pos, len);
		}

		pos+=len;
		if(len%2) pos++; // Padding byte
	}
}

static void de_run_ani(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In ani module\n");

	d = de_malloc(c, sizeof(lctx));

	process_riff_sequence(c, d, 0, c->infile->len);

	de_free(c, d);
}

static int de_identify_ani(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "RIFF", 4) && !de_memcmp(&buf[8], "ACON", 4))
		return 100;
	return 0;
}

void de_module_ani(deark *c, struct deark_module_info *mi)
{
	mi->id = "ani";
	mi->run_fn = de_run_ani;
	mi->identify_fn = de_identify_ani;
}
