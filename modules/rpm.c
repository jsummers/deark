// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

// RPM package manager

typedef struct localctx_struct {
	de_byte ver_major, ver_minor;
} lctx;

static int do_lead_section(deark *c, lctx *d)
{
	d->ver_major = de_getbyte(4);
	d->ver_minor = de_getbyte(5);
	de_dbg(c, "RPM format version %d.%d\n", (int)d->ver_major, (int)d->ver_minor);
	if(d->ver_major < 3) {
		de_err(c, "Unsupported RPM version (%d.%d)\n", (int)d->ver_major, (int)d->ver_minor);
		return 0;
	}
	return 1;
}

// Note that a header *structure* is distinct from the header *section*.
// Both the signature section and the header section use a header structure.
static int do_header_structure(deark *c, lctx *d, int is_sig, de_int64 pos1,
	de_int64 *section_size)
{
	de_int64 pos;
	de_int64 indexcount;
	de_int64 storesize;
	de_byte buf[4];
	de_byte header_ver;

	pos = pos1;

	de_read(buf, pos, 4);
	if(buf[0]!=0x8e || buf[1]!=0xad || buf[2]!=0xe8) {
		de_err(c, "Bad header signature at %d\n", (int)pos);
		return 0;
	}
	header_ver = buf[3];
	if(header_ver != 1) {
		de_err(c, "Unsupported header version\n");
		return 0;
	}
	pos += 8;

	indexcount = de_getui32be(pos);
	storesize = de_getui32be(pos+4);
	de_dbg(c, "%s: pos=%d indexcount=%d storesize=%d\n", is_sig?"sig":"hdr",
		(int)pos, (int)indexcount, (int)storesize);
	pos += 8;

	pos += 16*indexcount;
	pos += storesize;

	*section_size = pos - pos1;
	return 1;
}

static int do_signature_section(deark *c, lctx *d, de_int64 pos1, de_int64 *section_size)
{
	return do_header_structure(c, d, 1, pos1, section_size);
}

static int do_header_section(deark *c, lctx *d, de_int64 pos1, de_int64 *section_size)
{
	return do_header_structure(c, d, 0, pos1, section_size);
}

static void de_run_rpm(deark *c, const char *params)
{
	lctx *d = NULL;
	de_int64 pos;
	de_byte buf[8];
	const char *ext;
	de_int64 section_size = 0;

	d = de_malloc(c, sizeof(lctx));

	if(!do_lead_section(c, d)) {
		goto done;
	}

	pos = 96;

	if(!do_signature_section(c, d, pos, &section_size)) {
		goto done;
	}
	pos += section_size;

	// Header structures are 8-byte aligned. The first one always starts at
	// offset 96, so we don't have to worry about it. But we need to make
	// sure the second one is aligned.
	pos = ((pos + 7)/8)*8;

	if(pos > c->infile->len) goto done;

	if(!do_header_section(c, d, pos, &section_size)) {
		goto done;
	}
	pos += section_size;
	if(pos > c->infile->len) goto done;

	de_dbg(c, "data pos: %d\n", (int)pos);
	if(pos > c->infile->len) goto done;

	// Sniff the format of (what we assume is) the compressed cpio archive.
	// TODO: It's possible to read the compression type without sniffing, though
	// it's not clear whether that would be more, or less, reliable.
	// TODO: I think it's also theoretically possible that it could use an archive
	// format other than cpio.
	de_read(buf, pos, 8);

	if(buf[0]==0x1f && buf[1]==0x8b) {
		ext = "cpio.gz";
	}
	else if(buf[0]==0x42 && buf[1]==0x5a && buf[2]==0x68) {
		ext = "cpio.bz2";
	}
	else if(buf[0]==0xff && buf[1]==0x4c && buf[2]==0x5a) {
		// TODO: Is this correct? What exactly is this format?
		ext = "cpio.lzma";
	}
	else if(buf[0]==0xfd && buf[1]==0x37 && buf[2]==0x7a) {
		ext = "cpio.xz";
	}
	else if(buf[0]==0x5d) {
		// TODO: Better identification
		ext = "cpio.lzma";
	}
	else {
		de_warn(c, "Unidentified compression or archive format\n");
		ext = "cpio.bin";
	}

	dbuf_create_file_from_slice(c->infile, pos, c->infile->len - pos, ext, NULL);

done:
	de_free(c, d);
}

static int de_identify_rpm(deark *c)
{
	de_byte b[4];
	de_read(b, 0, 4);
	if(!de_memcmp(b, "\xed\xab\xee\xdb", 4))
		return 100;
	return 0;
}

void de_module_rpm(deark *c, struct deark_module_info *mi)
{
	mi->id = "rpm";
	mi->run_fn = de_run_rpm;
	mi->identify_fn = de_identify_rpm;
}
