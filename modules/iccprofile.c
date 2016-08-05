// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// [Description]

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_iccprofile);

typedef struct localctx_struct {
	unsigned int profile_ver_major;
	unsigned int profile_ver_minor;
	unsigned int profile_ver_bugfix;
} lctx;

static void fourcc_or_printable_or_none(const struct de_fourcc *tmp4cc,
	char *buf, size_t buflen)
{
	if(tmp4cc->id==0) de_strlcpy(buf, "(none)", buflen);
	else de_snprintf(buf, buflen, "\"%s\"", tmp4cc->id_printable);
}

static void do_read_header(deark *c, lctx *d, de_int64 pos)
{
	de_uint32 profile_ver_raw;
	de_int64 x;
	struct de_fourcc tmp4cc;
	char tmpbuf[16];

	de_dbg(c, "header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	x = de_getui32be(pos+0);
	de_dbg(c, "profile size: %d\n", (int)x);

	dbuf_read_fourcc(c->infile, pos+4, &tmp4cc, 0);
	de_dbg(c, "preferred CMM type: \"%s\"\n", tmp4cc.id_printable);

	profile_ver_raw = (de_uint32)de_getui32be(pos+8);
	d->profile_ver_major = 10*((profile_ver_raw&0xf0000000U)>>28) +
		((profile_ver_raw&0x0f000000U)>>24);
	d->profile_ver_minor = (profile_ver_raw&0x00f00000U)>>20;
	d->profile_ver_bugfix = (profile_ver_raw&0x000f0000U)>>16;
	de_dbg(c, "profile version: %u.%u.%u\n", d->profile_ver_major,
		d->profile_ver_minor, d->profile_ver_bugfix);

	dbuf_read_fourcc(c->infile, pos+12, &tmp4cc, 0);
	de_dbg(c, "profile/device class: \"%s\"\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+16, &tmp4cc, 0);
	de_dbg(c, "colour space: \"%s\"\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+20, &tmp4cc, 0);
	de_dbg(c, "PCS: \"%s\"\n", tmp4cc.id_printable);

	// TODO: pos=24-35 Date & time

	dbuf_read_fourcc(c->infile, pos+36, &tmp4cc, 0);
	de_dbg(c, "file signature: \"%s\"\n", tmp4cc.id_printable);

	dbuf_read_fourcc(c->infile, pos+40, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "primary platform: %s\n", tmpbuf);

	// TODO: pos=44-47 Profile flags

	dbuf_read_fourcc(c->infile, pos+48, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "device manufacturer: %s\n", tmpbuf);

	dbuf_read_fourcc(c->infile, pos+52, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "device model: %s\n", tmpbuf);

	// TODO: pos=56-63 Device attributes

	x = de_getui32be(pos+64);
	de_dbg(c, "rendering intent: %d\n", (int)x);
	// TODO: name the rendering intent field

	// TODO: pos=68-79 PCS illuminant

	dbuf_read_fourcc(c->infile, pos+80, &tmp4cc, 0);
	fourcc_or_printable_or_none(&tmp4cc, tmpbuf, sizeof(tmpbuf));
	de_dbg(c, "profile creator: %s\n", tmpbuf);

	// TODO: pos=84-99 Profile ID

	de_dbg_indent(c, -1);
}

static void de_run_iccprofile(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	de_msg(c, "Note: ICC profiles can be parsed, but no files can be extracted from them.\n");

	pos = 0;
	do_read_header(c, d, pos);
	pos += 128;

	de_free(c, d);
}

static int de_identify_iccprofile(deark *c)
{
	if(!dbuf_memcmp(c->infile, 36, "acsp", 4))
		return 85;
	return 0;
}

void de_module_iccprofile(deark *c, struct deark_module_info *mi)
{
	mi->id = "iccprofile";
	mi->desc = "ICC profile";
	mi->run_fn = de_run_iccprofile;
	mi->identify_fn = de_identify_iccprofile;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
