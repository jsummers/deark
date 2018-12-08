// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Psion APP/IMG

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_psionapp);

typedef struct localctx_struct {
	int convert_images; // 0=extract PIC, 1=convert PIC
} lctx;

static void handle_embedded_file(deark *c, lctx *d, i64 offset, i64 len)
{
	u8 buf[16];
	const char *ext;
	int extract_this_file;
	int is_pic;

	de_dbg(c, "embedded file at %d, len=%d", (int)offset, (int)len);
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
		if(is_pic && d->convert_images) {
			// Convert PIC to PNG.
			// For consistency, this option shouldn't exist. But I'm not sure that
			// PIC files embedded in APP files are really the same as PIC files on
			// their own. They might need special handling. Until I'm sure they don't,
			// I'll leave this option here.
			de_run_module_by_id_on_slice(c, "psionpic", NULL, c->infile, offset, len);
		}
		else {
			// Just extract the file
			dbuf_create_file_from_slice(c->infile, offset, len, ext, NULL, is_pic?0:DE_CREATEFLAG_IS_AUX);
		}
	}
	else {
		de_dbg(c, "(not extracting this file)");
	}
}

static void do_opo_opa(deark *c, lctx *d)
{
	i64 offset_2ndheader;
	i64 pos;
	i64 n;
	i64 len;

	de_declare_fmt(c, "Psion OPO/OPA");

	// The second header marks the end of the embedded files section, I guess.
	offset_2ndheader = de_getu16le(18);
	de_dbg(c, "offset of second header: %d", (int)offset_2ndheader);
	pos = 20;

	// Read length of source filename
	n = (i64)de_getbyte(pos);
	pos++;
	pos+=n;
	while(pos<offset_2ndheader) {
		// Read length of this embedded file
		len = de_getu16le(pos);
		pos+=2;
		handle_embedded_file(c, d, pos, len);
		pos+=len;
	}
}

static void do_img_app(deark *c, lctx *d)
{
	i64 i;
	i64 offset;
	i64 len;

	de_declare_fmt(c, "Psion IMG/APP");

	for(i=0; i<4; i++) {
		offset = de_getu16le(40 + 4*i);
		len = de_getu16le(40 + 4*i + 2);
		if(offset==0) break;
		handle_embedded_file(c, d, offset, len);
	}
}

static void de_run_psionapp(deark *c, de_module_params *mparams)
{
	u8 b;
	const char *s;
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	s = de_get_ext_option(c, "psionapp:convertpic");
	if(s) {
		d->convert_images = 1;
	}

	b = de_getbyte(0);
	if(b=='O') {
		do_opo_opa(c, d);
	}
	else {
		do_img_app(c, d);
	}

	de_free(c, d);
}

static int de_identify_psionapp(deark *c)
{
	u8 b[16];
	de_read(b, 0, 16);
	if(!de_memcmp(b, "ImageFileType**\0", 16))
		return 100;
	if(!de_memcmp(b, "OPLObjectFile**\0", 16))
		return 100;
	return 0;
}

void de_module_psionapp(deark *c, struct deark_module_info *mi)
{
	mi->id = "psionapp";
	mi->desc = "Psion .APP/.IMG and .OPA/.OPO";
	mi->desc2 = "extract images";
	mi->run_fn = de_run_psionapp;
	mi->identify_fn = de_identify_psionapp;
}
