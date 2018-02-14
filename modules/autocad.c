// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// AutoCAD Slide Library (.slb)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_autocad_slb);

static void de_run_autocad_slb(deark *c, de_module_params *mparams)
{
	de_int64 pos;
	de_int64 nslides = 0;
	de_int64 k;
	struct slideinfo {
		de_int64 pos;
		de_int64 len;
	};
	struct slideinfo *si = NULL;
	de_ucstring *slidename = NULL;

	de_dbg(c, "[pass 1: counting slides]");
	pos = 32;
	while(1) {
		if(pos > (c->infile->len-36)) {
			de_err(c, "Unterminated directory");
			goto done;
		}
		if(de_getbyte(pos)==0) {
			break;
		}
		nslides++;
		pos += 36;
	}
	de_dbg(c, "slides found: %d", (int)nslides);

	de_dbg(c, "[pass 2: recording addresses]");
	si = de_malloc(c, nslides*sizeof(struct slideinfo));
	pos = 32;
	for(k=0; k<nslides; k++) {
		si[k].pos = de_getui32le(pos+32);

		if(si[k].pos > c->infile->len) {
				de_err(c, "Invalid directory");
				goto done;
		}
		if(k>0) {
			if(si[k].pos < si[k-1].pos) {
				de_err(c, "Invalid directory");
				goto done;
			}
		}

		if(k>0) {
			// Set the previous slide's length.
			si[k-1].len = si[k].pos - si[k-1].pos;
		}
		if(k==(nslides-1)) {
			// If this is the last slide, assume it goes to end of file.
			si[k].len = c->infile->len - si[k].pos;
		}

		pos += 36;
	}

	de_dbg(c, "[pass 3: extracting slides]");
	pos = 32;
	slidename = ucstring_create(c);
	for(k=0; k<nslides; k++) {
		de_finfo *fi = NULL;

		de_dbg(c, "slide dir entry at %d", (int)pos);
		de_dbg_indent(c, 1);

		ucstring_empty(slidename);
		dbuf_read_to_ucstring(c->infile, pos, 31, slidename,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);

		de_dbg(c, "address: %u", (unsigned int)si[k].pos);
		de_dbg(c, "calculated len: %u", (unsigned int)si[k].len);

		fi = de_finfo_create(c);
		de_finfo_set_name_from_ucstring(c, fi, slidename);
		dbuf_create_file_from_slice(c->infile, si[k].pos, si[k].len, "sld", fi, 0);
		de_finfo_destroy(c, fi);

		de_dbg_indent(c, -1);
		pos += 36;
	}

done:
	ucstring_destroy(slidename);
	de_free(c, si);
}

static int de_identify_autocad_slb(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "AutoCAD Slide Library 1.0\r\n\x1a", 28))
		return 100;
	return 0;
}

void de_module_autocad_slb(deark *c, struct deark_module_info *mi)
{
	mi->id = "autocad_slb";
	mi->desc = "AutoCAD Slide Library";
	mi->run_fn = de_run_autocad_slb;
	mi->identify_fn = de_identify_autocad_slb;
}
