// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// AutoCAD Slide Library (.slb)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_autocad_slb);

static void de_run_autocad_slb(deark *c, de_module_params *mparams)
{
	i64 pos;
	i64 nslides = 0;
	i64 k;
	struct slideinfo {
		i64 pos;
		i64 len;
	};
	i64 si_numalloc;
	struct slideinfo *si = NULL;
	de_ucstring *slidename = NULL;

	de_dbg(c, "[pass 1: recording addresses]");
	si_numalloc = 64;
	si = de_mallocarray(c, si_numalloc, sizeof(struct slideinfo));
	pos = 32;
	while(1) {
		i64 k;

		if(pos > (c->infile->len-36)) {
			de_err(c, "Unterminated directory");
			goto done;
		}
		if(de_getbyte(pos)==0) {
			break;
		}

		k = nslides; // Index of the new slide
		nslides++;

		if(nslides > si_numalloc) {
			i64 old_numalloc, new_numalloc;

			if(!de_good_image_count(c, nslides)) {
				de_err(c, "Too many slides");
				goto done;
			}
			old_numalloc = si_numalloc;
			new_numalloc = old_numalloc*2;
			si = de_reallocarray(c, si, old_numalloc, sizeof(struct slideinfo),
				new_numalloc);
			si_numalloc *= new_numalloc;
		}

		si[k].pos = de_getu32le(pos+32);

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
		// Start by assuming this slide ends at the end of the file. If this
		// turns out not to be the last slide, this value will be changed later.
		si[k].len = c->infile->len - si[k].pos;

		pos += 36;
	}

	de_dbg(c, "[pass 2: extracting slides]");
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
		de_finfo_set_name_from_ucstring(c, fi, slidename, 0);
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
