// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>

#include <deark-modules.h>

static void de_run_eps(deark *c, const char *params)
{
	de_int64 eps_offset, eps_len;
	de_int64 wmf_offset, wmf_len;
	de_int64 tiff_offset, tiff_len;

	de_dbg(c, "In eps module\n");


	eps_offset  = de_getui32le(4);
	eps_len     = de_getui32le(8);
	wmf_offset  = de_getui32le(12);
	wmf_len     = de_getui32le(16);
	tiff_offset = de_getui32le(20);
	tiff_len    = de_getui32le(24);

	if(eps_len>0) {
		de_dbg(c, "Extracting EPS offs=%d len=%d\n", (int)eps_offset, (int)eps_len);
		dbuf_create_file_from_slice(c->infile, eps_offset, eps_len, "eps");
	}
	if(wmf_len>0) {
		de_dbg(c, "Extracting WMF offs=%d len=%d\n", (int)wmf_offset, (int)wmf_len);
		dbuf_create_file_from_slice(c->infile, wmf_offset, wmf_len, "wmf");
	}
	if(tiff_len>0) {
		de_dbg(c, "Extracting TIFF offs=%d len=%d\n", (int)tiff_offset, (int)tiff_len);
		dbuf_create_file_from_slice(c->infile, tiff_offset, tiff_len, "tif");
	}
}

static int de_identify_eps(deark *c)
{
	de_byte b[4];
	de_read(b, 0, 4);

	if(b[0]==0xc5 && b[1]==0xd0 && b[2]==0xd3 && b[3]==0xc6)
		return 100;
	return 0;
}

void de_module_eps(deark *c, struct deark_module_info *mi)
{
	mi->id = "eps";
	mi->run_fn = de_run_eps;
	mi->identify_fn = de_identify_eps;
}
