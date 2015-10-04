// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Windows Metafile formats (WMF, EMF, etc.)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int has_aldus_header;
	de_int64 file_type;
	de_int64 version;
	de_int64 num_objects;
} lctx;

typedef void (*record_decoder_fn)(deark *c, lctx *d, de_int64 rectype);

struct func_info {
	de_uint16 rectype;
	const char *name;
	record_decoder_fn fn;
};
static const struct func_info func_info_arr[] = {
	{ 0x0000, "EOF", NULL },
	{ 0x001e, "SAVEDC", NULL },
	{ 0x0035, "REALIZEPALETTE", NULL },
	{ 0x00f7, "CREATEPALETTE", NULL },
	{ 0x0102, "SETBKMODE", NULL },
	{ 0x0103, "SETMAPMODE", NULL },
	{ 0x0104, "SETROP2", NULL },
	{ 0x0105, "SETRELABS", NULL },
	{ 0x0106, "SETPOLYFILLMODE", NULL },
	{ 0x01f0, "DELETEOBJECT", NULL },
	{ 0x012d, "SELECTOBJECT", NULL },
	{ 0x020b, "SETWINDOWORG", NULL },
	{ 0x020c, "SETWINDOWEXT", NULL },
	{ 0x0234, "SELECTPALETTE", NULL },
	{ 0x02fa, "CREATEPENINDIRECT", NULL },
	{ 0x02fc, "CREATEBRUSHINDIRECT", NULL },
	{ 0x0324, "POLYGON", NULL },
	{ 0x0325, "POLYLINE", NULL },
	{ 0x041f, "SETPIXEL", NULL },
	{ 0x0538, "POLYPOLYGON", NULL },
	{ 0x061d, "PATBLT", NULL },
	{ 0x0626, "ESCAPE", NULL },
	{ 0x0f43, "STRETCHDIB", NULL },
	{ 0xffff, NULL, NULL }
};

static void do_read_aldus_header(deark *c, lctx *d)
{
	de_int64 left, top, right, bottom;
	de_int64 units_per_inch;

	de_dbg(c, "Aldus Placeable Metafile header at 0\n");
	de_dbg_indent(c, 1);
	left = dbuf_geti16le(c->infile, 6);
	top = dbuf_geti16le(c->infile, 8);
	right = dbuf_geti16le(c->infile, 10);
	bottom = dbuf_geti16le(c->infile, 12);
	de_dbg(c, "location: (%d,%d) - (%d,%d)\n", (int)left, (int)top,
		(int)right, (int)bottom);
	units_per_inch = de_getui16le(14);
	de_dbg(c, "metafile units per inch: %d\n", (int)units_per_inch);
	de_dbg_indent(c, -1);
}

static int do_read_header(deark *c, lctx *d, de_int64 pos)
{
	de_int64 hsize_words, maxrecsize_words, filesize_words;
	int retval = 0;

	de_dbg(c, "WMF header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	d->file_type = de_getui16le(pos);
	de_dbg(c, "file type: %d\n", (int)d->file_type);
	if(d->file_type!=1 && d->file_type!=2) {
		de_err(c, "Invalid or unsupported WMF file type (%d)\n", (int)d->file_type);
		goto done;
	}
	hsize_words = de_getui16le(pos+2);
	de_dbg(c, "header size: %d bytes\n", (int)(hsize_words*2));
	if(hsize_words != 9) {
		de_err(c, "Incorrect WMF header size (expected 9, is %d)\n", (int)hsize_words);
		goto done;
	}
	d->version = de_getui16le(pos+4);
	de_dbg(c, "Windows version: %d.%d\n", (int)((d->version&0xff00)>>8),
		(int)(d->version&0x00ff));
	filesize_words = de_getui32le(pos+6);
	de_dbg(c, "reported file size: %d bytes\n", (int)(filesize_words*2));
	d->num_objects = de_getui16le(pos+10);
	de_dbg(c, "number of objects: %d\n", (int)d->num_objects);
	maxrecsize_words = de_getui32le(pos+12);
	de_dbg(c, "max record size: %d bytes\n", (int)(maxrecsize_words*2));
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static const struct func_info *find_func_info(de_int64 rectype)
{
	de_int64 i;

	for(i=0; func_info_arr[i].rectype!=0xffff; i++) {
		if(func_info_arr[i].rectype == rectype) {
			return &func_info_arr[i];
		}
	}
	return NULL;
}

// Returns 0 if EOF record was found.
static int do_wmf_record(deark *c, lctx *d, de_int64 recnum, de_int64 recpos,
	de_int64 recsize_bytes)
{
	de_int64 rectype = 0;
	const struct func_info *fnci;

	rectype = de_getui16le(recpos+4);

	fnci = find_func_info(rectype);

	de_dbg(c, "record #%d at %d, type=0x%04x (%s), size=%d bytes\n", (int)recnum,
		(int)recpos, (unsigned int)rectype,
		fnci ? fnci->name : "?",
		(int)recsize_bytes);

	return (rectype==0x0000)?0:1;
}

static void do_wmf_record_list(deark *c, lctx *d, de_int64 pos)
{
	de_int64 recpos;
	de_int64 recsize_words, recsize_bytes;
	de_int64 count;

	de_dbg(c, "record list at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	count = 0;
	while(1) {
		recpos = pos;
		if(recpos >= c->infile->len) break; // Unexpected EOF

		recsize_words = de_getui32le(recpos);
		recsize_bytes = recsize_words*2;
		if(recpos + recsize_bytes > c->infile->len) break; // Unexpected EOF
		if(recsize_bytes < 6) break; // Invalid size

		if(!do_wmf_record(c, d, count, recpos, recsize_bytes)) {
			break;
		}

		pos += recsize_bytes;
		count++;
	}

	de_dbg_indent(c, -1);
}

static void de_run_wmf(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!dbuf_memcmp(c->infile, 0, "\xd7\xcd\xc6\x9a", 4)) {
		do_read_aldus_header(c, d);
		pos = 22;
	}

	if(!do_read_header(c, d, pos)) {
		goto done;
	}
	pos += 18;

	do_wmf_record_list(c, d, pos);

done:
	de_free(c, d);
}

static int de_identify_wmf(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xd7\xcd\xc6\x9a", 4))
		return 100;
	// TODO: Identify WMF without a Placeable Metafile header
	// TODO: Identify EMF
	return 0;
}

void de_module_wmf(deark *c, struct deark_module_info *mi)
{
	mi->id = "wmf";
	mi->run_fn = de_run_wmf;
	mi->identify_fn = de_identify_wmf;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
