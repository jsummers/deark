// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// PNG and related formats

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_png);

#define PNGID_IDAT 0x49444154
#define PNGID_iCCP 0x69434350

typedef struct localctx_struct {
#define DE_PNGFMT_PNG 1
#define DE_PNGFMT_JNG 2
#define DE_PNGFMT_MNG 3
	int fmt;
} lctx;

static void do_png_iccp(deark *c, de_int64 pos, de_int64 len)
{
	de_byte prof_name[81];
	de_int64 prof_name_len;
	de_byte cmpr_type;
	dbuf *f = NULL;
	de_finfo *fi = NULL;

	de_read(prof_name, pos, 80); // One of the next 80 bytes should be a NUL.
	prof_name[80] = '\0';
	prof_name_len = de_strlen((const char*)prof_name);
	if(prof_name_len > 79) return;
	cmpr_type = de_getbyte(pos + prof_name_len + 1);
	if(cmpr_type!=0) return;

	fi = de_finfo_create(c);
	if(c->filenames_from_file)
		de_finfo_set_name_from_sz(c, fi, (const char*)prof_name, DE_ENCODING_LATIN1);
	f = dbuf_create_output_file(c, "icc", fi, DE_CREATEFLAG_IS_AUX);
	de_uncompress_zlib(c->infile, pos + prof_name_len + 2,
		len - (prof_name_len + 2), f);
	dbuf_close(f);
	de_finfo_destroy(c, fi);
}

static int do_identify_png_internal(deark *c)
{
	de_byte buf[8];
	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_PNG;
	if(!de_memcmp(buf, "\x8b\x4a\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_JNG;
	if(!de_memcmp(buf, "\x8a\x4d\x4e\x47\x0d\x0a\x1a\x0a", 8)) return DE_PNGFMT_MNG;
	return 0;
}

static void de_run_png(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 chunk_data_len;
	de_int32 prev_chunk_id = 0;
	int suppress_idat_dbg = 0;
	struct de_fourcc chunk4cc;

	d = de_malloc(c, sizeof(lctx));

	d->fmt = do_identify_png_internal(c);
	switch(d->fmt) {
	case DE_PNGFMT_PNG: de_declare_fmt(c, "PNG"); break;
	case DE_PNGFMT_JNG: de_declare_fmt(c, "JNG"); break;
	case DE_PNGFMT_MNG: de_declare_fmt(c, "MNG"); break;
	}

	pos = 8;
	while(pos < c->infile->len) {
		chunk_data_len = de_getui32be(pos);
		if(pos + 8 + chunk_data_len + 4 > c->infile->len) break;
		dbuf_read_fourcc(c->infile, pos+4, &chunk4cc, 0);

		if(chunk4cc.id==PNGID_IDAT && suppress_idat_dbg) {
			;
		}
		else if(chunk4cc.id==PNGID_IDAT && prev_chunk_id==PNGID_IDAT && c->debug_level<2) {
			de_dbg(c, "(more IDAT chunks follow)\n");
			suppress_idat_dbg = 1;
		}
		else {
			de_dbg(c, "'%s' chunk at %d dpos=%d dlen=%d\n", chunk4cc.id_printable, (int)pos,
				(int)(pos+8), (int)chunk_data_len);
			if(chunk4cc.id!=PNGID_IDAT) suppress_idat_dbg = 0;
		}

		if(chunk4cc.id==PNGID_iCCP) {
			do_png_iccp(c, pos+8, chunk_data_len);
		}
		pos += 8 + chunk_data_len + 4;
		prev_chunk_id = chunk4cc.id;
	}

	de_free(c, d);
}

static int de_identify_png(deark *c)
{
	int x;
	x = do_identify_png_internal(c);
	if(x!=0) return 100;
	return 0;
}

void de_module_png(deark *c, struct deark_module_info *mi)
{
	mi->id = "png";
	mi->desc = "PNG image (resources only)";
	mi->run_fn = de_run_png;
	mi->identify_fn = de_identify_png;
}

