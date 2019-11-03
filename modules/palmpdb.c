// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// Palm Database (PDB)
// Palm Resource (PRC)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_palmdb);
DE_DECLARE_MODULE(de_module_palmrc);

#define CODE_Tbmp 0x54626d70U
#define CODE_View 0x56696577U
#define CODE_appl 0x6170706cU
#define CODE_clpr 0x636c7072U
#define CODE_lnch 0x6c6e6368U
#define CODE_pqa  0x70716120U
#define CODE_tAIB 0x74414942U
#define CODE_tAIN 0x7441494eU
#define CODE_tAIS 0x74414953U
#define CODE_tSTR 0x74535452U
#define CODE_tver 0x74766572U
#define CODE_vIMG 0x76494d47U

struct rec_data_struct {
	u32 offset;
};

struct rec_list_struct {
	i64 num_recs;
	// The rec_data items are in the order they appear in the file
	struct rec_data_struct *rec_data;
	// A list of all the rec_data indices, in the order we should read them
	size_t *order_to_read;
	i64 icon_name_count;
};

struct rsrc_type_info_struct {
	u32 id;
	u32 flags; // 1=standard Palm resource
	const char *descr;
	void* /* rsrc_decoder_fn */ decoder_fn;
};

struct img_gen_info {
	i64 w, h;
	i64 bitsperpixel;
	i64 rowbytes;
	de_finfo *fi;
	unsigned int createflags;
};

typedef struct localctx_struct {
#define FMT_PDB     1
#define FMT_PRC     2
	int file_fmt;
#define SUBFMT_NONE 0
#define SUBFMT_PQA  1
#define SUBFMT_IMAGEVIEWER 2
	int file_subfmt;

#define TIMESTAMPFMT_UNKNOWN 0
#define TIMESTAMPFMT_MACBE   1
#define TIMESTAMPFMT_UNIXBE  2
#define TIMESTAMPFMT_MACLE   3
	int timestampfmt;

	int has_nonzero_ids;
	const char *fmt_shortname;
	i64 rec_size; // bytes per record
	struct de_fourcc dtype4cc;
	struct de_fourcc creator4cc;
	struct de_timestamp mod_time;
	i64 appinfo_offs;
	i64 sortinfo_offs;
	struct rec_list_struct rec_list;
	de_ucstring *icon_name;
} lctx;

static void handle_palm_timestamp(deark *c, lctx *d, i64 pos, const char *name,
	struct de_timestamp *returned_ts)
{
	struct de_timestamp ts;
	char timestamp_buf[64];
	i64 ts_int;

	de_zeromem(&ts, sizeof(struct de_timestamp));
	if(returned_ts) {
		de_zeromem(returned_ts, sizeof(struct de_timestamp));
	}

	ts_int = de_getu32be(pos);
	if(ts_int==0) {
		de_dbg(c, "%s: 0 (not set)", name);
		goto done;
	}

	de_dbg(c, "%s: ...", name);
	de_dbg_indent(c, 1);

	// I've seen three different ways to interpret this 32-bit timestamp, and
	// I don't know how to guess the correct one.

	if(d->timestampfmt==TIMESTAMPFMT_MACBE || d->timestampfmt==TIMESTAMPFMT_UNKNOWN) {
		de_mac_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Mac-BE: %"I64_FMT" (%s)", ts_int, timestamp_buf);
	}

	ts_int = de_geti32be(pos);
	if(d->timestampfmt==TIMESTAMPFMT_UNIXBE ||
		(d->timestampfmt==TIMESTAMPFMT_UNKNOWN && ts_int>0)) // Assume dates before 1970 are wrong
	{
		de_unix_time_to_timestamp(ts_int, &ts, 0x1);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Unix-BE: %"I64_FMT" (%s)", ts_int, timestamp_buf);
	}

	ts_int = de_getu32le(pos);
	if(d->timestampfmt==TIMESTAMPFMT_MACLE ||
		(d->timestampfmt==TIMESTAMPFMT_UNKNOWN && ts_int>2082844800))
	{
		de_mac_time_to_timestamp(ts_int, &ts);
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "... if Mac-LE: %"I64_FMT" (%s)", ts_int, timestamp_buf);
	}

	de_dbg_indent(c, -1);

done:
	if(returned_ts && d->timestampfmt!=TIMESTAMPFMT_UNKNOWN) {
		*returned_ts = ts;
	}
}

static void get_db_attr_descr(de_ucstring *s, u32 attribs)
{
	size_t i;
	struct { u32 a; const char *n; } flags_arr[] = {
		{0x0001, "dmHdrAttrResDB"},
		{0x0002, "dmHdrAttrReadOnly"},
		{0x0004, "dmHdrAttrAppInfoDirty"},
		{0x0008, "dmHdrAttrBackup"},
		{0x0010, "dmHdrAttrOKToInstallNewer"},
		{0x0020, "dmHdrAttrResetAfterInstall"},
		{0x0040, "dmHdrAttrCopyPrevention"},
		{0x0080, "dmHdrAttrStream"},
		{0x0100, "dmHdrAttrHidden"},
		{0x0200, "dmHdrAttrLaunchableData"},
		{0x0400, "dmHdrAttrRecyclable"},
		{0x0800, "dmHdrAttrBundle"},
		{0x8000, "dmHdrAttrOpen"}
	};
	for(i=0; i<DE_ARRAYCOUNT(flags_arr); i++) {
		if(attribs & flags_arr[i].a)
			ucstring_append_flags_item(s, flags_arr[i].n);

	}
	if(attribs==0) ucstring_append_flags_item(s, "none");
}

static int do_read_pdb_prc_header(deark *c, lctx *d)
{
	i64 pos1 = 0;
	de_ucstring *dname = NULL;
	de_ucstring *attr_descr = NULL;
	u32 attribs;
	u32 version;
	i64 x;
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos1);
	de_dbg_indent(c, 1);

	dname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos1, 32, dname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(dname));

	attribs = (u32)de_getu16be(pos1+32);
	attr_descr = ucstring_create(c);
	get_db_attr_descr(attr_descr, attribs);
	de_dbg(c, "attributes: 0x%04x (%s)", (unsigned int)attribs,
		ucstring_getpsz(attr_descr));

	version = (u32)de_getu16be(pos1+34);
	de_dbg(c, "version: 0x%04x", (unsigned int)version);

	handle_palm_timestamp(c, d, pos1+36, "create date", NULL);
	handle_palm_timestamp(c, d, pos1+40, "mod date", &d->mod_time);
	handle_palm_timestamp(c, d, pos1+44, "backup date", NULL);

	x = de_getu32be(pos1+48);
	de_dbg(c, "mod number: %d", (int)x);
	d->appinfo_offs = de_getu32be(pos1+52);
	de_dbg(c, "app info pos: %d", (int)d->appinfo_offs);
	d->sortinfo_offs = de_getu32be(pos1+56);
	de_dbg(c, "sort info pos: %d", (int)d->sortinfo_offs);

	dbuf_read_fourcc(c->infile, pos1+60, &d->dtype4cc, 4, 0x0);
	de_dbg(c, "type: \"%s\"", d->dtype4cc.id_dbgstr);

	dbuf_read_fourcc(c->infile, pos1+64, &d->creator4cc, 4, 0x0);
	de_dbg(c, "creator: \"%s\"", d->creator4cc.id_dbgstr);

	if(d->file_fmt==FMT_PDB) {
		d->fmt_shortname = "PDB";
		if(d->dtype4cc.id==CODE_pqa && d->creator4cc.id==CODE_clpr) {
			d->file_subfmt = SUBFMT_PQA;
			de_declare_fmt(c, "Palm PQA");
		}
		else if(d->dtype4cc.id==CODE_vIMG && d->creator4cc.id==CODE_View) {
			d->file_subfmt = SUBFMT_IMAGEVIEWER;
			de_declare_fmt(c, "Palm Database ImageViewer");
		}
		else {
			de_declare_fmt(c, "Palm PDB");
		}
	}
	else if(d->file_fmt==FMT_PRC) {
		d->fmt_shortname = "PRC";
	}
	else {
		goto done;
	}

	x = de_getu32be(68);
	de_dbg(c, "uniqueIDseed: %u", (unsigned int)x);

	retval = 1;
done:
	de_dbg_indent(c, -1);
	ucstring_destroy(dname);
	ucstring_destroy(attr_descr);
	return retval;
}

static i64 calc_rec_len(deark *c, lctx *d, i64 rec_idx)
{
	i64 len;
	if(rec_idx+1 < d->rec_list.num_recs) {
		len = (i64)(d->rec_list.rec_data[rec_idx+1].offset - d->rec_list.rec_data[rec_idx].offset);
	}
	else {
		len = c->infile->len - (i64)d->rec_list.rec_data[rec_idx].offset;
	}
	return len;
}

// ext_ucstring will be used if ext_sz is NULL
static void extract_item(deark *c, lctx *d, i64 data_offs, i64 data_len,
	const char *ext_sz, de_ucstring *ext_ucstring,
	unsigned int createflags, int always_extract)
{
	de_finfo *fi = NULL;

	if(c->extract_level<2 && !always_extract) goto done;
	if(data_offs<0 || data_len<0) goto done;
	if(data_offs+data_len > c->infile->len) goto done;
	fi = de_finfo_create(c);
	if(ext_sz) {
		de_finfo_set_name_from_sz(c, fi, ext_sz, 0, DE_ENCODING_ASCII);
	}
	else if(ext_ucstring) {
		de_finfo_set_name_from_ucstring(c, fi, ext_ucstring, 0);
	}
	dbuf_create_file_from_slice(c->infile, data_offs, data_len, NULL, fi, createflags);
done:
	de_finfo_destroy(c, fi);
}

static int do_decompress_imgview_image(deark *c, lctx *d, dbuf *inf,
	i64 pos1, i64 len, dbuf *unc_pixels)
{
	i64 pos = pos1;
	u8 b1, b2;
	i64 count;

	while(pos < pos1+len) {
		b1 = dbuf_getbyte(inf, pos++);
		if(b1>128) {
			count = (i64)b1-127;
			b2 = dbuf_getbyte(inf, pos++);
			dbuf_write_run(unc_pixels, b2, count);
		}
		else {
			count = (i64)b1+1;
			dbuf_copy(inf, pos, count, unc_pixels);
			pos += count;
		}
	}
	return 1;
}

static void do_generate_unc_image(deark *c, lctx *d, dbuf *unc_pixels,
	struct img_gen_info *igi)
{
	i64 i, j;
	u8 b;
	u8 b_adj;
	de_bitmap *img = NULL;

	if(igi->bitsperpixel==1) {
		de_convert_and_write_image_bilevel(unc_pixels, 0, igi->w, igi->h, igi->rowbytes,
			DE_CVTF_WHITEISZERO, igi->fi, igi->createflags);
		goto done;
	}

	img = de_bitmap_create(c, igi->w, igi->h, 1);

	for(j=0; j<igi->h; j++) {
		for(i=0; i<igi->w; i++) {
			b = de_get_bits_symbol(unc_pixels, igi->bitsperpixel, igi->rowbytes*j, i);
			b_adj = 255 - de_sample_nbit_to_8bit(igi->bitsperpixel, (unsigned int)b);
			de_bitmap_setpixel_gray(img, i, j, b_adj);
		}
	}

	de_bitmap_write_to_file_finfo(img, igi->fi, igi->createflags);

done:
	de_bitmap_destroy(img);
}

// A wrapper that decompresses the image if necessary, then calls do_generate_unc_image().
static void do_generate_image(deark *c, lctx *d,
	dbuf *inf, i64 pos, i64 len, unsigned int cmpr_meth,
	struct img_gen_info *igi)
{
	dbuf *unc_pixels = NULL;
	i64 expected_num_uncmpr_image_bytes;

	expected_num_uncmpr_image_bytes = igi->rowbytes*igi->h;

	if(cmpr_meth==0) {
		if(expected_num_uncmpr_image_bytes > len) {
			de_warn(c, "Not enough data for image");
		}
		unc_pixels = dbuf_open_input_subfile(inf, pos, len);
	}
	else {
		unc_pixels = dbuf_create_membuf(c, expected_num_uncmpr_image_bytes, 1);
		do_decompress_imgview_image(c, d, inf, pos, len, unc_pixels);

		// TODO: The byte counts in this message are not very accurate.
		de_dbg(c, "decompressed %d bytes to %d bytes", (int)len,
			(int)unc_pixels->len);
	}

	do_generate_unc_image(c, d, unc_pixels, igi);

	dbuf_close(unc_pixels);
}

static void do_imgview_image(deark *c, lctx *d, i64 pos1, i64 len)
{
	u8 imgver;
	u8 imgtype;
	unsigned int cmpr_meth;
	i64 x0, x1;
	i64 pos = pos1;
	i64 num_raw_image_bytes;
	de_ucstring *iname = NULL;
	struct img_gen_info *igi = NULL;

	igi = de_malloc(c, sizeof(struct img_gen_info));
	igi->fi = de_finfo_create(c);

	de_dbg(c, "image record at %d", (int)pos1);
	de_dbg_indent(c, 1);

	igi->fi->image_mod_time = d->mod_time;

	iname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 32, iname, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz(iname));
	if(iname->len>0 && c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, igi->fi, iname, 0);
	}
	pos += 32;

	imgver = de_getbyte(pos++);
	de_dbg(c, "version: 0x%02x", (unsigned int)imgver);
	cmpr_meth = (unsigned int)(imgver&0x07);
	de_dbg_indent(c, 1);
	de_dbg(c, "compression method: %u", cmpr_meth);
	de_dbg_indent(c, -1);
	if(imgver>0x01) {
		de_warn(c, "This version of ImageViewer format (0x%02x) might not be supported correctly.",
			(unsigned int)imgver);
	}

	imgtype = de_getbyte(pos++);
	de_dbg(c, "type: 0x%02x", (unsigned int)imgtype);
	de_dbg_indent(c, 1);
	switch(imgtype) {
	case 0: igi->bitsperpixel = 2; break;
	case 2: igi->bitsperpixel = 4; break;
	default: igi->bitsperpixel = 1;
	}
	de_dbg(c, "bits/pixel: %d", (int)igi->bitsperpixel);
	de_dbg_indent(c, -1);

	x0 = de_getu32be(pos);
	de_dbg(c, "reserved1: 0x%08x", (unsigned int)x0);
	pos += 4;

	x0 = de_getu32be(pos);
	de_dbg(c, "note: 0x%08x", (unsigned int)x0);
	pos += 4;

	x0 = de_getu16be(pos);
	pos += 2;
	x1 = de_getu16be(pos);
	pos += 2;
	de_dbg(c, "last: (%d,%d)", (int)x0, (int)x1);

	x0 = de_getu32be(pos);
	de_dbg(c, "reserved2: 0x%08x", (unsigned int)x0);
	pos += 4;

	// TODO: Is the anchor signed or unsigned?
	x0 = de_getu16be(pos);
	pos += 2;
	x1 = de_getu16be(pos);
	pos += 2;
	de_dbg(c, "anchor: (%d,%d)", (int)x0, (int)x1);

	igi->w = de_getu16be(pos);
	pos += 2;
	igi->h = de_getu16be(pos);
	pos += 2;
	de_dbg_dimensions(c, igi->w, igi->h);
	if(!de_good_image_dimensions(c, igi->w, igi->h)) goto done;

	igi->rowbytes = (igi->w*igi->bitsperpixel + 7)/8;
	num_raw_image_bytes = pos1+len-pos;

	de_dbg(c, "image data at %d", (int)pos);
	de_dbg_indent(c, 1);
	do_generate_image(c, d, c->infile, pos, num_raw_image_bytes,
		cmpr_meth, igi);
	de_dbg_indent(c, -1);

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(iname);
	if(igi) {
		de_finfo_destroy(c, igi->fi);
		de_free(c, igi);
	}
}

static void do_imgview_text(deark *c, lctx *d, i64 pos, i64 len)
{
	de_ucstring *s = NULL;

	if(len<1) return;

	// (I'm pretty much just guessing the format of this record.)
	s = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, len, s, DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);

	// TODO: Decide when to write the text record to a file.
	// Problem is that we're already using -a to mean "write all raw records to files".
	{
		dbuf *outf = NULL;
		outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
		ucstring_write_as_utf8(c, s, outf, 1);
		dbuf_close(outf);
	}

	ucstring_destroy(s);
}

static void get_rec_attr_descr(de_ucstring *s, u8 attribs)
{
	if(attribs&0x10) ucstring_append_flags_item(s, "mRecAttrSecret");
	if(attribs&0x20) ucstring_append_flags_item(s, "dmRecAttrBusy");
	if(attribs&0x40) ucstring_append_flags_item(s, "dmRecAttrDirty");
	if(attribs&0x80) ucstring_append_flags_item(s, "dmRecAttrDelete");
	if(attribs==0) ucstring_append_flags_item(s, "none");
}

// For PDB or PQA format
static int do_read_pdb_record(deark *c, lctx *d, i64 rec_idx, i64 pos1)
{
	i64 data_offs;
	u8 attribs;
	u32 id;
	i64 data_len;
	de_ucstring *attr_descr = NULL;
	char extfull[80];

	de_dbg(c, "record[%d] at %d", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	data_offs = (int)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d", (int)data_offs);

	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d", (int)data_len);

	de_snprintf(extfull, sizeof(extfull), "rec%d.bin", (int)rec_idx); // May be overridden

	{
		const char *idname = NULL;
		char tmpstr[80];

		attribs = de_getbyte(pos1+4);
		attr_descr = ucstring_create(c);
		get_rec_attr_descr(attr_descr, attribs);
		de_dbg(c, "attributes: 0x%02x (%s)", (unsigned int)attribs,
			ucstring_getpsz(attr_descr));

		id = (de_getbyte(pos1+5)<<16) |
			(de_getbyte(pos1+6)<<8) |
			(de_getbyte(pos1+7));

		if(d->file_subfmt==SUBFMT_IMAGEVIEWER) {
			if(id==0x6f8000) idname = "image record";
			else if(id==0x6f8001) idname = "text record";
			else idname = "?";
		}
		if(idname)
			de_snprintf(tmpstr, sizeof(tmpstr), " (%s)", idname);
		else
			tmpstr[0] = '\0';

		de_dbg(c, "id: %u (0x%06x)%s", (unsigned int)id, (unsigned int)id, tmpstr);

		if(d->has_nonzero_ids) {
			de_snprintf(extfull, sizeof(extfull), "%06x.bin", (unsigned int)id);
		}

		if(d->file_subfmt==SUBFMT_IMAGEVIEWER) {
			if(id==0x6f8000) do_imgview_image(c, d, data_offs, data_len);
			else if(id==0x6f8001) do_imgview_text(c, d, data_offs, data_len);
		}
	}

	extract_item(c, d, data_offs, data_len, extfull, NULL, 0, 0);

	de_dbg_indent(c, -1);
	ucstring_destroy(attr_descr);
	return 1;
}

static void do_string_rsrc(deark *c, lctx *d,
	i64 pos, i64 len,
	const struct rsrc_type_info_struct *rti, unsigned int flags)
{
	de_ucstring *s = NULL;

	if(!rti || !rti->descr) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "%s: \"%s\"", rti->descr, ucstring_getpsz(s));

	if((flags&0x1) & !d->icon_name) {
		// Also save the string to d->icon_name, to be used later
		d->icon_name = ucstring_create(c);
		dbuf_read_to_ucstring_n(c->infile, pos, len, 80, d->icon_name,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	}

	ucstring_destroy(s);
}

static const struct rsrc_type_info_struct rsrc_type_info_arr[] = {
	//{ FONT, 0x1, "custom font", NULL },
	{ 0x4d424152U /* MBAR */, 0x1, "menu bar", NULL },
	{ 0x4d454e55U /* MENU */, 0x1, "menu", NULL },
	//{ TRAP, 0x0, "", NULL },
	{ 0x54616c74U /* Talt */, 0x1, "alert", NULL },
	{ CODE_Tbmp, 0x1, "bitmap image", NULL },
	//{ cnty, 0x1, "country-dependent info", NULL },
	{ 0x636f6465U /* code */, 0x0, "code segment", NULL },
	{ 0x64617461U /* data */, 0x0, "data segment", NULL },
	//{ libr, 0x0, "", NULL }
	//{ 0x70726566U /* pref */, 0x0, "", NULL },
	//{ rloc, 0x0, "", NULL }
	//{ silk, 0x1, "silk-screened area info", NULL },
	{ CODE_tAIB, 0x1, "app icon", NULL },
	{ CODE_tAIN, 0x1, "app icon name", NULL },
	{ CODE_tAIS, 0x1, "app info string", NULL },
	{ 0x7442544eU /* tBTN */, 0x1, "command button", NULL },
	//{ tCBX, 0x1, "check box", NULL },
	//{ tFBM, 0x1, "form bitmap", NULL },
	{ 0x74464c44U /* tFLD */, 0x1, "text field", NULL },
	{ 0x7446524dU /* tFRM */, 0x1, "form", NULL },
	//{ tGDT, 0x1, "gadget", NULL },
	//{ tGSI, 0x1, "graffiti shift indicator", NULL },
	{ 0x744c424c /* tLBL */, 0x1, "label", NULL },
	//{ tLST, 0x1, "list", NULL },
	//{ tPBN, 0x1, "push button", NULL },
	{ 0x7450554cU /* tPUL */, 0x1, "pop-up list", NULL },
	{ 0x74505554U /* tPUT */, 0x1, "pop-up trigger", NULL },
	//{ tREP, 0x1, "repeating button", NULL },
	//{ tSCL, 0x1, "scroll bar", NULL },
	//{ tSLT, 0x1, "selector trigger", NULL },
	{ 0x7453544cU /* tSTL */, 0x1, "string list", NULL },
	{ CODE_tSTR, 0x1, "string", NULL },
	{ 0x7454424cU /* tTBL */, 0x1, "table", NULL },
	//{ taif, 0x1, "app icon family", NULL },
	//{ tbmf, 0x1, "bitmap family", NULL },
	//{ tgbn, 0x1, "graphic button", NULL },
	//{ tgpb, 0x1, "graphic push button", NULL },
	//{ tgrb, 0x1, "graphic repeating button", NULL },
	//{ tint, 0x1, "integer constant", NULL },
	{ CODE_tver, 0x1, "app version string", NULL }
};

static const struct rsrc_type_info_struct *get_rsrc_type_info(u32 id)
{
	size_t i;

	for(i=0; i<DE_ARRAYCOUNT(rsrc_type_info_arr); i++) {
		if(id == rsrc_type_info_arr[i].id) {
			return &rsrc_type_info_arr[i];
		}
	}
	return NULL;
}

static int do_read_prc_record(deark *c, lctx *d, i64 rec_idx, i64 pos1)
{
	u32 id;
	struct de_fourcc rsrc_type_4cc;
	i64 data_offs;
	i64 data_len;
	int always_extract = 0;
	de_ucstring *ext_ucstring = NULL;
	int ext_set = 0;
	const char *rsrc_type_descr;
	const struct rsrc_type_info_struct *rti;

	de_dbg(c, "record[%d] at %d", (int)rec_idx, (int)pos1);
	de_dbg_indent(c, 1);

	dbuf_read_fourcc(c->infile, pos1, &rsrc_type_4cc, 4, 0x0);
	rti = get_rsrc_type_info(rsrc_type_4cc.id);
	if(rti && rti->descr) rsrc_type_descr = rti->descr;
	else rsrc_type_descr = "?";
	de_dbg(c, "resource type: '%s' (%s)", rsrc_type_4cc.id_dbgstr, rsrc_type_descr);

	ext_ucstring = ucstring_create(c);
	// The "filename" always starts with the fourcc.
	ucstring_append_sz(ext_ucstring, rsrc_type_4cc.id_sanitized_sz, DE_ENCODING_ASCII);

	id = (u32)de_getu16be(pos1+4);
	de_dbg(c, "id: %d", (int)id);

	data_offs = (i64)d->rec_list.rec_data[rec_idx].offset;
	de_dbg(c, "data pos: %d", (int)data_offs);
	data_len = calc_rec_len(c, d, rec_idx);
	de_dbg(c, "calculated len: %d", (int)data_len);

	switch(rsrc_type_4cc.id) {
	case CODE_Tbmp:
		ucstring_append_sz(ext_ucstring, ".palm", DE_ENCODING_LATIN1);
		ext_set = 1;
		always_extract = 1;
		break;
		// TODO: tbmf, taif
	case CODE_tAIB:
		if(d->icon_name && c->filenames_from_file) {
			ucstring_append_sz(ext_ucstring, ".", DE_ENCODING_LATIN1);
			ucstring_append_ucstring(ext_ucstring, d->icon_name);
		}
		ucstring_append_sz(ext_ucstring, ".palm", DE_ENCODING_LATIN1);
		ext_set = 1;
		always_extract = 1;
		break;
	case CODE_tAIN:
		do_string_rsrc(c, d, data_offs, data_len, rti,
			(d->rec_list.icon_name_count==1)?0x1:0x0);
		break;
	case CODE_tAIS:
	case CODE_tSTR:
	case CODE_tver:
		do_string_rsrc(c, d, data_offs, data_len, rti, 0);
		break;
	}

	if(!ext_set) {
		ucstring_append_sz(ext_ucstring, ".bin", DE_ENCODING_LATIN1);
	}
	extract_item(c, d, data_offs, data_len, NULL, ext_ucstring, 0, always_extract);

	de_dbg_indent(c, -1);
	ucstring_destroy(ext_ucstring);
	return 1;
}

// Put idx at the beginning of the order_to_read array, shifting everything else
// over. Assumes items [0] through [idx-1] are valid.
static void rec_list_insert_at_start(struct rec_list_struct *rl, i64 idx)
{
	i64 i;
	// Move [idx-1] to [idx],
	//      [idx-2] to [idx-1], ...
	for(i=idx; i>0; i--) {
		rl->order_to_read[i] = rl->order_to_read[i-1];
	}
	// Put idx at [0]
	rl->order_to_read[0] = (size_t)idx;
}

// Allocates and populates the d->rec_data array.
// Tests for sanity, and returns 0 if there is a problem.
static int do_prescan_records(deark *c, lctx *d, i64 pos1)
{
	i64 i;

	if(d->rec_list.num_recs<1) return 1;
	// num_recs is untrusted, but it is a 16-bit int that can be at most 65535.
	d->rec_list.rec_data = de_mallocarray(c, d->rec_list.num_recs, sizeof(struct rec_data_struct));
	d->rec_list.order_to_read = de_mallocarray(c, d->rec_list.num_recs, sizeof(size_t));
	for(i=0; i<d->rec_list.num_recs; i++) {
		// By default, read the records in the order they appear in the file.
		d->rec_list.order_to_read[i] = (size_t)i;

		if(d->file_fmt==FMT_PRC) {
			u32 rsrc_type;
			rsrc_type = (u32)de_getu32be(pos1 + d->rec_size*i);
			if(rsrc_type==CODE_tAIN && d->rec_list.icon_name_count==0) {
				// "Move" the tAIN record to the beginning, so we will read it
				// before any tAIB resources.
				rec_list_insert_at_start(&d->rec_list, i);
				d->rec_list.icon_name_count++;
			}
			d->rec_list.rec_data[i].offset = (u32)de_getu32be(pos1 + d->rec_size*i + 6);
		}
		else {
			u32 id;
			d->rec_list.rec_data[i].offset = (u32)de_getu32be(pos1 + d->rec_size*i);
			if(!d->has_nonzero_ids) {
				id = (de_getbyte(pos1+d->rec_size*i+5)<<16) |
					(de_getbyte(pos1+d->rec_size*i+6)<<8) |
					(de_getbyte(pos1+d->rec_size*i+7));
				if(id!=0) d->has_nonzero_ids = 1;
			}
		}

		// Record data must not start beyond the end of file.
		if((i64)d->rec_list.rec_data[i].offset > c->infile->len) {
			de_err(c, "Record %d (at %d) starts after end of file (%d)",
				(int)i, (int)d->rec_list.rec_data[i].offset, (int)c->infile->len);
			return 0;
		}

		// Record data must not start before the previous record's data.
		if(i>0) {
			if(d->rec_list.rec_data[i].offset < d->rec_list.rec_data[i-1].offset) {
				de_err(c, "Record %d (at %d) starts before previous record (at %d)",
					(int)i, (int)d->rec_list.rec_data[i].offset, (int)d->rec_list.rec_data[i-1].offset);
				return 0;
			}
		}
	}
	return 1;
}

// Read "Palm Database record list" or PRC records, and the data it refers to
static int do_read_pdb_prc_records(deark *c, lctx *d, i64 pos1)
{
	i64 i;
	i64 x;
	int retval = 0;

	de_dbg(c, "%s record list at %d", d->fmt_shortname, (int)pos1);
	de_dbg_indent(c, 1);

	// 6-byte header

	x = de_getu32be(pos1);
	de_dbg(c, "nextRecordListID: %d", (int)x);
	if(x!=0) {
		de_warn(c, "This file contains multiple record lists, which is not supported.");
	}

	d->rec_list.num_recs = de_getu16be(pos1+4);
	de_dbg(c, "number of records: %d", (int)d->rec_list.num_recs);

	/////

	if(d->file_fmt==FMT_PRC) d->rec_size = 10;
	else d->rec_size = 8;

	de_dbg(c, "[pre-scanning record list]");
	if(!do_prescan_records(c, d, pos1+6)) goto done;
	de_dbg(c, "[main pass through record list]");

	// i is the index in rec_list.order_to_read
	// n is the index in rec_list.rec_data
	for(i=0; i<d->rec_list.num_recs; i++) {
		i64 n;
		n = (i64)d->rec_list.order_to_read[i];
		if(d->file_fmt==FMT_PRC) {
			if(!do_read_prc_record(c, d, n, pos1+6+d->rec_size*n))
				goto done;
		}
		else {
			if(!do_read_pdb_record(c, d, n, pos1+6+d->rec_size*n))
				goto done;
		}
	}
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_pqa_app_info_block(deark *c, lctx *d, i64 pos1, i64 len)
{
	u32 sig;
	u32 ux;
	i64 n;
	de_ucstring *s = NULL;
	i64 pos = pos1;

	de_dbg(c, "hello");
	sig = (u32)de_getu32be_p(&pos);
	if(sig!=CODE_lnch) return; // Apparently not a PQA appinfo block
	de_dbg(c, "PQA sig: 0x%08x", (unsigned int)sig);

	ux = (u32)de_getu16be_p(&pos);
	de_dbg(c, "hdrVersion: 0x%04x", (unsigned int)ux);
	ux = (u32)de_getu16be_p(&pos);
	de_dbg(c, "encVersion: 0x%04x", (unsigned int)ux);

	s = ucstring_create(c);

	n = de_getu16be_p(&pos);
	dbuf_read_to_ucstring_n(c->infile, pos, n*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "verStr: \"%s\"", ucstring_getpsz(s));
	ucstring_empty(s);
	pos += 2*n;

	n = de_getu16be_p(&pos);
	dbuf_read_to_ucstring_n(c->infile, pos, n*2, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_PALM);
	de_dbg(c, "pqaTitle: \"%s\"", ucstring_getpsz(s));
	ucstring_empty(s);
	pos += 2*n;

	de_dbg(c, "icon");
	de_dbg_indent(c, 1);
	n = de_getu16be_p(&pos); // iconWords (length prefix)
	extract_item(c, d, pos, 2*n, "icon.palm", NULL, DE_CREATEFLAG_IS_AUX, 1);
	pos += 2*n;
	de_dbg_indent(c, -1);

	de_dbg(c, "smIcon");
	de_dbg_indent(c, 1);
	n = de_getu16be_p(&pos); // smIconWords
	extract_item(c, d, pos, 2*n, "smicon.palm", NULL, DE_CREATEFLAG_IS_AUX, 1);
	pos += 2*n;
	de_dbg_indent(c, -1);

	ucstring_destroy(s);
}

static void do_app_info_block(deark *c, lctx *d)
{
	i64 len;

	if(d->appinfo_offs==0) return;
	de_dbg(c, "app info block at %d", (int)d->appinfo_offs);

	de_dbg_indent(c, 1);
	if(d->sortinfo_offs) {
		len = d->sortinfo_offs - d->appinfo_offs;
	}
	else if(d->rec_list.num_recs>0) {
		len = (i64)d->rec_list.rec_data[0].offset - d->appinfo_offs;
	}
	else {
		len = c->infile->len - d->appinfo_offs;
	}
	de_dbg(c, "calculated len: %d", (int)len);

	if(len>0) {
		// TODO: In many cases, this can be parsed as a format called "standard
		// category data". But I don't know how to tell whether it is in that
		// format.
		extract_item(c, d, d->appinfo_offs, len, "appinfo.bin", NULL, DE_CREATEFLAG_IS_AUX, 0);

		if(d->file_subfmt==SUBFMT_PQA) {
			do_pqa_app_info_block(c, d, d->appinfo_offs, len);
		}
	}

	de_dbg_indent(c, -1);
}

static void do_sort_info_block(deark *c, lctx *d)
{
	i64 len;

	if(d->sortinfo_offs==0) return;
	de_dbg(c, "sort info block at %d", (int)d->sortinfo_offs);

	de_dbg_indent(c, 1);
	if(d->rec_list.num_recs>0) {
		len = (i64)d->rec_list.rec_data[0].offset - d->sortinfo_offs;
	}
	else {
		len = c->infile->len - d->sortinfo_offs;
	}
	de_dbg(c, "calculated len: %d", (int)len);

	if(len>0) {
		extract_item(c, d, d->sortinfo_offs, len, "sortinfo.bin", NULL, DE_CREATEFLAG_IS_AUX, 0);
	}

	de_dbg_indent(c, -1);
}

static void free_lctx(deark *c, lctx *d)
{
	if(d) {
		de_free(c, d->rec_list.rec_data);
		de_free(c, d->rec_list.order_to_read);
		ucstring_destroy(d->icon_name);
		de_free(c, d);
	}
}

static void de_run_pdb_or_prc(deark *c, lctx *d, de_module_params *mparams)
{
	const char *s;

	s = de_get_ext_option(c, "palm:timestampfmt");
	if(s) {
		if(!de_strcmp(s, "macbe"))
			d->timestampfmt = TIMESTAMPFMT_MACBE;
		else if(!de_strcmp(s, "unixbe"))
			d->timestampfmt = TIMESTAMPFMT_UNIXBE;
		else if(!de_strcmp(s, "macle"))
			d->timestampfmt = TIMESTAMPFMT_MACLE;
	}

	if(!do_read_pdb_prc_header(c, d)) goto done;
	if(!do_read_pdb_prc_records(c, d, 72)) goto done;
	do_app_info_block(c, d);
	do_sort_info_block(c, d);
done:
	;
}

static void de_run_palmdb(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	d = de_malloc(c, sizeof(lctx));
	d->file_fmt = FMT_PDB;
	de_run_pdb_or_prc(c, d, mparams);
	free_lctx(c, d);
}

static void de_run_palmrc(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	d = de_malloc(c, sizeof(lctx));
	d->file_fmt = FMT_PRC;
	de_declare_fmt(c, "Palm PRC");
	de_run_pdb_or_prc(c, d, mparams);
	free_lctx(c, d);
}

static int de_identify_palmdb(deark *c)
{
	int has_ext = 0;
	u8 id[8];
	u8 buf[32];
	u32 attribs;
	i64 appinfo_offs;
	i64 sortinfo_offs;
	i64 n;
	i64 num_recs;
	i64 recdata_offs;
	i64 curpos;

	static const char *exts[] = {"pdb", "prc", "pqa", "mobi"};
	static const char *ids[] = {"vIMGView", "TEXtREAd", "pqa clpr", "BOOKMOBI"};
	size_t k;

	for(k=0; k<DE_ARRAYCOUNT(exts); k++) {
		if(de_input_file_has_ext(c, exts[k])) {
			has_ext = 1;
			break;
		}
	}
	if(!has_ext) return 0;

	attribs = (u32)de_getu16be(32);
	if(attribs & 0x0001) return 0; // Might be PRC, but is not PDB

	// It is not easy to identify PDB format from its contents.
	// But it's good to do what we can, because the .pdb file extension
	// is used by several other formats.

	// The type/creator codes must presumably be printable characters
	de_read(id, 60, 8);
	for(k=0; k<8; k++) {
		if(id[k]<32) return 0;
	}

	// Check for known file types
	for(k=0; k<DE_ARRAYCOUNT(ids); k++) {
		if(!de_memcmp(id, ids[k], 8)) return 100;
	}

	// There must be at least one NUL byte in the first 32 bytes,
	// and any bytes before the NUL must presumably be printable.
	de_read(buf, 0, 32);
	n = 0;
	for(k=0; k<32; k++) {
		if(buf[k]=='\0') {
			n=1;
			break;
		}
		if(buf[k]<32) return 0;
	}
	if(n==0) return 0;

	appinfo_offs = de_getu32be(52);
	sortinfo_offs = de_getu32be(56);
	num_recs = de_getu16be(72+4);

	curpos = 72 + 6 + num_recs*8;
	if(curpos>c->infile->len) return 0;

	if(appinfo_offs!=0) {
		if(appinfo_offs<curpos) return 0;
		curpos = appinfo_offs;
	}
	if(curpos>c->infile->len) return 0;

	if(sortinfo_offs!=0) {
		if(sortinfo_offs<curpos) return 0;
		curpos = sortinfo_offs;
	}
	if(curpos>c->infile->len) return 0;

	if(num_recs>0) {
		// Sanity-check the first record.
		// TODO? We could check more than one record.
		recdata_offs = de_getu32be(72+6+0);
		if(recdata_offs<curpos) return 0;
		curpos = recdata_offs;
		if(curpos>c->infile->len) return 0;
	}

	return 25;
}

static int looks_like_a_4cc(dbuf *f, i64 pos)
{
	i64 i;
	u8 buf[4];
	dbuf_read(f, buf, pos, 4);
	for(i=0; i<4; i++) {
		if(buf[i]<32 || buf[i]>126) return 0;
	}
	return 1;
}

// returns 1 if it might be a pdb, 2 if it might be a prc
// TODO: pdb
// TODO: Improve this ID algorithm
static int identify_pdb_prc_internal(deark *c, dbuf *f)
{
	i64 nrecs;
	u32 attribs;
	attribs = (u32)dbuf_getu16be(f, 32);
	if(!looks_like_a_4cc(f, 60)) return 0;
	if(!looks_like_a_4cc(f, 64)) return 0;
	nrecs = dbuf_getu16be(f, 72+4);
	if(nrecs<1) return 0;
	if(!(attribs&0x0001)) return 0;
	if(!looks_like_a_4cc(f, 72+6+0)) return 0;
	return 2;
}

static int de_identify_palmrc(deark *c)
{
	int prc_ext = 0;
	int pdb_ext = 0;
	int x;
	u8 id[8];

	if(de_input_file_has_ext(c, "prc"))
		prc_ext = 1;
	else if(de_input_file_has_ext(c, "pdb"))
		pdb_ext = 1;
	if(!prc_ext && !pdb_ext) return 0;

	de_read(id, 60, 8);
	if(!de_memcmp(id, "appl", 4)) return 100;

	x = identify_pdb_prc_internal(c, c->infile);
	if(x==2 && prc_ext) return 90;
	if(x==2 && pdb_ext) return 60;
	return 0;
}

static void de_help_pdb_prc(deark *c)
{
	de_msg(c, "-opt timestampfmt=<macbe|unixbe|macle> : The format of the "
		"timestamp fields");
}

void de_module_palmdb(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmdb";
	mi->desc = "Palm OS PDB";
	mi->run_fn = de_run_palmdb;
	mi->identify_fn = de_identify_palmdb;
	mi->help_fn = de_help_pdb_prc;
}

void de_module_palmrc(deark *c, struct deark_module_info *mi)
{
	mi->id = "palmrc";
	mi->desc = "Palm OS PRC";
	mi->run_fn = de_run_palmrc;
	mi->identify_fn = de_identify_palmrc;
	mi->help_fn = de_help_pdb_prc;
}
