// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Office Art / Office Drawing / "Escher" / "Blip"
// Refer to Microsoft's "[MS-ODRAW]" document.
// Found in some PowerPoint and Publisher files.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_officeart);

struct officeart_rectype {
	u16 rectype;
	u16 flags;
	const char *name;
	void *reserved;
};

static const struct officeart_rectype officeart_rectype_arr[] = {
	{ 0xf000, 0, "DggContainer", NULL },
	{ 0xf001, 0, "BStoreContainer", NULL },
	{ 0xf006, 0, "FDGGBlock", NULL },
	{ 0xf007, 0, "FBSE", NULL },
	{ 0xf00b, 0, "FOPT", NULL },
	{ 0xf01a, 0, "BlipEMF", NULL },
	{ 0xf01b, 0, "BlipWMF", NULL },
	{ 0xf01c, 0, "BlipPICT", NULL },
	{ 0xf01d, 0, "BlipJPEG", NULL },
	{ 0xf01e, 0, "BlipPNG", NULL },
	{ 0xf01f, 0, "BlipDIB", NULL },
	{ 0xf029, 0, "BlipTIFF", NULL },
	{ 0xf02a, 0, "BlipJPEG", NULL },
	{ 0xf11a, 0, "ColorMRUContainer", NULL },
	{ 0xf11e, 0, "SplitMenuColorContainer", NULL },
	{ 0xf122, 0, "TertiaryFOPT", NULL }
};

static const char *get_officeart_rectype_name(unsigned int t)
{
	size_t k;

	for(k=0; k<DE_ITEMS_IN_ARRAY(officeart_rectype_arr); k++) {
		if((unsigned int)officeart_rectype_arr[k].rectype == t) {
			return officeart_rectype_arr[k].name;
		}
	}
	return "?";
}

struct officeartctx {
#define OACTX_STACKSIZE 10
	i64 container_end_stack[OACTX_STACKSIZE];
	size_t container_end_stackptr;

	// Passed to do_OfficeArtStream_record():
	i64 record_pos;

	// Returned from do_OfficeArtStream_record():
	i64 record_bytes_consumed;
	int is_container;
	i64 container_endpos; // valid if (is_container)
};

static int do_OfficeArtStream_record(deark *c, struct officeartctx *oactx,
	dbuf *inf)
{
	unsigned int rectype;
	unsigned int recinstance;
	unsigned int recver;
	unsigned int n;
	i64 reclen;
	i64 extra_bytes = 0;
	dbuf *outf = NULL;
	const char *ext = "bin";
	int has_metafileHeader = 0;
	int has_zlib_cmpr = 0;
	int is_dib = 0;
	int is_pict = 0;
	int retval = 0;
	int is_blip = 0;
	int saved_indent_level;
	i64 pos1 = oactx->record_pos;
	i64 pos = pos1;

	oactx->record_bytes_consumed = 0;
	oactx->is_container = 0;
	oactx->container_endpos = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	n = (unsigned int)dbuf_getu16le_p(inf, &pos);
	recver = n&0x0f;
	if(recver==0x0f) oactx->is_container = 1;
	recinstance = n>>4;

	rectype = (unsigned int)dbuf_getu16le_p(inf, &pos);
	if((rectype&0xf000)!=0xf000) {
		// Assume this is the end of data, not necessarily an error.
		goto done;
	}

	reclen = dbuf_getu32le_p(inf, &pos);

	de_dbg(c, "record at [%"I64_FMT"], ver=0x%x, inst=0x%03x, type=0x%04x (%s), dlen=%"I64_FMT,
		pos1, recver, recinstance,
		rectype, get_officeart_rectype_name(rectype), reclen);
	de_dbg_indent(c, 1);

	if(pos + reclen > inf->len) goto done;
	if(oactx->is_container) {
		// A container is described as *being* its header record. It does have
		// a recLen, but it should be safe to ignore it if all we care about is
		// reading the records at a low level.
		oactx->record_bytes_consumed = 8;
		oactx->container_endpos = oactx->record_pos + 8 + reclen;
	}
	else {
		oactx->record_bytes_consumed = (pos-pos1) + reclen;
	}
	retval = 1;

	if(rectype>=0xf018 && rectype<=0xf117) is_blip = 1;
	if(!is_blip) goto done;

	if(rectype==0xf01a) {
		ext = "emf";
		if(recinstance==0x3d4) extra_bytes=50;
		else if(recinstance==0x3d5) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
	}
	else if(rectype==0xf01b) {
		ext = "wmf";
		if(recinstance==0x216) extra_bytes=50;
		else if(recinstance==0x217) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
	}
	else if(rectype==0xf01c) {
		ext = "pict";
		if(recinstance==0x542) extra_bytes=50;
		else if(recinstance==0x543) extra_bytes=66;
		if(extra_bytes) has_metafileHeader=1;
		is_pict = 1;
	}
	else if(rectype==0xf01d) {
		ext = "jpg";
		if(recinstance==0x46a || recinstance==0x6e2) extra_bytes = 17;
		else if(recinstance==0x46b || recinstance==0x6e3) extra_bytes = 33;
	}
	else if(rectype==0xf01e) {
		ext = "png";
		if(recinstance==0x6e0) extra_bytes = 17;
		else if(recinstance==0x6e1) extra_bytes = 33;
	}
	else if(rectype==0xf01f) {
		ext = "dib";
		if(recinstance==0x7a8) extra_bytes = 17;
		else if(recinstance==0x7a9) extra_bytes = 33;
		if(extra_bytes) is_dib=1;
	}
	else if(rectype==0xf029) {
		ext = "tif";
		if(recinstance==0x6e4) extra_bytes = 17;
		else if(recinstance==0x6e5) extra_bytes = 33;
	}

	if(extra_bytes==0) {
		de_warn(c, "Unsupported OfficeArtBlip format (recInstance=0x%03x, recType=0x%04x)",
			recinstance, rectype);
		goto done;
	}

	if(has_metafileHeader) {
		// metafileHeader starts at pos+extra_bytes-34
		u8 cmpr = dbuf_getbyte(inf, pos+extra_bytes-2);
		// 0=DEFLATE, 0xfe=NONE
		de_dbg(c, "compression type: %u", (unsigned int)cmpr);
		has_zlib_cmpr = (cmpr==0);
	}

	pos += extra_bytes;

	if(is_dib) {
		de_run_module_by_id_on_slice2(c, "dib", "X", inf, pos, reclen-extra_bytes);
		goto done;
	}

	outf = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);
	if(is_pict) {
		dbuf_write_zeroes(outf, 512);
	}

	if(has_zlib_cmpr) {
		i64 cmprlen;

		cmprlen = reclen-extra_bytes;
		de_decompress_deflate(inf, pos, cmprlen, outf, 0, NULL, DE_DEFLATEFLAG_ISZLIB);
		de_dbg(c, "decompressed %"I64_FMT" to %"I64_FMT" bytes", cmprlen, outf->len);
	}
	else {
		dbuf_copy(inf, pos, reclen-extra_bytes, outf);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	dbuf_close(outf);
	return retval;
}

static void de_run_officeart(deark *c, de_module_params *mparams)
{
	struct officeartctx * oactx = NULL;
	dbuf *inf = c->infile;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	oactx = de_malloc(c, sizeof(struct officeartctx));

	oactx->record_pos = 0;
	while(1) {
		i64 ret;

		if(oactx->record_pos >= inf->len-8) break;

		// Have we reached the end of any containers?
		while(oactx->container_end_stackptr>0 &&
			oactx->record_pos>=oactx->container_end_stack[oactx->container_end_stackptr-1])
		{
			oactx->container_end_stackptr--;
			de_dbg_indent(c, -1);
		}

		ret = do_OfficeArtStream_record(c, oactx, inf);
		if(!ret || oactx->record_bytes_consumed<=0) break;

		oactx->record_pos += oactx->record_bytes_consumed;

		// Is a new container open?
		if(oactx->is_container && oactx->container_end_stackptr<OACTX_STACKSIZE) {
			oactx->container_end_stack[oactx->container_end_stackptr++] = oactx->container_endpos;
			de_dbg_indent(c, 1);
		}
	}

	de_free(c, oactx);
	de_dbg_indent_restore(c, saved_indent_level);
}

void de_module_officeart(deark *c, struct deark_module_info *mi)
{
	mi->id = "officeart";
	mi->desc = "Office Art data";
	mi->run_fn = de_run_officeart;
	mi->flags |= DE_MODFLAG_HIDDEN;
}
